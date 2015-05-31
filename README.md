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

As time passes and the internet matures in our life, cyber crime is becoming increasingly sophisticated. Although there many tools (detection of malware, viruses, intrusion detection and prevension systems, etc) to help us isolate the budguys, there are now a lot more than just such attacks.

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
   However, they only include individual IPs (no subnets) which have attacked their users the last 48 hours and their list contains 20.000 to 40.000 IPs (which is small enough considering the size of the internet).
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

The following list was automatically generated on Sun May 31 09:12:50 UTC 2015.

The update frequency is the maximum allowed by internal configuration. A list will never be downloaded sooner than the update frequency stated. A list may also not be downloaded, after this frequency expired, if it has not been modified on the server (as reported by HTTP `IF_MODIFIED_SINCE` method).

name|info|type|entries|update|
:--:|:--:|:--:|:-----:|:----:|
[alienvault_reputation](#alienvault_reputation)|[AlienVault.com](https://www.alienvault.com/) IP reputation database (this list seems to include port scanning hosts and to be updated regularly, but we found no information about its retention policy)|ipv4 hash:ip|173978 unique IPs|updated every 6 hours  from [this link](https://reputation.alienvault.com/reputation.generic)
[blocklist_de](#blocklist_de)|[Blocklist.de](https://www.blocklist.de/) IPs that have been detected by fail2ban in the last 48 hours - **excellent list**|ipv4 hash:ip|21934 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/all.txt)
[blocklist_de_apache](#blocklist_de_apache)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service Apache, Apache-DDOS, RFI-Attacks.|ipv4 hash:ip|13637 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/apache.txt)
[blocklist_de_bots](#blocklist_de_bots)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the RFI-Attacks, REG-Bots, IRC-Bots or BadBots (BadBots = he has posted a Spam-Comment on a open Forum or Wiki).|ipv4 hash:ip|3238 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/bots.txt)
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|[Blocklist.de](https://www.blocklist.de/) All IPs which attacks Joomlas, Wordpress and other Web-Logins with Brute-Force Logins.|ipv4 hash:ip|1281 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/bruteforcelogin.txt)
[blocklist_de_ftp](#blocklist_de_ftp)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours for attacks on the Service FTP.|ipv4 hash:ip|195 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/ftp.txt)
[blocklist_de_imap](#blocklist_de_imap)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours for attacks on the Service imap, sasl, pop3, etc.|ipv4 hash:ip|666 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/imap.txt)
[blocklist_de_mail](#blocklist_de_mail)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service Mail, Postfix.|ipv4 hash:ip|14118 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/mail.txt)
[blocklist_de_sip](#blocklist_de_sip)|[Blocklist.de](https://www.blocklist.de/) All IP addresses that tried to login in a SIP, VOIP or Asterisk Server and are included in the IPs list from [infiltrated.net](www.infiltrated.net)|ipv4 hash:ip|106 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/sip.txt)
[blocklist_de_ssh](#blocklist_de_ssh)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service SSH.|ipv4 hash:ip|1731 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/ssh.txt)
[blocklist_de_strongips](#blocklist_de_strongips)|[Blocklist.de](https://www.blocklist.de/) All IPs which are older then 2 month and have more then 5.000 attacks.|ipv4 hash:ip|178 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/strongips.txt)
[bm_tor](#bm_tor)|[torstatus.blutmagie.de](https://torstatus.blutmagie.de) list of all TOR network servers|ipv4 hash:ip|6397 unique IPs|updated every 30 mins  from [this link](https://torstatus.blutmagie.de/ip_list_all.php/Tor_ip_list_ALL.csv)
[bogons](#bogons)|[Team-Cymru.org](http://www.team-cymru.org) private and reserved addresses defined by RFC 1918, RFC 5735, and RFC 6598 and netblocks that have not been allocated to a regional internet registry - **excellent list - use it only your internet interface**|ipv4 hash:net|13 subnets, 592708608 unique IPs|updated every 1 day  from [this link](http://www.team-cymru.org/Services/Bogons/bogon-bn-agg.txt)
[bruteforceblocker](#bruteforceblocker)|[danger.rulez.sk](http://danger.rulez.sk/) IPs detected by [bruteforceblocker](http://danger.rulez.sk/index.php/bruteforceblocker/) (fail2ban alternative for SSH on OpenBSD). This is an automatically generated list from users reporting failed authentication attempts. An IP seems to be included if 3 or more users report it. Its retention pocily seems 30 days.|ipv4 hash:ip|2212 unique IPs|updated every 3 hours  from [this link](http://danger.rulez.sk/projects/bruteforceblocker/blist.php)
[ciarmy](#ciarmy)|[CIArmy.com](http://ciarmy.com/) IPs with poor Rogue Packet score that have not yet been identified as malicious by the community|ipv4 hash:ip|331 unique IPs|updated every 3 hours  from [this link](http://cinsscore.com/list/ci-badguys.txt)
[cleanmx_viruses](#cleanmx_viruses)|[Clean-MX.de](http://support.clean-mx.de/clean-mx/viruses.php) IPs with viruses|ipv4 hash:ip|317 unique IPs|updated every 12 hours  from [this link](http://support.clean-mx.de/clean-mx/xmlviruses.php?sort=id%20desc&response=alive)
[dm_tor](#dm_tor)|[dan.me.uk](https://www.dan.me.uk) dynamic list of TOR exit points|ipv4 hash:ip|6431 unique IPs|updated every 30 mins  from [this link](https://www.dan.me.uk/torlist/)
[dshield](#dshield)|[DShield.org](https://dshield.org/) top 20 attacking class C (/24) subnets over the last three days - **excellent list**|ipv4 hash:net|19 subnets, 5120 unique IPs|updated every 4 hours  from [this link](http://feeds.dshield.org/block.txt)
[et_block](#et_block)|[EmergingThreats.net](http://www.emergingthreats.net/) default blacklist (at the time of writing includes spamhaus DROP, dshield and abuse.ch trackers, which are available separately too - prefer to use the direct ipsets instead of this, they seem to lag a bit in updates)|ipv4 hash:net|986 subnets, 18056524 unique IPs|updated every 12 hours  from [this link](http://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt)
[et_botcc](#et_botcc)|[EmergingThreats.net Command and Control IPs](http://doc.emergingthreats.net/bin/view/Main/BotCC) These IPs are updates every 24 hours and should be considered VERY highly reliable indications that a host is communicating with a known and active Bot or Malware command and control server - (although they say this includes abuse.ch trackers, it does not - most probably it is the shadowserver.org C&C list)|ipv4 hash:ip|501 unique IPs|updated every 12 hours  from [this link](http://rules.emergingthreats.net/fwrules/emerging-PIX-CC.rules)
[et_compromised](#et_compromised)|[EmergingThreats.net](http://www.emergingthreats.net/) compromised hosts (seems to be a derivate of other lists)|ipv4 hash:ip|2367 unique IPs|updated every 12 hours  from [this link](http://rules.emergingthreats.net/blockrules/compromised-ips.txt)
[et_tor](#et_tor)|[EmergingThreats.net](http://www.emergingthreats.net/) [list](http://doc.emergingthreats.net/bin/view/Main/TorRules) of TOR network IPs|ipv4 hash:ip|6470 unique IPs|updated every 12 hours  from [this link](http://rules.emergingthreats.net/blockrules/emerging-tor.rules)
[feodo](#feodo)|[Abuse.ch Feodo tracker](https://feodotracker.abuse.ch) trojan includes IPs which are being used by Feodo (also known as Cridex or Bugat) which commits ebanking fraud - **excellent list**|ipv4 hash:ip|71 unique IPs|updated every 30 mins  from [this link](https://feodotracker.abuse.ch/blocklist/?download=ipblocklist)
[fullbogons](#fullbogons)|[Team-Cymru.org](http://www.team-cymru.org) IP space that has been allocated to an RIR, but not assigned by that RIR to an actual ISP or other end-user - **excellent list - use it only your internet interface**|ipv4 hash:net|3642 subnets, 670590424 unique IPs|updated every 1 day  from [this link](http://www.team-cymru.org/Services/Bogons/fullbogons-ipv4.txt)
[geolite2_country](https://github.com/ktsaou/blocklist-ipsets/tree/master/geolite2_country)|[MaxMind GeoLite2](http://dev.maxmind.com/geoip/geoip2/geolite2/) databases are free IP geolocation databases comparable to, but less accurate than, MaxMind’s GeoIP2 databases. They include IPs per country, IPs per continent, IPs used by anonymous services (VPNs, Proxies, etc) and Satellite Providers.|ipv4 hash:net|All the world|updated every 7 days  from [this link](http://geolite.maxmind.com/download/geoip/database/GeoLite2-Country-CSV.zip)
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|[iBlocklist.com](https://www.iblocklist.com/) free version of [BlueTack.co.uk](http://www.bluetack.co.uk/) IPs that have been reported for bad deeds in p2p|ipv4 hash:ip|48134 unique IPs|updated every 12 hours  from [this link](http://list.iblocklist.com/?list=cwworuawihqvocglcoss&fileformat=p2p&archiveformat=gz)
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|[iBlocklist.com](https://www.iblocklist.com/) free version of [BlueTack.co.uk](http://www.bluetack.co.uk/) hijacked IP-Blocks Hijacked IP space are IP blocks that are being used without permission|ipv4 hash:net|535 subnets, 9177856 unique IPs|updated every 12 hours  from [this link](http://list.iblocklist.com/?list=usrcshglbiilevmyfhse&fileformat=p2p&archiveformat=gz)
[ib_bluetack_level1](#ib_bluetack_level1)|[iBlocklist.com](https://www.iblocklist.com/) free version of [BlueTack.co.uk](http://www.bluetack.co.uk/) Level 1 (for use in p2p): Companies or organizations who are clearly involved with trying to stop filesharing (e.g. Baytsp, MediaDefender, Mediasentry a.o.). Companies which anti-p2p activity has been seen from. Companies that produce or have a strong financial interest in copyrighted material (e.g. music, movie, software industries a.o.). Government ranges or companies that have a strong financial interest in doing work for governments. Legal industry ranges. IPs or ranges of ISPs from which anti-p2p activity has been observed. Basically this list will block all kinds of internet connections that most people would rather not have during their internet travels.|ipv4 hash:net|218309 subnets, 764987411 unique IPs|updated every 12 hours  from [this link](http://list.iblocklist.com/?list=ydxerpxkpcfqjaybcssw&fileformat=p2p&archiveformat=gz)
[ib_bluetack_level2](#ib_bluetack_level2)|[iBlocklist.com](https://www.iblocklist.com/) free version of BlueTack.co.uk Level 2 (for use in p2p). General corporate ranges. Ranges used by labs or researchers. Proxies.|ipv4 hash:net|72774 subnets, 348707599 unique IPs|updated every 12 hours  from [this link](http://list.iblocklist.com/?list=gyisgnzbhppbvsphucsw&fileformat=p2p&archiveformat=gz)
[ib_bluetack_level3](#ib_bluetack_level3)|[iBlocklist.com](https://www.iblocklist.com/) free version of BlueTack.co.uk Level 3 (for use in p2p). Many portal-type websites. ISP ranges that may be dodgy for some reason. Ranges that belong to an individual, but which have not been determined to be used by a particular company. Ranges for things that are unusual in some way. The L3 list is aka the paranoid list.|ipv4 hash:net|17802 subnets, 139104824 unique IPs|updated every 12 hours  from [this link](http://list.iblocklist.com/?list=uwnukjqktoggdknzrhgh&fileformat=p2p&archiveformat=gz)
[ib_bluetack_proxies](#ib_bluetack_proxies)|[iBlocklist.com](https://www.iblocklist.com/) free version of [BlueTack.co.uk](http://www.bluetack.co.uk/) Open Proxies IPs list (without TOR)|ipv4 hash:ip|673 unique IPs|updated every 12 hours  from [this link](http://list.iblocklist.com/?list=xoebmbyexwuiogmbyprb&fileformat=p2p&archiveformat=gz)
[ib_bluetack_spyware](#ib_bluetack_spyware)|[iBlocklist.com](https://www.iblocklist.com/) free version of [BlueTack.co.uk](http://www.bluetack.co.uk/) known malicious SPYWARE and ADWARE IP Address ranges|ipv4 hash:net|3274 subnets, 339192 unique IPs|updated every 12 hours  from [this link](http://list.iblocklist.com/?list=llvtlsjyoyiczbkjsxpf&fileformat=p2p&archiveformat=gz)
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|[iBlocklist.com](https://www.iblocklist.com/) free version of [BlueTack.co.uk](http://www.bluetack.co.uk/) web server hack and exploit attempts|ipv4 hash:ip|1460 unique IPs|updated every 12 hours  from [this link](http://list.iblocklist.com/?list=ghlzqtqxnzctvvajwwag&fileformat=p2p&archiveformat=gz)
[malc0de](#malc0de)|[Malc0de.com](http://malc0de.com) malicious IPs of the last 30 days|ipv4 hash:ip|407 unique IPs|updated every 1 day  from [this link](http://malc0de.com/bl/IP_Blacklist.txt)
[malwaredomainlist](#malwaredomainlist)|[malwaredomainlist.com](http://www.malwaredomainlist.com) list of malware active ip addresses|ipv4 hash:ip|1282 unique IPs|updated every 12 hours  from [this link](http://www.malwaredomainlist.com/hostslist/ip.txt)
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|[MaxMind.com](https://www.maxmind.com/en/anonymous-proxy-fraudulent-ip-address-list) list of anonymous proxy fraudelent IP addresses.|ipv4 hash:ip|372 unique IPs|updated every 4 hours  from [this link](https://www.maxmind.com/en/anonymous-proxy-fraudulent-ip-address-list)
[nixspam](#nixspam)|[NiX Spam](http://www.heise.de/ix/NiX-Spam-DNSBL-and-blacklist-for-download-499637.html) IP addresses that sent spam in the last hour - automatically generated entries without distinguishing open proxies from relays, dialup gateways, and so on. All IPs are removed after 12 hours if there is no spam from there.|ipv4 hash:ip|20463 unique IPs|updated every 15 mins  from [this link](http://www.dnsbl.manitu.net/download/nixspam-ip.dump.gz)
[openbl_1d](#openbl_1d)|[OpenBL.org](http://www.openbl.org/) last 24 hours IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|187 unique IPs|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_1days.txt)
[openbl_30d](#openbl_30d)|[OpenBL.org](http://www.openbl.org/) last 30 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|3280 unique IPs|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_30days.txt)
[openbl_60d](#openbl_60d)|[OpenBL.org](http://www.openbl.org/) last 60 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|7635 unique IPs|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_60days.txt)
[openbl_7d](#openbl_7d)|[OpenBL.org](http://www.openbl.org/) last 7 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|909 unique IPs|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_7days.txt)
[palevo](#palevo)|[Abuse.ch Palevo tracker](https://palevotracker.abuse.ch) worm includes IPs which are being used as botnet C&C for the Palevo crimeware - **excellent list**|ipv4 hash:ip|13 unique IPs|updated every 30 mins  from [this link](https://palevotracker.abuse.ch/blocklists.php?download=ipblocklist)
[php_commenters](#php_commenters)|[projecthoneypot.org](http://www.projecthoneypot.org/) comment spammers (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|281 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=c&rss=1)
[php_dictionary](#php_dictionary)|[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) directory attackers (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|433 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=d&rss=1)
[php_harvesters](#php_harvesters)|[projecthoneypot.org](http://www.projecthoneypot.org/) harvesters (IPs that surf the internet looking for email addresses) (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|257 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=h&rss=1)
[php_spammers](#php_spammers)|[projecthoneypot.org](http://www.projecthoneypot.org/) spam servers (IPs used by spammers to send messages) (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|417 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=s&rss=1)
[proxyrss](#proxyrss)|[proxyrss.com](http://www.proxyrss.com) open proxies syndicated from multiple sources.|ipv4 hash:ip|1784 unique IPs|updated every 4 hours  from [this link](http://www.proxyrss.com/proxylists/all.gz)
[proxz](#proxz)|[proxz.com](http://www.proxz.com) open proxies (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|322 unique IPs|updated every 1 hour  from [this link](http://www.proxz.com/proxylists.xml)
[ri_connect_proxies](#ri_connect_proxies)|[rosinstrument.com](http://www.rosinstrument.com) open CONNECT proxies (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|1929 unique IPs|updated every 1 hour  from [this link](http://tools.rosinstrument.com/proxy/plab100.xml)
[ri_web_proxies](#ri_web_proxies)|[rosinstrument.com](http://www.rosinstrument.com) open HTTP proxies (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|5126 unique IPs|updated every 1 hour  from [this link](http://tools.rosinstrument.com/proxy/l100.xml)
[shunlist](#shunlist)|[AutoShun.org](http://autoshun.org/) IPs identified as hostile by correlating logs from distributed snort installations running the autoshun plugin|ipv4 hash:ip|1195 unique IPs|updated every 4 hours  from [this link](http://www.autoshun.org/files/shunlist.csv)
[snort_ipfilter](#snort_ipfilter)|[labs.snort.org](https://labs.snort.org/) supplied IP blacklist (this list seems to be updated frequently, but we found no information about it)|ipv4 hash:ip|1922 unique IPs|updated every 12 hours  from [this link](http://labs.snort.org/feeds/ip-filter.blf)
[spamhaus_drop](#spamhaus_drop)|[Spamhaus.org](http://www.spamhaus.org) DROP list (according to their site this list should be dropped at tier-1 ISPs globaly) - **excellent list**|ipv4 hash:net|650 subnets, 18333440 unique IPs|updated every 12 hours  from [this link](http://www.spamhaus.org/drop/drop.txt)
[spamhaus_edrop](#spamhaus_edrop)|[Spamhaus.org](http://www.spamhaus.org) EDROP (extended matches that should be used with DROP) - **excellent list**|ipv4 hash:net|56 subnets, 421632 unique IPs|updated every 12 hours  from [this link](http://www.spamhaus.org/drop/edrop.txt)
[sslbl](#sslbl)|[Abuse.ch SSL Blacklist](https://sslbl.abuse.ch/) bad SSL traffic related to malware or botnet activities - **excellent list**|ipv4 hash:ip|357 unique IPs|updated every 30 mins  from [this link](https://sslbl.abuse.ch/blacklist/sslipblacklist.csv)
[stopforumspam_1d](#stopforumspam_1d)|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers in the last 24 hours - **excellent list**|ipv4 hash:ip|6802 unique IPs|updated every 1 hour  from [this link](http://www.stopforumspam.com/downloads/listed_ip_1.zip)
[stopforumspam_30d](#stopforumspam_30d)|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 30 days)|ipv4 hash:ip|92135 unique IPs|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/listed_ip_30.zip)
[stopforumspam_7d](#stopforumspam_7d)|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 7 days)|ipv4 hash:ip|31070 unique IPs|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/listed_ip_7.zip)
[voipbl](#voipbl)|[VoIPBL.org](http://www.voipbl.org/) a distributed VoIP blacklist that is aimed to protects against VoIP Fraud and minimizing abuse for network that have publicly accessible PBX's. Several algorithms, external sources and manual confirmation are used before they categorize something as an attack and determine the threat level.|ipv4 hash:net|10327 subnets, 10736 unique IPs|updated every 4 hours  from [this link](http://www.voipbl.org/update/)
[xroxy](#xroxy)|[xroxy.com](http://www.xroxy.com) open proxies (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|1983 unique IPs|updated every 1 hour  from [this link](http://www.xroxy.com/proxyrss.xml)
[zeus](#zeus)|[Abuse.ch Zeus tracker](https://zeustracker.abuse.ch) standard, contains the same data as the ZeuS IP blocklist (zeus_badips) but with the slight difference that it doesn't exclude hijacked websites (level 2) and free web hosting providers (level 3). This means that this blocklist contains all IPv4 addresses associated with ZeuS C&Cs which are currently being tracked by ZeuS Tracker. Hence this blocklist will likely cause some false positives. - **excellent list**|ipv4 hash:ip|264 unique IPs|updated every 30 mins  from [this link](https://zeustracker.abuse.ch/blocklist.php?download=ipblocklist)
[zeus_badips](#zeus_badips)|[Abuse.ch Zeus tracker](https://zeustracker.abuse.ch) badips includes IPv4 addresses that are used by the ZeuS trojan. It is the recommened blocklist if you want to block only ZeuS IPs. It excludes IP addresses that ZeuS Tracker believes to be hijacked (level 2) or belong to a free web hosting provider (level 3). Hence the false postive rate should be much lower compared to the standard ZeuS IP blocklist. **excellent list**|ipv4 hash:ip|229 unique IPs|updated every 30 mins  from [this link](https://zeustracker.abuse.ch/blocklist.php?download=badips)

# Comparison of ipsets

Below we compare each ipset against all other.


## alienvault_reputation

[AlienVault.com](https://www.alienvault.com/) IP reputation database (this list seems to include port scanning hosts and to be updated regularly, but we found no information about its retention policy)

Source is downloaded from [this link](https://reputation.alienvault.com/reputation.generic).

The last time downloaded was found to be dated: Sun May 31 04:01:02 UTC 2015.

The ipset `alienvault_reputation` has **173978** entries, **173978** unique IPs.

The following table shows the overlaps of `alienvault_reputation` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `alienvault_reputation`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `alienvault_reputation`.
- ` this % ` is the percentage **of this ipset (`alienvault_reputation`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|15145|0.0%|8.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|8133|0.0%|4.6%|
[openbl_60d](#openbl_60d)|7635|7635|7608|99.6%|4.3%|
[et_block](#et_block)|986|18056524|6045|0.0%|3.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|4707|0.0%|2.7%|
[openbl_30d](#openbl_30d)|3280|3280|3261|99.4%|1.8%|
[dshield](#dshield)|19|5120|3076|60.0%|1.7%|
[spamhaus_drop](#spamhaus_drop)|650|18333440|1629|0.0%|0.9%|
[et_compromised](#et_compromised)|2367|2367|1533|64.7%|0.8%|
[bruteforceblocker](#bruteforceblocker)|2212|2212|1435|64.8%|0.8%|
[blocklist_de](#blocklist_de)|21934|21934|1207|5.5%|0.6%|
[shunlist](#shunlist)|1195|1195|1184|99.0%|0.6%|
[blocklist_de_ssh](#blocklist_de_ssh)|1731|1731|952|54.9%|0.5%|
[openbl_7d](#openbl_7d)|909|909|896|98.5%|0.5%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|519|0.0%|0.2%|
[ciarmy](#ciarmy)|331|331|322|97.2%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|288|0.0%|0.1%|
[spamhaus_edrop](#spamhaus_edrop)|56|421632|271|0.0%|0.1%|
[stopforumspam_30d](#stopforumspam_30d)|92135|92135|222|0.2%|0.1%|
[voipbl](#voipbl)|10327|10736|215|2.0%|0.1%|
[openbl_1d](#openbl_1d)|187|187|186|99.4%|0.1%|
[blocklist_de_apache](#blocklist_de_apache)|13637|13637|116|0.8%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|31070|31070|112|0.3%|0.0%|
[snort_ipfilter](#snort_ipfilter)|1922|1922|110|5.7%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14118|14118|92|0.6%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|666|666|67|10.0%|0.0%|
[zeus](#zeus)|264|264|66|25.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6802|6802|61|0.8%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|178|178|58|32.5%|0.0%|
[et_tor](#et_tor)|6470|6470|48|0.7%|0.0%|
[bm_tor](#bm_tor)|6397|6397|47|0.7%|0.0%|
[dm_tor](#dm_tor)|6431|6431|46|0.7%|0.0%|
[nixspam](#nixspam)|20463|20463|38|0.1%|0.0%|
[zeus_badips](#zeus_badips)|229|229|37|16.1%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3238|3238|30|0.9%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|25|6.7%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|106|106|19|17.9%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|14|0.0%|0.0%|
[sslbl](#sslbl)|357|357|13|3.6%|0.0%|
[php_commenters](#php_commenters)|281|281|13|4.6%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1281|1281|10|0.7%|0.0%|
[php_harvesters](#php_harvesters)|257|257|9|3.5%|0.0%|
[malc0de](#malc0de)|407|407|9|2.2%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|195|195|9|4.6%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|8|0.5%|0.0%|
[php_dictionary](#php_dictionary)|433|433|7|1.6%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1282|1282|6|0.4%|0.0%|
[xroxy](#xroxy)|1983|1983|5|0.2%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|317|317|4|1.2%|0.0%|
[ri_web_proxies](#ri_web_proxies)|5126|5126|3|0.0%|0.0%|
[php_spammers](#php_spammers)|417|417|3|0.7%|0.0%|
[et_botcc](#et_botcc)|501|501|3|0.5%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|1929|1929|2|0.1%|0.0%|
[proxz](#proxz)|322|322|2|0.6%|0.0%|
[proxyrss](#proxyrss)|1784|1784|2|0.1%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|1|0.1%|0.0%|
[feodo](#feodo)|71|71|1|1.4%|0.0%|

## blocklist_de

[Blocklist.de](https://www.blocklist.de/) IPs that have been detected by fail2ban in the last 48 hours - **excellent list**

Source is downloaded from [this link](http://lists.blocklist.de/lists/all.txt).

The last time downloaded was found to be dated: Sun May 31 08:42:03 UTC 2015.

The ipset `blocklist_de` has **21934** entries, **21934** unique IPs.

The following table shows the overlaps of `blocklist_de` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de`.
- ` this % ` is the percentage **of this ipset (`blocklist_de`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de_mail](#blocklist_de_mail)|14118|14118|14118|100.0%|64.3%|
[blocklist_de_apache](#blocklist_de_apache)|13637|13637|13636|99.9%|62.1%|
[blocklist_de_bots](#blocklist_de_bots)|3238|3238|3238|100.0%|14.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|2777|0.0%|12.6%|
[stopforumspam_30d](#stopforumspam_30d)|92135|92135|2518|2.7%|11.4%|
[stopforumspam_7d](#stopforumspam_7d)|31070|31070|2216|7.1%|10.1%|
[blocklist_de_ssh](#blocklist_de_ssh)|1731|1731|1731|100.0%|7.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|1457|0.0%|6.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|1443|0.0%|6.5%|
[stopforumspam_1d](#stopforumspam_1d)|6802|6802|1386|20.3%|6.3%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1281|1281|1281|100.0%|5.8%|
[alienvault_reputation](#alienvault_reputation)|173978|173978|1207|0.6%|5.5%|
[openbl_60d](#openbl_60d)|7635|7635|899|11.7%|4.0%|
[openbl_30d](#openbl_30d)|3280|3280|830|25.3%|3.7%|
[bruteforceblocker](#bruteforceblocker)|2212|2212|736|33.2%|3.3%|
[et_compromised](#et_compromised)|2367|2367|692|29.2%|3.1%|
[blocklist_de_imap](#blocklist_de_imap)|666|666|666|100.0%|3.0%|
[openbl_7d](#openbl_7d)|909|909|558|61.3%|2.5%|
[shunlist](#shunlist)|1195|1195|443|37.0%|2.0%|
[nixspam](#nixspam)|20463|20463|373|1.8%|1.7%|
[ri_web_proxies](#ri_web_proxies)|5126|5126|371|7.2%|1.6%|
[xroxy](#xroxy)|1983|1983|267|13.4%|1.2%|
[proxyrss](#proxyrss)|1784|1784|261|14.6%|1.1%|
[blocklist_de_ftp](#blocklist_de_ftp)|195|195|195|100.0%|0.8%|
[et_block](#et_block)|986|18056524|190|0.0%|0.8%|
[spamhaus_drop](#spamhaus_drop)|650|18333440|188|0.0%|0.8%|
[blocklist_de_strongips](#blocklist_de_strongips)|178|178|178|100.0%|0.8%|
[openbl_1d](#openbl_1d)|187|187|167|89.3%|0.7%|
[blocklist_de_sip](#blocklist_de_sip)|106|106|87|82.0%|0.3%|
[proxz](#proxz)|322|322|81|25.1%|0.3%|
[dshield](#dshield)|19|5120|75|1.4%|0.3%|
[ri_connect_proxies](#ri_connect_proxies)|1929|1929|72|3.7%|0.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|64|0.0%|0.2%|
[php_commenters](#php_commenters)|281|281|56|19.9%|0.2%|
[php_dictionary](#php_dictionary)|433|433|53|12.2%|0.2%|
[voipbl](#voipbl)|10327|10736|46|0.4%|0.2%|
[php_spammers](#php_spammers)|417|417|46|11.0%|0.2%|
[ciarmy](#ciarmy)|331|331|46|13.8%|0.2%|
[php_harvesters](#php_harvesters)|257|257|24|9.3%|0.1%|
[spamhaus_edrop](#spamhaus_edrop)|56|421632|18|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|1922|1922|4|0.2%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|4|0.5%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|3|0.8%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|3|0.0%|0.0%|
[et_tor](#et_tor)|6470|6470|3|0.0%|0.0%|
[dm_tor](#dm_tor)|6431|6431|3|0.0%|0.0%|
[bm_tor](#bm_tor)|6397|6397|3|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|2|0.0%|0.0%|
[zeus](#zeus)|264|264|1|0.3%|0.0%|

## blocklist_de_apache

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service Apache, Apache-DDOS, RFI-Attacks.

Source is downloaded from [this link](http://lists.blocklist.de/lists/apache.txt).

The last time downloaded was found to be dated: Sun May 31 08:56:07 UTC 2015.

The ipset `blocklist_de_apache` has **13637** entries, **13637** unique IPs.

The following table shows the overlaps of `blocklist_de_apache` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_apache`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_apache`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_apache`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|21934|21934|13636|62.1%|99.9%|
[blocklist_de_mail](#blocklist_de_mail)|14118|14118|11059|78.3%|81.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|2195|0.0%|16.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|1305|0.0%|9.5%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1281|1281|1281|100.0%|9.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|1068|0.0%|7.8%|
[stopforumspam_30d](#stopforumspam_30d)|92135|92135|199|0.2%|1.4%|
[stopforumspam_7d](#stopforumspam_7d)|31070|31070|117|0.3%|0.8%|
[alienvault_reputation](#alienvault_reputation)|173978|173978|116|0.0%|0.8%|
[stopforumspam_1d](#stopforumspam_1d)|6802|6802|59|0.8%|0.4%|
[ciarmy](#ciarmy)|331|331|40|12.0%|0.2%|
[blocklist_de_strongips](#blocklist_de_strongips)|178|178|33|18.5%|0.2%|
[shunlist](#shunlist)|1195|1195|26|2.1%|0.1%|
[php_commenters](#php_commenters)|281|281|24|8.5%|0.1%|
[blocklist_de_bots](#blocklist_de_bots)|3238|3238|18|0.5%|0.1%|
[nixspam](#nixspam)|20463|20463|8|0.0%|0.0%|
[openbl_60d](#openbl_60d)|7635|7635|6|0.0%|0.0%|
[et_block](#et_block)|986|18056524|6|0.0%|0.0%|
[openbl_30d](#openbl_30d)|3280|3280|5|0.1%|0.0%|
[php_spammers](#php_spammers)|417|417|4|0.9%|0.0%|
[voipbl](#voipbl)|10327|10736|3|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|650|18333440|3|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|1922|1922|3|0.1%|0.0%|
[et_tor](#et_tor)|6470|6470|3|0.0%|0.0%|
[et_compromised](#et_compromised)|2367|2367|3|0.1%|0.0%|
[dm_tor](#dm_tor)|6431|6431|3|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2212|2212|3|0.1%|0.0%|
[bm_tor](#bm_tor)|6397|6397|3|0.0%|0.0%|
[xroxy](#xroxy)|1983|1983|2|0.1%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|421632|2|0.0%|0.0%|
[proxyrss](#proxyrss)|1784|1784|2|0.1%|0.0%|
[openbl_7d](#openbl_7d)|909|909|2|0.2%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|2|0.5%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|2|0.0%|0.0%|
[dshield](#dshield)|19|5120|2|0.0%|0.0%|
[zeus](#zeus)|264|264|1|0.3%|0.0%|
[ri_web_proxies](#ri_web_proxies)|5126|5126|1|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|1929|1929|1|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.0%|

## blocklist_de_bots

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the RFI-Attacks, REG-Bots, IRC-Bots or BadBots (BadBots = he has posted a Spam-Comment on a open Forum or Wiki).

Source is downloaded from [this link](http://lists.blocklist.de/lists/bots.txt).

The last time downloaded was found to be dated: Sun May 31 08:42:20 UTC 2015.

The ipset `blocklist_de_bots` has **3238** entries, **3238** unique IPs.

The following table shows the overlaps of `blocklist_de_bots` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_bots`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_bots`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_bots`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|21934|21934|3238|14.7%|100.0%|
[stopforumspam_30d](#stopforumspam_30d)|92135|92135|2235|2.4%|69.0%|
[stopforumspam_7d](#stopforumspam_7d)|31070|31070|2050|6.5%|63.3%|
[stopforumspam_1d](#stopforumspam_1d)|6802|6802|1322|19.4%|40.8%|
[ri_web_proxies](#ri_web_proxies)|5126|5126|345|6.7%|10.6%|
[proxyrss](#proxyrss)|1784|1784|259|14.5%|7.9%|
[xroxy](#xroxy)|1983|1983|231|11.6%|7.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|200|0.0%|6.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|176|0.0%|5.4%|
[blocklist_de_strongips](#blocklist_de_strongips)|178|178|108|60.6%|3.3%|
[ri_connect_proxies](#ri_connect_proxies)|1929|1929|70|3.6%|2.1%|
[proxz](#proxz)|322|322|69|21.4%|2.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|59|0.0%|1.8%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|53|0.0%|1.6%|
[nixspam](#nixspam)|20463|20463|51|0.2%|1.5%|
[spamhaus_drop](#spamhaus_drop)|650|18333440|48|0.0%|1.4%|
[et_block](#et_block)|986|18056524|48|0.0%|1.4%|
[php_commenters](#php_commenters)|281|281|45|16.0%|1.3%|
[alienvault_reputation](#alienvault_reputation)|173978|173978|30|0.0%|0.9%|
[php_harvesters](#php_harvesters)|257|257|21|8.1%|0.6%|
[blocklist_de_mail](#blocklist_de_mail)|14118|14118|18|0.1%|0.5%|
[blocklist_de_apache](#blocklist_de_apache)|13637|13637|18|0.1%|0.5%|
[php_spammers](#php_spammers)|417|417|15|3.5%|0.4%|
[php_dictionary](#php_dictionary)|433|433|13|3.0%|0.4%|
[spamhaus_edrop](#spamhaus_edrop)|56|421632|10|0.0%|0.3%|
[openbl_60d](#openbl_60d)|7635|7635|3|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|3|0.4%|0.0%|
[voipbl](#voipbl)|10327|10736|1|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|
[et_compromised](#et_compromised)|2367|2367|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2212|2212|1|0.0%|0.0%|

## blocklist_de_bruteforce

[Blocklist.de](https://www.blocklist.de/) All IPs which attacks Joomlas, Wordpress and other Web-Logins with Brute-Force Logins.

Source is downloaded from [this link](http://lists.blocklist.de/lists/bruteforcelogin.txt).

The last time downloaded was found to be dated: Sun May 31 08:42:24 UTC 2015.

The ipset `blocklist_de_bruteforce` has **1281** entries, **1281** unique IPs.

The following table shows the overlaps of `blocklist_de_bruteforce` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_bruteforce`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_bruteforce`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_bruteforce`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de_apache](#blocklist_de_apache)|13637|13637|1281|9.3%|100.0%|
[blocklist_de](#blocklist_de)|21934|21934|1281|5.8%|100.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|97|0.0%|7.5%|
[stopforumspam_30d](#stopforumspam_30d)|92135|92135|40|0.0%|3.1%|
[stopforumspam_7d](#stopforumspam_7d)|31070|31070|32|0.1%|2.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|32|0.0%|2.4%|
[stopforumspam_1d](#stopforumspam_1d)|6802|6802|17|0.2%|1.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|17|0.0%|1.3%|
[blocklist_de_strongips](#blocklist_de_strongips)|178|178|10|5.6%|0.7%|
[alienvault_reputation](#alienvault_reputation)|173978|173978|10|0.0%|0.7%|
[nixspam](#nixspam)|20463|20463|8|0.0%|0.6%|
[php_spammers](#php_spammers)|417|417|4|0.9%|0.3%|
[php_commenters](#php_commenters)|281|281|4|1.4%|0.3%|
[et_block](#et_block)|986|18056524|4|0.0%|0.3%|
[spamhaus_drop](#spamhaus_drop)|650|18333440|3|0.0%|0.2%|
[xroxy](#xroxy)|1983|1983|2|0.1%|0.1%|
[proxyrss](#proxyrss)|1784|1784|2|0.1%|0.1%|
[zeus](#zeus)|264|264|1|0.3%|0.0%|
[voipbl](#voipbl)|10327|10736|1|0.0%|0.0%|
[shunlist](#shunlist)|1195|1195|1|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|5126|5126|1|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|1929|1929|1|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.0%|

## blocklist_de_ftp

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours for attacks on the Service FTP.

Source is downloaded from [this link](http://lists.blocklist.de/lists/ftp.txt).

The last time downloaded was found to be dated: Sun May 31 08:42:14 UTC 2015.

The ipset `blocklist_de_ftp` has **195** entries, **195** unique IPs.

The following table shows the overlaps of `blocklist_de_ftp` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_ftp`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_ftp`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_ftp`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|21934|21934|195|0.8%|100.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|13|0.0%|6.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|12|0.0%|6.1%|
[alienvault_reputation](#alienvault_reputation)|173978|173978|9|0.0%|4.6%|
[stopforumspam_30d](#stopforumspam_30d)|92135|92135|8|0.0%|4.1%|
[stopforumspam_7d](#stopforumspam_7d)|31070|31070|5|0.0%|2.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|5|0.0%|2.5%|
[php_harvesters](#php_harvesters)|257|257|2|0.7%|1.0%|
[openbl_60d](#openbl_60d)|7635|7635|2|0.0%|1.0%|
[stopforumspam_1d](#stopforumspam_1d)|6802|6802|1|0.0%|0.5%|
[openbl_7d](#openbl_7d)|909|909|1|0.1%|0.5%|
[openbl_30d](#openbl_30d)|3280|3280|1|0.0%|0.5%|
[ciarmy](#ciarmy)|331|331|1|0.3%|0.5%|
[blocklist_de_strongips](#blocklist_de_strongips)|178|178|1|0.5%|0.5%|

## blocklist_de_imap

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours for attacks on the Service imap, sasl, pop3, etc.

Source is downloaded from [this link](http://lists.blocklist.de/lists/imap.txt).

The last time downloaded was found to be dated: Sun May 31 08:42:13 UTC 2015.

The ipset `blocklist_de_imap` has **666** entries, **666** unique IPs.

The following table shows the overlaps of `blocklist_de_imap` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_imap`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_imap`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_imap`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de_mail](#blocklist_de_mail)|14118|14118|666|4.7%|100.0%|
[blocklist_de](#blocklist_de)|21934|21934|666|3.0%|100.0%|
[alienvault_reputation](#alienvault_reputation)|173978|173978|67|0.0%|10.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|48|0.0%|7.2%|
[openbl_60d](#openbl_60d)|7635|7635|43|0.5%|6.4%|
[openbl_30d](#openbl_30d)|3280|3280|39|1.1%|5.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|38|0.0%|5.7%|
[openbl_7d](#openbl_7d)|909|909|24|2.6%|3.6%|
[spamhaus_drop](#spamhaus_drop)|650|18333440|17|0.0%|2.5%|
[et_block](#et_block)|986|18056524|17|0.0%|2.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|15|0.0%|2.2%|
[et_compromised](#et_compromised)|2367|2367|15|0.6%|2.2%|
[bruteforceblocker](#bruteforceblocker)|2212|2212|12|0.5%|1.8%|
[shunlist](#shunlist)|1195|1195|4|0.3%|0.6%|
[openbl_1d](#openbl_1d)|187|187|4|2.1%|0.6%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|0.4%|
[stopforumspam_30d](#stopforumspam_30d)|92135|92135|2|0.0%|0.3%|
[nixspam](#nixspam)|20463|20463|2|0.0%|0.3%|
[ciarmy](#ciarmy)|331|331|2|0.6%|0.3%|
[voipbl](#voipbl)|10327|10736|1|0.0%|0.1%|
[stopforumspam_7d](#stopforumspam_7d)|31070|31070|1|0.0%|0.1%|
[dshield](#dshield)|19|5120|1|0.0%|0.1%|
[blocklist_de_strongips](#blocklist_de_strongips)|178|178|1|0.5%|0.1%|

## blocklist_de_mail

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service Mail, Postfix.

Source is downloaded from [this link](http://lists.blocklist.de/lists/mail.txt).

The last time downloaded was found to be dated: Sun May 31 08:42:10 UTC 2015.

The ipset `blocklist_de_mail` has **14118** entries, **14118** unique IPs.

The following table shows the overlaps of `blocklist_de_mail` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_mail`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_mail`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_mail`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|21934|21934|14118|64.3%|100.0%|
[blocklist_de_apache](#blocklist_de_apache)|13637|13637|11059|81.0%|78.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|2245|0.0%|15.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|1319|0.0%|9.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|1125|0.0%|7.9%|
[blocklist_de_imap](#blocklist_de_imap)|666|666|666|100.0%|4.7%|
[nixspam](#nixspam)|20463|20463|313|1.5%|2.2%|
[stopforumspam_30d](#stopforumspam_30d)|92135|92135|213|0.2%|1.5%|
[stopforumspam_7d](#stopforumspam_7d)|31070|31070|117|0.3%|0.8%|
[alienvault_reputation](#alienvault_reputation)|173978|173978|92|0.0%|0.6%|
[openbl_60d](#openbl_60d)|7635|7635|57|0.7%|0.4%|
[openbl_30d](#openbl_30d)|3280|3280|52|1.5%|0.3%|
[stopforumspam_1d](#stopforumspam_1d)|6802|6802|51|0.7%|0.3%|
[php_dictionary](#php_dictionary)|433|433|40|9.2%|0.2%|
[xroxy](#xroxy)|1983|1983|33|1.6%|0.2%|
[openbl_7d](#openbl_7d)|909|909|30|3.3%|0.2%|
[php_spammers](#php_spammers)|417|417|26|6.2%|0.1%|
[ri_web_proxies](#ri_web_proxies)|5126|5126|25|0.4%|0.1%|
[et_block](#et_block)|986|18056524|22|0.0%|0.1%|
[spamhaus_drop](#spamhaus_drop)|650|18333440|21|0.0%|0.1%|
[et_compromised](#et_compromised)|2367|2367|18|0.7%|0.1%|
[blocklist_de_strongips](#blocklist_de_strongips)|178|178|18|10.1%|0.1%|
[blocklist_de_bots](#blocklist_de_bots)|3238|3238|18|0.5%|0.1%|
[php_commenters](#php_commenters)|281|281|17|6.0%|0.1%|
[bruteforceblocker](#bruteforceblocker)|2212|2212|15|0.6%|0.1%|
[proxz](#proxz)|322|322|11|3.4%|0.0%|
[shunlist](#shunlist)|1195|1195|7|0.5%|0.0%|
[openbl_1d](#openbl_1d)|187|187|5|2.6%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|4|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|1922|1922|3|0.1%|0.0%|
[et_tor](#et_tor)|6470|6470|3|0.0%|0.0%|
[dm_tor](#dm_tor)|6431|6431|3|0.0%|0.0%|
[bm_tor](#bm_tor)|6397|6397|3|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|2|0.0%|0.0%|
[dshield](#dshield)|19|5120|2|0.0%|0.0%|
[ciarmy](#ciarmy)|331|331|2|0.6%|0.0%|
[voipbl](#voipbl)|10327|10736|1|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|1929|1929|1|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|1|0.1%|0.0%|

## blocklist_de_sip

[Blocklist.de](https://www.blocklist.de/) All IP addresses that tried to login in a SIP, VOIP or Asterisk Server and are included in the IPs list from [infiltrated.net](www.infiltrated.net)

Source is downloaded from [this link](http://lists.blocklist.de/lists/sip.txt).

The last time downloaded was found to be dated: Sun May 31 08:42:16 UTC 2015.

The ipset `blocklist_de_sip` has **106** entries, **106** unique IPs.

The following table shows the overlaps of `blocklist_de_sip` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_sip`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_sip`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_sip`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|21934|21934|87|0.3%|82.0%|
[voipbl](#voipbl)|10327|10736|38|0.3%|35.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|19|0.0%|17.9%|
[alienvault_reputation](#alienvault_reputation)|173978|173978|19|0.0%|17.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|12|0.0%|11.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|5|0.0%|4.7%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|2|0.0%|1.8%|
[spamhaus_drop](#spamhaus_drop)|650|18333440|1|0.0%|0.9%|
[shunlist](#shunlist)|1195|1195|1|0.0%|0.9%|
[et_botcc](#et_botcc)|501|501|1|0.1%|0.9%|
[et_block](#et_block)|986|18056524|1|0.0%|0.9%|

## blocklist_de_ssh

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service SSH.

Source is downloaded from [this link](http://lists.blocklist.de/lists/ssh.txt).

The last time downloaded was found to be dated: Sun May 31 08:42:04 UTC 2015.

The ipset `blocklist_de_ssh` has **1731** entries, **1731** unique IPs.

The following table shows the overlaps of `blocklist_de_ssh` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_ssh`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_ssh`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_ssh`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|21934|21934|1731|7.8%|100.0%|
[alienvault_reputation](#alienvault_reputation)|173978|173978|952|0.5%|54.9%|
[openbl_60d](#openbl_60d)|7635|7635|831|10.8%|48.0%|
[openbl_30d](#openbl_30d)|3280|3280|772|23.5%|44.5%|
[bruteforceblocker](#bruteforceblocker)|2212|2212|717|32.4%|41.4%|
[et_compromised](#et_compromised)|2367|2367|670|28.3%|38.7%|
[openbl_7d](#openbl_7d)|909|909|525|57.7%|30.3%|
[shunlist](#shunlist)|1195|1195|409|34.2%|23.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|181|0.0%|10.4%|
[openbl_1d](#openbl_1d)|187|187|162|86.6%|9.3%|
[spamhaus_drop](#spamhaus_drop)|650|18333440|115|0.0%|6.6%|
[et_block](#et_block)|986|18056524|113|0.0%|6.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|90|0.0%|5.1%|
[dshield](#dshield)|19|5120|71|1.3%|4.1%|
[blocklist_de_strongips](#blocklist_de_strongips)|178|178|50|28.0%|2.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|31|0.0%|1.7%|
[stopforumspam_30d](#stopforumspam_30d)|92135|92135|7|0.0%|0.4%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|7|0.0%|0.4%|
[spamhaus_edrop](#spamhaus_edrop)|56|421632|6|0.0%|0.3%|
[voipbl](#voipbl)|10327|10736|3|0.0%|0.1%|
[stopforumspam_7d](#stopforumspam_7d)|31070|31070|3|0.0%|0.1%|
[ciarmy](#ciarmy)|331|331|3|0.9%|0.1%|
[xroxy](#xroxy)|1983|1983|1|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|1922|1922|1|0.0%|0.0%|
[proxz](#proxz)|322|322|1|0.3%|0.0%|
[php_spammers](#php_spammers)|417|417|1|0.2%|0.0%|
[nixspam](#nixspam)|20463|20463|1|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.0%|

## blocklist_de_strongips

[Blocklist.de](https://www.blocklist.de/) All IPs which are older then 2 month and have more then 5.000 attacks.

Source is downloaded from [this link](http://lists.blocklist.de/lists/strongips.txt).

The last time downloaded was found to be dated: Sun May 31 08:42:22 UTC 2015.

The ipset `blocklist_de_strongips` has **178** entries, **178** unique IPs.

The following table shows the overlaps of `blocklist_de_strongips` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_strongips`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_strongips`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_strongips`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|21934|21934|178|0.8%|100.0%|
[stopforumspam_30d](#stopforumspam_30d)|92135|92135|115|0.1%|64.6%|
[blocklist_de_bots](#blocklist_de_bots)|3238|3238|108|3.3%|60.6%|
[stopforumspam_7d](#stopforumspam_7d)|31070|31070|106|0.3%|59.5%|
[stopforumspam_1d](#stopforumspam_1d)|6802|6802|90|1.3%|50.5%|
[alienvault_reputation](#alienvault_reputation)|173978|173978|58|0.0%|32.5%|
[blocklist_de_ssh](#blocklist_de_ssh)|1731|1731|50|2.8%|28.0%|
[openbl_60d](#openbl_60d)|7635|7635|49|0.6%|27.5%|
[openbl_30d](#openbl_30d)|3280|3280|47|1.4%|26.4%|
[openbl_7d](#openbl_7d)|909|909|46|5.0%|25.8%|
[shunlist](#shunlist)|1195|1195|42|3.5%|23.5%|
[blocklist_de_apache](#blocklist_de_apache)|13637|13637|33|0.2%|18.5%|
[php_commenters](#php_commenters)|281|281|30|10.6%|16.8%|
[openbl_1d](#openbl_1d)|187|187|23|12.2%|12.9%|
[blocklist_de_mail](#blocklist_de_mail)|14118|14118|18|0.1%|10.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|15|0.0%|8.4%|
[spamhaus_edrop](#spamhaus_edrop)|56|421632|10|0.0%|5.6%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1281|1281|10|0.7%|5.6%|
[xroxy](#xroxy)|1983|1983|6|0.3%|3.3%|
[spamhaus_drop](#spamhaus_drop)|650|18333440|5|0.0%|2.8%|
[proxyrss](#proxyrss)|1784|1784|5|0.2%|2.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|5|0.0%|2.8%|
[et_block](#et_block)|986|18056524|5|0.0%|2.8%|
[ri_web_proxies](#ri_web_proxies)|5126|5126|4|0.0%|2.2%|
[php_spammers](#php_spammers)|417|417|4|0.9%|2.2%|
[nixspam](#nixspam)|20463|20463|3|0.0%|1.6%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|1.6%|
[proxz](#proxz)|322|322|2|0.6%|1.1%|
[php_harvesters](#php_harvesters)|257|257|2|0.7%|1.1%|
[php_dictionary](#php_dictionary)|433|433|2|0.4%|1.1%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|1|0.0%|0.5%|
[blocklist_de_imap](#blocklist_de_imap)|666|666|1|0.1%|0.5%|
[blocklist_de_ftp](#blocklist_de_ftp)|195|195|1|0.5%|0.5%|

## bm_tor

[torstatus.blutmagie.de](https://torstatus.blutmagie.de) list of all TOR network servers

Source is downloaded from [this link](https://torstatus.blutmagie.de/ip_list_all.php/Tor_ip_list_ALL.csv).

The last time downloaded was found to be dated: Sun May 31 09:00:10 UTC 2015.

The ipset `bm_tor` has **6397** entries, **6397** unique IPs.

The following table shows the overlaps of `bm_tor` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `bm_tor`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `bm_tor`.
- ` this % ` is the percentage **of this ipset (`bm_tor`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[dm_tor](#dm_tor)|6431|6431|6350|98.7%|99.2%|
[et_tor](#et_tor)|6470|6470|5649|87.3%|88.3%|
[snort_ipfilter](#snort_ipfilter)|1922|1922|980|50.9%|15.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|614|0.0%|9.5%|
[stopforumspam_30d](#stopforumspam_30d)|92135|92135|584|0.6%|9.1%|
[stopforumspam_7d](#stopforumspam_7d)|31070|31070|475|1.5%|7.4%|
[stopforumspam_1d](#stopforumspam_1d)|6802|6802|343|5.0%|5.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|185|0.0%|2.8%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|172|46.2%|2.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|158|0.0%|2.4%|
[alienvault_reputation](#alienvault_reputation)|173978|173978|47|0.0%|0.7%|
[php_commenters](#php_commenters)|281|281|28|9.9%|0.4%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|21|0.0%|0.3%|
[openbl_60d](#openbl_60d)|7635|7635|20|0.2%|0.3%|
[php_harvesters](#php_harvesters)|257|257|7|2.7%|0.1%|
[php_spammers](#php_spammers)|417|417|6|1.4%|0.0%|
[nixspam](#nixspam)|20463|20463|6|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|5126|5126|4|0.0%|0.0%|
[php_dictionary](#php_dictionary)|433|433|4|0.9%|0.0%|
[xroxy](#xroxy)|1983|1983|3|0.1%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|0.0%|
[et_block](#et_block)|986|18056524|3|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14118|14118|3|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13637|13637|3|0.0%|0.0%|
[blocklist_de](#blocklist_de)|21934|21934|3|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|650|18333440|2|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|1929|1929|2|0.1%|0.0%|
[voipbl](#voipbl)|10327|10736|1|0.0%|0.0%|
[shunlist](#shunlist)|1195|1195|1|0.0%|0.0%|
[proxz](#proxz)|322|322|1|0.3%|0.0%|

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
[fullbogons](#fullbogons)|3642|670590424|592708608|88.3%|100.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|4194304|3.0%|0.7%|
[voipbl](#voipbl)|10327|10736|319|2.9%|0.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|5|0.0%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92135|92135|1|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2212|2212|1|0.0%|0.0%|

## bruteforceblocker

[danger.rulez.sk](http://danger.rulez.sk/) IPs detected by [bruteforceblocker](http://danger.rulez.sk/index.php/bruteforceblocker/) (fail2ban alternative for SSH on OpenBSD). This is an automatically generated list from users reporting failed authentication attempts. An IP seems to be included if 3 or more users report it. Its retention pocily seems 30 days.

Source is downloaded from [this link](http://danger.rulez.sk/projects/bruteforceblocker/blist.php).

The last time downloaded was found to be dated: Sun May 31 08:09:08 UTC 2015.

The ipset `bruteforceblocker` has **2212** entries, **2212** unique IPs.

The following table shows the overlaps of `bruteforceblocker` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `bruteforceblocker`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `bruteforceblocker`.
- ` this % ` is the percentage **of this ipset (`bruteforceblocker`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[et_compromised](#et_compromised)|2367|2367|2135|90.1%|96.5%|
[alienvault_reputation](#alienvault_reputation)|173978|173978|1435|0.8%|64.8%|
[openbl_60d](#openbl_60d)|7635|7635|1334|17.4%|60.3%|
[openbl_30d](#openbl_30d)|3280|3280|1262|38.4%|57.0%|
[blocklist_de](#blocklist_de)|21934|21934|736|3.3%|33.2%|
[blocklist_de_ssh](#blocklist_de_ssh)|1731|1731|717|41.4%|32.4%|
[openbl_7d](#openbl_7d)|909|909|510|56.1%|23.0%|
[shunlist](#shunlist)|1195|1195|504|42.1%|22.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|212|0.0%|9.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|124|0.0%|5.6%|
[openbl_1d](#openbl_1d)|187|187|110|58.8%|4.9%|
[et_block](#et_block)|986|18056524|103|0.0%|4.6%|
[spamhaus_drop](#spamhaus_drop)|650|18333440|102|0.0%|4.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|65|0.0%|2.9%|
[dshield](#dshield)|19|5120|61|1.1%|2.7%|
[blocklist_de_mail](#blocklist_de_mail)|14118|14118|15|0.1%|0.6%|
[blocklist_de_imap](#blocklist_de_imap)|666|666|12|1.8%|0.5%|
[stopforumspam_30d](#stopforumspam_30d)|92135|92135|6|0.0%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|5|0.0%|0.2%|
[stopforumspam_7d](#stopforumspam_7d)|31070|31070|3|0.0%|0.1%|
[blocklist_de_apache](#blocklist_de_apache)|13637|13637|3|0.0%|0.1%|
[proxz](#proxz)|322|322|2|0.6%|0.0%|
[zeus_badips](#zeus_badips)|229|229|1|0.4%|0.0%|
[zeus](#zeus)|264|264|1|0.3%|0.0%|
[xroxy](#xroxy)|1983|1983|1|0.0%|0.0%|
[voipbl](#voipbl)|10327|10736|1|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6802|6802|1|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|1922|1922|1|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.0%|
[fullbogons](#fullbogons)|3642|670590424|1|0.0%|0.0%|
[bogons](#bogons)|13|592708608|1|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3238|3238|1|0.0%|0.0%|

## ciarmy

[CIArmy.com](http://ciarmy.com/) IPs with poor Rogue Packet score that have not yet been identified as malicious by the community

Source is downloaded from [this link](http://cinsscore.com/list/ci-badguys.txt).

The last time downloaded was found to be dated: Sun May 31 07:15:16 UTC 2015.

The ipset `ciarmy` has **331** entries, **331** unique IPs.

The following table shows the overlaps of `ciarmy` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ciarmy`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ciarmy`.
- ` this % ` is the percentage **of this ipset (`ciarmy`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[alienvault_reputation](#alienvault_reputation)|173978|173978|322|0.1%|97.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|55|0.0%|16.6%|
[blocklist_de](#blocklist_de)|21934|21934|46|0.2%|13.8%|
[blocklist_de_apache](#blocklist_de_apache)|13637|13637|40|0.2%|12.0%|
[shunlist](#shunlist)|1195|1195|23|1.9%|6.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|21|0.0%|6.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|11|0.0%|3.3%|
[voipbl](#voipbl)|10327|10736|4|0.0%|1.2%|
[blocklist_de_ssh](#blocklist_de_ssh)|1731|1731|3|0.1%|0.9%|
[blocklist_de_mail](#blocklist_de_mail)|14118|14118|2|0.0%|0.6%|
[blocklist_de_imap](#blocklist_de_imap)|666|666|2|0.3%|0.6%|
[stopforumspam_30d](#stopforumspam_30d)|92135|92135|1|0.0%|0.3%|
[nixspam](#nixspam)|20463|20463|1|0.0%|0.3%|
[blocklist_de_ftp](#blocklist_de_ftp)|195|195|1|0.5%|0.3%|

## cleanmx_viruses

[Clean-MX.de](http://support.clean-mx.de/clean-mx/viruses.php) IPs with viruses

Source is downloaded from [this link](http://support.clean-mx.de/clean-mx/xmlviruses.php?sort=id%20desc&response=alive).

The last time downloaded was found to be dated: Sun May 31 06:00:56 UTC 2015.

The ipset `cleanmx_viruses` has **317** entries, **317** unique IPs.

The following table shows the overlaps of `cleanmx_viruses` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `cleanmx_viruses`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `cleanmx_viruses`.
- ` this % ` is the percentage **of this ipset (`cleanmx_viruses`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|37|0.0%|11.6%|
[malc0de](#malc0de)|407|407|23|5.6%|7.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|14|0.0%|4.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|12|0.0%|3.7%|
[alienvault_reputation](#alienvault_reputation)|173978|173978|4|0.0%|1.2%|
[malwaredomainlist](#malwaredomainlist)|1282|1282|3|0.2%|0.9%|
[snort_ipfilter](#snort_ipfilter)|1922|1922|2|0.1%|0.6%|
[zeus](#zeus)|264|264|1|0.3%|0.3%|
[stopforumspam_30d](#stopforumspam_30d)|92135|92135|1|0.0%|0.3%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.3%|
[et_block](#et_block)|986|18056524|1|0.0%|0.3%|

## dm_tor

[dan.me.uk](https://www.dan.me.uk) dynamic list of TOR exit points

Source is downloaded from [this link](https://www.dan.me.uk/torlist/).

The last time downloaded was found to be dated: Sun May 31 09:00:07 UTC 2015.

The ipset `dm_tor` has **6431** entries, **6431** unique IPs.

The following table shows the overlaps of `dm_tor` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `dm_tor`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `dm_tor`.
- ` this % ` is the percentage **of this ipset (`dm_tor`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[bm_tor](#bm_tor)|6397|6397|6350|99.2%|98.7%|
[et_tor](#et_tor)|6470|6470|5634|87.0%|87.6%|
[snort_ipfilter](#snort_ipfilter)|1922|1922|982|51.0%|15.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|613|0.0%|9.5%|
[stopforumspam_30d](#stopforumspam_30d)|92135|92135|584|0.6%|9.0%|
[stopforumspam_7d](#stopforumspam_7d)|31070|31070|475|1.5%|7.3%|
[stopforumspam_1d](#stopforumspam_1d)|6802|6802|343|5.0%|5.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|184|0.0%|2.8%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|172|46.2%|2.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|157|0.0%|2.4%|
[alienvault_reputation](#alienvault_reputation)|173978|173978|46|0.0%|0.7%|
[php_commenters](#php_commenters)|281|281|28|9.9%|0.4%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|21|0.0%|0.3%|
[openbl_60d](#openbl_60d)|7635|7635|19|0.2%|0.2%|
[php_harvesters](#php_harvesters)|257|257|7|2.7%|0.1%|
[php_spammers](#php_spammers)|417|417|6|1.4%|0.0%|
[nixspam](#nixspam)|20463|20463|6|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|5126|5126|4|0.0%|0.0%|
[php_dictionary](#php_dictionary)|433|433|4|0.9%|0.0%|
[xroxy](#xroxy)|1983|1983|3|0.1%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|0.0%|
[et_block](#et_block)|986|18056524|3|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14118|14118|3|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13637|13637|3|0.0%|0.0%|
[blocklist_de](#blocklist_de)|21934|21934|3|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|650|18333440|2|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|1929|1929|2|0.1%|0.0%|
[voipbl](#voipbl)|10327|10736|1|0.0%|0.0%|
[shunlist](#shunlist)|1195|1195|1|0.0%|0.0%|
[proxz](#proxz)|322|322|1|0.3%|0.0%|

## dshield

[DShield.org](https://dshield.org/) top 20 attacking class C (/24) subnets over the last three days - **excellent list**

Source is downloaded from [this link](http://feeds.dshield.org/block.txt).

The last time downloaded was found to be dated: Sun May 31 06:56:41 UTC 2015.

The ipset `dshield` has **19** entries, **5120** unique IPs.

The following table shows the overlaps of `dshield` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `dshield`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `dshield`.
- ` this % ` is the percentage **of this ipset (`dshield`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[alienvault_reputation](#alienvault_reputation)|173978|173978|3076|1.7%|60.0%|
[et_block](#et_block)|986|18056524|1024|0.0%|20.0%|
[spamhaus_drop](#spamhaus_drop)|650|18333440|256|0.0%|5.0%|
[blocklist_de](#blocklist_de)|21934|21934|75|0.3%|1.4%|
[openbl_60d](#openbl_60d)|7635|7635|73|0.9%|1.4%|
[openbl_30d](#openbl_30d)|3280|3280|72|2.1%|1.4%|
[shunlist](#shunlist)|1195|1195|71|5.9%|1.3%|
[blocklist_de_ssh](#blocklist_de_ssh)|1731|1731|71|4.1%|1.3%|
[et_compromised](#et_compromised)|2367|2367|61|2.5%|1.1%|
[bruteforceblocker](#bruteforceblocker)|2212|2212|61|2.7%|1.1%|
[openbl_7d](#openbl_7d)|909|909|41|4.5%|0.8%|
[blocklist_de_mail](#blocklist_de_mail)|14118|14118|2|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13637|13637|2|0.0%|0.0%|
[openbl_1d](#openbl_1d)|187|187|1|0.5%|0.0%|
[nixspam](#nixspam)|20463|20463|1|0.0%|0.0%|
[malc0de](#malc0de)|407|407|1|0.2%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|666|666|1|0.1%|0.0%|

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
[spamhaus_drop](#spamhaus_drop)|650|18333440|17920256|97.7%|99.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|8402471|2.4%|46.5%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|7211008|78.5%|39.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|2133460|0.2%|11.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|196184|0.1%|1.0%|
[fullbogons](#fullbogons)|3642|670590424|20480|0.0%|0.1%|
[alienvault_reputation](#alienvault_reputation)|173978|173978|6045|3.4%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1040|0.3%|0.0%|
[dshield](#dshield)|19|5120|1024|20.0%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92135|92135|747|0.8%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|421632|517|0.1%|0.0%|
[snort_ipfilter](#snort_ipfilter)|1922|1922|290|15.0%|0.0%|
[zeus](#zeus)|264|264|261|98.8%|0.0%|
[openbl_60d](#openbl_60d)|7635|7635|241|3.1%|0.0%|
[zeus_badips](#zeus_badips)|229|229|228|99.5%|0.0%|
[nixspam](#nixspam)|20463|20463|223|1.0%|0.0%|
[openbl_30d](#openbl_30d)|3280|3280|207|6.3%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|31070|31070|202|0.6%|0.0%|
[blocklist_de](#blocklist_de)|21934|21934|190|0.8%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1731|1731|113|6.5%|0.0%|
[shunlist](#shunlist)|1195|1195|111|9.2%|0.0%|
[et_compromised](#et_compromised)|2367|2367|103|4.3%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2212|2212|103|4.6%|0.0%|
[openbl_7d](#openbl_7d)|909|909|85|9.3%|0.0%|
[feodo](#feodo)|71|71|67|94.3%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3238|3238|48|1.4%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1282|1282|28|2.1%|0.0%|
[sslbl](#sslbl)|357|357|27|7.5%|0.0%|
[php_commenters](#php_commenters)|281|281|24|8.5%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14118|14118|22|0.1%|0.0%|
[voipbl](#voipbl)|10327|10736|17|0.1%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|666|666|17|2.5%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6802|6802|14|0.2%|0.0%|
[palevo](#palevo)|13|13|13|100.0%|0.0%|
[openbl_1d](#openbl_1d)|187|187|11|5.8%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|7|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|6|0.4%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13637|13637|6|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|178|178|5|2.8%|0.0%|
[php_dictionary](#php_dictionary)|433|433|4|0.9%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1281|1281|4|0.3%|0.0%|
[malc0de](#malc0de)|407|407|3|0.7%|0.0%|
[et_tor](#et_tor)|6470|6470|3|0.0%|0.0%|
[dm_tor](#dm_tor)|6431|6431|3|0.0%|0.0%|
[bm_tor](#bm_tor)|6397|6397|3|0.0%|0.0%|
[php_spammers](#php_spammers)|417|417|2|0.4%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|2|0.2%|0.0%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.0%|
[et_botcc](#et_botcc)|501|501|1|0.1%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|317|317|1|0.3%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|106|106|1|0.9%|0.0%|

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
[alienvault_reputation](#alienvault_reputation)|173978|173978|3|0.0%|0.5%|
[spamhaus_drop](#spamhaus_drop)|650|18333440|1|0.0%|0.1%|
[malwaredomainlist](#malwaredomainlist)|1282|1282|1|0.0%|0.1%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.1%|
[et_block](#et_block)|986|18056524|1|0.0%|0.1%|
[blocklist_de_sip](#blocklist_de_sip)|106|106|1|0.9%|0.1%|

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
[bruteforceblocker](#bruteforceblocker)|2212|2212|2135|96.5%|90.1%|
[alienvault_reputation](#alienvault_reputation)|173978|173978|1533|0.8%|64.7%|
[openbl_60d](#openbl_60d)|7635|7635|1423|18.6%|60.1%|
[openbl_30d](#openbl_30d)|3280|3280|1319|40.2%|55.7%|
[blocklist_de](#blocklist_de)|21934|21934|692|3.1%|29.2%|
[blocklist_de_ssh](#blocklist_de_ssh)|1731|1731|670|38.7%|28.3%|
[openbl_7d](#openbl_7d)|909|909|510|56.1%|21.5%|
[shunlist](#shunlist)|1195|1195|507|42.4%|21.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|227|0.0%|9.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|140|0.0%|5.9%|
[openbl_1d](#openbl_1d)|187|187|107|57.2%|4.5%|
[et_block](#et_block)|986|18056524|103|0.0%|4.3%|
[spamhaus_drop](#spamhaus_drop)|650|18333440|102|0.0%|4.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|70|0.0%|2.9%|
[dshield](#dshield)|19|5120|61|1.1%|2.5%|
[blocklist_de_mail](#blocklist_de_mail)|14118|14118|18|0.1%|0.7%|
[blocklist_de_imap](#blocklist_de_imap)|666|666|15|2.2%|0.6%|
[stopforumspam_30d](#stopforumspam_30d)|92135|92135|6|0.0%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|5|0.0%|0.2%|
[stopforumspam_7d](#stopforumspam_7d)|31070|31070|3|0.0%|0.1%|
[blocklist_de_apache](#blocklist_de_apache)|13637|13637|3|0.0%|0.1%|
[proxz](#proxz)|322|322|2|0.6%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.0%|
[zeus_badips](#zeus_badips)|229|229|1|0.4%|0.0%|
[zeus](#zeus)|264|264|1|0.3%|0.0%|
[xroxy](#xroxy)|1983|1983|1|0.0%|0.0%|
[voipbl](#voipbl)|10327|10736|1|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6802|6802|1|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|1922|1922|1|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3238|3238|1|0.0%|0.0%|

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
[bm_tor](#bm_tor)|6397|6397|5649|88.3%|87.3%|
[dm_tor](#dm_tor)|6431|6431|5634|87.6%|87.0%|
[snort_ipfilter](#snort_ipfilter)|1922|1922|1071|55.7%|16.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|619|0.0%|9.5%|
[stopforumspam_30d](#stopforumspam_30d)|92135|92135|618|0.6%|9.5%|
[stopforumspam_7d](#stopforumspam_7d)|31070|31070|500|1.6%|7.7%|
[stopforumspam_1d](#stopforumspam_1d)|6802|6802|348|5.1%|5.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|184|0.0%|2.8%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|179|48.1%|2.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|163|0.0%|2.5%|
[alienvault_reputation](#alienvault_reputation)|173978|173978|48|0.0%|0.7%|
[php_commenters](#php_commenters)|281|281|29|10.3%|0.4%|
[openbl_60d](#openbl_60d)|7635|7635|21|0.2%|0.3%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|21|0.0%|0.3%|
[php_harvesters](#php_harvesters)|257|257|7|2.7%|0.1%|
[php_spammers](#php_spammers)|417|417|6|1.4%|0.0%|
[nixspam](#nixspam)|20463|20463|6|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|5126|5126|4|0.0%|0.0%|
[php_dictionary](#php_dictionary)|433|433|4|0.9%|0.0%|
[xroxy](#xroxy)|1983|1983|3|0.1%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|0.0%|
[et_block](#et_block)|986|18056524|3|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14118|14118|3|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13637|13637|3|0.0%|0.0%|
[blocklist_de](#blocklist_de)|21934|21934|3|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|650|18333440|2|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|1929|1929|2|0.1%|0.0%|
[voipbl](#voipbl)|10327|10736|1|0.0%|0.0%|
[shunlist](#shunlist)|1195|1195|1|0.0%|0.0%|
[proxz](#proxz)|322|322|1|0.3%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|

## feodo

[Abuse.ch Feodo tracker](https://feodotracker.abuse.ch) trojan includes IPs which are being used by Feodo (also known as Cridex or Bugat) which commits ebanking fraud - **excellent list**

Source is downloaded from [this link](https://feodotracker.abuse.ch/blocklist/?download=ipblocklist).

The last time downloaded was found to be dated: Sun May 31 09:00:25 UTC 2015.

The ipset `feodo` has **71** entries, **71** unique IPs.

The following table shows the overlaps of `feodo` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `feodo`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `feodo`.
- ` this % ` is the percentage **of this ipset (`feodo`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[et_block](#et_block)|986|18056524|67|0.0%|94.3%|
[snort_ipfilter](#snort_ipfilter)|1922|1922|53|2.7%|74.6%|
[sslbl](#sslbl)|357|357|26|7.2%|36.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|6|0.0%|8.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|3|0.0%|4.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|3|0.0%|4.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|1.4%|
[alienvault_reputation](#alienvault_reputation)|173978|173978|1|0.0%|1.4%|

## fullbogons

[Team-Cymru.org](http://www.team-cymru.org) IP space that has been allocated to an RIR, but not assigned by that RIR to an actual ISP or other end-user - **excellent list - use it only your internet interface**

Source is downloaded from [this link](http://www.team-cymru.org/Services/Bogons/fullbogons-ipv4.txt).

The last time downloaded was found to be dated: Sat May 30 09:35:11 UTC 2015.

The ipset `fullbogons` has **3642** entries, **670590424** unique IPs.

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
[spamhaus_drop](#spamhaus_drop)|650|18333440|20480|0.1%|0.0%|
[et_block](#et_block)|986|18056524|20480|0.1%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|890|0.2%|0.0%|
[voipbl](#voipbl)|10327|10736|319|2.9%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|33|2.2%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|14|0.0%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1282|1282|9|0.7%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92135|92135|2|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2212|2212|1|0.0%|0.0%|

## ib_bluetack_badpeers

[iBlocklist.com](https://www.iblocklist.com/) free version of [BlueTack.co.uk](http://www.bluetack.co.uk/) IPs that have been reported for bad deeds in p2p

Source is downloaded from [this link](http://list.iblocklist.com/?list=cwworuawihqvocglcoss&fileformat=p2p&archiveformat=gz).

The last time downloaded was found to be dated: Sun May 31 03:51:18 UTC 2015.

The ipset `ib_bluetack_badpeers` has **48134** entries, **48134** unique IPs.

The following table shows the overlaps of `ib_bluetack_badpeers` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ib_bluetack_badpeers`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ib_bluetack_badpeers`.
- ` this % ` is the percentage **of this ipset (`ib_bluetack_badpeers`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|1172|0.0%|2.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|406|0.0%|0.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|230|0.0%|0.4%|
[stopforumspam_30d](#stopforumspam_30d)|92135|92135|15|0.0%|0.0%|
[fullbogons](#fullbogons)|3642|670590424|14|0.0%|0.0%|
[alienvault_reputation](#alienvault_reputation)|173978|173978|14|0.0%|0.0%|
[nixspam](#nixspam)|20463|20463|12|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|11|1.6%|0.0%|
[et_block](#et_block)|986|18056524|7|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|650|18333440|6|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|4|0.0%|0.0%|
[xroxy](#xroxy)|1983|1983|3|0.1%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|31070|31070|3|0.0%|0.0%|
[voipbl](#voipbl)|10327|10736|2|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|2|0.7%|0.0%|
[php_dictionary](#php_dictionary)|433|433|2|0.4%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14118|14118|2|0.0%|0.0%|
[blocklist_de](#blocklist_de)|21934|21934|2|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6802|6802|1|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|5126|5126|1|0.0%|0.0%|
[proxyrss](#proxyrss)|1784|1784|1|0.0%|0.0%|
[php_spammers](#php_spammers)|417|417|1|0.2%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|

## ib_bluetack_hijacked

[iBlocklist.com](https://www.iblocklist.com/) free version of [BlueTack.co.uk](http://www.bluetack.co.uk/) hijacked IP-Blocks Hijacked IP space are IP blocks that are being used without permission

Source is downloaded from [this link](http://list.iblocklist.com/?list=usrcshglbiilevmyfhse&fileformat=p2p&archiveformat=gz).

The last time downloaded was found to be dated: Sun May 31 04:20:01 UTC 2015.

The ipset `ib_bluetack_hijacked` has **535** entries, **9177856** unique IPs.

The following table shows the overlaps of `ib_bluetack_hijacked` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ib_bluetack_hijacked`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ib_bluetack_hijacked`.
- ` this % ` is the percentage **of this ipset (`ib_bluetack_hijacked`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[et_block](#et_block)|986|18056524|7211008|39.9%|78.5%|
[spamhaus_drop](#spamhaus_drop)|650|18333440|7079936|38.6%|77.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|2526625|0.7%|27.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|904796|0.1%|9.8%|
[fullbogons](#fullbogons)|3642|670590424|565248|0.0%|6.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|145472|0.1%|1.5%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1036|0.3%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92135|92135|752|0.8%|0.0%|
[alienvault_reputation](#alienvault_reputation)|173978|173978|519|0.2%|0.0%|
[nixspam](#nixspam)|20463|20463|222|1.0%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|31070|31070|192|0.6%|0.0%|
[blocklist_de](#blocklist_de)|21934|21934|64|0.2%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3238|3238|53|1.6%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1282|1282|27|2.1%|0.0%|
[openbl_60d](#openbl_60d)|7635|7635|19|0.2%|0.0%|
[openbl_30d](#openbl_30d)|3280|3280|14|0.4%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6802|6802|13|0.1%|0.0%|
[snort_ipfilter](#snort_ipfilter)|1922|1922|11|0.5%|0.0%|
[openbl_7d](#openbl_7d)|909|909|11|1.2%|0.0%|
[zeus_badips](#zeus_badips)|229|229|10|4.3%|0.0%|
[zeus](#zeus)|264|264|10|3.7%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|7|0.4%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1731|1731|7|0.4%|0.0%|
[et_compromised](#et_compromised)|2367|2367|5|0.2%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2212|2212|5|0.2%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14118|14118|4|0.0%|0.0%|
[shunlist](#shunlist)|1195|1195|3|0.2%|0.0%|
[openbl_1d](#openbl_1d)|187|187|3|1.6%|0.0%|
[et_tor](#et_tor)|6470|6470|3|0.0%|0.0%|
[dm_tor](#dm_tor)|6431|6431|3|0.0%|0.0%|
[bm_tor](#bm_tor)|6397|6397|3|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|178|178|3|1.6%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|666|666|3|0.4%|0.0%|
[php_spammers](#php_spammers)|417|417|2|0.4%|0.0%|
[php_dictionary](#php_dictionary)|433|433|2|0.4%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|2|0.2%|0.0%|
[voipbl](#voipbl)|10327|10736|1|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.0%|
[php_commenters](#php_commenters)|281|281|1|0.3%|0.0%|
[et_botcc](#et_botcc)|501|501|1|0.1%|0.0%|

## ib_bluetack_level1

[iBlocklist.com](https://www.iblocklist.com/) free version of [BlueTack.co.uk](http://www.bluetack.co.uk/) Level 1 (for use in p2p): Companies or organizations who are clearly involved with trying to stop filesharing (e.g. Baytsp, MediaDefender, Mediasentry a.o.). Companies which anti-p2p activity has been seen from. Companies that produce or have a strong financial interest in copyrighted material (e.g. music, movie, software industries a.o.). Government ranges or companies that have a strong financial interest in doing work for governments. Legal industry ranges. IPs or ranges of ISPs from which anti-p2p activity has been observed. Basically this list will block all kinds of internet connections that most people would rather not have during their internet travels.

Source is downloaded from [this link](http://list.iblocklist.com/?list=ydxerpxkpcfqjaybcssw&fileformat=p2p&archiveformat=gz).

The last time downloaded was found to be dated: Sat May 30 09:51:02 UTC 2015.

The ipset `ib_bluetack_level1` has **218309** entries, **764987411** unique IPs.

The following table shows the overlaps of `ib_bluetack_level1` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ib_bluetack_level1`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ib_bluetack_level1`.
- ` this % ` is the percentage **of this ipset (`ib_bluetack_level1`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|16300309|4.6%|2.1%|
[spamhaus_drop](#spamhaus_drop)|650|18333440|2272266|12.3%|0.2%|
[et_block](#et_block)|986|18056524|2133460|11.8%|0.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|1354348|0.9%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|904796|9.8%|0.1%|
[fullbogons](#fullbogons)|3642|670590424|234359|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|421632|33155|7.8%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|13248|3.9%|0.0%|
[alienvault_reputation](#alienvault_reputation)|173978|173978|4707|2.7%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92135|92135|1523|1.6%|0.0%|
[blocklist_de](#blocklist_de)|21934|21934|1443|6.5%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14118|14118|1319|9.3%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13637|13637|1305|9.5%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|31070|31070|567|1.8%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|406|0.8%|0.0%|
[voipbl](#voipbl)|10327|10736|295|2.7%|0.0%|
[nixspam](#nixspam)|20463|20463|249|1.2%|0.0%|
[openbl_60d](#openbl_60d)|7635|7635|173|2.2%|0.0%|
[et_tor](#et_tor)|6470|6470|163|2.5%|0.0%|
[bm_tor](#bm_tor)|6397|6397|158|2.4%|0.0%|
[dm_tor](#dm_tor)|6431|6431|157|2.4%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6802|6802|146|2.1%|0.0%|
[ri_web_proxies](#ri_web_proxies)|5126|5126|113|2.2%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|97|6.6%|0.0%|
[et_compromised](#et_compromised)|2367|2367|70|2.9%|0.0%|
[openbl_30d](#openbl_30d)|3280|3280|68|2.0%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1282|1282|66|5.1%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|1929|1929|65|3.3%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2212|2212|65|2.9%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3238|3238|59|1.8%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|58|8.6%|0.0%|
[xroxy](#xroxy)|1983|1983|56|2.8%|0.0%|
[snort_ipfilter](#snort_ipfilter)|1922|1922|47|2.4%|0.0%|
[proxyrss](#proxyrss)|1784|1784|46|2.5%|0.0%|
[et_botcc](#et_botcc)|501|501|40|7.9%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1731|1731|31|1.7%|0.0%|
[shunlist](#shunlist)|1195|1195|24|2.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|17|4.5%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1281|1281|17|1.3%|0.0%|
[openbl_7d](#openbl_7d)|909|909|16|1.7%|0.0%|
[proxz](#proxz)|322|322|15|4.6%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|666|666|15|2.2%|0.0%|
[malc0de](#malc0de)|407|407|12|2.9%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|317|317|12|3.7%|0.0%|
[ciarmy](#ciarmy)|331|331|11|3.3%|0.0%|
[php_dictionary](#php_dictionary)|433|433|9|2.0%|0.0%|
[zeus](#zeus)|264|264|7|2.6%|0.0%|
[php_harvesters](#php_harvesters)|257|257|7|2.7%|0.0%|
[php_spammers](#php_spammers)|417|417|5|1.1%|0.0%|
[php_commenters](#php_commenters)|281|281|5|1.7%|0.0%|
[bogons](#bogons)|13|592708608|5|0.0%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|106|106|5|4.7%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|195|195|5|2.5%|0.0%|
[zeus_badips](#zeus_badips)|229|229|4|1.7%|0.0%|
[sslbl](#sslbl)|357|357|3|0.8%|0.0%|
[feodo](#feodo)|71|71|3|4.2%|0.0%|
[openbl_1d](#openbl_1d)|187|187|1|0.5%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|178|178|1|0.5%|0.0%|

## ib_bluetack_level2

[iBlocklist.com](https://www.iblocklist.com/) free version of BlueTack.co.uk Level 2 (for use in p2p). General corporate ranges. Ranges used by labs or researchers. Proxies.

Source is downloaded from [this link](http://list.iblocklist.com/?list=gyisgnzbhppbvsphucsw&fileformat=p2p&archiveformat=gz).

The last time downloaded was found to be dated: Sun May 31 04:20:35 UTC 2015.

The ipset `ib_bluetack_level2` has **72774** entries, **348707599** unique IPs.

The following table shows the overlaps of `ib_bluetack_level2` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ib_bluetack_level2`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ib_bluetack_level2`.
- ` this % ` is the percentage **of this ipset (`ib_bluetack_level2`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|16300309|2.1%|4.6%|
[spamhaus_drop](#spamhaus_drop)|650|18333440|8598042|46.8%|2.4%|
[et_block](#et_block)|986|18056524|8402471|46.5%|2.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|2830140|2.0%|0.8%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2526625|27.5%|0.7%|
[fullbogons](#fullbogons)|3642|670590424|248319|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|421632|33368|7.9%|0.0%|
[alienvault_reputation](#alienvault_reputation)|173978|173978|8133|4.6%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|7733|2.2%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92135|92135|2487|2.6%|0.0%|
[blocklist_de](#blocklist_de)|21934|21934|1457|6.6%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14118|14118|1125|7.9%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13637|13637|1068|7.8%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|31070|31070|937|3.0%|0.0%|
[nixspam](#nixspam)|20463|20463|578|2.8%|0.0%|
[voipbl](#voipbl)|10327|10736|429|3.9%|0.0%|
[openbl_60d](#openbl_60d)|7635|7635|360|4.7%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6802|6802|242|3.5%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|230|0.4%|0.0%|
[bm_tor](#bm_tor)|6397|6397|185|2.8%|0.0%|
[et_tor](#et_tor)|6470|6470|184|2.8%|0.0%|
[dm_tor](#dm_tor)|6431|6431|184|2.8%|0.0%|
[openbl_30d](#openbl_30d)|3280|3280|180|5.4%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3238|3238|176|5.4%|0.0%|
[ri_web_proxies](#ri_web_proxies)|5126|5126|169|3.2%|0.0%|
[et_compromised](#et_compromised)|2367|2367|140|5.9%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2212|2212|124|5.6%|0.0%|
[xroxy](#xroxy)|1983|1983|96|4.8%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1731|1731|90|5.1%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|1929|1929|79|4.0%|0.0%|
[shunlist](#shunlist)|1195|1195|71|5.9%|0.0%|
[proxyrss](#proxyrss)|1784|1784|71|3.9%|0.0%|
[snort_ipfilter](#snort_ipfilter)|1922|1922|67|3.4%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|45|3.0%|0.0%|
[openbl_7d](#openbl_7d)|909|909|40|4.4%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|666|666|38|5.7%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1281|1281|32|2.4%|0.0%|
[php_spammers](#php_spammers)|417|417|31|7.4%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|28|4.1%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1282|1282|26|2.0%|0.0%|
[malc0de](#malc0de)|407|407|25|6.1%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|21|5.6%|0.0%|
[et_botcc](#et_botcc)|501|501|21|4.1%|0.0%|
[ciarmy](#ciarmy)|331|331|21|6.3%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|317|317|14|4.4%|0.0%|
[proxz](#proxz)|322|322|13|4.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|195|195|13|6.6%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|106|106|12|11.3%|0.0%|
[php_dictionary](#php_dictionary)|433|433|10|2.3%|0.0%|
[zeus](#zeus)|264|264|9|3.4%|0.0%|
[php_commenters](#php_commenters)|281|281|9|3.2%|0.0%|
[zeus_badips](#zeus_badips)|229|229|8|3.4%|0.0%|
[php_harvesters](#php_harvesters)|257|257|7|2.7%|0.0%|
[sslbl](#sslbl)|357|357|6|1.6%|0.0%|
[openbl_1d](#openbl_1d)|187|187|5|2.6%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|178|178|5|2.8%|0.0%|
[feodo](#feodo)|71|71|3|4.2%|0.0%|
[palevo](#palevo)|13|13|2|15.3%|0.0%|

## ib_bluetack_level3

[iBlocklist.com](https://www.iblocklist.com/) free version of BlueTack.co.uk Level 3 (for use in p2p). Many portal-type websites. ISP ranges that may be dodgy for some reason. Ranges that belong to an individual, but which have not been determined to be used by a particular company. Ranges for things that are unusual in some way. The L3 list is aka the paranoid list.

Source is downloaded from [this link](http://list.iblocklist.com/?list=uwnukjqktoggdknzrhgh&fileformat=p2p&archiveformat=gz).

The last time downloaded was found to be dated: Sun May 31 04:20:05 UTC 2015.

The ipset `ib_bluetack_level3` has **17802** entries, **139104824** unique IPs.

The following table shows the overlaps of `ib_bluetack_level3` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ib_bluetack_level3`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ib_bluetack_level3`.
- ` this % ` is the percentage **of this ipset (`ib_bluetack_level3`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[fullbogons](#fullbogons)|3642|670590424|4233775|0.6%|3.0%|
[bogons](#bogons)|13|592708608|4194304|0.7%|3.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|2830140|0.8%|2.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|1354348|0.1%|0.9%|
[spamhaus_edrop](#spamhaus_edrop)|56|421632|270785|64.2%|0.1%|
[et_block](#et_block)|986|18056524|196184|1.0%|0.1%|
[spamhaus_drop](#spamhaus_drop)|650|18333440|195904|1.0%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|145472|1.5%|0.1%|
[alienvault_reputation](#alienvault_reputation)|173978|173978|15145|8.7%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|9231|2.7%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92135|92135|5963|6.4%|0.0%|
[blocklist_de](#blocklist_de)|21934|21934|2777|12.6%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14118|14118|2245|15.9%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13637|13637|2195|16.0%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|31070|31070|2085|6.7%|0.0%|
[voipbl](#voipbl)|10327|10736|1588|14.7%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1172|2.4%|0.0%|
[nixspam](#nixspam)|20463|20463|1110|5.4%|0.0%|
[openbl_60d](#openbl_60d)|7635|7635|712|9.3%|0.0%|
[et_tor](#et_tor)|6470|6470|619|9.5%|0.0%|
[bm_tor](#bm_tor)|6397|6397|614|9.5%|0.0%|
[dm_tor](#dm_tor)|6431|6431|613|9.5%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6802|6802|499|7.3%|0.0%|
[openbl_30d](#openbl_30d)|3280|3280|286|8.7%|0.0%|
[et_compromised](#et_compromised)|2367|2367|227|9.5%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2212|2212|212|9.5%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3238|3238|200|6.1%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1731|1731|181|10.4%|0.0%|
[snort_ipfilter](#snort_ipfilter)|1922|1922|159|8.2%|0.0%|
[ri_web_proxies](#ri_web_proxies)|5126|5126|150|2.9%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1282|1282|146|11.3%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|125|33.6%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|110|7.5%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1281|1281|97|7.5%|0.0%|
[shunlist](#shunlist)|1195|1195|91|7.6%|0.0%|
[openbl_7d](#openbl_7d)|909|909|90|9.9%|0.0%|
[xroxy](#xroxy)|1983|1983|81|4.0%|0.0%|
[malc0de](#malc0de)|407|407|74|18.1%|0.0%|
[et_botcc](#et_botcc)|501|501|74|14.7%|0.0%|
[proxyrss](#proxyrss)|1784|1784|57|3.1%|0.0%|
[ciarmy](#ciarmy)|331|331|55|16.6%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|51|7.5%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|666|666|48|7.2%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|1929|1929|44|2.2%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|317|317|37|11.6%|0.0%|
[proxz](#proxz)|322|322|35|10.8%|0.0%|
[php_spammers](#php_spammers)|417|417|26|6.2%|0.0%|
[php_dictionary](#php_dictionary)|433|433|24|5.5%|0.0%|
[sslbl](#sslbl)|357|357|23|6.4%|0.0%|
[openbl_1d](#openbl_1d)|187|187|20|10.6%|0.0%|
[zeus](#zeus)|264|264|19|7.1%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|106|106|19|17.9%|0.0%|
[php_harvesters](#php_harvesters)|257|257|15|5.8%|0.0%|
[php_commenters](#php_commenters)|281|281|15|5.3%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|178|178|15|8.4%|0.0%|
[zeus_badips](#zeus_badips)|229|229|14|6.1%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|195|195|12|6.1%|0.0%|
[feodo](#feodo)|71|71|6|8.4%|0.0%|
[palevo](#palevo)|13|13|1|7.6%|0.0%|

## ib_bluetack_proxies

[iBlocklist.com](https://www.iblocklist.com/) free version of [BlueTack.co.uk](http://www.bluetack.co.uk/) Open Proxies IPs list (without TOR)

Source is downloaded from [this link](http://list.iblocklist.com/?list=xoebmbyexwuiogmbyprb&fileformat=p2p&archiveformat=gz).

The last time downloaded was found to be dated: Sun May 31 04:20:25 UTC 2015.

The ipset `ib_bluetack_proxies` has **673** entries, **673** unique IPs.

The following table shows the overlaps of `ib_bluetack_proxies` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ib_bluetack_proxies`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ib_bluetack_proxies`.
- ` this % ` is the percentage **of this ipset (`ib_bluetack_proxies`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|58|0.0%|8.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|51|0.0%|7.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|28|0.0%|4.1%|
[stopforumspam_30d](#stopforumspam_30d)|92135|92135|22|0.0%|3.2%|
[xroxy](#xroxy)|1983|1983|13|0.6%|1.9%|
[stopforumspam_7d](#stopforumspam_7d)|31070|31070|11|0.0%|1.6%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|11|0.0%|1.6%|
[ri_web_proxies](#ri_web_proxies)|5126|5126|10|0.1%|1.4%|
[proxyrss](#proxyrss)|1784|1784|10|0.5%|1.4%|
[ri_connect_proxies](#ri_connect_proxies)|1929|1929|6|0.3%|0.8%|
[stopforumspam_1d](#stopforumspam_1d)|6802|6802|5|0.0%|0.7%|
[blocklist_de](#blocklist_de)|21934|21934|4|0.0%|0.5%|
[blocklist_de_bots](#blocklist_de_bots)|3238|3238|3|0.0%|0.4%|
[spamhaus_drop](#spamhaus_drop)|650|18333440|2|0.0%|0.2%|
[nixspam](#nixspam)|20463|20463|2|0.0%|0.2%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2|0.0%|0.2%|
[et_block](#et_block)|986|18056524|2|0.0%|0.2%|
[proxz](#proxz)|322|322|1|0.3%|0.1%|
[php_dictionary](#php_dictionary)|433|433|1|0.2%|0.1%|
[blocklist_de_mail](#blocklist_de_mail)|14118|14118|1|0.0%|0.1%|
[alienvault_reputation](#alienvault_reputation)|173978|173978|1|0.0%|0.1%|

## ib_bluetack_spyware

[iBlocklist.com](https://www.iblocklist.com/) free version of [BlueTack.co.uk](http://www.bluetack.co.uk/) known malicious SPYWARE and ADWARE IP Address ranges

Source is downloaded from [this link](http://list.iblocklist.com/?list=llvtlsjyoyiczbkjsxpf&fileformat=p2p&archiveformat=gz).

The last time downloaded was found to be dated: Sun May 31 03:50:04 UTC 2015.

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
[spamhaus_drop](#spamhaus_drop)|650|18333440|1037|0.0%|0.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1036|0.0%|0.3%|
[fullbogons](#fullbogons)|3642|670590424|890|0.0%|0.2%|
[alienvault_reputation](#alienvault_reputation)|173978|173978|288|0.1%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92135|92135|44|0.0%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1282|1282|25|1.9%|0.0%|
[et_tor](#et_tor)|6470|6470|21|0.3%|0.0%|
[dm_tor](#dm_tor)|6431|6431|21|0.3%|0.0%|
[bm_tor](#bm_tor)|6397|6397|21|0.3%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|31070|31070|20|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|19|1.3%|0.0%|
[snort_ipfilter](#snort_ipfilter)|1922|1922|14|0.7%|0.0%|
[nixspam](#nixspam)|20463|20463|14|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6802|6802|9|0.1%|0.0%|
[openbl_60d](#openbl_60d)|7635|7635|5|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|5|1.3%|0.0%|
[voipbl](#voipbl)|10327|10736|4|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|5126|5126|4|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|4|0.0%|0.0%|
[openbl_30d](#openbl_30d)|3280|3280|3|0.0%|0.0%|
[malc0de](#malc0de)|407|407|3|0.7%|0.0%|
[blocklist_de](#blocklist_de)|21934|21934|3|0.0%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|106|106|2|1.8%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13637|13637|2|0.0%|0.0%|
[zeus_badips](#zeus_badips)|229|229|1|0.4%|0.0%|
[zeus](#zeus)|264|264|1|0.3%|0.0%|
[xroxy](#xroxy)|1983|1983|1|0.0%|0.0%|
[sslbl](#sslbl)|357|357|1|0.2%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|421632|1|0.0%|0.0%|
[shunlist](#shunlist)|1195|1195|1|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.0%|
[php_dictionary](#php_dictionary)|433|433|1|0.2%|0.0%|
[palevo](#palevo)|13|13|1|7.6%|0.0%|
[openbl_7d](#openbl_7d)|909|909|1|0.1%|0.0%|
[feodo](#feodo)|71|71|1|1.4%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|317|317|1|0.3%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2212|2212|1|0.0%|0.0%|
[bogons](#bogons)|13|592708608|1|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1731|1731|1|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14118|14118|1|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1281|1281|1|0.0%|0.0%|

## ib_bluetack_webexploit

[iBlocklist.com](https://www.iblocklist.com/) free version of [BlueTack.co.uk](http://www.bluetack.co.uk/) web server hack and exploit attempts

Source is downloaded from [this link](http://list.iblocklist.com/?list=ghlzqtqxnzctvvajwwag&fileformat=p2p&archiveformat=gz).

The last time downloaded was found to be dated: Sun May 31 03:50:04 UTC 2015.

The ipset `ib_bluetack_webexploit` has **1460** entries, **1460** unique IPs.

The following table shows the overlaps of `ib_bluetack_webexploit` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ib_bluetack_webexploit`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ib_bluetack_webexploit`.
- ` this % ` is the percentage **of this ipset (`ib_bluetack_webexploit`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|110|0.0%|7.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|97|0.0%|6.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|45|0.0%|3.0%|
[fullbogons](#fullbogons)|3642|670590424|33|0.0%|2.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|19|0.0%|1.3%|
[alienvault_reputation](#alienvault_reputation)|173978|173978|8|0.0%|0.5%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|7|0.0%|0.4%|
[spamhaus_drop](#spamhaus_drop)|650|18333440|6|0.0%|0.4%|
[et_block](#et_block)|986|18056524|6|0.0%|0.4%|
[malwaredomainlist](#malwaredomainlist)|1282|1282|3|0.2%|0.2%|
[stopforumspam_7d](#stopforumspam_7d)|31070|31070|2|0.0%|0.1%|
[stopforumspam_30d](#stopforumspam_30d)|92135|92135|2|0.0%|0.1%|
[openbl_60d](#openbl_60d)|7635|7635|2|0.0%|0.1%|
[openbl_30d](#openbl_30d)|3280|3280|2|0.0%|0.1%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|2|0.2%|0.1%|
[et_compromised](#et_compromised)|2367|2367|2|0.0%|0.1%|
[blocklist_de](#blocklist_de)|21934|21934|2|0.0%|0.1%|
[stopforumspam_1d](#stopforumspam_1d)|6802|6802|1|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|1922|1922|1|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|5126|5126|1|0.0%|0.0%|
[openbl_7d](#openbl_7d)|909|909|1|0.1%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1|0.0%|0.0%|
[et_tor](#et_tor)|6470|6470|1|0.0%|0.0%|
[et_botcc](#et_botcc)|501|501|1|0.1%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2212|2212|1|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|178|178|1|0.5%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1731|1731|1|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3238|3238|1|0.0%|0.0%|

## malc0de

[Malc0de.com](http://malc0de.com) malicious IPs of the last 30 days

Source is downloaded from [this link](http://malc0de.com/bl/IP_Blacklist.txt).

The last time downloaded was found to be dated: Sat May 30 13:17:03 UTC 2015.

The ipset `malc0de` has **407** entries, **407** unique IPs.

The following table shows the overlaps of `malc0de` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `malc0de`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `malc0de`.
- ` this % ` is the percentage **of this ipset (`malc0de`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|74|0.0%|18.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|25|0.0%|6.1%|
[cleanmx_viruses](#cleanmx_viruses)|317|317|23|7.2%|5.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|12|0.0%|2.9%|
[alienvault_reputation](#alienvault_reputation)|173978|173978|9|0.0%|2.2%|
[spamhaus_drop](#spamhaus_drop)|650|18333440|4|0.0%|0.9%|
[malwaredomainlist](#malwaredomainlist)|1282|1282|4|0.3%|0.9%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|3|0.0%|0.7%|
[et_block](#et_block)|986|18056524|3|0.0%|0.7%|
[spamhaus_edrop](#spamhaus_edrop)|56|421632|1|0.0%|0.2%|
[dshield](#dshield)|19|5120|1|0.0%|0.2%|

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
[spamhaus_drop](#spamhaus_drop)|650|18333440|29|0.0%|2.2%|
[et_block](#et_block)|986|18056524|28|0.0%|2.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|27|0.0%|2.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|26|0.0%|2.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|25|0.0%|1.9%|
[snort_ipfilter](#snort_ipfilter)|1922|1922|23|1.1%|1.7%|
[fullbogons](#fullbogons)|3642|670590424|9|0.0%|0.7%|
[alienvault_reputation](#alienvault_reputation)|173978|173978|6|0.0%|0.4%|
[malc0de](#malc0de)|407|407|4|0.9%|0.3%|
[stopforumspam_30d](#stopforumspam_30d)|92135|92135|3|0.0%|0.2%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|3|0.2%|0.2%|
[cleanmx_viruses](#cleanmx_viruses)|317|317|3|0.9%|0.2%|
[stopforumspam_7d](#stopforumspam_7d)|31070|31070|2|0.0%|0.1%|
[nixspam](#nixspam)|20463|20463|1|0.0%|0.0%|
[et_botcc](#et_botcc)|501|501|1|0.1%|0.0%|

## maxmind_proxy_fraud

[MaxMind.com](https://www.maxmind.com/en/anonymous-proxy-fraudulent-ip-address-list) list of anonymous proxy fraudelent IP addresses.

Source is downloaded from [this link](https://www.maxmind.com/en/anonymous-proxy-fraudulent-ip-address-list).

The last time downloaded was found to be dated: Sun May 31 05:36:25 UTC 2015.

The ipset `maxmind_proxy_fraud` has **372** entries, **372** unique IPs.

The following table shows the overlaps of `maxmind_proxy_fraud` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `maxmind_proxy_fraud`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `maxmind_proxy_fraud`.
- ` this % ` is the percentage **of this ipset (`maxmind_proxy_fraud`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_30d](#stopforumspam_30d)|92135|92135|236|0.2%|63.4%|
[stopforumspam_7d](#stopforumspam_7d)|31070|31070|200|0.6%|53.7%|
[snort_ipfilter](#snort_ipfilter)|1922|1922|183|9.5%|49.1%|
[et_tor](#et_tor)|6470|6470|179|2.7%|48.1%|
[dm_tor](#dm_tor)|6431|6431|172|2.6%|46.2%|
[bm_tor](#bm_tor)|6397|6397|172|2.6%|46.2%|
[stopforumspam_1d](#stopforumspam_1d)|6802|6802|171|2.5%|45.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|125|0.0%|33.6%|
[php_commenters](#php_commenters)|281|281|28|9.9%|7.5%|
[alienvault_reputation](#alienvault_reputation)|173978|173978|25|0.0%|6.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|21|0.0%|5.6%|
[openbl_60d](#openbl_60d)|7635|7635|18|0.2%|4.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|17|0.0%|4.5%|
[php_harvesters](#php_harvesters)|257|257|6|2.3%|1.6%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|5|0.0%|1.3%|
[ri_web_proxies](#ri_web_proxies)|5126|5126|4|0.0%|1.0%|
[php_spammers](#php_spammers)|417|417|4|0.9%|1.0%|
[php_dictionary](#php_dictionary)|433|433|4|0.9%|1.0%|
[blocklist_de](#blocklist_de)|21934|21934|3|0.0%|0.8%|
[shunlist](#shunlist)|1195|1195|2|0.1%|0.5%|
[blocklist_de_apache](#blocklist_de_apache)|13637|13637|2|0.0%|0.5%|
[xroxy](#xroxy)|1983|1983|1|0.0%|0.2%|
[voipbl](#voipbl)|10327|10736|1|0.0%|0.2%|
[ri_connect_proxies](#ri_connect_proxies)|1929|1929|1|0.0%|0.2%|
[nixspam](#nixspam)|20463|20463|1|0.0%|0.2%|
[blocklist_de_mail](#blocklist_de_mail)|14118|14118|1|0.0%|0.2%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1281|1281|1|0.0%|0.2%|
[blocklist_de_bots](#blocklist_de_bots)|3238|3238|1|0.0%|0.2%|

## nixspam

[NiX Spam](http://www.heise.de/ix/NiX-Spam-DNSBL-and-blacklist-for-download-499637.html) IP addresses that sent spam in the last hour - automatically generated entries without distinguishing open proxies from relays, dialup gateways, and so on. All IPs are removed after 12 hours if there is no spam from there.

Source is downloaded from [this link](http://www.dnsbl.manitu.net/download/nixspam-ip.dump.gz).

The last time downloaded was found to be dated: Sun May 31 09:00:02 UTC 2015.

The ipset `nixspam` has **20463** entries, **20463** unique IPs.

The following table shows the overlaps of `nixspam` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `nixspam`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `nixspam`.
- ` this % ` is the percentage **of this ipset (`nixspam`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|1110|0.0%|5.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|578|0.0%|2.8%|
[blocklist_de](#blocklist_de)|21934|21934|373|1.7%|1.8%|
[blocklist_de_mail](#blocklist_de_mail)|14118|14118|313|2.2%|1.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|249|0.0%|1.2%|
[et_block](#et_block)|986|18056524|223|0.0%|1.0%|
[spamhaus_drop](#spamhaus_drop)|650|18333440|222|0.0%|1.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|222|0.0%|1.0%|
[stopforumspam_30d](#stopforumspam_30d)|92135|92135|220|0.2%|1.0%|
[stopforumspam_7d](#stopforumspam_7d)|31070|31070|145|0.4%|0.7%|
[ri_web_proxies](#ri_web_proxies)|5126|5126|79|1.5%|0.3%|
[php_dictionary](#php_dictionary)|433|433|74|17.0%|0.3%|
[stopforumspam_1d](#stopforumspam_1d)|6802|6802|73|1.0%|0.3%|
[xroxy](#xroxy)|1983|1983|64|3.2%|0.3%|
[php_spammers](#php_spammers)|417|417|60|14.3%|0.2%|
[blocklist_de_bots](#blocklist_de_bots)|3238|3238|51|1.5%|0.2%|
[alienvault_reputation](#alienvault_reputation)|173978|173978|38|0.0%|0.1%|
[proxz](#proxz)|322|322|14|4.3%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|14|0.0%|0.0%|
[openbl_60d](#openbl_60d)|7635|7635|12|0.1%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|12|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|1922|1922|11|0.5%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|1929|1929|10|0.5%|0.0%|
[php_commenters](#php_commenters)|281|281|10|3.5%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1281|1281|8|0.6%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13637|13637|8|0.0%|0.0%|
[proxyrss](#proxyrss)|1784|1784|6|0.3%|0.0%|
[et_tor](#et_tor)|6470|6470|6|0.0%|0.0%|
[dm_tor](#dm_tor)|6431|6431|6|0.0%|0.0%|
[bm_tor](#bm_tor)|6397|6397|6|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|3|1.1%|0.0%|
[openbl_30d](#openbl_30d)|3280|3280|3|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|178|178|3|1.6%|0.0%|
[voipbl](#voipbl)|10327|10736|2|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|2|0.2%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|666|666|2|0.3%|0.0%|
[zeus_badips](#zeus_badips)|229|229|1|0.4%|0.0%|
[zeus](#zeus)|264|264|1|0.3%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|421632|1|0.0%|0.0%|
[shunlist](#shunlist)|1195|1195|1|0.0%|0.0%|
[openbl_7d](#openbl_7d)|909|909|1|0.1%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1282|1282|1|0.0%|0.0%|
[dshield](#dshield)|19|5120|1|0.0%|0.0%|
[ciarmy](#ciarmy)|331|331|1|0.3%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1731|1731|1|0.0%|0.0%|

## openbl_1d

[OpenBL.org](http://www.openbl.org/) last 24 hours IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.

Source is downloaded from [this link](http://www.openbl.org/lists/base_1days.txt).

The last time downloaded was found to be dated: Sun May 31 06:07:00 UTC 2015.

The ipset `openbl_1d` has **187** entries, **187** unique IPs.

The following table shows the overlaps of `openbl_1d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl_1d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl_1d`.
- ` this % ` is the percentage **of this ipset (`openbl_1d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[openbl_7d](#openbl_7d)|909|909|187|20.5%|100.0%|
[openbl_60d](#openbl_60d)|7635|7635|187|2.4%|100.0%|
[openbl_30d](#openbl_30d)|3280|3280|187|5.7%|100.0%|
[alienvault_reputation](#alienvault_reputation)|173978|173978|186|0.1%|99.4%|
[blocklist_de](#blocklist_de)|21934|21934|167|0.7%|89.3%|
[blocklist_de_ssh](#blocklist_de_ssh)|1731|1731|162|9.3%|86.6%|
[bruteforceblocker](#bruteforceblocker)|2212|2212|110|4.9%|58.8%|
[et_compromised](#et_compromised)|2367|2367|107|4.5%|57.2%|
[shunlist](#shunlist)|1195|1195|89|7.4%|47.5%|
[blocklist_de_strongips](#blocklist_de_strongips)|178|178|23|12.9%|12.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|20|0.0%|10.6%|
[spamhaus_drop](#spamhaus_drop)|650|18333440|11|0.0%|5.8%|
[et_block](#et_block)|986|18056524|11|0.0%|5.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|5|0.0%|2.6%|
[blocklist_de_mail](#blocklist_de_mail)|14118|14118|5|0.0%|2.6%|
[blocklist_de_imap](#blocklist_de_imap)|666|666|4|0.6%|2.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|1.6%|
[spamhaus_edrop](#spamhaus_edrop)|56|421632|2|0.0%|1.0%|
[voipbl](#voipbl)|10327|10736|1|0.0%|0.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|1|0.0%|0.5%|
[dshield](#dshield)|19|5120|1|0.0%|0.5%|

## openbl_30d

[OpenBL.org](http://www.openbl.org/) last 30 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.

Source is downloaded from [this link](http://www.openbl.org/lists/base_30days.txt).

The last time downloaded was found to be dated: Sun May 31 07:42:00 UTC 2015.

The ipset `openbl_30d` has **3280** entries, **3280** unique IPs.

The following table shows the overlaps of `openbl_30d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl_30d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl_30d`.
- ` this % ` is the percentage **of this ipset (`openbl_30d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[openbl_60d](#openbl_60d)|7635|7635|3280|42.9%|100.0%|
[alienvault_reputation](#alienvault_reputation)|173978|173978|3261|1.8%|99.4%|
[et_compromised](#et_compromised)|2367|2367|1319|55.7%|40.2%|
[bruteforceblocker](#bruteforceblocker)|2212|2212|1262|57.0%|38.4%|
[openbl_7d](#openbl_7d)|909|909|909|100.0%|27.7%|
[blocklist_de](#blocklist_de)|21934|21934|830|3.7%|25.3%|
[blocklist_de_ssh](#blocklist_de_ssh)|1731|1731|772|44.5%|23.5%|
[shunlist](#shunlist)|1195|1195|585|48.9%|17.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|286|0.0%|8.7%|
[et_block](#et_block)|986|18056524|207|0.0%|6.3%|
[spamhaus_drop](#spamhaus_drop)|650|18333440|205|0.0%|6.2%|
[openbl_1d](#openbl_1d)|187|187|187|100.0%|5.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|180|0.0%|5.4%|
[dshield](#dshield)|19|5120|72|1.4%|2.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|68|0.0%|2.0%|
[blocklist_de_mail](#blocklist_de_mail)|14118|14118|52|0.3%|1.5%|
[blocklist_de_strongips](#blocklist_de_strongips)|178|178|47|26.4%|1.4%|
[blocklist_de_imap](#blocklist_de_imap)|666|666|39|5.8%|1.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|14|0.0%|0.4%|
[spamhaus_edrop](#spamhaus_edrop)|56|421632|6|0.0%|0.1%|
[stopforumspam_30d](#stopforumspam_30d)|92135|92135|5|0.0%|0.1%|
[blocklist_de_apache](#blocklist_de_apache)|13637|13637|5|0.0%|0.1%|
[voipbl](#voipbl)|10327|10736|3|0.0%|0.0%|
[nixspam](#nixspam)|20463|20463|3|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|3|0.0%|0.0%|
[zeus](#zeus)|264|264|2|0.7%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|31070|31070|2|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|1922|1922|2|0.1%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.0%|
[zeus_badips](#zeus_badips)|229|229|1|0.4%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6802|6802|1|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|195|195|1|0.5%|0.0%|

## openbl_60d

[OpenBL.org](http://www.openbl.org/) last 60 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.

Source is downloaded from [this link](http://www.openbl.org/lists/base_60days.txt).

The last time downloaded was found to be dated: Sun May 31 07:42:00 UTC 2015.

The ipset `openbl_60d` has **7635** entries, **7635** unique IPs.

The following table shows the overlaps of `openbl_60d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl_60d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl_60d`.
- ` this % ` is the percentage **of this ipset (`openbl_60d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[alienvault_reputation](#alienvault_reputation)|173978|173978|7608|4.3%|99.6%|
[openbl_30d](#openbl_30d)|3280|3280|3280|100.0%|42.9%|
[et_compromised](#et_compromised)|2367|2367|1423|60.1%|18.6%|
[bruteforceblocker](#bruteforceblocker)|2212|2212|1334|60.3%|17.4%|
[openbl_7d](#openbl_7d)|909|909|909|100.0%|11.9%|
[blocklist_de](#blocklist_de)|21934|21934|899|4.0%|11.7%|
[blocklist_de_ssh](#blocklist_de_ssh)|1731|1731|831|48.0%|10.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|712|0.0%|9.3%|
[shunlist](#shunlist)|1195|1195|602|50.3%|7.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|360|0.0%|4.7%|
[et_block](#et_block)|986|18056524|241|0.0%|3.1%|
[spamhaus_drop](#spamhaus_drop)|650|18333440|239|0.0%|3.1%|
[openbl_1d](#openbl_1d)|187|187|187|100.0%|2.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|173|0.0%|2.2%|
[dshield](#dshield)|19|5120|73|1.4%|0.9%|
[blocklist_de_mail](#blocklist_de_mail)|14118|14118|57|0.4%|0.7%|
[stopforumspam_30d](#stopforumspam_30d)|92135|92135|56|0.0%|0.7%|
[blocklist_de_strongips](#blocklist_de_strongips)|178|178|49|27.5%|0.6%|
[blocklist_de_imap](#blocklist_de_imap)|666|666|43|6.4%|0.5%|
[stopforumspam_7d](#stopforumspam_7d)|31070|31070|27|0.0%|0.3%|
[snort_ipfilter](#snort_ipfilter)|1922|1922|24|1.2%|0.3%|
[stopforumspam_1d](#stopforumspam_1d)|6802|6802|21|0.3%|0.2%|
[et_tor](#et_tor)|6470|6470|21|0.3%|0.2%|
[bm_tor](#bm_tor)|6397|6397|20|0.3%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|19|0.0%|0.2%|
[dm_tor](#dm_tor)|6431|6431|19|0.2%|0.2%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|18|4.8%|0.2%|
[nixspam](#nixspam)|20463|20463|12|0.0%|0.1%|
[voipbl](#voipbl)|10327|10736|9|0.0%|0.1%|
[php_commenters](#php_commenters)|281|281|8|2.8%|0.1%|
[spamhaus_edrop](#spamhaus_edrop)|56|421632|6|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13637|13637|6|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|5|1.9%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|5|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3238|3238|3|0.0%|0.0%|
[zeus](#zeus)|264|264|2|0.7%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|195|195|2|1.0%|0.0%|
[zeus_badips](#zeus_badips)|229|229|1|0.4%|0.0%|

## openbl_7d

[OpenBL.org](http://www.openbl.org/) last 7 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.

Source is downloaded from [this link](http://www.openbl.org/lists/base_7days.txt).

The last time downloaded was found to be dated: Sun May 31 07:42:00 UTC 2015.

The ipset `openbl_7d` has **909** entries, **909** unique IPs.

The following table shows the overlaps of `openbl_7d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl_7d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl_7d`.
- ` this % ` is the percentage **of this ipset (`openbl_7d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[openbl_60d](#openbl_60d)|7635|7635|909|11.9%|100.0%|
[openbl_30d](#openbl_30d)|3280|3280|909|27.7%|100.0%|
[alienvault_reputation](#alienvault_reputation)|173978|173978|896|0.5%|98.5%|
[blocklist_de](#blocklist_de)|21934|21934|558|2.5%|61.3%|
[blocklist_de_ssh](#blocklist_de_ssh)|1731|1731|525|30.3%|57.7%|
[et_compromised](#et_compromised)|2367|2367|510|21.5%|56.1%|
[bruteforceblocker](#bruteforceblocker)|2212|2212|510|23.0%|56.1%|
[shunlist](#shunlist)|1195|1195|375|31.3%|41.2%|
[openbl_1d](#openbl_1d)|187|187|187|100.0%|20.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|90|0.0%|9.9%|
[spamhaus_drop](#spamhaus_drop)|650|18333440|85|0.0%|9.3%|
[et_block](#et_block)|986|18056524|85|0.0%|9.3%|
[blocklist_de_strongips](#blocklist_de_strongips)|178|178|46|25.8%|5.0%|
[dshield](#dshield)|19|5120|41|0.8%|4.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|40|0.0%|4.4%|
[blocklist_de_mail](#blocklist_de_mail)|14118|14118|30|0.2%|3.3%|
[blocklist_de_imap](#blocklist_de_imap)|666|666|24|3.6%|2.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|16|0.0%|1.7%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|11|0.0%|1.2%|
[spamhaus_edrop](#spamhaus_edrop)|56|421632|5|0.0%|0.5%|
[voipbl](#voipbl)|10327|10736|3|0.0%|0.3%|
[blocklist_de_apache](#blocklist_de_apache)|13637|13637|2|0.0%|0.2%|
[zeus](#zeus)|264|264|1|0.3%|0.1%|
[snort_ipfilter](#snort_ipfilter)|1922|1922|1|0.0%|0.1%|
[nixspam](#nixspam)|20463|20463|1|0.0%|0.1%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.1%|
[blocklist_de_ftp](#blocklist_de_ftp)|195|195|1|0.5%|0.1%|

## palevo

[Abuse.ch Palevo tracker](https://palevotracker.abuse.ch) worm includes IPs which are being used as botnet C&C for the Palevo crimeware - **excellent list**

Source is downloaded from [this link](https://palevotracker.abuse.ch/blocklists.php?download=ipblocklist).

The last time downloaded was found to be dated: Sun May 31 09:00:22 UTC 2015.

The ipset `palevo` has **13** entries, **13** unique IPs.

The following table shows the overlaps of `palevo` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `palevo`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `palevo`.
- ` this % ` is the percentage **of this ipset (`palevo`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[et_block](#et_block)|986|18056524|13|0.0%|100.0%|
[snort_ipfilter](#snort_ipfilter)|1922|1922|11|0.5%|84.6%|
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
[stopforumspam_30d](#stopforumspam_30d)|92135|92135|203|0.2%|72.2%|
[stopforumspam_7d](#stopforumspam_7d)|31070|31070|178|0.5%|63.3%|
[stopforumspam_1d](#stopforumspam_1d)|6802|6802|88|1.2%|31.3%|
[blocklist_de](#blocklist_de)|21934|21934|56|0.2%|19.9%|
[blocklist_de_bots](#blocklist_de_bots)|3238|3238|45|1.3%|16.0%|
[php_spammers](#php_spammers)|417|417|32|7.6%|11.3%|
[snort_ipfilter](#snort_ipfilter)|1922|1922|31|1.6%|11.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|178|178|30|16.8%|10.6%|
[et_tor](#et_tor)|6470|6470|29|0.4%|10.3%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|28|7.5%|9.9%|
[dm_tor](#dm_tor)|6431|6431|28|0.4%|9.9%|
[bm_tor](#bm_tor)|6397|6397|28|0.4%|9.9%|
[spamhaus_drop](#spamhaus_drop)|650|18333440|24|0.0%|8.5%|
[et_block](#et_block)|986|18056524|24|0.0%|8.5%|
[blocklist_de_apache](#blocklist_de_apache)|13637|13637|24|0.1%|8.5%|
[php_dictionary](#php_dictionary)|433|433|22|5.0%|7.8%|
[blocklist_de_mail](#blocklist_de_mail)|14118|14118|17|0.1%|6.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|15|0.0%|5.3%|
[alienvault_reputation](#alienvault_reputation)|173978|173978|13|0.0%|4.6%|
[ri_web_proxies](#ri_web_proxies)|5126|5126|10|0.1%|3.5%|
[nixspam](#nixspam)|20463|20463|10|0.0%|3.5%|
[php_harvesters](#php_harvesters)|257|257|9|3.5%|3.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|9|0.0%|3.2%|
[openbl_60d](#openbl_60d)|7635|7635|8|0.1%|2.8%|
[spamhaus_edrop](#spamhaus_edrop)|56|421632|7|0.0%|2.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|5|0.0%|1.7%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1281|1281|4|0.3%|1.4%|
[xroxy](#xroxy)|1983|1983|3|0.1%|1.0%|
[proxz](#proxz)|322|322|2|0.6%|0.7%|
[zeus_badips](#zeus_badips)|229|229|1|0.4%|0.3%|
[zeus](#zeus)|264|264|1|0.3%|0.3%|
[proxyrss](#proxyrss)|1784|1784|1|0.0%|0.3%|
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
[stopforumspam_30d](#stopforumspam_30d)|92135|92135|82|0.0%|18.9%|
[nixspam](#nixspam)|20463|20463|74|0.3%|17.0%|
[stopforumspam_7d](#stopforumspam_7d)|31070|31070|64|0.2%|14.7%|
[blocklist_de](#blocklist_de)|21934|21934|53|0.2%|12.2%|
[blocklist_de_mail](#blocklist_de_mail)|14118|14118|40|0.2%|9.2%|
[ri_web_proxies](#ri_web_proxies)|5126|5126|28|0.5%|6.4%|
[stopforumspam_1d](#stopforumspam_1d)|6802|6802|25|0.3%|5.7%|
[xroxy](#xroxy)|1983|1983|24|1.2%|5.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|24|0.0%|5.5%|
[php_commenters](#php_commenters)|281|281|22|7.8%|5.0%|
[blocklist_de_bots](#blocklist_de_bots)|3238|3238|13|0.4%|3.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|10|0.0%|2.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|9|0.0%|2.0%|
[snort_ipfilter](#snort_ipfilter)|1922|1922|7|0.3%|1.6%|
[alienvault_reputation](#alienvault_reputation)|173978|173978|7|0.0%|1.6%|
[proxz](#proxz)|322|322|6|1.8%|1.3%|
[spamhaus_drop](#spamhaus_drop)|650|18333440|4|0.0%|0.9%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|4|1.0%|0.9%|
[et_tor](#et_tor)|6470|6470|4|0.0%|0.9%|
[et_block](#et_block)|986|18056524|4|0.0%|0.9%|
[dm_tor](#dm_tor)|6431|6431|4|0.0%|0.9%|
[bm_tor](#bm_tor)|6397|6397|4|0.0%|0.9%|
[ri_connect_proxies](#ri_connect_proxies)|1929|1929|3|0.1%|0.6%|
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
[stopforumspam_30d](#stopforumspam_30d)|92135|92135|62|0.0%|24.1%|
[stopforumspam_7d](#stopforumspam_7d)|31070|31070|45|0.1%|17.5%|
[stopforumspam_1d](#stopforumspam_1d)|6802|6802|37|0.5%|14.3%|
[blocklist_de](#blocklist_de)|21934|21934|24|0.1%|9.3%|
[blocklist_de_bots](#blocklist_de_bots)|3238|3238|21|0.6%|8.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|15|0.0%|5.8%|
[php_commenters](#php_commenters)|281|281|9|3.2%|3.5%|
[alienvault_reputation](#alienvault_reputation)|173978|173978|9|0.0%|3.5%|
[snort_ipfilter](#snort_ipfilter)|1922|1922|7|0.3%|2.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|7|0.0%|2.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|7|0.0%|2.7%|
[et_tor](#et_tor)|6470|6470|7|0.1%|2.7%|
[dm_tor](#dm_tor)|6431|6431|7|0.1%|2.7%|
[bm_tor](#bm_tor)|6397|6397|7|0.1%|2.7%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|6|1.6%|2.3%|
[openbl_60d](#openbl_60d)|7635|7635|5|0.0%|1.9%|
[nixspam](#nixspam)|20463|20463|3|0.0%|1.1%|
[xroxy](#xroxy)|1983|1983|2|0.1%|0.7%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|2|0.0%|0.7%|
[blocklist_de_strongips](#blocklist_de_strongips)|178|178|2|1.1%|0.7%|
[blocklist_de_ftp](#blocklist_de_ftp)|195|195|2|1.0%|0.7%|
[spamhaus_edrop](#spamhaus_edrop)|56|421632|1|0.0%|0.3%|
[spamhaus_drop](#spamhaus_drop)|650|18333440|1|0.0%|0.3%|
[ri_web_proxies](#ri_web_proxies)|5126|5126|1|0.0%|0.3%|
[proxyrss](#proxyrss)|1784|1784|1|0.0%|0.3%|
[php_spammers](#php_spammers)|417|417|1|0.2%|0.3%|
[php_dictionary](#php_dictionary)|433|433|1|0.2%|0.3%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.3%|
[fullbogons](#fullbogons)|3642|670590424|1|0.0%|0.3%|
[et_block](#et_block)|986|18056524|1|0.0%|0.3%|
[bogons](#bogons)|13|592708608|1|0.0%|0.3%|
[blocklist_de_mail](#blocklist_de_mail)|14118|14118|1|0.0%|0.3%|
[blocklist_de_apache](#blocklist_de_apache)|13637|13637|1|0.0%|0.3%|

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
[stopforumspam_30d](#stopforumspam_30d)|92135|92135|98|0.1%|23.5%|
[php_dictionary](#php_dictionary)|433|433|84|19.3%|20.1%|
[stopforumspam_7d](#stopforumspam_7d)|31070|31070|69|0.2%|16.5%|
[nixspam](#nixspam)|20463|20463|60|0.2%|14.3%|
[blocklist_de](#blocklist_de)|21934|21934|46|0.2%|11.0%|
[php_commenters](#php_commenters)|281|281|32|11.3%|7.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|31|0.0%|7.4%|
[stopforumspam_1d](#stopforumspam_1d)|6802|6802|27|0.3%|6.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|26|0.0%|6.2%|
[blocklist_de_mail](#blocklist_de_mail)|14118|14118|26|0.1%|6.2%|
[ri_web_proxies](#ri_web_proxies)|5126|5126|24|0.4%|5.7%|
[xroxy](#xroxy)|1983|1983|18|0.9%|4.3%|
[blocklist_de_bots](#blocklist_de_bots)|3238|3238|15|0.4%|3.5%|
[snort_ipfilter](#snort_ipfilter)|1922|1922|8|0.4%|1.9%|
[proxz](#proxz)|322|322|6|1.8%|1.4%|
[et_tor](#et_tor)|6470|6470|6|0.0%|1.4%|
[dm_tor](#dm_tor)|6431|6431|6|0.0%|1.4%|
[bm_tor](#bm_tor)|6397|6397|6|0.0%|1.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|5|0.0%|1.1%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|4|1.0%|0.9%|
[blocklist_de_strongips](#blocklist_de_strongips)|178|178|4|2.2%|0.9%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1281|1281|4|0.3%|0.9%|
[blocklist_de_apache](#blocklist_de_apache)|13637|13637|4|0.0%|0.9%|
[alienvault_reputation](#alienvault_reputation)|173978|173978|3|0.0%|0.7%|
[spamhaus_drop](#spamhaus_drop)|650|18333440|2|0.0%|0.4%|
[ri_connect_proxies](#ri_connect_proxies)|1929|1929|2|0.1%|0.4%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2|0.0%|0.4%|
[et_block](#et_block)|986|18056524|2|0.0%|0.4%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.2%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1|0.0%|0.2%|
[blocklist_de_ssh](#blocklist_de_ssh)|1731|1731|1|0.0%|0.2%|

## proxyrss

[proxyrss.com](http://www.proxyrss.com) open proxies syndicated from multiple sources.

Source is downloaded from [this link](http://www.proxyrss.com/proxylists/all.gz).

The last time downloaded was found to be dated: Sun May 31 07:31:29 UTC 2015.

The ipset `proxyrss` has **1784** entries, **1784** unique IPs.

The following table shows the overlaps of `proxyrss` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `proxyrss`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `proxyrss`.
- ` this % ` is the percentage **of this ipset (`proxyrss`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_30d](#stopforumspam_30d)|92135|92135|926|1.0%|51.9%|
[stopforumspam_7d](#stopforumspam_7d)|31070|31070|793|2.5%|44.4%|
[ri_web_proxies](#ri_web_proxies)|5126|5126|662|12.9%|37.1%|
[xroxy](#xroxy)|1983|1983|533|26.8%|29.8%|
[stopforumspam_1d](#stopforumspam_1d)|6802|6802|514|7.5%|28.8%|
[blocklist_de](#blocklist_de)|21934|21934|261|1.1%|14.6%|
[blocklist_de_bots](#blocklist_de_bots)|3238|3238|259|7.9%|14.5%|
[ri_connect_proxies](#ri_connect_proxies)|1929|1929|247|12.8%|13.8%|
[proxz](#proxz)|322|322|135|41.9%|7.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|71|0.0%|3.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|57|0.0%|3.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|46|0.0%|2.5%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|10|1.4%|0.5%|
[nixspam](#nixspam)|20463|20463|6|0.0%|0.3%|
[blocklist_de_strongips](#blocklist_de_strongips)|178|178|5|2.8%|0.2%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1281|1281|2|0.1%|0.1%|
[blocklist_de_apache](#blocklist_de_apache)|13637|13637|2|0.0%|0.1%|
[alienvault_reputation](#alienvault_reputation)|173978|173978|2|0.0%|0.1%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.0%|
[php_commenters](#php_commenters)|281|281|1|0.3%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1|0.0%|0.0%|

## proxz

[proxz.com](http://www.proxz.com) open proxies (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.proxz.com/proxylists.xml).

The last time downloaded was found to be dated: Sun May 31 07:31:34 UTC 2015.

The ipset `proxz` has **322** entries, **322** unique IPs.

The following table shows the overlaps of `proxz` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `proxz`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `proxz`.
- ` this % ` is the percentage **of this ipset (`proxz`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_30d](#stopforumspam_30d)|92135|92135|188|0.2%|58.3%|
[xroxy](#xroxy)|1983|1983|183|9.2%|56.8%|
[stopforumspam_7d](#stopforumspam_7d)|31070|31070|169|0.5%|52.4%|
[ri_web_proxies](#ri_web_proxies)|5126|5126|146|2.8%|45.3%|
[proxyrss](#proxyrss)|1784|1784|135|7.5%|41.9%|
[stopforumspam_1d](#stopforumspam_1d)|6802|6802|91|1.3%|28.2%|
[blocklist_de](#blocklist_de)|21934|21934|81|0.3%|25.1%|
[blocklist_de_bots](#blocklist_de_bots)|3238|3238|69|2.1%|21.4%|
[ri_connect_proxies](#ri_connect_proxies)|1929|1929|49|2.5%|15.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|35|0.0%|10.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|15|0.0%|4.6%|
[nixspam](#nixspam)|20463|20463|14|0.0%|4.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|13|0.0%|4.0%|
[blocklist_de_mail](#blocklist_de_mail)|14118|14118|11|0.0%|3.4%|
[php_spammers](#php_spammers)|417|417|6|1.4%|1.8%|
[php_dictionary](#php_dictionary)|433|433|6|1.3%|1.8%|
[php_commenters](#php_commenters)|281|281|2|0.7%|0.6%|
[et_compromised](#et_compromised)|2367|2367|2|0.0%|0.6%|
[bruteforceblocker](#bruteforceblocker)|2212|2212|2|0.0%|0.6%|
[blocklist_de_strongips](#blocklist_de_strongips)|178|178|2|1.1%|0.6%|
[alienvault_reputation](#alienvault_reputation)|173978|173978|2|0.0%|0.6%|
[snort_ipfilter](#snort_ipfilter)|1922|1922|1|0.0%|0.3%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|1|0.1%|0.3%|
[et_tor](#et_tor)|6470|6470|1|0.0%|0.3%|
[dm_tor](#dm_tor)|6431|6431|1|0.0%|0.3%|
[bm_tor](#bm_tor)|6397|6397|1|0.0%|0.3%|
[blocklist_de_ssh](#blocklist_de_ssh)|1731|1731|1|0.0%|0.3%|

## ri_connect_proxies

[rosinstrument.com](http://www.rosinstrument.com) open CONNECT proxies (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://tools.rosinstrument.com/proxy/plab100.xml).

The last time downloaded was found to be dated: Sun May 31 04:43:04 UTC 2015.

The ipset `ri_connect_proxies` has **1929** entries, **1929** unique IPs.

The following table shows the overlaps of `ri_connect_proxies` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ri_connect_proxies`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ri_connect_proxies`.
- ` this % ` is the percentage **of this ipset (`ri_connect_proxies`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_30d](#stopforumspam_30d)|92135|92135|1137|1.2%|58.9%|
[ri_web_proxies](#ri_web_proxies)|5126|5126|770|15.0%|39.9%|
[stopforumspam_7d](#stopforumspam_7d)|31070|31070|685|2.2%|35.5%|
[xroxy](#xroxy)|1983|1983|306|15.4%|15.8%|
[proxyrss](#proxyrss)|1784|1784|247|13.8%|12.8%|
[stopforumspam_1d](#stopforumspam_1d)|6802|6802|160|2.3%|8.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|79|0.0%|4.0%|
[blocklist_de](#blocklist_de)|21934|21934|72|0.3%|3.7%|
[blocklist_de_bots](#blocklist_de_bots)|3238|3238|70|2.1%|3.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|65|0.0%|3.3%|
[proxz](#proxz)|322|322|49|15.2%|2.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|44|0.0%|2.2%|
[nixspam](#nixspam)|20463|20463|10|0.0%|0.5%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|6|0.8%|0.3%|
[php_dictionary](#php_dictionary)|433|433|3|0.6%|0.1%|
[php_spammers](#php_spammers)|417|417|2|0.4%|0.1%|
[et_tor](#et_tor)|6470|6470|2|0.0%|0.1%|
[dm_tor](#dm_tor)|6431|6431|2|0.0%|0.1%|
[bm_tor](#bm_tor)|6397|6397|2|0.0%|0.1%|
[alienvault_reputation](#alienvault_reputation)|173978|173978|2|0.0%|0.1%|
[snort_ipfilter](#snort_ipfilter)|1922|1922|1|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14118|14118|1|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1281|1281|1|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13637|13637|1|0.0%|0.0%|

## ri_web_proxies

[rosinstrument.com](http://www.rosinstrument.com) open HTTP proxies (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://tools.rosinstrument.com/proxy/l100.xml).

The last time downloaded was found to be dated: Sun May 31 06:31:02 UTC 2015.

The ipset `ri_web_proxies` has **5126** entries, **5126** unique IPs.

The following table shows the overlaps of `ri_web_proxies` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ri_web_proxies`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ri_web_proxies`.
- ` this % ` is the percentage **of this ipset (`ri_web_proxies`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_30d](#stopforumspam_30d)|92135|92135|2510|2.7%|48.9%|
[stopforumspam_7d](#stopforumspam_7d)|31070|31070|1683|5.4%|32.8%|
[xroxy](#xroxy)|1983|1983|782|39.4%|15.2%|
[ri_connect_proxies](#ri_connect_proxies)|1929|1929|770|39.9%|15.0%|
[proxyrss](#proxyrss)|1784|1784|662|37.1%|12.9%|
[stopforumspam_1d](#stopforumspam_1d)|6802|6802|522|7.6%|10.1%|
[blocklist_de](#blocklist_de)|21934|21934|371|1.6%|7.2%|
[blocklist_de_bots](#blocklist_de_bots)|3238|3238|345|10.6%|6.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|169|0.0%|3.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|150|0.0%|2.9%|
[proxz](#proxz)|322|322|146|45.3%|2.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|113|0.0%|2.2%|
[nixspam](#nixspam)|20463|20463|79|0.3%|1.5%|
[php_dictionary](#php_dictionary)|433|433|28|6.4%|0.5%|
[blocklist_de_mail](#blocklist_de_mail)|14118|14118|25|0.1%|0.4%|
[php_spammers](#php_spammers)|417|417|24|5.7%|0.4%|
[php_commenters](#php_commenters)|281|281|10|3.5%|0.1%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|10|1.4%|0.1%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|4|1.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|4|0.0%|0.0%|
[et_tor](#et_tor)|6470|6470|4|0.0%|0.0%|
[dm_tor](#dm_tor)|6431|6431|4|0.0%|0.0%|
[bm_tor](#bm_tor)|6397|6397|4|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|178|178|4|2.2%|0.0%|
[snort_ipfilter](#snort_ipfilter)|1922|1922|3|0.1%|0.0%|
[alienvault_reputation](#alienvault_reputation)|173978|173978|3|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1281|1281|1|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13637|13637|1|0.0%|0.0%|

## shunlist

[AutoShun.org](http://autoshun.org/) IPs identified as hostile by correlating logs from distributed snort installations running the autoshun plugin

Source is downloaded from [this link](http://www.autoshun.org/files/shunlist.csv).

The last time downloaded was found to be dated: Sun May 31 06:30:05 UTC 2015.

The ipset `shunlist` has **1195** entries, **1195** unique IPs.

The following table shows the overlaps of `shunlist` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `shunlist`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `shunlist`.
- ` this % ` is the percentage **of this ipset (`shunlist`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[alienvault_reputation](#alienvault_reputation)|173978|173978|1184|0.6%|99.0%|
[openbl_60d](#openbl_60d)|7635|7635|602|7.8%|50.3%|
[openbl_30d](#openbl_30d)|3280|3280|585|17.8%|48.9%|
[et_compromised](#et_compromised)|2367|2367|507|21.4%|42.4%|
[bruteforceblocker](#bruteforceblocker)|2212|2212|504|22.7%|42.1%|
[blocklist_de](#blocklist_de)|21934|21934|443|2.0%|37.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1731|1731|409|23.6%|34.2%|
[openbl_7d](#openbl_7d)|909|909|375|41.2%|31.3%|
[et_block](#et_block)|986|18056524|111|0.0%|9.2%|
[spamhaus_drop](#spamhaus_drop)|650|18333440|101|0.0%|8.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|91|0.0%|7.6%|
[openbl_1d](#openbl_1d)|187|187|89|47.5%|7.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|71|0.0%|5.9%|
[dshield](#dshield)|19|5120|71|1.3%|5.9%|
[blocklist_de_strongips](#blocklist_de_strongips)|178|178|42|23.5%|3.5%|
[blocklist_de_apache](#blocklist_de_apache)|13637|13637|26|0.1%|2.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|24|0.0%|2.0%|
[ciarmy](#ciarmy)|331|331|23|6.9%|1.9%|
[voipbl](#voipbl)|10327|10736|12|0.1%|1.0%|
[blocklist_de_mail](#blocklist_de_mail)|14118|14118|7|0.0%|0.5%|
[sslbl](#sslbl)|357|357|6|1.6%|0.5%|
[spamhaus_edrop](#spamhaus_edrop)|56|421632|5|0.0%|0.4%|
[stopforumspam_30d](#stopforumspam_30d)|92135|92135|4|0.0%|0.3%|
[blocklist_de_imap](#blocklist_de_imap)|666|666|4|0.6%|0.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|0.2%|
[stopforumspam_7d](#stopforumspam_7d)|31070|31070|2|0.0%|0.1%|
[snort_ipfilter](#snort_ipfilter)|1922|1922|2|0.1%|0.1%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|2|0.5%|0.1%|
[stopforumspam_1d](#stopforumspam_1d)|6802|6802|1|0.0%|0.0%|
[nixspam](#nixspam)|20463|20463|1|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.0%|
[et_tor](#et_tor)|6470|6470|1|0.0%|0.0%|
[dm_tor](#dm_tor)|6431|6431|1|0.0%|0.0%|
[bm_tor](#bm_tor)|6397|6397|1|0.0%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|106|106|1|0.9%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1281|1281|1|0.0%|0.0%|

## snort_ipfilter

[labs.snort.org](https://labs.snort.org/) supplied IP blacklist (this list seems to be updated frequently, but we found no information about it)

Source is downloaded from [this link](http://labs.snort.org/feeds/ip-filter.blf).

The last time downloaded was found to be dated: Sun May 31 01:30:00 UTC 2015.

The ipset `snort_ipfilter` has **1922** entries, **1922** unique IPs.

The following table shows the overlaps of `snort_ipfilter` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `snort_ipfilter`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `snort_ipfilter`.
- ` this % ` is the percentage **of this ipset (`snort_ipfilter`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[et_tor](#et_tor)|6470|6470|1071|16.5%|55.7%|
[dm_tor](#dm_tor)|6431|6431|982|15.2%|51.0%|
[bm_tor](#bm_tor)|6397|6397|980|15.3%|50.9%|
[stopforumspam_30d](#stopforumspam_30d)|92135|92135|638|0.6%|33.1%|
[stopforumspam_7d](#stopforumspam_7d)|31070|31070|520|1.6%|27.0%|
[stopforumspam_1d](#stopforumspam_1d)|6802|6802|353|5.1%|18.3%|
[et_block](#et_block)|986|18056524|290|0.0%|15.0%|
[zeus](#zeus)|264|264|218|82.5%|11.3%|
[zeus_badips](#zeus_badips)|229|229|197|86.0%|10.2%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|183|49.1%|9.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|159|0.0%|8.2%|
[alienvault_reputation](#alienvault_reputation)|173978|173978|110|0.0%|5.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|67|0.0%|3.4%|
[feodo](#feodo)|71|71|53|74.6%|2.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|47|0.0%|2.4%|
[php_commenters](#php_commenters)|281|281|31|11.0%|1.6%|
[openbl_60d](#openbl_60d)|7635|7635|24|0.3%|1.2%|
[malwaredomainlist](#malwaredomainlist)|1282|1282|23|1.7%|1.1%|
[sslbl](#sslbl)|357|357|21|5.8%|1.0%|
[spamhaus_drop](#spamhaus_drop)|650|18333440|18|0.0%|0.9%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|14|0.0%|0.7%|
[palevo](#palevo)|13|13|11|84.6%|0.5%|
[nixspam](#nixspam)|20463|20463|11|0.0%|0.5%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|11|0.0%|0.5%|
[php_spammers](#php_spammers)|417|417|8|1.9%|0.4%|
[php_harvesters](#php_harvesters)|257|257|7|2.7%|0.3%|
[php_dictionary](#php_dictionary)|433|433|7|1.6%|0.3%|
[spamhaus_edrop](#spamhaus_edrop)|56|421632|6|0.0%|0.3%|
[xroxy](#xroxy)|1983|1983|4|0.2%|0.2%|
[blocklist_de](#blocklist_de)|21934|21934|4|0.0%|0.2%|
[ri_web_proxies](#ri_web_proxies)|5126|5126|3|0.0%|0.1%|
[blocklist_de_mail](#blocklist_de_mail)|14118|14118|3|0.0%|0.1%|
[blocklist_de_apache](#blocklist_de_apache)|13637|13637|3|0.0%|0.1%|
[shunlist](#shunlist)|1195|1195|2|0.1%|0.1%|
[openbl_30d](#openbl_30d)|3280|3280|2|0.0%|0.1%|
[cleanmx_viruses](#cleanmx_viruses)|317|317|2|0.6%|0.1%|
[ri_connect_proxies](#ri_connect_proxies)|1929|1929|1|0.0%|0.0%|
[proxz](#proxz)|322|322|1|0.3%|0.0%|
[openbl_7d](#openbl_7d)|909|909|1|0.1%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|
[et_compromised](#et_compromised)|2367|2367|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2212|2212|1|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1731|1731|1|0.0%|0.0%|

## spamhaus_drop

[Spamhaus.org](http://www.spamhaus.org) DROP list (according to their site this list should be dropped at tier-1 ISPs globaly) - **excellent list**

Source is downloaded from [this link](http://www.spamhaus.org/drop/drop.txt).

The last time downloaded was found to be dated: Sat May 30 17:20:03 UTC 2015.

The ipset `spamhaus_drop` has **650** entries, **18333440** unique IPs.

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
[fullbogons](#fullbogons)|3642|670590424|20480|0.0%|0.1%|
[alienvault_reputation](#alienvault_reputation)|173978|173978|1629|0.9%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1037|0.3%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92135|92135|978|1.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|421632|512|0.1%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|31070|31070|347|1.1%|0.0%|
[dshield](#dshield)|19|5120|256|5.0%|0.0%|
[openbl_60d](#openbl_60d)|7635|7635|239|3.1%|0.0%|
[nixspam](#nixspam)|20463|20463|222|1.0%|0.0%|
[openbl_30d](#openbl_30d)|3280|3280|205|6.2%|0.0%|
[blocklist_de](#blocklist_de)|21934|21934|188|0.8%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1731|1731|115|6.6%|0.0%|
[et_compromised](#et_compromised)|2367|2367|102|4.3%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2212|2212|102|4.6%|0.0%|
[shunlist](#shunlist)|1195|1195|101|8.4%|0.0%|
[openbl_7d](#openbl_7d)|909|909|85|9.3%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3238|3238|48|1.4%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6802|6802|45|0.6%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1282|1282|29|2.2%|0.0%|
[php_commenters](#php_commenters)|281|281|24|8.5%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14118|14118|21|0.1%|0.0%|
[snort_ipfilter](#snort_ipfilter)|1922|1922|18|0.9%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|666|666|17|2.5%|0.0%|
[zeus_badips](#zeus_badips)|229|229|16|6.9%|0.0%|
[zeus](#zeus)|264|264|16|6.0%|0.0%|
[voipbl](#voipbl)|10327|10736|14|0.1%|0.0%|
[openbl_1d](#openbl_1d)|187|187|11|5.8%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|6|0.4%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|6|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|178|178|5|2.8%|0.0%|
[php_dictionary](#php_dictionary)|433|433|4|0.9%|0.0%|
[malc0de](#malc0de)|407|407|4|0.9%|0.0%|
[sslbl](#sslbl)|357|357|3|0.8%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1281|1281|3|0.2%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13637|13637|3|0.0%|0.0%|
[php_spammers](#php_spammers)|417|417|2|0.4%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|2|0.2%|0.0%|
[et_tor](#et_tor)|6470|6470|2|0.0%|0.0%|
[dm_tor](#dm_tor)|6431|6431|2|0.0%|0.0%|
[bm_tor](#bm_tor)|6397|6397|2|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.0%|
[et_botcc](#et_botcc)|501|501|1|0.1%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|106|106|1|0.9%|0.0%|

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
[spamhaus_drop](#spamhaus_drop)|650|18333440|512|0.0%|0.1%|
[alienvault_reputation](#alienvault_reputation)|173978|173978|271|0.1%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92135|92135|106|0.1%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|31070|31070|43|0.1%|0.0%|
[blocklist_de](#blocklist_de)|21934|21934|18|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|178|178|10|5.6%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3238|3238|10|0.3%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6802|6802|8|0.1%|0.0%|
[php_commenters](#php_commenters)|281|281|7|2.4%|0.0%|
[snort_ipfilter](#snort_ipfilter)|1922|1922|6|0.3%|0.0%|
[openbl_60d](#openbl_60d)|7635|7635|6|0.0%|0.0%|
[openbl_30d](#openbl_30d)|3280|3280|6|0.1%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1731|1731|6|0.3%|0.0%|
[zeus_badips](#zeus_badips)|229|229|5|2.1%|0.0%|
[zeus](#zeus)|264|264|5|1.8%|0.0%|
[shunlist](#shunlist)|1195|1195|5|0.4%|0.0%|
[openbl_7d](#openbl_7d)|909|909|5|0.5%|0.0%|
[openbl_1d](#openbl_1d)|187|187|2|1.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13637|13637|2|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.0%|
[nixspam](#nixspam)|20463|20463|1|0.0%|0.0%|
[malc0de](#malc0de)|407|407|1|0.2%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.0%|

## sslbl

[Abuse.ch SSL Blacklist](https://sslbl.abuse.ch/) bad SSL traffic related to malware or botnet activities - **excellent list**

Source is downloaded from [this link](https://sslbl.abuse.ch/blacklist/sslipblacklist.csv).

The last time downloaded was found to be dated: Sun May 31 08:45:06 UTC 2015.

The ipset `sslbl` has **357** entries, **357** unique IPs.

The following table shows the overlaps of `sslbl` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `sslbl`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `sslbl`.
- ` this % ` is the percentage **of this ipset (`sslbl`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[et_block](#et_block)|986|18056524|27|0.0%|7.5%|
[feodo](#feodo)|71|71|26|36.6%|7.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|23|0.0%|6.4%|
[snort_ipfilter](#snort_ipfilter)|1922|1922|21|1.0%|5.8%|
[alienvault_reputation](#alienvault_reputation)|173978|173978|13|0.0%|3.6%|
[shunlist](#shunlist)|1195|1195|6|0.5%|1.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|6|0.0%|1.6%|
[spamhaus_drop](#spamhaus_drop)|650|18333440|3|0.0%|0.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|3|0.0%|0.8%|
[stopforumspam_30d](#stopforumspam_30d)|92135|92135|1|0.0%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.2%|

## stopforumspam_1d

[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers in the last 24 hours - **excellent list**

Source is downloaded from [this link](http://www.stopforumspam.com/downloads/listed_ip_1.zip).

The last time downloaded was found to be dated: Sun May 31 09:00:02 UTC 2015.

The ipset `stopforumspam_1d` has **6802** entries, **6802** unique IPs.

The following table shows the overlaps of `stopforumspam_1d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `stopforumspam_1d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `stopforumspam_1d`.
- ` this % ` is the percentage **of this ipset (`stopforumspam_1d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_7d](#stopforumspam_7d)|31070|31070|5909|19.0%|86.8%|
[stopforumspam_30d](#stopforumspam_30d)|92135|92135|5884|6.3%|86.5%|
[blocklist_de](#blocklist_de)|21934|21934|1386|6.3%|20.3%|
[blocklist_de_bots](#blocklist_de_bots)|3238|3238|1322|40.8%|19.4%|
[ri_web_proxies](#ri_web_proxies)|5126|5126|522|10.1%|7.6%|
[proxyrss](#proxyrss)|1784|1784|514|28.8%|7.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|499|0.0%|7.3%|
[xroxy](#xroxy)|1983|1983|373|18.8%|5.4%|
[snort_ipfilter](#snort_ipfilter)|1922|1922|353|18.3%|5.1%|
[et_tor](#et_tor)|6470|6470|348|5.3%|5.1%|
[dm_tor](#dm_tor)|6431|6431|343|5.3%|5.0%|
[bm_tor](#bm_tor)|6397|6397|343|5.3%|5.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|242|0.0%|3.5%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|171|45.9%|2.5%|
[ri_connect_proxies](#ri_connect_proxies)|1929|1929|160|8.2%|2.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|146|0.0%|2.1%|
[proxz](#proxz)|322|322|91|28.2%|1.3%|
[blocklist_de_strongips](#blocklist_de_strongips)|178|178|90|50.5%|1.3%|
[php_commenters](#php_commenters)|281|281|88|31.3%|1.2%|
[nixspam](#nixspam)|20463|20463|73|0.3%|1.0%|
[alienvault_reputation](#alienvault_reputation)|173978|173978|61|0.0%|0.8%|
[blocklist_de_apache](#blocklist_de_apache)|13637|13637|59|0.4%|0.8%|
[blocklist_de_mail](#blocklist_de_mail)|14118|14118|51|0.3%|0.7%|
[spamhaus_drop](#spamhaus_drop)|650|18333440|45|0.0%|0.6%|
[php_harvesters](#php_harvesters)|257|257|37|14.3%|0.5%|
[php_spammers](#php_spammers)|417|417|27|6.4%|0.3%|
[php_dictionary](#php_dictionary)|433|433|25|5.7%|0.3%|
[openbl_60d](#openbl_60d)|7635|7635|21|0.2%|0.3%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1281|1281|17|1.3%|0.2%|
[et_block](#et_block)|986|18056524|14|0.0%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|13|0.0%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|9|0.0%|0.1%|
[spamhaus_edrop](#spamhaus_edrop)|56|421632|8|0.0%|0.1%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|5|0.7%|0.0%|
[voipbl](#voipbl)|10327|10736|4|0.0%|0.0%|
[shunlist](#shunlist)|1195|1195|1|0.0%|0.0%|
[openbl_30d](#openbl_30d)|3280|3280|1|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1|0.0%|0.0%|
[et_compromised](#et_compromised)|2367|2367|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2212|2212|1|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|195|195|1|0.5%|0.0%|

## stopforumspam_30d

[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 30 days)

Source is downloaded from [this link](http://www.stopforumspam.com/downloads/listed_ip_30.zip).

The last time downloaded was found to be dated: Sun May 31 00:01:02 UTC 2015.

The ipset `stopforumspam_30d` has **92135** entries, **92135** unique IPs.

The following table shows the overlaps of `stopforumspam_30d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `stopforumspam_30d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `stopforumspam_30d`.
- ` this % ` is the percentage **of this ipset (`stopforumspam_30d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_7d](#stopforumspam_7d)|31070|31070|30899|99.4%|33.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|5963|0.0%|6.4%|
[stopforumspam_1d](#stopforumspam_1d)|6802|6802|5884|86.5%|6.3%|
[blocklist_de](#blocklist_de)|21934|21934|2518|11.4%|2.7%|
[ri_web_proxies](#ri_web_proxies)|5126|5126|2510|48.9%|2.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|2487|0.0%|2.6%|
[blocklist_de_bots](#blocklist_de_bots)|3238|3238|2235|69.0%|2.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|1523|0.0%|1.6%|
[xroxy](#xroxy)|1983|1983|1155|58.2%|1.2%|
[ri_connect_proxies](#ri_connect_proxies)|1929|1929|1137|58.9%|1.2%|
[spamhaus_drop](#spamhaus_drop)|650|18333440|978|0.0%|1.0%|
[proxyrss](#proxyrss)|1784|1784|926|51.9%|1.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|752|0.0%|0.8%|
[et_block](#et_block)|986|18056524|747|0.0%|0.8%|
[snort_ipfilter](#snort_ipfilter)|1922|1922|638|33.1%|0.6%|
[et_tor](#et_tor)|6470|6470|618|9.5%|0.6%|
[dm_tor](#dm_tor)|6431|6431|584|9.0%|0.6%|
[bm_tor](#bm_tor)|6397|6397|584|9.1%|0.6%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|236|63.4%|0.2%|
[alienvault_reputation](#alienvault_reputation)|173978|173978|222|0.1%|0.2%|
[nixspam](#nixspam)|20463|20463|220|1.0%|0.2%|
[blocklist_de_mail](#blocklist_de_mail)|14118|14118|213|1.5%|0.2%|
[php_commenters](#php_commenters)|281|281|203|72.2%|0.2%|
[blocklist_de_apache](#blocklist_de_apache)|13637|13637|199|1.4%|0.2%|
[proxz](#proxz)|322|322|188|58.3%|0.2%|
[blocklist_de_strongips](#blocklist_de_strongips)|178|178|115|64.6%|0.1%|
[spamhaus_edrop](#spamhaus_edrop)|56|421632|106|0.0%|0.1%|
[php_spammers](#php_spammers)|417|417|98|23.5%|0.1%|
[php_dictionary](#php_dictionary)|433|433|82|18.9%|0.0%|
[php_harvesters](#php_harvesters)|257|257|62|24.1%|0.0%|
[openbl_60d](#openbl_60d)|7635|7635|56|0.7%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|44|0.0%|0.0%|
[voipbl](#voipbl)|10327|10736|41|0.3%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1281|1281|40|3.1%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|22|3.2%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|15|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|195|195|8|4.1%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1731|1731|7|0.4%|0.0%|
[et_compromised](#et_compromised)|2367|2367|6|0.2%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2212|2212|6|0.2%|0.0%|
[openbl_30d](#openbl_30d)|3280|3280|5|0.1%|0.0%|
[shunlist](#shunlist)|1195|1195|4|0.3%|0.0%|
[zeus_badips](#zeus_badips)|229|229|3|1.3%|0.0%|
[zeus](#zeus)|264|264|3|1.1%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1282|1282|3|0.2%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.0%|
[fullbogons](#fullbogons)|3642|670590424|2|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|666|666|2|0.3%|0.0%|
[sslbl](#sslbl)|357|357|1|0.2%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|317|317|1|0.3%|0.0%|
[ciarmy](#ciarmy)|331|331|1|0.3%|0.0%|
[bogons](#bogons)|13|592708608|1|0.0%|0.0%|

## stopforumspam_7d

[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 7 days)

Source is downloaded from [this link](http://www.stopforumspam.com/downloads/listed_ip_7.zip).

The last time downloaded was found to be dated: Sun May 31 02:00:09 UTC 2015.

The ipset `stopforumspam_7d` has **31070** entries, **31070** unique IPs.

The following table shows the overlaps of `stopforumspam_7d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `stopforumspam_7d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `stopforumspam_7d`.
- ` this % ` is the percentage **of this ipset (`stopforumspam_7d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_30d](#stopforumspam_30d)|92135|92135|30899|33.5%|99.4%|
[stopforumspam_1d](#stopforumspam_1d)|6802|6802|5909|86.8%|19.0%|
[blocklist_de](#blocklist_de)|21934|21934|2216|10.1%|7.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|2085|0.0%|6.7%|
[blocklist_de_bots](#blocklist_de_bots)|3238|3238|2050|63.3%|6.5%|
[ri_web_proxies](#ri_web_proxies)|5126|5126|1683|32.8%|5.4%|
[xroxy](#xroxy)|1983|1983|986|49.7%|3.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|937|0.0%|3.0%|
[proxyrss](#proxyrss)|1784|1784|793|44.4%|2.5%|
[ri_connect_proxies](#ri_connect_proxies)|1929|1929|685|35.5%|2.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|567|0.0%|1.8%|
[snort_ipfilter](#snort_ipfilter)|1922|1922|520|27.0%|1.6%|
[et_tor](#et_tor)|6470|6470|500|7.7%|1.6%|
[dm_tor](#dm_tor)|6431|6431|475|7.3%|1.5%|
[bm_tor](#bm_tor)|6397|6397|475|7.4%|1.5%|
[spamhaus_drop](#spamhaus_drop)|650|18333440|347|0.0%|1.1%|
[et_block](#et_block)|986|18056524|202|0.0%|0.6%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|200|53.7%|0.6%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|192|0.0%|0.6%|
[php_commenters](#php_commenters)|281|281|178|63.3%|0.5%|
[proxz](#proxz)|322|322|169|52.4%|0.5%|
[nixspam](#nixspam)|20463|20463|145|0.7%|0.4%|
[blocklist_de_mail](#blocklist_de_mail)|14118|14118|117|0.8%|0.3%|
[blocklist_de_apache](#blocklist_de_apache)|13637|13637|117|0.8%|0.3%|
[alienvault_reputation](#alienvault_reputation)|173978|173978|112|0.0%|0.3%|
[blocklist_de_strongips](#blocklist_de_strongips)|178|178|106|59.5%|0.3%|
[php_spammers](#php_spammers)|417|417|69|16.5%|0.2%|
[php_dictionary](#php_dictionary)|433|433|64|14.7%|0.2%|
[php_harvesters](#php_harvesters)|257|257|45|17.5%|0.1%|
[spamhaus_edrop](#spamhaus_edrop)|56|421632|43|0.0%|0.1%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1281|1281|32|2.4%|0.1%|
[openbl_60d](#openbl_60d)|7635|7635|27|0.3%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|20|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|11|1.6%|0.0%|
[voipbl](#voipbl)|10327|10736|10|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|195|195|5|2.5%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|3|0.0%|0.0%|
[et_compromised](#et_compromised)|2367|2367|3|0.1%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2212|2212|3|0.1%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1731|1731|3|0.1%|0.0%|
[shunlist](#shunlist)|1195|1195|2|0.1%|0.0%|
[openbl_30d](#openbl_30d)|3280|3280|2|0.0%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1282|1282|2|0.1%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.0%|
[zeus_badips](#zeus_badips)|229|229|1|0.4%|0.0%|
[zeus](#zeus)|264|264|1|0.3%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|666|666|1|0.1%|0.0%|

## voipbl

[VoIPBL.org](http://www.voipbl.org/) a distributed VoIP blacklist that is aimed to protects against VoIP Fraud and minimizing abuse for network that have publicly accessible PBX's. Several algorithms, external sources and manual confirmation are used before they categorize something as an attack and determine the threat level.

Source is downloaded from [this link](http://www.voipbl.org/update/).

The last time downloaded was found to be dated: Sun May 31 08:01:05 UTC 2015.

The ipset `voipbl` has **10327** entries, **10736** unique IPs.

The following table shows the overlaps of `voipbl` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `voipbl`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `voipbl`.
- ` this % ` is the percentage **of this ipset (`voipbl`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|1588|0.0%|14.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|429|0.0%|3.9%|
[fullbogons](#fullbogons)|3642|670590424|319|0.0%|2.9%|
[bogons](#bogons)|13|592708608|319|0.0%|2.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|295|0.0%|2.7%|
[alienvault_reputation](#alienvault_reputation)|173978|173978|215|0.1%|2.0%|
[blocklist_de](#blocklist_de)|21934|21934|46|0.2%|0.4%|
[stopforumspam_30d](#stopforumspam_30d)|92135|92135|41|0.0%|0.3%|
[blocklist_de_sip](#blocklist_de_sip)|106|106|38|35.8%|0.3%|
[et_block](#et_block)|986|18056524|17|0.0%|0.1%|
[spamhaus_drop](#spamhaus_drop)|650|18333440|14|0.0%|0.1%|
[shunlist](#shunlist)|1195|1195|12|1.0%|0.1%|
[stopforumspam_7d](#stopforumspam_7d)|31070|31070|10|0.0%|0.0%|
[openbl_60d](#openbl_60d)|7635|7635|9|0.1%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6802|6802|4|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|4|0.0%|0.0%|
[ciarmy](#ciarmy)|331|331|4|1.2%|0.0%|
[openbl_7d](#openbl_7d)|909|909|3|0.3%|0.0%|
[openbl_30d](#openbl_30d)|3280|3280|3|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1731|1731|3|0.1%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13637|13637|3|0.0%|0.0%|
[nixspam](#nixspam)|20463|20463|2|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|2|0.0%|0.0%|
[openbl_1d](#openbl_1d)|187|187|1|0.5%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.0%|
[et_tor](#et_tor)|6470|6470|1|0.0%|0.0%|
[et_compromised](#et_compromised)|2367|2367|1|0.0%|0.0%|
[dm_tor](#dm_tor)|6431|6431|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2212|2212|1|0.0%|0.0%|
[bm_tor](#bm_tor)|6397|6397|1|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14118|14118|1|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|666|666|1|0.1%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1281|1281|1|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3238|3238|1|0.0%|0.0%|

## xroxy

[xroxy.com](http://www.xroxy.com) open proxies (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.xroxy.com/proxyrss.xml).

The last time downloaded was found to be dated: Sun May 31 08:33:01 UTC 2015.

The ipset `xroxy` has **1983** entries, **1983** unique IPs.

The following table shows the overlaps of `xroxy` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `xroxy`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `xroxy`.
- ` this % ` is the percentage **of this ipset (`xroxy`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_30d](#stopforumspam_30d)|92135|92135|1155|1.2%|58.2%|
[stopforumspam_7d](#stopforumspam_7d)|31070|31070|986|3.1%|49.7%|
[ri_web_proxies](#ri_web_proxies)|5126|5126|782|15.2%|39.4%|
[proxyrss](#proxyrss)|1784|1784|533|29.8%|26.8%|
[stopforumspam_1d](#stopforumspam_1d)|6802|6802|373|5.4%|18.8%|
[ri_connect_proxies](#ri_connect_proxies)|1929|1929|306|15.8%|15.4%|
[blocklist_de](#blocklist_de)|21934|21934|267|1.2%|13.4%|
[blocklist_de_bots](#blocklist_de_bots)|3238|3238|231|7.1%|11.6%|
[proxz](#proxz)|322|322|183|56.8%|9.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|96|0.0%|4.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|81|0.0%|4.0%|
[nixspam](#nixspam)|20463|20463|64|0.3%|3.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|56|0.0%|2.8%|
[blocklist_de_mail](#blocklist_de_mail)|14118|14118|33|0.2%|1.6%|
[php_dictionary](#php_dictionary)|433|433|24|5.5%|1.2%|
[php_spammers](#php_spammers)|417|417|18|4.3%|0.9%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|13|1.9%|0.6%|
[blocklist_de_strongips](#blocklist_de_strongips)|178|178|6|3.3%|0.3%|
[alienvault_reputation](#alienvault_reputation)|173978|173978|5|0.0%|0.2%|
[snort_ipfilter](#snort_ipfilter)|1922|1922|4|0.2%|0.2%|
[php_commenters](#php_commenters)|281|281|3|1.0%|0.1%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|3|0.0%|0.1%|
[et_tor](#et_tor)|6470|6470|3|0.0%|0.1%|
[dm_tor](#dm_tor)|6431|6431|3|0.0%|0.1%|
[bm_tor](#bm_tor)|6397|6397|3|0.0%|0.1%|
[php_harvesters](#php_harvesters)|257|257|2|0.7%|0.1%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1281|1281|2|0.1%|0.1%|
[blocklist_de_apache](#blocklist_de_apache)|13637|13637|2|0.0%|0.1%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.0%|
[et_compromised](#et_compromised)|2367|2367|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2212|2212|1|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1731|1731|1|0.0%|0.0%|

## zeus

[Abuse.ch Zeus tracker](https://zeustracker.abuse.ch) standard, contains the same data as the ZeuS IP blocklist (zeus_badips) but with the slight difference that it doesn't exclude hijacked websites (level 2) and free web hosting providers (level 3). This means that this blocklist contains all IPv4 addresses associated with ZeuS C&Cs which are currently being tracked by ZeuS Tracker. Hence this blocklist will likely cause some false positives. - **excellent list**

Source is downloaded from [this link](https://zeustracker.abuse.ch/blocklist.php?download=ipblocklist).

The last time downloaded was found to be dated: Sat May 30 21:08:55 UTC 2015.

The ipset `zeus` has **264** entries, **264** unique IPs.

The following table shows the overlaps of `zeus` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `zeus`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `zeus`.
- ` this % ` is the percentage **of this ipset (`zeus`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[et_block](#et_block)|986|18056524|261|0.0%|98.8%|
[zeus_badips](#zeus_badips)|229|229|229|100.0%|86.7%|
[snort_ipfilter](#snort_ipfilter)|1922|1922|218|11.3%|82.5%|
[alienvault_reputation](#alienvault_reputation)|173978|173978|66|0.0%|25.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|19|0.0%|7.1%|
[spamhaus_drop](#spamhaus_drop)|650|18333440|16|0.0%|6.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|10|0.0%|3.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|9|0.0%|3.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|7|0.0%|2.6%|
[spamhaus_edrop](#spamhaus_edrop)|56|421632|5|0.0%|1.8%|
[stopforumspam_30d](#stopforumspam_30d)|92135|92135|3|0.0%|1.1%|
[openbl_60d](#openbl_60d)|7635|7635|2|0.0%|0.7%|
[openbl_30d](#openbl_30d)|3280|3280|2|0.0%|0.7%|
[stopforumspam_7d](#stopforumspam_7d)|31070|31070|1|0.0%|0.3%|
[php_commenters](#php_commenters)|281|281|1|0.3%|0.3%|
[openbl_7d](#openbl_7d)|909|909|1|0.1%|0.3%|
[nixspam](#nixspam)|20463|20463|1|0.0%|0.3%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.3%|
[et_compromised](#et_compromised)|2367|2367|1|0.0%|0.3%|
[cleanmx_viruses](#cleanmx_viruses)|317|317|1|0.3%|0.3%|
[bruteforceblocker](#bruteforceblocker)|2212|2212|1|0.0%|0.3%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1281|1281|1|0.0%|0.3%|
[blocklist_de_apache](#blocklist_de_apache)|13637|13637|1|0.0%|0.3%|
[blocklist_de](#blocklist_de)|21934|21934|1|0.0%|0.3%|

## zeus_badips

[Abuse.ch Zeus tracker](https://zeustracker.abuse.ch) badips includes IPv4 addresses that are used by the ZeuS trojan. It is the recommened blocklist if you want to block only ZeuS IPs. It excludes IP addresses that ZeuS Tracker believes to be hijacked (level 2) or belong to a free web hosting provider (level 3). Hence the false postive rate should be much lower compared to the standard ZeuS IP blocklist. **excellent list**

Source is downloaded from [this link](https://zeustracker.abuse.ch/blocklist.php?download=badips).

The last time downloaded was found to be dated: Sun May 31 09:00:21 UTC 2015.

The ipset `zeus_badips` has **229** entries, **229** unique IPs.

The following table shows the overlaps of `zeus_badips` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `zeus_badips`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `zeus_badips`.
- ` this % ` is the percentage **of this ipset (`zeus_badips`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[zeus](#zeus)|264|264|229|86.7%|100.0%|
[et_block](#et_block)|986|18056524|228|0.0%|99.5%|
[snort_ipfilter](#snort_ipfilter)|1922|1922|197|10.2%|86.0%|
[alienvault_reputation](#alienvault_reputation)|173978|173978|37|0.0%|16.1%|
[spamhaus_drop](#spamhaus_drop)|650|18333440|16|0.0%|6.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|14|0.0%|6.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|10|0.0%|4.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|8|0.0%|3.4%|
[spamhaus_edrop](#spamhaus_edrop)|56|421632|5|0.0%|2.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|4|0.0%|1.7%|
[stopforumspam_30d](#stopforumspam_30d)|92135|92135|3|0.0%|1.3%|
[stopforumspam_7d](#stopforumspam_7d)|31070|31070|1|0.0%|0.4%|
[php_commenters](#php_commenters)|281|281|1|0.3%|0.4%|
[openbl_60d](#openbl_60d)|7635|7635|1|0.0%|0.4%|
[openbl_30d](#openbl_30d)|3280|3280|1|0.0%|0.4%|
[nixspam](#nixspam)|20463|20463|1|0.0%|0.4%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.4%|
[et_compromised](#et_compromised)|2367|2367|1|0.0%|0.4%|
[bruteforceblocker](#bruteforceblocker)|2212|2212|1|0.0%|0.4%|
