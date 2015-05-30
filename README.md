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

As time passes and the internet matures in our life, cyber crime is becoming increasingly sophisticated.
Although there many tools (detection of malware, viruses, intrusion detection and prevension systems, etc)
to help us isolate the budguys, there are now a lot more than just such attacks.

What is more interesting is that the fraudsters or attackers in many cases are not going to do a
direct damage to you or your systems. They will use you and your systems to gain something else,
possibly not related or indirectly related to your business. Nowdays the attacks cannot be identified easily. They are
distributed and come to our systems from a vast amount of IPs around the world.

To get an idea, check for example the [XRumer](http://en.wikipedia.org/wiki/XRumer) software. This thing mimics human
behaviour to post ads, it creates email accounts, responds to emails it receives, bypasses captchas, it goes gently
to stay unoticed, etc.

To increase our effectiveness we need to complement our security solutions with our 
shared knowledge, our shared experience in this fight.

Hopefully, there are many teams out there that do their best to identify the attacks and pinpoint
the attackers. These teams release blocklists. Blocklists of IPs (for use in firewalls), domains & URLs
(for use in proxies), etc.

What we are interested here is IPs.

Using IP blocklists at the internet side of your firewall is a key component of internet security.
These lists share key knowledge between us, allowing us to learn from each other and effectively
isolate fraudsters and attackers from our services.

I decided to upload these lists to a github repo because:

1. They are freely available on the internet. The intention of their creators is to help internet security.
 Keep in mind though that a few of these lists may have special licences attached. Before using them, please
 check their source site for any information regarding proper use.

2. Github provides (via `git pull`) a unified way of updating all the lists together.
 Pulling this repo regularly on your machines, you will update all the IP lists at once.

3. Github also provides a unified version control. Using it we can have a history of what each list has done,
 which IPs or subnets were added and which were removed.

## DNSBLs

Check also another tool included in FireHOL v3+, called `dnsbl-ipset.sh`.

This tool is capable of creating an ipset based on your traffic by looking up information on DNSBLs and scoring it according to your preferences.

More information [here](https://github.com/ktsaou/firehol/wiki/dnsbl-ipset.sh).


---

# Using these ipsets

Please be very careful what you choose to use and how you use it.
If you blacklist traffic using these lists you may end up blocking
your users, your customers, even yourself (!) from accessing your
services.

1. Goto to the site of each list and read how each list is maintained. You are going to trust these guys for doing their job right.

2. Most sites have either a donation system or commercial lists of higher quality. Try to support them. 

3. I have included the TOR network in these lists (`bm_tor`, `dm_tor`, `et_tor`). The TOR network is not necessarily bad and you should not block it if you want to allow your users be anonymous. I have included it because for certain cases, allowing an anonymity network might be a risky thing (such as eCommerce).

4. Apply any blacklist at the internet side of your firewall. Be very carefull. The `bogons` and `fullbogons` lists contain private, unroutable IPs that should not be routed on the internet. If you apply such a blocklist on your DMZ or LAN side, you will be blocked out of your firewall.

5. Always have a whitelist too, containing the IP addresses or subnets you trust. Try to build the rules in such a way that if an IP is in the whitelist, it should not be blocked by these blocklists.


## Which ones to use

These are the ones I install on all my firewalls:

1. **Abuse.ch** lists `feodo`, `palevo`, `sslbl`, `zeus`, `zeus_badips`
   
   These folks are doing a great job tracking crimeware. Their blocklists are very focused.

2. **DShield.org** list `dshield`

   It contains the top 20 attacking class C (/24) subnets, over the last three days.

3. **Spamhaus.org** lists `spamhaus_drop`, `spamhaus_edrop`
   
   DROP (Don't Route Or Peer) and EDROP are advisory "drop all traffic" lists, consisting of netblocks that are "hijacked" or leased by professional spam or cyber-crime operations (used for dissemination of malware, trojan downloaders, botnet controllers).
   According to Spamhaus.org:

   > When implemented at a network or ISP's 'core routers', DROP and EDROP will help protect the network's users from spamming, scanning, harvesting, DNS-hijacking and DDoS attacks originating on rogue netblocks.
   > 
   > Spamhaus strongly encourages the use of DROP and EDROP by tier-1s and backbones.

4. **Team-Cymru.org** list `bogons` or `fullbogons`

   These are lists of IPs that should not be routed on the internet. No one should be using them.
   Be very carefull to apply either of the two on the internet side of your network.

5. **OpenBL.org** lists `openbl*`
   
   The team of OpenBL tracks brute force attacks on their hosts. They suggest to use the default blacklist which has a retension policy of 90 days (`openbl`), but they also provide lists with different retension policies (from 1 day to 1 year).
   Their goal is to report abuse to the responsible provider so that the infection is disabled.

6. **Blocklist.de** lists `blocklist_de*`
   
   Is a network of users reporting abuse mainly using `fail2ban`.
   They only include IPs that have attacked them in the last 48 hours.
   Their goal is also to report abuse back, so that the infection is disabled.


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

The following list was automatically generated on Sat May 30 11:43:55 UTC 2015.

The update frequency is the maximum allowed by internal configuration. A list will never be downloaded sooner than the update frequency stated. A list may also not be downloaded, after this frequency expired, if it has not been modified on the server (as reported by HTTP `IF_MODIFIED_SINCE` method).

name|info|type|entries|update|
:--:|:--:|:--:|:-----:|:----:|
[alienvault_reputation](#alienvault_reputation)|[AlienVault.com](https://www.alienvault.com/) IP reputation database (this list seems to include port scanning hosts and to be updated regularly, but we found no information about its retention policy)|ipv4 hash:ip|174737 unique IPs|updated every 6 hours  from [this link](https://reputation.alienvault.com/reputation.generic)
[blocklist_de](#blocklist_de)|[Blocklist.de](https://www.blocklist.de/) IPs that have been detected by fail2ban in the last 48 hours - **excellent list**|ipv4 hash:ip|21611 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/all.txt)
[blocklist_de_apache](#blocklist_de_apache)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service Apache, Apache-DDOS, RFI-Attacks.|ipv4 hash:ip|12527 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/apache.txt)
[blocklist_de_bots](#blocklist_de_bots)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the RFI-Attacks, REG-Bots, IRC-Bots or BadBots (BadBots = he has posted a Spam-Comment on a open Forum or Wiki).|ipv4 hash:ip|3420 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/bots.txt)
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|[Blocklist.de](https://www.blocklist.de/) All IPs which attacks Joomlas, Wordpress and other Web-Logins with Brute-Force Logins.|ipv4 hash:ip|1201 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/bruteforcelogin.txt)
[blocklist_de_ftp](#blocklist_de_ftp)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours for attacks on the Service FTP.|ipv4 hash:ip|373 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/ftp.txt)
[blocklist_de_imap](#blocklist_de_imap)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours for attacks on the Service imap, sasl, pop3, etc.|ipv4 hash:ip|777 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/imap.txt)
[blocklist_de_mail](#blocklist_de_mail)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service Mail, Postfix.|ipv4 hash:ip|14463 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/mail.txt)
[blocklist_de_sip](#blocklist_de_sip)|[Blocklist.de](https://www.blocklist.de/) All IP addresses that tried to login in a SIP, VOIP or Asterisk Server and are included in the IPs list from [infiltrated.net](www.infiltrated.net)|ipv4 hash:ip|85 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/sip.txt)
[blocklist_de_ssh](#blocklist_de_ssh)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service SSH.|ipv4 hash:ip|1834 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/ssh.txt)
[blocklist_de_strongips](#blocklist_de_strongips)|[Blocklist.de](https://www.blocklist.de/) All IPs which are older then 2 month and have more then 5.000 attacks.|ipv4 hash:ip|194 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/strongips.txt)
[bm_tor](#bm_tor)|[torstatus.blutmagie.de](https://torstatus.blutmagie.de) list of all TOR network servers|ipv4 hash:ip|6474 unique IPs|updated every 30 mins  from [this link](https://torstatus.blutmagie.de/ip_list_all.php/Tor_ip_list_ALL.csv)
[bogons](#bogons)|[Team-Cymru.org](http://www.team-cymru.org) private and reserved addresses defined by RFC 1918, RFC 5735, and RFC 6598 and netblocks that have not been allocated to a regional internet registry - **excellent list - use it only your internet interface**|ipv4 hash:net|13 subnets, 592708608 unique IPs|updated every 1 day  from [this link](http://www.team-cymru.org/Services/Bogons/bogon-bn-agg.txt)
[bruteforceblocker](#bruteforceblocker)|[danger.rulez.sk](http://danger.rulez.sk/) IPs detected by [bruteforceblocker](http://danger.rulez.sk/index.php/bruteforceblocker/) (fail2ban alternative for SSH on OpenBSD)|ipv4 hash:ip|2254 unique IPs|updated every 3 hours  from [this link](http://danger.rulez.sk/projects/bruteforceblocker/blist.php)
[ciarmy](#ciarmy)|[CIArmy.com](http://ciarmy.com/) IPs with poor Rogue Packet score that have not yet been identified as malicious by the community|ipv4 hash:ip|348 unique IPs|updated every 3 hours  from [this link](http://cinsscore.com/list/ci-badguys.txt)
[cleanmx_viruses](#cleanmx_viruses)|[Clean-MX.de](http://support.clean-mx.de/clean-mx/viruses.php) IPs with viruses|ipv4 hash:ip|259 unique IPs|updated every 12 hours  from [this link](http://support.clean-mx.de/clean-mx/xmlviruses.php?sort=id%20desc&response=alive)
[dm_tor](#dm_tor)|[dan.me.uk](https://www.dan.me.uk) dynamic list of TOR exit points|ipv4 hash:ip|6479 unique IPs|updated every 30 mins  from [this link](https://www.dan.me.uk/torlist/)
[dshield](#dshield)|[DShield.org](https://dshield.org/) top 20 attacking class C (/24) subnets over the last three days - **excellent list**|ipv4 hash:net|20 subnets, 5120 unique IPs|updated every 4 hours  from [this link](http://feeds.dshield.org/block.txt)
[et_block](#et_block)|[EmergingThreats.net](http://www.emergingthreats.net/) default blacklist (at the time of writing includes spamhaus DROP, dshield and abuse.ch trackers, which are available separately too - prefer to use the direct ipsets instead of this, they seem to lag a bit in updates)|ipv4 hash:net|986 subnets, 18056524 unique IPs|updated every 12 hours  from [this link](http://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt)
[et_botcc](#et_botcc)|[EmergingThreats.net Command and Control IPs](http://doc.emergingthreats.net/bin/view/Main/BotCC) These IPs are updates every 24 hours and should be considered VERY highly reliable indications that a host is communicating with a known and active Bot or Malware command and control server - (although they say this includes abuse.ch trackers, it does not - most probably it is the shadowserver.org C&C list)|ipv4 hash:ip|501 unique IPs|updated every 12 hours  from [this link](http://rules.emergingthreats.net/fwrules/emerging-PIX-CC.rules)
[et_compromised](#et_compromised)|[EmergingThreats.net](http://www.emergingthreats.net/) compromised hosts (seems to be a derivate of other lists)|ipv4 hash:ip|2367 unique IPs|updated every 12 hours  from [this link](http://rules.emergingthreats.net/blockrules/compromised-ips.txt)
[et_tor](#et_tor)|[EmergingThreats.net](http://www.emergingthreats.net/) [list](http://doc.emergingthreats.net/bin/view/Main/TorRules) of TOR network IPs|ipv4 hash:ip|6470 unique IPs|updated every 12 hours  from [this link](http://rules.emergingthreats.net/blockrules/emerging-tor.rules)
[feodo](#feodo)|[Abuse.ch Feodo tracker](https://feodotracker.abuse.ch) trojan includes IPs which are being used by Feodo (also known as Cridex or Bugat) which commits ebanking fraud - **excellent list**|ipv4 hash:ip|70 unique IPs|updated every 30 mins  from [this link](https://feodotracker.abuse.ch/blocklist/?download=ipblocklist)
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
[malc0de](#malc0de)|[Malc0de.com](http://malc0de.com) malicious IPs of the last 30 days|ipv4 hash:ip|410 unique IPs|updated every 1 day  from [this link](http://malc0de.com/bl/IP_Blacklist.txt)
[malwaredomainlist](#malwaredomainlist)|[malwaredomainlist.com](http://www.malwaredomainlist.com) list of malware active ip addresses|ipv4 hash:ip|1282 unique IPs|updated every 12 hours  from [this link](http://www.malwaredomainlist.com/hostslist/ip.txt)
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|[MaxMind.com](https://www.maxmind.com/en/anonymous-proxy-fraudulent-ip-address-list) list of anonymous proxy fraudelent IP addresses.|ipv4 hash:ip|372 unique IPs|updated every 4 hours  from [this link](https://www.maxmind.com/en/anonymous-proxy-fraudulent-ip-address-list)
[nixspam](#nixspam)|[NiX Spam](http://www.heise.de/ix/NiX-Spam-DNSBL-and-blacklist-for-download-499637.html) IP addresses that sent spam in the last hour - automatically generated entries without distinguishing open proxies from relays, dialup gateways, and so on. All IPs are removed after 12 hours if there is no spam from there.|ipv4 hash:ip|22785 unique IPs|updated every 15 mins  from [this link](http://www.dnsbl.manitu.net/download/nixspam-ip.dump.gz)
[openbl](#openbl)|[OpenBL.org](http://www.openbl.org/) default blacklist (currently it is the same with 90 days). OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications - **excellent list**|ipv4 hash:ip|9797 unique IPs|updated every 4 hours  from [this link](http://www.openbl.org/lists/base.txt)
[openbl_1d](#openbl_1d)|[OpenBL.org](http://www.openbl.org/) last 24 hours IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|229 unique IPs|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_1days.txt)
[openbl_30d](#openbl_30d)|[OpenBL.org](http://www.openbl.org/) last 30 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|3339 unique IPs|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_30days.txt)
[openbl_60d](#openbl_60d)|[OpenBL.org](http://www.openbl.org/) last 60 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|7680 unique IPs|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_60days.txt)
[openbl_7d](#openbl_7d)|[OpenBL.org](http://www.openbl.org/) last 7 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|949 unique IPs|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_7days.txt)
[openbl_90d](#openbl_90d)|[OpenBL.org](http://www.openbl.org/) last 90 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|9797 unique IPs|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_90days.txt)
[palevo](#palevo)|[Abuse.ch Palevo tracker](https://palevotracker.abuse.ch) worm includes IPs which are being used as botnet C&C for the Palevo crimeware - **excellent list**|ipv4 hash:ip|13 unique IPs|updated every 30 mins  from [this link](https://palevotracker.abuse.ch/blocklists.php?download=ipblocklist)
[php_bad](#php_bad)|[projecthoneypot.org](http://www.projecthoneypot.org/) bad web hosts (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|281 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=b&rss=1)
[php_commenters](#php_commenters)|[projecthoneypot.org](http://www.projecthoneypot.org/) comment spammers (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|281 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=c&rss=1)
[php_dictionary](#php_dictionary)|[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) directory attackers (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|433 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=d&rss=1)
[php_harvesters](#php_harvesters)|[projecthoneypot.org](http://www.projecthoneypot.org/) harvesters (IPs that surf the internet looking for email addresses) (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|257 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=h&rss=1)
[php_spammers](#php_spammers)|[projecthoneypot.org](http://www.projecthoneypot.org/) spam servers (IPs used by spammers to send messages) (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|417 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=s&rss=1)
[proxyrss](#proxyrss)|[proxyrss.com](http://www.proxyrss.com) open proxies syndicated from multiple sources.|ipv4 hash:ip|1548 unique IPs|updated every 4 hours  from [this link](http://www.proxyrss.com/proxylists/all.gz)
[proxz](#proxz)|[proxz.com](http://www.proxz.com) open proxies (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|236 unique IPs|updated every 1 hour  from [this link](http://www.proxz.com/proxylists.xml)
[ri_connect_proxies](#ri_connect_proxies)|[rosinstrument.com](http://www.rosinstrument.com) open CONNECT proxies (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|1842 unique IPs|updated every 1 hour  from [this link](http://tools.rosinstrument.com/proxy/plab100.xml)
[ri_web_proxies](#ri_web_proxies)|[rosinstrument.com](http://www.rosinstrument.com) open HTTP proxies (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|4837 unique IPs|updated every 1 hour  from [this link](http://tools.rosinstrument.com/proxy/l100.xml)
[shunlist](#shunlist)|[AutoShun.org](http://autoshun.org/) IPs identified as hostile by correlating logs from distributed snort installations running the autoshun plugin|ipv4 hash:ip|1180 unique IPs|updated every 4 hours  from [this link](http://www.autoshun.org/files/shunlist.csv)
[snort_ipfilter](#snort_ipfilter)|[labs.snort.org](https://labs.snort.org/) supplied IP blacklist (this list seems to be updated frequently, but we found no information about it)|ipv4 hash:ip|5712 unique IPs|updated every 12 hours  from [this link](http://labs.snort.org/feeds/ip-filter.blf)
[spamhaus_drop](#spamhaus_drop)|[Spamhaus.org](http://www.spamhaus.org) DROP list (according to their site this list should be dropped at tier-1 ISPs globaly) - **excellent list**|ipv4 hash:net|640 subnets, 17925376 unique IPs|updated every 12 hours  from [this link](http://www.spamhaus.org/drop/drop.txt)
[spamhaus_edrop](#spamhaus_edrop)|[Spamhaus.org](http://www.spamhaus.org) EDROP (extended matches that should be used with DROP) - **excellent list**|ipv4 hash:net|55 subnets, 421120 unique IPs|updated every 12 hours  from [this link](http://www.spamhaus.org/drop/edrop.txt)
[sslbl](#sslbl)|[Abuse.ch SSL Blacklist](https://sslbl.abuse.ch/) bad SSL traffic related to malware or botnet activities - **excellent list**|ipv4 hash:ip|349 unique IPs|updated every 30 mins  from [this link](https://sslbl.abuse.ch/blacklist/sslipblacklist.csv)
[stopforumspam_1d](#stopforumspam_1d)|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers in the last 24 hours - **excellent list**|ipv4 hash:ip|6841 unique IPs|updated every 1 hour  from [this link](http://www.stopforumspam.com/downloads/listed_ip_1.zip)
[stopforumspam_30d](#stopforumspam_30d)|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 30 days)|ipv4 hash:ip|92359 unique IPs|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/listed_ip_30.zip)
[stopforumspam_7d](#stopforumspam_7d)|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 7 days)|ipv4 hash:ip|30993 unique IPs|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/listed_ip_7.zip)
[voipbl](#voipbl)|[VoIPBL.org](http://www.voipbl.org/) a distributed VoIP blacklist that is aimed to protects against VoIP Fraud and minimizing abuse for network that have publicly accessible PBX's. Several algorithms, external sources and manual confirmation are used before they categorize something as an attack and determine the threat level.|ipv4 hash:net|10305 subnets, 10714 unique IPs|updated every 4 hours  from [this link](http://www.voipbl.org/update/)
[xroxy](#xroxy)|[xroxy.com](http://www.xroxy.com) open proxies (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|1963 unique IPs|updated every 1 hour  from [this link](http://www.xroxy.com/proxyrss.xml)
[zeus](#zeus)|[Abuse.ch Zeus tracker](https://zeustracker.abuse.ch) standard, contains the same data as the ZeuS IP blocklist (zeus_badips) but with the slight difference that it doesn't exclude hijacked websites (level 2) and free web hosting providers (level 3). This means that this blocklist contains all IPv4 addresses associated with ZeuS C&Cs which are currently being tracked by ZeuS Tracker. Hence this blocklist will likely cause some false positives. - **excellent list**|ipv4 hash:ip|267 unique IPs|updated every 30 mins  from [this link](https://zeustracker.abuse.ch/blocklist.php?download=ipblocklist)
[zeus_badips](#zeus_badips)|[Abuse.ch Zeus tracker](https://zeustracker.abuse.ch) badips includes IPv4 addresses that are used by the ZeuS trojan. It is the recommened blocklist if you want to block only ZeuS IPs. It excludes IP addresses that ZeuS Tracker believes to be hijacked (level 2) or belong to a free web hosting provider (level 3). Hence the false postive rate should be much lower compared to the standard ZeuS IP blocklist. **excellent list**|ipv4 hash:ip|229 unique IPs|updated every 30 mins  from [this link](https://zeustracker.abuse.ch/blocklist.php?download=badips)

# Comparison of ipsets

Below we compare each ipset against all other.


## alienvault_reputation

[AlienVault.com](https://www.alienvault.com/) IP reputation database (this list seems to include port scanning hosts and to be updated regularly, but we found no information about its retention policy)

Source is downloaded from [this link](https://reputation.alienvault.com/reputation.generic).

The last time downloaded was found to be dated: Sat May 30 10:00:35 UTC 2015.

The ipset `alienvault_reputation` has **174737** entries, **174737** unique IPs.

The following table shows the overlaps of `alienvault_reputation` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `alienvault_reputation`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `alienvault_reputation`.
- ` this % ` is the percentage **of this ipset (`alienvault_reputation`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|14896|0.0%|8.5%|
[openbl_90d](#openbl_90d)|9797|9797|9772|99.7%|5.5%|
[openbl](#openbl)|9797|9797|9772|99.7%|5.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|8388|0.0%|4.8%|
[openbl_60d](#openbl_60d)|7680|7680|7658|99.7%|4.3%|
[et_block](#et_block)|986|18056524|6044|0.0%|3.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|4710|0.0%|2.6%|
[openbl_30d](#openbl_30d)|3339|3339|3325|99.5%|1.9%|
[dshield](#dshield)|20|5120|2562|50.0%|1.4%|
[spamhaus_drop](#spamhaus_drop)|640|17925376|1626|0.0%|0.9%|
[et_compromised](#et_compromised)|2367|2367|1533|64.7%|0.8%|
[bruteforceblocker](#bruteforceblocker)|2254|2254|1469|65.1%|0.8%|
[blocklist_de](#blocklist_de)|21611|21611|1301|6.0%|0.7%|
[shunlist](#shunlist)|1180|1180|1179|99.9%|0.6%|
[blocklist_de_ssh](#blocklist_de_ssh)|1834|1834|1051|57.3%|0.6%|
[openbl_7d](#openbl_7d)|949|949|941|99.1%|0.5%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|519|0.0%|0.2%|
[ciarmy](#ciarmy)|348|348|336|96.5%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|289|0.0%|0.1%|
[openbl_1d](#openbl_1d)|229|229|227|99.1%|0.1%|
[stopforumspam_30d](#stopforumspam_30d)|92359|92359|226|0.2%|0.1%|
[voipbl](#voipbl)|10305|10714|208|1.9%|0.1%|
[blocklist_de_apache](#blocklist_de_apache)|12527|12527|120|0.9%|0.0%|
[snort_ipfilter](#snort_ipfilter)|5712|5712|117|2.0%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|30993|30993|114|0.3%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14463|14463|84|0.5%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|777|777|67|8.6%|0.0%|
[zeus](#zeus)|267|267|65|24.3%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6841|6841|60|0.8%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|194|194|58|29.8%|0.0%|
[et_tor](#et_tor)|6470|6470|48|0.7%|0.0%|
[dm_tor](#dm_tor)|6479|6479|48|0.7%|0.0%|
[bm_tor](#bm_tor)|6474|6474|48|0.7%|0.0%|
[nixspam](#nixspam)|22785|22785|42|0.1%|0.0%|
[zeus_badips](#zeus_badips)|229|229|37|16.1%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|25|6.7%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3420|3420|25|0.7%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|85|85|18|21.1%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1201|1201|17|1.4%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|15|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|14|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|373|373|14|3.7%|0.0%|
[php_commenters](#php_commenters)|281|281|12|4.2%|0.0%|
[php_bad](#php_bad)|281|281|12|4.2%|0.0%|
[sslbl](#sslbl)|349|349|11|3.1%|0.0%|
[php_harvesters](#php_harvesters)|257|257|9|3.5%|0.0%|
[malc0de](#malc0de)|410|410|9|2.1%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|8|0.5%|0.0%|
[php_dictionary](#php_dictionary)|433|433|7|1.6%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1282|1282|7|0.5%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|259|259|6|2.3%|0.0%|
[xroxy](#xroxy)|1963|1963|5|0.2%|0.0%|
[ri_web_proxies](#ri_web_proxies)|4837|4837|3|0.0%|0.0%|
[php_spammers](#php_spammers)|417|417|3|0.7%|0.0%|
[et_botcc](#et_botcc)|501|501|3|0.5%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|1842|1842|2|0.1%|0.0%|
[proxz](#proxz)|236|236|2|0.8%|0.0%|
[proxyrss](#proxyrss)|1548|1548|2|0.1%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|1|0.1%|0.0%|
[feodo](#feodo)|70|70|1|1.4%|0.0%|

## blocklist_de

[Blocklist.de](https://www.blocklist.de/) IPs that have been detected by fail2ban in the last 48 hours - **excellent list**

Source is downloaded from [this link](http://lists.blocklist.de/lists/all.txt).

The last time downloaded was found to be dated: Sat May 30 11:10:03 UTC 2015.

The ipset `blocklist_de` has **21611** entries, **21611** unique IPs.

The following table shows the overlaps of `blocklist_de` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de`.
- ` this % ` is the percentage **of this ipset (`blocklist_de`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de_mail](#blocklist_de_mail)|14463|14463|14461|99.9%|66.9%|
[blocklist_de_apache](#blocklist_de_apache)|12527|12527|12526|99.9%|57.9%|
[blocklist_de_bots](#blocklist_de_bots)|3420|3420|3420|100.0%|15.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|2809|0.0%|12.9%|
[stopforumspam_30d](#stopforumspam_30d)|92359|92359|2704|2.9%|12.5%|
[stopforumspam_7d](#stopforumspam_7d)|30993|30993|2369|7.6%|10.9%|
[blocklist_de_ssh](#blocklist_de_ssh)|1834|1834|1834|100.0%|8.4%|
[stopforumspam_1d](#stopforumspam_1d)|6841|6841|1563|22.8%|7.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|1469|0.0%|6.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|1440|0.0%|6.6%|
[alienvault_reputation](#alienvault_reputation)|174737|174737|1301|0.7%|6.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1201|1201|1201|100.0%|5.5%|
[openbl_90d](#openbl_90d)|9797|9797|1036|10.5%|4.7%|
[openbl](#openbl)|9797|9797|1036|10.5%|4.7%|
[openbl_60d](#openbl_60d)|7680|7680|987|12.8%|4.5%|
[openbl_30d](#openbl_30d)|3339|3339|909|27.2%|4.2%|
[bruteforceblocker](#bruteforceblocker)|2254|2254|813|36.0%|3.7%|
[et_compromised](#et_compromised)|2367|2367|789|33.3%|3.6%|
[blocklist_de_imap](#blocklist_de_imap)|777|777|777|100.0%|3.5%|
[openbl_7d](#openbl_7d)|949|949|578|60.9%|2.6%|
[nixspam](#nixspam)|22785|22785|539|2.3%|2.4%|
[shunlist](#shunlist)|1180|1180|479|40.5%|2.2%|
[ri_web_proxies](#ri_web_proxies)|4837|4837|396|8.1%|1.8%|
[blocklist_de_ftp](#blocklist_de_ftp)|373|373|373|100.0%|1.7%|
[xroxy](#xroxy)|1963|1963|304|15.4%|1.4%|
[proxyrss](#proxyrss)|1548|1548|262|16.9%|1.2%|
[openbl_1d](#openbl_1d)|229|229|212|92.5%|0.9%|
[et_block](#et_block)|986|18056524|195|0.0%|0.9%|
[blocklist_de_strongips](#blocklist_de_strongips)|194|194|194|100.0%|0.8%|
[spamhaus_drop](#spamhaus_drop)|640|17925376|184|0.0%|0.8%|
[snort_ipfilter](#snort_ipfilter)|5712|5712|122|2.1%|0.5%|
[dshield](#dshield)|20|5120|106|2.0%|0.4%|
[ri_connect_proxies](#ri_connect_proxies)|1842|1842|84|4.5%|0.3%|
[php_commenters](#php_commenters)|281|281|67|23.8%|0.3%|
[php_bad](#php_bad)|281|281|67|23.8%|0.3%|
[php_dictionary](#php_dictionary)|433|433|66|15.2%|0.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|66|0.0%|0.3%|
[blocklist_de_sip](#blocklist_de_sip)|85|85|66|77.6%|0.3%|
[proxz](#proxz)|236|236|64|27.1%|0.2%|
[php_spammers](#php_spammers)|417|417|59|14.1%|0.2%|
[ciarmy](#ciarmy)|348|348|43|12.3%|0.1%|
[voipbl](#voipbl)|10305|10714|37|0.3%|0.1%|
[php_harvesters](#php_harvesters)|257|257|28|10.8%|0.1%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|19|0.0%|0.0%|
[dm_tor](#dm_tor)|6479|6479|17|0.2%|0.0%|
[bm_tor](#bm_tor)|6474|6474|17|0.2%|0.0%|
[et_tor](#et_tor)|6470|6470|16|0.2%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|5|0.7%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|3|0.8%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|259|259|3|1.1%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|2|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|2|0.0%|0.0%|
[zeus](#zeus)|267|267|1|0.3%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|

## blocklist_de_apache

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service Apache, Apache-DDOS, RFI-Attacks.

Source is downloaded from [this link](http://lists.blocklist.de/lists/apache.txt).

The last time downloaded was found to be dated: Sat May 30 11:28:05 UTC 2015.

The ipset `blocklist_de_apache` has **12527** entries, **12527** unique IPs.

The following table shows the overlaps of `blocklist_de_apache` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_apache`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_apache`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_apache`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|21611|21611|12526|57.9%|99.9%|
[blocklist_de_mail](#blocklist_de_mail)|14463|14463|11059|76.4%|88.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|2191|0.0%|17.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|1312|0.0%|10.4%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1201|1201|1201|100.0%|9.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|1068|0.0%|8.5%|
[stopforumspam_30d](#stopforumspam_30d)|92359|92359|215|0.2%|1.7%|
[stopforumspam_7d](#stopforumspam_7d)|30993|30993|129|0.4%|1.0%|
[alienvault_reputation](#alienvault_reputation)|174737|174737|120|0.0%|0.9%|
[stopforumspam_1d](#stopforumspam_1d)|6841|6841|75|1.0%|0.5%|
[ciarmy](#ciarmy)|348|348|39|11.2%|0.3%|
[blocklist_de_strongips](#blocklist_de_strongips)|194|194|35|18.0%|0.2%|
[shunlist](#shunlist)|1180|1180|32|2.7%|0.2%|
[php_commenters](#php_commenters)|281|281|26|9.2%|0.2%|
[php_bad](#php_bad)|281|281|26|9.2%|0.2%|
[snort_ipfilter](#snort_ipfilter)|5712|5712|24|0.4%|0.1%|
[blocklist_de_bots](#blocklist_de_bots)|3420|3420|17|0.4%|0.1%|
[et_tor](#et_tor)|6470|6470|16|0.2%|0.1%|
[dm_tor](#dm_tor)|6479|6479|16|0.2%|0.1%|
[bm_tor](#bm_tor)|6474|6474|16|0.2%|0.1%|
[openbl_90d](#openbl_90d)|9797|9797|12|0.1%|0.0%|
[openbl](#openbl)|9797|9797|12|0.1%|0.0%|
[openbl_60d](#openbl_60d)|7680|7680|10|0.1%|0.0%|
[nixspam](#nixspam)|22785|22785|8|0.0%|0.0%|
[openbl_30d](#openbl_30d)|3339|3339|6|0.1%|0.0%|
[et_block](#et_block)|986|18056524|6|0.0%|0.0%|
[php_spammers](#php_spammers)|417|417|5|1.1%|0.0%|
[spamhaus_drop](#spamhaus_drop)|640|17925376|3|0.0%|0.0%|
[openbl_7d](#openbl_7d)|949|949|3|0.3%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|259|259|3|1.1%|0.0%|
[voipbl](#voipbl)|10305|10714|2|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|2|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|2|0.5%|0.0%|
[et_compromised](#et_compromised)|2367|2367|2|0.0%|0.0%|
[dshield](#dshield)|20|5120|2|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2254|2254|2|0.0%|0.0%|
[zeus](#zeus)|267|267|1|0.3%|0.0%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.0%|
[openbl_1d](#openbl_1d)|229|229|1|0.4%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.0%|

## blocklist_de_bots

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the RFI-Attacks, REG-Bots, IRC-Bots or BadBots (BadBots = he has posted a Spam-Comment on a open Forum or Wiki).

Source is downloaded from [this link](http://lists.blocklist.de/lists/bots.txt).

The last time downloaded was found to be dated: Sat May 30 11:10:09 UTC 2015.

The ipset `blocklist_de_bots` has **3420** entries, **3420** unique IPs.

The following table shows the overlaps of `blocklist_de_bots` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_bots`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_bots`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_bots`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|21611|21611|3420|15.8%|100.0%|
[stopforumspam_30d](#stopforumspam_30d)|92359|92359|2397|2.5%|70.0%|
[stopforumspam_7d](#stopforumspam_7d)|30993|30993|2194|7.0%|64.1%|
[stopforumspam_1d](#stopforumspam_1d)|6841|6841|1491|21.7%|43.5%|
[ri_web_proxies](#ri_web_proxies)|4837|4837|365|7.5%|10.6%|
[xroxy](#xroxy)|1963|1963|261|13.2%|7.6%|
[proxyrss](#proxyrss)|1548|1548|261|16.8%|7.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|168|0.0%|4.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|133|0.0%|3.8%|
[blocklist_de_strongips](#blocklist_de_strongips)|194|194|125|64.4%|3.6%|
[ri_connect_proxies](#ri_connect_proxies)|1842|1842|82|4.4%|2.3%|
[proxz](#proxz)|236|236|58|24.5%|1.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|57|0.0%|1.6%|
[php_commenters](#php_commenters)|281|281|52|18.5%|1.5%|
[php_bad](#php_bad)|281|281|52|18.5%|1.5%|
[spamhaus_drop](#spamhaus_drop)|640|17925376|51|0.0%|1.4%|
[et_block](#et_block)|986|18056524|51|0.0%|1.4%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|50|0.0%|1.4%|
[nixspam](#nixspam)|22785|22785|48|0.2%|1.4%|
[alienvault_reputation](#alienvault_reputation)|174737|174737|25|0.0%|0.7%|
[php_harvesters](#php_harvesters)|257|257|23|8.9%|0.6%|
[snort_ipfilter](#snort_ipfilter)|5712|5712|17|0.2%|0.4%|
[blocklist_de_mail](#blocklist_de_mail)|14463|14463|17|0.1%|0.4%|
[blocklist_de_apache](#blocklist_de_apache)|12527|12527|17|0.1%|0.4%|
[php_spammers](#php_spammers)|417|417|16|3.8%|0.4%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|15|0.0%|0.4%|
[php_dictionary](#php_dictionary)|433|433|15|3.4%|0.4%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|4|0.5%|0.1%|
[voipbl](#voipbl)|10305|10714|1|0.0%|0.0%|
[openbl_90d](#openbl_90d)|9797|9797|1|0.0%|0.0%|
[openbl](#openbl)|9797|9797|1|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1|0.0%|0.0%|
[dm_tor](#dm_tor)|6479|6479|1|0.0%|0.0%|
[bm_tor](#bm_tor)|6474|6474|1|0.0%|0.0%|

## blocklist_de_bruteforce

[Blocklist.de](https://www.blocklist.de/) All IPs which attacks Joomlas, Wordpress and other Web-Logins with Brute-Force Logins.

Source is downloaded from [this link](http://lists.blocklist.de/lists/bruteforcelogin.txt).

The last time downloaded was found to be dated: Sat May 30 11:10:11 UTC 2015.

The ipset `blocklist_de_bruteforce` has **1201** entries, **1201** unique IPs.

The following table shows the overlaps of `blocklist_de_bruteforce` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_bruteforce`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_bruteforce`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_bruteforce`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de_apache](#blocklist_de_apache)|12527|12527|1201|9.5%|100.0%|
[blocklist_de](#blocklist_de)|21611|21611|1201|5.5%|100.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|98|0.0%|8.1%|
[stopforumspam_30d](#stopforumspam_30d)|92359|92359|62|0.0%|5.1%|
[stopforumspam_7d](#stopforumspam_7d)|30993|30993|54|0.1%|4.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|31|0.0%|2.5%|
[stopforumspam_1d](#stopforumspam_1d)|6841|6841|29|0.4%|2.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|23|0.0%|1.9%|
[snort_ipfilter](#snort_ipfilter)|5712|5712|21|0.3%|1.7%|
[alienvault_reputation](#alienvault_reputation)|174737|174737|17|0.0%|1.4%|
[et_tor](#et_tor)|6470|6470|13|0.2%|1.0%|
[dm_tor](#dm_tor)|6479|6479|13|0.2%|1.0%|
[bm_tor](#bm_tor)|6474|6474|13|0.2%|1.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|194|194|10|5.1%|0.8%|
[nixspam](#nixspam)|22785|22785|8|0.0%|0.6%|
[php_commenters](#php_commenters)|281|281|6|2.1%|0.4%|
[php_bad](#php_bad)|281|281|6|2.1%|0.4%|
[php_spammers](#php_spammers)|417|417|5|1.1%|0.4%|
[et_block](#et_block)|986|18056524|4|0.0%|0.3%|
[spamhaus_drop](#spamhaus_drop)|640|17925376|3|0.0%|0.2%|
[openbl_90d](#openbl_90d)|9797|9797|3|0.0%|0.2%|
[openbl](#openbl)|9797|9797|3|0.0%|0.2%|
[cleanmx_viruses](#cleanmx_viruses)|259|259|3|1.1%|0.2%|
[shunlist](#shunlist)|1180|1180|2|0.1%|0.1%|
[zeus](#zeus)|267|267|1|0.3%|0.0%|
[voipbl](#voipbl)|10305|10714|1|0.0%|0.0%|
[openbl_60d](#openbl_60d)|7680|7680|1|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.0%|
[dshield](#dshield)|20|5120|1|0.0%|0.0%|

## blocklist_de_ftp

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours for attacks on the Service FTP.

Source is downloaded from [this link](http://lists.blocklist.de/lists/ftp.txt).

The last time downloaded was found to be dated: Sat May 30 11:10:07 UTC 2015.

The ipset `blocklist_de_ftp` has **373** entries, **373** unique IPs.

The following table shows the overlaps of `blocklist_de_ftp` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_ftp`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_ftp`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_ftp`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|21611|21611|373|1.7%|100.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|28|0.0%|7.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|20|0.0%|5.3%|
[alienvault_reputation](#alienvault_reputation)|174737|174737|14|0.0%|3.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|13|0.0%|3.4%|
[stopforumspam_30d](#stopforumspam_30d)|92359|92359|11|0.0%|2.9%|
[openbl_90d](#openbl_90d)|9797|9797|7|0.0%|1.8%|
[openbl](#openbl)|9797|9797|7|0.0%|1.8%|
[nixspam](#nixspam)|22785|22785|7|0.0%|1.8%|
[openbl_60d](#openbl_60d)|7680|7680|6|0.0%|1.6%|
[php_harvesters](#php_harvesters)|257|257|4|1.5%|1.0%|
[stopforumspam_7d](#stopforumspam_7d)|30993|30993|3|0.0%|0.8%|
[stopforumspam_1d](#stopforumspam_1d)|6841|6841|2|0.0%|0.5%|
[openbl_7d](#openbl_7d)|949|949|2|0.2%|0.5%|
[openbl_30d](#openbl_30d)|3339|3339|2|0.0%|0.5%|
[spamhaus_drop](#spamhaus_drop)|640|17925376|1|0.0%|0.2%|
[snort_ipfilter](#snort_ipfilter)|5712|5712|1|0.0%|0.2%|
[shunlist](#shunlist)|1180|1180|1|0.0%|0.2%|
[openbl_1d](#openbl_1d)|229|229|1|0.4%|0.2%|
[et_compromised](#et_compromised)|2367|2367|1|0.0%|0.2%|
[et_block](#et_block)|986|18056524|1|0.0%|0.2%|
[dshield](#dshield)|20|5120|1|0.0%|0.2%|
[ciarmy](#ciarmy)|348|348|1|0.2%|0.2%|
[bruteforceblocker](#bruteforceblocker)|2254|2254|1|0.0%|0.2%|

## blocklist_de_imap

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours for attacks on the Service imap, sasl, pop3, etc.

Source is downloaded from [this link](http://lists.blocklist.de/lists/imap.txt).

The last time downloaded was found to be dated: Sat May 30 11:10:07 UTC 2015.

The ipset `blocklist_de_imap` has **777** entries, **777** unique IPs.

The following table shows the overlaps of `blocklist_de_imap` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_imap`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_imap`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_imap`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de_mail](#blocklist_de_mail)|14463|14463|777|5.3%|100.0%|
[blocklist_de](#blocklist_de)|21611|21611|777|3.5%|100.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|68|0.0%|8.7%|
[alienvault_reputation](#alienvault_reputation)|174737|174737|67|0.0%|8.6%|
[openbl_90d](#openbl_90d)|9797|9797|53|0.5%|6.8%|
[openbl](#openbl)|9797|9797|53|0.5%|6.8%|
[openbl_60d](#openbl_60d)|7680|7680|48|0.6%|6.1%|
[openbl_30d](#openbl_30d)|3339|3339|43|1.2%|5.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|40|0.0%|5.1%|
[openbl_7d](#openbl_7d)|949|949|29|3.0%|3.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|16|0.0%|2.0%|
[spamhaus_drop](#spamhaus_drop)|640|17925376|15|0.0%|1.9%|
[et_compromised](#et_compromised)|2367|2367|15|0.6%|1.9%|
[et_block](#et_block)|986|18056524|15|0.0%|1.9%|
[bruteforceblocker](#bruteforceblocker)|2254|2254|12|0.5%|1.5%|
[shunlist](#shunlist)|1180|1180|5|0.4%|0.6%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|4|0.0%|0.5%|
[openbl_1d](#openbl_1d)|229|229|3|1.3%|0.3%|
[stopforumspam_30d](#stopforumspam_30d)|92359|92359|2|0.0%|0.2%|
[nixspam](#nixspam)|22785|22785|2|0.0%|0.2%|
[stopforumspam_7d](#stopforumspam_7d)|30993|30993|1|0.0%|0.1%|
[snort_ipfilter](#snort_ipfilter)|5712|5712|1|0.0%|0.1%|
[dshield](#dshield)|20|5120|1|0.0%|0.1%|
[ciarmy](#ciarmy)|348|348|1|0.2%|0.1%|
[blocklist_de_strongips](#blocklist_de_strongips)|194|194|1|0.5%|0.1%|

## blocklist_de_mail

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service Mail, Postfix.

Source is downloaded from [this link](http://lists.blocklist.de/lists/mail.txt).

The last time downloaded was found to be dated: Sat May 30 11:14:04 UTC 2015.

The ipset `blocklist_de_mail` has **14463** entries, **14463** unique IPs.

The following table shows the overlaps of `blocklist_de_mail` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_mail`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_mail`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_mail`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|21611|21611|14461|66.9%|99.9%|
[blocklist_de_apache](#blocklist_de_apache)|12527|12527|11059|88.2%|76.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|2293|0.0%|15.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|1329|0.0%|9.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|1138|0.0%|7.8%|
[blocklist_de_imap](#blocklist_de_imap)|777|777|777|100.0%|5.3%|
[nixspam](#nixspam)|22785|22785|474|2.0%|3.2%|
[stopforumspam_30d](#stopforumspam_30d)|92359|92359|214|0.2%|1.4%|
[stopforumspam_7d](#stopforumspam_7d)|30993|30993|107|0.3%|0.7%|
[alienvault_reputation](#alienvault_reputation)|174737|174737|84|0.0%|0.5%|
[snort_ipfilter](#snort_ipfilter)|5712|5712|82|1.4%|0.5%|
[openbl_90d](#openbl_90d)|9797|9797|63|0.6%|0.4%|
[openbl](#openbl)|9797|9797|63|0.6%|0.4%|
[openbl_60d](#openbl_60d)|7680|7680|58|0.7%|0.4%|
[openbl_30d](#openbl_30d)|3339|3339|52|1.5%|0.3%|
[php_dictionary](#php_dictionary)|433|433|51|11.7%|0.3%|
[stopforumspam_1d](#stopforumspam_1d)|6841|6841|45|0.6%|0.3%|
[xroxy](#xroxy)|1963|1963|42|2.1%|0.2%|
[php_spammers](#php_spammers)|417|417|37|8.8%|0.2%|
[ri_web_proxies](#ri_web_proxies)|4837|4837|31|0.6%|0.2%|
[openbl_7d](#openbl_7d)|949|949|31|3.2%|0.2%|
[et_block](#et_block)|986|18056524|21|0.0%|0.1%|
[spamhaus_drop](#spamhaus_drop)|640|17925376|20|0.0%|0.1%|
[php_commenters](#php_commenters)|281|281|19|6.7%|0.1%|
[php_bad](#php_bad)|281|281|19|6.7%|0.1%|
[blocklist_de_strongips](#blocklist_de_strongips)|194|194|18|9.2%|0.1%|
[et_compromised](#et_compromised)|2367|2367|17|0.7%|0.1%|
[blocklist_de_bots](#blocklist_de_bots)|3420|3420|17|0.4%|0.1%|
[bruteforceblocker](#bruteforceblocker)|2254|2254|14|0.6%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|6|0.0%|0.0%|
[shunlist](#shunlist)|1180|1180|5|0.4%|0.0%|
[proxz](#proxz)|236|236|5|2.1%|0.0%|
[voipbl](#voipbl)|10305|10714|3|0.0%|0.0%|
[openbl_1d](#openbl_1d)|229|229|3|1.3%|0.0%|
[et_tor](#et_tor)|6470|6470|3|0.0%|0.0%|
[dm_tor](#dm_tor)|6479|6479|3|0.0%|0.0%|
[bm_tor](#bm_tor)|6474|6474|3|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|2|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|1842|1842|2|0.1%|0.0%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|1|0.1%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1|0.0%|0.0%|
[dshield](#dshield)|20|5120|1|0.0%|0.0%|
[ciarmy](#ciarmy)|348|348|1|0.2%|0.0%|

## blocklist_de_sip

[Blocklist.de](https://www.blocklist.de/) All IP addresses that tried to login in a SIP, VOIP or Asterisk Server and are included in the IPs list from [infiltrated.net](www.infiltrated.net)

Source is downloaded from [this link](http://lists.blocklist.de/lists/sip.txt).

The last time downloaded was found to be dated: Sat May 30 11:14:06 UTC 2015.

The ipset `blocklist_de_sip` has **85** entries, **85** unique IPs.

The following table shows the overlaps of `blocklist_de_sip` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_sip`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_sip`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_sip`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|21611|21611|66|0.3%|77.6%|
[voipbl](#voipbl)|10305|10714|28|0.2%|32.9%|
[alienvault_reputation](#alienvault_reputation)|174737|174737|18|0.0%|21.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|16|0.0%|18.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|6|0.0%|7.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|5|0.0%|5.8%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|2|0.0%|2.3%|
[spamhaus_drop](#spamhaus_drop)|640|17925376|1|0.0%|1.1%|
[shunlist](#shunlist)|1180|1180|1|0.0%|1.1%|
[et_botcc](#et_botcc)|501|501|1|0.1%|1.1%|
[et_block](#et_block)|986|18056524|1|0.0%|1.1%|
[ciarmy](#ciarmy)|348|348|1|0.2%|1.1%|

## blocklist_de_ssh

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service SSH.

Source is downloaded from [this link](http://lists.blocklist.de/lists/ssh.txt).

The last time downloaded was found to be dated: Sat May 30 11:10:04 UTC 2015.

The ipset `blocklist_de_ssh` has **1834** entries, **1834** unique IPs.

The following table shows the overlaps of `blocklist_de_ssh` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_ssh`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_ssh`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_ssh`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|21611|21611|1834|8.4%|100.0%|
[alienvault_reputation](#alienvault_reputation)|174737|174737|1051|0.6%|57.3%|
[openbl_90d](#openbl_90d)|9797|9797|953|9.7%|51.9%|
[openbl](#openbl)|9797|9797|953|9.7%|51.9%|
[openbl_60d](#openbl_60d)|7680|7680|913|11.8%|49.7%|
[openbl_30d](#openbl_30d)|3339|3339|849|25.4%|46.2%|
[bruteforceblocker](#bruteforceblocker)|2254|2254|796|35.3%|43.4%|
[et_compromised](#et_compromised)|2367|2367|769|32.4%|41.9%|
[openbl_7d](#openbl_7d)|949|949|542|57.1%|29.5%|
[shunlist](#shunlist)|1180|1180|440|37.2%|23.9%|
[openbl_1d](#openbl_1d)|229|229|207|90.3%|11.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|196|0.0%|10.6%|
[et_block](#et_block)|986|18056524|115|0.0%|6.2%|
[spamhaus_drop](#spamhaus_drop)|640|17925376|108|0.0%|5.8%|
[dshield](#dshield)|20|5120|102|1.9%|5.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|93|0.0%|5.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|194|194|48|24.7%|2.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|34|0.0%|1.8%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|9|0.0%|0.4%|
[stopforumspam_30d](#stopforumspam_30d)|92359|92359|5|0.0%|0.2%|
[voipbl](#voipbl)|10305|10714|3|0.0%|0.1%|
[stopforumspam_7d](#stopforumspam_7d)|30993|30993|3|0.0%|0.1%|
[nixspam](#nixspam)|22785|22785|2|0.0%|0.1%|
[xroxy](#xroxy)|1963|1963|1|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|5712|5712|1|0.0%|0.0%|
[proxz](#proxz)|236|236|1|0.4%|0.0%|
[proxyrss](#proxyrss)|1548|1548|1|0.0%|0.0%|
[php_spammers](#php_spammers)|417|417|1|0.2%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.0%|
[ciarmy](#ciarmy)|348|348|1|0.2%|0.0%|

## blocklist_de_strongips

[Blocklist.de](https://www.blocklist.de/) All IPs which are older then 2 month and have more then 5.000 attacks.

Source is downloaded from [this link](http://lists.blocklist.de/lists/strongips.txt).

The last time downloaded was found to be dated: Sat May 30 11:28:08 UTC 2015.

The ipset `blocklist_de_strongips` has **194** entries, **194** unique IPs.

The following table shows the overlaps of `blocklist_de_strongips` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_strongips`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_strongips`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_strongips`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|21611|21611|194|0.8%|100.0%|
[stopforumspam_30d](#stopforumspam_30d)|92359|92359|131|0.1%|67.5%|
[blocklist_de_bots](#blocklist_de_bots)|3420|3420|125|3.6%|64.4%|
[stopforumspam_7d](#stopforumspam_7d)|30993|30993|120|0.3%|61.8%|
[stopforumspam_1d](#stopforumspam_1d)|6841|6841|98|1.4%|50.5%|
[alienvault_reputation](#alienvault_reputation)|174737|174737|58|0.0%|29.8%|
[openbl_90d](#openbl_90d)|9797|9797|49|0.5%|25.2%|
[openbl](#openbl)|9797|9797|49|0.5%|25.2%|
[openbl_60d](#openbl_60d)|7680|7680|48|0.6%|24.7%|
[blocklist_de_ssh](#blocklist_de_ssh)|1834|1834|48|2.6%|24.7%|
[openbl_30d](#openbl_30d)|3339|3339|46|1.3%|23.7%|
[openbl_7d](#openbl_7d)|949|949|45|4.7%|23.1%|
[openbl_1d](#openbl_1d)|229|229|43|18.7%|22.1%|
[shunlist](#shunlist)|1180|1180|42|3.5%|21.6%|
[blocklist_de_apache](#blocklist_de_apache)|12527|12527|35|0.2%|18.0%|
[php_commenters](#php_commenters)|281|281|33|11.7%|17.0%|
[php_bad](#php_bad)|281|281|33|11.7%|17.0%|
[blocklist_de_mail](#blocklist_de_mail)|14463|14463|18|0.1%|9.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|17|0.0%|8.7%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1201|1201|10|0.8%|5.1%|
[xroxy](#xroxy)|1963|1963|6|0.3%|3.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|6|0.0%|3.0%|
[spamhaus_drop](#spamhaus_drop)|640|17925376|6|0.0%|3.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|6|0.0%|3.0%|
[et_block](#et_block)|986|18056524|6|0.0%|3.0%|
[php_spammers](#php_spammers)|417|417|5|1.1%|2.5%|
[ri_web_proxies](#ri_web_proxies)|4837|4837|3|0.0%|1.5%|
[nixspam](#nixspam)|22785|22785|3|0.0%|1.5%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|1.5%|
[proxyrss](#proxyrss)|1548|1548|2|0.1%|1.0%|
[php_harvesters](#php_harvesters)|257|257|2|0.7%|1.0%|
[php_dictionary](#php_dictionary)|433|433|2|0.4%|1.0%|
[snort_ipfilter](#snort_ipfilter)|5712|5712|1|0.0%|0.5%|
[proxz](#proxz)|236|236|1|0.4%|0.5%|
[blocklist_de_imap](#blocklist_de_imap)|777|777|1|0.1%|0.5%|

## bm_tor

[torstatus.blutmagie.de](https://torstatus.blutmagie.de) list of all TOR network servers

Source is downloaded from [this link](https://torstatus.blutmagie.de/ip_list_all.php/Tor_ip_list_ALL.csv).

The last time downloaded was found to be dated: Sat May 30 11:36:16 UTC 2015.

The ipset `bm_tor` has **6474** entries, **6474** unique IPs.

The following table shows the overlaps of `bm_tor` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `bm_tor`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `bm_tor`.
- ` this % ` is the percentage **of this ipset (`bm_tor`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[dm_tor](#dm_tor)|6479|6479|6402|98.8%|98.8%|
[et_tor](#et_tor)|6470|6470|5733|88.6%|88.5%|
[snort_ipfilter](#snort_ipfilter)|5712|5712|1002|17.5%|15.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|608|0.0%|9.3%|
[stopforumspam_30d](#stopforumspam_30d)|92359|92359|586|0.6%|9.0%|
[stopforumspam_7d](#stopforumspam_7d)|30993|30993|466|1.5%|7.1%|
[stopforumspam_1d](#stopforumspam_1d)|6841|6841|328|4.7%|5.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|183|0.0%|2.8%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|174|46.7%|2.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|158|0.0%|2.4%|
[alienvault_reputation](#alienvault_reputation)|174737|174737|48|0.0%|0.7%|
[php_commenters](#php_commenters)|281|281|29|10.3%|0.4%|
[php_bad](#php_bad)|281|281|29|10.3%|0.4%|
[openbl_90d](#openbl_90d)|9797|9797|21|0.2%|0.3%|
[openbl_60d](#openbl_60d)|7680|7680|21|0.2%|0.3%|
[openbl](#openbl)|9797|9797|21|0.2%|0.3%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|21|0.0%|0.3%|
[blocklist_de](#blocklist_de)|21611|21611|17|0.0%|0.2%|
[blocklist_de_apache](#blocklist_de_apache)|12527|12527|16|0.1%|0.2%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1201|1201|13|1.0%|0.2%|
[php_harvesters](#php_harvesters)|257|257|7|2.7%|0.1%|
[php_spammers](#php_spammers)|417|417|6|1.4%|0.0%|
[ri_web_proxies](#ri_web_proxies)|4837|4837|4|0.0%|0.0%|
[php_dictionary](#php_dictionary)|433|433|4|0.9%|0.0%|
[nixspam](#nixspam)|22785|22785|3|0.0%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|0.0%|
[et_block](#et_block)|986|18056524|3|0.0%|0.0%|
[dshield](#dshield)|20|5120|3|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14463|14463|3|0.0%|0.0%|
[xroxy](#xroxy)|1963|1963|2|0.1%|0.0%|
[spamhaus_drop](#spamhaus_drop)|640|17925376|2|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|1842|1842|2|0.1%|0.0%|
[proxyrss](#proxyrss)|1548|1548|2|0.1%|0.0%|
[voipbl](#voipbl)|10305|10714|1|0.0%|0.0%|
[shunlist](#shunlist)|1180|1180|1|0.0%|0.0%|
[proxz](#proxz)|236|236|1|0.4%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3420|3420|1|0.0%|0.0%|

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
[voipbl](#voipbl)|10305|10714|319|2.9%|0.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|5|0.0%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92359|92359|1|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2254|2254|1|0.0%|0.0%|

## bruteforceblocker

[danger.rulez.sk](http://danger.rulez.sk/) IPs detected by [bruteforceblocker](http://danger.rulez.sk/index.php/bruteforceblocker/) (fail2ban alternative for SSH on OpenBSD)

Source is downloaded from [this link](http://danger.rulez.sk/projects/bruteforceblocker/blist.php).

The last time downloaded was found to be dated: Sat May 30 10:10:00 UTC 2015.

The ipset `bruteforceblocker` has **2254** entries, **2254** unique IPs.

The following table shows the overlaps of `bruteforceblocker` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `bruteforceblocker`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `bruteforceblocker`.
- ` this % ` is the percentage **of this ipset (`bruteforceblocker`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[et_compromised](#et_compromised)|2367|2367|2207|93.2%|97.9%|
[alienvault_reputation](#alienvault_reputation)|174737|174737|1469|0.8%|65.1%|
[openbl_90d](#openbl_90d)|9797|9797|1380|14.0%|61.2%|
[openbl](#openbl)|9797|9797|1380|14.0%|61.2%|
[openbl_60d](#openbl_60d)|7680|7680|1366|17.7%|60.6%|
[openbl_30d](#openbl_30d)|3339|3339|1301|38.9%|57.7%|
[blocklist_de](#blocklist_de)|21611|21611|813|3.7%|36.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1834|1834|796|43.4%|35.3%|
[openbl_7d](#openbl_7d)|949|949|504|53.1%|22.3%|
[shunlist](#shunlist)|1180|1180|493|41.7%|21.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|217|0.0%|9.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|130|0.0%|5.7%|
[openbl_1d](#openbl_1d)|229|229|126|55.0%|5.5%|
[et_block](#et_block)|986|18056524|103|0.0%|4.5%|
[spamhaus_drop](#spamhaus_drop)|640|17925376|102|0.0%|4.5%|
[dshield](#dshield)|20|5120|95|1.8%|4.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|65|0.0%|2.8%|
[blocklist_de_mail](#blocklist_de_mail)|14463|14463|14|0.0%|0.6%|
[blocklist_de_imap](#blocklist_de_imap)|777|777|12|1.5%|0.5%|
[stopforumspam_30d](#stopforumspam_30d)|92359|92359|6|0.0%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|5|0.0%|0.2%|
[stopforumspam_7d](#stopforumspam_7d)|30993|30993|3|0.0%|0.1%|
[proxz](#proxz)|236|236|2|0.8%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|12527|12527|2|0.0%|0.0%|
[zeus_badips](#zeus_badips)|229|229|1|0.4%|0.0%|
[zeus](#zeus)|267|267|1|0.3%|0.0%|
[xroxy](#xroxy)|1963|1963|1|0.0%|0.0%|
[voipbl](#voipbl)|10305|10714|1|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6841|6841|1|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|5712|5712|1|0.0%|0.0%|
[proxyrss](#proxyrss)|1548|1548|1|0.0%|0.0%|
[nixspam](#nixspam)|22785|22785|1|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.0%|
[fullbogons](#fullbogons)|3642|670590424|1|0.0%|0.0%|
[bogons](#bogons)|13|592708608|1|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|373|373|1|0.2%|0.0%|

## ciarmy

[CIArmy.com](http://ciarmy.com/) IPs with poor Rogue Packet score that have not yet been identified as malicious by the community

Source is downloaded from [this link](http://cinsscore.com/list/ci-badguys.txt).

The last time downloaded was found to be dated: Sat May 30 10:15:15 UTC 2015.

The ipset `ciarmy` has **348** entries, **348** unique IPs.

The following table shows the overlaps of `ciarmy` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ciarmy`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ciarmy`.
- ` this % ` is the percentage **of this ipset (`ciarmy`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[alienvault_reputation](#alienvault_reputation)|174737|174737|336|0.1%|96.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|56|0.0%|16.0%|
[blocklist_de](#blocklist_de)|21611|21611|43|0.1%|12.3%|
[blocklist_de_apache](#blocklist_de_apache)|12527|12527|39|0.3%|11.2%|
[shunlist](#shunlist)|1180|1180|21|1.7%|6.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|21|0.0%|6.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|11|0.0%|3.1%|
[voipbl](#voipbl)|10305|10714|2|0.0%|0.5%|
[dshield](#dshield)|20|5120|2|0.0%|0.5%|
[stopforumspam_30d](#stopforumspam_30d)|92359|92359|1|0.0%|0.2%|
[openbl_90d](#openbl_90d)|9797|9797|1|0.0%|0.2%|
[openbl_7d](#openbl_7d)|949|949|1|0.1%|0.2%|
[openbl_60d](#openbl_60d)|7680|7680|1|0.0%|0.2%|
[openbl_30d](#openbl_30d)|3339|3339|1|0.0%|0.2%|
[openbl](#openbl)|9797|9797|1|0.0%|0.2%|
[blocklist_de_ssh](#blocklist_de_ssh)|1834|1834|1|0.0%|0.2%|
[blocklist_de_sip](#blocklist_de_sip)|85|85|1|1.1%|0.2%|
[blocklist_de_mail](#blocklist_de_mail)|14463|14463|1|0.0%|0.2%|
[blocklist_de_imap](#blocklist_de_imap)|777|777|1|0.1%|0.2%|
[blocklist_de_ftp](#blocklist_de_ftp)|373|373|1|0.2%|0.2%|

## cleanmx_viruses

[Clean-MX.de](http://support.clean-mx.de/clean-mx/viruses.php) IPs with viruses

Source is downloaded from [this link](http://support.clean-mx.de/clean-mx/xmlviruses.php?sort=id%20desc&response=alive).

The last time downloaded was found to be dated: Sat May 30 05:18:48 UTC 2015.

The ipset `cleanmx_viruses` has **259** entries, **259** unique IPs.

The following table shows the overlaps of `cleanmx_viruses` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `cleanmx_viruses`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `cleanmx_viruses`.
- ` this % ` is the percentage **of this ipset (`cleanmx_viruses`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|38|0.0%|14.6%|
[malc0de](#malc0de)|410|410|28|6.8%|10.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|10|0.0%|3.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|6|0.0%|2.3%|
[alienvault_reputation](#alienvault_reputation)|174737|174737|6|0.0%|2.3%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1201|1201|3|0.2%|1.1%|
[blocklist_de_apache](#blocklist_de_apache)|12527|12527|3|0.0%|1.1%|
[blocklist_de](#blocklist_de)|21611|21611|3|0.0%|1.1%|
[zeus_badips](#zeus_badips)|229|229|1|0.4%|0.3%|
[zeus](#zeus)|267|267|1|0.3%|0.3%|
[snort_ipfilter](#snort_ipfilter)|5712|5712|1|0.0%|0.3%|
[malwaredomainlist](#malwaredomainlist)|1282|1282|1|0.0%|0.3%|
[et_block](#et_block)|986|18056524|1|0.0%|0.3%|

## dm_tor

[dan.me.uk](https://www.dan.me.uk) dynamic list of TOR exit points

Source is downloaded from [this link](https://www.dan.me.uk/torlist/).

The last time downloaded was found to be dated: Sat May 30 11:36:14 UTC 2015.

The ipset `dm_tor` has **6479** entries, **6479** unique IPs.

The following table shows the overlaps of `dm_tor` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `dm_tor`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `dm_tor`.
- ` this % ` is the percentage **of this ipset (`dm_tor`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[bm_tor](#bm_tor)|6474|6474|6402|98.8%|98.8%|
[et_tor](#et_tor)|6470|6470|5719|88.3%|88.2%|
[snort_ipfilter](#snort_ipfilter)|5712|5712|997|17.4%|15.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|612|0.0%|9.4%|
[stopforumspam_30d](#stopforumspam_30d)|92359|92359|588|0.6%|9.0%|
[stopforumspam_7d](#stopforumspam_7d)|30993|30993|468|1.5%|7.2%|
[stopforumspam_1d](#stopforumspam_1d)|6841|6841|330|4.8%|5.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|184|0.0%|2.8%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|174|46.7%|2.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|158|0.0%|2.4%|
[alienvault_reputation](#alienvault_reputation)|174737|174737|48|0.0%|0.7%|
[php_commenters](#php_commenters)|281|281|29|10.3%|0.4%|
[php_bad](#php_bad)|281|281|29|10.3%|0.4%|
[openbl_90d](#openbl_90d)|9797|9797|21|0.2%|0.3%|
[openbl_60d](#openbl_60d)|7680|7680|21|0.2%|0.3%|
[openbl](#openbl)|9797|9797|21|0.2%|0.3%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|21|0.0%|0.3%|
[blocklist_de](#blocklist_de)|21611|21611|17|0.0%|0.2%|
[blocklist_de_apache](#blocklist_de_apache)|12527|12527|16|0.1%|0.2%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1201|1201|13|1.0%|0.2%|
[php_harvesters](#php_harvesters)|257|257|7|2.7%|0.1%|
[php_spammers](#php_spammers)|417|417|6|1.4%|0.0%|
[ri_web_proxies](#ri_web_proxies)|4837|4837|4|0.0%|0.0%|
[php_dictionary](#php_dictionary)|433|433|4|0.9%|0.0%|
[nixspam](#nixspam)|22785|22785|3|0.0%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|0.0%|
[et_block](#et_block)|986|18056524|3|0.0%|0.0%|
[dshield](#dshield)|20|5120|3|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14463|14463|3|0.0%|0.0%|
[xroxy](#xroxy)|1963|1963|2|0.1%|0.0%|
[spamhaus_drop](#spamhaus_drop)|640|17925376|2|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|1842|1842|2|0.1%|0.0%|
[proxyrss](#proxyrss)|1548|1548|2|0.1%|0.0%|
[voipbl](#voipbl)|10305|10714|1|0.0%|0.0%|
[shunlist](#shunlist)|1180|1180|1|0.0%|0.0%|
[proxz](#proxz)|236|236|1|0.4%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3420|3420|1|0.0%|0.0%|

## dshield

[DShield.org](https://dshield.org/) top 20 attacking class C (/24) subnets over the last three days - **excellent list**

Source is downloaded from [this link](http://feeds.dshield.org/block.txt).

The last time downloaded was found to be dated: Sat May 30 10:53:16 UTC 2015.

The ipset `dshield` has **20** entries, **5120** unique IPs.

The following table shows the overlaps of `dshield` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `dshield`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `dshield`.
- ` this % ` is the percentage **of this ipset (`dshield`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[alienvault_reputation](#alienvault_reputation)|174737|174737|2562|1.4%|50.0%|
[et_block](#et_block)|986|18056524|1280|0.0%|25.0%|
[spamhaus_drop](#spamhaus_drop)|640|17925376|512|0.0%|10.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|256|0.0%|5.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|256|0.0%|5.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|256|0.0%|5.0%|
[blocklist_de](#blocklist_de)|21611|21611|106|0.4%|2.0%|
[openbl_90d](#openbl_90d)|9797|9797|105|1.0%|2.0%|
[openbl](#openbl)|9797|9797|105|1.0%|2.0%|
[shunlist](#shunlist)|1180|1180|104|8.8%|2.0%|
[openbl_60d](#openbl_60d)|7680|7680|104|1.3%|2.0%|
[openbl_30d](#openbl_30d)|3339|3339|104|3.1%|2.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1834|1834|102|5.5%|1.9%|
[et_compromised](#et_compromised)|2367|2367|95|4.0%|1.8%|
[bruteforceblocker](#bruteforceblocker)|2254|2254|95|4.2%|1.8%|
[openbl_7d](#openbl_7d)|949|949|73|7.6%|1.4%|
[openbl_1d](#openbl_1d)|229|229|16|6.9%|0.3%|
[et_tor](#et_tor)|6470|6470|3|0.0%|0.0%|
[dm_tor](#dm_tor)|6479|6479|3|0.0%|0.0%|
[bm_tor](#bm_tor)|6474|6474|3|0.0%|0.0%|
[voipbl](#voipbl)|10305|10714|2|0.0%|0.0%|
[ciarmy](#ciarmy)|348|348|2|0.5%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|12527|12527|2|0.0%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|30993|30993|1|0.0%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92359|92359|1|0.0%|0.0%|
[nixspam](#nixspam)|22785|22785|1|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14463|14463|1|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|777|777|1|0.1%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|373|373|1|0.2%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1201|1201|1|0.0%|0.0%|

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
[spamhaus_drop](#spamhaus_drop)|640|17925376|17920256|99.9%|99.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|8402471|2.4%|46.5%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|7211008|78.5%|39.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|2133460|0.2%|11.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|196184|0.1%|1.0%|
[fullbogons](#fullbogons)|3642|670590424|20480|0.0%|0.1%|
[alienvault_reputation](#alienvault_reputation)|174737|174737|6044|3.4%|0.0%|
[dshield](#dshield)|20|5120|1280|25.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1040|0.3%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92359|92359|746|0.8%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|517|0.1%|0.0%|
[openbl_90d](#openbl_90d)|9797|9797|454|4.6%|0.0%|
[openbl](#openbl)|9797|9797|454|4.6%|0.0%|
[snort_ipfilter](#snort_ipfilter)|5712|5712|294|5.1%|0.0%|
[zeus](#zeus)|267|267|260|97.3%|0.0%|
[openbl_60d](#openbl_60d)|7680|7680|241|3.1%|0.0%|
[nixspam](#nixspam)|22785|22785|237|1.0%|0.0%|
[zeus_badips](#zeus_badips)|229|229|228|99.5%|0.0%|
[openbl_30d](#openbl_30d)|3339|3339|209|6.2%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|30993|30993|208|0.6%|0.0%|
[blocklist_de](#blocklist_de)|21611|21611|195|0.9%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1834|1834|115|6.2%|0.0%|
[shunlist](#shunlist)|1180|1180|110|9.3%|0.0%|
[et_compromised](#et_compromised)|2367|2367|103|4.3%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2254|2254|103|4.5%|0.0%|
[openbl_7d](#openbl_7d)|949|949|85|8.9%|0.0%|
[feodo](#feodo)|70|70|67|95.7%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3420|3420|51|1.4%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6841|6841|45|0.6%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1282|1282|28|2.1%|0.0%|
[sslbl](#sslbl)|349|349|27|7.7%|0.0%|
[php_commenters](#php_commenters)|281|281|24|8.5%|0.0%|
[php_bad](#php_bad)|281|281|24|8.5%|0.0%|
[openbl_1d](#openbl_1d)|229|229|21|9.1%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14463|14463|21|0.1%|0.0%|
[voipbl](#voipbl)|10305|10714|17|0.1%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|777|777|15|1.9%|0.0%|
[palevo](#palevo)|13|13|13|100.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|7|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|6|0.4%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|194|194|6|3.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|12527|12527|6|0.0%|0.0%|
[php_dictionary](#php_dictionary)|433|433|4|0.9%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1201|1201|4|0.3%|0.0%|
[malc0de](#malc0de)|410|410|3|0.7%|0.0%|
[et_tor](#et_tor)|6470|6470|3|0.0%|0.0%|
[dm_tor](#dm_tor)|6479|6479|3|0.0%|0.0%|
[bm_tor](#bm_tor)|6474|6474|3|0.0%|0.0%|
[php_spammers](#php_spammers)|417|417|2|0.4%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|2|0.2%|0.0%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.0%|
[et_botcc](#et_botcc)|501|501|1|0.1%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|259|259|1|0.3%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|85|85|1|1.1%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|373|373|1|0.2%|0.0%|

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
[alienvault_reputation](#alienvault_reputation)|174737|174737|3|0.0%|0.5%|
[spamhaus_drop](#spamhaus_drop)|640|17925376|1|0.0%|0.1%|
[malwaredomainlist](#malwaredomainlist)|1282|1282|1|0.0%|0.1%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.1%|
[et_block](#et_block)|986|18056524|1|0.0%|0.1%|
[blocklist_de_sip](#blocklist_de_sip)|85|85|1|1.1%|0.1%|

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
[bruteforceblocker](#bruteforceblocker)|2254|2254|2207|97.9%|93.2%|
[alienvault_reputation](#alienvault_reputation)|174737|174737|1533|0.8%|64.7%|
[openbl_90d](#openbl_90d)|9797|9797|1434|14.6%|60.5%|
[openbl](#openbl)|9797|9797|1434|14.6%|60.5%|
[openbl_60d](#openbl_60d)|7680|7680|1419|18.4%|59.9%|
[openbl_30d](#openbl_30d)|3339|3339|1337|40.0%|56.4%|
[blocklist_de](#blocklist_de)|21611|21611|789|3.6%|33.3%|
[blocklist_de_ssh](#blocklist_de_ssh)|1834|1834|769|41.9%|32.4%|
[openbl_7d](#openbl_7d)|949|949|504|53.1%|21.2%|
[shunlist](#shunlist)|1180|1180|495|41.9%|20.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|227|0.0%|9.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|140|0.0%|5.9%|
[openbl_1d](#openbl_1d)|229|229|123|53.7%|5.1%|
[et_block](#et_block)|986|18056524|103|0.0%|4.3%|
[spamhaus_drop](#spamhaus_drop)|640|17925376|102|0.0%|4.3%|
[dshield](#dshield)|20|5120|95|1.8%|4.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|70|0.0%|2.9%|
[blocklist_de_mail](#blocklist_de_mail)|14463|14463|17|0.1%|0.7%|
[blocklist_de_imap](#blocklist_de_imap)|777|777|15|1.9%|0.6%|
[stopforumspam_30d](#stopforumspam_30d)|92359|92359|6|0.0%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|5|0.0%|0.2%|
[stopforumspam_7d](#stopforumspam_7d)|30993|30993|3|0.0%|0.1%|
[proxz](#proxz)|236|236|2|0.8%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|12527|12527|2|0.0%|0.0%|
[zeus_badips](#zeus_badips)|229|229|1|0.4%|0.0%|
[zeus](#zeus)|267|267|1|0.3%|0.0%|
[xroxy](#xroxy)|1963|1963|1|0.0%|0.0%|
[voipbl](#voipbl)|10305|10714|1|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6841|6841|1|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|5712|5712|1|0.0%|0.0%|
[proxyrss](#proxyrss)|1548|1548|1|0.0%|0.0%|
[nixspam](#nixspam)|22785|22785|1|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|373|373|1|0.2%|0.0%|

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
[bm_tor](#bm_tor)|6474|6474|5733|88.5%|88.6%|
[dm_tor](#dm_tor)|6479|6479|5719|88.2%|88.3%|
[snort_ipfilter](#snort_ipfilter)|5712|5712|1072|18.7%|16.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|619|0.0%|9.5%|
[stopforumspam_30d](#stopforumspam_30d)|92359|92359|614|0.6%|9.4%|
[stopforumspam_7d](#stopforumspam_7d)|30993|30993|485|1.5%|7.4%|
[stopforumspam_1d](#stopforumspam_1d)|6841|6841|330|4.8%|5.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|184|0.0%|2.8%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|179|48.1%|2.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|163|0.0%|2.5%|
[alienvault_reputation](#alienvault_reputation)|174737|174737|48|0.0%|0.7%|
[php_commenters](#php_commenters)|281|281|29|10.3%|0.4%|
[php_bad](#php_bad)|281|281|29|10.3%|0.4%|
[openbl_90d](#openbl_90d)|9797|9797|21|0.2%|0.3%|
[openbl_60d](#openbl_60d)|7680|7680|21|0.2%|0.3%|
[openbl](#openbl)|9797|9797|21|0.2%|0.3%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|21|0.0%|0.3%|
[blocklist_de_apache](#blocklist_de_apache)|12527|12527|16|0.1%|0.2%|
[blocklist_de](#blocklist_de)|21611|21611|16|0.0%|0.2%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1201|1201|13|1.0%|0.2%|
[php_harvesters](#php_harvesters)|257|257|7|2.7%|0.1%|
[php_spammers](#php_spammers)|417|417|6|1.4%|0.0%|
[ri_web_proxies](#ri_web_proxies)|4837|4837|4|0.0%|0.0%|
[php_dictionary](#php_dictionary)|433|433|4|0.9%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|0.0%|
[et_block](#et_block)|986|18056524|3|0.0%|0.0%|
[dshield](#dshield)|20|5120|3|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14463|14463|3|0.0%|0.0%|
[xroxy](#xroxy)|1963|1963|2|0.1%|0.0%|
[spamhaus_drop](#spamhaus_drop)|640|17925376|2|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|1842|1842|2|0.1%|0.0%|
[proxyrss](#proxyrss)|1548|1548|2|0.1%|0.0%|
[nixspam](#nixspam)|22785|22785|2|0.0%|0.0%|
[voipbl](#voipbl)|10305|10714|1|0.0%|0.0%|
[shunlist](#shunlist)|1180|1180|1|0.0%|0.0%|
[proxz](#proxz)|236|236|1|0.4%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|

## feodo

[Abuse.ch Feodo tracker](https://feodotracker.abuse.ch) trojan includes IPs which are being used by Feodo (also known as Cridex or Bugat) which commits ebanking fraud - **excellent list**

Source is downloaded from [this link](https://feodotracker.abuse.ch/blocklist/?download=ipblocklist).

The last time downloaded was found to be dated: Sat May 30 11:36:28 UTC 2015.

The ipset `feodo` has **70** entries, **70** unique IPs.

The following table shows the overlaps of `feodo` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `feodo`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `feodo`.
- ` this % ` is the percentage **of this ipset (`feodo`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[et_block](#et_block)|986|18056524|67|0.0%|95.7%|
[snort_ipfilter](#snort_ipfilter)|5712|5712|53|0.9%|75.7%|
[sslbl](#sslbl)|349|349|26|7.4%|37.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|5|0.0%|7.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|3|0.0%|4.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|3|0.0%|4.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|1.4%|
[alienvault_reputation](#alienvault_reputation)|174737|174737|1|0.0%|1.4%|

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
[spamhaus_drop](#spamhaus_drop)|640|17925376|20480|0.1%|0.0%|
[et_block](#et_block)|986|18056524|20480|0.1%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|890|0.2%|0.0%|
[voipbl](#voipbl)|10305|10714|319|2.9%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|33|2.2%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|14|0.0%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1282|1282|9|0.7%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92359|92359|2|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2254|2254|1|0.0%|0.0%|

## ib_bluetack_badpeers

[iBlocklist.com](https://www.iblocklist.com/) free version of [BlueTack.co.uk](http://www.bluetack.co.uk/) IPs that have been reported for bad deeds in p2p

Source is downloaded from [this link](http://list.iblocklist.com/?list=cwworuawihqvocglcoss&fileformat=p2p&archiveformat=gz).

The last time downloaded was found to be dated: Sat May 30 03:40:49 UTC 2015.

The ipset `ib_bluetack_badpeers` has **48134** entries, **48134** unique IPs.

The following table shows the overlaps of `ib_bluetack_badpeers` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ib_bluetack_badpeers`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ib_bluetack_badpeers`.
- ` this % ` is the percentage **of this ipset (`ib_bluetack_badpeers`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|1172|0.0%|2.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|406|0.0%|0.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|230|0.0%|0.4%|
[stopforumspam_30d](#stopforumspam_30d)|92359|92359|15|0.0%|0.0%|
[fullbogons](#fullbogons)|3642|670590424|14|0.0%|0.0%|
[alienvault_reputation](#alienvault_reputation)|174737|174737|14|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|11|1.6%|0.0%|
[nixspam](#nixspam)|22785|22785|9|0.0%|0.0%|
[et_block](#et_block)|986|18056524|7|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|640|17925376|6|0.0%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|30993|30993|5|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|4|0.0%|0.0%|
[xroxy](#xroxy)|1963|1963|3|0.1%|0.0%|
[voipbl](#voipbl)|10305|10714|2|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|2|0.7%|0.0%|
[php_dictionary](#php_dictionary)|433|433|2|0.4%|0.0%|
[blocklist_de](#blocklist_de)|21611|21611|2|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6841|6841|1|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|5712|5712|1|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|4837|4837|1|0.0%|0.0%|
[php_spammers](#php_spammers)|417|417|1|0.2%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14463|14463|1|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3420|3420|1|0.0%|0.0%|

## ib_bluetack_hijacked

[iBlocklist.com](https://www.iblocklist.com/) free version of [BlueTack.co.uk](http://www.bluetack.co.uk/) hijacked IP-Blocks Hijacked IP space are IP blocks that are being used without permission

Source is downloaded from [this link](http://list.iblocklist.com/?list=usrcshglbiilevmyfhse&fileformat=p2p&archiveformat=gz).

The last time downloaded was found to be dated: Sat May 30 04:10:07 UTC 2015.

The ipset `ib_bluetack_hijacked` has **535** entries, **9177856** unique IPs.

The following table shows the overlaps of `ib_bluetack_hijacked` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ib_bluetack_hijacked`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ib_bluetack_hijacked`.
- ` this % ` is the percentage **of this ipset (`ib_bluetack_hijacked`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[et_block](#et_block)|986|18056524|7211008|39.9%|78.5%|
[spamhaus_drop](#spamhaus_drop)|640|17925376|7079936|39.4%|77.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|2526625|0.7%|27.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|904796|0.1%|9.8%|
[fullbogons](#fullbogons)|3642|670590424|565248|0.0%|6.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|145472|0.1%|1.5%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1036|0.3%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92359|92359|748|0.8%|0.0%|
[alienvault_reputation](#alienvault_reputation)|174737|174737|519|0.2%|0.0%|
[nixspam](#nixspam)|22785|22785|238|1.0%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|30993|30993|196|0.6%|0.0%|
[blocklist_de](#blocklist_de)|21611|21611|66|0.3%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3420|3420|50|1.4%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6841|6841|27|0.3%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1282|1282|27|2.1%|0.0%|
[openbl_90d](#openbl_90d)|9797|9797|20|0.2%|0.0%|
[openbl](#openbl)|9797|9797|20|0.2%|0.0%|
[openbl_60d](#openbl_60d)|7680|7680|19|0.2%|0.0%|
[openbl_30d](#openbl_30d)|3339|3339|14|0.4%|0.0%|
[snort_ipfilter](#snort_ipfilter)|5712|5712|11|0.1%|0.0%|
[openbl_7d](#openbl_7d)|949|949|11|1.1%|0.0%|
[zeus_badips](#zeus_badips)|229|229|10|4.3%|0.0%|
[zeus](#zeus)|267|267|10|3.7%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1834|1834|9|0.4%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|7|0.4%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14463|14463|6|0.0%|0.0%|
[et_compromised](#et_compromised)|2367|2367|5|0.2%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2254|2254|5|0.2%|0.0%|
[shunlist](#shunlist)|1180|1180|4|0.3%|0.0%|
[openbl_1d](#openbl_1d)|229|229|4|1.7%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|777|777|4|0.5%|0.0%|
[et_tor](#et_tor)|6470|6470|3|0.0%|0.0%|
[dm_tor](#dm_tor)|6479|6479|3|0.0%|0.0%|
[bm_tor](#bm_tor)|6474|6474|3|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|194|194|3|1.5%|0.0%|
[php_spammers](#php_spammers)|417|417|2|0.4%|0.0%|
[php_dictionary](#php_dictionary)|433|433|2|0.4%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|2|0.2%|0.0%|
[voipbl](#voipbl)|10305|10714|1|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.0%|
[php_commenters](#php_commenters)|281|281|1|0.3%|0.0%|
[php_bad](#php_bad)|281|281|1|0.3%|0.0%|
[et_botcc](#et_botcc)|501|501|1|0.1%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1201|1201|1|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|12527|12527|1|0.0%|0.0%|

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
[et_block](#et_block)|986|18056524|2133460|11.8%|0.2%|
[spamhaus_drop](#spamhaus_drop)|640|17925376|2133002|11.8%|0.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|1354348|0.9%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|904796|9.8%|0.1%|
[fullbogons](#fullbogons)|3642|670590424|234359|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|33155|7.8%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|13248|3.9%|0.0%|
[alienvault_reputation](#alienvault_reputation)|174737|174737|4710|2.6%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92359|92359|1522|1.6%|0.0%|
[blocklist_de](#blocklist_de)|21611|21611|1469|6.7%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14463|14463|1329|9.1%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|12527|12527|1312|10.4%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|30993|30993|563|1.8%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|406|0.8%|0.0%|
[voipbl](#voipbl)|10305|10714|295|2.7%|0.0%|
[nixspam](#nixspam)|22785|22785|295|1.2%|0.0%|
[dshield](#dshield)|20|5120|256|5.0%|0.0%|
[openbl_90d](#openbl_90d)|9797|9797|216|2.2%|0.0%|
[openbl](#openbl)|9797|9797|216|2.2%|0.0%|
[openbl_60d](#openbl_60d)|7680|7680|177|2.3%|0.0%|
[et_tor](#et_tor)|6470|6470|163|2.5%|0.0%|
[dm_tor](#dm_tor)|6479|6479|158|2.4%|0.0%|
[bm_tor](#bm_tor)|6474|6474|158|2.4%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6841|6841|142|2.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|4837|4837|109|2.2%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|97|6.6%|0.0%|
[openbl_30d](#openbl_30d)|3339|3339|71|2.1%|0.0%|
[et_compromised](#et_compromised)|2367|2367|70|2.9%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1282|1282|66|5.1%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2254|2254|65|2.8%|0.0%|
[snort_ipfilter](#snort_ipfilter)|5712|5712|64|1.1%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|1842|1842|64|3.4%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|58|8.6%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3420|3420|57|1.6%|0.0%|
[xroxy](#xroxy)|1963|1963|54|2.7%|0.0%|
[et_botcc](#et_botcc)|501|501|40|7.9%|0.0%|
[proxyrss](#proxyrss)|1548|1548|36|2.3%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1834|1834|34|1.8%|0.0%|
[shunlist](#shunlist)|1180|1180|24|2.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1201|1201|23|1.9%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|17|4.5%|0.0%|
[openbl_7d](#openbl_7d)|949|949|16|1.6%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|777|777|16|2.0%|0.0%|
[proxz](#proxz)|236|236|13|5.5%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|373|373|13|3.4%|0.0%|
[malc0de](#malc0de)|410|410|12|2.9%|0.0%|
[ciarmy](#ciarmy)|348|348|11|3.1%|0.0%|
[zeus](#zeus)|267|267|9|3.3%|0.0%|
[php_dictionary](#php_dictionary)|433|433|9|2.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|7|2.7%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|259|259|6|2.3%|0.0%|
[php_spammers](#php_spammers)|417|417|5|1.1%|0.0%|
[php_commenters](#php_commenters)|281|281|5|1.7%|0.0%|
[php_bad](#php_bad)|281|281|5|1.7%|0.0%|
[bogons](#bogons)|13|592708608|5|0.0%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|85|85|5|5.8%|0.0%|
[zeus_badips](#zeus_badips)|229|229|4|1.7%|0.0%|
[openbl_1d](#openbl_1d)|229|229|4|1.7%|0.0%|
[sslbl](#sslbl)|349|349|3|0.8%|0.0%|
[feodo](#feodo)|70|70|3|4.2%|0.0%|

## ib_bluetack_level2

[iBlocklist.com](https://www.iblocklist.com/) free version of BlueTack.co.uk Level 2 (for use in p2p). General corporate ranges. Ranges used by labs or researchers. Proxies.

Source is downloaded from [this link](http://list.iblocklist.com/?list=gyisgnzbhppbvsphucsw&fileformat=p2p&archiveformat=gz).

The last time downloaded was found to be dated: Sat May 30 04:11:22 UTC 2015.

The ipset `ib_bluetack_level2` has **72774** entries, **348707599** unique IPs.

The following table shows the overlaps of `ib_bluetack_level2` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ib_bluetack_level2`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ib_bluetack_level2`.
- ` this % ` is the percentage **of this ipset (`ib_bluetack_level2`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|16300309|2.1%|4.6%|
[et_block](#et_block)|986|18056524|8402471|46.5%|2.4%|
[spamhaus_drop](#spamhaus_drop)|640|17925376|8401434|46.8%|2.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|2830140|2.0%|0.8%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2526625|27.5%|0.7%|
[fullbogons](#fullbogons)|3642|670590424|248319|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|33368|7.9%|0.0%|
[alienvault_reputation](#alienvault_reputation)|174737|174737|8388|4.8%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|7733|2.2%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92359|92359|2449|2.6%|0.0%|
[blocklist_de](#blocklist_de)|21611|21611|1440|6.6%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14463|14463|1138|7.8%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|12527|12527|1068|8.5%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|30993|30993|919|2.9%|0.0%|
[nixspam](#nixspam)|22785|22785|567|2.4%|0.0%|
[openbl_90d](#openbl_90d)|9797|9797|501|5.1%|0.0%|
[openbl](#openbl)|9797|9797|501|5.1%|0.0%|
[voipbl](#voipbl)|10305|10714|429|4.0%|0.0%|
[openbl_60d](#openbl_60d)|7680|7680|358|4.6%|0.0%|
[dshield](#dshield)|20|5120|256|5.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6841|6841|238|3.4%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|230|0.4%|0.0%|
[et_tor](#et_tor)|6470|6470|184|2.8%|0.0%|
[dm_tor](#dm_tor)|6479|6479|184|2.8%|0.0%|
[bm_tor](#bm_tor)|6474|6474|183|2.8%|0.0%|
[openbl_30d](#openbl_30d)|3339|3339|180|5.3%|0.0%|
[ri_web_proxies](#ri_web_proxies)|4837|4837|165|3.4%|0.0%|
[et_compromised](#et_compromised)|2367|2367|140|5.9%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3420|3420|133|3.8%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2254|2254|130|5.7%|0.0%|
[xroxy](#xroxy)|1963|1963|93|4.7%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1834|1834|93|5.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|5712|5712|90|1.5%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|1842|1842|76|4.1%|0.0%|
[shunlist](#shunlist)|1180|1180|72|6.1%|0.0%|
[proxyrss](#proxyrss)|1548|1548|63|4.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|45|3.0%|0.0%|
[openbl_7d](#openbl_7d)|949|949|41|4.3%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|777|777|40|5.1%|0.0%|
[php_spammers](#php_spammers)|417|417|31|7.4%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1201|1201|31|2.5%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|28|4.1%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|373|373|28|7.5%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1282|1282|26|2.0%|0.0%|
[malc0de](#malc0de)|410|410|26|6.3%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|21|5.6%|0.0%|
[et_botcc](#et_botcc)|501|501|21|4.1%|0.0%|
[ciarmy](#ciarmy)|348|348|21|6.0%|0.0%|
[openbl_1d](#openbl_1d)|229|229|11|4.8%|0.0%|
[php_dictionary](#php_dictionary)|433|433|10|2.3%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|259|259|10|3.8%|0.0%|
[zeus](#zeus)|267|267|9|3.3%|0.0%|
[proxz](#proxz)|236|236|9|3.8%|0.0%|
[php_commenters](#php_commenters)|281|281|9|3.2%|0.0%|
[php_bad](#php_bad)|281|281|9|3.2%|0.0%|
[zeus_badips](#zeus_badips)|229|229|8|3.4%|0.0%|
[php_harvesters](#php_harvesters)|257|257|7|2.7%|0.0%|
[sslbl](#sslbl)|349|349|6|1.7%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|194|194|6|3.0%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|85|85|6|7.0%|0.0%|
[feodo](#feodo)|70|70|3|4.2%|0.0%|
[palevo](#palevo)|13|13|2|15.3%|0.0%|

## ib_bluetack_level3

[iBlocklist.com](https://www.iblocklist.com/) free version of BlueTack.co.uk Level 3 (for use in p2p). Many portal-type websites. ISP ranges that may be dodgy for some reason. Ranges that belong to an individual, but which have not been determined to be used by a particular company. Ranges for things that are unusual in some way. The L3 list is aka the paranoid list.

Source is downloaded from [this link](http://list.iblocklist.com/?list=uwnukjqktoggdknzrhgh&fileformat=p2p&archiveformat=gz).

The last time downloaded was found to be dated: Sat May 30 04:11:05 UTC 2015.

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
[spamhaus_edrop](#spamhaus_edrop)|55|421120|270785|64.3%|0.1%|
[et_block](#et_block)|986|18056524|196184|1.0%|0.1%|
[spamhaus_drop](#spamhaus_drop)|640|17925376|195904|1.0%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|145472|1.5%|0.1%|
[alienvault_reputation](#alienvault_reputation)|174737|174737|14896|8.5%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|9231|2.7%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92359|92359|5991|6.4%|0.0%|
[blocklist_de](#blocklist_de)|21611|21611|2809|12.9%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14463|14463|2293|15.8%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|12527|12527|2191|17.4%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|30993|30993|2081|6.7%|0.0%|
[voipbl](#voipbl)|10305|10714|1586|14.8%|0.0%|
[nixspam](#nixspam)|22785|22785|1520|6.6%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1172|2.4%|0.0%|
[openbl_90d](#openbl_90d)|9797|9797|944|9.6%|0.0%|
[openbl](#openbl)|9797|9797|944|9.6%|0.0%|
[openbl_60d](#openbl_60d)|7680|7680|722|9.4%|0.0%|
[et_tor](#et_tor)|6470|6470|619|9.5%|0.0%|
[dm_tor](#dm_tor)|6479|6479|612|9.4%|0.0%|
[bm_tor](#bm_tor)|6474|6474|608|9.3%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6841|6841|443|6.4%|0.0%|
[openbl_30d](#openbl_30d)|3339|3339|289|8.6%|0.0%|
[dshield](#dshield)|20|5120|256|5.0%|0.0%|
[et_compromised](#et_compromised)|2367|2367|227|9.5%|0.0%|
[snort_ipfilter](#snort_ipfilter)|5712|5712|218|3.8%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2254|2254|217|9.6%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1834|1834|196|10.6%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3420|3420|168|4.9%|0.0%|
[ri_web_proxies](#ri_web_proxies)|4837|4837|146|3.0%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1282|1282|146|11.3%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|125|33.6%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|110|7.5%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1201|1201|98|8.1%|0.0%|
[openbl_7d](#openbl_7d)|949|949|94|9.9%|0.0%|
[shunlist](#shunlist)|1180|1180|89|7.5%|0.0%|
[xroxy](#xroxy)|1963|1963|79|4.0%|0.0%|
[malc0de](#malc0de)|410|410|76|18.5%|0.0%|
[et_botcc](#et_botcc)|501|501|74|14.7%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|777|777|68|8.7%|0.0%|
[ciarmy](#ciarmy)|348|348|56|16.0%|0.0%|
[proxyrss](#proxyrss)|1548|1548|53|3.4%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|51|7.5%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|1842|1842|43|2.3%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|259|259|38|14.6%|0.0%|
[proxz](#proxz)|236|236|31|13.1%|0.0%|
[php_spammers](#php_spammers)|417|417|26|6.2%|0.0%|
[php_dictionary](#php_dictionary)|433|433|24|5.5%|0.0%|
[sslbl](#sslbl)|349|349|23|6.5%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|373|373|20|5.3%|0.0%|
[zeus](#zeus)|267|267|19|7.1%|0.0%|
[openbl_1d](#openbl_1d)|229|229|18|7.8%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|194|194|17|8.7%|0.0%|
[php_bad](#php_bad)|281|281|16|5.6%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|85|85|16|18.8%|0.0%|
[php_harvesters](#php_harvesters)|257|257|15|5.8%|0.0%|
[php_commenters](#php_commenters)|281|281|15|5.3%|0.0%|
[zeus_badips](#zeus_badips)|229|229|14|6.1%|0.0%|
[feodo](#feodo)|70|70|5|7.1%|0.0%|
[palevo](#palevo)|13|13|1|7.6%|0.0%|

## ib_bluetack_proxies

[iBlocklist.com](https://www.iblocklist.com/) free version of [BlueTack.co.uk](http://www.bluetack.co.uk/) Open Proxies IPs list (without TOR)

Source is downloaded from [this link](http://list.iblocklist.com/?list=xoebmbyexwuiogmbyprb&fileformat=p2p&archiveformat=gz).

The last time downloaded was found to be dated: Sat May 30 04:10:23 UTC 2015.

The ipset `ib_bluetack_proxies` has **673** entries, **673** unique IPs.

The following table shows the overlaps of `ib_bluetack_proxies` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ib_bluetack_proxies`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ib_bluetack_proxies`.
- ` this % ` is the percentage **of this ipset (`ib_bluetack_proxies`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|58|0.0%|8.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|51|0.0%|7.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|28|0.0%|4.1%|
[stopforumspam_30d](#stopforumspam_30d)|92359|92359|22|0.0%|3.2%|
[xroxy](#xroxy)|1963|1963|13|0.6%|1.9%|
[proxyrss](#proxyrss)|1548|1548|13|0.8%|1.9%|
[stopforumspam_7d](#stopforumspam_7d)|30993|30993|11|0.0%|1.6%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|11|0.0%|1.6%|
[ri_web_proxies](#ri_web_proxies)|4837|4837|10|0.2%|1.4%|
[ri_connect_proxies](#ri_connect_proxies)|1842|1842|6|0.3%|0.8%|
[blocklist_de](#blocklist_de)|21611|21611|5|0.0%|0.7%|
[blocklist_de_bots](#blocklist_de_bots)|3420|3420|4|0.1%|0.5%|
[stopforumspam_1d](#stopforumspam_1d)|6841|6841|3|0.0%|0.4%|
[spamhaus_drop](#spamhaus_drop)|640|17925376|2|0.0%|0.2%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2|0.0%|0.2%|
[et_block](#et_block)|986|18056524|2|0.0%|0.2%|
[snort_ipfilter](#snort_ipfilter)|5712|5712|1|0.0%|0.1%|
[php_dictionary](#php_dictionary)|433|433|1|0.2%|0.1%|
[nixspam](#nixspam)|22785|22785|1|0.0%|0.1%|
[blocklist_de_mail](#blocklist_de_mail)|14463|14463|1|0.0%|0.1%|
[alienvault_reputation](#alienvault_reputation)|174737|174737|1|0.0%|0.1%|

## ib_bluetack_spyware

[iBlocklist.com](https://www.iblocklist.com/) free version of [BlueTack.co.uk](http://www.bluetack.co.uk/) known malicious SPYWARE and ADWARE IP Address ranges

Source is downloaded from [this link](http://list.iblocklist.com/?list=llvtlsjyoyiczbkjsxpf&fileformat=p2p&archiveformat=gz).

The last time downloaded was found to be dated: Sat May 30 03:40:09 UTC 2015.

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
[spamhaus_drop](#spamhaus_drop)|640|17925376|1037|0.0%|0.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1036|0.0%|0.3%|
[fullbogons](#fullbogons)|3642|670590424|890|0.0%|0.2%|
[alienvault_reputation](#alienvault_reputation)|174737|174737|289|0.1%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92359|92359|42|0.0%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1282|1282|25|1.9%|0.0%|
[et_tor](#et_tor)|6470|6470|21|0.3%|0.0%|
[dm_tor](#dm_tor)|6479|6479|21|0.3%|0.0%|
[bm_tor](#bm_tor)|6474|6474|21|0.3%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|30993|30993|19|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|19|1.3%|0.0%|
[snort_ipfilter](#snort_ipfilter)|5712|5712|15|0.2%|0.0%|
[nixspam](#nixspam)|22785|22785|11|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6841|6841|10|0.1%|0.0%|
[openbl_90d](#openbl_90d)|9797|9797|6|0.0%|0.0%|
[openbl](#openbl)|9797|9797|6|0.0%|0.0%|
[openbl_60d](#openbl_60d)|7680|7680|5|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|5|1.3%|0.0%|
[voipbl](#voipbl)|10305|10714|4|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|4837|4837|4|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|4|0.0%|0.0%|
[openbl_30d](#openbl_30d)|3339|3339|3|0.0%|0.0%|
[malc0de](#malc0de)|410|410|3|0.7%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|85|85|2|2.3%|0.0%|
[blocklist_de](#blocklist_de)|21611|21611|2|0.0%|0.0%|
[zeus_badips](#zeus_badips)|229|229|1|0.4%|0.0%|
[zeus](#zeus)|267|267|1|0.3%|0.0%|
[xroxy](#xroxy)|1963|1963|1|0.0%|0.0%|
[sslbl](#sslbl)|349|349|1|0.2%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|1|0.0%|0.0%|
[shunlist](#shunlist)|1180|1180|1|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.0%|
[php_dictionary](#php_dictionary)|433|433|1|0.2%|0.0%|
[palevo](#palevo)|13|13|1|7.6%|0.0%|
[openbl_7d](#openbl_7d)|949|949|1|0.1%|0.0%|
[feodo](#feodo)|70|70|1|1.4%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2254|2254|1|0.0%|0.0%|
[bogons](#bogons)|13|592708608|1|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1834|1834|1|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14463|14463|1|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|12527|12527|1|0.0%|0.0%|

## ib_bluetack_webexploit

[iBlocklist.com](https://www.iblocklist.com/) free version of [BlueTack.co.uk](http://www.bluetack.co.uk/) web server hack and exploit attempts

Source is downloaded from [this link](http://list.iblocklist.com/?list=ghlzqtqxnzctvvajwwag&fileformat=p2p&archiveformat=gz).

The last time downloaded was found to be dated: Sat May 30 03:40:10 UTC 2015.

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
[alienvault_reputation](#alienvault_reputation)|174737|174737|8|0.0%|0.5%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|7|0.0%|0.4%|
[spamhaus_drop](#spamhaus_drop)|640|17925376|6|0.0%|0.4%|
[et_block](#et_block)|986|18056524|6|0.0%|0.4%|
[malwaredomainlist](#malwaredomainlist)|1282|1282|3|0.2%|0.2%|
[stopforumspam_7d](#stopforumspam_7d)|30993|30993|2|0.0%|0.1%|
[stopforumspam_30d](#stopforumspam_30d)|92359|92359|2|0.0%|0.1%|
[snort_ipfilter](#snort_ipfilter)|5712|5712|2|0.0%|0.1%|
[openbl_90d](#openbl_90d)|9797|9797|2|0.0%|0.1%|
[openbl_60d](#openbl_60d)|7680|7680|2|0.0%|0.1%|
[openbl_30d](#openbl_30d)|3339|3339|2|0.0%|0.1%|
[openbl](#openbl)|9797|9797|2|0.0%|0.1%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|2|0.2%|0.1%|
[et_compromised](#et_compromised)|2367|2367|2|0.0%|0.1%|
[stopforumspam_1d](#stopforumspam_1d)|6841|6841|1|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|4837|4837|1|0.0%|0.0%|
[openbl_7d](#openbl_7d)|949|949|1|0.1%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1|0.0%|0.0%|
[et_tor](#et_tor)|6470|6470|1|0.0%|0.0%|
[et_botcc](#et_botcc)|501|501|1|0.1%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2254|2254|1|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1834|1834|1|0.0%|0.0%|
[blocklist_de](#blocklist_de)|21611|21611|1|0.0%|0.0%|

## malc0de

[Malc0de.com](http://malc0de.com) malicious IPs of the last 30 days

Source is downloaded from [this link](http://malc0de.com/bl/IP_Blacklist.txt).

The last time downloaded was found to be dated: Fri May 29 13:17:02 UTC 2015.

The ipset `malc0de` has **410** entries, **410** unique IPs.

The following table shows the overlaps of `malc0de` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `malc0de`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `malc0de`.
- ` this % ` is the percentage **of this ipset (`malc0de`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|76|0.0%|18.5%|
[cleanmx_viruses](#cleanmx_viruses)|259|259|28|10.8%|6.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|26|0.0%|6.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|12|0.0%|2.9%|
[alienvault_reputation](#alienvault_reputation)|174737|174737|9|0.0%|2.1%|
[malwaredomainlist](#malwaredomainlist)|1282|1282|4|0.3%|0.9%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|3|0.0%|0.7%|
[et_block](#et_block)|986|18056524|3|0.0%|0.7%|
[spamhaus_drop](#spamhaus_drop)|640|17925376|2|0.0%|0.4%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|1|0.0%|0.2%|
[snort_ipfilter](#snort_ipfilter)|5712|5712|1|0.0%|0.2%|

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
[spamhaus_drop](#spamhaus_drop)|640|17925376|29|0.0%|2.2%|
[et_block](#et_block)|986|18056524|28|0.0%|2.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|27|0.0%|2.1%|
[snort_ipfilter](#snort_ipfilter)|5712|5712|26|0.4%|2.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|26|0.0%|2.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|25|0.0%|1.9%|
[fullbogons](#fullbogons)|3642|670590424|9|0.0%|0.7%|
[alienvault_reputation](#alienvault_reputation)|174737|174737|7|0.0%|0.5%|
[malc0de](#malc0de)|410|410|4|0.9%|0.3%|
[stopforumspam_30d](#stopforumspam_30d)|92359|92359|3|0.0%|0.2%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|3|0.2%|0.2%|
[stopforumspam_7d](#stopforumspam_7d)|30993|30993|2|0.0%|0.1%|
[nixspam](#nixspam)|22785|22785|2|0.0%|0.1%|
[stopforumspam_1d](#stopforumspam_1d)|6841|6841|1|0.0%|0.0%|
[et_botcc](#et_botcc)|501|501|1|0.1%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|259|259|1|0.3%|0.0%|

## maxmind_proxy_fraud

[MaxMind.com](https://www.maxmind.com/en/anonymous-proxy-fraudulent-ip-address-list) list of anonymous proxy fraudelent IP addresses.

Source is downloaded from [this link](https://www.maxmind.com/en/anonymous-proxy-fraudulent-ip-address-list).

The last time downloaded was found to be dated: Sat May 30 08:54:09 UTC 2015.

The ipset `maxmind_proxy_fraud` has **372** entries, **372** unique IPs.

The following table shows the overlaps of `maxmind_proxy_fraud` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `maxmind_proxy_fraud`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `maxmind_proxy_fraud`.
- ` this % ` is the percentage **of this ipset (`maxmind_proxy_fraud`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_30d](#stopforumspam_30d)|92359|92359|237|0.2%|63.7%|
[stopforumspam_7d](#stopforumspam_7d)|30993|30993|200|0.6%|53.7%|
[snort_ipfilter](#snort_ipfilter)|5712|5712|184|3.2%|49.4%|
[et_tor](#et_tor)|6470|6470|179|2.7%|48.1%|
[dm_tor](#dm_tor)|6479|6479|174|2.6%|46.7%|
[bm_tor](#bm_tor)|6474|6474|174|2.6%|46.7%|
[stopforumspam_1d](#stopforumspam_1d)|6841|6841|166|2.4%|44.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|125|0.0%|33.6%|
[php_commenters](#php_commenters)|281|281|28|9.9%|7.5%|
[php_bad](#php_bad)|281|281|28|9.9%|7.5%|
[alienvault_reputation](#alienvault_reputation)|174737|174737|25|0.0%|6.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|21|0.0%|5.6%|
[openbl_90d](#openbl_90d)|9797|9797|18|0.1%|4.8%|
[openbl_60d](#openbl_60d)|7680|7680|18|0.2%|4.8%|
[openbl](#openbl)|9797|9797|18|0.1%|4.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|17|0.0%|4.5%|
[php_harvesters](#php_harvesters)|257|257|6|2.3%|1.6%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|5|0.0%|1.3%|
[ri_web_proxies](#ri_web_proxies)|4837|4837|4|0.0%|1.0%|
[php_spammers](#php_spammers)|417|417|4|0.9%|1.0%|
[php_dictionary](#php_dictionary)|433|433|4|0.9%|1.0%|
[blocklist_de](#blocklist_de)|21611|21611|3|0.0%|0.8%|
[shunlist](#shunlist)|1180|1180|2|0.1%|0.5%|
[blocklist_de_apache](#blocklist_de_apache)|12527|12527|2|0.0%|0.5%|
[xroxy](#xroxy)|1963|1963|1|0.0%|0.2%|
[voipbl](#voipbl)|10305|10714|1|0.0%|0.2%|
[ri_connect_proxies](#ri_connect_proxies)|1842|1842|1|0.0%|0.2%|
[blocklist_de_mail](#blocklist_de_mail)|14463|14463|1|0.0%|0.2%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1201|1201|1|0.0%|0.2%|
[blocklist_de_bots](#blocklist_de_bots)|3420|3420|1|0.0%|0.2%|

## nixspam

[NiX Spam](http://www.heise.de/ix/NiX-Spam-DNSBL-and-blacklist-for-download-499637.html) IP addresses that sent spam in the last hour - automatically generated entries without distinguishing open proxies from relays, dialup gateways, and so on. All IPs are removed after 12 hours if there is no spam from there.

Source is downloaded from [this link](http://www.dnsbl.manitu.net/download/nixspam-ip.dump.gz).

The last time downloaded was found to be dated: Sat May 30 11:30:02 UTC 2015.

The ipset `nixspam` has **22785** entries, **22785** unique IPs.

The following table shows the overlaps of `nixspam` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `nixspam`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `nixspam`.
- ` this % ` is the percentage **of this ipset (`nixspam`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|1520|0.0%|6.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|567|0.0%|2.4%|
[blocklist_de](#blocklist_de)|21611|21611|539|2.4%|2.3%|
[blocklist_de_mail](#blocklist_de_mail)|14463|14463|474|3.2%|2.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|295|0.0%|1.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|238|0.0%|1.0%|
[spamhaus_drop](#spamhaus_drop)|640|17925376|237|0.0%|1.0%|
[et_block](#et_block)|986|18056524|237|0.0%|1.0%|
[stopforumspam_30d](#stopforumspam_30d)|92359|92359|218|0.2%|0.9%|
[stopforumspam_7d](#stopforumspam_7d)|30993|30993|131|0.4%|0.5%|
[snort_ipfilter](#snort_ipfilter)|5712|5712|131|2.2%|0.5%|
[php_dictionary](#php_dictionary)|433|433|84|19.3%|0.3%|
[ri_web_proxies](#ri_web_proxies)|4837|4837|75|1.5%|0.3%|
[xroxy](#xroxy)|1963|1963|70|3.5%|0.3%|
[php_spammers](#php_spammers)|417|417|67|16.0%|0.2%|
[stopforumspam_1d](#stopforumspam_1d)|6841|6841|61|0.8%|0.2%|
[blocklist_de_bots](#blocklist_de_bots)|3420|3420|48|1.4%|0.2%|
[alienvault_reputation](#alienvault_reputation)|174737|174737|42|0.0%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|11|0.0%|0.0%|
[openbl_90d](#openbl_90d)|9797|9797|10|0.1%|0.0%|
[openbl](#openbl)|9797|9797|10|0.1%|0.0%|
[proxz](#proxz)|236|236|9|3.8%|0.0%|
[proxyrss](#proxyrss)|1548|1548|9|0.5%|0.0%|
[openbl_60d](#openbl_60d)|7680|7680|9|0.1%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|9|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|1842|1842|8|0.4%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1201|1201|8|0.6%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|12527|12527|8|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|373|373|7|1.8%|0.0%|
[php_commenters](#php_commenters)|281|281|6|2.1%|0.0%|
[php_bad](#php_bad)|281|281|6|2.1%|0.0%|
[php_harvesters](#php_harvesters)|257|257|5|1.9%|0.0%|
[dm_tor](#dm_tor)|6479|6479|3|0.0%|0.0%|
[bm_tor](#bm_tor)|6474|6474|3|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|194|194|3|1.5%|0.0%|
[voipbl](#voipbl)|10305|10714|2|0.0%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1282|1282|2|0.1%|0.0%|
[et_tor](#et_tor)|6470|6470|2|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1834|1834|2|0.1%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|777|777|2|0.2%|0.0%|
[zeus_badips](#zeus_badips)|229|229|1|0.4%|0.0%|
[zeus](#zeus)|267|267|1|0.3%|0.0%|
[shunlist](#shunlist)|1180|1180|1|0.0%|0.0%|
[openbl_30d](#openbl_30d)|3339|3339|1|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|1|0.1%|0.0%|
[et_compromised](#et_compromised)|2367|2367|1|0.0%|0.0%|
[dshield](#dshield)|20|5120|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2254|2254|1|0.0%|0.0%|

## openbl

[OpenBL.org](http://www.openbl.org/) default blacklist (currently it is the same with 90 days). OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications - **excellent list**

Source is downloaded from [this link](http://www.openbl.org/lists/base.txt).

The last time downloaded was found to be dated: Sat May 30 11:32:00 UTC 2015.

The ipset `openbl` has **9797** entries, **9797** unique IPs.

The following table shows the overlaps of `openbl` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl`.
- ` this % ` is the percentage **of this ipset (`openbl`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[openbl_90d](#openbl_90d)|9797|9797|9797|100.0%|100.0%|
[alienvault_reputation](#alienvault_reputation)|174737|174737|9772|5.5%|99.7%|
[openbl_60d](#openbl_60d)|7680|7680|7680|100.0%|78.3%|
[openbl_30d](#openbl_30d)|3339|3339|3339|100.0%|34.0%|
[et_compromised](#et_compromised)|2367|2367|1434|60.5%|14.6%|
[bruteforceblocker](#bruteforceblocker)|2254|2254|1380|61.2%|14.0%|
[blocklist_de](#blocklist_de)|21611|21611|1036|4.7%|10.5%|
[blocklist_de_ssh](#blocklist_de_ssh)|1834|1834|953|51.9%|9.7%|
[openbl_7d](#openbl_7d)|949|949|949|100.0%|9.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|944|0.0%|9.6%|
[shunlist](#shunlist)|1180|1180|599|50.7%|6.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|501|0.0%|5.1%|
[et_block](#et_block)|986|18056524|454|0.0%|4.6%|
[spamhaus_drop](#spamhaus_drop)|640|17925376|449|0.0%|4.5%|
[openbl_1d](#openbl_1d)|229|229|229|100.0%|2.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|216|0.0%|2.2%|
[dshield](#dshield)|20|5120|105|2.0%|1.0%|
[stopforumspam_30d](#stopforumspam_30d)|92359|92359|63|0.0%|0.6%|
[blocklist_de_mail](#blocklist_de_mail)|14463|14463|63|0.4%|0.6%|
[blocklist_de_imap](#blocklist_de_imap)|777|777|53|6.8%|0.5%|
[blocklist_de_strongips](#blocklist_de_strongips)|194|194|49|25.2%|0.5%|
[stopforumspam_7d](#stopforumspam_7d)|30993|30993|29|0.0%|0.2%|
[snort_ipfilter](#snort_ipfilter)|5712|5712|25|0.4%|0.2%|
[stopforumspam_1d](#stopforumspam_1d)|6841|6841|21|0.3%|0.2%|
[et_tor](#et_tor)|6470|6470|21|0.3%|0.2%|
[dm_tor](#dm_tor)|6479|6479|21|0.3%|0.2%|
[bm_tor](#bm_tor)|6474|6474|21|0.3%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|20|0.0%|0.2%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|18|4.8%|0.1%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|14|0.0%|0.1%|
[blocklist_de_apache](#blocklist_de_apache)|12527|12527|12|0.0%|0.1%|
[voipbl](#voipbl)|10305|10714|11|0.1%|0.1%|
[nixspam](#nixspam)|22785|22785|10|0.0%|0.1%|
[php_commenters](#php_commenters)|281|281|8|2.8%|0.0%|
[php_bad](#php_bad)|281|281|8|2.8%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|373|373|7|1.8%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|6|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|5|1.9%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1201|1201|3|0.2%|0.0%|
[zeus](#zeus)|267|267|2|0.7%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.0%|
[zeus_badips](#zeus_badips)|229|229|1|0.4%|0.0%|
[xroxy](#xroxy)|1963|1963|1|0.0%|0.0%|
[sslbl](#sslbl)|349|349|1|0.2%|0.0%|
[ri_web_proxies](#ri_web_proxies)|4837|4837|1|0.0%|0.0%|
[ciarmy](#ciarmy)|348|348|1|0.2%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3420|3420|1|0.0%|0.0%|

## openbl_1d

[OpenBL.org](http://www.openbl.org/) last 24 hours IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.

Source is downloaded from [this link](http://www.openbl.org/lists/base_1days.txt).

The last time downloaded was found to be dated: Sat May 30 10:07:00 UTC 2015.

The ipset `openbl_1d` has **229** entries, **229** unique IPs.

The following table shows the overlaps of `openbl_1d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl_1d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl_1d`.
- ` this % ` is the percentage **of this ipset (`openbl_1d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[openbl_90d](#openbl_90d)|9797|9797|229|2.3%|100.0%|
[openbl_7d](#openbl_7d)|949|949|229|24.1%|100.0%|
[openbl_60d](#openbl_60d)|7680|7680|229|2.9%|100.0%|
[openbl_30d](#openbl_30d)|3339|3339|229|6.8%|100.0%|
[openbl](#openbl)|9797|9797|229|2.3%|100.0%|
[alienvault_reputation](#alienvault_reputation)|174737|174737|227|0.1%|99.1%|
[blocklist_de](#blocklist_de)|21611|21611|212|0.9%|92.5%|
[blocklist_de_ssh](#blocklist_de_ssh)|1834|1834|207|11.2%|90.3%|
[shunlist](#shunlist)|1180|1180|132|11.1%|57.6%|
[bruteforceblocker](#bruteforceblocker)|2254|2254|126|5.5%|55.0%|
[et_compromised](#et_compromised)|2367|2367|123|5.1%|53.7%|
[blocklist_de_strongips](#blocklist_de_strongips)|194|194|43|22.1%|18.7%|
[spamhaus_drop](#spamhaus_drop)|640|17925376|21|0.0%|9.1%|
[et_block](#et_block)|986|18056524|21|0.0%|9.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|18|0.0%|7.8%|
[dshield](#dshield)|20|5120|16|0.3%|6.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|11|0.0%|4.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|4|0.0%|1.7%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|4|0.0%|1.7%|
[blocklist_de_mail](#blocklist_de_mail)|14463|14463|3|0.0%|1.3%|
[blocklist_de_imap](#blocklist_de_imap)|777|777|3|0.3%|1.3%|
[blocklist_de_ftp](#blocklist_de_ftp)|373|373|1|0.2%|0.4%|
[blocklist_de_apache](#blocklist_de_apache)|12527|12527|1|0.0%|0.4%|

## openbl_30d

[OpenBL.org](http://www.openbl.org/) last 30 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.

Source is downloaded from [this link](http://www.openbl.org/lists/base_30days.txt).

The last time downloaded was found to be dated: Sat May 30 11:32:00 UTC 2015.

The ipset `openbl_30d` has **3339** entries, **3339** unique IPs.

The following table shows the overlaps of `openbl_30d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl_30d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl_30d`.
- ` this % ` is the percentage **of this ipset (`openbl_30d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[openbl_90d](#openbl_90d)|9797|9797|3339|34.0%|100.0%|
[openbl_60d](#openbl_60d)|7680|7680|3339|43.4%|100.0%|
[openbl](#openbl)|9797|9797|3339|34.0%|100.0%|
[alienvault_reputation](#alienvault_reputation)|174737|174737|3325|1.9%|99.5%|
[et_compromised](#et_compromised)|2367|2367|1337|56.4%|40.0%|
[bruteforceblocker](#bruteforceblocker)|2254|2254|1301|57.7%|38.9%|
[openbl_7d](#openbl_7d)|949|949|949|100.0%|28.4%|
[blocklist_de](#blocklist_de)|21611|21611|909|4.2%|27.2%|
[blocklist_de_ssh](#blocklist_de_ssh)|1834|1834|849|46.2%|25.4%|
[shunlist](#shunlist)|1180|1180|575|48.7%|17.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|289|0.0%|8.6%|
[openbl_1d](#openbl_1d)|229|229|229|100.0%|6.8%|
[et_block](#et_block)|986|18056524|209|0.0%|6.2%|
[spamhaus_drop](#spamhaus_drop)|640|17925376|205|0.0%|6.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|180|0.0%|5.3%|
[dshield](#dshield)|20|5120|104|2.0%|3.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|71|0.0%|2.1%|
[blocklist_de_mail](#blocklist_de_mail)|14463|14463|52|0.3%|1.5%|
[blocklist_de_strongips](#blocklist_de_strongips)|194|194|46|23.7%|1.3%|
[blocklist_de_imap](#blocklist_de_imap)|777|777|43|5.5%|1.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|14|0.0%|0.4%|
[stopforumspam_30d](#stopforumspam_30d)|92359|92359|6|0.0%|0.1%|
[blocklist_de_apache](#blocklist_de_apache)|12527|12527|6|0.0%|0.1%|
[voipbl](#voipbl)|10305|10714|4|0.0%|0.1%|
[stopforumspam_7d](#stopforumspam_7d)|30993|30993|3|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|5712|5712|3|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|3|0.0%|0.0%|
[zeus](#zeus)|267|267|2|0.7%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|373|373|2|0.5%|0.0%|
[zeus_badips](#zeus_badips)|229|229|1|0.4%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6841|6841|1|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|1|0.0%|0.0%|
[nixspam](#nixspam)|22785|22785|1|0.0%|0.0%|
[ciarmy](#ciarmy)|348|348|1|0.2%|0.0%|

## openbl_60d

[OpenBL.org](http://www.openbl.org/) last 60 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.

Source is downloaded from [this link](http://www.openbl.org/lists/base_60days.txt).

The last time downloaded was found to be dated: Sat May 30 11:32:00 UTC 2015.

The ipset `openbl_60d` has **7680** entries, **7680** unique IPs.

The following table shows the overlaps of `openbl_60d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl_60d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl_60d`.
- ` this % ` is the percentage **of this ipset (`openbl_60d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[openbl_90d](#openbl_90d)|9797|9797|7680|78.3%|100.0%|
[openbl](#openbl)|9797|9797|7680|78.3%|100.0%|
[alienvault_reputation](#alienvault_reputation)|174737|174737|7658|4.3%|99.7%|
[openbl_30d](#openbl_30d)|3339|3339|3339|100.0%|43.4%|
[et_compromised](#et_compromised)|2367|2367|1419|59.9%|18.4%|
[bruteforceblocker](#bruteforceblocker)|2254|2254|1366|60.6%|17.7%|
[blocklist_de](#blocklist_de)|21611|21611|987|4.5%|12.8%|
[openbl_7d](#openbl_7d)|949|949|949|100.0%|12.3%|
[blocklist_de_ssh](#blocklist_de_ssh)|1834|1834|913|49.7%|11.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|722|0.0%|9.4%|
[shunlist](#shunlist)|1180|1180|590|50.0%|7.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|358|0.0%|4.6%|
[et_block](#et_block)|986|18056524|241|0.0%|3.1%|
[spamhaus_drop](#spamhaus_drop)|640|17925376|237|0.0%|3.0%|
[openbl_1d](#openbl_1d)|229|229|229|100.0%|2.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|177|0.0%|2.3%|
[dshield](#dshield)|20|5120|104|2.0%|1.3%|
[blocklist_de_mail](#blocklist_de_mail)|14463|14463|58|0.4%|0.7%|
[stopforumspam_30d](#stopforumspam_30d)|92359|92359|56|0.0%|0.7%|
[blocklist_de_strongips](#blocklist_de_strongips)|194|194|48|24.7%|0.6%|
[blocklist_de_imap](#blocklist_de_imap)|777|777|48|6.1%|0.6%|
[stopforumspam_7d](#stopforumspam_7d)|30993|30993|27|0.0%|0.3%|
[snort_ipfilter](#snort_ipfilter)|5712|5712|25|0.4%|0.3%|
[et_tor](#et_tor)|6470|6470|21|0.3%|0.2%|
[dm_tor](#dm_tor)|6479|6479|21|0.3%|0.2%|
[bm_tor](#bm_tor)|6474|6474|21|0.3%|0.2%|
[stopforumspam_1d](#stopforumspam_1d)|6841|6841|20|0.2%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|19|0.0%|0.2%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|18|4.8%|0.2%|
[blocklist_de_apache](#blocklist_de_apache)|12527|12527|10|0.0%|0.1%|
[voipbl](#voipbl)|10305|10714|9|0.0%|0.1%|
[nixspam](#nixspam)|22785|22785|9|0.0%|0.1%|
[php_commenters](#php_commenters)|281|281|8|2.8%|0.1%|
[php_bad](#php_bad)|281|281|8|2.8%|0.1%|
[blocklist_de_ftp](#blocklist_de_ftp)|373|373|6|1.6%|0.0%|
[php_harvesters](#php_harvesters)|257|257|5|1.9%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|5|0.0%|0.0%|
[zeus](#zeus)|267|267|2|0.7%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.0%|
[zeus_badips](#zeus_badips)|229|229|1|0.4%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|1|0.0%|0.0%|
[ciarmy](#ciarmy)|348|348|1|0.2%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1201|1201|1|0.0%|0.0%|

## openbl_7d

[OpenBL.org](http://www.openbl.org/) last 7 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.

Source is downloaded from [this link](http://www.openbl.org/lists/base_7days.txt).

The last time downloaded was found to be dated: Sat May 30 11:32:00 UTC 2015.

The ipset `openbl_7d` has **949** entries, **949** unique IPs.

The following table shows the overlaps of `openbl_7d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl_7d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl_7d`.
- ` this % ` is the percentage **of this ipset (`openbl_7d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[openbl_90d](#openbl_90d)|9797|9797|949|9.6%|100.0%|
[openbl_60d](#openbl_60d)|7680|7680|949|12.3%|100.0%|
[openbl_30d](#openbl_30d)|3339|3339|949|28.4%|100.0%|
[openbl](#openbl)|9797|9797|949|9.6%|100.0%|
[alienvault_reputation](#alienvault_reputation)|174737|174737|941|0.5%|99.1%|
[blocklist_de](#blocklist_de)|21611|21611|578|2.6%|60.9%|
[blocklist_de_ssh](#blocklist_de_ssh)|1834|1834|542|29.5%|57.1%|
[et_compromised](#et_compromised)|2367|2367|504|21.2%|53.1%|
[bruteforceblocker](#bruteforceblocker)|2254|2254|504|22.3%|53.1%|
[shunlist](#shunlist)|1180|1180|367|31.1%|38.6%|
[openbl_1d](#openbl_1d)|229|229|229|100.0%|24.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|94|0.0%|9.9%|
[et_block](#et_block)|986|18056524|85|0.0%|8.9%|
[spamhaus_drop](#spamhaus_drop)|640|17925376|84|0.0%|8.8%|
[dshield](#dshield)|20|5120|73|1.4%|7.6%|
[blocklist_de_strongips](#blocklist_de_strongips)|194|194|45|23.1%|4.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|41|0.0%|4.3%|
[blocklist_de_mail](#blocklist_de_mail)|14463|14463|31|0.2%|3.2%|
[blocklist_de_imap](#blocklist_de_imap)|777|777|29|3.7%|3.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|16|0.0%|1.6%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|11|0.0%|1.1%|
[blocklist_de_apache](#blocklist_de_apache)|12527|12527|3|0.0%|0.3%|
[voipbl](#voipbl)|10305|10714|2|0.0%|0.2%|
[snort_ipfilter](#snort_ipfilter)|5712|5712|2|0.0%|0.2%|
[blocklist_de_ftp](#blocklist_de_ftp)|373|373|2|0.5%|0.2%|
[zeus](#zeus)|267|267|1|0.3%|0.1%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.1%|
[ciarmy](#ciarmy)|348|348|1|0.2%|0.1%|

## openbl_90d

[OpenBL.org](http://www.openbl.org/) last 90 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.

Source is downloaded from [this link](http://www.openbl.org/lists/base_90days.txt).

The last time downloaded was found to be dated: Sat May 30 11:32:00 UTC 2015.

The ipset `openbl_90d` has **9797** entries, **9797** unique IPs.

The following table shows the overlaps of `openbl_90d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl_90d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl_90d`.
- ` this % ` is the percentage **of this ipset (`openbl_90d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[openbl](#openbl)|9797|9797|9797|100.0%|100.0%|
[alienvault_reputation](#alienvault_reputation)|174737|174737|9772|5.5%|99.7%|
[openbl_60d](#openbl_60d)|7680|7680|7680|100.0%|78.3%|
[openbl_30d](#openbl_30d)|3339|3339|3339|100.0%|34.0%|
[et_compromised](#et_compromised)|2367|2367|1434|60.5%|14.6%|
[bruteforceblocker](#bruteforceblocker)|2254|2254|1380|61.2%|14.0%|
[blocklist_de](#blocklist_de)|21611|21611|1036|4.7%|10.5%|
[blocklist_de_ssh](#blocklist_de_ssh)|1834|1834|953|51.9%|9.7%|
[openbl_7d](#openbl_7d)|949|949|949|100.0%|9.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|944|0.0%|9.6%|
[shunlist](#shunlist)|1180|1180|599|50.7%|6.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|501|0.0%|5.1%|
[et_block](#et_block)|986|18056524|454|0.0%|4.6%|
[spamhaus_drop](#spamhaus_drop)|640|17925376|449|0.0%|4.5%|
[openbl_1d](#openbl_1d)|229|229|229|100.0%|2.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|216|0.0%|2.2%|
[dshield](#dshield)|20|5120|105|2.0%|1.0%|
[stopforumspam_30d](#stopforumspam_30d)|92359|92359|63|0.0%|0.6%|
[blocklist_de_mail](#blocklist_de_mail)|14463|14463|63|0.4%|0.6%|
[blocklist_de_imap](#blocklist_de_imap)|777|777|53|6.8%|0.5%|
[blocklist_de_strongips](#blocklist_de_strongips)|194|194|49|25.2%|0.5%|
[stopforumspam_7d](#stopforumspam_7d)|30993|30993|29|0.0%|0.2%|
[snort_ipfilter](#snort_ipfilter)|5712|5712|25|0.4%|0.2%|
[stopforumspam_1d](#stopforumspam_1d)|6841|6841|21|0.3%|0.2%|
[et_tor](#et_tor)|6470|6470|21|0.3%|0.2%|
[dm_tor](#dm_tor)|6479|6479|21|0.3%|0.2%|
[bm_tor](#bm_tor)|6474|6474|21|0.3%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|20|0.0%|0.2%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|18|4.8%|0.1%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|14|0.0%|0.1%|
[blocklist_de_apache](#blocklist_de_apache)|12527|12527|12|0.0%|0.1%|
[voipbl](#voipbl)|10305|10714|11|0.1%|0.1%|
[nixspam](#nixspam)|22785|22785|10|0.0%|0.1%|
[php_commenters](#php_commenters)|281|281|8|2.8%|0.0%|
[php_bad](#php_bad)|281|281|8|2.8%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|373|373|7|1.8%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|6|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|5|1.9%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1201|1201|3|0.2%|0.0%|
[zeus](#zeus)|267|267|2|0.7%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.0%|
[zeus_badips](#zeus_badips)|229|229|1|0.4%|0.0%|
[xroxy](#xroxy)|1963|1963|1|0.0%|0.0%|
[sslbl](#sslbl)|349|349|1|0.2%|0.0%|
[ri_web_proxies](#ri_web_proxies)|4837|4837|1|0.0%|0.0%|
[ciarmy](#ciarmy)|348|348|1|0.2%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3420|3420|1|0.0%|0.0%|

## palevo

[Abuse.ch Palevo tracker](https://palevotracker.abuse.ch) worm includes IPs which are being used as botnet C&C for the Palevo crimeware - **excellent list**

Source is downloaded from [this link](https://palevotracker.abuse.ch/blocklists.php?download=ipblocklist).

The last time downloaded was found to be dated: Sat May 30 11:36:25 UTC 2015.

The ipset `palevo` has **13** entries, **13** unique IPs.

The following table shows the overlaps of `palevo` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `palevo`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `palevo`.
- ` this % ` is the percentage **of this ipset (`palevo`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[et_block](#et_block)|986|18056524|13|0.0%|100.0%|
[snort_ipfilter](#snort_ipfilter)|5712|5712|11|0.1%|84.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|2|0.0%|15.3%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|7.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|1|0.0%|7.6%|

## php_bad

[projecthoneypot.org](http://www.projecthoneypot.org/) bad web hosts (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=b&rss=1).

The last time downloaded was found to be dated: Thu May 28 20:53:18 UTC 2015.

The ipset `php_bad` has **281** entries, **281** unique IPs.

The following table shows the overlaps of `php_bad` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `php_bad`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `php_bad`.
- ` this % ` is the percentage **of this ipset (`php_bad`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[php_commenters](#php_commenters)|281|281|279|99.2%|99.2%|
[stopforumspam_30d](#stopforumspam_30d)|92359|92359|202|0.2%|71.8%|
[stopforumspam_7d](#stopforumspam_7d)|30993|30993|180|0.5%|64.0%|
[stopforumspam_1d](#stopforumspam_1d)|6841|6841|103|1.5%|36.6%|
[blocklist_de](#blocklist_de)|21611|21611|67|0.3%|23.8%|
[blocklist_de_bots](#blocklist_de_bots)|3420|3420|52|1.5%|18.5%|
[snort_ipfilter](#snort_ipfilter)|5712|5712|37|0.6%|13.1%|
[blocklist_de_strongips](#blocklist_de_strongips)|194|194|33|17.0%|11.7%|
[php_spammers](#php_spammers)|417|417|32|7.6%|11.3%|
[et_tor](#et_tor)|6470|6470|29|0.4%|10.3%|
[dm_tor](#dm_tor)|6479|6479|29|0.4%|10.3%|
[bm_tor](#bm_tor)|6474|6474|29|0.4%|10.3%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|28|7.5%|9.9%|
[blocklist_de_apache](#blocklist_de_apache)|12527|12527|26|0.2%|9.2%|
[spamhaus_drop](#spamhaus_drop)|640|17925376|24|0.0%|8.5%|
[et_block](#et_block)|986|18056524|24|0.0%|8.5%|
[php_dictionary](#php_dictionary)|433|433|22|5.0%|7.8%|
[blocklist_de_mail](#blocklist_de_mail)|14463|14463|19|0.1%|6.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|16|0.0%|5.6%|
[alienvault_reputation](#alienvault_reputation)|174737|174737|12|0.0%|4.2%|
[ri_web_proxies](#ri_web_proxies)|4837|4837|10|0.2%|3.5%|
[php_harvesters](#php_harvesters)|257|257|9|3.5%|3.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|9|0.0%|3.2%|
[openbl_90d](#openbl_90d)|9797|9797|8|0.0%|2.8%|
[openbl_60d](#openbl_60d)|7680|7680|8|0.1%|2.8%|
[openbl](#openbl)|9797|9797|8|0.0%|2.8%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|7|0.0%|2.4%|
[nixspam](#nixspam)|22785|22785|6|0.0%|2.1%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1201|1201|6|0.4%|2.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|5|0.0%|1.7%|
[xroxy](#xroxy)|1963|1963|3|0.1%|1.0%|
[proxz](#proxz)|236|236|2|0.8%|0.7%|
[proxyrss](#proxyrss)|1548|1548|2|0.1%|0.7%|
[zeus_badips](#zeus_badips)|229|229|1|0.4%|0.3%|
[zeus](#zeus)|267|267|1|0.3%|0.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.3%|

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
[php_bad](#php_bad)|281|281|279|99.2%|99.2%|
[stopforumspam_30d](#stopforumspam_30d)|92359|92359|203|0.2%|72.2%|
[stopforumspam_7d](#stopforumspam_7d)|30993|30993|181|0.5%|64.4%|
[stopforumspam_1d](#stopforumspam_1d)|6841|6841|103|1.5%|36.6%|
[blocklist_de](#blocklist_de)|21611|21611|67|0.3%|23.8%|
[blocklist_de_bots](#blocklist_de_bots)|3420|3420|52|1.5%|18.5%|
[snort_ipfilter](#snort_ipfilter)|5712|5712|38|0.6%|13.5%|
[blocklist_de_strongips](#blocklist_de_strongips)|194|194|33|17.0%|11.7%|
[php_spammers](#php_spammers)|417|417|32|7.6%|11.3%|
[et_tor](#et_tor)|6470|6470|29|0.4%|10.3%|
[dm_tor](#dm_tor)|6479|6479|29|0.4%|10.3%|
[bm_tor](#bm_tor)|6474|6474|29|0.4%|10.3%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|28|7.5%|9.9%|
[blocklist_de_apache](#blocklist_de_apache)|12527|12527|26|0.2%|9.2%|
[spamhaus_drop](#spamhaus_drop)|640|17925376|24|0.0%|8.5%|
[et_block](#et_block)|986|18056524|24|0.0%|8.5%|
[php_dictionary](#php_dictionary)|433|433|22|5.0%|7.8%|
[blocklist_de_mail](#blocklist_de_mail)|14463|14463|19|0.1%|6.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|15|0.0%|5.3%|
[alienvault_reputation](#alienvault_reputation)|174737|174737|12|0.0%|4.2%|
[ri_web_proxies](#ri_web_proxies)|4837|4837|10|0.2%|3.5%|
[php_harvesters](#php_harvesters)|257|257|9|3.5%|3.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|9|0.0%|3.2%|
[openbl_90d](#openbl_90d)|9797|9797|8|0.0%|2.8%|
[openbl_60d](#openbl_60d)|7680|7680|8|0.1%|2.8%|
[openbl](#openbl)|9797|9797|8|0.0%|2.8%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|7|0.0%|2.4%|
[nixspam](#nixspam)|22785|22785|6|0.0%|2.1%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1201|1201|6|0.4%|2.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|5|0.0%|1.7%|
[xroxy](#xroxy)|1963|1963|3|0.1%|1.0%|
[proxz](#proxz)|236|236|2|0.8%|0.7%|
[proxyrss](#proxyrss)|1548|1548|2|0.1%|0.7%|
[zeus_badips](#zeus_badips)|229|229|1|0.4%|0.3%|
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
[nixspam](#nixspam)|22785|22785|84|0.3%|19.3%|
[stopforumspam_30d](#stopforumspam_30d)|92359|92359|81|0.0%|18.7%|
[blocklist_de](#blocklist_de)|21611|21611|66|0.3%|15.2%|
[stopforumspam_7d](#stopforumspam_7d)|30993|30993|64|0.2%|14.7%|
[snort_ipfilter](#snort_ipfilter)|5712|5712|51|0.8%|11.7%|
[blocklist_de_mail](#blocklist_de_mail)|14463|14463|51|0.3%|11.7%|
[ri_web_proxies](#ri_web_proxies)|4837|4837|27|0.5%|6.2%|
[xroxy](#xroxy)|1963|1963|24|1.2%|5.5%|
[stopforumspam_1d](#stopforumspam_1d)|6841|6841|24|0.3%|5.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|24|0.0%|5.5%|
[php_commenters](#php_commenters)|281|281|22|7.8%|5.0%|
[php_bad](#php_bad)|281|281|22|7.8%|5.0%|
[blocklist_de_bots](#blocklist_de_bots)|3420|3420|15|0.4%|3.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|10|0.0%|2.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|9|0.0%|2.0%|
[alienvault_reputation](#alienvault_reputation)|174737|174737|7|0.0%|1.6%|
[spamhaus_drop](#spamhaus_drop)|640|17925376|4|0.0%|0.9%|
[proxz](#proxz)|236|236|4|1.6%|0.9%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|4|1.0%|0.9%|
[et_tor](#et_tor)|6470|6470|4|0.0%|0.9%|
[et_block](#et_block)|986|18056524|4|0.0%|0.9%|
[dm_tor](#dm_tor)|6479|6479|4|0.0%|0.9%|
[bm_tor](#bm_tor)|6474|6474|4|0.0%|0.9%|
[ri_connect_proxies](#ri_connect_proxies)|1842|1842|3|0.1%|0.6%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2|0.0%|0.4%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|2|0.0%|0.4%|
[blocklist_de_strongips](#blocklist_de_strongips)|194|194|2|1.0%|0.4%|
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
[stopforumspam_30d](#stopforumspam_30d)|92359|92359|62|0.0%|24.1%|
[stopforumspam_7d](#stopforumspam_7d)|30993|30993|47|0.1%|18.2%|
[stopforumspam_1d](#stopforumspam_1d)|6841|6841|34|0.4%|13.2%|
[blocklist_de](#blocklist_de)|21611|21611|28|0.1%|10.8%|
[blocklist_de_bots](#blocklist_de_bots)|3420|3420|23|0.6%|8.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|15|0.0%|5.8%|
[snort_ipfilter](#snort_ipfilter)|5712|5712|9|0.1%|3.5%|
[php_commenters](#php_commenters)|281|281|9|3.2%|3.5%|
[php_bad](#php_bad)|281|281|9|3.2%|3.5%|
[alienvault_reputation](#alienvault_reputation)|174737|174737|9|0.0%|3.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|7|0.0%|2.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|7|0.0%|2.7%|
[et_tor](#et_tor)|6470|6470|7|0.1%|2.7%|
[dm_tor](#dm_tor)|6479|6479|7|0.1%|2.7%|
[bm_tor](#bm_tor)|6474|6474|7|0.1%|2.7%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|6|1.6%|2.3%|
[openbl_90d](#openbl_90d)|9797|9797|5|0.0%|1.9%|
[openbl_60d](#openbl_60d)|7680|7680|5|0.0%|1.9%|
[openbl](#openbl)|9797|9797|5|0.0%|1.9%|
[nixspam](#nixspam)|22785|22785|5|0.0%|1.9%|
[blocklist_de_ftp](#blocklist_de_ftp)|373|373|4|1.0%|1.5%|
[xroxy](#xroxy)|1963|1963|2|0.1%|0.7%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|2|0.0%|0.7%|
[blocklist_de_strongips](#blocklist_de_strongips)|194|194|2|1.0%|0.7%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|1|0.0%|0.3%|
[spamhaus_drop](#spamhaus_drop)|640|17925376|1|0.0%|0.3%|
[ri_web_proxies](#ri_web_proxies)|4837|4837|1|0.0%|0.3%|
[proxyrss](#proxyrss)|1548|1548|1|0.0%|0.3%|
[php_spammers](#php_spammers)|417|417|1|0.2%|0.3%|
[php_dictionary](#php_dictionary)|433|433|1|0.2%|0.3%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.3%|
[fullbogons](#fullbogons)|3642|670590424|1|0.0%|0.3%|
[et_block](#et_block)|986|18056524|1|0.0%|0.3%|
[bogons](#bogons)|13|592708608|1|0.0%|0.3%|
[blocklist_de_mail](#blocklist_de_mail)|14463|14463|1|0.0%|0.3%|
[blocklist_de_apache](#blocklist_de_apache)|12527|12527|1|0.0%|0.3%|

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
[stopforumspam_30d](#stopforumspam_30d)|92359|92359|97|0.1%|23.2%|
[php_dictionary](#php_dictionary)|433|433|84|19.3%|20.1%|
[nixspam](#nixspam)|22785|22785|67|0.2%|16.0%|
[stopforumspam_7d](#stopforumspam_7d)|30993|30993|66|0.2%|15.8%|
[blocklist_de](#blocklist_de)|21611|21611|59|0.2%|14.1%|
[snort_ipfilter](#snort_ipfilter)|5712|5712|48|0.8%|11.5%|
[blocklist_de_mail](#blocklist_de_mail)|14463|14463|37|0.2%|8.8%|
[php_commenters](#php_commenters)|281|281|32|11.3%|7.6%|
[php_bad](#php_bad)|281|281|32|11.3%|7.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|31|0.0%|7.4%|
[stopforumspam_1d](#stopforumspam_1d)|6841|6841|29|0.4%|6.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|26|0.0%|6.2%|
[ri_web_proxies](#ri_web_proxies)|4837|4837|22|0.4%|5.2%|
[xroxy](#xroxy)|1963|1963|18|0.9%|4.3%|
[blocklist_de_bots](#blocklist_de_bots)|3420|3420|16|0.4%|3.8%|
[et_tor](#et_tor)|6470|6470|6|0.0%|1.4%|
[dm_tor](#dm_tor)|6479|6479|6|0.0%|1.4%|
[bm_tor](#bm_tor)|6474|6474|6|0.0%|1.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|5|0.0%|1.1%|
[blocklist_de_strongips](#blocklist_de_strongips)|194|194|5|2.5%|1.1%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1201|1201|5|0.4%|1.1%|
[blocklist_de_apache](#blocklist_de_apache)|12527|12527|5|0.0%|1.1%|
[proxz](#proxz)|236|236|4|1.6%|0.9%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|4|1.0%|0.9%|
[alienvault_reputation](#alienvault_reputation)|174737|174737|3|0.0%|0.7%|
[spamhaus_drop](#spamhaus_drop)|640|17925376|2|0.0%|0.4%|
[ri_connect_proxies](#ri_connect_proxies)|1842|1842|2|0.1%|0.4%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2|0.0%|0.4%|
[et_block](#et_block)|986|18056524|2|0.0%|0.4%|
[proxyrss](#proxyrss)|1548|1548|1|0.0%|0.2%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.2%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1|0.0%|0.2%|
[blocklist_de_ssh](#blocklist_de_ssh)|1834|1834|1|0.0%|0.2%|

## proxyrss

[proxyrss.com](http://www.proxyrss.com) open proxies syndicated from multiple sources.

Source is downloaded from [this link](http://www.proxyrss.com/proxylists/all.gz).

The last time downloaded was found to be dated: Sat May 30 07:41:27 UTC 2015.

The ipset `proxyrss` has **1548** entries, **1548** unique IPs.

The following table shows the overlaps of `proxyrss` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `proxyrss`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `proxyrss`.
- ` this % ` is the percentage **of this ipset (`proxyrss`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_30d](#stopforumspam_30d)|92359|92359|858|0.9%|55.4%|
[stopforumspam_7d](#stopforumspam_7d)|30993|30993|722|2.3%|46.6%|
[ri_web_proxies](#ri_web_proxies)|4837|4837|619|12.7%|39.9%|
[xroxy](#xroxy)|1963|1963|549|27.9%|35.4%|
[stopforumspam_1d](#stopforumspam_1d)|6841|6841|389|5.6%|25.1%|
[blocklist_de](#blocklist_de)|21611|21611|262|1.2%|16.9%|
[blocklist_de_bots](#blocklist_de_bots)|3420|3420|261|7.6%|16.8%|
[ri_connect_proxies](#ri_connect_proxies)|1842|1842|243|13.1%|15.6%|
[proxz](#proxz)|236|236|110|46.6%|7.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|63|0.0%|4.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|53|0.0%|3.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|36|0.0%|2.3%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|13|1.9%|0.8%|
[nixspam](#nixspam)|22785|22785|9|0.0%|0.5%|
[snort_ipfilter](#snort_ipfilter)|5712|5712|4|0.0%|0.2%|
[php_commenters](#php_commenters)|281|281|2|0.7%|0.1%|
[php_bad](#php_bad)|281|281|2|0.7%|0.1%|
[et_tor](#et_tor)|6470|6470|2|0.0%|0.1%|
[dm_tor](#dm_tor)|6479|6479|2|0.0%|0.1%|
[bm_tor](#bm_tor)|6474|6474|2|0.0%|0.1%|
[blocklist_de_strongips](#blocklist_de_strongips)|194|194|2|1.0%|0.1%|
[alienvault_reputation](#alienvault_reputation)|174737|174737|2|0.0%|0.1%|
[php_spammers](#php_spammers)|417|417|1|0.2%|0.0%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.0%|
[et_compromised](#et_compromised)|2367|2367|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2254|2254|1|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1834|1834|1|0.0%|0.0%|

## proxz

[proxz.com](http://www.proxz.com) open proxies (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.proxz.com/proxylists.xml).

The last time downloaded was found to be dated: Sat May 30 07:41:32 UTC 2015.

The ipset `proxz` has **236** entries, **236** unique IPs.

The following table shows the overlaps of `proxz` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `proxz`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `proxz`.
- ` this % ` is the percentage **of this ipset (`proxz`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_30d](#stopforumspam_30d)|92359|92359|141|0.1%|59.7%|
[xroxy](#xroxy)|1963|1963|140|7.1%|59.3%|
[stopforumspam_7d](#stopforumspam_7d)|30993|30993|127|0.4%|53.8%|
[proxyrss](#proxyrss)|1548|1548|110|7.1%|46.6%|
[ri_web_proxies](#ri_web_proxies)|4837|4837|104|2.1%|44.0%|
[blocklist_de](#blocklist_de)|21611|21611|64|0.2%|27.1%|
[stopforumspam_1d](#stopforumspam_1d)|6841|6841|59|0.8%|25.0%|
[blocklist_de_bots](#blocklist_de_bots)|3420|3420|58|1.6%|24.5%|
[ri_connect_proxies](#ri_connect_proxies)|1842|1842|36|1.9%|15.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|31|0.0%|13.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|13|0.0%|5.5%|
[nixspam](#nixspam)|22785|22785|9|0.0%|3.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|9|0.0%|3.8%|
[blocklist_de_mail](#blocklist_de_mail)|14463|14463|5|0.0%|2.1%|
[snort_ipfilter](#snort_ipfilter)|5712|5712|4|0.0%|1.6%|
[php_spammers](#php_spammers)|417|417|4|0.9%|1.6%|
[php_dictionary](#php_dictionary)|433|433|4|0.9%|1.6%|
[php_commenters](#php_commenters)|281|281|2|0.7%|0.8%|
[php_bad](#php_bad)|281|281|2|0.7%|0.8%|
[et_compromised](#et_compromised)|2367|2367|2|0.0%|0.8%|
[bruteforceblocker](#bruteforceblocker)|2254|2254|2|0.0%|0.8%|
[alienvault_reputation](#alienvault_reputation)|174737|174737|2|0.0%|0.8%|
[et_tor](#et_tor)|6470|6470|1|0.0%|0.4%|
[dm_tor](#dm_tor)|6479|6479|1|0.0%|0.4%|
[bm_tor](#bm_tor)|6474|6474|1|0.0%|0.4%|
[blocklist_de_strongips](#blocklist_de_strongips)|194|194|1|0.5%|0.4%|
[blocklist_de_ssh](#blocklist_de_ssh)|1834|1834|1|0.0%|0.4%|

## ri_connect_proxies

[rosinstrument.com](http://www.rosinstrument.com) open CONNECT proxies (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://tools.rosinstrument.com/proxy/plab100.xml).

The last time downloaded was found to be dated: Sat May 30 04:44:02 UTC 2015.

The ipset `ri_connect_proxies` has **1842** entries, **1842** unique IPs.

The following table shows the overlaps of `ri_connect_proxies` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ri_connect_proxies`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ri_connect_proxies`.
- ` this % ` is the percentage **of this ipset (`ri_connect_proxies`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_30d](#stopforumspam_30d)|92359|92359|1087|1.1%|59.0%|
[ri_web_proxies](#ri_web_proxies)|4837|4837|738|15.2%|40.0%|
[stopforumspam_7d](#stopforumspam_7d)|30993|30993|689|2.2%|37.4%|
[xroxy](#xroxy)|1963|1963|295|15.0%|16.0%|
[proxyrss](#proxyrss)|1548|1548|243|15.6%|13.1%|
[stopforumspam_1d](#stopforumspam_1d)|6841|6841|137|2.0%|7.4%|
[blocklist_de](#blocklist_de)|21611|21611|84|0.3%|4.5%|
[blocklist_de_bots](#blocklist_de_bots)|3420|3420|82|2.3%|4.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|76|0.0%|4.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|64|0.0%|3.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|43|0.0%|2.3%|
[proxz](#proxz)|236|236|36|15.2%|1.9%|
[nixspam](#nixspam)|22785|22785|8|0.0%|0.4%|
[snort_ipfilter](#snort_ipfilter)|5712|5712|6|0.1%|0.3%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|6|0.8%|0.3%|
[php_dictionary](#php_dictionary)|433|433|3|0.6%|0.1%|
[php_spammers](#php_spammers)|417|417|2|0.4%|0.1%|
[et_tor](#et_tor)|6470|6470|2|0.0%|0.1%|
[dm_tor](#dm_tor)|6479|6479|2|0.0%|0.1%|
[bm_tor](#bm_tor)|6474|6474|2|0.0%|0.1%|
[blocklist_de_mail](#blocklist_de_mail)|14463|14463|2|0.0%|0.1%|
[alienvault_reputation](#alienvault_reputation)|174737|174737|2|0.0%|0.1%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|

## ri_web_proxies

[rosinstrument.com](http://www.rosinstrument.com) open HTTP proxies (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://tools.rosinstrument.com/proxy/l100.xml).

The last time downloaded was found to be dated: Sat May 30 06:41:17 UTC 2015.

The ipset `ri_web_proxies` has **4837** entries, **4837** unique IPs.

The following table shows the overlaps of `ri_web_proxies` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ri_web_proxies`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ri_web_proxies`.
- ` this % ` is the percentage **of this ipset (`ri_web_proxies`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_30d](#stopforumspam_30d)|92359|92359|2413|2.6%|49.8%|
[stopforumspam_7d](#stopforumspam_7d)|30993|30993|1689|5.4%|34.9%|
[xroxy](#xroxy)|1963|1963|769|39.1%|15.8%|
[ri_connect_proxies](#ri_connect_proxies)|1842|1842|738|40.0%|15.2%|
[proxyrss](#proxyrss)|1548|1548|619|39.9%|12.7%|
[stopforumspam_1d](#stopforumspam_1d)|6841|6841|458|6.6%|9.4%|
[blocklist_de](#blocklist_de)|21611|21611|396|1.8%|8.1%|
[blocklist_de_bots](#blocklist_de_bots)|3420|3420|365|10.6%|7.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|165|0.0%|3.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|146|0.0%|3.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|109|0.0%|2.2%|
[proxz](#proxz)|236|236|104|44.0%|2.1%|
[nixspam](#nixspam)|22785|22785|75|0.3%|1.5%|
[snort_ipfilter](#snort_ipfilter)|5712|5712|33|0.5%|0.6%|
[blocklist_de_mail](#blocklist_de_mail)|14463|14463|31|0.2%|0.6%|
[php_dictionary](#php_dictionary)|433|433|27|6.2%|0.5%|
[php_spammers](#php_spammers)|417|417|22|5.2%|0.4%|
[php_commenters](#php_commenters)|281|281|10|3.5%|0.2%|
[php_bad](#php_bad)|281|281|10|3.5%|0.2%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|10|1.4%|0.2%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|4|1.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|4|0.0%|0.0%|
[et_tor](#et_tor)|6470|6470|4|0.0%|0.0%|
[dm_tor](#dm_tor)|6479|6479|4|0.0%|0.0%|
[bm_tor](#bm_tor)|6474|6474|4|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|194|194|3|1.5%|0.0%|
[alienvault_reputation](#alienvault_reputation)|174737|174737|3|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.0%|
[openbl_90d](#openbl_90d)|9797|9797|1|0.0%|0.0%|
[openbl](#openbl)|9797|9797|1|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1|0.0%|0.0%|

## shunlist

[AutoShun.org](http://autoshun.org/) IPs identified as hostile by correlating logs from distributed snort installations running the autoshun plugin

Source is downloaded from [this link](http://www.autoshun.org/files/shunlist.csv).

The last time downloaded was found to be dated: Sat May 30 10:30:04 UTC 2015.

The ipset `shunlist` has **1180** entries, **1180** unique IPs.

The following table shows the overlaps of `shunlist` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `shunlist`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `shunlist`.
- ` this % ` is the percentage **of this ipset (`shunlist`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[alienvault_reputation](#alienvault_reputation)|174737|174737|1179|0.6%|99.9%|
[openbl_90d](#openbl_90d)|9797|9797|599|6.1%|50.7%|
[openbl](#openbl)|9797|9797|599|6.1%|50.7%|
[openbl_60d](#openbl_60d)|7680|7680|590|7.6%|50.0%|
[openbl_30d](#openbl_30d)|3339|3339|575|17.2%|48.7%|
[et_compromised](#et_compromised)|2367|2367|495|20.9%|41.9%|
[bruteforceblocker](#bruteforceblocker)|2254|2254|493|21.8%|41.7%|
[blocklist_de](#blocklist_de)|21611|21611|479|2.2%|40.5%|
[blocklist_de_ssh](#blocklist_de_ssh)|1834|1834|440|23.9%|37.2%|
[openbl_7d](#openbl_7d)|949|949|367|38.6%|31.1%|
[openbl_1d](#openbl_1d)|229|229|132|57.6%|11.1%|
[et_block](#et_block)|986|18056524|110|0.0%|9.3%|
[dshield](#dshield)|20|5120|104|2.0%|8.8%|
[spamhaus_drop](#spamhaus_drop)|640|17925376|101|0.0%|8.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|89|0.0%|7.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|72|0.0%|6.1%|
[blocklist_de_strongips](#blocklist_de_strongips)|194|194|42|21.6%|3.5%|
[blocklist_de_apache](#blocklist_de_apache)|12527|12527|32|0.2%|2.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|24|0.0%|2.0%|
[ciarmy](#ciarmy)|348|348|21|6.0%|1.7%|
[voipbl](#voipbl)|10305|10714|12|0.1%|1.0%|
[blocklist_de_mail](#blocklist_de_mail)|14463|14463|5|0.0%|0.4%|
[blocklist_de_imap](#blocklist_de_imap)|777|777|5|0.6%|0.4%|
[stopforumspam_30d](#stopforumspam_30d)|92359|92359|4|0.0%|0.3%|
[sslbl](#sslbl)|349|349|4|1.1%|0.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|4|0.0%|0.3%|
[stopforumspam_7d](#stopforumspam_7d)|30993|30993|2|0.0%|0.1%|
[snort_ipfilter](#snort_ipfilter)|5712|5712|2|0.0%|0.1%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|2|0.5%|0.1%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1201|1201|2|0.1%|0.1%|
[stopforumspam_1d](#stopforumspam_1d)|6841|6841|1|0.0%|0.0%|
[nixspam](#nixspam)|22785|22785|1|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.0%|
[et_tor](#et_tor)|6470|6470|1|0.0%|0.0%|
[dm_tor](#dm_tor)|6479|6479|1|0.0%|0.0%|
[bm_tor](#bm_tor)|6474|6474|1|0.0%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|85|85|1|1.1%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|373|373|1|0.2%|0.0%|

## snort_ipfilter

[labs.snort.org](https://labs.snort.org/) supplied IP blacklist (this list seems to be updated frequently, but we found no information about it)

Source is downloaded from [this link](http://labs.snort.org/feeds/ip-filter.blf).

The last time downloaded was found to be dated: Sat May 30 01:30:00 UTC 2015.

The ipset `snort_ipfilter` has **5712** entries, **5712** unique IPs.

The following table shows the overlaps of `snort_ipfilter` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `snort_ipfilter`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `snort_ipfilter`.
- ` this % ` is the percentage **of this ipset (`snort_ipfilter`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[et_tor](#et_tor)|6470|6470|1072|16.5%|18.7%|
[bm_tor](#bm_tor)|6474|6474|1002|15.4%|17.5%|
[dm_tor](#dm_tor)|6479|6479|997|15.3%|17.4%|
[stopforumspam_30d](#stopforumspam_30d)|92359|92359|732|0.7%|12.8%|
[stopforumspam_7d](#stopforumspam_7d)|30993|30993|570|1.8%|9.9%|
[stopforumspam_1d](#stopforumspam_1d)|6841|6841|358|5.2%|6.2%|
[et_block](#et_block)|986|18056524|294|0.0%|5.1%|
[zeus](#zeus)|267|267|222|83.1%|3.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|218|0.0%|3.8%|
[zeus_badips](#zeus_badips)|229|229|199|86.8%|3.4%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|184|49.4%|3.2%|
[nixspam](#nixspam)|22785|22785|131|0.5%|2.2%|
[blocklist_de](#blocklist_de)|21611|21611|122|0.5%|2.1%|
[alienvault_reputation](#alienvault_reputation)|174737|174737|117|0.0%|2.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|90|0.0%|1.5%|
[blocklist_de_mail](#blocklist_de_mail)|14463|14463|82|0.5%|1.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|64|0.0%|1.1%|
[feodo](#feodo)|70|70|53|75.7%|0.9%|
[php_dictionary](#php_dictionary)|433|433|51|11.7%|0.8%|
[php_spammers](#php_spammers)|417|417|48|11.5%|0.8%|
[php_commenters](#php_commenters)|281|281|38|13.5%|0.6%|
[php_bad](#php_bad)|281|281|37|13.1%|0.6%|
[xroxy](#xroxy)|1963|1963|34|1.7%|0.5%|
[ri_web_proxies](#ri_web_proxies)|4837|4837|33|0.6%|0.5%|
[malwaredomainlist](#malwaredomainlist)|1282|1282|26|2.0%|0.4%|
[openbl_90d](#openbl_90d)|9797|9797|25|0.2%|0.4%|
[openbl_60d](#openbl_60d)|7680|7680|25|0.3%|0.4%|
[openbl](#openbl)|9797|9797|25|0.2%|0.4%|
[blocklist_de_apache](#blocklist_de_apache)|12527|12527|24|0.1%|0.4%|
[sslbl](#sslbl)|349|349|21|6.0%|0.3%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1201|1201|21|1.7%|0.3%|
[spamhaus_drop](#spamhaus_drop)|640|17925376|18|0.0%|0.3%|
[blocklist_de_bots](#blocklist_de_bots)|3420|3420|17|0.4%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|15|0.0%|0.2%|
[palevo](#palevo)|13|13|11|84.6%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|11|0.0%|0.1%|
[php_harvesters](#php_harvesters)|257|257|9|3.5%|0.1%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|6|0.0%|0.1%|
[ri_connect_proxies](#ri_connect_proxies)|1842|1842|6|0.3%|0.1%|
[proxz](#proxz)|236|236|4|1.6%|0.0%|
[proxyrss](#proxyrss)|1548|1548|4|0.2%|0.0%|
[openbl_30d](#openbl_30d)|3339|3339|3|0.0%|0.0%|
[shunlist](#shunlist)|1180|1180|2|0.1%|0.0%|
[openbl_7d](#openbl_7d)|949|949|2|0.2%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.0%|
[malc0de](#malc0de)|410|410|1|0.2%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|1|0.1%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1|0.0%|0.0%|
[et_compromised](#et_compromised)|2367|2367|1|0.0%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|259|259|1|0.3%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2254|2254|1|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|194|194|1|0.5%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1834|1834|1|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|777|777|1|0.1%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|373|373|1|0.2%|0.0%|

## spamhaus_drop

[Spamhaus.org](http://www.spamhaus.org) DROP list (according to their site this list should be dropped at tier-1 ISPs globaly) - **excellent list**

Source is downloaded from [this link](http://www.spamhaus.org/drop/drop.txt).

The last time downloaded was found to be dated: Sat May 30 07:28:58 UTC 2015.

The ipset `spamhaus_drop` has **640** entries, **17925376** unique IPs.

The following table shows the overlaps of `spamhaus_drop` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `spamhaus_drop`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `spamhaus_drop`.
- ` this % ` is the percentage **of this ipset (`spamhaus_drop`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[et_block](#et_block)|986|18056524|17920256|99.2%|99.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|8401434|2.4%|46.8%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|7079936|77.1%|39.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|2133002|0.2%|11.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|195904|0.1%|1.0%|
[fullbogons](#fullbogons)|3642|670590424|20480|0.0%|0.1%|
[alienvault_reputation](#alienvault_reputation)|174737|174737|1626|0.9%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1037|0.3%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92359|92359|744|0.8%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|512|0.1%|0.0%|
[dshield](#dshield)|20|5120|512|10.0%|0.0%|
[openbl_90d](#openbl_90d)|9797|9797|449|4.5%|0.0%|
[openbl](#openbl)|9797|9797|449|4.5%|0.0%|
[openbl_60d](#openbl_60d)|7680|7680|237|3.0%|0.0%|
[nixspam](#nixspam)|22785|22785|237|1.0%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|30993|30993|208|0.6%|0.0%|
[openbl_30d](#openbl_30d)|3339|3339|205|6.1%|0.0%|
[blocklist_de](#blocklist_de)|21611|21611|184|0.8%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1834|1834|108|5.8%|0.0%|
[et_compromised](#et_compromised)|2367|2367|102|4.3%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2254|2254|102|4.5%|0.0%|
[shunlist](#shunlist)|1180|1180|101|8.5%|0.0%|
[openbl_7d](#openbl_7d)|949|949|84|8.8%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3420|3420|51|1.4%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6841|6841|45|0.6%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1282|1282|29|2.2%|0.0%|
[php_commenters](#php_commenters)|281|281|24|8.5%|0.0%|
[php_bad](#php_bad)|281|281|24|8.5%|0.0%|
[openbl_1d](#openbl_1d)|229|229|21|9.1%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14463|14463|20|0.1%|0.0%|
[snort_ipfilter](#snort_ipfilter)|5712|5712|18|0.3%|0.0%|
[zeus_badips](#zeus_badips)|229|229|16|6.9%|0.0%|
[zeus](#zeus)|267|267|16|5.9%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|777|777|15|1.9%|0.0%|
[voipbl](#voipbl)|10305|10714|14|0.1%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|6|0.4%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|6|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|194|194|6|3.0%|0.0%|
[php_dictionary](#php_dictionary)|433|433|4|0.9%|0.0%|
[sslbl](#sslbl)|349|349|3|0.8%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1201|1201|3|0.2%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|12527|12527|3|0.0%|0.0%|
[php_spammers](#php_spammers)|417|417|2|0.4%|0.0%|
[malc0de](#malc0de)|410|410|2|0.4%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|2|0.2%|0.0%|
[et_tor](#et_tor)|6470|6470|2|0.0%|0.0%|
[dm_tor](#dm_tor)|6479|6479|2|0.0%|0.0%|
[bm_tor](#bm_tor)|6474|6474|2|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.0%|
[et_botcc](#et_botcc)|501|501|1|0.1%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|85|85|1|1.1%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|373|373|1|0.2%|0.0%|

## spamhaus_edrop

[Spamhaus.org](http://www.spamhaus.org) EDROP (extended matches that should be used with DROP) - **excellent list**

Source is downloaded from [this link](http://www.spamhaus.org/drop/edrop.txt).

The last time downloaded was found to be dated: Fri May 22 19:52:08 UTC 2015.

The ipset `spamhaus_edrop` has **55** entries, **421120** unique IPs.

The following table shows the overlaps of `spamhaus_edrop` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `spamhaus_edrop`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `spamhaus_edrop`.
- ` this % ` is the percentage **of this ipset (`spamhaus_edrop`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|270785|0.1%|64.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|33368|0.0%|7.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|33155|0.0%|7.8%|
[et_block](#et_block)|986|18056524|517|0.0%|0.1%|
[spamhaus_drop](#spamhaus_drop)|640|17925376|512|0.0%|0.1%|
[stopforumspam_30d](#stopforumspam_30d)|92359|92359|106|0.1%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|30993|30993|45|0.1%|0.0%|
[blocklist_de](#blocklist_de)|21611|21611|19|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3420|3420|15|0.4%|0.0%|
[alienvault_reputation](#alienvault_reputation)|174737|174737|15|0.0%|0.0%|
[openbl_90d](#openbl_90d)|9797|9797|14|0.1%|0.0%|
[openbl](#openbl)|9797|9797|14|0.1%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6841|6841|9|0.1%|0.0%|
[php_commenters](#php_commenters)|281|281|7|2.4%|0.0%|
[php_bad](#php_bad)|281|281|7|2.4%|0.0%|
[snort_ipfilter](#snort_ipfilter)|5712|5712|6|0.1%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|194|194|6|3.0%|0.0%|
[zeus_badips](#zeus_badips)|229|229|5|2.1%|0.0%|
[zeus](#zeus)|267|267|5|1.8%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14463|14463|2|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|12527|12527|2|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.0%|
[openbl_60d](#openbl_60d)|7680|7680|1|0.0%|0.0%|
[openbl_30d](#openbl_30d)|3339|3339|1|0.0%|0.0%|
[malc0de](#malc0de)|410|410|1|0.2%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.0%|

## sslbl

[Abuse.ch SSL Blacklist](https://sslbl.abuse.ch/) bad SSL traffic related to malware or botnet activities - **excellent list**

Source is downloaded from [this link](https://sslbl.abuse.ch/blacklist/sslipblacklist.csv).

The last time downloaded was found to be dated: Sat May 30 11:15:06 UTC 2015.

The ipset `sslbl` has **349** entries, **349** unique IPs.

The following table shows the overlaps of `sslbl` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `sslbl`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `sslbl`.
- ` this % ` is the percentage **of this ipset (`sslbl`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[et_block](#et_block)|986|18056524|27|0.0%|7.7%|
[feodo](#feodo)|70|70|26|37.1%|7.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|23|0.0%|6.5%|
[snort_ipfilter](#snort_ipfilter)|5712|5712|21|0.3%|6.0%|
[alienvault_reputation](#alienvault_reputation)|174737|174737|11|0.0%|3.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|6|0.0%|1.7%|
[shunlist](#shunlist)|1180|1180|4|0.3%|1.1%|
[spamhaus_drop](#spamhaus_drop)|640|17925376|3|0.0%|0.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|3|0.0%|0.8%|
[stopforumspam_30d](#stopforumspam_30d)|92359|92359|1|0.0%|0.2%|
[openbl_90d](#openbl_90d)|9797|9797|1|0.0%|0.2%|
[openbl](#openbl)|9797|9797|1|0.0%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.2%|

## stopforumspam_1d

[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers in the last 24 hours - **excellent list**

Source is downloaded from [this link](http://www.stopforumspam.com/downloads/listed_ip_1.zip).

The last time downloaded was found to be dated: Sat May 30 11:00:02 UTC 2015.

The ipset `stopforumspam_1d` has **6841** entries, **6841** unique IPs.

The following table shows the overlaps of `stopforumspam_1d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `stopforumspam_1d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `stopforumspam_1d`.
- ` this % ` is the percentage **of this ipset (`stopforumspam_1d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_7d](#stopforumspam_7d)|30993|30993|5625|18.1%|82.2%|
[stopforumspam_30d](#stopforumspam_30d)|92359|92359|5624|6.0%|82.2%|
[blocklist_de](#blocklist_de)|21611|21611|1563|7.2%|22.8%|
[blocklist_de_bots](#blocklist_de_bots)|3420|3420|1491|43.5%|21.7%|
[ri_web_proxies](#ri_web_proxies)|4837|4837|458|9.4%|6.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|443|0.0%|6.4%|
[proxyrss](#proxyrss)|1548|1548|389|25.1%|5.6%|
[xroxy](#xroxy)|1963|1963|373|19.0%|5.4%|
[snort_ipfilter](#snort_ipfilter)|5712|5712|358|6.2%|5.2%|
[et_tor](#et_tor)|6470|6470|330|5.1%|4.8%|
[dm_tor](#dm_tor)|6479|6479|330|5.0%|4.8%|
[bm_tor](#bm_tor)|6474|6474|328|5.0%|4.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|238|0.0%|3.4%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|166|44.6%|2.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|142|0.0%|2.0%|
[ri_connect_proxies](#ri_connect_proxies)|1842|1842|137|7.4%|2.0%|
[php_commenters](#php_commenters)|281|281|103|36.6%|1.5%|
[php_bad](#php_bad)|281|281|103|36.6%|1.5%|
[blocklist_de_strongips](#blocklist_de_strongips)|194|194|98|50.5%|1.4%|
[blocklist_de_apache](#blocklist_de_apache)|12527|12527|75|0.5%|1.0%|
[nixspam](#nixspam)|22785|22785|61|0.2%|0.8%|
[alienvault_reputation](#alienvault_reputation)|174737|174737|60|0.0%|0.8%|
[proxz](#proxz)|236|236|59|25.0%|0.8%|
[spamhaus_drop](#spamhaus_drop)|640|17925376|45|0.0%|0.6%|
[et_block](#et_block)|986|18056524|45|0.0%|0.6%|
[blocklist_de_mail](#blocklist_de_mail)|14463|14463|45|0.3%|0.6%|
[php_harvesters](#php_harvesters)|257|257|34|13.2%|0.4%|
[php_spammers](#php_spammers)|417|417|29|6.9%|0.4%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1201|1201|29|2.4%|0.4%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|27|0.0%|0.3%|
[php_dictionary](#php_dictionary)|433|433|24|5.5%|0.3%|
[openbl_90d](#openbl_90d)|9797|9797|21|0.2%|0.3%|
[openbl](#openbl)|9797|9797|21|0.2%|0.3%|
[openbl_60d](#openbl_60d)|7680|7680|20|0.2%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|10|0.0%|0.1%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|9|0.0%|0.1%|
[voipbl](#voipbl)|10305|10714|3|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|3|0.4%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|373|373|2|0.5%|0.0%|
[zeus_badips](#zeus_badips)|229|229|1|0.4%|0.0%|
[zeus](#zeus)|267|267|1|0.3%|0.0%|
[shunlist](#shunlist)|1180|1180|1|0.0%|0.0%|
[openbl_30d](#openbl_30d)|3339|3339|1|0.0%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1282|1282|1|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1|0.0%|0.0%|
[et_compromised](#et_compromised)|2367|2367|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2254|2254|1|0.0%|0.0%|

## stopforumspam_30d

[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 30 days)

Source is downloaded from [this link](http://www.stopforumspam.com/downloads/listed_ip_30.zip).

The last time downloaded was found to be dated: Sat May 30 00:00:54 UTC 2015.

The ipset `stopforumspam_30d` has **92359** entries, **92359** unique IPs.

The following table shows the overlaps of `stopforumspam_30d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `stopforumspam_30d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `stopforumspam_30d`.
- ` this % ` is the percentage **of this ipset (`stopforumspam_30d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_7d](#stopforumspam_7d)|30993|30993|30826|99.4%|33.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|5991|0.0%|6.4%|
[stopforumspam_1d](#stopforumspam_1d)|6841|6841|5624|82.2%|6.0%|
[blocklist_de](#blocklist_de)|21611|21611|2704|12.5%|2.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|2449|0.0%|2.6%|
[ri_web_proxies](#ri_web_proxies)|4837|4837|2413|49.8%|2.6%|
[blocklist_de_bots](#blocklist_de_bots)|3420|3420|2397|70.0%|2.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|1522|0.0%|1.6%|
[xroxy](#xroxy)|1963|1963|1135|57.8%|1.2%|
[ri_connect_proxies](#ri_connect_proxies)|1842|1842|1087|59.0%|1.1%|
[proxyrss](#proxyrss)|1548|1548|858|55.4%|0.9%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|748|0.0%|0.8%|
[et_block](#et_block)|986|18056524|746|0.0%|0.8%|
[spamhaus_drop](#spamhaus_drop)|640|17925376|744|0.0%|0.8%|
[snort_ipfilter](#snort_ipfilter)|5712|5712|732|12.8%|0.7%|
[et_tor](#et_tor)|6470|6470|614|9.4%|0.6%|
[dm_tor](#dm_tor)|6479|6479|588|9.0%|0.6%|
[bm_tor](#bm_tor)|6474|6474|586|9.0%|0.6%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|237|63.7%|0.2%|
[alienvault_reputation](#alienvault_reputation)|174737|174737|226|0.1%|0.2%|
[nixspam](#nixspam)|22785|22785|218|0.9%|0.2%|
[blocklist_de_apache](#blocklist_de_apache)|12527|12527|215|1.7%|0.2%|
[blocklist_de_mail](#blocklist_de_mail)|14463|14463|214|1.4%|0.2%|
[php_commenters](#php_commenters)|281|281|203|72.2%|0.2%|
[php_bad](#php_bad)|281|281|202|71.8%|0.2%|
[proxz](#proxz)|236|236|141|59.7%|0.1%|
[blocklist_de_strongips](#blocklist_de_strongips)|194|194|131|67.5%|0.1%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|106|0.0%|0.1%|
[php_spammers](#php_spammers)|417|417|97|23.2%|0.1%|
[php_dictionary](#php_dictionary)|433|433|81|18.7%|0.0%|
[openbl_90d](#openbl_90d)|9797|9797|63|0.6%|0.0%|
[openbl](#openbl)|9797|9797|63|0.6%|0.0%|
[php_harvesters](#php_harvesters)|257|257|62|24.1%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1201|1201|62|5.1%|0.0%|
[openbl_60d](#openbl_60d)|7680|7680|56|0.7%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|42|0.0%|0.0%|
[voipbl](#voipbl)|10305|10714|41|0.3%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|22|3.2%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|15|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|373|373|11|2.9%|0.0%|
[openbl_30d](#openbl_30d)|3339|3339|6|0.1%|0.0%|
[et_compromised](#et_compromised)|2367|2367|6|0.2%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2254|2254|6|0.2%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1834|1834|5|0.2%|0.0%|
[shunlist](#shunlist)|1180|1180|4|0.3%|0.0%|
[zeus_badips](#zeus_badips)|229|229|3|1.3%|0.0%|
[zeus](#zeus)|267|267|3|1.1%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1282|1282|3|0.2%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.0%|
[fullbogons](#fullbogons)|3642|670590424|2|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|777|777|2|0.2%|0.0%|
[sslbl](#sslbl)|349|349|1|0.2%|0.0%|
[dshield](#dshield)|20|5120|1|0.0%|0.0%|
[ciarmy](#ciarmy)|348|348|1|0.2%|0.0%|
[bogons](#bogons)|13|592708608|1|0.0%|0.0%|

## stopforumspam_7d

[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 7 days)

Source is downloaded from [this link](http://www.stopforumspam.com/downloads/listed_ip_7.zip).

The last time downloaded was found to be dated: Sat May 30 02:02:03 UTC 2015.

The ipset `stopforumspam_7d` has **30993** entries, **30993** unique IPs.

The following table shows the overlaps of `stopforumspam_7d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `stopforumspam_7d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `stopforumspam_7d`.
- ` this % ` is the percentage **of this ipset (`stopforumspam_7d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_30d](#stopforumspam_30d)|92359|92359|30826|33.3%|99.4%|
[stopforumspam_1d](#stopforumspam_1d)|6841|6841|5625|82.2%|18.1%|
[blocklist_de](#blocklist_de)|21611|21611|2369|10.9%|7.6%|
[blocklist_de_bots](#blocklist_de_bots)|3420|3420|2194|64.1%|7.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|2081|0.0%|6.7%|
[ri_web_proxies](#ri_web_proxies)|4837|4837|1689|34.9%|5.4%|
[xroxy](#xroxy)|1963|1963|976|49.7%|3.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|919|0.0%|2.9%|
[proxyrss](#proxyrss)|1548|1548|722|46.6%|2.3%|
[ri_connect_proxies](#ri_connect_proxies)|1842|1842|689|37.4%|2.2%|
[snort_ipfilter](#snort_ipfilter)|5712|5712|570|9.9%|1.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|563|0.0%|1.8%|
[et_tor](#et_tor)|6470|6470|485|7.4%|1.5%|
[dm_tor](#dm_tor)|6479|6479|468|7.2%|1.5%|
[bm_tor](#bm_tor)|6474|6474|466|7.1%|1.5%|
[spamhaus_drop](#spamhaus_drop)|640|17925376|208|0.0%|0.6%|
[et_block](#et_block)|986|18056524|208|0.0%|0.6%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|200|53.7%|0.6%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|196|0.0%|0.6%|
[php_commenters](#php_commenters)|281|281|181|64.4%|0.5%|
[php_bad](#php_bad)|281|281|180|64.0%|0.5%|
[nixspam](#nixspam)|22785|22785|131|0.5%|0.4%|
[blocklist_de_apache](#blocklist_de_apache)|12527|12527|129|1.0%|0.4%|
[proxz](#proxz)|236|236|127|53.8%|0.4%|
[blocklist_de_strongips](#blocklist_de_strongips)|194|194|120|61.8%|0.3%|
[alienvault_reputation](#alienvault_reputation)|174737|174737|114|0.0%|0.3%|
[blocklist_de_mail](#blocklist_de_mail)|14463|14463|107|0.7%|0.3%|
[php_spammers](#php_spammers)|417|417|66|15.8%|0.2%|
[php_dictionary](#php_dictionary)|433|433|64|14.7%|0.2%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1201|1201|54|4.4%|0.1%|
[php_harvesters](#php_harvesters)|257|257|47|18.2%|0.1%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|45|0.0%|0.1%|
[openbl_90d](#openbl_90d)|9797|9797|29|0.2%|0.0%|
[openbl](#openbl)|9797|9797|29|0.2%|0.0%|
[openbl_60d](#openbl_60d)|7680|7680|27|0.3%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|19|0.0%|0.0%|
[voipbl](#voipbl)|10305|10714|11|0.1%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|11|1.6%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|5|0.0%|0.0%|
[openbl_30d](#openbl_30d)|3339|3339|3|0.0%|0.0%|
[et_compromised](#et_compromised)|2367|2367|3|0.1%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2254|2254|3|0.1%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1834|1834|3|0.1%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|373|373|3|0.8%|0.0%|
[shunlist](#shunlist)|1180|1180|2|0.1%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1282|1282|2|0.1%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.0%|
[zeus_badips](#zeus_badips)|229|229|1|0.4%|0.0%|
[zeus](#zeus)|267|267|1|0.3%|0.0%|
[dshield](#dshield)|20|5120|1|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|777|777|1|0.1%|0.0%|

## voipbl

[VoIPBL.org](http://www.voipbl.org/) a distributed VoIP blacklist that is aimed to protects against VoIP Fraud and minimizing abuse for network that have publicly accessible PBX's. Several algorithms, external sources and manual confirmation are used before they categorize something as an attack and determine the threat level.

Source is downloaded from [this link](http://www.voipbl.org/update/).

The last time downloaded was found to be dated: Sat May 30 11:18:26 UTC 2015.

The ipset `voipbl` has **10305** entries, **10714** unique IPs.

The following table shows the overlaps of `voipbl` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `voipbl`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `voipbl`.
- ` this % ` is the percentage **of this ipset (`voipbl`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|1586|0.0%|14.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|429|0.0%|4.0%|
[fullbogons](#fullbogons)|3642|670590424|319|0.0%|2.9%|
[bogons](#bogons)|13|592708608|319|0.0%|2.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|295|0.0%|2.7%|
[alienvault_reputation](#alienvault_reputation)|174737|174737|208|0.1%|1.9%|
[stopforumspam_30d](#stopforumspam_30d)|92359|92359|41|0.0%|0.3%|
[blocklist_de](#blocklist_de)|21611|21611|37|0.1%|0.3%|
[blocklist_de_sip](#blocklist_de_sip)|85|85|28|32.9%|0.2%|
[et_block](#et_block)|986|18056524|17|0.0%|0.1%|
[spamhaus_drop](#spamhaus_drop)|640|17925376|14|0.0%|0.1%|
[shunlist](#shunlist)|1180|1180|12|1.0%|0.1%|
[stopforumspam_7d](#stopforumspam_7d)|30993|30993|11|0.0%|0.1%|
[openbl_90d](#openbl_90d)|9797|9797|11|0.1%|0.1%|
[openbl](#openbl)|9797|9797|11|0.1%|0.1%|
[openbl_60d](#openbl_60d)|7680|7680|9|0.1%|0.0%|
[openbl_30d](#openbl_30d)|3339|3339|4|0.1%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|4|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6841|6841|3|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1834|1834|3|0.1%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14463|14463|3|0.0%|0.0%|
[openbl_7d](#openbl_7d)|949|949|2|0.2%|0.0%|
[nixspam](#nixspam)|22785|22785|2|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|2|0.0%|0.0%|
[dshield](#dshield)|20|5120|2|0.0%|0.0%|
[ciarmy](#ciarmy)|348|348|2|0.5%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|12527|12527|2|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.0%|
[et_tor](#et_tor)|6470|6470|1|0.0%|0.0%|
[et_compromised](#et_compromised)|2367|2367|1|0.0%|0.0%|
[dm_tor](#dm_tor)|6479|6479|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2254|2254|1|0.0%|0.0%|
[bm_tor](#bm_tor)|6474|6474|1|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1201|1201|1|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3420|3420|1|0.0%|0.0%|

## xroxy

[xroxy.com](http://www.xroxy.com) open proxies (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.xroxy.com/proxyrss.xml).

The last time downloaded was found to be dated: Sat May 30 11:33:01 UTC 2015.

The ipset `xroxy` has **1963** entries, **1963** unique IPs.

The following table shows the overlaps of `xroxy` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `xroxy`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `xroxy`.
- ` this % ` is the percentage **of this ipset (`xroxy`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_30d](#stopforumspam_30d)|92359|92359|1135|1.2%|57.8%|
[stopforumspam_7d](#stopforumspam_7d)|30993|30993|976|3.1%|49.7%|
[ri_web_proxies](#ri_web_proxies)|4837|4837|769|15.8%|39.1%|
[proxyrss](#proxyrss)|1548|1548|549|35.4%|27.9%|
[stopforumspam_1d](#stopforumspam_1d)|6841|6841|373|5.4%|19.0%|
[blocklist_de](#blocklist_de)|21611|21611|304|1.4%|15.4%|
[ri_connect_proxies](#ri_connect_proxies)|1842|1842|295|16.0%|15.0%|
[blocklist_de_bots](#blocklist_de_bots)|3420|3420|261|7.6%|13.2%|
[proxz](#proxz)|236|236|140|59.3%|7.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|93|0.0%|4.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|79|0.0%|4.0%|
[nixspam](#nixspam)|22785|22785|70|0.3%|3.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|54|0.0%|2.7%|
[blocklist_de_mail](#blocklist_de_mail)|14463|14463|42|0.2%|2.1%|
[snort_ipfilter](#snort_ipfilter)|5712|5712|34|0.5%|1.7%|
[php_dictionary](#php_dictionary)|433|433|24|5.5%|1.2%|
[php_spammers](#php_spammers)|417|417|18|4.3%|0.9%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|13|1.9%|0.6%|
[blocklist_de_strongips](#blocklist_de_strongips)|194|194|6|3.0%|0.3%|
[alienvault_reputation](#alienvault_reputation)|174737|174737|5|0.0%|0.2%|
[php_commenters](#php_commenters)|281|281|3|1.0%|0.1%|
[php_bad](#php_bad)|281|281|3|1.0%|0.1%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|3|0.0%|0.1%|
[php_harvesters](#php_harvesters)|257|257|2|0.7%|0.1%|
[et_tor](#et_tor)|6470|6470|2|0.0%|0.1%|
[dm_tor](#dm_tor)|6479|6479|2|0.0%|0.1%|
[bm_tor](#bm_tor)|6474|6474|2|0.0%|0.1%|
[openbl_90d](#openbl_90d)|9797|9797|1|0.0%|0.0%|
[openbl](#openbl)|9797|9797|1|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.0%|
[et_compromised](#et_compromised)|2367|2367|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2254|2254|1|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1834|1834|1|0.0%|0.0%|

## zeus

[Abuse.ch Zeus tracker](https://zeustracker.abuse.ch) standard, contains the same data as the ZeuS IP blocklist (zeus_badips) but with the slight difference that it doesn't exclude hijacked websites (level 2) and free web hosting providers (level 3). This means that this blocklist contains all IPv4 addresses associated with ZeuS C&Cs which are currently being tracked by ZeuS Tracker. Hence this blocklist will likely cause some false positives. - **excellent list**

Source is downloaded from [this link](https://zeustracker.abuse.ch/blocklist.php?download=ipblocklist).

The last time downloaded was found to be dated: Sat May 30 11:26:13 UTC 2015.

The ipset `zeus` has **267** entries, **267** unique IPs.

The following table shows the overlaps of `zeus` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `zeus`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `zeus`.
- ` this % ` is the percentage **of this ipset (`zeus`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[et_block](#et_block)|986|18056524|260|0.0%|97.3%|
[zeus_badips](#zeus_badips)|229|229|229|100.0%|85.7%|
[snort_ipfilter](#snort_ipfilter)|5712|5712|222|3.8%|83.1%|
[alienvault_reputation](#alienvault_reputation)|174737|174737|65|0.0%|24.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|19|0.0%|7.1%|
[spamhaus_drop](#spamhaus_drop)|640|17925376|16|0.0%|5.9%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|10|0.0%|3.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|9|0.0%|3.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|9|0.0%|3.3%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|5|0.0%|1.8%|
[stopforumspam_30d](#stopforumspam_30d)|92359|92359|3|0.0%|1.1%|
[openbl_90d](#openbl_90d)|9797|9797|2|0.0%|0.7%|
[openbl_60d](#openbl_60d)|7680|7680|2|0.0%|0.7%|
[openbl_30d](#openbl_30d)|3339|3339|2|0.0%|0.7%|
[openbl](#openbl)|9797|9797|2|0.0%|0.7%|
[stopforumspam_7d](#stopforumspam_7d)|30993|30993|1|0.0%|0.3%|
[stopforumspam_1d](#stopforumspam_1d)|6841|6841|1|0.0%|0.3%|
[php_commenters](#php_commenters)|281|281|1|0.3%|0.3%|
[php_bad](#php_bad)|281|281|1|0.3%|0.3%|
[openbl_7d](#openbl_7d)|949|949|1|0.1%|0.3%|
[nixspam](#nixspam)|22785|22785|1|0.0%|0.3%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.3%|
[et_compromised](#et_compromised)|2367|2367|1|0.0%|0.3%|
[cleanmx_viruses](#cleanmx_viruses)|259|259|1|0.3%|0.3%|
[bruteforceblocker](#bruteforceblocker)|2254|2254|1|0.0%|0.3%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1201|1201|1|0.0%|0.3%|
[blocklist_de_apache](#blocklist_de_apache)|12527|12527|1|0.0%|0.3%|
[blocklist_de](#blocklist_de)|21611|21611|1|0.0%|0.3%|

## zeus_badips

[Abuse.ch Zeus tracker](https://zeustracker.abuse.ch) badips includes IPv4 addresses that are used by the ZeuS trojan. It is the recommened blocklist if you want to block only ZeuS IPs. It excludes IP addresses that ZeuS Tracker believes to be hijacked (level 2) or belong to a free web hosting provider (level 3). Hence the false postive rate should be much lower compared to the standard ZeuS IP blocklist. **excellent list**

Source is downloaded from [this link](https://zeustracker.abuse.ch/blocklist.php?download=badips).

The last time downloaded was found to be dated: Sat May 30 11:36:23 UTC 2015.

The ipset `zeus_badips` has **229** entries, **229** unique IPs.

The following table shows the overlaps of `zeus_badips` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `zeus_badips`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `zeus_badips`.
- ` this % ` is the percentage **of this ipset (`zeus_badips`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[zeus](#zeus)|267|267|229|85.7%|100.0%|
[et_block](#et_block)|986|18056524|228|0.0%|99.5%|
[snort_ipfilter](#snort_ipfilter)|5712|5712|199|3.4%|86.8%|
[alienvault_reputation](#alienvault_reputation)|174737|174737|37|0.0%|16.1%|
[spamhaus_drop](#spamhaus_drop)|640|17925376|16|0.0%|6.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|14|0.0%|6.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|10|0.0%|4.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|8|0.0%|3.4%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|5|0.0%|2.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|4|0.0%|1.7%|
[stopforumspam_30d](#stopforumspam_30d)|92359|92359|3|0.0%|1.3%|
[stopforumspam_7d](#stopforumspam_7d)|30993|30993|1|0.0%|0.4%|
[stopforumspam_1d](#stopforumspam_1d)|6841|6841|1|0.0%|0.4%|
[php_commenters](#php_commenters)|281|281|1|0.3%|0.4%|
[php_bad](#php_bad)|281|281|1|0.3%|0.4%|
[openbl_90d](#openbl_90d)|9797|9797|1|0.0%|0.4%|
[openbl_60d](#openbl_60d)|7680|7680|1|0.0%|0.4%|
[openbl_30d](#openbl_30d)|3339|3339|1|0.0%|0.4%|
[openbl](#openbl)|9797|9797|1|0.0%|0.4%|
[nixspam](#nixspam)|22785|22785|1|0.0%|0.4%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.4%|
[et_compromised](#et_compromised)|2367|2367|1|0.0%|0.4%|
[cleanmx_viruses](#cleanmx_viruses)|259|259|1|0.3%|0.4%|
[bruteforceblocker](#bruteforceblocker)|2254|2254|1|0.0%|0.4%|
