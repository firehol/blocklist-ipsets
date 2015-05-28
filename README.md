### Contents

- [About this repo](#about-this-repo)

- [Using these ipsets](#using-these-ipsets)
 - [Which ones to use?](#which-ones-to-use)
   
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

To get an idea, check for example the [XRumer](http://en.wikipedia.org/wiki/XRumer) software. This think mimics human
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

1. **Abuse.ch** lists `feodo`, `palevo`, `sslbl`, `zeus`
   
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
   
   The team of OpenBL tracks brute force attacks on their hosts. They suggest to use the default blacklist which has a retension policy of 90 days (`openbl`), but they also provide a list with retension of 1 day (`openbl_1d`).
   Their goal is to report abuse to the responsible provider so that the infection is disabled.

6. **Blocklist.de** lists `blocklist_de*`
   
   Is a network of users reporting abuse mainly using `fail2ban`.
   Their goal is also to report abuse back, so that the infection is disabled.
   The list includes IPs that were participating in attacks in the last 48 hours.

Of course there are more lists included. You can check them and decide if they fit for your needs.


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
	for x in fullbogons dshield spamhaus_drop spamhaus_edrop voipbl
	do
		ipset4 create  ${x} hash:net
		ipset4 addfile ${x} ipsets/${x}.netset
		blacklist4 full inface "${wan}" log "BLACKLIST ${x^^}" ipset:${x} \
			except src ipset:whitelist
	done

	# individual IPs - ipsets
	for x in feodo palevo sslbl zeus openbl blocklist_de \
		shunlist malc0de ciarmy malwaredomainlist \
		snort_ipfilter stop_forum_spam_1h stop_forum_spam_7d \
		bruteforceblocker ri_connect_proxies ri_web_proxies
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

The following list was automatically generated on Thu May 28 09:45:33 UTC 2015.

The update frequency is the maximum allowed by internal configuration. A list will never be downloaded sooner than the update frequency stated. A list may also not be downloaded, after this frequency expired, if it has not been modified on the server (as reported by HTTP `IF_MODIFIED_SINCE` method).

name|info|type|entries|update|
:--:|:--:|:--:|:-----:|:----:|
[alienvault_reputation](#alienvault_reputation)|[AlienVault.com](https://www.alienvault.com/) IP reputation database (this list seems to include port scanning hosts and to be updated regularly, but we found no information about its retention policy)|ipv4 hash:ip|177044 unique IPs|updated every 6 hours  from [this link](https://reputation.alienvault.com/reputation.generic)
[blocklist_de](#blocklist_de)|[Blocklist.de](https://www.blocklist.de/) IPs that have been detected by fail2ban in the last 48 hours - **excellent list**|ipv4 hash:ip|22392 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/all.txt)
[blocklist_de_apache](#blocklist_de_apache)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service Apache, Apache-DDOS, RFI-Attacks.|ipv4 hash:ip|12673 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/apache.txt)
[blocklist_de_bots](#blocklist_de_bots)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the RFI-Attacks, REG-Bots, IRC-Bots or BadBots (BadBots = he has posted a Spam-Comment on a open Forum or Wiki).|ipv4 hash:ip|3467 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/bots.txt)
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|[Blocklist.de](https://www.blocklist.de/) All IPs which attacks Joomlas, Wordpress and other Web-Logins with Brute-Force Logins.|ipv4 hash:ip|1350 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/bruteforcelogin.txt)
[blocklist_de_ftp](#blocklist_de_ftp)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours for attacks on the Service FTP.|ipv4 hash:ip|239 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/ftp.txt)
[blocklist_de_imap](#blocklist_de_imap)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours for attacks on the Service imap, sasl, pop3, etc.|ipv4 hash:ip|683 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/imap.txt)
[blocklist_de_mail](#blocklist_de_mail)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service Mail, Postfix.|ipv4 hash:ip|14733 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/mail.txt)
[blocklist_de_sip](#blocklist_de_sip)|[Blocklist.de](https://www.blocklist.de/) All IP addresses that tried to login in a SIP, VOIP or Asterisk Server and are included in the IPs list from [infiltrated.net](www.infiltrated.net)|ipv4 hash:ip|103 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/sip.txt)
[blocklist_de_ssh](#blocklist_de_ssh)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service SSH.|ipv4 hash:ip|2276 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/ssh.txt)
[blocklist_de_strongips](#blocklist_de_strongips)|[Blocklist.de](https://www.blocklist.de/) All IPs which are older then 2 month and have more then 5.000 attacks.|ipv4 hash:ip|225 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/strongips.txt)
[bm_tor](#bm_tor)|[torstatus.blutmagie.de](https://torstatus.blutmagie.de) list of all TOR network servers|ipv4 hash:ip|6436 unique IPs|updated every 30 mins  from [this link](https://torstatus.blutmagie.de/ip_list_all.php/Tor_ip_list_ALL.csv)
[bogons](#bogons)|[Team-Cymru.org](http://www.team-cymru.org) private and reserved addresses defined by RFC 1918, RFC 5735, and RFC 6598 and netblocks that have not been allocated to a regional internet registry - **excellent list - use it only your internet interface**|ipv4 hash:net|13 subnets, 592708608 unique IPs|updated every 1 day  from [this link](http://www.team-cymru.org/Services/Bogons/bogon-bn-agg.txt)
[bruteforceblocker](#bruteforceblocker)|[danger.rulez.sk](http://danger.rulez.sk/) IPs detected by [bruteforceblocker](http://danger.rulez.sk/index.php/bruteforceblocker/) (fail2ban alternative for SSH on OpenBSD)|ipv4 hash:ip|2415 unique IPs|updated every 3 hours  from [this link](http://danger.rulez.sk/projects/bruteforceblocker/blist.php)
[ciarmy](#ciarmy)|[CIArmy.com](http://ciarmy.com/) IPs with poor Rogue Packet score that have not yet been identified as malicious by the community|ipv4 hash:ip|394 unique IPs|updated every 3 hours  from [this link](http://cinsscore.com/list/ci-badguys.txt)
[clean_mx_viruses](#clean_mx_viruses)|[Clean-MX.de](http://support.clean-mx.de/clean-mx/viruses.php) IPs with viruses|ipv4 hash:ip|104 unique IPs|updated every 12 hours  from [this link](http://support.clean-mx.de/clean-mx/xmlviruses.php?sort=id%20desc&response=alive)
[dm_tor](#dm_tor)|[dan.me.uk](https://www.dan.me.uk) dynamic list of TOR exit points|ipv4 hash:ip|6438 unique IPs|updated every 30 mins  from [this link](https://www.dan.me.uk/torlist/)
[dshield](#dshield)|[DShield.org](https://dshield.org/) top 20 attacking class C (/24) subnets over the last three days - **excellent list**|ipv4 hash:net|20 subnets, 5120 unique IPs|updated every 4 hours  from [this link](http://feeds.dshield.org/block.txt)
[et_block](#et_block)|[EmergingThreats.net](http://www.emergingthreats.net/) default blacklist (at the time of writing includes spamhaus DROP, dshield and abuse.ch trackers, which are available separately too - prefer to use the direct ipsets instead of this, they seem to lag a bit in updates)|ipv4 hash:net|975 subnets, 18056513 unique IPs|updated every 12 hours  from [this link](http://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt)
[et_botnet](#et_botnet)|[EmergingThreats.net](http://www.emergingthreats.net/) botnet IPs|ipv4 hash:ip|512 unique IPs|updated every 12 hours  from [this link](http://rules.emergingthreats.net/fwrules/emerging-PIX-CC.rules)
[et_compromised](#et_compromised)|[EmergingThreats.net](http://www.emergingthreats.net/) compromised hosts (seems to be a derivate of other lists)|ipv4 hash:ip|2338 unique IPs|updated every 12 hours  from [this link](http://rules.emergingthreats.net/blockrules/compromised-ips.txt)
[et_tor](#et_tor)|[EmergingThreats.net](http://www.emergingthreats.net/) [list](http://doc.emergingthreats.net/bin/view/Main/TorRules) of TOR network IPs|ipv4 hash:ip|6490 unique IPs|updated every 12 hours  from [this link](http://rules.emergingthreats.net/blockrules/emerging-tor.rules)
[feodo](#feodo)|[Abuse.ch Feodo tracker](https://feodotracker.abuse.ch) trojan includes IPs which are being used by Feodo (also known as Cridex or Bugat) which commits ebanking fraud - **excellent list**|ipv4 hash:ip|63 unique IPs|updated every 30 mins  from [this link](https://feodotracker.abuse.ch/blocklist/?download=ipblocklist)
[fullbogons](#fullbogons)|[Team-Cymru.org](http://www.team-cymru.org) IP space that has been allocated to an RIR, but not assigned by that RIR to an actual ISP or other end-user - **excellent list - use it only your internet interface**|ipv4 hash:net|3656 subnets, 670735064 unique IPs|updated every 1 day  from [this link](http://www.team-cymru.org/Services/Bogons/fullbogons-ipv4.txt)
[geolite2_country](tree/master/geolite2_country)|[MaxMind GeoLite2](http://dev.maxmind.com/geoip/geoip2/geolite2/) databases are free IP geolocation databases comparable to, but less accurate than, MaxMind’s GeoIP2 databases. They include IPs per country, IPs per continent, IPs used by anonymous services (VPNs, Proxies, etc) and Satellite Providers.|ipv4 hash:net|All the world|updated every 7 days  from [this link](http://geolite.maxmind.com/download/geoip/database/GeoLite2-Country-CSV.zip)
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|[iBlocklist.com](https://www.iblocklist.com/) free version of [BlueTack.co.uk](http://www.bluetack.co.uk/) IPs that have been reported for bad deeds in p2p|ipv4 hash:ip|48134 unique IPs|updated every 12 hours  from [this link](http://list.iblocklist.com/?list=cwworuawihqvocglcoss&fileformat=p2p&archiveformat=gz)
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|[iBlocklist.com](https://www.iblocklist.com/) free version of [BlueTack.co.uk](http://www.bluetack.co.uk/) hijacked IP-Blocks Hijacked IP space are IP blocks that are being used without permission|ipv4 hash:net|535 subnets, 9177856 unique IPs|updated every 12 hours  from [this link](http://list.iblocklist.com/?list=usrcshglbiilevmyfhse&fileformat=p2p&archiveformat=gz)
[ib_bluetack_level1](#ib_bluetack_level1)|[iBlocklist.com](https://www.iblocklist.com/) free version of [BlueTack.co.uk](http://www.bluetack.co.uk/) Level 1 (for use in p2p): Companies or organizations who are clearly involved with trying to stop filesharing (e.g. Baytsp, MediaDefender, Mediasentry a.o.). Companies which anti-p2p activity has been seen from. Companies that produce or have a strong financial interest in copyrighted material (e.g. music, movie, software industries a.o.). Government ranges or companies that have a strong financial interest in doing work for governments. Legal industry ranges. IPs or ranges of ISPs from which anti-p2p activity has been observed. Basically this list will block all kinds of internet connections that most people would rather not have during their internet travels.|ipv4 hash:net|236319 subnets, 765065682 unique IPs|updated every 12 hours  from [this link](http://list.iblocklist.com/?list=ydxerpxkpcfqjaybcssw&fileformat=p2p&archiveformat=gz)
[ib_bluetack_level2](#ib_bluetack_level2)|[iBlocklist.com](https://www.iblocklist.com/) free version of BlueTack.co.uk Level 2 (for use in p2p). General corporate ranges. Ranges used by labs or researchers. Proxies.|ipv4 hash:net|78389 subnets, 348732007 unique IPs|updated every 12 hours  from [this link](http://list.iblocklist.com/?list=gyisgnzbhppbvsphucsw&fileformat=p2p&archiveformat=gz)
[ib_bluetack_level3](#ib_bluetack_level3)|[iBlocklist.com](https://www.iblocklist.com/) free version of BlueTack.co.uk Level 3 (for use in p2p). Many portal-type websites. ISP ranges that may be dodgy for some reason. Ranges that belong to an individual, but which have not been determined to be used by a particular company. Ranges for things that are unusual in some way. The L3 list is aka the paranoid list.|ipv4 hash:net|18879 subnets, 139109195 unique IPs|updated every 12 hours  from [this link](http://list.iblocklist.com/?list=uwnukjqktoggdknzrhgh&fileformat=p2p&archiveformat=gz)
[ib_bluetack_proxies](#ib_bluetack_proxies)|[iBlocklist.com](https://www.iblocklist.com/) free version of [BlueTack.co.uk](http://www.bluetack.co.uk/) Open Proxies IPs list (without TOR)|ipv4 hash:ip|673 unique IPs|updated every 12 hours  from [this link](http://list.iblocklist.com/?list=xoebmbyexwuiogmbyprb&fileformat=p2p&archiveformat=gz)
[ib_bluetack_spyware](#ib_bluetack_spyware)|[iBlocklist.com](https://www.iblocklist.com/) free version of [BlueTack.co.uk](http://www.bluetack.co.uk/) known malicious SPYWARE and ADWARE IP Address ranges|ipv4 hash:net|3339 subnets, 339461 unique IPs|updated every 12 hours  from [this link](http://list.iblocklist.com/?list=llvtlsjyoyiczbkjsxpf&fileformat=p2p&archiveformat=gz)
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|[iBlocklist.com](https://www.iblocklist.com/) free version of [BlueTack.co.uk](http://www.bluetack.co.uk/) web server hack and exploit attempts|ipv4 hash:ip|1460 unique IPs|updated every 12 hours  from [this link](http://list.iblocklist.com/?list=ghlzqtqxnzctvvajwwag&fileformat=p2p&archiveformat=gz)
[malc0de](#malc0de)|[Malc0de.com](http://malc0de.com) malicious IPs of the last 30 days|ipv4 hash:ip|414 unique IPs|updated every 1 day  from [this link](http://malc0de.com/bl/IP_Blacklist.txt)
[malwaredomainlist](#malwaredomainlist)|[malwaredomainlist.com](http://www.malwaredomainlist.com) list of malware active ip addresses|ipv4 hash:ip|1283 unique IPs|updated every 12 hours  from [this link](http://www.malwaredomainlist.com/hostslist/ip.txt)
[nixspam](#nixspam)|[NiX Spam](http://www.heise.de/ix/NiX-Spam-DNSBL-and-blacklist-for-download-499637.html) IP addresses that sent spam in the last hour - automatically generated entries without distinguishing open proxies from relays, dialup gateways, and so on. All IPs are removed after 12 hours if there is no spam from there.|ipv4 hash:ip|26013 unique IPs|updated every 15 mins  from [this link](http://www.dnsbl.manitu.net/download/nixspam-ip.dump.gz)
[openbl](#openbl)|[OpenBL.org](http://www.openbl.org/) default blacklist (currently it is the same with 90 days). OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications - **excellent list**|ipv4 hash:ip|9897 unique IPs|updated every 4 hours  from [this link](http://www.openbl.org/lists/base.txt.gz)
[openbl_1d](#openbl_1d)|[OpenBL.org](http://www.openbl.org/) last 24 hours IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|357 unique IPs|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_1days.txt.gz)
[openbl_30d](#openbl_30d)|[OpenBL.org](http://www.openbl.org/) last 30 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|4449 unique IPs|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_30days.txt.gz)
[openbl_60d](#openbl_60d)|[OpenBL.org](http://www.openbl.org/) last 60 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|7801 unique IPs|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_60days.txt.gz)
[openbl_7d](#openbl_7d)|[OpenBL.org](http://www.openbl.org/) last 7 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|997 unique IPs|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_7days.txt.gz)
[openbl_90d](#openbl_90d)|[OpenBL.org](http://www.openbl.org/) last 90 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|9897 unique IPs|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_90days.txt.gz)
[palevo](#palevo)|[Abuse.ch Palevo tracker](https://palevotracker.abuse.ch) worm includes IPs which are being used as botnet C&C for the Palevo crimeware - **excellent list**|ipv4 hash:ip|13 unique IPs|updated every 30 mins  from [this link](https://palevotracker.abuse.ch/blocklists.php?download=ipblocklist)
[php_bad](#php_bad)|[projecthoneypot.org](http://www.projecthoneypot.org/) bad web hosts (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|281 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=b&rss=1)
[php_commenters](#php_commenters)|[projecthoneypot.org](http://www.projecthoneypot.org/) comment spammers (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|281 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=c&rss=1)
[php_dictionary](#php_dictionary)|[projecthoneypot.org](http://www.projecthoneypot.org/) directory attackers (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|398 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=d&rss=1)
[php_harvesters](#php_harvesters)|[projecthoneypot.org](http://www.projecthoneypot.org/) harvesters (IPs that surf the internet looking for email addresses) (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|257 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=h&rss=1)
[php_spammers](#php_spammers)|[projecthoneypot.org](http://www.projecthoneypot.org/) spam servers (IPs used by spammers to send messages) (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|417 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=s&rss=1)
[ri_connect_proxies](#ri_connect_proxies)|[rosinstrument.com](http://www.rosinstrument.com) open CONNECT proxies (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|1668 unique IPs|updated every 1 hour  from [this link](http://tools.rosinstrument.com/proxy/plab100.xml)
[ri_web_proxies](#ri_web_proxies)|[rosinstrument.com](http://www.rosinstrument.com) open HTTP proxies (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|4267 unique IPs|updated every 1 hour  from [this link](http://tools.rosinstrument.com/proxy/l100.xml)
[shunlist](#shunlist)|[AutoShun.org](http://autoshun.org/) IPs identified as hostile by correlating logs from distributed snort installations running the autoshun plugin|ipv4 hash:ip|51 unique IPs|updated every 4 hours  from [this link](http://www.autoshun.org/files/shunlist.csv)
[snort_ipfilter](#snort_ipfilter)|[labs.snort.org](https://labs.snort.org/) supplied IP blacklist (this list seems to be updated frequently, but we found no information about it)|ipv4 hash:ip|7236 unique IPs|updated every 12 hours  from [this link](http://labs.snort.org/feeds/ip-filter.blf)
[spamhaus_drop](#spamhaus_drop)|[Spamhaus.org](http://www.spamhaus.org) DROP list (according to their site this list should be dropped at tier-1 ISPs globaly) - **excellent list**|ipv4 hash:net|641 subnets, 18117120 unique IPs|updated every 12 hours  from [this link](http://www.spamhaus.org/drop/drop.txt)
[spamhaus_edrop](#spamhaus_edrop)|[Spamhaus.org](http://www.spamhaus.org) EDROP (extended matches that should be used with DROP) - **excellent list**|ipv4 hash:net|55 subnets, 421120 unique IPs|updated every 12 hours  from [this link](http://www.spamhaus.org/drop/edrop.txt)
[sslbl](#sslbl)|[Abuse.ch SSL Blacklist](https://sslbl.abuse.ch/) bad SSL traffic related to malware or botnet activities - **excellent list**|ipv4 hash:ip|345 unique IPs|updated every 30 mins  from [this link](https://sslbl.abuse.ch/blacklist/sslipblacklist.csv)
[stop_forum_spam_1h](#stop_forum_spam_1h)|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers in the last 24 hours - **excellent list**|ipv4 hash:ip|7580 unique IPs|updated every 1 hour  from [this link](http://www.stopforumspam.com/downloads/listed_ip_1.zip)
[stop_forum_spam_30d](#stop_forum_spam_30d)|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 30 days)|ipv4 hash:ip|92800 unique IPs|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/listed_ip_30.zip)
[stop_forum_spam_7d](#stop_forum_spam_7d)|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 7 days)|ipv4 hash:ip|30710 unique IPs|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/listed_ip_7.zip)
[voipbl](#voipbl)|[VoIPBL.org](http://www.voipbl.org/) a distributed VoIP blacklist that is aimed to protects against VoIP Fraud and minimizing abuse for network that have publicly accessible PBX's. Several algorithms, external sources and manual confirmation are used before they categorize something as an attack and determine the threat level.|ipv4 hash:net|10286 subnets, 10757 unique IPs|updated every 4 hours  from [this link](http://www.voipbl.org/update/)
[zeus](#zeus)|[Abuse.ch Zeus tracker](https://zeustracker.abuse.ch) default blocklist including hijacked sites and web hosting providers - **excellent list**|ipv4 hash:ip|266 unique IPs|updated every 30 mins  from [this link](https://zeustracker.abuse.ch/blocklist.php?download=ipblocklist)
[zeus_badips](#zeus_badips)|[Abuse.ch Zeus tracker](https://zeustracker.abuse.ch) includes IPv4 addresses that are used by the ZeuS trojan|ipv4 hash:ip|229 unique IPs|updated every 30 mins  from [this link](https://zeustracker.abuse.ch/blocklist.php?download=badips)

# Comparison of ipsets

Below we compare each ipset against all other.


## alienvault_reputation

[AlienVault.com](https://www.alienvault.com/) IP reputation database (this list seems to include port scanning hosts and to be updated regularly, but we found no information about its retention policy)

Source is downloaded from [this link](https://reputation.alienvault.com/reputation.generic).

The last time downloaded was found to be dated: Thu May 28 04:00:26 UTC 2015.

The ipset `alienvault_reputation` has **177044** entries, **177044** unique IPs.

The following table shows the overlaps of `alienvault_reputation` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `alienvault_reputation`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `alienvault_reputation`.
- ` this % ` is the percentage **of this ipset (`alienvault_reputation`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|14946|0.0%|8.4%|
[openbl_90d](#openbl_90d)|9897|9897|9865|99.6%|5.5%|
[openbl](#openbl)|9897|9897|9865|99.6%|5.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|8400|0.0%|4.7%|
[openbl_60d](#openbl_60d)|7801|7801|7772|99.6%|4.3%|
[et_block](#et_block)|975|18056513|5527|0.0%|3.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|5207|0.0%|2.9%|
[openbl_30d](#openbl_30d)|4449|4449|4428|99.5%|2.5%|
[dshield](#dshield)|20|5120|3584|70.0%|2.0%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|1624|0.0%|0.9%|
[blocklist_de](#blocklist_de)|22392|22392|1591|7.1%|0.8%|
[bruteforceblocker](#bruteforceblocker)|2415|2415|1491|61.7%|0.8%|
[et_compromised](#et_compromised)|2338|2338|1463|62.5%|0.8%|
[blocklist_de_ssh](#blocklist_de_ssh)|2276|2276|1350|59.3%|0.7%|
[openbl_7d](#openbl_7d)|997|997|981|98.3%|0.5%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|519|0.0%|0.2%|
[ciarmy](#ciarmy)|394|394|375|95.1%|0.2%|
[openbl_1d](#openbl_1d)|357|357|355|99.4%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|293|0.0%|0.1%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92800|92800|239|0.2%|0.1%|
[voipbl](#voipbl)|10286|10757|196|1.8%|0.1%|
[snort_ipfilter](#snort_ipfilter)|7236|7236|123|1.6%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|12673|12673|120|0.9%|0.0%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30710|30710|115|0.3%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|225|225|83|36.8%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14733|14733|76|0.5%|0.0%|
[zeus](#zeus)|266|266|67|25.1%|0.0%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7580|7580|64|0.8%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|683|683|63|9.2%|0.0%|
[shunlist](#shunlist)|51|51|51|100.0%|0.0%|
[dm_tor](#dm_tor)|6438|6438|45|0.6%|0.0%|
[bm_tor](#bm_tor)|6436|6436|45|0.6%|0.0%|
[et_tor](#et_tor)|6490|6490|44|0.6%|0.0%|
[zeus_badips](#zeus_badips)|229|229|36|15.7%|0.0%|
[nixspam](#nixspam)|26013|26013|36|0.1%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3467|3467|26|0.7%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|103|103|20|19.4%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1350|1350|17|1.2%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|15|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|13|0.0%|0.0%|
[php_commenters](#php_commenters)|281|281|12|4.2%|0.0%|
[php_bad](#php_bad)|281|281|12|4.2%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|239|239|12|5.0%|0.0%|
[malc0de](#malc0de)|414|414|10|2.4%|0.0%|
[php_harvesters](#php_harvesters)|257|257|9|3.5%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|8|0.5%|0.0%|
[sslbl](#sslbl)|345|345|7|2.0%|0.0%|
[php_dictionary](#php_dictionary)|398|398|7|1.7%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|6|0.4%|0.0%|
[ri_web_proxies](#ri_web_proxies)|4267|4267|3|0.0%|0.0%|
[php_spammers](#php_spammers)|417|417|3|0.7%|0.0%|
[et_botnet](#et_botnet)|512|512|3|0.5%|0.0%|
[clean_mx_viruses](#clean_mx_viruses)|104|104|2|1.9%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|1668|1668|1|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|1|0.1%|0.0%|
[feodo](#feodo)|63|63|1|1.5%|0.0%|

## blocklist_de

[Blocklist.de](https://www.blocklist.de/) IPs that have been detected by fail2ban in the last 48 hours - **excellent list**

Source is downloaded from [this link](http://lists.blocklist.de/lists/all.txt).

The last time downloaded was found to be dated: Thu May 28 09:09:28 UTC 2015.

The ipset `blocklist_de` has **22392** entries, **22392** unique IPs.

The following table shows the overlaps of `blocklist_de` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de`.
- ` this % ` is the percentage **of this ipset (`blocklist_de`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de_mail](#blocklist_de_mail)|14733|14733|14730|99.9%|65.7%|
[blocklist_de_apache](#blocklist_de_apache)|12673|12673|12673|100.0%|56.5%|
[blocklist_de_bots](#blocklist_de_bots)|3467|3467|3462|99.8%|15.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|2798|0.0%|12.4%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30710|30710|2335|7.6%|10.4%|
[blocklist_de_ssh](#blocklist_de_ssh)|2276|2276|2275|99.9%|10.1%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92800|92800|2174|2.3%|9.7%|
[alienvault_reputation](#alienvault_reputation)|177044|177044|1591|0.8%|7.1%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7580|7580|1512|19.9%|6.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|1480|0.0%|6.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|1439|0.0%|6.4%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1350|1350|1350|100.0%|6.0%|
[openbl_90d](#openbl_90d)|9897|9897|1347|13.6%|6.0%|
[openbl](#openbl)|9897|9897|1347|13.6%|6.0%|
[openbl_60d](#openbl_60d)|7801|7801|1288|16.5%|5.7%|
[openbl_30d](#openbl_30d)|4449|4449|1190|26.7%|5.3%|
[bruteforceblocker](#bruteforceblocker)|2415|2415|1142|47.2%|5.1%|
[et_compromised](#et_compromised)|2338|2338|1047|44.7%|4.6%|
[blocklist_de_imap](#blocklist_de_imap)|683|683|683|100.0%|3.0%|
[openbl_7d](#openbl_7d)|997|997|676|67.8%|3.0%|
[nixspam](#nixspam)|26013|26013|585|2.2%|2.6%|
[ri_web_proxies](#ri_web_proxies)|4267|4267|386|9.0%|1.7%|
[openbl_1d](#openbl_1d)|357|357|246|68.9%|1.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|239|239|239|100.0%|1.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|225|225|225|100.0%|1.0%|
[et_block](#et_block)|975|18056513|191|0.0%|0.8%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|183|0.0%|0.8%|
[snort_ipfilter](#snort_ipfilter)|7236|7236|152|2.1%|0.6%|
[dshield](#dshield)|20|5120|142|2.7%|0.6%|
[blocklist_de_sip](#blocklist_de_sip)|103|103|84|81.5%|0.3%|
[ri_connect_proxies](#ri_connect_proxies)|1668|1668|83|4.9%|0.3%|
[php_commenters](#php_commenters)|281|281|81|28.8%|0.3%|
[php_bad](#php_bad)|281|281|80|28.4%|0.3%|
[php_dictionary](#php_dictionary)|398|398|69|17.3%|0.3%|
[php_spammers](#php_spammers)|417|417|62|14.8%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|60|0.0%|0.2%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|37|0.0%|0.1%|
[voipbl](#voipbl)|10286|10757|36|0.3%|0.1%|
[ciarmy](#ciarmy)|394|394|34|8.6%|0.1%|
[php_harvesters](#php_harvesters)|257|257|31|12.0%|0.1%|
[et_tor](#et_tor)|6490|6490|27|0.4%|0.1%|
[dm_tor](#dm_tor)|6438|6438|26|0.4%|0.1%|
[bm_tor](#bm_tor)|6436|6436|26|0.4%|0.1%|
[shunlist](#shunlist)|51|51|10|19.6%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|7|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|3|0.2%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|3|0.4%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|3|0.0%|0.0%|
[zeus](#zeus)|266|266|1|0.3%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|1|0.0%|0.0%|
[clean_mx_viruses](#clean_mx_viruses)|104|104|1|0.9%|0.0%|

## blocklist_de_apache

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service Apache, Apache-DDOS, RFI-Attacks.

Source is downloaded from [this link](http://lists.blocklist.de/lists/apache.txt).

The last time downloaded was found to be dated: Thu May 28 09:14:05 UTC 2015.

The ipset `blocklist_de_apache` has **12673** entries, **12673** unique IPs.

The following table shows the overlaps of `blocklist_de_apache` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_apache`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_apache`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_apache`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|22392|22392|12673|56.5%|100.0%|
[blocklist_de_mail](#blocklist_de_mail)|14733|14733|11059|75.0%|87.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|2220|0.0%|17.5%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1350|1350|1350|100.0%|10.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|1321|0.0%|10.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|1077|0.0%|8.4%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92800|92800|206|0.2%|1.6%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30710|30710|136|0.4%|1.0%|
[alienvault_reputation](#alienvault_reputation)|177044|177044|120|0.0%|0.9%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7580|7580|92|1.2%|0.7%|
[snort_ipfilter](#snort_ipfilter)|7236|7236|43|0.5%|0.3%|
[blocklist_de_strongips](#blocklist_de_strongips)|225|225|35|15.5%|0.2%|
[ciarmy](#ciarmy)|394|394|28|7.1%|0.2%|
[et_tor](#et_tor)|6490|6490|27|0.4%|0.2%|
[dm_tor](#dm_tor)|6438|6438|26|0.4%|0.2%|
[bm_tor](#bm_tor)|6436|6436|26|0.4%|0.2%|
[php_commenters](#php_commenters)|281|281|24|8.5%|0.1%|
[php_bad](#php_bad)|281|281|24|8.5%|0.1%|
[blocklist_de_bots](#blocklist_de_bots)|3467|3467|19|0.5%|0.1%|
[openbl_90d](#openbl_90d)|9897|9897|15|0.1%|0.1%|
[openbl](#openbl)|9897|9897|15|0.1%|0.1%|
[openbl_60d](#openbl_60d)|7801|7801|10|0.1%|0.0%|
[et_block](#et_block)|975|18056513|8|0.0%|0.0%|
[openbl_30d](#openbl_30d)|4449|4449|7|0.1%|0.0%|
[php_spammers](#php_spammers)|417|417|5|1.1%|0.0%|
[openbl_7d](#openbl_7d)|997|997|4|0.4%|0.0%|
[nixspam](#nixspam)|26013|26013|4|0.0%|0.0%|
[dshield](#dshield)|20|5120|4|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|3|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|3|0.0%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|0.0%|
[et_compromised](#et_compromised)|2338|2338|3|0.1%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2415|2415|3|0.1%|0.0%|
[voipbl](#voipbl)|10286|10757|2|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|2|0.0%|0.0%|
[shunlist](#shunlist)|51|51|2|3.9%|0.0%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.0%|
[clean_mx_viruses](#clean_mx_viruses)|104|104|1|0.9%|0.0%|

## blocklist_de_bots

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the RFI-Attacks, REG-Bots, IRC-Bots or BadBots (BadBots = he has posted a Spam-Comment on a open Forum or Wiki).

Source is downloaded from [this link](http://lists.blocklist.de/lists/bots.txt).

The last time downloaded was found to be dated: Thu May 28 09:14:09 UTC 2015.

The ipset `blocklist_de_bots` has **3467** entries, **3467** unique IPs.

The following table shows the overlaps of `blocklist_de_bots` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_bots`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_bots`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_bots`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|22392|22392|3462|15.4%|99.8%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30710|30710|2165|7.0%|62.4%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92800|92800|1905|2.0%|54.9%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7580|7580|1428|18.8%|41.1%|
[ri_web_proxies](#ri_web_proxies)|4267|4267|359|8.4%|10.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|151|0.0%|4.3%|
[blocklist_de_strongips](#blocklist_de_strongips)|225|225|126|56.0%|3.6%|
[ri_connect_proxies](#ri_connect_proxies)|1668|1668|82|4.9%|2.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|76|0.0%|2.1%|
[php_commenters](#php_commenters)|281|281|66|23.4%|1.9%|
[php_bad](#php_bad)|281|281|66|23.4%|1.9%|
[nixspam](#nixspam)|26013|26013|50|0.1%|1.4%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|44|0.0%|1.2%|
[et_block](#et_block)|975|18056513|43|0.0%|1.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|41|0.0%|1.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|37|0.0%|1.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|30|0.0%|0.8%|
[alienvault_reputation](#alienvault_reputation)|177044|177044|26|0.0%|0.7%|
[php_harvesters](#php_harvesters)|257|257|25|9.7%|0.7%|
[blocklist_de_mail](#blocklist_de_mail)|14733|14733|19|0.1%|0.5%|
[blocklist_de_apache](#blocklist_de_apache)|12673|12673|19|0.1%|0.5%|
[snort_ipfilter](#snort_ipfilter)|7236|7236|18|0.2%|0.5%|
[php_spammers](#php_spammers)|417|417|17|4.0%|0.4%|
[php_dictionary](#php_dictionary)|398|398|10|2.5%|0.2%|
[openbl_90d](#openbl_90d)|9897|9897|3|0.0%|0.0%|
[openbl](#openbl)|9897|9897|3|0.0%|0.0%|
[voipbl](#voipbl)|10286|10757|2|0.0%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|1|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|1|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|1|0.1%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1|0.0%|0.0%|
[et_compromised](#et_compromised)|2338|2338|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2415|2415|1|0.0%|0.0%|

## blocklist_de_bruteforce

[Blocklist.de](https://www.blocklist.de/) All IPs which attacks Joomlas, Wordpress and other Web-Logins with Brute-Force Logins.

Source is downloaded from [this link](http://lists.blocklist.de/lists/bruteforcelogin.txt).

The last time downloaded was found to be dated: Thu May 28 09:14:11 UTC 2015.

The ipset `blocklist_de_bruteforce` has **1350** entries, **1350** unique IPs.

The following table shows the overlaps of `blocklist_de_bruteforce` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_bruteforce`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_bruteforce`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_bruteforce`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de_apache](#blocklist_de_apache)|12673|12673|1350|10.6%|100.0%|
[blocklist_de](#blocklist_de)|22392|22392|1350|6.0%|100.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|127|0.0%|9.4%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30710|30710|74|0.2%|5.4%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92800|92800|71|0.0%|5.2%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7580|7580|54|0.7%|4.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|44|0.0%|3.2%|
[snort_ipfilter](#snort_ipfilter)|7236|7236|40|0.5%|2.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|28|0.0%|2.0%|
[et_tor](#et_tor)|6490|6490|24|0.3%|1.7%|
[dm_tor](#dm_tor)|6438|6438|23|0.3%|1.7%|
[bm_tor](#bm_tor)|6436|6436|23|0.3%|1.7%|
[alienvault_reputation](#alienvault_reputation)|177044|177044|17|0.0%|1.2%|
[blocklist_de_strongips](#blocklist_de_strongips)|225|225|11|4.8%|0.8%|
[openbl_90d](#openbl_90d)|9897|9897|6|0.0%|0.4%|
[openbl](#openbl)|9897|9897|6|0.0%|0.4%|
[php_spammers](#php_spammers)|417|417|5|1.1%|0.3%|
[php_commenters](#php_commenters)|281|281|4|1.4%|0.2%|
[php_bad](#php_bad)|281|281|4|1.4%|0.2%|
[nixspam](#nixspam)|26013|26013|4|0.0%|0.2%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|3|0.0%|0.2%|
[openbl_60d](#openbl_60d)|7801|7801|3|0.0%|0.2%|
[et_block](#et_block)|975|18056513|3|0.0%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2|0.0%|0.1%|
[voipbl](#voipbl)|10286|10757|1|0.0%|0.0%|
[openbl_30d](#openbl_30d)|4449|4449|1|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|1|0.0%|0.0%|
[et_compromised](#et_compromised)|2338|2338|1|0.0%|0.0%|
[clean_mx_viruses](#clean_mx_viruses)|104|104|1|0.9%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2415|2415|1|0.0%|0.0%|

## blocklist_de_ftp

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours for attacks on the Service FTP.

Source is downloaded from [this link](http://lists.blocklist.de/lists/ftp.txt).

The last time downloaded was found to be dated: Thu May 28 09:30:09 UTC 2015.

The ipset `blocklist_de_ftp` has **239** entries, **239** unique IPs.

The following table shows the overlaps of `blocklist_de_ftp` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_ftp`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_ftp`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_ftp`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|22392|22392|239|1.0%|100.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|21|0.0%|8.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|17|0.0%|7.1%|
[alienvault_reputation](#alienvault_reputation)|177044|177044|12|0.0%|5.0%|
[openbl_90d](#openbl_90d)|9897|9897|7|0.0%|2.9%|
[openbl](#openbl)|9897|9897|7|0.0%|2.9%|
[openbl_60d](#openbl_60d)|7801|7801|5|0.0%|2.0%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92800|92800|4|0.0%|1.6%|
[nixspam](#nixspam)|26013|26013|4|0.0%|1.6%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30710|30710|2|0.0%|0.8%|
[php_harvesters](#php_harvesters)|257|257|2|0.7%|0.8%|
[openbl_30d](#openbl_30d)|4449|4449|2|0.0%|0.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|2|0.0%|0.8%|
[ciarmy](#ciarmy)|394|394|2|0.5%|0.8%|
[blocklist_de_strongips](#blocklist_de_strongips)|225|225|2|0.8%|0.8%|
[openbl_7d](#openbl_7d)|997|997|1|0.1%|0.4%|
[openbl_1d](#openbl_1d)|357|357|1|0.2%|0.4%|

## blocklist_de_imap

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours for attacks on the Service imap, sasl, pop3, etc.

Source is downloaded from [this link](http://lists.blocklist.de/lists/imap.txt).

The last time downloaded was found to be dated: Thu May 28 09:09:30 UTC 2015.

The ipset `blocklist_de_imap` has **683** entries, **683** unique IPs.

The following table shows the overlaps of `blocklist_de_imap` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_imap`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_imap`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_imap`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de_mail](#blocklist_de_mail)|14733|14733|683|4.6%|100.0%|
[blocklist_de](#blocklist_de)|22392|22392|683|3.0%|100.0%|
[alienvault_reputation](#alienvault_reputation)|177044|177044|63|0.0%|9.2%|
[openbl_90d](#openbl_90d)|9897|9897|49|0.4%|7.1%|
[openbl](#openbl)|9897|9897|49|0.4%|7.1%|
[openbl_60d](#openbl_60d)|7801|7801|45|0.5%|6.5%|
[openbl_30d](#openbl_30d)|4449|4449|41|0.9%|6.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|38|0.0%|5.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|37|0.0%|5.4%|
[openbl_7d](#openbl_7d)|997|997|26|2.6%|3.8%|
[et_compromised](#et_compromised)|2338|2338|15|0.6%|2.1%|
[bruteforceblocker](#bruteforceblocker)|2415|2415|15|0.6%|2.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|13|0.0%|1.9%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|12|0.0%|1.7%|
[et_block](#et_block)|975|18056513|12|0.0%|1.7%|
[openbl_1d](#openbl_1d)|357|357|9|2.5%|1.3%|
[nixspam](#nixspam)|26013|26013|5|0.0%|0.7%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|0.4%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|2|0.0%|0.2%|
[blocklist_de_strongips](#blocklist_de_strongips)|225|225|2|0.8%|0.2%|
[shunlist](#shunlist)|51|51|1|1.9%|0.1%|
[ciarmy](#ciarmy)|394|394|1|0.2%|0.1%|

## blocklist_de_mail

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service Mail, Postfix.

Source is downloaded from [this link](http://lists.blocklist.de/lists/mail.txt).

The last time downloaded was found to be dated: Thu May 28 09:14:04 UTC 2015.

The ipset `blocklist_de_mail` has **14733** entries, **14733** unique IPs.

The following table shows the overlaps of `blocklist_de_mail` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_mail`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_mail`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_mail`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|22392|22392|14730|65.7%|99.9%|
[blocklist_de_apache](#blocklist_de_apache)|12673|12673|11059|87.2%|75.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|2238|0.0%|15.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|1347|0.0%|9.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|1162|0.0%|7.8%|
[blocklist_de_imap](#blocklist_de_imap)|683|683|683|100.0%|4.6%|
[nixspam](#nixspam)|26013|26013|525|2.0%|3.5%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92800|92800|183|0.1%|1.2%|
[snort_ipfilter](#snort_ipfilter)|7236|7236|91|1.2%|0.6%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30710|30710|89|0.2%|0.6%|
[alienvault_reputation](#alienvault_reputation)|177044|177044|76|0.0%|0.5%|
[php_dictionary](#php_dictionary)|398|398|59|14.8%|0.4%|
[openbl_90d](#openbl_90d)|9897|9897|57|0.5%|0.3%|
[openbl](#openbl)|9897|9897|57|0.5%|0.3%|
[openbl_60d](#openbl_60d)|7801|7801|53|0.6%|0.3%|
[openbl_30d](#openbl_30d)|4449|4449|47|1.0%|0.3%|
[php_spammers](#php_spammers)|417|417|40|9.5%|0.2%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7580|7580|34|0.4%|0.2%|
[openbl_7d](#openbl_7d)|997|997|27|2.7%|0.1%|
[ri_web_proxies](#ri_web_proxies)|4267|4267|26|0.6%|0.1%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|21|0.0%|0.1%|
[php_commenters](#php_commenters)|281|281|21|7.4%|0.1%|
[php_bad](#php_bad)|281|281|20|7.1%|0.1%|
[et_compromised](#et_compromised)|2338|2338|20|0.8%|0.1%|
[bruteforceblocker](#bruteforceblocker)|2415|2415|20|0.8%|0.1%|
[et_block](#et_block)|975|18056513|19|0.0%|0.1%|
[blocklist_de_strongips](#blocklist_de_strongips)|225|225|19|8.4%|0.1%|
[blocklist_de_bots](#blocklist_de_bots)|3467|3467|19|0.5%|0.1%|
[openbl_1d](#openbl_1d)|357|357|10|2.8%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|5|0.0%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|5|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|4|1.5%|0.0%|
[et_tor](#et_tor)|6490|6490|3|0.0%|0.0%|
[dm_tor](#dm_tor)|6438|6438|3|0.0%|0.0%|
[bm_tor](#bm_tor)|6436|6436|3|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|2|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|2|0.2%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|2|0.0%|0.0%|
[voipbl](#voipbl)|10286|10757|1|0.0%|0.0%|
[shunlist](#shunlist)|51|51|1|1.9%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|1668|1668|1|0.0%|0.0%|
[dshield](#dshield)|20|5120|1|0.0%|0.0%|
[ciarmy](#ciarmy)|394|394|1|0.2%|0.0%|

## blocklist_de_sip

[Blocklist.de](https://www.blocklist.de/) All IP addresses that tried to login in a SIP, VOIP or Asterisk Server and are included in the IPs list from [infiltrated.net](www.infiltrated.net)

Source is downloaded from [this link](http://lists.blocklist.de/lists/sip.txt).

The last time downloaded was found to be dated: Thu May 28 09:09:31 UTC 2015.

The ipset `blocklist_de_sip` has **103** entries, **103** unique IPs.

The following table shows the overlaps of `blocklist_de_sip` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_sip`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_sip`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_sip`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|22392|22392|84|0.3%|81.5%|
[voipbl](#voipbl)|10286|10757|28|0.2%|27.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|22|0.0%|21.3%|
[alienvault_reputation](#alienvault_reputation)|177044|177044|20|0.0%|19.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|8|0.0%|7.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|4|0.0%|3.8%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|2|0.0%|1.9%|
[ciarmy](#ciarmy)|394|394|2|0.5%|1.9%|
[et_botnet](#et_botnet)|512|512|1|0.1%|0.9%|

## blocklist_de_ssh

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service SSH.

Source is downloaded from [this link](http://lists.blocklist.de/lists/ssh.txt).

The last time downloaded was found to be dated: Thu May 28 09:14:03 UTC 2015.

The ipset `blocklist_de_ssh` has **2276** entries, **2276** unique IPs.

The following table shows the overlaps of `blocklist_de_ssh` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_ssh`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_ssh`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_ssh`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|22392|22392|2275|10.1%|99.9%|
[alienvault_reputation](#alienvault_reputation)|177044|177044|1350|0.7%|59.3%|
[openbl_90d](#openbl_90d)|9897|9897|1266|12.7%|55.6%|
[openbl](#openbl)|9897|9897|1266|12.7%|55.6%|
[openbl_60d](#openbl_60d)|7801|7801|1221|15.6%|53.6%|
[openbl_30d](#openbl_30d)|4449|4449|1135|25.5%|49.8%|
[bruteforceblocker](#bruteforceblocker)|2415|2415|1118|46.2%|49.1%|
[et_compromised](#et_compromised)|2338|2338|1023|43.7%|44.9%|
[openbl_7d](#openbl_7d)|997|997|644|64.5%|28.2%|
[openbl_1d](#openbl_1d)|357|357|235|65.8%|10.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|221|0.0%|9.7%|
[dshield](#dshield)|20|5120|137|2.6%|6.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|127|0.0%|5.5%|
[et_block](#et_block)|975|18056513|122|0.0%|5.3%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|116|0.0%|5.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|225|225|75|33.3%|3.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|51|0.0%|2.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|12|0.0%|0.5%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92800|92800|8|0.0%|0.3%|
[shunlist](#shunlist)|51|51|7|13.7%|0.3%|
[voipbl](#voipbl)|10286|10757|3|0.0%|0.1%|
[snort_ipfilter](#snort_ipfilter)|7236|7236|3|0.0%|0.1%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30710|30710|2|0.0%|0.0%|
[nixspam](#nixspam)|26013|26013|2|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|2|0.0%|0.0%|
[zeus](#zeus)|266|266|1|0.3%|0.0%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7580|7580|1|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|4267|4267|1|0.0%|0.0%|
[ciarmy](#ciarmy)|394|394|1|0.2%|0.0%|

## blocklist_de_strongips

[Blocklist.de](https://www.blocklist.de/) All IPs which are older then 2 month and have more then 5.000 attacks.

Source is downloaded from [this link](http://lists.blocklist.de/lists/strongips.txt).

The last time downloaded was found to be dated: Thu May 28 09:09:33 UTC 2015.

The ipset `blocklist_de_strongips` has **225** entries, **225** unique IPs.

The following table shows the overlaps of `blocklist_de_strongips` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_strongips`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_strongips`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_strongips`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|22392|22392|225|1.0%|100.0%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92800|92800|126|0.1%|56.0%|
[blocklist_de_bots](#blocklist_de_bots)|3467|3467|126|3.6%|56.0%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30710|30710|118|0.3%|52.4%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7580|7580|105|1.3%|46.6%|
[alienvault_reputation](#alienvault_reputation)|177044|177044|83|0.0%|36.8%|
[openbl_90d](#openbl_90d)|9897|9897|76|0.7%|33.7%|
[openbl](#openbl)|9897|9897|76|0.7%|33.7%|
[openbl_60d](#openbl_60d)|7801|7801|75|0.9%|33.3%|
[blocklist_de_ssh](#blocklist_de_ssh)|2276|2276|75|3.2%|33.3%|
[openbl_7d](#openbl_7d)|997|997|74|7.4%|32.8%|
[openbl_30d](#openbl_30d)|4449|4449|74|1.6%|32.8%|
[openbl_1d](#openbl_1d)|357|357|68|19.0%|30.2%|
[blocklist_de_apache](#blocklist_de_apache)|12673|12673|35|0.2%|15.5%|
[php_commenters](#php_commenters)|281|281|34|12.0%|15.1%|
[php_bad](#php_bad)|281|281|34|12.0%|15.1%|
[et_compromised](#et_compromised)|2338|2338|26|1.1%|11.5%|
[bruteforceblocker](#bruteforceblocker)|2415|2415|22|0.9%|9.7%|
[dshield](#dshield)|20|5120|19|0.3%|8.4%|
[blocklist_de_mail](#blocklist_de_mail)|14733|14733|19|0.1%|8.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|17|0.0%|7.5%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1350|1350|11|0.8%|4.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|8|0.0%|3.5%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|7|0.0%|3.1%|
[et_block](#et_block)|975|18056513|7|0.0%|3.1%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|4|0.0%|1.7%|
[php_spammers](#php_spammers)|417|417|4|0.9%|1.7%|
[ri_web_proxies](#ri_web_proxies)|4267|4267|3|0.0%|1.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|1.3%|
[blocklist_de_imap](#blocklist_de_imap)|683|683|2|0.2%|0.8%|
[blocklist_de_ftp](#blocklist_de_ftp)|239|239|2|0.8%|0.8%|
[snort_ipfilter](#snort_ipfilter)|7236|7236|1|0.0%|0.4%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.4%|
[php_dictionary](#php_dictionary)|398|398|1|0.2%|0.4%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.4%|

## bm_tor

[torstatus.blutmagie.de](https://torstatus.blutmagie.de) list of all TOR network servers

Source is downloaded from [this link](https://torstatus.blutmagie.de/ip_list_all.php/Tor_ip_list_ALL.csv).

The last time downloaded was found to be dated: Thu May 28 09:40:06 UTC 2015.

The ipset `bm_tor` has **6436** entries, **6436** unique IPs.

The following table shows the overlaps of `bm_tor` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `bm_tor`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `bm_tor`.
- ` this % ` is the percentage **of this ipset (`bm_tor`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[dm_tor](#dm_tor)|6438|6438|6372|98.9%|99.0%|
[et_tor](#et_tor)|6490|6490|5735|88.3%|89.1%|
[snort_ipfilter](#snort_ipfilter)|7236|7236|1039|14.3%|16.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|611|0.0%|9.4%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92800|92800|570|0.6%|8.8%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30710|30710|436|1.4%|6.7%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7580|7580|292|3.8%|4.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|184|0.0%|2.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|165|0.0%|2.5%|
[alienvault_reputation](#alienvault_reputation)|177044|177044|45|0.0%|0.6%|
[php_commenters](#php_commenters)|281|281|29|10.3%|0.4%|
[php_bad](#php_bad)|281|281|29|10.3%|0.4%|
[blocklist_de_apache](#blocklist_de_apache)|12673|12673|26|0.2%|0.4%|
[blocklist_de](#blocklist_de)|22392|22392|26|0.1%|0.4%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1350|1350|23|1.7%|0.3%|
[openbl_90d](#openbl_90d)|9897|9897|21|0.2%|0.3%|
[openbl_60d](#openbl_60d)|7801|7801|21|0.2%|0.3%|
[openbl](#openbl)|9897|9897|21|0.2%|0.3%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|21|0.0%|0.3%|
[php_harvesters](#php_harvesters)|257|257|7|2.7%|0.1%|
[php_spammers](#php_spammers)|417|417|6|1.4%|0.0%|
[ri_web_proxies](#ri_web_proxies)|4267|4267|4|0.0%|0.0%|
[php_dictionary](#php_dictionary)|398|398|4|1.0%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|0.0%|
[et_block](#et_block)|975|18056513|3|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14733|14733|3|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|2|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|1668|1668|2|0.1%|0.0%|
[nixspam](#nixspam)|26013|26013|2|0.0%|0.0%|
[voipbl](#voipbl)|10286|10757|1|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|

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
[fullbogons](#fullbogons)|3656|670735064|592708608|88.3%|100.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|4194304|3.0%|0.7%|
[voipbl](#voipbl)|10286|10757|351|3.2%|0.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|5|0.0%|0.0%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92800|92800|1|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2415|2415|1|0.0%|0.0%|

## bruteforceblocker

[danger.rulez.sk](http://danger.rulez.sk/) IPs detected by [bruteforceblocker](http://danger.rulez.sk/index.php/bruteforceblocker/) (fail2ban alternative for SSH on OpenBSD)

Source is downloaded from [this link](http://danger.rulez.sk/projects/bruteforceblocker/blist.php).

The last time downloaded was found to be dated: Thu May 28 07:20:54 UTC 2015.

The ipset `bruteforceblocker` has **2415** entries, **2415** unique IPs.

The following table shows the overlaps of `bruteforceblocker` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `bruteforceblocker`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `bruteforceblocker`.
- ` this % ` is the percentage **of this ipset (`bruteforceblocker`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[et_compromised](#et_compromised)|2338|2338|2295|98.1%|95.0%|
[alienvault_reputation](#alienvault_reputation)|177044|177044|1491|0.8%|61.7%|
[openbl_90d](#openbl_90d)|9897|9897|1421|14.3%|58.8%|
[openbl](#openbl)|9897|9897|1421|14.3%|58.8%|
[openbl_60d](#openbl_60d)|7801|7801|1404|17.9%|58.1%|
[openbl_30d](#openbl_30d)|4449|4449|1346|30.2%|55.7%|
[blocklist_de](#blocklist_de)|22392|22392|1142|5.1%|47.2%|
[blocklist_de_ssh](#blocklist_de_ssh)|2276|2276|1118|49.1%|46.2%|
[openbl_7d](#openbl_7d)|997|997|512|51.3%|21.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|232|0.0%|9.6%|
[openbl_1d](#openbl_1d)|357|357|203|56.8%|8.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|148|0.0%|6.1%|
[et_block](#et_block)|975|18056513|99|0.0%|4.0%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|98|0.0%|4.0%|
[dshield](#dshield)|20|5120|96|1.8%|3.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|74|0.0%|3.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|225|225|22|9.7%|0.9%|
[blocklist_de_mail](#blocklist_de_mail)|14733|14733|20|0.1%|0.8%|
[blocklist_de_imap](#blocklist_de_imap)|683|683|15|2.1%|0.6%|
[shunlist](#shunlist)|51|51|8|15.6%|0.3%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92800|92800|6|0.0%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|4|0.0%|0.1%|
[blocklist_de_apache](#blocklist_de_apache)|12673|12673|3|0.0%|0.1%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30710|30710|2|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.0%|
[zeus_badips](#zeus_badips)|229|229|1|0.4%|0.0%|
[zeus](#zeus)|266|266|1|0.3%|0.0%|
[voipbl](#voipbl)|10286|10757|1|0.0%|0.0%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7580|7580|1|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|7236|7236|1|0.0%|0.0%|
[fullbogons](#fullbogons)|3656|670735064|1|0.0%|0.0%|
[bogons](#bogons)|13|592708608|1|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1350|1350|1|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3467|3467|1|0.0%|0.0%|

## ciarmy

[CIArmy.com](http://ciarmy.com/) IPs with poor Rogue Packet score that have not yet been identified as malicious by the community

Source is downloaded from [this link](http://cinsscore.com/list/ci-badguys.txt).

The last time downloaded was found to be dated: Thu May 28 09:15:06 UTC 2015.

The ipset `ciarmy` has **394** entries, **394** unique IPs.

The following table shows the overlaps of `ciarmy` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ciarmy`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ciarmy`.
- ` this % ` is the percentage **of this ipset (`ciarmy`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[alienvault_reputation](#alienvault_reputation)|177044|177044|375|0.2%|95.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|72|0.0%|18.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|40|0.0%|10.1%|
[blocklist_de](#blocklist_de)|22392|22392|34|0.1%|8.6%|
[blocklist_de_apache](#blocklist_de_apache)|12673|12673|28|0.2%|7.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|22|0.0%|5.5%|
[voipbl](#voipbl)|10286|10757|3|0.0%|0.7%|
[shunlist](#shunlist)|51|51|2|3.9%|0.5%|
[blocklist_de_sip](#blocklist_de_sip)|103|103|2|1.9%|0.5%|
[blocklist_de_ftp](#blocklist_de_ftp)|239|239|2|0.8%|0.5%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92800|92800|1|0.0%|0.2%|
[openbl_90d](#openbl_90d)|9897|9897|1|0.0%|0.2%|
[openbl_7d](#openbl_7d)|997|997|1|0.1%|0.2%|
[openbl_60d](#openbl_60d)|7801|7801|1|0.0%|0.2%|
[openbl_30d](#openbl_30d)|4449|4449|1|0.0%|0.2%|
[openbl](#openbl)|9897|9897|1|0.0%|0.2%|
[et_block](#et_block)|975|18056513|1|0.0%|0.2%|
[dshield](#dshield)|20|5120|1|0.0%|0.2%|
[blocklist_de_ssh](#blocklist_de_ssh)|2276|2276|1|0.0%|0.2%|
[blocklist_de_mail](#blocklist_de_mail)|14733|14733|1|0.0%|0.2%|
[blocklist_de_imap](#blocklist_de_imap)|683|683|1|0.1%|0.2%|

## clean_mx_viruses

[Clean-MX.de](http://support.clean-mx.de/clean-mx/viruses.php) IPs with viruses

Source is downloaded from [this link](http://support.clean-mx.de/clean-mx/xmlviruses.php?sort=id%20desc&response=alive).

The last time downloaded was found to be dated: Thu May 28 04:21:25 UTC 2015.

The ipset `clean_mx_viruses` has **104** entries, **104** unique IPs.

The following table shows the overlaps of `clean_mx_viruses` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `clean_mx_viruses`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `clean_mx_viruses`.
- ` this % ` is the percentage **of this ipset (`clean_mx_viruses`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|13|0.0%|12.5%|
[malc0de](#malc0de)|414|414|11|2.6%|10.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|6|0.0%|5.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|4|0.0%|3.8%|
[alienvault_reputation](#alienvault_reputation)|177044|177044|2|0.0%|1.9%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|1|0.0%|0.9%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1350|1350|1|0.0%|0.9%|
[blocklist_de_apache](#blocklist_de_apache)|12673|12673|1|0.0%|0.9%|
[blocklist_de](#blocklist_de)|22392|22392|1|0.0%|0.9%|

## dm_tor

[dan.me.uk](https://www.dan.me.uk) dynamic list of TOR exit points

Source is downloaded from [this link](https://www.dan.me.uk/torlist/).

The last time downloaded was found to be dated: Thu May 28 09:40:04 UTC 2015.

The ipset `dm_tor` has **6438** entries, **6438** unique IPs.

The following table shows the overlaps of `dm_tor` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `dm_tor`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `dm_tor`.
- ` this % ` is the percentage **of this ipset (`dm_tor`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[bm_tor](#bm_tor)|6436|6436|6372|99.0%|98.9%|
[et_tor](#et_tor)|6490|6490|5720|88.1%|88.8%|
[snort_ipfilter](#snort_ipfilter)|7236|7236|1036|14.3%|16.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|612|0.0%|9.5%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92800|92800|569|0.6%|8.8%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30710|30710|435|1.4%|6.7%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7580|7580|290|3.8%|4.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|184|0.0%|2.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|165|0.0%|2.5%|
[alienvault_reputation](#alienvault_reputation)|177044|177044|45|0.0%|0.6%|
[php_commenters](#php_commenters)|281|281|29|10.3%|0.4%|
[php_bad](#php_bad)|281|281|29|10.3%|0.4%|
[blocklist_de_apache](#blocklist_de_apache)|12673|12673|26|0.2%|0.4%|
[blocklist_de](#blocklist_de)|22392|22392|26|0.1%|0.4%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1350|1350|23|1.7%|0.3%|
[openbl_90d](#openbl_90d)|9897|9897|21|0.2%|0.3%|
[openbl_60d](#openbl_60d)|7801|7801|21|0.2%|0.3%|
[openbl](#openbl)|9897|9897|21|0.2%|0.3%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|21|0.0%|0.3%|
[php_harvesters](#php_harvesters)|257|257|7|2.7%|0.1%|
[php_spammers](#php_spammers)|417|417|6|1.4%|0.0%|
[ri_web_proxies](#ri_web_proxies)|4267|4267|5|0.1%|0.0%|
[php_dictionary](#php_dictionary)|398|398|4|1.0%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|0.0%|
[et_block](#et_block)|975|18056513|3|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14733|14733|3|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|2|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|1668|1668|2|0.1%|0.0%|
[nixspam](#nixspam)|26013|26013|2|0.0%|0.0%|
[voipbl](#voipbl)|10286|10757|1|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|

## dshield

[DShield.org](https://dshield.org/) top 20 attacking class C (/24) subnets over the last three days - **excellent list**

Source is downloaded from [this link](http://feeds.dshield.org/block.txt).

The last time downloaded was found to be dated: Thu May 28 06:55:56 UTC 2015.

The ipset `dshield` has **20** entries, **5120** unique IPs.

The following table shows the overlaps of `dshield` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `dshield`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `dshield`.
- ` this % ` is the percentage **of this ipset (`dshield`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[alienvault_reputation](#alienvault_reputation)|177044|177044|3584|2.0%|70.0%|
[et_block](#et_block)|975|18056513|1024|0.0%|20.0%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|512|0.0%|10.0%|
[openbl_90d](#openbl_90d)|9897|9897|164|1.6%|3.2%|
[openbl](#openbl)|9897|9897|164|1.6%|3.2%|
[openbl_60d](#openbl_60d)|7801|7801|151|1.9%|2.9%|
[blocklist_de](#blocklist_de)|22392|22392|142|0.6%|2.7%|
[openbl_30d](#openbl_30d)|4449|4449|141|3.1%|2.7%|
[blocklist_de_ssh](#blocklist_de_ssh)|2276|2276|137|6.0%|2.6%|
[openbl_7d](#openbl_7d)|997|997|116|11.6%|2.2%|
[bruteforceblocker](#bruteforceblocker)|2415|2415|96|3.9%|1.8%|
[et_compromised](#et_compromised)|2338|2338|90|3.8%|1.7%|
[openbl_1d](#openbl_1d)|357|357|45|12.6%|0.8%|
[blocklist_de_strongips](#blocklist_de_strongips)|225|225|19|8.4%|0.3%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|4|0.0%|0.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|4|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|12673|12673|4|0.0%|0.0%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92800|92800|1|0.0%|0.0%|
[nixspam](#nixspam)|26013|26013|1|0.0%|0.0%|
[ciarmy](#ciarmy)|394|394|1|0.2%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14733|14733|1|0.0%|0.0%|

## et_block

[EmergingThreats.net](http://www.emergingthreats.net/) default blacklist (at the time of writing includes spamhaus DROP, dshield and abuse.ch trackers, which are available separately too - prefer to use the direct ipsets instead of this, they seem to lag a bit in updates)

Source is downloaded from [this link](http://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt).

The last time downloaded was found to be dated: Wed May 27 04:30:01 UTC 2015.

The ipset `et_block` has **975** entries, **18056513** unique IPs.

The following table shows the overlaps of `et_block` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `et_block`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `et_block`.
- ` this % ` is the percentage **of this ipset (`et_block`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[spamhaus_drop](#spamhaus_drop)|641|18117120|18051584|99.6%|99.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|8401703|2.4%|46.5%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|7211008|78.5%|39.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|2133031|0.2%|11.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|196440|0.1%|1.0%|
[fullbogons](#fullbogons)|3656|670735064|20480|0.0%|0.1%|
[alienvault_reputation](#alienvault_reputation)|177044|177044|5527|3.1%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|1044|0.3%|0.0%|
[dshield](#dshield)|20|5120|1024|20.0%|0.0%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92800|92800|769|0.8%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|517|0.1%|0.0%|
[openbl_90d](#openbl_90d)|9897|9897|455|4.5%|0.0%|
[openbl](#openbl)|9897|9897|455|4.5%|0.0%|
[openbl_60d](#openbl_60d)|7801|7801|300|3.8%|0.0%|
[snort_ipfilter](#snort_ipfilter)|7236|7236|286|3.9%|0.0%|
[zeus](#zeus)|266|266|262|98.4%|0.0%|
[zeus_badips](#zeus_badips)|229|229|228|99.5%|0.0%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30710|30710|214|0.6%|0.0%|
[openbl_30d](#openbl_30d)|4449|4449|213|4.7%|0.0%|
[nixspam](#nixspam)|26013|26013|193|0.7%|0.0%|
[blocklist_de](#blocklist_de)|22392|22392|191|0.8%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2276|2276|122|5.3%|0.0%|
[openbl_7d](#openbl_7d)|997|997|100|10.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2415|2415|99|4.0%|0.0%|
[et_compromised](#et_compromised)|2338|2338|94|4.0%|0.0%|
[feodo](#feodo)|63|63|61|96.8%|0.0%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7580|7580|48|0.6%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3467|3467|43|1.2%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|28|2.1%|0.0%|
[openbl_1d](#openbl_1d)|357|357|27|7.5%|0.0%|
[php_commenters](#php_commenters)|281|281|24|8.5%|0.0%|
[php_bad](#php_bad)|281|281|24|8.5%|0.0%|
[sslbl](#sslbl)|345|345|23|6.6%|0.0%|
[voipbl](#voipbl)|10286|10757|20|0.1%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14733|14733|19|0.1%|0.0%|
[palevo](#palevo)|13|13|12|92.3%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|683|683|12|1.7%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|10|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|12673|12673|8|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|225|225|7|3.1%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|6|0.4%|0.0%|
[php_dictionary](#php_dictionary)|398|398|3|0.7%|0.0%|
[malc0de](#malc0de)|414|414|3|0.7%|0.0%|
[et_tor](#et_tor)|6490|6490|3|0.0%|0.0%|
[dm_tor](#dm_tor)|6438|6438|3|0.0%|0.0%|
[bm_tor](#bm_tor)|6436|6436|3|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1350|1350|3|0.2%|0.0%|
[php_spammers](#php_spammers)|417|417|2|0.4%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|2|0.2%|0.0%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.0%|
[et_botnet](#et_botnet)|512|512|1|0.1%|0.0%|
[ciarmy](#ciarmy)|394|394|1|0.2%|0.0%|

## et_botnet

[EmergingThreats.net](http://www.emergingthreats.net/) botnet IPs

Source is downloaded from [this link](http://rules.emergingthreats.net/fwrules/emerging-PIX-CC.rules).

The last time downloaded was found to be dated: Wed May 27 04:30:01 UTC 2015.

The ipset `et_botnet` has **512** entries, **512** unique IPs.

The following table shows the overlaps of `et_botnet` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `et_botnet`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `et_botnet`.
- ` this % ` is the percentage **of this ipset (`et_botnet`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|75|0.0%|14.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|43|0.0%|8.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|21|0.0%|4.1%|
[alienvault_reputation](#alienvault_reputation)|177044|177044|3|0.0%|0.5%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|1|0.0%|0.1%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|1|0.0%|0.1%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.1%|
[et_block](#et_block)|975|18056513|1|0.0%|0.1%|
[blocklist_de_sip](#blocklist_de_sip)|103|103|1|0.9%|0.1%|

## et_compromised

[EmergingThreats.net](http://www.emergingthreats.net/) compromised hosts (seems to be a derivate of other lists)

Source is downloaded from [this link](http://rules.emergingthreats.net/blockrules/compromised-ips.txt).

The last time downloaded was found to be dated: Wed May 27 04:30:08 UTC 2015.

The ipset `et_compromised` has **2338** entries, **2338** unique IPs.

The following table shows the overlaps of `et_compromised` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `et_compromised`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `et_compromised`.
- ` this % ` is the percentage **of this ipset (`et_compromised`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[bruteforceblocker](#bruteforceblocker)|2415|2415|2295|95.0%|98.1%|
[alienvault_reputation](#alienvault_reputation)|177044|177044|1463|0.8%|62.5%|
[openbl_90d](#openbl_90d)|9897|9897|1392|14.0%|59.5%|
[openbl](#openbl)|9897|9897|1392|14.0%|59.5%|
[openbl_60d](#openbl_60d)|7801|7801|1381|17.7%|59.0%|
[openbl_30d](#openbl_30d)|4449|4449|1324|29.7%|56.6%|
[blocklist_de](#blocklist_de)|22392|22392|1047|4.6%|44.7%|
[blocklist_de_ssh](#blocklist_de_ssh)|2276|2276|1023|44.9%|43.7%|
[openbl_7d](#openbl_7d)|997|997|498|49.9%|21.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|225|0.0%|9.6%|
[openbl_1d](#openbl_1d)|357|357|207|57.9%|8.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|143|0.0%|6.1%|
[et_block](#et_block)|975|18056513|94|0.0%|4.0%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|92|0.0%|3.9%|
[dshield](#dshield)|20|5120|90|1.7%|3.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|75|0.0%|3.2%|
[blocklist_de_strongips](#blocklist_de_strongips)|225|225|26|11.5%|1.1%|
[blocklist_de_mail](#blocklist_de_mail)|14733|14733|20|0.1%|0.8%|
[blocklist_de_imap](#blocklist_de_imap)|683|683|15|2.1%|0.6%|
[shunlist](#shunlist)|51|51|8|15.6%|0.3%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92800|92800|5|0.0%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|5|0.0%|0.2%|
[blocklist_de_apache](#blocklist_de_apache)|12673|12673|3|0.0%|0.1%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30710|30710|2|0.0%|0.0%|
[zeus_badips](#zeus_badips)|229|229|1|0.4%|0.0%|
[zeus](#zeus)|266|266|1|0.3%|0.0%|
[voipbl](#voipbl)|10286|10757|1|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|7236|7236|1|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1350|1350|1|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3467|3467|1|0.0%|0.0%|

## et_tor

[EmergingThreats.net](http://www.emergingthreats.net/) [list](http://doc.emergingthreats.net/bin/view/Main/TorRules) of TOR network IPs

Source is downloaded from [this link](http://rules.emergingthreats.net/blockrules/emerging-tor.rules).

The last time downloaded was found to be dated: Wed May 27 04:30:09 UTC 2015.

The ipset `et_tor` has **6490** entries, **6490** unique IPs.

The following table shows the overlaps of `et_tor` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `et_tor`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `et_tor`.
- ` this % ` is the percentage **of this ipset (`et_tor`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[bm_tor](#bm_tor)|6436|6436|5735|89.1%|88.3%|
[dm_tor](#dm_tor)|6438|6438|5720|88.8%|88.1%|
[snort_ipfilter](#snort_ipfilter)|7236|7236|1090|15.0%|16.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|608|0.0%|9.3%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92800|92800|573|0.6%|8.8%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30710|30710|442|1.4%|6.8%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7580|7580|285|3.7%|4.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|184|0.0%|2.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|165|0.0%|2.5%|
[alienvault_reputation](#alienvault_reputation)|177044|177044|44|0.0%|0.6%|
[php_commenters](#php_commenters)|281|281|29|10.3%|0.4%|
[php_bad](#php_bad)|281|281|29|10.3%|0.4%|
[blocklist_de_apache](#blocklist_de_apache)|12673|12673|27|0.2%|0.4%|
[blocklist_de](#blocklist_de)|22392|22392|27|0.1%|0.4%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1350|1350|24|1.7%|0.3%|
[openbl_90d](#openbl_90d)|9897|9897|21|0.2%|0.3%|
[openbl_60d](#openbl_60d)|7801|7801|21|0.2%|0.3%|
[openbl](#openbl)|9897|9897|21|0.2%|0.3%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|21|0.0%|0.3%|
[php_harvesters](#php_harvesters)|257|257|7|2.7%|0.1%|
[php_spammers](#php_spammers)|417|417|6|1.4%|0.0%|
[ri_web_proxies](#ri_web_proxies)|4267|4267|5|0.1%|0.0%|
[php_dictionary](#php_dictionary)|398|398|3|0.7%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|0.0%|
[et_block](#et_block)|975|18056513|3|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14733|14733|3|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|2|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|1668|1668|2|0.1%|0.0%|
[nixspam](#nixspam)|26013|26013|2|0.0%|0.0%|
[voipbl](#voipbl)|10286|10757|1|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|

## feodo

[Abuse.ch Feodo tracker](https://feodotracker.abuse.ch) trojan includes IPs which are being used by Feodo (also known as Cridex or Bugat) which commits ebanking fraud - **excellent list**

Source is downloaded from [this link](https://feodotracker.abuse.ch/blocklist/?download=ipblocklist).

The last time downloaded was found to be dated: Thu May 28 08:20:24 UTC 2015.

The ipset `feodo` has **63** entries, **63** unique IPs.

The following table shows the overlaps of `feodo` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `feodo`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `feodo`.
- ` this % ` is the percentage **of this ipset (`feodo`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[et_block](#et_block)|975|18056513|61|0.0%|96.8%|
[snort_ipfilter](#snort_ipfilter)|7236|7236|48|0.6%|76.1%|
[sslbl](#sslbl)|345|345|20|5.7%|31.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|3|0.0%|4.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|3|0.0%|4.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|3|0.0%|4.7%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|1|0.0%|1.5%|
[alienvault_reputation](#alienvault_reputation)|177044|177044|1|0.0%|1.5%|

## fullbogons

[Team-Cymru.org](http://www.team-cymru.org) IP space that has been allocated to an RIR, but not assigned by that RIR to an actual ISP or other end-user - **excellent list - use it only your internet interface**

Source is downloaded from [this link](http://www.team-cymru.org/Services/Bogons/fullbogons-ipv4.txt).

The last time downloaded was found to be dated: Thu May 28 09:35:12 UTC 2015.

The ipset `fullbogons` has **3656** entries, **670735064** unique IPs.

The following table shows the overlaps of `fullbogons` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `fullbogons`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `fullbogons`.
- ` this % ` is the percentage **of this ipset (`fullbogons`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[bogons](#bogons)|13|592708608|592708608|100.0%|88.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|4233779|3.0%|0.6%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|565248|6.1%|0.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|248327|0.0%|0.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|235151|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|20480|0.1%|0.0%|
[et_block](#et_block)|975|18056513|20480|0.1%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|894|0.2%|0.0%|
[voipbl](#voipbl)|10286|10757|351|3.2%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|33|2.2%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|14|0.0%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|9|0.7%|0.0%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92800|92800|3|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2415|2415|1|0.0%|0.0%|

## ib_bluetack_badpeers

[iBlocklist.com](https://www.iblocklist.com/) free version of [BlueTack.co.uk](http://www.bluetack.co.uk/) IPs that have been reported for bad deeds in p2p

Source is downloaded from [this link](http://list.iblocklist.com/?list=cwworuawihqvocglcoss&fileformat=p2p&archiveformat=gz).

The last time downloaded was found to be dated: Thu May 28 03:20:53 UTC 2015.

The ipset `ib_bluetack_badpeers` has **48134** entries, **48134** unique IPs.

The following table shows the overlaps of `ib_bluetack_badpeers` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ib_bluetack_badpeers`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ib_bluetack_badpeers`.
- ` this % ` is the percentage **of this ipset (`ib_bluetack_badpeers`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|1172|0.0%|2.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|432|0.0%|0.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|233|0.0%|0.4%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92800|92800|14|0.0%|0.0%|
[fullbogons](#fullbogons)|3656|670735064|14|0.0%|0.0%|
[alienvault_reputation](#alienvault_reputation)|177044|177044|13|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|11|1.6%|0.0%|
[et_block](#et_block)|975|18056513|10|0.0%|0.0%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30710|30710|6|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|6|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|6|0.0%|0.0%|
[nixspam](#nixspam)|26013|26013|5|0.0%|0.0%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7580|7580|3|0.0%|0.0%|
[blocklist_de](#blocklist_de)|22392|22392|3|0.0%|0.0%|
[voipbl](#voipbl)|10286|10757|2|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|2|0.7%|0.0%|
[php_dictionary](#php_dictionary)|398|398|2|0.5%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14733|14733|2|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|7236|7236|1|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|4267|4267|1|0.0%|0.0%|
[php_spammers](#php_spammers)|417|417|1|0.2%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3467|3467|1|0.0%|0.0%|

## ib_bluetack_hijacked

[iBlocklist.com](https://www.iblocklist.com/) free version of [BlueTack.co.uk](http://www.bluetack.co.uk/) hijacked IP-Blocks Hijacked IP space are IP blocks that are being used without permission

Source is downloaded from [this link](http://list.iblocklist.com/?list=usrcshglbiilevmyfhse&fileformat=p2p&archiveformat=gz).

The last time downloaded was found to be dated: Thu May 28 03:50:50 UTC 2015.

The ipset `ib_bluetack_hijacked` has **535** entries, **9177856** unique IPs.

The following table shows the overlaps of `ib_bluetack_hijacked` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ib_bluetack_hijacked`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ib_bluetack_hijacked`.
- ` this % ` is the percentage **of this ipset (`ib_bluetack_hijacked`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[spamhaus_drop](#spamhaus_drop)|641|18117120|7211008|39.8%|78.5%|
[et_block](#et_block)|975|18056513|7211008|39.9%|78.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|2526625|0.7%|27.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|904796|0.1%|9.8%|
[fullbogons](#fullbogons)|3656|670735064|565248|0.0%|6.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|145472|0.1%|1.5%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|1036|0.3%|0.0%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92800|92800|737|0.7%|0.0%|
[alienvault_reputation](#alienvault_reputation)|177044|177044|519|0.2%|0.0%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30710|30710|195|0.6%|0.0%|
[nixspam](#nixspam)|26013|26013|193|0.7%|0.0%|
[blocklist_de](#blocklist_de)|22392|22392|60|0.2%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3467|3467|41|1.1%|0.0%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7580|7580|31|0.4%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|27|2.1%|0.0%|
[openbl_90d](#openbl_90d)|9897|9897|19|0.1%|0.0%|
[openbl](#openbl)|9897|9897|19|0.1%|0.0%|
[openbl_60d](#openbl_60d)|7801|7801|18|0.2%|0.0%|
[openbl_30d](#openbl_30d)|4449|4449|13|0.2%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2276|2276|12|0.5%|0.0%|
[snort_ipfilter](#snort_ipfilter)|7236|7236|11|0.1%|0.0%|
[zeus_badips](#zeus_badips)|229|229|10|4.3%|0.0%|
[zeus](#zeus)|266|266|10|3.7%|0.0%|
[openbl_7d](#openbl_7d)|997|997|9|0.9%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|7|0.4%|0.0%|
[openbl_1d](#openbl_1d)|357|357|5|1.4%|0.0%|
[et_compromised](#et_compromised)|2338|2338|5|0.2%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14733|14733|5|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2415|2415|4|0.1%|0.0%|
[et_tor](#et_tor)|6490|6490|3|0.0%|0.0%|
[dm_tor](#dm_tor)|6438|6438|3|0.0%|0.0%|
[bm_tor](#bm_tor)|6436|6436|3|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|225|225|3|1.3%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|683|683|3|0.4%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|12673|12673|3|0.0%|0.0%|
[php_spammers](#php_spammers)|417|417|2|0.4%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|2|0.2%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1350|1350|2|0.1%|0.0%|
[voipbl](#voipbl)|10286|10757|1|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.0%|
[php_dictionary](#php_dictionary)|398|398|1|0.2%|0.0%|
[php_commenters](#php_commenters)|281|281|1|0.3%|0.0%|
[php_bad](#php_bad)|281|281|1|0.3%|0.0%|
[et_botnet](#et_botnet)|512|512|1|0.1%|0.0%|

## ib_bluetack_level1

[iBlocklist.com](https://www.iblocklist.com/) free version of [BlueTack.co.uk](http://www.bluetack.co.uk/) Level 1 (for use in p2p): Companies or organizations who are clearly involved with trying to stop filesharing (e.g. Baytsp, MediaDefender, Mediasentry a.o.). Companies which anti-p2p activity has been seen from. Companies that produce or have a strong financial interest in copyrighted material (e.g. music, movie, software industries a.o.). Government ranges or companies that have a strong financial interest in doing work for governments. Legal industry ranges. IPs or ranges of ISPs from which anti-p2p activity has been observed. Basically this list will block all kinds of internet connections that most people would rather not have during their internet travels.

Source is downloaded from [this link](http://list.iblocklist.com/?list=ydxerpxkpcfqjaybcssw&fileformat=p2p&archiveformat=gz).

The last time downloaded was found to be dated: Wed May 27 09:29:59 UTC 2015.

The ipset `ib_bluetack_level1` has **236319** entries, **765065682** unique IPs.

The following table shows the overlaps of `ib_bluetack_level1` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ib_bluetack_level1`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ib_bluetack_level1`.
- ` this % ` is the percentage **of this ipset (`ib_bluetack_level1`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|16317427|4.6%|2.1%|
[et_block](#et_block)|975|18056513|2133031|11.8%|0.2%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|2133002|11.7%|0.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|1360049|0.9%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|904796|9.8%|0.1%|
[fullbogons](#fullbogons)|3656|670735064|235151|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|33155|7.8%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|13328|3.9%|0.0%|
[alienvault_reputation](#alienvault_reputation)|177044|177044|5207|2.9%|0.0%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92800|92800|1498|1.6%|0.0%|
[blocklist_de](#blocklist_de)|22392|22392|1480|6.6%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14733|14733|1347|9.1%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|12673|12673|1321|10.4%|0.0%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30710|30710|581|1.8%|0.0%|
[nixspam](#nixspam)|26013|26013|506|1.9%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|432|0.8%|0.0%|
[voipbl](#voipbl)|10286|10757|301|2.7%|0.0%|
[openbl_90d](#openbl_90d)|9897|9897|221|2.2%|0.0%|
[openbl](#openbl)|9897|9897|221|2.2%|0.0%|
[openbl_60d](#openbl_60d)|7801|7801|181|2.3%|0.0%|
[et_tor](#et_tor)|6490|6490|165|2.5%|0.0%|
[dm_tor](#dm_tor)|6438|6438|165|2.5%|0.0%|
[bm_tor](#bm_tor)|6436|6436|165|2.5%|0.0%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7580|7580|149|1.9%|0.0%|
[openbl_30d](#openbl_30d)|4449|4449|100|2.2%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|98|6.7%|0.0%|
[ri_web_proxies](#ri_web_proxies)|4267|4267|97|2.2%|0.0%|
[snort_ipfilter](#snort_ipfilter)|7236|7236|92|1.2%|0.0%|
[et_compromised](#et_compromised)|2338|2338|75|3.2%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2415|2415|74|3.0%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|66|5.1%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|1668|1668|59|3.5%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|58|8.6%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2276|2276|51|2.2%|0.0%|
[et_botnet](#et_botnet)|512|512|43|8.3%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3467|3467|37|1.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1350|1350|28|2.0%|0.0%|
[ciarmy](#ciarmy)|394|394|22|5.5%|0.0%|
[openbl_7d](#openbl_7d)|997|997|19|1.9%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|683|683|13|1.9%|0.0%|
[malc0de](#malc0de)|414|414|12|2.8%|0.0%|
[php_dictionary](#php_dictionary)|398|398|9|2.2%|0.0%|
[zeus](#zeus)|266|266|7|2.6%|0.0%|
[php_harvesters](#php_harvesters)|257|257|7|2.7%|0.0%|
[openbl_1d](#openbl_1d)|357|357|7|1.9%|0.0%|
[php_spammers](#php_spammers)|417|417|5|1.1%|0.0%|
[php_commenters](#php_commenters)|281|281|5|1.7%|0.0%|
[php_bad](#php_bad)|281|281|5|1.7%|0.0%|
[bogons](#bogons)|13|592708608|5|0.0%|0.0%|
[zeus_badips](#zeus_badips)|229|229|4|1.7%|0.0%|
[dshield](#dshield)|20|5120|4|0.0%|0.0%|
[clean_mx_viruses](#clean_mx_viruses)|104|104|4|3.8%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|103|103|4|3.8%|0.0%|
[sslbl](#sslbl)|345|345|3|0.8%|0.0%|
[feodo](#feodo)|63|63|3|4.7%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|239|239|2|0.8%|0.0%|

## ib_bluetack_level2

[iBlocklist.com](https://www.iblocklist.com/) free version of BlueTack.co.uk Level 2 (for use in p2p). General corporate ranges. Ranges used by labs or researchers. Proxies.

Source is downloaded from [this link](http://list.iblocklist.com/?list=gyisgnzbhppbvsphucsw&fileformat=p2p&archiveformat=gz).

The last time downloaded was found to be dated: Thu May 28 03:50:51 UTC 2015.

The ipset `ib_bluetack_level2` has **78389** entries, **348732007** unique IPs.

The following table shows the overlaps of `ib_bluetack_level2` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ib_bluetack_level2`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ib_bluetack_level2`.
- ` this % ` is the percentage **of this ipset (`ib_bluetack_level2`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|16317427|2.1%|4.6%|
[et_block](#et_block)|975|18056513|8401703|46.5%|2.4%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|8401434|46.3%|2.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|2832265|2.0%|0.8%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2526625|27.5%|0.7%|
[fullbogons](#fullbogons)|3656|670735064|248327|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|33368|7.9%|0.0%|
[alienvault_reputation](#alienvault_reputation)|177044|177044|8400|4.7%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|7752|2.2%|0.0%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92800|92800|2453|2.6%|0.0%|
[blocklist_de](#blocklist_de)|22392|22392|1439|6.4%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14733|14733|1162|7.8%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|12673|12673|1077|8.4%|0.0%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30710|30710|927|3.0%|0.0%|
[nixspam](#nixspam)|26013|26013|569|2.1%|0.0%|
[openbl_90d](#openbl_90d)|9897|9897|514|5.1%|0.0%|
[openbl](#openbl)|9897|9897|514|5.1%|0.0%|
[voipbl](#voipbl)|10286|10757|428|3.9%|0.0%|
[openbl_60d](#openbl_60d)|7801|7801|365|4.6%|0.0%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7580|7580|251|3.3%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|233|0.4%|0.0%|
[openbl_30d](#openbl_30d)|4449|4449|229|5.1%|0.0%|
[et_tor](#et_tor)|6490|6490|184|2.8%|0.0%|
[dm_tor](#dm_tor)|6438|6438|184|2.8%|0.0%|
[bm_tor](#bm_tor)|6436|6436|184|2.8%|0.0%|
[ri_web_proxies](#ri_web_proxies)|4267|4267|151|3.5%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2415|2415|148|6.1%|0.0%|
[et_compromised](#et_compromised)|2338|2338|143|6.1%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2276|2276|127|5.5%|0.0%|
[snort_ipfilter](#snort_ipfilter)|7236|7236|100|1.3%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3467|3467|76|2.1%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|1668|1668|75|4.4%|0.0%|
[openbl_7d](#openbl_7d)|997|997|50|5.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|45|3.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1350|1350|44|3.2%|0.0%|
[ciarmy](#ciarmy)|394|394|40|10.1%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|683|683|38|5.5%|0.0%|
[php_spammers](#php_spammers)|417|417|31|7.4%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|28|4.1%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|26|2.0%|0.0%|
[malc0de](#malc0de)|414|414|26|6.2%|0.0%|
[et_botnet](#et_botnet)|512|512|21|4.1%|0.0%|
[openbl_1d](#openbl_1d)|357|357|17|4.7%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|239|239|17|7.1%|0.0%|
[zeus](#zeus)|266|266|9|3.3%|0.0%|
[php_dictionary](#php_dictionary)|398|398|9|2.2%|0.0%|
[php_commenters](#php_commenters)|281|281|9|3.2%|0.0%|
[php_bad](#php_bad)|281|281|9|3.2%|0.0%|
[zeus_badips](#zeus_badips)|229|229|8|3.4%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|225|225|8|3.5%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|103|103|8|7.7%|0.0%|
[php_harvesters](#php_harvesters)|257|257|7|2.7%|0.0%|
[sslbl](#sslbl)|345|345|6|1.7%|0.0%|
[clean_mx_viruses](#clean_mx_viruses)|104|104|6|5.7%|0.0%|
[palevo](#palevo)|13|13|3|23.0%|0.0%|
[feodo](#feodo)|63|63|3|4.7%|0.0%|
[shunlist](#shunlist)|51|51|2|3.9%|0.0%|

## ib_bluetack_level3

[iBlocklist.com](https://www.iblocklist.com/) free version of BlueTack.co.uk Level 3 (for use in p2p). Many portal-type websites. ISP ranges that may be dodgy for some reason. Ranges that belong to an individual, but which have not been determined to be used by a particular company. Ranges for things that are unusual in some way. The L3 list is aka the paranoid list.

Source is downloaded from [this link](http://list.iblocklist.com/?list=uwnukjqktoggdknzrhgh&fileformat=p2p&archiveformat=gz).

The last time downloaded was found to be dated: Thu May 28 03:50:11 UTC 2015.

The ipset `ib_bluetack_level3` has **18879** entries, **139109195** unique IPs.

The following table shows the overlaps of `ib_bluetack_level3` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ib_bluetack_level3`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ib_bluetack_level3`.
- ` this % ` is the percentage **of this ipset (`ib_bluetack_level3`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[fullbogons](#fullbogons)|3656|670735064|4233779|0.6%|3.0%|
[bogons](#bogons)|13|592708608|4194304|0.7%|3.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|2832265|0.8%|2.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|1360049|0.1%|0.9%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|270785|64.3%|0.1%|
[et_block](#et_block)|975|18056513|196440|1.0%|0.1%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|195904|1.0%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|145472|1.5%|0.1%|
[alienvault_reputation](#alienvault_reputation)|177044|177044|14946|8.4%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|9278|2.7%|0.0%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92800|92800|6226|6.7%|0.0%|
[blocklist_de](#blocklist_de)|22392|22392|2798|12.4%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14733|14733|2238|15.1%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|12673|12673|2220|17.5%|0.0%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30710|30710|2079|6.7%|0.0%|
[nixspam](#nixspam)|26013|26013|1918|7.3%|0.0%|
[voipbl](#voipbl)|10286|10757|1587|14.7%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1172|2.4%|0.0%|
[openbl_90d](#openbl_90d)|9897|9897|959|9.6%|0.0%|
[openbl](#openbl)|9897|9897|959|9.6%|0.0%|
[openbl_60d](#openbl_60d)|7801|7801|716|9.1%|0.0%|
[dm_tor](#dm_tor)|6438|6438|612|9.5%|0.0%|
[bm_tor](#bm_tor)|6436|6436|611|9.4%|0.0%|
[et_tor](#et_tor)|6490|6490|608|9.3%|0.0%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7580|7580|516|6.8%|0.0%|
[openbl_30d](#openbl_30d)|4449|4449|444|9.9%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2415|2415|232|9.6%|0.0%|
[et_compromised](#et_compromised)|2338|2338|225|9.6%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2276|2276|221|9.7%|0.0%|
[snort_ipfilter](#snort_ipfilter)|7236|7236|214|2.9%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3467|3467|151|4.3%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|146|11.3%|0.0%|
[ri_web_proxies](#ri_web_proxies)|4267|4267|134|3.1%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1350|1350|127|9.4%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|110|7.5%|0.0%|
[openbl_7d](#openbl_7d)|997|997|92|9.2%|0.0%|
[malc0de](#malc0de)|414|414|76|18.3%|0.0%|
[et_botnet](#et_botnet)|512|512|75|14.6%|0.0%|
[ciarmy](#ciarmy)|394|394|72|18.2%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|51|7.5%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|1668|1668|41|2.4%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|683|683|37|5.4%|0.0%|
[php_spammers](#php_spammers)|417|417|26|6.2%|0.0%|
[php_dictionary](#php_dictionary)|398|398|23|5.7%|0.0%|
[sslbl](#sslbl)|345|345|22|6.3%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|103|103|22|21.3%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|239|239|21|8.7%|0.0%|
[zeus](#zeus)|266|266|20|7.5%|0.0%|
[openbl_1d](#openbl_1d)|357|357|20|5.6%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|225|225|17|7.5%|0.0%|
[php_bad](#php_bad)|281|281|16|5.6%|0.0%|
[php_harvesters](#php_harvesters)|257|257|15|5.8%|0.0%|
[php_commenters](#php_commenters)|281|281|15|5.3%|0.0%|
[zeus_badips](#zeus_badips)|229|229|14|6.1%|0.0%|
[clean_mx_viruses](#clean_mx_viruses)|104|104|13|12.5%|0.0%|
[shunlist](#shunlist)|51|51|6|11.7%|0.0%|
[feodo](#feodo)|63|63|3|4.7%|0.0%|
[palevo](#palevo)|13|13|1|7.6%|0.0%|

## ib_bluetack_proxies

[iBlocklist.com](https://www.iblocklist.com/) free version of [BlueTack.co.uk](http://www.bluetack.co.uk/) Open Proxies IPs list (without TOR)

Source is downloaded from [this link](http://list.iblocklist.com/?list=xoebmbyexwuiogmbyprb&fileformat=p2p&archiveformat=gz).

The last time downloaded was found to be dated: Thu May 28 03:50:04 UTC 2015.

The ipset `ib_bluetack_proxies` has **673** entries, **673** unique IPs.

The following table shows the overlaps of `ib_bluetack_proxies` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ib_bluetack_proxies`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ib_bluetack_proxies`.
- ` this % ` is the percentage **of this ipset (`ib_bluetack_proxies`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|58|0.0%|8.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|51|0.0%|7.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|28|0.0%|4.1%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92800|92800|24|0.0%|3.5%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30710|30710|12|0.0%|1.7%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|11|0.0%|1.6%|
[ri_web_proxies](#ri_web_proxies)|4267|4267|10|0.2%|1.4%|
[ri_connect_proxies](#ri_connect_proxies)|1668|1668|6|0.3%|0.8%|
[blocklist_de](#blocklist_de)|22392|22392|3|0.0%|0.4%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|2|0.0%|0.2%|
[nixspam](#nixspam)|26013|26013|2|0.0%|0.2%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2|0.0%|0.2%|
[et_block](#et_block)|975|18056513|2|0.0%|0.2%|
[blocklist_de_mail](#blocklist_de_mail)|14733|14733|2|0.0%|0.2%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7580|7580|1|0.0%|0.1%|
[snort_ipfilter](#snort_ipfilter)|7236|7236|1|0.0%|0.1%|
[php_dictionary](#php_dictionary)|398|398|1|0.2%|0.1%|
[blocklist_de_bots](#blocklist_de_bots)|3467|3467|1|0.0%|0.1%|
[alienvault_reputation](#alienvault_reputation)|177044|177044|1|0.0%|0.1%|

## ib_bluetack_spyware

[iBlocklist.com](https://www.iblocklist.com/) free version of [BlueTack.co.uk](http://www.bluetack.co.uk/) known malicious SPYWARE and ADWARE IP Address ranges

Source is downloaded from [this link](http://list.iblocklist.com/?list=llvtlsjyoyiczbkjsxpf&fileformat=p2p&archiveformat=gz).

The last time downloaded was found to be dated: Thu May 28 03:20:02 UTC 2015.

The ipset `ib_bluetack_spyware` has **3339** entries, **339461** unique IPs.

The following table shows the overlaps of `ib_bluetack_spyware` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ib_bluetack_spyware`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ib_bluetack_spyware`.
- ` this % ` is the percentage **of this ipset (`ib_bluetack_spyware`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|13328|0.0%|3.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|9278|0.0%|2.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|7752|0.0%|2.2%|
[et_block](#et_block)|975|18056513|1044|0.0%|0.3%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|1037|0.0%|0.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1036|0.0%|0.3%|
[fullbogons](#fullbogons)|3656|670735064|894|0.0%|0.2%|
[alienvault_reputation](#alienvault_reputation)|177044|177044|293|0.1%|0.0%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92800|92800|46|0.0%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|25|1.9%|0.0%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30710|30710|22|0.0%|0.0%|
[et_tor](#et_tor)|6490|6490|21|0.3%|0.0%|
[dm_tor](#dm_tor)|6438|6438|21|0.3%|0.0%|
[bm_tor](#bm_tor)|6436|6436|21|0.3%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|19|1.3%|0.0%|
[snort_ipfilter](#snort_ipfilter)|7236|7236|15|0.2%|0.0%|
[nixspam](#nixspam)|26013|26013|10|0.0%|0.0%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7580|7580|9|0.1%|0.0%|
[blocklist_de](#blocklist_de)|22392|22392|7|0.0%|0.0%|
[openbl_90d](#openbl_90d)|9897|9897|6|0.0%|0.0%|
[openbl](#openbl)|9897|9897|6|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|6|0.0%|0.0%|
[openbl_60d](#openbl_60d)|7801|7801|5|0.0%|0.0%|
[voipbl](#voipbl)|10286|10757|4|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|4267|4267|4|0.0%|0.0%|
[openbl_30d](#openbl_30d)|4449|4449|4|0.0%|0.0%|
[dshield](#dshield)|20|5120|4|0.0%|0.0%|
[malc0de](#malc0de)|414|414|3|0.7%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|12673|12673|3|0.0%|0.0%|
[palevo](#palevo)|13|13|2|15.3%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2276|2276|2|0.0%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|103|103|2|1.9%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14733|14733|2|0.0%|0.0%|
[zeus_badips](#zeus_badips)|229|229|1|0.4%|0.0%|
[zeus](#zeus)|266|266|1|0.3%|0.0%|
[sslbl](#sslbl)|345|345|1|0.2%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|1|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.0%|
[php_dictionary](#php_dictionary)|398|398|1|0.2%|0.0%|
[openbl_7d](#openbl_7d)|997|997|1|0.1%|0.0%|
[feodo](#feodo)|63|63|1|1.5%|0.0%|
[bogons](#bogons)|13|592708608|1|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1350|1350|1|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3467|3467|1|0.0%|0.0%|

## ib_bluetack_webexploit

[iBlocklist.com](https://www.iblocklist.com/) free version of [BlueTack.co.uk](http://www.bluetack.co.uk/) web server hack and exploit attempts

Source is downloaded from [this link](http://list.iblocklist.com/?list=ghlzqtqxnzctvvajwwag&fileformat=p2p&archiveformat=gz).

The last time downloaded was found to be dated: Thu May 28 03:20:17 UTC 2015.

The ipset `ib_bluetack_webexploit` has **1460** entries, **1460** unique IPs.

The following table shows the overlaps of `ib_bluetack_webexploit` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ib_bluetack_webexploit`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ib_bluetack_webexploit`.
- ` this % ` is the percentage **of this ipset (`ib_bluetack_webexploit`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|110|0.0%|7.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|98|0.0%|6.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|45|0.0%|3.0%|
[fullbogons](#fullbogons)|3656|670735064|33|0.0%|2.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|19|0.0%|1.3%|
[alienvault_reputation](#alienvault_reputation)|177044|177044|8|0.0%|0.5%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|7|0.0%|0.4%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|6|0.0%|0.4%|
[et_block](#et_block)|975|18056513|6|0.0%|0.4%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|3|0.2%|0.2%|
[blocklist_de](#blocklist_de)|22392|22392|3|0.0%|0.2%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30710|30710|2|0.0%|0.1%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92800|92800|2|0.0%|0.1%|
[snort_ipfilter](#snort_ipfilter)|7236|7236|2|0.0%|0.1%|
[openbl_90d](#openbl_90d)|9897|9897|2|0.0%|0.1%|
[openbl_60d](#openbl_60d)|7801|7801|2|0.0%|0.1%|
[openbl_30d](#openbl_30d)|4449|4449|2|0.0%|0.1%|
[openbl](#openbl)|9897|9897|2|0.0%|0.1%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|2|0.2%|0.1%|
[bruteforceblocker](#bruteforceblocker)|2415|2415|2|0.0%|0.1%|
[blocklist_de_ssh](#blocklist_de_ssh)|2276|2276|2|0.0%|0.1%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7580|7580|1|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|4267|4267|1|0.0%|0.0%|
[openbl_7d](#openbl_7d)|997|997|1|0.1%|0.0%|
[openbl_1d](#openbl_1d)|357|357|1|0.2%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1|0.0%|0.0%|
[et_tor](#et_tor)|6490|6490|1|0.0%|0.0%|
[et_compromised](#et_compromised)|2338|2338|1|0.0%|0.0%|
[et_botnet](#et_botnet)|512|512|1|0.1%|0.0%|
[dm_tor](#dm_tor)|6438|6438|1|0.0%|0.0%|
[bm_tor](#bm_tor)|6436|6436|1|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|225|225|1|0.4%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3467|3467|1|0.0%|0.0%|

## malc0de

[Malc0de.com](http://malc0de.com) malicious IPs of the last 30 days

Source is downloaded from [this link](http://malc0de.com/bl/IP_Blacklist.txt).

The last time downloaded was found to be dated: Wed May 27 13:17:02 UTC 2015.

The ipset `malc0de` has **414** entries, **414** unique IPs.

The following table shows the overlaps of `malc0de` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `malc0de`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `malc0de`.
- ` this % ` is the percentage **of this ipset (`malc0de`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|76|0.0%|18.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|26|0.0%|6.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|12|0.0%|2.8%|
[clean_mx_viruses](#clean_mx_viruses)|104|104|11|10.5%|2.6%|
[alienvault_reputation](#alienvault_reputation)|177044|177044|10|0.0%|2.4%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|4|0.3%|0.9%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|3|0.0%|0.7%|
[et_block](#et_block)|975|18056513|3|0.0%|0.7%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|2|0.0%|0.4%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|1|0.0%|0.2%|

## malwaredomainlist

[malwaredomainlist.com](http://www.malwaredomainlist.com) list of malware active ip addresses

Source is downloaded from [this link](http://www.malwaredomainlist.com/hostslist/ip.txt).

The last time downloaded was found to be dated: Thu May 14 20:46:41 UTC 2015.

The ipset `malwaredomainlist` has **1283** entries, **1283** unique IPs.

The following table shows the overlaps of `malwaredomainlist` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `malwaredomainlist`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `malwaredomainlist`.
- ` this % ` is the percentage **of this ipset (`malwaredomainlist`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|146|0.0%|11.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|66|0.0%|5.1%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|28|0.0%|2.1%|
[et_block](#et_block)|975|18056513|28|0.0%|2.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|27|0.0%|2.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|26|0.0%|2.0%|
[snort_ipfilter](#snort_ipfilter)|7236|7236|25|0.3%|1.9%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|25|0.0%|1.9%|
[fullbogons](#fullbogons)|3656|670735064|9|0.0%|0.7%|
[alienvault_reputation](#alienvault_reputation)|177044|177044|6|0.0%|0.4%|
[malc0de](#malc0de)|414|414|4|0.9%|0.3%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|3|0.2%|0.2%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92800|92800|2|0.0%|0.1%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30710|30710|1|0.0%|0.0%|
[et_botnet](#et_botnet)|512|512|1|0.1%|0.0%|
[clean_mx_viruses](#clean_mx_viruses)|104|104|1|0.9%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3467|3467|1|0.0%|0.0%|
[blocklist_de](#blocklist_de)|22392|22392|1|0.0%|0.0%|

## nixspam

[NiX Spam](http://www.heise.de/ix/NiX-Spam-DNSBL-and-blacklist-for-download-499637.html) IP addresses that sent spam in the last hour - automatically generated entries without distinguishing open proxies from relays, dialup gateways, and so on. All IPs are removed after 12 hours if there is no spam from there.

Source is downloaded from [this link](http://www.dnsbl.manitu.net/download/nixspam-ip.dump.gz).

The last time downloaded was found to be dated: Thu May 28 09:30:02 UTC 2015.

The ipset `nixspam` has **26013** entries, **26013** unique IPs.

The following table shows the overlaps of `nixspam` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `nixspam`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `nixspam`.
- ` this % ` is the percentage **of this ipset (`nixspam`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|1918|0.0%|7.3%|
[blocklist_de](#blocklist_de)|22392|22392|585|2.6%|2.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|569|0.0%|2.1%|
[blocklist_de_mail](#blocklist_de_mail)|14733|14733|525|3.5%|2.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|506|0.0%|1.9%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92800|92800|244|0.2%|0.9%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|201|0.0%|0.7%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|193|0.0%|0.7%|
[et_block](#et_block)|975|18056513|193|0.0%|0.7%|
[snort_ipfilter](#snort_ipfilter)|7236|7236|154|2.1%|0.5%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30710|30710|141|0.4%|0.5%|
[php_dictionary](#php_dictionary)|398|398|94|23.6%|0.3%|
[php_spammers](#php_spammers)|417|417|78|18.7%|0.2%|
[ri_web_proxies](#ri_web_proxies)|4267|4267|77|1.8%|0.2%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7580|7580|56|0.7%|0.2%|
[blocklist_de_bots](#blocklist_de_bots)|3467|3467|50|1.4%|0.1%|
[alienvault_reputation](#alienvault_reputation)|177044|177044|36|0.0%|0.1%|
[php_commenters](#php_commenters)|281|281|16|5.6%|0.0%|
[php_bad](#php_bad)|281|281|15|5.3%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|1668|1668|12|0.7%|0.0%|
[openbl_90d](#openbl_90d)|9897|9897|10|0.1%|0.0%|
[openbl](#openbl)|9897|9897|10|0.1%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|10|0.0%|0.0%|
[openbl_60d](#openbl_60d)|7801|7801|9|0.1%|0.0%|
[php_harvesters](#php_harvesters)|257|257|7|2.7%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|5|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|683|683|5|0.7%|0.0%|
[openbl_30d](#openbl_30d)|4449|4449|4|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|239|239|4|1.6%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1350|1350|4|0.2%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|12673|12673|4|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|2|0.2%|0.0%|
[et_tor](#et_tor)|6490|6490|2|0.0%|0.0%|
[dm_tor](#dm_tor)|6438|6438|2|0.0%|0.0%|
[bm_tor](#bm_tor)|6436|6436|2|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2276|2276|2|0.0%|0.0%|
[voipbl](#voipbl)|10286|10757|1|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|1|0.0%|0.0%|
[dshield](#dshield)|20|5120|1|0.0%|0.0%|

## openbl

[OpenBL.org](http://www.openbl.org/) default blacklist (currently it is the same with 90 days). OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications - **excellent list**

Source is downloaded from [this link](http://www.openbl.org/lists/base.txt.gz).

The last time downloaded was found to be dated: Thu May 28 07:17:00 UTC 2015.

The ipset `openbl` has **9897** entries, **9897** unique IPs.

The following table shows the overlaps of `openbl` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl`.
- ` this % ` is the percentage **of this ipset (`openbl`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[openbl_90d](#openbl_90d)|9897|9897|9897|100.0%|100.0%|
[alienvault_reputation](#alienvault_reputation)|177044|177044|9865|5.5%|99.6%|
[openbl_60d](#openbl_60d)|7801|7801|7801|100.0%|78.8%|
[openbl_30d](#openbl_30d)|4449|4449|4449|100.0%|44.9%|
[bruteforceblocker](#bruteforceblocker)|2415|2415|1421|58.8%|14.3%|
[et_compromised](#et_compromised)|2338|2338|1392|59.5%|14.0%|
[blocklist_de](#blocklist_de)|22392|22392|1347|6.0%|13.6%|
[blocklist_de_ssh](#blocklist_de_ssh)|2276|2276|1266|55.6%|12.7%|
[openbl_7d](#openbl_7d)|997|997|997|100.0%|10.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|959|0.0%|9.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|514|0.0%|5.1%|
[et_block](#et_block)|975|18056513|455|0.0%|4.5%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|447|0.0%|4.5%|
[openbl_1d](#openbl_1d)|357|357|357|100.0%|3.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|221|0.0%|2.2%|
[dshield](#dshield)|20|5120|164|3.2%|1.6%|
[blocklist_de_strongips](#blocklist_de_strongips)|225|225|76|33.7%|0.7%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92800|92800|70|0.0%|0.7%|
[blocklist_de_mail](#blocklist_de_mail)|14733|14733|57|0.3%|0.5%|
[blocklist_de_imap](#blocklist_de_imap)|683|683|49|7.1%|0.4%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30710|30710|36|0.1%|0.3%|
[snort_ipfilter](#snort_ipfilter)|7236|7236|25|0.3%|0.2%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7580|7580|23|0.3%|0.2%|
[et_tor](#et_tor)|6490|6490|21|0.3%|0.2%|
[dm_tor](#dm_tor)|6438|6438|21|0.3%|0.2%|
[bm_tor](#bm_tor)|6436|6436|21|0.3%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|19|0.0%|0.1%|
[blocklist_de_apache](#blocklist_de_apache)|12673|12673|15|0.1%|0.1%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|14|0.0%|0.1%|
[voipbl](#voipbl)|10286|10757|11|0.1%|0.1%|
[shunlist](#shunlist)|51|51|10|19.6%|0.1%|
[nixspam](#nixspam)|26013|26013|10|0.0%|0.1%|
[php_commenters](#php_commenters)|281|281|8|2.8%|0.0%|
[php_bad](#php_bad)|281|281|8|2.8%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|239|239|7|2.9%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|6|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1350|1350|6|0.4%|0.0%|
[php_harvesters](#php_harvesters)|257|257|5|1.9%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3467|3467|3|0.0%|0.0%|
[zeus](#zeus)|266|266|2|0.7%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.0%|
[zeus_badips](#zeus_badips)|229|229|1|0.4%|0.0%|
[sslbl](#sslbl)|345|345|1|0.2%|0.0%|
[ri_web_proxies](#ri_web_proxies)|4267|4267|1|0.0%|0.0%|
[ciarmy](#ciarmy)|394|394|1|0.2%|0.0%|

## openbl_1d

[OpenBL.org](http://www.openbl.org/) last 24 hours IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.

Source is downloaded from [this link](http://www.openbl.org/lists/base_1days.txt.gz).

The last time downloaded was found to be dated: Wed May 20 19:07:00 UTC 2015.

The ipset `openbl_1d` has **357** entries, **357** unique IPs.

The following table shows the overlaps of `openbl_1d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl_1d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl_1d`.
- ` this % ` is the percentage **of this ipset (`openbl_1d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[openbl_90d](#openbl_90d)|9897|9897|357|3.6%|100.0%|
[openbl_60d](#openbl_60d)|7801|7801|357|4.5%|100.0%|
[openbl_30d](#openbl_30d)|4449|4449|357|8.0%|100.0%|
[openbl](#openbl)|9897|9897|357|3.6%|100.0%|
[alienvault_reputation](#alienvault_reputation)|177044|177044|355|0.2%|99.4%|
[blocklist_de](#blocklist_de)|22392|22392|246|1.0%|68.9%|
[blocklist_de_ssh](#blocklist_de_ssh)|2276|2276|235|10.3%|65.8%|
[et_compromised](#et_compromised)|2338|2338|207|8.8%|57.9%|
[openbl_7d](#openbl_7d)|997|997|206|20.6%|57.7%|
[bruteforceblocker](#bruteforceblocker)|2415|2415|203|8.4%|56.8%|
[blocklist_de_strongips](#blocklist_de_strongips)|225|225|68|30.2%|19.0%|
[dshield](#dshield)|20|5120|45|0.8%|12.6%|
[et_block](#et_block)|975|18056513|27|0.0%|7.5%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|26|0.0%|7.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|20|0.0%|5.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|17|0.0%|4.7%|
[blocklist_de_mail](#blocklist_de_mail)|14733|14733|10|0.0%|2.8%|
[blocklist_de_imap](#blocklist_de_imap)|683|683|9|1.3%|2.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|7|0.0%|1.9%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|5|0.0%|1.4%|
[shunlist](#shunlist)|51|51|2|3.9%|0.5%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92800|92800|1|0.0%|0.2%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|1|0.0%|0.2%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.2%|
[blocklist_de_ftp](#blocklist_de_ftp)|239|239|1|0.4%|0.2%|

## openbl_30d

[OpenBL.org](http://www.openbl.org/) last 30 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.

Source is downloaded from [this link](http://www.openbl.org/lists/base_30days.txt.gz).

The last time downloaded was found to be dated: Thu May 28 07:17:00 UTC 2015.

The ipset `openbl_30d` has **4449** entries, **4449** unique IPs.

The following table shows the overlaps of `openbl_30d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl_30d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl_30d`.
- ` this % ` is the percentage **of this ipset (`openbl_30d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[openbl_90d](#openbl_90d)|9897|9897|4449|44.9%|100.0%|
[openbl_60d](#openbl_60d)|7801|7801|4449|57.0%|100.0%|
[openbl](#openbl)|9897|9897|4449|44.9%|100.0%|
[alienvault_reputation](#alienvault_reputation)|177044|177044|4428|2.5%|99.5%|
[bruteforceblocker](#bruteforceblocker)|2415|2415|1346|55.7%|30.2%|
[et_compromised](#et_compromised)|2338|2338|1324|56.6%|29.7%|
[blocklist_de](#blocklist_de)|22392|22392|1190|5.3%|26.7%|
[blocklist_de_ssh](#blocklist_de_ssh)|2276|2276|1135|49.8%|25.5%|
[openbl_7d](#openbl_7d)|997|997|997|100.0%|22.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|444|0.0%|9.9%|
[openbl_1d](#openbl_1d)|357|357|357|100.0%|8.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|229|0.0%|5.1%|
[et_block](#et_block)|975|18056513|213|0.0%|4.7%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|208|0.0%|4.6%|
[dshield](#dshield)|20|5120|141|2.7%|3.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|100|0.0%|2.2%|
[blocklist_de_strongips](#blocklist_de_strongips)|225|225|74|32.8%|1.6%|
[blocklist_de_mail](#blocklist_de_mail)|14733|14733|47|0.3%|1.0%|
[blocklist_de_imap](#blocklist_de_imap)|683|683|41|6.0%|0.9%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92800|92800|21|0.0%|0.4%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|13|0.0%|0.2%|
[shunlist](#shunlist)|51|51|9|17.6%|0.2%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30710|30710|7|0.0%|0.1%|
[blocklist_de_apache](#blocklist_de_apache)|12673|12673|7|0.0%|0.1%|
[nixspam](#nixspam)|26013|26013|4|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|4|0.0%|0.0%|
[voipbl](#voipbl)|10286|10757|3|0.0%|0.0%|
[zeus](#zeus)|266|266|2|0.7%|0.0%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7580|7580|2|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|7236|7236|2|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|239|239|2|0.8%|0.0%|
[zeus_badips](#zeus_badips)|229|229|1|0.4%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|1|0.0%|0.0%|
[ciarmy](#ciarmy)|394|394|1|0.2%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1350|1350|1|0.0%|0.0%|

## openbl_60d

[OpenBL.org](http://www.openbl.org/) last 60 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.

Source is downloaded from [this link](http://www.openbl.org/lists/base_60days.txt.gz).

The last time downloaded was found to be dated: Thu May 28 07:17:00 UTC 2015.

The ipset `openbl_60d` has **7801** entries, **7801** unique IPs.

The following table shows the overlaps of `openbl_60d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl_60d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl_60d`.
- ` this % ` is the percentage **of this ipset (`openbl_60d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[openbl_90d](#openbl_90d)|9897|9897|7801|78.8%|100.0%|
[openbl](#openbl)|9897|9897|7801|78.8%|100.0%|
[alienvault_reputation](#alienvault_reputation)|177044|177044|7772|4.3%|99.6%|
[openbl_30d](#openbl_30d)|4449|4449|4449|100.0%|57.0%|
[bruteforceblocker](#bruteforceblocker)|2415|2415|1404|58.1%|17.9%|
[et_compromised](#et_compromised)|2338|2338|1381|59.0%|17.7%|
[blocklist_de](#blocklist_de)|22392|22392|1288|5.7%|16.5%|
[blocklist_de_ssh](#blocklist_de_ssh)|2276|2276|1221|53.6%|15.6%|
[openbl_7d](#openbl_7d)|997|997|997|100.0%|12.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|716|0.0%|9.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|365|0.0%|4.6%|
[openbl_1d](#openbl_1d)|357|357|357|100.0%|4.5%|
[et_block](#et_block)|975|18056513|300|0.0%|3.8%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|294|0.0%|3.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|181|0.0%|2.3%|
[dshield](#dshield)|20|5120|151|2.9%|1.9%|
[blocklist_de_strongips](#blocklist_de_strongips)|225|225|75|33.3%|0.9%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92800|92800|63|0.0%|0.8%|
[blocklist_de_mail](#blocklist_de_mail)|14733|14733|53|0.3%|0.6%|
[blocklist_de_imap](#blocklist_de_imap)|683|683|45|6.5%|0.5%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30710|30710|34|0.1%|0.4%|
[snort_ipfilter](#snort_ipfilter)|7236|7236|25|0.3%|0.3%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7580|7580|22|0.2%|0.2%|
[et_tor](#et_tor)|6490|6490|21|0.3%|0.2%|
[dm_tor](#dm_tor)|6438|6438|21|0.3%|0.2%|
[bm_tor](#bm_tor)|6436|6436|21|0.3%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|18|0.0%|0.2%|
[shunlist](#shunlist)|51|51|10|19.6%|0.1%|
[blocklist_de_apache](#blocklist_de_apache)|12673|12673|10|0.0%|0.1%|
[voipbl](#voipbl)|10286|10757|9|0.0%|0.1%|
[nixspam](#nixspam)|26013|26013|9|0.0%|0.1%|
[php_commenters](#php_commenters)|281|281|8|2.8%|0.1%|
[php_bad](#php_bad)|281|281|8|2.8%|0.1%|
[php_harvesters](#php_harvesters)|257|257|5|1.9%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|5|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|239|239|5|2.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1350|1350|3|0.2%|0.0%|
[zeus](#zeus)|266|266|2|0.7%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.0%|
[zeus_badips](#zeus_badips)|229|229|1|0.4%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|1|0.0%|0.0%|
[ciarmy](#ciarmy)|394|394|1|0.2%|0.0%|

## openbl_7d

[OpenBL.org](http://www.openbl.org/) last 7 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.

Source is downloaded from [this link](http://www.openbl.org/lists/base_7days.txt.gz).

The last time downloaded was found to be dated: Thu May 28 07:17:00 UTC 2015.

The ipset `openbl_7d` has **997** entries, **997** unique IPs.

The following table shows the overlaps of `openbl_7d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl_7d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl_7d`.
- ` this % ` is the percentage **of this ipset (`openbl_7d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[openbl_90d](#openbl_90d)|9897|9897|997|10.0%|100.0%|
[openbl_60d](#openbl_60d)|7801|7801|997|12.7%|100.0%|
[openbl_30d](#openbl_30d)|4449|4449|997|22.4%|100.0%|
[openbl](#openbl)|9897|9897|997|10.0%|100.0%|
[alienvault_reputation](#alienvault_reputation)|177044|177044|981|0.5%|98.3%|
[blocklist_de](#blocklist_de)|22392|22392|676|3.0%|67.8%|
[blocklist_de_ssh](#blocklist_de_ssh)|2276|2276|644|28.2%|64.5%|
[bruteforceblocker](#bruteforceblocker)|2415|2415|512|21.2%|51.3%|
[et_compromised](#et_compromised)|2338|2338|498|21.3%|49.9%|
[openbl_1d](#openbl_1d)|357|357|206|57.7%|20.6%|
[dshield](#dshield)|20|5120|116|2.2%|11.6%|
[et_block](#et_block)|975|18056513|100|0.0%|10.0%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|97|0.0%|9.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|92|0.0%|9.2%|
[blocklist_de_strongips](#blocklist_de_strongips)|225|225|74|32.8%|7.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|50|0.0%|5.0%|
[blocklist_de_mail](#blocklist_de_mail)|14733|14733|27|0.1%|2.7%|
[blocklist_de_imap](#blocklist_de_imap)|683|683|26|3.8%|2.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|19|0.0%|1.9%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|9|0.0%|0.9%|
[shunlist](#shunlist)|51|51|5|9.8%|0.5%|
[blocklist_de_apache](#blocklist_de_apache)|12673|12673|4|0.0%|0.4%|
[voipbl](#voipbl)|10286|10757|2|0.0%|0.2%|
[zeus](#zeus)|266|266|1|0.3%|0.1%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92800|92800|1|0.0%|0.1%|
[snort_ipfilter](#snort_ipfilter)|7236|7236|1|0.0%|0.1%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|1|0.0%|0.1%|
[ciarmy](#ciarmy)|394|394|1|0.2%|0.1%|
[blocklist_de_ftp](#blocklist_de_ftp)|239|239|1|0.4%|0.1%|

## openbl_90d

[OpenBL.org](http://www.openbl.org/) last 90 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.

Source is downloaded from [this link](http://www.openbl.org/lists/base_90days.txt.gz).

The last time downloaded was found to be dated: Thu May 28 07:17:00 UTC 2015.

The ipset `openbl_90d` has **9897** entries, **9897** unique IPs.

The following table shows the overlaps of `openbl_90d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl_90d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl_90d`.
- ` this % ` is the percentage **of this ipset (`openbl_90d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[openbl](#openbl)|9897|9897|9897|100.0%|100.0%|
[alienvault_reputation](#alienvault_reputation)|177044|177044|9865|5.5%|99.6%|
[openbl_60d](#openbl_60d)|7801|7801|7801|100.0%|78.8%|
[openbl_30d](#openbl_30d)|4449|4449|4449|100.0%|44.9%|
[bruteforceblocker](#bruteforceblocker)|2415|2415|1421|58.8%|14.3%|
[et_compromised](#et_compromised)|2338|2338|1392|59.5%|14.0%|
[blocklist_de](#blocklist_de)|22392|22392|1347|6.0%|13.6%|
[blocklist_de_ssh](#blocklist_de_ssh)|2276|2276|1266|55.6%|12.7%|
[openbl_7d](#openbl_7d)|997|997|997|100.0%|10.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|959|0.0%|9.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|514|0.0%|5.1%|
[et_block](#et_block)|975|18056513|455|0.0%|4.5%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|447|0.0%|4.5%|
[openbl_1d](#openbl_1d)|357|357|357|100.0%|3.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|221|0.0%|2.2%|
[dshield](#dshield)|20|5120|164|3.2%|1.6%|
[blocklist_de_strongips](#blocklist_de_strongips)|225|225|76|33.7%|0.7%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92800|92800|70|0.0%|0.7%|
[blocklist_de_mail](#blocklist_de_mail)|14733|14733|57|0.3%|0.5%|
[blocklist_de_imap](#blocklist_de_imap)|683|683|49|7.1%|0.4%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30710|30710|36|0.1%|0.3%|
[snort_ipfilter](#snort_ipfilter)|7236|7236|25|0.3%|0.2%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7580|7580|23|0.3%|0.2%|
[et_tor](#et_tor)|6490|6490|21|0.3%|0.2%|
[dm_tor](#dm_tor)|6438|6438|21|0.3%|0.2%|
[bm_tor](#bm_tor)|6436|6436|21|0.3%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|19|0.0%|0.1%|
[blocklist_de_apache](#blocklist_de_apache)|12673|12673|15|0.1%|0.1%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|14|0.0%|0.1%|
[voipbl](#voipbl)|10286|10757|11|0.1%|0.1%|
[shunlist](#shunlist)|51|51|10|19.6%|0.1%|
[nixspam](#nixspam)|26013|26013|10|0.0%|0.1%|
[php_commenters](#php_commenters)|281|281|8|2.8%|0.0%|
[php_bad](#php_bad)|281|281|8|2.8%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|239|239|7|2.9%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|6|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1350|1350|6|0.4%|0.0%|
[php_harvesters](#php_harvesters)|257|257|5|1.9%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3467|3467|3|0.0%|0.0%|
[zeus](#zeus)|266|266|2|0.7%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.0%|
[zeus_badips](#zeus_badips)|229|229|1|0.4%|0.0%|
[sslbl](#sslbl)|345|345|1|0.2%|0.0%|
[ri_web_proxies](#ri_web_proxies)|4267|4267|1|0.0%|0.0%|
[ciarmy](#ciarmy)|394|394|1|0.2%|0.0%|

## palevo

[Abuse.ch Palevo tracker](https://palevotracker.abuse.ch) worm includes IPs which are being used as botnet C&C for the Palevo crimeware - **excellent list**

Source is downloaded from [this link](https://palevotracker.abuse.ch/blocklists.php?download=ipblocklist).

The last time downloaded was found to be dated: Thu May 28 09:40:12 UTC 2015.

The ipset `palevo` has **13** entries, **13** unique IPs.

The following table shows the overlaps of `palevo` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `palevo`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `palevo`.
- ` this % ` is the percentage **of this ipset (`palevo`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[et_block](#et_block)|975|18056513|12|0.0%|92.3%|
[snort_ipfilter](#snort_ipfilter)|7236|7236|11|0.1%|84.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|3|0.0%|23.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|2|0.0%|15.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|1|0.0%|7.6%|

## php_bad

[projecthoneypot.org](http://www.projecthoneypot.org/) bad web hosts (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=b&rss=1).

The last time downloaded was found to be dated: Thu May 28 09:20:26 UTC 2015.

The ipset `php_bad` has **281** entries, **281** unique IPs.

The following table shows the overlaps of `php_bad` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `php_bad`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `php_bad`.
- ` this % ` is the percentage **of this ipset (`php_bad`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[php_commenters](#php_commenters)|281|281|279|99.2%|99.2%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92800|92800|193|0.2%|68.6%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30710|30710|190|0.6%|67.6%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7580|7580|113|1.4%|40.2%|
[blocklist_de](#blocklist_de)|22392|22392|80|0.3%|28.4%|
[blocklist_de_bots](#blocklist_de_bots)|3467|3467|66|1.9%|23.4%|
[snort_ipfilter](#snort_ipfilter)|7236|7236|42|0.5%|14.9%|
[blocklist_de_strongips](#blocklist_de_strongips)|225|225|34|15.1%|12.0%|
[php_spammers](#php_spammers)|417|417|32|7.6%|11.3%|
[et_tor](#et_tor)|6490|6490|29|0.4%|10.3%|
[dm_tor](#dm_tor)|6438|6438|29|0.4%|10.3%|
[bm_tor](#bm_tor)|6436|6436|29|0.4%|10.3%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|25|0.0%|8.8%|
[et_block](#et_block)|975|18056513|24|0.0%|8.5%|
[blocklist_de_apache](#blocklist_de_apache)|12673|12673|24|0.1%|8.5%|
[php_dictionary](#php_dictionary)|398|398|21|5.2%|7.4%|
[blocklist_de_mail](#blocklist_de_mail)|14733|14733|20|0.1%|7.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|16|0.0%|5.6%|
[nixspam](#nixspam)|26013|26013|15|0.0%|5.3%|
[alienvault_reputation](#alienvault_reputation)|177044|177044|12|0.0%|4.2%|
[php_harvesters](#php_harvesters)|257|257|9|3.5%|3.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|9|0.0%|3.2%|
[openbl_90d](#openbl_90d)|9897|9897|8|0.0%|2.8%|
[openbl_60d](#openbl_60d)|7801|7801|8|0.1%|2.8%|
[openbl](#openbl)|9897|9897|8|0.0%|2.8%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|7|0.0%|2.4%|
[ri_web_proxies](#ri_web_proxies)|4267|4267|7|0.1%|2.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|5|0.0%|1.7%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1350|1350|4|0.2%|1.4%|
[zeus_badips](#zeus_badips)|229|229|1|0.4%|0.3%|
[zeus](#zeus)|266|266|1|0.3%|0.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.3%|

## php_commenters

[projecthoneypot.org](http://www.projecthoneypot.org/) comment spammers (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=c&rss=1).

The last time downloaded was found to be dated: Thu May 28 09:20:27 UTC 2015.

The ipset `php_commenters` has **281** entries, **281** unique IPs.

The following table shows the overlaps of `php_commenters` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `php_commenters`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `php_commenters`.
- ` this % ` is the percentage **of this ipset (`php_commenters`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[php_bad](#php_bad)|281|281|279|99.2%|99.2%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92800|92800|194|0.2%|69.0%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30710|30710|191|0.6%|67.9%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7580|7580|113|1.4%|40.2%|
[blocklist_de](#blocklist_de)|22392|22392|81|0.3%|28.8%|
[blocklist_de_bots](#blocklist_de_bots)|3467|3467|66|1.9%|23.4%|
[snort_ipfilter](#snort_ipfilter)|7236|7236|41|0.5%|14.5%|
[blocklist_de_strongips](#blocklist_de_strongips)|225|225|34|15.1%|12.0%|
[php_spammers](#php_spammers)|417|417|32|7.6%|11.3%|
[et_tor](#et_tor)|6490|6490|29|0.4%|10.3%|
[dm_tor](#dm_tor)|6438|6438|29|0.4%|10.3%|
[bm_tor](#bm_tor)|6436|6436|29|0.4%|10.3%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|25|0.0%|8.8%|
[et_block](#et_block)|975|18056513|24|0.0%|8.5%|
[blocklist_de_apache](#blocklist_de_apache)|12673|12673|24|0.1%|8.5%|
[php_dictionary](#php_dictionary)|398|398|21|5.2%|7.4%|
[blocklist_de_mail](#blocklist_de_mail)|14733|14733|21|0.1%|7.4%|
[nixspam](#nixspam)|26013|26013|16|0.0%|5.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|15|0.0%|5.3%|
[alienvault_reputation](#alienvault_reputation)|177044|177044|12|0.0%|4.2%|
[php_harvesters](#php_harvesters)|257|257|9|3.5%|3.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|9|0.0%|3.2%|
[openbl_90d](#openbl_90d)|9897|9897|8|0.0%|2.8%|
[openbl_60d](#openbl_60d)|7801|7801|8|0.1%|2.8%|
[openbl](#openbl)|9897|9897|8|0.0%|2.8%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|7|0.0%|2.4%|
[ri_web_proxies](#ri_web_proxies)|4267|4267|7|0.1%|2.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|5|0.0%|1.7%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1350|1350|4|0.2%|1.4%|
[zeus_badips](#zeus_badips)|229|229|1|0.4%|0.3%|
[zeus](#zeus)|266|266|1|0.3%|0.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.3%|

## php_dictionary

[projecthoneypot.org](http://www.projecthoneypot.org/) directory attackers (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=d&rss=1).

The last time downloaded was found to be dated: Thu May 28 09:20:29 UTC 2015.

The ipset `php_dictionary` has **398** entries, **398** unique IPs.

The following table shows the overlaps of `php_dictionary` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `php_dictionary`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `php_dictionary`.
- ` this % ` is the percentage **of this ipset (`php_dictionary`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[nixspam](#nixspam)|26013|26013|94|0.3%|23.6%|
[php_spammers](#php_spammers)|417|417|81|19.4%|20.3%|
[blocklist_de](#blocklist_de)|22392|22392|69|0.3%|17.3%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92800|92800|61|0.0%|15.3%|
[snort_ipfilter](#snort_ipfilter)|7236|7236|61|0.8%|15.3%|
[blocklist_de_mail](#blocklist_de_mail)|14733|14733|59|0.4%|14.8%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30710|30710|53|0.1%|13.3%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7580|7580|26|0.3%|6.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|23|0.0%|5.7%|
[php_commenters](#php_commenters)|281|281|21|7.4%|5.2%|
[php_bad](#php_bad)|281|281|21|7.4%|5.2%|
[ri_web_proxies](#ri_web_proxies)|4267|4267|20|0.4%|5.0%|
[blocklist_de_bots](#blocklist_de_bots)|3467|3467|10|0.2%|2.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|9|0.0%|2.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|9|0.0%|2.2%|
[alienvault_reputation](#alienvault_reputation)|177044|177044|7|0.0%|1.7%|
[dm_tor](#dm_tor)|6438|6438|4|0.0%|1.0%|
[bm_tor](#bm_tor)|6436|6436|4|0.0%|1.0%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|3|0.0%|0.7%|
[et_tor](#et_tor)|6490|6490|3|0.0%|0.7%|
[et_block](#et_block)|975|18056513|3|0.0%|0.7%|
[ri_connect_proxies](#ri_connect_proxies)|1668|1668|2|0.1%|0.5%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|2|0.0%|0.5%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|1|0.0%|0.2%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|1|0.1%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.2%|
[blocklist_de_strongips](#blocklist_de_strongips)|225|225|1|0.4%|0.2%|

## php_harvesters

[projecthoneypot.org](http://www.projecthoneypot.org/) harvesters (IPs that surf the internet looking for email addresses) (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=h&rss=1).

The last time downloaded was found to be dated: Thu May 28 09:20:24 UTC 2015.

The ipset `php_harvesters` has **257** entries, **257** unique IPs.

The following table shows the overlaps of `php_harvesters` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `php_harvesters`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `php_harvesters`.
- ` this % ` is the percentage **of this ipset (`php_harvesters`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92800|92800|60|0.0%|23.3%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30710|30710|50|0.1%|19.4%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7580|7580|35|0.4%|13.6%|
[blocklist_de](#blocklist_de)|22392|22392|31|0.1%|12.0%|
[blocklist_de_bots](#blocklist_de_bots)|3467|3467|25|0.7%|9.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|15|0.0%|5.8%|
[snort_ipfilter](#snort_ipfilter)|7236|7236|10|0.1%|3.8%|
[php_commenters](#php_commenters)|281|281|9|3.2%|3.5%|
[php_bad](#php_bad)|281|281|9|3.2%|3.5%|
[alienvault_reputation](#alienvault_reputation)|177044|177044|9|0.0%|3.5%|
[nixspam](#nixspam)|26013|26013|7|0.0%|2.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|7|0.0%|2.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|7|0.0%|2.7%|
[et_tor](#et_tor)|6490|6490|7|0.1%|2.7%|
[dm_tor](#dm_tor)|6438|6438|7|0.1%|2.7%|
[bm_tor](#bm_tor)|6436|6436|7|0.1%|2.7%|
[openbl_90d](#openbl_90d)|9897|9897|5|0.0%|1.9%|
[openbl_60d](#openbl_60d)|7801|7801|5|0.0%|1.9%|
[openbl](#openbl)|9897|9897|5|0.0%|1.9%|
[blocklist_de_mail](#blocklist_de_mail)|14733|14733|4|0.0%|1.5%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|2|0.0%|0.7%|
[blocklist_de_ftp](#blocklist_de_ftp)|239|239|2|0.8%|0.7%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|1|0.0%|0.3%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|1|0.0%|0.3%|
[ri_web_proxies](#ri_web_proxies)|4267|4267|1|0.0%|0.3%|
[php_spammers](#php_spammers)|417|417|1|0.2%|0.3%|
[php_dictionary](#php_dictionary)|398|398|1|0.2%|0.3%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|1|0.0%|0.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.3%|
[fullbogons](#fullbogons)|3656|670735064|1|0.0%|0.3%|
[et_block](#et_block)|975|18056513|1|0.0%|0.3%|
[bogons](#bogons)|13|592708608|1|0.0%|0.3%|
[blocklist_de_strongips](#blocklist_de_strongips)|225|225|1|0.4%|0.3%|
[blocklist_de_apache](#blocklist_de_apache)|12673|12673|1|0.0%|0.3%|

## php_spammers

[projecthoneypot.org](http://www.projecthoneypot.org/) spam servers (IPs used by spammers to send messages) (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=s&rss=1).

The last time downloaded was found to be dated: Thu May 28 09:20:25 UTC 2015.

The ipset `php_spammers` has **417** entries, **417** unique IPs.

The following table shows the overlaps of `php_spammers` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `php_spammers`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `php_spammers`.
- ` this % ` is the percentage **of this ipset (`php_spammers`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92800|92800|88|0.0%|21.1%|
[php_dictionary](#php_dictionary)|398|398|81|20.3%|19.4%|
[nixspam](#nixspam)|26013|26013|78|0.2%|18.7%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30710|30710|64|0.2%|15.3%|
[snort_ipfilter](#snort_ipfilter)|7236|7236|63|0.8%|15.1%|
[blocklist_de](#blocklist_de)|22392|22392|62|0.2%|14.8%|
[blocklist_de_mail](#blocklist_de_mail)|14733|14733|40|0.2%|9.5%|
[php_commenters](#php_commenters)|281|281|32|11.3%|7.6%|
[php_bad](#php_bad)|281|281|32|11.3%|7.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|31|0.0%|7.4%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7580|7580|27|0.3%|6.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|26|0.0%|6.2%|
[ri_web_proxies](#ri_web_proxies)|4267|4267|17|0.3%|4.0%|
[blocklist_de_bots](#blocklist_de_bots)|3467|3467|17|0.4%|4.0%|
[et_tor](#et_tor)|6490|6490|6|0.0%|1.4%|
[dm_tor](#dm_tor)|6438|6438|6|0.0%|1.4%|
[bm_tor](#bm_tor)|6436|6436|6|0.0%|1.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|5|0.0%|1.1%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1350|1350|5|0.3%|1.1%|
[blocklist_de_apache](#blocklist_de_apache)|12673|12673|5|0.0%|1.1%|
[blocklist_de_strongips](#blocklist_de_strongips)|225|225|4|1.7%|0.9%|
[alienvault_reputation](#alienvault_reputation)|177044|177044|3|0.0%|0.7%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|2|0.0%|0.4%|
[ri_connect_proxies](#ri_connect_proxies)|1668|1668|2|0.1%|0.4%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2|0.0%|0.4%|
[et_block](#et_block)|975|18056513|2|0.0%|0.4%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.2%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1|0.0%|0.2%|

## ri_connect_proxies

[rosinstrument.com](http://www.rosinstrument.com) open CONNECT proxies (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://tools.rosinstrument.com/proxy/plab100.xml).

The last time downloaded was found to be dated: Thu May 28 02:59:35 UTC 2015.

The ipset `ri_connect_proxies` has **1668** entries, **1668** unique IPs.

The following table shows the overlaps of `ri_connect_proxies` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ri_connect_proxies`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ri_connect_proxies`.
- ` this % ` is the percentage **of this ipset (`ri_connect_proxies`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92800|92800|949|1.0%|56.8%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30710|30710|687|2.2%|41.1%|
[ri_web_proxies](#ri_web_proxies)|4267|4267|677|15.8%|40.5%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7580|7580|168|2.2%|10.0%|
[blocklist_de](#blocklist_de)|22392|22392|83|0.3%|4.9%|
[blocklist_de_bots](#blocklist_de_bots)|3467|3467|82|2.3%|4.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|75|0.0%|4.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|59|0.0%|3.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|41|0.0%|2.4%|
[nixspam](#nixspam)|26013|26013|12|0.0%|0.7%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|6|0.8%|0.3%|
[snort_ipfilter](#snort_ipfilter)|7236|7236|3|0.0%|0.1%|
[php_spammers](#php_spammers)|417|417|2|0.4%|0.1%|
[php_dictionary](#php_dictionary)|398|398|2|0.5%|0.1%|
[et_tor](#et_tor)|6490|6490|2|0.0%|0.1%|
[dm_tor](#dm_tor)|6438|6438|2|0.0%|0.1%|
[bm_tor](#bm_tor)|6436|6436|2|0.0%|0.1%|
[blocklist_de_mail](#blocklist_de_mail)|14733|14733|1|0.0%|0.0%|
[alienvault_reputation](#alienvault_reputation)|177044|177044|1|0.0%|0.0%|

## ri_web_proxies

[rosinstrument.com](http://www.rosinstrument.com) open HTTP proxies (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://tools.rosinstrument.com/proxy/l100.xml).

The last time downloaded was found to be dated: Thu May 28 06:34:23 UTC 2015.

The ipset `ri_web_proxies` has **4267** entries, **4267** unique IPs.

The following table shows the overlaps of `ri_web_proxies` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ri_web_proxies`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ri_web_proxies`.
- ` this % ` is the percentage **of this ipset (`ri_web_proxies`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92800|92800|2033|2.1%|47.6%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30710|30710|1588|5.1%|37.2%|
[ri_connect_proxies](#ri_connect_proxies)|1668|1668|677|40.5%|15.8%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7580|7580|524|6.9%|12.2%|
[blocklist_de](#blocklist_de)|22392|22392|386|1.7%|9.0%|
[blocklist_de_bots](#blocklist_de_bots)|3467|3467|359|10.3%|8.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|151|0.0%|3.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|134|0.0%|3.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|97|0.0%|2.2%|
[nixspam](#nixspam)|26013|26013|77|0.2%|1.8%|
[blocklist_de_mail](#blocklist_de_mail)|14733|14733|26|0.1%|0.6%|
[snort_ipfilter](#snort_ipfilter)|7236|7236|25|0.3%|0.5%|
[php_dictionary](#php_dictionary)|398|398|20|5.0%|0.4%|
[php_spammers](#php_spammers)|417|417|17|4.0%|0.3%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|10|1.4%|0.2%|
[php_commenters](#php_commenters)|281|281|7|2.4%|0.1%|
[php_bad](#php_bad)|281|281|7|2.4%|0.1%|
[et_tor](#et_tor)|6490|6490|5|0.0%|0.1%|
[dm_tor](#dm_tor)|6438|6438|5|0.0%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|4|0.0%|0.0%|
[bm_tor](#bm_tor)|6436|6436|4|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|225|225|3|1.3%|0.0%|
[alienvault_reputation](#alienvault_reputation)|177044|177044|3|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.0%|
[openbl_90d](#openbl_90d)|9897|9897|1|0.0%|0.0%|
[openbl](#openbl)|9897|9897|1|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2276|2276|1|0.0%|0.0%|

## shunlist

[AutoShun.org](http://autoshun.org/) IPs identified as hostile by correlating logs from distributed snort installations running the autoshun plugin

Source is downloaded from [this link](http://www.autoshun.org/files/shunlist.csv).

The last time downloaded was found to be dated: Thu May 28 06:30:03 UTC 2015.

The ipset `shunlist` has **51** entries, **51** unique IPs.

The following table shows the overlaps of `shunlist` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `shunlist`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `shunlist`.
- ` this % ` is the percentage **of this ipset (`shunlist`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[alienvault_reputation](#alienvault_reputation)|177044|177044|51|0.0%|100.0%|
[openbl_90d](#openbl_90d)|9897|9897|10|0.1%|19.6%|
[openbl_60d](#openbl_60d)|7801|7801|10|0.1%|19.6%|
[openbl](#openbl)|9897|9897|10|0.1%|19.6%|
[blocklist_de](#blocklist_de)|22392|22392|10|0.0%|19.6%|
[openbl_30d](#openbl_30d)|4449|4449|9|0.2%|17.6%|
[et_compromised](#et_compromised)|2338|2338|8|0.3%|15.6%|
[bruteforceblocker](#bruteforceblocker)|2415|2415|8|0.3%|15.6%|
[blocklist_de_ssh](#blocklist_de_ssh)|2276|2276|7|0.3%|13.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|6|0.0%|11.7%|
[openbl_7d](#openbl_7d)|997|997|5|0.5%|9.8%|
[voipbl](#voipbl)|10286|10757|3|0.0%|5.8%|
[openbl_1d](#openbl_1d)|357|357|2|0.5%|3.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|2|0.0%|3.9%|
[ciarmy](#ciarmy)|394|394|2|0.5%|3.9%|
[blocklist_de_apache](#blocklist_de_apache)|12673|12673|2|0.0%|3.9%|
[blocklist_de_mail](#blocklist_de_mail)|14733|14733|1|0.0%|1.9%|
[blocklist_de_imap](#blocklist_de_imap)|683|683|1|0.1%|1.9%|

## snort_ipfilter

[labs.snort.org](https://labs.snort.org/) supplied IP blacklist (this list seems to be updated frequently, but we found no information about it)

Source is downloaded from [this link](http://labs.snort.org/feeds/ip-filter.blf).

The last time downloaded was found to be dated: Thu May 28 00:30:00 UTC 2015.

The ipset `snort_ipfilter` has **7236** entries, **7236** unique IPs.

The following table shows the overlaps of `snort_ipfilter` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `snort_ipfilter`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `snort_ipfilter`.
- ` this % ` is the percentage **of this ipset (`snort_ipfilter`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[et_tor](#et_tor)|6490|6490|1090|16.7%|15.0%|
[bm_tor](#bm_tor)|6436|6436|1039|16.1%|14.3%|
[dm_tor](#dm_tor)|6438|6438|1036|16.0%|14.3%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92800|92800|679|0.7%|9.3%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30710|30710|522|1.6%|7.2%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7580|7580|310|4.0%|4.2%|
[et_block](#et_block)|975|18056513|286|0.0%|3.9%|
[zeus](#zeus)|266|266|227|85.3%|3.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|214|0.0%|2.9%|
[zeus_badips](#zeus_badips)|229|229|201|87.7%|2.7%|
[nixspam](#nixspam)|26013|26013|154|0.5%|2.1%|
[blocklist_de](#blocklist_de)|22392|22392|152|0.6%|2.1%|
[alienvault_reputation](#alienvault_reputation)|177044|177044|123|0.0%|1.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|100|0.0%|1.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|92|0.0%|1.2%|
[blocklist_de_mail](#blocklist_de_mail)|14733|14733|91|0.6%|1.2%|
[php_spammers](#php_spammers)|417|417|63|15.1%|0.8%|
[php_dictionary](#php_dictionary)|398|398|61|15.3%|0.8%|
[feodo](#feodo)|63|63|48|76.1%|0.6%|
[blocklist_de_apache](#blocklist_de_apache)|12673|12673|43|0.3%|0.5%|
[php_bad](#php_bad)|281|281|42|14.9%|0.5%|
[php_commenters](#php_commenters)|281|281|41|14.5%|0.5%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1350|1350|40|2.9%|0.5%|
[ri_web_proxies](#ri_web_proxies)|4267|4267|25|0.5%|0.3%|
[openbl_90d](#openbl_90d)|9897|9897|25|0.2%|0.3%|
[openbl_60d](#openbl_60d)|7801|7801|25|0.3%|0.3%|
[openbl](#openbl)|9897|9897|25|0.2%|0.3%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|25|1.9%|0.3%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|20|0.0%|0.2%|
[blocklist_de_bots](#blocklist_de_bots)|3467|3467|18|0.5%|0.2%|
[sslbl](#sslbl)|345|345|17|4.9%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|15|0.0%|0.2%|
[palevo](#palevo)|13|13|11|84.6%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|11|0.0%|0.1%|
[php_harvesters](#php_harvesters)|257|257|10|3.8%|0.1%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|6|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|1668|1668|3|0.1%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2276|2276|3|0.1%|0.0%|
[openbl_30d](#openbl_30d)|4449|4449|2|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.0%|
[openbl_7d](#openbl_7d)|997|997|1|0.1%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|1|0.1%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1|0.0%|0.0%|
[et_compromised](#et_compromised)|2338|2338|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2415|2415|1|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|225|225|1|0.4%|0.0%|

## spamhaus_drop

[Spamhaus.org](http://www.spamhaus.org) DROP list (according to their site this list should be dropped at tier-1 ISPs globaly) - **excellent list**

Source is downloaded from [this link](http://www.spamhaus.org/drop/drop.txt).

The last time downloaded was found to be dated: Mon May 25 12:30:10 UTC 2015.

The ipset `spamhaus_drop` has **641** entries, **18117120** unique IPs.

The following table shows the overlaps of `spamhaus_drop` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `spamhaus_drop`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `spamhaus_drop`.
- ` this % ` is the percentage **of this ipset (`spamhaus_drop`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[et_block](#et_block)|975|18056513|18051584|99.9%|99.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|8401434|2.4%|46.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|7211008|78.5%|39.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|2133002|0.2%|11.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|195904|0.1%|1.0%|
[fullbogons](#fullbogons)|3656|670735064|20480|0.0%|0.1%|
[alienvault_reputation](#alienvault_reputation)|177044|177044|1624|0.9%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|1037|0.3%|0.0%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92800|92800|788|0.8%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|512|0.1%|0.0%|
[dshield](#dshield)|20|5120|512|10.0%|0.0%|
[openbl_90d](#openbl_90d)|9897|9897|447|4.5%|0.0%|
[openbl](#openbl)|9897|9897|447|4.5%|0.0%|
[openbl_60d](#openbl_60d)|7801|7801|294|3.7%|0.0%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30710|30710|235|0.7%|0.0%|
[openbl_30d](#openbl_30d)|4449|4449|208|4.6%|0.0%|
[nixspam](#nixspam)|26013|26013|201|0.7%|0.0%|
[blocklist_de](#blocklist_de)|22392|22392|183|0.8%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2276|2276|116|5.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2415|2415|98|4.0%|0.0%|
[openbl_7d](#openbl_7d)|997|997|97|9.7%|0.0%|
[et_compromised](#et_compromised)|2338|2338|92|3.9%|0.0%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7580|7580|54|0.7%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3467|3467|44|1.2%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|28|2.1%|0.0%|
[openbl_1d](#openbl_1d)|357|357|26|7.2%|0.0%|
[php_commenters](#php_commenters)|281|281|25|8.8%|0.0%|
[php_bad](#php_bad)|281|281|25|8.8%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14733|14733|21|0.1%|0.0%|
[snort_ipfilter](#snort_ipfilter)|7236|7236|20|0.2%|0.0%|
[zeus_badips](#zeus_badips)|229|229|16|6.9%|0.0%|
[zeus](#zeus)|266|266|16|6.0%|0.0%|
[voipbl](#voipbl)|10286|10757|14|0.1%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|683|683|12|1.7%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|225|225|7|3.1%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|6|0.4%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|6|0.0%|0.0%|
[sslbl](#sslbl)|345|345|3|0.8%|0.0%|
[php_dictionary](#php_dictionary)|398|398|3|0.7%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1350|1350|3|0.2%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|12673|12673|3|0.0%|0.0%|
[php_spammers](#php_spammers)|417|417|2|0.4%|0.0%|
[malc0de](#malc0de)|414|414|2|0.4%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|2|0.2%|0.0%|
[et_tor](#et_tor)|6490|6490|2|0.0%|0.0%|
[dm_tor](#dm_tor)|6438|6438|2|0.0%|0.0%|
[bm_tor](#bm_tor)|6436|6436|2|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.0%|
[et_botnet](#et_botnet)|512|512|1|0.1%|0.0%|

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
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|270785|0.1%|64.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|33368|0.0%|7.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|33155|0.0%|7.8%|
[et_block](#et_block)|975|18056513|517|0.0%|0.1%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|512|0.0%|0.1%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92800|92800|109|0.1%|0.0%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30710|30710|40|0.1%|0.0%|
[blocklist_de](#blocklist_de)|22392|22392|37|0.1%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3467|3467|30|0.8%|0.0%|
[alienvault_reputation](#alienvault_reputation)|177044|177044|15|0.0%|0.0%|
[openbl_90d](#openbl_90d)|9897|9897|14|0.1%|0.0%|
[openbl](#openbl)|9897|9897|14|0.1%|0.0%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7580|7580|10|0.1%|0.0%|
[php_commenters](#php_commenters)|281|281|7|2.4%|0.0%|
[php_bad](#php_bad)|281|281|7|2.4%|0.0%|
[snort_ipfilter](#snort_ipfilter)|7236|7236|6|0.0%|0.0%|
[zeus_badips](#zeus_badips)|229|229|5|2.1%|0.0%|
[zeus](#zeus)|266|266|5|1.8%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14733|14733|5|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|225|225|4|1.7%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|683|683|2|0.2%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|12673|12673|2|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.0%|
[openbl_60d](#openbl_60d)|7801|7801|1|0.0%|0.0%|
[openbl_30d](#openbl_30d)|4449|4449|1|0.0%|0.0%|
[openbl_1d](#openbl_1d)|357|357|1|0.2%|0.0%|
[nixspam](#nixspam)|26013|26013|1|0.0%|0.0%|
[malc0de](#malc0de)|414|414|1|0.2%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|1|0.0%|0.0%|

## sslbl

[Abuse.ch SSL Blacklist](https://sslbl.abuse.ch/) bad SSL traffic related to malware or botnet activities - **excellent list**

Source is downloaded from [this link](https://sslbl.abuse.ch/blacklist/sslipblacklist.csv).

The last time downloaded was found to be dated: Thu May 28 09:30:06 UTC 2015.

The ipset `sslbl` has **345** entries, **345** unique IPs.

The following table shows the overlaps of `sslbl` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `sslbl`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `sslbl`.
- ` this % ` is the percentage **of this ipset (`sslbl`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[et_block](#et_block)|975|18056513|23|0.0%|6.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|22|0.0%|6.3%|
[feodo](#feodo)|63|63|20|31.7%|5.7%|
[snort_ipfilter](#snort_ipfilter)|7236|7236|17|0.2%|4.9%|
[alienvault_reputation](#alienvault_reputation)|177044|177044|7|0.0%|2.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|6|0.0%|1.7%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|3|0.0%|0.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|3|0.0%|0.8%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92800|92800|1|0.0%|0.2%|
[openbl_90d](#openbl_90d)|9897|9897|1|0.0%|0.2%|
[openbl](#openbl)|9897|9897|1|0.0%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|1|0.0%|0.2%|

## stop_forum_spam_1h

[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers in the last 24 hours - **excellent list**

Source is downloaded from [this link](http://www.stopforumspam.com/downloads/listed_ip_1.zip).

The last time downloaded was found to be dated: Thu May 28 09:00:02 UTC 2015.

The ipset `stop_forum_spam_1h` has **7580** entries, **7580** unique IPs.

The following table shows the overlaps of `stop_forum_spam_1h` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `stop_forum_spam_1h`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `stop_forum_spam_1h`.
- ` this % ` is the percentage **of this ipset (`stop_forum_spam_1h`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30710|30710|6761|22.0%|89.1%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92800|92800|4279|4.6%|56.4%|
[blocklist_de](#blocklist_de)|22392|22392|1512|6.7%|19.9%|
[blocklist_de_bots](#blocklist_de_bots)|3467|3467|1428|41.1%|18.8%|
[ri_web_proxies](#ri_web_proxies)|4267|4267|524|12.2%|6.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|516|0.0%|6.8%|
[snort_ipfilter](#snort_ipfilter)|7236|7236|310|4.2%|4.0%|
[bm_tor](#bm_tor)|6436|6436|292|4.5%|3.8%|
[dm_tor](#dm_tor)|6438|6438|290|4.5%|3.8%|
[et_tor](#et_tor)|6490|6490|285|4.3%|3.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|251|0.0%|3.3%|
[ri_connect_proxies](#ri_connect_proxies)|1668|1668|168|10.0%|2.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|149|0.0%|1.9%|
[php_commenters](#php_commenters)|281|281|113|40.2%|1.4%|
[php_bad](#php_bad)|281|281|113|40.2%|1.4%|
[blocklist_de_strongips](#blocklist_de_strongips)|225|225|105|46.6%|1.3%|
[blocklist_de_apache](#blocklist_de_apache)|12673|12673|92|0.7%|1.2%|
[alienvault_reputation](#alienvault_reputation)|177044|177044|64|0.0%|0.8%|
[nixspam](#nixspam)|26013|26013|56|0.2%|0.7%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|54|0.0%|0.7%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1350|1350|54|4.0%|0.7%|
[et_block](#et_block)|975|18056513|48|0.0%|0.6%|
[php_harvesters](#php_harvesters)|257|257|35|13.6%|0.4%|
[blocklist_de_mail](#blocklist_de_mail)|14733|14733|34|0.2%|0.4%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|31|0.0%|0.4%|
[php_spammers](#php_spammers)|417|417|27|6.4%|0.3%|
[php_dictionary](#php_dictionary)|398|398|26|6.5%|0.3%|
[openbl_90d](#openbl_90d)|9897|9897|23|0.2%|0.3%|
[openbl](#openbl)|9897|9897|23|0.2%|0.3%|
[openbl_60d](#openbl_60d)|7801|7801|22|0.2%|0.2%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|10|0.0%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|9|0.0%|0.1%|
[voipbl](#voipbl)|10286|10757|4|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|3|0.0%|0.0%|
[openbl_30d](#openbl_30d)|4449|4449|2|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|1|0.1%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2415|2415|1|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2276|2276|1|0.0%|0.0%|

## stop_forum_spam_30d

[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 30 days)

Source is downloaded from [this link](http://www.stopforumspam.com/downloads/listed_ip_30.zip).

The last time downloaded was found to be dated: Wed May 27 12:20:20 UTC 2015.

The ipset `stop_forum_spam_30d` has **92800** entries, **92800** unique IPs.

The following table shows the overlaps of `stop_forum_spam_30d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `stop_forum_spam_30d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `stop_forum_spam_30d`.
- ` this % ` is the percentage **of this ipset (`stop_forum_spam_30d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30710|30710|25780|83.9%|27.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|6226|0.0%|6.7%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7580|7580|4279|56.4%|4.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|2453|0.0%|2.6%|
[blocklist_de](#blocklist_de)|22392|22392|2174|9.7%|2.3%|
[ri_web_proxies](#ri_web_proxies)|4267|4267|2033|47.6%|2.1%|
[blocklist_de_bots](#blocklist_de_bots)|3467|3467|1905|54.9%|2.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|1498|0.0%|1.6%|
[ri_connect_proxies](#ri_connect_proxies)|1668|1668|949|56.8%|1.0%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|788|0.0%|0.8%|
[et_block](#et_block)|975|18056513|769|0.0%|0.8%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|737|0.0%|0.7%|
[snort_ipfilter](#snort_ipfilter)|7236|7236|679|9.3%|0.7%|
[et_tor](#et_tor)|6490|6490|573|8.8%|0.6%|
[bm_tor](#bm_tor)|6436|6436|570|8.8%|0.6%|
[dm_tor](#dm_tor)|6438|6438|569|8.8%|0.6%|
[nixspam](#nixspam)|26013|26013|244|0.9%|0.2%|
[alienvault_reputation](#alienvault_reputation)|177044|177044|239|0.1%|0.2%|
[blocklist_de_apache](#blocklist_de_apache)|12673|12673|206|1.6%|0.2%|
[php_commenters](#php_commenters)|281|281|194|69.0%|0.2%|
[php_bad](#php_bad)|281|281|193|68.6%|0.2%|
[blocklist_de_mail](#blocklist_de_mail)|14733|14733|183|1.2%|0.1%|
[blocklist_de_strongips](#blocklist_de_strongips)|225|225|126|56.0%|0.1%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|109|0.0%|0.1%|
[php_spammers](#php_spammers)|417|417|88|21.1%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1350|1350|71|5.2%|0.0%|
[openbl_90d](#openbl_90d)|9897|9897|70|0.7%|0.0%|
[openbl](#openbl)|9897|9897|70|0.7%|0.0%|
[openbl_60d](#openbl_60d)|7801|7801|63|0.8%|0.0%|
[php_dictionary](#php_dictionary)|398|398|61|15.3%|0.0%|
[php_harvesters](#php_harvesters)|257|257|60|23.3%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|46|0.0%|0.0%|
[voipbl](#voipbl)|10286|10757|39|0.3%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|24|3.5%|0.0%|
[openbl_30d](#openbl_30d)|4449|4449|21|0.4%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|14|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2276|2276|8|0.3%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2415|2415|6|0.2%|0.0%|
[et_compromised](#et_compromised)|2338|2338|5|0.2%|0.0%|
[zeus](#zeus)|266|266|4|1.5%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|239|239|4|1.6%|0.0%|
[zeus_badips](#zeus_badips)|229|229|3|1.3%|0.0%|
[fullbogons](#fullbogons)|3656|670735064|3|0.0%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|2|0.1%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.0%|
[sslbl](#sslbl)|345|345|1|0.2%|0.0%|
[openbl_7d](#openbl_7d)|997|997|1|0.1%|0.0%|
[openbl_1d](#openbl_1d)|357|357|1|0.2%|0.0%|
[dshield](#dshield)|20|5120|1|0.0%|0.0%|
[ciarmy](#ciarmy)|394|394|1|0.2%|0.0%|
[bogons](#bogons)|13|592708608|1|0.0%|0.0%|

## stop_forum_spam_7d

[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 7 days)

Source is downloaded from [this link](http://www.stopforumspam.com/downloads/listed_ip_7.zip).

The last time downloaded was found to be dated: Thu May 28 02:00:08 UTC 2015.

The ipset `stop_forum_spam_7d` has **30710** entries, **30710** unique IPs.

The following table shows the overlaps of `stop_forum_spam_7d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `stop_forum_spam_7d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `stop_forum_spam_7d`.
- ` this % ` is the percentage **of this ipset (`stop_forum_spam_7d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92800|92800|25780|27.7%|83.9%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7580|7580|6761|89.1%|22.0%|
[blocklist_de](#blocklist_de)|22392|22392|2335|10.4%|7.6%|
[blocklist_de_bots](#blocklist_de_bots)|3467|3467|2165|62.4%|7.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|2079|0.0%|6.7%|
[ri_web_proxies](#ri_web_proxies)|4267|4267|1588|37.2%|5.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|927|0.0%|3.0%|
[ri_connect_proxies](#ri_connect_proxies)|1668|1668|687|41.1%|2.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|581|0.0%|1.8%|
[snort_ipfilter](#snort_ipfilter)|7236|7236|522|7.2%|1.6%|
[et_tor](#et_tor)|6490|6490|442|6.8%|1.4%|
[bm_tor](#bm_tor)|6436|6436|436|6.7%|1.4%|
[dm_tor](#dm_tor)|6438|6438|435|6.7%|1.4%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|235|0.0%|0.7%|
[et_block](#et_block)|975|18056513|214|0.0%|0.6%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|195|0.0%|0.6%|
[php_commenters](#php_commenters)|281|281|191|67.9%|0.6%|
[php_bad](#php_bad)|281|281|190|67.6%|0.6%|
[nixspam](#nixspam)|26013|26013|141|0.5%|0.4%|
[blocklist_de_apache](#blocklist_de_apache)|12673|12673|136|1.0%|0.4%|
[blocklist_de_strongips](#blocklist_de_strongips)|225|225|118|52.4%|0.3%|
[alienvault_reputation](#alienvault_reputation)|177044|177044|115|0.0%|0.3%|
[blocklist_de_mail](#blocklist_de_mail)|14733|14733|89|0.6%|0.2%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1350|1350|74|5.4%|0.2%|
[php_spammers](#php_spammers)|417|417|64|15.3%|0.2%|
[php_dictionary](#php_dictionary)|398|398|53|13.3%|0.1%|
[php_harvesters](#php_harvesters)|257|257|50|19.4%|0.1%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|40|0.0%|0.1%|
[openbl_90d](#openbl_90d)|9897|9897|36|0.3%|0.1%|
[openbl](#openbl)|9897|9897|36|0.3%|0.1%|
[openbl_60d](#openbl_60d)|7801|7801|34|0.4%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|22|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|12|1.7%|0.0%|
[voipbl](#voipbl)|10286|10757|11|0.1%|0.0%|
[openbl_30d](#openbl_30d)|4449|4449|7|0.1%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|6|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.0%|
[et_compromised](#et_compromised)|2338|2338|2|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2415|2415|2|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2276|2276|2|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|239|239|2|0.8%|0.0%|
[zeus_badips](#zeus_badips)|229|229|1|0.4%|0.0%|
[zeus](#zeus)|266|266|1|0.3%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|1|0.0%|0.0%|

## voipbl

[VoIPBL.org](http://www.voipbl.org/) a distributed VoIP blacklist that is aimed to protects against VoIP Fraud and minimizing abuse for network that have publicly accessible PBX's. Several algorithms, external sources and manual confirmation are used before they categorize something as an attack and determine the threat level.

Source is downloaded from [this link](http://www.voipbl.org/update/).

The last time downloaded was found to be dated: Thu May 28 09:40:25 UTC 2015.

The ipset `voipbl` has **10286** entries, **10757** unique IPs.

The following table shows the overlaps of `voipbl` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `voipbl`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `voipbl`.
- ` this % ` is the percentage **of this ipset (`voipbl`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|1587|0.0%|14.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|428|0.0%|3.9%|
[fullbogons](#fullbogons)|3656|670735064|351|0.0%|3.2%|
[bogons](#bogons)|13|592708608|351|0.0%|3.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|301|0.0%|2.7%|
[alienvault_reputation](#alienvault_reputation)|177044|177044|196|0.1%|1.8%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92800|92800|39|0.0%|0.3%|
[blocklist_de](#blocklist_de)|22392|22392|36|0.1%|0.3%|
[blocklist_de_sip](#blocklist_de_sip)|103|103|28|27.1%|0.2%|
[et_block](#et_block)|975|18056513|20|0.0%|0.1%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|14|0.0%|0.1%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30710|30710|11|0.0%|0.1%|
[openbl_90d](#openbl_90d)|9897|9897|11|0.1%|0.1%|
[openbl](#openbl)|9897|9897|11|0.1%|0.1%|
[openbl_60d](#openbl_60d)|7801|7801|9|0.1%|0.0%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7580|7580|4|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|4|0.0%|0.0%|
[shunlist](#shunlist)|51|51|3|5.8%|0.0%|
[openbl_30d](#openbl_30d)|4449|4449|3|0.0%|0.0%|
[ciarmy](#ciarmy)|394|394|3|0.7%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2276|2276|3|0.1%|0.0%|
[openbl_7d](#openbl_7d)|997|997|2|0.2%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|2|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3467|3467|2|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|12673|12673|2|0.0%|0.0%|
[nixspam](#nixspam)|26013|26013|1|0.0%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.0%|
[et_tor](#et_tor)|6490|6490|1|0.0%|0.0%|
[et_compromised](#et_compromised)|2338|2338|1|0.0%|0.0%|
[dm_tor](#dm_tor)|6438|6438|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2415|2415|1|0.0%|0.0%|
[bm_tor](#bm_tor)|6436|6436|1|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14733|14733|1|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1350|1350|1|0.0%|0.0%|

## zeus

[Abuse.ch Zeus tracker](https://zeustracker.abuse.ch) default blocklist including hijacked sites and web hosting providers - **excellent list**

Source is downloaded from [this link](https://zeustracker.abuse.ch/blocklist.php?download=ipblocklist).

The last time downloaded was found to be dated: Thu May 28 04:30:42 UTC 2015.

The ipset `zeus` has **266** entries, **266** unique IPs.

The following table shows the overlaps of `zeus` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `zeus`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `zeus`.
- ` this % ` is the percentage **of this ipset (`zeus`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[et_block](#et_block)|975|18056513|262|0.0%|98.4%|
[zeus_badips](#zeus_badips)|229|229|229|100.0%|86.0%|
[snort_ipfilter](#snort_ipfilter)|7236|7236|227|3.1%|85.3%|
[alienvault_reputation](#alienvault_reputation)|177044|177044|67|0.0%|25.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|20|0.0%|7.5%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|16|0.0%|6.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|10|0.0%|3.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|9|0.0%|3.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|7|0.0%|2.6%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|5|0.0%|1.8%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92800|92800|4|0.0%|1.5%|
[openbl_90d](#openbl_90d)|9897|9897|2|0.0%|0.7%|
[openbl_60d](#openbl_60d)|7801|7801|2|0.0%|0.7%|
[openbl_30d](#openbl_30d)|4449|4449|2|0.0%|0.7%|
[openbl](#openbl)|9897|9897|2|0.0%|0.7%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30710|30710|1|0.0%|0.3%|
[php_commenters](#php_commenters)|281|281|1|0.3%|0.3%|
[php_bad](#php_bad)|281|281|1|0.3%|0.3%|
[openbl_7d](#openbl_7d)|997|997|1|0.1%|0.3%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|1|0.0%|0.3%|
[et_compromised](#et_compromised)|2338|2338|1|0.0%|0.3%|
[bruteforceblocker](#bruteforceblocker)|2415|2415|1|0.0%|0.3%|
[blocklist_de_ssh](#blocklist_de_ssh)|2276|2276|1|0.0%|0.3%|
[blocklist_de](#blocklist_de)|22392|22392|1|0.0%|0.3%|

## zeus_badips

[Abuse.ch Zeus tracker](https://zeustracker.abuse.ch) includes IPv4 addresses that are used by the ZeuS trojan

Source is downloaded from [this link](https://zeustracker.abuse.ch/blocklist.php?download=badips).

The last time downloaded was found to be dated: Thu May 28 09:00:28 UTC 2015.

The ipset `zeus_badips` has **229** entries, **229** unique IPs.

The following table shows the overlaps of `zeus_badips` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `zeus_badips`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `zeus_badips`.
- ` this % ` is the percentage **of this ipset (`zeus_badips`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[zeus](#zeus)|266|266|229|86.0%|100.0%|
[et_block](#et_block)|975|18056513|228|0.0%|99.5%|
[snort_ipfilter](#snort_ipfilter)|7236|7236|201|2.7%|87.7%|
[alienvault_reputation](#alienvault_reputation)|177044|177044|36|0.0%|15.7%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|16|0.0%|6.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|14|0.0%|6.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|10|0.0%|4.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|8|0.0%|3.4%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|5|0.0%|2.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|4|0.0%|1.7%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92800|92800|3|0.0%|1.3%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30710|30710|1|0.0%|0.4%|
[php_commenters](#php_commenters)|281|281|1|0.3%|0.4%|
[php_bad](#php_bad)|281|281|1|0.3%|0.4%|
[openbl_90d](#openbl_90d)|9897|9897|1|0.0%|0.4%|
[openbl_60d](#openbl_60d)|7801|7801|1|0.0%|0.4%|
[openbl_30d](#openbl_30d)|4449|4449|1|0.0%|0.4%|
[openbl](#openbl)|9897|9897|1|0.0%|0.4%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|1|0.0%|0.4%|
[et_compromised](#et_compromised)|2338|2338|1|0.0%|0.4%|
[bruteforceblocker](#bruteforceblocker)|2415|2415|1|0.0%|0.4%|
