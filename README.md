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
   
   The team of OpenBL tracks brute force attacks on their hosts. They suggest to use the default blacklist which has a retension policy of 90 days (`openbl`), but they also provide a list with different retension policies (from 1 day to 1 year).
   Their goal is to report abuse to the responsible provider so that the infection is disabled.

6. **Blocklist.de** lists `blocklist_de*`
   
   Is a network of users reporting abuse mainly using `fail2ban`.
   They only include IPs that has attacked them in the last 48 hours.
   Their goal is also to report abuse back, so that the infection is disabled.

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

The following list was automatically generated on Thu May 28 14:45:24 UTC 2015.

The update frequency is the maximum allowed by internal configuration. A list will never be downloaded sooner than the update frequency stated. A list may also not be downloaded, after this frequency expired, if it has not been modified on the server (as reported by HTTP `IF_MODIFIED_SINCE` method).

name|info|type|entries|update|
:--:|:--:|:--:|:-----:|:----:|
[alienvault_reputation](#alienvault_reputation)|[AlienVault.com](https://www.alienvault.com/) IP reputation database (this list seems to include port scanning hosts and to be updated regularly, but we found no information about its retention policy)|ipv4 hash:ip|178600 unique IPs|updated every 6 hours  from [this link](https://reputation.alienvault.com/reputation.generic)
[blocklist_de](#blocklist_de)|[Blocklist.de](https://www.blocklist.de/) IPs that have been detected by fail2ban in the last 48 hours - **excellent list**|ipv4 hash:ip|22576 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/all.txt)
[blocklist_de_apache](#blocklist_de_apache)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service Apache, Apache-DDOS, RFI-Attacks.|ipv4 hash:ip|12757 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/apache.txt)
[blocklist_de_bots](#blocklist_de_bots)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the RFI-Attacks, REG-Bots, IRC-Bots or BadBots (BadBots = he has posted a Spam-Comment on a open Forum or Wiki).|ipv4 hash:ip|3492 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/bots.txt)
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|[Blocklist.de](https://www.blocklist.de/) All IPs which attacks Joomlas, Wordpress and other Web-Logins with Brute-Force Logins.|ipv4 hash:ip|1453 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/bruteforcelogin.txt)
[blocklist_de_ftp](#blocklist_de_ftp)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours for attacks on the Service FTP.|ipv4 hash:ip|273 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/ftp.txt)
[blocklist_de_imap](#blocklist_de_imap)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours for attacks on the Service imap, sasl, pop3, etc.|ipv4 hash:ip|705 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/imap.txt)
[blocklist_de_mail](#blocklist_de_mail)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service Mail, Postfix.|ipv4 hash:ip|14780 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/mail.txt)
[blocklist_de_sip](#blocklist_de_sip)|[Blocklist.de](https://www.blocklist.de/) All IP addresses that tried to login in a SIP, VOIP or Asterisk Server and are included in the IPs list from [infiltrated.net](www.infiltrated.net)|ipv4 hash:ip|98 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/sip.txt)
[blocklist_de_ssh](#blocklist_de_ssh)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service SSH.|ipv4 hash:ip|2249 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/ssh.txt)
[blocklist_de_strongips](#blocklist_de_strongips)|[Blocklist.de](https://www.blocklist.de/) All IPs which are older then 2 month and have more then 5.000 attacks.|ipv4 hash:ip|226 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/strongips.txt)
[bm_tor](#bm_tor)|[torstatus.blutmagie.de](https://torstatus.blutmagie.de) list of all TOR network servers|ipv4 hash:ip|6462 unique IPs|updated every 30 mins  from [this link](https://torstatus.blutmagie.de/ip_list_all.php/Tor_ip_list_ALL.csv)
[bogons](#bogons)|[Team-Cymru.org](http://www.team-cymru.org) private and reserved addresses defined by RFC 1918, RFC 5735, and RFC 6598 and netblocks that have not been allocated to a regional internet registry - **excellent list - use it only your internet interface**|ipv4 hash:net|13 subnets, 592708608 unique IPs|updated every 1 day  from [this link](http://www.team-cymru.org/Services/Bogons/bogon-bn-agg.txt)
[bruteforceblocker](#bruteforceblocker)|[danger.rulez.sk](http://danger.rulez.sk/) IPs detected by [bruteforceblocker](http://danger.rulez.sk/index.php/bruteforceblocker/) (fail2ban alternative for SSH on OpenBSD)|ipv4 hash:ip|2426 unique IPs|updated every 3 hours  from [this link](http://danger.rulez.sk/projects/bruteforceblocker/blist.php)
[ciarmy](#ciarmy)|[CIArmy.com](http://ciarmy.com/) IPs with poor Rogue Packet score that have not yet been identified as malicious by the community|ipv4 hash:ip|404 unique IPs|updated every 3 hours  from [this link](http://cinsscore.com/list/ci-badguys.txt)
[clean_mx_viruses](#clean_mx_viruses)|[Clean-MX.de](http://support.clean-mx.de/clean-mx/viruses.php) IPs with viruses|ipv4 hash:ip|104 unique IPs|updated every 12 hours  from [this link](http://support.clean-mx.de/clean-mx/xmlviruses.php?sort=id%20desc&response=alive)
[dm_tor](#dm_tor)|[dan.me.uk](https://www.dan.me.uk) dynamic list of TOR exit points|ipv4 hash:ip|6461 unique IPs|updated every 30 mins  from [this link](https://www.dan.me.uk/torlist/)
[dshield](#dshield)|[DShield.org](https://dshield.org/) top 20 attacking class C (/24) subnets over the last three days - **excellent list**|ipv4 hash:net|20 subnets, 5120 unique IPs|updated every 4 hours  from [this link](http://feeds.dshield.org/block.txt)
[et_block](#et_block)|[EmergingThreats.net](http://www.emergingthreats.net/) default blacklist (at the time of writing includes spamhaus DROP, dshield and abuse.ch trackers, which are available separately too - prefer to use the direct ipsets instead of this, they seem to lag a bit in updates)|ipv4 hash:net|975 subnets, 18056513 unique IPs|updated every 12 hours  from [this link](http://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt)
[et_botnet](#et_botnet)|[EmergingThreats.net](http://www.emergingthreats.net/) botnet IPs|ipv4 hash:ip|512 unique IPs|updated every 12 hours  from [this link](http://rules.emergingthreats.net/fwrules/emerging-PIX-CC.rules)
[et_compromised](#et_compromised)|[EmergingThreats.net](http://www.emergingthreats.net/) compromised hosts (seems to be a derivate of other lists)|ipv4 hash:ip|2338 unique IPs|updated every 12 hours  from [this link](http://rules.emergingthreats.net/blockrules/compromised-ips.txt)
[et_tor](#et_tor)|[EmergingThreats.net](http://www.emergingthreats.net/) [list](http://doc.emergingthreats.net/bin/view/Main/TorRules) of TOR network IPs|ipv4 hash:ip|6490 unique IPs|updated every 12 hours  from [this link](http://rules.emergingthreats.net/blockrules/emerging-tor.rules)
[feodo](#feodo)|[Abuse.ch Feodo tracker](https://feodotracker.abuse.ch) trojan includes IPs which are being used by Feodo (also known as Cridex or Bugat) which commits ebanking fraud - **excellent list**|ipv4 hash:ip|67 unique IPs|updated every 30 mins  from [this link](https://feodotracker.abuse.ch/blocklist/?download=ipblocklist)
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
[malc0de](#malc0de)|[Malc0de.com](http://malc0de.com) malicious IPs of the last 30 days|ipv4 hash:ip|411 unique IPs|updated every 1 day  from [this link](http://malc0de.com/bl/IP_Blacklist.txt)
[malwaredomainlist](#malwaredomainlist)|[malwaredomainlist.com](http://www.malwaredomainlist.com) list of malware active ip addresses|ipv4 hash:ip|1283 unique IPs|updated every 12 hours  from [this link](http://www.malwaredomainlist.com/hostslist/ip.txt)
[nixspam](#nixspam)|[NiX Spam](http://www.heise.de/ix/NiX-Spam-DNSBL-and-blacklist-for-download-499637.html) IP addresses that sent spam in the last hour - automatically generated entries without distinguishing open proxies from relays, dialup gateways, and so on. All IPs are removed after 12 hours if there is no spam from there.|ipv4 hash:ip|31903 unique IPs|updated every 15 mins  from [this link](http://www.dnsbl.manitu.net/download/nixspam-ip.dump.gz)
[openbl](#openbl)|[OpenBL.org](http://www.openbl.org/) default blacklist (currently it is the same with 90 days). OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications - **excellent list**|ipv4 hash:ip|9892 unique IPs|updated every 4 hours  from [this link](http://www.openbl.org/lists/base.txt.gz)
[openbl_1d](#openbl_1d)|[OpenBL.org](http://www.openbl.org/) last 24 hours IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|357 unique IPs|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_1days.txt.gz)
[openbl_30d](#openbl_30d)|[OpenBL.org](http://www.openbl.org/) last 30 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|4448 unique IPs|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_30days.txt.gz)
[openbl_60d](#openbl_60d)|[OpenBL.org](http://www.openbl.org/) last 60 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|7795 unique IPs|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_60days.txt.gz)
[openbl_7d](#openbl_7d)|[OpenBL.org](http://www.openbl.org/) last 7 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|1003 unique IPs|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_7days.txt.gz)
[openbl_90d](#openbl_90d)|[OpenBL.org](http://www.openbl.org/) last 90 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|9892 unique IPs|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_90days.txt.gz)
[palevo](#palevo)|[Abuse.ch Palevo tracker](https://palevotracker.abuse.ch) worm includes IPs which are being used as botnet C&C for the Palevo crimeware - **excellent list**|ipv4 hash:ip|13 unique IPs|updated every 30 mins  from [this link](https://palevotracker.abuse.ch/blocklists.php?download=ipblocklist)
[php_bad](#php_bad)|[projecthoneypot.org](http://www.projecthoneypot.org/) bad web hosts (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|281 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=b&rss=1)
[php_commenters](#php_commenters)|[projecthoneypot.org](http://www.projecthoneypot.org/) comment spammers (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|281 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=c&rss=1)
[php_dictionary](#php_dictionary)|[projecthoneypot.org](http://www.projecthoneypot.org/) directory attackers (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|398 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=d&rss=1)
[php_harvesters](#php_harvesters)|[projecthoneypot.org](http://www.projecthoneypot.org/) harvesters (IPs that surf the internet looking for email addresses) (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|257 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=h&rss=1)
[php_spammers](#php_spammers)|[projecthoneypot.org](http://www.projecthoneypot.org/) spam servers (IPs used by spammers to send messages) (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|417 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=s&rss=1)
[ri_connect_proxies](#ri_connect_proxies)|[rosinstrument.com](http://www.rosinstrument.com) open CONNECT proxies (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|1693 unique IPs|updated every 1 hour  from [this link](http://tools.rosinstrument.com/proxy/plab100.xml)
[ri_web_proxies](#ri_web_proxies)|[rosinstrument.com](http://www.rosinstrument.com) open HTTP proxies (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|4329 unique IPs|updated every 1 hour  from [this link](http://tools.rosinstrument.com/proxy/l100.xml)
[shunlist](#shunlist)|[AutoShun.org](http://autoshun.org/) IPs identified as hostile by correlating logs from distributed snort installations running the autoshun plugin|ipv4 hash:ip|51 unique IPs|updated every 4 hours  from [this link](http://www.autoshun.org/files/shunlist.csv)
[snort_ipfilter](#snort_ipfilter)|[labs.snort.org](https://labs.snort.org/) supplied IP blacklist (this list seems to be updated frequently, but we found no information about it)|ipv4 hash:ip|7240 unique IPs|updated every 12 hours  from [this link](http://labs.snort.org/feeds/ip-filter.blf)
[spamhaus_drop](#spamhaus_drop)|[Spamhaus.org](http://www.spamhaus.org) DROP list (according to their site this list should be dropped at tier-1 ISPs globaly) - **excellent list**|ipv4 hash:net|641 subnets, 18117120 unique IPs|updated every 12 hours  from [this link](http://www.spamhaus.org/drop/drop.txt)
[spamhaus_edrop](#spamhaus_edrop)|[Spamhaus.org](http://www.spamhaus.org) EDROP (extended matches that should be used with DROP) - **excellent list**|ipv4 hash:net|55 subnets, 421120 unique IPs|updated every 12 hours  from [this link](http://www.spamhaus.org/drop/edrop.txt)
[sslbl](#sslbl)|[Abuse.ch SSL Blacklist](https://sslbl.abuse.ch/) bad SSL traffic related to malware or botnet activities - **excellent list**|ipv4 hash:ip|345 unique IPs|updated every 30 mins  from [this link](https://sslbl.abuse.ch/blacklist/sslipblacklist.csv)
[stop_forum_spam_1h](#stop_forum_spam_1h)|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers in the last 24 hours - **excellent list**|ipv4 hash:ip|7698 unique IPs|updated every 1 hour  from [this link](http://www.stopforumspam.com/downloads/listed_ip_1.zip)
[stop_forum_spam_30d](#stop_forum_spam_30d)|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 30 days)|ipv4 hash:ip|92103 unique IPs|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/listed_ip_30.zip)
[stop_forum_spam_7d](#stop_forum_spam_7d)|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 7 days)|ipv4 hash:ip|30710 unique IPs|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/listed_ip_7.zip)
[voipbl](#voipbl)|[VoIPBL.org](http://www.voipbl.org/) a distributed VoIP blacklist that is aimed to protects against VoIP Fraud and minimizing abuse for network that have publicly accessible PBX's. Several algorithms, external sources and manual confirmation are used before they categorize something as an attack and determine the threat level.|ipv4 hash:net|10286 subnets, 10757 unique IPs|updated every 4 hours  from [this link](http://www.voipbl.org/update/)
[zeus](#zeus)|[Abuse.ch Zeus tracker](https://zeustracker.abuse.ch) standard, contains the same data as the ZeuS IP blocklist (zeus_badips) but with the slight difference that it doesn't exclude hijacked websites (level 2) and free web hosting providers (level 3). This means that this blocklist contains all IPv4 addresses associated with ZeuS C&Cs which are currently being tracked by ZeuS Tracker. Hence this blocklist will likely cause some false positives. - **excellent list**|ipv4 hash:ip|265 unique IPs|updated every 30 mins  from [this link](https://zeustracker.abuse.ch/blocklist.php?download=ipblocklist)
[zeus_badips](#zeus_badips)|[Abuse.ch Zeus tracker](https://zeustracker.abuse.ch) badips includes IPv4 addresses that are used by the ZeuS trojan. It is the recommened blocklist if you want to block only ZeuS IPs. It excludes IP addresses that ZeuS Tracker believes to be hijacked (level 2) or belong to a free web hosting provider (level 3). Hence the false postive rate should be much lower compared to the standard ZeuS IP blocklist. **excellent list**|ipv4 hash:ip|230 unique IPs|updated every 30 mins  from [this link](https://zeustracker.abuse.ch/blocklist.php?download=badips)

# Comparison of ipsets

Below we compare each ipset against all other.


## alienvault_reputation

[AlienVault.com](https://www.alienvault.com/) IP reputation database (this list seems to include port scanning hosts and to be updated regularly, but we found no information about its retention policy)

Source is downloaded from [this link](https://reputation.alienvault.com/reputation.generic).

The last time downloaded was found to be dated: Thu May 28 10:00:36 UTC 2015.

The ipset `alienvault_reputation` has **178600** entries, **178600** unique IPs.

The following table shows the overlaps of `alienvault_reputation` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `alienvault_reputation`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `alienvault_reputation`.
- ` this % ` is the percentage **of this ipset (`alienvault_reputation`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|15208|0.0%|8.5%|
[openbl_90d](#openbl_90d)|9892|9892|9862|99.6%|5.5%|
[openbl](#openbl)|9892|9892|9862|99.6%|5.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|8400|0.0%|4.7%|
[openbl_60d](#openbl_60d)|7795|7795|7768|99.6%|4.3%|
[et_block](#et_block)|975|18056513|5527|0.0%|3.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|5208|0.0%|2.9%|
[openbl_30d](#openbl_30d)|4448|4448|4429|99.5%|2.4%|
[dshield](#dshield)|20|5120|3073|60.0%|1.7%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|1624|0.0%|0.9%|
[blocklist_de](#blocklist_de)|22576|22576|1544|6.8%|0.8%|
[bruteforceblocker](#bruteforceblocker)|2426|2426|1500|61.8%|0.8%|
[et_compromised](#et_compromised)|2338|2338|1465|62.6%|0.8%|
[blocklist_de_ssh](#blocklist_de_ssh)|2249|2249|1315|58.4%|0.7%|
[openbl_7d](#openbl_7d)|1003|1003|989|98.6%|0.5%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|519|0.0%|0.2%|
[ciarmy](#ciarmy)|404|404|390|96.5%|0.2%|
[openbl_1d](#openbl_1d)|357|357|355|99.4%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|293|0.0%|0.1%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92103|92103|228|0.2%|0.1%|
[voipbl](#voipbl)|10286|10757|197|1.8%|0.1%|
[snort_ipfilter](#snort_ipfilter)|7240|7240|122|1.6%|0.0%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30710|30710|115|0.3%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|12757|12757|104|0.8%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|226|226|84|37.1%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14780|14780|78|0.5%|0.0%|
[zeus](#zeus)|265|265|66|24.9%|0.0%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7698|7698|65|0.8%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|705|705|61|8.6%|0.0%|
[nixspam](#nixspam)|31903|31903|51|0.1%|0.0%|
[shunlist](#shunlist)|51|51|50|98.0%|0.0%|
[et_tor](#et_tor)|6490|6490|44|0.6%|0.0%|
[dm_tor](#dm_tor)|6461|6461|43|0.6%|0.0%|
[bm_tor](#bm_tor)|6462|6462|43|0.6%|0.0%|
[zeus_badips](#zeus_badips)|230|230|36|15.6%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3492|3492|24|0.6%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|98|98|20|20.4%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1453|1453|17|1.1%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|15|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|13|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|273|273|13|4.7%|0.0%|
[php_commenters](#php_commenters)|281|281|12|4.2%|0.0%|
[php_bad](#php_bad)|281|281|12|4.2%|0.0%|
[malc0de](#malc0de)|411|411|10|2.4%|0.0%|
[php_harvesters](#php_harvesters)|257|257|9|3.5%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|8|0.5%|0.0%|
[sslbl](#sslbl)|345|345|7|2.0%|0.0%|
[php_dictionary](#php_dictionary)|398|398|7|1.7%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|6|0.4%|0.0%|
[ri_web_proxies](#ri_web_proxies)|4329|4329|3|0.0%|0.0%|
[php_spammers](#php_spammers)|417|417|3|0.7%|0.0%|
[et_botnet](#et_botnet)|512|512|3|0.5%|0.0%|
[clean_mx_viruses](#clean_mx_viruses)|104|104|2|1.9%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|1693|1693|1|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|1|0.1%|0.0%|
[feodo](#feodo)|67|67|1|1.4%|0.0%|

## blocklist_de

[Blocklist.de](https://www.blocklist.de/) IPs that have been detected by fail2ban in the last 48 hours - **excellent list**

Source is downloaded from [this link](http://lists.blocklist.de/lists/all.txt).

The last time downloaded was found to be dated: Thu May 28 14:14:04 UTC 2015.

The ipset `blocklist_de` has **22576** entries, **22576** unique IPs.

The following table shows the overlaps of `blocklist_de` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de`.
- ` this % ` is the percentage **of this ipset (`blocklist_de`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de_mail](#blocklist_de_mail)|14780|14780|14760|99.8%|65.3%|
[blocklist_de_apache](#blocklist_de_apache)|12757|12757|12756|99.9%|56.5%|
[blocklist_de_bots](#blocklist_de_bots)|3492|3492|3492|100.0%|15.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|2826|0.0%|12.5%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92103|92103|2651|2.8%|11.7%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30710|30710|2296|7.4%|10.1%|
[blocklist_de_ssh](#blocklist_de_ssh)|2249|2249|2247|99.9%|9.9%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7698|7698|1553|20.1%|6.8%|
[alienvault_reputation](#alienvault_reputation)|178600|178600|1544|0.8%|6.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|1471|0.0%|6.5%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1453|1453|1453|100.0%|6.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|1449|0.0%|6.4%|
[openbl_90d](#openbl_90d)|9892|9892|1313|13.2%|5.8%|
[openbl](#openbl)|9892|9892|1313|13.2%|5.8%|
[openbl_60d](#openbl_60d)|7795|7795|1255|16.1%|5.5%|
[openbl_30d](#openbl_30d)|4448|4448|1162|26.1%|5.1%|
[bruteforceblocker](#bruteforceblocker)|2426|2426|1122|46.2%|4.9%|
[et_compromised](#et_compromised)|2338|2338|1010|43.1%|4.4%|
[nixspam](#nixspam)|31903|31903|783|2.4%|3.4%|
[blocklist_de_imap](#blocklist_de_imap)|705|705|699|99.1%|3.0%|
[openbl_7d](#openbl_7d)|1003|1003|665|66.3%|2.9%|
[ri_web_proxies](#ri_web_proxies)|4329|4329|383|8.8%|1.6%|
[blocklist_de_ftp](#blocklist_de_ftp)|273|273|273|100.0%|1.2%|
[openbl_1d](#openbl_1d)|357|357|242|67.7%|1.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|226|226|226|100.0%|1.0%|
[et_block](#et_block)|975|18056513|194|0.0%|0.8%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|189|0.0%|0.8%|
[snort_ipfilter](#snort_ipfilter)|7240|7240|188|2.5%|0.8%|
[dshield](#dshield)|20|5120|132|2.5%|0.5%|
[php_commenters](#php_commenters)|281|281|82|29.1%|0.3%|
[php_bad](#php_bad)|281|281|81|28.8%|0.3%|
[ri_connect_proxies](#ri_connect_proxies)|1693|1693|80|4.7%|0.3%|
[blocklist_de_sip](#blocklist_de_sip)|98|98|79|80.6%|0.3%|
[php_dictionary](#php_dictionary)|398|398|70|17.5%|0.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|68|0.0%|0.3%|
[php_spammers](#php_spammers)|417|417|64|15.3%|0.2%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|38|0.0%|0.1%|
[voipbl](#voipbl)|10286|10757|37|0.3%|0.1%|
[php_harvesters](#php_harvesters)|257|257|31|12.0%|0.1%|
[ciarmy](#ciarmy)|404|404|30|7.4%|0.1%|
[et_tor](#et_tor)|6490|6490|26|0.4%|0.1%|
[dm_tor](#dm_tor)|6461|6461|25|0.3%|0.1%|
[bm_tor](#bm_tor)|6462|6462|25|0.3%|0.1%|
[shunlist](#shunlist)|51|51|12|23.5%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|7|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|3|0.2%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|2|0.2%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|2|0.0%|0.0%|
[zeus](#zeus)|265|265|1|0.3%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|1|0.0%|0.0%|
[clean_mx_viruses](#clean_mx_viruses)|104|104|1|0.9%|0.0%|

## blocklist_de_apache

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service Apache, Apache-DDOS, RFI-Attacks.

Source is downloaded from [this link](http://lists.blocklist.de/lists/apache.txt).

The last time downloaded was found to be dated: Thu May 28 14:28:05 UTC 2015.

The ipset `blocklist_de_apache` has **12757** entries, **12757** unique IPs.

The following table shows the overlaps of `blocklist_de_apache` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_apache`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_apache`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_apache`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|22576|22576|12756|56.5%|99.9%|
[blocklist_de_mail](#blocklist_de_mail)|14780|14780|11059|74.8%|86.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|2223|0.0%|17.4%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1453|1453|1453|100.0%|11.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|1319|0.0%|10.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|1077|0.0%|8.4%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92103|92103|223|0.2%|1.7%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30710|30710|136|0.4%|1.0%|
[alienvault_reputation](#alienvault_reputation)|178600|178600|104|0.0%|0.8%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7698|7698|90|1.1%|0.7%|
[snort_ipfilter](#snort_ipfilter)|7240|7240|44|0.6%|0.3%|
[blocklist_de_strongips](#blocklist_de_strongips)|226|226|32|14.1%|0.2%|
[et_tor](#et_tor)|6490|6490|26|0.4%|0.2%|
[dm_tor](#dm_tor)|6461|6461|25|0.3%|0.1%|
[ciarmy](#ciarmy)|404|404|25|6.1%|0.1%|
[bm_tor](#bm_tor)|6462|6462|25|0.3%|0.1%|
[php_commenters](#php_commenters)|281|281|23|8.1%|0.1%|
[php_bad](#php_bad)|281|281|23|8.1%|0.1%|
[blocklist_de_bots](#blocklist_de_bots)|3492|3492|18|0.5%|0.1%|
[openbl_90d](#openbl_90d)|9892|9892|13|0.1%|0.1%|
[openbl](#openbl)|9892|9892|13|0.1%|0.1%|
[openbl_60d](#openbl_60d)|7795|7795|10|0.1%|0.0%|
[nixspam](#nixspam)|31903|31903|9|0.0%|0.0%|
[openbl_30d](#openbl_30d)|4448|4448|7|0.1%|0.0%|
[et_block](#et_block)|975|18056513|7|0.0%|0.0%|
[php_spammers](#php_spammers)|417|417|5|1.1%|0.0%|
[openbl_7d](#openbl_7d)|1003|1003|4|0.3%|0.0%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|3|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|3|0.0%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|0.0%|
[et_compromised](#et_compromised)|2338|2338|3|0.1%|0.0%|
[dshield](#dshield)|20|5120|3|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2426|2426|3|0.1%|0.0%|
[voipbl](#voipbl)|10286|10757|2|0.0%|0.0%|
[shunlist](#shunlist)|51|51|2|3.9%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|1|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|4329|4329|1|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.0%|
[clean_mx_viruses](#clean_mx_viruses)|104|104|1|0.9%|0.0%|

## blocklist_de_bots

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the RFI-Attacks, REG-Bots, IRC-Bots or BadBots (BadBots = he has posted a Spam-Comment on a open Forum or Wiki).

Source is downloaded from [this link](http://lists.blocklist.de/lists/bots.txt).

The last time downloaded was found to be dated: Thu May 28 14:14:10 UTC 2015.

The ipset `blocklist_de_bots` has **3492** entries, **3492** unique IPs.

The following table shows the overlaps of `blocklist_de_bots` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_bots`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_bots`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_bots`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|22576|22576|3492|15.4%|100.0%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92103|92103|2354|2.5%|67.4%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30710|30710|2118|6.8%|60.6%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7698|7698|1460|18.9%|41.8%|
[ri_web_proxies](#ri_web_proxies)|4329|4329|355|8.2%|10.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|150|0.0%|4.2%|
[blocklist_de_strongips](#blocklist_de_strongips)|226|226|130|57.5%|3.7%|
[ri_connect_proxies](#ri_connect_proxies)|1693|1693|79|4.6%|2.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|79|0.0%|2.2%|
[php_commenters](#php_commenters)|281|281|67|23.8%|1.9%|
[php_bad](#php_bad)|281|281|67|23.8%|1.9%|
[nixspam](#nixspam)|31903|31903|57|0.1%|1.6%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|50|0.0%|1.4%|
[et_block](#et_block)|975|18056513|49|0.0%|1.4%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|47|0.0%|1.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|39|0.0%|1.1%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|32|0.0%|0.9%|
[snort_ipfilter](#snort_ipfilter)|7240|7240|27|0.3%|0.7%|
[php_harvesters](#php_harvesters)|257|257|26|10.1%|0.7%|
[alienvault_reputation](#alienvault_reputation)|178600|178600|24|0.0%|0.6%|
[blocklist_de_mail](#blocklist_de_mail)|14780|14780|18|0.1%|0.5%|
[blocklist_de_apache](#blocklist_de_apache)|12757|12757|18|0.1%|0.5%|
[php_spammers](#php_spammers)|417|417|16|3.8%|0.4%|
[php_dictionary](#php_dictionary)|398|398|8|2.0%|0.2%|
[openbl_90d](#openbl_90d)|9892|9892|3|0.0%|0.0%|
[openbl](#openbl)|9892|9892|3|0.0%|0.0%|
[voipbl](#voipbl)|10286|10757|2|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|2|0.2%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|1|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|1|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1|0.0%|0.0%|
[et_compromised](#et_compromised)|2338|2338|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2426|2426|1|0.0%|0.0%|

## blocklist_de_bruteforce

[Blocklist.de](https://www.blocklist.de/) All IPs which attacks Joomlas, Wordpress and other Web-Logins with Brute-Force Logins.

Source is downloaded from [this link](http://lists.blocklist.de/lists/bruteforcelogin.txt).

The last time downloaded was found to be dated: Thu May 28 14:14:11 UTC 2015.

The ipset `blocklist_de_bruteforce` has **1453** entries, **1453** unique IPs.

The following table shows the overlaps of `blocklist_de_bruteforce` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_bruteforce`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_bruteforce`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_bruteforce`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de_apache](#blocklist_de_apache)|12757|12757|1453|11.3%|100.0%|
[blocklist_de](#blocklist_de)|22576|22576|1453|6.4%|100.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|134|0.0%|9.2%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92103|92103|85|0.0%|5.8%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30710|30710|75|0.2%|5.1%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7698|7698|55|0.7%|3.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|44|0.0%|3.0%|
[snort_ipfilter](#snort_ipfilter)|7240|7240|41|0.5%|2.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|27|0.0%|1.8%|
[et_tor](#et_tor)|6490|6490|23|0.3%|1.5%|
[dm_tor](#dm_tor)|6461|6461|22|0.3%|1.5%|
[bm_tor](#bm_tor)|6462|6462|22|0.3%|1.5%|
[alienvault_reputation](#alienvault_reputation)|178600|178600|17|0.0%|1.1%|
[blocklist_de_strongips](#blocklist_de_strongips)|226|226|9|3.9%|0.6%|
[nixspam](#nixspam)|31903|31903|8|0.0%|0.5%|
[php_spammers](#php_spammers)|417|417|5|1.1%|0.3%|
[openbl_90d](#openbl_90d)|9892|9892|5|0.0%|0.3%|
[openbl](#openbl)|9892|9892|5|0.0%|0.3%|
[php_commenters](#php_commenters)|281|281|4|1.4%|0.2%|
[php_bad](#php_bad)|281|281|4|1.4%|0.2%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|3|0.0%|0.2%|
[openbl_60d](#openbl_60d)|7795|7795|3|0.0%|0.2%|
[et_block](#et_block)|975|18056513|3|0.0%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2|0.0%|0.1%|
[voipbl](#voipbl)|10286|10757|1|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|4329|4329|1|0.0%|0.0%|
[openbl_30d](#openbl_30d)|4448|4448|1|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|1|0.0%|0.0%|
[et_compromised](#et_compromised)|2338|2338|1|0.0%|0.0%|
[dshield](#dshield)|20|5120|1|0.0%|0.0%|
[clean_mx_viruses](#clean_mx_viruses)|104|104|1|0.9%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2426|2426|1|0.0%|0.0%|

## blocklist_de_ftp

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours for attacks on the Service FTP.

Source is downloaded from [this link](http://lists.blocklist.de/lists/ftp.txt).

The last time downloaded was found to be dated: Thu May 28 14:14:08 UTC 2015.

The ipset `blocklist_de_ftp` has **273** entries, **273** unique IPs.

The following table shows the overlaps of `blocklist_de_ftp` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_ftp`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_ftp`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_ftp`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|22576|22576|273|1.2%|100.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|23|0.0%|8.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|22|0.0%|8.0%|
[alienvault_reputation](#alienvault_reputation)|178600|178600|13|0.0%|4.7%|
[openbl_90d](#openbl_90d)|9892|9892|7|0.0%|2.5%|
[openbl](#openbl)|9892|9892|7|0.0%|2.5%|
[nixspam](#nixspam)|31903|31903|7|0.0%|2.5%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92103|92103|5|0.0%|1.8%|
[openbl_60d](#openbl_60d)|7795|7795|5|0.0%|1.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|4|0.0%|1.4%|
[openbl_30d](#openbl_30d)|4448|4448|3|0.0%|1.0%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30710|30710|2|0.0%|0.7%|
[openbl_7d](#openbl_7d)|1003|1003|2|0.1%|0.7%|
[ciarmy](#ciarmy)|404|404|2|0.4%|0.7%|
[blocklist_de_strongips](#blocklist_de_strongips)|226|226|2|0.8%|0.7%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|1|0.0%|0.3%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.3%|
[openbl_1d](#openbl_1d)|357|357|1|0.2%|0.3%|
[et_compromised](#et_compromised)|2338|2338|1|0.0%|0.3%|
[et_block](#et_block)|975|18056513|1|0.0%|0.3%|
[bruteforceblocker](#bruteforceblocker)|2426|2426|1|0.0%|0.3%|

## blocklist_de_imap

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours for attacks on the Service imap, sasl, pop3, etc.

Source is downloaded from [this link](http://lists.blocklist.de/lists/imap.txt).

The last time downloaded was found to be dated: Thu May 28 14:28:06 UTC 2015.

The ipset `blocklist_de_imap` has **705** entries, **705** unique IPs.

The following table shows the overlaps of `blocklist_de_imap` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_imap`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_imap`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_imap`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de_mail](#blocklist_de_mail)|14780|14780|705|4.7%|100.0%|
[blocklist_de](#blocklist_de)|22576|22576|699|3.0%|99.1%|
[alienvault_reputation](#alienvault_reputation)|178600|178600|61|0.0%|8.6%|
[openbl_90d](#openbl_90d)|9892|9892|46|0.4%|6.5%|
[openbl](#openbl)|9892|9892|46|0.4%|6.5%|
[openbl_60d](#openbl_60d)|7795|7795|42|0.5%|5.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|41|0.0%|5.8%|
[openbl_30d](#openbl_30d)|4448|4448|38|0.8%|5.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|38|0.0%|5.3%|
[openbl_7d](#openbl_7d)|1003|1003|24|2.3%|3.4%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|14|0.0%|1.9%|
[et_block](#et_block)|975|18056513|14|0.0%|1.9%|
[et_compromised](#et_compromised)|2338|2338|13|0.5%|1.8%|
[bruteforceblocker](#bruteforceblocker)|2426|2426|13|0.5%|1.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|12|0.0%|1.7%|
[nixspam](#nixspam)|31903|31903|7|0.0%|0.9%|
[openbl_1d](#openbl_1d)|357|357|6|1.6%|0.8%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|5|0.0%|0.7%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30710|30710|2|0.0%|0.2%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92103|92103|2|0.0%|0.2%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|2|0.0%|0.2%|
[snort_ipfilter](#snort_ipfilter)|7240|7240|2|0.0%|0.2%|
[blocklist_de_strongips](#blocklist_de_strongips)|226|226|2|0.8%|0.2%|
[voipbl](#voipbl)|10286|10757|1|0.0%|0.1%|
[shunlist](#shunlist)|51|51|1|1.9%|0.1%|
[dshield](#dshield)|20|5120|1|0.0%|0.1%|
[ciarmy](#ciarmy)|404|404|1|0.2%|0.1%|

## blocklist_de_mail

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service Mail, Postfix.

Source is downloaded from [this link](http://lists.blocklist.de/lists/mail.txt).

The last time downloaded was found to be dated: Thu May 28 14:28:05 UTC 2015.

The ipset `blocklist_de_mail` has **14780** entries, **14780** unique IPs.

The following table shows the overlaps of `blocklist_de_mail` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_mail`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_mail`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_mail`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|22576|22576|14760|65.3%|99.8%|
[blocklist_de_apache](#blocklist_de_apache)|12757|12757|11059|86.6%|74.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|2262|0.0%|15.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|1337|0.0%|9.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|1163|0.0%|7.8%|
[nixspam](#nixspam)|31903|31903|706|2.2%|4.7%|
[blocklist_de_imap](#blocklist_de_imap)|705|705|705|100.0%|4.7%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92103|92103|191|0.2%|1.2%|
[snort_ipfilter](#snort_ipfilter)|7240|7240|116|1.6%|0.7%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30710|30710|94|0.3%|0.6%|
[alienvault_reputation](#alienvault_reputation)|178600|178600|78|0.0%|0.5%|
[php_dictionary](#php_dictionary)|398|398|61|15.3%|0.4%|
[openbl_90d](#openbl_90d)|9892|9892|60|0.6%|0.4%|
[openbl](#openbl)|9892|9892|60|0.6%|0.4%|
[openbl_60d](#openbl_60d)|7795|7795|56|0.7%|0.3%|
[openbl_30d](#openbl_30d)|4448|4448|50|1.1%|0.3%|
[php_spammers](#php_spammers)|417|417|42|10.0%|0.2%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7698|7698|38|0.4%|0.2%|
[openbl_7d](#openbl_7d)|1003|1003|28|2.7%|0.1%|
[ri_web_proxies](#ri_web_proxies)|4329|4329|25|0.5%|0.1%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|23|0.0%|0.1%|
[php_commenters](#php_commenters)|281|281|22|7.8%|0.1%|
[php_bad](#php_bad)|281|281|21|7.4%|0.1%|
[et_block](#et_block)|975|18056513|19|0.0%|0.1%|
[blocklist_de_strongips](#blocklist_de_strongips)|226|226|19|8.4%|0.1%|
[et_compromised](#et_compromised)|2338|2338|18|0.7%|0.1%|
[bruteforceblocker](#bruteforceblocker)|2426|2426|18|0.7%|0.1%|
[blocklist_de_bots](#blocklist_de_bots)|3492|3492|18|0.5%|0.1%|
[openbl_1d](#openbl_1d)|357|357|9|2.5%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|6|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|5|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|4|1.5%|0.0%|
[et_tor](#et_tor)|6490|6490|3|0.0%|0.0%|
[dm_tor](#dm_tor)|6461|6461|3|0.0%|0.0%|
[bm_tor](#bm_tor)|6462|6462|3|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|2|0.0%|0.0%|
[voipbl](#voipbl)|10286|10757|1|0.0%|0.0%|
[shunlist](#shunlist)|51|51|1|1.9%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|1693|1693|1|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1|0.0%|0.0%|
[dshield](#dshield)|20|5120|1|0.0%|0.0%|
[ciarmy](#ciarmy)|404|404|1|0.2%|0.0%|

## blocklist_de_sip

[Blocklist.de](https://www.blocklist.de/) All IP addresses that tried to login in a SIP, VOIP or Asterisk Server and are included in the IPs list from [infiltrated.net](www.infiltrated.net)

Source is downloaded from [this link](http://lists.blocklist.de/lists/sip.txt).

The last time downloaded was found to be dated: Thu May 28 14:28:06 UTC 2015.

The ipset `blocklist_de_sip` has **98** entries, **98** unique IPs.

The following table shows the overlaps of `blocklist_de_sip` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_sip`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_sip`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_sip`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|22576|22576|79|0.3%|80.6%|
[voipbl](#voipbl)|10286|10757|29|0.2%|29.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|21|0.0%|21.4%|
[alienvault_reputation](#alienvault_reputation)|178600|178600|20|0.0%|20.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|7|0.0%|7.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|4|0.0%|4.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|2|0.0%|2.0%|
[nixspam](#nixspam)|31903|31903|1|0.0%|1.0%|
[et_botnet](#et_botnet)|512|512|1|0.1%|1.0%|
[ciarmy](#ciarmy)|404|404|1|0.2%|1.0%|

## blocklist_de_ssh

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service SSH.

Source is downloaded from [this link](http://lists.blocklist.de/lists/ssh.txt).

The last time downloaded was found to be dated: Thu May 28 14:28:03 UTC 2015.

The ipset `blocklist_de_ssh` has **2249** entries, **2249** unique IPs.

The following table shows the overlaps of `blocklist_de_ssh` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_ssh`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_ssh`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_ssh`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|22576|22576|2247|9.9%|99.9%|
[alienvault_reputation](#alienvault_reputation)|178600|178600|1315|0.7%|58.4%|
[openbl_90d](#openbl_90d)|9892|9892|1229|12.4%|54.6%|
[openbl](#openbl)|9892|9892|1229|12.4%|54.6%|
[openbl_60d](#openbl_60d)|7795|7795|1183|15.1%|52.6%|
[openbl_30d](#openbl_30d)|4448|4448|1101|24.7%|48.9%|
[bruteforceblocker](#bruteforceblocker)|2426|2426|1099|45.3%|48.8%|
[et_compromised](#et_compromised)|2338|2338|987|42.2%|43.8%|
[openbl_7d](#openbl_7d)|1003|1003|631|62.9%|28.0%|
[openbl_1d](#openbl_1d)|357|357|232|64.9%|10.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|219|0.0%|9.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|130|0.0%|5.7%|
[dshield](#dshield)|20|5120|128|2.5%|5.6%|
[et_block](#et_block)|975|18056513|117|0.0%|5.2%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|111|0.0%|4.9%|
[blocklist_de_strongips](#blocklist_de_strongips)|226|226|75|33.1%|3.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|51|0.0%|2.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|12|0.0%|0.5%|
[shunlist](#shunlist)|51|51|9|17.6%|0.4%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92103|92103|8|0.0%|0.3%|
[voipbl](#voipbl)|10286|10757|3|0.0%|0.1%|
[snort_ipfilter](#snort_ipfilter)|7240|7240|3|0.0%|0.1%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30710|30710|2|0.0%|0.0%|
[nixspam](#nixspam)|31903|31903|2|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|2|0.0%|0.0%|
[zeus](#zeus)|265|265|1|0.3%|0.0%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7698|7698|1|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|4329|4329|1|0.0%|0.0%|
[ciarmy](#ciarmy)|404|404|1|0.2%|0.0%|

## blocklist_de_strongips

[Blocklist.de](https://www.blocklist.de/) All IPs which are older then 2 month and have more then 5.000 attacks.

Source is downloaded from [this link](http://lists.blocklist.de/lists/strongips.txt).

The last time downloaded was found to be dated: Thu May 28 14:14:11 UTC 2015.

The ipset `blocklist_de_strongips` has **226** entries, **226** unique IPs.

The following table shows the overlaps of `blocklist_de_strongips` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_strongips`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_strongips`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_strongips`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|22576|22576|226|1.0%|100.0%|
[blocklist_de_bots](#blocklist_de_bots)|3492|3492|130|3.7%|57.5%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92103|92103|128|0.1%|56.6%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30710|30710|117|0.3%|51.7%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7698|7698|110|1.4%|48.6%|
[alienvault_reputation](#alienvault_reputation)|178600|178600|84|0.0%|37.1%|
[openbl_90d](#openbl_90d)|9892|9892|76|0.7%|33.6%|
[openbl](#openbl)|9892|9892|76|0.7%|33.6%|
[openbl_60d](#openbl_60d)|7795|7795|75|0.9%|33.1%|
[blocklist_de_ssh](#blocklist_de_ssh)|2249|2249|75|3.3%|33.1%|
[openbl_7d](#openbl_7d)|1003|1003|74|7.3%|32.7%|
[openbl_30d](#openbl_30d)|4448|4448|74|1.6%|32.7%|
[openbl_1d](#openbl_1d)|357|357|68|19.0%|30.0%|
[php_commenters](#php_commenters)|281|281|34|12.0%|15.0%|
[php_bad](#php_bad)|281|281|34|12.0%|15.0%|
[dshield](#dshield)|20|5120|34|0.6%|15.0%|
[blocklist_de_apache](#blocklist_de_apache)|12757|12757|32|0.2%|14.1%|
[et_compromised](#et_compromised)|2338|2338|26|1.1%|11.5%|
[bruteforceblocker](#bruteforceblocker)|2426|2426|22|0.9%|9.7%|
[blocklist_de_mail](#blocklist_de_mail)|14780|14780|19|0.1%|8.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|18|0.0%|7.9%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1453|1453|9|0.6%|3.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|8|0.0%|3.5%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|7|0.0%|3.0%|
[et_block](#et_block)|975|18056513|7|0.0%|3.0%|
[php_spammers](#php_spammers)|417|417|5|1.1%|2.2%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|4|0.0%|1.7%|
[ri_web_proxies](#ri_web_proxies)|4329|4329|3|0.0%|1.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|1.3%|
[nixspam](#nixspam)|31903|31903|2|0.0%|0.8%|
[blocklist_de_imap](#blocklist_de_imap)|705|705|2|0.2%|0.8%|
[blocklist_de_ftp](#blocklist_de_ftp)|273|273|2|0.7%|0.8%|
[snort_ipfilter](#snort_ipfilter)|7240|7240|1|0.0%|0.4%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.4%|
[php_dictionary](#php_dictionary)|398|398|1|0.2%|0.4%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.4%|

## bm_tor

[torstatus.blutmagie.de](https://torstatus.blutmagie.de) list of all TOR network servers

Source is downloaded from [this link](https://torstatus.blutmagie.de/ip_list_all.php/Tor_ip_list_ALL.csv).

The last time downloaded was found to be dated: Thu May 28 14:20:06 UTC 2015.

The ipset `bm_tor` has **6462** entries, **6462** unique IPs.

The following table shows the overlaps of `bm_tor` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `bm_tor`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `bm_tor`.
- ` this % ` is the percentage **of this ipset (`bm_tor`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[dm_tor](#dm_tor)|6461|6461|6461|100.0%|99.9%|
[et_tor](#et_tor)|6490|6490|5695|87.7%|88.1%|
[snort_ipfilter](#snort_ipfilter)|7240|7240|1056|14.5%|16.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|615|0.0%|9.5%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92103|92103|579|0.6%|8.9%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30710|30710|435|1.4%|6.7%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7698|7698|320|4.1%|4.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|184|0.0%|2.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|165|0.0%|2.5%|
[alienvault_reputation](#alienvault_reputation)|178600|178600|43|0.0%|0.6%|
[php_commenters](#php_commenters)|281|281|29|10.3%|0.4%|
[php_bad](#php_bad)|281|281|29|10.3%|0.4%|
[blocklist_de_apache](#blocklist_de_apache)|12757|12757|25|0.1%|0.3%|
[blocklist_de](#blocklist_de)|22576|22576|25|0.1%|0.3%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1453|1453|22|1.5%|0.3%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|21|0.0%|0.3%|
[openbl_90d](#openbl_90d)|9892|9892|20|0.2%|0.3%|
[openbl_60d](#openbl_60d)|7795|7795|20|0.2%|0.3%|
[openbl](#openbl)|9892|9892|20|0.2%|0.3%|
[php_harvesters](#php_harvesters)|257|257|7|2.7%|0.1%|
[php_spammers](#php_spammers)|417|417|6|1.4%|0.0%|
[ri_web_proxies](#ri_web_proxies)|4329|4329|4|0.0%|0.0%|
[php_dictionary](#php_dictionary)|398|398|4|1.0%|0.0%|
[nixspam](#nixspam)|31903|31903|3|0.0%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14780|14780|3|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|2|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|1693|1693|2|0.1%|0.0%|
[et_block](#et_block)|975|18056513|2|0.0%|0.0%|
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
[stop_forum_spam_30d](#stop_forum_spam_30d)|92103|92103|1|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2426|2426|1|0.0%|0.0%|

## bruteforceblocker

[danger.rulez.sk](http://danger.rulez.sk/) IPs detected by [bruteforceblocker](http://danger.rulez.sk/index.php/bruteforceblocker/) (fail2ban alternative for SSH on OpenBSD)

Source is downloaded from [this link](http://danger.rulez.sk/projects/bruteforceblocker/blist.php).

The last time downloaded was found to be dated: Thu May 28 13:48:32 UTC 2015.

The ipset `bruteforceblocker` has **2426** entries, **2426** unique IPs.

The following table shows the overlaps of `bruteforceblocker` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `bruteforceblocker`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `bruteforceblocker`.
- ` this % ` is the percentage **of this ipset (`bruteforceblocker`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[et_compromised](#et_compromised)|2338|2338|2288|97.8%|94.3%|
[alienvault_reputation](#alienvault_reputation)|178600|178600|1500|0.8%|61.8%|
[openbl_90d](#openbl_90d)|9892|9892|1429|14.4%|58.9%|
[openbl](#openbl)|9892|9892|1429|14.4%|58.9%|
[openbl_60d](#openbl_60d)|7795|7795|1412|18.1%|58.2%|
[openbl_30d](#openbl_30d)|4448|4448|1351|30.3%|55.6%|
[blocklist_de](#blocklist_de)|22576|22576|1122|4.9%|46.2%|
[blocklist_de_ssh](#blocklist_de_ssh)|2249|2249|1099|48.8%|45.3%|
[openbl_7d](#openbl_7d)|1003|1003|521|51.9%|21.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|232|0.0%|9.5%|
[openbl_1d](#openbl_1d)|357|357|203|56.8%|8.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|147|0.0%|6.0%|
[et_block](#et_block)|975|18056513|103|0.0%|4.2%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|102|0.0%|4.2%|
[dshield](#dshield)|20|5120|89|1.7%|3.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|74|0.0%|3.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|226|226|22|9.7%|0.9%|
[blocklist_de_mail](#blocklist_de_mail)|14780|14780|18|0.1%|0.7%|
[blocklist_de_imap](#blocklist_de_imap)|705|705|13|1.8%|0.5%|
[shunlist](#shunlist)|51|51|9|17.6%|0.3%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92103|92103|6|0.0%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|5|0.0%|0.2%|
[blocklist_de_apache](#blocklist_de_apache)|12757|12757|3|0.0%|0.1%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30710|30710|2|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.0%|
[zeus_badips](#zeus_badips)|230|230|1|0.4%|0.0%|
[zeus](#zeus)|265|265|1|0.3%|0.0%|
[voipbl](#voipbl)|10286|10757|1|0.0%|0.0%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7698|7698|1|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|7240|7240|1|0.0%|0.0%|
[fullbogons](#fullbogons)|3656|670735064|1|0.0%|0.0%|
[bogons](#bogons)|13|592708608|1|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|273|273|1|0.3%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1453|1453|1|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3492|3492|1|0.0%|0.0%|

## ciarmy

[CIArmy.com](http://ciarmy.com/) IPs with poor Rogue Packet score that have not yet been identified as malicious by the community

Source is downloaded from [this link](http://cinsscore.com/list/ci-badguys.txt).

The last time downloaded was found to be dated: Thu May 28 13:15:06 UTC 2015.

The ipset `ciarmy` has **404** entries, **404** unique IPs.

The following table shows the overlaps of `ciarmy` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ciarmy`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ciarmy`.
- ` this % ` is the percentage **of this ipset (`ciarmy`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[alienvault_reputation](#alienvault_reputation)|178600|178600|390|0.2%|96.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|75|0.0%|18.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|40|0.0%|9.9%|
[blocklist_de](#blocklist_de)|22576|22576|30|0.1%|7.4%|
[blocklist_de_apache](#blocklist_de_apache)|12757|12757|25|0.1%|6.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|24|0.0%|5.9%|
[voipbl](#voipbl)|10286|10757|3|0.0%|0.7%|
[shunlist](#shunlist)|51|51|2|3.9%|0.4%|
[blocklist_de_ftp](#blocklist_de_ftp)|273|273|2|0.7%|0.4%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92103|92103|1|0.0%|0.2%|
[openbl_90d](#openbl_90d)|9892|9892|1|0.0%|0.2%|
[openbl_7d](#openbl_7d)|1003|1003|1|0.0%|0.2%|
[openbl_60d](#openbl_60d)|7795|7795|1|0.0%|0.2%|
[openbl_30d](#openbl_30d)|4448|4448|1|0.0%|0.2%|
[openbl](#openbl)|9892|9892|1|0.0%|0.2%|
[et_block](#et_block)|975|18056513|1|0.0%|0.2%|
[dshield](#dshield)|20|5120|1|0.0%|0.2%|
[blocklist_de_ssh](#blocklist_de_ssh)|2249|2249|1|0.0%|0.2%|
[blocklist_de_sip](#blocklist_de_sip)|98|98|1|1.0%|0.2%|
[blocklist_de_mail](#blocklist_de_mail)|14780|14780|1|0.0%|0.2%|
[blocklist_de_imap](#blocklist_de_imap)|705|705|1|0.1%|0.2%|

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
[malc0de](#malc0de)|411|411|11|2.6%|10.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|6|0.0%|5.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|4|0.0%|3.8%|
[alienvault_reputation](#alienvault_reputation)|178600|178600|2|0.0%|1.9%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|1|0.0%|0.9%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1453|1453|1|0.0%|0.9%|
[blocklist_de_apache](#blocklist_de_apache)|12757|12757|1|0.0%|0.9%|
[blocklist_de](#blocklist_de)|22576|22576|1|0.0%|0.9%|

## dm_tor

[dan.me.uk](https://www.dan.me.uk) dynamic list of TOR exit points

Source is downloaded from [this link](https://www.dan.me.uk/torlist/).

The last time downloaded was found to be dated: Thu May 28 14:20:05 UTC 2015.

The ipset `dm_tor` has **6461** entries, **6461** unique IPs.

The following table shows the overlaps of `dm_tor` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `dm_tor`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `dm_tor`.
- ` this % ` is the percentage **of this ipset (`dm_tor`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[bm_tor](#bm_tor)|6462|6462|6461|99.9%|100.0%|
[et_tor](#et_tor)|6490|6490|5694|87.7%|88.1%|
[snort_ipfilter](#snort_ipfilter)|7240|7240|1056|14.5%|16.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|615|0.0%|9.5%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92103|92103|579|0.6%|8.9%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30710|30710|435|1.4%|6.7%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7698|7698|320|4.1%|4.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|184|0.0%|2.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|165|0.0%|2.5%|
[alienvault_reputation](#alienvault_reputation)|178600|178600|43|0.0%|0.6%|
[php_commenters](#php_commenters)|281|281|29|10.3%|0.4%|
[php_bad](#php_bad)|281|281|29|10.3%|0.4%|
[blocklist_de_apache](#blocklist_de_apache)|12757|12757|25|0.1%|0.3%|
[blocklist_de](#blocklist_de)|22576|22576|25|0.1%|0.3%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1453|1453|22|1.5%|0.3%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|21|0.0%|0.3%|
[openbl_90d](#openbl_90d)|9892|9892|20|0.2%|0.3%|
[openbl_60d](#openbl_60d)|7795|7795|20|0.2%|0.3%|
[openbl](#openbl)|9892|9892|20|0.2%|0.3%|
[php_harvesters](#php_harvesters)|257|257|7|2.7%|0.1%|
[php_spammers](#php_spammers)|417|417|6|1.4%|0.0%|
[ri_web_proxies](#ri_web_proxies)|4329|4329|4|0.0%|0.0%|
[php_dictionary](#php_dictionary)|398|398|4|1.0%|0.0%|
[nixspam](#nixspam)|31903|31903|3|0.0%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14780|14780|3|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|2|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|1693|1693|2|0.1%|0.0%|
[et_block](#et_block)|975|18056513|2|0.0%|0.0%|
[voipbl](#voipbl)|10286|10757|1|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|

## dshield

[DShield.org](https://dshield.org/) top 20 attacking class C (/24) subnets over the last three days - **excellent list**

Source is downloaded from [this link](http://feeds.dshield.org/block.txt).

The last time downloaded was found to be dated: Thu May 28 10:56:00 UTC 2015.

The ipset `dshield` has **20** entries, **5120** unique IPs.

The following table shows the overlaps of `dshield` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `dshield`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `dshield`.
- ` this % ` is the percentage **of this ipset (`dshield`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[alienvault_reputation](#alienvault_reputation)|178600|178600|3073|1.7%|60.0%|
[et_block](#et_block)|975|18056513|512|0.0%|10.0%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|256|0.0%|5.0%|
[openbl_90d](#openbl_90d)|9892|9892|169|1.7%|3.3%|
[openbl](#openbl)|9892|9892|169|1.7%|3.3%|
[openbl_60d](#openbl_60d)|7795|7795|155|1.9%|3.0%|
[openbl_30d](#openbl_30d)|4448|4448|135|3.0%|2.6%|
[blocklist_de](#blocklist_de)|22576|22576|132|0.5%|2.5%|
[blocklist_de_ssh](#blocklist_de_ssh)|2249|2249|128|5.6%|2.5%|
[openbl_7d](#openbl_7d)|1003|1003|108|10.7%|2.1%|
[bruteforceblocker](#bruteforceblocker)|2426|2426|89|3.6%|1.7%|
[et_compromised](#et_compromised)|2338|2338|81|3.4%|1.5%|
[openbl_1d](#openbl_1d)|357|357|47|13.1%|0.9%|
[blocklist_de_strongips](#blocklist_de_strongips)|226|226|34|15.0%|0.6%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|4|0.0%|0.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|4|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|12757|12757|3|0.0%|0.0%|
[nixspam](#nixspam)|31903|31903|1|0.0%|0.0%|
[malc0de](#malc0de)|411|411|1|0.2%|0.0%|
[ciarmy](#ciarmy)|404|404|1|0.2%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14780|14780|1|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|705|705|1|0.1%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1453|1453|1|0.0%|0.0%|

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
[alienvault_reputation](#alienvault_reputation)|178600|178600|5527|3.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|1044|0.3%|0.0%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92103|92103|762|0.8%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|517|0.1%|0.0%|
[dshield](#dshield)|20|5120|512|10.0%|0.0%|
[openbl_90d](#openbl_90d)|9892|9892|455|4.5%|0.0%|
[openbl](#openbl)|9892|9892|455|4.5%|0.0%|
[openbl_60d](#openbl_60d)|7795|7795|296|3.7%|0.0%|
[snort_ipfilter](#snort_ipfilter)|7240|7240|286|3.9%|0.0%|
[zeus](#zeus)|265|265|262|98.8%|0.0%|
[zeus_badips](#zeus_badips)|230|230|229|99.5%|0.0%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30710|30710|214|0.6%|0.0%|
[openbl_30d](#openbl_30d)|4448|4448|213|4.7%|0.0%|
[nixspam](#nixspam)|31903|31903|206|0.6%|0.0%|
[blocklist_de](#blocklist_de)|22576|22576|194|0.8%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2249|2249|117|5.2%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2426|2426|103|4.2%|0.0%|
[openbl_7d](#openbl_7d)|1003|1003|101|10.0%|0.0%|
[et_compromised](#et_compromised)|2338|2338|94|4.0%|0.0%|
[feodo](#feodo)|67|67|61|91.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3492|3492|49|1.4%|0.0%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7698|7698|46|0.5%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|28|2.1%|0.0%|
[openbl_1d](#openbl_1d)|357|357|27|7.5%|0.0%|
[php_commenters](#php_commenters)|281|281|24|8.5%|0.0%|
[php_bad](#php_bad)|281|281|24|8.5%|0.0%|
[sslbl](#sslbl)|345|345|23|6.6%|0.0%|
[voipbl](#voipbl)|10286|10757|20|0.1%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14780|14780|19|0.1%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|705|705|14|1.9%|0.0%|
[palevo](#palevo)|13|13|13|100.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|10|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|226|226|7|3.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|12757|12757|7|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|6|0.4%|0.0%|
[php_dictionary](#php_dictionary)|398|398|3|0.7%|0.0%|
[malc0de](#malc0de)|411|411|3|0.7%|0.0%|
[et_tor](#et_tor)|6490|6490|3|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1453|1453|3|0.2%|0.0%|
[php_spammers](#php_spammers)|417|417|2|0.4%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|2|0.2%|0.0%|
[dm_tor](#dm_tor)|6461|6461|2|0.0%|0.0%|
[bm_tor](#bm_tor)|6462|6462|2|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.0%|
[et_botnet](#et_botnet)|512|512|1|0.1%|0.0%|
[ciarmy](#ciarmy)|404|404|1|0.2%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|273|273|1|0.3%|0.0%|

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
[alienvault_reputation](#alienvault_reputation)|178600|178600|3|0.0%|0.5%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|1|0.0%|0.1%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|1|0.0%|0.1%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.1%|
[et_block](#et_block)|975|18056513|1|0.0%|0.1%|
[blocklist_de_sip](#blocklist_de_sip)|98|98|1|1.0%|0.1%|

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
[bruteforceblocker](#bruteforceblocker)|2426|2426|2288|94.3%|97.8%|
[alienvault_reputation](#alienvault_reputation)|178600|178600|1465|0.8%|62.6%|
[openbl_90d](#openbl_90d)|9892|9892|1392|14.0%|59.5%|
[openbl](#openbl)|9892|9892|1392|14.0%|59.5%|
[openbl_60d](#openbl_60d)|7795|7795|1382|17.7%|59.1%|
[openbl_30d](#openbl_30d)|4448|4448|1322|29.7%|56.5%|
[blocklist_de](#blocklist_de)|22576|22576|1010|4.4%|43.1%|
[blocklist_de_ssh](#blocklist_de_ssh)|2249|2249|987|43.8%|42.2%|
[openbl_7d](#openbl_7d)|1003|1003|500|49.8%|21.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|225|0.0%|9.6%|
[openbl_1d](#openbl_1d)|357|357|207|57.9%|8.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|143|0.0%|6.1%|
[et_block](#et_block)|975|18056513|94|0.0%|4.0%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|92|0.0%|3.9%|
[dshield](#dshield)|20|5120|81|1.5%|3.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|75|0.0%|3.2%|
[blocklist_de_strongips](#blocklist_de_strongips)|226|226|26|11.5%|1.1%|
[blocklist_de_mail](#blocklist_de_mail)|14780|14780|18|0.1%|0.7%|
[blocklist_de_imap](#blocklist_de_imap)|705|705|13|1.8%|0.5%|
[shunlist](#shunlist)|51|51|9|17.6%|0.3%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92103|92103|5|0.0%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|5|0.0%|0.2%|
[blocklist_de_apache](#blocklist_de_apache)|12757|12757|3|0.0%|0.1%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30710|30710|2|0.0%|0.0%|
[zeus_badips](#zeus_badips)|230|230|1|0.4%|0.0%|
[zeus](#zeus)|265|265|1|0.3%|0.0%|
[voipbl](#voipbl)|10286|10757|1|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|7240|7240|1|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|273|273|1|0.3%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1453|1453|1|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3492|3492|1|0.0%|0.0%|

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
[bm_tor](#bm_tor)|6462|6462|5695|88.1%|87.7%|
[dm_tor](#dm_tor)|6461|6461|5694|88.1%|87.7%|
[snort_ipfilter](#snort_ipfilter)|7240|7240|1090|15.0%|16.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|608|0.0%|9.3%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92103|92103|591|0.6%|9.1%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30710|30710|442|1.4%|6.8%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7698|7698|315|4.0%|4.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|184|0.0%|2.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|165|0.0%|2.5%|
[alienvault_reputation](#alienvault_reputation)|178600|178600|44|0.0%|0.6%|
[php_commenters](#php_commenters)|281|281|29|10.3%|0.4%|
[php_bad](#php_bad)|281|281|29|10.3%|0.4%|
[blocklist_de_apache](#blocklist_de_apache)|12757|12757|26|0.2%|0.4%|
[blocklist_de](#blocklist_de)|22576|22576|26|0.1%|0.4%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1453|1453|23|1.5%|0.3%|
[openbl_90d](#openbl_90d)|9892|9892|21|0.2%|0.3%|
[openbl_60d](#openbl_60d)|7795|7795|21|0.2%|0.3%|
[openbl](#openbl)|9892|9892|21|0.2%|0.3%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|21|0.0%|0.3%|
[php_harvesters](#php_harvesters)|257|257|7|2.7%|0.1%|
[php_spammers](#php_spammers)|417|417|6|1.4%|0.0%|
[ri_web_proxies](#ri_web_proxies)|4329|4329|5|0.1%|0.0%|
[php_dictionary](#php_dictionary)|398|398|3|0.7%|0.0%|
[nixspam](#nixspam)|31903|31903|3|0.0%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|0.0%|
[et_block](#et_block)|975|18056513|3|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14780|14780|3|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|2|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|1693|1693|2|0.1%|0.0%|
[voipbl](#voipbl)|10286|10757|1|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|

## feodo

[Abuse.ch Feodo tracker](https://feodotracker.abuse.ch) trojan includes IPs which are being used by Feodo (also known as Cridex or Bugat) which commits ebanking fraud - **excellent list**

Source is downloaded from [this link](https://feodotracker.abuse.ch/blocklist/?download=ipblocklist).

The last time downloaded was found to be dated: Thu May 28 14:20:23 UTC 2015.

The ipset `feodo` has **67** entries, **67** unique IPs.

The following table shows the overlaps of `feodo` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `feodo`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `feodo`.
- ` this % ` is the percentage **of this ipset (`feodo`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[et_block](#et_block)|975|18056513|61|0.0%|91.0%|
[snort_ipfilter](#snort_ipfilter)|7240|7240|48|0.6%|71.6%|
[sslbl](#sslbl)|345|345|24|6.9%|35.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|4|0.0%|5.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|3|0.0%|4.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|3|0.0%|4.4%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|1|0.0%|1.4%|
[alienvault_reputation](#alienvault_reputation)|178600|178600|1|0.0%|1.4%|

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
[stop_forum_spam_30d](#stop_forum_spam_30d)|92103|92103|2|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2426|2426|1|0.0%|0.0%|

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
[stop_forum_spam_30d](#stop_forum_spam_30d)|92103|92103|16|0.0%|0.0%|
[nixspam](#nixspam)|31903|31903|14|0.0%|0.0%|
[fullbogons](#fullbogons)|3656|670735064|14|0.0%|0.0%|
[alienvault_reputation](#alienvault_reputation)|178600|178600|13|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|11|1.6%|0.0%|
[et_block](#et_block)|975|18056513|10|0.0%|0.0%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30710|30710|6|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|6|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|6|0.0%|0.0%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7698|7698|3|0.0%|0.0%|
[voipbl](#voipbl)|10286|10757|2|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|2|0.7%|0.0%|
[php_dictionary](#php_dictionary)|398|398|2|0.5%|0.0%|
[blocklist_de](#blocklist_de)|22576|22576|2|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|7240|7240|1|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|4329|4329|1|0.0%|0.0%|
[php_spammers](#php_spammers)|417|417|1|0.2%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14780|14780|1|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3492|3492|1|0.0%|0.0%|

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
[stop_forum_spam_30d](#stop_forum_spam_30d)|92103|92103|741|0.8%|0.0%|
[alienvault_reputation](#alienvault_reputation)|178600|178600|519|0.2%|0.0%|
[nixspam](#nixspam)|31903|31903|206|0.6%|0.0%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30710|30710|195|0.6%|0.0%|
[blocklist_de](#blocklist_de)|22576|22576|68|0.3%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3492|3492|47|1.3%|0.0%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7698|7698|34|0.4%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|27|2.1%|0.0%|
[openbl_90d](#openbl_90d)|9892|9892|19|0.1%|0.0%|
[openbl](#openbl)|9892|9892|19|0.1%|0.0%|
[openbl_60d](#openbl_60d)|7795|7795|18|0.2%|0.0%|
[openbl_30d](#openbl_30d)|4448|4448|13|0.2%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2249|2249|12|0.5%|0.0%|
[snort_ipfilter](#snort_ipfilter)|7240|7240|11|0.1%|0.0%|
[zeus_badips](#zeus_badips)|230|230|10|4.3%|0.0%|
[zeus](#zeus)|265|265|10|3.7%|0.0%|
[openbl_7d](#openbl_7d)|1003|1003|9|0.8%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|7|0.4%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14780|14780|6|0.0%|0.0%|
[openbl_1d](#openbl_1d)|357|357|5|1.4%|0.0%|
[et_compromised](#et_compromised)|2338|2338|5|0.2%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2426|2426|5|0.2%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|705|705|5|0.7%|0.0%|
[et_tor](#et_tor)|6490|6490|3|0.0%|0.0%|
[dm_tor](#dm_tor)|6461|6461|3|0.0%|0.0%|
[bm_tor](#bm_tor)|6462|6462|3|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|226|226|3|1.3%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|12757|12757|3|0.0%|0.0%|
[php_spammers](#php_spammers)|417|417|2|0.4%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|2|0.2%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1453|1453|2|0.1%|0.0%|
[voipbl](#voipbl)|10286|10757|1|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.0%|
[php_dictionary](#php_dictionary)|398|398|1|0.2%|0.0%|
[php_commenters](#php_commenters)|281|281|1|0.3%|0.0%|
[php_bad](#php_bad)|281|281|1|0.3%|0.0%|
[et_botnet](#et_botnet)|512|512|1|0.1%|0.0%|

## ib_bluetack_level1

[iBlocklist.com](https://www.iblocklist.com/) free version of [BlueTack.co.uk](http://www.bluetack.co.uk/) Level 1 (for use in p2p): Companies or organizations who are clearly involved with trying to stop filesharing (e.g. Baytsp, MediaDefender, Mediasentry a.o.). Companies which anti-p2p activity has been seen from. Companies that produce or have a strong financial interest in copyrighted material (e.g. music, movie, software industries a.o.). Government ranges or companies that have a strong financial interest in doing work for governments. Legal industry ranges. IPs or ranges of ISPs from which anti-p2p activity has been observed. Basically this list will block all kinds of internet connections that most people would rather not have during their internet travels.

Source is downloaded from [this link](http://list.iblocklist.com/?list=ydxerpxkpcfqjaybcssw&fileformat=p2p&archiveformat=gz).

The last time downloaded was found to be dated: Thu May 28 09:22:00 UTC 2015.

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
[alienvault_reputation](#alienvault_reputation)|178600|178600|5208|2.9%|0.0%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92103|92103|1511|1.6%|0.0%|
[blocklist_de](#blocklist_de)|22576|22576|1471|6.5%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14780|14780|1337|9.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|12757|12757|1319|10.3%|0.0%|
[nixspam](#nixspam)|31903|31903|583|1.8%|0.0%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30710|30710|581|1.8%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|432|0.8%|0.0%|
[voipbl](#voipbl)|10286|10757|301|2.7%|0.0%|
[openbl_90d](#openbl_90d)|9892|9892|221|2.2%|0.0%|
[openbl](#openbl)|9892|9892|221|2.2%|0.0%|
[openbl_60d](#openbl_60d)|7795|7795|182|2.3%|0.0%|
[et_tor](#et_tor)|6490|6490|165|2.5%|0.0%|
[dm_tor](#dm_tor)|6461|6461|165|2.5%|0.0%|
[bm_tor](#bm_tor)|6462|6462|165|2.5%|0.0%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7698|7698|146|1.8%|0.0%|
[openbl_30d](#openbl_30d)|4448|4448|101|2.2%|0.0%|
[ri_web_proxies](#ri_web_proxies)|4329|4329|99|2.2%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|98|6.7%|0.0%|
[snort_ipfilter](#snort_ipfilter)|7240|7240|85|1.1%|0.0%|
[et_compromised](#et_compromised)|2338|2338|75|3.2%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2426|2426|74|3.0%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|66|5.1%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|1693|1693|60|3.5%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|58|8.6%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2249|2249|51|2.2%|0.0%|
[et_botnet](#et_botnet)|512|512|43|8.3%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3492|3492|39|1.1%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1453|1453|27|1.8%|0.0%|
[ciarmy](#ciarmy)|404|404|24|5.9%|0.0%|
[openbl_7d](#openbl_7d)|1003|1003|19|1.8%|0.0%|
[malc0de](#malc0de)|411|411|12|2.9%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|705|705|12|1.7%|0.0%|
[php_dictionary](#php_dictionary)|398|398|9|2.2%|0.0%|
[zeus](#zeus)|265|265|7|2.6%|0.0%|
[php_harvesters](#php_harvesters)|257|257|7|2.7%|0.0%|
[openbl_1d](#openbl_1d)|357|357|7|1.9%|0.0%|
[php_spammers](#php_spammers)|417|417|5|1.1%|0.0%|
[php_commenters](#php_commenters)|281|281|5|1.7%|0.0%|
[php_bad](#php_bad)|281|281|5|1.7%|0.0%|
[bogons](#bogons)|13|592708608|5|0.0%|0.0%|
[zeus_badips](#zeus_badips)|230|230|4|1.7%|0.0%|
[dshield](#dshield)|20|5120|4|0.0%|0.0%|
[clean_mx_viruses](#clean_mx_viruses)|104|104|4|3.8%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|98|98|4|4.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|273|273|4|1.4%|0.0%|
[sslbl](#sslbl)|345|345|3|0.8%|0.0%|
[feodo](#feodo)|67|67|3|4.4%|0.0%|

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
[alienvault_reputation](#alienvault_reputation)|178600|178600|8400|4.7%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|7752|2.2%|0.0%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92103|92103|2467|2.6%|0.0%|
[blocklist_de](#blocklist_de)|22576|22576|1449|6.4%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14780|14780|1163|7.8%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|12757|12757|1077|8.4%|0.0%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30710|30710|927|3.0%|0.0%|
[nixspam](#nixspam)|31903|31903|736|2.3%|0.0%|
[openbl_90d](#openbl_90d)|9892|9892|514|5.1%|0.0%|
[openbl](#openbl)|9892|9892|514|5.1%|0.0%|
[voipbl](#voipbl)|10286|10757|428|3.9%|0.0%|
[openbl_60d](#openbl_60d)|7795|7795|365|4.6%|0.0%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7698|7698|239|3.1%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|233|0.4%|0.0%|
[openbl_30d](#openbl_30d)|4448|4448|229|5.1%|0.0%|
[et_tor](#et_tor)|6490|6490|184|2.8%|0.0%|
[dm_tor](#dm_tor)|6461|6461|184|2.8%|0.0%|
[bm_tor](#bm_tor)|6462|6462|184|2.8%|0.0%|
[ri_web_proxies](#ri_web_proxies)|4329|4329|151|3.4%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2426|2426|147|6.0%|0.0%|
[et_compromised](#et_compromised)|2338|2338|143|6.1%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2249|2249|130|5.7%|0.0%|
[snort_ipfilter](#snort_ipfilter)|7240|7240|101|1.3%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3492|3492|79|2.2%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|1693|1693|76|4.4%|0.0%|
[openbl_7d](#openbl_7d)|1003|1003|51|5.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|45|3.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1453|1453|44|3.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|705|705|41|5.8%|0.0%|
[ciarmy](#ciarmy)|404|404|40|9.9%|0.0%|
[php_spammers](#php_spammers)|417|417|31|7.4%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|28|4.1%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|26|2.0%|0.0%|
[malc0de](#malc0de)|411|411|26|6.3%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|273|273|22|8.0%|0.0%|
[et_botnet](#et_botnet)|512|512|21|4.1%|0.0%|
[openbl_1d](#openbl_1d)|357|357|17|4.7%|0.0%|
[zeus](#zeus)|265|265|9|3.3%|0.0%|
[php_dictionary](#php_dictionary)|398|398|9|2.2%|0.0%|
[php_commenters](#php_commenters)|281|281|9|3.2%|0.0%|
[php_bad](#php_bad)|281|281|9|3.2%|0.0%|
[zeus_badips](#zeus_badips)|230|230|8|3.4%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|226|226|8|3.5%|0.0%|
[php_harvesters](#php_harvesters)|257|257|7|2.7%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|98|98|7|7.1%|0.0%|
[sslbl](#sslbl)|345|345|6|1.7%|0.0%|
[clean_mx_viruses](#clean_mx_viruses)|104|104|6|5.7%|0.0%|
[shunlist](#shunlist)|51|51|3|5.8%|0.0%|
[feodo](#feodo)|67|67|3|4.4%|0.0%|
[palevo](#palevo)|13|13|2|15.3%|0.0%|

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
[alienvault_reputation](#alienvault_reputation)|178600|178600|15208|8.5%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|9278|2.7%|0.0%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92103|92103|6117|6.6%|0.0%|
[blocklist_de](#blocklist_de)|22576|22576|2826|12.5%|0.0%|
[nixspam](#nixspam)|31903|31903|2788|8.7%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14780|14780|2262|15.3%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|12757|12757|2223|17.4%|0.0%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30710|30710|2079|6.7%|0.0%|
[voipbl](#voipbl)|10286|10757|1587|14.7%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1172|2.4%|0.0%|
[openbl_90d](#openbl_90d)|9892|9892|960|9.7%|0.0%|
[openbl](#openbl)|9892|9892|960|9.7%|0.0%|
[openbl_60d](#openbl_60d)|7795|7795|718|9.2%|0.0%|
[dm_tor](#dm_tor)|6461|6461|615|9.5%|0.0%|
[bm_tor](#bm_tor)|6462|6462|615|9.5%|0.0%|
[et_tor](#et_tor)|6490|6490|608|9.3%|0.0%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7698|7698|548|7.1%|0.0%|
[openbl_30d](#openbl_30d)|4448|4448|446|10.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2426|2426|232|9.5%|0.0%|
[et_compromised](#et_compromised)|2338|2338|225|9.6%|0.0%|
[snort_ipfilter](#snort_ipfilter)|7240|7240|222|3.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2249|2249|219|9.7%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3492|3492|150|4.2%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|146|11.3%|0.0%|
[ri_web_proxies](#ri_web_proxies)|4329|4329|134|3.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1453|1453|134|9.2%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|110|7.5%|0.0%|
[openbl_7d](#openbl_7d)|1003|1003|93|9.2%|0.0%|
[malc0de](#malc0de)|411|411|76|18.4%|0.0%|
[et_botnet](#et_botnet)|512|512|75|14.6%|0.0%|
[ciarmy](#ciarmy)|404|404|75|18.5%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|51|7.5%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|1693|1693|41|2.4%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|705|705|38|5.3%|0.0%|
[php_spammers](#php_spammers)|417|417|26|6.2%|0.0%|
[php_dictionary](#php_dictionary)|398|398|23|5.7%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|273|273|23|8.4%|0.0%|
[sslbl](#sslbl)|345|345|22|6.3%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|98|98|21|21.4%|0.0%|
[openbl_1d](#openbl_1d)|357|357|20|5.6%|0.0%|
[zeus](#zeus)|265|265|19|7.1%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|226|226|18|7.9%|0.0%|
[php_bad](#php_bad)|281|281|16|5.6%|0.0%|
[zeus_badips](#zeus_badips)|230|230|15|6.5%|0.0%|
[php_harvesters](#php_harvesters)|257|257|15|5.8%|0.0%|
[php_commenters](#php_commenters)|281|281|15|5.3%|0.0%|
[clean_mx_viruses](#clean_mx_viruses)|104|104|13|12.5%|0.0%|
[shunlist](#shunlist)|51|51|4|7.8%|0.0%|
[feodo](#feodo)|67|67|4|5.9%|0.0%|
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
[stop_forum_spam_30d](#stop_forum_spam_30d)|92103|92103|22|0.0%|3.2%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30710|30710|12|0.0%|1.7%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|11|0.0%|1.6%|
[ri_web_proxies](#ri_web_proxies)|4329|4329|10|0.2%|1.4%|
[ri_connect_proxies](#ri_connect_proxies)|1693|1693|6|0.3%|0.8%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7698|7698|3|0.0%|0.4%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|2|0.0%|0.2%|
[nixspam](#nixspam)|31903|31903|2|0.0%|0.2%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2|0.0%|0.2%|
[et_block](#et_block)|975|18056513|2|0.0%|0.2%|
[blocklist_de_bots](#blocklist_de_bots)|3492|3492|2|0.0%|0.2%|
[blocklist_de](#blocklist_de)|22576|22576|2|0.0%|0.2%|
[snort_ipfilter](#snort_ipfilter)|7240|7240|1|0.0%|0.1%|
[php_dictionary](#php_dictionary)|398|398|1|0.2%|0.1%|
[alienvault_reputation](#alienvault_reputation)|178600|178600|1|0.0%|0.1%|

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
[alienvault_reputation](#alienvault_reputation)|178600|178600|293|0.1%|0.0%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92103|92103|44|0.0%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|25|1.9%|0.0%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30710|30710|22|0.0%|0.0%|
[et_tor](#et_tor)|6490|6490|21|0.3%|0.0%|
[dm_tor](#dm_tor)|6461|6461|21|0.3%|0.0%|
[bm_tor](#bm_tor)|6462|6462|21|0.3%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|19|1.3%|0.0%|
[snort_ipfilter](#snort_ipfilter)|7240|7240|15|0.2%|0.0%|
[nixspam](#nixspam)|31903|31903|13|0.0%|0.0%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7698|7698|8|0.1%|0.0%|
[blocklist_de](#blocklist_de)|22576|22576|7|0.0%|0.0%|
[openbl_90d](#openbl_90d)|9892|9892|6|0.0%|0.0%|
[openbl](#openbl)|9892|9892|6|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|6|0.0%|0.0%|
[openbl_60d](#openbl_60d)|7795|7795|5|0.0%|0.0%|
[voipbl](#voipbl)|10286|10757|4|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|4329|4329|4|0.0%|0.0%|
[openbl_30d](#openbl_30d)|4448|4448|4|0.0%|0.0%|
[dshield](#dshield)|20|5120|4|0.0%|0.0%|
[malc0de](#malc0de)|411|411|3|0.7%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|12757|12757|3|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2249|2249|2|0.0%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|98|98|2|2.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14780|14780|2|0.0%|0.0%|
[zeus_badips](#zeus_badips)|230|230|1|0.4%|0.0%|
[zeus](#zeus)|265|265|1|0.3%|0.0%|
[sslbl](#sslbl)|345|345|1|0.2%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|1|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.0%|
[php_dictionary](#php_dictionary)|398|398|1|0.2%|0.0%|
[palevo](#palevo)|13|13|1|7.6%|0.0%|
[openbl_7d](#openbl_7d)|1003|1003|1|0.0%|0.0%|
[feodo](#feodo)|67|67|1|1.4%|0.0%|
[bogons](#bogons)|13|592708608|1|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1453|1453|1|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3492|3492|1|0.0%|0.0%|

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
[alienvault_reputation](#alienvault_reputation)|178600|178600|8|0.0%|0.5%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|7|0.0%|0.4%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|6|0.0%|0.4%|
[et_block](#et_block)|975|18056513|6|0.0%|0.4%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|3|0.2%|0.2%|
[blocklist_de](#blocklist_de)|22576|22576|3|0.0%|0.2%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30710|30710|2|0.0%|0.1%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92103|92103|2|0.0%|0.1%|
[snort_ipfilter](#snort_ipfilter)|7240|7240|2|0.0%|0.1%|
[openbl_90d](#openbl_90d)|9892|9892|2|0.0%|0.1%|
[openbl_60d](#openbl_60d)|7795|7795|2|0.0%|0.1%|
[openbl_30d](#openbl_30d)|4448|4448|2|0.0%|0.1%|
[openbl](#openbl)|9892|9892|2|0.0%|0.1%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|2|0.2%|0.1%|
[bruteforceblocker](#bruteforceblocker)|2426|2426|2|0.0%|0.1%|
[blocklist_de_ssh](#blocklist_de_ssh)|2249|2249|2|0.0%|0.1%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7698|7698|1|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|4329|4329|1|0.0%|0.0%|
[openbl_7d](#openbl_7d)|1003|1003|1|0.0%|0.0%|
[openbl_1d](#openbl_1d)|357|357|1|0.2%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1|0.0%|0.0%|
[et_tor](#et_tor)|6490|6490|1|0.0%|0.0%|
[et_compromised](#et_compromised)|2338|2338|1|0.0%|0.0%|
[et_botnet](#et_botnet)|512|512|1|0.1%|0.0%|
[dm_tor](#dm_tor)|6461|6461|1|0.0%|0.0%|
[bm_tor](#bm_tor)|6462|6462|1|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|226|226|1|0.4%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3492|3492|1|0.0%|0.0%|

## malc0de

[Malc0de.com](http://malc0de.com) malicious IPs of the last 30 days

Source is downloaded from [this link](http://malc0de.com/bl/IP_Blacklist.txt).

The last time downloaded was found to be dated: Thu May 28 13:17:02 UTC 2015.

The ipset `malc0de` has **411** entries, **411** unique IPs.

The following table shows the overlaps of `malc0de` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `malc0de`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `malc0de`.
- ` this % ` is the percentage **of this ipset (`malc0de`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|76|0.0%|18.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|26|0.0%|6.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|12|0.0%|2.9%|
[clean_mx_viruses](#clean_mx_viruses)|104|104|11|10.5%|2.6%|
[alienvault_reputation](#alienvault_reputation)|178600|178600|10|0.0%|2.4%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|4|0.3%|0.9%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|3|0.0%|0.7%|
[et_block](#et_block)|975|18056513|3|0.0%|0.7%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|2|0.0%|0.4%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|1|0.0%|0.2%|
[snort_ipfilter](#snort_ipfilter)|7240|7240|1|0.0%|0.2%|
[dshield](#dshield)|20|5120|1|0.0%|0.2%|

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
[snort_ipfilter](#snort_ipfilter)|7240|7240|25|0.3%|1.9%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|25|0.0%|1.9%|
[fullbogons](#fullbogons)|3656|670735064|9|0.0%|0.7%|
[alienvault_reputation](#alienvault_reputation)|178600|178600|6|0.0%|0.4%|
[malc0de](#malc0de)|411|411|4|0.9%|0.3%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|3|0.2%|0.2%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92103|92103|2|0.0%|0.1%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30710|30710|1|0.0%|0.0%|
[nixspam](#nixspam)|31903|31903|1|0.0%|0.0%|
[et_botnet](#et_botnet)|512|512|1|0.1%|0.0%|
[clean_mx_viruses](#clean_mx_viruses)|104|104|1|0.9%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3492|3492|1|0.0%|0.0%|
[blocklist_de](#blocklist_de)|22576|22576|1|0.0%|0.0%|

## nixspam

[NiX Spam](http://www.heise.de/ix/NiX-Spam-DNSBL-and-blacklist-for-download-499637.html) IP addresses that sent spam in the last hour - automatically generated entries without distinguishing open proxies from relays, dialup gateways, and so on. All IPs are removed after 12 hours if there is no spam from there.

Source is downloaded from [this link](http://www.dnsbl.manitu.net/download/nixspam-ip.dump.gz).

The last time downloaded was found to be dated: Thu May 28 14:30:02 UTC 2015.

The ipset `nixspam` has **31903** entries, **31903** unique IPs.

The following table shows the overlaps of `nixspam` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `nixspam`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `nixspam`.
- ` this % ` is the percentage **of this ipset (`nixspam`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|2788|0.0%|8.7%|
[blocklist_de](#blocklist_de)|22576|22576|783|3.4%|2.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|736|0.0%|2.3%|
[blocklist_de_mail](#blocklist_de_mail)|14780|14780|706|4.7%|2.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|583|0.0%|1.8%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92103|92103|278|0.3%|0.8%|
[snort_ipfilter](#snort_ipfilter)|7240|7240|223|3.0%|0.6%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|211|0.0%|0.6%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|206|0.0%|0.6%|
[et_block](#et_block)|975|18056513|206|0.0%|0.6%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30710|30710|151|0.4%|0.4%|
[php_dictionary](#php_dictionary)|398|398|92|23.1%|0.2%|
[ri_web_proxies](#ri_web_proxies)|4329|4329|79|1.8%|0.2%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7698|7698|76|0.9%|0.2%|
[php_spammers](#php_spammers)|417|417|73|17.5%|0.2%|
[blocklist_de_bots](#blocklist_de_bots)|3492|3492|57|1.6%|0.1%|
[alienvault_reputation](#alienvault_reputation)|178600|178600|51|0.0%|0.1%|
[openbl_90d](#openbl_90d)|9892|9892|20|0.2%|0.0%|
[openbl](#openbl)|9892|9892|20|0.2%|0.0%|
[openbl_60d](#openbl_60d)|7795|7795|18|0.2%|0.0%|
[php_commenters](#php_commenters)|281|281|17|6.0%|0.0%|
[php_bad](#php_bad)|281|281|16|5.6%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|1693|1693|15|0.8%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|14|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|13|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|10|3.8%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|12757|12757|9|0.0%|0.0%|
[openbl_30d](#openbl_30d)|4448|4448|8|0.1%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1453|1453|8|0.5%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|705|705|7|0.9%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|273|273|7|2.5%|0.0%|
[voipbl](#voipbl)|10286|10757|4|0.0%|0.0%|
[et_tor](#et_tor)|6490|6490|3|0.0%|0.0%|
[dm_tor](#dm_tor)|6461|6461|3|0.0%|0.0%|
[bm_tor](#bm_tor)|6462|6462|3|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|2|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|2|0.2%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|226|226|2|0.8%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2249|2249|2|0.0%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|1|0.0%|0.0%|
[dshield](#dshield)|20|5120|1|0.0%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|98|98|1|1.0%|0.0%|

## openbl

[OpenBL.org](http://www.openbl.org/) default blacklist (currently it is the same with 90 days). OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications - **excellent list**

Source is downloaded from [this link](http://www.openbl.org/lists/base.txt.gz).

The last time downloaded was found to be dated: Thu May 28 11:17:00 UTC 2015.

The ipset `openbl` has **9892** entries, **9892** unique IPs.

The following table shows the overlaps of `openbl` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl`.
- ` this % ` is the percentage **of this ipset (`openbl`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[openbl_90d](#openbl_90d)|9892|9892|9892|100.0%|100.0%|
[alienvault_reputation](#alienvault_reputation)|178600|178600|9862|5.5%|99.6%|
[openbl_60d](#openbl_60d)|7795|7795|7795|100.0%|78.8%|
[openbl_30d](#openbl_30d)|4448|4448|4448|100.0%|44.9%|
[bruteforceblocker](#bruteforceblocker)|2426|2426|1429|58.9%|14.4%|
[et_compromised](#et_compromised)|2338|2338|1392|59.5%|14.0%|
[blocklist_de](#blocklist_de)|22576|22576|1313|5.8%|13.2%|
[blocklist_de_ssh](#blocklist_de_ssh)|2249|2249|1229|54.6%|12.4%|
[openbl_7d](#openbl_7d)|1003|1003|1003|100.0%|10.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|960|0.0%|9.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|514|0.0%|5.1%|
[et_block](#et_block)|975|18056513|455|0.0%|4.5%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|447|0.0%|4.5%|
[openbl_1d](#openbl_1d)|357|357|357|100.0%|3.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|221|0.0%|2.2%|
[dshield](#dshield)|20|5120|169|3.3%|1.7%|
[blocklist_de_strongips](#blocklist_de_strongips)|226|226|76|33.6%|0.7%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92103|92103|66|0.0%|0.6%|
[blocklist_de_mail](#blocklist_de_mail)|14780|14780|60|0.4%|0.6%|
[blocklist_de_imap](#blocklist_de_imap)|705|705|46|6.5%|0.4%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30710|30710|36|0.1%|0.3%|
[snort_ipfilter](#snort_ipfilter)|7240|7240|26|0.3%|0.2%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7698|7698|23|0.2%|0.2%|
[et_tor](#et_tor)|6490|6490|21|0.3%|0.2%|
[nixspam](#nixspam)|31903|31903|20|0.0%|0.2%|
[dm_tor](#dm_tor)|6461|6461|20|0.3%|0.2%|
[bm_tor](#bm_tor)|6462|6462|20|0.3%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|19|0.0%|0.1%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|14|0.0%|0.1%|
[blocklist_de_apache](#blocklist_de_apache)|12757|12757|13|0.1%|0.1%|
[voipbl](#voipbl)|10286|10757|12|0.1%|0.1%|
[shunlist](#shunlist)|51|51|11|21.5%|0.1%|
[php_commenters](#php_commenters)|281|281|8|2.8%|0.0%|
[php_bad](#php_bad)|281|281|8|2.8%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|273|273|7|2.5%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|6|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|5|1.9%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1453|1453|5|0.3%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3492|3492|3|0.0%|0.0%|
[zeus](#zeus)|265|265|2|0.7%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.0%|
[zeus_badips](#zeus_badips)|230|230|1|0.4%|0.0%|
[sslbl](#sslbl)|345|345|1|0.2%|0.0%|
[ri_web_proxies](#ri_web_proxies)|4329|4329|1|0.0%|0.0%|
[ciarmy](#ciarmy)|404|404|1|0.2%|0.0%|

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
[openbl_90d](#openbl_90d)|9892|9892|357|3.6%|100.0%|
[openbl_60d](#openbl_60d)|7795|7795|357|4.5%|100.0%|
[openbl_30d](#openbl_30d)|4448|4448|357|8.0%|100.0%|
[openbl](#openbl)|9892|9892|357|3.6%|100.0%|
[alienvault_reputation](#alienvault_reputation)|178600|178600|355|0.1%|99.4%|
[blocklist_de](#blocklist_de)|22576|22576|242|1.0%|67.7%|
[blocklist_de_ssh](#blocklist_de_ssh)|2249|2249|232|10.3%|64.9%|
[openbl_7d](#openbl_7d)|1003|1003|207|20.6%|57.9%|
[et_compromised](#et_compromised)|2338|2338|207|8.8%|57.9%|
[bruteforceblocker](#bruteforceblocker)|2426|2426|203|8.3%|56.8%|
[blocklist_de_strongips](#blocklist_de_strongips)|226|226|68|30.0%|19.0%|
[dshield](#dshield)|20|5120|47|0.9%|13.1%|
[et_block](#et_block)|975|18056513|27|0.0%|7.5%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|26|0.0%|7.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|20|0.0%|5.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|17|0.0%|4.7%|
[blocklist_de_mail](#blocklist_de_mail)|14780|14780|9|0.0%|2.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|7|0.0%|1.9%|
[blocklist_de_imap](#blocklist_de_imap)|705|705|6|0.8%|1.6%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|5|0.0%|1.4%|
[shunlist](#shunlist)|51|51|2|3.9%|0.5%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92103|92103|1|0.0%|0.2%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|1|0.0%|0.2%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.2%|
[blocklist_de_ftp](#blocklist_de_ftp)|273|273|1|0.3%|0.2%|

## openbl_30d

[OpenBL.org](http://www.openbl.org/) last 30 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.

Source is downloaded from [this link](http://www.openbl.org/lists/base_30days.txt.gz).

The last time downloaded was found to be dated: Thu May 28 11:17:00 UTC 2015.

The ipset `openbl_30d` has **4448** entries, **4448** unique IPs.

The following table shows the overlaps of `openbl_30d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl_30d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl_30d`.
- ` this % ` is the percentage **of this ipset (`openbl_30d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[openbl_90d](#openbl_90d)|9892|9892|4448|44.9%|100.0%|
[openbl_60d](#openbl_60d)|7795|7795|4448|57.0%|100.0%|
[openbl](#openbl)|9892|9892|4448|44.9%|100.0%|
[alienvault_reputation](#alienvault_reputation)|178600|178600|4429|2.4%|99.5%|
[bruteforceblocker](#bruteforceblocker)|2426|2426|1351|55.6%|30.3%|
[et_compromised](#et_compromised)|2338|2338|1322|56.5%|29.7%|
[blocklist_de](#blocklist_de)|22576|22576|1162|5.1%|26.1%|
[blocklist_de_ssh](#blocklist_de_ssh)|2249|2249|1101|48.9%|24.7%|
[openbl_7d](#openbl_7d)|1003|1003|1003|100.0%|22.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|446|0.0%|10.0%|
[openbl_1d](#openbl_1d)|357|357|357|100.0%|8.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|229|0.0%|5.1%|
[et_block](#et_block)|975|18056513|213|0.0%|4.7%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|208|0.0%|4.6%|
[dshield](#dshield)|20|5120|135|2.6%|3.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|101|0.0%|2.2%|
[blocklist_de_strongips](#blocklist_de_strongips)|226|226|74|32.7%|1.6%|
[blocklist_de_mail](#blocklist_de_mail)|14780|14780|50|0.3%|1.1%|
[blocklist_de_imap](#blocklist_de_imap)|705|705|38|5.3%|0.8%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92103|92103|18|0.0%|0.4%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|13|0.0%|0.2%|
[shunlist](#shunlist)|51|51|10|19.6%|0.2%|
[nixspam](#nixspam)|31903|31903|8|0.0%|0.1%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30710|30710|7|0.0%|0.1%|
[blocklist_de_apache](#blocklist_de_apache)|12757|12757|7|0.0%|0.1%|
[voipbl](#voipbl)|10286|10757|4|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|4|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|7240|7240|3|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|273|273|3|1.0%|0.0%|
[zeus](#zeus)|265|265|2|0.7%|0.0%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7698|7698|2|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.0%|
[zeus_badips](#zeus_badips)|230|230|1|0.4%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|1|0.0%|0.0%|
[ciarmy](#ciarmy)|404|404|1|0.2%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1453|1453|1|0.0%|0.0%|

## openbl_60d

[OpenBL.org](http://www.openbl.org/) last 60 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.

Source is downloaded from [this link](http://www.openbl.org/lists/base_60days.txt.gz).

The last time downloaded was found to be dated: Thu May 28 11:17:00 UTC 2015.

The ipset `openbl_60d` has **7795** entries, **7795** unique IPs.

The following table shows the overlaps of `openbl_60d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl_60d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl_60d`.
- ` this % ` is the percentage **of this ipset (`openbl_60d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[openbl_90d](#openbl_90d)|9892|9892|7795|78.8%|100.0%|
[openbl](#openbl)|9892|9892|7795|78.8%|100.0%|
[alienvault_reputation](#alienvault_reputation)|178600|178600|7768|4.3%|99.6%|
[openbl_30d](#openbl_30d)|4448|4448|4448|100.0%|57.0%|
[bruteforceblocker](#bruteforceblocker)|2426|2426|1412|58.2%|18.1%|
[et_compromised](#et_compromised)|2338|2338|1382|59.1%|17.7%|
[blocklist_de](#blocklist_de)|22576|22576|1255|5.5%|16.1%|
[blocklist_de_ssh](#blocklist_de_ssh)|2249|2249|1183|52.6%|15.1%|
[openbl_7d](#openbl_7d)|1003|1003|1003|100.0%|12.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|718|0.0%|9.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|365|0.0%|4.6%|
[openbl_1d](#openbl_1d)|357|357|357|100.0%|4.5%|
[et_block](#et_block)|975|18056513|296|0.0%|3.7%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|290|0.0%|3.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|182|0.0%|2.3%|
[dshield](#dshield)|20|5120|155|3.0%|1.9%|
[blocklist_de_strongips](#blocklist_de_strongips)|226|226|75|33.1%|0.9%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92103|92103|59|0.0%|0.7%|
[blocklist_de_mail](#blocklist_de_mail)|14780|14780|56|0.3%|0.7%|
[blocklist_de_imap](#blocklist_de_imap)|705|705|42|5.9%|0.5%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30710|30710|34|0.1%|0.4%|
[snort_ipfilter](#snort_ipfilter)|7240|7240|26|0.3%|0.3%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7698|7698|22|0.2%|0.2%|
[et_tor](#et_tor)|6490|6490|21|0.3%|0.2%|
[dm_tor](#dm_tor)|6461|6461|20|0.3%|0.2%|
[bm_tor](#bm_tor)|6462|6462|20|0.3%|0.2%|
[nixspam](#nixspam)|31903|31903|18|0.0%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|18|0.0%|0.2%|
[shunlist](#shunlist)|51|51|11|21.5%|0.1%|
[blocklist_de_apache](#blocklist_de_apache)|12757|12757|10|0.0%|0.1%|
[voipbl](#voipbl)|10286|10757|9|0.0%|0.1%|
[php_commenters](#php_commenters)|281|281|8|2.8%|0.1%|
[php_bad](#php_bad)|281|281|8|2.8%|0.1%|
[php_harvesters](#php_harvesters)|257|257|5|1.9%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|5|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|273|273|5|1.8%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1453|1453|3|0.2%|0.0%|
[zeus](#zeus)|265|265|2|0.7%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.0%|
[zeus_badips](#zeus_badips)|230|230|1|0.4%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|1|0.0%|0.0%|
[ciarmy](#ciarmy)|404|404|1|0.2%|0.0%|

## openbl_7d

[OpenBL.org](http://www.openbl.org/) last 7 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.

Source is downloaded from [this link](http://www.openbl.org/lists/base_7days.txt.gz).

The last time downloaded was found to be dated: Thu May 28 11:17:00 UTC 2015.

The ipset `openbl_7d` has **1003** entries, **1003** unique IPs.

The following table shows the overlaps of `openbl_7d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl_7d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl_7d`.
- ` this % ` is the percentage **of this ipset (`openbl_7d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[openbl_90d](#openbl_90d)|9892|9892|1003|10.1%|100.0%|
[openbl_60d](#openbl_60d)|7795|7795|1003|12.8%|100.0%|
[openbl_30d](#openbl_30d)|4448|4448|1003|22.5%|100.0%|
[openbl](#openbl)|9892|9892|1003|10.1%|100.0%|
[alienvault_reputation](#alienvault_reputation)|178600|178600|989|0.5%|98.6%|
[blocklist_de](#blocklist_de)|22576|22576|665|2.9%|66.3%|
[blocklist_de_ssh](#blocklist_de_ssh)|2249|2249|631|28.0%|62.9%|
[bruteforceblocker](#bruteforceblocker)|2426|2426|521|21.4%|51.9%|
[et_compromised](#et_compromised)|2338|2338|500|21.3%|49.8%|
[openbl_1d](#openbl_1d)|357|357|207|57.9%|20.6%|
[dshield](#dshield)|20|5120|108|2.1%|10.7%|
[et_block](#et_block)|975|18056513|101|0.0%|10.0%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|98|0.0%|9.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|93|0.0%|9.2%|
[blocklist_de_strongips](#blocklist_de_strongips)|226|226|74|32.7%|7.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|51|0.0%|5.0%|
[blocklist_de_mail](#blocklist_de_mail)|14780|14780|28|0.1%|2.7%|
[blocklist_de_imap](#blocklist_de_imap)|705|705|24|3.4%|2.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|19|0.0%|1.8%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|9|0.0%|0.8%|
[shunlist](#shunlist)|51|51|5|9.8%|0.4%|
[blocklist_de_apache](#blocklist_de_apache)|12757|12757|4|0.0%|0.3%|
[voipbl](#voipbl)|10286|10757|3|0.0%|0.2%|
[snort_ipfilter](#snort_ipfilter)|7240|7240|2|0.0%|0.1%|
[blocklist_de_ftp](#blocklist_de_ftp)|273|273|2|0.7%|0.1%|
[zeus](#zeus)|265|265|1|0.3%|0.0%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92103|92103|1|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|1|0.0%|0.0%|
[ciarmy](#ciarmy)|404|404|1|0.2%|0.0%|

## openbl_90d

[OpenBL.org](http://www.openbl.org/) last 90 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.

Source is downloaded from [this link](http://www.openbl.org/lists/base_90days.txt.gz).

The last time downloaded was found to be dated: Thu May 28 11:17:00 UTC 2015.

The ipset `openbl_90d` has **9892** entries, **9892** unique IPs.

The following table shows the overlaps of `openbl_90d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl_90d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl_90d`.
- ` this % ` is the percentage **of this ipset (`openbl_90d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[openbl](#openbl)|9892|9892|9892|100.0%|100.0%|
[alienvault_reputation](#alienvault_reputation)|178600|178600|9862|5.5%|99.6%|
[openbl_60d](#openbl_60d)|7795|7795|7795|100.0%|78.8%|
[openbl_30d](#openbl_30d)|4448|4448|4448|100.0%|44.9%|
[bruteforceblocker](#bruteforceblocker)|2426|2426|1429|58.9%|14.4%|
[et_compromised](#et_compromised)|2338|2338|1392|59.5%|14.0%|
[blocklist_de](#blocklist_de)|22576|22576|1313|5.8%|13.2%|
[blocklist_de_ssh](#blocklist_de_ssh)|2249|2249|1229|54.6%|12.4%|
[openbl_7d](#openbl_7d)|1003|1003|1003|100.0%|10.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|960|0.0%|9.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|514|0.0%|5.1%|
[et_block](#et_block)|975|18056513|455|0.0%|4.5%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|447|0.0%|4.5%|
[openbl_1d](#openbl_1d)|357|357|357|100.0%|3.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|221|0.0%|2.2%|
[dshield](#dshield)|20|5120|169|3.3%|1.7%|
[blocklist_de_strongips](#blocklist_de_strongips)|226|226|76|33.6%|0.7%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92103|92103|66|0.0%|0.6%|
[blocklist_de_mail](#blocklist_de_mail)|14780|14780|60|0.4%|0.6%|
[blocklist_de_imap](#blocklist_de_imap)|705|705|46|6.5%|0.4%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30710|30710|36|0.1%|0.3%|
[snort_ipfilter](#snort_ipfilter)|7240|7240|26|0.3%|0.2%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7698|7698|23|0.2%|0.2%|
[et_tor](#et_tor)|6490|6490|21|0.3%|0.2%|
[nixspam](#nixspam)|31903|31903|20|0.0%|0.2%|
[dm_tor](#dm_tor)|6461|6461|20|0.3%|0.2%|
[bm_tor](#bm_tor)|6462|6462|20|0.3%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|19|0.0%|0.1%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|14|0.0%|0.1%|
[blocklist_de_apache](#blocklist_de_apache)|12757|12757|13|0.1%|0.1%|
[voipbl](#voipbl)|10286|10757|12|0.1%|0.1%|
[shunlist](#shunlist)|51|51|11|21.5%|0.1%|
[php_commenters](#php_commenters)|281|281|8|2.8%|0.0%|
[php_bad](#php_bad)|281|281|8|2.8%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|273|273|7|2.5%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|6|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|5|1.9%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1453|1453|5|0.3%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3492|3492|3|0.0%|0.0%|
[zeus](#zeus)|265|265|2|0.7%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.0%|
[zeus_badips](#zeus_badips)|230|230|1|0.4%|0.0%|
[sslbl](#sslbl)|345|345|1|0.2%|0.0%|
[ri_web_proxies](#ri_web_proxies)|4329|4329|1|0.0%|0.0%|
[ciarmy](#ciarmy)|404|404|1|0.2%|0.0%|

## palevo

[Abuse.ch Palevo tracker](https://palevotracker.abuse.ch) worm includes IPs which are being used as botnet C&C for the Palevo crimeware - **excellent list**

Source is downloaded from [this link](https://palevotracker.abuse.ch/blocklists.php?download=ipblocklist).

The last time downloaded was found to be dated: Thu May 28 14:20:20 UTC 2015.

The ipset `palevo` has **13** entries, **13** unique IPs.

The following table shows the overlaps of `palevo` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `palevo`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `palevo`.
- ` this % ` is the percentage **of this ipset (`palevo`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[et_block](#et_block)|975|18056513|13|0.0%|100.0%|
[snort_ipfilter](#snort_ipfilter)|7240|7240|11|0.1%|84.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|2|0.0%|15.3%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|1|0.0%|7.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|1|0.0%|7.6%|

## php_bad

[projecthoneypot.org](http://www.projecthoneypot.org/) bad web hosts (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=b&rss=1).

The last time downloaded was found to be dated: Thu May 28 13:48:26 UTC 2015.

The ipset `php_bad` has **281** entries, **281** unique IPs.

The following table shows the overlaps of `php_bad` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `php_bad`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `php_bad`.
- ` this % ` is the percentage **of this ipset (`php_bad`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[php_commenters](#php_commenters)|281|281|279|99.2%|99.2%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92103|92103|202|0.2%|71.8%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30710|30710|190|0.6%|67.6%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7698|7698|114|1.4%|40.5%|
[blocklist_de](#blocklist_de)|22576|22576|81|0.3%|28.8%|
[blocklist_de_bots](#blocklist_de_bots)|3492|3492|67|1.9%|23.8%|
[snort_ipfilter](#snort_ipfilter)|7240|7240|41|0.5%|14.5%|
[blocklist_de_strongips](#blocklist_de_strongips)|226|226|34|15.0%|12.0%|
[php_spammers](#php_spammers)|417|417|32|7.6%|11.3%|
[et_tor](#et_tor)|6490|6490|29|0.4%|10.3%|
[dm_tor](#dm_tor)|6461|6461|29|0.4%|10.3%|
[bm_tor](#bm_tor)|6462|6462|29|0.4%|10.3%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|25|0.0%|8.8%|
[et_block](#et_block)|975|18056513|24|0.0%|8.5%|
[blocklist_de_apache](#blocklist_de_apache)|12757|12757|23|0.1%|8.1%|
[php_dictionary](#php_dictionary)|398|398|21|5.2%|7.4%|
[blocklist_de_mail](#blocklist_de_mail)|14780|14780|21|0.1%|7.4%|
[nixspam](#nixspam)|31903|31903|16|0.0%|5.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|16|0.0%|5.6%|
[alienvault_reputation](#alienvault_reputation)|178600|178600|12|0.0%|4.2%|
[php_harvesters](#php_harvesters)|257|257|9|3.5%|3.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|9|0.0%|3.2%|
[openbl_90d](#openbl_90d)|9892|9892|8|0.0%|2.8%|
[openbl_60d](#openbl_60d)|7795|7795|8|0.1%|2.8%|
[openbl](#openbl)|9892|9892|8|0.0%|2.8%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|7|0.0%|2.4%|
[ri_web_proxies](#ri_web_proxies)|4329|4329|7|0.1%|2.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|5|0.0%|1.7%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1453|1453|4|0.2%|1.4%|
[zeus_badips](#zeus_badips)|230|230|1|0.4%|0.3%|
[zeus](#zeus)|265|265|1|0.3%|0.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.3%|

## php_commenters

[projecthoneypot.org](http://www.projecthoneypot.org/) comment spammers (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=c&rss=1).

The last time downloaded was found to be dated: Thu May 28 13:48:27 UTC 2015.

The ipset `php_commenters` has **281** entries, **281** unique IPs.

The following table shows the overlaps of `php_commenters` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `php_commenters`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `php_commenters`.
- ` this % ` is the percentage **of this ipset (`php_commenters`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[php_bad](#php_bad)|281|281|279|99.2%|99.2%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92103|92103|203|0.2%|72.2%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30710|30710|191|0.6%|67.9%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7698|7698|114|1.4%|40.5%|
[blocklist_de](#blocklist_de)|22576|22576|82|0.3%|29.1%|
[blocklist_de_bots](#blocklist_de_bots)|3492|3492|67|1.9%|23.8%|
[snort_ipfilter](#snort_ipfilter)|7240|7240|40|0.5%|14.2%|
[blocklist_de_strongips](#blocklist_de_strongips)|226|226|34|15.0%|12.0%|
[php_spammers](#php_spammers)|417|417|32|7.6%|11.3%|
[et_tor](#et_tor)|6490|6490|29|0.4%|10.3%|
[dm_tor](#dm_tor)|6461|6461|29|0.4%|10.3%|
[bm_tor](#bm_tor)|6462|6462|29|0.4%|10.3%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|25|0.0%|8.8%|
[et_block](#et_block)|975|18056513|24|0.0%|8.5%|
[blocklist_de_apache](#blocklist_de_apache)|12757|12757|23|0.1%|8.1%|
[blocklist_de_mail](#blocklist_de_mail)|14780|14780|22|0.1%|7.8%|
[php_dictionary](#php_dictionary)|398|398|21|5.2%|7.4%|
[nixspam](#nixspam)|31903|31903|17|0.0%|6.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|15|0.0%|5.3%|
[alienvault_reputation](#alienvault_reputation)|178600|178600|12|0.0%|4.2%|
[php_harvesters](#php_harvesters)|257|257|9|3.5%|3.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|9|0.0%|3.2%|
[openbl_90d](#openbl_90d)|9892|9892|8|0.0%|2.8%|
[openbl_60d](#openbl_60d)|7795|7795|8|0.1%|2.8%|
[openbl](#openbl)|9892|9892|8|0.0%|2.8%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|7|0.0%|2.4%|
[ri_web_proxies](#ri_web_proxies)|4329|4329|7|0.1%|2.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|5|0.0%|1.7%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1453|1453|4|0.2%|1.4%|
[zeus_badips](#zeus_badips)|230|230|1|0.4%|0.3%|
[zeus](#zeus)|265|265|1|0.3%|0.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.3%|

## php_dictionary

[projecthoneypot.org](http://www.projecthoneypot.org/) directory attackers (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=d&rss=1).

The last time downloaded was found to be dated: Thu May 28 13:48:28 UTC 2015.

The ipset `php_dictionary` has **398** entries, **398** unique IPs.

The following table shows the overlaps of `php_dictionary` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `php_dictionary`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `php_dictionary`.
- ` this % ` is the percentage **of this ipset (`php_dictionary`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[nixspam](#nixspam)|31903|31903|92|0.2%|23.1%|
[php_spammers](#php_spammers)|417|417|81|19.4%|20.3%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92103|92103|71|0.0%|17.8%|
[blocklist_de](#blocklist_de)|22576|22576|70|0.3%|17.5%|
[snort_ipfilter](#snort_ipfilter)|7240|7240|66|0.9%|16.5%|
[blocklist_de_mail](#blocklist_de_mail)|14780|14780|61|0.4%|15.3%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30710|30710|53|0.1%|13.3%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7698|7698|26|0.3%|6.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|23|0.0%|5.7%|
[php_commenters](#php_commenters)|281|281|21|7.4%|5.2%|
[php_bad](#php_bad)|281|281|21|7.4%|5.2%|
[ri_web_proxies](#ri_web_proxies)|4329|4329|20|0.4%|5.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|9|0.0%|2.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|9|0.0%|2.2%|
[blocklist_de_bots](#blocklist_de_bots)|3492|3492|8|0.2%|2.0%|
[alienvault_reputation](#alienvault_reputation)|178600|178600|7|0.0%|1.7%|
[dm_tor](#dm_tor)|6461|6461|4|0.0%|1.0%|
[bm_tor](#bm_tor)|6462|6462|4|0.0%|1.0%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|3|0.0%|0.7%|
[et_tor](#et_tor)|6490|6490|3|0.0%|0.7%|
[et_block](#et_block)|975|18056513|3|0.0%|0.7%|
[ri_connect_proxies](#ri_connect_proxies)|1693|1693|2|0.1%|0.5%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|2|0.0%|0.5%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|1|0.0%|0.2%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|1|0.1%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.2%|
[blocklist_de_strongips](#blocklist_de_strongips)|226|226|1|0.4%|0.2%|

## php_harvesters

[projecthoneypot.org](http://www.projecthoneypot.org/) harvesters (IPs that surf the internet looking for email addresses) (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=h&rss=1).

The last time downloaded was found to be dated: Thu May 28 13:48:25 UTC 2015.

The ipset `php_harvesters` has **257** entries, **257** unique IPs.

The following table shows the overlaps of `php_harvesters` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `php_harvesters`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `php_harvesters`.
- ` this % ` is the percentage **of this ipset (`php_harvesters`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92103|92103|62|0.0%|24.1%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30710|30710|50|0.1%|19.4%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7698|7698|38|0.4%|14.7%|
[blocklist_de](#blocklist_de)|22576|22576|31|0.1%|12.0%|
[blocklist_de_bots](#blocklist_de_bots)|3492|3492|26|0.7%|10.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|15|0.0%|5.8%|
[snort_ipfilter](#snort_ipfilter)|7240|7240|10|0.1%|3.8%|
[nixspam](#nixspam)|31903|31903|10|0.0%|3.8%|
[php_commenters](#php_commenters)|281|281|9|3.2%|3.5%|
[php_bad](#php_bad)|281|281|9|3.2%|3.5%|
[alienvault_reputation](#alienvault_reputation)|178600|178600|9|0.0%|3.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|7|0.0%|2.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|7|0.0%|2.7%|
[et_tor](#et_tor)|6490|6490|7|0.1%|2.7%|
[dm_tor](#dm_tor)|6461|6461|7|0.1%|2.7%|
[bm_tor](#bm_tor)|6462|6462|7|0.1%|2.7%|
[openbl_90d](#openbl_90d)|9892|9892|5|0.0%|1.9%|
[openbl_60d](#openbl_60d)|7795|7795|5|0.0%|1.9%|
[openbl](#openbl)|9892|9892|5|0.0%|1.9%|
[blocklist_de_mail](#blocklist_de_mail)|14780|14780|4|0.0%|1.5%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|2|0.0%|0.7%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|1|0.0%|0.3%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|1|0.0%|0.3%|
[ri_web_proxies](#ri_web_proxies)|4329|4329|1|0.0%|0.3%|
[php_spammers](#php_spammers)|417|417|1|0.2%|0.3%|
[php_dictionary](#php_dictionary)|398|398|1|0.2%|0.3%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|1|0.0%|0.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.3%|
[fullbogons](#fullbogons)|3656|670735064|1|0.0%|0.3%|
[et_block](#et_block)|975|18056513|1|0.0%|0.3%|
[bogons](#bogons)|13|592708608|1|0.0%|0.3%|
[blocklist_de_strongips](#blocklist_de_strongips)|226|226|1|0.4%|0.3%|
[blocklist_de_ftp](#blocklist_de_ftp)|273|273|1|0.3%|0.3%|
[blocklist_de_apache](#blocklist_de_apache)|12757|12757|1|0.0%|0.3%|

## php_spammers

[projecthoneypot.org](http://www.projecthoneypot.org/) spam servers (IPs used by spammers to send messages) (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=s&rss=1).

The last time downloaded was found to be dated: Thu May 28 13:48:25 UTC 2015.

The ipset `php_spammers` has **417** entries, **417** unique IPs.

The following table shows the overlaps of `php_spammers` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `php_spammers`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `php_spammers`.
- ` this % ` is the percentage **of this ipset (`php_spammers`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92103|92103|95|0.1%|22.7%|
[php_dictionary](#php_dictionary)|398|398|81|20.3%|19.4%|
[nixspam](#nixspam)|31903|31903|73|0.2%|17.5%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30710|30710|64|0.2%|15.3%|
[blocklist_de](#blocklist_de)|22576|22576|64|0.2%|15.3%|
[snort_ipfilter](#snort_ipfilter)|7240|7240|60|0.8%|14.3%|
[blocklist_de_mail](#blocklist_de_mail)|14780|14780|42|0.2%|10.0%|
[php_commenters](#php_commenters)|281|281|32|11.3%|7.6%|
[php_bad](#php_bad)|281|281|32|11.3%|7.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|31|0.0%|7.4%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7698|7698|29|0.3%|6.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|26|0.0%|6.2%|
[ri_web_proxies](#ri_web_proxies)|4329|4329|17|0.3%|4.0%|
[blocklist_de_bots](#blocklist_de_bots)|3492|3492|16|0.4%|3.8%|
[et_tor](#et_tor)|6490|6490|6|0.0%|1.4%|
[dm_tor](#dm_tor)|6461|6461|6|0.0%|1.4%|
[bm_tor](#bm_tor)|6462|6462|6|0.0%|1.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|5|0.0%|1.1%|
[blocklist_de_strongips](#blocklist_de_strongips)|226|226|5|2.2%|1.1%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1453|1453|5|0.3%|1.1%|
[blocklist_de_apache](#blocklist_de_apache)|12757|12757|5|0.0%|1.1%|
[alienvault_reputation](#alienvault_reputation)|178600|178600|3|0.0%|0.7%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|2|0.0%|0.4%|
[ri_connect_proxies](#ri_connect_proxies)|1693|1693|2|0.1%|0.4%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2|0.0%|0.4%|
[et_block](#et_block)|975|18056513|2|0.0%|0.4%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.2%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1|0.0%|0.2%|

## ri_connect_proxies

[rosinstrument.com](http://www.rosinstrument.com) open CONNECT proxies (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://tools.rosinstrument.com/proxy/plab100.xml).

The last time downloaded was found to be dated: Thu May 28 11:16:07 UTC 2015.

The ipset `ri_connect_proxies` has **1693** entries, **1693** unique IPs.

The following table shows the overlaps of `ri_connect_proxies` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ri_connect_proxies`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ri_connect_proxies`.
- ` this % ` is the percentage **of this ipset (`ri_connect_proxies`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92103|92103|993|1.0%|58.6%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30710|30710|691|2.2%|40.8%|
[ri_web_proxies](#ri_web_proxies)|4329|4329|686|15.8%|40.5%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7698|7698|176|2.2%|10.3%|
[blocklist_de](#blocklist_de)|22576|22576|80|0.3%|4.7%|
[blocklist_de_bots](#blocklist_de_bots)|3492|3492|79|2.2%|4.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|76|0.0%|4.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|60|0.0%|3.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|41|0.0%|2.4%|
[nixspam](#nixspam)|31903|31903|15|0.0%|0.8%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|6|0.8%|0.3%|
[snort_ipfilter](#snort_ipfilter)|7240|7240|3|0.0%|0.1%|
[php_spammers](#php_spammers)|417|417|2|0.4%|0.1%|
[php_dictionary](#php_dictionary)|398|398|2|0.5%|0.1%|
[et_tor](#et_tor)|6490|6490|2|0.0%|0.1%|
[dm_tor](#dm_tor)|6461|6461|2|0.0%|0.1%|
[bm_tor](#bm_tor)|6462|6462|2|0.0%|0.1%|
[blocklist_de_mail](#blocklist_de_mail)|14780|14780|1|0.0%|0.0%|
[alienvault_reputation](#alienvault_reputation)|178600|178600|1|0.0%|0.0%|

## ri_web_proxies

[rosinstrument.com](http://www.rosinstrument.com) open HTTP proxies (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://tools.rosinstrument.com/proxy/l100.xml).

The last time downloaded was found to be dated: Thu May 28 13:34:11 UTC 2015.

The ipset `ri_web_proxies` has **4329** entries, **4329** unique IPs.

The following table shows the overlaps of `ri_web_proxies` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ri_web_proxies`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ri_web_proxies`.
- ` this % ` is the percentage **of this ipset (`ri_web_proxies`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92103|92103|2152|2.3%|49.7%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30710|30710|1597|5.2%|36.8%|
[ri_connect_proxies](#ri_connect_proxies)|1693|1693|686|40.5%|15.8%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7698|7698|547|7.1%|12.6%|
[blocklist_de](#blocklist_de)|22576|22576|383|1.6%|8.8%|
[blocklist_de_bots](#blocklist_de_bots)|3492|3492|355|10.1%|8.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|151|0.0%|3.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|134|0.0%|3.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|99|0.0%|2.2%|
[nixspam](#nixspam)|31903|31903|79|0.2%|1.8%|
[snort_ipfilter](#snort_ipfilter)|7240|7240|28|0.3%|0.6%|
[blocklist_de_mail](#blocklist_de_mail)|14780|14780|25|0.1%|0.5%|
[php_dictionary](#php_dictionary)|398|398|20|5.0%|0.4%|
[php_spammers](#php_spammers)|417|417|17|4.0%|0.3%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|10|1.4%|0.2%|
[php_commenters](#php_commenters)|281|281|7|2.4%|0.1%|
[php_bad](#php_bad)|281|281|7|2.4%|0.1%|
[et_tor](#et_tor)|6490|6490|5|0.0%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|4|0.0%|0.0%|
[dm_tor](#dm_tor)|6461|6461|4|0.0%|0.0%|
[bm_tor](#bm_tor)|6462|6462|4|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|226|226|3|1.3%|0.0%|
[alienvault_reputation](#alienvault_reputation)|178600|178600|3|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.0%|
[openbl_90d](#openbl_90d)|9892|9892|1|0.0%|0.0%|
[openbl](#openbl)|9892|9892|1|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2249|2249|1|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1453|1453|1|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|12757|12757|1|0.0%|0.0%|

## shunlist

[AutoShun.org](http://autoshun.org/) IPs identified as hostile by correlating logs from distributed snort installations running the autoshun plugin

Source is downloaded from [this link](http://www.autoshun.org/files/shunlist.csv).

The last time downloaded was found to be dated: Thu May 28 14:30:06 UTC 2015.

The ipset `shunlist` has **51** entries, **51** unique IPs.

The following table shows the overlaps of `shunlist` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `shunlist`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `shunlist`.
- ` this % ` is the percentage **of this ipset (`shunlist`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[alienvault_reputation](#alienvault_reputation)|178600|178600|50|0.0%|98.0%|
[blocklist_de](#blocklist_de)|22576|22576|12|0.0%|23.5%|
[openbl_90d](#openbl_90d)|9892|9892|11|0.1%|21.5%|
[openbl_60d](#openbl_60d)|7795|7795|11|0.1%|21.5%|
[openbl](#openbl)|9892|9892|11|0.1%|21.5%|
[openbl_30d](#openbl_30d)|4448|4448|10|0.2%|19.6%|
[et_compromised](#et_compromised)|2338|2338|9|0.3%|17.6%|
[bruteforceblocker](#bruteforceblocker)|2426|2426|9|0.3%|17.6%|
[blocklist_de_ssh](#blocklist_de_ssh)|2249|2249|9|0.4%|17.6%|
[openbl_7d](#openbl_7d)|1003|1003|5|0.4%|9.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|4|0.0%|7.8%|
[voipbl](#voipbl)|10286|10757|3|0.0%|5.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|3|0.0%|5.8%|
[openbl_1d](#openbl_1d)|357|357|2|0.5%|3.9%|
[ciarmy](#ciarmy)|404|404|2|0.4%|3.9%|
[blocklist_de_apache](#blocklist_de_apache)|12757|12757|2|0.0%|3.9%|
[blocklist_de_mail](#blocklist_de_mail)|14780|14780|1|0.0%|1.9%|
[blocklist_de_imap](#blocklist_de_imap)|705|705|1|0.1%|1.9%|

## snort_ipfilter

[labs.snort.org](https://labs.snort.org/) supplied IP blacklist (this list seems to be updated frequently, but we found no information about it)

Source is downloaded from [this link](http://labs.snort.org/feeds/ip-filter.blf).

The last time downloaded was found to be dated: Thu May 28 13:30:00 UTC 2015.

The ipset `snort_ipfilter` has **7240** entries, **7240** unique IPs.

The following table shows the overlaps of `snort_ipfilter` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `snort_ipfilter`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `snort_ipfilter`.
- ` this % ` is the percentage **of this ipset (`snort_ipfilter`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[et_tor](#et_tor)|6490|6490|1090|16.7%|15.0%|
[dm_tor](#dm_tor)|6461|6461|1056|16.3%|14.5%|
[bm_tor](#bm_tor)|6462|6462|1056|16.3%|14.5%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92103|92103|718|0.7%|9.9%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30710|30710|526|1.7%|7.2%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7698|7698|354|4.5%|4.8%|
[et_block](#et_block)|975|18056513|286|0.0%|3.9%|
[zeus](#zeus)|265|265|226|85.2%|3.1%|
[nixspam](#nixspam)|31903|31903|223|0.6%|3.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|222|0.0%|3.0%|
[zeus_badips](#zeus_badips)|230|230|202|87.8%|2.7%|
[blocklist_de](#blocklist_de)|22576|22576|188|0.8%|2.5%|
[alienvault_reputation](#alienvault_reputation)|178600|178600|122|0.0%|1.6%|
[blocklist_de_mail](#blocklist_de_mail)|14780|14780|116|0.7%|1.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|101|0.0%|1.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|85|0.0%|1.1%|
[php_dictionary](#php_dictionary)|398|398|66|16.5%|0.9%|
[php_spammers](#php_spammers)|417|417|60|14.3%|0.8%|
[feodo](#feodo)|67|67|48|71.6%|0.6%|
[blocklist_de_apache](#blocklist_de_apache)|12757|12757|44|0.3%|0.6%|
[php_bad](#php_bad)|281|281|41|14.5%|0.5%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1453|1453|41|2.8%|0.5%|
[php_commenters](#php_commenters)|281|281|40|14.2%|0.5%|
[ri_web_proxies](#ri_web_proxies)|4329|4329|28|0.6%|0.3%|
[blocklist_de_bots](#blocklist_de_bots)|3492|3492|27|0.7%|0.3%|
[openbl_90d](#openbl_90d)|9892|9892|26|0.2%|0.3%|
[openbl_60d](#openbl_60d)|7795|7795|26|0.3%|0.3%|
[openbl](#openbl)|9892|9892|26|0.2%|0.3%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|25|1.9%|0.3%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|20|0.0%|0.2%|
[sslbl](#sslbl)|345|345|17|4.9%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|15|0.0%|0.2%|
[palevo](#palevo)|13|13|11|84.6%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|11|0.0%|0.1%|
[php_harvesters](#php_harvesters)|257|257|10|3.8%|0.1%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|6|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|1693|1693|3|0.1%|0.0%|
[openbl_30d](#openbl_30d)|4448|4448|3|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2249|2249|3|0.1%|0.0%|
[openbl_7d](#openbl_7d)|1003|1003|2|0.1%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|705|705|2|0.2%|0.0%|
[malc0de](#malc0de)|411|411|1|0.2%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|1|0.1%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1|0.0%|0.0%|
[et_compromised](#et_compromised)|2338|2338|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2426|2426|1|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|226|226|1|0.4%|0.0%|

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
[alienvault_reputation](#alienvault_reputation)|178600|178600|1624|0.9%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|1037|0.3%|0.0%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92103|92103|782|0.8%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|512|0.1%|0.0%|
[openbl_90d](#openbl_90d)|9892|9892|447|4.5%|0.0%|
[openbl](#openbl)|9892|9892|447|4.5%|0.0%|
[openbl_60d](#openbl_60d)|7795|7795|290|3.7%|0.0%|
[dshield](#dshield)|20|5120|256|5.0%|0.0%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30710|30710|235|0.7%|0.0%|
[nixspam](#nixspam)|31903|31903|211|0.6%|0.0%|
[openbl_30d](#openbl_30d)|4448|4448|208|4.6%|0.0%|
[blocklist_de](#blocklist_de)|22576|22576|189|0.8%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2249|2249|111|4.9%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2426|2426|102|4.2%|0.0%|
[openbl_7d](#openbl_7d)|1003|1003|98|9.7%|0.0%|
[et_compromised](#et_compromised)|2338|2338|92|3.9%|0.0%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7698|7698|52|0.6%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3492|3492|50|1.4%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|28|2.1%|0.0%|
[openbl_1d](#openbl_1d)|357|357|26|7.2%|0.0%|
[php_commenters](#php_commenters)|281|281|25|8.8%|0.0%|
[php_bad](#php_bad)|281|281|25|8.8%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14780|14780|23|0.1%|0.0%|
[snort_ipfilter](#snort_ipfilter)|7240|7240|20|0.2%|0.0%|
[zeus_badips](#zeus_badips)|230|230|16|6.9%|0.0%|
[zeus](#zeus)|265|265|16|6.0%|0.0%|
[voipbl](#voipbl)|10286|10757|14|0.1%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|705|705|14|1.9%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|226|226|7|3.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|6|0.4%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|6|0.0%|0.0%|
[sslbl](#sslbl)|345|345|3|0.8%|0.0%|
[php_dictionary](#php_dictionary)|398|398|3|0.7%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1453|1453|3|0.2%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|12757|12757|3|0.0%|0.0%|
[php_spammers](#php_spammers)|417|417|2|0.4%|0.0%|
[malc0de](#malc0de)|411|411|2|0.4%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|2|0.2%|0.0%|
[et_tor](#et_tor)|6490|6490|2|0.0%|0.0%|
[dm_tor](#dm_tor)|6461|6461|2|0.0%|0.0%|
[bm_tor](#bm_tor)|6462|6462|2|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.0%|
[et_botnet](#et_botnet)|512|512|1|0.1%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|273|273|1|0.3%|0.0%|

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
[stop_forum_spam_30d](#stop_forum_spam_30d)|92103|92103|105|0.1%|0.0%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30710|30710|40|0.1%|0.0%|
[blocklist_de](#blocklist_de)|22576|22576|38|0.1%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3492|3492|32|0.9%|0.0%|
[alienvault_reputation](#alienvault_reputation)|178600|178600|15|0.0%|0.0%|
[openbl_90d](#openbl_90d)|9892|9892|14|0.1%|0.0%|
[openbl](#openbl)|9892|9892|14|0.1%|0.0%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7698|7698|10|0.1%|0.0%|
[php_commenters](#php_commenters)|281|281|7|2.4%|0.0%|
[php_bad](#php_bad)|281|281|7|2.4%|0.0%|
[snort_ipfilter](#snort_ipfilter)|7240|7240|6|0.0%|0.0%|
[zeus_badips](#zeus_badips)|230|230|5|2.1%|0.0%|
[zeus](#zeus)|265|265|5|1.8%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14780|14780|5|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|226|226|4|1.7%|0.0%|
[nixspam](#nixspam)|31903|31903|2|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|705|705|2|0.2%|0.0%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.0%|
[openbl_60d](#openbl_60d)|7795|7795|1|0.0%|0.0%|
[openbl_30d](#openbl_30d)|4448|4448|1|0.0%|0.0%|
[openbl_1d](#openbl_1d)|357|357|1|0.2%|0.0%|
[malc0de](#malc0de)|411|411|1|0.2%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|1|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|12757|12757|1|0.0%|0.0%|

## sslbl

[Abuse.ch SSL Blacklist](https://sslbl.abuse.ch/) bad SSL traffic related to malware or botnet activities - **excellent list**

Source is downloaded from [this link](https://sslbl.abuse.ch/blacklist/sslipblacklist.csv).

The last time downloaded was found to be dated: Thu May 28 14:15:06 UTC 2015.

The ipset `sslbl` has **345** entries, **345** unique IPs.

The following table shows the overlaps of `sslbl` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `sslbl`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `sslbl`.
- ` this % ` is the percentage **of this ipset (`sslbl`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[feodo](#feodo)|67|67|24|35.8%|6.9%|
[et_block](#et_block)|975|18056513|23|0.0%|6.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|22|0.0%|6.3%|
[snort_ipfilter](#snort_ipfilter)|7240|7240|17|0.2%|4.9%|
[alienvault_reputation](#alienvault_reputation)|178600|178600|7|0.0%|2.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|6|0.0%|1.7%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|3|0.0%|0.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|3|0.0%|0.8%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92103|92103|1|0.0%|0.2%|
[openbl_90d](#openbl_90d)|9892|9892|1|0.0%|0.2%|
[openbl](#openbl)|9892|9892|1|0.0%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|1|0.0%|0.2%|

## stop_forum_spam_1h

[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers in the last 24 hours - **excellent list**

Source is downloaded from [this link](http://www.stopforumspam.com/downloads/listed_ip_1.zip).

The last time downloaded was found to be dated: Thu May 28 14:00:02 UTC 2015.

The ipset `stop_forum_spam_1h` has **7698** entries, **7698** unique IPs.

The following table shows the overlaps of `stop_forum_spam_1h` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `stop_forum_spam_1h`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `stop_forum_spam_1h`.
- ` this % ` is the percentage **of this ipset (`stop_forum_spam_1h`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92103|92103|5988|6.5%|77.7%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30710|30710|5882|19.1%|76.4%|
[blocklist_de](#blocklist_de)|22576|22576|1553|6.8%|20.1%|
[blocklist_de_bots](#blocklist_de_bots)|3492|3492|1460|41.8%|18.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|548|0.0%|7.1%|
[ri_web_proxies](#ri_web_proxies)|4329|4329|547|12.6%|7.1%|
[snort_ipfilter](#snort_ipfilter)|7240|7240|354|4.8%|4.5%|
[dm_tor](#dm_tor)|6461|6461|320|4.9%|4.1%|
[bm_tor](#bm_tor)|6462|6462|320|4.9%|4.1%|
[et_tor](#et_tor)|6490|6490|315|4.8%|4.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|239|0.0%|3.1%|
[ri_connect_proxies](#ri_connect_proxies)|1693|1693|176|10.3%|2.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|146|0.0%|1.8%|
[php_commenters](#php_commenters)|281|281|114|40.5%|1.4%|
[php_bad](#php_bad)|281|281|114|40.5%|1.4%|
[blocklist_de_strongips](#blocklist_de_strongips)|226|226|110|48.6%|1.4%|
[blocklist_de_apache](#blocklist_de_apache)|12757|12757|90|0.7%|1.1%|
[nixspam](#nixspam)|31903|31903|76|0.2%|0.9%|
[alienvault_reputation](#alienvault_reputation)|178600|178600|65|0.0%|0.8%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1453|1453|55|3.7%|0.7%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|52|0.0%|0.6%|
[et_block](#et_block)|975|18056513|46|0.0%|0.5%|
[php_harvesters](#php_harvesters)|257|257|38|14.7%|0.4%|
[blocklist_de_mail](#blocklist_de_mail)|14780|14780|38|0.2%|0.4%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|34|0.0%|0.4%|
[php_spammers](#php_spammers)|417|417|29|6.9%|0.3%|
[php_dictionary](#php_dictionary)|398|398|26|6.5%|0.3%|
[openbl_90d](#openbl_90d)|9892|9892|23|0.2%|0.2%|
[openbl](#openbl)|9892|9892|23|0.2%|0.2%|
[openbl_60d](#openbl_60d)|7795|7795|22|0.2%|0.2%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|10|0.0%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|8|0.0%|0.1%|
[voipbl](#voipbl)|10286|10757|3|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|3|0.4%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|3|0.0%|0.0%|
[openbl_30d](#openbl_30d)|4448|4448|2|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2426|2426|1|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2249|2249|1|0.0%|0.0%|

## stop_forum_spam_30d

[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 30 days)

Source is downloaded from [this link](http://www.stopforumspam.com/downloads/listed_ip_30.zip).

The last time downloaded was found to be dated: Thu May 28 00:00:49 UTC 2015.

The ipset `stop_forum_spam_30d` has **92103** entries, **92103** unique IPs.

The following table shows the overlaps of `stop_forum_spam_30d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `stop_forum_spam_30d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `stop_forum_spam_30d`.
- ` this % ` is the percentage **of this ipset (`stop_forum_spam_30d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30710|30710|30535|99.4%|33.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|6117|0.0%|6.6%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7698|7698|5988|77.7%|6.5%|
[blocklist_de](#blocklist_de)|22576|22576|2651|11.7%|2.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|2467|0.0%|2.6%|
[blocklist_de_bots](#blocklist_de_bots)|3492|3492|2354|67.4%|2.5%|
[ri_web_proxies](#ri_web_proxies)|4329|4329|2152|49.7%|2.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|1511|0.0%|1.6%|
[ri_connect_proxies](#ri_connect_proxies)|1693|1693|993|58.6%|1.0%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|782|0.0%|0.8%|
[et_block](#et_block)|975|18056513|762|0.0%|0.8%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|741|0.0%|0.8%|
[snort_ipfilter](#snort_ipfilter)|7240|7240|718|9.9%|0.7%|
[et_tor](#et_tor)|6490|6490|591|9.1%|0.6%|
[dm_tor](#dm_tor)|6461|6461|579|8.9%|0.6%|
[bm_tor](#bm_tor)|6462|6462|579|8.9%|0.6%|
[nixspam](#nixspam)|31903|31903|278|0.8%|0.3%|
[alienvault_reputation](#alienvault_reputation)|178600|178600|228|0.1%|0.2%|
[blocklist_de_apache](#blocklist_de_apache)|12757|12757|223|1.7%|0.2%|
[php_commenters](#php_commenters)|281|281|203|72.2%|0.2%|
[php_bad](#php_bad)|281|281|202|71.8%|0.2%|
[blocklist_de_mail](#blocklist_de_mail)|14780|14780|191|1.2%|0.2%|
[blocklist_de_strongips](#blocklist_de_strongips)|226|226|128|56.6%|0.1%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|105|0.0%|0.1%|
[php_spammers](#php_spammers)|417|417|95|22.7%|0.1%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1453|1453|85|5.8%|0.0%|
[php_dictionary](#php_dictionary)|398|398|71|17.8%|0.0%|
[openbl_90d](#openbl_90d)|9892|9892|66|0.6%|0.0%|
[openbl](#openbl)|9892|9892|66|0.6%|0.0%|
[php_harvesters](#php_harvesters)|257|257|62|24.1%|0.0%|
[openbl_60d](#openbl_60d)|7795|7795|59|0.7%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|44|0.0%|0.0%|
[voipbl](#voipbl)|10286|10757|40|0.3%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|22|3.2%|0.0%|
[openbl_30d](#openbl_30d)|4448|4448|18|0.4%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|16|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2249|2249|8|0.3%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2426|2426|6|0.2%|0.0%|
[et_compromised](#et_compromised)|2338|2338|5|0.2%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|273|273|5|1.8%|0.0%|
[zeus_badips](#zeus_badips)|230|230|3|1.3%|0.0%|
[zeus](#zeus)|265|265|3|1.1%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|2|0.1%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.0%|
[fullbogons](#fullbogons)|3656|670735064|2|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|705|705|2|0.2%|0.0%|
[sslbl](#sslbl)|345|345|1|0.2%|0.0%|
[openbl_7d](#openbl_7d)|1003|1003|1|0.0%|0.0%|
[openbl_1d](#openbl_1d)|357|357|1|0.2%|0.0%|
[ciarmy](#ciarmy)|404|404|1|0.2%|0.0%|
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
[stop_forum_spam_30d](#stop_forum_spam_30d)|92103|92103|30535|33.1%|99.4%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7698|7698|5882|76.4%|19.1%|
[blocklist_de](#blocklist_de)|22576|22576|2296|10.1%|7.4%|
[blocklist_de_bots](#blocklist_de_bots)|3492|3492|2118|60.6%|6.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|2079|0.0%|6.7%|
[ri_web_proxies](#ri_web_proxies)|4329|4329|1597|36.8%|5.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|927|0.0%|3.0%|
[ri_connect_proxies](#ri_connect_proxies)|1693|1693|691|40.8%|2.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|581|0.0%|1.8%|
[snort_ipfilter](#snort_ipfilter)|7240|7240|526|7.2%|1.7%|
[et_tor](#et_tor)|6490|6490|442|6.8%|1.4%|
[dm_tor](#dm_tor)|6461|6461|435|6.7%|1.4%|
[bm_tor](#bm_tor)|6462|6462|435|6.7%|1.4%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|235|0.0%|0.7%|
[et_block](#et_block)|975|18056513|214|0.0%|0.6%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|195|0.0%|0.6%|
[php_commenters](#php_commenters)|281|281|191|67.9%|0.6%|
[php_bad](#php_bad)|281|281|190|67.6%|0.6%|
[nixspam](#nixspam)|31903|31903|151|0.4%|0.4%|
[blocklist_de_apache](#blocklist_de_apache)|12757|12757|136|1.0%|0.4%|
[blocklist_de_strongips](#blocklist_de_strongips)|226|226|117|51.7%|0.3%|
[alienvault_reputation](#alienvault_reputation)|178600|178600|115|0.0%|0.3%|
[blocklist_de_mail](#blocklist_de_mail)|14780|14780|94|0.6%|0.3%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1453|1453|75|5.1%|0.2%|
[php_spammers](#php_spammers)|417|417|64|15.3%|0.2%|
[php_dictionary](#php_dictionary)|398|398|53|13.3%|0.1%|
[php_harvesters](#php_harvesters)|257|257|50|19.4%|0.1%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|40|0.0%|0.1%|
[openbl_90d](#openbl_90d)|9892|9892|36|0.3%|0.1%|
[openbl](#openbl)|9892|9892|36|0.3%|0.1%|
[openbl_60d](#openbl_60d)|7795|7795|34|0.4%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|22|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|12|1.7%|0.0%|
[voipbl](#voipbl)|10286|10757|11|0.1%|0.0%|
[openbl_30d](#openbl_30d)|4448|4448|7|0.1%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|6|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.0%|
[et_compromised](#et_compromised)|2338|2338|2|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2426|2426|2|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2249|2249|2|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|705|705|2|0.2%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|273|273|2|0.7%|0.0%|
[zeus_badips](#zeus_badips)|230|230|1|0.4%|0.0%|
[zeus](#zeus)|265|265|1|0.3%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|1|0.0%|0.0%|

## voipbl

[VoIPBL.org](http://www.voipbl.org/) a distributed VoIP blacklist that is aimed to protects against VoIP Fraud and minimizing abuse for network that have publicly accessible PBX's. Several algorithms, external sources and manual confirmation are used before they categorize something as an attack and determine the threat level.

Source is downloaded from [this link](http://www.voipbl.org/update/).

The last time downloaded was found to be dated: Thu May 28 13:48:43 UTC 2015.

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
[alienvault_reputation](#alienvault_reputation)|178600|178600|197|0.1%|1.8%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92103|92103|40|0.0%|0.3%|
[blocklist_de](#blocklist_de)|22576|22576|37|0.1%|0.3%|
[blocklist_de_sip](#blocklist_de_sip)|98|98|29|29.5%|0.2%|
[et_block](#et_block)|975|18056513|20|0.0%|0.1%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|14|0.0%|0.1%|
[openbl_90d](#openbl_90d)|9892|9892|12|0.1%|0.1%|
[openbl](#openbl)|9892|9892|12|0.1%|0.1%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30710|30710|11|0.0%|0.1%|
[openbl_60d](#openbl_60d)|7795|7795|9|0.1%|0.0%|
[openbl_30d](#openbl_30d)|4448|4448|4|0.0%|0.0%|
[nixspam](#nixspam)|31903|31903|4|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|4|0.0%|0.0%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7698|7698|3|0.0%|0.0%|
[shunlist](#shunlist)|51|51|3|5.8%|0.0%|
[openbl_7d](#openbl_7d)|1003|1003|3|0.2%|0.0%|
[ciarmy](#ciarmy)|404|404|3|0.7%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2249|2249|3|0.1%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|2|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3492|3492|2|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|12757|12757|2|0.0%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.0%|
[et_tor](#et_tor)|6490|6490|1|0.0%|0.0%|
[et_compromised](#et_compromised)|2338|2338|1|0.0%|0.0%|
[dm_tor](#dm_tor)|6461|6461|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2426|2426|1|0.0%|0.0%|
[bm_tor](#bm_tor)|6462|6462|1|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14780|14780|1|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|705|705|1|0.1%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1453|1453|1|0.0%|0.0%|

## zeus

[Abuse.ch Zeus tracker](https://zeustracker.abuse.ch) standard, contains the same data as the ZeuS IP blocklist (zeus_badips) but with the slight difference that it doesn't exclude hijacked websites (level 2) and free web hosting providers (level 3). This means that this blocklist contains all IPv4 addresses associated with ZeuS C&Cs which are currently being tracked by ZeuS Tracker. Hence this blocklist will likely cause some false positives. - **excellent list**

Source is downloaded from [this link](https://zeustracker.abuse.ch/blocklist.php?download=ipblocklist).

The last time downloaded was found to be dated: Thu May 28 13:33:06 UTC 2015.

The ipset `zeus` has **265** entries, **265** unique IPs.

The following table shows the overlaps of `zeus` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `zeus`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `zeus`.
- ` this % ` is the percentage **of this ipset (`zeus`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[et_block](#et_block)|975|18056513|262|0.0%|98.8%|
[zeus_badips](#zeus_badips)|230|230|230|100.0%|86.7%|
[snort_ipfilter](#snort_ipfilter)|7240|7240|226|3.1%|85.2%|
[alienvault_reputation](#alienvault_reputation)|178600|178600|66|0.0%|24.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|19|0.0%|7.1%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|16|0.0%|6.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|10|0.0%|3.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|9|0.0%|3.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|7|0.0%|2.6%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|5|0.0%|1.8%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92103|92103|3|0.0%|1.1%|
[openbl_90d](#openbl_90d)|9892|9892|2|0.0%|0.7%|
[openbl_60d](#openbl_60d)|7795|7795|2|0.0%|0.7%|
[openbl_30d](#openbl_30d)|4448|4448|2|0.0%|0.7%|
[openbl](#openbl)|9892|9892|2|0.0%|0.7%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30710|30710|1|0.0%|0.3%|
[php_commenters](#php_commenters)|281|281|1|0.3%|0.3%|
[php_bad](#php_bad)|281|281|1|0.3%|0.3%|
[openbl_7d](#openbl_7d)|1003|1003|1|0.0%|0.3%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|1|0.0%|0.3%|
[et_compromised](#et_compromised)|2338|2338|1|0.0%|0.3%|
[bruteforceblocker](#bruteforceblocker)|2426|2426|1|0.0%|0.3%|
[blocklist_de_ssh](#blocklist_de_ssh)|2249|2249|1|0.0%|0.3%|
[blocklist_de](#blocklist_de)|22576|22576|1|0.0%|0.3%|

## zeus_badips

[Abuse.ch Zeus tracker](https://zeustracker.abuse.ch) badips includes IPv4 addresses that are used by the ZeuS trojan. It is the recommened blocklist if you want to block only ZeuS IPs. It excludes IP addresses that ZeuS Tracker believes to be hijacked (level 2) or belong to a free web hosting provider (level 3). Hence the false postive rate should be much lower compared to the standard ZeuS IP blocklist. **excellent list**

Source is downloaded from [this link](https://zeustracker.abuse.ch/blocklist.php?download=badips).

The last time downloaded was found to be dated: Thu May 28 14:20:16 UTC 2015.

The ipset `zeus_badips` has **230** entries, **230** unique IPs.

The following table shows the overlaps of `zeus_badips` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `zeus_badips`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `zeus_badips`.
- ` this % ` is the percentage **of this ipset (`zeus_badips`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[zeus](#zeus)|265|265|230|86.7%|100.0%|
[et_block](#et_block)|975|18056513|229|0.0%|99.5%|
[snort_ipfilter](#snort_ipfilter)|7240|7240|202|2.7%|87.8%|
[alienvault_reputation](#alienvault_reputation)|178600|178600|36|0.0%|15.6%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|16|0.0%|6.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|15|0.0%|6.5%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|10|0.0%|4.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|8|0.0%|3.4%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|5|0.0%|2.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|4|0.0%|1.7%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92103|92103|3|0.0%|1.3%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30710|30710|1|0.0%|0.4%|
[php_commenters](#php_commenters)|281|281|1|0.3%|0.4%|
[php_bad](#php_bad)|281|281|1|0.3%|0.4%|
[openbl_90d](#openbl_90d)|9892|9892|1|0.0%|0.4%|
[openbl_60d](#openbl_60d)|7795|7795|1|0.0%|0.4%|
[openbl_30d](#openbl_30d)|4448|4448|1|0.0%|0.4%|
[openbl](#openbl)|9892|9892|1|0.0%|0.4%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|1|0.0%|0.4%|
[et_compromised](#et_compromised)|2338|2338|1|0.0%|0.4%|
[bruteforceblocker](#bruteforceblocker)|2426|2426|1|0.0%|0.4%|
