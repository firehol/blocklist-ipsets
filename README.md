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

The following list was automatically generated on Fri Jun  5 10:45:49 UTC 2015.

The update frequency is the maximum allowed by internal configuration. A list will never be downloaded sooner than the update frequency stated. A list may also not be downloaded, after this frequency expired, if it has not been modified on the server (as reported by HTTP `IF_MODIFIED_SINCE` method).

name|info|type|entries|update|
:--:|:--:|:--:|:-----:|:----:|
[alienvault_reputation](#alienvault_reputation)|[AlienVault.com](https://www.alienvault.com/) IP reputation database (this list seems to include port scanning hosts and to be updated regularly, but we found no information about its retention policy)|ipv4 hash:ip|180239 unique IPs|updated every 6 hours  from [this link](https://reputation.alienvault.com/reputation.generic)
[blocklist_de](#blocklist_de)|[Blocklist.de](https://www.blocklist.de/) IPs that have been detected by fail2ban in the last 48 hours - **excellent list**|ipv4 hash:ip|31150 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/all.txt)
[blocklist_de_apache](#blocklist_de_apache)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service Apache, Apache-DDOS, RFI-Attacks.|ipv4 hash:ip|13701 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/apache.txt)
[blocklist_de_bots](#blocklist_de_bots)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the RFI-Attacks, REG-Bots, IRC-Bots or BadBots (BadBots = he has posted a Spam-Comment on a open Forum or Wiki).|ipv4 hash:ip|3243 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/bots.txt)
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|[Blocklist.de](https://www.blocklist.de/) All IPs which attacks Joomlas, Wordpress and other Web-Logins with Brute-Force Logins.|ipv4 hash:ip|2348 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/bruteforcelogin.txt)
[blocklist_de_ftp](#blocklist_de_ftp)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours for attacks on the Service FTP.|ipv4 hash:ip|915 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/ftp.txt)
[blocklist_de_imap](#blocklist_de_imap)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours for attacks on the Service imap, sasl, pop3, etc.|ipv4 hash:ip|2409 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/imap.txt)
[blocklist_de_mail](#blocklist_de_mail)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service Mail, Postfix.|ipv4 hash:ip|16101 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/mail.txt)
[blocklist_de_sip](#blocklist_de_sip)|[Blocklist.de](https://www.blocklist.de/) All IP addresses that tried to login in a SIP, VOIP or Asterisk Server and are included in the IPs list from [infiltrated.net](www.infiltrated.net)|ipv4 hash:ip|96 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/sip.txt)
[blocklist_de_ssh](#blocklist_de_ssh)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service SSH.|ipv4 hash:ip|8193 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/ssh.txt)
[blocklist_de_strongips](#blocklist_de_strongips)|[Blocklist.de](https://www.blocklist.de/) All IPs which are older then 2 month and have more then 5.000 attacks.|ipv4 hash:ip|176 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/strongips.txt)
[bm_tor](#bm_tor)|[torstatus.blutmagie.de](https://torstatus.blutmagie.de) list of all TOR network servers|ipv4 hash:ip|6548 unique IPs|updated every 30 mins  from [this link](https://torstatus.blutmagie.de/ip_list_all.php/Tor_ip_list_ALL.csv)
[bogons](#bogons)|[Team-Cymru.org](http://www.team-cymru.org) private and reserved addresses defined by RFC 1918, RFC 5735, and RFC 6598 and netblocks that have not been allocated to a regional internet registry - **excellent list - use it only your internet interface**|ipv4 hash:net|13 subnets, 592708608 unique IPs|updated every 1 day  from [this link](http://www.team-cymru.org/Services/Bogons/bogon-bn-agg.txt)
[bruteforceblocker](#bruteforceblocker)|[danger.rulez.sk](http://danger.rulez.sk/) IPs detected by [bruteforceblocker](http://danger.rulez.sk/index.php/bruteforceblocker/) (fail2ban alternative for SSH on OpenBSD). This is an automatically generated list from users reporting failed authentication attempts. An IP seems to be included if 3 or more users report it. Its retention pocily seems 30 days.|ipv4 hash:ip|2007 unique IPs|updated every 3 hours  from [this link](http://danger.rulez.sk/projects/bruteforceblocker/blist.php)
[ciarmy](#ciarmy)|[CIArmy.com](http://ciarmy.com/) IPs with poor Rogue Packet score that have not yet been identified as malicious by the community|ipv4 hash:ip|396 unique IPs|updated every 3 hours  from [this link](http://cinsscore.com/list/ci-badguys.txt)
[cleanmx_viruses](#cleanmx_viruses)|[Clean-MX.de](http://support.clean-mx.de/clean-mx/viruses.php) IPs with viruses|ipv4 hash:ip|309 unique IPs|updated every 12 hours  from [this link](http://support.clean-mx.de/clean-mx/xmlviruses.php?sort=id%20desc&response=alive)
[dm_tor](#dm_tor)|[dan.me.uk](https://www.dan.me.uk) dynamic list of TOR exit points|ipv4 hash:ip|6554 unique IPs|updated every 30 mins  from [this link](https://www.dan.me.uk/torlist/)
[dshield](#dshield)|[DShield.org](https://dshield.org/) top 20 attacking class C (/24) subnets over the last three days - **excellent list**|ipv4 hash:net|20 subnets, 5120 unique IPs|updated every 4 hours  from [this link](http://feeds.dshield.org/block.txt)
[et_block](#et_block)|[EmergingThreats.net](http://www.emergingthreats.net/) default blacklist (at the time of writing includes spamhaus DROP, dshield and abuse.ch trackers, which are available separately too - prefer to use the direct ipsets instead of this, they seem to lag a bit in updates)|ipv4 hash:net|1016 subnets, 18338655 unique IPs|updated every 12 hours  from [this link](http://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt)
[et_botcc](#et_botcc)|[EmergingThreats.net Command and Control IPs](http://doc.emergingthreats.net/bin/view/Main/BotCC) These IPs are updates every 24 hours and should be considered VERY highly reliable indications that a host is communicating with a known and active Bot or Malware command and control server - (although they say this includes abuse.ch trackers, it does not - most probably it is the shadowserver.org C&C list)|ipv4 hash:ip|509 unique IPs|updated every 12 hours  from [this link](http://rules.emergingthreats.net/fwrules/emerging-PIX-CC.rules)
[et_compromised](#et_compromised)|[EmergingThreats.net compromised hosts](http://doc.emergingthreats.net/bin/view/Main/CompromisedHost) - (this seems to be based on bruteforceblocker)|ipv4 hash:ip|2086 unique IPs|updated every 12 hours  from [this link](http://rules.emergingthreats.net/blockrules/compromised-ips.txt)
et_dshield|[EmergingThreats.net](http://www.emergingthreats.net/) dshield blocklist|ipv4 hash:net|disabled|updated every 12 hours  from [this link](http://rules.emergingthreats.net/fwrules/emerging-PIX-DSHIELD.rules)
et_spamhaus|[EmergingThreats.net](http://www.emergingthreats.net/) spamhaus blocklist|ipv4 hash:net|disabled|updated every 12 hours  from [this link](http://rules.emergingthreats.net/fwrules/emerging-PIX-DROP.rules)
[et_tor](#et_tor)|[EmergingThreats.net](http://www.emergingthreats.net/) [list](http://doc.emergingthreats.net/bin/view/Main/TorRules) of TOR network IPs|ipv4 hash:ip|6610 unique IPs|updated every 12 hours  from [this link](http://rules.emergingthreats.net/blockrules/emerging-tor.rules)
[feodo](#feodo)|[Abuse.ch Feodo tracker](https://feodotracker.abuse.ch) trojan includes IPs which are being used by Feodo (also known as Cridex or Bugat) which commits ebanking fraud - **excellent list**|ipv4 hash:ip|94 unique IPs|updated every 30 mins  from [this link](https://feodotracker.abuse.ch/blocklist/?download=ipblocklist)
[fullbogons](#fullbogons)|[Team-Cymru.org](http://www.team-cymru.org) IP space that has been allocated to an RIR, but not assigned by that RIR to an actual ISP or other end-user - **excellent list - use it only your internet interface**|ipv4 hash:net|3715 subnets, 670310296 unique IPs|updated every 1 day  from [this link](http://www.team-cymru.org/Services/Bogons/fullbogons-ipv4.txt)
[geolite2_country](https://github.com/ktsaou/blocklist-ipsets/tree/master/geolite2_country)|[MaxMind GeoLite2](http://dev.maxmind.com/geoip/geoip2/geolite2/) databases are free IP geolocation databases comparable to, but less accurate than, MaxMind’s GeoIP2 databases. They include IPs per country, IPs per continent, IPs used by anonymous services (VPNs, Proxies, etc) and Satellite Providers.|ipv4 hash:net|All the world|updated every 7 days  from [this link](http://geolite.maxmind.com/download/geoip/database/GeoLite2-Country-CSV.zip)
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|[iBlocklist.com](https://www.iblocklist.com/) free version of [BlueTack.co.uk](http://www.bluetack.co.uk/) IPs that have been reported for bad deeds in p2p|ipv4 hash:ip|48134 unique IPs|updated every 12 hours  from [this link](http://list.iblocklist.com/?list=cwworuawihqvocglcoss&fileformat=p2p&archiveformat=gz)
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|[iBlocklist.com](https://www.iblocklist.com/) free version of [BlueTack.co.uk](http://www.bluetack.co.uk/) hijacked IP-Blocks Hijacked IP space are IP blocks that are being used without permission|ipv4 hash:net|535 subnets, 9177856 unique IPs|updated every 12 hours  from [this link](http://list.iblocklist.com/?list=usrcshglbiilevmyfhse&fileformat=p2p&archiveformat=gz)
[ib_bluetack_level1](#ib_bluetack_level1)|[iBlocklist.com](https://www.iblocklist.com/) free version of [BlueTack.co.uk](http://www.bluetack.co.uk/) Level 1 (for use in p2p): Companies or organizations who are clearly involved with trying to stop filesharing (e.g. Baytsp, MediaDefender, Mediasentry a.o.). Companies which anti-p2p activity has been seen from. Companies that produce or have a strong financial interest in copyrighted material (e.g. music, movie, software industries a.o.). Government ranges or companies that have a strong financial interest in doing work for governments. Legal industry ranges. IPs or ranges of ISPs from which anti-p2p activity has been observed. Basically this list will block all kinds of internet connections that most people would rather not have during their internet travels.|ipv4 hash:net|218309 subnets, 764987411 unique IPs|updated every 12 hours  from [this link](http://list.iblocklist.com/?list=ydxerpxkpcfqjaybcssw&fileformat=p2p&archiveformat=gz)
[ib_bluetack_level2](#ib_bluetack_level2)|[iBlocklist.com](https://www.iblocklist.com/) free version of BlueTack.co.uk Level 2 (for use in p2p). General corporate ranges. Ranges used by labs or researchers. Proxies.|ipv4 hash:net|72774 subnets, 348707599 unique IPs|updated every 12 hours  from [this link](http://list.iblocklist.com/?list=gyisgnzbhppbvsphucsw&fileformat=p2p&archiveformat=gz)
badips.com categories ipsets|[BadIPs.com](https://www.badips.com) community based IP blacklisting. They score IPs based on the reports they reports.|ipv4 hash:ip|disabled|disabled
[ib_bluetack_proxies](#ib_bluetack_proxies)|[iBlocklist.com](https://www.iblocklist.com/) free version of [BlueTack.co.uk](http://www.bluetack.co.uk/) Open Proxies IPs list (without TOR)|ipv4 hash:ip|673 unique IPs|updated every 12 hours  from [this link](http://list.iblocklist.com/?list=xoebmbyexwuiogmbyprb&fileformat=p2p&archiveformat=gz)
[ib_bluetack_spyware](#ib_bluetack_spyware)|[iBlocklist.com](https://www.iblocklist.com/) free version of [BlueTack.co.uk](http://www.bluetack.co.uk/) known malicious SPYWARE and ADWARE IP Address ranges|ipv4 hash:net|3274 subnets, 339192 unique IPs|updated every 12 hours  from [this link](http://list.iblocklist.com/?list=llvtlsjyoyiczbkjsxpf&fileformat=p2p&archiveformat=gz)
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|[iBlocklist.com](https://www.iblocklist.com/) free version of [BlueTack.co.uk](http://www.bluetack.co.uk/) web server hack and exploit attempts|ipv4 hash:ip|1460 unique IPs|updated every 12 hours  from [this link](http://list.iblocklist.com/?list=ghlzqtqxnzctvvajwwag&fileformat=p2p&archiveformat=gz)
infiltrated|[infiltrated.net](http://www.infiltrated.net) (this list seems to be updated frequently, but we found no information about it)|ipv4 hash:ip|disabled|updated every 12 hours  from [this link](http://www.infiltrated.net/blacklisted)
lashback_ubl|[The LashBack UBL](http://blacklist.lashback.com/) The Unsubscribe Blacklist (UBL) is a real-time blacklist of IP addresses which are sending email to names harvested from suppression files (this is a big list, more than 500.000 IPs)|ipv4 hash:ip|disabled|updated every 1 day  from [this link](http://www.unsubscore.com/blacklist.txt)
[malc0de](#malc0de)|[Malc0de.com](http://malc0de.com) malicious IPs of the last 30 days|ipv4 hash:ip|379 unique IPs|updated every 1 day  from [this link](http://malc0de.com/bl/IP_Blacklist.txt)
[malwaredomainlist](#malwaredomainlist)|[malwaredomainlist.com](http://www.malwaredomainlist.com) list of malware active ip addresses|ipv4 hash:ip|1288 unique IPs|updated every 12 hours  from [this link](http://www.malwaredomainlist.com/hostslist/ip.txt)
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|[MaxMind.com](https://www.maxmind.com/en/anonymous-proxy-fraudulent-ip-address-list) list of anonymous proxy fraudelent IP addresses.|ipv4 hash:ip|372 unique IPs|updated every 4 hours  from [this link](https://www.maxmind.com/en/anonymous-proxy-fraudulent-ip-address-list)
[nixspam](#nixspam)|[NiX Spam](http://www.heise.de/ix/NiX-Spam-DNSBL-and-blacklist-for-download-499637.html) IP addresses that sent spam in the last hour - automatically generated entries without distinguishing open proxies from relays, dialup gateways, and so on. All IPs are removed after 12 hours if there is no spam from there.|ipv4 hash:ip|23361 unique IPs|updated every 15 mins  from [this link](http://www.dnsbl.manitu.net/download/nixspam-ip.dump.gz)
openbl|[OpenBL.org](http://www.openbl.org/) default blacklist (currently it is the same with 90 days). OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications - **excellent list**|ipv4 hash:ip|disabled|updated every 4 hours  from [this link](http://www.openbl.org/lists/base.txt)
openbl_180d|[OpenBL.org](http://www.openbl.org/) last 180 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|disabled|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_180days.txt)
[openbl_1d](#openbl_1d)|[OpenBL.org](http://www.openbl.org/) last 24 hours IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|161 unique IPs|updated every 1 hour  from [this link](http://www.openbl.org/lists/base_1days.txt)
[openbl_30d](#openbl_30d)|[OpenBL.org](http://www.openbl.org/) last 30 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|3256 unique IPs|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_30days.txt)
openbl_360d|[OpenBL.org](http://www.openbl.org/) last 360 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|disabled|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_360days.txt)
[openbl_60d](#openbl_60d)|[OpenBL.org](http://www.openbl.org/) last 60 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|7689 unique IPs|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_60days.txt)
[openbl_7d](#openbl_7d)|[OpenBL.org](http://www.openbl.org/) last 7 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|910 unique IPs|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_7days.txt)
openbl_90d|[OpenBL.org](http://www.openbl.org/) last 90 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|disabled|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_90days.txt)
openbl_all|[OpenBL.org](http://www.openbl.org/) last all IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|disabled|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_all.txt)
[palevo](#palevo)|[Abuse.ch Palevo tracker](https://palevotracker.abuse.ch) worm includes IPs which are being used as botnet C&C for the Palevo crimeware - **excellent list**|ipv4 hash:ip|12 unique IPs|updated every 30 mins  from [this link](https://palevotracker.abuse.ch/blocklists.php?download=ipblocklist)
php_bad|[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) bad web hosts (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|disabled|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=b&rss=1)
[php_commenters](#php_commenters)|[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) comment spammers (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|301 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=c&rss=1)
[php_dictionary](#php_dictionary)|[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) directory attackers (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|508 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=d&rss=1)
[php_harvesters](#php_harvesters)|[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) harvesters (IPs that surf the internet looking for email addresses) (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|298 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=h&rss=1)
[php_spammers](#php_spammers)|[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) spam servers (IPs used by spammers to send messages) (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|461 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=s&rss=1)
[proxyrss](#proxyrss)|[proxyrss.com](http://www.proxyrss.com) open proxies syndicated from multiple sources.|ipv4 hash:ip|1553 unique IPs|updated every 4 hours  from [this link](http://www.proxyrss.com/proxylists/all.gz)
[proxz](#proxz)|[proxz.com](http://www.proxz.com) open proxies (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|776 unique IPs|updated every 1 hour  from [this link](http://www.proxz.com/proxylists.xml)
[ri_connect_proxies](#ri_connect_proxies)|[rosinstrument.com](http://www.rosinstrument.com) open CONNECT proxies (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|2376 unique IPs|updated every 1 hour  from [this link](http://tools.rosinstrument.com/proxy/plab100.xml)
[ri_web_proxies](#ri_web_proxies)|[rosinstrument.com](http://www.rosinstrument.com) open HTTP proxies (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|6346 unique IPs|updated every 1 hour  from [this link](http://tools.rosinstrument.com/proxy/l100.xml)
[shunlist](#shunlist)|[AutoShun.org](http://autoshun.org/) IPs identified as hostile by correlating logs from distributed snort installations running the autoshun plugin|ipv4 hash:ip|1261 unique IPs|updated every 4 hours  from [this link](http://www.autoshun.org/files/shunlist.csv)
[snort_ipfilter](#snort_ipfilter)|[labs.snort.org](https://labs.snort.org/) supplied IP blacklist (this list seems to be updated frequently, but we found no information about it)|ipv4 hash:ip|9882 unique IPs|updated every 12 hours  from [this link](http://labs.snort.org/feeds/ip-filter.blf)
[sorbs_dul](#sorbs_dul)|[Sorbs.net](https://www.sorbs.net/) DUL, Dynamic User IPs extracted from deltas.|ipv4 hash:net|8 subnets, 3584 unique IPs|updated every 1 min  from [this link]()
[sorbs_http](#sorbs_http)|[Sorbs.net](https://www.sorbs.net/) HTTP proxies, extracted from deltas.|ipv4 hash:net|31 subnets, 31 unique IPs|updated every 1 min  from [this link]()
[sorbs_misc](#sorbs_misc)|[Sorbs.net](https://www.sorbs.net/) MISC proxies, extracted from deltas.|ipv4 hash:net|31 subnets, 31 unique IPs|updated every 1 min  from [this link]()
[sorbs_new_spam](#sorbs_new_spam)|[Sorbs.net](https://www.sorbs.net/) NEW Spam senders, extracted from deltas.|ipv4 hash:net|23675 subnets, 24482 unique IPs|updated every 1 min  from [this link]()
[sorbs_recent_spam](#sorbs_recent_spam)|[Sorbs.net](https://www.sorbs.net/) RECENT Spam senders, extracted from deltas.|ipv4 hash:net|23675 subnets, 24482 unique IPs|updated every 1 min  from [this link]()
[sorbs_smtp](#sorbs_smtp)|[Sorbs.net](https://www.sorbs.net/) SMTP Open Relays, extracted from deltas.|ipv4 hash:net|14 subnets, 14 unique IPs|updated every 1 min  from [this link]()
[sorbs_socks](#sorbs_socks)|[Sorbs.net](https://www.sorbs.net/) SOCKS proxies, extracted from deltas.|ipv4 hash:net|31 subnets, 31 unique IPs|updated every 1 min  from [this link]()
[sorbs_spam](#sorbs_spam)|[Sorbs.net](https://www.sorbs.net/) Spam senders, extracted from deltas.|ipv4 hash:net|28347 subnets, 29370 unique IPs|updated every 1 min  from [this link]()
[sorbs_web](#sorbs_web)|[Sorbs.net](https://www.sorbs.net/) WEB exploits, extracted from deltas.|ipv4 hash:net|785 subnets, 787 unique IPs|updated every 1 min  from [this link]()
[spamhaus_drop](#spamhaus_drop)|[Spamhaus.org](http://www.spamhaus.org) DROP list (according to their site this list should be dropped at tier-1 ISPs globaly) - **excellent list**|ipv4 hash:net|653 subnets, 18404096 unique IPs|updated every 12 hours  from [this link](http://www.spamhaus.org/drop/drop.txt)
[spamhaus_edrop](#spamhaus_edrop)|[Spamhaus.org](http://www.spamhaus.org) EDROP (extended matches that should be used with DROP) - **excellent list**|ipv4 hash:net|55 subnets, 486400 unique IPs|updated every 12 hours  from [this link](http://www.spamhaus.org/drop/edrop.txt)
[sslbl](#sslbl)|[Abuse.ch SSL Blacklist](https://sslbl.abuse.ch/) bad SSL traffic related to malware or botnet activities - **excellent list**|ipv4 hash:ip|365 unique IPs|updated every 30 mins  from [this link](https://sslbl.abuse.ch/blacklist/sslipblacklist.csv)
stopforumspam_180d|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 180 days)|ipv4 hash:ip|disabled|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/listed_ip_180.zip)
[stopforumspam_1d](#stopforumspam_1d)|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers in the last 24 hours - **excellent list**|ipv4 hash:ip|7188 unique IPs|updated every 1 hour  from [this link](http://www.stopforumspam.com/downloads/listed_ip_1.zip)
[stopforumspam_30d](#stopforumspam_30d)|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 30 days)|ipv4 hash:ip|93498 unique IPs|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/listed_ip_30.zip)
stopforumspam_365d|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 365 days)|ipv4 hash:ip|disabled|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/listed_ip_365.zip)
[stopforumspam_7d](#stopforumspam_7d)|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 7 days)|ipv4 hash:ip|29882 unique IPs|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/listed_ip_7.zip)
stopforumspam_90d|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 90 days)|ipv4 hash:ip|disabled|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/listed_ip_90.zip)
stopforumspam_ever|[StopForumSpam.com](http://www.stopforumspam.com) all IPs used by forum spammers, **ever** (normally you don't want to use this ipset, use the hourly one which includes last 24 hours IPs or the 7 days one)|ipv4 hash:ip|disabled|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/bannedips.zip)
[virbl](#virbl)|[VirBL](http://virbl.bit.nl/) is a project of which the idea was born during the RIPE-48 meeting. The plan was to get reports of virusscanning mailservers, and put the IP-addresses that were reported to send viruses on a blacklist.|ipv4 hash:ip|10 unique IPs|updated every 1 hour  from [this link](http://virbl.bit.nl/download/virbl.dnsbl.bit.nl.txt)
[voipbl](#voipbl)|[VoIPBL.org](http://www.voipbl.org/) a distributed VoIP blacklist that is aimed to protects against VoIP Fraud and minimizing abuse for network that have publicly accessible PBX's. Several algorithms, external sources and manual confirmation are used before they categorize something as an attack and determine the threat level.|ipv4 hash:net|10426 subnets, 10837 unique IPs|updated every 4 hours  from [this link](http://www.voipbl.org/update/)
[xroxy](#xroxy)|[xroxy.com](http://www.xroxy.com) open proxies (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|2079 unique IPs|updated every 1 hour  from [this link](http://www.xroxy.com/proxyrss.xml)
[zeus](#zeus)|[Abuse.ch Zeus tracker](https://zeustracker.abuse.ch) standard, contains the same data as the ZeuS IP blocklist (zeus_badips) but with the slight difference that it doesn't exclude hijacked websites (level 2) and free web hosting providers (level 3). This means that this blocklist contains all IPv4 addresses associated with ZeuS C&Cs which are currently being tracked by ZeuS Tracker. Hence this blocklist will likely cause some false positives. - **excellent list**|ipv4 hash:ip|231 unique IPs|updated every 30 mins  from [this link](https://zeustracker.abuse.ch/blocklist.php?download=ipblocklist)
[zeus_badips](#zeus_badips)|[Abuse.ch Zeus tracker](https://zeustracker.abuse.ch) badips includes IPv4 addresses that are used by the ZeuS trojan. It is the recommened blocklist if you want to block only ZeuS IPs. It excludes IP addresses that ZeuS Tracker believes to be hijacked (level 2) or belong to a free web hosting provider (level 3). Hence the false postive rate should be much lower compared to the standard ZeuS IP blocklist. **excellent list**|ipv4 hash:ip|202 unique IPs|updated every 30 mins  from [this link](https://zeustracker.abuse.ch/blocklist.php?download=badips)

# Comparison of ipsets

Below we compare each ipset against all other.


## alienvault_reputation

[AlienVault.com](https://www.alienvault.com/) IP reputation database (this list seems to include port scanning hosts and to be updated regularly, but we found no information about its retention policy)

Source is downloaded from [this link](https://reputation.alienvault.com/reputation.generic).

The last time downloaded was found to be dated: Fri Jun  5 10:00:35 UTC 2015.

The ipset `alienvault_reputation` has **180239** entries, **180239** unique IPs.

The following table shows the overlaps of `alienvault_reputation` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `alienvault_reputation`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `alienvault_reputation`.
- ` this % ` is the percentage **of this ipset (`alienvault_reputation`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|14666|0.0%|8.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|7809|0.0%|4.3%|
[openbl_60d](#openbl_60d)|7689|7689|7668|99.7%|4.2%|
[et_block](#et_block)|1016|18338655|5534|0.0%|3.0%|
[dshield](#dshield)|20|5120|5120|100.0%|2.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|4481|0.0%|2.4%|
[openbl_30d](#openbl_30d)|3256|3256|3241|99.5%|1.7%|
[blocklist_de](#blocklist_de)|31150|31150|1830|5.8%|1.0%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|1630|0.0%|0.9%|
[blocklist_de_ssh](#blocklist_de_ssh)|8193|8193|1589|19.3%|0.8%|
[et_compromised](#et_compromised)|2086|2086|1364|65.3%|0.7%|
[bruteforceblocker](#bruteforceblocker)|2007|2007|1296|64.5%|0.7%|
[shunlist](#shunlist)|1261|1261|1253|99.3%|0.6%|
[openbl_7d](#openbl_7d)|910|910|904|99.3%|0.5%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|518|0.0%|0.2%|
[ciarmy](#ciarmy)|396|396|392|98.9%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|287|0.0%|0.1%|
[voipbl](#voipbl)|10426|10837|214|1.9%|0.1%|
[stopforumspam_30d](#stopforumspam_30d)|93498|93498|207|0.2%|0.1%|
[openbl_1d](#openbl_1d)|161|161|157|97.5%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13701|13701|128|0.9%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9882|9882|125|1.2%|0.0%|
[sorbs_spam](#sorbs_spam)|28347|29370|105|0.3%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29882|29882|95|0.3%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|23675|24482|91|0.3%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|23675|24482|91|0.3%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|16101|16101|71|0.4%|0.0%|
[sslbl](#sslbl)|365|365|64|17.5%|0.0%|
[zeus](#zeus)|231|231|62|26.8%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7188|7188|52|0.7%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2409|2409|49|2.0%|0.0%|
[et_tor](#et_tor)|6610|6610|44|0.6%|0.0%|
[dm_tor](#dm_tor)|6554|6554|43|0.6%|0.0%|
[bm_tor](#bm_tor)|6548|6548|43|0.6%|0.0%|
[nixspam](#nixspam)|23361|23361|40|0.1%|0.0%|
[zeus_badips](#zeus_badips)|202|202|37|18.3%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|176|176|35|19.8%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|26|6.9%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3243|3243|23|0.7%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|96|96|17|17.7%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2348|2348|17|0.7%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|486400|15|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|15|0.0%|0.0%|
[php_commenters](#php_commenters)|301|301|14|4.6%|0.0%|
[malc0de](#malc0de)|379|379|11|2.9%|0.0%|
[php_harvesters](#php_harvesters)|298|298|10|3.3%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|309|309|9|2.9%|0.0%|
[php_dictionary](#php_dictionary)|508|508|8|1.5%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|8|0.5%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|915|915|8|0.8%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|6|0.4%|0.0%|
[xroxy](#xroxy)|2079|2079|5|0.2%|0.0%|
[php_spammers](#php_spammers)|461|461|5|1.0%|0.0%|
[et_botcc](#et_botcc)|509|509|4|0.7%|0.0%|
[ri_web_proxies](#ri_web_proxies)|6346|6346|3|0.0%|0.0%|
[proxz](#proxz)|776|776|3|0.3%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2376|2376|2|0.0%|0.0%|
[feodo](#feodo)|94|94|2|2.1%|0.0%|
[virbl](#virbl)|10|10|1|10.0%|0.0%|
[proxyrss](#proxyrss)|1553|1553|1|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|1|0.1%|0.0%|

## blocklist_de

[Blocklist.de](https://www.blocklist.de/) IPs that have been detected by fail2ban in the last 48 hours - **excellent list**

Source is downloaded from [this link](http://lists.blocklist.de/lists/all.txt).

The last time downloaded was found to be dated: Fri Jun  5 10:28:02 UTC 2015.

The ipset `blocklist_de` has **31150** entries, **31150** unique IPs.

The following table shows the overlaps of `blocklist_de` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de`.
- ` this % ` is the percentage **of this ipset (`blocklist_de`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de_mail](#blocklist_de_mail)|16101|16101|16027|99.5%|51.4%|
[blocklist_de_apache](#blocklist_de_apache)|13701|13701|13700|99.9%|43.9%|
[blocklist_de_ssh](#blocklist_de_ssh)|8193|8193|8191|99.9%|26.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|4802|0.0%|15.4%|
[blocklist_de_bots](#blocklist_de_bots)|3243|3243|3243|100.0%|10.4%|
[stopforumspam_30d](#stopforumspam_30d)|93498|93498|2529|2.7%|8.1%|
[blocklist_de_imap](#blocklist_de_imap)|2409|2409|2409|100.0%|7.7%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2348|2348|2348|100.0%|7.5%|
[stopforumspam_7d](#stopforumspam_7d)|29882|29882|2163|7.2%|6.9%|
[alienvault_reputation](#alienvault_reputation)|180239|180239|1830|1.0%|5.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|1591|0.0%|5.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|1531|0.0%|4.9%|
[openbl_60d](#openbl_60d)|7689|7689|1515|19.7%|4.8%|
[stopforumspam_1d](#stopforumspam_1d)|7188|7188|1488|20.7%|4.7%|
[sorbs_spam](#sorbs_spam)|28347|29370|1096|3.7%|3.5%|
[sorbs_recent_spam](#sorbs_recent_spam)|23675|24482|1073|4.3%|3.4%|
[sorbs_new_spam](#sorbs_new_spam)|23675|24482|1073|4.3%|3.4%|
[blocklist_de_ftp](#blocklist_de_ftp)|915|915|904|98.7%|2.9%|
[openbl_30d](#openbl_30d)|3256|3256|826|25.3%|2.6%|
[nixspam](#nixspam)|23361|23361|766|3.2%|2.4%|
[bruteforceblocker](#bruteforceblocker)|2007|2007|675|33.6%|2.1%|
[et_compromised](#et_compromised)|2086|2086|653|31.3%|2.0%|
[openbl_7d](#openbl_7d)|910|910|541|59.4%|1.7%|
[ri_web_proxies](#ri_web_proxies)|6346|6346|413|6.5%|1.3%|
[shunlist](#shunlist)|1261|1261|385|30.5%|1.2%|
[xroxy](#xroxy)|2079|2079|265|12.7%|0.8%|
[proxyrss](#proxyrss)|1553|1553|230|14.8%|0.7%|
[et_block](#et_block)|1016|18338655|182|0.0%|0.5%|
[snort_ipfilter](#snort_ipfilter)|9882|9882|179|1.8%|0.5%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|177|0.0%|0.5%|
[blocklist_de_strongips](#blocklist_de_strongips)|176|176|175|99.4%|0.5%|
[proxz](#proxz)|776|776|140|18.0%|0.4%|
[openbl_1d](#openbl_1d)|161|161|135|83.8%|0.4%|
[dshield](#dshield)|20|5120|121|2.3%|0.3%|
[sorbs_web](#sorbs_web)|785|787|91|11.5%|0.2%|
[php_dictionary](#php_dictionary)|508|508|84|16.5%|0.2%|
[blocklist_de_sip](#blocklist_de_sip)|96|96|76|79.1%|0.2%|
[ri_connect_proxies](#ri_connect_proxies)|2376|2376|72|3.0%|0.2%|
[php_commenters](#php_commenters)|301|301|72|23.9%|0.2%|
[php_spammers](#php_spammers)|461|461|67|14.5%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|45|0.0%|0.1%|
[voipbl](#voipbl)|10426|10837|44|0.4%|0.1%|
[ciarmy](#ciarmy)|396|396|37|9.3%|0.1%|
[php_harvesters](#php_harvesters)|298|298|31|10.4%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|11|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|486400|8|0.0%|0.0%|
[sorbs_socks](#sorbs_socks)|31|31|8|25.8%|0.0%|
[sorbs_misc](#sorbs_misc)|31|31|8|25.8%|0.0%|
[sorbs_http](#sorbs_http)|31|31|8|25.8%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|6|0.8%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|6|0.0%|0.0%|
[et_tor](#et_tor)|6610|6610|4|0.0%|0.0%|
[dm_tor](#dm_tor)|6554|6554|4|0.0%|0.0%|
[bm_tor](#bm_tor)|6548|6548|4|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|3|0.8%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|3|0.2%|0.0%|
[sslbl](#sslbl)|365|365|1|0.2%|0.0%|

## blocklist_de_apache

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service Apache, Apache-DDOS, RFI-Attacks.

Source is downloaded from [this link](http://lists.blocklist.de/lists/apache.txt).

The last time downloaded was found to be dated: Fri Jun  5 10:14:07 UTC 2015.

The ipset `blocklist_de_apache` has **13701** entries, **13701** unique IPs.

The following table shows the overlaps of `blocklist_de_apache` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_apache`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_apache`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_apache`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|31150|31150|13700|43.9%|99.9%|
[blocklist_de_mail](#blocklist_de_mail)|16101|16101|11059|68.6%|80.7%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2348|2348|2348|100.0%|17.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|2290|0.0%|16.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|1324|0.0%|9.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|1069|0.0%|7.8%|
[stopforumspam_30d](#stopforumspam_30d)|93498|93498|216|0.2%|1.5%|
[stopforumspam_7d](#stopforumspam_7d)|29882|29882|136|0.4%|0.9%|
[alienvault_reputation](#alienvault_reputation)|180239|180239|128|0.0%|0.9%|
[sorbs_spam](#sorbs_spam)|28347|29370|72|0.2%|0.5%|
[sorbs_recent_spam](#sorbs_recent_spam)|23675|24482|71|0.2%|0.5%|
[sorbs_new_spam](#sorbs_new_spam)|23675|24482|71|0.2%|0.5%|
[stopforumspam_1d](#stopforumspam_1d)|7188|7188|67|0.9%|0.4%|
[blocklist_de_strongips](#blocklist_de_strongips)|176|176|37|21.0%|0.2%|
[shunlist](#shunlist)|1261|1261|33|2.6%|0.2%|
[ciarmy](#ciarmy)|396|396|33|8.3%|0.2%|
[blocklist_de_bots](#blocklist_de_bots)|3243|3243|26|0.8%|0.1%|
[php_commenters](#php_commenters)|301|301|24|7.9%|0.1%|
[nixspam](#nixspam)|23361|23361|18|0.0%|0.1%|
[dshield](#dshield)|20|5120|10|0.1%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9882|9882|8|0.0%|0.0%|
[et_block](#et_block)|1016|18338655|7|0.0%|0.0%|
[php_spammers](#php_spammers)|461|461|6|1.3%|0.0%|
[php_dictionary](#php_dictionary)|508|508|5|0.9%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|4|0.0%|0.0%|
[php_harvesters](#php_harvesters)|298|298|4|1.3%|0.0%|
[et_tor](#et_tor)|6610|6610|4|0.0%|0.0%|
[dm_tor](#dm_tor)|6554|6554|4|0.0%|0.0%|
[bm_tor](#bm_tor)|6548|6548|4|0.0%|0.0%|
[voipbl](#voipbl)|10426|10837|3|0.0%|0.0%|
[sorbs_web](#sorbs_web)|785|787|3|0.3%|0.0%|
[openbl_60d](#openbl_60d)|7689|7689|3|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|3|0.0%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|3|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|2|0.5%|0.0%|
[et_compromised](#et_compromised)|2086|2086|2|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2007|2007|2|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|486400|1|0.0%|0.0%|
[openbl_30d](#openbl_30d)|3256|3256|1|0.0%|0.0%|

## blocklist_de_bots

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the RFI-Attacks, REG-Bots, IRC-Bots or BadBots (BadBots = he has posted a Spam-Comment on a open Forum or Wiki).

Source is downloaded from [this link](http://lists.blocklist.de/lists/bots.txt).

The last time downloaded was found to be dated: Fri Jun  5 10:28:09 UTC 2015.

The ipset `blocklist_de_bots` has **3243** entries, **3243** unique IPs.

The following table shows the overlaps of `blocklist_de_bots` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_bots`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_bots`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_bots`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|31150|31150|3243|10.4%|100.0%|
[stopforumspam_30d](#stopforumspam_30d)|93498|93498|2140|2.2%|65.9%|
[stopforumspam_7d](#stopforumspam_7d)|29882|29882|1951|6.5%|60.1%|
[stopforumspam_1d](#stopforumspam_1d)|7188|7188|1414|19.6%|43.6%|
[ri_web_proxies](#ri_web_proxies)|6346|6346|361|5.6%|11.1%|
[proxyrss](#proxyrss)|1553|1553|230|14.8%|7.0%|
[xroxy](#xroxy)|2079|2079|210|10.1%|6.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|183|0.0%|5.6%|
[blocklist_de_strongips](#blocklist_de_strongips)|176|176|129|73.2%|3.9%|
[proxz](#proxz)|776|776|118|15.2%|3.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|98|0.0%|3.0%|
[ri_connect_proxies](#ri_connect_proxies)|2376|2376|70|2.9%|2.1%|
[php_commenters](#php_commenters)|301|301|58|19.2%|1.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|45|0.0%|1.3%|
[nixspam](#nixspam)|23361|23361|41|0.1%|1.2%|
[et_block](#et_block)|1016|18338655|38|0.0%|1.1%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|37|0.0%|1.1%|
[sorbs_spam](#sorbs_spam)|28347|29370|37|0.1%|1.1%|
[sorbs_recent_spam](#sorbs_recent_spam)|23675|24482|36|0.1%|1.1%|
[sorbs_new_spam](#sorbs_new_spam)|23675|24482|36|0.1%|1.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|29|0.0%|0.8%|
[blocklist_de_mail](#blocklist_de_mail)|16101|16101|26|0.1%|0.8%|
[blocklist_de_apache](#blocklist_de_apache)|13701|13701|26|0.1%|0.8%|
[alienvault_reputation](#alienvault_reputation)|180239|180239|23|0.0%|0.7%|
[php_harvesters](#php_harvesters)|298|298|22|7.3%|0.6%|
[snort_ipfilter](#snort_ipfilter)|9882|9882|20|0.2%|0.6%|
[php_spammers](#php_spammers)|461|461|11|2.3%|0.3%|
[php_dictionary](#php_dictionary)|508|508|11|2.1%|0.3%|
[sorbs_web](#sorbs_web)|785|787|9|1.1%|0.2%|
[spamhaus_edrop](#spamhaus_edrop)|55|486400|4|0.0%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|4|0.0%|0.1%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|4|0.5%|0.1%|
[voipbl](#voipbl)|10426|10837|3|0.0%|0.0%|
[openbl_60d](#openbl_60d)|7689|7689|3|0.0%|0.0%|
[sorbs_socks](#sorbs_socks)|31|31|2|6.4%|0.0%|
[sorbs_misc](#sorbs_misc)|31|31|2|6.4%|0.0%|
[sorbs_http](#sorbs_http)|31|31|2|6.4%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.0%|
[dshield](#dshield)|20|5120|2|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2007|2007|2|0.0%|0.0%|
[openbl_30d](#openbl_30d)|3256|3256|1|0.0%|0.0%|
[et_compromised](#et_compromised)|2086|2086|1|0.0%|0.0%|

## blocklist_de_bruteforce

[Blocklist.de](https://www.blocklist.de/) All IPs which attacks Joomlas, Wordpress and other Web-Logins with Brute-Force Logins.

Source is downloaded from [this link](http://lists.blocklist.de/lists/bruteforcelogin.txt).

The last time downloaded was found to be dated: Fri Jun  5 10:28:11 UTC 2015.

The ipset `blocklist_de_bruteforce` has **2348** entries, **2348** unique IPs.

The following table shows the overlaps of `blocklist_de_bruteforce` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_bruteforce`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_bruteforce`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_bruteforce`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de_apache](#blocklist_de_apache)|13701|13701|2348|17.1%|100.0%|
[blocklist_de](#blocklist_de)|31150|31150|2348|7.5%|100.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|195|0.0%|8.3%|
[sorbs_spam](#sorbs_spam)|28347|29370|72|0.2%|3.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|23675|24482|71|0.2%|3.0%|
[sorbs_new_spam](#sorbs_new_spam)|23675|24482|71|0.2%|3.0%|
[stopforumspam_30d](#stopforumspam_30d)|93498|93498|45|0.0%|1.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|37|0.0%|1.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|33|0.0%|1.4%|
[stopforumspam_7d](#stopforumspam_7d)|29882|29882|31|0.1%|1.3%|
[stopforumspam_1d](#stopforumspam_1d)|7188|7188|20|0.2%|0.8%|
[nixspam](#nixspam)|23361|23361|18|0.0%|0.7%|
[alienvault_reputation](#alienvault_reputation)|180239|180239|17|0.0%|0.7%|
[blocklist_de_strongips](#blocklist_de_strongips)|176|176|8|4.5%|0.3%|
[php_spammers](#php_spammers)|461|461|6|1.3%|0.2%|
[php_commenters](#php_commenters)|301|301|6|1.9%|0.2%|
[php_dictionary](#php_dictionary)|508|508|5|0.9%|0.2%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|4|0.0%|0.1%|
[snort_ipfilter](#snort_ipfilter)|9882|9882|4|0.0%|0.1%|
[sorbs_web](#sorbs_web)|785|787|3|0.3%|0.1%|
[shunlist](#shunlist)|1261|1261|3|0.2%|0.1%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|3|0.0%|0.1%|
[et_block](#et_block)|1016|18338655|3|0.0%|0.1%|
[php_harvesters](#php_harvesters)|298|298|2|0.6%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|2|0.0%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2|0.0%|0.0%|
[voipbl](#voipbl)|10426|10837|1|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[dshield](#dshield)|20|5120|1|0.0%|0.0%|

## blocklist_de_ftp

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours for attacks on the Service FTP.

Source is downloaded from [this link](http://lists.blocklist.de/lists/ftp.txt).

The last time downloaded was found to be dated: Fri Jun  5 10:14:08 UTC 2015.

The ipset `blocklist_de_ftp` has **915** entries, **915** unique IPs.

The following table shows the overlaps of `blocklist_de_ftp` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_ftp`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_ftp`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_ftp`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|31150|31150|904|2.9%|98.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|73|0.0%|7.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|18|0.0%|1.9%|
[nixspam](#nixspam)|23361|23361|17|0.0%|1.8%|
[stopforumspam_30d](#stopforumspam_30d)|93498|93498|13|0.0%|1.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|13|0.0%|1.4%|
[alienvault_reputation](#alienvault_reputation)|180239|180239|8|0.0%|0.8%|
[stopforumspam_7d](#stopforumspam_7d)|29882|29882|5|0.0%|0.5%|
[sorbs_spam](#sorbs_spam)|28347|29370|3|0.0%|0.3%|
[php_harvesters](#php_harvesters)|298|298|3|1.0%|0.3%|
[openbl_60d](#openbl_60d)|7689|7689|3|0.0%|0.3%|
[blocklist_de_strongips](#blocklist_de_strongips)|176|176|2|1.1%|0.2%|
[stopforumspam_1d](#stopforumspam_1d)|7188|7188|1|0.0%|0.1%|
[spamhaus_edrop](#spamhaus_edrop)|55|486400|1|0.0%|0.1%|
[sorbs_recent_spam](#sorbs_recent_spam)|23675|24482|1|0.0%|0.1%|
[sorbs_new_spam](#sorbs_new_spam)|23675|24482|1|0.0%|0.1%|
[php_spammers](#php_spammers)|461|461|1|0.2%|0.1%|
[openbl_30d](#openbl_30d)|3256|3256|1|0.0%|0.1%|

## blocklist_de_imap

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours for attacks on the Service imap, sasl, pop3, etc.

Source is downloaded from [this link](http://lists.blocklist.de/lists/imap.txt).

The last time downloaded was found to be dated: Fri Jun  5 10:28:07 UTC 2015.

The ipset `blocklist_de_imap` has **2409** entries, **2409** unique IPs.

The following table shows the overlaps of `blocklist_de_imap` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_imap`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_imap`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_imap`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|31150|31150|2409|7.7%|100.0%|
[blocklist_de_mail](#blocklist_de_mail)|16101|16101|2380|14.7%|98.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|283|0.0%|11.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|58|0.0%|2.4%|
[alienvault_reputation](#alienvault_reputation)|180239|180239|49|0.0%|2.0%|
[openbl_60d](#openbl_60d)|7689|7689|39|0.5%|1.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|39|0.0%|1.6%|
[openbl_30d](#openbl_30d)|3256|3256|32|0.9%|1.3%|
[sorbs_spam](#sorbs_spam)|28347|29370|23|0.0%|0.9%|
[nixspam](#nixspam)|23361|23361|23|0.0%|0.9%|
[sorbs_recent_spam](#sorbs_recent_spam)|23675|24482|19|0.0%|0.7%|
[sorbs_new_spam](#sorbs_new_spam)|23675|24482|19|0.0%|0.7%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|17|0.0%|0.7%|
[et_block](#et_block)|1016|18338655|17|0.0%|0.7%|
[openbl_7d](#openbl_7d)|910|910|12|1.3%|0.4%|
[stopforumspam_30d](#stopforumspam_30d)|93498|93498|9|0.0%|0.3%|
[et_compromised](#et_compromised)|2086|2086|6|0.2%|0.2%|
[bruteforceblocker](#bruteforceblocker)|2007|2007|6|0.2%|0.2%|
[snort_ipfilter](#snort_ipfilter)|9882|9882|5|0.0%|0.2%|
[stopforumspam_7d](#stopforumspam_7d)|29882|29882|3|0.0%|0.1%|
[shunlist](#shunlist)|1261|1261|3|0.2%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|0.1%|
[openbl_1d](#openbl_1d)|161|161|2|1.2%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|2|0.0%|0.0%|
[voipbl](#voipbl)|10426|10837|1|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7188|7188|1|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2376|2376|1|0.0%|0.0%|
[php_dictionary](#php_dictionary)|508|508|1|0.1%|0.0%|
[dshield](#dshield)|20|5120|1|0.0%|0.0%|
[ciarmy](#ciarmy)|396|396|1|0.2%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|176|176|1|0.5%|0.0%|

## blocklist_de_mail

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service Mail, Postfix.

Source is downloaded from [this link](http://lists.blocklist.de/lists/mail.txt).

The last time downloaded was found to be dated: Fri Jun  5 10:14:06 UTC 2015.

The ipset `blocklist_de_mail` has **16101** entries, **16101** unique IPs.

The following table shows the overlaps of `blocklist_de_mail` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_mail`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_mail`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_mail`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|31150|31150|16027|51.4%|99.5%|
[blocklist_de_apache](#blocklist_de_apache)|13701|13701|11059|80.7%|68.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|2500|0.0%|15.5%|
[blocklist_de_imap](#blocklist_de_imap)|2409|2409|2380|98.7%|14.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|1382|0.0%|8.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|1164|0.0%|7.2%|
[sorbs_spam](#sorbs_spam)|28347|29370|930|3.1%|5.7%|
[sorbs_recent_spam](#sorbs_recent_spam)|23675|24482|913|3.7%|5.6%|
[sorbs_new_spam](#sorbs_new_spam)|23675|24482|913|3.7%|5.6%|
[nixspam](#nixspam)|23361|23361|674|2.8%|4.1%|
[stopforumspam_30d](#stopforumspam_30d)|93498|93498|264|0.2%|1.6%|
[stopforumspam_7d](#stopforumspam_7d)|29882|29882|161|0.5%|0.9%|
[snort_ipfilter](#snort_ipfilter)|9882|9882|156|1.5%|0.9%|
[sorbs_web](#sorbs_web)|785|787|80|10.1%|0.4%|
[alienvault_reputation](#alienvault_reputation)|180239|180239|71|0.0%|0.4%|
[php_dictionary](#php_dictionary)|508|508|67|13.1%|0.4%|
[stopforumspam_1d](#stopforumspam_1d)|7188|7188|59|0.8%|0.3%|
[xroxy](#xroxy)|2079|2079|56|2.6%|0.3%|
[ri_web_proxies](#ri_web_proxies)|6346|6346|53|0.8%|0.3%|
[php_spammers](#php_spammers)|461|461|49|10.6%|0.3%|
[openbl_60d](#openbl_60d)|7689|7689|46|0.5%|0.2%|
[openbl_30d](#openbl_30d)|3256|3256|39|1.1%|0.2%|
[blocklist_de_bots](#blocklist_de_bots)|3243|3243|26|0.8%|0.1%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|25|0.0%|0.1%|
[et_block](#et_block)|1016|18338655|25|0.0%|0.1%|
[blocklist_de_strongips](#blocklist_de_strongips)|176|176|23|13.0%|0.1%|
[proxz](#proxz)|776|776|22|2.8%|0.1%|
[php_commenters](#php_commenters)|301|301|20|6.6%|0.1%|
[openbl_7d](#openbl_7d)|910|910|15|1.6%|0.0%|
[et_compromised](#et_compromised)|2086|2086|8|0.3%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2007|2007|8|0.3%|0.0%|
[sorbs_socks](#sorbs_socks)|31|31|5|16.1%|0.0%|
[sorbs_misc](#sorbs_misc)|31|31|5|16.1%|0.0%|
[sorbs_http](#sorbs_http)|31|31|5|16.1%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|5|0.0%|0.0%|
[openbl_1d](#openbl_1d)|161|161|4|2.4%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|4|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|4|0.0%|0.0%|
[et_tor](#et_tor)|6610|6610|4|0.0%|0.0%|
[dm_tor](#dm_tor)|6554|6554|4|0.0%|0.0%|
[bm_tor](#bm_tor)|6548|6548|4|0.0%|0.0%|
[shunlist](#shunlist)|1261|1261|3|0.2%|0.0%|
[php_harvesters](#php_harvesters)|298|298|3|1.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2376|2376|2|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|2|0.2%|0.0%|
[voipbl](#voipbl)|10426|10837|1|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|486400|1|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[dshield](#dshield)|20|5120|1|0.0%|0.0%|
[ciarmy](#ciarmy)|396|396|1|0.2%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|8193|8193|1|0.0%|0.0%|

## blocklist_de_sip

[Blocklist.de](https://www.blocklist.de/) All IP addresses that tried to login in a SIP, VOIP or Asterisk Server and are included in the IPs list from [infiltrated.net](www.infiltrated.net)

Source is downloaded from [this link](http://lists.blocklist.de/lists/sip.txt).

The last time downloaded was found to be dated: Fri Jun  5 10:42:10 UTC 2015.

The ipset `blocklist_de_sip` has **96** entries, **96** unique IPs.

The following table shows the overlaps of `blocklist_de_sip` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_sip`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_sip`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_sip`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|31150|31150|76|0.2%|79.1%|
[voipbl](#voipbl)|10426|10837|35|0.3%|36.4%|
[alienvault_reputation](#alienvault_reputation)|180239|180239|17|0.0%|17.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|12|0.0%|12.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|9|0.0%|9.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|4|0.0%|4.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|2|0.0%|2.0%|
[et_botcc](#et_botcc)|509|509|1|0.1%|1.0%|

## blocklist_de_ssh

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service SSH.

Source is downloaded from [this link](http://lists.blocklist.de/lists/ssh.txt).

The last time downloaded was found to be dated: Fri Jun  5 10:42:06 UTC 2015.

The ipset `blocklist_de_ssh` has **8193** entries, **8193** unique IPs.

The following table shows the overlaps of `blocklist_de_ssh` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_ssh`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_ssh`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_ssh`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|31150|31150|8191|26.2%|99.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|1811|0.0%|22.1%|
[alienvault_reputation](#alienvault_reputation)|180239|180239|1589|0.8%|19.3%|
[openbl_60d](#openbl_60d)|7689|7689|1454|18.9%|17.7%|
[openbl_30d](#openbl_30d)|3256|3256|781|23.9%|9.5%|
[bruteforceblocker](#bruteforceblocker)|2007|2007|660|32.8%|8.0%|
[et_compromised](#et_compromised)|2086|2086|639|30.6%|7.7%|
[openbl_7d](#openbl_7d)|910|910|523|57.4%|6.3%|
[shunlist](#shunlist)|1261|1261|347|27.5%|4.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|201|0.0%|2.4%|
[openbl_1d](#openbl_1d)|161|161|132|81.9%|1.6%|
[et_block](#et_block)|1016|18338655|112|0.0%|1.3%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|111|0.0%|1.3%|
[dshield](#dshield)|20|5120|108|2.1%|1.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|104|0.0%|1.2%|
[stopforumspam_30d](#stopforumspam_30d)|93498|93498|60|0.0%|0.7%|
[sorbs_spam](#sorbs_spam)|28347|29370|52|0.1%|0.6%|
[sorbs_recent_spam](#sorbs_recent_spam)|23675|24482|50|0.2%|0.6%|
[sorbs_new_spam](#sorbs_new_spam)|23675|24482|50|0.2%|0.6%|
[blocklist_de_strongips](#blocklist_de_strongips)|176|176|27|15.3%|0.3%|
[stopforumspam_7d](#stopforumspam_7d)|29882|29882|12|0.0%|0.1%|
[nixspam](#nixspam)|23361|23361|8|0.0%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|8|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7188|7188|4|0.0%|0.0%|
[ciarmy](#ciarmy)|396|396|3|0.7%|0.0%|
[voipbl](#voipbl)|10426|10837|2|0.0%|0.0%|
[sslbl](#sslbl)|365|365|1|0.2%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|486400|1|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|16101|16101|1|0.0%|0.0%|

## blocklist_de_strongips

[Blocklist.de](https://www.blocklist.de/) All IPs which are older then 2 month and have more then 5.000 attacks.

Source is downloaded from [this link](http://lists.blocklist.de/lists/strongips.txt).

The last time downloaded was found to be dated: Fri Jun  5 10:14:14 UTC 2015.

The ipset `blocklist_de_strongips` has **176** entries, **176** unique IPs.

The following table shows the overlaps of `blocklist_de_strongips` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_strongips`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_strongips`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_strongips`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|31150|31150|175|0.5%|99.4%|
[blocklist_de_bots](#blocklist_de_bots)|3243|3243|129|3.9%|73.2%|
[stopforumspam_30d](#stopforumspam_30d)|93498|93498|128|0.1%|72.7%|
[stopforumspam_7d](#stopforumspam_7d)|29882|29882|116|0.3%|65.9%|
[stopforumspam_1d](#stopforumspam_1d)|7188|7188|103|1.4%|58.5%|
[blocklist_de_apache](#blocklist_de_apache)|13701|13701|37|0.2%|21.0%|
[alienvault_reputation](#alienvault_reputation)|180239|180239|35|0.0%|19.8%|
[php_commenters](#php_commenters)|301|301|32|10.6%|18.1%|
[blocklist_de_ssh](#blocklist_de_ssh)|8193|8193|27|0.3%|15.3%|
[openbl_60d](#openbl_60d)|7689|7689|26|0.3%|14.7%|
[openbl_30d](#openbl_30d)|3256|3256|24|0.7%|13.6%|
[openbl_7d](#openbl_7d)|910|910|23|2.5%|13.0%|
[blocklist_de_mail](#blocklist_de_mail)|16101|16101|23|0.1%|13.0%|
[shunlist](#shunlist)|1261|1261|20|1.5%|11.3%|
[openbl_1d](#openbl_1d)|161|161|19|11.8%|10.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|15|0.0%|8.5%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2348|2348|8|0.3%|4.5%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|6|0.0%|3.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|6|0.0%|3.4%|
[et_block](#et_block)|1016|18338655|6|0.0%|3.4%|
[dshield](#dshield)|20|5120|6|0.1%|3.4%|
[xroxy](#xroxy)|2079|2079|5|0.2%|2.8%|
[ri_web_proxies](#ri_web_proxies)|6346|6346|5|0.0%|2.8%|
[proxyrss](#proxyrss)|1553|1553|5|0.3%|2.8%|
[php_spammers](#php_spammers)|461|461|5|1.0%|2.8%|
[spamhaus_edrop](#spamhaus_edrop)|55|486400|4|0.0%|2.2%|
[proxz](#proxz)|776|776|4|0.5%|2.2%|
[php_dictionary](#php_dictionary)|508|508|3|0.5%|1.7%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|1.7%|
[nixspam](#nixspam)|23361|23361|2|0.0%|1.1%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|1.1%|
[blocklist_de_ftp](#blocklist_de_ftp)|915|915|2|0.2%|1.1%|
[sorbs_web](#sorbs_web)|785|787|1|0.1%|0.5%|
[sorbs_spam](#sorbs_spam)|28347|29370|1|0.0%|0.5%|
[sorbs_recent_spam](#sorbs_recent_spam)|23675|24482|1|0.0%|0.5%|
[sorbs_new_spam](#sorbs_new_spam)|23675|24482|1|0.0%|0.5%|
[snort_ipfilter](#snort_ipfilter)|9882|9882|1|0.0%|0.5%|
[php_harvesters](#php_harvesters)|298|298|1|0.3%|0.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|1|0.0%|0.5%|
[blocklist_de_imap](#blocklist_de_imap)|2409|2409|1|0.0%|0.5%|

## bm_tor

[torstatus.blutmagie.de](https://torstatus.blutmagie.de) list of all TOR network servers

Source is downloaded from [this link](https://torstatus.blutmagie.de/ip_list_all.php/Tor_ip_list_ALL.csv).

The last time downloaded was found to be dated: Fri Jun  5 10:18:06 UTC 2015.

The ipset `bm_tor` has **6548** entries, **6548** unique IPs.

The following table shows the overlaps of `bm_tor` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `bm_tor`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `bm_tor`.
- ` this % ` is the percentage **of this ipset (`bm_tor`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[dm_tor](#dm_tor)|6554|6554|6485|98.9%|99.0%|
[et_tor](#et_tor)|6610|6610|5881|88.9%|89.8%|
[snort_ipfilter](#snort_ipfilter)|9882|9882|1056|10.6%|16.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|631|0.0%|9.6%|
[stopforumspam_30d](#stopforumspam_30d)|93498|93498|628|0.6%|9.5%|
[stopforumspam_7d](#stopforumspam_7d)|29882|29882|500|1.6%|7.6%|
[stopforumspam_1d](#stopforumspam_1d)|7188|7188|324|4.5%|4.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|190|0.0%|2.9%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|167|44.8%|2.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|167|0.0%|2.5%|
[alienvault_reputation](#alienvault_reputation)|180239|180239|43|0.0%|0.6%|
[php_commenters](#php_commenters)|301|301|32|10.6%|0.4%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|22|0.0%|0.3%|
[openbl_60d](#openbl_60d)|7689|7689|20|0.2%|0.3%|
[php_harvesters](#php_harvesters)|298|298|7|2.3%|0.1%|
[et_block](#et_block)|1016|18338655|7|0.0%|0.1%|
[php_spammers](#php_spammers)|461|461|5|1.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|6346|6346|4|0.0%|0.0%|
[php_dictionary](#php_dictionary)|508|508|4|0.7%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|16101|16101|4|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13701|13701|4|0.0%|0.0%|
[blocklist_de](#blocklist_de)|31150|31150|4|0.0%|0.0%|
[voipbl](#voipbl)|10426|10837|3|0.0%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|0.0%|
[xroxy](#xroxy)|2079|2079|2|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|2|0.0%|0.0%|
[nixspam](#nixspam)|23361|23361|2|0.0%|0.0%|
[dshield](#dshield)|20|5120|2|0.0%|0.0%|
[sorbs_spam](#sorbs_spam)|28347|29370|1|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|23675|24482|1|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|23675|24482|1|0.0%|0.0%|
[shunlist](#shunlist)|1261|1261|1|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2376|2376|1|0.0%|0.0%|

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
[fullbogons](#fullbogons)|3715|670310296|592708608|88.4%|100.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|4194304|3.0%|0.7%|
[voipbl](#voipbl)|10426|10837|319|2.9%|0.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|5|0.0%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|93498|93498|1|0.0%|0.0%|
[php_harvesters](#php_harvesters)|298|298|1|0.3%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.0%|
[ciarmy](#ciarmy)|396|396|1|0.2%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2007|2007|1|0.0%|0.0%|

## bruteforceblocker

[danger.rulez.sk](http://danger.rulez.sk/) IPs detected by [bruteforceblocker](http://danger.rulez.sk/index.php/bruteforceblocker/) (fail2ban alternative for SSH on OpenBSD). This is an automatically generated list from users reporting failed authentication attempts. An IP seems to be included if 3 or more users report it. Its retention pocily seems 30 days.

Source is downloaded from [this link](http://danger.rulez.sk/projects/bruteforceblocker/blist.php).

The last time downloaded was found to be dated: Fri Jun  5 10:27:06 UTC 2015.

The ipset `bruteforceblocker` has **2007** entries, **2007** unique IPs.

The following table shows the overlaps of `bruteforceblocker` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `bruteforceblocker`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `bruteforceblocker`.
- ` this % ` is the percentage **of this ipset (`bruteforceblocker`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[et_compromised](#et_compromised)|2086|2086|1969|94.3%|98.1%|
[alienvault_reputation](#alienvault_reputation)|180239|180239|1296|0.7%|64.5%|
[openbl_60d](#openbl_60d)|7689|7689|1198|15.5%|59.6%|
[openbl_30d](#openbl_30d)|3256|3256|1144|35.1%|57.0%|
[blocklist_de](#blocklist_de)|31150|31150|675|2.1%|33.6%|
[blocklist_de_ssh](#blocklist_de_ssh)|8193|8193|660|8.0%|32.8%|
[shunlist](#shunlist)|1261|1261|474|37.5%|23.6%|
[openbl_7d](#openbl_7d)|910|910|405|44.5%|20.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|197|0.0%|9.8%|
[et_block](#et_block)|1016|18338655|101|0.0%|5.0%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|100|0.0%|4.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|97|0.0%|4.8%|
[dshield](#dshield)|20|5120|96|1.8%|4.7%|
[openbl_1d](#openbl_1d)|161|161|94|58.3%|4.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|50|0.0%|2.4%|
[stopforumspam_30d](#stopforumspam_30d)|93498|93498|11|0.0%|0.5%|
[blocklist_de_mail](#blocklist_de_mail)|16101|16101|8|0.0%|0.3%|
[stopforumspam_7d](#stopforumspam_7d)|29882|29882|7|0.0%|0.3%|
[blocklist_de_imap](#blocklist_de_imap)|2409|2409|6|0.2%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|5|0.0%|0.2%|
[stopforumspam_1d](#stopforumspam_1d)|7188|7188|3|0.0%|0.1%|
[voipbl](#voipbl)|10426|10837|2|0.0%|0.0%|
[proxz](#proxz)|776|776|2|0.2%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|2|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3243|3243|2|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13701|13701|2|0.0%|0.0%|
[xroxy](#xroxy)|2079|2079|1|0.0%|0.0%|
[sorbs_spam](#sorbs_spam)|28347|29370|1|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9882|9882|1|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|6346|6346|1|0.0%|0.0%|
[proxyrss](#proxyrss)|1553|1553|1|0.0%|0.0%|
[fullbogons](#fullbogons)|3715|670310296|1|0.0%|0.0%|
[ciarmy](#ciarmy)|396|396|1|0.2%|0.0%|
[bogons](#bogons)|13|592708608|1|0.0%|0.0%|

## ciarmy

[CIArmy.com](http://ciarmy.com/) IPs with poor Rogue Packet score that have not yet been identified as malicious by the community

Source is downloaded from [this link](http://cinsscore.com/list/ci-badguys.txt).

The last time downloaded was found to be dated: Fri Jun  5 10:15:16 UTC 2015.

The ipset `ciarmy` has **396** entries, **396** unique IPs.

The following table shows the overlaps of `ciarmy` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ciarmy`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ciarmy`.
- ` this % ` is the percentage **of this ipset (`ciarmy`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[alienvault_reputation](#alienvault_reputation)|180239|180239|392|0.2%|98.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|85|0.0%|21.4%|
[blocklist_de](#blocklist_de)|31150|31150|37|0.1%|9.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|34|0.0%|8.5%|
[blocklist_de_apache](#blocklist_de_apache)|13701|13701|33|0.2%|8.3%|
[shunlist](#shunlist)|1261|1261|29|2.2%|7.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|20|0.0%|5.0%|
[voipbl](#voipbl)|10426|10837|6|0.0%|1.5%|
[blocklist_de_ssh](#blocklist_de_ssh)|8193|8193|3|0.0%|0.7%|
[et_block](#et_block)|1016|18338655|2|0.0%|0.5%|
[stopforumspam_7d](#stopforumspam_7d)|29882|29882|1|0.0%|0.2%|
[stopforumspam_30d](#stopforumspam_30d)|93498|93498|1|0.0%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.2%|
[fullbogons](#fullbogons)|3715|670310296|1|0.0%|0.2%|
[et_compromised](#et_compromised)|2086|2086|1|0.0%|0.2%|
[bruteforceblocker](#bruteforceblocker)|2007|2007|1|0.0%|0.2%|
[bogons](#bogons)|13|592708608|1|0.0%|0.2%|
[blocklist_de_mail](#blocklist_de_mail)|16101|16101|1|0.0%|0.2%|
[blocklist_de_imap](#blocklist_de_imap)|2409|2409|1|0.0%|0.2%|

## cleanmx_viruses

[Clean-MX.de](http://support.clean-mx.de/clean-mx/viruses.php) IPs with viruses

Source is downloaded from [this link](http://support.clean-mx.de/clean-mx/xmlviruses.php?sort=id%20desc&response=alive).

The last time downloaded was found to be dated: Fri Jun  5 07:27:53 UTC 2015.

The ipset `cleanmx_viruses` has **309** entries, **309** unique IPs.

The following table shows the overlaps of `cleanmx_viruses` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `cleanmx_viruses`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `cleanmx_viruses`.
- ` this % ` is the percentage **of this ipset (`cleanmx_viruses`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|41|0.0%|13.2%|
[malc0de](#malc0de)|379|379|29|7.6%|9.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|15|0.0%|4.8%|
[alienvault_reputation](#alienvault_reputation)|180239|180239|9|0.0%|2.9%|
[snort_ipfilter](#snort_ipfilter)|9882|9882|4|0.0%|1.2%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|3|0.2%|0.9%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|3|0.0%|0.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|2|0.0%|0.6%|
[stopforumspam_30d](#stopforumspam_30d)|93498|93498|1|0.0%|0.3%|
[sslbl](#sslbl)|365|365|1|0.2%|0.3%|
[nixspam](#nixspam)|23361|23361|1|0.0%|0.3%|
[dshield](#dshield)|20|5120|1|0.0%|0.3%|

## dm_tor

[dan.me.uk](https://www.dan.me.uk) dynamic list of TOR exit points

Source is downloaded from [this link](https://www.dan.me.uk/torlist/).

The last time downloaded was found to be dated: Fri Jun  5 10:18:04 UTC 2015.

The ipset `dm_tor` has **6554** entries, **6554** unique IPs.

The following table shows the overlaps of `dm_tor` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `dm_tor`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `dm_tor`.
- ` this % ` is the percentage **of this ipset (`dm_tor`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[bm_tor](#bm_tor)|6548|6548|6485|99.0%|98.9%|
[et_tor](#et_tor)|6610|6610|5865|88.7%|89.4%|
[snort_ipfilter](#snort_ipfilter)|9882|9882|1054|10.6%|16.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|631|0.0%|9.6%|
[stopforumspam_30d](#stopforumspam_30d)|93498|93498|628|0.6%|9.5%|
[stopforumspam_7d](#stopforumspam_7d)|29882|29882|500|1.6%|7.6%|
[stopforumspam_1d](#stopforumspam_1d)|7188|7188|324|4.5%|4.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|190|0.0%|2.8%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|167|44.8%|2.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|167|0.0%|2.5%|
[alienvault_reputation](#alienvault_reputation)|180239|180239|43|0.0%|0.6%|
[php_commenters](#php_commenters)|301|301|32|10.6%|0.4%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|22|0.0%|0.3%|
[openbl_60d](#openbl_60d)|7689|7689|20|0.2%|0.3%|
[php_harvesters](#php_harvesters)|298|298|7|2.3%|0.1%|
[et_block](#et_block)|1016|18338655|7|0.0%|0.1%|
[php_spammers](#php_spammers)|461|461|5|1.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|6346|6346|4|0.0%|0.0%|
[php_dictionary](#php_dictionary)|508|508|4|0.7%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|16101|16101|4|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13701|13701|4|0.0%|0.0%|
[blocklist_de](#blocklist_de)|31150|31150|4|0.0%|0.0%|
[voipbl](#voipbl)|10426|10837|3|0.0%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|0.0%|
[xroxy](#xroxy)|2079|2079|2|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|2|0.0%|0.0%|
[nixspam](#nixspam)|23361|23361|2|0.0%|0.0%|
[dshield](#dshield)|20|5120|2|0.0%|0.0%|
[sorbs_spam](#sorbs_spam)|28347|29370|1|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|23675|24482|1|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|23675|24482|1|0.0%|0.0%|
[shunlist](#shunlist)|1261|1261|1|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2376|2376|1|0.0%|0.0%|

## dshield

[DShield.org](https://dshield.org/) top 20 attacking class C (/24) subnets over the last three days - **excellent list**

Source is downloaded from [this link](http://feeds.dshield.org/block.txt).

The last time downloaded was found to be dated: Fri Jun  5 07:27:39 UTC 2015.

The ipset `dshield` has **20** entries, **5120** unique IPs.

The following table shows the overlaps of `dshield` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `dshield`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `dshield`.
- ` this % ` is the percentage **of this ipset (`dshield`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[alienvault_reputation](#alienvault_reputation)|180239|180239|5120|2.8%|100.0%|
[et_block](#et_block)|1016|18338655|1536|0.0%|30.0%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|512|0.0%|10.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|256|0.0%|5.0%|
[openbl_60d](#openbl_60d)|7689|7689|133|1.7%|2.5%|
[blocklist_de](#blocklist_de)|31150|31150|121|0.3%|2.3%|
[openbl_30d](#openbl_30d)|3256|3256|119|3.6%|2.3%|
[shunlist](#shunlist)|1261|1261|112|8.8%|2.1%|
[blocklist_de_ssh](#blocklist_de_ssh)|8193|8193|108|1.3%|2.1%|
[et_compromised](#et_compromised)|2086|2086|97|4.6%|1.8%|
[bruteforceblocker](#bruteforceblocker)|2007|2007|96|4.7%|1.8%|
[openbl_7d](#openbl_7d)|910|910|51|5.6%|0.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|33|0.0%|0.6%|
[openbl_1d](#openbl_1d)|161|161|17|10.5%|0.3%|
[blocklist_de_apache](#blocklist_de_apache)|13701|13701|10|0.0%|0.1%|
[stopforumspam_30d](#stopforumspam_30d)|93498|93498|8|0.0%|0.1%|
[blocklist_de_strongips](#blocklist_de_strongips)|176|176|6|3.4%|0.1%|
[stopforumspam_7d](#stopforumspam_7d)|29882|29882|5|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7188|7188|4|0.0%|0.0%|
[malc0de](#malc0de)|379|379|2|0.5%|0.0%|
[et_tor](#et_tor)|6610|6610|2|0.0%|0.0%|
[dm_tor](#dm_tor)|6554|6554|2|0.0%|0.0%|
[bm_tor](#bm_tor)|6548|6548|2|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3243|3243|2|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9882|9882|1|0.0%|0.0%|
[php_harvesters](#php_harvesters)|298|298|1|0.3%|0.0%|
[php_commenters](#php_commenters)|301|301|1|0.3%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|309|309|1|0.3%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|16101|16101|1|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2409|2409|1|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2348|2348|1|0.0%|0.0%|

## et_block

[EmergingThreats.net](http://www.emergingthreats.net/) default blacklist (at the time of writing includes spamhaus DROP, dshield and abuse.ch trackers, which are available separately too - prefer to use the direct ipsets instead of this, they seem to lag a bit in updates)

Source is downloaded from [this link](http://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt).

The last time downloaded was found to be dated: Thu Jun  4 04:30:01 UTC 2015.

The ipset `et_block` has **1016** entries, **18338655** unique IPs.

The following table shows the overlaps of `et_block` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `et_block`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `et_block`.
- ` this % ` is the percentage **of this ipset (`et_block`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[spamhaus_drop](#spamhaus_drop)|653|18404096|18120448|98.4%|98.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|8598071|2.4%|46.8%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|7079936|77.1%|38.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|2272532|0.2%|12.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|196699|0.1%|1.0%|
[fullbogons](#fullbogons)|3715|670310296|20480|0.0%|0.1%|
[alienvault_reputation](#alienvault_reputation)|180239|180239|5534|3.0%|0.0%|
[dshield](#dshield)|20|5120|1536|30.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1043|0.3%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|93498|93498|1028|1.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|486400|517|0.1%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29882|29882|341|1.1%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9882|9882|315|3.1%|0.0%|
[openbl_60d](#openbl_60d)|7689|7689|245|3.1%|0.0%|
[zeus](#zeus)|231|231|223|96.5%|0.0%|
[nixspam](#nixspam)|23361|23361|200|0.8%|0.0%|
[zeus_badips](#zeus_badips)|202|202|199|98.5%|0.0%|
[blocklist_de](#blocklist_de)|31150|31150|182|0.5%|0.0%|
[openbl_30d](#openbl_30d)|3256|3256|165|5.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|8193|8193|112|1.3%|0.0%|
[shunlist](#shunlist)|1261|1261|108|8.5%|0.0%|
[et_compromised](#et_compromised)|2086|2086|102|4.8%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2007|2007|101|5.0%|0.0%|
[feodo](#feodo)|94|94|87|92.5%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7188|7188|79|1.0%|0.0%|
[openbl_7d](#openbl_7d)|910|910|52|5.7%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3243|3243|38|1.1%|0.0%|
[sslbl](#sslbl)|365|365|33|9.0%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|29|2.2%|0.0%|
[php_commenters](#php_commenters)|301|301|26|8.6%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|16101|16101|25|0.1%|0.0%|
[voipbl](#voipbl)|10426|10837|21|0.1%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2409|2409|17|0.7%|0.0%|
[sorbs_spam](#sorbs_spam)|28347|29370|12|0.0%|0.0%|
[palevo](#palevo)|12|12|11|91.6%|0.0%|
[openbl_1d](#openbl_1d)|161|161|10|6.2%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|8|0.0%|0.0%|
[et_tor](#et_tor)|6610|6610|8|0.1%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|23675|24482|7|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|23675|24482|7|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|7|0.4%|0.0%|
[dm_tor](#dm_tor)|6554|6554|7|0.1%|0.0%|
[bm_tor](#bm_tor)|6548|6548|7|0.1%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13701|13701|7|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|176|176|6|3.4%|0.0%|
[php_dictionary](#php_dictionary)|508|508|4|0.7%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|4|1.0%|0.0%|
[malc0de](#malc0de)|379|379|4|1.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2348|2348|3|0.1%|0.0%|
[php_spammers](#php_spammers)|461|461|2|0.4%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|2|0.2%|0.0%|
[et_botcc](#et_botcc)|509|509|2|0.3%|0.0%|
[ciarmy](#ciarmy)|396|396|2|0.5%|0.0%|
[xroxy](#xroxy)|2079|2079|1|0.0%|0.0%|
[sorbs_web](#sorbs_web)|785|787|1|0.1%|0.0%|
[proxz](#proxz)|776|776|1|0.1%|0.0%|
[php_harvesters](#php_harvesters)|298|298|1|0.3%|0.0%|

## et_botcc

[EmergingThreats.net Command and Control IPs](http://doc.emergingthreats.net/bin/view/Main/BotCC) These IPs are updates every 24 hours and should be considered VERY highly reliable indications that a host is communicating with a known and active Bot or Malware command and control server - (although they say this includes abuse.ch trackers, it does not - most probably it is the shadowserver.org C&C list)

Source is downloaded from [this link](http://rules.emergingthreats.net/fwrules/emerging-PIX-CC.rules).

The last time downloaded was found to be dated: Thu Jun  4 04:30:01 UTC 2015.

The ipset `et_botcc` has **509** entries, **509** unique IPs.

The following table shows the overlaps of `et_botcc` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `et_botcc`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `et_botcc`.
- ` this % ` is the percentage **of this ipset (`et_botcc`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|78|0.0%|15.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|41|0.0%|8.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|22|0.0%|4.3%|
[alienvault_reputation](#alienvault_reputation)|180239|180239|4|0.0%|0.7%|
[et_block](#et_block)|1016|18338655|2|0.0%|0.3%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|1|0.0%|0.1%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|1|0.0%|0.1%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.1%|
[blocklist_de_sip](#blocklist_de_sip)|96|96|1|1.0%|0.1%|

## et_compromised

[EmergingThreats.net compromised hosts](http://doc.emergingthreats.net/bin/view/Main/CompromisedHost) - (this seems to be based on bruteforceblocker)

Source is downloaded from [this link](http://rules.emergingthreats.net/blockrules/compromised-ips.txt).

The last time downloaded was found to be dated: Thu Jun  4 04:30:08 UTC 2015.

The ipset `et_compromised` has **2086** entries, **2086** unique IPs.

The following table shows the overlaps of `et_compromised` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `et_compromised`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `et_compromised`.
- ` this % ` is the percentage **of this ipset (`et_compromised`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[bruteforceblocker](#bruteforceblocker)|2007|2007|1969|98.1%|94.3%|
[alienvault_reputation](#alienvault_reputation)|180239|180239|1364|0.7%|65.3%|
[openbl_60d](#openbl_60d)|7689|7689|1265|16.4%|60.6%|
[openbl_30d](#openbl_30d)|3256|3256|1191|36.5%|57.0%|
[blocklist_de](#blocklist_de)|31150|31150|653|2.0%|31.3%|
[blocklist_de_ssh](#blocklist_de_ssh)|8193|8193|639|7.7%|30.6%|
[shunlist](#shunlist)|1261|1261|486|38.5%|23.2%|
[openbl_7d](#openbl_7d)|910|910|402|44.1%|19.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|209|0.0%|10.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|105|0.0%|5.0%|
[et_block](#et_block)|1016|18338655|102|0.0%|4.8%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|100|0.0%|4.7%|
[dshield](#dshield)|20|5120|97|1.8%|4.6%|
[openbl_1d](#openbl_1d)|161|161|88|54.6%|4.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|59|0.0%|2.8%|
[stopforumspam_30d](#stopforumspam_30d)|93498|93498|10|0.0%|0.4%|
[blocklist_de_mail](#blocklist_de_mail)|16101|16101|8|0.0%|0.3%|
[stopforumspam_7d](#stopforumspam_7d)|29882|29882|6|0.0%|0.2%|
[blocklist_de_imap](#blocklist_de_imap)|2409|2409|6|0.2%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|5|0.0%|0.2%|
[voipbl](#voipbl)|10426|10837|2|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7188|7188|2|0.0%|0.0%|
[proxz](#proxz)|776|776|2|0.2%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|2|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13701|13701|2|0.0%|0.0%|
[xroxy](#xroxy)|2079|2079|1|0.0%|0.0%|
[sorbs_spam](#sorbs_spam)|28347|29370|1|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9882|9882|1|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|6346|6346|1|0.0%|0.0%|
[proxyrss](#proxyrss)|1553|1553|1|0.0%|0.0%|
[ciarmy](#ciarmy)|396|396|1|0.2%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3243|3243|1|0.0%|0.0%|

## et_tor

[EmergingThreats.net](http://www.emergingthreats.net/) [list](http://doc.emergingthreats.net/bin/view/Main/TorRules) of TOR network IPs

Source is downloaded from [this link](http://rules.emergingthreats.net/blockrules/emerging-tor.rules).

The last time downloaded was found to be dated: Thu Jun  4 04:30:08 UTC 2015.

The ipset `et_tor` has **6610** entries, **6610** unique IPs.

The following table shows the overlaps of `et_tor` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `et_tor`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `et_tor`.
- ` this % ` is the percentage **of this ipset (`et_tor`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[bm_tor](#bm_tor)|6548|6548|5881|89.8%|88.9%|
[dm_tor](#dm_tor)|6554|6554|5865|89.4%|88.7%|
[snort_ipfilter](#snort_ipfilter)|9882|9882|1112|11.2%|16.8%|
[stopforumspam_30d](#stopforumspam_30d)|93498|93498|644|0.6%|9.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|635|0.0%|9.6%|
[stopforumspam_7d](#stopforumspam_7d)|29882|29882|516|1.7%|7.8%|
[stopforumspam_1d](#stopforumspam_1d)|7188|7188|327|4.5%|4.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|187|0.0%|2.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|173|0.0%|2.6%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|172|46.2%|2.6%|
[alienvault_reputation](#alienvault_reputation)|180239|180239|44|0.0%|0.6%|
[php_commenters](#php_commenters)|301|301|33|10.9%|0.4%|
[openbl_60d](#openbl_60d)|7689|7689|21|0.2%|0.3%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|21|0.0%|0.3%|
[et_block](#et_block)|1016|18338655|8|0.0%|0.1%|
[php_harvesters](#php_harvesters)|298|298|7|2.3%|0.1%|
[php_spammers](#php_spammers)|461|461|6|1.3%|0.0%|
[php_dictionary](#php_dictionary)|508|508|5|0.9%|0.0%|
[ri_web_proxies](#ri_web_proxies)|6346|6346|4|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|16101|16101|4|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13701|13701|4|0.0%|0.0%|
[blocklist_de](#blocklist_de)|31150|31150|4|0.0%|0.0%|
[voipbl](#voipbl)|10426|10837|3|0.0%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|0.0%|
[xroxy](#xroxy)|2079|2079|2|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|2|0.0%|0.0%|
[sorbs_spam](#sorbs_spam)|28347|29370|2|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|23675|24482|2|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|23675|24482|2|0.0%|0.0%|
[nixspam](#nixspam)|23361|23361|2|0.0%|0.0%|
[dshield](#dshield)|20|5120|2|0.0%|0.0%|
[shunlist](#shunlist)|1261|1261|1|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2376|2376|1|0.0%|0.0%|

## feodo

[Abuse.ch Feodo tracker](https://feodotracker.abuse.ch) trojan includes IPs which are being used by Feodo (also known as Cridex or Bugat) which commits ebanking fraud - **excellent list**

Source is downloaded from [this link](https://feodotracker.abuse.ch/blocklist/?download=ipblocklist).

The last time downloaded was found to be dated: Fri Jun  5 10:18:20 UTC 2015.

The ipset `feodo` has **94** entries, **94** unique IPs.

The following table shows the overlaps of `feodo` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `feodo`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `feodo`.
- ` this % ` is the percentage **of this ipset (`feodo`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[et_block](#et_block)|1016|18338655|87|0.0%|92.5%|
[snort_ipfilter](#snort_ipfilter)|9882|9882|73|0.7%|77.6%|
[sslbl](#sslbl)|365|365|34|9.3%|36.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|10|0.0%|10.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|3|0.0%|3.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|3|0.0%|3.1%|
[alienvault_reputation](#alienvault_reputation)|180239|180239|2|0.0%|2.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|1.0%|

## fullbogons

[Team-Cymru.org](http://www.team-cymru.org) IP space that has been allocated to an RIR, but not assigned by that RIR to an actual ISP or other end-user - **excellent list - use it only your internet interface**

Source is downloaded from [this link](http://www.team-cymru.org/Services/Bogons/fullbogons-ipv4.txt).

The last time downloaded was found to be dated: Fri Jun  5 09:35:07 UTC 2015.

The ipset `fullbogons` has **3715** entries, **670310296** unique IPs.

The following table shows the overlaps of `fullbogons` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `fullbogons`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `fullbogons`.
- ` this % ` is the percentage **of this ipset (`fullbogons`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[bogons](#bogons)|13|592708608|592708608|100.0%|88.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|4236335|3.0%|0.6%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|565248|6.1%|0.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|249087|0.0%|0.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|239993|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|151552|0.8%|0.0%|
[et_block](#et_block)|1016|18338655|20480|0.1%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|890|0.2%|0.0%|
[voipbl](#voipbl)|10426|10837|319|2.9%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|33|2.2%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|15|0.0%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|9|0.6%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|93498|93498|2|0.0%|0.0%|
[php_harvesters](#php_harvesters)|298|298|1|0.3%|0.0%|
[ciarmy](#ciarmy)|396|396|1|0.2%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2007|2007|1|0.0%|0.0%|

## ib_bluetack_badpeers

[iBlocklist.com](https://www.iblocklist.com/) free version of [BlueTack.co.uk](http://www.bluetack.co.uk/) IPs that have been reported for bad deeds in p2p

Source is downloaded from [this link](http://list.iblocklist.com/?list=cwworuawihqvocglcoss&fileformat=p2p&archiveformat=gz).

The last time downloaded was found to be dated: Fri Jun  5 04:40:53 UTC 2015.

The ipset `ib_bluetack_badpeers` has **48134** entries, **48134** unique IPs.

The following table shows the overlaps of `ib_bluetack_badpeers` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ib_bluetack_badpeers`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ib_bluetack_badpeers`.
- ` this % ` is the percentage **of this ipset (`ib_bluetack_badpeers`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|1172|0.0%|2.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|406|0.0%|0.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|230|0.0%|0.4%|
[fullbogons](#fullbogons)|3715|670310296|15|0.0%|0.0%|
[alienvault_reputation](#alienvault_reputation)|180239|180239|15|0.0%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|93498|93498|14|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|11|1.6%|0.0%|
[nixspam](#nixspam)|23361|23361|10|0.0%|0.0%|
[sorbs_spam](#sorbs_spam)|28347|29370|8|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|23675|24482|8|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|23675|24482|8|0.0%|0.0%|
[et_block](#et_block)|1016|18338655|8|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|6|0.0%|0.0%|
[blocklist_de](#blocklist_de)|31150|31150|6|0.0%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29882|29882|5|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|4|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|16101|16101|4|0.0%|0.0%|
[xroxy](#xroxy)|2079|2079|3|0.1%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2348|2348|3|0.1%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13701|13701|3|0.0%|0.0%|
[voipbl](#voipbl)|10426|10837|2|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|6346|6346|2|0.0%|0.0%|
[php_harvesters](#php_harvesters)|298|298|2|0.6%|0.0%|
[php_dictionary](#php_dictionary)|508|508|2|0.3%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7188|7188|1|0.0%|0.0%|
[sorbs_web](#sorbs_web)|785|787|1|0.1%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9882|9882|1|0.0%|0.0%|
[proxz](#proxz)|776|776|1|0.1%|0.0%|
[php_spammers](#php_spammers)|461|461|1|0.2%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|

## ib_bluetack_hijacked

[iBlocklist.com](https://www.iblocklist.com/) free version of [BlueTack.co.uk](http://www.bluetack.co.uk/) hijacked IP-Blocks Hijacked IP space are IP blocks that are being used without permission

Source is downloaded from [this link](http://list.iblocklist.com/?list=usrcshglbiilevmyfhse&fileformat=p2p&archiveformat=gz).

The last time downloaded was found to be dated: Fri Jun  5 05:10:45 UTC 2015.

The ipset `ib_bluetack_hijacked` has **535** entries, **9177856** unique IPs.

The following table shows the overlaps of `ib_bluetack_hijacked` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ib_bluetack_hijacked`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ib_bluetack_hijacked`.
- ` this % ` is the percentage **of this ipset (`ib_bluetack_hijacked`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[et_block](#et_block)|1016|18338655|7079936|38.6%|77.1%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|6998016|38.0%|76.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|2526625|0.7%|27.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|904796|0.1%|9.8%|
[fullbogons](#fullbogons)|3715|670310296|565248|0.0%|6.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|145472|0.1%|1.5%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1036|0.3%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|93498|93498|759|0.8%|0.0%|
[alienvault_reputation](#alienvault_reputation)|180239|180239|518|0.2%|0.0%|
[nixspam](#nixspam)|23361|23361|199|0.8%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29882|29882|177|0.5%|0.0%|
[blocklist_de](#blocklist_de)|31150|31150|45|0.1%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3243|3243|29|0.8%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|27|2.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7188|7188|22|0.3%|0.0%|
[openbl_60d](#openbl_60d)|7689|7689|18|0.2%|0.0%|
[openbl_30d](#openbl_30d)|3256|3256|13|0.3%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9882|9882|11|0.1%|0.0%|
[zeus_badips](#zeus_badips)|202|202|10|4.9%|0.0%|
[zeus](#zeus)|231|231|10|4.3%|0.0%|
[sorbs_spam](#sorbs_spam)|28347|29370|8|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|8193|8193|8|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|7|0.4%|0.0%|
[openbl_7d](#openbl_7d)|910|910|6|0.6%|0.0%|
[et_compromised](#et_compromised)|2086|2086|5|0.2%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2007|2007|5|0.2%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|16101|16101|5|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|23675|24482|3|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|23675|24482|3|0.0%|0.0%|
[et_tor](#et_tor)|6610|6610|3|0.0%|0.0%|
[dm_tor](#dm_tor)|6554|6554|3|0.0%|0.0%|
[bm_tor](#bm_tor)|6548|6548|3|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|176|176|3|1.7%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2409|2409|3|0.1%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13701|13701|3|0.0%|0.0%|
[shunlist](#shunlist)|1261|1261|2|0.1%|0.0%|
[php_spammers](#php_spammers)|461|461|2|0.4%|0.0%|
[php_dictionary](#php_dictionary)|508|508|2|0.3%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|2|0.2%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2348|2348|2|0.0%|0.0%|
[voipbl](#voipbl)|10426|10837|1|0.0%|0.0%|
[php_harvesters](#php_harvesters)|298|298|1|0.3%|0.0%|
[php_commenters](#php_commenters)|301|301|1|0.3%|0.0%|
[openbl_1d](#openbl_1d)|161|161|1|0.6%|0.0%|
[et_botcc](#et_botcc)|509|509|1|0.1%|0.0%|

## ib_bluetack_level1

[iBlocklist.com](https://www.iblocklist.com/) free version of [BlueTack.co.uk](http://www.bluetack.co.uk/) Level 1 (for use in p2p): Companies or organizations who are clearly involved with trying to stop filesharing (e.g. Baytsp, MediaDefender, Mediasentry a.o.). Companies which anti-p2p activity has been seen from. Companies that produce or have a strong financial interest in copyrighted material (e.g. music, movie, software industries a.o.). Government ranges or companies that have a strong financial interest in doing work for governments. Legal industry ranges. IPs or ranges of ISPs from which anti-p2p activity has been observed. Basically this list will block all kinds of internet connections that most people would rather not have during their internet travels.

Source is downloaded from [this link](http://list.iblocklist.com/?list=ydxerpxkpcfqjaybcssw&fileformat=p2p&archiveformat=gz).

The last time downloaded was found to be dated: Fri Jun  5 09:14:41 UTC 2015.

The ipset `ib_bluetack_level1` has **218309** entries, **764987411** unique IPs.

The following table shows the overlaps of `ib_bluetack_level1` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ib_bluetack_level1`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ib_bluetack_level1`.
- ` this % ` is the percentage **of this ipset (`ib_bluetack_level1`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|16300309|4.6%|2.1%|
[et_block](#et_block)|1016|18338655|2272532|12.3%|0.2%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|2272265|12.3%|0.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|1354348|0.9%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|904796|9.8%|0.1%|
[fullbogons](#fullbogons)|3715|670310296|239993|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|486400|33155|6.8%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|13248|3.9%|0.0%|
[alienvault_reputation](#alienvault_reputation)|180239|180239|4481|2.4%|0.0%|
[blocklist_de](#blocklist_de)|31150|31150|1591|5.1%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|93498|93498|1554|1.6%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|16101|16101|1382|8.5%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13701|13701|1324|9.6%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29882|29882|566|1.8%|0.0%|
[sorbs_spam](#sorbs_spam)|28347|29370|452|1.5%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|406|0.8%|0.0%|
[nixspam](#nixspam)|23361|23361|383|1.6%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|23675|24482|368|1.5%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|23675|24482|368|1.5%|0.0%|
[voipbl](#voipbl)|10426|10837|299|2.7%|0.0%|
[et_tor](#et_tor)|6610|6610|173|2.6%|0.0%|
[openbl_60d](#openbl_60d)|7689|7689|172|2.2%|0.0%|
[dm_tor](#dm_tor)|6554|6554|167|2.5%|0.0%|
[bm_tor](#bm_tor)|6548|6548|167|2.5%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7188|7188|151|2.1%|0.0%|
[ri_web_proxies](#ri_web_proxies)|6346|6346|133|2.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|8193|8193|104|1.2%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9882|9882|99|1.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|97|6.6%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2376|2376|75|3.1%|0.0%|
[openbl_30d](#openbl_30d)|3256|3256|71|2.1%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|66|5.1%|0.0%|
[et_compromised](#et_compromised)|2086|2086|59|2.8%|0.0%|
[xroxy](#xroxy)|2079|2079|58|2.7%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|58|8.6%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2007|2007|50|2.4%|0.0%|
[proxyrss](#proxyrss)|1553|1553|45|2.8%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3243|3243|45|1.3%|0.0%|
[et_botcc](#et_botcc)|509|509|41|8.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2409|2409|39|1.6%|0.0%|
[dshield](#dshield)|20|5120|33|0.6%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2348|2348|33|1.4%|0.0%|
[proxz](#proxz)|776|776|28|3.6%|0.0%|
[sorbs_web](#sorbs_web)|785|787|26|3.3%|0.0%|
[shunlist](#shunlist)|1261|1261|26|2.0%|0.0%|
[openbl_7d](#openbl_7d)|910|910|20|2.1%|0.0%|
[ciarmy](#ciarmy)|396|396|20|5.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|17|4.5%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|915|915|13|1.4%|0.0%|
[malc0de](#malc0de)|379|379|12|3.1%|0.0%|
[php_dictionary](#php_dictionary)|508|508|11|2.1%|0.0%|
[php_harvesters](#php_harvesters)|298|298|9|3.0%|0.0%|
[zeus](#zeus)|231|231|7|3.0%|0.0%|
[php_commenters](#php_commenters)|301|301|6|1.9%|0.0%|
[zeus_badips](#zeus_badips)|202|202|5|2.4%|0.0%|
[php_spammers](#php_spammers)|461|461|5|1.0%|0.0%|
[bogons](#bogons)|13|592708608|5|0.0%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|96|96|4|4.1%|0.0%|
[sslbl](#sslbl)|365|365|3|0.8%|0.0%|
[openbl_1d](#openbl_1d)|161|161|3|1.8%|0.0%|
[feodo](#feodo)|94|94|3|3.1%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|309|309|2|0.6%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|176|176|1|0.5%|0.0%|

## ib_bluetack_level2

[iBlocklist.com](https://www.iblocklist.com/) free version of BlueTack.co.uk Level 2 (for use in p2p). General corporate ranges. Ranges used by labs or researchers. Proxies.

Source is downloaded from [this link](http://list.iblocklist.com/?list=gyisgnzbhppbvsphucsw&fileformat=p2p&archiveformat=gz).

The last time downloaded was found to be dated: Fri Jun  5 05:10:25 UTC 2015.

The ipset `ib_bluetack_level2` has **72774** entries, **348707599** unique IPs.

The following table shows the overlaps of `ib_bluetack_level2` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ib_bluetack_level2`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ib_bluetack_level2`.
- ` this % ` is the percentage **of this ipset (`ib_bluetack_level2`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|16300309|2.1%|4.6%|
[et_block](#et_block)|1016|18338655|8598071|46.8%|2.4%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|8598042|46.7%|2.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|2830140|2.0%|0.8%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2526625|27.5%|0.7%|
[fullbogons](#fullbogons)|3715|670310296|249087|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|486400|98904|20.3%|0.0%|
[alienvault_reputation](#alienvault_reputation)|180239|180239|7809|4.3%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|7733|2.2%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|93498|93498|2548|2.7%|0.0%|
[blocklist_de](#blocklist_de)|31150|31150|1531|4.9%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|16101|16101|1164|7.2%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13701|13701|1069|7.8%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29882|29882|932|3.1%|0.0%|
[sorbs_spam](#sorbs_spam)|28347|29370|692|2.3%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|23675|24482|608|2.4%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|23675|24482|608|2.4%|0.0%|
[nixspam](#nixspam)|23361|23361|582|2.4%|0.0%|
[voipbl](#voipbl)|10426|10837|434|4.0%|0.0%|
[openbl_60d](#openbl_60d)|7689|7689|340|4.4%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7188|7188|230|3.1%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|230|0.4%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|8193|8193|201|2.4%|0.0%|
[dm_tor](#dm_tor)|6554|6554|190|2.8%|0.0%|
[bm_tor](#bm_tor)|6548|6548|190|2.9%|0.0%|
[ri_web_proxies](#ri_web_proxies)|6346|6346|187|2.9%|0.0%|
[et_tor](#et_tor)|6610|6610|187|2.8%|0.0%|
[openbl_30d](#openbl_30d)|3256|3256|169|5.1%|0.0%|
[et_compromised](#et_compromised)|2086|2086|105|5.0%|0.0%|
[xroxy](#xroxy)|2079|2079|100|4.8%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3243|3243|98|3.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9882|9882|97|0.9%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2007|2007|97|4.8%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2376|2376|91|3.8%|0.0%|
[shunlist](#shunlist)|1261|1261|76|6.0%|0.0%|
[proxyrss](#proxyrss)|1553|1553|60|3.8%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2409|2409|58|2.4%|0.0%|
[openbl_7d](#openbl_7d)|910|910|49|5.3%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|45|3.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2348|2348|37|1.5%|0.0%|
[php_spammers](#php_spammers)|461|461|34|7.3%|0.0%|
[ciarmy](#ciarmy)|396|396|34|8.5%|0.0%|
[proxz](#proxz)|776|776|32|4.1%|0.0%|
[sorbs_web](#sorbs_web)|785|787|29|3.6%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|28|4.1%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|26|2.0%|0.0%|
[malc0de](#malc0de)|379|379|23|6.0%|0.0%|
[et_botcc](#et_botcc)|509|509|22|4.3%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|21|5.6%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|915|915|18|1.9%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|309|309|15|4.8%|0.0%|
[php_dictionary](#php_dictionary)|508|508|13|2.5%|0.0%|
[php_commenters](#php_commenters)|301|301|11|3.6%|0.0%|
[zeus](#zeus)|231|231|9|3.8%|0.0%|
[php_harvesters](#php_harvesters)|298|298|9|3.0%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|96|96|9|9.3%|0.0%|
[zeus_badips](#zeus_badips)|202|202|8|3.9%|0.0%|
[openbl_1d](#openbl_1d)|161|161|7|4.3%|0.0%|
[sslbl](#sslbl)|365|365|6|1.6%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|176|176|6|3.4%|0.0%|
[palevo](#palevo)|12|12|3|25.0%|0.0%|
[feodo](#feodo)|94|94|3|3.1%|0.0%|
[virbl](#virbl)|10|10|1|10.0%|0.0%|
[sorbs_socks](#sorbs_socks)|31|31|1|3.2%|0.0%|
[sorbs_smtp](#sorbs_smtp)|14|14|1|7.1%|0.0%|
[sorbs_misc](#sorbs_misc)|31|31|1|3.2%|0.0%|
[sorbs_http](#sorbs_http)|31|31|1|3.2%|0.0%|

## ib_bluetack_level3

[iBlocklist.com](https://www.iblocklist.com/) free version of BlueTack.co.uk Level 3 (for use in p2p). Many portal-type websites. ISP ranges that may be dodgy for some reason. Ranges that belong to an individual, but which have not been determined to be used by a particular company. Ranges for things that are unusual in some way. The L3 list is aka the paranoid list.

Source is downloaded from [this link](http://list.iblocklist.com/?list=uwnukjqktoggdknzrhgh&fileformat=p2p&archiveformat=gz).

The last time downloaded was found to be dated: Fri Jun  5 05:10:17 UTC 2015.

The ipset `ib_bluetack_level3` has **17802** entries, **139104824** unique IPs.

The following table shows the overlaps of `ib_bluetack_level3` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ib_bluetack_level3`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ib_bluetack_level3`.
- ` this % ` is the percentage **of this ipset (`ib_bluetack_level3`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[fullbogons](#fullbogons)|3715|670310296|4236335|0.6%|3.0%|
[bogons](#bogons)|13|592708608|4194304|0.7%|3.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|2830140|0.8%|2.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|1354348|0.1%|0.9%|
[spamhaus_edrop](#spamhaus_edrop)|55|486400|270785|55.6%|0.1%|
[et_block](#et_block)|1016|18338655|196699|1.0%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|145472|1.5%|0.1%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|130368|0.7%|0.0%|
[alienvault_reputation](#alienvault_reputation)|180239|180239|14666|8.1%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|9231|2.7%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|93498|93498|5886|6.2%|0.0%|
[blocklist_de](#blocklist_de)|31150|31150|4802|15.4%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|16101|16101|2500|15.5%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13701|13701|2290|16.7%|0.0%|
[sorbs_spam](#sorbs_spam)|28347|29370|2158|7.3%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29882|29882|1876|6.2%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|8193|8193|1811|22.1%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|23675|24482|1778|7.2%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|23675|24482|1778|7.2%|0.0%|
[nixspam](#nixspam)|23361|23361|1642|7.0%|0.0%|
[voipbl](#voipbl)|10426|10837|1596|14.7%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1172|2.4%|0.0%|
[openbl_60d](#openbl_60d)|7689|7689|747|9.7%|0.0%|
[et_tor](#et_tor)|6610|6610|635|9.6%|0.0%|
[dm_tor](#dm_tor)|6554|6554|631|9.6%|0.0%|
[bm_tor](#bm_tor)|6548|6548|631|9.6%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7188|7188|502|6.9%|0.0%|
[openbl_30d](#openbl_30d)|3256|3256|310|9.5%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2409|2409|283|11.7%|0.0%|
[dshield](#dshield)|20|5120|256|5.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9882|9882|225|2.2%|0.0%|
[et_compromised](#et_compromised)|2086|2086|209|10.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2007|2007|197|9.8%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2348|2348|195|8.3%|0.0%|
[ri_web_proxies](#ri_web_proxies)|6346|6346|183|2.8%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3243|3243|183|5.6%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|147|11.4%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|125|33.6%|0.0%|
[openbl_7d](#openbl_7d)|910|910|114|12.5%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|110|7.5%|0.0%|
[shunlist](#shunlist)|1261|1261|106|8.4%|0.0%|
[xroxy](#xroxy)|2079|2079|92|4.4%|0.0%|
[ciarmy](#ciarmy)|396|396|85|21.4%|0.0%|
[et_botcc](#et_botcc)|509|509|78|15.3%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|915|915|73|7.9%|0.0%|
[proxz](#proxz)|776|776|67|8.6%|0.0%|
[malc0de](#malc0de)|379|379|67|17.6%|0.0%|
[proxyrss](#proxyrss)|1553|1553|57|3.6%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2376|2376|52|2.1%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|51|7.5%|0.0%|
[sorbs_web](#sorbs_web)|785|787|50|6.3%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|309|309|41|13.2%|0.0%|
[php_dictionary](#php_dictionary)|508|508|29|5.7%|0.0%|
[php_spammers](#php_spammers)|461|461|26|5.6%|0.0%|
[sslbl](#sslbl)|365|365|23|6.3%|0.0%|
[php_harvesters](#php_harvesters)|298|298|17|5.7%|0.0%|
[php_commenters](#php_commenters)|301|301|17|5.6%|0.0%|
[openbl_1d](#openbl_1d)|161|161|16|9.9%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|176|176|15|8.5%|0.0%|
[zeus](#zeus)|231|231|14|6.0%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|96|96|12|12.5%|0.0%|
[feodo](#feodo)|94|94|10|10.6%|0.0%|
[zeus_badips](#zeus_badips)|202|202|9|4.4%|0.0%|
[virbl](#virbl)|10|10|1|10.0%|0.0%|
[sorbs_socks](#sorbs_socks)|31|31|1|3.2%|0.0%|
[sorbs_misc](#sorbs_misc)|31|31|1|3.2%|0.0%|
[sorbs_http](#sorbs_http)|31|31|1|3.2%|0.0%|

## ib_bluetack_proxies

[iBlocklist.com](https://www.iblocklist.com/) free version of [BlueTack.co.uk](http://www.bluetack.co.uk/) Open Proxies IPs list (without TOR)

Source is downloaded from [this link](http://list.iblocklist.com/?list=xoebmbyexwuiogmbyprb&fileformat=p2p&archiveformat=gz).

The last time downloaded was found to be dated: Fri Jun  5 05:10:10 UTC 2015.

The ipset `ib_bluetack_proxies` has **673** entries, **673** unique IPs.

The following table shows the overlaps of `ib_bluetack_proxies` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ib_bluetack_proxies`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ib_bluetack_proxies`.
- ` this % ` is the percentage **of this ipset (`ib_bluetack_proxies`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|58|0.0%|8.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|51|0.0%|7.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|28|0.0%|4.1%|
[stopforumspam_30d](#stopforumspam_30d)|93498|93498|22|0.0%|3.2%|
[xroxy](#xroxy)|2079|2079|13|0.6%|1.9%|
[stopforumspam_7d](#stopforumspam_7d)|29882|29882|12|0.0%|1.7%|
[ri_web_proxies](#ri_web_proxies)|6346|6346|12|0.1%|1.7%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|11|0.0%|1.6%|
[proxyrss](#proxyrss)|1553|1553|9|0.5%|1.3%|
[ri_connect_proxies](#ri_connect_proxies)|2376|2376|6|0.2%|0.8%|
[blocklist_de](#blocklist_de)|31150|31150|6|0.0%|0.8%|
[stopforumspam_1d](#stopforumspam_1d)|7188|7188|5|0.0%|0.7%|
[proxz](#proxz)|776|776|5|0.6%|0.7%|
[blocklist_de_bots](#blocklist_de_bots)|3243|3243|4|0.1%|0.5%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|2|0.0%|0.2%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2|0.0%|0.2%|
[et_block](#et_block)|1016|18338655|2|0.0%|0.2%|
[blocklist_de_mail](#blocklist_de_mail)|16101|16101|2|0.0%|0.2%|
[sorbs_spam](#sorbs_spam)|28347|29370|1|0.0%|0.1%|
[sorbs_recent_spam](#sorbs_recent_spam)|23675|24482|1|0.0%|0.1%|
[sorbs_new_spam](#sorbs_new_spam)|23675|24482|1|0.0%|0.1%|
[snort_ipfilter](#snort_ipfilter)|9882|9882|1|0.0%|0.1%|
[php_dictionary](#php_dictionary)|508|508|1|0.1%|0.1%|
[nixspam](#nixspam)|23361|23361|1|0.0%|0.1%|
[alienvault_reputation](#alienvault_reputation)|180239|180239|1|0.0%|0.1%|

## ib_bluetack_spyware

[iBlocklist.com](https://www.iblocklist.com/) free version of [BlueTack.co.uk](http://www.bluetack.co.uk/) known malicious SPYWARE and ADWARE IP Address ranges

Source is downloaded from [this link](http://list.iblocklist.com/?list=llvtlsjyoyiczbkjsxpf&fileformat=p2p&archiveformat=gz).

The last time downloaded was found to be dated: Fri Jun  5 04:40:02 UTC 2015.

The ipset `ib_bluetack_spyware` has **3274** entries, **339192** unique IPs.

The following table shows the overlaps of `ib_bluetack_spyware` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ib_bluetack_spyware`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ib_bluetack_spyware`.
- ` this % ` is the percentage **of this ipset (`ib_bluetack_spyware`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|13248|0.0%|3.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|9231|0.0%|2.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|7733|0.0%|2.2%|
[et_block](#et_block)|1016|18338655|1043|0.0%|0.3%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|1037|0.0%|0.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1036|0.0%|0.3%|
[fullbogons](#fullbogons)|3715|670310296|890|0.0%|0.2%|
[alienvault_reputation](#alienvault_reputation)|180239|180239|287|0.1%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|93498|93498|47|0.0%|0.0%|
[sorbs_spam](#sorbs_spam)|28347|29370|28|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|23675|24482|27|0.1%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|23675|24482|27|0.1%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|27|2.0%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29882|29882|24|0.0%|0.0%|
[dm_tor](#dm_tor)|6554|6554|22|0.3%|0.0%|
[bm_tor](#bm_tor)|6548|6548|22|0.3%|0.0%|
[et_tor](#et_tor)|6610|6610|21|0.3%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|19|1.3%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9882|9882|13|0.1%|0.0%|
[blocklist_de](#blocklist_de)|31150|31150|11|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7188|7188|10|0.1%|0.0%|
[nixspam](#nixspam)|23361|23361|7|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|6346|6346|5|0.0%|0.0%|
[openbl_60d](#openbl_60d)|7689|7689|5|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|5|1.3%|0.0%|
[voipbl](#voipbl)|10426|10837|4|0.0%|0.0%|
[openbl_30d](#openbl_30d)|3256|3256|4|0.1%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|4|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|16101|16101|4|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3243|3243|4|0.1%|0.0%|
[malc0de](#malc0de)|379|379|3|0.7%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|309|309|3|0.9%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13701|13701|3|0.0%|0.0%|
[palevo](#palevo)|12|12|2|16.6%|0.0%|
[et_compromised](#et_compromised)|2086|2086|2|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2007|2007|2|0.0%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|96|96|2|2.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2409|2409|2|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2348|2348|2|0.0%|0.0%|
[zeus_badips](#zeus_badips)|202|202|1|0.4%|0.0%|
[zeus](#zeus)|231|231|1|0.4%|0.0%|
[xroxy](#xroxy)|2079|2079|1|0.0%|0.0%|
[sslbl](#sslbl)|365|365|1|0.2%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|486400|1|0.0%|0.0%|
[shunlist](#shunlist)|1261|1261|1|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2376|2376|1|0.0%|0.0%|
[php_harvesters](#php_harvesters)|298|298|1|0.3%|0.0%|
[php_dictionary](#php_dictionary)|508|508|1|0.1%|0.0%|
[openbl_7d](#openbl_7d)|910|910|1|0.1%|0.0%|
[feodo](#feodo)|94|94|1|1.0%|0.0%|
[ciarmy](#ciarmy)|396|396|1|0.2%|0.0%|
[bogons](#bogons)|13|592708608|1|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|8193|8193|1|0.0%|0.0%|

## ib_bluetack_webexploit

[iBlocklist.com](https://www.iblocklist.com/) free version of [BlueTack.co.uk](http://www.bluetack.co.uk/) web server hack and exploit attempts

Source is downloaded from [this link](http://list.iblocklist.com/?list=ghlzqtqxnzctvvajwwag&fileformat=p2p&archiveformat=gz).

The last time downloaded was found to be dated: Fri Jun  5 04:40:03 UTC 2015.

The ipset `ib_bluetack_webexploit` has **1460** entries, **1460** unique IPs.

The following table shows the overlaps of `ib_bluetack_webexploit` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ib_bluetack_webexploit`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ib_bluetack_webexploit`.
- ` this % ` is the percentage **of this ipset (`ib_bluetack_webexploit`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|110|0.0%|7.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|97|0.0%|6.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|45|0.0%|3.0%|
[fullbogons](#fullbogons)|3715|670310296|33|0.0%|2.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|19|0.0%|1.3%|
[alienvault_reputation](#alienvault_reputation)|180239|180239|8|0.0%|0.5%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|7|0.0%|0.4%|
[et_block](#et_block)|1016|18338655|7|0.0%|0.4%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|6|0.0%|0.4%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|3|0.2%|0.2%|
[blocklist_de](#blocklist_de)|31150|31150|3|0.0%|0.2%|
[stopforumspam_30d](#stopforumspam_30d)|93498|93498|2|0.0%|0.1%|
[stopforumspam_1d](#stopforumspam_1d)|7188|7188|2|0.0%|0.1%|
[openbl_60d](#openbl_60d)|7689|7689|2|0.0%|0.1%|
[openbl_30d](#openbl_30d)|3256|3256|2|0.0%|0.1%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|2|0.2%|0.1%|
[blocklist_de_strongips](#blocklist_de_strongips)|176|176|2|1.1%|0.1%|
[blocklist_de_bots](#blocklist_de_bots)|3243|3243|2|0.0%|0.1%|
[stopforumspam_7d](#stopforumspam_7d)|29882|29882|1|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9882|9882|1|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|6346|6346|1|0.0%|0.0%|
[openbl_7d](#openbl_7d)|910|910|1|0.1%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1|0.0%|0.0%|
[et_botcc](#et_botcc)|509|509|1|0.1%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|8193|8193|1|0.0%|0.0%|

## malc0de

[Malc0de.com](http://malc0de.com) malicious IPs of the last 30 days

Source is downloaded from [this link](http://malc0de.com/bl/IP_Blacklist.txt).

The last time downloaded was found to be dated: Thu Jun  4 13:17:02 UTC 2015.

The ipset `malc0de` has **379** entries, **379** unique IPs.

The following table shows the overlaps of `malc0de` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `malc0de`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `malc0de`.
- ` this % ` is the percentage **of this ipset (`malc0de`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|67|0.0%|17.6%|
[cleanmx_viruses](#cleanmx_viruses)|309|309|29|9.3%|7.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|23|0.0%|6.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|12|0.0%|3.1%|
[alienvault_reputation](#alienvault_reputation)|180239|180239|11|0.0%|2.9%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|4|0.0%|1.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|4|0.3%|1.0%|
[et_block](#et_block)|1016|18338655|4|0.0%|1.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|3|0.0%|0.7%|
[dshield](#dshield)|20|5120|2|0.0%|0.5%|
[spamhaus_edrop](#spamhaus_edrop)|55|486400|1|0.0%|0.2%|
[snort_ipfilter](#snort_ipfilter)|9882|9882|1|0.0%|0.2%|

## malwaredomainlist

[malwaredomainlist.com](http://www.malwaredomainlist.com) list of malware active ip addresses

Source is downloaded from [this link](http://www.malwaredomainlist.com/hostslist/ip.txt).

The last time downloaded was found to be dated: Thu Jun  4 07:14:07 UTC 2015.

The ipset `malwaredomainlist` has **1288** entries, **1288** unique IPs.

The following table shows the overlaps of `malwaredomainlist` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `malwaredomainlist`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `malwaredomainlist`.
- ` this % ` is the percentage **of this ipset (`malwaredomainlist`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|147|0.0%|11.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|66|0.0%|5.1%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|29|0.0%|2.2%|
[snort_ipfilter](#snort_ipfilter)|9882|9882|29|0.2%|2.2%|
[et_block](#et_block)|1016|18338655|29|0.0%|2.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|27|0.0%|2.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|27|0.0%|2.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|26|0.0%|2.0%|
[fullbogons](#fullbogons)|3715|670310296|9|0.0%|0.6%|
[alienvault_reputation](#alienvault_reputation)|180239|180239|6|0.0%|0.4%|
[stopforumspam_30d](#stopforumspam_30d)|93498|93498|4|0.0%|0.3%|
[malc0de](#malc0de)|379|379|4|1.0%|0.3%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|3|0.2%|0.2%|
[cleanmx_viruses](#cleanmx_viruses)|309|309|3|0.9%|0.2%|
[stopforumspam_7d](#stopforumspam_7d)|29882|29882|2|0.0%|0.1%|
[sorbs_spam](#sorbs_spam)|28347|29370|1|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|23675|24482|1|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|23675|24482|1|0.0%|0.0%|
[et_botcc](#et_botcc)|509|509|1|0.1%|0.0%|

## maxmind_proxy_fraud

[MaxMind.com](https://www.maxmind.com/en/anonymous-proxy-fraudulent-ip-address-list) list of anonymous proxy fraudelent IP addresses.

Source is downloaded from [this link](https://www.maxmind.com/en/anonymous-proxy-fraudulent-ip-address-list).

The last time downloaded was found to be dated: Fri Jun  5 09:54:14 UTC 2015.

The ipset `maxmind_proxy_fraud` has **372** entries, **372** unique IPs.

The following table shows the overlaps of `maxmind_proxy_fraud` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `maxmind_proxy_fraud`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `maxmind_proxy_fraud`.
- ` this % ` is the percentage **of this ipset (`maxmind_proxy_fraud`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_30d](#stopforumspam_30d)|93498|93498|233|0.2%|62.6%|
[stopforumspam_7d](#stopforumspam_7d)|29882|29882|190|0.6%|51.0%|
[snort_ipfilter](#snort_ipfilter)|9882|9882|179|1.8%|48.1%|
[et_tor](#et_tor)|6610|6610|172|2.6%|46.2%|
[dm_tor](#dm_tor)|6554|6554|167|2.5%|44.8%|
[bm_tor](#bm_tor)|6548|6548|167|2.5%|44.8%|
[stopforumspam_1d](#stopforumspam_1d)|7188|7188|154|2.1%|41.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|125|0.0%|33.6%|
[php_commenters](#php_commenters)|301|301|31|10.2%|8.3%|
[alienvault_reputation](#alienvault_reputation)|180239|180239|26|0.0%|6.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|21|0.0%|5.6%|
[openbl_60d](#openbl_60d)|7689|7689|18|0.2%|4.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|17|0.0%|4.5%|
[php_harvesters](#php_harvesters)|298|298|6|2.0%|1.6%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|5|0.0%|1.3%|
[ri_web_proxies](#ri_web_proxies)|6346|6346|4|0.0%|1.0%|
[php_spammers](#php_spammers)|461|461|4|0.8%|1.0%|
[php_dictionary](#php_dictionary)|508|508|4|0.7%|1.0%|
[et_block](#et_block)|1016|18338655|4|0.0%|1.0%|
[blocklist_de](#blocklist_de)|31150|31150|3|0.0%|0.8%|
[shunlist](#shunlist)|1261|1261|2|0.1%|0.5%|
[blocklist_de_apache](#blocklist_de_apache)|13701|13701|2|0.0%|0.5%|
[xroxy](#xroxy)|2079|2079|1|0.0%|0.2%|
[voipbl](#voipbl)|10426|10837|1|0.0%|0.2%|
[ri_connect_proxies](#ri_connect_proxies)|2376|2376|1|0.0%|0.2%|
[dshield](#dshield)|20|5120|1|0.0%|0.2%|
[blocklist_de_ssh](#blocklist_de_ssh)|8193|8193|1|0.0%|0.2%|
[blocklist_de_mail](#blocklist_de_mail)|16101|16101|1|0.0%|0.2%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2348|2348|1|0.0%|0.2%|

## nixspam

[NiX Spam](http://www.heise.de/ix/NiX-Spam-DNSBL-and-blacklist-for-download-499637.html) IP addresses that sent spam in the last hour - automatically generated entries without distinguishing open proxies from relays, dialup gateways, and so on. All IPs are removed after 12 hours if there is no spam from there.

Source is downloaded from [this link](http://www.dnsbl.manitu.net/download/nixspam-ip.dump.gz).

The last time downloaded was found to be dated: Fri Jun  5 10:30:02 UTC 2015.

The ipset `nixspam` has **23361** entries, **23361** unique IPs.

The following table shows the overlaps of `nixspam` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `nixspam`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `nixspam`.
- ` this % ` is the percentage **of this ipset (`nixspam`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[sorbs_spam](#sorbs_spam)|28347|29370|4492|15.2%|19.2%|
[sorbs_recent_spam](#sorbs_recent_spam)|23675|24482|4347|17.7%|18.6%|
[sorbs_new_spam](#sorbs_new_spam)|23675|24482|4347|17.7%|18.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|1642|0.0%|7.0%|
[blocklist_de](#blocklist_de)|31150|31150|766|2.4%|3.2%|
[blocklist_de_mail](#blocklist_de_mail)|16101|16101|674|4.1%|2.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|582|0.0%|2.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|383|0.0%|1.6%|
[stopforumspam_30d](#stopforumspam_30d)|93498|93498|282|0.3%|1.2%|
[et_block](#et_block)|1016|18338655|200|0.0%|0.8%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|199|0.0%|0.8%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|197|0.0%|0.8%|
[snort_ipfilter](#snort_ipfilter)|9882|9882|179|1.8%|0.7%|
[stopforumspam_7d](#stopforumspam_7d)|29882|29882|165|0.5%|0.7%|
[sorbs_web](#sorbs_web)|785|787|154|19.5%|0.6%|
[ri_web_proxies](#ri_web_proxies)|6346|6346|99|1.5%|0.4%|
[php_dictionary](#php_dictionary)|508|508|97|19.0%|0.4%|
[xroxy](#xroxy)|2079|2079|75|3.6%|0.3%|
[stopforumspam_1d](#stopforumspam_1d)|7188|7188|68|0.9%|0.2%|
[php_spammers](#php_spammers)|461|461|65|14.0%|0.2%|
[blocklist_de_bots](#blocklist_de_bots)|3243|3243|41|1.2%|0.1%|
[proxz](#proxz)|776|776|40|5.1%|0.1%|
[alienvault_reputation](#alienvault_reputation)|180239|180239|40|0.0%|0.1%|
[blocklist_de_imap](#blocklist_de_imap)|2409|2409|23|0.9%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2348|2348|18|0.7%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13701|13701|18|0.1%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2376|2376|17|0.7%|0.0%|
[proxyrss](#proxyrss)|1553|1553|17|1.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|915|915|17|1.8%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|10|0.0%|0.0%|
[php_commenters](#php_commenters)|301|301|8|2.6%|0.0%|
[openbl_60d](#openbl_60d)|7689|7689|8|0.1%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|8193|8193|8|0.0%|0.0%|
[php_harvesters](#php_harvesters)|298|298|7|2.3%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|7|0.0%|0.0%|
[sorbs_socks](#sorbs_socks)|31|31|6|19.3%|0.0%|
[sorbs_misc](#sorbs_misc)|31|31|6|19.3%|0.0%|
[sorbs_http](#sorbs_http)|31|31|6|19.3%|0.0%|
[openbl_30d](#openbl_30d)|3256|3256|3|0.0%|0.0%|
[openbl_7d](#openbl_7d)|910|910|2|0.2%|0.0%|
[et_tor](#et_tor)|6610|6610|2|0.0%|0.0%|
[dm_tor](#dm_tor)|6554|6554|2|0.0%|0.0%|
[bm_tor](#bm_tor)|6548|6548|2|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|176|176|2|1.1%|0.0%|
[zeus_badips](#zeus_badips)|202|202|1|0.4%|0.0%|
[zeus](#zeus)|231|231|1|0.4%|0.0%|
[shunlist](#shunlist)|1261|1261|1|0.0%|0.0%|
[openbl_1d](#openbl_1d)|161|161|1|0.6%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|1|0.1%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|309|309|1|0.3%|0.0%|

## openbl_1d

[OpenBL.org](http://www.openbl.org/) last 24 hours IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.

Source is downloaded from [this link](http://www.openbl.org/lists/base_1days.txt).

The last time downloaded was found to be dated: Fri Jun  5 10:32:00 UTC 2015.

The ipset `openbl_1d` has **161** entries, **161** unique IPs.

The following table shows the overlaps of `openbl_1d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl_1d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl_1d`.
- ` this % ` is the percentage **of this ipset (`openbl_1d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[openbl_60d](#openbl_60d)|7689|7689|158|2.0%|98.1%|
[openbl_30d](#openbl_30d)|3256|3256|158|4.8%|98.1%|
[alienvault_reputation](#alienvault_reputation)|180239|180239|157|0.0%|97.5%|
[openbl_7d](#openbl_7d)|910|910|156|17.1%|96.8%|
[blocklist_de](#blocklist_de)|31150|31150|135|0.4%|83.8%|
[blocklist_de_ssh](#blocklist_de_ssh)|8193|8193|132|1.6%|81.9%|
[bruteforceblocker](#bruteforceblocker)|2007|2007|94|4.6%|58.3%|
[et_compromised](#et_compromised)|2086|2086|88|4.2%|54.6%|
[shunlist](#shunlist)|1261|1261|75|5.9%|46.5%|
[blocklist_de_strongips](#blocklist_de_strongips)|176|176|19|10.7%|11.8%|
[dshield](#dshield)|20|5120|17|0.3%|10.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|16|0.0%|9.9%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|10|0.0%|6.2%|
[et_block](#et_block)|1016|18338655|10|0.0%|6.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|7|0.0%|4.3%|
[blocklist_de_mail](#blocklist_de_mail)|16101|16101|4|0.0%|2.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|3|0.0%|1.8%|
[blocklist_de_imap](#blocklist_de_imap)|2409|2409|2|0.0%|1.2%|
[nixspam](#nixspam)|23361|23361|1|0.0%|0.6%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.6%|

## openbl_30d

[OpenBL.org](http://www.openbl.org/) last 30 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.

Source is downloaded from [this link](http://www.openbl.org/lists/base_30days.txt).

The last time downloaded was found to be dated: Fri Jun  5 07:42:00 UTC 2015.

The ipset `openbl_30d` has **3256** entries, **3256** unique IPs.

The following table shows the overlaps of `openbl_30d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl_30d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl_30d`.
- ` this % ` is the percentage **of this ipset (`openbl_30d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[openbl_60d](#openbl_60d)|7689|7689|3256|42.3%|100.0%|
[alienvault_reputation](#alienvault_reputation)|180239|180239|3241|1.7%|99.5%|
[et_compromised](#et_compromised)|2086|2086|1191|57.0%|36.5%|
[bruteforceblocker](#bruteforceblocker)|2007|2007|1144|57.0%|35.1%|
[openbl_7d](#openbl_7d)|910|910|910|100.0%|27.9%|
[blocklist_de](#blocklist_de)|31150|31150|826|2.6%|25.3%|
[blocklist_de_ssh](#blocklist_de_ssh)|8193|8193|781|9.5%|23.9%|
[shunlist](#shunlist)|1261|1261|569|45.1%|17.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|310|0.0%|9.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|169|0.0%|5.1%|
[et_block](#et_block)|1016|18338655|165|0.0%|5.0%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|159|0.0%|4.8%|
[openbl_1d](#openbl_1d)|161|161|158|98.1%|4.8%|
[dshield](#dshield)|20|5120|119|2.3%|3.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|71|0.0%|2.1%|
[blocklist_de_mail](#blocklist_de_mail)|16101|16101|39|0.2%|1.1%|
[blocklist_de_imap](#blocklist_de_imap)|2409|2409|32|1.3%|0.9%|
[blocklist_de_strongips](#blocklist_de_strongips)|176|176|24|13.6%|0.7%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|13|0.0%|0.3%|
[snort_ipfilter](#snort_ipfilter)|9882|9882|6|0.0%|0.1%|
[stopforumspam_30d](#stopforumspam_30d)|93498|93498|4|0.0%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|4|0.0%|0.1%|
[voipbl](#voipbl)|10426|10837|3|0.0%|0.0%|
[nixspam](#nixspam)|23361|23361|3|0.0%|0.0%|
[zeus](#zeus)|231|231|2|0.8%|0.0%|
[sorbs_spam](#sorbs_spam)|28347|29370|2|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|23675|24482|2|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|23675|24482|2|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.0%|
[zeus_badips](#zeus_badips)|202|202|1|0.4%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29882|29882|1|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7188|7188|1|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|486400|1|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|915|915|1|0.1%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3243|3243|1|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13701|13701|1|0.0%|0.0%|

## openbl_60d

[OpenBL.org](http://www.openbl.org/) last 60 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.

Source is downloaded from [this link](http://www.openbl.org/lists/base_60days.txt).

The last time downloaded was found to be dated: Fri Jun  5 07:42:00 UTC 2015.

The ipset `openbl_60d` has **7689** entries, **7689** unique IPs.

The following table shows the overlaps of `openbl_60d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl_60d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl_60d`.
- ` this % ` is the percentage **of this ipset (`openbl_60d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[alienvault_reputation](#alienvault_reputation)|180239|180239|7668|4.2%|99.7%|
[openbl_30d](#openbl_30d)|3256|3256|3256|100.0%|42.3%|
[blocklist_de](#blocklist_de)|31150|31150|1515|4.8%|19.7%|
[blocklist_de_ssh](#blocklist_de_ssh)|8193|8193|1454|17.7%|18.9%|
[et_compromised](#et_compromised)|2086|2086|1265|60.6%|16.4%|
[bruteforceblocker](#bruteforceblocker)|2007|2007|1198|59.6%|15.5%|
[openbl_7d](#openbl_7d)|910|910|910|100.0%|11.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|747|0.0%|9.7%|
[shunlist](#shunlist)|1261|1261|583|46.2%|7.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|340|0.0%|4.4%|
[et_block](#et_block)|1016|18338655|245|0.0%|3.1%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|239|0.0%|3.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|172|0.0%|2.2%|
[openbl_1d](#openbl_1d)|161|161|158|98.1%|2.0%|
[dshield](#dshield)|20|5120|133|2.5%|1.7%|
[stopforumspam_30d](#stopforumspam_30d)|93498|93498|57|0.0%|0.7%|
[blocklist_de_mail](#blocklist_de_mail)|16101|16101|46|0.2%|0.5%|
[blocklist_de_imap](#blocklist_de_imap)|2409|2409|39|1.6%|0.5%|
[snort_ipfilter](#snort_ipfilter)|9882|9882|29|0.2%|0.3%|
[blocklist_de_strongips](#blocklist_de_strongips)|176|176|26|14.7%|0.3%|
[stopforumspam_7d](#stopforumspam_7d)|29882|29882|25|0.0%|0.3%|
[stopforumspam_1d](#stopforumspam_1d)|7188|7188|21|0.2%|0.2%|
[et_tor](#et_tor)|6610|6610|21|0.3%|0.2%|
[dm_tor](#dm_tor)|6554|6554|20|0.3%|0.2%|
[bm_tor](#bm_tor)|6548|6548|20|0.3%|0.2%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|18|4.8%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|18|0.0%|0.2%|
[sorbs_spam](#sorbs_spam)|28347|29370|15|0.0%|0.1%|
[sorbs_recent_spam](#sorbs_recent_spam)|23675|24482|14|0.0%|0.1%|
[sorbs_new_spam](#sorbs_new_spam)|23675|24482|14|0.0%|0.1%|
[php_commenters](#php_commenters)|301|301|9|2.9%|0.1%|
[voipbl](#voipbl)|10426|10837|8|0.0%|0.1%|
[nixspam](#nixspam)|23361|23361|8|0.0%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|5|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|915|915|3|0.3%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3243|3243|3|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13701|13701|3|0.0%|0.0%|
[zeus](#zeus)|231|231|2|0.8%|0.0%|
[php_harvesters](#php_harvesters)|298|298|2|0.6%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.0%|
[zeus_badips](#zeus_badips)|202|202|1|0.4%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|486400|1|0.0%|0.0%|

## openbl_7d

[OpenBL.org](http://www.openbl.org/) last 7 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.

Source is downloaded from [this link](http://www.openbl.org/lists/base_7days.txt).

The last time downloaded was found to be dated: Fri Jun  5 07:42:00 UTC 2015.

The ipset `openbl_7d` has **910** entries, **910** unique IPs.

The following table shows the overlaps of `openbl_7d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl_7d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl_7d`.
- ` this % ` is the percentage **of this ipset (`openbl_7d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[openbl_60d](#openbl_60d)|7689|7689|910|11.8%|100.0%|
[openbl_30d](#openbl_30d)|3256|3256|910|27.9%|100.0%|
[alienvault_reputation](#alienvault_reputation)|180239|180239|904|0.5%|99.3%|
[blocklist_de](#blocklist_de)|31150|31150|541|1.7%|59.4%|
[blocklist_de_ssh](#blocklist_de_ssh)|8193|8193|523|6.3%|57.4%|
[bruteforceblocker](#bruteforceblocker)|2007|2007|405|20.1%|44.5%|
[et_compromised](#et_compromised)|2086|2086|402|19.2%|44.1%|
[shunlist](#shunlist)|1261|1261|296|23.4%|32.5%|
[openbl_1d](#openbl_1d)|161|161|156|96.8%|17.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|114|0.0%|12.5%|
[et_block](#et_block)|1016|18338655|52|0.0%|5.7%|
[dshield](#dshield)|20|5120|51|0.9%|5.6%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|50|0.0%|5.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|49|0.0%|5.3%|
[blocklist_de_strongips](#blocklist_de_strongips)|176|176|23|13.0%|2.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|20|0.0%|2.1%|
[blocklist_de_mail](#blocklist_de_mail)|16101|16101|15|0.0%|1.6%|
[blocklist_de_imap](#blocklist_de_imap)|2409|2409|12|0.4%|1.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|6|0.0%|0.6%|
[stopforumspam_30d](#stopforumspam_30d)|93498|93498|3|0.0%|0.3%|
[snort_ipfilter](#snort_ipfilter)|9882|9882|2|0.0%|0.2%|
[nixspam](#nixspam)|23361|23361|2|0.0%|0.2%|
[voipbl](#voipbl)|10426|10837|1|0.0%|0.1%|
[sorbs_spam](#sorbs_spam)|28347|29370|1|0.0%|0.1%|
[sorbs_recent_spam](#sorbs_recent_spam)|23675|24482|1|0.0%|0.1%|
[sorbs_new_spam](#sorbs_new_spam)|23675|24482|1|0.0%|0.1%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.1%|

## palevo

[Abuse.ch Palevo tracker](https://palevotracker.abuse.ch) worm includes IPs which are being used as botnet C&C for the Palevo crimeware - **excellent list**

Source is downloaded from [this link](https://palevotracker.abuse.ch/blocklists.php?download=ipblocklist).

The last time downloaded was found to be dated: Fri Jun  5 10:18:17 UTC 2015.

The ipset `palevo` has **12** entries, **12** unique IPs.

The following table shows the overlaps of `palevo` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `palevo`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `palevo`.
- ` this % ` is the percentage **of this ipset (`palevo`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[et_block](#et_block)|1016|18338655|11|0.0%|91.6%|
[snort_ipfilter](#snort_ipfilter)|9882|9882|10|0.1%|83.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|3|0.0%|25.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|2|0.0%|16.6%|

## php_commenters

[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) comment spammers (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=c&rss=1).

The last time downloaded was found to be dated: Fri Jun  5 10:09:21 UTC 2015.

The ipset `php_commenters` has **301** entries, **301** unique IPs.

The following table shows the overlaps of `php_commenters` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `php_commenters`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `php_commenters`.
- ` this % ` is the percentage **of this ipset (`php_commenters`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_30d](#stopforumspam_30d)|93498|93498|219|0.2%|72.7%|
[stopforumspam_7d](#stopforumspam_7d)|29882|29882|157|0.5%|52.1%|
[stopforumspam_1d](#stopforumspam_1d)|7188|7188|121|1.6%|40.1%|
[blocklist_de](#blocklist_de)|31150|31150|72|0.2%|23.9%|
[blocklist_de_bots](#blocklist_de_bots)|3243|3243|58|1.7%|19.2%|
[snort_ipfilter](#snort_ipfilter)|9882|9882|41|0.4%|13.6%|
[php_spammers](#php_spammers)|461|461|33|7.1%|10.9%|
[et_tor](#et_tor)|6610|6610|33|0.4%|10.9%|
[dm_tor](#dm_tor)|6554|6554|32|0.4%|10.6%|
[bm_tor](#bm_tor)|6548|6548|32|0.4%|10.6%|
[blocklist_de_strongips](#blocklist_de_strongips)|176|176|32|18.1%|10.6%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|31|8.3%|10.2%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|26|0.0%|8.6%|
[et_block](#et_block)|1016|18338655|26|0.0%|8.6%|
[blocklist_de_apache](#blocklist_de_apache)|13701|13701|24|0.1%|7.9%|
[php_dictionary](#php_dictionary)|508|508|23|4.5%|7.6%|
[blocklist_de_mail](#blocklist_de_mail)|16101|16101|20|0.1%|6.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|17|0.0%|5.6%|
[ri_web_proxies](#ri_web_proxies)|6346|6346|15|0.2%|4.9%|
[alienvault_reputation](#alienvault_reputation)|180239|180239|14|0.0%|4.6%|
[sorbs_spam](#sorbs_spam)|28347|29370|12|0.0%|3.9%|
[sorbs_recent_spam](#sorbs_recent_spam)|23675|24482|12|0.0%|3.9%|
[sorbs_new_spam](#sorbs_new_spam)|23675|24482|12|0.0%|3.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|11|0.0%|3.6%|
[php_harvesters](#php_harvesters)|298|298|9|3.0%|2.9%|
[openbl_60d](#openbl_60d)|7689|7689|9|0.1%|2.9%|
[nixspam](#nixspam)|23361|23361|8|0.0%|2.6%|
[spamhaus_edrop](#spamhaus_edrop)|55|486400|7|0.0%|2.3%|
[xroxy](#xroxy)|2079|2079|6|0.2%|1.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|6|0.0%|1.9%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2348|2348|6|0.2%|1.9%|
[proxz](#proxz)|776|776|4|0.5%|1.3%|
[sorbs_web](#sorbs_web)|785|787|2|0.2%|0.6%|
[ri_connect_proxies](#ri_connect_proxies)|2376|2376|2|0.0%|0.6%|
[proxyrss](#proxyrss)|1553|1553|2|0.1%|0.6%|
[zeus_badips](#zeus_badips)|202|202|1|0.4%|0.3%|
[zeus](#zeus)|231|231|1|0.4%|0.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.3%|
[dshield](#dshield)|20|5120|1|0.0%|0.3%|

## php_dictionary

[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) directory attackers (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=d&rss=1).

The last time downloaded was found to be dated: Fri Jun  5 10:27:03 UTC 2015.

The ipset `php_dictionary` has **508** entries, **508** unique IPs.

The following table shows the overlaps of `php_dictionary` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `php_dictionary`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `php_dictionary`.
- ` this % ` is the percentage **of this ipset (`php_dictionary`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[sorbs_spam](#sorbs_spam)|28347|29370|135|0.4%|26.5%|
[sorbs_recent_spam](#sorbs_recent_spam)|23675|24482|129|0.5%|25.3%|
[sorbs_new_spam](#sorbs_new_spam)|23675|24482|129|0.5%|25.3%|
[php_spammers](#php_spammers)|461|461|125|27.1%|24.6%|
[stopforumspam_30d](#stopforumspam_30d)|93498|93498|98|0.1%|19.2%|
[nixspam](#nixspam)|23361|23361|97|0.4%|19.0%|
[blocklist_de](#blocklist_de)|31150|31150|84|0.2%|16.5%|
[snort_ipfilter](#snort_ipfilter)|9882|9882|76|0.7%|14.9%|
[blocklist_de_mail](#blocklist_de_mail)|16101|16101|67|0.4%|13.1%|
[stopforumspam_7d](#stopforumspam_7d)|29882|29882|66|0.2%|12.9%|
[ri_web_proxies](#ri_web_proxies)|6346|6346|40|0.6%|7.8%|
[sorbs_web](#sorbs_web)|785|787|38|4.8%|7.4%|
[xroxy](#xroxy)|2079|2079|31|1.4%|6.1%|
[stopforumspam_1d](#stopforumspam_1d)|7188|7188|30|0.4%|5.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|29|0.0%|5.7%|
[php_commenters](#php_commenters)|301|301|23|7.6%|4.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|13|0.0%|2.5%|
[proxz](#proxz)|776|776|12|1.5%|2.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|11|0.0%|2.1%|
[blocklist_de_bots](#blocklist_de_bots)|3243|3243|11|0.3%|2.1%|
[alienvault_reputation](#alienvault_reputation)|180239|180239|8|0.0%|1.5%|
[et_tor](#et_tor)|6610|6610|5|0.0%|0.9%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2348|2348|5|0.2%|0.9%|
[blocklist_de_apache](#blocklist_de_apache)|13701|13701|5|0.0%|0.9%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|4|0.0%|0.7%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|4|1.0%|0.7%|
[et_block](#et_block)|1016|18338655|4|0.0%|0.7%|
[dm_tor](#dm_tor)|6554|6554|4|0.0%|0.7%|
[bm_tor](#bm_tor)|6548|6548|4|0.0%|0.7%|
[ri_connect_proxies](#ri_connect_proxies)|2376|2376|3|0.1%|0.5%|
[blocklist_de_strongips](#blocklist_de_strongips)|176|176|3|1.7%|0.5%|
[proxyrss](#proxyrss)|1553|1553|2|0.1%|0.3%|
[php_harvesters](#php_harvesters)|298|298|2|0.6%|0.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2|0.0%|0.3%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|2|0.0%|0.3%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.1%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|1|0.1%|0.1%|
[blocklist_de_imap](#blocklist_de_imap)|2409|2409|1|0.0%|0.1%|

## php_harvesters

[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) harvesters (IPs that surf the internet looking for email addresses) (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=h&rss=1).

The last time downloaded was found to be dated: Fri Jun  5 10:09:19 UTC 2015.

The ipset `php_harvesters` has **298** entries, **298** unique IPs.

The following table shows the overlaps of `php_harvesters` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `php_harvesters`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `php_harvesters`.
- ` this % ` is the percentage **of this ipset (`php_harvesters`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_30d](#stopforumspam_30d)|93498|93498|67|0.0%|22.4%|
[stopforumspam_7d](#stopforumspam_7d)|29882|29882|52|0.1%|17.4%|
[stopforumspam_1d](#stopforumspam_1d)|7188|7188|35|0.4%|11.7%|
[blocklist_de](#blocklist_de)|31150|31150|31|0.0%|10.4%|
[blocklist_de_bots](#blocklist_de_bots)|3243|3243|22|0.6%|7.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|17|0.0%|5.7%|
[snort_ipfilter](#snort_ipfilter)|9882|9882|10|0.1%|3.3%|
[alienvault_reputation](#alienvault_reputation)|180239|180239|10|0.0%|3.3%|
[php_commenters](#php_commenters)|301|301|9|2.9%|3.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|9|0.0%|3.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|9|0.0%|3.0%|
[sorbs_spam](#sorbs_spam)|28347|29370|8|0.0%|2.6%|
[nixspam](#nixspam)|23361|23361|7|0.0%|2.3%|
[et_tor](#et_tor)|6610|6610|7|0.1%|2.3%|
[dm_tor](#dm_tor)|6554|6554|7|0.1%|2.3%|
[bm_tor](#bm_tor)|6548|6548|7|0.1%|2.3%|
[sorbs_recent_spam](#sorbs_recent_spam)|23675|24482|6|0.0%|2.0%|
[sorbs_new_spam](#sorbs_new_spam)|23675|24482|6|0.0%|2.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|6|1.6%|2.0%|
[blocklist_de_apache](#blocklist_de_apache)|13701|13701|4|0.0%|1.3%|
[blocklist_de_mail](#blocklist_de_mail)|16101|16101|3|0.0%|1.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|915|915|3|0.3%|1.0%|
[xroxy](#xroxy)|2079|2079|2|0.0%|0.6%|
[proxyrss](#proxyrss)|1553|1553|2|0.1%|0.6%|
[php_spammers](#php_spammers)|461|461|2|0.4%|0.6%|
[php_dictionary](#php_dictionary)|508|508|2|0.3%|0.6%|
[openbl_60d](#openbl_60d)|7689|7689|2|0.0%|0.6%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|2|0.0%|0.6%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2348|2348|2|0.0%|0.6%|
[spamhaus_edrop](#spamhaus_edrop)|55|486400|1|0.0%|0.3%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|1|0.0%|0.3%|
[ri_web_proxies](#ri_web_proxies)|6346|6346|1|0.0%|0.3%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.3%|
[fullbogons](#fullbogons)|3715|670310296|1|0.0%|0.3%|
[et_block](#et_block)|1016|18338655|1|0.0%|0.3%|
[dshield](#dshield)|20|5120|1|0.0%|0.3%|
[bogons](#bogons)|13|592708608|1|0.0%|0.3%|
[blocklist_de_strongips](#blocklist_de_strongips)|176|176|1|0.5%|0.3%|

## php_spammers

[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) spam servers (IPs used by spammers to send messages) (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=s&rss=1).

The last time downloaded was found to be dated: Fri Jun  5 10:09:19 UTC 2015.

The ipset `php_spammers` has **461** entries, **461** unique IPs.

The following table shows the overlaps of `php_spammers` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `php_spammers`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `php_spammers`.
- ` this % ` is the percentage **of this ipset (`php_spammers`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[php_dictionary](#php_dictionary)|508|508|125|24.6%|27.1%|
[stopforumspam_30d](#stopforumspam_30d)|93498|93498|102|0.1%|22.1%|
[sorbs_spam](#sorbs_spam)|28347|29370|101|0.3%|21.9%|
[sorbs_recent_spam](#sorbs_recent_spam)|23675|24482|92|0.3%|19.9%|
[sorbs_new_spam](#sorbs_new_spam)|23675|24482|92|0.3%|19.9%|
[blocklist_de](#blocklist_de)|31150|31150|67|0.2%|14.5%|
[nixspam](#nixspam)|23361|23361|65|0.2%|14.0%|
[snort_ipfilter](#snort_ipfilter)|9882|9882|59|0.5%|12.7%|
[stopforumspam_7d](#stopforumspam_7d)|29882|29882|57|0.1%|12.3%|
[blocklist_de_mail](#blocklist_de_mail)|16101|16101|49|0.3%|10.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|34|0.0%|7.3%|
[php_commenters](#php_commenters)|301|301|33|10.9%|7.1%|
[stopforumspam_1d](#stopforumspam_1d)|7188|7188|30|0.4%|6.5%|
[ri_web_proxies](#ri_web_proxies)|6346|6346|27|0.4%|5.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|26|0.0%|5.6%|
[sorbs_web](#sorbs_web)|785|787|25|3.1%|5.4%|
[xroxy](#xroxy)|2079|2079|22|1.0%|4.7%|
[proxz](#proxz)|776|776|11|1.4%|2.3%|
[blocklist_de_bots](#blocklist_de_bots)|3243|3243|11|0.3%|2.3%|
[et_tor](#et_tor)|6610|6610|6|0.0%|1.3%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2348|2348|6|0.2%|1.3%|
[blocklist_de_apache](#blocklist_de_apache)|13701|13701|6|0.0%|1.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|5|0.0%|1.0%|
[dm_tor](#dm_tor)|6554|6554|5|0.0%|1.0%|
[bm_tor](#bm_tor)|6548|6548|5|0.0%|1.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|176|176|5|2.8%|1.0%|
[alienvault_reputation](#alienvault_reputation)|180239|180239|5|0.0%|1.0%|
[proxyrss](#proxyrss)|1553|1553|4|0.2%|0.8%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|4|1.0%|0.8%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|3|0.0%|0.6%|
[ri_connect_proxies](#ri_connect_proxies)|2376|2376|2|0.0%|0.4%|
[php_harvesters](#php_harvesters)|298|298|2|0.6%|0.4%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2|0.0%|0.4%|
[et_block](#et_block)|1016|18338655|2|0.0%|0.4%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1|0.0%|0.2%|
[blocklist_de_ftp](#blocklist_de_ftp)|915|915|1|0.1%|0.2%|

## proxyrss

[proxyrss.com](http://www.proxyrss.com) open proxies syndicated from multiple sources.

Source is downloaded from [this link](http://www.proxyrss.com/proxylists/all.gz).

The last time downloaded was found to be dated: Fri Jun  5 09:11:29 UTC 2015.

The ipset `proxyrss` has **1553** entries, **1553** unique IPs.

The following table shows the overlaps of `proxyrss` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `proxyrss`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `proxyrss`.
- ` this % ` is the percentage **of this ipset (`proxyrss`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_30d](#stopforumspam_30d)|93498|93498|819|0.8%|52.7%|
[ri_web_proxies](#ri_web_proxies)|6346|6346|683|10.7%|43.9%|
[stopforumspam_7d](#stopforumspam_7d)|29882|29882|658|2.2%|42.3%|
[xroxy](#xroxy)|2079|2079|421|20.2%|27.1%|
[stopforumspam_1d](#stopforumspam_1d)|7188|7188|377|5.2%|24.2%|
[ri_connect_proxies](#ri_connect_proxies)|2376|2376|251|10.5%|16.1%|
[blocklist_de_bots](#blocklist_de_bots)|3243|3243|230|7.0%|14.8%|
[blocklist_de](#blocklist_de)|31150|31150|230|0.7%|14.8%|
[proxz](#proxz)|776|776|220|28.3%|14.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|60|0.0%|3.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|57|0.0%|3.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|45|0.0%|2.8%|
[nixspam](#nixspam)|23361|23361|17|0.0%|1.0%|
[sorbs_spam](#sorbs_spam)|28347|29370|9|0.0%|0.5%|
[sorbs_recent_spam](#sorbs_recent_spam)|23675|24482|9|0.0%|0.5%|
[sorbs_new_spam](#sorbs_new_spam)|23675|24482|9|0.0%|0.5%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|9|1.3%|0.5%|
[snort_ipfilter](#snort_ipfilter)|9882|9882|5|0.0%|0.3%|
[blocklist_de_strongips](#blocklist_de_strongips)|176|176|5|2.8%|0.3%|
[php_spammers](#php_spammers)|461|461|4|0.8%|0.2%|
[sorbs_web](#sorbs_web)|785|787|2|0.2%|0.1%|
[php_harvesters](#php_harvesters)|298|298|2|0.6%|0.1%|
[php_dictionary](#php_dictionary)|508|508|2|0.3%|0.1%|
[php_commenters](#php_commenters)|301|301|2|0.6%|0.1%|
[et_compromised](#et_compromised)|2086|2086|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2007|2007|1|0.0%|0.0%|
[alienvault_reputation](#alienvault_reputation)|180239|180239|1|0.0%|0.0%|

## proxz

[proxz.com](http://www.proxz.com) open proxies (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.proxz.com/proxylists.xml).

The last time downloaded was found to be dated: Fri Jun  5 09:11:34 UTC 2015.

The ipset `proxz` has **776** entries, **776** unique IPs.

The following table shows the overlaps of `proxz` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `proxz`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `proxz`.
- ` this % ` is the percentage **of this ipset (`proxz`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_30d](#stopforumspam_30d)|93498|93498|469|0.5%|60.4%|
[stopforumspam_7d](#stopforumspam_7d)|29882|29882|380|1.2%|48.9%|
[ri_web_proxies](#ri_web_proxies)|6346|6346|348|5.4%|44.8%|
[xroxy](#xroxy)|2079|2079|316|15.1%|40.7%|
[proxyrss](#proxyrss)|1553|1553|220|14.1%|28.3%|
[stopforumspam_1d](#stopforumspam_1d)|7188|7188|149|2.0%|19.2%|
[blocklist_de](#blocklist_de)|31150|31150|140|0.4%|18.0%|
[ri_connect_proxies](#ri_connect_proxies)|2376|2376|124|5.2%|15.9%|
[blocklist_de_bots](#blocklist_de_bots)|3243|3243|118|3.6%|15.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|67|0.0%|8.6%|
[nixspam](#nixspam)|23361|23361|40|0.1%|5.1%|
[sorbs_spam](#sorbs_spam)|28347|29370|35|0.1%|4.5%|
[sorbs_recent_spam](#sorbs_recent_spam)|23675|24482|35|0.1%|4.5%|
[sorbs_new_spam](#sorbs_new_spam)|23675|24482|35|0.1%|4.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|32|0.0%|4.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|28|0.0%|3.6%|
[blocklist_de_mail](#blocklist_de_mail)|16101|16101|22|0.1%|2.8%|
[snort_ipfilter](#snort_ipfilter)|9882|9882|20|0.2%|2.5%|
[sorbs_web](#sorbs_web)|785|787|14|1.7%|1.8%|
[php_dictionary](#php_dictionary)|508|508|12|2.3%|1.5%|
[php_spammers](#php_spammers)|461|461|11|2.3%|1.4%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|5|0.7%|0.6%|
[php_commenters](#php_commenters)|301|301|4|1.3%|0.5%|
[blocklist_de_strongips](#blocklist_de_strongips)|176|176|4|2.2%|0.5%|
[alienvault_reputation](#alienvault_reputation)|180239|180239|3|0.0%|0.3%|
[et_compromised](#et_compromised)|2086|2086|2|0.0%|0.2%|
[bruteforceblocker](#bruteforceblocker)|2007|2007|2|0.0%|0.2%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1|0.0%|0.1%|
[et_block](#et_block)|1016|18338655|1|0.0%|0.1%|

## ri_connect_proxies

[rosinstrument.com](http://www.rosinstrument.com) open CONNECT proxies (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://tools.rosinstrument.com/proxy/plab100.xml).

The last time downloaded was found to be dated: Fri Jun  5 04:26:21 UTC 2015.

The ipset `ri_connect_proxies` has **2376** entries, **2376** unique IPs.

The following table shows the overlaps of `ri_connect_proxies` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ri_connect_proxies`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ri_connect_proxies`.
- ` this % ` is the percentage **of this ipset (`ri_connect_proxies`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_30d](#stopforumspam_30d)|93498|93498|1382|1.4%|58.1%|
[ri_web_proxies](#ri_web_proxies)|6346|6346|969|15.2%|40.7%|
[stopforumspam_7d](#stopforumspam_7d)|29882|29882|649|2.1%|27.3%|
[xroxy](#xroxy)|2079|2079|360|17.3%|15.1%|
[proxyrss](#proxyrss)|1553|1553|251|16.1%|10.5%|
[stopforumspam_1d](#stopforumspam_1d)|7188|7188|147|2.0%|6.1%|
[proxz](#proxz)|776|776|124|15.9%|5.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|91|0.0%|3.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|75|0.0%|3.1%|
[blocklist_de](#blocklist_de)|31150|31150|72|0.2%|3.0%|
[blocklist_de_bots](#blocklist_de_bots)|3243|3243|70|2.1%|2.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|52|0.0%|2.1%|
[nixspam](#nixspam)|23361|23361|17|0.0%|0.7%|
[sorbs_spam](#sorbs_spam)|28347|29370|11|0.0%|0.4%|
[sorbs_recent_spam](#sorbs_recent_spam)|23675|24482|10|0.0%|0.4%|
[sorbs_new_spam](#sorbs_new_spam)|23675|24482|10|0.0%|0.4%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|6|0.8%|0.2%|
[snort_ipfilter](#snort_ipfilter)|9882|9882|5|0.0%|0.2%|
[php_dictionary](#php_dictionary)|508|508|3|0.5%|0.1%|
[sorbs_web](#sorbs_web)|785|787|2|0.2%|0.0%|
[php_spammers](#php_spammers)|461|461|2|0.4%|0.0%|
[php_commenters](#php_commenters)|301|301|2|0.6%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|16101|16101|2|0.0%|0.0%|
[alienvault_reputation](#alienvault_reputation)|180239|180239|2|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.0%|
[et_tor](#et_tor)|6610|6610|1|0.0%|0.0%|
[dm_tor](#dm_tor)|6554|6554|1|0.0%|0.0%|
[bm_tor](#bm_tor)|6548|6548|1|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2409|2409|1|0.0%|0.0%|

## ri_web_proxies

[rosinstrument.com](http://www.rosinstrument.com) open HTTP proxies (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://tools.rosinstrument.com/proxy/l100.xml).

The last time downloaded was found to be dated: Fri Jun  5 06:41:48 UTC 2015.

The ipset `ri_web_proxies` has **6346** entries, **6346** unique IPs.

The following table shows the overlaps of `ri_web_proxies` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ri_web_proxies`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ri_web_proxies`.
- ` this % ` is the percentage **of this ipset (`ri_web_proxies`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_30d](#stopforumspam_30d)|93498|93498|3093|3.3%|48.7%|
[stopforumspam_7d](#stopforumspam_7d)|29882|29882|1620|5.4%|25.5%|
[ri_connect_proxies](#ri_connect_proxies)|2376|2376|969|40.7%|15.2%|
[xroxy](#xroxy)|2079|2079|884|42.5%|13.9%|
[proxyrss](#proxyrss)|1553|1553|683|43.9%|10.7%|
[stopforumspam_1d](#stopforumspam_1d)|7188|7188|506|7.0%|7.9%|
[blocklist_de](#blocklist_de)|31150|31150|413|1.3%|6.5%|
[blocklist_de_bots](#blocklist_de_bots)|3243|3243|361|11.1%|5.6%|
[proxz](#proxz)|776|776|348|44.8%|5.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|187|0.0%|2.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|183|0.0%|2.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|133|0.0%|2.0%|
[sorbs_spam](#sorbs_spam)|28347|29370|127|0.4%|2.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|23675|24482|121|0.4%|1.9%|
[sorbs_new_spam](#sorbs_new_spam)|23675|24482|121|0.4%|1.9%|
[nixspam](#nixspam)|23361|23361|99|0.4%|1.5%|
[snort_ipfilter](#snort_ipfilter)|9882|9882|61|0.6%|0.9%|
[blocklist_de_mail](#blocklist_de_mail)|16101|16101|53|0.3%|0.8%|
[php_dictionary](#php_dictionary)|508|508|40|7.8%|0.6%|
[sorbs_web](#sorbs_web)|785|787|31|3.9%|0.4%|
[php_spammers](#php_spammers)|461|461|27|5.8%|0.4%|
[php_commenters](#php_commenters)|301|301|15|4.9%|0.2%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|12|1.7%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|5|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|176|176|5|2.8%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|4|1.0%|0.0%|
[et_tor](#et_tor)|6610|6610|4|0.0%|0.0%|
[dm_tor](#dm_tor)|6554|6554|4|0.0%|0.0%|
[bm_tor](#bm_tor)|6548|6548|4|0.0%|0.0%|
[alienvault_reputation](#alienvault_reputation)|180239|180239|3|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|2|0.0%|0.0%|
[sorbs_socks](#sorbs_socks)|31|31|1|3.2%|0.0%|
[sorbs_misc](#sorbs_misc)|31|31|1|3.2%|0.0%|
[sorbs_http](#sorbs_http)|31|31|1|3.2%|0.0%|
[php_harvesters](#php_harvesters)|298|298|1|0.3%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|
[et_compromised](#et_compromised)|2086|2086|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2007|2007|1|0.0%|0.0%|

## shunlist

[AutoShun.org](http://autoshun.org/) IPs identified as hostile by correlating logs from distributed snort installations running the autoshun plugin

Source is downloaded from [this link](http://www.autoshun.org/files/shunlist.csv).

The last time downloaded was found to be dated: Fri Jun  5 10:30:05 UTC 2015.

The ipset `shunlist` has **1261** entries, **1261** unique IPs.

The following table shows the overlaps of `shunlist` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `shunlist`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `shunlist`.
- ` this % ` is the percentage **of this ipset (`shunlist`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[alienvault_reputation](#alienvault_reputation)|180239|180239|1253|0.6%|99.3%|
[openbl_60d](#openbl_60d)|7689|7689|583|7.5%|46.2%|
[openbl_30d](#openbl_30d)|3256|3256|569|17.4%|45.1%|
[et_compromised](#et_compromised)|2086|2086|486|23.2%|38.5%|
[bruteforceblocker](#bruteforceblocker)|2007|2007|474|23.6%|37.5%|
[blocklist_de](#blocklist_de)|31150|31150|385|1.2%|30.5%|
[blocklist_de_ssh](#blocklist_de_ssh)|8193|8193|347|4.2%|27.5%|
[openbl_7d](#openbl_7d)|910|910|296|32.5%|23.4%|
[dshield](#dshield)|20|5120|112|2.1%|8.8%|
[et_block](#et_block)|1016|18338655|108|0.0%|8.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|106|0.0%|8.4%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|98|0.0%|7.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|76|0.0%|6.0%|
[openbl_1d](#openbl_1d)|161|161|75|46.5%|5.9%|
[sslbl](#sslbl)|365|365|56|15.3%|4.4%|
[blocklist_de_apache](#blocklist_de_apache)|13701|13701|33|0.2%|2.6%|
[ciarmy](#ciarmy)|396|396|29|7.3%|2.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|26|0.0%|2.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|176|176|20|11.3%|1.5%|
[voipbl](#voipbl)|10426|10837|12|0.1%|0.9%|
[stopforumspam_30d](#stopforumspam_30d)|93498|93498|4|0.0%|0.3%|
[stopforumspam_7d](#stopforumspam_7d)|29882|29882|3|0.0%|0.2%|
[blocklist_de_mail](#blocklist_de_mail)|16101|16101|3|0.0%|0.2%|
[blocklist_de_imap](#blocklist_de_imap)|2409|2409|3|0.1%|0.2%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2348|2348|3|0.1%|0.2%|
[snort_ipfilter](#snort_ipfilter)|9882|9882|2|0.0%|0.1%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|2|0.5%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2|0.0%|0.1%|
[stopforumspam_1d](#stopforumspam_1d)|7188|7188|1|0.0%|0.0%|
[sorbs_spam](#sorbs_spam)|28347|29370|1|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|23675|24482|1|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|23675|24482|1|0.0%|0.0%|
[nixspam](#nixspam)|23361|23361|1|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.0%|
[et_tor](#et_tor)|6610|6610|1|0.0%|0.0%|
[dm_tor](#dm_tor)|6554|6554|1|0.0%|0.0%|
[bm_tor](#bm_tor)|6548|6548|1|0.0%|0.0%|

## snort_ipfilter

[labs.snort.org](https://labs.snort.org/) supplied IP blacklist (this list seems to be updated frequently, but we found no information about it)

Source is downloaded from [this link](http://labs.snort.org/feeds/ip-filter.blf).

The last time downloaded was found to be dated: Fri Jun  5 01:30:00 UTC 2015.

The ipset `snort_ipfilter` has **9882** entries, **9882** unique IPs.

The following table shows the overlaps of `snort_ipfilter` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `snort_ipfilter`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `snort_ipfilter`.
- ` this % ` is the percentage **of this ipset (`snort_ipfilter`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[et_tor](#et_tor)|6610|6610|1112|16.8%|11.2%|
[bm_tor](#bm_tor)|6548|6548|1056|16.1%|10.6%|
[dm_tor](#dm_tor)|6554|6554|1054|16.0%|10.6%|
[stopforumspam_30d](#stopforumspam_30d)|93498|93498|803|0.8%|8.1%|
[stopforumspam_7d](#stopforumspam_7d)|29882|29882|631|2.1%|6.3%|
[stopforumspam_1d](#stopforumspam_1d)|7188|7188|368|5.1%|3.7%|
[sorbs_spam](#sorbs_spam)|28347|29370|332|1.1%|3.3%|
[sorbs_recent_spam](#sorbs_recent_spam)|23675|24482|320|1.3%|3.2%|
[sorbs_new_spam](#sorbs_new_spam)|23675|24482|320|1.3%|3.2%|
[et_block](#et_block)|1016|18338655|315|0.0%|3.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|225|0.0%|2.2%|
[zeus](#zeus)|231|231|200|86.5%|2.0%|
[nixspam](#nixspam)|23361|23361|179|0.7%|1.8%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|179|48.1%|1.8%|
[blocklist_de](#blocklist_de)|31150|31150|179|0.5%|1.8%|
[zeus_badips](#zeus_badips)|202|202|178|88.1%|1.8%|
[blocklist_de_mail](#blocklist_de_mail)|16101|16101|156|0.9%|1.5%|
[alienvault_reputation](#alienvault_reputation)|180239|180239|125|0.0%|1.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|99|0.0%|1.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|97|0.0%|0.9%|
[php_dictionary](#php_dictionary)|508|508|76|14.9%|0.7%|
[feodo](#feodo)|94|94|73|77.6%|0.7%|
[ri_web_proxies](#ri_web_proxies)|6346|6346|61|0.9%|0.6%|
[sorbs_web](#sorbs_web)|785|787|60|7.6%|0.6%|
[php_spammers](#php_spammers)|461|461|59|12.7%|0.5%|
[xroxy](#xroxy)|2079|2079|51|2.4%|0.5%|
[php_commenters](#php_commenters)|301|301|41|13.6%|0.4%|
[sslbl](#sslbl)|365|365|29|7.9%|0.2%|
[openbl_60d](#openbl_60d)|7689|7689|29|0.3%|0.2%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|29|2.2%|0.2%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|20|0.0%|0.2%|
[proxz](#proxz)|776|776|20|2.5%|0.2%|
[blocklist_de_bots](#blocklist_de_bots)|3243|3243|20|0.6%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|13|0.0%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|11|0.0%|0.1%|
[php_harvesters](#php_harvesters)|298|298|10|3.3%|0.1%|
[palevo](#palevo)|12|12|10|83.3%|0.1%|
[blocklist_de_apache](#blocklist_de_apache)|13701|13701|8|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|486400|6|0.0%|0.0%|
[sorbs_socks](#sorbs_socks)|31|31|6|19.3%|0.0%|
[sorbs_misc](#sorbs_misc)|31|31|6|19.3%|0.0%|
[sorbs_http](#sorbs_http)|31|31|6|19.3%|0.0%|
[openbl_30d](#openbl_30d)|3256|3256|6|0.1%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2376|2376|5|0.2%|0.0%|
[proxyrss](#proxyrss)|1553|1553|5|0.3%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2409|2409|5|0.2%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|309|309|4|1.2%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2348|2348|4|0.1%|0.0%|
[shunlist](#shunlist)|1261|1261|2|0.1%|0.0%|
[openbl_7d](#openbl_7d)|910|910|2|0.2%|0.0%|
[voipbl](#voipbl)|10426|10837|1|0.0%|0.0%|
[malc0de](#malc0de)|379|379|1|0.2%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|1|0.1%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1|0.0%|0.0%|
[et_compromised](#et_compromised)|2086|2086|1|0.0%|0.0%|
[dshield](#dshield)|20|5120|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2007|2007|1|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|176|176|1|0.5%|0.0%|

## sorbs_dul

[Sorbs.net](https://www.sorbs.net/) DUL, Dynamic User IPs extracted from deltas.

Source is downloaded from [this link]().

The last time downloaded was found to be dated: Thu Jun  4 14:48:14 UTC 2015.

The ipset `sorbs_dul` has **8** entries, **3584** unique IPs.

The following table shows the overlaps of `sorbs_dul` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `sorbs_dul`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `sorbs_dul`.
- ` this % ` is the percentage **of this ipset (`sorbs_dul`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|

## sorbs_http

[Sorbs.net](https://www.sorbs.net/) HTTP proxies, extracted from deltas.

Source is downloaded from [this link]().

The last time downloaded was found to be dated: Fri Jun  5 10:04:14 UTC 2015.

The ipset `sorbs_http` has **31** entries, **31** unique IPs.

The following table shows the overlaps of `sorbs_http` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `sorbs_http`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `sorbs_http`.
- ` this % ` is the percentage **of this ipset (`sorbs_http`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[sorbs_socks](#sorbs_socks)|31|31|31|100.0%|100.0%|
[sorbs_misc](#sorbs_misc)|31|31|31|100.0%|100.0%|
[sorbs_spam](#sorbs_spam)|28347|29370|25|0.0%|80.6%|
[sorbs_recent_spam](#sorbs_recent_spam)|23675|24482|21|0.0%|67.7%|
[sorbs_new_spam](#sorbs_new_spam)|23675|24482|21|0.0%|67.7%|
[blocklist_de](#blocklist_de)|31150|31150|8|0.0%|25.8%|
[snort_ipfilter](#snort_ipfilter)|9882|9882|6|0.0%|19.3%|
[nixspam](#nixspam)|23361|23361|6|0.0%|19.3%|
[sorbs_web](#sorbs_web)|785|787|5|0.6%|16.1%|
[blocklist_de_mail](#blocklist_de_mail)|16101|16101|5|0.0%|16.1%|
[stopforumspam_7d](#stopforumspam_7d)|29882|29882|3|0.0%|9.6%|
[stopforumspam_30d](#stopforumspam_30d)|93498|93498|3|0.0%|9.6%|
[blocklist_de_bots](#blocklist_de_bots)|3243|3243|2|0.0%|6.4%|
[xroxy](#xroxy)|2079|2079|1|0.0%|3.2%|
[ri_web_proxies](#ri_web_proxies)|6346|6346|1|0.0%|3.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|1|0.0%|3.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|1|0.0%|3.2%|

## sorbs_misc

[Sorbs.net](https://www.sorbs.net/) MISC proxies, extracted from deltas.

Source is downloaded from [this link]().

The last time downloaded was found to be dated: Fri Jun  5 10:04:14 UTC 2015.

The ipset `sorbs_misc` has **31** entries, **31** unique IPs.

The following table shows the overlaps of `sorbs_misc` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `sorbs_misc`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `sorbs_misc`.
- ` this % ` is the percentage **of this ipset (`sorbs_misc`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[sorbs_socks](#sorbs_socks)|31|31|31|100.0%|100.0%|
[sorbs_http](#sorbs_http)|31|31|31|100.0%|100.0%|
[sorbs_spam](#sorbs_spam)|28347|29370|25|0.0%|80.6%|
[sorbs_recent_spam](#sorbs_recent_spam)|23675|24482|21|0.0%|67.7%|
[sorbs_new_spam](#sorbs_new_spam)|23675|24482|21|0.0%|67.7%|
[blocklist_de](#blocklist_de)|31150|31150|8|0.0%|25.8%|
[snort_ipfilter](#snort_ipfilter)|9882|9882|6|0.0%|19.3%|
[nixspam](#nixspam)|23361|23361|6|0.0%|19.3%|
[sorbs_web](#sorbs_web)|785|787|5|0.6%|16.1%|
[blocklist_de_mail](#blocklist_de_mail)|16101|16101|5|0.0%|16.1%|
[stopforumspam_7d](#stopforumspam_7d)|29882|29882|3|0.0%|9.6%|
[stopforumspam_30d](#stopforumspam_30d)|93498|93498|3|0.0%|9.6%|
[blocklist_de_bots](#blocklist_de_bots)|3243|3243|2|0.0%|6.4%|
[xroxy](#xroxy)|2079|2079|1|0.0%|3.2%|
[ri_web_proxies](#ri_web_proxies)|6346|6346|1|0.0%|3.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|1|0.0%|3.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|1|0.0%|3.2%|

## sorbs_new_spam

[Sorbs.net](https://www.sorbs.net/) NEW Spam senders, extracted from deltas.

Source is downloaded from [this link]().

The last time downloaded was found to be dated: Fri Jun  5 10:04:14 UTC 2015.

The ipset `sorbs_new_spam` has **23675** entries, **24482** unique IPs.

The following table shows the overlaps of `sorbs_new_spam` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `sorbs_new_spam`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `sorbs_new_spam`.
- ` this % ` is the percentage **of this ipset (`sorbs_new_spam`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[sorbs_spam](#sorbs_spam)|28347|29370|24482|83.3%|100.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|23675|24482|24482|100.0%|100.0%|
[nixspam](#nixspam)|23361|23361|4347|18.6%|17.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|1778|0.0%|7.2%|
[blocklist_de](#blocklist_de)|31150|31150|1073|3.4%|4.3%|
[blocklist_de_mail](#blocklist_de_mail)|16101|16101|913|5.6%|3.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|608|0.0%|2.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|368|0.0%|1.5%|
[snort_ipfilter](#snort_ipfilter)|9882|9882|320|3.2%|1.3%|
[sorbs_web](#sorbs_web)|785|787|319|40.5%|1.3%|
[stopforumspam_30d](#stopforumspam_30d)|93498|93498|301|0.3%|1.2%|
[stopforumspam_7d](#stopforumspam_7d)|29882|29882|173|0.5%|0.7%|
[php_dictionary](#php_dictionary)|508|508|129|25.3%|0.5%|
[ri_web_proxies](#ri_web_proxies)|6346|6346|121|1.9%|0.4%|
[php_spammers](#php_spammers)|461|461|92|19.9%|0.3%|
[alienvault_reputation](#alienvault_reputation)|180239|180239|91|0.0%|0.3%|
[xroxy](#xroxy)|2079|2079|82|3.9%|0.3%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2348|2348|71|3.0%|0.2%|
[blocklist_de_apache](#blocklist_de_apache)|13701|13701|71|0.5%|0.2%|
[stopforumspam_1d](#stopforumspam_1d)|7188|7188|54|0.7%|0.2%|
[blocklist_de_ssh](#blocklist_de_ssh)|8193|8193|50|0.6%|0.2%|
[blocklist_de_bots](#blocklist_de_bots)|3243|3243|36|1.1%|0.1%|
[proxz](#proxz)|776|776|35|4.5%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|27|0.0%|0.1%|
[sorbs_socks](#sorbs_socks)|31|31|21|67.7%|0.0%|
[sorbs_misc](#sorbs_misc)|31|31|21|67.7%|0.0%|
[sorbs_http](#sorbs_http)|31|31|21|67.7%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2409|2409|19|0.7%|0.0%|
[openbl_60d](#openbl_60d)|7689|7689|14|0.1%|0.0%|
[sorbs_smtp](#sorbs_smtp)|14|14|13|92.8%|0.0%|
[php_commenters](#php_commenters)|301|301|12|3.9%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2376|2376|10|0.4%|0.0%|
[proxyrss](#proxyrss)|1553|1553|9|0.5%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|8|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|7|0.0%|0.0%|
[et_block](#et_block)|1016|18338655|7|0.0%|0.0%|
[php_harvesters](#php_harvesters)|298|298|6|2.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|486400|3|0.0%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|0.0%|
[openbl_30d](#openbl_30d)|3256|3256|2|0.0%|0.0%|
[et_tor](#et_tor)|6610|6610|2|0.0%|0.0%|
[shunlist](#shunlist)|1261|1261|1|0.0%|0.0%|
[openbl_7d](#openbl_7d)|910|910|1|0.1%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|1|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|1|0.1%|0.0%|
[dm_tor](#dm_tor)|6554|6554|1|0.0%|0.0%|
[bm_tor](#bm_tor)|6548|6548|1|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|176|176|1|0.5%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|915|915|1|0.1%|0.0%|

## sorbs_recent_spam

[Sorbs.net](https://www.sorbs.net/) RECENT Spam senders, extracted from deltas.

Source is downloaded from [this link]().

The last time downloaded was found to be dated: Fri Jun  5 10:04:14 UTC 2015.

The ipset `sorbs_recent_spam` has **23675** entries, **24482** unique IPs.

The following table shows the overlaps of `sorbs_recent_spam` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `sorbs_recent_spam`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `sorbs_recent_spam`.
- ` this % ` is the percentage **of this ipset (`sorbs_recent_spam`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[sorbs_spam](#sorbs_spam)|28347|29370|24482|83.3%|100.0%|
[sorbs_new_spam](#sorbs_new_spam)|23675|24482|24482|100.0%|100.0%|
[nixspam](#nixspam)|23361|23361|4347|18.6%|17.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|1778|0.0%|7.2%|
[blocklist_de](#blocklist_de)|31150|31150|1073|3.4%|4.3%|
[blocklist_de_mail](#blocklist_de_mail)|16101|16101|913|5.6%|3.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|608|0.0%|2.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|368|0.0%|1.5%|
[snort_ipfilter](#snort_ipfilter)|9882|9882|320|3.2%|1.3%|
[sorbs_web](#sorbs_web)|785|787|319|40.5%|1.3%|
[stopforumspam_30d](#stopforumspam_30d)|93498|93498|301|0.3%|1.2%|
[stopforumspam_7d](#stopforumspam_7d)|29882|29882|173|0.5%|0.7%|
[php_dictionary](#php_dictionary)|508|508|129|25.3%|0.5%|
[ri_web_proxies](#ri_web_proxies)|6346|6346|121|1.9%|0.4%|
[php_spammers](#php_spammers)|461|461|92|19.9%|0.3%|
[alienvault_reputation](#alienvault_reputation)|180239|180239|91|0.0%|0.3%|
[xroxy](#xroxy)|2079|2079|82|3.9%|0.3%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2348|2348|71|3.0%|0.2%|
[blocklist_de_apache](#blocklist_de_apache)|13701|13701|71|0.5%|0.2%|
[stopforumspam_1d](#stopforumspam_1d)|7188|7188|54|0.7%|0.2%|
[blocklist_de_ssh](#blocklist_de_ssh)|8193|8193|50|0.6%|0.2%|
[blocklist_de_bots](#blocklist_de_bots)|3243|3243|36|1.1%|0.1%|
[proxz](#proxz)|776|776|35|4.5%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|27|0.0%|0.1%|
[sorbs_socks](#sorbs_socks)|31|31|21|67.7%|0.0%|
[sorbs_misc](#sorbs_misc)|31|31|21|67.7%|0.0%|
[sorbs_http](#sorbs_http)|31|31|21|67.7%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2409|2409|19|0.7%|0.0%|
[openbl_60d](#openbl_60d)|7689|7689|14|0.1%|0.0%|
[sorbs_smtp](#sorbs_smtp)|14|14|13|92.8%|0.0%|
[php_commenters](#php_commenters)|301|301|12|3.9%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2376|2376|10|0.4%|0.0%|
[proxyrss](#proxyrss)|1553|1553|9|0.5%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|8|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|7|0.0%|0.0%|
[et_block](#et_block)|1016|18338655|7|0.0%|0.0%|
[php_harvesters](#php_harvesters)|298|298|6|2.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|486400|3|0.0%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|0.0%|
[openbl_30d](#openbl_30d)|3256|3256|2|0.0%|0.0%|
[et_tor](#et_tor)|6610|6610|2|0.0%|0.0%|
[shunlist](#shunlist)|1261|1261|1|0.0%|0.0%|
[openbl_7d](#openbl_7d)|910|910|1|0.1%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|1|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|1|0.1%|0.0%|
[dm_tor](#dm_tor)|6554|6554|1|0.0%|0.0%|
[bm_tor](#bm_tor)|6548|6548|1|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|176|176|1|0.5%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|915|915|1|0.1%|0.0%|

## sorbs_smtp

[Sorbs.net](https://www.sorbs.net/) SMTP Open Relays, extracted from deltas.

Source is downloaded from [this link]().

The last time downloaded was found to be dated: Fri Jun  5 02:04:14 UTC 2015.

The ipset `sorbs_smtp` has **14** entries, **14** unique IPs.

The following table shows the overlaps of `sorbs_smtp` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `sorbs_smtp`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `sorbs_smtp`.
- ` this % ` is the percentage **of this ipset (`sorbs_smtp`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[sorbs_spam](#sorbs_spam)|28347|29370|14|0.0%|100.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|23675|24482|13|0.0%|92.8%|
[sorbs_new_spam](#sorbs_new_spam)|23675|24482|13|0.0%|92.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|1|0.0%|7.1%|

## sorbs_socks

[Sorbs.net](https://www.sorbs.net/) SOCKS proxies, extracted from deltas.

Source is downloaded from [this link]().

The last time downloaded was found to be dated: Fri Jun  5 10:04:14 UTC 2015.

The ipset `sorbs_socks` has **31** entries, **31** unique IPs.

The following table shows the overlaps of `sorbs_socks` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `sorbs_socks`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `sorbs_socks`.
- ` this % ` is the percentage **of this ipset (`sorbs_socks`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[sorbs_misc](#sorbs_misc)|31|31|31|100.0%|100.0%|
[sorbs_http](#sorbs_http)|31|31|31|100.0%|100.0%|
[sorbs_spam](#sorbs_spam)|28347|29370|25|0.0%|80.6%|
[sorbs_recent_spam](#sorbs_recent_spam)|23675|24482|21|0.0%|67.7%|
[sorbs_new_spam](#sorbs_new_spam)|23675|24482|21|0.0%|67.7%|
[blocklist_de](#blocklist_de)|31150|31150|8|0.0%|25.8%|
[snort_ipfilter](#snort_ipfilter)|9882|9882|6|0.0%|19.3%|
[nixspam](#nixspam)|23361|23361|6|0.0%|19.3%|
[sorbs_web](#sorbs_web)|785|787|5|0.6%|16.1%|
[blocklist_de_mail](#blocklist_de_mail)|16101|16101|5|0.0%|16.1%|
[stopforumspam_7d](#stopforumspam_7d)|29882|29882|3|0.0%|9.6%|
[stopforumspam_30d](#stopforumspam_30d)|93498|93498|3|0.0%|9.6%|
[blocklist_de_bots](#blocklist_de_bots)|3243|3243|2|0.0%|6.4%|
[xroxy](#xroxy)|2079|2079|1|0.0%|3.2%|
[ri_web_proxies](#ri_web_proxies)|6346|6346|1|0.0%|3.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|1|0.0%|3.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|1|0.0%|3.2%|

## sorbs_spam

[Sorbs.net](https://www.sorbs.net/) Spam senders, extracted from deltas.

Source is downloaded from [this link]().

The last time downloaded was found to be dated: Fri Jun  5 10:04:14 UTC 2015.

The ipset `sorbs_spam` has **28347** entries, **29370** unique IPs.

The following table shows the overlaps of `sorbs_spam` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `sorbs_spam`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `sorbs_spam`.
- ` this % ` is the percentage **of this ipset (`sorbs_spam`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[sorbs_recent_spam](#sorbs_recent_spam)|23675|24482|24482|100.0%|83.3%|
[sorbs_new_spam](#sorbs_new_spam)|23675|24482|24482|100.0%|83.3%|
[nixspam](#nixspam)|23361|23361|4492|19.2%|15.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|2158|0.0%|7.3%|
[blocklist_de](#blocklist_de)|31150|31150|1096|3.5%|3.7%|
[blocklist_de_mail](#blocklist_de_mail)|16101|16101|930|5.7%|3.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|692|0.0%|2.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|452|0.0%|1.5%|
[sorbs_web](#sorbs_web)|785|787|347|44.0%|1.1%|
[stopforumspam_30d](#stopforumspam_30d)|93498|93498|337|0.3%|1.1%|
[snort_ipfilter](#snort_ipfilter)|9882|9882|332|3.3%|1.1%|
[stopforumspam_7d](#stopforumspam_7d)|29882|29882|188|0.6%|0.6%|
[php_dictionary](#php_dictionary)|508|508|135|26.5%|0.4%|
[ri_web_proxies](#ri_web_proxies)|6346|6346|127|2.0%|0.4%|
[alienvault_reputation](#alienvault_reputation)|180239|180239|105|0.0%|0.3%|
[php_spammers](#php_spammers)|461|461|101|21.9%|0.3%|
[xroxy](#xroxy)|2079|2079|84|4.0%|0.2%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2348|2348|72|3.0%|0.2%|
[blocklist_de_apache](#blocklist_de_apache)|13701|13701|72|0.5%|0.2%|
[stopforumspam_1d](#stopforumspam_1d)|7188|7188|56|0.7%|0.1%|
[blocklist_de_ssh](#blocklist_de_ssh)|8193|8193|52|0.6%|0.1%|
[blocklist_de_bots](#blocklist_de_bots)|3243|3243|37|1.1%|0.1%|
[proxz](#proxz)|776|776|35|4.5%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|28|0.0%|0.0%|
[sorbs_socks](#sorbs_socks)|31|31|25|80.6%|0.0%|
[sorbs_misc](#sorbs_misc)|31|31|25|80.6%|0.0%|
[sorbs_http](#sorbs_http)|31|31|25|80.6%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2409|2409|23|0.9%|0.0%|
[openbl_60d](#openbl_60d)|7689|7689|15|0.1%|0.0%|
[sorbs_smtp](#sorbs_smtp)|14|14|14|100.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|12|0.0%|0.0%|
[php_commenters](#php_commenters)|301|301|12|3.9%|0.0%|
[et_block](#et_block)|1016|18338655|12|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2376|2376|11|0.4%|0.0%|
[proxyrss](#proxyrss)|1553|1553|9|0.5%|0.0%|
[php_harvesters](#php_harvesters)|298|298|8|2.6%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|8|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|8|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|486400|4|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|915|915|3|0.3%|0.0%|
[openbl_30d](#openbl_30d)|3256|3256|2|0.0%|0.0%|
[et_tor](#et_tor)|6610|6610|2|0.0%|0.0%|
[shunlist](#shunlist)|1261|1261|1|0.0%|0.0%|
[openbl_7d](#openbl_7d)|910|910|1|0.1%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|1|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|1|0.1%|0.0%|
[et_compromised](#et_compromised)|2086|2086|1|0.0%|0.0%|
[dm_tor](#dm_tor)|6554|6554|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2007|2007|1|0.0%|0.0%|
[bm_tor](#bm_tor)|6548|6548|1|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|176|176|1|0.5%|0.0%|

## sorbs_web

[Sorbs.net](https://www.sorbs.net/) WEB exploits, extracted from deltas.

Source is downloaded from [this link]().

The last time downloaded was found to be dated: Fri Jun  5 10:04:14 UTC 2015.

The ipset `sorbs_web` has **785** entries, **787** unique IPs.

The following table shows the overlaps of `sorbs_web` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `sorbs_web`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `sorbs_web`.
- ` this % ` is the percentage **of this ipset (`sorbs_web`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[sorbs_spam](#sorbs_spam)|28347|29370|347|1.1%|44.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|23675|24482|319|1.3%|40.5%|
[sorbs_new_spam](#sorbs_new_spam)|23675|24482|319|1.3%|40.5%|
[nixspam](#nixspam)|23361|23361|154|0.6%|19.5%|
[blocklist_de](#blocklist_de)|31150|31150|91|0.2%|11.5%|
[blocklist_de_mail](#blocklist_de_mail)|16101|16101|80|0.4%|10.1%|
[stopforumspam_30d](#stopforumspam_30d)|93498|93498|69|0.0%|8.7%|
[snort_ipfilter](#snort_ipfilter)|9882|9882|60|0.6%|7.6%|
[stopforumspam_7d](#stopforumspam_7d)|29882|29882|52|0.1%|6.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|50|0.0%|6.3%|
[php_dictionary](#php_dictionary)|508|508|38|7.4%|4.8%|
[ri_web_proxies](#ri_web_proxies)|6346|6346|31|0.4%|3.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|29|0.0%|3.6%|
[xroxy](#xroxy)|2079|2079|27|1.2%|3.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|26|0.0%|3.3%|
[php_spammers](#php_spammers)|461|461|25|5.4%|3.1%|
[stopforumspam_1d](#stopforumspam_1d)|7188|7188|17|0.2%|2.1%|
[proxz](#proxz)|776|776|14|1.8%|1.7%|
[blocklist_de_bots](#blocklist_de_bots)|3243|3243|9|0.2%|1.1%|
[sorbs_socks](#sorbs_socks)|31|31|5|16.1%|0.6%|
[sorbs_misc](#sorbs_misc)|31|31|5|16.1%|0.6%|
[sorbs_http](#sorbs_http)|31|31|5|16.1%|0.6%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2348|2348|3|0.1%|0.3%|
[blocklist_de_apache](#blocklist_de_apache)|13701|13701|3|0.0%|0.3%|
[ri_connect_proxies](#ri_connect_proxies)|2376|2376|2|0.0%|0.2%|
[proxyrss](#proxyrss)|1553|1553|2|0.1%|0.2%|
[php_commenters](#php_commenters)|301|301|2|0.6%|0.2%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|1|0.0%|0.1%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1|0.0%|0.1%|
[et_block](#et_block)|1016|18338655|1|0.0%|0.1%|
[blocklist_de_strongips](#blocklist_de_strongips)|176|176|1|0.5%|0.1%|

## spamhaus_drop

[Spamhaus.org](http://www.spamhaus.org) DROP list (according to their site this list should be dropped at tier-1 ISPs globaly) - **excellent list**

Source is downloaded from [this link](http://www.spamhaus.org/drop/drop.txt).

The last time downloaded was found to be dated: Thu Jun  4 12:16:20 UTC 2015.

The ipset `spamhaus_drop` has **653** entries, **18404096** unique IPs.

The following table shows the overlaps of `spamhaus_drop` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `spamhaus_drop`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `spamhaus_drop`.
- ` this % ` is the percentage **of this ipset (`spamhaus_drop`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[et_block](#et_block)|1016|18338655|18120448|98.8%|98.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|8598042|2.4%|46.7%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|6998016|76.2%|38.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|2272265|0.2%|12.3%|
[fullbogons](#fullbogons)|3715|670310296|151552|0.0%|0.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|130368|0.0%|0.7%|
[alienvault_reputation](#alienvault_reputation)|180239|180239|1630|0.9%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1037|0.3%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|93498|93498|1023|1.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|486400|512|0.1%|0.0%|
[dshield](#dshield)|20|5120|512|10.0%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29882|29882|336|1.1%|0.0%|
[openbl_60d](#openbl_60d)|7689|7689|239|3.1%|0.0%|
[nixspam](#nixspam)|23361|23361|197|0.8%|0.0%|
[blocklist_de](#blocklist_de)|31150|31150|177|0.5%|0.0%|
[openbl_30d](#openbl_30d)|3256|3256|159|4.8%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|8193|8193|111|1.3%|0.0%|
[et_compromised](#et_compromised)|2086|2086|100|4.7%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2007|2007|100|4.9%|0.0%|
[shunlist](#shunlist)|1261|1261|98|7.7%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7188|7188|81|1.1%|0.0%|
[openbl_7d](#openbl_7d)|910|910|50|5.4%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3243|3243|37|1.1%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|29|2.2%|0.0%|
[php_commenters](#php_commenters)|301|301|26|8.6%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|16101|16101|25|0.1%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9882|9882|20|0.2%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2409|2409|17|0.7%|0.0%|
[zeus_badips](#zeus_badips)|202|202|16|7.9%|0.0%|
[zeus](#zeus)|231|231|16|6.9%|0.0%|
[voipbl](#voipbl)|10426|10837|14|0.1%|0.0%|
[sorbs_spam](#sorbs_spam)|28347|29370|12|0.0%|0.0%|
[openbl_1d](#openbl_1d)|161|161|10|6.2%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|23675|24482|7|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|23675|24482|7|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|6|0.4%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|6|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|176|176|6|3.4%|0.0%|
[php_dictionary](#php_dictionary)|508|508|4|0.7%|0.0%|
[malc0de](#malc0de)|379|379|4|1.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2348|2348|4|0.1%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13701|13701|4|0.0%|0.0%|
[php_spammers](#php_spammers)|461|461|3|0.6%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|2|0.2%|0.0%|
[et_tor](#et_tor)|6610|6610|2|0.0%|0.0%|
[dm_tor](#dm_tor)|6554|6554|2|0.0%|0.0%|
[bm_tor](#bm_tor)|6548|6548|2|0.0%|0.0%|
[sslbl](#sslbl)|365|365|1|0.2%|0.0%|
[sorbs_web](#sorbs_web)|785|787|1|0.1%|0.0%|
[php_harvesters](#php_harvesters)|298|298|1|0.3%|0.0%|
[et_botcc](#et_botcc)|509|509|1|0.1%|0.0%|

## spamhaus_edrop

[Spamhaus.org](http://www.spamhaus.org) EDROP (extended matches that should be used with DROP) - **excellent list**

Source is downloaded from [this link](http://www.spamhaus.org/drop/edrop.txt).

The last time downloaded was found to be dated: Wed Jun  3 21:37:19 UTC 2015.

The ipset `spamhaus_edrop` has **55** entries, **486400** unique IPs.

The following table shows the overlaps of `spamhaus_edrop` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `spamhaus_edrop`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `spamhaus_edrop`.
- ` this % ` is the percentage **of this ipset (`spamhaus_edrop`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|270785|0.1%|55.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|98904|0.0%|20.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|33155|0.0%|6.8%|
[et_block](#et_block)|1016|18338655|517|0.0%|0.1%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|512|0.0%|0.1%|
[stopforumspam_30d](#stopforumspam_30d)|93498|93498|92|0.0%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29882|29882|17|0.0%|0.0%|
[alienvault_reputation](#alienvault_reputation)|180239|180239|15|0.0%|0.0%|
[blocklist_de](#blocklist_de)|31150|31150|8|0.0%|0.0%|
[php_commenters](#php_commenters)|301|301|7|2.3%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9882|9882|6|0.0%|0.0%|
[zeus_badips](#zeus_badips)|202|202|5|2.4%|0.0%|
[zeus](#zeus)|231|231|5|2.1%|0.0%|
[sorbs_spam](#sorbs_spam)|28347|29370|4|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|176|176|4|2.2%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3243|3243|4|0.1%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7188|7188|3|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|23675|24482|3|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|23675|24482|3|0.0%|0.0%|
[php_harvesters](#php_harvesters)|298|298|1|0.3%|0.0%|
[openbl_60d](#openbl_60d)|7689|7689|1|0.0%|0.0%|
[openbl_30d](#openbl_30d)|3256|3256|1|0.0%|0.0%|
[malc0de](#malc0de)|379|379|1|0.2%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|8193|8193|1|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|16101|16101|1|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|915|915|1|0.1%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13701|13701|1|0.0%|0.0%|

## sslbl

[Abuse.ch SSL Blacklist](https://sslbl.abuse.ch/) bad SSL traffic related to malware or botnet activities - **excellent list**

Source is downloaded from [this link](https://sslbl.abuse.ch/blacklist/sslipblacklist.csv).

The last time downloaded was found to be dated: Fri Jun  5 10:15:07 UTC 2015.

The ipset `sslbl` has **365** entries, **365** unique IPs.

The following table shows the overlaps of `sslbl` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `sslbl`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `sslbl`.
- ` this % ` is the percentage **of this ipset (`sslbl`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[alienvault_reputation](#alienvault_reputation)|180239|180239|64|0.0%|17.5%|
[shunlist](#shunlist)|1261|1261|56|4.4%|15.3%|
[feodo](#feodo)|94|94|34|36.1%|9.3%|
[et_block](#et_block)|1016|18338655|33|0.0%|9.0%|
[snort_ipfilter](#snort_ipfilter)|9882|9882|29|0.2%|7.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|23|0.0%|6.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|6|0.0%|1.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|3|0.0%|0.8%|
[stopforumspam_30d](#stopforumspam_30d)|93498|93498|1|0.0%|0.2%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|1|0.0%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.2%|
[cleanmx_viruses](#cleanmx_viruses)|309|309|1|0.3%|0.2%|
[blocklist_de_ssh](#blocklist_de_ssh)|8193|8193|1|0.0%|0.2%|
[blocklist_de](#blocklist_de)|31150|31150|1|0.0%|0.2%|

## stopforumspam_1d

[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers in the last 24 hours - **excellent list**

Source is downloaded from [this link](http://www.stopforumspam.com/downloads/listed_ip_1.zip).

The last time downloaded was found to be dated: Fri Jun  5 10:00:02 UTC 2015.

The ipset `stopforumspam_1d` has **7188** entries, **7188** unique IPs.

The following table shows the overlaps of `stopforumspam_1d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `stopforumspam_1d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `stopforumspam_1d`.
- ` this % ` is the percentage **of this ipset (`stopforumspam_1d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_30d](#stopforumspam_30d)|93498|93498|6118|6.5%|85.1%|
[stopforumspam_7d](#stopforumspam_7d)|29882|29882|5960|19.9%|82.9%|
[blocklist_de](#blocklist_de)|31150|31150|1488|4.7%|20.7%|
[blocklist_de_bots](#blocklist_de_bots)|3243|3243|1414|43.6%|19.6%|
[ri_web_proxies](#ri_web_proxies)|6346|6346|506|7.9%|7.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|502|0.0%|6.9%|
[proxyrss](#proxyrss)|1553|1553|377|24.2%|5.2%|
[snort_ipfilter](#snort_ipfilter)|9882|9882|368|3.7%|5.1%|
[et_tor](#et_tor)|6610|6610|327|4.9%|4.5%|
[dm_tor](#dm_tor)|6554|6554|324|4.9%|4.5%|
[bm_tor](#bm_tor)|6548|6548|324|4.9%|4.5%|
[xroxy](#xroxy)|2079|2079|295|14.1%|4.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|230|0.0%|3.1%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|154|41.3%|2.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|151|0.0%|2.1%|
[proxz](#proxz)|776|776|149|19.2%|2.0%|
[ri_connect_proxies](#ri_connect_proxies)|2376|2376|147|6.1%|2.0%|
[php_commenters](#php_commenters)|301|301|121|40.1%|1.6%|
[blocklist_de_strongips](#blocklist_de_strongips)|176|176|103|58.5%|1.4%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|81|0.0%|1.1%|
[et_block](#et_block)|1016|18338655|79|0.0%|1.0%|
[nixspam](#nixspam)|23361|23361|68|0.2%|0.9%|
[blocklist_de_apache](#blocklist_de_apache)|13701|13701|67|0.4%|0.9%|
[blocklist_de_mail](#blocklist_de_mail)|16101|16101|59|0.3%|0.8%|
[sorbs_spam](#sorbs_spam)|28347|29370|56|0.1%|0.7%|
[sorbs_recent_spam](#sorbs_recent_spam)|23675|24482|54|0.2%|0.7%|
[sorbs_new_spam](#sorbs_new_spam)|23675|24482|54|0.2%|0.7%|
[alienvault_reputation](#alienvault_reputation)|180239|180239|52|0.0%|0.7%|
[php_harvesters](#php_harvesters)|298|298|35|11.7%|0.4%|
[php_spammers](#php_spammers)|461|461|30|6.5%|0.4%|
[php_dictionary](#php_dictionary)|508|508|30|5.9%|0.4%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|22|0.0%|0.3%|
[openbl_60d](#openbl_60d)|7689|7689|21|0.2%|0.2%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2348|2348|20|0.8%|0.2%|
[sorbs_web](#sorbs_web)|785|787|17|2.1%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|10|0.0%|0.1%|
[voipbl](#voipbl)|10426|10837|5|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|5|0.7%|0.0%|
[dshield](#dshield)|20|5120|4|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|8193|8193|4|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|486400|3|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2007|2007|3|0.1%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.0%|
[et_compromised](#et_compromised)|2086|2086|2|0.0%|0.0%|
[zeus_badips](#zeus_badips)|202|202|1|0.4%|0.0%|
[zeus](#zeus)|231|231|1|0.4%|0.0%|
[shunlist](#shunlist)|1261|1261|1|0.0%|0.0%|
[openbl_30d](#openbl_30d)|3256|3256|1|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2409|2409|1|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|915|915|1|0.1%|0.0%|

## stopforumspam_30d

[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 30 days)

Source is downloaded from [this link](http://www.stopforumspam.com/downloads/listed_ip_30.zip).

The last time downloaded was found to be dated: Fri Jun  5 00:01:20 UTC 2015.

The ipset `stopforumspam_30d` has **93498** entries, **93498** unique IPs.

The following table shows the overlaps of `stopforumspam_30d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `stopforumspam_30d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `stopforumspam_30d`.
- ` this % ` is the percentage **of this ipset (`stopforumspam_30d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_7d](#stopforumspam_7d)|29882|29882|29803|99.7%|31.8%|
[stopforumspam_1d](#stopforumspam_1d)|7188|7188|6118|85.1%|6.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|5886|0.0%|6.2%|
[ri_web_proxies](#ri_web_proxies)|6346|6346|3093|48.7%|3.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|2548|0.0%|2.7%|
[blocklist_de](#blocklist_de)|31150|31150|2529|8.1%|2.7%|
[blocklist_de_bots](#blocklist_de_bots)|3243|3243|2140|65.9%|2.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|1554|0.0%|1.6%|
[ri_connect_proxies](#ri_connect_proxies)|2376|2376|1382|58.1%|1.4%|
[xroxy](#xroxy)|2079|2079|1219|58.6%|1.3%|
[et_block](#et_block)|1016|18338655|1028|0.0%|1.0%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|1023|0.0%|1.0%|
[proxyrss](#proxyrss)|1553|1553|819|52.7%|0.8%|
[snort_ipfilter](#snort_ipfilter)|9882|9882|803|8.1%|0.8%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|759|0.0%|0.8%|
[et_tor](#et_tor)|6610|6610|644|9.7%|0.6%|
[dm_tor](#dm_tor)|6554|6554|628|9.5%|0.6%|
[bm_tor](#bm_tor)|6548|6548|628|9.5%|0.6%|
[proxz](#proxz)|776|776|469|60.4%|0.5%|
[sorbs_spam](#sorbs_spam)|28347|29370|337|1.1%|0.3%|
[sorbs_recent_spam](#sorbs_recent_spam)|23675|24482|301|1.2%|0.3%|
[sorbs_new_spam](#sorbs_new_spam)|23675|24482|301|1.2%|0.3%|
[nixspam](#nixspam)|23361|23361|282|1.2%|0.3%|
[blocklist_de_mail](#blocklist_de_mail)|16101|16101|264|1.6%|0.2%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|233|62.6%|0.2%|
[php_commenters](#php_commenters)|301|301|219|72.7%|0.2%|
[blocklist_de_apache](#blocklist_de_apache)|13701|13701|216|1.5%|0.2%|
[alienvault_reputation](#alienvault_reputation)|180239|180239|207|0.1%|0.2%|
[blocklist_de_strongips](#blocklist_de_strongips)|176|176|128|72.7%|0.1%|
[php_spammers](#php_spammers)|461|461|102|22.1%|0.1%|
[php_dictionary](#php_dictionary)|508|508|98|19.2%|0.1%|
[spamhaus_edrop](#spamhaus_edrop)|55|486400|92|0.0%|0.0%|
[sorbs_web](#sorbs_web)|785|787|69|8.7%|0.0%|
[php_harvesters](#php_harvesters)|298|298|67|22.4%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|8193|8193|60|0.7%|0.0%|
[openbl_60d](#openbl_60d)|7689|7689|57|0.7%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|47|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2348|2348|45|1.9%|0.0%|
[voipbl](#voipbl)|10426|10837|37|0.3%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|22|3.2%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|14|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|915|915|13|1.4%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2007|2007|11|0.5%|0.0%|
[et_compromised](#et_compromised)|2086|2086|10|0.4%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2409|2409|9|0.3%|0.0%|
[dshield](#dshield)|20|5120|8|0.1%|0.0%|
[shunlist](#shunlist)|1261|1261|4|0.3%|0.0%|
[openbl_30d](#openbl_30d)|3256|3256|4|0.1%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|4|0.3%|0.0%|
[sorbs_socks](#sorbs_socks)|31|31|3|9.6%|0.0%|
[sorbs_misc](#sorbs_misc)|31|31|3|9.6%|0.0%|
[sorbs_http](#sorbs_http)|31|31|3|9.6%|0.0%|
[openbl_7d](#openbl_7d)|910|910|3|0.3%|0.0%|
[zeus_badips](#zeus_badips)|202|202|2|0.9%|0.0%|
[zeus](#zeus)|231|231|2|0.8%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.0%|
[fullbogons](#fullbogons)|3715|670310296|2|0.0%|0.0%|
[sslbl](#sslbl)|365|365|1|0.2%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|309|309|1|0.3%|0.0%|
[ciarmy](#ciarmy)|396|396|1|0.2%|0.0%|
[bogons](#bogons)|13|592708608|1|0.0%|0.0%|

## stopforumspam_7d

[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 7 days)

Source is downloaded from [this link](http://www.stopforumspam.com/downloads/listed_ip_7.zip).

The last time downloaded was found to be dated: Fri Jun  5 01:02:36 UTC 2015.

The ipset `stopforumspam_7d` has **29882** entries, **29882** unique IPs.

The following table shows the overlaps of `stopforumspam_7d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `stopforumspam_7d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `stopforumspam_7d`.
- ` this % ` is the percentage **of this ipset (`stopforumspam_7d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_30d](#stopforumspam_30d)|93498|93498|29803|31.8%|99.7%|
[stopforumspam_1d](#stopforumspam_1d)|7188|7188|5960|82.9%|19.9%|
[blocklist_de](#blocklist_de)|31150|31150|2163|6.9%|7.2%|
[blocklist_de_bots](#blocklist_de_bots)|3243|3243|1951|60.1%|6.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|1876|0.0%|6.2%|
[ri_web_proxies](#ri_web_proxies)|6346|6346|1620|25.5%|5.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|932|0.0%|3.1%|
[xroxy](#xroxy)|2079|2079|772|37.1%|2.5%|
[proxyrss](#proxyrss)|1553|1553|658|42.3%|2.2%|
[ri_connect_proxies](#ri_connect_proxies)|2376|2376|649|27.3%|2.1%|
[snort_ipfilter](#snort_ipfilter)|9882|9882|631|6.3%|2.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|566|0.0%|1.8%|
[et_tor](#et_tor)|6610|6610|516|7.8%|1.7%|
[dm_tor](#dm_tor)|6554|6554|500|7.6%|1.6%|
[bm_tor](#bm_tor)|6548|6548|500|7.6%|1.6%|
[proxz](#proxz)|776|776|380|48.9%|1.2%|
[et_block](#et_block)|1016|18338655|341|0.0%|1.1%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|336|0.0%|1.1%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|190|51.0%|0.6%|
[sorbs_spam](#sorbs_spam)|28347|29370|188|0.6%|0.6%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|177|0.0%|0.5%|
[sorbs_recent_spam](#sorbs_recent_spam)|23675|24482|173|0.7%|0.5%|
[sorbs_new_spam](#sorbs_new_spam)|23675|24482|173|0.7%|0.5%|
[nixspam](#nixspam)|23361|23361|165|0.7%|0.5%|
[blocklist_de_mail](#blocklist_de_mail)|16101|16101|161|0.9%|0.5%|
[php_commenters](#php_commenters)|301|301|157|52.1%|0.5%|
[blocklist_de_apache](#blocklist_de_apache)|13701|13701|136|0.9%|0.4%|
[blocklist_de_strongips](#blocklist_de_strongips)|176|176|116|65.9%|0.3%|
[alienvault_reputation](#alienvault_reputation)|180239|180239|95|0.0%|0.3%|
[php_dictionary](#php_dictionary)|508|508|66|12.9%|0.2%|
[php_spammers](#php_spammers)|461|461|57|12.3%|0.1%|
[sorbs_web](#sorbs_web)|785|787|52|6.6%|0.1%|
[php_harvesters](#php_harvesters)|298|298|52|17.4%|0.1%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2348|2348|31|1.3%|0.1%|
[openbl_60d](#openbl_60d)|7689|7689|25|0.3%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|24|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|486400|17|0.0%|0.0%|
[voipbl](#voipbl)|10426|10837|13|0.1%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|12|1.7%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|8193|8193|12|0.1%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2007|2007|7|0.3%|0.0%|
[et_compromised](#et_compromised)|2086|2086|6|0.2%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|5|0.0%|0.0%|
[dshield](#dshield)|20|5120|5|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|915|915|5|0.5%|0.0%|
[sorbs_socks](#sorbs_socks)|31|31|3|9.6%|0.0%|
[sorbs_misc](#sorbs_misc)|31|31|3|9.6%|0.0%|
[sorbs_http](#sorbs_http)|31|31|3|9.6%|0.0%|
[shunlist](#shunlist)|1261|1261|3|0.2%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2409|2409|3|0.1%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|2|0.1%|0.0%|
[zeus_badips](#zeus_badips)|202|202|1|0.4%|0.0%|
[zeus](#zeus)|231|231|1|0.4%|0.0%|
[openbl_30d](#openbl_30d)|3256|3256|1|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|
[ciarmy](#ciarmy)|396|396|1|0.2%|0.0%|

## virbl

[VirBL](http://virbl.bit.nl/) is a project of which the idea was born during the RIPE-48 meeting. The plan was to get reports of virusscanning mailservers, and put the IP-addresses that were reported to send viruses on a blacklist.

Source is downloaded from [this link](http://virbl.bit.nl/download/virbl.dnsbl.bit.nl.txt).

The last time downloaded was found to be dated: Fri Jun  5 09:52:04 UTC 2015.

The ipset `virbl` has **10** entries, **10** unique IPs.

The following table shows the overlaps of `virbl` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `virbl`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `virbl`.
- ` this % ` is the percentage **of this ipset (`virbl`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|1|0.0%|10.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|1|0.0%|10.0%|
[alienvault_reputation](#alienvault_reputation)|180239|180239|1|0.0%|10.0%|

## voipbl

[VoIPBL.org](http://www.voipbl.org/) a distributed VoIP blacklist that is aimed to protects against VoIP Fraud and minimizing abuse for network that have publicly accessible PBX's. Several algorithms, external sources and manual confirmation are used before they categorize something as an attack and determine the threat level.

Source is downloaded from [this link](http://www.voipbl.org/update/).

The last time downloaded was found to be dated: Fri Jun  5 08:09:11 UTC 2015.

The ipset `voipbl` has **10426** entries, **10837** unique IPs.

The following table shows the overlaps of `voipbl` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `voipbl`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `voipbl`.
- ` this % ` is the percentage **of this ipset (`voipbl`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|1596|0.0%|14.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|434|0.0%|4.0%|
[fullbogons](#fullbogons)|3715|670310296|319|0.0%|2.9%|
[bogons](#bogons)|13|592708608|319|0.0%|2.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|299|0.0%|2.7%|
[alienvault_reputation](#alienvault_reputation)|180239|180239|214|0.1%|1.9%|
[blocklist_de](#blocklist_de)|31150|31150|44|0.1%|0.4%|
[stopforumspam_30d](#stopforumspam_30d)|93498|93498|37|0.0%|0.3%|
[blocklist_de_sip](#blocklist_de_sip)|96|96|35|36.4%|0.3%|
[et_block](#et_block)|1016|18338655|21|0.0%|0.1%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|14|0.0%|0.1%|
[stopforumspam_7d](#stopforumspam_7d)|29882|29882|13|0.0%|0.1%|
[shunlist](#shunlist)|1261|1261|12|0.9%|0.1%|
[openbl_60d](#openbl_60d)|7689|7689|8|0.1%|0.0%|
[ciarmy](#ciarmy)|396|396|6|1.5%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7188|7188|5|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|4|0.0%|0.0%|
[openbl_30d](#openbl_30d)|3256|3256|3|0.0%|0.0%|
[et_tor](#et_tor)|6610|6610|3|0.0%|0.0%|
[dm_tor](#dm_tor)|6554|6554|3|0.0%|0.0%|
[bm_tor](#bm_tor)|6548|6548|3|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3243|3243|3|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13701|13701|3|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|2|0.0%|0.0%|
[et_compromised](#et_compromised)|2086|2086|2|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2007|2007|2|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|8193|8193|2|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9882|9882|1|0.0%|0.0%|
[openbl_7d](#openbl_7d)|910|910|1|0.1%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|16101|16101|1|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2409|2409|1|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2348|2348|1|0.0%|0.0%|

## xroxy

[xroxy.com](http://www.xroxy.com) open proxies (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.xroxy.com/proxyrss.xml).

The last time downloaded was found to be dated: Fri Jun  5 10:33:02 UTC 2015.

The ipset `xroxy` has **2079** entries, **2079** unique IPs.

The following table shows the overlaps of `xroxy` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `xroxy`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `xroxy`.
- ` this % ` is the percentage **of this ipset (`xroxy`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_30d](#stopforumspam_30d)|93498|93498|1219|1.3%|58.6%|
[ri_web_proxies](#ri_web_proxies)|6346|6346|884|13.9%|42.5%|
[stopforumspam_7d](#stopforumspam_7d)|29882|29882|772|2.5%|37.1%|
[proxyrss](#proxyrss)|1553|1553|421|27.1%|20.2%|
[ri_connect_proxies](#ri_connect_proxies)|2376|2376|360|15.1%|17.3%|
[proxz](#proxz)|776|776|316|40.7%|15.1%|
[stopforumspam_1d](#stopforumspam_1d)|7188|7188|295|4.1%|14.1%|
[blocklist_de](#blocklist_de)|31150|31150|265|0.8%|12.7%|
[blocklist_de_bots](#blocklist_de_bots)|3243|3243|210|6.4%|10.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|100|0.0%|4.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|92|0.0%|4.4%|
[sorbs_spam](#sorbs_spam)|28347|29370|84|0.2%|4.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|23675|24482|82|0.3%|3.9%|
[sorbs_new_spam](#sorbs_new_spam)|23675|24482|82|0.3%|3.9%|
[nixspam](#nixspam)|23361|23361|75|0.3%|3.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|58|0.0%|2.7%|
[blocklist_de_mail](#blocklist_de_mail)|16101|16101|56|0.3%|2.6%|
[snort_ipfilter](#snort_ipfilter)|9882|9882|51|0.5%|2.4%|
[php_dictionary](#php_dictionary)|508|508|31|6.1%|1.4%|
[sorbs_web](#sorbs_web)|785|787|27|3.4%|1.2%|
[php_spammers](#php_spammers)|461|461|22|4.7%|1.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|13|1.9%|0.6%|
[php_commenters](#php_commenters)|301|301|6|1.9%|0.2%|
[blocklist_de_strongips](#blocklist_de_strongips)|176|176|5|2.8%|0.2%|
[alienvault_reputation](#alienvault_reputation)|180239|180239|5|0.0%|0.2%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|3|0.0%|0.1%|
[php_harvesters](#php_harvesters)|298|298|2|0.6%|0.0%|
[et_tor](#et_tor)|6610|6610|2|0.0%|0.0%|
[dm_tor](#dm_tor)|6554|6554|2|0.0%|0.0%|
[bm_tor](#bm_tor)|6548|6548|2|0.0%|0.0%|
[sorbs_socks](#sorbs_socks)|31|31|1|3.2%|0.0%|
[sorbs_misc](#sorbs_misc)|31|31|1|3.2%|0.0%|
[sorbs_http](#sorbs_http)|31|31|1|3.2%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.0%|
[et_compromised](#et_compromised)|2086|2086|1|0.0%|0.0%|
[et_block](#et_block)|1016|18338655|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2007|2007|1|0.0%|0.0%|

## zeus

[Abuse.ch Zeus tracker](https://zeustracker.abuse.ch) standard, contains the same data as the ZeuS IP blocklist (zeus_badips) but with the slight difference that it doesn't exclude hijacked websites (level 2) and free web hosting providers (level 3). This means that this blocklist contains all IPv4 addresses associated with ZeuS C&Cs which are currently being tracked by ZeuS Tracker. Hence this blocklist will likely cause some false positives. - **excellent list**

Source is downloaded from [this link](https://zeustracker.abuse.ch/blocklist.php?download=ipblocklist).

The last time downloaded was found to be dated: Fri Jun  5 10:26:59 UTC 2015.

The ipset `zeus` has **231** entries, **231** unique IPs.

The following table shows the overlaps of `zeus` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `zeus`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `zeus`.
- ` this % ` is the percentage **of this ipset (`zeus`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[et_block](#et_block)|1016|18338655|223|0.0%|96.5%|
[zeus_badips](#zeus_badips)|202|202|202|100.0%|87.4%|
[snort_ipfilter](#snort_ipfilter)|9882|9882|200|2.0%|86.5%|
[alienvault_reputation](#alienvault_reputation)|180239|180239|62|0.0%|26.8%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|16|0.0%|6.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|14|0.0%|6.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|10|0.0%|4.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|9|0.0%|3.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|7|0.0%|3.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|486400|5|0.0%|2.1%|
[stopforumspam_30d](#stopforumspam_30d)|93498|93498|2|0.0%|0.8%|
[openbl_60d](#openbl_60d)|7689|7689|2|0.0%|0.8%|
[openbl_30d](#openbl_30d)|3256|3256|2|0.0%|0.8%|
[stopforumspam_7d](#stopforumspam_7d)|29882|29882|1|0.0%|0.4%|
[stopforumspam_1d](#stopforumspam_1d)|7188|7188|1|0.0%|0.4%|
[php_commenters](#php_commenters)|301|301|1|0.3%|0.4%|
[nixspam](#nixspam)|23361|23361|1|0.0%|0.4%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.4%|

## zeus_badips

[Abuse.ch Zeus tracker](https://zeustracker.abuse.ch) badips includes IPv4 addresses that are used by the ZeuS trojan. It is the recommened blocklist if you want to block only ZeuS IPs. It excludes IP addresses that ZeuS Tracker believes to be hijacked (level 2) or belong to a free web hosting provider (level 3). Hence the false postive rate should be much lower compared to the standard ZeuS IP blocklist. **excellent list**

Source is downloaded from [this link](https://zeustracker.abuse.ch/blocklist.php?download=badips).

The last time downloaded was found to be dated: Fri Jun  5 10:18:15 UTC 2015.

The ipset `zeus_badips` has **202** entries, **202** unique IPs.

The following table shows the overlaps of `zeus_badips` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `zeus_badips`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `zeus_badips`.
- ` this % ` is the percentage **of this ipset (`zeus_badips`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[zeus](#zeus)|231|231|202|87.4%|100.0%|
[et_block](#et_block)|1016|18338655|199|0.0%|98.5%|
[snort_ipfilter](#snort_ipfilter)|9882|9882|178|1.8%|88.1%|
[alienvault_reputation](#alienvault_reputation)|180239|180239|37|0.0%|18.3%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|16|0.0%|7.9%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|10|0.0%|4.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|9|0.0%|4.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|8|0.0%|3.9%|
[spamhaus_edrop](#spamhaus_edrop)|55|486400|5|0.0%|2.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|5|0.0%|2.4%|
[stopforumspam_30d](#stopforumspam_30d)|93498|93498|2|0.0%|0.9%|
[stopforumspam_7d](#stopforumspam_7d)|29882|29882|1|0.0%|0.4%|
[stopforumspam_1d](#stopforumspam_1d)|7188|7188|1|0.0%|0.4%|
[php_commenters](#php_commenters)|301|301|1|0.3%|0.4%|
[openbl_60d](#openbl_60d)|7689|7689|1|0.0%|0.4%|
[openbl_30d](#openbl_30d)|3256|3256|1|0.0%|0.4%|
[nixspam](#nixspam)|23361|23361|1|0.0%|0.4%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.4%|
