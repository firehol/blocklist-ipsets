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

The following list was automatically generated on Fri Jun  5 02:55:47 UTC 2015.

The update frequency is the maximum allowed by internal configuration. A list will never be downloaded sooner than the update frequency stated. A list may also not be downloaded, after this frequency expired, if it has not been modified on the server (as reported by HTTP `IF_MODIFIED_SINCE` method).

name|info|type|entries|update|
:--:|:--:|:--:|:-----:|:----:|
[alienvault_reputation](#alienvault_reputation)|[AlienVault.com](https://www.alienvault.com/) IP reputation database (this list seems to include port scanning hosts and to be updated regularly, but we found no information about its retention policy)|ipv4 hash:ip|177715 unique IPs|updated every 6 hours  from [this link](https://reputation.alienvault.com/reputation.generic)
[blocklist_de](#blocklist_de)|[Blocklist.de](https://www.blocklist.de/) IPs that have been detected by fail2ban in the last 48 hours - **excellent list**|ipv4 hash:ip|33391 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/all.txt)
[blocklist_de_apache](#blocklist_de_apache)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service Apache, Apache-DDOS, RFI-Attacks.|ipv4 hash:ip|13971 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/apache.txt)
[blocklist_de_bots](#blocklist_de_bots)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the RFI-Attacks, REG-Bots, IRC-Bots or BadBots (BadBots = he has posted a Spam-Comment on a open Forum or Wiki).|ipv4 hash:ip|3165 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/bots.txt)
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|[Blocklist.de](https://www.blocklist.de/) All IPs which attacks Joomlas, Wordpress and other Web-Logins with Brute-Force Logins.|ipv4 hash:ip|2620 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/bruteforcelogin.txt)
[blocklist_de_ftp](#blocklist_de_ftp)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours for attacks on the Service FTP.|ipv4 hash:ip|912 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/ftp.txt)
[blocklist_de_imap](#blocklist_de_imap)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours for attacks on the Service imap, sasl, pop3, etc.|ipv4 hash:ip|2784 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/imap.txt)
[blocklist_de_mail](#blocklist_de_mail)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service Mail, Postfix.|ipv4 hash:ip|16579 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/mail.txt)
[blocklist_de_sip](#blocklist_de_sip)|[Blocklist.de](https://www.blocklist.de/) All IP addresses that tried to login in a SIP, VOIP or Asterisk Server and are included in the IPs list from [infiltrated.net](www.infiltrated.net)|ipv4 hash:ip|101 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/sip.txt)
[blocklist_de_ssh](#blocklist_de_ssh)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service SSH.|ipv4 hash:ip|9757 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/ssh.txt)
[blocklist_de_strongips](#blocklist_de_strongips)|[Blocklist.de](https://www.blocklist.de/) All IPs which are older then 2 month and have more then 5.000 attacks.|ipv4 hash:ip|177 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/strongips.txt)
[bm_tor](#bm_tor)|[torstatus.blutmagie.de](https://torstatus.blutmagie.de) list of all TOR network servers|ipv4 hash:ip|6497 unique IPs|updated every 30 mins  from [this link](https://torstatus.blutmagie.de/ip_list_all.php/Tor_ip_list_ALL.csv)
[bogons](#bogons)|[Team-Cymru.org](http://www.team-cymru.org) private and reserved addresses defined by RFC 1918, RFC 5735, and RFC 6598 and netblocks that have not been allocated to a regional internet registry - **excellent list - use it only your internet interface**|ipv4 hash:net|13 subnets, 592708608 unique IPs|updated every 1 day  from [this link](http://www.team-cymru.org/Services/Bogons/bogon-bn-agg.txt)
[bruteforceblocker](#bruteforceblocker)|[danger.rulez.sk](http://danger.rulez.sk/) IPs detected by [bruteforceblocker](http://danger.rulez.sk/index.php/bruteforceblocker/) (fail2ban alternative for SSH on OpenBSD). This is an automatically generated list from users reporting failed authentication attempts. An IP seems to be included if 3 or more users report it. Its retention pocily seems 30 days.|ipv4 hash:ip|2024 unique IPs|updated every 3 hours  from [this link](http://danger.rulez.sk/projects/bruteforceblocker/blist.php)
[ciarmy](#ciarmy)|[CIArmy.com](http://ciarmy.com/) IPs with poor Rogue Packet score that have not yet been identified as malicious by the community|ipv4 hash:ip|329 unique IPs|updated every 3 hours  from [this link](http://cinsscore.com/list/ci-badguys.txt)
[cleanmx_viruses](#cleanmx_viruses)|[Clean-MX.de](http://support.clean-mx.de/clean-mx/viruses.php) IPs with viruses|ipv4 hash:ip|370 unique IPs|updated every 12 hours  from [this link](http://support.clean-mx.de/clean-mx/xmlviruses.php?sort=id%20desc&response=alive)
[dm_tor](#dm_tor)|[dan.me.uk](https://www.dan.me.uk) dynamic list of TOR exit points|ipv4 hash:ip|6496 unique IPs|updated every 30 mins  from [this link](https://www.dan.me.uk/torlist/)
[dshield](#dshield)|[DShield.org](https://dshield.org/) top 20 attacking class C (/24) subnets over the last three days - **excellent list**|ipv4 hash:net|20 subnets, 5120 unique IPs|updated every 4 hours  from [this link](http://feeds.dshield.org/block.txt)
[et_block](#et_block)|[EmergingThreats.net](http://www.emergingthreats.net/) default blacklist (at the time of writing includes spamhaus DROP, dshield and abuse.ch trackers, which are available separately too - prefer to use the direct ipsets instead of this, they seem to lag a bit in updates)|ipv4 hash:net|1007 subnets, 18338646 unique IPs|updated every 12 hours  from [this link](http://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt)
[et_botcc](#et_botcc)|[EmergingThreats.net Command and Control IPs](http://doc.emergingthreats.net/bin/view/Main/BotCC) These IPs are updates every 24 hours and should be considered VERY highly reliable indications that a host is communicating with a known and active Bot or Malware command and control server - (although they say this includes abuse.ch trackers, it does not - most probably it is the shadowserver.org C&C list)|ipv4 hash:ip|508 unique IPs|updated every 12 hours  from [this link](http://rules.emergingthreats.net/fwrules/emerging-PIX-CC.rules)
[et_compromised](#et_compromised)|[EmergingThreats.net compromised hosts](http://doc.emergingthreats.net/bin/view/Main/CompromisedHost) - (this seems to be based on bruteforceblocker)|ipv4 hash:ip|2171 unique IPs|updated every 12 hours  from [this link](http://rules.emergingthreats.net/blockrules/compromised-ips.txt)
et_dshield|[EmergingThreats.net](http://www.emergingthreats.net/) dshield blocklist|ipv4 hash:net|disabled|updated every 12 hours  from [this link](http://rules.emergingthreats.net/fwrules/emerging-PIX-DSHIELD.rules)
et_spamhaus|[EmergingThreats.net](http://www.emergingthreats.net/) spamhaus blocklist|ipv4 hash:net|disabled|updated every 12 hours  from [this link](http://rules.emergingthreats.net/fwrules/emerging-PIX-DROP.rules)
[et_tor](#et_tor)|[EmergingThreats.net](http://www.emergingthreats.net/) [list](http://doc.emergingthreats.net/bin/view/Main/TorRules) of TOR network IPs|ipv4 hash:ip|6380 unique IPs|updated every 12 hours  from [this link](http://rules.emergingthreats.net/blockrules/emerging-tor.rules)
[feodo](#feodo)|[Abuse.ch Feodo tracker](https://feodotracker.abuse.ch) trojan includes IPs which are being used by Feodo (also known as Cridex or Bugat) which commits ebanking fraud - **excellent list**|ipv4 hash:ip|94 unique IPs|updated every 30 mins  from [this link](https://feodotracker.abuse.ch/blocklist/?download=ipblocklist)
[fullbogons](#fullbogons)|[Team-Cymru.org](http://www.team-cymru.org) IP space that has been allocated to an RIR, but not assigned by that RIR to an actual ISP or other end-user - **excellent list - use it only your internet interface**|ipv4 hash:net|3733 subnets, 670419608 unique IPs|updated every 1 day  from [this link](http://www.team-cymru.org/Services/Bogons/fullbogons-ipv4.txt)
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
[nixspam](#nixspam)|[NiX Spam](http://www.heise.de/ix/NiX-Spam-DNSBL-and-blacklist-for-download-499637.html) IP addresses that sent spam in the last hour - automatically generated entries without distinguishing open proxies from relays, dialup gateways, and so on. All IPs are removed after 12 hours if there is no spam from there.|ipv4 hash:ip|18430 unique IPs|updated every 15 mins  from [this link](http://www.dnsbl.manitu.net/download/nixspam-ip.dump.gz)
openbl|[OpenBL.org](http://www.openbl.org/) default blacklist (currently it is the same with 90 days). OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications - **excellent list**|ipv4 hash:ip|disabled|updated every 4 hours  from [this link](http://www.openbl.org/lists/base.txt)
openbl_180d|[OpenBL.org](http://www.openbl.org/) last 180 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|disabled|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_180days.txt)
[openbl_1d](#openbl_1d)|[OpenBL.org](http://www.openbl.org/) last 24 hours IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|174 unique IPs|updated every 1 hour  from [this link](http://www.openbl.org/lists/base_1days.txt)
[openbl_30d](#openbl_30d)|[OpenBL.org](http://www.openbl.org/) last 30 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|3260 unique IPs|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_30days.txt)
openbl_360d|[OpenBL.org](http://www.openbl.org/) last 360 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|disabled|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_360days.txt)
[openbl_60d](#openbl_60d)|[OpenBL.org](http://www.openbl.org/) last 60 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|7695 unique IPs|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_60days.txt)
[openbl_7d](#openbl_7d)|[OpenBL.org](http://www.openbl.org/) last 7 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|927 unique IPs|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_7days.txt)
openbl_90d|[OpenBL.org](http://www.openbl.org/) last 90 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|disabled|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_90days.txt)
openbl_all|[OpenBL.org](http://www.openbl.org/) last all IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|disabled|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_all.txt)
[palevo](#palevo)|[Abuse.ch Palevo tracker](https://palevotracker.abuse.ch) worm includes IPs which are being used as botnet C&C for the Palevo crimeware - **excellent list**|ipv4 hash:ip|13 unique IPs|updated every 30 mins  from [this link](https://palevotracker.abuse.ch/blocklists.php?download=ipblocklist)
php_bad|[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) bad web hosts (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|disabled|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=b&rss=1)
[php_commenters](#php_commenters)|[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) comment spammers (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|301 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=c&rss=1)
[php_dictionary](#php_dictionary)|[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) directory attackers (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|475 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=d&rss=1)
[php_harvesters](#php_harvesters)|[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) harvesters (IPs that surf the internet looking for email addresses) (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|298 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=h&rss=1)
[php_spammers](#php_spammers)|[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) spam servers (IPs used by spammers to send messages) (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|461 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=s&rss=1)
[proxyrss](#proxyrss)|[proxyrss.com](http://www.proxyrss.com) open proxies syndicated from multiple sources.|ipv4 hash:ip|1772 unique IPs|updated every 4 hours  from [this link](http://www.proxyrss.com/proxylists/all.gz)
[proxz](#proxz)|[proxz.com](http://www.proxz.com) open proxies (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|747 unique IPs|updated every 1 hour  from [this link](http://www.proxz.com/proxylists.xml)
[ri_connect_proxies](#ri_connect_proxies)|[rosinstrument.com](http://www.rosinstrument.com) open CONNECT proxies (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|2352 unique IPs|updated every 1 hour  from [this link](http://tools.rosinstrument.com/proxy/plab100.xml)
[ri_web_proxies](#ri_web_proxies)|[rosinstrument.com](http://www.rosinstrument.com) open HTTP proxies (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|6295 unique IPs|updated every 1 hour  from [this link](http://tools.rosinstrument.com/proxy/l100.xml)
[shunlist](#shunlist)|[AutoShun.org](http://autoshun.org/) IPs identified as hostile by correlating logs from distributed snort installations running the autoshun plugin|ipv4 hash:ip|1254 unique IPs|updated every 4 hours  from [this link](http://www.autoshun.org/files/shunlist.csv)
[snort_ipfilter](#snort_ipfilter)|[labs.snort.org](https://labs.snort.org/) supplied IP blacklist (this list seems to be updated frequently, but we found no information about it)|ipv4 hash:ip|9882 unique IPs|updated every 12 hours  from [this link](http://labs.snort.org/feeds/ip-filter.blf)
[sorbs_dul](#sorbs_dul)|[Sorbs.net](https://www.sorbs.net/) DUL, Dynamic User IPs extracted from deltas.|ipv4 hash:net|8 subnets, 3584 unique IPs|updated every 1 min  from [this link]()
[sorbs_http](#sorbs_http)|[Sorbs.net](https://www.sorbs.net/) HTTP proxies, extracted from deltas.|ipv4 hash:net|29 subnets, 29 unique IPs|updated every 1 min  from [this link]()
[sorbs_misc](#sorbs_misc)|[Sorbs.net](https://www.sorbs.net/) MISC proxies, extracted from deltas.|ipv4 hash:net|29 subnets, 29 unique IPs|updated every 1 min  from [this link]()
[sorbs_new_spam](#sorbs_new_spam)|[Sorbs.net](https://www.sorbs.net/) NEW Spam senders, extracted from deltas.|ipv4 hash:net|21123 subnets, 21796 unique IPs|updated every 1 min  from [this link]()
[sorbs_recent_spam](#sorbs_recent_spam)|[Sorbs.net](https://www.sorbs.net/) RECENT Spam senders, extracted from deltas.|ipv4 hash:net|21123 subnets, 21796 unique IPs|updated every 1 min  from [this link]()
[sorbs_smtp](#sorbs_smtp)|[Sorbs.net](https://www.sorbs.net/) SMTP Open Relays, extracted from deltas.|ipv4 hash:net|14 subnets, 14 unique IPs|updated every 1 min  from [this link]()
[sorbs_socks](#sorbs_socks)|[Sorbs.net](https://www.sorbs.net/) SOCKS proxies, extracted from deltas.|ipv4 hash:net|29 subnets, 29 unique IPs|updated every 1 min  from [this link]()
[sorbs_spam](#sorbs_spam)|[Sorbs.net](https://www.sorbs.net/) Spam senders, extracted from deltas.|ipv4 hash:net|25876 subnets, 26785 unique IPs|updated every 1 min  from [this link]()
[sorbs_web](#sorbs_web)|[Sorbs.net](https://www.sorbs.net/) WEB exploits, extracted from deltas.|ipv4 hash:net|749 subnets, 751 unique IPs|updated every 1 min  from [this link]()
[spamhaus_drop](#spamhaus_drop)|[Spamhaus.org](http://www.spamhaus.org) DROP list (according to their site this list should be dropped at tier-1 ISPs globaly) - **excellent list**|ipv4 hash:net|653 subnets, 18404096 unique IPs|updated every 12 hours  from [this link](http://www.spamhaus.org/drop/drop.txt)
[spamhaus_edrop](#spamhaus_edrop)|[Spamhaus.org](http://www.spamhaus.org) EDROP (extended matches that should be used with DROP) - **excellent list**|ipv4 hash:net|55 subnets, 486400 unique IPs|updated every 12 hours  from [this link](http://www.spamhaus.org/drop/edrop.txt)
[sslbl](#sslbl)|[Abuse.ch SSL Blacklist](https://sslbl.abuse.ch/) bad SSL traffic related to malware or botnet activities - **excellent list**|ipv4 hash:ip|365 unique IPs|updated every 30 mins  from [this link](https://sslbl.abuse.ch/blacklist/sslipblacklist.csv)
stopforumspam_180d|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 180 days)|ipv4 hash:ip|disabled|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/listed_ip_180.zip)
[stopforumspam_1d](#stopforumspam_1d)|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers in the last 24 hours - **excellent list**|ipv4 hash:ip|7048 unique IPs|updated every 1 hour  from [this link](http://www.stopforumspam.com/downloads/listed_ip_1.zip)
[stopforumspam_30d](#stopforumspam_30d)|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 30 days)|ipv4 hash:ip|93498 unique IPs|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/listed_ip_30.zip)
stopforumspam_365d|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 365 days)|ipv4 hash:ip|disabled|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/listed_ip_365.zip)
[stopforumspam_7d](#stopforumspam_7d)|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 7 days)|ipv4 hash:ip|29882 unique IPs|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/listed_ip_7.zip)
stopforumspam_90d|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 90 days)|ipv4 hash:ip|disabled|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/listed_ip_90.zip)
stopforumspam_ever|[StopForumSpam.com](http://www.stopforumspam.com) all IPs used by forum spammers, **ever** (normally you don't want to use this ipset, use the hourly one which includes last 24 hours IPs or the 7 days one)|ipv4 hash:ip|disabled|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/bannedips.zip)
[virbl](#virbl)|[VirBL](http://virbl.bit.nl/) is a project of which the idea was born during the RIPE-48 meeting. The plan was to get reports of virusscanning mailservers, and put the IP-addresses that were reported to send viruses on a blacklist.|ipv4 hash:ip|10 unique IPs|updated every 1 hour  from [this link](http://virbl.bit.nl/download/virbl.dnsbl.bit.nl.txt)
[voipbl](#voipbl)|[VoIPBL.org](http://www.voipbl.org/) a distributed VoIP blacklist that is aimed to protects against VoIP Fraud and minimizing abuse for network that have publicly accessible PBX's. Several algorithms, external sources and manual confirmation are used before they categorize something as an attack and determine the threat level.|ipv4 hash:net|10426 subnets, 10837 unique IPs|updated every 4 hours  from [this link](http://www.voipbl.org/update/)
[xroxy](#xroxy)|[xroxy.com](http://www.xroxy.com) open proxies (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|2076 unique IPs|updated every 1 hour  from [this link](http://www.xroxy.com/proxyrss.xml)
[zeus](#zeus)|[Abuse.ch Zeus tracker](https://zeustracker.abuse.ch) standard, contains the same data as the ZeuS IP blocklist (zeus_badips) but with the slight difference that it doesn't exclude hijacked websites (level 2) and free web hosting providers (level 3). This means that this blocklist contains all IPv4 addresses associated with ZeuS C&Cs which are currently being tracked by ZeuS Tracker. Hence this blocklist will likely cause some false positives. - **excellent list**|ipv4 hash:ip|269 unique IPs|updated every 30 mins  from [this link](https://zeustracker.abuse.ch/blocklist.php?download=ipblocklist)
[zeus_badips](#zeus_badips)|[Abuse.ch Zeus tracker](https://zeustracker.abuse.ch) badips includes IPv4 addresses that are used by the ZeuS trojan. It is the recommened blocklist if you want to block only ZeuS IPs. It excludes IP addresses that ZeuS Tracker believes to be hijacked (level 2) or belong to a free web hosting provider (level 3). Hence the false postive rate should be much lower compared to the standard ZeuS IP blocklist. **excellent list**|ipv4 hash:ip|235 unique IPs|updated every 30 mins  from [this link](https://zeustracker.abuse.ch/blocklist.php?download=badips)

# Comparison of ipsets

Below we compare each ipset against all other.


## alienvault_reputation

[AlienVault.com](https://www.alienvault.com/) IP reputation database (this list seems to include port scanning hosts and to be updated regularly, but we found no information about its retention policy)

Source is downloaded from [this link](https://reputation.alienvault.com/reputation.generic).

The last time downloaded was found to be dated: Thu Jun  4 22:01:09 UTC 2015.

The ipset `alienvault_reputation` has **177715** entries, **177715** unique IPs.

The following table shows the overlaps of `alienvault_reputation` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `alienvault_reputation`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `alienvault_reputation`.
- ` this % ` is the percentage **of this ipset (`alienvault_reputation`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|14082|0.0%|7.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|7785|0.0%|4.3%|
[openbl_60d](#openbl_60d)|7695|7695|7672|99.7%|4.3%|
[et_block](#et_block)|1007|18338646|5538|0.0%|3.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|4428|0.0%|2.4%|
[dshield](#dshield)|20|5120|4111|80.2%|2.3%|
[openbl_30d](#openbl_30d)|3260|3260|3243|99.4%|1.8%|
[blocklist_de](#blocklist_de)|33391|33391|1953|5.8%|1.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|9757|9757|1720|17.6%|0.9%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|1630|0.0%|0.9%|
[et_compromised](#et_compromised)|2171|2171|1411|64.9%|0.7%|
[bruteforceblocker](#bruteforceblocker)|2024|2024|1312|64.8%|0.7%|
[shunlist](#shunlist)|1254|1254|1240|98.8%|0.6%|
[openbl_7d](#openbl_7d)|927|927|919|99.1%|0.5%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|518|0.0%|0.2%|
[ciarmy](#ciarmy)|329|329|321|97.5%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|286|0.0%|0.1%|
[stopforumspam_30d](#stopforumspam_30d)|93498|93498|207|0.2%|0.1%|
[voipbl](#voipbl)|10426|10837|204|1.8%|0.1%|
[openbl_1d](#openbl_1d)|174|174|167|95.9%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13971|13971|132|0.9%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9882|9882|124|1.2%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29882|29882|95|0.3%|0.0%|
[sorbs_spam](#sorbs_spam)|25876|26785|83|0.3%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|21123|21796|74|0.3%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|21123|21796|74|0.3%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|16579|16579|66|0.3%|0.0%|
[zeus](#zeus)|269|269|65|24.1%|0.0%|
[sslbl](#sslbl)|365|365|64|17.5%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7048|7048|53|0.7%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2784|2784|46|1.6%|0.0%|
[et_tor](#et_tor)|6380|6380|43|0.6%|0.0%|
[dm_tor](#dm_tor)|6496|6496|42|0.6%|0.0%|
[bm_tor](#bm_tor)|6497|6497|42|0.6%|0.0%|
[zeus_badips](#zeus_badips)|235|235|38|16.1%|0.0%|
[nixspam](#nixspam)|18430|18430|37|0.2%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|177|177|35|19.7%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|26|6.9%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3165|3165|22|0.6%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2620|2620|18|0.6%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|101|101|17|16.8%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|486400|15|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|15|0.0%|0.0%|
[php_commenters](#php_commenters)|301|301|14|4.6%|0.0%|
[malc0de](#malc0de)|379|379|11|2.9%|0.0%|
[php_harvesters](#php_harvesters)|298|298|10|3.3%|0.0%|
[php_dictionary](#php_dictionary)|475|475|8|1.6%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|8|0.5%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|912|912|7|0.7%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|6|0.4%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|370|370|6|1.6%|0.0%|
[xroxy](#xroxy)|2076|2076|5|0.2%|0.0%|
[php_spammers](#php_spammers)|461|461|5|1.0%|0.0%|
[et_botcc](#et_botcc)|508|508|4|0.7%|0.0%|
[ri_web_proxies](#ri_web_proxies)|6295|6295|3|0.0%|0.0%|
[proxz](#proxz)|747|747|3|0.4%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2352|2352|2|0.0%|0.0%|
[proxyrss](#proxyrss)|1772|1772|2|0.1%|0.0%|
[feodo](#feodo)|94|94|2|2.1%|0.0%|
[virbl](#virbl)|10|10|1|10.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|1|0.1%|0.0%|

## blocklist_de

[Blocklist.de](https://www.blocklist.de/) IPs that have been detected by fail2ban in the last 48 hours - **excellent list**

Source is downloaded from [this link](http://lists.blocklist.de/lists/all.txt).

The last time downloaded was found to be dated: Fri Jun  5 02:42:03 UTC 2015.

The ipset `blocklist_de` has **33391** entries, **33391** unique IPs.

The following table shows the overlaps of `blocklist_de` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de`.
- ` this % ` is the percentage **of this ipset (`blocklist_de`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de_mail](#blocklist_de_mail)|16579|16579|16572|99.9%|49.6%|
[blocklist_de_apache](#blocklist_de_apache)|13971|13971|13971|100.0%|41.8%|
[blocklist_de_ssh](#blocklist_de_ssh)|9757|9757|9757|100.0%|29.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|5288|0.0%|15.8%|
[blocklist_de_bots](#blocklist_de_bots)|3165|3165|3158|99.7%|9.4%|
[blocklist_de_imap](#blocklist_de_imap)|2784|2784|2781|99.8%|8.3%|
[stopforumspam_30d](#stopforumspam_30d)|93498|93498|2667|2.8%|7.9%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2620|2620|2620|100.0%|7.8%|
[stopforumspam_7d](#stopforumspam_7d)|29882|29882|2302|7.7%|6.8%|
[alienvault_reputation](#alienvault_reputation)|177715|177715|1953|1.0%|5.8%|
[openbl_60d](#openbl_60d)|7695|7695|1632|21.2%|4.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|1594|0.0%|4.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|1554|0.0%|4.6%|
[stopforumspam_1d](#stopforumspam_1d)|7048|7048|1464|20.7%|4.3%|
[sorbs_spam](#sorbs_spam)|25876|26785|1011|3.7%|3.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|21123|21796|979|4.4%|2.9%|
[sorbs_new_spam](#sorbs_new_spam)|21123|21796|979|4.4%|2.9%|
[blocklist_de_ftp](#blocklist_de_ftp)|912|912|910|99.7%|2.7%|
[openbl_30d](#openbl_30d)|3260|3260|853|26.1%|2.5%|
[bruteforceblocker](#bruteforceblocker)|2024|2024|689|34.0%|2.0%|
[et_compromised](#et_compromised)|2171|2171|660|30.4%|1.9%|
[nixspam](#nixspam)|18430|18430|608|3.2%|1.8%|
[openbl_7d](#openbl_7d)|927|927|568|61.2%|1.7%|
[ri_web_proxies](#ri_web_proxies)|6295|6295|415|6.5%|1.2%|
[shunlist](#shunlist)|1254|1254|394|31.4%|1.1%|
[xroxy](#xroxy)|2076|2076|269|12.9%|0.8%|
[proxyrss](#proxyrss)|1772|1772|267|15.0%|0.7%|
[snort_ipfilter](#snort_ipfilter)|9882|9882|182|1.8%|0.5%|
[blocklist_de_strongips](#blocklist_de_strongips)|177|177|177|100.0%|0.5%|
[et_block](#et_block)|1007|18338646|169|0.0%|0.5%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|166|0.0%|0.4%|
[openbl_1d](#openbl_1d)|174|174|139|79.8%|0.4%|
[proxz](#proxz)|747|747|137|18.3%|0.4%|
[dshield](#dshield)|20|5120|119|2.3%|0.3%|
[sorbs_web](#sorbs_web)|749|751|94|12.5%|0.2%|
[blocklist_de_sip](#blocklist_de_sip)|101|101|82|81.1%|0.2%|
[ri_connect_proxies](#ri_connect_proxies)|2352|2352|77|3.2%|0.2%|
[php_commenters](#php_commenters)|301|301|76|25.2%|0.2%|
[php_dictionary](#php_dictionary)|475|475|65|13.6%|0.1%|
[php_spammers](#php_spammers)|461|461|63|13.6%|0.1%|
[voipbl](#voipbl)|10426|10837|47|0.4%|0.1%|
[ciarmy](#ciarmy)|329|329|39|11.8%|0.1%|
[php_harvesters](#php_harvesters)|298|298|33|11.0%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|33|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|12|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|486400|9|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|9|0.0%|0.0%|
[sorbs_socks](#sorbs_socks)|29|29|7|24.1%|0.0%|
[sorbs_misc](#sorbs_misc)|29|29|7|24.1%|0.0%|
[sorbs_http](#sorbs_http)|29|29|7|24.1%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|6|0.8%|0.0%|
[dm_tor](#dm_tor)|6496|6496|4|0.0%|0.0%|
[bm_tor](#bm_tor)|6497|6497|4|0.0%|0.0%|
[et_tor](#et_tor)|6380|6380|3|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|2|0.5%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.0%|
[sslbl](#sslbl)|365|365|1|0.2%|0.0%|

## blocklist_de_apache

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service Apache, Apache-DDOS, RFI-Attacks.

Source is downloaded from [this link](http://lists.blocklist.de/lists/apache.txt).

The last time downloaded was found to be dated: Fri Jun  5 02:30:10 UTC 2015.

The ipset `blocklist_de_apache` has **13971** entries, **13971** unique IPs.

The following table shows the overlaps of `blocklist_de_apache` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_apache`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_apache`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_apache`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|33391|33391|13971|41.8%|100.0%|
[blocklist_de_mail](#blocklist_de_mail)|16579|16579|11059|66.7%|79.1%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2620|2620|2620|100.0%|18.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|2315|0.0%|16.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|1329|0.0%|9.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|1070|0.0%|7.6%|
[stopforumspam_30d](#stopforumspam_30d)|93498|93498|215|0.2%|1.5%|
[stopforumspam_7d](#stopforumspam_7d)|29882|29882|135|0.4%|0.9%|
[alienvault_reputation](#alienvault_reputation)|177715|177715|132|0.0%|0.9%|
[sorbs_spam](#sorbs_spam)|25876|26785|77|0.2%|0.5%|
[sorbs_recent_spam](#sorbs_recent_spam)|21123|21796|74|0.3%|0.5%|
[sorbs_new_spam](#sorbs_new_spam)|21123|21796|74|0.3%|0.5%|
[stopforumspam_1d](#stopforumspam_1d)|7048|7048|70|0.9%|0.5%|
[shunlist](#shunlist)|1254|1254|36|2.8%|0.2%|
[ciarmy](#ciarmy)|329|329|36|10.9%|0.2%|
[blocklist_de_strongips](#blocklist_de_strongips)|177|177|36|20.3%|0.2%|
[nixspam](#nixspam)|18430|18430|25|0.1%|0.1%|
[php_commenters](#php_commenters)|301|301|24|7.9%|0.1%|
[blocklist_de_bots](#blocklist_de_bots)|3165|3165|24|0.7%|0.1%|
[snort_ipfilter](#snort_ipfilter)|9882|9882|8|0.0%|0.0%|
[dshield](#dshield)|20|5120|8|0.1%|0.0%|
[php_spammers](#php_spammers)|461|461|6|1.3%|0.0%|
[php_dictionary](#php_dictionary)|475|475|5|1.0%|0.0%|
[et_block](#et_block)|1007|18338646|5|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|4|0.0%|0.0%|
[php_harvesters](#php_harvesters)|298|298|4|1.3%|0.0%|
[openbl_60d](#openbl_60d)|7695|7695|4|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|4|0.0%|0.0%|
[dm_tor](#dm_tor)|6496|6496|4|0.0%|0.0%|
[bm_tor](#bm_tor)|6497|6497|4|0.0%|0.0%|
[voipbl](#voipbl)|10426|10837|3|0.0%|0.0%|
[sorbs_web](#sorbs_web)|749|751|3|0.3%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|3|0.0%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|0.0%|
[et_tor](#et_tor)|6380|6380|3|0.0%|0.0%|
[et_compromised](#et_compromised)|2171|2171|3|0.1%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|486400|2|0.0%|0.0%|
[openbl_30d](#openbl_30d)|3260|3260|2|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|2|0.5%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2024|2024|2|0.0%|0.0%|
[xroxy](#xroxy)|2076|2076|1|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|6295|6295|1|0.0%|0.0%|
[proxyrss](#proxyrss)|1772|1772|1|0.0%|0.0%|
[openbl_7d](#openbl_7d)|927|927|1|0.1%|0.0%|
[openbl_1d](#openbl_1d)|174|174|1|0.5%|0.0%|

## blocklist_de_bots

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the RFI-Attacks, REG-Bots, IRC-Bots or BadBots (BadBots = he has posted a Spam-Comment on a open Forum or Wiki).

Source is downloaded from [this link](http://lists.blocklist.de/lists/bots.txt).

The last time downloaded was found to be dated: Fri Jun  5 02:30:13 UTC 2015.

The ipset `blocklist_de_bots` has **3165** entries, **3165** unique IPs.

The following table shows the overlaps of `blocklist_de_bots` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_bots`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_bots`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_bots`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|33391|33391|3158|9.4%|99.7%|
[stopforumspam_30d](#stopforumspam_30d)|93498|93498|2256|2.4%|71.2%|
[stopforumspam_7d](#stopforumspam_7d)|29882|29882|2086|6.9%|65.9%|
[stopforumspam_1d](#stopforumspam_1d)|7048|7048|1386|19.6%|43.7%|
[ri_web_proxies](#ri_web_proxies)|6295|6295|359|5.7%|11.3%|
[proxyrss](#proxyrss)|1772|1772|266|15.0%|8.4%|
[xroxy](#xroxy)|2076|2076|211|10.1%|6.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|167|0.0%|5.2%|
[blocklist_de_strongips](#blocklist_de_strongips)|177|177|133|75.1%|4.2%|
[proxz](#proxz)|747|747|113|15.1%|3.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|95|0.0%|3.0%|
[ri_connect_proxies](#ri_connect_proxies)|2352|2352|73|3.1%|2.3%|
[php_commenters](#php_commenters)|301|301|62|20.5%|1.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|45|0.0%|1.4%|
[nixspam](#nixspam)|18430|18430|44|0.2%|1.3%|
[sorbs_spam](#sorbs_spam)|25876|26785|32|0.1%|1.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|21123|21796|31|0.1%|0.9%|
[sorbs_new_spam](#sorbs_new_spam)|21123|21796|31|0.1%|0.9%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|27|0.0%|0.8%|
[et_block](#et_block)|1007|18338646|27|0.0%|0.8%|
[blocklist_de_mail](#blocklist_de_mail)|16579|16579|24|0.1%|0.7%|
[blocklist_de_apache](#blocklist_de_apache)|13971|13971|24|0.1%|0.7%|
[php_harvesters](#php_harvesters)|298|298|23|7.7%|0.7%|
[alienvault_reputation](#alienvault_reputation)|177715|177715|22|0.0%|0.6%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|18|0.0%|0.5%|
[snort_ipfilter](#snort_ipfilter)|9882|9882|17|0.1%|0.5%|
[php_spammers](#php_spammers)|461|461|8|1.7%|0.2%|
[php_dictionary](#php_dictionary)|475|475|8|1.6%|0.2%|
[sorbs_web](#sorbs_web)|749|751|7|0.9%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|4|0.0%|0.1%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|4|0.5%|0.1%|
[spamhaus_edrop](#spamhaus_edrop)|55|486400|3|0.0%|0.0%|
[openbl_60d](#openbl_60d)|7695|7695|3|0.0%|0.0%|
[voipbl](#voipbl)|10426|10837|2|0.0%|0.0%|
[sorbs_socks](#sorbs_socks)|29|29|2|6.8%|0.0%|
[sorbs_misc](#sorbs_misc)|29|29|2|6.8%|0.0%|
[sorbs_http](#sorbs_http)|29|29|2|6.8%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2024|2024|2|0.0%|0.0%|
[openbl_30d](#openbl_30d)|3260|3260|1|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|
[et_compromised](#et_compromised)|2171|2171|1|0.0%|0.0%|

## blocklist_de_bruteforce

[Blocklist.de](https://www.blocklist.de/) All IPs which attacks Joomlas, Wordpress and other Web-Logins with Brute-Force Logins.

Source is downloaded from [this link](http://lists.blocklist.de/lists/bruteforcelogin.txt).

The last time downloaded was found to be dated: Fri Jun  5 02:42:16 UTC 2015.

The ipset `blocklist_de_bruteforce` has **2620** entries, **2620** unique IPs.

The following table shows the overlaps of `blocklist_de_bruteforce` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_bruteforce`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_bruteforce`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_bruteforce`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de_apache](#blocklist_de_apache)|13971|13971|2620|18.7%|100.0%|
[blocklist_de](#blocklist_de)|33391|33391|2620|7.8%|100.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|218|0.0%|8.3%|
[sorbs_spam](#sorbs_spam)|25876|26785|77|0.2%|2.9%|
[sorbs_recent_spam](#sorbs_recent_spam)|21123|21796|74|0.3%|2.8%|
[sorbs_new_spam](#sorbs_new_spam)|21123|21796|74|0.3%|2.8%|
[stopforumspam_30d](#stopforumspam_30d)|93498|93498|43|0.0%|1.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|39|0.0%|1.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|37|0.0%|1.4%|
[stopforumspam_7d](#stopforumspam_7d)|29882|29882|29|0.0%|1.1%|
[nixspam](#nixspam)|18430|18430|24|0.1%|0.9%|
[stopforumspam_1d](#stopforumspam_1d)|7048|7048|19|0.2%|0.7%|
[alienvault_reputation](#alienvault_reputation)|177715|177715|18|0.0%|0.6%|
[blocklist_de_strongips](#blocklist_de_strongips)|177|177|7|3.9%|0.2%|
[php_spammers](#php_spammers)|461|461|6|1.3%|0.2%|
[php_dictionary](#php_dictionary)|475|475|5|1.0%|0.1%|
[php_commenters](#php_commenters)|301|301|5|1.6%|0.1%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|4|0.0%|0.1%|
[snort_ipfilter](#snort_ipfilter)|9882|9882|4|0.0%|0.1%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|4|0.0%|0.1%|
[sorbs_web](#sorbs_web)|749|751|3|0.3%|0.1%|
[shunlist](#shunlist)|1254|1254|3|0.2%|0.1%|
[et_block](#et_block)|1007|18338646|3|0.0%|0.1%|
[php_harvesters](#php_harvesters)|298|298|2|0.6%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|2|0.0%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2|0.0%|0.0%|
[xroxy](#xroxy)|2076|2076|1|0.0%|0.0%|
[voipbl](#voipbl)|10426|10837|1|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|6295|6295|1|0.0%|0.0%|
[proxyrss](#proxyrss)|1772|1772|1|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[dshield](#dshield)|20|5120|1|0.0%|0.0%|

## blocklist_de_ftp

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours for attacks on the Service FTP.

Source is downloaded from [this link](http://lists.blocklist.de/lists/ftp.txt).

The last time downloaded was found to be dated: Fri Jun  5 02:30:11 UTC 2015.

The ipset `blocklist_de_ftp` has **912** entries, **912** unique IPs.

The following table shows the overlaps of `blocklist_de_ftp` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_ftp`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_ftp`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_ftp`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|33391|33391|910|2.7%|99.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|71|0.0%|7.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|19|0.0%|2.0%|
[stopforumspam_30d](#stopforumspam_30d)|93498|93498|12|0.0%|1.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|10|0.0%|1.0%|
[alienvault_reputation](#alienvault_reputation)|177715|177715|7|0.0%|0.7%|
[stopforumspam_7d](#stopforumspam_7d)|29882|29882|5|0.0%|0.5%|
[nixspam](#nixspam)|18430|18430|5|0.0%|0.5%|
[sorbs_spam](#sorbs_spam)|25876|26785|4|0.0%|0.4%|
[sorbs_recent_spam](#sorbs_recent_spam)|21123|21796|3|0.0%|0.3%|
[sorbs_new_spam](#sorbs_new_spam)|21123|21796|3|0.0%|0.3%|
[php_harvesters](#php_harvesters)|298|298|3|1.0%|0.3%|
[openbl_60d](#openbl_60d)|7695|7695|2|0.0%|0.2%|
[stopforumspam_1d](#stopforumspam_1d)|7048|7048|1|0.0%|0.1%|
[spamhaus_edrop](#spamhaus_edrop)|55|486400|1|0.0%|0.1%|
[php_spammers](#php_spammers)|461|461|1|0.2%|0.1%|
[openbl_30d](#openbl_30d)|3260|3260|1|0.0%|0.1%|

## blocklist_de_imap

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours for attacks on the Service imap, sasl, pop3, etc.

Source is downloaded from [this link](http://lists.blocklist.de/lists/imap.txt).

The last time downloaded was found to be dated: Fri Jun  5 02:30:11 UTC 2015.

The ipset `blocklist_de_imap` has **2784** entries, **2784** unique IPs.

The following table shows the overlaps of `blocklist_de_imap` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_imap`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_imap`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_imap`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de_mail](#blocklist_de_mail)|16579|16579|2784|16.7%|100.0%|
[blocklist_de](#blocklist_de)|33391|33391|2781|8.3%|99.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|359|0.0%|12.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|65|0.0%|2.3%|
[alienvault_reputation](#alienvault_reputation)|177715|177715|46|0.0%|1.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|39|0.0%|1.4%|
[openbl_60d](#openbl_60d)|7695|7695|37|0.4%|1.3%|
[openbl_30d](#openbl_30d)|3260|3260|32|0.9%|1.1%|
[sorbs_spam](#sorbs_spam)|25876|26785|23|0.0%|0.8%|
[nixspam](#nixspam)|18430|18430|20|0.1%|0.7%|
[sorbs_recent_spam](#sorbs_recent_spam)|21123|21796|19|0.0%|0.6%|
[sorbs_new_spam](#sorbs_new_spam)|21123|21796|19|0.0%|0.6%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|17|0.0%|0.6%|
[et_block](#et_block)|1007|18338646|17|0.0%|0.6%|
[openbl_7d](#openbl_7d)|927|927|11|1.1%|0.3%|
[stopforumspam_30d](#stopforumspam_30d)|93498|93498|10|0.0%|0.3%|
[snort_ipfilter](#snort_ipfilter)|9882|9882|5|0.0%|0.1%|
[et_compromised](#et_compromised)|2171|2171|4|0.1%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|0.1%|
[bruteforceblocker](#bruteforceblocker)|2024|2024|3|0.1%|0.1%|
[stopforumspam_7d](#stopforumspam_7d)|29882|29882|2|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|2|0.0%|0.0%|
[voipbl](#voipbl)|10426|10837|1|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7048|7048|1|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|486400|1|0.0%|0.0%|
[sorbs_web](#sorbs_web)|749|751|1|0.1%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2352|2352|1|0.0%|0.0%|
[openbl_1d](#openbl_1d)|174|174|1|0.5%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1|0.0%|0.0%|
[ciarmy](#ciarmy)|329|329|1|0.3%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|177|177|1|0.5%|0.0%|

## blocklist_de_mail

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service Mail, Postfix.

Source is downloaded from [this link](http://lists.blocklist.de/lists/mail.txt).

The last time downloaded was found to be dated: Fri Jun  5 02:30:08 UTC 2015.

The ipset `blocklist_de_mail` has **16579** entries, **16579** unique IPs.

The following table shows the overlaps of `blocklist_de_mail` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_mail`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_mail`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_mail`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|33391|33391|16572|49.6%|99.9%|
[blocklist_de_apache](#blocklist_de_apache)|13971|13971|11059|79.1%|66.7%|
[blocklist_de_imap](#blocklist_de_imap)|2784|2784|2784|100.0%|16.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|2559|0.0%|15.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|1377|0.0%|8.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|1172|0.0%|7.0%|
[sorbs_spam](#sorbs_spam)|25876|26785|837|3.1%|5.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|21123|21796|813|3.7%|4.9%|
[sorbs_new_spam](#sorbs_new_spam)|21123|21796|813|3.7%|4.9%|
[nixspam](#nixspam)|18430|18430|516|2.7%|3.1%|
[stopforumspam_30d](#stopforumspam_30d)|93498|93498|266|0.2%|1.6%|
[stopforumspam_7d](#stopforumspam_7d)|29882|29882|162|0.5%|0.9%|
[snort_ipfilter](#snort_ipfilter)|9882|9882|161|1.6%|0.9%|
[sorbs_web](#sorbs_web)|749|751|84|11.1%|0.5%|
[alienvault_reputation](#alienvault_reputation)|177715|177715|66|0.0%|0.3%|
[stopforumspam_1d](#stopforumspam_1d)|7048|7048|59|0.8%|0.3%|
[xroxy](#xroxy)|2076|2076|55|2.6%|0.3%|
[ri_web_proxies](#ri_web_proxies)|6295|6295|54|0.8%|0.3%|
[php_dictionary](#php_dictionary)|475|475|52|10.9%|0.3%|
[php_spammers](#php_spammers)|461|461|48|10.4%|0.2%|
[openbl_60d](#openbl_60d)|7695|7695|43|0.5%|0.2%|
[openbl_30d](#openbl_30d)|3260|3260|38|1.1%|0.2%|
[et_block](#et_block)|1007|18338646|25|0.0%|0.1%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|24|0.0%|0.1%|
[blocklist_de_bots](#blocklist_de_bots)|3165|3165|24|0.7%|0.1%|
[blocklist_de_strongips](#blocklist_de_strongips)|177|177|23|12.9%|0.1%|
[proxz](#proxz)|747|747|22|2.9%|0.1%|
[php_commenters](#php_commenters)|301|301|20|6.6%|0.1%|
[openbl_7d](#openbl_7d)|927|927|14|1.5%|0.0%|
[et_compromised](#et_compromised)|2171|2171|7|0.3%|0.0%|
[sorbs_socks](#sorbs_socks)|29|29|5|17.2%|0.0%|
[sorbs_misc](#sorbs_misc)|29|29|5|17.2%|0.0%|
[sorbs_http](#sorbs_http)|29|29|5|17.2%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|5|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2024|2024|5|0.2%|0.0%|
[php_harvesters](#php_harvesters)|298|298|4|1.3%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|4|0.0%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|4|0.0%|0.0%|
[dm_tor](#dm_tor)|6496|6496|4|0.0%|0.0%|
[bm_tor](#bm_tor)|6497|6497|4|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2352|2352|3|0.1%|0.0%|
[et_tor](#et_tor)|6380|6380|3|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|486400|2|0.0%|0.0%|
[shunlist](#shunlist)|1254|1254|2|0.1%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|2|0.2%|0.0%|
[voipbl](#voipbl)|10426|10837|1|0.0%|0.0%|
[openbl_1d](#openbl_1d)|174|174|1|0.5%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[dshield](#dshield)|20|5120|1|0.0%|0.0%|
[ciarmy](#ciarmy)|329|329|1|0.3%|0.0%|

## blocklist_de_sip

[Blocklist.de](https://www.blocklist.de/) All IP addresses that tried to login in a SIP, VOIP or Asterisk Server and are included in the IPs list from [infiltrated.net](www.infiltrated.net)

Source is downloaded from [this link](http://lists.blocklist.de/lists/sip.txt).

The last time downloaded was found to be dated: Fri Jun  5 02:30:11 UTC 2015.

The ipset `blocklist_de_sip` has **101** entries, **101** unique IPs.

The following table shows the overlaps of `blocklist_de_sip` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_sip`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_sip`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_sip`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|33391|33391|82|0.2%|81.1%|
[voipbl](#voipbl)|10426|10837|38|0.3%|37.6%|
[alienvault_reputation](#alienvault_reputation)|177715|177715|17|0.0%|16.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|13|0.0%|12.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|9|0.0%|8.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|4|0.0%|3.9%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|2|0.0%|1.9%|
[et_botcc](#et_botcc)|508|508|1|0.1%|0.9%|

## blocklist_de_ssh

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service SSH.

Source is downloaded from [this link](http://lists.blocklist.de/lists/ssh.txt).

The last time downloaded was found to be dated: Fri Jun  5 02:42:04 UTC 2015.

The ipset `blocklist_de_ssh` has **9757** entries, **9757** unique IPs.

The following table shows the overlaps of `blocklist_de_ssh` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_ssh`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_ssh`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_ssh`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|33391|33391|9757|29.2%|100.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|2236|0.0%|22.9%|
[alienvault_reputation](#alienvault_reputation)|177715|177715|1720|0.9%|17.6%|
[openbl_60d](#openbl_60d)|7695|7695|1579|20.5%|16.1%|
[openbl_30d](#openbl_30d)|3260|3260|810|24.8%|8.3%|
[bruteforceblocker](#bruteforceblocker)|2024|2024|679|33.5%|6.9%|
[et_compromised](#et_compromised)|2171|2171|648|29.8%|6.6%|
[openbl_7d](#openbl_7d)|927|927|552|59.5%|5.6%|
[shunlist](#shunlist)|1254|1254|356|28.3%|3.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|216|0.0%|2.2%|
[openbl_1d](#openbl_1d)|174|174|137|78.7%|1.4%|
[et_block](#et_block)|1007|18338646|112|0.0%|1.1%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|111|0.0%|1.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|111|0.0%|1.1%|
[dshield](#dshield)|20|5120|110|2.1%|1.1%|
[stopforumspam_30d](#stopforumspam_30d)|93498|93498|79|0.0%|0.8%|
[sorbs_spam](#sorbs_spam)|25876|26785|63|0.2%|0.6%|
[sorbs_recent_spam](#sorbs_recent_spam)|21123|21796|60|0.2%|0.6%|
[sorbs_new_spam](#sorbs_new_spam)|21123|21796|60|0.2%|0.6%|
[blocklist_de_strongips](#blocklist_de_strongips)|177|177|27|15.2%|0.2%|
[nixspam](#nixspam)|18430|18430|18|0.0%|0.1%|
[stopforumspam_7d](#stopforumspam_7d)|29882|29882|15|0.0%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|8|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7048|7048|5|0.0%|0.0%|
[voipbl](#voipbl)|10426|10837|3|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|2|0.0%|0.0%|
[ciarmy](#ciarmy)|329|329|2|0.6%|0.0%|
[xroxy](#xroxy)|2076|2076|1|0.0%|0.0%|
[sslbl](#sslbl)|365|365|1|0.2%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|486400|1|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2352|2352|1|0.0%|0.0%|
[proxz](#proxz)|747|747|1|0.1%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|

## blocklist_de_strongips

[Blocklist.de](https://www.blocklist.de/) All IPs which are older then 2 month and have more then 5.000 attacks.

Source is downloaded from [this link](http://lists.blocklist.de/lists/strongips.txt).

The last time downloaded was found to be dated: Fri Jun  5 02:42:13 UTC 2015.

The ipset `blocklist_de_strongips` has **177** entries, **177** unique IPs.

The following table shows the overlaps of `blocklist_de_strongips` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_strongips`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_strongips`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_strongips`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|33391|33391|177|0.5%|100.0%|
[stopforumspam_30d](#stopforumspam_30d)|93498|93498|133|0.1%|75.1%|
[blocklist_de_bots](#blocklist_de_bots)|3165|3165|133|4.2%|75.1%|
[stopforumspam_7d](#stopforumspam_7d)|29882|29882|122|0.4%|68.9%|
[stopforumspam_1d](#stopforumspam_1d)|7048|7048|104|1.4%|58.7%|
[blocklist_de_apache](#blocklist_de_apache)|13971|13971|36|0.2%|20.3%|
[alienvault_reputation](#alienvault_reputation)|177715|177715|35|0.0%|19.7%|
[php_commenters](#php_commenters)|301|301|32|10.6%|18.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|9757|9757|27|0.2%|15.2%|
[openbl_60d](#openbl_60d)|7695|7695|26|0.3%|14.6%|
[openbl_30d](#openbl_30d)|3260|3260|24|0.7%|13.5%|
[openbl_7d](#openbl_7d)|927|927|23|2.4%|12.9%|
[blocklist_de_mail](#blocklist_de_mail)|16579|16579|23|0.1%|12.9%|
[openbl_1d](#openbl_1d)|174|174|21|12.0%|11.8%|
[shunlist](#shunlist)|1254|1254|20|1.5%|11.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|15|0.0%|8.4%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2620|2620|7|0.2%|3.9%|
[xroxy](#xroxy)|2076|2076|6|0.2%|3.3%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|6|0.0%|3.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|6|0.0%|3.3%|
[et_block](#et_block)|1007|18338646|6|0.0%|3.3%|
[ri_web_proxies](#ri_web_proxies)|6295|6295|5|0.0%|2.8%|
[proxyrss](#proxyrss)|1772|1772|5|0.2%|2.8%|
[spamhaus_edrop](#spamhaus_edrop)|55|486400|4|0.0%|2.2%|
[php_spammers](#php_spammers)|461|461|4|0.8%|2.2%|
[proxz](#proxz)|747|747|3|0.4%|1.6%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|1.6%|
[php_harvesters](#php_harvesters)|298|298|2|0.6%|1.1%|
[php_dictionary](#php_dictionary)|475|475|2|0.4%|1.1%|
[nixspam](#nixspam)|18430|18430|2|0.0%|1.1%|
[sorbs_web](#sorbs_web)|749|751|1|0.1%|0.5%|
[sorbs_spam](#sorbs_spam)|25876|26785|1|0.0%|0.5%|
[sorbs_recent_spam](#sorbs_recent_spam)|21123|21796|1|0.0%|0.5%|
[sorbs_new_spam](#sorbs_new_spam)|21123|21796|1|0.0%|0.5%|
[snort_ipfilter](#snort_ipfilter)|9882|9882|1|0.0%|0.5%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|1|0.0%|0.5%|
[blocklist_de_imap](#blocklist_de_imap)|2784|2784|1|0.0%|0.5%|

## bm_tor

[torstatus.blutmagie.de](https://torstatus.blutmagie.de) list of all TOR network servers

Source is downloaded from [this link](https://torstatus.blutmagie.de/ip_list_all.php/Tor_ip_list_ALL.csv).

The last time downloaded was found to be dated: Fri Jun  5 02:54:08 UTC 2015.

The ipset `bm_tor` has **6497** entries, **6497** unique IPs.

The following table shows the overlaps of `bm_tor` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `bm_tor`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `bm_tor`.
- ` this % ` is the percentage **of this ipset (`bm_tor`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[dm_tor](#dm_tor)|6496|6496|6383|98.2%|98.2%|
[et_tor](#et_tor)|6380|6380|5693|89.2%|87.6%|
[snort_ipfilter](#snort_ipfilter)|9882|9882|1080|10.9%|16.6%|
[stopforumspam_30d](#stopforumspam_30d)|93498|93498|635|0.6%|9.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|632|0.0%|9.7%|
[stopforumspam_7d](#stopforumspam_7d)|29882|29882|506|1.6%|7.7%|
[stopforumspam_1d](#stopforumspam_1d)|7048|7048|340|4.8%|5.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|189|0.0%|2.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|169|0.0%|2.6%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|168|45.1%|2.5%|
[alienvault_reputation](#alienvault_reputation)|177715|177715|42|0.0%|0.6%|
[php_commenters](#php_commenters)|301|301|33|10.9%|0.5%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|22|0.0%|0.3%|
[openbl_60d](#openbl_60d)|7695|7695|20|0.2%|0.3%|
[php_harvesters](#php_harvesters)|298|298|7|2.3%|0.1%|
[php_spammers](#php_spammers)|461|461|6|1.3%|0.0%|
[php_dictionary](#php_dictionary)|475|475|5|1.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|6295|6295|4|0.0%|0.0%|
[et_block](#et_block)|1007|18338646|4|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|16579|16579|4|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13971|13971|4|0.0%|0.0%|
[blocklist_de](#blocklist_de)|33391|33391|4|0.0%|0.0%|
[voipbl](#voipbl)|10426|10837|3|0.0%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|0.0%|
[xroxy](#xroxy)|2076|2076|2|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|2|0.0%|0.0%|
[dshield](#dshield)|20|5120|2|0.0%|0.0%|
[sorbs_spam](#sorbs_spam)|25876|26785|1|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|21123|21796|1|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|21123|21796|1|0.0%|0.0%|
[shunlist](#shunlist)|1254|1254|1|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2352|2352|1|0.0%|0.0%|
[nixspam](#nixspam)|18430|18430|1|0.0%|0.0%|

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
[fullbogons](#fullbogons)|3733|670419608|592708608|88.4%|100.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|4194304|3.0%|0.7%|
[voipbl](#voipbl)|10426|10837|319|2.9%|0.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|5|0.0%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|93498|93498|1|0.0%|0.0%|
[php_harvesters](#php_harvesters)|298|298|1|0.3%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.0%|
[ciarmy](#ciarmy)|329|329|1|0.3%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2024|2024|1|0.0%|0.0%|

## bruteforceblocker

[danger.rulez.sk](http://danger.rulez.sk/) IPs detected by [bruteforceblocker](http://danger.rulez.sk/index.php/bruteforceblocker/) (fail2ban alternative for SSH on OpenBSD). This is an automatically generated list from users reporting failed authentication attempts. An IP seems to be included if 3 or more users report it. Its retention pocily seems 30 days.

Source is downloaded from [this link](http://danger.rulez.sk/projects/bruteforceblocker/blist.php).

The last time downloaded was found to be dated: Fri Jun  5 01:00:05 UTC 2015.

The ipset `bruteforceblocker` has **2024** entries, **2024** unique IPs.

The following table shows the overlaps of `bruteforceblocker` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `bruteforceblocker`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `bruteforceblocker`.
- ` this % ` is the percentage **of this ipset (`bruteforceblocker`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[et_compromised](#et_compromised)|2171|2171|1963|90.4%|96.9%|
[alienvault_reputation](#alienvault_reputation)|177715|177715|1312|0.7%|64.8%|
[openbl_60d](#openbl_60d)|7695|7695|1214|15.7%|59.9%|
[openbl_30d](#openbl_30d)|3260|3260|1159|35.5%|57.2%|
[blocklist_de](#blocklist_de)|33391|33391|689|2.0%|34.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|9757|9757|679|6.9%|33.5%|
[shunlist](#shunlist)|1254|1254|477|38.0%|23.5%|
[openbl_7d](#openbl_7d)|927|927|416|44.8%|20.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|200|0.0%|9.8%|
[dshield](#dshield)|20|5120|112|2.1%|5.5%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|100|0.0%|4.9%|
[et_block](#et_block)|1007|18338646|100|0.0%|4.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|97|0.0%|4.7%|
[openbl_1d](#openbl_1d)|174|174|92|52.8%|4.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|54|0.0%|2.6%|
[stopforumspam_30d](#stopforumspam_30d)|93498|93498|11|0.0%|0.5%|
[stopforumspam_7d](#stopforumspam_7d)|29882|29882|7|0.0%|0.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|5|0.0%|0.2%|
[blocklist_de_mail](#blocklist_de_mail)|16579|16579|5|0.0%|0.2%|
[blocklist_de_imap](#blocklist_de_imap)|2784|2784|3|0.1%|0.1%|
[voipbl](#voipbl)|10426|10837|2|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7048|7048|2|0.0%|0.0%|
[proxz](#proxz)|747|747|2|0.2%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|2|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3165|3165|2|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13971|13971|2|0.0%|0.0%|
[xroxy](#xroxy)|2076|2076|1|0.0%|0.0%|
[sorbs_spam](#sorbs_spam)|25876|26785|1|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9882|9882|1|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|6295|6295|1|0.0%|0.0%|
[proxyrss](#proxyrss)|1772|1772|1|0.0%|0.0%|
[fullbogons](#fullbogons)|3733|670419608|1|0.0%|0.0%|
[ciarmy](#ciarmy)|329|329|1|0.3%|0.0%|
[bogons](#bogons)|13|592708608|1|0.0%|0.0%|

## ciarmy

[CIArmy.com](http://ciarmy.com/) IPs with poor Rogue Packet score that have not yet been identified as malicious by the community

Source is downloaded from [this link](http://cinsscore.com/list/ci-badguys.txt).

The last time downloaded was found to be dated: Fri Jun  5 01:15:15 UTC 2015.

The ipset `ciarmy` has **329** entries, **329** unique IPs.

The following table shows the overlaps of `ciarmy` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ciarmy`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ciarmy`.
- ` this % ` is the percentage **of this ipset (`ciarmy`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[alienvault_reputation](#alienvault_reputation)|177715|177715|321|0.1%|97.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|51|0.0%|15.5%|
[blocklist_de](#blocklist_de)|33391|33391|39|0.1%|11.8%|
[blocklist_de_apache](#blocklist_de_apache)|13971|13971|36|0.2%|10.9%|
[shunlist](#shunlist)|1254|1254|28|2.2%|8.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|17|0.0%|5.1%|
[voipbl](#voipbl)|10426|10837|6|0.0%|1.8%|
[dshield](#dshield)|20|5120|6|0.1%|1.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|4|0.0%|1.2%|
[blocklist_de_ssh](#blocklist_de_ssh)|9757|9757|2|0.0%|0.6%|
[stopforumspam_7d](#stopforumspam_7d)|29882|29882|1|0.0%|0.3%|
[stopforumspam_30d](#stopforumspam_30d)|93498|93498|1|0.0%|0.3%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.3%|
[fullbogons](#fullbogons)|3733|670419608|1|0.0%|0.3%|
[et_compromised](#et_compromised)|2171|2171|1|0.0%|0.3%|
[et_block](#et_block)|1007|18338646|1|0.0%|0.3%|
[bruteforceblocker](#bruteforceblocker)|2024|2024|1|0.0%|0.3%|
[bogons](#bogons)|13|592708608|1|0.0%|0.3%|
[blocklist_de_mail](#blocklist_de_mail)|16579|16579|1|0.0%|0.3%|
[blocklist_de_imap](#blocklist_de_imap)|2784|2784|1|0.0%|0.3%|

## cleanmx_viruses

[Clean-MX.de](http://support.clean-mx.de/clean-mx/viruses.php) IPs with viruses

Source is downloaded from [this link](http://support.clean-mx.de/clean-mx/xmlviruses.php?sort=id%20desc&response=alive).

The last time downloaded was found to be dated: Thu Jun  4 19:18:40 UTC 2015.

The ipset `cleanmx_viruses` has **370** entries, **370** unique IPs.

The following table shows the overlaps of `cleanmx_viruses` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `cleanmx_viruses`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `cleanmx_viruses`.
- ` this % ` is the percentage **of this ipset (`cleanmx_viruses`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|42|0.0%|11.3%|
[malc0de](#malc0de)|379|379|33|8.7%|8.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|27|0.0%|7.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|13|0.0%|3.5%|
[alienvault_reputation](#alienvault_reputation)|177715|177715|6|0.0%|1.6%|
[stopforumspam_30d](#stopforumspam_30d)|93498|93498|3|0.0%|0.8%|
[snort_ipfilter](#snort_ipfilter)|9882|9882|3|0.0%|0.8%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|3|0.0%|0.8%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|2|0.0%|0.5%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|2|0.1%|0.5%|
[et_block](#et_block)|1007|18338646|2|0.0%|0.5%|
[ri_web_proxies](#ri_web_proxies)|6295|6295|1|0.0%|0.2%|
[dshield](#dshield)|20|5120|1|0.0%|0.2%|

## dm_tor

[dan.me.uk](https://www.dan.me.uk) dynamic list of TOR exit points

Source is downloaded from [this link](https://www.dan.me.uk/torlist/).

The last time downloaded was found to be dated: Fri Jun  5 02:54:05 UTC 2015.

The ipset `dm_tor` has **6496** entries, **6496** unique IPs.

The following table shows the overlaps of `dm_tor` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `dm_tor`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `dm_tor`.
- ` this % ` is the percentage **of this ipset (`dm_tor`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[bm_tor](#bm_tor)|6497|6497|6383|98.2%|98.2%|
[et_tor](#et_tor)|6380|6380|5688|89.1%|87.5%|
[snort_ipfilter](#snort_ipfilter)|9882|9882|1070|10.8%|16.4%|
[stopforumspam_30d](#stopforumspam_30d)|93498|93498|633|0.6%|9.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|633|0.0%|9.7%|
[stopforumspam_7d](#stopforumspam_7d)|29882|29882|505|1.6%|7.7%|
[stopforumspam_1d](#stopforumspam_1d)|7048|7048|340|4.8%|5.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|190|0.0%|2.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|169|0.0%|2.6%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|168|45.1%|2.5%|
[alienvault_reputation](#alienvault_reputation)|177715|177715|42|0.0%|0.6%|
[php_commenters](#php_commenters)|301|301|33|10.9%|0.5%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|22|0.0%|0.3%|
[openbl_60d](#openbl_60d)|7695|7695|20|0.2%|0.3%|
[php_harvesters](#php_harvesters)|298|298|7|2.3%|0.1%|
[php_spammers](#php_spammers)|461|461|6|1.3%|0.0%|
[php_dictionary](#php_dictionary)|475|475|5|1.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|6295|6295|4|0.0%|0.0%|
[et_block](#et_block)|1007|18338646|4|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|16579|16579|4|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13971|13971|4|0.0%|0.0%|
[blocklist_de](#blocklist_de)|33391|33391|4|0.0%|0.0%|
[voipbl](#voipbl)|10426|10837|3|0.0%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|0.0%|
[xroxy](#xroxy)|2076|2076|2|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|2|0.0%|0.0%|
[dshield](#dshield)|20|5120|2|0.0%|0.0%|
[sorbs_spam](#sorbs_spam)|25876|26785|1|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|21123|21796|1|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|21123|21796|1|0.0%|0.0%|
[shunlist](#shunlist)|1254|1254|1|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2352|2352|1|0.0%|0.0%|
[nixspam](#nixspam)|18430|18430|1|0.0%|0.0%|

## dshield

[DShield.org](https://dshield.org/) top 20 attacking class C (/24) subnets over the last three days - **excellent list**

Source is downloaded from [this link](http://feeds.dshield.org/block.txt).

The last time downloaded was found to be dated: Thu Jun  4 23:26:54 UTC 2015.

The ipset `dshield` has **20** entries, **5120** unique IPs.

The following table shows the overlaps of `dshield` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `dshield`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `dshield`.
- ` this % ` is the percentage **of this ipset (`dshield`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[alienvault_reputation](#alienvault_reputation)|177715|177715|4111|2.3%|80.2%|
[et_block](#et_block)|1007|18338646|1792|0.0%|35.0%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|512|0.0%|10.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|272|0.0%|5.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|256|0.0%|5.0%|
[openbl_60d](#openbl_60d)|7695|7695|176|2.2%|3.4%|
[openbl_30d](#openbl_30d)|3260|3260|157|4.8%|3.0%|
[shunlist](#shunlist)|1254|1254|127|10.1%|2.4%|
[blocklist_de](#blocklist_de)|33391|33391|119|0.3%|2.3%|
[et_compromised](#et_compromised)|2171|2171|117|5.3%|2.2%|
[bruteforceblocker](#bruteforceblocker)|2024|2024|112|5.5%|2.1%|
[blocklist_de_ssh](#blocklist_de_ssh)|9757|9757|110|1.1%|2.1%|
[openbl_7d](#openbl_7d)|927|927|50|5.3%|0.9%|
[openbl_1d](#openbl_1d)|174|174|12|6.8%|0.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|9|0.0%|0.1%|
[blocklist_de_apache](#blocklist_de_apache)|13971|13971|8|0.0%|0.1%|
[ciarmy](#ciarmy)|329|329|6|1.8%|0.1%|
[voipbl](#voipbl)|10426|10837|3|0.0%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|93498|93498|2|0.0%|0.0%|
[php_commenters](#php_commenters)|301|301|2|0.6%|0.0%|
[malc0de](#malc0de)|379|379|2|0.5%|0.0%|
[et_tor](#et_tor)|6380|6380|2|0.0%|0.0%|
[dm_tor](#dm_tor)|6496|6496|2|0.0%|0.0%|
[bm_tor](#bm_tor)|6497|6497|2|0.0%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29882|29882|1|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7048|7048|1|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9882|9882|1|0.0%|0.0%|
[proxz](#proxz)|747|747|1|0.1%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|370|370|1|0.2%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|16579|16579|1|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2620|2620|1|0.0%|0.0%|

## et_block

[EmergingThreats.net](http://www.emergingthreats.net/) default blacklist (at the time of writing includes spamhaus DROP, dshield and abuse.ch trackers, which are available separately too - prefer to use the direct ipsets instead of this, they seem to lag a bit in updates)

Source is downloaded from [this link](http://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt).

The last time downloaded was found to be dated: Wed Jun  3 04:30:02 UTC 2015.

The ipset `et_block` has **1007** entries, **18338646** unique IPs.

The following table shows the overlaps of `et_block` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `et_block`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `et_block`.
- ` this % ` is the percentage **of this ipset (`et_block`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[spamhaus_drop](#spamhaus_drop)|653|18404096|18120448|98.4%|98.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|8598327|2.4%|46.8%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|7079936|77.1%|38.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|2272279|0.2%|12.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|196442|0.1%|1.0%|
[fullbogons](#fullbogons)|3733|670419608|20480|0.0%|0.1%|
[alienvault_reputation](#alienvault_reputation)|177715|177715|5538|3.1%|0.0%|
[dshield](#dshield)|20|5120|1792|35.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1040|0.3%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|93498|93498|1021|1.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|486400|517|0.1%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29882|29882|334|1.1%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9882|9882|305|3.0%|0.0%|
[zeus](#zeus)|269|269|258|95.9%|0.0%|
[openbl_60d](#openbl_60d)|7695|7695|244|3.1%|0.0%|
[zeus_badips](#zeus_badips)|235|235|230|97.8%|0.0%|
[nixspam](#nixspam)|18430|18430|226|1.2%|0.0%|
[blocklist_de](#blocklist_de)|33391|33391|169|0.5%|0.0%|
[openbl_30d](#openbl_30d)|3260|3260|163|5.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|9757|9757|112|1.1%|0.0%|
[shunlist](#shunlist)|1254|1254|108|8.6%|0.0%|
[et_compromised](#et_compromised)|2171|2171|100|4.6%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2024|2024|100|4.9%|0.0%|
[feodo](#feodo)|94|94|80|85.1%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7048|7048|76|1.0%|0.0%|
[openbl_7d](#openbl_7d)|927|927|55|5.9%|0.0%|
[sslbl](#sslbl)|365|365|32|8.7%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|29|2.2%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3165|3165|27|0.8%|0.0%|
[php_commenters](#php_commenters)|301|301|26|8.6%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|16579|16579|25|0.1%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2784|2784|17|0.6%|0.0%|
[voipbl](#voipbl)|10426|10837|14|0.1%|0.0%|
[openbl_1d](#openbl_1d)|174|174|14|8.0%|0.0%|
[sorbs_spam](#sorbs_spam)|25876|26785|12|0.0%|0.0%|
[palevo](#palevo)|13|13|12|92.3%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|21123|21796|7|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|21123|21796|7|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|6|0.4%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|6|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|177|177|6|3.3%|0.0%|
[malc0de](#malc0de)|379|379|5|1.3%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13971|13971|5|0.0%|0.0%|
[php_dictionary](#php_dictionary)|475|475|4|0.8%|0.0%|
[et_tor](#et_tor)|6380|6380|4|0.0%|0.0%|
[dm_tor](#dm_tor)|6496|6496|4|0.0%|0.0%|
[bm_tor](#bm_tor)|6497|6497|4|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2620|2620|3|0.1%|0.0%|
[php_spammers](#php_spammers)|461|461|2|0.4%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|2|0.2%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|370|370|2|0.5%|0.0%|
[sorbs_web](#sorbs_web)|749|751|1|0.1%|0.0%|
[php_harvesters](#php_harvesters)|298|298|1|0.3%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[et_botcc](#et_botcc)|508|508|1|0.1%|0.0%|
[ciarmy](#ciarmy)|329|329|1|0.3%|0.0%|

## et_botcc

[EmergingThreats.net Command and Control IPs](http://doc.emergingthreats.net/bin/view/Main/BotCC) These IPs are updates every 24 hours and should be considered VERY highly reliable indications that a host is communicating with a known and active Bot or Malware command and control server - (although they say this includes abuse.ch trackers, it does not - most probably it is the shadowserver.org C&C list)

Source is downloaded from [this link](http://rules.emergingthreats.net/fwrules/emerging-PIX-CC.rules).

The last time downloaded was found to be dated: Wed Jun  3 04:30:02 UTC 2015.

The ipset `et_botcc` has **508** entries, **508** unique IPs.

The following table shows the overlaps of `et_botcc` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `et_botcc`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `et_botcc`.
- ` this % ` is the percentage **of this ipset (`et_botcc`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|76|0.0%|14.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|40|0.0%|7.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|22|0.0%|4.3%|
[alienvault_reputation](#alienvault_reputation)|177715|177715|4|0.0%|0.7%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|1|0.0%|0.1%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|1|0.0%|0.1%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.1%|
[et_block](#et_block)|1007|18338646|1|0.0%|0.1%|
[blocklist_de_sip](#blocklist_de_sip)|101|101|1|0.9%|0.1%|

## et_compromised

[EmergingThreats.net compromised hosts](http://doc.emergingthreats.net/bin/view/Main/CompromisedHost) - (this seems to be based on bruteforceblocker)

Source is downloaded from [this link](http://rules.emergingthreats.net/blockrules/compromised-ips.txt).

The last time downloaded was found to be dated: Wed Jun  3 04:30:10 UTC 2015.

The ipset `et_compromised` has **2171** entries, **2171** unique IPs.

The following table shows the overlaps of `et_compromised` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `et_compromised`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `et_compromised`.
- ` this % ` is the percentage **of this ipset (`et_compromised`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[bruteforceblocker](#bruteforceblocker)|2024|2024|1963|96.9%|90.4%|
[alienvault_reputation](#alienvault_reputation)|177715|177715|1411|0.7%|64.9%|
[openbl_60d](#openbl_60d)|7695|7695|1311|17.0%|60.3%|
[openbl_30d](#openbl_30d)|3260|3260|1215|37.2%|55.9%|
[blocklist_de](#blocklist_de)|33391|33391|660|1.9%|30.4%|
[blocklist_de_ssh](#blocklist_de_ssh)|9757|9757|648|6.6%|29.8%|
[shunlist](#shunlist)|1254|1254|487|38.8%|22.4%|
[openbl_7d](#openbl_7d)|927|927|407|43.9%|18.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|216|0.0%|9.9%|
[dshield](#dshield)|20|5120|117|2.2%|5.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|115|0.0%|5.2%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|100|0.0%|4.6%|
[et_block](#et_block)|1007|18338646|100|0.0%|4.6%|
[openbl_1d](#openbl_1d)|174|174|89|51.1%|4.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|62|0.0%|2.8%|
[stopforumspam_30d](#stopforumspam_30d)|93498|93498|10|0.0%|0.4%|
[blocklist_de_mail](#blocklist_de_mail)|16579|16579|7|0.0%|0.3%|
[stopforumspam_7d](#stopforumspam_7d)|29882|29882|6|0.0%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|5|0.0%|0.2%|
[blocklist_de_imap](#blocklist_de_imap)|2784|2784|4|0.1%|0.1%|
[blocklist_de_apache](#blocklist_de_apache)|13971|13971|3|0.0%|0.1%|
[voipbl](#voipbl)|10426|10837|2|0.0%|0.0%|
[proxz](#proxz)|747|747|2|0.2%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|2|0.0%|0.0%|
[xroxy](#xroxy)|2076|2076|1|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7048|7048|1|0.0%|0.0%|
[sorbs_spam](#sorbs_spam)|25876|26785|1|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9882|9882|1|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|6295|6295|1|0.0%|0.0%|
[proxyrss](#proxyrss)|1772|1772|1|0.0%|0.0%|
[ciarmy](#ciarmy)|329|329|1|0.3%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3165|3165|1|0.0%|0.0%|

## et_tor

[EmergingThreats.net](http://www.emergingthreats.net/) [list](http://doc.emergingthreats.net/bin/view/Main/TorRules) of TOR network IPs

Source is downloaded from [this link](http://rules.emergingthreats.net/blockrules/emerging-tor.rules).

The last time downloaded was found to be dated: Wed Jun  3 04:30:09 UTC 2015.

The ipset `et_tor` has **6380** entries, **6380** unique IPs.

The following table shows the overlaps of `et_tor` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `et_tor`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `et_tor`.
- ` this % ` is the percentage **of this ipset (`et_tor`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[bm_tor](#bm_tor)|6497|6497|5693|87.6%|89.2%|
[dm_tor](#dm_tor)|6496|6496|5688|87.5%|89.1%|
[snort_ipfilter](#snort_ipfilter)|9882|9882|1086|10.9%|17.0%|
[stopforumspam_30d](#stopforumspam_30d)|93498|93498|643|0.6%|10.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|626|0.0%|9.8%|
[stopforumspam_7d](#stopforumspam_7d)|29882|29882|517|1.7%|8.1%|
[stopforumspam_1d](#stopforumspam_1d)|7048|7048|342|4.8%|5.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|185|0.0%|2.8%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|171|45.9%|2.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|167|0.0%|2.6%|
[alienvault_reputation](#alienvault_reputation)|177715|177715|43|0.0%|0.6%|
[php_commenters](#php_commenters)|301|301|33|10.9%|0.5%|
[openbl_60d](#openbl_60d)|7695|7695|21|0.2%|0.3%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|21|0.0%|0.3%|
[php_harvesters](#php_harvesters)|298|298|7|2.3%|0.1%|
[php_spammers](#php_spammers)|461|461|6|1.3%|0.0%|
[php_dictionary](#php_dictionary)|475|475|5|1.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|6295|6295|4|0.0%|0.0%|
[et_block](#et_block)|1007|18338646|4|0.0%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|16579|16579|3|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13971|13971|3|0.0%|0.0%|
[blocklist_de](#blocklist_de)|33391|33391|3|0.0%|0.0%|
[xroxy](#xroxy)|2076|2076|2|0.0%|0.0%|
[voipbl](#voipbl)|10426|10837|2|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|2|0.0%|0.0%|
[sorbs_spam](#sorbs_spam)|25876|26785|2|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|21123|21796|2|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|21123|21796|2|0.0%|0.0%|
[dshield](#dshield)|20|5120|2|0.0%|0.0%|
[shunlist](#shunlist)|1254|1254|1|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2352|2352|1|0.0%|0.0%|
[nixspam](#nixspam)|18430|18430|1|0.0%|0.0%|

## feodo

[Abuse.ch Feodo tracker](https://feodotracker.abuse.ch) trojan includes IPs which are being used by Feodo (also known as Cridex or Bugat) which commits ebanking fraud - **excellent list**

Source is downloaded from [this link](https://feodotracker.abuse.ch/blocklist/?download=ipblocklist).

The last time downloaded was found to be dated: Fri Jun  5 02:54:22 UTC 2015.

The ipset `feodo` has **94** entries, **94** unique IPs.

The following table shows the overlaps of `feodo` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `feodo`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `feodo`.
- ` this % ` is the percentage **of this ipset (`feodo`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[et_block](#et_block)|1007|18338646|80|0.0%|85.1%|
[snort_ipfilter](#snort_ipfilter)|9882|9882|73|0.7%|77.6%|
[sslbl](#sslbl)|365|365|34|9.3%|36.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|10|0.0%|10.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|3|0.0%|3.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|3|0.0%|3.1%|
[alienvault_reputation](#alienvault_reputation)|177715|177715|2|0.0%|2.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|1.0%|

## fullbogons

[Team-Cymru.org](http://www.team-cymru.org) IP space that has been allocated to an RIR, but not assigned by that RIR to an actual ISP or other end-user - **excellent list - use it only your internet interface**

Source is downloaded from [this link](http://www.team-cymru.org/Services/Bogons/fullbogons-ipv4.txt).

The last time downloaded was found to be dated: Thu Jun  4 09:35:05 UTC 2015.

The ipset `fullbogons` has **3733** entries, **670419608** unique IPs.

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
[et_block](#et_block)|1007|18338646|20480|0.1%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|890|0.2%|0.0%|
[voipbl](#voipbl)|10426|10837|319|2.9%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|33|2.2%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|15|0.0%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|9|0.6%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|93498|93498|2|0.0%|0.0%|
[php_harvesters](#php_harvesters)|298|298|1|0.3%|0.0%|
[ciarmy](#ciarmy)|329|329|1|0.3%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2024|2024|1|0.0%|0.0%|

## ib_bluetack_badpeers

[iBlocklist.com](https://www.iblocklist.com/) free version of [BlueTack.co.uk](http://www.bluetack.co.uk/) IPs that have been reported for bad deeds in p2p

Source is downloaded from [this link](http://list.iblocklist.com/?list=cwworuawihqvocglcoss&fileformat=p2p&archiveformat=gz).

The last time downloaded was found to be dated: Thu Jun  4 04:30:59 UTC 2015.

The ipset `ib_bluetack_badpeers` has **48134** entries, **48134** unique IPs.

The following table shows the overlaps of `ib_bluetack_badpeers` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ib_bluetack_badpeers`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ib_bluetack_badpeers`.
- ` this % ` is the percentage **of this ipset (`ib_bluetack_badpeers`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|1172|0.0%|2.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|406|0.0%|0.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|230|0.0%|0.4%|
[fullbogons](#fullbogons)|3733|670419608|15|0.0%|0.0%|
[alienvault_reputation](#alienvault_reputation)|177715|177715|15|0.0%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|93498|93498|14|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|11|1.6%|0.0%|
[blocklist_de](#blocklist_de)|33391|33391|9|0.0%|0.0%|
[sorbs_spam](#sorbs_spam)|25876|26785|7|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|21123|21796|7|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|21123|21796|7|0.0%|0.0%|
[nixspam](#nixspam)|18430|18430|7|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|6|0.0%|0.0%|
[et_block](#et_block)|1007|18338646|6|0.0%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29882|29882|5|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|16579|16579|5|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|4|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2620|2620|4|0.1%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13971|13971|4|0.0%|0.0%|
[xroxy](#xroxy)|2076|2076|3|0.1%|0.0%|
[voipbl](#voipbl)|10426|10837|2|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|6295|6295|2|0.0%|0.0%|
[php_harvesters](#php_harvesters)|298|298|2|0.6%|0.0%|
[php_dictionary](#php_dictionary)|475|475|2|0.4%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7048|7048|1|0.0%|0.0%|
[sorbs_web](#sorbs_web)|749|751|1|0.1%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9882|9882|1|0.0%|0.0%|
[proxz](#proxz)|747|747|1|0.1%|0.0%|
[php_spammers](#php_spammers)|461|461|1|0.2%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2784|2784|1|0.0%|0.0%|

## ib_bluetack_hijacked

[iBlocklist.com](https://www.iblocklist.com/) free version of [BlueTack.co.uk](http://www.bluetack.co.uk/) hijacked IP-Blocks Hijacked IP space are IP blocks that are being used without permission

Source is downloaded from [this link](http://list.iblocklist.com/?list=usrcshglbiilevmyfhse&fileformat=p2p&archiveformat=gz).

The last time downloaded was found to be dated: Thu Jun  4 05:00:02 UTC 2015.

The ipset `ib_bluetack_hijacked` has **535** entries, **9177856** unique IPs.

The following table shows the overlaps of `ib_bluetack_hijacked` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ib_bluetack_hijacked`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ib_bluetack_hijacked`.
- ` this % ` is the percentage **of this ipset (`ib_bluetack_hijacked`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[et_block](#et_block)|1007|18338646|7079936|38.6%|77.1%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|6998016|38.0%|76.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|2526625|0.7%|27.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|904796|0.1%|9.8%|
[fullbogons](#fullbogons)|3733|670419608|565248|0.0%|6.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|145472|0.1%|1.5%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1036|0.3%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|93498|93498|759|0.8%|0.0%|
[alienvault_reputation](#alienvault_reputation)|177715|177715|518|0.2%|0.0%|
[nixspam](#nixspam)|18430|18430|225|1.2%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29882|29882|177|0.5%|0.0%|
[blocklist_de](#blocklist_de)|33391|33391|33|0.0%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|27|2.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7048|7048|24|0.3%|0.0%|
[openbl_60d](#openbl_60d)|7695|7695|18|0.2%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3165|3165|18|0.5%|0.0%|
[openbl_30d](#openbl_30d)|3260|3260|13|0.3%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9882|9882|11|0.1%|0.0%|
[zeus_badips](#zeus_badips)|235|235|10|4.2%|0.0%|
[zeus](#zeus)|269|269|10|3.7%|0.0%|
[sorbs_spam](#sorbs_spam)|25876|26785|8|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|9757|9757|8|0.0%|0.0%|
[openbl_7d](#openbl_7d)|927|927|7|0.7%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|7|0.4%|0.0%|
[et_compromised](#et_compromised)|2171|2171|5|0.2%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2024|2024|5|0.2%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|16579|16579|4|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|21123|21796|3|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|21123|21796|3|0.0%|0.0%|
[openbl_1d](#openbl_1d)|174|174|3|1.7%|0.0%|
[et_tor](#et_tor)|6380|6380|3|0.0%|0.0%|
[dm_tor](#dm_tor)|6496|6496|3|0.0%|0.0%|
[bm_tor](#bm_tor)|6497|6497|3|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|177|177|3|1.6%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2784|2784|3|0.1%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13971|13971|3|0.0%|0.0%|
[shunlist](#shunlist)|1254|1254|2|0.1%|0.0%|
[php_spammers](#php_spammers)|461|461|2|0.4%|0.0%|
[php_dictionary](#php_dictionary)|475|475|2|0.4%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|2|0.2%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2620|2620|2|0.0%|0.0%|
[voipbl](#voipbl)|10426|10837|1|0.0%|0.0%|
[php_harvesters](#php_harvesters)|298|298|1|0.3%|0.0%|
[php_commenters](#php_commenters)|301|301|1|0.3%|0.0%|
[et_botcc](#et_botcc)|508|508|1|0.1%|0.0%|

## ib_bluetack_level1

[iBlocklist.com](https://www.iblocklist.com/) free version of [BlueTack.co.uk](http://www.bluetack.co.uk/) Level 1 (for use in p2p): Companies or organizations who are clearly involved with trying to stop filesharing (e.g. Baytsp, MediaDefender, Mediasentry a.o.). Companies which anti-p2p activity has been seen from. Companies that produce or have a strong financial interest in copyrighted material (e.g. music, movie, software industries a.o.). Government ranges or companies that have a strong financial interest in doing work for governments. Legal industry ranges. IPs or ranges of ISPs from which anti-p2p activity has been observed. Basically this list will block all kinds of internet connections that most people would rather not have during their internet travels.

Source is downloaded from [this link](http://list.iblocklist.com/?list=ydxerpxkpcfqjaybcssw&fileformat=p2p&archiveformat=gz).

The last time downloaded was found to be dated: Thu Jun  4 09:08:05 UTC 2015.

The ipset `ib_bluetack_level1` has **218309** entries, **764987411** unique IPs.

The following table shows the overlaps of `ib_bluetack_level1` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ib_bluetack_level1`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ib_bluetack_level1`.
- ` this % ` is the percentage **of this ipset (`ib_bluetack_level1`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|16300309|4.6%|2.1%|
[et_block](#et_block)|1007|18338646|2272279|12.3%|0.2%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|2272265|12.3%|0.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|1354348|0.9%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|904796|9.8%|0.1%|
[fullbogons](#fullbogons)|3733|670419608|239993|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|486400|33155|6.8%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|13248|3.9%|0.0%|
[alienvault_reputation](#alienvault_reputation)|177715|177715|4428|2.4%|0.0%|
[blocklist_de](#blocklist_de)|33391|33391|1594|4.7%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|93498|93498|1554|1.6%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|16579|16579|1377|8.3%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13971|13971|1329|9.5%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29882|29882|566|1.8%|0.0%|
[nixspam](#nixspam)|18430|18430|445|2.4%|0.0%|
[sorbs_spam](#sorbs_spam)|25876|26785|423|1.5%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|406|0.8%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|21123|21796|337|1.5%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|21123|21796|337|1.5%|0.0%|
[voipbl](#voipbl)|10426|10837|299|2.7%|0.0%|
[openbl_60d](#openbl_60d)|7695|7695|172|2.2%|0.0%|
[dm_tor](#dm_tor)|6496|6496|169|2.6%|0.0%|
[bm_tor](#bm_tor)|6497|6497|169|2.6%|0.0%|
[et_tor](#et_tor)|6380|6380|167|2.6%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7048|7048|140|1.9%|0.0%|
[ri_web_proxies](#ri_web_proxies)|6295|6295|132|2.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|9757|9757|111|1.1%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9882|9882|99|1.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|97|6.6%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2352|2352|75|3.1%|0.0%|
[openbl_30d](#openbl_30d)|3260|3260|70|2.1%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|66|5.1%|0.0%|
[et_compromised](#et_compromised)|2171|2171|62|2.8%|0.0%|
[xroxy](#xroxy)|2076|2076|58|2.7%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|58|8.6%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2024|2024|54|2.6%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3165|3165|45|1.4%|0.0%|
[et_botcc](#et_botcc)|508|508|40|7.8%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2784|2784|39|1.4%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2620|2620|39|1.4%|0.0%|
[proxyrss](#proxyrss)|1772|1772|36|2.0%|0.0%|
[proxz](#proxz)|747|747|28|3.7%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|370|370|27|7.2%|0.0%|
[sorbs_web](#sorbs_web)|749|751|26|3.4%|0.0%|
[shunlist](#shunlist)|1254|1254|25|1.9%|0.0%|
[openbl_7d](#openbl_7d)|927|927|19|2.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|17|4.5%|0.0%|
[malc0de](#malc0de)|379|379|12|3.1%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|912|912|10|1.0%|0.0%|
[php_harvesters](#php_harvesters)|298|298|9|3.0%|0.0%|
[php_dictionary](#php_dictionary)|475|475|9|1.8%|0.0%|
[dshield](#dshield)|20|5120|9|0.1%|0.0%|
[zeus](#zeus)|269|269|7|2.6%|0.0%|
[php_commenters](#php_commenters)|301|301|6|1.9%|0.0%|
[zeus_badips](#zeus_badips)|235|235|5|2.1%|0.0%|
[php_spammers](#php_spammers)|461|461|5|1.0%|0.0%|
[bogons](#bogons)|13|592708608|5|0.0%|0.0%|
[sslbl](#sslbl)|365|365|4|1.0%|0.0%|
[openbl_1d](#openbl_1d)|174|174|4|2.2%|0.0%|
[ciarmy](#ciarmy)|329|329|4|1.2%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|101|101|4|3.9%|0.0%|
[feodo](#feodo)|94|94|3|3.1%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|177|177|1|0.5%|0.0%|

## ib_bluetack_level2

[iBlocklist.com](https://www.iblocklist.com/) free version of BlueTack.co.uk Level 2 (for use in p2p). General corporate ranges. Ranges used by labs or researchers. Proxies.

Source is downloaded from [this link](http://list.iblocklist.com/?list=gyisgnzbhppbvsphucsw&fileformat=p2p&archiveformat=gz).

The last time downloaded was found to be dated: Thu Jun  4 05:01:56 UTC 2015.

The ipset `ib_bluetack_level2` has **72774** entries, **348707599** unique IPs.

The following table shows the overlaps of `ib_bluetack_level2` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ib_bluetack_level2`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ib_bluetack_level2`.
- ` this % ` is the percentage **of this ipset (`ib_bluetack_level2`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|16300309|2.1%|4.6%|
[et_block](#et_block)|1007|18338646|8598327|46.8%|2.4%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|8598042|46.7%|2.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|2830140|2.0%|0.8%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2526625|27.5%|0.7%|
[fullbogons](#fullbogons)|3733|670419608|249087|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|486400|98904|20.3%|0.0%|
[alienvault_reputation](#alienvault_reputation)|177715|177715|7785|4.3%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|7733|2.2%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|93498|93498|2548|2.7%|0.0%|
[blocklist_de](#blocklist_de)|33391|33391|1554|4.6%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|16579|16579|1172|7.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13971|13971|1070|7.6%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29882|29882|932|3.1%|0.0%|
[sorbs_spam](#sorbs_spam)|25876|26785|647|2.4%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|21123|21796|563|2.5%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|21123|21796|563|2.5%|0.0%|
[nixspam](#nixspam)|18430|18430|481|2.6%|0.0%|
[voipbl](#voipbl)|10426|10837|434|4.0%|0.0%|
[openbl_60d](#openbl_60d)|7695|7695|340|4.4%|0.0%|
[dshield](#dshield)|20|5120|272|5.3%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7048|7048|239|3.3%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|230|0.4%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|9757|9757|216|2.2%|0.0%|
[dm_tor](#dm_tor)|6496|6496|190|2.9%|0.0%|
[bm_tor](#bm_tor)|6497|6497|189|2.9%|0.0%|
[ri_web_proxies](#ri_web_proxies)|6295|6295|186|2.9%|0.0%|
[et_tor](#et_tor)|6380|6380|185|2.8%|0.0%|
[openbl_30d](#openbl_30d)|3260|3260|170|5.2%|0.0%|
[et_compromised](#et_compromised)|2171|2171|115|5.2%|0.0%|
[xroxy](#xroxy)|2076|2076|100|4.8%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9882|9882|97|0.9%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2024|2024|97|4.7%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3165|3165|95|3.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2352|2352|91|3.8%|0.0%|
[shunlist](#shunlist)|1254|1254|76|6.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2784|2784|65|2.3%|0.0%|
[proxyrss](#proxyrss)|1772|1772|63|3.5%|0.0%|
[openbl_7d](#openbl_7d)|927|927|48|5.1%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|45|3.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2620|2620|37|1.4%|0.0%|
[php_spammers](#php_spammers)|461|461|34|7.3%|0.0%|
[proxz](#proxz)|747|747|31|4.1%|0.0%|
[sorbs_web](#sorbs_web)|749|751|28|3.7%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|28|4.1%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|26|2.0%|0.0%|
[malc0de](#malc0de)|379|379|23|6.0%|0.0%|
[et_botcc](#et_botcc)|508|508|22|4.3%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|21|5.6%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|912|912|19|2.0%|0.0%|
[ciarmy](#ciarmy)|329|329|17|5.1%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|370|370|13|3.5%|0.0%|
[php_dictionary](#php_dictionary)|475|475|11|2.3%|0.0%|
[php_commenters](#php_commenters)|301|301|11|3.6%|0.0%|
[zeus](#zeus)|269|269|9|3.3%|0.0%|
[php_harvesters](#php_harvesters)|298|298|9|3.0%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|101|101|9|8.9%|0.0%|
[zeus_badips](#zeus_badips)|235|235|8|3.4%|0.0%|
[sslbl](#sslbl)|365|365|6|1.6%|0.0%|
[openbl_1d](#openbl_1d)|174|174|6|3.4%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|177|177|6|3.3%|0.0%|
[palevo](#palevo)|13|13|3|23.0%|0.0%|
[feodo](#feodo)|94|94|3|3.1%|0.0%|
[sorbs_socks](#sorbs_socks)|29|29|1|3.4%|0.0%|
[sorbs_smtp](#sorbs_smtp)|14|14|1|7.1%|0.0%|
[sorbs_misc](#sorbs_misc)|29|29|1|3.4%|0.0%|
[sorbs_http](#sorbs_http)|29|29|1|3.4%|0.0%|

## ib_bluetack_level3

[iBlocklist.com](https://www.iblocklist.com/) free version of BlueTack.co.uk Level 3 (for use in p2p). Many portal-type websites. ISP ranges that may be dodgy for some reason. Ranges that belong to an individual, but which have not been determined to be used by a particular company. Ranges for things that are unusual in some way. The L3 list is aka the paranoid list.

Source is downloaded from [this link](http://list.iblocklist.com/?list=uwnukjqktoggdknzrhgh&fileformat=p2p&archiveformat=gz).

The last time downloaded was found to be dated: Thu Jun  4 05:01:20 UTC 2015.

The ipset `ib_bluetack_level3` has **17802** entries, **139104824** unique IPs.

The following table shows the overlaps of `ib_bluetack_level3` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ib_bluetack_level3`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ib_bluetack_level3`.
- ` this % ` is the percentage **of this ipset (`ib_bluetack_level3`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[fullbogons](#fullbogons)|3733|670419608|4236335|0.6%|3.0%|
[bogons](#bogons)|13|592708608|4194304|0.7%|3.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|2830140|0.8%|2.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|1354348|0.1%|0.9%|
[spamhaus_edrop](#spamhaus_edrop)|55|486400|270785|55.6%|0.1%|
[et_block](#et_block)|1007|18338646|196442|1.0%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|145472|1.5%|0.1%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|130368|0.7%|0.0%|
[alienvault_reputation](#alienvault_reputation)|177715|177715|14082|7.9%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|9231|2.7%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|93498|93498|5886|6.2%|0.0%|
[blocklist_de](#blocklist_de)|33391|33391|5288|15.8%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|16579|16579|2559|15.4%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13971|13971|2315|16.5%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|9757|9757|2236|22.9%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29882|29882|1876|6.2%|0.0%|
[sorbs_spam](#sorbs_spam)|25876|26785|1870|6.9%|0.0%|
[voipbl](#voipbl)|10426|10837|1596|14.7%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|21123|21796|1489|6.8%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|21123|21796|1489|6.8%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1172|2.4%|0.0%|
[nixspam](#nixspam)|18430|18430|912|4.9%|0.0%|
[openbl_60d](#openbl_60d)|7695|7695|748|9.7%|0.0%|
[dm_tor](#dm_tor)|6496|6496|633|9.7%|0.0%|
[bm_tor](#bm_tor)|6497|6497|632|9.7%|0.0%|
[et_tor](#et_tor)|6380|6380|626|9.8%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7048|7048|492|6.9%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2784|2784|359|12.8%|0.0%|
[openbl_30d](#openbl_30d)|3260|3260|311|9.5%|0.0%|
[dshield](#dshield)|20|5120|256|5.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9882|9882|225|2.2%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2620|2620|218|8.3%|0.0%|
[et_compromised](#et_compromised)|2171|2171|216|9.9%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2024|2024|200|9.8%|0.0%|
[ri_web_proxies](#ri_web_proxies)|6295|6295|179|2.8%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3165|3165|167|5.2%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|147|11.4%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|125|33.6%|0.0%|
[openbl_7d](#openbl_7d)|927|927|115|12.4%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|110|7.5%|0.0%|
[shunlist](#shunlist)|1254|1254|105|8.3%|0.0%|
[xroxy](#xroxy)|2076|2076|92|4.4%|0.0%|
[et_botcc](#et_botcc)|508|508|76|14.9%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|912|912|71|7.7%|0.0%|
[proxz](#proxz)|747|747|67|8.9%|0.0%|
[malc0de](#malc0de)|379|379|67|17.6%|0.0%|
[proxyrss](#proxyrss)|1772|1772|63|3.5%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2352|2352|52|2.2%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|51|7.5%|0.0%|
[ciarmy](#ciarmy)|329|329|51|15.5%|0.0%|
[sorbs_web](#sorbs_web)|749|751|48|6.3%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|370|370|42|11.3%|0.0%|
[php_spammers](#php_spammers)|461|461|26|5.6%|0.0%|
[php_dictionary](#php_dictionary)|475|475|25|5.2%|0.0%|
[sslbl](#sslbl)|365|365|23|6.3%|0.0%|
[zeus](#zeus)|269|269|20|7.4%|0.0%|
[openbl_1d](#openbl_1d)|174|174|19|10.9%|0.0%|
[php_harvesters](#php_harvesters)|298|298|17|5.7%|0.0%|
[php_commenters](#php_commenters)|301|301|17|5.6%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|177|177|15|8.4%|0.0%|
[zeus_badips](#zeus_badips)|235|235|14|5.9%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|101|101|13|12.8%|0.0%|
[feodo](#feodo)|94|94|10|10.6%|0.0%|
[virbl](#virbl)|10|10|1|10.0%|0.0%|
[sorbs_socks](#sorbs_socks)|29|29|1|3.4%|0.0%|
[sorbs_misc](#sorbs_misc)|29|29|1|3.4%|0.0%|
[sorbs_http](#sorbs_http)|29|29|1|3.4%|0.0%|
[palevo](#palevo)|13|13|1|7.6%|0.0%|

## ib_bluetack_proxies

[iBlocklist.com](https://www.iblocklist.com/) free version of [BlueTack.co.uk](http://www.bluetack.co.uk/) Open Proxies IPs list (without TOR)

Source is downloaded from [this link](http://list.iblocklist.com/?list=xoebmbyexwuiogmbyprb&fileformat=p2p&archiveformat=gz).

The last time downloaded was found to be dated: Thu Jun  4 05:00:11 UTC 2015.

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
[xroxy](#xroxy)|2076|2076|13|0.6%|1.9%|
[stopforumspam_7d](#stopforumspam_7d)|29882|29882|12|0.0%|1.7%|
[ri_web_proxies](#ri_web_proxies)|6295|6295|12|0.1%|1.7%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|11|0.0%|1.6%|
[proxyrss](#proxyrss)|1772|1772|7|0.3%|1.0%|
[stopforumspam_1d](#stopforumspam_1d)|7048|7048|6|0.0%|0.8%|
[ri_connect_proxies](#ri_connect_proxies)|2352|2352|6|0.2%|0.8%|
[blocklist_de](#blocklist_de)|33391|33391|6|0.0%|0.8%|
[proxz](#proxz)|747|747|4|0.5%|0.5%|
[blocklist_de_bots](#blocklist_de_bots)|3165|3165|4|0.1%|0.5%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|2|0.0%|0.2%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2|0.0%|0.2%|
[et_block](#et_block)|1007|18338646|2|0.0%|0.2%|
[blocklist_de_mail](#blocklist_de_mail)|16579|16579|2|0.0%|0.2%|
[sorbs_spam](#sorbs_spam)|25876|26785|1|0.0%|0.1%|
[sorbs_recent_spam](#sorbs_recent_spam)|21123|21796|1|0.0%|0.1%|
[sorbs_new_spam](#sorbs_new_spam)|21123|21796|1|0.0%|0.1%|
[snort_ipfilter](#snort_ipfilter)|9882|9882|1|0.0%|0.1%|
[php_dictionary](#php_dictionary)|475|475|1|0.2%|0.1%|
[nixspam](#nixspam)|18430|18430|1|0.0%|0.1%|
[alienvault_reputation](#alienvault_reputation)|177715|177715|1|0.0%|0.1%|

## ib_bluetack_spyware

[iBlocklist.com](https://www.iblocklist.com/) free version of [BlueTack.co.uk](http://www.bluetack.co.uk/) known malicious SPYWARE and ADWARE IP Address ranges

Source is downloaded from [this link](http://list.iblocklist.com/?list=llvtlsjyoyiczbkjsxpf&fileformat=p2p&archiveformat=gz).

The last time downloaded was found to be dated: Thu Jun  4 04:30:03 UTC 2015.

The ipset `ib_bluetack_spyware` has **3274** entries, **339192** unique IPs.

The following table shows the overlaps of `ib_bluetack_spyware` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ib_bluetack_spyware`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ib_bluetack_spyware`.
- ` this % ` is the percentage **of this ipset (`ib_bluetack_spyware`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|13248|0.0%|3.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|9231|0.0%|2.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|7733|0.0%|2.2%|
[et_block](#et_block)|1007|18338646|1040|0.0%|0.3%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|1037|0.0%|0.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1036|0.0%|0.3%|
[fullbogons](#fullbogons)|3733|670419608|890|0.0%|0.2%|
[alienvault_reputation](#alienvault_reputation)|177715|177715|286|0.1%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|93498|93498|47|0.0%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|27|2.0%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29882|29882|24|0.0%|0.0%|
[sorbs_spam](#sorbs_spam)|25876|26785|24|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|21123|21796|23|0.1%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|21123|21796|23|0.1%|0.0%|
[dm_tor](#dm_tor)|6496|6496|22|0.3%|0.0%|
[bm_tor](#bm_tor)|6497|6497|22|0.3%|0.0%|
[et_tor](#et_tor)|6380|6380|21|0.3%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|19|1.3%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9882|9882|13|0.1%|0.0%|
[blocklist_de](#blocklist_de)|33391|33391|12|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7048|7048|9|0.1%|0.0%|
[nixspam](#nixspam)|18430|18430|7|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|6295|6295|5|0.0%|0.0%|
[openbl_60d](#openbl_60d)|7695|7695|5|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|5|1.3%|0.0%|
[voipbl](#voipbl)|10426|10837|4|0.0%|0.0%|
[openbl_30d](#openbl_30d)|3260|3260|4|0.1%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|4|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|16579|16579|4|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3165|3165|4|0.1%|0.0%|
[malc0de](#malc0de)|379|379|3|0.7%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|370|370|3|0.8%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13971|13971|3|0.0%|0.0%|
[palevo](#palevo)|13|13|2|15.3%|0.0%|
[et_compromised](#et_compromised)|2171|2171|2|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2024|2024|2|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|9757|9757|2|0.0%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|101|101|2|1.9%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2784|2784|2|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2620|2620|2|0.0%|0.0%|
[zeus_badips](#zeus_badips)|235|235|1|0.4%|0.0%|
[zeus](#zeus)|269|269|1|0.3%|0.0%|
[xroxy](#xroxy)|2076|2076|1|0.0%|0.0%|
[sslbl](#sslbl)|365|365|1|0.2%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|486400|1|0.0%|0.0%|
[shunlist](#shunlist)|1254|1254|1|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2352|2352|1|0.0%|0.0%|
[proxyrss](#proxyrss)|1772|1772|1|0.0%|0.0%|
[php_harvesters](#php_harvesters)|298|298|1|0.3%|0.0%|
[php_dictionary](#php_dictionary)|475|475|1|0.2%|0.0%|
[openbl_7d](#openbl_7d)|927|927|1|0.1%|0.0%|
[feodo](#feodo)|94|94|1|1.0%|0.0%|
[ciarmy](#ciarmy)|329|329|1|0.3%|0.0%|
[bogons](#bogons)|13|592708608|1|0.0%|0.0%|

## ib_bluetack_webexploit

[iBlocklist.com](https://www.iblocklist.com/) free version of [BlueTack.co.uk](http://www.bluetack.co.uk/) web server hack and exploit attempts

Source is downloaded from [this link](http://list.iblocklist.com/?list=ghlzqtqxnzctvvajwwag&fileformat=p2p&archiveformat=gz).

The last time downloaded was found to be dated: Thu Jun  4 04:30:02 UTC 2015.

The ipset `ib_bluetack_webexploit` has **1460** entries, **1460** unique IPs.

The following table shows the overlaps of `ib_bluetack_webexploit` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ib_bluetack_webexploit`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ib_bluetack_webexploit`.
- ` this % ` is the percentage **of this ipset (`ib_bluetack_webexploit`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|110|0.0%|7.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|97|0.0%|6.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|45|0.0%|3.0%|
[fullbogons](#fullbogons)|3733|670419608|33|0.0%|2.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|19|0.0%|1.3%|
[alienvault_reputation](#alienvault_reputation)|177715|177715|8|0.0%|0.5%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|7|0.0%|0.4%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|6|0.0%|0.4%|
[et_block](#et_block)|1007|18338646|6|0.0%|0.4%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|3|0.2%|0.2%|
[stopforumspam_30d](#stopforumspam_30d)|93498|93498|2|0.0%|0.1%|
[openbl_60d](#openbl_60d)|7695|7695|2|0.0%|0.1%|
[openbl_30d](#openbl_30d)|3260|3260|2|0.0%|0.1%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|2|0.2%|0.1%|
[blocklist_de](#blocklist_de)|33391|33391|2|0.0%|0.1%|
[stopforumspam_7d](#stopforumspam_7d)|29882|29882|1|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7048|7048|1|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9882|9882|1|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|6295|6295|1|0.0%|0.0%|
[openbl_7d](#openbl_7d)|927|927|1|0.1%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1|0.0%|0.0%|
[et_botcc](#et_botcc)|508|508|1|0.1%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|177|177|1|0.5%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|9757|9757|1|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3165|3165|1|0.0%|0.0%|

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
[cleanmx_viruses](#cleanmx_viruses)|370|370|33|8.9%|8.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|23|0.0%|6.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|12|0.0%|3.1%|
[alienvault_reputation](#alienvault_reputation)|177715|177715|11|0.0%|2.9%|
[et_block](#et_block)|1007|18338646|5|0.0%|1.3%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|4|0.0%|1.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|4|0.3%|1.0%|
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
[et_block](#et_block)|1007|18338646|29|0.0%|2.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|27|0.0%|2.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|27|0.0%|2.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|26|0.0%|2.0%|
[fullbogons](#fullbogons)|3733|670419608|9|0.0%|0.6%|
[alienvault_reputation](#alienvault_reputation)|177715|177715|6|0.0%|0.4%|
[stopforumspam_30d](#stopforumspam_30d)|93498|93498|4|0.0%|0.3%|
[malc0de](#malc0de)|379|379|4|1.0%|0.3%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|3|0.2%|0.2%|
[stopforumspam_7d](#stopforumspam_7d)|29882|29882|2|0.0%|0.1%|
[cleanmx_viruses](#cleanmx_viruses)|370|370|2|0.5%|0.1%|
[sorbs_spam](#sorbs_spam)|25876|26785|1|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|21123|21796|1|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|21123|21796|1|0.0%|0.0%|
[nixspam](#nixspam)|18430|18430|1|0.0%|0.0%|
[et_botcc](#et_botcc)|508|508|1|0.1%|0.0%|

## maxmind_proxy_fraud

[MaxMind.com](https://www.maxmind.com/en/anonymous-proxy-fraudulent-ip-address-list) list of anonymous proxy fraudelent IP addresses.

Source is downloaded from [this link](https://www.maxmind.com/en/anonymous-proxy-fraudulent-ip-address-list).

The last time downloaded was found to be dated: Fri Jun  5 01:36:24 UTC 2015.

The ipset `maxmind_proxy_fraud` has **372** entries, **372** unique IPs.

The following table shows the overlaps of `maxmind_proxy_fraud` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `maxmind_proxy_fraud`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `maxmind_proxy_fraud`.
- ` this % ` is the percentage **of this ipset (`maxmind_proxy_fraud`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_30d](#stopforumspam_30d)|93498|93498|233|0.2%|62.6%|
[stopforumspam_7d](#stopforumspam_7d)|29882|29882|190|0.6%|51.0%|
[snort_ipfilter](#snort_ipfilter)|9882|9882|179|1.8%|48.1%|
[et_tor](#et_tor)|6380|6380|171|2.6%|45.9%|
[dm_tor](#dm_tor)|6496|6496|168|2.5%|45.1%|
[bm_tor](#bm_tor)|6497|6497|168|2.5%|45.1%|
[stopforumspam_1d](#stopforumspam_1d)|7048|7048|163|2.3%|43.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|125|0.0%|33.6%|
[php_commenters](#php_commenters)|301|301|31|10.2%|8.3%|
[alienvault_reputation](#alienvault_reputation)|177715|177715|26|0.0%|6.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|21|0.0%|5.6%|
[openbl_60d](#openbl_60d)|7695|7695|18|0.2%|4.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|17|0.0%|4.5%|
[php_harvesters](#php_harvesters)|298|298|6|2.0%|1.6%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|5|0.0%|1.3%|
[ri_web_proxies](#ri_web_proxies)|6295|6295|4|0.0%|1.0%|
[php_spammers](#php_spammers)|461|461|4|0.8%|1.0%|
[php_dictionary](#php_dictionary)|475|475|4|0.8%|1.0%|
[shunlist](#shunlist)|1254|1254|2|0.1%|0.5%|
[blocklist_de_apache](#blocklist_de_apache)|13971|13971|2|0.0%|0.5%|
[blocklist_de](#blocklist_de)|33391|33391|2|0.0%|0.5%|
[xroxy](#xroxy)|2076|2076|1|0.0%|0.2%|
[voipbl](#voipbl)|10426|10837|1|0.0%|0.2%|
[ri_connect_proxies](#ri_connect_proxies)|2352|2352|1|0.0%|0.2%|
[et_block](#et_block)|1007|18338646|1|0.0%|0.2%|
[dshield](#dshield)|20|5120|1|0.0%|0.2%|
[blocklist_de_mail](#blocklist_de_mail)|16579|16579|1|0.0%|0.2%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2620|2620|1|0.0%|0.2%|

## nixspam

[NiX Spam](http://www.heise.de/ix/NiX-Spam-DNSBL-and-blacklist-for-download-499637.html) IP addresses that sent spam in the last hour - automatically generated entries without distinguishing open proxies from relays, dialup gateways, and so on. All IPs are removed after 12 hours if there is no spam from there.

Source is downloaded from [this link](http://www.dnsbl.manitu.net/download/nixspam-ip.dump.gz).

The last time downloaded was found to be dated: Fri Jun  5 02:45:02 UTC 2015.

The ipset `nixspam` has **18430** entries, **18430** unique IPs.

The following table shows the overlaps of `nixspam` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `nixspam`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `nixspam`.
- ` this % ` is the percentage **of this ipset (`nixspam`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[sorbs_spam](#sorbs_spam)|25876|26785|3203|11.9%|17.3%|
[sorbs_recent_spam](#sorbs_recent_spam)|21123|21796|3086|14.1%|16.7%|
[sorbs_new_spam](#sorbs_new_spam)|21123|21796|3086|14.1%|16.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|912|0.0%|4.9%|
[blocklist_de](#blocklist_de)|33391|33391|608|1.8%|3.2%|
[blocklist_de_mail](#blocklist_de_mail)|16579|16579|516|3.1%|2.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|481|0.0%|2.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|445|0.0%|2.4%|
[stopforumspam_30d](#stopforumspam_30d)|93498|93498|247|0.2%|1.3%|
[et_block](#et_block)|1007|18338646|226|0.0%|1.2%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|225|0.0%|1.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|225|0.0%|1.2%|
[snort_ipfilter](#snort_ipfilter)|9882|9882|196|1.9%|1.0%|
[stopforumspam_7d](#stopforumspam_7d)|29882|29882|155|0.5%|0.8%|
[sorbs_web](#sorbs_web)|749|751|146|19.4%|0.7%|
[ri_web_proxies](#ri_web_proxies)|6295|6295|104|1.6%|0.5%|
[xroxy](#xroxy)|2076|2076|78|3.7%|0.4%|
[php_dictionary](#php_dictionary)|475|475|73|15.3%|0.3%|
[stopforumspam_1d](#stopforumspam_1d)|7048|7048|71|1.0%|0.3%|
[php_spammers](#php_spammers)|461|461|64|13.8%|0.3%|
[blocklist_de_bots](#blocklist_de_bots)|3165|3165|44|1.3%|0.2%|
[alienvault_reputation](#alienvault_reputation)|177715|177715|37|0.0%|0.2%|
[proxz](#proxz)|747|747|36|4.8%|0.1%|
[blocklist_de_apache](#blocklist_de_apache)|13971|13971|25|0.1%|0.1%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2620|2620|24|0.9%|0.1%|
[ri_connect_proxies](#ri_connect_proxies)|2352|2352|22|0.9%|0.1%|
[proxyrss](#proxyrss)|1772|1772|22|1.2%|0.1%|
[blocklist_de_imap](#blocklist_de_imap)|2784|2784|20|0.7%|0.1%|
[blocklist_de_ssh](#blocklist_de_ssh)|9757|9757|18|0.1%|0.0%|
[php_commenters](#php_commenters)|301|301|10|3.3%|0.0%|
[sorbs_socks](#sorbs_socks)|29|29|8|27.5%|0.0%|
[sorbs_misc](#sorbs_misc)|29|29|8|27.5%|0.0%|
[sorbs_http](#sorbs_http)|29|29|8|27.5%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|7|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|7|0.0%|0.0%|
[php_harvesters](#php_harvesters)|298|298|6|2.0%|0.0%|
[openbl_60d](#openbl_60d)|7695|7695|6|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|912|912|5|0.5%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|486400|2|0.0%|0.0%|
[openbl_30d](#openbl_30d)|3260|3260|2|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|177|177|2|1.1%|0.0%|
[zeus_badips](#zeus_badips)|235|235|1|0.4%|0.0%|
[zeus](#zeus)|269|269|1|0.3%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|1|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|1|0.1%|0.0%|
[et_tor](#et_tor)|6380|6380|1|0.0%|0.0%|
[dm_tor](#dm_tor)|6496|6496|1|0.0%|0.0%|
[bm_tor](#bm_tor)|6497|6497|1|0.0%|0.0%|

## openbl_1d

[OpenBL.org](http://www.openbl.org/) last 24 hours IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.

Source is downloaded from [this link](http://www.openbl.org/lists/base_1days.txt).

The last time downloaded was found to be dated: Fri Jun  5 02:32:00 UTC 2015.

The ipset `openbl_1d` has **174** entries, **174** unique IPs.

The following table shows the overlaps of `openbl_1d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl_1d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl_1d`.
- ` this % ` is the percentage **of this ipset (`openbl_1d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[openbl_7d](#openbl_7d)|927|927|171|18.4%|98.2%|
[openbl_60d](#openbl_60d)|7695|7695|171|2.2%|98.2%|
[openbl_30d](#openbl_30d)|3260|3260|171|5.2%|98.2%|
[alienvault_reputation](#alienvault_reputation)|177715|177715|167|0.0%|95.9%|
[blocklist_de](#blocklist_de)|33391|33391|139|0.4%|79.8%|
[blocklist_de_ssh](#blocklist_de_ssh)|9757|9757|137|1.4%|78.7%|
[bruteforceblocker](#bruteforceblocker)|2024|2024|92|4.5%|52.8%|
[et_compromised](#et_compromised)|2171|2171|89|4.0%|51.1%|
[shunlist](#shunlist)|1254|1254|75|5.9%|43.1%|
[blocklist_de_strongips](#blocklist_de_strongips)|177|177|21|11.8%|12.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|19|0.0%|10.9%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|14|0.0%|8.0%|
[et_block](#et_block)|1007|18338646|14|0.0%|8.0%|
[dshield](#dshield)|20|5120|12|0.2%|6.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|6|0.0%|3.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|4|0.0%|2.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|1.7%|
[blocklist_de_mail](#blocklist_de_mail)|16579|16579|1|0.0%|0.5%|
[blocklist_de_imap](#blocklist_de_imap)|2784|2784|1|0.0%|0.5%|
[blocklist_de_apache](#blocklist_de_apache)|13971|13971|1|0.0%|0.5%|

## openbl_30d

[OpenBL.org](http://www.openbl.org/) last 30 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.

Source is downloaded from [this link](http://www.openbl.org/lists/base_30days.txt).

The last time downloaded was found to be dated: Thu Jun  4 23:42:00 UTC 2015.

The ipset `openbl_30d` has **3260** entries, **3260** unique IPs.

The following table shows the overlaps of `openbl_30d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl_30d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl_30d`.
- ` this % ` is the percentage **of this ipset (`openbl_30d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[openbl_60d](#openbl_60d)|7695|7695|3260|42.3%|100.0%|
[alienvault_reputation](#alienvault_reputation)|177715|177715|3243|1.8%|99.4%|
[et_compromised](#et_compromised)|2171|2171|1215|55.9%|37.2%|
[bruteforceblocker](#bruteforceblocker)|2024|2024|1159|57.2%|35.5%|
[openbl_7d](#openbl_7d)|927|927|927|100.0%|28.4%|
[blocklist_de](#blocklist_de)|33391|33391|853|2.5%|26.1%|
[blocklist_de_ssh](#blocklist_de_ssh)|9757|9757|810|8.3%|24.8%|
[shunlist](#shunlist)|1254|1254|568|45.2%|17.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|311|0.0%|9.5%|
[openbl_1d](#openbl_1d)|174|174|171|98.2%|5.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|170|0.0%|5.2%|
[et_block](#et_block)|1007|18338646|163|0.0%|5.0%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|159|0.0%|4.8%|
[dshield](#dshield)|20|5120|157|3.0%|4.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|70|0.0%|2.1%|
[blocklist_de_mail](#blocklist_de_mail)|16579|16579|38|0.2%|1.1%|
[blocklist_de_imap](#blocklist_de_imap)|2784|2784|32|1.1%|0.9%|
[blocklist_de_strongips](#blocklist_de_strongips)|177|177|24|13.5%|0.7%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|13|0.0%|0.3%|
[snort_ipfilter](#snort_ipfilter)|9882|9882|6|0.0%|0.1%|
[stopforumspam_30d](#stopforumspam_30d)|93498|93498|4|0.0%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|4|0.0%|0.1%|
[voipbl](#voipbl)|10426|10837|3|0.0%|0.0%|
[zeus](#zeus)|269|269|2|0.7%|0.0%|
[sorbs_spam](#sorbs_spam)|25876|26785|2|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|21123|21796|2|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|21123|21796|2|0.0%|0.0%|
[nixspam](#nixspam)|18430|18430|2|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13971|13971|2|0.0%|0.0%|
[zeus_badips](#zeus_badips)|235|235|1|0.4%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29882|29882|1|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7048|7048|1|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|486400|1|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|912|912|1|0.1%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3165|3165|1|0.0%|0.0%|

## openbl_60d

[OpenBL.org](http://www.openbl.org/) last 60 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.

Source is downloaded from [this link](http://www.openbl.org/lists/base_60days.txt).

The last time downloaded was found to be dated: Thu Jun  4 23:42:00 UTC 2015.

The ipset `openbl_60d` has **7695** entries, **7695** unique IPs.

The following table shows the overlaps of `openbl_60d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl_60d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl_60d`.
- ` this % ` is the percentage **of this ipset (`openbl_60d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[alienvault_reputation](#alienvault_reputation)|177715|177715|7672|4.3%|99.7%|
[openbl_30d](#openbl_30d)|3260|3260|3260|100.0%|42.3%|
[blocklist_de](#blocklist_de)|33391|33391|1632|4.8%|21.2%|
[blocklist_de_ssh](#blocklist_de_ssh)|9757|9757|1579|16.1%|20.5%|
[et_compromised](#et_compromised)|2171|2171|1311|60.3%|17.0%|
[bruteforceblocker](#bruteforceblocker)|2024|2024|1214|59.9%|15.7%|
[openbl_7d](#openbl_7d)|927|927|927|100.0%|12.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|748|0.0%|9.7%|
[shunlist](#shunlist)|1254|1254|583|46.4%|7.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|340|0.0%|4.4%|
[et_block](#et_block)|1007|18338646|244|0.0%|3.1%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|239|0.0%|3.1%|
[dshield](#dshield)|20|5120|176|3.4%|2.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|172|0.0%|2.2%|
[openbl_1d](#openbl_1d)|174|174|171|98.2%|2.2%|
[stopforumspam_30d](#stopforumspam_30d)|93498|93498|57|0.0%|0.7%|
[blocklist_de_mail](#blocklist_de_mail)|16579|16579|43|0.2%|0.5%|
[blocklist_de_imap](#blocklist_de_imap)|2784|2784|37|1.3%|0.4%|
[snort_ipfilter](#snort_ipfilter)|9882|9882|29|0.2%|0.3%|
[blocklist_de_strongips](#blocklist_de_strongips)|177|177|26|14.6%|0.3%|
[stopforumspam_7d](#stopforumspam_7d)|29882|29882|25|0.0%|0.3%|
[stopforumspam_1d](#stopforumspam_1d)|7048|7048|21|0.2%|0.2%|
[et_tor](#et_tor)|6380|6380|21|0.3%|0.2%|
[dm_tor](#dm_tor)|6496|6496|20|0.3%|0.2%|
[bm_tor](#bm_tor)|6497|6497|20|0.3%|0.2%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|18|4.8%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|18|0.0%|0.2%|
[sorbs_spam](#sorbs_spam)|25876|26785|15|0.0%|0.1%|
[sorbs_recent_spam](#sorbs_recent_spam)|21123|21796|14|0.0%|0.1%|
[sorbs_new_spam](#sorbs_new_spam)|21123|21796|14|0.0%|0.1%|
[php_commenters](#php_commenters)|301|301|9|2.9%|0.1%|
[voipbl](#voipbl)|10426|10837|8|0.0%|0.1%|
[nixspam](#nixspam)|18430|18430|6|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|5|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13971|13971|4|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3165|3165|3|0.0%|0.0%|
[zeus](#zeus)|269|269|2|0.7%|0.0%|
[php_harvesters](#php_harvesters)|298|298|2|0.6%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|912|912|2|0.2%|0.0%|
[zeus_badips](#zeus_badips)|235|235|1|0.4%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|486400|1|0.0%|0.0%|

## openbl_7d

[OpenBL.org](http://www.openbl.org/) last 7 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.

Source is downloaded from [this link](http://www.openbl.org/lists/base_7days.txt).

The last time downloaded was found to be dated: Thu Jun  4 23:42:00 UTC 2015.

The ipset `openbl_7d` has **927** entries, **927** unique IPs.

The following table shows the overlaps of `openbl_7d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl_7d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl_7d`.
- ` this % ` is the percentage **of this ipset (`openbl_7d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[openbl_60d](#openbl_60d)|7695|7695|927|12.0%|100.0%|
[openbl_30d](#openbl_30d)|3260|3260|927|28.4%|100.0%|
[alienvault_reputation](#alienvault_reputation)|177715|177715|919|0.5%|99.1%|
[blocklist_de](#blocklist_de)|33391|33391|568|1.7%|61.2%|
[blocklist_de_ssh](#blocklist_de_ssh)|9757|9757|552|5.6%|59.5%|
[bruteforceblocker](#bruteforceblocker)|2024|2024|416|20.5%|44.8%|
[et_compromised](#et_compromised)|2171|2171|407|18.7%|43.9%|
[shunlist](#shunlist)|1254|1254|305|24.3%|32.9%|
[openbl_1d](#openbl_1d)|174|174|171|98.2%|18.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|115|0.0%|12.4%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|55|0.0%|5.9%|
[et_block](#et_block)|1007|18338646|55|0.0%|5.9%|
[dshield](#dshield)|20|5120|50|0.9%|5.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|48|0.0%|5.1%|
[blocklist_de_strongips](#blocklist_de_strongips)|177|177|23|12.9%|2.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|19|0.0%|2.0%|
[blocklist_de_mail](#blocklist_de_mail)|16579|16579|14|0.0%|1.5%|
[blocklist_de_imap](#blocklist_de_imap)|2784|2784|11|0.3%|1.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|7|0.0%|0.7%|
[stopforumspam_30d](#stopforumspam_30d)|93498|93498|3|0.0%|0.3%|
[snort_ipfilter](#snort_ipfilter)|9882|9882|2|0.0%|0.2%|
[voipbl](#voipbl)|10426|10837|1|0.0%|0.1%|
[sorbs_spam](#sorbs_spam)|25876|26785|1|0.0%|0.1%|
[sorbs_recent_spam](#sorbs_recent_spam)|21123|21796|1|0.0%|0.1%|
[sorbs_new_spam](#sorbs_new_spam)|21123|21796|1|0.0%|0.1%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.1%|
[blocklist_de_apache](#blocklist_de_apache)|13971|13971|1|0.0%|0.1%|

## palevo

[Abuse.ch Palevo tracker](https://palevotracker.abuse.ch) worm includes IPs which are being used as botnet C&C for the Palevo crimeware - **excellent list**

Source is downloaded from [this link](https://palevotracker.abuse.ch/blocklists.php?download=ipblocklist).

The last time downloaded was found to be dated: Fri Jun  5 02:54:20 UTC 2015.

The ipset `palevo` has **13** entries, **13** unique IPs.

The following table shows the overlaps of `palevo` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `palevo`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `palevo`.
- ` this % ` is the percentage **of this ipset (`palevo`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[et_block](#et_block)|1007|18338646|12|0.0%|92.3%|
[snort_ipfilter](#snort_ipfilter)|9882|9882|11|0.1%|84.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|3|0.0%|23.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|2|0.0%|15.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|1|0.0%|7.6%|

## php_commenters

[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) comment spammers (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=c&rss=1).

The last time downloaded was found to be dated: Fri Jun  5 02:09:18 UTC 2015.

The ipset `php_commenters` has **301** entries, **301** unique IPs.

The following table shows the overlaps of `php_commenters` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `php_commenters`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `php_commenters`.
- ` this % ` is the percentage **of this ipset (`php_commenters`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_30d](#stopforumspam_30d)|93498|93498|219|0.2%|72.7%|
[stopforumspam_7d](#stopforumspam_7d)|29882|29882|157|0.5%|52.1%|
[stopforumspam_1d](#stopforumspam_1d)|7048|7048|121|1.7%|40.1%|
[blocklist_de](#blocklist_de)|33391|33391|76|0.2%|25.2%|
[blocklist_de_bots](#blocklist_de_bots)|3165|3165|62|1.9%|20.5%|
[snort_ipfilter](#snort_ipfilter)|9882|9882|41|0.4%|13.6%|
[php_spammers](#php_spammers)|461|461|33|7.1%|10.9%|
[et_tor](#et_tor)|6380|6380|33|0.5%|10.9%|
[dm_tor](#dm_tor)|6496|6496|33|0.5%|10.9%|
[bm_tor](#bm_tor)|6497|6497|33|0.5%|10.9%|
[blocklist_de_strongips](#blocklist_de_strongips)|177|177|32|18.0%|10.6%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|31|8.3%|10.2%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|26|0.0%|8.6%|
[et_block](#et_block)|1007|18338646|26|0.0%|8.6%|
[blocklist_de_apache](#blocklist_de_apache)|13971|13971|24|0.1%|7.9%|
[php_dictionary](#php_dictionary)|475|475|23|4.8%|7.6%|
[blocklist_de_mail](#blocklist_de_mail)|16579|16579|20|0.1%|6.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|17|0.0%|5.6%|
[ri_web_proxies](#ri_web_proxies)|6295|6295|15|0.2%|4.9%|
[alienvault_reputation](#alienvault_reputation)|177715|177715|14|0.0%|4.6%|
[sorbs_spam](#sorbs_spam)|25876|26785|12|0.0%|3.9%|
[sorbs_recent_spam](#sorbs_recent_spam)|21123|21796|12|0.0%|3.9%|
[sorbs_new_spam](#sorbs_new_spam)|21123|21796|12|0.0%|3.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|11|0.0%|3.6%|
[nixspam](#nixspam)|18430|18430|10|0.0%|3.3%|
[php_harvesters](#php_harvesters)|298|298|9|3.0%|2.9%|
[openbl_60d](#openbl_60d)|7695|7695|9|0.1%|2.9%|
[spamhaus_edrop](#spamhaus_edrop)|55|486400|7|0.0%|2.3%|
[xroxy](#xroxy)|2076|2076|6|0.2%|1.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|6|0.0%|1.9%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2620|2620|5|0.1%|1.6%|
[proxz](#proxz)|747|747|4|0.5%|1.3%|
[proxyrss](#proxyrss)|1772|1772|4|0.2%|1.3%|
[sorbs_web](#sorbs_web)|749|751|2|0.2%|0.6%|
[ri_connect_proxies](#ri_connect_proxies)|2352|2352|2|0.0%|0.6%|
[dshield](#dshield)|20|5120|2|0.0%|0.6%|
[zeus_badips](#zeus_badips)|235|235|1|0.4%|0.3%|
[zeus](#zeus)|269|269|1|0.3%|0.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.3%|

## php_dictionary

[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) directory attackers (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=d&rss=1).

The last time downloaded was found to be dated: Fri Jun  5 02:27:04 UTC 2015.

The ipset `php_dictionary` has **475** entries, **475** unique IPs.

The following table shows the overlaps of `php_dictionary` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `php_dictionary`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `php_dictionary`.
- ` this % ` is the percentage **of this ipset (`php_dictionary`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[php_spammers](#php_spammers)|461|461|120|26.0%|25.2%|
[sorbs_spam](#sorbs_spam)|25876|26785|113|0.4%|23.7%|
[sorbs_recent_spam](#sorbs_recent_spam)|21123|21796|107|0.4%|22.5%|
[sorbs_new_spam](#sorbs_new_spam)|21123|21796|107|0.4%|22.5%|
[stopforumspam_30d](#stopforumspam_30d)|93498|93498|90|0.0%|18.9%|
[nixspam](#nixspam)|18430|18430|73|0.3%|15.3%|
[snort_ipfilter](#snort_ipfilter)|9882|9882|65|0.6%|13.6%|
[blocklist_de](#blocklist_de)|33391|33391|65|0.1%|13.6%|
[stopforumspam_7d](#stopforumspam_7d)|29882|29882|59|0.1%|12.4%|
[blocklist_de_mail](#blocklist_de_mail)|16579|16579|52|0.3%|10.9%|
[ri_web_proxies](#ri_web_proxies)|6295|6295|34|0.5%|7.1%|
[sorbs_web](#sorbs_web)|749|751|31|4.1%|6.5%|
[xroxy](#xroxy)|2076|2076|27|1.3%|5.6%|
[stopforumspam_1d](#stopforumspam_1d)|7048|7048|25|0.3%|5.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|25|0.0%|5.2%|
[php_commenters](#php_commenters)|301|301|23|7.6%|4.8%|
[proxz](#proxz)|747|747|11|1.4%|2.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|11|0.0%|2.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|9|0.0%|1.8%|
[blocklist_de_bots](#blocklist_de_bots)|3165|3165|8|0.2%|1.6%|
[alienvault_reputation](#alienvault_reputation)|177715|177715|8|0.0%|1.6%|
[et_tor](#et_tor)|6380|6380|5|0.0%|1.0%|
[dm_tor](#dm_tor)|6496|6496|5|0.0%|1.0%|
[bm_tor](#bm_tor)|6497|6497|5|0.0%|1.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2620|2620|5|0.1%|1.0%|
[blocklist_de_apache](#blocklist_de_apache)|13971|13971|5|0.0%|1.0%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|4|0.0%|0.8%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|4|1.0%|0.8%|
[et_block](#et_block)|1007|18338646|4|0.0%|0.8%|
[ri_connect_proxies](#ri_connect_proxies)|2352|2352|3|0.1%|0.6%|
[proxyrss](#proxyrss)|1772|1772|3|0.1%|0.6%|
[php_harvesters](#php_harvesters)|298|298|2|0.6%|0.4%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2|0.0%|0.4%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|2|0.0%|0.4%|
[blocklist_de_strongips](#blocklist_de_strongips)|177|177|2|1.1%|0.4%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.2%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|1|0.1%|0.2%|

## php_harvesters

[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) harvesters (IPs that surf the internet looking for email addresses) (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=h&rss=1).

The last time downloaded was found to be dated: Fri Jun  5 02:09:16 UTC 2015.

The ipset `php_harvesters` has **298** entries, **298** unique IPs.

The following table shows the overlaps of `php_harvesters` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `php_harvesters`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `php_harvesters`.
- ` this % ` is the percentage **of this ipset (`php_harvesters`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_30d](#stopforumspam_30d)|93498|93498|67|0.0%|22.4%|
[stopforumspam_7d](#stopforumspam_7d)|29882|29882|52|0.1%|17.4%|
[stopforumspam_1d](#stopforumspam_1d)|7048|7048|35|0.4%|11.7%|
[blocklist_de](#blocklist_de)|33391|33391|33|0.0%|11.0%|
[blocklist_de_bots](#blocklist_de_bots)|3165|3165|23|0.7%|7.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|17|0.0%|5.7%|
[snort_ipfilter](#snort_ipfilter)|9882|9882|10|0.1%|3.3%|
[alienvault_reputation](#alienvault_reputation)|177715|177715|10|0.0%|3.3%|
[php_commenters](#php_commenters)|301|301|9|2.9%|3.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|9|0.0%|3.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|9|0.0%|3.0%|
[sorbs_spam](#sorbs_spam)|25876|26785|8|0.0%|2.6%|
[et_tor](#et_tor)|6380|6380|7|0.1%|2.3%|
[dm_tor](#dm_tor)|6496|6496|7|0.1%|2.3%|
[bm_tor](#bm_tor)|6497|6497|7|0.1%|2.3%|
[sorbs_recent_spam](#sorbs_recent_spam)|21123|21796|6|0.0%|2.0%|
[sorbs_new_spam](#sorbs_new_spam)|21123|21796|6|0.0%|2.0%|
[nixspam](#nixspam)|18430|18430|6|0.0%|2.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|6|1.6%|2.0%|
[blocklist_de_mail](#blocklist_de_mail)|16579|16579|4|0.0%|1.3%|
[blocklist_de_apache](#blocklist_de_apache)|13971|13971|4|0.0%|1.3%|
[blocklist_de_ftp](#blocklist_de_ftp)|912|912|3|0.3%|1.0%|
[xroxy](#xroxy)|2076|2076|2|0.0%|0.6%|
[proxyrss](#proxyrss)|1772|1772|2|0.1%|0.6%|
[php_spammers](#php_spammers)|461|461|2|0.4%|0.6%|
[php_dictionary](#php_dictionary)|475|475|2|0.4%|0.6%|
[openbl_60d](#openbl_60d)|7695|7695|2|0.0%|0.6%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|2|0.0%|0.6%|
[blocklist_de_strongips](#blocklist_de_strongips)|177|177|2|1.1%|0.6%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2620|2620|2|0.0%|0.6%|
[spamhaus_edrop](#spamhaus_edrop)|55|486400|1|0.0%|0.3%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|1|0.0%|0.3%|
[ri_web_proxies](#ri_web_proxies)|6295|6295|1|0.0%|0.3%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.3%|
[fullbogons](#fullbogons)|3733|670419608|1|0.0%|0.3%|
[et_block](#et_block)|1007|18338646|1|0.0%|0.3%|
[bogons](#bogons)|13|592708608|1|0.0%|0.3%|

## php_spammers

[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) spam servers (IPs used by spammers to send messages) (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=s&rss=1).

The last time downloaded was found to be dated: Fri Jun  5 02:09:16 UTC 2015.

The ipset `php_spammers` has **461** entries, **461** unique IPs.

The following table shows the overlaps of `php_spammers` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `php_spammers`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `php_spammers`.
- ` this % ` is the percentage **of this ipset (`php_spammers`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[php_dictionary](#php_dictionary)|475|475|120|25.2%|26.0%|
[stopforumspam_30d](#stopforumspam_30d)|93498|93498|102|0.1%|22.1%|
[sorbs_spam](#sorbs_spam)|25876|26785|99|0.3%|21.4%|
[sorbs_recent_spam](#sorbs_recent_spam)|21123|21796|90|0.4%|19.5%|
[sorbs_new_spam](#sorbs_new_spam)|21123|21796|90|0.4%|19.5%|
[nixspam](#nixspam)|18430|18430|64|0.3%|13.8%|
[blocklist_de](#blocklist_de)|33391|33391|63|0.1%|13.6%|
[snort_ipfilter](#snort_ipfilter)|9882|9882|59|0.5%|12.7%|
[stopforumspam_7d](#stopforumspam_7d)|29882|29882|57|0.1%|12.3%|
[blocklist_de_mail](#blocklist_de_mail)|16579|16579|48|0.2%|10.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|34|0.0%|7.3%|
[php_commenters](#php_commenters)|301|301|33|10.9%|7.1%|
[stopforumspam_1d](#stopforumspam_1d)|7048|7048|30|0.4%|6.5%|
[ri_web_proxies](#ri_web_proxies)|6295|6295|26|0.4%|5.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|26|0.0%|5.6%|
[sorbs_web](#sorbs_web)|749|751|25|3.3%|5.4%|
[xroxy](#xroxy)|2076|2076|22|1.0%|4.7%|
[proxz](#proxz)|747|747|10|1.3%|2.1%|
[blocklist_de_bots](#blocklist_de_bots)|3165|3165|8|0.2%|1.7%|
[et_tor](#et_tor)|6380|6380|6|0.0%|1.3%|
[dm_tor](#dm_tor)|6496|6496|6|0.0%|1.3%|
[bm_tor](#bm_tor)|6497|6497|6|0.0%|1.3%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2620|2620|6|0.2%|1.3%|
[blocklist_de_apache](#blocklist_de_apache)|13971|13971|6|0.0%|1.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|5|0.0%|1.0%|
[alienvault_reputation](#alienvault_reputation)|177715|177715|5|0.0%|1.0%|
[proxyrss](#proxyrss)|1772|1772|4|0.2%|0.8%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|4|1.0%|0.8%|
[blocklist_de_strongips](#blocklist_de_strongips)|177|177|4|2.2%|0.8%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|3|0.0%|0.6%|
[ri_connect_proxies](#ri_connect_proxies)|2352|2352|2|0.0%|0.4%|
[php_harvesters](#php_harvesters)|298|298|2|0.6%|0.4%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2|0.0%|0.4%|
[et_block](#et_block)|1007|18338646|2|0.0%|0.4%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1|0.0%|0.2%|
[blocklist_de_ftp](#blocklist_de_ftp)|912|912|1|0.1%|0.2%|

## proxyrss

[proxyrss.com](http://www.proxyrss.com) open proxies syndicated from multiple sources.

Source is downloaded from [this link](http://www.proxyrss.com/proxylists/all.gz).

The last time downloaded was found to be dated: Fri Jun  5 01:31:31 UTC 2015.

The ipset `proxyrss` has **1772** entries, **1772** unique IPs.

The following table shows the overlaps of `proxyrss` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `proxyrss`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `proxyrss`.
- ` this % ` is the percentage **of this ipset (`proxyrss`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_30d](#stopforumspam_30d)|93498|93498|902|0.9%|50.9%|
[stopforumspam_7d](#stopforumspam_7d)|29882|29882|741|2.4%|41.8%|
[ri_web_proxies](#ri_web_proxies)|6295|6295|708|11.2%|39.9%|
[xroxy](#xroxy)|2076|2076|450|21.6%|25.3%|
[stopforumspam_1d](#stopforumspam_1d)|7048|7048|438|6.2%|24.7%|
[blocklist_de](#blocklist_de)|33391|33391|267|0.7%|15.0%|
[blocklist_de_bots](#blocklist_de_bots)|3165|3165|266|8.4%|15.0%|
[ri_connect_proxies](#ri_connect_proxies)|2352|2352|251|10.6%|14.1%|
[proxz](#proxz)|747|747|223|29.8%|12.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|63|0.0%|3.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|63|0.0%|3.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|36|0.0%|2.0%|
[nixspam](#nixspam)|18430|18430|22|0.1%|1.2%|
[sorbs_spam](#sorbs_spam)|25876|26785|7|0.0%|0.3%|
[sorbs_recent_spam](#sorbs_recent_spam)|21123|21796|7|0.0%|0.3%|
[sorbs_new_spam](#sorbs_new_spam)|21123|21796|7|0.0%|0.3%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|7|1.0%|0.3%|
[snort_ipfilter](#snort_ipfilter)|9882|9882|6|0.0%|0.3%|
[blocklist_de_strongips](#blocklist_de_strongips)|177|177|5|2.8%|0.2%|
[php_spammers](#php_spammers)|461|461|4|0.8%|0.2%|
[php_commenters](#php_commenters)|301|301|4|1.3%|0.2%|
[php_dictionary](#php_dictionary)|475|475|3|0.6%|0.1%|
[sorbs_web](#sorbs_web)|749|751|2|0.2%|0.1%|
[php_harvesters](#php_harvesters)|298|298|2|0.6%|0.1%|
[alienvault_reputation](#alienvault_reputation)|177715|177715|2|0.0%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.0%|
[et_compromised](#et_compromised)|2171|2171|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2024|2024|1|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2620|2620|1|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13971|13971|1|0.0%|0.0%|

## proxz

[proxz.com](http://www.proxz.com) open proxies (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.proxz.com/proxylists.xml).

The last time downloaded was found to be dated: Fri Jun  5 01:31:37 UTC 2015.

The ipset `proxz` has **747** entries, **747** unique IPs.

The following table shows the overlaps of `proxz` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `proxz`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `proxz`.
- ` this % ` is the percentage **of this ipset (`proxz`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_30d](#stopforumspam_30d)|93498|93498|455|0.4%|60.9%|
[stopforumspam_7d](#stopforumspam_7d)|29882|29882|366|1.2%|48.9%|
[ri_web_proxies](#ri_web_proxies)|6295|6295|334|5.3%|44.7%|
[xroxy](#xroxy)|2076|2076|310|14.9%|41.4%|
[proxyrss](#proxyrss)|1772|1772|223|12.5%|29.8%|
[blocklist_de](#blocklist_de)|33391|33391|137|0.4%|18.3%|
[stopforumspam_1d](#stopforumspam_1d)|7048|7048|136|1.9%|18.2%|
[ri_connect_proxies](#ri_connect_proxies)|2352|2352|121|5.1%|16.1%|
[blocklist_de_bots](#blocklist_de_bots)|3165|3165|113|3.5%|15.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|67|0.0%|8.9%|
[nixspam](#nixspam)|18430|18430|36|0.1%|4.8%|
[sorbs_spam](#sorbs_spam)|25876|26785|33|0.1%|4.4%|
[sorbs_recent_spam](#sorbs_recent_spam)|21123|21796|33|0.1%|4.4%|
[sorbs_new_spam](#sorbs_new_spam)|21123|21796|33|0.1%|4.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|31|0.0%|4.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|28|0.0%|3.7%|
[blocklist_de_mail](#blocklist_de_mail)|16579|16579|22|0.1%|2.9%|
[snort_ipfilter](#snort_ipfilter)|9882|9882|19|0.1%|2.5%|
[sorbs_web](#sorbs_web)|749|751|12|1.5%|1.6%|
[php_dictionary](#php_dictionary)|475|475|11|2.3%|1.4%|
[php_spammers](#php_spammers)|461|461|10|2.1%|1.3%|
[php_commenters](#php_commenters)|301|301|4|1.3%|0.5%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|4|0.5%|0.5%|
[blocklist_de_strongips](#blocklist_de_strongips)|177|177|3|1.6%|0.4%|
[alienvault_reputation](#alienvault_reputation)|177715|177715|3|0.0%|0.4%|
[et_compromised](#et_compromised)|2171|2171|2|0.0%|0.2%|
[bruteforceblocker](#bruteforceblocker)|2024|2024|2|0.0%|0.2%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1|0.0%|0.1%|
[dshield](#dshield)|20|5120|1|0.0%|0.1%|
[blocklist_de_ssh](#blocklist_de_ssh)|9757|9757|1|0.0%|0.1%|

## ri_connect_proxies

[rosinstrument.com](http://www.rosinstrument.com) open CONNECT proxies (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://tools.rosinstrument.com/proxy/plab100.xml).

The last time downloaded was found to be dated: Fri Jun  5 01:24:48 UTC 2015.

The ipset `ri_connect_proxies` has **2352** entries, **2352** unique IPs.

The following table shows the overlaps of `ri_connect_proxies` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ri_connect_proxies`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ri_connect_proxies`.
- ` this % ` is the percentage **of this ipset (`ri_connect_proxies`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_30d](#stopforumspam_30d)|93498|93498|1371|1.4%|58.2%|
[ri_web_proxies](#ri_web_proxies)|6295|6295|963|15.2%|40.9%|
[stopforumspam_7d](#stopforumspam_7d)|29882|29882|643|2.1%|27.3%|
[xroxy](#xroxy)|2076|2076|357|17.1%|15.1%|
[proxyrss](#proxyrss)|1772|1772|251|14.1%|10.6%|
[stopforumspam_1d](#stopforumspam_1d)|7048|7048|154|2.1%|6.5%|
[proxz](#proxz)|747|747|121|16.1%|5.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|91|0.0%|3.8%|
[blocklist_de](#blocklist_de)|33391|33391|77|0.2%|3.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|75|0.0%|3.1%|
[blocklist_de_bots](#blocklist_de_bots)|3165|3165|73|2.3%|3.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|52|0.0%|2.2%|
[nixspam](#nixspam)|18430|18430|22|0.1%|0.9%|
[sorbs_spam](#sorbs_spam)|25876|26785|10|0.0%|0.4%|
[sorbs_recent_spam](#sorbs_recent_spam)|21123|21796|9|0.0%|0.3%|
[sorbs_new_spam](#sorbs_new_spam)|21123|21796|9|0.0%|0.3%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|6|0.8%|0.2%|
[snort_ipfilter](#snort_ipfilter)|9882|9882|5|0.0%|0.2%|
[php_dictionary](#php_dictionary)|475|475|3|0.6%|0.1%|
[blocklist_de_mail](#blocklist_de_mail)|16579|16579|3|0.0%|0.1%|
[sorbs_web](#sorbs_web)|749|751|2|0.2%|0.0%|
[php_spammers](#php_spammers)|461|461|2|0.4%|0.0%|
[php_commenters](#php_commenters)|301|301|2|0.6%|0.0%|
[alienvault_reputation](#alienvault_reputation)|177715|177715|2|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.0%|
[et_tor](#et_tor)|6380|6380|1|0.0%|0.0%|
[dm_tor](#dm_tor)|6496|6496|1|0.0%|0.0%|
[bm_tor](#bm_tor)|6497|6497|1|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|9757|9757|1|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2784|2784|1|0.0%|0.0%|

## ri_web_proxies

[rosinstrument.com](http://www.rosinstrument.com) open HTTP proxies (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://tools.rosinstrument.com/proxy/l100.xml).

The last time downloaded was found to be dated: Fri Jun  5 01:24:40 UTC 2015.

The ipset `ri_web_proxies` has **6295** entries, **6295** unique IPs.

The following table shows the overlaps of `ri_web_proxies` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ri_web_proxies`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ri_web_proxies`.
- ` this % ` is the percentage **of this ipset (`ri_web_proxies`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_30d](#stopforumspam_30d)|93498|93498|3077|3.2%|48.8%|
[stopforumspam_7d](#stopforumspam_7d)|29882|29882|1608|5.3%|25.5%|
[ri_connect_proxies](#ri_connect_proxies)|2352|2352|963|40.9%|15.2%|
[xroxy](#xroxy)|2076|2076|881|42.4%|13.9%|
[proxyrss](#proxyrss)|1772|1772|708|39.9%|11.2%|
[stopforumspam_1d](#stopforumspam_1d)|7048|7048|518|7.3%|8.2%|
[blocklist_de](#blocklist_de)|33391|33391|415|1.2%|6.5%|
[blocklist_de_bots](#blocklist_de_bots)|3165|3165|359|11.3%|5.7%|
[proxz](#proxz)|747|747|334|44.7%|5.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|186|0.0%|2.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|179|0.0%|2.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|132|0.0%|2.0%|
[sorbs_spam](#sorbs_spam)|25876|26785|120|0.4%|1.9%|
[sorbs_recent_spam](#sorbs_recent_spam)|21123|21796|114|0.5%|1.8%|
[sorbs_new_spam](#sorbs_new_spam)|21123|21796|114|0.5%|1.8%|
[nixspam](#nixspam)|18430|18430|104|0.5%|1.6%|
[snort_ipfilter](#snort_ipfilter)|9882|9882|60|0.6%|0.9%|
[blocklist_de_mail](#blocklist_de_mail)|16579|16579|54|0.3%|0.8%|
[php_dictionary](#php_dictionary)|475|475|34|7.1%|0.5%|
[sorbs_web](#sorbs_web)|749|751|29|3.8%|0.4%|
[php_spammers](#php_spammers)|461|461|26|5.6%|0.4%|
[php_commenters](#php_commenters)|301|301|15|4.9%|0.2%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|12|1.7%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|5|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|177|177|5|2.8%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|4|1.0%|0.0%|
[et_tor](#et_tor)|6380|6380|4|0.0%|0.0%|
[dm_tor](#dm_tor)|6496|6496|4|0.0%|0.0%|
[bm_tor](#bm_tor)|6497|6497|4|0.0%|0.0%|
[alienvault_reputation](#alienvault_reputation)|177715|177715|3|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|2|0.0%|0.0%|
[sorbs_socks](#sorbs_socks)|29|29|1|3.4%|0.0%|
[sorbs_misc](#sorbs_misc)|29|29|1|3.4%|0.0%|
[sorbs_http](#sorbs_http)|29|29|1|3.4%|0.0%|
[php_harvesters](#php_harvesters)|298|298|1|0.3%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|
[et_compromised](#et_compromised)|2171|2171|1|0.0%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|370|370|1|0.2%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2024|2024|1|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2620|2620|1|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13971|13971|1|0.0%|0.0%|

## shunlist

[AutoShun.org](http://autoshun.org/) IPs identified as hostile by correlating logs from distributed snort installations running the autoshun plugin

Source is downloaded from [this link](http://www.autoshun.org/files/shunlist.csv).

The last time downloaded was found to be dated: Fri Jun  5 02:30:03 UTC 2015.

The ipset `shunlist` has **1254** entries, **1254** unique IPs.

The following table shows the overlaps of `shunlist` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `shunlist`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `shunlist`.
- ` this % ` is the percentage **of this ipset (`shunlist`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[alienvault_reputation](#alienvault_reputation)|177715|177715|1240|0.6%|98.8%|
[openbl_60d](#openbl_60d)|7695|7695|583|7.5%|46.4%|
[openbl_30d](#openbl_30d)|3260|3260|568|17.4%|45.2%|
[et_compromised](#et_compromised)|2171|2171|487|22.4%|38.8%|
[bruteforceblocker](#bruteforceblocker)|2024|2024|477|23.5%|38.0%|
[blocklist_de](#blocklist_de)|33391|33391|394|1.1%|31.4%|
[blocklist_de_ssh](#blocklist_de_ssh)|9757|9757|356|3.6%|28.3%|
[openbl_7d](#openbl_7d)|927|927|305|32.9%|24.3%|
[dshield](#dshield)|20|5120|127|2.4%|10.1%|
[et_block](#et_block)|1007|18338646|108|0.0%|8.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|105|0.0%|8.3%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|98|0.0%|7.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|76|0.0%|6.0%|
[openbl_1d](#openbl_1d)|174|174|75|43.1%|5.9%|
[sslbl](#sslbl)|365|365|56|15.3%|4.4%|
[blocklist_de_apache](#blocklist_de_apache)|13971|13971|36|0.2%|2.8%|
[ciarmy](#ciarmy)|329|329|28|8.5%|2.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|25|0.0%|1.9%|
[blocklist_de_strongips](#blocklist_de_strongips)|177|177|20|11.2%|1.5%|
[voipbl](#voipbl)|10426|10837|12|0.1%|0.9%|
[stopforumspam_30d](#stopforumspam_30d)|93498|93498|4|0.0%|0.3%|
[stopforumspam_7d](#stopforumspam_7d)|29882|29882|3|0.0%|0.2%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2620|2620|3|0.1%|0.2%|
[snort_ipfilter](#snort_ipfilter)|9882|9882|2|0.0%|0.1%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|2|0.5%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2|0.0%|0.1%|
[blocklist_de_mail](#blocklist_de_mail)|16579|16579|2|0.0%|0.1%|
[stopforumspam_1d](#stopforumspam_1d)|7048|7048|1|0.0%|0.0%|
[sorbs_spam](#sorbs_spam)|25876|26785|1|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|21123|21796|1|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|21123|21796|1|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.0%|
[et_tor](#et_tor)|6380|6380|1|0.0%|0.0%|
[dm_tor](#dm_tor)|6496|6496|1|0.0%|0.0%|
[bm_tor](#bm_tor)|6497|6497|1|0.0%|0.0%|

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
[et_tor](#et_tor)|6380|6380|1086|17.0%|10.9%|
[bm_tor](#bm_tor)|6497|6497|1080|16.6%|10.9%|
[dm_tor](#dm_tor)|6496|6496|1070|16.4%|10.8%|
[stopforumspam_30d](#stopforumspam_30d)|93498|93498|803|0.8%|8.1%|
[stopforumspam_7d](#stopforumspam_7d)|29882|29882|631|2.1%|6.3%|
[stopforumspam_1d](#stopforumspam_1d)|7048|7048|390|5.5%|3.9%|
[sorbs_spam](#sorbs_spam)|25876|26785|329|1.2%|3.3%|
[sorbs_recent_spam](#sorbs_recent_spam)|21123|21796|313|1.4%|3.1%|
[sorbs_new_spam](#sorbs_new_spam)|21123|21796|313|1.4%|3.1%|
[et_block](#et_block)|1007|18338646|305|0.0%|3.0%|
[zeus](#zeus)|269|269|229|85.1%|2.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|225|0.0%|2.2%|
[zeus_badips](#zeus_badips)|235|235|206|87.6%|2.0%|
[nixspam](#nixspam)|18430|18430|196|1.0%|1.9%|
[blocklist_de](#blocklist_de)|33391|33391|182|0.5%|1.8%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|179|48.1%|1.8%|
[blocklist_de_mail](#blocklist_de_mail)|16579|16579|161|0.9%|1.6%|
[alienvault_reputation](#alienvault_reputation)|177715|177715|124|0.0%|1.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|99|0.0%|1.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|97|0.0%|0.9%|
[feodo](#feodo)|94|94|73|77.6%|0.7%|
[php_dictionary](#php_dictionary)|475|475|65|13.6%|0.6%|
[sorbs_web](#sorbs_web)|749|751|60|7.9%|0.6%|
[ri_web_proxies](#ri_web_proxies)|6295|6295|60|0.9%|0.6%|
[php_spammers](#php_spammers)|461|461|59|12.7%|0.5%|
[xroxy](#xroxy)|2076|2076|51|2.4%|0.5%|
[php_commenters](#php_commenters)|301|301|41|13.6%|0.4%|
[sslbl](#sslbl)|365|365|29|7.9%|0.2%|
[openbl_60d](#openbl_60d)|7695|7695|29|0.3%|0.2%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|29|2.2%|0.2%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|20|0.0%|0.2%|
[proxz](#proxz)|747|747|19|2.5%|0.1%|
[blocklist_de_bots](#blocklist_de_bots)|3165|3165|17|0.5%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|13|0.0%|0.1%|
[palevo](#palevo)|13|13|11|84.6%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|11|0.0%|0.1%|
[php_harvesters](#php_harvesters)|298|298|10|3.3%|0.1%|
[blocklist_de_apache](#blocklist_de_apache)|13971|13971|8|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|486400|6|0.0%|0.0%|
[sorbs_socks](#sorbs_socks)|29|29|6|20.6%|0.0%|
[sorbs_misc](#sorbs_misc)|29|29|6|20.6%|0.0%|
[sorbs_http](#sorbs_http)|29|29|6|20.6%|0.0%|
[proxyrss](#proxyrss)|1772|1772|6|0.3%|0.0%|
[openbl_30d](#openbl_30d)|3260|3260|6|0.1%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2352|2352|5|0.2%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2784|2784|5|0.1%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2620|2620|4|0.1%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|370|370|3|0.8%|0.0%|
[shunlist](#shunlist)|1254|1254|2|0.1%|0.0%|
[openbl_7d](#openbl_7d)|927|927|2|0.2%|0.0%|
[voipbl](#voipbl)|10426|10837|1|0.0%|0.0%|
[malc0de](#malc0de)|379|379|1|0.2%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|1|0.1%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1|0.0%|0.0%|
[et_compromised](#et_compromised)|2171|2171|1|0.0%|0.0%|
[dshield](#dshield)|20|5120|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2024|2024|1|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|177|177|1|0.5%|0.0%|

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

The last time downloaded was found to be dated: Thu Jun  4 23:04:17 UTC 2015.

The ipset `sorbs_http` has **29** entries, **29** unique IPs.

The following table shows the overlaps of `sorbs_http` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `sorbs_http`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `sorbs_http`.
- ` this % ` is the percentage **of this ipset (`sorbs_http`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[sorbs_socks](#sorbs_socks)|29|29|29|100.0%|100.0%|
[sorbs_misc](#sorbs_misc)|29|29|29|100.0%|100.0%|
[sorbs_spam](#sorbs_spam)|25876|26785|23|0.0%|79.3%|
[sorbs_recent_spam](#sorbs_recent_spam)|21123|21796|18|0.0%|62.0%|
[sorbs_new_spam](#sorbs_new_spam)|21123|21796|18|0.0%|62.0%|
[nixspam](#nixspam)|18430|18430|8|0.0%|27.5%|
[blocklist_de](#blocklist_de)|33391|33391|7|0.0%|24.1%|
[snort_ipfilter](#snort_ipfilter)|9882|9882|6|0.0%|20.6%|
[sorbs_web](#sorbs_web)|749|751|5|0.6%|17.2%|
[blocklist_de_mail](#blocklist_de_mail)|16579|16579|5|0.0%|17.2%|
[stopforumspam_7d](#stopforumspam_7d)|29882|29882|3|0.0%|10.3%|
[stopforumspam_30d](#stopforumspam_30d)|93498|93498|3|0.0%|10.3%|
[stopforumspam_1d](#stopforumspam_1d)|7048|7048|2|0.0%|6.8%|
[blocklist_de_bots](#blocklist_de_bots)|3165|3165|2|0.0%|6.8%|
[xroxy](#xroxy)|2076|2076|1|0.0%|3.4%|
[ri_web_proxies](#ri_web_proxies)|6295|6295|1|0.0%|3.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|1|0.0%|3.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|1|0.0%|3.4%|

## sorbs_misc

[Sorbs.net](https://www.sorbs.net/) MISC proxies, extracted from deltas.

Source is downloaded from [this link]().

The last time downloaded was found to be dated: Thu Jun  4 23:04:17 UTC 2015.

The ipset `sorbs_misc` has **29** entries, **29** unique IPs.

The following table shows the overlaps of `sorbs_misc` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `sorbs_misc`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `sorbs_misc`.
- ` this % ` is the percentage **of this ipset (`sorbs_misc`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[sorbs_socks](#sorbs_socks)|29|29|29|100.0%|100.0%|
[sorbs_http](#sorbs_http)|29|29|29|100.0%|100.0%|
[sorbs_spam](#sorbs_spam)|25876|26785|23|0.0%|79.3%|
[sorbs_recent_spam](#sorbs_recent_spam)|21123|21796|18|0.0%|62.0%|
[sorbs_new_spam](#sorbs_new_spam)|21123|21796|18|0.0%|62.0%|
[nixspam](#nixspam)|18430|18430|8|0.0%|27.5%|
[blocklist_de](#blocklist_de)|33391|33391|7|0.0%|24.1%|
[snort_ipfilter](#snort_ipfilter)|9882|9882|6|0.0%|20.6%|
[sorbs_web](#sorbs_web)|749|751|5|0.6%|17.2%|
[blocklist_de_mail](#blocklist_de_mail)|16579|16579|5|0.0%|17.2%|
[stopforumspam_7d](#stopforumspam_7d)|29882|29882|3|0.0%|10.3%|
[stopforumspam_30d](#stopforumspam_30d)|93498|93498|3|0.0%|10.3%|
[stopforumspam_1d](#stopforumspam_1d)|7048|7048|2|0.0%|6.8%|
[blocklist_de_bots](#blocklist_de_bots)|3165|3165|2|0.0%|6.8%|
[xroxy](#xroxy)|2076|2076|1|0.0%|3.4%|
[ri_web_proxies](#ri_web_proxies)|6295|6295|1|0.0%|3.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|1|0.0%|3.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|1|0.0%|3.4%|

## sorbs_new_spam

[Sorbs.net](https://www.sorbs.net/) NEW Spam senders, extracted from deltas.

Source is downloaded from [this link]().

The last time downloaded was found to be dated: Fri Jun  5 02:04:14 UTC 2015.

The ipset `sorbs_new_spam` has **21123** entries, **21796** unique IPs.

The following table shows the overlaps of `sorbs_new_spam` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `sorbs_new_spam`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `sorbs_new_spam`.
- ` this % ` is the percentage **of this ipset (`sorbs_new_spam`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[sorbs_spam](#sorbs_spam)|25876|26785|21796|81.3%|100.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|21123|21796|21796|100.0%|100.0%|
[nixspam](#nixspam)|18430|18430|3086|16.7%|14.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|1489|0.0%|6.8%|
[blocklist_de](#blocklist_de)|33391|33391|979|2.9%|4.4%|
[blocklist_de_mail](#blocklist_de_mail)|16579|16579|813|4.9%|3.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|563|0.0%|2.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|337|0.0%|1.5%|
[snort_ipfilter](#snort_ipfilter)|9882|9882|313|3.1%|1.4%|
[sorbs_web](#sorbs_web)|749|751|297|39.5%|1.3%|
[stopforumspam_30d](#stopforumspam_30d)|93498|93498|282|0.3%|1.2%|
[stopforumspam_7d](#stopforumspam_7d)|29882|29882|164|0.5%|0.7%|
[ri_web_proxies](#ri_web_proxies)|6295|6295|114|1.8%|0.5%|
[php_dictionary](#php_dictionary)|475|475|107|22.5%|0.4%|
[php_spammers](#php_spammers)|461|461|90|19.5%|0.4%|
[xroxy](#xroxy)|2076|2076|81|3.9%|0.3%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2620|2620|74|2.8%|0.3%|
[blocklist_de_apache](#blocklist_de_apache)|13971|13971|74|0.5%|0.3%|
[alienvault_reputation](#alienvault_reputation)|177715|177715|74|0.0%|0.3%|
[blocklist_de_ssh](#blocklist_de_ssh)|9757|9757|60|0.6%|0.2%|
[stopforumspam_1d](#stopforumspam_1d)|7048|7048|59|0.8%|0.2%|
[proxz](#proxz)|747|747|33|4.4%|0.1%|
[blocklist_de_bots](#blocklist_de_bots)|3165|3165|31|0.9%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|23|0.0%|0.1%|
[blocklist_de_imap](#blocklist_de_imap)|2784|2784|19|0.6%|0.0%|
[sorbs_socks](#sorbs_socks)|29|29|18|62.0%|0.0%|
[sorbs_misc](#sorbs_misc)|29|29|18|62.0%|0.0%|
[sorbs_http](#sorbs_http)|29|29|18|62.0%|0.0%|
[openbl_60d](#openbl_60d)|7695|7695|14|0.1%|0.0%|
[sorbs_smtp](#sorbs_smtp)|14|14|13|92.8%|0.0%|
[php_commenters](#php_commenters)|301|301|12|3.9%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2352|2352|9|0.3%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|7|0.0%|0.0%|
[proxyrss](#proxyrss)|1772|1772|7|0.3%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|7|0.0%|0.0%|
[et_block](#et_block)|1007|18338646|7|0.0%|0.0%|
[php_harvesters](#php_harvesters)|298|298|6|2.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|486400|3|0.0%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|912|912|3|0.3%|0.0%|
[openbl_30d](#openbl_30d)|3260|3260|2|0.0%|0.0%|
[et_tor](#et_tor)|6380|6380|2|0.0%|0.0%|
[shunlist](#shunlist)|1254|1254|1|0.0%|0.0%|
[openbl_7d](#openbl_7d)|927|927|1|0.1%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|1|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|1|0.1%|0.0%|
[dm_tor](#dm_tor)|6496|6496|1|0.0%|0.0%|
[bm_tor](#bm_tor)|6497|6497|1|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|177|177|1|0.5%|0.0%|

## sorbs_recent_spam

[Sorbs.net](https://www.sorbs.net/) RECENT Spam senders, extracted from deltas.

Source is downloaded from [this link]().

The last time downloaded was found to be dated: Fri Jun  5 02:04:13 UTC 2015.

The ipset `sorbs_recent_spam` has **21123** entries, **21796** unique IPs.

The following table shows the overlaps of `sorbs_recent_spam` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `sorbs_recent_spam`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `sorbs_recent_spam`.
- ` this % ` is the percentage **of this ipset (`sorbs_recent_spam`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[sorbs_spam](#sorbs_spam)|25876|26785|21796|81.3%|100.0%|
[sorbs_new_spam](#sorbs_new_spam)|21123|21796|21796|100.0%|100.0%|
[nixspam](#nixspam)|18430|18430|3086|16.7%|14.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|1489|0.0%|6.8%|
[blocklist_de](#blocklist_de)|33391|33391|979|2.9%|4.4%|
[blocklist_de_mail](#blocklist_de_mail)|16579|16579|813|4.9%|3.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|563|0.0%|2.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|337|0.0%|1.5%|
[snort_ipfilter](#snort_ipfilter)|9882|9882|313|3.1%|1.4%|
[sorbs_web](#sorbs_web)|749|751|297|39.5%|1.3%|
[stopforumspam_30d](#stopforumspam_30d)|93498|93498|282|0.3%|1.2%|
[stopforumspam_7d](#stopforumspam_7d)|29882|29882|164|0.5%|0.7%|
[ri_web_proxies](#ri_web_proxies)|6295|6295|114|1.8%|0.5%|
[php_dictionary](#php_dictionary)|475|475|107|22.5%|0.4%|
[php_spammers](#php_spammers)|461|461|90|19.5%|0.4%|
[xroxy](#xroxy)|2076|2076|81|3.9%|0.3%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2620|2620|74|2.8%|0.3%|
[blocklist_de_apache](#blocklist_de_apache)|13971|13971|74|0.5%|0.3%|
[alienvault_reputation](#alienvault_reputation)|177715|177715|74|0.0%|0.3%|
[blocklist_de_ssh](#blocklist_de_ssh)|9757|9757|60|0.6%|0.2%|
[stopforumspam_1d](#stopforumspam_1d)|7048|7048|59|0.8%|0.2%|
[proxz](#proxz)|747|747|33|4.4%|0.1%|
[blocklist_de_bots](#blocklist_de_bots)|3165|3165|31|0.9%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|23|0.0%|0.1%|
[blocklist_de_imap](#blocklist_de_imap)|2784|2784|19|0.6%|0.0%|
[sorbs_socks](#sorbs_socks)|29|29|18|62.0%|0.0%|
[sorbs_misc](#sorbs_misc)|29|29|18|62.0%|0.0%|
[sorbs_http](#sorbs_http)|29|29|18|62.0%|0.0%|
[openbl_60d](#openbl_60d)|7695|7695|14|0.1%|0.0%|
[sorbs_smtp](#sorbs_smtp)|14|14|13|92.8%|0.0%|
[php_commenters](#php_commenters)|301|301|12|3.9%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2352|2352|9|0.3%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|7|0.0%|0.0%|
[proxyrss](#proxyrss)|1772|1772|7|0.3%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|7|0.0%|0.0%|
[et_block](#et_block)|1007|18338646|7|0.0%|0.0%|
[php_harvesters](#php_harvesters)|298|298|6|2.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|486400|3|0.0%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|912|912|3|0.3%|0.0%|
[openbl_30d](#openbl_30d)|3260|3260|2|0.0%|0.0%|
[et_tor](#et_tor)|6380|6380|2|0.0%|0.0%|
[shunlist](#shunlist)|1254|1254|1|0.0%|0.0%|
[openbl_7d](#openbl_7d)|927|927|1|0.1%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|1|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|1|0.1%|0.0%|
[dm_tor](#dm_tor)|6496|6496|1|0.0%|0.0%|
[bm_tor](#bm_tor)|6497|6497|1|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|177|177|1|0.5%|0.0%|

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
[sorbs_spam](#sorbs_spam)|25876|26785|14|0.0%|100.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|21123|21796|13|0.0%|92.8%|
[sorbs_new_spam](#sorbs_new_spam)|21123|21796|13|0.0%|92.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|1|0.0%|7.1%|

## sorbs_socks

[Sorbs.net](https://www.sorbs.net/) SOCKS proxies, extracted from deltas.

Source is downloaded from [this link]().

The last time downloaded was found to be dated: Thu Jun  4 23:04:18 UTC 2015.

The ipset `sorbs_socks` has **29** entries, **29** unique IPs.

The following table shows the overlaps of `sorbs_socks` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `sorbs_socks`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `sorbs_socks`.
- ` this % ` is the percentage **of this ipset (`sorbs_socks`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[sorbs_misc](#sorbs_misc)|29|29|29|100.0%|100.0%|
[sorbs_http](#sorbs_http)|29|29|29|100.0%|100.0%|
[sorbs_spam](#sorbs_spam)|25876|26785|23|0.0%|79.3%|
[sorbs_recent_spam](#sorbs_recent_spam)|21123|21796|18|0.0%|62.0%|
[sorbs_new_spam](#sorbs_new_spam)|21123|21796|18|0.0%|62.0%|
[nixspam](#nixspam)|18430|18430|8|0.0%|27.5%|
[blocklist_de](#blocklist_de)|33391|33391|7|0.0%|24.1%|
[snort_ipfilter](#snort_ipfilter)|9882|9882|6|0.0%|20.6%|
[sorbs_web](#sorbs_web)|749|751|5|0.6%|17.2%|
[blocklist_de_mail](#blocklist_de_mail)|16579|16579|5|0.0%|17.2%|
[stopforumspam_7d](#stopforumspam_7d)|29882|29882|3|0.0%|10.3%|
[stopforumspam_30d](#stopforumspam_30d)|93498|93498|3|0.0%|10.3%|
[stopforumspam_1d](#stopforumspam_1d)|7048|7048|2|0.0%|6.8%|
[blocklist_de_bots](#blocklist_de_bots)|3165|3165|2|0.0%|6.8%|
[xroxy](#xroxy)|2076|2076|1|0.0%|3.4%|
[ri_web_proxies](#ri_web_proxies)|6295|6295|1|0.0%|3.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|1|0.0%|3.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|1|0.0%|3.4%|

## sorbs_spam

[Sorbs.net](https://www.sorbs.net/) Spam senders, extracted from deltas.

Source is downloaded from [this link]().

The last time downloaded was found to be dated: Fri Jun  5 02:04:13 UTC 2015.

The ipset `sorbs_spam` has **25876** entries, **26785** unique IPs.

The following table shows the overlaps of `sorbs_spam` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `sorbs_spam`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `sorbs_spam`.
- ` this % ` is the percentage **of this ipset (`sorbs_spam`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[sorbs_recent_spam](#sorbs_recent_spam)|21123|21796|21796|100.0%|81.3%|
[sorbs_new_spam](#sorbs_new_spam)|21123|21796|21796|100.0%|81.3%|
[nixspam](#nixspam)|18430|18430|3203|17.3%|11.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|1870|0.0%|6.9%|
[blocklist_de](#blocklist_de)|33391|33391|1011|3.0%|3.7%|
[blocklist_de_mail](#blocklist_de_mail)|16579|16579|837|5.0%|3.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|647|0.0%|2.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|423|0.0%|1.5%|
[snort_ipfilter](#snort_ipfilter)|9882|9882|329|3.3%|1.2%|
[sorbs_web](#sorbs_web)|749|751|326|43.4%|1.2%|
[stopforumspam_30d](#stopforumspam_30d)|93498|93498|323|0.3%|1.2%|
[stopforumspam_7d](#stopforumspam_7d)|29882|29882|181|0.6%|0.6%|
[ri_web_proxies](#ri_web_proxies)|6295|6295|120|1.9%|0.4%|
[php_dictionary](#php_dictionary)|475|475|113|23.7%|0.4%|
[php_spammers](#php_spammers)|461|461|99|21.4%|0.3%|
[xroxy](#xroxy)|2076|2076|83|3.9%|0.3%|
[alienvault_reputation](#alienvault_reputation)|177715|177715|83|0.0%|0.3%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2620|2620|77|2.9%|0.2%|
[blocklist_de_apache](#blocklist_de_apache)|13971|13971|77|0.5%|0.2%|
[blocklist_de_ssh](#blocklist_de_ssh)|9757|9757|63|0.6%|0.2%|
[stopforumspam_1d](#stopforumspam_1d)|7048|7048|60|0.8%|0.2%|
[proxz](#proxz)|747|747|33|4.4%|0.1%|
[blocklist_de_bots](#blocklist_de_bots)|3165|3165|32|1.0%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|24|0.0%|0.0%|
[sorbs_socks](#sorbs_socks)|29|29|23|79.3%|0.0%|
[sorbs_misc](#sorbs_misc)|29|29|23|79.3%|0.0%|
[sorbs_http](#sorbs_http)|29|29|23|79.3%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2784|2784|23|0.8%|0.0%|
[openbl_60d](#openbl_60d)|7695|7695|15|0.1%|0.0%|
[sorbs_smtp](#sorbs_smtp)|14|14|14|100.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|12|0.0%|0.0%|
[php_commenters](#php_commenters)|301|301|12|3.9%|0.0%|
[et_block](#et_block)|1007|18338646|12|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2352|2352|10|0.4%|0.0%|
[php_harvesters](#php_harvesters)|298|298|8|2.6%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|8|0.0%|0.0%|
[proxyrss](#proxyrss)|1772|1772|7|0.3%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|7|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|486400|4|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|912|912|4|0.4%|0.0%|
[openbl_30d](#openbl_30d)|3260|3260|2|0.0%|0.0%|
[et_tor](#et_tor)|6380|6380|2|0.0%|0.0%|
[shunlist](#shunlist)|1254|1254|1|0.0%|0.0%|
[openbl_7d](#openbl_7d)|927|927|1|0.1%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|1|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|1|0.1%|0.0%|
[et_compromised](#et_compromised)|2171|2171|1|0.0%|0.0%|
[dm_tor](#dm_tor)|6496|6496|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2024|2024|1|0.0%|0.0%|
[bm_tor](#bm_tor)|6497|6497|1|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|177|177|1|0.5%|0.0%|

## sorbs_web

[Sorbs.net](https://www.sorbs.net/) WEB exploits, extracted from deltas.

Source is downloaded from [this link]().

The last time downloaded was found to be dated: Fri Jun  5 02:04:14 UTC 2015.

The ipset `sorbs_web` has **749** entries, **751** unique IPs.

The following table shows the overlaps of `sorbs_web` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `sorbs_web`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `sorbs_web`.
- ` this % ` is the percentage **of this ipset (`sorbs_web`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[sorbs_spam](#sorbs_spam)|25876|26785|326|1.2%|43.4%|
[sorbs_recent_spam](#sorbs_recent_spam)|21123|21796|297|1.3%|39.5%|
[sorbs_new_spam](#sorbs_new_spam)|21123|21796|297|1.3%|39.5%|
[nixspam](#nixspam)|18430|18430|146|0.7%|19.4%|
[blocklist_de](#blocklist_de)|33391|33391|94|0.2%|12.5%|
[blocklist_de_mail](#blocklist_de_mail)|16579|16579|84|0.5%|11.1%|
[stopforumspam_30d](#stopforumspam_30d)|93498|93498|69|0.0%|9.1%|
[snort_ipfilter](#snort_ipfilter)|9882|9882|60|0.6%|7.9%|
[stopforumspam_7d](#stopforumspam_7d)|29882|29882|52|0.1%|6.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|48|0.0%|6.3%|
[php_dictionary](#php_dictionary)|475|475|31|6.5%|4.1%|
[ri_web_proxies](#ri_web_proxies)|6295|6295|29|0.4%|3.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|28|0.0%|3.7%|
[xroxy](#xroxy)|2076|2076|27|1.3%|3.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|26|0.0%|3.4%|
[php_spammers](#php_spammers)|461|461|25|5.4%|3.3%|
[stopforumspam_1d](#stopforumspam_1d)|7048|7048|18|0.2%|2.3%|
[proxz](#proxz)|747|747|12|1.6%|1.5%|
[blocklist_de_bots](#blocklist_de_bots)|3165|3165|7|0.2%|0.9%|
[sorbs_socks](#sorbs_socks)|29|29|5|17.2%|0.6%|
[sorbs_misc](#sorbs_misc)|29|29|5|17.2%|0.6%|
[sorbs_http](#sorbs_http)|29|29|5|17.2%|0.6%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2620|2620|3|0.1%|0.3%|
[blocklist_de_apache](#blocklist_de_apache)|13971|13971|3|0.0%|0.3%|
[ri_connect_proxies](#ri_connect_proxies)|2352|2352|2|0.0%|0.2%|
[proxyrss](#proxyrss)|1772|1772|2|0.1%|0.2%|
[php_commenters](#php_commenters)|301|301|2|0.6%|0.2%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|1|0.0%|0.1%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1|0.0%|0.1%|
[et_block](#et_block)|1007|18338646|1|0.0%|0.1%|
[blocklist_de_strongips](#blocklist_de_strongips)|177|177|1|0.5%|0.1%|
[blocklist_de_imap](#blocklist_de_imap)|2784|2784|1|0.0%|0.1%|

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
[et_block](#et_block)|1007|18338646|18120448|98.8%|98.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|8598042|2.4%|46.7%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|6998016|76.2%|38.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|2272265|0.2%|12.3%|
[fullbogons](#fullbogons)|3733|670419608|151552|0.0%|0.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|130368|0.0%|0.7%|
[alienvault_reputation](#alienvault_reputation)|177715|177715|1630|0.9%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1037|0.3%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|93498|93498|1023|1.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|486400|512|0.1%|0.0%|
[dshield](#dshield)|20|5120|512|10.0%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29882|29882|336|1.1%|0.0%|
[openbl_60d](#openbl_60d)|7695|7695|239|3.1%|0.0%|
[nixspam](#nixspam)|18430|18430|225|1.2%|0.0%|
[blocklist_de](#blocklist_de)|33391|33391|166|0.4%|0.0%|
[openbl_30d](#openbl_30d)|3260|3260|159|4.8%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|9757|9757|111|1.1%|0.0%|
[et_compromised](#et_compromised)|2171|2171|100|4.6%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2024|2024|100|4.9%|0.0%|
[shunlist](#shunlist)|1254|1254|98|7.8%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7048|7048|78|1.1%|0.0%|
[openbl_7d](#openbl_7d)|927|927|55|5.9%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|29|2.2%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3165|3165|27|0.8%|0.0%|
[php_commenters](#php_commenters)|301|301|26|8.6%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|16579|16579|24|0.1%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9882|9882|20|0.2%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2784|2784|17|0.6%|0.0%|
[zeus_badips](#zeus_badips)|235|235|16|6.8%|0.0%|
[zeus](#zeus)|269|269|16|5.9%|0.0%|
[voipbl](#voipbl)|10426|10837|14|0.1%|0.0%|
[openbl_1d](#openbl_1d)|174|174|14|8.0%|0.0%|
[sorbs_spam](#sorbs_spam)|25876|26785|12|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|21123|21796|7|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|21123|21796|7|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|6|0.4%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|6|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|177|177|6|3.3%|0.0%|
[php_dictionary](#php_dictionary)|475|475|4|0.8%|0.0%|
[malc0de](#malc0de)|379|379|4|1.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2620|2620|4|0.1%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13971|13971|4|0.0%|0.0%|
[php_spammers](#php_spammers)|461|461|3|0.6%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|2|0.2%|0.0%|
[et_tor](#et_tor)|6380|6380|2|0.0%|0.0%|
[dm_tor](#dm_tor)|6496|6496|2|0.0%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|370|370|2|0.5%|0.0%|
[bm_tor](#bm_tor)|6497|6497|2|0.0%|0.0%|
[sslbl](#sslbl)|365|365|1|0.2%|0.0%|
[sorbs_web](#sorbs_web)|749|751|1|0.1%|0.0%|
[php_harvesters](#php_harvesters)|298|298|1|0.3%|0.0%|
[et_botcc](#et_botcc)|508|508|1|0.1%|0.0%|

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
[et_block](#et_block)|1007|18338646|517|0.0%|0.1%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|512|0.0%|0.1%|
[stopforumspam_30d](#stopforumspam_30d)|93498|93498|92|0.0%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29882|29882|17|0.0%|0.0%|
[alienvault_reputation](#alienvault_reputation)|177715|177715|15|0.0%|0.0%|
[blocklist_de](#blocklist_de)|33391|33391|9|0.0%|0.0%|
[php_commenters](#php_commenters)|301|301|7|2.3%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9882|9882|6|0.0%|0.0%|
[zeus_badips](#zeus_badips)|235|235|5|2.1%|0.0%|
[zeus](#zeus)|269|269|5|1.8%|0.0%|
[sorbs_spam](#sorbs_spam)|25876|26785|4|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|177|177|4|2.2%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7048|7048|3|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|21123|21796|3|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|21123|21796|3|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3165|3165|3|0.0%|0.0%|
[nixspam](#nixspam)|18430|18430|2|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|16579|16579|2|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13971|13971|2|0.0%|0.0%|
[php_harvesters](#php_harvesters)|298|298|1|0.3%|0.0%|
[openbl_60d](#openbl_60d)|7695|7695|1|0.0%|0.0%|
[openbl_30d](#openbl_30d)|3260|3260|1|0.0%|0.0%|
[malc0de](#malc0de)|379|379|1|0.2%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|9757|9757|1|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2784|2784|1|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|912|912|1|0.1%|0.0%|

## sslbl

[Abuse.ch SSL Blacklist](https://sslbl.abuse.ch/) bad SSL traffic related to malware or botnet activities - **excellent list**

Source is downloaded from [this link](https://sslbl.abuse.ch/blacklist/sslipblacklist.csv).

The last time downloaded was found to be dated: Fri Jun  5 02:45:05 UTC 2015.

The ipset `sslbl` has **365** entries, **365** unique IPs.

The following table shows the overlaps of `sslbl` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `sslbl`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `sslbl`.
- ` this % ` is the percentage **of this ipset (`sslbl`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[alienvault_reputation](#alienvault_reputation)|177715|177715|64|0.0%|17.5%|
[shunlist](#shunlist)|1254|1254|56|4.4%|15.3%|
[feodo](#feodo)|94|94|34|36.1%|9.3%|
[et_block](#et_block)|1007|18338646|32|0.0%|8.7%|
[snort_ipfilter](#snort_ipfilter)|9882|9882|29|0.2%|7.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|23|0.0%|6.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|6|0.0%|1.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|4|0.0%|1.0%|
[stopforumspam_30d](#stopforumspam_30d)|93498|93498|1|0.0%|0.2%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|1|0.0%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.2%|
[blocklist_de_ssh](#blocklist_de_ssh)|9757|9757|1|0.0%|0.2%|
[blocklist_de](#blocklist_de)|33391|33391|1|0.0%|0.2%|

## stopforumspam_1d

[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers in the last 24 hours - **excellent list**

Source is downloaded from [this link](http://www.stopforumspam.com/downloads/listed_ip_1.zip).

The last time downloaded was found to be dated: Fri Jun  5 02:01:11 UTC 2015.

The ipset `stopforumspam_1d` has **7048** entries, **7048** unique IPs.

The following table shows the overlaps of `stopforumspam_1d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `stopforumspam_1d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `stopforumspam_1d`.
- ` this % ` is the percentage **of this ipset (`stopforumspam_1d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_7d](#stopforumspam_7d)|29882|29882|6935|23.2%|98.3%|
[stopforumspam_30d](#stopforumspam_30d)|93498|93498|6897|7.3%|97.8%|
[blocklist_de](#blocklist_de)|33391|33391|1464|4.3%|20.7%|
[blocklist_de_bots](#blocklist_de_bots)|3165|3165|1386|43.7%|19.6%|
[ri_web_proxies](#ri_web_proxies)|6295|6295|518|8.2%|7.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|492|0.0%|6.9%|
[proxyrss](#proxyrss)|1772|1772|438|24.7%|6.2%|
[snort_ipfilter](#snort_ipfilter)|9882|9882|390|3.9%|5.5%|
[et_tor](#et_tor)|6380|6380|342|5.3%|4.8%|
[dm_tor](#dm_tor)|6496|6496|340|5.2%|4.8%|
[bm_tor](#bm_tor)|6497|6497|340|5.2%|4.8%|
[xroxy](#xroxy)|2076|2076|278|13.3%|3.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|239|0.0%|3.3%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|163|43.8%|2.3%|
[ri_connect_proxies](#ri_connect_proxies)|2352|2352|154|6.5%|2.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|140|0.0%|1.9%|
[proxz](#proxz)|747|747|136|18.2%|1.9%|
[php_commenters](#php_commenters)|301|301|121|40.1%|1.7%|
[blocklist_de_strongips](#blocklist_de_strongips)|177|177|104|58.7%|1.4%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|78|0.0%|1.1%|
[et_block](#et_block)|1007|18338646|76|0.0%|1.0%|
[nixspam](#nixspam)|18430|18430|71|0.3%|1.0%|
[blocklist_de_apache](#blocklist_de_apache)|13971|13971|70|0.5%|0.9%|
[sorbs_spam](#sorbs_spam)|25876|26785|60|0.2%|0.8%|
[sorbs_recent_spam](#sorbs_recent_spam)|21123|21796|59|0.2%|0.8%|
[sorbs_new_spam](#sorbs_new_spam)|21123|21796|59|0.2%|0.8%|
[blocklist_de_mail](#blocklist_de_mail)|16579|16579|59|0.3%|0.8%|
[alienvault_reputation](#alienvault_reputation)|177715|177715|53|0.0%|0.7%|
[php_harvesters](#php_harvesters)|298|298|35|11.7%|0.4%|
[php_spammers](#php_spammers)|461|461|30|6.5%|0.4%|
[php_dictionary](#php_dictionary)|475|475|25|5.2%|0.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|24|0.0%|0.3%|
[openbl_60d](#openbl_60d)|7695|7695|21|0.2%|0.2%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2620|2620|19|0.7%|0.2%|
[sorbs_web](#sorbs_web)|749|751|18|2.3%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|9|0.0%|0.1%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|6|0.8%|0.0%|
[voipbl](#voipbl)|10426|10837|5|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|9757|9757|5|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|486400|3|0.0%|0.0%|
[sorbs_socks](#sorbs_socks)|29|29|2|6.8%|0.0%|
[sorbs_misc](#sorbs_misc)|29|29|2|6.8%|0.0%|
[sorbs_http](#sorbs_http)|29|29|2|6.8%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2024|2024|2|0.0%|0.0%|
[zeus_badips](#zeus_badips)|235|235|1|0.4%|0.0%|
[zeus](#zeus)|269|269|1|0.3%|0.0%|
[shunlist](#shunlist)|1254|1254|1|0.0%|0.0%|
[openbl_30d](#openbl_30d)|3260|3260|1|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1|0.0%|0.0%|
[et_compromised](#et_compromised)|2171|2171|1|0.0%|0.0%|
[dshield](#dshield)|20|5120|1|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2784|2784|1|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|912|912|1|0.1%|0.0%|

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
[stopforumspam_1d](#stopforumspam_1d)|7048|7048|6897|97.8%|7.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|5886|0.0%|6.2%|
[ri_web_proxies](#ri_web_proxies)|6295|6295|3077|48.8%|3.2%|
[blocklist_de](#blocklist_de)|33391|33391|2667|7.9%|2.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|2548|0.0%|2.7%|
[blocklist_de_bots](#blocklist_de_bots)|3165|3165|2256|71.2%|2.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|1554|0.0%|1.6%|
[ri_connect_proxies](#ri_connect_proxies)|2352|2352|1371|58.2%|1.4%|
[xroxy](#xroxy)|2076|2076|1218|58.6%|1.3%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|1023|0.0%|1.0%|
[et_block](#et_block)|1007|18338646|1021|0.0%|1.0%|
[proxyrss](#proxyrss)|1772|1772|902|50.9%|0.9%|
[snort_ipfilter](#snort_ipfilter)|9882|9882|803|8.1%|0.8%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|759|0.0%|0.8%|
[et_tor](#et_tor)|6380|6380|643|10.0%|0.6%|
[bm_tor](#bm_tor)|6497|6497|635|9.7%|0.6%|
[dm_tor](#dm_tor)|6496|6496|633|9.7%|0.6%|
[proxz](#proxz)|747|747|455|60.9%|0.4%|
[sorbs_spam](#sorbs_spam)|25876|26785|323|1.2%|0.3%|
[sorbs_recent_spam](#sorbs_recent_spam)|21123|21796|282|1.2%|0.3%|
[sorbs_new_spam](#sorbs_new_spam)|21123|21796|282|1.2%|0.3%|
[blocklist_de_mail](#blocklist_de_mail)|16579|16579|266|1.6%|0.2%|
[nixspam](#nixspam)|18430|18430|247|1.3%|0.2%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|233|62.6%|0.2%|
[php_commenters](#php_commenters)|301|301|219|72.7%|0.2%|
[blocklist_de_apache](#blocklist_de_apache)|13971|13971|215|1.5%|0.2%|
[alienvault_reputation](#alienvault_reputation)|177715|177715|207|0.1%|0.2%|
[blocklist_de_strongips](#blocklist_de_strongips)|177|177|133|75.1%|0.1%|
[php_spammers](#php_spammers)|461|461|102|22.1%|0.1%|
[spamhaus_edrop](#spamhaus_edrop)|55|486400|92|0.0%|0.0%|
[php_dictionary](#php_dictionary)|475|475|90|18.9%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|9757|9757|79|0.8%|0.0%|
[sorbs_web](#sorbs_web)|749|751|69|9.1%|0.0%|
[php_harvesters](#php_harvesters)|298|298|67|22.4%|0.0%|
[openbl_60d](#openbl_60d)|7695|7695|57|0.7%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|47|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2620|2620|43|1.6%|0.0%|
[voipbl](#voipbl)|10426|10837|37|0.3%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|22|3.2%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|14|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|912|912|12|1.3%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2024|2024|11|0.5%|0.0%|
[et_compromised](#et_compromised)|2171|2171|10|0.4%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2784|2784|10|0.3%|0.0%|
[shunlist](#shunlist)|1254|1254|4|0.3%|0.0%|
[openbl_30d](#openbl_30d)|3260|3260|4|0.1%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|4|0.3%|0.0%|
[sorbs_socks](#sorbs_socks)|29|29|3|10.3%|0.0%|
[sorbs_misc](#sorbs_misc)|29|29|3|10.3%|0.0%|
[sorbs_http](#sorbs_http)|29|29|3|10.3%|0.0%|
[openbl_7d](#openbl_7d)|927|927|3|0.3%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|370|370|3|0.8%|0.0%|
[zeus_badips](#zeus_badips)|235|235|2|0.8%|0.0%|
[zeus](#zeus)|269|269|2|0.7%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.0%|
[fullbogons](#fullbogons)|3733|670419608|2|0.0%|0.0%|
[dshield](#dshield)|20|5120|2|0.0%|0.0%|
[sslbl](#sslbl)|365|365|1|0.2%|0.0%|
[ciarmy](#ciarmy)|329|329|1|0.3%|0.0%|
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
[stopforumspam_1d](#stopforumspam_1d)|7048|7048|6935|98.3%|23.2%|
[blocklist_de](#blocklist_de)|33391|33391|2302|6.8%|7.7%|
[blocklist_de_bots](#blocklist_de_bots)|3165|3165|2086|65.9%|6.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|1876|0.0%|6.2%|
[ri_web_proxies](#ri_web_proxies)|6295|6295|1608|25.5%|5.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|932|0.0%|3.1%|
[xroxy](#xroxy)|2076|2076|771|37.1%|2.5%|
[proxyrss](#proxyrss)|1772|1772|741|41.8%|2.4%|
[ri_connect_proxies](#ri_connect_proxies)|2352|2352|643|27.3%|2.1%|
[snort_ipfilter](#snort_ipfilter)|9882|9882|631|6.3%|2.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|566|0.0%|1.8%|
[et_tor](#et_tor)|6380|6380|517|8.1%|1.7%|
[bm_tor](#bm_tor)|6497|6497|506|7.7%|1.6%|
[dm_tor](#dm_tor)|6496|6496|505|7.7%|1.6%|
[proxz](#proxz)|747|747|366|48.9%|1.2%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|336|0.0%|1.1%|
[et_block](#et_block)|1007|18338646|334|0.0%|1.1%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|190|51.0%|0.6%|
[sorbs_spam](#sorbs_spam)|25876|26785|181|0.6%|0.6%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|177|0.0%|0.5%|
[sorbs_recent_spam](#sorbs_recent_spam)|21123|21796|164|0.7%|0.5%|
[sorbs_new_spam](#sorbs_new_spam)|21123|21796|164|0.7%|0.5%|
[blocklist_de_mail](#blocklist_de_mail)|16579|16579|162|0.9%|0.5%|
[php_commenters](#php_commenters)|301|301|157|52.1%|0.5%|
[nixspam](#nixspam)|18430|18430|155|0.8%|0.5%|
[blocklist_de_apache](#blocklist_de_apache)|13971|13971|135|0.9%|0.4%|
[blocklist_de_strongips](#blocklist_de_strongips)|177|177|122|68.9%|0.4%|
[alienvault_reputation](#alienvault_reputation)|177715|177715|95|0.0%|0.3%|
[php_dictionary](#php_dictionary)|475|475|59|12.4%|0.1%|
[php_spammers](#php_spammers)|461|461|57|12.3%|0.1%|
[sorbs_web](#sorbs_web)|749|751|52|6.9%|0.1%|
[php_harvesters](#php_harvesters)|298|298|52|17.4%|0.1%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2620|2620|29|1.1%|0.0%|
[openbl_60d](#openbl_60d)|7695|7695|25|0.3%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|24|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|486400|17|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|9757|9757|15|0.1%|0.0%|
[voipbl](#voipbl)|10426|10837|13|0.1%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|12|1.7%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2024|2024|7|0.3%|0.0%|
[et_compromised](#et_compromised)|2171|2171|6|0.2%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|5|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|912|912|5|0.5%|0.0%|
[sorbs_socks](#sorbs_socks)|29|29|3|10.3%|0.0%|
[sorbs_misc](#sorbs_misc)|29|29|3|10.3%|0.0%|
[sorbs_http](#sorbs_http)|29|29|3|10.3%|0.0%|
[shunlist](#shunlist)|1254|1254|3|0.2%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|2|0.1%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2784|2784|2|0.0%|0.0%|
[zeus_badips](#zeus_badips)|235|235|1|0.4%|0.0%|
[zeus](#zeus)|269|269|1|0.3%|0.0%|
[openbl_30d](#openbl_30d)|3260|3260|1|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|
[dshield](#dshield)|20|5120|1|0.0%|0.0%|
[ciarmy](#ciarmy)|329|329|1|0.3%|0.0%|

## virbl

[VirBL](http://virbl.bit.nl/) is a project of which the idea was born during the RIPE-48 meeting. The plan was to get reports of virusscanning mailservers, and put the IP-addresses that were reported to send viruses on a blacklist.

Source is downloaded from [this link](http://virbl.bit.nl/download/virbl.dnsbl.bit.nl.txt).

The last time downloaded was found to be dated: Fri Jun  5 02:52:04 UTC 2015.

The ipset `virbl` has **10** entries, **10** unique IPs.

The following table shows the overlaps of `virbl` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `virbl`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `virbl`.
- ` this % ` is the percentage **of this ipset (`virbl`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|1|0.0%|10.0%|
[alienvault_reputation](#alienvault_reputation)|177715|177715|1|0.0%|10.0%|

## voipbl

[VoIPBL.org](http://www.voipbl.org/) a distributed VoIP blacklist that is aimed to protects against VoIP Fraud and minimizing abuse for network that have publicly accessible PBX's. Several algorithms, external sources and manual confirmation are used before they categorize something as an attack and determine the threat level.

Source is downloaded from [this link](http://www.voipbl.org/update/).

The last time downloaded was found to be dated: Thu Jun  4 23:54:13 UTC 2015.

The ipset `voipbl` has **10426** entries, **10837** unique IPs.

The following table shows the overlaps of `voipbl` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `voipbl`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `voipbl`.
- ` this % ` is the percentage **of this ipset (`voipbl`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|1596|0.0%|14.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|434|0.0%|4.0%|
[fullbogons](#fullbogons)|3733|670419608|319|0.0%|2.9%|
[bogons](#bogons)|13|592708608|319|0.0%|2.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|299|0.0%|2.7%|
[alienvault_reputation](#alienvault_reputation)|177715|177715|204|0.1%|1.8%|
[blocklist_de](#blocklist_de)|33391|33391|47|0.1%|0.4%|
[blocklist_de_sip](#blocklist_de_sip)|101|101|38|37.6%|0.3%|
[stopforumspam_30d](#stopforumspam_30d)|93498|93498|37|0.0%|0.3%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|14|0.0%|0.1%|
[et_block](#et_block)|1007|18338646|14|0.0%|0.1%|
[stopforumspam_7d](#stopforumspam_7d)|29882|29882|13|0.0%|0.1%|
[shunlist](#shunlist)|1254|1254|12|0.9%|0.1%|
[openbl_60d](#openbl_60d)|7695|7695|8|0.1%|0.0%|
[ciarmy](#ciarmy)|329|329|6|1.8%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7048|7048|5|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|4|0.0%|0.0%|
[openbl_30d](#openbl_30d)|3260|3260|3|0.0%|0.0%|
[dshield](#dshield)|20|5120|3|0.0%|0.0%|
[dm_tor](#dm_tor)|6496|6496|3|0.0%|0.0%|
[bm_tor](#bm_tor)|6497|6497|3|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|9757|9757|3|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13971|13971|3|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|2|0.0%|0.0%|
[et_tor](#et_tor)|6380|6380|2|0.0%|0.0%|
[et_compromised](#et_compromised)|2171|2171|2|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2024|2024|2|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3165|3165|2|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9882|9882|1|0.0%|0.0%|
[openbl_7d](#openbl_7d)|927|927|1|0.1%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|16579|16579|1|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2784|2784|1|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2620|2620|1|0.0%|0.0%|

## xroxy

[xroxy.com](http://www.xroxy.com) open proxies (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.xroxy.com/proxyrss.xml).

The last time downloaded was found to be dated: Fri Jun  5 02:33:02 UTC 2015.

The ipset `xroxy` has **2076** entries, **2076** unique IPs.

The following table shows the overlaps of `xroxy` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `xroxy`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `xroxy`.
- ` this % ` is the percentage **of this ipset (`xroxy`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_30d](#stopforumspam_30d)|93498|93498|1218|1.3%|58.6%|
[ri_web_proxies](#ri_web_proxies)|6295|6295|881|13.9%|42.4%|
[stopforumspam_7d](#stopforumspam_7d)|29882|29882|771|2.5%|37.1%|
[proxyrss](#proxyrss)|1772|1772|450|25.3%|21.6%|
[ri_connect_proxies](#ri_connect_proxies)|2352|2352|357|15.1%|17.1%|
[proxz](#proxz)|747|747|310|41.4%|14.9%|
[stopforumspam_1d](#stopforumspam_1d)|7048|7048|278|3.9%|13.3%|
[blocklist_de](#blocklist_de)|33391|33391|269|0.8%|12.9%|
[blocklist_de_bots](#blocklist_de_bots)|3165|3165|211|6.6%|10.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|100|0.0%|4.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|92|0.0%|4.4%|
[sorbs_spam](#sorbs_spam)|25876|26785|83|0.3%|3.9%|
[sorbs_recent_spam](#sorbs_recent_spam)|21123|21796|81|0.3%|3.9%|
[sorbs_new_spam](#sorbs_new_spam)|21123|21796|81|0.3%|3.9%|
[nixspam](#nixspam)|18430|18430|78|0.4%|3.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|58|0.0%|2.7%|
[blocklist_de_mail](#blocklist_de_mail)|16579|16579|55|0.3%|2.6%|
[snort_ipfilter](#snort_ipfilter)|9882|9882|51|0.5%|2.4%|
[sorbs_web](#sorbs_web)|749|751|27|3.5%|1.3%|
[php_dictionary](#php_dictionary)|475|475|27|5.6%|1.3%|
[php_spammers](#php_spammers)|461|461|22|4.7%|1.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|13|1.9%|0.6%|
[php_commenters](#php_commenters)|301|301|6|1.9%|0.2%|
[blocklist_de_strongips](#blocklist_de_strongips)|177|177|6|3.3%|0.2%|
[alienvault_reputation](#alienvault_reputation)|177715|177715|5|0.0%|0.2%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|3|0.0%|0.1%|
[php_harvesters](#php_harvesters)|298|298|2|0.6%|0.0%|
[et_tor](#et_tor)|6380|6380|2|0.0%|0.0%|
[dm_tor](#dm_tor)|6496|6496|2|0.0%|0.0%|
[bm_tor](#bm_tor)|6497|6497|2|0.0%|0.0%|
[sorbs_socks](#sorbs_socks)|29|29|1|3.4%|0.0%|
[sorbs_misc](#sorbs_misc)|29|29|1|3.4%|0.0%|
[sorbs_http](#sorbs_http)|29|29|1|3.4%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.0%|
[et_compromised](#et_compromised)|2171|2171|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2024|2024|1|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|9757|9757|1|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2620|2620|1|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13971|13971|1|0.0%|0.0%|

## zeus

[Abuse.ch Zeus tracker](https://zeustracker.abuse.ch) standard, contains the same data as the ZeuS IP blocklist (zeus_badips) but with the slight difference that it doesn't exclude hijacked websites (level 2) and free web hosting providers (level 3). This means that this blocklist contains all IPv4 addresses associated with ZeuS C&Cs which are currently being tracked by ZeuS Tracker. Hence this blocklist will likely cause some false positives. - **excellent list**

Source is downloaded from [this link](https://zeustracker.abuse.ch/blocklist.php?download=ipblocklist).

The last time downloaded was found to be dated: Fri Jun  5 02:42:24 UTC 2015.

The ipset `zeus` has **269** entries, **269** unique IPs.

The following table shows the overlaps of `zeus` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `zeus`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `zeus`.
- ` this % ` is the percentage **of this ipset (`zeus`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[et_block](#et_block)|1007|18338646|258|0.0%|95.9%|
[zeus_badips](#zeus_badips)|235|235|235|100.0%|87.3%|
[snort_ipfilter](#snort_ipfilter)|9882|9882|229|2.3%|85.1%|
[alienvault_reputation](#alienvault_reputation)|177715|177715|65|0.0%|24.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|20|0.0%|7.4%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|16|0.0%|5.9%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|10|0.0%|3.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|9|0.0%|3.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|7|0.0%|2.6%|
[spamhaus_edrop](#spamhaus_edrop)|55|486400|5|0.0%|1.8%|
[stopforumspam_30d](#stopforumspam_30d)|93498|93498|2|0.0%|0.7%|
[openbl_60d](#openbl_60d)|7695|7695|2|0.0%|0.7%|
[openbl_30d](#openbl_30d)|3260|3260|2|0.0%|0.7%|
[stopforumspam_7d](#stopforumspam_7d)|29882|29882|1|0.0%|0.3%|
[stopforumspam_1d](#stopforumspam_1d)|7048|7048|1|0.0%|0.3%|
[php_commenters](#php_commenters)|301|301|1|0.3%|0.3%|
[nixspam](#nixspam)|18430|18430|1|0.0%|0.3%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.3%|

## zeus_badips

[Abuse.ch Zeus tracker](https://zeustracker.abuse.ch) badips includes IPv4 addresses that are used by the ZeuS trojan. It is the recommened blocklist if you want to block only ZeuS IPs. It excludes IP addresses that ZeuS Tracker believes to be hijacked (level 2) or belong to a free web hosting provider (level 3). Hence the false postive rate should be much lower compared to the standard ZeuS IP blocklist. **excellent list**

Source is downloaded from [this link](https://zeustracker.abuse.ch/blocklist.php?download=badips).

The last time downloaded was found to be dated: Fri Jun  5 02:54:17 UTC 2015.

The ipset `zeus_badips` has **235** entries, **235** unique IPs.

The following table shows the overlaps of `zeus_badips` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `zeus_badips`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `zeus_badips`.
- ` this % ` is the percentage **of this ipset (`zeus_badips`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[zeus](#zeus)|269|269|235|87.3%|100.0%|
[et_block](#et_block)|1007|18338646|230|0.0%|97.8%|
[snort_ipfilter](#snort_ipfilter)|9882|9882|206|2.0%|87.6%|
[alienvault_reputation](#alienvault_reputation)|177715|177715|38|0.0%|16.1%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|16|0.0%|6.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|14|0.0%|5.9%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|10|0.0%|4.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|8|0.0%|3.4%|
[spamhaus_edrop](#spamhaus_edrop)|55|486400|5|0.0%|2.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|5|0.0%|2.1%|
[stopforumspam_30d](#stopforumspam_30d)|93498|93498|2|0.0%|0.8%|
[stopforumspam_7d](#stopforumspam_7d)|29882|29882|1|0.0%|0.4%|
[stopforumspam_1d](#stopforumspam_1d)|7048|7048|1|0.0%|0.4%|
[php_commenters](#php_commenters)|301|301|1|0.3%|0.4%|
[openbl_60d](#openbl_60d)|7695|7695|1|0.0%|0.4%|
[openbl_30d](#openbl_30d)|3260|3260|1|0.0%|0.4%|
[nixspam](#nixspam)|18430|18430|1|0.0%|0.4%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.4%|
