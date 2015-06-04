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

The following list was automatically generated on Thu Jun  4 21:38:02 UTC 2015.

The update frequency is the maximum allowed by internal configuration. A list will never be downloaded sooner than the update frequency stated. A list may also not be downloaded, after this frequency expired, if it has not been modified on the server (as reported by HTTP `IF_MODIFIED_SINCE` method).

name|info|type|entries|update|
:--:|:--:|:--:|:-----:|:----:|
[alienvault_reputation](#alienvault_reputation)|[AlienVault.com](https://www.alienvault.com/) IP reputation database (this list seems to include port scanning hosts and to be updated regularly, but we found no information about its retention policy)|ipv4 hash:ip|182510 unique IPs|updated every 6 hours  from [this link](https://reputation.alienvault.com/reputation.generic)
[blocklist_de](#blocklist_de)|[Blocklist.de](https://www.blocklist.de/) IPs that have been detected by fail2ban in the last 48 hours - **excellent list**|ipv4 hash:ip|35206 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/all.txt)
[blocklist_de_apache](#blocklist_de_apache)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service Apache, Apache-DDOS, RFI-Attacks.|ipv4 hash:ip|13937 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/apache.txt)
[blocklist_de_bots](#blocklist_de_bots)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the RFI-Attacks, REG-Bots, IRC-Bots or BadBots (BadBots = he has posted a Spam-Comment on a open Forum or Wiki).|ipv4 hash:ip|3178 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/bots.txt)
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|[Blocklist.de](https://www.blocklist.de/) All IPs which attacks Joomlas, Wordpress and other Web-Logins with Brute-Force Logins.|ipv4 hash:ip|2582 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/bruteforcelogin.txt)
[blocklist_de_ftp](#blocklist_de_ftp)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours for attacks on the Service FTP.|ipv4 hash:ip|908 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/ftp.txt)
[blocklist_de_imap](#blocklist_de_imap)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours for attacks on the Service imap, sasl, pop3, etc.|ipv4 hash:ip|2837 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/imap.txt)
[blocklist_de_mail](#blocklist_de_mail)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service Mail, Postfix.|ipv4 hash:ip|16874 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/mail.txt)
[blocklist_de_sip](#blocklist_de_sip)|[Blocklist.de](https://www.blocklist.de/) All IP addresses that tried to login in a SIP, VOIP or Asterisk Server and are included in the IPs list from [infiltrated.net](www.infiltrated.net)|ipv4 hash:ip|105 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/sip.txt)
[blocklist_de_ssh](#blocklist_de_ssh)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service SSH.|ipv4 hash:ip|11179 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/ssh.txt)
[blocklist_de_strongips](#blocklist_de_strongips)|[Blocklist.de](https://www.blocklist.de/) All IPs which are older then 2 month and have more then 5.000 attacks.|ipv4 hash:ip|175 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/strongips.txt)
[bm_tor](#bm_tor)|[torstatus.blutmagie.de](https://torstatus.blutmagie.de) list of all TOR network servers|ipv4 hash:ip|6624 unique IPs|updated every 30 mins  from [this link](https://torstatus.blutmagie.de/ip_list_all.php/Tor_ip_list_ALL.csv)
[bogons](#bogons)|[Team-Cymru.org](http://www.team-cymru.org) private and reserved addresses defined by RFC 1918, RFC 5735, and RFC 6598 and netblocks that have not been allocated to a regional internet registry - **excellent list - use it only your internet interface**|ipv4 hash:net|13 subnets, 592708608 unique IPs|updated every 1 day  from [this link](http://www.team-cymru.org/Services/Bogons/bogon-bn-agg.txt)
[bruteforceblocker](#bruteforceblocker)|[danger.rulez.sk](http://danger.rulez.sk/) IPs detected by [bruteforceblocker](http://danger.rulez.sk/index.php/bruteforceblocker/) (fail2ban alternative for SSH on OpenBSD). This is an automatically generated list from users reporting failed authentication attempts. An IP seems to be included if 3 or more users report it. Its retention pocily seems 30 days.|ipv4 hash:ip|2039 unique IPs|updated every 3 hours  from [this link](http://danger.rulez.sk/projects/bruteforceblocker/blist.php)
[ciarmy](#ciarmy)|[CIArmy.com](http://ciarmy.com/) IPs with poor Rogue Packet score that have not yet been identified as malicious by the community|ipv4 hash:ip|359 unique IPs|updated every 3 hours  from [this link](http://cinsscore.com/list/ci-badguys.txt)
[cleanmx_viruses](#cleanmx_viruses)|[Clean-MX.de](http://support.clean-mx.de/clean-mx/viruses.php) IPs with viruses|ipv4 hash:ip|370 unique IPs|updated every 12 hours  from [this link](http://support.clean-mx.de/clean-mx/xmlviruses.php?sort=id%20desc&response=alive)
[dm_tor](#dm_tor)|[dan.me.uk](https://www.dan.me.uk) dynamic list of TOR exit points|ipv4 hash:ip|6610 unique IPs|updated every 30 mins  from [this link](https://www.dan.me.uk/torlist/)
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
[nixspam](#nixspam)|[NiX Spam](http://www.heise.de/ix/NiX-Spam-DNSBL-and-blacklist-for-download-499637.html) IP addresses that sent spam in the last hour - automatically generated entries without distinguishing open proxies from relays, dialup gateways, and so on. All IPs are removed after 12 hours if there is no spam from there.|ipv4 hash:ip|21252 unique IPs|updated every 15 mins  from [this link](http://www.dnsbl.manitu.net/download/nixspam-ip.dump.gz)
openbl|[OpenBL.org](http://www.openbl.org/) default blacklist (currently it is the same with 90 days). OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications - **excellent list**|ipv4 hash:ip|disabled|updated every 4 hours  from [this link](http://www.openbl.org/lists/base.txt)
openbl_180d|[OpenBL.org](http://www.openbl.org/) last 180 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|disabled|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_180days.txt)
[openbl_1d](#openbl_1d)|[OpenBL.org](http://www.openbl.org/) last 24 hours IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|182 unique IPs|updated every 1 hour  from [this link](http://www.openbl.org/lists/base_1days.txt)
[openbl_30d](#openbl_30d)|[OpenBL.org](http://www.openbl.org/) last 30 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|3261 unique IPs|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_30days.txt)
openbl_360d|[OpenBL.org](http://www.openbl.org/) last 360 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|disabled|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_360days.txt)
[openbl_60d](#openbl_60d)|[OpenBL.org](http://www.openbl.org/) last 60 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|7699 unique IPs|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_60days.txt)
[openbl_7d](#openbl_7d)|[OpenBL.org](http://www.openbl.org/) last 7 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|935 unique IPs|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_7days.txt)
openbl_90d|[OpenBL.org](http://www.openbl.org/) last 90 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|disabled|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_90days.txt)
openbl_all|[OpenBL.org](http://www.openbl.org/) last all IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|disabled|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_all.txt)
[palevo](#palevo)|[Abuse.ch Palevo tracker](https://palevotracker.abuse.ch) worm includes IPs which are being used as botnet C&C for the Palevo crimeware - **excellent list**|ipv4 hash:ip|13 unique IPs|updated every 30 mins  from [this link](https://palevotracker.abuse.ch/blocklists.php?download=ipblocklist)
php_bad|[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) bad web hosts (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|disabled|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=b&rss=1)
[php_commenters](#php_commenters)|[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) comment spammers (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|301 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=c&rss=1)
[php_dictionary](#php_dictionary)|[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) directory attackers (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|475 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=d&rss=1)
[php_harvesters](#php_harvesters)|[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) harvesters (IPs that surf the internet looking for email addresses) (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|298 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=h&rss=1)
[php_spammers](#php_spammers)|[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) spam servers (IPs used by spammers to send messages) (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|461 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=s&rss=1)
[proxyrss](#proxyrss)|[proxyrss.com](http://www.proxyrss.com) open proxies syndicated from multiple sources.|ipv4 hash:ip|1758 unique IPs|updated every 4 hours  from [this link](http://www.proxyrss.com/proxylists/all.gz)
[proxz](#proxz)|[proxz.com](http://www.proxz.com) open proxies (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|733 unique IPs|updated every 1 hour  from [this link](http://www.proxz.com/proxylists.xml)
[ri_connect_proxies](#ri_connect_proxies)|[rosinstrument.com](http://www.rosinstrument.com) open CONNECT proxies (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|2341 unique IPs|updated every 1 hour  from [this link](http://tools.rosinstrument.com/proxy/plab100.xml)
[ri_web_proxies](#ri_web_proxies)|[rosinstrument.com](http://www.rosinstrument.com) open HTTP proxies (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|6246 unique IPs|updated every 1 hour  from [this link](http://tools.rosinstrument.com/proxy/l100.xml)
[shunlist](#shunlist)|[AutoShun.org](http://autoshun.org/) IPs identified as hostile by correlating logs from distributed snort installations running the autoshun plugin|ipv4 hash:ip|1229 unique IPs|updated every 4 hours  from [this link](http://www.autoshun.org/files/shunlist.csv)
[snort_ipfilter](#snort_ipfilter)|[labs.snort.org](https://labs.snort.org/) supplied IP blacklist (this list seems to be updated frequently, but we found no information about it)|ipv4 hash:ip|9591 unique IPs|updated every 12 hours  from [this link](http://labs.snort.org/feeds/ip-filter.blf)
[sorbs_dul](#sorbs_dul)|[Sorbs.net](https://www.sorbs.net/) DUL, Dynamic User IPs extracted from deltas.|ipv4 hash:net|8 subnets, 3584 unique IPs|updated every 1 min  from [this link]()
[sorbs_http](#sorbs_http)|[Sorbs.net](https://www.sorbs.net/) HTTP proxies, extracted from deltas.|ipv4 hash:net|28 subnets, 28 unique IPs|updated every 1 min  from [this link]()
[sorbs_misc](#sorbs_misc)|[Sorbs.net](https://www.sorbs.net/) MISC proxies, extracted from deltas.|ipv4 hash:net|28 subnets, 28 unique IPs|updated every 1 min  from [this link]()
[sorbs_new_spam](#sorbs_new_spam)|[Sorbs.net](https://www.sorbs.net/) NEW Spam senders, extracted from deltas.|ipv4 hash:net|20387 subnets, 21001 unique IPs|updated every 1 min  from [this link]()
[sorbs_recent_spam](#sorbs_recent_spam)|[Sorbs.net](https://www.sorbs.net/) RECENT Spam senders, extracted from deltas.|ipv4 hash:net|20387 subnets, 21001 unique IPs|updated every 1 min  from [this link]()
[sorbs_smtp](#sorbs_smtp)|[Sorbs.net](https://www.sorbs.net/) SMTP Open Relays, extracted from deltas.|ipv4 hash:net|10 subnets, 10 unique IPs|updated every 1 min  from [this link]()
[sorbs_socks](#sorbs_socks)|[Sorbs.net](https://www.sorbs.net/) SOCKS proxies, extracted from deltas.|ipv4 hash:net|28 subnets, 28 unique IPs|updated every 1 min  from [this link]()
[sorbs_spam](#sorbs_spam)|[Sorbs.net](https://www.sorbs.net/) Spam senders, extracted from deltas.|ipv4 hash:net|25175 subnets, 26038 unique IPs|updated every 1 min  from [this link]()
[sorbs_web](#sorbs_web)|[Sorbs.net](https://www.sorbs.net/) WEB exploits, extracted from deltas.|ipv4 hash:net|730 subnets, 732 unique IPs|updated every 1 min  from [this link]()
[spamhaus_drop](#spamhaus_drop)|[Spamhaus.org](http://www.spamhaus.org) DROP list (according to their site this list should be dropped at tier-1 ISPs globaly) - **excellent list**|ipv4 hash:net|653 subnets, 18404096 unique IPs|updated every 12 hours  from [this link](http://www.spamhaus.org/drop/drop.txt)
[spamhaus_edrop](#spamhaus_edrop)|[Spamhaus.org](http://www.spamhaus.org) EDROP (extended matches that should be used with DROP) - **excellent list**|ipv4 hash:net|55 subnets, 486400 unique IPs|updated every 12 hours  from [this link](http://www.spamhaus.org/drop/edrop.txt)
[sslbl](#sslbl)|[Abuse.ch SSL Blacklist](https://sslbl.abuse.ch/) bad SSL traffic related to malware or botnet activities - **excellent list**|ipv4 hash:ip|365 unique IPs|updated every 30 mins  from [this link](https://sslbl.abuse.ch/blacklist/sslipblacklist.csv)
stopforumspam_180d|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 180 days)|ipv4 hash:ip|disabled|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/listed_ip_180.zip)
[stopforumspam_1d](#stopforumspam_1d)|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers in the last 24 hours - **excellent list**|ipv4 hash:ip|7043 unique IPs|updated every 1 hour  from [this link](http://www.stopforumspam.com/downloads/listed_ip_1.zip)
[stopforumspam_30d](#stopforumspam_30d)|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 30 days)|ipv4 hash:ip|92996 unique IPs|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/listed_ip_30.zip)
stopforumspam_365d|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 365 days)|ipv4 hash:ip|disabled|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/listed_ip_365.zip)
[stopforumspam_7d](#stopforumspam_7d)|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 7 days)|ipv4 hash:ip|30334 unique IPs|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/listed_ip_7.zip)
stopforumspam_90d|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 90 days)|ipv4 hash:ip|disabled|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/listed_ip_90.zip)
stopforumspam_ever|[StopForumSpam.com](http://www.stopforumspam.com) all IPs used by forum spammers, **ever** (normally you don't want to use this ipset, use the hourly one which includes last 24 hours IPs or the 7 days one)|ipv4 hash:ip|disabled|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/bannedips.zip)
[virbl](#virbl)|[VirBL](http://virbl.bit.nl/) is a project of which the idea was born during the RIPE-48 meeting. The plan was to get reports of virusscanning mailservers, and put the IP-addresses that were reported to send viruses on a blacklist.|ipv4 hash:ip|11 unique IPs|updated every 1 hour  from [this link](http://virbl.bit.nl/download/virbl.dnsbl.bit.nl.txt)
[voipbl](#voipbl)|[VoIPBL.org](http://www.voipbl.org/) a distributed VoIP blacklist that is aimed to protects against VoIP Fraud and minimizing abuse for network that have publicly accessible PBX's. Several algorithms, external sources and manual confirmation are used before they categorize something as an attack and determine the threat level.|ipv4 hash:net|10426 subnets, 10837 unique IPs|updated every 4 hours  from [this link](http://www.voipbl.org/update/)
[xroxy](#xroxy)|[xroxy.com](http://www.xroxy.com) open proxies (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|2072 unique IPs|updated every 1 hour  from [this link](http://www.xroxy.com/proxyrss.xml)
[zeus](#zeus)|[Abuse.ch Zeus tracker](https://zeustracker.abuse.ch) standard, contains the same data as the ZeuS IP blocklist (zeus_badips) but with the slight difference that it doesn't exclude hijacked websites (level 2) and free web hosting providers (level 3). This means that this blocklist contains all IPv4 addresses associated with ZeuS C&Cs which are currently being tracked by ZeuS Tracker. Hence this blocklist will likely cause some false positives. - **excellent list**|ipv4 hash:ip|268 unique IPs|updated every 30 mins  from [this link](https://zeustracker.abuse.ch/blocklist.php?download=ipblocklist)
[zeus_badips](#zeus_badips)|[Abuse.ch Zeus tracker](https://zeustracker.abuse.ch) badips includes IPv4 addresses that are used by the ZeuS trojan. It is the recommened blocklist if you want to block only ZeuS IPs. It excludes IP addresses that ZeuS Tracker believes to be hijacked (level 2) or belong to a free web hosting provider (level 3). Hence the false postive rate should be much lower compared to the standard ZeuS IP blocklist. **excellent list**|ipv4 hash:ip|234 unique IPs|updated every 30 mins  from [this link](https://zeustracker.abuse.ch/blocklist.php?download=badips)

# Comparison of ipsets

Below we compare each ipset against all other.


## alienvault_reputation

[AlienVault.com](https://www.alienvault.com/) IP reputation database (this list seems to include port scanning hosts and to be updated regularly, but we found no information about its retention policy)

Source is downloaded from [this link](https://reputation.alienvault.com/reputation.generic).

The last time downloaded was found to be dated: Thu Jun  4 16:00:23 UTC 2015.

The ipset `alienvault_reputation` has **182510** entries, **182510** unique IPs.

The following table shows the overlaps of `alienvault_reputation` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `alienvault_reputation`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `alienvault_reputation`.
- ` this % ` is the percentage **of this ipset (`alienvault_reputation`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|14395|0.0%|7.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|7807|0.0%|4.2%|
[openbl_60d](#openbl_60d)|7699|7699|7673|99.6%|4.2%|
[et_block](#et_block)|1007|18338646|5793|0.0%|3.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|4479|0.0%|2.4%|
[dshield](#dshield)|20|5120|3334|65.1%|1.8%|
[openbl_30d](#openbl_30d)|3261|3261|3241|99.3%|1.7%|
[blocklist_de](#blocklist_de)|35206|35206|2088|5.9%|1.1%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|1885|0.0%|1.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|11179|11179|1835|16.4%|1.0%|
[et_compromised](#et_compromised)|2171|2171|1408|64.8%|0.7%|
[bruteforceblocker](#bruteforceblocker)|2039|2039|1327|65.0%|0.7%|
[shunlist](#shunlist)|1229|1229|1221|99.3%|0.6%|
[openbl_7d](#openbl_7d)|935|935|924|98.8%|0.5%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|518|0.0%|0.2%|
[ciarmy](#ciarmy)|359|359|346|96.3%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|287|0.0%|0.1%|
[stopforumspam_30d](#stopforumspam_30d)|92996|92996|220|0.2%|0.1%|
[voipbl](#voipbl)|10426|10837|203|1.8%|0.1%|
[openbl_1d](#openbl_1d)|182|182|176|96.7%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13937|13937|137|0.9%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9591|9591|125|1.3%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|30334|30334|108|0.3%|0.0%|
[sorbs_spam](#sorbs_spam)|25175|26038|76|0.2%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|16874|16874|73|0.4%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|20387|21001|66|0.3%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|20387|21001|66|0.3%|0.0%|
[zeus](#zeus)|268|268|65|24.2%|0.0%|
[sslbl](#sslbl)|365|365|64|17.5%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7043|7043|60|0.8%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2837|2837|50|1.7%|0.0%|
[et_tor](#et_tor)|6380|6380|43|0.6%|0.0%|
[dm_tor](#dm_tor)|6610|6610|43|0.6%|0.0%|
[bm_tor](#bm_tor)|6624|6624|43|0.6%|0.0%|
[nixspam](#nixspam)|21252|21252|39|0.1%|0.0%|
[zeus_badips](#zeus_badips)|234|234|38|16.2%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|175|175|34|19.4%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|26|6.9%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3178|3178|25|0.7%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|105|105|18|17.1%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2582|2582|18|0.6%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|486400|15|0.0%|0.0%|
[php_commenters](#php_commenters)|301|301|15|4.9%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|15|0.0%|0.0%|
[malc0de](#malc0de)|379|379|11|2.9%|0.0%|
[php_harvesters](#php_harvesters)|298|298|10|3.3%|0.0%|
[php_dictionary](#php_dictionary)|475|475|8|1.6%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|8|0.5%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|908|908|7|0.7%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|6|0.4%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|370|370|6|1.6%|0.0%|
[xroxy](#xroxy)|2072|2072|5|0.2%|0.0%|
[php_spammers](#php_spammers)|461|461|5|1.0%|0.0%|
[et_botcc](#et_botcc)|508|508|4|0.7%|0.0%|
[ri_web_proxies](#ri_web_proxies)|6246|6246|3|0.0%|0.0%|
[proxz](#proxz)|733|733|3|0.4%|0.0%|
[proxyrss](#proxyrss)|1758|1758|3|0.1%|0.0%|
[virbl](#virbl)|11|11|2|18.1%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2341|2341|2|0.0%|0.0%|
[feodo](#feodo)|94|94|2|2.1%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|1|0.1%|0.0%|

## blocklist_de

[Blocklist.de](https://www.blocklist.de/) IPs that have been detected by fail2ban in the last 48 hours - **excellent list**

Source is downloaded from [this link](http://lists.blocklist.de/lists/all.txt).

The last time downloaded was found to be dated: Thu Jun  4 21:10:04 UTC 2015.

The ipset `blocklist_de` has **35206** entries, **35206** unique IPs.

The following table shows the overlaps of `blocklist_de` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de`.
- ` this % ` is the percentage **of this ipset (`blocklist_de`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de_mail](#blocklist_de_mail)|16874|16874|16874|100.0%|47.9%|
[blocklist_de_apache](#blocklist_de_apache)|13937|13937|13937|100.0%|39.5%|
[blocklist_de_ssh](#blocklist_de_ssh)|11179|11179|11175|99.9%|31.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|5814|0.0%|16.5%|
[blocklist_de_bots](#blocklist_de_bots)|3178|3178|3173|99.8%|9.0%|
[blocklist_de_imap](#blocklist_de_imap)|2837|2837|2837|100.0%|8.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2582|2582|2582|100.0%|7.3%|
[stopforumspam_30d](#stopforumspam_30d)|92996|92996|2469|2.6%|7.0%|
[alienvault_reputation](#alienvault_reputation)|182510|182510|2088|1.1%|5.9%|
[stopforumspam_7d](#stopforumspam_7d)|30334|30334|2078|6.8%|5.9%|
[openbl_60d](#openbl_60d)|7699|7699|1734|22.5%|4.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|1594|0.0%|4.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|1556|0.0%|4.4%|
[stopforumspam_1d](#stopforumspam_1d)|7043|7043|1461|20.7%|4.1%|
[sorbs_spam](#sorbs_spam)|25175|26038|1077|4.1%|3.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|20387|21001|1040|4.9%|2.9%|
[sorbs_new_spam](#sorbs_new_spam)|20387|21001|1040|4.9%|2.9%|
[blocklist_de_ftp](#blocklist_de_ftp)|908|908|905|99.6%|2.5%|
[openbl_30d](#openbl_30d)|3261|3261|865|26.5%|2.4%|
[nixspam](#nixspam)|21252|21252|744|3.5%|2.1%|
[bruteforceblocker](#bruteforceblocker)|2039|2039|678|33.2%|1.9%|
[et_compromised](#et_compromised)|2171|2171|653|30.0%|1.8%|
[openbl_7d](#openbl_7d)|935|935|583|62.3%|1.6%|
[ri_web_proxies](#ri_web_proxies)|6246|6246|416|6.6%|1.1%|
[shunlist](#shunlist)|1229|1229|381|31.0%|1.0%|
[proxyrss](#proxyrss)|1758|1758|271|15.4%|0.7%|
[xroxy](#xroxy)|2072|2072|270|13.0%|0.7%|
[snort_ipfilter](#snort_ipfilter)|9591|9591|194|2.0%|0.5%|
[blocklist_de_strongips](#blocklist_de_strongips)|175|175|175|100.0%|0.4%|
[et_block](#et_block)|1007|18338646|165|0.0%|0.4%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|162|0.0%|0.4%|
[openbl_1d](#openbl_1d)|182|182|148|81.3%|0.4%|
[proxz](#proxz)|733|733|141|19.2%|0.4%|
[sorbs_web](#sorbs_web)|730|732|93|12.7%|0.2%|
[blocklist_de_sip](#blocklist_de_sip)|105|105|86|81.9%|0.2%|
[ri_connect_proxies](#ri_connect_proxies)|2341|2341|75|3.2%|0.2%|
[php_commenters](#php_commenters)|301|301|74|24.5%|0.2%|
[php_dictionary](#php_dictionary)|475|475|67|14.1%|0.1%|
[php_spammers](#php_spammers)|461|461|63|13.6%|0.1%|
[dshield](#dshield)|20|5120|51|0.9%|0.1%|
[voipbl](#voipbl)|10426|10837|47|0.4%|0.1%|
[ciarmy](#ciarmy)|359|359|40|11.1%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|32|0.0%|0.0%|
[php_harvesters](#php_harvesters)|298|298|31|10.4%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|13|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|486400|10|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|9|0.0%|0.0%|
[sorbs_socks](#sorbs_socks)|28|28|6|21.4%|0.0%|
[sorbs_misc](#sorbs_misc)|28|28|6|21.4%|0.0%|
[sorbs_http](#sorbs_http)|28|28|6|21.4%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|6|0.8%|0.0%|
[dm_tor](#dm_tor)|6610|6610|4|0.0%|0.0%|
[bm_tor](#bm_tor)|6624|6624|4|0.0%|0.0%|
[et_tor](#et_tor)|6380|6380|3|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|2|0.5%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.0%|
[sslbl](#sslbl)|365|365|1|0.2%|0.0%|

## blocklist_de_apache

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service Apache, Apache-DDOS, RFI-Attacks.

Source is downloaded from [this link](http://lists.blocklist.de/lists/apache.txt).

The last time downloaded was found to be dated: Thu Jun  4 21:10:06 UTC 2015.

The ipset `blocklist_de_apache` has **13937** entries, **13937** unique IPs.

The following table shows the overlaps of `blocklist_de_apache` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_apache`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_apache`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_apache`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|35206|35206|13937|39.5%|100.0%|
[blocklist_de_mail](#blocklist_de_mail)|16874|16874|11059|65.5%|79.3%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2582|2582|2582|100.0%|18.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|2315|0.0%|16.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|1328|0.0%|9.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|1071|0.0%|7.6%|
[stopforumspam_30d](#stopforumspam_30d)|92996|92996|209|0.2%|1.4%|
[alienvault_reputation](#alienvault_reputation)|182510|182510|137|0.0%|0.9%|
[stopforumspam_7d](#stopforumspam_7d)|30334|30334|129|0.4%|0.9%|
[sorbs_spam](#sorbs_spam)|25175|26038|75|0.2%|0.5%|
[stopforumspam_1d](#stopforumspam_1d)|7043|7043|73|1.0%|0.5%|
[sorbs_recent_spam](#sorbs_recent_spam)|20387|21001|72|0.3%|0.5%|
[sorbs_new_spam](#sorbs_new_spam)|20387|21001|72|0.3%|0.5%|
[nixspam](#nixspam)|21252|21252|46|0.2%|0.3%|
[ciarmy](#ciarmy)|359|359|35|9.7%|0.2%|
[blocklist_de_strongips](#blocklist_de_strongips)|175|175|35|20.0%|0.2%|
[shunlist](#shunlist)|1229|1229|32|2.6%|0.2%|
[php_commenters](#php_commenters)|301|301|24|7.9%|0.1%|
[blocklist_de_bots](#blocklist_de_bots)|3178|3178|24|0.7%|0.1%|
[dshield](#dshield)|20|5120|10|0.1%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9591|9591|8|0.0%|0.0%|
[php_spammers](#php_spammers)|461|461|6|1.3%|0.0%|
[php_dictionary](#php_dictionary)|475|475|5|1.0%|0.0%|
[et_block](#et_block)|1007|18338646|5|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|4|0.0%|0.0%|
[php_harvesters](#php_harvesters)|298|298|4|1.3%|0.0%|
[openbl_60d](#openbl_60d)|7699|7699|4|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|4|0.0%|0.0%|
[et_compromised](#et_compromised)|2171|2171|4|0.1%|0.0%|
[dm_tor](#dm_tor)|6610|6610|4|0.0%|0.0%|
[bm_tor](#bm_tor)|6624|6624|4|0.0%|0.0%|
[voipbl](#voipbl)|10426|10837|3|0.0%|0.0%|
[sorbs_web](#sorbs_web)|730|732|3|0.4%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|3|0.0%|0.0%|
[et_tor](#et_tor)|6380|6380|3|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2039|2039|3|0.1%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|486400|2|0.0%|0.0%|
[openbl_30d](#openbl_30d)|3261|3261|2|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|2|0.5%|0.0%|
[xroxy](#xroxy)|2072|2072|1|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|6246|6246|1|0.0%|0.0%|
[proxyrss](#proxyrss)|1758|1758|1|0.0%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.0%|

## blocklist_de_bots

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the RFI-Attacks, REG-Bots, IRC-Bots or BadBots (BadBots = he has posted a Spam-Comment on a open Forum or Wiki).

Source is downloaded from [this link](http://lists.blocklist.de/lists/bots.txt).

The last time downloaded was found to be dated: Thu Jun  4 21:14:11 UTC 2015.

The ipset `blocklist_de_bots` has **3178** entries, **3178** unique IPs.

The following table shows the overlaps of `blocklist_de_bots` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_bots`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_bots`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_bots`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|35206|35206|3173|9.0%|99.8%|
[stopforumspam_30d](#stopforumspam_30d)|92996|92996|2063|2.2%|64.9%|
[stopforumspam_7d](#stopforumspam_7d)|30334|30334|1874|6.1%|58.9%|
[stopforumspam_1d](#stopforumspam_1d)|7043|7043|1377|19.5%|43.3%|
[ri_web_proxies](#ri_web_proxies)|6246|6246|363|5.8%|11.4%|
[proxyrss](#proxyrss)|1758|1758|270|15.3%|8.4%|
[xroxy](#xroxy)|2072|2072|214|10.3%|6.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|160|0.0%|5.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|175|175|133|76.0%|4.1%|
[proxz](#proxz)|733|733|118|16.0%|3.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|88|0.0%|2.7%|
[ri_connect_proxies](#ri_connect_proxies)|2341|2341|72|3.0%|2.2%|
[php_commenters](#php_commenters)|301|301|59|19.6%|1.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|42|0.0%|1.3%|
[nixspam](#nixspam)|21252|21252|41|0.1%|1.2%|
[sorbs_spam](#sorbs_spam)|25175|26038|32|0.1%|1.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|20387|21001|31|0.1%|0.9%|
[sorbs_new_spam](#sorbs_new_spam)|20387|21001|31|0.1%|0.9%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|25|0.0%|0.7%|
[et_block](#et_block)|1007|18338646|25|0.0%|0.7%|
[alienvault_reputation](#alienvault_reputation)|182510|182510|25|0.0%|0.7%|
[blocklist_de_mail](#blocklist_de_mail)|16874|16874|24|0.1%|0.7%|
[blocklist_de_apache](#blocklist_de_apache)|13937|13937|24|0.1%|0.7%|
[php_harvesters](#php_harvesters)|298|298|21|7.0%|0.6%|
[snort_ipfilter](#snort_ipfilter)|9591|9591|19|0.1%|0.5%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|17|0.0%|0.5%|
[sorbs_web](#sorbs_web)|730|732|10|1.3%|0.3%|
[php_spammers](#php_spammers)|461|461|9|1.9%|0.2%|
[php_dictionary](#php_dictionary)|475|475|8|1.6%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|5|0.0%|0.1%|
[spamhaus_edrop](#spamhaus_edrop)|55|486400|4|0.0%|0.1%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|4|0.5%|0.1%|
[bruteforceblocker](#bruteforceblocker)|2039|2039|3|0.1%|0.0%|
[sorbs_socks](#sorbs_socks)|28|28|2|7.1%|0.0%|
[sorbs_misc](#sorbs_misc)|28|28|2|7.1%|0.0%|
[sorbs_http](#sorbs_http)|28|28|2|7.1%|0.0%|
[et_compromised](#et_compromised)|2171|2171|2|0.0%|0.0%|
[voipbl](#voipbl)|10426|10837|1|0.0%|0.0%|
[openbl_60d](#openbl_60d)|7699|7699|1|0.0%|0.0%|
[openbl_30d](#openbl_30d)|3261|3261|1|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|

## blocklist_de_bruteforce

[Blocklist.de](https://www.blocklist.de/) All IPs which attacks Joomlas, Wordpress and other Web-Logins with Brute-Force Logins.

Source is downloaded from [this link](http://lists.blocklist.de/lists/bruteforcelogin.txt).

The last time downloaded was found to be dated: Thu Jun  4 21:28:12 UTC 2015.

The ipset `blocklist_de_bruteforce` has **2582** entries, **2582** unique IPs.

The following table shows the overlaps of `blocklist_de_bruteforce` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_bruteforce`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_bruteforce`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_bruteforce`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de_apache](#blocklist_de_apache)|13937|13937|2582|18.5%|100.0%|
[blocklist_de](#blocklist_de)|35206|35206|2582|7.3%|100.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|217|0.0%|8.4%|
[sorbs_spam](#sorbs_spam)|25175|26038|75|0.2%|2.9%|
[sorbs_recent_spam](#sorbs_recent_spam)|20387|21001|72|0.3%|2.7%|
[sorbs_new_spam](#sorbs_new_spam)|20387|21001|72|0.3%|2.7%|
[nixspam](#nixspam)|21252|21252|43|0.2%|1.6%|
[stopforumspam_30d](#stopforumspam_30d)|92996|92996|39|0.0%|1.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|39|0.0%|1.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|36|0.0%|1.3%|
[stopforumspam_7d](#stopforumspam_7d)|30334|30334|29|0.0%|1.1%|
[stopforumspam_1d](#stopforumspam_1d)|7043|7043|21|0.2%|0.8%|
[alienvault_reputation](#alienvault_reputation)|182510|182510|18|0.0%|0.6%|
[blocklist_de_strongips](#blocklist_de_strongips)|175|175|7|4.0%|0.2%|
[php_spammers](#php_spammers)|461|461|6|1.3%|0.2%|
[php_dictionary](#php_dictionary)|475|475|5|1.0%|0.1%|
[php_commenters](#php_commenters)|301|301|5|1.6%|0.1%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|4|0.0%|0.1%|
[snort_ipfilter](#snort_ipfilter)|9591|9591|4|0.0%|0.1%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|4|0.0%|0.1%|
[sorbs_web](#sorbs_web)|730|732|3|0.4%|0.1%|
[shunlist](#shunlist)|1229|1229|3|0.2%|0.1%|
[et_block](#et_block)|1007|18338646|3|0.0%|0.1%|
[php_harvesters](#php_harvesters)|298|298|2|0.6%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|2|0.0%|0.0%|
[xroxy](#xroxy)|2072|2072|1|0.0%|0.0%|
[voipbl](#voipbl)|10426|10837|1|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|6246|6246|1|0.0%|0.0%|
[proxyrss](#proxyrss)|1758|1758|1|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.0%|

## blocklist_de_ftp

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours for attacks on the Service FTP.

Source is downloaded from [this link](http://lists.blocklist.de/lists/ftp.txt).

The last time downloaded was found to be dated: Thu Jun  4 21:14:09 UTC 2015.

The ipset `blocklist_de_ftp` has **908** entries, **908** unique IPs.

The following table shows the overlaps of `blocklist_de_ftp` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_ftp`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_ftp`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_ftp`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|35206|35206|905|2.5%|99.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|67|0.0%|7.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|19|0.0%|2.0%|
[stopforumspam_30d](#stopforumspam_30d)|92996|92996|12|0.0%|1.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|12|0.0%|1.3%|
[alienvault_reputation](#alienvault_reputation)|182510|182510|7|0.0%|0.7%|
[stopforumspam_7d](#stopforumspam_7d)|30334|30334|6|0.0%|0.6%|
[nixspam](#nixspam)|21252|21252|6|0.0%|0.6%|
[sorbs_spam](#sorbs_spam)|25175|26038|3|0.0%|0.3%|
[php_harvesters](#php_harvesters)|298|298|3|1.0%|0.3%|
[stopforumspam_1d](#stopforumspam_1d)|7043|7043|2|0.0%|0.2%|
[sorbs_recent_spam](#sorbs_recent_spam)|20387|21001|2|0.0%|0.2%|
[sorbs_new_spam](#sorbs_new_spam)|20387|21001|2|0.0%|0.2%|
[spamhaus_edrop](#spamhaus_edrop)|55|486400|1|0.0%|0.1%|
[php_spammers](#php_spammers)|461|461|1|0.2%|0.1%|
[ciarmy](#ciarmy)|359|359|1|0.2%|0.1%|

## blocklist_de_imap

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours for attacks on the Service imap, sasl, pop3, etc.

Source is downloaded from [this link](http://lists.blocklist.de/lists/imap.txt).

The last time downloaded was found to be dated: Thu Jun  4 21:10:07 UTC 2015.

The ipset `blocklist_de_imap` has **2837** entries, **2837** unique IPs.

The following table shows the overlaps of `blocklist_de_imap` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_imap`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_imap`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_imap`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de_mail](#blocklist_de_mail)|16874|16874|2837|16.8%|100.0%|
[blocklist_de](#blocklist_de)|35206|35206|2837|8.0%|100.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|366|0.0%|12.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|63|0.0%|2.2%|
[alienvault_reputation](#alienvault_reputation)|182510|182510|50|0.0%|1.7%|
[openbl_60d](#openbl_60d)|7699|7699|41|0.5%|1.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|39|0.0%|1.3%|
[openbl_30d](#openbl_30d)|3261|3261|35|1.0%|1.2%|
[nixspam](#nixspam)|21252|21252|25|0.1%|0.8%|
[sorbs_spam](#sorbs_spam)|25175|26038|24|0.0%|0.8%|
[sorbs_recent_spam](#sorbs_recent_spam)|20387|21001|19|0.0%|0.6%|
[sorbs_new_spam](#sorbs_new_spam)|20387|21001|19|0.0%|0.6%|
[openbl_7d](#openbl_7d)|935|935|13|1.3%|0.4%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|12|0.0%|0.4%|
[et_block](#et_block)|1007|18338646|12|0.0%|0.4%|
[stopforumspam_30d](#stopforumspam_30d)|92996|92996|9|0.0%|0.3%|
[et_compromised](#et_compromised)|2171|2171|6|0.2%|0.2%|
[snort_ipfilter](#snort_ipfilter)|9591|9591|5|0.0%|0.1%|
[bruteforceblocker](#bruteforceblocker)|2039|2039|5|0.2%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|0.1%|
[openbl_1d](#openbl_1d)|182|182|2|1.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|2|0.0%|0.0%|
[voipbl](#voipbl)|10426|10837|1|0.0%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|30334|30334|1|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7043|7043|1|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|486400|1|0.0%|0.0%|
[sorbs_web](#sorbs_web)|730|732|1|0.1%|0.0%|
[shunlist](#shunlist)|1229|1229|1|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1|0.0%|0.0%|
[ciarmy](#ciarmy)|359|359|1|0.2%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|175|175|1|0.5%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|11179|11179|1|0.0%|0.0%|

## blocklist_de_mail

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service Mail, Postfix.

Source is downloaded from [this link](http://lists.blocklist.de/lists/mail.txt).

The last time downloaded was found to be dated: Thu Jun  4 21:10:05 UTC 2015.

The ipset `blocklist_de_mail` has **16874** entries, **16874** unique IPs.

The following table shows the overlaps of `blocklist_de_mail` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_mail`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_mail`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_mail`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|35206|35206|16874|47.9%|100.0%|
[blocklist_de_apache](#blocklist_de_apache)|13937|13937|11059|79.3%|65.5%|
[blocklist_de_imap](#blocklist_de_imap)|2837|2837|2837|100.0%|16.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|2574|0.0%|15.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|1374|0.0%|8.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|1172|0.0%|6.9%|
[sorbs_spam](#sorbs_spam)|25175|26038|899|3.4%|5.3%|
[sorbs_recent_spam](#sorbs_recent_spam)|20387|21001|870|4.1%|5.1%|
[sorbs_new_spam](#sorbs_new_spam)|20387|21001|870|4.1%|5.1%|
[nixspam](#nixspam)|21252|21252|638|3.0%|3.7%|
[stopforumspam_30d](#stopforumspam_30d)|92996|92996|262|0.2%|1.5%|
[snort_ipfilter](#snort_ipfilter)|9591|9591|170|1.7%|1.0%|
[stopforumspam_7d](#stopforumspam_7d)|30334|30334|154|0.5%|0.9%|
[sorbs_web](#sorbs_web)|730|732|79|10.7%|0.4%|
[alienvault_reputation](#alienvault_reputation)|182510|182510|73|0.0%|0.4%|
[stopforumspam_1d](#stopforumspam_1d)|7043|7043|61|0.8%|0.3%|
[xroxy](#xroxy)|2072|2072|54|2.6%|0.3%|
[php_dictionary](#php_dictionary)|475|475|54|11.3%|0.3%|
[ri_web_proxies](#ri_web_proxies)|6246|6246|52|0.8%|0.3%|
[php_spammers](#php_spammers)|461|461|47|10.1%|0.2%|
[openbl_60d](#openbl_60d)|7699|7699|46|0.5%|0.2%|
[openbl_30d](#openbl_30d)|3261|3261|40|1.2%|0.2%|
[blocklist_de_bots](#blocklist_de_bots)|3178|3178|24|0.7%|0.1%|
[et_block](#et_block)|1007|18338646|23|0.0%|0.1%|
[blocklist_de_strongips](#blocklist_de_strongips)|175|175|23|13.1%|0.1%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|22|0.0%|0.1%|
[proxz](#proxz)|733|733|22|3.0%|0.1%|
[php_commenters](#php_commenters)|301|301|21|6.9%|0.1%|
[openbl_7d](#openbl_7d)|935|935|15|1.6%|0.0%|
[et_compromised](#et_compromised)|2171|2171|9|0.4%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2039|2039|7|0.3%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|6|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|5|0.0%|0.0%|
[sorbs_socks](#sorbs_socks)|28|28|4|14.2%|0.0%|
[sorbs_misc](#sorbs_misc)|28|28|4|14.2%|0.0%|
[sorbs_http](#sorbs_http)|28|28|4|14.2%|0.0%|
[php_harvesters](#php_harvesters)|298|298|4|1.3%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|4|0.0%|0.0%|
[dm_tor](#dm_tor)|6610|6610|4|0.0%|0.0%|
[bm_tor](#bm_tor)|6624|6624|4|0.0%|0.0%|
[openbl_1d](#openbl_1d)|182|182|3|1.6%|0.0%|
[et_tor](#et_tor)|6380|6380|3|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|486400|2|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2341|2341|2|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|2|0.2%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|11179|11179|2|0.0%|0.0%|
[voipbl](#voipbl)|10426|10837|1|0.0%|0.0%|
[shunlist](#shunlist)|1229|1229|1|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[dshield](#dshield)|20|5120|1|0.0%|0.0%|
[ciarmy](#ciarmy)|359|359|1|0.2%|0.0%|

## blocklist_de_sip

[Blocklist.de](https://www.blocklist.de/) All IP addresses that tried to login in a SIP, VOIP or Asterisk Server and are included in the IPs list from [infiltrated.net](www.infiltrated.net)

Source is downloaded from [this link](http://lists.blocklist.de/lists/sip.txt).

The last time downloaded was found to be dated: Thu Jun  4 21:10:07 UTC 2015.

The ipset `blocklist_de_sip` has **105** entries, **105** unique IPs.

The following table shows the overlaps of `blocklist_de_sip` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_sip`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_sip`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_sip`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|35206|35206|86|0.2%|81.9%|
[voipbl](#voipbl)|10426|10837|39|0.3%|37.1%|
[alienvault_reputation](#alienvault_reputation)|182510|182510|18|0.0%|17.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|14|0.0%|13.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|9|0.0%|8.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|5|0.0%|4.7%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|2|0.0%|1.9%|
[et_botcc](#et_botcc)|508|508|1|0.1%|0.9%|
[dshield](#dshield)|20|5120|1|0.0%|0.9%|
[ciarmy](#ciarmy)|359|359|1|0.2%|0.9%|

## blocklist_de_ssh

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service SSH.

Source is downloaded from [this link](http://lists.blocklist.de/lists/ssh.txt).

The last time downloaded was found to be dated: Thu Jun  4 21:28:05 UTC 2015.

The ipset `blocklist_de_ssh` has **11179** entries, **11179** unique IPs.

The following table shows the overlaps of `blocklist_de_ssh` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_ssh`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_ssh`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_ssh`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|35206|35206|11175|31.7%|99.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|2713|0.0%|24.2%|
[alienvault_reputation](#alienvault_reputation)|182510|182510|1835|1.0%|16.4%|
[openbl_60d](#openbl_60d)|7699|7699|1678|21.7%|15.0%|
[openbl_30d](#openbl_30d)|3261|3261|822|25.2%|7.3%|
[bruteforceblocker](#bruteforceblocker)|2039|2039|666|32.6%|5.9%|
[et_compromised](#et_compromised)|2171|2171|639|29.4%|5.7%|
[openbl_7d](#openbl_7d)|935|935|568|60.7%|5.0%|
[shunlist](#shunlist)|1229|1229|348|28.3%|3.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|224|0.0%|2.0%|
[openbl_1d](#openbl_1d)|182|182|147|80.7%|1.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|115|0.0%|1.0%|
[et_block](#et_block)|1007|18338646|112|0.0%|1.0%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|111|0.0%|0.9%|
[stopforumspam_30d](#stopforumspam_30d)|92996|92996|84|0.0%|0.7%|
[sorbs_spam](#sorbs_spam)|25175|26038|68|0.2%|0.6%|
[sorbs_recent_spam](#sorbs_recent_spam)|20387|21001|65|0.3%|0.5%|
[sorbs_new_spam](#sorbs_new_spam)|20387|21001|65|0.3%|0.5%|
[dshield](#dshield)|20|5120|39|0.7%|0.3%|
[blocklist_de_strongips](#blocklist_de_strongips)|175|175|26|14.8%|0.2%|
[nixspam](#nixspam)|21252|21252|13|0.0%|0.1%|
[stopforumspam_7d](#stopforumspam_7d)|30334|30334|12|0.0%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|8|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7043|7043|6|0.0%|0.0%|
[voipbl](#voipbl)|10426|10837|3|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|2|0.0%|0.0%|
[ciarmy](#ciarmy)|359|359|2|0.5%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|16874|16874|2|0.0%|0.0%|
[xroxy](#xroxy)|2072|2072|1|0.0%|0.0%|
[sslbl](#sslbl)|365|365|1|0.2%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|486400|1|0.0%|0.0%|
[sorbs_web](#sorbs_web)|730|732|1|0.1%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9591|9591|1|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2341|2341|1|0.0%|0.0%|
[proxz](#proxz)|733|733|1|0.1%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2837|2837|1|0.0%|0.0%|

## blocklist_de_strongips

[Blocklist.de](https://www.blocklist.de/) All IPs which are older then 2 month and have more then 5.000 attacks.

Source is downloaded from [this link](http://lists.blocklist.de/lists/strongips.txt).

The last time downloaded was found to be dated: Thu Jun  4 21:14:12 UTC 2015.

The ipset `blocklist_de_strongips` has **175** entries, **175** unique IPs.

The following table shows the overlaps of `blocklist_de_strongips` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_strongips`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_strongips`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_strongips`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|35206|35206|175|0.4%|100.0%|
[blocklist_de_bots](#blocklist_de_bots)|3178|3178|133|4.1%|76.0%|
[stopforumspam_30d](#stopforumspam_30d)|92996|92996|130|0.1%|74.2%|
[stopforumspam_7d](#stopforumspam_7d)|30334|30334|117|0.3%|66.8%|
[stopforumspam_1d](#stopforumspam_1d)|7043|7043|102|1.4%|58.2%|
[blocklist_de_apache](#blocklist_de_apache)|13937|13937|35|0.2%|20.0%|
[alienvault_reputation](#alienvault_reputation)|182510|182510|34|0.0%|19.4%|
[php_commenters](#php_commenters)|301|301|32|10.6%|18.2%|
[blocklist_de_ssh](#blocklist_de_ssh)|11179|11179|26|0.2%|14.8%|
[openbl_60d](#openbl_60d)|7699|7699|25|0.3%|14.2%|
[openbl_30d](#openbl_30d)|3261|3261|24|0.7%|13.7%|
[openbl_7d](#openbl_7d)|935|935|23|2.4%|13.1%|
[blocklist_de_mail](#blocklist_de_mail)|16874|16874|23|0.1%|13.1%|
[openbl_1d](#openbl_1d)|182|182|21|11.5%|12.0%|
[shunlist](#shunlist)|1229|1229|20|1.6%|11.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|15|0.0%|8.5%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2582|2582|7|0.2%|4.0%|
[xroxy](#xroxy)|2072|2072|6|0.2%|3.4%|
[spamhaus_edrop](#spamhaus_edrop)|55|486400|5|0.0%|2.8%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|5|0.0%|2.8%|
[ri_web_proxies](#ri_web_proxies)|6246|6246|5|0.0%|2.8%|
[proxyrss](#proxyrss)|1758|1758|5|0.2%|2.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|5|0.0%|2.8%|
[et_block](#et_block)|1007|18338646|5|0.0%|2.8%|
[php_spammers](#php_spammers)|461|461|4|0.8%|2.2%|
[proxz](#proxz)|733|733|3|0.4%|1.7%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|1.7%|
[php_harvesters](#php_harvesters)|298|298|2|0.6%|1.1%|
[php_dictionary](#php_dictionary)|475|475|2|0.4%|1.1%|
[nixspam](#nixspam)|21252|21252|2|0.0%|1.1%|
[sorbs_web](#sorbs_web)|730|732|1|0.1%|0.5%|
[sorbs_spam](#sorbs_spam)|25175|26038|1|0.0%|0.5%|
[sorbs_recent_spam](#sorbs_recent_spam)|20387|21001|1|0.0%|0.5%|
[sorbs_new_spam](#sorbs_new_spam)|20387|21001|1|0.0%|0.5%|
[snort_ipfilter](#snort_ipfilter)|9591|9591|1|0.0%|0.5%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|1|0.0%|0.5%|
[blocklist_de_imap](#blocklist_de_imap)|2837|2837|1|0.0%|0.5%|

## bm_tor

[torstatus.blutmagie.de](https://torstatus.blutmagie.de) list of all TOR network servers

Source is downloaded from [this link](https://torstatus.blutmagie.de/ip_list_all.php/Tor_ip_list_ALL.csv).

The last time downloaded was found to be dated: Thu Jun  4 21:09:06 UTC 2015.

The ipset `bm_tor` has **6624** entries, **6624** unique IPs.

The following table shows the overlaps of `bm_tor` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `bm_tor`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `bm_tor`.
- ` this % ` is the percentage **of this ipset (`bm_tor`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[dm_tor](#dm_tor)|6610|6610|6527|98.7%|98.5%|
[et_tor](#et_tor)|6380|6380|5669|88.8%|85.5%|
[snort_ipfilter](#snort_ipfilter)|9591|9591|1088|11.3%|16.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|633|0.0%|9.5%|
[stopforumspam_30d](#stopforumspam_30d)|92996|92996|625|0.6%|9.4%|
[stopforumspam_7d](#stopforumspam_7d)|30334|30334|484|1.5%|7.3%|
[stopforumspam_1d](#stopforumspam_1d)|7043|7043|333|4.7%|5.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|188|0.0%|2.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|173|0.0%|2.6%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|169|45.4%|2.5%|
[alienvault_reputation](#alienvault_reputation)|182510|182510|43|0.0%|0.6%|
[php_commenters](#php_commenters)|301|301|33|10.9%|0.4%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|21|0.0%|0.3%|
[openbl_60d](#openbl_60d)|7699|7699|20|0.2%|0.3%|
[php_harvesters](#php_harvesters)|298|298|7|2.3%|0.1%|
[php_spammers](#php_spammers)|461|461|6|1.3%|0.0%|
[php_dictionary](#php_dictionary)|475|475|5|1.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|6246|6246|4|0.0%|0.0%|
[et_block](#et_block)|1007|18338646|4|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|16874|16874|4|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13937|13937|4|0.0%|0.0%|
[blocklist_de](#blocklist_de)|35206|35206|4|0.0%|0.0%|
[voipbl](#voipbl)|10426|10837|3|0.0%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|0.0%|
[xroxy](#xroxy)|2072|2072|2|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|2|0.0%|0.0%|
[nixspam](#nixspam)|21252|21252|2|0.0%|0.0%|
[dshield](#dshield)|20|5120|2|0.0%|0.0%|
[sorbs_spam](#sorbs_spam)|25175|26038|1|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|20387|21001|1|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|20387|21001|1|0.0%|0.0%|
[shunlist](#shunlist)|1229|1229|1|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2341|2341|1|0.0%|0.0%|
[proxyrss](#proxyrss)|1758|1758|1|0.0%|0.0%|

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
[stopforumspam_30d](#stopforumspam_30d)|92996|92996|1|0.0%|0.0%|
[php_harvesters](#php_harvesters)|298|298|1|0.3%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.0%|
[ciarmy](#ciarmy)|359|359|1|0.2%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2039|2039|1|0.0%|0.0%|

## bruteforceblocker

[danger.rulez.sk](http://danger.rulez.sk/) IPs detected by [bruteforceblocker](http://danger.rulez.sk/index.php/bruteforceblocker/) (fail2ban alternative for SSH on OpenBSD). This is an automatically generated list from users reporting failed authentication attempts. An IP seems to be included if 3 or more users report it. Its retention pocily seems 30 days.

Source is downloaded from [this link](http://danger.rulez.sk/projects/bruteforceblocker/blist.php).

The last time downloaded was found to be dated: Thu Jun  4 18:45:06 UTC 2015.

The ipset `bruteforceblocker` has **2039** entries, **2039** unique IPs.

The following table shows the overlaps of `bruteforceblocker` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `bruteforceblocker`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `bruteforceblocker`.
- ` this % ` is the percentage **of this ipset (`bruteforceblocker`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[et_compromised](#et_compromised)|2171|2171|1985|91.4%|97.3%|
[alienvault_reputation](#alienvault_reputation)|182510|182510|1327|0.7%|65.0%|
[openbl_60d](#openbl_60d)|7699|7699|1231|15.9%|60.3%|
[openbl_30d](#openbl_30d)|3261|3261|1173|35.9%|57.5%|
[blocklist_de](#blocklist_de)|35206|35206|678|1.9%|33.2%|
[blocklist_de_ssh](#blocklist_de_ssh)|11179|11179|666|5.9%|32.6%|
[shunlist](#shunlist)|1229|1229|474|38.5%|23.2%|
[openbl_7d](#openbl_7d)|935|935|422|45.1%|20.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|199|0.0%|9.7%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|100|0.0%|4.9%|
[et_block](#et_block)|1007|18338646|100|0.0%|4.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|97|0.0%|4.7%|
[openbl_1d](#openbl_1d)|182|182|96|52.7%|4.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|56|0.0%|2.7%|
[dshield](#dshield)|20|5120|35|0.6%|1.7%|
[stopforumspam_30d](#stopforumspam_30d)|92996|92996|10|0.0%|0.4%|
[blocklist_de_mail](#blocklist_de_mail)|16874|16874|7|0.0%|0.3%|
[stopforumspam_7d](#stopforumspam_7d)|30334|30334|6|0.0%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|5|0.0%|0.2%|
[blocklist_de_imap](#blocklist_de_imap)|2837|2837|5|0.1%|0.2%|
[blocklist_de_bots](#blocklist_de_bots)|3178|3178|3|0.0%|0.1%|
[blocklist_de_apache](#blocklist_de_apache)|13937|13937|3|0.0%|0.1%|
[voipbl](#voipbl)|10426|10837|2|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7043|7043|2|0.0%|0.0%|
[proxz](#proxz)|733|733|2|0.2%|0.0%|
[proxyrss](#proxyrss)|1758|1758|2|0.1%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|2|0.0%|0.0%|
[xroxy](#xroxy)|2072|2072|1|0.0%|0.0%|
[sorbs_spam](#sorbs_spam)|25175|26038|1|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9591|9591|1|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|6246|6246|1|0.0%|0.0%|
[fullbogons](#fullbogons)|3733|670419608|1|0.0%|0.0%|
[ciarmy](#ciarmy)|359|359|1|0.2%|0.0%|
[bogons](#bogons)|13|592708608|1|0.0%|0.0%|

## ciarmy

[CIArmy.com](http://ciarmy.com/) IPs with poor Rogue Packet score that have not yet been identified as malicious by the community

Source is downloaded from [this link](http://cinsscore.com/list/ci-badguys.txt).

The last time downloaded was found to be dated: Thu Jun  4 19:15:16 UTC 2015.

The ipset `ciarmy` has **359** entries, **359** unique IPs.

The following table shows the overlaps of `ciarmy` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ciarmy`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ciarmy`.
- ` this % ` is the percentage **of this ipset (`ciarmy`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[alienvault_reputation](#alienvault_reputation)|182510|182510|346|0.1%|96.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|55|0.0%|15.3%|
[blocklist_de](#blocklist_de)|35206|35206|40|0.1%|11.1%|
[blocklist_de_apache](#blocklist_de_apache)|13937|13937|35|0.2%|9.7%|
[shunlist](#shunlist)|1229|1229|28|2.2%|7.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|18|0.0%|5.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|7|0.0%|1.9%|
[voipbl](#voipbl)|10426|10837|6|0.0%|1.6%|
[dshield](#dshield)|20|5120|3|0.0%|0.8%|
[blocklist_de_ssh](#blocklist_de_ssh)|11179|11179|2|0.0%|0.5%|
[stopforumspam_7d](#stopforumspam_7d)|30334|30334|1|0.0%|0.2%|
[stopforumspam_30d](#stopforumspam_30d)|92996|92996|1|0.0%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.2%|
[fullbogons](#fullbogons)|3733|670419608|1|0.0%|0.2%|
[et_compromised](#et_compromised)|2171|2171|1|0.0%|0.2%|
[et_block](#et_block)|1007|18338646|1|0.0%|0.2%|
[bruteforceblocker](#bruteforceblocker)|2039|2039|1|0.0%|0.2%|
[bogons](#bogons)|13|592708608|1|0.0%|0.2%|
[blocklist_de_sip](#blocklist_de_sip)|105|105|1|0.9%|0.2%|
[blocklist_de_mail](#blocklist_de_mail)|16874|16874|1|0.0%|0.2%|
[blocklist_de_imap](#blocklist_de_imap)|2837|2837|1|0.0%|0.2%|
[blocklist_de_ftp](#blocklist_de_ftp)|908|908|1|0.1%|0.2%|

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
[alienvault_reputation](#alienvault_reputation)|182510|182510|6|0.0%|1.6%|
[stopforumspam_30d](#stopforumspam_30d)|92996|92996|3|0.0%|0.8%|
[snort_ipfilter](#snort_ipfilter)|9591|9591|3|0.0%|0.8%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|3|0.0%|0.8%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|2|0.0%|0.5%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|2|0.1%|0.5%|
[et_block](#et_block)|1007|18338646|2|0.0%|0.5%|
[ri_web_proxies](#ri_web_proxies)|6246|6246|1|0.0%|0.2%|
[dshield](#dshield)|20|5120|1|0.0%|0.2%|

## dm_tor

[dan.me.uk](https://www.dan.me.uk) dynamic list of TOR exit points

Source is downloaded from [this link](https://www.dan.me.uk/torlist/).

The last time downloaded was found to be dated: Thu Jun  4 21:09:05 UTC 2015.

The ipset `dm_tor` has **6610** entries, **6610** unique IPs.

The following table shows the overlaps of `dm_tor` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `dm_tor`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `dm_tor`.
- ` this % ` is the percentage **of this ipset (`dm_tor`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[bm_tor](#bm_tor)|6624|6624|6527|98.5%|98.7%|
[et_tor](#et_tor)|6380|6380|5651|88.5%|85.4%|
[snort_ipfilter](#snort_ipfilter)|9591|9591|1083|11.2%|16.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|631|0.0%|9.5%|
[stopforumspam_30d](#stopforumspam_30d)|92996|92996|624|0.6%|9.4%|
[stopforumspam_7d](#stopforumspam_7d)|30334|30334|483|1.5%|7.3%|
[stopforumspam_1d](#stopforumspam_1d)|7043|7043|333|4.7%|5.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|189|0.0%|2.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|173|0.0%|2.6%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|168|45.1%|2.5%|
[alienvault_reputation](#alienvault_reputation)|182510|182510|43|0.0%|0.6%|
[php_commenters](#php_commenters)|301|301|33|10.9%|0.4%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|21|0.0%|0.3%|
[openbl_60d](#openbl_60d)|7699|7699|20|0.2%|0.3%|
[php_harvesters](#php_harvesters)|298|298|7|2.3%|0.1%|
[php_spammers](#php_spammers)|461|461|6|1.3%|0.0%|
[php_dictionary](#php_dictionary)|475|475|5|1.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|6246|6246|4|0.0%|0.0%|
[et_block](#et_block)|1007|18338646|4|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|16874|16874|4|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13937|13937|4|0.0%|0.0%|
[blocklist_de](#blocklist_de)|35206|35206|4|0.0%|0.0%|
[voipbl](#voipbl)|10426|10837|3|0.0%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|0.0%|
[xroxy](#xroxy)|2072|2072|2|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|2|0.0%|0.0%|
[nixspam](#nixspam)|21252|21252|2|0.0%|0.0%|
[dshield](#dshield)|20|5120|2|0.0%|0.0%|
[sorbs_spam](#sorbs_spam)|25175|26038|1|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|20387|21001|1|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|20387|21001|1|0.0%|0.0%|
[shunlist](#shunlist)|1229|1229|1|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2341|2341|1|0.0%|0.0%|
[proxyrss](#proxyrss)|1758|1758|1|0.0%|0.0%|

## dshield

[DShield.org](https://dshield.org/) top 20 attacking class C (/24) subnets over the last three days - **excellent list**

Source is downloaded from [this link](http://feeds.dshield.org/block.txt).

The last time downloaded was found to be dated: Thu Jun  4 19:22:45 UTC 2015.

The ipset `dshield` has **20** entries, **5120** unique IPs.

The following table shows the overlaps of `dshield` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `dshield`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `dshield`.
- ` this % ` is the percentage **of this ipset (`dshield`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[alienvault_reputation](#alienvault_reputation)|182510|182510|3334|1.8%|65.1%|
[et_block](#et_block)|1007|18338646|1792|0.0%|35.0%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|256|0.0%|5.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|256|0.0%|5.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|256|0.0%|5.0%|
[openbl_60d](#openbl_60d)|7699|7699|56|0.7%|1.0%|
[openbl_30d](#openbl_30d)|3261|3261|55|1.6%|1.0%|
[blocklist_de](#blocklist_de)|35206|35206|51|0.1%|0.9%|
[blocklist_de_ssh](#blocklist_de_ssh)|11179|11179|39|0.3%|0.7%|
[shunlist](#shunlist)|1229|1229|38|3.0%|0.7%|
[et_compromised](#et_compromised)|2171|2171|35|1.6%|0.6%|
[bruteforceblocker](#bruteforceblocker)|2039|2039|35|1.7%|0.6%|
[openbl_7d](#openbl_7d)|935|935|33|3.5%|0.6%|
[blocklist_de_apache](#blocklist_de_apache)|13937|13937|10|0.0%|0.1%|
[openbl_1d](#openbl_1d)|182|182|8|4.3%|0.1%|
[voipbl](#voipbl)|10426|10837|4|0.0%|0.0%|
[ciarmy](#ciarmy)|359|359|3|0.8%|0.0%|
[et_tor](#et_tor)|6380|6380|2|0.0%|0.0%|
[dm_tor](#dm_tor)|6610|6610|2|0.0%|0.0%|
[bm_tor](#bm_tor)|6624|6624|2|0.0%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|30334|30334|1|0.0%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92996|92996|1|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7043|7043|1|0.0%|0.0%|
[sorbs_spam](#sorbs_spam)|25175|26038|1|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|20387|21001|1|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|20387|21001|1|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9591|9591|1|0.0%|0.0%|
[php_commenters](#php_commenters)|301|301|1|0.3%|0.0%|
[nixspam](#nixspam)|21252|21252|1|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[malc0de](#malc0de)|379|379|1|0.2%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|370|370|1|0.2%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|105|105|1|0.9%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|16874|16874|1|0.0%|0.0%|

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
[alienvault_reputation](#alienvault_reputation)|182510|182510|5793|3.1%|0.0%|
[dshield](#dshield)|20|5120|1792|35.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1040|0.3%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92996|92996|1014|1.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|486400|517|0.1%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|30334|30334|335|1.1%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9591|9591|305|3.1%|0.0%|
[zeus](#zeus)|268|268|258|96.2%|0.0%|
[openbl_60d](#openbl_60d)|7699|7699|244|3.1%|0.0%|
[zeus_badips](#zeus_badips)|234|234|230|98.2%|0.0%|
[nixspam](#nixspam)|21252|21252|191|0.8%|0.0%|
[blocklist_de](#blocklist_de)|35206|35206|165|0.4%|0.0%|
[openbl_30d](#openbl_30d)|3261|3261|163|4.9%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|11179|11179|112|1.0%|0.0%|
[shunlist](#shunlist)|1229|1229|106|8.6%|0.0%|
[et_compromised](#et_compromised)|2171|2171|100|4.6%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2039|2039|100|4.9%|0.0%|
[feodo](#feodo)|94|94|80|85.1%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7043|7043|76|1.0%|0.0%|
[openbl_7d](#openbl_7d)|935|935|57|6.0%|0.0%|
[sslbl](#sslbl)|365|365|32|8.7%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|29|2.2%|0.0%|
[php_commenters](#php_commenters)|301|301|26|8.6%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3178|3178|25|0.7%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|16874|16874|23|0.1%|0.0%|
[voipbl](#voipbl)|10426|10837|14|0.1%|0.0%|
[sorbs_spam](#sorbs_spam)|25175|26038|12|0.0%|0.0%|
[palevo](#palevo)|13|13|12|92.3%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2837|2837|12|0.4%|0.0%|
[openbl_1d](#openbl_1d)|182|182|11|6.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|20387|21001|7|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|20387|21001|7|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|6|0.4%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|6|0.0%|0.0%|
[malc0de](#malc0de)|379|379|5|1.3%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|175|175|5|2.8%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13937|13937|5|0.0%|0.0%|
[php_dictionary](#php_dictionary)|475|475|4|0.8%|0.0%|
[et_tor](#et_tor)|6380|6380|4|0.0%|0.0%|
[dm_tor](#dm_tor)|6610|6610|4|0.0%|0.0%|
[bm_tor](#bm_tor)|6624|6624|4|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2582|2582|3|0.1%|0.0%|
[php_spammers](#php_spammers)|461|461|2|0.4%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|2|0.2%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|370|370|2|0.5%|0.0%|
[sorbs_web](#sorbs_web)|730|732|1|0.1%|0.0%|
[php_harvesters](#php_harvesters)|298|298|1|0.3%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[et_botcc](#et_botcc)|508|508|1|0.1%|0.0%|
[ciarmy](#ciarmy)|359|359|1|0.2%|0.0%|

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
[alienvault_reputation](#alienvault_reputation)|182510|182510|4|0.0%|0.7%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|1|0.0%|0.1%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|1|0.0%|0.1%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.1%|
[et_block](#et_block)|1007|18338646|1|0.0%|0.1%|
[blocklist_de_sip](#blocklist_de_sip)|105|105|1|0.9%|0.1%|

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
[bruteforceblocker](#bruteforceblocker)|2039|2039|1985|97.3%|91.4%|
[alienvault_reputation](#alienvault_reputation)|182510|182510|1408|0.7%|64.8%|
[openbl_60d](#openbl_60d)|7699|7699|1311|17.0%|60.3%|
[openbl_30d](#openbl_30d)|3261|3261|1216|37.2%|56.0%|
[blocklist_de](#blocklist_de)|35206|35206|653|1.8%|30.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|11179|11179|639|5.7%|29.4%|
[shunlist](#shunlist)|1229|1229|480|39.0%|22.1%|
[openbl_7d](#openbl_7d)|935|935|411|43.9%|18.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|216|0.0%|9.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|115|0.0%|5.2%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|100|0.0%|4.6%|
[et_block](#et_block)|1007|18338646|100|0.0%|4.6%|
[openbl_1d](#openbl_1d)|182|182|90|49.4%|4.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|62|0.0%|2.8%|
[dshield](#dshield)|20|5120|35|0.6%|1.6%|
[stopforumspam_30d](#stopforumspam_30d)|92996|92996|10|0.0%|0.4%|
[blocklist_de_mail](#blocklist_de_mail)|16874|16874|9|0.0%|0.4%|
[stopforumspam_7d](#stopforumspam_7d)|30334|30334|6|0.0%|0.2%|
[blocklist_de_imap](#blocklist_de_imap)|2837|2837|6|0.2%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|5|0.0%|0.2%|
[blocklist_de_apache](#blocklist_de_apache)|13937|13937|4|0.0%|0.1%|
[voipbl](#voipbl)|10426|10837|2|0.0%|0.0%|
[proxz](#proxz)|733|733|2|0.2%|0.0%|
[proxyrss](#proxyrss)|1758|1758|2|0.1%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|2|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3178|3178|2|0.0%|0.0%|
[xroxy](#xroxy)|2072|2072|1|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7043|7043|1|0.0%|0.0%|
[sorbs_spam](#sorbs_spam)|25175|26038|1|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9591|9591|1|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|6246|6246|1|0.0%|0.0%|
[ciarmy](#ciarmy)|359|359|1|0.2%|0.0%|

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
[bm_tor](#bm_tor)|6624|6624|5669|85.5%|88.8%|
[dm_tor](#dm_tor)|6610|6610|5651|85.4%|88.5%|
[snort_ipfilter](#snort_ipfilter)|9591|9591|1086|11.3%|17.0%|
[stopforumspam_30d](#stopforumspam_30d)|92996|92996|636|0.6%|9.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|626|0.0%|9.8%|
[stopforumspam_7d](#stopforumspam_7d)|30334|30334|499|1.6%|7.8%|
[stopforumspam_1d](#stopforumspam_1d)|7043|7043|338|4.7%|5.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|185|0.0%|2.8%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|171|45.9%|2.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|167|0.0%|2.6%|
[alienvault_reputation](#alienvault_reputation)|182510|182510|43|0.0%|0.6%|
[php_commenters](#php_commenters)|301|301|33|10.9%|0.5%|
[openbl_60d](#openbl_60d)|7699|7699|21|0.2%|0.3%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|21|0.0%|0.3%|
[php_harvesters](#php_harvesters)|298|298|7|2.3%|0.1%|
[php_spammers](#php_spammers)|461|461|6|1.3%|0.0%|
[php_dictionary](#php_dictionary)|475|475|5|1.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|6246|6246|4|0.0%|0.0%|
[et_block](#et_block)|1007|18338646|4|0.0%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|16874|16874|3|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13937|13937|3|0.0%|0.0%|
[blocklist_de](#blocklist_de)|35206|35206|3|0.0%|0.0%|
[xroxy](#xroxy)|2072|2072|2|0.0%|0.0%|
[voipbl](#voipbl)|10426|10837|2|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|2|0.0%|0.0%|
[sorbs_spam](#sorbs_spam)|25175|26038|2|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|20387|21001|2|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|20387|21001|2|0.0%|0.0%|
[dshield](#dshield)|20|5120|2|0.0%|0.0%|
[shunlist](#shunlist)|1229|1229|1|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2341|2341|1|0.0%|0.0%|
[proxyrss](#proxyrss)|1758|1758|1|0.0%|0.0%|
[nixspam](#nixspam)|21252|21252|1|0.0%|0.0%|

## feodo

[Abuse.ch Feodo tracker](https://feodotracker.abuse.ch) trojan includes IPs which are being used by Feodo (also known as Cridex or Bugat) which commits ebanking fraud - **excellent list**

Source is downloaded from [this link](https://feodotracker.abuse.ch/blocklist/?download=ipblocklist).

The last time downloaded was found to be dated: Thu Jun  4 21:09:13 UTC 2015.

The ipset `feodo` has **94** entries, **94** unique IPs.

The following table shows the overlaps of `feodo` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `feodo`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `feodo`.
- ` this % ` is the percentage **of this ipset (`feodo`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[et_block](#et_block)|1007|18338646|80|0.0%|85.1%|
[snort_ipfilter](#snort_ipfilter)|9591|9591|68|0.7%|72.3%|
[sslbl](#sslbl)|365|365|34|9.3%|36.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|10|0.0%|10.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|3|0.0%|3.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|3|0.0%|3.1%|
[alienvault_reputation](#alienvault_reputation)|182510|182510|2|0.0%|2.1%|
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
[stopforumspam_30d](#stopforumspam_30d)|92996|92996|2|0.0%|0.0%|
[php_harvesters](#php_harvesters)|298|298|1|0.3%|0.0%|
[ciarmy](#ciarmy)|359|359|1|0.2%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2039|2039|1|0.0%|0.0%|

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
[stopforumspam_30d](#stopforumspam_30d)|92996|92996|15|0.0%|0.0%|
[fullbogons](#fullbogons)|3733|670419608|15|0.0%|0.0%|
[alienvault_reputation](#alienvault_reputation)|182510|182510|15|0.0%|0.0%|
[nixspam](#nixspam)|21252|21252|11|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|11|1.6%|0.0%|
[blocklist_de](#blocklist_de)|35206|35206|9|0.0%|0.0%|
[sorbs_spam](#sorbs_spam)|25175|26038|7|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|20387|21001|7|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|20387|21001|7|0.0%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|30334|30334|6|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|6|0.0%|0.0%|
[et_block](#et_block)|1007|18338646|6|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|16874|16874|5|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|4|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2582|2582|4|0.1%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13937|13937|4|0.0%|0.0%|
[xroxy](#xroxy)|2072|2072|3|0.1%|0.0%|
[voipbl](#voipbl)|10426|10837|2|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|6246|6246|2|0.0%|0.0%|
[php_harvesters](#php_harvesters)|298|298|2|0.6%|0.0%|
[php_dictionary](#php_dictionary)|475|475|2|0.4%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7043|7043|1|0.0%|0.0%|
[sorbs_web](#sorbs_web)|730|732|1|0.1%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9591|9591|1|0.0%|0.0%|
[proxz](#proxz)|733|733|1|0.1%|0.0%|
[php_spammers](#php_spammers)|461|461|1|0.2%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2837|2837|1|0.0%|0.0%|

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
[stopforumspam_30d](#stopforumspam_30d)|92996|92996|756|0.8%|0.0%|
[alienvault_reputation](#alienvault_reputation)|182510|182510|518|0.2%|0.0%|
[nixspam](#nixspam)|21252|21252|190|0.8%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|30334|30334|186|0.6%|0.0%|
[blocklist_de](#blocklist_de)|35206|35206|32|0.0%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|27|2.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7043|7043|24|0.3%|0.0%|
[openbl_60d](#openbl_60d)|7699|7699|18|0.2%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3178|3178|17|0.5%|0.0%|
[openbl_30d](#openbl_30d)|3261|3261|13|0.3%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9591|9591|11|0.1%|0.0%|
[zeus_badips](#zeus_badips)|234|234|10|4.2%|0.0%|
[zeus](#zeus)|268|268|10|3.7%|0.0%|
[sorbs_spam](#sorbs_spam)|25175|26038|8|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|11179|11179|8|0.0%|0.0%|
[openbl_7d](#openbl_7d)|935|935|7|0.7%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|7|0.4%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|16874|16874|6|0.0%|0.0%|
[et_compromised](#et_compromised)|2171|2171|5|0.2%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2039|2039|5|0.2%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|20387|21001|3|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|20387|21001|3|0.0%|0.0%|
[openbl_1d](#openbl_1d)|182|182|3|1.6%|0.0%|
[et_tor](#et_tor)|6380|6380|3|0.0%|0.0%|
[dm_tor](#dm_tor)|6610|6610|3|0.0%|0.0%|
[bm_tor](#bm_tor)|6624|6624|3|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|175|175|3|1.7%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2837|2837|3|0.1%|0.0%|
[shunlist](#shunlist)|1229|1229|2|0.1%|0.0%|
[php_spammers](#php_spammers)|461|461|2|0.4%|0.0%|
[php_dictionary](#php_dictionary)|475|475|2|0.4%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|2|0.2%|0.0%|
[voipbl](#voipbl)|10426|10837|1|0.0%|0.0%|
[php_harvesters](#php_harvesters)|298|298|1|0.3%|0.0%|
[php_commenters](#php_commenters)|301|301|1|0.3%|0.0%|
[et_botcc](#et_botcc)|508|508|1|0.1%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2582|2582|1|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13937|13937|1|0.0%|0.0%|

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
[alienvault_reputation](#alienvault_reputation)|182510|182510|4479|2.4%|0.0%|
[blocklist_de](#blocklist_de)|35206|35206|1594|4.5%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92996|92996|1551|1.6%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|16874|16874|1374|8.1%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13937|13937|1328|9.5%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|30334|30334|571|1.8%|0.0%|
[nixspam](#nixspam)|21252|21252|491|2.3%|0.0%|
[sorbs_spam](#sorbs_spam)|25175|26038|417|1.6%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|406|0.8%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|20387|21001|331|1.5%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|20387|21001|331|1.5%|0.0%|
[voipbl](#voipbl)|10426|10837|299|2.7%|0.0%|
[dshield](#dshield)|20|5120|256|5.0%|0.0%|
[dm_tor](#dm_tor)|6610|6610|173|2.6%|0.0%|
[bm_tor](#bm_tor)|6624|6624|173|2.6%|0.0%|
[openbl_60d](#openbl_60d)|7699|7699|172|2.2%|0.0%|
[et_tor](#et_tor)|6380|6380|167|2.6%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7043|7043|145|2.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|6246|6246|131|2.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|11179|11179|115|1.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9591|9591|100|1.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|97|6.6%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2341|2341|74|3.1%|0.0%|
[openbl_30d](#openbl_30d)|3261|3261|71|2.1%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|66|5.1%|0.0%|
[et_compromised](#et_compromised)|2171|2171|62|2.8%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|58|8.6%|0.0%|
[xroxy](#xroxy)|2072|2072|57|2.7%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2039|2039|56|2.7%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3178|3178|42|1.3%|0.0%|
[et_botcc](#et_botcc)|508|508|40|7.8%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2837|2837|39|1.3%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2582|2582|39|1.5%|0.0%|
[proxyrss](#proxyrss)|1758|1758|37|2.1%|0.0%|
[proxz](#proxz)|733|733|28|3.8%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|370|370|27|7.2%|0.0%|
[sorbs_web](#sorbs_web)|730|732|26|3.5%|0.0%|
[shunlist](#shunlist)|1229|1229|25|2.0%|0.0%|
[openbl_7d](#openbl_7d)|935|935|19|2.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|17|4.5%|0.0%|
[malc0de](#malc0de)|379|379|12|3.1%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|908|908|12|1.3%|0.0%|
[php_harvesters](#php_harvesters)|298|298|9|3.0%|0.0%|
[php_dictionary](#php_dictionary)|475|475|9|1.8%|0.0%|
[ciarmy](#ciarmy)|359|359|7|1.9%|0.0%|
[zeus](#zeus)|268|268|6|2.2%|0.0%|
[php_commenters](#php_commenters)|301|301|6|1.9%|0.0%|
[php_spammers](#php_spammers)|461|461|5|1.0%|0.0%|
[bogons](#bogons)|13|592708608|5|0.0%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|105|105|5|4.7%|0.0%|
[zeus_badips](#zeus_badips)|234|234|4|1.7%|0.0%|
[sslbl](#sslbl)|365|365|4|1.0%|0.0%|
[openbl_1d](#openbl_1d)|182|182|3|1.6%|0.0%|
[feodo](#feodo)|94|94|3|3.1%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|175|175|1|0.5%|0.0%|

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
[alienvault_reputation](#alienvault_reputation)|182510|182510|7807|4.2%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|7733|2.2%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92996|92996|2521|2.7%|0.0%|
[blocklist_de](#blocklist_de)|35206|35206|1556|4.4%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|16874|16874|1172|6.9%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13937|13937|1071|7.6%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|30334|30334|908|2.9%|0.0%|
[sorbs_spam](#sorbs_spam)|25175|26038|623|2.3%|0.0%|
[nixspam](#nixspam)|21252|21252|587|2.7%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|20387|21001|539|2.5%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|20387|21001|539|2.5%|0.0%|
[voipbl](#voipbl)|10426|10837|434|4.0%|0.0%|
[openbl_60d](#openbl_60d)|7699|7699|340|4.4%|0.0%|
[dshield](#dshield)|20|5120|256|5.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7043|7043|237|3.3%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|230|0.4%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|11179|11179|224|2.0%|0.0%|
[dm_tor](#dm_tor)|6610|6610|189|2.8%|0.0%|
[bm_tor](#bm_tor)|6624|6624|188|2.8%|0.0%|
[et_tor](#et_tor)|6380|6380|185|2.8%|0.0%|
[ri_web_proxies](#ri_web_proxies)|6246|6246|184|2.9%|0.0%|
[openbl_30d](#openbl_30d)|3261|3261|170|5.2%|0.0%|
[et_compromised](#et_compromised)|2171|2171|115|5.2%|0.0%|
[xroxy](#xroxy)|2072|2072|99|4.7%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9591|9591|98|1.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2039|2039|97|4.7%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2341|2341|91|3.8%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3178|3178|88|2.7%|0.0%|
[shunlist](#shunlist)|1229|1229|72|5.8%|0.0%|
[proxyrss](#proxyrss)|1758|1758|68|3.8%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2837|2837|63|2.2%|0.0%|
[openbl_7d](#openbl_7d)|935|935|49|5.2%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|45|3.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2582|2582|36|1.3%|0.0%|
[php_spammers](#php_spammers)|461|461|34|7.3%|0.0%|
[proxz](#proxz)|733|733|31|4.2%|0.0%|
[sorbs_web](#sorbs_web)|730|732|28|3.8%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|28|4.1%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|26|2.0%|0.0%|
[malc0de](#malc0de)|379|379|23|6.0%|0.0%|
[et_botcc](#et_botcc)|508|508|22|4.3%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|21|5.6%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|908|908|19|2.0%|0.0%|
[ciarmy](#ciarmy)|359|359|18|5.0%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|370|370|13|3.5%|0.0%|
[php_dictionary](#php_dictionary)|475|475|11|2.3%|0.0%|
[php_commenters](#php_commenters)|301|301|11|3.6%|0.0%|
[zeus](#zeus)|268|268|9|3.3%|0.0%|
[php_harvesters](#php_harvesters)|298|298|9|3.0%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|105|105|9|8.5%|0.0%|
[zeus_badips](#zeus_badips)|234|234|8|3.4%|0.0%|
[openbl_1d](#openbl_1d)|182|182|7|3.8%|0.0%|
[sslbl](#sslbl)|365|365|6|1.6%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|175|175|5|2.8%|0.0%|
[feodo](#feodo)|94|94|3|3.1%|0.0%|
[palevo](#palevo)|13|13|2|15.3%|0.0%|
[sorbs_socks](#sorbs_socks)|28|28|1|3.5%|0.0%|
[sorbs_smtp](#sorbs_smtp)|10|10|1|10.0%|0.0%|
[sorbs_misc](#sorbs_misc)|28|28|1|3.5%|0.0%|
[sorbs_http](#sorbs_http)|28|28|1|3.5%|0.0%|

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
[alienvault_reputation](#alienvault_reputation)|182510|182510|14395|7.8%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|9231|2.7%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92996|92996|5857|6.2%|0.0%|
[blocklist_de](#blocklist_de)|35206|35206|5814|16.5%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|11179|11179|2713|24.2%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|16874|16874|2574|15.2%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13937|13937|2315|16.6%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|30334|30334|1930|6.3%|0.0%|
[sorbs_spam](#sorbs_spam)|25175|26038|1833|7.0%|0.0%|
[voipbl](#voipbl)|10426|10837|1596|14.7%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|20387|21001|1450|6.9%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|20387|21001|1450|6.9%|0.0%|
[nixspam](#nixspam)|21252|21252|1361|6.4%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1172|2.4%|0.0%|
[openbl_60d](#openbl_60d)|7699|7699|749|9.7%|0.0%|
[bm_tor](#bm_tor)|6624|6624|633|9.5%|0.0%|
[dm_tor](#dm_tor)|6610|6610|631|9.5%|0.0%|
[et_tor](#et_tor)|6380|6380|626|9.8%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7043|7043|464|6.5%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2837|2837|366|12.9%|0.0%|
[openbl_30d](#openbl_30d)|3261|3261|312|9.5%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9591|9591|219|2.2%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2582|2582|217|8.4%|0.0%|
[et_compromised](#et_compromised)|2171|2171|216|9.9%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2039|2039|199|9.7%|0.0%|
[ri_web_proxies](#ri_web_proxies)|6246|6246|177|2.8%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3178|3178|160|5.0%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|147|11.4%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|125|33.6%|0.0%|
[openbl_7d](#openbl_7d)|935|935|115|12.2%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|110|7.5%|0.0%|
[shunlist](#shunlist)|1229|1229|101|8.2%|0.0%|
[xroxy](#xroxy)|2072|2072|92|4.4%|0.0%|
[et_botcc](#et_botcc)|508|508|76|14.9%|0.0%|
[malc0de](#malc0de)|379|379|67|17.6%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|908|908|67|7.3%|0.0%|
[proxz](#proxz)|733|733|65|8.8%|0.0%|
[proxyrss](#proxyrss)|1758|1758|58|3.2%|0.0%|
[ciarmy](#ciarmy)|359|359|55|15.3%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2341|2341|52|2.2%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|51|7.5%|0.0%|
[sorbs_web](#sorbs_web)|730|732|45|6.1%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|370|370|42|11.3%|0.0%|
[php_spammers](#php_spammers)|461|461|26|5.6%|0.0%|
[php_dictionary](#php_dictionary)|475|475|25|5.2%|0.0%|
[sslbl](#sslbl)|365|365|23|6.3%|0.0%|
[openbl_1d](#openbl_1d)|182|182|23|12.6%|0.0%|
[zeus](#zeus)|268|268|20|7.4%|0.0%|
[php_harvesters](#php_harvesters)|298|298|17|5.7%|0.0%|
[php_commenters](#php_commenters)|301|301|17|5.6%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|175|175|15|8.5%|0.0%|
[zeus_badips](#zeus_badips)|234|234|14|5.9%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|105|105|14|13.3%|0.0%|
[feodo](#feodo)|94|94|10|10.6%|0.0%|
[virbl](#virbl)|11|11|1|9.0%|0.0%|
[sorbs_socks](#sorbs_socks)|28|28|1|3.5%|0.0%|
[sorbs_misc](#sorbs_misc)|28|28|1|3.5%|0.0%|
[sorbs_http](#sorbs_http)|28|28|1|3.5%|0.0%|
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
[stopforumspam_30d](#stopforumspam_30d)|92996|92996|22|0.0%|3.2%|
[xroxy](#xroxy)|2072|2072|13|0.6%|1.9%|
[stopforumspam_7d](#stopforumspam_7d)|30334|30334|12|0.0%|1.7%|
[ri_web_proxies](#ri_web_proxies)|6246|6246|12|0.1%|1.7%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|11|0.0%|1.6%|
[proxyrss](#proxyrss)|1758|1758|8|0.4%|1.1%|
[stopforumspam_1d](#stopforumspam_1d)|7043|7043|6|0.0%|0.8%|
[ri_connect_proxies](#ri_connect_proxies)|2341|2341|6|0.2%|0.8%|
[blocklist_de](#blocklist_de)|35206|35206|6|0.0%|0.8%|
[proxz](#proxz)|733|733|4|0.5%|0.5%|
[blocklist_de_bots](#blocklist_de_bots)|3178|3178|4|0.1%|0.5%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|2|0.0%|0.2%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2|0.0%|0.2%|
[et_block](#et_block)|1007|18338646|2|0.0%|0.2%|
[blocklist_de_mail](#blocklist_de_mail)|16874|16874|2|0.0%|0.2%|
[sorbs_spam](#sorbs_spam)|25175|26038|1|0.0%|0.1%|
[sorbs_recent_spam](#sorbs_recent_spam)|20387|21001|1|0.0%|0.1%|
[sorbs_new_spam](#sorbs_new_spam)|20387|21001|1|0.0%|0.1%|
[snort_ipfilter](#snort_ipfilter)|9591|9591|1|0.0%|0.1%|
[php_dictionary](#php_dictionary)|475|475|1|0.2%|0.1%|
[nixspam](#nixspam)|21252|21252|1|0.0%|0.1%|
[alienvault_reputation](#alienvault_reputation)|182510|182510|1|0.0%|0.1%|

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
[alienvault_reputation](#alienvault_reputation)|182510|182510|287|0.1%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92996|92996|48|0.0%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|27|2.0%|0.0%|
[sorbs_spam](#sorbs_spam)|25175|26038|24|0.0%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|30334|30334|23|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|20387|21001|23|0.1%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|20387|21001|23|0.1%|0.0%|
[et_tor](#et_tor)|6380|6380|21|0.3%|0.0%|
[dm_tor](#dm_tor)|6610|6610|21|0.3%|0.0%|
[bm_tor](#bm_tor)|6624|6624|21|0.3%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|19|1.3%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9591|9591|14|0.1%|0.0%|
[blocklist_de](#blocklist_de)|35206|35206|13|0.0%|0.0%|
[nixspam](#nixspam)|21252|21252|12|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7043|7043|10|0.1%|0.0%|
[ri_web_proxies](#ri_web_proxies)|6246|6246|5|0.0%|0.0%|
[openbl_60d](#openbl_60d)|7699|7699|5|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|5|1.3%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3178|3178|5|0.1%|0.0%|
[voipbl](#voipbl)|10426|10837|4|0.0%|0.0%|
[openbl_30d](#openbl_30d)|3261|3261|4|0.1%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|4|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|16874|16874|4|0.0%|0.0%|
[malc0de](#malc0de)|379|379|3|0.7%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|370|370|3|0.8%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13937|13937|3|0.0%|0.0%|
[et_compromised](#et_compromised)|2171|2171|2|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2039|2039|2|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|11179|11179|2|0.0%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|105|105|2|1.9%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2837|2837|2|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2582|2582|2|0.0%|0.0%|
[zeus_badips](#zeus_badips)|234|234|1|0.4%|0.0%|
[zeus](#zeus)|268|268|1|0.3%|0.0%|
[xroxy](#xroxy)|2072|2072|1|0.0%|0.0%|
[sslbl](#sslbl)|365|365|1|0.2%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|486400|1|0.0%|0.0%|
[shunlist](#shunlist)|1229|1229|1|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2341|2341|1|0.0%|0.0%|
[proxyrss](#proxyrss)|1758|1758|1|0.0%|0.0%|
[php_harvesters](#php_harvesters)|298|298|1|0.3%|0.0%|
[php_dictionary](#php_dictionary)|475|475|1|0.2%|0.0%|
[palevo](#palevo)|13|13|1|7.6%|0.0%|
[openbl_7d](#openbl_7d)|935|935|1|0.1%|0.0%|
[feodo](#feodo)|94|94|1|1.0%|0.0%|
[ciarmy](#ciarmy)|359|359|1|0.2%|0.0%|
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
[alienvault_reputation](#alienvault_reputation)|182510|182510|8|0.0%|0.5%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|7|0.0%|0.4%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|6|0.0%|0.4%|
[et_block](#et_block)|1007|18338646|6|0.0%|0.4%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|3|0.2%|0.2%|
[stopforumspam_30d](#stopforumspam_30d)|92996|92996|2|0.0%|0.1%|
[openbl_60d](#openbl_60d)|7699|7699|2|0.0%|0.1%|
[openbl_30d](#openbl_30d)|3261|3261|2|0.0%|0.1%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|2|0.2%|0.1%|
[blocklist_de](#blocklist_de)|35206|35206|2|0.0%|0.1%|
[stopforumspam_7d](#stopforumspam_7d)|30334|30334|1|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7043|7043|1|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9591|9591|1|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|6246|6246|1|0.0%|0.0%|
[openbl_7d](#openbl_7d)|935|935|1|0.1%|0.0%|
[nixspam](#nixspam)|21252|21252|1|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1|0.0%|0.0%|
[et_botcc](#et_botcc)|508|508|1|0.1%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|175|175|1|0.5%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|11179|11179|1|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3178|3178|1|0.0%|0.0%|

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
[alienvault_reputation](#alienvault_reputation)|182510|182510|11|0.0%|2.9%|
[et_block](#et_block)|1007|18338646|5|0.0%|1.3%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|4|0.0%|1.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|4|0.3%|1.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|3|0.0%|0.7%|
[spamhaus_edrop](#spamhaus_edrop)|55|486400|1|0.0%|0.2%|
[snort_ipfilter](#snort_ipfilter)|9591|9591|1|0.0%|0.2%|
[dshield](#dshield)|20|5120|1|0.0%|0.2%|

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
[snort_ipfilter](#snort_ipfilter)|9591|9591|29|0.3%|2.2%|
[et_block](#et_block)|1007|18338646|29|0.0%|2.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|27|0.0%|2.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|27|0.0%|2.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|26|0.0%|2.0%|
[fullbogons](#fullbogons)|3733|670419608|9|0.0%|0.6%|
[alienvault_reputation](#alienvault_reputation)|182510|182510|6|0.0%|0.4%|
[stopforumspam_30d](#stopforumspam_30d)|92996|92996|4|0.0%|0.3%|
[malc0de](#malc0de)|379|379|4|1.0%|0.3%|
[stopforumspam_7d](#stopforumspam_7d)|30334|30334|3|0.0%|0.2%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|3|0.2%|0.2%|
[cleanmx_viruses](#cleanmx_viruses)|370|370|2|0.5%|0.1%|
[sorbs_spam](#sorbs_spam)|25175|26038|1|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|20387|21001|1|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|20387|21001|1|0.0%|0.0%|
[nixspam](#nixspam)|21252|21252|1|0.0%|0.0%|
[et_botcc](#et_botcc)|508|508|1|0.1%|0.0%|

## maxmind_proxy_fraud

[MaxMind.com](https://www.maxmind.com/en/anonymous-proxy-fraudulent-ip-address-list) list of anonymous proxy fraudelent IP addresses.

Source is downloaded from [this link](https://www.maxmind.com/en/anonymous-proxy-fraudulent-ip-address-list).

The last time downloaded was found to be dated: Thu Jun  4 21:27:05 UTC 2015.

The ipset `maxmind_proxy_fraud` has **372** entries, **372** unique IPs.

The following table shows the overlaps of `maxmind_proxy_fraud` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `maxmind_proxy_fraud`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `maxmind_proxy_fraud`.
- ` this % ` is the percentage **of this ipset (`maxmind_proxy_fraud`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_30d](#stopforumspam_30d)|92996|92996|233|0.2%|62.6%|
[stopforumspam_7d](#stopforumspam_7d)|30334|30334|194|0.6%|52.1%|
[snort_ipfilter](#snort_ipfilter)|9591|9591|177|1.8%|47.5%|
[et_tor](#et_tor)|6380|6380|171|2.6%|45.9%|
[bm_tor](#bm_tor)|6624|6624|169|2.5%|45.4%|
[dm_tor](#dm_tor)|6610|6610|168|2.5%|45.1%|
[stopforumspam_1d](#stopforumspam_1d)|7043|7043|166|2.3%|44.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|125|0.0%|33.6%|
[php_commenters](#php_commenters)|301|301|31|10.2%|8.3%|
[alienvault_reputation](#alienvault_reputation)|182510|182510|26|0.0%|6.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|21|0.0%|5.6%|
[openbl_60d](#openbl_60d)|7699|7699|18|0.2%|4.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|17|0.0%|4.5%|
[php_harvesters](#php_harvesters)|298|298|6|2.0%|1.6%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|5|0.0%|1.3%|
[ri_web_proxies](#ri_web_proxies)|6246|6246|4|0.0%|1.0%|
[php_spammers](#php_spammers)|461|461|4|0.8%|1.0%|
[php_dictionary](#php_dictionary)|475|475|4|0.8%|1.0%|
[shunlist](#shunlist)|1229|1229|2|0.1%|0.5%|
[blocklist_de_apache](#blocklist_de_apache)|13937|13937|2|0.0%|0.5%|
[blocklist_de](#blocklist_de)|35206|35206|2|0.0%|0.5%|
[xroxy](#xroxy)|2072|2072|1|0.0%|0.2%|
[voipbl](#voipbl)|10426|10837|1|0.0%|0.2%|
[ri_connect_proxies](#ri_connect_proxies)|2341|2341|1|0.0%|0.2%|
[et_block](#et_block)|1007|18338646|1|0.0%|0.2%|
[dshield](#dshield)|20|5120|1|0.0%|0.2%|
[blocklist_de_mail](#blocklist_de_mail)|16874|16874|1|0.0%|0.2%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2582|2582|1|0.0%|0.2%|

## nixspam

[NiX Spam](http://www.heise.de/ix/NiX-Spam-DNSBL-and-blacklist-for-download-499637.html) IP addresses that sent spam in the last hour - automatically generated entries without distinguishing open proxies from relays, dialup gateways, and so on. All IPs are removed after 12 hours if there is no spam from there.

Source is downloaded from [this link](http://www.dnsbl.manitu.net/download/nixspam-ip.dump.gz).

The last time downloaded was found to be dated: Thu Jun  4 21:30:02 UTC 2015.

The ipset `nixspam` has **21252** entries, **21252** unique IPs.

The following table shows the overlaps of `nixspam` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `nixspam`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `nixspam`.
- ` this % ` is the percentage **of this ipset (`nixspam`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[sorbs_spam](#sorbs_spam)|25175|26038|3971|15.2%|18.6%|
[sorbs_recent_spam](#sorbs_recent_spam)|20387|21001|3832|18.2%|18.0%|
[sorbs_new_spam](#sorbs_new_spam)|20387|21001|3832|18.2%|18.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|1361|0.0%|6.4%|
[blocklist_de](#blocklist_de)|35206|35206|744|2.1%|3.5%|
[blocklist_de_mail](#blocklist_de_mail)|16874|16874|638|3.7%|3.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|587|0.0%|2.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|491|0.0%|2.3%|
[stopforumspam_30d](#stopforumspam_30d)|92996|92996|242|0.2%|1.1%|
[et_block](#et_block)|1007|18338646|191|0.0%|0.8%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|190|0.0%|0.8%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|190|0.0%|0.8%|
[snort_ipfilter](#snort_ipfilter)|9591|9591|178|1.8%|0.8%|
[stopforumspam_7d](#stopforumspam_7d)|30334|30334|156|0.5%|0.7%|
[sorbs_web](#sorbs_web)|730|732|155|21.1%|0.7%|
[ri_web_proxies](#ri_web_proxies)|6246|6246|103|1.6%|0.4%|
[php_dictionary](#php_dictionary)|475|475|88|18.5%|0.4%|
[xroxy](#xroxy)|2072|2072|79|3.8%|0.3%|
[stopforumspam_1d](#stopforumspam_1d)|7043|7043|74|1.0%|0.3%|
[php_spammers](#php_spammers)|461|461|67|14.5%|0.3%|
[blocklist_de_apache](#blocklist_de_apache)|13937|13937|46|0.3%|0.2%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2582|2582|43|1.6%|0.2%|
[blocklist_de_bots](#blocklist_de_bots)|3178|3178|41|1.2%|0.1%|
[alienvault_reputation](#alienvault_reputation)|182510|182510|39|0.0%|0.1%|
[proxz](#proxz)|733|733|35|4.7%|0.1%|
[blocklist_de_imap](#blocklist_de_imap)|2837|2837|25|0.8%|0.1%|
[ri_connect_proxies](#ri_connect_proxies)|2341|2341|20|0.8%|0.0%|
[proxyrss](#proxyrss)|1758|1758|19|1.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|11179|11179|13|0.1%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|12|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|11|0.0%|0.0%|
[php_commenters](#php_commenters)|301|301|9|2.9%|0.0%|
[sorbs_socks](#sorbs_socks)|28|28|7|25.0%|0.0%|
[sorbs_misc](#sorbs_misc)|28|28|7|25.0%|0.0%|
[sorbs_http](#sorbs_http)|28|28|7|25.0%|0.0%|
[php_harvesters](#php_harvesters)|298|298|6|2.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|908|908|6|0.6%|0.0%|
[dm_tor](#dm_tor)|6610|6610|2|0.0%|0.0%|
[bm_tor](#bm_tor)|6624|6624|2|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|175|175|2|1.1%|0.0%|
[zeus_badips](#zeus_badips)|234|234|1|0.4%|0.0%|
[zeus](#zeus)|268|268|1|0.3%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|486400|1|0.0%|0.0%|
[openbl_60d](#openbl_60d)|7699|7699|1|0.0%|0.0%|
[openbl_30d](#openbl_30d)|3261|3261|1|0.0%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|1|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|1|0.1%|0.0%|
[et_tor](#et_tor)|6380|6380|1|0.0%|0.0%|
[dshield](#dshield)|20|5120|1|0.0%|0.0%|

## openbl_1d

[OpenBL.org](http://www.openbl.org/) last 24 hours IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.

Source is downloaded from [this link](http://www.openbl.org/lists/base_1days.txt).

The last time downloaded was found to be dated: Thu Jun  4 21:32:00 UTC 2015.

The ipset `openbl_1d` has **182** entries, **182** unique IPs.

The following table shows the overlaps of `openbl_1d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl_1d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl_1d`.
- ` this % ` is the percentage **of this ipset (`openbl_1d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[openbl_7d](#openbl_7d)|935|935|182|19.4%|100.0%|
[openbl_60d](#openbl_60d)|7699|7699|182|2.3%|100.0%|
[openbl_30d](#openbl_30d)|3261|3261|182|5.5%|100.0%|
[alienvault_reputation](#alienvault_reputation)|182510|182510|176|0.0%|96.7%|
[blocklist_de](#blocklist_de)|35206|35206|148|0.4%|81.3%|
[blocklist_de_ssh](#blocklist_de_ssh)|11179|11179|147|1.3%|80.7%|
[bruteforceblocker](#bruteforceblocker)|2039|2039|96|4.7%|52.7%|
[et_compromised](#et_compromised)|2171|2171|90|4.1%|49.4%|
[shunlist](#shunlist)|1229|1229|76|6.1%|41.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|23|0.0%|12.6%|
[blocklist_de_strongips](#blocklist_de_strongips)|175|175|21|12.0%|11.5%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|11|0.0%|6.0%|
[et_block](#et_block)|1007|18338646|11|0.0%|6.0%|
[dshield](#dshield)|20|5120|8|0.1%|4.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|7|0.0%|3.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|3|0.0%|1.6%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|1.6%|
[blocklist_de_mail](#blocklist_de_mail)|16874|16874|3|0.0%|1.6%|
[blocklist_de_imap](#blocklist_de_imap)|2837|2837|2|0.0%|1.0%|

## openbl_30d

[OpenBL.org](http://www.openbl.org/) last 30 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.

Source is downloaded from [this link](http://www.openbl.org/lists/base_30days.txt).

The last time downloaded was found to be dated: Thu Jun  4 19:42:00 UTC 2015.

The ipset `openbl_30d` has **3261** entries, **3261** unique IPs.

The following table shows the overlaps of `openbl_30d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl_30d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl_30d`.
- ` this % ` is the percentage **of this ipset (`openbl_30d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[openbl_60d](#openbl_60d)|7699|7699|3261|42.3%|100.0%|
[alienvault_reputation](#alienvault_reputation)|182510|182510|3241|1.7%|99.3%|
[et_compromised](#et_compromised)|2171|2171|1216|56.0%|37.2%|
[bruteforceblocker](#bruteforceblocker)|2039|2039|1173|57.5%|35.9%|
[openbl_7d](#openbl_7d)|935|935|935|100.0%|28.6%|
[blocklist_de](#blocklist_de)|35206|35206|865|2.4%|26.5%|
[blocklist_de_ssh](#blocklist_de_ssh)|11179|11179|822|7.3%|25.2%|
[shunlist](#shunlist)|1229|1229|561|45.6%|17.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|312|0.0%|9.5%|
[openbl_1d](#openbl_1d)|182|182|182|100.0%|5.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|170|0.0%|5.2%|
[et_block](#et_block)|1007|18338646|163|0.0%|4.9%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|159|0.0%|4.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|71|0.0%|2.1%|
[dshield](#dshield)|20|5120|55|1.0%|1.6%|
[blocklist_de_mail](#blocklist_de_mail)|16874|16874|40|0.2%|1.2%|
[blocklist_de_imap](#blocklist_de_imap)|2837|2837|35|1.2%|1.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|175|175|24|13.7%|0.7%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|13|0.0%|0.3%|
[snort_ipfilter](#snort_ipfilter)|9591|9591|8|0.0%|0.2%|
[stopforumspam_30d](#stopforumspam_30d)|92996|92996|4|0.0%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|4|0.0%|0.1%|
[voipbl](#voipbl)|10426|10837|3|0.0%|0.0%|
[zeus](#zeus)|268|268|2|0.7%|0.0%|
[sorbs_spam](#sorbs_spam)|25175|26038|2|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|20387|21001|2|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|20387|21001|2|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13937|13937|2|0.0%|0.0%|
[zeus_badips](#zeus_badips)|234|234|1|0.4%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|30334|30334|1|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7043|7043|1|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|486400|1|0.0%|0.0%|
[nixspam](#nixspam)|21252|21252|1|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3178|3178|1|0.0%|0.0%|

## openbl_60d

[OpenBL.org](http://www.openbl.org/) last 60 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.

Source is downloaded from [this link](http://www.openbl.org/lists/base_60days.txt).

The last time downloaded was found to be dated: Thu Jun  4 19:42:00 UTC 2015.

The ipset `openbl_60d` has **7699** entries, **7699** unique IPs.

The following table shows the overlaps of `openbl_60d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl_60d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl_60d`.
- ` this % ` is the percentage **of this ipset (`openbl_60d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[alienvault_reputation](#alienvault_reputation)|182510|182510|7673|4.2%|99.6%|
[openbl_30d](#openbl_30d)|3261|3261|3261|100.0%|42.3%|
[blocklist_de](#blocklist_de)|35206|35206|1734|4.9%|22.5%|
[blocklist_de_ssh](#blocklist_de_ssh)|11179|11179|1678|15.0%|21.7%|
[et_compromised](#et_compromised)|2171|2171|1311|60.3%|17.0%|
[bruteforceblocker](#bruteforceblocker)|2039|2039|1231|60.3%|15.9%|
[openbl_7d](#openbl_7d)|935|935|935|100.0%|12.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|749|0.0%|9.7%|
[shunlist](#shunlist)|1229|1229|576|46.8%|7.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|340|0.0%|4.4%|
[et_block](#et_block)|1007|18338646|244|0.0%|3.1%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|239|0.0%|3.1%|
[openbl_1d](#openbl_1d)|182|182|182|100.0%|2.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|172|0.0%|2.2%|
[stopforumspam_30d](#stopforumspam_30d)|92996|92996|56|0.0%|0.7%|
[dshield](#dshield)|20|5120|56|1.0%|0.7%|
[blocklist_de_mail](#blocklist_de_mail)|16874|16874|46|0.2%|0.5%|
[blocklist_de_imap](#blocklist_de_imap)|2837|2837|41|1.4%|0.5%|
[snort_ipfilter](#snort_ipfilter)|9591|9591|31|0.3%|0.4%|
[stopforumspam_7d](#stopforumspam_7d)|30334|30334|25|0.0%|0.3%|
[blocklist_de_strongips](#blocklist_de_strongips)|175|175|25|14.2%|0.3%|
[stopforumspam_1d](#stopforumspam_1d)|7043|7043|21|0.2%|0.2%|
[et_tor](#et_tor)|6380|6380|21|0.3%|0.2%|
[dm_tor](#dm_tor)|6610|6610|20|0.3%|0.2%|
[bm_tor](#bm_tor)|6624|6624|20|0.3%|0.2%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|18|4.8%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|18|0.0%|0.2%|
[sorbs_spam](#sorbs_spam)|25175|26038|14|0.0%|0.1%|
[sorbs_recent_spam](#sorbs_recent_spam)|20387|21001|13|0.0%|0.1%|
[sorbs_new_spam](#sorbs_new_spam)|20387|21001|13|0.0%|0.1%|
[php_commenters](#php_commenters)|301|301|9|2.9%|0.1%|
[voipbl](#voipbl)|10426|10837|8|0.0%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|5|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13937|13937|4|0.0%|0.0%|
[zeus](#zeus)|268|268|2|0.7%|0.0%|
[php_harvesters](#php_harvesters)|298|298|2|0.6%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.0%|
[zeus_badips](#zeus_badips)|234|234|1|0.4%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|486400|1|0.0%|0.0%|
[nixspam](#nixspam)|21252|21252|1|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3178|3178|1|0.0%|0.0%|

## openbl_7d

[OpenBL.org](http://www.openbl.org/) last 7 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.

Source is downloaded from [this link](http://www.openbl.org/lists/base_7days.txt).

The last time downloaded was found to be dated: Thu Jun  4 19:42:00 UTC 2015.

The ipset `openbl_7d` has **935** entries, **935** unique IPs.

The following table shows the overlaps of `openbl_7d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl_7d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl_7d`.
- ` this % ` is the percentage **of this ipset (`openbl_7d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[openbl_60d](#openbl_60d)|7699|7699|935|12.1%|100.0%|
[openbl_30d](#openbl_30d)|3261|3261|935|28.6%|100.0%|
[alienvault_reputation](#alienvault_reputation)|182510|182510|924|0.5%|98.8%|
[blocklist_de](#blocklist_de)|35206|35206|583|1.6%|62.3%|
[blocklist_de_ssh](#blocklist_de_ssh)|11179|11179|568|5.0%|60.7%|
[bruteforceblocker](#bruteforceblocker)|2039|2039|422|20.6%|45.1%|
[et_compromised](#et_compromised)|2171|2171|411|18.9%|43.9%|
[shunlist](#shunlist)|1229|1229|303|24.6%|32.4%|
[openbl_1d](#openbl_1d)|182|182|182|100.0%|19.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|115|0.0%|12.2%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|57|0.0%|6.0%|
[et_block](#et_block)|1007|18338646|57|0.0%|6.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|49|0.0%|5.2%|
[dshield](#dshield)|20|5120|33|0.6%|3.5%|
[blocklist_de_strongips](#blocklist_de_strongips)|175|175|23|13.1%|2.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|19|0.0%|2.0%|
[blocklist_de_mail](#blocklist_de_mail)|16874|16874|15|0.0%|1.6%|
[blocklist_de_imap](#blocklist_de_imap)|2837|2837|13|0.4%|1.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|7|0.0%|0.7%|
[stopforumspam_30d](#stopforumspam_30d)|92996|92996|3|0.0%|0.3%|
[snort_ipfilter](#snort_ipfilter)|9591|9591|3|0.0%|0.3%|
[voipbl](#voipbl)|10426|10837|1|0.0%|0.1%|
[sorbs_spam](#sorbs_spam)|25175|26038|1|0.0%|0.1%|
[sorbs_recent_spam](#sorbs_recent_spam)|20387|21001|1|0.0%|0.1%|
[sorbs_new_spam](#sorbs_new_spam)|20387|21001|1|0.0%|0.1%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.1%|

## palevo

[Abuse.ch Palevo tracker](https://palevotracker.abuse.ch) worm includes IPs which are being used as botnet C&C for the Palevo crimeware - **excellent list**

Source is downloaded from [this link](https://palevotracker.abuse.ch/blocklists.php?download=ipblocklist).

The last time downloaded was found to be dated: Thu Jun  4 21:09:10 UTC 2015.

The ipset `palevo` has **13** entries, **13** unique IPs.

The following table shows the overlaps of `palevo` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `palevo`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `palevo`.
- ` this % ` is the percentage **of this ipset (`palevo`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[et_block](#et_block)|1007|18338646|12|0.0%|92.3%|
[snort_ipfilter](#snort_ipfilter)|9591|9591|11|0.1%|84.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|2|0.0%|15.3%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|7.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|1|0.0%|7.6%|

## php_commenters

[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) comment spammers (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=c&rss=1).

The last time downloaded was found to be dated: Thu Jun  4 21:36:40 UTC 2015.

The ipset `php_commenters` has **301** entries, **301** unique IPs.

The following table shows the overlaps of `php_commenters` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `php_commenters`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `php_commenters`.
- ` this % ` is the percentage **of this ipset (`php_commenters`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_30d](#stopforumspam_30d)|92996|92996|220|0.2%|73.0%|
[stopforumspam_7d](#stopforumspam_7d)|30334|30334|158|0.5%|52.4%|
[stopforumspam_1d](#stopforumspam_1d)|7043|7043|118|1.6%|39.2%|
[blocklist_de](#blocklist_de)|35206|35206|74|0.2%|24.5%|
[blocklist_de_bots](#blocklist_de_bots)|3178|3178|59|1.8%|19.6%|
[snort_ipfilter](#snort_ipfilter)|9591|9591|42|0.4%|13.9%|
[php_spammers](#php_spammers)|461|461|33|7.1%|10.9%|
[et_tor](#et_tor)|6380|6380|33|0.5%|10.9%|
[dm_tor](#dm_tor)|6610|6610|33|0.4%|10.9%|
[bm_tor](#bm_tor)|6624|6624|33|0.4%|10.9%|
[blocklist_de_strongips](#blocklist_de_strongips)|175|175|32|18.2%|10.6%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|31|8.3%|10.2%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|26|0.0%|8.6%|
[et_block](#et_block)|1007|18338646|26|0.0%|8.6%|
[blocklist_de_apache](#blocklist_de_apache)|13937|13937|24|0.1%|7.9%|
[php_dictionary](#php_dictionary)|475|475|23|4.8%|7.6%|
[blocklist_de_mail](#blocklist_de_mail)|16874|16874|21|0.1%|6.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|17|0.0%|5.6%|
[ri_web_proxies](#ri_web_proxies)|6246|6246|15|0.2%|4.9%|
[alienvault_reputation](#alienvault_reputation)|182510|182510|15|0.0%|4.9%|
[sorbs_spam](#sorbs_spam)|25175|26038|11|0.0%|3.6%|
[sorbs_recent_spam](#sorbs_recent_spam)|20387|21001|11|0.0%|3.6%|
[sorbs_new_spam](#sorbs_new_spam)|20387|21001|11|0.0%|3.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|11|0.0%|3.6%|
[php_harvesters](#php_harvesters)|298|298|9|3.0%|2.9%|
[openbl_60d](#openbl_60d)|7699|7699|9|0.1%|2.9%|
[nixspam](#nixspam)|21252|21252|9|0.0%|2.9%|
[spamhaus_edrop](#spamhaus_edrop)|55|486400|7|0.0%|2.3%|
[xroxy](#xroxy)|2072|2072|6|0.2%|1.9%|
[proxyrss](#proxyrss)|1758|1758|6|0.3%|1.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|6|0.0%|1.9%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2582|2582|5|0.1%|1.6%|
[proxz](#proxz)|733|733|4|0.5%|1.3%|
[sorbs_web](#sorbs_web)|730|732|2|0.2%|0.6%|
[ri_connect_proxies](#ri_connect_proxies)|2341|2341|2|0.0%|0.6%|
[zeus_badips](#zeus_badips)|234|234|1|0.4%|0.3%|
[zeus](#zeus)|268|268|1|0.3%|0.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.3%|
[dshield](#dshield)|20|5120|1|0.0%|0.3%|

## php_dictionary

[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) directory attackers (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=d&rss=1).

The last time downloaded was found to be dated: Thu Jun  4 20:45:03 UTC 2015.

The ipset `php_dictionary` has **475** entries, **475** unique IPs.

The following table shows the overlaps of `php_dictionary` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `php_dictionary`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `php_dictionary`.
- ` this % ` is the percentage **of this ipset (`php_dictionary`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[php_spammers](#php_spammers)|461|461|120|26.0%|25.2%|
[sorbs_spam](#sorbs_spam)|25175|26038|110|0.4%|23.1%|
[sorbs_recent_spam](#sorbs_recent_spam)|20387|21001|102|0.4%|21.4%|
[sorbs_new_spam](#sorbs_new_spam)|20387|21001|102|0.4%|21.4%|
[stopforumspam_30d](#stopforumspam_30d)|92996|92996|90|0.0%|18.9%|
[nixspam](#nixspam)|21252|21252|88|0.4%|18.5%|
[blocklist_de](#blocklist_de)|35206|35206|67|0.1%|14.1%|
[stopforumspam_7d](#stopforumspam_7d)|30334|30334|61|0.2%|12.8%|
[snort_ipfilter](#snort_ipfilter)|9591|9591|61|0.6%|12.8%|
[blocklist_de_mail](#blocklist_de_mail)|16874|16874|54|0.3%|11.3%|
[ri_web_proxies](#ri_web_proxies)|6246|6246|34|0.5%|7.1%|
[sorbs_web](#sorbs_web)|730|732|31|4.2%|6.5%|
[xroxy](#xroxy)|2072|2072|27|1.3%|5.6%|
[stopforumspam_1d](#stopforumspam_1d)|7043|7043|26|0.3%|5.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|25|0.0%|5.2%|
[php_commenters](#php_commenters)|301|301|23|7.6%|4.8%|
[proxz](#proxz)|733|733|11|1.5%|2.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|11|0.0%|2.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|9|0.0%|1.8%|
[blocklist_de_bots](#blocklist_de_bots)|3178|3178|8|0.2%|1.6%|
[alienvault_reputation](#alienvault_reputation)|182510|182510|8|0.0%|1.6%|
[et_tor](#et_tor)|6380|6380|5|0.0%|1.0%|
[dm_tor](#dm_tor)|6610|6610|5|0.0%|1.0%|
[bm_tor](#bm_tor)|6624|6624|5|0.0%|1.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2582|2582|5|0.1%|1.0%|
[blocklist_de_apache](#blocklist_de_apache)|13937|13937|5|0.0%|1.0%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|4|0.0%|0.8%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|4|1.0%|0.8%|
[et_block](#et_block)|1007|18338646|4|0.0%|0.8%|
[ri_connect_proxies](#ri_connect_proxies)|2341|2341|3|0.1%|0.6%|
[php_harvesters](#php_harvesters)|298|298|2|0.6%|0.4%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2|0.0%|0.4%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|2|0.0%|0.4%|
[blocklist_de_strongips](#blocklist_de_strongips)|175|175|2|1.1%|0.4%|
[proxyrss](#proxyrss)|1758|1758|1|0.0%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.2%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|1|0.1%|0.2%|

## php_harvesters

[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) harvesters (IPs that surf the internet looking for email addresses) (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=h&rss=1).

The last time downloaded was found to be dated: Thu Jun  4 21:36:37 UTC 2015.

The ipset `php_harvesters` has **298** entries, **298** unique IPs.

The following table shows the overlaps of `php_harvesters` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `php_harvesters`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `php_harvesters`.
- ` this % ` is the percentage **of this ipset (`php_harvesters`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_30d](#stopforumspam_30d)|92996|92996|67|0.0%|22.4%|
[stopforumspam_7d](#stopforumspam_7d)|30334|30334|53|0.1%|17.7%|
[stopforumspam_1d](#stopforumspam_1d)|7043|7043|36|0.5%|12.0%|
[blocklist_de](#blocklist_de)|35206|35206|31|0.0%|10.4%|
[blocklist_de_bots](#blocklist_de_bots)|3178|3178|21|0.6%|7.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|17|0.0%|5.7%|
[snort_ipfilter](#snort_ipfilter)|9591|9591|10|0.1%|3.3%|
[alienvault_reputation](#alienvault_reputation)|182510|182510|10|0.0%|3.3%|
[php_commenters](#php_commenters)|301|301|9|2.9%|3.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|9|0.0%|3.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|9|0.0%|3.0%|
[sorbs_spam](#sorbs_spam)|25175|26038|8|0.0%|2.6%|
[et_tor](#et_tor)|6380|6380|7|0.1%|2.3%|
[dm_tor](#dm_tor)|6610|6610|7|0.1%|2.3%|
[bm_tor](#bm_tor)|6624|6624|7|0.1%|2.3%|
[sorbs_recent_spam](#sorbs_recent_spam)|20387|21001|6|0.0%|2.0%|
[sorbs_new_spam](#sorbs_new_spam)|20387|21001|6|0.0%|2.0%|
[nixspam](#nixspam)|21252|21252|6|0.0%|2.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|6|1.6%|2.0%|
[blocklist_de_mail](#blocklist_de_mail)|16874|16874|4|0.0%|1.3%|
[blocklist_de_apache](#blocklist_de_apache)|13937|13937|4|0.0%|1.3%|
[blocklist_de_ftp](#blocklist_de_ftp)|908|908|3|0.3%|1.0%|
[xroxy](#xroxy)|2072|2072|2|0.0%|0.6%|
[proxyrss](#proxyrss)|1758|1758|2|0.1%|0.6%|
[php_spammers](#php_spammers)|461|461|2|0.4%|0.6%|
[php_dictionary](#php_dictionary)|475|475|2|0.4%|0.6%|
[openbl_60d](#openbl_60d)|7699|7699|2|0.0%|0.6%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|2|0.0%|0.6%|
[blocklist_de_strongips](#blocklist_de_strongips)|175|175|2|1.1%|0.6%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2582|2582|2|0.0%|0.6%|
[spamhaus_edrop](#spamhaus_edrop)|55|486400|1|0.0%|0.3%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|1|0.0%|0.3%|
[ri_web_proxies](#ri_web_proxies)|6246|6246|1|0.0%|0.3%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.3%|
[fullbogons](#fullbogons)|3733|670419608|1|0.0%|0.3%|
[et_block](#et_block)|1007|18338646|1|0.0%|0.3%|
[bogons](#bogons)|13|592708608|1|0.0%|0.3%|

## php_spammers

[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) spam servers (IPs used by spammers to send messages) (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=s&rss=1).

The last time downloaded was found to be dated: Thu Jun  4 21:36:39 UTC 2015.

The ipset `php_spammers` has **461** entries, **461** unique IPs.

The following table shows the overlaps of `php_spammers` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `php_spammers`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `php_spammers`.
- ` this % ` is the percentage **of this ipset (`php_spammers`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[php_dictionary](#php_dictionary)|475|475|120|25.2%|26.0%|
[stopforumspam_30d](#stopforumspam_30d)|92996|92996|103|0.1%|22.3%|
[sorbs_spam](#sorbs_spam)|25175|26038|98|0.3%|21.2%|
[sorbs_recent_spam](#sorbs_recent_spam)|20387|21001|89|0.4%|19.3%|
[sorbs_new_spam](#sorbs_new_spam)|20387|21001|89|0.4%|19.3%|
[nixspam](#nixspam)|21252|21252|67|0.3%|14.5%|
[blocklist_de](#blocklist_de)|35206|35206|63|0.1%|13.6%|
[stopforumspam_7d](#stopforumspam_7d)|30334|30334|60|0.1%|13.0%|
[snort_ipfilter](#snort_ipfilter)|9591|9591|59|0.6%|12.7%|
[blocklist_de_mail](#blocklist_de_mail)|16874|16874|47|0.2%|10.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|34|0.0%|7.3%|
[php_commenters](#php_commenters)|301|301|33|10.9%|7.1%|
[stopforumspam_1d](#stopforumspam_1d)|7043|7043|31|0.4%|6.7%|
[ri_web_proxies](#ri_web_proxies)|6246|6246|26|0.4%|5.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|26|0.0%|5.6%|
[sorbs_web](#sorbs_web)|730|732|24|3.2%|5.2%|
[xroxy](#xroxy)|2072|2072|22|1.0%|4.7%|
[proxz](#proxz)|733|733|10|1.3%|2.1%|
[blocklist_de_bots](#blocklist_de_bots)|3178|3178|9|0.2%|1.9%|
[et_tor](#et_tor)|6380|6380|6|0.0%|1.3%|
[dm_tor](#dm_tor)|6610|6610|6|0.0%|1.3%|
[bm_tor](#bm_tor)|6624|6624|6|0.0%|1.3%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2582|2582|6|0.2%|1.3%|
[blocklist_de_apache](#blocklist_de_apache)|13937|13937|6|0.0%|1.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|5|0.0%|1.0%|
[alienvault_reputation](#alienvault_reputation)|182510|182510|5|0.0%|1.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|4|1.0%|0.8%|
[blocklist_de_strongips](#blocklist_de_strongips)|175|175|4|2.2%|0.8%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|3|0.0%|0.6%|
[ri_connect_proxies](#ri_connect_proxies)|2341|2341|2|0.0%|0.4%|
[proxyrss](#proxyrss)|1758|1758|2|0.1%|0.4%|
[php_harvesters](#php_harvesters)|298|298|2|0.6%|0.4%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2|0.0%|0.4%|
[et_block](#et_block)|1007|18338646|2|0.0%|0.4%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1|0.0%|0.2%|
[blocklist_de_ftp](#blocklist_de_ftp)|908|908|1|0.1%|0.2%|

## proxyrss

[proxyrss.com](http://www.proxyrss.com) open proxies syndicated from multiple sources.

Source is downloaded from [this link](http://www.proxyrss.com/proxylists/all.gz).

The last time downloaded was found to be dated: Thu Jun  4 20:01:31 UTC 2015.

The ipset `proxyrss` has **1758** entries, **1758** unique IPs.

The following table shows the overlaps of `proxyrss` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `proxyrss`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `proxyrss`.
- ` this % ` is the percentage **of this ipset (`proxyrss`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_30d](#stopforumspam_30d)|92996|92996|839|0.9%|47.7%|
[ri_web_proxies](#ri_web_proxies)|6246|6246|707|11.3%|40.2%|
[stopforumspam_7d](#stopforumspam_7d)|30334|30334|669|2.2%|38.0%|
[xroxy](#xroxy)|2072|2072|443|21.3%|25.1%|
[stopforumspam_1d](#stopforumspam_1d)|7043|7043|429|6.0%|24.4%|
[blocklist_de](#blocklist_de)|35206|35206|271|0.7%|15.4%|
[blocklist_de_bots](#blocklist_de_bots)|3178|3178|270|8.4%|15.3%|
[ri_connect_proxies](#ri_connect_proxies)|2341|2341|242|10.3%|13.7%|
[proxz](#proxz)|733|733|214|29.1%|12.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|68|0.0%|3.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|58|0.0%|3.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|37|0.0%|2.1%|
[nixspam](#nixspam)|21252|21252|19|0.0%|1.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|8|1.1%|0.4%|
[sorbs_spam](#sorbs_spam)|25175|26038|6|0.0%|0.3%|
[sorbs_recent_spam](#sorbs_recent_spam)|20387|21001|6|0.0%|0.3%|
[sorbs_new_spam](#sorbs_new_spam)|20387|21001|6|0.0%|0.3%|
[php_commenters](#php_commenters)|301|301|6|1.9%|0.3%|
[snort_ipfilter](#snort_ipfilter)|9591|9591|5|0.0%|0.2%|
[blocklist_de_strongips](#blocklist_de_strongips)|175|175|5|2.8%|0.2%|
[alienvault_reputation](#alienvault_reputation)|182510|182510|3|0.0%|0.1%|
[php_spammers](#php_spammers)|461|461|2|0.4%|0.1%|
[php_harvesters](#php_harvesters)|298|298|2|0.6%|0.1%|
[et_compromised](#et_compromised)|2171|2171|2|0.0%|0.1%|
[bruteforceblocker](#bruteforceblocker)|2039|2039|2|0.0%|0.1%|
[sorbs_web](#sorbs_web)|730|732|1|0.1%|0.0%|
[php_dictionary](#php_dictionary)|475|475|1|0.2%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.0%|
[et_tor](#et_tor)|6380|6380|1|0.0%|0.0%|
[dm_tor](#dm_tor)|6610|6610|1|0.0%|0.0%|
[bm_tor](#bm_tor)|6624|6624|1|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2582|2582|1|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13937|13937|1|0.0%|0.0%|

## proxz

[proxz.com](http://www.proxz.com) open proxies (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.proxz.com/proxylists.xml).

The last time downloaded was found to be dated: Thu Jun  4 20:01:40 UTC 2015.

The ipset `proxz` has **733** entries, **733** unique IPs.

The following table shows the overlaps of `proxz` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `proxz`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `proxz`.
- ` this % ` is the percentage **of this ipset (`proxz`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_30d](#stopforumspam_30d)|92996|92996|436|0.4%|59.4%|
[stopforumspam_7d](#stopforumspam_7d)|30334|30334|363|1.1%|49.5%|
[ri_web_proxies](#ri_web_proxies)|6246|6246|326|5.2%|44.4%|
[xroxy](#xroxy)|2072|2072|306|14.7%|41.7%|
[proxyrss](#proxyrss)|1758|1758|214|12.1%|29.1%|
[blocklist_de](#blocklist_de)|35206|35206|141|0.4%|19.2%|
[stopforumspam_1d](#stopforumspam_1d)|7043|7043|128|1.8%|17.4%|
[ri_connect_proxies](#ri_connect_proxies)|2341|2341|121|5.1%|16.5%|
[blocklist_de_bots](#blocklist_de_bots)|3178|3178|118|3.7%|16.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|65|0.0%|8.8%|
[nixspam](#nixspam)|21252|21252|35|0.1%|4.7%|
[sorbs_spam](#sorbs_spam)|25175|26038|32|0.1%|4.3%|
[sorbs_recent_spam](#sorbs_recent_spam)|20387|21001|32|0.1%|4.3%|
[sorbs_new_spam](#sorbs_new_spam)|20387|21001|32|0.1%|4.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|31|0.0%|4.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|28|0.0%|3.8%|
[blocklist_de_mail](#blocklist_de_mail)|16874|16874|22|0.1%|3.0%|
[snort_ipfilter](#snort_ipfilter)|9591|9591|21|0.2%|2.8%|
[sorbs_web](#sorbs_web)|730|732|12|1.6%|1.6%|
[php_dictionary](#php_dictionary)|475|475|11|2.3%|1.5%|
[php_spammers](#php_spammers)|461|461|10|2.1%|1.3%|
[php_commenters](#php_commenters)|301|301|4|1.3%|0.5%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|4|0.5%|0.5%|
[blocklist_de_strongips](#blocklist_de_strongips)|175|175|3|1.7%|0.4%|
[alienvault_reputation](#alienvault_reputation)|182510|182510|3|0.0%|0.4%|
[et_compromised](#et_compromised)|2171|2171|2|0.0%|0.2%|
[bruteforceblocker](#bruteforceblocker)|2039|2039|2|0.0%|0.2%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1|0.0%|0.1%|
[blocklist_de_ssh](#blocklist_de_ssh)|11179|11179|1|0.0%|0.1%|

## ri_connect_proxies

[rosinstrument.com](http://www.rosinstrument.com) open CONNECT proxies (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://tools.rosinstrument.com/proxy/plab100.xml).

The last time downloaded was found to be dated: Thu Jun  4 21:08:58 UTC 2015.

The ipset `ri_connect_proxies` has **2341** entries, **2341** unique IPs.

The following table shows the overlaps of `ri_connect_proxies` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ri_connect_proxies`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ri_connect_proxies`.
- ` this % ` is the percentage **of this ipset (`ri_connect_proxies`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_30d](#stopforumspam_30d)|92996|92996|1354|1.4%|57.8%|
[ri_web_proxies](#ri_web_proxies)|6246|6246|958|15.3%|40.9%|
[stopforumspam_7d](#stopforumspam_7d)|30334|30334|690|2.2%|29.4%|
[xroxy](#xroxy)|2072|2072|354|17.0%|15.1%|
[proxyrss](#proxyrss)|1758|1758|242|13.7%|10.3%|
[stopforumspam_1d](#stopforumspam_1d)|7043|7043|160|2.2%|6.8%|
[proxz](#proxz)|733|733|121|16.5%|5.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|91|0.0%|3.8%|
[blocklist_de](#blocklist_de)|35206|35206|75|0.2%|3.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|74|0.0%|3.1%|
[blocklist_de_bots](#blocklist_de_bots)|3178|3178|72|2.2%|3.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|52|0.0%|2.2%|
[nixspam](#nixspam)|21252|21252|20|0.0%|0.8%|
[sorbs_spam](#sorbs_spam)|25175|26038|10|0.0%|0.4%|
[sorbs_recent_spam](#sorbs_recent_spam)|20387|21001|9|0.0%|0.3%|
[sorbs_new_spam](#sorbs_new_spam)|20387|21001|9|0.0%|0.3%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|6|0.8%|0.2%|
[snort_ipfilter](#snort_ipfilter)|9591|9591|5|0.0%|0.2%|
[php_dictionary](#php_dictionary)|475|475|3|0.6%|0.1%|
[sorbs_web](#sorbs_web)|730|732|2|0.2%|0.0%|
[php_spammers](#php_spammers)|461|461|2|0.4%|0.0%|
[php_commenters](#php_commenters)|301|301|2|0.6%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|16874|16874|2|0.0%|0.0%|
[alienvault_reputation](#alienvault_reputation)|182510|182510|2|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.0%|
[et_tor](#et_tor)|6380|6380|1|0.0%|0.0%|
[dm_tor](#dm_tor)|6610|6610|1|0.0%|0.0%|
[bm_tor](#bm_tor)|6624|6624|1|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|11179|11179|1|0.0%|0.0%|

## ri_web_proxies

[rosinstrument.com](http://www.rosinstrument.com) open HTTP proxies (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://tools.rosinstrument.com/proxy/l100.xml).

The last time downloaded was found to be dated: Thu Jun  4 21:07:19 UTC 2015.

The ipset `ri_web_proxies` has **6246** entries, **6246** unique IPs.

The following table shows the overlaps of `ri_web_proxies` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ri_web_proxies`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ri_web_proxies`.
- ` this % ` is the percentage **of this ipset (`ri_web_proxies`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_30d](#stopforumspam_30d)|92996|92996|3010|3.2%|48.1%|
[stopforumspam_7d](#stopforumspam_7d)|30334|30334|1682|5.5%|26.9%|
[ri_connect_proxies](#ri_connect_proxies)|2341|2341|958|40.9%|15.3%|
[xroxy](#xroxy)|2072|2072|878|42.3%|14.0%|
[proxyrss](#proxyrss)|1758|1758|707|40.2%|11.3%|
[stopforumspam_1d](#stopforumspam_1d)|7043|7043|529|7.5%|8.4%|
[blocklist_de](#blocklist_de)|35206|35206|416|1.1%|6.6%|
[blocklist_de_bots](#blocklist_de_bots)|3178|3178|363|11.4%|5.8%|
[proxz](#proxz)|733|733|326|44.4%|5.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|184|0.0%|2.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|177|0.0%|2.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|131|0.0%|2.0%|
[sorbs_spam](#sorbs_spam)|25175|26038|116|0.4%|1.8%|
[sorbs_recent_spam](#sorbs_recent_spam)|20387|21001|110|0.5%|1.7%|
[sorbs_new_spam](#sorbs_new_spam)|20387|21001|110|0.5%|1.7%|
[nixspam](#nixspam)|21252|21252|103|0.4%|1.6%|
[snort_ipfilter](#snort_ipfilter)|9591|9591|62|0.6%|0.9%|
[blocklist_de_mail](#blocklist_de_mail)|16874|16874|52|0.3%|0.8%|
[php_dictionary](#php_dictionary)|475|475|34|7.1%|0.5%|
[sorbs_web](#sorbs_web)|730|732|28|3.8%|0.4%|
[php_spammers](#php_spammers)|461|461|26|5.6%|0.4%|
[php_commenters](#php_commenters)|301|301|15|4.9%|0.2%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|12|1.7%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|5|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|175|175|5|2.8%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|4|1.0%|0.0%|
[et_tor](#et_tor)|6380|6380|4|0.0%|0.0%|
[dm_tor](#dm_tor)|6610|6610|4|0.0%|0.0%|
[bm_tor](#bm_tor)|6624|6624|4|0.0%|0.0%|
[alienvault_reputation](#alienvault_reputation)|182510|182510|3|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|2|0.0%|0.0%|
[sorbs_socks](#sorbs_socks)|28|28|1|3.5%|0.0%|
[sorbs_misc](#sorbs_misc)|28|28|1|3.5%|0.0%|
[sorbs_http](#sorbs_http)|28|28|1|3.5%|0.0%|
[php_harvesters](#php_harvesters)|298|298|1|0.3%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|
[et_compromised](#et_compromised)|2171|2171|1|0.0%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|370|370|1|0.2%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2039|2039|1|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2582|2582|1|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13937|13937|1|0.0%|0.0%|

## shunlist

[AutoShun.org](http://autoshun.org/) IPs identified as hostile by correlating logs from distributed snort installations running the autoshun plugin

Source is downloaded from [this link](http://www.autoshun.org/files/shunlist.csv).

The last time downloaded was found to be dated: Thu Jun  4 18:30:03 UTC 2015.

The ipset `shunlist` has **1229** entries, **1229** unique IPs.

The following table shows the overlaps of `shunlist` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `shunlist`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `shunlist`.
- ` this % ` is the percentage **of this ipset (`shunlist`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[alienvault_reputation](#alienvault_reputation)|182510|182510|1221|0.6%|99.3%|
[openbl_60d](#openbl_60d)|7699|7699|576|7.4%|46.8%|
[openbl_30d](#openbl_30d)|3261|3261|561|17.2%|45.6%|
[et_compromised](#et_compromised)|2171|2171|480|22.1%|39.0%|
[bruteforceblocker](#bruteforceblocker)|2039|2039|474|23.2%|38.5%|
[blocklist_de](#blocklist_de)|35206|35206|381|1.0%|31.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|11179|11179|348|3.1%|28.3%|
[openbl_7d](#openbl_7d)|935|935|303|32.4%|24.6%|
[et_block](#et_block)|1007|18338646|106|0.0%|8.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|101|0.0%|8.2%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|98|0.0%|7.9%|
[openbl_1d](#openbl_1d)|182|182|76|41.7%|6.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|72|0.0%|5.8%|
[sslbl](#sslbl)|365|365|56|15.3%|4.5%|
[dshield](#dshield)|20|5120|38|0.7%|3.0%|
[blocklist_de_apache](#blocklist_de_apache)|13937|13937|32|0.2%|2.6%|
[ciarmy](#ciarmy)|359|359|28|7.7%|2.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|25|0.0%|2.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|175|175|20|11.4%|1.6%|
[voipbl](#voipbl)|10426|10837|12|0.1%|0.9%|
[stopforumspam_30d](#stopforumspam_30d)|92996|92996|4|0.0%|0.3%|
[stopforumspam_7d](#stopforumspam_7d)|30334|30334|3|0.0%|0.2%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2582|2582|3|0.1%|0.2%|
[snort_ipfilter](#snort_ipfilter)|9591|9591|2|0.0%|0.1%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|2|0.5%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2|0.0%|0.1%|
[stopforumspam_1d](#stopforumspam_1d)|7043|7043|1|0.0%|0.0%|
[sorbs_spam](#sorbs_spam)|25175|26038|1|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|20387|21001|1|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|20387|21001|1|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.0%|
[et_tor](#et_tor)|6380|6380|1|0.0%|0.0%|
[dm_tor](#dm_tor)|6610|6610|1|0.0%|0.0%|
[bm_tor](#bm_tor)|6624|6624|1|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|16874|16874|1|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2837|2837|1|0.0%|0.0%|

## snort_ipfilter

[labs.snort.org](https://labs.snort.org/) supplied IP blacklist (this list seems to be updated frequently, but we found no information about it)

Source is downloaded from [this link](http://labs.snort.org/feeds/ip-filter.blf).

The last time downloaded was found to be dated: Thu Jun  4 13:30:00 UTC 2015.

The ipset `snort_ipfilter` has **9591** entries, **9591** unique IPs.

The following table shows the overlaps of `snort_ipfilter` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `snort_ipfilter`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `snort_ipfilter`.
- ` this % ` is the percentage **of this ipset (`snort_ipfilter`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[bm_tor](#bm_tor)|6624|6624|1088|16.4%|11.3%|
[et_tor](#et_tor)|6380|6380|1086|17.0%|11.3%|
[dm_tor](#dm_tor)|6610|6610|1083|16.3%|11.2%|
[stopforumspam_30d](#stopforumspam_30d)|92996|92996|810|0.8%|8.4%|
[stopforumspam_7d](#stopforumspam_7d)|30334|30334|618|2.0%|6.4%|
[stopforumspam_1d](#stopforumspam_1d)|7043|7043|388|5.5%|4.0%|
[sorbs_spam](#sorbs_spam)|25175|26038|346|1.3%|3.6%|
[sorbs_recent_spam](#sorbs_recent_spam)|20387|21001|324|1.5%|3.3%|
[sorbs_new_spam](#sorbs_new_spam)|20387|21001|324|1.5%|3.3%|
[et_block](#et_block)|1007|18338646|305|0.0%|3.1%|
[zeus](#zeus)|268|268|227|84.7%|2.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|219|0.0%|2.2%|
[zeus_badips](#zeus_badips)|234|234|205|87.6%|2.1%|
[blocklist_de](#blocklist_de)|35206|35206|194|0.5%|2.0%|
[nixspam](#nixspam)|21252|21252|178|0.8%|1.8%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|177|47.5%|1.8%|
[blocklist_de_mail](#blocklist_de_mail)|16874|16874|170|1.0%|1.7%|
[alienvault_reputation](#alienvault_reputation)|182510|182510|125|0.0%|1.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|100|0.0%|1.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|98|0.0%|1.0%|
[feodo](#feodo)|94|94|68|72.3%|0.7%|
[ri_web_proxies](#ri_web_proxies)|6246|6246|62|0.9%|0.6%|
[php_dictionary](#php_dictionary)|475|475|61|12.8%|0.6%|
[sorbs_web](#sorbs_web)|730|732|59|8.0%|0.6%|
[php_spammers](#php_spammers)|461|461|59|12.7%|0.6%|
[xroxy](#xroxy)|2072|2072|50|2.4%|0.5%|
[php_commenters](#php_commenters)|301|301|42|13.9%|0.4%|
[openbl_60d](#openbl_60d)|7699|7699|31|0.4%|0.3%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|29|2.2%|0.3%|
[sslbl](#sslbl)|365|365|28|7.6%|0.2%|
[proxz](#proxz)|733|733|21|2.8%|0.2%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|20|0.0%|0.2%|
[blocklist_de_bots](#blocklist_de_bots)|3178|3178|19|0.5%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|14|0.0%|0.1%|
[palevo](#palevo)|13|13|11|84.6%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|11|0.0%|0.1%|
[php_harvesters](#php_harvesters)|298|298|10|3.3%|0.1%|
[openbl_30d](#openbl_30d)|3261|3261|8|0.2%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13937|13937|8|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|486400|6|0.0%|0.0%|
[sorbs_socks](#sorbs_socks)|28|28|6|21.4%|0.0%|
[sorbs_misc](#sorbs_misc)|28|28|6|21.4%|0.0%|
[sorbs_http](#sorbs_http)|28|28|6|21.4%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2341|2341|5|0.2%|0.0%|
[proxyrss](#proxyrss)|1758|1758|5|0.2%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2837|2837|5|0.1%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2582|2582|4|0.1%|0.0%|
[openbl_7d](#openbl_7d)|935|935|3|0.3%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|370|370|3|0.8%|0.0%|
[shunlist](#shunlist)|1229|1229|2|0.1%|0.0%|
[voipbl](#voipbl)|10426|10837|1|0.0%|0.0%|
[malc0de](#malc0de)|379|379|1|0.2%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|1|0.1%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1|0.0%|0.0%|
[et_compromised](#et_compromised)|2171|2171|1|0.0%|0.0%|
[dshield](#dshield)|20|5120|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2039|2039|1|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|175|175|1|0.5%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|11179|11179|1|0.0%|0.0%|

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

The last time downloaded was found to be dated: Thu Jun  4 20:04:14 UTC 2015.

The ipset `sorbs_http` has **28** entries, **28** unique IPs.

The following table shows the overlaps of `sorbs_http` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `sorbs_http`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `sorbs_http`.
- ` this % ` is the percentage **of this ipset (`sorbs_http`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[sorbs_socks](#sorbs_socks)|28|28|28|100.0%|100.0%|
[sorbs_misc](#sorbs_misc)|28|28|28|100.0%|100.0%|
[sorbs_spam](#sorbs_spam)|25175|26038|22|0.0%|78.5%|
[sorbs_recent_spam](#sorbs_recent_spam)|20387|21001|17|0.0%|60.7%|
[sorbs_new_spam](#sorbs_new_spam)|20387|21001|17|0.0%|60.7%|
[nixspam](#nixspam)|21252|21252|7|0.0%|25.0%|
[snort_ipfilter](#snort_ipfilter)|9591|9591|6|0.0%|21.4%|
[blocklist_de](#blocklist_de)|35206|35206|6|0.0%|21.4%|
[sorbs_web](#sorbs_web)|730|732|5|0.6%|17.8%|
[blocklist_de_mail](#blocklist_de_mail)|16874|16874|4|0.0%|14.2%|
[stopforumspam_7d](#stopforumspam_7d)|30334|30334|2|0.0%|7.1%|
[stopforumspam_30d](#stopforumspam_30d)|92996|92996|2|0.0%|7.1%|
[stopforumspam_1d](#stopforumspam_1d)|7043|7043|2|0.0%|7.1%|
[blocklist_de_bots](#blocklist_de_bots)|3178|3178|2|0.0%|7.1%|
[xroxy](#xroxy)|2072|2072|1|0.0%|3.5%|
[ri_web_proxies](#ri_web_proxies)|6246|6246|1|0.0%|3.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|1|0.0%|3.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|1|0.0%|3.5%|

## sorbs_misc

[Sorbs.net](https://www.sorbs.net/) MISC proxies, extracted from deltas.

Source is downloaded from [this link]().

The last time downloaded was found to be dated: Thu Jun  4 20:04:14 UTC 2015.

The ipset `sorbs_misc` has **28** entries, **28** unique IPs.

The following table shows the overlaps of `sorbs_misc` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `sorbs_misc`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `sorbs_misc`.
- ` this % ` is the percentage **of this ipset (`sorbs_misc`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[sorbs_socks](#sorbs_socks)|28|28|28|100.0%|100.0%|
[sorbs_http](#sorbs_http)|28|28|28|100.0%|100.0%|
[sorbs_spam](#sorbs_spam)|25175|26038|22|0.0%|78.5%|
[sorbs_recent_spam](#sorbs_recent_spam)|20387|21001|17|0.0%|60.7%|
[sorbs_new_spam](#sorbs_new_spam)|20387|21001|17|0.0%|60.7%|
[nixspam](#nixspam)|21252|21252|7|0.0%|25.0%|
[snort_ipfilter](#snort_ipfilter)|9591|9591|6|0.0%|21.4%|
[blocklist_de](#blocklist_de)|35206|35206|6|0.0%|21.4%|
[sorbs_web](#sorbs_web)|730|732|5|0.6%|17.8%|
[blocklist_de_mail](#blocklist_de_mail)|16874|16874|4|0.0%|14.2%|
[stopforumspam_7d](#stopforumspam_7d)|30334|30334|2|0.0%|7.1%|
[stopforumspam_30d](#stopforumspam_30d)|92996|92996|2|0.0%|7.1%|
[stopforumspam_1d](#stopforumspam_1d)|7043|7043|2|0.0%|7.1%|
[blocklist_de_bots](#blocklist_de_bots)|3178|3178|2|0.0%|7.1%|
[xroxy](#xroxy)|2072|2072|1|0.0%|3.5%|
[ri_web_proxies](#ri_web_proxies)|6246|6246|1|0.0%|3.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|1|0.0%|3.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|1|0.0%|3.5%|

## sorbs_new_spam

[Sorbs.net](https://www.sorbs.net/) NEW Spam senders, extracted from deltas.

Source is downloaded from [this link]().

The last time downloaded was found to be dated: Thu Jun  4 21:04:16 UTC 2015.

The ipset `sorbs_new_spam` has **20387** entries, **21001** unique IPs.

The following table shows the overlaps of `sorbs_new_spam` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `sorbs_new_spam`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `sorbs_new_spam`.
- ` this % ` is the percentage **of this ipset (`sorbs_new_spam`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[sorbs_spam](#sorbs_spam)|25175|26038|21001|80.6%|100.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|20387|21001|21001|100.0%|100.0%|
[nixspam](#nixspam)|21252|21252|3832|18.0%|18.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|1450|0.0%|6.9%|
[blocklist_de](#blocklist_de)|35206|35206|1040|2.9%|4.9%|
[blocklist_de_mail](#blocklist_de_mail)|16874|16874|870|5.1%|4.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|539|0.0%|2.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|331|0.0%|1.5%|
[snort_ipfilter](#snort_ipfilter)|9591|9591|324|3.3%|1.5%|
[sorbs_web](#sorbs_web)|730|732|285|38.9%|1.3%|
[stopforumspam_30d](#stopforumspam_30d)|92996|92996|266|0.2%|1.2%|
[stopforumspam_7d](#stopforumspam_7d)|30334|30334|155|0.5%|0.7%|
[ri_web_proxies](#ri_web_proxies)|6246|6246|110|1.7%|0.5%|
[php_dictionary](#php_dictionary)|475|475|102|21.4%|0.4%|
[php_spammers](#php_spammers)|461|461|89|19.3%|0.4%|
[xroxy](#xroxy)|2072|2072|79|3.8%|0.3%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2582|2582|72|2.7%|0.3%|
[blocklist_de_apache](#blocklist_de_apache)|13937|13937|72|0.5%|0.3%|
[alienvault_reputation](#alienvault_reputation)|182510|182510|66|0.0%|0.3%|
[blocklist_de_ssh](#blocklist_de_ssh)|11179|11179|65|0.5%|0.3%|
[stopforumspam_1d](#stopforumspam_1d)|7043|7043|60|0.8%|0.2%|
[proxz](#proxz)|733|733|32|4.3%|0.1%|
[blocklist_de_bots](#blocklist_de_bots)|3178|3178|31|0.9%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|23|0.0%|0.1%|
[blocklist_de_imap](#blocklist_de_imap)|2837|2837|19|0.6%|0.0%|
[sorbs_socks](#sorbs_socks)|28|28|17|60.7%|0.0%|
[sorbs_misc](#sorbs_misc)|28|28|17|60.7%|0.0%|
[sorbs_http](#sorbs_http)|28|28|17|60.7%|0.0%|
[openbl_60d](#openbl_60d)|7699|7699|13|0.1%|0.0%|
[php_commenters](#php_commenters)|301|301|11|3.6%|0.0%|
[sorbs_smtp](#sorbs_smtp)|10|10|9|90.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2341|2341|9|0.3%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|7|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|7|0.0%|0.0%|
[et_block](#et_block)|1007|18338646|7|0.0%|0.0%|
[proxyrss](#proxyrss)|1758|1758|6|0.3%|0.0%|
[php_harvesters](#php_harvesters)|298|298|6|2.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|486400|3|0.0%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|0.0%|
[openbl_30d](#openbl_30d)|3261|3261|2|0.0%|0.0%|
[et_tor](#et_tor)|6380|6380|2|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|908|908|2|0.2%|0.0%|
[shunlist](#shunlist)|1229|1229|1|0.0%|0.0%|
[openbl_7d](#openbl_7d)|935|935|1|0.1%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|1|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|1|0.1%|0.0%|
[dshield](#dshield)|20|5120|1|0.0%|0.0%|
[dm_tor](#dm_tor)|6610|6610|1|0.0%|0.0%|
[bm_tor](#bm_tor)|6624|6624|1|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|175|175|1|0.5%|0.0%|

## sorbs_recent_spam

[Sorbs.net](https://www.sorbs.net/) RECENT Spam senders, extracted from deltas.

Source is downloaded from [this link]().

The last time downloaded was found to be dated: Thu Jun  4 21:04:16 UTC 2015.

The ipset `sorbs_recent_spam` has **20387** entries, **21001** unique IPs.

The following table shows the overlaps of `sorbs_recent_spam` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `sorbs_recent_spam`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `sorbs_recent_spam`.
- ` this % ` is the percentage **of this ipset (`sorbs_recent_spam`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[sorbs_spam](#sorbs_spam)|25175|26038|21001|80.6%|100.0%|
[sorbs_new_spam](#sorbs_new_spam)|20387|21001|21001|100.0%|100.0%|
[nixspam](#nixspam)|21252|21252|3832|18.0%|18.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|1450|0.0%|6.9%|
[blocklist_de](#blocklist_de)|35206|35206|1040|2.9%|4.9%|
[blocklist_de_mail](#blocklist_de_mail)|16874|16874|870|5.1%|4.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|539|0.0%|2.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|331|0.0%|1.5%|
[snort_ipfilter](#snort_ipfilter)|9591|9591|324|3.3%|1.5%|
[sorbs_web](#sorbs_web)|730|732|285|38.9%|1.3%|
[stopforumspam_30d](#stopforumspam_30d)|92996|92996|266|0.2%|1.2%|
[stopforumspam_7d](#stopforumspam_7d)|30334|30334|155|0.5%|0.7%|
[ri_web_proxies](#ri_web_proxies)|6246|6246|110|1.7%|0.5%|
[php_dictionary](#php_dictionary)|475|475|102|21.4%|0.4%|
[php_spammers](#php_spammers)|461|461|89|19.3%|0.4%|
[xroxy](#xroxy)|2072|2072|79|3.8%|0.3%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2582|2582|72|2.7%|0.3%|
[blocklist_de_apache](#blocklist_de_apache)|13937|13937|72|0.5%|0.3%|
[alienvault_reputation](#alienvault_reputation)|182510|182510|66|0.0%|0.3%|
[blocklist_de_ssh](#blocklist_de_ssh)|11179|11179|65|0.5%|0.3%|
[stopforumspam_1d](#stopforumspam_1d)|7043|7043|60|0.8%|0.2%|
[proxz](#proxz)|733|733|32|4.3%|0.1%|
[blocklist_de_bots](#blocklist_de_bots)|3178|3178|31|0.9%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|23|0.0%|0.1%|
[blocklist_de_imap](#blocklist_de_imap)|2837|2837|19|0.6%|0.0%|
[sorbs_socks](#sorbs_socks)|28|28|17|60.7%|0.0%|
[sorbs_misc](#sorbs_misc)|28|28|17|60.7%|0.0%|
[sorbs_http](#sorbs_http)|28|28|17|60.7%|0.0%|
[openbl_60d](#openbl_60d)|7699|7699|13|0.1%|0.0%|
[php_commenters](#php_commenters)|301|301|11|3.6%|0.0%|
[sorbs_smtp](#sorbs_smtp)|10|10|9|90.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2341|2341|9|0.3%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|7|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|7|0.0%|0.0%|
[et_block](#et_block)|1007|18338646|7|0.0%|0.0%|
[proxyrss](#proxyrss)|1758|1758|6|0.3%|0.0%|
[php_harvesters](#php_harvesters)|298|298|6|2.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|486400|3|0.0%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|0.0%|
[openbl_30d](#openbl_30d)|3261|3261|2|0.0%|0.0%|
[et_tor](#et_tor)|6380|6380|2|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|908|908|2|0.2%|0.0%|
[shunlist](#shunlist)|1229|1229|1|0.0%|0.0%|
[openbl_7d](#openbl_7d)|935|935|1|0.1%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|1|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|1|0.1%|0.0%|
[dshield](#dshield)|20|5120|1|0.0%|0.0%|
[dm_tor](#dm_tor)|6610|6610|1|0.0%|0.0%|
[bm_tor](#bm_tor)|6624|6624|1|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|175|175|1|0.5%|0.0%|

## sorbs_smtp

[Sorbs.net](https://www.sorbs.net/) SMTP Open Relays, extracted from deltas.

Source is downloaded from [this link]().

The last time downloaded was found to be dated: Thu Jun  4 20:04:14 UTC 2015.

The ipset `sorbs_smtp` has **10** entries, **10** unique IPs.

The following table shows the overlaps of `sorbs_smtp` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `sorbs_smtp`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `sorbs_smtp`.
- ` this % ` is the percentage **of this ipset (`sorbs_smtp`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[sorbs_spam](#sorbs_spam)|25175|26038|10|0.0%|100.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|20387|21001|9|0.0%|90.0%|
[sorbs_new_spam](#sorbs_new_spam)|20387|21001|9|0.0%|90.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|1|0.0%|10.0%|

## sorbs_socks

[Sorbs.net](https://www.sorbs.net/) SOCKS proxies, extracted from deltas.

Source is downloaded from [this link]().

The last time downloaded was found to be dated: Thu Jun  4 20:04:14 UTC 2015.

The ipset `sorbs_socks` has **28** entries, **28** unique IPs.

The following table shows the overlaps of `sorbs_socks` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `sorbs_socks`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `sorbs_socks`.
- ` this % ` is the percentage **of this ipset (`sorbs_socks`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[sorbs_misc](#sorbs_misc)|28|28|28|100.0%|100.0%|
[sorbs_http](#sorbs_http)|28|28|28|100.0%|100.0%|
[sorbs_spam](#sorbs_spam)|25175|26038|22|0.0%|78.5%|
[sorbs_recent_spam](#sorbs_recent_spam)|20387|21001|17|0.0%|60.7%|
[sorbs_new_spam](#sorbs_new_spam)|20387|21001|17|0.0%|60.7%|
[nixspam](#nixspam)|21252|21252|7|0.0%|25.0%|
[snort_ipfilter](#snort_ipfilter)|9591|9591|6|0.0%|21.4%|
[blocklist_de](#blocklist_de)|35206|35206|6|0.0%|21.4%|
[sorbs_web](#sorbs_web)|730|732|5|0.6%|17.8%|
[blocklist_de_mail](#blocklist_de_mail)|16874|16874|4|0.0%|14.2%|
[stopforumspam_7d](#stopforumspam_7d)|30334|30334|2|0.0%|7.1%|
[stopforumspam_30d](#stopforumspam_30d)|92996|92996|2|0.0%|7.1%|
[stopforumspam_1d](#stopforumspam_1d)|7043|7043|2|0.0%|7.1%|
[blocklist_de_bots](#blocklist_de_bots)|3178|3178|2|0.0%|7.1%|
[xroxy](#xroxy)|2072|2072|1|0.0%|3.5%|
[ri_web_proxies](#ri_web_proxies)|6246|6246|1|0.0%|3.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|1|0.0%|3.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|1|0.0%|3.5%|

## sorbs_spam

[Sorbs.net](https://www.sorbs.net/) Spam senders, extracted from deltas.

Source is downloaded from [this link]().

The last time downloaded was found to be dated: Thu Jun  4 21:04:16 UTC 2015.

The ipset `sorbs_spam` has **25175** entries, **26038** unique IPs.

The following table shows the overlaps of `sorbs_spam` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `sorbs_spam`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `sorbs_spam`.
- ` this % ` is the percentage **of this ipset (`sorbs_spam`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[sorbs_recent_spam](#sorbs_recent_spam)|20387|21001|21001|100.0%|80.6%|
[sorbs_new_spam](#sorbs_new_spam)|20387|21001|21001|100.0%|80.6%|
[nixspam](#nixspam)|21252|21252|3971|18.6%|15.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|1833|0.0%|7.0%|
[blocklist_de](#blocklist_de)|35206|35206|1077|3.0%|4.1%|
[blocklist_de_mail](#blocklist_de_mail)|16874|16874|899|5.3%|3.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|623|0.0%|2.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|417|0.0%|1.6%|
[snort_ipfilter](#snort_ipfilter)|9591|9591|346|3.6%|1.3%|
[sorbs_web](#sorbs_web)|730|732|314|42.8%|1.2%|
[stopforumspam_30d](#stopforumspam_30d)|92996|92996|311|0.3%|1.1%|
[stopforumspam_7d](#stopforumspam_7d)|30334|30334|174|0.5%|0.6%|
[ri_web_proxies](#ri_web_proxies)|6246|6246|116|1.8%|0.4%|
[php_dictionary](#php_dictionary)|475|475|110|23.1%|0.4%|
[php_spammers](#php_spammers)|461|461|98|21.2%|0.3%|
[xroxy](#xroxy)|2072|2072|81|3.9%|0.3%|
[alienvault_reputation](#alienvault_reputation)|182510|182510|76|0.0%|0.2%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2582|2582|75|2.9%|0.2%|
[blocklist_de_apache](#blocklist_de_apache)|13937|13937|75|0.5%|0.2%|
[blocklist_de_ssh](#blocklist_de_ssh)|11179|11179|68|0.6%|0.2%|
[stopforumspam_1d](#stopforumspam_1d)|7043|7043|60|0.8%|0.2%|
[proxz](#proxz)|733|733|32|4.3%|0.1%|
[blocklist_de_bots](#blocklist_de_bots)|3178|3178|32|1.0%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|24|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2837|2837|24|0.8%|0.0%|
[sorbs_socks](#sorbs_socks)|28|28|22|78.5%|0.0%|
[sorbs_misc](#sorbs_misc)|28|28|22|78.5%|0.0%|
[sorbs_http](#sorbs_http)|28|28|22|78.5%|0.0%|
[openbl_60d](#openbl_60d)|7699|7699|14|0.1%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|12|0.0%|0.0%|
[et_block](#et_block)|1007|18338646|12|0.0%|0.0%|
[php_commenters](#php_commenters)|301|301|11|3.6%|0.0%|
[sorbs_smtp](#sorbs_smtp)|10|10|10|100.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2341|2341|10|0.4%|0.0%|
[php_harvesters](#php_harvesters)|298|298|8|2.6%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|8|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|7|0.0%|0.0%|
[proxyrss](#proxyrss)|1758|1758|6|0.3%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|486400|4|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|908|908|3|0.3%|0.0%|
[openbl_30d](#openbl_30d)|3261|3261|2|0.0%|0.0%|
[et_tor](#et_tor)|6380|6380|2|0.0%|0.0%|
[shunlist](#shunlist)|1229|1229|1|0.0%|0.0%|
[openbl_7d](#openbl_7d)|935|935|1|0.1%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|1|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|1|0.1%|0.0%|
[et_compromised](#et_compromised)|2171|2171|1|0.0%|0.0%|
[dshield](#dshield)|20|5120|1|0.0%|0.0%|
[dm_tor](#dm_tor)|6610|6610|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2039|2039|1|0.0%|0.0%|
[bm_tor](#bm_tor)|6624|6624|1|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|175|175|1|0.5%|0.0%|

## sorbs_web

[Sorbs.net](https://www.sorbs.net/) WEB exploits, extracted from deltas.

Source is downloaded from [this link]().

The last time downloaded was found to be dated: Thu Jun  4 21:04:16 UTC 2015.

The ipset `sorbs_web` has **730** entries, **732** unique IPs.

The following table shows the overlaps of `sorbs_web` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `sorbs_web`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `sorbs_web`.
- ` this % ` is the percentage **of this ipset (`sorbs_web`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[sorbs_spam](#sorbs_spam)|25175|26038|314|1.2%|42.8%|
[sorbs_recent_spam](#sorbs_recent_spam)|20387|21001|285|1.3%|38.9%|
[sorbs_new_spam](#sorbs_new_spam)|20387|21001|285|1.3%|38.9%|
[nixspam](#nixspam)|21252|21252|155|0.7%|21.1%|
[blocklist_de](#blocklist_de)|35206|35206|93|0.2%|12.7%|
[blocklist_de_mail](#blocklist_de_mail)|16874|16874|79|0.4%|10.7%|
[stopforumspam_30d](#stopforumspam_30d)|92996|92996|67|0.0%|9.1%|
[snort_ipfilter](#snort_ipfilter)|9591|9591|59|0.6%|8.0%|
[stopforumspam_7d](#stopforumspam_7d)|30334|30334|49|0.1%|6.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|45|0.0%|6.1%|
[php_dictionary](#php_dictionary)|475|475|31|6.5%|4.2%|
[ri_web_proxies](#ri_web_proxies)|6246|6246|28|0.4%|3.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|28|0.0%|3.8%|
[xroxy](#xroxy)|2072|2072|27|1.3%|3.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|26|0.0%|3.5%|
[php_spammers](#php_spammers)|461|461|24|5.2%|3.2%|
[stopforumspam_1d](#stopforumspam_1d)|7043|7043|23|0.3%|3.1%|
[proxz](#proxz)|733|733|12|1.6%|1.6%|
[blocklist_de_bots](#blocklist_de_bots)|3178|3178|10|0.3%|1.3%|
[sorbs_socks](#sorbs_socks)|28|28|5|17.8%|0.6%|
[sorbs_misc](#sorbs_misc)|28|28|5|17.8%|0.6%|
[sorbs_http](#sorbs_http)|28|28|5|17.8%|0.6%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2582|2582|3|0.1%|0.4%|
[blocklist_de_apache](#blocklist_de_apache)|13937|13937|3|0.0%|0.4%|
[ri_connect_proxies](#ri_connect_proxies)|2341|2341|2|0.0%|0.2%|
[php_commenters](#php_commenters)|301|301|2|0.6%|0.2%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|1|0.0%|0.1%|
[proxyrss](#proxyrss)|1758|1758|1|0.0%|0.1%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1|0.0%|0.1%|
[et_block](#et_block)|1007|18338646|1|0.0%|0.1%|
[blocklist_de_strongips](#blocklist_de_strongips)|175|175|1|0.5%|0.1%|
[blocklist_de_ssh](#blocklist_de_ssh)|11179|11179|1|0.0%|0.1%|
[blocklist_de_imap](#blocklist_de_imap)|2837|2837|1|0.0%|0.1%|

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
[alienvault_reputation](#alienvault_reputation)|182510|182510|1885|1.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1037|0.3%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92996|92996|1014|1.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|486400|512|0.1%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|30334|30334|336|1.1%|0.0%|
[dshield](#dshield)|20|5120|256|5.0%|0.0%|
[openbl_60d](#openbl_60d)|7699|7699|239|3.1%|0.0%|
[nixspam](#nixspam)|21252|21252|190|0.8%|0.0%|
[blocklist_de](#blocklist_de)|35206|35206|162|0.4%|0.0%|
[openbl_30d](#openbl_30d)|3261|3261|159|4.8%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|11179|11179|111|0.9%|0.0%|
[et_compromised](#et_compromised)|2171|2171|100|4.6%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2039|2039|100|4.9%|0.0%|
[shunlist](#shunlist)|1229|1229|98|7.9%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7043|7043|76|1.0%|0.0%|
[openbl_7d](#openbl_7d)|935|935|57|6.0%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|29|2.2%|0.0%|
[php_commenters](#php_commenters)|301|301|26|8.6%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3178|3178|25|0.7%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|16874|16874|22|0.1%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9591|9591|20|0.2%|0.0%|
[zeus_badips](#zeus_badips)|234|234|16|6.8%|0.0%|
[zeus](#zeus)|268|268|16|5.9%|0.0%|
[voipbl](#voipbl)|10426|10837|14|0.1%|0.0%|
[sorbs_spam](#sorbs_spam)|25175|26038|12|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2837|2837|12|0.4%|0.0%|
[openbl_1d](#openbl_1d)|182|182|11|6.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|20387|21001|7|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|20387|21001|7|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|6|0.4%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|6|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|175|175|5|2.8%|0.0%|
[php_dictionary](#php_dictionary)|475|475|4|0.8%|0.0%|
[malc0de](#malc0de)|379|379|4|1.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2582|2582|4|0.1%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13937|13937|4|0.0%|0.0%|
[php_spammers](#php_spammers)|461|461|3|0.6%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|2|0.2%|0.0%|
[et_tor](#et_tor)|6380|6380|2|0.0%|0.0%|
[dm_tor](#dm_tor)|6610|6610|2|0.0%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|370|370|2|0.5%|0.0%|
[bm_tor](#bm_tor)|6624|6624|2|0.0%|0.0%|
[sslbl](#sslbl)|365|365|1|0.2%|0.0%|
[sorbs_web](#sorbs_web)|730|732|1|0.1%|0.0%|
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
[stopforumspam_30d](#stopforumspam_30d)|92996|92996|96|0.1%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|30334|30334|21|0.0%|0.0%|
[alienvault_reputation](#alienvault_reputation)|182510|182510|15|0.0%|0.0%|
[blocklist_de](#blocklist_de)|35206|35206|10|0.0%|0.0%|
[php_commenters](#php_commenters)|301|301|7|2.3%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9591|9591|6|0.0%|0.0%|
[zeus_badips](#zeus_badips)|234|234|5|2.1%|0.0%|
[zeus](#zeus)|268|268|5|1.8%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|175|175|5|2.8%|0.0%|
[sorbs_spam](#sorbs_spam)|25175|26038|4|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3178|3178|4|0.1%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7043|7043|3|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|20387|21001|3|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|20387|21001|3|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|16874|16874|2|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13937|13937|2|0.0%|0.0%|
[php_harvesters](#php_harvesters)|298|298|1|0.3%|0.0%|
[openbl_60d](#openbl_60d)|7699|7699|1|0.0%|0.0%|
[openbl_30d](#openbl_30d)|3261|3261|1|0.0%|0.0%|
[nixspam](#nixspam)|21252|21252|1|0.0%|0.0%|
[malc0de](#malc0de)|379|379|1|0.2%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|11179|11179|1|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2837|2837|1|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|908|908|1|0.1%|0.0%|

## sslbl

[Abuse.ch SSL Blacklist](https://sslbl.abuse.ch/) bad SSL traffic related to malware or botnet activities - **excellent list**

Source is downloaded from [this link](https://sslbl.abuse.ch/blacklist/sslipblacklist.csv).

The last time downloaded was found to be dated: Thu Jun  4 21:15:06 UTC 2015.

The ipset `sslbl` has **365** entries, **365** unique IPs.

The following table shows the overlaps of `sslbl` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `sslbl`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `sslbl`.
- ` this % ` is the percentage **of this ipset (`sslbl`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[alienvault_reputation](#alienvault_reputation)|182510|182510|64|0.0%|17.5%|
[shunlist](#shunlist)|1229|1229|56|4.5%|15.3%|
[feodo](#feodo)|94|94|34|36.1%|9.3%|
[et_block](#et_block)|1007|18338646|32|0.0%|8.7%|
[snort_ipfilter](#snort_ipfilter)|9591|9591|28|0.2%|7.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|23|0.0%|6.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|6|0.0%|1.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|4|0.0%|1.0%|
[stopforumspam_30d](#stopforumspam_30d)|92996|92996|1|0.0%|0.2%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|1|0.0%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.2%|
[blocklist_de_ssh](#blocklist_de_ssh)|11179|11179|1|0.0%|0.2%|
[blocklist_de](#blocklist_de)|35206|35206|1|0.0%|0.2%|

## stopforumspam_1d

[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers in the last 24 hours - **excellent list**

Source is downloaded from [this link](http://www.stopforumspam.com/downloads/listed_ip_1.zip).

The last time downloaded was found to be dated: Thu Jun  4 21:00:02 UTC 2015.

The ipset `stopforumspam_1d` has **7043** entries, **7043** unique IPs.

The following table shows the overlaps of `stopforumspam_1d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `stopforumspam_1d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `stopforumspam_1d`.
- ` this % ` is the percentage **of this ipset (`stopforumspam_1d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_30d](#stopforumspam_30d)|92996|92996|4600|4.9%|65.3%|
[stopforumspam_7d](#stopforumspam_7d)|30334|30334|4232|13.9%|60.0%|
[blocklist_de](#blocklist_de)|35206|35206|1461|4.1%|20.7%|
[blocklist_de_bots](#blocklist_de_bots)|3178|3178|1377|43.3%|19.5%|
[ri_web_proxies](#ri_web_proxies)|6246|6246|529|8.4%|7.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|464|0.0%|6.5%|
[proxyrss](#proxyrss)|1758|1758|429|24.4%|6.0%|
[snort_ipfilter](#snort_ipfilter)|9591|9591|388|4.0%|5.5%|
[et_tor](#et_tor)|6380|6380|338|5.2%|4.7%|
[dm_tor](#dm_tor)|6610|6610|333|5.0%|4.7%|
[bm_tor](#bm_tor)|6624|6624|333|5.0%|4.7%|
[xroxy](#xroxy)|2072|2072|297|14.3%|4.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|237|0.0%|3.3%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|166|44.6%|2.3%|
[ri_connect_proxies](#ri_connect_proxies)|2341|2341|160|6.8%|2.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|145|0.0%|2.0%|
[proxz](#proxz)|733|733|128|17.4%|1.8%|
[php_commenters](#php_commenters)|301|301|118|39.2%|1.6%|
[blocklist_de_strongips](#blocklist_de_strongips)|175|175|102|58.2%|1.4%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|76|0.0%|1.0%|
[et_block](#et_block)|1007|18338646|76|0.0%|1.0%|
[nixspam](#nixspam)|21252|21252|74|0.3%|1.0%|
[blocklist_de_apache](#blocklist_de_apache)|13937|13937|73|0.5%|1.0%|
[blocklist_de_mail](#blocklist_de_mail)|16874|16874|61|0.3%|0.8%|
[sorbs_spam](#sorbs_spam)|25175|26038|60|0.2%|0.8%|
[sorbs_recent_spam](#sorbs_recent_spam)|20387|21001|60|0.2%|0.8%|
[sorbs_new_spam](#sorbs_new_spam)|20387|21001|60|0.2%|0.8%|
[alienvault_reputation](#alienvault_reputation)|182510|182510|60|0.0%|0.8%|
[php_harvesters](#php_harvesters)|298|298|36|12.0%|0.5%|
[php_spammers](#php_spammers)|461|461|31|6.7%|0.4%|
[php_dictionary](#php_dictionary)|475|475|26|5.4%|0.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|24|0.0%|0.3%|
[sorbs_web](#sorbs_web)|730|732|23|3.1%|0.3%|
[openbl_60d](#openbl_60d)|7699|7699|21|0.2%|0.2%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2582|2582|21|0.8%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|10|0.0%|0.1%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|6|0.8%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|11179|11179|6|0.0%|0.0%|
[voipbl](#voipbl)|10426|10837|5|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|486400|3|0.0%|0.0%|
[sorbs_socks](#sorbs_socks)|28|28|2|7.1%|0.0%|
[sorbs_misc](#sorbs_misc)|28|28|2|7.1%|0.0%|
[sorbs_http](#sorbs_http)|28|28|2|7.1%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2039|2039|2|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|908|908|2|0.2%|0.0%|
[zeus_badips](#zeus_badips)|234|234|1|0.4%|0.0%|
[zeus](#zeus)|268|268|1|0.3%|0.0%|
[shunlist](#shunlist)|1229|1229|1|0.0%|0.0%|
[openbl_30d](#openbl_30d)|3261|3261|1|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1|0.0%|0.0%|
[et_compromised](#et_compromised)|2171|2171|1|0.0%|0.0%|
[dshield](#dshield)|20|5120|1|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2837|2837|1|0.0%|0.0%|

## stopforumspam_30d

[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 30 days)

Source is downloaded from [this link](http://www.stopforumspam.com/downloads/listed_ip_30.zip).

The last time downloaded was found to be dated: Thu Jun  4 00:00:36 UTC 2015.

The ipset `stopforumspam_30d` has **92996** entries, **92996** unique IPs.

The following table shows the overlaps of `stopforumspam_30d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `stopforumspam_30d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `stopforumspam_30d`.
- ` this % ` is the percentage **of this ipset (`stopforumspam_30d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_7d](#stopforumspam_7d)|30334|30334|30222|99.6%|32.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|5857|0.0%|6.2%|
[stopforumspam_1d](#stopforumspam_1d)|7043|7043|4600|65.3%|4.9%|
[ri_web_proxies](#ri_web_proxies)|6246|6246|3010|48.1%|3.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|2521|0.0%|2.7%|
[blocklist_de](#blocklist_de)|35206|35206|2469|7.0%|2.6%|
[blocklist_de_bots](#blocklist_de_bots)|3178|3178|2063|64.9%|2.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|1551|0.0%|1.6%|
[ri_connect_proxies](#ri_connect_proxies)|2341|2341|1354|57.8%|1.4%|
[xroxy](#xroxy)|2072|2072|1212|58.4%|1.3%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|1014|0.0%|1.0%|
[et_block](#et_block)|1007|18338646|1014|0.0%|1.0%|
[proxyrss](#proxyrss)|1758|1758|839|47.7%|0.9%|
[snort_ipfilter](#snort_ipfilter)|9591|9591|810|8.4%|0.8%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|756|0.0%|0.8%|
[et_tor](#et_tor)|6380|6380|636|9.9%|0.6%|
[bm_tor](#bm_tor)|6624|6624|625|9.4%|0.6%|
[dm_tor](#dm_tor)|6610|6610|624|9.4%|0.6%|
[proxz](#proxz)|733|733|436|59.4%|0.4%|
[sorbs_spam](#sorbs_spam)|25175|26038|311|1.1%|0.3%|
[sorbs_recent_spam](#sorbs_recent_spam)|20387|21001|266|1.2%|0.2%|
[sorbs_new_spam](#sorbs_new_spam)|20387|21001|266|1.2%|0.2%|
[blocklist_de_mail](#blocklist_de_mail)|16874|16874|262|1.5%|0.2%|
[nixspam](#nixspam)|21252|21252|242|1.1%|0.2%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|233|62.6%|0.2%|
[php_commenters](#php_commenters)|301|301|220|73.0%|0.2%|
[alienvault_reputation](#alienvault_reputation)|182510|182510|220|0.1%|0.2%|
[blocklist_de_apache](#blocklist_de_apache)|13937|13937|209|1.4%|0.2%|
[blocklist_de_strongips](#blocklist_de_strongips)|175|175|130|74.2%|0.1%|
[php_spammers](#php_spammers)|461|461|103|22.3%|0.1%|
[spamhaus_edrop](#spamhaus_edrop)|55|486400|96|0.0%|0.1%|
[php_dictionary](#php_dictionary)|475|475|90|18.9%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|11179|11179|84|0.7%|0.0%|
[sorbs_web](#sorbs_web)|730|732|67|9.1%|0.0%|
[php_harvesters](#php_harvesters)|298|298|67|22.4%|0.0%|
[openbl_60d](#openbl_60d)|7699|7699|56|0.7%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|48|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2582|2582|39|1.5%|0.0%|
[voipbl](#voipbl)|10426|10837|38|0.3%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|22|3.2%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|15|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|908|908|12|1.3%|0.0%|
[et_compromised](#et_compromised)|2171|2171|10|0.4%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2039|2039|10|0.4%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2837|2837|9|0.3%|0.0%|
[shunlist](#shunlist)|1229|1229|4|0.3%|0.0%|
[openbl_30d](#openbl_30d)|3261|3261|4|0.1%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|4|0.3%|0.0%|
[zeus_badips](#zeus_badips)|234|234|3|1.2%|0.0%|
[zeus](#zeus)|268|268|3|1.1%|0.0%|
[openbl_7d](#openbl_7d)|935|935|3|0.3%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|370|370|3|0.8%|0.0%|
[sorbs_socks](#sorbs_socks)|28|28|2|7.1%|0.0%|
[sorbs_misc](#sorbs_misc)|28|28|2|7.1%|0.0%|
[sorbs_http](#sorbs_http)|28|28|2|7.1%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.0%|
[fullbogons](#fullbogons)|3733|670419608|2|0.0%|0.0%|
[sslbl](#sslbl)|365|365|1|0.2%|0.0%|
[dshield](#dshield)|20|5120|1|0.0%|0.0%|
[ciarmy](#ciarmy)|359|359|1|0.2%|0.0%|
[bogons](#bogons)|13|592708608|1|0.0%|0.0%|

## stopforumspam_7d

[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 7 days)

Source is downloaded from [this link](http://www.stopforumspam.com/downloads/listed_ip_7.zip).

The last time downloaded was found to be dated: Thu Jun  4 01:02:49 UTC 2015.

The ipset `stopforumspam_7d` has **30334** entries, **30334** unique IPs.

The following table shows the overlaps of `stopforumspam_7d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `stopforumspam_7d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `stopforumspam_7d`.
- ` this % ` is the percentage **of this ipset (`stopforumspam_7d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_30d](#stopforumspam_30d)|92996|92996|30222|32.4%|99.6%|
[stopforumspam_1d](#stopforumspam_1d)|7043|7043|4232|60.0%|13.9%|
[blocklist_de](#blocklist_de)|35206|35206|2078|5.9%|6.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|1930|0.0%|6.3%|
[blocklist_de_bots](#blocklist_de_bots)|3178|3178|1874|58.9%|6.1%|
[ri_web_proxies](#ri_web_proxies)|6246|6246|1682|26.9%|5.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|908|0.0%|2.9%|
[xroxy](#xroxy)|2072|2072|907|43.7%|2.9%|
[ri_connect_proxies](#ri_connect_proxies)|2341|2341|690|29.4%|2.2%|
[proxyrss](#proxyrss)|1758|1758|669|38.0%|2.2%|
[snort_ipfilter](#snort_ipfilter)|9591|9591|618|6.4%|2.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|571|0.0%|1.8%|
[et_tor](#et_tor)|6380|6380|499|7.8%|1.6%|
[bm_tor](#bm_tor)|6624|6624|484|7.3%|1.5%|
[dm_tor](#dm_tor)|6610|6610|483|7.3%|1.5%|
[proxz](#proxz)|733|733|363|49.5%|1.1%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|336|0.0%|1.1%|
[et_block](#et_block)|1007|18338646|335|0.0%|1.1%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|194|52.1%|0.6%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|186|0.0%|0.6%|
[sorbs_spam](#sorbs_spam)|25175|26038|174|0.6%|0.5%|
[php_commenters](#php_commenters)|301|301|158|52.4%|0.5%|
[nixspam](#nixspam)|21252|21252|156|0.7%|0.5%|
[sorbs_recent_spam](#sorbs_recent_spam)|20387|21001|155|0.7%|0.5%|
[sorbs_new_spam](#sorbs_new_spam)|20387|21001|155|0.7%|0.5%|
[blocklist_de_mail](#blocklist_de_mail)|16874|16874|154|0.9%|0.5%|
[blocklist_de_apache](#blocklist_de_apache)|13937|13937|129|0.9%|0.4%|
[blocklist_de_strongips](#blocklist_de_strongips)|175|175|117|66.8%|0.3%|
[alienvault_reputation](#alienvault_reputation)|182510|182510|108|0.0%|0.3%|
[php_dictionary](#php_dictionary)|475|475|61|12.8%|0.2%|
[php_spammers](#php_spammers)|461|461|60|13.0%|0.1%|
[php_harvesters](#php_harvesters)|298|298|53|17.7%|0.1%|
[sorbs_web](#sorbs_web)|730|732|49|6.6%|0.1%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2582|2582|29|1.1%|0.0%|
[openbl_60d](#openbl_60d)|7699|7699|25|0.3%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|23|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|486400|21|0.0%|0.0%|
[voipbl](#voipbl)|10426|10837|13|0.1%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|12|1.7%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|11179|11179|12|0.1%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|6|0.0%|0.0%|
[et_compromised](#et_compromised)|2171|2171|6|0.2%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2039|2039|6|0.2%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|908|908|6|0.6%|0.0%|
[shunlist](#shunlist)|1229|1229|3|0.2%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|3|0.2%|0.0%|
[sorbs_socks](#sorbs_socks)|28|28|2|7.1%|0.0%|
[sorbs_misc](#sorbs_misc)|28|28|2|7.1%|0.0%|
[sorbs_http](#sorbs_http)|28|28|2|7.1%|0.0%|
[zeus_badips](#zeus_badips)|234|234|1|0.4%|0.0%|
[zeus](#zeus)|268|268|1|0.3%|0.0%|
[openbl_30d](#openbl_30d)|3261|3261|1|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|
[dshield](#dshield)|20|5120|1|0.0%|0.0%|
[ciarmy](#ciarmy)|359|359|1|0.2%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2837|2837|1|0.0%|0.0%|

## virbl

[VirBL](http://virbl.bit.nl/) is a project of which the idea was born during the RIPE-48 meeting. The plan was to get reports of virusscanning mailservers, and put the IP-addresses that were reported to send viruses on a blacklist.

Source is downloaded from [this link](http://virbl.bit.nl/download/virbl.dnsbl.bit.nl.txt).

The last time downloaded was found to be dated: Thu Jun  4 20:52:04 UTC 2015.

The ipset `virbl` has **11** entries, **11** unique IPs.

The following table shows the overlaps of `virbl` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `virbl`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `virbl`.
- ` this % ` is the percentage **of this ipset (`virbl`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[alienvault_reputation](#alienvault_reputation)|182510|182510|2|0.0%|18.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|1|0.0%|9.0%|

## voipbl

[VoIPBL.org](http://www.voipbl.org/) a distributed VoIP blacklist that is aimed to protects against VoIP Fraud and minimizing abuse for network that have publicly accessible PBX's. Several algorithms, external sources and manual confirmation are used before they categorize something as an attack and determine the threat level.

Source is downloaded from [this link](http://www.voipbl.org/update/).

The last time downloaded was found to be dated: Thu Jun  4 19:45:17 UTC 2015.

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
[alienvault_reputation](#alienvault_reputation)|182510|182510|203|0.1%|1.8%|
[blocklist_de](#blocklist_de)|35206|35206|47|0.1%|0.4%|
[blocklist_de_sip](#blocklist_de_sip)|105|105|39|37.1%|0.3%|
[stopforumspam_30d](#stopforumspam_30d)|92996|92996|38|0.0%|0.3%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|14|0.0%|0.1%|
[et_block](#et_block)|1007|18338646|14|0.0%|0.1%|
[stopforumspam_7d](#stopforumspam_7d)|30334|30334|13|0.0%|0.1%|
[shunlist](#shunlist)|1229|1229|12|0.9%|0.1%|
[openbl_60d](#openbl_60d)|7699|7699|8|0.1%|0.0%|
[ciarmy](#ciarmy)|359|359|6|1.6%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7043|7043|5|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|4|0.0%|0.0%|
[dshield](#dshield)|20|5120|4|0.0%|0.0%|
[openbl_30d](#openbl_30d)|3261|3261|3|0.0%|0.0%|
[dm_tor](#dm_tor)|6610|6610|3|0.0%|0.0%|
[bm_tor](#bm_tor)|6624|6624|3|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|11179|11179|3|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13937|13937|3|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|2|0.0%|0.0%|
[et_tor](#et_tor)|6380|6380|2|0.0%|0.0%|
[et_compromised](#et_compromised)|2171|2171|2|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2039|2039|2|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9591|9591|1|0.0%|0.0%|
[openbl_7d](#openbl_7d)|935|935|1|0.1%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|16874|16874|1|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2837|2837|1|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2582|2582|1|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3178|3178|1|0.0%|0.0%|

## xroxy

[xroxy.com](http://www.xroxy.com) open proxies (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.xroxy.com/proxyrss.xml).

The last time downloaded was found to be dated: Thu Jun  4 21:33:01 UTC 2015.

The ipset `xroxy` has **2072** entries, **2072** unique IPs.

The following table shows the overlaps of `xroxy` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `xroxy`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `xroxy`.
- ` this % ` is the percentage **of this ipset (`xroxy`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_30d](#stopforumspam_30d)|92996|92996|1212|1.3%|58.4%|
[stopforumspam_7d](#stopforumspam_7d)|30334|30334|907|2.9%|43.7%|
[ri_web_proxies](#ri_web_proxies)|6246|6246|878|14.0%|42.3%|
[proxyrss](#proxyrss)|1758|1758|443|25.1%|21.3%|
[ri_connect_proxies](#ri_connect_proxies)|2341|2341|354|15.1%|17.0%|
[proxz](#proxz)|733|733|306|41.7%|14.7%|
[stopforumspam_1d](#stopforumspam_1d)|7043|7043|297|4.2%|14.3%|
[blocklist_de](#blocklist_de)|35206|35206|270|0.7%|13.0%|
[blocklist_de_bots](#blocklist_de_bots)|3178|3178|214|6.7%|10.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|99|0.0%|4.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|92|0.0%|4.4%|
[sorbs_spam](#sorbs_spam)|25175|26038|81|0.3%|3.9%|
[sorbs_recent_spam](#sorbs_recent_spam)|20387|21001|79|0.3%|3.8%|
[sorbs_new_spam](#sorbs_new_spam)|20387|21001|79|0.3%|3.8%|
[nixspam](#nixspam)|21252|21252|79|0.3%|3.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|57|0.0%|2.7%|
[blocklist_de_mail](#blocklist_de_mail)|16874|16874|54|0.3%|2.6%|
[snort_ipfilter](#snort_ipfilter)|9591|9591|50|0.5%|2.4%|
[sorbs_web](#sorbs_web)|730|732|27|3.6%|1.3%|
[php_dictionary](#php_dictionary)|475|475|27|5.6%|1.3%|
[php_spammers](#php_spammers)|461|461|22|4.7%|1.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|13|1.9%|0.6%|
[php_commenters](#php_commenters)|301|301|6|1.9%|0.2%|
[blocklist_de_strongips](#blocklist_de_strongips)|175|175|6|3.4%|0.2%|
[alienvault_reputation](#alienvault_reputation)|182510|182510|5|0.0%|0.2%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|3|0.0%|0.1%|
[php_harvesters](#php_harvesters)|298|298|2|0.6%|0.0%|
[et_tor](#et_tor)|6380|6380|2|0.0%|0.0%|
[dm_tor](#dm_tor)|6610|6610|2|0.0%|0.0%|
[bm_tor](#bm_tor)|6624|6624|2|0.0%|0.0%|
[sorbs_socks](#sorbs_socks)|28|28|1|3.5%|0.0%|
[sorbs_misc](#sorbs_misc)|28|28|1|3.5%|0.0%|
[sorbs_http](#sorbs_http)|28|28|1|3.5%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.0%|
[et_compromised](#et_compromised)|2171|2171|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2039|2039|1|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|11179|11179|1|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2582|2582|1|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13937|13937|1|0.0%|0.0%|

## zeus

[Abuse.ch Zeus tracker](https://zeustracker.abuse.ch) standard, contains the same data as the ZeuS IP blocklist (zeus_badips) but with the slight difference that it doesn't exclude hijacked websites (level 2) and free web hosting providers (level 3). This means that this blocklist contains all IPv4 addresses associated with ZeuS C&Cs which are currently being tracked by ZeuS Tracker. Hence this blocklist will likely cause some false positives. - **excellent list**

Source is downloaded from [this link](https://zeustracker.abuse.ch/blocklist.php?download=ipblocklist).

The last time downloaded was found to be dated: Thu Jun  4 21:03:47 UTC 2015.

The ipset `zeus` has **268** entries, **268** unique IPs.

The following table shows the overlaps of `zeus` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `zeus`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `zeus`.
- ` this % ` is the percentage **of this ipset (`zeus`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[et_block](#et_block)|1007|18338646|258|0.0%|96.2%|
[zeus_badips](#zeus_badips)|234|234|234|100.0%|87.3%|
[snort_ipfilter](#snort_ipfilter)|9591|9591|227|2.3%|84.7%|
[alienvault_reputation](#alienvault_reputation)|182510|182510|65|0.0%|24.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|20|0.0%|7.4%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|16|0.0%|5.9%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|10|0.0%|3.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|9|0.0%|3.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|6|0.0%|2.2%|
[spamhaus_edrop](#spamhaus_edrop)|55|486400|5|0.0%|1.8%|
[stopforumspam_30d](#stopforumspam_30d)|92996|92996|3|0.0%|1.1%|
[openbl_60d](#openbl_60d)|7699|7699|2|0.0%|0.7%|
[openbl_30d](#openbl_30d)|3261|3261|2|0.0%|0.7%|
[stopforumspam_7d](#stopforumspam_7d)|30334|30334|1|0.0%|0.3%|
[stopforumspam_1d](#stopforumspam_1d)|7043|7043|1|0.0%|0.3%|
[php_commenters](#php_commenters)|301|301|1|0.3%|0.3%|
[nixspam](#nixspam)|21252|21252|1|0.0%|0.3%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.3%|

## zeus_badips

[Abuse.ch Zeus tracker](https://zeustracker.abuse.ch) badips includes IPv4 addresses that are used by the ZeuS trojan. It is the recommened blocklist if you want to block only ZeuS IPs. It excludes IP addresses that ZeuS Tracker believes to be hijacked (level 2) or belong to a free web hosting provider (level 3). Hence the false postive rate should be much lower compared to the standard ZeuS IP blocklist. **excellent list**

Source is downloaded from [this link](https://zeustracker.abuse.ch/blocklist.php?download=badips).

The last time downloaded was found to be dated: Thu Jun  4 21:09:08 UTC 2015.

The ipset `zeus_badips` has **234** entries, **234** unique IPs.

The following table shows the overlaps of `zeus_badips` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `zeus_badips`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `zeus_badips`.
- ` this % ` is the percentage **of this ipset (`zeus_badips`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[zeus](#zeus)|268|268|234|87.3%|100.0%|
[et_block](#et_block)|1007|18338646|230|0.0%|98.2%|
[snort_ipfilter](#snort_ipfilter)|9591|9591|205|2.1%|87.6%|
[alienvault_reputation](#alienvault_reputation)|182510|182510|38|0.0%|16.2%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|16|0.0%|6.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|14|0.0%|5.9%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|10|0.0%|4.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|8|0.0%|3.4%|
[spamhaus_edrop](#spamhaus_edrop)|55|486400|5|0.0%|2.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|4|0.0%|1.7%|
[stopforumspam_30d](#stopforumspam_30d)|92996|92996|3|0.0%|1.2%|
[stopforumspam_7d](#stopforumspam_7d)|30334|30334|1|0.0%|0.4%|
[stopforumspam_1d](#stopforumspam_1d)|7043|7043|1|0.0%|0.4%|
[php_commenters](#php_commenters)|301|301|1|0.3%|0.4%|
[openbl_60d](#openbl_60d)|7699|7699|1|0.0%|0.4%|
[openbl_30d](#openbl_30d)|3261|3261|1|0.0%|0.4%|
[nixspam](#nixspam)|21252|21252|1|0.0%|0.4%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.4%|
