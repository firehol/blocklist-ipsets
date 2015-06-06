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

The following list was automatically generated on Sat Jun  6 18:55:08 UTC 2015.

The update frequency is the maximum allowed by internal configuration. A list will never be downloaded sooner than the update frequency stated. A list may also not be downloaded, after this frequency expired, if it has not been modified on the server (as reported by HTTP `IF_MODIFIED_SINCE` method).

name|info|type|entries|update|
:--:|:--:|:--:|:-----:|:----:|
[alienvault_reputation](#alienvault_reputation)|[AlienVault.com](https://www.alienvault.com/) IP reputation database (this list seems to include port scanning hosts and to be updated regularly, but we found no information about its retention policy)|ipv4 hash:ip|182275 unique IPs|updated every 6 hours  from [this link](https://reputation.alienvault.com/reputation.generic)
[blocklist_de](#blocklist_de)|[Blocklist.de](https://www.blocklist.de/) IPs that have been detected by fail2ban in the last 48 hours - **excellent list**|ipv4 hash:ip|26256 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/all.txt)
[blocklist_de_apache](#blocklist_de_apache)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service Apache, Apache-DDOS, RFI-Attacks.|ipv4 hash:ip|15244 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/apache.txt)
[blocklist_de_bots](#blocklist_de_bots)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the RFI-Attacks, REG-Bots, IRC-Bots or BadBots (BadBots = he has posted a Spam-Comment on a open Forum or Wiki).|ipv4 hash:ip|2967 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/bots.txt)
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|[Blocklist.de](https://www.blocklist.de/) All IPs which attacks Joomlas, Wordpress and other Web-Logins with Brute-Force Logins.|ipv4 hash:ip|3893 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/bruteforcelogin.txt)
[blocklist_de_ftp](#blocklist_de_ftp)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours for attacks on the Service FTP.|ipv4 hash:ip|830 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/ftp.txt)
[blocklist_de_imap](#blocklist_de_imap)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours for attacks on the Service imap, sasl, pop3, etc.|ipv4 hash:ip|1605 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/imap.txt)
[blocklist_de_mail](#blocklist_de_mail)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service Mail, Postfix.|ipv4 hash:ip|16558 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/mail.txt)
[blocklist_de_sip](#blocklist_de_sip)|[Blocklist.de](https://www.blocklist.de/) All IP addresses that tried to login in a SIP, VOIP or Asterisk Server and are included in the IPs list from [infiltrated.net](www.infiltrated.net)|ipv4 hash:ip|91 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/sip.txt)
[blocklist_de_ssh](#blocklist_de_ssh)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service SSH.|ipv4 hash:ip|1659 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/ssh.txt)
[blocklist_de_strongips](#blocklist_de_strongips)|[Blocklist.de](https://www.blocklist.de/) All IPs which are older then 2 month and have more then 5.000 attacks.|ipv4 hash:ip|177 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/strongips.txt)
[bm_tor](#bm_tor)|[torstatus.blutmagie.de](https://torstatus.blutmagie.de) list of all TOR network servers|ipv4 hash:ip|6516 unique IPs|updated every 30 mins  from [this link](https://torstatus.blutmagie.de/ip_list_all.php/Tor_ip_list_ALL.csv)
[bogons](#bogons)|[Team-Cymru.org](http://www.team-cymru.org) private and reserved addresses defined by RFC 1918, RFC 5735, and RFC 6598 and netblocks that have not been allocated to a regional internet registry - **excellent list - use it only your internet interface**|ipv4 hash:net|13 subnets, 592708608 unique IPs|updated every 1 day  from [this link](http://www.team-cymru.org/Services/Bogons/bogon-bn-agg.txt)
[bruteforceblocker](#bruteforceblocker)|[danger.rulez.sk](http://danger.rulez.sk/) IPs detected by [bruteforceblocker](http://danger.rulez.sk/index.php/bruteforceblocker/) (fail2ban alternative for SSH on OpenBSD). This is an automatically generated list from users reporting failed authentication attempts. An IP seems to be included if 3 or more users report it. Its retention pocily seems 30 days.|ipv4 hash:ip|1821 unique IPs|updated every 3 hours  from [this link](http://danger.rulez.sk/projects/bruteforceblocker/blist.php)
[ciarmy](#ciarmy)|[CIArmy.com](http://ciarmy.com/) IPs with poor Rogue Packet score that have not yet been identified as malicious by the community|ipv4 hash:ip|412 unique IPs|updated every 3 hours  from [this link](http://cinsscore.com/list/ci-badguys.txt)
[cleanmx_viruses](#cleanmx_viruses)|[Clean-MX.de](http://support.clean-mx.de/clean-mx/viruses.php) IPs with viruses|ipv4 hash:ip|168 unique IPs|updated every 12 hours  from [this link](http://support.clean-mx.de/clean-mx/xmlviruses.php?sort=id%20desc&response=alive)
[dm_tor](#dm_tor)|[dan.me.uk](https://www.dan.me.uk) dynamic list of TOR exit points|ipv4 hash:ip|6512 unique IPs|updated every 30 mins  from [this link](https://www.dan.me.uk/torlist/)
[dshield](#dshield)|[DShield.org](https://dshield.org/) top 20 attacking class C (/24) subnets over the last three days - **excellent list**|ipv4 hash:net|19 subnets, 19,5120 unique IPs|updated every 4 hours  from [this link](http://feeds.dshield.org/block.txt)
[et_block](#et_block)|[EmergingThreats.net](http://www.emergingthreats.net/) default blacklist (at the time of writing includes spamhaus DROP, dshield and abuse.ch trackers, which are available separately too - prefer to use the direct ipsets instead of this, they seem to lag a bit in updates)|ipv4 hash:net|1023 subnets, 18338662 unique IPs|updated every 12 hours  from [this link](http://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt)
[et_botcc](#et_botcc)|[EmergingThreats.net Command and Control IPs](http://doc.emergingthreats.net/bin/view/Main/BotCC) These IPs are updates every 24 hours and should be considered VERY highly reliable indications that a host is communicating with a known and active Bot or Malware command and control server - (although they say this includes abuse.ch trackers, it does not - most probably it is the shadowserver.org C&C list)|ipv4 hash:ip|509 unique IPs|updated every 12 hours  from [this link](http://rules.emergingthreats.net/fwrules/emerging-PIX-CC.rules)
[et_compromised](#et_compromised)|[EmergingThreats.net compromised hosts](http://doc.emergingthreats.net/bin/view/Main/CompromisedHost) - (this seems to be based on bruteforceblocker)|ipv4 hash:ip|2016 unique IPs|updated every 12 hours  from [this link](http://rules.emergingthreats.net/blockrules/compromised-ips.txt)
et_dshield|[EmergingThreats.net](http://www.emergingthreats.net/) dshield blocklist|ipv4 hash:net|disabled|updated every 12 hours  from [this link](http://rules.emergingthreats.net/fwrules/emerging-PIX-DSHIELD.rules)
et_spamhaus|[EmergingThreats.net](http://www.emergingthreats.net/) spamhaus blocklist|ipv4 hash:net|disabled|updated every 12 hours  from [this link](http://rules.emergingthreats.net/fwrules/emerging-PIX-DROP.rules)
[et_tor](#et_tor)|[EmergingThreats.net](http://www.emergingthreats.net/) [list](http://doc.emergingthreats.net/bin/view/Main/TorRules) of TOR network IPs|ipv4 hash:ip|6470 unique IPs|updated every 12 hours  from [this link](http://rules.emergingthreats.net/blockrules/emerging-tor.rules)
[feodo](#feodo)|[Abuse.ch Feodo tracker](https://feodotracker.abuse.ch) trojan includes IPs which are being used by Feodo (also known as Cridex or Bugat) which commits ebanking fraud - **excellent list**|ipv4 hash:ip|99 unique IPs|updated every 30 mins  from [this link](https://feodotracker.abuse.ch/blocklist/?download=ipblocklist)
[fullbogons](#fullbogons)|[Team-Cymru.org](http://www.team-cymru.org) IP space that has been allocated to an RIR, but not assigned by that RIR to an actual ISP or other end-user - **excellent list - use it only your internet interface**|ipv4 hash:net|3721 subnets, 670267288 unique IPs|updated every 1 day  from [this link](http://www.team-cymru.org/Services/Bogons/fullbogons-ipv4.txt)
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
[malc0de](#malc0de)|[Malc0de.com](http://malc0de.com) malicious IPs of the last 30 days|ipv4 hash:ip|361 unique IPs|updated every 1 day  from [this link](http://malc0de.com/bl/IP_Blacklist.txt)
[malwaredomainlist](#malwaredomainlist)|[malwaredomainlist.com](http://www.malwaredomainlist.com) list of malware active ip addresses|ipv4 hash:ip|1288 unique IPs|updated every 12 hours  from [this link](http://www.malwaredomainlist.com/hostslist/ip.txt)
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|[MaxMind.com](https://www.maxmind.com/en/anonymous-proxy-fraudulent-ip-address-list) list of anonymous proxy fraudelent IP addresses.|ipv4 hash:ip|372 unique IPs|updated every 4 hours  from [this link](https://www.maxmind.com/en/anonymous-proxy-fraudulent-ip-address-list)
[nixspam](#nixspam)|[NiX Spam](http://www.heise.de/ix/NiX-Spam-DNSBL-and-blacklist-for-download-499637.html) IP addresses that sent spam in the last hour - automatically generated entries without distinguishing open proxies from relays, dialup gateways, and so on. All IPs are removed after 12 hours if there is no spam from there.|ipv4 hash:ip|19062 unique IPs|updated every 15 mins  from [this link](http://www.dnsbl.manitu.net/download/nixspam-ip.dump.gz)
openbl|[OpenBL.org](http://www.openbl.org/) default blacklist (currently it is the same with 90 days). OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications - **excellent list**|ipv4 hash:ip|disabled|updated every 4 hours  from [this link](http://www.openbl.org/lists/base.txt)
openbl_180d|[OpenBL.org](http://www.openbl.org/) last 180 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|disabled|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_180days.txt)
[openbl_1d](#openbl_1d)|[OpenBL.org](http://www.openbl.org/) last 24 hours IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|146 unique IPs|updated every 1 hour  from [this link](http://www.openbl.org/lists/base_1days.txt)
[openbl_30d](#openbl_30d)|[OpenBL.org](http://www.openbl.org/) last 30 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|3252 unique IPs|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_30days.txt)
openbl_360d|[OpenBL.org](http://www.openbl.org/) last 360 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|disabled|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_360days.txt)
[openbl_60d](#openbl_60d)|[OpenBL.org](http://www.openbl.org/) last 60 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|7286 unique IPs|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_60days.txt)
[openbl_7d](#openbl_7d)|[OpenBL.org](http://www.openbl.org/) last 7 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|843 unique IPs|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_7days.txt)
openbl_90d|[OpenBL.org](http://www.openbl.org/) last 90 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|disabled|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_90days.txt)
openbl_all|[OpenBL.org](http://www.openbl.org/) last all IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|disabled|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_all.txt)
[palevo](#palevo)|[Abuse.ch Palevo tracker](https://palevotracker.abuse.ch) worm includes IPs which are being used as botnet C&C for the Palevo crimeware - **excellent list**|ipv4 hash:ip|13 unique IPs|updated every 30 mins  from [this link](https://palevotracker.abuse.ch/blocklists.php?download=ipblocklist)
php_bad|[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) bad web hosts (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|disabled|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=b&rss=1)
[php_commenters](#php_commenters)|[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) comment spammers (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|349 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=c&rss=1)
[php_dictionary](#php_dictionary)|[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) directory attackers (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|545 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=d&rss=1)
[php_harvesters](#php_harvesters)|[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) harvesters (IPs that surf the internet looking for email addresses) (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|311 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=h&rss=1)
[php_spammers](#php_spammers)|[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) spam servers (IPs used by spammers to send messages) (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|536 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=s&rss=1)
[proxyrss](#proxyrss)|[proxyrss.com](http://www.proxyrss.com) open proxies syndicated from multiple sources.|ipv4 hash:ip|1416 unique IPs|updated every 4 hours  from [this link](http://www.proxyrss.com/proxylists/all.gz)
[proxz](#proxz)|[proxz.com](http://www.proxz.com) open proxies (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|906 unique IPs|updated every 1 hour  from [this link](http://www.proxz.com/proxylists.xml)
[ri_connect_proxies](#ri_connect_proxies)|[rosinstrument.com](http://www.rosinstrument.com) open CONNECT proxies (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|2475 unique IPs|updated every 1 hour  from [this link](http://tools.rosinstrument.com/proxy/plab100.xml)
[ri_web_proxies](#ri_web_proxies)|[rosinstrument.com](http://www.rosinstrument.com) open HTTP proxies (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|6664 unique IPs|updated every 1 hour  from [this link](http://tools.rosinstrument.com/proxy/l100.xml)
[shunlist](#shunlist)|[AutoShun.org](http://autoshun.org/) IPs identified as hostile by correlating logs from distributed snort installations running the autoshun plugin|ipv4 hash:ip|1215 unique IPs|updated every 4 hours  from [this link](http://www.autoshun.org/files/shunlist.csv)
[snort_ipfilter](#snort_ipfilter)|[labs.snort.org](https://labs.snort.org/) supplied IP blacklist (this list seems to be updated frequently, but we found no information about it)|ipv4 hash:ip|9943 unique IPs|updated every 12 hours  from [this link](http://labs.snort.org/feeds/ip-filter.blf)
[sorbs_dul](#sorbs_dul)|[Sorbs.net](https://www.sorbs.net/) DUL, Dynamic User IPs extracted from deltas.|ipv4 hash:net|8 subnets, 3584 unique IPs|updated every 1 min  from [this link]()
[sorbs_http](#sorbs_http)|[Sorbs.net](https://www.sorbs.net/) HTTP proxies, extracted from deltas.|ipv4 hash:net|22 subnets, 22,22 unique IPs|updated every 1 min  from [this link]()
[sorbs_misc](#sorbs_misc)|[Sorbs.net](https://www.sorbs.net/) MISC proxies, extracted from deltas.|ipv4 hash:net|22 subnets, 22,22 unique IPs|updated every 1 min  from [this link]()
[sorbs_new_spam](#sorbs_new_spam)|[Sorbs.net](https://www.sorbs.net/) NEW Spam senders, extracted from deltas.|ipv4 hash:net|31523 subnets, 31523,32638 unique IPs|updated every 1 min  from [this link]()
[sorbs_recent_spam](#sorbs_recent_spam)|[Sorbs.net](https://www.sorbs.net/) RECENT Spam senders, extracted from deltas.|ipv4 hash:net|31523 subnets, 31523,32638 unique IPs|updated every 1 min  from [this link]()
[sorbs_smtp](#sorbs_smtp)|[Sorbs.net](https://www.sorbs.net/) SMTP Open Relays, extracted from deltas.|ipv4 hash:net|14 subnets, 14,14 unique IPs|updated every 1 min  from [this link]()
[sorbs_socks](#sorbs_socks)|[Sorbs.net](https://www.sorbs.net/) SOCKS proxies, extracted from deltas.|ipv4 hash:net|22 subnets, 22,22 unique IPs|updated every 1 min  from [this link]()
[sorbs_spam](#sorbs_spam)|[Sorbs.net](https://www.sorbs.net/) Spam senders, extracted from deltas.|ipv4 hash:net|31523 subnets, 31523,32638 unique IPs|updated every 1 min  from [this link]()
[sorbs_web](#sorbs_web)|[Sorbs.net](https://www.sorbs.net/) WEB exploits, extracted from deltas.|ipv4 hash:net|693 subnets, 693,694 unique IPs|updated every 1 min  from [this link]()
[spamhaus_drop](#spamhaus_drop)|[Spamhaus.org](http://www.spamhaus.org) DROP list (according to their site this list should be dropped at tier-1 ISPs globaly) - **excellent list**|ipv4 hash:net|653 subnets, 18404096 unique IPs|updated every 12 hours  from [this link](http://www.spamhaus.org/drop/drop.txt)
[spamhaus_edrop](#spamhaus_edrop)|[Spamhaus.org](http://www.spamhaus.org) EDROP (extended matches that should be used with DROP) - **excellent list**|ipv4 hash:net|56 subnets, 487424 unique IPs|updated every 12 hours  from [this link](http://www.spamhaus.org/drop/edrop.txt)
[sslbl](#sslbl)|[Abuse.ch SSL Blacklist](https://sslbl.abuse.ch/) bad SSL traffic related to malware or botnet activities - **excellent list**|ipv4 hash:ip|369 unique IPs|updated every 30 mins  from [this link](https://sslbl.abuse.ch/blacklist/sslipblacklist.csv)
stopforumspam_180d|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 180 days)|ipv4 hash:ip|disabled|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/listed_ip_180.zip)
[stopforumspam_1d](#stopforumspam_1d)|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers in the last 24 hours - **excellent list**|ipv4 hash:ip|6675 unique IPs|updated every 1 hour  from [this link](http://www.stopforumspam.com/downloads/listed_ip_1.zip)
[stopforumspam_30d](#stopforumspam_30d)|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 30 days)|ipv4 hash:ip|93258 unique IPs|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/listed_ip_30.zip)
stopforumspam_365d|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 365 days)|ipv4 hash:ip|disabled|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/listed_ip_365.zip)
[stopforumspam_7d](#stopforumspam_7d)|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 7 days)|ipv4 hash:ip|30121 unique IPs|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/listed_ip_7.zip)
stopforumspam_90d|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 90 days)|ipv4 hash:ip|disabled|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/listed_ip_90.zip)
stopforumspam_ever|[StopForumSpam.com](http://www.stopforumspam.com) all IPs used by forum spammers, **ever** (normally you don't want to use this ipset, use the hourly one which includes last 24 hours IPs or the 7 days one)|ipv4 hash:ip|disabled|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/bannedips.zip)
[virbl](#virbl)|[VirBL](http://virbl.bit.nl/) is a project of which the idea was born during the RIPE-48 meeting. The plan was to get reports of virusscanning mailservers, and put the IP-addresses that were reported to send viruses on a blacklist.|ipv4 hash:ip|4 unique IPs|updated every 1 hour  from [this link](http://virbl.bit.nl/download/virbl.dnsbl.bit.nl.txt)
[voipbl](#voipbl)|[VoIPBL.org](http://www.voipbl.org/) a distributed VoIP blacklist that is aimed to protects against VoIP Fraud and minimizing abuse for network that have publicly accessible PBX's. Several algorithms, external sources and manual confirmation are used before they categorize something as an attack and determine the threat level.|ipv4 hash:net|10476 subnets, 10476,10888 unique IPs|updated every 4 hours  from [this link](http://www.voipbl.org/update/)
[xroxy](#xroxy)|[xroxy.com](http://www.xroxy.com) open proxies (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|2107 unique IPs|updated every 1 hour  from [this link](http://www.xroxy.com/proxyrss.xml)
[zeus](#zeus)|[Abuse.ch Zeus tracker](https://zeustracker.abuse.ch) standard, contains the same data as the ZeuS IP blocklist (zeus_badips) but with the slight difference that it doesn't exclude hijacked websites (level 2) and free web hosting providers (level 3). This means that this blocklist contains all IPv4 addresses associated with ZeuS C&Cs which are currently being tracked by ZeuS Tracker. Hence this blocklist will likely cause some false positives. - **excellent list**|ipv4 hash:ip|232 unique IPs|updated every 30 mins  from [this link](https://zeustracker.abuse.ch/blocklist.php?download=ipblocklist)
[zeus_badips](#zeus_badips)|[Abuse.ch Zeus tracker](https://zeustracker.abuse.ch) badips includes IPv4 addresses that are used by the ZeuS trojan. It is the recommened blocklist if you want to block only ZeuS IPs. It excludes IP addresses that ZeuS Tracker believes to be hijacked (level 2) or belong to a free web hosting provider (level 3). Hence the false postive rate should be much lower compared to the standard ZeuS IP blocklist. **excellent list**|ipv4 hash:ip|202 unique IPs|updated every 30 mins  from [this link](https://zeustracker.abuse.ch/blocklist.php?download=badips)

# Comparison of ipsets

Below we compare each ipset against all other.


## alienvault_reputation

[AlienVault.com](https://www.alienvault.com/) IP reputation database (this list seems to include port scanning hosts and to be updated regularly, but we found no information about its retention policy)

Source is downloaded from [this link](https://reputation.alienvault.com/reputation.generic).

The last time downloaded was found to be dated: Sat Jun  6 16:00:21 UTC 2015.

The ipset `alienvault_reputation` has **182275** entries, **182275** unique IPs.

The following table shows the overlaps of `alienvault_reputation` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `alienvault_reputation`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `alienvault_reputation`.
- ` this % ` is the percentage **of this ipset (`alienvault_reputation`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|14152|0.0%|7.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|7535|0.0%|4.1%|
[openbl_60d](#openbl_60d)|7286|7286|7266|99.7%|3.9%|
[et_block](#et_block)|1023|18338662|5262|0.0%|2.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|4688|0.0%|2.5%|
[dshield](#dshield)|19|19,5120|3572|69.7%|1.9%|
[openbl_30d](#openbl_30d)|3252|3252|3237|99.5%|1.7%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|1627|0.0%|0.8%|
[et_compromised](#et_compromised)|2016|2016|1313|65.1%|0.7%|
[shunlist](#shunlist)|1215|1215|1200|98.7%|0.6%|
[bruteforceblocker](#bruteforceblocker)|1821|1821|1177|64.6%|0.6%|
[blocklist_de](#blocklist_de)|26256|26256|1001|3.8%|0.5%|
[openbl_7d](#openbl_7d)|843|843|838|99.4%|0.4%|
[blocklist_de_ssh](#blocklist_de_ssh)|1659|1659|765|46.1%|0.4%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|516|0.0%|0.2%|
[ciarmy](#ciarmy)|412|412|407|98.7%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|286|0.0%|0.1%|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|205|0.2%|0.1%|
[voipbl](#voipbl)|10476|10476,10888|203|1.8%|0.1%|
[openbl_1d](#openbl_1d)|146|146|143|97.9%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|15244|15244|135|0.8%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9943|9943|119|1.1%|0.0%|
[sorbs_spam](#sorbs_spam)|31523|31523,32638|98|0.3%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|31523|31523,32638|98|0.3%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|31523|31523,32638|98|0.3%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|94|0.3%|0.0%|
[sslbl](#sslbl)|369|369|65|17.6%|0.0%|
[zeus](#zeus)|232|232|63|27.1%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|16558|16558|62|0.3%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6675|6675|51|0.7%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|1605|1605|43|2.6%|0.0%|
[et_tor](#et_tor)|6470|6470|42|0.6%|0.0%|
[dm_tor](#dm_tor)|6512|6512|42|0.6%|0.0%|
[bm_tor](#bm_tor)|6516|6516|42|0.6%|0.0%|
[zeus_badips](#zeus_badips)|202|202|38|18.8%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|177|177|37|20.9%|0.0%|
[nixspam](#nixspam)|19062|19062|34|0.1%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|2967|2967|29|0.9%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|26|6.9%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|3893|3893|23|0.5%|0.0%|
[php_commenters](#php_commenters)|349|349|17|4.8%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|91|91|16|17.5%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|15|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|15|0.0%|0.0%|
[malc0de](#malc0de)|361|361|11|3.0%|0.0%|
[php_harvesters](#php_harvesters)|311|311|10|3.2%|0.0%|
[php_dictionary](#php_dictionary)|545|545|8|1.4%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|8|0.5%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|168|168|7|4.1%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|6|0.4%|0.0%|
[php_spammers](#php_spammers)|536|536|5|0.9%|0.0%|
[et_botcc](#et_botcc)|509|509|5|0.9%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|830|830|5|0.6%|0.0%|
[xroxy](#xroxy)|2107|2107|4|0.1%|0.0%|
[ri_web_proxies](#ri_web_proxies)|6664|6664|3|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2475|2475|3|0.1%|0.0%|
[proxz](#proxz)|906|906|3|0.3%|0.0%|
[feodo](#feodo)|99|99|2|2.0%|0.0%|
[sorbs_web](#sorbs_web)|693|693,694|1|0.1%|0.0%|
[proxyrss](#proxyrss)|1416|1416|1|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|1|0.1%|0.0%|

## blocklist_de

[Blocklist.de](https://www.blocklist.de/) IPs that have been detected by fail2ban in the last 48 hours - **excellent list**

Source is downloaded from [this link](http://lists.blocklist.de/lists/all.txt).

The last time downloaded was found to be dated: Sat Jun  6 18:42:05 UTC 2015.

The ipset `blocklist_de` has **26256** entries, **26256** unique IPs.

The following table shows the overlaps of `blocklist_de` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de`.
- ` this % ` is the percentage **of this ipset (`blocklist_de`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de_mail](#blocklist_de_mail)|16558|16558|16558|100.0%|63.0%|
[blocklist_de_apache](#blocklist_de_apache)|15244|15244|15234|99.9%|58.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|3893|3893|3884|99.7%|14.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|3378|0.0%|12.8%|
[blocklist_de_bots](#blocklist_de_bots)|2967|2967|2962|99.8%|11.2%|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|2238|2.3%|8.5%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|1920|6.3%|7.3%|
[blocklist_de_ssh](#blocklist_de_ssh)|1659|1659|1659|100.0%|6.3%|
[blocklist_de_imap](#blocklist_de_imap)|1605|1605|1602|99.8%|6.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|1496|0.0%|5.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|1425|0.0%|5.4%|
[stopforumspam_1d](#stopforumspam_1d)|6675|6675|1221|18.2%|4.6%|
[alienvault_reputation](#alienvault_reputation)|182275|182275|1001|0.5%|3.8%|
[sorbs_spam](#sorbs_spam)|31523|31523,32638|951|2.9%|3.6%|
[sorbs_recent_spam](#sorbs_recent_spam)|31523|31523,32638|951|2.9%|3.6%|
[sorbs_new_spam](#sorbs_new_spam)|31523|31523,32638|951|2.9%|3.6%|
[blocklist_de_ftp](#blocklist_de_ftp)|830|830|827|99.6%|3.1%|
[openbl_60d](#openbl_60d)|7286|7286|745|10.2%|2.8%|
[openbl_30d](#openbl_30d)|3252|3252|691|21.2%|2.6%|
[et_compromised](#et_compromised)|2016|2016|619|30.7%|2.3%|
[bruteforceblocker](#bruteforceblocker)|1821|1821|613|33.6%|2.3%|
[openbl_7d](#openbl_7d)|843|843|412|48.8%|1.5%|
[nixspam](#nixspam)|19062|19062|390|2.0%|1.4%|
[ri_web_proxies](#ri_web_proxies)|6664|6664|370|5.5%|1.4%|
[shunlist](#shunlist)|1215|1215|355|29.2%|1.3%|
[xroxy](#xroxy)|2107|2107|218|10.3%|0.8%|
[et_block](#et_block)|1023|18338662|191|0.0%|0.7%|
[proxyrss](#proxyrss)|1416|1416|185|13.0%|0.7%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|177|0.0%|0.6%|
[blocklist_de_strongips](#blocklist_de_strongips)|177|177|177|100.0%|0.6%|
[snort_ipfilter](#snort_ipfilter)|9943|9943|159|1.5%|0.6%|
[proxz](#proxz)|906|906|136|15.0%|0.5%|
[openbl_1d](#openbl_1d)|146|146|123|84.2%|0.4%|
[php_spammers](#php_spammers)|536|536|93|17.3%|0.3%|
[php_dictionary](#php_dictionary)|545|545|88|16.1%|0.3%|
[php_commenters](#php_commenters)|349|349|86|24.6%|0.3%|
[sorbs_web](#sorbs_web)|693|693,694|73|10.5%|0.2%|
[blocklist_de_sip](#blocklist_de_sip)|91|91|72|79.1%|0.2%|
[ri_connect_proxies](#ri_connect_proxies)|2475|2475|64|2.5%|0.2%|
[dshield](#dshield)|19|19,5120|51|0.9%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|50|0.0%|0.1%|
[voipbl](#voipbl)|10476|10476,10888|35|0.3%|0.1%|
[ciarmy](#ciarmy)|412|412|35|8.4%|0.1%|
[php_harvesters](#php_harvesters)|311|311|32|10.2%|0.1%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|13|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|10|0.0%|0.0%|
[sorbs_socks](#sorbs_socks)|22|22,22|5|22.7%|0.0%|
[sorbs_misc](#sorbs_misc)|22|22,22|5|22.7%|0.0%|
[sorbs_http](#sorbs_http)|22|22,22|5|22.7%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|4|0.0%|0.0%|
[et_tor](#et_tor)|6470|6470|4|0.0%|0.0%|
[dm_tor](#dm_tor)|6512|6512|4|0.0%|0.0%|
[bm_tor](#bm_tor)|6516|6516|4|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|3|0.8%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|3|0.4%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.0%|
[sslbl](#sslbl)|369|369|1|0.2%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|168|168|1|0.5%|0.0%|

## blocklist_de_apache

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service Apache, Apache-DDOS, RFI-Attacks.

Source is downloaded from [this link](http://lists.blocklist.de/lists/apache.txt).

The last time downloaded was found to be dated: Sat Jun  6 18:28:05 UTC 2015.

The ipset `blocklist_de_apache` has **15244** entries, **15244** unique IPs.

The following table shows the overlaps of `blocklist_de_apache` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_apache`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_apache`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_apache`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|26256|26256|15234|58.0%|99.9%|
[blocklist_de_mail](#blocklist_de_mail)|16558|16558|11059|66.7%|72.5%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|3893|3893|3893|100.0%|25.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|2384|0.0%|15.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|1327|0.0%|8.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|1087|0.0%|7.1%|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|217|0.2%|1.4%|
[alienvault_reputation](#alienvault_reputation)|182275|182275|135|0.0%|0.8%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|129|0.4%|0.8%|
[sorbs_spam](#sorbs_spam)|31523|31523,32638|111|0.3%|0.7%|
[sorbs_recent_spam](#sorbs_recent_spam)|31523|31523,32638|111|0.3%|0.7%|
[sorbs_new_spam](#sorbs_new_spam)|31523|31523,32638|111|0.3%|0.7%|
[stopforumspam_1d](#stopforumspam_1d)|6675|6675|63|0.9%|0.4%|
[shunlist](#shunlist)|1215|1215|35|2.8%|0.2%|
[blocklist_de_strongips](#blocklist_de_strongips)|177|177|34|19.2%|0.2%|
[ciarmy](#ciarmy)|412|412|32|7.7%|0.2%|
[nixspam](#nixspam)|19062|19062|31|0.1%|0.2%|
[php_commenters](#php_commenters)|349|349|26|7.4%|0.1%|
[blocklist_de_bots](#blocklist_de_bots)|2967|2967|22|0.7%|0.1%|
[et_block](#et_block)|1023|18338662|13|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9943|9943|9|0.0%|0.0%|
[openbl_60d](#openbl_60d)|7286|7286|8|0.1%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|7|0.0%|0.0%|
[dshield](#dshield)|19|19,5120|7|0.1%|0.0%|
[php_spammers](#php_spammers)|536|536|6|1.1%|0.0%|
[openbl_30d](#openbl_30d)|3252|3252|6|0.1%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|5|0.0%|0.0%|
[php_harvesters](#php_harvesters)|311|311|5|1.6%|0.0%|
[php_dictionary](#php_dictionary)|545|545|4|0.7%|0.0%|
[et_tor](#et_tor)|6470|6470|4|0.0%|0.0%|
[dm_tor](#dm_tor)|6512|6512|4|0.0%|0.0%|
[bm_tor](#bm_tor)|6516|6516|4|0.0%|0.0%|
[voipbl](#voipbl)|10476|10476,10888|3|0.0%|0.0%|
[sorbs_web](#sorbs_web)|693|693,694|3|0.4%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|3|0.0%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|0.0%|
[openbl_7d](#openbl_7d)|843|843|2|0.2%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|2|0.5%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|1|0.0%|0.0%|
[et_compromised](#et_compromised)|2016|2016|1|0.0%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|168|168|1|0.5%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1821|1821|1|0.0%|0.0%|

## blocklist_de_bots

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the RFI-Attacks, REG-Bots, IRC-Bots or BadBots (BadBots = he has posted a Spam-Comment on a open Forum or Wiki).

Source is downloaded from [this link](http://lists.blocklist.de/lists/bots.txt).

The last time downloaded was found to be dated: Sat Jun  6 18:28:08 UTC 2015.

The ipset `blocklist_de_bots` has **2967** entries, **2967** unique IPs.

The following table shows the overlaps of `blocklist_de_bots` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_bots`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_bots`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_bots`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|26256|26256|2962|11.2%|99.8%|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|1910|2.0%|64.3%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|1741|5.7%|58.6%|
[stopforumspam_1d](#stopforumspam_1d)|6675|6675|1162|17.4%|39.1%|
[ri_web_proxies](#ri_web_proxies)|6664|6664|313|4.6%|10.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|200|0.0%|6.7%|
[proxyrss](#proxyrss)|1416|1416|184|12.9%|6.2%|
[xroxy](#xroxy)|2107|2107|179|8.4%|6.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|177|177|131|74.0%|4.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|120|0.0%|4.0%|
[proxz](#proxz)|906|906|116|12.8%|3.9%|
[php_commenters](#php_commenters)|349|349|70|20.0%|2.3%|
[ri_connect_proxies](#ri_connect_proxies)|2475|2475|61|2.4%|2.0%|
[sorbs_spam](#sorbs_spam)|31523|31523,32638|49|0.1%|1.6%|
[sorbs_recent_spam](#sorbs_recent_spam)|31523|31523,32638|49|0.1%|1.6%|
[sorbs_new_spam](#sorbs_new_spam)|31523|31523,32638|49|0.1%|1.6%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|42|0.0%|1.4%|
[et_block](#et_block)|1023|18338662|42|0.0%|1.4%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|36|0.0%|1.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|33|0.0%|1.1%|
[alienvault_reputation](#alienvault_reputation)|182275|182275|29|0.0%|0.9%|
[snort_ipfilter](#snort_ipfilter)|9943|9943|25|0.2%|0.8%|
[php_spammers](#php_spammers)|536|536|25|4.6%|0.8%|
[nixspam](#nixspam)|19062|19062|25|0.1%|0.8%|
[blocklist_de_mail](#blocklist_de_mail)|16558|16558|23|0.1%|0.7%|
[php_harvesters](#php_harvesters)|311|311|22|7.0%|0.7%|
[blocklist_de_apache](#blocklist_de_apache)|15244|15244|22|0.1%|0.7%|
[php_dictionary](#php_dictionary)|545|545|21|3.8%|0.7%|
[sorbs_web](#sorbs_web)|693|693,694|14|2.0%|0.4%|
[openbl_60d](#openbl_60d)|7286|7286|11|0.1%|0.3%|
[voipbl](#voipbl)|10476|10476,10888|4|0.0%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|4|0.0%|0.1%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|3|0.0%|0.1%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|3|0.4%|0.1%|
[openbl_30d](#openbl_30d)|3252|3252|2|0.0%|0.0%|
[dshield](#dshield)|19|19,5120|2|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1|0.0%|0.0%|
[et_compromised](#et_compromised)|2016|2016|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1821|1821|1|0.0%|0.0%|

## blocklist_de_bruteforce

[Blocklist.de](https://www.blocklist.de/) All IPs which attacks Joomlas, Wordpress and other Web-Logins with Brute-Force Logins.

Source is downloaded from [this link](http://lists.blocklist.de/lists/bruteforcelogin.txt).

The last time downloaded was found to be dated: Sat Jun  6 18:28:10 UTC 2015.

The ipset `blocklist_de_bruteforce` has **3893** entries, **3893** unique IPs.

The following table shows the overlaps of `blocklist_de_bruteforce` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_bruteforce`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_bruteforce`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_bruteforce`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de_apache](#blocklist_de_apache)|15244|15244|3893|25.5%|100.0%|
[blocklist_de](#blocklist_de)|26256|26256|3884|14.7%|99.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|284|0.0%|7.2%|
[sorbs_spam](#sorbs_spam)|31523|31523,32638|111|0.3%|2.8%|
[sorbs_recent_spam](#sorbs_recent_spam)|31523|31523,32638|111|0.3%|2.8%|
[sorbs_new_spam](#sorbs_new_spam)|31523|31523,32638|111|0.3%|2.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|56|0.0%|1.4%|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|55|0.0%|1.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|36|0.0%|0.9%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|33|0.1%|0.8%|
[nixspam](#nixspam)|19062|19062|30|0.1%|0.7%|
[alienvault_reputation](#alienvault_reputation)|182275|182275|23|0.0%|0.5%|
[stopforumspam_1d](#stopforumspam_1d)|6675|6675|17|0.2%|0.4%|
[php_commenters](#php_commenters)|349|349|8|2.2%|0.2%|
[blocklist_de_strongips](#blocklist_de_strongips)|177|177|8|4.5%|0.2%|
[php_spammers](#php_spammers)|536|536|6|1.1%|0.1%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|6|0.0%|0.1%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|5|0.0%|0.1%|
[snort_ipfilter](#snort_ipfilter)|9943|9943|5|0.0%|0.1%|
[php_dictionary](#php_dictionary)|545|545|4|0.7%|0.1%|
[et_block](#et_block)|1023|18338662|4|0.0%|0.1%|
[sorbs_web](#sorbs_web)|693|693,694|3|0.4%|0.0%|
[php_harvesters](#php_harvesters)|311|311|3|0.9%|0.0%|
[shunlist](#shunlist)|1215|1215|2|0.1%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|2|0.0%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2|0.0%|0.0%|
[voipbl](#voipbl)|10476|10476,10888|1|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|168|168|1|0.5%|0.0%|
[ciarmy](#ciarmy)|412|412|1|0.2%|0.0%|

## blocklist_de_ftp

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours for attacks on the Service FTP.

Source is downloaded from [this link](http://lists.blocklist.de/lists/ftp.txt).

The last time downloaded was found to be dated: Sat Jun  6 18:28:07 UTC 2015.

The ipset `blocklist_de_ftp` has **830** entries, **830** unique IPs.

The following table shows the overlaps of `blocklist_de_ftp` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_ftp`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_ftp`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_ftp`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|26256|26256|827|3.1%|99.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|79|0.0%|9.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|14|0.0%|1.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|13|0.0%|1.5%|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|11|0.0%|1.3%|
[sorbs_spam](#sorbs_spam)|31523|31523,32638|6|0.0%|0.7%|
[sorbs_recent_spam](#sorbs_recent_spam)|31523|31523,32638|6|0.0%|0.7%|
[sorbs_new_spam](#sorbs_new_spam)|31523|31523,32638|6|0.0%|0.7%|
[nixspam](#nixspam)|19062|19062|5|0.0%|0.6%|
[alienvault_reputation](#alienvault_reputation)|182275|182275|5|0.0%|0.6%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|4|0.0%|0.4%|
[php_harvesters](#php_harvesters)|311|311|3|0.9%|0.3%|
[stopforumspam_1d](#stopforumspam_1d)|6675|6675|2|0.0%|0.2%|
[openbl_60d](#openbl_60d)|7286|7286|2|0.0%|0.2%|
[blocklist_de_strongips](#blocklist_de_strongips)|177|177|2|1.1%|0.2%|
[php_spammers](#php_spammers)|536|536|1|0.1%|0.1%|
[php_dictionary](#php_dictionary)|545|545|1|0.1%|0.1%|
[openbl_30d](#openbl_30d)|3252|3252|1|0.0%|0.1%|
[ciarmy](#ciarmy)|412|412|1|0.2%|0.1%|

## blocklist_de_imap

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours for attacks on the Service imap, sasl, pop3, etc.

Source is downloaded from [this link](http://lists.blocklist.de/lists/imap.txt).

The last time downloaded was found to be dated: Sat Jun  6 18:28:07 UTC 2015.

The ipset `blocklist_de_imap` has **1605** entries, **1605** unique IPs.

The following table shows the overlaps of `blocklist_de_imap` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_imap`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_imap`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_imap`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de_mail](#blocklist_de_mail)|16558|16558|1602|9.6%|99.8%|
[blocklist_de](#blocklist_de)|26256|26256|1602|6.1%|99.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|133|0.0%|8.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|49|0.0%|3.0%|
[alienvault_reputation](#alienvault_reputation)|182275|182275|43|0.0%|2.6%|
[openbl_60d](#openbl_60d)|7286|7286|37|0.5%|2.3%|
[openbl_30d](#openbl_30d)|3252|3252|31|0.9%|1.9%|
[nixspam](#nixspam)|19062|19062|21|0.1%|1.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|21|0.0%|1.3%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|16|0.0%|0.9%|
[et_block](#et_block)|1023|18338662|16|0.0%|0.9%|
[sorbs_spam](#sorbs_spam)|31523|31523,32638|12|0.0%|0.7%|
[sorbs_recent_spam](#sorbs_recent_spam)|31523|31523,32638|12|0.0%|0.7%|
[sorbs_new_spam](#sorbs_new_spam)|31523|31523,32638|12|0.0%|0.7%|
[openbl_7d](#openbl_7d)|843|843|11|1.3%|0.6%|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|8|0.0%|0.4%|
[et_compromised](#et_compromised)|2016|2016|7|0.3%|0.4%|
[bruteforceblocker](#bruteforceblocker)|1821|1821|7|0.3%|0.4%|
[ri_web_proxies](#ri_web_proxies)|6664|6664|5|0.0%|0.3%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|3|0.0%|0.1%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|3|0.0%|0.1%|
[snort_ipfilter](#snort_ipfilter)|9943|9943|2|0.0%|0.1%|
[shunlist](#shunlist)|1215|1215|1|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2475|2475|1|0.0%|0.0%|
[php_dictionary](#php_dictionary)|545|545|1|0.1%|0.0%|
[php_commenters](#php_commenters)|349|349|1|0.2%|0.0%|
[openbl_1d](#openbl_1d)|146|146|1|0.6%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.0%|
[ciarmy](#ciarmy)|412|412|1|0.2%|0.0%|

## blocklist_de_mail

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service Mail, Postfix.

Source is downloaded from [this link](http://lists.blocklist.de/lists/mail.txt).

The last time downloaded was found to be dated: Sat Jun  6 18:42:11 UTC 2015.

The ipset `blocklist_de_mail` has **16558** entries, **16558** unique IPs.

The following table shows the overlaps of `blocklist_de_mail` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_mail`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_mail`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_mail`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|26256|26256|16558|63.0%|100.0%|
[blocklist_de_apache](#blocklist_de_apache)|15244|15244|11059|72.5%|66.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|2608|0.0%|15.7%|
[blocklist_de_imap](#blocklist_de_imap)|1605|1605|1602|99.8%|9.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|1375|0.0%|8.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|1140|0.0%|6.8%|
[sorbs_spam](#sorbs_spam)|31523|31523,32638|785|2.4%|4.7%|
[sorbs_recent_spam](#sorbs_recent_spam)|31523|31523,32638|785|2.4%|4.7%|
[sorbs_new_spam](#sorbs_new_spam)|31523|31523,32638|785|2.4%|4.7%|
[nixspam](#nixspam)|19062|19062|326|1.7%|1.9%|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|255|0.2%|1.5%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|142|0.4%|0.8%|
[snort_ipfilter](#snort_ipfilter)|9943|9943|127|1.2%|0.7%|
[php_dictionary](#php_dictionary)|545|545|62|11.3%|0.3%|
[alienvault_reputation](#alienvault_reputation)|182275|182275|62|0.0%|0.3%|
[php_spammers](#php_spammers)|536|536|61|11.3%|0.3%|
[ri_web_proxies](#ri_web_proxies)|6664|6664|57|0.8%|0.3%|
[sorbs_web](#sorbs_web)|693|693,694|56|8.0%|0.3%|
[stopforumspam_1d](#stopforumspam_1d)|6675|6675|52|0.7%|0.3%|
[openbl_60d](#openbl_60d)|7286|7286|46|0.6%|0.2%|
[openbl_30d](#openbl_30d)|3252|3252|40|1.2%|0.2%|
[xroxy](#xroxy)|2107|2107|38|1.8%|0.2%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|24|0.0%|0.1%|
[et_block](#et_block)|1023|18338662|24|0.0%|0.1%|
[blocklist_de_bots](#blocklist_de_bots)|2967|2967|23|0.7%|0.1%|
[php_commenters](#php_commenters)|349|349|22|6.3%|0.1%|
[proxz](#proxz)|906|906|21|2.3%|0.1%|
[blocklist_de_strongips](#blocklist_de_strongips)|177|177|21|11.8%|0.1%|
[openbl_7d](#openbl_7d)|843|843|13|1.5%|0.0%|
[et_compromised](#et_compromised)|2016|2016|11|0.5%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1821|1821|11|0.6%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|6|0.0%|0.0%|
[sorbs_socks](#sorbs_socks)|22|22,22|5|22.7%|0.0%|
[sorbs_misc](#sorbs_misc)|22|22,22|5|22.7%|0.0%|
[sorbs_http](#sorbs_http)|22|22,22|5|22.7%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|4|0.0%|0.0%|
[et_tor](#et_tor)|6470|6470|4|0.0%|0.0%|
[dm_tor](#dm_tor)|6512|6512|4|0.0%|0.0%|
[bm_tor](#bm_tor)|6516|6516|4|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2475|2475|3|0.1%|0.0%|
[openbl_1d](#openbl_1d)|146|146|3|2.0%|0.0%|
[shunlist](#shunlist)|1215|1215|2|0.1%|0.0%|
[php_harvesters](#php_harvesters)|311|311|2|0.6%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|2|0.0%|0.0%|
[voipbl](#voipbl)|10476|10476,10888|1|0.0%|0.0%|
[proxyrss](#proxyrss)|1416|1416|1|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[ciarmy](#ciarmy)|412|412|1|0.2%|0.0%|

## blocklist_de_sip

[Blocklist.de](https://www.blocklist.de/) All IP addresses that tried to login in a SIP, VOIP or Asterisk Server and are included in the IPs list from [infiltrated.net](www.infiltrated.net)

Source is downloaded from [this link](http://lists.blocklist.de/lists/sip.txt).

The last time downloaded was found to be dated: Sat Jun  6 18:28:07 UTC 2015.

The ipset `blocklist_de_sip` has **91** entries, **91** unique IPs.

The following table shows the overlaps of `blocklist_de_sip` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_sip`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_sip`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_sip`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|26256|26256|72|0.2%|79.1%|
[voipbl](#voipbl)|10476|10476,10888|27|0.2%|29.6%|
[alienvault_reputation](#alienvault_reputation)|182275|182275|16|0.0%|17.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|13|0.0%|14.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|7|0.0%|7.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|4|0.0%|4.3%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|2|0.0%|2.1%|
[et_block](#et_block)|1023|18338662|2|0.0%|2.1%|
[et_botcc](#et_botcc)|509|509|1|0.1%|1.0%|

## blocklist_de_ssh

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service SSH.

Source is downloaded from [this link](http://lists.blocklist.de/lists/ssh.txt).

The last time downloaded was found to be dated: Sat Jun  6 18:42:07 UTC 2015.

The ipset `blocklist_de_ssh` has **1659** entries, **1659** unique IPs.

The following table shows the overlaps of `blocklist_de_ssh` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_ssh`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_ssh`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_ssh`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|26256|26256|1659|6.3%|100.0%|
[alienvault_reputation](#alienvault_reputation)|182275|182275|765|0.4%|46.1%|
[openbl_60d](#openbl_60d)|7286|7286|677|9.2%|40.8%|
[openbl_30d](#openbl_30d)|3252|3252|641|19.7%|38.6%|
[et_compromised](#et_compromised)|2016|2016|605|30.0%|36.4%|
[bruteforceblocker](#bruteforceblocker)|1821|1821|599|32.8%|36.1%|
[openbl_7d](#openbl_7d)|843|843|396|46.9%|23.8%|
[shunlist](#shunlist)|1215|1215|318|26.1%|19.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|166|0.0%|10.0%|
[openbl_1d](#openbl_1d)|146|146|120|82.1%|7.2%|
[et_block](#et_block)|1023|18338662|110|0.0%|6.6%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|106|0.0%|6.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|84|0.0%|5.0%|
[dshield](#dshield)|19|19,5120|42|0.8%|2.5%|
[blocklist_de_strongips](#blocklist_de_strongips)|177|177|29|16.3%|1.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|25|0.0%|1.5%|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|6|0.0%|0.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|5|0.0%|0.3%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|2|0.0%|0.1%|
[nixspam](#nixspam)|19062|19062|2|0.0%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|2|0.0%|0.1%|
[sslbl](#sslbl)|369|369|1|0.2%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9943|9943|1|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1|0.0%|0.0%|
[ciarmy](#ciarmy)|412|412|1|0.2%|0.0%|

## blocklist_de_strongips

[Blocklist.de](https://www.blocklist.de/) All IPs which are older then 2 month and have more then 5.000 attacks.

Source is downloaded from [this link](http://lists.blocklist.de/lists/strongips.txt).

The last time downloaded was found to be dated: Sat Jun  6 18:42:40 UTC 2015.

The ipset `blocklist_de_strongips` has **177** entries, **177** unique IPs.

The following table shows the overlaps of `blocklist_de_strongips` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_strongips`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_strongips`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_strongips`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|26256|26256|177|0.6%|100.0%|
[blocklist_de_bots](#blocklist_de_bots)|2967|2967|131|4.4%|74.0%|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|129|0.1%|72.8%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|118|0.3%|66.6%|
[stopforumspam_1d](#stopforumspam_1d)|6675|6675|101|1.5%|57.0%|
[alienvault_reputation](#alienvault_reputation)|182275|182275|37|0.0%|20.9%|
[php_commenters](#php_commenters)|349|349|36|10.3%|20.3%|
[blocklist_de_apache](#blocklist_de_apache)|15244|15244|34|0.2%|19.2%|
[blocklist_de_ssh](#blocklist_de_ssh)|1659|1659|29|1.7%|16.3%|
[openbl_60d](#openbl_60d)|7286|7286|27|0.3%|15.2%|
[openbl_30d](#openbl_30d)|3252|3252|25|0.7%|14.1%|
[openbl_7d](#openbl_7d)|843|843|24|2.8%|13.5%|
[blocklist_de_mail](#blocklist_de_mail)|16558|16558|21|0.1%|11.8%|
[shunlist](#shunlist)|1215|1215|20|1.6%|11.2%|
[openbl_1d](#openbl_1d)|146|146|20|13.6%|11.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|16|0.0%|9.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|8|0.0%|4.5%|
[et_block](#et_block)|1023|18338662|8|0.0%|4.5%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|3893|3893|8|0.2%|4.5%|
[xroxy](#xroxy)|2107|2107|7|0.3%|3.9%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|7|0.0%|3.9%|
[ri_web_proxies](#ri_web_proxies)|6664|6664|5|0.0%|2.8%|
[proxyrss](#proxyrss)|1416|1416|5|0.3%|2.8%|
[php_spammers](#php_spammers)|536|536|5|0.9%|2.8%|
[proxz](#proxz)|906|906|4|0.4%|2.2%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|3|0.0%|1.6%|
[php_dictionary](#php_dictionary)|545|545|3|0.5%|1.6%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|1.6%|
[php_harvesters](#php_harvesters)|311|311|2|0.6%|1.1%|
[blocklist_de_ftp](#blocklist_de_ftp)|830|830|2|0.2%|1.1%|
[sorbs_web](#sorbs_web)|693|693,694|1|0.1%|0.5%|
[sorbs_spam](#sorbs_spam)|31523|31523,32638|1|0.0%|0.5%|
[sorbs_recent_spam](#sorbs_recent_spam)|31523|31523,32638|1|0.0%|0.5%|
[sorbs_new_spam](#sorbs_new_spam)|31523|31523,32638|1|0.0%|0.5%|
[snort_ipfilter](#snort_ipfilter)|9943|9943|1|0.0%|0.5%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.5%|

## bm_tor

[torstatus.blutmagie.de](https://torstatus.blutmagie.de) list of all TOR network servers

Source is downloaded from [this link](https://torstatus.blutmagie.de/ip_list_all.php/Tor_ip_list_ALL.csv).

The last time downloaded was found to be dated: Sat Jun  6 18:27:05 UTC 2015.

The ipset `bm_tor` has **6516** entries, **6516** unique IPs.

The following table shows the overlaps of `bm_tor` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `bm_tor`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `bm_tor`.
- ` this % ` is the percentage **of this ipset (`bm_tor`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[dm_tor](#dm_tor)|6512|6512|6512|100.0%|99.9%|
[et_tor](#et_tor)|6470|6470|5732|88.5%|87.9%|
[snort_ipfilter](#snort_ipfilter)|9943|9943|1080|10.8%|16.5%|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|637|0.6%|9.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|627|0.0%|9.6%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|504|1.6%|7.7%|
[stopforumspam_1d](#stopforumspam_1d)|6675|6675|334|5.0%|5.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|190|0.0%|2.9%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|166|44.6%|2.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|162|0.0%|2.4%|
[alienvault_reputation](#alienvault_reputation)|182275|182275|42|0.0%|0.6%|
[php_commenters](#php_commenters)|349|349|36|10.3%|0.5%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|22|0.0%|0.3%|
[openbl_60d](#openbl_60d)|7286|7286|19|0.2%|0.2%|
[php_harvesters](#php_harvesters)|311|311|7|2.2%|0.1%|
[ri_web_proxies](#ri_web_proxies)|6664|6664|5|0.0%|0.0%|
[php_spammers](#php_spammers)|536|536|5|0.9%|0.0%|
[et_block](#et_block)|1023|18338662|5|0.0%|0.0%|
[php_dictionary](#php_dictionary)|545|545|4|0.7%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|4|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|16558|16558|4|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|15244|15244|4|0.0%|0.0%|
[blocklist_de](#blocklist_de)|26256|26256|4|0.0%|0.0%|
[voipbl](#voipbl)|10476|10476,10888|3|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|3|0.0%|0.0%|
[dshield](#dshield)|19|19,5120|3|0.0%|0.0%|
[xroxy](#xroxy)|2107|2107|2|0.0%|0.0%|
[sorbs_spam](#sorbs_spam)|31523|31523,32638|2|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|31523|31523,32638|2|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|31523|31523,32638|2|0.0%|0.0%|
[shunlist](#shunlist)|1215|1215|1|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2475|2475|1|0.0%|0.0%|
[nixspam](#nixspam)|19062|19062|1|0.0%|0.0%|

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
[fullbogons](#fullbogons)|3721|670267288|592708608|88.4%|100.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|4194304|3.0%|0.7%|
[voipbl](#voipbl)|10476|10476,10888|319|2.9%|0.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|5|0.0%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|1|0.0%|0.0%|
[php_harvesters](#php_harvesters)|311|311|1|0.3%|0.0%|
[php_commenters](#php_commenters)|349|349|1|0.2%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.0%|
[ciarmy](#ciarmy)|412|412|1|0.2%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1821|1821|1|0.0%|0.0%|

## bruteforceblocker

[danger.rulez.sk](http://danger.rulez.sk/) IPs detected by [bruteforceblocker](http://danger.rulez.sk/index.php/bruteforceblocker/) (fail2ban alternative for SSH on OpenBSD). This is an automatically generated list from users reporting failed authentication attempts. An IP seems to be included if 3 or more users report it. Its retention pocily seems 30 days.

Source is downloaded from [this link](http://danger.rulez.sk/projects/bruteforceblocker/blist.php).

The last time downloaded was found to be dated: Sat Jun  6 17:54:27 UTC 2015.

The ipset `bruteforceblocker` has **1821** entries, **1821** unique IPs.

The following table shows the overlaps of `bruteforceblocker` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `bruteforceblocker`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `bruteforceblocker`.
- ` this % ` is the percentage **of this ipset (`bruteforceblocker`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[et_compromised](#et_compromised)|2016|2016|1764|87.5%|96.8%|
[alienvault_reputation](#alienvault_reputation)|182275|182275|1177|0.6%|64.6%|
[openbl_60d](#openbl_60d)|7286|7286|1081|14.8%|59.3%|
[openbl_30d](#openbl_30d)|3252|3252|1037|31.8%|56.9%|
[blocklist_de](#blocklist_de)|26256|26256|613|2.3%|33.6%|
[blocklist_de_ssh](#blocklist_de_ssh)|1659|1659|599|36.1%|32.8%|
[shunlist](#shunlist)|1215|1215|425|34.9%|23.3%|
[openbl_7d](#openbl_7d)|843|843|362|42.9%|19.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|173|0.0%|9.5%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|101|0.0%|5.5%|
[et_block](#et_block)|1023|18338662|101|0.0%|5.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|90|0.0%|4.9%|
[openbl_1d](#openbl_1d)|146|146|78|53.4%|4.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|47|0.0%|2.5%|
[dshield](#dshield)|19|19,5120|36|0.7%|1.9%|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|11|0.0%|0.6%|
[blocklist_de_mail](#blocklist_de_mail)|16558|16558|11|0.0%|0.6%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|7|0.0%|0.3%|
[blocklist_de_imap](#blocklist_de_imap)|1605|1605|7|0.4%|0.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|5|0.0%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|3|0.0%|0.1%|
[voipbl](#voipbl)|10476|10476,10888|2|0.0%|0.1%|
[proxz](#proxz)|906|906|2|0.2%|0.1%|
[proxyrss](#proxyrss)|1416|1416|2|0.1%|0.1%|
[xroxy](#xroxy)|2107|2107|1|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|6664|6664|1|0.0%|0.0%|
[nixspam](#nixspam)|19062|19062|1|0.0%|0.0%|
[fullbogons](#fullbogons)|3721|670267288|1|0.0%|0.0%|
[ciarmy](#ciarmy)|412|412|1|0.2%|0.0%|
[bogons](#bogons)|13|592708608|1|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|2967|2967|1|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|15244|15244|1|0.0%|0.0%|

## ciarmy

[CIArmy.com](http://ciarmy.com/) IPs with poor Rogue Packet score that have not yet been identified as malicious by the community

Source is downloaded from [this link](http://cinsscore.com/list/ci-badguys.txt).

The last time downloaded was found to be dated: Sat Jun  6 16:15:15 UTC 2015.

The ipset `ciarmy` has **412** entries, **412** unique IPs.

The following table shows the overlaps of `ciarmy` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ciarmy`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ciarmy`.
- ` this % ` is the percentage **of this ipset (`ciarmy`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[alienvault_reputation](#alienvault_reputation)|182275|182275|407|0.2%|98.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|80|0.0%|19.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|43|0.0%|10.4%|
[blocklist_de](#blocklist_de)|26256|26256|35|0.1%|8.4%|
[blocklist_de_apache](#blocklist_de_apache)|15244|15244|32|0.2%|7.7%|
[shunlist](#shunlist)|1215|1215|31|2.5%|7.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|30|0.0%|7.2%|
[et_block](#et_block)|1023|18338662|6|0.0%|1.4%|
[dshield](#dshield)|19|19,5120|5|0.0%|1.2%|
[voipbl](#voipbl)|10476|10476,10888|4|0.0%|0.9%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|1|0.0%|0.2%|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|1|0.0%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.2%|
[fullbogons](#fullbogons)|3721|670267288|1|0.0%|0.2%|
[et_compromised](#et_compromised)|2016|2016|1|0.0%|0.2%|
[bruteforceblocker](#bruteforceblocker)|1821|1821|1|0.0%|0.2%|
[bogons](#bogons)|13|592708608|1|0.0%|0.2%|
[blocklist_de_ssh](#blocklist_de_ssh)|1659|1659|1|0.0%|0.2%|
[blocklist_de_mail](#blocklist_de_mail)|16558|16558|1|0.0%|0.2%|
[blocklist_de_imap](#blocklist_de_imap)|1605|1605|1|0.0%|0.2%|
[blocklist_de_ftp](#blocklist_de_ftp)|830|830|1|0.1%|0.2%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|3893|3893|1|0.0%|0.2%|

## cleanmx_viruses

[Clean-MX.de](http://support.clean-mx.de/clean-mx/viruses.php) IPs with viruses

Source is downloaded from [this link](http://support.clean-mx.de/clean-mx/xmlviruses.php?sort=id%20desc&response=alive).

The last time downloaded was found to be dated: Sat Jun  6 07:45:32 UTC 2015.

The ipset `cleanmx_viruses` has **168** entries, **168** unique IPs.

The following table shows the overlaps of `cleanmx_viruses` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `cleanmx_viruses`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `cleanmx_viruses`.
- ` this % ` is the percentage **of this ipset (`cleanmx_viruses`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[malc0de](#malc0de)|361|361|27|7.4%|16.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|17|0.0%|10.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|9|0.0%|5.3%|
[alienvault_reputation](#alienvault_reputation)|182275|182275|7|0.0%|4.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|3|0.0%|1.7%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|2|0.1%|1.1%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|3893|3893|1|0.0%|0.5%|
[blocklist_de_apache](#blocklist_de_apache)|15244|15244|1|0.0%|0.5%|
[blocklist_de](#blocklist_de)|26256|26256|1|0.0%|0.5%|

## dm_tor

[dan.me.uk](https://www.dan.me.uk) dynamic list of TOR exit points

Source is downloaded from [this link](https://www.dan.me.uk/torlist/).

The last time downloaded was found to be dated: Sat Jun  6 18:27:04 UTC 2015.

The ipset `dm_tor` has **6512** entries, **6512** unique IPs.

The following table shows the overlaps of `dm_tor` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `dm_tor`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `dm_tor`.
- ` this % ` is the percentage **of this ipset (`dm_tor`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[bm_tor](#bm_tor)|6516|6516|6512|99.9%|100.0%|
[et_tor](#et_tor)|6470|6470|5729|88.5%|87.9%|
[snort_ipfilter](#snort_ipfilter)|9943|9943|1079|10.8%|16.5%|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|637|0.6%|9.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|627|0.0%|9.6%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|504|1.6%|7.7%|
[stopforumspam_1d](#stopforumspam_1d)|6675|6675|334|5.0%|5.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|190|0.0%|2.9%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|166|44.6%|2.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|162|0.0%|2.4%|
[alienvault_reputation](#alienvault_reputation)|182275|182275|42|0.0%|0.6%|
[php_commenters](#php_commenters)|349|349|36|10.3%|0.5%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|22|0.0%|0.3%|
[openbl_60d](#openbl_60d)|7286|7286|19|0.2%|0.2%|
[php_harvesters](#php_harvesters)|311|311|7|2.2%|0.1%|
[ri_web_proxies](#ri_web_proxies)|6664|6664|5|0.0%|0.0%|
[php_spammers](#php_spammers)|536|536|5|0.9%|0.0%|
[et_block](#et_block)|1023|18338662|5|0.0%|0.0%|
[php_dictionary](#php_dictionary)|545|545|4|0.7%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|4|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|16558|16558|4|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|15244|15244|4|0.0%|0.0%|
[blocklist_de](#blocklist_de)|26256|26256|4|0.0%|0.0%|
[voipbl](#voipbl)|10476|10476,10888|3|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|3|0.0%|0.0%|
[dshield](#dshield)|19|19,5120|3|0.0%|0.0%|
[xroxy](#xroxy)|2107|2107|2|0.0%|0.0%|
[sorbs_spam](#sorbs_spam)|31523|31523,32638|2|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|31523|31523,32638|2|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|31523|31523,32638|2|0.0%|0.0%|
[shunlist](#shunlist)|1215|1215|1|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2475|2475|1|0.0%|0.0%|
[nixspam](#nixspam)|19062|19062|1|0.0%|0.0%|

## dshield

[DShield.org](https://dshield.org/) top 20 attacking class C (/24) subnets over the last three days - **excellent list**

Source is downloaded from [this link](http://feeds.dshield.org/block.txt).

The last time downloaded was found to be dated: Sat Jun  6 15:17:39 UTC 2015.

The ipset `dshield` has **19** entries, **19,5120** unique IPs.

The following table shows the overlaps of `dshield` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `dshield`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `dshield`.
- ` this % ` is the percentage **of this ipset (`dshield`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[alienvault_reputation](#alienvault_reputation)|182275|182275|3572|1.9%|69.7%|
[et_block](#et_block)|1023|18338662|1024|0.0%|20.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|267|0.0%|5.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|256|0.0%|5.0%|
[openbl_60d](#openbl_60d)|7286|7286|56|0.7%|1.0%|
[blocklist_de](#blocklist_de)|26256|26256|51|0.1%|0.9%|
[openbl_30d](#openbl_30d)|3252|3252|45|1.3%|0.8%|
[blocklist_de_ssh](#blocklist_de_ssh)|1659|1659|42|2.5%|0.8%|
[bruteforceblocker](#bruteforceblocker)|1821|1821|36|1.9%|0.7%|
[et_compromised](#et_compromised)|2016|2016|35|1.7%|0.6%|
[shunlist](#shunlist)|1215|1215|34|2.7%|0.6%|
[openbl_7d](#openbl_7d)|843|843|31|3.6%|0.6%|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|15|0.0%|0.2%|
[openbl_1d](#openbl_1d)|146|146|9|6.1%|0.1%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|8|0.0%|0.1%|
[blocklist_de_apache](#blocklist_de_apache)|15244|15244|7|0.0%|0.1%|
[voipbl](#voipbl)|10476|10476,10888|5|0.0%|0.0%|
[ciarmy](#ciarmy)|412|412|5|1.2%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6675|6675|4|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|4|0.0%|0.0%|
[et_tor](#et_tor)|6470|6470|3|0.0%|0.0%|
[dm_tor](#dm_tor)|6512|6512|3|0.0%|0.0%|
[bm_tor](#bm_tor)|6516|6516|3|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9943|9943|2|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|2967|2967|2|0.0%|0.0%|
[php_commenters](#php_commenters)|349|349|1|0.2%|0.0%|
[nixspam](#nixspam)|19062|19062|1|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|1|0.0%|0.0%|
[malc0de](#malc0de)|361|361|1|0.2%|0.0%|

## et_block

[EmergingThreats.net](http://www.emergingthreats.net/) default blacklist (at the time of writing includes spamhaus DROP, dshield and abuse.ch trackers, which are available separately too - prefer to use the direct ipsets instead of this, they seem to lag a bit in updates)

Source is downloaded from [this link](http://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt).

The last time downloaded was found to be dated: Fri Jun  5 04:30:01 UTC 2015.

The ipset `et_block` has **1023** entries, **18338662** unique IPs.

The following table shows the overlaps of `et_block` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `et_block`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `et_block`.
- ` this % ` is the percentage **of this ipset (`et_block`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[spamhaus_drop](#spamhaus_drop)|653|18404096|18120448|98.4%|98.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|8598311|2.4%|46.8%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|7079936|77.1%|38.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|2272276|0.2%|12.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|195933|0.1%|1.0%|
[fullbogons](#fullbogons)|3721|670267288|20480|0.0%|0.1%|
[alienvault_reputation](#alienvault_reputation)|182275|182275|5262|2.8%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1040|0.3%|0.0%|
[dshield](#dshield)|19|19,5120|1024|20.0%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|1013|1.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|517|0.1%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|314|1.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9943|9943|313|3.1%|0.0%|
[openbl_60d](#openbl_60d)|7286|7286|250|3.4%|0.0%|
[zeus](#zeus)|232|232|220|94.8%|0.0%|
[zeus_badips](#zeus_badips)|202|202|200|99.0%|0.0%|
[blocklist_de](#blocklist_de)|26256|26256|191|0.7%|0.0%|
[openbl_30d](#openbl_30d)|3252|3252|166|5.1%|0.0%|
[shunlist](#shunlist)|1215|1215|110|9.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1659|1659|110|6.6%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1821|1821|101|5.5%|0.0%|
[et_compromised](#et_compromised)|2016|2016|100|4.9%|0.0%|
[feodo](#feodo)|99|99|94|94.9%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6675|6675|80|1.1%|0.0%|
[openbl_7d](#openbl_7d)|843|843|50|5.9%|0.0%|
[nixspam](#nixspam)|19062|19062|44|0.2%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|2967|2967|42|1.4%|0.0%|
[sslbl](#sslbl)|369|369|35|9.4%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|29|2.2%|0.0%|
[php_commenters](#php_commenters)|349|349|28|8.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|16558|16558|24|0.1%|0.0%|
[voipbl](#voipbl)|10476|10476,10888|17|0.1%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|1605|1605|16|0.9%|0.0%|
[sorbs_spam](#sorbs_spam)|31523|31523,32638|14|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|31523|31523,32638|14|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|31523|31523,32638|14|0.0%|0.0%|
[palevo](#palevo)|13|13|13|100.0%|0.0%|
[openbl_1d](#openbl_1d)|146|146|13|8.9%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|15244|15244|13|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|177|177|8|4.5%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|6|0.4%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|6|0.0%|0.0%|
[ciarmy](#ciarmy)|412|412|6|1.4%|0.0%|
[malc0de](#malc0de)|361|361|5|1.3%|0.0%|
[dm_tor](#dm_tor)|6512|6512|5|0.0%|0.0%|
[bm_tor](#bm_tor)|6516|6516|5|0.0%|0.0%|
[php_dictionary](#php_dictionary)|545|545|4|0.7%|0.0%|
[et_tor](#et_tor)|6470|6470|4|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|3893|3893|4|0.1%|0.0%|
[php_spammers](#php_spammers)|536|536|2|0.3%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|2|0.2%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|91|91|2|2.1%|0.0%|
[php_harvesters](#php_harvesters)|311|311|1|0.3%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[et_botcc](#et_botcc)|509|509|1|0.1%|0.0%|

## et_botcc

[EmergingThreats.net Command and Control IPs](http://doc.emergingthreats.net/bin/view/Main/BotCC) These IPs are updates every 24 hours and should be considered VERY highly reliable indications that a host is communicating with a known and active Bot or Malware command and control server - (although they say this includes abuse.ch trackers, it does not - most probably it is the shadowserver.org C&C list)

Source is downloaded from [this link](http://rules.emergingthreats.net/fwrules/emerging-PIX-CC.rules).

The last time downloaded was found to be dated: Fri Jun  5 04:30:01 UTC 2015.

The ipset `et_botcc` has **509** entries, **509** unique IPs.

The following table shows the overlaps of `et_botcc` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `et_botcc`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `et_botcc`.
- ` this % ` is the percentage **of this ipset (`et_botcc`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|78|0.0%|15.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|41|0.0%|8.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|22|0.0%|4.3%|
[alienvault_reputation](#alienvault_reputation)|182275|182275|5|0.0%|0.9%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|1|0.0%|0.1%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|1|0.0%|0.1%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.1%|
[et_block](#et_block)|1023|18338662|1|0.0%|0.1%|
[blocklist_de_sip](#blocklist_de_sip)|91|91|1|1.0%|0.1%|

## et_compromised

[EmergingThreats.net compromised hosts](http://doc.emergingthreats.net/bin/view/Main/CompromisedHost) - (this seems to be based on bruteforceblocker)

Source is downloaded from [this link](http://rules.emergingthreats.net/blockrules/compromised-ips.txt).

The last time downloaded was found to be dated: Fri Jun  5 04:30:08 UTC 2015.

The ipset `et_compromised` has **2016** entries, **2016** unique IPs.

The following table shows the overlaps of `et_compromised` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `et_compromised`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `et_compromised`.
- ` this % ` is the percentage **of this ipset (`et_compromised`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[bruteforceblocker](#bruteforceblocker)|1821|1821|1764|96.8%|87.5%|
[alienvault_reputation](#alienvault_reputation)|182275|182275|1313|0.7%|65.1%|
[openbl_60d](#openbl_60d)|7286|7286|1217|16.7%|60.3%|
[openbl_30d](#openbl_30d)|3252|3252|1151|35.3%|57.0%|
[blocklist_de](#blocklist_de)|26256|26256|619|2.3%|30.7%|
[blocklist_de_ssh](#blocklist_de_ssh)|1659|1659|605|36.4%|30.0%|
[shunlist](#shunlist)|1215|1215|436|35.8%|21.6%|
[openbl_7d](#openbl_7d)|843|843|372|44.1%|18.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|199|0.0%|9.8%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|100|0.0%|4.9%|
[et_block](#et_block)|1023|18338662|100|0.0%|4.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|97|0.0%|4.8%|
[openbl_1d](#openbl_1d)|146|146|74|50.6%|3.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|52|0.0%|2.5%|
[dshield](#dshield)|19|19,5120|35|0.6%|1.7%|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|11|0.0%|0.5%|
[blocklist_de_mail](#blocklist_de_mail)|16558|16558|11|0.0%|0.5%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|7|0.0%|0.3%|
[blocklist_de_imap](#blocklist_de_imap)|1605|1605|7|0.4%|0.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|5|0.0%|0.2%|
[voipbl](#voipbl)|10476|10476,10888|2|0.0%|0.0%|
[proxz](#proxz)|906|906|2|0.2%|0.0%|
[proxyrss](#proxyrss)|1416|1416|2|0.1%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|2|0.0%|0.0%|
[xroxy](#xroxy)|2107|2107|1|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|6664|6664|1|0.0%|0.0%|
[nixspam](#nixspam)|19062|19062|1|0.0%|0.0%|
[ciarmy](#ciarmy)|412|412|1|0.2%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|2967|2967|1|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|15244|15244|1|0.0%|0.0%|

## et_tor

[EmergingThreats.net](http://www.emergingthreats.net/) [list](http://doc.emergingthreats.net/bin/view/Main/TorRules) of TOR network IPs

Source is downloaded from [this link](http://rules.emergingthreats.net/blockrules/emerging-tor.rules).

The last time downloaded was found to be dated: Fri Jun  5 04:30:10 UTC 2015.

The ipset `et_tor` has **6470** entries, **6470** unique IPs.

The following table shows the overlaps of `et_tor` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `et_tor`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `et_tor`.
- ` this % ` is the percentage **of this ipset (`et_tor`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[bm_tor](#bm_tor)|6516|6516|5732|87.9%|88.5%|
[dm_tor](#dm_tor)|6512|6512|5729|87.9%|88.5%|
[snort_ipfilter](#snort_ipfilter)|9943|9943|1084|10.9%|16.7%|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|647|0.6%|10.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|633|0.0%|9.7%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|516|1.7%|7.9%|
[stopforumspam_1d](#stopforumspam_1d)|6675|6675|333|4.9%|5.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|190|0.0%|2.9%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|168|45.1%|2.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|168|0.0%|2.5%|
[alienvault_reputation](#alienvault_reputation)|182275|182275|42|0.0%|0.6%|
[php_commenters](#php_commenters)|349|349|37|10.6%|0.5%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|22|0.0%|0.3%|
[openbl_60d](#openbl_60d)|7286|7286|20|0.2%|0.3%|
[php_harvesters](#php_harvesters)|311|311|7|2.2%|0.1%|
[php_spammers](#php_spammers)|536|536|6|1.1%|0.0%|
[ri_web_proxies](#ri_web_proxies)|6664|6664|5|0.0%|0.0%|
[php_dictionary](#php_dictionary)|545|545|5|0.9%|0.0%|
[et_block](#et_block)|1023|18338662|4|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|16558|16558|4|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|15244|15244|4|0.0%|0.0%|
[blocklist_de](#blocklist_de)|26256|26256|4|0.0%|0.0%|
[voipbl](#voipbl)|10476|10476,10888|3|0.0%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|0.0%|
[dshield](#dshield)|19|19,5120|3|0.0%|0.0%|
[xroxy](#xroxy)|2107|2107|2|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|2|0.0%|0.0%|
[sorbs_spam](#sorbs_spam)|31523|31523,32638|2|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|31523|31523,32638|2|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|31523|31523,32638|2|0.0%|0.0%|
[shunlist](#shunlist)|1215|1215|1|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2475|2475|1|0.0%|0.0%|
[nixspam](#nixspam)|19062|19062|1|0.0%|0.0%|

## feodo

[Abuse.ch Feodo tracker](https://feodotracker.abuse.ch) trojan includes IPs which are being used by Feodo (also known as Cridex or Bugat) which commits ebanking fraud - **excellent list**

Source is downloaded from [this link](https://feodotracker.abuse.ch/blocklist/?download=ipblocklist).

The last time downloaded was found to be dated: Sat Jun  6 18:27:13 UTC 2015.

The ipset `feodo` has **99** entries, **99** unique IPs.

The following table shows the overlaps of `feodo` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `feodo`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `feodo`.
- ` this % ` is the percentage **of this ipset (`feodo`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[et_block](#et_block)|1023|18338662|94|0.0%|94.9%|
[snort_ipfilter](#snort_ipfilter)|9943|9943|79|0.7%|79.7%|
[sslbl](#sslbl)|369|369|36|9.7%|36.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|11|0.0%|11.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|3|0.0%|3.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|3|0.0%|3.0%|
[alienvault_reputation](#alienvault_reputation)|182275|182275|2|0.0%|2.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|1.0%|

## fullbogons

[Team-Cymru.org](http://www.team-cymru.org) IP space that has been allocated to an RIR, but not assigned by that RIR to an actual ISP or other end-user - **excellent list - use it only your internet interface**

Source is downloaded from [this link](http://www.team-cymru.org/Services/Bogons/fullbogons-ipv4.txt).

The last time downloaded was found to be dated: Sat Jun  6 09:35:12 UTC 2015.

The ipset `fullbogons` has **3721** entries, **670267288** unique IPs.

The following table shows the overlaps of `fullbogons` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `fullbogons`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `fullbogons`.
- ` this % ` is the percentage **of this ipset (`fullbogons`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[bogons](#bogons)|13|592708608|592708608|100.0%|88.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|4235823|3.0%|0.6%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|565248|6.1%|0.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|249087|0.0%|0.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|239993|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|151552|0.8%|0.0%|
[et_block](#et_block)|1023|18338662|20480|0.1%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|890|0.2%|0.0%|
[voipbl](#voipbl)|10476|10476,10888|319|2.9%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|33|2.2%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|15|0.0%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|9|0.6%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|2|0.0%|0.0%|
[php_harvesters](#php_harvesters)|311|311|1|0.3%|0.0%|
[php_commenters](#php_commenters)|349|349|1|0.2%|0.0%|
[ciarmy](#ciarmy)|412|412|1|0.2%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1821|1821|1|0.0%|0.0%|

## ib_bluetack_badpeers

[iBlocklist.com](https://www.iblocklist.com/) free version of [BlueTack.co.uk](http://www.bluetack.co.uk/) IPs that have been reported for bad deeds in p2p

Source is downloaded from [this link](http://list.iblocklist.com/?list=cwworuawihqvocglcoss&fileformat=p2p&archiveformat=gz).

The last time downloaded was found to be dated: Sat Jun  6 04:51:01 UTC 2015.

The ipset `ib_bluetack_badpeers` has **48134** entries, **48134** unique IPs.

The following table shows the overlaps of `ib_bluetack_badpeers` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ib_bluetack_badpeers`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ib_bluetack_badpeers`.
- ` this % ` is the percentage **of this ipset (`ib_bluetack_badpeers`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|1172|0.0%|2.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|406|0.0%|0.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|230|0.0%|0.4%|
[sorbs_spam](#sorbs_spam)|31523|31523,32638|15|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|31523|31523,32638|15|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|31523|31523,32638|15|0.0%|0.0%|
[nixspam](#nixspam)|19062|19062|15|0.0%|0.0%|
[fullbogons](#fullbogons)|3721|670267288|15|0.0%|0.0%|
[alienvault_reputation](#alienvault_reputation)|182275|182275|15|0.0%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|14|0.0%|0.0%|
[blocklist_de](#blocklist_de)|26256|26256|13|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|11|1.6%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|15244|15244|7|0.0%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|6|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|6|0.0%|0.0%|
[et_block](#et_block)|1023|18338662|6|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|3893|3893|6|0.1%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|4|0.0%|0.0%|
[dshield](#dshield)|19|19,5120|4|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|16558|16558|4|0.0%|0.0%|
[xroxy](#xroxy)|2107|2107|3|0.1%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6675|6675|3|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|6664|6664|3|0.0%|0.0%|
[php_dictionary](#php_dictionary)|545|545|3|0.5%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|1605|1605|3|0.1%|0.0%|
[voipbl](#voipbl)|10476|10476,10888|2|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9943|9943|2|0.0%|0.0%|
[php_harvesters](#php_harvesters)|311|311|2|0.6%|0.0%|
[sorbs_web](#sorbs_web)|693|693,694|1|0.1%|0.0%|
[proxz](#proxz)|906|906|1|0.1%|0.0%|
[proxyrss](#proxyrss)|1416|1416|1|0.0%|0.0%|
[php_spammers](#php_spammers)|536|536|1|0.1%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1659|1659|1|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|2967|2967|1|0.0%|0.0%|

## ib_bluetack_hijacked

[iBlocklist.com](https://www.iblocklist.com/) free version of [BlueTack.co.uk](http://www.bluetack.co.uk/) hijacked IP-Blocks Hijacked IP space are IP blocks that are being used without permission

Source is downloaded from [this link](http://list.iblocklist.com/?list=usrcshglbiilevmyfhse&fileformat=p2p&archiveformat=gz).

The last time downloaded was found to be dated: Sat Jun  6 05:20:02 UTC 2015.

The ipset `ib_bluetack_hijacked` has **535** entries, **9177856** unique IPs.

The following table shows the overlaps of `ib_bluetack_hijacked` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ib_bluetack_hijacked`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ib_bluetack_hijacked`.
- ` this % ` is the percentage **of this ipset (`ib_bluetack_hijacked`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[et_block](#et_block)|1023|18338662|7079936|38.6%|77.1%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|6998016|38.0%|76.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|2526625|0.7%|27.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|904796|0.1%|9.8%|
[fullbogons](#fullbogons)|3721|670267288|565248|0.0%|6.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|145472|0.1%|1.5%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1036|0.3%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|744|0.7%|0.0%|
[alienvault_reputation](#alienvault_reputation)|182275|182275|516|0.2%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|153|0.5%|0.0%|
[blocklist_de](#blocklist_de)|26256|26256|50|0.1%|0.0%|
[nixspam](#nixspam)|19062|19062|39|0.2%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|2967|2967|36|1.2%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|27|2.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6675|6675|20|0.2%|0.0%|
[openbl_60d](#openbl_60d)|7286|7286|17|0.2%|0.0%|
[openbl_30d](#openbl_30d)|3252|3252|13|0.3%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9943|9943|12|0.1%|0.0%|
[zeus_badips](#zeus_badips)|202|202|10|4.9%|0.0%|
[zeus](#zeus)|232|232|10|4.3%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|7|0.4%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|16558|16558|6|0.0%|0.0%|
[sorbs_spam](#sorbs_spam)|31523|31523,32638|5|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|31523|31523,32638|5|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|31523|31523,32638|5|0.0%|0.0%|
[openbl_7d](#openbl_7d)|843|843|5|0.5%|0.0%|
[et_compromised](#et_compromised)|2016|2016|5|0.2%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1821|1821|5|0.2%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1659|1659|5|0.3%|0.0%|
[dm_tor](#dm_tor)|6512|6512|4|0.0%|0.0%|
[bm_tor](#bm_tor)|6516|6516|4|0.0%|0.0%|
[et_tor](#et_tor)|6470|6470|3|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|177|177|3|1.6%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|15244|15244|3|0.0%|0.0%|
[shunlist](#shunlist)|1215|1215|2|0.1%|0.0%|
[php_spammers](#php_spammers)|536|536|2|0.3%|0.0%|
[php_dictionary](#php_dictionary)|545|545|2|0.3%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|2|0.2%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|3893|3893|2|0.0%|0.0%|
[voipbl](#voipbl)|10476|10476,10888|1|0.0%|0.0%|
[php_harvesters](#php_harvesters)|311|311|1|0.3%|0.0%|
[php_commenters](#php_commenters)|349|349|1|0.2%|0.0%|
[openbl_1d](#openbl_1d)|146|146|1|0.6%|0.0%|
[et_botcc](#et_botcc)|509|509|1|0.1%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|1605|1605|1|0.0%|0.0%|

## ib_bluetack_level1

[iBlocklist.com](https://www.iblocklist.com/) free version of [BlueTack.co.uk](http://www.bluetack.co.uk/) Level 1 (for use in p2p): Companies or organizations who are clearly involved with trying to stop filesharing (e.g. Baytsp, MediaDefender, Mediasentry a.o.). Companies which anti-p2p activity has been seen from. Companies that produce or have a strong financial interest in copyrighted material (e.g. music, movie, software industries a.o.). Government ranges or companies that have a strong financial interest in doing work for governments. Legal industry ranges. IPs or ranges of ISPs from which anti-p2p activity has been observed. Basically this list will block all kinds of internet connections that most people would rather not have during their internet travels.

Source is downloaded from [this link](http://list.iblocklist.com/?list=ydxerpxkpcfqjaybcssw&fileformat=p2p&archiveformat=gz).

The last time downloaded was found to be dated: Sat Jun  6 09:21:15 UTC 2015.

The ipset `ib_bluetack_level1` has **218309** entries, **764987411** unique IPs.

The following table shows the overlaps of `ib_bluetack_level1` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ib_bluetack_level1`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ib_bluetack_level1`.
- ` this % ` is the percentage **of this ipset (`ib_bluetack_level1`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|16300309|4.6%|2.1%|
[et_block](#et_block)|1023|18338662|2272276|12.3%|0.2%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|2272265|12.3%|0.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|1354348|0.9%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|904796|9.8%|0.1%|
[fullbogons](#fullbogons)|3721|670267288|239993|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|33155|6.8%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|13248|3.9%|0.0%|
[alienvault_reputation](#alienvault_reputation)|182275|182275|4688|2.5%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|1543|1.6%|0.0%|
[blocklist_de](#blocklist_de)|26256|26256|1496|5.6%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|16558|16558|1375|8.3%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|15244|15244|1327|8.7%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|568|1.8%|0.0%|
[sorbs_spam](#sorbs_spam)|31523|31523,32638|505|1.5%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|31523|31523,32638|505|1.5%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|31523|31523,32638|505|1.5%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|406|0.8%|0.0%|
[voipbl](#voipbl)|10476|10476,10888|297|2.7%|0.0%|
[dshield](#dshield)|19|19,5120|267|5.2%|0.0%|
[nixspam](#nixspam)|19062|19062|246|1.2%|0.0%|
[et_tor](#et_tor)|6470|6470|168|2.5%|0.0%|
[openbl_60d](#openbl_60d)|7286|7286|167|2.2%|0.0%|
[dm_tor](#dm_tor)|6512|6512|162|2.4%|0.0%|
[bm_tor](#bm_tor)|6516|6516|162|2.4%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6675|6675|139|2.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|6664|6664|134|2.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|97|6.6%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9943|9943|78|0.7%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2475|2475|78|3.1%|0.0%|
[openbl_30d](#openbl_30d)|3252|3252|71|2.1%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|66|5.1%|0.0%|
[xroxy](#xroxy)|2107|2107|58|2.7%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|58|8.6%|0.0%|
[et_compromised](#et_compromised)|2016|2016|52|2.5%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1821|1821|47|2.5%|0.0%|
[proxyrss](#proxyrss)|1416|1416|45|3.1%|0.0%|
[et_botcc](#et_botcc)|509|509|41|8.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|3893|3893|36|0.9%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|2967|2967|33|1.1%|0.0%|
[proxz](#proxz)|906|906|31|3.4%|0.0%|
[ciarmy](#ciarmy)|412|412|30|7.2%|0.0%|
[shunlist](#shunlist)|1215|1215|28|2.3%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1659|1659|25|1.5%|0.0%|
[sorbs_web](#sorbs_web)|693|693,694|22|3.1%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|1605|1605|21|1.3%|0.0%|
[openbl_7d](#openbl_7d)|843|843|19|2.2%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|17|4.5%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|830|830|14|1.6%|0.0%|
[php_dictionary](#php_dictionary)|545|545|11|2.0%|0.0%|
[malc0de](#malc0de)|361|361|11|3.0%|0.0%|
[php_harvesters](#php_harvesters)|311|311|9|2.8%|0.0%|
[php_commenters](#php_commenters)|349|349|8|2.2%|0.0%|
[php_spammers](#php_spammers)|536|536|7|1.3%|0.0%|
[zeus](#zeus)|232|232|6|2.5%|0.0%|
[bogons](#bogons)|13|592708608|5|0.0%|0.0%|
[zeus_badips](#zeus_badips)|202|202|4|1.9%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|91|91|4|4.3%|0.0%|
[sslbl](#sslbl)|369|369|3|0.8%|0.0%|
[openbl_1d](#openbl_1d)|146|146|3|2.0%|0.0%|
[feodo](#feodo)|99|99|3|3.0%|0.0%|
[virbl](#virbl)|4|4|1|25.0%|0.0%|
[sorbs_socks](#sorbs_socks)|22|22,22|1|4.5%|0.0%|
[sorbs_misc](#sorbs_misc)|22|22,22|1|4.5%|0.0%|
[sorbs_http](#sorbs_http)|22|22,22|1|4.5%|0.0%|

## ib_bluetack_level2

[iBlocklist.com](https://www.iblocklist.com/) free version of BlueTack.co.uk Level 2 (for use in p2p). General corporate ranges. Ranges used by labs or researchers. Proxies.

Source is downloaded from [this link](http://list.iblocklist.com/?list=gyisgnzbhppbvsphucsw&fileformat=p2p&archiveformat=gz).

The last time downloaded was found to be dated: Sat Jun  6 05:22:18 UTC 2015.

The ipset `ib_bluetack_level2` has **72774** entries, **348707599** unique IPs.

The following table shows the overlaps of `ib_bluetack_level2` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ib_bluetack_level2`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ib_bluetack_level2`.
- ` this % ` is the percentage **of this ipset (`ib_bluetack_level2`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|16300309|2.1%|4.6%|
[et_block](#et_block)|1023|18338662|8598311|46.8%|2.4%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|8598042|46.7%|2.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|2830140|2.0%|0.8%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2526625|27.5%|0.7%|
[fullbogons](#fullbogons)|3721|670267288|249087|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|98904|20.2%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|7733|2.2%|0.0%|
[alienvault_reputation](#alienvault_reputation)|182275|182275|7535|4.1%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|2524|2.7%|0.0%|
[blocklist_de](#blocklist_de)|26256|26256|1425|5.4%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|16558|16558|1140|6.8%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|15244|15244|1087|7.1%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|909|3.0%|0.0%|
[sorbs_spam](#sorbs_spam)|31523|31523,32638|810|2.4%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|31523|31523,32638|810|2.4%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|31523|31523,32638|810|2.4%|0.0%|
[nixspam](#nixspam)|19062|19062|456|2.3%|0.0%|
[voipbl](#voipbl)|10476|10476,10888|434|3.9%|0.0%|
[openbl_60d](#openbl_60d)|7286|7286|327|4.4%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|230|0.4%|0.0%|
[ri_web_proxies](#ri_web_proxies)|6664|6664|195|2.9%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6675|6675|192|2.8%|0.0%|
[et_tor](#et_tor)|6470|6470|190|2.9%|0.0%|
[dm_tor](#dm_tor)|6512|6512|190|2.9%|0.0%|
[bm_tor](#bm_tor)|6516|6516|190|2.9%|0.0%|
[openbl_30d](#openbl_30d)|3252|3252|169|5.1%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|2967|2967|120|4.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9943|9943|103|1.0%|0.0%|
[xroxy](#xroxy)|2107|2107|101|4.7%|0.0%|
[et_compromised](#et_compromised)|2016|2016|97|4.8%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2475|2475|96|3.8%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1821|1821|90|4.9%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1659|1659|84|5.0%|0.0%|
[shunlist](#shunlist)|1215|1215|68|5.5%|0.0%|
[proxyrss](#proxyrss)|1416|1416|64|4.5%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|3893|3893|56|1.4%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|1605|1605|49|3.0%|0.0%|
[php_spammers](#php_spammers)|536|536|45|8.3%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|45|3.0%|0.0%|
[openbl_7d](#openbl_7d)|843|843|43|5.1%|0.0%|
[ciarmy](#ciarmy)|412|412|43|10.4%|0.0%|
[proxz](#proxz)|906|906|37|4.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|28|4.1%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|26|2.0%|0.0%|
[sorbs_web](#sorbs_web)|693|693,694|25|3.6%|0.0%|
[et_botcc](#et_botcc)|509|509|22|4.3%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|21|5.6%|0.0%|
[malc0de](#malc0de)|361|361|21|5.8%|0.0%|
[php_dictionary](#php_dictionary)|545|545|17|3.1%|0.0%|
[php_commenters](#php_commenters)|349|349|14|4.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|830|830|13|1.5%|0.0%|
[zeus](#zeus)|232|232|9|3.8%|0.0%|
[php_harvesters](#php_harvesters)|311|311|9|2.8%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|168|168|9|5.3%|0.0%|
[zeus_badips](#zeus_badips)|202|202|8|3.9%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|177|177|8|4.5%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|91|91|7|7.6%|0.0%|
[openbl_1d](#openbl_1d)|146|146|6|4.1%|0.0%|
[sslbl](#sslbl)|369|369|5|1.3%|0.0%|
[feodo](#feodo)|99|99|3|3.0%|0.0%|
[palevo](#palevo)|13|13|2|15.3%|0.0%|
[sorbs_socks](#sorbs_socks)|22|22,22|1|4.5%|0.0%|
[sorbs_smtp](#sorbs_smtp)|14|14,14|1|7.1%|0.0%|
[sorbs_misc](#sorbs_misc)|22|22,22|1|4.5%|0.0%|
[sorbs_http](#sorbs_http)|22|22,22|1|4.5%|0.0%|

## ib_bluetack_level3

[iBlocklist.com](https://www.iblocklist.com/) free version of BlueTack.co.uk Level 3 (for use in p2p). Many portal-type websites. ISP ranges that may be dodgy for some reason. Ranges that belong to an individual, but which have not been determined to be used by a particular company. Ranges for things that are unusual in some way. The L3 list is aka the paranoid list.

Source is downloaded from [this link](http://list.iblocklist.com/?list=uwnukjqktoggdknzrhgh&fileformat=p2p&archiveformat=gz).

The last time downloaded was found to be dated: Sat Jun  6 05:20:06 UTC 2015.

The ipset `ib_bluetack_level3` has **17802** entries, **139104824** unique IPs.

The following table shows the overlaps of `ib_bluetack_level3` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ib_bluetack_level3`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ib_bluetack_level3`.
- ` this % ` is the percentage **of this ipset (`ib_bluetack_level3`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[fullbogons](#fullbogons)|3721|670267288|4235823|0.6%|3.0%|
[bogons](#bogons)|13|592708608|4194304|0.7%|3.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|2830140|0.8%|2.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|1354348|0.1%|0.9%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|270785|55.5%|0.1%|
[et_block](#et_block)|1023|18338662|195933|1.0%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|145472|1.5%|0.1%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|130368|0.7%|0.0%|
[alienvault_reputation](#alienvault_reputation)|182275|182275|14152|7.7%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|9231|2.7%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|5841|6.2%|0.0%|
[blocklist_de](#blocklist_de)|26256|26256|3378|12.8%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|16558|16558|2608|15.7%|0.0%|
[sorbs_spam](#sorbs_spam)|31523|31523,32638|2393|7.3%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|31523|31523,32638|2393|7.3%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|31523|31523,32638|2393|7.3%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|15244|15244|2384|15.6%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|1912|6.3%|0.0%|
[voipbl](#voipbl)|10476|10476,10888|1599|14.6%|0.0%|
[nixspam](#nixspam)|19062|19062|1439|7.5%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1172|2.4%|0.0%|
[openbl_60d](#openbl_60d)|7286|7286|746|10.2%|0.0%|
[et_tor](#et_tor)|6470|6470|633|9.7%|0.0%|
[dm_tor](#dm_tor)|6512|6512|627|9.6%|0.0%|
[bm_tor](#bm_tor)|6516|6516|627|9.6%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6675|6675|512|7.6%|0.0%|
[openbl_30d](#openbl_30d)|3252|3252|313|9.6%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|3893|3893|284|7.2%|0.0%|
[dshield](#dshield)|19|19,5120|256|5.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9943|9943|232|2.3%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|2967|2967|200|6.7%|0.0%|
[et_compromised](#et_compromised)|2016|2016|199|9.8%|0.0%|
[ri_web_proxies](#ri_web_proxies)|6664|6664|192|2.8%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1821|1821|173|9.5%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1659|1659|166|10.0%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|147|11.4%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|1605|1605|133|8.2%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|125|33.6%|0.0%|
[openbl_7d](#openbl_7d)|843|843|115|13.6%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|110|7.5%|0.0%|
[shunlist](#shunlist)|1215|1215|108|8.8%|0.0%|
[xroxy](#xroxy)|2107|2107|97|4.6%|0.0%|
[ciarmy](#ciarmy)|412|412|80|19.4%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|830|830|79|9.5%|0.0%|
[et_botcc](#et_botcc)|509|509|78|15.3%|0.0%|
[proxz](#proxz)|906|906|73|8.0%|0.0%|
[malc0de](#malc0de)|361|361|54|14.9%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2475|2475|53|2.1%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|51|7.5%|0.0%|
[sorbs_web](#sorbs_web)|693|693,694|49|7.0%|0.0%|
[proxyrss](#proxyrss)|1416|1416|49|3.4%|0.0%|
[php_spammers](#php_spammers)|536|536|31|5.7%|0.0%|
[php_dictionary](#php_dictionary)|545|545|31|5.6%|0.0%|
[sslbl](#sslbl)|369|369|26|7.0%|0.0%|
[php_commenters](#php_commenters)|349|349|22|6.3%|0.0%|
[php_harvesters](#php_harvesters)|311|311|17|5.4%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|168|168|17|10.1%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|177|177|16|9.0%|0.0%|
[zeus](#zeus)|232|232|14|6.0%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|91|91|13|14.2%|0.0%|
[openbl_1d](#openbl_1d)|146|146|11|7.5%|0.0%|
[feodo](#feodo)|99|99|11|11.1%|0.0%|
[zeus_badips](#zeus_badips)|202|202|10|4.9%|0.0%|
[palevo](#palevo)|13|13|1|7.6%|0.0%|

## ib_bluetack_proxies

[iBlocklist.com](https://www.iblocklist.com/) free version of [BlueTack.co.uk](http://www.bluetack.co.uk/) Open Proxies IPs list (without TOR)

Source is downloaded from [this link](http://list.iblocklist.com/?list=xoebmbyexwuiogmbyprb&fileformat=p2p&archiveformat=gz).

The last time downloaded was found to be dated: Sat Jun  6 05:20:03 UTC 2015.

The ipset `ib_bluetack_proxies` has **673** entries, **673** unique IPs.

The following table shows the overlaps of `ib_bluetack_proxies` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ib_bluetack_proxies`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ib_bluetack_proxies`.
- ` this % ` is the percentage **of this ipset (`ib_bluetack_proxies`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|58|0.0%|8.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|51|0.0%|7.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|28|0.0%|4.1%|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|22|0.0%|3.2%|
[xroxy](#xroxy)|2107|2107|13|0.6%|1.9%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|12|0.0%|1.7%|
[ri_web_proxies](#ri_web_proxies)|6664|6664|12|0.1%|1.7%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|11|0.0%|1.6%|
[proxyrss](#proxyrss)|1416|1416|9|0.6%|1.3%|
[ri_connect_proxies](#ri_connect_proxies)|2475|2475|7|0.2%|1.0%|
[proxz](#proxz)|906|906|6|0.6%|0.8%|
[stopforumspam_1d](#stopforumspam_1d)|6675|6675|3|0.0%|0.4%|
[blocklist_de_bots](#blocklist_de_bots)|2967|2967|3|0.1%|0.4%|
[blocklist_de](#blocklist_de)|26256|26256|3|0.0%|0.4%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|2|0.0%|0.2%|
[sorbs_spam](#sorbs_spam)|31523|31523,32638|2|0.0%|0.2%|
[sorbs_recent_spam](#sorbs_recent_spam)|31523|31523,32638|2|0.0%|0.2%|
[sorbs_new_spam](#sorbs_new_spam)|31523|31523,32638|2|0.0%|0.2%|
[nixspam](#nixspam)|19062|19062|2|0.0%|0.2%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2|0.0%|0.2%|
[et_block](#et_block)|1023|18338662|2|0.0%|0.2%|
[php_dictionary](#php_dictionary)|545|545|1|0.1%|0.1%|
[alienvault_reputation](#alienvault_reputation)|182275|182275|1|0.0%|0.1%|

## ib_bluetack_spyware

[iBlocklist.com](https://www.iblocklist.com/) free version of [BlueTack.co.uk](http://www.bluetack.co.uk/) known malicious SPYWARE and ADWARE IP Address ranges

Source is downloaded from [this link](http://list.iblocklist.com/?list=llvtlsjyoyiczbkjsxpf&fileformat=p2p&archiveformat=gz).

The last time downloaded was found to be dated: Sat Jun  6 04:50:03 UTC 2015.

The ipset `ib_bluetack_spyware` has **3274** entries, **339192** unique IPs.

The following table shows the overlaps of `ib_bluetack_spyware` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ib_bluetack_spyware`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ib_bluetack_spyware`.
- ` this % ` is the percentage **of this ipset (`ib_bluetack_spyware`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|13248|0.0%|3.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|9231|0.0%|2.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|7733|0.0%|2.2%|
[et_block](#et_block)|1023|18338662|1040|0.0%|0.3%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|1037|0.0%|0.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1036|0.0%|0.3%|
[fullbogons](#fullbogons)|3721|670267288|890|0.0%|0.2%|
[alienvault_reputation](#alienvault_reputation)|182275|182275|286|0.1%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|46|0.0%|0.0%|
[sorbs_spam](#sorbs_spam)|31523|31523,32638|33|0.1%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|31523|31523,32638|33|0.1%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|31523|31523,32638|33|0.1%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|27|2.0%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|25|0.0%|0.0%|
[et_tor](#et_tor)|6470|6470|22|0.3%|0.0%|
[dm_tor](#dm_tor)|6512|6512|22|0.3%|0.0%|
[bm_tor](#bm_tor)|6516|6516|22|0.3%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|19|1.3%|0.0%|
[nixspam](#nixspam)|19062|19062|15|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9943|9943|14|0.1%|0.0%|
[blocklist_de](#blocklist_de)|26256|26256|10|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6675|6675|6|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|6664|6664|5|0.0%|0.0%|
[openbl_60d](#openbl_60d)|7286|7286|5|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|5|1.3%|0.0%|
[voipbl](#voipbl)|10476|10476,10888|4|0.0%|0.0%|
[openbl_30d](#openbl_30d)|3252|3252|4|0.1%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|4|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|2967|2967|4|0.1%|0.0%|
[malc0de](#malc0de)|361|361|3|0.8%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|168|168|3|1.7%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1821|1821|3|0.1%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|15244|15244|3|0.0%|0.0%|
[et_compromised](#et_compromised)|2016|2016|2|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1659|1659|2|0.1%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|91|91|2|2.1%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|16558|16558|2|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|3893|3893|2|0.0%|0.0%|
[zeus_badips](#zeus_badips)|202|202|1|0.4%|0.0%|
[zeus](#zeus)|232|232|1|0.4%|0.0%|
[xroxy](#xroxy)|2107|2107|1|0.0%|0.0%|
[sslbl](#sslbl)|369|369|1|0.2%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|1|0.0%|0.0%|
[shunlist](#shunlist)|1215|1215|1|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2475|2475|1|0.0%|0.0%|
[php_harvesters](#php_harvesters)|311|311|1|0.3%|0.0%|
[php_dictionary](#php_dictionary)|545|545|1|0.1%|0.0%|
[palevo](#palevo)|13|13|1|7.6%|0.0%|
[openbl_7d](#openbl_7d)|843|843|1|0.1%|0.0%|
[feodo](#feodo)|99|99|1|1.0%|0.0%|
[ciarmy](#ciarmy)|412|412|1|0.2%|0.0%|
[bogons](#bogons)|13|592708608|1|0.0%|0.0%|

## ib_bluetack_webexploit

[iBlocklist.com](https://www.iblocklist.com/) free version of [BlueTack.co.uk](http://www.bluetack.co.uk/) web server hack and exploit attempts

Source is downloaded from [this link](http://list.iblocklist.com/?list=ghlzqtqxnzctvvajwwag&fileformat=p2p&archiveformat=gz).

The last time downloaded was found to be dated: Sat Jun  6 04:50:23 UTC 2015.

The ipset `ib_bluetack_webexploit` has **1460** entries, **1460** unique IPs.

The following table shows the overlaps of `ib_bluetack_webexploit` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ib_bluetack_webexploit`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ib_bluetack_webexploit`.
- ` this % ` is the percentage **of this ipset (`ib_bluetack_webexploit`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|110|0.0%|7.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|97|0.0%|6.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|45|0.0%|3.0%|
[fullbogons](#fullbogons)|3721|670267288|33|0.0%|2.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|19|0.0%|1.3%|
[alienvault_reputation](#alienvault_reputation)|182275|182275|8|0.0%|0.5%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|7|0.0%|0.4%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|6|0.0%|0.4%|
[et_block](#et_block)|1023|18338662|6|0.0%|0.4%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|3|0.2%|0.2%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|2|0.0%|0.1%|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|2|0.0%|0.1%|
[stopforumspam_1d](#stopforumspam_1d)|6675|6675|2|0.0%|0.1%|
[openbl_60d](#openbl_60d)|7286|7286|2|0.0%|0.1%|
[openbl_30d](#openbl_30d)|3252|3252|2|0.0%|0.1%|
[nixspam](#nixspam)|19062|19062|2|0.0%|0.1%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|2|0.2%|0.1%|
[blocklist_de](#blocklist_de)|26256|26256|2|0.0%|0.1%|
[snort_ipfilter](#snort_ipfilter)|9943|9943|1|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|6664|6664|1|0.0%|0.0%|
[openbl_7d](#openbl_7d)|843|843|1|0.1%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1|0.0%|0.0%|
[et_botcc](#et_botcc)|509|509|1|0.1%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|177|177|1|0.5%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1659|1659|1|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|2967|2967|1|0.0%|0.0%|

## malc0de

[Malc0de.com](http://malc0de.com) malicious IPs of the last 30 days

Source is downloaded from [this link](http://malc0de.com/bl/IP_Blacklist.txt).

The last time downloaded was found to be dated: Sat Jun  6 13:17:03 UTC 2015.

The ipset `malc0de` has **361** entries, **361** unique IPs.

The following table shows the overlaps of `malc0de` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `malc0de`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `malc0de`.
- ` this % ` is the percentage **of this ipset (`malc0de`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|54|0.0%|14.9%|
[cleanmx_viruses](#cleanmx_viruses)|168|168|27|16.0%|7.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|21|0.0%|5.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|11|0.0%|3.0%|
[alienvault_reputation](#alienvault_reputation)|182275|182275|11|0.0%|3.0%|
[et_block](#et_block)|1023|18338662|5|0.0%|1.3%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|4|0.0%|1.1%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|4|0.3%|1.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|3|0.0%|0.8%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|1|0.0%|0.2%|
[dshield](#dshield)|19|19,5120|1|0.0%|0.2%|

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
[et_block](#et_block)|1023|18338662|29|0.0%|2.2%|
[snort_ipfilter](#snort_ipfilter)|9943|9943|28|0.2%|2.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|27|0.0%|2.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|27|0.0%|2.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|26|0.0%|2.0%|
[fullbogons](#fullbogons)|3721|670267288|9|0.0%|0.6%|
[alienvault_reputation](#alienvault_reputation)|182275|182275|6|0.0%|0.4%|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|4|0.0%|0.3%|
[malc0de](#malc0de)|361|361|4|1.1%|0.3%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|3|0.2%|0.2%|
[sorbs_spam](#sorbs_spam)|31523|31523,32638|2|0.0%|0.1%|
[sorbs_recent_spam](#sorbs_recent_spam)|31523|31523,32638|2|0.0%|0.1%|
[sorbs_new_spam](#sorbs_new_spam)|31523|31523,32638|2|0.0%|0.1%|
[cleanmx_viruses](#cleanmx_viruses)|168|168|2|1.1%|0.1%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|1|0.0%|0.0%|
[nixspam](#nixspam)|19062|19062|1|0.0%|0.0%|
[et_botcc](#et_botcc)|509|509|1|0.1%|0.0%|
[dshield](#dshield)|19|19,5120|1|0.0%|0.0%|

## maxmind_proxy_fraud

[MaxMind.com](https://www.maxmind.com/en/anonymous-proxy-fraudulent-ip-address-list) list of anonymous proxy fraudelent IP addresses.

Source is downloaded from [this link](https://www.maxmind.com/en/anonymous-proxy-fraudulent-ip-address-list).

The last time downloaded was found to be dated: Sat Jun  6 14:54:19 UTC 2015.

The ipset `maxmind_proxy_fraud` has **372** entries, **372** unique IPs.

The following table shows the overlaps of `maxmind_proxy_fraud` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `maxmind_proxy_fraud`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `maxmind_proxy_fraud`.
- ` this % ` is the percentage **of this ipset (`maxmind_proxy_fraud`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|231|0.2%|62.0%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|191|0.6%|51.3%|
[snort_ipfilter](#snort_ipfilter)|9943|9943|177|1.7%|47.5%|
[et_tor](#et_tor)|6470|6470|168|2.5%|45.1%|
[dm_tor](#dm_tor)|6512|6512|166|2.5%|44.6%|
[bm_tor](#bm_tor)|6516|6516|166|2.5%|44.6%|
[stopforumspam_1d](#stopforumspam_1d)|6675|6675|165|2.4%|44.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|125|0.0%|33.6%|
[php_commenters](#php_commenters)|349|349|34|9.7%|9.1%|
[alienvault_reputation](#alienvault_reputation)|182275|182275|26|0.0%|6.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|21|0.0%|5.6%|
[openbl_60d](#openbl_60d)|7286|7286|18|0.2%|4.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|17|0.0%|4.5%|
[php_harvesters](#php_harvesters)|311|311|6|1.9%|1.6%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|5|0.0%|1.3%|
[ri_web_proxies](#ri_web_proxies)|6664|6664|4|0.0%|1.0%|
[php_spammers](#php_spammers)|536|536|4|0.7%|1.0%|
[php_dictionary](#php_dictionary)|545|545|4|0.7%|1.0%|
[blocklist_de](#blocklist_de)|26256|26256|3|0.0%|0.8%|
[blocklist_de_apache](#blocklist_de_apache)|15244|15244|2|0.0%|0.5%|
[xroxy](#xroxy)|2107|2107|1|0.0%|0.2%|
[voipbl](#voipbl)|10476|10476,10888|1|0.0%|0.2%|
[shunlist](#shunlist)|1215|1215|1|0.0%|0.2%|
[ri_connect_proxies](#ri_connect_proxies)|2475|2475|1|0.0%|0.2%|
[et_block](#et_block)|1023|18338662|1|0.0%|0.2%|
[dshield](#dshield)|19|19,5120|1|0.0%|0.2%|
[blocklist_de_ssh](#blocklist_de_ssh)|1659|1659|1|0.0%|0.2%|
[blocklist_de_mail](#blocklist_de_mail)|16558|16558|1|0.0%|0.2%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|3893|3893|1|0.0%|0.2%|

## nixspam

[NiX Spam](http://www.heise.de/ix/NiX-Spam-DNSBL-and-blacklist-for-download-499637.html) IP addresses that sent spam in the last hour - automatically generated entries without distinguishing open proxies from relays, dialup gateways, and so on. All IPs are removed after 12 hours if there is no spam from there.

Source is downloaded from [this link](http://www.dnsbl.manitu.net/download/nixspam-ip.dump.gz).

The last time downloaded was found to be dated: Sat Jun  6 18:45:02 UTC 2015.

The ipset `nixspam` has **19062** entries, **19062** unique IPs.

The following table shows the overlaps of `nixspam` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `nixspam`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `nixspam`.
- ` this % ` is the percentage **of this ipset (`nixspam`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[sorbs_spam](#sorbs_spam)|31523|31523,32638|3071|9.4%|16.1%|
[sorbs_recent_spam](#sorbs_recent_spam)|31523|31523,32638|3071|9.4%|16.1%|
[sorbs_new_spam](#sorbs_new_spam)|31523|31523,32638|3071|9.4%|16.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|1439|0.0%|7.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|456|0.0%|2.3%|
[blocklist_de](#blocklist_de)|26256|26256|390|1.4%|2.0%|
[blocklist_de_mail](#blocklist_de_mail)|16558|16558|326|1.9%|1.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|246|0.0%|1.2%|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|155|0.1%|0.8%|
[snort_ipfilter](#snort_ipfilter)|9943|9943|105|1.0%|0.5%|
[sorbs_web](#sorbs_web)|693|693,694|98|14.1%|0.5%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|84|0.2%|0.4%|
[php_dictionary](#php_dictionary)|545|545|61|11.1%|0.3%|
[ri_web_proxies](#ri_web_proxies)|6664|6664|56|0.8%|0.2%|
[php_spammers](#php_spammers)|536|536|53|9.8%|0.2%|
[stopforumspam_1d](#stopforumspam_1d)|6675|6675|45|0.6%|0.2%|
[et_block](#et_block)|1023|18338662|44|0.0%|0.2%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|41|0.0%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|39|0.0%|0.2%|
[alienvault_reputation](#alienvault_reputation)|182275|182275|34|0.0%|0.1%|
[xroxy](#xroxy)|2107|2107|32|1.5%|0.1%|
[blocklist_de_apache](#blocklist_de_apache)|15244|15244|31|0.2%|0.1%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|3893|3893|30|0.7%|0.1%|
[blocklist_de_bots](#blocklist_de_bots)|2967|2967|25|0.8%|0.1%|
[blocklist_de_imap](#blocklist_de_imap)|1605|1605|21|1.3%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|15|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|15|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2475|2475|12|0.4%|0.0%|
[proxz](#proxz)|906|906|11|1.2%|0.0%|
[openbl_60d](#openbl_60d)|7286|7286|11|0.1%|0.0%|
[proxyrss](#proxyrss)|1416|1416|9|0.6%|0.0%|
[php_commenters](#php_commenters)|349|349|8|2.2%|0.0%|
[openbl_30d](#openbl_30d)|3252|3252|6|0.1%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|830|830|5|0.6%|0.0%|
[sorbs_socks](#sorbs_socks)|22|22,22|4|18.1%|0.0%|
[sorbs_misc](#sorbs_misc)|22|22,22|4|18.1%|0.0%|
[sorbs_http](#sorbs_http)|22|22,22|4|18.1%|0.0%|
[php_harvesters](#php_harvesters)|311|311|4|1.2%|0.0%|
[openbl_7d](#openbl_7d)|843|843|3|0.3%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|2|0.2%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1659|1659|2|0.1%|0.0%|
[sorbs_smtp](#sorbs_smtp)|14|14,14|1|7.1%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|1|0.0%|0.0%|
[et_tor](#et_tor)|6470|6470|1|0.0%|0.0%|
[et_compromised](#et_compromised)|2016|2016|1|0.0%|0.0%|
[dshield](#dshield)|19|19,5120|1|0.0%|0.0%|
[dm_tor](#dm_tor)|6512|6512|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1821|1821|1|0.0%|0.0%|
[bm_tor](#bm_tor)|6516|6516|1|0.0%|0.0%|

## openbl_1d

[OpenBL.org](http://www.openbl.org/) last 24 hours IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.

Source is downloaded from [this link](http://www.openbl.org/lists/base_1days.txt).

The last time downloaded was found to be dated: Sat Jun  6 18:32:00 UTC 2015.

The ipset `openbl_1d` has **146** entries, **146** unique IPs.

The following table shows the overlaps of `openbl_1d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl_1d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl_1d`.
- ` this % ` is the percentage **of this ipset (`openbl_1d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[alienvault_reputation](#alienvault_reputation)|182275|182275|143|0.0%|97.9%|
[openbl_60d](#openbl_60d)|7286|7286|141|1.9%|96.5%|
[openbl_30d](#openbl_30d)|3252|3252|141|4.3%|96.5%|
[openbl_7d](#openbl_7d)|843|843|139|16.4%|95.2%|
[blocklist_de](#blocklist_de)|26256|26256|123|0.4%|84.2%|
[blocklist_de_ssh](#blocklist_de_ssh)|1659|1659|120|7.2%|82.1%|
[bruteforceblocker](#bruteforceblocker)|1821|1821|78|4.2%|53.4%|
[et_compromised](#et_compromised)|2016|2016|74|3.6%|50.6%|
[shunlist](#shunlist)|1215|1215|71|5.8%|48.6%|
[blocklist_de_strongips](#blocklist_de_strongips)|177|177|20|11.2%|13.6%|
[et_block](#et_block)|1023|18338662|13|0.0%|8.9%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|12|0.0%|8.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|11|0.0%|7.5%|
[dshield](#dshield)|19|19,5120|9|0.1%|6.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|6|0.0%|4.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|3|0.0%|2.0%|
[blocklist_de_mail](#blocklist_de_mail)|16558|16558|3|0.0%|2.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.6%|
[blocklist_de_imap](#blocklist_de_imap)|1605|1605|1|0.0%|0.6%|

## openbl_30d

[OpenBL.org](http://www.openbl.org/) last 30 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.

Source is downloaded from [this link](http://www.openbl.org/lists/base_30days.txt).

The last time downloaded was found to be dated: Sat Jun  6 15:42:00 UTC 2015.

The ipset `openbl_30d` has **3252** entries, **3252** unique IPs.

The following table shows the overlaps of `openbl_30d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl_30d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl_30d`.
- ` this % ` is the percentage **of this ipset (`openbl_30d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[openbl_60d](#openbl_60d)|7286|7286|3252|44.6%|100.0%|
[alienvault_reputation](#alienvault_reputation)|182275|182275|3237|1.7%|99.5%|
[et_compromised](#et_compromised)|2016|2016|1151|57.0%|35.3%|
[bruteforceblocker](#bruteforceblocker)|1821|1821|1037|56.9%|31.8%|
[openbl_7d](#openbl_7d)|843|843|843|100.0%|25.9%|
[blocklist_de](#blocklist_de)|26256|26256|691|2.6%|21.2%|
[blocklist_de_ssh](#blocklist_de_ssh)|1659|1659|641|38.6%|19.7%|
[shunlist](#shunlist)|1215|1215|527|43.3%|16.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|313|0.0%|9.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|169|0.0%|5.1%|
[et_block](#et_block)|1023|18338662|166|0.0%|5.1%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|160|0.0%|4.9%|
[openbl_1d](#openbl_1d)|146|146|141|96.5%|4.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|71|0.0%|2.1%|
[dshield](#dshield)|19|19,5120|45|0.8%|1.3%|
[blocklist_de_mail](#blocklist_de_mail)|16558|16558|40|0.2%|1.2%|
[blocklist_de_imap](#blocklist_de_imap)|1605|1605|31|1.9%|0.9%|
[blocklist_de_strongips](#blocklist_de_strongips)|177|177|25|14.1%|0.7%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|13|0.0%|0.3%|
[nixspam](#nixspam)|19062|19062|6|0.0%|0.1%|
[blocklist_de_apache](#blocklist_de_apache)|15244|15244|6|0.0%|0.1%|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|5|0.0%|0.1%|
[snort_ipfilter](#snort_ipfilter)|9943|9943|4|0.0%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|4|0.0%|0.1%|
[voipbl](#voipbl)|10476|10476,10888|3|0.0%|0.0%|
[sorbs_spam](#sorbs_spam)|31523|31523,32638|3|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|31523|31523,32638|3|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|31523|31523,32638|3|0.0%|0.0%|
[zeus](#zeus)|232|232|2|0.8%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|2|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|2967|2967|2|0.0%|0.0%|
[zeus_badips](#zeus_badips)|202|202|1|0.4%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6675|6675|1|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|1|0.0%|0.0%|
[sorbs_web](#sorbs_web)|693|693,694|1|0.1%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|830|830|1|0.1%|0.0%|

## openbl_60d

[OpenBL.org](http://www.openbl.org/) last 60 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.

Source is downloaded from [this link](http://www.openbl.org/lists/base_60days.txt).

The last time downloaded was found to be dated: Sat Jun  6 15:42:00 UTC 2015.

The ipset `openbl_60d` has **7286** entries, **7286** unique IPs.

The following table shows the overlaps of `openbl_60d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl_60d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl_60d`.
- ` this % ` is the percentage **of this ipset (`openbl_60d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[alienvault_reputation](#alienvault_reputation)|182275|182275|7266|3.9%|99.7%|
[openbl_30d](#openbl_30d)|3252|3252|3252|100.0%|44.6%|
[et_compromised](#et_compromised)|2016|2016|1217|60.3%|16.7%|
[bruteforceblocker](#bruteforceblocker)|1821|1821|1081|59.3%|14.8%|
[openbl_7d](#openbl_7d)|843|843|843|100.0%|11.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|746|0.0%|10.2%|
[blocklist_de](#blocklist_de)|26256|26256|745|2.8%|10.2%|
[blocklist_de_ssh](#blocklist_de_ssh)|1659|1659|677|40.8%|9.2%|
[shunlist](#shunlist)|1215|1215|542|44.6%|7.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|327|0.0%|4.4%|
[et_block](#et_block)|1023|18338662|250|0.0%|3.4%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|239|0.0%|3.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|167|0.0%|2.2%|
[openbl_1d](#openbl_1d)|146|146|141|96.5%|1.9%|
[dshield](#dshield)|19|19,5120|56|1.0%|0.7%|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|54|0.0%|0.7%|
[blocklist_de_mail](#blocklist_de_mail)|16558|16558|46|0.2%|0.6%|
[blocklist_de_imap](#blocklist_de_imap)|1605|1605|37|2.3%|0.5%|
[snort_ipfilter](#snort_ipfilter)|9943|9943|27|0.2%|0.3%|
[blocklist_de_strongips](#blocklist_de_strongips)|177|177|27|15.2%|0.3%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|25|0.0%|0.3%|
[stopforumspam_1d](#stopforumspam_1d)|6675|6675|20|0.2%|0.2%|
[et_tor](#et_tor)|6470|6470|20|0.3%|0.2%|
[dm_tor](#dm_tor)|6512|6512|19|0.2%|0.2%|
[bm_tor](#bm_tor)|6516|6516|19|0.2%|0.2%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|18|4.8%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|17|0.0%|0.2%|
[sorbs_spam](#sorbs_spam)|31523|31523,32638|14|0.0%|0.1%|
[sorbs_recent_spam](#sorbs_recent_spam)|31523|31523,32638|14|0.0%|0.1%|
[sorbs_new_spam](#sorbs_new_spam)|31523|31523,32638|14|0.0%|0.1%|
[nixspam](#nixspam)|19062|19062|11|0.0%|0.1%|
[blocklist_de_bots](#blocklist_de_bots)|2967|2967|11|0.3%|0.1%|
[php_commenters](#php_commenters)|349|349|9|2.5%|0.1%|
[voipbl](#voipbl)|10476|10476,10888|8|0.0%|0.1%|
[blocklist_de_apache](#blocklist_de_apache)|15244|15244|8|0.0%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|5|0.0%|0.0%|
[zeus](#zeus)|232|232|2|0.8%|0.0%|
[php_harvesters](#php_harvesters)|311|311|2|0.6%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|830|830|2|0.2%|0.0%|
[zeus_badips](#zeus_badips)|202|202|1|0.4%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|1|0.0%|0.0%|
[sorbs_web](#sorbs_web)|693|693,694|1|0.1%|0.0%|

## openbl_7d

[OpenBL.org](http://www.openbl.org/) last 7 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.

Source is downloaded from [this link](http://www.openbl.org/lists/base_7days.txt).

The last time downloaded was found to be dated: Sat Jun  6 15:42:00 UTC 2015.

The ipset `openbl_7d` has **843** entries, **843** unique IPs.

The following table shows the overlaps of `openbl_7d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl_7d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl_7d`.
- ` this % ` is the percentage **of this ipset (`openbl_7d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[openbl_60d](#openbl_60d)|7286|7286|843|11.5%|100.0%|
[openbl_30d](#openbl_30d)|3252|3252|843|25.9%|100.0%|
[alienvault_reputation](#alienvault_reputation)|182275|182275|838|0.4%|99.4%|
[blocklist_de](#blocklist_de)|26256|26256|412|1.5%|48.8%|
[blocklist_de_ssh](#blocklist_de_ssh)|1659|1659|396|23.8%|46.9%|
[et_compromised](#et_compromised)|2016|2016|372|18.4%|44.1%|
[bruteforceblocker](#bruteforceblocker)|1821|1821|362|19.8%|42.9%|
[shunlist](#shunlist)|1215|1215|234|19.2%|27.7%|
[openbl_1d](#openbl_1d)|146|146|139|95.2%|16.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|115|0.0%|13.6%|
[et_block](#et_block)|1023|18338662|50|0.0%|5.9%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|47|0.0%|5.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|43|0.0%|5.1%|
[dshield](#dshield)|19|19,5120|31|0.6%|3.6%|
[blocklist_de_strongips](#blocklist_de_strongips)|177|177|24|13.5%|2.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|19|0.0%|2.2%|
[blocklist_de_mail](#blocklist_de_mail)|16558|16558|13|0.0%|1.5%|
[blocklist_de_imap](#blocklist_de_imap)|1605|1605|11|0.6%|1.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|5|0.0%|0.5%|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|3|0.0%|0.3%|
[nixspam](#nixspam)|19062|19062|3|0.0%|0.3%|
[blocklist_de_apache](#blocklist_de_apache)|15244|15244|2|0.0%|0.2%|
[voipbl](#voipbl)|10476|10476,10888|1|0.0%|0.1%|
[sorbs_spam](#sorbs_spam)|31523|31523,32638|1|0.0%|0.1%|
[sorbs_recent_spam](#sorbs_recent_spam)|31523|31523,32638|1|0.0%|0.1%|
[sorbs_new_spam](#sorbs_new_spam)|31523|31523,32638|1|0.0%|0.1%|
[snort_ipfilter](#snort_ipfilter)|9943|9943|1|0.0%|0.1%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.1%|

## palevo

[Abuse.ch Palevo tracker](https://palevotracker.abuse.ch) worm includes IPs which are being used as botnet C&C for the Palevo crimeware - **excellent list**

Source is downloaded from [this link](https://palevotracker.abuse.ch/blocklists.php?download=ipblocklist).

The last time downloaded was found to be dated: Sat Jun  6 18:27:10 UTC 2015.

The ipset `palevo` has **13** entries, **13** unique IPs.

The following table shows the overlaps of `palevo` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `palevo`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `palevo`.
- ` this % ` is the percentage **of this ipset (`palevo`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[et_block](#et_block)|1023|18338662|13|0.0%|100.0%|
[snort_ipfilter](#snort_ipfilter)|9943|9943|11|0.1%|84.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|2|0.0%|15.3%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|7.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|1|0.0%|7.6%|

## php_commenters

[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) comment spammers (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=c&rss=1).

The last time downloaded was found to be dated: Sat Jun  6 18:09:49 UTC 2015.

The ipset `php_commenters` has **349** entries, **349** unique IPs.

The following table shows the overlaps of `php_commenters` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `php_commenters`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `php_commenters`.
- ` this % ` is the percentage **of this ipset (`php_commenters`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|253|0.2%|72.4%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|185|0.6%|53.0%|
[stopforumspam_1d](#stopforumspam_1d)|6675|6675|135|2.0%|38.6%|
[blocklist_de](#blocklist_de)|26256|26256|86|0.3%|24.6%|
[blocklist_de_bots](#blocklist_de_bots)|2967|2967|70|2.3%|20.0%|
[snort_ipfilter](#snort_ipfilter)|9943|9943|46|0.4%|13.1%|
[php_spammers](#php_spammers)|536|536|38|7.0%|10.8%|
[et_tor](#et_tor)|6470|6470|37|0.5%|10.6%|
[dm_tor](#dm_tor)|6512|6512|36|0.5%|10.3%|
[bm_tor](#bm_tor)|6516|6516|36|0.5%|10.3%|
[blocklist_de_strongips](#blocklist_de_strongips)|177|177|36|20.3%|10.3%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|34|9.1%|9.7%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|28|0.0%|8.0%|
[et_block](#et_block)|1023|18338662|28|0.0%|8.0%|
[blocklist_de_apache](#blocklist_de_apache)|15244|15244|26|0.1%|7.4%|
[php_dictionary](#php_dictionary)|545|545|25|4.5%|7.1%|
[ri_web_proxies](#ri_web_proxies)|6664|6664|23|0.3%|6.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|22|0.0%|6.3%|
[blocklist_de_mail](#blocklist_de_mail)|16558|16558|22|0.1%|6.3%|
[alienvault_reputation](#alienvault_reputation)|182275|182275|17|0.0%|4.8%|
[sorbs_spam](#sorbs_spam)|31523|31523,32638|15|0.0%|4.2%|
[sorbs_recent_spam](#sorbs_recent_spam)|31523|31523,32638|15|0.0%|4.2%|
[sorbs_new_spam](#sorbs_new_spam)|31523|31523,32638|15|0.0%|4.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|14|0.0%|4.0%|
[php_harvesters](#php_harvesters)|311|311|13|4.1%|3.7%|
[openbl_60d](#openbl_60d)|7286|7286|9|0.1%|2.5%|
[xroxy](#xroxy)|2107|2107|8|0.3%|2.2%|
[nixspam](#nixspam)|19062|19062|8|0.0%|2.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|8|0.0%|2.2%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|3893|3893|8|0.2%|2.2%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|7|0.0%|2.0%|
[proxyrss](#proxyrss)|1416|1416|7|0.4%|2.0%|
[proxz](#proxz)|906|906|6|0.6%|1.7%|
[ri_connect_proxies](#ri_connect_proxies)|2475|2475|5|0.2%|1.4%|
[sorbs_web](#sorbs_web)|693|693,694|3|0.4%|0.8%|
[zeus_badips](#zeus_badips)|202|202|1|0.4%|0.2%|
[zeus](#zeus)|232|232|1|0.4%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.2%|
[fullbogons](#fullbogons)|3721|670267288|1|0.0%|0.2%|
[dshield](#dshield)|19|19,5120|1|0.0%|0.2%|
[bogons](#bogons)|13|592708608|1|0.0%|0.2%|
[blocklist_de_imap](#blocklist_de_imap)|1605|1605|1|0.0%|0.2%|

## php_dictionary

[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) directory attackers (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=d&rss=1).

The last time downloaded was found to be dated: Sat Jun  6 18:27:14 UTC 2015.

The ipset `php_dictionary` has **545** entries, **545** unique IPs.

The following table shows the overlaps of `php_dictionary` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `php_dictionary`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `php_dictionary`.
- ` this % ` is the percentage **of this ipset (`php_dictionary`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[php_spammers](#php_spammers)|536|536|180|33.5%|33.0%|
[sorbs_spam](#sorbs_spam)|31523|31523,32638|150|0.4%|27.5%|
[sorbs_recent_spam](#sorbs_recent_spam)|31523|31523,32638|150|0.4%|27.5%|
[sorbs_new_spam](#sorbs_new_spam)|31523|31523,32638|150|0.4%|27.5%|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|103|0.1%|18.8%|
[blocklist_de](#blocklist_de)|26256|26256|88|0.3%|16.1%|
[snort_ipfilter](#snort_ipfilter)|9943|9943|79|0.7%|14.4%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|66|0.2%|12.1%|
[blocklist_de_mail](#blocklist_de_mail)|16558|16558|62|0.3%|11.3%|
[nixspam](#nixspam)|19062|19062|61|0.3%|11.1%|
[ri_web_proxies](#ri_web_proxies)|6664|6664|43|0.6%|7.8%|
[xroxy](#xroxy)|2107|2107|33|1.5%|6.0%|
[stopforumspam_1d](#stopforumspam_1d)|6675|6675|33|0.4%|6.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|31|0.0%|5.6%|
[sorbs_web](#sorbs_web)|693|693,694|30|4.3%|5.5%|
[php_commenters](#php_commenters)|349|349|25|7.1%|4.5%|
[blocklist_de_bots](#blocklist_de_bots)|2967|2967|21|0.7%|3.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|17|0.0%|3.1%|
[proxz](#proxz)|906|906|14|1.5%|2.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|11|0.0%|2.0%|
[alienvault_reputation](#alienvault_reputation)|182275|182275|8|0.0%|1.4%|
[et_tor](#et_tor)|6470|6470|5|0.0%|0.9%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|4|0.0%|0.7%|
[ri_connect_proxies](#ri_connect_proxies)|2475|2475|4|0.1%|0.7%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|4|1.0%|0.7%|
[et_block](#et_block)|1023|18338662|4|0.0%|0.7%|
[dm_tor](#dm_tor)|6512|6512|4|0.0%|0.7%|
[bm_tor](#bm_tor)|6516|6516|4|0.0%|0.7%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|3893|3893|4|0.1%|0.7%|
[blocklist_de_apache](#blocklist_de_apache)|15244|15244|4|0.0%|0.7%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|3|0.0%|0.5%|
[blocklist_de_strongips](#blocklist_de_strongips)|177|177|3|1.6%|0.5%|
[sorbs_socks](#sorbs_socks)|22|22,22|2|9.0%|0.3%|
[sorbs_misc](#sorbs_misc)|22|22,22|2|9.0%|0.3%|
[sorbs_http](#sorbs_http)|22|22,22|2|9.0%|0.3%|
[php_harvesters](#php_harvesters)|311|311|2|0.6%|0.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2|0.0%|0.3%|
[proxyrss](#proxyrss)|1416|1416|1|0.0%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.1%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|1|0.1%|0.1%|
[blocklist_de_imap](#blocklist_de_imap)|1605|1605|1|0.0%|0.1%|
[blocklist_de_ftp](#blocklist_de_ftp)|830|830|1|0.1%|0.1%|

## php_harvesters

[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) harvesters (IPs that surf the internet looking for email addresses) (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=h&rss=1).

The last time downloaded was found to be dated: Sat Jun  6 18:09:47 UTC 2015.

The ipset `php_harvesters` has **311** entries, **311** unique IPs.

The following table shows the overlaps of `php_harvesters` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `php_harvesters`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `php_harvesters`.
- ` this % ` is the percentage **of this ipset (`php_harvesters`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|68|0.0%|21.8%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|51|0.1%|16.3%|
[stopforumspam_1d](#stopforumspam_1d)|6675|6675|37|0.5%|11.8%|
[blocklist_de](#blocklist_de)|26256|26256|32|0.1%|10.2%|
[blocklist_de_bots](#blocklist_de_bots)|2967|2967|22|0.7%|7.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|17|0.0%|5.4%|
[php_commenters](#php_commenters)|349|349|13|3.7%|4.1%|
[snort_ipfilter](#snort_ipfilter)|9943|9943|11|0.1%|3.5%|
[alienvault_reputation](#alienvault_reputation)|182275|182275|10|0.0%|3.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|9|0.0%|2.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|9|0.0%|2.8%|
[sorbs_spam](#sorbs_spam)|31523|31523,32638|7|0.0%|2.2%|
[sorbs_recent_spam](#sorbs_recent_spam)|31523|31523,32638|7|0.0%|2.2%|
[sorbs_new_spam](#sorbs_new_spam)|31523|31523,32638|7|0.0%|2.2%|
[et_tor](#et_tor)|6470|6470|7|0.1%|2.2%|
[dm_tor](#dm_tor)|6512|6512|7|0.1%|2.2%|
[bm_tor](#bm_tor)|6516|6516|7|0.1%|2.2%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|6|1.6%|1.9%|
[blocklist_de_apache](#blocklist_de_apache)|15244|15244|5|0.0%|1.6%|
[nixspam](#nixspam)|19062|19062|4|0.0%|1.2%|
[blocklist_de_ftp](#blocklist_de_ftp)|830|830|3|0.3%|0.9%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|3893|3893|3|0.0%|0.9%|
[xroxy](#xroxy)|2107|2107|2|0.0%|0.6%|
[proxyrss](#proxyrss)|1416|1416|2|0.1%|0.6%|
[php_spammers](#php_spammers)|536|536|2|0.3%|0.6%|
[php_dictionary](#php_dictionary)|545|545|2|0.3%|0.6%|
[openbl_60d](#openbl_60d)|7286|7286|2|0.0%|0.6%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|2|0.0%|0.6%|
[blocklist_de_strongips](#blocklist_de_strongips)|177|177|2|1.1%|0.6%|
[blocklist_de_mail](#blocklist_de_mail)|16558|16558|2|0.0%|0.6%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|1|0.0%|0.3%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|1|0.0%|0.3%|
[ri_web_proxies](#ri_web_proxies)|6664|6664|1|0.0%|0.3%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.3%|
[fullbogons](#fullbogons)|3721|670267288|1|0.0%|0.3%|
[et_block](#et_block)|1023|18338662|1|0.0%|0.3%|
[bogons](#bogons)|13|592708608|1|0.0%|0.3%|

## php_spammers

[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) spam servers (IPs used by spammers to send messages) (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=s&rss=1).

The last time downloaded was found to be dated: Sat Jun  6 18:09:49 UTC 2015.

The ipset `php_spammers` has **536** entries, **536** unique IPs.

The following table shows the overlaps of `php_spammers` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `php_spammers`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `php_spammers`.
- ` this % ` is the percentage **of this ipset (`php_spammers`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[php_dictionary](#php_dictionary)|545|545|180|33.0%|33.5%|
[sorbs_spam](#sorbs_spam)|31523|31523,32638|134|0.4%|25.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|31523|31523,32638|134|0.4%|25.0%|
[sorbs_new_spam](#sorbs_new_spam)|31523|31523,32638|134|0.4%|25.0%|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|117|0.1%|21.8%|
[blocklist_de](#blocklist_de)|26256|26256|93|0.3%|17.3%|
[snort_ipfilter](#snort_ipfilter)|9943|9943|76|0.7%|14.1%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|66|0.2%|12.3%|
[blocklist_de_mail](#blocklist_de_mail)|16558|16558|61|0.3%|11.3%|
[nixspam](#nixspam)|19062|19062|53|0.2%|9.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|45|0.0%|8.3%|
[stopforumspam_1d](#stopforumspam_1d)|6675|6675|39|0.5%|7.2%|
[ri_web_proxies](#ri_web_proxies)|6664|6664|38|0.5%|7.0%|
[php_commenters](#php_commenters)|349|349|38|10.8%|7.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|31|0.0%|5.7%|
[sorbs_web](#sorbs_web)|693|693,694|28|4.0%|5.2%|
[xroxy](#xroxy)|2107|2107|26|1.2%|4.8%|
[blocklist_de_bots](#blocklist_de_bots)|2967|2967|25|0.8%|4.6%|
[proxz](#proxz)|906|906|17|1.8%|3.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|7|0.0%|1.3%|
[et_tor](#et_tor)|6470|6470|6|0.0%|1.1%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|3893|3893|6|0.1%|1.1%|
[blocklist_de_apache](#blocklist_de_apache)|15244|15244|6|0.0%|1.1%|
[dm_tor](#dm_tor)|6512|6512|5|0.0%|0.9%|
[bm_tor](#bm_tor)|6516|6516|5|0.0%|0.9%|
[blocklist_de_strongips](#blocklist_de_strongips)|177|177|5|2.8%|0.9%|
[alienvault_reputation](#alienvault_reputation)|182275|182275|5|0.0%|0.9%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|4|1.0%|0.7%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|3|0.0%|0.5%|
[ri_connect_proxies](#ri_connect_proxies)|2475|2475|3|0.1%|0.5%|
[proxyrss](#proxyrss)|1416|1416|3|0.2%|0.5%|
[php_harvesters](#php_harvesters)|311|311|2|0.6%|0.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2|0.0%|0.3%|
[et_block](#et_block)|1023|18338662|2|0.0%|0.3%|
[sorbs_socks](#sorbs_socks)|22|22,22|1|4.5%|0.1%|
[sorbs_misc](#sorbs_misc)|22|22,22|1|4.5%|0.1%|
[sorbs_http](#sorbs_http)|22|22,22|1|4.5%|0.1%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1|0.0%|0.1%|
[blocklist_de_ftp](#blocklist_de_ftp)|830|830|1|0.1%|0.1%|

## proxyrss

[proxyrss.com](http://www.proxyrss.com) open proxies syndicated from multiple sources.

Source is downloaded from [this link](http://www.proxyrss.com/proxylists/all.gz).

The last time downloaded was found to be dated: Sat Jun  6 15:11:27 UTC 2015.

The ipset `proxyrss` has **1416** entries, **1416** unique IPs.

The following table shows the overlaps of `proxyrss` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `proxyrss`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `proxyrss`.
- ` this % ` is the percentage **of this ipset (`proxyrss`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|722|0.7%|50.9%|
[ri_web_proxies](#ri_web_proxies)|6664|6664|621|9.3%|43.8%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|577|1.9%|40.7%|
[xroxy](#xroxy)|2107|2107|391|18.5%|27.6%|
[stopforumspam_1d](#stopforumspam_1d)|6675|6675|316|4.7%|22.3%|
[proxz](#proxz)|906|906|244|26.9%|17.2%|
[ri_connect_proxies](#ri_connect_proxies)|2475|2475|237|9.5%|16.7%|
[blocklist_de](#blocklist_de)|26256|26256|185|0.7%|13.0%|
[blocklist_de_bots](#blocklist_de_bots)|2967|2967|184|6.2%|12.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|64|0.0%|4.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|49|0.0%|3.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|45|0.0%|3.1%|
[sorbs_spam](#sorbs_spam)|31523|31523,32638|9|0.0%|0.6%|
[sorbs_recent_spam](#sorbs_recent_spam)|31523|31523,32638|9|0.0%|0.6%|
[sorbs_new_spam](#sorbs_new_spam)|31523|31523,32638|9|0.0%|0.6%|
[nixspam](#nixspam)|19062|19062|9|0.0%|0.6%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|9|1.3%|0.6%|
[php_commenters](#php_commenters)|349|349|7|2.0%|0.4%|
[blocklist_de_strongips](#blocklist_de_strongips)|177|177|5|2.8%|0.3%|
[snort_ipfilter](#snort_ipfilter)|9943|9943|4|0.0%|0.2%|
[php_spammers](#php_spammers)|536|536|3|0.5%|0.2%|
[php_harvesters](#php_harvesters)|311|311|2|0.6%|0.1%|
[et_compromised](#et_compromised)|2016|2016|2|0.0%|0.1%|
[bruteforceblocker](#bruteforceblocker)|1821|1821|2|0.1%|0.1%|
[sorbs_web](#sorbs_web)|693|693,694|1|0.1%|0.0%|
[php_dictionary](#php_dictionary)|545|545|1|0.1%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|16558|16558|1|0.0%|0.0%|
[alienvault_reputation](#alienvault_reputation)|182275|182275|1|0.0%|0.0%|

## proxz

[proxz.com](http://www.proxz.com) open proxies (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.proxz.com/proxylists.xml).

The last time downloaded was found to be dated: Sat Jun  6 17:51:37 UTC 2015.

The ipset `proxz` has **906** entries, **906** unique IPs.

The following table shows the overlaps of `proxz` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `proxz`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `proxz`.
- ` this % ` is the percentage **of this ipset (`proxz`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|542|0.5%|59.8%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|422|1.4%|46.5%|
[ri_web_proxies](#ri_web_proxies)|6664|6664|410|6.1%|45.2%|
[xroxy](#xroxy)|2107|2107|346|16.4%|38.1%|
[proxyrss](#proxyrss)|1416|1416|244|17.2%|26.9%|
[stopforumspam_1d](#stopforumspam_1d)|6675|6675|158|2.3%|17.4%|
[ri_connect_proxies](#ri_connect_proxies)|2475|2475|148|5.9%|16.3%|
[blocklist_de](#blocklist_de)|26256|26256|136|0.5%|15.0%|
[blocklist_de_bots](#blocklist_de_bots)|2967|2967|116|3.9%|12.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|73|0.0%|8.0%|
[sorbs_spam](#sorbs_spam)|31523|31523,32638|42|0.1%|4.6%|
[sorbs_recent_spam](#sorbs_recent_spam)|31523|31523,32638|42|0.1%|4.6%|
[sorbs_new_spam](#sorbs_new_spam)|31523|31523,32638|42|0.1%|4.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|37|0.0%|4.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|31|0.0%|3.4%|
[snort_ipfilter](#snort_ipfilter)|9943|9943|23|0.2%|2.5%|
[blocklist_de_mail](#blocklist_de_mail)|16558|16558|21|0.1%|2.3%|
[php_spammers](#php_spammers)|536|536|17|3.1%|1.8%|
[php_dictionary](#php_dictionary)|545|545|14|2.5%|1.5%|
[sorbs_web](#sorbs_web)|693|693,694|11|1.5%|1.2%|
[nixspam](#nixspam)|19062|19062|11|0.0%|1.2%|
[php_commenters](#php_commenters)|349|349|6|1.7%|0.6%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|6|0.8%|0.6%|
[blocklist_de_strongips](#blocklist_de_strongips)|177|177|4|2.2%|0.4%|
[alienvault_reputation](#alienvault_reputation)|182275|182275|3|0.0%|0.3%|
[et_compromised](#et_compromised)|2016|2016|2|0.0%|0.2%|
[bruteforceblocker](#bruteforceblocker)|1821|1821|2|0.1%|0.2%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1|0.0%|0.1%|

## ri_connect_proxies

[rosinstrument.com](http://www.rosinstrument.com) open CONNECT proxies (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://tools.rosinstrument.com/proxy/plab100.xml).

The last time downloaded was found to be dated: Sat Jun  6 14:51:12 UTC 2015.

The ipset `ri_connect_proxies` has **2475** entries, **2475** unique IPs.

The following table shows the overlaps of `ri_connect_proxies` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ri_connect_proxies`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ri_connect_proxies`.
- ` this % ` is the percentage **of this ipset (`ri_connect_proxies`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|1418|1.5%|57.2%|
[ri_web_proxies](#ri_web_proxies)|6664|6664|1026|15.3%|41.4%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|651|2.1%|26.3%|
[xroxy](#xroxy)|2107|2107|365|17.3%|14.7%|
[proxyrss](#proxyrss)|1416|1416|237|16.7%|9.5%|
[proxz](#proxz)|906|906|148|16.3%|5.9%|
[stopforumspam_1d](#stopforumspam_1d)|6675|6675|137|2.0%|5.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|96|0.0%|3.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|78|0.0%|3.1%|
[blocklist_de](#blocklist_de)|26256|26256|64|0.2%|2.5%|
[blocklist_de_bots](#blocklist_de_bots)|2967|2967|61|2.0%|2.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|53|0.0%|2.1%|
[nixspam](#nixspam)|19062|19062|12|0.0%|0.4%|
[sorbs_spam](#sorbs_spam)|31523|31523,32638|11|0.0%|0.4%|
[sorbs_recent_spam](#sorbs_recent_spam)|31523|31523,32638|11|0.0%|0.4%|
[sorbs_new_spam](#sorbs_new_spam)|31523|31523,32638|11|0.0%|0.4%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|7|1.0%|0.2%|
[php_commenters](#php_commenters)|349|349|5|1.4%|0.2%|
[php_dictionary](#php_dictionary)|545|545|4|0.7%|0.1%|
[snort_ipfilter](#snort_ipfilter)|9943|9943|3|0.0%|0.1%|
[php_spammers](#php_spammers)|536|536|3|0.5%|0.1%|
[blocklist_de_mail](#blocklist_de_mail)|16558|16558|3|0.0%|0.1%|
[alienvault_reputation](#alienvault_reputation)|182275|182275|3|0.0%|0.1%|
[sorbs_web](#sorbs_web)|693|693,694|1|0.1%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.0%|
[et_tor](#et_tor)|6470|6470|1|0.0%|0.0%|
[dm_tor](#dm_tor)|6512|6512|1|0.0%|0.0%|
[bm_tor](#bm_tor)|6516|6516|1|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|1605|1605|1|0.0%|0.0%|

## ri_web_proxies

[rosinstrument.com](http://www.rosinstrument.com) open HTTP proxies (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://tools.rosinstrument.com/proxy/l100.xml).

The last time downloaded was found to be dated: Sat Jun  6 17:39:40 UTC 2015.

The ipset `ri_web_proxies` has **6664** entries, **6664** unique IPs.

The following table shows the overlaps of `ri_web_proxies` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ri_web_proxies`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ri_web_proxies`.
- ` this % ` is the percentage **of this ipset (`ri_web_proxies`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|3207|3.4%|48.1%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|1627|5.4%|24.4%|
[ri_connect_proxies](#ri_connect_proxies)|2475|2475|1026|41.4%|15.3%|
[xroxy](#xroxy)|2107|2107|901|42.7%|13.5%|
[proxyrss](#proxyrss)|1416|1416|621|43.8%|9.3%|
[stopforumspam_1d](#stopforumspam_1d)|6675|6675|454|6.8%|6.8%|
[proxz](#proxz)|906|906|410|45.2%|6.1%|
[blocklist_de](#blocklist_de)|26256|26256|370|1.4%|5.5%|
[blocklist_de_bots](#blocklist_de_bots)|2967|2967|313|10.5%|4.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|195|0.0%|2.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|192|0.0%|2.8%|
[sorbs_spam](#sorbs_spam)|31523|31523,32638|140|0.4%|2.1%|
[sorbs_recent_spam](#sorbs_recent_spam)|31523|31523,32638|140|0.4%|2.1%|
[sorbs_new_spam](#sorbs_new_spam)|31523|31523,32638|140|0.4%|2.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|134|0.0%|2.0%|
[snort_ipfilter](#snort_ipfilter)|9943|9943|66|0.6%|0.9%|
[blocklist_de_mail](#blocklist_de_mail)|16558|16558|57|0.3%|0.8%|
[nixspam](#nixspam)|19062|19062|56|0.2%|0.8%|
[php_dictionary](#php_dictionary)|545|545|43|7.8%|0.6%|
[php_spammers](#php_spammers)|536|536|38|7.0%|0.5%|
[sorbs_web](#sorbs_web)|693|693,694|24|3.4%|0.3%|
[php_commenters](#php_commenters)|349|349|23|6.5%|0.3%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|12|1.7%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|5|0.0%|0.0%|
[et_tor](#et_tor)|6470|6470|5|0.0%|0.0%|
[dm_tor](#dm_tor)|6512|6512|5|0.0%|0.0%|
[bm_tor](#bm_tor)|6516|6516|5|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|177|177|5|2.8%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|1605|1605|5|0.3%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|4|1.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|3|0.0%|0.0%|
[alienvault_reputation](#alienvault_reputation)|182275|182275|3|0.0%|0.0%|
[sslbl](#sslbl)|369|369|1|0.2%|0.0%|
[php_harvesters](#php_harvesters)|311|311|1|0.3%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|
[et_compromised](#et_compromised)|2016|2016|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1821|1821|1|0.0%|0.0%|

## shunlist

[AutoShun.org](http://autoshun.org/) IPs identified as hostile by correlating logs from distributed snort installations running the autoshun plugin

Source is downloaded from [this link](http://www.autoshun.org/files/shunlist.csv).

The last time downloaded was found to be dated: Sat Jun  6 18:30:05 UTC 2015.

The ipset `shunlist` has **1215** entries, **1215** unique IPs.

The following table shows the overlaps of `shunlist` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `shunlist`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `shunlist`.
- ` this % ` is the percentage **of this ipset (`shunlist`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[alienvault_reputation](#alienvault_reputation)|182275|182275|1200|0.6%|98.7%|
[openbl_60d](#openbl_60d)|7286|7286|542|7.4%|44.6%|
[openbl_30d](#openbl_30d)|3252|3252|527|16.2%|43.3%|
[et_compromised](#et_compromised)|2016|2016|436|21.6%|35.8%|
[bruteforceblocker](#bruteforceblocker)|1821|1821|425|23.3%|34.9%|
[blocklist_de](#blocklist_de)|26256|26256|355|1.3%|29.2%|
[blocklist_de_ssh](#blocklist_de_ssh)|1659|1659|318|19.1%|26.1%|
[openbl_7d](#openbl_7d)|843|843|234|27.7%|19.2%|
[et_block](#et_block)|1023|18338662|110|0.0%|9.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|108|0.0%|8.8%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|96|0.0%|7.9%|
[openbl_1d](#openbl_1d)|146|146|71|48.6%|5.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|68|0.0%|5.5%|
[sslbl](#sslbl)|369|369|57|15.4%|4.6%|
[blocklist_de_apache](#blocklist_de_apache)|15244|15244|35|0.2%|2.8%|
[dshield](#dshield)|19|19,5120|34|0.6%|2.7%|
[ciarmy](#ciarmy)|412|412|31|7.5%|2.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|28|0.0%|2.3%|
[blocklist_de_strongips](#blocklist_de_strongips)|177|177|20|11.2%|1.6%|
[voipbl](#voipbl)|10476|10476,10888|13|0.1%|1.0%|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|5|0.0%|0.4%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|2|0.0%|0.1%|
[snort_ipfilter](#snort_ipfilter)|9943|9943|2|0.0%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2|0.0%|0.1%|
[blocklist_de_mail](#blocklist_de_mail)|16558|16558|2|0.0%|0.1%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|3893|3893|2|0.0%|0.1%|
[stopforumspam_1d](#stopforumspam_1d)|6675|6675|1|0.0%|0.0%|
[sorbs_spam](#sorbs_spam)|31523|31523,32638|1|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|31523|31523,32638|1|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|31523|31523,32638|1|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.0%|
[et_tor](#et_tor)|6470|6470|1|0.0%|0.0%|
[dm_tor](#dm_tor)|6512|6512|1|0.0%|0.0%|
[bm_tor](#bm_tor)|6516|6516|1|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|1605|1605|1|0.0%|0.0%|

## snort_ipfilter

[labs.snort.org](https://labs.snort.org/) supplied IP blacklist (this list seems to be updated frequently, but we found no information about it)

Source is downloaded from [this link](http://labs.snort.org/feeds/ip-filter.blf).

The last time downloaded was found to be dated: Sat Jun  6 13:30:00 UTC 2015.

The ipset `snort_ipfilter` has **9943** entries, **9943** unique IPs.

The following table shows the overlaps of `snort_ipfilter` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `snort_ipfilter`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `snort_ipfilter`.
- ` this % ` is the percentage **of this ipset (`snort_ipfilter`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[et_tor](#et_tor)|6470|6470|1084|16.7%|10.9%|
[bm_tor](#bm_tor)|6516|6516|1080|16.5%|10.8%|
[dm_tor](#dm_tor)|6512|6512|1079|16.5%|10.8%|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|803|0.8%|8.0%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|626|2.0%|6.2%|
[stopforumspam_1d](#stopforumspam_1d)|6675|6675|382|5.7%|3.8%|
[sorbs_spam](#sorbs_spam)|31523|31523,32638|317|0.9%|3.1%|
[sorbs_recent_spam](#sorbs_recent_spam)|31523|31523,32638|317|0.9%|3.1%|
[sorbs_new_spam](#sorbs_new_spam)|31523|31523,32638|317|0.9%|3.1%|
[et_block](#et_block)|1023|18338662|313|0.0%|3.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|232|0.0%|2.3%|
[zeus](#zeus)|232|232|203|87.5%|2.0%|
[zeus_badips](#zeus_badips)|202|202|179|88.6%|1.8%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|177|47.5%|1.7%|
[blocklist_de](#blocklist_de)|26256|26256|159|0.6%|1.5%|
[blocklist_de_mail](#blocklist_de_mail)|16558|16558|127|0.7%|1.2%|
[alienvault_reputation](#alienvault_reputation)|182275|182275|119|0.0%|1.1%|
[nixspam](#nixspam)|19062|19062|105|0.5%|1.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|103|0.0%|1.0%|
[php_dictionary](#php_dictionary)|545|545|79|14.4%|0.7%|
[feodo](#feodo)|99|99|79|79.7%|0.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|78|0.0%|0.7%|
[php_spammers](#php_spammers)|536|536|76|14.1%|0.7%|
[ri_web_proxies](#ri_web_proxies)|6664|6664|66|0.9%|0.6%|
[sorbs_web](#sorbs_web)|693|693,694|52|7.4%|0.5%|
[xroxy](#xroxy)|2107|2107|46|2.1%|0.4%|
[php_commenters](#php_commenters)|349|349|46|13.1%|0.4%|
[sslbl](#sslbl)|369|369|31|8.4%|0.3%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|28|2.1%|0.2%|
[openbl_60d](#openbl_60d)|7286|7286|27|0.3%|0.2%|
[blocklist_de_bots](#blocklist_de_bots)|2967|2967|25|0.8%|0.2%|
[proxz](#proxz)|906|906|23|2.5%|0.2%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|20|0.0%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|14|0.0%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|12|0.0%|0.1%|
[php_harvesters](#php_harvesters)|311|311|11|3.5%|0.1%|
[palevo](#palevo)|13|13|11|84.6%|0.1%|
[blocklist_de_apache](#blocklist_de_apache)|15244|15244|9|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|6|0.0%|0.0%|
[sorbs_socks](#sorbs_socks)|22|22,22|5|22.7%|0.0%|
[sorbs_misc](#sorbs_misc)|22|22,22|5|22.7%|0.0%|
[sorbs_http](#sorbs_http)|22|22,22|5|22.7%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|3893|3893|5|0.1%|0.0%|
[proxyrss](#proxyrss)|1416|1416|4|0.2%|0.0%|
[openbl_30d](#openbl_30d)|3252|3252|4|0.1%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2475|2475|3|0.1%|0.0%|
[shunlist](#shunlist)|1215|1215|2|0.1%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|2|0.0%|0.0%|
[dshield](#dshield)|19|19,5120|2|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|1605|1605|2|0.1%|0.0%|
[openbl_7d](#openbl_7d)|843|843|1|0.1%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|177|177|1|0.5%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1659|1659|1|0.0%|0.0%|

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

The last time downloaded was found to be dated: Sat Jun  6 17:06:03 UTC 2015.

The ipset `sorbs_http` has **22** entries, **22,22** unique IPs.

The following table shows the overlaps of `sorbs_http` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `sorbs_http`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `sorbs_http`.
- ` this % ` is the percentage **of this ipset (`sorbs_http`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[sorbs_spam](#sorbs_spam)|31523|31523,32638|22|0.0%|100.0%|
[sorbs_socks](#sorbs_socks)|22|22,22|22|100.0%|100.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|31523|31523,32638|22|0.0%|100.0%|
[sorbs_new_spam](#sorbs_new_spam)|31523|31523,32638|22|0.0%|100.0%|
[sorbs_misc](#sorbs_misc)|22|22,22|22|100.0%|100.0%|
[snort_ipfilter](#snort_ipfilter)|9943|9943|5|0.0%|22.7%|
[blocklist_de_mail](#blocklist_de_mail)|16558|16558|5|0.0%|22.7%|
[blocklist_de](#blocklist_de)|26256|26256|5|0.0%|22.7%|
[nixspam](#nixspam)|19062|19062|4|0.0%|18.1%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|3|0.0%|13.6%|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|3|0.0%|13.6%|
[sorbs_web](#sorbs_web)|693|693,694|3|0.4%|13.6%|
[php_dictionary](#php_dictionary)|545|545|2|0.3%|9.0%|
[xroxy](#xroxy)|2107|2107|1|0.0%|4.5%|
[php_spammers](#php_spammers)|536|536|1|0.1%|4.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|1|0.0%|4.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|1|0.0%|4.5%|

## sorbs_misc

[Sorbs.net](https://www.sorbs.net/) MISC proxies, extracted from deltas.

Source is downloaded from [this link]().

The last time downloaded was found to be dated: Sat Jun  6 17:06:03 UTC 2015.

The ipset `sorbs_misc` has **22** entries, **22,22** unique IPs.

The following table shows the overlaps of `sorbs_misc` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `sorbs_misc`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `sorbs_misc`.
- ` this % ` is the percentage **of this ipset (`sorbs_misc`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[sorbs_spam](#sorbs_spam)|31523|31523,32638|22|0.0%|100.0%|
[sorbs_socks](#sorbs_socks)|22|22,22|22|100.0%|100.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|31523|31523,32638|22|0.0%|100.0%|
[sorbs_new_spam](#sorbs_new_spam)|31523|31523,32638|22|0.0%|100.0%|
[sorbs_http](#sorbs_http)|22|22,22|22|100.0%|100.0%|
[snort_ipfilter](#snort_ipfilter)|9943|9943|5|0.0%|22.7%|
[blocklist_de_mail](#blocklist_de_mail)|16558|16558|5|0.0%|22.7%|
[blocklist_de](#blocklist_de)|26256|26256|5|0.0%|22.7%|
[nixspam](#nixspam)|19062|19062|4|0.0%|18.1%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|3|0.0%|13.6%|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|3|0.0%|13.6%|
[sorbs_web](#sorbs_web)|693|693,694|3|0.4%|13.6%|
[php_dictionary](#php_dictionary)|545|545|2|0.3%|9.0%|
[xroxy](#xroxy)|2107|2107|1|0.0%|4.5%|
[php_spammers](#php_spammers)|536|536|1|0.1%|4.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|1|0.0%|4.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|1|0.0%|4.5%|

## sorbs_new_spam

[Sorbs.net](https://www.sorbs.net/) NEW Spam senders, extracted from deltas.

Source is downloaded from [this link]().

The last time downloaded was found to be dated: Sat Jun  6 18:04:12 UTC 2015.

The ipset `sorbs_new_spam` has **31523** entries, **31523,32638** unique IPs.

The following table shows the overlaps of `sorbs_new_spam` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `sorbs_new_spam`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `sorbs_new_spam`.
- ` this % ` is the percentage **of this ipset (`sorbs_new_spam`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[sorbs_spam](#sorbs_spam)|31523|31523,32638|32638|100.0%|100.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|31523|31523,32638|32638|100.0%|100.0%|
[nixspam](#nixspam)|19062|19062|3071|16.1%|9.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|2393|0.0%|7.3%|
[blocklist_de](#blocklist_de)|26256|26256|951|3.6%|2.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|810|0.0%|2.4%|
[blocklist_de_mail](#blocklist_de_mail)|16558|16558|785|4.7%|2.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|505|0.0%|1.5%|
[sorbs_web](#sorbs_web)|693|693,694|344|49.5%|1.0%|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|341|0.3%|1.0%|
[snort_ipfilter](#snort_ipfilter)|9943|9943|317|3.1%|0.9%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|181|0.6%|0.5%|
[php_dictionary](#php_dictionary)|545|545|150|27.5%|0.4%|
[ri_web_proxies](#ri_web_proxies)|6664|6664|140|2.1%|0.4%|
[php_spammers](#php_spammers)|536|536|134|25.0%|0.4%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|3893|3893|111|2.8%|0.3%|
[blocklist_de_apache](#blocklist_de_apache)|15244|15244|111|0.7%|0.3%|
[alienvault_reputation](#alienvault_reputation)|182275|182275|98|0.0%|0.3%|
[xroxy](#xroxy)|2107|2107|86|4.0%|0.2%|
[stopforumspam_1d](#stopforumspam_1d)|6675|6675|57|0.8%|0.1%|
[blocklist_de_bots](#blocklist_de_bots)|2967|2967|49|1.6%|0.1%|
[proxz](#proxz)|906|906|42|4.6%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|33|0.0%|0.1%|
[sorbs_socks](#sorbs_socks)|22|22,22|22|100.0%|0.0%|
[sorbs_misc](#sorbs_misc)|22|22,22|22|100.0%|0.0%|
[sorbs_http](#sorbs_http)|22|22,22|22|100.0%|0.0%|
[php_commenters](#php_commenters)|349|349|15|4.2%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|15|0.0%|0.0%|
[sorbs_smtp](#sorbs_smtp)|14|14,14|14|100.0%|0.0%|
[openbl_60d](#openbl_60d)|7286|7286|14|0.1%|0.0%|
[et_block](#et_block)|1023|18338662|14|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|12|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|1605|1605|12|0.7%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2475|2475|11|0.4%|0.0%|
[proxyrss](#proxyrss)|1416|1416|9|0.6%|0.0%|
[php_harvesters](#php_harvesters)|311|311|7|2.2%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|830|830|6|0.7%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|5|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|3|0.0%|0.0%|
[openbl_30d](#openbl_30d)|3252|3252|3|0.0%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|2|0.1%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|2|0.2%|0.0%|
[et_tor](#et_tor)|6470|6470|2|0.0%|0.0%|
[dm_tor](#dm_tor)|6512|6512|2|0.0%|0.0%|
[bm_tor](#bm_tor)|6516|6516|2|0.0%|0.0%|
[shunlist](#shunlist)|1215|1215|1|0.0%|0.0%|
[openbl_7d](#openbl_7d)|843|843|1|0.1%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|177|177|1|0.5%|0.0%|

## sorbs_recent_spam

[Sorbs.net](https://www.sorbs.net/) RECENT Spam senders, extracted from deltas.

Source is downloaded from [this link]().

The last time downloaded was found to be dated: Sat Jun  6 18:04:12 UTC 2015.

The ipset `sorbs_recent_spam` has **31523** entries, **31523,32638** unique IPs.

The following table shows the overlaps of `sorbs_recent_spam` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `sorbs_recent_spam`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `sorbs_recent_spam`.
- ` this % ` is the percentage **of this ipset (`sorbs_recent_spam`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[sorbs_spam](#sorbs_spam)|31523|31523,32638|32638|100.0%|100.0%|
[sorbs_new_spam](#sorbs_new_spam)|31523|31523,32638|32638|100.0%|100.0%|
[nixspam](#nixspam)|19062|19062|3071|16.1%|9.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|2393|0.0%|7.3%|
[blocklist_de](#blocklist_de)|26256|26256|951|3.6%|2.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|810|0.0%|2.4%|
[blocklist_de_mail](#blocklist_de_mail)|16558|16558|785|4.7%|2.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|505|0.0%|1.5%|
[sorbs_web](#sorbs_web)|693|693,694|344|49.5%|1.0%|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|341|0.3%|1.0%|
[snort_ipfilter](#snort_ipfilter)|9943|9943|317|3.1%|0.9%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|181|0.6%|0.5%|
[php_dictionary](#php_dictionary)|545|545|150|27.5%|0.4%|
[ri_web_proxies](#ri_web_proxies)|6664|6664|140|2.1%|0.4%|
[php_spammers](#php_spammers)|536|536|134|25.0%|0.4%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|3893|3893|111|2.8%|0.3%|
[blocklist_de_apache](#blocklist_de_apache)|15244|15244|111|0.7%|0.3%|
[alienvault_reputation](#alienvault_reputation)|182275|182275|98|0.0%|0.3%|
[xroxy](#xroxy)|2107|2107|86|4.0%|0.2%|
[stopforumspam_1d](#stopforumspam_1d)|6675|6675|57|0.8%|0.1%|
[blocklist_de_bots](#blocklist_de_bots)|2967|2967|49|1.6%|0.1%|
[proxz](#proxz)|906|906|42|4.6%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|33|0.0%|0.1%|
[sorbs_socks](#sorbs_socks)|22|22,22|22|100.0%|0.0%|
[sorbs_misc](#sorbs_misc)|22|22,22|22|100.0%|0.0%|
[sorbs_http](#sorbs_http)|22|22,22|22|100.0%|0.0%|
[php_commenters](#php_commenters)|349|349|15|4.2%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|15|0.0%|0.0%|
[sorbs_smtp](#sorbs_smtp)|14|14,14|14|100.0%|0.0%|
[openbl_60d](#openbl_60d)|7286|7286|14|0.1%|0.0%|
[et_block](#et_block)|1023|18338662|14|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|12|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|1605|1605|12|0.7%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2475|2475|11|0.4%|0.0%|
[proxyrss](#proxyrss)|1416|1416|9|0.6%|0.0%|
[php_harvesters](#php_harvesters)|311|311|7|2.2%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|830|830|6|0.7%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|5|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|3|0.0%|0.0%|
[openbl_30d](#openbl_30d)|3252|3252|3|0.0%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|2|0.1%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|2|0.2%|0.0%|
[et_tor](#et_tor)|6470|6470|2|0.0%|0.0%|
[dm_tor](#dm_tor)|6512|6512|2|0.0%|0.0%|
[bm_tor](#bm_tor)|6516|6516|2|0.0%|0.0%|
[shunlist](#shunlist)|1215|1215|1|0.0%|0.0%|
[openbl_7d](#openbl_7d)|843|843|1|0.1%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|177|177|1|0.5%|0.0%|

## sorbs_smtp

[Sorbs.net](https://www.sorbs.net/) SMTP Open Relays, extracted from deltas.

Source is downloaded from [this link]().

The last time downloaded was found to be dated: Sat Jun  6 14:04:12 UTC 2015.

The ipset `sorbs_smtp` has **14** entries, **14,14** unique IPs.

The following table shows the overlaps of `sorbs_smtp` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `sorbs_smtp`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `sorbs_smtp`.
- ` this % ` is the percentage **of this ipset (`sorbs_smtp`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[sorbs_spam](#sorbs_spam)|31523|31523,32638|14|0.0%|100.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|31523|31523,32638|14|0.0%|100.0%|
[sorbs_new_spam](#sorbs_new_spam)|31523|31523,32638|14|0.0%|100.0%|
[nixspam](#nixspam)|19062|19062|1|0.0%|7.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|1|0.0%|7.1%|

## sorbs_socks

[Sorbs.net](https://www.sorbs.net/) SOCKS proxies, extracted from deltas.

Source is downloaded from [this link]().

The last time downloaded was found to be dated: Sat Jun  6 17:06:04 UTC 2015.

The ipset `sorbs_socks` has **22** entries, **22,22** unique IPs.

The following table shows the overlaps of `sorbs_socks` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `sorbs_socks`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `sorbs_socks`.
- ` this % ` is the percentage **of this ipset (`sorbs_socks`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[sorbs_spam](#sorbs_spam)|31523|31523,32638|22|0.0%|100.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|31523|31523,32638|22|0.0%|100.0%|
[sorbs_new_spam](#sorbs_new_spam)|31523|31523,32638|22|0.0%|100.0%|
[sorbs_misc](#sorbs_misc)|22|22,22|22|100.0%|100.0%|
[sorbs_http](#sorbs_http)|22|22,22|22|100.0%|100.0%|
[snort_ipfilter](#snort_ipfilter)|9943|9943|5|0.0%|22.7%|
[blocklist_de_mail](#blocklist_de_mail)|16558|16558|5|0.0%|22.7%|
[blocklist_de](#blocklist_de)|26256|26256|5|0.0%|22.7%|
[nixspam](#nixspam)|19062|19062|4|0.0%|18.1%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|3|0.0%|13.6%|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|3|0.0%|13.6%|
[sorbs_web](#sorbs_web)|693|693,694|3|0.4%|13.6%|
[php_dictionary](#php_dictionary)|545|545|2|0.3%|9.0%|
[xroxy](#xroxy)|2107|2107|1|0.0%|4.5%|
[php_spammers](#php_spammers)|536|536|1|0.1%|4.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|1|0.0%|4.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|1|0.0%|4.5%|

## sorbs_spam

[Sorbs.net](https://www.sorbs.net/) Spam senders, extracted from deltas.

Source is downloaded from [this link]().

The last time downloaded was found to be dated: Sat Jun  6 18:04:11 UTC 2015.

The ipset `sorbs_spam` has **31523** entries, **31523,32638** unique IPs.

The following table shows the overlaps of `sorbs_spam` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `sorbs_spam`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `sorbs_spam`.
- ` this % ` is the percentage **of this ipset (`sorbs_spam`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[sorbs_recent_spam](#sorbs_recent_spam)|31523|31523,32638|32638|100.0%|100.0%|
[sorbs_new_spam](#sorbs_new_spam)|31523|31523,32638|32638|100.0%|100.0%|
[nixspam](#nixspam)|19062|19062|3071|16.1%|9.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|2393|0.0%|7.3%|
[blocklist_de](#blocklist_de)|26256|26256|951|3.6%|2.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|810|0.0%|2.4%|
[blocklist_de_mail](#blocklist_de_mail)|16558|16558|785|4.7%|2.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|505|0.0%|1.5%|
[sorbs_web](#sorbs_web)|693|693,694|344|49.5%|1.0%|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|341|0.3%|1.0%|
[snort_ipfilter](#snort_ipfilter)|9943|9943|317|3.1%|0.9%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|181|0.6%|0.5%|
[php_dictionary](#php_dictionary)|545|545|150|27.5%|0.4%|
[ri_web_proxies](#ri_web_proxies)|6664|6664|140|2.1%|0.4%|
[php_spammers](#php_spammers)|536|536|134|25.0%|0.4%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|3893|3893|111|2.8%|0.3%|
[blocklist_de_apache](#blocklist_de_apache)|15244|15244|111|0.7%|0.3%|
[alienvault_reputation](#alienvault_reputation)|182275|182275|98|0.0%|0.3%|
[xroxy](#xroxy)|2107|2107|86|4.0%|0.2%|
[stopforumspam_1d](#stopforumspam_1d)|6675|6675|57|0.8%|0.1%|
[blocklist_de_bots](#blocklist_de_bots)|2967|2967|49|1.6%|0.1%|
[proxz](#proxz)|906|906|42|4.6%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|33|0.0%|0.1%|
[sorbs_socks](#sorbs_socks)|22|22,22|22|100.0%|0.0%|
[sorbs_misc](#sorbs_misc)|22|22,22|22|100.0%|0.0%|
[sorbs_http](#sorbs_http)|22|22,22|22|100.0%|0.0%|
[php_commenters](#php_commenters)|349|349|15|4.2%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|15|0.0%|0.0%|
[sorbs_smtp](#sorbs_smtp)|14|14,14|14|100.0%|0.0%|
[openbl_60d](#openbl_60d)|7286|7286|14|0.1%|0.0%|
[et_block](#et_block)|1023|18338662|14|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|12|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|1605|1605|12|0.7%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2475|2475|11|0.4%|0.0%|
[proxyrss](#proxyrss)|1416|1416|9|0.6%|0.0%|
[php_harvesters](#php_harvesters)|311|311|7|2.2%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|830|830|6|0.7%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|5|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|3|0.0%|0.0%|
[openbl_30d](#openbl_30d)|3252|3252|3|0.0%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|2|0.1%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|2|0.2%|0.0%|
[et_tor](#et_tor)|6470|6470|2|0.0%|0.0%|
[dm_tor](#dm_tor)|6512|6512|2|0.0%|0.0%|
[bm_tor](#bm_tor)|6516|6516|2|0.0%|0.0%|
[shunlist](#shunlist)|1215|1215|1|0.0%|0.0%|
[openbl_7d](#openbl_7d)|843|843|1|0.1%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|177|177|1|0.5%|0.0%|

## sorbs_web

[Sorbs.net](https://www.sorbs.net/) WEB exploits, extracted from deltas.

Source is downloaded from [this link]().

The last time downloaded was found to be dated: Sat Jun  6 18:04:12 UTC 2015.

The ipset `sorbs_web` has **693** entries, **693,694** unique IPs.

The following table shows the overlaps of `sorbs_web` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `sorbs_web`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `sorbs_web`.
- ` this % ` is the percentage **of this ipset (`sorbs_web`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[sorbs_spam](#sorbs_spam)|31523|31523,32638|344|1.0%|49.5%|
[sorbs_recent_spam](#sorbs_recent_spam)|31523|31523,32638|344|1.0%|49.5%|
[sorbs_new_spam](#sorbs_new_spam)|31523|31523,32638|344|1.0%|49.5%|
[nixspam](#nixspam)|19062|19062|98|0.5%|14.1%|
[blocklist_de](#blocklist_de)|26256|26256|73|0.2%|10.5%|
[blocklist_de_mail](#blocklist_de_mail)|16558|16558|56|0.3%|8.0%|
[snort_ipfilter](#snort_ipfilter)|9943|9943|52|0.5%|7.4%|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|51|0.0%|7.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|49|0.0%|7.0%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|37|0.1%|5.3%|
[php_dictionary](#php_dictionary)|545|545|30|5.5%|4.3%|
[php_spammers](#php_spammers)|536|536|28|5.2%|4.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|25|0.0%|3.6%|
[ri_web_proxies](#ri_web_proxies)|6664|6664|24|0.3%|3.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|22|0.0%|3.1%|
[xroxy](#xroxy)|2107|2107|17|0.8%|2.4%|
[stopforumspam_1d](#stopforumspam_1d)|6675|6675|16|0.2%|2.3%|
[blocklist_de_bots](#blocklist_de_bots)|2967|2967|14|0.4%|2.0%|
[proxz](#proxz)|906|906|11|1.2%|1.5%|
[sorbs_socks](#sorbs_socks)|22|22,22|3|13.6%|0.4%|
[sorbs_misc](#sorbs_misc)|22|22,22|3|13.6%|0.4%|
[sorbs_http](#sorbs_http)|22|22,22|3|13.6%|0.4%|
[php_commenters](#php_commenters)|349|349|3|0.8%|0.4%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|3893|3893|3|0.0%|0.4%|
[blocklist_de_apache](#blocklist_de_apache)|15244|15244|3|0.0%|0.4%|
[ri_connect_proxies](#ri_connect_proxies)|2475|2475|1|0.0%|0.1%|
[proxyrss](#proxyrss)|1416|1416|1|0.0%|0.1%|
[openbl_60d](#openbl_60d)|7286|7286|1|0.0%|0.1%|
[openbl_30d](#openbl_30d)|3252|3252|1|0.0%|0.1%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1|0.0%|0.1%|
[blocklist_de_strongips](#blocklist_de_strongips)|177|177|1|0.5%|0.1%|
[alienvault_reputation](#alienvault_reputation)|182275|182275|1|0.0%|0.1%|

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
[et_block](#et_block)|1023|18338662|18120448|98.8%|98.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|8598042|2.4%|46.7%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|6998016|76.2%|38.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|2272265|0.2%|12.3%|
[fullbogons](#fullbogons)|3721|670267288|151552|0.0%|0.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|130368|0.0%|0.7%|
[alienvault_reputation](#alienvault_reputation)|182275|182275|1627|0.8%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1037|0.3%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|1021|1.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|512|0.1%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|322|1.0%|0.0%|
[openbl_60d](#openbl_60d)|7286|7286|239|3.2%|0.0%|
[blocklist_de](#blocklist_de)|26256|26256|177|0.6%|0.0%|
[openbl_30d](#openbl_30d)|3252|3252|160|4.9%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1659|1659|106|6.3%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1821|1821|101|5.5%|0.0%|
[et_compromised](#et_compromised)|2016|2016|100|4.9%|0.0%|
[shunlist](#shunlist)|1215|1215|96|7.9%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6675|6675|84|1.2%|0.0%|
[openbl_7d](#openbl_7d)|843|843|47|5.5%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|2967|2967|42|1.4%|0.0%|
[nixspam](#nixspam)|19062|19062|41|0.2%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|29|2.2%|0.0%|
[php_commenters](#php_commenters)|349|349|28|8.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|16558|16558|24|0.1%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9943|9943|20|0.2%|0.0%|
[zeus_badips](#zeus_badips)|202|202|16|7.9%|0.0%|
[zeus](#zeus)|232|232|16|6.8%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|1605|1605|16|0.9%|0.0%|
[voipbl](#voipbl)|10476|10476,10888|14|0.1%|0.0%|
[sorbs_spam](#sorbs_spam)|31523|31523,32638|12|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|31523|31523,32638|12|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|31523|31523,32638|12|0.0%|0.0%|
[openbl_1d](#openbl_1d)|146|146|12|8.2%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|177|177|7|3.9%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|6|0.4%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|6|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|3893|3893|5|0.1%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|15244|15244|5|0.0%|0.0%|
[php_dictionary](#php_dictionary)|545|545|4|0.7%|0.0%|
[malc0de](#malc0de)|361|361|4|1.1%|0.0%|
[php_spammers](#php_spammers)|536|536|3|0.5%|0.0%|
[dm_tor](#dm_tor)|6512|6512|3|0.0%|0.0%|
[bm_tor](#bm_tor)|6516|6516|3|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|2|0.2%|0.0%|
[et_tor](#et_tor)|6470|6470|2|0.0%|0.0%|
[sslbl](#sslbl)|369|369|1|0.2%|0.0%|
[php_harvesters](#php_harvesters)|311|311|1|0.3%|0.0%|
[et_botcc](#et_botcc)|509|509|1|0.1%|0.0%|

## spamhaus_edrop

[Spamhaus.org](http://www.spamhaus.org) EDROP (extended matches that should be used with DROP) - **excellent list**

Source is downloaded from [this link](http://www.spamhaus.org/drop/edrop.txt).

The last time downloaded was found to be dated: Fri Jun  5 14:46:17 UTC 2015.

The ipset `spamhaus_edrop` has **56** entries, **487424** unique IPs.

The following table shows the overlaps of `spamhaus_edrop` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `spamhaus_edrop`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `spamhaus_edrop`.
- ` this % ` is the percentage **of this ipset (`spamhaus_edrop`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|270785|0.1%|55.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|98904|0.0%|20.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|33155|0.0%|6.8%|
[et_block](#et_block)|1023|18338662|517|0.0%|0.1%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|512|0.0%|0.1%|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|88|0.0%|0.0%|
[alienvault_reputation](#alienvault_reputation)|182275|182275|15|0.0%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|11|0.0%|0.0%|
[php_commenters](#php_commenters)|349|349|7|2.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9943|9943|6|0.0%|0.0%|
[zeus_badips](#zeus_badips)|202|202|5|2.4%|0.0%|
[zeus](#zeus)|232|232|5|2.1%|0.0%|
[blocklist_de](#blocklist_de)|26256|26256|4|0.0%|0.0%|
[sorbs_spam](#sorbs_spam)|31523|31523,32638|3|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|31523|31523,32638|3|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|31523|31523,32638|3|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|177|177|3|1.6%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|2967|2967|3|0.1%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6675|6675|2|0.0%|0.0%|
[php_harvesters](#php_harvesters)|311|311|1|0.3%|0.0%|
[openbl_60d](#openbl_60d)|7286|7286|1|0.0%|0.0%|
[openbl_30d](#openbl_30d)|3252|3252|1|0.0%|0.0%|
[malc0de](#malc0de)|361|361|1|0.2%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|15244|15244|1|0.0%|0.0%|

## sslbl

[Abuse.ch SSL Blacklist](https://sslbl.abuse.ch/) bad SSL traffic related to malware or botnet activities - **excellent list**

Source is downloaded from [this link](https://sslbl.abuse.ch/blacklist/sslipblacklist.csv).

The last time downloaded was found to be dated: Sat Jun  6 18:45:06 UTC 2015.

The ipset `sslbl` has **369** entries, **369** unique IPs.

The following table shows the overlaps of `sslbl` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `sslbl`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `sslbl`.
- ` this % ` is the percentage **of this ipset (`sslbl`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[alienvault_reputation](#alienvault_reputation)|182275|182275|65|0.0%|17.6%|
[shunlist](#shunlist)|1215|1215|57|4.6%|15.4%|
[feodo](#feodo)|99|99|36|36.3%|9.7%|
[et_block](#et_block)|1023|18338662|35|0.0%|9.4%|
[snort_ipfilter](#snort_ipfilter)|9943|9943|31|0.3%|8.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|26|0.0%|7.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|5|0.0%|1.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|3|0.0%|0.8%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|1|0.0%|0.2%|
[ri_web_proxies](#ri_web_proxies)|6664|6664|1|0.0%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.2%|
[blocklist_de_ssh](#blocklist_de_ssh)|1659|1659|1|0.0%|0.2%|
[blocklist_de](#blocklist_de)|26256|26256|1|0.0%|0.2%|

## stopforumspam_1d

[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers in the last 24 hours - **excellent list**

Source is downloaded from [this link](http://www.stopforumspam.com/downloads/listed_ip_1.zip).

The last time downloaded was found to be dated: Sat Jun  6 18:00:01 UTC 2015.

The ipset `stopforumspam_1d` has **6675** entries, **6675** unique IPs.

The following table shows the overlaps of `stopforumspam_1d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `stopforumspam_1d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `stopforumspam_1d`.
- ` this % ` is the percentage **of this ipset (`stopforumspam_1d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|4806|5.1%|72.0%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|4512|14.9%|67.5%|
[blocklist_de](#blocklist_de)|26256|26256|1221|4.6%|18.2%|
[blocklist_de_bots](#blocklist_de_bots)|2967|2967|1162|39.1%|17.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|512|0.0%|7.6%|
[ri_web_proxies](#ri_web_proxies)|6664|6664|454|6.8%|6.8%|
[snort_ipfilter](#snort_ipfilter)|9943|9943|382|3.8%|5.7%|
[dm_tor](#dm_tor)|6512|6512|334|5.1%|5.0%|
[bm_tor](#bm_tor)|6516|6516|334|5.1%|5.0%|
[et_tor](#et_tor)|6470|6470|333|5.1%|4.9%|
[proxyrss](#proxyrss)|1416|1416|316|22.3%|4.7%|
[xroxy](#xroxy)|2107|2107|266|12.6%|3.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|192|0.0%|2.8%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|165|44.3%|2.4%|
[proxz](#proxz)|906|906|158|17.4%|2.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|139|0.0%|2.0%|
[ri_connect_proxies](#ri_connect_proxies)|2475|2475|137|5.5%|2.0%|
[php_commenters](#php_commenters)|349|349|135|38.6%|2.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|177|177|101|57.0%|1.5%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|84|0.0%|1.2%|
[et_block](#et_block)|1023|18338662|80|0.0%|1.1%|
[blocklist_de_apache](#blocklist_de_apache)|15244|15244|63|0.4%|0.9%|
[sorbs_spam](#sorbs_spam)|31523|31523,32638|57|0.1%|0.8%|
[sorbs_recent_spam](#sorbs_recent_spam)|31523|31523,32638|57|0.1%|0.8%|
[sorbs_new_spam](#sorbs_new_spam)|31523|31523,32638|57|0.1%|0.8%|
[blocklist_de_mail](#blocklist_de_mail)|16558|16558|52|0.3%|0.7%|
[alienvault_reputation](#alienvault_reputation)|182275|182275|51|0.0%|0.7%|
[nixspam](#nixspam)|19062|19062|45|0.2%|0.6%|
[php_spammers](#php_spammers)|536|536|39|7.2%|0.5%|
[php_harvesters](#php_harvesters)|311|311|37|11.8%|0.5%|
[php_dictionary](#php_dictionary)|545|545|33|6.0%|0.4%|
[openbl_60d](#openbl_60d)|7286|7286|20|0.2%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|20|0.0%|0.2%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|3893|3893|17|0.4%|0.2%|
[sorbs_web](#sorbs_web)|693|693,694|16|2.3%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|6|0.0%|0.0%|
[voipbl](#voipbl)|10476|10476,10888|5|0.0%|0.0%|
[dshield](#dshield)|19|19,5120|4|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|3|0.4%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|3|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|2|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|830|830|2|0.2%|0.0%|
[zeus_badips](#zeus_badips)|202|202|1|0.4%|0.0%|
[zeus](#zeus)|232|232|1|0.4%|0.0%|
[shunlist](#shunlist)|1215|1215|1|0.0%|0.0%|
[openbl_30d](#openbl_30d)|3252|3252|1|0.0%|0.0%|

## stopforumspam_30d

[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 30 days)

Source is downloaded from [this link](http://www.stopforumspam.com/downloads/listed_ip_30.zip).

The last time downloaded was found to be dated: Sat Jun  6 00:00:44 UTC 2015.

The ipset `stopforumspam_30d` has **93258** entries, **93258** unique IPs.

The following table shows the overlaps of `stopforumspam_30d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `stopforumspam_30d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `stopforumspam_30d`.
- ` this % ` is the percentage **of this ipset (`stopforumspam_30d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|29983|99.5%|32.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|5841|0.0%|6.2%|
[stopforumspam_1d](#stopforumspam_1d)|6675|6675|4806|72.0%|5.1%|
[ri_web_proxies](#ri_web_proxies)|6664|6664|3207|48.1%|3.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|2524|0.0%|2.7%|
[blocklist_de](#blocklist_de)|26256|26256|2238|8.5%|2.3%|
[blocklist_de_bots](#blocklist_de_bots)|2967|2967|1910|64.3%|2.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|1543|0.0%|1.6%|
[ri_connect_proxies](#ri_connect_proxies)|2475|2475|1418|57.2%|1.5%|
[xroxy](#xroxy)|2107|2107|1239|58.8%|1.3%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|1021|0.0%|1.0%|
[et_block](#et_block)|1023|18338662|1013|0.0%|1.0%|
[snort_ipfilter](#snort_ipfilter)|9943|9943|803|8.0%|0.8%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|744|0.0%|0.7%|
[proxyrss](#proxyrss)|1416|1416|722|50.9%|0.7%|
[et_tor](#et_tor)|6470|6470|647|10.0%|0.6%|
[dm_tor](#dm_tor)|6512|6512|637|9.7%|0.6%|
[bm_tor](#bm_tor)|6516|6516|637|9.7%|0.6%|
[proxz](#proxz)|906|906|542|59.8%|0.5%|
[sorbs_spam](#sorbs_spam)|31523|31523,32638|341|1.0%|0.3%|
[sorbs_recent_spam](#sorbs_recent_spam)|31523|31523,32638|341|1.0%|0.3%|
[sorbs_new_spam](#sorbs_new_spam)|31523|31523,32638|341|1.0%|0.3%|
[blocklist_de_mail](#blocklist_de_mail)|16558|16558|255|1.5%|0.2%|
[php_commenters](#php_commenters)|349|349|253|72.4%|0.2%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|231|62.0%|0.2%|
[blocklist_de_apache](#blocklist_de_apache)|15244|15244|217|1.4%|0.2%|
[alienvault_reputation](#alienvault_reputation)|182275|182275|205|0.1%|0.2%|
[nixspam](#nixspam)|19062|19062|155|0.8%|0.1%|
[blocklist_de_strongips](#blocklist_de_strongips)|177|177|129|72.8%|0.1%|
[php_spammers](#php_spammers)|536|536|117|21.8%|0.1%|
[php_dictionary](#php_dictionary)|545|545|103|18.8%|0.1%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|88|0.0%|0.0%|
[php_harvesters](#php_harvesters)|311|311|68|21.8%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|3893|3893|55|1.4%|0.0%|
[openbl_60d](#openbl_60d)|7286|7286|54|0.7%|0.0%|
[sorbs_web](#sorbs_web)|693|693,694|51|7.3%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|46|0.0%|0.0%|
[voipbl](#voipbl)|10476|10476,10888|35|0.3%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|22|3.2%|0.0%|
[dshield](#dshield)|19|19,5120|15|0.2%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|14|0.0%|0.0%|
[et_compromised](#et_compromised)|2016|2016|11|0.5%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1821|1821|11|0.6%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|830|830|11|1.3%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|1605|1605|8|0.4%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1659|1659|6|0.3%|0.0%|
[shunlist](#shunlist)|1215|1215|5|0.4%|0.0%|
[openbl_30d](#openbl_30d)|3252|3252|5|0.1%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|4|0.3%|0.0%|
[sorbs_socks](#sorbs_socks)|22|22,22|3|13.6%|0.0%|
[sorbs_misc](#sorbs_misc)|22|22,22|3|13.6%|0.0%|
[sorbs_http](#sorbs_http)|22|22,22|3|13.6%|0.0%|
[openbl_7d](#openbl_7d)|843|843|3|0.3%|0.0%|
[zeus_badips](#zeus_badips)|202|202|2|0.9%|0.0%|
[zeus](#zeus)|232|232|2|0.8%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.0%|
[fullbogons](#fullbogons)|3721|670267288|2|0.0%|0.0%|
[ciarmy](#ciarmy)|412|412|1|0.2%|0.0%|
[bogons](#bogons)|13|592708608|1|0.0%|0.0%|

## stopforumspam_7d

[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 7 days)

Source is downloaded from [this link](http://www.stopforumspam.com/downloads/listed_ip_7.zip).

The last time downloaded was found to be dated: Sat Jun  6 01:02:25 UTC 2015.

The ipset `stopforumspam_7d` has **30121** entries, **30121** unique IPs.

The following table shows the overlaps of `stopforumspam_7d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `stopforumspam_7d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `stopforumspam_7d`.
- ` this % ` is the percentage **of this ipset (`stopforumspam_7d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|29983|32.1%|99.5%|
[stopforumspam_1d](#stopforumspam_1d)|6675|6675|4512|67.5%|14.9%|
[blocklist_de](#blocklist_de)|26256|26256|1920|7.3%|6.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|1912|0.0%|6.3%|
[blocklist_de_bots](#blocklist_de_bots)|2967|2967|1741|58.6%|5.7%|
[ri_web_proxies](#ri_web_proxies)|6664|6664|1627|24.4%|5.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|909|0.0%|3.0%|
[xroxy](#xroxy)|2107|2107|723|34.3%|2.4%|
[ri_connect_proxies](#ri_connect_proxies)|2475|2475|651|26.3%|2.1%|
[snort_ipfilter](#snort_ipfilter)|9943|9943|626|6.2%|2.0%|
[proxyrss](#proxyrss)|1416|1416|577|40.7%|1.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|568|0.0%|1.8%|
[et_tor](#et_tor)|6470|6470|516|7.9%|1.7%|
[dm_tor](#dm_tor)|6512|6512|504|7.7%|1.6%|
[bm_tor](#bm_tor)|6516|6516|504|7.7%|1.6%|
[proxz](#proxz)|906|906|422|46.5%|1.4%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|322|0.0%|1.0%|
[et_block](#et_block)|1023|18338662|314|0.0%|1.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|191|51.3%|0.6%|
[php_commenters](#php_commenters)|349|349|185|53.0%|0.6%|
[sorbs_spam](#sorbs_spam)|31523|31523,32638|181|0.5%|0.6%|
[sorbs_recent_spam](#sorbs_recent_spam)|31523|31523,32638|181|0.5%|0.6%|
[sorbs_new_spam](#sorbs_new_spam)|31523|31523,32638|181|0.5%|0.6%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|153|0.0%|0.5%|
[blocklist_de_mail](#blocklist_de_mail)|16558|16558|142|0.8%|0.4%|
[blocklist_de_apache](#blocklist_de_apache)|15244|15244|129|0.8%|0.4%|
[blocklist_de_strongips](#blocklist_de_strongips)|177|177|118|66.6%|0.3%|
[alienvault_reputation](#alienvault_reputation)|182275|182275|94|0.0%|0.3%|
[nixspam](#nixspam)|19062|19062|84|0.4%|0.2%|
[php_spammers](#php_spammers)|536|536|66|12.3%|0.2%|
[php_dictionary](#php_dictionary)|545|545|66|12.1%|0.2%|
[php_harvesters](#php_harvesters)|311|311|51|16.3%|0.1%|
[sorbs_web](#sorbs_web)|693|693,694|37|5.3%|0.1%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|3893|3893|33|0.8%|0.1%|
[openbl_60d](#openbl_60d)|7286|7286|25|0.3%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|25|0.0%|0.0%|
[voipbl](#voipbl)|10476|10476,10888|12|0.1%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|12|1.7%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|11|0.0%|0.0%|
[dshield](#dshield)|19|19,5120|8|0.1%|0.0%|
[et_compromised](#et_compromised)|2016|2016|7|0.3%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1821|1821|7|0.3%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|6|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|830|830|4|0.4%|0.0%|
[sorbs_socks](#sorbs_socks)|22|22,22|3|13.6%|0.0%|
[sorbs_misc](#sorbs_misc)|22|22,22|3|13.6%|0.0%|
[sorbs_http](#sorbs_http)|22|22,22|3|13.6%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|1605|1605|3|0.1%|0.0%|
[shunlist](#shunlist)|1215|1215|2|0.1%|0.0%|
[openbl_30d](#openbl_30d)|3252|3252|2|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1659|1659|2|0.1%|0.0%|
[zeus_badips](#zeus_badips)|202|202|1|0.4%|0.0%|
[zeus](#zeus)|232|232|1|0.4%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|1|0.0%|0.0%|
[ciarmy](#ciarmy)|412|412|1|0.2%|0.0%|

## virbl

[VirBL](http://virbl.bit.nl/) is a project of which the idea was born during the RIPE-48 meeting. The plan was to get reports of virusscanning mailservers, and put the IP-addresses that were reported to send viruses on a blacklist.

Source is downloaded from [this link](http://virbl.bit.nl/download/virbl.dnsbl.bit.nl.txt).

The last time downloaded was found to be dated: Sat Jun  6 18:52:03 UTC 2015.

The ipset `virbl` has **4** entries, **4** unique IPs.

The following table shows the overlaps of `virbl` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `virbl`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `virbl`.
- ` this % ` is the percentage **of this ipset (`virbl`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|1|0.0%|25.0%|

## voipbl

[VoIPBL.org](http://www.voipbl.org/) a distributed VoIP blacklist that is aimed to protects against VoIP Fraud and minimizing abuse for network that have publicly accessible PBX's. Several algorithms, external sources and manual confirmation are used before they categorize something as an attack and determine the threat level.

Source is downloaded from [this link](http://www.voipbl.org/update/).

The last time downloaded was found to be dated: Sat Jun  6 17:18:39 UTC 2015.

The ipset `voipbl` has **10476** entries, **10476,10888** unique IPs.

The following table shows the overlaps of `voipbl` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `voipbl`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `voipbl`.
- ` this % ` is the percentage **of this ipset (`voipbl`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|1599|0.0%|14.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|434|0.0%|3.9%|
[fullbogons](#fullbogons)|3721|670267288|319|0.0%|2.9%|
[bogons](#bogons)|13|592708608|319|0.0%|2.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|297|0.0%|2.7%|
[alienvault_reputation](#alienvault_reputation)|182275|182275|203|0.1%|1.8%|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|35|0.0%|0.3%|
[blocklist_de](#blocklist_de)|26256|26256|35|0.1%|0.3%|
[blocklist_de_sip](#blocklist_de_sip)|91|91|27|29.6%|0.2%|
[et_block](#et_block)|1023|18338662|17|0.0%|0.1%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|14|0.0%|0.1%|
[shunlist](#shunlist)|1215|1215|13|1.0%|0.1%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|12|0.0%|0.1%|
[openbl_60d](#openbl_60d)|7286|7286|8|0.1%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6675|6675|5|0.0%|0.0%|
[dshield](#dshield)|19|19,5120|5|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|4|0.0%|0.0%|
[ciarmy](#ciarmy)|412|412|4|0.9%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|2967|2967|4|0.1%|0.0%|
[openbl_30d](#openbl_30d)|3252|3252|3|0.0%|0.0%|
[et_tor](#et_tor)|6470|6470|3|0.0%|0.0%|
[dm_tor](#dm_tor)|6512|6512|3|0.0%|0.0%|
[bm_tor](#bm_tor)|6516|6516|3|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|15244|15244|3|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|2|0.0%|0.0%|
[et_compromised](#et_compromised)|2016|2016|2|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1821|1821|2|0.1%|0.0%|
[openbl_7d](#openbl_7d)|843|843|1|0.1%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|16558|16558|1|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|3893|3893|1|0.0%|0.0%|

## xroxy

[xroxy.com](http://www.xroxy.com) open proxies (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.xroxy.com/proxyrss.xml).

The last time downloaded was found to be dated: Sat Jun  6 18:33:01 UTC 2015.

The ipset `xroxy` has **2107** entries, **2107** unique IPs.

The following table shows the overlaps of `xroxy` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `xroxy`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `xroxy`.
- ` this % ` is the percentage **of this ipset (`xroxy`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|1239|1.3%|58.8%|
[ri_web_proxies](#ri_web_proxies)|6664|6664|901|13.5%|42.7%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|723|2.4%|34.3%|
[proxyrss](#proxyrss)|1416|1416|391|27.6%|18.5%|
[ri_connect_proxies](#ri_connect_proxies)|2475|2475|365|14.7%|17.3%|
[proxz](#proxz)|906|906|346|38.1%|16.4%|
[stopforumspam_1d](#stopforumspam_1d)|6675|6675|266|3.9%|12.6%|
[blocklist_de](#blocklist_de)|26256|26256|218|0.8%|10.3%|
[blocklist_de_bots](#blocklist_de_bots)|2967|2967|179|6.0%|8.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|101|0.0%|4.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|97|0.0%|4.6%|
[sorbs_spam](#sorbs_spam)|31523|31523,32638|86|0.2%|4.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|31523|31523,32638|86|0.2%|4.0%|
[sorbs_new_spam](#sorbs_new_spam)|31523|31523,32638|86|0.2%|4.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|58|0.0%|2.7%|
[snort_ipfilter](#snort_ipfilter)|9943|9943|46|0.4%|2.1%|
[blocklist_de_mail](#blocklist_de_mail)|16558|16558|38|0.2%|1.8%|
[php_dictionary](#php_dictionary)|545|545|33|6.0%|1.5%|
[nixspam](#nixspam)|19062|19062|32|0.1%|1.5%|
[php_spammers](#php_spammers)|536|536|26|4.8%|1.2%|
[sorbs_web](#sorbs_web)|693|693,694|17|2.4%|0.8%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|13|1.9%|0.6%|
[php_commenters](#php_commenters)|349|349|8|2.2%|0.3%|
[blocklist_de_strongips](#blocklist_de_strongips)|177|177|7|3.9%|0.3%|
[alienvault_reputation](#alienvault_reputation)|182275|182275|4|0.0%|0.1%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|3|0.0%|0.1%|
[php_harvesters](#php_harvesters)|311|311|2|0.6%|0.0%|
[et_tor](#et_tor)|6470|6470|2|0.0%|0.0%|
[dm_tor](#dm_tor)|6512|6512|2|0.0%|0.0%|
[bm_tor](#bm_tor)|6516|6516|2|0.0%|0.0%|
[sorbs_socks](#sorbs_socks)|22|22,22|1|4.5%|0.0%|
[sorbs_misc](#sorbs_misc)|22|22,22|1|4.5%|0.0%|
[sorbs_http](#sorbs_http)|22|22,22|1|4.5%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.0%|
[et_compromised](#et_compromised)|2016|2016|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1821|1821|1|0.0%|0.0%|

## zeus

[Abuse.ch Zeus tracker](https://zeustracker.abuse.ch) standard, contains the same data as the ZeuS IP blocklist (zeus_badips) but with the slight difference that it doesn't exclude hijacked websites (level 2) and free web hosting providers (level 3). This means that this blocklist contains all IPv4 addresses associated with ZeuS C&Cs which are currently being tracked by ZeuS Tracker. Hence this blocklist will likely cause some false positives. - **excellent list**

Source is downloaded from [this link](https://zeustracker.abuse.ch/blocklist.php?download=ipblocklist).

The last time downloaded was found to be dated: Sat Jun  6 16:01:18 UTC 2015.

The ipset `zeus` has **232** entries, **232** unique IPs.

The following table shows the overlaps of `zeus` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `zeus`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `zeus`.
- ` this % ` is the percentage **of this ipset (`zeus`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[et_block](#et_block)|1023|18338662|220|0.0%|94.8%|
[snort_ipfilter](#snort_ipfilter)|9943|9943|203|2.0%|87.5%|
[zeus_badips](#zeus_badips)|202|202|202|100.0%|87.0%|
[alienvault_reputation](#alienvault_reputation)|182275|182275|63|0.0%|27.1%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|16|0.0%|6.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|14|0.0%|6.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|10|0.0%|4.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|9|0.0%|3.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|6|0.0%|2.5%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|5|0.0%|2.1%|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|2|0.0%|0.8%|
[openbl_60d](#openbl_60d)|7286|7286|2|0.0%|0.8%|
[openbl_30d](#openbl_30d)|3252|3252|2|0.0%|0.8%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|1|0.0%|0.4%|
[stopforumspam_1d](#stopforumspam_1d)|6675|6675|1|0.0%|0.4%|
[php_commenters](#php_commenters)|349|349|1|0.2%|0.4%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.4%|

## zeus_badips

[Abuse.ch Zeus tracker](https://zeustracker.abuse.ch) badips includes IPv4 addresses that are used by the ZeuS trojan. It is the recommened blocklist if you want to block only ZeuS IPs. It excludes IP addresses that ZeuS Tracker believes to be hijacked (level 2) or belong to a free web hosting provider (level 3). Hence the false postive rate should be much lower compared to the standard ZeuS IP blocklist. **excellent list**

Source is downloaded from [this link](https://zeustracker.abuse.ch/blocklist.php?download=badips).

The last time downloaded was found to be dated: Sat Jun  6 18:27:08 UTC 2015.

The ipset `zeus_badips` has **202** entries, **202** unique IPs.

The following table shows the overlaps of `zeus_badips` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `zeus_badips`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `zeus_badips`.
- ` this % ` is the percentage **of this ipset (`zeus_badips`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[zeus](#zeus)|232|232|202|87.0%|100.0%|
[et_block](#et_block)|1023|18338662|200|0.0%|99.0%|
[snort_ipfilter](#snort_ipfilter)|9943|9943|179|1.8%|88.6%|
[alienvault_reputation](#alienvault_reputation)|182275|182275|38|0.0%|18.8%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|16|0.0%|7.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|10|0.0%|4.9%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|10|0.0%|4.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|8|0.0%|3.9%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|5|0.0%|2.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|4|0.0%|1.9%|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|2|0.0%|0.9%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|1|0.0%|0.4%|
[stopforumspam_1d](#stopforumspam_1d)|6675|6675|1|0.0%|0.4%|
[php_commenters](#php_commenters)|349|349|1|0.2%|0.4%|
[openbl_60d](#openbl_60d)|7286|7286|1|0.0%|0.4%|
[openbl_30d](#openbl_30d)|3252|3252|1|0.0%|0.4%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.4%|
