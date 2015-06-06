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

The following list was automatically generated on Sat Jun  6 22:19:31 UTC 2015.

The update frequency is the maximum allowed by internal configuration. A list will never be downloaded sooner than the update frequency stated. A list may also not be downloaded, after this frequency expired, if it has not been modified on the server (as reported by HTTP `IF_MODIFIED_SINCE` method).

name|info|type|entries|update|
:--:|:--:|:--:|:-----:|:----:|
[alienvault_reputation](#alienvault_reputation)|[AlienVault.com](https://www.alienvault.com/) IP reputation database (this list seems to include port scanning hosts and to be updated regularly, but we found no information about its retention policy)|ipv4 hash:ip|177556 unique IPs|updated every 6 hours  from [this link](https://reputation.alienvault.com/reputation.generic)
[blocklist_de](#blocklist_de)|[Blocklist.de](https://www.blocklist.de/) IPs that have been detected by fail2ban in the last 48 hours - **excellent list**|ipv4 hash:ip|26854 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/all.txt)
[blocklist_de_apache](#blocklist_de_apache)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service Apache, Apache-DDOS, RFI-Attacks.|ipv4 hash:ip|15414 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/apache.txt)
[blocklist_de_bots](#blocklist_de_bots)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the RFI-Attacks, REG-Bots, IRC-Bots or BadBots (BadBots = he has posted a Spam-Comment on a open Forum or Wiki).|ipv4 hash:ip|3010 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/bots.txt)
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|[Blocklist.de](https://www.blocklist.de/) All IPs which attacks Joomlas, Wordpress and other Web-Logins with Brute-Force Logins.|ipv4 hash:ip|4063 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/bruteforcelogin.txt)
[blocklist_de_ftp](#blocklist_de_ftp)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours for attacks on the Service FTP.|ipv4 hash:ip|828 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/ftp.txt)
[blocklist_de_imap](#blocklist_de_imap)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours for attacks on the Service imap, sasl, pop3, etc.|ipv4 hash:ip|1984 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/imap.txt)
[blocklist_de_mail](#blocklist_de_mail)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service Mail, Postfix.|ipv4 hash:ip|16943 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/mail.txt)
[blocklist_de_sip](#blocklist_de_sip)|[Blocklist.de](https://www.blocklist.de/) All IP addresses that tried to login in a SIP, VOIP or Asterisk Server and are included in the IPs list from [infiltrated.net](www.infiltrated.net)|ipv4 hash:ip|94 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/sip.txt)
[blocklist_de_ssh](#blocklist_de_ssh)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service SSH.|ipv4 hash:ip|1689 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/ssh.txt)
[blocklist_de_strongips](#blocklist_de_strongips)|[Blocklist.de](https://www.blocklist.de/) All IPs which are older then 2 month and have more then 5.000 attacks.|ipv4 hash:ip|179 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/strongips.txt)
[bm_tor](#bm_tor)|[torstatus.blutmagie.de](https://torstatus.blutmagie.de) list of all TOR network servers|ipv4 hash:ip|6501 unique IPs|updated every 30 mins  from [this link](https://torstatus.blutmagie.de/ip_list_all.php/Tor_ip_list_ALL.csv)
[bogons](#bogons)|[Team-Cymru.org](http://www.team-cymru.org) private and reserved addresses defined by RFC 1918, RFC 5735, and RFC 6598 and netblocks that have not been allocated to a regional internet registry - **excellent list - use it only your internet interface**|ipv4 hash:net|13 subnets, 592708608 unique IPs|updated every 1 day  from [this link](http://www.team-cymru.org/Services/Bogons/bogon-bn-agg.txt)
[bruteforceblocker](#bruteforceblocker)|[danger.rulez.sk](http://danger.rulez.sk/) IPs detected by [bruteforceblocker](http://danger.rulez.sk/index.php/bruteforceblocker/) (fail2ban alternative for SSH on OpenBSD). This is an automatically generated list from users reporting failed authentication attempts. An IP seems to be included if 3 or more users report it. Its retention pocily seems 30 days.|ipv4 hash:ip|1801 unique IPs|updated every 3 hours  from [this link](http://danger.rulez.sk/projects/bruteforceblocker/blist.php)
[ciarmy](#ciarmy)|[CIArmy.com](http://ciarmy.com/) IPs with poor Rogue Packet score that have not yet been identified as malicious by the community|ipv4 hash:ip|423 unique IPs|updated every 3 hours  from [this link](http://cinsscore.com/list/ci-badguys.txt)
[cleanmx_viruses](#cleanmx_viruses)|[Clean-MX.de](http://support.clean-mx.de/clean-mx/viruses.php) IPs with viruses|ipv4 hash:ip|230 unique IPs|updated every 12 hours  from [this link](http://support.clean-mx.de/clean-mx/xmlviruses.php?sort=id%20desc&response=alive)
[dm_tor](#dm_tor)|[dan.me.uk](https://www.dan.me.uk) dynamic list of TOR exit points|ipv4 hash:ip|6497 unique IPs|updated every 30 mins  from [this link](https://www.dan.me.uk/torlist/)
[dshield](#dshield)|[DShield.org](https://dshield.org/) top 20 attacking class C (/24) subnets over the last three days - **excellent list**|ipv4 hash:net|20 subnets, 20,5120 unique IPs|updated every 4 hours  from [this link](http://feeds.dshield.org/block.txt)
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
[nixspam](#nixspam)|[NiX Spam](http://www.heise.de/ix/NiX-Spam-DNSBL-and-blacklist-for-download-499637.html) IP addresses that sent spam in the last hour - automatically generated entries without distinguishing open proxies from relays, dialup gateways, and so on. All IPs are removed after 12 hours if there is no spam from there.|ipv4 hash:ip|19587 unique IPs|updated every 15 mins  from [this link](http://www.dnsbl.manitu.net/download/nixspam-ip.dump.gz)
openbl|[OpenBL.org](http://www.openbl.org/) default blacklist (currently it is the same with 90 days). OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications - **excellent list**|ipv4 hash:ip|disabled|updated every 4 hours  from [this link](http://www.openbl.org/lists/base.txt)
openbl_180d|[OpenBL.org](http://www.openbl.org/) last 180 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|disabled|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_180days.txt)
[openbl_1d](#openbl_1d)|[OpenBL.org](http://www.openbl.org/) last 24 hours IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|150 unique IPs|updated every 1 hour  from [this link](http://www.openbl.org/lists/base_1days.txt)
[openbl_30d](#openbl_30d)|[OpenBL.org](http://www.openbl.org/) last 30 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|3257 unique IPs|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_30days.txt)
openbl_360d|[OpenBL.org](http://www.openbl.org/) last 360 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|disabled|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_360days.txt)
[openbl_60d](#openbl_60d)|[OpenBL.org](http://www.openbl.org/) last 60 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|7286 unique IPs|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_60days.txt)
[openbl_7d](#openbl_7d)|[OpenBL.org](http://www.openbl.org/) last 7 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|836 unique IPs|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_7days.txt)
openbl_90d|[OpenBL.org](http://www.openbl.org/) last 90 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|disabled|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_90days.txt)
openbl_all|[OpenBL.org](http://www.openbl.org/) last all IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|disabled|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_all.txt)
[palevo](#palevo)|[Abuse.ch Palevo tracker](https://palevotracker.abuse.ch) worm includes IPs which are being used as botnet C&C for the Palevo crimeware - **excellent list**|ipv4 hash:ip|13 unique IPs|updated every 30 mins  from [this link](https://palevotracker.abuse.ch/blocklists.php?download=ipblocklist)
php_bad|[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) bad web hosts (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|disabled|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=b&rss=1)
[php_commenters](#php_commenters)|[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) comment spammers (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|349 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=c&rss=1)
[php_dictionary](#php_dictionary)|[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) directory attackers (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|545 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=d&rss=1)
[php_harvesters](#php_harvesters)|[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) harvesters (IPs that surf the internet looking for email addresses) (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|324 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=h&rss=1)
[php_spammers](#php_spammers)|[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) spam servers (IPs used by spammers to send messages) (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|536 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=s&rss=1)
[proxyrss](#proxyrss)|[proxyrss.com](http://www.proxyrss.com) open proxies syndicated from multiple sources.|ipv4 hash:ip|1748 unique IPs|updated every 4 hours  from [this link](http://www.proxyrss.com/proxylists/all.gz)
[proxz](#proxz)|[proxz.com](http://www.proxz.com) open proxies (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|915 unique IPs|updated every 1 hour  from [this link](http://www.proxz.com/proxylists.xml)
[ri_connect_proxies](#ri_connect_proxies)|[rosinstrument.com](http://www.rosinstrument.com) open CONNECT proxies (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|2475 unique IPs|updated every 1 hour  from [this link](http://tools.rosinstrument.com/proxy/plab100.xml)
[ri_web_proxies](#ri_web_proxies)|[rosinstrument.com](http://www.rosinstrument.com) open HTTP proxies (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|6677 unique IPs|updated every 1 hour  from [this link](http://tools.rosinstrument.com/proxy/l100.xml)
[shunlist](#shunlist)|[AutoShun.org](http://autoshun.org/) IPs identified as hostile by correlating logs from distributed snort installations running the autoshun plugin|ipv4 hash:ip|1215 unique IPs|updated every 4 hours  from [this link](http://www.autoshun.org/files/shunlist.csv)
[snort_ipfilter](#snort_ipfilter)|[labs.snort.org](https://labs.snort.org/) supplied IP blacklist (this list seems to be updated frequently, but we found no information about it)|ipv4 hash:ip|9943 unique IPs|updated every 12 hours  from [this link](http://labs.snort.org/feeds/ip-filter.blf)
[sorbs_dul](#sorbs_dul)|[Sorbs.net](https://www.sorbs.net/) DUL, Dynamic User IPs extracted from deltas.|ipv4 hash:net|8 subnets, 3584 unique IPs|updated every 1 min  from [this link]()
[sorbs_http](#sorbs_http)|[Sorbs.net](https://www.sorbs.net/) HTTP proxies, extracted from deltas.|ipv4 hash:net|22 subnets, 22,22 unique IPs|updated every 1 min  from [this link]()
[sorbs_misc](#sorbs_misc)|[Sorbs.net](https://www.sorbs.net/) MISC proxies, extracted from deltas.|ipv4 hash:net|22 subnets, 22,22 unique IPs|updated every 1 min  from [this link]()
[sorbs_new_spam](#sorbs_new_spam)|[Sorbs.net](https://www.sorbs.net/) NEW Spam senders, extracted from deltas.|ipv4 hash:net|32328 subnets, 32328,33461 unique IPs|updated every 1 min  from [this link]()
[sorbs_recent_spam](#sorbs_recent_spam)|[Sorbs.net](https://www.sorbs.net/) RECENT Spam senders, extracted from deltas.|ipv4 hash:net|32328 subnets, 32328,33461 unique IPs|updated every 1 min  from [this link]()
[sorbs_smtp](#sorbs_smtp)|[Sorbs.net](https://www.sorbs.net/) SMTP Open Relays, extracted from deltas.|ipv4 hash:net|14 subnets, 14,14 unique IPs|updated every 1 min  from [this link]()
[sorbs_socks](#sorbs_socks)|[Sorbs.net](https://www.sorbs.net/) SOCKS proxies, extracted from deltas.|ipv4 hash:net|22 subnets, 22,22 unique IPs|updated every 1 min  from [this link]()
[sorbs_spam](#sorbs_spam)|[Sorbs.net](https://www.sorbs.net/) Spam senders, extracted from deltas.|ipv4 hash:net|32328 subnets, 32328,33461 unique IPs|updated every 1 min  from [this link]()
[sorbs_web](#sorbs_web)|[Sorbs.net](https://www.sorbs.net/) WEB exploits, extracted from deltas.|ipv4 hash:net|709 subnets, 709,710 unique IPs|updated every 1 min  from [this link]()
[spamhaus_drop](#spamhaus_drop)|[Spamhaus.org](http://www.spamhaus.org) DROP list (according to their site this list should be dropped at tier-1 ISPs globaly) - **excellent list**|ipv4 hash:net|653 subnets, 18404096 unique IPs|updated every 12 hours  from [this link](http://www.spamhaus.org/drop/drop.txt)
[spamhaus_edrop](#spamhaus_edrop)|[Spamhaus.org](http://www.spamhaus.org) EDROP (extended matches that should be used with DROP) - **excellent list**|ipv4 hash:net|56 subnets, 487424 unique IPs|updated every 12 hours  from [this link](http://www.spamhaus.org/drop/edrop.txt)
[sslbl](#sslbl)|[Abuse.ch SSL Blacklist](https://sslbl.abuse.ch/) bad SSL traffic related to malware or botnet activities - **excellent list**|ipv4 hash:ip|367 unique IPs|updated every 30 mins  from [this link](https://sslbl.abuse.ch/blacklist/sslipblacklist.csv)
stopforumspam_180d|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 180 days)|ipv4 hash:ip|disabled|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/listed_ip_180.zip)
[stopforumspam_1d](#stopforumspam_1d)|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers in the last 24 hours - **excellent list**|ipv4 hash:ip|6481 unique IPs|updated every 1 hour  from [this link](http://www.stopforumspam.com/downloads/listed_ip_1.zip)
[stopforumspam_30d](#stopforumspam_30d)|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 30 days)|ipv4 hash:ip|93258 unique IPs|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/listed_ip_30.zip)
stopforumspam_365d|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 365 days)|ipv4 hash:ip|disabled|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/listed_ip_365.zip)
[stopforumspam_7d](#stopforumspam_7d)|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 7 days)|ipv4 hash:ip|30121 unique IPs|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/listed_ip_7.zip)
stopforumspam_90d|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 90 days)|ipv4 hash:ip|disabled|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/listed_ip_90.zip)
stopforumspam_ever|[StopForumSpam.com](http://www.stopforumspam.com) all IPs used by forum spammers, **ever** (normally you don't want to use this ipset, use the hourly one which includes last 24 hours IPs or the 7 days one)|ipv4 hash:ip|disabled|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/bannedips.zip)
[virbl](#virbl)|[VirBL](http://virbl.bit.nl/) is a project of which the idea was born during the RIPE-48 meeting. The plan was to get reports of virusscanning mailservers, and put the IP-addresses that were reported to send viruses on a blacklist.|ipv4 hash:ip|4 unique IPs|updated every 1 hour  from [this link](http://virbl.bit.nl/download/virbl.dnsbl.bit.nl.txt)
[voipbl](#voipbl)|[VoIPBL.org](http://www.voipbl.org/) a distributed VoIP blacklist that is aimed to protects against VoIP Fraud and minimizing abuse for network that have publicly accessible PBX's. Several algorithms, external sources and manual confirmation are used before they categorize something as an attack and determine the threat level.|ipv4 hash:net|10476 subnets, 10476,10888 unique IPs|updated every 4 hours  from [this link](http://www.voipbl.org/update/)
[xroxy](#xroxy)|[xroxy.com](http://www.xroxy.com) open proxies (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|2108 unique IPs|updated every 1 hour  from [this link](http://www.xroxy.com/proxyrss.xml)
[zeus](#zeus)|[Abuse.ch Zeus tracker](https://zeustracker.abuse.ch) standard, contains the same data as the ZeuS IP blocklist (zeus_badips) but with the slight difference that it doesn't exclude hijacked websites (level 2) and free web hosting providers (level 3). This means that this blocklist contains all IPv4 addresses associated with ZeuS C&Cs which are currently being tracked by ZeuS Tracker. Hence this blocklist will likely cause some false positives. - **excellent list**|ipv4 hash:ip|232 unique IPs|updated every 30 mins  from [this link](https://zeustracker.abuse.ch/blocklist.php?download=ipblocklist)
[zeus_badips](#zeus_badips)|[Abuse.ch Zeus tracker](https://zeustracker.abuse.ch) badips includes IPv4 addresses that are used by the ZeuS trojan. It is the recommened blocklist if you want to block only ZeuS IPs. It excludes IP addresses that ZeuS Tracker believes to be hijacked (level 2) or belong to a free web hosting provider (level 3). Hence the false postive rate should be much lower compared to the standard ZeuS IP blocklist. **excellent list**|ipv4 hash:ip|202 unique IPs|updated every 30 mins  from [this link](https://zeustracker.abuse.ch/blocklist.php?download=badips)

# Comparison of ipsets

Below we compare each ipset against all other.


## alienvault_reputation

[AlienVault.com](https://www.alienvault.com/) IP reputation database (this list seems to include port scanning hosts and to be updated regularly, but we found no information about its retention policy)

Source is downloaded from [this link](https://reputation.alienvault.com/reputation.generic).

The last time downloaded was found to be dated: Sat Jun  6 22:01:16 UTC 2015.

The ipset `alienvault_reputation` has **177556** entries, **177556** unique IPs.

The following table shows the overlaps of `alienvault_reputation` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `alienvault_reputation`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `alienvault_reputation`.
- ` this % ` is the percentage **of this ipset (`alienvault_reputation`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|13873|0.0%|7.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|7271|0.0%|4.0%|
[openbl_60d](#openbl_60d)|7286|7286|7266|99.7%|4.0%|
[et_block](#et_block)|1023|18338662|5262|0.0%|2.9%|
[dshield](#dshield)|20|20,5120|3321|64.8%|1.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|3303|0.0%|1.8%|
[openbl_30d](#openbl_30d)|3257|3257|3242|99.5%|1.8%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|1627|0.0%|0.9%|
[et_compromised](#et_compromised)|2016|2016|1314|65.1%|0.7%|
[shunlist](#shunlist)|1215|1215|1210|99.5%|0.6%|
[bruteforceblocker](#bruteforceblocker)|1801|1801|1160|64.4%|0.6%|
[blocklist_de](#blocklist_de)|26854|26854|1029|3.8%|0.5%|
[openbl_7d](#openbl_7d)|836|836|831|99.4%|0.4%|
[blocklist_de_ssh](#blocklist_de_ssh)|1689|1689|798|47.2%|0.4%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|516|0.0%|0.2%|
[ciarmy](#ciarmy)|423|423|416|98.3%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|285|0.0%|0.1%|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|205|0.2%|0.1%|
[voipbl](#voipbl)|10476|10476,10888|198|1.8%|0.1%|
[openbl_1d](#openbl_1d)|150|150|147|98.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|15414|15414|132|0.8%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9943|9943|119|1.1%|0.0%|
[sorbs_spam](#sorbs_spam)|32328|32328,33461|100|0.2%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|32328|32328,33461|100|0.2%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|32328|32328,33461|100|0.2%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|93|0.3%|0.0%|
[sslbl](#sslbl)|367|367|64|17.4%|0.0%|
[zeus](#zeus)|232|232|63|27.1%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|16943|16943|61|0.3%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6481|6481|52|0.8%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|1984|1984|45|2.2%|0.0%|
[dm_tor](#dm_tor)|6497|6497|41|0.6%|0.0%|
[bm_tor](#bm_tor)|6501|6501|41|0.6%|0.0%|
[et_tor](#et_tor)|6470|6470|40|0.6%|0.0%|
[zeus_badips](#zeus_badips)|202|202|38|18.8%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|179|179|36|20.1%|0.0%|
[nixspam](#nixspam)|19587|19587|29|0.1%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3010|3010|29|0.9%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|26|6.9%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4063|4063|21|0.5%|0.0%|
[php_commenters](#php_commenters)|349|349|17|4.8%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|16|0.0%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|94|94|16|17.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|15|0.0%|0.0%|
[malc0de](#malc0de)|361|361|11|3.0%|0.0%|
[php_harvesters](#php_harvesters)|324|324|10|3.0%|0.0%|
[php_dictionary](#php_dictionary)|545|545|8|1.4%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|8|0.5%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|230|230|8|3.4%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|6|0.4%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|828|828|6|0.7%|0.0%|
[php_spammers](#php_spammers)|536|536|5|0.9%|0.0%|
[et_botcc](#et_botcc)|509|509|5|0.9%|0.0%|
[xroxy](#xroxy)|2108|2108|4|0.1%|0.0%|
[ri_web_proxies](#ri_web_proxies)|6677|6677|3|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2475|2475|3|0.1%|0.0%|
[proxz](#proxz)|915|915|3|0.3%|0.0%|
[feodo](#feodo)|99|99|2|2.0%|0.0%|
[sorbs_web](#sorbs_web)|709|709,710|1|0.1%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|1|0.1%|0.0%|

## blocklist_de

[Blocklist.de](https://www.blocklist.de/) IPs that have been detected by fail2ban in the last 48 hours - **excellent list**

Source is downloaded from [this link](http://lists.blocklist.de/lists/all.txt).

The last time downloaded was found to be dated: Sat Jun  6 21:56:05 UTC 2015.

The ipset `blocklist_de` has **26854** entries, **26854** unique IPs.

The following table shows the overlaps of `blocklist_de` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de`.
- ` this % ` is the percentage **of this ipset (`blocklist_de`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de_mail](#blocklist_de_mail)|16943|16943|16920|99.8%|63.0%|
[blocklist_de_apache](#blocklist_de_apache)|15414|15414|15413|99.9%|57.3%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4063|4063|4061|99.9%|15.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|3449|0.0%|12.8%|
[blocklist_de_bots](#blocklist_de_bots)|3010|3010|3010|100.0%|11.2%|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|2242|2.4%|8.3%|
[blocklist_de_imap](#blocklist_de_imap)|1984|1984|1969|99.2%|7.3%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|1901|6.3%|7.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1689|1689|1667|98.6%|6.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|1491|0.0%|5.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|1433|0.0%|5.3%|
[stopforumspam_1d](#stopforumspam_1d)|6481|6481|1210|18.6%|4.5%|
[sorbs_spam](#sorbs_spam)|32328|32328,33461|1043|3.1%|3.8%|
[sorbs_recent_spam](#sorbs_recent_spam)|32328|32328,33461|1043|3.1%|3.8%|
[sorbs_new_spam](#sorbs_new_spam)|32328|32328,33461|1043|3.1%|3.8%|
[alienvault_reputation](#alienvault_reputation)|177556|177556|1029|0.5%|3.8%|
[blocklist_de_ftp](#blocklist_de_ftp)|828|828|828|100.0%|3.0%|
[openbl_60d](#openbl_60d)|7286|7286|766|10.5%|2.8%|
[openbl_30d](#openbl_30d)|3257|3257|696|21.3%|2.5%|
[et_compromised](#et_compromised)|2016|2016|613|30.4%|2.2%|
[bruteforceblocker](#bruteforceblocker)|1801|1801|606|33.6%|2.2%|
[nixspam](#nixspam)|19587|19587|434|2.2%|1.6%|
[openbl_7d](#openbl_7d)|836|836|413|49.4%|1.5%|
[shunlist](#shunlist)|1215|1215|356|29.3%|1.3%|
[ri_web_proxies](#ri_web_proxies)|6677|6677|356|5.3%|1.3%|
[xroxy](#xroxy)|2108|2108|209|9.9%|0.7%|
[et_block](#et_block)|1023|18338662|192|0.0%|0.7%|
[proxyrss](#proxyrss)|1748|1748|179|10.2%|0.6%|
[blocklist_de_strongips](#blocklist_de_strongips)|179|179|179|100.0%|0.6%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|177|0.0%|0.6%|
[snort_ipfilter](#snort_ipfilter)|9943|9943|156|1.5%|0.5%|
[proxz](#proxz)|915|915|136|14.8%|0.5%|
[openbl_1d](#openbl_1d)|150|150|122|81.3%|0.4%|
[dshield](#dshield)|20|20,5120|114|2.2%|0.4%|
[php_spammers](#php_spammers)|536|536|92|17.1%|0.3%|
[php_dictionary](#php_dictionary)|545|545|89|16.3%|0.3%|
[php_commenters](#php_commenters)|349|349|86|24.6%|0.3%|
[sorbs_web](#sorbs_web)|709|709,710|77|10.8%|0.2%|
[blocklist_de_sip](#blocklist_de_sip)|94|94|75|79.7%|0.2%|
[ri_connect_proxies](#ri_connect_proxies)|2475|2475|61|2.4%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|48|0.0%|0.1%|
[voipbl](#voipbl)|10476|10476,10888|36|0.3%|0.1%|
[ciarmy](#ciarmy)|423|423|35|8.2%|0.1%|
[php_harvesters](#php_harvesters)|324|324|33|10.1%|0.1%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|13|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|10|0.0%|0.0%|
[sorbs_socks](#sorbs_socks)|22|22,22|5|22.7%|0.0%|
[sorbs_misc](#sorbs_misc)|22|22,22|5|22.7%|0.0%|
[sorbs_http](#sorbs_http)|22|22,22|5|22.7%|0.0%|
[dm_tor](#dm_tor)|6497|6497|5|0.0%|0.0%|
[bm_tor](#bm_tor)|6501|6501|5|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|4|0.0%|0.0%|
[et_tor](#et_tor)|6470|6470|4|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|3|0.8%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|2|0.2%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|230|230|1|0.4%|0.0%|

## blocklist_de_apache

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service Apache, Apache-DDOS, RFI-Attacks.

Source is downloaded from [this link](http://lists.blocklist.de/lists/apache.txt).

The last time downloaded was found to be dated: Sat Jun  6 21:56:11 UTC 2015.

The ipset `blocklist_de_apache` has **15414** entries, **15414** unique IPs.

The following table shows the overlaps of `blocklist_de_apache` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_apache`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_apache`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_apache`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|26854|26854|15413|57.3%|99.9%|
[blocklist_de_mail](#blocklist_de_mail)|16943|16943|11059|65.2%|71.7%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4063|4063|4062|99.9%|26.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|2406|0.0%|15.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|1324|0.0%|8.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|1086|0.0%|7.0%|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|216|0.2%|1.4%|
[alienvault_reputation](#alienvault_reputation)|177556|177556|132|0.0%|0.8%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|127|0.4%|0.8%|
[sorbs_spam](#sorbs_spam)|32328|32328,33461|108|0.3%|0.7%|
[sorbs_recent_spam](#sorbs_recent_spam)|32328|32328,33461|108|0.3%|0.7%|
[sorbs_new_spam](#sorbs_new_spam)|32328|32328,33461|108|0.3%|0.7%|
[stopforumspam_1d](#stopforumspam_1d)|6481|6481|59|0.9%|0.3%|
[shunlist](#shunlist)|1215|1215|36|2.9%|0.2%|
[blocklist_de_strongips](#blocklist_de_strongips)|179|179|34|18.9%|0.2%|
[nixspam](#nixspam)|19587|19587|31|0.1%|0.2%|
[ciarmy](#ciarmy)|423|423|31|7.3%|0.2%|
[php_commenters](#php_commenters)|349|349|26|7.4%|0.1%|
[blocklist_de_bots](#blocklist_de_bots)|3010|3010|22|0.7%|0.1%|
[et_block](#et_block)|1023|18338662|13|0.0%|0.0%|
[openbl_60d](#openbl_60d)|7286|7286|9|0.1%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9943|9943|8|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|7|0.0%|0.0%|
[php_spammers](#php_spammers)|536|536|6|1.1%|0.0%|
[openbl_30d](#openbl_30d)|3257|3257|6|0.1%|0.0%|
[dshield](#dshield)|20|20,5120|6|0.1%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|5|0.0%|0.0%|
[php_harvesters](#php_harvesters)|324|324|5|1.5%|0.0%|
[php_dictionary](#php_dictionary)|545|545|4|0.7%|0.0%|
[et_tor](#et_tor)|6470|6470|4|0.0%|0.0%|
[dm_tor](#dm_tor)|6497|6497|4|0.0%|0.0%|
[bm_tor](#bm_tor)|6501|6501|4|0.0%|0.0%|
[voipbl](#voipbl)|10476|10476,10888|3|0.0%|0.0%|
[sorbs_web](#sorbs_web)|709|709,710|3|0.4%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|3|0.0%|0.0%|
[openbl_7d](#openbl_7d)|836|836|2|0.2%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|2|0.5%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|1|0.0%|0.0%|
[et_compromised](#et_compromised)|2016|2016|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1801|1801|1|0.0%|0.0%|

## blocklist_de_bots

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the RFI-Attacks, REG-Bots, IRC-Bots or BadBots (BadBots = he has posted a Spam-Comment on a open Forum or Wiki).

Source is downloaded from [this link](http://lists.blocklist.de/lists/bots.txt).

The last time downloaded was found to be dated: Sat Jun  6 21:56:13 UTC 2015.

The ipset `blocklist_de_bots` has **3010** entries, **3010** unique IPs.

The following table shows the overlaps of `blocklist_de_bots` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_bots`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_bots`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_bots`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|26854|26854|3010|11.2%|100.0%|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|1924|2.0%|63.9%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|1731|5.7%|57.5%|
[stopforumspam_1d](#stopforumspam_1d)|6481|6481|1159|17.8%|38.5%|
[ri_web_proxies](#ri_web_proxies)|6677|6677|301|4.5%|10.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|201|0.0%|6.6%|
[proxyrss](#proxyrss)|1748|1748|179|10.2%|5.9%|
[xroxy](#xroxy)|2108|2108|171|8.1%|5.6%|
[blocklist_de_strongips](#blocklist_de_strongips)|179|179|134|74.8%|4.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|123|0.0%|4.0%|
[proxz](#proxz)|915|915|115|12.5%|3.8%|
[php_commenters](#php_commenters)|349|349|70|20.0%|2.3%|
[ri_connect_proxies](#ri_connect_proxies)|2475|2475|58|2.3%|1.9%|
[sorbs_spam](#sorbs_spam)|32328|32328,33461|57|0.1%|1.8%|
[sorbs_recent_spam](#sorbs_recent_spam)|32328|32328,33461|57|0.1%|1.8%|
[sorbs_new_spam](#sorbs_new_spam)|32328|32328,33461|57|0.1%|1.8%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|41|0.0%|1.3%|
[et_block](#et_block)|1023|18338662|41|0.0%|1.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|35|0.0%|1.1%|
[snort_ipfilter](#snort_ipfilter)|9943|9943|30|0.3%|0.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|29|0.0%|0.9%|
[alienvault_reputation](#alienvault_reputation)|177556|177556|29|0.0%|0.9%|
[php_spammers](#php_spammers)|536|536|26|4.8%|0.8%|
[nixspam](#nixspam)|19587|19587|25|0.1%|0.8%|
[php_harvesters](#php_harvesters)|324|324|24|7.4%|0.7%|
[php_dictionary](#php_dictionary)|545|545|24|4.4%|0.7%|
[blocklist_de_mail](#blocklist_de_mail)|16943|16943|22|0.1%|0.7%|
[blocklist_de_apache](#blocklist_de_apache)|15414|15414|22|0.1%|0.7%|
[sorbs_web](#sorbs_web)|709|709,710|15|2.1%|0.4%|
[openbl_60d](#openbl_60d)|7286|7286|11|0.1%|0.3%|
[voipbl](#voipbl)|10476|10476,10888|4|0.0%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|4|0.0%|0.1%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|3|0.0%|0.0%|
[openbl_30d](#openbl_30d)|3257|3257|2|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|2|0.2%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1|0.0%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|230|230|1|0.4%|0.0%|

## blocklist_de_bruteforce

[Blocklist.de](https://www.blocklist.de/) All IPs which attacks Joomlas, Wordpress and other Web-Logins with Brute-Force Logins.

Source is downloaded from [this link](http://lists.blocklist.de/lists/bruteforcelogin.txt).

The last time downloaded was found to be dated: Sat Jun  6 21:56:15 UTC 2015.

The ipset `blocklist_de_bruteforce` has **4063** entries, **4063** unique IPs.

The following table shows the overlaps of `blocklist_de_bruteforce` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_bruteforce`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_bruteforce`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_bruteforce`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de_apache](#blocklist_de_apache)|15414|15414|4062|26.3%|99.9%|
[blocklist_de](#blocklist_de)|26854|26854|4061|15.1%|99.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|305|0.0%|7.5%|
[sorbs_spam](#sorbs_spam)|32328|32328,33461|108|0.3%|2.6%|
[sorbs_recent_spam](#sorbs_recent_spam)|32328|32328,33461|108|0.3%|2.6%|
[sorbs_new_spam](#sorbs_new_spam)|32328|32328,33461|108|0.3%|2.6%|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|57|0.0%|1.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|56|0.0%|1.3%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|34|0.1%|0.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|34|0.0%|0.8%|
[nixspam](#nixspam)|19587|19587|30|0.1%|0.7%|
[alienvault_reputation](#alienvault_reputation)|177556|177556|21|0.0%|0.5%|
[stopforumspam_1d](#stopforumspam_1d)|6481|6481|20|0.3%|0.4%|
[php_commenters](#php_commenters)|349|349|8|2.2%|0.1%|
[blocklist_de_strongips](#blocklist_de_strongips)|179|179|8|4.4%|0.1%|
[php_spammers](#php_spammers)|536|536|6|1.1%|0.1%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|6|0.0%|0.1%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|5|0.0%|0.1%|
[snort_ipfilter](#snort_ipfilter)|9943|9943|4|0.0%|0.0%|
[php_dictionary](#php_dictionary)|545|545|4|0.7%|0.0%|
[et_block](#et_block)|1023|18338662|4|0.0%|0.0%|
[sorbs_web](#sorbs_web)|709|709,710|3|0.4%|0.0%|
[php_harvesters](#php_harvesters)|324|324|3|0.9%|0.0%|
[shunlist](#shunlist)|1215|1215|2|0.1%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|2|0.0%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2|0.0%|0.0%|
[voipbl](#voipbl)|10476|10476,10888|1|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[ciarmy](#ciarmy)|423|423|1|0.2%|0.0%|

## blocklist_de_ftp

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours for attacks on the Service FTP.

Source is downloaded from [this link](http://lists.blocklist.de/lists/ftp.txt).

The last time downloaded was found to be dated: Sat Jun  6 21:56:12 UTC 2015.

The ipset `blocklist_de_ftp` has **828** entries, **828** unique IPs.

The following table shows the overlaps of `blocklist_de_ftp` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_ftp`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_ftp`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_ftp`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|26854|26854|828|3.0%|100.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|80|0.0%|9.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|14|0.0%|1.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|13|0.0%|1.5%|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|11|0.0%|1.3%|
[sorbs_spam](#sorbs_spam)|32328|32328,33461|6|0.0%|0.7%|
[sorbs_recent_spam](#sorbs_recent_spam)|32328|32328,33461|6|0.0%|0.7%|
[sorbs_new_spam](#sorbs_new_spam)|32328|32328,33461|6|0.0%|0.7%|
[alienvault_reputation](#alienvault_reputation)|177556|177556|6|0.0%|0.7%|
[nixspam](#nixspam)|19587|19587|4|0.0%|0.4%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|3|0.0%|0.3%|
[php_harvesters](#php_harvesters)|324|324|3|0.9%|0.3%|
[openbl_60d](#openbl_60d)|7286|7286|2|0.0%|0.2%|
[blocklist_de_strongips](#blocklist_de_strongips)|179|179|2|1.1%|0.2%|
[stopforumspam_1d](#stopforumspam_1d)|6481|6481|1|0.0%|0.1%|
[php_spammers](#php_spammers)|536|536|1|0.1%|0.1%|
[php_dictionary](#php_dictionary)|545|545|1|0.1%|0.1%|
[openbl_30d](#openbl_30d)|3257|3257|1|0.0%|0.1%|
[dm_tor](#dm_tor)|6497|6497|1|0.0%|0.1%|
[ciarmy](#ciarmy)|423|423|1|0.2%|0.1%|
[bm_tor](#bm_tor)|6501|6501|1|0.0%|0.1%|
[blocklist_de_mail](#blocklist_de_mail)|16943|16943|1|0.0%|0.1%|

## blocklist_de_imap

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours for attacks on the Service imap, sasl, pop3, etc.

Source is downloaded from [this link](http://lists.blocklist.de/lists/imap.txt).

The last time downloaded was found to be dated: Sat Jun  6 22:10:09 UTC 2015.

The ipset `blocklist_de_imap` has **1984** entries, **1984** unique IPs.

The following table shows the overlaps of `blocklist_de_imap` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_imap`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_imap`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_imap`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de_mail](#blocklist_de_mail)|16943|16943|1984|11.7%|100.0%|
[blocklist_de](#blocklist_de)|26854|26854|1969|7.3%|99.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|171|0.0%|8.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|51|0.0%|2.5%|
[alienvault_reputation](#alienvault_reputation)|177556|177556|45|0.0%|2.2%|
[openbl_60d](#openbl_60d)|7286|7286|37|0.5%|1.8%|
[openbl_30d](#openbl_30d)|3257|3257|31|0.9%|1.5%|
[nixspam](#nixspam)|19587|19587|27|0.1%|1.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|21|0.0%|1.0%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|18|0.0%|0.9%|
[sorbs_spam](#sorbs_spam)|32328|32328,33461|18|0.0%|0.9%|
[sorbs_recent_spam](#sorbs_recent_spam)|32328|32328,33461|18|0.0%|0.9%|
[sorbs_new_spam](#sorbs_new_spam)|32328|32328,33461|18|0.0%|0.9%|
[et_block](#et_block)|1023|18338662|18|0.0%|0.9%|
[openbl_7d](#openbl_7d)|836|836|10|1.1%|0.5%|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|8|0.0%|0.4%|
[et_compromised](#et_compromised)|2016|2016|8|0.3%|0.4%|
[bruteforceblocker](#bruteforceblocker)|1801|1801|8|0.4%|0.4%|
[ri_web_proxies](#ri_web_proxies)|6677|6677|5|0.0%|0.2%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|3|0.0%|0.1%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|3|0.0%|0.1%|
[snort_ipfilter](#snort_ipfilter)|9943|9943|2|0.0%|0.1%|
[openbl_1d](#openbl_1d)|150|150|2|1.3%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2|0.0%|0.1%|
[shunlist](#shunlist)|1215|1215|1|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2475|2475|1|0.0%|0.0%|
[php_dictionary](#php_dictionary)|545|545|1|0.1%|0.0%|
[php_commenters](#php_commenters)|349|349|1|0.2%|0.0%|
[ciarmy](#ciarmy)|423|423|1|0.2%|0.0%|

## blocklist_de_mail

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service Mail, Postfix.

Source is downloaded from [this link](http://lists.blocklist.de/lists/mail.txt).

The last time downloaded was found to be dated: Sat Jun  6 22:14:06 UTC 2015.

The ipset `blocklist_de_mail` has **16943** entries, **16943** unique IPs.

The following table shows the overlaps of `blocklist_de_mail` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_mail`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_mail`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_mail`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|26854|26854|16920|63.0%|99.8%|
[blocklist_de_apache](#blocklist_de_apache)|15414|15414|11059|71.7%|65.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|2638|0.0%|15.5%|
[blocklist_de_imap](#blocklist_de_imap)|1984|1984|1984|100.0%|11.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|1373|0.0%|8.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|1143|0.0%|6.7%|
[sorbs_spam](#sorbs_spam)|32328|32328,33461|870|2.6%|5.1%|
[sorbs_recent_spam](#sorbs_recent_spam)|32328|32328,33461|870|2.6%|5.1%|
[sorbs_new_spam](#sorbs_new_spam)|32328|32328,33461|870|2.6%|5.1%|
[nixspam](#nixspam)|19587|19587|371|1.8%|2.1%|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|249|0.2%|1.4%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|138|0.4%|0.8%|
[snort_ipfilter](#snort_ipfilter)|9943|9943|120|1.2%|0.7%|
[alienvault_reputation](#alienvault_reputation)|177556|177556|61|0.0%|0.3%|
[sorbs_web](#sorbs_web)|709|709,710|59|8.3%|0.3%|
[php_dictionary](#php_dictionary)|545|545|59|10.8%|0.3%|
[php_spammers](#php_spammers)|536|536|58|10.8%|0.3%|
[ri_web_proxies](#ri_web_proxies)|6677|6677|53|0.7%|0.3%|
[stopforumspam_1d](#stopforumspam_1d)|6481|6481|44|0.6%|0.2%|
[openbl_60d](#openbl_60d)|7286|7286|43|0.5%|0.2%|
[xroxy](#xroxy)|2108|2108|38|1.8%|0.2%|
[openbl_30d](#openbl_30d)|3257|3257|37|1.1%|0.2%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|24|0.0%|0.1%|
[et_block](#et_block)|1023|18338662|24|0.0%|0.1%|
[php_commenters](#php_commenters)|349|349|22|6.3%|0.1%|
[blocklist_de_bots](#blocklist_de_bots)|3010|3010|22|0.7%|0.1%|
[blocklist_de_strongips](#blocklist_de_strongips)|179|179|21|11.7%|0.1%|
[proxz](#proxz)|915|915|20|2.1%|0.1%|
[openbl_7d](#openbl_7d)|836|836|13|1.5%|0.0%|
[et_compromised](#et_compromised)|2016|2016|10|0.4%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1801|1801|10|0.5%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|6|0.0%|0.0%|
[sorbs_socks](#sorbs_socks)|22|22,22|5|22.7%|0.0%|
[sorbs_misc](#sorbs_misc)|22|22,22|5|22.7%|0.0%|
[sorbs_http](#sorbs_http)|22|22,22|5|22.7%|0.0%|
[openbl_1d](#openbl_1d)|150|150|4|2.6%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|4|0.0%|0.0%|
[et_tor](#et_tor)|6470|6470|4|0.0%|0.0%|
[dm_tor](#dm_tor)|6497|6497|4|0.0%|0.0%|
[bm_tor](#bm_tor)|6501|6501|4|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2475|2475|3|0.1%|0.0%|
[php_harvesters](#php_harvesters)|324|324|2|0.6%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|2|0.0%|0.0%|
[voipbl](#voipbl)|10476|10476,10888|1|0.0%|0.0%|
[shunlist](#shunlist)|1215|1215|1|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[ciarmy](#ciarmy)|423|423|1|0.2%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1689|1689|1|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|828|828|1|0.1%|0.0%|

## blocklist_de_sip

[Blocklist.de](https://www.blocklist.de/) All IP addresses that tried to login in a SIP, VOIP or Asterisk Server and are included in the IPs list from [infiltrated.net](www.infiltrated.net)

Source is downloaded from [this link](http://lists.blocklist.de/lists/sip.txt).

The last time downloaded was found to be dated: Sat Jun  6 22:14:08 UTC 2015.

The ipset `blocklist_de_sip` has **94** entries, **94** unique IPs.

The following table shows the overlaps of `blocklist_de_sip` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_sip`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_sip`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_sip`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|26854|26854|75|0.2%|79.7%|
[voipbl](#voipbl)|10476|10476,10888|28|0.2%|29.7%|
[alienvault_reputation](#alienvault_reputation)|177556|177556|16|0.0%|17.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|13|0.0%|13.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|7|0.0%|7.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|4|0.0%|4.2%|
[et_block](#et_block)|1023|18338662|3|0.0%|3.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|2|0.0%|2.1%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|1|0.0%|1.0%|
[et_botcc](#et_botcc)|509|509|1|0.1%|1.0%|

## blocklist_de_ssh

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service SSH.

Source is downloaded from [this link](http://lists.blocklist.de/lists/ssh.txt).

The last time downloaded was found to be dated: Sat Jun  6 22:10:05 UTC 2015.

The ipset `blocklist_de_ssh` has **1689** entries, **1689** unique IPs.

The following table shows the overlaps of `blocklist_de_ssh` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_ssh`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_ssh`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_ssh`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|26854|26854|1667|6.2%|98.6%|
[alienvault_reputation](#alienvault_reputation)|177556|177556|798|0.4%|47.2%|
[openbl_60d](#openbl_60d)|7286|7286|701|9.6%|41.5%|
[openbl_30d](#openbl_30d)|3257|3257|649|19.9%|38.4%|
[et_compromised](#et_compromised)|2016|2016|602|29.8%|35.6%|
[bruteforceblocker](#bruteforceblocker)|1801|1801|595|33.0%|35.2%|
[openbl_7d](#openbl_7d)|836|836|396|47.3%|23.4%|
[shunlist](#shunlist)|1215|1215|319|26.2%|18.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|190|0.0%|11.2%|
[openbl_1d](#openbl_1d)|150|150|118|78.6%|6.9%|
[et_block](#et_block)|1023|18338662|111|0.0%|6.5%|
[dshield](#dshield)|20|20,5120|107|2.0%|6.3%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|106|0.0%|6.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|88|0.0%|5.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|29|0.0%|1.7%|
[blocklist_de_strongips](#blocklist_de_strongips)|179|179|28|15.6%|1.6%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|5|0.0%|0.2%|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|4|0.0%|0.2%|
[nixspam](#nixspam)|19587|19587|3|0.0%|0.1%|
[ciarmy](#ciarmy)|423|423|3|0.7%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|2|0.0%|0.1%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|1|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|1|0.0%|0.0%|
[sorbs_spam](#sorbs_spam)|32328|32328,33461|1|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|32328|32328,33461|1|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|32328|32328,33461|1|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9943|9943|1|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|16943|16943|1|0.0%|0.0%|

## blocklist_de_strongips

[Blocklist.de](https://www.blocklist.de/) All IPs which are older then 2 month and have more then 5.000 attacks.

Source is downloaded from [this link](http://lists.blocklist.de/lists/strongips.txt).

The last time downloaded was found to be dated: Sat Jun  6 22:14:10 UTC 2015.

The ipset `blocklist_de_strongips` has **179** entries, **179** unique IPs.

The following table shows the overlaps of `blocklist_de_strongips` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_strongips`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_strongips`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_strongips`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|26854|26854|179|0.6%|100.0%|
[blocklist_de_bots](#blocklist_de_bots)|3010|3010|134|4.4%|74.8%|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|132|0.1%|73.7%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|121|0.4%|67.5%|
[stopforumspam_1d](#stopforumspam_1d)|6481|6481|101|1.5%|56.4%|
[php_commenters](#php_commenters)|349|349|37|10.6%|20.6%|
[alienvault_reputation](#alienvault_reputation)|177556|177556|36|0.0%|20.1%|
[blocklist_de_apache](#blocklist_de_apache)|15414|15414|34|0.2%|18.9%|
[blocklist_de_ssh](#blocklist_de_ssh)|1689|1689|28|1.6%|15.6%|
[openbl_60d](#openbl_60d)|7286|7286|26|0.3%|14.5%|
[openbl_7d](#openbl_7d)|836|836|24|2.8%|13.4%|
[openbl_30d](#openbl_30d)|3257|3257|24|0.7%|13.4%|
[blocklist_de_mail](#blocklist_de_mail)|16943|16943|21|0.1%|11.7%|
[shunlist](#shunlist)|1215|1215|20|1.6%|11.1%|
[openbl_1d](#openbl_1d)|150|150|20|13.3%|11.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|16|0.0%|8.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|8|0.0%|4.4%|
[et_block](#et_block)|1023|18338662|8|0.0%|4.4%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4063|4063|8|0.1%|4.4%|
[xroxy](#xroxy)|2108|2108|7|0.3%|3.9%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|7|0.0%|3.9%|
[ri_web_proxies](#ri_web_proxies)|6677|6677|5|0.0%|2.7%|
[proxyrss](#proxyrss)|1748|1748|5|0.2%|2.7%|
[php_spammers](#php_spammers)|536|536|5|0.9%|2.7%|
[proxz](#proxz)|915|915|4|0.4%|2.2%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|3|0.0%|1.6%|
[php_harvesters](#php_harvesters)|324|324|3|0.9%|1.6%|
[php_dictionary](#php_dictionary)|545|545|3|0.5%|1.6%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|1.6%|
[blocklist_de_ftp](#blocklist_de_ftp)|828|828|2|0.2%|1.1%|
[sorbs_web](#sorbs_web)|709|709,710|1|0.1%|0.5%|
[sorbs_spam](#sorbs_spam)|32328|32328,33461|1|0.0%|0.5%|
[sorbs_recent_spam](#sorbs_recent_spam)|32328|32328,33461|1|0.0%|0.5%|
[sorbs_new_spam](#sorbs_new_spam)|32328|32328,33461|1|0.0%|0.5%|
[snort_ipfilter](#snort_ipfilter)|9943|9943|1|0.0%|0.5%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.5%|
[dshield](#dshield)|20|20,5120|1|0.0%|0.5%|

## bm_tor

[torstatus.blutmagie.de](https://torstatus.blutmagie.de) list of all TOR network servers

Source is downloaded from [this link](https://torstatus.blutmagie.de/ip_list_all.php/Tor_ip_list_ALL.csv).

The last time downloaded was found to be dated: Sat Jun  6 21:54:07 UTC 2015.

The ipset `bm_tor` has **6501** entries, **6501** unique IPs.

The following table shows the overlaps of `bm_tor` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `bm_tor`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `bm_tor`.
- ` this % ` is the percentage **of this ipset (`bm_tor`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[dm_tor](#dm_tor)|6497|6497|6436|99.0%|99.0%|
[et_tor](#et_tor)|6470|6470|5711|88.2%|87.8%|
[snort_ipfilter](#snort_ipfilter)|9943|9943|1073|10.7%|16.5%|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|631|0.6%|9.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|622|0.0%|9.5%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|498|1.6%|7.6%|
[stopforumspam_1d](#stopforumspam_1d)|6481|6481|318|4.9%|4.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|191|0.0%|2.9%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|166|44.6%|2.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|162|0.0%|2.4%|
[alienvault_reputation](#alienvault_reputation)|177556|177556|41|0.0%|0.6%|
[php_commenters](#php_commenters)|349|349|36|10.3%|0.5%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|22|0.0%|0.3%|
[openbl_60d](#openbl_60d)|7286|7286|20|0.2%|0.3%|
[php_harvesters](#php_harvesters)|324|324|7|2.1%|0.1%|
[ri_web_proxies](#ri_web_proxies)|6677|6677|5|0.0%|0.0%|
[et_block](#et_block)|1023|18338662|5|0.0%|0.0%|
[blocklist_de](#blocklist_de)|26854|26854|5|0.0%|0.0%|
[php_spammers](#php_spammers)|536|536|4|0.7%|0.0%|
[php_dictionary](#php_dictionary)|545|545|4|0.7%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|4|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|16943|16943|4|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|15414|15414|4|0.0%|0.0%|
[voipbl](#voipbl)|10476|10476,10888|3|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|3|0.0%|0.0%|
[xroxy](#xroxy)|2108|2108|2|0.0%|0.0%|
[sorbs_spam](#sorbs_spam)|32328|32328,33461|2|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|32328|32328,33461|2|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|32328|32328,33461|2|0.0%|0.0%|
[shunlist](#shunlist)|1215|1215|1|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2475|2475|1|0.0%|0.0%|
[nixspam](#nixspam)|19587|19587|1|0.0%|0.0%|
[dshield](#dshield)|20|20,5120|1|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|828|828|1|0.1%|0.0%|

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
[php_harvesters](#php_harvesters)|324|324|1|0.3%|0.0%|
[php_commenters](#php_commenters)|349|349|1|0.2%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.0%|
[ciarmy](#ciarmy)|423|423|1|0.2%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1801|1801|1|0.0%|0.0%|

## bruteforceblocker

[danger.rulez.sk](http://danger.rulez.sk/) IPs detected by [bruteforceblocker](http://danger.rulez.sk/index.php/bruteforceblocker/) (fail2ban alternative for SSH on OpenBSD). This is an automatically generated list from users reporting failed authentication attempts. An IP seems to be included if 3 or more users report it. Its retention pocily seems 30 days.

Source is downloaded from [this link](http://danger.rulez.sk/projects/bruteforceblocker/blist.php).

The last time downloaded was found to be dated: Sat Jun  6 21:00:42 UTC 2015.

The ipset `bruteforceblocker` has **1801** entries, **1801** unique IPs.

The following table shows the overlaps of `bruteforceblocker` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `bruteforceblocker`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `bruteforceblocker`.
- ` this % ` is the percentage **of this ipset (`bruteforceblocker`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[et_compromised](#et_compromised)|2016|2016|1743|86.4%|96.7%|
[alienvault_reputation](#alienvault_reputation)|177556|177556|1160|0.6%|64.4%|
[openbl_60d](#openbl_60d)|7286|7286|1067|14.6%|59.2%|
[openbl_30d](#openbl_30d)|3257|3257|1027|31.5%|57.0%|
[blocklist_de](#blocklist_de)|26854|26854|606|2.2%|33.6%|
[blocklist_de_ssh](#blocklist_de_ssh)|1689|1689|595|35.2%|33.0%|
[shunlist](#shunlist)|1215|1215|422|34.7%|23.4%|
[openbl_7d](#openbl_7d)|836|836|351|41.9%|19.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|172|0.0%|9.5%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|101|0.0%|5.6%|
[et_block](#et_block)|1023|18338662|101|0.0%|5.6%|
[dshield](#dshield)|20|20,5120|101|1.9%|5.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|86|0.0%|4.7%|
[openbl_1d](#openbl_1d)|150|150|73|48.6%|4.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|46|0.0%|2.5%|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|11|0.0%|0.6%|
[blocklist_de_mail](#blocklist_de_mail)|16943|16943|10|0.0%|0.5%|
[blocklist_de_imap](#blocklist_de_imap)|1984|1984|8|0.4%|0.4%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|7|0.0%|0.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|5|0.0%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|3|0.0%|0.1%|
[voipbl](#voipbl)|10476|10476,10888|2|0.0%|0.1%|
[proxz](#proxz)|915|915|2|0.2%|0.1%|
[proxyrss](#proxyrss)|1748|1748|2|0.1%|0.1%|
[xroxy](#xroxy)|2108|2108|1|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6481|6481|1|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|6677|6677|1|0.0%|0.0%|
[nixspam](#nixspam)|19587|19587|1|0.0%|0.0%|
[fullbogons](#fullbogons)|3721|670267288|1|0.0%|0.0%|
[ciarmy](#ciarmy)|423|423|1|0.2%|0.0%|
[bogons](#bogons)|13|592708608|1|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|15414|15414|1|0.0%|0.0%|

## ciarmy

[CIArmy.com](http://ciarmy.com/) IPs with poor Rogue Packet score that have not yet been identified as malicious by the community

Source is downloaded from [this link](http://cinsscore.com/list/ci-badguys.txt).

The last time downloaded was found to be dated: Sat Jun  6 22:15:16 UTC 2015.

The ipset `ciarmy` has **423** entries, **423** unique IPs.

The following table shows the overlaps of `ciarmy` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ciarmy`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ciarmy`.
- ` this % ` is the percentage **of this ipset (`ciarmy`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[alienvault_reputation](#alienvault_reputation)|177556|177556|416|0.2%|98.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|81|0.0%|19.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|44|0.0%|10.4%|
[blocklist_de](#blocklist_de)|26854|26854|35|0.1%|8.2%|
[shunlist](#shunlist)|1215|1215|32|2.6%|7.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|31|0.0%|7.3%|
[blocklist_de_apache](#blocklist_de_apache)|15414|15414|31|0.2%|7.3%|
[et_block](#et_block)|1023|18338662|6|0.0%|1.4%|
[voipbl](#voipbl)|10476|10476,10888|4|0.0%|0.9%|
[dshield](#dshield)|20|20,5120|3|0.0%|0.7%|
[blocklist_de_ssh](#blocklist_de_ssh)|1689|1689|3|0.1%|0.7%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|1|0.0%|0.2%|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|1|0.0%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.2%|
[fullbogons](#fullbogons)|3721|670267288|1|0.0%|0.2%|
[et_compromised](#et_compromised)|2016|2016|1|0.0%|0.2%|
[bruteforceblocker](#bruteforceblocker)|1801|1801|1|0.0%|0.2%|
[bogons](#bogons)|13|592708608|1|0.0%|0.2%|
[blocklist_de_mail](#blocklist_de_mail)|16943|16943|1|0.0%|0.2%|
[blocklist_de_imap](#blocklist_de_imap)|1984|1984|1|0.0%|0.2%|
[blocklist_de_ftp](#blocklist_de_ftp)|828|828|1|0.1%|0.2%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4063|4063|1|0.0%|0.2%|

## cleanmx_viruses

[Clean-MX.de](http://support.clean-mx.de/clean-mx/viruses.php) IPs with viruses

Source is downloaded from [this link](http://support.clean-mx.de/clean-mx/xmlviruses.php?sort=id%20desc&response=alive).

The last time downloaded was found to be dated: Sat Jun  6 19:54:36 UTC 2015.

The ipset `cleanmx_viruses` has **230** entries, **230** unique IPs.

The following table shows the overlaps of `cleanmx_viruses` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `cleanmx_viruses`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `cleanmx_viruses`.
- ` this % ` is the percentage **of this ipset (`cleanmx_viruses`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|34|0.0%|14.7%|
[malc0de](#malc0de)|361|361|29|8.0%|12.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|14|0.0%|6.0%|
[alienvault_reputation](#alienvault_reputation)|177556|177556|8|0.0%|3.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|5|0.0%|2.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|2|0.0%|0.8%|
[xroxy](#xroxy)|2108|2108|1|0.0%|0.4%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|1|0.0%|0.4%|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|1|0.0%|0.4%|
[stopforumspam_1d](#stopforumspam_1d)|6481|6481|1|0.0%|0.4%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|1|0.0%|0.4%|
[snort_ipfilter](#snort_ipfilter)|9943|9943|1|0.0%|0.4%|
[ri_web_proxies](#ri_web_proxies)|6677|6677|1|0.0%|0.4%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|1|0.0%|0.4%|
[blocklist_de_bots](#blocklist_de_bots)|3010|3010|1|0.0%|0.4%|
[blocklist_de](#blocklist_de)|26854|26854|1|0.0%|0.4%|

## dm_tor

[dan.me.uk](https://www.dan.me.uk) dynamic list of TOR exit points

Source is downloaded from [this link](https://www.dan.me.uk/torlist/).

The last time downloaded was found to be dated: Sat Jun  6 21:54:04 UTC 2015.

The ipset `dm_tor` has **6497** entries, **6497** unique IPs.

The following table shows the overlaps of `dm_tor` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `dm_tor`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `dm_tor`.
- ` this % ` is the percentage **of this ipset (`dm_tor`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[bm_tor](#bm_tor)|6501|6501|6436|99.0%|99.0%|
[et_tor](#et_tor)|6470|6470|5706|88.1%|87.8%|
[snort_ipfilter](#snort_ipfilter)|9943|9943|1072|10.7%|16.4%|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|634|0.6%|9.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|622|0.0%|9.5%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|502|1.6%|7.7%|
[stopforumspam_1d](#stopforumspam_1d)|6481|6481|317|4.8%|4.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|191|0.0%|2.9%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|167|44.8%|2.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|161|0.0%|2.4%|
[alienvault_reputation](#alienvault_reputation)|177556|177556|41|0.0%|0.6%|
[php_commenters](#php_commenters)|349|349|36|10.3%|0.5%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|22|0.0%|0.3%|
[openbl_60d](#openbl_60d)|7286|7286|20|0.2%|0.3%|
[php_harvesters](#php_harvesters)|324|324|7|2.1%|0.1%|
[ri_web_proxies](#ri_web_proxies)|6677|6677|5|0.0%|0.0%|
[et_block](#et_block)|1023|18338662|5|0.0%|0.0%|
[blocklist_de](#blocklist_de)|26854|26854|5|0.0%|0.0%|
[php_spammers](#php_spammers)|536|536|4|0.7%|0.0%|
[php_dictionary](#php_dictionary)|545|545|4|0.7%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|4|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|16943|16943|4|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|15414|15414|4|0.0%|0.0%|
[voipbl](#voipbl)|10476|10476,10888|3|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|3|0.0%|0.0%|
[xroxy](#xroxy)|2108|2108|2|0.0%|0.0%|
[sorbs_spam](#sorbs_spam)|32328|32328,33461|2|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|32328|32328,33461|2|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|32328|32328,33461|2|0.0%|0.0%|
[shunlist](#shunlist)|1215|1215|1|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2475|2475|1|0.0%|0.0%|
[nixspam](#nixspam)|19587|19587|1|0.0%|0.0%|
[dshield](#dshield)|20|20,5120|1|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|828|828|1|0.1%|0.0%|

## dshield

[DShield.org](https://dshield.org/) top 20 attacking class C (/24) subnets over the last three days - **excellent list**

Source is downloaded from [this link](http://feeds.dshield.org/block.txt).

The last time downloaded was found to be dated: Sat Jun  6 19:20:01 UTC 2015.

The ipset `dshield` has **20** entries, **20,5120** unique IPs.

The following table shows the overlaps of `dshield` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `dshield`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `dshield`.
- ` this % ` is the percentage **of this ipset (`dshield`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[alienvault_reputation](#alienvault_reputation)|177556|177556|3321|1.8%|64.8%|
[et_block](#et_block)|1023|18338662|1280|0.0%|25.0%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|256|0.0%|5.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|256|0.0%|5.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|256|0.0%|5.0%|
[openbl_60d](#openbl_60d)|7286|7286|172|2.3%|3.3%|
[openbl_30d](#openbl_30d)|3257|3257|160|4.9%|3.1%|
[shunlist](#shunlist)|1215|1215|123|10.1%|2.4%|
[blocklist_de](#blocklist_de)|26854|26854|114|0.4%|2.2%|
[et_compromised](#et_compromised)|2016|2016|109|5.4%|2.1%|
[blocklist_de_ssh](#blocklist_de_ssh)|1689|1689|107|6.3%|2.0%|
[bruteforceblocker](#bruteforceblocker)|1801|1801|101|5.6%|1.9%|
[openbl_7d](#openbl_7d)|836|836|43|5.1%|0.8%|
[openbl_1d](#openbl_1d)|150|150|12|8.0%|0.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|11|0.0%|0.2%|
[blocklist_de_apache](#blocklist_de_apache)|15414|15414|6|0.0%|0.1%|
[voipbl](#voipbl)|10476|10476,10888|5|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9943|9943|4|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|4|0.0%|0.0%|
[zeus_badips](#zeus_badips)|202|202|3|1.4%|0.0%|
[zeus](#zeus)|232|232|3|1.2%|0.0%|
[ciarmy](#ciarmy)|423|423|3|0.7%|0.0%|
[malc0de](#malc0de)|361|361|2|0.5%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|1|0.0%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|1|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6481|6481|1|0.0%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|1|0.0%|0.0%|
[et_tor](#et_tor)|6470|6470|1|0.0%|0.0%|
[dm_tor](#dm_tor)|6497|6497|1|0.0%|0.0%|
[bm_tor](#bm_tor)|6501|6501|1|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|179|179|1|0.5%|0.0%|

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
[alienvault_reputation](#alienvault_reputation)|177556|177556|5262|2.9%|0.0%|
[dshield](#dshield)|20|20,5120|1280|25.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1040|0.3%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|1013|1.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|517|0.1%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|314|1.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9943|9943|313|3.1%|0.0%|
[openbl_60d](#openbl_60d)|7286|7286|250|3.4%|0.0%|
[zeus](#zeus)|232|232|220|94.8%|0.0%|
[zeus_badips](#zeus_badips)|202|202|200|99.0%|0.0%|
[blocklist_de](#blocklist_de)|26854|26854|192|0.7%|0.0%|
[openbl_30d](#openbl_30d)|3257|3257|166|5.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1689|1689|111|6.5%|0.0%|
[shunlist](#shunlist)|1215|1215|110|9.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1801|1801|101|5.6%|0.0%|
[et_compromised](#et_compromised)|2016|2016|100|4.9%|0.0%|
[feodo](#feodo)|99|99|94|94.9%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6481|6481|78|1.2%|0.0%|
[openbl_7d](#openbl_7d)|836|836|50|5.9%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3010|3010|41|1.3%|0.0%|
[sslbl](#sslbl)|367|367|35|9.5%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|29|2.2%|0.0%|
[php_commenters](#php_commenters)|349|349|28|8.0%|0.0%|
[nixspam](#nixspam)|19587|19587|25|0.1%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|16943|16943|24|0.1%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|1984|1984|18|0.9%|0.0%|
[voipbl](#voipbl)|10476|10476,10888|17|0.1%|0.0%|
[sorbs_spam](#sorbs_spam)|32328|32328,33461|15|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|32328|32328,33461|15|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|32328|32328,33461|15|0.0%|0.0%|
[openbl_1d](#openbl_1d)|150|150|14|9.3%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|15414|15414|13|0.0%|0.0%|
[palevo](#palevo)|13|13|12|92.3%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|179|179|8|4.4%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|6|0.4%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|6|0.0%|0.0%|
[ciarmy](#ciarmy)|423|423|6|1.4%|0.0%|
[malc0de](#malc0de)|361|361|5|1.3%|0.0%|
[dm_tor](#dm_tor)|6497|6497|5|0.0%|0.0%|
[bm_tor](#bm_tor)|6501|6501|5|0.0%|0.0%|
[php_dictionary](#php_dictionary)|545|545|4|0.7%|0.0%|
[et_tor](#et_tor)|6470|6470|4|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4063|4063|4|0.0%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|94|94|3|3.1%|0.0%|
[php_spammers](#php_spammers)|536|536|2|0.3%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|2|0.2%|0.0%|
[php_harvesters](#php_harvesters)|324|324|1|0.3%|0.0%|
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
[alienvault_reputation](#alienvault_reputation)|177556|177556|5|0.0%|0.9%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|1|0.0%|0.1%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|1|0.0%|0.1%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.1%|
[et_block](#et_block)|1023|18338662|1|0.0%|0.1%|
[blocklist_de_sip](#blocklist_de_sip)|94|94|1|1.0%|0.1%|

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
[bruteforceblocker](#bruteforceblocker)|1801|1801|1743|96.7%|86.4%|
[alienvault_reputation](#alienvault_reputation)|177556|177556|1314|0.7%|65.1%|
[openbl_60d](#openbl_60d)|7286|7286|1217|16.7%|60.3%|
[openbl_30d](#openbl_30d)|3257|3257|1151|35.3%|57.0%|
[blocklist_de](#blocklist_de)|26854|26854|613|2.2%|30.4%|
[blocklist_de_ssh](#blocklist_de_ssh)|1689|1689|602|35.6%|29.8%|
[shunlist](#shunlist)|1215|1215|436|35.8%|21.6%|
[openbl_7d](#openbl_7d)|836|836|363|43.4%|18.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|199|0.0%|9.8%|
[dshield](#dshield)|20|20,5120|109|2.1%|5.4%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|100|0.0%|4.9%|
[et_block](#et_block)|1023|18338662|100|0.0%|4.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|97|0.0%|4.8%|
[openbl_1d](#openbl_1d)|150|150|72|48.0%|3.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|52|0.0%|2.5%|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|11|0.0%|0.5%|
[blocklist_de_mail](#blocklist_de_mail)|16943|16943|10|0.0%|0.4%|
[blocklist_de_imap](#blocklist_de_imap)|1984|1984|8|0.4%|0.3%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|7|0.0%|0.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|5|0.0%|0.2%|
[voipbl](#voipbl)|10476|10476,10888|2|0.0%|0.0%|
[proxz](#proxz)|915|915|2|0.2%|0.0%|
[proxyrss](#proxyrss)|1748|1748|2|0.1%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|2|0.0%|0.0%|
[xroxy](#xroxy)|2108|2108|1|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6481|6481|1|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|6677|6677|1|0.0%|0.0%|
[nixspam](#nixspam)|19587|19587|1|0.0%|0.0%|
[ciarmy](#ciarmy)|423|423|1|0.2%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|15414|15414|1|0.0%|0.0%|

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
[bm_tor](#bm_tor)|6501|6501|5711|87.8%|88.2%|
[dm_tor](#dm_tor)|6497|6497|5706|87.8%|88.1%|
[snort_ipfilter](#snort_ipfilter)|9943|9943|1084|10.9%|16.7%|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|647|0.6%|10.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|633|0.0%|9.7%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|516|1.7%|7.9%|
[stopforumspam_1d](#stopforumspam_1d)|6481|6481|317|4.8%|4.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|190|0.0%|2.9%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|168|45.1%|2.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|168|0.0%|2.5%|
[alienvault_reputation](#alienvault_reputation)|177556|177556|40|0.0%|0.6%|
[php_commenters](#php_commenters)|349|349|37|10.6%|0.5%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|22|0.0%|0.3%|
[openbl_60d](#openbl_60d)|7286|7286|20|0.2%|0.3%|
[php_harvesters](#php_harvesters)|324|324|7|2.1%|0.1%|
[php_spammers](#php_spammers)|536|536|6|1.1%|0.0%|
[ri_web_proxies](#ri_web_proxies)|6677|6677|5|0.0%|0.0%|
[php_dictionary](#php_dictionary)|545|545|5|0.9%|0.0%|
[et_block](#et_block)|1023|18338662|4|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|16943|16943|4|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|15414|15414|4|0.0%|0.0%|
[blocklist_de](#blocklist_de)|26854|26854|4|0.0%|0.0%|
[voipbl](#voipbl)|10476|10476,10888|3|0.0%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|0.0%|
[xroxy](#xroxy)|2108|2108|2|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|2|0.0%|0.0%|
[sorbs_spam](#sorbs_spam)|32328|32328,33461|2|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|32328|32328,33461|2|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|32328|32328,33461|2|0.0%|0.0%|
[shunlist](#shunlist)|1215|1215|1|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2475|2475|1|0.0%|0.0%|
[nixspam](#nixspam)|19587|19587|1|0.0%|0.0%|
[dshield](#dshield)|20|20,5120|1|0.0%|0.0%|

## feodo

[Abuse.ch Feodo tracker](https://feodotracker.abuse.ch) trojan includes IPs which are being used by Feodo (also known as Cridex or Bugat) which commits ebanking fraud - **excellent list**

Source is downloaded from [this link](https://feodotracker.abuse.ch/blocklist/?download=ipblocklist).

The last time downloaded was found to be dated: Sat Jun  6 21:54:22 UTC 2015.

The ipset `feodo` has **99** entries, **99** unique IPs.

The following table shows the overlaps of `feodo` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `feodo`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `feodo`.
- ` this % ` is the percentage **of this ipset (`feodo`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[et_block](#et_block)|1023|18338662|94|0.0%|94.9%|
[snort_ipfilter](#snort_ipfilter)|9943|9943|79|0.7%|79.7%|
[sslbl](#sslbl)|367|367|36|9.8%|36.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|11|0.0%|11.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|3|0.0%|3.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|3|0.0%|3.0%|
[alienvault_reputation](#alienvault_reputation)|177556|177556|2|0.0%|2.0%|
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
[php_harvesters](#php_harvesters)|324|324|1|0.3%|0.0%|
[php_commenters](#php_commenters)|349|349|1|0.2%|0.0%|
[ciarmy](#ciarmy)|423|423|1|0.2%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1801|1801|1|0.0%|0.0%|

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
[sorbs_spam](#sorbs_spam)|32328|32328,33461|16|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|32328|32328,33461|16|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|32328|32328,33461|16|0.0%|0.0%|
[alienvault_reputation](#alienvault_reputation)|177556|177556|16|0.0%|0.0%|
[fullbogons](#fullbogons)|3721|670267288|15|0.0%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|14|0.0%|0.0%|
[nixspam](#nixspam)|19587|19587|13|0.0%|0.0%|
[blocklist_de](#blocklist_de)|26854|26854|13|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|11|1.6%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|15414|15414|7|0.0%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|6|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|6|0.0%|0.0%|
[et_block](#et_block)|1023|18338662|6|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4063|4063|6|0.1%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|4|0.0%|0.0%|
[dshield](#dshield)|20|20,5120|4|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|16943|16943|4|0.0%|0.0%|
[xroxy](#xroxy)|2108|2108|3|0.1%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6481|6481|3|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|6677|6677|3|0.0%|0.0%|
[php_dictionary](#php_dictionary)|545|545|3|0.5%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|1984|1984|3|0.1%|0.0%|
[voipbl](#voipbl)|10476|10476,10888|2|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9943|9943|2|0.0%|0.0%|
[php_harvesters](#php_harvesters)|324|324|2|0.6%|0.0%|
[sorbs_web](#sorbs_web)|709|709,710|1|0.1%|0.0%|
[proxz](#proxz)|915|915|1|0.1%|0.0%|
[proxyrss](#proxyrss)|1748|1748|1|0.0%|0.0%|
[php_spammers](#php_spammers)|536|536|1|0.1%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1689|1689|1|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3010|3010|1|0.0%|0.0%|

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
[alienvault_reputation](#alienvault_reputation)|177556|177556|516|0.2%|0.0%|
[dshield](#dshield)|20|20,5120|256|5.0%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|153|0.5%|0.0%|
[blocklist_de](#blocklist_de)|26854|26854|48|0.1%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3010|3010|35|1.1%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|27|2.0%|0.0%|
[nixspam](#nixspam)|19587|19587|20|0.1%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6481|6481|18|0.2%|0.0%|
[openbl_60d](#openbl_60d)|7286|7286|17|0.2%|0.0%|
[openbl_30d](#openbl_30d)|3257|3257|13|0.3%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9943|9943|12|0.1%|0.0%|
[zeus_badips](#zeus_badips)|202|202|10|4.9%|0.0%|
[zeus](#zeus)|232|232|10|4.3%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|7|0.4%|0.0%|
[sorbs_spam](#sorbs_spam)|32328|32328,33461|6|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|32328|32328,33461|6|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|32328|32328,33461|6|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|16943|16943|6|0.0%|0.0%|
[openbl_7d](#openbl_7d)|836|836|5|0.5%|0.0%|
[et_compromised](#et_compromised)|2016|2016|5|0.2%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1801|1801|5|0.2%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1689|1689|5|0.2%|0.0%|
[dm_tor](#dm_tor)|6497|6497|4|0.0%|0.0%|
[bm_tor](#bm_tor)|6501|6501|4|0.0%|0.0%|
[et_tor](#et_tor)|6470|6470|3|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|179|179|3|1.6%|0.0%|
[shunlist](#shunlist)|1215|1215|2|0.1%|0.0%|
[php_spammers](#php_spammers)|536|536|2|0.3%|0.0%|
[php_dictionary](#php_dictionary)|545|545|2|0.3%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|2|0.2%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|1984|1984|2|0.1%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4063|4063|2|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|15414|15414|2|0.0%|0.0%|
[voipbl](#voipbl)|10476|10476,10888|1|0.0%|0.0%|
[php_harvesters](#php_harvesters)|324|324|1|0.3%|0.0%|
[php_commenters](#php_commenters)|349|349|1|0.2%|0.0%|
[openbl_1d](#openbl_1d)|150|150|1|0.6%|0.0%|
[et_botcc](#et_botcc)|509|509|1|0.1%|0.0%|

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
[alienvault_reputation](#alienvault_reputation)|177556|177556|3303|1.8%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|1543|1.6%|0.0%|
[blocklist_de](#blocklist_de)|26854|26854|1491|5.5%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|16943|16943|1373|8.1%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|15414|15414|1324|8.5%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|568|1.8%|0.0%|
[sorbs_spam](#sorbs_spam)|32328|32328,33461|525|1.5%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|32328|32328,33461|525|1.5%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|32328|32328,33461|525|1.5%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|406|0.8%|0.0%|
[voipbl](#voipbl)|10476|10476,10888|297|2.7%|0.0%|
[nixspam](#nixspam)|19587|19587|254|1.2%|0.0%|
[et_tor](#et_tor)|6470|6470|168|2.5%|0.0%|
[openbl_60d](#openbl_60d)|7286|7286|167|2.2%|0.0%|
[bm_tor](#bm_tor)|6501|6501|162|2.4%|0.0%|
[dm_tor](#dm_tor)|6497|6497|161|2.4%|0.0%|
[ri_web_proxies](#ri_web_proxies)|6677|6677|134|2.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6481|6481|130|2.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|97|6.6%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9943|9943|78|0.7%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2475|2475|78|3.1%|0.0%|
[openbl_30d](#openbl_30d)|3257|3257|71|2.1%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|66|5.1%|0.0%|
[xroxy](#xroxy)|2108|2108|58|2.7%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|58|8.6%|0.0%|
[et_compromised](#et_compromised)|2016|2016|52|2.5%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1801|1801|46|2.5%|0.0%|
[proxyrss](#proxyrss)|1748|1748|41|2.3%|0.0%|
[et_botcc](#et_botcc)|509|509|41|8.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4063|4063|34|0.8%|0.0%|
[proxz](#proxz)|915|915|31|3.3%|0.0%|
[ciarmy](#ciarmy)|423|423|31|7.3%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1689|1689|29|1.7%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3010|3010|29|0.9%|0.0%|
[shunlist](#shunlist)|1215|1215|28|2.3%|0.0%|
[sorbs_web](#sorbs_web)|709|709,710|22|3.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|1984|1984|21|1.0%|0.0%|
[openbl_7d](#openbl_7d)|836|836|19|2.2%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|17|4.5%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|828|828|14|1.6%|0.0%|
[php_harvesters](#php_harvesters)|324|324|11|3.3%|0.0%|
[php_dictionary](#php_dictionary)|545|545|11|2.0%|0.0%|
[malc0de](#malc0de)|361|361|11|3.0%|0.0%|
[dshield](#dshield)|20|20,5120|11|0.2%|0.0%|
[php_commenters](#php_commenters)|349|349|8|2.2%|0.0%|
[php_spammers](#php_spammers)|536|536|7|1.3%|0.0%|
[zeus](#zeus)|232|232|6|2.5%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|230|230|5|2.1%|0.0%|
[bogons](#bogons)|13|592708608|5|0.0%|0.0%|
[zeus_badips](#zeus_badips)|202|202|4|1.9%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|94|94|4|4.2%|0.0%|
[sslbl](#sslbl)|367|367|3|0.8%|0.0%|
[openbl_1d](#openbl_1d)|150|150|3|2.0%|0.0%|
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
[alienvault_reputation](#alienvault_reputation)|177556|177556|7271|4.0%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|2524|2.7%|0.0%|
[blocklist_de](#blocklist_de)|26854|26854|1433|5.3%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|16943|16943|1143|6.7%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|15414|15414|1086|7.0%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|909|3.0%|0.0%|
[sorbs_spam](#sorbs_spam)|32328|32328,33461|816|2.4%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|32328|32328,33461|816|2.4%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|32328|32328,33461|816|2.4%|0.0%|
[nixspam](#nixspam)|19587|19587|461|2.3%|0.0%|
[voipbl](#voipbl)|10476|10476,10888|434|3.9%|0.0%|
[openbl_60d](#openbl_60d)|7286|7286|327|4.4%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|230|0.4%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6481|6481|195|3.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|6677|6677|195|2.9%|0.0%|
[dm_tor](#dm_tor)|6497|6497|191|2.9%|0.0%|
[bm_tor](#bm_tor)|6501|6501|191|2.9%|0.0%|
[et_tor](#et_tor)|6470|6470|190|2.9%|0.0%|
[openbl_30d](#openbl_30d)|3257|3257|169|5.1%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3010|3010|123|4.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9943|9943|103|1.0%|0.0%|
[xroxy](#xroxy)|2108|2108|101|4.7%|0.0%|
[et_compromised](#et_compromised)|2016|2016|97|4.8%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2475|2475|96|3.8%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1689|1689|88|5.2%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1801|1801|86|4.7%|0.0%|
[shunlist](#shunlist)|1215|1215|68|5.5%|0.0%|
[proxyrss](#proxyrss)|1748|1748|57|3.2%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4063|4063|56|1.3%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|1984|1984|51|2.5%|0.0%|
[php_spammers](#php_spammers)|536|536|45|8.3%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|45|3.0%|0.0%|
[ciarmy](#ciarmy)|423|423|44|10.4%|0.0%|
[openbl_7d](#openbl_7d)|836|836|43|5.1%|0.0%|
[proxz](#proxz)|915|915|37|4.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|28|4.1%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|26|2.0%|0.0%|
[sorbs_web](#sorbs_web)|709|709,710|25|3.5%|0.0%|
[et_botcc](#et_botcc)|509|509|22|4.3%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|21|5.6%|0.0%|
[malc0de](#malc0de)|361|361|21|5.8%|0.0%|
[php_dictionary](#php_dictionary)|545|545|17|3.1%|0.0%|
[php_commenters](#php_commenters)|349|349|14|4.0%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|230|230|14|6.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|828|828|13|1.5%|0.0%|
[zeus](#zeus)|232|232|9|3.8%|0.0%|
[php_harvesters](#php_harvesters)|324|324|9|2.7%|0.0%|
[zeus_badips](#zeus_badips)|202|202|8|3.9%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|179|179|8|4.4%|0.0%|
[openbl_1d](#openbl_1d)|150|150|7|4.6%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|94|94|7|7.4%|0.0%|
[sslbl](#sslbl)|367|367|5|1.3%|0.0%|
[palevo](#palevo)|13|13|3|23.0%|0.0%|
[feodo](#feodo)|99|99|3|3.0%|0.0%|
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
[alienvault_reputation](#alienvault_reputation)|177556|177556|13873|7.8%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|9231|2.7%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|5841|6.2%|0.0%|
[blocklist_de](#blocklist_de)|26854|26854|3449|12.8%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|16943|16943|2638|15.5%|0.0%|
[sorbs_spam](#sorbs_spam)|32328|32328,33461|2459|7.3%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|32328|32328,33461|2459|7.3%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|32328|32328,33461|2459|7.3%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|15414|15414|2406|15.6%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|1912|6.3%|0.0%|
[voipbl](#voipbl)|10476|10476,10888|1599|14.6%|0.0%|
[nixspam](#nixspam)|19587|19587|1268|6.4%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1172|2.4%|0.0%|
[openbl_60d](#openbl_60d)|7286|7286|746|10.2%|0.0%|
[et_tor](#et_tor)|6470|6470|633|9.7%|0.0%|
[dm_tor](#dm_tor)|6497|6497|622|9.5%|0.0%|
[bm_tor](#bm_tor)|6501|6501|622|9.5%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6481|6481|491|7.5%|0.0%|
[openbl_30d](#openbl_30d)|3257|3257|313|9.6%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4063|4063|305|7.5%|0.0%|
[dshield](#dshield)|20|20,5120|256|5.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9943|9943|232|2.3%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3010|3010|201|6.6%|0.0%|
[et_compromised](#et_compromised)|2016|2016|199|9.8%|0.0%|
[ri_web_proxies](#ri_web_proxies)|6677|6677|192|2.8%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1689|1689|190|11.2%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1801|1801|172|9.5%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|1984|1984|171|8.6%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|147|11.4%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|125|33.6%|0.0%|
[openbl_7d](#openbl_7d)|836|836|114|13.6%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|110|7.5%|0.0%|
[shunlist](#shunlist)|1215|1215|108|8.8%|0.0%|
[xroxy](#xroxy)|2108|2108|97|4.6%|0.0%|
[ciarmy](#ciarmy)|423|423|81|19.1%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|828|828|80|9.6%|0.0%|
[et_botcc](#et_botcc)|509|509|78|15.3%|0.0%|
[proxz](#proxz)|915|915|75|8.1%|0.0%|
[malc0de](#malc0de)|361|361|54|14.9%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2475|2475|53|2.1%|0.0%|
[sorbs_web](#sorbs_web)|709|709,710|52|7.3%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|51|7.5%|0.0%|
[proxyrss](#proxyrss)|1748|1748|48|2.7%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|230|230|34|14.7%|0.0%|
[php_spammers](#php_spammers)|536|536|31|5.7%|0.0%|
[php_dictionary](#php_dictionary)|545|545|31|5.6%|0.0%|
[sslbl](#sslbl)|367|367|26|7.0%|0.0%|
[php_commenters](#php_commenters)|349|349|22|6.3%|0.0%|
[php_harvesters](#php_harvesters)|324|324|17|5.2%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|179|179|16|8.9%|0.0%|
[zeus](#zeus)|232|232|14|6.0%|0.0%|
[openbl_1d](#openbl_1d)|150|150|13|8.6%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|94|94|13|13.8%|0.0%|
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
[xroxy](#xroxy)|2108|2108|13|0.6%|1.9%|
[ri_web_proxies](#ri_web_proxies)|6677|6677|13|0.1%|1.9%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|12|0.0%|1.7%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|11|0.0%|1.6%|
[ri_connect_proxies](#ri_connect_proxies)|2475|2475|7|0.2%|1.0%|
[proxz](#proxz)|915|915|6|0.6%|0.8%|
[proxyrss](#proxyrss)|1748|1748|6|0.3%|0.8%|
[stopforumspam_1d](#stopforumspam_1d)|6481|6481|4|0.0%|0.5%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|2|0.0%|0.2%|
[sorbs_spam](#sorbs_spam)|32328|32328,33461|2|0.0%|0.2%|
[sorbs_recent_spam](#sorbs_recent_spam)|32328|32328,33461|2|0.0%|0.2%|
[sorbs_new_spam](#sorbs_new_spam)|32328|32328,33461|2|0.0%|0.2%|
[nixspam](#nixspam)|19587|19587|2|0.0%|0.2%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2|0.0%|0.2%|
[et_block](#et_block)|1023|18338662|2|0.0%|0.2%|
[blocklist_de_bots](#blocklist_de_bots)|3010|3010|2|0.0%|0.2%|
[blocklist_de](#blocklist_de)|26854|26854|2|0.0%|0.2%|
[php_dictionary](#php_dictionary)|545|545|1|0.1%|0.1%|
[alienvault_reputation](#alienvault_reputation)|177556|177556|1|0.0%|0.1%|

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
[alienvault_reputation](#alienvault_reputation)|177556|177556|285|0.1%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|46|0.0%|0.0%|
[sorbs_spam](#sorbs_spam)|32328|32328,33461|41|0.1%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|32328|32328,33461|41|0.1%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|32328|32328,33461|41|0.1%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|27|2.0%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|25|0.0%|0.0%|
[et_tor](#et_tor)|6470|6470|22|0.3%|0.0%|
[dm_tor](#dm_tor)|6497|6497|22|0.3%|0.0%|
[bm_tor](#bm_tor)|6501|6501|22|0.3%|0.0%|
[nixspam](#nixspam)|19587|19587|20|0.1%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|19|1.3%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9943|9943|14|0.1%|0.0%|
[blocklist_de](#blocklist_de)|26854|26854|10|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6481|6481|7|0.1%|0.0%|
[ri_web_proxies](#ri_web_proxies)|6677|6677|5|0.0%|0.0%|
[openbl_60d](#openbl_60d)|7286|7286|5|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|5|1.3%|0.0%|
[voipbl](#voipbl)|10476|10476,10888|4|0.0%|0.0%|
[openbl_30d](#openbl_30d)|3257|3257|4|0.1%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|4|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3010|3010|4|0.1%|0.0%|
[malc0de](#malc0de)|361|361|3|0.8%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1801|1801|3|0.1%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|15414|15414|3|0.0%|0.0%|
[palevo](#palevo)|13|13|2|15.3%|0.0%|
[et_compromised](#et_compromised)|2016|2016|2|0.0%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|230|230|2|0.8%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1689|1689|2|0.1%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|94|94|2|2.1%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|16943|16943|2|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4063|4063|2|0.0%|0.0%|
[zeus_badips](#zeus_badips)|202|202|1|0.4%|0.0%|
[zeus](#zeus)|232|232|1|0.4%|0.0%|
[xroxy](#xroxy)|2108|2108|1|0.0%|0.0%|
[sslbl](#sslbl)|367|367|1|0.2%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|1|0.0%|0.0%|
[shunlist](#shunlist)|1215|1215|1|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2475|2475|1|0.0%|0.0%|
[php_harvesters](#php_harvesters)|324|324|1|0.3%|0.0%|
[php_dictionary](#php_dictionary)|545|545|1|0.1%|0.0%|
[openbl_7d](#openbl_7d)|836|836|1|0.1%|0.0%|
[feodo](#feodo)|99|99|1|1.0%|0.0%|
[ciarmy](#ciarmy)|423|423|1|0.2%|0.0%|
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
[alienvault_reputation](#alienvault_reputation)|177556|177556|8|0.0%|0.5%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|7|0.0%|0.4%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|6|0.0%|0.4%|
[et_block](#et_block)|1023|18338662|6|0.0%|0.4%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|3|0.2%|0.2%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|2|0.0%|0.1%|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|2|0.0%|0.1%|
[stopforumspam_1d](#stopforumspam_1d)|6481|6481|2|0.0%|0.1%|
[openbl_60d](#openbl_60d)|7286|7286|2|0.0%|0.1%|
[openbl_30d](#openbl_30d)|3257|3257|2|0.0%|0.1%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|2|0.2%|0.1%|
[blocklist_de](#blocklist_de)|26854|26854|2|0.0%|0.1%|
[snort_ipfilter](#snort_ipfilter)|9943|9943|1|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|6677|6677|1|0.0%|0.0%|
[openbl_7d](#openbl_7d)|836|836|1|0.1%|0.0%|
[nixspam](#nixspam)|19587|19587|1|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1|0.0%|0.0%|
[et_botcc](#et_botcc)|509|509|1|0.1%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|179|179|1|0.5%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1689|1689|1|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3010|3010|1|0.0%|0.0%|

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
[cleanmx_viruses](#cleanmx_viruses)|230|230|29|12.6%|8.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|21|0.0%|5.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|11|0.0%|3.0%|
[alienvault_reputation](#alienvault_reputation)|177556|177556|11|0.0%|3.0%|
[et_block](#et_block)|1023|18338662|5|0.0%|1.3%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|4|0.0%|1.1%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|4|0.3%|1.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|3|0.0%|0.8%|
[dshield](#dshield)|20|20,5120|2|0.0%|0.5%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|1|0.0%|0.2%|

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
[alienvault_reputation](#alienvault_reputation)|177556|177556|6|0.0%|0.4%|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|4|0.0%|0.3%|
[malc0de](#malc0de)|361|361|4|1.1%|0.3%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|3|0.2%|0.2%|
[sorbs_spam](#sorbs_spam)|32328|32328,33461|2|0.0%|0.1%|
[sorbs_recent_spam](#sorbs_recent_spam)|32328|32328,33461|2|0.0%|0.1%|
[sorbs_new_spam](#sorbs_new_spam)|32328|32328,33461|2|0.0%|0.1%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|1|0.0%|0.0%|
[nixspam](#nixspam)|19587|19587|1|0.0%|0.0%|
[et_botcc](#et_botcc)|509|509|1|0.1%|0.0%|
[dshield](#dshield)|20|20,5120|1|0.0%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|230|230|1|0.4%|0.0%|

## maxmind_proxy_fraud

[MaxMind.com](https://www.maxmind.com/en/anonymous-proxy-fraudulent-ip-address-list) list of anonymous proxy fraudelent IP addresses.

Source is downloaded from [this link](https://www.maxmind.com/en/anonymous-proxy-fraudulent-ip-address-list).

The last time downloaded was found to be dated: Sat Jun  6 19:00:26 UTC 2015.

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
[dm_tor](#dm_tor)|6497|6497|167|2.5%|44.8%|
[bm_tor](#bm_tor)|6501|6501|166|2.5%|44.6%|
[stopforumspam_1d](#stopforumspam_1d)|6481|6481|159|2.4%|42.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|125|0.0%|33.6%|
[php_commenters](#php_commenters)|349|349|34|9.7%|9.1%|
[alienvault_reputation](#alienvault_reputation)|177556|177556|26|0.0%|6.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|21|0.0%|5.6%|
[openbl_60d](#openbl_60d)|7286|7286|18|0.2%|4.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|17|0.0%|4.5%|
[php_harvesters](#php_harvesters)|324|324|6|1.8%|1.6%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|5|0.0%|1.3%|
[ri_web_proxies](#ri_web_proxies)|6677|6677|4|0.0%|1.0%|
[php_spammers](#php_spammers)|536|536|4|0.7%|1.0%|
[php_dictionary](#php_dictionary)|545|545|4|0.7%|1.0%|
[blocklist_de](#blocklist_de)|26854|26854|3|0.0%|0.8%|
[blocklist_de_apache](#blocklist_de_apache)|15414|15414|2|0.0%|0.5%|
[xroxy](#xroxy)|2108|2108|1|0.0%|0.2%|
[voipbl](#voipbl)|10476|10476,10888|1|0.0%|0.2%|
[shunlist](#shunlist)|1215|1215|1|0.0%|0.2%|
[ri_connect_proxies](#ri_connect_proxies)|2475|2475|1|0.0%|0.2%|
[et_block](#et_block)|1023|18338662|1|0.0%|0.2%|
[blocklist_de_ssh](#blocklist_de_ssh)|1689|1689|1|0.0%|0.2%|
[blocklist_de_mail](#blocklist_de_mail)|16943|16943|1|0.0%|0.2%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4063|4063|1|0.0%|0.2%|

## nixspam

[NiX Spam](http://www.heise.de/ix/NiX-Spam-DNSBL-and-blacklist-for-download-499637.html) IP addresses that sent spam in the last hour - automatically generated entries without distinguishing open proxies from relays, dialup gateways, and so on. All IPs are removed after 12 hours if there is no spam from there.

Source is downloaded from [this link](http://www.dnsbl.manitu.net/download/nixspam-ip.dump.gz).

The last time downloaded was found to be dated: Sat Jun  6 22:15:02 UTC 2015.

The ipset `nixspam` has **19587** entries, **19587** unique IPs.

The following table shows the overlaps of `nixspam` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `nixspam`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `nixspam`.
- ` this % ` is the percentage **of this ipset (`nixspam`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[sorbs_spam](#sorbs_spam)|32328|32328,33461|3447|10.3%|17.5%|
[sorbs_recent_spam](#sorbs_recent_spam)|32328|32328,33461|3447|10.3%|17.5%|
[sorbs_new_spam](#sorbs_new_spam)|32328|32328,33461|3447|10.3%|17.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|1268|0.0%|6.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|461|0.0%|2.3%|
[blocklist_de](#blocklist_de)|26854|26854|434|1.6%|2.2%|
[blocklist_de_mail](#blocklist_de_mail)|16943|16943|371|2.1%|1.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|254|0.0%|1.2%|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|143|0.1%|0.7%|
[sorbs_web](#sorbs_web)|709|709,710|94|13.2%|0.4%|
[snort_ipfilter](#snort_ipfilter)|9943|9943|92|0.9%|0.4%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|73|0.2%|0.3%|
[php_dictionary](#php_dictionary)|545|545|59|10.8%|0.3%|
[ri_web_proxies](#ri_web_proxies)|6677|6677|52|0.7%|0.2%|
[php_spammers](#php_spammers)|536|536|50|9.3%|0.2%|
[blocklist_de_apache](#blocklist_de_apache)|15414|15414|31|0.2%|0.1%|
[stopforumspam_1d](#stopforumspam_1d)|6481|6481|30|0.4%|0.1%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4063|4063|30|0.7%|0.1%|
[alienvault_reputation](#alienvault_reputation)|177556|177556|29|0.0%|0.1%|
[xroxy](#xroxy)|2108|2108|27|1.2%|0.1%|
[blocklist_de_imap](#blocklist_de_imap)|1984|1984|27|1.3%|0.1%|
[et_block](#et_block)|1023|18338662|25|0.0%|0.1%|
[blocklist_de_bots](#blocklist_de_bots)|3010|3010|25|0.8%|0.1%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|21|0.0%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|20|0.0%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|20|0.0%|0.1%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|13|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2475|2475|10|0.4%|0.0%|
[proxyrss](#proxyrss)|1748|1748|9|0.5%|0.0%|
[proxz](#proxz)|915|915|8|0.8%|0.0%|
[php_commenters](#php_commenters)|349|349|7|2.0%|0.0%|
[sorbs_socks](#sorbs_socks)|22|22,22|4|18.1%|0.0%|
[sorbs_misc](#sorbs_misc)|22|22,22|4|18.1%|0.0%|
[sorbs_http](#sorbs_http)|22|22,22|4|18.1%|0.0%|
[php_harvesters](#php_harvesters)|324|324|4|1.2%|0.0%|
[openbl_60d](#openbl_60d)|7286|7286|4|0.0%|0.0%|
[openbl_30d](#openbl_30d)|3257|3257|4|0.1%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|828|828|4|0.4%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1689|1689|3|0.1%|0.0%|
[openbl_7d](#openbl_7d)|836|836|2|0.2%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|2|0.2%|0.0%|
[zeus](#zeus)|232|232|1|0.4%|0.0%|
[sorbs_smtp](#sorbs_smtp)|14|14,14|1|7.1%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|1|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|
[et_tor](#et_tor)|6470|6470|1|0.0%|0.0%|
[et_compromised](#et_compromised)|2016|2016|1|0.0%|0.0%|
[dm_tor](#dm_tor)|6497|6497|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1801|1801|1|0.0%|0.0%|
[bm_tor](#bm_tor)|6501|6501|1|0.0%|0.0%|

## openbl_1d

[OpenBL.org](http://www.openbl.org/) last 24 hours IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.

Source is downloaded from [this link](http://www.openbl.org/lists/base_1days.txt).

The last time downloaded was found to be dated: Sat Jun  6 21:32:00 UTC 2015.

The ipset `openbl_1d` has **150** entries, **150** unique IPs.

The following table shows the overlaps of `openbl_1d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl_1d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl_1d`.
- ` this % ` is the percentage **of this ipset (`openbl_1d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[alienvault_reputation](#alienvault_reputation)|177556|177556|147|0.0%|98.0%|
[openbl_60d](#openbl_60d)|7286|7286|146|2.0%|97.3%|
[openbl_30d](#openbl_30d)|3257|3257|145|4.4%|96.6%|
[openbl_7d](#openbl_7d)|836|836|144|17.2%|96.0%|
[blocklist_de](#blocklist_de)|26854|26854|122|0.4%|81.3%|
[blocklist_de_ssh](#blocklist_de_ssh)|1689|1689|118|6.9%|78.6%|
[bruteforceblocker](#bruteforceblocker)|1801|1801|73|4.0%|48.6%|
[et_compromised](#et_compromised)|2016|2016|72|3.5%|48.0%|
[shunlist](#shunlist)|1215|1215|71|5.8%|47.3%|
[blocklist_de_strongips](#blocklist_de_strongips)|179|179|20|11.1%|13.3%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|14|0.0%|9.3%|
[et_block](#et_block)|1023|18338662|14|0.0%|9.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|13|0.0%|8.6%|
[dshield](#dshield)|20|20,5120|12|0.2%|8.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|7|0.0%|4.6%|
[blocklist_de_mail](#blocklist_de_mail)|16943|16943|4|0.0%|2.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|3|0.0%|2.0%|
[blocklist_de_imap](#blocklist_de_imap)|1984|1984|2|0.1%|1.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.6%|

## openbl_30d

[OpenBL.org](http://www.openbl.org/) last 30 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.

Source is downloaded from [this link](http://www.openbl.org/lists/base_30days.txt).

The last time downloaded was found to be dated: Sat Jun  6 19:42:00 UTC 2015.

The ipset `openbl_30d` has **3257** entries, **3257** unique IPs.

The following table shows the overlaps of `openbl_30d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl_30d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl_30d`.
- ` this % ` is the percentage **of this ipset (`openbl_30d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[openbl_60d](#openbl_60d)|7286|7286|3257|44.7%|100.0%|
[alienvault_reputation](#alienvault_reputation)|177556|177556|3242|1.8%|99.5%|
[et_compromised](#et_compromised)|2016|2016|1151|57.0%|35.3%|
[bruteforceblocker](#bruteforceblocker)|1801|1801|1027|57.0%|31.5%|
[openbl_7d](#openbl_7d)|836|836|836|100.0%|25.6%|
[blocklist_de](#blocklist_de)|26854|26854|696|2.5%|21.3%|
[blocklist_de_ssh](#blocklist_de_ssh)|1689|1689|649|38.4%|19.9%|
[shunlist](#shunlist)|1215|1215|527|43.3%|16.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|313|0.0%|9.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|169|0.0%|5.1%|
[et_block](#et_block)|1023|18338662|166|0.0%|5.0%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|160|0.0%|4.9%|
[dshield](#dshield)|20|20,5120|160|3.1%|4.9%|
[openbl_1d](#openbl_1d)|150|150|145|96.6%|4.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|71|0.0%|2.1%|
[blocklist_de_mail](#blocklist_de_mail)|16943|16943|37|0.2%|1.1%|
[blocklist_de_imap](#blocklist_de_imap)|1984|1984|31|1.5%|0.9%|
[blocklist_de_strongips](#blocklist_de_strongips)|179|179|24|13.4%|0.7%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|13|0.0%|0.3%|
[blocklist_de_apache](#blocklist_de_apache)|15414|15414|6|0.0%|0.1%|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|5|0.0%|0.1%|
[snort_ipfilter](#snort_ipfilter)|9943|9943|4|0.0%|0.1%|
[nixspam](#nixspam)|19587|19587|4|0.0%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|4|0.0%|0.1%|
[voipbl](#voipbl)|10476|10476,10888|3|0.0%|0.0%|
[sorbs_spam](#sorbs_spam)|32328|32328,33461|3|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|32328|32328,33461|3|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|32328|32328,33461|3|0.0%|0.0%|
[zeus](#zeus)|232|232|2|0.8%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|2|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3010|3010|2|0.0%|0.0%|
[zeus_badips](#zeus_badips)|202|202|1|0.4%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6481|6481|1|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|1|0.0%|0.0%|
[sorbs_web](#sorbs_web)|709|709,710|1|0.1%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|828|828|1|0.1%|0.0%|

## openbl_60d

[OpenBL.org](http://www.openbl.org/) last 60 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.

Source is downloaded from [this link](http://www.openbl.org/lists/base_60days.txt).

The last time downloaded was found to be dated: Sat Jun  6 19:42:00 UTC 2015.

The ipset `openbl_60d` has **7286** entries, **7286** unique IPs.

The following table shows the overlaps of `openbl_60d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl_60d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl_60d`.
- ` this % ` is the percentage **of this ipset (`openbl_60d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[alienvault_reputation](#alienvault_reputation)|177556|177556|7266|4.0%|99.7%|
[openbl_30d](#openbl_30d)|3257|3257|3257|100.0%|44.7%|
[et_compromised](#et_compromised)|2016|2016|1217|60.3%|16.7%|
[bruteforceblocker](#bruteforceblocker)|1801|1801|1067|59.2%|14.6%|
[openbl_7d](#openbl_7d)|836|836|836|100.0%|11.4%|
[blocklist_de](#blocklist_de)|26854|26854|766|2.8%|10.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|746|0.0%|10.2%|
[blocklist_de_ssh](#blocklist_de_ssh)|1689|1689|701|41.5%|9.6%|
[shunlist](#shunlist)|1215|1215|542|44.6%|7.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|327|0.0%|4.4%|
[et_block](#et_block)|1023|18338662|250|0.0%|3.4%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|239|0.0%|3.2%|
[dshield](#dshield)|20|20,5120|172|3.3%|2.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|167|0.0%|2.2%|
[openbl_1d](#openbl_1d)|150|150|146|97.3%|2.0%|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|54|0.0%|0.7%|
[blocklist_de_mail](#blocklist_de_mail)|16943|16943|43|0.2%|0.5%|
[blocklist_de_imap](#blocklist_de_imap)|1984|1984|37|1.8%|0.5%|
[snort_ipfilter](#snort_ipfilter)|9943|9943|27|0.2%|0.3%|
[blocklist_de_strongips](#blocklist_de_strongips)|179|179|26|14.5%|0.3%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|25|0.0%|0.3%|
[stopforumspam_1d](#stopforumspam_1d)|6481|6481|20|0.3%|0.2%|
[et_tor](#et_tor)|6470|6470|20|0.3%|0.2%|
[dm_tor](#dm_tor)|6497|6497|20|0.3%|0.2%|
[bm_tor](#bm_tor)|6501|6501|20|0.3%|0.2%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|18|4.8%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|17|0.0%|0.2%|
[sorbs_spam](#sorbs_spam)|32328|32328,33461|14|0.0%|0.1%|
[sorbs_recent_spam](#sorbs_recent_spam)|32328|32328,33461|14|0.0%|0.1%|
[sorbs_new_spam](#sorbs_new_spam)|32328|32328,33461|14|0.0%|0.1%|
[blocklist_de_bots](#blocklist_de_bots)|3010|3010|11|0.3%|0.1%|
[php_commenters](#php_commenters)|349|349|9|2.5%|0.1%|
[blocklist_de_apache](#blocklist_de_apache)|15414|15414|9|0.0%|0.1%|
[voipbl](#voipbl)|10476|10476,10888|8|0.0%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|5|0.0%|0.0%|
[nixspam](#nixspam)|19587|19587|4|0.0%|0.0%|
[zeus](#zeus)|232|232|2|0.8%|0.0%|
[php_harvesters](#php_harvesters)|324|324|2|0.6%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|828|828|2|0.2%|0.0%|
[zeus_badips](#zeus_badips)|202|202|1|0.4%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|1|0.0%|0.0%|
[sorbs_web](#sorbs_web)|709|709,710|1|0.1%|0.0%|

## openbl_7d

[OpenBL.org](http://www.openbl.org/) last 7 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.

Source is downloaded from [this link](http://www.openbl.org/lists/base_7days.txt).

The last time downloaded was found to be dated: Sat Jun  6 19:42:00 UTC 2015.

The ipset `openbl_7d` has **836** entries, **836** unique IPs.

The following table shows the overlaps of `openbl_7d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl_7d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl_7d`.
- ` this % ` is the percentage **of this ipset (`openbl_7d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[openbl_60d](#openbl_60d)|7286|7286|836|11.4%|100.0%|
[openbl_30d](#openbl_30d)|3257|3257|836|25.6%|100.0%|
[alienvault_reputation](#alienvault_reputation)|177556|177556|831|0.4%|99.4%|
[blocklist_de](#blocklist_de)|26854|26854|413|1.5%|49.4%|
[blocklist_de_ssh](#blocklist_de_ssh)|1689|1689|396|23.4%|47.3%|
[et_compromised](#et_compromised)|2016|2016|363|18.0%|43.4%|
[bruteforceblocker](#bruteforceblocker)|1801|1801|351|19.4%|41.9%|
[shunlist](#shunlist)|1215|1215|232|19.0%|27.7%|
[openbl_1d](#openbl_1d)|150|150|144|96.0%|17.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|114|0.0%|13.6%|
[et_block](#et_block)|1023|18338662|50|0.0%|5.9%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|47|0.0%|5.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|43|0.0%|5.1%|
[dshield](#dshield)|20|20,5120|43|0.8%|5.1%|
[blocklist_de_strongips](#blocklist_de_strongips)|179|179|24|13.4%|2.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|19|0.0%|2.2%|
[blocklist_de_mail](#blocklist_de_mail)|16943|16943|13|0.0%|1.5%|
[blocklist_de_imap](#blocklist_de_imap)|1984|1984|10|0.5%|1.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|5|0.0%|0.5%|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|3|0.0%|0.3%|
[nixspam](#nixspam)|19587|19587|2|0.0%|0.2%|
[blocklist_de_apache](#blocklist_de_apache)|15414|15414|2|0.0%|0.2%|
[sorbs_spam](#sorbs_spam)|32328|32328,33461|1|0.0%|0.1%|
[sorbs_recent_spam](#sorbs_recent_spam)|32328|32328,33461|1|0.0%|0.1%|
[sorbs_new_spam](#sorbs_new_spam)|32328|32328,33461|1|0.0%|0.1%|
[snort_ipfilter](#snort_ipfilter)|9943|9943|1|0.0%|0.1%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.1%|

## palevo

[Abuse.ch Palevo tracker](https://palevotracker.abuse.ch) worm includes IPs which are being used as botnet C&C for the Palevo crimeware - **excellent list**

Source is downloaded from [this link](https://palevotracker.abuse.ch/blocklists.php?download=ipblocklist).

The last time downloaded was found to be dated: Sat Jun  6 21:54:19 UTC 2015.

The ipset `palevo` has **13** entries, **13** unique IPs.

The following table shows the overlaps of `palevo` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `palevo`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `palevo`.
- ` this % ` is the percentage **of this ipset (`palevo`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[et_block](#et_block)|1023|18338662|12|0.0%|92.3%|
[snort_ipfilter](#snort_ipfilter)|9943|9943|11|0.1%|84.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|3|0.0%|23.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|2|0.0%|15.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|1|0.0%|7.6%|

## php_commenters

[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) comment spammers (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=c&rss=1).

The last time downloaded was found to be dated: Sat Jun  6 21:36:29 UTC 2015.

The ipset `php_commenters` has **349** entries, **349** unique IPs.

The following table shows the overlaps of `php_commenters` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `php_commenters`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `php_commenters`.
- ` this % ` is the percentage **of this ipset (`php_commenters`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|253|0.2%|72.4%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|185|0.6%|53.0%|
[stopforumspam_1d](#stopforumspam_1d)|6481|6481|135|2.0%|38.6%|
[blocklist_de](#blocklist_de)|26854|26854|86|0.3%|24.6%|
[blocklist_de_bots](#blocklist_de_bots)|3010|3010|70|2.3%|20.0%|
[snort_ipfilter](#snort_ipfilter)|9943|9943|46|0.4%|13.1%|
[php_spammers](#php_spammers)|536|536|38|7.0%|10.8%|
[et_tor](#et_tor)|6470|6470|37|0.5%|10.6%|
[blocklist_de_strongips](#blocklist_de_strongips)|179|179|37|20.6%|10.6%|
[dm_tor](#dm_tor)|6497|6497|36|0.5%|10.3%|
[bm_tor](#bm_tor)|6501|6501|36|0.5%|10.3%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|34|9.1%|9.7%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|28|0.0%|8.0%|
[et_block](#et_block)|1023|18338662|28|0.0%|8.0%|
[blocklist_de_apache](#blocklist_de_apache)|15414|15414|26|0.1%|7.4%|
[php_dictionary](#php_dictionary)|545|545|25|4.5%|7.1%|
[ri_web_proxies](#ri_web_proxies)|6677|6677|23|0.3%|6.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|22|0.0%|6.3%|
[blocklist_de_mail](#blocklist_de_mail)|16943|16943|22|0.1%|6.3%|
[alienvault_reputation](#alienvault_reputation)|177556|177556|17|0.0%|4.8%|
[sorbs_spam](#sorbs_spam)|32328|32328,33461|15|0.0%|4.2%|
[sorbs_recent_spam](#sorbs_recent_spam)|32328|32328,33461|15|0.0%|4.2%|
[sorbs_new_spam](#sorbs_new_spam)|32328|32328,33461|15|0.0%|4.2%|
[php_harvesters](#php_harvesters)|324|324|14|4.3%|4.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|14|0.0%|4.0%|
[openbl_60d](#openbl_60d)|7286|7286|9|0.1%|2.5%|
[xroxy](#xroxy)|2108|2108|8|0.3%|2.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|8|0.0%|2.2%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4063|4063|8|0.1%|2.2%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|7|0.0%|2.0%|
[nixspam](#nixspam)|19587|19587|7|0.0%|2.0%|
[proxz](#proxz)|915|915|6|0.6%|1.7%|
[ri_connect_proxies](#ri_connect_proxies)|2475|2475|5|0.2%|1.4%|
[proxyrss](#proxyrss)|1748|1748|5|0.2%|1.4%|
[sorbs_web](#sorbs_web)|709|709,710|3|0.4%|0.8%|
[zeus_badips](#zeus_badips)|202|202|1|0.4%|0.2%|
[zeus](#zeus)|232|232|1|0.4%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.2%|
[fullbogons](#fullbogons)|3721|670267288|1|0.0%|0.2%|
[bogons](#bogons)|13|592708608|1|0.0%|0.2%|
[blocklist_de_imap](#blocklist_de_imap)|1984|1984|1|0.0%|0.2%|

## php_dictionary

[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) directory attackers (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=d&rss=1).

The last time downloaded was found to be dated: Sat Jun  6 21:54:27 UTC 2015.

The ipset `php_dictionary` has **545** entries, **545** unique IPs.

The following table shows the overlaps of `php_dictionary` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `php_dictionary`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `php_dictionary`.
- ` this % ` is the percentage **of this ipset (`php_dictionary`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[php_spammers](#php_spammers)|536|536|180|33.5%|33.0%|
[sorbs_spam](#sorbs_spam)|32328|32328,33461|151|0.4%|27.7%|
[sorbs_recent_spam](#sorbs_recent_spam)|32328|32328,33461|151|0.4%|27.7%|
[sorbs_new_spam](#sorbs_new_spam)|32328|32328,33461|151|0.4%|27.7%|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|103|0.1%|18.8%|
[blocklist_de](#blocklist_de)|26854|26854|89|0.3%|16.3%|
[snort_ipfilter](#snort_ipfilter)|9943|9943|79|0.7%|14.4%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|66|0.2%|12.1%|
[nixspam](#nixspam)|19587|19587|59|0.3%|10.8%|
[blocklist_de_mail](#blocklist_de_mail)|16943|16943|59|0.3%|10.8%|
[ri_web_proxies](#ri_web_proxies)|6677|6677|43|0.6%|7.8%|
[xroxy](#xroxy)|2108|2108|33|1.5%|6.0%|
[stopforumspam_1d](#stopforumspam_1d)|6481|6481|33|0.5%|6.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|31|0.0%|5.6%|
[sorbs_web](#sorbs_web)|709|709,710|30|4.2%|5.5%|
[php_commenters](#php_commenters)|349|349|25|7.1%|4.5%|
[blocklist_de_bots](#blocklist_de_bots)|3010|3010|24|0.7%|4.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|17|0.0%|3.1%|
[proxz](#proxz)|915|915|15|1.6%|2.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|11|0.0%|2.0%|
[alienvault_reputation](#alienvault_reputation)|177556|177556|8|0.0%|1.4%|
[et_tor](#et_tor)|6470|6470|5|0.0%|0.9%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|4|0.0%|0.7%|
[ri_connect_proxies](#ri_connect_proxies)|2475|2475|4|0.1%|0.7%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|4|1.0%|0.7%|
[et_block](#et_block)|1023|18338662|4|0.0%|0.7%|
[dm_tor](#dm_tor)|6497|6497|4|0.0%|0.7%|
[bm_tor](#bm_tor)|6501|6501|4|0.0%|0.7%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4063|4063|4|0.0%|0.7%|
[blocklist_de_apache](#blocklist_de_apache)|15414|15414|4|0.0%|0.7%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|3|0.0%|0.5%|
[blocklist_de_strongips](#blocklist_de_strongips)|179|179|3|1.6%|0.5%|
[sorbs_socks](#sorbs_socks)|22|22,22|2|9.0%|0.3%|
[sorbs_misc](#sorbs_misc)|22|22,22|2|9.0%|0.3%|
[sorbs_http](#sorbs_http)|22|22,22|2|9.0%|0.3%|
[proxyrss](#proxyrss)|1748|1748|2|0.1%|0.3%|
[php_harvesters](#php_harvesters)|324|324|2|0.6%|0.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2|0.0%|0.3%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.1%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|1|0.1%|0.1%|
[blocklist_de_imap](#blocklist_de_imap)|1984|1984|1|0.0%|0.1%|
[blocklist_de_ftp](#blocklist_de_ftp)|828|828|1|0.1%|0.1%|

## php_harvesters

[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) harvesters (IPs that surf the internet looking for email addresses) (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=h&rss=1).

The last time downloaded was found to be dated: Sat Jun  6 21:36:25 UTC 2015.

The ipset `php_harvesters` has **324** entries, **324** unique IPs.

The following table shows the overlaps of `php_harvesters` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `php_harvesters`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `php_harvesters`.
- ` this % ` is the percentage **of this ipset (`php_harvesters`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|72|0.0%|22.2%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|54|0.1%|16.6%|
[stopforumspam_1d](#stopforumspam_1d)|6481|6481|40|0.6%|12.3%|
[blocklist_de](#blocklist_de)|26854|26854|33|0.1%|10.1%|
[blocklist_de_bots](#blocklist_de_bots)|3010|3010|24|0.7%|7.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|17|0.0%|5.2%|
[php_commenters](#php_commenters)|349|349|14|4.0%|4.3%|
[snort_ipfilter](#snort_ipfilter)|9943|9943|11|0.1%|3.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|11|0.0%|3.3%|
[alienvault_reputation](#alienvault_reputation)|177556|177556|10|0.0%|3.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|9|0.0%|2.7%|
[sorbs_spam](#sorbs_spam)|32328|32328,33461|8|0.0%|2.4%|
[sorbs_recent_spam](#sorbs_recent_spam)|32328|32328,33461|8|0.0%|2.4%|
[sorbs_new_spam](#sorbs_new_spam)|32328|32328,33461|8|0.0%|2.4%|
[et_tor](#et_tor)|6470|6470|7|0.1%|2.1%|
[dm_tor](#dm_tor)|6497|6497|7|0.1%|2.1%|
[bm_tor](#bm_tor)|6501|6501|7|0.1%|2.1%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|6|1.6%|1.8%|
[blocklist_de_apache](#blocklist_de_apache)|15414|15414|5|0.0%|1.5%|
[nixspam](#nixspam)|19587|19587|4|0.0%|1.2%|
[proxyrss](#proxyrss)|1748|1748|3|0.1%|0.9%|
[blocklist_de_strongips](#blocklist_de_strongips)|179|179|3|1.6%|0.9%|
[blocklist_de_ftp](#blocklist_de_ftp)|828|828|3|0.3%|0.9%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4063|4063|3|0.0%|0.9%|
[xroxy](#xroxy)|2108|2108|2|0.0%|0.6%|
[ri_web_proxies](#ri_web_proxies)|6677|6677|2|0.0%|0.6%|
[php_spammers](#php_spammers)|536|536|2|0.3%|0.6%|
[php_dictionary](#php_dictionary)|545|545|2|0.3%|0.6%|
[openbl_60d](#openbl_60d)|7286|7286|2|0.0%|0.6%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|2|0.0%|0.6%|
[blocklist_de_mail](#blocklist_de_mail)|16943|16943|2|0.0%|0.6%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|1|0.0%|0.3%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|1|0.0%|0.3%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.3%|
[fullbogons](#fullbogons)|3721|670267288|1|0.0%|0.3%|
[et_block](#et_block)|1023|18338662|1|0.0%|0.3%|
[bogons](#bogons)|13|592708608|1|0.0%|0.3%|

## php_spammers

[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) spam servers (IPs used by spammers to send messages) (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=s&rss=1).

The last time downloaded was found to be dated: Sat Jun  6 21:36:28 UTC 2015.

The ipset `php_spammers` has **536** entries, **536** unique IPs.

The following table shows the overlaps of `php_spammers` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `php_spammers`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `php_spammers`.
- ` this % ` is the percentage **of this ipset (`php_spammers`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[php_dictionary](#php_dictionary)|545|545|180|33.0%|33.5%|
[sorbs_spam](#sorbs_spam)|32328|32328,33461|134|0.4%|25.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|32328|32328,33461|134|0.4%|25.0%|
[sorbs_new_spam](#sorbs_new_spam)|32328|32328,33461|134|0.4%|25.0%|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|117|0.1%|21.8%|
[blocklist_de](#blocklist_de)|26854|26854|92|0.3%|17.1%|
[snort_ipfilter](#snort_ipfilter)|9943|9943|76|0.7%|14.1%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|66|0.2%|12.3%|
[blocklist_de_mail](#blocklist_de_mail)|16943|16943|58|0.3%|10.8%|
[nixspam](#nixspam)|19587|19587|50|0.2%|9.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|45|0.0%|8.3%|
[ri_web_proxies](#ri_web_proxies)|6677|6677|38|0.5%|7.0%|
[php_commenters](#php_commenters)|349|349|38|10.8%|7.0%|
[stopforumspam_1d](#stopforumspam_1d)|6481|6481|36|0.5%|6.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|31|0.0%|5.7%|
[sorbs_web](#sorbs_web)|709|709,710|28|3.9%|5.2%|
[xroxy](#xroxy)|2108|2108|26|1.2%|4.8%|
[blocklist_de_bots](#blocklist_de_bots)|3010|3010|26|0.8%|4.8%|
[proxz](#proxz)|915|915|17|1.8%|3.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|7|0.0%|1.3%|
[et_tor](#et_tor)|6470|6470|6|0.0%|1.1%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4063|4063|6|0.1%|1.1%|
[blocklist_de_apache](#blocklist_de_apache)|15414|15414|6|0.0%|1.1%|
[blocklist_de_strongips](#blocklist_de_strongips)|179|179|5|2.7%|0.9%|
[alienvault_reputation](#alienvault_reputation)|177556|177556|5|0.0%|0.9%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|4|1.0%|0.7%|
[dm_tor](#dm_tor)|6497|6497|4|0.0%|0.7%|
[bm_tor](#bm_tor)|6501|6501|4|0.0%|0.7%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|3|0.0%|0.5%|
[ri_connect_proxies](#ri_connect_proxies)|2475|2475|3|0.1%|0.5%|
[proxyrss](#proxyrss)|1748|1748|3|0.1%|0.5%|
[php_harvesters](#php_harvesters)|324|324|2|0.6%|0.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2|0.0%|0.3%|
[et_block](#et_block)|1023|18338662|2|0.0%|0.3%|
[sorbs_socks](#sorbs_socks)|22|22,22|1|4.5%|0.1%|
[sorbs_misc](#sorbs_misc)|22|22,22|1|4.5%|0.1%|
[sorbs_http](#sorbs_http)|22|22,22|1|4.5%|0.1%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1|0.0%|0.1%|
[blocklist_de_ftp](#blocklist_de_ftp)|828|828|1|0.1%|0.1%|

## proxyrss

[proxyrss.com](http://www.proxyrss.com) open proxies syndicated from multiple sources.

Source is downloaded from [this link](http://www.proxyrss.com/proxylists/all.gz).

The last time downloaded was found to be dated: Sat Jun  6 20:41:25 UTC 2015.

The ipset `proxyrss` has **1748** entries, **1748** unique IPs.

The following table shows the overlaps of `proxyrss` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `proxyrss`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `proxyrss`.
- ` this % ` is the percentage **of this ipset (`proxyrss`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|791|0.8%|45.2%|
[ri_web_proxies](#ri_web_proxies)|6677|6677|650|9.7%|37.1%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|605|2.0%|34.6%|
[xroxy](#xroxy)|2108|2108|406|19.2%|23.2%|
[stopforumspam_1d](#stopforumspam_1d)|6481|6481|362|5.5%|20.7%|
[proxz](#proxz)|915|915|233|25.4%|13.3%|
[ri_connect_proxies](#ri_connect_proxies)|2475|2475|228|9.2%|13.0%|
[blocklist_de_bots](#blocklist_de_bots)|3010|3010|179|5.9%|10.2%|
[blocklist_de](#blocklist_de)|26854|26854|179|0.6%|10.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|57|0.0%|3.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|48|0.0%|2.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|41|0.0%|2.3%|
[nixspam](#nixspam)|19587|19587|9|0.0%|0.5%|
[sorbs_spam](#sorbs_spam)|32328|32328,33461|8|0.0%|0.4%|
[sorbs_recent_spam](#sorbs_recent_spam)|32328|32328,33461|8|0.0%|0.4%|
[sorbs_new_spam](#sorbs_new_spam)|32328|32328,33461|8|0.0%|0.4%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|6|0.8%|0.3%|
[php_commenters](#php_commenters)|349|349|5|1.4%|0.2%|
[blocklist_de_strongips](#blocklist_de_strongips)|179|179|5|2.7%|0.2%|
[snort_ipfilter](#snort_ipfilter)|9943|9943|3|0.0%|0.1%|
[php_spammers](#php_spammers)|536|536|3|0.5%|0.1%|
[php_harvesters](#php_harvesters)|324|324|3|0.9%|0.1%|
[php_dictionary](#php_dictionary)|545|545|2|0.3%|0.1%|
[et_compromised](#et_compromised)|2016|2016|2|0.0%|0.1%|
[bruteforceblocker](#bruteforceblocker)|1801|1801|2|0.1%|0.1%|
[sorbs_web](#sorbs_web)|709|709,710|1|0.1%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1|0.0%|0.0%|

## proxz

[proxz.com](http://www.proxz.com) open proxies (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.proxz.com/proxylists.xml).

The last time downloaded was found to be dated: Sat Jun  6 20:41:31 UTC 2015.

The ipset `proxz` has **915** entries, **915** unique IPs.

The following table shows the overlaps of `proxz` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `proxz`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `proxz`.
- ` this % ` is the percentage **of this ipset (`proxz`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|548|0.5%|59.8%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|426|1.4%|46.5%|
[ri_web_proxies](#ri_web_proxies)|6677|6677|416|6.2%|45.4%|
[xroxy](#xroxy)|2108|2108|350|16.6%|38.2%|
[proxyrss](#proxyrss)|1748|1748|233|13.3%|25.4%|
[stopforumspam_1d](#stopforumspam_1d)|6481|6481|154|2.3%|16.8%|
[ri_connect_proxies](#ri_connect_proxies)|2475|2475|149|6.0%|16.2%|
[blocklist_de](#blocklist_de)|26854|26854|136|0.5%|14.8%|
[blocklist_de_bots](#blocklist_de_bots)|3010|3010|115|3.8%|12.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|75|0.0%|8.1%|
[sorbs_spam](#sorbs_spam)|32328|32328,33461|44|0.1%|4.8%|
[sorbs_recent_spam](#sorbs_recent_spam)|32328|32328,33461|44|0.1%|4.8%|
[sorbs_new_spam](#sorbs_new_spam)|32328|32328,33461|44|0.1%|4.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|37|0.0%|4.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|31|0.0%|3.3%|
[snort_ipfilter](#snort_ipfilter)|9943|9943|24|0.2%|2.6%|
[blocklist_de_mail](#blocklist_de_mail)|16943|16943|20|0.1%|2.1%|
[php_spammers](#php_spammers)|536|536|17|3.1%|1.8%|
[php_dictionary](#php_dictionary)|545|545|15|2.7%|1.6%|
[sorbs_web](#sorbs_web)|709|709,710|12|1.6%|1.3%|
[nixspam](#nixspam)|19587|19587|8|0.0%|0.8%|
[php_commenters](#php_commenters)|349|349|6|1.7%|0.6%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|6|0.8%|0.6%|
[blocklist_de_strongips](#blocklist_de_strongips)|179|179|4|2.2%|0.4%|
[alienvault_reputation](#alienvault_reputation)|177556|177556|3|0.0%|0.3%|
[et_compromised](#et_compromised)|2016|2016|2|0.0%|0.2%|
[bruteforceblocker](#bruteforceblocker)|1801|1801|2|0.1%|0.2%|
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
[ri_web_proxies](#ri_web_proxies)|6677|6677|1029|15.4%|41.5%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|651|2.1%|26.3%|
[xroxy](#xroxy)|2108|2108|365|17.3%|14.7%|
[proxyrss](#proxyrss)|1748|1748|228|13.0%|9.2%|
[proxz](#proxz)|915|915|149|16.2%|6.0%|
[stopforumspam_1d](#stopforumspam_1d)|6481|6481|127|1.9%|5.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|96|0.0%|3.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|78|0.0%|3.1%|
[blocklist_de](#blocklist_de)|26854|26854|61|0.2%|2.4%|
[blocklist_de_bots](#blocklist_de_bots)|3010|3010|58|1.9%|2.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|53|0.0%|2.1%|
[sorbs_spam](#sorbs_spam)|32328|32328,33461|11|0.0%|0.4%|
[sorbs_recent_spam](#sorbs_recent_spam)|32328|32328,33461|11|0.0%|0.4%|
[sorbs_new_spam](#sorbs_new_spam)|32328|32328,33461|11|0.0%|0.4%|
[nixspam](#nixspam)|19587|19587|10|0.0%|0.4%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|7|1.0%|0.2%|
[php_commenters](#php_commenters)|349|349|5|1.4%|0.2%|
[php_dictionary](#php_dictionary)|545|545|4|0.7%|0.1%|
[snort_ipfilter](#snort_ipfilter)|9943|9943|3|0.0%|0.1%|
[php_spammers](#php_spammers)|536|536|3|0.5%|0.1%|
[blocklist_de_mail](#blocklist_de_mail)|16943|16943|3|0.0%|0.1%|
[alienvault_reputation](#alienvault_reputation)|177556|177556|3|0.0%|0.1%|
[sorbs_web](#sorbs_web)|709|709,710|1|0.1%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.0%|
[et_tor](#et_tor)|6470|6470|1|0.0%|0.0%|
[dm_tor](#dm_tor)|6497|6497|1|0.0%|0.0%|
[bm_tor](#bm_tor)|6501|6501|1|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|1984|1984|1|0.0%|0.0%|

## ri_web_proxies

[rosinstrument.com](http://www.rosinstrument.com) open HTTP proxies (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://tools.rosinstrument.com/proxy/l100.xml).

The last time downloaded was found to be dated: Sat Jun  6 20:45:19 UTC 2015.

The ipset `ri_web_proxies` has **6677** entries, **6677** unique IPs.

The following table shows the overlaps of `ri_web_proxies` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ri_web_proxies`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ri_web_proxies`.
- ` this % ` is the percentage **of this ipset (`ri_web_proxies`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|3212|3.4%|48.1%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|1632|5.4%|24.4%|
[ri_connect_proxies](#ri_connect_proxies)|2475|2475|1029|41.5%|15.4%|
[xroxy](#xroxy)|2108|2108|902|42.7%|13.5%|
[proxyrss](#proxyrss)|1748|1748|650|37.1%|9.7%|
[stopforumspam_1d](#stopforumspam_1d)|6481|6481|452|6.9%|6.7%|
[proxz](#proxz)|915|915|416|45.4%|6.2%|
[blocklist_de](#blocklist_de)|26854|26854|356|1.3%|5.3%|
[blocklist_de_bots](#blocklist_de_bots)|3010|3010|301|10.0%|4.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|195|0.0%|2.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|192|0.0%|2.8%|
[sorbs_spam](#sorbs_spam)|32328|32328,33461|140|0.4%|2.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|32328|32328,33461|140|0.4%|2.0%|
[sorbs_new_spam](#sorbs_new_spam)|32328|32328,33461|140|0.4%|2.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|134|0.0%|2.0%|
[snort_ipfilter](#snort_ipfilter)|9943|9943|66|0.6%|0.9%|
[blocklist_de_mail](#blocklist_de_mail)|16943|16943|53|0.3%|0.7%|
[nixspam](#nixspam)|19587|19587|52|0.2%|0.7%|
[php_dictionary](#php_dictionary)|545|545|43|7.8%|0.6%|
[php_spammers](#php_spammers)|536|536|38|7.0%|0.5%|
[sorbs_web](#sorbs_web)|709|709,710|24|3.3%|0.3%|
[php_commenters](#php_commenters)|349|349|23|6.5%|0.3%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|13|1.9%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|5|0.0%|0.0%|
[et_tor](#et_tor)|6470|6470|5|0.0%|0.0%|
[dm_tor](#dm_tor)|6497|6497|5|0.0%|0.0%|
[bm_tor](#bm_tor)|6501|6501|5|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|179|179|5|2.7%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|1984|1984|5|0.2%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|4|1.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|3|0.0%|0.0%|
[alienvault_reputation](#alienvault_reputation)|177556|177556|3|0.0%|0.0%|
[php_harvesters](#php_harvesters)|324|324|2|0.6%|0.0%|
[sslbl](#sslbl)|367|367|1|0.2%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|
[et_compromised](#et_compromised)|2016|2016|1|0.0%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|230|230|1|0.4%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1801|1801|1|0.0%|0.0%|

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
[alienvault_reputation](#alienvault_reputation)|177556|177556|1210|0.6%|99.5%|
[openbl_60d](#openbl_60d)|7286|7286|542|7.4%|44.6%|
[openbl_30d](#openbl_30d)|3257|3257|527|16.1%|43.3%|
[et_compromised](#et_compromised)|2016|2016|436|21.6%|35.8%|
[bruteforceblocker](#bruteforceblocker)|1801|1801|422|23.4%|34.7%|
[blocklist_de](#blocklist_de)|26854|26854|356|1.3%|29.3%|
[blocklist_de_ssh](#blocklist_de_ssh)|1689|1689|319|18.8%|26.2%|
[openbl_7d](#openbl_7d)|836|836|232|27.7%|19.0%|
[dshield](#dshield)|20|20,5120|123|2.4%|10.1%|
[et_block](#et_block)|1023|18338662|110|0.0%|9.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|108|0.0%|8.8%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|96|0.0%|7.9%|
[openbl_1d](#openbl_1d)|150|150|71|47.3%|5.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|68|0.0%|5.5%|
[sslbl](#sslbl)|367|367|57|15.5%|4.6%|
[blocklist_de_apache](#blocklist_de_apache)|15414|15414|36|0.2%|2.9%|
[ciarmy](#ciarmy)|423|423|32|7.5%|2.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|28|0.0%|2.3%|
[blocklist_de_strongips](#blocklist_de_strongips)|179|179|20|11.1%|1.6%|
[voipbl](#voipbl)|10476|10476,10888|13|0.1%|1.0%|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|5|0.0%|0.4%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|2|0.0%|0.1%|
[snort_ipfilter](#snort_ipfilter)|9943|9943|2|0.0%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2|0.0%|0.1%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4063|4063|2|0.0%|0.1%|
[stopforumspam_1d](#stopforumspam_1d)|6481|6481|1|0.0%|0.0%|
[sorbs_spam](#sorbs_spam)|32328|32328,33461|1|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|32328|32328,33461|1|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|32328|32328,33461|1|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.0%|
[et_tor](#et_tor)|6470|6470|1|0.0%|0.0%|
[dm_tor](#dm_tor)|6497|6497|1|0.0%|0.0%|
[bm_tor](#bm_tor)|6501|6501|1|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|16943|16943|1|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|1984|1984|1|0.0%|0.0%|

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
[bm_tor](#bm_tor)|6501|6501|1073|16.5%|10.7%|
[dm_tor](#dm_tor)|6497|6497|1072|16.4%|10.7%|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|803|0.8%|8.0%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|626|2.0%|6.2%|
[stopforumspam_1d](#stopforumspam_1d)|6481|6481|366|5.6%|3.6%|
[sorbs_spam](#sorbs_spam)|32328|32328,33461|319|0.9%|3.2%|
[sorbs_recent_spam](#sorbs_recent_spam)|32328|32328,33461|319|0.9%|3.2%|
[sorbs_new_spam](#sorbs_new_spam)|32328|32328,33461|319|0.9%|3.2%|
[et_block](#et_block)|1023|18338662|313|0.0%|3.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|232|0.0%|2.3%|
[zeus](#zeus)|232|232|203|87.5%|2.0%|
[zeus_badips](#zeus_badips)|202|202|179|88.6%|1.8%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|177|47.5%|1.7%|
[blocklist_de](#blocklist_de)|26854|26854|156|0.5%|1.5%|
[blocklist_de_mail](#blocklist_de_mail)|16943|16943|120|0.7%|1.2%|
[alienvault_reputation](#alienvault_reputation)|177556|177556|119|0.0%|1.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|103|0.0%|1.0%|
[nixspam](#nixspam)|19587|19587|92|0.4%|0.9%|
[php_dictionary](#php_dictionary)|545|545|79|14.4%|0.7%|
[feodo](#feodo)|99|99|79|79.7%|0.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|78|0.0%|0.7%|
[php_spammers](#php_spammers)|536|536|76|14.1%|0.7%|
[ri_web_proxies](#ri_web_proxies)|6677|6677|66|0.9%|0.6%|
[sorbs_web](#sorbs_web)|709|709,710|52|7.3%|0.5%|
[xroxy](#xroxy)|2108|2108|46|2.1%|0.4%|
[php_commenters](#php_commenters)|349|349|46|13.1%|0.4%|
[sslbl](#sslbl)|367|367|31|8.4%|0.3%|
[blocklist_de_bots](#blocklist_de_bots)|3010|3010|30|0.9%|0.3%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|28|2.1%|0.2%|
[openbl_60d](#openbl_60d)|7286|7286|27|0.3%|0.2%|
[proxz](#proxz)|915|915|24|2.6%|0.2%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|20|0.0%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|14|0.0%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|12|0.0%|0.1%|
[php_harvesters](#php_harvesters)|324|324|11|3.3%|0.1%|
[palevo](#palevo)|13|13|11|84.6%|0.1%|
[blocklist_de_apache](#blocklist_de_apache)|15414|15414|8|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|6|0.0%|0.0%|
[sorbs_socks](#sorbs_socks)|22|22,22|5|22.7%|0.0%|
[sorbs_misc](#sorbs_misc)|22|22,22|5|22.7%|0.0%|
[sorbs_http](#sorbs_http)|22|22,22|5|22.7%|0.0%|
[openbl_30d](#openbl_30d)|3257|3257|4|0.1%|0.0%|
[dshield](#dshield)|20|20,5120|4|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4063|4063|4|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2475|2475|3|0.1%|0.0%|
[proxyrss](#proxyrss)|1748|1748|3|0.1%|0.0%|
[shunlist](#shunlist)|1215|1215|2|0.1%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|2|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|1984|1984|2|0.1%|0.0%|
[openbl_7d](#openbl_7d)|836|836|1|0.1%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|230|230|1|0.4%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|179|179|1|0.5%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1689|1689|1|0.0%|0.0%|

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
[sorbs_spam](#sorbs_spam)|32328|32328,33461|22|0.0%|100.0%|
[sorbs_socks](#sorbs_socks)|22|22,22|22|100.0%|100.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|32328|32328,33461|22|0.0%|100.0%|
[sorbs_new_spam](#sorbs_new_spam)|32328|32328,33461|22|0.0%|100.0%|
[sorbs_misc](#sorbs_misc)|22|22,22|22|100.0%|100.0%|
[snort_ipfilter](#snort_ipfilter)|9943|9943|5|0.0%|22.7%|
[blocklist_de_mail](#blocklist_de_mail)|16943|16943|5|0.0%|22.7%|
[blocklist_de](#blocklist_de)|26854|26854|5|0.0%|22.7%|
[nixspam](#nixspam)|19587|19587|4|0.0%|18.1%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|3|0.0%|13.6%|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|3|0.0%|13.6%|
[sorbs_web](#sorbs_web)|709|709,710|3|0.4%|13.6%|
[php_dictionary](#php_dictionary)|545|545|2|0.3%|9.0%|
[xroxy](#xroxy)|2108|2108|1|0.0%|4.5%|
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
[sorbs_spam](#sorbs_spam)|32328|32328,33461|22|0.0%|100.0%|
[sorbs_socks](#sorbs_socks)|22|22,22|22|100.0%|100.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|32328|32328,33461|22|0.0%|100.0%|
[sorbs_new_spam](#sorbs_new_spam)|32328|32328,33461|22|0.0%|100.0%|
[sorbs_http](#sorbs_http)|22|22,22|22|100.0%|100.0%|
[snort_ipfilter](#snort_ipfilter)|9943|9943|5|0.0%|22.7%|
[blocklist_de_mail](#blocklist_de_mail)|16943|16943|5|0.0%|22.7%|
[blocklist_de](#blocklist_de)|26854|26854|5|0.0%|22.7%|
[nixspam](#nixspam)|19587|19587|4|0.0%|18.1%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|3|0.0%|13.6%|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|3|0.0%|13.6%|
[sorbs_web](#sorbs_web)|709|709,710|3|0.4%|13.6%|
[php_dictionary](#php_dictionary)|545|545|2|0.3%|9.0%|
[xroxy](#xroxy)|2108|2108|1|0.0%|4.5%|
[php_spammers](#php_spammers)|536|536|1|0.1%|4.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|1|0.0%|4.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|1|0.0%|4.5%|

## sorbs_new_spam

[Sorbs.net](https://www.sorbs.net/) NEW Spam senders, extracted from deltas.

Source is downloaded from [this link]().

The last time downloaded was found to be dated: Sat Jun  6 22:04:12 UTC 2015.

The ipset `sorbs_new_spam` has **32328** entries, **32328,33461** unique IPs.

The following table shows the overlaps of `sorbs_new_spam` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `sorbs_new_spam`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `sorbs_new_spam`.
- ` this % ` is the percentage **of this ipset (`sorbs_new_spam`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[sorbs_spam](#sorbs_spam)|32328|32328,33461|33461|100.0%|100.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|32328|32328,33461|33461|100.0%|100.0%|
[nixspam](#nixspam)|19587|19587|3447|17.5%|10.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|2459|0.0%|7.3%|
[blocklist_de](#blocklist_de)|26854|26854|1043|3.8%|3.1%|
[blocklist_de_mail](#blocklist_de_mail)|16943|16943|870|5.1%|2.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|816|0.0%|2.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|525|0.0%|1.5%|
[sorbs_web](#sorbs_web)|709|709,710|354|49.8%|1.0%|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|345|0.3%|1.0%|
[snort_ipfilter](#snort_ipfilter)|9943|9943|319|3.2%|0.9%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|183|0.6%|0.5%|
[php_dictionary](#php_dictionary)|545|545|151|27.7%|0.4%|
[ri_web_proxies](#ri_web_proxies)|6677|6677|140|2.0%|0.4%|
[php_spammers](#php_spammers)|536|536|134|25.0%|0.4%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4063|4063|108|2.6%|0.3%|
[blocklist_de_apache](#blocklist_de_apache)|15414|15414|108|0.7%|0.3%|
[alienvault_reputation](#alienvault_reputation)|177556|177556|100|0.0%|0.2%|
[xroxy](#xroxy)|2108|2108|88|4.1%|0.2%|
[blocklist_de_bots](#blocklist_de_bots)|3010|3010|57|1.8%|0.1%|
[stopforumspam_1d](#stopforumspam_1d)|6481|6481|55|0.8%|0.1%|
[proxz](#proxz)|915|915|44|4.8%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|41|0.0%|0.1%|
[sorbs_socks](#sorbs_socks)|22|22,22|22|100.0%|0.0%|
[sorbs_misc](#sorbs_misc)|22|22,22|22|100.0%|0.0%|
[sorbs_http](#sorbs_http)|22|22,22|22|100.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|1984|1984|18|0.9%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|16|0.0%|0.0%|
[php_commenters](#php_commenters)|349|349|15|4.2%|0.0%|
[et_block](#et_block)|1023|18338662|15|0.0%|0.0%|
[sorbs_smtp](#sorbs_smtp)|14|14,14|14|100.0%|0.0%|
[openbl_60d](#openbl_60d)|7286|7286|14|0.1%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|13|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2475|2475|11|0.4%|0.0%|
[proxyrss](#proxyrss)|1748|1748|8|0.4%|0.0%|
[php_harvesters](#php_harvesters)|324|324|8|2.4%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|6|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|828|828|6|0.7%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|3|0.0%|0.0%|
[openbl_30d](#openbl_30d)|3257|3257|3|0.0%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|2|0.1%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|2|0.2%|0.0%|
[et_tor](#et_tor)|6470|6470|2|0.0%|0.0%|
[dm_tor](#dm_tor)|6497|6497|2|0.0%|0.0%|
[bm_tor](#bm_tor)|6501|6501|2|0.0%|0.0%|
[shunlist](#shunlist)|1215|1215|1|0.0%|0.0%|
[openbl_7d](#openbl_7d)|836|836|1|0.1%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|179|179|1|0.5%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1689|1689|1|0.0%|0.0%|

## sorbs_recent_spam

[Sorbs.net](https://www.sorbs.net/) RECENT Spam senders, extracted from deltas.

Source is downloaded from [this link]().

The last time downloaded was found to be dated: Sat Jun  6 22:04:12 UTC 2015.

The ipset `sorbs_recent_spam` has **32328** entries, **32328,33461** unique IPs.

The following table shows the overlaps of `sorbs_recent_spam` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `sorbs_recent_spam`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `sorbs_recent_spam`.
- ` this % ` is the percentage **of this ipset (`sorbs_recent_spam`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[sorbs_spam](#sorbs_spam)|32328|32328,33461|33461|100.0%|100.0%|
[sorbs_new_spam](#sorbs_new_spam)|32328|32328,33461|33461|100.0%|100.0%|
[nixspam](#nixspam)|19587|19587|3447|17.5%|10.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|2459|0.0%|7.3%|
[blocklist_de](#blocklist_de)|26854|26854|1043|3.8%|3.1%|
[blocklist_de_mail](#blocklist_de_mail)|16943|16943|870|5.1%|2.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|816|0.0%|2.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|525|0.0%|1.5%|
[sorbs_web](#sorbs_web)|709|709,710|354|49.8%|1.0%|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|345|0.3%|1.0%|
[snort_ipfilter](#snort_ipfilter)|9943|9943|319|3.2%|0.9%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|183|0.6%|0.5%|
[php_dictionary](#php_dictionary)|545|545|151|27.7%|0.4%|
[ri_web_proxies](#ri_web_proxies)|6677|6677|140|2.0%|0.4%|
[php_spammers](#php_spammers)|536|536|134|25.0%|0.4%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4063|4063|108|2.6%|0.3%|
[blocklist_de_apache](#blocklist_de_apache)|15414|15414|108|0.7%|0.3%|
[alienvault_reputation](#alienvault_reputation)|177556|177556|100|0.0%|0.2%|
[xroxy](#xroxy)|2108|2108|88|4.1%|0.2%|
[blocklist_de_bots](#blocklist_de_bots)|3010|3010|57|1.8%|0.1%|
[stopforumspam_1d](#stopforumspam_1d)|6481|6481|55|0.8%|0.1%|
[proxz](#proxz)|915|915|44|4.8%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|41|0.0%|0.1%|
[sorbs_socks](#sorbs_socks)|22|22,22|22|100.0%|0.0%|
[sorbs_misc](#sorbs_misc)|22|22,22|22|100.0%|0.0%|
[sorbs_http](#sorbs_http)|22|22,22|22|100.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|1984|1984|18|0.9%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|16|0.0%|0.0%|
[php_commenters](#php_commenters)|349|349|15|4.2%|0.0%|
[et_block](#et_block)|1023|18338662|15|0.0%|0.0%|
[sorbs_smtp](#sorbs_smtp)|14|14,14|14|100.0%|0.0%|
[openbl_60d](#openbl_60d)|7286|7286|14|0.1%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|13|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2475|2475|11|0.4%|0.0%|
[proxyrss](#proxyrss)|1748|1748|8|0.4%|0.0%|
[php_harvesters](#php_harvesters)|324|324|8|2.4%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|6|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|828|828|6|0.7%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|3|0.0%|0.0%|
[openbl_30d](#openbl_30d)|3257|3257|3|0.0%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|2|0.1%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|2|0.2%|0.0%|
[et_tor](#et_tor)|6470|6470|2|0.0%|0.0%|
[dm_tor](#dm_tor)|6497|6497|2|0.0%|0.0%|
[bm_tor](#bm_tor)|6501|6501|2|0.0%|0.0%|
[shunlist](#shunlist)|1215|1215|1|0.0%|0.0%|
[openbl_7d](#openbl_7d)|836|836|1|0.1%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|179|179|1|0.5%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1689|1689|1|0.0%|0.0%|

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
[sorbs_spam](#sorbs_spam)|32328|32328,33461|14|0.0%|100.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|32328|32328,33461|14|0.0%|100.0%|
[sorbs_new_spam](#sorbs_new_spam)|32328|32328,33461|14|0.0%|100.0%|
[nixspam](#nixspam)|19587|19587|1|0.0%|7.1%|
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
[sorbs_spam](#sorbs_spam)|32328|32328,33461|22|0.0%|100.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|32328|32328,33461|22|0.0%|100.0%|
[sorbs_new_spam](#sorbs_new_spam)|32328|32328,33461|22|0.0%|100.0%|
[sorbs_misc](#sorbs_misc)|22|22,22|22|100.0%|100.0%|
[sorbs_http](#sorbs_http)|22|22,22|22|100.0%|100.0%|
[snort_ipfilter](#snort_ipfilter)|9943|9943|5|0.0%|22.7%|
[blocklist_de_mail](#blocklist_de_mail)|16943|16943|5|0.0%|22.7%|
[blocklist_de](#blocklist_de)|26854|26854|5|0.0%|22.7%|
[nixspam](#nixspam)|19587|19587|4|0.0%|18.1%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|3|0.0%|13.6%|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|3|0.0%|13.6%|
[sorbs_web](#sorbs_web)|709|709,710|3|0.4%|13.6%|
[php_dictionary](#php_dictionary)|545|545|2|0.3%|9.0%|
[xroxy](#xroxy)|2108|2108|1|0.0%|4.5%|
[php_spammers](#php_spammers)|536|536|1|0.1%|4.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|1|0.0%|4.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|1|0.0%|4.5%|

## sorbs_spam

[Sorbs.net](https://www.sorbs.net/) Spam senders, extracted from deltas.

Source is downloaded from [this link]().

The last time downloaded was found to be dated: Sat Jun  6 22:04:12 UTC 2015.

The ipset `sorbs_spam` has **32328** entries, **32328,33461** unique IPs.

The following table shows the overlaps of `sorbs_spam` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `sorbs_spam`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `sorbs_spam`.
- ` this % ` is the percentage **of this ipset (`sorbs_spam`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[sorbs_recent_spam](#sorbs_recent_spam)|32328|32328,33461|33461|100.0%|100.0%|
[sorbs_new_spam](#sorbs_new_spam)|32328|32328,33461|33461|100.0%|100.0%|
[nixspam](#nixspam)|19587|19587|3447|17.5%|10.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|2459|0.0%|7.3%|
[blocklist_de](#blocklist_de)|26854|26854|1043|3.8%|3.1%|
[blocklist_de_mail](#blocklist_de_mail)|16943|16943|870|5.1%|2.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|816|0.0%|2.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|525|0.0%|1.5%|
[sorbs_web](#sorbs_web)|709|709,710|354|49.8%|1.0%|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|345|0.3%|1.0%|
[snort_ipfilter](#snort_ipfilter)|9943|9943|319|3.2%|0.9%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|183|0.6%|0.5%|
[php_dictionary](#php_dictionary)|545|545|151|27.7%|0.4%|
[ri_web_proxies](#ri_web_proxies)|6677|6677|140|2.0%|0.4%|
[php_spammers](#php_spammers)|536|536|134|25.0%|0.4%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4063|4063|108|2.6%|0.3%|
[blocklist_de_apache](#blocklist_de_apache)|15414|15414|108|0.7%|0.3%|
[alienvault_reputation](#alienvault_reputation)|177556|177556|100|0.0%|0.2%|
[xroxy](#xroxy)|2108|2108|88|4.1%|0.2%|
[blocklist_de_bots](#blocklist_de_bots)|3010|3010|57|1.8%|0.1%|
[stopforumspam_1d](#stopforumspam_1d)|6481|6481|55|0.8%|0.1%|
[proxz](#proxz)|915|915|44|4.8%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|41|0.0%|0.1%|
[sorbs_socks](#sorbs_socks)|22|22,22|22|100.0%|0.0%|
[sorbs_misc](#sorbs_misc)|22|22,22|22|100.0%|0.0%|
[sorbs_http](#sorbs_http)|22|22,22|22|100.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|1984|1984|18|0.9%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|16|0.0%|0.0%|
[php_commenters](#php_commenters)|349|349|15|4.2%|0.0%|
[et_block](#et_block)|1023|18338662|15|0.0%|0.0%|
[sorbs_smtp](#sorbs_smtp)|14|14,14|14|100.0%|0.0%|
[openbl_60d](#openbl_60d)|7286|7286|14|0.1%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|13|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2475|2475|11|0.4%|0.0%|
[proxyrss](#proxyrss)|1748|1748|8|0.4%|0.0%|
[php_harvesters](#php_harvesters)|324|324|8|2.4%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|6|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|828|828|6|0.7%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|3|0.0%|0.0%|
[openbl_30d](#openbl_30d)|3257|3257|3|0.0%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|2|0.1%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|2|0.2%|0.0%|
[et_tor](#et_tor)|6470|6470|2|0.0%|0.0%|
[dm_tor](#dm_tor)|6497|6497|2|0.0%|0.0%|
[bm_tor](#bm_tor)|6501|6501|2|0.0%|0.0%|
[shunlist](#shunlist)|1215|1215|1|0.0%|0.0%|
[openbl_7d](#openbl_7d)|836|836|1|0.1%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|179|179|1|0.5%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1689|1689|1|0.0%|0.0%|

## sorbs_web

[Sorbs.net](https://www.sorbs.net/) WEB exploits, extracted from deltas.

Source is downloaded from [this link]().

The last time downloaded was found to be dated: Sat Jun  6 22:04:12 UTC 2015.

The ipset `sorbs_web` has **709** entries, **709,710** unique IPs.

The following table shows the overlaps of `sorbs_web` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `sorbs_web`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `sorbs_web`.
- ` this % ` is the percentage **of this ipset (`sorbs_web`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[sorbs_spam](#sorbs_spam)|32328|32328,33461|354|1.0%|49.8%|
[sorbs_recent_spam](#sorbs_recent_spam)|32328|32328,33461|354|1.0%|49.8%|
[sorbs_new_spam](#sorbs_new_spam)|32328|32328,33461|354|1.0%|49.8%|
[nixspam](#nixspam)|19587|19587|94|0.4%|13.2%|
[blocklist_de](#blocklist_de)|26854|26854|77|0.2%|10.8%|
[blocklist_de_mail](#blocklist_de_mail)|16943|16943|59|0.3%|8.3%|
[snort_ipfilter](#snort_ipfilter)|9943|9943|52|0.5%|7.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|52|0.0%|7.3%|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|51|0.0%|7.1%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|37|0.1%|5.2%|
[php_dictionary](#php_dictionary)|545|545|30|5.5%|4.2%|
[php_spammers](#php_spammers)|536|536|28|5.2%|3.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|25|0.0%|3.5%|
[ri_web_proxies](#ri_web_proxies)|6677|6677|24|0.3%|3.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|22|0.0%|3.0%|
[xroxy](#xroxy)|2108|2108|17|0.8%|2.3%|
[stopforumspam_1d](#stopforumspam_1d)|6481|6481|16|0.2%|2.2%|
[blocklist_de_bots](#blocklist_de_bots)|3010|3010|15|0.4%|2.1%|
[proxz](#proxz)|915|915|12|1.3%|1.6%|
[sorbs_socks](#sorbs_socks)|22|22,22|3|13.6%|0.4%|
[sorbs_misc](#sorbs_misc)|22|22,22|3|13.6%|0.4%|
[sorbs_http](#sorbs_http)|22|22,22|3|13.6%|0.4%|
[php_commenters](#php_commenters)|349|349|3|0.8%|0.4%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4063|4063|3|0.0%|0.4%|
[blocklist_de_apache](#blocklist_de_apache)|15414|15414|3|0.0%|0.4%|
[ri_connect_proxies](#ri_connect_proxies)|2475|2475|1|0.0%|0.1%|
[proxyrss](#proxyrss)|1748|1748|1|0.0%|0.1%|
[openbl_60d](#openbl_60d)|7286|7286|1|0.0%|0.1%|
[openbl_30d](#openbl_30d)|3257|3257|1|0.0%|0.1%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1|0.0%|0.1%|
[blocklist_de_strongips](#blocklist_de_strongips)|179|179|1|0.5%|0.1%|
[alienvault_reputation](#alienvault_reputation)|177556|177556|1|0.0%|0.1%|

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
[alienvault_reputation](#alienvault_reputation)|177556|177556|1627|0.9%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1037|0.3%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|1021|1.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|512|0.1%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|322|1.0%|0.0%|
[dshield](#dshield)|20|20,5120|256|5.0%|0.0%|
[openbl_60d](#openbl_60d)|7286|7286|239|3.2%|0.0%|
[blocklist_de](#blocklist_de)|26854|26854|177|0.6%|0.0%|
[openbl_30d](#openbl_30d)|3257|3257|160|4.9%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1689|1689|106|6.2%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1801|1801|101|5.6%|0.0%|
[et_compromised](#et_compromised)|2016|2016|100|4.9%|0.0%|
[shunlist](#shunlist)|1215|1215|96|7.9%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6481|6481|82|1.2%|0.0%|
[openbl_7d](#openbl_7d)|836|836|47|5.6%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3010|3010|41|1.3%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|29|2.2%|0.0%|
[php_commenters](#php_commenters)|349|349|28|8.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|16943|16943|24|0.1%|0.0%|
[nixspam](#nixspam)|19587|19587|21|0.1%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9943|9943|20|0.2%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|1984|1984|18|0.9%|0.0%|
[zeus_badips](#zeus_badips)|202|202|16|7.9%|0.0%|
[zeus](#zeus)|232|232|16|6.8%|0.0%|
[voipbl](#voipbl)|10476|10476,10888|14|0.1%|0.0%|
[openbl_1d](#openbl_1d)|150|150|14|9.3%|0.0%|
[sorbs_spam](#sorbs_spam)|32328|32328,33461|13|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|32328|32328,33461|13|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|32328|32328,33461|13|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|179|179|7|3.9%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|6|0.4%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|6|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4063|4063|5|0.1%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|15414|15414|5|0.0%|0.0%|
[php_dictionary](#php_dictionary)|545|545|4|0.7%|0.0%|
[malc0de](#malc0de)|361|361|4|1.1%|0.0%|
[php_spammers](#php_spammers)|536|536|3|0.5%|0.0%|
[dm_tor](#dm_tor)|6497|6497|3|0.0%|0.0%|
[bm_tor](#bm_tor)|6501|6501|3|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|2|0.2%|0.0%|
[et_tor](#et_tor)|6470|6470|2|0.0%|0.0%|
[sslbl](#sslbl)|367|367|1|0.2%|0.0%|
[php_harvesters](#php_harvesters)|324|324|1|0.3%|0.0%|
[et_botcc](#et_botcc)|509|509|1|0.1%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|94|94|1|1.0%|0.0%|

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
[alienvault_reputation](#alienvault_reputation)|177556|177556|15|0.0%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|11|0.0%|0.0%|
[php_commenters](#php_commenters)|349|349|7|2.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9943|9943|6|0.0%|0.0%|
[zeus_badips](#zeus_badips)|202|202|5|2.4%|0.0%|
[zeus](#zeus)|232|232|5|2.1%|0.0%|
[blocklist_de](#blocklist_de)|26854|26854|4|0.0%|0.0%|
[sorbs_spam](#sorbs_spam)|32328|32328,33461|3|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|32328|32328,33461|3|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|32328|32328,33461|3|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|179|179|3|1.6%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3010|3010|3|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6481|6481|2|0.0%|0.0%|
[php_harvesters](#php_harvesters)|324|324|1|0.3%|0.0%|
[openbl_60d](#openbl_60d)|7286|7286|1|0.0%|0.0%|
[openbl_30d](#openbl_30d)|3257|3257|1|0.0%|0.0%|
[malc0de](#malc0de)|361|361|1|0.2%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|230|230|1|0.4%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1689|1689|1|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|15414|15414|1|0.0%|0.0%|

## sslbl

[Abuse.ch SSL Blacklist](https://sslbl.abuse.ch/) bad SSL traffic related to malware or botnet activities - **excellent list**

Source is downloaded from [this link](https://sslbl.abuse.ch/blacklist/sslipblacklist.csv).

The last time downloaded was found to be dated: Sat Jun  6 22:15:06 UTC 2015.

The ipset `sslbl` has **367** entries, **367** unique IPs.

The following table shows the overlaps of `sslbl` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `sslbl`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `sslbl`.
- ` this % ` is the percentage **of this ipset (`sslbl`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[alienvault_reputation](#alienvault_reputation)|177556|177556|64|0.0%|17.4%|
[shunlist](#shunlist)|1215|1215|57|4.6%|15.5%|
[feodo](#feodo)|99|99|36|36.3%|9.8%|
[et_block](#et_block)|1023|18338662|35|0.0%|9.5%|
[snort_ipfilter](#snort_ipfilter)|9943|9943|31|0.3%|8.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|26|0.0%|7.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|5|0.0%|1.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|3|0.0%|0.8%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|1|0.0%|0.2%|
[ri_web_proxies](#ri_web_proxies)|6677|6677|1|0.0%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.2%|

## stopforumspam_1d

[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers in the last 24 hours - **excellent list**

Source is downloaded from [this link](http://www.stopforumspam.com/downloads/listed_ip_1.zip).

The last time downloaded was found to be dated: Sat Jun  6 22:00:02 UTC 2015.

The ipset `stopforumspam_1d` has **6481** entries, **6481** unique IPs.

The following table shows the overlaps of `stopforumspam_1d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `stopforumspam_1d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `stopforumspam_1d`.
- ` this % ` is the percentage **of this ipset (`stopforumspam_1d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|4337|4.6%|66.9%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|3963|13.1%|61.1%|
[blocklist_de](#blocklist_de)|26854|26854|1210|4.5%|18.6%|
[blocklist_de_bots](#blocklist_de_bots)|3010|3010|1159|38.5%|17.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|491|0.0%|7.5%|
[ri_web_proxies](#ri_web_proxies)|6677|6677|452|6.7%|6.9%|
[snort_ipfilter](#snort_ipfilter)|9943|9943|366|3.6%|5.6%|
[proxyrss](#proxyrss)|1748|1748|362|20.7%|5.5%|
[bm_tor](#bm_tor)|6501|6501|318|4.8%|4.9%|
[et_tor](#et_tor)|6470|6470|317|4.8%|4.8%|
[dm_tor](#dm_tor)|6497|6497|317|4.8%|4.8%|
[xroxy](#xroxy)|2108|2108|260|12.3%|4.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|195|0.0%|3.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|159|42.7%|2.4%|
[proxz](#proxz)|915|915|154|16.8%|2.3%|
[php_commenters](#php_commenters)|349|349|135|38.6%|2.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|130|0.0%|2.0%|
[ri_connect_proxies](#ri_connect_proxies)|2475|2475|127|5.1%|1.9%|
[blocklist_de_strongips](#blocklist_de_strongips)|179|179|101|56.4%|1.5%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|82|0.0%|1.2%|
[et_block](#et_block)|1023|18338662|78|0.0%|1.2%|
[blocklist_de_apache](#blocklist_de_apache)|15414|15414|59|0.3%|0.9%|
[sorbs_spam](#sorbs_spam)|32328|32328,33461|55|0.1%|0.8%|
[sorbs_recent_spam](#sorbs_recent_spam)|32328|32328,33461|55|0.1%|0.8%|
[sorbs_new_spam](#sorbs_new_spam)|32328|32328,33461|55|0.1%|0.8%|
[alienvault_reputation](#alienvault_reputation)|177556|177556|52|0.0%|0.8%|
[blocklist_de_mail](#blocklist_de_mail)|16943|16943|44|0.2%|0.6%|
[php_harvesters](#php_harvesters)|324|324|40|12.3%|0.6%|
[php_spammers](#php_spammers)|536|536|36|6.7%|0.5%|
[php_dictionary](#php_dictionary)|545|545|33|6.0%|0.5%|
[nixspam](#nixspam)|19587|19587|30|0.1%|0.4%|
[openbl_60d](#openbl_60d)|7286|7286|20|0.2%|0.3%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4063|4063|20|0.4%|0.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|18|0.0%|0.2%|
[sorbs_web](#sorbs_web)|709|709,710|16|2.2%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|7|0.0%|0.1%|
[voipbl](#voipbl)|10476|10476,10888|4|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|4|0.5%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|3|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|2|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.0%|
[zeus_badips](#zeus_badips)|202|202|1|0.4%|0.0%|
[zeus](#zeus)|232|232|1|0.4%|0.0%|
[shunlist](#shunlist)|1215|1215|1|0.0%|0.0%|
[openbl_30d](#openbl_30d)|3257|3257|1|0.0%|0.0%|
[et_compromised](#et_compromised)|2016|2016|1|0.0%|0.0%|
[dshield](#dshield)|20|20,5120|1|0.0%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|230|230|1|0.4%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1801|1801|1|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|828|828|1|0.1%|0.0%|

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
[stopforumspam_1d](#stopforumspam_1d)|6481|6481|4337|66.9%|4.6%|
[ri_web_proxies](#ri_web_proxies)|6677|6677|3212|48.1%|3.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|2524|0.0%|2.7%|
[blocklist_de](#blocklist_de)|26854|26854|2242|8.3%|2.4%|
[blocklist_de_bots](#blocklist_de_bots)|3010|3010|1924|63.9%|2.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|1543|0.0%|1.6%|
[ri_connect_proxies](#ri_connect_proxies)|2475|2475|1418|57.2%|1.5%|
[xroxy](#xroxy)|2108|2108|1239|58.7%|1.3%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|1021|0.0%|1.0%|
[et_block](#et_block)|1023|18338662|1013|0.0%|1.0%|
[snort_ipfilter](#snort_ipfilter)|9943|9943|803|8.0%|0.8%|
[proxyrss](#proxyrss)|1748|1748|791|45.2%|0.8%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|744|0.0%|0.7%|
[et_tor](#et_tor)|6470|6470|647|10.0%|0.6%|
[dm_tor](#dm_tor)|6497|6497|634|9.7%|0.6%|
[bm_tor](#bm_tor)|6501|6501|631|9.7%|0.6%|
[proxz](#proxz)|915|915|548|59.8%|0.5%|
[sorbs_spam](#sorbs_spam)|32328|32328,33461|345|1.0%|0.3%|
[sorbs_recent_spam](#sorbs_recent_spam)|32328|32328,33461|345|1.0%|0.3%|
[sorbs_new_spam](#sorbs_new_spam)|32328|32328,33461|345|1.0%|0.3%|
[php_commenters](#php_commenters)|349|349|253|72.4%|0.2%|
[blocklist_de_mail](#blocklist_de_mail)|16943|16943|249|1.4%|0.2%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|231|62.0%|0.2%|
[blocklist_de_apache](#blocklist_de_apache)|15414|15414|216|1.4%|0.2%|
[alienvault_reputation](#alienvault_reputation)|177556|177556|205|0.1%|0.2%|
[nixspam](#nixspam)|19587|19587|143|0.7%|0.1%|
[blocklist_de_strongips](#blocklist_de_strongips)|179|179|132|73.7%|0.1%|
[php_spammers](#php_spammers)|536|536|117|21.8%|0.1%|
[php_dictionary](#php_dictionary)|545|545|103|18.8%|0.1%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|88|0.0%|0.0%|
[php_harvesters](#php_harvesters)|324|324|72|22.2%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4063|4063|57|1.4%|0.0%|
[openbl_60d](#openbl_60d)|7286|7286|54|0.7%|0.0%|
[sorbs_web](#sorbs_web)|709|709,710|51|7.1%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|46|0.0%|0.0%|
[voipbl](#voipbl)|10476|10476,10888|35|0.3%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|22|3.2%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|14|0.0%|0.0%|
[et_compromised](#et_compromised)|2016|2016|11|0.5%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1801|1801|11|0.6%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|828|828|11|1.3%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|1984|1984|8|0.4%|0.0%|
[shunlist](#shunlist)|1215|1215|5|0.4%|0.0%|
[openbl_30d](#openbl_30d)|3257|3257|5|0.1%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|4|0.3%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1689|1689|4|0.2%|0.0%|
[sorbs_socks](#sorbs_socks)|22|22,22|3|13.6%|0.0%|
[sorbs_misc](#sorbs_misc)|22|22,22|3|13.6%|0.0%|
[sorbs_http](#sorbs_http)|22|22,22|3|13.6%|0.0%|
[openbl_7d](#openbl_7d)|836|836|3|0.3%|0.0%|
[zeus_badips](#zeus_badips)|202|202|2|0.9%|0.0%|
[zeus](#zeus)|232|232|2|0.8%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.0%|
[fullbogons](#fullbogons)|3721|670267288|2|0.0%|0.0%|
[dshield](#dshield)|20|20,5120|1|0.0%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|230|230|1|0.4%|0.0%|
[ciarmy](#ciarmy)|423|423|1|0.2%|0.0%|
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
[stopforumspam_1d](#stopforumspam_1d)|6481|6481|3963|61.1%|13.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|1912|0.0%|6.3%|
[blocklist_de](#blocklist_de)|26854|26854|1901|7.0%|6.3%|
[blocklist_de_bots](#blocklist_de_bots)|3010|3010|1731|57.5%|5.7%|
[ri_web_proxies](#ri_web_proxies)|6677|6677|1632|24.4%|5.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|909|0.0%|3.0%|
[xroxy](#xroxy)|2108|2108|723|34.2%|2.4%|
[ri_connect_proxies](#ri_connect_proxies)|2475|2475|651|26.3%|2.1%|
[snort_ipfilter](#snort_ipfilter)|9943|9943|626|6.2%|2.0%|
[proxyrss](#proxyrss)|1748|1748|605|34.6%|2.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|568|0.0%|1.8%|
[et_tor](#et_tor)|6470|6470|516|7.9%|1.7%|
[dm_tor](#dm_tor)|6497|6497|502|7.7%|1.6%|
[bm_tor](#bm_tor)|6501|6501|498|7.6%|1.6%|
[proxz](#proxz)|915|915|426|46.5%|1.4%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|322|0.0%|1.0%|
[et_block](#et_block)|1023|18338662|314|0.0%|1.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|191|51.3%|0.6%|
[php_commenters](#php_commenters)|349|349|185|53.0%|0.6%|
[sorbs_spam](#sorbs_spam)|32328|32328,33461|183|0.5%|0.6%|
[sorbs_recent_spam](#sorbs_recent_spam)|32328|32328,33461|183|0.5%|0.6%|
[sorbs_new_spam](#sorbs_new_spam)|32328|32328,33461|183|0.5%|0.6%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|153|0.0%|0.5%|
[blocklist_de_mail](#blocklist_de_mail)|16943|16943|138|0.8%|0.4%|
[blocklist_de_apache](#blocklist_de_apache)|15414|15414|127|0.8%|0.4%|
[blocklist_de_strongips](#blocklist_de_strongips)|179|179|121|67.5%|0.4%|
[alienvault_reputation](#alienvault_reputation)|177556|177556|93|0.0%|0.3%|
[nixspam](#nixspam)|19587|19587|73|0.3%|0.2%|
[php_spammers](#php_spammers)|536|536|66|12.3%|0.2%|
[php_dictionary](#php_dictionary)|545|545|66|12.1%|0.2%|
[php_harvesters](#php_harvesters)|324|324|54|16.6%|0.1%|
[sorbs_web](#sorbs_web)|709|709,710|37|5.2%|0.1%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4063|4063|34|0.8%|0.1%|
[openbl_60d](#openbl_60d)|7286|7286|25|0.3%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|25|0.0%|0.0%|
[voipbl](#voipbl)|10476|10476,10888|12|0.1%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|12|1.7%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|11|0.0%|0.0%|
[et_compromised](#et_compromised)|2016|2016|7|0.3%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1801|1801|7|0.3%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|6|0.0%|0.0%|
[sorbs_socks](#sorbs_socks)|22|22,22|3|13.6%|0.0%|
[sorbs_misc](#sorbs_misc)|22|22,22|3|13.6%|0.0%|
[sorbs_http](#sorbs_http)|22|22,22|3|13.6%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|1984|1984|3|0.1%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|828|828|3|0.3%|0.0%|
[shunlist](#shunlist)|1215|1215|2|0.1%|0.0%|
[openbl_30d](#openbl_30d)|3257|3257|2|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.0%|
[zeus_badips](#zeus_badips)|202|202|1|0.4%|0.0%|
[zeus](#zeus)|232|232|1|0.4%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|1|0.0%|0.0%|
[dshield](#dshield)|20|20,5120|1|0.0%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|230|230|1|0.4%|0.0%|
[ciarmy](#ciarmy)|423|423|1|0.2%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1689|1689|1|0.0%|0.0%|

## virbl

[VirBL](http://virbl.bit.nl/) is a project of which the idea was born during the RIPE-48 meeting. The plan was to get reports of virusscanning mailservers, and put the IP-addresses that were reported to send viruses on a blacklist.

Source is downloaded from [this link](http://virbl.bit.nl/download/virbl.dnsbl.bit.nl.txt).

The last time downloaded was found to be dated: Sat Jun  6 21:52:04 UTC 2015.

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

The last time downloaded was found to be dated: Sat Jun  6 21:27:04 UTC 2015.

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
[alienvault_reputation](#alienvault_reputation)|177556|177556|198|0.1%|1.8%|
[blocklist_de](#blocklist_de)|26854|26854|36|0.1%|0.3%|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|35|0.0%|0.3%|
[blocklist_de_sip](#blocklist_de_sip)|94|94|28|29.7%|0.2%|
[et_block](#et_block)|1023|18338662|17|0.0%|0.1%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|14|0.0%|0.1%|
[shunlist](#shunlist)|1215|1215|13|1.0%|0.1%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|12|0.0%|0.1%|
[openbl_60d](#openbl_60d)|7286|7286|8|0.1%|0.0%|
[dshield](#dshield)|20|20,5120|5|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6481|6481|4|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|4|0.0%|0.0%|
[ciarmy](#ciarmy)|423|423|4|0.9%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3010|3010|4|0.1%|0.0%|
[openbl_30d](#openbl_30d)|3257|3257|3|0.0%|0.0%|
[et_tor](#et_tor)|6470|6470|3|0.0%|0.0%|
[dm_tor](#dm_tor)|6497|6497|3|0.0%|0.0%|
[bm_tor](#bm_tor)|6501|6501|3|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|15414|15414|3|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|2|0.0%|0.0%|
[et_compromised](#et_compromised)|2016|2016|2|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1801|1801|2|0.1%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|16943|16943|1|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4063|4063|1|0.0%|0.0%|

## xroxy

[xroxy.com](http://www.xroxy.com) open proxies (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.xroxy.com/proxyrss.xml).

The last time downloaded was found to be dated: Sat Jun  6 21:33:02 UTC 2015.

The ipset `xroxy` has **2108** entries, **2108** unique IPs.

The following table shows the overlaps of `xroxy` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `xroxy`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `xroxy`.
- ` this % ` is the percentage **of this ipset (`xroxy`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|1239|1.3%|58.7%|
[ri_web_proxies](#ri_web_proxies)|6677|6677|902|13.5%|42.7%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|723|2.4%|34.2%|
[proxyrss](#proxyrss)|1748|1748|406|23.2%|19.2%|
[ri_connect_proxies](#ri_connect_proxies)|2475|2475|365|14.7%|17.3%|
[proxz](#proxz)|915|915|350|38.2%|16.6%|
[stopforumspam_1d](#stopforumspam_1d)|6481|6481|260|4.0%|12.3%|
[blocklist_de](#blocklist_de)|26854|26854|209|0.7%|9.9%|
[blocklist_de_bots](#blocklist_de_bots)|3010|3010|171|5.6%|8.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|101|0.0%|4.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|97|0.0%|4.6%|
[sorbs_spam](#sorbs_spam)|32328|32328,33461|88|0.2%|4.1%|
[sorbs_recent_spam](#sorbs_recent_spam)|32328|32328,33461|88|0.2%|4.1%|
[sorbs_new_spam](#sorbs_new_spam)|32328|32328,33461|88|0.2%|4.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|58|0.0%|2.7%|
[snort_ipfilter](#snort_ipfilter)|9943|9943|46|0.4%|2.1%|
[blocklist_de_mail](#blocklist_de_mail)|16943|16943|38|0.2%|1.8%|
[php_dictionary](#php_dictionary)|545|545|33|6.0%|1.5%|
[nixspam](#nixspam)|19587|19587|27|0.1%|1.2%|
[php_spammers](#php_spammers)|536|536|26|4.8%|1.2%|
[sorbs_web](#sorbs_web)|709|709,710|17|2.3%|0.8%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|13|1.9%|0.6%|
[php_commenters](#php_commenters)|349|349|8|2.2%|0.3%|
[blocklist_de_strongips](#blocklist_de_strongips)|179|179|7|3.9%|0.3%|
[alienvault_reputation](#alienvault_reputation)|177556|177556|4|0.0%|0.1%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|3|0.0%|0.1%|
[php_harvesters](#php_harvesters)|324|324|2|0.6%|0.0%|
[et_tor](#et_tor)|6470|6470|2|0.0%|0.0%|
[dm_tor](#dm_tor)|6497|6497|2|0.0%|0.0%|
[bm_tor](#bm_tor)|6501|6501|2|0.0%|0.0%|
[sorbs_socks](#sorbs_socks)|22|22,22|1|4.5%|0.0%|
[sorbs_misc](#sorbs_misc)|22|22,22|1|4.5%|0.0%|
[sorbs_http](#sorbs_http)|22|22,22|1|4.5%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.0%|
[et_compromised](#et_compromised)|2016|2016|1|0.0%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|230|230|1|0.4%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1801|1801|1|0.0%|0.0%|

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
[alienvault_reputation](#alienvault_reputation)|177556|177556|63|0.0%|27.1%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|16|0.0%|6.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|14|0.0%|6.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|10|0.0%|4.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|9|0.0%|3.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|6|0.0%|2.5%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|5|0.0%|2.1%|
[dshield](#dshield)|20|20,5120|3|0.0%|1.2%|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|2|0.0%|0.8%|
[openbl_60d](#openbl_60d)|7286|7286|2|0.0%|0.8%|
[openbl_30d](#openbl_30d)|3257|3257|2|0.0%|0.8%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|1|0.0%|0.4%|
[stopforumspam_1d](#stopforumspam_1d)|6481|6481|1|0.0%|0.4%|
[php_commenters](#php_commenters)|349|349|1|0.2%|0.4%|
[nixspam](#nixspam)|19587|19587|1|0.0%|0.4%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.4%|

## zeus_badips

[Abuse.ch Zeus tracker](https://zeustracker.abuse.ch) badips includes IPv4 addresses that are used by the ZeuS trojan. It is the recommened blocklist if you want to block only ZeuS IPs. It excludes IP addresses that ZeuS Tracker believes to be hijacked (level 2) or belong to a free web hosting provider (level 3). Hence the false postive rate should be much lower compared to the standard ZeuS IP blocklist. **excellent list**

Source is downloaded from [this link](https://zeustracker.abuse.ch/blocklist.php?download=badips).

The last time downloaded was found to be dated: Sat Jun  6 21:54:16 UTC 2015.

The ipset `zeus_badips` has **202** entries, **202** unique IPs.

The following table shows the overlaps of `zeus_badips` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `zeus_badips`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `zeus_badips`.
- ` this % ` is the percentage **of this ipset (`zeus_badips`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[zeus](#zeus)|232|232|202|87.0%|100.0%|
[et_block](#et_block)|1023|18338662|200|0.0%|99.0%|
[snort_ipfilter](#snort_ipfilter)|9943|9943|179|1.8%|88.6%|
[alienvault_reputation](#alienvault_reputation)|177556|177556|38|0.0%|18.8%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|16|0.0%|7.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|10|0.0%|4.9%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|10|0.0%|4.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|8|0.0%|3.9%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|5|0.0%|2.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|4|0.0%|1.9%|
[dshield](#dshield)|20|20,5120|3|0.0%|1.4%|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|2|0.0%|0.9%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|1|0.0%|0.4%|
[stopforumspam_1d](#stopforumspam_1d)|6481|6481|1|0.0%|0.4%|
[php_commenters](#php_commenters)|349|349|1|0.2%|0.4%|
[openbl_60d](#openbl_60d)|7286|7286|1|0.0%|0.4%|
[openbl_30d](#openbl_30d)|3257|3257|1|0.0%|0.4%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.4%|
