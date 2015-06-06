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

The following list was automatically generated on Sat Jun  6 14:28:07 UTC 2015.

The update frequency is the maximum allowed by internal configuration. A list will never be downloaded sooner than the update frequency stated. A list may also not be downloaded, after this frequency expired, if it has not been modified on the server (as reported by HTTP `IF_MODIFIED_SINCE` method).

name|info|type|entries|update|
:--:|:--:|:--:|:-----:|:----:|
[alienvault_reputation](#alienvault_reputation)|[AlienVault.com](https://www.alienvault.com/) IP reputation database (this list seems to include port scanning hosts and to be updated regularly, but we found no information about its retention policy)|ipv4 hash:ip|180710 unique IPs|updated every 6 hours  from [this link](https://reputation.alienvault.com/reputation.generic)
[blocklist_de](#blocklist_de)|[Blocklist.de](https://www.blocklist.de/) IPs that have been detected by fail2ban in the last 48 hours - **excellent list**|ipv4 hash:ip|26186 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/all.txt)
[blocklist_de_apache](#blocklist_de_apache)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service Apache, Apache-DDOS, RFI-Attacks.|ipv4 hash:ip|15231 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/apache.txt)
[blocklist_de_bots](#blocklist_de_bots)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the RFI-Attacks, REG-Bots, IRC-Bots or BadBots (BadBots = he has posted a Spam-Comment on a open Forum or Wiki).|ipv4 hash:ip|3020 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/bots.txt)
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|[Blocklist.de](https://www.blocklist.de/) All IPs which attacks Joomlas, Wordpress and other Web-Logins with Brute-Force Logins.|ipv4 hash:ip|3873 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/bruteforcelogin.txt)
[blocklist_de_ftp](#blocklist_de_ftp)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours for attacks on the Service FTP.|ipv4 hash:ip|867 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/ftp.txt)
[blocklist_de_imap](#blocklist_de_imap)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours for attacks on the Service imap, sasl, pop3, etc.|ipv4 hash:ip|1555 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/imap.txt)
[blocklist_de_mail](#blocklist_de_mail)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service Mail, Postfix.|ipv4 hash:ip|16382 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/mail.txt)
[blocklist_de_sip](#blocklist_de_sip)|[Blocklist.de](https://www.blocklist.de/) All IP addresses that tried to login in a SIP, VOIP or Asterisk Server and are included in the IPs list from [infiltrated.net](www.infiltrated.net)|ipv4 hash:ip|90 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/sip.txt)
[blocklist_de_ssh](#blocklist_de_ssh)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service SSH.|ipv4 hash:ip|1675 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/ssh.txt)
[blocklist_de_strongips](#blocklist_de_strongips)|[Blocklist.de](https://www.blocklist.de/) All IPs which are older then 2 month and have more then 5.000 attacks.|ipv4 hash:ip|180 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/strongips.txt)
[bm_tor](#bm_tor)|[torstatus.blutmagie.de](https://torstatus.blutmagie.de) list of all TOR network servers|ipv4 hash:ip|6525 unique IPs|updated every 30 mins  from [this link](https://torstatus.blutmagie.de/ip_list_all.php/Tor_ip_list_ALL.csv)
[bogons](#bogons)|[Team-Cymru.org](http://www.team-cymru.org) private and reserved addresses defined by RFC 1918, RFC 5735, and RFC 6598 and netblocks that have not been allocated to a regional internet registry - **excellent list - use it only your internet interface**|ipv4 hash:net|13 subnets, 592708608 unique IPs|updated every 1 day  from [this link](http://www.team-cymru.org/Services/Bogons/bogon-bn-agg.txt)
[bruteforceblocker](#bruteforceblocker)|[danger.rulez.sk](http://danger.rulez.sk/) IPs detected by [bruteforceblocker](http://danger.rulez.sk/index.php/bruteforceblocker/) (fail2ban alternative for SSH on OpenBSD). This is an automatically generated list from users reporting failed authentication attempts. An IP seems to be included if 3 or more users report it. Its retention pocily seems 30 days.|ipv4 hash:ip|1870 unique IPs|updated every 3 hours  from [this link](http://danger.rulez.sk/projects/bruteforceblocker/blist.php)
[ciarmy](#ciarmy)|[CIArmy.com](http://ciarmy.com/) IPs with poor Rogue Packet score that have not yet been identified as malicious by the community|ipv4 hash:ip|408 unique IPs|updated every 3 hours  from [this link](http://cinsscore.com/list/ci-badguys.txt)
[cleanmx_viruses](#cleanmx_viruses)|[Clean-MX.de](http://support.clean-mx.de/clean-mx/viruses.php) IPs with viruses|ipv4 hash:ip|168 unique IPs|updated every 12 hours  from [this link](http://support.clean-mx.de/clean-mx/xmlviruses.php?sort=id%20desc&response=alive)
[dm_tor](#dm_tor)|[dan.me.uk](https://www.dan.me.uk) dynamic list of TOR exit points|ipv4 hash:ip|6521 unique IPs|updated every 30 mins  from [this link](https://www.dan.me.uk/torlist/)
[dshield](#dshield)|[DShield.org](https://dshield.org/) top 20 attacking class C (/24) subnets over the last three days - **excellent list**|ipv4 hash:net|20 subnets, 5120 unique IPs|updated every 4 hours  from [this link](http://feeds.dshield.org/block.txt)
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
[nixspam](#nixspam)|[NiX Spam](http://www.heise.de/ix/NiX-Spam-DNSBL-and-blacklist-for-download-499637.html) IP addresses that sent spam in the last hour - automatically generated entries without distinguishing open proxies from relays, dialup gateways, and so on. All IPs are removed after 12 hours if there is no spam from there.|ipv4 hash:ip|17534 unique IPs|updated every 15 mins  from [this link](http://www.dnsbl.manitu.net/download/nixspam-ip.dump.gz)
openbl|[OpenBL.org](http://www.openbl.org/) default blacklist (currently it is the same with 90 days). OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications - **excellent list**|ipv4 hash:ip|disabled|updated every 4 hours  from [this link](http://www.openbl.org/lists/base.txt)
openbl_180d|[OpenBL.org](http://www.openbl.org/) last 180 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|disabled|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_180days.txt)
[openbl_1d](#openbl_1d)|[OpenBL.org](http://www.openbl.org/) last 24 hours IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|140 unique IPs|updated every 1 hour  from [this link](http://www.openbl.org/lists/base_1days.txt)
[openbl_30d](#openbl_30d)|[OpenBL.org](http://www.openbl.org/) last 30 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|3251 unique IPs|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_30days.txt)
openbl_360d|[OpenBL.org](http://www.openbl.org/) last 360 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|disabled|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_360days.txt)
[openbl_60d](#openbl_60d)|[OpenBL.org](http://www.openbl.org/) last 60 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|7563 unique IPs|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_60days.txt)
[openbl_7d](#openbl_7d)|[OpenBL.org](http://www.openbl.org/) last 7 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|856 unique IPs|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_7days.txt)
openbl_90d|[OpenBL.org](http://www.openbl.org/) last 90 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|disabled|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_90days.txt)
openbl_all|[OpenBL.org](http://www.openbl.org/) last all IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|disabled|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_all.txt)
[palevo](#palevo)|[Abuse.ch Palevo tracker](https://palevotracker.abuse.ch) worm includes IPs which are being used as botnet C&C for the Palevo crimeware - **excellent list**|ipv4 hash:ip|13 unique IPs|updated every 30 mins  from [this link](https://palevotracker.abuse.ch/blocklists.php?download=ipblocklist)
php_bad|[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) bad web hosts (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|disabled|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=b&rss=1)
[php_commenters](#php_commenters)|[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) comment spammers (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|326 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=c&rss=1)
[php_dictionary](#php_dictionary)|[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) directory attackers (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|545 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=d&rss=1)
[php_harvesters](#php_harvesters)|[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) harvesters (IPs that surf the internet looking for email addresses) (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|311 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=h&rss=1)
[php_spammers](#php_spammers)|[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) spam servers (IPs used by spammers to send messages) (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|536 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=s&rss=1)
[proxyrss](#proxyrss)|[proxyrss.com](http://www.proxyrss.com) open proxies syndicated from multiple sources.|ipv4 hash:ip|1524 unique IPs|updated every 4 hours  from [this link](http://www.proxyrss.com/proxylists/all.gz)
[proxz](#proxz)|[proxz.com](http://www.proxz.com) open proxies (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|886 unique IPs|updated every 1 hour  from [this link](http://www.proxz.com/proxylists.xml)
[ri_connect_proxies](#ri_connect_proxies)|[rosinstrument.com](http://www.rosinstrument.com) open CONNECT proxies (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|2461 unique IPs|updated every 1 hour  from [this link](http://tools.rosinstrument.com/proxy/plab100.xml)
[ri_web_proxies](#ri_web_proxies)|[rosinstrument.com](http://www.rosinstrument.com) open HTTP proxies (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|6611 unique IPs|updated every 1 hour  from [this link](http://tools.rosinstrument.com/proxy/l100.xml)
[shunlist](#shunlist)|[AutoShun.org](http://autoshun.org/) IPs identified as hostile by correlating logs from distributed snort installations running the autoshun plugin|ipv4 hash:ip|1259 unique IPs|updated every 4 hours  from [this link](http://www.autoshun.org/files/shunlist.csv)
[snort_ipfilter](#snort_ipfilter)|[labs.snort.org](https://labs.snort.org/) supplied IP blacklist (this list seems to be updated frequently, but we found no information about it)|ipv4 hash:ip|9943 unique IPs|updated every 12 hours  from [this link](http://labs.snort.org/feeds/ip-filter.blf)
[sorbs_dul](#sorbs_dul)|[Sorbs.net](https://www.sorbs.net/) DUL, Dynamic User IPs extracted from deltas.|ipv4 hash:net|8 subnets, 3584 unique IPs|updated every 1 min  from [this link]()
[sorbs_http](#sorbs_http)|[Sorbs.net](https://www.sorbs.net/) HTTP proxies, extracted from deltas.|ipv4 hash:net|20 subnets, 20,20 unique IPs|updated every 1 min  from [this link]()
[sorbs_misc](#sorbs_misc)|[Sorbs.net](https://www.sorbs.net/) MISC proxies, extracted from deltas.|ipv4 hash:net|20 subnets, 20,20 unique IPs|updated every 1 min  from [this link]()
[sorbs_new_spam](#sorbs_new_spam)|[Sorbs.net](https://www.sorbs.net/) NEW Spam senders, extracted from deltas.|ipv4 hash:net|30553 subnets, 30553,31638 unique IPs|updated every 1 min  from [this link]()
[sorbs_recent_spam](#sorbs_recent_spam)|[Sorbs.net](https://www.sorbs.net/) RECENT Spam senders, extracted from deltas.|ipv4 hash:net|30553 subnets, 30553,31638 unique IPs|updated every 1 min  from [this link]()
[sorbs_smtp](#sorbs_smtp)|[Sorbs.net](https://www.sorbs.net/) SMTP Open Relays, extracted from deltas.|ipv4 hash:net|14 subnets, 14,14 unique IPs|updated every 1 min  from [this link]()
[sorbs_socks](#sorbs_socks)|[Sorbs.net](https://www.sorbs.net/) SOCKS proxies, extracted from deltas.|ipv4 hash:net|20 subnets, 20,20 unique IPs|updated every 1 min  from [this link]()
[sorbs_spam](#sorbs_spam)|[Sorbs.net](https://www.sorbs.net/) Spam senders, extracted from deltas.|ipv4 hash:net|30553 subnets, 30553,31638 unique IPs|updated every 1 min  from [this link]()
[sorbs_web](#sorbs_web)|[Sorbs.net](https://www.sorbs.net/) WEB exploits, extracted from deltas.|ipv4 hash:net|667 subnets, 667,668 unique IPs|updated every 1 min  from [this link]()
[spamhaus_drop](#spamhaus_drop)|[Spamhaus.org](http://www.spamhaus.org) DROP list (according to their site this list should be dropped at tier-1 ISPs globaly) - **excellent list**|ipv4 hash:net|653 subnets, 18404096 unique IPs|updated every 12 hours  from [this link](http://www.spamhaus.org/drop/drop.txt)
[spamhaus_edrop](#spamhaus_edrop)|[Spamhaus.org](http://www.spamhaus.org) EDROP (extended matches that should be used with DROP) - **excellent list**|ipv4 hash:net|56 subnets, 487424 unique IPs|updated every 12 hours  from [this link](http://www.spamhaus.org/drop/edrop.txt)
[sslbl](#sslbl)|[Abuse.ch SSL Blacklist](https://sslbl.abuse.ch/) bad SSL traffic related to malware or botnet activities - **excellent list**|ipv4 hash:ip|369 unique IPs|updated every 30 mins  from [this link](https://sslbl.abuse.ch/blacklist/sslipblacklist.csv)
stopforumspam_180d|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 180 days)|ipv4 hash:ip|disabled|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/listed_ip_180.zip)
[stopforumspam_1d](#stopforumspam_1d)|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers in the last 24 hours - **excellent list**|ipv4 hash:ip|6922 unique IPs|updated every 1 hour  from [this link](http://www.stopforumspam.com/downloads/listed_ip_1.zip)
[stopforumspam_30d](#stopforumspam_30d)|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 30 days)|ipv4 hash:ip|93258 unique IPs|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/listed_ip_30.zip)
stopforumspam_365d|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 365 days)|ipv4 hash:ip|disabled|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/listed_ip_365.zip)
[stopforumspam_7d](#stopforumspam_7d)|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 7 days)|ipv4 hash:ip|30121 unique IPs|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/listed_ip_7.zip)
stopforumspam_90d|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 90 days)|ipv4 hash:ip|disabled|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/listed_ip_90.zip)
stopforumspam_ever|[StopForumSpam.com](http://www.stopforumspam.com) all IPs used by forum spammers, **ever** (normally you don't want to use this ipset, use the hourly one which includes last 24 hours IPs or the 7 days one)|ipv4 hash:ip|disabled|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/bannedips.zip)
[virbl](#virbl)|[VirBL](http://virbl.bit.nl/) is a project of which the idea was born during the RIPE-48 meeting. The plan was to get reports of virusscanning mailservers, and put the IP-addresses that were reported to send viruses on a blacklist.|ipv4 hash:ip|4 unique IPs|updated every 1 hour  from [this link](http://virbl.bit.nl/download/virbl.dnsbl.bit.nl.txt)
[voipbl](#voipbl)|[VoIPBL.org](http://www.voipbl.org/) a distributed VoIP blacklist that is aimed to protects against VoIP Fraud and minimizing abuse for network that have publicly accessible PBX's. Several algorithms, external sources and manual confirmation are used before they categorize something as an attack and determine the threat level.|ipv4 hash:net|10452 subnets, 10864 unique IPs|updated every 4 hours  from [this link](http://www.voipbl.org/update/)
[xroxy](#xroxy)|[xroxy.com](http://www.xroxy.com) open proxies (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|2099 unique IPs|updated every 1 hour  from [this link](http://www.xroxy.com/proxyrss.xml)
[zeus](#zeus)|[Abuse.ch Zeus tracker](https://zeustracker.abuse.ch) standard, contains the same data as the ZeuS IP blocklist (zeus_badips) but with the slight difference that it doesn't exclude hijacked websites (level 2) and free web hosting providers (level 3). This means that this blocklist contains all IPv4 addresses associated with ZeuS C&Cs which are currently being tracked by ZeuS Tracker. Hence this blocklist will likely cause some false positives. - **excellent list**|ipv4 hash:ip|231 unique IPs|updated every 30 mins  from [this link](https://zeustracker.abuse.ch/blocklist.php?download=ipblocklist)
[zeus_badips](#zeus_badips)|[Abuse.ch Zeus tracker](https://zeustracker.abuse.ch) badips includes IPv4 addresses that are used by the ZeuS trojan. It is the recommened blocklist if you want to block only ZeuS IPs. It excludes IP addresses that ZeuS Tracker believes to be hijacked (level 2) or belong to a free web hosting provider (level 3). Hence the false postive rate should be much lower compared to the standard ZeuS IP blocklist. **excellent list**|ipv4 hash:ip|202 unique IPs|updated every 30 mins  from [this link](https://zeustracker.abuse.ch/blocklist.php?download=badips)

# Comparison of ipsets

Below we compare each ipset against all other.


## alienvault_reputation

[AlienVault.com](https://www.alienvault.com/) IP reputation database (this list seems to include port scanning hosts and to be updated regularly, but we found no information about its retention policy)

Source is downloaded from [this link](https://reputation.alienvault.com/reputation.generic).

The last time downloaded was found to be dated: Sat Jun  6 10:00:33 UTC 2015.

The ipset `alienvault_reputation` has **180710** entries, **180710** unique IPs.

The following table shows the overlaps of `alienvault_reputation` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `alienvault_reputation`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `alienvault_reputation`.
- ` this % ` is the percentage **of this ipset (`alienvault_reputation`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|14152|0.0%|7.8%|
[openbl_60d](#openbl_60d)|7563|7563|7538|99.6%|4.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|7538|0.0%|4.1%|
[et_block](#et_block)|1023|18338662|5280|0.0%|2.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|4735|0.0%|2.6%|
[dshield](#dshield)|20|5120|4355|85.0%|2.4%|
[openbl_30d](#openbl_30d)|3251|3251|3231|99.3%|1.7%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|1631|0.0%|0.9%|
[et_compromised](#et_compromised)|2016|2016|1312|65.0%|0.7%|
[shunlist](#shunlist)|1259|1259|1251|99.3%|0.6%|
[bruteforceblocker](#bruteforceblocker)|1870|1870|1210|64.7%|0.6%|
[blocklist_de](#blocklist_de)|26186|26186|1013|3.8%|0.5%|
[openbl_7d](#openbl_7d)|856|856|846|98.8%|0.4%|
[blocklist_de_ssh](#blocklist_de_ssh)|1675|1675|770|45.9%|0.4%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|518|0.0%|0.2%|
[ciarmy](#ciarmy)|408|408|398|97.5%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|287|0.0%|0.1%|
[voipbl](#voipbl)|10452|10864|209|1.9%|0.1%|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|205|0.2%|0.1%|
[blocklist_de_apache](#blocklist_de_apache)|15231|15231|140|0.9%|0.0%|
[openbl_1d](#openbl_1d)|140|140|132|94.2%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9943|9943|118|1.1%|0.0%|
[sorbs_spam](#sorbs_spam)|30553|30553,31638|97|0.3%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|30553|30553,31638|97|0.3%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|30553|30553,31638|97|0.3%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|94|0.3%|0.0%|
[sslbl](#sslbl)|369|369|65|17.6%|0.0%|
[zeus](#zeus)|231|231|62|26.8%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|16382|16382|60|0.3%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6922|6922|53|0.7%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|1555|1555|46|2.9%|0.0%|
[et_tor](#et_tor)|6470|6470|42|0.6%|0.0%|
[dm_tor](#dm_tor)|6521|6521|42|0.6%|0.0%|
[bm_tor](#bm_tor)|6525|6525|42|0.6%|0.0%|
[zeus_badips](#zeus_badips)|202|202|38|18.8%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|180|180|37|20.5%|0.0%|
[nixspam](#nixspam)|17534|17534|34|0.1%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3020|3020|30|0.9%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|26|6.9%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|3873|3873|21|0.5%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|90|90|16|17.7%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|15|0.0%|0.0%|
[php_commenters](#php_commenters)|326|326|15|4.6%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|15|0.0%|0.0%|
[malc0de](#malc0de)|361|361|11|3.0%|0.0%|
[php_harvesters](#php_harvesters)|311|311|10|3.2%|0.0%|
[php_dictionary](#php_dictionary)|545|545|8|1.4%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|8|0.5%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|168|168|7|4.1%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|867|867|7|0.8%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|6|0.4%|0.0%|
[php_spammers](#php_spammers)|536|536|5|0.9%|0.0%|
[et_botcc](#et_botcc)|509|509|5|0.9%|0.0%|
[xroxy](#xroxy)|2099|2099|4|0.1%|0.0%|
[ri_web_proxies](#ri_web_proxies)|6611|6611|3|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2461|2461|3|0.1%|0.0%|
[proxz](#proxz)|886|886|3|0.3%|0.0%|
[feodo](#feodo)|99|99|2|2.0%|0.0%|
[sorbs_web](#sorbs_web)|667|667,668|1|0.1%|0.0%|
[proxyrss](#proxyrss)|1524|1524|1|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|1|0.1%|0.0%|

## blocklist_de

[Blocklist.de](https://www.blocklist.de/) IPs that have been detected by fail2ban in the last 48 hours - **excellent list**

Source is downloaded from [this link](http://lists.blocklist.de/lists/all.txt).

The last time downloaded was found to be dated: Sat Jun  6 14:14:03 UTC 2015.

The ipset `blocklist_de` has **26186** entries, **26186** unique IPs.

The following table shows the overlaps of `blocklist_de` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de`.
- ` this % ` is the percentage **of this ipset (`blocklist_de`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de_mail](#blocklist_de_mail)|16382|16382|16382|100.0%|62.5%|
[blocklist_de_apache](#blocklist_de_apache)|15231|15231|15231|100.0%|58.1%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|3873|3873|3872|99.9%|14.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|3352|0.0%|12.8%|
[blocklist_de_bots](#blocklist_de_bots)|3020|3020|3013|99.7%|11.5%|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|2328|2.4%|8.8%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|2004|6.6%|7.6%|
[blocklist_de_ssh](#blocklist_de_ssh)|1675|1675|1675|100.0%|6.3%|
[blocklist_de_imap](#blocklist_de_imap)|1555|1555|1555|100.0%|5.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|1499|0.0%|5.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|1423|0.0%|5.4%|
[stopforumspam_1d](#stopforumspam_1d)|6922|6922|1259|18.1%|4.8%|
[sorbs_spam](#sorbs_spam)|30553|30553,31638|1037|3.2%|3.9%|
[sorbs_recent_spam](#sorbs_recent_spam)|30553|30553,31638|1037|3.2%|3.9%|
[sorbs_new_spam](#sorbs_new_spam)|30553|30553,31638|1037|3.2%|3.9%|
[alienvault_reputation](#alienvault_reputation)|180710|180710|1013|0.5%|3.8%|
[blocklist_de_ftp](#blocklist_de_ftp)|867|867|864|99.6%|3.2%|
[openbl_60d](#openbl_60d)|7563|7563|748|9.8%|2.8%|
[openbl_30d](#openbl_30d)|3251|3251|692|21.2%|2.6%|
[bruteforceblocker](#bruteforceblocker)|1870|1870|631|33.7%|2.4%|
[et_compromised](#et_compromised)|2016|2016|629|31.2%|2.4%|
[openbl_7d](#openbl_7d)|856|856|426|49.7%|1.6%|
[nixspam](#nixspam)|17534|17534|380|2.1%|1.4%|
[ri_web_proxies](#ri_web_proxies)|6611|6611|379|5.7%|1.4%|
[shunlist](#shunlist)|1259|1259|366|29.0%|1.3%|
[xroxy](#xroxy)|2099|2099|230|10.9%|0.8%|
[proxyrss](#proxyrss)|1524|1524|208|13.6%|0.7%|
[et_block](#et_block)|1023|18338662|192|0.0%|0.7%|
[blocklist_de_strongips](#blocklist_de_strongips)|180|180|180|100.0%|0.6%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|179|0.0%|0.6%|
[snort_ipfilter](#snort_ipfilter)|9943|9943|169|1.6%|0.6%|
[proxz](#proxz)|886|886|142|16.0%|0.5%|
[openbl_1d](#openbl_1d)|140|140|120|85.7%|0.4%|
[php_spammers](#php_spammers)|536|536|94|17.5%|0.3%|
[php_dictionary](#php_dictionary)|545|545|88|16.1%|0.3%|
[sorbs_web](#sorbs_web)|667|667,668|74|11.0%|0.2%|
[php_commenters](#php_commenters)|326|326|74|22.6%|0.2%|
[blocklist_de_sip](#blocklist_de_sip)|90|90|71|78.8%|0.2%|
[ri_connect_proxies](#ri_connect_proxies)|2461|2461|67|2.7%|0.2%|
[dshield](#dshield)|20|5120|63|1.2%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|52|0.0%|0.1%|
[ciarmy](#ciarmy)|408|408|37|9.0%|0.1%|
[voipbl](#voipbl)|10452|10864|32|0.2%|0.1%|
[php_harvesters](#php_harvesters)|311|311|31|9.9%|0.1%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|13|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|11|0.0%|0.0%|
[sorbs_socks](#sorbs_socks)|20|20,20|5|25.0%|0.0%|
[sorbs_misc](#sorbs_misc)|20|20,20|5|25.0%|0.0%|
[sorbs_http](#sorbs_http)|20|20,20|5|25.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|4|0.0%|0.0%|
[et_tor](#et_tor)|6470|6470|4|0.0%|0.0%|
[dm_tor](#dm_tor)|6521|6521|4|0.0%|0.0%|
[bm_tor](#bm_tor)|6525|6525|4|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|3|0.8%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|3|0.4%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.0%|
[sslbl](#sslbl)|369|369|1|0.2%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|168|168|1|0.5%|0.0%|

## blocklist_de_apache

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service Apache, Apache-DDOS, RFI-Attacks.

Source is downloaded from [this link](http://lists.blocklist.de/lists/apache.txt).

The last time downloaded was found to be dated: Sat Jun  6 14:14:05 UTC 2015.

The ipset `blocklist_de_apache` has **15231** entries, **15231** unique IPs.

The following table shows the overlaps of `blocklist_de_apache` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_apache`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_apache`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_apache`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|26186|26186|15231|58.1%|100.0%|
[blocklist_de_mail](#blocklist_de_mail)|16382|16382|11059|67.5%|72.6%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|3873|3873|3872|99.9%|25.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|2384|0.0%|15.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|1328|0.0%|8.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|1089|0.0%|7.1%|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|222|0.2%|1.4%|
[alienvault_reputation](#alienvault_reputation)|180710|180710|140|0.0%|0.9%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|135|0.4%|0.8%|
[sorbs_spam](#sorbs_spam)|30553|30553,31638|108|0.3%|0.7%|
[sorbs_recent_spam](#sorbs_recent_spam)|30553|30553,31638|108|0.3%|0.7%|
[sorbs_new_spam](#sorbs_new_spam)|30553|30553,31638|108|0.3%|0.7%|
[stopforumspam_1d](#stopforumspam_1d)|6922|6922|67|0.9%|0.4%|
[shunlist](#shunlist)|1259|1259|37|2.9%|0.2%|
[ciarmy](#ciarmy)|408|408|34|8.3%|0.2%|
[blocklist_de_strongips](#blocklist_de_strongips)|180|180|34|18.8%|0.2%|
[nixspam](#nixspam)|17534|17534|28|0.1%|0.1%|
[php_commenters](#php_commenters)|326|326|25|7.6%|0.1%|
[blocklist_de_bots](#blocklist_de_bots)|3020|3020|23|0.7%|0.1%|
[dshield](#dshield)|20|5120|13|0.2%|0.0%|
[et_block](#et_block)|1023|18338662|12|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9943|9943|9|0.0%|0.0%|
[openbl_60d](#openbl_60d)|7563|7563|8|0.1%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|7|0.0%|0.0%|
[php_spammers](#php_spammers)|536|536|6|1.1%|0.0%|
[openbl_30d](#openbl_30d)|3251|3251|6|0.1%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|5|0.0%|0.0%|
[php_harvesters](#php_harvesters)|311|311|5|1.6%|0.0%|
[php_dictionary](#php_dictionary)|545|545|4|0.7%|0.0%|
[et_tor](#et_tor)|6470|6470|4|0.0%|0.0%|
[dm_tor](#dm_tor)|6521|6521|4|0.0%|0.0%|
[bm_tor](#bm_tor)|6525|6525|4|0.0%|0.0%|
[voipbl](#voipbl)|10452|10864|3|0.0%|0.0%|
[sorbs_web](#sorbs_web)|667|667,668|3|0.4%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|3|0.0%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|0.0%|
[openbl_7d](#openbl_7d)|856|856|2|0.2%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|2|0.5%|0.0%|
[et_compromised](#et_compromised)|2016|2016|2|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1870|1870|2|0.1%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|1|0.0%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|168|168|1|0.5%|0.0%|

## blocklist_de_bots

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the RFI-Attacks, REG-Bots, IRC-Bots or BadBots (BadBots = he has posted a Spam-Comment on a open Forum or Wiki).

Source is downloaded from [this link](http://lists.blocklist.de/lists/bots.txt).

The last time downloaded was found to be dated: Sat Jun  6 13:56:09 UTC 2015.

The ipset `blocklist_de_bots` has **3020** entries, **3020** unique IPs.

The following table shows the overlaps of `blocklist_de_bots` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_bots`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_bots`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_bots`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|26186|26186|3013|11.5%|99.7%|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|1999|2.1%|66.1%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|1827|6.0%|60.4%|
[stopforumspam_1d](#stopforumspam_1d)|6922|6922|1196|17.2%|39.6%|
[ri_web_proxies](#ri_web_proxies)|6611|6611|322|4.8%|10.6%|
[proxyrss](#proxyrss)|1524|1524|207|13.5%|6.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|192|0.0%|6.3%|
[xroxy](#xroxy)|2099|2099|188|8.9%|6.2%|
[blocklist_de_strongips](#blocklist_de_strongips)|180|180|133|73.8%|4.4%|
[proxz](#proxz)|886|886|120|13.5%|3.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|116|0.0%|3.8%|
[ri_connect_proxies](#ri_connect_proxies)|2461|2461|64|2.6%|2.1%|
[php_commenters](#php_commenters)|326|326|60|18.4%|1.9%|
[sorbs_spam](#sorbs_spam)|30553|30553,31638|48|0.1%|1.5%|
[sorbs_recent_spam](#sorbs_recent_spam)|30553|30553,31638|48|0.1%|1.5%|
[sorbs_new_spam](#sorbs_new_spam)|30553|30553,31638|48|0.1%|1.5%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|42|0.0%|1.3%|
[et_block](#et_block)|1023|18338662|42|0.0%|1.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|36|0.0%|1.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|32|0.0%|1.0%|
[alienvault_reputation](#alienvault_reputation)|180710|180710|30|0.0%|0.9%|
[php_spammers](#php_spammers)|536|536|26|4.8%|0.8%|
[snort_ipfilter](#snort_ipfilter)|9943|9943|24|0.2%|0.7%|
[nixspam](#nixspam)|17534|17534|24|0.1%|0.7%|
[php_harvesters](#php_harvesters)|311|311|23|7.3%|0.7%|
[blocklist_de_mail](#blocklist_de_mail)|16382|16382|23|0.1%|0.7%|
[blocklist_de_apache](#blocklist_de_apache)|15231|15231|23|0.1%|0.7%|
[php_dictionary](#php_dictionary)|545|545|21|3.8%|0.6%|
[sorbs_web](#sorbs_web)|667|667,668|15|2.2%|0.4%|
[openbl_60d](#openbl_60d)|7563|7563|10|0.1%|0.3%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|5|0.0%|0.1%|
[voipbl](#voipbl)|10452|10864|4|0.0%|0.1%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|3|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|3|0.4%|0.0%|
[openbl_30d](#openbl_30d)|3251|3251|2|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|2|0.0%|0.0%|
[et_compromised](#et_compromised)|2016|2016|2|0.0%|0.0%|
[dshield](#dshield)|20|5120|2|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1870|1870|2|0.1%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|

## blocklist_de_bruteforce

[Blocklist.de](https://www.blocklist.de/) All IPs which attacks Joomlas, Wordpress and other Web-Logins with Brute-Force Logins.

Source is downloaded from [this link](http://lists.blocklist.de/lists/bruteforcelogin.txt).

The last time downloaded was found to be dated: Sat Jun  6 13:56:11 UTC 2015.

The ipset `blocklist_de_bruteforce` has **3873** entries, **3873** unique IPs.

The following table shows the overlaps of `blocklist_de_bruteforce` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_bruteforce`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_bruteforce`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_bruteforce`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de_apache](#blocklist_de_apache)|15231|15231|3872|25.4%|99.9%|
[blocklist_de](#blocklist_de)|26186|26186|3872|14.7%|99.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|284|0.0%|7.3%|
[sorbs_spam](#sorbs_spam)|30553|30553,31638|108|0.3%|2.7%|
[sorbs_recent_spam](#sorbs_recent_spam)|30553|30553,31638|108|0.3%|2.7%|
[sorbs_new_spam](#sorbs_new_spam)|30553|30553,31638|108|0.3%|2.7%|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|59|0.0%|1.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|57|0.0%|1.4%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|38|0.1%|0.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|36|0.0%|0.9%|
[nixspam](#nixspam)|17534|17534|27|0.1%|0.6%|
[alienvault_reputation](#alienvault_reputation)|180710|180710|21|0.0%|0.5%|
[stopforumspam_1d](#stopforumspam_1d)|6922|6922|19|0.2%|0.4%|
[blocklist_de_strongips](#blocklist_de_strongips)|180|180|8|4.4%|0.2%|
[php_commenters](#php_commenters)|326|326|7|2.1%|0.1%|
[php_spammers](#php_spammers)|536|536|6|1.1%|0.1%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|6|0.0%|0.1%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|5|0.0%|0.1%|
[snort_ipfilter](#snort_ipfilter)|9943|9943|5|0.0%|0.1%|
[php_dictionary](#php_dictionary)|545|545|4|0.7%|0.1%|
[et_block](#et_block)|1023|18338662|4|0.0%|0.1%|
[sorbs_web](#sorbs_web)|667|667,668|3|0.4%|0.0%|
[php_harvesters](#php_harvesters)|311|311|3|0.9%|0.0%|
[shunlist](#shunlist)|1259|1259|2|0.1%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|2|0.0%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2|0.0%|0.0%|
[voipbl](#voipbl)|10452|10864|1|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[dshield](#dshield)|20|5120|1|0.0%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|168|168|1|0.5%|0.0%|
[ciarmy](#ciarmy)|408|408|1|0.2%|0.0%|

## blocklist_de_ftp

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours for attacks on the Service FTP.

Source is downloaded from [this link](http://lists.blocklist.de/lists/ftp.txt).

The last time downloaded was found to be dated: Sat Jun  6 13:56:08 UTC 2015.

The ipset `blocklist_de_ftp` has **867** entries, **867** unique IPs.

The following table shows the overlaps of `blocklist_de_ftp` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_ftp`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_ftp`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_ftp`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|26186|26186|864|3.2%|99.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|73|0.0%|8.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|12|0.0%|1.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|11|0.0%|1.2%|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|10|0.0%|1.1%|
[nixspam](#nixspam)|17534|17534|9|0.0%|1.0%|
[alienvault_reputation](#alienvault_reputation)|180710|180710|7|0.0%|0.8%|
[sorbs_spam](#sorbs_spam)|30553|30553,31638|5|0.0%|0.5%|
[sorbs_recent_spam](#sorbs_recent_spam)|30553|30553,31638|5|0.0%|0.5%|
[sorbs_new_spam](#sorbs_new_spam)|30553|30553,31638|5|0.0%|0.5%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|2|0.0%|0.2%|
[php_spammers](#php_spammers)|536|536|2|0.3%|0.2%|
[php_harvesters](#php_harvesters)|311|311|2|0.6%|0.2%|
[openbl_60d](#openbl_60d)|7563|7563|2|0.0%|0.2%|
[blocklist_de_strongips](#blocklist_de_strongips)|180|180|2|1.1%|0.2%|
[php_dictionary](#php_dictionary)|545|545|1|0.1%|0.1%|
[openbl_30d](#openbl_30d)|3251|3251|1|0.0%|0.1%|
[ciarmy](#ciarmy)|408|408|1|0.2%|0.1%|

## blocklist_de_imap

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours for attacks on the Service imap, sasl, pop3, etc.

Source is downloaded from [this link](http://lists.blocklist.de/lists/imap.txt).

The last time downloaded was found to be dated: Sat Jun  6 14:14:07 UTC 2015.

The ipset `blocklist_de_imap` has **1555** entries, **1555** unique IPs.

The following table shows the overlaps of `blocklist_de_imap` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_imap`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_imap`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_imap`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de_mail](#blocklist_de_mail)|16382|16382|1555|9.4%|100.0%|
[blocklist_de](#blocklist_de)|26186|26186|1555|5.9%|100.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|138|0.0%|8.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|50|0.0%|3.2%|
[alienvault_reputation](#alienvault_reputation)|180710|180710|46|0.0%|2.9%|
[openbl_60d](#openbl_60d)|7563|7563|39|0.5%|2.5%|
[openbl_30d](#openbl_30d)|3251|3251|32|0.9%|2.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|25|0.0%|1.6%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|18|0.0%|1.1%|
[et_block](#et_block)|1023|18338662|18|0.0%|1.1%|
[openbl_7d](#openbl_7d)|856|856|13|1.5%|0.8%|
[sorbs_spam](#sorbs_spam)|30553|30553,31638|10|0.0%|0.6%|
[sorbs_recent_spam](#sorbs_recent_spam)|30553|30553,31638|10|0.0%|0.6%|
[sorbs_new_spam](#sorbs_new_spam)|30553|30553,31638|10|0.0%|0.6%|
[nixspam](#nixspam)|17534|17534|10|0.0%|0.6%|
[et_compromised](#et_compromised)|2016|2016|8|0.3%|0.5%|
[bruteforceblocker](#bruteforceblocker)|1870|1870|8|0.4%|0.5%|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|4|0.0%|0.2%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|3|0.0%|0.1%|
[snort_ipfilter](#snort_ipfilter)|9943|9943|2|0.0%|0.1%|
[shunlist](#shunlist)|1259|1259|2|0.1%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2|0.0%|0.1%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|1|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2461|2461|1|0.0%|0.0%|
[openbl_1d](#openbl_1d)|140|140|1|0.7%|0.0%|
[ciarmy](#ciarmy)|408|408|1|0.2%|0.0%|

## blocklist_de_mail

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service Mail, Postfix.

Source is downloaded from [this link](http://lists.blocklist.de/lists/mail.txt).

The last time downloaded was found to be dated: Sat Jun  6 14:14:04 UTC 2015.

The ipset `blocklist_de_mail` has **16382** entries, **16382** unique IPs.

The following table shows the overlaps of `blocklist_de_mail` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_mail`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_mail`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_mail`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|26186|26186|16382|62.5%|100.0%|
[blocklist_de_apache](#blocklist_de_apache)|15231|15231|11059|72.6%|67.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|2594|0.0%|15.8%|
[blocklist_de_imap](#blocklist_de_imap)|1555|1555|1555|100.0%|9.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|1379|0.0%|8.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|1141|0.0%|6.9%|
[sorbs_spam](#sorbs_spam)|30553|30553,31638|875|2.7%|5.3%|
[sorbs_recent_spam](#sorbs_recent_spam)|30553|30553,31638|875|2.7%|5.3%|
[sorbs_new_spam](#sorbs_new_spam)|30553|30553,31638|875|2.7%|5.3%|
[nixspam](#nixspam)|17534|17534|316|1.8%|1.9%|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|258|0.2%|1.5%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|143|0.4%|0.8%|
[snort_ipfilter](#snort_ipfilter)|9943|9943|139|1.3%|0.8%|
[php_dictionary](#php_dictionary)|545|545|62|11.3%|0.3%|
[php_spammers](#php_spammers)|536|536|60|11.1%|0.3%|
[alienvault_reputation](#alienvault_reputation)|180710|180710|60|0.0%|0.3%|
[sorbs_web](#sorbs_web)|667|667,668|56|8.3%|0.3%|
[ri_web_proxies](#ri_web_proxies)|6611|6611|56|0.8%|0.3%|
[stopforumspam_1d](#stopforumspam_1d)|6922|6922|54|0.7%|0.3%|
[openbl_60d](#openbl_60d)|7563|7563|44|0.5%|0.2%|
[xroxy](#xroxy)|2099|2099|42|2.0%|0.2%|
[openbl_30d](#openbl_30d)|3251|3251|37|1.1%|0.2%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|26|0.0%|0.1%|
[et_block](#et_block)|1023|18338662|26|0.0%|0.1%|
[blocklist_de_bots](#blocklist_de_bots)|3020|3020|23|0.7%|0.1%|
[proxz](#proxz)|886|886|22|2.4%|0.1%|
[php_commenters](#php_commenters)|326|326|21|6.4%|0.1%|
[blocklist_de_strongips](#blocklist_de_strongips)|180|180|21|11.6%|0.1%|
[openbl_7d](#openbl_7d)|856|856|13|1.5%|0.0%|
[et_compromised](#et_compromised)|2016|2016|9|0.4%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1870|1870|9|0.4%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|6|0.0%|0.0%|
[sorbs_socks](#sorbs_socks)|20|20,20|5|25.0%|0.0%|
[sorbs_misc](#sorbs_misc)|20|20,20|5|25.0%|0.0%|
[sorbs_http](#sorbs_http)|20|20,20|5|25.0%|0.0%|
[et_tor](#et_tor)|6470|6470|4|0.0%|0.0%|
[dm_tor](#dm_tor)|6521|6521|4|0.0%|0.0%|
[bm_tor](#bm_tor)|6525|6525|4|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2461|2461|3|0.1%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|3|0.0%|0.0%|
[shunlist](#shunlist)|1259|1259|2|0.1%|0.0%|
[php_harvesters](#php_harvesters)|311|311|2|0.6%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|2|0.0%|0.0%|
[voipbl](#voipbl)|10452|10864|1|0.0%|0.0%|
[openbl_1d](#openbl_1d)|140|140|1|0.7%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[dshield](#dshield)|20|5120|1|0.0%|0.0%|
[ciarmy](#ciarmy)|408|408|1|0.2%|0.0%|

## blocklist_de_sip

[Blocklist.de](https://www.blocklist.de/) All IP addresses that tried to login in a SIP, VOIP or Asterisk Server and are included in the IPs list from [infiltrated.net](www.infiltrated.net)

Source is downloaded from [this link](http://lists.blocklist.de/lists/sip.txt).

The last time downloaded was found to be dated: Sat Jun  6 13:56:08 UTC 2015.

The ipset `blocklist_de_sip` has **90** entries, **90** unique IPs.

The following table shows the overlaps of `blocklist_de_sip` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_sip`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_sip`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_sip`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|26186|26186|71|0.2%|78.8%|
[voipbl](#voipbl)|10452|10864|24|0.2%|26.6%|
[alienvault_reputation](#alienvault_reputation)|180710|180710|16|0.0%|17.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|12|0.0%|13.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|7|0.0%|7.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|4|0.0%|4.4%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|2|0.0%|2.2%|
[et_block](#et_block)|1023|18338662|2|0.0%|2.2%|
[dshield](#dshield)|20|5120|2|0.0%|2.2%|
[et_botcc](#et_botcc)|509|509|1|0.1%|1.1%|

## blocklist_de_ssh

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service SSH.

Source is downloaded from [this link](http://lists.blocklist.de/lists/ssh.txt).

The last time downloaded was found to be dated: Sat Jun  6 14:10:05 UTC 2015.

The ipset `blocklist_de_ssh` has **1675** entries, **1675** unique IPs.

The following table shows the overlaps of `blocklist_de_ssh` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_ssh`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_ssh`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_ssh`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|26186|26186|1675|6.3%|100.0%|
[alienvault_reputation](#alienvault_reputation)|180710|180710|770|0.4%|45.9%|
[openbl_60d](#openbl_60d)|7563|7563|682|9.0%|40.7%|
[openbl_30d](#openbl_30d)|3251|3251|644|19.8%|38.4%|
[bruteforceblocker](#bruteforceblocker)|1870|1870|617|32.9%|36.8%|
[et_compromised](#et_compromised)|2016|2016|615|30.5%|36.7%|
[openbl_7d](#openbl_7d)|856|856|410|47.8%|24.4%|
[shunlist](#shunlist)|1259|1259|327|25.9%|19.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|169|0.0%|10.0%|
[openbl_1d](#openbl_1d)|140|140|119|85.0%|7.1%|
[et_block](#et_block)|1023|18338662|109|0.0%|6.5%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|105|0.0%|6.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|83|0.0%|4.9%|
[dshield](#dshield)|20|5120|45|0.8%|2.6%|
[blocklist_de_strongips](#blocklist_de_strongips)|180|180|30|16.6%|1.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|26|0.0%|1.5%|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|6|0.0%|0.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|6|0.0%|0.3%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|2|0.0%|0.1%|
[nixspam](#nixspam)|17534|17534|2|0.0%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|2|0.0%|0.1%|
[sslbl](#sslbl)|369|369|1|0.2%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9943|9943|1|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1|0.0%|0.0%|
[ciarmy](#ciarmy)|408|408|1|0.2%|0.0%|

## blocklist_de_strongips

[Blocklist.de](https://www.blocklist.de/) All IPs which are older then 2 month and have more then 5.000 attacks.

Source is downloaded from [this link](http://lists.blocklist.de/lists/strongips.txt).

The last time downloaded was found to be dated: Sat Jun  6 13:56:11 UTC 2015.

The ipset `blocklist_de_strongips` has **180** entries, **180** unique IPs.

The following table shows the overlaps of `blocklist_de_strongips` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_strongips`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_strongips`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_strongips`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|26186|26186|180|0.6%|100.0%|
[blocklist_de_bots](#blocklist_de_bots)|3020|3020|133|4.4%|73.8%|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|131|0.1%|72.7%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|120|0.3%|66.6%|
[stopforumspam_1d](#stopforumspam_1d)|6922|6922|106|1.5%|58.8%|
[alienvault_reputation](#alienvault_reputation)|180710|180710|37|0.0%|20.5%|
[php_commenters](#php_commenters)|326|326|34|10.4%|18.8%|
[blocklist_de_apache](#blocklist_de_apache)|15231|15231|34|0.2%|18.8%|
[blocklist_de_ssh](#blocklist_de_ssh)|1675|1675|30|1.7%|16.6%|
[openbl_60d](#openbl_60d)|7563|7563|27|0.3%|15.0%|
[openbl_30d](#openbl_30d)|3251|3251|25|0.7%|13.8%|
[openbl_7d](#openbl_7d)|856|856|24|2.8%|13.3%|
[blocklist_de_mail](#blocklist_de_mail)|16382|16382|21|0.1%|11.6%|
[shunlist](#shunlist)|1259|1259|20|1.5%|11.1%|
[openbl_1d](#openbl_1d)|140|140|20|14.2%|11.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|16|0.0%|8.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|8|0.0%|4.4%|
[et_block](#et_block)|1023|18338662|8|0.0%|4.4%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|3873|3873|8|0.2%|4.4%|
[xroxy](#xroxy)|2099|2099|7|0.3%|3.8%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|7|0.0%|3.8%|
[ri_web_proxies](#ri_web_proxies)|6611|6611|5|0.0%|2.7%|
[proxyrss](#proxyrss)|1524|1524|5|0.3%|2.7%|
[php_spammers](#php_spammers)|536|536|5|0.9%|2.7%|
[proxz](#proxz)|886|886|4|0.4%|2.2%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|3|0.0%|1.6%|
[php_dictionary](#php_dictionary)|545|545|3|0.5%|1.6%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|1.6%|
[php_harvesters](#php_harvesters)|311|311|2|0.6%|1.1%|
[blocklist_de_ftp](#blocklist_de_ftp)|867|867|2|0.2%|1.1%|
[sorbs_web](#sorbs_web)|667|667,668|1|0.1%|0.5%|
[sorbs_spam](#sorbs_spam)|30553|30553,31638|1|0.0%|0.5%|
[sorbs_recent_spam](#sorbs_recent_spam)|30553|30553,31638|1|0.0%|0.5%|
[sorbs_new_spam](#sorbs_new_spam)|30553|30553,31638|1|0.0%|0.5%|
[snort_ipfilter](#snort_ipfilter)|9943|9943|1|0.0%|0.5%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.5%|
[bruteforceblocker](#bruteforceblocker)|1870|1870|1|0.0%|0.5%|

## bm_tor

[torstatus.blutmagie.de](https://torstatus.blutmagie.de) list of all TOR network servers

Source is downloaded from [this link](https://torstatus.blutmagie.de/ip_list_all.php/Tor_ip_list_ALL.csv).

The last time downloaded was found to be dated: Sat Jun  6 14:27:06 UTC 2015.

The ipset `bm_tor` has **6525** entries, **6525** unique IPs.

The following table shows the overlaps of `bm_tor` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `bm_tor`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `bm_tor`.
- ` this % ` is the percentage **of this ipset (`bm_tor`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[dm_tor](#dm_tor)|6521|6521|6521|100.0%|99.9%|
[et_tor](#et_tor)|6470|6470|5750|88.8%|88.1%|
[snort_ipfilter](#snort_ipfilter)|9943|9943|1081|10.8%|16.5%|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|639|0.6%|9.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|631|0.0%|9.6%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|506|1.6%|7.7%|
[stopforumspam_1d](#stopforumspam_1d)|6922|6922|335|4.8%|5.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|190|0.0%|2.9%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|167|44.8%|2.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|162|0.0%|2.4%|
[alienvault_reputation](#alienvault_reputation)|180710|180710|42|0.0%|0.6%|
[php_commenters](#php_commenters)|326|326|34|10.4%|0.5%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|22|0.0%|0.3%|
[openbl_60d](#openbl_60d)|7563|7563|20|0.2%|0.3%|
[php_harvesters](#php_harvesters)|311|311|7|2.2%|0.1%|
[ri_web_proxies](#ri_web_proxies)|6611|6611|5|0.0%|0.0%|
[php_spammers](#php_spammers)|536|536|5|0.9%|0.0%|
[et_block](#et_block)|1023|18338662|5|0.0%|0.0%|
[php_dictionary](#php_dictionary)|545|545|4|0.7%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|4|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|16382|16382|4|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|15231|15231|4|0.0%|0.0%|
[blocklist_de](#blocklist_de)|26186|26186|4|0.0%|0.0%|
[voipbl](#voipbl)|10452|10864|3|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|3|0.0%|0.0%|
[xroxy](#xroxy)|2099|2099|2|0.0%|0.0%|
[sorbs_spam](#sorbs_spam)|30553|30553,31638|2|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|30553|30553,31638|2|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|30553|30553,31638|2|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|1|0.0%|0.0%|
[shunlist](#shunlist)|1259|1259|1|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2461|2461|1|0.0%|0.0%|
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
[fullbogons](#fullbogons)|3721|670267288|592708608|88.4%|100.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|4194304|3.0%|0.7%|
[voipbl](#voipbl)|10452|10864|319|2.9%|0.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|5|0.0%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|1|0.0%|0.0%|
[php_harvesters](#php_harvesters)|311|311|1|0.3%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.0%|
[ciarmy](#ciarmy)|408|408|1|0.2%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1870|1870|1|0.0%|0.0%|

## bruteforceblocker

[danger.rulez.sk](http://danger.rulez.sk/) IPs detected by [bruteforceblocker](http://danger.rulez.sk/index.php/bruteforceblocker/) (fail2ban alternative for SSH on OpenBSD). This is an automatically generated list from users reporting failed authentication attempts. An IP seems to be included if 3 or more users report it. Its retention pocily seems 30 days.

Source is downloaded from [this link](http://danger.rulez.sk/projects/bruteforceblocker/blist.php).

The last time downloaded was found to be dated: Sat Jun  6 11:36:30 UTC 2015.

The ipset `bruteforceblocker` has **1870** entries, **1870** unique IPs.

The following table shows the overlaps of `bruteforceblocker` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `bruteforceblocker`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `bruteforceblocker`.
- ` this % ` is the percentage **of this ipset (`bruteforceblocker`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[et_compromised](#et_compromised)|2016|2016|1822|90.3%|97.4%|
[alienvault_reputation](#alienvault_reputation)|180710|180710|1210|0.6%|64.7%|
[openbl_60d](#openbl_60d)|7563|7563|1116|14.7%|59.6%|
[openbl_30d](#openbl_30d)|3251|3251|1068|32.8%|57.1%|
[blocklist_de](#blocklist_de)|26186|26186|631|2.4%|33.7%|
[blocklist_de_ssh](#blocklist_de_ssh)|1675|1675|617|36.8%|32.9%|
[shunlist](#shunlist)|1259|1259|451|35.8%|24.1%|
[openbl_7d](#openbl_7d)|856|856|379|44.2%|20.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|176|0.0%|9.4%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|101|0.0%|5.4%|
[et_block](#et_block)|1023|18338662|101|0.0%|5.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|96|0.0%|5.1%|
[openbl_1d](#openbl_1d)|140|140|80|57.1%|4.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|48|0.0%|2.5%|
[dshield](#dshield)|20|5120|43|0.8%|2.2%|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|11|0.0%|0.5%|
[blocklist_de_mail](#blocklist_de_mail)|16382|16382|9|0.0%|0.4%|
[blocklist_de_imap](#blocklist_de_imap)|1555|1555|8|0.5%|0.4%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|7|0.0%|0.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|5|0.0%|0.2%|
[voipbl](#voipbl)|10452|10864|2|0.0%|0.1%|
[proxz](#proxz)|886|886|2|0.2%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|2|0.0%|0.1%|
[blocklist_de_bots](#blocklist_de_bots)|3020|3020|2|0.0%|0.1%|
[blocklist_de_apache](#blocklist_de_apache)|15231|15231|2|0.0%|0.1%|
[xroxy](#xroxy)|2099|2099|1|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|6611|6611|1|0.0%|0.0%|
[proxyrss](#proxyrss)|1524|1524|1|0.0%|0.0%|
[nixspam](#nixspam)|17534|17534|1|0.0%|0.0%|
[fullbogons](#fullbogons)|3721|670267288|1|0.0%|0.0%|
[ciarmy](#ciarmy)|408|408|1|0.2%|0.0%|
[bogons](#bogons)|13|592708608|1|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|180|180|1|0.5%|0.0%|

## ciarmy

[CIArmy.com](http://ciarmy.com/) IPs with poor Rogue Packet score that have not yet been identified as malicious by the community

Source is downloaded from [this link](http://cinsscore.com/list/ci-badguys.txt).

The last time downloaded was found to be dated: Sat Jun  6 13:15:16 UTC 2015.

The ipset `ciarmy` has **408** entries, **408** unique IPs.

The following table shows the overlaps of `ciarmy` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ciarmy`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ciarmy`.
- ` this % ` is the percentage **of this ipset (`ciarmy`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[alienvault_reputation](#alienvault_reputation)|180710|180710|398|0.2%|97.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|80|0.0%|19.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|43|0.0%|10.5%|
[blocklist_de](#blocklist_de)|26186|26186|37|0.1%|9.0%|
[blocklist_de_apache](#blocklist_de_apache)|15231|15231|34|0.2%|8.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|30|0.0%|7.3%|
[shunlist](#shunlist)|1259|1259|29|2.3%|7.1%|
[dshield](#dshield)|20|5120|8|0.1%|1.9%|
[et_block](#et_block)|1023|18338662|6|0.0%|1.4%|
[voipbl](#voipbl)|10452|10864|4|0.0%|0.9%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|1|0.0%|0.2%|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|1|0.0%|0.2%|
[stopforumspam_1d](#stopforumspam_1d)|6922|6922|1|0.0%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.2%|
[fullbogons](#fullbogons)|3721|670267288|1|0.0%|0.2%|
[et_compromised](#et_compromised)|2016|2016|1|0.0%|0.2%|
[bruteforceblocker](#bruteforceblocker)|1870|1870|1|0.0%|0.2%|
[bogons](#bogons)|13|592708608|1|0.0%|0.2%|
[blocklist_de_ssh](#blocklist_de_ssh)|1675|1675|1|0.0%|0.2%|
[blocklist_de_mail](#blocklist_de_mail)|16382|16382|1|0.0%|0.2%|
[blocklist_de_imap](#blocklist_de_imap)|1555|1555|1|0.0%|0.2%|
[blocklist_de_ftp](#blocklist_de_ftp)|867|867|1|0.1%|0.2%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|3873|3873|1|0.0%|0.2%|

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
[alienvault_reputation](#alienvault_reputation)|180710|180710|7|0.0%|4.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|3|0.0%|1.7%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|2|0.1%|1.1%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|3873|3873|1|0.0%|0.5%|
[blocklist_de_apache](#blocklist_de_apache)|15231|15231|1|0.0%|0.5%|
[blocklist_de](#blocklist_de)|26186|26186|1|0.0%|0.5%|

## dm_tor

[dan.me.uk](https://www.dan.me.uk) dynamic list of TOR exit points

Source is downloaded from [this link](https://www.dan.me.uk/torlist/).

The last time downloaded was found to be dated: Sat Jun  6 14:27:04 UTC 2015.

The ipset `dm_tor` has **6521** entries, **6521** unique IPs.

The following table shows the overlaps of `dm_tor` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `dm_tor`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `dm_tor`.
- ` this % ` is the percentage **of this ipset (`dm_tor`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[bm_tor](#bm_tor)|6525|6525|6521|99.9%|100.0%|
[et_tor](#et_tor)|6470|6470|5747|88.8%|88.1%|
[snort_ipfilter](#snort_ipfilter)|9943|9943|1080|10.8%|16.5%|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|639|0.6%|9.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|631|0.0%|9.6%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|506|1.6%|7.7%|
[stopforumspam_1d](#stopforumspam_1d)|6922|6922|335|4.8%|5.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|190|0.0%|2.9%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|167|44.8%|2.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|162|0.0%|2.4%|
[alienvault_reputation](#alienvault_reputation)|180710|180710|42|0.0%|0.6%|
[php_commenters](#php_commenters)|326|326|34|10.4%|0.5%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|22|0.0%|0.3%|
[openbl_60d](#openbl_60d)|7563|7563|20|0.2%|0.3%|
[php_harvesters](#php_harvesters)|311|311|7|2.2%|0.1%|
[ri_web_proxies](#ri_web_proxies)|6611|6611|5|0.0%|0.0%|
[php_spammers](#php_spammers)|536|536|5|0.9%|0.0%|
[et_block](#et_block)|1023|18338662|5|0.0%|0.0%|
[php_dictionary](#php_dictionary)|545|545|4|0.7%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|4|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|16382|16382|4|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|15231|15231|4|0.0%|0.0%|
[blocklist_de](#blocklist_de)|26186|26186|4|0.0%|0.0%|
[voipbl](#voipbl)|10452|10864|3|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|3|0.0%|0.0%|
[xroxy](#xroxy)|2099|2099|2|0.0%|0.0%|
[sorbs_spam](#sorbs_spam)|30553|30553,31638|2|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|30553|30553,31638|2|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|30553|30553,31638|2|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|1|0.0%|0.0%|
[shunlist](#shunlist)|1259|1259|1|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2461|2461|1|0.0%|0.0%|
[dshield](#dshield)|20|5120|1|0.0%|0.0%|

## dshield

[DShield.org](https://dshield.org/) top 20 attacking class C (/24) subnets over the last three days - **excellent list**

Source is downloaded from [this link](http://feeds.dshield.org/block.txt).

The last time downloaded was found to be dated: Sat Jun  6 11:18:02 UTC 2015.

The ipset `dshield` has **20** entries, **5120** unique IPs.

The following table shows the overlaps of `dshield` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `dshield`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `dshield`.
- ` this % ` is the percentage **of this ipset (`dshield`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[alienvault_reputation](#alienvault_reputation)|180710|180710|4355|2.4%|85.0%|
[et_block](#et_block)|1023|18338662|1280|0.0%|25.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|264|0.0%|5.1%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|256|0.0%|5.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|256|0.0%|5.0%|
[openbl_60d](#openbl_60d)|7563|7563|105|1.3%|2.0%|
[openbl_30d](#openbl_30d)|3251|3251|88|2.7%|1.7%|
[blocklist_de](#blocklist_de)|26186|26186|63|0.2%|1.2%|
[shunlist](#shunlist)|1259|1259|59|4.6%|1.1%|
[et_compromised](#et_compromised)|2016|2016|50|2.4%|0.9%|
[blocklist_de_ssh](#blocklist_de_ssh)|1675|1675|45|2.6%|0.8%|
[bruteforceblocker](#bruteforceblocker)|1870|1870|43|2.2%|0.8%|
[openbl_7d](#openbl_7d)|856|856|34|3.9%|0.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|16|0.0%|0.3%|
[blocklist_de_apache](#blocklist_de_apache)|15231|15231|13|0.0%|0.2%|
[ciarmy](#ciarmy)|408|408|8|1.9%|0.1%|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|7|0.0%|0.1%|
[openbl_1d](#openbl_1d)|140|140|7|5.0%|0.1%|
[voipbl](#voipbl)|10452|10864|6|0.0%|0.1%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|5|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6922|6922|4|0.0%|0.0%|
[sorbs_spam](#sorbs_spam)|30553|30553,31638|2|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|30553|30553,31638|2|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|30553|30553,31638|2|0.0%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|90|90|2|2.2%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3020|3020|2|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9943|9943|1|0.0%|0.0%|
[malc0de](#malc0de)|361|361|1|0.2%|0.0%|
[et_tor](#et_tor)|6470|6470|1|0.0%|0.0%|
[dm_tor](#dm_tor)|6521|6521|1|0.0%|0.0%|
[bm_tor](#bm_tor)|6525|6525|1|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|16382|16382|1|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|3873|3873|1|0.0%|0.0%|

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
[alienvault_reputation](#alienvault_reputation)|180710|180710|5280|2.9%|0.0%|
[dshield](#dshield)|20|5120|1280|25.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1040|0.3%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|1013|1.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|517|0.1%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|314|1.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9943|9943|313|3.1%|0.0%|
[openbl_60d](#openbl_60d)|7563|7563|250|3.3%|0.0%|
[zeus](#zeus)|231|231|223|96.5%|0.0%|
[zeus_badips](#zeus_badips)|202|202|200|99.0%|0.0%|
[blocklist_de](#blocklist_de)|26186|26186|192|0.7%|0.0%|
[openbl_30d](#openbl_30d)|3251|3251|166|5.1%|0.0%|
[shunlist](#shunlist)|1259|1259|111|8.8%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1675|1675|109|6.5%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1870|1870|101|5.4%|0.0%|
[et_compromised](#et_compromised)|2016|2016|100|4.9%|0.0%|
[feodo](#feodo)|99|99|94|94.9%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6922|6922|83|1.1%|0.0%|
[nixspam](#nixspam)|17534|17534|81|0.4%|0.0%|
[openbl_7d](#openbl_7d)|856|856|51|5.9%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3020|3020|42|1.3%|0.0%|
[sslbl](#sslbl)|369|369|35|9.4%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|29|2.2%|0.0%|
[php_commenters](#php_commenters)|326|326|28|8.5%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|16382|16382|26|0.1%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|1555|1555|18|1.1%|0.0%|
[voipbl](#voipbl)|10452|10864|16|0.1%|0.0%|
[palevo](#palevo)|13|13|12|92.3%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|15231|15231|12|0.0%|0.0%|
[sorbs_spam](#sorbs_spam)|30553|30553,31638|11|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|30553|30553,31638|11|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|30553|30553,31638|11|0.0%|0.0%|
[openbl_1d](#openbl_1d)|140|140|11|7.8%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|180|180|8|4.4%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|6|0.4%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|6|0.0%|0.0%|
[ciarmy](#ciarmy)|408|408|6|1.4%|0.0%|
[malc0de](#malc0de)|361|361|5|1.3%|0.0%|
[dm_tor](#dm_tor)|6521|6521|5|0.0%|0.0%|
[bm_tor](#bm_tor)|6525|6525|5|0.0%|0.0%|
[php_dictionary](#php_dictionary)|545|545|4|0.7%|0.0%|
[et_tor](#et_tor)|6470|6470|4|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|3873|3873|4|0.1%|0.0%|
[php_spammers](#php_spammers)|536|536|2|0.3%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|2|0.2%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|90|90|2|2.2%|0.0%|
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
[alienvault_reputation](#alienvault_reputation)|180710|180710|5|0.0%|0.9%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|1|0.0%|0.1%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|1|0.0%|0.1%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.1%|
[et_block](#et_block)|1023|18338662|1|0.0%|0.1%|
[blocklist_de_sip](#blocklist_de_sip)|90|90|1|1.1%|0.1%|

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
[bruteforceblocker](#bruteforceblocker)|1870|1870|1822|97.4%|90.3%|
[alienvault_reputation](#alienvault_reputation)|180710|180710|1312|0.7%|65.0%|
[openbl_60d](#openbl_60d)|7563|7563|1216|16.0%|60.3%|
[openbl_30d](#openbl_30d)|3251|3251|1150|35.3%|57.0%|
[blocklist_de](#blocklist_de)|26186|26186|629|2.4%|31.2%|
[blocklist_de_ssh](#blocklist_de_ssh)|1675|1675|615|36.7%|30.5%|
[shunlist](#shunlist)|1259|1259|460|36.5%|22.8%|
[openbl_7d](#openbl_7d)|856|856|385|44.9%|19.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|199|0.0%|9.8%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|100|0.0%|4.9%|
[et_block](#et_block)|1023|18338662|100|0.0%|4.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|97|0.0%|4.8%|
[openbl_1d](#openbl_1d)|140|140|77|55.0%|3.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|52|0.0%|2.5%|
[dshield](#dshield)|20|5120|50|0.9%|2.4%|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|11|0.0%|0.5%|
[blocklist_de_mail](#blocklist_de_mail)|16382|16382|9|0.0%|0.4%|
[blocklist_de_imap](#blocklist_de_imap)|1555|1555|8|0.5%|0.3%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|7|0.0%|0.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|5|0.0%|0.2%|
[voipbl](#voipbl)|10452|10864|2|0.0%|0.0%|
[proxz](#proxz)|886|886|2|0.2%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|2|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3020|3020|2|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|15231|15231|2|0.0%|0.0%|
[xroxy](#xroxy)|2099|2099|1|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|6611|6611|1|0.0%|0.0%|
[proxyrss](#proxyrss)|1524|1524|1|0.0%|0.0%|
[nixspam](#nixspam)|17534|17534|1|0.0%|0.0%|
[ciarmy](#ciarmy)|408|408|1|0.2%|0.0%|

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
[bm_tor](#bm_tor)|6525|6525|5750|88.1%|88.8%|
[dm_tor](#dm_tor)|6521|6521|5747|88.1%|88.8%|
[snort_ipfilter](#snort_ipfilter)|9943|9943|1084|10.9%|16.7%|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|647|0.6%|10.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|633|0.0%|9.7%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|516|1.7%|7.9%|
[stopforumspam_1d](#stopforumspam_1d)|6922|6922|334|4.8%|5.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|190|0.0%|2.9%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|168|45.1%|2.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|168|0.0%|2.5%|
[alienvault_reputation](#alienvault_reputation)|180710|180710|42|0.0%|0.6%|
[php_commenters](#php_commenters)|326|326|35|10.7%|0.5%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|22|0.0%|0.3%|
[openbl_60d](#openbl_60d)|7563|7563|20|0.2%|0.3%|
[php_harvesters](#php_harvesters)|311|311|7|2.2%|0.1%|
[php_spammers](#php_spammers)|536|536|6|1.1%|0.0%|
[ri_web_proxies](#ri_web_proxies)|6611|6611|5|0.0%|0.0%|
[php_dictionary](#php_dictionary)|545|545|5|0.9%|0.0%|
[et_block](#et_block)|1023|18338662|4|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|16382|16382|4|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|15231|15231|4|0.0%|0.0%|
[blocklist_de](#blocklist_de)|26186|26186|4|0.0%|0.0%|
[voipbl](#voipbl)|10452|10864|3|0.0%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|0.0%|
[xroxy](#xroxy)|2099|2099|2|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|2|0.0%|0.0%|
[sorbs_spam](#sorbs_spam)|30553|30553,31638|2|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|30553|30553,31638|2|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|30553|30553,31638|2|0.0%|0.0%|
[shunlist](#shunlist)|1259|1259|1|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2461|2461|1|0.0%|0.0%|
[dshield](#dshield)|20|5120|1|0.0%|0.0%|

## feodo

[Abuse.ch Feodo tracker](https://feodotracker.abuse.ch) trojan includes IPs which are being used by Feodo (also known as Cridex or Bugat) which commits ebanking fraud - **excellent list**

Source is downloaded from [this link](https://feodotracker.abuse.ch/blocklist/?download=ipblocklist).

The last time downloaded was found to be dated: Sat Jun  6 14:27:17 UTC 2015.

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
[alienvault_reputation](#alienvault_reputation)|180710|180710|2|0.0%|2.0%|
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
[voipbl](#voipbl)|10452|10864|319|2.9%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|33|2.2%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|15|0.0%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|9|0.6%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|2|0.0%|0.0%|
[php_harvesters](#php_harvesters)|311|311|1|0.3%|0.0%|
[ciarmy](#ciarmy)|408|408|1|0.2%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1870|1870|1|0.0%|0.0%|

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
[sorbs_spam](#sorbs_spam)|30553|30553,31638|15|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|30553|30553,31638|15|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|30553|30553,31638|15|0.0%|0.0%|
[fullbogons](#fullbogons)|3721|670267288|15|0.0%|0.0%|
[alienvault_reputation](#alienvault_reputation)|180710|180710|15|0.0%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|14|0.0%|0.0%|
[blocklist_de](#blocklist_de)|26186|26186|13|0.0%|0.0%|
[nixspam](#nixspam)|17534|17534|11|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|11|1.6%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|15231|15231|7|0.0%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|6|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|6|0.0%|0.0%|
[et_block](#et_block)|1023|18338662|6|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|3873|3873|6|0.1%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|4|0.0%|0.0%|
[xroxy](#xroxy)|2099|2099|3|0.1%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6922|6922|3|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|6611|6611|3|0.0%|0.0%|
[php_dictionary](#php_dictionary)|545|545|3|0.5%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|16382|16382|3|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|1555|1555|3|0.1%|0.0%|
[voipbl](#voipbl)|10452|10864|2|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9943|9943|2|0.0%|0.0%|
[php_harvesters](#php_harvesters)|311|311|2|0.6%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3020|3020|2|0.0%|0.0%|
[sorbs_web](#sorbs_web)|667|667,668|1|0.1%|0.0%|
[proxz](#proxz)|886|886|1|0.1%|0.0%|
[proxyrss](#proxyrss)|1524|1524|1|0.0%|0.0%|
[php_spammers](#php_spammers)|536|536|1|0.1%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1675|1675|1|0.0%|0.0%|

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
[alienvault_reputation](#alienvault_reputation)|180710|180710|518|0.2%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|153|0.5%|0.0%|
[nixspam](#nixspam)|17534|17534|77|0.4%|0.0%|
[blocklist_de](#blocklist_de)|26186|26186|52|0.1%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3020|3020|36|1.1%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|27|2.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6922|6922|25|0.3%|0.0%|
[openbl_60d](#openbl_60d)|7563|7563|17|0.2%|0.0%|
[openbl_30d](#openbl_30d)|3251|3251|13|0.3%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9943|9943|12|0.1%|0.0%|
[zeus_badips](#zeus_badips)|202|202|10|4.9%|0.0%|
[zeus](#zeus)|231|231|10|4.3%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|7|0.4%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1675|1675|6|0.3%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|16382|16382|6|0.0%|0.0%|
[sorbs_spam](#sorbs_spam)|30553|30553,31638|5|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|30553|30553,31638|5|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|30553|30553,31638|5|0.0%|0.0%|
[openbl_7d](#openbl_7d)|856|856|5|0.5%|0.0%|
[et_compromised](#et_compromised)|2016|2016|5|0.2%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1870|1870|5|0.2%|0.0%|
[dm_tor](#dm_tor)|6521|6521|4|0.0%|0.0%|
[bm_tor](#bm_tor)|6525|6525|4|0.0%|0.0%|
[et_tor](#et_tor)|6470|6470|3|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|180|180|3|1.6%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|15231|15231|3|0.0%|0.0%|
[shunlist](#shunlist)|1259|1259|2|0.1%|0.0%|
[php_spammers](#php_spammers)|536|536|2|0.3%|0.0%|
[php_dictionary](#php_dictionary)|545|545|2|0.3%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|2|0.2%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|1555|1555|2|0.1%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|3873|3873|2|0.0%|0.0%|
[voipbl](#voipbl)|10452|10864|1|0.0%|0.0%|
[php_harvesters](#php_harvesters)|311|311|1|0.3%|0.0%|
[php_commenters](#php_commenters)|326|326|1|0.3%|0.0%|
[openbl_1d](#openbl_1d)|140|140|1|0.7%|0.0%|
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
[alienvault_reputation](#alienvault_reputation)|180710|180710|4735|2.6%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|1543|1.6%|0.0%|
[blocklist_de](#blocklist_de)|26186|26186|1499|5.7%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|16382|16382|1379|8.4%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|15231|15231|1328|8.7%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|568|1.8%|0.0%|
[sorbs_spam](#sorbs_spam)|30553|30553,31638|492|1.5%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|30553|30553,31638|492|1.5%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|30553|30553,31638|492|1.5%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|406|0.8%|0.0%|
[voipbl](#voipbl)|10452|10864|299|2.7%|0.0%|
[dshield](#dshield)|20|5120|264|5.1%|0.0%|
[nixspam](#nixspam)|17534|17534|222|1.2%|0.0%|
[openbl_60d](#openbl_60d)|7563|7563|168|2.2%|0.0%|
[et_tor](#et_tor)|6470|6470|168|2.5%|0.0%|
[dm_tor](#dm_tor)|6521|6521|162|2.4%|0.0%|
[bm_tor](#bm_tor)|6525|6525|162|2.4%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6922|6922|139|2.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|6611|6611|134|2.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|97|6.6%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9943|9943|78|0.7%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2461|2461|78|3.1%|0.0%|
[openbl_30d](#openbl_30d)|3251|3251|71|2.1%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|66|5.1%|0.0%|
[xroxy](#xroxy)|2099|2099|58|2.7%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|58|8.6%|0.0%|
[et_compromised](#et_compromised)|2016|2016|52|2.5%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1870|1870|48|2.5%|0.0%|
[proxyrss](#proxyrss)|1524|1524|43|2.8%|0.0%|
[et_botcc](#et_botcc)|509|509|41|8.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|3873|3873|36|0.9%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3020|3020|32|1.0%|0.0%|
[proxz](#proxz)|886|886|31|3.4%|0.0%|
[ciarmy](#ciarmy)|408|408|30|7.3%|0.0%|
[shunlist](#shunlist)|1259|1259|28|2.2%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1675|1675|26|1.5%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|1555|1555|25|1.6%|0.0%|
[sorbs_web](#sorbs_web)|667|667,668|21|3.1%|0.0%|
[openbl_7d](#openbl_7d)|856|856|19|2.2%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|17|4.5%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|867|867|12|1.3%|0.0%|
[php_dictionary](#php_dictionary)|545|545|11|2.0%|0.0%|
[malc0de](#malc0de)|361|361|11|3.0%|0.0%|
[php_harvesters](#php_harvesters)|311|311|9|2.8%|0.0%|
[php_spammers](#php_spammers)|536|536|7|1.3%|0.0%|
[php_commenters](#php_commenters)|326|326|7|2.1%|0.0%|
[zeus](#zeus)|231|231|6|2.5%|0.0%|
[bogons](#bogons)|13|592708608|5|0.0%|0.0%|
[zeus_badips](#zeus_badips)|202|202|4|1.9%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|90|90|4|4.4%|0.0%|
[sslbl](#sslbl)|369|369|3|0.8%|0.0%|
[openbl_1d](#openbl_1d)|140|140|3|2.1%|0.0%|
[feodo](#feodo)|99|99|3|3.0%|0.0%|
[virbl](#virbl)|4|4|1|25.0%|0.0%|

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
[alienvault_reputation](#alienvault_reputation)|180710|180710|7538|4.1%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|2524|2.7%|0.0%|
[blocklist_de](#blocklist_de)|26186|26186|1423|5.4%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|16382|16382|1141|6.9%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|15231|15231|1089|7.1%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|909|3.0%|0.0%|
[sorbs_spam](#sorbs_spam)|30553|30553,31638|789|2.4%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|30553|30553,31638|789|2.4%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|30553|30553,31638|789|2.4%|0.0%|
[voipbl](#voipbl)|10452|10864|434|3.9%|0.0%|
[nixspam](#nixspam)|17534|17534|408|2.3%|0.0%|
[openbl_60d](#openbl_60d)|7563|7563|330|4.3%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|230|0.4%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6922|6922|192|2.7%|0.0%|
[ri_web_proxies](#ri_web_proxies)|6611|6611|192|2.9%|0.0%|
[et_tor](#et_tor)|6470|6470|190|2.9%|0.0%|
[dm_tor](#dm_tor)|6521|6521|190|2.9%|0.0%|
[bm_tor](#bm_tor)|6525|6525|190|2.9%|0.0%|
[openbl_30d](#openbl_30d)|3251|3251|168|5.1%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3020|3020|116|3.8%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9943|9943|103|1.0%|0.0%|
[xroxy](#xroxy)|2099|2099|101|4.8%|0.0%|
[et_compromised](#et_compromised)|2016|2016|97|4.8%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2461|2461|96|3.9%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1870|1870|96|5.1%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1675|1675|83|4.9%|0.0%|
[shunlist](#shunlist)|1259|1259|73|5.7%|0.0%|
[proxyrss](#proxyrss)|1524|1524|71|4.6%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|3873|3873|57|1.4%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|1555|1555|50|3.2%|0.0%|
[php_spammers](#php_spammers)|536|536|45|8.3%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|45|3.0%|0.0%|
[openbl_7d](#openbl_7d)|856|856|43|5.0%|0.0%|
[ciarmy](#ciarmy)|408|408|43|10.5%|0.0%|
[proxz](#proxz)|886|886|37|4.1%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|28|4.1%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|26|2.0%|0.0%|
[sorbs_web](#sorbs_web)|667|667,668|25|3.7%|0.0%|
[et_botcc](#et_botcc)|509|509|22|4.3%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|21|5.6%|0.0%|
[malc0de](#malc0de)|361|361|21|5.8%|0.0%|
[php_dictionary](#php_dictionary)|545|545|17|3.1%|0.0%|
[dshield](#dshield)|20|5120|16|0.3%|0.0%|
[php_commenters](#php_commenters)|326|326|13|3.9%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|867|867|11|1.2%|0.0%|
[zeus](#zeus)|231|231|9|3.8%|0.0%|
[php_harvesters](#php_harvesters)|311|311|9|2.8%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|168|168|9|5.3%|0.0%|
[zeus_badips](#zeus_badips)|202|202|8|3.9%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|180|180|8|4.4%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|90|90|7|7.7%|0.0%|
[sslbl](#sslbl)|369|369|5|1.3%|0.0%|
[openbl_1d](#openbl_1d)|140|140|5|3.5%|0.0%|
[palevo](#palevo)|13|13|3|23.0%|0.0%|
[feodo](#feodo)|99|99|3|3.0%|0.0%|
[sorbs_socks](#sorbs_socks)|20|20,20|1|5.0%|0.0%|
[sorbs_smtp](#sorbs_smtp)|14|14,14|1|7.1%|0.0%|
[sorbs_misc](#sorbs_misc)|20|20,20|1|5.0%|0.0%|
[sorbs_http](#sorbs_http)|20|20,20|1|5.0%|0.0%|

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
[alienvault_reputation](#alienvault_reputation)|180710|180710|14152|7.8%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|9231|2.7%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|5841|6.2%|0.0%|
[blocklist_de](#blocklist_de)|26186|26186|3352|12.8%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|16382|16382|2594|15.8%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|15231|15231|2384|15.6%|0.0%|
[sorbs_spam](#sorbs_spam)|30553|30553,31638|2313|7.3%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|30553|30553,31638|2313|7.3%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|30553|30553,31638|2313|7.3%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|1912|6.3%|0.0%|
[voipbl](#voipbl)|10452|10864|1598|14.7%|0.0%|
[nixspam](#nixspam)|17534|17534|1379|7.8%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1172|2.4%|0.0%|
[openbl_60d](#openbl_60d)|7563|7563|746|9.8%|0.0%|
[et_tor](#et_tor)|6470|6470|633|9.7%|0.0%|
[dm_tor](#dm_tor)|6521|6521|631|9.6%|0.0%|
[bm_tor](#bm_tor)|6525|6525|631|9.6%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6922|6922|517|7.4%|0.0%|
[openbl_30d](#openbl_30d)|3251|3251|313|9.6%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|3873|3873|284|7.3%|0.0%|
[dshield](#dshield)|20|5120|256|5.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9943|9943|232|2.3%|0.0%|
[et_compromised](#et_compromised)|2016|2016|199|9.8%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3020|3020|192|6.3%|0.0%|
[ri_web_proxies](#ri_web_proxies)|6611|6611|190|2.8%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1870|1870|176|9.4%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1675|1675|169|10.0%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|147|11.4%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|1555|1555|138|8.8%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|125|33.6%|0.0%|
[openbl_7d](#openbl_7d)|856|856|115|13.4%|0.0%|
[shunlist](#shunlist)|1259|1259|113|8.9%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|110|7.5%|0.0%|
[xroxy](#xroxy)|2099|2099|94|4.4%|0.0%|
[ciarmy](#ciarmy)|408|408|80|19.6%|0.0%|
[et_botcc](#et_botcc)|509|509|78|15.3%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|867|867|73|8.4%|0.0%|
[proxz](#proxz)|886|886|72|8.1%|0.0%|
[proxyrss](#proxyrss)|1524|1524|61|4.0%|0.0%|
[malc0de](#malc0de)|361|361|54|14.9%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2461|2461|53|2.1%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|51|7.5%|0.0%|
[sorbs_web](#sorbs_web)|667|667,668|47|7.0%|0.0%|
[php_spammers](#php_spammers)|536|536|31|5.7%|0.0%|
[php_dictionary](#php_dictionary)|545|545|31|5.6%|0.0%|
[sslbl](#sslbl)|369|369|26|7.0%|0.0%|
[php_commenters](#php_commenters)|326|326|18|5.5%|0.0%|
[php_harvesters](#php_harvesters)|311|311|17|5.4%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|168|168|17|10.1%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|180|180|16|8.8%|0.0%|
[zeus](#zeus)|231|231|14|6.0%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|90|90|12|13.3%|0.0%|
[openbl_1d](#openbl_1d)|140|140|11|7.8%|0.0%|
[feodo](#feodo)|99|99|11|11.1%|0.0%|
[zeus_badips](#zeus_badips)|202|202|10|4.9%|0.0%|
[virbl](#virbl)|4|4|1|25.0%|0.0%|
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
[xroxy](#xroxy)|2099|2099|13|0.6%|1.9%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|12|0.0%|1.7%|
[ri_web_proxies](#ri_web_proxies)|6611|6611|12|0.1%|1.7%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|11|0.0%|1.6%|
[proxyrss](#proxyrss)|1524|1524|10|0.6%|1.4%|
[ri_connect_proxies](#ri_connect_proxies)|2461|2461|7|0.2%|1.0%|
[proxz](#proxz)|886|886|6|0.6%|0.8%|
[blocklist_de_bots](#blocklist_de_bots)|3020|3020|3|0.0%|0.4%|
[blocklist_de](#blocklist_de)|26186|26186|3|0.0%|0.4%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|2|0.0%|0.2%|
[sorbs_spam](#sorbs_spam)|30553|30553,31638|2|0.0%|0.2%|
[sorbs_recent_spam](#sorbs_recent_spam)|30553|30553,31638|2|0.0%|0.2%|
[sorbs_new_spam](#sorbs_new_spam)|30553|30553,31638|2|0.0%|0.2%|
[nixspam](#nixspam)|17534|17534|2|0.0%|0.2%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2|0.0%|0.2%|
[et_block](#et_block)|1023|18338662|2|0.0%|0.2%|
[stopforumspam_1d](#stopforumspam_1d)|6922|6922|1|0.0%|0.1%|
[php_dictionary](#php_dictionary)|545|545|1|0.1%|0.1%|
[alienvault_reputation](#alienvault_reputation)|180710|180710|1|0.0%|0.1%|

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
[alienvault_reputation](#alienvault_reputation)|180710|180710|287|0.1%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|46|0.0%|0.0%|
[sorbs_spam](#sorbs_spam)|30553|30553,31638|33|0.1%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|30553|30553,31638|33|0.1%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|30553|30553,31638|33|0.1%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|27|2.0%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|25|0.0%|0.0%|
[et_tor](#et_tor)|6470|6470|22|0.3%|0.0%|
[dm_tor](#dm_tor)|6521|6521|22|0.3%|0.0%|
[bm_tor](#bm_tor)|6525|6525|22|0.3%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|19|1.3%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9943|9943|14|0.1%|0.0%|
[nixspam](#nixspam)|17534|17534|12|0.0%|0.0%|
[blocklist_de](#blocklist_de)|26186|26186|11|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6922|6922|7|0.1%|0.0%|
[ri_web_proxies](#ri_web_proxies)|6611|6611|5|0.0%|0.0%|
[openbl_60d](#openbl_60d)|7563|7563|5|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|5|1.3%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3020|3020|5|0.1%|0.0%|
[voipbl](#voipbl)|10452|10864|4|0.0%|0.0%|
[openbl_30d](#openbl_30d)|3251|3251|4|0.1%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|4|0.0%|0.0%|
[malc0de](#malc0de)|361|361|3|0.8%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|168|168|3|1.7%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|15231|15231|3|0.0%|0.0%|
[palevo](#palevo)|13|13|2|15.3%|0.0%|
[et_compromised](#et_compromised)|2016|2016|2|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1870|1870|2|0.1%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1675|1675|2|0.1%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|90|90|2|2.2%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|16382|16382|2|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|3873|3873|2|0.0%|0.0%|
[zeus_badips](#zeus_badips)|202|202|1|0.4%|0.0%|
[zeus](#zeus)|231|231|1|0.4%|0.0%|
[xroxy](#xroxy)|2099|2099|1|0.0%|0.0%|
[sslbl](#sslbl)|369|369|1|0.2%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|1|0.0%|0.0%|
[shunlist](#shunlist)|1259|1259|1|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2461|2461|1|0.0%|0.0%|
[proxyrss](#proxyrss)|1524|1524|1|0.0%|0.0%|
[php_harvesters](#php_harvesters)|311|311|1|0.3%|0.0%|
[php_dictionary](#php_dictionary)|545|545|1|0.1%|0.0%|
[openbl_7d](#openbl_7d)|856|856|1|0.1%|0.0%|
[feodo](#feodo)|99|99|1|1.0%|0.0%|
[ciarmy](#ciarmy)|408|408|1|0.2%|0.0%|
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
[alienvault_reputation](#alienvault_reputation)|180710|180710|8|0.0%|0.5%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|7|0.0%|0.4%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|6|0.0%|0.4%|
[et_block](#et_block)|1023|18338662|6|0.0%|0.4%|
[nixspam](#nixspam)|17534|17534|3|0.0%|0.2%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|3|0.2%|0.2%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|2|0.0%|0.1%|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|2|0.0%|0.1%|
[stopforumspam_1d](#stopforumspam_1d)|6922|6922|2|0.0%|0.1%|
[openbl_60d](#openbl_60d)|7563|7563|2|0.0%|0.1%|
[openbl_30d](#openbl_30d)|3251|3251|2|0.0%|0.1%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|2|0.2%|0.1%|
[blocklist_de](#blocklist_de)|26186|26186|2|0.0%|0.1%|
[snort_ipfilter](#snort_ipfilter)|9943|9943|1|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|6611|6611|1|0.0%|0.0%|
[openbl_7d](#openbl_7d)|856|856|1|0.1%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1|0.0%|0.0%|
[et_botcc](#et_botcc)|509|509|1|0.1%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|180|180|1|0.5%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1675|1675|1|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3020|3020|1|0.0%|0.0%|

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
[alienvault_reputation](#alienvault_reputation)|180710|180710|11|0.0%|3.0%|
[et_block](#et_block)|1023|18338662|5|0.0%|1.3%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|4|0.0%|1.1%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|4|0.3%|1.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|3|0.0%|0.8%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|1|0.0%|0.2%|
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
[et_block](#et_block)|1023|18338662|29|0.0%|2.2%|
[snort_ipfilter](#snort_ipfilter)|9943|9943|28|0.2%|2.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|27|0.0%|2.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|27|0.0%|2.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|26|0.0%|2.0%|
[fullbogons](#fullbogons)|3721|670267288|9|0.0%|0.6%|
[alienvault_reputation](#alienvault_reputation)|180710|180710|6|0.0%|0.4%|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|4|0.0%|0.3%|
[malc0de](#malc0de)|361|361|4|1.1%|0.3%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|3|0.2%|0.2%|
[cleanmx_viruses](#cleanmx_viruses)|168|168|2|1.1%|0.1%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|1|0.0%|0.0%|
[sorbs_spam](#sorbs_spam)|30553|30553,31638|1|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|30553|30553,31638|1|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|30553|30553,31638|1|0.0%|0.0%|
[nixspam](#nixspam)|17534|17534|1|0.0%|0.0%|
[et_botcc](#et_botcc)|509|509|1|0.1%|0.0%|

## maxmind_proxy_fraud

[MaxMind.com](https://www.maxmind.com/en/anonymous-proxy-fraudulent-ip-address-list) list of anonymous proxy fraudelent IP addresses.

Source is downloaded from [this link](https://www.maxmind.com/en/anonymous-proxy-fraudulent-ip-address-list).

The last time downloaded was found to be dated: Sat Jun  6 10:45:05 UTC 2015.

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
[dm_tor](#dm_tor)|6521|6521|167|2.5%|44.8%|
[bm_tor](#bm_tor)|6525|6525|167|2.5%|44.8%|
[stopforumspam_1d](#stopforumspam_1d)|6922|6922|165|2.3%|44.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|125|0.0%|33.6%|
[php_commenters](#php_commenters)|326|326|32|9.8%|8.6%|
[alienvault_reputation](#alienvault_reputation)|180710|180710|26|0.0%|6.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|21|0.0%|5.6%|
[openbl_60d](#openbl_60d)|7563|7563|18|0.2%|4.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|17|0.0%|4.5%|
[php_harvesters](#php_harvesters)|311|311|6|1.9%|1.6%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|5|0.0%|1.3%|
[ri_web_proxies](#ri_web_proxies)|6611|6611|4|0.0%|1.0%|
[php_spammers](#php_spammers)|536|536|4|0.7%|1.0%|
[php_dictionary](#php_dictionary)|545|545|4|0.7%|1.0%|
[blocklist_de](#blocklist_de)|26186|26186|3|0.0%|0.8%|
[shunlist](#shunlist)|1259|1259|2|0.1%|0.5%|
[blocklist_de_apache](#blocklist_de_apache)|15231|15231|2|0.0%|0.5%|
[xroxy](#xroxy)|2099|2099|1|0.0%|0.2%|
[voipbl](#voipbl)|10452|10864|1|0.0%|0.2%|
[ri_connect_proxies](#ri_connect_proxies)|2461|2461|1|0.0%|0.2%|
[et_block](#et_block)|1023|18338662|1|0.0%|0.2%|
[blocklist_de_ssh](#blocklist_de_ssh)|1675|1675|1|0.0%|0.2%|
[blocklist_de_mail](#blocklist_de_mail)|16382|16382|1|0.0%|0.2%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|3873|3873|1|0.0%|0.2%|

## nixspam

[NiX Spam](http://www.heise.de/ix/NiX-Spam-DNSBL-and-blacklist-for-download-499637.html) IP addresses that sent spam in the last hour - automatically generated entries without distinguishing open proxies from relays, dialup gateways, and so on. All IPs are removed after 12 hours if there is no spam from there.

Source is downloaded from [this link](http://www.dnsbl.manitu.net/download/nixspam-ip.dump.gz).

The last time downloaded was found to be dated: Sat Jun  6 14:15:02 UTC 2015.

The ipset `nixspam` has **17534** entries, **17534** unique IPs.

The following table shows the overlaps of `nixspam` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `nixspam`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `nixspam`.
- ` this % ` is the percentage **of this ipset (`nixspam`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[sorbs_spam](#sorbs_spam)|30553|30553,31638|2492|7.8%|14.2%|
[sorbs_recent_spam](#sorbs_recent_spam)|30553|30553,31638|2492|7.8%|14.2%|
[sorbs_new_spam](#sorbs_new_spam)|30553|30553,31638|2492|7.8%|14.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|1379|0.0%|7.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|408|0.0%|2.3%|
[blocklist_de](#blocklist_de)|26186|26186|380|1.4%|2.1%|
[blocklist_de_mail](#blocklist_de_mail)|16382|16382|316|1.9%|1.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|222|0.0%|1.2%|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|158|0.1%|0.9%|
[snort_ipfilter](#snort_ipfilter)|9943|9943|109|1.0%|0.6%|
[sorbs_web](#sorbs_web)|667|667,668|87|13.0%|0.4%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|81|0.2%|0.4%|
[et_block](#et_block)|1023|18338662|81|0.0%|0.4%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|79|0.0%|0.4%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|77|0.0%|0.4%|
[php_dictionary](#php_dictionary)|545|545|65|11.9%|0.3%|
[php_spammers](#php_spammers)|536|536|61|11.3%|0.3%|
[ri_web_proxies](#ri_web_proxies)|6611|6611|50|0.7%|0.2%|
[stopforumspam_1d](#stopforumspam_1d)|6922|6922|40|0.5%|0.2%|
[xroxy](#xroxy)|2099|2099|36|1.7%|0.2%|
[alienvault_reputation](#alienvault_reputation)|180710|180710|34|0.0%|0.1%|
[blocklist_de_apache](#blocklist_de_apache)|15231|15231|28|0.1%|0.1%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|3873|3873|27|0.6%|0.1%|
[blocklist_de_bots](#blocklist_de_bots)|3020|3020|24|0.7%|0.1%|
[proxz](#proxz)|886|886|16|1.8%|0.0%|
[openbl_60d](#openbl_60d)|7563|7563|12|0.1%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|12|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|11|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|1555|1555|10|0.6%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2461|2461|9|0.3%|0.0%|
[proxyrss](#proxyrss)|1524|1524|9|0.5%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|867|867|9|1.0%|0.0%|
[php_commenters](#php_commenters)|326|326|8|2.4%|0.0%|
[php_harvesters](#php_harvesters)|311|311|5|1.6%|0.0%|
[openbl_30d](#openbl_30d)|3251|3251|5|0.1%|0.0%|
[openbl_7d](#openbl_7d)|856|856|3|0.3%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|3|0.2%|0.0%|
[sorbs_socks](#sorbs_socks)|20|20,20|2|10.0%|0.0%|
[sorbs_misc](#sorbs_misc)|20|20,20|2|10.0%|0.0%|
[sorbs_http](#sorbs_http)|20|20,20|2|10.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|2|0.2%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1675|1675|2|0.1%|0.0%|
[sorbs_smtp](#sorbs_smtp)|14|14,14|1|7.1%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|1|0.0%|0.0%|
[et_compromised](#et_compromised)|2016|2016|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1870|1870|1|0.0%|0.0%|

## openbl_1d

[OpenBL.org](http://www.openbl.org/) last 24 hours IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.

Source is downloaded from [this link](http://www.openbl.org/lists/base_1days.txt).

The last time downloaded was found to be dated: Sat Jun  6 13:32:00 UTC 2015.

The ipset `openbl_1d` has **140** entries, **140** unique IPs.

The following table shows the overlaps of `openbl_1d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl_1d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl_1d`.
- ` this % ` is the percentage **of this ipset (`openbl_1d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[openbl_60d](#openbl_60d)|7563|7563|138|1.8%|98.5%|
[openbl_30d](#openbl_30d)|3251|3251|138|4.2%|98.5%|
[openbl_7d](#openbl_7d)|856|856|137|16.0%|97.8%|
[alienvault_reputation](#alienvault_reputation)|180710|180710|132|0.0%|94.2%|
[blocklist_de](#blocklist_de)|26186|26186|120|0.4%|85.7%|
[blocklist_de_ssh](#blocklist_de_ssh)|1675|1675|119|7.1%|85.0%|
[bruteforceblocker](#bruteforceblocker)|1870|1870|80|4.2%|57.1%|
[et_compromised](#et_compromised)|2016|2016|77|3.8%|55.0%|
[shunlist](#shunlist)|1259|1259|66|5.2%|47.1%|
[blocklist_de_strongips](#blocklist_de_strongips)|180|180|20|11.1%|14.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|11|0.0%|7.8%|
[et_block](#et_block)|1023|18338662|11|0.0%|7.8%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|10|0.0%|7.1%|
[dshield](#dshield)|20|5120|7|0.1%|5.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|5|0.0%|3.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|3|0.0%|2.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.7%|
[blocklist_de_mail](#blocklist_de_mail)|16382|16382|1|0.0%|0.7%|
[blocklist_de_imap](#blocklist_de_imap)|1555|1555|1|0.0%|0.7%|

## openbl_30d

[OpenBL.org](http://www.openbl.org/) last 30 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.

Source is downloaded from [this link](http://www.openbl.org/lists/base_30days.txt).

The last time downloaded was found to be dated: Sat Jun  6 11:42:00 UTC 2015.

The ipset `openbl_30d` has **3251** entries, **3251** unique IPs.

The following table shows the overlaps of `openbl_30d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl_30d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl_30d`.
- ` this % ` is the percentage **of this ipset (`openbl_30d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[openbl_60d](#openbl_60d)|7563|7563|3251|42.9%|100.0%|
[alienvault_reputation](#alienvault_reputation)|180710|180710|3231|1.7%|99.3%|
[et_compromised](#et_compromised)|2016|2016|1150|57.0%|35.3%|
[bruteforceblocker](#bruteforceblocker)|1870|1870|1068|57.1%|32.8%|
[openbl_7d](#openbl_7d)|856|856|856|100.0%|26.3%|
[blocklist_de](#blocklist_de)|26186|26186|692|2.6%|21.2%|
[blocklist_de_ssh](#blocklist_de_ssh)|1675|1675|644|38.4%|19.8%|
[shunlist](#shunlist)|1259|1259|552|43.8%|16.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|313|0.0%|9.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|168|0.0%|5.1%|
[et_block](#et_block)|1023|18338662|166|0.0%|5.1%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|160|0.0%|4.9%|
[openbl_1d](#openbl_1d)|140|140|138|98.5%|4.2%|
[dshield](#dshield)|20|5120|88|1.7%|2.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|71|0.0%|2.1%|
[blocklist_de_mail](#blocklist_de_mail)|16382|16382|37|0.2%|1.1%|
[blocklist_de_imap](#blocklist_de_imap)|1555|1555|32|2.0%|0.9%|
[blocklist_de_strongips](#blocklist_de_strongips)|180|180|25|13.8%|0.7%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|13|0.0%|0.3%|
[blocklist_de_apache](#blocklist_de_apache)|15231|15231|6|0.0%|0.1%|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|5|0.0%|0.1%|
[nixspam](#nixspam)|17534|17534|5|0.0%|0.1%|
[snort_ipfilter](#snort_ipfilter)|9943|9943|4|0.0%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|4|0.0%|0.1%|
[voipbl](#voipbl)|10452|10864|3|0.0%|0.0%|
[sorbs_spam](#sorbs_spam)|30553|30553,31638|3|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|30553|30553,31638|3|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|30553|30553,31638|3|0.0%|0.0%|
[zeus](#zeus)|231|231|2|0.8%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|2|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6922|6922|2|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3020|3020|2|0.0%|0.0%|
[zeus_badips](#zeus_badips)|202|202|1|0.4%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|1|0.0%|0.0%|
[sorbs_web](#sorbs_web)|667|667,668|1|0.1%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|867|867|1|0.1%|0.0%|

## openbl_60d

[OpenBL.org](http://www.openbl.org/) last 60 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.

Source is downloaded from [this link](http://www.openbl.org/lists/base_60days.txt).

The last time downloaded was found to be dated: Sat Jun  6 11:42:00 UTC 2015.

The ipset `openbl_60d` has **7563** entries, **7563** unique IPs.

The following table shows the overlaps of `openbl_60d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl_60d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl_60d`.
- ` this % ` is the percentage **of this ipset (`openbl_60d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[alienvault_reputation](#alienvault_reputation)|180710|180710|7538|4.1%|99.6%|
[openbl_30d](#openbl_30d)|3251|3251|3251|100.0%|42.9%|
[et_compromised](#et_compromised)|2016|2016|1216|60.3%|16.0%|
[bruteforceblocker](#bruteforceblocker)|1870|1870|1116|59.6%|14.7%|
[openbl_7d](#openbl_7d)|856|856|856|100.0%|11.3%|
[blocklist_de](#blocklist_de)|26186|26186|748|2.8%|9.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|746|0.0%|9.8%|
[blocklist_de_ssh](#blocklist_de_ssh)|1675|1675|682|40.7%|9.0%|
[shunlist](#shunlist)|1259|1259|567|45.0%|7.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|330|0.0%|4.3%|
[et_block](#et_block)|1023|18338662|250|0.0%|3.3%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|239|0.0%|3.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|168|0.0%|2.2%|
[openbl_1d](#openbl_1d)|140|140|138|98.5%|1.8%|
[dshield](#dshield)|20|5120|105|2.0%|1.3%|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|56|0.0%|0.7%|
[blocklist_de_mail](#blocklist_de_mail)|16382|16382|44|0.2%|0.5%|
[blocklist_de_imap](#blocklist_de_imap)|1555|1555|39|2.5%|0.5%|
[snort_ipfilter](#snort_ipfilter)|9943|9943|27|0.2%|0.3%|
[blocklist_de_strongips](#blocklist_de_strongips)|180|180|27|15.0%|0.3%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|26|0.0%|0.3%|
[stopforumspam_1d](#stopforumspam_1d)|6922|6922|21|0.3%|0.2%|
[et_tor](#et_tor)|6470|6470|20|0.3%|0.2%|
[dm_tor](#dm_tor)|6521|6521|20|0.3%|0.2%|
[bm_tor](#bm_tor)|6525|6525|20|0.3%|0.2%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|18|4.8%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|17|0.0%|0.2%|
[sorbs_spam](#sorbs_spam)|30553|30553,31638|15|0.0%|0.1%|
[sorbs_recent_spam](#sorbs_recent_spam)|30553|30553,31638|15|0.0%|0.1%|
[sorbs_new_spam](#sorbs_new_spam)|30553|30553,31638|15|0.0%|0.1%|
[nixspam](#nixspam)|17534|17534|12|0.0%|0.1%|
[blocklist_de_bots](#blocklist_de_bots)|3020|3020|10|0.3%|0.1%|
[php_commenters](#php_commenters)|326|326|9|2.7%|0.1%|
[voipbl](#voipbl)|10452|10864|8|0.0%|0.1%|
[blocklist_de_apache](#blocklist_de_apache)|15231|15231|8|0.0%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|5|0.0%|0.0%|
[zeus](#zeus)|231|231|2|0.8%|0.0%|
[php_harvesters](#php_harvesters)|311|311|2|0.6%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|867|867|2|0.2%|0.0%|
[zeus_badips](#zeus_badips)|202|202|1|0.4%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|1|0.0%|0.0%|
[sorbs_web](#sorbs_web)|667|667,668|1|0.1%|0.0%|

## openbl_7d

[OpenBL.org](http://www.openbl.org/) last 7 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.

Source is downloaded from [this link](http://www.openbl.org/lists/base_7days.txt).

The last time downloaded was found to be dated: Sat Jun  6 11:42:00 UTC 2015.

The ipset `openbl_7d` has **856** entries, **856** unique IPs.

The following table shows the overlaps of `openbl_7d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl_7d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl_7d`.
- ` this % ` is the percentage **of this ipset (`openbl_7d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[openbl_60d](#openbl_60d)|7563|7563|856|11.3%|100.0%|
[openbl_30d](#openbl_30d)|3251|3251|856|26.3%|100.0%|
[alienvault_reputation](#alienvault_reputation)|180710|180710|846|0.4%|98.8%|
[blocklist_de](#blocklist_de)|26186|26186|426|1.6%|49.7%|
[blocklist_de_ssh](#blocklist_de_ssh)|1675|1675|410|24.4%|47.8%|
[et_compromised](#et_compromised)|2016|2016|385|19.0%|44.9%|
[bruteforceblocker](#bruteforceblocker)|1870|1870|379|20.2%|44.2%|
[shunlist](#shunlist)|1259|1259|245|19.4%|28.6%|
[openbl_1d](#openbl_1d)|140|140|137|97.8%|16.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|115|0.0%|13.4%|
[et_block](#et_block)|1023|18338662|51|0.0%|5.9%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|48|0.0%|5.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|43|0.0%|5.0%|
[dshield](#dshield)|20|5120|34|0.6%|3.9%|
[blocklist_de_strongips](#blocklist_de_strongips)|180|180|24|13.3%|2.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|19|0.0%|2.2%|
[blocklist_de_mail](#blocklist_de_mail)|16382|16382|13|0.0%|1.5%|
[blocklist_de_imap](#blocklist_de_imap)|1555|1555|13|0.8%|1.5%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|5|0.0%|0.5%|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|3|0.0%|0.3%|
[nixspam](#nixspam)|17534|17534|3|0.0%|0.3%|
[blocklist_de_apache](#blocklist_de_apache)|15231|15231|2|0.0%|0.2%|
[voipbl](#voipbl)|10452|10864|1|0.0%|0.1%|
[sorbs_spam](#sorbs_spam)|30553|30553,31638|1|0.0%|0.1%|
[sorbs_recent_spam](#sorbs_recent_spam)|30553|30553,31638|1|0.0%|0.1%|
[sorbs_new_spam](#sorbs_new_spam)|30553|30553,31638|1|0.0%|0.1%|
[snort_ipfilter](#snort_ipfilter)|9943|9943|1|0.0%|0.1%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.1%|

## palevo

[Abuse.ch Palevo tracker](https://palevotracker.abuse.ch) worm includes IPs which are being used as botnet C&C for the Palevo crimeware - **excellent list**

Source is downloaded from [this link](https://palevotracker.abuse.ch/blocklists.php?download=ipblocklist).

The last time downloaded was found to be dated: Sat Jun  6 14:27:13 UTC 2015.

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

The last time downloaded was found to be dated: Sat Jun  6 13:36:13 UTC 2015.

The ipset `php_commenters` has **326** entries, **326** unique IPs.

The following table shows the overlaps of `php_commenters` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `php_commenters`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `php_commenters`.
- ` this % ` is the percentage **of this ipset (`php_commenters`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|238|0.2%|73.0%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|171|0.5%|52.4%|
[stopforumspam_1d](#stopforumspam_1d)|6922|6922|125|1.8%|38.3%|
[blocklist_de](#blocklist_de)|26186|26186|74|0.2%|22.6%|
[blocklist_de_bots](#blocklist_de_bots)|3020|3020|60|1.9%|18.4%|
[snort_ipfilter](#snort_ipfilter)|9943|9943|44|0.4%|13.4%|
[php_spammers](#php_spammers)|536|536|36|6.7%|11.0%|
[et_tor](#et_tor)|6470|6470|35|0.5%|10.7%|
[dm_tor](#dm_tor)|6521|6521|34|0.5%|10.4%|
[bm_tor](#bm_tor)|6525|6525|34|0.5%|10.4%|
[blocklist_de_strongips](#blocklist_de_strongips)|180|180|34|18.8%|10.4%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|32|8.6%|9.8%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|28|0.0%|8.5%|
[et_block](#et_block)|1023|18338662|28|0.0%|8.5%|
[blocklist_de_apache](#blocklist_de_apache)|15231|15231|25|0.1%|7.6%|
[php_dictionary](#php_dictionary)|545|545|24|4.4%|7.3%|
[blocklist_de_mail](#blocklist_de_mail)|16382|16382|21|0.1%|6.4%|
[ri_web_proxies](#ri_web_proxies)|6611|6611|19|0.2%|5.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|18|0.0%|5.5%|
[sorbs_spam](#sorbs_spam)|30553|30553,31638|15|0.0%|4.6%|
[sorbs_recent_spam](#sorbs_recent_spam)|30553|30553,31638|15|0.0%|4.6%|
[sorbs_new_spam](#sorbs_new_spam)|30553|30553,31638|15|0.0%|4.6%|
[alienvault_reputation](#alienvault_reputation)|180710|180710|15|0.0%|4.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|13|0.0%|3.9%|
[php_harvesters](#php_harvesters)|311|311|11|3.5%|3.3%|
[openbl_60d](#openbl_60d)|7563|7563|9|0.1%|2.7%|
[nixspam](#nixspam)|17534|17534|8|0.0%|2.4%|
[xroxy](#xroxy)|2099|2099|7|0.3%|2.1%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|7|0.0%|2.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|7|0.0%|2.1%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|3873|3873|7|0.1%|2.1%|
[ri_connect_proxies](#ri_connect_proxies)|2461|2461|4|0.1%|1.2%|
[proxz](#proxz)|886|886|4|0.4%|1.2%|
[proxyrss](#proxyrss)|1524|1524|4|0.2%|1.2%|
[sorbs_web](#sorbs_web)|667|667,668|3|0.4%|0.9%|
[zeus_badips](#zeus_badips)|202|202|1|0.4%|0.3%|
[zeus](#zeus)|231|231|1|0.4%|0.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.3%|

## php_dictionary

[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) directory attackers (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=d&rss=1).

The last time downloaded was found to be dated: Sat Jun  6 13:55:04 UTC 2015.

The ipset `php_dictionary` has **545** entries, **545** unique IPs.

The following table shows the overlaps of `php_dictionary` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `php_dictionary`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `php_dictionary`.
- ` this % ` is the percentage **of this ipset (`php_dictionary`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[php_spammers](#php_spammers)|536|536|180|33.5%|33.0%|
[sorbs_spam](#sorbs_spam)|30553|30553,31638|149|0.4%|27.3%|
[sorbs_recent_spam](#sorbs_recent_spam)|30553|30553,31638|149|0.4%|27.3%|
[sorbs_new_spam](#sorbs_new_spam)|30553|30553,31638|149|0.4%|27.3%|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|103|0.1%|18.8%|
[blocklist_de](#blocklist_de)|26186|26186|88|0.3%|16.1%|
[snort_ipfilter](#snort_ipfilter)|9943|9943|79|0.7%|14.4%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|66|0.2%|12.1%|
[nixspam](#nixspam)|17534|17534|65|0.3%|11.9%|
[blocklist_de_mail](#blocklist_de_mail)|16382|16382|62|0.3%|11.3%|
[ri_web_proxies](#ri_web_proxies)|6611|6611|43|0.6%|7.8%|
[stopforumspam_1d](#stopforumspam_1d)|6922|6922|34|0.4%|6.2%|
[xroxy](#xroxy)|2099|2099|32|1.5%|5.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|31|0.0%|5.6%|
[sorbs_web](#sorbs_web)|667|667,668|29|4.3%|5.3%|
[php_commenters](#php_commenters)|326|326|24|7.3%|4.4%|
[blocklist_de_bots](#blocklist_de_bots)|3020|3020|21|0.6%|3.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|17|0.0%|3.1%|
[proxz](#proxz)|886|886|14|1.5%|2.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|11|0.0%|2.0%|
[alienvault_reputation](#alienvault_reputation)|180710|180710|8|0.0%|1.4%|
[et_tor](#et_tor)|6470|6470|5|0.0%|0.9%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|4|0.0%|0.7%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|4|1.0%|0.7%|
[et_block](#et_block)|1023|18338662|4|0.0%|0.7%|
[dm_tor](#dm_tor)|6521|6521|4|0.0%|0.7%|
[bm_tor](#bm_tor)|6525|6525|4|0.0%|0.7%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|3873|3873|4|0.1%|0.7%|
[blocklist_de_apache](#blocklist_de_apache)|15231|15231|4|0.0%|0.7%|
[ri_connect_proxies](#ri_connect_proxies)|2461|2461|3|0.1%|0.5%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|3|0.0%|0.5%|
[blocklist_de_strongips](#blocklist_de_strongips)|180|180|3|1.6%|0.5%|
[sorbs_socks](#sorbs_socks)|20|20,20|2|10.0%|0.3%|
[sorbs_misc](#sorbs_misc)|20|20,20|2|10.0%|0.3%|
[sorbs_http](#sorbs_http)|20|20,20|2|10.0%|0.3%|
[php_harvesters](#php_harvesters)|311|311|2|0.6%|0.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2|0.0%|0.3%|
[proxyrss](#proxyrss)|1524|1524|1|0.0%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.1%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|1|0.1%|0.1%|
[blocklist_de_ftp](#blocklist_de_ftp)|867|867|1|0.1%|0.1%|

## php_harvesters

[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) harvesters (IPs that surf the internet looking for email addresses) (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=h&rss=1).

The last time downloaded was found to be dated: Sat Jun  6 13:36:11 UTC 2015.

The ipset `php_harvesters` has **311** entries, **311** unique IPs.

The following table shows the overlaps of `php_harvesters` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `php_harvesters`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `php_harvesters`.
- ` this % ` is the percentage **of this ipset (`php_harvesters`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|68|0.0%|21.8%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|51|0.1%|16.3%|
[stopforumspam_1d](#stopforumspam_1d)|6922|6922|37|0.5%|11.8%|
[blocklist_de](#blocklist_de)|26186|26186|31|0.1%|9.9%|
[blocklist_de_bots](#blocklist_de_bots)|3020|3020|23|0.7%|7.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|17|0.0%|5.4%|
[snort_ipfilter](#snort_ipfilter)|9943|9943|11|0.1%|3.5%|
[php_commenters](#php_commenters)|326|326|11|3.3%|3.5%|
[alienvault_reputation](#alienvault_reputation)|180710|180710|10|0.0%|3.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|9|0.0%|2.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|9|0.0%|2.8%|
[sorbs_spam](#sorbs_spam)|30553|30553,31638|7|0.0%|2.2%|
[sorbs_recent_spam](#sorbs_recent_spam)|30553|30553,31638|7|0.0%|2.2%|
[sorbs_new_spam](#sorbs_new_spam)|30553|30553,31638|7|0.0%|2.2%|
[et_tor](#et_tor)|6470|6470|7|0.1%|2.2%|
[dm_tor](#dm_tor)|6521|6521|7|0.1%|2.2%|
[bm_tor](#bm_tor)|6525|6525|7|0.1%|2.2%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|6|1.6%|1.9%|
[nixspam](#nixspam)|17534|17534|5|0.0%|1.6%|
[blocklist_de_apache](#blocklist_de_apache)|15231|15231|5|0.0%|1.6%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|3873|3873|3|0.0%|0.9%|
[xroxy](#xroxy)|2099|2099|2|0.0%|0.6%|
[proxyrss](#proxyrss)|1524|1524|2|0.1%|0.6%|
[php_spammers](#php_spammers)|536|536|2|0.3%|0.6%|
[php_dictionary](#php_dictionary)|545|545|2|0.3%|0.6%|
[openbl_60d](#openbl_60d)|7563|7563|2|0.0%|0.6%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|2|0.0%|0.6%|
[blocklist_de_strongips](#blocklist_de_strongips)|180|180|2|1.1%|0.6%|
[blocklist_de_mail](#blocklist_de_mail)|16382|16382|2|0.0%|0.6%|
[blocklist_de_ftp](#blocklist_de_ftp)|867|867|2|0.2%|0.6%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|1|0.0%|0.3%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|1|0.0%|0.3%|
[ri_web_proxies](#ri_web_proxies)|6611|6611|1|0.0%|0.3%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.3%|
[fullbogons](#fullbogons)|3721|670267288|1|0.0%|0.3%|
[et_block](#et_block)|1023|18338662|1|0.0%|0.3%|
[bogons](#bogons)|13|592708608|1|0.0%|0.3%|

## php_spammers

[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) spam servers (IPs used by spammers to send messages) (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=s&rss=1).

The last time downloaded was found to be dated: Sat Jun  6 13:36:12 UTC 2015.

The ipset `php_spammers` has **536** entries, **536** unique IPs.

The following table shows the overlaps of `php_spammers` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `php_spammers`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `php_spammers`.
- ` this % ` is the percentage **of this ipset (`php_spammers`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[php_dictionary](#php_dictionary)|545|545|180|33.0%|33.5%|
[sorbs_spam](#sorbs_spam)|30553|30553,31638|133|0.4%|24.8%|
[sorbs_recent_spam](#sorbs_recent_spam)|30553|30553,31638|133|0.4%|24.8%|
[sorbs_new_spam](#sorbs_new_spam)|30553|30553,31638|133|0.4%|24.8%|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|117|0.1%|21.8%|
[blocklist_de](#blocklist_de)|26186|26186|94|0.3%|17.5%|
[snort_ipfilter](#snort_ipfilter)|9943|9943|76|0.7%|14.1%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|66|0.2%|12.3%|
[nixspam](#nixspam)|17534|17534|61|0.3%|11.3%|
[blocklist_de_mail](#blocklist_de_mail)|16382|16382|60|0.3%|11.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|45|0.0%|8.3%|
[stopforumspam_1d](#stopforumspam_1d)|6922|6922|38|0.5%|7.0%|
[ri_web_proxies](#ri_web_proxies)|6611|6611|38|0.5%|7.0%|
[php_commenters](#php_commenters)|326|326|36|11.0%|6.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|31|0.0%|5.7%|
[sorbs_web](#sorbs_web)|667|667,668|27|4.0%|5.0%|
[xroxy](#xroxy)|2099|2099|26|1.2%|4.8%|
[blocklist_de_bots](#blocklist_de_bots)|3020|3020|26|0.8%|4.8%|
[proxz](#proxz)|886|886|17|1.9%|3.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|7|0.0%|1.3%|
[et_tor](#et_tor)|6470|6470|6|0.0%|1.1%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|3873|3873|6|0.1%|1.1%|
[blocklist_de_apache](#blocklist_de_apache)|15231|15231|6|0.0%|1.1%|
[dm_tor](#dm_tor)|6521|6521|5|0.0%|0.9%|
[bm_tor](#bm_tor)|6525|6525|5|0.0%|0.9%|
[blocklist_de_strongips](#blocklist_de_strongips)|180|180|5|2.7%|0.9%|
[alienvault_reputation](#alienvault_reputation)|180710|180710|5|0.0%|0.9%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|4|1.0%|0.7%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|3|0.0%|0.5%|
[ri_connect_proxies](#ri_connect_proxies)|2461|2461|3|0.1%|0.5%|
[proxyrss](#proxyrss)|1524|1524|3|0.1%|0.5%|
[php_harvesters](#php_harvesters)|311|311|2|0.6%|0.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2|0.0%|0.3%|
[et_block](#et_block)|1023|18338662|2|0.0%|0.3%|
[blocklist_de_ftp](#blocklist_de_ftp)|867|867|2|0.2%|0.3%|
[sorbs_socks](#sorbs_socks)|20|20,20|1|5.0%|0.1%|
[sorbs_misc](#sorbs_misc)|20|20,20|1|5.0%|0.1%|
[sorbs_http](#sorbs_http)|20|20,20|1|5.0%|0.1%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1|0.0%|0.1%|

## proxyrss

[proxyrss.com](http://www.proxyrss.com) open proxies syndicated from multiple sources.

Source is downloaded from [this link](http://www.proxyrss.com/proxylists/all.gz).

The last time downloaded was found to be dated: Sat Jun  6 12:51:29 UTC 2015.

The ipset `proxyrss` has **1524** entries, **1524** unique IPs.

The following table shows the overlaps of `proxyrss` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `proxyrss`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `proxyrss`.
- ` this % ` is the percentage **of this ipset (`proxyrss`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|759|0.8%|49.8%|
[ri_web_proxies](#ri_web_proxies)|6611|6611|642|9.7%|42.1%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|608|2.0%|39.8%|
[xroxy](#xroxy)|2099|2099|405|19.2%|26.5%|
[stopforumspam_1d](#stopforumspam_1d)|6922|6922|341|4.9%|22.3%|
[proxz](#proxz)|886|886|250|28.2%|16.4%|
[ri_connect_proxies](#ri_connect_proxies)|2461|2461|240|9.7%|15.7%|
[blocklist_de](#blocklist_de)|26186|26186|208|0.7%|13.6%|
[blocklist_de_bots](#blocklist_de_bots)|3020|3020|207|6.8%|13.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|71|0.0%|4.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|61|0.0%|4.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|43|0.0%|2.8%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|10|1.4%|0.6%|
[nixspam](#nixspam)|17534|17534|9|0.0%|0.5%|
[sorbs_spam](#sorbs_spam)|30553|30553,31638|8|0.0%|0.5%|
[sorbs_recent_spam](#sorbs_recent_spam)|30553|30553,31638|8|0.0%|0.5%|
[sorbs_new_spam](#sorbs_new_spam)|30553|30553,31638|8|0.0%|0.5%|
[blocklist_de_strongips](#blocklist_de_strongips)|180|180|5|2.7%|0.3%|
[php_commenters](#php_commenters)|326|326|4|1.2%|0.2%|
[snort_ipfilter](#snort_ipfilter)|9943|9943|3|0.0%|0.1%|
[php_spammers](#php_spammers)|536|536|3|0.5%|0.1%|
[php_harvesters](#php_harvesters)|311|311|2|0.6%|0.1%|
[sorbs_web](#sorbs_web)|667|667,668|1|0.1%|0.0%|
[php_dictionary](#php_dictionary)|545|545|1|0.1%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1|0.0%|0.0%|
[et_compromised](#et_compromised)|2016|2016|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1870|1870|1|0.0%|0.0%|
[alienvault_reputation](#alienvault_reputation)|180710|180710|1|0.0%|0.0%|

## proxz

[proxz.com](http://www.proxz.com) open proxies (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.proxz.com/proxylists.xml).

The last time downloaded was found to be dated: Sat Jun  6 12:51:34 UTC 2015.

The ipset `proxz` has **886** entries, **886** unique IPs.

The following table shows the overlaps of `proxz` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `proxz`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `proxz`.
- ` this % ` is the percentage **of this ipset (`proxz`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|535|0.5%|60.3%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|419|1.3%|47.2%|
[ri_web_proxies](#ri_web_proxies)|6611|6611|403|6.0%|45.4%|
[xroxy](#xroxy)|2099|2099|345|16.4%|38.9%|
[proxyrss](#proxyrss)|1524|1524|250|16.4%|28.2%|
[stopforumspam_1d](#stopforumspam_1d)|6922|6922|156|2.2%|17.6%|
[ri_connect_proxies](#ri_connect_proxies)|2461|2461|145|5.8%|16.3%|
[blocklist_de](#blocklist_de)|26186|26186|142|0.5%|16.0%|
[blocklist_de_bots](#blocklist_de_bots)|3020|3020|120|3.9%|13.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|72|0.0%|8.1%|
[sorbs_spam](#sorbs_spam)|30553|30553,31638|42|0.1%|4.7%|
[sorbs_recent_spam](#sorbs_recent_spam)|30553|30553,31638|42|0.1%|4.7%|
[sorbs_new_spam](#sorbs_new_spam)|30553|30553,31638|42|0.1%|4.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|37|0.0%|4.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|31|0.0%|3.4%|
[snort_ipfilter](#snort_ipfilter)|9943|9943|23|0.2%|2.5%|
[blocklist_de_mail](#blocklist_de_mail)|16382|16382|22|0.1%|2.4%|
[php_spammers](#php_spammers)|536|536|17|3.1%|1.9%|
[nixspam](#nixspam)|17534|17534|16|0.0%|1.8%|
[php_dictionary](#php_dictionary)|545|545|14|2.5%|1.5%|
[sorbs_web](#sorbs_web)|667|667,668|11|1.6%|1.2%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|6|0.8%|0.6%|
[php_commenters](#php_commenters)|326|326|4|1.2%|0.4%|
[blocklist_de_strongips](#blocklist_de_strongips)|180|180|4|2.2%|0.4%|
[alienvault_reputation](#alienvault_reputation)|180710|180710|3|0.0%|0.3%|
[et_compromised](#et_compromised)|2016|2016|2|0.0%|0.2%|
[bruteforceblocker](#bruteforceblocker)|1870|1870|2|0.1%|0.2%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1|0.0%|0.1%|

## ri_connect_proxies

[rosinstrument.com](http://www.rosinstrument.com) open CONNECT proxies (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://tools.rosinstrument.com/proxy/plab100.xml).

The last time downloaded was found to be dated: Sat Jun  6 12:08:49 UTC 2015.

The ipset `ri_connect_proxies` has **2461** entries, **2461** unique IPs.

The following table shows the overlaps of `ri_connect_proxies` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ri_connect_proxies`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ri_connect_proxies`.
- ` this % ` is the percentage **of this ipset (`ri_connect_proxies`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|1416|1.5%|57.5%|
[ri_web_proxies](#ri_web_proxies)|6611|6611|1017|15.3%|41.3%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|650|2.1%|26.4%|
[xroxy](#xroxy)|2099|2099|365|17.3%|14.8%|
[proxyrss](#proxyrss)|1524|1524|240|15.7%|9.7%|
[proxz](#proxz)|886|886|145|16.3%|5.8%|
[stopforumspam_1d](#stopforumspam_1d)|6922|6922|131|1.8%|5.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|96|0.0%|3.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|78|0.0%|3.1%|
[blocklist_de](#blocklist_de)|26186|26186|67|0.2%|2.7%|
[blocklist_de_bots](#blocklist_de_bots)|3020|3020|64|2.1%|2.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|53|0.0%|2.1%|
[sorbs_spam](#sorbs_spam)|30553|30553,31638|11|0.0%|0.4%|
[sorbs_recent_spam](#sorbs_recent_spam)|30553|30553,31638|11|0.0%|0.4%|
[sorbs_new_spam](#sorbs_new_spam)|30553|30553,31638|11|0.0%|0.4%|
[nixspam](#nixspam)|17534|17534|9|0.0%|0.3%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|7|1.0%|0.2%|
[php_commenters](#php_commenters)|326|326|4|1.2%|0.1%|
[snort_ipfilter](#snort_ipfilter)|9943|9943|3|0.0%|0.1%|
[php_spammers](#php_spammers)|536|536|3|0.5%|0.1%|
[php_dictionary](#php_dictionary)|545|545|3|0.5%|0.1%|
[blocklist_de_mail](#blocklist_de_mail)|16382|16382|3|0.0%|0.1%|
[alienvault_reputation](#alienvault_reputation)|180710|180710|3|0.0%|0.1%|
[sorbs_web](#sorbs_web)|667|667,668|1|0.1%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.0%|
[et_tor](#et_tor)|6470|6470|1|0.0%|0.0%|
[dm_tor](#dm_tor)|6521|6521|1|0.0%|0.0%|
[bm_tor](#bm_tor)|6525|6525|1|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|1555|1555|1|0.0%|0.0%|

## ri_web_proxies

[rosinstrument.com](http://www.rosinstrument.com) open HTTP proxies (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://tools.rosinstrument.com/proxy/l100.xml).

The last time downloaded was found to be dated: Sat Jun  6 13:42:03 UTC 2015.

The ipset `ri_web_proxies` has **6611** entries, **6611** unique IPs.

The following table shows the overlaps of `ri_web_proxies` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ri_web_proxies`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ri_web_proxies`.
- ` this % ` is the percentage **of this ipset (`ri_web_proxies`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|3188|3.4%|48.2%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|1616|5.3%|24.4%|
[ri_connect_proxies](#ri_connect_proxies)|2461|2461|1017|41.3%|15.3%|
[xroxy](#xroxy)|2099|2099|898|42.7%|13.5%|
[proxyrss](#proxyrss)|1524|1524|642|42.1%|9.7%|
[stopforumspam_1d](#stopforumspam_1d)|6922|6922|462|6.6%|6.9%|
[proxz](#proxz)|886|886|403|45.4%|6.0%|
[blocklist_de](#blocklist_de)|26186|26186|379|1.4%|5.7%|
[blocklist_de_bots](#blocklist_de_bots)|3020|3020|322|10.6%|4.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|192|0.0%|2.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|190|0.0%|2.8%|
[sorbs_spam](#sorbs_spam)|30553|30553,31638|138|0.4%|2.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|30553|30553,31638|138|0.4%|2.0%|
[sorbs_new_spam](#sorbs_new_spam)|30553|30553,31638|138|0.4%|2.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|134|0.0%|2.0%|
[snort_ipfilter](#snort_ipfilter)|9943|9943|66|0.6%|0.9%|
[blocklist_de_mail](#blocklist_de_mail)|16382|16382|56|0.3%|0.8%|
[nixspam](#nixspam)|17534|17534|50|0.2%|0.7%|
[php_dictionary](#php_dictionary)|545|545|43|7.8%|0.6%|
[php_spammers](#php_spammers)|536|536|38|7.0%|0.5%|
[sorbs_web](#sorbs_web)|667|667,668|24|3.5%|0.3%|
[php_commenters](#php_commenters)|326|326|19|5.8%|0.2%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|12|1.7%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|5|0.0%|0.0%|
[et_tor](#et_tor)|6470|6470|5|0.0%|0.0%|
[dm_tor](#dm_tor)|6521|6521|5|0.0%|0.0%|
[bm_tor](#bm_tor)|6525|6525|5|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|180|180|5|2.7%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|4|1.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|3|0.0%|0.0%|
[alienvault_reputation](#alienvault_reputation)|180710|180710|3|0.0%|0.0%|
[sslbl](#sslbl)|369|369|1|0.2%|0.0%|
[php_harvesters](#php_harvesters)|311|311|1|0.3%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|
[et_compromised](#et_compromised)|2016|2016|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1870|1870|1|0.0%|0.0%|

## shunlist

[AutoShun.org](http://autoshun.org/) IPs identified as hostile by correlating logs from distributed snort installations running the autoshun plugin

Source is downloaded from [this link](http://www.autoshun.org/files/shunlist.csv).

The last time downloaded was found to be dated: Sat Jun  6 10:30:06 UTC 2015.

The ipset `shunlist` has **1259** entries, **1259** unique IPs.

The following table shows the overlaps of `shunlist` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `shunlist`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `shunlist`.
- ` this % ` is the percentage **of this ipset (`shunlist`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[alienvault_reputation](#alienvault_reputation)|180710|180710|1251|0.6%|99.3%|
[openbl_60d](#openbl_60d)|7563|7563|567|7.4%|45.0%|
[openbl_30d](#openbl_30d)|3251|3251|552|16.9%|43.8%|
[et_compromised](#et_compromised)|2016|2016|460|22.8%|36.5%|
[bruteforceblocker](#bruteforceblocker)|1870|1870|451|24.1%|35.8%|
[blocklist_de](#blocklist_de)|26186|26186|366|1.3%|29.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1675|1675|327|19.5%|25.9%|
[openbl_7d](#openbl_7d)|856|856|245|28.6%|19.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|113|0.0%|8.9%|
[et_block](#et_block)|1023|18338662|111|0.0%|8.8%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|97|0.0%|7.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|73|0.0%|5.7%|
[openbl_1d](#openbl_1d)|140|140|66|47.1%|5.2%|
[dshield](#dshield)|20|5120|59|1.1%|4.6%|
[sslbl](#sslbl)|369|369|57|15.4%|4.5%|
[blocklist_de_apache](#blocklist_de_apache)|15231|15231|37|0.2%|2.9%|
[ciarmy](#ciarmy)|408|408|29|7.1%|2.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|28|0.0%|2.2%|
[blocklist_de_strongips](#blocklist_de_strongips)|180|180|20|11.1%|1.5%|
[voipbl](#voipbl)|10452|10864|12|0.1%|0.9%|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|4|0.0%|0.3%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|2|0.0%|0.1%|
[snort_ipfilter](#snort_ipfilter)|9943|9943|2|0.0%|0.1%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|2|0.5%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2|0.0%|0.1%|
[blocklist_de_mail](#blocklist_de_mail)|16382|16382|2|0.0%|0.1%|
[blocklist_de_imap](#blocklist_de_imap)|1555|1555|2|0.1%|0.1%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|3873|3873|2|0.0%|0.1%|
[stopforumspam_1d](#stopforumspam_1d)|6922|6922|1|0.0%|0.0%|
[sorbs_spam](#sorbs_spam)|30553|30553,31638|1|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|30553|30553,31638|1|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|30553|30553,31638|1|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.0%|
[et_tor](#et_tor)|6470|6470|1|0.0%|0.0%|
[dm_tor](#dm_tor)|6521|6521|1|0.0%|0.0%|
[bm_tor](#bm_tor)|6525|6525|1|0.0%|0.0%|

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
[bm_tor](#bm_tor)|6525|6525|1081|16.5%|10.8%|
[dm_tor](#dm_tor)|6521|6521|1080|16.5%|10.8%|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|803|0.8%|8.0%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|626|2.0%|6.2%|
[stopforumspam_1d](#stopforumspam_1d)|6922|6922|383|5.5%|3.8%|
[sorbs_spam](#sorbs_spam)|30553|30553,31638|315|0.9%|3.1%|
[sorbs_recent_spam](#sorbs_recent_spam)|30553|30553,31638|315|0.9%|3.1%|
[sorbs_new_spam](#sorbs_new_spam)|30553|30553,31638|315|0.9%|3.1%|
[et_block](#et_block)|1023|18338662|313|0.0%|3.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|232|0.0%|2.3%|
[zeus](#zeus)|231|231|202|87.4%|2.0%|
[zeus_badips](#zeus_badips)|202|202|179|88.6%|1.8%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|177|47.5%|1.7%|
[blocklist_de](#blocklist_de)|26186|26186|169|0.6%|1.6%|
[blocklist_de_mail](#blocklist_de_mail)|16382|16382|139|0.8%|1.3%|
[alienvault_reputation](#alienvault_reputation)|180710|180710|118|0.0%|1.1%|
[nixspam](#nixspam)|17534|17534|109|0.6%|1.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|103|0.0%|1.0%|
[php_dictionary](#php_dictionary)|545|545|79|14.4%|0.7%|
[feodo](#feodo)|99|99|79|79.7%|0.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|78|0.0%|0.7%|
[php_spammers](#php_spammers)|536|536|76|14.1%|0.7%|
[ri_web_proxies](#ri_web_proxies)|6611|6611|66|0.9%|0.6%|
[sorbs_web](#sorbs_web)|667|667,668|51|7.6%|0.5%|
[xroxy](#xroxy)|2099|2099|46|2.1%|0.4%|
[php_commenters](#php_commenters)|326|326|44|13.4%|0.4%|
[sslbl](#sslbl)|369|369|31|8.4%|0.3%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|28|2.1%|0.2%|
[openbl_60d](#openbl_60d)|7563|7563|27|0.3%|0.2%|
[blocklist_de_bots](#blocklist_de_bots)|3020|3020|24|0.7%|0.2%|
[proxz](#proxz)|886|886|23|2.5%|0.2%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|20|0.0%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|14|0.0%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|12|0.0%|0.1%|
[php_harvesters](#php_harvesters)|311|311|11|3.5%|0.1%|
[palevo](#palevo)|13|13|11|84.6%|0.1%|
[blocklist_de_apache](#blocklist_de_apache)|15231|15231|9|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|6|0.0%|0.0%|
[sorbs_socks](#sorbs_socks)|20|20,20|5|25.0%|0.0%|
[sorbs_misc](#sorbs_misc)|20|20,20|5|25.0%|0.0%|
[sorbs_http](#sorbs_http)|20|20,20|5|25.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|3873|3873|5|0.1%|0.0%|
[openbl_30d](#openbl_30d)|3251|3251|4|0.1%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2461|2461|3|0.1%|0.0%|
[proxyrss](#proxyrss)|1524|1524|3|0.1%|0.0%|
[shunlist](#shunlist)|1259|1259|2|0.1%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|2|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|1555|1555|2|0.1%|0.0%|
[openbl_7d](#openbl_7d)|856|856|1|0.1%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|
[dshield](#dshield)|20|5120|1|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|180|180|1|0.5%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1675|1675|1|0.0%|0.0%|

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

The last time downloaded was found to be dated: Sat Jun  6 14:04:11 UTC 2015.

The ipset `sorbs_http` has **20** entries, **20,20** unique IPs.

The following table shows the overlaps of `sorbs_http` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `sorbs_http`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `sorbs_http`.
- ` this % ` is the percentage **of this ipset (`sorbs_http`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[sorbs_spam](#sorbs_spam)|30553|30553,31638|20|0.0%|100.0%|
[sorbs_socks](#sorbs_socks)|20|20,20|20|100.0%|100.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|30553|30553,31638|20|0.0%|100.0%|
[sorbs_new_spam](#sorbs_new_spam)|30553|30553,31638|20|0.0%|100.0%|
[sorbs_misc](#sorbs_misc)|20|20,20|20|100.0%|100.0%|
[snort_ipfilter](#snort_ipfilter)|9943|9943|5|0.0%|25.0%|
[blocklist_de_mail](#blocklist_de_mail)|16382|16382|5|0.0%|25.0%|
[blocklist_de](#blocklist_de)|26186|26186|5|0.0%|25.0%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|3|0.0%|15.0%|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|3|0.0%|15.0%|
[sorbs_web](#sorbs_web)|667|667,668|3|0.4%|15.0%|
[php_dictionary](#php_dictionary)|545|545|2|0.3%|10.0%|
[nixspam](#nixspam)|17534|17534|2|0.0%|10.0%|
[xroxy](#xroxy)|2099|2099|1|0.0%|5.0%|
[php_spammers](#php_spammers)|536|536|1|0.1%|5.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|1|0.0%|5.0%|

## sorbs_misc

[Sorbs.net](https://www.sorbs.net/) MISC proxies, extracted from deltas.

Source is downloaded from [this link]().

The last time downloaded was found to be dated: Sat Jun  6 14:04:11 UTC 2015.

The ipset `sorbs_misc` has **20** entries, **20,20** unique IPs.

The following table shows the overlaps of `sorbs_misc` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `sorbs_misc`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `sorbs_misc`.
- ` this % ` is the percentage **of this ipset (`sorbs_misc`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[sorbs_spam](#sorbs_spam)|30553|30553,31638|20|0.0%|100.0%|
[sorbs_socks](#sorbs_socks)|20|20,20|20|100.0%|100.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|30553|30553,31638|20|0.0%|100.0%|
[sorbs_new_spam](#sorbs_new_spam)|30553|30553,31638|20|0.0%|100.0%|
[sorbs_http](#sorbs_http)|20|20,20|20|100.0%|100.0%|
[snort_ipfilter](#snort_ipfilter)|9943|9943|5|0.0%|25.0%|
[blocklist_de_mail](#blocklist_de_mail)|16382|16382|5|0.0%|25.0%|
[blocklist_de](#blocklist_de)|26186|26186|5|0.0%|25.0%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|3|0.0%|15.0%|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|3|0.0%|15.0%|
[sorbs_web](#sorbs_web)|667|667,668|3|0.4%|15.0%|
[php_dictionary](#php_dictionary)|545|545|2|0.3%|10.0%|
[nixspam](#nixspam)|17534|17534|2|0.0%|10.0%|
[xroxy](#xroxy)|2099|2099|1|0.0%|5.0%|
[php_spammers](#php_spammers)|536|536|1|0.1%|5.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|1|0.0%|5.0%|

## sorbs_new_spam

[Sorbs.net](https://www.sorbs.net/) NEW Spam senders, extracted from deltas.

Source is downloaded from [this link]().

The last time downloaded was found to be dated: Sat Jun  6 14:04:12 UTC 2015.

The ipset `sorbs_new_spam` has **30553** entries, **30553,31638** unique IPs.

The following table shows the overlaps of `sorbs_new_spam` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `sorbs_new_spam`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `sorbs_new_spam`.
- ` this % ` is the percentage **of this ipset (`sorbs_new_spam`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[sorbs_spam](#sorbs_spam)|30553|30553,31638|31638|100.0%|100.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|30553|30553,31638|31638|100.0%|100.0%|
[nixspam](#nixspam)|17534|17534|2492|14.2%|7.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|2313|0.0%|7.3%|
[blocklist_de](#blocklist_de)|26186|26186|1037|3.9%|3.2%|
[blocklist_de_mail](#blocklist_de_mail)|16382|16382|875|5.3%|2.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|789|0.0%|2.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|492|0.0%|1.5%|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|338|0.3%|1.0%|
[sorbs_web](#sorbs_web)|667|667,668|325|48.6%|1.0%|
[snort_ipfilter](#snort_ipfilter)|9943|9943|315|3.1%|0.9%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|181|0.6%|0.5%|
[php_dictionary](#php_dictionary)|545|545|149|27.3%|0.4%|
[ri_web_proxies](#ri_web_proxies)|6611|6611|138|2.0%|0.4%|
[php_spammers](#php_spammers)|536|536|133|24.8%|0.4%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|3873|3873|108|2.7%|0.3%|
[blocklist_de_apache](#blocklist_de_apache)|15231|15231|108|0.7%|0.3%|
[alienvault_reputation](#alienvault_reputation)|180710|180710|97|0.0%|0.3%|
[xroxy](#xroxy)|2099|2099|86|4.0%|0.2%|
[stopforumspam_1d](#stopforumspam_1d)|6922|6922|60|0.8%|0.1%|
[blocklist_de_bots](#blocklist_de_bots)|3020|3020|48|1.5%|0.1%|
[proxz](#proxz)|886|886|42|4.7%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|33|0.0%|0.1%|
[sorbs_socks](#sorbs_socks)|20|20,20|20|100.0%|0.0%|
[sorbs_misc](#sorbs_misc)|20|20,20|20|100.0%|0.0%|
[sorbs_http](#sorbs_http)|20|20,20|20|100.0%|0.0%|
[php_commenters](#php_commenters)|326|326|15|4.6%|0.0%|
[openbl_60d](#openbl_60d)|7563|7563|15|0.1%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|15|0.0%|0.0%|
[sorbs_smtp](#sorbs_smtp)|14|14,14|14|100.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2461|2461|11|0.4%|0.0%|
[et_block](#et_block)|1023|18338662|11|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|1555|1555|10|0.6%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|9|0.0%|0.0%|
[proxyrss](#proxyrss)|1524|1524|8|0.5%|0.0%|
[php_harvesters](#php_harvesters)|311|311|7|2.2%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|5|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|867|867|5|0.5%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|3|0.0%|0.0%|
[openbl_30d](#openbl_30d)|3251|3251|3|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|2|0.2%|0.0%|
[et_tor](#et_tor)|6470|6470|2|0.0%|0.0%|
[dshield](#dshield)|20|5120|2|0.0%|0.0%|
[dm_tor](#dm_tor)|6521|6521|2|0.0%|0.0%|
[bm_tor](#bm_tor)|6525|6525|2|0.0%|0.0%|
[shunlist](#shunlist)|1259|1259|1|0.0%|0.0%|
[openbl_7d](#openbl_7d)|856|856|1|0.1%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|1|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|180|180|1|0.5%|0.0%|

## sorbs_recent_spam

[Sorbs.net](https://www.sorbs.net/) RECENT Spam senders, extracted from deltas.

Source is downloaded from [this link]().

The last time downloaded was found to be dated: Sat Jun  6 14:04:11 UTC 2015.

The ipset `sorbs_recent_spam` has **30553** entries, **30553,31638** unique IPs.

The following table shows the overlaps of `sorbs_recent_spam` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `sorbs_recent_spam`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `sorbs_recent_spam`.
- ` this % ` is the percentage **of this ipset (`sorbs_recent_spam`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[sorbs_spam](#sorbs_spam)|30553|30553,31638|31638|100.0%|100.0%|
[sorbs_new_spam](#sorbs_new_spam)|30553|30553,31638|31638|100.0%|100.0%|
[nixspam](#nixspam)|17534|17534|2492|14.2%|7.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|2313|0.0%|7.3%|
[blocklist_de](#blocklist_de)|26186|26186|1037|3.9%|3.2%|
[blocklist_de_mail](#blocklist_de_mail)|16382|16382|875|5.3%|2.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|789|0.0%|2.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|492|0.0%|1.5%|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|338|0.3%|1.0%|
[sorbs_web](#sorbs_web)|667|667,668|325|48.6%|1.0%|
[snort_ipfilter](#snort_ipfilter)|9943|9943|315|3.1%|0.9%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|181|0.6%|0.5%|
[php_dictionary](#php_dictionary)|545|545|149|27.3%|0.4%|
[ri_web_proxies](#ri_web_proxies)|6611|6611|138|2.0%|0.4%|
[php_spammers](#php_spammers)|536|536|133|24.8%|0.4%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|3873|3873|108|2.7%|0.3%|
[blocklist_de_apache](#blocklist_de_apache)|15231|15231|108|0.7%|0.3%|
[alienvault_reputation](#alienvault_reputation)|180710|180710|97|0.0%|0.3%|
[xroxy](#xroxy)|2099|2099|86|4.0%|0.2%|
[stopforumspam_1d](#stopforumspam_1d)|6922|6922|60|0.8%|0.1%|
[blocklist_de_bots](#blocklist_de_bots)|3020|3020|48|1.5%|0.1%|
[proxz](#proxz)|886|886|42|4.7%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|33|0.0%|0.1%|
[sorbs_socks](#sorbs_socks)|20|20,20|20|100.0%|0.0%|
[sorbs_misc](#sorbs_misc)|20|20,20|20|100.0%|0.0%|
[sorbs_http](#sorbs_http)|20|20,20|20|100.0%|0.0%|
[php_commenters](#php_commenters)|326|326|15|4.6%|0.0%|
[openbl_60d](#openbl_60d)|7563|7563|15|0.1%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|15|0.0%|0.0%|
[sorbs_smtp](#sorbs_smtp)|14|14,14|14|100.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2461|2461|11|0.4%|0.0%|
[et_block](#et_block)|1023|18338662|11|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|1555|1555|10|0.6%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|9|0.0%|0.0%|
[proxyrss](#proxyrss)|1524|1524|8|0.5%|0.0%|
[php_harvesters](#php_harvesters)|311|311|7|2.2%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|5|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|867|867|5|0.5%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|3|0.0%|0.0%|
[openbl_30d](#openbl_30d)|3251|3251|3|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|2|0.2%|0.0%|
[et_tor](#et_tor)|6470|6470|2|0.0%|0.0%|
[dshield](#dshield)|20|5120|2|0.0%|0.0%|
[dm_tor](#dm_tor)|6521|6521|2|0.0%|0.0%|
[bm_tor](#bm_tor)|6525|6525|2|0.0%|0.0%|
[shunlist](#shunlist)|1259|1259|1|0.0%|0.0%|
[openbl_7d](#openbl_7d)|856|856|1|0.1%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|1|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|180|180|1|0.5%|0.0%|

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
[sorbs_spam](#sorbs_spam)|30553|30553,31638|14|0.0%|100.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|30553|30553,31638|14|0.0%|100.0%|
[sorbs_new_spam](#sorbs_new_spam)|30553|30553,31638|14|0.0%|100.0%|
[nixspam](#nixspam)|17534|17534|1|0.0%|7.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|1|0.0%|7.1%|

## sorbs_socks

[Sorbs.net](https://www.sorbs.net/) SOCKS proxies, extracted from deltas.

Source is downloaded from [this link]().

The last time downloaded was found to be dated: Sat Jun  6 14:04:11 UTC 2015.

The ipset `sorbs_socks` has **20** entries, **20,20** unique IPs.

The following table shows the overlaps of `sorbs_socks` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `sorbs_socks`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `sorbs_socks`.
- ` this % ` is the percentage **of this ipset (`sorbs_socks`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[sorbs_spam](#sorbs_spam)|30553|30553,31638|20|0.0%|100.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|30553|30553,31638|20|0.0%|100.0%|
[sorbs_new_spam](#sorbs_new_spam)|30553|30553,31638|20|0.0%|100.0%|
[sorbs_misc](#sorbs_misc)|20|20,20|20|100.0%|100.0%|
[sorbs_http](#sorbs_http)|20|20,20|20|100.0%|100.0%|
[snort_ipfilter](#snort_ipfilter)|9943|9943|5|0.0%|25.0%|
[blocklist_de_mail](#blocklist_de_mail)|16382|16382|5|0.0%|25.0%|
[blocklist_de](#blocklist_de)|26186|26186|5|0.0%|25.0%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|3|0.0%|15.0%|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|3|0.0%|15.0%|
[sorbs_web](#sorbs_web)|667|667,668|3|0.4%|15.0%|
[php_dictionary](#php_dictionary)|545|545|2|0.3%|10.0%|
[nixspam](#nixspam)|17534|17534|2|0.0%|10.0%|
[xroxy](#xroxy)|2099|2099|1|0.0%|5.0%|
[php_spammers](#php_spammers)|536|536|1|0.1%|5.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|1|0.0%|5.0%|

## sorbs_spam

[Sorbs.net](https://www.sorbs.net/) Spam senders, extracted from deltas.

Source is downloaded from [this link]().

The last time downloaded was found to be dated: Sat Jun  6 14:04:11 UTC 2015.

The ipset `sorbs_spam` has **30553** entries, **30553,31638** unique IPs.

The following table shows the overlaps of `sorbs_spam` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `sorbs_spam`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `sorbs_spam`.
- ` this % ` is the percentage **of this ipset (`sorbs_spam`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[sorbs_recent_spam](#sorbs_recent_spam)|30553|30553,31638|31638|100.0%|100.0%|
[sorbs_new_spam](#sorbs_new_spam)|30553|30553,31638|31638|100.0%|100.0%|
[nixspam](#nixspam)|17534|17534|2492|14.2%|7.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|2313|0.0%|7.3%|
[blocklist_de](#blocklist_de)|26186|26186|1037|3.9%|3.2%|
[blocklist_de_mail](#blocklist_de_mail)|16382|16382|875|5.3%|2.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|789|0.0%|2.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|492|0.0%|1.5%|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|338|0.3%|1.0%|
[sorbs_web](#sorbs_web)|667|667,668|325|48.6%|1.0%|
[snort_ipfilter](#snort_ipfilter)|9943|9943|315|3.1%|0.9%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|181|0.6%|0.5%|
[php_dictionary](#php_dictionary)|545|545|149|27.3%|0.4%|
[ri_web_proxies](#ri_web_proxies)|6611|6611|138|2.0%|0.4%|
[php_spammers](#php_spammers)|536|536|133|24.8%|0.4%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|3873|3873|108|2.7%|0.3%|
[blocklist_de_apache](#blocklist_de_apache)|15231|15231|108|0.7%|0.3%|
[alienvault_reputation](#alienvault_reputation)|180710|180710|97|0.0%|0.3%|
[xroxy](#xroxy)|2099|2099|86|4.0%|0.2%|
[stopforumspam_1d](#stopforumspam_1d)|6922|6922|60|0.8%|0.1%|
[blocklist_de_bots](#blocklist_de_bots)|3020|3020|48|1.5%|0.1%|
[proxz](#proxz)|886|886|42|4.7%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|33|0.0%|0.1%|
[sorbs_socks](#sorbs_socks)|20|20,20|20|100.0%|0.0%|
[sorbs_misc](#sorbs_misc)|20|20,20|20|100.0%|0.0%|
[sorbs_http](#sorbs_http)|20|20,20|20|100.0%|0.0%|
[php_commenters](#php_commenters)|326|326|15|4.6%|0.0%|
[openbl_60d](#openbl_60d)|7563|7563|15|0.1%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|15|0.0%|0.0%|
[sorbs_smtp](#sorbs_smtp)|14|14,14|14|100.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2461|2461|11|0.4%|0.0%|
[et_block](#et_block)|1023|18338662|11|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|1555|1555|10|0.6%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|9|0.0%|0.0%|
[proxyrss](#proxyrss)|1524|1524|8|0.5%|0.0%|
[php_harvesters](#php_harvesters)|311|311|7|2.2%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|5|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|867|867|5|0.5%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|3|0.0%|0.0%|
[openbl_30d](#openbl_30d)|3251|3251|3|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|2|0.2%|0.0%|
[et_tor](#et_tor)|6470|6470|2|0.0%|0.0%|
[dshield](#dshield)|20|5120|2|0.0%|0.0%|
[dm_tor](#dm_tor)|6521|6521|2|0.0%|0.0%|
[bm_tor](#bm_tor)|6525|6525|2|0.0%|0.0%|
[shunlist](#shunlist)|1259|1259|1|0.0%|0.0%|
[openbl_7d](#openbl_7d)|856|856|1|0.1%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|1|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|180|180|1|0.5%|0.0%|

## sorbs_web

[Sorbs.net](https://www.sorbs.net/) WEB exploits, extracted from deltas.

Source is downloaded from [this link]().

The last time downloaded was found to be dated: Sat Jun  6 14:04:11 UTC 2015.

The ipset `sorbs_web` has **667** entries, **667,668** unique IPs.

The following table shows the overlaps of `sorbs_web` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `sorbs_web`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `sorbs_web`.
- ` this % ` is the percentage **of this ipset (`sorbs_web`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[sorbs_spam](#sorbs_spam)|30553|30553,31638|325|1.0%|48.6%|
[sorbs_recent_spam](#sorbs_recent_spam)|30553|30553,31638|325|1.0%|48.6%|
[sorbs_new_spam](#sorbs_new_spam)|30553|30553,31638|325|1.0%|48.6%|
[nixspam](#nixspam)|17534|17534|87|0.4%|13.0%|
[blocklist_de](#blocklist_de)|26186|26186|74|0.2%|11.0%|
[blocklist_de_mail](#blocklist_de_mail)|16382|16382|56|0.3%|8.3%|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|51|0.0%|7.6%|
[snort_ipfilter](#snort_ipfilter)|9943|9943|51|0.5%|7.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|47|0.0%|7.0%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|37|0.1%|5.5%|
[php_dictionary](#php_dictionary)|545|545|29|5.3%|4.3%|
[php_spammers](#php_spammers)|536|536|27|5.0%|4.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|25|0.0%|3.7%|
[ri_web_proxies](#ri_web_proxies)|6611|6611|24|0.3%|3.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|21|0.0%|3.1%|
[xroxy](#xroxy)|2099|2099|16|0.7%|2.3%|
[stopforumspam_1d](#stopforumspam_1d)|6922|6922|16|0.2%|2.3%|
[blocklist_de_bots](#blocklist_de_bots)|3020|3020|15|0.4%|2.2%|
[proxz](#proxz)|886|886|11|1.2%|1.6%|
[sorbs_socks](#sorbs_socks)|20|20,20|3|15.0%|0.4%|
[sorbs_misc](#sorbs_misc)|20|20,20|3|15.0%|0.4%|
[sorbs_http](#sorbs_http)|20|20,20|3|15.0%|0.4%|
[php_commenters](#php_commenters)|326|326|3|0.9%|0.4%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|3873|3873|3|0.0%|0.4%|
[blocklist_de_apache](#blocklist_de_apache)|15231|15231|3|0.0%|0.4%|
[ri_connect_proxies](#ri_connect_proxies)|2461|2461|1|0.0%|0.1%|
[proxyrss](#proxyrss)|1524|1524|1|0.0%|0.1%|
[openbl_60d](#openbl_60d)|7563|7563|1|0.0%|0.1%|
[openbl_30d](#openbl_30d)|3251|3251|1|0.0%|0.1%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1|0.0%|0.1%|
[blocklist_de_strongips](#blocklist_de_strongips)|180|180|1|0.5%|0.1%|
[alienvault_reputation](#alienvault_reputation)|180710|180710|1|0.0%|0.1%|

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
[alienvault_reputation](#alienvault_reputation)|180710|180710|1631|0.9%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1037|0.3%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|1021|1.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|512|0.1%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|322|1.0%|0.0%|
[dshield](#dshield)|20|5120|256|5.0%|0.0%|
[openbl_60d](#openbl_60d)|7563|7563|239|3.1%|0.0%|
[blocklist_de](#blocklist_de)|26186|26186|179|0.6%|0.0%|
[openbl_30d](#openbl_30d)|3251|3251|160|4.9%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1675|1675|105|6.2%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1870|1870|101|5.4%|0.0%|
[et_compromised](#et_compromised)|2016|2016|100|4.9%|0.0%|
[shunlist](#shunlist)|1259|1259|97|7.7%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6922|6922|88|1.2%|0.0%|
[nixspam](#nixspam)|17534|17534|79|0.4%|0.0%|
[openbl_7d](#openbl_7d)|856|856|48|5.6%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3020|3020|42|1.3%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|29|2.2%|0.0%|
[php_commenters](#php_commenters)|326|326|28|8.5%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|16382|16382|26|0.1%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9943|9943|20|0.2%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|1555|1555|18|1.1%|0.0%|
[zeus_badips](#zeus_badips)|202|202|16|7.9%|0.0%|
[zeus](#zeus)|231|231|16|6.9%|0.0%|
[voipbl](#voipbl)|10452|10864|14|0.1%|0.0%|
[openbl_1d](#openbl_1d)|140|140|10|7.1%|0.0%|
[sorbs_spam](#sorbs_spam)|30553|30553,31638|9|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|30553|30553,31638|9|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|30553|30553,31638|9|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|180|180|7|3.8%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|6|0.4%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|6|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|3873|3873|5|0.1%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|15231|15231|5|0.0%|0.0%|
[php_dictionary](#php_dictionary)|545|545|4|0.7%|0.0%|
[malc0de](#malc0de)|361|361|4|1.1%|0.0%|
[php_spammers](#php_spammers)|536|536|3|0.5%|0.0%|
[dm_tor](#dm_tor)|6521|6521|3|0.0%|0.0%|
[bm_tor](#bm_tor)|6525|6525|3|0.0%|0.0%|
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
[alienvault_reputation](#alienvault_reputation)|180710|180710|15|0.0%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|11|0.0%|0.0%|
[php_commenters](#php_commenters)|326|326|7|2.1%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9943|9943|6|0.0%|0.0%|
[zeus_badips](#zeus_badips)|202|202|5|2.4%|0.0%|
[zeus](#zeus)|231|231|5|2.1%|0.0%|
[blocklist_de](#blocklist_de)|26186|26186|4|0.0%|0.0%|
[sorbs_spam](#sorbs_spam)|30553|30553,31638|3|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|30553|30553,31638|3|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|30553|30553,31638|3|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|180|180|3|1.6%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3020|3020|3|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6922|6922|2|0.0%|0.0%|
[php_harvesters](#php_harvesters)|311|311|1|0.3%|0.0%|
[openbl_60d](#openbl_60d)|7563|7563|1|0.0%|0.0%|
[openbl_30d](#openbl_30d)|3251|3251|1|0.0%|0.0%|
[malc0de](#malc0de)|361|361|1|0.2%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.0%|
[dm_tor](#dm_tor)|6521|6521|1|0.0%|0.0%|
[bm_tor](#bm_tor)|6525|6525|1|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|15231|15231|1|0.0%|0.0%|

## sslbl

[Abuse.ch SSL Blacklist](https://sslbl.abuse.ch/) bad SSL traffic related to malware or botnet activities - **excellent list**

Source is downloaded from [this link](https://sslbl.abuse.ch/blacklist/sslipblacklist.csv).

The last time downloaded was found to be dated: Sat Jun  6 14:15:07 UTC 2015.

The ipset `sslbl` has **369** entries, **369** unique IPs.

The following table shows the overlaps of `sslbl` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `sslbl`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `sslbl`.
- ` this % ` is the percentage **of this ipset (`sslbl`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[alienvault_reputation](#alienvault_reputation)|180710|180710|65|0.0%|17.6%|
[shunlist](#shunlist)|1259|1259|57|4.5%|15.4%|
[feodo](#feodo)|99|99|36|36.3%|9.7%|
[et_block](#et_block)|1023|18338662|35|0.0%|9.4%|
[snort_ipfilter](#snort_ipfilter)|9943|9943|31|0.3%|8.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|26|0.0%|7.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|5|0.0%|1.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|3|0.0%|0.8%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|1|0.0%|0.2%|
[ri_web_proxies](#ri_web_proxies)|6611|6611|1|0.0%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.2%|
[blocklist_de_ssh](#blocklist_de_ssh)|1675|1675|1|0.0%|0.2%|
[blocklist_de](#blocklist_de)|26186|26186|1|0.0%|0.2%|

## stopforumspam_1d

[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers in the last 24 hours - **excellent list**

Source is downloaded from [this link](http://www.stopforumspam.com/downloads/listed_ip_1.zip).

The last time downloaded was found to be dated: Sat Jun  6 14:00:01 UTC 2015.

The ipset `stopforumspam_1d` has **6922** entries, **6922** unique IPs.

The following table shows the overlaps of `stopforumspam_1d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `stopforumspam_1d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `stopforumspam_1d`.
- ` this % ` is the percentage **of this ipset (`stopforumspam_1d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|5468|5.8%|78.9%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|5250|17.4%|75.8%|
[blocklist_de](#blocklist_de)|26186|26186|1259|4.8%|18.1%|
[blocklist_de_bots](#blocklist_de_bots)|3020|3020|1196|39.6%|17.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|517|0.0%|7.4%|
[ri_web_proxies](#ri_web_proxies)|6611|6611|462|6.9%|6.6%|
[snort_ipfilter](#snort_ipfilter)|9943|9943|383|3.8%|5.5%|
[proxyrss](#proxyrss)|1524|1524|341|22.3%|4.9%|
[dm_tor](#dm_tor)|6521|6521|335|5.1%|4.8%|
[bm_tor](#bm_tor)|6525|6525|335|5.1%|4.8%|
[et_tor](#et_tor)|6470|6470|334|5.1%|4.8%|
[xroxy](#xroxy)|2099|2099|270|12.8%|3.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|192|0.0%|2.7%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|165|44.3%|2.3%|
[proxz](#proxz)|886|886|156|17.6%|2.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|139|0.0%|2.0%|
[ri_connect_proxies](#ri_connect_proxies)|2461|2461|131|5.3%|1.8%|
[php_commenters](#php_commenters)|326|326|125|38.3%|1.8%|
[blocklist_de_strongips](#blocklist_de_strongips)|180|180|106|58.8%|1.5%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|88|0.0%|1.2%|
[et_block](#et_block)|1023|18338662|83|0.0%|1.1%|
[blocklist_de_apache](#blocklist_de_apache)|15231|15231|67|0.4%|0.9%|
[sorbs_spam](#sorbs_spam)|30553|30553,31638|60|0.1%|0.8%|
[sorbs_recent_spam](#sorbs_recent_spam)|30553|30553,31638|60|0.1%|0.8%|
[sorbs_new_spam](#sorbs_new_spam)|30553|30553,31638|60|0.1%|0.8%|
[blocklist_de_mail](#blocklist_de_mail)|16382|16382|54|0.3%|0.7%|
[alienvault_reputation](#alienvault_reputation)|180710|180710|53|0.0%|0.7%|
[nixspam](#nixspam)|17534|17534|40|0.2%|0.5%|
[php_spammers](#php_spammers)|536|536|38|7.0%|0.5%|
[php_harvesters](#php_harvesters)|311|311|37|11.8%|0.5%|
[php_dictionary](#php_dictionary)|545|545|34|6.2%|0.4%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|25|0.0%|0.3%|
[openbl_60d](#openbl_60d)|7563|7563|21|0.2%|0.3%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|3873|3873|19|0.4%|0.2%|
[sorbs_web](#sorbs_web)|667|667,668|16|2.3%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|7|0.0%|0.1%|
[voipbl](#voipbl)|10452|10864|5|0.0%|0.0%|
[dshield](#dshield)|20|5120|4|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|3|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|2|0.0%|0.0%|
[openbl_30d](#openbl_30d)|3251|3251|2|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.0%|
[zeus_badips](#zeus_badips)|202|202|1|0.4%|0.0%|
[zeus](#zeus)|231|231|1|0.4%|0.0%|
[shunlist](#shunlist)|1259|1259|1|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|1|0.1%|0.0%|
[ciarmy](#ciarmy)|408|408|1|0.2%|0.0%|

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
[stopforumspam_1d](#stopforumspam_1d)|6922|6922|5468|78.9%|5.8%|
[ri_web_proxies](#ri_web_proxies)|6611|6611|3188|48.2%|3.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|2524|0.0%|2.7%|
[blocklist_de](#blocklist_de)|26186|26186|2328|8.8%|2.4%|
[blocklist_de_bots](#blocklist_de_bots)|3020|3020|1999|66.1%|2.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|1543|0.0%|1.6%|
[ri_connect_proxies](#ri_connect_proxies)|2461|2461|1416|57.5%|1.5%|
[xroxy](#xroxy)|2099|2099|1237|58.9%|1.3%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|1021|0.0%|1.0%|
[et_block](#et_block)|1023|18338662|1013|0.0%|1.0%|
[snort_ipfilter](#snort_ipfilter)|9943|9943|803|8.0%|0.8%|
[proxyrss](#proxyrss)|1524|1524|759|49.8%|0.8%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|744|0.0%|0.7%|
[et_tor](#et_tor)|6470|6470|647|10.0%|0.6%|
[dm_tor](#dm_tor)|6521|6521|639|9.7%|0.6%|
[bm_tor](#bm_tor)|6525|6525|639|9.7%|0.6%|
[proxz](#proxz)|886|886|535|60.3%|0.5%|
[sorbs_spam](#sorbs_spam)|30553|30553,31638|338|1.0%|0.3%|
[sorbs_recent_spam](#sorbs_recent_spam)|30553|30553,31638|338|1.0%|0.3%|
[sorbs_new_spam](#sorbs_new_spam)|30553|30553,31638|338|1.0%|0.3%|
[blocklist_de_mail](#blocklist_de_mail)|16382|16382|258|1.5%|0.2%|
[php_commenters](#php_commenters)|326|326|238|73.0%|0.2%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|231|62.0%|0.2%|
[blocklist_de_apache](#blocklist_de_apache)|15231|15231|222|1.4%|0.2%|
[alienvault_reputation](#alienvault_reputation)|180710|180710|205|0.1%|0.2%|
[nixspam](#nixspam)|17534|17534|158|0.9%|0.1%|
[blocklist_de_strongips](#blocklist_de_strongips)|180|180|131|72.7%|0.1%|
[php_spammers](#php_spammers)|536|536|117|21.8%|0.1%|
[php_dictionary](#php_dictionary)|545|545|103|18.8%|0.1%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|88|0.0%|0.0%|
[php_harvesters](#php_harvesters)|311|311|68|21.8%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|3873|3873|59|1.5%|0.0%|
[openbl_60d](#openbl_60d)|7563|7563|56|0.7%|0.0%|
[sorbs_web](#sorbs_web)|667|667,668|51|7.6%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|46|0.0%|0.0%|
[voipbl](#voipbl)|10452|10864|35|0.3%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|22|3.2%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|14|0.0%|0.0%|
[et_compromised](#et_compromised)|2016|2016|11|0.5%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1870|1870|11|0.5%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|867|867|10|1.1%|0.0%|
[dshield](#dshield)|20|5120|7|0.1%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1675|1675|6|0.3%|0.0%|
[openbl_30d](#openbl_30d)|3251|3251|5|0.1%|0.0%|
[shunlist](#shunlist)|1259|1259|4|0.3%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|4|0.3%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|1555|1555|4|0.2%|0.0%|
[sorbs_socks](#sorbs_socks)|20|20,20|3|15.0%|0.0%|
[sorbs_misc](#sorbs_misc)|20|20,20|3|15.0%|0.0%|
[sorbs_http](#sorbs_http)|20|20,20|3|15.0%|0.0%|
[openbl_7d](#openbl_7d)|856|856|3|0.3%|0.0%|
[zeus_badips](#zeus_badips)|202|202|2|0.9%|0.0%|
[zeus](#zeus)|231|231|2|0.8%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.0%|
[fullbogons](#fullbogons)|3721|670267288|2|0.0%|0.0%|
[ciarmy](#ciarmy)|408|408|1|0.2%|0.0%|
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
[stopforumspam_1d](#stopforumspam_1d)|6922|6922|5250|75.8%|17.4%|
[blocklist_de](#blocklist_de)|26186|26186|2004|7.6%|6.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|1912|0.0%|6.3%|
[blocklist_de_bots](#blocklist_de_bots)|3020|3020|1827|60.4%|6.0%|
[ri_web_proxies](#ri_web_proxies)|6611|6611|1616|24.4%|5.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|909|0.0%|3.0%|
[xroxy](#xroxy)|2099|2099|723|34.4%|2.4%|
[ri_connect_proxies](#ri_connect_proxies)|2461|2461|650|26.4%|2.1%|
[snort_ipfilter](#snort_ipfilter)|9943|9943|626|6.2%|2.0%|
[proxyrss](#proxyrss)|1524|1524|608|39.8%|2.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|568|0.0%|1.8%|
[et_tor](#et_tor)|6470|6470|516|7.9%|1.7%|
[dm_tor](#dm_tor)|6521|6521|506|7.7%|1.6%|
[bm_tor](#bm_tor)|6525|6525|506|7.7%|1.6%|
[proxz](#proxz)|886|886|419|47.2%|1.3%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|322|0.0%|1.0%|
[et_block](#et_block)|1023|18338662|314|0.0%|1.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|191|51.3%|0.6%|
[sorbs_spam](#sorbs_spam)|30553|30553,31638|181|0.5%|0.6%|
[sorbs_recent_spam](#sorbs_recent_spam)|30553|30553,31638|181|0.5%|0.6%|
[sorbs_new_spam](#sorbs_new_spam)|30553|30553,31638|181|0.5%|0.6%|
[php_commenters](#php_commenters)|326|326|171|52.4%|0.5%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|153|0.0%|0.5%|
[blocklist_de_mail](#blocklist_de_mail)|16382|16382|143|0.8%|0.4%|
[blocklist_de_apache](#blocklist_de_apache)|15231|15231|135|0.8%|0.4%|
[blocklist_de_strongips](#blocklist_de_strongips)|180|180|120|66.6%|0.3%|
[alienvault_reputation](#alienvault_reputation)|180710|180710|94|0.0%|0.3%|
[nixspam](#nixspam)|17534|17534|81|0.4%|0.2%|
[php_spammers](#php_spammers)|536|536|66|12.3%|0.2%|
[php_dictionary](#php_dictionary)|545|545|66|12.1%|0.2%|
[php_harvesters](#php_harvesters)|311|311|51|16.3%|0.1%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|3873|3873|38|0.9%|0.1%|
[sorbs_web](#sorbs_web)|667|667,668|37|5.5%|0.1%|
[openbl_60d](#openbl_60d)|7563|7563|26|0.3%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|25|0.0%|0.0%|
[voipbl](#voipbl)|10452|10864|12|0.1%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|12|1.7%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|11|0.0%|0.0%|
[et_compromised](#et_compromised)|2016|2016|7|0.3%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1870|1870|7|0.3%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|6|0.0%|0.0%|
[dshield](#dshield)|20|5120|5|0.0%|0.0%|
[sorbs_socks](#sorbs_socks)|20|20,20|3|15.0%|0.0%|
[sorbs_misc](#sorbs_misc)|20|20,20|3|15.0%|0.0%|
[sorbs_http](#sorbs_http)|20|20,20|3|15.0%|0.0%|
[shunlist](#shunlist)|1259|1259|2|0.1%|0.0%|
[openbl_30d](#openbl_30d)|3251|3251|2|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1675|1675|2|0.1%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|867|867|2|0.2%|0.0%|
[zeus_badips](#zeus_badips)|202|202|1|0.4%|0.0%|
[zeus](#zeus)|231|231|1|0.4%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|1|0.0%|0.0%|
[ciarmy](#ciarmy)|408|408|1|0.2%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|1555|1555|1|0.0%|0.0%|

## virbl

[VirBL](http://virbl.bit.nl/) is a project of which the idea was born during the RIPE-48 meeting. The plan was to get reports of virusscanning mailservers, and put the IP-addresses that were reported to send viruses on a blacklist.

Source is downloaded from [this link](http://virbl.bit.nl/download/virbl.dnsbl.bit.nl.txt).

The last time downloaded was found to be dated: Sat Jun  6 13:52:04 UTC 2015.

The ipset `virbl` has **4** entries, **4** unique IPs.

The following table shows the overlaps of `virbl` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `virbl`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `virbl`.
- ` this % ` is the percentage **of this ipset (`virbl`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|1|0.0%|25.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|1|0.0%|25.0%|

## voipbl

[VoIPBL.org](http://www.voipbl.org/) a distributed VoIP blacklist that is aimed to protects against VoIP Fraud and minimizing abuse for network that have publicly accessible PBX's. Several algorithms, external sources and manual confirmation are used before they categorize something as an attack and determine the threat level.

Source is downloaded from [this link](http://www.voipbl.org/update/).

The last time downloaded was found to be dated: Sat Jun  6 13:09:12 UTC 2015.

The ipset `voipbl` has **10452** entries, **10864** unique IPs.

The following table shows the overlaps of `voipbl` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `voipbl`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `voipbl`.
- ` this % ` is the percentage **of this ipset (`voipbl`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|1598|0.0%|14.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|434|0.0%|3.9%|
[fullbogons](#fullbogons)|3721|670267288|319|0.0%|2.9%|
[bogons](#bogons)|13|592708608|319|0.0%|2.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|299|0.0%|2.7%|
[alienvault_reputation](#alienvault_reputation)|180710|180710|209|0.1%|1.9%|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|35|0.0%|0.3%|
[blocklist_de](#blocklist_de)|26186|26186|32|0.1%|0.2%|
[blocklist_de_sip](#blocklist_de_sip)|90|90|24|26.6%|0.2%|
[et_block](#et_block)|1023|18338662|16|0.0%|0.1%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|14|0.0%|0.1%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|12|0.0%|0.1%|
[shunlist](#shunlist)|1259|1259|12|0.9%|0.1%|
[openbl_60d](#openbl_60d)|7563|7563|8|0.1%|0.0%|
[dshield](#dshield)|20|5120|6|0.1%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6922|6922|5|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|4|0.0%|0.0%|
[ciarmy](#ciarmy)|408|408|4|0.9%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3020|3020|4|0.1%|0.0%|
[openbl_30d](#openbl_30d)|3251|3251|3|0.0%|0.0%|
[et_tor](#et_tor)|6470|6470|3|0.0%|0.0%|
[dm_tor](#dm_tor)|6521|6521|3|0.0%|0.0%|
[bm_tor](#bm_tor)|6525|6525|3|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|15231|15231|3|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|2|0.0%|0.0%|
[et_compromised](#et_compromised)|2016|2016|2|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1870|1870|2|0.1%|0.0%|
[openbl_7d](#openbl_7d)|856|856|1|0.1%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|16382|16382|1|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|3873|3873|1|0.0%|0.0%|

## xroxy

[xroxy.com](http://www.xroxy.com) open proxies (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.xroxy.com/proxyrss.xml).

The last time downloaded was found to be dated: Sat Jun  6 13:33:01 UTC 2015.

The ipset `xroxy` has **2099** entries, **2099** unique IPs.

The following table shows the overlaps of `xroxy` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `xroxy`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `xroxy`.
- ` this % ` is the percentage **of this ipset (`xroxy`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|1237|1.3%|58.9%|
[ri_web_proxies](#ri_web_proxies)|6611|6611|898|13.5%|42.7%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|723|2.4%|34.4%|
[proxyrss](#proxyrss)|1524|1524|405|26.5%|19.2%|
[ri_connect_proxies](#ri_connect_proxies)|2461|2461|365|14.8%|17.3%|
[proxz](#proxz)|886|886|345|38.9%|16.4%|
[stopforumspam_1d](#stopforumspam_1d)|6922|6922|270|3.9%|12.8%|
[blocklist_de](#blocklist_de)|26186|26186|230|0.8%|10.9%|
[blocklist_de_bots](#blocklist_de_bots)|3020|3020|188|6.2%|8.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|101|0.0%|4.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|94|0.0%|4.4%|
[sorbs_spam](#sorbs_spam)|30553|30553,31638|86|0.2%|4.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|30553|30553,31638|86|0.2%|4.0%|
[sorbs_new_spam](#sorbs_new_spam)|30553|30553,31638|86|0.2%|4.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|58|0.0%|2.7%|
[snort_ipfilter](#snort_ipfilter)|9943|9943|46|0.4%|2.1%|
[blocklist_de_mail](#blocklist_de_mail)|16382|16382|42|0.2%|2.0%|
[nixspam](#nixspam)|17534|17534|36|0.2%|1.7%|
[php_dictionary](#php_dictionary)|545|545|32|5.8%|1.5%|
[php_spammers](#php_spammers)|536|536|26|4.8%|1.2%|
[sorbs_web](#sorbs_web)|667|667,668|16|2.3%|0.7%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|13|1.9%|0.6%|
[php_commenters](#php_commenters)|326|326|7|2.1%|0.3%|
[blocklist_de_strongips](#blocklist_de_strongips)|180|180|7|3.8%|0.3%|
[alienvault_reputation](#alienvault_reputation)|180710|180710|4|0.0%|0.1%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|3|0.0%|0.1%|
[php_harvesters](#php_harvesters)|311|311|2|0.6%|0.0%|
[et_tor](#et_tor)|6470|6470|2|0.0%|0.0%|
[dm_tor](#dm_tor)|6521|6521|2|0.0%|0.0%|
[bm_tor](#bm_tor)|6525|6525|2|0.0%|0.0%|
[sorbs_socks](#sorbs_socks)|20|20,20|1|5.0%|0.0%|
[sorbs_misc](#sorbs_misc)|20|20,20|1|5.0%|0.0%|
[sorbs_http](#sorbs_http)|20|20,20|1|5.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.0%|
[et_compromised](#et_compromised)|2016|2016|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1870|1870|1|0.0%|0.0%|

## zeus

[Abuse.ch Zeus tracker](https://zeustracker.abuse.ch) standard, contains the same data as the ZeuS IP blocklist (zeus_badips) but with the slight difference that it doesn't exclude hijacked websites (level 2) and free web hosting providers (level 3). This means that this blocklist contains all IPv4 addresses associated with ZeuS C&Cs which are currently being tracked by ZeuS Tracker. Hence this blocklist will likely cause some false positives. - **excellent list**

Source is downloaded from [this link](https://zeustracker.abuse.ch/blocklist.php?download=ipblocklist).

The last time downloaded was found to be dated: Sat Jun  6 12:29:54 UTC 2015.

The ipset `zeus` has **231** entries, **231** unique IPs.

The following table shows the overlaps of `zeus` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `zeus`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `zeus`.
- ` this % ` is the percentage **of this ipset (`zeus`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[et_block](#et_block)|1023|18338662|223|0.0%|96.5%|
[zeus_badips](#zeus_badips)|202|202|202|100.0%|87.4%|
[snort_ipfilter](#snort_ipfilter)|9943|9943|202|2.0%|87.4%|
[alienvault_reputation](#alienvault_reputation)|180710|180710|62|0.0%|26.8%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|16|0.0%|6.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|14|0.0%|6.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|10|0.0%|4.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|9|0.0%|3.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|6|0.0%|2.5%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|5|0.0%|2.1%|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|2|0.0%|0.8%|
[openbl_60d](#openbl_60d)|7563|7563|2|0.0%|0.8%|
[openbl_30d](#openbl_30d)|3251|3251|2|0.0%|0.8%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|1|0.0%|0.4%|
[stopforumspam_1d](#stopforumspam_1d)|6922|6922|1|0.0%|0.4%|
[php_commenters](#php_commenters)|326|326|1|0.3%|0.4%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.4%|

## zeus_badips

[Abuse.ch Zeus tracker](https://zeustracker.abuse.ch) badips includes IPv4 addresses that are used by the ZeuS trojan. It is the recommened blocklist if you want to block only ZeuS IPs. It excludes IP addresses that ZeuS Tracker believes to be hijacked (level 2) or belong to a free web hosting provider (level 3). Hence the false postive rate should be much lower compared to the standard ZeuS IP blocklist. **excellent list**

Source is downloaded from [this link](https://zeustracker.abuse.ch/blocklist.php?download=badips).

The last time downloaded was found to be dated: Sat Jun  6 14:27:10 UTC 2015.

The ipset `zeus_badips` has **202** entries, **202** unique IPs.

The following table shows the overlaps of `zeus_badips` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `zeus_badips`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `zeus_badips`.
- ` this % ` is the percentage **of this ipset (`zeus_badips`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[zeus](#zeus)|231|231|202|87.4%|100.0%|
[et_block](#et_block)|1023|18338662|200|0.0%|99.0%|
[snort_ipfilter](#snort_ipfilter)|9943|9943|179|1.8%|88.6%|
[alienvault_reputation](#alienvault_reputation)|180710|180710|38|0.0%|18.8%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|16|0.0%|7.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|10|0.0%|4.9%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|10|0.0%|4.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|8|0.0%|3.9%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|5|0.0%|2.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|4|0.0%|1.9%|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|2|0.0%|0.9%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|1|0.0%|0.4%|
[stopforumspam_1d](#stopforumspam_1d)|6922|6922|1|0.0%|0.4%|
[php_commenters](#php_commenters)|326|326|1|0.3%|0.4%|
[openbl_60d](#openbl_60d)|7563|7563|1|0.0%|0.4%|
[openbl_30d](#openbl_30d)|3251|3251|1|0.0%|0.4%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.4%|
