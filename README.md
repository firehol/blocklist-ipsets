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

The following list was automatically generated on Sat Jun  6 11:27:36 UTC 2015.

The update frequency is the maximum allowed by internal configuration. A list will never be downloaded sooner than the update frequency stated. A list may also not be downloaded, after this frequency expired, if it has not been modified on the server (as reported by HTTP `IF_MODIFIED_SINCE` method).

name|info|type|entries|update|
:--:|:--:|:--:|:-----:|:----:|
[alienvault_reputation](#alienvault_reputation)|[AlienVault.com](https://www.alienvault.com/) IP reputation database (this list seems to include port scanning hosts and to be updated regularly, but we found no information about its retention policy)|ipv4 hash:ip|180710 unique IPs|updated every 6 hours  from [this link](https://reputation.alienvault.com/reputation.generic)
[blocklist_de](#blocklist_de)|[Blocklist.de](https://www.blocklist.de/) IPs that have been detected by fail2ban in the last 48 hours - **excellent list**|ipv4 hash:ip|25421 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/all.txt)
[blocklist_de_apache](#blocklist_de_apache)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service Apache, Apache-DDOS, RFI-Attacks.|ipv4 hash:ip|15060 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/apache.txt)
[blocklist_de_bots](#blocklist_de_bots)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the RFI-Attacks, REG-Bots, IRC-Bots or BadBots (BadBots = he has posted a Spam-Comment on a open Forum or Wiki).|ipv4 hash:ip|3081 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/bots.txt)
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|[Blocklist.de](https://www.blocklist.de/) All IPs which attacks Joomlas, Wordpress and other Web-Logins with Brute-Force Logins.|ipv4 hash:ip|3708 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/bruteforcelogin.txt)
[blocklist_de_ftp](#blocklist_de_ftp)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours for attacks on the Service FTP.|ipv4 hash:ip|888 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/ftp.txt)
[blocklist_de_imap](#blocklist_de_imap)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours for attacks on the Service imap, sasl, pop3, etc.|ipv4 hash:ip|1804 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/imap.txt)
[blocklist_de_mail](#blocklist_de_mail)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service Mail, Postfix.|ipv4 hash:ip|15605 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/mail.txt)
[blocklist_de_sip](#blocklist_de_sip)|[Blocklist.de](https://www.blocklist.de/) All IP addresses that tried to login in a SIP, VOIP or Asterisk Server and are included in the IPs list from [infiltrated.net](www.infiltrated.net)|ipv4 hash:ip|87 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/sip.txt)
[blocklist_de_ssh](#blocklist_de_ssh)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service SSH.|ipv4 hash:ip|1764 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/ssh.txt)
[blocklist_de_strongips](#blocklist_de_strongips)|[Blocklist.de](https://www.blocklist.de/) All IPs which are older then 2 month and have more then 5.000 attacks.|ipv4 hash:ip|182 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/strongips.txt)
[bm_tor](#bm_tor)|[torstatus.blutmagie.de](https://torstatus.blutmagie.de) list of all TOR network servers|ipv4 hash:ip|6490 unique IPs|updated every 30 mins  from [this link](https://torstatus.blutmagie.de/ip_list_all.php/Tor_ip_list_ALL.csv)
[bogons](#bogons)|[Team-Cymru.org](http://www.team-cymru.org) private and reserved addresses defined by RFC 1918, RFC 5735, and RFC 6598 and netblocks that have not been allocated to a regional internet registry - **excellent list - use it only your internet interface**|ipv4 hash:net|13 subnets, 592708608 unique IPs|updated every 1 day  from [this link](http://www.team-cymru.org/Services/Bogons/bogon-bn-agg.txt)
[bruteforceblocker](#bruteforceblocker)|[danger.rulez.sk](http://danger.rulez.sk/) IPs detected by [bruteforceblocker](http://danger.rulez.sk/index.php/bruteforceblocker/) (fail2ban alternative for SSH on OpenBSD). This is an automatically generated list from users reporting failed authentication attempts. An IP seems to be included if 3 or more users report it. Its retention pocily seems 30 days.|ipv4 hash:ip|1892 unique IPs|updated every 3 hours  from [this link](http://danger.rulez.sk/projects/bruteforceblocker/blist.php)
[ciarmy](#ciarmy)|[CIArmy.com](http://ciarmy.com/) IPs with poor Rogue Packet score that have not yet been identified as malicious by the community|ipv4 hash:ip|402 unique IPs|updated every 3 hours  from [this link](http://cinsscore.com/list/ci-badguys.txt)
[cleanmx_viruses](#cleanmx_viruses)|[Clean-MX.de](http://support.clean-mx.de/clean-mx/viruses.php) IPs with viruses|ipv4 hash:ip|168 unique IPs|updated every 12 hours  from [this link](http://support.clean-mx.de/clean-mx/xmlviruses.php?sort=id%20desc&response=alive)
[dm_tor](#dm_tor)|[dan.me.uk](https://www.dan.me.uk) dynamic list of TOR exit points|ipv4 hash:ip|6485 unique IPs|updated every 30 mins  from [this link](https://www.dan.me.uk/torlist/)
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
[malc0de](#malc0de)|[Malc0de.com](http://malc0de.com) malicious IPs of the last 30 days|ipv4 hash:ip|371 unique IPs|updated every 1 day  from [this link](http://malc0de.com/bl/IP_Blacklist.txt)
[malwaredomainlist](#malwaredomainlist)|[malwaredomainlist.com](http://www.malwaredomainlist.com) list of malware active ip addresses|ipv4 hash:ip|1288 unique IPs|updated every 12 hours  from [this link](http://www.malwaredomainlist.com/hostslist/ip.txt)
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|[MaxMind.com](https://www.maxmind.com/en/anonymous-proxy-fraudulent-ip-address-list) list of anonymous proxy fraudelent IP addresses.|ipv4 hash:ip|372 unique IPs|updated every 4 hours  from [this link](https://www.maxmind.com/en/anonymous-proxy-fraudulent-ip-address-list)
[nixspam](#nixspam)|[NiX Spam](http://www.heise.de/ix/NiX-Spam-DNSBL-and-blacklist-for-download-499637.html) IP addresses that sent spam in the last hour - automatically generated entries without distinguishing open proxies from relays, dialup gateways, and so on. All IPs are removed after 12 hours if there is no spam from there.|ipv4 hash:ip|15861 unique IPs|updated every 15 mins  from [this link](http://www.dnsbl.manitu.net/download/nixspam-ip.dump.gz)
openbl|[OpenBL.org](http://www.openbl.org/) default blacklist (currently it is the same with 90 days). OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications - **excellent list**|ipv4 hash:ip|disabled|updated every 4 hours  from [this link](http://www.openbl.org/lists/base.txt)
openbl_180d|[OpenBL.org](http://www.openbl.org/) last 180 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|disabled|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_180days.txt)
[openbl_1d](#openbl_1d)|[OpenBL.org](http://www.openbl.org/) last 24 hours IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|143 unique IPs|updated every 1 hour  from [this link](http://www.openbl.org/lists/base_1days.txt)
[openbl_30d](#openbl_30d)|[OpenBL.org](http://www.openbl.org/) last 30 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|3251 unique IPs|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_30days.txt)
openbl_360d|[OpenBL.org](http://www.openbl.org/) last 360 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|disabled|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_360days.txt)
[openbl_60d](#openbl_60d)|[OpenBL.org](http://www.openbl.org/) last 60 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|7651 unique IPs|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_60days.txt)
[openbl_7d](#openbl_7d)|[OpenBL.org](http://www.openbl.org/) last 7 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|861 unique IPs|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_7days.txt)
openbl_90d|[OpenBL.org](http://www.openbl.org/) last 90 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|disabled|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_90days.txt)
openbl_all|[OpenBL.org](http://www.openbl.org/) last all IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|disabled|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_all.txt)
[palevo](#palevo)|[Abuse.ch Palevo tracker](https://palevotracker.abuse.ch) worm includes IPs which are being used as botnet C&C for the Palevo crimeware - **excellent list**|ipv4 hash:ip|13 unique IPs|updated every 30 mins  from [this link](https://palevotracker.abuse.ch/blocklists.php?download=ipblocklist)
php_bad|[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) bad web hosts (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|disabled|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=b&rss=1)
[php_commenters](#php_commenters)|[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) comment spammers (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|326 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=c&rss=1)
[php_dictionary](#php_dictionary)|[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) directory attackers (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|545 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=d&rss=1)
[php_harvesters](#php_harvesters)|[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) harvesters (IPs that surf the internet looking for email addresses) (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|311 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=h&rss=1)
[php_spammers](#php_spammers)|[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) spam servers (IPs used by spammers to send messages) (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|536 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=s&rss=1)
[proxyrss](#proxyrss)|[proxyrss.com](http://www.proxyrss.com) open proxies syndicated from multiple sources.|ipv4 hash:ip|1599 unique IPs|updated every 4 hours  from [this link](http://www.proxyrss.com/proxylists/all.gz)
[proxz](#proxz)|[proxz.com](http://www.proxz.com) open proxies (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|874 unique IPs|updated every 1 hour  from [this link](http://www.proxz.com/proxylists.xml)
[ri_connect_proxies](#ri_connect_proxies)|[rosinstrument.com](http://www.rosinstrument.com) open CONNECT proxies (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|2447 unique IPs|updated every 1 hour  from [this link](http://tools.rosinstrument.com/proxy/plab100.xml)
[ri_web_proxies](#ri_web_proxies)|[rosinstrument.com](http://www.rosinstrument.com) open HTTP proxies (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|6565 unique IPs|updated every 1 hour  from [this link](http://tools.rosinstrument.com/proxy/l100.xml)
[shunlist](#shunlist)|[AutoShun.org](http://autoshun.org/) IPs identified as hostile by correlating logs from distributed snort installations running the autoshun plugin|ipv4 hash:ip|1259 unique IPs|updated every 4 hours  from [this link](http://www.autoshun.org/files/shunlist.csv)
[snort_ipfilter](#snort_ipfilter)|[labs.snort.org](https://labs.snort.org/) supplied IP blacklist (this list seems to be updated frequently, but we found no information about it)|ipv4 hash:ip|8977 unique IPs|updated every 12 hours  from [this link](http://labs.snort.org/feeds/ip-filter.blf)
[sorbs_dul](#sorbs_dul)|[Sorbs.net](https://www.sorbs.net/) DUL, Dynamic User IPs extracted from deltas.|ipv4 hash:net|8 subnets, 3584 unique IPs|updated every 1 min  from [this link]()
[sorbs_http](#sorbs_http)|[Sorbs.net](https://www.sorbs.net/) HTTP proxies, extracted from deltas.|ipv4 hash:net|19 subnets, 19 unique IPs|updated every 1 min  from [this link]()
[sorbs_misc](#sorbs_misc)|[Sorbs.net](https://www.sorbs.net/) MISC proxies, extracted from deltas.|ipv4 hash:net|19 subnets, 19 unique IPs|updated every 1 min  from [this link]()
[sorbs_new_spam](#sorbs_new_spam)|[Sorbs.net](https://www.sorbs.net/) NEW Spam senders, extracted from deltas.|ipv4 hash:net|29892 subnets, 30945 unique IPs|updated every 1 min  from [this link]()
[sorbs_recent_spam](#sorbs_recent_spam)|[Sorbs.net](https://www.sorbs.net/) RECENT Spam senders, extracted from deltas.|ipv4 hash:net|29892 subnets, 30945 unique IPs|updated every 1 min  from [this link]()
[sorbs_smtp](#sorbs_smtp)|[Sorbs.net](https://www.sorbs.net/) SMTP Open Relays, extracted from deltas.|ipv4 hash:net|13 subnets, 13 unique IPs|updated every 1 min  from [this link]()
[sorbs_socks](#sorbs_socks)|[Sorbs.net](https://www.sorbs.net/) SOCKS proxies, extracted from deltas.|ipv4 hash:net|19 subnets, 19 unique IPs|updated every 1 min  from [this link]()
[sorbs_spam](#sorbs_spam)|[Sorbs.net](https://www.sorbs.net/) Spam senders, extracted from deltas.|ipv4 hash:net|29892 subnets, 30945 unique IPs|updated every 1 min  from [this link]()
[sorbs_web](#sorbs_web)|[Sorbs.net](https://www.sorbs.net/) WEB exploits, extracted from deltas.|ipv4 hash:net|654 subnets, 655 unique IPs|updated every 1 min  from [this link]()
[spamhaus_drop](#spamhaus_drop)|[Spamhaus.org](http://www.spamhaus.org) DROP list (according to their site this list should be dropped at tier-1 ISPs globaly) - **excellent list**|ipv4 hash:net|653 subnets, 18404096 unique IPs|updated every 12 hours  from [this link](http://www.spamhaus.org/drop/drop.txt)
[spamhaus_edrop](#spamhaus_edrop)|[Spamhaus.org](http://www.spamhaus.org) EDROP (extended matches that should be used with DROP) - **excellent list**|ipv4 hash:net|56 subnets, 487424 unique IPs|updated every 12 hours  from [this link](http://www.spamhaus.org/drop/edrop.txt)
[sslbl](#sslbl)|[Abuse.ch SSL Blacklist](https://sslbl.abuse.ch/) bad SSL traffic related to malware or botnet activities - **excellent list**|ipv4 hash:ip|370 unique IPs|updated every 30 mins  from [this link](https://sslbl.abuse.ch/blacklist/sslipblacklist.csv)
stopforumspam_180d|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 180 days)|ipv4 hash:ip|disabled|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/listed_ip_180.zip)
[stopforumspam_1d](#stopforumspam_1d)|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers in the last 24 hours - **excellent list**|ipv4 hash:ip|6954 unique IPs|updated every 1 hour  from [this link](http://www.stopforumspam.com/downloads/listed_ip_1.zip)
[stopforumspam_30d](#stopforumspam_30d)|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 30 days)|ipv4 hash:ip|93258 unique IPs|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/listed_ip_30.zip)
stopforumspam_365d|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 365 days)|ipv4 hash:ip|disabled|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/listed_ip_365.zip)
[stopforumspam_7d](#stopforumspam_7d)|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 7 days)|ipv4 hash:ip|30121 unique IPs|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/listed_ip_7.zip)
stopforumspam_90d|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 90 days)|ipv4 hash:ip|disabled|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/listed_ip_90.zip)
stopforumspam_ever|[StopForumSpam.com](http://www.stopforumspam.com) all IPs used by forum spammers, **ever** (normally you don't want to use this ipset, use the hourly one which includes last 24 hours IPs or the 7 days one)|ipv4 hash:ip|disabled|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/bannedips.zip)
[virbl](#virbl)|[VirBL](http://virbl.bit.nl/) is a project of which the idea was born during the RIPE-48 meeting. The plan was to get reports of virusscanning mailservers, and put the IP-addresses that were reported to send viruses on a blacklist.|ipv4 hash:ip|8 unique IPs|updated every 1 hour  from [this link](http://virbl.bit.nl/download/virbl.dnsbl.bit.nl.txt)
[voipbl](#voipbl)|[VoIPBL.org](http://www.voipbl.org/) a distributed VoIP blacklist that is aimed to protects against VoIP Fraud and minimizing abuse for network that have publicly accessible PBX's. Several algorithms, external sources and manual confirmation are used before they categorize something as an attack and determine the threat level.|ipv4 hash:net|10452 subnets, 10864 unique IPs|updated every 4 hours  from [this link](http://www.voipbl.org/update/)
[xroxy](#xroxy)|[xroxy.com](http://www.xroxy.com) open proxies (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|2098 unique IPs|updated every 1 hour  from [this link](http://www.xroxy.com/proxyrss.xml)
[zeus](#zeus)|[Abuse.ch Zeus tracker](https://zeustracker.abuse.ch) standard, contains the same data as the ZeuS IP blocklist (zeus_badips) but with the slight difference that it doesn't exclude hijacked websites (level 2) and free web hosting providers (level 3). This means that this blocklist contains all IPv4 addresses associated with ZeuS C&Cs which are currently being tracked by ZeuS Tracker. Hence this blocklist will likely cause some false positives. - **excellent list**|ipv4 hash:ip|230 unique IPs|updated every 30 mins  from [this link](https://zeustracker.abuse.ch/blocklist.php?download=ipblocklist)
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
[openbl_60d](#openbl_60d)|7651|7651|7631|99.7%|4.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|7538|0.0%|4.1%|
[et_block](#et_block)|1023|18338662|5280|0.0%|2.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|4735|0.0%|2.6%|
[dshield](#dshield)|20|5120|4355|85.0%|2.4%|
[openbl_30d](#openbl_30d)|3251|3251|3236|99.5%|1.7%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|1631|0.0%|0.9%|
[et_compromised](#et_compromised)|2016|2016|1312|65.0%|0.7%|
[shunlist](#shunlist)|1259|1259|1251|99.3%|0.6%|
[bruteforceblocker](#bruteforceblocker)|1892|1892|1227|64.8%|0.6%|
[blocklist_de](#blocklist_de)|25421|25421|1030|4.0%|0.5%|
[openbl_7d](#openbl_7d)|861|861|856|99.4%|0.4%|
[blocklist_de_ssh](#blocklist_de_ssh)|1764|1764|795|45.0%|0.4%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|518|0.0%|0.2%|
[ciarmy](#ciarmy)|402|402|398|99.0%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|287|0.0%|0.1%|
[voipbl](#voipbl)|10452|10864|209|1.9%|0.1%|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|205|0.2%|0.1%|
[openbl_1d](#openbl_1d)|143|143|138|96.5%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|15060|15060|133|0.8%|0.0%|
[snort_ipfilter](#snort_ipfilter)|8977|8977|119|1.3%|0.0%|
[sorbs_spam](#sorbs_spam)|29892|30945|105|0.3%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|29892|30945|105|0.3%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|29892|30945|105|0.3%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|94|0.3%|0.0%|
[sslbl](#sslbl)|370|370|65|17.5%|0.0%|
[zeus](#zeus)|230|230|62|26.9%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|15605|15605|60|0.3%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6954|6954|54|0.7%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|1804|1804|46|2.5%|0.0%|
[et_tor](#et_tor)|6470|6470|42|0.6%|0.0%|
[dm_tor](#dm_tor)|6485|6485|42|0.6%|0.0%|
[bm_tor](#bm_tor)|6490|6490|42|0.6%|0.0%|
[zeus_badips](#zeus_badips)|202|202|38|18.8%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|182|182|37|20.3%|0.0%|
[nixspam](#nixspam)|15861|15861|29|0.1%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3081|3081|29|0.9%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|26|6.9%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|3708|3708|21|0.5%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|87|87|16|18.3%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|15|0.0%|0.0%|
[php_commenters](#php_commenters)|326|326|15|4.6%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|15|0.0%|0.0%|
[malc0de](#malc0de)|371|371|11|2.9%|0.0%|
[php_harvesters](#php_harvesters)|311|311|10|3.2%|0.0%|
[php_dictionary](#php_dictionary)|545|545|8|1.4%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|8|0.5%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|168|168|7|4.1%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|888|888|7|0.7%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|6|0.4%|0.0%|
[php_spammers](#php_spammers)|536|536|5|0.9%|0.0%|
[et_botcc](#et_botcc)|509|509|5|0.9%|0.0%|
[xroxy](#xroxy)|2098|2098|4|0.1%|0.0%|
[ri_web_proxies](#ri_web_proxies)|6565|6565|3|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2447|2447|3|0.1%|0.0%|
[proxz](#proxz)|874|874|3|0.3%|0.0%|
[feodo](#feodo)|99|99|2|2.0%|0.0%|
[sorbs_web](#sorbs_web)|654|655|1|0.1%|0.0%|
[proxyrss](#proxyrss)|1599|1599|1|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|1|0.1%|0.0%|

## blocklist_de

[Blocklist.de](https://www.blocklist.de/) IPs that have been detected by fail2ban in the last 48 hours - **excellent list**

Source is downloaded from [this link](http://lists.blocklist.de/lists/all.txt).

The last time downloaded was found to be dated: Sat Jun  6 10:56:04 UTC 2015.

The ipset `blocklist_de` has **25421** entries, **25421** unique IPs.

The following table shows the overlaps of `blocklist_de` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de`.
- ` this % ` is the percentage **of this ipset (`blocklist_de`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de_mail](#blocklist_de_mail)|15605|15605|15590|99.9%|61.3%|
[blocklist_de_apache](#blocklist_de_apache)|15060|15060|15060|100.0%|59.2%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|3708|3708|3707|99.9%|14.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|3220|0.0%|12.6%|
[blocklist_de_bots](#blocklist_de_bots)|3081|3081|3081|100.0%|12.1%|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|2403|2.5%|9.4%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|2077|6.8%|8.1%|
[blocklist_de_imap](#blocklist_de_imap)|1804|1804|1795|99.5%|7.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1764|1764|1762|99.8%|6.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|1496|0.0%|5.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|1423|0.0%|5.5%|
[stopforumspam_1d](#stopforumspam_1d)|6954|6954|1299|18.6%|5.1%|
[sorbs_spam](#sorbs_spam)|29892|30945|1066|3.4%|4.1%|
[sorbs_recent_spam](#sorbs_recent_spam)|29892|30945|1066|3.4%|4.1%|
[sorbs_new_spam](#sorbs_new_spam)|29892|30945|1066|3.4%|4.1%|
[alienvault_reputation](#alienvault_reputation)|180710|180710|1030|0.5%|4.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|888|888|888|100.0%|3.4%|
[openbl_60d](#openbl_60d)|7651|7651|769|10.0%|3.0%|
[openbl_30d](#openbl_30d)|3251|3251|691|21.2%|2.7%|
[bruteforceblocker](#bruteforceblocker)|1892|1892|636|33.6%|2.5%|
[et_compromised](#et_compromised)|2016|2016|634|31.4%|2.4%|
[openbl_7d](#openbl_7d)|861|861|429|49.8%|1.6%|
[ri_web_proxies](#ri_web_proxies)|6565|6565|385|5.8%|1.5%|
[shunlist](#shunlist)|1259|1259|365|28.9%|1.4%|
[nixspam](#nixspam)|15861|15861|353|2.2%|1.3%|
[xroxy](#xroxy)|2098|2098|238|11.3%|0.9%|
[proxyrss](#proxyrss)|1599|1599|212|13.2%|0.8%|
[et_block](#et_block)|1023|18338662|195|0.0%|0.7%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|182|0.0%|0.7%|
[blocklist_de_strongips](#blocklist_de_strongips)|182|182|182|100.0%|0.7%|
[snort_ipfilter](#snort_ipfilter)|8977|8977|168|1.8%|0.6%|
[proxz](#proxz)|874|874|142|16.2%|0.5%|
[openbl_1d](#openbl_1d)|143|143|121|84.6%|0.4%|
[php_spammers](#php_spammers)|536|536|98|18.2%|0.3%|
[php_dictionary](#php_dictionary)|545|545|94|17.2%|0.3%|
[php_commenters](#php_commenters)|326|326|77|23.6%|0.3%|
[sorbs_web](#sorbs_web)|654|655|75|11.4%|0.2%|
[blocklist_de_sip](#blocklist_de_sip)|87|87|68|78.1%|0.2%|
[ri_connect_proxies](#ri_connect_proxies)|2447|2447|66|2.6%|0.2%|
[dshield](#dshield)|20|5120|64|1.2%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|54|0.0%|0.2%|
[ciarmy](#ciarmy)|402|402|34|8.4%|0.1%|
[voipbl](#voipbl)|10452|10864|33|0.3%|0.1%|
[php_harvesters](#php_harvesters)|311|311|30|9.6%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|13|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|12|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|5|0.0%|0.0%|
[sorbs_socks](#sorbs_socks)|19|19|5|26.3%|0.0%|
[sorbs_misc](#sorbs_misc)|19|19|5|26.3%|0.0%|
[sorbs_http](#sorbs_http)|19|19|5|26.3%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|4|0.5%|0.0%|
[et_tor](#et_tor)|6470|6470|4|0.0%|0.0%|
[dm_tor](#dm_tor)|6485|6485|4|0.0%|0.0%|
[bm_tor](#bm_tor)|6490|6490|4|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|3|0.8%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|3|0.2%|0.0%|
[sslbl](#sslbl)|370|370|1|0.2%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|168|168|1|0.5%|0.0%|

## blocklist_de_apache

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service Apache, Apache-DDOS, RFI-Attacks.

Source is downloaded from [this link](http://lists.blocklist.de/lists/apache.txt).

The last time downloaded was found to be dated: Sat Jun  6 10:56:08 UTC 2015.

The ipset `blocklist_de_apache` has **15060** entries, **15060** unique IPs.

The following table shows the overlaps of `blocklist_de_apache` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_apache`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_apache`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_apache`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|25421|25421|15060|59.2%|100.0%|
[blocklist_de_mail](#blocklist_de_mail)|15605|15605|11059|70.8%|73.4%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|3708|3708|3707|99.9%|24.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|2367|0.0%|15.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|1329|0.0%|8.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|1087|0.0%|7.2%|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|225|0.2%|1.4%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|138|0.4%|0.9%|
[alienvault_reputation](#alienvault_reputation)|180710|180710|133|0.0%|0.8%|
[sorbs_spam](#sorbs_spam)|29892|30945|104|0.3%|0.6%|
[sorbs_recent_spam](#sorbs_recent_spam)|29892|30945|104|0.3%|0.6%|
[sorbs_new_spam](#sorbs_new_spam)|29892|30945|104|0.3%|0.6%|
[stopforumspam_1d](#stopforumspam_1d)|6954|6954|70|1.0%|0.4%|
[shunlist](#shunlist)|1259|1259|35|2.7%|0.2%|
[blocklist_de_strongips](#blocklist_de_strongips)|182|182|33|18.1%|0.2%|
[ciarmy](#ciarmy)|402|402|31|7.7%|0.2%|
[php_commenters](#php_commenters)|326|326|25|7.6%|0.1%|
[blocklist_de_bots](#blocklist_de_bots)|3081|3081|23|0.7%|0.1%|
[nixspam](#nixspam)|15861|15861|22|0.1%|0.1%|
[dshield](#dshield)|20|5120|13|0.2%|0.0%|
[et_block](#et_block)|1023|18338662|12|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|8977|8977|9|0.1%|0.0%|
[openbl_60d](#openbl_60d)|7651|7651|7|0.0%|0.0%|
[php_spammers](#php_spammers)|536|536|6|1.1%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|6|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|5|0.0%|0.0%|
[php_harvesters](#php_harvesters)|311|311|5|1.6%|0.0%|
[openbl_30d](#openbl_30d)|3251|3251|5|0.1%|0.0%|
[php_dictionary](#php_dictionary)|545|545|4|0.7%|0.0%|
[et_tor](#et_tor)|6470|6470|4|0.0%|0.0%|
[dm_tor](#dm_tor)|6485|6485|4|0.0%|0.0%|
[bm_tor](#bm_tor)|6490|6490|4|0.0%|0.0%|
[voipbl](#voipbl)|10452|10864|3|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|3|0.0%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|0.0%|
[sorbs_web](#sorbs_web)|654|655|2|0.3%|0.0%|
[openbl_7d](#openbl_7d)|861|861|2|0.2%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|2|0.5%|0.0%|
[et_compromised](#et_compromised)|2016|2016|2|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1892|1892|2|0.1%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|1|0.0%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|168|168|1|0.5%|0.0%|

## blocklist_de_bots

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the RFI-Attacks, REG-Bots, IRC-Bots or BadBots (BadBots = he has posted a Spam-Comment on a open Forum or Wiki).

Source is downloaded from [this link](http://lists.blocklist.de/lists/bots.txt).

The last time downloaded was found to be dated: Sat Jun  6 10:56:12 UTC 2015.

The ipset `blocklist_de_bots` has **3081** entries, **3081** unique IPs.

The following table shows the overlaps of `blocklist_de_bots` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_bots`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_bots`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_bots`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|25421|25421|3081|12.1%|100.0%|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|2064|2.2%|66.9%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|1892|6.2%|61.4%|
[stopforumspam_1d](#stopforumspam_1d)|6954|6954|1234|17.7%|40.0%|
[ri_web_proxies](#ri_web_proxies)|6565|6565|330|5.0%|10.7%|
[proxyrss](#proxyrss)|1599|1599|212|13.2%|6.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|196|0.0%|6.3%|
[xroxy](#xroxy)|2098|2098|193|9.1%|6.2%|
[blocklist_de_strongips](#blocklist_de_strongips)|182|182|136|74.7%|4.4%|
[proxz](#proxz)|874|874|121|13.8%|3.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|113|0.0%|3.6%|
[ri_connect_proxies](#ri_connect_proxies)|2447|2447|63|2.5%|2.0%|
[php_commenters](#php_commenters)|326|326|63|19.3%|2.0%|
[sorbs_spam](#sorbs_spam)|29892|30945|45|0.1%|1.4%|
[sorbs_recent_spam](#sorbs_recent_spam)|29892|30945|45|0.1%|1.4%|
[sorbs_new_spam](#sorbs_new_spam)|29892|30945|45|0.1%|1.4%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|42|0.0%|1.3%|
[et_block](#et_block)|1023|18338662|42|0.0%|1.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|37|0.0%|1.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|35|0.0%|1.1%|
[alienvault_reputation](#alienvault_reputation)|180710|180710|29|0.0%|0.9%|
[php_spammers](#php_spammers)|536|536|25|4.6%|0.8%|
[snort_ipfilter](#snort_ipfilter)|8977|8977|23|0.2%|0.7%|
[php_harvesters](#php_harvesters)|311|311|23|7.3%|0.7%|
[blocklist_de_mail](#blocklist_de_mail)|15605|15605|23|0.1%|0.7%|
[blocklist_de_apache](#blocklist_de_apache)|15060|15060|23|0.1%|0.7%|
[nixspam](#nixspam)|15861|15861|21|0.1%|0.6%|
[php_dictionary](#php_dictionary)|545|545|20|3.6%|0.6%|
[sorbs_web](#sorbs_web)|654|655|13|1.9%|0.4%|
[openbl_60d](#openbl_60d)|7651|7651|10|0.1%|0.3%|
[voipbl](#voipbl)|10452|10864|5|0.0%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|5|0.0%|0.1%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|3|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|3|0.4%|0.0%|
[openbl_30d](#openbl_30d)|3251|3251|2|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.0%|
[et_compromised](#et_compromised)|2016|2016|2|0.0%|0.0%|
[dshield](#dshield)|20|5120|2|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1892|1892|2|0.1%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1|0.0%|0.0%|

## blocklist_de_bruteforce

[Blocklist.de](https://www.blocklist.de/) All IPs which attacks Joomlas, Wordpress and other Web-Logins with Brute-Force Logins.

Source is downloaded from [this link](http://lists.blocklist.de/lists/bruteforcelogin.txt).

The last time downloaded was found to be dated: Sat Jun  6 11:14:10 UTC 2015.

The ipset `blocklist_de_bruteforce` has **3708** entries, **3708** unique IPs.

The following table shows the overlaps of `blocklist_de_bruteforce` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_bruteforce`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_bruteforce`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_bruteforce`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de_apache](#blocklist_de_apache)|15060|15060|3707|24.6%|99.9%|
[blocklist_de](#blocklist_de)|25421|25421|3707|14.5%|99.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|268|0.0%|7.2%|
[sorbs_spam](#sorbs_spam)|29892|30945|104|0.3%|2.8%|
[sorbs_recent_spam](#sorbs_recent_spam)|29892|30945|104|0.3%|2.8%|
[sorbs_new_spam](#sorbs_new_spam)|29892|30945|104|0.3%|2.8%|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|59|0.0%|1.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|53|0.0%|1.4%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|38|0.1%|1.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|37|0.0%|0.9%|
[stopforumspam_1d](#stopforumspam_1d)|6954|6954|22|0.3%|0.5%|
[nixspam](#nixspam)|15861|15861|21|0.1%|0.5%|
[alienvault_reputation](#alienvault_reputation)|180710|180710|21|0.0%|0.5%|
[php_commenters](#php_commenters)|326|326|7|2.1%|0.1%|
[blocklist_de_strongips](#blocklist_de_strongips)|182|182|7|3.8%|0.1%|
[php_spammers](#php_spammers)|536|536|6|1.1%|0.1%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|6|0.0%|0.1%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|5|0.0%|0.1%|
[snort_ipfilter](#snort_ipfilter)|8977|8977|5|0.0%|0.1%|
[php_dictionary](#php_dictionary)|545|545|4|0.7%|0.1%|
[et_block](#et_block)|1023|18338662|4|0.0%|0.1%|
[php_harvesters](#php_harvesters)|311|311|3|0.9%|0.0%|
[sorbs_web](#sorbs_web)|654|655|2|0.3%|0.0%|
[shunlist](#shunlist)|1259|1259|2|0.1%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|2|0.0%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2|0.0%|0.0%|
[voipbl](#voipbl)|10452|10864|1|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[dshield](#dshield)|20|5120|1|0.0%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|168|168|1|0.5%|0.0%|
[ciarmy](#ciarmy)|402|402|1|0.2%|0.0%|

## blocklist_de_ftp

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours for attacks on the Service FTP.

Source is downloaded from [this link](http://lists.blocklist.de/lists/ftp.txt).

The last time downloaded was found to be dated: Sat Jun  6 10:56:09 UTC 2015.

The ipset `blocklist_de_ftp` has **888** entries, **888** unique IPs.

The following table shows the overlaps of `blocklist_de_ftp` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_ftp`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_ftp`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_ftp`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|25421|25421|888|3.4%|100.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|79|0.0%|8.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|15|0.0%|1.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|13|0.0%|1.4%|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|12|0.0%|1.3%|
[nixspam](#nixspam)|15861|15861|9|0.0%|1.0%|
[alienvault_reputation](#alienvault_reputation)|180710|180710|7|0.0%|0.7%|
[sorbs_spam](#sorbs_spam)|29892|30945|4|0.0%|0.4%|
[sorbs_recent_spam](#sorbs_recent_spam)|29892|30945|4|0.0%|0.4%|
[sorbs_new_spam](#sorbs_new_spam)|29892|30945|4|0.0%|0.4%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|3|0.0%|0.3%|
[php_spammers](#php_spammers)|536|536|2|0.3%|0.2%|
[php_harvesters](#php_harvesters)|311|311|2|0.6%|0.2%|
[openbl_60d](#openbl_60d)|7651|7651|2|0.0%|0.2%|
[blocklist_de_strongips](#blocklist_de_strongips)|182|182|2|1.0%|0.2%|
[php_dictionary](#php_dictionary)|545|545|1|0.1%|0.1%|
[openbl_30d](#openbl_30d)|3251|3251|1|0.0%|0.1%|
[ciarmy](#ciarmy)|402|402|1|0.2%|0.1%|

## blocklist_de_imap

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours for attacks on the Service imap, sasl, pop3, etc.

Source is downloaded from [this link](http://lists.blocklist.de/lists/imap.txt).

The last time downloaded was found to be dated: Sat Jun  6 11:14:06 UTC 2015.

The ipset `blocklist_de_imap` has **1804** entries, **1804** unique IPs.

The following table shows the overlaps of `blocklist_de_imap` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_imap`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_imap`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_imap`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de_mail](#blocklist_de_mail)|15605|15605|1804|11.5%|100.0%|
[blocklist_de](#blocklist_de)|25421|25421|1795|7.0%|99.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|170|0.0%|9.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|52|0.0%|2.8%|
[alienvault_reputation](#alienvault_reputation)|180710|180710|46|0.0%|2.5%|
[openbl_60d](#openbl_60d)|7651|7651|38|0.4%|2.1%|
[openbl_30d](#openbl_30d)|3251|3251|31|0.9%|1.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|28|0.0%|1.5%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|18|0.0%|0.9%|
[et_block](#et_block)|1023|18338662|18|0.0%|0.9%|
[nixspam](#nixspam)|15861|15861|14|0.0%|0.7%|
[sorbs_spam](#sorbs_spam)|29892|30945|12|0.0%|0.6%|
[sorbs_recent_spam](#sorbs_recent_spam)|29892|30945|12|0.0%|0.6%|
[sorbs_new_spam](#sorbs_new_spam)|29892|30945|12|0.0%|0.6%|
[openbl_7d](#openbl_7d)|861|861|11|1.2%|0.6%|
[et_compromised](#et_compromised)|2016|2016|6|0.2%|0.3%|
[bruteforceblocker](#bruteforceblocker)|1892|1892|6|0.3%|0.3%|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|5|0.0%|0.2%|
[snort_ipfilter](#snort_ipfilter)|8977|8977|3|0.0%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|2|0.0%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2|0.0%|0.1%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|2|0.0%|0.1%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|1|0.0%|0.0%|
[shunlist](#shunlist)|1259|1259|1|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2447|2447|1|0.0%|0.0%|
[openbl_1d](#openbl_1d)|143|143|1|0.6%|0.0%|
[ciarmy](#ciarmy)|402|402|1|0.2%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|182|182|1|0.5%|0.0%|

## blocklist_de_mail

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service Mail, Postfix.

Source is downloaded from [this link](http://lists.blocklist.de/lists/mail.txt).

The last time downloaded was found to be dated: Sat Jun  6 11:14:05 UTC 2015.

The ipset `blocklist_de_mail` has **15605** entries, **15605** unique IPs.

The following table shows the overlaps of `blocklist_de_mail` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_mail`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_mail`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_mail`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|25421|25421|15590|61.3%|99.9%|
[blocklist_de_apache](#blocklist_de_apache)|15060|15060|11059|73.4%|70.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|2453|0.0%|15.7%|
[blocklist_de_imap](#blocklist_de_imap)|1804|1804|1804|100.0%|11.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|1364|0.0%|8.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|1137|0.0%|7.2%|
[sorbs_spam](#sorbs_spam)|29892|30945|907|2.9%|5.8%|
[sorbs_recent_spam](#sorbs_recent_spam)|29892|30945|907|2.9%|5.8%|
[sorbs_new_spam](#sorbs_new_spam)|29892|30945|907|2.9%|5.8%|
[nixspam](#nixspam)|15861|15861|295|1.8%|1.8%|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|258|0.2%|1.6%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|143|0.4%|0.9%|
[snort_ipfilter](#snort_ipfilter)|8977|8977|137|1.5%|0.8%|
[php_dictionary](#php_dictionary)|545|545|67|12.2%|0.4%|
[php_spammers](#php_spammers)|536|536|63|11.7%|0.4%|
[alienvault_reputation](#alienvault_reputation)|180710|180710|60|0.0%|0.3%|
[sorbs_web](#sorbs_web)|654|655|59|9.0%|0.3%|
[ri_web_proxies](#ri_web_proxies)|6565|6565|55|0.8%|0.3%|
[stopforumspam_1d](#stopforumspam_1d)|6954|6954|52|0.7%|0.3%|
[xroxy](#xroxy)|2098|2098|45|2.1%|0.2%|
[openbl_60d](#openbl_60d)|7651|7651|43|0.5%|0.2%|
[openbl_30d](#openbl_30d)|3251|3251|36|1.1%|0.2%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|28|0.0%|0.1%|
[et_block](#et_block)|1023|18338662|28|0.0%|0.1%|
[blocklist_de_bots](#blocklist_de_bots)|3081|3081|23|0.7%|0.1%|
[blocklist_de_strongips](#blocklist_de_strongips)|182|182|22|12.0%|0.1%|
[proxz](#proxz)|874|874|21|2.4%|0.1%|
[php_commenters](#php_commenters)|326|326|21|6.4%|0.1%|
[openbl_7d](#openbl_7d)|861|861|12|1.3%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|6|0.0%|0.0%|
[et_compromised](#et_compromised)|2016|2016|6|0.2%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1892|1892|6|0.3%|0.0%|
[sorbs_socks](#sorbs_socks)|19|19|5|26.3%|0.0%|
[sorbs_misc](#sorbs_misc)|19|19|5|26.3%|0.0%|
[sorbs_http](#sorbs_http)|19|19|5|26.3%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|4|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|4|0.0%|0.0%|
[et_tor](#et_tor)|6470|6470|4|0.0%|0.0%|
[dm_tor](#dm_tor)|6485|6485|4|0.0%|0.0%|
[bm_tor](#bm_tor)|6490|6490|4|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2447|2447|3|0.1%|0.0%|
[voipbl](#voipbl)|10452|10864|1|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|1|0.0%|0.0%|
[shunlist](#shunlist)|1259|1259|1|0.0%|0.0%|
[php_harvesters](#php_harvesters)|311|311|1|0.3%|0.0%|
[openbl_1d](#openbl_1d)|143|143|1|0.6%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|1|0.1%|0.0%|
[dshield](#dshield)|20|5120|1|0.0%|0.0%|
[ciarmy](#ciarmy)|402|402|1|0.2%|0.0%|

## blocklist_de_sip

[Blocklist.de](https://www.blocklist.de/) All IP addresses that tried to login in a SIP, VOIP or Asterisk Server and are included in the IPs list from [infiltrated.net](www.infiltrated.net)

Source is downloaded from [this link](http://lists.blocklist.de/lists/sip.txt).

The last time downloaded was found to be dated: Sat Jun  6 11:10:10 UTC 2015.

The ipset `blocklist_de_sip` has **87** entries, **87** unique IPs.

The following table shows the overlaps of `blocklist_de_sip` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_sip`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_sip`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_sip`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|25421|25421|68|0.2%|78.1%|
[voipbl](#voipbl)|10452|10864|23|0.2%|26.4%|
[alienvault_reputation](#alienvault_reputation)|180710|180710|16|0.0%|18.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|12|0.0%|13.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|8|0.0%|9.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|3|0.0%|3.4%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|2|0.0%|2.2%|
[et_block](#et_block)|1023|18338662|2|0.0%|2.2%|
[dshield](#dshield)|20|5120|2|0.0%|2.2%|
[et_botcc](#et_botcc)|509|509|1|0.1%|1.1%|

## blocklist_de_ssh

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service SSH.

Source is downloaded from [this link](http://lists.blocklist.de/lists/ssh.txt).

The last time downloaded was found to be dated: Sat Jun  6 11:14:04 UTC 2015.

The ipset `blocklist_de_ssh` has **1764** entries, **1764** unique IPs.

The following table shows the overlaps of `blocklist_de_ssh` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_ssh`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_ssh`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_ssh`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|25421|25421|1762|6.9%|99.8%|
[alienvault_reputation](#alienvault_reputation)|180710|180710|795|0.4%|45.0%|
[openbl_60d](#openbl_60d)|7651|7651|705|9.2%|39.9%|
[openbl_30d](#openbl_30d)|3251|3251|648|19.9%|36.7%|
[bruteforceblocker](#bruteforceblocker)|1892|1892|625|33.0%|35.4%|
[et_compromised](#et_compromised)|2016|2016|623|30.9%|35.3%|
[openbl_7d](#openbl_7d)|861|861|414|48.0%|23.4%|
[shunlist](#shunlist)|1259|1259|329|26.1%|18.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|181|0.0%|10.2%|
[openbl_1d](#openbl_1d)|143|143|120|83.9%|6.8%|
[et_block](#et_block)|1023|18338662|111|0.0%|6.2%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|107|0.0%|6.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|90|0.0%|5.1%|
[dshield](#dshield)|20|5120|46|0.8%|2.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|30|0.0%|1.7%|
[blocklist_de_strongips](#blocklist_de_strongips)|182|182|29|15.9%|1.6%|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|8|0.0%|0.4%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|8|0.0%|0.4%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|3|0.0%|0.1%|
[nixspam](#nixspam)|15861|15861|3|0.0%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|2|0.0%|0.1%|
[sslbl](#sslbl)|370|370|1|0.2%|0.0%|
[snort_ipfilter](#snort_ipfilter)|8977|8977|1|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1|0.0%|0.0%|
[ciarmy](#ciarmy)|402|402|1|0.2%|0.0%|

## blocklist_de_strongips

[Blocklist.de](https://www.blocklist.de/) All IPs which are older then 2 month and have more then 5.000 attacks.

Source is downloaded from [this link](http://lists.blocklist.de/lists/strongips.txt).

The last time downloaded was found to be dated: Sat Jun  6 11:10:12 UTC 2015.

The ipset `blocklist_de_strongips` has **182** entries, **182** unique IPs.

The following table shows the overlaps of `blocklist_de_strongips` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_strongips`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_strongips`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_strongips`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|25421|25421|182|0.7%|100.0%|
[blocklist_de_bots](#blocklist_de_bots)|3081|3081|136|4.4%|74.7%|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|134|0.1%|73.6%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|123|0.4%|67.5%|
[stopforumspam_1d](#stopforumspam_1d)|6954|6954|109|1.5%|59.8%|
[alienvault_reputation](#alienvault_reputation)|180710|180710|37|0.0%|20.3%|
[php_commenters](#php_commenters)|326|326|35|10.7%|19.2%|
[blocklist_de_apache](#blocklist_de_apache)|15060|15060|33|0.2%|18.1%|
[blocklist_de_ssh](#blocklist_de_ssh)|1764|1764|29|1.6%|15.9%|
[openbl_60d](#openbl_60d)|7651|7651|27|0.3%|14.8%|
[openbl_30d](#openbl_30d)|3251|3251|25|0.7%|13.7%|
[openbl_7d](#openbl_7d)|861|861|24|2.7%|13.1%|
[blocklist_de_mail](#blocklist_de_mail)|15605|15605|22|0.1%|12.0%|
[openbl_1d](#openbl_1d)|143|143|21|14.6%|11.5%|
[shunlist](#shunlist)|1259|1259|20|1.5%|10.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|16|0.0%|8.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|8|0.0%|4.3%|
[et_block](#et_block)|1023|18338662|8|0.0%|4.3%|
[xroxy](#xroxy)|2098|2098|7|0.3%|3.8%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|7|0.0%|3.8%|
[proxyrss](#proxyrss)|1599|1599|7|0.4%|3.8%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|3708|3708|7|0.1%|3.8%|
[ri_web_proxies](#ri_web_proxies)|6565|6565|6|0.0%|3.2%|
[php_spammers](#php_spammers)|536|536|5|0.9%|2.7%|
[proxz](#proxz)|874|874|4|0.4%|2.1%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|3|0.0%|1.6%|
[php_dictionary](#php_dictionary)|545|545|3|0.5%|1.6%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|1.6%|
[php_harvesters](#php_harvesters)|311|311|2|0.6%|1.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|1.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|888|888|2|0.2%|1.0%|
[sorbs_web](#sorbs_web)|654|655|1|0.1%|0.5%|
[sorbs_spam](#sorbs_spam)|29892|30945|1|0.0%|0.5%|
[sorbs_recent_spam](#sorbs_recent_spam)|29892|30945|1|0.0%|0.5%|
[sorbs_new_spam](#sorbs_new_spam)|29892|30945|1|0.0%|0.5%|
[snort_ipfilter](#snort_ipfilter)|8977|8977|1|0.0%|0.5%|
[nixspam](#nixspam)|15861|15861|1|0.0%|0.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|1|0.0%|0.5%|
[bruteforceblocker](#bruteforceblocker)|1892|1892|1|0.0%|0.5%|
[blocklist_de_imap](#blocklist_de_imap)|1804|1804|1|0.0%|0.5%|

## bm_tor

[torstatus.blutmagie.de](https://torstatus.blutmagie.de) list of all TOR network servers

Source is downloaded from [this link](https://torstatus.blutmagie.de/ip_list_all.php/Tor_ip_list_ALL.csv).

The last time downloaded was found to be dated: Sat Jun  6 11:00:09 UTC 2015.

The ipset `bm_tor` has **6490** entries, **6490** unique IPs.

The following table shows the overlaps of `bm_tor` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `bm_tor`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `bm_tor`.
- ` this % ` is the percentage **of this ipset (`bm_tor`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[dm_tor](#dm_tor)|6485|6485|6485|100.0%|99.9%|
[et_tor](#et_tor)|6470|6470|5777|89.2%|89.0%|
[snort_ipfilter](#snort_ipfilter)|8977|8977|1052|11.7%|16.2%|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|640|0.6%|9.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|628|0.0%|9.6%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|506|1.6%|7.7%|
[stopforumspam_1d](#stopforumspam_1d)|6954|6954|337|4.8%|5.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|190|0.0%|2.9%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|168|45.1%|2.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|164|0.0%|2.5%|
[alienvault_reputation](#alienvault_reputation)|180710|180710|42|0.0%|0.6%|
[php_commenters](#php_commenters)|326|326|34|10.4%|0.5%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|22|0.0%|0.3%|
[openbl_60d](#openbl_60d)|7651|7651|20|0.2%|0.3%|
[php_harvesters](#php_harvesters)|311|311|7|2.2%|0.1%|
[ri_web_proxies](#ri_web_proxies)|6565|6565|5|0.0%|0.0%|
[php_spammers](#php_spammers)|536|536|5|0.9%|0.0%|
[et_block](#et_block)|1023|18338662|5|0.0%|0.0%|
[php_dictionary](#php_dictionary)|545|545|4|0.7%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|4|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|15605|15605|4|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|15060|15060|4|0.0%|0.0%|
[blocklist_de](#blocklist_de)|25421|25421|4|0.0%|0.0%|
[voipbl](#voipbl)|10452|10864|3|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|3|0.0%|0.0%|
[xroxy](#xroxy)|2098|2098|2|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|2|0.0%|0.0%|
[sorbs_spam](#sorbs_spam)|29892|30945|2|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|29892|30945|2|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|29892|30945|2|0.0%|0.0%|
[shunlist](#shunlist)|1259|1259|1|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2447|2447|1|0.0%|0.0%|
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
[ciarmy](#ciarmy)|402|402|1|0.2%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1892|1892|1|0.0%|0.0%|

## bruteforceblocker

[danger.rulez.sk](http://danger.rulez.sk/) IPs detected by [bruteforceblocker](http://danger.rulez.sk/index.php/bruteforceblocker/) (fail2ban alternative for SSH on OpenBSD). This is an automatically generated list from users reporting failed authentication attempts. An IP seems to be included if 3 or more users report it. Its retention pocily seems 30 days.

Source is downloaded from [this link](http://danger.rulez.sk/projects/bruteforceblocker/blist.php).

The last time downloaded was found to be dated: Sat Jun  6 08:27:03 UTC 2015.

The ipset `bruteforceblocker` has **1892** entries, **1892** unique IPs.

The following table shows the overlaps of `bruteforceblocker` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `bruteforceblocker`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `bruteforceblocker`.
- ` this % ` is the percentage **of this ipset (`bruteforceblocker`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[et_compromised](#et_compromised)|2016|2016|1851|91.8%|97.8%|
[alienvault_reputation](#alienvault_reputation)|180710|180710|1227|0.6%|64.8%|
[openbl_60d](#openbl_60d)|7651|7651|1130|14.7%|59.7%|
[openbl_30d](#openbl_30d)|3251|3251|1081|33.2%|57.1%|
[blocklist_de](#blocklist_de)|25421|25421|636|2.5%|33.6%|
[blocklist_de_ssh](#blocklist_de_ssh)|1764|1764|625|35.4%|33.0%|
[shunlist](#shunlist)|1259|1259|450|35.7%|23.7%|
[openbl_7d](#openbl_7d)|861|861|382|44.3%|20.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|179|0.0%|9.4%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|101|0.0%|5.3%|
[et_block](#et_block)|1023|18338662|101|0.0%|5.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|95|0.0%|5.0%|
[openbl_1d](#openbl_1d)|143|143|83|58.0%|4.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|50|0.0%|2.6%|
[dshield](#dshield)|20|5120|43|0.8%|2.2%|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|11|0.0%|0.5%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|7|0.0%|0.3%|
[blocklist_de_mail](#blocklist_de_mail)|15605|15605|6|0.0%|0.3%|
[blocklist_de_imap](#blocklist_de_imap)|1804|1804|6|0.3%|0.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|5|0.0%|0.2%|
[voipbl](#voipbl)|10452|10864|2|0.0%|0.1%|
[proxz](#proxz)|874|874|2|0.2%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|2|0.0%|0.1%|
[blocklist_de_bots](#blocklist_de_bots)|3081|3081|2|0.0%|0.1%|
[blocklist_de_apache](#blocklist_de_apache)|15060|15060|2|0.0%|0.1%|
[xroxy](#xroxy)|2098|2098|1|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|6565|6565|1|0.0%|0.0%|
[nixspam](#nixspam)|15861|15861|1|0.0%|0.0%|
[fullbogons](#fullbogons)|3721|670267288|1|0.0%|0.0%|
[ciarmy](#ciarmy)|402|402|1|0.2%|0.0%|
[bogons](#bogons)|13|592708608|1|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|182|182|1|0.5%|0.0%|

## ciarmy

[CIArmy.com](http://ciarmy.com/) IPs with poor Rogue Packet score that have not yet been identified as malicious by the community

Source is downloaded from [this link](http://cinsscore.com/list/ci-badguys.txt).

The last time downloaded was found to be dated: Sat Jun  6 10:15:15 UTC 2015.

The ipset `ciarmy` has **402** entries, **402** unique IPs.

The following table shows the overlaps of `ciarmy` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ciarmy`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ciarmy`.
- ` this % ` is the percentage **of this ipset (`ciarmy`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[alienvault_reputation](#alienvault_reputation)|180710|180710|398|0.2%|99.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|78|0.0%|19.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|41|0.0%|10.1%|
[blocklist_de](#blocklist_de)|25421|25421|34|0.1%|8.4%|
[blocklist_de_apache](#blocklist_de_apache)|15060|15060|31|0.2%|7.7%|
[shunlist](#shunlist)|1259|1259|29|2.3%|7.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|29|0.0%|7.2%|
[dshield](#dshield)|20|5120|8|0.1%|1.9%|
[et_block](#et_block)|1023|18338662|6|0.0%|1.4%|
[voipbl](#voipbl)|10452|10864|4|0.0%|0.9%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|1|0.0%|0.2%|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|1|0.0%|0.2%|
[stopforumspam_1d](#stopforumspam_1d)|6954|6954|1|0.0%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.2%|
[fullbogons](#fullbogons)|3721|670267288|1|0.0%|0.2%|
[et_compromised](#et_compromised)|2016|2016|1|0.0%|0.2%|
[bruteforceblocker](#bruteforceblocker)|1892|1892|1|0.0%|0.2%|
[bogons](#bogons)|13|592708608|1|0.0%|0.2%|
[blocklist_de_ssh](#blocklist_de_ssh)|1764|1764|1|0.0%|0.2%|
[blocklist_de_mail](#blocklist_de_mail)|15605|15605|1|0.0%|0.2%|
[blocklist_de_imap](#blocklist_de_imap)|1804|1804|1|0.0%|0.2%|
[blocklist_de_ftp](#blocklist_de_ftp)|888|888|1|0.1%|0.2%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|3708|3708|1|0.0%|0.2%|

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
[malc0de](#malc0de)|371|371|27|7.2%|16.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|17|0.0%|10.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|9|0.0%|5.3%|
[alienvault_reputation](#alienvault_reputation)|180710|180710|7|0.0%|4.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|3|0.0%|1.7%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|2|0.1%|1.1%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|3708|3708|1|0.0%|0.5%|
[blocklist_de_apache](#blocklist_de_apache)|15060|15060|1|0.0%|0.5%|
[blocklist_de](#blocklist_de)|25421|25421|1|0.0%|0.5%|

## dm_tor

[dan.me.uk](https://www.dan.me.uk) dynamic list of TOR exit points

Source is downloaded from [this link](https://www.dan.me.uk/torlist/).

The last time downloaded was found to be dated: Sat Jun  6 11:00:06 UTC 2015.

The ipset `dm_tor` has **6485** entries, **6485** unique IPs.

The following table shows the overlaps of `dm_tor` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `dm_tor`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `dm_tor`.
- ` this % ` is the percentage **of this ipset (`dm_tor`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[bm_tor](#bm_tor)|6490|6490|6485|99.9%|100.0%|
[et_tor](#et_tor)|6470|6470|5774|89.2%|89.0%|
[snort_ipfilter](#snort_ipfilter)|8977|8977|1051|11.7%|16.2%|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|640|0.6%|9.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|628|0.0%|9.6%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|506|1.6%|7.8%|
[stopforumspam_1d](#stopforumspam_1d)|6954|6954|337|4.8%|5.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|190|0.0%|2.9%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|168|45.1%|2.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|164|0.0%|2.5%|
[alienvault_reputation](#alienvault_reputation)|180710|180710|42|0.0%|0.6%|
[php_commenters](#php_commenters)|326|326|34|10.4%|0.5%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|22|0.0%|0.3%|
[openbl_60d](#openbl_60d)|7651|7651|20|0.2%|0.3%|
[php_harvesters](#php_harvesters)|311|311|7|2.2%|0.1%|
[ri_web_proxies](#ri_web_proxies)|6565|6565|5|0.0%|0.0%|
[php_spammers](#php_spammers)|536|536|5|0.9%|0.0%|
[et_block](#et_block)|1023|18338662|5|0.0%|0.0%|
[php_dictionary](#php_dictionary)|545|545|4|0.7%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|4|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|15605|15605|4|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|15060|15060|4|0.0%|0.0%|
[blocklist_de](#blocklist_de)|25421|25421|4|0.0%|0.0%|
[voipbl](#voipbl)|10452|10864|3|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|3|0.0%|0.0%|
[xroxy](#xroxy)|2098|2098|2|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|2|0.0%|0.0%|
[sorbs_spam](#sorbs_spam)|29892|30945|2|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|29892|30945|2|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|29892|30945|2|0.0%|0.0%|
[shunlist](#shunlist)|1259|1259|1|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2447|2447|1|0.0%|0.0%|
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
[openbl_60d](#openbl_60d)|7651|7651|105|1.3%|2.0%|
[openbl_30d](#openbl_30d)|3251|3251|88|2.7%|1.7%|
[blocklist_de](#blocklist_de)|25421|25421|64|0.2%|1.2%|
[shunlist](#shunlist)|1259|1259|59|4.6%|1.1%|
[et_compromised](#et_compromised)|2016|2016|50|2.4%|0.9%|
[blocklist_de_ssh](#blocklist_de_ssh)|1764|1764|46|2.6%|0.8%|
[bruteforceblocker](#bruteforceblocker)|1892|1892|43|2.2%|0.8%|
[openbl_7d](#openbl_7d)|861|861|34|3.9%|0.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|16|0.0%|0.3%|
[blocklist_de_apache](#blocklist_de_apache)|15060|15060|13|0.0%|0.2%|
[ciarmy](#ciarmy)|402|402|8|1.9%|0.1%|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|7|0.0%|0.1%|
[openbl_1d](#openbl_1d)|143|143|7|4.8%|0.1%|
[voipbl](#voipbl)|10452|10864|6|0.0%|0.1%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|5|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6954|6954|4|0.0%|0.0%|
[sorbs_spam](#sorbs_spam)|29892|30945|2|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|29892|30945|2|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|29892|30945|2|0.0%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|87|87|2|2.2%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3081|3081|2|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|8977|8977|1|0.0%|0.0%|
[malc0de](#malc0de)|371|371|1|0.2%|0.0%|
[et_tor](#et_tor)|6470|6470|1|0.0%|0.0%|
[dm_tor](#dm_tor)|6485|6485|1|0.0%|0.0%|
[bm_tor](#bm_tor)|6490|6490|1|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|15605|15605|1|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|3708|3708|1|0.0%|0.0%|

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
[snort_ipfilter](#snort_ipfilter)|8977|8977|317|3.5%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|314|1.0%|0.0%|
[openbl_60d](#openbl_60d)|7651|7651|250|3.2%|0.0%|
[zeus](#zeus)|230|230|223|96.9%|0.0%|
[zeus_badips](#zeus_badips)|202|202|200|99.0%|0.0%|
[blocklist_de](#blocklist_de)|25421|25421|195|0.7%|0.0%|
[openbl_30d](#openbl_30d)|3251|3251|166|5.1%|0.0%|
[shunlist](#shunlist)|1259|1259|111|8.8%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1764|1764|111|6.2%|0.0%|
[nixspam](#nixspam)|15861|15861|104|0.6%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1892|1892|101|5.3%|0.0%|
[et_compromised](#et_compromised)|2016|2016|100|4.9%|0.0%|
[feodo](#feodo)|99|99|94|94.9%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6954|6954|77|1.1%|0.0%|
[openbl_7d](#openbl_7d)|861|861|51|5.9%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3081|3081|42|1.3%|0.0%|
[sslbl](#sslbl)|370|370|35|9.4%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|29|2.2%|0.0%|
[php_commenters](#php_commenters)|326|326|28|8.5%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|15605|15605|28|0.1%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|1804|1804|18|0.9%|0.0%|
[voipbl](#voipbl)|10452|10864|16|0.1%|0.0%|
[palevo](#palevo)|13|13|13|100.0%|0.0%|
[openbl_1d](#openbl_1d)|143|143|12|8.3%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|15060|15060|12|0.0%|0.0%|
[sorbs_spam](#sorbs_spam)|29892|30945|10|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|29892|30945|10|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|29892|30945|10|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|182|182|8|4.3%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|6|0.4%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|6|0.0%|0.0%|
[ciarmy](#ciarmy)|402|402|6|1.4%|0.0%|
[malc0de](#malc0de)|371|371|5|1.3%|0.0%|
[dm_tor](#dm_tor)|6485|6485|5|0.0%|0.0%|
[bm_tor](#bm_tor)|6490|6490|5|0.0%|0.0%|
[php_dictionary](#php_dictionary)|545|545|4|0.7%|0.0%|
[et_tor](#et_tor)|6470|6470|4|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|3708|3708|4|0.1%|0.0%|
[php_spammers](#php_spammers)|536|536|2|0.3%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|2|0.2%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|87|87|2|2.2%|0.0%|
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
[blocklist_de_sip](#blocklist_de_sip)|87|87|1|1.1%|0.1%|

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
[bruteforceblocker](#bruteforceblocker)|1892|1892|1851|97.8%|91.8%|
[alienvault_reputation](#alienvault_reputation)|180710|180710|1312|0.7%|65.0%|
[openbl_60d](#openbl_60d)|7651|7651|1216|15.8%|60.3%|
[openbl_30d](#openbl_30d)|3251|3251|1151|35.4%|57.0%|
[blocklist_de](#blocklist_de)|25421|25421|634|2.4%|31.4%|
[blocklist_de_ssh](#blocklist_de_ssh)|1764|1764|623|35.3%|30.9%|
[shunlist](#shunlist)|1259|1259|460|36.5%|22.8%|
[openbl_7d](#openbl_7d)|861|861|386|44.8%|19.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|199|0.0%|9.8%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|100|0.0%|4.9%|
[et_block](#et_block)|1023|18338662|100|0.0%|4.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|97|0.0%|4.8%|
[openbl_1d](#openbl_1d)|143|143|79|55.2%|3.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|52|0.0%|2.5%|
[dshield](#dshield)|20|5120|50|0.9%|2.4%|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|11|0.0%|0.5%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|7|0.0%|0.3%|
[blocklist_de_mail](#blocklist_de_mail)|15605|15605|6|0.0%|0.2%|
[blocklist_de_imap](#blocklist_de_imap)|1804|1804|6|0.3%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|5|0.0%|0.2%|
[voipbl](#voipbl)|10452|10864|2|0.0%|0.0%|
[proxz](#proxz)|874|874|2|0.2%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|2|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3081|3081|2|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|15060|15060|2|0.0%|0.0%|
[xroxy](#xroxy)|2098|2098|1|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|6565|6565|1|0.0%|0.0%|
[nixspam](#nixspam)|15861|15861|1|0.0%|0.0%|
[ciarmy](#ciarmy)|402|402|1|0.2%|0.0%|

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
[bm_tor](#bm_tor)|6490|6490|5777|89.0%|89.2%|
[dm_tor](#dm_tor)|6485|6485|5774|89.0%|89.2%|
[snort_ipfilter](#snort_ipfilter)|8977|8977|1085|12.0%|16.7%|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|647|0.6%|10.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|633|0.0%|9.7%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|516|1.7%|7.9%|
[stopforumspam_1d](#stopforumspam_1d)|6954|6954|337|4.8%|5.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|190|0.0%|2.9%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|168|45.1%|2.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|168|0.0%|2.5%|
[alienvault_reputation](#alienvault_reputation)|180710|180710|42|0.0%|0.6%|
[php_commenters](#php_commenters)|326|326|35|10.7%|0.5%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|22|0.0%|0.3%|
[openbl_60d](#openbl_60d)|7651|7651|20|0.2%|0.3%|
[php_harvesters](#php_harvesters)|311|311|7|2.2%|0.1%|
[php_spammers](#php_spammers)|536|536|6|1.1%|0.0%|
[ri_web_proxies](#ri_web_proxies)|6565|6565|5|0.0%|0.0%|
[php_dictionary](#php_dictionary)|545|545|5|0.9%|0.0%|
[et_block](#et_block)|1023|18338662|4|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|15605|15605|4|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|15060|15060|4|0.0%|0.0%|
[blocklist_de](#blocklist_de)|25421|25421|4|0.0%|0.0%|
[voipbl](#voipbl)|10452|10864|3|0.0%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|0.0%|
[xroxy](#xroxy)|2098|2098|2|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|2|0.0%|0.0%|
[sorbs_spam](#sorbs_spam)|29892|30945|2|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|29892|30945|2|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|29892|30945|2|0.0%|0.0%|
[shunlist](#shunlist)|1259|1259|1|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2447|2447|1|0.0%|0.0%|
[dshield](#dshield)|20|5120|1|0.0%|0.0%|

## feodo

[Abuse.ch Feodo tracker](https://feodotracker.abuse.ch) trojan includes IPs which are being used by Feodo (also known as Cridex or Bugat) which commits ebanking fraud - **excellent list**

Source is downloaded from [this link](https://feodotracker.abuse.ch/blocklist/?download=ipblocklist).

The last time downloaded was found to be dated: Sat Jun  6 11:00:17 UTC 2015.

The ipset `feodo` has **99** entries, **99** unique IPs.

The following table shows the overlaps of `feodo` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `feodo`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `feodo`.
- ` this % ` is the percentage **of this ipset (`feodo`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[et_block](#et_block)|1023|18338662|94|0.0%|94.9%|
[snort_ipfilter](#snort_ipfilter)|8977|8977|76|0.8%|76.7%|
[sslbl](#sslbl)|370|370|36|9.7%|36.3%|
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
[ciarmy](#ciarmy)|402|402|1|0.2%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1892|1892|1|0.0%|0.0%|

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
[sorbs_spam](#sorbs_spam)|29892|30945|15|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|29892|30945|15|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|29892|30945|15|0.0%|0.0%|
[fullbogons](#fullbogons)|3721|670267288|15|0.0%|0.0%|
[alienvault_reputation](#alienvault_reputation)|180710|180710|15|0.0%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|14|0.0%|0.0%|
[blocklist_de](#blocklist_de)|25421|25421|12|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|11|1.6%|0.0%|
[nixspam](#nixspam)|15861|15861|9|0.0%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|6|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|6|0.0%|0.0%|
[et_block](#et_block)|1023|18338662|6|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|3708|3708|6|0.1%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|15060|15060|6|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|4|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|15605|15605|4|0.0%|0.0%|
[xroxy](#xroxy)|2098|2098|3|0.1%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6954|6954|3|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|6565|6565|3|0.0%|0.0%|
[php_dictionary](#php_dictionary)|545|545|3|0.5%|0.0%|
[voipbl](#voipbl)|10452|10864|2|0.0%|0.0%|
[proxyrss](#proxyrss)|1599|1599|2|0.1%|0.0%|
[php_harvesters](#php_harvesters)|311|311|2|0.6%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|1804|1804|2|0.1%|0.0%|
[sorbs_web](#sorbs_web)|654|655|1|0.1%|0.0%|
[snort_ipfilter](#snort_ipfilter)|8977|8977|1|0.0%|0.0%|
[proxz](#proxz)|874|874|1|0.1%|0.0%|
[php_spammers](#php_spammers)|536|536|1|0.1%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1764|1764|1|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3081|3081|1|0.0%|0.0%|

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
[nixspam](#nixspam)|15861|15861|100|0.6%|0.0%|
[blocklist_de](#blocklist_de)|25421|25421|54|0.2%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3081|3081|37|1.2%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|27|2.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6954|6954|25|0.3%|0.0%|
[openbl_60d](#openbl_60d)|7651|7651|17|0.2%|0.0%|
[openbl_30d](#openbl_30d)|3251|3251|13|0.3%|0.0%|
[snort_ipfilter](#snort_ipfilter)|8977|8977|12|0.1%|0.0%|
[zeus_badips](#zeus_badips)|202|202|10|4.9%|0.0%|
[zeus](#zeus)|230|230|10|4.3%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1764|1764|8|0.4%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|7|0.4%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|15605|15605|6|0.0%|0.0%|
[openbl_7d](#openbl_7d)|861|861|5|0.5%|0.0%|
[et_compromised](#et_compromised)|2016|2016|5|0.2%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1892|1892|5|0.2%|0.0%|
[sorbs_spam](#sorbs_spam)|29892|30945|4|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|29892|30945|4|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|29892|30945|4|0.0%|0.0%|
[dm_tor](#dm_tor)|6485|6485|4|0.0%|0.0%|
[bm_tor](#bm_tor)|6490|6490|4|0.0%|0.0%|
[et_tor](#et_tor)|6470|6470|3|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|182|182|3|1.6%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|15060|15060|3|0.0%|0.0%|
[shunlist](#shunlist)|1259|1259|2|0.1%|0.0%|
[php_spammers](#php_spammers)|536|536|2|0.3%|0.0%|
[php_dictionary](#php_dictionary)|545|545|2|0.3%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|2|0.2%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|1804|1804|2|0.1%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|3708|3708|2|0.0%|0.0%|
[voipbl](#voipbl)|10452|10864|1|0.0%|0.0%|
[php_harvesters](#php_harvesters)|311|311|1|0.3%|0.0%|
[php_commenters](#php_commenters)|326|326|1|0.3%|0.0%|
[openbl_1d](#openbl_1d)|143|143|1|0.6%|0.0%|
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
[blocklist_de](#blocklist_de)|25421|25421|1496|5.8%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|15605|15605|1364|8.7%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|15060|15060|1329|8.8%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|568|1.8%|0.0%|
[sorbs_spam](#sorbs_spam)|29892|30945|487|1.5%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|29892|30945|487|1.5%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|29892|30945|487|1.5%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|406|0.8%|0.0%|
[voipbl](#voipbl)|10452|10864|299|2.7%|0.0%|
[dshield](#dshield)|20|5120|264|5.1%|0.0%|
[nixspam](#nixspam)|15861|15861|208|1.3%|0.0%|
[openbl_60d](#openbl_60d)|7651|7651|171|2.2%|0.0%|
[et_tor](#et_tor)|6470|6470|168|2.5%|0.0%|
[dm_tor](#dm_tor)|6485|6485|164|2.5%|0.0%|
[bm_tor](#bm_tor)|6490|6490|164|2.5%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6954|6954|138|1.9%|0.0%|
[ri_web_proxies](#ri_web_proxies)|6565|6565|135|2.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|97|6.6%|0.0%|
[snort_ipfilter](#snort_ipfilter)|8977|8977|83|0.9%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2447|2447|76|3.1%|0.0%|
[openbl_30d](#openbl_30d)|3251|3251|71|2.1%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|66|5.1%|0.0%|
[xroxy](#xroxy)|2098|2098|58|2.7%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|58|8.6%|0.0%|
[et_compromised](#et_compromised)|2016|2016|52|2.5%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1892|1892|50|2.6%|0.0%|
[et_botcc](#et_botcc)|509|509|41|8.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|3708|3708|37|0.9%|0.0%|
[proxyrss](#proxyrss)|1599|1599|36|2.2%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3081|3081|35|1.1%|0.0%|
[proxz](#proxz)|874|874|31|3.5%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1764|1764|30|1.7%|0.0%|
[ciarmy](#ciarmy)|402|402|29|7.2%|0.0%|
[shunlist](#shunlist)|1259|1259|28|2.2%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|1804|1804|28|1.5%|0.0%|
[sorbs_web](#sorbs_web)|654|655|22|3.3%|0.0%|
[openbl_7d](#openbl_7d)|861|861|19|2.2%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|17|4.5%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|888|888|15|1.6%|0.0%|
[php_dictionary](#php_dictionary)|545|545|11|2.0%|0.0%|
[malc0de](#malc0de)|371|371|11|2.9%|0.0%|
[php_harvesters](#php_harvesters)|311|311|9|2.8%|0.0%|
[php_spammers](#php_spammers)|536|536|7|1.3%|0.0%|
[php_commenters](#php_commenters)|326|326|7|2.1%|0.0%|
[zeus](#zeus)|230|230|6|2.6%|0.0%|
[bogons](#bogons)|13|592708608|5|0.0%|0.0%|
[zeus_badips](#zeus_badips)|202|202|4|1.9%|0.0%|
[sslbl](#sslbl)|370|370|3|0.8%|0.0%|
[openbl_1d](#openbl_1d)|143|143|3|2.0%|0.0%|
[feodo](#feodo)|99|99|3|3.0%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|87|87|3|3.4%|0.0%|
[virbl](#virbl)|8|8|2|25.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|182|182|1|0.5%|0.0%|

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
[blocklist_de](#blocklist_de)|25421|25421|1423|5.5%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|15605|15605|1137|7.2%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|15060|15060|1087|7.2%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|909|3.0%|0.0%|
[sorbs_spam](#sorbs_spam)|29892|30945|783|2.5%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|29892|30945|783|2.5%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|29892|30945|783|2.5%|0.0%|
[voipbl](#voipbl)|10452|10864|434|3.9%|0.0%|
[nixspam](#nixspam)|15861|15861|407|2.5%|0.0%|
[openbl_60d](#openbl_60d)|7651|7651|332|4.3%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|230|0.4%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6954|6954|195|2.8%|0.0%|
[ri_web_proxies](#ri_web_proxies)|6565|6565|191|2.9%|0.0%|
[et_tor](#et_tor)|6470|6470|190|2.9%|0.0%|
[dm_tor](#dm_tor)|6485|6485|190|2.9%|0.0%|
[bm_tor](#bm_tor)|6490|6490|190|2.9%|0.0%|
[openbl_30d](#openbl_30d)|3251|3251|168|5.1%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3081|3081|113|3.6%|0.0%|
[xroxy](#xroxy)|2098|2098|101|4.8%|0.0%|
[snort_ipfilter](#snort_ipfilter)|8977|8977|100|1.1%|0.0%|
[et_compromised](#et_compromised)|2016|2016|97|4.8%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2447|2447|96|3.9%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1892|1892|95|5.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1764|1764|90|5.1%|0.0%|
[shunlist](#shunlist)|1259|1259|73|5.7%|0.0%|
[proxyrss](#proxyrss)|1599|1599|67|4.1%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|3708|3708|53|1.4%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|1804|1804|52|2.8%|0.0%|
[php_spammers](#php_spammers)|536|536|45|8.3%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|45|3.0%|0.0%|
[openbl_7d](#openbl_7d)|861|861|43|4.9%|0.0%|
[ciarmy](#ciarmy)|402|402|41|10.1%|0.0%|
[proxz](#proxz)|874|874|35|4.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|28|4.1%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|26|2.0%|0.0%|
[sorbs_web](#sorbs_web)|654|655|25|3.8%|0.0%|
[malc0de](#malc0de)|371|371|22|5.9%|0.0%|
[et_botcc](#et_botcc)|509|509|22|4.3%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|21|5.6%|0.0%|
[php_dictionary](#php_dictionary)|545|545|17|3.1%|0.0%|
[dshield](#dshield)|20|5120|16|0.3%|0.0%|
[php_commenters](#php_commenters)|326|326|13|3.9%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|888|888|13|1.4%|0.0%|
[zeus](#zeus)|230|230|9|3.9%|0.0%|
[php_harvesters](#php_harvesters)|311|311|9|2.8%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|168|168|9|5.3%|0.0%|
[zeus_badips](#zeus_badips)|202|202|8|3.9%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|182|182|8|4.3%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|87|87|8|9.1%|0.0%|
[sslbl](#sslbl)|370|370|5|1.3%|0.0%|
[openbl_1d](#openbl_1d)|143|143|4|2.7%|0.0%|
[feodo](#feodo)|99|99|3|3.0%|0.0%|
[palevo](#palevo)|13|13|2|15.3%|0.0%|
[sorbs_socks](#sorbs_socks)|19|19|1|5.2%|0.0%|
[sorbs_smtp](#sorbs_smtp)|13|13|1|7.6%|0.0%|
[sorbs_misc](#sorbs_misc)|19|19|1|5.2%|0.0%|
[sorbs_http](#sorbs_http)|19|19|1|5.2%|0.0%|

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
[blocklist_de](#blocklist_de)|25421|25421|3220|12.6%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|15605|15605|2453|15.7%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|15060|15060|2367|15.7%|0.0%|
[sorbs_spam](#sorbs_spam)|29892|30945|2243|7.2%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|29892|30945|2243|7.2%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|29892|30945|2243|7.2%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|1912|6.3%|0.0%|
[voipbl](#voipbl)|10452|10864|1598|14.7%|0.0%|
[nixspam](#nixspam)|15861|15861|1200|7.5%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1172|2.4%|0.0%|
[openbl_60d](#openbl_60d)|7651|7651|745|9.7%|0.0%|
[et_tor](#et_tor)|6470|6470|633|9.7%|0.0%|
[dm_tor](#dm_tor)|6485|6485|628|9.6%|0.0%|
[bm_tor](#bm_tor)|6490|6490|628|9.6%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6954|6954|510|7.3%|0.0%|
[openbl_30d](#openbl_30d)|3251|3251|312|9.5%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|3708|3708|268|7.2%|0.0%|
[dshield](#dshield)|20|5120|256|5.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|8977|8977|231|2.5%|0.0%|
[et_compromised](#et_compromised)|2016|2016|199|9.8%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3081|3081|196|6.3%|0.0%|
[ri_web_proxies](#ri_web_proxies)|6565|6565|190|2.8%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1764|1764|181|10.2%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1892|1892|179|9.4%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|1804|1804|170|9.4%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|147|11.4%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|125|33.6%|0.0%|
[openbl_7d](#openbl_7d)|861|861|115|13.3%|0.0%|
[shunlist](#shunlist)|1259|1259|113|8.9%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|110|7.5%|0.0%|
[xroxy](#xroxy)|2098|2098|94|4.4%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|888|888|79|8.8%|0.0%|
[et_botcc](#et_botcc)|509|509|78|15.3%|0.0%|
[ciarmy](#ciarmy)|402|402|78|19.4%|0.0%|
[proxz](#proxz)|874|874|72|8.2%|0.0%|
[proxyrss](#proxyrss)|1599|1599|61|3.8%|0.0%|
[malc0de](#malc0de)|371|371|61|16.4%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2447|2447|53|2.1%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|51|7.5%|0.0%|
[sorbs_web](#sorbs_web)|654|655|45|6.8%|0.0%|
[php_spammers](#php_spammers)|536|536|31|5.7%|0.0%|
[php_dictionary](#php_dictionary)|545|545|31|5.6%|0.0%|
[sslbl](#sslbl)|370|370|26|7.0%|0.0%|
[php_commenters](#php_commenters)|326|326|18|5.5%|0.0%|
[php_harvesters](#php_harvesters)|311|311|17|5.4%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|168|168|17|10.1%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|182|182|16|8.7%|0.0%|
[zeus](#zeus)|230|230|14|6.0%|0.0%|
[openbl_1d](#openbl_1d)|143|143|12|8.3%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|87|87|12|13.7%|0.0%|
[feodo](#feodo)|99|99|11|11.1%|0.0%|
[zeus_badips](#zeus_badips)|202|202|10|4.9%|0.0%|
[virbl](#virbl)|8|8|1|12.5%|0.0%|
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
[xroxy](#xroxy)|2098|2098|13|0.6%|1.9%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|12|0.0%|1.7%|
[ri_web_proxies](#ri_web_proxies)|6565|6565|12|0.1%|1.7%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|11|0.0%|1.6%|
[proxyrss](#proxyrss)|1599|1599|8|0.5%|1.1%|
[ri_connect_proxies](#ri_connect_proxies)|2447|2447|6|0.2%|0.8%|
[proxz](#proxz)|874|874|6|0.6%|0.8%|
[blocklist_de](#blocklist_de)|25421|25421|4|0.0%|0.5%|
[blocklist_de_bots](#blocklist_de_bots)|3081|3081|3|0.0%|0.4%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|2|0.0%|0.2%|
[sorbs_spam](#sorbs_spam)|29892|30945|2|0.0%|0.2%|
[sorbs_recent_spam](#sorbs_recent_spam)|29892|30945|2|0.0%|0.2%|
[sorbs_new_spam](#sorbs_new_spam)|29892|30945|2|0.0%|0.2%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2|0.0%|0.2%|
[et_block](#et_block)|1023|18338662|2|0.0%|0.2%|
[stopforumspam_1d](#stopforumspam_1d)|6954|6954|1|0.0%|0.1%|
[snort_ipfilter](#snort_ipfilter)|8977|8977|1|0.0%|0.1%|
[php_dictionary](#php_dictionary)|545|545|1|0.1%|0.1%|
[blocklist_de_mail](#blocklist_de_mail)|15605|15605|1|0.0%|0.1%|
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
[sorbs_spam](#sorbs_spam)|29892|30945|33|0.1%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|29892|30945|33|0.1%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|29892|30945|33|0.1%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|27|2.0%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|25|0.0%|0.0%|
[et_tor](#et_tor)|6470|6470|22|0.3%|0.0%|
[dm_tor](#dm_tor)|6485|6485|22|0.3%|0.0%|
[bm_tor](#bm_tor)|6490|6490|22|0.3%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|19|1.3%|0.0%|
[snort_ipfilter](#snort_ipfilter)|8977|8977|14|0.1%|0.0%|
[blocklist_de](#blocklist_de)|25421|25421|13|0.0%|0.0%|
[nixspam](#nixspam)|15861|15861|11|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6954|6954|8|0.1%|0.0%|
[ri_web_proxies](#ri_web_proxies)|6565|6565|5|0.0%|0.0%|
[openbl_60d](#openbl_60d)|7651|7651|5|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|5|1.3%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3081|3081|5|0.1%|0.0%|
[voipbl](#voipbl)|10452|10864|4|0.0%|0.0%|
[openbl_30d](#openbl_30d)|3251|3251|4|0.1%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|4|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|15605|15605|4|0.0%|0.0%|
[malc0de](#malc0de)|371|371|3|0.8%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|168|168|3|1.7%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|15060|15060|3|0.0%|0.0%|
[et_compromised](#et_compromised)|2016|2016|2|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1892|1892|2|0.1%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1764|1764|2|0.1%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|87|87|2|2.2%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|1804|1804|2|0.1%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|3708|3708|2|0.0%|0.0%|
[zeus_badips](#zeus_badips)|202|202|1|0.4%|0.0%|
[zeus](#zeus)|230|230|1|0.4%|0.0%|
[xroxy](#xroxy)|2098|2098|1|0.0%|0.0%|
[sslbl](#sslbl)|370|370|1|0.2%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|1|0.0%|0.0%|
[shunlist](#shunlist)|1259|1259|1|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2447|2447|1|0.0%|0.0%|
[proxyrss](#proxyrss)|1599|1599|1|0.0%|0.0%|
[php_harvesters](#php_harvesters)|311|311|1|0.3%|0.0%|
[php_dictionary](#php_dictionary)|545|545|1|0.1%|0.0%|
[palevo](#palevo)|13|13|1|7.6%|0.0%|
[openbl_7d](#openbl_7d)|861|861|1|0.1%|0.0%|
[feodo](#feodo)|99|99|1|1.0%|0.0%|
[ciarmy](#ciarmy)|402|402|1|0.2%|0.0%|
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
[nixspam](#nixspam)|15861|15861|3|0.0%|0.2%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|3|0.2%|0.2%|
[blocklist_de](#blocklist_de)|25421|25421|3|0.0%|0.2%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|2|0.0%|0.1%|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|2|0.0%|0.1%|
[stopforumspam_1d](#stopforumspam_1d)|6954|6954|2|0.0%|0.1%|
[openbl_60d](#openbl_60d)|7651|7651|2|0.0%|0.1%|
[openbl_30d](#openbl_30d)|3251|3251|2|0.0%|0.1%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|2|0.2%|0.1%|
[blocklist_de_strongips](#blocklist_de_strongips)|182|182|2|1.0%|0.1%|
[blocklist_de_bots](#blocklist_de_bots)|3081|3081|2|0.0%|0.1%|
[snort_ipfilter](#snort_ipfilter)|8977|8977|1|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|6565|6565|1|0.0%|0.0%|
[openbl_7d](#openbl_7d)|861|861|1|0.1%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1|0.0%|0.0%|
[et_botcc](#et_botcc)|509|509|1|0.1%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1764|1764|1|0.0%|0.0%|

## malc0de

[Malc0de.com](http://malc0de.com) malicious IPs of the last 30 days

Source is downloaded from [this link](http://malc0de.com/bl/IP_Blacklist.txt).

The last time downloaded was found to be dated: Fri Jun  5 13:17:02 UTC 2015.

The ipset `malc0de` has **371** entries, **371** unique IPs.

The following table shows the overlaps of `malc0de` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `malc0de`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `malc0de`.
- ` this % ` is the percentage **of this ipset (`malc0de`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|61|0.0%|16.4%|
[cleanmx_viruses](#cleanmx_viruses)|168|168|27|16.0%|7.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|22|0.0%|5.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|11|0.0%|2.9%|
[alienvault_reputation](#alienvault_reputation)|180710|180710|11|0.0%|2.9%|
[et_block](#et_block)|1023|18338662|5|0.0%|1.3%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|4|0.0%|1.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|4|0.3%|1.0%|
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
[snort_ipfilter](#snort_ipfilter)|8977|8977|28|0.3%|2.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|27|0.0%|2.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|27|0.0%|2.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|26|0.0%|2.0%|
[fullbogons](#fullbogons)|3721|670267288|9|0.0%|0.6%|
[alienvault_reputation](#alienvault_reputation)|180710|180710|6|0.0%|0.4%|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|4|0.0%|0.3%|
[malc0de](#malc0de)|371|371|4|1.0%|0.3%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|3|0.2%|0.2%|
[cleanmx_viruses](#cleanmx_viruses)|168|168|2|1.1%|0.1%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|1|0.0%|0.0%|
[sorbs_spam](#sorbs_spam)|29892|30945|1|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|29892|30945|1|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|29892|30945|1|0.0%|0.0%|
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
[snort_ipfilter](#snort_ipfilter)|8977|8977|177|1.9%|47.5%|
[et_tor](#et_tor)|6470|6470|168|2.5%|45.1%|
[dm_tor](#dm_tor)|6485|6485|168|2.5%|45.1%|
[bm_tor](#bm_tor)|6490|6490|168|2.5%|45.1%|
[stopforumspam_1d](#stopforumspam_1d)|6954|6954|163|2.3%|43.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|125|0.0%|33.6%|
[php_commenters](#php_commenters)|326|326|32|9.8%|8.6%|
[alienvault_reputation](#alienvault_reputation)|180710|180710|26|0.0%|6.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|21|0.0%|5.6%|
[openbl_60d](#openbl_60d)|7651|7651|18|0.2%|4.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|17|0.0%|4.5%|
[php_harvesters](#php_harvesters)|311|311|6|1.9%|1.6%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|5|0.0%|1.3%|
[ri_web_proxies](#ri_web_proxies)|6565|6565|4|0.0%|1.0%|
[php_spammers](#php_spammers)|536|536|4|0.7%|1.0%|
[php_dictionary](#php_dictionary)|545|545|4|0.7%|1.0%|
[blocklist_de](#blocklist_de)|25421|25421|3|0.0%|0.8%|
[shunlist](#shunlist)|1259|1259|2|0.1%|0.5%|
[blocklist_de_apache](#blocklist_de_apache)|15060|15060|2|0.0%|0.5%|
[xroxy](#xroxy)|2098|2098|1|0.0%|0.2%|
[voipbl](#voipbl)|10452|10864|1|0.0%|0.2%|
[ri_connect_proxies](#ri_connect_proxies)|2447|2447|1|0.0%|0.2%|
[et_block](#et_block)|1023|18338662|1|0.0%|0.2%|
[blocklist_de_ssh](#blocklist_de_ssh)|1764|1764|1|0.0%|0.2%|
[blocklist_de_mail](#blocklist_de_mail)|15605|15605|1|0.0%|0.2%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|3708|3708|1|0.0%|0.2%|

## nixspam

[NiX Spam](http://www.heise.de/ix/NiX-Spam-DNSBL-and-blacklist-for-download-499637.html) IP addresses that sent spam in the last hour - automatically generated entries without distinguishing open proxies from relays, dialup gateways, and so on. All IPs are removed after 12 hours if there is no spam from there.

Source is downloaded from [this link](http://www.dnsbl.manitu.net/download/nixspam-ip.dump.gz).

The last time downloaded was found to be dated: Sat Jun  6 11:15:01 UTC 2015.

The ipset `nixspam` has **15861** entries, **15861** unique IPs.

The following table shows the overlaps of `nixspam` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `nixspam`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `nixspam`.
- ` this % ` is the percentage **of this ipset (`nixspam`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[sorbs_spam](#sorbs_spam)|29892|30945|2210|7.1%|13.9%|
[sorbs_recent_spam](#sorbs_recent_spam)|29892|30945|2210|7.1%|13.9%|
[sorbs_new_spam](#sorbs_new_spam)|29892|30945|2210|7.1%|13.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|1200|0.0%|7.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|407|0.0%|2.5%|
[blocklist_de](#blocklist_de)|25421|25421|353|1.3%|2.2%|
[blocklist_de_mail](#blocklist_de_mail)|15605|15605|295|1.8%|1.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|208|0.0%|1.3%|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|164|0.1%|1.0%|
[et_block](#et_block)|1023|18338662|104|0.0%|0.6%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|102|0.0%|0.6%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|100|0.0%|0.6%|
[sorbs_web](#sorbs_web)|654|655|95|14.5%|0.5%|
[snort_ipfilter](#snort_ipfilter)|8977|8977|95|1.0%|0.5%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|86|0.2%|0.5%|
[php_dictionary](#php_dictionary)|545|545|68|12.4%|0.4%|
[php_spammers](#php_spammers)|536|536|61|11.3%|0.3%|
[ri_web_proxies](#ri_web_proxies)|6565|6565|58|0.8%|0.3%|
[stopforumspam_1d](#stopforumspam_1d)|6954|6954|43|0.6%|0.2%|
[xroxy](#xroxy)|2098|2098|38|1.8%|0.2%|
[alienvault_reputation](#alienvault_reputation)|180710|180710|29|0.0%|0.1%|
[blocklist_de_apache](#blocklist_de_apache)|15060|15060|22|0.1%|0.1%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|3708|3708|21|0.5%|0.1%|
[blocklist_de_bots](#blocklist_de_bots)|3081|3081|21|0.6%|0.1%|
[proxz](#proxz)|874|874|20|2.2%|0.1%|
[ri_connect_proxies](#ri_connect_proxies)|2447|2447|14|0.5%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|1804|1804|14|0.7%|0.0%|
[proxyrss](#proxyrss)|1599|1599|13|0.8%|0.0%|
[openbl_60d](#openbl_60d)|7651|7651|13|0.1%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|11|0.0%|0.0%|
[php_commenters](#php_commenters)|326|326|10|3.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|9|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|888|888|9|1.0%|0.0%|
[openbl_30d](#openbl_30d)|3251|3251|5|0.1%|0.0%|
[php_harvesters](#php_harvesters)|311|311|3|0.9%|0.0%|
[openbl_7d](#openbl_7d)|861|861|3|0.3%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|3|0.2%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1764|1764|3|0.1%|0.0%|
[voipbl](#voipbl)|10452|10864|2|0.0%|0.0%|
[sorbs_socks](#sorbs_socks)|19|19|1|5.2%|0.0%|
[sorbs_misc](#sorbs_misc)|19|19|1|5.2%|0.0%|
[sorbs_http](#sorbs_http)|19|19|1|5.2%|0.0%|
[et_compromised](#et_compromised)|2016|2016|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1892|1892|1|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|182|182|1|0.5%|0.0%|

## openbl_1d

[OpenBL.org](http://www.openbl.org/) last 24 hours IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.

Source is downloaded from [this link](http://www.openbl.org/lists/base_1days.txt).

The last time downloaded was found to be dated: Sat Jun  6 10:32:00 UTC 2015.

The ipset `openbl_1d` has **143** entries, **143** unique IPs.

The following table shows the overlaps of `openbl_1d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl_1d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl_1d`.
- ` this % ` is the percentage **of this ipset (`openbl_1d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[openbl_60d](#openbl_60d)|7651|7651|138|1.8%|96.5%|
[openbl_30d](#openbl_30d)|3251|3251|138|4.2%|96.5%|
[alienvault_reputation](#alienvault_reputation)|180710|180710|138|0.0%|96.5%|
[openbl_7d](#openbl_7d)|861|861|135|15.6%|94.4%|
[blocklist_de](#blocklist_de)|25421|25421|121|0.4%|84.6%|
[blocklist_de_ssh](#blocklist_de_ssh)|1764|1764|120|6.8%|83.9%|
[bruteforceblocker](#bruteforceblocker)|1892|1892|83|4.3%|58.0%|
[et_compromised](#et_compromised)|2016|2016|79|3.9%|55.2%|
[shunlist](#shunlist)|1259|1259|69|5.4%|48.2%|
[blocklist_de_strongips](#blocklist_de_strongips)|182|182|21|11.5%|14.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|12|0.0%|8.3%|
[et_block](#et_block)|1023|18338662|12|0.0%|8.3%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|11|0.0%|7.6%|
[dshield](#dshield)|20|5120|7|0.1%|4.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|4|0.0%|2.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|3|0.0%|2.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.6%|
[blocklist_de_mail](#blocklist_de_mail)|15605|15605|1|0.0%|0.6%|
[blocklist_de_imap](#blocklist_de_imap)|1804|1804|1|0.0%|0.6%|

## openbl_30d

[OpenBL.org](http://www.openbl.org/) last 30 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.

Source is downloaded from [this link](http://www.openbl.org/lists/base_30days.txt).

The last time downloaded was found to be dated: Sat Jun  6 07:42:00 UTC 2015.

The ipset `openbl_30d` has **3251** entries, **3251** unique IPs.

The following table shows the overlaps of `openbl_30d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl_30d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl_30d`.
- ` this % ` is the percentage **of this ipset (`openbl_30d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[openbl_60d](#openbl_60d)|7651|7651|3251|42.4%|100.0%|
[alienvault_reputation](#alienvault_reputation)|180710|180710|3236|1.7%|99.5%|
[et_compromised](#et_compromised)|2016|2016|1151|57.0%|35.4%|
[bruteforceblocker](#bruteforceblocker)|1892|1892|1081|57.1%|33.2%|
[openbl_7d](#openbl_7d)|861|861|861|100.0%|26.4%|
[blocklist_de](#blocklist_de)|25421|25421|691|2.7%|21.2%|
[blocklist_de_ssh](#blocklist_de_ssh)|1764|1764|648|36.7%|19.9%|
[shunlist](#shunlist)|1259|1259|552|43.8%|16.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|312|0.0%|9.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|168|0.0%|5.1%|
[et_block](#et_block)|1023|18338662|166|0.0%|5.1%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|160|0.0%|4.9%|
[openbl_1d](#openbl_1d)|143|143|138|96.5%|4.2%|
[dshield](#dshield)|20|5120|88|1.7%|2.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|71|0.0%|2.1%|
[blocklist_de_mail](#blocklist_de_mail)|15605|15605|36|0.2%|1.1%|
[blocklist_de_imap](#blocklist_de_imap)|1804|1804|31|1.7%|0.9%|
[blocklist_de_strongips](#blocklist_de_strongips)|182|182|25|13.7%|0.7%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|13|0.0%|0.3%|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|5|0.0%|0.1%|
[nixspam](#nixspam)|15861|15861|5|0.0%|0.1%|
[blocklist_de_apache](#blocklist_de_apache)|15060|15060|5|0.0%|0.1%|
[snort_ipfilter](#snort_ipfilter)|8977|8977|4|0.0%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|4|0.0%|0.1%|
[voipbl](#voipbl)|10452|10864|3|0.0%|0.0%|
[sorbs_spam](#sorbs_spam)|29892|30945|3|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|29892|30945|3|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|29892|30945|3|0.0%|0.0%|
[zeus](#zeus)|230|230|2|0.8%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|2|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6954|6954|2|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3081|3081|2|0.0%|0.0%|
[zeus_badips](#zeus_badips)|202|202|1|0.4%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|1|0.0%|0.0%|
[sorbs_web](#sorbs_web)|654|655|1|0.1%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|888|888|1|0.1%|0.0%|

## openbl_60d

[OpenBL.org](http://www.openbl.org/) last 60 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.

Source is downloaded from [this link](http://www.openbl.org/lists/base_60days.txt).

The last time downloaded was found to be dated: Sat Jun  6 07:42:00 UTC 2015.

The ipset `openbl_60d` has **7651** entries, **7651** unique IPs.

The following table shows the overlaps of `openbl_60d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl_60d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl_60d`.
- ` this % ` is the percentage **of this ipset (`openbl_60d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[alienvault_reputation](#alienvault_reputation)|180710|180710|7631|4.2%|99.7%|
[openbl_30d](#openbl_30d)|3251|3251|3251|100.0%|42.4%|
[et_compromised](#et_compromised)|2016|2016|1216|60.3%|15.8%|
[bruteforceblocker](#bruteforceblocker)|1892|1892|1130|59.7%|14.7%|
[openbl_7d](#openbl_7d)|861|861|861|100.0%|11.2%|
[blocklist_de](#blocklist_de)|25421|25421|769|3.0%|10.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|745|0.0%|9.7%|
[blocklist_de_ssh](#blocklist_de_ssh)|1764|1764|705|39.9%|9.2%|
[shunlist](#shunlist)|1259|1259|567|45.0%|7.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|332|0.0%|4.3%|
[et_block](#et_block)|1023|18338662|250|0.0%|3.2%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|239|0.0%|3.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|171|0.0%|2.2%|
[openbl_1d](#openbl_1d)|143|143|138|96.5%|1.8%|
[dshield](#dshield)|20|5120|105|2.0%|1.3%|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|57|0.0%|0.7%|
[blocklist_de_mail](#blocklist_de_mail)|15605|15605|43|0.2%|0.5%|
[blocklist_de_imap](#blocklist_de_imap)|1804|1804|38|2.1%|0.4%|
[snort_ipfilter](#snort_ipfilter)|8977|8977|27|0.3%|0.3%|
[blocklist_de_strongips](#blocklist_de_strongips)|182|182|27|14.8%|0.3%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|26|0.0%|0.3%|
[stopforumspam_1d](#stopforumspam_1d)|6954|6954|21|0.3%|0.2%|
[et_tor](#et_tor)|6470|6470|20|0.3%|0.2%|
[dm_tor](#dm_tor)|6485|6485|20|0.3%|0.2%|
[bm_tor](#bm_tor)|6490|6490|20|0.3%|0.2%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|18|4.8%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|17|0.0%|0.2%|
[sorbs_spam](#sorbs_spam)|29892|30945|15|0.0%|0.1%|
[sorbs_recent_spam](#sorbs_recent_spam)|29892|30945|15|0.0%|0.1%|
[sorbs_new_spam](#sorbs_new_spam)|29892|30945|15|0.0%|0.1%|
[nixspam](#nixspam)|15861|15861|13|0.0%|0.1%|
[blocklist_de_bots](#blocklist_de_bots)|3081|3081|10|0.3%|0.1%|
[php_commenters](#php_commenters)|326|326|9|2.7%|0.1%|
[voipbl](#voipbl)|10452|10864|8|0.0%|0.1%|
[blocklist_de_apache](#blocklist_de_apache)|15060|15060|7|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|5|0.0%|0.0%|
[zeus](#zeus)|230|230|2|0.8%|0.0%|
[php_harvesters](#php_harvesters)|311|311|2|0.6%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|888|888|2|0.2%|0.0%|
[zeus_badips](#zeus_badips)|202|202|1|0.4%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|1|0.0%|0.0%|
[sorbs_web](#sorbs_web)|654|655|1|0.1%|0.0%|

## openbl_7d

[OpenBL.org](http://www.openbl.org/) last 7 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.

Source is downloaded from [this link](http://www.openbl.org/lists/base_7days.txt).

The last time downloaded was found to be dated: Sat Jun  6 07:42:00 UTC 2015.

The ipset `openbl_7d` has **861** entries, **861** unique IPs.

The following table shows the overlaps of `openbl_7d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl_7d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl_7d`.
- ` this % ` is the percentage **of this ipset (`openbl_7d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[openbl_60d](#openbl_60d)|7651|7651|861|11.2%|100.0%|
[openbl_30d](#openbl_30d)|3251|3251|861|26.4%|100.0%|
[alienvault_reputation](#alienvault_reputation)|180710|180710|856|0.4%|99.4%|
[blocklist_de](#blocklist_de)|25421|25421|429|1.6%|49.8%|
[blocklist_de_ssh](#blocklist_de_ssh)|1764|1764|414|23.4%|48.0%|
[et_compromised](#et_compromised)|2016|2016|386|19.1%|44.8%|
[bruteforceblocker](#bruteforceblocker)|1892|1892|382|20.1%|44.3%|
[shunlist](#shunlist)|1259|1259|249|19.7%|28.9%|
[openbl_1d](#openbl_1d)|143|143|135|94.4%|15.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|115|0.0%|13.3%|
[et_block](#et_block)|1023|18338662|51|0.0%|5.9%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|48|0.0%|5.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|43|0.0%|4.9%|
[dshield](#dshield)|20|5120|34|0.6%|3.9%|
[blocklist_de_strongips](#blocklist_de_strongips)|182|182|24|13.1%|2.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|19|0.0%|2.2%|
[blocklist_de_mail](#blocklist_de_mail)|15605|15605|12|0.0%|1.3%|
[blocklist_de_imap](#blocklist_de_imap)|1804|1804|11|0.6%|1.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|5|0.0%|0.5%|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|3|0.0%|0.3%|
[nixspam](#nixspam)|15861|15861|3|0.0%|0.3%|
[snort_ipfilter](#snort_ipfilter)|8977|8977|2|0.0%|0.2%|
[blocklist_de_apache](#blocklist_de_apache)|15060|15060|2|0.0%|0.2%|
[voipbl](#voipbl)|10452|10864|1|0.0%|0.1%|
[sorbs_spam](#sorbs_spam)|29892|30945|1|0.0%|0.1%|
[sorbs_recent_spam](#sorbs_recent_spam)|29892|30945|1|0.0%|0.1%|
[sorbs_new_spam](#sorbs_new_spam)|29892|30945|1|0.0%|0.1%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.1%|

## palevo

[Abuse.ch Palevo tracker](https://palevotracker.abuse.ch) worm includes IPs which are being used as botnet C&C for the Palevo crimeware - **excellent list**

Source is downloaded from [this link](https://palevotracker.abuse.ch/blocklists.php?download=ipblocklist).

The last time downloaded was found to be dated: Sat Jun  6 11:00:13 UTC 2015.

The ipset `palevo` has **13** entries, **13** unique IPs.

The following table shows the overlaps of `palevo` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `palevo`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `palevo`.
- ` this % ` is the percentage **of this ipset (`palevo`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[et_block](#et_block)|1023|18338662|13|0.0%|100.0%|
[snort_ipfilter](#snort_ipfilter)|8977|8977|11|0.1%|84.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|2|0.0%|15.3%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|7.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|1|0.0%|7.6%|

## php_commenters

[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) comment spammers (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=c&rss=1).

The last time downloaded was found to be dated: Sat Jun  6 11:18:25 UTC 2015.

The ipset `php_commenters` has **326** entries, **326** unique IPs.

The following table shows the overlaps of `php_commenters` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `php_commenters`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `php_commenters`.
- ` this % ` is the percentage **of this ipset (`php_commenters`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|238|0.2%|73.0%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|171|0.5%|52.4%|
[stopforumspam_1d](#stopforumspam_1d)|6954|6954|125|1.7%|38.3%|
[blocklist_de](#blocklist_de)|25421|25421|77|0.3%|23.6%|
[blocklist_de_bots](#blocklist_de_bots)|3081|3081|63|2.0%|19.3%|
[snort_ipfilter](#snort_ipfilter)|8977|8977|44|0.4%|13.4%|
[php_spammers](#php_spammers)|536|536|36|6.7%|11.0%|
[et_tor](#et_tor)|6470|6470|35|0.5%|10.7%|
[blocklist_de_strongips](#blocklist_de_strongips)|182|182|35|19.2%|10.7%|
[dm_tor](#dm_tor)|6485|6485|34|0.5%|10.4%|
[bm_tor](#bm_tor)|6490|6490|34|0.5%|10.4%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|32|8.6%|9.8%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|28|0.0%|8.5%|
[et_block](#et_block)|1023|18338662|28|0.0%|8.5%|
[blocklist_de_apache](#blocklist_de_apache)|15060|15060|25|0.1%|7.6%|
[php_dictionary](#php_dictionary)|545|545|24|4.4%|7.3%|
[blocklist_de_mail](#blocklist_de_mail)|15605|15605|21|0.1%|6.4%|
[ri_web_proxies](#ri_web_proxies)|6565|6565|19|0.2%|5.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|18|0.0%|5.5%|
[sorbs_spam](#sorbs_spam)|29892|30945|15|0.0%|4.6%|
[sorbs_recent_spam](#sorbs_recent_spam)|29892|30945|15|0.0%|4.6%|
[sorbs_new_spam](#sorbs_new_spam)|29892|30945|15|0.0%|4.6%|
[alienvault_reputation](#alienvault_reputation)|180710|180710|15|0.0%|4.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|13|0.0%|3.9%|
[php_harvesters](#php_harvesters)|311|311|11|3.5%|3.3%|
[nixspam](#nixspam)|15861|15861|10|0.0%|3.0%|
[openbl_60d](#openbl_60d)|7651|7651|9|0.1%|2.7%|
[xroxy](#xroxy)|2098|2098|7|0.3%|2.1%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|7|0.0%|2.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|7|0.0%|2.1%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|3708|3708|7|0.1%|2.1%|
[ri_connect_proxies](#ri_connect_proxies)|2447|2447|4|0.1%|1.2%|
[proxz](#proxz)|874|874|4|0.4%|1.2%|
[sorbs_web](#sorbs_web)|654|655|3|0.4%|0.9%|
[proxyrss](#proxyrss)|1599|1599|3|0.1%|0.9%|
[zeus_badips](#zeus_badips)|202|202|1|0.4%|0.3%|
[zeus](#zeus)|230|230|1|0.4%|0.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.3%|

## php_dictionary

[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) directory attackers (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=d&rss=1).

The last time downloaded was found to be dated: Sat Jun  6 10:27:18 UTC 2015.

The ipset `php_dictionary` has **545** entries, **545** unique IPs.

The following table shows the overlaps of `php_dictionary` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `php_dictionary`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `php_dictionary`.
- ` this % ` is the percentage **of this ipset (`php_dictionary`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[php_spammers](#php_spammers)|536|536|180|33.5%|33.0%|
[sorbs_spam](#sorbs_spam)|29892|30945|150|0.4%|27.5%|
[sorbs_recent_spam](#sorbs_recent_spam)|29892|30945|150|0.4%|27.5%|
[sorbs_new_spam](#sorbs_new_spam)|29892|30945|150|0.4%|27.5%|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|103|0.1%|18.8%|
[blocklist_de](#blocklist_de)|25421|25421|94|0.3%|17.2%|
[snort_ipfilter](#snort_ipfilter)|8977|8977|78|0.8%|14.3%|
[nixspam](#nixspam)|15861|15861|68|0.4%|12.4%|
[blocklist_de_mail](#blocklist_de_mail)|15605|15605|67|0.4%|12.2%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|66|0.2%|12.1%|
[ri_web_proxies](#ri_web_proxies)|6565|6565|43|0.6%|7.8%|
[stopforumspam_1d](#stopforumspam_1d)|6954|6954|33|0.4%|6.0%|
[xroxy](#xroxy)|2098|2098|32|1.5%|5.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|31|0.0%|5.6%|
[sorbs_web](#sorbs_web)|654|655|29|4.4%|5.3%|
[php_commenters](#php_commenters)|326|326|24|7.3%|4.4%|
[blocklist_de_bots](#blocklist_de_bots)|3081|3081|20|0.6%|3.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|17|0.0%|3.1%|
[proxz](#proxz)|874|874|12|1.3%|2.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|11|0.0%|2.0%|
[alienvault_reputation](#alienvault_reputation)|180710|180710|8|0.0%|1.4%|
[et_tor](#et_tor)|6470|6470|5|0.0%|0.9%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|4|0.0%|0.7%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|4|1.0%|0.7%|
[et_block](#et_block)|1023|18338662|4|0.0%|0.7%|
[dm_tor](#dm_tor)|6485|6485|4|0.0%|0.7%|
[bm_tor](#bm_tor)|6490|6490|4|0.0%|0.7%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|3708|3708|4|0.1%|0.7%|
[blocklist_de_apache](#blocklist_de_apache)|15060|15060|4|0.0%|0.7%|
[ri_connect_proxies](#ri_connect_proxies)|2447|2447|3|0.1%|0.5%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|3|0.0%|0.5%|
[blocklist_de_strongips](#blocklist_de_strongips)|182|182|3|1.6%|0.5%|
[sorbs_socks](#sorbs_socks)|19|19|2|10.5%|0.3%|
[sorbs_misc](#sorbs_misc)|19|19|2|10.5%|0.3%|
[sorbs_http](#sorbs_http)|19|19|2|10.5%|0.3%|
[proxyrss](#proxyrss)|1599|1599|2|0.1%|0.3%|
[php_harvesters](#php_harvesters)|311|311|2|0.6%|0.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2|0.0%|0.3%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.1%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|1|0.1%|0.1%|
[blocklist_de_ftp](#blocklist_de_ftp)|888|888|1|0.1%|0.1%|

## php_harvesters

[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) harvesters (IPs that surf the internet looking for email addresses) (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=h&rss=1).

The last time downloaded was found to be dated: Sat Jun  6 11:18:17 UTC 2015.

The ipset `php_harvesters` has **311** entries, **311** unique IPs.

The following table shows the overlaps of `php_harvesters` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `php_harvesters`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `php_harvesters`.
- ` this % ` is the percentage **of this ipset (`php_harvesters`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|68|0.0%|21.8%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|51|0.1%|16.3%|
[stopforumspam_1d](#stopforumspam_1d)|6954|6954|38|0.5%|12.2%|
[blocklist_de](#blocklist_de)|25421|25421|30|0.1%|9.6%|
[blocklist_de_bots](#blocklist_de_bots)|3081|3081|23|0.7%|7.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|17|0.0%|5.4%|
[snort_ipfilter](#snort_ipfilter)|8977|8977|11|0.1%|3.5%|
[php_commenters](#php_commenters)|326|326|11|3.3%|3.5%|
[alienvault_reputation](#alienvault_reputation)|180710|180710|10|0.0%|3.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|9|0.0%|2.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|9|0.0%|2.8%|
[sorbs_spam](#sorbs_spam)|29892|30945|7|0.0%|2.2%|
[sorbs_recent_spam](#sorbs_recent_spam)|29892|30945|7|0.0%|2.2%|
[sorbs_new_spam](#sorbs_new_spam)|29892|30945|7|0.0%|2.2%|
[et_tor](#et_tor)|6470|6470|7|0.1%|2.2%|
[dm_tor](#dm_tor)|6485|6485|7|0.1%|2.2%|
[bm_tor](#bm_tor)|6490|6490|7|0.1%|2.2%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|6|1.6%|1.9%|
[blocklist_de_apache](#blocklist_de_apache)|15060|15060|5|0.0%|1.6%|
[nixspam](#nixspam)|15861|15861|3|0.0%|0.9%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|3708|3708|3|0.0%|0.9%|
[xroxy](#xroxy)|2098|2098|2|0.0%|0.6%|
[proxyrss](#proxyrss)|1599|1599|2|0.1%|0.6%|
[php_spammers](#php_spammers)|536|536|2|0.3%|0.6%|
[php_dictionary](#php_dictionary)|545|545|2|0.3%|0.6%|
[openbl_60d](#openbl_60d)|7651|7651|2|0.0%|0.6%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|2|0.0%|0.6%|
[blocklist_de_strongips](#blocklist_de_strongips)|182|182|2|1.0%|0.6%|
[blocklist_de_ftp](#blocklist_de_ftp)|888|888|2|0.2%|0.6%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|1|0.0%|0.3%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|1|0.0%|0.3%|
[ri_web_proxies](#ri_web_proxies)|6565|6565|1|0.0%|0.3%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.3%|
[fullbogons](#fullbogons)|3721|670267288|1|0.0%|0.3%|
[et_block](#et_block)|1023|18338662|1|0.0%|0.3%|
[bogons](#bogons)|13|592708608|1|0.0%|0.3%|
[blocklist_de_mail](#blocklist_de_mail)|15605|15605|1|0.0%|0.3%|

## php_spammers

[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) spam servers (IPs used by spammers to send messages) (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=s&rss=1).

The last time downloaded was found to be dated: Sat Jun  6 11:18:18 UTC 2015.

The ipset `php_spammers` has **536** entries, **536** unique IPs.

The following table shows the overlaps of `php_spammers` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `php_spammers`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `php_spammers`.
- ` this % ` is the percentage **of this ipset (`php_spammers`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[php_dictionary](#php_dictionary)|545|545|180|33.0%|33.5%|
[sorbs_spam](#sorbs_spam)|29892|30945|133|0.4%|24.8%|
[sorbs_recent_spam](#sorbs_recent_spam)|29892|30945|133|0.4%|24.8%|
[sorbs_new_spam](#sorbs_new_spam)|29892|30945|133|0.4%|24.8%|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|117|0.1%|21.8%|
[blocklist_de](#blocklist_de)|25421|25421|98|0.3%|18.2%|
[snort_ipfilter](#snort_ipfilter)|8977|8977|74|0.8%|13.8%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|66|0.2%|12.3%|
[blocklist_de_mail](#blocklist_de_mail)|15605|15605|63|0.4%|11.7%|
[nixspam](#nixspam)|15861|15861|61|0.3%|11.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|45|0.0%|8.3%|
[ri_web_proxies](#ri_web_proxies)|6565|6565|38|0.5%|7.0%|
[stopforumspam_1d](#stopforumspam_1d)|6954|6954|36|0.5%|6.7%|
[php_commenters](#php_commenters)|326|326|36|11.0%|6.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|31|0.0%|5.7%|
[sorbs_web](#sorbs_web)|654|655|27|4.1%|5.0%|
[xroxy](#xroxy)|2098|2098|26|1.2%|4.8%|
[blocklist_de_bots](#blocklist_de_bots)|3081|3081|25|0.8%|4.6%|
[proxz](#proxz)|874|874|15|1.7%|2.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|7|0.0%|1.3%|
[et_tor](#et_tor)|6470|6470|6|0.0%|1.1%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|3708|3708|6|0.1%|1.1%|
[blocklist_de_apache](#blocklist_de_apache)|15060|15060|6|0.0%|1.1%|
[dm_tor](#dm_tor)|6485|6485|5|0.0%|0.9%|
[bm_tor](#bm_tor)|6490|6490|5|0.0%|0.9%|
[blocklist_de_strongips](#blocklist_de_strongips)|182|182|5|2.7%|0.9%|
[alienvault_reputation](#alienvault_reputation)|180710|180710|5|0.0%|0.9%|
[proxyrss](#proxyrss)|1599|1599|4|0.2%|0.7%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|4|1.0%|0.7%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|3|0.0%|0.5%|
[ri_connect_proxies](#ri_connect_proxies)|2447|2447|3|0.1%|0.5%|
[php_harvesters](#php_harvesters)|311|311|2|0.6%|0.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2|0.0%|0.3%|
[et_block](#et_block)|1023|18338662|2|0.0%|0.3%|
[blocklist_de_ftp](#blocklist_de_ftp)|888|888|2|0.2%|0.3%|
[sorbs_socks](#sorbs_socks)|19|19|1|5.2%|0.1%|
[sorbs_misc](#sorbs_misc)|19|19|1|5.2%|0.1%|
[sorbs_http](#sorbs_http)|19|19|1|5.2%|0.1%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1|0.0%|0.1%|

## proxyrss

[proxyrss.com](http://www.proxyrss.com) open proxies syndicated from multiple sources.

Source is downloaded from [this link](http://www.proxyrss.com/proxylists/all.gz).

The last time downloaded was found to be dated: Sat Jun  6 08:01:22 UTC 2015.

The ipset `proxyrss` has **1599** entries, **1599** unique IPs.

The following table shows the overlaps of `proxyrss` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `proxyrss`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `proxyrss`.
- ` this % ` is the percentage **of this ipset (`proxyrss`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|790|0.8%|49.4%|
[ri_web_proxies](#ri_web_proxies)|6565|6565|672|10.2%|42.0%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|626|2.0%|39.1%|
[xroxy](#xroxy)|2098|2098|427|20.3%|26.7%|
[stopforumspam_1d](#stopforumspam_1d)|6954|6954|375|5.3%|23.4%|
[ri_connect_proxies](#ri_connect_proxies)|2447|2447|251|10.2%|15.6%|
[proxz](#proxz)|874|874|251|28.7%|15.6%|
[blocklist_de_bots](#blocklist_de_bots)|3081|3081|212|6.8%|13.2%|
[blocklist_de](#blocklist_de)|25421|25421|212|0.8%|13.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|67|0.0%|4.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|61|0.0%|3.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|36|0.0%|2.2%|
[nixspam](#nixspam)|15861|15861|13|0.0%|0.8%|
[sorbs_spam](#sorbs_spam)|29892|30945|8|0.0%|0.5%|
[sorbs_recent_spam](#sorbs_recent_spam)|29892|30945|8|0.0%|0.5%|
[sorbs_new_spam](#sorbs_new_spam)|29892|30945|8|0.0%|0.5%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|8|1.1%|0.5%|
[blocklist_de_strongips](#blocklist_de_strongips)|182|182|7|3.8%|0.4%|
[snort_ipfilter](#snort_ipfilter)|8977|8977|4|0.0%|0.2%|
[php_spammers](#php_spammers)|536|536|4|0.7%|0.2%|
[php_commenters](#php_commenters)|326|326|3|0.9%|0.1%|
[php_harvesters](#php_harvesters)|311|311|2|0.6%|0.1%|
[php_dictionary](#php_dictionary)|545|545|2|0.3%|0.1%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|2|0.0%|0.1%|
[sorbs_web](#sorbs_web)|654|655|1|0.1%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.0%|
[alienvault_reputation](#alienvault_reputation)|180710|180710|1|0.0%|0.0%|

## proxz

[proxz.com](http://www.proxz.com) open proxies (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.proxz.com/proxylists.xml).

The last time downloaded was found to be dated: Sat Jun  6 10:21:38 UTC 2015.

The ipset `proxz` has **874** entries, **874** unique IPs.

The following table shows the overlaps of `proxz` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `proxz`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `proxz`.
- ` this % ` is the percentage **of this ipset (`proxz`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|526|0.5%|60.1%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|414|1.3%|47.3%|
[ri_web_proxies](#ri_web_proxies)|6565|6565|400|6.0%|45.7%|
[xroxy](#xroxy)|2098|2098|343|16.3%|39.2%|
[proxyrss](#proxyrss)|1599|1599|251|15.6%|28.7%|
[stopforumspam_1d](#stopforumspam_1d)|6954|6954|156|2.2%|17.8%|
[ri_connect_proxies](#ri_connect_proxies)|2447|2447|142|5.8%|16.2%|
[blocklist_de](#blocklist_de)|25421|25421|142|0.5%|16.2%|
[blocklist_de_bots](#blocklist_de_bots)|3081|3081|121|3.9%|13.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|72|0.0%|8.2%|
[sorbs_spam](#sorbs_spam)|29892|30945|40|0.1%|4.5%|
[sorbs_recent_spam](#sorbs_recent_spam)|29892|30945|40|0.1%|4.5%|
[sorbs_new_spam](#sorbs_new_spam)|29892|30945|40|0.1%|4.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|35|0.0%|4.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|31|0.0%|3.5%|
[snort_ipfilter](#snort_ipfilter)|8977|8977|21|0.2%|2.4%|
[blocklist_de_mail](#blocklist_de_mail)|15605|15605|21|0.1%|2.4%|
[nixspam](#nixspam)|15861|15861|20|0.1%|2.2%|
[php_spammers](#php_spammers)|536|536|15|2.7%|1.7%|
[php_dictionary](#php_dictionary)|545|545|12|2.2%|1.3%|
[sorbs_web](#sorbs_web)|654|655|10|1.5%|1.1%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|6|0.8%|0.6%|
[php_commenters](#php_commenters)|326|326|4|1.2%|0.4%|
[blocklist_de_strongips](#blocklist_de_strongips)|182|182|4|2.1%|0.4%|
[alienvault_reputation](#alienvault_reputation)|180710|180710|3|0.0%|0.3%|
[et_compromised](#et_compromised)|2016|2016|2|0.0%|0.2%|
[bruteforceblocker](#bruteforceblocker)|1892|1892|2|0.1%|0.2%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1|0.0%|0.1%|

## ri_connect_proxies

[rosinstrument.com](http://www.rosinstrument.com) open CONNECT proxies (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://tools.rosinstrument.com/proxy/plab100.xml).

The last time downloaded was found to be dated: Sat Jun  6 05:14:34 UTC 2015.

The ipset `ri_connect_proxies` has **2447** entries, **2447** unique IPs.

The following table shows the overlaps of `ri_connect_proxies` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ri_connect_proxies`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ri_connect_proxies`.
- ` this % ` is the percentage **of this ipset (`ri_connect_proxies`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|1412|1.5%|57.7%|
[ri_web_proxies](#ri_web_proxies)|6565|6565|1012|15.4%|41.3%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|646|2.1%|26.3%|
[xroxy](#xroxy)|2098|2098|365|17.3%|14.9%|
[proxyrss](#proxyrss)|1599|1599|251|15.6%|10.2%|
[proxz](#proxz)|874|874|142|16.2%|5.8%|
[stopforumspam_1d](#stopforumspam_1d)|6954|6954|135|1.9%|5.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|96|0.0%|3.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|76|0.0%|3.1%|
[blocklist_de](#blocklist_de)|25421|25421|66|0.2%|2.6%|
[blocklist_de_bots](#blocklist_de_bots)|3081|3081|63|2.0%|2.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|53|0.0%|2.1%|
[nixspam](#nixspam)|15861|15861|14|0.0%|0.5%|
[sorbs_spam](#sorbs_spam)|29892|30945|11|0.0%|0.4%|
[sorbs_recent_spam](#sorbs_recent_spam)|29892|30945|11|0.0%|0.4%|
[sorbs_new_spam](#sorbs_new_spam)|29892|30945|11|0.0%|0.4%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|6|0.8%|0.2%|
[php_commenters](#php_commenters)|326|326|4|1.2%|0.1%|
[snort_ipfilter](#snort_ipfilter)|8977|8977|3|0.0%|0.1%|
[php_spammers](#php_spammers)|536|536|3|0.5%|0.1%|
[php_dictionary](#php_dictionary)|545|545|3|0.5%|0.1%|
[blocklist_de_mail](#blocklist_de_mail)|15605|15605|3|0.0%|0.1%|
[alienvault_reputation](#alienvault_reputation)|180710|180710|3|0.0%|0.1%|
[sorbs_web](#sorbs_web)|654|655|1|0.1%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.0%|
[et_tor](#et_tor)|6470|6470|1|0.0%|0.0%|
[dm_tor](#dm_tor)|6485|6485|1|0.0%|0.0%|
[bm_tor](#bm_tor)|6490|6490|1|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|1804|1804|1|0.0%|0.0%|

## ri_web_proxies

[rosinstrument.com](http://www.rosinstrument.com) open HTTP proxies (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://tools.rosinstrument.com/proxy/l100.xml).

The last time downloaded was found to be dated: Sat Jun  6 06:38:59 UTC 2015.

The ipset `ri_web_proxies` has **6565** entries, **6565** unique IPs.

The following table shows the overlaps of `ri_web_proxies` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ri_web_proxies`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ri_web_proxies`.
- ` this % ` is the percentage **of this ipset (`ri_web_proxies`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|3182|3.4%|48.4%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|1613|5.3%|24.5%|
[ri_connect_proxies](#ri_connect_proxies)|2447|2447|1012|41.3%|15.4%|
[xroxy](#xroxy)|2098|2098|898|42.8%|13.6%|
[proxyrss](#proxyrss)|1599|1599|672|42.0%|10.2%|
[stopforumspam_1d](#stopforumspam_1d)|6954|6954|473|6.8%|7.2%|
[proxz](#proxz)|874|874|400|45.7%|6.0%|
[blocklist_de](#blocklist_de)|25421|25421|385|1.5%|5.8%|
[blocklist_de_bots](#blocklist_de_bots)|3081|3081|330|10.7%|5.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|191|0.0%|2.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|190|0.0%|2.8%|
[sorbs_spam](#sorbs_spam)|29892|30945|138|0.4%|2.1%|
[sorbs_recent_spam](#sorbs_recent_spam)|29892|30945|138|0.4%|2.1%|
[sorbs_new_spam](#sorbs_new_spam)|29892|30945|138|0.4%|2.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|135|0.0%|2.0%|
[snort_ipfilter](#snort_ipfilter)|8977|8977|63|0.7%|0.9%|
[nixspam](#nixspam)|15861|15861|58|0.3%|0.8%|
[blocklist_de_mail](#blocklist_de_mail)|15605|15605|55|0.3%|0.8%|
[php_dictionary](#php_dictionary)|545|545|43|7.8%|0.6%|
[php_spammers](#php_spammers)|536|536|38|7.0%|0.5%|
[sorbs_web](#sorbs_web)|654|655|24|3.6%|0.3%|
[php_commenters](#php_commenters)|326|326|19|5.8%|0.2%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|12|1.7%|0.1%|
[blocklist_de_strongips](#blocklist_de_strongips)|182|182|6|3.2%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|5|0.0%|0.0%|
[et_tor](#et_tor)|6470|6470|5|0.0%|0.0%|
[dm_tor](#dm_tor)|6485|6485|5|0.0%|0.0%|
[bm_tor](#bm_tor)|6490|6490|5|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|4|1.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|3|0.0%|0.0%|
[alienvault_reputation](#alienvault_reputation)|180710|180710|3|0.0%|0.0%|
[sslbl](#sslbl)|370|370|1|0.2%|0.0%|
[php_harvesters](#php_harvesters)|311|311|1|0.3%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|
[et_compromised](#et_compromised)|2016|2016|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1892|1892|1|0.0%|0.0%|

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
[openbl_60d](#openbl_60d)|7651|7651|567|7.4%|45.0%|
[openbl_30d](#openbl_30d)|3251|3251|552|16.9%|43.8%|
[et_compromised](#et_compromised)|2016|2016|460|22.8%|36.5%|
[bruteforceblocker](#bruteforceblocker)|1892|1892|450|23.7%|35.7%|
[blocklist_de](#blocklist_de)|25421|25421|365|1.4%|28.9%|
[blocklist_de_ssh](#blocklist_de_ssh)|1764|1764|329|18.6%|26.1%|
[openbl_7d](#openbl_7d)|861|861|249|28.9%|19.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|113|0.0%|8.9%|
[et_block](#et_block)|1023|18338662|111|0.0%|8.8%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|97|0.0%|7.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|73|0.0%|5.7%|
[openbl_1d](#openbl_1d)|143|143|69|48.2%|5.4%|
[dshield](#dshield)|20|5120|59|1.1%|4.6%|
[sslbl](#sslbl)|370|370|57|15.4%|4.5%|
[blocklist_de_apache](#blocklist_de_apache)|15060|15060|35|0.2%|2.7%|
[ciarmy](#ciarmy)|402|402|29|7.2%|2.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|28|0.0%|2.2%|
[blocklist_de_strongips](#blocklist_de_strongips)|182|182|20|10.9%|1.5%|
[voipbl](#voipbl)|10452|10864|12|0.1%|0.9%|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|4|0.0%|0.3%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|2|0.0%|0.1%|
[snort_ipfilter](#snort_ipfilter)|8977|8977|2|0.0%|0.1%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|2|0.5%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2|0.0%|0.1%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|3708|3708|2|0.0%|0.1%|
[stopforumspam_1d](#stopforumspam_1d)|6954|6954|1|0.0%|0.0%|
[sorbs_spam](#sorbs_spam)|29892|30945|1|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|29892|30945|1|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|29892|30945|1|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.0%|
[et_tor](#et_tor)|6470|6470|1|0.0%|0.0%|
[dm_tor](#dm_tor)|6485|6485|1|0.0%|0.0%|
[bm_tor](#bm_tor)|6490|6490|1|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|15605|15605|1|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|1804|1804|1|0.0%|0.0%|

## snort_ipfilter

[labs.snort.org](https://labs.snort.org/) supplied IP blacklist (this list seems to be updated frequently, but we found no information about it)

Source is downloaded from [this link](http://labs.snort.org/feeds/ip-filter.blf).

The last time downloaded was found to be dated: Sat Jun  6 01:30:00 UTC 2015.

The ipset `snort_ipfilter` has **8977** entries, **8977** unique IPs.

The following table shows the overlaps of `snort_ipfilter` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `snort_ipfilter`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `snort_ipfilter`.
- ` this % ` is the percentage **of this ipset (`snort_ipfilter`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[et_tor](#et_tor)|6470|6470|1085|16.7%|12.0%|
[bm_tor](#bm_tor)|6490|6490|1052|16.2%|11.7%|
[dm_tor](#dm_tor)|6485|6485|1051|16.2%|11.7%|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|804|0.8%|8.9%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|632|2.0%|7.0%|
[stopforumspam_1d](#stopforumspam_1d)|6954|6954|381|5.4%|4.2%|
[et_block](#et_block)|1023|18338662|317|0.0%|3.5%|
[sorbs_spam](#sorbs_spam)|29892|30945|309|0.9%|3.4%|
[sorbs_recent_spam](#sorbs_recent_spam)|29892|30945|309|0.9%|3.4%|
[sorbs_new_spam](#sorbs_new_spam)|29892|30945|309|0.9%|3.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|231|0.0%|2.5%|
[zeus](#zeus)|230|230|201|87.3%|2.2%|
[zeus_badips](#zeus_badips)|202|202|179|88.6%|1.9%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|177|47.5%|1.9%|
[blocklist_de](#blocklist_de)|25421|25421|168|0.6%|1.8%|
[blocklist_de_mail](#blocklist_de_mail)|15605|15605|137|0.8%|1.5%|
[alienvault_reputation](#alienvault_reputation)|180710|180710|119|0.0%|1.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|100|0.0%|1.1%|
[nixspam](#nixspam)|15861|15861|95|0.5%|1.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|83|0.0%|0.9%|
[php_dictionary](#php_dictionary)|545|545|78|14.3%|0.8%|
[feodo](#feodo)|99|99|76|76.7%|0.8%|
[php_spammers](#php_spammers)|536|536|74|13.8%|0.8%|
[ri_web_proxies](#ri_web_proxies)|6565|6565|63|0.9%|0.7%|
[sorbs_web](#sorbs_web)|654|655|48|7.3%|0.5%|
[xroxy](#xroxy)|2098|2098|46|2.1%|0.5%|
[php_commenters](#php_commenters)|326|326|44|13.4%|0.4%|
[sslbl](#sslbl)|370|370|31|8.3%|0.3%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|28|2.1%|0.3%|
[openbl_60d](#openbl_60d)|7651|7651|27|0.3%|0.3%|
[blocklist_de_bots](#blocklist_de_bots)|3081|3081|23|0.7%|0.2%|
[proxz](#proxz)|874|874|21|2.4%|0.2%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|20|0.0%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|14|0.0%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|12|0.0%|0.1%|
[php_harvesters](#php_harvesters)|311|311|11|3.5%|0.1%|
[palevo](#palevo)|13|13|11|84.6%|0.1%|
[blocklist_de_apache](#blocklist_de_apache)|15060|15060|9|0.0%|0.1%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|6|0.0%|0.0%|
[sorbs_socks](#sorbs_socks)|19|19|6|31.5%|0.0%|
[sorbs_misc](#sorbs_misc)|19|19|6|31.5%|0.0%|
[sorbs_http](#sorbs_http)|19|19|6|31.5%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|3708|3708|5|0.1%|0.0%|
[proxyrss](#proxyrss)|1599|1599|4|0.2%|0.0%|
[openbl_30d](#openbl_30d)|3251|3251|4|0.1%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2447|2447|3|0.1%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|1804|1804|3|0.1%|0.0%|
[shunlist](#shunlist)|1259|1259|2|0.1%|0.0%|
[openbl_7d](#openbl_7d)|861|861|2|0.2%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|1|0.1%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1|0.0%|0.0%|
[dshield](#dshield)|20|5120|1|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|182|182|1|0.5%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1764|1764|1|0.0%|0.0%|

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

The last time downloaded was found to be dated: Fri Jun  5 17:04:14 UTC 2015.

The ipset `sorbs_http` has **19** entries, **19** unique IPs.

The following table shows the overlaps of `sorbs_http` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `sorbs_http`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `sorbs_http`.
- ` this % ` is the percentage **of this ipset (`sorbs_http`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[sorbs_spam](#sorbs_spam)|29892|30945|19|0.0%|100.0%|
[sorbs_socks](#sorbs_socks)|19|19|19|100.0%|100.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|29892|30945|19|0.0%|100.0%|
[sorbs_new_spam](#sorbs_new_spam)|29892|30945|19|0.0%|100.0%|
[sorbs_misc](#sorbs_misc)|19|19|19|100.0%|100.0%|
[snort_ipfilter](#snort_ipfilter)|8977|8977|6|0.0%|31.5%|
[blocklist_de_mail](#blocklist_de_mail)|15605|15605|5|0.0%|26.3%|
[blocklist_de](#blocklist_de)|25421|25421|5|0.0%|26.3%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|3|0.0%|15.7%|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|3|0.0%|15.7%|
[sorbs_web](#sorbs_web)|654|655|3|0.4%|15.7%|
[php_dictionary](#php_dictionary)|545|545|2|0.3%|10.5%|
[xroxy](#xroxy)|2098|2098|1|0.0%|5.2%|
[php_spammers](#php_spammers)|536|536|1|0.1%|5.2%|
[nixspam](#nixspam)|15861|15861|1|0.0%|5.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|1|0.0%|5.2%|

## sorbs_misc

[Sorbs.net](https://www.sorbs.net/) MISC proxies, extracted from deltas.

Source is downloaded from [this link]().

The last time downloaded was found to be dated: Fri Jun  5 17:04:14 UTC 2015.

The ipset `sorbs_misc` has **19** entries, **19** unique IPs.

The following table shows the overlaps of `sorbs_misc` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `sorbs_misc`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `sorbs_misc`.
- ` this % ` is the percentage **of this ipset (`sorbs_misc`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[sorbs_spam](#sorbs_spam)|29892|30945|19|0.0%|100.0%|
[sorbs_socks](#sorbs_socks)|19|19|19|100.0%|100.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|29892|30945|19|0.0%|100.0%|
[sorbs_new_spam](#sorbs_new_spam)|29892|30945|19|0.0%|100.0%|
[sorbs_http](#sorbs_http)|19|19|19|100.0%|100.0%|
[snort_ipfilter](#snort_ipfilter)|8977|8977|6|0.0%|31.5%|
[blocklist_de_mail](#blocklist_de_mail)|15605|15605|5|0.0%|26.3%|
[blocklist_de](#blocklist_de)|25421|25421|5|0.0%|26.3%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|3|0.0%|15.7%|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|3|0.0%|15.7%|
[sorbs_web](#sorbs_web)|654|655|3|0.4%|15.7%|
[php_dictionary](#php_dictionary)|545|545|2|0.3%|10.5%|
[xroxy](#xroxy)|2098|2098|1|0.0%|5.2%|
[php_spammers](#php_spammers)|536|536|1|0.1%|5.2%|
[nixspam](#nixspam)|15861|15861|1|0.0%|5.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|1|0.0%|5.2%|

## sorbs_new_spam

[Sorbs.net](https://www.sorbs.net/) NEW Spam senders, extracted from deltas.

Source is downloaded from [this link]().

The last time downloaded was found to be dated: Sat Jun  6 11:04:11 UTC 2015.

The ipset `sorbs_new_spam` has **29892** entries, **30945** unique IPs.

The following table shows the overlaps of `sorbs_new_spam` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `sorbs_new_spam`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `sorbs_new_spam`.
- ` this % ` is the percentage **of this ipset (`sorbs_new_spam`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[sorbs_spam](#sorbs_spam)|29892|30945|30945|100.0%|100.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|29892|30945|30945|100.0%|100.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|2243|0.0%|7.2%|
[nixspam](#nixspam)|15861|15861|2210|13.9%|7.1%|
[blocklist_de](#blocklist_de)|25421|25421|1066|4.1%|3.4%|
[blocklist_de_mail](#blocklist_de_mail)|15605|15605|907|5.8%|2.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|783|0.0%|2.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|487|0.0%|1.5%|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|341|0.3%|1.1%|
[sorbs_web](#sorbs_web)|654|655|318|48.5%|1.0%|
[snort_ipfilter](#snort_ipfilter)|8977|8977|309|3.4%|0.9%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|181|0.6%|0.5%|
[php_dictionary](#php_dictionary)|545|545|150|27.5%|0.4%|
[ri_web_proxies](#ri_web_proxies)|6565|6565|138|2.1%|0.4%|
[php_spammers](#php_spammers)|536|536|133|24.8%|0.4%|
[alienvault_reputation](#alienvault_reputation)|180710|180710|105|0.0%|0.3%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|3708|3708|104|2.8%|0.3%|
[blocklist_de_apache](#blocklist_de_apache)|15060|15060|104|0.6%|0.3%|
[xroxy](#xroxy)|2098|2098|86|4.0%|0.2%|
[stopforumspam_1d](#stopforumspam_1d)|6954|6954|59|0.8%|0.1%|
[blocklist_de_bots](#blocklist_de_bots)|3081|3081|45|1.4%|0.1%|
[proxz](#proxz)|874|874|40|4.5%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|33|0.0%|0.1%|
[sorbs_socks](#sorbs_socks)|19|19|19|100.0%|0.0%|
[sorbs_misc](#sorbs_misc)|19|19|19|100.0%|0.0%|
[sorbs_http](#sorbs_http)|19|19|19|100.0%|0.0%|
[php_commenters](#php_commenters)|326|326|15|4.6%|0.0%|
[openbl_60d](#openbl_60d)|7651|7651|15|0.1%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|15|0.0%|0.0%|
[sorbs_smtp](#sorbs_smtp)|13|13|13|100.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|1804|1804|12|0.6%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2447|2447|11|0.4%|0.0%|
[et_block](#et_block)|1023|18338662|10|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|8|0.0%|0.0%|
[proxyrss](#proxyrss)|1599|1599|8|0.5%|0.0%|
[php_harvesters](#php_harvesters)|311|311|7|2.2%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|4|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|888|888|4|0.4%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|3|0.0%|0.0%|
[openbl_30d](#openbl_30d)|3251|3251|3|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|2|0.2%|0.0%|
[et_tor](#et_tor)|6470|6470|2|0.0%|0.0%|
[dshield](#dshield)|20|5120|2|0.0%|0.0%|
[dm_tor](#dm_tor)|6485|6485|2|0.0%|0.0%|
[bm_tor](#bm_tor)|6490|6490|2|0.0%|0.0%|
[shunlist](#shunlist)|1259|1259|1|0.0%|0.0%|
[openbl_7d](#openbl_7d)|861|861|1|0.1%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|1|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|182|182|1|0.5%|0.0%|

## sorbs_recent_spam

[Sorbs.net](https://www.sorbs.net/) RECENT Spam senders, extracted from deltas.

Source is downloaded from [this link]().

The last time downloaded was found to be dated: Sat Jun  6 11:04:11 UTC 2015.

The ipset `sorbs_recent_spam` has **29892** entries, **30945** unique IPs.

The following table shows the overlaps of `sorbs_recent_spam` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `sorbs_recent_spam`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `sorbs_recent_spam`.
- ` this % ` is the percentage **of this ipset (`sorbs_recent_spam`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[sorbs_spam](#sorbs_spam)|29892|30945|30945|100.0%|100.0%|
[sorbs_new_spam](#sorbs_new_spam)|29892|30945|30945|100.0%|100.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|2243|0.0%|7.2%|
[nixspam](#nixspam)|15861|15861|2210|13.9%|7.1%|
[blocklist_de](#blocklist_de)|25421|25421|1066|4.1%|3.4%|
[blocklist_de_mail](#blocklist_de_mail)|15605|15605|907|5.8%|2.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|783|0.0%|2.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|487|0.0%|1.5%|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|341|0.3%|1.1%|
[sorbs_web](#sorbs_web)|654|655|318|48.5%|1.0%|
[snort_ipfilter](#snort_ipfilter)|8977|8977|309|3.4%|0.9%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|181|0.6%|0.5%|
[php_dictionary](#php_dictionary)|545|545|150|27.5%|0.4%|
[ri_web_proxies](#ri_web_proxies)|6565|6565|138|2.1%|0.4%|
[php_spammers](#php_spammers)|536|536|133|24.8%|0.4%|
[alienvault_reputation](#alienvault_reputation)|180710|180710|105|0.0%|0.3%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|3708|3708|104|2.8%|0.3%|
[blocklist_de_apache](#blocklist_de_apache)|15060|15060|104|0.6%|0.3%|
[xroxy](#xroxy)|2098|2098|86|4.0%|0.2%|
[stopforumspam_1d](#stopforumspam_1d)|6954|6954|59|0.8%|0.1%|
[blocklist_de_bots](#blocklist_de_bots)|3081|3081|45|1.4%|0.1%|
[proxz](#proxz)|874|874|40|4.5%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|33|0.0%|0.1%|
[sorbs_socks](#sorbs_socks)|19|19|19|100.0%|0.0%|
[sorbs_misc](#sorbs_misc)|19|19|19|100.0%|0.0%|
[sorbs_http](#sorbs_http)|19|19|19|100.0%|0.0%|
[php_commenters](#php_commenters)|326|326|15|4.6%|0.0%|
[openbl_60d](#openbl_60d)|7651|7651|15|0.1%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|15|0.0%|0.0%|
[sorbs_smtp](#sorbs_smtp)|13|13|13|100.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|1804|1804|12|0.6%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2447|2447|11|0.4%|0.0%|
[et_block](#et_block)|1023|18338662|10|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|8|0.0%|0.0%|
[proxyrss](#proxyrss)|1599|1599|8|0.5%|0.0%|
[php_harvesters](#php_harvesters)|311|311|7|2.2%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|4|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|888|888|4|0.4%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|3|0.0%|0.0%|
[openbl_30d](#openbl_30d)|3251|3251|3|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|2|0.2%|0.0%|
[et_tor](#et_tor)|6470|6470|2|0.0%|0.0%|
[dshield](#dshield)|20|5120|2|0.0%|0.0%|
[dm_tor](#dm_tor)|6485|6485|2|0.0%|0.0%|
[bm_tor](#bm_tor)|6490|6490|2|0.0%|0.0%|
[shunlist](#shunlist)|1259|1259|1|0.0%|0.0%|
[openbl_7d](#openbl_7d)|861|861|1|0.1%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|1|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|182|182|1|0.5%|0.0%|

## sorbs_smtp

[Sorbs.net](https://www.sorbs.net/) SMTP Open Relays, extracted from deltas.

Source is downloaded from [this link]().

The last time downloaded was found to be dated: Fri Jun  5 12:04:15 UTC 2015.

The ipset `sorbs_smtp` has **13** entries, **13** unique IPs.

The following table shows the overlaps of `sorbs_smtp` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `sorbs_smtp`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `sorbs_smtp`.
- ` this % ` is the percentage **of this ipset (`sorbs_smtp`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[sorbs_spam](#sorbs_spam)|29892|30945|13|0.0%|100.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|29892|30945|13|0.0%|100.0%|
[sorbs_new_spam](#sorbs_new_spam)|29892|30945|13|0.0%|100.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|1|0.0%|7.6%|

## sorbs_socks

[Sorbs.net](https://www.sorbs.net/) SOCKS proxies, extracted from deltas.

Source is downloaded from [this link]().

The last time downloaded was found to be dated: Fri Jun  5 17:04:14 UTC 2015.

The ipset `sorbs_socks` has **19** entries, **19** unique IPs.

The following table shows the overlaps of `sorbs_socks` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `sorbs_socks`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `sorbs_socks`.
- ` this % ` is the percentage **of this ipset (`sorbs_socks`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[sorbs_spam](#sorbs_spam)|29892|30945|19|0.0%|100.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|29892|30945|19|0.0%|100.0%|
[sorbs_new_spam](#sorbs_new_spam)|29892|30945|19|0.0%|100.0%|
[sorbs_misc](#sorbs_misc)|19|19|19|100.0%|100.0%|
[sorbs_http](#sorbs_http)|19|19|19|100.0%|100.0%|
[snort_ipfilter](#snort_ipfilter)|8977|8977|6|0.0%|31.5%|
[blocklist_de_mail](#blocklist_de_mail)|15605|15605|5|0.0%|26.3%|
[blocklist_de](#blocklist_de)|25421|25421|5|0.0%|26.3%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|3|0.0%|15.7%|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|3|0.0%|15.7%|
[sorbs_web](#sorbs_web)|654|655|3|0.4%|15.7%|
[php_dictionary](#php_dictionary)|545|545|2|0.3%|10.5%|
[xroxy](#xroxy)|2098|2098|1|0.0%|5.2%|
[php_spammers](#php_spammers)|536|536|1|0.1%|5.2%|
[nixspam](#nixspam)|15861|15861|1|0.0%|5.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|1|0.0%|5.2%|

## sorbs_spam

[Sorbs.net](https://www.sorbs.net/) Spam senders, extracted from deltas.

Source is downloaded from [this link]().

The last time downloaded was found to be dated: Sat Jun  6 11:04:10 UTC 2015.

The ipset `sorbs_spam` has **29892** entries, **30945** unique IPs.

The following table shows the overlaps of `sorbs_spam` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `sorbs_spam`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `sorbs_spam`.
- ` this % ` is the percentage **of this ipset (`sorbs_spam`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[sorbs_recent_spam](#sorbs_recent_spam)|29892|30945|30945|100.0%|100.0%|
[sorbs_new_spam](#sorbs_new_spam)|29892|30945|30945|100.0%|100.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|2243|0.0%|7.2%|
[nixspam](#nixspam)|15861|15861|2210|13.9%|7.1%|
[blocklist_de](#blocklist_de)|25421|25421|1066|4.1%|3.4%|
[blocklist_de_mail](#blocklist_de_mail)|15605|15605|907|5.8%|2.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|783|0.0%|2.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|487|0.0%|1.5%|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|341|0.3%|1.1%|
[sorbs_web](#sorbs_web)|654|655|318|48.5%|1.0%|
[snort_ipfilter](#snort_ipfilter)|8977|8977|309|3.4%|0.9%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|181|0.6%|0.5%|
[php_dictionary](#php_dictionary)|545|545|150|27.5%|0.4%|
[ri_web_proxies](#ri_web_proxies)|6565|6565|138|2.1%|0.4%|
[php_spammers](#php_spammers)|536|536|133|24.8%|0.4%|
[alienvault_reputation](#alienvault_reputation)|180710|180710|105|0.0%|0.3%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|3708|3708|104|2.8%|0.3%|
[blocklist_de_apache](#blocklist_de_apache)|15060|15060|104|0.6%|0.3%|
[xroxy](#xroxy)|2098|2098|86|4.0%|0.2%|
[stopforumspam_1d](#stopforumspam_1d)|6954|6954|59|0.8%|0.1%|
[blocklist_de_bots](#blocklist_de_bots)|3081|3081|45|1.4%|0.1%|
[proxz](#proxz)|874|874|40|4.5%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|33|0.0%|0.1%|
[sorbs_socks](#sorbs_socks)|19|19|19|100.0%|0.0%|
[sorbs_misc](#sorbs_misc)|19|19|19|100.0%|0.0%|
[sorbs_http](#sorbs_http)|19|19|19|100.0%|0.0%|
[php_commenters](#php_commenters)|326|326|15|4.6%|0.0%|
[openbl_60d](#openbl_60d)|7651|7651|15|0.1%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|15|0.0%|0.0%|
[sorbs_smtp](#sorbs_smtp)|13|13|13|100.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|1804|1804|12|0.6%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2447|2447|11|0.4%|0.0%|
[et_block](#et_block)|1023|18338662|10|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|8|0.0%|0.0%|
[proxyrss](#proxyrss)|1599|1599|8|0.5%|0.0%|
[php_harvesters](#php_harvesters)|311|311|7|2.2%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|4|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|888|888|4|0.4%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|3|0.0%|0.0%|
[openbl_30d](#openbl_30d)|3251|3251|3|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|2|0.2%|0.0%|
[et_tor](#et_tor)|6470|6470|2|0.0%|0.0%|
[dshield](#dshield)|20|5120|2|0.0%|0.0%|
[dm_tor](#dm_tor)|6485|6485|2|0.0%|0.0%|
[bm_tor](#bm_tor)|6490|6490|2|0.0%|0.0%|
[shunlist](#shunlist)|1259|1259|1|0.0%|0.0%|
[openbl_7d](#openbl_7d)|861|861|1|0.1%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|1|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|182|182|1|0.5%|0.0%|

## sorbs_web

[Sorbs.net](https://www.sorbs.net/) WEB exploits, extracted from deltas.

Source is downloaded from [this link]().

The last time downloaded was found to be dated: Sat Jun  6 11:04:11 UTC 2015.

The ipset `sorbs_web` has **654** entries, **655** unique IPs.

The following table shows the overlaps of `sorbs_web` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `sorbs_web`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `sorbs_web`.
- ` this % ` is the percentage **of this ipset (`sorbs_web`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[sorbs_spam](#sorbs_spam)|29892|30945|318|1.0%|48.5%|
[sorbs_recent_spam](#sorbs_recent_spam)|29892|30945|318|1.0%|48.5%|
[sorbs_new_spam](#sorbs_new_spam)|29892|30945|318|1.0%|48.5%|
[nixspam](#nixspam)|15861|15861|95|0.5%|14.5%|
[blocklist_de](#blocklist_de)|25421|25421|75|0.2%|11.4%|
[blocklist_de_mail](#blocklist_de_mail)|15605|15605|59|0.3%|9.0%|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|52|0.0%|7.9%|
[snort_ipfilter](#snort_ipfilter)|8977|8977|48|0.5%|7.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|45|0.0%|6.8%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|37|0.1%|5.6%|
[php_dictionary](#php_dictionary)|545|545|29|5.3%|4.4%|
[php_spammers](#php_spammers)|536|536|27|5.0%|4.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|25|0.0%|3.8%|
[ri_web_proxies](#ri_web_proxies)|6565|6565|24|0.3%|3.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|22|0.0%|3.3%|
[xroxy](#xroxy)|2098|2098|16|0.7%|2.4%|
[stopforumspam_1d](#stopforumspam_1d)|6954|6954|15|0.2%|2.2%|
[blocklist_de_bots](#blocklist_de_bots)|3081|3081|13|0.4%|1.9%|
[proxz](#proxz)|874|874|10|1.1%|1.5%|
[sorbs_socks](#sorbs_socks)|19|19|3|15.7%|0.4%|
[sorbs_misc](#sorbs_misc)|19|19|3|15.7%|0.4%|
[sorbs_http](#sorbs_http)|19|19|3|15.7%|0.4%|
[php_commenters](#php_commenters)|326|326|3|0.9%|0.4%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|3708|3708|2|0.0%|0.3%|
[blocklist_de_apache](#blocklist_de_apache)|15060|15060|2|0.0%|0.3%|
[ri_connect_proxies](#ri_connect_proxies)|2447|2447|1|0.0%|0.1%|
[proxyrss](#proxyrss)|1599|1599|1|0.0%|0.1%|
[openbl_60d](#openbl_60d)|7651|7651|1|0.0%|0.1%|
[openbl_30d](#openbl_30d)|3251|3251|1|0.0%|0.1%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1|0.0%|0.1%|
[blocklist_de_strongips](#blocklist_de_strongips)|182|182|1|0.5%|0.1%|
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
[openbl_60d](#openbl_60d)|7651|7651|239|3.1%|0.0%|
[blocklist_de](#blocklist_de)|25421|25421|182|0.7%|0.0%|
[openbl_30d](#openbl_30d)|3251|3251|160|4.9%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1764|1764|107|6.0%|0.0%|
[nixspam](#nixspam)|15861|15861|102|0.6%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1892|1892|101|5.3%|0.0%|
[et_compromised](#et_compromised)|2016|2016|100|4.9%|0.0%|
[shunlist](#shunlist)|1259|1259|97|7.7%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6954|6954|82|1.1%|0.0%|
[openbl_7d](#openbl_7d)|861|861|48|5.5%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3081|3081|42|1.3%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|29|2.2%|0.0%|
[php_commenters](#php_commenters)|326|326|28|8.5%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|15605|15605|28|0.1%|0.0%|
[snort_ipfilter](#snort_ipfilter)|8977|8977|20|0.2%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|1804|1804|18|0.9%|0.0%|
[zeus_badips](#zeus_badips)|202|202|16|7.9%|0.0%|
[zeus](#zeus)|230|230|16|6.9%|0.0%|
[voipbl](#voipbl)|10452|10864|14|0.1%|0.0%|
[openbl_1d](#openbl_1d)|143|143|11|7.6%|0.0%|
[sorbs_spam](#sorbs_spam)|29892|30945|8|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|29892|30945|8|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|29892|30945|8|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|182|182|7|3.8%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|6|0.4%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|6|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|3708|3708|5|0.1%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|15060|15060|5|0.0%|0.0%|
[php_dictionary](#php_dictionary)|545|545|4|0.7%|0.0%|
[malc0de](#malc0de)|371|371|4|1.0%|0.0%|
[php_spammers](#php_spammers)|536|536|3|0.5%|0.0%|
[dm_tor](#dm_tor)|6485|6485|3|0.0%|0.0%|
[bm_tor](#bm_tor)|6490|6490|3|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|2|0.2%|0.0%|
[et_tor](#et_tor)|6470|6470|2|0.0%|0.0%|
[sslbl](#sslbl)|370|370|1|0.2%|0.0%|
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
[snort_ipfilter](#snort_ipfilter)|8977|8977|6|0.0%|0.0%|
[zeus_badips](#zeus_badips)|202|202|5|2.4%|0.0%|
[zeus](#zeus)|230|230|5|2.1%|0.0%|
[blocklist_de](#blocklist_de)|25421|25421|5|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6954|6954|3|0.0%|0.0%|
[sorbs_spam](#sorbs_spam)|29892|30945|3|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|29892|30945|3|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|29892|30945|3|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|182|182|3|1.6%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3081|3081|3|0.0%|0.0%|
[dm_tor](#dm_tor)|6485|6485|2|0.0%|0.0%|
[bm_tor](#bm_tor)|6490|6490|2|0.0%|0.0%|
[php_harvesters](#php_harvesters)|311|311|1|0.3%|0.0%|
[openbl_60d](#openbl_60d)|7651|7651|1|0.0%|0.0%|
[openbl_30d](#openbl_30d)|3251|3251|1|0.0%|0.0%|
[malc0de](#malc0de)|371|371|1|0.2%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|15605|15605|1|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|15060|15060|1|0.0%|0.0%|

## sslbl

[Abuse.ch SSL Blacklist](https://sslbl.abuse.ch/) bad SSL traffic related to malware or botnet activities - **excellent list**

Source is downloaded from [this link](https://sslbl.abuse.ch/blacklist/sslipblacklist.csv).

The last time downloaded was found to be dated: Sat Jun  6 11:15:06 UTC 2015.

The ipset `sslbl` has **370** entries, **370** unique IPs.

The following table shows the overlaps of `sslbl` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `sslbl`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `sslbl`.
- ` this % ` is the percentage **of this ipset (`sslbl`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[alienvault_reputation](#alienvault_reputation)|180710|180710|65|0.0%|17.5%|
[shunlist](#shunlist)|1259|1259|57|4.5%|15.4%|
[feodo](#feodo)|99|99|36|36.3%|9.7%|
[et_block](#et_block)|1023|18338662|35|0.0%|9.4%|
[snort_ipfilter](#snort_ipfilter)|8977|8977|31|0.3%|8.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|26|0.0%|7.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|5|0.0%|1.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|3|0.0%|0.8%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|1|0.0%|0.2%|
[ri_web_proxies](#ri_web_proxies)|6565|6565|1|0.0%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.2%|
[blocklist_de_ssh](#blocklist_de_ssh)|1764|1764|1|0.0%|0.2%|
[blocklist_de](#blocklist_de)|25421|25421|1|0.0%|0.2%|

## stopforumspam_1d

[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers in the last 24 hours - **excellent list**

Source is downloaded from [this link](http://www.stopforumspam.com/downloads/listed_ip_1.zip).

The last time downloaded was found to be dated: Sat Jun  6 11:00:02 UTC 2015.

The ipset `stopforumspam_1d` has **6954** entries, **6954** unique IPs.

The following table shows the overlaps of `stopforumspam_1d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `stopforumspam_1d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `stopforumspam_1d`.
- ` this % ` is the percentage **of this ipset (`stopforumspam_1d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|5860|6.2%|84.2%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|5728|19.0%|82.3%|
[blocklist_de](#blocklist_de)|25421|25421|1299|5.1%|18.6%|
[blocklist_de_bots](#blocklist_de_bots)|3081|3081|1234|40.0%|17.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|510|0.0%|7.3%|
[ri_web_proxies](#ri_web_proxies)|6565|6565|473|7.2%|6.8%|
[snort_ipfilter](#snort_ipfilter)|8977|8977|381|4.2%|5.4%|
[proxyrss](#proxyrss)|1599|1599|375|23.4%|5.3%|
[et_tor](#et_tor)|6470|6470|337|5.2%|4.8%|
[dm_tor](#dm_tor)|6485|6485|337|5.1%|4.8%|
[bm_tor](#bm_tor)|6490|6490|337|5.1%|4.8%|
[xroxy](#xroxy)|2098|2098|273|13.0%|3.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|195|0.0%|2.8%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|163|43.8%|2.3%|
[proxz](#proxz)|874|874|156|17.8%|2.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|138|0.0%|1.9%|
[ri_connect_proxies](#ri_connect_proxies)|2447|2447|135|5.5%|1.9%|
[php_commenters](#php_commenters)|326|326|125|38.3%|1.7%|
[blocklist_de_strongips](#blocklist_de_strongips)|182|182|109|59.8%|1.5%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|82|0.0%|1.1%|
[et_block](#et_block)|1023|18338662|77|0.0%|1.1%|
[blocklist_de_apache](#blocklist_de_apache)|15060|15060|70|0.4%|1.0%|
[sorbs_spam](#sorbs_spam)|29892|30945|59|0.1%|0.8%|
[sorbs_recent_spam](#sorbs_recent_spam)|29892|30945|59|0.1%|0.8%|
[sorbs_new_spam](#sorbs_new_spam)|29892|30945|59|0.1%|0.8%|
[alienvault_reputation](#alienvault_reputation)|180710|180710|54|0.0%|0.7%|
[blocklist_de_mail](#blocklist_de_mail)|15605|15605|52|0.3%|0.7%|
[nixspam](#nixspam)|15861|15861|43|0.2%|0.6%|
[php_harvesters](#php_harvesters)|311|311|38|12.2%|0.5%|
[php_spammers](#php_spammers)|536|536|36|6.7%|0.5%|
[php_dictionary](#php_dictionary)|545|545|33|6.0%|0.4%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|25|0.0%|0.3%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|3708|3708|22|0.5%|0.3%|
[openbl_60d](#openbl_60d)|7651|7651|21|0.2%|0.3%|
[sorbs_web](#sorbs_web)|654|655|15|2.2%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|8|0.0%|0.1%|
[voipbl](#voipbl)|10452|10864|6|0.0%|0.0%|
[dshield](#dshield)|20|5120|4|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|3|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|3|0.0%|0.0%|
[openbl_30d](#openbl_30d)|3251|3251|2|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.0%|
[zeus_badips](#zeus_badips)|202|202|1|0.4%|0.0%|
[zeus](#zeus)|230|230|1|0.4%|0.0%|
[shunlist](#shunlist)|1259|1259|1|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|1|0.1%|0.0%|
[ciarmy](#ciarmy)|402|402|1|0.2%|0.0%|

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
[stopforumspam_1d](#stopforumspam_1d)|6954|6954|5860|84.2%|6.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|5841|0.0%|6.2%|
[ri_web_proxies](#ri_web_proxies)|6565|6565|3182|48.4%|3.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|2524|0.0%|2.7%|
[blocklist_de](#blocklist_de)|25421|25421|2403|9.4%|2.5%|
[blocklist_de_bots](#blocklist_de_bots)|3081|3081|2064|66.9%|2.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|1543|0.0%|1.6%|
[ri_connect_proxies](#ri_connect_proxies)|2447|2447|1412|57.7%|1.5%|
[xroxy](#xroxy)|2098|2098|1237|58.9%|1.3%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|1021|0.0%|1.0%|
[et_block](#et_block)|1023|18338662|1013|0.0%|1.0%|
[snort_ipfilter](#snort_ipfilter)|8977|8977|804|8.9%|0.8%|
[proxyrss](#proxyrss)|1599|1599|790|49.4%|0.8%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|744|0.0%|0.7%|
[et_tor](#et_tor)|6470|6470|647|10.0%|0.6%|
[dm_tor](#dm_tor)|6485|6485|640|9.8%|0.6%|
[bm_tor](#bm_tor)|6490|6490|640|9.8%|0.6%|
[proxz](#proxz)|874|874|526|60.1%|0.5%|
[sorbs_spam](#sorbs_spam)|29892|30945|341|1.1%|0.3%|
[sorbs_recent_spam](#sorbs_recent_spam)|29892|30945|341|1.1%|0.3%|
[sorbs_new_spam](#sorbs_new_spam)|29892|30945|341|1.1%|0.3%|
[blocklist_de_mail](#blocklist_de_mail)|15605|15605|258|1.6%|0.2%|
[php_commenters](#php_commenters)|326|326|238|73.0%|0.2%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|231|62.0%|0.2%|
[blocklist_de_apache](#blocklist_de_apache)|15060|15060|225|1.4%|0.2%|
[alienvault_reputation](#alienvault_reputation)|180710|180710|205|0.1%|0.2%|
[nixspam](#nixspam)|15861|15861|164|1.0%|0.1%|
[blocklist_de_strongips](#blocklist_de_strongips)|182|182|134|73.6%|0.1%|
[php_spammers](#php_spammers)|536|536|117|21.8%|0.1%|
[php_dictionary](#php_dictionary)|545|545|103|18.8%|0.1%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|88|0.0%|0.0%|
[php_harvesters](#php_harvesters)|311|311|68|21.8%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|3708|3708|59|1.5%|0.0%|
[openbl_60d](#openbl_60d)|7651|7651|57|0.7%|0.0%|
[sorbs_web](#sorbs_web)|654|655|52|7.9%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|46|0.0%|0.0%|
[voipbl](#voipbl)|10452|10864|35|0.3%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|22|3.2%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|14|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|888|888|12|1.3%|0.0%|
[et_compromised](#et_compromised)|2016|2016|11|0.5%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1892|1892|11|0.5%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1764|1764|8|0.4%|0.0%|
[dshield](#dshield)|20|5120|7|0.1%|0.0%|
[openbl_30d](#openbl_30d)|3251|3251|5|0.1%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|1804|1804|5|0.2%|0.0%|
[shunlist](#shunlist)|1259|1259|4|0.3%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|4|0.3%|0.0%|
[sorbs_socks](#sorbs_socks)|19|19|3|15.7%|0.0%|
[sorbs_misc](#sorbs_misc)|19|19|3|15.7%|0.0%|
[sorbs_http](#sorbs_http)|19|19|3|15.7%|0.0%|
[openbl_7d](#openbl_7d)|861|861|3|0.3%|0.0%|
[zeus_badips](#zeus_badips)|202|202|2|0.9%|0.0%|
[zeus](#zeus)|230|230|2|0.8%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.0%|
[fullbogons](#fullbogons)|3721|670267288|2|0.0%|0.0%|
[ciarmy](#ciarmy)|402|402|1|0.2%|0.0%|
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
[stopforumspam_1d](#stopforumspam_1d)|6954|6954|5728|82.3%|19.0%|
[blocklist_de](#blocklist_de)|25421|25421|2077|8.1%|6.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|1912|0.0%|6.3%|
[blocklist_de_bots](#blocklist_de_bots)|3081|3081|1892|61.4%|6.2%|
[ri_web_proxies](#ri_web_proxies)|6565|6565|1613|24.5%|5.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|909|0.0%|3.0%|
[xroxy](#xroxy)|2098|2098|723|34.4%|2.4%|
[ri_connect_proxies](#ri_connect_proxies)|2447|2447|646|26.3%|2.1%|
[snort_ipfilter](#snort_ipfilter)|8977|8977|632|7.0%|2.0%|
[proxyrss](#proxyrss)|1599|1599|626|39.1%|2.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|568|0.0%|1.8%|
[et_tor](#et_tor)|6470|6470|516|7.9%|1.7%|
[dm_tor](#dm_tor)|6485|6485|506|7.8%|1.6%|
[bm_tor](#bm_tor)|6490|6490|506|7.7%|1.6%|
[proxz](#proxz)|874|874|414|47.3%|1.3%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|322|0.0%|1.0%|
[et_block](#et_block)|1023|18338662|314|0.0%|1.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|191|51.3%|0.6%|
[sorbs_spam](#sorbs_spam)|29892|30945|181|0.5%|0.6%|
[sorbs_recent_spam](#sorbs_recent_spam)|29892|30945|181|0.5%|0.6%|
[sorbs_new_spam](#sorbs_new_spam)|29892|30945|181|0.5%|0.6%|
[php_commenters](#php_commenters)|326|326|171|52.4%|0.5%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|153|0.0%|0.5%|
[blocklist_de_mail](#blocklist_de_mail)|15605|15605|143|0.9%|0.4%|
[blocklist_de_apache](#blocklist_de_apache)|15060|15060|138|0.9%|0.4%|
[blocklist_de_strongips](#blocklist_de_strongips)|182|182|123|67.5%|0.4%|
[alienvault_reputation](#alienvault_reputation)|180710|180710|94|0.0%|0.3%|
[nixspam](#nixspam)|15861|15861|86|0.5%|0.2%|
[php_spammers](#php_spammers)|536|536|66|12.3%|0.2%|
[php_dictionary](#php_dictionary)|545|545|66|12.1%|0.2%|
[php_harvesters](#php_harvesters)|311|311|51|16.3%|0.1%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|3708|3708|38|1.0%|0.1%|
[sorbs_web](#sorbs_web)|654|655|37|5.6%|0.1%|
[openbl_60d](#openbl_60d)|7651|7651|26|0.3%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|25|0.0%|0.0%|
[voipbl](#voipbl)|10452|10864|12|0.1%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|12|1.7%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|11|0.0%|0.0%|
[et_compromised](#et_compromised)|2016|2016|7|0.3%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1892|1892|7|0.3%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|6|0.0%|0.0%|
[dshield](#dshield)|20|5120|5|0.0%|0.0%|
[sorbs_socks](#sorbs_socks)|19|19|3|15.7%|0.0%|
[sorbs_misc](#sorbs_misc)|19|19|3|15.7%|0.0%|
[sorbs_http](#sorbs_http)|19|19|3|15.7%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1764|1764|3|0.1%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|888|888|3|0.3%|0.0%|
[shunlist](#shunlist)|1259|1259|2|0.1%|0.0%|
[openbl_30d](#openbl_30d)|3251|3251|2|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.0%|
[zeus_badips](#zeus_badips)|202|202|1|0.4%|0.0%|
[zeus](#zeus)|230|230|1|0.4%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|1|0.0%|0.0%|
[ciarmy](#ciarmy)|402|402|1|0.2%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|1804|1804|1|0.0%|0.0%|

## virbl

[VirBL](http://virbl.bit.nl/) is a project of which the idea was born during the RIPE-48 meeting. The plan was to get reports of virusscanning mailservers, and put the IP-addresses that were reported to send viruses on a blacklist.

Source is downloaded from [this link](http://virbl.bit.nl/download/virbl.dnsbl.bit.nl.txt).

The last time downloaded was found to be dated: Sat Jun  6 10:52:04 UTC 2015.

The ipset `virbl` has **8** entries, **8** unique IPs.

The following table shows the overlaps of `virbl` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `virbl`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `virbl`.
- ` this % ` is the percentage **of this ipset (`virbl`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|2|0.0%|25.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|1|0.0%|12.5%|

## voipbl

[VoIPBL.org](http://www.voipbl.org/) a distributed VoIP blacklist that is aimed to protects against VoIP Fraud and minimizing abuse for network that have publicly accessible PBX's. Several algorithms, external sources and manual confirmation are used before they categorize something as an attack and determine the threat level.

Source is downloaded from [this link](http://www.voipbl.org/update/).

The last time downloaded was found to be dated: Sat Jun  6 09:00:06 UTC 2015.

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
[blocklist_de](#blocklist_de)|25421|25421|33|0.1%|0.3%|
[blocklist_de_sip](#blocklist_de_sip)|87|87|23|26.4%|0.2%|
[et_block](#et_block)|1023|18338662|16|0.0%|0.1%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|14|0.0%|0.1%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|12|0.0%|0.1%|
[shunlist](#shunlist)|1259|1259|12|0.9%|0.1%|
[openbl_60d](#openbl_60d)|7651|7651|8|0.1%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6954|6954|6|0.0%|0.0%|
[dshield](#dshield)|20|5120|6|0.1%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3081|3081|5|0.1%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|4|0.0%|0.0%|
[ciarmy](#ciarmy)|402|402|4|0.9%|0.0%|
[openbl_30d](#openbl_30d)|3251|3251|3|0.0%|0.0%|
[et_tor](#et_tor)|6470|6470|3|0.0%|0.0%|
[dm_tor](#dm_tor)|6485|6485|3|0.0%|0.0%|
[bm_tor](#bm_tor)|6490|6490|3|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|15060|15060|3|0.0%|0.0%|
[nixspam](#nixspam)|15861|15861|2|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|2|0.0%|0.0%|
[et_compromised](#et_compromised)|2016|2016|2|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1892|1892|2|0.1%|0.0%|
[openbl_7d](#openbl_7d)|861|861|1|0.1%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|15605|15605|1|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|3708|3708|1|0.0%|0.0%|

## xroxy

[xroxy.com](http://www.xroxy.com) open proxies (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.xroxy.com/proxyrss.xml).

The last time downloaded was found to be dated: Sat Jun  6 10:33:02 UTC 2015.

The ipset `xroxy` has **2098** entries, **2098** unique IPs.

The following table shows the overlaps of `xroxy` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `xroxy`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `xroxy`.
- ` this % ` is the percentage **of this ipset (`xroxy`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|1237|1.3%|58.9%|
[ri_web_proxies](#ri_web_proxies)|6565|6565|898|13.6%|42.8%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|723|2.4%|34.4%|
[proxyrss](#proxyrss)|1599|1599|427|26.7%|20.3%|
[ri_connect_proxies](#ri_connect_proxies)|2447|2447|365|14.9%|17.3%|
[proxz](#proxz)|874|874|343|39.2%|16.3%|
[stopforumspam_1d](#stopforumspam_1d)|6954|6954|273|3.9%|13.0%|
[blocklist_de](#blocklist_de)|25421|25421|238|0.9%|11.3%|
[blocklist_de_bots](#blocklist_de_bots)|3081|3081|193|6.2%|9.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|101|0.0%|4.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|94|0.0%|4.4%|
[sorbs_spam](#sorbs_spam)|29892|30945|86|0.2%|4.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|29892|30945|86|0.2%|4.0%|
[sorbs_new_spam](#sorbs_new_spam)|29892|30945|86|0.2%|4.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|58|0.0%|2.7%|
[snort_ipfilter](#snort_ipfilter)|8977|8977|46|0.5%|2.1%|
[blocklist_de_mail](#blocklist_de_mail)|15605|15605|45|0.2%|2.1%|
[nixspam](#nixspam)|15861|15861|38|0.2%|1.8%|
[php_dictionary](#php_dictionary)|545|545|32|5.8%|1.5%|
[php_spammers](#php_spammers)|536|536|26|4.8%|1.2%|
[sorbs_web](#sorbs_web)|654|655|16|2.4%|0.7%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|13|1.9%|0.6%|
[php_commenters](#php_commenters)|326|326|7|2.1%|0.3%|
[blocklist_de_strongips](#blocklist_de_strongips)|182|182|7|3.8%|0.3%|
[alienvault_reputation](#alienvault_reputation)|180710|180710|4|0.0%|0.1%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|3|0.0%|0.1%|
[php_harvesters](#php_harvesters)|311|311|2|0.6%|0.0%|
[et_tor](#et_tor)|6470|6470|2|0.0%|0.0%|
[dm_tor](#dm_tor)|6485|6485|2|0.0%|0.0%|
[bm_tor](#bm_tor)|6490|6490|2|0.0%|0.0%|
[sorbs_socks](#sorbs_socks)|19|19|1|5.2%|0.0%|
[sorbs_misc](#sorbs_misc)|19|19|1|5.2%|0.0%|
[sorbs_http](#sorbs_http)|19|19|1|5.2%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.0%|
[et_compromised](#et_compromised)|2016|2016|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1892|1892|1|0.0%|0.0%|

## zeus

[Abuse.ch Zeus tracker](https://zeustracker.abuse.ch) standard, contains the same data as the ZeuS IP blocklist (zeus_badips) but with the slight difference that it doesn't exclude hijacked websites (level 2) and free web hosting providers (level 3). This means that this blocklist contains all IPv4 addresses associated with ZeuS C&Cs which are currently being tracked by ZeuS Tracker. Hence this blocklist will likely cause some false positives. - **excellent list**

Source is downloaded from [this link](https://zeustracker.abuse.ch/blocklist.php?download=ipblocklist).

The last time downloaded was found to be dated: Sat Jun  6 08:01:15 UTC 2015.

The ipset `zeus` has **230** entries, **230** unique IPs.

The following table shows the overlaps of `zeus` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `zeus`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `zeus`.
- ` this % ` is the percentage **of this ipset (`zeus`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[et_block](#et_block)|1023|18338662|223|0.0%|96.9%|
[zeus_badips](#zeus_badips)|202|202|202|100.0%|87.8%|
[snort_ipfilter](#snort_ipfilter)|8977|8977|201|2.2%|87.3%|
[alienvault_reputation](#alienvault_reputation)|180710|180710|62|0.0%|26.9%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|16|0.0%|6.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|14|0.0%|6.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|10|0.0%|4.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|9|0.0%|3.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|6|0.0%|2.6%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|5|0.0%|2.1%|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|2|0.0%|0.8%|
[openbl_60d](#openbl_60d)|7651|7651|2|0.0%|0.8%|
[openbl_30d](#openbl_30d)|3251|3251|2|0.0%|0.8%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|1|0.0%|0.4%|
[stopforumspam_1d](#stopforumspam_1d)|6954|6954|1|0.0%|0.4%|
[php_commenters](#php_commenters)|326|326|1|0.3%|0.4%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.4%|

## zeus_badips

[Abuse.ch Zeus tracker](https://zeustracker.abuse.ch) badips includes IPv4 addresses that are used by the ZeuS trojan. It is the recommened blocklist if you want to block only ZeuS IPs. It excludes IP addresses that ZeuS Tracker believes to be hijacked (level 2) or belong to a free web hosting provider (level 3). Hence the false postive rate should be much lower compared to the standard ZeuS IP blocklist. **excellent list**

Source is downloaded from [this link](https://zeustracker.abuse.ch/blocklist.php?download=badips).

The last time downloaded was found to be dated: Sat Jun  6 11:00:12 UTC 2015.

The ipset `zeus_badips` has **202** entries, **202** unique IPs.

The following table shows the overlaps of `zeus_badips` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `zeus_badips`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `zeus_badips`.
- ` this % ` is the percentage **of this ipset (`zeus_badips`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[zeus](#zeus)|230|230|202|87.8%|100.0%|
[et_block](#et_block)|1023|18338662|200|0.0%|99.0%|
[snort_ipfilter](#snort_ipfilter)|8977|8977|179|1.9%|88.6%|
[alienvault_reputation](#alienvault_reputation)|180710|180710|38|0.0%|18.8%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|16|0.0%|7.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|10|0.0%|4.9%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|10|0.0%|4.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|8|0.0%|3.9%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|5|0.0%|2.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|4|0.0%|1.9%|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|2|0.0%|0.9%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|1|0.0%|0.4%|
[stopforumspam_1d](#stopforumspam_1d)|6954|6954|1|0.0%|0.4%|
[php_commenters](#php_commenters)|326|326|1|0.3%|0.4%|
[openbl_60d](#openbl_60d)|7651|7651|1|0.0%|0.4%|
[openbl_30d](#openbl_30d)|3251|3251|1|0.0%|0.4%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.4%|
