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

The following list was automatically generated on Thu Jun  4 15:45:57 UTC 2015.

The update frequency is the maximum allowed by internal configuration. A list will never be downloaded sooner than the update frequency stated. A list may also not be downloaded, after this frequency expired, if it has not been modified on the server (as reported by HTTP `IF_MODIFIED_SINCE` method).

name|info|type|entries|update|
:--:|:--:|:--:|:-----:|:----:|
[alienvault_reputation](#alienvault_reputation)|[AlienVault.com](https://www.alienvault.com/) IP reputation database (this list seems to include port scanning hosts and to be updated regularly, but we found no information about its retention policy)|ipv4 hash:ip|178477 unique IPs|updated every 6 hours  from [this link](https://reputation.alienvault.com/reputation.generic)
[blocklist_de](#blocklist_de)|[Blocklist.de](https://www.blocklist.de/) IPs that have been detected by fail2ban in the last 48 hours - **excellent list**|ipv4 hash:ip|37184 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/all.txt)
[blocklist_de_apache](#blocklist_de_apache)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service Apache, Apache-DDOS, RFI-Attacks.|ipv4 hash:ip|13430 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/apache.txt)
[blocklist_de_bots](#blocklist_de_bots)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the RFI-Attacks, REG-Bots, IRC-Bots or BadBots (BadBots = he has posted a Spam-Comment on a open Forum or Wiki).|ipv4 hash:ip|3094 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/bots.txt)
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|[Blocklist.de](https://www.blocklist.de/) All IPs which attacks Joomlas, Wordpress and other Web-Logins with Brute-Force Logins.|ipv4 hash:ip|2089 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/bruteforcelogin.txt)
[blocklist_de_ftp](#blocklist_de_ftp)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours for attacks on the Service FTP.|ipv4 hash:ip|872 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/ftp.txt)
[blocklist_de_imap](#blocklist_de_imap)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours for attacks on the Service imap, sasl, pop3, etc.|ipv4 hash:ip|2830 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/imap.txt)
[blocklist_de_mail](#blocklist_de_mail)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service Mail, Postfix.|ipv4 hash:ip|17091 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/mail.txt)
[blocklist_de_sip](#blocklist_de_sip)|[Blocklist.de](https://www.blocklist.de/) All IP addresses that tried to login in a SIP, VOIP or Asterisk Server and are included in the IPs list from [infiltrated.net](www.infiltrated.net)|ipv4 hash:ip|103 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/sip.txt)
[blocklist_de_ssh](#blocklist_de_ssh)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service SSH.|ipv4 hash:ip|13692 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/ssh.txt)
[blocklist_de_strongips](#blocklist_de_strongips)|[Blocklist.de](https://www.blocklist.de/) All IPs which are older then 2 month and have more then 5.000 attacks.|ipv4 hash:ip|179 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/strongips.txt)
[bm_tor](#bm_tor)|[torstatus.blutmagie.de](https://torstatus.blutmagie.de) list of all TOR network servers|ipv4 hash:ip|6616 unique IPs|updated every 30 mins  from [this link](https://torstatus.blutmagie.de/ip_list_all.php/Tor_ip_list_ALL.csv)
[bogons](#bogons)|[Team-Cymru.org](http://www.team-cymru.org) private and reserved addresses defined by RFC 1918, RFC 5735, and RFC 6598 and netblocks that have not been allocated to a regional internet registry - **excellent list - use it only your internet interface**|ipv4 hash:net|13 subnets, 592708608 unique IPs|updated every 1 day  from [this link](http://www.team-cymru.org/Services/Bogons/bogon-bn-agg.txt)
[bruteforceblocker](#bruteforceblocker)|[danger.rulez.sk](http://danger.rulez.sk/) IPs detected by [bruteforceblocker](http://danger.rulez.sk/index.php/bruteforceblocker/) (fail2ban alternative for SSH on OpenBSD). This is an automatically generated list from users reporting failed authentication attempts. An IP seems to be included if 3 or more users report it. Its retention pocily seems 30 days.|ipv4 hash:ip|2051 unique IPs|updated every 3 hours  from [this link](http://danger.rulez.sk/projects/bruteforceblocker/blist.php)
[ciarmy](#ciarmy)|[CIArmy.com](http://ciarmy.com/) IPs with poor Rogue Packet score that have not yet been identified as malicious by the community|ipv4 hash:ip|343 unique IPs|updated every 3 hours  from [this link](http://cinsscore.com/list/ci-badguys.txt)
[cleanmx_viruses](#cleanmx_viruses)|[Clean-MX.de](http://support.clean-mx.de/clean-mx/viruses.php) IPs with viruses|ipv4 hash:ip|206 unique IPs|updated every 12 hours  from [this link](http://support.clean-mx.de/clean-mx/xmlviruses.php?sort=id%20desc&response=alive)
[dm_tor](#dm_tor)|[dan.me.uk](https://www.dan.me.uk) dynamic list of TOR exit points|ipv4 hash:ip|6611 unique IPs|updated every 30 mins  from [this link](https://www.dan.me.uk/torlist/)
[dshield](#dshield)|[DShield.org](https://dshield.org/) top 20 attacking class C (/24) subnets over the last three days - **excellent list**|ipv4 hash:net|20 subnets, 5120 unique IPs|updated every 4 hours  from [this link](http://feeds.dshield.org/block.txt)
[et_block](#et_block)|[EmergingThreats.net](http://www.emergingthreats.net/) default blacklist (at the time of writing includes spamhaus DROP, dshield and abuse.ch trackers, which are available separately too - prefer to use the direct ipsets instead of this, they seem to lag a bit in updates)|ipv4 hash:net|1007 subnets, 18338646 unique IPs|updated every 12 hours  from [this link](http://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt)
[et_botcc](#et_botcc)|[EmergingThreats.net Command and Control IPs](http://doc.emergingthreats.net/bin/view/Main/BotCC) These IPs are updates every 24 hours and should be considered VERY highly reliable indications that a host is communicating with a known and active Bot or Malware command and control server - (although they say this includes abuse.ch trackers, it does not - most probably it is the shadowserver.org C&C list)|ipv4 hash:ip|508 unique IPs|updated every 12 hours  from [this link](http://rules.emergingthreats.net/fwrules/emerging-PIX-CC.rules)
[et_compromised](#et_compromised)|[EmergingThreats.net compromised hosts](http://doc.emergingthreats.net/bin/view/Main/CompromisedHost) - (this seems to be based on bruteforceblocker)|ipv4 hash:ip|2171 unique IPs|updated every 12 hours  from [this link](http://rules.emergingthreats.net/blockrules/compromised-ips.txt)
et_dshield|[EmergingThreats.net](http://www.emergingthreats.net/) dshield blocklist|ipv4 hash:net|disabled|updated every 12 hours  from [this link](http://rules.emergingthreats.net/fwrules/emerging-PIX-DSHIELD.rules)
et_spamhaus|[EmergingThreats.net](http://www.emergingthreats.net/) spamhaus blocklist|ipv4 hash:net|disabled|updated every 12 hours  from [this link](http://rules.emergingthreats.net/fwrules/emerging-PIX-DROP.rules)
[et_tor](#et_tor)|[EmergingThreats.net](http://www.emergingthreats.net/) [list](http://doc.emergingthreats.net/bin/view/Main/TorRules) of TOR network IPs|ipv4 hash:ip|6380 unique IPs|updated every 12 hours  from [this link](http://rules.emergingthreats.net/blockrules/emerging-tor.rules)
[feodo](#feodo)|[Abuse.ch Feodo tracker](https://feodotracker.abuse.ch) trojan includes IPs which are being used by Feodo (also known as Cridex or Bugat) which commits ebanking fraud - **excellent list**|ipv4 hash:ip|93 unique IPs|updated every 30 mins  from [this link](https://feodotracker.abuse.ch/blocklist/?download=ipblocklist)
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
[nixspam](#nixspam)|[NiX Spam](http://www.heise.de/ix/NiX-Spam-DNSBL-and-blacklist-for-download-499637.html) IP addresses that sent spam in the last hour - automatically generated entries without distinguishing open proxies from relays, dialup gateways, and so on. All IPs are removed after 12 hours if there is no spam from there.|ipv4 hash:ip|21627 unique IPs|updated every 15 mins  from [this link](http://www.dnsbl.manitu.net/download/nixspam-ip.dump.gz)
openbl|[OpenBL.org](http://www.openbl.org/) default blacklist (currently it is the same with 90 days). OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications - **excellent list**|ipv4 hash:ip|disabled|updated every 4 hours  from [this link](http://www.openbl.org/lists/base.txt)
openbl_180d|[OpenBL.org](http://www.openbl.org/) last 180 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|disabled|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_180days.txt)
[openbl_1d](#openbl_1d)|[OpenBL.org](http://www.openbl.org/) last 24 hours IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|192 unique IPs|updated every 1 hour  from [this link](http://www.openbl.org/lists/base_1days.txt)
[openbl_30d](#openbl_30d)|[OpenBL.org](http://www.openbl.org/) last 30 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|3260 unique IPs|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_30days.txt)
openbl_360d|[OpenBL.org](http://www.openbl.org/) last 360 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|disabled|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_360days.txt)
[openbl_60d](#openbl_60d)|[OpenBL.org](http://www.openbl.org/) last 60 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|7702 unique IPs|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_60days.txt)
[openbl_7d](#openbl_7d)|[OpenBL.org](http://www.openbl.org/) last 7 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|943 unique IPs|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_7days.txt)
openbl_90d|[OpenBL.org](http://www.openbl.org/) last 90 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|disabled|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_90days.txt)
openbl_all|[OpenBL.org](http://www.openbl.org/) last all IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|disabled|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_all.txt)
[palevo](#palevo)|[Abuse.ch Palevo tracker](https://palevotracker.abuse.ch) worm includes IPs which are being used as botnet C&C for the Palevo crimeware - **excellent list**|ipv4 hash:ip|13 unique IPs|updated every 30 mins  from [this link](https://palevotracker.abuse.ch/blocklists.php?download=ipblocklist)
php_bad|[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) bad web hosts (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|disabled|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=b&rss=1)
[php_commenters](#php_commenters)|[projecthoneypot.org](http://www.projecthoneypot.org/) comment spammers (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|281 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=c&rss=1)
[php_dictionary](#php_dictionary)|[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) directory attackers (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|433 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=d&rss=1)
[php_harvesters](#php_harvesters)|[projecthoneypot.org](http://www.projecthoneypot.org/) harvesters (IPs that surf the internet looking for email addresses) (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|257 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=h&rss=1)
[php_spammers](#php_spammers)|[projecthoneypot.org](http://www.projecthoneypot.org/) spam servers (IPs used by spammers to send messages) (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|417 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=s&rss=1)
[proxyrss](#proxyrss)|[proxyrss.com](http://www.proxyrss.com) open proxies syndicated from multiple sources.|ipv4 hash:ip|1606 unique IPs|updated every 4 hours  from [this link](http://www.proxyrss.com/proxylists/all.gz)
[proxz](#proxz)|[proxz.com](http://www.proxz.com) open proxies (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|712 unique IPs|updated every 1 hour  from [this link](http://www.proxz.com/proxylists.xml)
[ri_connect_proxies](#ri_connect_proxies)|[rosinstrument.com](http://www.rosinstrument.com) open CONNECT proxies (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|2327 unique IPs|updated every 1 hour  from [this link](http://tools.rosinstrument.com/proxy/plab100.xml)
[ri_web_proxies](#ri_web_proxies)|[rosinstrument.com](http://www.rosinstrument.com) open HTTP proxies (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|6189 unique IPs|updated every 1 hour  from [this link](http://tools.rosinstrument.com/proxy/l100.xml)
[shunlist](#shunlist)|[AutoShun.org](http://autoshun.org/) IPs identified as hostile by correlating logs from distributed snort installations running the autoshun plugin|ipv4 hash:ip|1273 unique IPs|updated every 4 hours  from [this link](http://www.autoshun.org/files/shunlist.csv)
[snort_ipfilter](#snort_ipfilter)|[labs.snort.org](https://labs.snort.org/) supplied IP blacklist (this list seems to be updated frequently, but we found no information about it)|ipv4 hash:ip|9591 unique IPs|updated every 12 hours  from [this link](http://labs.snort.org/feeds/ip-filter.blf)
[sorbs_dul](#sorbs_dul)|[Sorbs.net](https://www.sorbs.net/) DUL, Dynamic User IPs extracted from deltas.|ipv4 hash:net|8 subnets, 3584 unique IPs|updated every 1 min  from [this link]()
[sorbs_http](#sorbs_http)|[Sorbs.net](https://www.sorbs.net/) HTTP proxies, extracted from deltas.|ipv4 hash:net|23 subnets, 23 unique IPs|updated every 1 min  from [this link]()
[sorbs_misc](#sorbs_misc)|[Sorbs.net](https://www.sorbs.net/) MISC proxies, extracted from deltas.|ipv4 hash:net|23 subnets, 23 unique IPs|updated every 1 min  from [this link]()
[sorbs_new_spam](#sorbs_new_spam)|[Sorbs.net](https://www.sorbs.net/) NEW Spam senders, extracted from deltas.|ipv4 hash:net|18771 subnets, 19329 unique IPs|updated every 1 min  from [this link]()
[sorbs_recent_spam](#sorbs_recent_spam)|[Sorbs.net](https://www.sorbs.net/) RECENT Spam senders, extracted from deltas.|ipv4 hash:net|18771 subnets, 19329 unique IPs|updated every 1 min  from [this link]()
[sorbs_smtp](#sorbs_smtp)|[Sorbs.net](https://www.sorbs.net/) SMTP Open Relays, extracted from deltas.|ipv4 hash:net|9 subnets, 9 unique IPs|updated every 1 min  from [this link]()
[sorbs_socks](#sorbs_socks)|[Sorbs.net](https://www.sorbs.net/) SOCKS proxies, extracted from deltas.|ipv4 hash:net|23 subnets, 23 unique IPs|updated every 1 min  from [this link]()
[sorbs_spam](#sorbs_spam)|[Sorbs.net](https://www.sorbs.net/) Spam senders, extracted from deltas.|ipv4 hash:net|23635 subnets, 24447 unique IPs|updated every 1 min  from [this link]()
[sorbs_web](#sorbs_web)|[Sorbs.net](https://www.sorbs.net/) WEB exploits, extracted from deltas.|ipv4 hash:net|680 subnets, 682 unique IPs|updated every 1 min  from [this link]()
[spamhaus_drop](#spamhaus_drop)|[Spamhaus.org](http://www.spamhaus.org) DROP list (according to their site this list should be dropped at tier-1 ISPs globaly) - **excellent list**|ipv4 hash:net|654 subnets, 18469632 unique IPs|updated every 12 hours  from [this link](http://www.spamhaus.org/drop/drop.txt)
[spamhaus_edrop](#spamhaus_edrop)|[Spamhaus.org](http://www.spamhaus.org) EDROP (extended matches that should be used with DROP) - **excellent list**|ipv4 hash:net|55 subnets, 486400 unique IPs|updated every 12 hours  from [this link](http://www.spamhaus.org/drop/edrop.txt)
[sslbl](#sslbl)|[Abuse.ch SSL Blacklist](https://sslbl.abuse.ch/) bad SSL traffic related to malware or botnet activities - **excellent list**|ipv4 hash:ip|366 unique IPs|updated every 30 mins  from [this link](https://sslbl.abuse.ch/blacklist/sslipblacklist.csv)
stopforumspam_180d|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 180 days)|ipv4 hash:ip|disabled|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/listed_ip_180.zip)
[stopforumspam_1d](#stopforumspam_1d)|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers in the last 24 hours - **excellent list**|ipv4 hash:ip|7131 unique IPs|updated every 1 hour  from [this link](http://www.stopforumspam.com/downloads/listed_ip_1.zip)
[stopforumspam_30d](#stopforumspam_30d)|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 30 days)|ipv4 hash:ip|92996 unique IPs|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/listed_ip_30.zip)
stopforumspam_365d|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 365 days)|ipv4 hash:ip|disabled|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/listed_ip_365.zip)
[stopforumspam_7d](#stopforumspam_7d)|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 7 days)|ipv4 hash:ip|30334 unique IPs|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/listed_ip_7.zip)
stopforumspam_90d|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 90 days)|ipv4 hash:ip|disabled|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/listed_ip_90.zip)
stopforumspam_ever|[StopForumSpam.com](http://www.stopforumspam.com) all IPs used by forum spammers, **ever** (normally you don't want to use this ipset, use the hourly one which includes last 24 hours IPs or the 7 days one)|ipv4 hash:ip|disabled|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/bannedips.zip)
[virbl](#virbl)|[VirBL](http://virbl.bit.nl/) is a project of which the idea was born during the RIPE-48 meeting. The plan was to get reports of virusscanning mailservers, and put the IP-addresses that were reported to send viruses on a blacklist.|ipv4 hash:ip|11 unique IPs|updated every 1 hour  from [this link](http://virbl.bit.nl/download/virbl.dnsbl.bit.nl.txt)
[voipbl](#voipbl)|[VoIPBL.org](http://www.voipbl.org/) a distributed VoIP blacklist that is aimed to protects against VoIP Fraud and minimizing abuse for network that have publicly accessible PBX's. Several algorithms, external sources and manual confirmation are used before they categorize something as an attack and determine the threat level.|ipv4 hash:net|10426 subnets, 10837 unique IPs|updated every 4 hours  from [this link](http://www.voipbl.org/update/)
[xroxy](#xroxy)|[xroxy.com](http://www.xroxy.com) open proxies (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|2060 unique IPs|updated every 1 hour  from [this link](http://www.xroxy.com/proxyrss.xml)
[zeus](#zeus)|[Abuse.ch Zeus tracker](https://zeustracker.abuse.ch) standard, contains the same data as the ZeuS IP blocklist (zeus_badips) but with the slight difference that it doesn't exclude hijacked websites (level 2) and free web hosting providers (level 3). This means that this blocklist contains all IPv4 addresses associated with ZeuS C&Cs which are currently being tracked by ZeuS Tracker. Hence this blocklist will likely cause some false positives. - **excellent list**|ipv4 hash:ip|269 unique IPs|updated every 30 mins  from [this link](https://zeustracker.abuse.ch/blocklist.php?download=ipblocklist)
[zeus_badips](#zeus_badips)|[Abuse.ch Zeus tracker](https://zeustracker.abuse.ch) badips includes IPv4 addresses that are used by the ZeuS trojan. It is the recommened blocklist if you want to block only ZeuS IPs. It excludes IP addresses that ZeuS Tracker believes to be hijacked (level 2) or belong to a free web hosting provider (level 3). Hence the false postive rate should be much lower compared to the standard ZeuS IP blocklist. **excellent list**|ipv4 hash:ip|234 unique IPs|updated every 30 mins  from [this link](https://zeustracker.abuse.ch/blocklist.php?download=badips)

# Comparison of ipsets

Below we compare each ipset against all other.


## alienvault_reputation

[AlienVault.com](https://www.alienvault.com/) IP reputation database (this list seems to include port scanning hosts and to be updated regularly, but we found no information about its retention policy)

Source is downloaded from [this link](https://reputation.alienvault.com/reputation.generic).

The last time downloaded was found to be dated: Thu Jun  4 10:00:33 UTC 2015.

The ipset `alienvault_reputation` has **178477** entries, **178477** unique IPs.

The following table shows the overlaps of `alienvault_reputation` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `alienvault_reputation`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `alienvault_reputation`.
- ` this % ` is the percentage **of this ipset (`alienvault_reputation`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|14125|0.0%|7.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|7803|0.0%|4.3%|
[openbl_60d](#openbl_60d)|7702|7702|7670|99.5%|4.2%|
[et_block](#et_block)|1007|18338646|5793|0.0%|3.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|4471|0.0%|2.5%|
[openbl_30d](#openbl_30d)|3260|3260|3234|99.2%|1.8%|
[dshield](#dshield)|20|5120|3091|60.3%|1.7%|
[blocklist_de](#blocklist_de)|37184|37184|2220|5.9%|1.2%|
[blocklist_de_ssh](#blocklist_de_ssh)|13692|13692|1973|14.4%|1.1%|
[spamhaus_drop](#spamhaus_drop)|654|18469632|1885|0.0%|1.0%|
[et_compromised](#et_compromised)|2171|2171|1406|64.7%|0.7%|
[bruteforceblocker](#bruteforceblocker)|2051|2051|1332|64.9%|0.7%|
[shunlist](#shunlist)|1273|1273|1265|99.3%|0.7%|
[openbl_7d](#openbl_7d)|943|943|926|98.1%|0.5%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|518|0.0%|0.2%|
[ciarmy](#ciarmy)|343|343|330|96.2%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|287|0.0%|0.1%|
[stopforumspam_30d](#stopforumspam_30d)|92996|92996|218|0.2%|0.1%|
[voipbl](#voipbl)|10426|10837|200|1.8%|0.1%|
[openbl_1d](#openbl_1d)|192|192|180|93.7%|0.1%|
[blocklist_de_apache](#blocklist_de_apache)|13430|13430|132|0.9%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9591|9591|124|1.2%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|30334|30334|106|0.3%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|17091|17091|76|0.4%|0.0%|
[zeus](#zeus)|269|269|66|24.5%|0.0%|
[sslbl](#sslbl)|366|366|64|17.4%|0.0%|
[sorbs_spam](#sorbs_spam)|23635|24447|63|0.2%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7131|7131|62|0.8%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|18771|19329|53|0.2%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|18771|19329|53|0.2%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2830|2830|51|1.8%|0.0%|
[dm_tor](#dm_tor)|6611|6611|43|0.6%|0.0%|
[bm_tor](#bm_tor)|6616|6616|43|0.6%|0.0%|
[et_tor](#et_tor)|6380|6380|42|0.6%|0.0%|
[zeus_badips](#zeus_badips)|234|234|38|16.2%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|179|179|34|18.9%|0.0%|
[nixspam](#nixspam)|21627|21627|30|0.1%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3094|3094|26|0.8%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|25|6.7%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|103|103|18|17.4%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2089|2089|16|0.7%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|486400|15|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|15|0.0%|0.0%|
[php_commenters](#php_commenters)|281|281|14|4.9%|0.0%|
[malc0de](#malc0de)|379|379|11|2.9%|0.0%|
[php_harvesters](#php_harvesters)|257|257|8|3.1%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|8|0.5%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|206|206|7|3.3%|0.0%|
[php_dictionary](#php_dictionary)|433|433|6|1.3%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|6|0.4%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|872|872|6|0.6%|0.0%|
[xroxy](#xroxy)|2060|2060|5|0.2%|0.0%|
[et_botcc](#et_botcc)|508|508|4|0.7%|0.0%|
[ri_web_proxies](#ri_web_proxies)|6189|6189|3|0.0%|0.0%|
[proxz](#proxz)|712|712|3|0.4%|0.0%|
[php_spammers](#php_spammers)|417|417|3|0.7%|0.0%|
[virbl](#virbl)|11|11|2|18.1%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2327|2327|2|0.0%|0.0%|
[proxyrss](#proxyrss)|1606|1606|2|0.1%|0.0%|
[feodo](#feodo)|93|93|2|2.1%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|1|0.1%|0.0%|

## blocklist_de

[Blocklist.de](https://www.blocklist.de/) IPs that have been detected by fail2ban in the last 48 hours - **excellent list**

Source is downloaded from [this link](http://lists.blocklist.de/lists/all.txt).

The last time downloaded was found to be dated: Thu Jun  4 15:28:03 UTC 2015.

The ipset `blocklist_de` has **37184** entries, **37184** unique IPs.

The following table shows the overlaps of `blocklist_de` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de`.
- ` this % ` is the percentage **of this ipset (`blocklist_de`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de_mail](#blocklist_de_mail)|17091|17091|17091|100.0%|45.9%|
[blocklist_de_ssh](#blocklist_de_ssh)|13692|13692|13692|100.0%|36.8%|
[blocklist_de_apache](#blocklist_de_apache)|13430|13430|13430|100.0%|36.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|6691|0.0%|17.9%|
[blocklist_de_bots](#blocklist_de_bots)|3094|3094|3093|99.9%|8.3%|
[blocklist_de_imap](#blocklist_de_imap)|2830|2830|2830|100.0%|7.6%|
[stopforumspam_30d](#stopforumspam_30d)|92996|92996|2532|2.7%|6.8%|
[alienvault_reputation](#alienvault_reputation)|178477|178477|2220|1.2%|5.9%|
[stopforumspam_7d](#stopforumspam_7d)|30334|30334|2146|7.0%|5.7%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2089|2089|2089|100.0%|5.6%|
[openbl_60d](#openbl_60d)|7702|7702|1865|24.2%|5.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|1592|0.0%|4.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|1561|0.0%|4.1%|
[stopforumspam_1d](#stopforumspam_1d)|7131|7131|1482|20.7%|3.9%|
[sorbs_spam](#sorbs_spam)|23635|24447|1021|4.1%|2.7%|
[sorbs_recent_spam](#sorbs_recent_spam)|18771|19329|976|5.0%|2.6%|
[sorbs_new_spam](#sorbs_new_spam)|18771|19329|976|5.0%|2.6%|
[openbl_30d](#openbl_30d)|3260|3260|891|27.3%|2.3%|
[blocklist_de_ftp](#blocklist_de_ftp)|872|872|872|100.0%|2.3%|
[nixspam](#nixspam)|21627|21627|744|3.4%|2.0%|
[bruteforceblocker](#bruteforceblocker)|2051|2051|680|33.1%|1.8%|
[et_compromised](#et_compromised)|2171|2171|657|30.2%|1.7%|
[openbl_7d](#openbl_7d)|943|943|599|63.5%|1.6%|
[ri_web_proxies](#ri_web_proxies)|6189|6189|402|6.4%|1.0%|
[shunlist](#shunlist)|1273|1273|396|31.1%|1.0%|
[xroxy](#xroxy)|2060|2060|261|12.6%|0.7%|
[proxyrss](#proxyrss)|1606|1606|258|16.0%|0.6%|
[snort_ipfilter](#snort_ipfilter)|9591|9591|197|2.0%|0.5%|
[blocklist_de_strongips](#blocklist_de_strongips)|179|179|179|100.0%|0.4%|
[openbl_1d](#openbl_1d)|192|192|157|81.7%|0.4%|
[et_block](#et_block)|1007|18338646|157|0.0%|0.4%|
[spamhaus_drop](#spamhaus_drop)|654|18469632|153|0.0%|0.4%|
[proxz](#proxz)|712|712|133|18.6%|0.3%|
[dshield](#dshield)|20|5120|122|2.3%|0.3%|
[sorbs_web](#sorbs_web)|680|682|86|12.6%|0.2%|
[blocklist_de_sip](#blocklist_de_sip)|103|103|84|81.5%|0.2%|
[ri_connect_proxies](#ri_connect_proxies)|2327|2327|71|3.0%|0.1%|
[php_commenters](#php_commenters)|281|281|67|23.8%|0.1%|
[php_dictionary](#php_dictionary)|433|433|56|12.9%|0.1%|
[php_spammers](#php_spammers)|417|417|54|12.9%|0.1%|
[voipbl](#voipbl)|10426|10837|47|0.4%|0.1%|
[ciarmy](#ciarmy)|343|343|41|11.9%|0.1%|
[php_harvesters](#php_harvesters)|257|257|27|10.5%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|25|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|486400|12|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|11|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|8|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|6|0.8%|0.0%|
[sorbs_socks](#sorbs_socks)|23|23|5|21.7%|0.0%|
[sorbs_misc](#sorbs_misc)|23|23|5|21.7%|0.0%|
[sorbs_http](#sorbs_http)|23|23|5|21.7%|0.0%|
[dm_tor](#dm_tor)|6611|6611|4|0.0%|0.0%|
[bm_tor](#bm_tor)|6616|6616|4|0.0%|0.0%|
[et_tor](#et_tor)|6380|6380|3|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|2|0.5%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.0%|

## blocklist_de_apache

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service Apache, Apache-DDOS, RFI-Attacks.

Source is downloaded from [this link](http://lists.blocklist.de/lists/apache.txt).

The last time downloaded was found to be dated: Thu Jun  4 15:28:07 UTC 2015.

The ipset `blocklist_de_apache` has **13430** entries, **13430** unique IPs.

The following table shows the overlaps of `blocklist_de_apache` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_apache`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_apache`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_apache`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|37184|37184|13430|36.1%|100.0%|
[blocklist_de_mail](#blocklist_de_mail)|17091|17091|11059|64.7%|82.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|2272|0.0%|16.9%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2089|2089|2089|100.0%|15.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|1326|0.0%|9.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|1070|0.0%|7.9%|
[stopforumspam_30d](#stopforumspam_30d)|92996|92996|205|0.2%|1.5%|
[alienvault_reputation](#alienvault_reputation)|178477|178477|132|0.0%|0.9%|
[stopforumspam_7d](#stopforumspam_7d)|30334|30334|126|0.4%|0.9%|
[stopforumspam_1d](#stopforumspam_1d)|7131|7131|76|1.0%|0.5%|
[sorbs_spam](#sorbs_spam)|23635|24447|52|0.2%|0.3%|
[sorbs_recent_spam](#sorbs_recent_spam)|18771|19329|49|0.2%|0.3%|
[sorbs_new_spam](#sorbs_new_spam)|18771|19329|49|0.2%|0.3%|
[shunlist](#shunlist)|1273|1273|36|2.8%|0.2%|
[ciarmy](#ciarmy)|343|343|36|10.4%|0.2%|
[blocklist_de_strongips](#blocklist_de_strongips)|179|179|36|20.1%|0.2%|
[nixspam](#nixspam)|21627|21627|26|0.1%|0.1%|
[php_commenters](#php_commenters)|281|281|24|8.5%|0.1%|
[blocklist_de_bots](#blocklist_de_bots)|3094|3094|23|0.7%|0.1%|
[snort_ipfilter](#snort_ipfilter)|9591|9591|8|0.0%|0.0%|
[dshield](#dshield)|20|5120|8|0.1%|0.0%|
[php_spammers](#php_spammers)|417|417|6|1.4%|0.0%|
[openbl_60d](#openbl_60d)|7702|7702|5|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|4|1.5%|0.0%|
[et_block](#et_block)|1007|18338646|4|0.0%|0.0%|
[dm_tor](#dm_tor)|6611|6611|4|0.0%|0.0%|
[bm_tor](#bm_tor)|6616|6616|4|0.0%|0.0%|
[voipbl](#voipbl)|10426|10837|3|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|654|18469632|3|0.0%|0.0%|
[sorbs_web](#sorbs_web)|680|682|3|0.4%|0.0%|
[php_dictionary](#php_dictionary)|433|433|3|0.6%|0.0%|
[openbl_30d](#openbl_30d)|3260|3260|3|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|3|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|3|0.0%|0.0%|
[et_tor](#et_tor)|6380|6380|3|0.0%|0.0%|
[et_compromised](#et_compromised)|2171|2171|3|0.1%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|486400|2|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|2|0.5%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2051|2051|2|0.0%|0.0%|
[openbl_7d](#openbl_7d)|943|943|1|0.1%|0.0%|

## blocklist_de_bots

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the RFI-Attacks, REG-Bots, IRC-Bots or BadBots (BadBots = he has posted a Spam-Comment on a open Forum or Wiki).

Source is downloaded from [this link](http://lists.blocklist.de/lists/bots.txt).

The last time downloaded was found to be dated: Thu Jun  4 15:28:09 UTC 2015.

The ipset `blocklist_de_bots` has **3094** entries, **3094** unique IPs.

The following table shows the overlaps of `blocklist_de_bots` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_bots`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_bots`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_bots`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|37184|37184|3093|8.3%|99.9%|
[stopforumspam_30d](#stopforumspam_30d)|92996|92996|2121|2.2%|68.5%|
[stopforumspam_7d](#stopforumspam_7d)|30334|30334|1948|6.4%|62.9%|
[stopforumspam_1d](#stopforumspam_1d)|7131|7131|1396|19.5%|45.1%|
[ri_web_proxies](#ri_web_proxies)|6189|6189|351|5.6%|11.3%|
[proxyrss](#proxyrss)|1606|1606|258|16.0%|8.3%|
[xroxy](#xroxy)|2060|2060|209|10.1%|6.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|156|0.0%|5.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|179|179|136|75.9%|4.3%|
[proxz](#proxz)|712|712|111|15.5%|3.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|84|0.0%|2.7%|
[ri_connect_proxies](#ri_connect_proxies)|2327|2327|68|2.9%|2.1%|
[php_commenters](#php_commenters)|281|281|52|18.5%|1.6%|
[nixspam](#nixspam)|21627|21627|47|0.2%|1.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|39|0.0%|1.2%|
[sorbs_spam](#sorbs_spam)|23635|24447|34|0.1%|1.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|18771|19329|32|0.1%|1.0%|
[sorbs_new_spam](#sorbs_new_spam)|18771|19329|32|0.1%|1.0%|
[alienvault_reputation](#alienvault_reputation)|178477|178477|26|0.0%|0.8%|
[snort_ipfilter](#snort_ipfilter)|9591|9591|23|0.2%|0.7%|
[blocklist_de_mail](#blocklist_de_mail)|17091|17091|23|0.1%|0.7%|
[blocklist_de_apache](#blocklist_de_apache)|13430|13430|23|0.1%|0.7%|
[spamhaus_drop](#spamhaus_drop)|654|18469632|20|0.0%|0.6%|
[et_block](#et_block)|1007|18338646|20|0.0%|0.6%|
[php_harvesters](#php_harvesters)|257|257|18|7.0%|0.5%|
[sorbs_web](#sorbs_web)|680|682|11|1.6%|0.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|11|0.0%|0.3%|
[php_spammers](#php_spammers)|417|417|8|1.9%|0.2%|
[php_dictionary](#php_dictionary)|433|433|8|1.8%|0.2%|
[spamhaus_edrop](#spamhaus_edrop)|55|486400|4|0.0%|0.1%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|4|0.5%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|3|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2051|2051|3|0.1%|0.0%|
[sorbs_socks](#sorbs_socks)|23|23|2|8.6%|0.0%|
[sorbs_misc](#sorbs_misc)|23|23|2|8.6%|0.0%|
[sorbs_http](#sorbs_http)|23|23|2|8.6%|0.0%|
[et_compromised](#et_compromised)|2171|2171|2|0.0%|0.0%|
[voipbl](#voipbl)|10426|10837|1|0.0%|0.0%|
[openbl_60d](#openbl_60d)|7702|7702|1|0.0%|0.0%|
[openbl_30d](#openbl_30d)|3260|3260|1|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|

## blocklist_de_bruteforce

[Blocklist.de](https://www.blocklist.de/) All IPs which attacks Joomlas, Wordpress and other Web-Logins with Brute-Force Logins.

Source is downloaded from [this link](http://lists.blocklist.de/lists/bruteforcelogin.txt).

The last time downloaded was found to be dated: Thu Jun  4 15:28:11 UTC 2015.

The ipset `blocklist_de_bruteforce` has **2089** entries, **2089** unique IPs.

The following table shows the overlaps of `blocklist_de_bruteforce` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_bruteforce`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_bruteforce`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_bruteforce`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de_apache](#blocklist_de_apache)|13430|13430|2089|15.5%|100.0%|
[blocklist_de](#blocklist_de)|37184|37184|2089|5.6%|100.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|173|0.0%|8.2%|
[sorbs_spam](#sorbs_spam)|23635|24447|52|0.2%|2.4%|
[sorbs_recent_spam](#sorbs_recent_spam)|18771|19329|49|0.2%|2.3%|
[sorbs_new_spam](#sorbs_new_spam)|18771|19329|49|0.2%|2.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|38|0.0%|1.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|35|0.0%|1.6%|
[stopforumspam_30d](#stopforumspam_30d)|92996|92996|34|0.0%|1.6%|
[stopforumspam_7d](#stopforumspam_7d)|30334|30334|24|0.0%|1.1%|
[nixspam](#nixspam)|21627|21627|24|0.1%|1.1%|
[stopforumspam_1d](#stopforumspam_1d)|7131|7131|20|0.2%|0.9%|
[alienvault_reputation](#alienvault_reputation)|178477|178477|16|0.0%|0.7%|
[blocklist_de_strongips](#blocklist_de_strongips)|179|179|8|4.4%|0.3%|
[php_spammers](#php_spammers)|417|417|6|1.4%|0.2%|
[php_commenters](#php_commenters)|281|281|5|1.7%|0.2%|
[snort_ipfilter](#snort_ipfilter)|9591|9591|4|0.0%|0.1%|
[spamhaus_drop](#spamhaus_drop)|654|18469632|3|0.0%|0.1%|
[sorbs_web](#sorbs_web)|680|682|3|0.4%|0.1%|
[shunlist](#shunlist)|1273|1273|3|0.2%|0.1%|
[php_harvesters](#php_harvesters)|257|257|3|1.1%|0.1%|
[php_dictionary](#php_dictionary)|433|433|3|0.6%|0.1%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|3|0.0%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|2|0.0%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2|0.0%|0.0%|
[et_block](#et_block)|1007|18338646|2|0.0%|0.0%|
[voipbl](#voipbl)|10426|10837|1|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|

## blocklist_de_ftp

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours for attacks on the Service FTP.

Source is downloaded from [this link](http://lists.blocklist.de/lists/ftp.txt).

The last time downloaded was found to be dated: Thu Jun  4 15:28:08 UTC 2015.

The ipset `blocklist_de_ftp` has **872** entries, **872** unique IPs.

The following table shows the overlaps of `blocklist_de_ftp` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_ftp`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_ftp`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_ftp`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|37184|37184|872|2.3%|100.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|68|0.0%|7.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|17|0.0%|1.9%|
[stopforumspam_30d](#stopforumspam_30d)|92996|92996|11|0.0%|1.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|11|0.0%|1.2%|
[stopforumspam_7d](#stopforumspam_7d)|30334|30334|6|0.0%|0.6%|
[alienvault_reputation](#alienvault_reputation)|178477|178477|6|0.0%|0.6%|
[nixspam](#nixspam)|21627|21627|5|0.0%|0.5%|
[stopforumspam_1d](#stopforumspam_1d)|7131|7131|4|0.0%|0.4%|
[sorbs_spam](#sorbs_spam)|23635|24447|4|0.0%|0.4%|
[sorbs_recent_spam](#sorbs_recent_spam)|18771|19329|3|0.0%|0.3%|
[sorbs_new_spam](#sorbs_new_spam)|18771|19329|3|0.0%|0.3%|
[php_harvesters](#php_harvesters)|257|257|2|0.7%|0.2%|
[spamhaus_edrop](#spamhaus_edrop)|55|486400|1|0.0%|0.1%|
[php_spammers](#php_spammers)|417|417|1|0.2%|0.1%|
[ciarmy](#ciarmy)|343|343|1|0.2%|0.1%|

## blocklist_de_imap

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours for attacks on the Service imap, sasl, pop3, etc.

Source is downloaded from [this link](http://lists.blocklist.de/lists/imap.txt).

The last time downloaded was found to be dated: Thu Jun  4 15:28:07 UTC 2015.

The ipset `blocklist_de_imap` has **2830** entries, **2830** unique IPs.

The following table shows the overlaps of `blocklist_de_imap` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_imap`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_imap`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_imap`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de_mail](#blocklist_de_mail)|17091|17091|2830|16.5%|100.0%|
[blocklist_de](#blocklist_de)|37184|37184|2830|7.6%|100.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|360|0.0%|12.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|64|0.0%|2.2%|
[alienvault_reputation](#alienvault_reputation)|178477|178477|51|0.0%|1.8%|
[openbl_60d](#openbl_60d)|7702|7702|40|0.5%|1.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|38|0.0%|1.3%|
[openbl_30d](#openbl_30d)|3260|3260|36|1.1%|1.2%|
[sorbs_spam](#sorbs_spam)|23635|24447|25|0.1%|0.8%|
[nixspam](#nixspam)|21627|21627|21|0.0%|0.7%|
[sorbs_recent_spam](#sorbs_recent_spam)|18771|19329|20|0.1%|0.7%|
[sorbs_new_spam](#sorbs_new_spam)|18771|19329|20|0.1%|0.7%|
[openbl_7d](#openbl_7d)|943|943|13|1.3%|0.4%|
[stopforumspam_30d](#stopforumspam_30d)|92996|92996|11|0.0%|0.3%|
[spamhaus_drop](#spamhaus_drop)|654|18469632|10|0.0%|0.3%|
[et_block](#et_block)|1007|18338646|10|0.0%|0.3%|
[et_compromised](#et_compromised)|2171|2171|8|0.3%|0.2%|
[snort_ipfilter](#snort_ipfilter)|9591|9591|7|0.0%|0.2%|
[bruteforceblocker](#bruteforceblocker)|2051|2051|7|0.3%|0.2%|
[shunlist](#shunlist)|1273|1273|4|0.3%|0.1%|
[openbl_1d](#openbl_1d)|192|192|3|1.5%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|0.1%|
[stopforumspam_7d](#stopforumspam_7d)|30334|30334|2|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|2|0.0%|0.0%|
[voipbl](#voipbl)|10426|10837|1|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7131|7131|1|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|486400|1|0.0%|0.0%|
[sorbs_web](#sorbs_web)|680|682|1|0.1%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1|0.0%|0.0%|
[ciarmy](#ciarmy)|343|343|1|0.2%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|179|179|1|0.5%|0.0%|

## blocklist_de_mail

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service Mail, Postfix.

Source is downloaded from [this link](http://lists.blocklist.de/lists/mail.txt).

The last time downloaded was found to be dated: Thu Jun  4 15:28:06 UTC 2015.

The ipset `blocklist_de_mail` has **17091** entries, **17091** unique IPs.

The following table shows the overlaps of `blocklist_de_mail` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_mail`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_mail`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_mail`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|37184|37184|17091|45.9%|100.0%|
[blocklist_de_apache](#blocklist_de_apache)|13430|13430|11059|82.3%|64.7%|
[blocklist_de_imap](#blocklist_de_imap)|2830|2830|2830|100.0%|16.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|2562|0.0%|14.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|1366|0.0%|7.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|1176|0.0%|6.8%|
[sorbs_spam](#sorbs_spam)|23635|24447|856|3.5%|5.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|18771|19329|819|4.2%|4.7%|
[sorbs_new_spam](#sorbs_new_spam)|18771|19329|819|4.2%|4.7%|
[nixspam](#nixspam)|21627|21627|660|3.0%|3.8%|
[stopforumspam_30d](#stopforumspam_30d)|92996|92996|256|0.2%|1.4%|
[snort_ipfilter](#snort_ipfilter)|9591|9591|169|1.7%|0.9%|
[stopforumspam_7d](#stopforumspam_7d)|30334|30334|149|0.4%|0.8%|
[alienvault_reputation](#alienvault_reputation)|178477|178477|76|0.0%|0.4%|
[sorbs_web](#sorbs_web)|680|682|71|10.4%|0.4%|
[stopforumspam_1d](#stopforumspam_1d)|7131|7131|60|0.8%|0.3%|
[xroxy](#xroxy)|2060|2060|51|2.4%|0.2%|
[ri_web_proxies](#ri_web_proxies)|6189|6189|51|0.8%|0.2%|
[php_dictionary](#php_dictionary)|433|433|45|10.3%|0.2%|
[openbl_60d](#openbl_60d)|7702|7702|45|0.5%|0.2%|
[openbl_30d](#openbl_30d)|3260|3260|41|1.2%|0.2%|
[php_spammers](#php_spammers)|417|417|39|9.3%|0.2%|
[blocklist_de_strongips](#blocklist_de_strongips)|179|179|23|12.8%|0.1%|
[blocklist_de_bots](#blocklist_de_bots)|3094|3094|23|0.7%|0.1%|
[proxz](#proxz)|712|712|21|2.9%|0.1%|
[php_commenters](#php_commenters)|281|281|21|7.4%|0.1%|
[et_block](#et_block)|1007|18338646|20|0.0%|0.1%|
[spamhaus_drop](#spamhaus_drop)|654|18469632|19|0.0%|0.1%|
[openbl_7d](#openbl_7d)|943|943|15|1.5%|0.0%|
[et_compromised](#et_compromised)|2171|2171|11|0.5%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2051|2051|9|0.4%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|5|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|5|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|486400|4|0.0%|0.0%|
[shunlist](#shunlist)|1273|1273|4|0.3%|0.0%|
[php_harvesters](#php_harvesters)|257|257|4|1.5%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|4|0.0%|0.0%|
[dm_tor](#dm_tor)|6611|6611|4|0.0%|0.0%|
[bm_tor](#bm_tor)|6616|6616|4|0.0%|0.0%|
[sorbs_socks](#sorbs_socks)|23|23|3|13.0%|0.0%|
[sorbs_misc](#sorbs_misc)|23|23|3|13.0%|0.0%|
[sorbs_http](#sorbs_http)|23|23|3|13.0%|0.0%|
[openbl_1d](#openbl_1d)|192|192|3|1.5%|0.0%|
[et_tor](#et_tor)|6380|6380|3|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2327|2327|2|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|2|0.2%|0.0%|
[dshield](#dshield)|20|5120|2|0.0%|0.0%|
[voipbl](#voipbl)|10426|10837|1|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[ciarmy](#ciarmy)|343|343|1|0.2%|0.0%|

## blocklist_de_sip

[Blocklist.de](https://www.blocklist.de/) All IP addresses that tried to login in a SIP, VOIP or Asterisk Server and are included in the IPs list from [infiltrated.net](www.infiltrated.net)

Source is downloaded from [this link](http://lists.blocklist.de/lists/sip.txt).

The last time downloaded was found to be dated: Thu Jun  4 15:28:08 UTC 2015.

The ipset `blocklist_de_sip` has **103** entries, **103** unique IPs.

The following table shows the overlaps of `blocklist_de_sip` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_sip`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_sip`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_sip`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|37184|37184|84|0.2%|81.5%|
[voipbl](#voipbl)|10426|10837|39|0.3%|37.8%|
[alienvault_reputation](#alienvault_reputation)|178477|178477|18|0.0%|17.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|14|0.0%|13.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|9|0.0%|8.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|5|0.0%|4.8%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|2|0.0%|1.9%|
[et_botcc](#et_botcc)|508|508|1|0.1%|0.9%|
[dshield](#dshield)|20|5120|1|0.0%|0.9%|
[ciarmy](#ciarmy)|343|343|1|0.2%|0.9%|

## blocklist_de_ssh

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service SSH.

Source is downloaded from [this link](http://lists.blocklist.de/lists/ssh.txt).

The last time downloaded was found to be dated: Thu Jun  4 15:28:05 UTC 2015.

The ipset `blocklist_de_ssh` has **13692** entries, **13692** unique IPs.

The following table shows the overlaps of `blocklist_de_ssh` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_ssh`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_ssh`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_ssh`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|37184|37184|13692|36.8%|100.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|3694|0.0%|26.9%|
[alienvault_reputation](#alienvault_reputation)|178477|178477|1973|1.1%|14.4%|
[openbl_60d](#openbl_60d)|7702|7702|1813|23.5%|13.2%|
[openbl_30d](#openbl_30d)|3260|3260|845|25.9%|6.1%|
[bruteforceblocker](#bruteforceblocker)|2051|2051|665|32.4%|4.8%|
[et_compromised](#et_compromised)|2171|2171|640|29.4%|4.6%|
[openbl_7d](#openbl_7d)|943|943|582|61.7%|4.2%|
[shunlist](#shunlist)|1273|1273|356|27.9%|2.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|231|0.0%|1.6%|
[openbl_1d](#openbl_1d)|192|192|154|80.2%|1.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|127|0.0%|0.9%|
[et_block](#et_block)|1007|18338646|113|0.0%|0.8%|
[spamhaus_drop](#spamhaus_drop)|654|18469632|111|0.0%|0.8%|
[dshield](#dshield)|20|5120|111|2.1%|0.8%|
[stopforumspam_30d](#stopforumspam_30d)|92996|92996|99|0.1%|0.7%|
[sorbs_spam](#sorbs_spam)|23635|24447|75|0.3%|0.5%|
[sorbs_recent_spam](#sorbs_recent_spam)|18771|19329|73|0.3%|0.5%|
[sorbs_new_spam](#sorbs_new_spam)|18771|19329|73|0.3%|0.5%|
[blocklist_de_strongips](#blocklist_de_strongips)|179|179|26|14.5%|0.1%|
[stopforumspam_7d](#stopforumspam_7d)|30334|30334|14|0.0%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|7|0.0%|0.0%|
[nixspam](#nixspam)|21627|21627|6|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7131|7131|4|0.0%|0.0%|
[voipbl](#voipbl)|10426|10837|3|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|2|0.0%|0.0%|
[ciarmy](#ciarmy)|343|343|2|0.5%|0.0%|
[xroxy](#xroxy)|2060|2060|1|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|486400|1|0.0%|0.0%|
[sorbs_web](#sorbs_web)|680|682|1|0.1%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9591|9591|1|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2327|2327|1|0.0%|0.0%|
[proxz](#proxz)|712|712|1|0.1%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|

## blocklist_de_strongips

[Blocklist.de](https://www.blocklist.de/) All IPs which are older then 2 month and have more then 5.000 attacks.

Source is downloaded from [this link](http://lists.blocklist.de/lists/strongips.txt).

The last time downloaded was found to be dated: Thu Jun  4 15:42:22 UTC 2015.

The ipset `blocklist_de_strongips` has **179** entries, **179** unique IPs.

The following table shows the overlaps of `blocklist_de_strongips` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_strongips`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_strongips`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_strongips`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|37184|37184|179|0.4%|100.0%|
[blocklist_de_bots](#blocklist_de_bots)|3094|3094|136|4.3%|75.9%|
[stopforumspam_30d](#stopforumspam_30d)|92996|92996|134|0.1%|74.8%|
[stopforumspam_7d](#stopforumspam_7d)|30334|30334|122|0.4%|68.1%|
[stopforumspam_1d](#stopforumspam_1d)|7131|7131|104|1.4%|58.1%|
[blocklist_de_apache](#blocklist_de_apache)|13430|13430|36|0.2%|20.1%|
[alienvault_reputation](#alienvault_reputation)|178477|178477|34|0.0%|18.9%|
[php_commenters](#php_commenters)|281|281|32|11.3%|17.8%|
[blocklist_de_ssh](#blocklist_de_ssh)|13692|13692|26|0.1%|14.5%|
[openbl_60d](#openbl_60d)|7702|7702|25|0.3%|13.9%|
[openbl_7d](#openbl_7d)|943|943|23|2.4%|12.8%|
[openbl_30d](#openbl_30d)|3260|3260|23|0.7%|12.8%|
[blocklist_de_mail](#blocklist_de_mail)|17091|17091|23|0.1%|12.8%|
[openbl_1d](#openbl_1d)|192|192|21|10.9%|11.7%|
[shunlist](#shunlist)|1273|1273|20|1.5%|11.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|15|0.0%|8.3%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2089|2089|8|0.3%|4.4%|
[xroxy](#xroxy)|2060|2060|7|0.3%|3.9%|
[spamhaus_drop](#spamhaus_drop)|654|18469632|6|0.0%|3.3%|
[ri_web_proxies](#ri_web_proxies)|6189|6189|6|0.0%|3.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|6|0.0%|3.3%|
[et_block](#et_block)|1007|18338646|6|0.0%|3.3%|
[spamhaus_edrop](#spamhaus_edrop)|55|486400|5|0.0%|2.7%|
[dshield](#dshield)|20|5120|5|0.0%|2.7%|
[proxyrss](#proxyrss)|1606|1606|4|0.2%|2.2%|
[php_spammers](#php_spammers)|417|417|4|0.9%|2.2%|
[proxz](#proxz)|712|712|3|0.4%|1.6%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|1.6%|
[php_harvesters](#php_harvesters)|257|257|2|0.7%|1.1%|
[php_dictionary](#php_dictionary)|433|433|2|0.4%|1.1%|
[nixspam](#nixspam)|21627|21627|2|0.0%|1.1%|
[sorbs_web](#sorbs_web)|680|682|1|0.1%|0.5%|
[sorbs_spam](#sorbs_spam)|23635|24447|1|0.0%|0.5%|
[sorbs_recent_spam](#sorbs_recent_spam)|18771|19329|1|0.0%|0.5%|
[sorbs_new_spam](#sorbs_new_spam)|18771|19329|1|0.0%|0.5%|
[snort_ipfilter](#snort_ipfilter)|9591|9591|1|0.0%|0.5%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|1|0.0%|0.5%|
[blocklist_de_imap](#blocklist_de_imap)|2830|2830|1|0.0%|0.5%|

## bm_tor

[torstatus.blutmagie.de](https://torstatus.blutmagie.de) list of all TOR network servers

Source is downloaded from [this link](https://torstatus.blutmagie.de/ip_list_all.php/Tor_ip_list_ALL.csv).

The last time downloaded was found to be dated: Thu Jun  4 15:27:09 UTC 2015.

The ipset `bm_tor` has **6616** entries, **6616** unique IPs.

The following table shows the overlaps of `bm_tor` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `bm_tor`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `bm_tor`.
- ` this % ` is the percentage **of this ipset (`bm_tor`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[dm_tor](#dm_tor)|6611|6611|6611|100.0%|99.9%|
[et_tor](#et_tor)|6380|6380|5707|89.4%|86.2%|
[snort_ipfilter](#snort_ipfilter)|9591|9591|1090|11.3%|16.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|631|0.0%|9.5%|
[stopforumspam_30d](#stopforumspam_30d)|92996|92996|624|0.6%|9.4%|
[stopforumspam_7d](#stopforumspam_7d)|30334|30334|486|1.6%|7.3%|
[stopforumspam_1d](#stopforumspam_1d)|7131|7131|323|4.5%|4.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|192|0.0%|2.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|170|0.0%|2.5%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|168|45.1%|2.5%|
[alienvault_reputation](#alienvault_reputation)|178477|178477|43|0.0%|0.6%|
[php_commenters](#php_commenters)|281|281|29|10.3%|0.4%|
[openbl_60d](#openbl_60d)|7702|7702|21|0.2%|0.3%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|19|0.0%|0.2%|
[php_spammers](#php_spammers)|417|417|6|1.4%|0.0%|
[php_harvesters](#php_harvesters)|257|257|6|2.3%|0.0%|
[ri_web_proxies](#ri_web_proxies)|6189|6189|4|0.0%|0.0%|
[php_dictionary](#php_dictionary)|433|433|4|0.9%|0.0%|
[et_block](#et_block)|1007|18338646|4|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|17091|17091|4|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13430|13430|4|0.0%|0.0%|
[blocklist_de](#blocklist_de)|37184|37184|4|0.0%|0.0%|
[voipbl](#voipbl)|10426|10837|3|0.0%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|0.0%|
[xroxy](#xroxy)|2060|2060|2|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|654|18469632|2|0.0%|0.0%|
[nixspam](#nixspam)|21627|21627|2|0.0%|0.0%|
[dshield](#dshield)|20|5120|2|0.0%|0.0%|
[sorbs_spam](#sorbs_spam)|23635|24447|1|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|18771|19329|1|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|18771|19329|1|0.0%|0.0%|
[shunlist](#shunlist)|1273|1273|1|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2327|2327|1|0.0%|0.0%|

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
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.0%|
[ciarmy](#ciarmy)|343|343|1|0.2%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2051|2051|1|0.0%|0.0%|

## bruteforceblocker

[danger.rulez.sk](http://danger.rulez.sk/) IPs detected by [bruteforceblocker](http://danger.rulez.sk/index.php/bruteforceblocker/) (fail2ban alternative for SSH on OpenBSD). This is an automatically generated list from users reporting failed authentication attempts. An IP seems to be included if 3 or more users report it. Its retention pocily seems 30 days.

Source is downloaded from [this link](http://danger.rulez.sk/projects/bruteforceblocker/blist.php).

The last time downloaded was found to be dated: Thu Jun  4 15:36:31 UTC 2015.

The ipset `bruteforceblocker` has **2051** entries, **2051** unique IPs.

The following table shows the overlaps of `bruteforceblocker` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `bruteforceblocker`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `bruteforceblocker`.
- ` this % ` is the percentage **of this ipset (`bruteforceblocker`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[et_compromised](#et_compromised)|2171|2171|2000|92.1%|97.5%|
[alienvault_reputation](#alienvault_reputation)|178477|178477|1332|0.7%|64.9%|
[openbl_60d](#openbl_60d)|7702|7702|1239|16.0%|60.4%|
[openbl_30d](#openbl_30d)|3260|3260|1181|36.2%|57.5%|
[blocklist_de](#blocklist_de)|37184|37184|680|1.8%|33.1%|
[blocklist_de_ssh](#blocklist_de_ssh)|13692|13692|665|4.8%|32.4%|
[shunlist](#shunlist)|1273|1273|490|38.4%|23.8%|
[openbl_7d](#openbl_7d)|943|943|426|45.1%|20.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|201|0.0%|9.8%|
[spamhaus_drop](#spamhaus_drop)|654|18469632|100|0.0%|4.8%|
[et_block](#et_block)|1007|18338646|100|0.0%|4.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|98|0.0%|4.7%|
[dshield](#dshield)|20|5120|97|1.8%|4.7%|
[openbl_1d](#openbl_1d)|192|192|90|46.8%|4.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|57|0.0%|2.7%|
[stopforumspam_30d](#stopforumspam_30d)|92996|92996|10|0.0%|0.4%|
[blocklist_de_mail](#blocklist_de_mail)|17091|17091|9|0.0%|0.4%|
[blocklist_de_imap](#blocklist_de_imap)|2830|2830|7|0.2%|0.3%|
[stopforumspam_7d](#stopforumspam_7d)|30334|30334|6|0.0%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|5|0.0%|0.2%|
[blocklist_de_bots](#blocklist_de_bots)|3094|3094|3|0.0%|0.1%|
[voipbl](#voipbl)|10426|10837|2|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7131|7131|2|0.0%|0.0%|
[proxz](#proxz)|712|712|2|0.2%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|2|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13430|13430|2|0.0%|0.0%|
[xroxy](#xroxy)|2060|2060|1|0.0%|0.0%|
[sorbs_spam](#sorbs_spam)|23635|24447|1|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9591|9591|1|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|6189|6189|1|0.0%|0.0%|
[proxyrss](#proxyrss)|1606|1606|1|0.0%|0.0%|
[fullbogons](#fullbogons)|3733|670419608|1|0.0%|0.0%|
[ciarmy](#ciarmy)|343|343|1|0.2%|0.0%|
[bogons](#bogons)|13|592708608|1|0.0%|0.0%|

## ciarmy

[CIArmy.com](http://ciarmy.com/) IPs with poor Rogue Packet score that have not yet been identified as malicious by the community

Source is downloaded from [this link](http://cinsscore.com/list/ci-badguys.txt).

The last time downloaded was found to be dated: Thu Jun  4 13:15:16 UTC 2015.

The ipset `ciarmy` has **343** entries, **343** unique IPs.

The following table shows the overlaps of `ciarmy` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ciarmy`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ciarmy`.
- ` this % ` is the percentage **of this ipset (`ciarmy`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[alienvault_reputation](#alienvault_reputation)|178477|178477|330|0.1%|96.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|53|0.0%|15.4%|
[blocklist_de](#blocklist_de)|37184|37184|41|0.1%|11.9%|
[blocklist_de_apache](#blocklist_de_apache)|13430|13430|36|0.2%|10.4%|
[shunlist](#shunlist)|1273|1273|27|2.1%|7.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|16|0.0%|4.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|7|0.0%|2.0%|
[voipbl](#voipbl)|10426|10837|6|0.0%|1.7%|
[dshield](#dshield)|20|5120|4|0.0%|1.1%|
[blocklist_de_ssh](#blocklist_de_ssh)|13692|13692|2|0.0%|0.5%|
[stopforumspam_7d](#stopforumspam_7d)|30334|30334|1|0.0%|0.2%|
[stopforumspam_30d](#stopforumspam_30d)|92996|92996|1|0.0%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.2%|
[fullbogons](#fullbogons)|3733|670419608|1|0.0%|0.2%|
[et_compromised](#et_compromised)|2171|2171|1|0.0%|0.2%|
[et_block](#et_block)|1007|18338646|1|0.0%|0.2%|
[bruteforceblocker](#bruteforceblocker)|2051|2051|1|0.0%|0.2%|
[bogons](#bogons)|13|592708608|1|0.0%|0.2%|
[blocklist_de_sip](#blocklist_de_sip)|103|103|1|0.9%|0.2%|
[blocklist_de_mail](#blocklist_de_mail)|17091|17091|1|0.0%|0.2%|
[blocklist_de_imap](#blocklist_de_imap)|2830|2830|1|0.0%|0.2%|
[blocklist_de_ftp](#blocklist_de_ftp)|872|872|1|0.1%|0.2%|

## cleanmx_viruses

[Clean-MX.de](http://support.clean-mx.de/clean-mx/viruses.php) IPs with viruses

Source is downloaded from [this link](http://support.clean-mx.de/clean-mx/xmlviruses.php?sort=id%20desc&response=alive).

The last time downloaded was found to be dated: Thu Jun  4 07:09:47 UTC 2015.

The ipset `cleanmx_viruses` has **206** entries, **206** unique IPs.

The following table shows the overlaps of `cleanmx_viruses` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `cleanmx_viruses`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `cleanmx_viruses`.
- ` this % ` is the percentage **of this ipset (`cleanmx_viruses`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|36|0.0%|17.4%|
[malc0de](#malc0de)|379|379|19|5.0%|9.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|12|0.0%|5.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|8|0.0%|3.8%|
[alienvault_reputation](#alienvault_reputation)|178477|178477|7|0.0%|3.3%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|3|0.2%|1.4%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|2|0.0%|0.9%|

## dm_tor

[dan.me.uk](https://www.dan.me.uk) dynamic list of TOR exit points

Source is downloaded from [this link](https://www.dan.me.uk/torlist/).

The last time downloaded was found to be dated: Thu Jun  4 15:27:08 UTC 2015.

The ipset `dm_tor` has **6611** entries, **6611** unique IPs.

The following table shows the overlaps of `dm_tor` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `dm_tor`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `dm_tor`.
- ` this % ` is the percentage **of this ipset (`dm_tor`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[bm_tor](#bm_tor)|6616|6616|6611|99.9%|100.0%|
[et_tor](#et_tor)|6380|6380|5703|89.3%|86.2%|
[snort_ipfilter](#snort_ipfilter)|9591|9591|1089|11.3%|16.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|631|0.0%|9.5%|
[stopforumspam_30d](#stopforumspam_30d)|92996|92996|624|0.6%|9.4%|
[stopforumspam_7d](#stopforumspam_7d)|30334|30334|486|1.6%|7.3%|
[stopforumspam_1d](#stopforumspam_1d)|7131|7131|323|4.5%|4.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|192|0.0%|2.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|170|0.0%|2.5%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|168|45.1%|2.5%|
[alienvault_reputation](#alienvault_reputation)|178477|178477|43|0.0%|0.6%|
[php_commenters](#php_commenters)|281|281|29|10.3%|0.4%|
[openbl_60d](#openbl_60d)|7702|7702|21|0.2%|0.3%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|19|0.0%|0.2%|
[php_spammers](#php_spammers)|417|417|6|1.4%|0.0%|
[php_harvesters](#php_harvesters)|257|257|6|2.3%|0.0%|
[ri_web_proxies](#ri_web_proxies)|6189|6189|4|0.0%|0.0%|
[php_dictionary](#php_dictionary)|433|433|4|0.9%|0.0%|
[et_block](#et_block)|1007|18338646|4|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|17091|17091|4|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13430|13430|4|0.0%|0.0%|
[blocklist_de](#blocklist_de)|37184|37184|4|0.0%|0.0%|
[voipbl](#voipbl)|10426|10837|3|0.0%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|0.0%|
[xroxy](#xroxy)|2060|2060|2|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|654|18469632|2|0.0%|0.0%|
[nixspam](#nixspam)|21627|21627|2|0.0%|0.0%|
[dshield](#dshield)|20|5120|2|0.0%|0.0%|
[sorbs_spam](#sorbs_spam)|23635|24447|1|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|18771|19329|1|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|18771|19329|1|0.0%|0.0%|
[shunlist](#shunlist)|1273|1273|1|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2327|2327|1|0.0%|0.0%|

## dshield

[DShield.org](https://dshield.org/) top 20 attacking class C (/24) subnets over the last three days - **excellent list**

Source is downloaded from [this link](http://feeds.dshield.org/block.txt).

The last time downloaded was found to be dated: Thu Jun  4 15:18:18 UTC 2015.

The ipset `dshield` has **20** entries, **5120** unique IPs.

The following table shows the overlaps of `dshield` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `dshield`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `dshield`.
- ` this % ` is the percentage **of this ipset (`dshield`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[alienvault_reputation](#alienvault_reputation)|178477|178477|3091|1.7%|60.3%|
[et_block](#et_block)|1007|18338646|1536|0.0%|30.0%|
[spamhaus_drop](#spamhaus_drop)|654|18469632|512|0.0%|10.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|256|0.0%|5.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|256|0.0%|5.0%|
[openbl_60d](#openbl_60d)|7702|7702|123|1.5%|2.4%|
[blocklist_de](#blocklist_de)|37184|37184|122|0.3%|2.3%|
[openbl_30d](#openbl_30d)|3260|3260|115|3.5%|2.2%|
[shunlist](#shunlist)|1273|1273|112|8.7%|2.1%|
[blocklist_de_ssh](#blocklist_de_ssh)|13692|13692|111|0.8%|2.1%|
[bruteforceblocker](#bruteforceblocker)|2051|2051|97|4.7%|1.8%|
[et_compromised](#et_compromised)|2171|2171|96|4.4%|1.8%|
[openbl_7d](#openbl_7d)|943|943|57|6.0%|1.1%|
[openbl_1d](#openbl_1d)|192|192|11|5.7%|0.2%|
[blocklist_de_apache](#blocklist_de_apache)|13430|13430|8|0.0%|0.1%|
[blocklist_de_strongips](#blocklist_de_strongips)|179|179|5|2.7%|0.0%|
[ciarmy](#ciarmy)|343|343|4|1.1%|0.0%|
[voipbl](#voipbl)|10426|10837|2|0.0%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|30334|30334|2|0.0%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92996|92996|2|0.0%|0.0%|
[et_tor](#et_tor)|6380|6380|2|0.0%|0.0%|
[dm_tor](#dm_tor)|6611|6611|2|0.0%|0.0%|
[bm_tor](#bm_tor)|6616|6616|2|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|17091|17091|2|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7131|7131|1|0.0%|0.0%|
[sorbs_spam](#sorbs_spam)|23635|24447|1|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|18771|19329|1|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|18771|19329|1|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9591|9591|1|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.0%|
[php_commenters](#php_commenters)|281|281|1|0.3%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[malc0de](#malc0de)|379|379|1|0.2%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|103|103|1|0.9%|0.0%|

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
[spamhaus_drop](#spamhaus_drop)|654|18469632|18202368|98.5%|99.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|8598327|2.4%|46.8%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|7079936|77.1%|38.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|2272279|0.2%|12.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|196442|0.1%|1.0%|
[fullbogons](#fullbogons)|3733|670419608|20480|0.0%|0.1%|
[alienvault_reputation](#alienvault_reputation)|178477|178477|5793|3.2%|0.0%|
[dshield](#dshield)|20|5120|1536|30.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1040|0.3%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92996|92996|1014|1.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|486400|517|0.1%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|30334|30334|335|1.1%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9591|9591|305|3.1%|0.0%|
[zeus](#zeus)|269|269|259|96.2%|0.0%|
[openbl_60d](#openbl_60d)|7702|7702|244|3.1%|0.0%|
[zeus_badips](#zeus_badips)|234|234|230|98.2%|0.0%|
[openbl_30d](#openbl_30d)|3260|3260|163|5.0%|0.0%|
[blocklist_de](#blocklist_de)|37184|37184|157|0.4%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|13692|13692|113|0.8%|0.0%|
[shunlist](#shunlist)|1273|1273|108|8.4%|0.0%|
[et_compromised](#et_compromised)|2171|2171|100|4.6%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2051|2051|100|4.8%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7131|7131|91|1.2%|0.0%|
[feodo](#feodo)|93|93|80|86.0%|0.0%|
[nixspam](#nixspam)|21627|21627|65|0.3%|0.0%|
[openbl_7d](#openbl_7d)|943|943|58|6.1%|0.0%|
[sslbl](#sslbl)|366|366|32|8.7%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|29|2.2%|0.0%|
[php_commenters](#php_commenters)|281|281|25|8.8%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|17091|17091|20|0.1%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3094|3094|20|0.6%|0.0%|
[voipbl](#voipbl)|10426|10837|14|0.1%|0.0%|
[sorbs_spam](#sorbs_spam)|23635|24447|12|0.0%|0.0%|
[palevo](#palevo)|13|13|12|92.3%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2830|2830|10|0.3%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|18771|19329|7|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|18771|19329|7|0.0%|0.0%|
[openbl_1d](#openbl_1d)|192|192|7|3.6%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|6|0.4%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|6|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|179|179|6|3.3%|0.0%|
[malc0de](#malc0de)|379|379|5|1.3%|0.0%|
[php_dictionary](#php_dictionary)|433|433|4|0.9%|0.0%|
[et_tor](#et_tor)|6380|6380|4|0.0%|0.0%|
[dm_tor](#dm_tor)|6611|6611|4|0.0%|0.0%|
[bm_tor](#bm_tor)|6616|6616|4|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13430|13430|4|0.0%|0.0%|
[php_spammers](#php_spammers)|417|417|2|0.4%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|2|0.2%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2089|2089|2|0.0%|0.0%|
[sorbs_web](#sorbs_web)|680|682|1|0.1%|0.0%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[et_botcc](#et_botcc)|508|508|1|0.1%|0.0%|
[ciarmy](#ciarmy)|343|343|1|0.2%|0.0%|

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
[alienvault_reputation](#alienvault_reputation)|178477|178477|4|0.0%|0.7%|
[spamhaus_drop](#spamhaus_drop)|654|18469632|1|0.0%|0.1%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|1|0.0%|0.1%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.1%|
[et_block](#et_block)|1007|18338646|1|0.0%|0.1%|
[blocklist_de_sip](#blocklist_de_sip)|103|103|1|0.9%|0.1%|

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
[bruteforceblocker](#bruteforceblocker)|2051|2051|2000|97.5%|92.1%|
[alienvault_reputation](#alienvault_reputation)|178477|178477|1406|0.7%|64.7%|
[openbl_60d](#openbl_60d)|7702|7702|1310|17.0%|60.3%|
[openbl_30d](#openbl_30d)|3260|3260|1217|37.3%|56.0%|
[blocklist_de](#blocklist_de)|37184|37184|657|1.7%|30.2%|
[blocklist_de_ssh](#blocklist_de_ssh)|13692|13692|640|4.6%|29.4%|
[shunlist](#shunlist)|1273|1273|496|38.9%|22.8%|
[openbl_7d](#openbl_7d)|943|943|416|44.1%|19.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|216|0.0%|9.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|115|0.0%|5.2%|
[spamhaus_drop](#spamhaus_drop)|654|18469632|100|0.0%|4.6%|
[et_block](#et_block)|1007|18338646|100|0.0%|4.6%|
[dshield](#dshield)|20|5120|96|1.8%|4.4%|
[openbl_1d](#openbl_1d)|192|192|84|43.7%|3.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|62|0.0%|2.8%|
[blocklist_de_mail](#blocklist_de_mail)|17091|17091|11|0.0%|0.5%|
[stopforumspam_30d](#stopforumspam_30d)|92996|92996|10|0.0%|0.4%|
[blocklist_de_imap](#blocklist_de_imap)|2830|2830|8|0.2%|0.3%|
[stopforumspam_7d](#stopforumspam_7d)|30334|30334|6|0.0%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|5|0.0%|0.2%|
[blocklist_de_apache](#blocklist_de_apache)|13430|13430|3|0.0%|0.1%|
[voipbl](#voipbl)|10426|10837|2|0.0%|0.0%|
[proxz](#proxz)|712|712|2|0.2%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|2|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3094|3094|2|0.0%|0.0%|
[xroxy](#xroxy)|2060|2060|1|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7131|7131|1|0.0%|0.0%|
[sorbs_spam](#sorbs_spam)|23635|24447|1|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9591|9591|1|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|6189|6189|1|0.0%|0.0%|
[proxyrss](#proxyrss)|1606|1606|1|0.0%|0.0%|
[ciarmy](#ciarmy)|343|343|1|0.2%|0.0%|

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
[bm_tor](#bm_tor)|6616|6616|5707|86.2%|89.4%|
[dm_tor](#dm_tor)|6611|6611|5703|86.2%|89.3%|
[snort_ipfilter](#snort_ipfilter)|9591|9591|1086|11.3%|17.0%|
[stopforumspam_30d](#stopforumspam_30d)|92996|92996|636|0.6%|9.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|626|0.0%|9.8%|
[stopforumspam_7d](#stopforumspam_7d)|30334|30334|499|1.6%|7.8%|
[stopforumspam_1d](#stopforumspam_1d)|7131|7131|331|4.6%|5.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|185|0.0%|2.8%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|171|45.9%|2.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|167|0.0%|2.6%|
[alienvault_reputation](#alienvault_reputation)|178477|178477|42|0.0%|0.6%|
[php_commenters](#php_commenters)|281|281|29|10.3%|0.4%|
[openbl_60d](#openbl_60d)|7702|7702|21|0.2%|0.3%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|21|0.0%|0.3%|
[php_harvesters](#php_harvesters)|257|257|7|2.7%|0.1%|
[php_spammers](#php_spammers)|417|417|6|1.4%|0.0%|
[ri_web_proxies](#ri_web_proxies)|6189|6189|4|0.0%|0.0%|
[php_dictionary](#php_dictionary)|433|433|4|0.9%|0.0%|
[et_block](#et_block)|1007|18338646|4|0.0%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|17091|17091|3|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13430|13430|3|0.0%|0.0%|
[blocklist_de](#blocklist_de)|37184|37184|3|0.0%|0.0%|
[xroxy](#xroxy)|2060|2060|2|0.0%|0.0%|
[voipbl](#voipbl)|10426|10837|2|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|654|18469632|2|0.0%|0.0%|
[sorbs_spam](#sorbs_spam)|23635|24447|2|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|18771|19329|2|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|18771|19329|2|0.0%|0.0%|
[nixspam](#nixspam)|21627|21627|2|0.0%|0.0%|
[dshield](#dshield)|20|5120|2|0.0%|0.0%|
[shunlist](#shunlist)|1273|1273|1|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2327|2327|1|0.0%|0.0%|

## feodo

[Abuse.ch Feodo tracker](https://feodotracker.abuse.ch) trojan includes IPs which are being used by Feodo (also known as Cridex or Bugat) which commits ebanking fraud - **excellent list**

Source is downloaded from [this link](https://feodotracker.abuse.ch/blocklist/?download=ipblocklist).

The last time downloaded was found to be dated: Thu Jun  4 15:27:18 UTC 2015.

The ipset `feodo` has **93** entries, **93** unique IPs.

The following table shows the overlaps of `feodo` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `feodo`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `feodo`.
- ` this % ` is the percentage **of this ipset (`feodo`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[et_block](#et_block)|1007|18338646|80|0.0%|86.0%|
[snort_ipfilter](#snort_ipfilter)|9591|9591|68|0.7%|73.1%|
[sslbl](#sslbl)|366|366|34|9.2%|36.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|10|0.0%|10.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|3|0.0%|3.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|3|0.0%|3.2%|
[alienvault_reputation](#alienvault_reputation)|178477|178477|2|0.0%|2.1%|
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
[spamhaus_drop](#spamhaus_drop)|654|18469632|151552|0.8%|0.0%|
[et_block](#et_block)|1007|18338646|20480|0.1%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|890|0.2%|0.0%|
[voipbl](#voipbl)|10426|10837|319|2.9%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|33|2.2%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|15|0.0%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|9|0.6%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92996|92996|2|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.0%|
[ciarmy](#ciarmy)|343|343|1|0.2%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2051|2051|1|0.0%|0.0%|

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
[alienvault_reputation](#alienvault_reputation)|178477|178477|15|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|11|1.6%|0.0%|
[nixspam](#nixspam)|21627|21627|8|0.0%|0.0%|
[blocklist_de](#blocklist_de)|37184|37184|8|0.0%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|30334|30334|6|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|654|18469632|6|0.0%|0.0%|
[sorbs_spam](#sorbs_spam)|23635|24447|6|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|18771|19329|6|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|18771|19329|6|0.0%|0.0%|
[et_block](#et_block)|1007|18338646|6|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|17091|17091|5|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|4|0.0%|0.0%|
[xroxy](#xroxy)|2060|2060|3|0.1%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2089|2089|3|0.1%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13430|13430|3|0.0%|0.0%|
[voipbl](#voipbl)|10426|10837|2|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|6189|6189|2|0.0%|0.0%|
[proxyrss](#proxyrss)|1606|1606|2|0.1%|0.0%|
[php_harvesters](#php_harvesters)|257|257|2|0.7%|0.0%|
[php_dictionary](#php_dictionary)|433|433|2|0.4%|0.0%|
[sorbs_web](#sorbs_web)|680|682|1|0.1%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9591|9591|1|0.0%|0.0%|
[proxz](#proxz)|712|712|1|0.1%|0.0%|
[php_spammers](#php_spammers)|417|417|1|0.2%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2830|2830|1|0.0%|0.0%|

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
[spamhaus_drop](#spamhaus_drop)|654|18469632|7014400|37.9%|76.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|2526625|0.7%|27.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|904796|0.1%|9.8%|
[fullbogons](#fullbogons)|3733|670419608|565248|0.0%|6.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|145472|0.1%|1.5%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1036|0.3%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92996|92996|756|0.8%|0.0%|
[alienvault_reputation](#alienvault_reputation)|178477|178477|518|0.2%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|30334|30334|186|0.6%|0.0%|
[nixspam](#nixspam)|21627|21627|65|0.3%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7131|7131|39|0.5%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|27|2.0%|0.0%|
[blocklist_de](#blocklist_de)|37184|37184|25|0.0%|0.0%|
[openbl_60d](#openbl_60d)|7702|7702|18|0.2%|0.0%|
[openbl_30d](#openbl_30d)|3260|3260|13|0.3%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9591|9591|11|0.1%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3094|3094|11|0.3%|0.0%|
[zeus_badips](#zeus_badips)|234|234|10|4.2%|0.0%|
[zeus](#zeus)|269|269|10|3.7%|0.0%|
[sorbs_spam](#sorbs_spam)|23635|24447|8|0.0%|0.0%|
[openbl_7d](#openbl_7d)|943|943|7|0.7%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|7|0.4%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|13692|13692|7|0.0%|0.0%|
[et_compromised](#et_compromised)|2171|2171|5|0.2%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2051|2051|5|0.2%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|17091|17091|5|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|18771|19329|3|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|18771|19329|3|0.0%|0.0%|
[openbl_1d](#openbl_1d)|192|192|3|1.5%|0.0%|
[et_tor](#et_tor)|6380|6380|3|0.0%|0.0%|
[dm_tor](#dm_tor)|6611|6611|3|0.0%|0.0%|
[bm_tor](#bm_tor)|6616|6616|3|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|179|179|3|1.6%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2830|2830|3|0.1%|0.0%|
[shunlist](#shunlist)|1273|1273|2|0.1%|0.0%|
[php_spammers](#php_spammers)|417|417|2|0.4%|0.0%|
[php_dictionary](#php_dictionary)|433|433|2|0.4%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|2|0.2%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2089|2089|2|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13430|13430|2|0.0%|0.0%|
[voipbl](#voipbl)|10426|10837|1|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.0%|
[php_commenters](#php_commenters)|281|281|1|0.3%|0.0%|
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
[spamhaus_drop](#spamhaus_drop)|654|18469632|2272265|12.3%|0.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|1354348|0.9%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|904796|9.8%|0.1%|
[fullbogons](#fullbogons)|3733|670419608|239993|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|486400|33155|6.8%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|13248|3.9%|0.0%|
[alienvault_reputation](#alienvault_reputation)|178477|178477|4471|2.5%|0.0%|
[blocklist_de](#blocklist_de)|37184|37184|1592|4.2%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92996|92996|1551|1.6%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|17091|17091|1366|7.9%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13430|13430|1326|9.8%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|30334|30334|571|1.8%|0.0%|
[nixspam](#nixspam)|21627|21627|425|1.9%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|406|0.8%|0.0%|
[sorbs_spam](#sorbs_spam)|23635|24447|380|1.5%|0.0%|
[voipbl](#voipbl)|10426|10837|299|2.7%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|18771|19329|294|1.5%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|18771|19329|294|1.5%|0.0%|
[openbl_60d](#openbl_60d)|7702|7702|172|2.2%|0.0%|
[dm_tor](#dm_tor)|6611|6611|170|2.5%|0.0%|
[bm_tor](#bm_tor)|6616|6616|170|2.5%|0.0%|
[et_tor](#et_tor)|6380|6380|167|2.6%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7131|7131|159|2.2%|0.0%|
[ri_web_proxies](#ri_web_proxies)|6189|6189|130|2.1%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|13692|13692|127|0.9%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9591|9591|100|1.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|97|6.6%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2327|2327|74|3.1%|0.0%|
[openbl_30d](#openbl_30d)|3260|3260|71|2.1%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|66|5.1%|0.0%|
[et_compromised](#et_compromised)|2171|2171|62|2.8%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|58|8.6%|0.0%|
[xroxy](#xroxy)|2060|2060|57|2.7%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2051|2051|57|2.7%|0.0%|
[proxyrss](#proxyrss)|1606|1606|49|3.0%|0.0%|
[et_botcc](#et_botcc)|508|508|40|7.8%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3094|3094|39|1.2%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2830|2830|38|1.3%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2089|2089|38|1.8%|0.0%|
[proxz](#proxz)|712|712|27|3.7%|0.0%|
[shunlist](#shunlist)|1273|1273|26|2.0%|0.0%|
[sorbs_web](#sorbs_web)|680|682|24|3.5%|0.0%|
[openbl_7d](#openbl_7d)|943|943|20|2.1%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|17|4.5%|0.0%|
[malc0de](#malc0de)|379|379|12|3.1%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|872|872|11|1.2%|0.0%|
[php_dictionary](#php_dictionary)|433|433|9|2.0%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|206|206|8|3.8%|0.0%|
[php_harvesters](#php_harvesters)|257|257|7|2.7%|0.0%|
[ciarmy](#ciarmy)|343|343|7|2.0%|0.0%|
[zeus](#zeus)|269|269|6|2.2%|0.0%|
[php_spammers](#php_spammers)|417|417|5|1.1%|0.0%|
[php_commenters](#php_commenters)|281|281|5|1.7%|0.0%|
[bogons](#bogons)|13|592708608|5|0.0%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|103|103|5|4.8%|0.0%|
[zeus_badips](#zeus_badips)|234|234|4|1.7%|0.0%|
[sslbl](#sslbl)|366|366|4|1.0%|0.0%|
[openbl_1d](#openbl_1d)|192|192|3|1.5%|0.0%|
[feodo](#feodo)|93|93|3|3.2%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|179|179|1|0.5%|0.0%|

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
[spamhaus_drop](#spamhaus_drop)|654|18469632|8598042|46.5%|2.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|2830140|2.0%|0.8%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2526625|27.5%|0.7%|
[fullbogons](#fullbogons)|3733|670419608|249087|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|486400|98904|20.3%|0.0%|
[alienvault_reputation](#alienvault_reputation)|178477|178477|7803|4.3%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|7733|2.2%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92996|92996|2521|2.7%|0.0%|
[blocklist_de](#blocklist_de)|37184|37184|1561|4.1%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|17091|17091|1176|6.8%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13430|13430|1070|7.9%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|30334|30334|908|2.9%|0.0%|
[sorbs_spam](#sorbs_spam)|23635|24447|590|2.4%|0.0%|
[nixspam](#nixspam)|21627|21627|580|2.6%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|18771|19329|502|2.5%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|18771|19329|502|2.5%|0.0%|
[voipbl](#voipbl)|10426|10837|434|4.0%|0.0%|
[openbl_60d](#openbl_60d)|7702|7702|339|4.4%|0.0%|
[dshield](#dshield)|20|5120|256|5.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|13692|13692|231|1.6%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|230|0.4%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7131|7131|229|3.2%|0.0%|
[dm_tor](#dm_tor)|6611|6611|192|2.9%|0.0%|
[bm_tor](#bm_tor)|6616|6616|192|2.9%|0.0%|
[et_tor](#et_tor)|6380|6380|185|2.8%|0.0%|
[ri_web_proxies](#ri_web_proxies)|6189|6189|184|2.9%|0.0%|
[openbl_30d](#openbl_30d)|3260|3260|169|5.1%|0.0%|
[et_compromised](#et_compromised)|2171|2171|115|5.2%|0.0%|
[xroxy](#xroxy)|2060|2060|99|4.8%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9591|9591|98|1.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2051|2051|98|4.7%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2327|2327|91|3.9%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3094|3094|84|2.7%|0.0%|
[shunlist](#shunlist)|1273|1273|74|5.8%|0.0%|
[proxyrss](#proxyrss)|1606|1606|66|4.1%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2830|2830|64|2.2%|0.0%|
[openbl_7d](#openbl_7d)|943|943|47|4.9%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|45|3.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2089|2089|35|1.6%|0.0%|
[proxz](#proxz)|712|712|31|4.3%|0.0%|
[php_spammers](#php_spammers)|417|417|31|7.4%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|28|4.1%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|26|2.0%|0.0%|
[sorbs_web](#sorbs_web)|680|682|25|3.6%|0.0%|
[malc0de](#malc0de)|379|379|23|6.0%|0.0%|
[et_botcc](#et_botcc)|508|508|22|4.3%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|21|5.6%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|872|872|17|1.9%|0.0%|
[ciarmy](#ciarmy)|343|343|16|4.6%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|206|206|12|5.8%|0.0%|
[php_dictionary](#php_dictionary)|433|433|10|2.3%|0.0%|
[zeus](#zeus)|269|269|9|3.3%|0.0%|
[php_commenters](#php_commenters)|281|281|9|3.2%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|103|103|9|8.7%|0.0%|
[zeus_badips](#zeus_badips)|234|234|8|3.4%|0.0%|
[php_harvesters](#php_harvesters)|257|257|7|2.7%|0.0%|
[sslbl](#sslbl)|366|366|6|1.6%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|179|179|6|3.3%|0.0%|
[openbl_1d](#openbl_1d)|192|192|5|2.6%|0.0%|
[palevo](#palevo)|13|13|3|23.0%|0.0%|
[feodo](#feodo)|93|93|3|3.2%|0.0%|
[sorbs_socks](#sorbs_socks)|23|23|1|4.3%|0.0%|
[sorbs_smtp](#sorbs_smtp)|9|9|1|11.1%|0.0%|
[sorbs_misc](#sorbs_misc)|23|23|1|4.3%|0.0%|
[sorbs_http](#sorbs_http)|23|23|1|4.3%|0.0%|

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
[spamhaus_drop](#spamhaus_drop)|654|18469632|195904|1.0%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|145472|1.5%|0.1%|
[alienvault_reputation](#alienvault_reputation)|178477|178477|14125|7.9%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|9231|2.7%|0.0%|
[blocklist_de](#blocklist_de)|37184|37184|6691|17.9%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92996|92996|5857|6.2%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|13692|13692|3694|26.9%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|17091|17091|2562|14.9%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13430|13430|2272|16.9%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|30334|30334|1930|6.3%|0.0%|
[sorbs_spam](#sorbs_spam)|23635|24447|1747|7.1%|0.0%|
[nixspam](#nixspam)|21627|21627|1637|7.5%|0.0%|
[voipbl](#voipbl)|10426|10837|1596|14.7%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|18771|19329|1361|7.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|18771|19329|1361|7.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1172|2.4%|0.0%|
[openbl_60d](#openbl_60d)|7702|7702|749|9.7%|0.0%|
[dm_tor](#dm_tor)|6611|6611|631|9.5%|0.0%|
[bm_tor](#bm_tor)|6616|6616|631|9.5%|0.0%|
[et_tor](#et_tor)|6380|6380|626|9.8%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7131|7131|471|6.6%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2830|2830|360|12.7%|0.0%|
[openbl_30d](#openbl_30d)|3260|3260|311|9.5%|0.0%|
[dshield](#dshield)|20|5120|256|5.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9591|9591|219|2.2%|0.0%|
[et_compromised](#et_compromised)|2171|2171|216|9.9%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2051|2051|201|9.8%|0.0%|
[ri_web_proxies](#ri_web_proxies)|6189|6189|173|2.7%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2089|2089|173|8.2%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3094|3094|156|5.0%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|147|11.4%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|125|33.6%|0.0%|
[openbl_7d](#openbl_7d)|943|943|114|12.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|110|7.5%|0.0%|
[shunlist](#shunlist)|1273|1273|104|8.1%|0.0%|
[xroxy](#xroxy)|2060|2060|90|4.3%|0.0%|
[et_botcc](#et_botcc)|508|508|76|14.9%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|872|872|68|7.7%|0.0%|
[malc0de](#malc0de)|379|379|67|17.6%|0.0%|
[proxz](#proxz)|712|712|60|8.4%|0.0%|
[proxyrss](#proxyrss)|1606|1606|58|3.6%|0.0%|
[ciarmy](#ciarmy)|343|343|53|15.4%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|51|7.5%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2327|2327|50|2.1%|0.0%|
[sorbs_web](#sorbs_web)|680|682|43|6.3%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|206|206|36|17.4%|0.0%|
[php_spammers](#php_spammers)|417|417|26|6.2%|0.0%|
[php_dictionary](#php_dictionary)|433|433|24|5.5%|0.0%|
[sslbl](#sslbl)|366|366|23|6.2%|0.0%|
[openbl_1d](#openbl_1d)|192|192|21|10.9%|0.0%|
[zeus](#zeus)|269|269|20|7.4%|0.0%|
[php_harvesters](#php_harvesters)|257|257|15|5.8%|0.0%|
[php_commenters](#php_commenters)|281|281|15|5.3%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|179|179|15|8.3%|0.0%|
[zeus_badips](#zeus_badips)|234|234|14|5.9%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|103|103|14|13.5%|0.0%|
[feodo](#feodo)|93|93|10|10.7%|0.0%|
[virbl](#virbl)|11|11|1|9.0%|0.0%|
[sorbs_socks](#sorbs_socks)|23|23|1|4.3%|0.0%|
[sorbs_misc](#sorbs_misc)|23|23|1|4.3%|0.0%|
[sorbs_http](#sorbs_http)|23|23|1|4.3%|0.0%|
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
[xroxy](#xroxy)|2060|2060|13|0.6%|1.9%|
[proxyrss](#proxyrss)|1606|1606|13|0.8%|1.9%|
[stopforumspam_7d](#stopforumspam_7d)|30334|30334|12|0.0%|1.7%|
[ri_web_proxies](#ri_web_proxies)|6189|6189|12|0.1%|1.7%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|11|0.0%|1.6%|
[stopforumspam_1d](#stopforumspam_1d)|7131|7131|6|0.0%|0.8%|
[ri_connect_proxies](#ri_connect_proxies)|2327|2327|6|0.2%|0.8%|
[blocklist_de](#blocklist_de)|37184|37184|6|0.0%|0.8%|
[proxz](#proxz)|712|712|4|0.5%|0.5%|
[blocklist_de_bots](#blocklist_de_bots)|3094|3094|4|0.1%|0.5%|
[spamhaus_drop](#spamhaus_drop)|654|18469632|2|0.0%|0.2%|
[nixspam](#nixspam)|21627|21627|2|0.0%|0.2%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2|0.0%|0.2%|
[et_block](#et_block)|1007|18338646|2|0.0%|0.2%|
[blocklist_de_mail](#blocklist_de_mail)|17091|17091|2|0.0%|0.2%|
[sorbs_spam](#sorbs_spam)|23635|24447|1|0.0%|0.1%|
[sorbs_recent_spam](#sorbs_recent_spam)|18771|19329|1|0.0%|0.1%|
[sorbs_new_spam](#sorbs_new_spam)|18771|19329|1|0.0%|0.1%|
[snort_ipfilter](#snort_ipfilter)|9591|9591|1|0.0%|0.1%|
[php_dictionary](#php_dictionary)|433|433|1|0.2%|0.1%|
[alienvault_reputation](#alienvault_reputation)|178477|178477|1|0.0%|0.1%|

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
[spamhaus_drop](#spamhaus_drop)|654|18469632|1037|0.0%|0.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1036|0.0%|0.3%|
[fullbogons](#fullbogons)|3733|670419608|890|0.0%|0.2%|
[alienvault_reputation](#alienvault_reputation)|178477|178477|287|0.1%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92996|92996|48|0.0%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|27|2.0%|0.0%|
[sorbs_spam](#sorbs_spam)|23635|24447|24|0.0%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|30334|30334|23|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|18771|19329|23|0.1%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|18771|19329|23|0.1%|0.0%|
[et_tor](#et_tor)|6380|6380|21|0.3%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|19|1.3%|0.0%|
[dm_tor](#dm_tor)|6611|6611|19|0.2%|0.0%|
[bm_tor](#bm_tor)|6616|6616|19|0.2%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9591|9591|14|0.1%|0.0%|
[nixspam](#nixspam)|21627|21627|12|0.0%|0.0%|
[blocklist_de](#blocklist_de)|37184|37184|11|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7131|7131|9|0.1%|0.0%|
[ri_web_proxies](#ri_web_proxies)|6189|6189|5|0.0%|0.0%|
[openbl_60d](#openbl_60d)|7702|7702|5|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|5|1.3%|0.0%|
[voipbl](#voipbl)|10426|10837|4|0.0%|0.0%|
[openbl_30d](#openbl_30d)|3260|3260|4|0.1%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|4|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|17091|17091|4|0.0%|0.0%|
[malc0de](#malc0de)|379|379|3|0.7%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3094|3094|3|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13430|13430|3|0.0%|0.0%|
[palevo](#palevo)|13|13|2|15.3%|0.0%|
[et_compromised](#et_compromised)|2171|2171|2|0.0%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|206|206|2|0.9%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2051|2051|2|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|13692|13692|2|0.0%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|103|103|2|1.9%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2830|2830|2|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2089|2089|2|0.0%|0.0%|
[zeus_badips](#zeus_badips)|234|234|1|0.4%|0.0%|
[zeus](#zeus)|269|269|1|0.3%|0.0%|
[xroxy](#xroxy)|2060|2060|1|0.0%|0.0%|
[sslbl](#sslbl)|366|366|1|0.2%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|486400|1|0.0%|0.0%|
[shunlist](#shunlist)|1273|1273|1|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2327|2327|1|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.0%|
[php_dictionary](#php_dictionary)|433|433|1|0.2%|0.0%|
[openbl_7d](#openbl_7d)|943|943|1|0.1%|0.0%|
[feodo](#feodo)|93|93|1|1.0%|0.0%|
[ciarmy](#ciarmy)|343|343|1|0.2%|0.0%|
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
[alienvault_reputation](#alienvault_reputation)|178477|178477|8|0.0%|0.5%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|7|0.0%|0.4%|
[spamhaus_drop](#spamhaus_drop)|654|18469632|6|0.0%|0.4%|
[et_block](#et_block)|1007|18338646|6|0.0%|0.4%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|3|0.2%|0.2%|
[stopforumspam_30d](#stopforumspam_30d)|92996|92996|2|0.0%|0.1%|
[openbl_60d](#openbl_60d)|7702|7702|2|0.0%|0.1%|
[openbl_30d](#openbl_30d)|3260|3260|2|0.0%|0.1%|
[nixspam](#nixspam)|21627|21627|2|0.0%|0.1%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|2|0.2%|0.1%|
[blocklist_de](#blocklist_de)|37184|37184|2|0.0%|0.1%|
[stopforumspam_7d](#stopforumspam_7d)|30334|30334|1|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7131|7131|1|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9591|9591|1|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|6189|6189|1|0.0%|0.0%|
[openbl_7d](#openbl_7d)|943|943|1|0.1%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1|0.0%|0.0%|
[et_botcc](#et_botcc)|508|508|1|0.1%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|179|179|1|0.5%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|13692|13692|1|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3094|3094|1|0.0%|0.0%|

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
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|23|0.0%|6.0%|
[cleanmx_viruses](#cleanmx_viruses)|206|206|19|9.2%|5.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|12|0.0%|3.1%|
[alienvault_reputation](#alienvault_reputation)|178477|178477|11|0.0%|2.9%|
[et_block](#et_block)|1007|18338646|5|0.0%|1.3%|
[spamhaus_drop](#spamhaus_drop)|654|18469632|4|0.0%|1.0%|
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
[spamhaus_drop](#spamhaus_drop)|654|18469632|29|0.0%|2.2%|
[snort_ipfilter](#snort_ipfilter)|9591|9591|29|0.3%|2.2%|
[et_block](#et_block)|1007|18338646|29|0.0%|2.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|27|0.0%|2.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|27|0.0%|2.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|26|0.0%|2.0%|
[fullbogons](#fullbogons)|3733|670419608|9|0.0%|0.6%|
[alienvault_reputation](#alienvault_reputation)|178477|178477|6|0.0%|0.4%|
[stopforumspam_30d](#stopforumspam_30d)|92996|92996|4|0.0%|0.3%|
[malc0de](#malc0de)|379|379|4|1.0%|0.3%|
[stopforumspam_7d](#stopforumspam_7d)|30334|30334|3|0.0%|0.2%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|3|0.2%|0.2%|
[cleanmx_viruses](#cleanmx_viruses)|206|206|3|1.4%|0.2%|
[sorbs_spam](#sorbs_spam)|23635|24447|1|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|18771|19329|1|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|18771|19329|1|0.0%|0.0%|
[et_botcc](#et_botcc)|508|508|1|0.1%|0.0%|

## maxmind_proxy_fraud

[MaxMind.com](https://www.maxmind.com/en/anonymous-proxy-fraudulent-ip-address-list) list of anonymous proxy fraudelent IP addresses.

Source is downloaded from [this link](https://www.maxmind.com/en/anonymous-proxy-fraudulent-ip-address-list).

The last time downloaded was found to be dated: Thu Jun  4 13:09:26 UTC 2015.

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
[dm_tor](#dm_tor)|6611|6611|168|2.5%|45.1%|
[bm_tor](#bm_tor)|6616|6616|168|2.5%|45.1%|
[stopforumspam_1d](#stopforumspam_1d)|7131|7131|166|2.3%|44.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|125|0.0%|33.6%|
[php_commenters](#php_commenters)|281|281|28|9.9%|7.5%|
[alienvault_reputation](#alienvault_reputation)|178477|178477|25|0.0%|6.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|21|0.0%|5.6%|
[openbl_60d](#openbl_60d)|7702|7702|18|0.2%|4.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|17|0.0%|4.5%|
[php_harvesters](#php_harvesters)|257|257|6|2.3%|1.6%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|5|0.0%|1.3%|
[ri_web_proxies](#ri_web_proxies)|6189|6189|4|0.0%|1.0%|
[php_spammers](#php_spammers)|417|417|4|0.9%|1.0%|
[php_dictionary](#php_dictionary)|433|433|4|0.9%|1.0%|
[shunlist](#shunlist)|1273|1273|2|0.1%|0.5%|
[blocklist_de_apache](#blocklist_de_apache)|13430|13430|2|0.0%|0.5%|
[blocklist_de](#blocklist_de)|37184|37184|2|0.0%|0.5%|
[xroxy](#xroxy)|2060|2060|1|0.0%|0.2%|
[voipbl](#voipbl)|10426|10837|1|0.0%|0.2%|
[ri_connect_proxies](#ri_connect_proxies)|2327|2327|1|0.0%|0.2%|
[nixspam](#nixspam)|21627|21627|1|0.0%|0.2%|
[et_block](#et_block)|1007|18338646|1|0.0%|0.2%|
[dshield](#dshield)|20|5120|1|0.0%|0.2%|
[blocklist_de_mail](#blocklist_de_mail)|17091|17091|1|0.0%|0.2%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2089|2089|1|0.0%|0.2%|

## nixspam

[NiX Spam](http://www.heise.de/ix/NiX-Spam-DNSBL-and-blacklist-for-download-499637.html) IP addresses that sent spam in the last hour - automatically generated entries without distinguishing open proxies from relays, dialup gateways, and so on. All IPs are removed after 12 hours if there is no spam from there.

Source is downloaded from [this link](http://www.dnsbl.manitu.net/download/nixspam-ip.dump.gz).

The last time downloaded was found to be dated: Thu Jun  4 15:30:02 UTC 2015.

The ipset `nixspam` has **21627** entries, **21627** unique IPs.

The following table shows the overlaps of `nixspam` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `nixspam`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `nixspam`.
- ` this % ` is the percentage **of this ipset (`nixspam`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[sorbs_spam](#sorbs_spam)|23635|24447|4008|16.3%|18.5%|
[sorbs_recent_spam](#sorbs_recent_spam)|18771|19329|3853|19.9%|17.8%|
[sorbs_new_spam](#sorbs_new_spam)|18771|19329|3853|19.9%|17.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|1637|0.0%|7.5%|
[blocklist_de](#blocklist_de)|37184|37184|744|2.0%|3.4%|
[blocklist_de_mail](#blocklist_de_mail)|17091|17091|660|3.8%|3.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|580|0.0%|2.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|425|0.0%|1.9%|
[stopforumspam_30d](#stopforumspam_30d)|92996|92996|239|0.2%|1.1%|
[snort_ipfilter](#snort_ipfilter)|9591|9591|164|1.7%|0.7%|
[stopforumspam_7d](#stopforumspam_7d)|30334|30334|162|0.5%|0.7%|
[sorbs_web](#sorbs_web)|680|682|149|21.8%|0.6%|
[ri_web_proxies](#ri_web_proxies)|6189|6189|90|1.4%|0.4%|
[stopforumspam_1d](#stopforumspam_1d)|7131|7131|72|1.0%|0.3%|
[php_dictionary](#php_dictionary)|433|433|72|16.6%|0.3%|
[xroxy](#xroxy)|2060|2060|66|3.2%|0.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|65|0.0%|0.3%|
[et_block](#et_block)|1007|18338646|65|0.0%|0.3%|
[spamhaus_drop](#spamhaus_drop)|654|18469632|64|0.0%|0.2%|
[php_spammers](#php_spammers)|417|417|52|12.4%|0.2%|
[blocklist_de_bots](#blocklist_de_bots)|3094|3094|47|1.5%|0.2%|
[proxz](#proxz)|712|712|32|4.4%|0.1%|
[alienvault_reputation](#alienvault_reputation)|178477|178477|30|0.0%|0.1%|
[blocklist_de_apache](#blocklist_de_apache)|13430|13430|26|0.1%|0.1%|
[ri_connect_proxies](#ri_connect_proxies)|2327|2327|25|1.0%|0.1%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2089|2089|24|1.1%|0.1%|
[blocklist_de_imap](#blocklist_de_imap)|2830|2830|21|0.7%|0.0%|
[proxyrss](#proxyrss)|1606|1606|19|1.1%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|12|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|8|0.0%|0.0%|
[php_commenters](#php_commenters)|281|281|7|2.4%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|13692|13692|6|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|5|1.9%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|872|872|5|0.5%|0.0%|
[sorbs_socks](#sorbs_socks)|23|23|3|13.0%|0.0%|
[sorbs_misc](#sorbs_misc)|23|23|3|13.0%|0.0%|
[sorbs_http](#sorbs_http)|23|23|3|13.0%|0.0%|
[openbl_60d](#openbl_60d)|7702|7702|2|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|2|0.2%|0.0%|
[et_tor](#et_tor)|6380|6380|2|0.0%|0.0%|
[dm_tor](#dm_tor)|6611|6611|2|0.0%|0.0%|
[bm_tor](#bm_tor)|6616|6616|2|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|179|179|2|1.1%|0.0%|
[zeus_badips](#zeus_badips)|234|234|1|0.4%|0.0%|
[zeus](#zeus)|269|269|1|0.3%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|486400|1|0.0%|0.0%|
[sorbs_smtp](#sorbs_smtp)|9|9|1|11.1%|0.0%|
[shunlist](#shunlist)|1273|1273|1|0.0%|0.0%|
[openbl_7d](#openbl_7d)|943|943|1|0.1%|0.0%|
[openbl_30d](#openbl_30d)|3260|3260|1|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|

## openbl_1d

[OpenBL.org](http://www.openbl.org/) last 24 hours IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.

Source is downloaded from [this link](http://www.openbl.org/lists/base_1days.txt).

The last time downloaded was found to be dated: Thu Jun  4 15:32:00 UTC 2015.

The ipset `openbl_1d` has **192** entries, **192** unique IPs.

The following table shows the overlaps of `openbl_1d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl_1d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl_1d`.
- ` this % ` is the percentage **of this ipset (`openbl_1d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[openbl_7d](#openbl_7d)|943|943|192|20.3%|100.0%|
[openbl_60d](#openbl_60d)|7702|7702|192|2.4%|100.0%|
[openbl_30d](#openbl_30d)|3260|3260|192|5.8%|100.0%|
[alienvault_reputation](#alienvault_reputation)|178477|178477|180|0.1%|93.7%|
[blocklist_de](#blocklist_de)|37184|37184|157|0.4%|81.7%|
[blocklist_de_ssh](#blocklist_de_ssh)|13692|13692|154|1.1%|80.2%|
[bruteforceblocker](#bruteforceblocker)|2051|2051|90|4.3%|46.8%|
[et_compromised](#et_compromised)|2171|2171|84|3.8%|43.7%|
[shunlist](#shunlist)|1273|1273|73|5.7%|38.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|21|0.0%|10.9%|
[blocklist_de_strongips](#blocklist_de_strongips)|179|179|21|11.7%|10.9%|
[dshield](#dshield)|20|5120|11|0.2%|5.7%|
[spamhaus_drop](#spamhaus_drop)|654|18469632|7|0.0%|3.6%|
[et_block](#et_block)|1007|18338646|7|0.0%|3.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|5|0.0%|2.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|3|0.0%|1.5%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|1.5%|
[blocklist_de_mail](#blocklist_de_mail)|17091|17091|3|0.0%|1.5%|
[blocklist_de_imap](#blocklist_de_imap)|2830|2830|3|0.1%|1.5%|

## openbl_30d

[OpenBL.org](http://www.openbl.org/) last 30 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.

Source is downloaded from [this link](http://www.openbl.org/lists/base_30days.txt).

The last time downloaded was found to be dated: Thu Jun  4 15:42:00 UTC 2015.

The ipset `openbl_30d` has **3260** entries, **3260** unique IPs.

The following table shows the overlaps of `openbl_30d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl_30d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl_30d`.
- ` this % ` is the percentage **of this ipset (`openbl_30d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[openbl_60d](#openbl_60d)|7702|7702|3260|42.3%|100.0%|
[alienvault_reputation](#alienvault_reputation)|178477|178477|3234|1.8%|99.2%|
[et_compromised](#et_compromised)|2171|2171|1217|56.0%|37.3%|
[bruteforceblocker](#bruteforceblocker)|2051|2051|1181|57.5%|36.2%|
[openbl_7d](#openbl_7d)|943|943|943|100.0%|28.9%|
[blocklist_de](#blocklist_de)|37184|37184|891|2.3%|27.3%|
[blocklist_de_ssh](#blocklist_de_ssh)|13692|13692|845|6.1%|25.9%|
[shunlist](#shunlist)|1273|1273|579|45.4%|17.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|311|0.0%|9.5%|
[openbl_1d](#openbl_1d)|192|192|192|100.0%|5.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|169|0.0%|5.1%|
[et_block](#et_block)|1007|18338646|163|0.0%|5.0%|
[spamhaus_drop](#spamhaus_drop)|654|18469632|159|0.0%|4.8%|
[dshield](#dshield)|20|5120|115|2.2%|3.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|71|0.0%|2.1%|
[blocklist_de_mail](#blocklist_de_mail)|17091|17091|41|0.2%|1.2%|
[blocklist_de_imap](#blocklist_de_imap)|2830|2830|36|1.2%|1.1%|
[blocklist_de_strongips](#blocklist_de_strongips)|179|179|23|12.8%|0.7%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|13|0.0%|0.3%|
[snort_ipfilter](#snort_ipfilter)|9591|9591|8|0.0%|0.2%|
[stopforumspam_30d](#stopforumspam_30d)|92996|92996|4|0.0%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|4|0.0%|0.1%|
[voipbl](#voipbl)|10426|10837|3|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13430|13430|3|0.0%|0.0%|
[zeus](#zeus)|269|269|2|0.7%|0.0%|
[sorbs_spam](#sorbs_spam)|23635|24447|2|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|18771|19329|2|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|18771|19329|2|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.0%|
[zeus_badips](#zeus_badips)|234|234|1|0.4%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|30334|30334|1|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7131|7131|1|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|486400|1|0.0%|0.0%|
[nixspam](#nixspam)|21627|21627|1|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3094|3094|1|0.0%|0.0%|

## openbl_60d

[OpenBL.org](http://www.openbl.org/) last 60 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.

Source is downloaded from [this link](http://www.openbl.org/lists/base_60days.txt).

The last time downloaded was found to be dated: Thu Jun  4 15:42:00 UTC 2015.

The ipset `openbl_60d` has **7702** entries, **7702** unique IPs.

The following table shows the overlaps of `openbl_60d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl_60d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl_60d`.
- ` this % ` is the percentage **of this ipset (`openbl_60d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[alienvault_reputation](#alienvault_reputation)|178477|178477|7670|4.2%|99.5%|
[openbl_30d](#openbl_30d)|3260|3260|3260|100.0%|42.3%|
[blocklist_de](#blocklist_de)|37184|37184|1865|5.0%|24.2%|
[blocklist_de_ssh](#blocklist_de_ssh)|13692|13692|1813|13.2%|23.5%|
[et_compromised](#et_compromised)|2171|2171|1310|60.3%|17.0%|
[bruteforceblocker](#bruteforceblocker)|2051|2051|1239|60.4%|16.0%|
[openbl_7d](#openbl_7d)|943|943|943|100.0%|12.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|749|0.0%|9.7%|
[shunlist](#shunlist)|1273|1273|594|46.6%|7.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|339|0.0%|4.4%|
[et_block](#et_block)|1007|18338646|244|0.0%|3.1%|
[spamhaus_drop](#spamhaus_drop)|654|18469632|239|0.0%|3.1%|
[openbl_1d](#openbl_1d)|192|192|192|100.0%|2.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|172|0.0%|2.2%|
[dshield](#dshield)|20|5120|123|2.4%|1.5%|
[stopforumspam_30d](#stopforumspam_30d)|92996|92996|56|0.0%|0.7%|
[blocklist_de_mail](#blocklist_de_mail)|17091|17091|45|0.2%|0.5%|
[blocklist_de_imap](#blocklist_de_imap)|2830|2830|40|1.4%|0.5%|
[snort_ipfilter](#snort_ipfilter)|9591|9591|31|0.3%|0.4%|
[stopforumspam_7d](#stopforumspam_7d)|30334|30334|25|0.0%|0.3%|
[blocklist_de_strongips](#blocklist_de_strongips)|179|179|25|13.9%|0.3%|
[stopforumspam_1d](#stopforumspam_1d)|7131|7131|22|0.3%|0.2%|
[et_tor](#et_tor)|6380|6380|21|0.3%|0.2%|
[dm_tor](#dm_tor)|6611|6611|21|0.3%|0.2%|
[bm_tor](#bm_tor)|6616|6616|21|0.3%|0.2%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|18|4.8%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|18|0.0%|0.2%|
[sorbs_spam](#sorbs_spam)|23635|24447|14|0.0%|0.1%|
[sorbs_recent_spam](#sorbs_recent_spam)|18771|19329|13|0.0%|0.1%|
[sorbs_new_spam](#sorbs_new_spam)|18771|19329|13|0.0%|0.1%|
[voipbl](#voipbl)|10426|10837|8|0.0%|0.1%|
[php_commenters](#php_commenters)|281|281|8|2.8%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|5|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13430|13430|5|0.0%|0.0%|
[zeus](#zeus)|269|269|2|0.7%|0.0%|
[php_harvesters](#php_harvesters)|257|257|2|0.7%|0.0%|
[nixspam](#nixspam)|21627|21627|2|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.0%|
[zeus_badips](#zeus_badips)|234|234|1|0.4%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|486400|1|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3094|3094|1|0.0%|0.0%|

## openbl_7d

[OpenBL.org](http://www.openbl.org/) last 7 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.

Source is downloaded from [this link](http://www.openbl.org/lists/base_7days.txt).

The last time downloaded was found to be dated: Thu Jun  4 15:42:00 UTC 2015.

The ipset `openbl_7d` has **943** entries, **943** unique IPs.

The following table shows the overlaps of `openbl_7d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl_7d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl_7d`.
- ` this % ` is the percentage **of this ipset (`openbl_7d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[openbl_60d](#openbl_60d)|7702|7702|943|12.2%|100.0%|
[openbl_30d](#openbl_30d)|3260|3260|943|28.9%|100.0%|
[alienvault_reputation](#alienvault_reputation)|178477|178477|926|0.5%|98.1%|
[blocklist_de](#blocklist_de)|37184|37184|599|1.6%|63.5%|
[blocklist_de_ssh](#blocklist_de_ssh)|13692|13692|582|4.2%|61.7%|
[bruteforceblocker](#bruteforceblocker)|2051|2051|426|20.7%|45.1%|
[et_compromised](#et_compromised)|2171|2171|416|19.1%|44.1%|
[shunlist](#shunlist)|1273|1273|313|24.5%|33.1%|
[openbl_1d](#openbl_1d)|192|192|192|100.0%|20.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|114|0.0%|12.0%|
[spamhaus_drop](#spamhaus_drop)|654|18469632|58|0.0%|6.1%|
[et_block](#et_block)|1007|18338646|58|0.0%|6.1%|
[dshield](#dshield)|20|5120|57|1.1%|6.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|47|0.0%|4.9%|
[blocklist_de_strongips](#blocklist_de_strongips)|179|179|23|12.8%|2.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|20|0.0%|2.1%|
[blocklist_de_mail](#blocklist_de_mail)|17091|17091|15|0.0%|1.5%|
[blocklist_de_imap](#blocklist_de_imap)|2830|2830|13|0.4%|1.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|7|0.0%|0.7%|
[stopforumspam_30d](#stopforumspam_30d)|92996|92996|3|0.0%|0.3%|
[snort_ipfilter](#snort_ipfilter)|9591|9591|3|0.0%|0.3%|
[voipbl](#voipbl)|10426|10837|1|0.0%|0.1%|
[sorbs_spam](#sorbs_spam)|23635|24447|1|0.0%|0.1%|
[sorbs_recent_spam](#sorbs_recent_spam)|18771|19329|1|0.0%|0.1%|
[sorbs_new_spam](#sorbs_new_spam)|18771|19329|1|0.0%|0.1%|
[nixspam](#nixspam)|21627|21627|1|0.0%|0.1%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.1%|
[blocklist_de_apache](#blocklist_de_apache)|13430|13430|1|0.0%|0.1%|

## palevo

[Abuse.ch Palevo tracker](https://palevotracker.abuse.ch) worm includes IPs which are being used as botnet C&C for the Palevo crimeware - **excellent list**

Source is downloaded from [this link](https://palevotracker.abuse.ch/blocklists.php?download=ipblocklist).

The last time downloaded was found to be dated: Thu Jun  4 15:27:15 UTC 2015.

The ipset `palevo` has **13** entries, **13** unique IPs.

The following table shows the overlaps of `palevo` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `palevo`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `palevo`.
- ` this % ` is the percentage **of this ipset (`palevo`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[et_block](#et_block)|1007|18338646|12|0.0%|92.3%|
[snort_ipfilter](#snort_ipfilter)|9591|9591|11|0.1%|84.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|3|0.0%|23.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|2|0.0%|15.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|1|0.0%|7.6%|

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
[stopforumspam_30d](#stopforumspam_30d)|92996|92996|206|0.2%|73.3%|
[stopforumspam_7d](#stopforumspam_7d)|30334|30334|145|0.4%|51.6%|
[stopforumspam_1d](#stopforumspam_1d)|7131|7131|109|1.5%|38.7%|
[blocklist_de](#blocklist_de)|37184|37184|67|0.1%|23.8%|
[blocklist_de_bots](#blocklist_de_bots)|3094|3094|52|1.6%|18.5%|
[snort_ipfilter](#snort_ipfilter)|9591|9591|38|0.3%|13.5%|
[php_spammers](#php_spammers)|417|417|32|7.6%|11.3%|
[blocklist_de_strongips](#blocklist_de_strongips)|179|179|32|17.8%|11.3%|
[et_tor](#et_tor)|6380|6380|29|0.4%|10.3%|
[dm_tor](#dm_tor)|6611|6611|29|0.4%|10.3%|
[bm_tor](#bm_tor)|6616|6616|29|0.4%|10.3%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|28|7.5%|9.9%|
[spamhaus_drop](#spamhaus_drop)|654|18469632|25|0.0%|8.8%|
[et_block](#et_block)|1007|18338646|25|0.0%|8.8%|
[blocklist_de_apache](#blocklist_de_apache)|13430|13430|24|0.1%|8.5%|
[php_dictionary](#php_dictionary)|433|433|22|5.0%|7.8%|
[blocklist_de_mail](#blocklist_de_mail)|17091|17091|21|0.1%|7.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|15|0.0%|5.3%|
[alienvault_reputation](#alienvault_reputation)|178477|178477|14|0.0%|4.9%|
[ri_web_proxies](#ri_web_proxies)|6189|6189|12|0.1%|4.2%|
[sorbs_spam](#sorbs_spam)|23635|24447|11|0.0%|3.9%|
[sorbs_recent_spam](#sorbs_recent_spam)|18771|19329|10|0.0%|3.5%|
[sorbs_new_spam](#sorbs_new_spam)|18771|19329|10|0.0%|3.5%|
[php_harvesters](#php_harvesters)|257|257|9|3.5%|3.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|9|0.0%|3.2%|
[openbl_60d](#openbl_60d)|7702|7702|8|0.1%|2.8%|
[spamhaus_edrop](#spamhaus_edrop)|55|486400|7|0.0%|2.4%|
[nixspam](#nixspam)|21627|21627|7|0.0%|2.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|5|0.0%|1.7%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2089|2089|5|0.2%|1.7%|
[proxz](#proxz)|712|712|4|0.5%|1.4%|
[xroxy](#xroxy)|2060|2060|3|0.1%|1.0%|
[sorbs_web](#sorbs_web)|680|682|2|0.2%|0.7%|
[zeus_badips](#zeus_badips)|234|234|1|0.4%|0.3%|
[zeus](#zeus)|269|269|1|0.3%|0.3%|
[proxyrss](#proxyrss)|1606|1606|1|0.0%|0.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.3%|
[dshield](#dshield)|20|5120|1|0.0%|0.3%|

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
[sorbs_spam](#sorbs_spam)|23635|24447|90|0.3%|20.7%|
[stopforumspam_30d](#stopforumspam_30d)|92996|92996|85|0.0%|19.6%|
[php_spammers](#php_spammers)|417|417|84|20.1%|19.3%|
[sorbs_recent_spam](#sorbs_recent_spam)|18771|19329|83|0.4%|19.1%|
[sorbs_new_spam](#sorbs_new_spam)|18771|19329|83|0.4%|19.1%|
[nixspam](#nixspam)|21627|21627|72|0.3%|16.6%|
[stopforumspam_7d](#stopforumspam_7d)|30334|30334|57|0.1%|13.1%|
[blocklist_de](#blocklist_de)|37184|37184|56|0.1%|12.9%|
[snort_ipfilter](#snort_ipfilter)|9591|9591|53|0.5%|12.2%|
[blocklist_de_mail](#blocklist_de_mail)|17091|17091|45|0.2%|10.3%|
[ri_web_proxies](#ri_web_proxies)|6189|6189|33|0.5%|7.6%|
[sorbs_web](#sorbs_web)|680|682|27|3.9%|6.2%|
[xroxy](#xroxy)|2060|2060|24|1.1%|5.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|24|0.0%|5.5%|
[stopforumspam_1d](#stopforumspam_1d)|7131|7131|23|0.3%|5.3%|
[php_commenters](#php_commenters)|281|281|22|7.8%|5.0%|
[proxz](#proxz)|712|712|10|1.4%|2.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|10|0.0%|2.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|9|0.0%|2.0%|
[blocklist_de_bots](#blocklist_de_bots)|3094|3094|8|0.2%|1.8%|
[alienvault_reputation](#alienvault_reputation)|178477|178477|6|0.0%|1.3%|
[spamhaus_drop](#spamhaus_drop)|654|18469632|4|0.0%|0.9%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|4|1.0%|0.9%|
[et_tor](#et_tor)|6380|6380|4|0.0%|0.9%|
[et_block](#et_block)|1007|18338646|4|0.0%|0.9%|
[dm_tor](#dm_tor)|6611|6611|4|0.0%|0.9%|
[bm_tor](#bm_tor)|6616|6616|4|0.0%|0.9%|
[ri_connect_proxies](#ri_connect_proxies)|2327|2327|3|0.1%|0.6%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2089|2089|3|0.1%|0.6%|
[blocklist_de_apache](#blocklist_de_apache)|13430|13430|3|0.0%|0.6%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2|0.0%|0.4%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|2|0.0%|0.4%|
[blocklist_de_strongips](#blocklist_de_strongips)|179|179|2|1.1%|0.4%|
[proxyrss](#proxyrss)|1606|1606|1|0.0%|0.2%|
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
[stopforumspam_30d](#stopforumspam_30d)|92996|92996|64|0.0%|24.9%|
[stopforumspam_7d](#stopforumspam_7d)|30334|30334|50|0.1%|19.4%|
[stopforumspam_1d](#stopforumspam_1d)|7131|7131|35|0.4%|13.6%|
[blocklist_de](#blocklist_de)|37184|37184|27|0.0%|10.5%|
[blocklist_de_bots](#blocklist_de_bots)|3094|3094|18|0.5%|7.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|15|0.0%|5.8%|
[snort_ipfilter](#snort_ipfilter)|9591|9591|9|0.0%|3.5%|
[php_commenters](#php_commenters)|281|281|9|3.2%|3.5%|
[alienvault_reputation](#alienvault_reputation)|178477|178477|8|0.0%|3.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|7|0.0%|2.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|7|0.0%|2.7%|
[et_tor](#et_tor)|6380|6380|7|0.1%|2.7%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|6|1.6%|2.3%|
[dm_tor](#dm_tor)|6611|6611|6|0.0%|2.3%|
[bm_tor](#bm_tor)|6616|6616|6|0.0%|2.3%|
[sorbs_spam](#sorbs_spam)|23635|24447|5|0.0%|1.9%|
[nixspam](#nixspam)|21627|21627|5|0.0%|1.9%|
[sorbs_recent_spam](#sorbs_recent_spam)|18771|19329|4|0.0%|1.5%|
[sorbs_new_spam](#sorbs_new_spam)|18771|19329|4|0.0%|1.5%|
[blocklist_de_mail](#blocklist_de_mail)|17091|17091|4|0.0%|1.5%|
[blocklist_de_apache](#blocklist_de_apache)|13430|13430|4|0.0%|1.5%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2089|2089|3|0.1%|1.1%|
[xroxy](#xroxy)|2060|2060|2|0.0%|0.7%|
[proxyrss](#proxyrss)|1606|1606|2|0.1%|0.7%|
[openbl_60d](#openbl_60d)|7702|7702|2|0.0%|0.7%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|2|0.0%|0.7%|
[blocklist_de_strongips](#blocklist_de_strongips)|179|179|2|1.1%|0.7%|
[blocklist_de_ftp](#blocklist_de_ftp)|872|872|2|0.2%|0.7%|
[spamhaus_edrop](#spamhaus_edrop)|55|486400|1|0.0%|0.3%|
[spamhaus_drop](#spamhaus_drop)|654|18469632|1|0.0%|0.3%|
[ri_web_proxies](#ri_web_proxies)|6189|6189|1|0.0%|0.3%|
[php_spammers](#php_spammers)|417|417|1|0.2%|0.3%|
[php_dictionary](#php_dictionary)|433|433|1|0.2%|0.3%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.3%|
[fullbogons](#fullbogons)|3733|670419608|1|0.0%|0.3%|
[et_block](#et_block)|1007|18338646|1|0.0%|0.3%|
[dshield](#dshield)|20|5120|1|0.0%|0.3%|
[bogons](#bogons)|13|592708608|1|0.0%|0.3%|

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
[stopforumspam_30d](#stopforumspam_30d)|92996|92996|100|0.1%|23.9%|
[php_dictionary](#php_dictionary)|433|433|84|19.3%|20.1%|
[sorbs_spam](#sorbs_spam)|23635|24447|83|0.3%|19.9%|
[sorbs_recent_spam](#sorbs_recent_spam)|18771|19329|74|0.3%|17.7%|
[sorbs_new_spam](#sorbs_new_spam)|18771|19329|74|0.3%|17.7%|
[stopforumspam_7d](#stopforumspam_7d)|30334|30334|57|0.1%|13.6%|
[snort_ipfilter](#snort_ipfilter)|9591|9591|54|0.5%|12.9%|
[blocklist_de](#blocklist_de)|37184|37184|54|0.1%|12.9%|
[nixspam](#nixspam)|21627|21627|52|0.2%|12.4%|
[blocklist_de_mail](#blocklist_de_mail)|17091|17091|39|0.2%|9.3%|
[php_commenters](#php_commenters)|281|281|32|11.3%|7.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|31|0.0%|7.4%|
[stopforumspam_1d](#stopforumspam_1d)|7131|7131|30|0.4%|7.1%|
[ri_web_proxies](#ri_web_proxies)|6189|6189|26|0.4%|6.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|26|0.0%|6.2%|
[sorbs_web](#sorbs_web)|680|682|22|3.2%|5.2%|
[xroxy](#xroxy)|2060|2060|20|0.9%|4.7%|
[proxz](#proxz)|712|712|9|1.2%|2.1%|
[blocklist_de_bots](#blocklist_de_bots)|3094|3094|8|0.2%|1.9%|
[et_tor](#et_tor)|6380|6380|6|0.0%|1.4%|
[dm_tor](#dm_tor)|6611|6611|6|0.0%|1.4%|
[bm_tor](#bm_tor)|6616|6616|6|0.0%|1.4%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2089|2089|6|0.2%|1.4%|
[blocklist_de_apache](#blocklist_de_apache)|13430|13430|6|0.0%|1.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|5|0.0%|1.1%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|4|1.0%|0.9%|
[blocklist_de_strongips](#blocklist_de_strongips)|179|179|4|2.2%|0.9%|
[spamhaus_drop](#spamhaus_drop)|654|18469632|3|0.0%|0.7%|
[alienvault_reputation](#alienvault_reputation)|178477|178477|3|0.0%|0.7%|
[ri_connect_proxies](#ri_connect_proxies)|2327|2327|2|0.0%|0.4%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2|0.0%|0.4%|
[et_block](#et_block)|1007|18338646|2|0.0%|0.4%|
[proxyrss](#proxyrss)|1606|1606|1|0.0%|0.2%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.2%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1|0.0%|0.2%|
[blocklist_de_ftp](#blocklist_de_ftp)|872|872|1|0.1%|0.2%|

## proxyrss

[proxyrss.com](http://www.proxyrss.com) open proxies syndicated from multiple sources.

Source is downloaded from [this link](http://www.proxyrss.com/proxylists/all.gz).

The last time downloaded was found to be dated: Thu Jun  4 12:11:35 UTC 2015.

The ipset `proxyrss` has **1606** entries, **1606** unique IPs.

The following table shows the overlaps of `proxyrss` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `proxyrss`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `proxyrss`.
- ` this % ` is the percentage **of this ipset (`proxyrss`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_30d](#stopforumspam_30d)|92996|92996|837|0.9%|52.1%|
[ri_web_proxies](#ri_web_proxies)|6189|6189|702|11.3%|43.7%|
[stopforumspam_7d](#stopforumspam_7d)|30334|30334|692|2.2%|43.0%|
[xroxy](#xroxy)|2060|2060|463|22.4%|28.8%|
[stopforumspam_1d](#stopforumspam_1d)|7131|7131|414|5.8%|25.7%|
[ri_connect_proxies](#ri_connect_proxies)|2327|2327|281|12.0%|17.4%|
[blocklist_de_bots](#blocklist_de_bots)|3094|3094|258|8.3%|16.0%|
[blocklist_de](#blocklist_de)|37184|37184|258|0.6%|16.0%|
[proxz](#proxz)|712|712|209|29.3%|13.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|66|0.0%|4.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|58|0.0%|3.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|49|0.0%|3.0%|
[nixspam](#nixspam)|21627|21627|19|0.0%|1.1%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|13|1.9%|0.8%|
[sorbs_spam](#sorbs_spam)|23635|24447|5|0.0%|0.3%|
[sorbs_recent_spam](#sorbs_recent_spam)|18771|19329|5|0.0%|0.3%|
[sorbs_new_spam](#sorbs_new_spam)|18771|19329|5|0.0%|0.3%|
[snort_ipfilter](#snort_ipfilter)|9591|9591|4|0.0%|0.2%|
[blocklist_de_strongips](#blocklist_de_strongips)|179|179|4|2.2%|0.2%|
[php_harvesters](#php_harvesters)|257|257|2|0.7%|0.1%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|2|0.0%|0.1%|
[alienvault_reputation](#alienvault_reputation)|178477|178477|2|0.0%|0.1%|
[sorbs_socks](#sorbs_socks)|23|23|1|4.3%|0.0%|
[sorbs_misc](#sorbs_misc)|23|23|1|4.3%|0.0%|
[sorbs_http](#sorbs_http)|23|23|1|4.3%|0.0%|
[php_spammers](#php_spammers)|417|417|1|0.2%|0.0%|
[php_dictionary](#php_dictionary)|433|433|1|0.2%|0.0%|
[php_commenters](#php_commenters)|281|281|1|0.3%|0.0%|
[et_compromised](#et_compromised)|2171|2171|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2051|2051|1|0.0%|0.0%|

## proxz

[proxz.com](http://www.proxz.com) open proxies (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.proxz.com/proxylists.xml).

The last time downloaded was found to be dated: Thu Jun  4 14:41:33 UTC 2015.

The ipset `proxz` has **712** entries, **712** unique IPs.

The following table shows the overlaps of `proxz` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `proxz`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `proxz`.
- ` this % ` is the percentage **of this ipset (`proxz`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_30d](#stopforumspam_30d)|92996|92996|428|0.4%|60.1%|
[stopforumspam_7d](#stopforumspam_7d)|30334|30334|356|1.1%|50.0%|
[ri_web_proxies](#ri_web_proxies)|6189|6189|315|5.0%|44.2%|
[xroxy](#xroxy)|2060|2060|300|14.5%|42.1%|
[proxyrss](#proxyrss)|1606|1606|209|13.0%|29.3%|
[blocklist_de](#blocklist_de)|37184|37184|133|0.3%|18.6%|
[stopforumspam_1d](#stopforumspam_1d)|7131|7131|131|1.8%|18.3%|
[ri_connect_proxies](#ri_connect_proxies)|2327|2327|119|5.1%|16.7%|
[blocklist_de_bots](#blocklist_de_bots)|3094|3094|111|3.5%|15.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|60|0.0%|8.4%|
[nixspam](#nixspam)|21627|21627|32|0.1%|4.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|31|0.0%|4.3%|
[sorbs_spam](#sorbs_spam)|23635|24447|30|0.1%|4.2%|
[sorbs_recent_spam](#sorbs_recent_spam)|18771|19329|30|0.1%|4.2%|
[sorbs_new_spam](#sorbs_new_spam)|18771|19329|30|0.1%|4.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|27|0.0%|3.7%|
[snort_ipfilter](#snort_ipfilter)|9591|9591|21|0.2%|2.9%|
[blocklist_de_mail](#blocklist_de_mail)|17091|17091|21|0.1%|2.9%|
[sorbs_web](#sorbs_web)|680|682|11|1.6%|1.5%|
[php_dictionary](#php_dictionary)|433|433|10|2.3%|1.4%|
[php_spammers](#php_spammers)|417|417|9|2.1%|1.2%|
[php_commenters](#php_commenters)|281|281|4|1.4%|0.5%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|4|0.5%|0.5%|
[blocklist_de_strongips](#blocklist_de_strongips)|179|179|3|1.6%|0.4%|
[alienvault_reputation](#alienvault_reputation)|178477|178477|3|0.0%|0.4%|
[et_compromised](#et_compromised)|2171|2171|2|0.0%|0.2%|
[bruteforceblocker](#bruteforceblocker)|2051|2051|2|0.0%|0.2%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1|0.0%|0.1%|
[blocklist_de_ssh](#blocklist_de_ssh)|13692|13692|1|0.0%|0.1%|

## ri_connect_proxies

[rosinstrument.com](http://www.rosinstrument.com) open CONNECT proxies (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://tools.rosinstrument.com/proxy/plab100.xml).

The last time downloaded was found to be dated: Thu Jun  4 14:25:06 UTC 2015.

The ipset `ri_connect_proxies` has **2327** entries, **2327** unique IPs.

The following table shows the overlaps of `ri_connect_proxies` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ri_connect_proxies`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ri_connect_proxies`.
- ` this % ` is the percentage **of this ipset (`ri_connect_proxies`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_30d](#stopforumspam_30d)|92996|92996|1349|1.4%|57.9%|
[ri_web_proxies](#ri_web_proxies)|6189|6189|948|15.3%|40.7%|
[stopforumspam_7d](#stopforumspam_7d)|30334|30334|687|2.2%|29.5%|
[xroxy](#xroxy)|2060|2060|351|17.0%|15.0%|
[proxyrss](#proxyrss)|1606|1606|281|17.4%|12.0%|
[stopforumspam_1d](#stopforumspam_1d)|7131|7131|165|2.3%|7.0%|
[proxz](#proxz)|712|712|119|16.7%|5.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|91|0.0%|3.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|74|0.0%|3.1%|
[blocklist_de](#blocklist_de)|37184|37184|71|0.1%|3.0%|
[blocklist_de_bots](#blocklist_de_bots)|3094|3094|68|2.1%|2.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|50|0.0%|2.1%|
[nixspam](#nixspam)|21627|21627|25|0.1%|1.0%|
[sorbs_spam](#sorbs_spam)|23635|24447|9|0.0%|0.3%|
[sorbs_recent_spam](#sorbs_recent_spam)|18771|19329|8|0.0%|0.3%|
[sorbs_new_spam](#sorbs_new_spam)|18771|19329|8|0.0%|0.3%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|6|0.8%|0.2%|
[snort_ipfilter](#snort_ipfilter)|9591|9591|5|0.0%|0.2%|
[php_dictionary](#php_dictionary)|433|433|3|0.6%|0.1%|
[sorbs_web](#sorbs_web)|680|682|2|0.2%|0.0%|
[php_spammers](#php_spammers)|417|417|2|0.4%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|17091|17091|2|0.0%|0.0%|
[alienvault_reputation](#alienvault_reputation)|178477|178477|2|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.0%|
[et_tor](#et_tor)|6380|6380|1|0.0%|0.0%|
[dm_tor](#dm_tor)|6611|6611|1|0.0%|0.0%|
[bm_tor](#bm_tor)|6616|6616|1|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|13692|13692|1|0.0%|0.0%|

## ri_web_proxies

[rosinstrument.com](http://www.rosinstrument.com) open HTTP proxies (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://tools.rosinstrument.com/proxy/l100.xml).

The last time downloaded was found to be dated: Thu Jun  4 14:25:01 UTC 2015.

The ipset `ri_web_proxies` has **6189** entries, **6189** unique IPs.

The following table shows the overlaps of `ri_web_proxies` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ri_web_proxies`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ri_web_proxies`.
- ` this % ` is the percentage **of this ipset (`ri_web_proxies`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_30d](#stopforumspam_30d)|92996|92996|2991|3.2%|48.3%|
[stopforumspam_7d](#stopforumspam_7d)|30334|30334|1664|5.4%|26.8%|
[ri_connect_proxies](#ri_connect_proxies)|2327|2327|948|40.7%|15.3%|
[xroxy](#xroxy)|2060|2060|871|42.2%|14.0%|
[proxyrss](#proxyrss)|1606|1606|702|43.7%|11.3%|
[stopforumspam_1d](#stopforumspam_1d)|7131|7131|507|7.1%|8.1%|
[blocklist_de](#blocklist_de)|37184|37184|402|1.0%|6.4%|
[blocklist_de_bots](#blocklist_de_bots)|3094|3094|351|11.3%|5.6%|
[proxz](#proxz)|712|712|315|44.2%|5.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|184|0.0%|2.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|173|0.0%|2.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|130|0.0%|2.1%|
[sorbs_spam](#sorbs_spam)|23635|24447|111|0.4%|1.7%|
[sorbs_recent_spam](#sorbs_recent_spam)|18771|19329|105|0.5%|1.6%|
[sorbs_new_spam](#sorbs_new_spam)|18771|19329|105|0.5%|1.6%|
[nixspam](#nixspam)|21627|21627|90|0.4%|1.4%|
[snort_ipfilter](#snort_ipfilter)|9591|9591|62|0.6%|1.0%|
[blocklist_de_mail](#blocklist_de_mail)|17091|17091|51|0.2%|0.8%|
[php_dictionary](#php_dictionary)|433|433|33|7.6%|0.5%|
[sorbs_web](#sorbs_web)|680|682|27|3.9%|0.4%|
[php_spammers](#php_spammers)|417|417|26|6.2%|0.4%|
[php_commenters](#php_commenters)|281|281|12|4.2%|0.1%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|12|1.7%|0.1%|
[blocklist_de_strongips](#blocklist_de_strongips)|179|179|6|3.3%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|5|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|4|1.0%|0.0%|
[et_tor](#et_tor)|6380|6380|4|0.0%|0.0%|
[dm_tor](#dm_tor)|6611|6611|4|0.0%|0.0%|
[bm_tor](#bm_tor)|6616|6616|4|0.0%|0.0%|
[alienvault_reputation](#alienvault_reputation)|178477|178477|3|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|2|0.0%|0.0%|
[sorbs_socks](#sorbs_socks)|23|23|1|4.3%|0.0%|
[sorbs_misc](#sorbs_misc)|23|23|1|4.3%|0.0%|
[sorbs_http](#sorbs_http)|23|23|1|4.3%|0.0%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|
[et_compromised](#et_compromised)|2171|2171|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2051|2051|1|0.0%|0.0%|

## shunlist

[AutoShun.org](http://autoshun.org/) IPs identified as hostile by correlating logs from distributed snort installations running the autoshun plugin

Source is downloaded from [this link](http://www.autoshun.org/files/shunlist.csv).

The last time downloaded was found to be dated: Thu Jun  4 14:30:04 UTC 2015.

The ipset `shunlist` has **1273** entries, **1273** unique IPs.

The following table shows the overlaps of `shunlist` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `shunlist`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `shunlist`.
- ` this % ` is the percentage **of this ipset (`shunlist`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[alienvault_reputation](#alienvault_reputation)|178477|178477|1265|0.7%|99.3%|
[openbl_60d](#openbl_60d)|7702|7702|594|7.7%|46.6%|
[openbl_30d](#openbl_30d)|3260|3260|579|17.7%|45.4%|
[et_compromised](#et_compromised)|2171|2171|496|22.8%|38.9%|
[bruteforceblocker](#bruteforceblocker)|2051|2051|490|23.8%|38.4%|
[blocklist_de](#blocklist_de)|37184|37184|396|1.0%|31.1%|
[blocklist_de_ssh](#blocklist_de_ssh)|13692|13692|356|2.6%|27.9%|
[openbl_7d](#openbl_7d)|943|943|313|33.1%|24.5%|
[dshield](#dshield)|20|5120|112|2.1%|8.7%|
[et_block](#et_block)|1007|18338646|108|0.0%|8.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|104|0.0%|8.1%|
[spamhaus_drop](#spamhaus_drop)|654|18469632|99|0.0%|7.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|74|0.0%|5.8%|
[openbl_1d](#openbl_1d)|192|192|73|38.0%|5.7%|
[sslbl](#sslbl)|366|366|56|15.3%|4.3%|
[blocklist_de_apache](#blocklist_de_apache)|13430|13430|36|0.2%|2.8%|
[ciarmy](#ciarmy)|343|343|27|7.8%|2.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|26|0.0%|2.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|179|179|20|11.1%|1.5%|
[voipbl](#voipbl)|10426|10837|11|0.1%|0.8%|
[stopforumspam_30d](#stopforumspam_30d)|92996|92996|4|0.0%|0.3%|
[blocklist_de_mail](#blocklist_de_mail)|17091|17091|4|0.0%|0.3%|
[blocklist_de_imap](#blocklist_de_imap)|2830|2830|4|0.1%|0.3%|
[stopforumspam_7d](#stopforumspam_7d)|30334|30334|3|0.0%|0.2%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2089|2089|3|0.1%|0.2%|
[snort_ipfilter](#snort_ipfilter)|9591|9591|2|0.0%|0.1%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|2|0.5%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2|0.0%|0.1%|
[stopforumspam_1d](#stopforumspam_1d)|7131|7131|1|0.0%|0.0%|
[sorbs_spam](#sorbs_spam)|23635|24447|1|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|18771|19329|1|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|18771|19329|1|0.0%|0.0%|
[nixspam](#nixspam)|21627|21627|1|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.0%|
[et_tor](#et_tor)|6380|6380|1|0.0%|0.0%|
[dm_tor](#dm_tor)|6611|6611|1|0.0%|0.0%|
[bm_tor](#bm_tor)|6616|6616|1|0.0%|0.0%|

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
[bm_tor](#bm_tor)|6616|6616|1090|16.4%|11.3%|
[dm_tor](#dm_tor)|6611|6611|1089|16.4%|11.3%|
[et_tor](#et_tor)|6380|6380|1086|17.0%|11.3%|
[stopforumspam_30d](#stopforumspam_30d)|92996|92996|810|0.8%|8.4%|
[stopforumspam_7d](#stopforumspam_7d)|30334|30334|618|2.0%|6.4%|
[stopforumspam_1d](#stopforumspam_1d)|7131|7131|381|5.3%|3.9%|
[sorbs_spam](#sorbs_spam)|23635|24447|340|1.3%|3.5%|
[sorbs_recent_spam](#sorbs_recent_spam)|18771|19329|316|1.6%|3.2%|
[sorbs_new_spam](#sorbs_new_spam)|18771|19329|316|1.6%|3.2%|
[et_block](#et_block)|1007|18338646|305|0.0%|3.1%|
[zeus](#zeus)|269|269|228|84.7%|2.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|219|0.0%|2.2%|
[zeus_badips](#zeus_badips)|234|234|205|87.6%|2.1%|
[blocklist_de](#blocklist_de)|37184|37184|197|0.5%|2.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|177|47.5%|1.8%|
[blocklist_de_mail](#blocklist_de_mail)|17091|17091|169|0.9%|1.7%|
[nixspam](#nixspam)|21627|21627|164|0.7%|1.7%|
[alienvault_reputation](#alienvault_reputation)|178477|178477|124|0.0%|1.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|100|0.0%|1.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|98|0.0%|1.0%|
[feodo](#feodo)|93|93|68|73.1%|0.7%|
[ri_web_proxies](#ri_web_proxies)|6189|6189|62|1.0%|0.6%|
[sorbs_web](#sorbs_web)|680|682|56|8.2%|0.5%|
[php_spammers](#php_spammers)|417|417|54|12.9%|0.5%|
[php_dictionary](#php_dictionary)|433|433|53|12.2%|0.5%|
[xroxy](#xroxy)|2060|2060|50|2.4%|0.5%|
[php_commenters](#php_commenters)|281|281|38|13.5%|0.3%|
[openbl_60d](#openbl_60d)|7702|7702|31|0.4%|0.3%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|29|2.2%|0.3%|
[sslbl](#sslbl)|366|366|28|7.6%|0.2%|
[blocklist_de_bots](#blocklist_de_bots)|3094|3094|23|0.7%|0.2%|
[proxz](#proxz)|712|712|21|2.9%|0.2%|
[spamhaus_drop](#spamhaus_drop)|654|18469632|20|0.0%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|14|0.0%|0.1%|
[palevo](#palevo)|13|13|11|84.6%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|11|0.0%|0.1%|
[php_harvesters](#php_harvesters)|257|257|9|3.5%|0.0%|
[openbl_30d](#openbl_30d)|3260|3260|8|0.2%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13430|13430|8|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2830|2830|7|0.2%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|486400|6|0.0%|0.0%|
[sorbs_socks](#sorbs_socks)|23|23|6|26.0%|0.0%|
[sorbs_misc](#sorbs_misc)|23|23|6|26.0%|0.0%|
[sorbs_http](#sorbs_http)|23|23|6|26.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2327|2327|5|0.2%|0.0%|
[proxyrss](#proxyrss)|1606|1606|4|0.2%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2089|2089|4|0.1%|0.0%|
[openbl_7d](#openbl_7d)|943|943|3|0.3%|0.0%|
[shunlist](#shunlist)|1273|1273|2|0.1%|0.0%|
[voipbl](#voipbl)|10426|10837|1|0.0%|0.0%|
[malc0de](#malc0de)|379|379|1|0.2%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|1|0.1%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1|0.0%|0.0%|
[et_compromised](#et_compromised)|2171|2171|1|0.0%|0.0%|
[dshield](#dshield)|20|5120|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2051|2051|1|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|179|179|1|0.5%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|13692|13692|1|0.0%|0.0%|

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

The last time downloaded was found to be dated: Thu Jun  4 14:48:13 UTC 2015.

The ipset `sorbs_http` has **23** entries, **23** unique IPs.

The following table shows the overlaps of `sorbs_http` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `sorbs_http`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `sorbs_http`.
- ` this % ` is the percentage **of this ipset (`sorbs_http`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[sorbs_socks](#sorbs_socks)|23|23|23|100.0%|100.0%|
[sorbs_misc](#sorbs_misc)|23|23|23|100.0%|100.0%|
[sorbs_spam](#sorbs_spam)|23635|24447|17|0.0%|73.9%|
[sorbs_recent_spam](#sorbs_recent_spam)|18771|19329|12|0.0%|52.1%|
[sorbs_new_spam](#sorbs_new_spam)|18771|19329|12|0.0%|52.1%|
[snort_ipfilter](#snort_ipfilter)|9591|9591|6|0.0%|26.0%|
[sorbs_web](#sorbs_web)|680|682|5|0.7%|21.7%|
[blocklist_de](#blocklist_de)|37184|37184|5|0.0%|21.7%|
[nixspam](#nixspam)|21627|21627|3|0.0%|13.0%|
[blocklist_de_mail](#blocklist_de_mail)|17091|17091|3|0.0%|13.0%|
[stopforumspam_7d](#stopforumspam_7d)|30334|30334|2|0.0%|8.6%|
[stopforumspam_30d](#stopforumspam_30d)|92996|92996|2|0.0%|8.6%|
[stopforumspam_1d](#stopforumspam_1d)|7131|7131|2|0.0%|8.6%|
[blocklist_de_bots](#blocklist_de_bots)|3094|3094|2|0.0%|8.6%|
[xroxy](#xroxy)|2060|2060|1|0.0%|4.3%|
[ri_web_proxies](#ri_web_proxies)|6189|6189|1|0.0%|4.3%|
[proxyrss](#proxyrss)|1606|1606|1|0.0%|4.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|1|0.0%|4.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|1|0.0%|4.3%|

## sorbs_misc

[Sorbs.net](https://www.sorbs.net/) MISC proxies, extracted from deltas.

Source is downloaded from [this link]().

The last time downloaded was found to be dated: Thu Jun  4 14:48:13 UTC 2015.

The ipset `sorbs_misc` has **23** entries, **23** unique IPs.

The following table shows the overlaps of `sorbs_misc` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `sorbs_misc`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `sorbs_misc`.
- ` this % ` is the percentage **of this ipset (`sorbs_misc`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[sorbs_socks](#sorbs_socks)|23|23|23|100.0%|100.0%|
[sorbs_http](#sorbs_http)|23|23|23|100.0%|100.0%|
[sorbs_spam](#sorbs_spam)|23635|24447|17|0.0%|73.9%|
[sorbs_recent_spam](#sorbs_recent_spam)|18771|19329|12|0.0%|52.1%|
[sorbs_new_spam](#sorbs_new_spam)|18771|19329|12|0.0%|52.1%|
[snort_ipfilter](#snort_ipfilter)|9591|9591|6|0.0%|26.0%|
[sorbs_web](#sorbs_web)|680|682|5|0.7%|21.7%|
[blocklist_de](#blocklist_de)|37184|37184|5|0.0%|21.7%|
[nixspam](#nixspam)|21627|21627|3|0.0%|13.0%|
[blocklist_de_mail](#blocklist_de_mail)|17091|17091|3|0.0%|13.0%|
[stopforumspam_7d](#stopforumspam_7d)|30334|30334|2|0.0%|8.6%|
[stopforumspam_30d](#stopforumspam_30d)|92996|92996|2|0.0%|8.6%|
[stopforumspam_1d](#stopforumspam_1d)|7131|7131|2|0.0%|8.6%|
[blocklist_de_bots](#blocklist_de_bots)|3094|3094|2|0.0%|8.6%|
[xroxy](#xroxy)|2060|2060|1|0.0%|4.3%|
[ri_web_proxies](#ri_web_proxies)|6189|6189|1|0.0%|4.3%|
[proxyrss](#proxyrss)|1606|1606|1|0.0%|4.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|1|0.0%|4.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|1|0.0%|4.3%|

## sorbs_new_spam

[Sorbs.net](https://www.sorbs.net/) NEW Spam senders, extracted from deltas.

Source is downloaded from [this link]().

The last time downloaded was found to be dated: Thu Jun  4 15:04:14 UTC 2015.

The ipset `sorbs_new_spam` has **18771** entries, **19329** unique IPs.

The following table shows the overlaps of `sorbs_new_spam` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `sorbs_new_spam`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `sorbs_new_spam`.
- ` this % ` is the percentage **of this ipset (`sorbs_new_spam`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[sorbs_spam](#sorbs_spam)|23635|24447|19329|79.0%|100.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|18771|19329|19329|100.0%|100.0%|
[nixspam](#nixspam)|21627|21627|3853|17.8%|19.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|1361|0.0%|7.0%|
[blocklist_de](#blocklist_de)|37184|37184|976|2.6%|5.0%|
[blocklist_de_mail](#blocklist_de_mail)|17091|17091|819|4.7%|4.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|502|0.0%|2.5%|
[snort_ipfilter](#snort_ipfilter)|9591|9591|316|3.2%|1.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|294|0.0%|1.5%|
[sorbs_web](#sorbs_web)|680|682|262|38.4%|1.3%|
[stopforumspam_30d](#stopforumspam_30d)|92996|92996|255|0.2%|1.3%|
[stopforumspam_7d](#stopforumspam_7d)|30334|30334|151|0.4%|0.7%|
[ri_web_proxies](#ri_web_proxies)|6189|6189|105|1.6%|0.5%|
[php_dictionary](#php_dictionary)|433|433|83|19.1%|0.4%|
[xroxy](#xroxy)|2060|2060|75|3.6%|0.3%|
[php_spammers](#php_spammers)|417|417|74|17.7%|0.3%|
[blocklist_de_ssh](#blocklist_de_ssh)|13692|13692|73|0.5%|0.3%|
[stopforumspam_1d](#stopforumspam_1d)|7131|7131|59|0.8%|0.3%|
[alienvault_reputation](#alienvault_reputation)|178477|178477|53|0.0%|0.2%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2089|2089|49|2.3%|0.2%|
[blocklist_de_apache](#blocklist_de_apache)|13430|13430|49|0.3%|0.2%|
[blocklist_de_bots](#blocklist_de_bots)|3094|3094|32|1.0%|0.1%|
[proxz](#proxz)|712|712|30|4.2%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|23|0.0%|0.1%|
[blocklist_de_imap](#blocklist_de_imap)|2830|2830|20|0.7%|0.1%|
[openbl_60d](#openbl_60d)|7702|7702|13|0.1%|0.0%|
[sorbs_socks](#sorbs_socks)|23|23|12|52.1%|0.0%|
[sorbs_misc](#sorbs_misc)|23|23|12|52.1%|0.0%|
[sorbs_http](#sorbs_http)|23|23|12|52.1%|0.0%|
[php_commenters](#php_commenters)|281|281|10|3.5%|0.0%|
[sorbs_smtp](#sorbs_smtp)|9|9|8|88.8%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2327|2327|8|0.3%|0.0%|
[spamhaus_drop](#spamhaus_drop)|654|18469632|7|0.0%|0.0%|
[et_block](#et_block)|1007|18338646|7|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|6|0.0%|0.0%|
[proxyrss](#proxyrss)|1606|1606|5|0.3%|0.0%|
[php_harvesters](#php_harvesters)|257|257|4|1.5%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|486400|3|0.0%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|872|872|3|0.3%|0.0%|
[openbl_30d](#openbl_30d)|3260|3260|2|0.0%|0.0%|
[et_tor](#et_tor)|6380|6380|2|0.0%|0.0%|
[shunlist](#shunlist)|1273|1273|1|0.0%|0.0%|
[openbl_7d](#openbl_7d)|943|943|1|0.1%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|1|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|1|0.1%|0.0%|
[dshield](#dshield)|20|5120|1|0.0%|0.0%|
[dm_tor](#dm_tor)|6611|6611|1|0.0%|0.0%|
[bm_tor](#bm_tor)|6616|6616|1|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|179|179|1|0.5%|0.0%|

## sorbs_recent_spam

[Sorbs.net](https://www.sorbs.net/) RECENT Spam senders, extracted from deltas.

Source is downloaded from [this link]().

The last time downloaded was found to be dated: Thu Jun  4 15:04:14 UTC 2015.

The ipset `sorbs_recent_spam` has **18771** entries, **19329** unique IPs.

The following table shows the overlaps of `sorbs_recent_spam` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `sorbs_recent_spam`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `sorbs_recent_spam`.
- ` this % ` is the percentage **of this ipset (`sorbs_recent_spam`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[sorbs_spam](#sorbs_spam)|23635|24447|19329|79.0%|100.0%|
[sorbs_new_spam](#sorbs_new_spam)|18771|19329|19329|100.0%|100.0%|
[nixspam](#nixspam)|21627|21627|3853|17.8%|19.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|1361|0.0%|7.0%|
[blocklist_de](#blocklist_de)|37184|37184|976|2.6%|5.0%|
[blocklist_de_mail](#blocklist_de_mail)|17091|17091|819|4.7%|4.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|502|0.0%|2.5%|
[snort_ipfilter](#snort_ipfilter)|9591|9591|316|3.2%|1.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|294|0.0%|1.5%|
[sorbs_web](#sorbs_web)|680|682|262|38.4%|1.3%|
[stopforumspam_30d](#stopforumspam_30d)|92996|92996|255|0.2%|1.3%|
[stopforumspam_7d](#stopforumspam_7d)|30334|30334|151|0.4%|0.7%|
[ri_web_proxies](#ri_web_proxies)|6189|6189|105|1.6%|0.5%|
[php_dictionary](#php_dictionary)|433|433|83|19.1%|0.4%|
[xroxy](#xroxy)|2060|2060|75|3.6%|0.3%|
[php_spammers](#php_spammers)|417|417|74|17.7%|0.3%|
[blocklist_de_ssh](#blocklist_de_ssh)|13692|13692|73|0.5%|0.3%|
[stopforumspam_1d](#stopforumspam_1d)|7131|7131|59|0.8%|0.3%|
[alienvault_reputation](#alienvault_reputation)|178477|178477|53|0.0%|0.2%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2089|2089|49|2.3%|0.2%|
[blocklist_de_apache](#blocklist_de_apache)|13430|13430|49|0.3%|0.2%|
[blocklist_de_bots](#blocklist_de_bots)|3094|3094|32|1.0%|0.1%|
[proxz](#proxz)|712|712|30|4.2%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|23|0.0%|0.1%|
[blocklist_de_imap](#blocklist_de_imap)|2830|2830|20|0.7%|0.1%|
[openbl_60d](#openbl_60d)|7702|7702|13|0.1%|0.0%|
[sorbs_socks](#sorbs_socks)|23|23|12|52.1%|0.0%|
[sorbs_misc](#sorbs_misc)|23|23|12|52.1%|0.0%|
[sorbs_http](#sorbs_http)|23|23|12|52.1%|0.0%|
[php_commenters](#php_commenters)|281|281|10|3.5%|0.0%|
[sorbs_smtp](#sorbs_smtp)|9|9|8|88.8%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2327|2327|8|0.3%|0.0%|
[spamhaus_drop](#spamhaus_drop)|654|18469632|7|0.0%|0.0%|
[et_block](#et_block)|1007|18338646|7|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|6|0.0%|0.0%|
[proxyrss](#proxyrss)|1606|1606|5|0.3%|0.0%|
[php_harvesters](#php_harvesters)|257|257|4|1.5%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|486400|3|0.0%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|872|872|3|0.3%|0.0%|
[openbl_30d](#openbl_30d)|3260|3260|2|0.0%|0.0%|
[et_tor](#et_tor)|6380|6380|2|0.0%|0.0%|
[shunlist](#shunlist)|1273|1273|1|0.0%|0.0%|
[openbl_7d](#openbl_7d)|943|943|1|0.1%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|1|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|1|0.1%|0.0%|
[dshield](#dshield)|20|5120|1|0.0%|0.0%|
[dm_tor](#dm_tor)|6611|6611|1|0.0%|0.0%|
[bm_tor](#bm_tor)|6616|6616|1|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|179|179|1|0.5%|0.0%|

## sorbs_smtp

[Sorbs.net](https://www.sorbs.net/) SMTP Open Relays, extracted from deltas.

Source is downloaded from [this link]().

The last time downloaded was found to be dated: Thu Jun  4 14:48:14 UTC 2015.

The ipset `sorbs_smtp` has **9** entries, **9** unique IPs.

The following table shows the overlaps of `sorbs_smtp` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `sorbs_smtp`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `sorbs_smtp`.
- ` this % ` is the percentage **of this ipset (`sorbs_smtp`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[sorbs_spam](#sorbs_spam)|23635|24447|9|0.0%|100.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|18771|19329|8|0.0%|88.8%|
[sorbs_new_spam](#sorbs_new_spam)|18771|19329|8|0.0%|88.8%|
[nixspam](#nixspam)|21627|21627|1|0.0%|11.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|1|0.0%|11.1%|

## sorbs_socks

[Sorbs.net](https://www.sorbs.net/) SOCKS proxies, extracted from deltas.

Source is downloaded from [this link]().

The last time downloaded was found to be dated: Thu Jun  4 14:48:14 UTC 2015.

The ipset `sorbs_socks` has **23** entries, **23** unique IPs.

The following table shows the overlaps of `sorbs_socks` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `sorbs_socks`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `sorbs_socks`.
- ` this % ` is the percentage **of this ipset (`sorbs_socks`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[sorbs_misc](#sorbs_misc)|23|23|23|100.0%|100.0%|
[sorbs_http](#sorbs_http)|23|23|23|100.0%|100.0%|
[sorbs_spam](#sorbs_spam)|23635|24447|17|0.0%|73.9%|
[sorbs_recent_spam](#sorbs_recent_spam)|18771|19329|12|0.0%|52.1%|
[sorbs_new_spam](#sorbs_new_spam)|18771|19329|12|0.0%|52.1%|
[snort_ipfilter](#snort_ipfilter)|9591|9591|6|0.0%|26.0%|
[sorbs_web](#sorbs_web)|680|682|5|0.7%|21.7%|
[blocklist_de](#blocklist_de)|37184|37184|5|0.0%|21.7%|
[nixspam](#nixspam)|21627|21627|3|0.0%|13.0%|
[blocklist_de_mail](#blocklist_de_mail)|17091|17091|3|0.0%|13.0%|
[stopforumspam_7d](#stopforumspam_7d)|30334|30334|2|0.0%|8.6%|
[stopforumspam_30d](#stopforumspam_30d)|92996|92996|2|0.0%|8.6%|
[stopforumspam_1d](#stopforumspam_1d)|7131|7131|2|0.0%|8.6%|
[blocklist_de_bots](#blocklist_de_bots)|3094|3094|2|0.0%|8.6%|
[xroxy](#xroxy)|2060|2060|1|0.0%|4.3%|
[ri_web_proxies](#ri_web_proxies)|6189|6189|1|0.0%|4.3%|
[proxyrss](#proxyrss)|1606|1606|1|0.0%|4.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|1|0.0%|4.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|1|0.0%|4.3%|

## sorbs_spam

[Sorbs.net](https://www.sorbs.net/) Spam senders, extracted from deltas.

Source is downloaded from [this link]().

The last time downloaded was found to be dated: Thu Jun  4 15:04:13 UTC 2015.

The ipset `sorbs_spam` has **23635** entries, **24447** unique IPs.

The following table shows the overlaps of `sorbs_spam` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `sorbs_spam`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `sorbs_spam`.
- ` this % ` is the percentage **of this ipset (`sorbs_spam`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[sorbs_recent_spam](#sorbs_recent_spam)|18771|19329|19329|100.0%|79.0%|
[sorbs_new_spam](#sorbs_new_spam)|18771|19329|19329|100.0%|79.0%|
[nixspam](#nixspam)|21627|21627|4008|18.5%|16.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|1747|0.0%|7.1%|
[blocklist_de](#blocklist_de)|37184|37184|1021|2.7%|4.1%|
[blocklist_de_mail](#blocklist_de_mail)|17091|17091|856|5.0%|3.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|590|0.0%|2.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|380|0.0%|1.5%|
[snort_ipfilter](#snort_ipfilter)|9591|9591|340|3.5%|1.3%|
[stopforumspam_30d](#stopforumspam_30d)|92996|92996|301|0.3%|1.2%|
[sorbs_web](#sorbs_web)|680|682|291|42.6%|1.1%|
[stopforumspam_7d](#stopforumspam_7d)|30334|30334|170|0.5%|0.6%|
[ri_web_proxies](#ri_web_proxies)|6189|6189|111|1.7%|0.4%|
[php_dictionary](#php_dictionary)|433|433|90|20.7%|0.3%|
[php_spammers](#php_spammers)|417|417|83|19.9%|0.3%|
[xroxy](#xroxy)|2060|2060|77|3.7%|0.3%|
[blocklist_de_ssh](#blocklist_de_ssh)|13692|13692|75|0.5%|0.3%|
[alienvault_reputation](#alienvault_reputation)|178477|178477|63|0.0%|0.2%|
[stopforumspam_1d](#stopforumspam_1d)|7131|7131|59|0.8%|0.2%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2089|2089|52|2.4%|0.2%|
[blocklist_de_apache](#blocklist_de_apache)|13430|13430|52|0.3%|0.2%|
[blocklist_de_bots](#blocklist_de_bots)|3094|3094|34|1.0%|0.1%|
[proxz](#proxz)|712|712|30|4.2%|0.1%|
[blocklist_de_imap](#blocklist_de_imap)|2830|2830|25|0.8%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|24|0.0%|0.0%|
[sorbs_socks](#sorbs_socks)|23|23|17|73.9%|0.0%|
[sorbs_misc](#sorbs_misc)|23|23|17|73.9%|0.0%|
[sorbs_http](#sorbs_http)|23|23|17|73.9%|0.0%|
[openbl_60d](#openbl_60d)|7702|7702|14|0.1%|0.0%|
[spamhaus_drop](#spamhaus_drop)|654|18469632|12|0.0%|0.0%|
[et_block](#et_block)|1007|18338646|12|0.0%|0.0%|
[php_commenters](#php_commenters)|281|281|11|3.9%|0.0%|
[sorbs_smtp](#sorbs_smtp)|9|9|9|100.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2327|2327|9|0.3%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|8|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|6|0.0%|0.0%|
[proxyrss](#proxyrss)|1606|1606|5|0.3%|0.0%|
[php_harvesters](#php_harvesters)|257|257|5|1.9%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|486400|4|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|872|872|4|0.4%|0.0%|
[openbl_30d](#openbl_30d)|3260|3260|2|0.0%|0.0%|
[et_tor](#et_tor)|6380|6380|2|0.0%|0.0%|
[shunlist](#shunlist)|1273|1273|1|0.0%|0.0%|
[openbl_7d](#openbl_7d)|943|943|1|0.1%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|1|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|1|0.1%|0.0%|
[et_compromised](#et_compromised)|2171|2171|1|0.0%|0.0%|
[dshield](#dshield)|20|5120|1|0.0%|0.0%|
[dm_tor](#dm_tor)|6611|6611|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2051|2051|1|0.0%|0.0%|
[bm_tor](#bm_tor)|6616|6616|1|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|179|179|1|0.5%|0.0%|

## sorbs_web

[Sorbs.net](https://www.sorbs.net/) WEB exploits, extracted from deltas.

Source is downloaded from [this link]().

The last time downloaded was found to be dated: Thu Jun  4 15:04:14 UTC 2015.

The ipset `sorbs_web` has **680** entries, **682** unique IPs.

The following table shows the overlaps of `sorbs_web` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `sorbs_web`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `sorbs_web`.
- ` this % ` is the percentage **of this ipset (`sorbs_web`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[sorbs_spam](#sorbs_spam)|23635|24447|291|1.1%|42.6%|
[sorbs_recent_spam](#sorbs_recent_spam)|18771|19329|262|1.3%|38.4%|
[sorbs_new_spam](#sorbs_new_spam)|18771|19329|262|1.3%|38.4%|
[nixspam](#nixspam)|21627|21627|149|0.6%|21.8%|
[blocklist_de](#blocklist_de)|37184|37184|86|0.2%|12.6%|
[blocklist_de_mail](#blocklist_de_mail)|17091|17091|71|0.4%|10.4%|
[stopforumspam_30d](#stopforumspam_30d)|92996|92996|63|0.0%|9.2%|
[snort_ipfilter](#snort_ipfilter)|9591|9591|56|0.5%|8.2%|
[stopforumspam_7d](#stopforumspam_7d)|30334|30334|46|0.1%|6.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|43|0.0%|6.3%|
[ri_web_proxies](#ri_web_proxies)|6189|6189|27|0.4%|3.9%|
[php_dictionary](#php_dictionary)|433|433|27|6.2%|3.9%|
[xroxy](#xroxy)|2060|2060|26|1.2%|3.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|25|0.0%|3.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|24|0.0%|3.5%|
[stopforumspam_1d](#stopforumspam_1d)|7131|7131|22|0.3%|3.2%|
[php_spammers](#php_spammers)|417|417|22|5.2%|3.2%|
[proxz](#proxz)|712|712|11|1.5%|1.6%|
[blocklist_de_bots](#blocklist_de_bots)|3094|3094|11|0.3%|1.6%|
[sorbs_socks](#sorbs_socks)|23|23|5|21.7%|0.7%|
[sorbs_misc](#sorbs_misc)|23|23|5|21.7%|0.7%|
[sorbs_http](#sorbs_http)|23|23|5|21.7%|0.7%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2089|2089|3|0.1%|0.4%|
[blocklist_de_apache](#blocklist_de_apache)|13430|13430|3|0.0%|0.4%|
[ri_connect_proxies](#ri_connect_proxies)|2327|2327|2|0.0%|0.2%|
[php_commenters](#php_commenters)|281|281|2|0.7%|0.2%|
[spamhaus_drop](#spamhaus_drop)|654|18469632|1|0.0%|0.1%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1|0.0%|0.1%|
[et_block](#et_block)|1007|18338646|1|0.0%|0.1%|
[blocklist_de_strongips](#blocklist_de_strongips)|179|179|1|0.5%|0.1%|
[blocklist_de_ssh](#blocklist_de_ssh)|13692|13692|1|0.0%|0.1%|
[blocklist_de_imap](#blocklist_de_imap)|2830|2830|1|0.0%|0.1%|

## spamhaus_drop

[Spamhaus.org](http://www.spamhaus.org) DROP list (according to their site this list should be dropped at tier-1 ISPs globaly) - **excellent list**

Source is downloaded from [this link](http://www.spamhaus.org/drop/drop.txt).

The last time downloaded was found to be dated: Wed Jun  3 21:37:54 UTC 2015.

The ipset `spamhaus_drop` has **654** entries, **18469632** unique IPs.

The following table shows the overlaps of `spamhaus_drop` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `spamhaus_drop`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `spamhaus_drop`.
- ` this % ` is the percentage **of this ipset (`spamhaus_drop`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[et_block](#et_block)|1007|18338646|18202368|99.2%|98.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|8598042|2.4%|46.5%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|7014400|76.4%|37.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|2272265|0.2%|12.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|195904|0.1%|1.0%|
[fullbogons](#fullbogons)|3733|670419608|151552|0.0%|0.8%|
[alienvault_reputation](#alienvault_reputation)|178477|178477|1885|1.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1037|0.3%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92996|92996|1014|1.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|486400|512|0.1%|0.0%|
[dshield](#dshield)|20|5120|512|10.0%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|30334|30334|336|1.1%|0.0%|
[openbl_60d](#openbl_60d)|7702|7702|239|3.1%|0.0%|
[openbl_30d](#openbl_30d)|3260|3260|159|4.8%|0.0%|
[blocklist_de](#blocklist_de)|37184|37184|153|0.4%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|13692|13692|111|0.8%|0.0%|
[et_compromised](#et_compromised)|2171|2171|100|4.6%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2051|2051|100|4.8%|0.0%|
[shunlist](#shunlist)|1273|1273|99|7.7%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7131|7131|91|1.2%|0.0%|
[nixspam](#nixspam)|21627|21627|64|0.2%|0.0%|
[openbl_7d](#openbl_7d)|943|943|58|6.1%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|29|2.2%|0.0%|
[php_commenters](#php_commenters)|281|281|25|8.8%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9591|9591|20|0.2%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3094|3094|20|0.6%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|17091|17091|19|0.1%|0.0%|
[zeus_badips](#zeus_badips)|234|234|16|6.8%|0.0%|
[zeus](#zeus)|269|269|16|5.9%|0.0%|
[voipbl](#voipbl)|10426|10837|14|0.1%|0.0%|
[sorbs_spam](#sorbs_spam)|23635|24447|12|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2830|2830|10|0.3%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|18771|19329|7|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|18771|19329|7|0.0%|0.0%|
[openbl_1d](#openbl_1d)|192|192|7|3.6%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|6|0.4%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|6|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|179|179|6|3.3%|0.0%|
[php_dictionary](#php_dictionary)|433|433|4|0.9%|0.0%|
[malc0de](#malc0de)|379|379|4|1.0%|0.0%|
[php_spammers](#php_spammers)|417|417|3|0.7%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2089|2089|3|0.1%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13430|13430|3|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|2|0.2%|0.0%|
[et_tor](#et_tor)|6380|6380|2|0.0%|0.0%|
[dm_tor](#dm_tor)|6611|6611|2|0.0%|0.0%|
[bm_tor](#bm_tor)|6616|6616|2|0.0%|0.0%|
[sslbl](#sslbl)|366|366|1|0.2%|0.0%|
[sorbs_web](#sorbs_web)|680|682|1|0.1%|0.0%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.0%|
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
[spamhaus_drop](#spamhaus_drop)|654|18469632|512|0.0%|0.1%|
[stopforumspam_30d](#stopforumspam_30d)|92996|92996|96|0.1%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|30334|30334|21|0.0%|0.0%|
[alienvault_reputation](#alienvault_reputation)|178477|178477|15|0.0%|0.0%|
[blocklist_de](#blocklist_de)|37184|37184|12|0.0%|0.0%|
[php_commenters](#php_commenters)|281|281|7|2.4%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9591|9591|6|0.0%|0.0%|
[zeus_badips](#zeus_badips)|234|234|5|2.1%|0.0%|
[zeus](#zeus)|269|269|5|1.8%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|179|179|5|2.7%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7131|7131|4|0.0%|0.0%|
[sorbs_spam](#sorbs_spam)|23635|24447|4|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|17091|17091|4|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3094|3094|4|0.1%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|18771|19329|3|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|18771|19329|3|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13430|13430|2|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.0%|
[openbl_60d](#openbl_60d)|7702|7702|1|0.0%|0.0%|
[openbl_30d](#openbl_30d)|3260|3260|1|0.0%|0.0%|
[nixspam](#nixspam)|21627|21627|1|0.0%|0.0%|
[malc0de](#malc0de)|379|379|1|0.2%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|13692|13692|1|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2830|2830|1|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|872|872|1|0.1%|0.0%|

## sslbl

[Abuse.ch SSL Blacklist](https://sslbl.abuse.ch/) bad SSL traffic related to malware or botnet activities - **excellent list**

Source is downloaded from [this link](https://sslbl.abuse.ch/blacklist/sslipblacklist.csv).

The last time downloaded was found to be dated: Thu Jun  4 15:15:06 UTC 2015.

The ipset `sslbl` has **366** entries, **366** unique IPs.

The following table shows the overlaps of `sslbl` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `sslbl`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `sslbl`.
- ` this % ` is the percentage **of this ipset (`sslbl`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[alienvault_reputation](#alienvault_reputation)|178477|178477|64|0.0%|17.4%|
[shunlist](#shunlist)|1273|1273|56|4.3%|15.3%|
[feodo](#feodo)|93|93|34|36.5%|9.2%|
[et_block](#et_block)|1007|18338646|32|0.0%|8.7%|
[snort_ipfilter](#snort_ipfilter)|9591|9591|28|0.2%|7.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|23|0.0%|6.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|6|0.0%|1.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|4|0.0%|1.0%|
[stopforumspam_30d](#stopforumspam_30d)|92996|92996|1|0.0%|0.2%|
[spamhaus_drop](#spamhaus_drop)|654|18469632|1|0.0%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.2%|

## stopforumspam_1d

[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers in the last 24 hours - **excellent list**

Source is downloaded from [this link](http://www.stopforumspam.com/downloads/listed_ip_1.zip).

The last time downloaded was found to be dated: Thu Jun  4 15:00:02 UTC 2015.

The ipset `stopforumspam_1d` has **7131** entries, **7131** unique IPs.

The following table shows the overlaps of `stopforumspam_1d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `stopforumspam_1d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `stopforumspam_1d`.
- ` this % ` is the percentage **of this ipset (`stopforumspam_1d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_30d](#stopforumspam_30d)|92996|92996|5325|5.7%|74.6%|
[stopforumspam_7d](#stopforumspam_7d)|30334|30334|5106|16.8%|71.6%|
[blocklist_de](#blocklist_de)|37184|37184|1482|3.9%|20.7%|
[blocklist_de_bots](#blocklist_de_bots)|3094|3094|1396|45.1%|19.5%|
[ri_web_proxies](#ri_web_proxies)|6189|6189|507|8.1%|7.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|471|0.0%|6.6%|
[proxyrss](#proxyrss)|1606|1606|414|25.7%|5.8%|
[snort_ipfilter](#snort_ipfilter)|9591|9591|381|3.9%|5.3%|
[et_tor](#et_tor)|6380|6380|331|5.1%|4.6%|
[dm_tor](#dm_tor)|6611|6611|323|4.8%|4.5%|
[bm_tor](#bm_tor)|6616|6616|323|4.8%|4.5%|
[xroxy](#xroxy)|2060|2060|292|14.1%|4.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|229|0.0%|3.2%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|166|44.6%|2.3%|
[ri_connect_proxies](#ri_connect_proxies)|2327|2327|165|7.0%|2.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|159|0.0%|2.2%|
[proxz](#proxz)|712|712|131|18.3%|1.8%|
[php_commenters](#php_commenters)|281|281|109|38.7%|1.5%|
[blocklist_de_strongips](#blocklist_de_strongips)|179|179|104|58.1%|1.4%|
[spamhaus_drop](#spamhaus_drop)|654|18469632|91|0.0%|1.2%|
[et_block](#et_block)|1007|18338646|91|0.0%|1.2%|
[blocklist_de_apache](#blocklist_de_apache)|13430|13430|76|0.5%|1.0%|
[nixspam](#nixspam)|21627|21627|72|0.3%|1.0%|
[alienvault_reputation](#alienvault_reputation)|178477|178477|62|0.0%|0.8%|
[blocklist_de_mail](#blocklist_de_mail)|17091|17091|60|0.3%|0.8%|
[sorbs_spam](#sorbs_spam)|23635|24447|59|0.2%|0.8%|
[sorbs_recent_spam](#sorbs_recent_spam)|18771|19329|59|0.3%|0.8%|
[sorbs_new_spam](#sorbs_new_spam)|18771|19329|59|0.3%|0.8%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|39|0.0%|0.5%|
[php_harvesters](#php_harvesters)|257|257|35|13.6%|0.4%|
[php_spammers](#php_spammers)|417|417|30|7.1%|0.4%|
[php_dictionary](#php_dictionary)|433|433|23|5.3%|0.3%|
[sorbs_web](#sorbs_web)|680|682|22|3.2%|0.3%|
[openbl_60d](#openbl_60d)|7702|7702|22|0.2%|0.3%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2089|2089|20|0.9%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|9|0.0%|0.1%|
[voipbl](#voipbl)|10426|10837|6|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|6|0.8%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|486400|4|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|13692|13692|4|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|872|872|4|0.4%|0.0%|
[sorbs_socks](#sorbs_socks)|23|23|2|8.6%|0.0%|
[sorbs_misc](#sorbs_misc)|23|23|2|8.6%|0.0%|
[sorbs_http](#sorbs_http)|23|23|2|8.6%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2051|2051|2|0.0%|0.0%|
[zeus_badips](#zeus_badips)|234|234|1|0.4%|0.0%|
[zeus](#zeus)|269|269|1|0.3%|0.0%|
[shunlist](#shunlist)|1273|1273|1|0.0%|0.0%|
[openbl_30d](#openbl_30d)|3260|3260|1|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|
[et_compromised](#et_compromised)|2171|2171|1|0.0%|0.0%|
[dshield](#dshield)|20|5120|1|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2830|2830|1|0.0%|0.0%|

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
[stopforumspam_1d](#stopforumspam_1d)|7131|7131|5325|74.6%|5.7%|
[ri_web_proxies](#ri_web_proxies)|6189|6189|2991|48.3%|3.2%|
[blocklist_de](#blocklist_de)|37184|37184|2532|6.8%|2.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|2521|0.0%|2.7%|
[blocklist_de_bots](#blocklist_de_bots)|3094|3094|2121|68.5%|2.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|1551|0.0%|1.6%|
[ri_connect_proxies](#ri_connect_proxies)|2327|2327|1349|57.9%|1.4%|
[xroxy](#xroxy)|2060|2060|1210|58.7%|1.3%|
[spamhaus_drop](#spamhaus_drop)|654|18469632|1014|0.0%|1.0%|
[et_block](#et_block)|1007|18338646|1014|0.0%|1.0%|
[proxyrss](#proxyrss)|1606|1606|837|52.1%|0.9%|
[snort_ipfilter](#snort_ipfilter)|9591|9591|810|8.4%|0.8%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|756|0.0%|0.8%|
[et_tor](#et_tor)|6380|6380|636|9.9%|0.6%|
[dm_tor](#dm_tor)|6611|6611|624|9.4%|0.6%|
[bm_tor](#bm_tor)|6616|6616|624|9.4%|0.6%|
[proxz](#proxz)|712|712|428|60.1%|0.4%|
[sorbs_spam](#sorbs_spam)|23635|24447|301|1.2%|0.3%|
[blocklist_de_mail](#blocklist_de_mail)|17091|17091|256|1.4%|0.2%|
[sorbs_recent_spam](#sorbs_recent_spam)|18771|19329|255|1.3%|0.2%|
[sorbs_new_spam](#sorbs_new_spam)|18771|19329|255|1.3%|0.2%|
[nixspam](#nixspam)|21627|21627|239|1.1%|0.2%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|233|62.6%|0.2%|
[alienvault_reputation](#alienvault_reputation)|178477|178477|218|0.1%|0.2%|
[php_commenters](#php_commenters)|281|281|206|73.3%|0.2%|
[blocklist_de_apache](#blocklist_de_apache)|13430|13430|205|1.5%|0.2%|
[blocklist_de_strongips](#blocklist_de_strongips)|179|179|134|74.8%|0.1%|
[php_spammers](#php_spammers)|417|417|100|23.9%|0.1%|
[blocklist_de_ssh](#blocklist_de_ssh)|13692|13692|99|0.7%|0.1%|
[spamhaus_edrop](#spamhaus_edrop)|55|486400|96|0.0%|0.1%|
[php_dictionary](#php_dictionary)|433|433|85|19.6%|0.0%|
[php_harvesters](#php_harvesters)|257|257|64|24.9%|0.0%|
[sorbs_web](#sorbs_web)|680|682|63|9.2%|0.0%|
[openbl_60d](#openbl_60d)|7702|7702|56|0.7%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|48|0.0%|0.0%|
[voipbl](#voipbl)|10426|10837|38|0.3%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2089|2089|34|1.6%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|22|3.2%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|15|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2830|2830|11|0.3%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|872|872|11|1.2%|0.0%|
[et_compromised](#et_compromised)|2171|2171|10|0.4%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2051|2051|10|0.4%|0.0%|
[shunlist](#shunlist)|1273|1273|4|0.3%|0.0%|
[openbl_30d](#openbl_30d)|3260|3260|4|0.1%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|4|0.3%|0.0%|
[zeus_badips](#zeus_badips)|234|234|3|1.2%|0.0%|
[zeus](#zeus)|269|269|3|1.1%|0.0%|
[openbl_7d](#openbl_7d)|943|943|3|0.3%|0.0%|
[sorbs_socks](#sorbs_socks)|23|23|2|8.6%|0.0%|
[sorbs_misc](#sorbs_misc)|23|23|2|8.6%|0.0%|
[sorbs_http](#sorbs_http)|23|23|2|8.6%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.0%|
[fullbogons](#fullbogons)|3733|670419608|2|0.0%|0.0%|
[dshield](#dshield)|20|5120|2|0.0%|0.0%|
[sslbl](#sslbl)|366|366|1|0.2%|0.0%|
[ciarmy](#ciarmy)|343|343|1|0.2%|0.0%|
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
[stopforumspam_1d](#stopforumspam_1d)|7131|7131|5106|71.6%|16.8%|
[blocklist_de](#blocklist_de)|37184|37184|2146|5.7%|7.0%|
[blocklist_de_bots](#blocklist_de_bots)|3094|3094|1948|62.9%|6.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|1930|0.0%|6.3%|
[ri_web_proxies](#ri_web_proxies)|6189|6189|1664|26.8%|5.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|908|0.0%|2.9%|
[xroxy](#xroxy)|2060|2060|906|43.9%|2.9%|
[proxyrss](#proxyrss)|1606|1606|692|43.0%|2.2%|
[ri_connect_proxies](#ri_connect_proxies)|2327|2327|687|29.5%|2.2%|
[snort_ipfilter](#snort_ipfilter)|9591|9591|618|6.4%|2.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|571|0.0%|1.8%|
[et_tor](#et_tor)|6380|6380|499|7.8%|1.6%|
[dm_tor](#dm_tor)|6611|6611|486|7.3%|1.6%|
[bm_tor](#bm_tor)|6616|6616|486|7.3%|1.6%|
[proxz](#proxz)|712|712|356|50.0%|1.1%|
[spamhaus_drop](#spamhaus_drop)|654|18469632|336|0.0%|1.1%|
[et_block](#et_block)|1007|18338646|335|0.0%|1.1%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|194|52.1%|0.6%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|186|0.0%|0.6%|
[sorbs_spam](#sorbs_spam)|23635|24447|170|0.6%|0.5%|
[nixspam](#nixspam)|21627|21627|162|0.7%|0.5%|
[sorbs_recent_spam](#sorbs_recent_spam)|18771|19329|151|0.7%|0.4%|
[sorbs_new_spam](#sorbs_new_spam)|18771|19329|151|0.7%|0.4%|
[blocklist_de_mail](#blocklist_de_mail)|17091|17091|149|0.8%|0.4%|
[php_commenters](#php_commenters)|281|281|145|51.6%|0.4%|
[blocklist_de_apache](#blocklist_de_apache)|13430|13430|126|0.9%|0.4%|
[blocklist_de_strongips](#blocklist_de_strongips)|179|179|122|68.1%|0.4%|
[alienvault_reputation](#alienvault_reputation)|178477|178477|106|0.0%|0.3%|
[php_spammers](#php_spammers)|417|417|57|13.6%|0.1%|
[php_dictionary](#php_dictionary)|433|433|57|13.1%|0.1%|
[php_harvesters](#php_harvesters)|257|257|50|19.4%|0.1%|
[sorbs_web](#sorbs_web)|680|682|46|6.7%|0.1%|
[openbl_60d](#openbl_60d)|7702|7702|25|0.3%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2089|2089|24|1.1%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|23|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|486400|21|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|13692|13692|14|0.1%|0.0%|
[voipbl](#voipbl)|10426|10837|13|0.1%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|12|1.7%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|6|0.0%|0.0%|
[et_compromised](#et_compromised)|2171|2171|6|0.2%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2051|2051|6|0.2%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|872|872|6|0.6%|0.0%|
[shunlist](#shunlist)|1273|1273|3|0.2%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|3|0.2%|0.0%|
[sorbs_socks](#sorbs_socks)|23|23|2|8.6%|0.0%|
[sorbs_misc](#sorbs_misc)|23|23|2|8.6%|0.0%|
[sorbs_http](#sorbs_http)|23|23|2|8.6%|0.0%|
[dshield](#dshield)|20|5120|2|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2830|2830|2|0.0%|0.0%|
[zeus_badips](#zeus_badips)|234|234|1|0.4%|0.0%|
[zeus](#zeus)|269|269|1|0.3%|0.0%|
[openbl_30d](#openbl_30d)|3260|3260|1|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|
[ciarmy](#ciarmy)|343|343|1|0.2%|0.0%|

## virbl

[VirBL](http://virbl.bit.nl/) is a project of which the idea was born during the RIPE-48 meeting. The plan was to get reports of virusscanning mailservers, and put the IP-addresses that were reported to send viruses on a blacklist.

Source is downloaded from [this link](http://virbl.bit.nl/download/virbl.dnsbl.bit.nl.txt).

The last time downloaded was found to be dated: Thu Jun  4 14:52:04 UTC 2015.

The ipset `virbl` has **11** entries, **11** unique IPs.

The following table shows the overlaps of `virbl` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `virbl`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `virbl`.
- ` this % ` is the percentage **of this ipset (`virbl`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[alienvault_reputation](#alienvault_reputation)|178477|178477|2|0.0%|18.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|1|0.0%|9.0%|

## voipbl

[VoIPBL.org](http://www.voipbl.org/) a distributed VoIP blacklist that is aimed to protects against VoIP Fraud and minimizing abuse for network that have publicly accessible PBX's. Several algorithms, external sources and manual confirmation are used before they categorize something as an attack and determine the threat level.

Source is downloaded from [this link](http://www.voipbl.org/update/).

The last time downloaded was found to be dated: Thu Jun  4 15:36:36 UTC 2015.

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
[alienvault_reputation](#alienvault_reputation)|178477|178477|200|0.1%|1.8%|
[blocklist_de](#blocklist_de)|37184|37184|47|0.1%|0.4%|
[blocklist_de_sip](#blocklist_de_sip)|103|103|39|37.8%|0.3%|
[stopforumspam_30d](#stopforumspam_30d)|92996|92996|38|0.0%|0.3%|
[spamhaus_drop](#spamhaus_drop)|654|18469632|14|0.0%|0.1%|
[et_block](#et_block)|1007|18338646|14|0.0%|0.1%|
[stopforumspam_7d](#stopforumspam_7d)|30334|30334|13|0.0%|0.1%|
[shunlist](#shunlist)|1273|1273|11|0.8%|0.1%|
[openbl_60d](#openbl_60d)|7702|7702|8|0.1%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7131|7131|6|0.0%|0.0%|
[ciarmy](#ciarmy)|343|343|6|1.7%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|4|0.0%|0.0%|
[openbl_30d](#openbl_30d)|3260|3260|3|0.0%|0.0%|
[dm_tor](#dm_tor)|6611|6611|3|0.0%|0.0%|
[bm_tor](#bm_tor)|6616|6616|3|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|13692|13692|3|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13430|13430|3|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|2|0.0%|0.0%|
[et_tor](#et_tor)|6380|6380|2|0.0%|0.0%|
[et_compromised](#et_compromised)|2171|2171|2|0.0%|0.0%|
[dshield](#dshield)|20|5120|2|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2051|2051|2|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9591|9591|1|0.0%|0.0%|
[openbl_7d](#openbl_7d)|943|943|1|0.1%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|17091|17091|1|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2830|2830|1|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2089|2089|1|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3094|3094|1|0.0%|0.0%|

## xroxy

[xroxy.com](http://www.xroxy.com) open proxies (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.xroxy.com/proxyrss.xml).

The last time downloaded was found to be dated: Thu Jun  4 15:33:01 UTC 2015.

The ipset `xroxy` has **2060** entries, **2060** unique IPs.

The following table shows the overlaps of `xroxy` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `xroxy`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `xroxy`.
- ` this % ` is the percentage **of this ipset (`xroxy`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_30d](#stopforumspam_30d)|92996|92996|1210|1.3%|58.7%|
[stopforumspam_7d](#stopforumspam_7d)|30334|30334|906|2.9%|43.9%|
[ri_web_proxies](#ri_web_proxies)|6189|6189|871|14.0%|42.2%|
[proxyrss](#proxyrss)|1606|1606|463|28.8%|22.4%|
[ri_connect_proxies](#ri_connect_proxies)|2327|2327|351|15.0%|17.0%|
[proxz](#proxz)|712|712|300|42.1%|14.5%|
[stopforumspam_1d](#stopforumspam_1d)|7131|7131|292|4.0%|14.1%|
[blocklist_de](#blocklist_de)|37184|37184|261|0.7%|12.6%|
[blocklist_de_bots](#blocklist_de_bots)|3094|3094|209|6.7%|10.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|99|0.0%|4.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|90|0.0%|4.3%|
[sorbs_spam](#sorbs_spam)|23635|24447|77|0.3%|3.7%|
[sorbs_recent_spam](#sorbs_recent_spam)|18771|19329|75|0.3%|3.6%|
[sorbs_new_spam](#sorbs_new_spam)|18771|19329|75|0.3%|3.6%|
[nixspam](#nixspam)|21627|21627|66|0.3%|3.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|57|0.0%|2.7%|
[blocklist_de_mail](#blocklist_de_mail)|17091|17091|51|0.2%|2.4%|
[snort_ipfilter](#snort_ipfilter)|9591|9591|50|0.5%|2.4%|
[sorbs_web](#sorbs_web)|680|682|26|3.8%|1.2%|
[php_dictionary](#php_dictionary)|433|433|24|5.5%|1.1%|
[php_spammers](#php_spammers)|417|417|20|4.7%|0.9%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|13|1.9%|0.6%|
[blocklist_de_strongips](#blocklist_de_strongips)|179|179|7|3.9%|0.3%|
[alienvault_reputation](#alienvault_reputation)|178477|178477|5|0.0%|0.2%|
[php_commenters](#php_commenters)|281|281|3|1.0%|0.1%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|3|0.0%|0.1%|
[php_harvesters](#php_harvesters)|257|257|2|0.7%|0.0%|
[et_tor](#et_tor)|6380|6380|2|0.0%|0.0%|
[dm_tor](#dm_tor)|6611|6611|2|0.0%|0.0%|
[bm_tor](#bm_tor)|6616|6616|2|0.0%|0.0%|
[sorbs_socks](#sorbs_socks)|23|23|1|4.3%|0.0%|
[sorbs_misc](#sorbs_misc)|23|23|1|4.3%|0.0%|
[sorbs_http](#sorbs_http)|23|23|1|4.3%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.0%|
[et_compromised](#et_compromised)|2171|2171|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2051|2051|1|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|13692|13692|1|0.0%|0.0%|

## zeus

[Abuse.ch Zeus tracker](https://zeustracker.abuse.ch) standard, contains the same data as the ZeuS IP blocklist (zeus_badips) but with the slight difference that it doesn't exclude hijacked websites (level 2) and free web hosting providers (level 3). This means that this blocklist contains all IPv4 addresses associated with ZeuS C&Cs which are currently being tracked by ZeuS Tracker. Hence this blocklist will likely cause some false positives. - **excellent list**

Source is downloaded from [this link](https://zeustracker.abuse.ch/blocklist.php?download=ipblocklist).

The last time downloaded was found to be dated: Thu Jun  4 13:31:56 UTC 2015.

The ipset `zeus` has **269** entries, **269** unique IPs.

The following table shows the overlaps of `zeus` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `zeus`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `zeus`.
- ` this % ` is the percentage **of this ipset (`zeus`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[et_block](#et_block)|1007|18338646|259|0.0%|96.2%|
[zeus_badips](#zeus_badips)|234|234|234|100.0%|86.9%|
[snort_ipfilter](#snort_ipfilter)|9591|9591|228|2.3%|84.7%|
[alienvault_reputation](#alienvault_reputation)|178477|178477|66|0.0%|24.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|20|0.0%|7.4%|
[spamhaus_drop](#spamhaus_drop)|654|18469632|16|0.0%|5.9%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|10|0.0%|3.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|9|0.0%|3.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|6|0.0%|2.2%|
[spamhaus_edrop](#spamhaus_edrop)|55|486400|5|0.0%|1.8%|
[stopforumspam_30d](#stopforumspam_30d)|92996|92996|3|0.0%|1.1%|
[openbl_60d](#openbl_60d)|7702|7702|2|0.0%|0.7%|
[openbl_30d](#openbl_30d)|3260|3260|2|0.0%|0.7%|
[stopforumspam_7d](#stopforumspam_7d)|30334|30334|1|0.0%|0.3%|
[stopforumspam_1d](#stopforumspam_1d)|7131|7131|1|0.0%|0.3%|
[php_commenters](#php_commenters)|281|281|1|0.3%|0.3%|
[nixspam](#nixspam)|21627|21627|1|0.0%|0.3%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.3%|

## zeus_badips

[Abuse.ch Zeus tracker](https://zeustracker.abuse.ch) badips includes IPv4 addresses that are used by the ZeuS trojan. It is the recommened blocklist if you want to block only ZeuS IPs. It excludes IP addresses that ZeuS Tracker believes to be hijacked (level 2) or belong to a free web hosting provider (level 3). Hence the false postive rate should be much lower compared to the standard ZeuS IP blocklist. **excellent list**

Source is downloaded from [this link](https://zeustracker.abuse.ch/blocklist.php?download=badips).

The last time downloaded was found to be dated: Thu Jun  4 15:27:12 UTC 2015.

The ipset `zeus_badips` has **234** entries, **234** unique IPs.

The following table shows the overlaps of `zeus_badips` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `zeus_badips`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `zeus_badips`.
- ` this % ` is the percentage **of this ipset (`zeus_badips`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[zeus](#zeus)|269|269|234|86.9%|100.0%|
[et_block](#et_block)|1007|18338646|230|0.0%|98.2%|
[snort_ipfilter](#snort_ipfilter)|9591|9591|205|2.1%|87.6%|
[alienvault_reputation](#alienvault_reputation)|178477|178477|38|0.0%|16.2%|
[spamhaus_drop](#spamhaus_drop)|654|18469632|16|0.0%|6.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|14|0.0%|5.9%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|10|0.0%|4.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|8|0.0%|3.4%|
[spamhaus_edrop](#spamhaus_edrop)|55|486400|5|0.0%|2.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|4|0.0%|1.7%|
[stopforumspam_30d](#stopforumspam_30d)|92996|92996|3|0.0%|1.2%|
[stopforumspam_7d](#stopforumspam_7d)|30334|30334|1|0.0%|0.4%|
[stopforumspam_1d](#stopforumspam_1d)|7131|7131|1|0.0%|0.4%|
[php_commenters](#php_commenters)|281|281|1|0.3%|0.4%|
[openbl_60d](#openbl_60d)|7702|7702|1|0.0%|0.4%|
[openbl_30d](#openbl_30d)|3260|3260|1|0.0%|0.4%|
[nixspam](#nixspam)|21627|21627|1|0.0%|0.4%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.4%|
