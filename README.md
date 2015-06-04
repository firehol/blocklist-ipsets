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

The following list was automatically generated on Thu Jun  4 13:27:33 UTC 2015.

The update frequency is the maximum allowed by internal configuration. A list will never be downloaded sooner than the update frequency stated. A list may also not be downloaded, after this frequency expired, if it has not been modified on the server (as reported by HTTP `IF_MODIFIED_SINCE` method).

name|info|type|entries|update|
:--:|:--:|:--:|:-----:|:----:|
[alienvault_reputation](#alienvault_reputation)|[AlienVault.com](https://www.alienvault.com/) IP reputation database (this list seems to include port scanning hosts and to be updated regularly, but we found no information about its retention policy)|ipv4 hash:ip|178477 unique IPs|updated every 6 hours  from [this link](https://reputation.alienvault.com/reputation.generic)
[blocklist_de](#blocklist_de)|[Blocklist.de](https://www.blocklist.de/) IPs that have been detected by fail2ban in the last 48 hours - **excellent list**|ipv4 hash:ip|38212 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/all.txt)
[blocklist_de_apache](#blocklist_de_apache)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service Apache, Apache-DDOS, RFI-Attacks.|ipv4 hash:ip|13522 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/apache.txt)
[blocklist_de_bots](#blocklist_de_bots)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the RFI-Attacks, REG-Bots, IRC-Bots or BadBots (BadBots = he has posted a Spam-Comment on a open Forum or Wiki).|ipv4 hash:ip|3113 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/bots.txt)
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|[Blocklist.de](https://www.blocklist.de/) All IPs which attacks Joomlas, Wordpress and other Web-Logins with Brute-Force Logins.|ipv4 hash:ip|2186 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/bruteforcelogin.txt)
[blocklist_de_ftp](#blocklist_de_ftp)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours for attacks on the Service FTP.|ipv4 hash:ip|877 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/ftp.txt)
[blocklist_de_imap](#blocklist_de_imap)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours for attacks on the Service imap, sasl, pop3, etc.|ipv4 hash:ip|3124 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/imap.txt)
[blocklist_de_mail](#blocklist_de_mail)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service Mail, Postfix.|ipv4 hash:ip|17398 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/mail.txt)
[blocklist_de_sip](#blocklist_de_sip)|[Blocklist.de](https://www.blocklist.de/) All IP addresses that tried to login in a SIP, VOIP or Asterisk Server and are included in the IPs list from [infiltrated.net](www.infiltrated.net)|ipv4 hash:ip|105 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/sip.txt)
[blocklist_de_ssh](#blocklist_de_ssh)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service SSH.|ipv4 hash:ip|14281 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/ssh.txt)
[blocklist_de_strongips](#blocklist_de_strongips)|[Blocklist.de](https://www.blocklist.de/) All IPs which are older then 2 month and have more then 5.000 attacks.|ipv4 hash:ip|178 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/strongips.txt)
[bm_tor](#bm_tor)|[torstatus.blutmagie.de](https://torstatus.blutmagie.de) list of all TOR network servers|ipv4 hash:ip|6584 unique IPs|updated every 30 mins  from [this link](https://torstatus.blutmagie.de/ip_list_all.php/Tor_ip_list_ALL.csv)
[bogons](#bogons)|[Team-Cymru.org](http://www.team-cymru.org) private and reserved addresses defined by RFC 1918, RFC 5735, and RFC 6598 and netblocks that have not been allocated to a regional internet registry - **excellent list - use it only your internet interface**|ipv4 hash:net|13 subnets, 592708608 unique IPs|updated every 1 day  from [this link](http://www.team-cymru.org/Services/Bogons/bogon-bn-agg.txt)
[bruteforceblocker](#bruteforceblocker)|[danger.rulez.sk](http://danger.rulez.sk/) IPs detected by [bruteforceblocker](http://danger.rulez.sk/index.php/bruteforceblocker/) (fail2ban alternative for SSH on OpenBSD). This is an automatically generated list from users reporting failed authentication attempts. An IP seems to be included if 3 or more users report it. Its retention pocily seems 30 days.|ipv4 hash:ip|2052 unique IPs|updated every 3 hours  from [this link](http://danger.rulez.sk/projects/bruteforceblocker/blist.php)
[ciarmy](#ciarmy)|[CIArmy.com](http://ciarmy.com/) IPs with poor Rogue Packet score that have not yet been identified as malicious by the community|ipv4 hash:ip|343 unique IPs|updated every 3 hours  from [this link](http://cinsscore.com/list/ci-badguys.txt)
[cleanmx_viruses](#cleanmx_viruses)|[Clean-MX.de](http://support.clean-mx.de/clean-mx/viruses.php) IPs with viruses|ipv4 hash:ip|206 unique IPs|updated every 12 hours  from [this link](http://support.clean-mx.de/clean-mx/xmlviruses.php?sort=id%20desc&response=alive)
[dm_tor](#dm_tor)|[dan.me.uk](https://www.dan.me.uk) dynamic list of TOR exit points|ipv4 hash:ip|6585 unique IPs|updated every 30 mins  from [this link](https://www.dan.me.uk/torlist/)
[dshield](#dshield)|[DShield.org](https://dshield.org/) top 20 attacking class C (/24) subnets over the last three days - **excellent list**|ipv4 hash:net|20 subnets, 5120 unique IPs|updated every 4 hours  from [this link](http://feeds.dshield.org/block.txt)
[et_block](#et_block)|[EmergingThreats.net](http://www.emergingthreats.net/) default blacklist (at the time of writing includes spamhaus DROP, dshield and abuse.ch trackers, which are available separately too - prefer to use the direct ipsets instead of this, they seem to lag a bit in updates)|ipv4 hash:net|1007 subnets, 18338646 unique IPs|updated every 12 hours  from [this link](http://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt)
[et_botcc](#et_botcc)|[EmergingThreats.net Command and Control IPs](http://doc.emergingthreats.net/bin/view/Main/BotCC) These IPs are updates every 24 hours and should be considered VERY highly reliable indications that a host is communicating with a known and active Bot or Malware command and control server - (although they say this includes abuse.ch trackers, it does not - most probably it is the shadowserver.org C&C list)|ipv4 hash:ip|508 unique IPs|updated every 12 hours  from [this link](http://rules.emergingthreats.net/fwrules/emerging-PIX-CC.rules)
[et_compromised](#et_compromised)|[EmergingThreats.net compromised hosts](http://doc.emergingthreats.net/bin/view/Main/CompromisedHost) - (this seems to be based on bruteforceblocker)|ipv4 hash:ip|2171 unique IPs|updated every 12 hours  from [this link](http://rules.emergingthreats.net/blockrules/compromised-ips.txt)
et_dshield|[EmergingThreats.net](http://www.emergingthreats.net/) dshield blocklist|ipv4 hash:net|disabled|updated every 12 hours  from [this link](http://rules.emergingthreats.net/fwrules/emerging-PIX-DSHIELD.rules)
et_spamhaus|[EmergingThreats.net](http://www.emergingthreats.net/) spamhaus blocklist|ipv4 hash:net|disabled|updated every 12 hours  from [this link](http://rules.emergingthreats.net/fwrules/emerging-PIX-DROP.rules)
[et_tor](#et_tor)|[EmergingThreats.net](http://www.emergingthreats.net/) [list](http://doc.emergingthreats.net/bin/view/Main/TorRules) of TOR network IPs|ipv4 hash:ip|6380 unique IPs|updated every 12 hours  from [this link](http://rules.emergingthreats.net/blockrules/emerging-tor.rules)
[feodo](#feodo)|[Abuse.ch Feodo tracker](https://feodotracker.abuse.ch) trojan includes IPs which are being used by Feodo (also known as Cridex or Bugat) which commits ebanking fraud - **excellent list**|ipv4 hash:ip|90 unique IPs|updated every 30 mins  from [this link](https://feodotracker.abuse.ch/blocklist/?download=ipblocklist)
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
[nixspam](#nixspam)|[NiX Spam](http://www.heise.de/ix/NiX-Spam-DNSBL-and-blacklist-for-download-499637.html) IP addresses that sent spam in the last hour - automatically generated entries without distinguishing open proxies from relays, dialup gateways, and so on. All IPs are removed after 12 hours if there is no spam from there.|ipv4 hash:ip|20978 unique IPs|updated every 15 mins  from [this link](http://www.dnsbl.manitu.net/download/nixspam-ip.dump.gz)
openbl|[OpenBL.org](http://www.openbl.org/) default blacklist (currently it is the same with 90 days). OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications - **excellent list**|ipv4 hash:ip|disabled|updated every 4 hours  from [this link](http://www.openbl.org/lists/base.txt)
openbl_180d|[OpenBL.org](http://www.openbl.org/) last 180 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|disabled|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_180days.txt)
[openbl_1d](#openbl_1d)|[OpenBL.org](http://www.openbl.org/) last 24 hours IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|189 unique IPs|updated every 1 hour  from [this link](http://www.openbl.org/lists/base_1days.txt)
[openbl_30d](#openbl_30d)|[OpenBL.org](http://www.openbl.org/) last 30 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|3255 unique IPs|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_30days.txt)
openbl_360d|[OpenBL.org](http://www.openbl.org/) last 360 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|disabled|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_360days.txt)
[openbl_60d](#openbl_60d)|[OpenBL.org](http://www.openbl.org/) last 60 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|7701 unique IPs|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_60days.txt)
[openbl_7d](#openbl_7d)|[OpenBL.org](http://www.openbl.org/) last 7 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|943 unique IPs|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_7days.txt)
openbl_90d|[OpenBL.org](http://www.openbl.org/) last 90 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|disabled|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_90days.txt)
openbl_all|[OpenBL.org](http://www.openbl.org/) last all IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|disabled|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_all.txt)
[palevo](#palevo)|[Abuse.ch Palevo tracker](https://palevotracker.abuse.ch) worm includes IPs which are being used as botnet C&C for the Palevo crimeware - **excellent list**|ipv4 hash:ip|13 unique IPs|updated every 30 mins  from [this link](https://palevotracker.abuse.ch/blocklists.php?download=ipblocklist)
php_bad|[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) bad web hosts (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|disabled|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=b&rss=1)
[php_commenters](#php_commenters)|[projecthoneypot.org](http://www.projecthoneypot.org/) comment spammers (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|281 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=c&rss=1)
[php_dictionary](#php_dictionary)|[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) directory attackers (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|433 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=d&rss=1)
[php_harvesters](#php_harvesters)|[projecthoneypot.org](http://www.projecthoneypot.org/) harvesters (IPs that surf the internet looking for email addresses) (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|257 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=h&rss=1)
[php_spammers](#php_spammers)|[projecthoneypot.org](http://www.projecthoneypot.org/) spam servers (IPs used by spammers to send messages) (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|417 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=s&rss=1)
[proxyrss](#proxyrss)|[proxyrss.com](http://www.proxyrss.com) open proxies syndicated from multiple sources.|ipv4 hash:ip|1604 unique IPs|updated every 4 hours  from [this link](http://www.proxyrss.com/proxylists/all.gz)
[proxz](#proxz)|[proxz.com](http://www.proxz.com) open proxies (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|702 unique IPs|updated every 1 hour  from [this link](http://www.proxz.com/proxylists.xml)
[ri_connect_proxies](#ri_connect_proxies)|[rosinstrument.com](http://www.rosinstrument.com) open CONNECT proxies (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|2310 unique IPs|updated every 1 hour  from [this link](http://tools.rosinstrument.com/proxy/plab100.xml)
[ri_web_proxies](#ri_web_proxies)|[rosinstrument.com](http://www.rosinstrument.com) open HTTP proxies (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|6153 unique IPs|updated every 1 hour  from [this link](http://tools.rosinstrument.com/proxy/l100.xml)
[shunlist](#shunlist)|[AutoShun.org](http://autoshun.org/) IPs identified as hostile by correlating logs from distributed snort installations running the autoshun plugin|ipv4 hash:ip|1272 unique IPs|updated every 4 hours  from [this link](http://www.autoshun.org/files/shunlist.csv)
[snort_ipfilter](#snort_ipfilter)|[labs.snort.org](https://labs.snort.org/) supplied IP blacklist (this list seems to be updated frequently, but we found no information about it)|ipv4 hash:ip|9369 unique IPs|updated every 12 hours  from [this link](http://labs.snort.org/feeds/ip-filter.blf)
[sorbs_dul](#sorbs_dul)|[Sorbs.net](https://www.sorbs.net/) DUL, Dynamic User IPs extracted from deltas.|ipv4 hash:net|8 subnets, 3584 unique IPs|updated every 1 min  from [this link]()
[sorbs_http](#sorbs_http)|[Sorbs.net](https://www.sorbs.net/) HTTP proxies, extracted from deltas.|ipv4 hash:net|23 subnets, 23 unique IPs|updated every 1 min  from [this link]()
[sorbs_misc](#sorbs_misc)|[Sorbs.net](https://www.sorbs.net/) MISC proxies, extracted from deltas.|ipv4 hash:net|23 subnets, 23 unique IPs|updated every 1 min  from [this link]()
[sorbs_smtp](#sorbs_smtp)|[Sorbs.net](https://www.sorbs.net/) SMTP Open Relays, extracted from deltas.|ipv4 hash:net|9 subnets, 9 unique IPs|updated every 1 min  from [this link]()
[sorbs_socks](#sorbs_socks)|[Sorbs.net](https://www.sorbs.net/) SOCKS proxies, extracted from deltas.|ipv4 hash:net|23 subnets, 23 unique IPs|updated every 1 min  from [this link]()
[sorbs_spam](#sorbs_spam)|[Sorbs.net](https://www.sorbs.net/) Spam senders, extracted from deltas.|ipv4 hash:net|23029 subnets, 23820 unique IPs|updated every 1 min  from [this link]()
[sorbs_web](#sorbs_web)|[Sorbs.net](https://www.sorbs.net/) WEB exploits, extracted from deltas.|ipv4 hash:net|656 subnets, 657 unique IPs|updated every 1 min  from [this link]()
[spamhaus_drop](#spamhaus_drop)|[Spamhaus.org](http://www.spamhaus.org) DROP list (according to their site this list should be dropped at tier-1 ISPs globaly) - **excellent list**|ipv4 hash:net|654 subnets, 18469632 unique IPs|updated every 12 hours  from [this link](http://www.spamhaus.org/drop/drop.txt)
[spamhaus_edrop](#spamhaus_edrop)|[Spamhaus.org](http://www.spamhaus.org) EDROP (extended matches that should be used with DROP) - **excellent list**|ipv4 hash:net|55 subnets, 486400 unique IPs|updated every 12 hours  from [this link](http://www.spamhaus.org/drop/edrop.txt)
[sslbl](#sslbl)|[Abuse.ch SSL Blacklist](https://sslbl.abuse.ch/) bad SSL traffic related to malware or botnet activities - **excellent list**|ipv4 hash:ip|366 unique IPs|updated every 30 mins  from [this link](https://sslbl.abuse.ch/blacklist/sslipblacklist.csv)
stopforumspam_180d|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 180 days)|ipv4 hash:ip|disabled|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/listed_ip_180.zip)
[stopforumspam_1d](#stopforumspam_1d)|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers in the last 24 hours - **excellent list**|ipv4 hash:ip|7074 unique IPs|updated every 1 hour  from [this link](http://www.stopforumspam.com/downloads/listed_ip_1.zip)
[stopforumspam_30d](#stopforumspam_30d)|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 30 days)|ipv4 hash:ip|92996 unique IPs|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/listed_ip_30.zip)
stopforumspam_365d|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 365 days)|ipv4 hash:ip|disabled|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/listed_ip_365.zip)
[stopforumspam_7d](#stopforumspam_7d)|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 7 days)|ipv4 hash:ip|30334 unique IPs|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/listed_ip_7.zip)
stopforumspam_90d|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 90 days)|ipv4 hash:ip|disabled|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/listed_ip_90.zip)
stopforumspam_ever|[StopForumSpam.com](http://www.stopforumspam.com) all IPs used by forum spammers, **ever** (normally you don't want to use this ipset, use the hourly one which includes last 24 hours IPs or the 7 days one)|ipv4 hash:ip|disabled|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/bannedips.zip)
[virbl](#virbl)|[VirBL](http://virbl.bit.nl/) is a project of which the idea was born during the RIPE-48 meeting. The plan was to get reports of virusscanning mailservers, and put the IP-addresses that were reported to send viruses on a blacklist.|ipv4 hash:ip|12 unique IPs|updated every 1 hour  from [this link](http://virbl.bit.nl/download/virbl.dnsbl.bit.nl.txt)
[voipbl](#voipbl)|[VoIPBL.org](http://www.voipbl.org/) a distributed VoIP blacklist that is aimed to protects against VoIP Fraud and minimizing abuse for network that have publicly accessible PBX's. Several algorithms, external sources and manual confirmation are used before they categorize something as an attack and determine the threat level.|ipv4 hash:net|10398 subnets, 10808 unique IPs|updated every 4 hours  from [this link](http://www.voipbl.org/update/)
[xroxy](#xroxy)|[xroxy.com](http://www.xroxy.com) open proxies (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|2059 unique IPs|updated every 1 hour  from [this link](http://www.xroxy.com/proxyrss.xml)
[zeus](#zeus)|[Abuse.ch Zeus tracker](https://zeustracker.abuse.ch) standard, contains the same data as the ZeuS IP blocklist (zeus_badips) but with the slight difference that it doesn't exclude hijacked websites (level 2) and free web hosting providers (level 3). This means that this blocklist contains all IPv4 addresses associated with ZeuS C&Cs which are currently being tracked by ZeuS Tracker. Hence this blocklist will likely cause some false positives. - **excellent list**|ipv4 hash:ip|268 unique IPs|updated every 30 mins  from [this link](https://zeustracker.abuse.ch/blocklist.php?download=ipblocklist)
[zeus_badips](#zeus_badips)|[Abuse.ch Zeus tracker](https://zeustracker.abuse.ch) badips includes IPv4 addresses that are used by the ZeuS trojan. It is the recommened blocklist if you want to block only ZeuS IPs. It excludes IP addresses that ZeuS Tracker believes to be hijacked (level 2) or belong to a free web hosting provider (level 3). Hence the false postive rate should be much lower compared to the standard ZeuS IP blocklist. **excellent list**|ipv4 hash:ip|235 unique IPs|updated every 30 mins  from [this link](https://zeustracker.abuse.ch/blocklist.php?download=badips)

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
[openbl_60d](#openbl_60d)|7701|7701|7676|99.6%|4.3%|
[et_block](#et_block)|1007|18338646|5793|0.0%|3.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|4471|0.0%|2.5%|
[dshield](#dshield)|20|5120|3589|70.0%|2.0%|
[openbl_30d](#openbl_30d)|3255|3255|3236|99.4%|1.8%|
[blocklist_de](#blocklist_de)|38212|38212|2263|5.9%|1.2%|
[blocklist_de_ssh](#blocklist_de_ssh)|14281|14281|2017|14.1%|1.1%|
[spamhaus_drop](#spamhaus_drop)|654|18469632|1885|0.0%|1.0%|
[et_compromised](#et_compromised)|2171|2171|1406|64.7%|0.7%|
[bruteforceblocker](#bruteforceblocker)|2052|2052|1336|65.1%|0.7%|
[shunlist](#shunlist)|1272|1272|1265|99.4%|0.7%|
[openbl_7d](#openbl_7d)|943|943|933|98.9%|0.5%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|518|0.0%|0.2%|
[ciarmy](#ciarmy)|343|343|330|96.2%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|287|0.0%|0.1%|
[stopforumspam_30d](#stopforumspam_30d)|92996|92996|218|0.2%|0.1%|
[voipbl](#voipbl)|10398|10808|200|1.8%|0.1%|
[openbl_1d](#openbl_1d)|189|189|184|97.3%|0.1%|
[blocklist_de_apache](#blocklist_de_apache)|13522|13522|133|0.9%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9369|9369|122|1.3%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|30334|30334|106|0.3%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|17398|17398|74|0.4%|0.0%|
[zeus](#zeus)|268|268|65|24.2%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7074|7074|64|0.9%|0.0%|
[sslbl](#sslbl)|366|366|64|17.4%|0.0%|
[sorbs_spam](#sorbs_spam)|23029|23820|62|0.2%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|3124|3124|45|1.4%|0.0%|
[dm_tor](#dm_tor)|6585|6585|43|0.6%|0.0%|
[bm_tor](#bm_tor)|6584|6584|43|0.6%|0.0%|
[et_tor](#et_tor)|6380|6380|42|0.6%|0.0%|
[zeus_badips](#zeus_badips)|235|235|39|16.5%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|178|178|34|19.1%|0.0%|
[nixspam](#nixspam)|20978|20978|27|0.1%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|25|6.7%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3113|3113|25|0.8%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|105|105|18|17.1%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2186|2186|16|0.7%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|486400|15|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|15|0.0%|0.0%|
[php_commenters](#php_commenters)|281|281|14|4.9%|0.0%|
[malc0de](#malc0de)|379|379|11|2.9%|0.0%|
[php_harvesters](#php_harvesters)|257|257|8|3.1%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|8|0.5%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|206|206|7|3.3%|0.0%|
[php_dictionary](#php_dictionary)|433|433|6|1.3%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|6|0.4%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|877|877|6|0.6%|0.0%|
[xroxy](#xroxy)|2059|2059|5|0.2%|0.0%|
[et_botcc](#et_botcc)|508|508|4|0.7%|0.0%|
[ri_web_proxies](#ri_web_proxies)|6153|6153|3|0.0%|0.0%|
[proxz](#proxz)|702|702|3|0.4%|0.0%|
[php_spammers](#php_spammers)|417|417|3|0.7%|0.0%|
[virbl](#virbl)|12|12|2|16.6%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2310|2310|2|0.0%|0.0%|
[proxyrss](#proxyrss)|1604|1604|2|0.1%|0.0%|
[feodo](#feodo)|90|90|2|2.2%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|1|0.1%|0.0%|

## blocklist_de

[Blocklist.de](https://www.blocklist.de/) IPs that have been detected by fail2ban in the last 48 hours - **excellent list**

Source is downloaded from [this link](http://lists.blocklist.de/lists/all.txt).

The last time downloaded was found to be dated: Thu Jun  4 13:14:03 UTC 2015.

The ipset `blocklist_de` has **38212** entries, **38212** unique IPs.

The following table shows the overlaps of `blocklist_de` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de`.
- ` this % ` is the percentage **of this ipset (`blocklist_de`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de_mail](#blocklist_de_mail)|17398|17398|17367|99.8%|45.4%|
[blocklist_de_ssh](#blocklist_de_ssh)|14281|14281|14281|100.0%|37.3%|
[blocklist_de_apache](#blocklist_de_apache)|13522|13522|13509|99.9%|35.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|6928|0.0%|18.1%|
[blocklist_de_imap](#blocklist_de_imap)|3124|3124|3123|99.9%|8.1%|
[blocklist_de_bots](#blocklist_de_bots)|3113|3113|3104|99.7%|8.1%|
[stopforumspam_30d](#stopforumspam_30d)|92996|92996|2558|2.7%|6.6%|
[alienvault_reputation](#alienvault_reputation)|178477|178477|2263|1.2%|5.9%|
[stopforumspam_7d](#stopforumspam_7d)|30334|30334|2180|7.1%|5.7%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2186|2186|2174|99.4%|5.6%|
[openbl_60d](#openbl_60d)|7701|7701|1902|24.6%|4.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|1595|0.0%|4.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|1564|0.0%|4.0%|
[stopforumspam_1d](#stopforumspam_1d)|7074|7074|1475|20.8%|3.8%|
[sorbs_spam](#sorbs_spam)|23029|23820|985|4.1%|2.5%|
[openbl_30d](#openbl_30d)|3255|3255|908|27.8%|2.3%|
[blocklist_de_ftp](#blocklist_de_ftp)|877|877|874|99.6%|2.2%|
[bruteforceblocker](#bruteforceblocker)|2052|2052|685|33.3%|1.7%|
[nixspam](#nixspam)|20978|20978|684|3.2%|1.7%|
[et_compromised](#et_compromised)|2171|2171|668|30.7%|1.7%|
[openbl_7d](#openbl_7d)|943|943|612|64.8%|1.6%|
[shunlist](#shunlist)|1272|1272|402|31.6%|1.0%|
[ri_web_proxies](#ri_web_proxies)|6153|6153|395|6.4%|1.0%|
[xroxy](#xroxy)|2059|2059|257|12.4%|0.6%|
[proxyrss](#proxyrss)|1604|1604|250|15.5%|0.6%|
[blocklist_de_strongips](#blocklist_de_strongips)|178|178|178|100.0%|0.4%|
[snort_ipfilter](#snort_ipfilter)|9369|9369|170|1.8%|0.4%|
[openbl_1d](#openbl_1d)|189|189|162|85.7%|0.4%|
[et_block](#et_block)|1007|18338646|160|0.0%|0.4%|
[spamhaus_drop](#spamhaus_drop)|654|18469632|155|0.0%|0.4%|
[proxz](#proxz)|702|702|131|18.6%|0.3%|
[dshield](#dshield)|20|5120|124|2.4%|0.3%|
[blocklist_de_sip](#blocklist_de_sip)|105|105|86|81.9%|0.2%|
[sorbs_web](#sorbs_web)|656|657|82|12.4%|0.2%|
[ri_connect_proxies](#ri_connect_proxies)|2310|2310|72|3.1%|0.1%|
[php_commenters](#php_commenters)|281|281|65|23.1%|0.1%|
[php_dictionary](#php_dictionary)|433|433|57|13.1%|0.1%|
[php_spammers](#php_spammers)|417|417|52|12.4%|0.1%|
[voipbl](#voipbl)|10398|10808|42|0.3%|0.1%|
[ciarmy](#ciarmy)|343|343|42|12.2%|0.1%|
[php_harvesters](#php_harvesters)|257|257|27|10.5%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|27|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|486400|12|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|11|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|8|0.0%|0.0%|
[sorbs_socks](#sorbs_socks)|23|23|5|21.7%|0.0%|
[sorbs_misc](#sorbs_misc)|23|23|5|21.7%|0.0%|
[sorbs_http](#sorbs_http)|23|23|5|21.7%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|5|0.7%|0.0%|
[dm_tor](#dm_tor)|6585|6585|4|0.0%|0.0%|
[bm_tor](#bm_tor)|6584|6584|4|0.0%|0.0%|
[et_tor](#et_tor)|6380|6380|3|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|2|0.5%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.0%|

## blocklist_de_apache

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service Apache, Apache-DDOS, RFI-Attacks.

Source is downloaded from [this link](http://lists.blocklist.de/lists/apache.txt).

The last time downloaded was found to be dated: Thu Jun  4 12:56:06 UTC 2015.

The ipset `blocklist_de_apache` has **13522** entries, **13522** unique IPs.

The following table shows the overlaps of `blocklist_de_apache` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_apache`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_apache`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_apache`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|38212|38212|13509|35.3%|99.9%|
[blocklist_de_mail](#blocklist_de_mail)|17398|17398|11059|63.5%|81.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|2278|0.0%|16.8%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2186|2186|2186|100.0%|16.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|1328|0.0%|9.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|1073|0.0%|7.9%|
[stopforumspam_30d](#stopforumspam_30d)|92996|92996|205|0.2%|1.5%|
[alienvault_reputation](#alienvault_reputation)|178477|178477|133|0.0%|0.9%|
[stopforumspam_7d](#stopforumspam_7d)|30334|30334|126|0.4%|0.9%|
[stopforumspam_1d](#stopforumspam_1d)|7074|7074|75|1.0%|0.5%|
[sorbs_spam](#sorbs_spam)|23029|23820|53|0.2%|0.3%|
[shunlist](#shunlist)|1272|1272|38|2.9%|0.2%|
[ciarmy](#ciarmy)|343|343|37|10.7%|0.2%|
[blocklist_de_strongips](#blocklist_de_strongips)|178|178|36|20.2%|0.2%|
[php_commenters](#php_commenters)|281|281|24|8.5%|0.1%|
[nixspam](#nixspam)|20978|20978|24|0.1%|0.1%|
[blocklist_de_bots](#blocklist_de_bots)|3113|3113|23|0.7%|0.1%|
[snort_ipfilter](#snort_ipfilter)|9369|9369|8|0.0%|0.0%|
[dshield](#dshield)|20|5120|7|0.1%|0.0%|
[php_spammers](#php_spammers)|417|417|5|1.1%|0.0%|
[et_block](#et_block)|1007|18338646|5|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|4|1.5%|0.0%|
[openbl_60d](#openbl_60d)|7701|7701|4|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|4|0.0%|0.0%|
[dm_tor](#dm_tor)|6585|6585|4|0.0%|0.0%|
[bm_tor](#bm_tor)|6584|6584|4|0.0%|0.0%|
[sorbs_web](#sorbs_web)|656|657|3|0.4%|0.0%|
[php_dictionary](#php_dictionary)|433|433|3|0.6%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|3|0.0%|0.0%|
[et_tor](#et_tor)|6380|6380|3|0.0%|0.0%|
[et_compromised](#et_compromised)|2171|2171|3|0.1%|0.0%|
[voipbl](#voipbl)|10398|10808|2|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|486400|2|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|654|18469632|2|0.0%|0.0%|
[openbl_30d](#openbl_30d)|3255|3255|2|0.0%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2052|2052|2|0.0%|0.0%|
[xroxy](#xroxy)|2059|2059|1|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|6153|6153|1|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2310|2310|1|0.0%|0.0%|
[proxz](#proxz)|702|702|1|0.1%|0.0%|
[proxyrss](#proxyrss)|1604|1604|1|0.0%|0.0%|
[openbl_7d](#openbl_7d)|943|943|1|0.1%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|

## blocklist_de_bots

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the RFI-Attacks, REG-Bots, IRC-Bots or BadBots (BadBots = he has posted a Spam-Comment on a open Forum or Wiki).

Source is downloaded from [this link](http://lists.blocklist.de/lists/bots.txt).

The last time downloaded was found to be dated: Thu Jun  4 12:56:09 UTC 2015.

The ipset `blocklist_de_bots` has **3113** entries, **3113** unique IPs.

The following table shows the overlaps of `blocklist_de_bots` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_bots`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_bots`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_bots`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|38212|38212|3104|8.1%|99.7%|
[stopforumspam_30d](#stopforumspam_30d)|92996|92996|2146|2.3%|68.9%|
[stopforumspam_7d](#stopforumspam_7d)|30334|30334|1979|6.5%|63.5%|
[stopforumspam_1d](#stopforumspam_1d)|7074|7074|1386|19.5%|44.5%|
[ri_web_proxies](#ri_web_proxies)|6153|6153|341|5.5%|10.9%|
[proxyrss](#proxyrss)|1604|1604|247|15.3%|7.9%|
[xroxy](#xroxy)|2059|2059|205|9.9%|6.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|154|0.0%|4.9%|
[blocklist_de_strongips](#blocklist_de_strongips)|178|178|135|75.8%|4.3%|
[proxz](#proxz)|702|702|109|15.5%|3.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|85|0.0%|2.7%|
[ri_connect_proxies](#ri_connect_proxies)|2310|2310|68|2.9%|2.1%|
[php_commenters](#php_commenters)|281|281|51|18.1%|1.6%|
[nixspam](#nixspam)|20978|20978|44|0.2%|1.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|42|0.0%|1.3%|
[sorbs_spam](#sorbs_spam)|23029|23820|34|0.1%|1.0%|
[alienvault_reputation](#alienvault_reputation)|178477|178477|25|0.0%|0.8%|
[blocklist_de_mail](#blocklist_de_mail)|17398|17398|23|0.1%|0.7%|
[blocklist_de_apache](#blocklist_de_apache)|13522|13522|23|0.1%|0.7%|
[spamhaus_drop](#spamhaus_drop)|654|18469632|21|0.0%|0.6%|
[et_block](#et_block)|1007|18338646|21|0.0%|0.6%|
[snort_ipfilter](#snort_ipfilter)|9369|9369|19|0.2%|0.6%|
[php_harvesters](#php_harvesters)|257|257|18|7.0%|0.5%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|13|0.0%|0.4%|
[sorbs_web](#sorbs_web)|656|657|11|1.6%|0.3%|
[php_dictionary](#php_dictionary)|433|433|10|2.3%|0.3%|
[php_spammers](#php_spammers)|417|417|8|1.9%|0.2%|
[spamhaus_edrop](#spamhaus_edrop)|55|486400|4|0.0%|0.1%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|4|0.5%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|3|0.0%|0.0%|
[sorbs_socks](#sorbs_socks)|23|23|2|8.6%|0.0%|
[sorbs_misc](#sorbs_misc)|23|23|2|8.6%|0.0%|
[sorbs_http](#sorbs_http)|23|23|2|8.6%|0.0%|
[voipbl](#voipbl)|10398|10808|1|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|
[et_compromised](#et_compromised)|2171|2171|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2052|2052|1|0.0%|0.0%|

## blocklist_de_bruteforce

[Blocklist.de](https://www.blocklist.de/) All IPs which attacks Joomlas, Wordpress and other Web-Logins with Brute-Force Logins.

Source is downloaded from [this link](http://lists.blocklist.de/lists/bruteforcelogin.txt).

The last time downloaded was found to be dated: Thu Jun  4 12:56:09 UTC 2015.

The ipset `blocklist_de_bruteforce` has **2186** entries, **2186** unique IPs.

The following table shows the overlaps of `blocklist_de_bruteforce` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_bruteforce`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_bruteforce`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_bruteforce`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de_apache](#blocklist_de_apache)|13522|13522|2186|16.1%|100.0%|
[blocklist_de](#blocklist_de)|38212|38212|2174|5.6%|99.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|181|0.0%|8.2%|
[sorbs_spam](#sorbs_spam)|23029|23820|53|0.2%|2.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|39|0.0%|1.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|39|0.0%|1.7%|
[stopforumspam_30d](#stopforumspam_30d)|92996|92996|37|0.0%|1.6%|
[stopforumspam_7d](#stopforumspam_7d)|30334|30334|27|0.0%|1.2%|
[stopforumspam_1d](#stopforumspam_1d)|7074|7074|22|0.3%|1.0%|
[nixspam](#nixspam)|20978|20978|22|0.1%|1.0%|
[alienvault_reputation](#alienvault_reputation)|178477|178477|16|0.0%|0.7%|
[blocklist_de_strongips](#blocklist_de_strongips)|178|178|8|4.4%|0.3%|
[php_spammers](#php_spammers)|417|417|5|1.1%|0.2%|
[php_commenters](#php_commenters)|281|281|5|1.7%|0.2%|
[snort_ipfilter](#snort_ipfilter)|9369|9369|4|0.0%|0.1%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|4|0.0%|0.1%|
[sorbs_web](#sorbs_web)|656|657|3|0.4%|0.1%|
[shunlist](#shunlist)|1272|1272|3|0.2%|0.1%|
[php_harvesters](#php_harvesters)|257|257|3|1.1%|0.1%|
[php_dictionary](#php_dictionary)|433|433|3|0.6%|0.1%|
[spamhaus_drop](#spamhaus_drop)|654|18469632|2|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|2|0.0%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2|0.0%|0.0%|
[et_block](#et_block)|1007|18338646|2|0.0%|0.0%|
[xroxy](#xroxy)|2059|2059|1|0.0%|0.0%|
[voipbl](#voipbl)|10398|10808|1|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|6153|6153|1|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2310|2310|1|0.0%|0.0%|
[proxz](#proxz)|702|702|1|0.1%|0.0%|
[proxyrss](#proxyrss)|1604|1604|1|0.0%|0.0%|

## blocklist_de_ftp

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours for attacks on the Service FTP.

Source is downloaded from [this link](http://lists.blocklist.de/lists/ftp.txt).

The last time downloaded was found to be dated: Thu Jun  4 12:56:06 UTC 2015.

The ipset `blocklist_de_ftp` has **877** entries, **877** unique IPs.

The following table shows the overlaps of `blocklist_de_ftp` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_ftp`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_ftp`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_ftp`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|38212|38212|874|2.2%|99.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|73|0.0%|8.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|16|0.0%|1.8%|
[stopforumspam_30d](#stopforumspam_30d)|92996|92996|11|0.0%|1.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|10|0.0%|1.1%|
[stopforumspam_7d](#stopforumspam_7d)|30334|30334|6|0.0%|0.6%|
[alienvault_reputation](#alienvault_reputation)|178477|178477|6|0.0%|0.6%|
[sorbs_spam](#sorbs_spam)|23029|23820|5|0.0%|0.5%|
[nixspam](#nixspam)|20978|20978|5|0.0%|0.5%|
[stopforumspam_1d](#stopforumspam_1d)|7074|7074|2|0.0%|0.2%|
[php_harvesters](#php_harvesters)|257|257|2|0.7%|0.2%|
[spamhaus_edrop](#spamhaus_edrop)|55|486400|1|0.0%|0.1%|
[ciarmy](#ciarmy)|343|343|1|0.2%|0.1%|

## blocklist_de_imap

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours for attacks on the Service imap, sasl, pop3, etc.

Source is downloaded from [this link](http://lists.blocklist.de/lists/imap.txt).

The last time downloaded was found to be dated: Thu Jun  4 12:56:06 UTC 2015.

The ipset `blocklist_de_imap` has **3124** entries, **3124** unique IPs.

The following table shows the overlaps of `blocklist_de_imap` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_imap`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_imap`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_imap`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de_mail](#blocklist_de_mail)|17398|17398|3124|17.9%|100.0%|
[blocklist_de](#blocklist_de)|38212|38212|3123|8.1%|99.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|380|0.0%|12.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|61|0.0%|1.9%|
[alienvault_reputation](#alienvault_reputation)|178477|178477|45|0.0%|1.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|37|0.0%|1.1%|
[openbl_60d](#openbl_60d)|7701|7701|33|0.4%|1.0%|
[openbl_30d](#openbl_30d)|3255|3255|31|0.9%|0.9%|
[sorbs_spam](#sorbs_spam)|23029|23820|24|0.1%|0.7%|
[nixspam](#nixspam)|20978|20978|23|0.1%|0.7%|
[openbl_7d](#openbl_7d)|943|943|12|1.2%|0.3%|
[stopforumspam_30d](#stopforumspam_30d)|92996|92996|10|0.0%|0.3%|
[spamhaus_drop](#spamhaus_drop)|654|18469632|9|0.0%|0.2%|
[et_block](#et_block)|1007|18338646|9|0.0%|0.2%|
[et_compromised](#et_compromised)|2171|2171|6|0.2%|0.1%|
[bruteforceblocker](#bruteforceblocker)|2052|2052|6|0.2%|0.1%|
[snort_ipfilter](#snort_ipfilter)|9369|9369|5|0.0%|0.1%|
[shunlist](#shunlist)|1272|1272|4|0.3%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|30334|30334|2|0.0%|0.0%|
[openbl_1d](#openbl_1d)|189|189|2|1.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|2|0.0%|0.0%|
[voipbl](#voipbl)|10398|10808|1|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7074|7074|1|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|486400|1|0.0%|0.0%|
[sorbs_web](#sorbs_web)|656|657|1|0.1%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1|0.0%|0.0%|
[ciarmy](#ciarmy)|343|343|1|0.2%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|14281|14281|1|0.0%|0.0%|

## blocklist_de_mail

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service Mail, Postfix.

Source is downloaded from [this link](http://lists.blocklist.de/lists/mail.txt).

The last time downloaded was found to be dated: Thu Jun  4 12:56:05 UTC 2015.

The ipset `blocklist_de_mail` has **17398** entries, **17398** unique IPs.

The following table shows the overlaps of `blocklist_de_mail` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_mail`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_mail`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_mail`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|38212|38212|17367|45.4%|99.8%|
[blocklist_de_apache](#blocklist_de_apache)|13522|13522|11059|81.7%|63.5%|
[blocklist_de_imap](#blocklist_de_imap)|3124|3124|3124|100.0%|17.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|2583|0.0%|14.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|1366|0.0%|7.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|1175|0.0%|6.7%|
[sorbs_spam](#sorbs_spam)|23029|23820|826|3.4%|4.7%|
[nixspam](#nixspam)|20978|20978|607|2.8%|3.4%|
[stopforumspam_30d](#stopforumspam_30d)|92996|92996|251|0.2%|1.4%|
[stopforumspam_7d](#stopforumspam_7d)|30334|30334|147|0.4%|0.8%|
[snort_ipfilter](#snort_ipfilter)|9369|9369|145|1.5%|0.8%|
[alienvault_reputation](#alienvault_reputation)|178477|178477|74|0.0%|0.4%|
[sorbs_web](#sorbs_web)|656|657|67|10.1%|0.3%|
[stopforumspam_1d](#stopforumspam_1d)|7074|7074|56|0.7%|0.3%|
[ri_web_proxies](#ri_web_proxies)|6153|6153|54|0.8%|0.3%|
[xroxy](#xroxy)|2059|2059|51|2.4%|0.2%|
[php_dictionary](#php_dictionary)|433|433|44|10.1%|0.2%|
[openbl_60d](#openbl_60d)|7701|7701|41|0.5%|0.2%|
[php_spammers](#php_spammers)|417|417|39|9.3%|0.2%|
[openbl_30d](#openbl_30d)|3255|3255|39|1.1%|0.2%|
[blocklist_de_strongips](#blocklist_de_strongips)|178|178|23|12.9%|0.1%|
[blocklist_de_bots](#blocklist_de_bots)|3113|3113|23|0.7%|0.1%|
[et_block](#et_block)|1007|18338646|21|0.0%|0.1%|
[proxz](#proxz)|702|702|20|2.8%|0.1%|
[php_commenters](#php_commenters)|281|281|20|7.1%|0.1%|
[spamhaus_drop](#spamhaus_drop)|654|18469632|19|0.0%|0.1%|
[openbl_7d](#openbl_7d)|943|943|15|1.5%|0.0%|
[et_compromised](#et_compromised)|2171|2171|9|0.4%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2052|2052|8|0.3%|0.0%|
[shunlist](#shunlist)|1272|1272|5|0.3%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|5|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|486400|4|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|4|1.5%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|4|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|4|0.0%|0.0%|
[dm_tor](#dm_tor)|6585|6585|4|0.0%|0.0%|
[bm_tor](#bm_tor)|6584|6584|4|0.0%|0.0%|
[sorbs_socks](#sorbs_socks)|23|23|3|13.0%|0.0%|
[sorbs_misc](#sorbs_misc)|23|23|3|13.0%|0.0%|
[sorbs_http](#sorbs_http)|23|23|3|13.0%|0.0%|
[openbl_1d](#openbl_1d)|189|189|3|1.5%|0.0%|
[et_tor](#et_tor)|6380|6380|3|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2310|2310|2|0.0%|0.0%|
[dshield](#dshield)|20|5120|2|0.0%|0.0%|
[voipbl](#voipbl)|10398|10808|1|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|1|0.1%|0.0%|
[ciarmy](#ciarmy)|343|343|1|0.2%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|14281|14281|1|0.0%|0.0%|

## blocklist_de_sip

[Blocklist.de](https://www.blocklist.de/) All IP addresses that tried to login in a SIP, VOIP or Asterisk Server and are included in the IPs list from [infiltrated.net](www.infiltrated.net)

Source is downloaded from [this link](http://lists.blocklist.de/lists/sip.txt).

The last time downloaded was found to be dated: Thu Jun  4 12:56:06 UTC 2015.

The ipset `blocklist_de_sip` has **105** entries, **105** unique IPs.

The following table shows the overlaps of `blocklist_de_sip` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_sip`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_sip`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_sip`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|38212|38212|86|0.2%|81.9%|
[voipbl](#voipbl)|10398|10808|35|0.3%|33.3%|
[alienvault_reputation](#alienvault_reputation)|178477|178477|18|0.0%|17.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|14|0.0%|13.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|10|0.0%|9.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|5|0.0%|4.7%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|2|0.0%|1.9%|
[spamhaus_drop](#spamhaus_drop)|654|18469632|1|0.0%|0.9%|
[et_botcc](#et_botcc)|508|508|1|0.1%|0.9%|
[et_block](#et_block)|1007|18338646|1|0.0%|0.9%|
[ciarmy](#ciarmy)|343|343|1|0.2%|0.9%|

## blocklist_de_ssh

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service SSH.

Source is downloaded from [this link](http://lists.blocklist.de/lists/ssh.txt).

The last time downloaded was found to be dated: Thu Jun  4 13:10:06 UTC 2015.

The ipset `blocklist_de_ssh` has **14281** entries, **14281** unique IPs.

The following table shows the overlaps of `blocklist_de_ssh` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_ssh`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_ssh`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_ssh`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|38212|38212|14281|37.3%|100.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|3896|0.0%|27.2%|
[alienvault_reputation](#alienvault_reputation)|178477|178477|2017|1.1%|14.1%|
[openbl_60d](#openbl_60d)|7701|7701|1857|24.1%|13.0%|
[openbl_30d](#openbl_30d)|3255|3255|867|26.6%|6.0%|
[bruteforceblocker](#bruteforceblocker)|2052|2052|674|32.8%|4.7%|
[et_compromised](#et_compromised)|2171|2171|654|30.1%|4.5%|
[openbl_7d](#openbl_7d)|943|943|596|63.2%|4.1%|
[shunlist](#shunlist)|1272|1272|361|28.3%|2.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|232|0.0%|1.6%|
[openbl_1d](#openbl_1d)|189|189|159|84.1%|1.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|129|0.0%|0.9%|
[dshield](#dshield)|20|5120|116|2.2%|0.8%|
[et_block](#et_block)|1007|18338646|113|0.0%|0.7%|
[spamhaus_drop](#spamhaus_drop)|654|18469632|111|0.0%|0.7%|
[stopforumspam_30d](#stopforumspam_30d)|92996|92996|101|0.1%|0.7%|
[sorbs_spam](#sorbs_spam)|23029|23820|76|0.3%|0.5%|
[blocklist_de_strongips](#blocklist_de_strongips)|178|178|26|14.6%|0.1%|
[stopforumspam_7d](#stopforumspam_7d)|30334|30334|14|0.0%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|7|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7074|7074|5|0.0%|0.0%|
[nixspam](#nixspam)|20978|20978|5|0.0%|0.0%|
[voipbl](#voipbl)|10398|10808|3|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|2|0.0%|0.0%|
[xroxy](#xroxy)|2059|2059|1|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|486400|1|0.0%|0.0%|
[sorbs_web](#sorbs_web)|656|657|1|0.1%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9369|9369|1|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2310|2310|1|0.0%|0.0%|
[proxz](#proxz)|702|702|1|0.1%|0.0%|
[proxyrss](#proxyrss)|1604|1604|1|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|
[ciarmy](#ciarmy)|343|343|1|0.2%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|17398|17398|1|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|3124|3124|1|0.0%|0.0%|

## blocklist_de_strongips

[Blocklist.de](https://www.blocklist.de/) All IPs which are older then 2 month and have more then 5.000 attacks.

Source is downloaded from [this link](http://lists.blocklist.de/lists/strongips.txt).

The last time downloaded was found to be dated: Thu Jun  4 13:10:12 UTC 2015.

The ipset `blocklist_de_strongips` has **178** entries, **178** unique IPs.

The following table shows the overlaps of `blocklist_de_strongips` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_strongips`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_strongips`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_strongips`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|38212|38212|178|0.4%|100.0%|
[blocklist_de_bots](#blocklist_de_bots)|3113|3113|135|4.3%|75.8%|
[stopforumspam_30d](#stopforumspam_30d)|92996|92996|133|0.1%|74.7%|
[stopforumspam_7d](#stopforumspam_7d)|30334|30334|122|0.4%|68.5%|
[stopforumspam_1d](#stopforumspam_1d)|7074|7074|104|1.4%|58.4%|
[blocklist_de_apache](#blocklist_de_apache)|13522|13522|36|0.2%|20.2%|
[alienvault_reputation](#alienvault_reputation)|178477|178477|34|0.0%|19.1%|
[php_commenters](#php_commenters)|281|281|32|11.3%|17.9%|
[blocklist_de_ssh](#blocklist_de_ssh)|14281|14281|26|0.1%|14.6%|
[openbl_60d](#openbl_60d)|7701|7701|25|0.3%|14.0%|
[openbl_7d](#openbl_7d)|943|943|23|2.4%|12.9%|
[openbl_30d](#openbl_30d)|3255|3255|23|0.7%|12.9%|
[blocklist_de_mail](#blocklist_de_mail)|17398|17398|23|0.1%|12.9%|
[openbl_1d](#openbl_1d)|189|189|21|11.1%|11.7%|
[shunlist](#shunlist)|1272|1272|20|1.5%|11.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|15|0.0%|8.4%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2186|2186|8|0.3%|4.4%|
[xroxy](#xroxy)|2059|2059|7|0.3%|3.9%|
[spamhaus_drop](#spamhaus_drop)|654|18469632|6|0.0%|3.3%|
[ri_web_proxies](#ri_web_proxies)|6153|6153|6|0.0%|3.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|6|0.0%|3.3%|
[et_block](#et_block)|1007|18338646|6|0.0%|3.3%|
[spamhaus_edrop](#spamhaus_edrop)|55|486400|5|0.0%|2.8%|
[proxyrss](#proxyrss)|1604|1604|4|0.2%|2.2%|
[php_spammers](#php_spammers)|417|417|4|0.9%|2.2%|
[proxz](#proxz)|702|702|3|0.4%|1.6%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|1.6%|
[php_harvesters](#php_harvesters)|257|257|2|0.7%|1.1%|
[php_dictionary](#php_dictionary)|433|433|2|0.4%|1.1%|
[nixspam](#nixspam)|20978|20978|2|0.0%|1.1%|
[sorbs_web](#sorbs_web)|656|657|1|0.1%|0.5%|
[sorbs_spam](#sorbs_spam)|23029|23820|1|0.0%|0.5%|
[snort_ipfilter](#snort_ipfilter)|9369|9369|1|0.0%|0.5%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|1|0.0%|0.5%|

## bm_tor

[torstatus.blutmagie.de](https://torstatus.blutmagie.de) list of all TOR network servers

Source is downloaded from [this link](https://torstatus.blutmagie.de/ip_list_all.php/Tor_ip_list_ALL.csv).

The last time downloaded was found to be dated: Thu Jun  4 13:09:05 UTC 2015.

The ipset `bm_tor` has **6584** entries, **6584** unique IPs.

The following table shows the overlaps of `bm_tor` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `bm_tor`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `bm_tor`.
- ` this % ` is the percentage **of this ipset (`bm_tor`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[dm_tor](#dm_tor)|6585|6585|6501|98.7%|98.7%|
[et_tor](#et_tor)|6380|6380|5733|89.8%|87.0%|
[snort_ipfilter](#snort_ipfilter)|9369|9369|1067|11.3%|16.2%|
[stopforumspam_30d](#stopforumspam_30d)|92996|92996|630|0.6%|9.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|627|0.0%|9.5%|
[stopforumspam_7d](#stopforumspam_7d)|30334|30334|489|1.6%|7.4%|
[stopforumspam_1d](#stopforumspam_1d)|7074|7074|323|4.5%|4.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|190|0.0%|2.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|170|0.0%|2.5%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|169|45.4%|2.5%|
[alienvault_reputation](#alienvault_reputation)|178477|178477|43|0.0%|0.6%|
[php_commenters](#php_commenters)|281|281|29|10.3%|0.4%|
[openbl_60d](#openbl_60d)|7701|7701|21|0.2%|0.3%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|19|0.0%|0.2%|
[php_spammers](#php_spammers)|417|417|6|1.4%|0.0%|
[php_harvesters](#php_harvesters)|257|257|6|2.3%|0.0%|
[ri_web_proxies](#ri_web_proxies)|6153|6153|4|0.0%|0.0%|
[php_dictionary](#php_dictionary)|433|433|4|0.9%|0.0%|
[et_block](#et_block)|1007|18338646|4|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|17398|17398|4|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13522|13522|4|0.0%|0.0%|
[blocklist_de](#blocklist_de)|38212|38212|4|0.0%|0.0%|
[voipbl](#voipbl)|10398|10808|3|0.0%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|0.0%|
[xroxy](#xroxy)|2059|2059|2|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|654|18469632|2|0.0%|0.0%|
[sorbs_spam](#sorbs_spam)|23029|23820|2|0.0%|0.0%|
[nixspam](#nixspam)|20978|20978|2|0.0%|0.0%|
[shunlist](#shunlist)|1272|1272|1|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2310|2310|1|0.0%|0.0%|

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
[voipbl](#voipbl)|10398|10808|319|2.9%|0.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|5|0.0%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92996|92996|1|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.0%|
[ciarmy](#ciarmy)|343|343|1|0.2%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2052|2052|1|0.0%|0.0%|

## bruteforceblocker

[danger.rulez.sk](http://danger.rulez.sk/) IPs detected by [bruteforceblocker](http://danger.rulez.sk/index.php/bruteforceblocker/) (fail2ban alternative for SSH on OpenBSD). This is an automatically generated list from users reporting failed authentication attempts. An IP seems to be included if 3 or more users report it. Its retention pocily seems 30 days.

Source is downloaded from [this link](http://danger.rulez.sk/projects/bruteforceblocker/blist.php).

The last time downloaded was found to be dated: Thu Jun  4 12:27:09 UTC 2015.

The ipset `bruteforceblocker` has **2052** entries, **2052** unique IPs.

The following table shows the overlaps of `bruteforceblocker` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `bruteforceblocker`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `bruteforceblocker`.
- ` this % ` is the percentage **of this ipset (`bruteforceblocker`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[et_compromised](#et_compromised)|2171|2171|2009|92.5%|97.9%|
[alienvault_reputation](#alienvault_reputation)|178477|178477|1336|0.7%|65.1%|
[openbl_60d](#openbl_60d)|7701|7701|1243|16.1%|60.5%|
[openbl_30d](#openbl_30d)|3255|3255|1181|36.2%|57.5%|
[blocklist_de](#blocklist_de)|38212|38212|685|1.7%|33.3%|
[blocklist_de_ssh](#blocklist_de_ssh)|14281|14281|674|4.7%|32.8%|
[shunlist](#shunlist)|1272|1272|489|38.4%|23.8%|
[openbl_7d](#openbl_7d)|943|943|425|45.0%|20.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|201|0.0%|9.7%|
[dshield](#dshield)|20|5120|118|2.3%|5.7%|
[spamhaus_drop](#spamhaus_drop)|654|18469632|100|0.0%|4.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|100|0.0%|4.8%|
[et_block](#et_block)|1007|18338646|100|0.0%|4.8%|
[openbl_1d](#openbl_1d)|189|189|89|47.0%|4.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|57|0.0%|2.7%|
[stopforumspam_30d](#stopforumspam_30d)|92996|92996|10|0.0%|0.4%|
[blocklist_de_mail](#blocklist_de_mail)|17398|17398|8|0.0%|0.3%|
[stopforumspam_7d](#stopforumspam_7d)|30334|30334|6|0.0%|0.2%|
[blocklist_de_imap](#blocklist_de_imap)|3124|3124|6|0.1%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|5|0.0%|0.2%|
[voipbl](#voipbl)|10398|10808|2|0.0%|0.0%|
[proxz](#proxz)|702|702|2|0.2%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|2|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13522|13522|2|0.0%|0.0%|
[xroxy](#xroxy)|2059|2059|1|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7074|7074|1|0.0%|0.0%|
[sorbs_spam](#sorbs_spam)|23029|23820|1|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|6153|6153|1|0.0%|0.0%|
[fullbogons](#fullbogons)|3733|670419608|1|0.0%|0.0%|
[ciarmy](#ciarmy)|343|343|1|0.2%|0.0%|
[bogons](#bogons)|13|592708608|1|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3113|3113|1|0.0%|0.0%|

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
[blocklist_de](#blocklist_de)|38212|38212|42|0.1%|12.2%|
[blocklist_de_apache](#blocklist_de_apache)|13522|13522|37|0.2%|10.7%|
[shunlist](#shunlist)|1272|1272|27|2.1%|7.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|16|0.0%|4.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|7|0.0%|2.0%|
[voipbl](#voipbl)|10398|10808|6|0.0%|1.7%|
[dshield](#dshield)|20|5120|2|0.0%|0.5%|
[stopforumspam_7d](#stopforumspam_7d)|30334|30334|1|0.0%|0.2%|
[stopforumspam_30d](#stopforumspam_30d)|92996|92996|1|0.0%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.2%|
[fullbogons](#fullbogons)|3733|670419608|1|0.0%|0.2%|
[et_compromised](#et_compromised)|2171|2171|1|0.0%|0.2%|
[et_block](#et_block)|1007|18338646|1|0.0%|0.2%|
[bruteforceblocker](#bruteforceblocker)|2052|2052|1|0.0%|0.2%|
[bogons](#bogons)|13|592708608|1|0.0%|0.2%|
[blocklist_de_ssh](#blocklist_de_ssh)|14281|14281|1|0.0%|0.2%|
[blocklist_de_sip](#blocklist_de_sip)|105|105|1|0.9%|0.2%|
[blocklist_de_mail](#blocklist_de_mail)|17398|17398|1|0.0%|0.2%|
[blocklist_de_imap](#blocklist_de_imap)|3124|3124|1|0.0%|0.2%|
[blocklist_de_ftp](#blocklist_de_ftp)|877|877|1|0.1%|0.2%|

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

The last time downloaded was found to be dated: Thu Jun  4 13:09:04 UTC 2015.

The ipset `dm_tor` has **6585** entries, **6585** unique IPs.

The following table shows the overlaps of `dm_tor` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `dm_tor`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `dm_tor`.
- ` this % ` is the percentage **of this ipset (`dm_tor`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[bm_tor](#bm_tor)|6584|6584|6501|98.7%|98.7%|
[et_tor](#et_tor)|6380|6380|5711|89.5%|86.7%|
[snort_ipfilter](#snort_ipfilter)|9369|9369|1065|11.3%|16.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|631|0.0%|9.5%|
[stopforumspam_30d](#stopforumspam_30d)|92996|92996|627|0.6%|9.5%|
[stopforumspam_7d](#stopforumspam_7d)|30334|30334|488|1.6%|7.4%|
[stopforumspam_1d](#stopforumspam_1d)|7074|7074|321|4.5%|4.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|190|0.0%|2.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|170|0.0%|2.5%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|169|45.4%|2.5%|
[alienvault_reputation](#alienvault_reputation)|178477|178477|43|0.0%|0.6%|
[php_commenters](#php_commenters)|281|281|29|10.3%|0.4%|
[openbl_60d](#openbl_60d)|7701|7701|21|0.2%|0.3%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|19|0.0%|0.2%|
[php_spammers](#php_spammers)|417|417|6|1.4%|0.0%|
[php_harvesters](#php_harvesters)|257|257|6|2.3%|0.0%|
[ri_web_proxies](#ri_web_proxies)|6153|6153|4|0.0%|0.0%|
[php_dictionary](#php_dictionary)|433|433|4|0.9%|0.0%|
[et_block](#et_block)|1007|18338646|4|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|17398|17398|4|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13522|13522|4|0.0%|0.0%|
[blocklist_de](#blocklist_de)|38212|38212|4|0.0%|0.0%|
[voipbl](#voipbl)|10398|10808|3|0.0%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|0.0%|
[xroxy](#xroxy)|2059|2059|2|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|654|18469632|2|0.0%|0.0%|
[nixspam](#nixspam)|20978|20978|2|0.0%|0.0%|
[sorbs_spam](#sorbs_spam)|23029|23820|1|0.0%|0.0%|
[shunlist](#shunlist)|1272|1272|1|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2310|2310|1|0.0%|0.0%|

## dshield

[DShield.org](https://dshield.org/) top 20 attacking class C (/24) subnets over the last three days - **excellent list**

Source is downloaded from [this link](http://feeds.dshield.org/block.txt).

The last time downloaded was found to be dated: Thu Jun  4 11:16:54 UTC 2015.

The ipset `dshield` has **20** entries, **5120** unique IPs.

The following table shows the overlaps of `dshield` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `dshield`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `dshield`.
- ` this % ` is the percentage **of this ipset (`dshield`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[alienvault_reputation](#alienvault_reputation)|178477|178477|3589|2.0%|70.0%|
[et_block](#et_block)|1007|18338646|1280|0.0%|25.0%|
[spamhaus_drop](#spamhaus_drop)|654|18469632|512|0.0%|10.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|512|0.0%|10.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|258|0.0%|5.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|256|0.0%|5.0%|
[openbl_60d](#openbl_60d)|7701|7701|180|2.3%|3.5%|
[openbl_30d](#openbl_30d)|3255|3255|159|4.8%|3.1%|
[shunlist](#shunlist)|1272|1272|126|9.9%|2.4%|
[blocklist_de](#blocklist_de)|38212|38212|124|0.3%|2.4%|
[et_compromised](#et_compromised)|2171|2171|118|5.4%|2.3%|
[bruteforceblocker](#bruteforceblocker)|2052|2052|118|5.7%|2.3%|
[blocklist_de_ssh](#blocklist_de_ssh)|14281|14281|116|0.8%|2.2%|
[openbl_7d](#openbl_7d)|943|943|59|6.2%|1.1%|
[blocklist_de_apache](#blocklist_de_apache)|13522|13522|7|0.0%|0.1%|
[openbl_1d](#openbl_1d)|189|189|6|3.1%|0.1%|
[stopforumspam_30d](#stopforumspam_30d)|92996|92996|4|0.0%|0.0%|
[voipbl](#voipbl)|10398|10808|3|0.0%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|30334|30334|2|0.0%|0.0%|
[ciarmy](#ciarmy)|343|343|2|0.5%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|17398|17398|2|0.0%|0.0%|
[malc0de](#malc0de)|379|379|1|0.2%|0.0%|

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
[dshield](#dshield)|20|5120|1280|25.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1040|0.3%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92996|92996|1014|1.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|486400|517|0.1%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|30334|30334|335|1.1%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9369|9369|305|3.2%|0.0%|
[zeus](#zeus)|268|268|258|96.2%|0.0%|
[openbl_60d](#openbl_60d)|7701|7701|244|3.1%|0.0%|
[zeus_badips](#zeus_badips)|235|235|231|98.2%|0.0%|
[openbl_30d](#openbl_30d)|3255|3255|163|5.0%|0.0%|
[blocklist_de](#blocklist_de)|38212|38212|160|0.4%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|14281|14281|113|0.7%|0.0%|
[shunlist](#shunlist)|1272|1272|108|8.4%|0.0%|
[et_compromised](#et_compromised)|2171|2171|100|4.6%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2052|2052|100|4.8%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7074|7074|93|1.3%|0.0%|
[feodo](#feodo)|90|90|80|88.8%|0.0%|
[openbl_7d](#openbl_7d)|943|943|61|6.4%|0.0%|
[nixspam](#nixspam)|20978|20978|57|0.2%|0.0%|
[sslbl](#sslbl)|366|366|32|8.7%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|29|2.2%|0.0%|
[php_commenters](#php_commenters)|281|281|25|8.8%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|17398|17398|21|0.1%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3113|3113|21|0.6%|0.0%|
[voipbl](#voipbl)|10398|10808|14|0.1%|0.0%|
[palevo](#palevo)|13|13|12|92.3%|0.0%|
[sorbs_spam](#sorbs_spam)|23029|23820|11|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|3124|3124|9|0.2%|0.0%|
[openbl_1d](#openbl_1d)|189|189|7|3.7%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|6|0.4%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|6|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|178|178|6|3.3%|0.0%|
[malc0de](#malc0de)|379|379|5|1.3%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13522|13522|5|0.0%|0.0%|
[php_dictionary](#php_dictionary)|433|433|4|0.9%|0.0%|
[et_tor](#et_tor)|6380|6380|4|0.0%|0.0%|
[dm_tor](#dm_tor)|6585|6585|4|0.0%|0.0%|
[bm_tor](#bm_tor)|6584|6584|4|0.0%|0.0%|
[php_spammers](#php_spammers)|417|417|2|0.4%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|2|0.2%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2186|2186|2|0.0%|0.0%|
[sorbs_web](#sorbs_web)|656|657|1|0.1%|0.0%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[et_botcc](#et_botcc)|508|508|1|0.1%|0.0%|
[ciarmy](#ciarmy)|343|343|1|0.2%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|105|105|1|0.9%|0.0%|

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
[bruteforceblocker](#bruteforceblocker)|2052|2052|2009|97.9%|92.5%|
[alienvault_reputation](#alienvault_reputation)|178477|178477|1406|0.7%|64.7%|
[openbl_60d](#openbl_60d)|7701|7701|1309|16.9%|60.2%|
[openbl_30d](#openbl_30d)|3255|3255|1216|37.3%|56.0%|
[blocklist_de](#blocklist_de)|38212|38212|668|1.7%|30.7%|
[blocklist_de_ssh](#blocklist_de_ssh)|14281|14281|654|4.5%|30.1%|
[shunlist](#shunlist)|1272|1272|496|38.9%|22.8%|
[openbl_7d](#openbl_7d)|943|943|417|44.2%|19.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|216|0.0%|9.9%|
[dshield](#dshield)|20|5120|118|2.3%|5.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|115|0.0%|5.2%|
[spamhaus_drop](#spamhaus_drop)|654|18469632|100|0.0%|4.6%|
[et_block](#et_block)|1007|18338646|100|0.0%|4.6%|
[openbl_1d](#openbl_1d)|189|189|84|44.4%|3.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|62|0.0%|2.8%|
[stopforumspam_30d](#stopforumspam_30d)|92996|92996|10|0.0%|0.4%|
[blocklist_de_mail](#blocklist_de_mail)|17398|17398|9|0.0%|0.4%|
[stopforumspam_7d](#stopforumspam_7d)|30334|30334|6|0.0%|0.2%|
[blocklist_de_imap](#blocklist_de_imap)|3124|3124|6|0.1%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|5|0.0%|0.2%|
[blocklist_de_apache](#blocklist_de_apache)|13522|13522|3|0.0%|0.1%|
[voipbl](#voipbl)|10398|10808|2|0.0%|0.0%|
[proxz](#proxz)|702|702|2|0.2%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|2|0.0%|0.0%|
[xroxy](#xroxy)|2059|2059|1|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7074|7074|1|0.0%|0.0%|
[sorbs_spam](#sorbs_spam)|23029|23820|1|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|6153|6153|1|0.0%|0.0%|
[ciarmy](#ciarmy)|343|343|1|0.2%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3113|3113|1|0.0%|0.0%|

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
[bm_tor](#bm_tor)|6584|6584|5733|87.0%|89.8%|
[dm_tor](#dm_tor)|6585|6585|5711|86.7%|89.5%|
[snort_ipfilter](#snort_ipfilter)|9369|9369|1088|11.6%|17.0%|
[stopforumspam_30d](#stopforumspam_30d)|92996|92996|636|0.6%|9.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|626|0.0%|9.8%|
[stopforumspam_7d](#stopforumspam_7d)|30334|30334|499|1.6%|7.8%|
[stopforumspam_1d](#stopforumspam_1d)|7074|7074|328|4.6%|5.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|185|0.0%|2.8%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|171|45.9%|2.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|167|0.0%|2.6%|
[alienvault_reputation](#alienvault_reputation)|178477|178477|42|0.0%|0.6%|
[php_commenters](#php_commenters)|281|281|29|10.3%|0.4%|
[openbl_60d](#openbl_60d)|7701|7701|21|0.2%|0.3%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|21|0.0%|0.3%|
[php_harvesters](#php_harvesters)|257|257|7|2.7%|0.1%|
[php_spammers](#php_spammers)|417|417|6|1.4%|0.0%|
[ri_web_proxies](#ri_web_proxies)|6153|6153|4|0.0%|0.0%|
[php_dictionary](#php_dictionary)|433|433|4|0.9%|0.0%|
[et_block](#et_block)|1007|18338646|4|0.0%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|17398|17398|3|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13522|13522|3|0.0%|0.0%|
[blocklist_de](#blocklist_de)|38212|38212|3|0.0%|0.0%|
[xroxy](#xroxy)|2059|2059|2|0.0%|0.0%|
[voipbl](#voipbl)|10398|10808|2|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|654|18469632|2|0.0%|0.0%|
[sorbs_spam](#sorbs_spam)|23029|23820|2|0.0%|0.0%|
[nixspam](#nixspam)|20978|20978|2|0.0%|0.0%|
[shunlist](#shunlist)|1272|1272|1|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2310|2310|1|0.0%|0.0%|

## feodo

[Abuse.ch Feodo tracker](https://feodotracker.abuse.ch) trojan includes IPs which are being used by Feodo (also known as Cridex or Bugat) which commits ebanking fraud - **excellent list**

Source is downloaded from [this link](https://feodotracker.abuse.ch/blocklist/?download=ipblocklist).

The last time downloaded was found to be dated: Thu Jun  4 13:09:24 UTC 2015.

The ipset `feodo` has **90** entries, **90** unique IPs.

The following table shows the overlaps of `feodo` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `feodo`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `feodo`.
- ` this % ` is the percentage **of this ipset (`feodo`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[et_block](#et_block)|1007|18338646|80|0.0%|88.8%|
[snort_ipfilter](#snort_ipfilter)|9369|9369|68|0.7%|75.5%|
[sslbl](#sslbl)|366|366|34|9.2%|37.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|9|0.0%|10.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|3|0.0%|3.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|3|0.0%|3.3%|
[alienvault_reputation](#alienvault_reputation)|178477|178477|2|0.0%|2.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|1.1%|

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
[voipbl](#voipbl)|10398|10808|319|2.9%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|33|2.2%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|15|0.0%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|9|0.6%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92996|92996|2|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.0%|
[ciarmy](#ciarmy)|343|343|1|0.2%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2052|2052|1|0.0%|0.0%|

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
[nixspam](#nixspam)|20978|20978|8|0.0%|0.0%|
[blocklist_de](#blocklist_de)|38212|38212|8|0.0%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|30334|30334|6|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|654|18469632|6|0.0%|0.0%|
[sorbs_spam](#sorbs_spam)|23029|23820|6|0.0%|0.0%|
[et_block](#et_block)|1007|18338646|6|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|4|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|17398|17398|4|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2186|2186|4|0.1%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13522|13522|4|0.0%|0.0%|
[xroxy](#xroxy)|2059|2059|3|0.1%|0.0%|
[voipbl](#voipbl)|10398|10808|2|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|6153|6153|2|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|2|0.7%|0.0%|
[php_dictionary](#php_dictionary)|433|433|2|0.4%|0.0%|
[sorbs_web](#sorbs_web)|656|657|1|0.1%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9369|9369|1|0.0%|0.0%|
[proxz](#proxz)|702|702|1|0.1%|0.0%|
[proxyrss](#proxyrss)|1604|1604|1|0.0%|0.0%|
[php_spammers](#php_spammers)|417|417|1|0.2%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|3124|3124|1|0.0%|0.0%|

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
[nixspam](#nixspam)|20978|20978|57|0.2%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7074|7074|45|0.6%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|27|2.0%|0.0%|
[blocklist_de](#blocklist_de)|38212|38212|27|0.0%|0.0%|
[openbl_60d](#openbl_60d)|7701|7701|18|0.2%|0.0%|
[openbl_30d](#openbl_30d)|3255|3255|13|0.3%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3113|3113|13|0.4%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9369|9369|11|0.1%|0.0%|
[zeus_badips](#zeus_badips)|235|235|10|4.2%|0.0%|
[zeus](#zeus)|268|268|10|3.7%|0.0%|
[sorbs_spam](#sorbs_spam)|23029|23820|7|0.0%|0.0%|
[openbl_7d](#openbl_7d)|943|943|7|0.7%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|7|0.4%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|14281|14281|7|0.0%|0.0%|
[et_compromised](#et_compromised)|2171|2171|5|0.2%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2052|2052|5|0.2%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|17398|17398|5|0.0%|0.0%|
[openbl_1d](#openbl_1d)|189|189|3|1.5%|0.0%|
[et_tor](#et_tor)|6380|6380|3|0.0%|0.0%|
[dm_tor](#dm_tor)|6585|6585|3|0.0%|0.0%|
[bm_tor](#bm_tor)|6584|6584|3|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|178|178|3|1.6%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|3124|3124|3|0.0%|0.0%|
[shunlist](#shunlist)|1272|1272|2|0.1%|0.0%|
[php_spammers](#php_spammers)|417|417|2|0.4%|0.0%|
[php_dictionary](#php_dictionary)|433|433|2|0.4%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|2|0.2%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2186|2186|2|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13522|13522|2|0.0%|0.0%|
[voipbl](#voipbl)|10398|10808|1|0.0%|0.0%|
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
[blocklist_de](#blocklist_de)|38212|38212|1595|4.1%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92996|92996|1551|1.6%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|17398|17398|1366|7.8%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13522|13522|1328|9.8%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|30334|30334|571|1.8%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|406|0.8%|0.0%|
[nixspam](#nixspam)|20978|20978|379|1.8%|0.0%|
[sorbs_spam](#sorbs_spam)|23029|23820|365|1.5%|0.0%|
[voipbl](#voipbl)|10398|10808|298|2.7%|0.0%|
[dshield](#dshield)|20|5120|258|5.0%|0.0%|
[openbl_60d](#openbl_60d)|7701|7701|172|2.2%|0.0%|
[dm_tor](#dm_tor)|6585|6585|170|2.5%|0.0%|
[bm_tor](#bm_tor)|6584|6584|170|2.5%|0.0%|
[et_tor](#et_tor)|6380|6380|167|2.6%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7074|7074|160|2.2%|0.0%|
[ri_web_proxies](#ri_web_proxies)|6153|6153|130|2.1%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|14281|14281|129|0.9%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9369|9369|98|1.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|97|6.6%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2310|2310|74|3.2%|0.0%|
[openbl_30d](#openbl_30d)|3255|3255|70|2.1%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|66|5.1%|0.0%|
[et_compromised](#et_compromised)|2171|2171|62|2.8%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|58|8.6%|0.0%|
[xroxy](#xroxy)|2059|2059|57|2.7%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2052|2052|57|2.7%|0.0%|
[proxyrss](#proxyrss)|1604|1604|51|3.1%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3113|3113|42|1.3%|0.0%|
[et_botcc](#et_botcc)|508|508|40|7.8%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2186|2186|39|1.7%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|3124|3124|37|1.1%|0.0%|
[proxz](#proxz)|702|702|27|3.8%|0.0%|
[shunlist](#shunlist)|1272|1272|26|2.0%|0.0%|
[sorbs_web](#sorbs_web)|656|657|22|3.3%|0.0%|
[openbl_7d](#openbl_7d)|943|943|19|2.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|17|4.5%|0.0%|
[malc0de](#malc0de)|379|379|12|3.1%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|877|877|10|1.1%|0.0%|
[php_dictionary](#php_dictionary)|433|433|9|2.0%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|206|206|8|3.8%|0.0%|
[php_harvesters](#php_harvesters)|257|257|7|2.7%|0.0%|
[ciarmy](#ciarmy)|343|343|7|2.0%|0.0%|
[zeus](#zeus)|268|268|6|2.2%|0.0%|
[php_spammers](#php_spammers)|417|417|5|1.1%|0.0%|
[php_commenters](#php_commenters)|281|281|5|1.7%|0.0%|
[bogons](#bogons)|13|592708608|5|0.0%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|105|105|5|4.7%|0.0%|
[zeus_badips](#zeus_badips)|235|235|4|1.7%|0.0%|
[sslbl](#sslbl)|366|366|4|1.0%|0.0%|
[feodo](#feodo)|90|90|3|3.3%|0.0%|
[openbl_1d](#openbl_1d)|189|189|2|1.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|178|178|1|0.5%|0.0%|

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
[blocklist_de](#blocklist_de)|38212|38212|1564|4.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|17398|17398|1175|6.7%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13522|13522|1073|7.9%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|30334|30334|908|2.9%|0.0%|
[sorbs_spam](#sorbs_spam)|23029|23820|559|2.3%|0.0%|
[nixspam](#nixspam)|20978|20978|512|2.4%|0.0%|
[voipbl](#voipbl)|10398|10808|432|3.9%|0.0%|
[openbl_60d](#openbl_60d)|7701|7701|339|4.4%|0.0%|
[dshield](#dshield)|20|5120|256|5.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|14281|14281|232|1.6%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|230|0.4%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7074|7074|224|3.1%|0.0%|
[dm_tor](#dm_tor)|6585|6585|190|2.8%|0.0%|
[bm_tor](#bm_tor)|6584|6584|190|2.8%|0.0%|
[et_tor](#et_tor)|6380|6380|185|2.8%|0.0%|
[ri_web_proxies](#ri_web_proxies)|6153|6153|179|2.9%|0.0%|
[openbl_30d](#openbl_30d)|3255|3255|169|5.1%|0.0%|
[et_compromised](#et_compromised)|2171|2171|115|5.2%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9369|9369|105|1.1%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2052|2052|100|4.8%|0.0%|
[xroxy](#xroxy)|2059|2059|99|4.8%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2310|2310|91|3.9%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3113|3113|85|2.7%|0.0%|
[shunlist](#shunlist)|1272|1272|74|5.8%|0.0%|
[proxyrss](#proxyrss)|1604|1604|71|4.4%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|3124|3124|61|1.9%|0.0%|
[openbl_7d](#openbl_7d)|943|943|47|4.9%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|45|3.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2186|2186|39|1.7%|0.0%|
[php_spammers](#php_spammers)|417|417|31|7.4%|0.0%|
[proxz](#proxz)|702|702|30|4.2%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|28|4.1%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|26|2.0%|0.0%|
[malc0de](#malc0de)|379|379|23|6.0%|0.0%|
[et_botcc](#et_botcc)|508|508|22|4.3%|0.0%|
[sorbs_web](#sorbs_web)|656|657|21|3.1%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|21|5.6%|0.0%|
[ciarmy](#ciarmy)|343|343|16|4.6%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|877|877|16|1.8%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|206|206|12|5.8%|0.0%|
[php_dictionary](#php_dictionary)|433|433|10|2.3%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|105|105|10|9.5%|0.0%|
[zeus](#zeus)|268|268|9|3.3%|0.0%|
[php_commenters](#php_commenters)|281|281|9|3.2%|0.0%|
[zeus_badips](#zeus_badips)|235|235|8|3.4%|0.0%|
[openbl_1d](#openbl_1d)|189|189|8|4.2%|0.0%|
[php_harvesters](#php_harvesters)|257|257|7|2.7%|0.0%|
[sslbl](#sslbl)|366|366|6|1.6%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|178|178|6|3.3%|0.0%|
[palevo](#palevo)|13|13|3|23.0%|0.0%|
[feodo](#feodo)|90|90|3|3.3%|0.0%|
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
[blocklist_de](#blocklist_de)|38212|38212|6928|18.1%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92996|92996|5857|6.2%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|14281|14281|3896|27.2%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|17398|17398|2583|14.8%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13522|13522|2278|16.8%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|30334|30334|1930|6.3%|0.0%|
[sorbs_spam](#sorbs_spam)|23029|23820|1710|7.1%|0.0%|
[voipbl](#voipbl)|10398|10808|1594|14.7%|0.0%|
[nixspam](#nixspam)|20978|20978|1523|7.2%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1172|2.4%|0.0%|
[openbl_60d](#openbl_60d)|7701|7701|749|9.7%|0.0%|
[dm_tor](#dm_tor)|6585|6585|631|9.5%|0.0%|
[bm_tor](#bm_tor)|6584|6584|627|9.5%|0.0%|
[et_tor](#et_tor)|6380|6380|626|9.8%|0.0%|
[dshield](#dshield)|20|5120|512|10.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7074|7074|460|6.5%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|3124|3124|380|12.1%|0.0%|
[openbl_30d](#openbl_30d)|3255|3255|310|9.5%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9369|9369|224|2.3%|0.0%|
[et_compromised](#et_compromised)|2171|2171|216|9.9%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2052|2052|201|9.7%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2186|2186|181|8.2%|0.0%|
[ri_web_proxies](#ri_web_proxies)|6153|6153|172|2.7%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3113|3113|154|4.9%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|147|11.4%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|125|33.6%|0.0%|
[openbl_7d](#openbl_7d)|943|943|114|12.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|110|7.5%|0.0%|
[shunlist](#shunlist)|1272|1272|104|8.1%|0.0%|
[xroxy](#xroxy)|2059|2059|90|4.3%|0.0%|
[et_botcc](#et_botcc)|508|508|76|14.9%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|877|877|73|8.3%|0.0%|
[malc0de](#malc0de)|379|379|67|17.6%|0.0%|
[proxz](#proxz)|702|702|60|8.5%|0.0%|
[proxyrss](#proxyrss)|1604|1604|57|3.5%|0.0%|
[ciarmy](#ciarmy)|343|343|53|15.4%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|51|7.5%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2310|2310|50|2.1%|0.0%|
[sorbs_web](#sorbs_web)|656|657|42|6.3%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|206|206|36|17.4%|0.0%|
[php_spammers](#php_spammers)|417|417|26|6.2%|0.0%|
[php_dictionary](#php_dictionary)|433|433|24|5.5%|0.0%|
[sslbl](#sslbl)|366|366|23|6.2%|0.0%|
[openbl_1d](#openbl_1d)|189|189|21|11.1%|0.0%|
[zeus](#zeus)|268|268|20|7.4%|0.0%|
[php_harvesters](#php_harvesters)|257|257|15|5.8%|0.0%|
[php_commenters](#php_commenters)|281|281|15|5.3%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|178|178|15|8.4%|0.0%|
[zeus_badips](#zeus_badips)|235|235|14|5.9%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|105|105|14|13.3%|0.0%|
[feodo](#feodo)|90|90|9|10.0%|0.0%|
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
[xroxy](#xroxy)|2059|2059|13|0.6%|1.9%|
[stopforumspam_7d](#stopforumspam_7d)|30334|30334|12|0.0%|1.7%|
[ri_web_proxies](#ri_web_proxies)|6153|6153|12|0.1%|1.7%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|11|0.0%|1.6%|
[proxyrss](#proxyrss)|1604|1604|10|0.6%|1.4%|
[stopforumspam_1d](#stopforumspam_1d)|7074|7074|6|0.0%|0.8%|
[ri_connect_proxies](#ri_connect_proxies)|2310|2310|6|0.2%|0.8%|
[blocklist_de](#blocklist_de)|38212|38212|5|0.0%|0.7%|
[proxz](#proxz)|702|702|4|0.5%|0.5%|
[blocklist_de_bots](#blocklist_de_bots)|3113|3113|4|0.1%|0.5%|
[spamhaus_drop](#spamhaus_drop)|654|18469632|2|0.0%|0.2%|
[nixspam](#nixspam)|20978|20978|2|0.0%|0.2%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2|0.0%|0.2%|
[et_block](#et_block)|1007|18338646|2|0.0%|0.2%|
[sorbs_spam](#sorbs_spam)|23029|23820|1|0.0%|0.1%|
[snort_ipfilter](#snort_ipfilter)|9369|9369|1|0.0%|0.1%|
[php_dictionary](#php_dictionary)|433|433|1|0.2%|0.1%|
[blocklist_de_mail](#blocklist_de_mail)|17398|17398|1|0.0%|0.1%|
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
[stopforumspam_7d](#stopforumspam_7d)|30334|30334|23|0.0%|0.0%|
[et_tor](#et_tor)|6380|6380|21|0.3%|0.0%|
[sorbs_spam](#sorbs_spam)|23029|23820|19|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|19|1.3%|0.0%|
[dm_tor](#dm_tor)|6585|6585|19|0.2%|0.0%|
[bm_tor](#bm_tor)|6584|6584|19|0.2%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9369|9369|14|0.1%|0.0%|
[blocklist_de](#blocklist_de)|38212|38212|11|0.0%|0.0%|
[nixspam](#nixspam)|20978|20978|9|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7074|7074|8|0.1%|0.0%|
[ri_web_proxies](#ri_web_proxies)|6153|6153|5|0.0%|0.0%|
[openbl_60d](#openbl_60d)|7701|7701|5|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|5|1.3%|0.0%|
[voipbl](#voipbl)|10398|10808|4|0.0%|0.0%|
[openbl_30d](#openbl_30d)|3255|3255|4|0.1%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|4|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|17398|17398|4|0.0%|0.0%|
[malc0de](#malc0de)|379|379|3|0.7%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3113|3113|3|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13522|13522|3|0.0%|0.0%|
[palevo](#palevo)|13|13|2|15.3%|0.0%|
[et_compromised](#et_compromised)|2171|2171|2|0.0%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|206|206|2|0.9%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2052|2052|2|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|14281|14281|2|0.0%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|105|105|2|1.9%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|3124|3124|2|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2186|2186|2|0.0%|0.0%|
[zeus_badips](#zeus_badips)|235|235|1|0.4%|0.0%|
[zeus](#zeus)|268|268|1|0.3%|0.0%|
[xroxy](#xroxy)|2059|2059|1|0.0%|0.0%|
[sslbl](#sslbl)|366|366|1|0.2%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|486400|1|0.0%|0.0%|
[shunlist](#shunlist)|1272|1272|1|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2310|2310|1|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.0%|
[php_dictionary](#php_dictionary)|433|433|1|0.2%|0.0%|
[openbl_7d](#openbl_7d)|943|943|1|0.1%|0.0%|
[feodo](#feodo)|90|90|1|1.1%|0.0%|
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
[openbl_60d](#openbl_60d)|7701|7701|2|0.0%|0.1%|
[openbl_30d](#openbl_30d)|3255|3255|2|0.0%|0.1%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|2|0.2%|0.1%|
[blocklist_de](#blocklist_de)|38212|38212|2|0.0%|0.1%|
[stopforumspam_7d](#stopforumspam_7d)|30334|30334|1|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7074|7074|1|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9369|9369|1|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|6153|6153|1|0.0%|0.0%|
[openbl_7d](#openbl_7d)|943|943|1|0.1%|0.0%|
[openbl_1d](#openbl_1d)|189|189|1|0.5%|0.0%|
[nixspam](#nixspam)|20978|20978|1|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1|0.0%|0.0%|
[et_botcc](#et_botcc)|508|508|1|0.1%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|178|178|1|0.5%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|14281|14281|1|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3113|3113|1|0.0%|0.0%|

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
[snort_ipfilter](#snort_ipfilter)|9369|9369|1|0.0%|0.2%|
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
[et_block](#et_block)|1007|18338646|29|0.0%|2.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|27|0.0%|2.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|27|0.0%|2.0%|
[snort_ipfilter](#snort_ipfilter)|9369|9369|26|0.2%|2.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|26|0.0%|2.0%|
[fullbogons](#fullbogons)|3733|670419608|9|0.0%|0.6%|
[alienvault_reputation](#alienvault_reputation)|178477|178477|6|0.0%|0.4%|
[stopforumspam_30d](#stopforumspam_30d)|92996|92996|4|0.0%|0.3%|
[malc0de](#malc0de)|379|379|4|1.0%|0.3%|
[stopforumspam_7d](#stopforumspam_7d)|30334|30334|3|0.0%|0.2%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|3|0.2%|0.2%|
[cleanmx_viruses](#cleanmx_viruses)|206|206|3|1.4%|0.2%|
[sorbs_spam](#sorbs_spam)|23029|23820|1|0.0%|0.0%|
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
[snort_ipfilter](#snort_ipfilter)|9369|9369|176|1.8%|47.3%|
[et_tor](#et_tor)|6380|6380|171|2.6%|45.9%|
[dm_tor](#dm_tor)|6585|6585|169|2.5%|45.4%|
[bm_tor](#bm_tor)|6584|6584|169|2.5%|45.4%|
[stopforumspam_1d](#stopforumspam_1d)|7074|7074|163|2.3%|43.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|125|0.0%|33.6%|
[php_commenters](#php_commenters)|281|281|28|9.9%|7.5%|
[alienvault_reputation](#alienvault_reputation)|178477|178477|25|0.0%|6.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|21|0.0%|5.6%|
[openbl_60d](#openbl_60d)|7701|7701|18|0.2%|4.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|17|0.0%|4.5%|
[php_harvesters](#php_harvesters)|257|257|6|2.3%|1.6%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|5|0.0%|1.3%|
[ri_web_proxies](#ri_web_proxies)|6153|6153|4|0.0%|1.0%|
[php_spammers](#php_spammers)|417|417|4|0.9%|1.0%|
[php_dictionary](#php_dictionary)|433|433|4|0.9%|1.0%|
[shunlist](#shunlist)|1272|1272|2|0.1%|0.5%|
[blocklist_de](#blocklist_de)|38212|38212|2|0.0%|0.5%|
[xroxy](#xroxy)|2059|2059|1|0.0%|0.2%|
[voipbl](#voipbl)|10398|10808|1|0.0%|0.2%|
[ri_connect_proxies](#ri_connect_proxies)|2310|2310|1|0.0%|0.2%|
[nixspam](#nixspam)|20978|20978|1|0.0%|0.2%|
[et_block](#et_block)|1007|18338646|1|0.0%|0.2%|
[blocklist_de_mail](#blocklist_de_mail)|17398|17398|1|0.0%|0.2%|
[blocklist_de_apache](#blocklist_de_apache)|13522|13522|1|0.0%|0.2%|

## nixspam

[NiX Spam](http://www.heise.de/ix/NiX-Spam-DNSBL-and-blacklist-for-download-499637.html) IP addresses that sent spam in the last hour - automatically generated entries without distinguishing open proxies from relays, dialup gateways, and so on. All IPs are removed after 12 hours if there is no spam from there.

Source is downloaded from [this link](http://www.dnsbl.manitu.net/download/nixspam-ip.dump.gz).

The last time downloaded was found to be dated: Thu Jun  4 13:15:02 UTC 2015.

The ipset `nixspam` has **20978** entries, **20978** unique IPs.

The following table shows the overlaps of `nixspam` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `nixspam`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `nixspam`.
- ` this % ` is the percentage **of this ipset (`nixspam`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[sorbs_spam](#sorbs_spam)|23029|23820|4007|16.8%|19.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|1523|0.0%|7.2%|
[blocklist_de](#blocklist_de)|38212|38212|684|1.7%|3.2%|
[blocklist_de_mail](#blocklist_de_mail)|17398|17398|607|3.4%|2.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|512|0.0%|2.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|379|0.0%|1.8%|
[stopforumspam_30d](#stopforumspam_30d)|92996|92996|234|0.2%|1.1%|
[stopforumspam_7d](#stopforumspam_7d)|30334|30334|155|0.5%|0.7%|
[sorbs_web](#sorbs_web)|656|657|147|22.3%|0.7%|
[snort_ipfilter](#snort_ipfilter)|9369|9369|144|1.5%|0.6%|
[ri_web_proxies](#ri_web_proxies)|6153|6153|89|1.4%|0.4%|
[php_dictionary](#php_dictionary)|433|433|70|16.1%|0.3%|
[xroxy](#xroxy)|2059|2059|69|3.3%|0.3%|
[stopforumspam_1d](#stopforumspam_1d)|7074|7074|67|0.9%|0.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|57|0.0%|0.2%|
[et_block](#et_block)|1007|18338646|57|0.0%|0.2%|
[spamhaus_drop](#spamhaus_drop)|654|18469632|56|0.0%|0.2%|
[php_spammers](#php_spammers)|417|417|53|12.7%|0.2%|
[blocklist_de_bots](#blocklist_de_bots)|3113|3113|44|1.4%|0.2%|
[proxz](#proxz)|702|702|31|4.4%|0.1%|
[alienvault_reputation](#alienvault_reputation)|178477|178477|27|0.0%|0.1%|
[blocklist_de_apache](#blocklist_de_apache)|13522|13522|24|0.1%|0.1%|
[blocklist_de_imap](#blocklist_de_imap)|3124|3124|23|0.7%|0.1%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2186|2186|22|1.0%|0.1%|
[ri_connect_proxies](#ri_connect_proxies)|2310|2310|20|0.8%|0.0%|
[proxyrss](#proxyrss)|1604|1604|17|1.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|9|0.0%|0.0%|
[php_commenters](#php_commenters)|281|281|8|2.8%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|8|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|5|1.9%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|14281|14281|5|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|877|877|5|0.5%|0.0%|
[openbl_60d](#openbl_60d)|7701|7701|3|0.0%|0.0%|
[sorbs_socks](#sorbs_socks)|23|23|2|8.6%|0.0%|
[sorbs_misc](#sorbs_misc)|23|23|2|8.6%|0.0%|
[sorbs_http](#sorbs_http)|23|23|2|8.6%|0.0%|
[shunlist](#shunlist)|1272|1272|2|0.1%|0.0%|
[openbl_30d](#openbl_30d)|3255|3255|2|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|2|0.2%|0.0%|
[et_tor](#et_tor)|6380|6380|2|0.0%|0.0%|
[dm_tor](#dm_tor)|6585|6585|2|0.0%|0.0%|
[bm_tor](#bm_tor)|6584|6584|2|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|178|178|2|1.1%|0.0%|
[zeus_badips](#zeus_badips)|235|235|1|0.4%|0.0%|
[zeus](#zeus)|268|268|1|0.3%|0.0%|
[sorbs_smtp](#sorbs_smtp)|9|9|1|11.1%|0.0%|
[openbl_7d](#openbl_7d)|943|943|1|0.1%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|

## openbl_1d

[OpenBL.org](http://www.openbl.org/) last 24 hours IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.

Source is downloaded from [this link](http://www.openbl.org/lists/base_1days.txt).

The last time downloaded was found to be dated: Thu Jun  4 12:32:00 UTC 2015.

The ipset `openbl_1d` has **189** entries, **189** unique IPs.

The following table shows the overlaps of `openbl_1d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl_1d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl_1d`.
- ` this % ` is the percentage **of this ipset (`openbl_1d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[openbl_60d](#openbl_60d)|7701|7701|189|2.4%|100.0%|
[openbl_30d](#openbl_30d)|3255|3255|189|5.8%|100.0%|
[openbl_7d](#openbl_7d)|943|943|188|19.9%|99.4%|
[alienvault_reputation](#alienvault_reputation)|178477|178477|184|0.1%|97.3%|
[blocklist_de](#blocklist_de)|38212|38212|162|0.4%|85.7%|
[blocklist_de_ssh](#blocklist_de_ssh)|14281|14281|159|1.1%|84.1%|
[bruteforceblocker](#bruteforceblocker)|2052|2052|89|4.3%|47.0%|
[et_compromised](#et_compromised)|2171|2171|84|3.8%|44.4%|
[shunlist](#shunlist)|1272|1272|73|5.7%|38.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|21|0.0%|11.1%|
[blocklist_de_strongips](#blocklist_de_strongips)|178|178|21|11.7%|11.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|8|0.0%|4.2%|
[spamhaus_drop](#spamhaus_drop)|654|18469632|7|0.0%|3.7%|
[et_block](#et_block)|1007|18338646|7|0.0%|3.7%|
[dshield](#dshield)|20|5120|6|0.1%|3.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|1.5%|
[blocklist_de_mail](#blocklist_de_mail)|17398|17398|3|0.0%|1.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|2|0.0%|1.0%|
[blocklist_de_imap](#blocklist_de_imap)|3124|3124|2|0.0%|1.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.5%|

## openbl_30d

[OpenBL.org](http://www.openbl.org/) last 30 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.

Source is downloaded from [this link](http://www.openbl.org/lists/base_30days.txt).

The last time downloaded was found to be dated: Thu Jun  4 11:42:00 UTC 2015.

The ipset `openbl_30d` has **3255** entries, **3255** unique IPs.

The following table shows the overlaps of `openbl_30d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl_30d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl_30d`.
- ` this % ` is the percentage **of this ipset (`openbl_30d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[openbl_60d](#openbl_60d)|7701|7701|3255|42.2%|100.0%|
[alienvault_reputation](#alienvault_reputation)|178477|178477|3236|1.8%|99.4%|
[et_compromised](#et_compromised)|2171|2171|1216|56.0%|37.3%|
[bruteforceblocker](#bruteforceblocker)|2052|2052|1181|57.5%|36.2%|
[openbl_7d](#openbl_7d)|943|943|943|100.0%|28.9%|
[blocklist_de](#blocklist_de)|38212|38212|908|2.3%|27.8%|
[blocklist_de_ssh](#blocklist_de_ssh)|14281|14281|867|6.0%|26.6%|
[shunlist](#shunlist)|1272|1272|579|45.5%|17.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|310|0.0%|9.5%|
[openbl_1d](#openbl_1d)|189|189|189|100.0%|5.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|169|0.0%|5.1%|
[et_block](#et_block)|1007|18338646|163|0.0%|5.0%|
[spamhaus_drop](#spamhaus_drop)|654|18469632|159|0.0%|4.8%|
[dshield](#dshield)|20|5120|159|3.1%|4.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|70|0.0%|2.1%|
[blocklist_de_mail](#blocklist_de_mail)|17398|17398|39|0.2%|1.1%|
[blocklist_de_imap](#blocklist_de_imap)|3124|3124|31|0.9%|0.9%|
[blocklist_de_strongips](#blocklist_de_strongips)|178|178|23|12.9%|0.7%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|13|0.0%|0.3%|
[snort_ipfilter](#snort_ipfilter)|9369|9369|6|0.0%|0.1%|
[stopforumspam_30d](#stopforumspam_30d)|92996|92996|4|0.0%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|4|0.0%|0.1%|
[voipbl](#voipbl)|10398|10808|3|0.0%|0.0%|
[zeus](#zeus)|268|268|2|0.7%|0.0%|
[sorbs_spam](#sorbs_spam)|23029|23820|2|0.0%|0.0%|
[nixspam](#nixspam)|20978|20978|2|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13522|13522|2|0.0%|0.0%|
[zeus_badips](#zeus_badips)|235|235|1|0.4%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|30334|30334|1|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7074|7074|1|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|486400|1|0.0%|0.0%|

## openbl_60d

[OpenBL.org](http://www.openbl.org/) last 60 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.

Source is downloaded from [this link](http://www.openbl.org/lists/base_60days.txt).

The last time downloaded was found to be dated: Thu Jun  4 11:42:00 UTC 2015.

The ipset `openbl_60d` has **7701** entries, **7701** unique IPs.

The following table shows the overlaps of `openbl_60d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl_60d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl_60d`.
- ` this % ` is the percentage **of this ipset (`openbl_60d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[alienvault_reputation](#alienvault_reputation)|178477|178477|7676|4.3%|99.6%|
[openbl_30d](#openbl_30d)|3255|3255|3255|100.0%|42.2%|
[blocklist_de](#blocklist_de)|38212|38212|1902|4.9%|24.6%|
[blocklist_de_ssh](#blocklist_de_ssh)|14281|14281|1857|13.0%|24.1%|
[et_compromised](#et_compromised)|2171|2171|1309|60.2%|16.9%|
[bruteforceblocker](#bruteforceblocker)|2052|2052|1243|60.5%|16.1%|
[openbl_7d](#openbl_7d)|943|943|943|100.0%|12.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|749|0.0%|9.7%|
[shunlist](#shunlist)|1272|1272|594|46.6%|7.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|339|0.0%|4.4%|
[et_block](#et_block)|1007|18338646|244|0.0%|3.1%|
[spamhaus_drop](#spamhaus_drop)|654|18469632|239|0.0%|3.1%|
[openbl_1d](#openbl_1d)|189|189|189|100.0%|2.4%|
[dshield](#dshield)|20|5120|180|3.5%|2.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|172|0.0%|2.2%|
[stopforumspam_30d](#stopforumspam_30d)|92996|92996|56|0.0%|0.7%|
[blocklist_de_mail](#blocklist_de_mail)|17398|17398|41|0.2%|0.5%|
[blocklist_de_imap](#blocklist_de_imap)|3124|3124|33|1.0%|0.4%|
[snort_ipfilter](#snort_ipfilter)|9369|9369|29|0.3%|0.3%|
[stopforumspam_7d](#stopforumspam_7d)|30334|30334|25|0.0%|0.3%|
[blocklist_de_strongips](#blocklist_de_strongips)|178|178|25|14.0%|0.3%|
[stopforumspam_1d](#stopforumspam_1d)|7074|7074|22|0.3%|0.2%|
[et_tor](#et_tor)|6380|6380|21|0.3%|0.2%|
[dm_tor](#dm_tor)|6585|6585|21|0.3%|0.2%|
[bm_tor](#bm_tor)|6584|6584|21|0.3%|0.2%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|18|4.8%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|18|0.0%|0.2%|
[sorbs_spam](#sorbs_spam)|23029|23820|14|0.0%|0.1%|
[voipbl](#voipbl)|10398|10808|8|0.0%|0.1%|
[php_commenters](#php_commenters)|281|281|8|2.8%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|5|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13522|13522|4|0.0%|0.0%|
[nixspam](#nixspam)|20978|20978|3|0.0%|0.0%|
[zeus](#zeus)|268|268|2|0.7%|0.0%|
[php_harvesters](#php_harvesters)|257|257|2|0.7%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.0%|
[zeus_badips](#zeus_badips)|235|235|1|0.4%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|486400|1|0.0%|0.0%|

## openbl_7d

[OpenBL.org](http://www.openbl.org/) last 7 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.

Source is downloaded from [this link](http://www.openbl.org/lists/base_7days.txt).

The last time downloaded was found to be dated: Thu Jun  4 11:42:00 UTC 2015.

The ipset `openbl_7d` has **943** entries, **943** unique IPs.

The following table shows the overlaps of `openbl_7d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl_7d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl_7d`.
- ` this % ` is the percentage **of this ipset (`openbl_7d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[openbl_60d](#openbl_60d)|7701|7701|943|12.2%|100.0%|
[openbl_30d](#openbl_30d)|3255|3255|943|28.9%|100.0%|
[alienvault_reputation](#alienvault_reputation)|178477|178477|933|0.5%|98.9%|
[blocklist_de](#blocklist_de)|38212|38212|612|1.6%|64.8%|
[blocklist_de_ssh](#blocklist_de_ssh)|14281|14281|596|4.1%|63.2%|
[bruteforceblocker](#bruteforceblocker)|2052|2052|425|20.7%|45.0%|
[et_compromised](#et_compromised)|2171|2171|417|19.2%|44.2%|
[shunlist](#shunlist)|1272|1272|314|24.6%|33.2%|
[openbl_1d](#openbl_1d)|189|189|188|99.4%|19.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|114|0.0%|12.0%|
[spamhaus_drop](#spamhaus_drop)|654|18469632|61|0.0%|6.4%|
[et_block](#et_block)|1007|18338646|61|0.0%|6.4%|
[dshield](#dshield)|20|5120|59|1.1%|6.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|47|0.0%|4.9%|
[blocklist_de_strongips](#blocklist_de_strongips)|178|178|23|12.9%|2.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|19|0.0%|2.0%|
[blocklist_de_mail](#blocklist_de_mail)|17398|17398|15|0.0%|1.5%|
[blocklist_de_imap](#blocklist_de_imap)|3124|3124|12|0.3%|1.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|7|0.0%|0.7%|
[stopforumspam_30d](#stopforumspam_30d)|92996|92996|3|0.0%|0.3%|
[snort_ipfilter](#snort_ipfilter)|9369|9369|3|0.0%|0.3%|
[voipbl](#voipbl)|10398|10808|1|0.0%|0.1%|
[sorbs_spam](#sorbs_spam)|23029|23820|1|0.0%|0.1%|
[nixspam](#nixspam)|20978|20978|1|0.0%|0.1%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.1%|
[blocklist_de_apache](#blocklist_de_apache)|13522|13522|1|0.0%|0.1%|

## palevo

[Abuse.ch Palevo tracker](https://palevotracker.abuse.ch) worm includes IPs which are being used as botnet C&C for the Palevo crimeware - **excellent list**

Source is downloaded from [this link](https://palevotracker.abuse.ch/blocklists.php?download=ipblocklist).

The last time downloaded was found to be dated: Thu Jun  4 13:09:22 UTC 2015.

The ipset `palevo` has **13** entries, **13** unique IPs.

The following table shows the overlaps of `palevo` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `palevo`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `palevo`.
- ` this % ` is the percentage **of this ipset (`palevo`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[et_block](#et_block)|1007|18338646|12|0.0%|92.3%|
[snort_ipfilter](#snort_ipfilter)|9369|9369|11|0.1%|84.6%|
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
[stopforumspam_1d](#stopforumspam_1d)|7074|7074|107|1.5%|38.0%|
[blocklist_de](#blocklist_de)|38212|38212|65|0.1%|23.1%|
[blocklist_de_bots](#blocklist_de_bots)|3113|3113|51|1.6%|18.1%|
[snort_ipfilter](#snort_ipfilter)|9369|9369|38|0.4%|13.5%|
[php_spammers](#php_spammers)|417|417|32|7.6%|11.3%|
[blocklist_de_strongips](#blocklist_de_strongips)|178|178|32|17.9%|11.3%|
[et_tor](#et_tor)|6380|6380|29|0.4%|10.3%|
[dm_tor](#dm_tor)|6585|6585|29|0.4%|10.3%|
[bm_tor](#bm_tor)|6584|6584|29|0.4%|10.3%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|28|7.5%|9.9%|
[spamhaus_drop](#spamhaus_drop)|654|18469632|25|0.0%|8.8%|
[et_block](#et_block)|1007|18338646|25|0.0%|8.8%|
[blocklist_de_apache](#blocklist_de_apache)|13522|13522|24|0.1%|8.5%|
[php_dictionary](#php_dictionary)|433|433|22|5.0%|7.8%|
[blocklist_de_mail](#blocklist_de_mail)|17398|17398|20|0.1%|7.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|15|0.0%|5.3%|
[alienvault_reputation](#alienvault_reputation)|178477|178477|14|0.0%|4.9%|
[sorbs_spam](#sorbs_spam)|23029|23820|11|0.0%|3.9%|
[ri_web_proxies](#ri_web_proxies)|6153|6153|11|0.1%|3.9%|
[php_harvesters](#php_harvesters)|257|257|9|3.5%|3.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|9|0.0%|3.2%|
[openbl_60d](#openbl_60d)|7701|7701|8|0.1%|2.8%|
[nixspam](#nixspam)|20978|20978|8|0.0%|2.8%|
[spamhaus_edrop](#spamhaus_edrop)|55|486400|7|0.0%|2.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|5|0.0%|1.7%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2186|2186|5|0.2%|1.7%|
[proxz](#proxz)|702|702|4|0.5%|1.4%|
[xroxy](#xroxy)|2059|2059|3|0.1%|1.0%|
[sorbs_web](#sorbs_web)|656|657|2|0.3%|0.7%|
[zeus_badips](#zeus_badips)|235|235|1|0.4%|0.3%|
[zeus](#zeus)|268|268|1|0.3%|0.3%|
[proxyrss](#proxyrss)|1604|1604|1|0.0%|0.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.3%|

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
[sorbs_spam](#sorbs_spam)|23029|23820|90|0.3%|20.7%|
[stopforumspam_30d](#stopforumspam_30d)|92996|92996|85|0.0%|19.6%|
[php_spammers](#php_spammers)|417|417|84|20.1%|19.3%|
[nixspam](#nixspam)|20978|20978|70|0.3%|16.1%|
[stopforumspam_7d](#stopforumspam_7d)|30334|30334|57|0.1%|13.1%|
[blocklist_de](#blocklist_de)|38212|38212|57|0.1%|13.1%|
[snort_ipfilter](#snort_ipfilter)|9369|9369|52|0.5%|12.0%|
[blocklist_de_mail](#blocklist_de_mail)|17398|17398|44|0.2%|10.1%|
[ri_web_proxies](#ri_web_proxies)|6153|6153|33|0.5%|7.6%|
[sorbs_web](#sorbs_web)|656|657|26|3.9%|6.0%|
[xroxy](#xroxy)|2059|2059|24|1.1%|5.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|24|0.0%|5.5%|
[php_commenters](#php_commenters)|281|281|22|7.8%|5.0%|
[stopforumspam_1d](#stopforumspam_1d)|7074|7074|21|0.2%|4.8%|
[proxz](#proxz)|702|702|10|1.4%|2.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|10|0.0%|2.3%|
[blocklist_de_bots](#blocklist_de_bots)|3113|3113|10|0.3%|2.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|9|0.0%|2.0%|
[alienvault_reputation](#alienvault_reputation)|178477|178477|6|0.0%|1.3%|
[spamhaus_drop](#spamhaus_drop)|654|18469632|4|0.0%|0.9%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|4|1.0%|0.9%|
[et_tor](#et_tor)|6380|6380|4|0.0%|0.9%|
[et_block](#et_block)|1007|18338646|4|0.0%|0.9%|
[dm_tor](#dm_tor)|6585|6585|4|0.0%|0.9%|
[bm_tor](#bm_tor)|6584|6584|4|0.0%|0.9%|
[ri_connect_proxies](#ri_connect_proxies)|2310|2310|3|0.1%|0.6%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2186|2186|3|0.1%|0.6%|
[blocklist_de_apache](#blocklist_de_apache)|13522|13522|3|0.0%|0.6%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2|0.0%|0.4%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|2|0.0%|0.4%|
[blocklist_de_strongips](#blocklist_de_strongips)|178|178|2|1.1%|0.4%|
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
[stopforumspam_1d](#stopforumspam_1d)|7074|7074|36|0.5%|14.0%|
[blocklist_de](#blocklist_de)|38212|38212|27|0.0%|10.5%|
[blocklist_de_bots](#blocklist_de_bots)|3113|3113|18|0.5%|7.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|15|0.0%|5.8%|
[snort_ipfilter](#snort_ipfilter)|9369|9369|9|0.0%|3.5%|
[php_commenters](#php_commenters)|281|281|9|3.2%|3.5%|
[alienvault_reputation](#alienvault_reputation)|178477|178477|8|0.0%|3.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|7|0.0%|2.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|7|0.0%|2.7%|
[et_tor](#et_tor)|6380|6380|7|0.1%|2.7%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|6|1.6%|2.3%|
[dm_tor](#dm_tor)|6585|6585|6|0.0%|2.3%|
[bm_tor](#bm_tor)|6584|6584|6|0.0%|2.3%|
[sorbs_spam](#sorbs_spam)|23029|23820|5|0.0%|1.9%|
[nixspam](#nixspam)|20978|20978|5|0.0%|1.9%|
[blocklist_de_mail](#blocklist_de_mail)|17398|17398|4|0.0%|1.5%|
[blocklist_de_apache](#blocklist_de_apache)|13522|13522|4|0.0%|1.5%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2186|2186|3|0.1%|1.1%|
[xroxy](#xroxy)|2059|2059|2|0.0%|0.7%|
[proxyrss](#proxyrss)|1604|1604|2|0.1%|0.7%|
[openbl_60d](#openbl_60d)|7701|7701|2|0.0%|0.7%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|2|0.0%|0.7%|
[blocklist_de_strongips](#blocklist_de_strongips)|178|178|2|1.1%|0.7%|
[blocklist_de_ftp](#blocklist_de_ftp)|877|877|2|0.2%|0.7%|
[spamhaus_edrop](#spamhaus_edrop)|55|486400|1|0.0%|0.3%|
[spamhaus_drop](#spamhaus_drop)|654|18469632|1|0.0%|0.3%|
[ri_web_proxies](#ri_web_proxies)|6153|6153|1|0.0%|0.3%|
[php_spammers](#php_spammers)|417|417|1|0.2%|0.3%|
[php_dictionary](#php_dictionary)|433|433|1|0.2%|0.3%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.3%|
[fullbogons](#fullbogons)|3733|670419608|1|0.0%|0.3%|
[et_block](#et_block)|1007|18338646|1|0.0%|0.3%|
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
[sorbs_spam](#sorbs_spam)|23029|23820|81|0.3%|19.4%|
[stopforumspam_7d](#stopforumspam_7d)|30334|30334|57|0.1%|13.6%|
[snort_ipfilter](#snort_ipfilter)|9369|9369|53|0.5%|12.7%|
[nixspam](#nixspam)|20978|20978|53|0.2%|12.7%|
[blocklist_de](#blocklist_de)|38212|38212|52|0.1%|12.4%|
[blocklist_de_mail](#blocklist_de_mail)|17398|17398|39|0.2%|9.3%|
[php_commenters](#php_commenters)|281|281|32|11.3%|7.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|31|0.0%|7.4%|
[stopforumspam_1d](#stopforumspam_1d)|7074|7074|27|0.3%|6.4%|
[ri_web_proxies](#ri_web_proxies)|6153|6153|26|0.4%|6.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|26|0.0%|6.2%|
[sorbs_web](#sorbs_web)|656|657|22|3.3%|5.2%|
[xroxy](#xroxy)|2059|2059|20|0.9%|4.7%|
[proxz](#proxz)|702|702|9|1.2%|2.1%|
[blocklist_de_bots](#blocklist_de_bots)|3113|3113|8|0.2%|1.9%|
[et_tor](#et_tor)|6380|6380|6|0.0%|1.4%|
[dm_tor](#dm_tor)|6585|6585|6|0.0%|1.4%|
[bm_tor](#bm_tor)|6584|6584|6|0.0%|1.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|5|0.0%|1.1%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2186|2186|5|0.2%|1.1%|
[blocklist_de_apache](#blocklist_de_apache)|13522|13522|5|0.0%|1.1%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|4|1.0%|0.9%|
[blocklist_de_strongips](#blocklist_de_strongips)|178|178|4|2.2%|0.9%|
[spamhaus_drop](#spamhaus_drop)|654|18469632|3|0.0%|0.7%|
[alienvault_reputation](#alienvault_reputation)|178477|178477|3|0.0%|0.7%|
[ri_connect_proxies](#ri_connect_proxies)|2310|2310|2|0.0%|0.4%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2|0.0%|0.4%|
[et_block](#et_block)|1007|18338646|2|0.0%|0.4%|
[proxyrss](#proxyrss)|1604|1604|1|0.0%|0.2%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.2%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1|0.0%|0.2%|

## proxyrss

[proxyrss.com](http://www.proxyrss.com) open proxies syndicated from multiple sources.

Source is downloaded from [this link](http://www.proxyrss.com/proxylists/all.gz).

The last time downloaded was found to be dated: Thu Jun  4 09:51:31 UTC 2015.

The ipset `proxyrss` has **1604** entries, **1604** unique IPs.

The following table shows the overlaps of `proxyrss` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `proxyrss`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `proxyrss`.
- ` this % ` is the percentage **of this ipset (`proxyrss`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_30d](#stopforumspam_30d)|92996|92996|841|0.9%|52.4%|
[ri_web_proxies](#ri_web_proxies)|6153|6153|700|11.3%|43.6%|
[stopforumspam_7d](#stopforumspam_7d)|30334|30334|696|2.2%|43.3%|
[xroxy](#xroxy)|2059|2059|454|22.0%|28.3%|
[stopforumspam_1d](#stopforumspam_1d)|7074|7074|410|5.7%|25.5%|
[ri_connect_proxies](#ri_connect_proxies)|2310|2310|285|12.3%|17.7%|
[blocklist_de](#blocklist_de)|38212|38212|250|0.6%|15.5%|
[blocklist_de_bots](#blocklist_de_bots)|3113|3113|247|7.9%|15.3%|
[proxz](#proxz)|702|702|202|28.7%|12.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|71|0.0%|4.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|57|0.0%|3.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|51|0.0%|3.1%|
[nixspam](#nixspam)|20978|20978|17|0.0%|1.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|10|1.4%|0.6%|
[sorbs_spam](#sorbs_spam)|23029|23820|5|0.0%|0.3%|
[blocklist_de_strongips](#blocklist_de_strongips)|178|178|4|2.2%|0.2%|
[snort_ipfilter](#snort_ipfilter)|9369|9369|3|0.0%|0.1%|
[php_harvesters](#php_harvesters)|257|257|2|0.7%|0.1%|
[alienvault_reputation](#alienvault_reputation)|178477|178477|2|0.0%|0.1%|
[sorbs_socks](#sorbs_socks)|23|23|1|4.3%|0.0%|
[sorbs_misc](#sorbs_misc)|23|23|1|4.3%|0.0%|
[sorbs_http](#sorbs_http)|23|23|1|4.3%|0.0%|
[php_spammers](#php_spammers)|417|417|1|0.2%|0.0%|
[php_commenters](#php_commenters)|281|281|1|0.3%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|14281|14281|1|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2186|2186|1|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13522|13522|1|0.0%|0.0%|

## proxz

[proxz.com](http://www.proxz.com) open proxies (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.proxz.com/proxylists.xml).

The last time downloaded was found to be dated: Thu Jun  4 12:11:40 UTC 2015.

The ipset `proxz` has **702** entries, **702** unique IPs.

The following table shows the overlaps of `proxz` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `proxz`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `proxz`.
- ` this % ` is the percentage **of this ipset (`proxz`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_30d](#stopforumspam_30d)|92996|92996|421|0.4%|59.9%|
[stopforumspam_7d](#stopforumspam_7d)|30334|30334|352|1.1%|50.1%|
[ri_web_proxies](#ri_web_proxies)|6153|6153|309|5.0%|44.0%|
[xroxy](#xroxy)|2059|2059|295|14.3%|42.0%|
[proxyrss](#proxyrss)|1604|1604|202|12.5%|28.7%|
[blocklist_de](#blocklist_de)|38212|38212|131|0.3%|18.6%|
[stopforumspam_1d](#stopforumspam_1d)|7074|7074|127|1.7%|18.0%|
[ri_connect_proxies](#ri_connect_proxies)|2310|2310|112|4.8%|15.9%|
[blocklist_de_bots](#blocklist_de_bots)|3113|3113|109|3.5%|15.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|60|0.0%|8.5%|
[nixspam](#nixspam)|20978|20978|31|0.1%|4.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|30|0.0%|4.2%|
[sorbs_spam](#sorbs_spam)|23029|23820|29|0.1%|4.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|27|0.0%|3.8%|
[snort_ipfilter](#snort_ipfilter)|9369|9369|20|0.2%|2.8%|
[blocklist_de_mail](#blocklist_de_mail)|17398|17398|20|0.1%|2.8%|
[sorbs_web](#sorbs_web)|656|657|11|1.6%|1.5%|
[php_dictionary](#php_dictionary)|433|433|10|2.3%|1.4%|
[php_spammers](#php_spammers)|417|417|9|2.1%|1.2%|
[php_commenters](#php_commenters)|281|281|4|1.4%|0.5%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|4|0.5%|0.5%|
[blocklist_de_strongips](#blocklist_de_strongips)|178|178|3|1.6%|0.4%|
[alienvault_reputation](#alienvault_reputation)|178477|178477|3|0.0%|0.4%|
[et_compromised](#et_compromised)|2171|2171|2|0.0%|0.2%|
[bruteforceblocker](#bruteforceblocker)|2052|2052|2|0.0%|0.2%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1|0.0%|0.1%|
[blocklist_de_ssh](#blocklist_de_ssh)|14281|14281|1|0.0%|0.1%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2186|2186|1|0.0%|0.1%|
[blocklist_de_apache](#blocklist_de_apache)|13522|13522|1|0.0%|0.1%|

## ri_connect_proxies

[rosinstrument.com](http://www.rosinstrument.com) open CONNECT proxies (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://tools.rosinstrument.com/proxy/plab100.xml).

The last time downloaded was found to be dated: Thu Jun  4 11:46:46 UTC 2015.

The ipset `ri_connect_proxies` has **2310** entries, **2310** unique IPs.

The following table shows the overlaps of `ri_connect_proxies` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ri_connect_proxies`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ri_connect_proxies`.
- ` this % ` is the percentage **of this ipset (`ri_connect_proxies`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_30d](#stopforumspam_30d)|92996|92996|1342|1.4%|58.0%|
[ri_web_proxies](#ri_web_proxies)|6153|6153|941|15.2%|40.7%|
[stopforumspam_7d](#stopforumspam_7d)|30334|30334|681|2.2%|29.4%|
[xroxy](#xroxy)|2059|2059|348|16.9%|15.0%|
[proxyrss](#proxyrss)|1604|1604|285|17.7%|12.3%|
[stopforumspam_1d](#stopforumspam_1d)|7074|7074|160|2.2%|6.9%|
[proxz](#proxz)|702|702|112|15.9%|4.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|91|0.0%|3.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|74|0.0%|3.2%|
[blocklist_de](#blocklist_de)|38212|38212|72|0.1%|3.1%|
[blocklist_de_bots](#blocklist_de_bots)|3113|3113|68|2.1%|2.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|50|0.0%|2.1%|
[nixspam](#nixspam)|20978|20978|20|0.0%|0.8%|
[sorbs_spam](#sorbs_spam)|23029|23820|9|0.0%|0.3%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|6|0.8%|0.2%|
[snort_ipfilter](#snort_ipfilter)|9369|9369|4|0.0%|0.1%|
[php_dictionary](#php_dictionary)|433|433|3|0.6%|0.1%|
[sorbs_web](#sorbs_web)|656|657|2|0.3%|0.0%|
[php_spammers](#php_spammers)|417|417|2|0.4%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|17398|17398|2|0.0%|0.0%|
[alienvault_reputation](#alienvault_reputation)|178477|178477|2|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.0%|
[et_tor](#et_tor)|6380|6380|1|0.0%|0.0%|
[dm_tor](#dm_tor)|6585|6585|1|0.0%|0.0%|
[bm_tor](#bm_tor)|6584|6584|1|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|14281|14281|1|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2186|2186|1|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13522|13522|1|0.0%|0.0%|

## ri_web_proxies

[rosinstrument.com](http://www.rosinstrument.com) open HTTP proxies (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://tools.rosinstrument.com/proxy/l100.xml).

The last time downloaded was found to be dated: Thu Jun  4 11:45:05 UTC 2015.

The ipset `ri_web_proxies` has **6153** entries, **6153** unique IPs.

The following table shows the overlaps of `ri_web_proxies` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ri_web_proxies`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ri_web_proxies`.
- ` this % ` is the percentage **of this ipset (`ri_web_proxies`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_30d](#stopforumspam_30d)|92996|92996|2986|3.2%|48.5%|
[stopforumspam_7d](#stopforumspam_7d)|30334|30334|1660|5.4%|26.9%|
[ri_connect_proxies](#ri_connect_proxies)|2310|2310|941|40.7%|15.2%|
[xroxy](#xroxy)|2059|2059|871|42.3%|14.1%|
[proxyrss](#proxyrss)|1604|1604|700|43.6%|11.3%|
[stopforumspam_1d](#stopforumspam_1d)|7074|7074|503|7.1%|8.1%|
[blocklist_de](#blocklist_de)|38212|38212|395|1.0%|6.4%|
[blocklist_de_bots](#blocklist_de_bots)|3113|3113|341|10.9%|5.5%|
[proxz](#proxz)|702|702|309|44.0%|5.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|179|0.0%|2.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|172|0.0%|2.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|130|0.0%|2.1%|
[sorbs_spam](#sorbs_spam)|23029|23820|106|0.4%|1.7%|
[nixspam](#nixspam)|20978|20978|89|0.4%|1.4%|
[snort_ipfilter](#snort_ipfilter)|9369|9369|61|0.6%|0.9%|
[blocklist_de_mail](#blocklist_de_mail)|17398|17398|54|0.3%|0.8%|
[php_dictionary](#php_dictionary)|433|433|33|7.6%|0.5%|
[sorbs_web](#sorbs_web)|656|657|26|3.9%|0.4%|
[php_spammers](#php_spammers)|417|417|26|6.2%|0.4%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|12|1.7%|0.1%|
[php_commenters](#php_commenters)|281|281|11|3.9%|0.1%|
[blocklist_de_strongips](#blocklist_de_strongips)|178|178|6|3.3%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|5|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|4|1.0%|0.0%|
[et_tor](#et_tor)|6380|6380|4|0.0%|0.0%|
[dm_tor](#dm_tor)|6585|6585|4|0.0%|0.0%|
[bm_tor](#bm_tor)|6584|6584|4|0.0%|0.0%|
[alienvault_reputation](#alienvault_reputation)|178477|178477|3|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|2|0.0%|0.0%|
[sorbs_socks](#sorbs_socks)|23|23|1|4.3%|0.0%|
[sorbs_misc](#sorbs_misc)|23|23|1|4.3%|0.0%|
[sorbs_http](#sorbs_http)|23|23|1|4.3%|0.0%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|
[et_compromised](#et_compromised)|2171|2171|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2052|2052|1|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2186|2186|1|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13522|13522|1|0.0%|0.0%|

## shunlist

[AutoShun.org](http://autoshun.org/) IPs identified as hostile by correlating logs from distributed snort installations running the autoshun plugin

Source is downloaded from [this link](http://www.autoshun.org/files/shunlist.csv).

The last time downloaded was found to be dated: Thu Jun  4 10:30:06 UTC 2015.

The ipset `shunlist` has **1272** entries, **1272** unique IPs.

The following table shows the overlaps of `shunlist` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `shunlist`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `shunlist`.
- ` this % ` is the percentage **of this ipset (`shunlist`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[alienvault_reputation](#alienvault_reputation)|178477|178477|1265|0.7%|99.4%|
[openbl_60d](#openbl_60d)|7701|7701|594|7.7%|46.6%|
[openbl_30d](#openbl_30d)|3255|3255|579|17.7%|45.5%|
[et_compromised](#et_compromised)|2171|2171|496|22.8%|38.9%|
[bruteforceblocker](#bruteforceblocker)|2052|2052|489|23.8%|38.4%|
[blocklist_de](#blocklist_de)|38212|38212|402|1.0%|31.6%|
[blocklist_de_ssh](#blocklist_de_ssh)|14281|14281|361|2.5%|28.3%|
[openbl_7d](#openbl_7d)|943|943|314|33.2%|24.6%|
[dshield](#dshield)|20|5120|126|2.4%|9.9%|
[et_block](#et_block)|1007|18338646|108|0.0%|8.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|104|0.0%|8.1%|
[spamhaus_drop](#spamhaus_drop)|654|18469632|99|0.0%|7.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|74|0.0%|5.8%|
[openbl_1d](#openbl_1d)|189|189|73|38.6%|5.7%|
[sslbl](#sslbl)|366|366|56|15.3%|4.4%|
[blocklist_de_apache](#blocklist_de_apache)|13522|13522|38|0.2%|2.9%|
[ciarmy](#ciarmy)|343|343|27|7.8%|2.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|26|0.0%|2.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|178|178|20|11.2%|1.5%|
[voipbl](#voipbl)|10398|10808|11|0.1%|0.8%|
[blocklist_de_mail](#blocklist_de_mail)|17398|17398|5|0.0%|0.3%|
[stopforumspam_30d](#stopforumspam_30d)|92996|92996|4|0.0%|0.3%|
[blocklist_de_imap](#blocklist_de_imap)|3124|3124|4|0.1%|0.3%|
[stopforumspam_7d](#stopforumspam_7d)|30334|30334|3|0.0%|0.2%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2186|2186|3|0.1%|0.2%|
[snort_ipfilter](#snort_ipfilter)|9369|9369|2|0.0%|0.1%|
[nixspam](#nixspam)|20978|20978|2|0.0%|0.1%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|2|0.5%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2|0.0%|0.1%|
[stopforumspam_1d](#stopforumspam_1d)|7074|7074|1|0.0%|0.0%|
[sorbs_spam](#sorbs_spam)|23029|23820|1|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.0%|
[et_tor](#et_tor)|6380|6380|1|0.0%|0.0%|
[dm_tor](#dm_tor)|6585|6585|1|0.0%|0.0%|
[bm_tor](#bm_tor)|6584|6584|1|0.0%|0.0%|

## snort_ipfilter

[labs.snort.org](https://labs.snort.org/) supplied IP blacklist (this list seems to be updated frequently, but we found no information about it)

Source is downloaded from [this link](http://labs.snort.org/feeds/ip-filter.blf).

The last time downloaded was found to be dated: Thu Jun  4 01:30:00 UTC 2015.

The ipset `snort_ipfilter` has **9369** entries, **9369** unique IPs.

The following table shows the overlaps of `snort_ipfilter` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `snort_ipfilter`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `snort_ipfilter`.
- ` this % ` is the percentage **of this ipset (`snort_ipfilter`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[et_tor](#et_tor)|6380|6380|1088|17.0%|11.6%|
[bm_tor](#bm_tor)|6584|6584|1067|16.2%|11.3%|
[dm_tor](#dm_tor)|6585|6585|1065|16.1%|11.3%|
[stopforumspam_30d](#stopforumspam_30d)|92996|92996|813|0.8%|8.6%|
[stopforumspam_7d](#stopforumspam_7d)|30334|30334|621|2.0%|6.6%|
[stopforumspam_1d](#stopforumspam_1d)|7074|7074|366|5.1%|3.9%|
[sorbs_spam](#sorbs_spam)|23029|23820|332|1.3%|3.5%|
[et_block](#et_block)|1007|18338646|305|0.0%|3.2%|
[zeus](#zeus)|268|268|227|84.7%|2.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|224|0.0%|2.3%|
[zeus_badips](#zeus_badips)|235|235|205|87.2%|2.1%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|176|47.3%|1.8%|
[blocklist_de](#blocklist_de)|38212|38212|170|0.4%|1.8%|
[blocklist_de_mail](#blocklist_de_mail)|17398|17398|145|0.8%|1.5%|
[nixspam](#nixspam)|20978|20978|144|0.6%|1.5%|
[alienvault_reputation](#alienvault_reputation)|178477|178477|122|0.0%|1.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|105|0.0%|1.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|98|0.0%|1.0%|
[feodo](#feodo)|90|90|68|75.5%|0.7%|
[ri_web_proxies](#ri_web_proxies)|6153|6153|61|0.9%|0.6%|
[sorbs_web](#sorbs_web)|656|657|58|8.8%|0.6%|
[php_spammers](#php_spammers)|417|417|53|12.7%|0.5%|
[php_dictionary](#php_dictionary)|433|433|52|12.0%|0.5%|
[xroxy](#xroxy)|2059|2059|49|2.3%|0.5%|
[php_commenters](#php_commenters)|281|281|38|13.5%|0.4%|
[openbl_60d](#openbl_60d)|7701|7701|29|0.3%|0.3%|
[sslbl](#sslbl)|366|366|28|7.6%|0.2%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|26|2.0%|0.2%|
[spamhaus_drop](#spamhaus_drop)|654|18469632|20|0.0%|0.2%|
[proxz](#proxz)|702|702|20|2.8%|0.2%|
[blocklist_de_bots](#blocklist_de_bots)|3113|3113|19|0.6%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|14|0.0%|0.1%|
[palevo](#palevo)|13|13|11|84.6%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|11|0.0%|0.1%|
[php_harvesters](#php_harvesters)|257|257|9|3.5%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13522|13522|8|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|486400|6|0.0%|0.0%|
[openbl_30d](#openbl_30d)|3255|3255|6|0.1%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|3124|3124|5|0.1%|0.0%|
[sorbs_socks](#sorbs_socks)|23|23|4|17.3%|0.0%|
[sorbs_misc](#sorbs_misc)|23|23|4|17.3%|0.0%|
[sorbs_http](#sorbs_http)|23|23|4|17.3%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2310|2310|4|0.1%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2186|2186|4|0.1%|0.0%|
[proxyrss](#proxyrss)|1604|1604|3|0.1%|0.0%|
[openbl_7d](#openbl_7d)|943|943|3|0.3%|0.0%|
[shunlist](#shunlist)|1272|1272|2|0.1%|0.0%|
[voipbl](#voipbl)|10398|10808|1|0.0%|0.0%|
[malc0de](#malc0de)|379|379|1|0.2%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|1|0.1%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|178|178|1|0.5%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|14281|14281|1|0.0%|0.0%|

## sorbs_dul

[Sorbs.net](https://www.sorbs.net/) DUL, Dynamic User IPs extracted from deltas.

Source is downloaded from [this link]().

The last time downloaded was found to be dated: Thu Jun  4 13:04:11 UTC 2015.

The ipset `sorbs_dul` has **8** entries, **3584** unique IPs.

The following table shows the overlaps of `sorbs_dul` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `sorbs_dul`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `sorbs_dul`.
- ` this % ` is the percentage **of this ipset (`sorbs_dul`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|

## sorbs_http

[Sorbs.net](https://www.sorbs.net/) HTTP proxies, extracted from deltas.

Source is downloaded from [this link]().

The last time downloaded was found to be dated: Thu Jun  4 13:04:10 UTC 2015.

The ipset `sorbs_http` has **23** entries, **23** unique IPs.

The following table shows the overlaps of `sorbs_http` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `sorbs_http`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `sorbs_http`.
- ` this % ` is the percentage **of this ipset (`sorbs_http`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[sorbs_socks](#sorbs_socks)|23|23|23|100.0%|100.0%|
[sorbs_misc](#sorbs_misc)|23|23|23|100.0%|100.0%|
[sorbs_spam](#sorbs_spam)|23029|23820|17|0.0%|73.9%|
[sorbs_web](#sorbs_web)|656|657|5|0.7%|21.7%|
[blocklist_de](#blocklist_de)|38212|38212|5|0.0%|21.7%|
[snort_ipfilter](#snort_ipfilter)|9369|9369|4|0.0%|17.3%|
[blocklist_de_mail](#blocklist_de_mail)|17398|17398|3|0.0%|13.0%|
[stopforumspam_7d](#stopforumspam_7d)|30334|30334|2|0.0%|8.6%|
[stopforumspam_30d](#stopforumspam_30d)|92996|92996|2|0.0%|8.6%|
[stopforumspam_1d](#stopforumspam_1d)|7074|7074|2|0.0%|8.6%|
[nixspam](#nixspam)|20978|20978|2|0.0%|8.6%|
[blocklist_de_bots](#blocklist_de_bots)|3113|3113|2|0.0%|8.6%|
[xroxy](#xroxy)|2059|2059|1|0.0%|4.3%|
[ri_web_proxies](#ri_web_proxies)|6153|6153|1|0.0%|4.3%|
[proxyrss](#proxyrss)|1604|1604|1|0.0%|4.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|1|0.0%|4.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|1|0.0%|4.3%|

## sorbs_misc

[Sorbs.net](https://www.sorbs.net/) MISC proxies, extracted from deltas.

Source is downloaded from [this link]().

The last time downloaded was found to be dated: Thu Jun  4 13:04:11 UTC 2015.

The ipset `sorbs_misc` has **23** entries, **23** unique IPs.

The following table shows the overlaps of `sorbs_misc` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `sorbs_misc`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `sorbs_misc`.
- ` this % ` is the percentage **of this ipset (`sorbs_misc`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[sorbs_socks](#sorbs_socks)|23|23|23|100.0%|100.0%|
[sorbs_http](#sorbs_http)|23|23|23|100.0%|100.0%|
[sorbs_spam](#sorbs_spam)|23029|23820|17|0.0%|73.9%|
[sorbs_web](#sorbs_web)|656|657|5|0.7%|21.7%|
[blocklist_de](#blocklist_de)|38212|38212|5|0.0%|21.7%|
[snort_ipfilter](#snort_ipfilter)|9369|9369|4|0.0%|17.3%|
[blocklist_de_mail](#blocklist_de_mail)|17398|17398|3|0.0%|13.0%|
[stopforumspam_7d](#stopforumspam_7d)|30334|30334|2|0.0%|8.6%|
[stopforumspam_30d](#stopforumspam_30d)|92996|92996|2|0.0%|8.6%|
[stopforumspam_1d](#stopforumspam_1d)|7074|7074|2|0.0%|8.6%|
[nixspam](#nixspam)|20978|20978|2|0.0%|8.6%|
[blocklist_de_bots](#blocklist_de_bots)|3113|3113|2|0.0%|8.6%|
[xroxy](#xroxy)|2059|2059|1|0.0%|4.3%|
[ri_web_proxies](#ri_web_proxies)|6153|6153|1|0.0%|4.3%|
[proxyrss](#proxyrss)|1604|1604|1|0.0%|4.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|1|0.0%|4.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|1|0.0%|4.3%|

## sorbs_smtp

[Sorbs.net](https://www.sorbs.net/) SMTP Open Relays, extracted from deltas.

Source is downloaded from [this link]().

The last time downloaded was found to be dated: Thu Jun  4 13:04:11 UTC 2015.

The ipset `sorbs_smtp` has **9** entries, **9** unique IPs.

The following table shows the overlaps of `sorbs_smtp` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `sorbs_smtp`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `sorbs_smtp`.
- ` this % ` is the percentage **of this ipset (`sorbs_smtp`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[sorbs_spam](#sorbs_spam)|23029|23820|9|0.0%|100.0%|
[nixspam](#nixspam)|20978|20978|1|0.0%|11.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|1|0.0%|11.1%|

## sorbs_socks

[Sorbs.net](https://www.sorbs.net/) SOCKS proxies, extracted from deltas.

Source is downloaded from [this link]().

The last time downloaded was found to be dated: Thu Jun  4 13:04:11 UTC 2015.

The ipset `sorbs_socks` has **23** entries, **23** unique IPs.

The following table shows the overlaps of `sorbs_socks` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `sorbs_socks`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `sorbs_socks`.
- ` this % ` is the percentage **of this ipset (`sorbs_socks`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[sorbs_misc](#sorbs_misc)|23|23|23|100.0%|100.0%|
[sorbs_http](#sorbs_http)|23|23|23|100.0%|100.0%|
[sorbs_spam](#sorbs_spam)|23029|23820|17|0.0%|73.9%|
[sorbs_web](#sorbs_web)|656|657|5|0.7%|21.7%|
[blocklist_de](#blocklist_de)|38212|38212|5|0.0%|21.7%|
[snort_ipfilter](#snort_ipfilter)|9369|9369|4|0.0%|17.3%|
[blocklist_de_mail](#blocklist_de_mail)|17398|17398|3|0.0%|13.0%|
[stopforumspam_7d](#stopforumspam_7d)|30334|30334|2|0.0%|8.6%|
[stopforumspam_30d](#stopforumspam_30d)|92996|92996|2|0.0%|8.6%|
[stopforumspam_1d](#stopforumspam_1d)|7074|7074|2|0.0%|8.6%|
[nixspam](#nixspam)|20978|20978|2|0.0%|8.6%|
[blocklist_de_bots](#blocklist_de_bots)|3113|3113|2|0.0%|8.6%|
[xroxy](#xroxy)|2059|2059|1|0.0%|4.3%|
[ri_web_proxies](#ri_web_proxies)|6153|6153|1|0.0%|4.3%|
[proxyrss](#proxyrss)|1604|1604|1|0.0%|4.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|1|0.0%|4.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|1|0.0%|4.3%|

## sorbs_spam

[Sorbs.net](https://www.sorbs.net/) Spam senders, extracted from deltas.

Source is downloaded from [this link]().

The last time downloaded was found to be dated: Thu Jun  4 13:04:11 UTC 2015.

The ipset `sorbs_spam` has **23029** entries, **23820** unique IPs.

The following table shows the overlaps of `sorbs_spam` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `sorbs_spam`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `sorbs_spam`.
- ` this % ` is the percentage **of this ipset (`sorbs_spam`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[nixspam](#nixspam)|20978|20978|4007|19.1%|16.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|1710|0.0%|7.1%|
[blocklist_de](#blocklist_de)|38212|38212|985|2.5%|4.1%|
[blocklist_de_mail](#blocklist_de_mail)|17398|17398|826|4.7%|3.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|559|0.0%|2.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|365|0.0%|1.5%|
[snort_ipfilter](#snort_ipfilter)|9369|9369|332|3.5%|1.3%|
[stopforumspam_30d](#stopforumspam_30d)|92996|92996|294|0.3%|1.2%|
[sorbs_web](#sorbs_web)|656|657|280|42.6%|1.1%|
[stopforumspam_7d](#stopforumspam_7d)|30334|30334|166|0.5%|0.6%|
[ri_web_proxies](#ri_web_proxies)|6153|6153|106|1.7%|0.4%|
[php_dictionary](#php_dictionary)|433|433|90|20.7%|0.3%|
[php_spammers](#php_spammers)|417|417|81|19.4%|0.3%|
[xroxy](#xroxy)|2059|2059|76|3.6%|0.3%|
[blocklist_de_ssh](#blocklist_de_ssh)|14281|14281|76|0.5%|0.3%|
[alienvault_reputation](#alienvault_reputation)|178477|178477|62|0.0%|0.2%|
[stopforumspam_1d](#stopforumspam_1d)|7074|7074|53|0.7%|0.2%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2186|2186|53|2.4%|0.2%|
[blocklist_de_apache](#blocklist_de_apache)|13522|13522|53|0.3%|0.2%|
[blocklist_de_bots](#blocklist_de_bots)|3113|3113|34|1.0%|0.1%|
[proxz](#proxz)|702|702|29|4.1%|0.1%|
[blocklist_de_imap](#blocklist_de_imap)|3124|3124|24|0.7%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|19|0.0%|0.0%|
[sorbs_socks](#sorbs_socks)|23|23|17|73.9%|0.0%|
[sorbs_misc](#sorbs_misc)|23|23|17|73.9%|0.0%|
[sorbs_http](#sorbs_http)|23|23|17|73.9%|0.0%|
[openbl_60d](#openbl_60d)|7701|7701|14|0.1%|0.0%|
[spamhaus_drop](#spamhaus_drop)|654|18469632|11|0.0%|0.0%|
[php_commenters](#php_commenters)|281|281|11|3.9%|0.0%|
[et_block](#et_block)|1007|18338646|11|0.0%|0.0%|
[sorbs_smtp](#sorbs_smtp)|9|9|9|100.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2310|2310|9|0.3%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|7|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|6|0.0%|0.0%|
[proxyrss](#proxyrss)|1604|1604|5|0.3%|0.0%|
[php_harvesters](#php_harvesters)|257|257|5|1.9%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|877|877|5|0.5%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|486400|3|0.0%|0.0%|
[openbl_30d](#openbl_30d)|3255|3255|2|0.0%|0.0%|
[et_tor](#et_tor)|6380|6380|2|0.0%|0.0%|
[bm_tor](#bm_tor)|6584|6584|2|0.0%|0.0%|
[shunlist](#shunlist)|1272|1272|1|0.0%|0.0%|
[openbl_7d](#openbl_7d)|943|943|1|0.1%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|1|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|1|0.1%|0.0%|
[et_compromised](#et_compromised)|2171|2171|1|0.0%|0.0%|
[dm_tor](#dm_tor)|6585|6585|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2052|2052|1|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|178|178|1|0.5%|0.0%|

## sorbs_web

[Sorbs.net](https://www.sorbs.net/) WEB exploits, extracted from deltas.

Source is downloaded from [this link]().

The last time downloaded was found to be dated: Thu Jun  4 13:04:11 UTC 2015.

The ipset `sorbs_web` has **656** entries, **657** unique IPs.

The following table shows the overlaps of `sorbs_web` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `sorbs_web`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `sorbs_web`.
- ` this % ` is the percentage **of this ipset (`sorbs_web`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[sorbs_spam](#sorbs_spam)|23029|23820|280|1.1%|42.6%|
[nixspam](#nixspam)|20978|20978|147|0.7%|22.3%|
[blocklist_de](#blocklist_de)|38212|38212|82|0.2%|12.4%|
[blocklist_de_mail](#blocklist_de_mail)|17398|17398|67|0.3%|10.1%|
[stopforumspam_30d](#stopforumspam_30d)|92996|92996|61|0.0%|9.2%|
[snort_ipfilter](#snort_ipfilter)|9369|9369|58|0.6%|8.8%|
[stopforumspam_7d](#stopforumspam_7d)|30334|30334|45|0.1%|6.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|42|0.0%|6.3%|
[xroxy](#xroxy)|2059|2059|26|1.2%|3.9%|
[ri_web_proxies](#ri_web_proxies)|6153|6153|26|0.4%|3.9%|
[php_dictionary](#php_dictionary)|433|433|26|6.0%|3.9%|
[php_spammers](#php_spammers)|417|417|22|5.2%|3.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|22|0.0%|3.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|21|0.0%|3.1%|
[stopforumspam_1d](#stopforumspam_1d)|7074|7074|19|0.2%|2.8%|
[proxz](#proxz)|702|702|11|1.5%|1.6%|
[blocklist_de_bots](#blocklist_de_bots)|3113|3113|11|0.3%|1.6%|
[sorbs_socks](#sorbs_socks)|23|23|5|21.7%|0.7%|
[sorbs_misc](#sorbs_misc)|23|23|5|21.7%|0.7%|
[sorbs_http](#sorbs_http)|23|23|5|21.7%|0.7%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2186|2186|3|0.1%|0.4%|
[blocklist_de_apache](#blocklist_de_apache)|13522|13522|3|0.0%|0.4%|
[ri_connect_proxies](#ri_connect_proxies)|2310|2310|2|0.0%|0.3%|
[php_commenters](#php_commenters)|281|281|2|0.7%|0.3%|
[spamhaus_drop](#spamhaus_drop)|654|18469632|1|0.0%|0.1%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1|0.0%|0.1%|
[et_block](#et_block)|1007|18338646|1|0.0%|0.1%|
[blocklist_de_strongips](#blocklist_de_strongips)|178|178|1|0.5%|0.1%|
[blocklist_de_ssh](#blocklist_de_ssh)|14281|14281|1|0.0%|0.1%|
[blocklist_de_imap](#blocklist_de_imap)|3124|3124|1|0.0%|0.1%|

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
[openbl_60d](#openbl_60d)|7701|7701|239|3.1%|0.0%|
[openbl_30d](#openbl_30d)|3255|3255|159|4.8%|0.0%|
[blocklist_de](#blocklist_de)|38212|38212|155|0.4%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|14281|14281|111|0.7%|0.0%|
[et_compromised](#et_compromised)|2171|2171|100|4.6%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2052|2052|100|4.8%|0.0%|
[shunlist](#shunlist)|1272|1272|99|7.7%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7074|7074|93|1.3%|0.0%|
[openbl_7d](#openbl_7d)|943|943|61|6.4%|0.0%|
[nixspam](#nixspam)|20978|20978|56|0.2%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|29|2.2%|0.0%|
[php_commenters](#php_commenters)|281|281|25|8.8%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3113|3113|21|0.6%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9369|9369|20|0.2%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|17398|17398|19|0.1%|0.0%|
[zeus_badips](#zeus_badips)|235|235|16|6.8%|0.0%|
[zeus](#zeus)|268|268|16|5.9%|0.0%|
[voipbl](#voipbl)|10398|10808|14|0.1%|0.0%|
[sorbs_spam](#sorbs_spam)|23029|23820|11|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|3124|3124|9|0.2%|0.0%|
[openbl_1d](#openbl_1d)|189|189|7|3.7%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|6|0.4%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|6|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|178|178|6|3.3%|0.0%|
[php_dictionary](#php_dictionary)|433|433|4|0.9%|0.0%|
[malc0de](#malc0de)|379|379|4|1.0%|0.0%|
[php_spammers](#php_spammers)|417|417|3|0.7%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|2|0.2%|0.0%|
[et_tor](#et_tor)|6380|6380|2|0.0%|0.0%|
[dm_tor](#dm_tor)|6585|6585|2|0.0%|0.0%|
[bm_tor](#bm_tor)|6584|6584|2|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2186|2186|2|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13522|13522|2|0.0%|0.0%|
[sslbl](#sslbl)|366|366|1|0.2%|0.0%|
[sorbs_web](#sorbs_web)|656|657|1|0.1%|0.0%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.0%|
[et_botcc](#et_botcc)|508|508|1|0.1%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|105|105|1|0.9%|0.0%|

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
[blocklist_de](#blocklist_de)|38212|38212|12|0.0%|0.0%|
[php_commenters](#php_commenters)|281|281|7|2.4%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9369|9369|6|0.0%|0.0%|
[zeus_badips](#zeus_badips)|235|235|5|2.1%|0.0%|
[zeus](#zeus)|268|268|5|1.8%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|178|178|5|2.8%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7074|7074|4|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|17398|17398|4|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3113|3113|4|0.1%|0.0%|
[sorbs_spam](#sorbs_spam)|23029|23820|3|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13522|13522|2|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.0%|
[openbl_60d](#openbl_60d)|7701|7701|1|0.0%|0.0%|
[openbl_30d](#openbl_30d)|3255|3255|1|0.0%|0.0%|
[malc0de](#malc0de)|379|379|1|0.2%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|14281|14281|1|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|3124|3124|1|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|877|877|1|0.1%|0.0%|

## sslbl

[Abuse.ch SSL Blacklist](https://sslbl.abuse.ch/) bad SSL traffic related to malware or botnet activities - **excellent list**

Source is downloaded from [this link](https://sslbl.abuse.ch/blacklist/sslipblacklist.csv).

The last time downloaded was found to be dated: Thu Jun  4 13:15:05 UTC 2015.

The ipset `sslbl` has **366** entries, **366** unique IPs.

The following table shows the overlaps of `sslbl` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `sslbl`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `sslbl`.
- ` this % ` is the percentage **of this ipset (`sslbl`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[alienvault_reputation](#alienvault_reputation)|178477|178477|64|0.0%|17.4%|
[shunlist](#shunlist)|1272|1272|56|4.4%|15.3%|
[feodo](#feodo)|90|90|34|37.7%|9.2%|
[et_block](#et_block)|1007|18338646|32|0.0%|8.7%|
[snort_ipfilter](#snort_ipfilter)|9369|9369|28|0.2%|7.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|23|0.0%|6.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|6|0.0%|1.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|4|0.0%|1.0%|
[stopforumspam_30d](#stopforumspam_30d)|92996|92996|1|0.0%|0.2%|
[spamhaus_drop](#spamhaus_drop)|654|18469632|1|0.0%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.2%|

## stopforumspam_1d

[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers in the last 24 hours - **excellent list**

Source is downloaded from [this link](http://www.stopforumspam.com/downloads/listed_ip_1.zip).

The last time downloaded was found to be dated: Thu Jun  4 13:00:02 UTC 2015.

The ipset `stopforumspam_1d` has **7074** entries, **7074** unique IPs.

The following table shows the overlaps of `stopforumspam_1d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `stopforumspam_1d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `stopforumspam_1d`.
- ` this % ` is the percentage **of this ipset (`stopforumspam_1d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_30d](#stopforumspam_30d)|92996|92996|5530|5.9%|78.1%|
[stopforumspam_7d](#stopforumspam_7d)|30334|30334|5368|17.6%|75.8%|
[blocklist_de](#blocklist_de)|38212|38212|1475|3.8%|20.8%|
[blocklist_de_bots](#blocklist_de_bots)|3113|3113|1386|44.5%|19.5%|
[ri_web_proxies](#ri_web_proxies)|6153|6153|503|8.1%|7.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|460|0.0%|6.5%|
[proxyrss](#proxyrss)|1604|1604|410|25.5%|5.7%|
[snort_ipfilter](#snort_ipfilter)|9369|9369|366|3.9%|5.1%|
[et_tor](#et_tor)|6380|6380|328|5.1%|4.6%|
[bm_tor](#bm_tor)|6584|6584|323|4.9%|4.5%|
[dm_tor](#dm_tor)|6585|6585|321|4.8%|4.5%|
[xroxy](#xroxy)|2059|2059|288|13.9%|4.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|224|0.0%|3.1%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|163|43.8%|2.3%|
[ri_connect_proxies](#ri_connect_proxies)|2310|2310|160|6.9%|2.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|160|0.0%|2.2%|
[proxz](#proxz)|702|702|127|18.0%|1.7%|
[php_commenters](#php_commenters)|281|281|107|38.0%|1.5%|
[blocklist_de_strongips](#blocklist_de_strongips)|178|178|104|58.4%|1.4%|
[spamhaus_drop](#spamhaus_drop)|654|18469632|93|0.0%|1.3%|
[et_block](#et_block)|1007|18338646|93|0.0%|1.3%|
[blocklist_de_apache](#blocklist_de_apache)|13522|13522|75|0.5%|1.0%|
[nixspam](#nixspam)|20978|20978|67|0.3%|0.9%|
[alienvault_reputation](#alienvault_reputation)|178477|178477|64|0.0%|0.9%|
[blocklist_de_mail](#blocklist_de_mail)|17398|17398|56|0.3%|0.7%|
[sorbs_spam](#sorbs_spam)|23029|23820|53|0.2%|0.7%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|45|0.0%|0.6%|
[php_harvesters](#php_harvesters)|257|257|36|14.0%|0.5%|
[php_spammers](#php_spammers)|417|417|27|6.4%|0.3%|
[openbl_60d](#openbl_60d)|7701|7701|22|0.2%|0.3%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2186|2186|22|1.0%|0.3%|
[php_dictionary](#php_dictionary)|433|433|21|4.8%|0.2%|
[sorbs_web](#sorbs_web)|656|657|19|2.8%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|8|0.0%|0.1%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|6|0.8%|0.0%|
[voipbl](#voipbl)|10398|10808|5|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|14281|14281|5|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|486400|4|0.0%|0.0%|
[sorbs_socks](#sorbs_socks)|23|23|2|8.6%|0.0%|
[sorbs_misc](#sorbs_misc)|23|23|2|8.6%|0.0%|
[sorbs_http](#sorbs_http)|23|23|2|8.6%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|877|877|2|0.2%|0.0%|
[zeus_badips](#zeus_badips)|235|235|1|0.4%|0.0%|
[zeus](#zeus)|268|268|1|0.3%|0.0%|
[shunlist](#shunlist)|1272|1272|1|0.0%|0.0%|
[openbl_30d](#openbl_30d)|3255|3255|1|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|
[et_compromised](#et_compromised)|2171|2171|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2052|2052|1|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|3124|3124|1|0.0%|0.0%|

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
[stopforumspam_1d](#stopforumspam_1d)|7074|7074|5530|78.1%|5.9%|
[ri_web_proxies](#ri_web_proxies)|6153|6153|2986|48.5%|3.2%|
[blocklist_de](#blocklist_de)|38212|38212|2558|6.6%|2.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|2521|0.0%|2.7%|
[blocklist_de_bots](#blocklist_de_bots)|3113|3113|2146|68.9%|2.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|1551|0.0%|1.6%|
[ri_connect_proxies](#ri_connect_proxies)|2310|2310|1342|58.0%|1.4%|
[xroxy](#xroxy)|2059|2059|1210|58.7%|1.3%|
[spamhaus_drop](#spamhaus_drop)|654|18469632|1014|0.0%|1.0%|
[et_block](#et_block)|1007|18338646|1014|0.0%|1.0%|
[proxyrss](#proxyrss)|1604|1604|841|52.4%|0.9%|
[snort_ipfilter](#snort_ipfilter)|9369|9369|813|8.6%|0.8%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|756|0.0%|0.8%|
[et_tor](#et_tor)|6380|6380|636|9.9%|0.6%|
[bm_tor](#bm_tor)|6584|6584|630|9.5%|0.6%|
[dm_tor](#dm_tor)|6585|6585|627|9.5%|0.6%|
[proxz](#proxz)|702|702|421|59.9%|0.4%|
[sorbs_spam](#sorbs_spam)|23029|23820|294|1.2%|0.3%|
[blocklist_de_mail](#blocklist_de_mail)|17398|17398|251|1.4%|0.2%|
[nixspam](#nixspam)|20978|20978|234|1.1%|0.2%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|233|62.6%|0.2%|
[alienvault_reputation](#alienvault_reputation)|178477|178477|218|0.1%|0.2%|
[php_commenters](#php_commenters)|281|281|206|73.3%|0.2%|
[blocklist_de_apache](#blocklist_de_apache)|13522|13522|205|1.5%|0.2%|
[blocklist_de_strongips](#blocklist_de_strongips)|178|178|133|74.7%|0.1%|
[blocklist_de_ssh](#blocklist_de_ssh)|14281|14281|101|0.7%|0.1%|
[php_spammers](#php_spammers)|417|417|100|23.9%|0.1%|
[spamhaus_edrop](#spamhaus_edrop)|55|486400|96|0.0%|0.1%|
[php_dictionary](#php_dictionary)|433|433|85|19.6%|0.0%|
[php_harvesters](#php_harvesters)|257|257|64|24.9%|0.0%|
[sorbs_web](#sorbs_web)|656|657|61|9.2%|0.0%|
[openbl_60d](#openbl_60d)|7701|7701|56|0.7%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|48|0.0%|0.0%|
[voipbl](#voipbl)|10398|10808|38|0.3%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2186|2186|37|1.6%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|22|3.2%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|15|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|877|877|11|1.2%|0.0%|
[et_compromised](#et_compromised)|2171|2171|10|0.4%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2052|2052|10|0.4%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|3124|3124|10|0.3%|0.0%|
[shunlist](#shunlist)|1272|1272|4|0.3%|0.0%|
[openbl_30d](#openbl_30d)|3255|3255|4|0.1%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|4|0.3%|0.0%|
[dshield](#dshield)|20|5120|4|0.0%|0.0%|
[zeus_badips](#zeus_badips)|235|235|3|1.2%|0.0%|
[zeus](#zeus)|268|268|3|1.1%|0.0%|
[openbl_7d](#openbl_7d)|943|943|3|0.3%|0.0%|
[sorbs_socks](#sorbs_socks)|23|23|2|8.6%|0.0%|
[sorbs_misc](#sorbs_misc)|23|23|2|8.6%|0.0%|
[sorbs_http](#sorbs_http)|23|23|2|8.6%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.0%|
[fullbogons](#fullbogons)|3733|670419608|2|0.0%|0.0%|
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
[stopforumspam_1d](#stopforumspam_1d)|7074|7074|5368|75.8%|17.6%|
[blocklist_de](#blocklist_de)|38212|38212|2180|5.7%|7.1%|
[blocklist_de_bots](#blocklist_de_bots)|3113|3113|1979|63.5%|6.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|1930|0.0%|6.3%|
[ri_web_proxies](#ri_web_proxies)|6153|6153|1660|26.9%|5.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|908|0.0%|2.9%|
[xroxy](#xroxy)|2059|2059|906|44.0%|2.9%|
[proxyrss](#proxyrss)|1604|1604|696|43.3%|2.2%|
[ri_connect_proxies](#ri_connect_proxies)|2310|2310|681|29.4%|2.2%|
[snort_ipfilter](#snort_ipfilter)|9369|9369|621|6.6%|2.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|571|0.0%|1.8%|
[et_tor](#et_tor)|6380|6380|499|7.8%|1.6%|
[bm_tor](#bm_tor)|6584|6584|489|7.4%|1.6%|
[dm_tor](#dm_tor)|6585|6585|488|7.4%|1.6%|
[proxz](#proxz)|702|702|352|50.1%|1.1%|
[spamhaus_drop](#spamhaus_drop)|654|18469632|336|0.0%|1.1%|
[et_block](#et_block)|1007|18338646|335|0.0%|1.1%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|194|52.1%|0.6%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|186|0.0%|0.6%|
[sorbs_spam](#sorbs_spam)|23029|23820|166|0.6%|0.5%|
[nixspam](#nixspam)|20978|20978|155|0.7%|0.5%|
[blocklist_de_mail](#blocklist_de_mail)|17398|17398|147|0.8%|0.4%|
[php_commenters](#php_commenters)|281|281|145|51.6%|0.4%|
[blocklist_de_apache](#blocklist_de_apache)|13522|13522|126|0.9%|0.4%|
[blocklist_de_strongips](#blocklist_de_strongips)|178|178|122|68.5%|0.4%|
[alienvault_reputation](#alienvault_reputation)|178477|178477|106|0.0%|0.3%|
[php_spammers](#php_spammers)|417|417|57|13.6%|0.1%|
[php_dictionary](#php_dictionary)|433|433|57|13.1%|0.1%|
[php_harvesters](#php_harvesters)|257|257|50|19.4%|0.1%|
[sorbs_web](#sorbs_web)|656|657|45|6.8%|0.1%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2186|2186|27|1.2%|0.0%|
[openbl_60d](#openbl_60d)|7701|7701|25|0.3%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|23|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|486400|21|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|14281|14281|14|0.0%|0.0%|
[voipbl](#voipbl)|10398|10808|13|0.1%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|12|1.7%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|6|0.0%|0.0%|
[et_compromised](#et_compromised)|2171|2171|6|0.2%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2052|2052|6|0.2%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|877|877|6|0.6%|0.0%|
[shunlist](#shunlist)|1272|1272|3|0.2%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|3|0.2%|0.0%|
[sorbs_socks](#sorbs_socks)|23|23|2|8.6%|0.0%|
[sorbs_misc](#sorbs_misc)|23|23|2|8.6%|0.0%|
[sorbs_http](#sorbs_http)|23|23|2|8.6%|0.0%|
[dshield](#dshield)|20|5120|2|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|3124|3124|2|0.0%|0.0%|
[zeus_badips](#zeus_badips)|235|235|1|0.4%|0.0%|
[zeus](#zeus)|268|268|1|0.3%|0.0%|
[openbl_30d](#openbl_30d)|3255|3255|1|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|
[ciarmy](#ciarmy)|343|343|1|0.2%|0.0%|

## virbl

[VirBL](http://virbl.bit.nl/) is a project of which the idea was born during the RIPE-48 meeting. The plan was to get reports of virusscanning mailservers, and put the IP-addresses that were reported to send viruses on a blacklist.

Source is downloaded from [this link](http://virbl.bit.nl/download/virbl.dnsbl.bit.nl.txt).

The last time downloaded was found to be dated: Thu Jun  4 12:52:04 UTC 2015.

The ipset `virbl` has **12** entries, **12** unique IPs.

The following table shows the overlaps of `virbl` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `virbl`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `virbl`.
- ` this % ` is the percentage **of this ipset (`virbl`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[alienvault_reputation](#alienvault_reputation)|178477|178477|2|0.0%|16.6%|

## voipbl

[VoIPBL.org](http://www.voipbl.org/) a distributed VoIP blacklist that is aimed to protects against VoIP Fraud and minimizing abuse for network that have publicly accessible PBX's. Several algorithms, external sources and manual confirmation are used before they categorize something as an attack and determine the threat level.

Source is downloaded from [this link](http://www.voipbl.org/update/).

The last time downloaded was found to be dated: Thu Jun  4 11:27:20 UTC 2015.

The ipset `voipbl` has **10398** entries, **10808** unique IPs.

The following table shows the overlaps of `voipbl` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `voipbl`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `voipbl`.
- ` this % ` is the percentage **of this ipset (`voipbl`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|1594|0.0%|14.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|432|0.0%|3.9%|
[fullbogons](#fullbogons)|3733|670419608|319|0.0%|2.9%|
[bogons](#bogons)|13|592708608|319|0.0%|2.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|298|0.0%|2.7%|
[alienvault_reputation](#alienvault_reputation)|178477|178477|200|0.1%|1.8%|
[blocklist_de](#blocklist_de)|38212|38212|42|0.1%|0.3%|
[stopforumspam_30d](#stopforumspam_30d)|92996|92996|38|0.0%|0.3%|
[blocklist_de_sip](#blocklist_de_sip)|105|105|35|33.3%|0.3%|
[spamhaus_drop](#spamhaus_drop)|654|18469632|14|0.0%|0.1%|
[et_block](#et_block)|1007|18338646|14|0.0%|0.1%|
[stopforumspam_7d](#stopforumspam_7d)|30334|30334|13|0.0%|0.1%|
[shunlist](#shunlist)|1272|1272|11|0.8%|0.1%|
[openbl_60d](#openbl_60d)|7701|7701|8|0.1%|0.0%|
[ciarmy](#ciarmy)|343|343|6|1.7%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7074|7074|5|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|4|0.0%|0.0%|
[openbl_30d](#openbl_30d)|3255|3255|3|0.0%|0.0%|
[dshield](#dshield)|20|5120|3|0.0%|0.0%|
[dm_tor](#dm_tor)|6585|6585|3|0.0%|0.0%|
[bm_tor](#bm_tor)|6584|6584|3|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|14281|14281|3|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|2|0.0%|0.0%|
[et_tor](#et_tor)|6380|6380|2|0.0%|0.0%|
[et_compromised](#et_compromised)|2171|2171|2|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2052|2052|2|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13522|13522|2|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9369|9369|1|0.0%|0.0%|
[openbl_7d](#openbl_7d)|943|943|1|0.1%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|17398|17398|1|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|3124|3124|1|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2186|2186|1|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3113|3113|1|0.0%|0.0%|

## xroxy

[xroxy.com](http://www.xroxy.com) open proxies (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.xroxy.com/proxyrss.xml).

The last time downloaded was found to be dated: Thu Jun  4 12:33:01 UTC 2015.

The ipset `xroxy` has **2059** entries, **2059** unique IPs.

The following table shows the overlaps of `xroxy` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `xroxy`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `xroxy`.
- ` this % ` is the percentage **of this ipset (`xroxy`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_30d](#stopforumspam_30d)|92996|92996|1210|1.3%|58.7%|
[stopforumspam_7d](#stopforumspam_7d)|30334|30334|906|2.9%|44.0%|
[ri_web_proxies](#ri_web_proxies)|6153|6153|871|14.1%|42.3%|
[proxyrss](#proxyrss)|1604|1604|454|28.3%|22.0%|
[ri_connect_proxies](#ri_connect_proxies)|2310|2310|348|15.0%|16.9%|
[proxz](#proxz)|702|702|295|42.0%|14.3%|
[stopforumspam_1d](#stopforumspam_1d)|7074|7074|288|4.0%|13.9%|
[blocklist_de](#blocklist_de)|38212|38212|257|0.6%|12.4%|
[blocklist_de_bots](#blocklist_de_bots)|3113|3113|205|6.5%|9.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|99|0.0%|4.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|90|0.0%|4.3%|
[sorbs_spam](#sorbs_spam)|23029|23820|76|0.3%|3.6%|
[nixspam](#nixspam)|20978|20978|69|0.3%|3.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|57|0.0%|2.7%|
[blocklist_de_mail](#blocklist_de_mail)|17398|17398|51|0.2%|2.4%|
[snort_ipfilter](#snort_ipfilter)|9369|9369|49|0.5%|2.3%|
[sorbs_web](#sorbs_web)|656|657|26|3.9%|1.2%|
[php_dictionary](#php_dictionary)|433|433|24|5.5%|1.1%|
[php_spammers](#php_spammers)|417|417|20|4.7%|0.9%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|13|1.9%|0.6%|
[blocklist_de_strongips](#blocklist_de_strongips)|178|178|7|3.9%|0.3%|
[alienvault_reputation](#alienvault_reputation)|178477|178477|5|0.0%|0.2%|
[php_commenters](#php_commenters)|281|281|3|1.0%|0.1%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|3|0.0%|0.1%|
[php_harvesters](#php_harvesters)|257|257|2|0.7%|0.0%|
[et_tor](#et_tor)|6380|6380|2|0.0%|0.0%|
[dm_tor](#dm_tor)|6585|6585|2|0.0%|0.0%|
[bm_tor](#bm_tor)|6584|6584|2|0.0%|0.0%|
[sorbs_socks](#sorbs_socks)|23|23|1|4.3%|0.0%|
[sorbs_misc](#sorbs_misc)|23|23|1|4.3%|0.0%|
[sorbs_http](#sorbs_http)|23|23|1|4.3%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.0%|
[et_compromised](#et_compromised)|2171|2171|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2052|2052|1|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|14281|14281|1|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2186|2186|1|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13522|13522|1|0.0%|0.0%|

## zeus

[Abuse.ch Zeus tracker](https://zeustracker.abuse.ch) standard, contains the same data as the ZeuS IP blocklist (zeus_badips) but with the slight difference that it doesn't exclude hijacked websites (level 2) and free web hosting providers (level 3). This means that this blocklist contains all IPv4 addresses associated with ZeuS C&Cs which are currently being tracked by ZeuS Tracker. Hence this blocklist will likely cause some false positives. - **excellent list**

Source is downloaded from [this link](https://zeustracker.abuse.ch/blocklist.php?download=ipblocklist).

The last time downloaded was found to be dated: Thu Jun  4 13:07:46 UTC 2015.

The ipset `zeus` has **268** entries, **268** unique IPs.

The following table shows the overlaps of `zeus` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `zeus`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `zeus`.
- ` this % ` is the percentage **of this ipset (`zeus`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[et_block](#et_block)|1007|18338646|258|0.0%|96.2%|
[zeus_badips](#zeus_badips)|235|235|235|100.0%|87.6%|
[snort_ipfilter](#snort_ipfilter)|9369|9369|227|2.4%|84.7%|
[alienvault_reputation](#alienvault_reputation)|178477|178477|65|0.0%|24.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|20|0.0%|7.4%|
[spamhaus_drop](#spamhaus_drop)|654|18469632|16|0.0%|5.9%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|10|0.0%|3.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|9|0.0%|3.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|6|0.0%|2.2%|
[spamhaus_edrop](#spamhaus_edrop)|55|486400|5|0.0%|1.8%|
[stopforumspam_30d](#stopforumspam_30d)|92996|92996|3|0.0%|1.1%|
[openbl_60d](#openbl_60d)|7701|7701|2|0.0%|0.7%|
[openbl_30d](#openbl_30d)|3255|3255|2|0.0%|0.7%|
[stopforumspam_7d](#stopforumspam_7d)|30334|30334|1|0.0%|0.3%|
[stopforumspam_1d](#stopforumspam_1d)|7074|7074|1|0.0%|0.3%|
[php_commenters](#php_commenters)|281|281|1|0.3%|0.3%|
[nixspam](#nixspam)|20978|20978|1|0.0%|0.3%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.3%|

## zeus_badips

[Abuse.ch Zeus tracker](https://zeustracker.abuse.ch) badips includes IPv4 addresses that are used by the ZeuS trojan. It is the recommened blocklist if you want to block only ZeuS IPs. It excludes IP addresses that ZeuS Tracker believes to be hijacked (level 2) or belong to a free web hosting provider (level 3). Hence the false postive rate should be much lower compared to the standard ZeuS IP blocklist. **excellent list**

Source is downloaded from [this link](https://zeustracker.abuse.ch/blocklist.php?download=badips).

The last time downloaded was found to be dated: Thu Jun  4 13:09:19 UTC 2015.

The ipset `zeus_badips` has **235** entries, **235** unique IPs.

The following table shows the overlaps of `zeus_badips` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `zeus_badips`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `zeus_badips`.
- ` this % ` is the percentage **of this ipset (`zeus_badips`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[zeus](#zeus)|268|268|235|87.6%|100.0%|
[et_block](#et_block)|1007|18338646|231|0.0%|98.2%|
[snort_ipfilter](#snort_ipfilter)|9369|9369|205|2.1%|87.2%|
[alienvault_reputation](#alienvault_reputation)|178477|178477|39|0.0%|16.5%|
[spamhaus_drop](#spamhaus_drop)|654|18469632|16|0.0%|6.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|14|0.0%|5.9%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|10|0.0%|4.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|8|0.0%|3.4%|
[spamhaus_edrop](#spamhaus_edrop)|55|486400|5|0.0%|2.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|4|0.0%|1.7%|
[stopforumspam_30d](#stopforumspam_30d)|92996|92996|3|0.0%|1.2%|
[stopforumspam_7d](#stopforumspam_7d)|30334|30334|1|0.0%|0.4%|
[stopforumspam_1d](#stopforumspam_1d)|7074|7074|1|0.0%|0.4%|
[php_commenters](#php_commenters)|281|281|1|0.3%|0.4%|
[openbl_60d](#openbl_60d)|7701|7701|1|0.0%|0.4%|
[openbl_30d](#openbl_30d)|3255|3255|1|0.0%|0.4%|
[nixspam](#nixspam)|20978|20978|1|0.0%|0.4%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.4%|
