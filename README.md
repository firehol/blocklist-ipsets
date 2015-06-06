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

The following list was automatically generated on Sat Jun  6 09:11:41 UTC 2015.

The update frequency is the maximum allowed by internal configuration. A list will never be downloaded sooner than the update frequency stated. A list may also not be downloaded, after this frequency expired, if it has not been modified on the server (as reported by HTTP `IF_MODIFIED_SINCE` method).

name|info|type|entries|update|
:--:|:--:|:--:|:-----:|:----:|
[alienvault_reputation](#alienvault_reputation)|[AlienVault.com](https://www.alienvault.com/) IP reputation database (this list seems to include port scanning hosts and to be updated regularly, but we found no information about its retention policy)|ipv4 hash:ip|178368 unique IPs|updated every 6 hours  from [this link](https://reputation.alienvault.com/reputation.generic)
[blocklist_de](#blocklist_de)|[Blocklist.de](https://www.blocklist.de/) IPs that have been detected by fail2ban in the last 48 hours - **excellent list**|ipv4 hash:ip|25717 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/all.txt)
[blocklist_de_apache](#blocklist_de_apache)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service Apache, Apache-DDOS, RFI-Attacks.|ipv4 hash:ip|14812 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/apache.txt)
[blocklist_de_bots](#blocklist_de_bots)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the RFI-Attacks, REG-Bots, IRC-Bots or BadBots (BadBots = he has posted a Spam-Comment on a open Forum or Wiki).|ipv4 hash:ip|3120 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/bots.txt)
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|[Blocklist.de](https://www.blocklist.de/) All IPs which attacks Joomlas, Wordpress and other Web-Logins with Brute-Force Logins.|ipv4 hash:ip|3461 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/bruteforcelogin.txt)
[blocklist_de_ftp](#blocklist_de_ftp)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours for attacks on the Service FTP.|ipv4 hash:ip|901 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/ftp.txt)
[blocklist_de_imap](#blocklist_de_imap)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours for attacks on the Service imap, sasl, pop3, etc.|ipv4 hash:ip|1810 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/imap.txt)
[blocklist_de_mail](#blocklist_de_mail)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service Mail, Postfix.|ipv4 hash:ip|15653 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/mail.txt)
[blocklist_de_sip](#blocklist_de_sip)|[Blocklist.de](https://www.blocklist.de/) All IP addresses that tried to login in a SIP, VOIP or Asterisk Server and are included in the IPs list from [infiltrated.net](www.infiltrated.net)|ipv4 hash:ip|90 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/sip.txt)
[blocklist_de_ssh](#blocklist_de_ssh)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service SSH.|ipv4 hash:ip|2229 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/ssh.txt)
[blocklist_de_strongips](#blocklist_de_strongips)|[Blocklist.de](https://www.blocklist.de/) All IPs which are older then 2 month and have more then 5.000 attacks.|ipv4 hash:ip|183 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/strongips.txt)
[bm_tor](#bm_tor)|[torstatus.blutmagie.de](https://torstatus.blutmagie.de) list of all TOR network servers|ipv4 hash:ip|6461 unique IPs|updated every 30 mins  from [this link](https://torstatus.blutmagie.de/ip_list_all.php/Tor_ip_list_ALL.csv)
[bogons](#bogons)|[Team-Cymru.org](http://www.team-cymru.org) private and reserved addresses defined by RFC 1918, RFC 5735, and RFC 6598 and netblocks that have not been allocated to a regional internet registry - **excellent list - use it only your internet interface**|ipv4 hash:net|13 subnets, 592708608 unique IPs|updated every 1 day  from [this link](http://www.team-cymru.org/Services/Bogons/bogon-bn-agg.txt)
[bruteforceblocker](#bruteforceblocker)|[danger.rulez.sk](http://danger.rulez.sk/) IPs detected by [bruteforceblocker](http://danger.rulez.sk/index.php/bruteforceblocker/) (fail2ban alternative for SSH on OpenBSD). This is an automatically generated list from users reporting failed authentication attempts. An IP seems to be included if 3 or more users report it. Its retention pocily seems 30 days.|ipv4 hash:ip|1892 unique IPs|updated every 3 hours  from [this link](http://danger.rulez.sk/projects/bruteforceblocker/blist.php)
[ciarmy](#ciarmy)|[CIArmy.com](http://ciarmy.com/) IPs with poor Rogue Packet score that have not yet been identified as malicious by the community|ipv4 hash:ip|395 unique IPs|updated every 3 hours  from [this link](http://cinsscore.com/list/ci-badguys.txt)
[cleanmx_viruses](#cleanmx_viruses)|[Clean-MX.de](http://support.clean-mx.de/clean-mx/viruses.php) IPs with viruses|ipv4 hash:ip|168 unique IPs|updated every 12 hours  from [this link](http://support.clean-mx.de/clean-mx/xmlviruses.php?sort=id%20desc&response=alive)
[dm_tor](#dm_tor)|[dan.me.uk](https://www.dan.me.uk) dynamic list of TOR exit points|ipv4 hash:ip|6475 unique IPs|updated every 30 mins  from [this link](https://www.dan.me.uk/torlist/)
[dshield](#dshield)|[DShield.org](https://dshield.org/) top 20 attacking class C (/24) subnets over the last three days - **excellent list**|ipv4 hash:net|19 subnets, 5120 unique IPs|updated every 4 hours  from [this link](http://feeds.dshield.org/block.txt)
[et_block](#et_block)|[EmergingThreats.net](http://www.emergingthreats.net/) default blacklist (at the time of writing includes spamhaus DROP, dshield and abuse.ch trackers, which are available separately too - prefer to use the direct ipsets instead of this, they seem to lag a bit in updates)|ipv4 hash:net|1023 subnets, 18338662 unique IPs|updated every 12 hours  from [this link](http://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt)
[et_botcc](#et_botcc)|[EmergingThreats.net Command and Control IPs](http://doc.emergingthreats.net/bin/view/Main/BotCC) These IPs are updates every 24 hours and should be considered VERY highly reliable indications that a host is communicating with a known and active Bot or Malware command and control server - (although they say this includes abuse.ch trackers, it does not - most probably it is the shadowserver.org C&C list)|ipv4 hash:ip|509 unique IPs|updated every 12 hours  from [this link](http://rules.emergingthreats.net/fwrules/emerging-PIX-CC.rules)
[et_compromised](#et_compromised)|[EmergingThreats.net compromised hosts](http://doc.emergingthreats.net/bin/view/Main/CompromisedHost) - (this seems to be based on bruteforceblocker)|ipv4 hash:ip|2016 unique IPs|updated every 12 hours  from [this link](http://rules.emergingthreats.net/blockrules/compromised-ips.txt)
et_dshield|[EmergingThreats.net](http://www.emergingthreats.net/) dshield blocklist|ipv4 hash:net|disabled|updated every 12 hours  from [this link](http://rules.emergingthreats.net/fwrules/emerging-PIX-DSHIELD.rules)
et_spamhaus|[EmergingThreats.net](http://www.emergingthreats.net/) spamhaus blocklist|ipv4 hash:net|disabled|updated every 12 hours  from [this link](http://rules.emergingthreats.net/fwrules/emerging-PIX-DROP.rules)
[et_tor](#et_tor)|[EmergingThreats.net](http://www.emergingthreats.net/) [list](http://doc.emergingthreats.net/bin/view/Main/TorRules) of TOR network IPs|ipv4 hash:ip|6470 unique IPs|updated every 12 hours  from [this link](http://rules.emergingthreats.net/blockrules/emerging-tor.rules)
[feodo](#feodo)|[Abuse.ch Feodo tracker](https://feodotracker.abuse.ch) trojan includes IPs which are being used by Feodo (also known as Cridex or Bugat) which commits ebanking fraud - **excellent list**|ipv4 hash:ip|99 unique IPs|updated every 30 mins  from [this link](https://feodotracker.abuse.ch/blocklist/?download=ipblocklist)
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
[malc0de](#malc0de)|[Malc0de.com](http://malc0de.com) malicious IPs of the last 30 days|ipv4 hash:ip|371 unique IPs|updated every 1 day  from [this link](http://malc0de.com/bl/IP_Blacklist.txt)
[malwaredomainlist](#malwaredomainlist)|[malwaredomainlist.com](http://www.malwaredomainlist.com) list of malware active ip addresses|ipv4 hash:ip|1288 unique IPs|updated every 12 hours  from [this link](http://www.malwaredomainlist.com/hostslist/ip.txt)
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|[MaxMind.com](https://www.maxmind.com/en/anonymous-proxy-fraudulent-ip-address-list) list of anonymous proxy fraudelent IP addresses.|ipv4 hash:ip|372 unique IPs|updated every 4 hours  from [this link](https://www.maxmind.com/en/anonymous-proxy-fraudulent-ip-address-list)
[nixspam](#nixspam)|[NiX Spam](http://www.heise.de/ix/NiX-Spam-DNSBL-and-blacklist-for-download-499637.html) IP addresses that sent spam in the last hour - automatically generated entries without distinguishing open proxies from relays, dialup gateways, and so on. All IPs are removed after 12 hours if there is no spam from there.|ipv4 hash:ip|16272 unique IPs|updated every 15 mins  from [this link](http://www.dnsbl.manitu.net/download/nixspam-ip.dump.gz)
openbl|[OpenBL.org](http://www.openbl.org/) default blacklist (currently it is the same with 90 days). OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications - **excellent list**|ipv4 hash:ip|disabled|updated every 4 hours  from [this link](http://www.openbl.org/lists/base.txt)
openbl_180d|[OpenBL.org](http://www.openbl.org/) last 180 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|disabled|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_180days.txt)
[openbl_1d](#openbl_1d)|[OpenBL.org](http://www.openbl.org/) last 24 hours IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|146 unique IPs|updated every 1 hour  from [this link](http://www.openbl.org/lists/base_1days.txt)
[openbl_30d](#openbl_30d)|[OpenBL.org](http://www.openbl.org/) last 30 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|3251 unique IPs|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_30days.txt)
openbl_360d|[OpenBL.org](http://www.openbl.org/) last 360 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|disabled|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_360days.txt)
[openbl_60d](#openbl_60d)|[OpenBL.org](http://www.openbl.org/) last 60 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|7651 unique IPs|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_60days.txt)
[openbl_7d](#openbl_7d)|[OpenBL.org](http://www.openbl.org/) last 7 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|861 unique IPs|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_7days.txt)
openbl_90d|[OpenBL.org](http://www.openbl.org/) last 90 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|disabled|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_90days.txt)
openbl_all|[OpenBL.org](http://www.openbl.org/) last all IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|disabled|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_all.txt)
[palevo](#palevo)|[Abuse.ch Palevo tracker](https://palevotracker.abuse.ch) worm includes IPs which are being used as botnet C&C for the Palevo crimeware - **excellent list**|ipv4 hash:ip|13 unique IPs|updated every 30 mins  from [this link](https://palevotracker.abuse.ch/blocklists.php?download=ipblocklist)
php_bad|[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) bad web hosts (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|disabled|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=b&rss=1)
[php_commenters](#php_commenters)|[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) comment spammers (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|326 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=c&rss=1)
[php_dictionary](#php_dictionary)|[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) directory attackers (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|508 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=d&rss=1)
[php_harvesters](#php_harvesters)|[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) harvesters (IPs that surf the internet looking for email addresses) (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|311 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=h&rss=1)
[php_spammers](#php_spammers)|[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) spam servers (IPs used by spammers to send messages) (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|495 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=s&rss=1)
[proxyrss](#proxyrss)|[proxyrss.com](http://www.proxyrss.com) open proxies syndicated from multiple sources.|ipv4 hash:ip|1688 unique IPs|updated every 4 hours  from [this link](http://www.proxyrss.com/proxylists/all.gz)
[proxz](#proxz)|[proxz.com](http://www.proxz.com) open proxies (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|862 unique IPs|updated every 1 hour  from [this link](http://www.proxz.com/proxylists.xml)
[ri_connect_proxies](#ri_connect_proxies)|[rosinstrument.com](http://www.rosinstrument.com) open CONNECT proxies (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|2447 unique IPs|updated every 1 hour  from [this link](http://tools.rosinstrument.com/proxy/plab100.xml)
[ri_web_proxies](#ri_web_proxies)|[rosinstrument.com](http://www.rosinstrument.com) open HTTP proxies (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|6565 unique IPs|updated every 1 hour  from [this link](http://tools.rosinstrument.com/proxy/l100.xml)
[shunlist](#shunlist)|[AutoShun.org](http://autoshun.org/) IPs identified as hostile by correlating logs from distributed snort installations running the autoshun plugin|ipv4 hash:ip|1248 unique IPs|updated every 4 hours  from [this link](http://www.autoshun.org/files/shunlist.csv)
[snort_ipfilter](#snort_ipfilter)|[labs.snort.org](https://labs.snort.org/) supplied IP blacklist (this list seems to be updated frequently, but we found no information about it)|ipv4 hash:ip|8977 unique IPs|updated every 12 hours  from [this link](http://labs.snort.org/feeds/ip-filter.blf)
[sorbs_dul](#sorbs_dul)|[Sorbs.net](https://www.sorbs.net/) DUL, Dynamic User IPs extracted from deltas.|ipv4 hash:net|8 subnets, 3584 unique IPs|updated every 1 min  from [this link]()
[sorbs_http](#sorbs_http)|[Sorbs.net](https://www.sorbs.net/) HTTP proxies, extracted from deltas.|ipv4 hash:net|19 subnets, 19 unique IPs|updated every 1 min  from [this link]()
[sorbs_misc](#sorbs_misc)|[Sorbs.net](https://www.sorbs.net/) MISC proxies, extracted from deltas.|ipv4 hash:net|19 subnets, 19 unique IPs|updated every 1 min  from [this link]()
[sorbs_new_spam](#sorbs_new_spam)|[Sorbs.net](https://www.sorbs.net/) NEW Spam senders, extracted from deltas.|ipv4 hash:net|29446 subnets, 30474 unique IPs|updated every 1 min  from [this link]()
[sorbs_recent_spam](#sorbs_recent_spam)|[Sorbs.net](https://www.sorbs.net/) RECENT Spam senders, extracted from deltas.|ipv4 hash:net|29446 subnets, 30474 unique IPs|updated every 1 min  from [this link]()
[sorbs_smtp](#sorbs_smtp)|[Sorbs.net](https://www.sorbs.net/) SMTP Open Relays, extracted from deltas.|ipv4 hash:net|13 subnets, 13 unique IPs|updated every 1 min  from [this link]()
[sorbs_socks](#sorbs_socks)|[Sorbs.net](https://www.sorbs.net/) SOCKS proxies, extracted from deltas.|ipv4 hash:net|19 subnets, 19 unique IPs|updated every 1 min  from [this link]()
[sorbs_spam](#sorbs_spam)|[Sorbs.net](https://www.sorbs.net/) Spam senders, extracted from deltas.|ipv4 hash:net|29446 subnets, 30474 unique IPs|updated every 1 min  from [this link]()
[sorbs_web](#sorbs_web)|[Sorbs.net](https://www.sorbs.net/) WEB exploits, extracted from deltas.|ipv4 hash:net|645 subnets, 646 unique IPs|updated every 1 min  from [this link]()
[spamhaus_drop](#spamhaus_drop)|[Spamhaus.org](http://www.spamhaus.org) DROP list (according to their site this list should be dropped at tier-1 ISPs globaly) - **excellent list**|ipv4 hash:net|653 subnets, 18404096 unique IPs|updated every 12 hours  from [this link](http://www.spamhaus.org/drop/drop.txt)
[spamhaus_edrop](#spamhaus_edrop)|[Spamhaus.org](http://www.spamhaus.org) EDROP (extended matches that should be used with DROP) - **excellent list**|ipv4 hash:net|56 subnets, 487424 unique IPs|updated every 12 hours  from [this link](http://www.spamhaus.org/drop/edrop.txt)
[sslbl](#sslbl)|[Abuse.ch SSL Blacklist](https://sslbl.abuse.ch/) bad SSL traffic related to malware or botnet activities - **excellent list**|ipv4 hash:ip|369 unique IPs|updated every 30 mins  from [this link](https://sslbl.abuse.ch/blacklist/sslipblacklist.csv)
stopforumspam_180d|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 180 days)|ipv4 hash:ip|disabled|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/listed_ip_180.zip)
[stopforumspam_1d](#stopforumspam_1d)|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers in the last 24 hours - **excellent list**|ipv4 hash:ip|7042 unique IPs|updated every 1 hour  from [this link](http://www.stopforumspam.com/downloads/listed_ip_1.zip)
[stopforumspam_30d](#stopforumspam_30d)|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 30 days)|ipv4 hash:ip|93258 unique IPs|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/listed_ip_30.zip)
stopforumspam_365d|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 365 days)|ipv4 hash:ip|disabled|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/listed_ip_365.zip)
[stopforumspam_7d](#stopforumspam_7d)|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 7 days)|ipv4 hash:ip|30121 unique IPs|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/listed_ip_7.zip)
stopforumspam_90d|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 90 days)|ipv4 hash:ip|disabled|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/listed_ip_90.zip)
stopforumspam_ever|[StopForumSpam.com](http://www.stopforumspam.com) all IPs used by forum spammers, **ever** (normally you don't want to use this ipset, use the hourly one which includes last 24 hours IPs or the 7 days one)|ipv4 hash:ip|disabled|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/bannedips.zip)
[virbl](#virbl)|[VirBL](http://virbl.bit.nl/) is a project of which the idea was born during the RIPE-48 meeting. The plan was to get reports of virusscanning mailservers, and put the IP-addresses that were reported to send viruses on a blacklist.|ipv4 hash:ip|8 unique IPs|updated every 1 hour  from [this link](http://virbl.bit.nl/download/virbl.dnsbl.bit.nl.txt)
[voipbl](#voipbl)|[VoIPBL.org](http://www.voipbl.org/) a distributed VoIP blacklist that is aimed to protects against VoIP Fraud and minimizing abuse for network that have publicly accessible PBX's. Several algorithms, external sources and manual confirmation are used before they categorize something as an attack and determine the threat level.|ipv4 hash:net|10452 subnets, 10864 unique IPs|updated every 4 hours  from [this link](http://www.voipbl.org/update/)
[xroxy](#xroxy)|[xroxy.com](http://www.xroxy.com) open proxies (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|2094 unique IPs|updated every 1 hour  from [this link](http://www.xroxy.com/proxyrss.xml)
[zeus](#zeus)|[Abuse.ch Zeus tracker](https://zeustracker.abuse.ch) standard, contains the same data as the ZeuS IP blocklist (zeus_badips) but with the slight difference that it doesn't exclude hijacked websites (level 2) and free web hosting providers (level 3). This means that this blocklist contains all IPv4 addresses associated with ZeuS C&Cs which are currently being tracked by ZeuS Tracker. Hence this blocklist will likely cause some false positives. - **excellent list**|ipv4 hash:ip|230 unique IPs|updated every 30 mins  from [this link](https://zeustracker.abuse.ch/blocklist.php?download=ipblocklist)
[zeus_badips](#zeus_badips)|[Abuse.ch Zeus tracker](https://zeustracker.abuse.ch) badips includes IPv4 addresses that are used by the ZeuS trojan. It is the recommened blocklist if you want to block only ZeuS IPs. It excludes IP addresses that ZeuS Tracker believes to be hijacked (level 2) or belong to a free web hosting provider (level 3). Hence the false postive rate should be much lower compared to the standard ZeuS IP blocklist. **excellent list**|ipv4 hash:ip|202 unique IPs|updated every 30 mins  from [this link](https://zeustracker.abuse.ch/blocklist.php?download=badips)

# Comparison of ipsets

Below we compare each ipset against all other.


## alienvault_reputation

[AlienVault.com](https://www.alienvault.com/) IP reputation database (this list seems to include port scanning hosts and to be updated regularly, but we found no information about its retention policy)

Source is downloaded from [this link](https://reputation.alienvault.com/reputation.generic).

The last time downloaded was found to be dated: Sat Jun  6 04:00:24 UTC 2015.

The ipset `alienvault_reputation` has **178368** entries, **178368** unique IPs.

The following table shows the overlaps of `alienvault_reputation` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `alienvault_reputation`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `alienvault_reputation`.
- ` this % ` is the percentage **of this ipset (`alienvault_reputation`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|13893|0.0%|7.7%|
[openbl_60d](#openbl_60d)|7651|7651|7627|99.6%|4.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|7532|0.0%|4.2%|
[et_block](#et_block)|1023|18338662|5280|0.0%|2.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|4729|0.0%|2.6%|
[dshield](#dshield)|19|5120|4354|85.0%|2.4%|
[openbl_30d](#openbl_30d)|3251|3251|3232|99.4%|1.8%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|1631|0.0%|0.9%|
[et_compromised](#et_compromised)|2016|2016|1311|65.0%|0.7%|
[shunlist](#shunlist)|1248|1248|1241|99.4%|0.6%|
[bruteforceblocker](#bruteforceblocker)|1892|1892|1225|64.7%|0.6%|
[blocklist_de](#blocklist_de)|25717|25717|1140|4.4%|0.6%|
[blocklist_de_ssh](#blocklist_de_ssh)|2229|2229|904|40.5%|0.5%|
[openbl_7d](#openbl_7d)|861|861|852|98.9%|0.4%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|518|0.0%|0.2%|
[ciarmy](#ciarmy)|395|395|369|93.4%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|287|0.0%|0.1%|
[voipbl](#voipbl)|10452|10864|209|1.9%|0.1%|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|203|0.2%|0.1%|
[openbl_1d](#openbl_1d)|146|146|138|94.5%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14812|14812|133|0.8%|0.0%|
[snort_ipfilter](#snort_ipfilter)|8977|8977|119|1.3%|0.0%|
[sorbs_spam](#sorbs_spam)|29446|30474|105|0.3%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|29446|30474|105|0.3%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|29446|30474|105|0.3%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|94|0.3%|0.0%|
[sslbl](#sslbl)|369|369|65|17.6%|0.0%|
[zeus](#zeus)|230|230|62|26.9%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|15653|15653|62|0.3%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7042|7042|53|0.7%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|1810|1810|46|2.5%|0.0%|
[dm_tor](#dm_tor)|6475|6475|43|0.6%|0.0%|
[bm_tor](#bm_tor)|6461|6461|43|0.6%|0.0%|
[et_tor](#et_tor)|6470|6470|42|0.6%|0.0%|
[zeus_badips](#zeus_badips)|202|202|38|18.8%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|183|183|36|19.6%|0.0%|
[nixspam](#nixspam)|16272|16272|30|0.1%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3120|3120|29|0.9%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|26|6.9%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|3461|3461|20|0.5%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|90|90|17|18.8%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|15|0.0%|0.0%|
[php_commenters](#php_commenters)|326|326|15|4.6%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|15|0.0%|0.0%|
[malc0de](#malc0de)|371|371|11|2.9%|0.0%|
[php_harvesters](#php_harvesters)|311|311|10|3.2%|0.0%|
[php_dictionary](#php_dictionary)|508|508|8|1.5%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|8|0.5%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|168|168|7|4.1%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|901|901|7|0.7%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|6|0.4%|0.0%|
[php_spammers](#php_spammers)|495|495|5|1.0%|0.0%|
[et_botcc](#et_botcc)|509|509|5|0.9%|0.0%|
[xroxy](#xroxy)|2094|2094|4|0.1%|0.0%|
[ri_web_proxies](#ri_web_proxies)|6565|6565|3|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2447|2447|3|0.1%|0.0%|
[proxz](#proxz)|862|862|3|0.3%|0.0%|
[feodo](#feodo)|99|99|2|2.0%|0.0%|
[sorbs_web](#sorbs_web)|645|646|1|0.1%|0.0%|
[proxyrss](#proxyrss)|1688|1688|1|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|1|0.1%|0.0%|

## blocklist_de

[Blocklist.de](https://www.blocklist.de/) IPs that have been detected by fail2ban in the last 48 hours - **excellent list**

Source is downloaded from [this link](http://lists.blocklist.de/lists/all.txt).

The last time downloaded was found to be dated: Sat Jun  6 08:42:03 UTC 2015.

The ipset `blocklist_de` has **25717** entries, **25717** unique IPs.

The following table shows the overlaps of `blocklist_de` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de`.
- ` this % ` is the percentage **of this ipset (`blocklist_de`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de_mail](#blocklist_de_mail)|15653|15653|15653|100.0%|60.8%|
[blocklist_de_apache](#blocklist_de_apache)|14812|14812|14811|99.9%|57.5%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|3461|3461|3461|100.0%|13.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|3264|0.0%|12.6%|
[blocklist_de_bots](#blocklist_de_bots)|3120|3120|3112|99.7%|12.1%|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|2458|2.6%|9.5%|
[blocklist_de_ssh](#blocklist_de_ssh)|2229|2229|2229|100.0%|8.6%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|2127|7.0%|8.2%|
[blocklist_de_imap](#blocklist_de_imap)|1810|1810|1810|100.0%|7.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|1513|0.0%|5.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|1435|0.0%|5.5%|
[stopforumspam_1d](#stopforumspam_1d)|7042|7042|1320|18.7%|5.1%|
[alienvault_reputation](#alienvault_reputation)|178368|178368|1140|0.6%|4.4%|
[sorbs_spam](#sorbs_spam)|29446|30474|1042|3.4%|4.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|29446|30474|1042|3.4%|4.0%|
[sorbs_new_spam](#sorbs_new_spam)|29446|30474|1042|3.4%|4.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|901|901|896|99.4%|3.4%|
[openbl_60d](#openbl_60d)|7651|7651|880|11.5%|3.4%|
[openbl_30d](#openbl_30d)|3251|3251|712|21.9%|2.7%|
[bruteforceblocker](#bruteforceblocker)|1892|1892|641|33.8%|2.4%|
[et_compromised](#et_compromised)|2016|2016|639|31.6%|2.4%|
[openbl_7d](#openbl_7d)|861|861|447|51.9%|1.7%|
[ri_web_proxies](#ri_web_proxies)|6565|6565|395|6.0%|1.5%|
[shunlist](#shunlist)|1248|1248|366|29.3%|1.4%|
[nixspam](#nixspam)|16272|16272|343|2.1%|1.3%|
[xroxy](#xroxy)|2094|2094|246|11.7%|0.9%|
[proxyrss](#proxyrss)|1688|1688|227|13.4%|0.8%|
[et_block](#et_block)|1023|18338662|197|0.0%|0.7%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|184|0.0%|0.7%|
[blocklist_de_strongips](#blocklist_de_strongips)|183|183|183|100.0%|0.7%|
[snort_ipfilter](#snort_ipfilter)|8977|8977|170|1.8%|0.6%|
[proxz](#proxz)|862|862|145|16.8%|0.5%|
[openbl_1d](#openbl_1d)|146|146|124|84.9%|0.4%|
[php_spammers](#php_spammers)|495|495|85|17.1%|0.3%|
[php_dictionary](#php_dictionary)|508|508|83|16.3%|0.3%|
[php_commenters](#php_commenters)|326|326|80|24.5%|0.3%|
[sorbs_web](#sorbs_web)|645|646|75|11.6%|0.2%|
[blocklist_de_sip](#blocklist_de_sip)|90|90|71|78.8%|0.2%|
[ri_connect_proxies](#ri_connect_proxies)|2447|2447|68|2.7%|0.2%|
[dshield](#dshield)|19|5120|58|1.1%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|55|0.0%|0.2%|
[voipbl](#voipbl)|10452|10864|35|0.3%|0.1%|
[ciarmy](#ciarmy)|395|395|35|8.8%|0.1%|
[php_harvesters](#php_harvesters)|311|311|30|9.6%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|11|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|11|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|7|0.0%|0.0%|
[sorbs_socks](#sorbs_socks)|19|19|5|26.3%|0.0%|
[sorbs_misc](#sorbs_misc)|19|19|5|26.3%|0.0%|
[sorbs_http](#sorbs_http)|19|19|5|26.3%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|4|0.5%|0.0%|
[et_tor](#et_tor)|6470|6470|4|0.0%|0.0%|
[dm_tor](#dm_tor)|6475|6475|4|0.0%|0.0%|
[bm_tor](#bm_tor)|6461|6461|4|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|3|0.8%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|3|0.2%|0.0%|
[sslbl](#sslbl)|369|369|1|0.2%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|168|168|1|0.5%|0.0%|

## blocklist_de_apache

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service Apache, Apache-DDOS, RFI-Attacks.

Source is downloaded from [this link](http://lists.blocklist.de/lists/apache.txt).

The last time downloaded was found to be dated: Sat Jun  6 08:56:13 UTC 2015.

The ipset `blocklist_de_apache` has **14812** entries, **14812** unique IPs.

The following table shows the overlaps of `blocklist_de_apache` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_apache`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_apache`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_apache`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|25717|25717|14811|57.5%|99.9%|
[blocklist_de_mail](#blocklist_de_mail)|15653|15653|11059|70.6%|74.6%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|3461|3461|3460|99.9%|23.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|2341|0.0%|15.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|1328|0.0%|8.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|1085|0.0%|7.3%|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|219|0.2%|1.4%|
[alienvault_reputation](#alienvault_reputation)|178368|178368|133|0.0%|0.8%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|132|0.4%|0.8%|
[sorbs_spam](#sorbs_spam)|29446|30474|98|0.3%|0.6%|
[sorbs_recent_spam](#sorbs_recent_spam)|29446|30474|98|0.3%|0.6%|
[sorbs_new_spam](#sorbs_new_spam)|29446|30474|98|0.3%|0.6%|
[stopforumspam_1d](#stopforumspam_1d)|7042|7042|65|0.9%|0.4%|
[shunlist](#shunlist)|1248|1248|34|2.7%|0.2%|
[blocklist_de_strongips](#blocklist_de_strongips)|183|183|32|17.4%|0.2%|
[ciarmy](#ciarmy)|395|395|31|7.8%|0.2%|
[php_commenters](#php_commenters)|326|326|25|7.6%|0.1%|
[blocklist_de_bots](#blocklist_de_bots)|3120|3120|23|0.7%|0.1%|
[nixspam](#nixspam)|16272|16272|20|0.1%|0.1%|
[et_block](#et_block)|1023|18338662|12|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|8977|8977|9|0.1%|0.0%|
[dshield](#dshield)|19|5120|9|0.1%|0.0%|
[openbl_60d](#openbl_60d)|7651|7651|7|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|5|0.0%|0.0%|
[php_spammers](#php_spammers)|495|495|5|1.0%|0.0%|
[php_harvesters](#php_harvesters)|311|311|5|1.6%|0.0%|
[openbl_30d](#openbl_30d)|3251|3251|5|0.1%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|5|0.0%|0.0%|
[php_dictionary](#php_dictionary)|508|508|4|0.7%|0.0%|
[et_tor](#et_tor)|6470|6470|4|0.0%|0.0%|
[dm_tor](#dm_tor)|6475|6475|4|0.0%|0.0%|
[bm_tor](#bm_tor)|6461|6461|4|0.0%|0.0%|
[voipbl](#voipbl)|10452|10864|3|0.0%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|0.0%|
[sorbs_web](#sorbs_web)|645|646|2|0.3%|0.0%|
[openbl_7d](#openbl_7d)|861|861|2|0.2%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|2|0.5%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|2|0.0%|0.0%|
[et_compromised](#et_compromised)|2016|2016|2|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1892|1892|2|0.1%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|1|0.0%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|168|168|1|0.5%|0.0%|

## blocklist_de_bots

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the RFI-Attacks, REG-Bots, IRC-Bots or BadBots (BadBots = he has posted a Spam-Comment on a open Forum or Wiki).

Source is downloaded from [this link](http://lists.blocklist.de/lists/bots.txt).

The last time downloaded was found to be dated: Sat Jun  6 08:56:18 UTC 2015.

The ipset `blocklist_de_bots` has **3120** entries, **3120** unique IPs.

The following table shows the overlaps of `blocklist_de_bots` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_bots`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_bots`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_bots`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|25717|25717|3112|12.1%|99.7%|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|2106|2.2%|67.5%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|1936|6.4%|62.0%|
[stopforumspam_1d](#stopforumspam_1d)|7042|7042|1260|17.8%|40.3%|
[ri_web_proxies](#ri_web_proxies)|6565|6565|336|5.1%|10.7%|
[proxyrss](#proxyrss)|1688|1688|227|13.4%|7.2%|
[xroxy](#xroxy)|2094|2094|196|9.3%|6.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|196|0.0%|6.2%|
[blocklist_de_strongips](#blocklist_de_strongips)|183|183|136|74.3%|4.3%|
[proxz](#proxz)|862|862|123|14.2%|3.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|114|0.0%|3.6%|
[ri_connect_proxies](#ri_connect_proxies)|2447|2447|65|2.6%|2.0%|
[php_commenters](#php_commenters)|326|326|65|19.9%|2.0%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|44|0.0%|1.4%|
[et_block](#et_block)|1023|18338662|44|0.0%|1.4%|
[sorbs_spam](#sorbs_spam)|29446|30474|40|0.1%|1.2%|
[sorbs_recent_spam](#sorbs_recent_spam)|29446|30474|40|0.1%|1.2%|
[sorbs_new_spam](#sorbs_new_spam)|29446|30474|40|0.1%|1.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|38|0.0%|1.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|37|0.0%|1.1%|
[alienvault_reputation](#alienvault_reputation)|178368|178368|29|0.0%|0.9%|
[nixspam](#nixspam)|16272|16272|25|0.1%|0.8%|
[php_harvesters](#php_harvesters)|311|311|23|7.3%|0.7%|
[blocklist_de_mail](#blocklist_de_mail)|15653|15653|23|0.1%|0.7%|
[blocklist_de_apache](#blocklist_de_apache)|14812|14812|23|0.1%|0.7%|
[snort_ipfilter](#snort_ipfilter)|8977|8977|21|0.2%|0.6%|
[php_spammers](#php_spammers)|495|495|20|4.0%|0.6%|
[php_dictionary](#php_dictionary)|508|508|15|2.9%|0.4%|
[sorbs_web](#sorbs_web)|645|646|11|1.7%|0.3%|
[openbl_60d](#openbl_60d)|7651|7651|10|0.1%|0.3%|
[voipbl](#voipbl)|10452|10864|5|0.0%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|5|0.0%|0.1%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|3|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|3|0.4%|0.0%|
[openbl_30d](#openbl_30d)|3251|3251|2|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.0%|
[et_compromised](#et_compromised)|2016|2016|2|0.0%|0.0%|
[dshield](#dshield)|19|5120|2|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1892|1892|2|0.1%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1|0.0%|0.0%|

## blocklist_de_bruteforce

[Blocklist.de](https://www.blocklist.de/) All IPs which attacks Joomlas, Wordpress and other Web-Logins with Brute-Force Logins.

Source is downloaded from [this link](http://lists.blocklist.de/lists/bruteforcelogin.txt).

The last time downloaded was found to be dated: Sat Jun  6 08:42:15 UTC 2015.

The ipset `blocklist_de_bruteforce` has **3461** entries, **3461** unique IPs.

The following table shows the overlaps of `blocklist_de_bruteforce` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_bruteforce`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_bruteforce`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_bruteforce`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|25717|25717|3461|13.4%|100.0%|
[blocklist_de_apache](#blocklist_de_apache)|14812|14812|3460|23.3%|99.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|243|0.0%|7.0%|
[sorbs_spam](#sorbs_spam)|29446|30474|98|0.3%|2.8%|
[sorbs_recent_spam](#sorbs_recent_spam)|29446|30474|98|0.3%|2.8%|
[sorbs_new_spam](#sorbs_new_spam)|29446|30474|98|0.3%|2.8%|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|53|0.0%|1.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|51|0.0%|1.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|36|0.0%|1.0%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|32|0.1%|0.9%|
[alienvault_reputation](#alienvault_reputation)|178368|178368|20|0.0%|0.5%|
[nixspam](#nixspam)|16272|16272|19|0.1%|0.5%|
[stopforumspam_1d](#stopforumspam_1d)|7042|7042|18|0.2%|0.5%|
[php_commenters](#php_commenters)|326|326|7|2.1%|0.2%|
[blocklist_de_strongips](#blocklist_de_strongips)|183|183|6|3.2%|0.1%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|5|0.0%|0.1%|
[snort_ipfilter](#snort_ipfilter)|8977|8977|5|0.0%|0.1%|
[php_spammers](#php_spammers)|495|495|5|1.0%|0.1%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|5|0.0%|0.1%|
[php_dictionary](#php_dictionary)|508|508|4|0.7%|0.1%|
[et_block](#et_block)|1023|18338662|4|0.0%|0.1%|
[php_harvesters](#php_harvesters)|311|311|3|0.9%|0.0%|
[sorbs_web](#sorbs_web)|645|646|2|0.3%|0.0%|
[shunlist](#shunlist)|1248|1248|2|0.1%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2|0.0%|0.0%|
[voipbl](#voipbl)|10452|10864|1|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|168|168|1|0.5%|0.0%|
[ciarmy](#ciarmy)|395|395|1|0.2%|0.0%|

## blocklist_de_ftp

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours for attacks on the Service FTP.

Source is downloaded from [this link](http://lists.blocklist.de/lists/ftp.txt).

The last time downloaded was found to be dated: Sat Jun  6 08:56:16 UTC 2015.

The ipset `blocklist_de_ftp` has **901** entries, **901** unique IPs.

The following table shows the overlaps of `blocklist_de_ftp` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_ftp`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_ftp`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_ftp`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|25717|25717|896|3.4%|99.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|83|0.0%|9.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|17|0.0%|1.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|12|0.0%|1.3%|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|11|0.0%|1.2%|
[nixspam](#nixspam)|16272|16272|9|0.0%|0.9%|
[alienvault_reputation](#alienvault_reputation)|178368|178368|7|0.0%|0.7%|
[sorbs_spam](#sorbs_spam)|29446|30474|5|0.0%|0.5%|
[sorbs_recent_spam](#sorbs_recent_spam)|29446|30474|5|0.0%|0.5%|
[sorbs_new_spam](#sorbs_new_spam)|29446|30474|5|0.0%|0.5%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|3|0.0%|0.3%|
[php_spammers](#php_spammers)|495|495|2|0.4%|0.2%|
[php_harvesters](#php_harvesters)|311|311|2|0.6%|0.2%|
[openbl_60d](#openbl_60d)|7651|7651|2|0.0%|0.2%|
[blocklist_de_strongips](#blocklist_de_strongips)|183|183|2|1.0%|0.2%|
[php_dictionary](#php_dictionary)|508|508|1|0.1%|0.1%|
[openbl_30d](#openbl_30d)|3251|3251|1|0.0%|0.1%|
[ciarmy](#ciarmy)|395|395|1|0.2%|0.1%|

## blocklist_de_imap

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours for attacks on the Service imap, sasl, pop3, etc.

Source is downloaded from [this link](http://lists.blocklist.de/lists/imap.txt).

The last time downloaded was found to be dated: Sat Jun  6 08:42:09 UTC 2015.

The ipset `blocklist_de_imap` has **1810** entries, **1810** unique IPs.

The following table shows the overlaps of `blocklist_de_imap` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_imap`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_imap`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_imap`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de_mail](#blocklist_de_mail)|15653|15653|1810|11.5%|100.0%|
[blocklist_de](#blocklist_de)|25717|25717|1810|7.0%|100.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|177|0.0%|9.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|54|0.0%|2.9%|
[alienvault_reputation](#alienvault_reputation)|178368|178368|46|0.0%|2.5%|
[openbl_60d](#openbl_60d)|7651|7651|38|0.4%|2.0%|
[openbl_30d](#openbl_30d)|3251|3251|32|0.9%|1.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|26|0.0%|1.4%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|17|0.0%|0.9%|
[et_block](#et_block)|1023|18338662|17|0.0%|0.9%|
[sorbs_spam](#sorbs_spam)|29446|30474|12|0.0%|0.6%|
[sorbs_recent_spam](#sorbs_recent_spam)|29446|30474|12|0.0%|0.6%|
[sorbs_new_spam](#sorbs_new_spam)|29446|30474|12|0.0%|0.6%|
[nixspam](#nixspam)|16272|16272|12|0.0%|0.6%|
[openbl_7d](#openbl_7d)|861|861|11|1.2%|0.6%|
[et_compromised](#et_compromised)|2016|2016|7|0.3%|0.3%|
[bruteforceblocker](#bruteforceblocker)|1892|1892|7|0.3%|0.3%|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|6|0.0%|0.3%|
[snort_ipfilter](#snort_ipfilter)|8977|8977|3|0.0%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|2|0.0%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2|0.0%|0.1%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|2|0.0%|0.1%|
[voipbl](#voipbl)|10452|10864|1|0.0%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|1|0.0%|0.0%|
[shunlist](#shunlist)|1248|1248|1|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2447|2447|1|0.0%|0.0%|
[openbl_1d](#openbl_1d)|146|146|1|0.6%|0.0%|
[ciarmy](#ciarmy)|395|395|1|0.2%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|183|183|1|0.5%|0.0%|

## blocklist_de_mail

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service Mail, Postfix.

Source is downloaded from [this link](http://lists.blocklist.de/lists/mail.txt).

The last time downloaded was found to be dated: Sat Jun  6 08:42:07 UTC 2015.

The ipset `blocklist_de_mail` has **15653** entries, **15653** unique IPs.

The following table shows the overlaps of `blocklist_de_mail` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_mail`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_mail`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_mail`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|25717|25717|15653|60.8%|100.0%|
[blocklist_de_apache](#blocklist_de_apache)|14812|14812|11059|74.6%|70.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|2459|0.0%|15.7%|
[blocklist_de_imap](#blocklist_de_imap)|1810|1810|1810|100.0%|11.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|1363|0.0%|8.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|1141|0.0%|7.2%|
[sorbs_spam](#sorbs_spam)|29446|30474|895|2.9%|5.7%|
[sorbs_recent_spam](#sorbs_recent_spam)|29446|30474|895|2.9%|5.7%|
[sorbs_new_spam](#sorbs_new_spam)|29446|30474|895|2.9%|5.7%|
[nixspam](#nixspam)|16272|16272|285|1.7%|1.8%|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|263|0.2%|1.6%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|146|0.4%|0.9%|
[snort_ipfilter](#snort_ipfilter)|8977|8977|143|1.5%|0.9%|
[php_dictionary](#php_dictionary)|508|508|63|12.4%|0.4%|
[sorbs_web](#sorbs_web)|645|646|62|9.5%|0.3%|
[alienvault_reputation](#alienvault_reputation)|178368|178368|62|0.0%|0.3%|
[php_spammers](#php_spammers)|495|495|58|11.7%|0.3%|
[ri_web_proxies](#ri_web_proxies)|6565|6565|57|0.8%|0.3%|
[stopforumspam_1d](#stopforumspam_1d)|7042|7042|54|0.7%|0.3%|
[xroxy](#xroxy)|2094|2094|48|2.2%|0.3%|
[openbl_60d](#openbl_60d)|7651|7651|45|0.5%|0.2%|
[openbl_30d](#openbl_30d)|3251|3251|39|1.1%|0.2%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|27|0.0%|0.1%|
[et_block](#et_block)|1023|18338662|27|0.0%|0.1%|
[blocklist_de_bots](#blocklist_de_bots)|3120|3120|23|0.7%|0.1%|
[blocklist_de_strongips](#blocklist_de_strongips)|183|183|22|12.0%|0.1%|
[proxz](#proxz)|862|862|21|2.4%|0.1%|
[php_commenters](#php_commenters)|326|326|21|6.4%|0.1%|
[openbl_7d](#openbl_7d)|861|861|13|1.5%|0.0%|
[et_compromised](#et_compromised)|2016|2016|9|0.4%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1892|1892|9|0.4%|0.0%|
[sorbs_socks](#sorbs_socks)|19|19|5|26.3%|0.0%|
[sorbs_misc](#sorbs_misc)|19|19|5|26.3%|0.0%|
[sorbs_http](#sorbs_http)|19|19|5|26.3%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|5|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|4|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|4|0.0%|0.0%|
[et_tor](#et_tor)|6470|6470|4|0.0%|0.0%|
[dm_tor](#dm_tor)|6475|6475|4|0.0%|0.0%|
[bm_tor](#bm_tor)|6461|6461|4|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2447|2447|3|0.1%|0.0%|
[voipbl](#voipbl)|10452|10864|2|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|1|0.0%|0.0%|
[shunlist](#shunlist)|1248|1248|1|0.0%|0.0%|
[php_harvesters](#php_harvesters)|311|311|1|0.3%|0.0%|
[openbl_1d](#openbl_1d)|146|146|1|0.6%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|1|0.1%|0.0%|
[ciarmy](#ciarmy)|395|395|1|0.2%|0.0%|

## blocklist_de_sip

[Blocklist.de](https://www.blocklist.de/) All IP addresses that tried to login in a SIP, VOIP or Asterisk Server and are included in the IPs list from [infiltrated.net](www.infiltrated.net)

Source is downloaded from [this link](http://lists.blocklist.de/lists/sip.txt).

The last time downloaded was found to be dated: Sat Jun  6 08:42:09 UTC 2015.

The ipset `blocklist_de_sip` has **90** entries, **90** unique IPs.

The following table shows the overlaps of `blocklist_de_sip` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_sip`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_sip`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_sip`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|25717|25717|71|0.2%|78.8%|
[voipbl](#voipbl)|10452|10864|25|0.2%|27.7%|
[alienvault_reputation](#alienvault_reputation)|178368|178368|17|0.0%|18.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|11|0.0%|12.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|8|0.0%|8.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|3|0.0%|3.3%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|2|0.0%|2.2%|
[et_block](#et_block)|1023|18338662|2|0.0%|2.2%|
[et_botcc](#et_botcc)|509|509|1|0.1%|1.1%|

## blocklist_de_ssh

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service SSH.

Source is downloaded from [this link](http://lists.blocklist.de/lists/ssh.txt).

The last time downloaded was found to be dated: Sat Jun  6 08:42:05 UTC 2015.

The ipset `blocklist_de_ssh` has **2229** entries, **2229** unique IPs.

The following table shows the overlaps of `blocklist_de_ssh` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_ssh`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_ssh`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_ssh`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|25717|25717|2229|8.6%|100.0%|
[alienvault_reputation](#alienvault_reputation)|178368|178368|904|0.5%|40.5%|
[openbl_60d](#openbl_60d)|7651|7651|815|10.6%|36.5%|
[openbl_30d](#openbl_30d)|3251|3251|664|20.4%|29.7%|
[bruteforceblocker](#bruteforceblocker)|1892|1892|627|33.1%|28.1%|
[et_compromised](#et_compromised)|2016|2016|625|31.0%|28.0%|
[openbl_7d](#openbl_7d)|861|861|431|50.0%|19.3%|
[shunlist](#shunlist)|1248|1248|331|26.5%|14.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|249|0.0%|11.1%|
[openbl_1d](#openbl_1d)|146|146|123|84.2%|5.5%|
[et_block](#et_block)|1023|18338662|111|0.0%|4.9%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|107|0.0%|4.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|101|0.0%|4.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|47|0.0%|2.1%|
[dshield](#dshield)|19|5120|47|0.9%|2.1%|
[blocklist_de_strongips](#blocklist_de_strongips)|183|183|29|15.8%|1.3%|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|16|0.0%|0.7%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|8|0.0%|0.3%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|5|0.0%|0.2%|
[sorbs_spam](#sorbs_spam)|29446|30474|3|0.0%|0.1%|
[sorbs_recent_spam](#sorbs_recent_spam)|29446|30474|3|0.0%|0.1%|
[sorbs_new_spam](#sorbs_new_spam)|29446|30474|3|0.0%|0.1%|
[nixspam](#nixspam)|16272|16272|3|0.0%|0.1%|
[ciarmy](#ciarmy)|395|395|2|0.5%|0.0%|
[sslbl](#sslbl)|369|369|1|0.2%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|1|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|8977|8977|1|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1|0.0%|0.0%|

## blocklist_de_strongips

[Blocklist.de](https://www.blocklist.de/) All IPs which are older then 2 month and have more then 5.000 attacks.

Source is downloaded from [this link](http://lists.blocklist.de/lists/strongips.txt).

The last time downloaded was found to be dated: Sat Jun  6 08:42:12 UTC 2015.

The ipset `blocklist_de_strongips` has **183** entries, **183** unique IPs.

The following table shows the overlaps of `blocklist_de_strongips` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_strongips`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_strongips`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_strongips`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|25717|25717|183|0.7%|100.0%|
[blocklist_de_bots](#blocklist_de_bots)|3120|3120|136|4.3%|74.3%|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|135|0.1%|73.7%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|124|0.4%|67.7%|
[stopforumspam_1d](#stopforumspam_1d)|7042|7042|108|1.5%|59.0%|
[php_commenters](#php_commenters)|326|326|36|11.0%|19.6%|
[alienvault_reputation](#alienvault_reputation)|178368|178368|36|0.0%|19.6%|
[blocklist_de_apache](#blocklist_de_apache)|14812|14812|32|0.2%|17.4%|
[blocklist_de_ssh](#blocklist_de_ssh)|2229|2229|29|1.3%|15.8%|
[openbl_60d](#openbl_60d)|7651|7651|27|0.3%|14.7%|
[openbl_30d](#openbl_30d)|3251|3251|25|0.7%|13.6%|
[openbl_7d](#openbl_7d)|861|861|24|2.7%|13.1%|
[blocklist_de_mail](#blocklist_de_mail)|15653|15653|22|0.1%|12.0%|
[shunlist](#shunlist)|1248|1248|20|1.6%|10.9%|
[openbl_1d](#openbl_1d)|146|146|20|13.6%|10.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|16|0.0%|8.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|8|0.0%|4.3%|
[et_block](#et_block)|1023|18338662|8|0.0%|4.3%|
[xroxy](#xroxy)|2094|2094|7|0.3%|3.8%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|7|0.0%|3.8%|
[proxyrss](#proxyrss)|1688|1688|7|0.4%|3.8%|
[ri_web_proxies](#ri_web_proxies)|6565|6565|6|0.0%|3.2%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|3461|3461|6|0.1%|3.2%|
[php_spammers](#php_spammers)|495|495|5|1.0%|2.7%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|4|0.0%|2.1%|
[proxz](#proxz)|862|862|4|0.4%|2.1%|
[php_dictionary](#php_dictionary)|508|508|3|0.5%|1.6%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|1.6%|
[php_harvesters](#php_harvesters)|311|311|2|0.6%|1.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|1.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|901|901|2|0.2%|1.0%|
[sorbs_web](#sorbs_web)|645|646|1|0.1%|0.5%|
[sorbs_spam](#sorbs_spam)|29446|30474|1|0.0%|0.5%|
[sorbs_recent_spam](#sorbs_recent_spam)|29446|30474|1|0.0%|0.5%|
[sorbs_new_spam](#sorbs_new_spam)|29446|30474|1|0.0%|0.5%|
[snort_ipfilter](#snort_ipfilter)|8977|8977|1|0.0%|0.5%|
[nixspam](#nixspam)|16272|16272|1|0.0%|0.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|1|0.0%|0.5%|
[dshield](#dshield)|19|5120|1|0.0%|0.5%|
[bruteforceblocker](#bruteforceblocker)|1892|1892|1|0.0%|0.5%|
[blocklist_de_imap](#blocklist_de_imap)|1810|1810|1|0.0%|0.5%|

## bm_tor

[torstatus.blutmagie.de](https://torstatus.blutmagie.de) list of all TOR network servers

Source is downloaded from [this link](https://torstatus.blutmagie.de/ip_list_all.php/Tor_ip_list_ALL.csv).

The last time downloaded was found to be dated: Sat Jun  6 08:45:08 UTC 2015.

The ipset `bm_tor` has **6461** entries, **6461** unique IPs.

The following table shows the overlaps of `bm_tor` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `bm_tor`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `bm_tor`.
- ` this % ` is the percentage **of this ipset (`bm_tor`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[dm_tor](#dm_tor)|6475|6475|6399|98.8%|99.0%|
[et_tor](#et_tor)|6470|6470|5816|89.8%|90.0%|
[snort_ipfilter](#snort_ipfilter)|8977|8977|1062|11.8%|16.4%|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|644|0.6%|9.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|626|0.0%|9.6%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|509|1.6%|7.8%|
[stopforumspam_1d](#stopforumspam_1d)|7042|7042|335|4.7%|5.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|190|0.0%|2.9%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|169|45.4%|2.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|165|0.0%|2.5%|
[alienvault_reputation](#alienvault_reputation)|178368|178368|43|0.0%|0.6%|
[php_commenters](#php_commenters)|326|326|34|10.4%|0.5%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|22|0.0%|0.3%|
[openbl_60d](#openbl_60d)|7651|7651|20|0.2%|0.3%|
[php_harvesters](#php_harvesters)|311|311|7|2.2%|0.1%|
[ri_web_proxies](#ri_web_proxies)|6565|6565|5|0.0%|0.0%|
[php_spammers](#php_spammers)|495|495|5|1.0%|0.0%|
[et_block](#et_block)|1023|18338662|5|0.0%|0.0%|
[php_dictionary](#php_dictionary)|508|508|4|0.7%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|4|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|15653|15653|4|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14812|14812|4|0.0%|0.0%|
[blocklist_de](#blocklist_de)|25717|25717|4|0.0%|0.0%|
[voipbl](#voipbl)|10452|10864|3|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|3|0.0%|0.0%|
[xroxy](#xroxy)|2094|2094|2|0.0%|0.0%|
[sorbs_spam](#sorbs_spam)|29446|30474|2|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|29446|30474|2|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|29446|30474|2|0.0%|0.0%|
[shunlist](#shunlist)|1248|1248|1|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2447|2447|1|0.0%|0.0%|
[dshield](#dshield)|19|5120|1|0.0%|0.0%|

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
[voipbl](#voipbl)|10452|10864|319|2.9%|0.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|5|0.0%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|1|0.0%|0.0%|
[php_harvesters](#php_harvesters)|311|311|1|0.3%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.0%|
[ciarmy](#ciarmy)|395|395|1|0.2%|0.0%|
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
[alienvault_reputation](#alienvault_reputation)|178368|178368|1225|0.6%|64.7%|
[openbl_60d](#openbl_60d)|7651|7651|1130|14.7%|59.7%|
[openbl_30d](#openbl_30d)|3251|3251|1081|33.2%|57.1%|
[blocklist_de](#blocklist_de)|25717|25717|641|2.4%|33.8%|
[blocklist_de_ssh](#blocklist_de_ssh)|2229|2229|627|28.1%|33.1%|
[shunlist](#shunlist)|1248|1248|449|35.9%|23.7%|
[openbl_7d](#openbl_7d)|861|861|382|44.3%|20.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|179|0.0%|9.4%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|101|0.0%|5.3%|
[et_block](#et_block)|1023|18338662|101|0.0%|5.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|95|0.0%|5.0%|
[openbl_1d](#openbl_1d)|146|146|84|57.5%|4.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|50|0.0%|2.6%|
[dshield](#dshield)|19|5120|43|0.8%|2.2%|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|11|0.0%|0.5%|
[blocklist_de_mail](#blocklist_de_mail)|15653|15653|9|0.0%|0.4%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|7|0.0%|0.3%|
[blocklist_de_imap](#blocklist_de_imap)|1810|1810|7|0.3%|0.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|5|0.0%|0.2%|
[voipbl](#voipbl)|10452|10864|2|0.0%|0.1%|
[proxz](#proxz)|862|862|2|0.2%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|2|0.0%|0.1%|
[blocklist_de_bots](#blocklist_de_bots)|3120|3120|2|0.0%|0.1%|
[blocklist_de_apache](#blocklist_de_apache)|14812|14812|2|0.0%|0.1%|
[xroxy](#xroxy)|2094|2094|1|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|6565|6565|1|0.0%|0.0%|
[nixspam](#nixspam)|16272|16272|1|0.0%|0.0%|
[fullbogons](#fullbogons)|3715|670310296|1|0.0%|0.0%|
[ciarmy](#ciarmy)|395|395|1|0.2%|0.0%|
[bogons](#bogons)|13|592708608|1|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|183|183|1|0.5%|0.0%|

## ciarmy

[CIArmy.com](http://ciarmy.com/) IPs with poor Rogue Packet score that have not yet been identified as malicious by the community

Source is downloaded from [this link](http://cinsscore.com/list/ci-badguys.txt).

The last time downloaded was found to be dated: Sat Jun  6 07:15:16 UTC 2015.

The ipset `ciarmy` has **395** entries, **395** unique IPs.

The following table shows the overlaps of `ciarmy` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ciarmy`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ciarmy`.
- ` this % ` is the percentage **of this ipset (`ciarmy`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[alienvault_reputation](#alienvault_reputation)|178368|178368|369|0.2%|93.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|77|0.0%|19.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|40|0.0%|10.1%|
[blocklist_de](#blocklist_de)|25717|25717|35|0.1%|8.8%|
[blocklist_de_apache](#blocklist_de_apache)|14812|14812|31|0.2%|7.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|29|0.0%|7.3%|
[shunlist](#shunlist)|1248|1248|25|2.0%|6.3%|
[et_block](#et_block)|1023|18338662|6|0.0%|1.5%|
[voipbl](#voipbl)|10452|10864|4|0.0%|1.0%|
[dshield](#dshield)|19|5120|3|0.0%|0.7%|
[blocklist_de_ssh](#blocklist_de_ssh)|2229|2229|2|0.0%|0.5%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|1|0.0%|0.2%|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|1|0.0%|0.2%|
[stopforumspam_1d](#stopforumspam_1d)|7042|7042|1|0.0%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.2%|
[fullbogons](#fullbogons)|3715|670310296|1|0.0%|0.2%|
[et_compromised](#et_compromised)|2016|2016|1|0.0%|0.2%|
[bruteforceblocker](#bruteforceblocker)|1892|1892|1|0.0%|0.2%|
[bogons](#bogons)|13|592708608|1|0.0%|0.2%|
[blocklist_de_mail](#blocklist_de_mail)|15653|15653|1|0.0%|0.2%|
[blocklist_de_imap](#blocklist_de_imap)|1810|1810|1|0.0%|0.2%|
[blocklist_de_ftp](#blocklist_de_ftp)|901|901|1|0.1%|0.2%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|3461|3461|1|0.0%|0.2%|

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
[alienvault_reputation](#alienvault_reputation)|178368|178368|7|0.0%|4.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|3|0.0%|1.7%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|2|0.1%|1.1%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|3461|3461|1|0.0%|0.5%|
[blocklist_de_apache](#blocklist_de_apache)|14812|14812|1|0.0%|0.5%|
[blocklist_de](#blocklist_de)|25717|25717|1|0.0%|0.5%|

## dm_tor

[dan.me.uk](https://www.dan.me.uk) dynamic list of TOR exit points

Source is downloaded from [this link](https://www.dan.me.uk/torlist/).

The last time downloaded was found to be dated: Sat Jun  6 08:45:05 UTC 2015.

The ipset `dm_tor` has **6475** entries, **6475** unique IPs.

The following table shows the overlaps of `dm_tor` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `dm_tor`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `dm_tor`.
- ` this % ` is the percentage **of this ipset (`dm_tor`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[bm_tor](#bm_tor)|6461|6461|6399|99.0%|98.8%|
[et_tor](#et_tor)|6470|6470|5803|89.6%|89.6%|
[snort_ipfilter](#snort_ipfilter)|8977|8977|1058|11.7%|16.3%|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|641|0.6%|9.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|633|0.0%|9.7%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|506|1.6%|7.8%|
[stopforumspam_1d](#stopforumspam_1d)|7042|7042|333|4.7%|5.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|188|0.0%|2.9%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|168|45.1%|2.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|165|0.0%|2.5%|
[alienvault_reputation](#alienvault_reputation)|178368|178368|43|0.0%|0.6%|
[php_commenters](#php_commenters)|326|326|34|10.4%|0.5%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|22|0.0%|0.3%|
[openbl_60d](#openbl_60d)|7651|7651|20|0.2%|0.3%|
[php_harvesters](#php_harvesters)|311|311|7|2.2%|0.1%|
[ri_web_proxies](#ri_web_proxies)|6565|6565|5|0.0%|0.0%|
[php_spammers](#php_spammers)|495|495|5|1.0%|0.0%|
[et_block](#et_block)|1023|18338662|5|0.0%|0.0%|
[php_dictionary](#php_dictionary)|508|508|4|0.7%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|4|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|15653|15653|4|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14812|14812|4|0.0%|0.0%|
[blocklist_de](#blocklist_de)|25717|25717|4|0.0%|0.0%|
[voipbl](#voipbl)|10452|10864|3|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|3|0.0%|0.0%|
[xroxy](#xroxy)|2094|2094|2|0.0%|0.0%|
[sorbs_spam](#sorbs_spam)|29446|30474|2|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|29446|30474|2|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|29446|30474|2|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|1|0.0%|0.0%|
[shunlist](#shunlist)|1248|1248|1|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2447|2447|1|0.0%|0.0%|
[dshield](#dshield)|19|5120|1|0.0%|0.0%|

## dshield

[DShield.org](https://dshield.org/) top 20 attacking class C (/24) subnets over the last three days - **excellent list**

Source is downloaded from [this link](http://feeds.dshield.org/block.txt).

The last time downloaded was found to be dated: Sat Jun  6 07:18:33 UTC 2015.

The ipset `dshield` has **19** entries, **5120** unique IPs.

The following table shows the overlaps of `dshield` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `dshield`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `dshield`.
- ` this % ` is the percentage **of this ipset (`dshield`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[alienvault_reputation](#alienvault_reputation)|178368|178368|4354|2.4%|85.0%|
[et_block](#et_block)|1023|18338662|1280|0.0%|25.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|512|0.0%|10.0%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|256|0.0%|5.0%|
[openbl_60d](#openbl_60d)|7651|7651|112|1.4%|2.1%|
[openbl_30d](#openbl_30d)|3251|3251|92|2.8%|1.7%|
[shunlist](#shunlist)|1248|1248|58|4.6%|1.1%|
[blocklist_de](#blocklist_de)|25717|25717|58|0.2%|1.1%|
[et_compromised](#et_compromised)|2016|2016|51|2.5%|0.9%|
[blocklist_de_ssh](#blocklist_de_ssh)|2229|2229|47|2.1%|0.9%|
[bruteforceblocker](#bruteforceblocker)|1892|1892|43|2.2%|0.8%|
[openbl_7d](#openbl_7d)|861|861|36|4.1%|0.7%|
[blocklist_de_apache](#blocklist_de_apache)|14812|14812|9|0.0%|0.1%|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|8|0.0%|0.1%|
[openbl_1d](#openbl_1d)|146|146|8|5.4%|0.1%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|6|0.0%|0.1%|
[voipbl](#voipbl)|10452|10864|5|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7042|7042|4|0.0%|0.0%|
[ciarmy](#ciarmy)|395|395|3|0.7%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3120|3120|2|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|8977|8977|1|0.0%|0.0%|
[nixspam](#nixspam)|16272|16272|1|0.0%|0.0%|
[malc0de](#malc0de)|371|371|1|0.2%|0.0%|
[et_tor](#et_tor)|6470|6470|1|0.0%|0.0%|
[dm_tor](#dm_tor)|6475|6475|1|0.0%|0.0%|
[bm_tor](#bm_tor)|6461|6461|1|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|183|183|1|0.5%|0.0%|

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
[fullbogons](#fullbogons)|3715|670310296|20480|0.0%|0.1%|
[alienvault_reputation](#alienvault_reputation)|178368|178368|5280|2.9%|0.0%|
[dshield](#dshield)|19|5120|1280|25.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1040|0.3%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|1013|1.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|517|0.1%|0.0%|
[snort_ipfilter](#snort_ipfilter)|8977|8977|317|3.5%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|314|1.0%|0.0%|
[openbl_60d](#openbl_60d)|7651|7651|250|3.2%|0.0%|
[zeus](#zeus)|230|230|223|96.9%|0.0%|
[zeus_badips](#zeus_badips)|202|202|200|99.0%|0.0%|
[blocklist_de](#blocklist_de)|25717|25717|197|0.7%|0.0%|
[openbl_30d](#openbl_30d)|3251|3251|166|5.1%|0.0%|
[shunlist](#shunlist)|1248|1248|111|8.8%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2229|2229|111|4.9%|0.0%|
[nixspam](#nixspam)|16272|16272|103|0.6%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1892|1892|101|5.3%|0.0%|
[et_compromised](#et_compromised)|2016|2016|100|4.9%|0.0%|
[feodo](#feodo)|99|99|94|94.9%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7042|7042|80|1.1%|0.0%|
[openbl_7d](#openbl_7d)|861|861|51|5.9%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3120|3120|44|1.4%|0.0%|
[sslbl](#sslbl)|369|369|35|9.4%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|29|2.2%|0.0%|
[php_commenters](#php_commenters)|326|326|28|8.5%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|15653|15653|27|0.1%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|1810|1810|17|0.9%|0.0%|
[voipbl](#voipbl)|10452|10864|16|0.1%|0.0%|
[palevo](#palevo)|13|13|13|100.0%|0.0%|
[openbl_1d](#openbl_1d)|146|146|13|8.9%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14812|14812|12|0.0%|0.0%|
[sorbs_spam](#sorbs_spam)|29446|30474|10|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|29446|30474|10|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|29446|30474|10|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|183|183|8|4.3%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|6|0.4%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|6|0.0%|0.0%|
[ciarmy](#ciarmy)|395|395|6|1.5%|0.0%|
[malc0de](#malc0de)|371|371|5|1.3%|0.0%|
[dm_tor](#dm_tor)|6475|6475|5|0.0%|0.0%|
[bm_tor](#bm_tor)|6461|6461|5|0.0%|0.0%|
[php_dictionary](#php_dictionary)|508|508|4|0.7%|0.0%|
[et_tor](#et_tor)|6470|6470|4|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|3461|3461|4|0.1%|0.0%|
[php_spammers](#php_spammers)|495|495|2|0.4%|0.0%|
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
[alienvault_reputation](#alienvault_reputation)|178368|178368|5|0.0%|0.9%|
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
[bruteforceblocker](#bruteforceblocker)|1892|1892|1851|97.8%|91.8%|
[alienvault_reputation](#alienvault_reputation)|178368|178368|1311|0.7%|65.0%|
[openbl_60d](#openbl_60d)|7651|7651|1216|15.8%|60.3%|
[openbl_30d](#openbl_30d)|3251|3251|1151|35.4%|57.0%|
[blocklist_de](#blocklist_de)|25717|25717|639|2.4%|31.6%|
[blocklist_de_ssh](#blocklist_de_ssh)|2229|2229|625|28.0%|31.0%|
[shunlist](#shunlist)|1248|1248|459|36.7%|22.7%|
[openbl_7d](#openbl_7d)|861|861|386|44.8%|19.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|199|0.0%|9.8%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|100|0.0%|4.9%|
[et_block](#et_block)|1023|18338662|100|0.0%|4.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|97|0.0%|4.8%|
[openbl_1d](#openbl_1d)|146|146|82|56.1%|4.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|52|0.0%|2.5%|
[dshield](#dshield)|19|5120|51|0.9%|2.5%|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|11|0.0%|0.5%|
[blocklist_de_mail](#blocklist_de_mail)|15653|15653|9|0.0%|0.4%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|7|0.0%|0.3%|
[blocklist_de_imap](#blocklist_de_imap)|1810|1810|7|0.3%|0.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|5|0.0%|0.2%|
[voipbl](#voipbl)|10452|10864|2|0.0%|0.0%|
[proxz](#proxz)|862|862|2|0.2%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|2|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3120|3120|2|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14812|14812|2|0.0%|0.0%|
[xroxy](#xroxy)|2094|2094|1|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|6565|6565|1|0.0%|0.0%|
[nixspam](#nixspam)|16272|16272|1|0.0%|0.0%|
[ciarmy](#ciarmy)|395|395|1|0.2%|0.0%|

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
[bm_tor](#bm_tor)|6461|6461|5816|90.0%|89.8%|
[dm_tor](#dm_tor)|6475|6475|5803|89.6%|89.6%|
[snort_ipfilter](#snort_ipfilter)|8977|8977|1085|12.0%|16.7%|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|647|0.6%|10.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|633|0.0%|9.7%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|516|1.7%|7.9%|
[stopforumspam_1d](#stopforumspam_1d)|7042|7042|337|4.7%|5.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|190|0.0%|2.9%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|168|45.1%|2.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|168|0.0%|2.5%|
[alienvault_reputation](#alienvault_reputation)|178368|178368|42|0.0%|0.6%|
[php_commenters](#php_commenters)|326|326|35|10.7%|0.5%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|22|0.0%|0.3%|
[openbl_60d](#openbl_60d)|7651|7651|20|0.2%|0.3%|
[php_harvesters](#php_harvesters)|311|311|7|2.2%|0.1%|
[php_spammers](#php_spammers)|495|495|6|1.2%|0.0%|
[ri_web_proxies](#ri_web_proxies)|6565|6565|5|0.0%|0.0%|
[php_dictionary](#php_dictionary)|508|508|5|0.9%|0.0%|
[et_block](#et_block)|1023|18338662|4|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|15653|15653|4|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14812|14812|4|0.0%|0.0%|
[blocklist_de](#blocklist_de)|25717|25717|4|0.0%|0.0%|
[voipbl](#voipbl)|10452|10864|3|0.0%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|0.0%|
[xroxy](#xroxy)|2094|2094|2|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|2|0.0%|0.0%|
[sorbs_spam](#sorbs_spam)|29446|30474|2|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|29446|30474|2|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|29446|30474|2|0.0%|0.0%|
[shunlist](#shunlist)|1248|1248|1|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2447|2447|1|0.0%|0.0%|
[dshield](#dshield)|19|5120|1|0.0%|0.0%|

## feodo

[Abuse.ch Feodo tracker](https://feodotracker.abuse.ch) trojan includes IPs which are being used by Feodo (also known as Cridex or Bugat) which commits ebanking fraud - **excellent list**

Source is downloaded from [this link](https://feodotracker.abuse.ch/blocklist/?download=ipblocklist).

The last time downloaded was found to be dated: Sat Jun  6 08:45:15 UTC 2015.

The ipset `feodo` has **99** entries, **99** unique IPs.

The following table shows the overlaps of `feodo` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `feodo`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `feodo`.
- ` this % ` is the percentage **of this ipset (`feodo`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[et_block](#et_block)|1023|18338662|94|0.0%|94.9%|
[snort_ipfilter](#snort_ipfilter)|8977|8977|76|0.8%|76.7%|
[sslbl](#sslbl)|369|369|36|9.7%|36.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|11|0.0%|11.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|3|0.0%|3.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|3|0.0%|3.0%|
[alienvault_reputation](#alienvault_reputation)|178368|178368|2|0.0%|2.0%|
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
[et_block](#et_block)|1023|18338662|20480|0.1%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|890|0.2%|0.0%|
[voipbl](#voipbl)|10452|10864|319|2.9%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|33|2.2%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|15|0.0%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|9|0.6%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|2|0.0%|0.0%|
[php_harvesters](#php_harvesters)|311|311|1|0.3%|0.0%|
[ciarmy](#ciarmy)|395|395|1|0.2%|0.0%|
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
[sorbs_spam](#sorbs_spam)|29446|30474|15|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|29446|30474|15|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|29446|30474|15|0.0%|0.0%|
[fullbogons](#fullbogons)|3715|670310296|15|0.0%|0.0%|
[alienvault_reputation](#alienvault_reputation)|178368|178368|15|0.0%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|14|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|11|1.6%|0.0%|
[blocklist_de](#blocklist_de)|25717|25717|11|0.0%|0.0%|
[nixspam](#nixspam)|16272|16272|9|0.0%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|6|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|6|0.0%|0.0%|
[et_block](#et_block)|1023|18338662|6|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|3461|3461|5|0.1%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14812|14812|5|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|4|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|15653|15653|4|0.0%|0.0%|
[xroxy](#xroxy)|2094|2094|3|0.1%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7042|7042|3|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|6565|6565|3|0.0%|0.0%|
[voipbl](#voipbl)|10452|10864|2|0.0%|0.0%|
[php_harvesters](#php_harvesters)|311|311|2|0.6%|0.0%|
[php_dictionary](#php_dictionary)|508|508|2|0.3%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|1810|1810|2|0.1%|0.0%|
[sorbs_web](#sorbs_web)|645|646|1|0.1%|0.0%|
[snort_ipfilter](#snort_ipfilter)|8977|8977|1|0.0%|0.0%|
[proxz](#proxz)|862|862|1|0.1%|0.0%|
[proxyrss](#proxyrss)|1688|1688|1|0.0%|0.0%|
[php_spammers](#php_spammers)|495|495|1|0.2%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2229|2229|1|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3120|3120|1|0.0%|0.0%|

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
[fullbogons](#fullbogons)|3715|670310296|565248|0.0%|6.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|145472|0.1%|1.5%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1036|0.3%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|744|0.7%|0.0%|
[alienvault_reputation](#alienvault_reputation)|178368|178368|518|0.2%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|153|0.5%|0.0%|
[nixspam](#nixspam)|16272|16272|100|0.6%|0.0%|
[blocklist_de](#blocklist_de)|25717|25717|55|0.2%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3120|3120|38|1.2%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|27|2.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7042|7042|26|0.3%|0.0%|
[openbl_60d](#openbl_60d)|7651|7651|17|0.2%|0.0%|
[openbl_30d](#openbl_30d)|3251|3251|13|0.3%|0.0%|
[snort_ipfilter](#snort_ipfilter)|8977|8977|12|0.1%|0.0%|
[zeus_badips](#zeus_badips)|202|202|10|4.9%|0.0%|
[zeus](#zeus)|230|230|10|4.3%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2229|2229|8|0.3%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|7|0.4%|0.0%|
[openbl_7d](#openbl_7d)|861|861|5|0.5%|0.0%|
[et_compromised](#et_compromised)|2016|2016|5|0.2%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1892|1892|5|0.2%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|15653|15653|5|0.0%|0.0%|
[sorbs_spam](#sorbs_spam)|29446|30474|4|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|29446|30474|4|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|29446|30474|4|0.0%|0.0%|
[dm_tor](#dm_tor)|6475|6475|4|0.0%|0.0%|
[bm_tor](#bm_tor)|6461|6461|4|0.0%|0.0%|
[et_tor](#et_tor)|6470|6470|3|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|183|183|3|1.6%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14812|14812|3|0.0%|0.0%|
[shunlist](#shunlist)|1248|1248|2|0.1%|0.0%|
[php_spammers](#php_spammers)|495|495|2|0.4%|0.0%|
[php_dictionary](#php_dictionary)|508|508|2|0.3%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|2|0.2%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|1810|1810|2|0.1%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|3461|3461|2|0.0%|0.0%|
[voipbl](#voipbl)|10452|10864|1|0.0%|0.0%|
[php_harvesters](#php_harvesters)|311|311|1|0.3%|0.0%|
[php_commenters](#php_commenters)|326|326|1|0.3%|0.0%|
[openbl_1d](#openbl_1d)|146|146|1|0.6%|0.0%|
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
[et_block](#et_block)|1023|18338662|2272276|12.3%|0.2%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|2272265|12.3%|0.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|1354348|0.9%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|904796|9.8%|0.1%|
[fullbogons](#fullbogons)|3715|670310296|239993|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|33155|6.8%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|13248|3.9%|0.0%|
[alienvault_reputation](#alienvault_reputation)|178368|178368|4729|2.6%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|1543|1.6%|0.0%|
[blocklist_de](#blocklist_de)|25717|25717|1513|5.8%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|15653|15653|1363|8.7%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14812|14812|1328|8.9%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|568|1.8%|0.0%|
[dshield](#dshield)|19|5120|512|10.0%|0.0%|
[sorbs_spam](#sorbs_spam)|29446|30474|476|1.5%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|29446|30474|476|1.5%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|29446|30474|476|1.5%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|406|0.8%|0.0%|
[voipbl](#voipbl)|10452|10864|299|2.7%|0.0%|
[nixspam](#nixspam)|16272|16272|214|1.3%|0.0%|
[openbl_60d](#openbl_60d)|7651|7651|171|2.2%|0.0%|
[et_tor](#et_tor)|6470|6470|168|2.5%|0.0%|
[dm_tor](#dm_tor)|6475|6475|165|2.5%|0.0%|
[bm_tor](#bm_tor)|6461|6461|165|2.5%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7042|7042|144|2.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|6565|6565|135|2.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|97|6.6%|0.0%|
[snort_ipfilter](#snort_ipfilter)|8977|8977|83|0.9%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2447|2447|76|3.1%|0.0%|
[openbl_30d](#openbl_30d)|3251|3251|71|2.1%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|66|5.1%|0.0%|
[xroxy](#xroxy)|2094|2094|58|2.7%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|58|8.6%|0.0%|
[et_compromised](#et_compromised)|2016|2016|52|2.5%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1892|1892|50|2.6%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2229|2229|47|2.1%|0.0%|
[proxyrss](#proxyrss)|1688|1688|41|2.4%|0.0%|
[et_botcc](#et_botcc)|509|509|41|8.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3120|3120|37|1.1%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|3461|3461|36|1.0%|0.0%|
[proxz](#proxz)|862|862|31|3.5%|0.0%|
[ciarmy](#ciarmy)|395|395|29|7.3%|0.0%|
[shunlist](#shunlist)|1248|1248|28|2.2%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|1810|1810|26|1.4%|0.0%|
[sorbs_web](#sorbs_web)|645|646|22|3.4%|0.0%|
[openbl_7d](#openbl_7d)|861|861|19|2.2%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|17|4.5%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|901|901|17|1.8%|0.0%|
[php_dictionary](#php_dictionary)|508|508|11|2.1%|0.0%|
[malc0de](#malc0de)|371|371|11|2.9%|0.0%|
[php_harvesters](#php_harvesters)|311|311|9|2.8%|0.0%|
[php_spammers](#php_spammers)|495|495|7|1.4%|0.0%|
[php_commenters](#php_commenters)|326|326|7|2.1%|0.0%|
[zeus](#zeus)|230|230|6|2.6%|0.0%|
[bogons](#bogons)|13|592708608|5|0.0%|0.0%|
[zeus_badips](#zeus_badips)|202|202|4|1.9%|0.0%|
[sslbl](#sslbl)|369|369|3|0.8%|0.0%|
[openbl_1d](#openbl_1d)|146|146|3|2.0%|0.0%|
[feodo](#feodo)|99|99|3|3.0%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|90|90|3|3.3%|0.0%|
[virbl](#virbl)|8|8|2|25.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|183|183|1|0.5%|0.0%|

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
[fullbogons](#fullbogons)|3715|670310296|249087|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|98904|20.2%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|7733|2.2%|0.0%|
[alienvault_reputation](#alienvault_reputation)|178368|178368|7532|4.2%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|2524|2.7%|0.0%|
[blocklist_de](#blocklist_de)|25717|25717|1435|5.5%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|15653|15653|1141|7.2%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14812|14812|1085|7.3%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|909|3.0%|0.0%|
[sorbs_spam](#sorbs_spam)|29446|30474|775|2.5%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|29446|30474|775|2.5%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|29446|30474|775|2.5%|0.0%|
[nixspam](#nixspam)|16272|16272|440|2.7%|0.0%|
[voipbl](#voipbl)|10452|10864|434|3.9%|0.0%|
[openbl_60d](#openbl_60d)|7651|7651|332|4.3%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|230|0.4%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7042|7042|197|2.7%|0.0%|
[ri_web_proxies](#ri_web_proxies)|6565|6565|191|2.9%|0.0%|
[et_tor](#et_tor)|6470|6470|190|2.9%|0.0%|
[bm_tor](#bm_tor)|6461|6461|190|2.9%|0.0%|
[dm_tor](#dm_tor)|6475|6475|188|2.9%|0.0%|
[openbl_30d](#openbl_30d)|3251|3251|168|5.1%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3120|3120|114|3.6%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2229|2229|101|4.5%|0.0%|
[xroxy](#xroxy)|2094|2094|100|4.7%|0.0%|
[snort_ipfilter](#snort_ipfilter)|8977|8977|100|1.1%|0.0%|
[et_compromised](#et_compromised)|2016|2016|97|4.8%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2447|2447|96|3.9%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1892|1892|95|5.0%|0.0%|
[shunlist](#shunlist)|1248|1248|72|5.7%|0.0%|
[proxyrss](#proxyrss)|1688|1688|71|4.2%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|1810|1810|54|2.9%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|3461|3461|51|1.4%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|45|3.0%|0.0%|
[openbl_7d](#openbl_7d)|861|861|43|4.9%|0.0%|
[ciarmy](#ciarmy)|395|395|40|10.1%|0.0%|
[php_spammers](#php_spammers)|495|495|36|7.2%|0.0%|
[proxz](#proxz)|862|862|34|3.9%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|28|4.1%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|26|2.0%|0.0%|
[sorbs_web](#sorbs_web)|645|646|25|3.8%|0.0%|
[malc0de](#malc0de)|371|371|22|5.9%|0.0%|
[et_botcc](#et_botcc)|509|509|22|4.3%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|21|5.6%|0.0%|
[php_dictionary](#php_dictionary)|508|508|13|2.5%|0.0%|
[php_commenters](#php_commenters)|326|326|13|3.9%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|901|901|12|1.3%|0.0%|
[zeus](#zeus)|230|230|9|3.9%|0.0%|
[php_harvesters](#php_harvesters)|311|311|9|2.8%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|168|168|9|5.3%|0.0%|
[zeus_badips](#zeus_badips)|202|202|8|3.9%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|183|183|8|4.3%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|90|90|8|8.8%|0.0%|
[sslbl](#sslbl)|369|369|5|1.3%|0.0%|
[openbl_1d](#openbl_1d)|146|146|4|2.7%|0.0%|
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
[fullbogons](#fullbogons)|3715|670310296|4236335|0.6%|3.0%|
[bogons](#bogons)|13|592708608|4194304|0.7%|3.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|2830140|0.8%|2.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|1354348|0.1%|0.9%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|270785|55.5%|0.1%|
[et_block](#et_block)|1023|18338662|195933|1.0%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|145472|1.5%|0.1%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|130368|0.7%|0.0%|
[alienvault_reputation](#alienvault_reputation)|178368|178368|13893|7.7%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|9231|2.7%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|5841|6.2%|0.0%|
[blocklist_de](#blocklist_de)|25717|25717|3264|12.6%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|15653|15653|2459|15.7%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14812|14812|2341|15.8%|0.0%|
[sorbs_spam](#sorbs_spam)|29446|30474|2193|7.1%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|29446|30474|2193|7.1%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|29446|30474|2193|7.1%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|1912|6.3%|0.0%|
[voipbl](#voipbl)|10452|10864|1598|14.7%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1172|2.4%|0.0%|
[nixspam](#nixspam)|16272|16272|1059|6.5%|0.0%|
[openbl_60d](#openbl_60d)|7651|7651|745|9.7%|0.0%|
[et_tor](#et_tor)|6470|6470|633|9.7%|0.0%|
[dm_tor](#dm_tor)|6475|6475|633|9.7%|0.0%|
[bm_tor](#bm_tor)|6461|6461|626|9.6%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7042|7042|521|7.3%|0.0%|
[openbl_30d](#openbl_30d)|3251|3251|312|9.5%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2229|2229|249|11.1%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|3461|3461|243|7.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|8977|8977|231|2.5%|0.0%|
[et_compromised](#et_compromised)|2016|2016|199|9.8%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3120|3120|196|6.2%|0.0%|
[ri_web_proxies](#ri_web_proxies)|6565|6565|190|2.8%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1892|1892|179|9.4%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|1810|1810|177|9.7%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|147|11.4%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|125|33.6%|0.0%|
[openbl_7d](#openbl_7d)|861|861|115|13.3%|0.0%|
[shunlist](#shunlist)|1248|1248|112|8.9%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|110|7.5%|0.0%|
[xroxy](#xroxy)|2094|2094|93|4.4%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|901|901|83|9.2%|0.0%|
[et_botcc](#et_botcc)|509|509|78|15.3%|0.0%|
[ciarmy](#ciarmy)|395|395|77|19.4%|0.0%|
[proxz](#proxz)|862|862|71|8.2%|0.0%|
[malc0de](#malc0de)|371|371|61|16.4%|0.0%|
[proxyrss](#proxyrss)|1688|1688|57|3.3%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2447|2447|53|2.1%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|51|7.5%|0.0%|
[sorbs_web](#sorbs_web)|645|646|44|6.8%|0.0%|
[php_dictionary](#php_dictionary)|508|508|29|5.7%|0.0%|
[php_spammers](#php_spammers)|495|495|28|5.6%|0.0%|
[sslbl](#sslbl)|369|369|25|6.7%|0.0%|
[php_commenters](#php_commenters)|326|326|18|5.5%|0.0%|
[php_harvesters](#php_harvesters)|311|311|17|5.4%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|168|168|17|10.1%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|183|183|16|8.7%|0.0%|
[zeus](#zeus)|230|230|14|6.0%|0.0%|
[openbl_1d](#openbl_1d)|146|146|12|8.2%|0.0%|
[feodo](#feodo)|99|99|11|11.1%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|90|90|11|12.2%|0.0%|
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
[xroxy](#xroxy)|2094|2094|13|0.6%|1.9%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|12|0.0%|1.7%|
[ri_web_proxies](#ri_web_proxies)|6565|6565|12|0.1%|1.7%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|11|0.0%|1.6%|
[proxyrss](#proxyrss)|1688|1688|10|0.5%|1.4%|
[ri_connect_proxies](#ri_connect_proxies)|2447|2447|6|0.2%|0.8%|
[proxz](#proxz)|862|862|6|0.6%|0.8%|
[blocklist_de](#blocklist_de)|25717|25717|4|0.0%|0.5%|
[stopforumspam_1d](#stopforumspam_1d)|7042|7042|3|0.0%|0.4%|
[blocklist_de_bots](#blocklist_de_bots)|3120|3120|3|0.0%|0.4%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|2|0.0%|0.2%|
[sorbs_spam](#sorbs_spam)|29446|30474|2|0.0%|0.2%|
[sorbs_recent_spam](#sorbs_recent_spam)|29446|30474|2|0.0%|0.2%|
[sorbs_new_spam](#sorbs_new_spam)|29446|30474|2|0.0%|0.2%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2|0.0%|0.2%|
[et_block](#et_block)|1023|18338662|2|0.0%|0.2%|
[snort_ipfilter](#snort_ipfilter)|8977|8977|1|0.0%|0.1%|
[php_dictionary](#php_dictionary)|508|508|1|0.1%|0.1%|
[blocklist_de_mail](#blocklist_de_mail)|15653|15653|1|0.0%|0.1%|
[alienvault_reputation](#alienvault_reputation)|178368|178368|1|0.0%|0.1%|

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
[fullbogons](#fullbogons)|3715|670310296|890|0.0%|0.2%|
[alienvault_reputation](#alienvault_reputation)|178368|178368|287|0.1%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|46|0.0%|0.0%|
[sorbs_spam](#sorbs_spam)|29446|30474|33|0.1%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|29446|30474|33|0.1%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|29446|30474|33|0.1%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|27|2.0%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|25|0.0%|0.0%|
[et_tor](#et_tor)|6470|6470|22|0.3%|0.0%|
[dm_tor](#dm_tor)|6475|6475|22|0.3%|0.0%|
[bm_tor](#bm_tor)|6461|6461|22|0.3%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|19|1.3%|0.0%|
[snort_ipfilter](#snort_ipfilter)|8977|8977|14|0.1%|0.0%|
[blocklist_de](#blocklist_de)|25717|25717|11|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7042|7042|8|0.1%|0.0%|
[nixspam](#nixspam)|16272|16272|8|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|6565|6565|5|0.0%|0.0%|
[openbl_60d](#openbl_60d)|7651|7651|5|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|5|1.3%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3120|3120|5|0.1%|0.0%|
[voipbl](#voipbl)|10452|10864|4|0.0%|0.0%|
[openbl_30d](#openbl_30d)|3251|3251|4|0.1%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|4|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|15653|15653|4|0.0%|0.0%|
[malc0de](#malc0de)|371|371|3|0.8%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|168|168|3|1.7%|0.0%|
[et_compromised](#et_compromised)|2016|2016|2|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1892|1892|2|0.1%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|90|90|2|2.2%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|1810|1810|2|0.1%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14812|14812|2|0.0%|0.0%|
[zeus_badips](#zeus_badips)|202|202|1|0.4%|0.0%|
[zeus](#zeus)|230|230|1|0.4%|0.0%|
[xroxy](#xroxy)|2094|2094|1|0.0%|0.0%|
[sslbl](#sslbl)|369|369|1|0.2%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|1|0.0%|0.0%|
[shunlist](#shunlist)|1248|1248|1|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2447|2447|1|0.0%|0.0%|
[proxyrss](#proxyrss)|1688|1688|1|0.0%|0.0%|
[php_harvesters](#php_harvesters)|311|311|1|0.3%|0.0%|
[php_dictionary](#php_dictionary)|508|508|1|0.1%|0.0%|
[palevo](#palevo)|13|13|1|7.6%|0.0%|
[openbl_7d](#openbl_7d)|861|861|1|0.1%|0.0%|
[feodo](#feodo)|99|99|1|1.0%|0.0%|
[ciarmy](#ciarmy)|395|395|1|0.2%|0.0%|
[bogons](#bogons)|13|592708608|1|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2229|2229|1|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|3461|3461|1|0.0%|0.0%|

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
[fullbogons](#fullbogons)|3715|670310296|33|0.0%|2.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|19|0.0%|1.3%|
[alienvault_reputation](#alienvault_reputation)|178368|178368|8|0.0%|0.5%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|7|0.0%|0.4%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|6|0.0%|0.4%|
[et_block](#et_block)|1023|18338662|6|0.0%|0.4%|
[nixspam](#nixspam)|16272|16272|3|0.0%|0.2%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|3|0.2%|0.2%|
[blocklist_de](#blocklist_de)|25717|25717|3|0.0%|0.2%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|2|0.0%|0.1%|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|2|0.0%|0.1%|
[stopforumspam_1d](#stopforumspam_1d)|7042|7042|2|0.0%|0.1%|
[openbl_60d](#openbl_60d)|7651|7651|2|0.0%|0.1%|
[openbl_30d](#openbl_30d)|3251|3251|2|0.0%|0.1%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|2|0.2%|0.1%|
[blocklist_de_strongips](#blocklist_de_strongips)|183|183|2|1.0%|0.1%|
[blocklist_de_bots](#blocklist_de_bots)|3120|3120|2|0.0%|0.1%|
[snort_ipfilter](#snort_ipfilter)|8977|8977|1|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|6565|6565|1|0.0%|0.0%|
[openbl_7d](#openbl_7d)|861|861|1|0.1%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1|0.0%|0.0%|
[et_botcc](#et_botcc)|509|509|1|0.1%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2229|2229|1|0.0%|0.0%|

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
[alienvault_reputation](#alienvault_reputation)|178368|178368|11|0.0%|2.9%|
[et_block](#et_block)|1023|18338662|5|0.0%|1.3%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|4|0.0%|1.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|4|0.3%|1.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|3|0.0%|0.8%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|1|0.0%|0.2%|
[dshield](#dshield)|19|5120|1|0.0%|0.2%|

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
[fullbogons](#fullbogons)|3715|670310296|9|0.0%|0.6%|
[alienvault_reputation](#alienvault_reputation)|178368|178368|6|0.0%|0.4%|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|4|0.0%|0.3%|
[malc0de](#malc0de)|371|371|4|1.0%|0.3%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|3|0.2%|0.2%|
[cleanmx_viruses](#cleanmx_viruses)|168|168|2|1.1%|0.1%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|1|0.0%|0.0%|
[sorbs_spam](#sorbs_spam)|29446|30474|1|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|29446|30474|1|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|29446|30474|1|0.0%|0.0%|
[et_botcc](#et_botcc)|509|509|1|0.1%|0.0%|

## maxmind_proxy_fraud

[MaxMind.com](https://www.maxmind.com/en/anonymous-proxy-fraudulent-ip-address-list) list of anonymous proxy fraudelent IP addresses.

Source is downloaded from [this link](https://www.maxmind.com/en/anonymous-proxy-fraudulent-ip-address-list).

The last time downloaded was found to be dated: Sat Jun  6 06:36:27 UTC 2015.

The ipset `maxmind_proxy_fraud` has **372** entries, **372** unique IPs.

The following table shows the overlaps of `maxmind_proxy_fraud` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `maxmind_proxy_fraud`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `maxmind_proxy_fraud`.
- ` this % ` is the percentage **of this ipset (`maxmind_proxy_fraud`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|231|0.2%|62.0%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|191|0.6%|51.3%|
[snort_ipfilter](#snort_ipfilter)|8977|8977|177|1.9%|47.5%|
[bm_tor](#bm_tor)|6461|6461|169|2.6%|45.4%|
[et_tor](#et_tor)|6470|6470|168|2.5%|45.1%|
[dm_tor](#dm_tor)|6475|6475|168|2.5%|45.1%|
[stopforumspam_1d](#stopforumspam_1d)|7042|7042|161|2.2%|43.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|125|0.0%|33.6%|
[php_commenters](#php_commenters)|326|326|32|9.8%|8.6%|
[alienvault_reputation](#alienvault_reputation)|178368|178368|26|0.0%|6.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|21|0.0%|5.6%|
[openbl_60d](#openbl_60d)|7651|7651|18|0.2%|4.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|17|0.0%|4.5%|
[php_harvesters](#php_harvesters)|311|311|6|1.9%|1.6%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|5|0.0%|1.3%|
[ri_web_proxies](#ri_web_proxies)|6565|6565|4|0.0%|1.0%|
[php_spammers](#php_spammers)|495|495|4|0.8%|1.0%|
[php_dictionary](#php_dictionary)|508|508|4|0.7%|1.0%|
[blocklist_de](#blocklist_de)|25717|25717|3|0.0%|0.8%|
[shunlist](#shunlist)|1248|1248|2|0.1%|0.5%|
[blocklist_de_apache](#blocklist_de_apache)|14812|14812|2|0.0%|0.5%|
[xroxy](#xroxy)|2094|2094|1|0.0%|0.2%|
[voipbl](#voipbl)|10452|10864|1|0.0%|0.2%|
[ri_connect_proxies](#ri_connect_proxies)|2447|2447|1|0.0%|0.2%|
[nixspam](#nixspam)|16272|16272|1|0.0%|0.2%|
[et_block](#et_block)|1023|18338662|1|0.0%|0.2%|
[blocklist_de_ssh](#blocklist_de_ssh)|2229|2229|1|0.0%|0.2%|
[blocklist_de_mail](#blocklist_de_mail)|15653|15653|1|0.0%|0.2%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|3461|3461|1|0.0%|0.2%|

## nixspam

[NiX Spam](http://www.heise.de/ix/NiX-Spam-DNSBL-and-blacklist-for-download-499637.html) IP addresses that sent spam in the last hour - automatically generated entries without distinguishing open proxies from relays, dialup gateways, and so on. All IPs are removed after 12 hours if there is no spam from there.

Source is downloaded from [this link](http://www.dnsbl.manitu.net/download/nixspam-ip.dump.gz).

The last time downloaded was found to be dated: Sat Jun  6 09:00:02 UTC 2015.

The ipset `nixspam` has **16272** entries, **16272** unique IPs.

The following table shows the overlaps of `nixspam` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `nixspam`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `nixspam`.
- ` this % ` is the percentage **of this ipset (`nixspam`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[sorbs_spam](#sorbs_spam)|29446|30474|2379|7.8%|14.6%|
[sorbs_recent_spam](#sorbs_recent_spam)|29446|30474|2379|7.8%|14.6%|
[sorbs_new_spam](#sorbs_new_spam)|29446|30474|2379|7.8%|14.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|1059|0.0%|6.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|440|0.0%|2.7%|
[blocklist_de](#blocklist_de)|25717|25717|343|1.3%|2.1%|
[blocklist_de_mail](#blocklist_de_mail)|15653|15653|285|1.8%|1.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|214|0.0%|1.3%|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|168|0.1%|1.0%|
[et_block](#et_block)|1023|18338662|103|0.0%|0.6%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|102|0.0%|0.6%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|100|0.0%|0.6%|
[sorbs_web](#sorbs_web)|645|646|99|15.3%|0.6%|
[snort_ipfilter](#snort_ipfilter)|8977|8977|96|1.0%|0.5%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|88|0.2%|0.5%|
[ri_web_proxies](#ri_web_proxies)|6565|6565|58|0.8%|0.3%|
[php_dictionary](#php_dictionary)|508|508|52|10.2%|0.3%|
[php_spammers](#php_spammers)|495|495|45|9.0%|0.2%|
[stopforumspam_1d](#stopforumspam_1d)|7042|7042|41|0.5%|0.2%|
[xroxy](#xroxy)|2094|2094|40|1.9%|0.2%|
[alienvault_reputation](#alienvault_reputation)|178368|178368|30|0.0%|0.1%|
[blocklist_de_bots](#blocklist_de_bots)|3120|3120|25|0.8%|0.1%|
[proxz](#proxz)|862|862|21|2.4%|0.1%|
[blocklist_de_apache](#blocklist_de_apache)|14812|14812|20|0.1%|0.1%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|3461|3461|19|0.5%|0.1%|
[ri_connect_proxies](#ri_connect_proxies)|2447|2447|15|0.6%|0.0%|
[proxyrss](#proxyrss)|1688|1688|15|0.8%|0.0%|
[openbl_60d](#openbl_60d)|7651|7651|13|0.1%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|1810|1810|12|0.6%|0.0%|
[php_commenters](#php_commenters)|326|326|10|3.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|9|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|901|901|9|0.9%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|8|0.0%|0.0%|
[php_harvesters](#php_harvesters)|311|311|5|1.6%|0.0%|
[openbl_30d](#openbl_30d)|3251|3251|5|0.1%|0.0%|
[openbl_7d](#openbl_7d)|861|861|3|0.3%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|3|0.2%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2229|2229|3|0.1%|0.0%|
[voipbl](#voipbl)|10452|10864|2|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|1|0.0%|0.0%|
[sorbs_socks](#sorbs_socks)|19|19|1|5.2%|0.0%|
[sorbs_misc](#sorbs_misc)|19|19|1|5.2%|0.0%|
[sorbs_http](#sorbs_http)|19|19|1|5.2%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[et_compromised](#et_compromised)|2016|2016|1|0.0%|0.0%|
[dshield](#dshield)|19|5120|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1892|1892|1|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|183|183|1|0.5%|0.0%|

## openbl_1d

[OpenBL.org](http://www.openbl.org/) last 24 hours IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.

Source is downloaded from [this link](http://www.openbl.org/lists/base_1days.txt).

The last time downloaded was found to be dated: Sat Jun  6 08:32:00 UTC 2015.

The ipset `openbl_1d` has **146** entries, **146** unique IPs.

The following table shows the overlaps of `openbl_1d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl_1d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl_1d`.
- ` this % ` is the percentage **of this ipset (`openbl_1d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[openbl_60d](#openbl_60d)|7651|7651|143|1.8%|97.9%|
[openbl_30d](#openbl_30d)|3251|3251|143|4.3%|97.9%|
[openbl_7d](#openbl_7d)|861|861|142|16.4%|97.2%|
[alienvault_reputation](#alienvault_reputation)|178368|178368|138|0.0%|94.5%|
[blocklist_de](#blocklist_de)|25717|25717|124|0.4%|84.9%|
[blocklist_de_ssh](#blocklist_de_ssh)|2229|2229|123|5.5%|84.2%|
[bruteforceblocker](#bruteforceblocker)|1892|1892|84|4.4%|57.5%|
[et_compromised](#et_compromised)|2016|2016|82|4.0%|56.1%|
[shunlist](#shunlist)|1248|1248|72|5.7%|49.3%|
[blocklist_de_strongips](#blocklist_de_strongips)|183|183|20|10.9%|13.6%|
[et_block](#et_block)|1023|18338662|13|0.0%|8.9%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|12|0.0%|8.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|12|0.0%|8.2%|
[dshield](#dshield)|19|5120|8|0.1%|5.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|4|0.0%|2.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|3|0.0%|2.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.6%|
[blocklist_de_mail](#blocklist_de_mail)|15653|15653|1|0.0%|0.6%|
[blocklist_de_imap](#blocklist_de_imap)|1810|1810|1|0.0%|0.6%|

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
[alienvault_reputation](#alienvault_reputation)|178368|178368|3232|1.8%|99.4%|
[et_compromised](#et_compromised)|2016|2016|1151|57.0%|35.4%|
[bruteforceblocker](#bruteforceblocker)|1892|1892|1081|57.1%|33.2%|
[openbl_7d](#openbl_7d)|861|861|861|100.0%|26.4%|
[blocklist_de](#blocklist_de)|25717|25717|712|2.7%|21.9%|
[blocklist_de_ssh](#blocklist_de_ssh)|2229|2229|664|29.7%|20.4%|
[shunlist](#shunlist)|1248|1248|551|44.1%|16.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|312|0.0%|9.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|168|0.0%|5.1%|
[et_block](#et_block)|1023|18338662|166|0.0%|5.1%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|160|0.0%|4.9%|
[openbl_1d](#openbl_1d)|146|146|143|97.9%|4.3%|
[dshield](#dshield)|19|5120|92|1.7%|2.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|71|0.0%|2.1%|
[blocklist_de_mail](#blocklist_de_mail)|15653|15653|39|0.2%|1.1%|
[blocklist_de_imap](#blocklist_de_imap)|1810|1810|32|1.7%|0.9%|
[blocklist_de_strongips](#blocklist_de_strongips)|183|183|25|13.6%|0.7%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|13|0.0%|0.3%|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|5|0.0%|0.1%|
[nixspam](#nixspam)|16272|16272|5|0.0%|0.1%|
[blocklist_de_apache](#blocklist_de_apache)|14812|14812|5|0.0%|0.1%|
[snort_ipfilter](#snort_ipfilter)|8977|8977|4|0.0%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|4|0.0%|0.1%|
[voipbl](#voipbl)|10452|10864|3|0.0%|0.0%|
[sorbs_spam](#sorbs_spam)|29446|30474|3|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|29446|30474|3|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|29446|30474|3|0.0%|0.0%|
[zeus](#zeus)|230|230|2|0.8%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|2|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7042|7042|2|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3120|3120|2|0.0%|0.0%|
[zeus_badips](#zeus_badips)|202|202|1|0.4%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|1|0.0%|0.0%|
[sorbs_web](#sorbs_web)|645|646|1|0.1%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|901|901|1|0.1%|0.0%|

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
[alienvault_reputation](#alienvault_reputation)|178368|178368|7627|4.2%|99.6%|
[openbl_30d](#openbl_30d)|3251|3251|3251|100.0%|42.4%|
[et_compromised](#et_compromised)|2016|2016|1216|60.3%|15.8%|
[bruteforceblocker](#bruteforceblocker)|1892|1892|1130|59.7%|14.7%|
[blocklist_de](#blocklist_de)|25717|25717|880|3.4%|11.5%|
[openbl_7d](#openbl_7d)|861|861|861|100.0%|11.2%|
[blocklist_de_ssh](#blocklist_de_ssh)|2229|2229|815|36.5%|10.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|745|0.0%|9.7%|
[shunlist](#shunlist)|1248|1248|566|45.3%|7.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|332|0.0%|4.3%|
[et_block](#et_block)|1023|18338662|250|0.0%|3.2%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|239|0.0%|3.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|171|0.0%|2.2%|
[openbl_1d](#openbl_1d)|146|146|143|97.9%|1.8%|
[dshield](#dshield)|19|5120|112|2.1%|1.4%|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|57|0.0%|0.7%|
[blocklist_de_mail](#blocklist_de_mail)|15653|15653|45|0.2%|0.5%|
[blocklist_de_imap](#blocklist_de_imap)|1810|1810|38|2.0%|0.4%|
[snort_ipfilter](#snort_ipfilter)|8977|8977|27|0.3%|0.3%|
[blocklist_de_strongips](#blocklist_de_strongips)|183|183|27|14.7%|0.3%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|26|0.0%|0.3%|
[stopforumspam_1d](#stopforumspam_1d)|7042|7042|21|0.2%|0.2%|
[et_tor](#et_tor)|6470|6470|20|0.3%|0.2%|
[dm_tor](#dm_tor)|6475|6475|20|0.3%|0.2%|
[bm_tor](#bm_tor)|6461|6461|20|0.3%|0.2%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|18|4.8%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|17|0.0%|0.2%|
[sorbs_spam](#sorbs_spam)|29446|30474|15|0.0%|0.1%|
[sorbs_recent_spam](#sorbs_recent_spam)|29446|30474|15|0.0%|0.1%|
[sorbs_new_spam](#sorbs_new_spam)|29446|30474|15|0.0%|0.1%|
[nixspam](#nixspam)|16272|16272|13|0.0%|0.1%|
[blocklist_de_bots](#blocklist_de_bots)|3120|3120|10|0.3%|0.1%|
[php_commenters](#php_commenters)|326|326|9|2.7%|0.1%|
[voipbl](#voipbl)|10452|10864|8|0.0%|0.1%|
[blocklist_de_apache](#blocklist_de_apache)|14812|14812|7|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|5|0.0%|0.0%|
[zeus](#zeus)|230|230|2|0.8%|0.0%|
[php_harvesters](#php_harvesters)|311|311|2|0.6%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|901|901|2|0.2%|0.0%|
[zeus_badips](#zeus_badips)|202|202|1|0.4%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|1|0.0%|0.0%|
[sorbs_web](#sorbs_web)|645|646|1|0.1%|0.0%|

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
[alienvault_reputation](#alienvault_reputation)|178368|178368|852|0.4%|98.9%|
[blocklist_de](#blocklist_de)|25717|25717|447|1.7%|51.9%|
[blocklist_de_ssh](#blocklist_de_ssh)|2229|2229|431|19.3%|50.0%|
[et_compromised](#et_compromised)|2016|2016|386|19.1%|44.8%|
[bruteforceblocker](#bruteforceblocker)|1892|1892|382|20.1%|44.3%|
[shunlist](#shunlist)|1248|1248|248|19.8%|28.8%|
[openbl_1d](#openbl_1d)|146|146|142|97.2%|16.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|115|0.0%|13.3%|
[et_block](#et_block)|1023|18338662|51|0.0%|5.9%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|48|0.0%|5.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|43|0.0%|4.9%|
[dshield](#dshield)|19|5120|36|0.7%|4.1%|
[blocklist_de_strongips](#blocklist_de_strongips)|183|183|24|13.1%|2.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|19|0.0%|2.2%|
[blocklist_de_mail](#blocklist_de_mail)|15653|15653|13|0.0%|1.5%|
[blocklist_de_imap](#blocklist_de_imap)|1810|1810|11|0.6%|1.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|5|0.0%|0.5%|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|3|0.0%|0.3%|
[nixspam](#nixspam)|16272|16272|3|0.0%|0.3%|
[snort_ipfilter](#snort_ipfilter)|8977|8977|2|0.0%|0.2%|
[blocklist_de_apache](#blocklist_de_apache)|14812|14812|2|0.0%|0.2%|
[voipbl](#voipbl)|10452|10864|1|0.0%|0.1%|
[sorbs_spam](#sorbs_spam)|29446|30474|1|0.0%|0.1%|
[sorbs_recent_spam](#sorbs_recent_spam)|29446|30474|1|0.0%|0.1%|
[sorbs_new_spam](#sorbs_new_spam)|29446|30474|1|0.0%|0.1%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.1%|

## palevo

[Abuse.ch Palevo tracker](https://palevotracker.abuse.ch) worm includes IPs which are being used as botnet C&C for the Palevo crimeware - **excellent list**

Source is downloaded from [this link](https://palevotracker.abuse.ch/blocklists.php?download=ipblocklist).

The last time downloaded was found to be dated: Sat Jun  6 08:45:12 UTC 2015.

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

The last time downloaded was found to be dated: Sat Jun  6 09:00:05 UTC 2015.

The ipset `php_commenters` has **326** entries, **326** unique IPs.

The following table shows the overlaps of `php_commenters` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `php_commenters`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `php_commenters`.
- ` this % ` is the percentage **of this ipset (`php_commenters`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|238|0.2%|73.0%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|171|0.5%|52.4%|
[stopforumspam_1d](#stopforumspam_1d)|7042|7042|128|1.8%|39.2%|
[blocklist_de](#blocklist_de)|25717|25717|80|0.3%|24.5%|
[blocklist_de_bots](#blocklist_de_bots)|3120|3120|65|2.0%|19.9%|
[snort_ipfilter](#snort_ipfilter)|8977|8977|44|0.4%|13.4%|
[php_spammers](#php_spammers)|495|495|36|7.2%|11.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|183|183|36|19.6%|11.0%|
[et_tor](#et_tor)|6470|6470|35|0.5%|10.7%|
[dm_tor](#dm_tor)|6475|6475|34|0.5%|10.4%|
[bm_tor](#bm_tor)|6461|6461|34|0.5%|10.4%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|32|8.6%|9.8%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|28|0.0%|8.5%|
[et_block](#et_block)|1023|18338662|28|0.0%|8.5%|
[blocklist_de_apache](#blocklist_de_apache)|14812|14812|25|0.1%|7.6%|
[php_dictionary](#php_dictionary)|508|508|24|4.7%|7.3%|
[blocklist_de_mail](#blocklist_de_mail)|15653|15653|21|0.1%|6.4%|
[ri_web_proxies](#ri_web_proxies)|6565|6565|19|0.2%|5.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|18|0.0%|5.5%|
[sorbs_spam](#sorbs_spam)|29446|30474|15|0.0%|4.6%|
[sorbs_recent_spam](#sorbs_recent_spam)|29446|30474|15|0.0%|4.6%|
[sorbs_new_spam](#sorbs_new_spam)|29446|30474|15|0.0%|4.6%|
[alienvault_reputation](#alienvault_reputation)|178368|178368|15|0.0%|4.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|13|0.0%|3.9%|
[php_harvesters](#php_harvesters)|311|311|11|3.5%|3.3%|
[nixspam](#nixspam)|16272|16272|10|0.0%|3.0%|
[openbl_60d](#openbl_60d)|7651|7651|9|0.1%|2.7%|
[xroxy](#xroxy)|2094|2094|7|0.3%|2.1%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|7|0.0%|2.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|7|0.0%|2.1%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|3461|3461|7|0.2%|2.1%|
[ri_connect_proxies](#ri_connect_proxies)|2447|2447|4|0.1%|1.2%|
[proxz](#proxz)|862|862|4|0.4%|1.2%|
[sorbs_web](#sorbs_web)|645|646|3|0.4%|0.9%|
[proxyrss](#proxyrss)|1688|1688|3|0.1%|0.9%|
[zeus_badips](#zeus_badips)|202|202|1|0.4%|0.3%|
[zeus](#zeus)|230|230|1|0.4%|0.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.3%|

## php_dictionary

[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) directory attackers (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=d&rss=1).

The last time downloaded was found to be dated: Sat Jun  6 08:09:29 UTC 2015.

The ipset `php_dictionary` has **508** entries, **508** unique IPs.

The following table shows the overlaps of `php_dictionary` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `php_dictionary`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `php_dictionary`.
- ` this % ` is the percentage **of this ipset (`php_dictionary`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[php_spammers](#php_spammers)|495|495|150|30.3%|29.5%|
[sorbs_spam](#sorbs_spam)|29446|30474|135|0.4%|26.5%|
[sorbs_recent_spam](#sorbs_recent_spam)|29446|30474|135|0.4%|26.5%|
[sorbs_new_spam](#sorbs_new_spam)|29446|30474|135|0.4%|26.5%|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|101|0.1%|19.8%|
[blocklist_de](#blocklist_de)|25717|25717|83|0.3%|16.3%|
[snort_ipfilter](#snort_ipfilter)|8977|8977|73|0.8%|14.3%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|65|0.2%|12.7%|
[blocklist_de_mail](#blocklist_de_mail)|15653|15653|63|0.4%|12.4%|
[nixspam](#nixspam)|16272|16272|52|0.3%|10.2%|
[ri_web_proxies](#ri_web_proxies)|6565|6565|41|0.6%|8.0%|
[xroxy](#xroxy)|2094|2094|31|1.4%|6.1%|
[stopforumspam_1d](#stopforumspam_1d)|7042|7042|31|0.4%|6.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|29|0.0%|5.7%|
[sorbs_web](#sorbs_web)|645|646|27|4.1%|5.3%|
[php_commenters](#php_commenters)|326|326|24|7.3%|4.7%|
[blocklist_de_bots](#blocklist_de_bots)|3120|3120|15|0.4%|2.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|13|0.0%|2.5%|
[proxz](#proxz)|862|862|12|1.3%|2.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|11|0.0%|2.1%|
[alienvault_reputation](#alienvault_reputation)|178368|178368|8|0.0%|1.5%|
[et_tor](#et_tor)|6470|6470|5|0.0%|0.9%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|4|0.0%|0.7%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|4|1.0%|0.7%|
[et_block](#et_block)|1023|18338662|4|0.0%|0.7%|
[dm_tor](#dm_tor)|6475|6475|4|0.0%|0.7%|
[bm_tor](#bm_tor)|6461|6461|4|0.0%|0.7%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|3461|3461|4|0.1%|0.7%|
[blocklist_de_apache](#blocklist_de_apache)|14812|14812|4|0.0%|0.7%|
[ri_connect_proxies](#ri_connect_proxies)|2447|2447|3|0.1%|0.5%|
[blocklist_de_strongips](#blocklist_de_strongips)|183|183|3|1.6%|0.5%|
[proxyrss](#proxyrss)|1688|1688|2|0.1%|0.3%|
[php_harvesters](#php_harvesters)|311|311|2|0.6%|0.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2|0.0%|0.3%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|2|0.0%|0.3%|
[sorbs_socks](#sorbs_socks)|19|19|1|5.2%|0.1%|
[sorbs_misc](#sorbs_misc)|19|19|1|5.2%|0.1%|
[sorbs_http](#sorbs_http)|19|19|1|5.2%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.1%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|1|0.1%|0.1%|
[blocklist_de_ftp](#blocklist_de_ftp)|901|901|1|0.1%|0.1%|

## php_harvesters

[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) harvesters (IPs that surf the internet looking for email addresses) (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=h&rss=1).

The last time downloaded was found to be dated: Sat Jun  6 09:00:03 UTC 2015.

The ipset `php_harvesters` has **311** entries, **311** unique IPs.

The following table shows the overlaps of `php_harvesters` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `php_harvesters`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `php_harvesters`.
- ` this % ` is the percentage **of this ipset (`php_harvesters`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|68|0.0%|21.8%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|51|0.1%|16.3%|
[stopforumspam_1d](#stopforumspam_1d)|7042|7042|39|0.5%|12.5%|
[blocklist_de](#blocklist_de)|25717|25717|30|0.1%|9.6%|
[blocklist_de_bots](#blocklist_de_bots)|3120|3120|23|0.7%|7.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|17|0.0%|5.4%|
[snort_ipfilter](#snort_ipfilter)|8977|8977|11|0.1%|3.5%|
[php_commenters](#php_commenters)|326|326|11|3.3%|3.5%|
[alienvault_reputation](#alienvault_reputation)|178368|178368|10|0.0%|3.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|9|0.0%|2.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|9|0.0%|2.8%|
[sorbs_spam](#sorbs_spam)|29446|30474|7|0.0%|2.2%|
[sorbs_recent_spam](#sorbs_recent_spam)|29446|30474|7|0.0%|2.2%|
[sorbs_new_spam](#sorbs_new_spam)|29446|30474|7|0.0%|2.2%|
[et_tor](#et_tor)|6470|6470|7|0.1%|2.2%|
[dm_tor](#dm_tor)|6475|6475|7|0.1%|2.2%|
[bm_tor](#bm_tor)|6461|6461|7|0.1%|2.2%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|6|1.6%|1.9%|
[nixspam](#nixspam)|16272|16272|5|0.0%|1.6%|
[blocklist_de_apache](#blocklist_de_apache)|14812|14812|5|0.0%|1.6%|
[proxyrss](#proxyrss)|1688|1688|3|0.1%|0.9%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|3461|3461|3|0.0%|0.9%|
[xroxy](#xroxy)|2094|2094|2|0.0%|0.6%|
[php_spammers](#php_spammers)|495|495|2|0.4%|0.6%|
[php_dictionary](#php_dictionary)|508|508|2|0.3%|0.6%|
[openbl_60d](#openbl_60d)|7651|7651|2|0.0%|0.6%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|2|0.0%|0.6%|
[blocklist_de_strongips](#blocklist_de_strongips)|183|183|2|1.0%|0.6%|
[blocklist_de_ftp](#blocklist_de_ftp)|901|901|2|0.2%|0.6%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|1|0.0%|0.3%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|1|0.0%|0.3%|
[ri_web_proxies](#ri_web_proxies)|6565|6565|1|0.0%|0.3%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.3%|
[fullbogons](#fullbogons)|3715|670310296|1|0.0%|0.3%|
[et_block](#et_block)|1023|18338662|1|0.0%|0.3%|
[bogons](#bogons)|13|592708608|1|0.0%|0.3%|
[blocklist_de_mail](#blocklist_de_mail)|15653|15653|1|0.0%|0.3%|

## php_spammers

[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) spam servers (IPs used by spammers to send messages) (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=s&rss=1).

The last time downloaded was found to be dated: Sat Jun  6 09:00:04 UTC 2015.

The ipset `php_spammers` has **495** entries, **495** unique IPs.

The following table shows the overlaps of `php_spammers` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `php_spammers`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `php_spammers`.
- ` this % ` is the percentage **of this ipset (`php_spammers`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[php_dictionary](#php_dictionary)|508|508|150|29.5%|30.3%|
[sorbs_spam](#sorbs_spam)|29446|30474|118|0.3%|23.8%|
[sorbs_recent_spam](#sorbs_recent_spam)|29446|30474|118|0.3%|23.8%|
[sorbs_new_spam](#sorbs_new_spam)|29446|30474|118|0.3%|23.8%|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|114|0.1%|23.0%|
[blocklist_de](#blocklist_de)|25717|25717|85|0.3%|17.1%|
[snort_ipfilter](#snort_ipfilter)|8977|8977|70|0.7%|14.1%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|64|0.2%|12.9%|
[blocklist_de_mail](#blocklist_de_mail)|15653|15653|58|0.3%|11.7%|
[nixspam](#nixspam)|16272|16272|45|0.2%|9.0%|
[php_commenters](#php_commenters)|326|326|36|11.0%|7.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|36|0.0%|7.2%|
[ri_web_proxies](#ri_web_proxies)|6565|6565|35|0.5%|7.0%|
[stopforumspam_1d](#stopforumspam_1d)|7042|7042|33|0.4%|6.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|28|0.0%|5.6%|
[sorbs_web](#sorbs_web)|645|646|26|4.0%|5.2%|
[xroxy](#xroxy)|2094|2094|25|1.1%|5.0%|
[blocklist_de_bots](#blocklist_de_bots)|3120|3120|20|0.6%|4.0%|
[proxz](#proxz)|862|862|14|1.6%|2.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|7|0.0%|1.4%|
[et_tor](#et_tor)|6470|6470|6|0.0%|1.2%|
[dm_tor](#dm_tor)|6475|6475|5|0.0%|1.0%|
[bm_tor](#bm_tor)|6461|6461|5|0.0%|1.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|183|183|5|2.7%|1.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|3461|3461|5|0.1%|1.0%|
[blocklist_de_apache](#blocklist_de_apache)|14812|14812|5|0.0%|1.0%|
[alienvault_reputation](#alienvault_reputation)|178368|178368|5|0.0%|1.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|4|1.0%|0.8%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|3|0.0%|0.6%|
[ri_connect_proxies](#ri_connect_proxies)|2447|2447|3|0.1%|0.6%|
[proxyrss](#proxyrss)|1688|1688|2|0.1%|0.4%|
[php_harvesters](#php_harvesters)|311|311|2|0.6%|0.4%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2|0.0%|0.4%|
[et_block](#et_block)|1023|18338662|2|0.0%|0.4%|
[blocklist_de_ftp](#blocklist_de_ftp)|901|901|2|0.2%|0.4%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1|0.0%|0.2%|

## proxyrss

[proxyrss.com](http://www.proxyrss.com) open proxies syndicated from multiple sources.

Source is downloaded from [this link](http://www.proxyrss.com/proxylists/all.gz).

The last time downloaded was found to be dated: Sat Jun  6 05:11:28 UTC 2015.

The ipset `proxyrss` has **1688** entries, **1688** unique IPs.

The following table shows the overlaps of `proxyrss` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `proxyrss`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `proxyrss`.
- ` this % ` is the percentage **of this ipset (`proxyrss`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|842|0.9%|49.8%|
[ri_web_proxies](#ri_web_proxies)|6565|6565|673|10.2%|39.8%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|662|2.1%|39.2%|
[xroxy](#xroxy)|2094|2094|437|20.8%|25.8%|
[stopforumspam_1d](#stopforumspam_1d)|7042|7042|416|5.9%|24.6%|
[ri_connect_proxies](#ri_connect_proxies)|2447|2447|255|10.4%|15.1%|
[proxz](#proxz)|862|862|252|29.2%|14.9%|
[blocklist_de_bots](#blocklist_de_bots)|3120|3120|227|7.2%|13.4%|
[blocklist_de](#blocklist_de)|25717|25717|227|0.8%|13.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|71|0.0%|4.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|57|0.0%|3.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|41|0.0%|2.4%|
[nixspam](#nixspam)|16272|16272|15|0.0%|0.8%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|10|1.4%|0.5%|
[sorbs_spam](#sorbs_spam)|29446|30474|9|0.0%|0.5%|
[sorbs_recent_spam](#sorbs_recent_spam)|29446|30474|9|0.0%|0.5%|
[sorbs_new_spam](#sorbs_new_spam)|29446|30474|9|0.0%|0.5%|
[blocklist_de_strongips](#blocklist_de_strongips)|183|183|7|3.8%|0.4%|
[snort_ipfilter](#snort_ipfilter)|8977|8977|4|0.0%|0.2%|
[php_harvesters](#php_harvesters)|311|311|3|0.9%|0.1%|
[php_commenters](#php_commenters)|326|326|3|0.9%|0.1%|
[php_spammers](#php_spammers)|495|495|2|0.4%|0.1%|
[php_dictionary](#php_dictionary)|508|508|2|0.3%|0.1%|
[sorbs_web](#sorbs_web)|645|646|1|0.1%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1|0.0%|0.0%|
[alienvault_reputation](#alienvault_reputation)|178368|178368|1|0.0%|0.0%|

## proxz

[proxz.com](http://www.proxz.com) open proxies (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.proxz.com/proxylists.xml).

The last time downloaded was found to be dated: Sat Jun  6 08:01:27 UTC 2015.

The ipset `proxz` has **862** entries, **862** unique IPs.

The following table shows the overlaps of `proxz` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `proxz`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `proxz`.
- ` this % ` is the percentage **of this ipset (`proxz`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|522|0.5%|60.5%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|411|1.3%|47.6%|
[ri_web_proxies](#ri_web_proxies)|6565|6565|397|6.0%|46.0%|
[xroxy](#xroxy)|2094|2094|340|16.2%|39.4%|
[proxyrss](#proxyrss)|1688|1688|252|14.9%|29.2%|
[stopforumspam_1d](#stopforumspam_1d)|7042|7042|162|2.3%|18.7%|
[blocklist_de](#blocklist_de)|25717|25717|145|0.5%|16.8%|
[ri_connect_proxies](#ri_connect_proxies)|2447|2447|141|5.7%|16.3%|
[blocklist_de_bots](#blocklist_de_bots)|3120|3120|123|3.9%|14.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|71|0.0%|8.2%|
[sorbs_spam](#sorbs_spam)|29446|30474|40|0.1%|4.6%|
[sorbs_recent_spam](#sorbs_recent_spam)|29446|30474|40|0.1%|4.6%|
[sorbs_new_spam](#sorbs_new_spam)|29446|30474|40|0.1%|4.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|34|0.0%|3.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|31|0.0%|3.5%|
[snort_ipfilter](#snort_ipfilter)|8977|8977|21|0.2%|2.4%|
[nixspam](#nixspam)|16272|16272|21|0.1%|2.4%|
[blocklist_de_mail](#blocklist_de_mail)|15653|15653|21|0.1%|2.4%|
[php_spammers](#php_spammers)|495|495|14|2.8%|1.6%|
[php_dictionary](#php_dictionary)|508|508|12|2.3%|1.3%|
[sorbs_web](#sorbs_web)|645|646|10|1.5%|1.1%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|6|0.8%|0.6%|
[php_commenters](#php_commenters)|326|326|4|1.2%|0.4%|
[blocklist_de_strongips](#blocklist_de_strongips)|183|183|4|2.1%|0.4%|
[alienvault_reputation](#alienvault_reputation)|178368|178368|3|0.0%|0.3%|
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
[xroxy](#xroxy)|2094|2094|365|17.4%|14.9%|
[proxyrss](#proxyrss)|1688|1688|255|15.1%|10.4%|
[stopforumspam_1d](#stopforumspam_1d)|7042|7042|142|2.0%|5.8%|
[proxz](#proxz)|862|862|141|16.3%|5.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|96|0.0%|3.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|76|0.0%|3.1%|
[blocklist_de](#blocklist_de)|25717|25717|68|0.2%|2.7%|
[blocklist_de_bots](#blocklist_de_bots)|3120|3120|65|2.0%|2.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|53|0.0%|2.1%|
[nixspam](#nixspam)|16272|16272|15|0.0%|0.6%|
[sorbs_spam](#sorbs_spam)|29446|30474|11|0.0%|0.4%|
[sorbs_recent_spam](#sorbs_recent_spam)|29446|30474|11|0.0%|0.4%|
[sorbs_new_spam](#sorbs_new_spam)|29446|30474|11|0.0%|0.4%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|6|0.8%|0.2%|
[php_commenters](#php_commenters)|326|326|4|1.2%|0.1%|
[snort_ipfilter](#snort_ipfilter)|8977|8977|3|0.0%|0.1%|
[php_spammers](#php_spammers)|495|495|3|0.6%|0.1%|
[php_dictionary](#php_dictionary)|508|508|3|0.5%|0.1%|
[blocklist_de_mail](#blocklist_de_mail)|15653|15653|3|0.0%|0.1%|
[alienvault_reputation](#alienvault_reputation)|178368|178368|3|0.0%|0.1%|
[sorbs_web](#sorbs_web)|645|646|1|0.1%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.0%|
[et_tor](#et_tor)|6470|6470|1|0.0%|0.0%|
[dm_tor](#dm_tor)|6475|6475|1|0.0%|0.0%|
[bm_tor](#bm_tor)|6461|6461|1|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|1810|1810|1|0.0%|0.0%|

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
[xroxy](#xroxy)|2094|2094|897|42.8%|13.6%|
[proxyrss](#proxyrss)|1688|1688|673|39.8%|10.2%|
[stopforumspam_1d](#stopforumspam_1d)|7042|7042|486|6.9%|7.4%|
[proxz](#proxz)|862|862|397|46.0%|6.0%|
[blocklist_de](#blocklist_de)|25717|25717|395|1.5%|6.0%|
[blocklist_de_bots](#blocklist_de_bots)|3120|3120|336|10.7%|5.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|191|0.0%|2.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|190|0.0%|2.8%|
[sorbs_spam](#sorbs_spam)|29446|30474|138|0.4%|2.1%|
[sorbs_recent_spam](#sorbs_recent_spam)|29446|30474|138|0.4%|2.1%|
[sorbs_new_spam](#sorbs_new_spam)|29446|30474|138|0.4%|2.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|135|0.0%|2.0%|
[snort_ipfilter](#snort_ipfilter)|8977|8977|63|0.7%|0.9%|
[nixspam](#nixspam)|16272|16272|58|0.3%|0.8%|
[blocklist_de_mail](#blocklist_de_mail)|15653|15653|57|0.3%|0.8%|
[php_dictionary](#php_dictionary)|508|508|41|8.0%|0.6%|
[php_spammers](#php_spammers)|495|495|35|7.0%|0.5%|
[sorbs_web](#sorbs_web)|645|646|24|3.7%|0.3%|
[php_commenters](#php_commenters)|326|326|19|5.8%|0.2%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|12|1.7%|0.1%|
[blocklist_de_strongips](#blocklist_de_strongips)|183|183|6|3.2%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|5|0.0%|0.0%|
[et_tor](#et_tor)|6470|6470|5|0.0%|0.0%|
[dm_tor](#dm_tor)|6475|6475|5|0.0%|0.0%|
[bm_tor](#bm_tor)|6461|6461|5|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|4|1.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|3|0.0%|0.0%|
[alienvault_reputation](#alienvault_reputation)|178368|178368|3|0.0%|0.0%|
[sslbl](#sslbl)|369|369|1|0.2%|0.0%|
[php_harvesters](#php_harvesters)|311|311|1|0.3%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|
[et_compromised](#et_compromised)|2016|2016|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1892|1892|1|0.0%|0.0%|

## shunlist

[AutoShun.org](http://autoshun.org/) IPs identified as hostile by correlating logs from distributed snort installations running the autoshun plugin

Source is downloaded from [this link](http://www.autoshun.org/files/shunlist.csv).

The last time downloaded was found to be dated: Sat Jun  6 06:30:05 UTC 2015.

The ipset `shunlist` has **1248** entries, **1248** unique IPs.

The following table shows the overlaps of `shunlist` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `shunlist`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `shunlist`.
- ` this % ` is the percentage **of this ipset (`shunlist`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[alienvault_reputation](#alienvault_reputation)|178368|178368|1241|0.6%|99.4%|
[openbl_60d](#openbl_60d)|7651|7651|566|7.3%|45.3%|
[openbl_30d](#openbl_30d)|3251|3251|551|16.9%|44.1%|
[et_compromised](#et_compromised)|2016|2016|459|22.7%|36.7%|
[bruteforceblocker](#bruteforceblocker)|1892|1892|449|23.7%|35.9%|
[blocklist_de](#blocklist_de)|25717|25717|366|1.4%|29.3%|
[blocklist_de_ssh](#blocklist_de_ssh)|2229|2229|331|14.8%|26.5%|
[openbl_7d](#openbl_7d)|861|861|248|28.8%|19.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|112|0.0%|8.9%|
[et_block](#et_block)|1023|18338662|111|0.0%|8.8%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|97|0.0%|7.7%|
[openbl_1d](#openbl_1d)|146|146|72|49.3%|5.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|72|0.0%|5.7%|
[dshield](#dshield)|19|5120|58|1.1%|4.6%|
[sslbl](#sslbl)|369|369|57|15.4%|4.5%|
[blocklist_de_apache](#blocklist_de_apache)|14812|14812|34|0.2%|2.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|28|0.0%|2.2%|
[ciarmy](#ciarmy)|395|395|25|6.3%|2.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|183|183|20|10.9%|1.6%|
[voipbl](#voipbl)|10452|10864|12|0.1%|0.9%|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|4|0.0%|0.3%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|2|0.0%|0.1%|
[snort_ipfilter](#snort_ipfilter)|8977|8977|2|0.0%|0.1%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|2|0.5%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2|0.0%|0.1%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|3461|3461|2|0.0%|0.1%|
[stopforumspam_1d](#stopforumspam_1d)|7042|7042|1|0.0%|0.0%|
[sorbs_spam](#sorbs_spam)|29446|30474|1|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|29446|30474|1|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|29446|30474|1|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.0%|
[et_tor](#et_tor)|6470|6470|1|0.0%|0.0%|
[dm_tor](#dm_tor)|6475|6475|1|0.0%|0.0%|
[bm_tor](#bm_tor)|6461|6461|1|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|15653|15653|1|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|1810|1810|1|0.0%|0.0%|

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
[bm_tor](#bm_tor)|6461|6461|1062|16.4%|11.8%|
[dm_tor](#dm_tor)|6475|6475|1058|16.3%|11.7%|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|804|0.8%|8.9%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|632|2.0%|7.0%|
[stopforumspam_1d](#stopforumspam_1d)|7042|7042|380|5.3%|4.2%|
[et_block](#et_block)|1023|18338662|317|0.0%|3.5%|
[sorbs_spam](#sorbs_spam)|29446|30474|308|1.0%|3.4%|
[sorbs_recent_spam](#sorbs_recent_spam)|29446|30474|308|1.0%|3.4%|
[sorbs_new_spam](#sorbs_new_spam)|29446|30474|308|1.0%|3.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|231|0.0%|2.5%|
[zeus](#zeus)|230|230|201|87.3%|2.2%|
[zeus_badips](#zeus_badips)|202|202|179|88.6%|1.9%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|177|47.5%|1.9%|
[blocklist_de](#blocklist_de)|25717|25717|170|0.6%|1.8%|
[blocklist_de_mail](#blocklist_de_mail)|15653|15653|143|0.9%|1.5%|
[alienvault_reputation](#alienvault_reputation)|178368|178368|119|0.0%|1.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|100|0.0%|1.1%|
[nixspam](#nixspam)|16272|16272|96|0.5%|1.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|83|0.0%|0.9%|
[feodo](#feodo)|99|99|76|76.7%|0.8%|
[php_dictionary](#php_dictionary)|508|508|73|14.3%|0.8%|
[php_spammers](#php_spammers)|495|495|70|14.1%|0.7%|
[ri_web_proxies](#ri_web_proxies)|6565|6565|63|0.9%|0.7%|
[sorbs_web](#sorbs_web)|645|646|48|7.4%|0.5%|
[xroxy](#xroxy)|2094|2094|46|2.1%|0.5%|
[php_commenters](#php_commenters)|326|326|44|13.4%|0.4%|
[sslbl](#sslbl)|369|369|31|8.4%|0.3%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|28|2.1%|0.3%|
[openbl_60d](#openbl_60d)|7651|7651|27|0.3%|0.3%|
[proxz](#proxz)|862|862|21|2.4%|0.2%|
[blocklist_de_bots](#blocklist_de_bots)|3120|3120|21|0.6%|0.2%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|20|0.0%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|14|0.0%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|12|0.0%|0.1%|
[php_harvesters](#php_harvesters)|311|311|11|3.5%|0.1%|
[palevo](#palevo)|13|13|11|84.6%|0.1%|
[blocklist_de_apache](#blocklist_de_apache)|14812|14812|9|0.0%|0.1%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|6|0.0%|0.0%|
[sorbs_socks](#sorbs_socks)|19|19|6|31.5%|0.0%|
[sorbs_misc](#sorbs_misc)|19|19|6|31.5%|0.0%|
[sorbs_http](#sorbs_http)|19|19|6|31.5%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|3461|3461|5|0.1%|0.0%|
[proxyrss](#proxyrss)|1688|1688|4|0.2%|0.0%|
[openbl_30d](#openbl_30d)|3251|3251|4|0.1%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2447|2447|3|0.1%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|1810|1810|3|0.1%|0.0%|
[shunlist](#shunlist)|1248|1248|2|0.1%|0.0%|
[openbl_7d](#openbl_7d)|861|861|2|0.2%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|1|0.1%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1|0.0%|0.0%|
[dshield](#dshield)|19|5120|1|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|183|183|1|0.5%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2229|2229|1|0.0%|0.0%|

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
[sorbs_spam](#sorbs_spam)|29446|30474|19|0.0%|100.0%|
[sorbs_socks](#sorbs_socks)|19|19|19|100.0%|100.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|29446|30474|19|0.0%|100.0%|
[sorbs_new_spam](#sorbs_new_spam)|29446|30474|19|0.0%|100.0%|
[sorbs_misc](#sorbs_misc)|19|19|19|100.0%|100.0%|
[snort_ipfilter](#snort_ipfilter)|8977|8977|6|0.0%|31.5%|
[blocklist_de_mail](#blocklist_de_mail)|15653|15653|5|0.0%|26.3%|
[blocklist_de](#blocklist_de)|25717|25717|5|0.0%|26.3%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|3|0.0%|15.7%|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|3|0.0%|15.7%|
[sorbs_web](#sorbs_web)|645|646|3|0.4%|15.7%|
[xroxy](#xroxy)|2094|2094|1|0.0%|5.2%|
[stopforumspam_1d](#stopforumspam_1d)|7042|7042|1|0.0%|5.2%|
[php_dictionary](#php_dictionary)|508|508|1|0.1%|5.2%|
[nixspam](#nixspam)|16272|16272|1|0.0%|5.2%|
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
[sorbs_spam](#sorbs_spam)|29446|30474|19|0.0%|100.0%|
[sorbs_socks](#sorbs_socks)|19|19|19|100.0%|100.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|29446|30474|19|0.0%|100.0%|
[sorbs_new_spam](#sorbs_new_spam)|29446|30474|19|0.0%|100.0%|
[sorbs_http](#sorbs_http)|19|19|19|100.0%|100.0%|
[snort_ipfilter](#snort_ipfilter)|8977|8977|6|0.0%|31.5%|
[blocklist_de_mail](#blocklist_de_mail)|15653|15653|5|0.0%|26.3%|
[blocklist_de](#blocklist_de)|25717|25717|5|0.0%|26.3%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|3|0.0%|15.7%|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|3|0.0%|15.7%|
[sorbs_web](#sorbs_web)|645|646|3|0.4%|15.7%|
[xroxy](#xroxy)|2094|2094|1|0.0%|5.2%|
[stopforumspam_1d](#stopforumspam_1d)|7042|7042|1|0.0%|5.2%|
[php_dictionary](#php_dictionary)|508|508|1|0.1%|5.2%|
[nixspam](#nixspam)|16272|16272|1|0.0%|5.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|1|0.0%|5.2%|

## sorbs_new_spam

[Sorbs.net](https://www.sorbs.net/) NEW Spam senders, extracted from deltas.

Source is downloaded from [this link]().

The last time downloaded was found to be dated: Sat Jun  6 09:04:13 UTC 2015.

The ipset `sorbs_new_spam` has **29446** entries, **30474** unique IPs.

The following table shows the overlaps of `sorbs_new_spam` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `sorbs_new_spam`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `sorbs_new_spam`.
- ` this % ` is the percentage **of this ipset (`sorbs_new_spam`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[sorbs_spam](#sorbs_spam)|29446|30474|30474|100.0%|100.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|29446|30474|30474|100.0%|100.0%|
[nixspam](#nixspam)|16272|16272|2379|14.6%|7.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|2193|0.0%|7.1%|
[blocklist_de](#blocklist_de)|25717|25717|1042|4.0%|3.4%|
[blocklist_de_mail](#blocklist_de_mail)|15653|15653|895|5.7%|2.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|775|0.0%|2.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|476|0.0%|1.5%|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|339|0.3%|1.1%|
[sorbs_web](#sorbs_web)|645|646|313|48.4%|1.0%|
[snort_ipfilter](#snort_ipfilter)|8977|8977|308|3.4%|1.0%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|181|0.6%|0.5%|
[ri_web_proxies](#ri_web_proxies)|6565|6565|138|2.1%|0.4%|
[php_dictionary](#php_dictionary)|508|508|135|26.5%|0.4%|
[php_spammers](#php_spammers)|495|495|118|23.8%|0.3%|
[alienvault_reputation](#alienvault_reputation)|178368|178368|105|0.0%|0.3%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|3461|3461|98|2.8%|0.3%|
[blocklist_de_apache](#blocklist_de_apache)|14812|14812|98|0.6%|0.3%|
[xroxy](#xroxy)|2094|2094|86|4.1%|0.2%|
[stopforumspam_1d](#stopforumspam_1d)|7042|7042|56|0.7%|0.1%|
[proxz](#proxz)|862|862|40|4.6%|0.1%|
[blocklist_de_bots](#blocklist_de_bots)|3120|3120|40|1.2%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|33|0.0%|0.1%|
[sorbs_socks](#sorbs_socks)|19|19|19|100.0%|0.0%|
[sorbs_misc](#sorbs_misc)|19|19|19|100.0%|0.0%|
[sorbs_http](#sorbs_http)|19|19|19|100.0%|0.0%|
[php_commenters](#php_commenters)|326|326|15|4.6%|0.0%|
[openbl_60d](#openbl_60d)|7651|7651|15|0.1%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|15|0.0%|0.0%|
[sorbs_smtp](#sorbs_smtp)|13|13|13|100.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|1810|1810|12|0.6%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2447|2447|11|0.4%|0.0%|
[et_block](#et_block)|1023|18338662|10|0.0%|0.0%|
[proxyrss](#proxyrss)|1688|1688|9|0.5%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|8|0.0%|0.0%|
[php_harvesters](#php_harvesters)|311|311|7|2.2%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|901|901|5|0.5%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|4|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|3|0.0%|0.0%|
[openbl_30d](#openbl_30d)|3251|3251|3|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2229|2229|3|0.1%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|2|0.2%|0.0%|
[et_tor](#et_tor)|6470|6470|2|0.0%|0.0%|
[dm_tor](#dm_tor)|6475|6475|2|0.0%|0.0%|
[bm_tor](#bm_tor)|6461|6461|2|0.0%|0.0%|
[shunlist](#shunlist)|1248|1248|1|0.0%|0.0%|
[openbl_7d](#openbl_7d)|861|861|1|0.1%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|1|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|183|183|1|0.5%|0.0%|

## sorbs_recent_spam

[Sorbs.net](https://www.sorbs.net/) RECENT Spam senders, extracted from deltas.

Source is downloaded from [this link]().

The last time downloaded was found to be dated: Sat Jun  6 09:04:13 UTC 2015.

The ipset `sorbs_recent_spam` has **29446** entries, **30474** unique IPs.

The following table shows the overlaps of `sorbs_recent_spam` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `sorbs_recent_spam`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `sorbs_recent_spam`.
- ` this % ` is the percentage **of this ipset (`sorbs_recent_spam`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[sorbs_spam](#sorbs_spam)|29446|30474|30474|100.0%|100.0%|
[sorbs_new_spam](#sorbs_new_spam)|29446|30474|30474|100.0%|100.0%|
[nixspam](#nixspam)|16272|16272|2379|14.6%|7.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|2193|0.0%|7.1%|
[blocklist_de](#blocklist_de)|25717|25717|1042|4.0%|3.4%|
[blocklist_de_mail](#blocklist_de_mail)|15653|15653|895|5.7%|2.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|775|0.0%|2.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|476|0.0%|1.5%|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|339|0.3%|1.1%|
[sorbs_web](#sorbs_web)|645|646|313|48.4%|1.0%|
[snort_ipfilter](#snort_ipfilter)|8977|8977|308|3.4%|1.0%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|181|0.6%|0.5%|
[ri_web_proxies](#ri_web_proxies)|6565|6565|138|2.1%|0.4%|
[php_dictionary](#php_dictionary)|508|508|135|26.5%|0.4%|
[php_spammers](#php_spammers)|495|495|118|23.8%|0.3%|
[alienvault_reputation](#alienvault_reputation)|178368|178368|105|0.0%|0.3%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|3461|3461|98|2.8%|0.3%|
[blocklist_de_apache](#blocklist_de_apache)|14812|14812|98|0.6%|0.3%|
[xroxy](#xroxy)|2094|2094|86|4.1%|0.2%|
[stopforumspam_1d](#stopforumspam_1d)|7042|7042|56|0.7%|0.1%|
[proxz](#proxz)|862|862|40|4.6%|0.1%|
[blocklist_de_bots](#blocklist_de_bots)|3120|3120|40|1.2%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|33|0.0%|0.1%|
[sorbs_socks](#sorbs_socks)|19|19|19|100.0%|0.0%|
[sorbs_misc](#sorbs_misc)|19|19|19|100.0%|0.0%|
[sorbs_http](#sorbs_http)|19|19|19|100.0%|0.0%|
[php_commenters](#php_commenters)|326|326|15|4.6%|0.0%|
[openbl_60d](#openbl_60d)|7651|7651|15|0.1%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|15|0.0%|0.0%|
[sorbs_smtp](#sorbs_smtp)|13|13|13|100.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|1810|1810|12|0.6%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2447|2447|11|0.4%|0.0%|
[et_block](#et_block)|1023|18338662|10|0.0%|0.0%|
[proxyrss](#proxyrss)|1688|1688|9|0.5%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|8|0.0%|0.0%|
[php_harvesters](#php_harvesters)|311|311|7|2.2%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|901|901|5|0.5%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|4|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|3|0.0%|0.0%|
[openbl_30d](#openbl_30d)|3251|3251|3|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2229|2229|3|0.1%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|2|0.2%|0.0%|
[et_tor](#et_tor)|6470|6470|2|0.0%|0.0%|
[dm_tor](#dm_tor)|6475|6475|2|0.0%|0.0%|
[bm_tor](#bm_tor)|6461|6461|2|0.0%|0.0%|
[shunlist](#shunlist)|1248|1248|1|0.0%|0.0%|
[openbl_7d](#openbl_7d)|861|861|1|0.1%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|1|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|183|183|1|0.5%|0.0%|

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
[sorbs_spam](#sorbs_spam)|29446|30474|13|0.0%|100.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|29446|30474|13|0.0%|100.0%|
[sorbs_new_spam](#sorbs_new_spam)|29446|30474|13|0.0%|100.0%|
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
[sorbs_spam](#sorbs_spam)|29446|30474|19|0.0%|100.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|29446|30474|19|0.0%|100.0%|
[sorbs_new_spam](#sorbs_new_spam)|29446|30474|19|0.0%|100.0%|
[sorbs_misc](#sorbs_misc)|19|19|19|100.0%|100.0%|
[sorbs_http](#sorbs_http)|19|19|19|100.0%|100.0%|
[snort_ipfilter](#snort_ipfilter)|8977|8977|6|0.0%|31.5%|
[blocklist_de_mail](#blocklist_de_mail)|15653|15653|5|0.0%|26.3%|
[blocklist_de](#blocklist_de)|25717|25717|5|0.0%|26.3%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|3|0.0%|15.7%|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|3|0.0%|15.7%|
[sorbs_web](#sorbs_web)|645|646|3|0.4%|15.7%|
[xroxy](#xroxy)|2094|2094|1|0.0%|5.2%|
[stopforumspam_1d](#stopforumspam_1d)|7042|7042|1|0.0%|5.2%|
[php_dictionary](#php_dictionary)|508|508|1|0.1%|5.2%|
[nixspam](#nixspam)|16272|16272|1|0.0%|5.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|1|0.0%|5.2%|

## sorbs_spam

[Sorbs.net](https://www.sorbs.net/) Spam senders, extracted from deltas.

Source is downloaded from [this link]().

The last time downloaded was found to be dated: Sat Jun  6 09:04:13 UTC 2015.

The ipset `sorbs_spam` has **29446** entries, **30474** unique IPs.

The following table shows the overlaps of `sorbs_spam` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `sorbs_spam`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `sorbs_spam`.
- ` this % ` is the percentage **of this ipset (`sorbs_spam`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[sorbs_recent_spam](#sorbs_recent_spam)|29446|30474|30474|100.0%|100.0%|
[sorbs_new_spam](#sorbs_new_spam)|29446|30474|30474|100.0%|100.0%|
[nixspam](#nixspam)|16272|16272|2379|14.6%|7.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|2193|0.0%|7.1%|
[blocklist_de](#blocklist_de)|25717|25717|1042|4.0%|3.4%|
[blocklist_de_mail](#blocklist_de_mail)|15653|15653|895|5.7%|2.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|775|0.0%|2.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|476|0.0%|1.5%|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|339|0.3%|1.1%|
[sorbs_web](#sorbs_web)|645|646|313|48.4%|1.0%|
[snort_ipfilter](#snort_ipfilter)|8977|8977|308|3.4%|1.0%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|181|0.6%|0.5%|
[ri_web_proxies](#ri_web_proxies)|6565|6565|138|2.1%|0.4%|
[php_dictionary](#php_dictionary)|508|508|135|26.5%|0.4%|
[php_spammers](#php_spammers)|495|495|118|23.8%|0.3%|
[alienvault_reputation](#alienvault_reputation)|178368|178368|105|0.0%|0.3%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|3461|3461|98|2.8%|0.3%|
[blocklist_de_apache](#blocklist_de_apache)|14812|14812|98|0.6%|0.3%|
[xroxy](#xroxy)|2094|2094|86|4.1%|0.2%|
[stopforumspam_1d](#stopforumspam_1d)|7042|7042|56|0.7%|0.1%|
[proxz](#proxz)|862|862|40|4.6%|0.1%|
[blocklist_de_bots](#blocklist_de_bots)|3120|3120|40|1.2%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|33|0.0%|0.1%|
[sorbs_socks](#sorbs_socks)|19|19|19|100.0%|0.0%|
[sorbs_misc](#sorbs_misc)|19|19|19|100.0%|0.0%|
[sorbs_http](#sorbs_http)|19|19|19|100.0%|0.0%|
[php_commenters](#php_commenters)|326|326|15|4.6%|0.0%|
[openbl_60d](#openbl_60d)|7651|7651|15|0.1%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|15|0.0%|0.0%|
[sorbs_smtp](#sorbs_smtp)|13|13|13|100.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|1810|1810|12|0.6%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2447|2447|11|0.4%|0.0%|
[et_block](#et_block)|1023|18338662|10|0.0%|0.0%|
[proxyrss](#proxyrss)|1688|1688|9|0.5%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|8|0.0%|0.0%|
[php_harvesters](#php_harvesters)|311|311|7|2.2%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|901|901|5|0.5%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|4|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|3|0.0%|0.0%|
[openbl_30d](#openbl_30d)|3251|3251|3|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2229|2229|3|0.1%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|2|0.2%|0.0%|
[et_tor](#et_tor)|6470|6470|2|0.0%|0.0%|
[dm_tor](#dm_tor)|6475|6475|2|0.0%|0.0%|
[bm_tor](#bm_tor)|6461|6461|2|0.0%|0.0%|
[shunlist](#shunlist)|1248|1248|1|0.0%|0.0%|
[openbl_7d](#openbl_7d)|861|861|1|0.1%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|1|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|183|183|1|0.5%|0.0%|

## sorbs_web

[Sorbs.net](https://www.sorbs.net/) WEB exploits, extracted from deltas.

Source is downloaded from [this link]().

The last time downloaded was found to be dated: Sat Jun  6 09:04:13 UTC 2015.

The ipset `sorbs_web` has **645** entries, **646** unique IPs.

The following table shows the overlaps of `sorbs_web` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `sorbs_web`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `sorbs_web`.
- ` this % ` is the percentage **of this ipset (`sorbs_web`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[sorbs_spam](#sorbs_spam)|29446|30474|313|1.0%|48.4%|
[sorbs_recent_spam](#sorbs_recent_spam)|29446|30474|313|1.0%|48.4%|
[sorbs_new_spam](#sorbs_new_spam)|29446|30474|313|1.0%|48.4%|
[nixspam](#nixspam)|16272|16272|99|0.6%|15.3%|
[blocklist_de](#blocklist_de)|25717|25717|75|0.2%|11.6%|
[blocklist_de_mail](#blocklist_de_mail)|15653|15653|62|0.3%|9.5%|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|52|0.0%|8.0%|
[snort_ipfilter](#snort_ipfilter)|8977|8977|48|0.5%|7.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|44|0.0%|6.8%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|37|0.1%|5.7%|
[php_dictionary](#php_dictionary)|508|508|27|5.3%|4.1%|
[php_spammers](#php_spammers)|495|495|26|5.2%|4.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|25|0.0%|3.8%|
[ri_web_proxies](#ri_web_proxies)|6565|6565|24|0.3%|3.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|22|0.0%|3.4%|
[xroxy](#xroxy)|2094|2094|16|0.7%|2.4%|
[stopforumspam_1d](#stopforumspam_1d)|7042|7042|16|0.2%|2.4%|
[blocklist_de_bots](#blocklist_de_bots)|3120|3120|11|0.3%|1.7%|
[proxz](#proxz)|862|862|10|1.1%|1.5%|
[sorbs_socks](#sorbs_socks)|19|19|3|15.7%|0.4%|
[sorbs_misc](#sorbs_misc)|19|19|3|15.7%|0.4%|
[sorbs_http](#sorbs_http)|19|19|3|15.7%|0.4%|
[php_commenters](#php_commenters)|326|326|3|0.9%|0.4%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|3461|3461|2|0.0%|0.3%|
[blocklist_de_apache](#blocklist_de_apache)|14812|14812|2|0.0%|0.3%|
[ri_connect_proxies](#ri_connect_proxies)|2447|2447|1|0.0%|0.1%|
[proxyrss](#proxyrss)|1688|1688|1|0.0%|0.1%|
[openbl_60d](#openbl_60d)|7651|7651|1|0.0%|0.1%|
[openbl_30d](#openbl_30d)|3251|3251|1|0.0%|0.1%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1|0.0%|0.1%|
[blocklist_de_strongips](#blocklist_de_strongips)|183|183|1|0.5%|0.1%|
[alienvault_reputation](#alienvault_reputation)|178368|178368|1|0.0%|0.1%|

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
[fullbogons](#fullbogons)|3715|670310296|151552|0.0%|0.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|130368|0.0%|0.7%|
[alienvault_reputation](#alienvault_reputation)|178368|178368|1631|0.9%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1037|0.3%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|1021|1.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|512|0.1%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|322|1.0%|0.0%|
[dshield](#dshield)|19|5120|256|5.0%|0.0%|
[openbl_60d](#openbl_60d)|7651|7651|239|3.1%|0.0%|
[blocklist_de](#blocklist_de)|25717|25717|184|0.7%|0.0%|
[openbl_30d](#openbl_30d)|3251|3251|160|4.9%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2229|2229|107|4.8%|0.0%|
[nixspam](#nixspam)|16272|16272|102|0.6%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1892|1892|101|5.3%|0.0%|
[et_compromised](#et_compromised)|2016|2016|100|4.9%|0.0%|
[shunlist](#shunlist)|1248|1248|97|7.7%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7042|7042|85|1.2%|0.0%|
[openbl_7d](#openbl_7d)|861|861|48|5.5%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3120|3120|44|1.4%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|29|2.2%|0.0%|
[php_commenters](#php_commenters)|326|326|28|8.5%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|15653|15653|27|0.1%|0.0%|
[snort_ipfilter](#snort_ipfilter)|8977|8977|20|0.2%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|1810|1810|17|0.9%|0.0%|
[zeus_badips](#zeus_badips)|202|202|16|7.9%|0.0%|
[zeus](#zeus)|230|230|16|6.9%|0.0%|
[voipbl](#voipbl)|10452|10864|14|0.1%|0.0%|
[openbl_1d](#openbl_1d)|146|146|12|8.2%|0.0%|
[sorbs_spam](#sorbs_spam)|29446|30474|8|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|29446|30474|8|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|29446|30474|8|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|183|183|7|3.8%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|6|0.4%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|6|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|3461|3461|5|0.1%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14812|14812|5|0.0%|0.0%|
[php_dictionary](#php_dictionary)|508|508|4|0.7%|0.0%|
[malc0de](#malc0de)|371|371|4|1.0%|0.0%|
[php_spammers](#php_spammers)|495|495|3|0.6%|0.0%|
[dm_tor](#dm_tor)|6475|6475|3|0.0%|0.0%|
[bm_tor](#bm_tor)|6461|6461|3|0.0%|0.0%|
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
[alienvault_reputation](#alienvault_reputation)|178368|178368|15|0.0%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|11|0.0%|0.0%|
[php_commenters](#php_commenters)|326|326|7|2.1%|0.0%|
[blocklist_de](#blocklist_de)|25717|25717|7|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|8977|8977|6|0.0%|0.0%|
[zeus_badips](#zeus_badips)|202|202|5|2.4%|0.0%|
[zeus](#zeus)|230|230|5|2.1%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|183|183|4|2.1%|0.0%|
[sorbs_spam](#sorbs_spam)|29446|30474|3|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|29446|30474|3|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|29446|30474|3|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3120|3120|3|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7042|7042|2|0.0%|0.0%|
[php_harvesters](#php_harvesters)|311|311|1|0.3%|0.0%|
[openbl_60d](#openbl_60d)|7651|7651|1|0.0%|0.0%|
[openbl_30d](#openbl_30d)|3251|3251|1|0.0%|0.0%|
[nixspam](#nixspam)|16272|16272|1|0.0%|0.0%|
[malc0de](#malc0de)|371|371|1|0.2%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.0%|
[dm_tor](#dm_tor)|6475|6475|1|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2229|2229|1|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|15653|15653|1|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14812|14812|1|0.0%|0.0%|

## sslbl

[Abuse.ch SSL Blacklist](https://sslbl.abuse.ch/) bad SSL traffic related to malware or botnet activities - **excellent list**

Source is downloaded from [this link](https://sslbl.abuse.ch/blacklist/sslipblacklist.csv).

The last time downloaded was found to be dated: Sat Jun  6 08:45:06 UTC 2015.

The ipset `sslbl` has **369** entries, **369** unique IPs.

The following table shows the overlaps of `sslbl` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `sslbl`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `sslbl`.
- ` this % ` is the percentage **of this ipset (`sslbl`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[alienvault_reputation](#alienvault_reputation)|178368|178368|65|0.0%|17.6%|
[shunlist](#shunlist)|1248|1248|57|4.5%|15.4%|
[feodo](#feodo)|99|99|36|36.3%|9.7%|
[et_block](#et_block)|1023|18338662|35|0.0%|9.4%|
[snort_ipfilter](#snort_ipfilter)|8977|8977|31|0.3%|8.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|25|0.0%|6.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|5|0.0%|1.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|3|0.0%|0.8%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|1|0.0%|0.2%|
[ri_web_proxies](#ri_web_proxies)|6565|6565|1|0.0%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.2%|
[blocklist_de_ssh](#blocklist_de_ssh)|2229|2229|1|0.0%|0.2%|
[blocklist_de](#blocklist_de)|25717|25717|1|0.0%|0.2%|

## stopforumspam_1d

[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers in the last 24 hours - **excellent list**

Source is downloaded from [this link](http://www.stopforumspam.com/downloads/listed_ip_1.zip).

The last time downloaded was found to be dated: Sat Jun  6 09:00:02 UTC 2015.

The ipset `stopforumspam_1d` has **7042** entries, **7042** unique IPs.

The following table shows the overlaps of `stopforumspam_1d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `stopforumspam_1d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `stopforumspam_1d`.
- ` this % ` is the percentage **of this ipset (`stopforumspam_1d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|6157|6.6%|87.4%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|6065|20.1%|86.1%|
[blocklist_de](#blocklist_de)|25717|25717|1320|5.1%|18.7%|
[blocklist_de_bots](#blocklist_de_bots)|3120|3120|1260|40.3%|17.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|521|0.0%|7.3%|
[ri_web_proxies](#ri_web_proxies)|6565|6565|486|7.4%|6.9%|
[proxyrss](#proxyrss)|1688|1688|416|24.6%|5.9%|
[snort_ipfilter](#snort_ipfilter)|8977|8977|380|4.2%|5.3%|
[et_tor](#et_tor)|6470|6470|337|5.2%|4.7%|
[bm_tor](#bm_tor)|6461|6461|335|5.1%|4.7%|
[dm_tor](#dm_tor)|6475|6475|333|5.1%|4.7%|
[xroxy](#xroxy)|2094|2094|279|13.3%|3.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|197|0.0%|2.7%|
[proxz](#proxz)|862|862|162|18.7%|2.3%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|161|43.2%|2.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|144|0.0%|2.0%|
[ri_connect_proxies](#ri_connect_proxies)|2447|2447|142|5.8%|2.0%|
[php_commenters](#php_commenters)|326|326|128|39.2%|1.8%|
[blocklist_de_strongips](#blocklist_de_strongips)|183|183|108|59.0%|1.5%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|85|0.0%|1.2%|
[et_block](#et_block)|1023|18338662|80|0.0%|1.1%|
[blocklist_de_apache](#blocklist_de_apache)|14812|14812|65|0.4%|0.9%|
[sorbs_spam](#sorbs_spam)|29446|30474|56|0.1%|0.7%|
[sorbs_recent_spam](#sorbs_recent_spam)|29446|30474|56|0.1%|0.7%|
[sorbs_new_spam](#sorbs_new_spam)|29446|30474|56|0.1%|0.7%|
[blocklist_de_mail](#blocklist_de_mail)|15653|15653|54|0.3%|0.7%|
[alienvault_reputation](#alienvault_reputation)|178368|178368|53|0.0%|0.7%|
[nixspam](#nixspam)|16272|16272|41|0.2%|0.5%|
[php_harvesters](#php_harvesters)|311|311|39|12.5%|0.5%|
[php_spammers](#php_spammers)|495|495|33|6.6%|0.4%|
[php_dictionary](#php_dictionary)|508|508|31|6.1%|0.4%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|26|0.0%|0.3%|
[openbl_60d](#openbl_60d)|7651|7651|21|0.2%|0.2%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|3461|3461|18|0.5%|0.2%|
[sorbs_web](#sorbs_web)|645|646|16|2.4%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|8|0.0%|0.1%|
[voipbl](#voipbl)|10452|10864|6|0.0%|0.0%|
[dshield](#dshield)|19|5120|4|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|3|0.4%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|3|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|2|0.0%|0.0%|
[openbl_30d](#openbl_30d)|3251|3251|2|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.0%|
[zeus_badips](#zeus_badips)|202|202|1|0.4%|0.0%|
[zeus](#zeus)|230|230|1|0.4%|0.0%|
[sorbs_socks](#sorbs_socks)|19|19|1|5.2%|0.0%|
[sorbs_misc](#sorbs_misc)|19|19|1|5.2%|0.0%|
[sorbs_http](#sorbs_http)|19|19|1|5.2%|0.0%|
[shunlist](#shunlist)|1248|1248|1|0.0%|0.0%|
[ciarmy](#ciarmy)|395|395|1|0.2%|0.0%|

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
[stopforumspam_1d](#stopforumspam_1d)|7042|7042|6157|87.4%|6.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|5841|0.0%|6.2%|
[ri_web_proxies](#ri_web_proxies)|6565|6565|3182|48.4%|3.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|2524|0.0%|2.7%|
[blocklist_de](#blocklist_de)|25717|25717|2458|9.5%|2.6%|
[blocklist_de_bots](#blocklist_de_bots)|3120|3120|2106|67.5%|2.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|1543|0.0%|1.6%|
[ri_connect_proxies](#ri_connect_proxies)|2447|2447|1412|57.7%|1.5%|
[xroxy](#xroxy)|2094|2094|1236|59.0%|1.3%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|1021|0.0%|1.0%|
[et_block](#et_block)|1023|18338662|1013|0.0%|1.0%|
[proxyrss](#proxyrss)|1688|1688|842|49.8%|0.9%|
[snort_ipfilter](#snort_ipfilter)|8977|8977|804|8.9%|0.8%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|744|0.0%|0.7%|
[et_tor](#et_tor)|6470|6470|647|10.0%|0.6%|
[bm_tor](#bm_tor)|6461|6461|644|9.9%|0.6%|
[dm_tor](#dm_tor)|6475|6475|641|9.8%|0.6%|
[proxz](#proxz)|862|862|522|60.5%|0.5%|
[sorbs_spam](#sorbs_spam)|29446|30474|339|1.1%|0.3%|
[sorbs_recent_spam](#sorbs_recent_spam)|29446|30474|339|1.1%|0.3%|
[sorbs_new_spam](#sorbs_new_spam)|29446|30474|339|1.1%|0.3%|
[blocklist_de_mail](#blocklist_de_mail)|15653|15653|263|1.6%|0.2%|
[php_commenters](#php_commenters)|326|326|238|73.0%|0.2%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|231|62.0%|0.2%|
[blocklist_de_apache](#blocklist_de_apache)|14812|14812|219|1.4%|0.2%|
[alienvault_reputation](#alienvault_reputation)|178368|178368|203|0.1%|0.2%|
[nixspam](#nixspam)|16272|16272|168|1.0%|0.1%|
[blocklist_de_strongips](#blocklist_de_strongips)|183|183|135|73.7%|0.1%|
[php_spammers](#php_spammers)|495|495|114|23.0%|0.1%|
[php_dictionary](#php_dictionary)|508|508|101|19.8%|0.1%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|88|0.0%|0.0%|
[php_harvesters](#php_harvesters)|311|311|68|21.8%|0.0%|
[openbl_60d](#openbl_60d)|7651|7651|57|0.7%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|3461|3461|53|1.5%|0.0%|
[sorbs_web](#sorbs_web)|645|646|52|8.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|46|0.0%|0.0%|
[voipbl](#voipbl)|10452|10864|35|0.3%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|22|3.2%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2229|2229|16|0.7%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|14|0.0%|0.0%|
[et_compromised](#et_compromised)|2016|2016|11|0.5%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1892|1892|11|0.5%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|901|901|11|1.2%|0.0%|
[dshield](#dshield)|19|5120|8|0.1%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|1810|1810|6|0.3%|0.0%|
[openbl_30d](#openbl_30d)|3251|3251|5|0.1%|0.0%|
[shunlist](#shunlist)|1248|1248|4|0.3%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|4|0.3%|0.0%|
[sorbs_socks](#sorbs_socks)|19|19|3|15.7%|0.0%|
[sorbs_misc](#sorbs_misc)|19|19|3|15.7%|0.0%|
[sorbs_http](#sorbs_http)|19|19|3|15.7%|0.0%|
[openbl_7d](#openbl_7d)|861|861|3|0.3%|0.0%|
[zeus_badips](#zeus_badips)|202|202|2|0.9%|0.0%|
[zeus](#zeus)|230|230|2|0.8%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.0%|
[fullbogons](#fullbogons)|3715|670310296|2|0.0%|0.0%|
[ciarmy](#ciarmy)|395|395|1|0.2%|0.0%|
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
[stopforumspam_1d](#stopforumspam_1d)|7042|7042|6065|86.1%|20.1%|
[blocklist_de](#blocklist_de)|25717|25717|2127|8.2%|7.0%|
[blocklist_de_bots](#blocklist_de_bots)|3120|3120|1936|62.0%|6.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|1912|0.0%|6.3%|
[ri_web_proxies](#ri_web_proxies)|6565|6565|1613|24.5%|5.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|909|0.0%|3.0%|
[xroxy](#xroxy)|2094|2094|722|34.4%|2.3%|
[proxyrss](#proxyrss)|1688|1688|662|39.2%|2.1%|
[ri_connect_proxies](#ri_connect_proxies)|2447|2447|646|26.3%|2.1%|
[snort_ipfilter](#snort_ipfilter)|8977|8977|632|7.0%|2.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|568|0.0%|1.8%|
[et_tor](#et_tor)|6470|6470|516|7.9%|1.7%|
[bm_tor](#bm_tor)|6461|6461|509|7.8%|1.6%|
[dm_tor](#dm_tor)|6475|6475|506|7.8%|1.6%|
[proxz](#proxz)|862|862|411|47.6%|1.3%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|322|0.0%|1.0%|
[et_block](#et_block)|1023|18338662|314|0.0%|1.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|191|51.3%|0.6%|
[sorbs_spam](#sorbs_spam)|29446|30474|181|0.5%|0.6%|
[sorbs_recent_spam](#sorbs_recent_spam)|29446|30474|181|0.5%|0.6%|
[sorbs_new_spam](#sorbs_new_spam)|29446|30474|181|0.5%|0.6%|
[php_commenters](#php_commenters)|326|326|171|52.4%|0.5%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|153|0.0%|0.5%|
[blocklist_de_mail](#blocklist_de_mail)|15653|15653|146|0.9%|0.4%|
[blocklist_de_apache](#blocklist_de_apache)|14812|14812|132|0.8%|0.4%|
[blocklist_de_strongips](#blocklist_de_strongips)|183|183|124|67.7%|0.4%|
[alienvault_reputation](#alienvault_reputation)|178368|178368|94|0.0%|0.3%|
[nixspam](#nixspam)|16272|16272|88|0.5%|0.2%|
[php_dictionary](#php_dictionary)|508|508|65|12.7%|0.2%|
[php_spammers](#php_spammers)|495|495|64|12.9%|0.2%|
[php_harvesters](#php_harvesters)|311|311|51|16.3%|0.1%|
[sorbs_web](#sorbs_web)|645|646|37|5.7%|0.1%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|3461|3461|32|0.9%|0.1%|
[openbl_60d](#openbl_60d)|7651|7651|26|0.3%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|25|0.0%|0.0%|
[voipbl](#voipbl)|10452|10864|12|0.1%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|12|1.7%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|11|0.0%|0.0%|
[et_compromised](#et_compromised)|2016|2016|7|0.3%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1892|1892|7|0.3%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|6|0.0%|0.0%|
[dshield](#dshield)|19|5120|6|0.1%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2229|2229|5|0.2%|0.0%|
[sorbs_socks](#sorbs_socks)|19|19|3|15.7%|0.0%|
[sorbs_misc](#sorbs_misc)|19|19|3|15.7%|0.0%|
[sorbs_http](#sorbs_http)|19|19|3|15.7%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|901|901|3|0.3%|0.0%|
[shunlist](#shunlist)|1248|1248|2|0.1%|0.0%|
[openbl_30d](#openbl_30d)|3251|3251|2|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.0%|
[zeus_badips](#zeus_badips)|202|202|1|0.4%|0.0%|
[zeus](#zeus)|230|230|1|0.4%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|1|0.0%|0.0%|
[ciarmy](#ciarmy)|395|395|1|0.2%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|1810|1810|1|0.0%|0.0%|

## virbl

[VirBL](http://virbl.bit.nl/) is a project of which the idea was born during the RIPE-48 meeting. The plan was to get reports of virusscanning mailservers, and put the IP-addresses that were reported to send viruses on a blacklist.

Source is downloaded from [this link](http://virbl.bit.nl/download/virbl.dnsbl.bit.nl.txt).

The last time downloaded was found to be dated: Sat Jun  6 08:52:03 UTC 2015.

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
[fullbogons](#fullbogons)|3715|670310296|319|0.0%|2.9%|
[bogons](#bogons)|13|592708608|319|0.0%|2.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|299|0.0%|2.7%|
[alienvault_reputation](#alienvault_reputation)|178368|178368|209|0.1%|1.9%|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|35|0.0%|0.3%|
[blocklist_de](#blocklist_de)|25717|25717|35|0.1%|0.3%|
[blocklist_de_sip](#blocklist_de_sip)|90|90|25|27.7%|0.2%|
[et_block](#et_block)|1023|18338662|16|0.0%|0.1%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|14|0.0%|0.1%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|12|0.0%|0.1%|
[shunlist](#shunlist)|1248|1248|12|0.9%|0.1%|
[openbl_60d](#openbl_60d)|7651|7651|8|0.1%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7042|7042|6|0.0%|0.0%|
[dshield](#dshield)|19|5120|5|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3120|3120|5|0.1%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|4|0.0%|0.0%|
[ciarmy](#ciarmy)|395|395|4|1.0%|0.0%|
[openbl_30d](#openbl_30d)|3251|3251|3|0.0%|0.0%|
[et_tor](#et_tor)|6470|6470|3|0.0%|0.0%|
[dm_tor](#dm_tor)|6475|6475|3|0.0%|0.0%|
[bm_tor](#bm_tor)|6461|6461|3|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14812|14812|3|0.0%|0.0%|
[nixspam](#nixspam)|16272|16272|2|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|2|0.0%|0.0%|
[et_compromised](#et_compromised)|2016|2016|2|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1892|1892|2|0.1%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|15653|15653|2|0.0%|0.0%|
[openbl_7d](#openbl_7d)|861|861|1|0.1%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|1810|1810|1|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|3461|3461|1|0.0%|0.0%|

## xroxy

[xroxy.com](http://www.xroxy.com) open proxies (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.xroxy.com/proxyrss.xml).

The last time downloaded was found to be dated: Sat Jun  6 08:33:02 UTC 2015.

The ipset `xroxy` has **2094** entries, **2094** unique IPs.

The following table shows the overlaps of `xroxy` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `xroxy`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `xroxy`.
- ` this % ` is the percentage **of this ipset (`xroxy`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|1236|1.3%|59.0%|
[ri_web_proxies](#ri_web_proxies)|6565|6565|897|13.6%|42.8%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|722|2.3%|34.4%|
[proxyrss](#proxyrss)|1688|1688|437|25.8%|20.8%|
[ri_connect_proxies](#ri_connect_proxies)|2447|2447|365|14.9%|17.4%|
[proxz](#proxz)|862|862|340|39.4%|16.2%|
[stopforumspam_1d](#stopforumspam_1d)|7042|7042|279|3.9%|13.3%|
[blocklist_de](#blocklist_de)|25717|25717|246|0.9%|11.7%|
[blocklist_de_bots](#blocklist_de_bots)|3120|3120|196|6.2%|9.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|100|0.0%|4.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|93|0.0%|4.4%|
[sorbs_spam](#sorbs_spam)|29446|30474|86|0.2%|4.1%|
[sorbs_recent_spam](#sorbs_recent_spam)|29446|30474|86|0.2%|4.1%|
[sorbs_new_spam](#sorbs_new_spam)|29446|30474|86|0.2%|4.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|58|0.0%|2.7%|
[blocklist_de_mail](#blocklist_de_mail)|15653|15653|48|0.3%|2.2%|
[snort_ipfilter](#snort_ipfilter)|8977|8977|46|0.5%|2.1%|
[nixspam](#nixspam)|16272|16272|40|0.2%|1.9%|
[php_dictionary](#php_dictionary)|508|508|31|6.1%|1.4%|
[php_spammers](#php_spammers)|495|495|25|5.0%|1.1%|
[sorbs_web](#sorbs_web)|645|646|16|2.4%|0.7%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|13|1.9%|0.6%|
[php_commenters](#php_commenters)|326|326|7|2.1%|0.3%|
[blocklist_de_strongips](#blocklist_de_strongips)|183|183|7|3.8%|0.3%|
[alienvault_reputation](#alienvault_reputation)|178368|178368|4|0.0%|0.1%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|3|0.0%|0.1%|
[php_harvesters](#php_harvesters)|311|311|2|0.6%|0.0%|
[et_tor](#et_tor)|6470|6470|2|0.0%|0.0%|
[dm_tor](#dm_tor)|6475|6475|2|0.0%|0.0%|
[bm_tor](#bm_tor)|6461|6461|2|0.0%|0.0%|
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
[alienvault_reputation](#alienvault_reputation)|178368|178368|62|0.0%|26.9%|
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
[stopforumspam_1d](#stopforumspam_1d)|7042|7042|1|0.0%|0.4%|
[php_commenters](#php_commenters)|326|326|1|0.3%|0.4%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.4%|

## zeus_badips

[Abuse.ch Zeus tracker](https://zeustracker.abuse.ch) badips includes IPv4 addresses that are used by the ZeuS trojan. It is the recommened blocklist if you want to block only ZeuS IPs. It excludes IP addresses that ZeuS Tracker believes to be hijacked (level 2) or belong to a free web hosting provider (level 3). Hence the false postive rate should be much lower compared to the standard ZeuS IP blocklist. **excellent list**

Source is downloaded from [this link](https://zeustracker.abuse.ch/blocklist.php?download=badips).

The last time downloaded was found to be dated: Sat Jun  6 08:45:10 UTC 2015.

The ipset `zeus_badips` has **202** entries, **202** unique IPs.

The following table shows the overlaps of `zeus_badips` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `zeus_badips`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `zeus_badips`.
- ` this % ` is the percentage **of this ipset (`zeus_badips`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[zeus](#zeus)|230|230|202|87.8%|100.0%|
[et_block](#et_block)|1023|18338662|200|0.0%|99.0%|
[snort_ipfilter](#snort_ipfilter)|8977|8977|179|1.9%|88.6%|
[alienvault_reputation](#alienvault_reputation)|178368|178368|38|0.0%|18.8%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|16|0.0%|7.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|10|0.0%|4.9%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|10|0.0%|4.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|8|0.0%|3.9%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|5|0.0%|2.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|4|0.0%|1.9%|
[stopforumspam_30d](#stopforumspam_30d)|93258|93258|2|0.0%|0.9%|
[stopforumspam_7d](#stopforumspam_7d)|30121|30121|1|0.0%|0.4%|
[stopforumspam_1d](#stopforumspam_1d)|7042|7042|1|0.0%|0.4%|
[php_commenters](#php_commenters)|326|326|1|0.3%|0.4%|
[openbl_60d](#openbl_60d)|7651|7651|1|0.0%|0.4%|
[openbl_30d](#openbl_30d)|3251|3251|1|0.0%|0.4%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.4%|
