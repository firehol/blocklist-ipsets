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

The following list was automatically generated on Thu Jun 11 00:00:56 UTC 2015.

The update frequency is the maximum allowed by internal configuration. A list will never be downloaded sooner than the update frequency stated. A list may also not be downloaded, after this frequency expired, if it has not been modified on the server (as reported by HTTP `IF_MODIFIED_SINCE` method).

name|info|type|entries|update|
:--:|:--:|:--:|:-----:|:----:|
[alienvault_reputation](#alienvault_reputation)|[AlienVault.com](https://www.alienvault.com/) IP reputation database (this list seems to include port scanning hosts and to be updated regularly, but we found no information about its retention policy)|ipv4 hash:ip|182721 unique IPs|updated every 6 hours  from [this link](https://reputation.alienvault.com/reputation.generic)
[blocklist_de](#blocklist_de)|[Blocklist.de](https://www.blocklist.de/) IPs that have been detected by fail2ban in the last 48 hours - **excellent list**|ipv4 hash:ip|29619 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/all.txt)
[blocklist_de_apache](#blocklist_de_apache)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service Apache, Apache-DDOS, RFI-Attacks.|ipv4 hash:ip|15454 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/apache.txt)
[blocklist_de_bots](#blocklist_de_bots)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the RFI-Attacks, REG-Bots, IRC-Bots or BadBots (BadBots = he has posted a Spam-Comment on a open Forum or Wiki).|ipv4 hash:ip|2949 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/bots.txt)
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|[Blocklist.de](https://www.blocklist.de/) All IPs which attacks Joomlas, Wordpress and other Web-Logins with Brute-Force Logins.|ipv4 hash:ip|4090 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/bruteforcelogin.txt)
[blocklist_de_ftp](#blocklist_de_ftp)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours for attacks on the Service FTP.|ipv4 hash:ip|1380 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/ftp.txt)
[blocklist_de_imap](#blocklist_de_imap)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours for attacks on the Service imap, sasl, pop3, etc.|ipv4 hash:ip|2412 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/imap.txt)
[blocklist_de_mail](#blocklist_de_mail)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service Mail, Postfix.|ipv4 hash:ip|17317 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/mail.txt)
[blocklist_de_sip](#blocklist_de_sip)|[Blocklist.de](https://www.blocklist.de/) All IP addresses that tried to login in a SIP, VOIP or Asterisk Server and are included in the IPs list from [infiltrated.net](www.infiltrated.net)|ipv4 hash:ip|79 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/sip.txt)
[blocklist_de_ssh](#blocklist_de_ssh)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service SSH.|ipv4 hash:ip|3531 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/ssh.txt)
[blocklist_de_strongips](#blocklist_de_strongips)|[Blocklist.de](https://www.blocklist.de/) All IPs which are older then 2 month and have more then 5.000 attacks.|ipv4 hash:ip|183 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/strongips.txt)
[bm_tor](#bm_tor)|[torstatus.blutmagie.de](https://torstatus.blutmagie.de) list of all TOR network servers|ipv4 hash:ip|6473 unique IPs|updated every 30 mins  from [this link](https://torstatus.blutmagie.de/ip_list_all.php/Tor_ip_list_ALL.csv)
[bogons](#bogons)|[Team-Cymru.org](http://www.team-cymru.org) private and reserved addresses defined by RFC 1918, RFC 5735, and RFC 6598 and netblocks that have not been allocated to a regional internet registry - **excellent list - use it only your internet interface**|ipv4 hash:net|13 subnets, 592708608 unique IPs|updated every 1 day  from [this link](http://www.team-cymru.org/Services/Bogons/bogon-bn-agg.txt)
[bruteforceblocker](#bruteforceblocker)|[danger.rulez.sk](http://danger.rulez.sk/) IPs detected by [bruteforceblocker](http://danger.rulez.sk/index.php/bruteforceblocker/) (fail2ban alternative for SSH on OpenBSD). This is an automatically generated list from users reporting failed authentication attempts. An IP seems to be included if 3 or more users report it. Its retention pocily seems 30 days.|ipv4 hash:ip|1706 unique IPs|updated every 3 hours  from [this link](http://danger.rulez.sk/projects/bruteforceblocker/blist.php)
[ciarmy](#ciarmy)|[CIArmy.com](http://ciarmy.com/) IPs with poor Rogue Packet score that have not yet been identified as malicious by the community|ipv4 hash:ip|469 unique IPs|updated every 3 hours  from [this link](http://cinsscore.com/list/ci-badguys.txt)
[cleanmx_viruses](#cleanmx_viruses)|[Clean-MX.de](http://support.clean-mx.de/clean-mx/viruses.php) IPs with viruses|ipv4 hash:ip|65 unique IPs|updated every 12 hours  from [this link](http://support.clean-mx.de/clean-mx/xmlviruses.php?sort=id%20desc&response=alive)
[dm_tor](#dm_tor)|[dan.me.uk](https://www.dan.me.uk) dynamic list of TOR nodes|ipv4 hash:ip|6459 unique IPs|updated every 30 mins  from [this link](https://www.dan.me.uk/torlist/)
[dragon_http](#dragon_http)|[Dragon Search Group](http://www.dragonresearchgroup.org/) IPs that have been seen sending HTTP requests to Dragon Research Pods in the last 7 days. This report lists hosts that are highly suspicious and are likely conducting malicious HTTP attacks. LEGITIMATE SEARCH ENGINE BOTS MAY BE IN THIS LIST. This report is informational.  It is not a blacklist, but some operators may choose to use it to help protect their networks and hosts in the forms of automated reporting and mitigation services.|ipv4 hash:net|1044 subnets, 273664 unique IPs|updated every 1 day  from [this link](http://www.dragonresearchgroup.org/insight/http-report.txt)
[dshield](#dshield)|[DShield.org](https://dshield.org/) top 20 attacking class C (/24) subnets over the last three days - **excellent list**|ipv4 hash:net|20 subnets, 5120 unique IPs|updated every 4 hours  from [this link](http://feeds.dshield.org/block.txt)
[et_block](#et_block)|[EmergingThreats.net](http://www.emergingthreats.net/) default blacklist (at the time of writing includes spamhaus DROP, dshield and abuse.ch trackers, which are available separately too - prefer to use the direct ipsets instead of this, they seem to lag a bit in updates)|ipv4 hash:net|1000 subnets, 18344011 unique IPs|updated every 12 hours  from [this link](http://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt)
[et_botcc](#et_botcc)|[EmergingThreats.net Command and Control IPs](http://doc.emergingthreats.net/bin/view/Main/BotCC) These IPs are updates every 24 hours and should be considered VERY highly reliable indications that a host is communicating with a known and active Bot or Malware command and control server - (although they say this includes abuse.ch trackers, it does not - most probably it is the shadowserver.org C&C list)|ipv4 hash:ip|506 unique IPs|updated every 12 hours  from [this link](http://rules.emergingthreats.net/fwrules/emerging-PIX-CC.rules)
[et_compromised](#et_compromised)|[EmergingThreats.net compromised hosts](http://doc.emergingthreats.net/bin/view/Main/CompromisedHost) - (this seems to be based on bruteforceblocker)|ipv4 hash:ip|1721 unique IPs|updated every 12 hours  from [this link](http://rules.emergingthreats.net/blockrules/compromised-ips.txt)
et_dshield|[EmergingThreats.net](http://www.emergingthreats.net/) dshield blocklist|ipv4 hash:net|disabled|updated every 12 hours  from [this link](http://rules.emergingthreats.net/fwrules/emerging-PIX-DSHIELD.rules)
et_spamhaus|[EmergingThreats.net](http://www.emergingthreats.net/) spamhaus blocklist|ipv4 hash:net|disabled|updated every 12 hours  from [this link](http://rules.emergingthreats.net/fwrules/emerging-PIX-DROP.rules)
[et_tor](#et_tor)|[EmergingThreats.net](http://www.emergingthreats.net/) [list](http://doc.emergingthreats.net/bin/view/Main/TorRules) of TOR network IPs|ipv4 hash:ip|6400 unique IPs|updated every 12 hours  from [this link](http://rules.emergingthreats.net/blockrules/emerging-tor.rules)
[feodo](#feodo)|[Abuse.ch Feodo tracker](https://feodotracker.abuse.ch) trojan includes IPs which are being used by Feodo (also known as Cridex or Bugat) which commits ebanking fraud - **excellent list**|ipv4 hash:ip|105 unique IPs|updated every 30 mins  from [this link](https://feodotracker.abuse.ch/blocklist/?download=ipblocklist)
[firehol_anonymous](#firehol_anonymous)|**FireHOL Anonymous** - Known anonymizing IPs. (includes: firehol_proxies anonymous bm_tor dm_tor tor_exits)|ipv4 hash:net|19001 subnets, 83032 unique IPs|
[firehol_level1](#firehol_level1)|**FireHOL Level 1** - Maximum protection without false positives. (includes: fullbogons dshield feodo palevo sslbl zeus spamhaus_drop spamhaus_edrop)|ipv4 hash:net|5135 subnets, 688894845 unique IPs|
[firehol_level2](#firehol_level2)|**FireHOL Level 2** - Maximum protection from attacks took place in the last 48 hours. (includes: openbl_1d blocklist_de stopforumspam_1d)|ipv4 hash:net|23356 subnets, 34994 unique IPs|
[firehol_level3](#firehol_level3)|**FireHOL Level 3** - All the bad IPs in last 30 days. (includes: openbl_30d stopforumspam_30d virbl malc0de shunlist malwaredomainlist bruteforceblocker ciarmy cleanmx_viruses snort_ipfilter ib_bluetack_spyware ib_bluetack_hijacked ib_bluetack_webexploit php_commenters php_dictionary php_harvesters php_spammers iw_wormlist)|ipv4 hash:net|110224 subnets, 9627969 unique IPs|
[firehol_proxies](#firehol_proxies)|**FireHOL Proxies** - Known open proxies in the last 30 days. (includes: ib_bluetack_proxies maxmind_proxy_fraud proxyrss proxz ri_connect_proxies ri_web_proxies xroxy)|ipv4 hash:net|12463 subnets, 12723 unique IPs|
[fullbogons](#fullbogons)|[Team-Cymru.org](http://www.team-cymru.org) IP space that has been allocated to an RIR, but not assigned by that RIR to an actual ISP or other end-user - **excellent list - use it only your internet interface**|ipv4 hash:net|3770 subnets, 670213096 unique IPs|updated every 1 day  from [this link](http://www.team-cymru.org/Services/Bogons/fullbogons-ipv4.txt)
[geolite2_country](https://github.com/ktsaou/blocklist-ipsets/tree/master/geolite2_country)|[MaxMind GeoLite2](http://dev.maxmind.com/geoip/geoip2/geolite2/) databases are free IP geolocation databases comparable to, but less accurate than, MaxMind’s GeoIP2 databases. They include IPs per country, IPs per continent, IPs used by anonymous services (VPNs, Proxies, etc) and Satellite Providers.|ipv4 hash:net|All the world|updated every 7 days  from [this link](http://geolite.maxmind.com/download/geoip/database/GeoLite2-Country-CSV.zip)
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|[iBlocklist.com](https://www.iblocklist.com/) free version of [BlueTack.co.uk](http://www.bluetack.co.uk/) IPs that have been reported for bad deeds in p2p|ipv4 hash:ip|47940 unique IPs|updated every 12 hours  from [this link](http://list.iblocklist.com/?list=cwworuawihqvocglcoss&fileformat=p2p&archiveformat=gz)
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|[iBlocklist.com](https://www.iblocklist.com/) free version of [BlueTack.co.uk](http://www.bluetack.co.uk/) hijacked IP-Blocks Hijacked IP space are IP blocks that are being used without permission|ipv4 hash:net|535 subnets, 9177856 unique IPs|updated every 12 hours  from [this link](http://list.iblocklist.com/?list=usrcshglbiilevmyfhse&fileformat=p2p&archiveformat=gz)
[ib_bluetack_level1](#ib_bluetack_level1)|[iBlocklist.com](https://www.iblocklist.com/) free version of [BlueTack.co.uk](http://www.bluetack.co.uk/) Level 1 (for use in p2p): Companies or organizations who are clearly involved with trying to stop filesharing (e.g. Baytsp, MediaDefender, Mediasentry a.o.). Companies which anti-p2p activity has been seen from. Companies that produce or have a strong financial interest in copyrighted material (e.g. music, movie, software industries a.o.). Government ranges or companies that have a strong financial interest in doing work for governments. Legal industry ranges. IPs or ranges of ISPs from which anti-p2p activity has been observed. Basically this list will block all kinds of internet connections that most people would rather not have during their internet travels.|ipv4 hash:net|218307 subnets, 764993634 unique IPs|updated every 12 hours  from [this link](http://list.iblocklist.com/?list=ydxerpxkpcfqjaybcssw&fileformat=p2p&archiveformat=gz)
[ib_bluetack_level2](#ib_bluetack_level2)|[iBlocklist.com](https://www.iblocklist.com/) free version of BlueTack.co.uk Level 2 (for use in p2p). General corporate ranges. Ranges used by labs or researchers. Proxies.|ipv4 hash:net|72950 subnets, 348710251 unique IPs|updated every 12 hours  from [this link](http://list.iblocklist.com/?list=gyisgnzbhppbvsphucsw&fileformat=p2p&archiveformat=gz)
badips.com categories ipsets|[BadIPs.com](https://www.badips.com) community based IP blacklisting. They score IPs based on the reports they reports.|ipv4 hash:ip|disabled|disabled
[ib_bluetack_proxies](#ib_bluetack_proxies)|[iBlocklist.com](https://www.iblocklist.com/) free version of [BlueTack.co.uk](http://www.bluetack.co.uk/) Open Proxies IPs list (without TOR)|ipv4 hash:ip|663 unique IPs|updated every 12 hours  from [this link](http://list.iblocklist.com/?list=xoebmbyexwuiogmbyprb&fileformat=p2p&archiveformat=gz)
[ib_bluetack_spyware](#ib_bluetack_spyware)|[iBlocklist.com](https://www.iblocklist.com/) free version of [BlueTack.co.uk](http://www.bluetack.co.uk/) known malicious SPYWARE and ADWARE IP Address ranges|ipv4 hash:net|3267 subnets, 339173 unique IPs|updated every 12 hours  from [this link](http://list.iblocklist.com/?list=llvtlsjyoyiczbkjsxpf&fileformat=p2p&archiveformat=gz)
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|[iBlocklist.com](https://www.iblocklist.com/) free version of [BlueTack.co.uk](http://www.bluetack.co.uk/) web server hack and exploit attempts|ipv4 hash:ip|1450 unique IPs|updated every 12 hours  from [this link](http://list.iblocklist.com/?list=ghlzqtqxnzctvvajwwag&fileformat=p2p&archiveformat=gz)
infiltrated|[infiltrated.net](http://www.infiltrated.net) (this list seems to be updated frequently, but we found no information about it)|ipv4 hash:ip|disabled|updated every 12 hours  from [this link](http://www.infiltrated.net/blacklisted)
[ipdeny_country](https://github.com/ktsaou/blocklist-ipsets/tree/master/ipdeny_country)|[IPDeny.com](http://www.ipdeny.com/) geolocation database|ipv4 hash:net|All the world|updated every 1 day  from [this link](http://www.ipdeny.com/ipblocks/data/countries/all-zones.tar.gz)
[iw_spamlist](#iw_spamlist)|[ImproWare Antispam](http://antispam.imp.ch/) IPs sending spam, in the last 3 days|ipv4 hash:ip|3703 unique IPs|updated every 1 hour  from [this link](http://antispam.imp.ch/spamlist)
[iw_wormlist](#iw_wormlist)|[ImproWare Antispam](http://antispam.imp.ch/) IPs sending emails with viruses or worms, in the last 3 days|ipv4 hash:ip|33 unique IPs|updated every 1 hour  from [this link](http://antispam.imp.ch/wormlist)
lashback_ubl|[The LashBack UBL](http://blacklist.lashback.com/) The Unsubscribe Blacklist (UBL) is a real-time blacklist of IP addresses which are sending email to names harvested from suppression files (this is a big list, more than 500.000 IPs)|ipv4 hash:ip|disabled|updated every 1 day  from [this link](http://www.unsubscore.com/blacklist.txt)
[malc0de](#malc0de)|[Malc0de.com](http://malc0de.com) malicious IPs of the last 30 days|ipv4 hash:ip|313 unique IPs|updated every 1 day  from [this link](http://malc0de.com/bl/IP_Blacklist.txt)
[malwaredomainlist](#malwaredomainlist)|[malwaredomainlist.com](http://www.malwaredomainlist.com) list of malware active ip addresses|ipv4 hash:ip|1288 unique IPs|updated every 12 hours  from [this link](http://www.malwaredomainlist.com/hostslist/ip.txt)
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|[MaxMind.com](https://www.maxmind.com/en/anonymous-proxy-fraudulent-ip-address-list) list of anonymous proxy fraudelent IP addresses.|ipv4 hash:ip|524 unique IPs|updated every 4 hours  from [this link](https://www.maxmind.com/en/anonymous-proxy-fraudulent-ip-address-list)
[nixspam](#nixspam)|[NiX Spam](http://www.heise.de/ix/NiX-Spam-DNSBL-and-blacklist-for-download-499637.html) IP addresses that sent spam in the last hour - automatically generated entries without distinguishing open proxies from relays, dialup gateways, and so on. All IPs are removed after 12 hours if there is no spam from there.|ipv4 hash:ip|28015 unique IPs|updated every 15 mins  from [this link](http://www.dnsbl.manitu.net/download/nixspam-ip.dump.gz)
[nt_malware_http](#nt_malware_http)|[No Think](http://www.nothink.org/) Malware HTTP|ipv4 hash:ip|69 unique IPs|updated every 1 hour  from [this link](http://www.nothink.org/blacklist/blacklist_malware_http.txt)
[nt_malware_irc](#nt_malware_irc)|[No Think](http://www.nothink.org/) Malware IRC|ipv4 hash:ip|43 unique IPs|updated every 1 hour  from [this link](http://www.nothink.org/blacklist/blacklist_malware_irc.txt)
[nt_ssh_7d](#nt_ssh_7d)|[No Think](http://www.nothink.org/) Last 7 days SSH attacks|ipv4 hash:ip|0 unique IPs|updated every 1 hour  from [this link](http://www.nothink.org/blacklist/blacklist_ssh_week.txt)
openbl|[OpenBL.org](http://www.openbl.org/) default blacklist (currently it is the same with 90 days). OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications - **excellent list**|ipv4 hash:ip|disabled|updated every 4 hours  from [this link](http://www.openbl.org/lists/base.txt)
openbl_180d|[OpenBL.org](http://www.openbl.org/) last 180 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|disabled|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_180days.txt)
[openbl_1d](#openbl_1d)|[OpenBL.org](http://www.openbl.org/) last 24 hours IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|152 unique IPs|updated every 1 hour  from [this link](http://www.openbl.org/lists/base_1days.txt)
[openbl_30d](#openbl_30d)|[OpenBL.org](http://www.openbl.org/) last 30 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|2835 unique IPs|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_30days.txt)
openbl_360d|[OpenBL.org](http://www.openbl.org/) last 360 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|disabled|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_360days.txt)
[openbl_60d](#openbl_60d)|[OpenBL.org](http://www.openbl.org/) last 60 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|7012 unique IPs|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_60days.txt)
[openbl_7d](#openbl_7d)|[OpenBL.org](http://www.openbl.org/) last 7 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|679 unique IPs|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_7days.txt)
openbl_90d|[OpenBL.org](http://www.openbl.org/) last 90 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|disabled|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_90days.txt)
openbl_all|[OpenBL.org](http://www.openbl.org/) last all IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|disabled|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_all.txt)
[palevo](#palevo)|[Abuse.ch Palevo tracker](https://palevotracker.abuse.ch) worm includes IPs which are being used as botnet C&C for the Palevo crimeware - **excellent list**|ipv4 hash:ip|13 unique IPs|updated every 30 mins  from [this link](https://palevotracker.abuse.ch/blocklists.php?download=ipblocklist)
php_bad|[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) bad web hosts (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|disabled|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=b&rss=1)
[php_commenters](#php_commenters)|[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) comment spammers (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|430 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=c&rss=1)
[php_dictionary](#php_dictionary)|[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) directory attackers (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|702 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=d&rss=1)
[php_harvesters](#php_harvesters)|[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) harvesters (IPs that surf the internet looking for email addresses) (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|392 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=h&rss=1)
[php_spammers](#php_spammers)|[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) spam servers (IPs used by spammers to send messages) (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|700 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=s&rss=1)
[proxyrss](#proxyrss)|[proxyrss.com](http://www.proxyrss.com) open proxies syndicated from multiple sources.|ipv4 hash:ip|1675 unique IPs|updated every 4 hours  from [this link](http://www.proxyrss.com/proxylists/all.gz)
[proxz](#proxz)|[proxz.com](http://www.proxz.com) open proxies (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|1244 unique IPs|updated every 1 hour  from [this link](http://www.proxz.com/proxylists.xml)
[ri_connect_proxies](#ri_connect_proxies)|[rosinstrument.com](http://www.rosinstrument.com) open CONNECT proxies (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|2751 unique IPs|updated every 1 hour  from [this link](http://tools.rosinstrument.com/proxy/plab100.xml)
[ri_web_proxies](#ri_web_proxies)|[rosinstrument.com](http://www.rosinstrument.com) open HTTP proxies (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|7624 unique IPs|updated every 1 hour  from [this link](http://tools.rosinstrument.com/proxy/l100.xml)
[shunlist](#shunlist)|[AutoShun.org](http://autoshun.org/) IPs identified as hostile by correlating logs from distributed snort installations running the autoshun plugin|ipv4 hash:ip|1234 unique IPs|updated every 4 hours  from [this link](http://www.autoshun.org/files/shunlist.csv)
[snort_ipfilter](#snort_ipfilter)|[labs.snort.org](https://labs.snort.org/) supplied IP blacklist (this list seems to be updated frequently, but we found no information about it)|ipv4 hash:ip|10158 unique IPs|updated every 12 hours  from [this link](http://labs.snort.org/feeds/ip-filter.blf)
[sorbs_dul](#sorbs_dul)|[Sorbs.net](https://www.sorbs.net/) DUL, Dynamic User IPs extracted from deltas.|ipv4 hash:net|9 subnets, 4608 unique IPs|updated every 1 min  from [this link]()
[sorbs_http](#sorbs_http)|[Sorbs.net](https://www.sorbs.net/) HTTP proxies, extracted from deltas.|ipv4 hash:net|3 subnets, 3 unique IPs|
[sorbs_misc](#sorbs_misc)|[Sorbs.net](https://www.sorbs.net/) MISC proxies, extracted from deltas.|ipv4 hash:net|3 subnets, 3 unique IPs|
[sorbs_new_spam](#sorbs_new_spam)|[Sorbs.net](https://www.sorbs.net/) NEW Spam senders, extracted from deltas.|ipv4 hash:net|60429 subnets, 61096 unique IPs|
[sorbs_recent_spam](#sorbs_recent_spam)|[Sorbs.net](https://www.sorbs.net/) RECENT Spam senders, extracted from deltas.|ipv4 hash:net|60429 subnets, 61096 unique IPs|
[sorbs_smtp](#sorbs_smtp)|[Sorbs.net](https://www.sorbs.net/) SMTP Open Relays, extracted from deltas.|ipv4 hash:net|4 subnets, 4 unique IPs|
[sorbs_socks](#sorbs_socks)|[Sorbs.net](https://www.sorbs.net/) SOCKS proxies, extracted from deltas.|ipv4 hash:net|3 subnets, 3 unique IPs|
[sorbs_spam](#sorbs_spam)|[Sorbs.net](https://www.sorbs.net/) Spam senders, extracted from deltas.|ipv4 hash:net|60429 subnets, 61096 unique IPs|
[sorbs_web](#sorbs_web)|[Sorbs.net](https://www.sorbs.net/) WEB exploits, extracted from deltas.|ipv4 hash:net|432 subnets, 433 unique IPs|
[spamhaus_drop](#spamhaus_drop)|[Spamhaus.org](http://www.spamhaus.org) DROP list (according to their site this list should be dropped at tier-1 ISPs globaly) - **excellent list**|ipv4 hash:net|653 subnets, 18340608 unique IPs|updated every 12 hours  from [this link](http://www.spamhaus.org/drop/drop.txt)
[spamhaus_edrop](#spamhaus_edrop)|[Spamhaus.org](http://www.spamhaus.org) EDROP (extended matches that should be used with DROP) - **excellent list**|ipv4 hash:net|56 subnets, 487424 unique IPs|updated every 12 hours  from [this link](http://www.spamhaus.org/drop/edrop.txt)
[sslbl](#sslbl)|[Abuse.ch SSL Blacklist](https://sslbl.abuse.ch/) bad SSL traffic related to malware or botnet activities - **excellent list**|ipv4 hash:ip|372 unique IPs|updated every 30 mins  from [this link](https://sslbl.abuse.ch/blacklist/sslipblacklist.csv)
stopforumspam_180d|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 180 days)|ipv4 hash:ip|disabled|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/listed_ip_180.zip)
[stopforumspam_1d](#stopforumspam_1d)|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers in the last 24 hours - **excellent list**|ipv4 hash:ip|6755 unique IPs|updated every 1 hour  from [this link](http://www.stopforumspam.com/downloads/listed_ip_1.zip)
[stopforumspam_30d](#stopforumspam_30d)|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 30 days)|ipv4 hash:ip|94424 unique IPs|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/listed_ip_30.zip)
stopforumspam_365d|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 365 days)|ipv4 hash:ip|disabled|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/listed_ip_365.zip)
[stopforumspam_7d](#stopforumspam_7d)|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 7 days)|ipv4 hash:ip|29338 unique IPs|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/listed_ip_7.zip)
stopforumspam_90d|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 90 days)|ipv4 hash:ip|disabled|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/listed_ip_90.zip)
stopforumspam_ever|[StopForumSpam.com](http://www.stopforumspam.com) all IPs used by forum spammers, **ever** (normally you don't want to use this ipset, use the hourly one which includes last 24 hours IPs or the 7 days one)|ipv4 hash:ip|disabled|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/bannedips.zip)
[tor_exits](#tor_exits)|[TorProject.org](https://www.torproject.org) list of all current TOR exit points (TorDNSEL)|ipv4 hash:ip|1128 unique IPs|updated every 30 mins  from [this link](https://check.torproject.org/exit-addresses)
[virbl](#virbl)|[VirBL](http://virbl.bit.nl/) is a project of which the idea was born during the RIPE-48 meeting. The plan was to get reports of virusscanning mailservers, and put the IP-addresses that were reported to send viruses on a blacklist.|ipv4 hash:ip|31 unique IPs|updated every 1 hour  from [this link](http://virbl.bit.nl/download/virbl.dnsbl.bit.nl.txt)
[voipbl](#voipbl)|[VoIPBL.org](http://www.voipbl.org/) a distributed VoIP blacklist that is aimed to protects against VoIP Fraud and minimizing abuse for network that have publicly accessible PBX's. Several algorithms, external sources and manual confirmation are used before they categorize something as an attack and determine the threat level.|ipv4 hash:net|10533 subnets, 10945 unique IPs|updated every 4 hours  from [this link](http://www.voipbl.org/update/)
[xroxy](#xroxy)|[xroxy.com](http://www.xroxy.com) open proxies (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|2159 unique IPs|updated every 1 hour  from [this link](http://www.xroxy.com/proxyrss.xml)
[zeus](#zeus)|[Abuse.ch Zeus tracker](https://zeustracker.abuse.ch) standard, contains the same data as the ZeuS IP blocklist (zeus_badips) but with the slight difference that it doesn't exclude hijacked websites (level 2) and free web hosting providers (level 3). This means that this blocklist contains all IPv4 addresses associated with ZeuS C&Cs which are currently being tracked by ZeuS Tracker. Hence this blocklist will likely cause some false positives. - **excellent list**|ipv4 hash:ip|230 unique IPs|updated every 30 mins  from [this link](https://zeustracker.abuse.ch/blocklist.php?download=ipblocklist)
[zeus_badips](#zeus_badips)|[Abuse.ch Zeus tracker](https://zeustracker.abuse.ch) badips includes IPv4 addresses that are used by the ZeuS trojan. It is the recommened blocklist if you want to block only ZeuS IPs. It excludes IP addresses that ZeuS Tracker believes to be hijacked (level 2) or belong to a free web hosting provider (level 3). Hence the false postive rate should be much lower compared to the standard ZeuS IP blocklist. **excellent list**|ipv4 hash:ip|202 unique IPs|updated every 30 mins  from [this link](https://zeustracker.abuse.ch/blocklist.php?download=badips)

# Comparison of ipsets

Below we compare each ipset against all other.


## alienvault_reputation

[AlienVault.com](https://www.alienvault.com/) IP reputation database (this list seems to include port scanning hosts and to be updated regularly, but we found no information about its retention policy)

Source is downloaded from [this link](https://reputation.alienvault.com/reputation.generic).

The last time downloaded was found to be dated: Wed Jun 10 22:01:17 UTC 2015.

The ipset `alienvault_reputation` has **182721** entries, **182721** unique IPs.

The following table shows the overlaps of `alienvault_reputation` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `alienvault_reputation`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `alienvault_reputation`.
- ` this % ` is the percentage **of this ipset (`alienvault_reputation`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|13319|0.0%|7.2%|
[openbl_60d](#openbl_60d)|7012|7012|6992|99.7%|3.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|6488|0.0%|3.5%|
[dragon_http](#dragon_http)|1044|273664|5638|2.0%|3.0%|
[firehol_level3](#firehol_level3)|110224|9627969|4896|0.0%|2.6%|
[et_block](#et_block)|1000|18344011|4764|0.0%|2.6%|
[firehol_level1](#firehol_level1)|5135|688894845|4597|0.0%|2.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|4445|0.0%|2.4%|
[dshield](#dshield)|20|5120|3085|60.2%|1.6%|
[openbl_30d](#openbl_30d)|2835|2835|2820|99.4%|1.5%|
[firehol_level2](#firehol_level2)|23356|34994|1387|3.9%|0.7%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|1372|0.0%|0.7%|
[blocklist_de](#blocklist_de)|29619|29619|1326|4.4%|0.7%|
[shunlist](#shunlist)|1234|1234|1223|99.1%|0.6%|
[blocklist_de_ssh](#blocklist_de_ssh)|3531|3531|1118|31.6%|0.6%|
[et_compromised](#et_compromised)|1721|1721|1113|64.6%|0.6%|
[bruteforceblocker](#bruteforceblocker)|1706|1706|1083|63.4%|0.5%|
[openbl_7d](#openbl_7d)|679|679|676|99.5%|0.3%|
[ciarmy](#ciarmy)|469|469|465|99.1%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|288|0.0%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|265|0.0%|0.1%|
[voipbl](#voipbl)|10533|10945|183|1.6%|0.1%|
[stopforumspam_30d](#stopforumspam_30d)|94424|94424|170|0.1%|0.0%|
[openbl_1d](#openbl_1d)|152|152|148|97.3%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|15454|15454|124|0.8%|0.0%|
[snort_ipfilter](#snort_ipfilter)|10158|10158|109|1.0%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|93|0.3%|0.0%|
[sorbs_spam](#sorbs_spam)|60429|61096|86|0.1%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|60429|61096|86|0.1%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|60429|61096|86|0.1%|0.0%|
[nixspam](#nixspam)|28015|28015|70|0.2%|0.0%|
[sslbl](#sslbl)|372|372|65|17.4%|0.0%|
[zeus](#zeus)|230|230|61|26.5%|0.0%|
[firehol_anonymous](#firehol_anonymous)|19001|83032|57|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|17317|17317|49|0.2%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6755|6755|47|0.6%|0.0%|
[dm_tor](#dm_tor)|6459|6459|42|0.6%|0.0%|
[bm_tor](#bm_tor)|6473|6473|42|0.6%|0.0%|
[et_tor](#et_tor)|6400|6400|39|0.6%|0.0%|
[firehol_proxies](#firehol_proxies)|12463|12723|38|0.2%|0.0%|
[zeus_badips](#zeus_badips)|202|202|37|18.3%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|183|183|35|19.1%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2412|2412|35|1.4%|0.0%|
[tor_exits](#tor_exits)|1128|1128|30|2.6%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|29|5.5%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4090|4090|20|0.4%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|2949|2949|19|0.6%|0.0%|
[php_commenters](#php_commenters)|430|430|18|4.1%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|79|79|18|22.7%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|15|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|14|0.0%|0.0%|
[iw_spamlist](#iw_spamlist)|3703|3703|13|0.3%|0.0%|
[php_harvesters](#php_harvesters)|392|392|12|3.0%|0.0%|
[malc0de](#malc0de)|313|313|10|3.1%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|1380|1380|9|0.6%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|8|0.6%|0.0%|
[php_dictionary](#php_dictionary)|702|702|7|0.9%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|6|0.4%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|65|65|6|9.2%|0.0%|
[xroxy](#xroxy)|2159|2159|5|0.2%|0.0%|
[php_spammers](#php_spammers)|700|700|5|0.7%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7624|7624|4|0.0%|0.0%|
[et_botcc](#et_botcc)|506|506|4|0.7%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2751|2751|3|0.1%|0.0%|
[proxz](#proxz)|1244|1244|3|0.2%|0.0%|
[nt_malware_irc](#nt_malware_irc)|43|43|2|4.6%|0.0%|
[feodo](#feodo)|105|105|2|1.9%|0.0%|
[proxyrss](#proxyrss)|1675|1675|1|0.0%|0.0%|
[nt_malware_http](#nt_malware_http)|69|69|1|1.4%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|1|0.1%|0.0%|

## blocklist_de

[Blocklist.de](https://www.blocklist.de/) IPs that have been detected by fail2ban in the last 48 hours - **excellent list**

Source is downloaded from [this link](http://lists.blocklist.de/lists/all.txt).

The last time downloaded was found to be dated: Wed Jun 10 23:42:05 UTC 2015.

The ipset `blocklist_de` has **29619** entries, **29619** unique IPs.

The following table shows the overlaps of `blocklist_de` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de`.
- ` this % ` is the percentage **of this ipset (`blocklist_de`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|23356|34994|29619|84.6%|100.0%|
[blocklist_de_mail](#blocklist_de_mail)|17317|17317|17317|100.0%|58.4%|
[blocklist_de_apache](#blocklist_de_apache)|15454|15454|15453|99.9%|52.1%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4090|4090|4090|100.0%|13.8%|
[firehol_level3](#firehol_level3)|110224|9627969|3956|0.0%|13.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|3766|0.0%|12.7%|
[blocklist_de_ssh](#blocklist_de_ssh)|3531|3531|3531|100.0%|11.9%|
[blocklist_de_bots](#blocklist_de_bots)|2949|2949|2949|100.0%|9.9%|
[stopforumspam_30d](#stopforumspam_30d)|94424|94424|2716|2.8%|9.1%|
[blocklist_de_imap](#blocklist_de_imap)|2412|2412|2412|100.0%|8.1%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|2163|7.3%|7.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|1583|0.0%|5.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|1555|0.0%|5.2%|
[stopforumspam_1d](#stopforumspam_1d)|6755|6755|1408|20.8%|4.7%|
[blocklist_de_ftp](#blocklist_de_ftp)|1380|1380|1379|99.9%|4.6%|
[alienvault_reputation](#alienvault_reputation)|182721|182721|1326|0.7%|4.4%|
[sorbs_spam](#sorbs_spam)|60429|61096|1307|2.1%|4.4%|
[sorbs_recent_spam](#sorbs_recent_spam)|60429|61096|1307|2.1%|4.4%|
[sorbs_new_spam](#sorbs_new_spam)|60429|61096|1307|2.1%|4.4%|
[openbl_60d](#openbl_60d)|7012|7012|952|13.5%|3.2%|
[openbl_30d](#openbl_30d)|2835|2835|762|26.8%|2.5%|
[nixspam](#nixspam)|28015|28015|692|2.4%|2.3%|
[firehol_anonymous](#firehol_anonymous)|19001|83032|671|0.8%|2.2%|
[et_compromised](#et_compromised)|1721|1721|643|37.3%|2.1%|
[firehol_proxies](#firehol_proxies)|12463|12723|638|5.0%|2.1%|
[bruteforceblocker](#bruteforceblocker)|1706|1706|634|37.1%|2.1%|
[ri_web_proxies](#ri_web_proxies)|7624|7624|446|5.8%|1.5%|
[shunlist](#shunlist)|1234|1234|424|34.3%|1.4%|
[openbl_7d](#openbl_7d)|679|679|391|57.5%|1.3%|
[firehol_level1](#firehol_level1)|5135|688894845|252|0.0%|0.8%|
[et_block](#et_block)|1000|18344011|247|0.0%|0.8%|
[proxyrss](#proxyrss)|1675|1675|228|13.6%|0.7%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|218|0.0%|0.7%|
[snort_ipfilter](#snort_ipfilter)|10158|10158|212|2.0%|0.7%|
[xroxy](#xroxy)|2159|2159|206|9.5%|0.6%|
[proxz](#proxz)|1244|1244|184|14.7%|0.6%|
[blocklist_de_strongips](#blocklist_de_strongips)|183|183|183|100.0%|0.6%|
[iw_spamlist](#iw_spamlist)|3703|3703|136|3.6%|0.4%|
[openbl_1d](#openbl_1d)|152|152|124|81.5%|0.4%|
[php_commenters](#php_commenters)|430|430|109|25.3%|0.3%|
[php_dictionary](#php_dictionary)|702|702|108|15.3%|0.3%|
[php_spammers](#php_spammers)|700|700|104|14.8%|0.3%|
[ri_connect_proxies](#ri_connect_proxies)|2751|2751|70|2.5%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|66|0.0%|0.2%|
[blocklist_de_sip](#blocklist_de_sip)|79|79|60|75.9%|0.2%|
[sorbs_web](#sorbs_web)|432|433|58|13.3%|0.1%|
[dragon_http](#dragon_http)|1044|273664|58|0.0%|0.1%|
[ciarmy](#ciarmy)|469|469|44|9.3%|0.1%|
[php_harvesters](#php_harvesters)|392|392|37|9.4%|0.1%|
[voipbl](#voipbl)|10533|10945|32|0.2%|0.1%|
[tor_exits](#tor_exits)|1128|1128|29|2.5%|0.0%|
[dshield](#dshield)|20|5120|29|0.5%|0.0%|
[et_tor](#et_tor)|6400|6400|20|0.3%|0.0%|
[dm_tor](#dm_tor)|6459|6459|19|0.2%|0.0%|
[bm_tor](#bm_tor)|6473|6473|19|0.2%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|11|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|9|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|8|1.5%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|5|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|4|0.6%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|2|0.1%|0.0%|
[zeus_badips](#zeus_badips)|202|202|1|0.4%|0.0%|
[zeus](#zeus)|230|230|1|0.4%|0.0%|
[iw_wormlist](#iw_wormlist)|33|33|1|3.0%|0.0%|

## blocklist_de_apache

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service Apache, Apache-DDOS, RFI-Attacks.

Source is downloaded from [this link](http://lists.blocklist.de/lists/apache.txt).

The last time downloaded was found to be dated: Wed Jun 10 23:28:07 UTC 2015.

The ipset `blocklist_de_apache` has **15454** entries, **15454** unique IPs.

The following table shows the overlaps of `blocklist_de_apache` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_apache`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_apache`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_apache`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|23356|34994|15453|44.1%|99.9%|
[blocklist_de](#blocklist_de)|29619|29619|15453|52.1%|99.9%|
[blocklist_de_mail](#blocklist_de_mail)|17317|17317|11060|63.8%|71.5%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4090|4090|4090|100.0%|26.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|2404|0.0%|15.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|1337|0.0%|8.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|1107|0.0%|7.1%|
[firehol_level3](#firehol_level3)|110224|9627969|325|0.0%|2.1%|
[stopforumspam_30d](#stopforumspam_30d)|94424|94424|233|0.2%|1.5%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|139|0.4%|0.8%|
[alienvault_reputation](#alienvault_reputation)|182721|182721|124|0.0%|0.8%|
[stopforumspam_1d](#stopforumspam_1d)|6755|6755|78|1.1%|0.5%|
[sorbs_spam](#sorbs_spam)|60429|61096|59|0.0%|0.3%|
[sorbs_recent_spam](#sorbs_recent_spam)|60429|61096|59|0.0%|0.3%|
[sorbs_new_spam](#sorbs_new_spam)|60429|61096|59|0.0%|0.3%|
[snort_ipfilter](#snort_ipfilter)|10158|10158|41|0.4%|0.2%|
[ciarmy](#ciarmy)|469|469|36|7.6%|0.2%|
[firehol_anonymous](#firehol_anonymous)|19001|83032|35|0.0%|0.2%|
[blocklist_de_strongips](#blocklist_de_strongips)|183|183|34|18.5%|0.2%|
[php_commenters](#php_commenters)|430|430|32|7.4%|0.2%|
[nixspam](#nixspam)|28015|28015|32|0.1%|0.2%|
[shunlist](#shunlist)|1234|1234|31|2.5%|0.2%|
[tor_exits](#tor_exits)|1128|1128|28|2.4%|0.1%|
[blocklist_de_bots](#blocklist_de_bots)|2949|2949|21|0.7%|0.1%|
[et_tor](#et_tor)|6400|6400|19|0.2%|0.1%|
[dm_tor](#dm_tor)|6459|6459|18|0.2%|0.1%|
[bm_tor](#bm_tor)|6473|6473|18|0.2%|0.1%|
[firehol_level1](#firehol_level1)|5135|688894845|14|0.0%|0.0%|
[et_block](#et_block)|1000|18344011|14|0.0%|0.0%|
[dragon_http](#dragon_http)|1044|273664|14|0.0%|0.0%|
[dshield](#dshield)|20|5120|9|0.1%|0.0%|
[php_spammers](#php_spammers)|700|700|8|1.1%|0.0%|
[openbl_60d](#openbl_60d)|7012|7012|7|0.0%|0.0%|
[openbl_30d](#openbl_30d)|2835|2835|7|0.2%|0.0%|
[firehol_proxies](#firehol_proxies)|12463|12723|7|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|5|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7624|7624|5|0.0%|0.0%|
[openbl_7d](#openbl_7d)|679|679|5|0.7%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|5|0.0%|0.0%|
[php_dictionary](#php_dictionary)|702|702|4|0.5%|0.0%|
[php_harvesters](#php_harvesters)|392|392|3|0.7%|0.0%|
[iw_spamlist](#iw_spamlist)|3703|3703|3|0.0%|0.0%|
[voipbl](#voipbl)|10533|10945|2|0.0%|0.0%|
[openbl_1d](#openbl_1d)|152|152|2|1.3%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|2|0.3%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|2|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2412|2412|1|0.0%|0.0%|

## blocklist_de_bots

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the RFI-Attacks, REG-Bots, IRC-Bots or BadBots (BadBots = he has posted a Spam-Comment on a open Forum or Wiki).

Source is downloaded from [this link](http://lists.blocklist.de/lists/bots.txt).

The last time downloaded was found to be dated: Wed Jun 10 23:42:11 UTC 2015.

The ipset `blocklist_de_bots` has **2949** entries, **2949** unique IPs.

The following table shows the overlaps of `blocklist_de_bots` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_bots`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_bots`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_bots`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|23356|34994|2949|8.4%|100.0%|
[blocklist_de](#blocklist_de)|29619|29619|2949|9.9%|100.0%|
[firehol_level3](#firehol_level3)|110224|9627969|2365|0.0%|80.1%|
[stopforumspam_30d](#stopforumspam_30d)|94424|94424|2327|2.4%|78.9%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|1949|6.6%|66.0%|
[stopforumspam_1d](#stopforumspam_1d)|6755|6755|1331|19.7%|45.1%|
[firehol_anonymous](#firehol_anonymous)|19001|83032|523|0.6%|17.7%|
[firehol_proxies](#firehol_proxies)|12463|12723|521|4.0%|17.6%|
[ri_web_proxies](#ri_web_proxies)|7624|7624|367|4.8%|12.4%|
[proxyrss](#proxyrss)|1675|1675|227|13.5%|7.6%|
[proxz](#proxz)|1244|1244|155|12.4%|5.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|155|0.0%|5.2%|
[xroxy](#xroxy)|2159|2159|153|7.0%|5.1%|
[blocklist_de_strongips](#blocklist_de_strongips)|183|183|135|73.7%|4.5%|
[php_commenters](#php_commenters)|430|430|87|20.2%|2.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|79|0.0%|2.6%|
[ri_connect_proxies](#ri_connect_proxies)|2751|2751|67|2.4%|2.2%|
[firehol_level1](#firehol_level1)|5135|688894845|60|0.0%|2.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|57|0.0%|1.9%|
[et_block](#et_block)|1000|18344011|57|0.0%|1.9%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|56|0.0%|1.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|40|0.0%|1.3%|
[sorbs_spam](#sorbs_spam)|60429|61096|34|0.0%|1.1%|
[sorbs_recent_spam](#sorbs_recent_spam)|60429|61096|34|0.0%|1.1%|
[sorbs_new_spam](#sorbs_new_spam)|60429|61096|34|0.0%|1.1%|
[nixspam](#nixspam)|28015|28015|34|0.1%|1.1%|
[php_harvesters](#php_harvesters)|392|392|26|6.6%|0.8%|
[php_spammers](#php_spammers)|700|700|24|3.4%|0.8%|
[snort_ipfilter](#snort_ipfilter)|10158|10158|21|0.2%|0.7%|
[blocklist_de_mail](#blocklist_de_mail)|17317|17317|21|0.1%|0.7%|
[blocklist_de_apache](#blocklist_de_apache)|15454|15454|21|0.1%|0.7%|
[php_dictionary](#php_dictionary)|702|702|20|2.8%|0.6%|
[alienvault_reputation](#alienvault_reputation)|182721|182721|19|0.0%|0.6%|
[sorbs_web](#sorbs_web)|432|433|5|1.1%|0.1%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|5|0.9%|0.1%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|4|0.0%|0.1%|
[iw_spamlist](#iw_spamlist)|3703|3703|4|0.1%|0.1%|
[dragon_http](#dragon_http)|1044|273664|4|0.0%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|2|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|2|0.3%|0.0%|
[tor_exits](#tor_exits)|1128|1128|1|0.0%|0.0%|
[openbl_60d](#openbl_60d)|7012|7012|1|0.0%|0.0%|
[openbl_30d](#openbl_30d)|2835|2835|1|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|1|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|1|0.0%|0.0%|
[et_compromised](#et_compromised)|1721|1721|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1706|1706|1|0.0%|0.0%|

## blocklist_de_bruteforce

[Blocklist.de](https://www.blocklist.de/) All IPs which attacks Joomlas, Wordpress and other Web-Logins with Brute-Force Logins.

Source is downloaded from [this link](http://lists.blocklist.de/lists/bruteforcelogin.txt).

The last time downloaded was found to be dated: Wed Jun 10 23:42:14 UTC 2015.

The ipset `blocklist_de_bruteforce` has **4090** entries, **4090** unique IPs.

The following table shows the overlaps of `blocklist_de_bruteforce` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_bruteforce`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_bruteforce`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_bruteforce`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|23356|34994|4090|11.6%|100.0%|
[blocklist_de_apache](#blocklist_de_apache)|15454|15454|4090|26.4%|100.0%|
[blocklist_de](#blocklist_de)|29619|29619|4090|13.8%|100.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|314|0.0%|7.6%|
[firehol_level3](#firehol_level3)|110224|9627969|120|0.0%|2.9%|
[stopforumspam_30d](#stopforumspam_30d)|94424|94424|93|0.0%|2.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|77|0.0%|1.8%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|66|0.2%|1.6%|
[sorbs_spam](#sorbs_spam)|60429|61096|59|0.0%|1.4%|
[sorbs_recent_spam](#sorbs_recent_spam)|60429|61096|59|0.0%|1.4%|
[sorbs_new_spam](#sorbs_new_spam)|60429|61096|59|0.0%|1.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|48|0.0%|1.1%|
[stopforumspam_1d](#stopforumspam_1d)|6755|6755|47|0.6%|1.1%|
[snort_ipfilter](#snort_ipfilter)|10158|10158|37|0.3%|0.9%|
[firehol_anonymous](#firehol_anonymous)|19001|83032|32|0.0%|0.7%|
[nixspam](#nixspam)|28015|28015|30|0.1%|0.7%|
[tor_exits](#tor_exits)|1128|1128|26|2.3%|0.6%|
[alienvault_reputation](#alienvault_reputation)|182721|182721|20|0.0%|0.4%|
[et_tor](#et_tor)|6400|6400|17|0.2%|0.4%|
[dm_tor](#dm_tor)|6459|6459|15|0.2%|0.3%|
[bm_tor](#bm_tor)|6473|6473|15|0.2%|0.3%|
[php_commenters](#php_commenters)|430|430|11|2.5%|0.2%|
[blocklist_de_strongips](#blocklist_de_strongips)|183|183|10|5.4%|0.2%|
[php_spammers](#php_spammers)|700|700|8|1.1%|0.1%|
[firehol_proxies](#firehol_proxies)|12463|12723|6|0.0%|0.1%|
[et_block](#et_block)|1000|18344011|6|0.0%|0.1%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|5|0.0%|0.1%|
[ri_web_proxies](#ri_web_proxies)|7624|7624|5|0.0%|0.1%|
[firehol_level1](#firehol_level1)|5135|688894845|5|0.0%|0.1%|
[php_dictionary](#php_dictionary)|702|702|4|0.5%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|4|0.0%|0.0%|
[dragon_http](#dragon_http)|1044|273664|4|0.0%|0.0%|
[iw_spamlist](#iw_spamlist)|3703|3703|3|0.0%|0.0%|
[php_harvesters](#php_harvesters)|392|392|2|0.5%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|2|0.0%|0.0%|
[voipbl](#voipbl)|10533|10945|1|0.0%|0.0%|
[shunlist](#shunlist)|1234|1234|1|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|1|0.1%|0.0%|

## blocklist_de_ftp

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours for attacks on the Service FTP.

Source is downloaded from [this link](http://lists.blocklist.de/lists/ftp.txt).

The last time downloaded was found to be dated: Wed Jun 10 23:28:07 UTC 2015.

The ipset `blocklist_de_ftp` has **1380** entries, **1380** unique IPs.

The following table shows the overlaps of `blocklist_de_ftp` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_ftp`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_ftp`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_ftp`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|23356|34994|1379|3.9%|99.9%|
[blocklist_de](#blocklist_de)|29619|29619|1379|4.6%|99.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|154|0.0%|11.1%|
[firehol_level3](#firehol_level3)|110224|9627969|26|0.0%|1.8%|
[stopforumspam_30d](#stopforumspam_30d)|94424|94424|19|0.0%|1.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|16|0.0%|1.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|13|0.0%|0.9%|
[alienvault_reputation](#alienvault_reputation)|182721|182721|9|0.0%|0.6%|
[sorbs_spam](#sorbs_spam)|60429|61096|8|0.0%|0.5%|
[sorbs_recent_spam](#sorbs_recent_spam)|60429|61096|8|0.0%|0.5%|
[sorbs_new_spam](#sorbs_new_spam)|60429|61096|8|0.0%|0.5%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|7|0.0%|0.5%|
[nixspam](#nixspam)|28015|28015|6|0.0%|0.4%|
[dragon_http](#dragon_http)|1044|273664|5|0.0%|0.3%|
[php_harvesters](#php_harvesters)|392|392|4|1.0%|0.2%|
[openbl_60d](#openbl_60d)|7012|7012|2|0.0%|0.1%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|2|0.0%|0.1%|
[firehol_anonymous](#firehol_anonymous)|19001|83032|2|0.0%|0.1%|
[blocklist_de_strongips](#blocklist_de_strongips)|183|183|2|1.0%|0.1%|
[sorbs_web](#sorbs_web)|432|433|1|0.2%|0.0%|
[openbl_7d](#openbl_7d)|679|679|1|0.1%|0.0%|
[openbl_30d](#openbl_30d)|2835|2835|1|0.0%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.0%|
[ciarmy](#ciarmy)|469|469|1|0.2%|0.0%|

## blocklist_de_imap

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours for attacks on the Service imap, sasl, pop3, etc.

Source is downloaded from [this link](http://lists.blocklist.de/lists/imap.txt).

The last time downloaded was found to be dated: Wed Jun 10 23:28:07 UTC 2015.

The ipset `blocklist_de_imap` has **2412** entries, **2412** unique IPs.

The following table shows the overlaps of `blocklist_de_imap` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_imap`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_imap`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_imap`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|23356|34994|2412|6.8%|100.0%|
[blocklist_de_mail](#blocklist_de_mail)|17317|17317|2412|13.9%|100.0%|
[blocklist_de](#blocklist_de)|29619|29619|2412|8.1%|100.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|305|0.0%|12.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|56|0.0%|2.3%|
[firehol_level3](#firehol_level3)|110224|9627969|43|0.0%|1.7%|
[alienvault_reputation](#alienvault_reputation)|182721|182721|35|0.0%|1.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|32|0.0%|1.3%|
[openbl_60d](#openbl_60d)|7012|7012|23|0.3%|0.9%|
[sorbs_spam](#sorbs_spam)|60429|61096|19|0.0%|0.7%|
[sorbs_recent_spam](#sorbs_recent_spam)|60429|61096|19|0.0%|0.7%|
[sorbs_new_spam](#sorbs_new_spam)|60429|61096|19|0.0%|0.7%|
[openbl_30d](#openbl_30d)|2835|2835|17|0.5%|0.7%|
[stopforumspam_30d](#stopforumspam_30d)|94424|94424|13|0.0%|0.5%|
[nixspam](#nixspam)|28015|28015|12|0.0%|0.4%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|10|0.0%|0.4%|
[firehol_level1](#firehol_level1)|5135|688894845|10|0.0%|0.4%|
[et_block](#et_block)|1000|18344011|10|0.0%|0.4%|
[snort_ipfilter](#snort_ipfilter)|10158|10158|6|0.0%|0.2%|
[openbl_7d](#openbl_7d)|679|679|6|0.8%|0.2%|
[dragon_http](#dragon_http)|1044|273664|6|0.0%|0.2%|
[shunlist](#shunlist)|1234|1234|4|0.3%|0.1%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|3|0.0%|0.1%|
[et_compromised](#et_compromised)|1721|1721|3|0.1%|0.1%|
[bruteforceblocker](#bruteforceblocker)|1706|1706|3|0.1%|0.1%|
[iw_spamlist](#iw_spamlist)|3703|3703|2|0.0%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2|0.0%|0.0%|
[ciarmy](#ciarmy)|469|469|2|0.4%|0.0%|
[xroxy](#xroxy)|2159|2159|1|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6755|6755|1|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2751|2751|1|0.0%|0.0%|
[php_harvesters](#php_harvesters)|392|392|1|0.2%|0.0%|
[openbl_1d](#openbl_1d)|152|152|1|0.6%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|1|0.0%|0.0%|
[firehol_proxies](#firehol_proxies)|12463|12723|1|0.0%|0.0%|
[firehol_anonymous](#firehol_anonymous)|19001|83032|1|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|15454|15454|1|0.0%|0.0%|

## blocklist_de_mail

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service Mail, Postfix.

Source is downloaded from [this link](http://lists.blocklist.de/lists/mail.txt).

The last time downloaded was found to be dated: Wed Jun 10 23:42:08 UTC 2015.

The ipset `blocklist_de_mail` has **17317** entries, **17317** unique IPs.

The following table shows the overlaps of `blocklist_de_mail` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_mail`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_mail`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_mail`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|23356|34994|17317|49.4%|100.0%|
[blocklist_de](#blocklist_de)|29619|29619|17317|58.4%|100.0%|
[blocklist_de_apache](#blocklist_de_apache)|15454|15454|11060|71.5%|63.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|2602|0.0%|15.0%|
[blocklist_de_imap](#blocklist_de_imap)|2412|2412|2412|100.0%|13.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|1383|0.0%|7.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|1265|0.0%|7.3%|
[sorbs_spam](#sorbs_spam)|60429|61096|1202|1.9%|6.9%|
[sorbs_recent_spam](#sorbs_recent_spam)|60429|61096|1202|1.9%|6.9%|
[sorbs_new_spam](#sorbs_new_spam)|60429|61096|1202|1.9%|6.9%|
[nixspam](#nixspam)|28015|28015|620|2.2%|3.5%|
[firehol_level3](#firehol_level3)|110224|9627969|398|0.0%|2.2%|
[stopforumspam_30d](#stopforumspam_30d)|94424|94424|257|0.2%|1.4%|
[snort_ipfilter](#snort_ipfilter)|10158|10158|154|1.5%|0.8%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|147|0.5%|0.8%|
[iw_spamlist](#iw_spamlist)|3703|3703|129|3.4%|0.7%|
[firehol_anonymous](#firehol_anonymous)|19001|83032|112|0.1%|0.6%|
[firehol_proxies](#firehol_proxies)|12463|12723|110|0.8%|0.6%|
[php_dictionary](#php_dictionary)|702|702|84|11.9%|0.4%|
[ri_web_proxies](#ri_web_proxies)|7624|7624|73|0.9%|0.4%|
[php_spammers](#php_spammers)|700|700|71|10.1%|0.4%|
[xroxy](#xroxy)|2159|2159|53|2.4%|0.3%|
[sorbs_web](#sorbs_web)|432|433|52|12.0%|0.3%|
[alienvault_reputation](#alienvault_reputation)|182721|182721|49|0.0%|0.2%|
[stopforumspam_1d](#stopforumspam_1d)|6755|6755|45|0.6%|0.2%|
[proxz](#proxz)|1244|1244|29|2.3%|0.1%|
[openbl_60d](#openbl_60d)|7012|7012|28|0.3%|0.1%|
[php_commenters](#php_commenters)|430|430|26|6.0%|0.1%|
[blocklist_de_strongips](#blocklist_de_strongips)|183|183|22|12.0%|0.1%|
[openbl_30d](#openbl_30d)|2835|2835|21|0.7%|0.1%|
[firehol_level1](#firehol_level1)|5135|688894845|21|0.0%|0.1%|
[et_block](#et_block)|1000|18344011|21|0.0%|0.1%|
[blocklist_de_bots](#blocklist_de_bots)|2949|2949|21|0.7%|0.1%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|20|0.0%|0.1%|
[dragon_http](#dragon_http)|1044|273664|17|0.0%|0.0%|
[openbl_7d](#openbl_7d)|679|679|7|1.0%|0.0%|
[php_harvesters](#php_harvesters)|392|392|5|1.2%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|5|0.0%|0.0%|
[shunlist](#shunlist)|1234|1234|4|0.3%|0.0%|
[et_compromised](#et_compromised)|1721|1721|4|0.2%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1706|1706|4|0.2%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2751|2751|3|0.1%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|0.0%|
[dm_tor](#dm_tor)|6459|6459|3|0.0%|0.0%|
[bm_tor](#bm_tor)|6473|6473|3|0.0%|0.0%|
[tor_exits](#tor_exits)|1128|1128|2|0.1%|0.0%|
[openbl_1d](#openbl_1d)|152|152|2|1.3%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|2|0.3%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|2|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|2|0.3%|0.0%|
[et_tor](#et_tor)|6400|6400|2|0.0%|0.0%|
[ciarmy](#ciarmy)|469|469|2|0.4%|0.0%|
[zeus_badips](#zeus_badips)|202|202|1|0.4%|0.0%|
[zeus](#zeus)|230|230|1|0.4%|0.0%|
[voipbl](#voipbl)|10533|10945|1|0.0%|0.0%|
[proxyrss](#proxyrss)|1675|1675|1|0.0%|0.0%|
[iw_wormlist](#iw_wormlist)|33|33|1|3.0%|0.0%|

## blocklist_de_sip

[Blocklist.de](https://www.blocklist.de/) All IP addresses that tried to login in a SIP, VOIP or Asterisk Server and are included in the IPs list from [infiltrated.net](www.infiltrated.net)

Source is downloaded from [this link](http://lists.blocklist.de/lists/sip.txt).

The last time downloaded was found to be dated: Wed Jun 10 23:42:10 UTC 2015.

The ipset `blocklist_de_sip` has **79** entries, **79** unique IPs.

The following table shows the overlaps of `blocklist_de_sip` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_sip`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_sip`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_sip`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|23356|34994|60|0.1%|75.9%|
[blocklist_de](#blocklist_de)|29619|29619|60|0.2%|75.9%|
[voipbl](#voipbl)|10533|10945|26|0.2%|32.9%|
[alienvault_reputation](#alienvault_reputation)|182721|182721|18|0.0%|22.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|10|0.0%|12.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|7|0.0%|8.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|6|0.0%|7.5%|
[firehol_level3](#firehol_level3)|110224|9627969|3|0.0%|3.7%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|2|0.0%|2.5%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|2|0.0%|2.5%|
[firehol_level1](#firehol_level1)|5135|688894845|2|0.0%|2.5%|
[et_block](#et_block)|1000|18344011|2|0.0%|2.5%|
[dragon_http](#dragon_http)|1044|273664|2|0.0%|2.5%|
[shunlist](#shunlist)|1234|1234|1|0.0%|1.2%|
[et_botcc](#et_botcc)|506|506|1|0.1%|1.2%|

## blocklist_de_ssh

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service SSH.

Source is downloaded from [this link](http://lists.blocklist.de/lists/ssh.txt).

The last time downloaded was found to be dated: Wed Jun 10 23:42:06 UTC 2015.

The ipset `blocklist_de_ssh` has **3531** entries, **3531** unique IPs.

The following table shows the overlaps of `blocklist_de_ssh` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_ssh`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_ssh`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_ssh`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|23356|34994|3531|10.0%|100.0%|
[blocklist_de](#blocklist_de)|29619|29619|3531|11.9%|100.0%|
[alienvault_reputation](#alienvault_reputation)|182721|182721|1118|0.6%|31.6%|
[firehol_level3](#firehol_level3)|110224|9627969|986|0.0%|27.9%|
[openbl_60d](#openbl_60d)|7012|7012|914|13.0%|25.8%|
[openbl_30d](#openbl_30d)|2835|2835|732|25.8%|20.7%|
[et_compromised](#et_compromised)|1721|1721|638|37.0%|18.0%|
[bruteforceblocker](#bruteforceblocker)|1706|1706|629|36.8%|17.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|516|0.0%|14.6%|
[shunlist](#shunlist)|1234|1234|387|31.3%|10.9%|
[openbl_7d](#openbl_7d)|679|679|378|55.6%|10.7%|
[firehol_level1](#firehol_level1)|5135|688894845|154|0.0%|4.3%|
[et_block](#et_block)|1000|18344011|153|0.0%|4.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|136|0.0%|3.8%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|134|0.0%|3.7%|
[openbl_1d](#openbl_1d)|152|152|120|78.9%|3.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|58|0.0%|1.6%|
[blocklist_de_strongips](#blocklist_de_strongips)|183|183|29|15.8%|0.8%|
[stopforumspam_30d](#stopforumspam_30d)|94424|94424|24|0.0%|0.6%|
[dshield](#dshield)|20|5120|20|0.3%|0.5%|
[dragon_http](#dragon_http)|1044|273664|16|0.0%|0.4%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|6|0.0%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|6|0.0%|0.1%|
[ciarmy](#ciarmy)|469|469|5|1.0%|0.1%|
[sorbs_spam](#sorbs_spam)|60429|61096|4|0.0%|0.1%|
[sorbs_recent_spam](#sorbs_recent_spam)|60429|61096|4|0.0%|0.1%|
[sorbs_new_spam](#sorbs_new_spam)|60429|61096|4|0.0%|0.1%|
[voipbl](#voipbl)|10533|10945|3|0.0%|0.0%|
[firehol_anonymous](#firehol_anonymous)|19001|83032|2|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7624|7624|1|0.0%|0.0%|
[php_spammers](#php_spammers)|700|700|1|0.1%|0.0%|
[php_commenters](#php_commenters)|430|430|1|0.2%|0.0%|
[nixspam](#nixspam)|28015|28015|1|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|1|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|1|0.0%|0.0%|
[firehol_proxies](#firehol_proxies)|12463|12723|1|0.0%|0.0%|
[et_tor](#et_tor)|6400|6400|1|0.0%|0.0%|
[dm_tor](#dm_tor)|6459|6459|1|0.0%|0.0%|
[bm_tor](#bm_tor)|6473|6473|1|0.0%|0.0%|

## blocklist_de_strongips

[Blocklist.de](https://www.blocklist.de/) All IPs which are older then 2 month and have more then 5.000 attacks.

Source is downloaded from [this link](http://lists.blocklist.de/lists/strongips.txt).

The last time downloaded was found to be dated: Wed Jun 10 23:42:13 UTC 2015.

The ipset `blocklist_de_strongips` has **183** entries, **183** unique IPs.

The following table shows the overlaps of `blocklist_de_strongips` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_strongips`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_strongips`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_strongips`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|23356|34994|183|0.5%|100.0%|
[blocklist_de](#blocklist_de)|29619|29619|183|0.6%|100.0%|
[firehol_level3](#firehol_level3)|110224|9627969|165|0.0%|90.1%|
[stopforumspam_30d](#stopforumspam_30d)|94424|94424|139|0.1%|75.9%|
[blocklist_de_bots](#blocklist_de_bots)|2949|2949|135|4.5%|73.7%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|118|0.4%|64.4%|
[stopforumspam_1d](#stopforumspam_1d)|6755|6755|113|1.6%|61.7%|
[php_commenters](#php_commenters)|430|430|48|11.1%|26.2%|
[alienvault_reputation](#alienvault_reputation)|182721|182721|35|0.0%|19.1%|
[blocklist_de_apache](#blocklist_de_apache)|15454|15454|34|0.2%|18.5%|
[blocklist_de_ssh](#blocklist_de_ssh)|3531|3531|29|0.8%|15.8%|
[openbl_60d](#openbl_60d)|7012|7012|25|0.3%|13.6%|
[openbl_7d](#openbl_7d)|679|679|24|3.5%|13.1%|
[openbl_30d](#openbl_30d)|2835|2835|24|0.8%|13.1%|
[blocklist_de_mail](#blocklist_de_mail)|17317|17317|22|0.1%|12.0%|
[shunlist](#shunlist)|1234|1234|19|1.5%|10.3%|
[openbl_1d](#openbl_1d)|152|152|17|11.1%|9.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|16|0.0%|8.7%|
[firehol_level1](#firehol_level1)|5135|688894845|12|0.0%|6.5%|
[et_block](#et_block)|1000|18344011|10|0.0%|5.4%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4090|4090|10|0.2%|5.4%|
[php_spammers](#php_spammers)|700|700|9|1.2%|4.9%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|8|0.0%|4.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|8|0.0%|4.3%|
[firehol_proxies](#firehol_proxies)|12463|12723|6|0.0%|3.2%|
[firehol_anonymous](#firehol_anonymous)|19001|83032|6|0.0%|3.2%|
[xroxy](#xroxy)|2159|2159|5|0.2%|2.7%|
[ri_web_proxies](#ri_web_proxies)|7624|7624|5|0.0%|2.7%|
[proxz](#proxz)|1244|1244|5|0.4%|2.7%|
[proxyrss](#proxyrss)|1675|1675|5|0.2%|2.7%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|4|0.0%|2.1%|
[php_dictionary](#php_dictionary)|702|702|4|0.5%|2.1%|
[php_harvesters](#php_harvesters)|392|392|3|0.7%|1.6%|
[nixspam](#nixspam)|28015|28015|3|0.0%|1.6%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|1.6%|
[sorbs_spam](#sorbs_spam)|60429|61096|2|0.0%|1.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|60429|61096|2|0.0%|1.0%|
[sorbs_new_spam](#sorbs_new_spam)|60429|61096|2|0.0%|1.0%|
[snort_ipfilter](#snort_ipfilter)|10158|10158|2|0.0%|1.0%|
[dragon_http](#dragon_http)|1044|273664|2|0.0%|1.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|1380|1380|2|0.1%|1.0%|
[sorbs_web](#sorbs_web)|432|433|1|0.2%|0.5%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|1|0.0%|0.5%|
[dshield](#dshield)|20|5120|1|0.0%|0.5%|

## bm_tor

[torstatus.blutmagie.de](https://torstatus.blutmagie.de) list of all TOR network servers

Source is downloaded from [this link](https://torstatus.blutmagie.de/ip_list_all.php/Tor_ip_list_ALL.csv).

The last time downloaded was found to be dated: Wed Jun 10 23:54:03 UTC 2015.

The ipset `bm_tor` has **6473** entries, **6473** unique IPs.

The following table shows the overlaps of `bm_tor` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `bm_tor`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `bm_tor`.
- ` this % ` is the percentage **of this ipset (`bm_tor`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_anonymous](#firehol_anonymous)|19001|83032|6473|7.7%|100.0%|
[dm_tor](#dm_tor)|6459|6459|6369|98.6%|98.3%|
[et_tor](#et_tor)|6400|6400|5947|92.9%|91.8%|
[firehol_level3](#firehol_level3)|110224|9627969|1098|0.0%|16.9%|
[snort_ipfilter](#snort_ipfilter)|10158|10158|1061|10.4%|16.3%|
[tor_exits](#tor_exits)|1128|1128|1021|90.5%|15.7%|
[stopforumspam_30d](#stopforumspam_30d)|94424|94424|642|0.6%|9.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|631|0.0%|9.7%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|521|1.7%|8.0%|
[firehol_level2](#firehol_level2)|23356|34994|392|1.1%|6.0%|
[stopforumspam_1d](#stopforumspam_1d)|6755|6755|383|5.6%|5.9%|
[firehol_proxies](#firehol_proxies)|12463|12723|239|1.8%|3.6%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|234|44.6%|3.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|181|0.0%|2.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|163|0.0%|2.5%|
[php_commenters](#php_commenters)|430|430|51|11.8%|0.7%|
[alienvault_reputation](#alienvault_reputation)|182721|182721|42|0.0%|0.6%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|22|0.0%|0.3%|
[openbl_60d](#openbl_60d)|7012|7012|20|0.2%|0.3%|
[blocklist_de](#blocklist_de)|29619|29619|19|0.0%|0.2%|
[blocklist_de_apache](#blocklist_de_apache)|15454|15454|18|0.1%|0.2%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4090|4090|15|0.3%|0.2%|
[dragon_http](#dragon_http)|1044|273664|11|0.0%|0.1%|
[php_harvesters](#php_harvesters)|392|392|7|1.7%|0.1%|
[ri_web_proxies](#ri_web_proxies)|7624|7624|5|0.0%|0.0%|
[php_spammers](#php_spammers)|700|700|5|0.7%|0.0%|
[sorbs_spam](#sorbs_spam)|60429|61096|4|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|60429|61096|4|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|60429|61096|4|0.0%|0.0%|
[php_dictionary](#php_dictionary)|702|702|4|0.5%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|4|0.0%|0.0%|
[voipbl](#voipbl)|10533|10945|3|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|3|0.0%|0.0%|
[nixspam](#nixspam)|28015|28015|3|0.0%|0.0%|
[firehol_level1](#firehol_level1)|5135|688894845|3|0.0%|0.0%|
[et_block](#et_block)|1000|18344011|3|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|17317|17317|3|0.0%|0.0%|
[xroxy](#xroxy)|2159|2159|2|0.0%|0.0%|
[shunlist](#shunlist)|1234|1234|1|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2751|2751|1|0.0%|0.0%|
[iw_spamlist](#iw_spamlist)|3703|3703|1|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3531|3531|1|0.0%|0.0%|

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
[fullbogons](#fullbogons)|3770|670213096|592708608|88.4%|100.0%|
[firehol_level1](#firehol_level1)|5135|688894845|592708608|86.0%|100.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|4194304|3.0%|0.7%|
[voipbl](#voipbl)|10533|10945|319|2.9%|0.0%|
[iw_spamlist](#iw_spamlist)|3703|3703|5|0.1%|0.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|5|0.0%|0.0%|
[firehol_level3](#firehol_level3)|110224|9627969|3|0.0%|0.0%|
[php_harvesters](#php_harvesters)|392|392|1|0.2%|0.0%|
[php_commenters](#php_commenters)|430|430|1|0.2%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.0%|
[ciarmy](#ciarmy)|469|469|1|0.2%|0.0%|

## bruteforceblocker

[danger.rulez.sk](http://danger.rulez.sk/) IPs detected by [bruteforceblocker](http://danger.rulez.sk/index.php/bruteforceblocker/) (fail2ban alternative for SSH on OpenBSD). This is an automatically generated list from users reporting failed authentication attempts. An IP seems to be included if 3 or more users report it. Its retention pocily seems 30 days.

Source is downloaded from [this link](http://danger.rulez.sk/projects/bruteforceblocker/blist.php).

The last time downloaded was found to be dated: Wed Jun 10 22:34:06 UTC 2015.

The ipset `bruteforceblocker` has **1706** entries, **1706** unique IPs.

The following table shows the overlaps of `bruteforceblocker` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `bruteforceblocker`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `bruteforceblocker`.
- ` this % ` is the percentage **of this ipset (`bruteforceblocker`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level3](#firehol_level3)|110224|9627969|1706|0.0%|100.0%|
[et_compromised](#et_compromised)|1721|1721|1666|96.8%|97.6%|
[alienvault_reputation](#alienvault_reputation)|182721|182721|1083|0.5%|63.4%|
[openbl_60d](#openbl_60d)|7012|7012|975|13.9%|57.1%|
[openbl_30d](#openbl_30d)|2835|2835|912|32.1%|53.4%|
[firehol_level2](#firehol_level2)|23356|34994|635|1.8%|37.2%|
[blocklist_de](#blocklist_de)|29619|29619|634|2.1%|37.1%|
[blocklist_de_ssh](#blocklist_de_ssh)|3531|3531|629|17.8%|36.8%|
[shunlist](#shunlist)|1234|1234|394|31.9%|23.0%|
[openbl_7d](#openbl_7d)|679|679|320|47.1%|18.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|156|0.0%|9.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|89|0.0%|5.2%|
[firehol_level1](#firehol_level1)|5135|688894845|81|0.0%|4.7%|
[et_block](#et_block)|1000|18344011|78|0.0%|4.5%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|70|0.0%|4.1%|
[openbl_1d](#openbl_1d)|152|152|63|41.4%|3.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|53|0.0%|3.1%|
[dragon_http](#dragon_http)|1044|273664|13|0.0%|0.7%|
[stopforumspam_30d](#stopforumspam_30d)|94424|94424|12|0.0%|0.7%|
[dshield](#dshield)|20|5120|11|0.2%|0.6%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|5|0.0%|0.2%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|4|0.0%|0.2%|
[blocklist_de_mail](#blocklist_de_mail)|17317|17317|4|0.0%|0.2%|
[voipbl](#voipbl)|10533|10945|3|0.0%|0.1%|
[sorbs_spam](#sorbs_spam)|60429|61096|3|0.0%|0.1%|
[sorbs_recent_spam](#sorbs_recent_spam)|60429|61096|3|0.0%|0.1%|
[sorbs_new_spam](#sorbs_new_spam)|60429|61096|3|0.0%|0.1%|
[firehol_proxies](#firehol_proxies)|12463|12723|3|0.0%|0.1%|
[firehol_anonymous](#firehol_anonymous)|19001|83032|3|0.0%|0.1%|
[blocklist_de_imap](#blocklist_de_imap)|2412|2412|3|0.1%|0.1%|
[proxz](#proxz)|1244|1244|2|0.1%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|2|0.0%|0.1%|
[ciarmy](#ciarmy)|469|469|2|0.4%|0.1%|
[xroxy](#xroxy)|2159|2159|1|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6755|6755|1|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|10158|10158|1|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7624|7624|1|0.0%|0.0%|
[proxyrss](#proxyrss)|1675|1675|1|0.0%|0.0%|
[php_spammers](#php_spammers)|700|700|1|0.1%|0.0%|
[php_commenters](#php_commenters)|430|430|1|0.2%|0.0%|
[nixspam](#nixspam)|28015|28015|1|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|2949|2949|1|0.0%|0.0%|

## ciarmy

[CIArmy.com](http://ciarmy.com/) IPs with poor Rogue Packet score that have not yet been identified as malicious by the community

Source is downloaded from [this link](http://cinsscore.com/list/ci-badguys.txt).

The last time downloaded was found to be dated: Wed Jun 10 22:15:06 UTC 2015.

The ipset `ciarmy` has **469** entries, **469** unique IPs.

The following table shows the overlaps of `ciarmy` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ciarmy`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ciarmy`.
- ` this % ` is the percentage **of this ipset (`ciarmy`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level3](#firehol_level3)|110224|9627969|469|0.0%|100.0%|
[alienvault_reputation](#alienvault_reputation)|182721|182721|465|0.2%|99.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|100|0.0%|21.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|50|0.0%|10.6%|
[firehol_level2](#firehol_level2)|23356|34994|44|0.1%|9.3%|
[blocklist_de](#blocklist_de)|29619|29619|44|0.1%|9.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|36|0.0%|7.6%|
[blocklist_de_apache](#blocklist_de_apache)|15454|15454|36|0.2%|7.6%|
[shunlist](#shunlist)|1234|1234|30|2.4%|6.3%|
[dragon_http](#dragon_http)|1044|273664|9|0.0%|1.9%|
[et_block](#et_block)|1000|18344011|6|0.0%|1.2%|
[blocklist_de_ssh](#blocklist_de_ssh)|3531|3531|5|0.1%|1.0%|
[firehol_level1](#firehol_level1)|5135|688894845|4|0.0%|0.8%|
[dshield](#dshield)|20|5120|3|0.0%|0.6%|
[stopforumspam_30d](#stopforumspam_30d)|94424|94424|2|0.0%|0.4%|
[openbl_7d](#openbl_7d)|679|679|2|0.2%|0.4%|
[openbl_60d](#openbl_60d)|7012|7012|2|0.0%|0.4%|
[openbl_30d](#openbl_30d)|2835|2835|2|0.0%|0.4%|
[et_compromised](#et_compromised)|1721|1721|2|0.1%|0.4%|
[bruteforceblocker](#bruteforceblocker)|1706|1706|2|0.1%|0.4%|
[blocklist_de_mail](#blocklist_de_mail)|17317|17317|2|0.0%|0.4%|
[blocklist_de_imap](#blocklist_de_imap)|2412|2412|2|0.0%|0.4%|
[voipbl](#voipbl)|10533|10945|1|0.0%|0.2%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|1|0.0%|0.2%|
[openbl_1d](#openbl_1d)|152|152|1|0.6%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.2%|
[fullbogons](#fullbogons)|3770|670213096|1|0.0%|0.2%|
[bogons](#bogons)|13|592708608|1|0.0%|0.2%|
[blocklist_de_ftp](#blocklist_de_ftp)|1380|1380|1|0.0%|0.2%|

## cleanmx_viruses

[Clean-MX.de](http://support.clean-mx.de/clean-mx/viruses.php) IPs with viruses

Source is downloaded from [this link](http://support.clean-mx.de/clean-mx/xmlviruses.php?sort=id%20desc&response=alive).

The last time downloaded was found to be dated: Wed Jun 10 21:00:49 UTC 2015.

The ipset `cleanmx_viruses` has **65** entries, **65** unique IPs.

The following table shows the overlaps of `cleanmx_viruses` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `cleanmx_viruses`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `cleanmx_viruses`.
- ` this % ` is the percentage **of this ipset (`cleanmx_viruses`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level3](#firehol_level3)|110224|9627969|65|0.0%|100.0%|
[alienvault_reputation](#alienvault_reputation)|182721|182721|6|0.0%|9.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|5|0.0%|7.6%|
[snort_ipfilter](#snort_ipfilter)|10158|10158|1|0.0%|1.5%|
[malc0de](#malc0de)|313|313|1|0.3%|1.5%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|1.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|1|0.0%|1.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|1|0.0%|1.5%|

## dm_tor

[dan.me.uk](https://www.dan.me.uk) dynamic list of TOR nodes

Source is downloaded from [this link](https://www.dan.me.uk/torlist/).

The last time downloaded was found to be dated: Wed Jun 10 23:36:06 UTC 2015.

The ipset `dm_tor` has **6459** entries, **6459** unique IPs.

The following table shows the overlaps of `dm_tor` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `dm_tor`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `dm_tor`.
- ` this % ` is the percentage **of this ipset (`dm_tor`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_anonymous](#firehol_anonymous)|19001|83032|6459|7.7%|100.0%|
[bm_tor](#bm_tor)|6473|6473|6369|98.3%|98.6%|
[et_tor](#et_tor)|6400|6400|5957|93.0%|92.2%|
[firehol_level3](#firehol_level3)|110224|9627969|1097|0.0%|16.9%|
[snort_ipfilter](#snort_ipfilter)|10158|10158|1060|10.4%|16.4%|
[tor_exits](#tor_exits)|1128|1128|1017|90.1%|15.7%|
[stopforumspam_30d](#stopforumspam_30d)|94424|94424|645|0.6%|9.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|638|0.0%|9.8%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|523|1.7%|8.0%|
[firehol_level2](#firehol_level2)|23356|34994|392|1.1%|6.0%|
[stopforumspam_1d](#stopforumspam_1d)|6755|6755|383|5.6%|5.9%|
[firehol_proxies](#firehol_proxies)|12463|12723|238|1.8%|3.6%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|233|44.4%|3.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|180|0.0%|2.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|165|0.0%|2.5%|
[php_commenters](#php_commenters)|430|430|51|11.8%|0.7%|
[alienvault_reputation](#alienvault_reputation)|182721|182721|42|0.0%|0.6%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|22|0.0%|0.3%|
[openbl_60d](#openbl_60d)|7012|7012|20|0.2%|0.3%|
[blocklist_de](#blocklist_de)|29619|29619|19|0.0%|0.2%|
[blocklist_de_apache](#blocklist_de_apache)|15454|15454|18|0.1%|0.2%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4090|4090|15|0.3%|0.2%|
[dragon_http](#dragon_http)|1044|273664|11|0.0%|0.1%|
[php_harvesters](#php_harvesters)|392|392|7|1.7%|0.1%|
[ri_web_proxies](#ri_web_proxies)|7624|7624|5|0.0%|0.0%|
[php_spammers](#php_spammers)|700|700|5|0.7%|0.0%|
[sorbs_spam](#sorbs_spam)|60429|61096|4|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|60429|61096|4|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|60429|61096|4|0.0%|0.0%|
[php_dictionary](#php_dictionary)|702|702|4|0.5%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|4|0.0%|0.0%|
[firehol_level1](#firehol_level1)|5135|688894845|4|0.0%|0.0%|
[voipbl](#voipbl)|10533|10945|3|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|3|0.0%|0.0%|
[nixspam](#nixspam)|28015|28015|3|0.0%|0.0%|
[et_block](#et_block)|1000|18344011|3|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|17317|17317|3|0.0%|0.0%|
[xroxy](#xroxy)|2159|2159|2|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|1|0.0%|0.0%|
[shunlist](#shunlist)|1234|1234|1|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2751|2751|1|0.0%|0.0%|
[iw_spamlist](#iw_spamlist)|3703|3703|1|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3531|3531|1|0.0%|0.0%|

## dragon_http

[Dragon Search Group](http://www.dragonresearchgroup.org/) IPs that have been seen sending HTTP requests to Dragon Research Pods in the last 7 days. This report lists hosts that are highly suspicious and are likely conducting malicious HTTP attacks. LEGITIMATE SEARCH ENGINE BOTS MAY BE IN THIS LIST. This report is informational.  It is not a blacklist, but some operators may choose to use it to help protect their networks and hosts in the forms of automated reporting and mitigation services.

Source is downloaded from [this link](http://www.dragonresearchgroup.org/insight/http-report.txt).

The last time downloaded was found to be dated: Wed Jun 10 02:00:07 UTC 2015.

The ipset `dragon_http` has **1044** entries, **273664** unique IPs.

The following table shows the overlaps of `dragon_http` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `dragon_http`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `dragon_http`.
- ` this % ` is the percentage **of this ipset (`dragon_http`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|19712|0.0%|7.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|12216|0.0%|4.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|7370|0.0%|2.6%|
[alienvault_reputation](#alienvault_reputation)|182721|182721|5638|3.0%|2.0%|
[firehol_level1](#firehol_level1)|5135|688894845|1281|0.0%|0.4%|
[et_block](#et_block)|1000|18344011|1024|0.0%|0.3%|
[dshield](#dshield)|20|5120|1024|20.0%|0.3%|
[firehol_level3](#firehol_level3)|110224|9627969|566|0.0%|0.2%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|256|0.0%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|256|0.0%|0.0%|
[openbl_60d](#openbl_60d)|7012|7012|223|3.1%|0.0%|
[openbl_30d](#openbl_30d)|2835|2835|154|5.4%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|94424|94424|115|0.1%|0.0%|
[firehol_level2](#firehol_level2)|23356|34994|68|0.1%|0.0%|
[sorbs_spam](#sorbs_spam)|60429|61096|61|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|60429|61096|61|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|60429|61096|61|0.0%|0.0%|
[openbl_7d](#openbl_7d)|679|679|60|8.8%|0.0%|
[blocklist_de](#blocklist_de)|29619|29619|58|0.1%|0.0%|
[firehol_anonymous](#firehol_anonymous)|19001|83032|39|0.0%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|37|0.1%|0.0%|
[shunlist](#shunlist)|1234|1234|37|2.9%|0.0%|
[nixspam](#nixspam)|28015|28015|32|0.1%|0.0%|
[firehol_proxies](#firehol_proxies)|12463|12723|29|0.2%|0.0%|
[voipbl](#voipbl)|10533|10945|25|0.2%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|24|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|17317|17317|17|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7624|7624|16|0.2%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3531|3531|16|0.4%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|15454|15454|14|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1706|1706|13|0.7%|0.0%|
[et_tor](#et_tor)|6400|6400|11|0.1%|0.0%|
[et_compromised](#et_compromised)|1721|1721|11|0.6%|0.0%|
[dm_tor](#dm_tor)|6459|6459|11|0.1%|0.0%|
[bm_tor](#bm_tor)|6473|6473|11|0.1%|0.0%|
[ciarmy](#ciarmy)|469|469|9|1.9%|0.0%|
[xroxy](#xroxy)|2159|2159|8|0.3%|0.0%|
[openbl_1d](#openbl_1d)|152|152|8|5.2%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6755|6755|7|0.1%|0.0%|
[snort_ipfilter](#snort_ipfilter)|10158|10158|7|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|6|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2412|2412|6|0.2%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|1380|1380|5|0.3%|0.0%|
[proxz](#proxz)|1244|1244|4|0.3%|0.0%|
[iw_spamlist](#iw_spamlist)|3703|3703|4|0.1%|0.0%|
[et_botcc](#et_botcc)|506|506|4|0.7%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4090|4090|4|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|2949|2949|4|0.1%|0.0%|
[zeus_badips](#zeus_badips)|202|202|3|1.4%|0.0%|
[zeus](#zeus)|230|230|3|1.3%|0.0%|
[tor_exits](#tor_exits)|1128|1128|3|0.2%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2751|2751|3|0.1%|0.0%|
[proxyrss](#proxyrss)|1675|1675|3|0.1%|0.0%|
[malc0de](#malc0de)|313|313|3|0.9%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|3|0.2%|0.0%|
[php_dictionary](#php_dictionary)|702|702|2|0.2%|0.0%|
[php_commenters](#php_commenters)|430|430|2|0.4%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|2|0.3%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|2|0.1%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|183|183|2|1.0%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|79|79|2|2.5%|0.0%|
[sslbl](#sslbl)|372|372|1|0.2%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|1|0.1%|0.0%|

## dshield

[DShield.org](https://dshield.org/) top 20 attacking class C (/24) subnets over the last three days - **excellent list**

Source is downloaded from [this link](http://feeds.dshield.org/block.txt).

The last time downloaded was found to be dated: Wed Jun 10 23:56:25 UTC 2015.

The ipset `dshield` has **20** entries, **5120** unique IPs.

The following table shows the overlaps of `dshield` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `dshield`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `dshield`.
- ` this % ` is the percentage **of this ipset (`dshield`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level1](#firehol_level1)|5135|688894845|5120|0.0%|100.0%|
[alienvault_reputation](#alienvault_reputation)|182721|182721|3085|1.6%|60.2%|
[et_block](#et_block)|1000|18344011|1792|0.0%|35.0%|
[dragon_http](#dragon_http)|1044|273664|1024|0.3%|20.0%|
[firehol_level3](#firehol_level3)|110224|9627969|60|0.0%|1.1%|
[openbl_60d](#openbl_60d)|7012|7012|58|0.8%|1.1%|
[openbl_30d](#openbl_30d)|2835|2835|39|1.3%|0.7%|
[firehol_level2](#firehol_level2)|23356|34994|30|0.0%|0.5%|
[blocklist_de](#blocklist_de)|29619|29619|29|0.0%|0.5%|
[shunlist](#shunlist)|1234|1234|22|1.7%|0.4%|
[blocklist_de_ssh](#blocklist_de_ssh)|3531|3531|20|0.5%|0.3%|
[bruteforceblocker](#bruteforceblocker)|1706|1706|11|0.6%|0.2%|
[et_compromised](#et_compromised)|1721|1721|10|0.5%|0.1%|
[openbl_7d](#openbl_7d)|679|679|9|1.3%|0.1%|
[blocklist_de_apache](#blocklist_de_apache)|15454|15454|9|0.0%|0.1%|
[stopforumspam_30d](#stopforumspam_30d)|94424|94424|4|0.0%|0.0%|
[openbl_1d](#openbl_1d)|152|152|3|1.9%|0.0%|
[ciarmy](#ciarmy)|469|469|3|0.6%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|2|0.0%|0.0%|
[malc0de](#malc0de)|313|313|2|0.6%|0.0%|
[sorbs_spam](#sorbs_spam)|60429|61096|1|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|60429|61096|1|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|60429|61096|1|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|1|0.0%|0.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|1|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|183|183|1|0.5%|0.0%|

## et_block

[EmergingThreats.net](http://www.emergingthreats.net/) default blacklist (at the time of writing includes spamhaus DROP, dshield and abuse.ch trackers, which are available separately too - prefer to use the direct ipsets instead of this, they seem to lag a bit in updates)

Source is downloaded from [this link](http://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt).

The last time downloaded was found to be dated: Wed Jun 10 04:30:01 UTC 2015.

The ipset `et_block` has **1000** entries, **18344011** unique IPs.

The following table shows the overlaps of `et_block` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `et_block`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `et_block`.
- ` this % ` is the percentage **of this ipset (`et_block`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level1](#firehol_level1)|5135|688894845|18340682|2.6%|99.9%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|18338560|99.9%|99.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|8532520|2.4%|46.5%|
[firehol_level3](#firehol_level3)|110224|9627969|6933378|72.0%|37.7%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|6932480|75.5%|37.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|2272548|0.2%|12.3%|
[fullbogons](#fullbogons)|3770|670213096|151552|0.0%|0.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|130394|0.0%|0.7%|
[alienvault_reputation](#alienvault_reputation)|182721|182721|4764|2.6%|0.0%|
[dshield](#dshield)|20|5120|1792|35.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1042|0.3%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|94424|94424|1025|1.0%|0.0%|
[dragon_http](#dragon_http)|1044|273664|1024|0.3%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|517|0.1%|0.0%|
[firehol_level2](#firehol_level2)|23356|34994|310|0.8%|0.0%|
[openbl_60d](#openbl_60d)|7012|7012|301|4.2%|0.0%|
[snort_ipfilter](#snort_ipfilter)|10158|10158|298|2.9%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|295|1.0%|0.0%|
[blocklist_de](#blocklist_de)|29619|29619|247|0.8%|0.0%|
[zeus](#zeus)|230|230|228|99.1%|0.0%|
[zeus_badips](#zeus_badips)|202|202|202|100.0%|0.0%|
[openbl_30d](#openbl_30d)|2835|2835|163|5.7%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3531|3531|153|4.3%|0.0%|
[shunlist](#shunlist)|1234|1234|113|9.1%|0.0%|
[nixspam](#nixspam)|28015|28015|109|0.3%|0.0%|
[et_compromised](#et_compromised)|1721|1721|109|6.3%|0.0%|
[feodo](#feodo)|105|105|104|99.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1706|1706|78|4.5%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6755|6755|77|1.1%|0.0%|
[openbl_7d](#openbl_7d)|679|679|61|8.9%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|2949|2949|57|1.9%|0.0%|
[sslbl](#sslbl)|372|372|38|10.2%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|30|2.3%|0.0%|
[php_commenters](#php_commenters)|430|430|29|6.7%|0.0%|
[sorbs_spam](#sorbs_spam)|60429|61096|22|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|60429|61096|22|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|60429|61096|22|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|17317|17317|21|0.1%|0.0%|
[openbl_1d](#openbl_1d)|152|152|18|11.8%|0.0%|
[voipbl](#voipbl)|10533|10945|14|0.1%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|15454|15454|14|0.0%|0.0%|
[palevo](#palevo)|13|13|13|100.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|183|183|10|5.4%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2412|2412|10|0.4%|0.0%|
[php_dictionary](#php_dictionary)|702|702|6|0.8%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|6|0.4%|0.0%|
[firehol_anonymous](#firehol_anonymous)|19001|83032|6|0.0%|0.0%|
[ciarmy](#ciarmy)|469|469|6|1.2%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4090|4090|6|0.1%|0.0%|
[malc0de](#malc0de)|313|313|5|1.5%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|5|0.0%|0.0%|
[php_spammers](#php_spammers)|700|700|4|0.5%|0.0%|
[nt_malware_http](#nt_malware_http)|69|69|4|5.7%|0.0%|
[nt_malware_irc](#nt_malware_irc)|43|43|3|6.9%|0.0%|
[iw_spamlist](#iw_spamlist)|3703|3703|3|0.0%|0.0%|
[firehol_proxies](#firehol_proxies)|12463|12723|3|0.0%|0.0%|
[et_tor](#et_tor)|6400|6400|3|0.0%|0.0%|
[dm_tor](#dm_tor)|6459|6459|3|0.0%|0.0%|
[bm_tor](#bm_tor)|6473|6473|3|0.0%|0.0%|
[tor_exits](#tor_exits)|1128|1128|2|0.1%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|2|0.3%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|79|79|2|2.5%|0.0%|
[php_harvesters](#php_harvesters)|392|392|1|0.2%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|1|0.1%|0.0%|
[et_botcc](#et_botcc)|506|506|1|0.1%|0.0%|

## et_botcc

[EmergingThreats.net Command and Control IPs](http://doc.emergingthreats.net/bin/view/Main/BotCC) These IPs are updates every 24 hours and should be considered VERY highly reliable indications that a host is communicating with a known and active Bot or Malware command and control server - (although they say this includes abuse.ch trackers, it does not - most probably it is the shadowserver.org C&C list)

Source is downloaded from [this link](http://rules.emergingthreats.net/fwrules/emerging-PIX-CC.rules).

The last time downloaded was found to be dated: Wed Jun 10 04:30:01 UTC 2015.

The ipset `et_botcc` has **506** entries, **506** unique IPs.

The following table shows the overlaps of `et_botcc` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `et_botcc`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `et_botcc`.
- ` this % ` is the percentage **of this ipset (`et_botcc`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|77|0.0%|15.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|40|0.0%|7.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|20|0.0%|3.9%|
[dragon_http](#dragon_http)|1044|273664|4|0.0%|0.7%|
[alienvault_reputation](#alienvault_reputation)|182721|182721|4|0.0%|0.7%|
[firehol_level3](#firehol_level3)|110224|9627969|3|0.0%|0.5%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|1|0.0%|0.1%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|1|0.0%|0.1%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|1|0.0%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.1%|
[firehol_level1](#firehol_level1)|5135|688894845|1|0.0%|0.1%|
[et_block](#et_block)|1000|18344011|1|0.0%|0.1%|
[blocklist_de_sip](#blocklist_de_sip)|79|79|1|1.2%|0.1%|

## et_compromised

[EmergingThreats.net compromised hosts](http://doc.emergingthreats.net/bin/view/Main/CompromisedHost) - (this seems to be based on bruteforceblocker)

Source is downloaded from [this link](http://rules.emergingthreats.net/blockrules/compromised-ips.txt).

The last time downloaded was found to be dated: Wed Jun 10 04:30:07 UTC 2015.

The ipset `et_compromised` has **1721** entries, **1721** unique IPs.

The following table shows the overlaps of `et_compromised` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `et_compromised`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `et_compromised`.
- ` this % ` is the percentage **of this ipset (`et_compromised`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level3](#firehol_level3)|110224|9627969|1704|0.0%|99.0%|
[bruteforceblocker](#bruteforceblocker)|1706|1706|1666|97.6%|96.8%|
[alienvault_reputation](#alienvault_reputation)|182721|182721|1113|0.6%|64.6%|
[openbl_60d](#openbl_60d)|7012|7012|1009|14.3%|58.6%|
[openbl_30d](#openbl_30d)|2835|2835|941|33.1%|54.6%|
[firehol_level2](#firehol_level2)|23356|34994|644|1.8%|37.4%|
[blocklist_de](#blocklist_de)|29619|29619|643|2.1%|37.3%|
[blocklist_de_ssh](#blocklist_de_ssh)|3531|3531|638|18.0%|37.0%|
[shunlist](#shunlist)|1234|1234|424|34.3%|24.6%|
[openbl_7d](#openbl_7d)|679|679|324|47.7%|18.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|152|0.0%|8.8%|
[firehol_level1](#firehol_level1)|5135|688894845|111|0.0%|6.4%|
[et_block](#et_block)|1000|18344011|109|0.0%|6.3%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|101|0.0%|5.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|85|0.0%|4.9%|
[openbl_1d](#openbl_1d)|152|152|63|41.4%|3.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|52|0.0%|3.0%|
[stopforumspam_30d](#stopforumspam_30d)|94424|94424|12|0.0%|0.6%|
[dragon_http](#dragon_http)|1044|273664|11|0.0%|0.6%|
[dshield](#dshield)|20|5120|10|0.1%|0.5%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|5|0.0%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|5|0.0%|0.2%|
[blocklist_de_mail](#blocklist_de_mail)|17317|17317|4|0.0%|0.2%|
[voipbl](#voipbl)|10533|10945|3|0.0%|0.1%|
[sorbs_spam](#sorbs_spam)|60429|61096|3|0.0%|0.1%|
[sorbs_recent_spam](#sorbs_recent_spam)|60429|61096|3|0.0%|0.1%|
[sorbs_new_spam](#sorbs_new_spam)|60429|61096|3|0.0%|0.1%|
[firehol_proxies](#firehol_proxies)|12463|12723|3|0.0%|0.1%|
[firehol_anonymous](#firehol_anonymous)|19001|83032|3|0.0%|0.1%|
[blocklist_de_imap](#blocklist_de_imap)|2412|2412|3|0.1%|0.1%|
[proxz](#proxz)|1244|1244|2|0.1%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|2|0.0%|0.1%|
[ciarmy](#ciarmy)|469|469|2|0.4%|0.1%|
[xroxy](#xroxy)|2159|2159|1|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6755|6755|1|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|10158|10158|1|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7624|7624|1|0.0%|0.0%|
[proxyrss](#proxyrss)|1675|1675|1|0.0%|0.0%|
[php_spammers](#php_spammers)|700|700|1|0.1%|0.0%|
[php_commenters](#php_commenters)|430|430|1|0.2%|0.0%|
[nixspam](#nixspam)|28015|28015|1|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|2949|2949|1|0.0%|0.0%|

## et_tor

[EmergingThreats.net](http://www.emergingthreats.net/) [list](http://doc.emergingthreats.net/bin/view/Main/TorRules) of TOR network IPs

Source is downloaded from [this link](http://rules.emergingthreats.net/blockrules/emerging-tor.rules).

The last time downloaded was found to be dated: Wed Jun 10 04:30:08 UTC 2015.

The ipset `et_tor` has **6400** entries, **6400** unique IPs.

The following table shows the overlaps of `et_tor` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `et_tor`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `et_tor`.
- ` this % ` is the percentage **of this ipset (`et_tor`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_anonymous](#firehol_anonymous)|19001|83032|6016|7.2%|94.0%|
[dm_tor](#dm_tor)|6459|6459|5957|92.2%|93.0%|
[bm_tor](#bm_tor)|6473|6473|5947|91.8%|92.9%|
[firehol_level3](#firehol_level3)|110224|9627969|1126|0.0%|17.5%|
[snort_ipfilter](#snort_ipfilter)|10158|10158|1089|10.7%|17.0%|
[tor_exits](#tor_exits)|1128|1128|999|88.5%|15.6%|
[stopforumspam_30d](#stopforumspam_30d)|94424|94424|649|0.6%|10.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|625|0.0%|9.7%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|530|1.8%|8.2%|
[firehol_level2](#firehol_level2)|23356|34994|396|1.1%|6.1%|
[stopforumspam_1d](#stopforumspam_1d)|6755|6755|384|5.6%|6.0%|
[firehol_proxies](#firehol_proxies)|12463|12723|238|1.8%|3.7%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|234|44.6%|3.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|181|0.0%|2.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|165|0.0%|2.5%|
[php_commenters](#php_commenters)|430|430|51|11.8%|0.7%|
[alienvault_reputation](#alienvault_reputation)|182721|182721|39|0.0%|0.6%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|22|0.0%|0.3%|
[openbl_60d](#openbl_60d)|7012|7012|20|0.2%|0.3%|
[blocklist_de](#blocklist_de)|29619|29619|20|0.0%|0.3%|
[blocklist_de_apache](#blocklist_de_apache)|15454|15454|19|0.1%|0.2%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4090|4090|17|0.4%|0.2%|
[dragon_http](#dragon_http)|1044|273664|11|0.0%|0.1%|
[php_harvesters](#php_harvesters)|392|392|7|1.7%|0.1%|
[php_spammers](#php_spammers)|700|700|5|0.7%|0.0%|
[sorbs_spam](#sorbs_spam)|60429|61096|4|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|60429|61096|4|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|60429|61096|4|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7624|7624|4|0.0%|0.0%|
[php_dictionary](#php_dictionary)|702|702|4|0.5%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|4|0.0%|0.0%|
[voipbl](#voipbl)|10533|10945|3|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|3|0.0%|0.0%|
[nixspam](#nixspam)|28015|28015|3|0.0%|0.0%|
[firehol_level1](#firehol_level1)|5135|688894845|3|0.0%|0.0%|
[et_block](#et_block)|1000|18344011|3|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|17317|17317|2|0.0%|0.0%|
[xroxy](#xroxy)|2159|2159|1|0.0%|0.0%|
[shunlist](#shunlist)|1234|1234|1|0.0%|0.0%|
[iw_spamlist](#iw_spamlist)|3703|3703|1|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3531|3531|1|0.0%|0.0%|

## feodo

[Abuse.ch Feodo tracker](https://feodotracker.abuse.ch) trojan includes IPs which are being used by Feodo (also known as Cridex or Bugat) which commits ebanking fraud - **excellent list**

Source is downloaded from [this link](https://feodotracker.abuse.ch/blocklist/?download=ipblocklist).

The last time downloaded was found to be dated: Wed Jun 10 23:54:21 UTC 2015.

The ipset `feodo` has **105** entries, **105** unique IPs.

The following table shows the overlaps of `feodo` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `feodo`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `feodo`.
- ` this % ` is the percentage **of this ipset (`feodo`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level1](#firehol_level1)|5135|688894845|105|0.0%|100.0%|
[et_block](#et_block)|1000|18344011|104|0.0%|99.0%|
[snort_ipfilter](#snort_ipfilter)|10158|10158|83|0.8%|79.0%|
[firehol_level3](#firehol_level3)|110224|9627969|83|0.0%|79.0%|
[sslbl](#sslbl)|372|372|38|10.2%|36.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|11|0.0%|10.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|3|0.0%|2.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|3|0.0%|2.8%|
[alienvault_reputation](#alienvault_reputation)|182721|182721|2|0.0%|1.9%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.9%|

## firehol_anonymous

**FireHOL Anonymous** - Known anonymizing IPs. (includes: firehol_proxies anonymous bm_tor dm_tor tor_exits)

Source is downloaded from [this link]().

The last time downloaded was found to be dated: Sun Jun  7 22:20:34 UTC 2015.

The ipset `firehol_anonymous` has **19001** entries, **83032** unique IPs.

The following table shows the overlaps of `firehol_anonymous` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `firehol_anonymous`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `firehol_anonymous`.
- ` this % ` is the percentage **of this ipset (`firehol_anonymous`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_proxies](#firehol_proxies)|12463|12723|12723|100.0%|15.3%|
[ri_web_proxies](#ri_web_proxies)|7624|7624|7624|100.0%|9.1%|
[firehol_level3](#firehol_level3)|110224|9627969|6704|0.0%|8.0%|
[bm_tor](#bm_tor)|6473|6473|6473|100.0%|7.7%|
[dm_tor](#dm_tor)|6459|6459|6459|100.0%|7.7%|
[stopforumspam_30d](#stopforumspam_30d)|94424|94424|6120|6.4%|7.3%|
[et_tor](#et_tor)|6400|6400|6016|94.0%|7.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|3440|0.0%|4.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|2895|0.0%|3.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|2888|0.0%|3.4%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|2786|9.4%|3.3%|
[ri_connect_proxies](#ri_connect_proxies)|2751|2751|2751|100.0%|3.3%|
[xroxy](#xroxy)|2159|2159|2159|100.0%|2.6%|
[proxyrss](#proxyrss)|1675|1675|1675|100.0%|2.0%|
[firehol_level2](#firehol_level2)|23356|34994|1460|4.1%|1.7%|
[snort_ipfilter](#snort_ipfilter)|10158|10158|1246|12.2%|1.5%|
[proxz](#proxz)|1244|1244|1244|100.0%|1.4%|
[tor_exits](#tor_exits)|1128|1128|1128|100.0%|1.3%|
[stopforumspam_1d](#stopforumspam_1d)|6755|6755|1081|16.0%|1.3%|
[blocklist_de](#blocklist_de)|29619|29619|671|2.2%|0.8%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|663|100.0%|0.7%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|524|100.0%|0.6%|
[blocklist_de_bots](#blocklist_de_bots)|2949|2949|523|17.7%|0.6%|
[sorbs_spam](#sorbs_spam)|60429|61096|186|0.3%|0.2%|
[sorbs_recent_spam](#sorbs_recent_spam)|60429|61096|186|0.3%|0.2%|
[sorbs_new_spam](#sorbs_new_spam)|60429|61096|186|0.3%|0.2%|
[nixspam](#nixspam)|28015|28015|174|0.6%|0.2%|
[blocklist_de_mail](#blocklist_de_mail)|17317|17317|112|0.6%|0.1%|
[php_dictionary](#php_dictionary)|702|702|95|13.5%|0.1%|
[php_commenters](#php_commenters)|430|430|82|19.0%|0.0%|
[php_spammers](#php_spammers)|700|700|80|11.4%|0.0%|
[voipbl](#voipbl)|10533|10945|79|0.7%|0.0%|
[alienvault_reputation](#alienvault_reputation)|182721|182721|57|0.0%|0.0%|
[dragon_http](#dragon_http)|1044|273664|39|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|15454|15454|35|0.2%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4090|4090|32|0.7%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|29|0.0%|0.0%|
[openbl_60d](#openbl_60d)|7012|7012|23|0.3%|0.0%|
[sorbs_web](#sorbs_web)|432|433|22|5.0%|0.0%|
[iw_spamlist](#iw_spamlist)|3703|3703|15|0.4%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|15|0.0%|0.0%|
[php_harvesters](#php_harvesters)|392|392|12|3.0%|0.0%|
[firehol_level1](#firehol_level1)|5135|688894845|8|0.0%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|7|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|6|0.0%|0.0%|
[et_block](#et_block)|1000|18344011|6|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|183|183|6|3.2%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|3|0.2%|0.0%|
[et_compromised](#et_compromised)|1721|1721|3|0.1%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1706|1706|3|0.1%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3531|3531|2|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|1380|1380|2|0.1%|0.0%|
[sslbl](#sslbl)|372|372|1|0.2%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|1|0.0%|0.0%|
[shunlist](#shunlist)|1234|1234|1|0.0%|0.0%|
[openbl_30d](#openbl_30d)|2835|2835|1|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2412|2412|1|0.0%|0.0%|

## firehol_level1

**FireHOL Level 1** - Maximum protection without false positives. (includes: fullbogons dshield feodo palevo sslbl zeus spamhaus_drop spamhaus_edrop)

Source is downloaded from [this link]().

The last time downloaded was found to be dated: Sun Jun  7 22:15:43 UTC 2015.

The ipset `firehol_level1` has **5135** entries, **688894845** unique IPs.

The following table shows the overlaps of `firehol_level1` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `firehol_level1`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `firehol_level1`.
- ` this % ` is the percentage **of this ipset (`firehol_level1`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[fullbogons](#fullbogons)|3770|670213096|670213096|100.0%|97.2%|
[bogons](#bogons)|13|592708608|592708608|100.0%|86.0%|
[et_block](#et_block)|1000|18344011|18340682|99.9%|2.6%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|18340608|100.0%|2.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|8867461|2.5%|1.2%|
[firehol_level3](#firehol_level3)|110224|9627969|7500215|77.9%|1.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|7498240|81.6%|1.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|4637346|3.3%|0.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|2570275|0.3%|0.3%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|487424|100.0%|0.0%|
[dshield](#dshield)|20|5120|5120|100.0%|0.0%|
[alienvault_reputation](#alienvault_reputation)|182721|182721|4597|2.5%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1932|0.5%|0.0%|
[dragon_http](#dragon_http)|1044|273664|1281|0.4%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|94424|94424|1103|1.1%|0.0%|
[sslbl](#sslbl)|372|372|372|100.0%|0.0%|
[voipbl](#voipbl)|10533|10945|333|3.0%|0.0%|
[firehol_level2](#firehol_level2)|23356|34994|317|0.9%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|304|1.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|10158|10158|301|2.9%|0.0%|
[openbl_60d](#openbl_60d)|7012|7012|296|4.2%|0.0%|
[blocklist_de](#blocklist_de)|29619|29619|252|0.8%|0.0%|
[zeus](#zeus)|230|230|230|100.0%|0.0%|
[zeus_badips](#zeus_badips)|202|202|202|100.0%|0.0%|
[shunlist](#shunlist)|1234|1234|175|14.1%|0.0%|
[openbl_30d](#openbl_30d)|2835|2835|161|5.6%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3531|3531|154|4.3%|0.0%|
[et_compromised](#et_compromised)|1721|1721|111|6.4%|0.0%|
[nixspam](#nixspam)|28015|28015|110|0.3%|0.0%|
[feodo](#feodo)|105|105|105|100.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1706|1706|81|4.7%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6755|6755|80|1.1%|0.0%|
[openbl_7d](#openbl_7d)|679|679|60|8.8%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|2949|2949|60|2.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|40|2.7%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|39|3.0%|0.0%|
[php_commenters](#php_commenters)|430|430|38|8.8%|0.0%|
[sorbs_spam](#sorbs_spam)|60429|61096|26|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|60429|61096|26|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|60429|61096|26|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|17317|17317|21|0.1%|0.0%|
[openbl_1d](#openbl_1d)|152|152|18|11.8%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|18|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|15454|15454|14|0.0%|0.0%|
[palevo](#palevo)|13|13|13|100.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|183|183|12|6.5%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2412|2412|10|0.4%|0.0%|
[nt_malware_http](#nt_malware_http)|69|69|8|11.5%|0.0%|
[iw_spamlist](#iw_spamlist)|3703|3703|8|0.2%|0.0%|
[firehol_anonymous](#firehol_anonymous)|19001|83032|8|0.0%|0.0%|
[malc0de](#malc0de)|313|313|7|2.2%|0.0%|
[php_dictionary](#php_dictionary)|702|702|6|0.8%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4090|4090|5|0.1%|0.0%|
[php_spammers](#php_spammers)|700|700|4|0.5%|0.0%|
[firehol_proxies](#firehol_proxies)|12463|12723|4|0.0%|0.0%|
[dm_tor](#dm_tor)|6459|6459|4|0.0%|0.0%|
[ciarmy](#ciarmy)|469|469|4|0.8%|0.0%|
[php_harvesters](#php_harvesters)|392|392|3|0.7%|0.0%|
[nt_malware_irc](#nt_malware_irc)|43|43|3|6.9%|0.0%|
[et_tor](#et_tor)|6400|6400|3|0.0%|0.0%|
[bm_tor](#bm_tor)|6473|6473|3|0.0%|0.0%|
[tor_exits](#tor_exits)|1128|1128|2|0.1%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|2|0.3%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|79|79|2|2.5%|0.0%|
[virbl](#virbl)|31|31|1|3.2%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7624|7624|1|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|1|0.1%|0.0%|
[et_botcc](#et_botcc)|506|506|1|0.1%|0.0%|

## firehol_level2

**FireHOL Level 2** - Maximum protection from attacks took place in the last 48 hours. (includes: openbl_1d blocklist_de stopforumspam_1d)

Source is downloaded from [this link]().

The last time downloaded was found to be dated: Sun Jun  7 22:20:34 UTC 2015.

The ipset `firehol_level2` has **23356** entries, **34994** unique IPs.

The following table shows the overlaps of `firehol_level2` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `firehol_level2`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `firehol_level2`.
- ` this % ` is the percentage **of this ipset (`firehol_level2`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|29619|29619|29619|100.0%|84.6%|
[blocklist_de_mail](#blocklist_de_mail)|17317|17317|17317|100.0%|49.4%|
[blocklist_de_apache](#blocklist_de_apache)|15454|15454|15453|99.9%|44.1%|
[firehol_level3](#firehol_level3)|110224|9627969|8319|0.0%|23.7%|
[stopforumspam_30d](#stopforumspam_30d)|94424|94424|7037|7.4%|20.1%|
[stopforumspam_1d](#stopforumspam_1d)|6755|6755|6755|100.0%|19.3%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|4819|16.4%|13.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|4179|0.0%|11.9%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4090|4090|4090|100.0%|11.6%|
[blocklist_de_ssh](#blocklist_de_ssh)|3531|3531|3531|100.0%|10.0%|
[blocklist_de_bots](#blocklist_de_bots)|2949|2949|2949|100.0%|8.4%|
[blocklist_de_imap](#blocklist_de_imap)|2412|2412|2412|100.0%|6.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|1729|0.0%|4.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|1678|0.0%|4.7%|
[firehol_anonymous](#firehol_anonymous)|19001|83032|1460|1.7%|4.1%|
[alienvault_reputation](#alienvault_reputation)|182721|182721|1387|0.7%|3.9%|
[blocklist_de_ftp](#blocklist_de_ftp)|1380|1380|1379|99.9%|3.9%|
[sorbs_spam](#sorbs_spam)|60429|61096|1318|2.1%|3.7%|
[sorbs_recent_spam](#sorbs_recent_spam)|60429|61096|1318|2.1%|3.7%|
[sorbs_new_spam](#sorbs_new_spam)|60429|61096|1318|2.1%|3.7%|
[firehol_proxies](#firehol_proxies)|12463|12723|1247|9.8%|3.5%|
[openbl_60d](#openbl_60d)|7012|7012|997|14.2%|2.8%|
[openbl_30d](#openbl_30d)|2835|2835|788|27.7%|2.2%|
[nixspam](#nixspam)|28015|28015|703|2.5%|2.0%|
[ri_web_proxies](#ri_web_proxies)|7624|7624|685|8.9%|1.9%|
[et_compromised](#et_compromised)|1721|1721|644|37.4%|1.8%|
[bruteforceblocker](#bruteforceblocker)|1706|1706|635|37.2%|1.8%|
[snort_ipfilter](#snort_ipfilter)|10158|10158|599|5.8%|1.7%|
[proxyrss](#proxyrss)|1675|1675|438|26.1%|1.2%|
[shunlist](#shunlist)|1234|1234|426|34.5%|1.2%|
[openbl_7d](#openbl_7d)|679|679|417|61.4%|1.1%|
[tor_exits](#tor_exits)|1128|1128|408|36.1%|1.1%|
[et_tor](#et_tor)|6400|6400|396|6.1%|1.1%|
[dm_tor](#dm_tor)|6459|6459|392|6.0%|1.1%|
[bm_tor](#bm_tor)|6473|6473|392|6.0%|1.1%|
[xroxy](#xroxy)|2159|2159|333|15.4%|0.9%|
[firehol_level1](#firehol_level1)|5135|688894845|317|0.0%|0.9%|
[et_block](#et_block)|1000|18344011|310|0.0%|0.8%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|279|0.0%|0.7%|
[proxz](#proxz)|1244|1244|271|21.7%|0.7%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|228|43.5%|0.6%|
[php_commenters](#php_commenters)|430|430|198|46.0%|0.5%|
[blocklist_de_strongips](#blocklist_de_strongips)|183|183|183|100.0%|0.5%|
[openbl_1d](#openbl_1d)|152|152|152|100.0%|0.4%|
[ri_connect_proxies](#ri_connect_proxies)|2751|2751|147|5.3%|0.4%|
[iw_spamlist](#iw_spamlist)|3703|3703|139|3.7%|0.3%|
[php_dictionary](#php_dictionary)|702|702|116|16.5%|0.3%|
[php_spammers](#php_spammers)|700|700|114|16.2%|0.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|91|0.0%|0.2%|
[dragon_http](#dragon_http)|1044|273664|68|0.0%|0.1%|
[php_harvesters](#php_harvesters)|392|392|60|15.3%|0.1%|
[blocklist_de_sip](#blocklist_de_sip)|79|79|60|75.9%|0.1%|
[sorbs_web](#sorbs_web)|432|433|58|13.3%|0.1%|
[ciarmy](#ciarmy)|469|469|44|9.3%|0.1%|
[voipbl](#voipbl)|10533|10945|36|0.3%|0.1%|
[dshield](#dshield)|20|5120|30|0.5%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|21|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|14|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|7|1.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|6|0.0%|0.0%|
[zeus_badips](#zeus_badips)|202|202|3|1.4%|0.0%|
[zeus](#zeus)|230|230|3|1.3%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|3|0.2%|0.0%|
[iw_wormlist](#iw_wormlist)|33|33|1|3.0%|0.0%|
[fullbogons](#fullbogons)|3770|670213096|1|0.0%|0.0%|

## firehol_level3

**FireHOL Level 3** - All the bad IPs in last 30 days. (includes: openbl_30d stopforumspam_30d virbl malc0de shunlist malwaredomainlist bruteforceblocker ciarmy cleanmx_viruses snort_ipfilter ib_bluetack_spyware ib_bluetack_hijacked ib_bluetack_webexploit php_commenters php_dictionary php_harvesters php_spammers iw_wormlist)

Source is downloaded from [this link]().

The last time downloaded was found to be dated: Sun Jun  7 22:20:34 UTC 2015.

The ipset `firehol_level3` has **110224** entries, **9627969** unique IPs.

The following table shows the overlaps of `firehol_level3` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `firehol_level3`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `firehol_level3`.
- ` this % ` is the percentage **of this ipset (`firehol_level3`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|9177856|100.0%|95.3%|
[firehol_level1](#firehol_level1)|5135|688894845|7500215|1.0%|77.9%|
[et_block](#et_block)|1000|18344011|6933378|37.7%|72.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|6933037|37.8%|72.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|2537317|0.7%|26.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|919965|0.1%|9.5%|
[fullbogons](#fullbogons)|3770|670213096|566693|0.0%|5.8%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|339173|100.0%|3.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|161588|0.1%|1.6%|
[stopforumspam_30d](#stopforumspam_30d)|94424|94424|94424|100.0%|0.9%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|29338|100.0%|0.3%|
[snort_ipfilter](#snort_ipfilter)|10158|10158|10158|100.0%|0.1%|
[firehol_level2](#firehol_level2)|23356|34994|8319|23.7%|0.0%|
[firehol_anonymous](#firehol_anonymous)|19001|83032|6704|8.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6755|6755|5630|83.3%|0.0%|
[firehol_proxies](#firehol_proxies)|12463|12723|5569|43.7%|0.0%|
[alienvault_reputation](#alienvault_reputation)|182721|182721|4896|2.6%|0.0%|
[blocklist_de](#blocklist_de)|29619|29619|3956|13.3%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7624|7624|3654|47.9%|0.0%|
[openbl_60d](#openbl_60d)|7012|7012|2964|42.2%|0.0%|
[openbl_30d](#openbl_30d)|2835|2835|2835|100.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|2949|2949|2365|80.1%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1706|1706|1706|100.0%|0.0%|
[et_compromised](#et_compromised)|1721|1721|1704|99.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2751|2751|1546|56.1%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|1450|100.0%|0.0%|
[sorbs_spam](#sorbs_spam)|60429|61096|1398|2.2%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|60429|61096|1398|2.2%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|60429|61096|1398|2.2%|0.0%|
[xroxy](#xroxy)|2159|2159|1292|59.8%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|1288|100.0%|0.0%|
[shunlist](#shunlist)|1234|1234|1234|100.0%|0.0%|
[et_tor](#et_tor)|6400|6400|1126|17.5%|0.0%|
[bm_tor](#bm_tor)|6473|6473|1098|16.9%|0.0%|
[tor_exits](#tor_exits)|1128|1128|1097|97.2%|0.0%|
[dm_tor](#dm_tor)|6459|6459|1097|16.9%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3531|3531|986|27.9%|0.0%|
[proxz](#proxz)|1244|1244|737|59.2%|0.0%|
[proxyrss](#proxyrss)|1675|1675|707|42.2%|0.0%|
[php_dictionary](#php_dictionary)|702|702|702|100.0%|0.0%|
[php_spammers](#php_spammers)|700|700|700|100.0%|0.0%|
[openbl_7d](#openbl_7d)|679|679|679|100.0%|0.0%|
[dragon_http](#dragon_http)|1044|273664|566|0.2%|0.0%|
[nixspam](#nixspam)|28015|28015|561|2.0%|0.0%|
[ciarmy](#ciarmy)|469|469|469|100.0%|0.0%|
[php_commenters](#php_commenters)|430|430|430|100.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|17317|17317|398|2.2%|0.0%|
[php_harvesters](#php_harvesters)|392|392|392|100.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|343|65.4%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|15454|15454|325|2.1%|0.0%|
[malc0de](#malc0de)|313|313|313|100.0%|0.0%|
[zeus](#zeus)|230|230|203|88.2%|0.0%|
[zeus_badips](#zeus_badips)|202|202|180|89.1%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|183|183|165|90.1%|0.0%|
[openbl_1d](#openbl_1d)|152|152|148|97.3%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4090|4090|120|2.9%|0.0%|
[sslbl](#sslbl)|372|372|93|25.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|88|0.0%|0.0%|
[iw_spamlist](#iw_spamlist)|3703|3703|84|2.2%|0.0%|
[feodo](#feodo)|105|105|83|79.0%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|65|65|65|100.0%|0.0%|
[dshield](#dshield)|20|5120|60|1.1%|0.0%|
[sorbs_web](#sorbs_web)|432|433|59|13.6%|0.0%|
[voipbl](#voipbl)|10533|10945|57|0.5%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2412|2412|43|1.7%|0.0%|
[iw_wormlist](#iw_wormlist)|33|33|33|100.0%|0.0%|
[virbl](#virbl)|31|31|31|100.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|1380|1380|26|1.8%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|24|3.6%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|24|0.0%|0.0%|
[palevo](#palevo)|13|13|11|84.6%|0.0%|
[nt_malware_http](#nt_malware_http)|69|69|3|4.3%|0.0%|
[et_botcc](#et_botcc)|506|506|3|0.5%|0.0%|
[bogons](#bogons)|13|592708608|3|0.0%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|79|79|3|3.7%|0.0%|
[sorbs_socks](#sorbs_socks)|3|3|1|33.3%|0.0%|
[sorbs_misc](#sorbs_misc)|3|3|1|33.3%|0.0%|
[sorbs_http](#sorbs_http)|3|3|1|33.3%|0.0%|
[nt_malware_irc](#nt_malware_irc)|43|43|1|2.3%|0.0%|

## firehol_proxies

**FireHOL Proxies** - Known open proxies in the last 30 days. (includes: ib_bluetack_proxies maxmind_proxy_fraud proxyrss proxz ri_connect_proxies ri_web_proxies xroxy)

Source is downloaded from [this link]().

The last time downloaded was found to be dated: Sun Jun  7 22:20:34 UTC 2015.

The ipset `firehol_proxies` has **12463** entries, **12723** unique IPs.

The following table shows the overlaps of `firehol_proxies` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `firehol_proxies`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `firehol_proxies`.
- ` this % ` is the percentage **of this ipset (`firehol_proxies`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_anonymous](#firehol_anonymous)|19001|83032|12723|15.3%|100.0%|
[ri_web_proxies](#ri_web_proxies)|7624|7624|7624|100.0%|59.9%|
[firehol_level3](#firehol_level3)|110224|9627969|5569|0.0%|43.7%|
[stopforumspam_30d](#stopforumspam_30d)|94424|94424|5509|5.8%|43.2%|
[ri_connect_proxies](#ri_connect_proxies)|2751|2751|2751|100.0%|21.6%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|2433|8.2%|19.1%|
[xroxy](#xroxy)|2159|2159|2159|100.0%|16.9%|
[proxyrss](#proxyrss)|1675|1675|1675|100.0%|13.1%|
[firehol_level2](#firehol_level2)|23356|34994|1247|3.5%|9.8%|
[proxz](#proxz)|1244|1244|1244|100.0%|9.7%|
[stopforumspam_1d](#stopforumspam_1d)|6755|6755|883|13.0%|6.9%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|663|100.0%|5.2%|
[blocklist_de](#blocklist_de)|29619|29619|638|2.1%|5.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|528|0.0%|4.1%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|524|100.0%|4.1%|
[blocklist_de_bots](#blocklist_de_bots)|2949|2949|521|17.6%|4.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|393|0.0%|3.0%|
[snort_ipfilter](#snort_ipfilter)|10158|10158|320|3.1%|2.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|288|0.0%|2.2%|
[bm_tor](#bm_tor)|6473|6473|239|3.6%|1.8%|
[et_tor](#et_tor)|6400|6400|238|3.7%|1.8%|
[dm_tor](#dm_tor)|6459|6459|238|3.6%|1.8%|
[tor_exits](#tor_exits)|1128|1128|231|20.4%|1.8%|
[sorbs_spam](#sorbs_spam)|60429|61096|181|0.2%|1.4%|
[sorbs_recent_spam](#sorbs_recent_spam)|60429|61096|181|0.2%|1.4%|
[sorbs_new_spam](#sorbs_new_spam)|60429|61096|181|0.2%|1.4%|
[nixspam](#nixspam)|28015|28015|168|0.5%|1.3%|
[blocklist_de_mail](#blocklist_de_mail)|17317|17317|110|0.6%|0.8%|
[php_dictionary](#php_dictionary)|702|702|94|13.3%|0.7%|
[php_commenters](#php_commenters)|430|430|80|18.6%|0.6%|
[php_spammers](#php_spammers)|700|700|78|11.1%|0.6%|
[alienvault_reputation](#alienvault_reputation)|182721|182721|38|0.0%|0.2%|
[dragon_http](#dragon_http)|1044|273664|29|0.0%|0.2%|
[sorbs_web](#sorbs_web)|432|433|22|5.0%|0.1%|
[openbl_60d](#openbl_60d)|7012|7012|20|0.2%|0.1%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|15|0.0%|0.1%|
[iw_spamlist](#iw_spamlist)|3703|3703|14|0.3%|0.1%|
[php_harvesters](#php_harvesters)|392|392|12|3.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|11|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|15454|15454|7|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|183|183|6|3.2%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4090|4090|6|0.1%|0.0%|
[firehol_level1](#firehol_level1)|5135|688894845|4|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|3|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|3|0.2%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|0.0%|
[et_compromised](#et_compromised)|1721|1721|3|0.1%|0.0%|
[et_block](#et_block)|1000|18344011|3|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1706|1706|3|0.1%|0.0%|
[voipbl](#voipbl)|10533|10945|2|0.0%|0.0%|
[sslbl](#sslbl)|372|372|1|0.2%|0.0%|
[shunlist](#shunlist)|1234|1234|1|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3531|3531|1|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2412|2412|1|0.0%|0.0%|

## fullbogons

[Team-Cymru.org](http://www.team-cymru.org) IP space that has been allocated to an RIR, but not assigned by that RIR to an actual ISP or other end-user - **excellent list - use it only your internet interface**

Source is downloaded from [this link](http://www.team-cymru.org/Services/Bogons/fullbogons-ipv4.txt).

The last time downloaded was found to be dated: Wed Jun 10 09:35:04 UTC 2015.

The ipset `fullbogons` has **3770** entries, **670213096** unique IPs.

The following table shows the overlaps of `fullbogons` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `fullbogons`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `fullbogons`.
- ` this % ` is the percentage **of this ipset (`fullbogons`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level1](#firehol_level1)|5135|688894845|670213096|97.2%|100.0%|
[bogons](#bogons)|13|592708608|592708608|100.0%|88.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|4236143|3.0%|0.6%|
[firehol_level3](#firehol_level3)|110224|9627969|566693|5.8%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|565760|6.1%|0.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|264841|0.0%|0.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|252415|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|151552|0.8%|0.0%|
[et_block](#et_block)|1000|18344011|151552|0.8%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|890|0.2%|0.0%|
[voipbl](#voipbl)|10533|10945|319|2.9%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|33|2.2%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|13|0.0%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|9|0.6%|0.0%|
[iw_spamlist](#iw_spamlist)|3703|3703|5|0.1%|0.0%|
[nt_malware_http](#nt_malware_http)|69|69|4|5.7%|0.0%|
[virbl](#virbl)|31|31|1|3.2%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|94424|94424|1|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6755|6755|1|0.0%|0.0%|
[php_harvesters](#php_harvesters)|392|392|1|0.2%|0.0%|
[php_commenters](#php_commenters)|430|430|1|0.2%|0.0%|
[firehol_level2](#firehol_level2)|23356|34994|1|0.0%|0.0%|
[ciarmy](#ciarmy)|469|469|1|0.2%|0.0%|

## ib_bluetack_badpeers

[iBlocklist.com](https://www.iblocklist.com/) free version of [BlueTack.co.uk](http://www.bluetack.co.uk/) IPs that have been reported for bad deeds in p2p

Source is downloaded from [this link](http://list.iblocklist.com/?list=cwworuawihqvocglcoss&fileformat=p2p&archiveformat=gz).

The last time downloaded was found to be dated: Wed Jun 10 05:30:23 UTC 2015.

The ipset `ib_bluetack_badpeers` has **47940** entries, **47940** unique IPs.

The following table shows the overlaps of `ib_bluetack_badpeers` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ib_bluetack_badpeers`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ib_bluetack_badpeers`.
- ` this % ` is the percentage **of this ipset (`ib_bluetack_badpeers`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|1172|0.0%|2.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|394|0.0%|0.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|226|0.0%|0.4%|
[firehol_level3](#firehol_level3)|110224|9627969|24|0.0%|0.0%|
[dragon_http](#dragon_http)|1044|273664|24|0.0%|0.0%|
[firehol_level1](#firehol_level1)|5135|688894845|18|0.0%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|94424|94424|16|0.0%|0.0%|
[sorbs_spam](#sorbs_spam)|60429|61096|15|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|60429|61096|15|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|60429|61096|15|0.0%|0.0%|
[firehol_proxies](#firehol_proxies)|12463|12723|15|0.1%|0.0%|
[firehol_anonymous](#firehol_anonymous)|19001|83032|15|0.0%|0.0%|
[alienvault_reputation](#alienvault_reputation)|182721|182721|15|0.0%|0.0%|
[firehol_level2](#firehol_level2)|23356|34994|14|0.0%|0.0%|
[fullbogons](#fullbogons)|3770|670213096|13|0.0%|0.0%|
[nixspam](#nixspam)|28015|28015|11|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|11|1.6%|0.0%|
[blocklist_de](#blocklist_de)|29619|29619|11|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6755|6755|5|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|5|0.0%|0.0%|
[et_block](#et_block)|1000|18344011|5|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|17317|17317|5|0.0%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|4|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7624|7624|4|0.0%|0.0%|
[xroxy](#xroxy)|2159|2159|3|0.1%|0.0%|
[php_dictionary](#php_dictionary)|702|702|3|0.4%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|3|0.0%|0.0%|
[voipbl](#voipbl)|10533|10945|2|0.0%|0.0%|
[php_harvesters](#php_harvesters)|392|392|2|0.5%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|1380|1380|2|0.1%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4090|4090|2|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|15454|15454|2|0.0%|0.0%|
[sorbs_web](#sorbs_web)|432|433|1|0.2%|0.0%|
[snort_ipfilter](#snort_ipfilter)|10158|10158|1|0.0%|0.0%|
[proxz](#proxz)|1244|1244|1|0.0%|0.0%|
[php_spammers](#php_spammers)|700|700|1|0.1%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|1|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3531|3531|1|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2412|2412|1|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|2949|2949|1|0.0%|0.0%|

## ib_bluetack_hijacked

[iBlocklist.com](https://www.iblocklist.com/) free version of [BlueTack.co.uk](http://www.bluetack.co.uk/) hijacked IP-Blocks Hijacked IP space are IP blocks that are being used without permission

Source is downloaded from [this link](http://list.iblocklist.com/?list=usrcshglbiilevmyfhse&fileformat=p2p&archiveformat=gz).

The last time downloaded was found to be dated: Wed Jun 10 06:00:03 UTC 2015.

The ipset `ib_bluetack_hijacked` has **535** entries, **9177856** unique IPs.

The following table shows the overlaps of `ib_bluetack_hijacked` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ib_bluetack_hijacked`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ib_bluetack_hijacked`.
- ` this % ` is the percentage **of this ipset (`ib_bluetack_hijacked`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level3](#firehol_level3)|110224|9627969|9177856|95.3%|100.0%|
[firehol_level1](#firehol_level1)|5135|688894845|7498240|1.0%|81.6%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|6932480|37.7%|75.5%|
[et_block](#et_block)|1000|18344011|6932480|37.7%|75.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|2526625|0.7%|27.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|904796|0.1%|9.8%|
[fullbogons](#fullbogons)|3770|670213096|565760|0.0%|6.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|145472|0.1%|1.5%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1036|0.3%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|94424|94424|731|0.7%|0.0%|
[alienvault_reputation](#alienvault_reputation)|182721|182721|265|0.1%|0.0%|
[dragon_http](#dragon_http)|1044|273664|256|0.0%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|167|0.5%|0.0%|
[nixspam](#nixspam)|28015|28015|108|0.3%|0.0%|
[firehol_level2](#firehol_level2)|23356|34994|91|0.2%|0.0%|
[blocklist_de](#blocklist_de)|29619|29619|66|0.2%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|2949|2949|56|1.8%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6755|6755|29|0.4%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|27|2.0%|0.0%|
[openbl_60d](#openbl_60d)|7012|7012|16|0.2%|0.0%|
[openbl_30d](#openbl_30d)|2835|2835|12|0.4%|0.0%|
[snort_ipfilter](#snort_ipfilter)|10158|10158|11|0.1%|0.0%|
[zeus_badips](#zeus_badips)|202|202|10|4.9%|0.0%|
[zeus](#zeus)|230|230|10|4.3%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|7|0.4%|0.0%|
[firehol_anonymous](#firehol_anonymous)|19001|83032|7|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3531|3531|6|0.1%|0.0%|
[openbl_7d](#openbl_7d)|679|679|5|0.7%|0.0%|
[et_compromised](#et_compromised)|1721|1721|5|0.2%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1706|1706|5|0.2%|0.0%|
[php_dictionary](#php_dictionary)|702|702|4|0.5%|0.0%|
[et_tor](#et_tor)|6400|6400|4|0.0%|0.0%|
[dm_tor](#dm_tor)|6459|6459|4|0.0%|0.0%|
[bm_tor](#bm_tor)|6473|6473|4|0.0%|0.0%|
[shunlist](#shunlist)|1234|1234|3|0.2%|0.0%|
[php_spammers](#php_spammers)|700|700|3|0.4%|0.0%|
[nt_malware_http](#nt_malware_http)|69|69|3|4.3%|0.0%|
[firehol_proxies](#firehol_proxies)|12463|12723|3|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|183|183|3|1.6%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|17317|17317|3|0.0%|0.0%|
[tor_exits](#tor_exits)|1128|1128|2|0.1%|0.0%|
[openbl_1d](#openbl_1d)|152|152|2|1.3%|0.0%|
[iw_spamlist](#iw_spamlist)|3703|3703|2|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|2|0.3%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2412|2412|2|0.0%|0.0%|
[voipbl](#voipbl)|10533|10945|1|0.0%|0.0%|
[sorbs_spam](#sorbs_spam)|60429|61096|1|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|60429|61096|1|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|60429|61096|1|0.0%|0.0%|
[php_harvesters](#php_harvesters)|392|392|1|0.2%|0.0%|
[php_commenters](#php_commenters)|430|430|1|0.2%|0.0%|
[nt_malware_irc](#nt_malware_irc)|43|43|1|2.3%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|1|0.1%|0.0%|
[et_botcc](#et_botcc)|506|506|1|0.1%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|1380|1380|1|0.0%|0.0%|

## ib_bluetack_level1

[iBlocklist.com](https://www.iblocklist.com/) free version of [BlueTack.co.uk](http://www.bluetack.co.uk/) Level 1 (for use in p2p): Companies or organizations who are clearly involved with trying to stop filesharing (e.g. Baytsp, MediaDefender, Mediasentry a.o.). Companies which anti-p2p activity has been seen from. Companies that produce or have a strong financial interest in copyrighted material (e.g. music, movie, software industries a.o.). Government ranges or companies that have a strong financial interest in doing work for governments. Legal industry ranges. IPs or ranges of ISPs from which anti-p2p activity has been observed. Basically this list will block all kinds of internet connections that most people would rather not have during their internet travels.

Source is downloaded from [this link](http://list.iblocklist.com/?list=ydxerpxkpcfqjaybcssw&fileformat=p2p&archiveformat=gz).

The last time downloaded was found to be dated: Wed Jun 10 09:45:00 UTC 2015.

The ipset `ib_bluetack_level1` has **218307** entries, **764993634** unique IPs.

The following table shows the overlaps of `ib_bluetack_level1` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ib_bluetack_level1`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ib_bluetack_level1`.
- ` this % ` is the percentage **of this ipset (`ib_bluetack_level1`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|16302420|4.6%|2.1%|
[firehol_level1](#firehol_level1)|5135|688894845|2570275|0.3%|0.3%|
[et_block](#et_block)|1000|18344011|2272548|12.3%|0.2%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|2272265|12.3%|0.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|1354507|0.9%|0.1%|
[firehol_level3](#firehol_level3)|110224|9627969|919965|9.5%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|904796|9.8%|0.1%|
[fullbogons](#fullbogons)|3770|670213096|264841|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|33155|6.8%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|13247|3.9%|0.0%|
[dragon_http](#dragon_http)|1044|273664|7370|2.6%|0.0%|
[alienvault_reputation](#alienvault_reputation)|182721|182721|4445|2.4%|0.0%|
[firehol_anonymous](#firehol_anonymous)|19001|83032|3440|4.1%|0.0%|
[firehol_level2](#firehol_level2)|23356|34994|1678|4.7%|0.0%|
[blocklist_de](#blocklist_de)|29619|29619|1555|5.2%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|94424|94424|1516|1.6%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|17317|17317|1383|7.9%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|15454|15454|1337|8.6%|0.0%|
[sorbs_spam](#sorbs_spam)|60429|61096|1148|1.8%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|60429|61096|1148|1.8%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|60429|61096|1148|1.8%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|529|1.8%|0.0%|
[nixspam](#nixspam)|28015|28015|467|1.6%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|394|0.8%|0.0%|
[voipbl](#voipbl)|10533|10945|299|2.7%|0.0%|
[firehol_proxies](#firehol_proxies)|12463|12723|288|2.2%|0.0%|
[et_tor](#et_tor)|6400|6400|165|2.5%|0.0%|
[dm_tor](#dm_tor)|6459|6459|165|2.5%|0.0%|
[bm_tor](#bm_tor)|6473|6473|163|2.5%|0.0%|
[openbl_60d](#openbl_60d)|7012|7012|162|2.3%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7624|7624|153|2.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6755|6755|146|2.1%|0.0%|
[snort_ipfilter](#snort_ipfilter)|10158|10158|117|1.1%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|97|6.6%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2751|2751|83|3.0%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|66|5.1%|0.0%|
[openbl_30d](#openbl_30d)|2835|2835|63|2.2%|0.0%|
[iw_spamlist](#iw_spamlist)|3703|3703|59|1.5%|0.0%|
[xroxy](#xroxy)|2159|2159|58|2.6%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3531|3531|58|1.6%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|56|8.4%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1706|1706|53|3.1%|0.0%|
[et_compromised](#et_compromised)|1721|1721|52|3.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4090|4090|48|1.1%|0.0%|
[proxz](#proxz)|1244|1244|43|3.4%|0.0%|
[et_botcc](#et_botcc)|506|506|40|7.9%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|2949|2949|40|1.3%|0.0%|
[tor_exits](#tor_exits)|1128|1128|38|3.3%|0.0%|
[ciarmy](#ciarmy)|469|469|36|7.6%|0.0%|
[proxyrss](#proxyrss)|1675|1675|33|1.9%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2412|2412|32|1.3%|0.0%|
[shunlist](#shunlist)|1234|1234|25|2.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|21|4.0%|0.0%|
[openbl_7d](#openbl_7d)|679|679|13|1.9%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|1380|1380|13|0.9%|0.0%|
[sorbs_web](#sorbs_web)|432|433|12|2.7%|0.0%|
[php_harvesters](#php_harvesters)|392|392|12|3.0%|0.0%|
[php_dictionary](#php_dictionary)|702|702|12|1.7%|0.0%|
[malc0de](#malc0de)|313|313|11|3.5%|0.0%|
[php_spammers](#php_spammers)|700|700|10|1.4%|0.0%|
[php_commenters](#php_commenters)|430|430|10|2.3%|0.0%|
[zeus](#zeus)|230|230|7|3.0%|0.0%|
[nt_malware_http](#nt_malware_http)|69|69|7|10.1%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|79|79|6|7.5%|0.0%|
[nt_malware_irc](#nt_malware_irc)|43|43|5|11.6%|0.0%|
[bogons](#bogons)|13|592708608|5|0.0%|0.0%|
[zeus_badips](#zeus_badips)|202|202|4|1.9%|0.0%|
[sslbl](#sslbl)|372|372|3|0.8%|0.0%|
[openbl_1d](#openbl_1d)|152|152|3|1.9%|0.0%|
[feodo](#feodo)|105|105|3|2.8%|0.0%|
[virbl](#virbl)|31|31|2|6.4%|0.0%|
[iw_wormlist](#iw_wormlist)|33|33|1|3.0%|0.0%|
[dshield](#dshield)|20|5120|1|0.0%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|65|65|1|1.5%|0.0%|

## ib_bluetack_level2

[iBlocklist.com](https://www.iblocklist.com/) free version of BlueTack.co.uk Level 2 (for use in p2p). General corporate ranges. Ranges used by labs or researchers. Proxies.

Source is downloaded from [this link](http://list.iblocklist.com/?list=gyisgnzbhppbvsphucsw&fileformat=p2p&archiveformat=gz).

The last time downloaded was found to be dated: Wed Jun 10 06:01:37 UTC 2015.

The ipset `ib_bluetack_level2` has **72950** entries, **348710251** unique IPs.

The following table shows the overlaps of `ib_bluetack_level2` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ib_bluetack_level2`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ib_bluetack_level2`.
- ` this % ` is the percentage **of this ipset (`ib_bluetack_level2`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|16302420|2.1%|4.6%|
[firehol_level1](#firehol_level1)|5135|688894845|8867461|1.2%|2.5%|
[et_block](#et_block)|1000|18344011|8532520|46.5%|2.4%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|8532506|46.5%|2.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|2830203|2.0%|0.8%|
[firehol_level3](#firehol_level3)|110224|9627969|2537317|26.3%|0.7%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2526625|27.5%|0.7%|
[fullbogons](#fullbogons)|3770|670213096|252415|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|98904|20.2%|0.0%|
[dragon_http](#dragon_http)|1044|273664|12216|4.4%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|7728|2.2%|0.0%|
[alienvault_reputation](#alienvault_reputation)|182721|182721|6488|3.5%|0.0%|
[firehol_anonymous](#firehol_anonymous)|19001|83032|2895|3.4%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|94424|94424|2508|2.6%|0.0%|
[firehol_level2](#firehol_level2)|23356|34994|1729|4.9%|0.0%|
[sorbs_spam](#sorbs_spam)|60429|61096|1636|2.6%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|60429|61096|1636|2.6%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|60429|61096|1636|2.6%|0.0%|
[blocklist_de](#blocklist_de)|29619|29619|1583|5.3%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|17317|17317|1265|7.3%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|15454|15454|1107|7.1%|0.0%|
[nixspam](#nixspam)|28015|28015|840|2.9%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|790|2.6%|0.0%|
[voipbl](#voipbl)|10533|10945|434|3.9%|0.0%|
[firehol_proxies](#firehol_proxies)|12463|12723|393|3.0%|0.0%|
[openbl_60d](#openbl_60d)|7012|7012|321|4.5%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|226|0.4%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7624|7624|222|2.9%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6755|6755|192|2.8%|0.0%|
[et_tor](#et_tor)|6400|6400|181|2.8%|0.0%|
[bm_tor](#bm_tor)|6473|6473|181|2.7%|0.0%|
[dm_tor](#dm_tor)|6459|6459|180|2.7%|0.0%|
[snort_ipfilter](#snort_ipfilter)|10158|10158|158|1.5%|0.0%|
[openbl_30d](#openbl_30d)|2835|2835|148|5.2%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3531|3531|136|3.8%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2751|2751|105|3.8%|0.0%|
[xroxy](#xroxy)|2159|2159|104|4.8%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1706|1706|89|5.2%|0.0%|
[iw_spamlist](#iw_spamlist)|3703|3703|88|2.3%|0.0%|
[et_compromised](#et_compromised)|1721|1721|85|4.9%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|2949|2949|79|2.6%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4090|4090|77|1.8%|0.0%|
[shunlist](#shunlist)|1234|1234|68|5.5%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2412|2412|56|2.3%|0.0%|
[php_spammers](#php_spammers)|700|700|54|7.7%|0.0%|
[proxyrss](#proxyrss)|1675|1675|53|3.1%|0.0%|
[proxz](#proxz)|1244|1244|51|4.0%|0.0%|
[ciarmy](#ciarmy)|469|469|50|10.6%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|45|3.1%|0.0%|
[openbl_7d](#openbl_7d)|679|679|40|5.8%|0.0%|
[tor_exits](#tor_exits)|1128|1128|39|3.4%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|29|5.5%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|26|2.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|26|3.9%|0.0%|
[php_dictionary](#php_dictionary)|702|702|23|3.2%|0.0%|
[et_botcc](#et_botcc)|506|506|20|3.9%|0.0%|
[php_commenters](#php_commenters)|430|430|18|4.1%|0.0%|
[malc0de](#malc0de)|313|313|16|5.1%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|1380|1380|16|1.1%|0.0%|
[sorbs_web](#sorbs_web)|432|433|13|3.0%|0.0%|
[zeus](#zeus)|230|230|9|3.9%|0.0%|
[php_harvesters](#php_harvesters)|392|392|9|2.2%|0.0%|
[zeus_badips](#zeus_badips)|202|202|8|3.9%|0.0%|
[openbl_1d](#openbl_1d)|152|152|8|5.2%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|183|183|8|4.3%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|79|79|7|8.8%|0.0%|
[sslbl](#sslbl)|372|372|6|1.6%|0.0%|
[palevo](#palevo)|13|13|3|23.0%|0.0%|
[feodo](#feodo)|105|105|3|2.8%|0.0%|
[virbl](#virbl)|31|31|2|6.4%|0.0%|
[nt_malware_irc](#nt_malware_irc)|43|43|2|4.6%|0.0%|
[nt_malware_http](#nt_malware_http)|69|69|2|2.8%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|65|65|1|1.5%|0.0%|

## ib_bluetack_level3

[iBlocklist.com](https://www.iblocklist.com/) free version of BlueTack.co.uk Level 3 (for use in p2p). Many portal-type websites. ISP ranges that may be dodgy for some reason. Ranges that belong to an individual, but which have not been determined to be used by a particular company. Ranges for things that are unusual in some way. The L3 list is aka the paranoid list.

Source is downloaded from [this link](http://list.iblocklist.com/?list=uwnukjqktoggdknzrhgh&fileformat=p2p&archiveformat=gz).

The last time downloaded was found to be dated: Wed Jun 10 06:01:55 UTC 2015.

The ipset `ib_bluetack_level3` has **17812** entries, **139104927** unique IPs.

The following table shows the overlaps of `ib_bluetack_level3` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ib_bluetack_level3`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ib_bluetack_level3`.
- ` this % ` is the percentage **of this ipset (`ib_bluetack_level3`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level1](#firehol_level1)|5135|688894845|4637346|0.6%|3.3%|
[fullbogons](#fullbogons)|3770|670213096|4236143|0.6%|3.0%|
[bogons](#bogons)|13|592708608|4194304|0.7%|3.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|2830203|0.8%|2.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|1354507|0.1%|0.9%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|270785|55.5%|0.1%|
[firehol_level3](#firehol_level3)|110224|9627969|161588|1.6%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|145472|1.5%|0.1%|
[et_block](#et_block)|1000|18344011|130394|0.7%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|130368|0.7%|0.0%|
[dragon_http](#dragon_http)|1044|273664|19712|7.2%|0.0%|
[alienvault_reputation](#alienvault_reputation)|182721|182721|13319|7.2%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|9226|2.7%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|94424|94424|5840|6.1%|0.0%|
[firehol_level2](#firehol_level2)|23356|34994|4179|11.9%|0.0%|
[blocklist_de](#blocklist_de)|29619|29619|3766|12.7%|0.0%|
[firehol_anonymous](#firehol_anonymous)|19001|83032|2888|3.4%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|17317|17317|2602|15.0%|0.0%|
[sorbs_spam](#sorbs_spam)|60429|61096|2514|4.1%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|60429|61096|2514|4.1%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|60429|61096|2514|4.1%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|15454|15454|2404|15.5%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|1913|6.5%|0.0%|
[voipbl](#voipbl)|10533|10945|1605|14.6%|0.0%|
[nixspam](#nixspam)|28015|28015|1241|4.4%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|1172|2.4%|0.0%|
[openbl_60d](#openbl_60d)|7012|7012|747|10.6%|0.0%|
[dm_tor](#dm_tor)|6459|6459|638|9.8%|0.0%|
[bm_tor](#bm_tor)|6473|6473|631|9.7%|0.0%|
[et_tor](#et_tor)|6400|6400|625|9.7%|0.0%|
[firehol_proxies](#firehol_proxies)|12463|12723|528|4.1%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3531|3531|516|14.6%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6755|6755|494|7.3%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4090|4090|314|7.6%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2412|2412|305|12.6%|0.0%|
[openbl_30d](#openbl_30d)|2835|2835|295|10.4%|0.0%|
[snort_ipfilter](#snort_ipfilter)|10158|10158|243|2.3%|0.0%|
[iw_spamlist](#iw_spamlist)|3703|3703|240|6.4%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7624|7624|218|2.8%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1706|1706|156|9.1%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|2949|2949|155|5.2%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|1380|1380|154|11.1%|0.0%|
[et_compromised](#et_compromised)|1721|1721|152|8.8%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|150|28.6%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|147|11.4%|0.0%|
[tor_exits](#tor_exits)|1128|1128|128|11.3%|0.0%|
[shunlist](#shunlist)|1234|1234|117|9.4%|0.0%|
[xroxy](#xroxy)|2159|2159|110|5.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|108|7.4%|0.0%|
[proxz](#proxz)|1244|1244|102|8.1%|0.0%|
[ciarmy](#ciarmy)|469|469|100|21.3%|0.0%|
[openbl_7d](#openbl_7d)|679|679|79|11.6%|0.0%|
[et_botcc](#et_botcc)|506|506|77|15.2%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2751|2751|57|2.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|51|7.6%|0.0%|
[proxyrss](#proxyrss)|1675|1675|47|2.8%|0.0%|
[malc0de](#malc0de)|313|313|45|14.3%|0.0%|
[php_spammers](#php_spammers)|700|700|43|6.1%|0.0%|
[php_dictionary](#php_dictionary)|702|702|38|5.4%|0.0%|
[sslbl](#sslbl)|372|372|28|7.5%|0.0%|
[php_commenters](#php_commenters)|430|430|28|6.5%|0.0%|
[php_harvesters](#php_harvesters)|392|392|20|5.1%|0.0%|
[sorbs_web](#sorbs_web)|432|433|18|4.1%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|183|183|16|8.7%|0.0%|
[zeus](#zeus)|230|230|14|6.0%|0.0%|
[openbl_1d](#openbl_1d)|152|152|11|7.2%|0.0%|
[feodo](#feodo)|105|105|11|10.4%|0.0%|
[zeus_badips](#zeus_badips)|202|202|10|4.9%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|79|79|10|12.6%|0.0%|
[nt_malware_http](#nt_malware_http)|69|69|5|7.2%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|65|65|5|7.6%|0.0%|
[virbl](#virbl)|31|31|4|12.9%|0.0%|
[iw_wormlist](#iw_wormlist)|33|33|2|6.0%|0.0%|
[palevo](#palevo)|13|13|1|7.6%|0.0%|
[nt_malware_irc](#nt_malware_irc)|43|43|1|2.3%|0.0%|

## ib_bluetack_proxies

[iBlocklist.com](https://www.iblocklist.com/) free version of [BlueTack.co.uk](http://www.bluetack.co.uk/) Open Proxies IPs list (without TOR)

Source is downloaded from [this link](http://list.iblocklist.com/?list=xoebmbyexwuiogmbyprb&fileformat=p2p&archiveformat=gz).

The last time downloaded was found to be dated: Wed Jun 10 06:00:03 UTC 2015.

The ipset `ib_bluetack_proxies` has **663** entries, **663** unique IPs.

The following table shows the overlaps of `ib_bluetack_proxies` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ib_bluetack_proxies`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ib_bluetack_proxies`.
- ` this % ` is the percentage **of this ipset (`ib_bluetack_proxies`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_proxies](#firehol_proxies)|12463|12723|663|5.2%|100.0%|
[firehol_anonymous](#firehol_anonymous)|19001|83032|663|0.7%|100.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|56|0.0%|8.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|51|0.0%|7.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|26|0.0%|3.9%|
[firehol_level3](#firehol_level3)|110224|9627969|24|0.0%|3.6%|
[stopforumspam_30d](#stopforumspam_30d)|94424|94424|19|0.0%|2.8%|
[ri_web_proxies](#ri_web_proxies)|7624|7624|14|0.1%|2.1%|
[xroxy](#xroxy)|2159|2159|13|0.6%|1.9%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|11|0.0%|1.6%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|11|0.0%|1.6%|
[proxyrss](#proxyrss)|1675|1675|8|0.4%|1.2%|
[ri_connect_proxies](#ri_connect_proxies)|2751|2751|7|0.2%|1.0%|
[firehol_level2](#firehol_level2)|23356|34994|7|0.0%|1.0%|
[proxz](#proxz)|1244|1244|6|0.4%|0.9%|
[stopforumspam_1d](#stopforumspam_1d)|6755|6755|4|0.0%|0.6%|
[blocklist_de](#blocklist_de)|29619|29619|4|0.0%|0.6%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|2|0.0%|0.3%|
[nixspam](#nixspam)|28015|28015|2|0.0%|0.3%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|2|0.1%|0.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2|0.0%|0.3%|
[firehol_level1](#firehol_level1)|5135|688894845|2|0.0%|0.3%|
[et_block](#et_block)|1000|18344011|2|0.0%|0.3%|
[blocklist_de_mail](#blocklist_de_mail)|17317|17317|2|0.0%|0.3%|
[blocklist_de_bots](#blocklist_de_bots)|2949|2949|2|0.0%|0.3%|
[sorbs_spam](#sorbs_spam)|60429|61096|1|0.0%|0.1%|
[sorbs_recent_spam](#sorbs_recent_spam)|60429|61096|1|0.0%|0.1%|
[sorbs_new_spam](#sorbs_new_spam)|60429|61096|1|0.0%|0.1%|
[snort_ipfilter](#snort_ipfilter)|10158|10158|1|0.0%|0.1%|
[php_dictionary](#php_dictionary)|702|702|1|0.1%|0.1%|
[dragon_http](#dragon_http)|1044|273664|1|0.0%|0.1%|
[alienvault_reputation](#alienvault_reputation)|182721|182721|1|0.0%|0.1%|

## ib_bluetack_spyware

[iBlocklist.com](https://www.iblocklist.com/) free version of [BlueTack.co.uk](http://www.bluetack.co.uk/) known malicious SPYWARE and ADWARE IP Address ranges

Source is downloaded from [this link](http://list.iblocklist.com/?list=llvtlsjyoyiczbkjsxpf&fileformat=p2p&archiveformat=gz).

The last time downloaded was found to be dated: Wed Jun 10 05:30:03 UTC 2015.

The ipset `ib_bluetack_spyware` has **3267** entries, **339173** unique IPs.

The following table shows the overlaps of `ib_bluetack_spyware` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ib_bluetack_spyware`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ib_bluetack_spyware`.
- ` this % ` is the percentage **of this ipset (`ib_bluetack_spyware`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level3](#firehol_level3)|110224|9627969|339173|3.5%|100.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|13247|0.0%|3.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|9226|0.0%|2.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|7728|0.0%|2.2%|
[firehol_level1](#firehol_level1)|5135|688894845|1932|0.0%|0.5%|
[et_block](#et_block)|1000|18344011|1042|0.0%|0.3%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|1037|0.0%|0.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1036|0.0%|0.3%|
[fullbogons](#fullbogons)|3770|670213096|890|0.0%|0.2%|
[alienvault_reputation](#alienvault_reputation)|182721|182721|288|0.1%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|94424|94424|49|0.0%|0.0%|
[sorbs_spam](#sorbs_spam)|60429|61096|34|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|60429|61096|34|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|60429|61096|34|0.0%|0.0%|
[firehol_anonymous](#firehol_anonymous)|19001|83032|29|0.0%|0.0%|
[nixspam](#nixspam)|28015|28015|27|0.0%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|27|2.0%|0.0%|
[et_tor](#et_tor)|6400|6400|22|0.3%|0.0%|
[dm_tor](#dm_tor)|6459|6459|22|0.3%|0.0%|
[bm_tor](#bm_tor)|6473|6473|22|0.3%|0.0%|
[firehol_level2](#firehol_level2)|23356|34994|21|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|19|1.3%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|18|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|10158|10158|14|0.1%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6755|6755|12|0.1%|0.0%|
[firehol_proxies](#firehol_proxies)|12463|12723|11|0.0%|0.0%|
[blocklist_de](#blocklist_de)|29619|29619|9|0.0%|0.0%|
[tor_exits](#tor_exits)|1128|1128|8|0.7%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7624|7624|6|0.0%|0.0%|
[dragon_http](#dragon_http)|1044|273664|6|0.0%|0.0%|
[openbl_60d](#openbl_60d)|7012|7012|5|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|5|0.9%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|15454|15454|5|0.0%|0.0%|
[voipbl](#voipbl)|10533|10945|4|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4090|4090|4|0.0%|0.0%|
[openbl_30d](#openbl_30d)|2835|2835|3|0.1%|0.0%|
[malc0de](#malc0de)|313|313|3|0.9%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|3|0.0%|0.0%|
[proxyrss](#proxyrss)|1675|1675|2|0.1%|0.0%|
[palevo](#palevo)|13|13|2|15.3%|0.0%|
[iw_spamlist](#iw_spamlist)|3703|3703|2|0.0%|0.0%|
[et_compromised](#et_compromised)|1721|1721|2|0.1%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1706|1706|2|0.1%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|79|79|2|2.5%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|17317|17317|2|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|2949|2949|2|0.0%|0.0%|
[zeus_badips](#zeus_badips)|202|202|1|0.4%|0.0%|
[zeus](#zeus)|230|230|1|0.4%|0.0%|
[xroxy](#xroxy)|2159|2159|1|0.0%|0.0%|
[sslbl](#sslbl)|372|372|1|0.2%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|1|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2751|2751|1|0.0%|0.0%|
[proxz](#proxz)|1244|1244|1|0.0%|0.0%|
[php_harvesters](#php_harvesters)|392|392|1|0.2%|0.0%|
[php_dictionary](#php_dictionary)|702|702|1|0.1%|0.0%|
[php_commenters](#php_commenters)|430|430|1|0.2%|0.0%|
[nt_malware_http](#nt_malware_http)|69|69|1|1.4%|0.0%|
[feodo](#feodo)|105|105|1|0.9%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|65|65|1|1.5%|0.0%|
[ciarmy](#ciarmy)|469|469|1|0.2%|0.0%|
[bogons](#bogons)|13|592708608|1|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3531|3531|1|0.0%|0.0%|

## ib_bluetack_webexploit

[iBlocklist.com](https://www.iblocklist.com/) free version of [BlueTack.co.uk](http://www.bluetack.co.uk/) web server hack and exploit attempts

Source is downloaded from [this link](http://list.iblocklist.com/?list=ghlzqtqxnzctvvajwwag&fileformat=p2p&archiveformat=gz).

The last time downloaded was found to be dated: Wed Jun 10 05:30:07 UTC 2015.

The ipset `ib_bluetack_webexploit` has **1450** entries, **1450** unique IPs.

The following table shows the overlaps of `ib_bluetack_webexploit` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ib_bluetack_webexploit`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ib_bluetack_webexploit`.
- ` this % ` is the percentage **of this ipset (`ib_bluetack_webexploit`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level3](#firehol_level3)|110224|9627969|1450|0.0%|100.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|108|0.0%|7.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|97|0.0%|6.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|45|0.0%|3.1%|
[firehol_level1](#firehol_level1)|5135|688894845|40|0.0%|2.7%|
[fullbogons](#fullbogons)|3770|670213096|33|0.0%|2.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|19|0.0%|1.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|7|0.0%|0.4%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|6|0.0%|0.4%|
[et_block](#et_block)|1000|18344011|6|0.0%|0.4%|
[alienvault_reputation](#alienvault_reputation)|182721|182721|6|0.0%|0.4%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|3|0.2%|0.2%|
[firehol_proxies](#firehol_proxies)|12463|12723|3|0.0%|0.2%|
[firehol_level2](#firehol_level2)|23356|34994|3|0.0%|0.2%|
[firehol_anonymous](#firehol_anonymous)|19001|83032|3|0.0%|0.2%|
[dragon_http](#dragon_http)|1044|273664|3|0.0%|0.2%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|2|0.0%|0.1%|
[stopforumspam_30d](#stopforumspam_30d)|94424|94424|2|0.0%|0.1%|
[stopforumspam_1d](#stopforumspam_1d)|6755|6755|2|0.0%|0.1%|
[sorbs_spam](#sorbs_spam)|60429|61096|2|0.0%|0.1%|
[sorbs_recent_spam](#sorbs_recent_spam)|60429|61096|2|0.0%|0.1%|
[sorbs_new_spam](#sorbs_new_spam)|60429|61096|2|0.0%|0.1%|
[openbl_60d](#openbl_60d)|7012|7012|2|0.0%|0.1%|
[openbl_30d](#openbl_30d)|2835|2835|2|0.0%|0.1%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|2|0.3%|0.1%|
[blocklist_de](#blocklist_de)|29619|29619|2|0.0%|0.1%|
[snort_ipfilter](#snort_ipfilter)|10158|10158|1|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7624|7624|1|0.0%|0.0%|
[nixspam](#nixspam)|28015|28015|1|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|1|0.0%|0.0%|
[et_botcc](#et_botcc)|506|506|1|0.1%|0.0%|
[dshield](#dshield)|20|5120|1|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|183|183|1|0.5%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3531|3531|1|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|2949|2949|1|0.0%|0.0%|

## iw_spamlist

[ImproWare Antispam](http://antispam.imp.ch/) IPs sending spam, in the last 3 days

Source is downloaded from [this link](http://antispam.imp.ch/spamlist).

The last time downloaded was found to be dated: Wed Jun 10 23:20:04 UTC 2015.

The ipset `iw_spamlist` has **3703** entries, **3703** unique IPs.

The following table shows the overlaps of `iw_spamlist` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `iw_spamlist`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `iw_spamlist`.
- ` this % ` is the percentage **of this ipset (`iw_spamlist`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[sorbs_spam](#sorbs_spam)|60429|61096|1157|1.8%|31.2%|
[sorbs_recent_spam](#sorbs_recent_spam)|60429|61096|1157|1.8%|31.2%|
[sorbs_new_spam](#sorbs_new_spam)|60429|61096|1157|1.8%|31.2%|
[nixspam](#nixspam)|28015|28015|727|2.5%|19.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|240|0.0%|6.4%|
[firehol_level2](#firehol_level2)|23356|34994|139|0.3%|3.7%|
[blocklist_de](#blocklist_de)|29619|29619|136|0.4%|3.6%|
[blocklist_de_mail](#blocklist_de_mail)|17317|17317|129|0.7%|3.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|88|0.0%|2.3%|
[firehol_level3](#firehol_level3)|110224|9627969|84|0.0%|2.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|59|0.0%|1.5%|
[snort_ipfilter](#snort_ipfilter)|10158|10158|52|0.5%|1.4%|
[sorbs_web](#sorbs_web)|432|433|30|6.9%|0.8%|
[stopforumspam_30d](#stopforumspam_30d)|94424|94424|18|0.0%|0.4%|
[firehol_anonymous](#firehol_anonymous)|19001|83032|15|0.0%|0.4%|
[iw_wormlist](#iw_wormlist)|33|33|14|42.4%|0.3%|
[firehol_proxies](#firehol_proxies)|12463|12723|14|0.1%|0.3%|
[alienvault_reputation](#alienvault_reputation)|182721|182721|13|0.0%|0.3%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|12|0.0%|0.3%|
[ri_web_proxies](#ri_web_proxies)|7624|7624|12|0.1%|0.3%|
[php_spammers](#php_spammers)|700|700|9|1.2%|0.2%|
[firehol_level1](#firehol_level1)|5135|688894845|8|0.0%|0.2%|
[stopforumspam_1d](#stopforumspam_1d)|6755|6755|6|0.0%|0.1%|
[php_dictionary](#php_dictionary)|702|702|6|0.8%|0.1%|
[fullbogons](#fullbogons)|3770|670213096|5|0.0%|0.1%|
[bogons](#bogons)|13|592708608|5|0.0%|0.1%|
[dragon_http](#dragon_http)|1044|273664|4|0.0%|0.1%|
[blocklist_de_bots](#blocklist_de_bots)|2949|2949|4|0.1%|0.1%|
[xroxy](#xroxy)|2159|2159|3|0.1%|0.0%|
[php_harvesters](#php_harvesters)|392|392|3|0.7%|0.0%|
[php_commenters](#php_commenters)|430|430|3|0.6%|0.0%|
[et_block](#et_block)|1000|18344011|3|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4090|4090|3|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|15454|15454|3|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|2|0.0%|0.0%|
[proxyrss](#proxyrss)|1675|1675|2|0.1%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|2|0.0%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2412|2412|2|0.0%|0.0%|
[zeus_badips](#zeus_badips)|202|202|1|0.4%|0.0%|
[zeus](#zeus)|230|230|1|0.4%|0.0%|
[tor_exits](#tor_exits)|1128|1128|1|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2751|2751|1|0.0%|0.0%|
[proxz](#proxz)|1244|1244|1|0.0%|0.0%|
[et_tor](#et_tor)|6400|6400|1|0.0%|0.0%|
[dm_tor](#dm_tor)|6459|6459|1|0.0%|0.0%|
[bm_tor](#bm_tor)|6473|6473|1|0.0%|0.0%|

## iw_wormlist

[ImproWare Antispam](http://antispam.imp.ch/) IPs sending emails with viruses or worms, in the last 3 days

Source is downloaded from [this link](http://antispam.imp.ch/wormlist).

The last time downloaded was found to be dated: Wed Jun 10 23:20:04 UTC 2015.

The ipset `iw_wormlist` has **33** entries, **33** unique IPs.

The following table shows the overlaps of `iw_wormlist` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `iw_wormlist`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `iw_wormlist`.
- ` this % ` is the percentage **of this ipset (`iw_wormlist`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level3](#firehol_level3)|110224|9627969|33|0.0%|100.0%|
[iw_spamlist](#iw_spamlist)|3703|3703|14|0.3%|42.4%|
[nixspam](#nixspam)|28015|28015|4|0.0%|12.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|2|0.0%|6.0%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|1|0.0%|3.0%|
[stopforumspam_30d](#stopforumspam_30d)|94424|94424|1|0.0%|3.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|1|0.0%|3.0%|
[firehol_level2](#firehol_level2)|23356|34994|1|0.0%|3.0%|
[blocklist_de_mail](#blocklist_de_mail)|17317|17317|1|0.0%|3.0%|
[blocklist_de](#blocklist_de)|29619|29619|1|0.0%|3.0%|

## malc0de

[Malc0de.com](http://malc0de.com) malicious IPs of the last 30 days

Source is downloaded from [this link](http://malc0de.com/bl/IP_Blacklist.txt).

The last time downloaded was found to be dated: Wed Jun 10 13:17:02 UTC 2015.

The ipset `malc0de` has **313** entries, **313** unique IPs.

The following table shows the overlaps of `malc0de` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `malc0de`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `malc0de`.
- ` this % ` is the percentage **of this ipset (`malc0de`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level3](#firehol_level3)|110224|9627969|313|0.0%|100.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|45|0.0%|14.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|16|0.0%|5.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|11|0.0%|3.5%|
[alienvault_reputation](#alienvault_reputation)|182721|182721|10|0.0%|3.1%|
[firehol_level1](#firehol_level1)|5135|688894845|7|0.0%|2.2%|
[et_block](#et_block)|1000|18344011|5|0.0%|1.5%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|4|0.0%|1.2%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|4|0.3%|1.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|3|0.0%|0.9%|
[dragon_http](#dragon_http)|1044|273664|3|0.0%|0.9%|
[dshield](#dshield)|20|5120|2|0.0%|0.6%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|1|0.0%|0.3%|
[sorbs_spam](#sorbs_spam)|60429|61096|1|0.0%|0.3%|
[sorbs_recent_spam](#sorbs_recent_spam)|60429|61096|1|0.0%|0.3%|
[sorbs_new_spam](#sorbs_new_spam)|60429|61096|1|0.0%|0.3%|
[cleanmx_viruses](#cleanmx_viruses)|65|65|1|1.5%|0.3%|

## malwaredomainlist

[malwaredomainlist.com](http://www.malwaredomainlist.com) list of malware active ip addresses

Source is downloaded from [this link](http://www.malwaredomainlist.com/hostslist/ip.txt).

The last time downloaded was found to be dated: Sun Jun  7 01:22:17 UTC 2015.

The ipset `malwaredomainlist` has **1288** entries, **1288** unique IPs.

The following table shows the overlaps of `malwaredomainlist` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `malwaredomainlist`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `malwaredomainlist`.
- ` this % ` is the percentage **of this ipset (`malwaredomainlist`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level3](#firehol_level3)|110224|9627969|1288|0.0%|100.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|147|0.0%|11.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|66|0.0%|5.1%|
[firehol_level1](#firehol_level1)|5135|688894845|39|0.0%|3.0%|
[et_block](#et_block)|1000|18344011|30|0.0%|2.3%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|29|0.0%|2.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|27|0.0%|2.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|27|0.0%|2.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|26|0.0%|2.0%|
[snort_ipfilter](#snort_ipfilter)|10158|10158|12|0.1%|0.9%|
[fullbogons](#fullbogons)|3770|670213096|9|0.0%|0.6%|
[alienvault_reputation](#alienvault_reputation)|182721|182721|8|0.0%|0.6%|
[stopforumspam_30d](#stopforumspam_30d)|94424|94424|4|0.0%|0.3%|
[malc0de](#malc0de)|313|313|4|1.2%|0.3%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|3|0.2%|0.2%|
[dragon_http](#dragon_http)|1044|273664|2|0.0%|0.1%|
[zeus](#zeus)|230|230|1|0.4%|0.0%|
[et_botcc](#et_botcc)|506|506|1|0.1%|0.0%|

## maxmind_proxy_fraud

[MaxMind.com](https://www.maxmind.com/en/anonymous-proxy-fraudulent-ip-address-list) list of anonymous proxy fraudelent IP addresses.

Source is downloaded from [this link](https://www.maxmind.com/en/anonymous-proxy-fraudulent-ip-address-list).

The last time downloaded was found to be dated: Wed Jun 10 22:45:13 UTC 2015.

The ipset `maxmind_proxy_fraud` has **524** entries, **524** unique IPs.

The following table shows the overlaps of `maxmind_proxy_fraud` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `maxmind_proxy_fraud`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `maxmind_proxy_fraud`.
- ` this % ` is the percentage **of this ipset (`maxmind_proxy_fraud`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_proxies](#firehol_proxies)|12463|12723|524|4.1%|100.0%|
[firehol_anonymous](#firehol_anonymous)|19001|83032|524|0.6%|100.0%|
[firehol_level3](#firehol_level3)|110224|9627969|343|0.0%|65.4%|
[stopforumspam_30d](#stopforumspam_30d)|94424|94424|342|0.3%|65.2%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|285|0.9%|54.3%|
[snort_ipfilter](#snort_ipfilter)|10158|10158|239|2.3%|45.6%|
[et_tor](#et_tor)|6400|6400|234|3.6%|44.6%|
[bm_tor](#bm_tor)|6473|6473|234|3.6%|44.6%|
[dm_tor](#dm_tor)|6459|6459|233|3.6%|44.4%|
[tor_exits](#tor_exits)|1128|1128|231|20.4%|44.0%|
[firehol_level2](#firehol_level2)|23356|34994|228|0.6%|43.5%|
[stopforumspam_1d](#stopforumspam_1d)|6755|6755|225|3.3%|42.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|150|0.0%|28.6%|
[php_commenters](#php_commenters)|430|430|52|12.0%|9.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|29|0.0%|5.5%|
[alienvault_reputation](#alienvault_reputation)|182721|182721|29|0.0%|5.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|21|0.0%|4.0%|
[openbl_60d](#openbl_60d)|7012|7012|20|0.2%|3.8%|
[ri_web_proxies](#ri_web_proxies)|7624|7624|10|0.1%|1.9%|
[blocklist_de](#blocklist_de)|29619|29619|8|0.0%|1.5%|
[php_harvesters](#php_harvesters)|392|392|7|1.7%|1.3%|
[php_spammers](#php_spammers)|700|700|6|0.8%|1.1%|
[php_dictionary](#php_dictionary)|702|702|5|0.7%|0.9%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|5|0.0%|0.9%|
[blocklist_de_bots](#blocklist_de_bots)|2949|2949|5|0.1%|0.9%|
[xroxy](#xroxy)|2159|2159|3|0.1%|0.5%|
[voipbl](#voipbl)|10533|10945|2|0.0%|0.3%|
[proxz](#proxz)|1244|1244|2|0.1%|0.3%|
[dragon_http](#dragon_http)|1044|273664|2|0.0%|0.3%|
[blocklist_de_mail](#blocklist_de_mail)|17317|17317|2|0.0%|0.3%|
[blocklist_de_apache](#blocklist_de_apache)|15454|15454|2|0.0%|0.3%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|1|0.0%|0.1%|
[sorbs_spam](#sorbs_spam)|60429|61096|1|0.0%|0.1%|
[sorbs_recent_spam](#sorbs_recent_spam)|60429|61096|1|0.0%|0.1%|
[sorbs_new_spam](#sorbs_new_spam)|60429|61096|1|0.0%|0.1%|
[shunlist](#shunlist)|1234|1234|1|0.0%|0.1%|
[ri_connect_proxies](#ri_connect_proxies)|2751|2751|1|0.0%|0.1%|
[proxyrss](#proxyrss)|1675|1675|1|0.0%|0.1%|
[nixspam](#nixspam)|28015|28015|1|0.0%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.1%|
[firehol_level1](#firehol_level1)|5135|688894845|1|0.0%|0.1%|
[et_block](#et_block)|1000|18344011|1|0.0%|0.1%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4090|4090|1|0.0%|0.1%|

## nixspam

[NiX Spam](http://www.heise.de/ix/NiX-Spam-DNSBL-and-blacklist-for-download-499637.html) IP addresses that sent spam in the last hour - automatically generated entries without distinguishing open proxies from relays, dialup gateways, and so on. All IPs are removed after 12 hours if there is no spam from there.

Source is downloaded from [this link](http://www.dnsbl.manitu.net/download/nixspam-ip.dump.gz).

The last time downloaded was found to be dated: Wed Jun 10 23:45:02 UTC 2015.

The ipset `nixspam` has **28015** entries, **28015** unique IPs.

The following table shows the overlaps of `nixspam` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `nixspam`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `nixspam`.
- ` this % ` is the percentage **of this ipset (`nixspam`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[sorbs_spam](#sorbs_spam)|60429|61096|5390|8.8%|19.2%|
[sorbs_recent_spam](#sorbs_recent_spam)|60429|61096|5390|8.8%|19.2%|
[sorbs_new_spam](#sorbs_new_spam)|60429|61096|5390|8.8%|19.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|1241|0.0%|4.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|840|0.0%|2.9%|
[iw_spamlist](#iw_spamlist)|3703|3703|727|19.6%|2.5%|
[firehol_level2](#firehol_level2)|23356|34994|703|2.0%|2.5%|
[blocklist_de](#blocklist_de)|29619|29619|692|2.3%|2.4%|
[blocklist_de_mail](#blocklist_de_mail)|17317|17317|620|3.5%|2.2%|
[firehol_level3](#firehol_level3)|110224|9627969|561|0.0%|2.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|467|0.0%|1.6%|
[snort_ipfilter](#snort_ipfilter)|10158|10158|230|2.2%|0.8%|
[stopforumspam_30d](#stopforumspam_30d)|94424|94424|217|0.2%|0.7%|
[firehol_anonymous](#firehol_anonymous)|19001|83032|174|0.2%|0.6%|
[firehol_proxies](#firehol_proxies)|12463|12723|168|1.3%|0.5%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|133|0.4%|0.4%|
[ri_web_proxies](#ri_web_proxies)|7624|7624|127|1.6%|0.4%|
[sorbs_web](#sorbs_web)|432|433|112|25.8%|0.3%|
[firehol_level1](#firehol_level1)|5135|688894845|110|0.0%|0.3%|
[et_block](#et_block)|1000|18344011|109|0.0%|0.3%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|108|0.0%|0.3%|
[php_dictionary](#php_dictionary)|702|702|108|15.3%|0.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|108|0.0%|0.3%|
[php_spammers](#php_spammers)|700|700|96|13.7%|0.3%|
[alienvault_reputation](#alienvault_reputation)|182721|182721|70|0.0%|0.2%|
[xroxy](#xroxy)|2159|2159|66|3.0%|0.2%|
[stopforumspam_1d](#stopforumspam_1d)|6755|6755|44|0.6%|0.1%|
[proxz](#proxz)|1244|1244|40|3.2%|0.1%|
[blocklist_de_bots](#blocklist_de_bots)|2949|2949|34|1.1%|0.1%|
[dragon_http](#dragon_http)|1044|273664|32|0.0%|0.1%|
[blocklist_de_apache](#blocklist_de_apache)|15454|15454|32|0.2%|0.1%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4090|4090|30|0.7%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|27|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2751|2751|14|0.5%|0.0%|
[php_commenters](#php_commenters)|430|430|14|3.2%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2412|2412|12|0.4%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|11|0.0%|0.0%|
[php_harvesters](#php_harvesters)|392|392|10|2.5%|0.0%|
[tor_exits](#tor_exits)|1128|1128|6|0.5%|0.0%|
[proxyrss](#proxyrss)|1675|1675|6|0.3%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|1380|1380|6|0.4%|0.0%|
[openbl_60d](#openbl_60d)|7012|7012|5|0.0%|0.0%|
[iw_wormlist](#iw_wormlist)|33|33|4|12.1%|0.0%|
[openbl_30d](#openbl_30d)|2835|2835|3|0.1%|0.0%|
[et_tor](#et_tor)|6400|6400|3|0.0%|0.0%|
[dm_tor](#dm_tor)|6459|6459|3|0.0%|0.0%|
[bm_tor](#bm_tor)|6473|6473|3|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|183|183|3|1.6%|0.0%|
[sorbs_socks](#sorbs_socks)|3|3|2|66.6%|0.0%|
[sorbs_misc](#sorbs_misc)|3|3|2|66.6%|0.0%|
[sorbs_http](#sorbs_http)|3|3|2|66.6%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|2|0.3%|0.0%|
[zeus_badips](#zeus_badips)|202|202|1|0.4%|0.0%|
[zeus](#zeus)|230|230|1|0.4%|0.0%|
[voipbl](#voipbl)|10533|10945|1|0.0%|0.0%|
[virbl](#virbl)|31|31|1|3.2%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|1|0.0%|0.0%|
[openbl_7d](#openbl_7d)|679|679|1|0.1%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|1|0.1%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|1|0.0%|0.0%|
[et_compromised](#et_compromised)|1721|1721|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1706|1706|1|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3531|3531|1|0.0%|0.0%|

## nt_malware_http

[No Think](http://www.nothink.org/) Malware HTTP

Source is downloaded from [this link](http://www.nothink.org/blacklist/blacklist_malware_http.txt).

The last time downloaded was found to be dated: Wed Jun 10 22:05:03 UTC 2015.

The ipset `nt_malware_http` has **69** entries, **69** unique IPs.

The following table shows the overlaps of `nt_malware_http` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `nt_malware_http`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `nt_malware_http`.
- ` this % ` is the percentage **of this ipset (`nt_malware_http`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level1](#firehol_level1)|5135|688894845|8|0.0%|11.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|7|0.0%|10.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|5|0.0%|7.2%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|4|0.0%|5.7%|
[fullbogons](#fullbogons)|3770|670213096|4|0.0%|5.7%|
[et_block](#et_block)|1000|18344011|4|0.0%|5.7%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|4.3%|
[firehol_level3](#firehol_level3)|110224|9627969|3|0.0%|4.3%|
[stopforumspam_30d](#stopforumspam_30d)|94424|94424|2|0.0%|2.8%|
[nt_malware_irc](#nt_malware_irc)|43|43|2|4.6%|2.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|2|0.0%|2.8%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|1.4%|
[alienvault_reputation](#alienvault_reputation)|182721|182721|1|0.0%|1.4%|

## nt_malware_irc

[No Think](http://www.nothink.org/) Malware IRC

Source is downloaded from [this link](http://www.nothink.org/blacklist/blacklist_malware_irc.txt).

The last time downloaded was found to be dated: Wed Jun 10 22:05:03 UTC 2015.

The ipset `nt_malware_irc` has **43** entries, **43** unique IPs.

The following table shows the overlaps of `nt_malware_irc` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `nt_malware_irc`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `nt_malware_irc`.
- ` this % ` is the percentage **of this ipset (`nt_malware_irc`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|5|0.0%|11.6%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|3|0.0%|6.9%|
[firehol_level1](#firehol_level1)|5135|688894845|3|0.0%|6.9%|
[et_block](#et_block)|1000|18344011|3|0.0%|6.9%|
[nt_malware_http](#nt_malware_http)|69|69|2|2.8%|4.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|2|0.0%|4.6%|
[alienvault_reputation](#alienvault_reputation)|182721|182721|2|0.0%|4.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|1|0.0%|2.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|2.3%|
[firehol_level3](#firehol_level3)|110224|9627969|1|0.0%|2.3%|

## nt_ssh_7d

[No Think](http://www.nothink.org/) Last 7 days SSH attacks

Source is downloaded from [this link](http://www.nothink.org/blacklist/blacklist_ssh_week.txt).

The last time downloaded was found to be dated: Wed Jun 10 22:05:03 UTC 2015.

The ipset `nt_ssh_7d` has **0** entries, **0** unique IPs.

The following table shows the overlaps of `nt_ssh_7d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `nt_ssh_7d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `nt_ssh_7d`.
- ` this % ` is the percentage **of this ipset (`nt_ssh_7d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|

## openbl_1d

[OpenBL.org](http://www.openbl.org/) last 24 hours IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.

Source is downloaded from [this link](http://www.openbl.org/lists/base_1days.txt).

The last time downloaded was found to be dated: Wed Jun 10 23:32:00 UTC 2015.

The ipset `openbl_1d` has **152** entries, **152** unique IPs.

The following table shows the overlaps of `openbl_1d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl_1d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl_1d`.
- ` this % ` is the percentage **of this ipset (`openbl_1d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|23356|34994|152|0.4%|100.0%|
[firehol_level3](#firehol_level3)|110224|9627969|148|0.0%|97.3%|
[alienvault_reputation](#alienvault_reputation)|182721|182721|148|0.0%|97.3%|
[openbl_60d](#openbl_60d)|7012|7012|147|2.0%|96.7%|
[openbl_30d](#openbl_30d)|2835|2835|146|5.1%|96.0%|
[openbl_7d](#openbl_7d)|679|679|140|20.6%|92.1%|
[blocklist_de](#blocklist_de)|29619|29619|124|0.4%|81.5%|
[blocklist_de_ssh](#blocklist_de_ssh)|3531|3531|120|3.3%|78.9%|
[et_compromised](#et_compromised)|1721|1721|63|3.6%|41.4%|
[bruteforceblocker](#bruteforceblocker)|1706|1706|63|3.6%|41.4%|
[shunlist](#shunlist)|1234|1234|56|4.5%|36.8%|
[firehol_level1](#firehol_level1)|5135|688894845|18|0.0%|11.8%|
[et_block](#et_block)|1000|18344011|18|0.0%|11.8%|
[blocklist_de_strongips](#blocklist_de_strongips)|183|183|17|9.2%|11.1%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|14|0.0%|9.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|11|0.0%|7.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|8|0.0%|5.2%|
[dragon_http](#dragon_http)|1044|273664|8|0.0%|5.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|3|0.0%|1.9%|
[dshield](#dshield)|20|5120|3|0.0%|1.9%|
[stopforumspam_30d](#stopforumspam_30d)|94424|94424|2|0.0%|1.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2|0.0%|1.3%|
[blocklist_de_mail](#blocklist_de_mail)|17317|17317|2|0.0%|1.3%|
[blocklist_de_apache](#blocklist_de_apache)|15454|15454|2|0.0%|1.3%|
[zeus_badips](#zeus_badips)|202|202|1|0.4%|0.6%|
[zeus](#zeus)|230|230|1|0.4%|0.6%|
[snort_ipfilter](#snort_ipfilter)|10158|10158|1|0.0%|0.6%|
[php_spammers](#php_spammers)|700|700|1|0.1%|0.6%|
[php_commenters](#php_commenters)|430|430|1|0.2%|0.6%|
[ciarmy](#ciarmy)|469|469|1|0.2%|0.6%|
[blocklist_de_imap](#blocklist_de_imap)|2412|2412|1|0.0%|0.6%|

## openbl_30d

[OpenBL.org](http://www.openbl.org/) last 30 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.

Source is downloaded from [this link](http://www.openbl.org/lists/base_30days.txt).

The last time downloaded was found to be dated: Wed Jun 10 20:07:00 UTC 2015.

The ipset `openbl_30d` has **2835** entries, **2835** unique IPs.

The following table shows the overlaps of `openbl_30d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl_30d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl_30d`.
- ` this % ` is the percentage **of this ipset (`openbl_30d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[openbl_60d](#openbl_60d)|7012|7012|2835|40.4%|100.0%|
[firehol_level3](#firehol_level3)|110224|9627969|2835|0.0%|100.0%|
[alienvault_reputation](#alienvault_reputation)|182721|182721|2820|1.5%|99.4%|
[et_compromised](#et_compromised)|1721|1721|941|54.6%|33.1%|
[bruteforceblocker](#bruteforceblocker)|1706|1706|912|53.4%|32.1%|
[firehol_level2](#firehol_level2)|23356|34994|788|2.2%|27.7%|
[blocklist_de](#blocklist_de)|29619|29619|762|2.5%|26.8%|
[blocklist_de_ssh](#blocklist_de_ssh)|3531|3531|732|20.7%|25.8%|
[openbl_7d](#openbl_7d)|679|679|679|100.0%|23.9%|
[shunlist](#shunlist)|1234|1234|502|40.6%|17.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|295|0.0%|10.4%|
[et_block](#et_block)|1000|18344011|163|0.0%|5.7%|
[firehol_level1](#firehol_level1)|5135|688894845|161|0.0%|5.6%|
[dragon_http](#dragon_http)|1044|273664|154|0.0%|5.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|148|0.0%|5.2%|
[openbl_1d](#openbl_1d)|152|152|146|96.0%|5.1%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|119|0.0%|4.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|63|0.0%|2.2%|
[dshield](#dshield)|20|5120|39|0.7%|1.3%|
[blocklist_de_strongips](#blocklist_de_strongips)|183|183|24|13.1%|0.8%|
[blocklist_de_mail](#blocklist_de_mail)|17317|17317|21|0.1%|0.7%|
[blocklist_de_imap](#blocklist_de_imap)|2412|2412|17|0.7%|0.5%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|12|0.0%|0.4%|
[blocklist_de_apache](#blocklist_de_apache)|15454|15454|7|0.0%|0.2%|
[stopforumspam_30d](#stopforumspam_30d)|94424|94424|5|0.0%|0.1%|
[voipbl](#voipbl)|10533|10945|3|0.0%|0.1%|
[snort_ipfilter](#snort_ipfilter)|10158|10158|3|0.0%|0.1%|
[nixspam](#nixspam)|28015|28015|3|0.0%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|3|0.0%|0.1%|
[zeus](#zeus)|230|230|2|0.8%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|2|0.1%|0.0%|
[ciarmy](#ciarmy)|469|469|2|0.4%|0.0%|
[zeus_badips](#zeus_badips)|202|202|1|0.4%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|1|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6755|6755|1|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|1|0.0%|0.0%|
[php_spammers](#php_spammers)|700|700|1|0.1%|0.0%|
[php_commenters](#php_commenters)|430|430|1|0.2%|0.0%|
[firehol_anonymous](#firehol_anonymous)|19001|83032|1|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|1380|1380|1|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|2949|2949|1|0.0%|0.0%|

## openbl_60d

[OpenBL.org](http://www.openbl.org/) last 60 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.

Source is downloaded from [this link](http://www.openbl.org/lists/base_60days.txt).

The last time downloaded was found to be dated: Wed Jun 10 20:07:00 UTC 2015.

The ipset `openbl_60d` has **7012** entries, **7012** unique IPs.

The following table shows the overlaps of `openbl_60d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl_60d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl_60d`.
- ` this % ` is the percentage **of this ipset (`openbl_60d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[alienvault_reputation](#alienvault_reputation)|182721|182721|6992|3.8%|99.7%|
[firehol_level3](#firehol_level3)|110224|9627969|2964|0.0%|42.2%|
[openbl_30d](#openbl_30d)|2835|2835|2835|100.0%|40.4%|
[et_compromised](#et_compromised)|1721|1721|1009|58.6%|14.3%|
[firehol_level2](#firehol_level2)|23356|34994|997|2.8%|14.2%|
[bruteforceblocker](#bruteforceblocker)|1706|1706|975|57.1%|13.9%|
[blocklist_de](#blocklist_de)|29619|29619|952|3.2%|13.5%|
[blocklist_de_ssh](#blocklist_de_ssh)|3531|3531|914|25.8%|13.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|747|0.0%|10.6%|
[openbl_7d](#openbl_7d)|679|679|679|100.0%|9.6%|
[shunlist](#shunlist)|1234|1234|531|43.0%|7.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|321|0.0%|4.5%|
[et_block](#et_block)|1000|18344011|301|0.0%|4.2%|
[firehol_level1](#firehol_level1)|5135|688894845|296|0.0%|4.2%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|235|0.0%|3.3%|
[dragon_http](#dragon_http)|1044|273664|223|0.0%|3.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|162|0.0%|2.3%|
[openbl_1d](#openbl_1d)|152|152|147|96.7%|2.0%|
[dshield](#dshield)|20|5120|58|1.1%|0.8%|
[stopforumspam_30d](#stopforumspam_30d)|94424|94424|48|0.0%|0.6%|
[blocklist_de_mail](#blocklist_de_mail)|17317|17317|28|0.1%|0.3%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|27|0.0%|0.3%|
[snort_ipfilter](#snort_ipfilter)|10158|10158|25|0.2%|0.3%|
[blocklist_de_strongips](#blocklist_de_strongips)|183|183|25|13.6%|0.3%|
[firehol_anonymous](#firehol_anonymous)|19001|83032|23|0.0%|0.3%|
[blocklist_de_imap](#blocklist_de_imap)|2412|2412|23|0.9%|0.3%|
[tor_exits](#tor_exits)|1128|1128|20|1.7%|0.2%|
[stopforumspam_1d](#stopforumspam_1d)|6755|6755|20|0.2%|0.2%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|20|3.8%|0.2%|
[firehol_proxies](#firehol_proxies)|12463|12723|20|0.1%|0.2%|
[et_tor](#et_tor)|6400|6400|20|0.3%|0.2%|
[dm_tor](#dm_tor)|6459|6459|20|0.3%|0.2%|
[bm_tor](#bm_tor)|6473|6473|20|0.3%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|16|0.0%|0.2%|
[php_commenters](#php_commenters)|430|430|11|2.5%|0.1%|
[voipbl](#voipbl)|10533|10945|8|0.0%|0.1%|
[blocklist_de_apache](#blocklist_de_apache)|15454|15454|7|0.0%|0.0%|
[nixspam](#nixspam)|28015|28015|5|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|5|0.0%|0.0%|
[zeus](#zeus)|230|230|2|0.8%|0.0%|
[sorbs_spam](#sorbs_spam)|60429|61096|2|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|60429|61096|2|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|60429|61096|2|0.0%|0.0%|
[php_harvesters](#php_harvesters)|392|392|2|0.5%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|2|0.1%|0.0%|
[ciarmy](#ciarmy)|469|469|2|0.4%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|1380|1380|2|0.1%|0.0%|
[zeus_badips](#zeus_badips)|202|202|1|0.4%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|1|0.0%|0.0%|
[php_spammers](#php_spammers)|700|700|1|0.1%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|2949|2949|1|0.0%|0.0%|

## openbl_7d

[OpenBL.org](http://www.openbl.org/) last 7 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.

Source is downloaded from [this link](http://www.openbl.org/lists/base_7days.txt).

The last time downloaded was found to be dated: Wed Jun 10 20:07:00 UTC 2015.

The ipset `openbl_7d` has **679** entries, **679** unique IPs.

The following table shows the overlaps of `openbl_7d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl_7d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl_7d`.
- ` this % ` is the percentage **of this ipset (`openbl_7d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[openbl_60d](#openbl_60d)|7012|7012|679|9.6%|100.0%|
[openbl_30d](#openbl_30d)|2835|2835|679|23.9%|100.0%|
[firehol_level3](#firehol_level3)|110224|9627969|679|0.0%|100.0%|
[alienvault_reputation](#alienvault_reputation)|182721|182721|676|0.3%|99.5%|
[firehol_level2](#firehol_level2)|23356|34994|417|1.1%|61.4%|
[blocklist_de](#blocklist_de)|29619|29619|391|1.3%|57.5%|
[blocklist_de_ssh](#blocklist_de_ssh)|3531|3531|378|10.7%|55.6%|
[et_compromised](#et_compromised)|1721|1721|324|18.8%|47.7%|
[bruteforceblocker](#bruteforceblocker)|1706|1706|320|18.7%|47.1%|
[shunlist](#shunlist)|1234|1234|210|17.0%|30.9%|
[openbl_1d](#openbl_1d)|152|152|140|92.1%|20.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|79|0.0%|11.6%|
[et_block](#et_block)|1000|18344011|61|0.0%|8.9%|
[firehol_level1](#firehol_level1)|5135|688894845|60|0.0%|8.8%|
[dragon_http](#dragon_http)|1044|273664|60|0.0%|8.8%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|50|0.0%|7.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|40|0.0%|5.8%|
[blocklist_de_strongips](#blocklist_de_strongips)|183|183|24|13.1%|3.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|13|0.0%|1.9%|
[dshield](#dshield)|20|5120|9|0.1%|1.3%|
[blocklist_de_mail](#blocklist_de_mail)|17317|17317|7|0.0%|1.0%|
[blocklist_de_imap](#blocklist_de_imap)|2412|2412|6|0.2%|0.8%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|5|0.0%|0.7%|
[blocklist_de_apache](#blocklist_de_apache)|15454|15454|5|0.0%|0.7%|
[stopforumspam_30d](#stopforumspam_30d)|94424|94424|2|0.0%|0.2%|
[ciarmy](#ciarmy)|469|469|2|0.4%|0.2%|
[zeus_badips](#zeus_badips)|202|202|1|0.4%|0.1%|
[zeus](#zeus)|230|230|1|0.4%|0.1%|
[snort_ipfilter](#snort_ipfilter)|10158|10158|1|0.0%|0.1%|
[php_spammers](#php_spammers)|700|700|1|0.1%|0.1%|
[php_commenters](#php_commenters)|430|430|1|0.2%|0.1%|
[nixspam](#nixspam)|28015|28015|1|0.0%|0.1%|
[blocklist_de_ftp](#blocklist_de_ftp)|1380|1380|1|0.0%|0.1%|

## palevo

[Abuse.ch Palevo tracker](https://palevotracker.abuse.ch) worm includes IPs which are being used as botnet C&C for the Palevo crimeware - **excellent list**

Source is downloaded from [this link](https://palevotracker.abuse.ch/blocklists.php?download=ipblocklist).

The last time downloaded was found to be dated: Wed Jun 10 23:54:19 UTC 2015.

The ipset `palevo` has **13** entries, **13** unique IPs.

The following table shows the overlaps of `palevo` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `palevo`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `palevo`.
- ` this % ` is the percentage **of this ipset (`palevo`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level1](#firehol_level1)|5135|688894845|13|0.0%|100.0%|
[et_block](#et_block)|1000|18344011|13|0.0%|100.0%|
[snort_ipfilter](#snort_ipfilter)|10158|10158|11|0.1%|84.6%|
[firehol_level3](#firehol_level3)|110224|9627969|11|0.0%|84.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|3|0.0%|23.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|2|0.0%|15.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|1|0.0%|7.6%|

## php_commenters

[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) comment spammers (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=c&rss=1).

The last time downloaded was found to be dated: Wed Jun 10 23:54:26 UTC 2015.

The ipset `php_commenters` has **430** entries, **430** unique IPs.

The following table shows the overlaps of `php_commenters` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `php_commenters`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `php_commenters`.
- ` this % ` is the percentage **of this ipset (`php_commenters`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level3](#firehol_level3)|110224|9627969|430|0.0%|100.0%|
[stopforumspam_30d](#stopforumspam_30d)|94424|94424|318|0.3%|73.9%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|237|0.8%|55.1%|
[firehol_level2](#firehol_level2)|23356|34994|198|0.5%|46.0%|
[stopforumspam_1d](#stopforumspam_1d)|6755|6755|172|2.5%|40.0%|
[blocklist_de](#blocklist_de)|29619|29619|109|0.3%|25.3%|
[blocklist_de_bots](#blocklist_de_bots)|2949|2949|87|2.9%|20.2%|
[firehol_anonymous](#firehol_anonymous)|19001|83032|82|0.0%|19.0%|
[firehol_proxies](#firehol_proxies)|12463|12723|80|0.6%|18.6%|
[snort_ipfilter](#snort_ipfilter)|10158|10158|65|0.6%|15.1%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|52|9.9%|12.0%|
[tor_exits](#tor_exits)|1128|1128|51|4.5%|11.8%|
[et_tor](#et_tor)|6400|6400|51|0.7%|11.8%|
[dm_tor](#dm_tor)|6459|6459|51|0.7%|11.8%|
[bm_tor](#bm_tor)|6473|6473|51|0.7%|11.8%|
[php_spammers](#php_spammers)|700|700|50|7.1%|11.6%|
[blocklist_de_strongips](#blocklist_de_strongips)|183|183|48|26.2%|11.1%|
[firehol_level1](#firehol_level1)|5135|688894845|38|0.0%|8.8%|
[php_dictionary](#php_dictionary)|702|702|33|4.7%|7.6%|
[blocklist_de_apache](#blocklist_de_apache)|15454|15454|32|0.2%|7.4%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|29|0.0%|6.7%|
[et_block](#et_block)|1000|18344011|29|0.0%|6.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|28|0.0%|6.5%|
[blocklist_de_mail](#blocklist_de_mail)|17317|17317|26|0.1%|6.0%|
[ri_web_proxies](#ri_web_proxies)|7624|7624|25|0.3%|5.8%|
[sorbs_spam](#sorbs_spam)|60429|61096|21|0.0%|4.8%|
[sorbs_recent_spam](#sorbs_recent_spam)|60429|61096|21|0.0%|4.8%|
[sorbs_new_spam](#sorbs_new_spam)|60429|61096|21|0.0%|4.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|18|0.0%|4.1%|
[alienvault_reputation](#alienvault_reputation)|182721|182721|18|0.0%|4.1%|
[php_harvesters](#php_harvesters)|392|392|15|3.8%|3.4%|
[nixspam](#nixspam)|28015|28015|14|0.0%|3.2%|
[openbl_60d](#openbl_60d)|7012|7012|11|0.1%|2.5%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4090|4090|11|0.2%|2.5%|
[xroxy](#xroxy)|2159|2159|10|0.4%|2.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|10|0.0%|2.3%|
[proxz](#proxz)|1244|1244|9|0.7%|2.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|8|0.0%|1.8%|
[ri_connect_proxies](#ri_connect_proxies)|2751|2751|5|0.1%|1.1%|
[proxyrss](#proxyrss)|1675|1675|5|0.2%|1.1%|
[iw_spamlist](#iw_spamlist)|3703|3703|3|0.0%|0.6%|
[sorbs_web](#sorbs_web)|432|433|2|0.4%|0.4%|
[dragon_http](#dragon_http)|1044|273664|2|0.0%|0.4%|
[zeus_badips](#zeus_badips)|202|202|1|0.4%|0.2%|
[zeus](#zeus)|230|230|1|0.4%|0.2%|
[openbl_7d](#openbl_7d)|679|679|1|0.1%|0.2%|
[openbl_30d](#openbl_30d)|2835|2835|1|0.0%|0.2%|
[openbl_1d](#openbl_1d)|152|152|1|0.6%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.2%|
[fullbogons](#fullbogons)|3770|670213096|1|0.0%|0.2%|
[et_compromised](#et_compromised)|1721|1721|1|0.0%|0.2%|
[bruteforceblocker](#bruteforceblocker)|1706|1706|1|0.0%|0.2%|
[bogons](#bogons)|13|592708608|1|0.0%|0.2%|
[blocklist_de_ssh](#blocklist_de_ssh)|3531|3531|1|0.0%|0.2%|

## php_dictionary

[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) directory attackers (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=d&rss=1).

The last time downloaded was found to be dated: Wed Jun 10 23:54:27 UTC 2015.

The ipset `php_dictionary` has **702** entries, **702** unique IPs.

The following table shows the overlaps of `php_dictionary` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `php_dictionary`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `php_dictionary`.
- ` this % ` is the percentage **of this ipset (`php_dictionary`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level3](#firehol_level3)|110224|9627969|702|0.0%|100.0%|
[php_spammers](#php_spammers)|700|700|296|42.2%|42.1%|
[sorbs_spam](#sorbs_spam)|60429|61096|186|0.3%|26.4%|
[sorbs_recent_spam](#sorbs_recent_spam)|60429|61096|186|0.3%|26.4%|
[sorbs_new_spam](#sorbs_new_spam)|60429|61096|186|0.3%|26.4%|
[stopforumspam_30d](#stopforumspam_30d)|94424|94424|133|0.1%|18.9%|
[firehol_level2](#firehol_level2)|23356|34994|116|0.3%|16.5%|
[nixspam](#nixspam)|28015|28015|108|0.3%|15.3%|
[blocklist_de](#blocklist_de)|29619|29619|108|0.3%|15.3%|
[firehol_anonymous](#firehol_anonymous)|19001|83032|95|0.1%|13.5%|
[firehol_proxies](#firehol_proxies)|12463|12723|94|0.7%|13.3%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|88|0.2%|12.5%|
[snort_ipfilter](#snort_ipfilter)|10158|10158|86|0.8%|12.2%|
[blocklist_de_mail](#blocklist_de_mail)|17317|17317|84|0.4%|11.9%|
[ri_web_proxies](#ri_web_proxies)|7624|7624|65|0.8%|9.2%|
[xroxy](#xroxy)|2159|2159|39|1.8%|5.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|38|0.0%|5.4%|
[php_commenters](#php_commenters)|430|430|33|7.6%|4.7%|
[stopforumspam_1d](#stopforumspam_1d)|6755|6755|28|0.4%|3.9%|
[sorbs_web](#sorbs_web)|432|433|27|6.2%|3.8%|
[proxz](#proxz)|1244|1244|23|1.8%|3.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|23|0.0%|3.2%|
[blocklist_de_bots](#blocklist_de_bots)|2949|2949|20|0.6%|2.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|12|0.0%|1.7%|
[alienvault_reputation](#alienvault_reputation)|182721|182721|7|0.0%|0.9%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|6|0.0%|0.8%|
[iw_spamlist](#iw_spamlist)|3703|3703|6|0.1%|0.8%|
[firehol_level1](#firehol_level1)|5135|688894845|6|0.0%|0.8%|
[et_block](#et_block)|1000|18344011|6|0.0%|0.8%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|5|0.9%|0.7%|
[tor_exits](#tor_exits)|1128|1128|4|0.3%|0.5%|
[ri_connect_proxies](#ri_connect_proxies)|2751|2751|4|0.1%|0.5%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|4|0.0%|0.5%|
[et_tor](#et_tor)|6400|6400|4|0.0%|0.5%|
[dm_tor](#dm_tor)|6459|6459|4|0.0%|0.5%|
[bm_tor](#bm_tor)|6473|6473|4|0.0%|0.5%|
[blocklist_de_strongips](#blocklist_de_strongips)|183|183|4|2.1%|0.5%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4090|4090|4|0.0%|0.5%|
[blocklist_de_apache](#blocklist_de_apache)|15454|15454|4|0.0%|0.5%|
[php_harvesters](#php_harvesters)|392|392|3|0.7%|0.4%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|3|0.0%|0.4%|
[dragon_http](#dragon_http)|1044|273664|2|0.0%|0.2%|
[proxyrss](#proxyrss)|1675|1675|1|0.0%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.1%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|1|0.1%|0.1%|

## php_harvesters

[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) harvesters (IPs that surf the internet looking for email addresses) (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=h&rss=1).

The last time downloaded was found to be dated: Wed Jun 10 23:54:24 UTC 2015.

The ipset `php_harvesters` has **392** entries, **392** unique IPs.

The following table shows the overlaps of `php_harvesters` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `php_harvesters`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `php_harvesters`.
- ` this % ` is the percentage **of this ipset (`php_harvesters`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level3](#firehol_level3)|110224|9627969|392|0.0%|100.0%|
[stopforumspam_30d](#stopforumspam_30d)|94424|94424|84|0.0%|21.4%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|61|0.2%|15.5%|
[firehol_level2](#firehol_level2)|23356|34994|60|0.1%|15.3%|
[stopforumspam_1d](#stopforumspam_1d)|6755|6755|49|0.7%|12.5%|
[blocklist_de](#blocklist_de)|29619|29619|37|0.1%|9.4%|
[blocklist_de_bots](#blocklist_de_bots)|2949|2949|26|0.8%|6.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|20|0.0%|5.1%|
[php_commenters](#php_commenters)|430|430|15|3.4%|3.8%|
[sorbs_spam](#sorbs_spam)|60429|61096|13|0.0%|3.3%|
[sorbs_recent_spam](#sorbs_recent_spam)|60429|61096|13|0.0%|3.3%|
[sorbs_new_spam](#sorbs_new_spam)|60429|61096|13|0.0%|3.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|12|0.0%|3.0%|
[firehol_proxies](#firehol_proxies)|12463|12723|12|0.0%|3.0%|
[firehol_anonymous](#firehol_anonymous)|19001|83032|12|0.0%|3.0%|
[alienvault_reputation](#alienvault_reputation)|182721|182721|12|0.0%|3.0%|
[snort_ipfilter](#snort_ipfilter)|10158|10158|11|0.1%|2.8%|
[nixspam](#nixspam)|28015|28015|10|0.0%|2.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|9|0.0%|2.2%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|7|1.3%|1.7%|
[et_tor](#et_tor)|6400|6400|7|0.1%|1.7%|
[dm_tor](#dm_tor)|6459|6459|7|0.1%|1.7%|
[bm_tor](#bm_tor)|6473|6473|7|0.1%|1.7%|
[tor_exits](#tor_exits)|1128|1128|6|0.5%|1.5%|
[blocklist_de_mail](#blocklist_de_mail)|17317|17317|5|0.0%|1.2%|
[blocklist_de_ftp](#blocklist_de_ftp)|1380|1380|4|0.2%|1.0%|
[php_spammers](#php_spammers)|700|700|3|0.4%|0.7%|
[php_dictionary](#php_dictionary)|702|702|3|0.4%|0.7%|
[iw_spamlist](#iw_spamlist)|3703|3703|3|0.0%|0.7%|
[firehol_level1](#firehol_level1)|5135|688894845|3|0.0%|0.7%|
[blocklist_de_strongips](#blocklist_de_strongips)|183|183|3|1.6%|0.7%|
[blocklist_de_apache](#blocklist_de_apache)|15454|15454|3|0.0%|0.7%|
[xroxy](#xroxy)|2159|2159|2|0.0%|0.5%|
[ri_web_proxies](#ri_web_proxies)|7624|7624|2|0.0%|0.5%|
[openbl_60d](#openbl_60d)|7012|7012|2|0.0%|0.5%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|2|0.0%|0.5%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4090|4090|2|0.0%|0.5%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|1|0.0%|0.2%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|1|0.0%|0.2%|
[proxyrss](#proxyrss)|1675|1675|1|0.0%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.2%|
[fullbogons](#fullbogons)|3770|670213096|1|0.0%|0.2%|
[et_block](#et_block)|1000|18344011|1|0.0%|0.2%|
[bogons](#bogons)|13|592708608|1|0.0%|0.2%|
[blocklist_de_imap](#blocklist_de_imap)|2412|2412|1|0.0%|0.2%|

## php_spammers

[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) spam servers (IPs used by spammers to send messages) (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=s&rss=1).

The last time downloaded was found to be dated: Wed Jun 10 23:54:25 UTC 2015.

The ipset `php_spammers` has **700** entries, **700** unique IPs.

The following table shows the overlaps of `php_spammers` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `php_spammers`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `php_spammers`.
- ` this % ` is the percentage **of this ipset (`php_spammers`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level3](#firehol_level3)|110224|9627969|700|0.0%|100.0%|
[php_dictionary](#php_dictionary)|702|702|296|42.1%|42.2%|
[sorbs_spam](#sorbs_spam)|60429|61096|159|0.2%|22.7%|
[sorbs_recent_spam](#sorbs_recent_spam)|60429|61096|159|0.2%|22.7%|
[sorbs_new_spam](#sorbs_new_spam)|60429|61096|159|0.2%|22.7%|
[stopforumspam_30d](#stopforumspam_30d)|94424|94424|144|0.1%|20.5%|
[firehol_level2](#firehol_level2)|23356|34994|114|0.3%|16.2%|
[blocklist_de](#blocklist_de)|29619|29619|104|0.3%|14.8%|
[nixspam](#nixspam)|28015|28015|96|0.3%|13.7%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|87|0.2%|12.4%|
[snort_ipfilter](#snort_ipfilter)|10158|10158|83|0.8%|11.8%|
[firehol_anonymous](#firehol_anonymous)|19001|83032|80|0.0%|11.4%|
[firehol_proxies](#firehol_proxies)|12463|12723|78|0.6%|11.1%|
[blocklist_de_mail](#blocklist_de_mail)|17317|17317|71|0.4%|10.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|54|0.0%|7.7%|
[ri_web_proxies](#ri_web_proxies)|7624|7624|53|0.6%|7.5%|
[php_commenters](#php_commenters)|430|430|50|11.6%|7.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|43|0.0%|6.1%|
[stopforumspam_1d](#stopforumspam_1d)|6755|6755|36|0.5%|5.1%|
[xroxy](#xroxy)|2159|2159|32|1.4%|4.5%|
[blocklist_de_bots](#blocklist_de_bots)|2949|2949|24|0.8%|3.4%|
[sorbs_web](#sorbs_web)|432|433|22|5.0%|3.1%|
[proxz](#proxz)|1244|1244|21|1.6%|3.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|10|0.0%|1.4%|
[iw_spamlist](#iw_spamlist)|3703|3703|9|0.2%|1.2%|
[blocklist_de_strongips](#blocklist_de_strongips)|183|183|9|4.9%|1.2%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4090|4090|8|0.1%|1.1%|
[blocklist_de_apache](#blocklist_de_apache)|15454|15454|8|0.0%|1.1%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|6|1.1%|0.8%|
[tor_exits](#tor_exits)|1128|1128|5|0.4%|0.7%|
[et_tor](#et_tor)|6400|6400|5|0.0%|0.7%|
[dm_tor](#dm_tor)|6459|6459|5|0.0%|0.7%|
[bm_tor](#bm_tor)|6473|6473|5|0.0%|0.7%|
[alienvault_reputation](#alienvault_reputation)|182721|182721|5|0.0%|0.7%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|4|0.0%|0.5%|
[firehol_level1](#firehol_level1)|5135|688894845|4|0.0%|0.5%|
[et_block](#et_block)|1000|18344011|4|0.0%|0.5%|
[ri_connect_proxies](#ri_connect_proxies)|2751|2751|3|0.1%|0.4%|
[proxyrss](#proxyrss)|1675|1675|3|0.1%|0.4%|
[php_harvesters](#php_harvesters)|392|392|3|0.7%|0.4%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|0.4%|
[openbl_7d](#openbl_7d)|679|679|1|0.1%|0.1%|
[openbl_60d](#openbl_60d)|7012|7012|1|0.0%|0.1%|
[openbl_30d](#openbl_30d)|2835|2835|1|0.0%|0.1%|
[openbl_1d](#openbl_1d)|152|152|1|0.6%|0.1%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|1|0.0%|0.1%|
[et_compromised](#et_compromised)|1721|1721|1|0.0%|0.1%|
[bruteforceblocker](#bruteforceblocker)|1706|1706|1|0.0%|0.1%|
[blocklist_de_ssh](#blocklist_de_ssh)|3531|3531|1|0.0%|0.1%|

## proxyrss

[proxyrss.com](http://www.proxyrss.com) open proxies syndicated from multiple sources.

Source is downloaded from [this link](http://www.proxyrss.com/proxylists/all.gz).

The last time downloaded was found to be dated: Wed Jun 10 20:01:25 UTC 2015.

The ipset `proxyrss` has **1675** entries, **1675** unique IPs.

The following table shows the overlaps of `proxyrss` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `proxyrss`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `proxyrss`.
- ` this % ` is the percentage **of this ipset (`proxyrss`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_proxies](#firehol_proxies)|12463|12723|1675|13.1%|100.0%|
[firehol_anonymous](#firehol_anonymous)|19001|83032|1675|2.0%|100.0%|
[stopforumspam_30d](#stopforumspam_30d)|94424|94424|707|0.7%|42.2%|
[firehol_level3](#firehol_level3)|110224|9627969|707|0.0%|42.2%|
[ri_web_proxies](#ri_web_proxies)|7624|7624|595|7.8%|35.5%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|500|1.7%|29.8%|
[firehol_level2](#firehol_level2)|23356|34994|438|1.2%|26.1%|
[stopforumspam_1d](#stopforumspam_1d)|6755|6755|366|5.4%|21.8%|
[xroxy](#xroxy)|2159|2159|337|15.6%|20.1%|
[proxz](#proxz)|1244|1244|272|21.8%|16.2%|
[blocklist_de](#blocklist_de)|29619|29619|228|0.7%|13.6%|
[blocklist_de_bots](#blocklist_de_bots)|2949|2949|227|7.6%|13.5%|
[ri_connect_proxies](#ri_connect_proxies)|2751|2751|197|7.1%|11.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|53|0.0%|3.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|47|0.0%|2.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|33|0.0%|1.9%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|8|1.2%|0.4%|
[sorbs_spam](#sorbs_spam)|60429|61096|6|0.0%|0.3%|
[sorbs_recent_spam](#sorbs_recent_spam)|60429|61096|6|0.0%|0.3%|
[sorbs_new_spam](#sorbs_new_spam)|60429|61096|6|0.0%|0.3%|
[snort_ipfilter](#snort_ipfilter)|10158|10158|6|0.0%|0.3%|
[nixspam](#nixspam)|28015|28015|6|0.0%|0.3%|
[php_commenters](#php_commenters)|430|430|5|1.1%|0.2%|
[blocklist_de_strongips](#blocklist_de_strongips)|183|183|5|2.7%|0.2%|
[php_spammers](#php_spammers)|700|700|3|0.4%|0.1%|
[dragon_http](#dragon_http)|1044|273664|3|0.0%|0.1%|
[iw_spamlist](#iw_spamlist)|3703|3703|2|0.0%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|2|0.0%|0.1%|
[sorbs_web](#sorbs_web)|432|433|1|0.2%|0.0%|
[php_harvesters](#php_harvesters)|392|392|1|0.2%|0.0%|
[php_dictionary](#php_dictionary)|702|702|1|0.1%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|1|0.1%|0.0%|
[et_compromised](#et_compromised)|1721|1721|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1706|1706|1|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|17317|17317|1|0.0%|0.0%|
[alienvault_reputation](#alienvault_reputation)|182721|182721|1|0.0%|0.0%|

## proxz

[proxz.com](http://www.proxz.com) open proxies (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.proxz.com/proxylists.xml).

The last time downloaded was found to be dated: Wed Jun 10 22:21:32 UTC 2015.

The ipset `proxz` has **1244** entries, **1244** unique IPs.

The following table shows the overlaps of `proxz` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `proxz`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `proxz`.
- ` this % ` is the percentage **of this ipset (`proxz`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_proxies](#firehol_proxies)|12463|12723|1244|9.7%|100.0%|
[firehol_anonymous](#firehol_anonymous)|19001|83032|1244|1.4%|100.0%|
[firehol_level3](#firehol_level3)|110224|9627969|737|0.0%|59.2%|
[stopforumspam_30d](#stopforumspam_30d)|94424|94424|731|0.7%|58.7%|
[ri_web_proxies](#ri_web_proxies)|7624|7624|571|7.4%|45.9%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|494|1.6%|39.7%|
[xroxy](#xroxy)|2159|2159|442|20.4%|35.5%|
[proxyrss](#proxyrss)|1675|1675|272|16.2%|21.8%|
[firehol_level2](#firehol_level2)|23356|34994|271|0.7%|21.7%|
[ri_connect_proxies](#ri_connect_proxies)|2751|2751|212|7.7%|17.0%|
[blocklist_de](#blocklist_de)|29619|29619|184|0.6%|14.7%|
[stopforumspam_1d](#stopforumspam_1d)|6755|6755|178|2.6%|14.3%|
[blocklist_de_bots](#blocklist_de_bots)|2949|2949|155|5.2%|12.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|102|0.0%|8.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|51|0.0%|4.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|43|0.0%|3.4%|
[sorbs_spam](#sorbs_spam)|60429|61096|42|0.0%|3.3%|
[sorbs_recent_spam](#sorbs_recent_spam)|60429|61096|42|0.0%|3.3%|
[sorbs_new_spam](#sorbs_new_spam)|60429|61096|42|0.0%|3.3%|
[nixspam](#nixspam)|28015|28015|40|0.1%|3.2%|
[blocklist_de_mail](#blocklist_de_mail)|17317|17317|29|0.1%|2.3%|
[snort_ipfilter](#snort_ipfilter)|10158|10158|26|0.2%|2.0%|
[php_dictionary](#php_dictionary)|702|702|23|3.2%|1.8%|
[php_spammers](#php_spammers)|700|700|21|3.0%|1.6%|
[php_commenters](#php_commenters)|430|430|9|2.0%|0.7%|
[sorbs_web](#sorbs_web)|432|433|7|1.6%|0.5%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|6|0.9%|0.4%|
[blocklist_de_strongips](#blocklist_de_strongips)|183|183|5|2.7%|0.4%|
[dragon_http](#dragon_http)|1044|273664|4|0.0%|0.3%|
[alienvault_reputation](#alienvault_reputation)|182721|182721|3|0.0%|0.2%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|2|0.3%|0.1%|
[et_compromised](#et_compromised)|1721|1721|2|0.1%|0.1%|
[bruteforceblocker](#bruteforceblocker)|1706|1706|2|0.1%|0.1%|
[iw_spamlist](#iw_spamlist)|3703|3703|1|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|1|0.0%|0.0%|

## ri_connect_proxies

[rosinstrument.com](http://www.rosinstrument.com) open CONNECT proxies (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://tools.rosinstrument.com/proxy/plab100.xml).

The last time downloaded was found to be dated: Wed Jun 10 21:40:37 UTC 2015.

The ipset `ri_connect_proxies` has **2751** entries, **2751** unique IPs.

The following table shows the overlaps of `ri_connect_proxies` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ri_connect_proxies`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ri_connect_proxies`.
- ` this % ` is the percentage **of this ipset (`ri_connect_proxies`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_proxies](#firehol_proxies)|12463|12723|2751|21.6%|100.0%|
[firehol_anonymous](#firehol_anonymous)|19001|83032|2751|3.3%|100.0%|
[stopforumspam_30d](#stopforumspam_30d)|94424|94424|1546|1.6%|56.1%|
[firehol_level3](#firehol_level3)|110224|9627969|1546|0.0%|56.1%|
[ri_web_proxies](#ri_web_proxies)|7624|7624|1170|15.3%|42.5%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|592|2.0%|21.5%|
[xroxy](#xroxy)|2159|2159|391|18.1%|14.2%|
[proxz](#proxz)|1244|1244|212|17.0%|7.7%|
[proxyrss](#proxyrss)|1675|1675|197|11.7%|7.1%|
[firehol_level2](#firehol_level2)|23356|34994|147|0.4%|5.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|105|0.0%|3.8%|
[stopforumspam_1d](#stopforumspam_1d)|6755|6755|103|1.5%|3.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|83|0.0%|3.0%|
[blocklist_de](#blocklist_de)|29619|29619|70|0.2%|2.5%|
[blocklist_de_bots](#blocklist_de_bots)|2949|2949|67|2.2%|2.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|57|0.0%|2.0%|
[nixspam](#nixspam)|28015|28015|14|0.0%|0.5%|
[sorbs_spam](#sorbs_spam)|60429|61096|13|0.0%|0.4%|
[sorbs_recent_spam](#sorbs_recent_spam)|60429|61096|13|0.0%|0.4%|
[sorbs_new_spam](#sorbs_new_spam)|60429|61096|13|0.0%|0.4%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|7|1.0%|0.2%|
[php_commenters](#php_commenters)|430|430|5|1.1%|0.1%|
[snort_ipfilter](#snort_ipfilter)|10158|10158|4|0.0%|0.1%|
[php_dictionary](#php_dictionary)|702|702|4|0.5%|0.1%|
[php_spammers](#php_spammers)|700|700|3|0.4%|0.1%|
[dragon_http](#dragon_http)|1044|273664|3|0.0%|0.1%|
[blocklist_de_mail](#blocklist_de_mail)|17317|17317|3|0.0%|0.1%|
[alienvault_reputation](#alienvault_reputation)|182721|182721|3|0.0%|0.1%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|1|0.1%|0.0%|
[iw_spamlist](#iw_spamlist)|3703|3703|1|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.0%|
[dm_tor](#dm_tor)|6459|6459|1|0.0%|0.0%|
[bm_tor](#bm_tor)|6473|6473|1|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2412|2412|1|0.0%|0.0%|

## ri_web_proxies

[rosinstrument.com](http://www.rosinstrument.com) open HTTP proxies (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://tools.rosinstrument.com/proxy/l100.xml).

The last time downloaded was found to be dated: Wed Jun 10 21:39:02 UTC 2015.

The ipset `ri_web_proxies` has **7624** entries, **7624** unique IPs.

The following table shows the overlaps of `ri_web_proxies` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ri_web_proxies`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ri_web_proxies`.
- ` this % ` is the percentage **of this ipset (`ri_web_proxies`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_proxies](#firehol_proxies)|12463|12723|7624|59.9%|100.0%|
[firehol_anonymous](#firehol_anonymous)|19001|83032|7624|9.1%|100.0%|
[firehol_level3](#firehol_level3)|110224|9627969|3654|0.0%|47.9%|
[stopforumspam_30d](#stopforumspam_30d)|94424|94424|3611|3.8%|47.3%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|1549|5.2%|20.3%|
[ri_connect_proxies](#ri_connect_proxies)|2751|2751|1170|42.5%|15.3%|
[xroxy](#xroxy)|2159|2159|953|44.1%|12.5%|
[firehol_level2](#firehol_level2)|23356|34994|685|1.9%|8.9%|
[proxyrss](#proxyrss)|1675|1675|595|35.5%|7.8%|
[proxz](#proxz)|1244|1244|571|45.9%|7.4%|
[stopforumspam_1d](#stopforumspam_1d)|6755|6755|455|6.7%|5.9%|
[blocklist_de](#blocklist_de)|29619|29619|446|1.5%|5.8%|
[blocklist_de_bots](#blocklist_de_bots)|2949|2949|367|12.4%|4.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|222|0.0%|2.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|218|0.0%|2.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|153|0.0%|2.0%|
[sorbs_spam](#sorbs_spam)|60429|61096|131|0.2%|1.7%|
[sorbs_recent_spam](#sorbs_recent_spam)|60429|61096|131|0.2%|1.7%|
[sorbs_new_spam](#sorbs_new_spam)|60429|61096|131|0.2%|1.7%|
[nixspam](#nixspam)|28015|28015|127|0.4%|1.6%|
[blocklist_de_mail](#blocklist_de_mail)|17317|17317|73|0.4%|0.9%|
[php_dictionary](#php_dictionary)|702|702|65|9.2%|0.8%|
[snort_ipfilter](#snort_ipfilter)|10158|10158|58|0.5%|0.7%|
[php_spammers](#php_spammers)|700|700|53|7.5%|0.6%|
[php_commenters](#php_commenters)|430|430|25|5.8%|0.3%|
[sorbs_web](#sorbs_web)|432|433|17|3.9%|0.2%|
[dragon_http](#dragon_http)|1044|273664|16|0.0%|0.2%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|14|2.1%|0.1%|
[iw_spamlist](#iw_spamlist)|3703|3703|12|0.3%|0.1%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|10|1.9%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|6|0.0%|0.0%|
[dm_tor](#dm_tor)|6459|6459|5|0.0%|0.0%|
[bm_tor](#bm_tor)|6473|6473|5|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|183|183|5|2.7%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4090|4090|5|0.1%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|15454|15454|5|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|4|0.0%|0.0%|
[et_tor](#et_tor)|6400|6400|4|0.0%|0.0%|
[alienvault_reputation](#alienvault_reputation)|182721|182721|4|0.0%|0.0%|
[php_harvesters](#php_harvesters)|392|392|2|0.5%|0.0%|
[sslbl](#sslbl)|372|372|1|0.2%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|1|0.0%|0.0%|
[firehol_level1](#firehol_level1)|5135|688894845|1|0.0%|0.0%|
[et_compromised](#et_compromised)|1721|1721|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1706|1706|1|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3531|3531|1|0.0%|0.0%|

## shunlist

[AutoShun.org](http://autoshun.org/) IPs identified as hostile by correlating logs from distributed snort installations running the autoshun plugin

Source is downloaded from [this link](http://www.autoshun.org/files/shunlist.csv).

The last time downloaded was found to be dated: Wed Jun 10 23:30:03 UTC 2015.

The ipset `shunlist` has **1234** entries, **1234** unique IPs.

The following table shows the overlaps of `shunlist` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `shunlist`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `shunlist`.
- ` this % ` is the percentage **of this ipset (`shunlist`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level3](#firehol_level3)|110224|9627969|1234|0.0%|100.0%|
[alienvault_reputation](#alienvault_reputation)|182721|182721|1223|0.6%|99.1%|
[openbl_60d](#openbl_60d)|7012|7012|531|7.5%|43.0%|
[openbl_30d](#openbl_30d)|2835|2835|502|17.7%|40.6%|
[firehol_level2](#firehol_level2)|23356|34994|426|1.2%|34.5%|
[et_compromised](#et_compromised)|1721|1721|424|24.6%|34.3%|
[blocklist_de](#blocklist_de)|29619|29619|424|1.4%|34.3%|
[bruteforceblocker](#bruteforceblocker)|1706|1706|394|23.0%|31.9%|
[blocklist_de_ssh](#blocklist_de_ssh)|3531|3531|387|10.9%|31.3%|
[openbl_7d](#openbl_7d)|679|679|210|30.9%|17.0%|
[firehol_level1](#firehol_level1)|5135|688894845|175|0.0%|14.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|117|0.0%|9.4%|
[et_block](#et_block)|1000|18344011|113|0.0%|9.1%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|92|0.0%|7.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|68|0.0%|5.5%|
[sslbl](#sslbl)|372|372|61|16.3%|4.9%|
[openbl_1d](#openbl_1d)|152|152|56|36.8%|4.5%|
[dragon_http](#dragon_http)|1044|273664|37|0.0%|2.9%|
[blocklist_de_apache](#blocklist_de_apache)|15454|15454|31|0.2%|2.5%|
[ciarmy](#ciarmy)|469|469|30|6.3%|2.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|25|0.0%|2.0%|
[dshield](#dshield)|20|5120|22|0.4%|1.7%|
[blocklist_de_strongips](#blocklist_de_strongips)|183|183|19|10.3%|1.5%|
[voipbl](#voipbl)|10533|10945|12|0.1%|0.9%|
[blocklist_de_mail](#blocklist_de_mail)|17317|17317|4|0.0%|0.3%|
[blocklist_de_imap](#blocklist_de_imap)|2412|2412|4|0.1%|0.3%|
[stopforumspam_30d](#stopforumspam_30d)|94424|94424|3|0.0%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|0.2%|
[sorbs_spam](#sorbs_spam)|60429|61096|2|0.0%|0.1%|
[sorbs_recent_spam](#sorbs_recent_spam)|60429|61096|2|0.0%|0.1%|
[sorbs_new_spam](#sorbs_new_spam)|60429|61096|2|0.0%|0.1%|
[snort_ipfilter](#snort_ipfilter)|10158|10158|2|0.0%|0.1%|
[tor_exits](#tor_exits)|1128|1128|1|0.0%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|1|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6755|6755|1|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|1|0.1%|0.0%|
[firehol_proxies](#firehol_proxies)|12463|12723|1|0.0%|0.0%|
[firehol_anonymous](#firehol_anonymous)|19001|83032|1|0.0%|0.0%|
[et_tor](#et_tor)|6400|6400|1|0.0%|0.0%|
[dm_tor](#dm_tor)|6459|6459|1|0.0%|0.0%|
[bm_tor](#bm_tor)|6473|6473|1|0.0%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|79|79|1|1.2%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4090|4090|1|0.0%|0.0%|

## snort_ipfilter

[labs.snort.org](https://labs.snort.org/) supplied IP blacklist (this list seems to be updated frequently, but we found no information about it)

Source is downloaded from [this link](http://labs.snort.org/feeds/ip-filter.blf).

The last time downloaded was found to be dated: Wed Jun 10 16:00:00 UTC 2015.

The ipset `snort_ipfilter` has **10158** entries, **10158** unique IPs.

The following table shows the overlaps of `snort_ipfilter` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `snort_ipfilter`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `snort_ipfilter`.
- ` this % ` is the percentage **of this ipset (`snort_ipfilter`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level3](#firehol_level3)|110224|9627969|10158|0.1%|100.0%|
[firehol_anonymous](#firehol_anonymous)|19001|83032|1246|1.5%|12.2%|
[tor_exits](#tor_exits)|1128|1128|1094|96.9%|10.7%|
[et_tor](#et_tor)|6400|6400|1089|17.0%|10.7%|
[bm_tor](#bm_tor)|6473|6473|1061|16.3%|10.4%|
[dm_tor](#dm_tor)|6459|6459|1060|16.4%|10.4%|
[sorbs_spam](#sorbs_spam)|60429|61096|1038|1.6%|10.2%|
[sorbs_recent_spam](#sorbs_recent_spam)|60429|61096|1038|1.6%|10.2%|
[sorbs_new_spam](#sorbs_new_spam)|60429|61096|1038|1.6%|10.2%|
[stopforumspam_30d](#stopforumspam_30d)|94424|94424|816|0.8%|8.0%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|658|2.2%|6.4%|
[firehol_level2](#firehol_level2)|23356|34994|599|1.7%|5.8%|
[stopforumspam_1d](#stopforumspam_1d)|6755|6755|426|6.3%|4.1%|
[firehol_proxies](#firehol_proxies)|12463|12723|320|2.5%|3.1%|
[firehol_level1](#firehol_level1)|5135|688894845|301|0.0%|2.9%|
[et_block](#et_block)|1000|18344011|298|0.0%|2.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|243|0.0%|2.3%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|239|45.6%|2.3%|
[nixspam](#nixspam)|28015|28015|230|0.8%|2.2%|
[blocklist_de](#blocklist_de)|29619|29619|212|0.7%|2.0%|
[zeus](#zeus)|230|230|200|86.9%|1.9%|
[zeus_badips](#zeus_badips)|202|202|178|88.1%|1.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|158|0.0%|1.5%|
[blocklist_de_mail](#blocklist_de_mail)|17317|17317|154|0.8%|1.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|117|0.0%|1.1%|
[alienvault_reputation](#alienvault_reputation)|182721|182721|109|0.0%|1.0%|
[php_dictionary](#php_dictionary)|702|702|86|12.2%|0.8%|
[php_spammers](#php_spammers)|700|700|83|11.8%|0.8%|
[feodo](#feodo)|105|105|83|79.0%|0.8%|
[php_commenters](#php_commenters)|430|430|65|15.1%|0.6%|
[ri_web_proxies](#ri_web_proxies)|7624|7624|58|0.7%|0.5%|
[iw_spamlist](#iw_spamlist)|3703|3703|52|1.4%|0.5%|
[sorbs_web](#sorbs_web)|432|433|48|11.0%|0.4%|
[xroxy](#xroxy)|2159|2159|41|1.8%|0.4%|
[blocklist_de_apache](#blocklist_de_apache)|15454|15454|41|0.2%|0.4%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4090|4090|37|0.9%|0.3%|
[sslbl](#sslbl)|372|372|32|8.6%|0.3%|
[proxz](#proxz)|1244|1244|26|2.0%|0.2%|
[openbl_60d](#openbl_60d)|7012|7012|25|0.3%|0.2%|
[blocklist_de_bots](#blocklist_de_bots)|2949|2949|21|0.7%|0.2%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|19|0.0%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|14|0.0%|0.1%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|12|0.9%|0.1%|
[php_harvesters](#php_harvesters)|392|392|11|2.8%|0.1%|
[palevo](#palevo)|13|13|11|84.6%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|11|0.0%|0.1%|
[dragon_http](#dragon_http)|1044|273664|7|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|6|0.0%|0.0%|
[proxyrss](#proxyrss)|1675|1675|6|0.3%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2412|2412|6|0.2%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2751|2751|4|0.1%|0.0%|
[openbl_30d](#openbl_30d)|2835|2835|3|0.1%|0.0%|
[shunlist](#shunlist)|1234|1234|2|0.1%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|183|183|2|1.0%|0.0%|
[voipbl](#voipbl)|10533|10945|1|0.0%|0.0%|
[virbl](#virbl)|31|31|1|3.2%|0.0%|
[sorbs_socks](#sorbs_socks)|3|3|1|33.3%|0.0%|
[sorbs_misc](#sorbs_misc)|3|3|1|33.3%|0.0%|
[sorbs_http](#sorbs_http)|3|3|1|33.3%|0.0%|
[openbl_7d](#openbl_7d)|679|679|1|0.1%|0.0%|
[openbl_1d](#openbl_1d)|152|152|1|0.6%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|1|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|1|0.1%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|1|0.0%|0.0%|
[et_compromised](#et_compromised)|1721|1721|1|0.0%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|65|65|1|1.5%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1706|1706|1|0.0%|0.0%|

## sorbs_dul

[Sorbs.net](https://www.sorbs.net/) DUL, Dynamic User IPs extracted from deltas.

Source is downloaded from [this link]().

The last time downloaded was found to be dated: Wed Jun 10 18:41:13 UTC 2015.

The ipset `sorbs_dul` has **9** entries, **4608** unique IPs.

The following table shows the overlaps of `sorbs_dul` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `sorbs_dul`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `sorbs_dul`.
- ` this % ` is the percentage **of this ipset (`sorbs_dul`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|

## sorbs_http

[Sorbs.net](https://www.sorbs.net/) HTTP proxies, extracted from deltas.

Source is downloaded from [this link]().

The last time downloaded was found to be dated: Wed Jun 10 22:04:31 UTC 2015.

The ipset `sorbs_http` has **3** entries, **3** unique IPs.

The following table shows the overlaps of `sorbs_http` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `sorbs_http`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `sorbs_http`.
- ` this % ` is the percentage **of this ipset (`sorbs_http`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[sorbs_spam](#sorbs_spam)|60429|61096|3|0.0%|100.0%|
[sorbs_socks](#sorbs_socks)|3|3|3|100.0%|100.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|60429|61096|3|0.0%|100.0%|
[sorbs_new_spam](#sorbs_new_spam)|60429|61096|3|0.0%|100.0%|
[sorbs_misc](#sorbs_misc)|3|3|3|100.0%|100.0%|
[nixspam](#nixspam)|28015|28015|2|0.0%|66.6%|
[snort_ipfilter](#snort_ipfilter)|10158|10158|1|0.0%|33.3%|
[firehol_level3](#firehol_level3)|110224|9627969|1|0.0%|33.3%|

## sorbs_misc

[Sorbs.net](https://www.sorbs.net/) MISC proxies, extracted from deltas.

Source is downloaded from [this link]().

The last time downloaded was found to be dated: Wed Jun 10 22:04:31 UTC 2015.

The ipset `sorbs_misc` has **3** entries, **3** unique IPs.

The following table shows the overlaps of `sorbs_misc` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `sorbs_misc`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `sorbs_misc`.
- ` this % ` is the percentage **of this ipset (`sorbs_misc`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[sorbs_spam](#sorbs_spam)|60429|61096|3|0.0%|100.0%|
[sorbs_socks](#sorbs_socks)|3|3|3|100.0%|100.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|60429|61096|3|0.0%|100.0%|
[sorbs_new_spam](#sorbs_new_spam)|60429|61096|3|0.0%|100.0%|
[sorbs_http](#sorbs_http)|3|3|3|100.0%|100.0%|
[nixspam](#nixspam)|28015|28015|2|0.0%|66.6%|
[snort_ipfilter](#snort_ipfilter)|10158|10158|1|0.0%|33.3%|
[firehol_level3](#firehol_level3)|110224|9627969|1|0.0%|33.3%|

## sorbs_new_spam

[Sorbs.net](https://www.sorbs.net/) NEW Spam senders, extracted from deltas.

Source is downloaded from [this link]().

The last time downloaded was found to be dated: Wed Jun 10 23:04:31 UTC 2015.

The ipset `sorbs_new_spam` has **60429** entries, **61096** unique IPs.

The following table shows the overlaps of `sorbs_new_spam` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `sorbs_new_spam`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `sorbs_new_spam`.
- ` this % ` is the percentage **of this ipset (`sorbs_new_spam`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[sorbs_spam](#sorbs_spam)|60429|61096|61096|100.0%|100.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|60429|61096|61096|100.0%|100.0%|
[nixspam](#nixspam)|28015|28015|5390|19.2%|8.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|2514|0.0%|4.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|1636|0.0%|2.6%|
[firehol_level3](#firehol_level3)|110224|9627969|1398|0.0%|2.2%|
[firehol_level2](#firehol_level2)|23356|34994|1318|3.7%|2.1%|
[blocklist_de](#blocklist_de)|29619|29619|1307|4.4%|2.1%|
[blocklist_de_mail](#blocklist_de_mail)|17317|17317|1202|6.9%|1.9%|
[iw_spamlist](#iw_spamlist)|3703|3703|1157|31.2%|1.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|1148|0.0%|1.8%|
[snort_ipfilter](#snort_ipfilter)|10158|10158|1038|10.2%|1.6%|
[stopforumspam_30d](#stopforumspam_30d)|94424|94424|286|0.3%|0.4%|
[sorbs_web](#sorbs_web)|432|433|240|55.4%|0.3%|
[php_dictionary](#php_dictionary)|702|702|186|26.4%|0.3%|
[firehol_anonymous](#firehol_anonymous)|19001|83032|186|0.2%|0.3%|
[firehol_proxies](#firehol_proxies)|12463|12723|181|1.4%|0.2%|
[php_spammers](#php_spammers)|700|700|159|22.7%|0.2%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|153|0.5%|0.2%|
[ri_web_proxies](#ri_web_proxies)|7624|7624|131|1.7%|0.2%|
[alienvault_reputation](#alienvault_reputation)|182721|182721|86|0.0%|0.1%|
[xroxy](#xroxy)|2159|2159|73|3.3%|0.1%|
[dragon_http](#dragon_http)|1044|273664|61|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4090|4090|59|1.4%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|15454|15454|59|0.3%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6755|6755|42|0.6%|0.0%|
[proxz](#proxz)|1244|1244|42|3.3%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|34|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|2949|2949|34|1.1%|0.0%|
[firehol_level1](#firehol_level1)|5135|688894845|26|0.0%|0.0%|
[et_block](#et_block)|1000|18344011|22|0.0%|0.0%|
[php_commenters](#php_commenters)|430|430|21|4.8%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|20|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|20|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2412|2412|19|0.7%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|15|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2751|2751|13|0.4%|0.0%|
[php_harvesters](#php_harvesters)|392|392|13|3.3%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|1380|1380|8|0.5%|0.0%|
[proxyrss](#proxyrss)|1675|1675|6|0.3%|0.0%|
[tor_exits](#tor_exits)|1128|1128|5|0.4%|0.0%|
[sorbs_smtp](#sorbs_smtp)|4|4|4|100.0%|0.0%|
[et_tor](#et_tor)|6400|6400|4|0.0%|0.0%|
[dm_tor](#dm_tor)|6459|6459|4|0.0%|0.0%|
[bm_tor](#bm_tor)|6473|6473|4|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3531|3531|4|0.1%|0.0%|
[sorbs_socks](#sorbs_socks)|3|3|3|100.0%|0.0%|
[sorbs_misc](#sorbs_misc)|3|3|3|100.0%|0.0%|
[sorbs_http](#sorbs_http)|3|3|3|100.0%|0.0%|
[et_compromised](#et_compromised)|1721|1721|3|0.1%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1706|1706|3|0.1%|0.0%|
[voipbl](#voipbl)|10533|10945|2|0.0%|0.0%|
[shunlist](#shunlist)|1234|1234|2|0.1%|0.0%|
[openbl_60d](#openbl_60d)|7012|7012|2|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|2|0.1%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|183|183|2|1.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|1|0.1%|0.0%|
[malc0de](#malc0de)|313|313|1|0.3%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|1|0.1%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.0%|
[dshield](#dshield)|20|5120|1|0.0%|0.0%|

## sorbs_recent_spam

[Sorbs.net](https://www.sorbs.net/) RECENT Spam senders, extracted from deltas.

Source is downloaded from [this link]().

The last time downloaded was found to be dated: Wed Jun 10 23:04:30 UTC 2015.

The ipset `sorbs_recent_spam` has **60429** entries, **61096** unique IPs.

The following table shows the overlaps of `sorbs_recent_spam` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `sorbs_recent_spam`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `sorbs_recent_spam`.
- ` this % ` is the percentage **of this ipset (`sorbs_recent_spam`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[sorbs_spam](#sorbs_spam)|60429|61096|61096|100.0%|100.0%|
[sorbs_new_spam](#sorbs_new_spam)|60429|61096|61096|100.0%|100.0%|
[nixspam](#nixspam)|28015|28015|5390|19.2%|8.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|2514|0.0%|4.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|1636|0.0%|2.6%|
[firehol_level3](#firehol_level3)|110224|9627969|1398|0.0%|2.2%|
[firehol_level2](#firehol_level2)|23356|34994|1318|3.7%|2.1%|
[blocklist_de](#blocklist_de)|29619|29619|1307|4.4%|2.1%|
[blocklist_de_mail](#blocklist_de_mail)|17317|17317|1202|6.9%|1.9%|
[iw_spamlist](#iw_spamlist)|3703|3703|1157|31.2%|1.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|1148|0.0%|1.8%|
[snort_ipfilter](#snort_ipfilter)|10158|10158|1038|10.2%|1.6%|
[stopforumspam_30d](#stopforumspam_30d)|94424|94424|286|0.3%|0.4%|
[sorbs_web](#sorbs_web)|432|433|240|55.4%|0.3%|
[php_dictionary](#php_dictionary)|702|702|186|26.4%|0.3%|
[firehol_anonymous](#firehol_anonymous)|19001|83032|186|0.2%|0.3%|
[firehol_proxies](#firehol_proxies)|12463|12723|181|1.4%|0.2%|
[php_spammers](#php_spammers)|700|700|159|22.7%|0.2%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|153|0.5%|0.2%|
[ri_web_proxies](#ri_web_proxies)|7624|7624|131|1.7%|0.2%|
[alienvault_reputation](#alienvault_reputation)|182721|182721|86|0.0%|0.1%|
[xroxy](#xroxy)|2159|2159|73|3.3%|0.1%|
[dragon_http](#dragon_http)|1044|273664|61|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4090|4090|59|1.4%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|15454|15454|59|0.3%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6755|6755|42|0.6%|0.0%|
[proxz](#proxz)|1244|1244|42|3.3%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|34|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|2949|2949|34|1.1%|0.0%|
[firehol_level1](#firehol_level1)|5135|688894845|26|0.0%|0.0%|
[et_block](#et_block)|1000|18344011|22|0.0%|0.0%|
[php_commenters](#php_commenters)|430|430|21|4.8%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|20|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|20|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2412|2412|19|0.7%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|15|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2751|2751|13|0.4%|0.0%|
[php_harvesters](#php_harvesters)|392|392|13|3.3%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|1380|1380|8|0.5%|0.0%|
[proxyrss](#proxyrss)|1675|1675|6|0.3%|0.0%|
[tor_exits](#tor_exits)|1128|1128|5|0.4%|0.0%|
[sorbs_smtp](#sorbs_smtp)|4|4|4|100.0%|0.0%|
[et_tor](#et_tor)|6400|6400|4|0.0%|0.0%|
[dm_tor](#dm_tor)|6459|6459|4|0.0%|0.0%|
[bm_tor](#bm_tor)|6473|6473|4|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3531|3531|4|0.1%|0.0%|
[sorbs_socks](#sorbs_socks)|3|3|3|100.0%|0.0%|
[sorbs_misc](#sorbs_misc)|3|3|3|100.0%|0.0%|
[sorbs_http](#sorbs_http)|3|3|3|100.0%|0.0%|
[et_compromised](#et_compromised)|1721|1721|3|0.1%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1706|1706|3|0.1%|0.0%|
[voipbl](#voipbl)|10533|10945|2|0.0%|0.0%|
[shunlist](#shunlist)|1234|1234|2|0.1%|0.0%|
[openbl_60d](#openbl_60d)|7012|7012|2|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|2|0.1%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|183|183|2|1.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|1|0.1%|0.0%|
[malc0de](#malc0de)|313|313|1|0.3%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|1|0.1%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.0%|
[dshield](#dshield)|20|5120|1|0.0%|0.0%|

## sorbs_smtp

[Sorbs.net](https://www.sorbs.net/) SMTP Open Relays, extracted from deltas.

Source is downloaded from [this link]().

The last time downloaded was found to be dated: Wed Jun 10 22:04:32 UTC 2015.

The ipset `sorbs_smtp` has **4** entries, **4** unique IPs.

The following table shows the overlaps of `sorbs_smtp` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `sorbs_smtp`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `sorbs_smtp`.
- ` this % ` is the percentage **of this ipset (`sorbs_smtp`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[sorbs_spam](#sorbs_spam)|60429|61096|4|0.0%|100.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|60429|61096|4|0.0%|100.0%|
[sorbs_new_spam](#sorbs_new_spam)|60429|61096|4|0.0%|100.0%|

## sorbs_socks

[Sorbs.net](https://www.sorbs.net/) SOCKS proxies, extracted from deltas.

Source is downloaded from [this link]().

The last time downloaded was found to be dated: Wed Jun 10 22:04:32 UTC 2015.

The ipset `sorbs_socks` has **3** entries, **3** unique IPs.

The following table shows the overlaps of `sorbs_socks` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `sorbs_socks`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `sorbs_socks`.
- ` this % ` is the percentage **of this ipset (`sorbs_socks`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[sorbs_spam](#sorbs_spam)|60429|61096|3|0.0%|100.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|60429|61096|3|0.0%|100.0%|
[sorbs_new_spam](#sorbs_new_spam)|60429|61096|3|0.0%|100.0%|
[sorbs_misc](#sorbs_misc)|3|3|3|100.0%|100.0%|
[sorbs_http](#sorbs_http)|3|3|3|100.0%|100.0%|
[nixspam](#nixspam)|28015|28015|2|0.0%|66.6%|
[snort_ipfilter](#snort_ipfilter)|10158|10158|1|0.0%|33.3%|
[firehol_level3](#firehol_level3)|110224|9627969|1|0.0%|33.3%|

## sorbs_spam

[Sorbs.net](https://www.sorbs.net/) Spam senders, extracted from deltas.

Source is downloaded from [this link]().

The last time downloaded was found to be dated: Wed Jun 10 23:04:30 UTC 2015.

The ipset `sorbs_spam` has **60429** entries, **61096** unique IPs.

The following table shows the overlaps of `sorbs_spam` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `sorbs_spam`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `sorbs_spam`.
- ` this % ` is the percentage **of this ipset (`sorbs_spam`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[sorbs_recent_spam](#sorbs_recent_spam)|60429|61096|61096|100.0%|100.0%|
[sorbs_new_spam](#sorbs_new_spam)|60429|61096|61096|100.0%|100.0%|
[nixspam](#nixspam)|28015|28015|5390|19.2%|8.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|2514|0.0%|4.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|1636|0.0%|2.6%|
[firehol_level3](#firehol_level3)|110224|9627969|1398|0.0%|2.2%|
[firehol_level2](#firehol_level2)|23356|34994|1318|3.7%|2.1%|
[blocklist_de](#blocklist_de)|29619|29619|1307|4.4%|2.1%|
[blocklist_de_mail](#blocklist_de_mail)|17317|17317|1202|6.9%|1.9%|
[iw_spamlist](#iw_spamlist)|3703|3703|1157|31.2%|1.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|1148|0.0%|1.8%|
[snort_ipfilter](#snort_ipfilter)|10158|10158|1038|10.2%|1.6%|
[stopforumspam_30d](#stopforumspam_30d)|94424|94424|286|0.3%|0.4%|
[sorbs_web](#sorbs_web)|432|433|240|55.4%|0.3%|
[php_dictionary](#php_dictionary)|702|702|186|26.4%|0.3%|
[firehol_anonymous](#firehol_anonymous)|19001|83032|186|0.2%|0.3%|
[firehol_proxies](#firehol_proxies)|12463|12723|181|1.4%|0.2%|
[php_spammers](#php_spammers)|700|700|159|22.7%|0.2%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|153|0.5%|0.2%|
[ri_web_proxies](#ri_web_proxies)|7624|7624|131|1.7%|0.2%|
[alienvault_reputation](#alienvault_reputation)|182721|182721|86|0.0%|0.1%|
[xroxy](#xroxy)|2159|2159|73|3.3%|0.1%|
[dragon_http](#dragon_http)|1044|273664|61|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4090|4090|59|1.4%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|15454|15454|59|0.3%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6755|6755|42|0.6%|0.0%|
[proxz](#proxz)|1244|1244|42|3.3%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|34|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|2949|2949|34|1.1%|0.0%|
[firehol_level1](#firehol_level1)|5135|688894845|26|0.0%|0.0%|
[et_block](#et_block)|1000|18344011|22|0.0%|0.0%|
[php_commenters](#php_commenters)|430|430|21|4.8%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|20|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|20|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2412|2412|19|0.7%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|15|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2751|2751|13|0.4%|0.0%|
[php_harvesters](#php_harvesters)|392|392|13|3.3%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|1380|1380|8|0.5%|0.0%|
[proxyrss](#proxyrss)|1675|1675|6|0.3%|0.0%|
[tor_exits](#tor_exits)|1128|1128|5|0.4%|0.0%|
[sorbs_smtp](#sorbs_smtp)|4|4|4|100.0%|0.0%|
[et_tor](#et_tor)|6400|6400|4|0.0%|0.0%|
[dm_tor](#dm_tor)|6459|6459|4|0.0%|0.0%|
[bm_tor](#bm_tor)|6473|6473|4|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3531|3531|4|0.1%|0.0%|
[sorbs_socks](#sorbs_socks)|3|3|3|100.0%|0.0%|
[sorbs_misc](#sorbs_misc)|3|3|3|100.0%|0.0%|
[sorbs_http](#sorbs_http)|3|3|3|100.0%|0.0%|
[et_compromised](#et_compromised)|1721|1721|3|0.1%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1706|1706|3|0.1%|0.0%|
[voipbl](#voipbl)|10533|10945|2|0.0%|0.0%|
[shunlist](#shunlist)|1234|1234|2|0.1%|0.0%|
[openbl_60d](#openbl_60d)|7012|7012|2|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|2|0.1%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|183|183|2|1.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|1|0.1%|0.0%|
[malc0de](#malc0de)|313|313|1|0.3%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|1|0.1%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.0%|
[dshield](#dshield)|20|5120|1|0.0%|0.0%|

## sorbs_web

[Sorbs.net](https://www.sorbs.net/) WEB exploits, extracted from deltas.

Source is downloaded from [this link]().

The last time downloaded was found to be dated: Wed Jun 10 23:04:30 UTC 2015.

The ipset `sorbs_web` has **432** entries, **433** unique IPs.

The following table shows the overlaps of `sorbs_web` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `sorbs_web`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `sorbs_web`.
- ` this % ` is the percentage **of this ipset (`sorbs_web`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[sorbs_spam](#sorbs_spam)|60429|61096|240|0.3%|55.4%|
[sorbs_recent_spam](#sorbs_recent_spam)|60429|61096|240|0.3%|55.4%|
[sorbs_new_spam](#sorbs_new_spam)|60429|61096|240|0.3%|55.4%|
[nixspam](#nixspam)|28015|28015|112|0.3%|25.8%|
[firehol_level3](#firehol_level3)|110224|9627969|59|0.0%|13.6%|
[firehol_level2](#firehol_level2)|23356|34994|58|0.1%|13.3%|
[blocklist_de](#blocklist_de)|29619|29619|58|0.1%|13.3%|
[blocklist_de_mail](#blocklist_de_mail)|17317|17317|52|0.3%|12.0%|
[snort_ipfilter](#snort_ipfilter)|10158|10158|48|0.4%|11.0%|
[stopforumspam_30d](#stopforumspam_30d)|94424|94424|33|0.0%|7.6%|
[iw_spamlist](#iw_spamlist)|3703|3703|30|0.8%|6.9%|
[php_dictionary](#php_dictionary)|702|702|27|3.8%|6.2%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|24|0.0%|5.5%|
[php_spammers](#php_spammers)|700|700|22|3.1%|5.0%|
[firehol_proxies](#firehol_proxies)|12463|12723|22|0.1%|5.0%|
[firehol_anonymous](#firehol_anonymous)|19001|83032|22|0.0%|5.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|18|0.0%|4.1%|
[ri_web_proxies](#ri_web_proxies)|7624|7624|17|0.2%|3.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|13|0.0%|3.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|12|0.0%|2.7%|
[xroxy](#xroxy)|2159|2159|11|0.5%|2.5%|
[proxz](#proxz)|1244|1244|7|0.5%|1.6%|
[stopforumspam_1d](#stopforumspam_1d)|6755|6755|6|0.0%|1.3%|
[blocklist_de_bots](#blocklist_de_bots)|2949|2949|5|0.1%|1.1%|
[php_commenters](#php_commenters)|430|430|2|0.4%|0.4%|
[proxyrss](#proxyrss)|1675|1675|1|0.0%|0.2%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|1|0.0%|0.2%|
[blocklist_de_strongips](#blocklist_de_strongips)|183|183|1|0.5%|0.2%|
[blocklist_de_ftp](#blocklist_de_ftp)|1380|1380|1|0.0%|0.2%|

## spamhaus_drop

[Spamhaus.org](http://www.spamhaus.org) DROP list (according to their site this list should be dropped at tier-1 ISPs globaly) - **excellent list**

Source is downloaded from [this link](http://www.spamhaus.org/drop/drop.txt).

The last time downloaded was found to be dated: Tue Jun  9 12:41:05 UTC 2015.

The ipset `spamhaus_drop` has **653** entries, **18340608** unique IPs.

The following table shows the overlaps of `spamhaus_drop` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `spamhaus_drop`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `spamhaus_drop`.
- ` this % ` is the percentage **of this ipset (`spamhaus_drop`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level1](#firehol_level1)|5135|688894845|18340608|2.6%|100.0%|
[et_block](#et_block)|1000|18344011|18338560|99.9%|99.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|8532506|2.4%|46.5%|
[firehol_level3](#firehol_level3)|110224|9627969|6933037|72.0%|37.8%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|6932480|75.5%|37.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|2272265|0.2%|12.3%|
[fullbogons](#fullbogons)|3770|670213096|151552|0.0%|0.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|130368|0.0%|0.7%|
[alienvault_reputation](#alienvault_reputation)|182721|182721|1372|0.7%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1037|0.3%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|94424|94424|1021|1.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|512|0.1%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|294|1.0%|0.0%|
[firehol_level2](#firehol_level2)|23356|34994|279|0.7%|0.0%|
[dragon_http](#dragon_http)|1044|273664|256|0.0%|0.0%|
[openbl_60d](#openbl_60d)|7012|7012|235|3.3%|0.0%|
[blocklist_de](#blocklist_de)|29619|29619|218|0.7%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3531|3531|134|3.7%|0.0%|
[openbl_30d](#openbl_30d)|2835|2835|119|4.1%|0.0%|
[nixspam](#nixspam)|28015|28015|108|0.3%|0.0%|
[et_compromised](#et_compromised)|1721|1721|101|5.8%|0.0%|
[shunlist](#shunlist)|1234|1234|92|7.4%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6755|6755|77|1.1%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1706|1706|70|4.1%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|2949|2949|57|1.9%|0.0%|
[openbl_7d](#openbl_7d)|679|679|50|7.3%|0.0%|
[php_commenters](#php_commenters)|430|430|29|6.7%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|29|2.2%|0.0%|
[sorbs_spam](#sorbs_spam)|60429|61096|20|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|60429|61096|20|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|60429|61096|20|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|17317|17317|20|0.1%|0.0%|
[snort_ipfilter](#snort_ipfilter)|10158|10158|19|0.1%|0.0%|
[zeus_badips](#zeus_badips)|202|202|15|7.4%|0.0%|
[zeus](#zeus)|230|230|15|6.5%|0.0%|
[voipbl](#voipbl)|10533|10945|14|0.1%|0.0%|
[openbl_1d](#openbl_1d)|152|152|14|9.2%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2412|2412|10|0.4%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|183|183|8|4.3%|0.0%|
[php_dictionary](#php_dictionary)|702|702|6|0.8%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|6|0.4%|0.0%|
[firehol_anonymous](#firehol_anonymous)|19001|83032|6|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|5|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4090|4090|5|0.1%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|15454|15454|5|0.0%|0.0%|
[php_spammers](#php_spammers)|700|700|4|0.5%|0.0%|
[nt_malware_http](#nt_malware_http)|69|69|4|5.7%|0.0%|
[malc0de](#malc0de)|313|313|4|1.2%|0.0%|
[nt_malware_irc](#nt_malware_irc)|43|43|3|6.9%|0.0%|
[firehol_proxies](#firehol_proxies)|12463|12723|3|0.0%|0.0%|
[et_tor](#et_tor)|6400|6400|3|0.0%|0.0%|
[dm_tor](#dm_tor)|6459|6459|3|0.0%|0.0%|
[bm_tor](#bm_tor)|6473|6473|3|0.0%|0.0%|
[tor_exits](#tor_exits)|1128|1128|2|0.1%|0.0%|
[iw_spamlist](#iw_spamlist)|3703|3703|2|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|2|0.3%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|79|79|2|2.5%|0.0%|
[sslbl](#sslbl)|372|372|1|0.2%|0.0%|
[php_harvesters](#php_harvesters)|392|392|1|0.2%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|1|0.1%|0.0%|
[et_botcc](#et_botcc)|506|506|1|0.1%|0.0%|

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
[firehol_level1](#firehol_level1)|5135|688894845|487424|0.0%|100.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|270785|0.1%|55.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|98904|0.0%|20.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|33155|0.0%|6.8%|
[et_block](#et_block)|1000|18344011|517|0.0%|0.1%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|512|0.0%|0.1%|
[firehol_level3](#firehol_level3)|110224|9627969|88|0.0%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|94424|94424|78|0.0%|0.0%|
[sorbs_spam](#sorbs_spam)|60429|61096|20|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|60429|61096|20|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|60429|61096|20|0.0%|0.0%|
[alienvault_reputation](#alienvault_reputation)|182721|182721|14|0.0%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|9|0.0%|0.0%|
[php_commenters](#php_commenters)|430|430|8|1.8%|0.0%|
[snort_ipfilter](#snort_ipfilter)|10158|10158|6|0.0%|0.0%|
[firehol_level2](#firehol_level2)|23356|34994|6|0.0%|0.0%|
[zeus_badips](#zeus_badips)|202|202|5|2.4%|0.0%|
[zeus](#zeus)|230|230|5|2.1%|0.0%|
[blocklist_de](#blocklist_de)|29619|29619|5|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|183|183|4|2.1%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|2949|2949|4|0.1%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6755|6755|2|0.0%|0.0%|
[php_harvesters](#php_harvesters)|392|392|1|0.2%|0.0%|
[openbl_60d](#openbl_60d)|7012|7012|1|0.0%|0.0%|
[openbl_30d](#openbl_30d)|2835|2835|1|0.0%|0.0%|
[nixspam](#nixspam)|28015|28015|1|0.0%|0.0%|
[malc0de](#malc0de)|313|313|1|0.3%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.0%|
[firehol_anonymous](#firehol_anonymous)|19001|83032|1|0.0%|0.0%|
[dm_tor](#dm_tor)|6459|6459|1|0.0%|0.0%|

## sslbl

[Abuse.ch SSL Blacklist](https://sslbl.abuse.ch/) bad SSL traffic related to malware or botnet activities - **excellent list**

Source is downloaded from [this link](https://sslbl.abuse.ch/blacklist/sslipblacklist.csv).

The last time downloaded was found to be dated: Wed Jun 10 23:45:06 UTC 2015.

The ipset `sslbl` has **372** entries, **372** unique IPs.

The following table shows the overlaps of `sslbl` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `sslbl`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `sslbl`.
- ` this % ` is the percentage **of this ipset (`sslbl`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level1](#firehol_level1)|5135|688894845|372|0.0%|100.0%|
[firehol_level3](#firehol_level3)|110224|9627969|93|0.0%|25.0%|
[alienvault_reputation](#alienvault_reputation)|182721|182721|65|0.0%|17.4%|
[shunlist](#shunlist)|1234|1234|61|4.9%|16.3%|
[feodo](#feodo)|105|105|38|36.1%|10.2%|
[et_block](#et_block)|1000|18344011|38|0.0%|10.2%|
[snort_ipfilter](#snort_ipfilter)|10158|10158|32|0.3%|8.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|28|0.0%|7.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|6|0.0%|1.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|3|0.0%|0.8%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|1|0.0%|0.2%|
[ri_web_proxies](#ri_web_proxies)|7624|7624|1|0.0%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.2%|
[firehol_proxies](#firehol_proxies)|12463|12723|1|0.0%|0.2%|
[firehol_anonymous](#firehol_anonymous)|19001|83032|1|0.0%|0.2%|
[dragon_http](#dragon_http)|1044|273664|1|0.0%|0.2%|

## stopforumspam_1d

[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers in the last 24 hours - **excellent list**

Source is downloaded from [this link](http://www.stopforumspam.com/downloads/listed_ip_1.zip).

The last time downloaded was found to be dated: Wed Jun 10 23:00:01 UTC 2015.

The ipset `stopforumspam_1d` has **6755** entries, **6755** unique IPs.

The following table shows the overlaps of `stopforumspam_1d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `stopforumspam_1d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `stopforumspam_1d`.
- ` this % ` is the percentage **of this ipset (`stopforumspam_1d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|23356|34994|6755|19.3%|100.0%|
[firehol_level3](#firehol_level3)|110224|9627969|5630|0.0%|83.3%|
[stopforumspam_30d](#stopforumspam_30d)|94424|94424|5607|5.9%|83.0%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|3750|12.7%|55.5%|
[blocklist_de](#blocklist_de)|29619|29619|1408|4.7%|20.8%|
[blocklist_de_bots](#blocklist_de_bots)|2949|2949|1331|45.1%|19.7%|
[firehol_anonymous](#firehol_anonymous)|19001|83032|1081|1.3%|16.0%|
[firehol_proxies](#firehol_proxies)|12463|12723|883|6.9%|13.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|494|0.0%|7.3%|
[ri_web_proxies](#ri_web_proxies)|7624|7624|455|5.9%|6.7%|
[snort_ipfilter](#snort_ipfilter)|10158|10158|426|4.1%|6.3%|
[tor_exits](#tor_exits)|1128|1128|398|35.2%|5.8%|
[et_tor](#et_tor)|6400|6400|384|6.0%|5.6%|
[dm_tor](#dm_tor)|6459|6459|383|5.9%|5.6%|
[bm_tor](#bm_tor)|6473|6473|383|5.9%|5.6%|
[proxyrss](#proxyrss)|1675|1675|366|21.8%|5.4%|
[xroxy](#xroxy)|2159|2159|234|10.8%|3.4%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|225|42.9%|3.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|192|0.0%|2.8%|
[proxz](#proxz)|1244|1244|178|14.3%|2.6%|
[php_commenters](#php_commenters)|430|430|172|40.0%|2.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|146|0.0%|2.1%|
[blocklist_de_strongips](#blocklist_de_strongips)|183|183|113|61.7%|1.6%|
[ri_connect_proxies](#ri_connect_proxies)|2751|2751|103|3.7%|1.5%|
[firehol_level1](#firehol_level1)|5135|688894845|80|0.0%|1.1%|
[blocklist_de_apache](#blocklist_de_apache)|15454|15454|78|0.5%|1.1%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|77|0.0%|1.1%|
[et_block](#et_block)|1000|18344011|77|0.0%|1.1%|
[php_harvesters](#php_harvesters)|392|392|49|12.5%|0.7%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4090|4090|47|1.1%|0.6%|
[alienvault_reputation](#alienvault_reputation)|182721|182721|47|0.0%|0.6%|
[blocklist_de_mail](#blocklist_de_mail)|17317|17317|45|0.2%|0.6%|
[nixspam](#nixspam)|28015|28015|44|0.1%|0.6%|
[sorbs_spam](#sorbs_spam)|60429|61096|42|0.0%|0.6%|
[sorbs_recent_spam](#sorbs_recent_spam)|60429|61096|42|0.0%|0.6%|
[sorbs_new_spam](#sorbs_new_spam)|60429|61096|42|0.0%|0.6%|
[php_spammers](#php_spammers)|700|700|36|5.1%|0.5%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|29|0.0%|0.4%|
[php_dictionary](#php_dictionary)|702|702|28|3.9%|0.4%|
[openbl_60d](#openbl_60d)|7012|7012|20|0.2%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|12|0.0%|0.1%|
[dragon_http](#dragon_http)|1044|273664|7|0.0%|0.1%|
[sorbs_web](#sorbs_web)|432|433|6|1.3%|0.0%|
[iw_spamlist](#iw_spamlist)|3703|3703|6|0.1%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|5|0.0%|0.0%|
[voipbl](#voipbl)|10533|10945|4|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|4|0.6%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|2|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|2|0.1%|0.0%|
[zeus_badips](#zeus_badips)|202|202|1|0.4%|0.0%|
[zeus](#zeus)|230|230|1|0.4%|0.0%|
[shunlist](#shunlist)|1234|1234|1|0.0%|0.0%|
[openbl_30d](#openbl_30d)|2835|2835|1|0.0%|0.0%|
[fullbogons](#fullbogons)|3770|670213096|1|0.0%|0.0%|
[et_compromised](#et_compromised)|1721|1721|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1706|1706|1|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2412|2412|1|0.0%|0.0%|

## stopforumspam_30d

[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 30 days)

Source is downloaded from [this link](http://www.stopforumspam.com/downloads/listed_ip_30.zip).

The last time downloaded was found to be dated: Wed Jun 10 12:00:33 UTC 2015.

The ipset `stopforumspam_30d` has **94424** entries, **94424** unique IPs.

The following table shows the overlaps of `stopforumspam_30d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `stopforumspam_30d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `stopforumspam_30d`.
- ` this % ` is the percentage **of this ipset (`stopforumspam_30d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level3](#firehol_level3)|110224|9627969|94424|0.9%|100.0%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|29338|100.0%|31.0%|
[firehol_level2](#firehol_level2)|23356|34994|7037|20.1%|7.4%|
[firehol_anonymous](#firehol_anonymous)|19001|83032|6120|7.3%|6.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|5840|0.0%|6.1%|
[stopforumspam_1d](#stopforumspam_1d)|6755|6755|5607|83.0%|5.9%|
[firehol_proxies](#firehol_proxies)|12463|12723|5509|43.2%|5.8%|
[ri_web_proxies](#ri_web_proxies)|7624|7624|3611|47.3%|3.8%|
[blocklist_de](#blocklist_de)|29619|29619|2716|9.1%|2.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|2508|0.0%|2.6%|
[blocklist_de_bots](#blocklist_de_bots)|2949|2949|2327|78.9%|2.4%|
[ri_connect_proxies](#ri_connect_proxies)|2751|2751|1546|56.1%|1.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|1516|0.0%|1.6%|
[xroxy](#xroxy)|2159|2159|1276|59.1%|1.3%|
[firehol_level1](#firehol_level1)|5135|688894845|1103|0.0%|1.1%|
[et_block](#et_block)|1000|18344011|1025|0.0%|1.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|1021|0.0%|1.0%|
[snort_ipfilter](#snort_ipfilter)|10158|10158|816|8.0%|0.8%|
[proxz](#proxz)|1244|1244|731|58.7%|0.7%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|731|0.0%|0.7%|
[proxyrss](#proxyrss)|1675|1675|707|42.2%|0.7%|
[et_tor](#et_tor)|6400|6400|649|10.1%|0.6%|
[dm_tor](#dm_tor)|6459|6459|645|9.9%|0.6%|
[bm_tor](#bm_tor)|6473|6473|642|9.9%|0.6%|
[tor_exits](#tor_exits)|1128|1128|633|56.1%|0.6%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|342|65.2%|0.3%|
[php_commenters](#php_commenters)|430|430|318|73.9%|0.3%|
[sorbs_spam](#sorbs_spam)|60429|61096|286|0.4%|0.3%|
[sorbs_recent_spam](#sorbs_recent_spam)|60429|61096|286|0.4%|0.3%|
[sorbs_new_spam](#sorbs_new_spam)|60429|61096|286|0.4%|0.3%|
[blocklist_de_mail](#blocklist_de_mail)|17317|17317|257|1.4%|0.2%|
[blocklist_de_apache](#blocklist_de_apache)|15454|15454|233|1.5%|0.2%|
[nixspam](#nixspam)|28015|28015|217|0.7%|0.2%|
[alienvault_reputation](#alienvault_reputation)|182721|182721|170|0.0%|0.1%|
[php_spammers](#php_spammers)|700|700|144|20.5%|0.1%|
[blocklist_de_strongips](#blocklist_de_strongips)|183|183|139|75.9%|0.1%|
[php_dictionary](#php_dictionary)|702|702|133|18.9%|0.1%|
[dragon_http](#dragon_http)|1044|273664|115|0.0%|0.1%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4090|4090|93|2.2%|0.0%|
[php_harvesters](#php_harvesters)|392|392|84|21.4%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|78|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|49|0.0%|0.0%|
[openbl_60d](#openbl_60d)|7012|7012|48|0.6%|0.0%|
[voipbl](#voipbl)|10533|10945|35|0.3%|0.0%|
[sorbs_web](#sorbs_web)|432|433|33|7.6%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3531|3531|24|0.6%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|19|2.8%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|1380|1380|19|1.3%|0.0%|
[iw_spamlist](#iw_spamlist)|3703|3703|18|0.4%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|16|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2412|2412|13|0.5%|0.0%|
[et_compromised](#et_compromised)|1721|1721|12|0.6%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1706|1706|12|0.7%|0.0%|
[openbl_30d](#openbl_30d)|2835|2835|5|0.1%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|4|0.3%|0.0%|
[dshield](#dshield)|20|5120|4|0.0%|0.0%|
[shunlist](#shunlist)|1234|1234|3|0.2%|0.0%|
[zeus_badips](#zeus_badips)|202|202|2|0.9%|0.0%|
[zeus](#zeus)|230|230|2|0.8%|0.0%|
[openbl_7d](#openbl_7d)|679|679|2|0.2%|0.0%|
[openbl_1d](#openbl_1d)|152|152|2|1.3%|0.0%|
[nt_malware_http](#nt_malware_http)|69|69|2|2.8%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|2|0.1%|0.0%|
[ciarmy](#ciarmy)|469|469|2|0.4%|0.0%|
[virbl](#virbl)|31|31|1|3.2%|0.0%|
[iw_wormlist](#iw_wormlist)|33|33|1|3.0%|0.0%|
[fullbogons](#fullbogons)|3770|670213096|1|0.0%|0.0%|

## stopforumspam_7d

[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 7 days)

Source is downloaded from [this link](http://www.stopforumspam.com/downloads/listed_ip_7.zip).

The last time downloaded was found to be dated: Wed Jun 10 01:03:21 UTC 2015.

The ipset `stopforumspam_7d` has **29338** entries, **29338** unique IPs.

The following table shows the overlaps of `stopforumspam_7d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `stopforumspam_7d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `stopforumspam_7d`.
- ` this % ` is the percentage **of this ipset (`stopforumspam_7d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_30d](#stopforumspam_30d)|94424|94424|29338|31.0%|100.0%|
[firehol_level3](#firehol_level3)|110224|9627969|29338|0.3%|100.0%|
[firehol_level2](#firehol_level2)|23356|34994|4819|13.7%|16.4%|
[stopforumspam_1d](#stopforumspam_1d)|6755|6755|3750|55.5%|12.7%|
[firehol_anonymous](#firehol_anonymous)|19001|83032|2786|3.3%|9.4%|
[firehol_proxies](#firehol_proxies)|12463|12723|2433|19.1%|8.2%|
[blocklist_de](#blocklist_de)|29619|29619|2163|7.3%|7.3%|
[blocklist_de_bots](#blocklist_de_bots)|2949|2949|1949|66.0%|6.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|1913|0.0%|6.5%|
[ri_web_proxies](#ri_web_proxies)|7624|7624|1549|20.3%|5.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|790|0.0%|2.6%|
[snort_ipfilter](#snort_ipfilter)|10158|10158|658|6.4%|2.2%|
[xroxy](#xroxy)|2159|2159|626|28.9%|2.1%|
[ri_connect_proxies](#ri_connect_proxies)|2751|2751|592|21.5%|2.0%|
[et_tor](#et_tor)|6400|6400|530|8.2%|1.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|529|0.0%|1.8%|
[tor_exits](#tor_exits)|1128|1128|528|46.8%|1.7%|
[dm_tor](#dm_tor)|6459|6459|523|8.0%|1.7%|
[bm_tor](#bm_tor)|6473|6473|521|8.0%|1.7%|
[proxyrss](#proxyrss)|1675|1675|500|29.8%|1.7%|
[proxz](#proxz)|1244|1244|494|39.7%|1.6%|
[firehol_level1](#firehol_level1)|5135|688894845|304|0.0%|1.0%|
[et_block](#et_block)|1000|18344011|295|0.0%|1.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|294|0.0%|1.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|285|54.3%|0.9%|
[php_commenters](#php_commenters)|430|430|237|55.1%|0.8%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|167|0.0%|0.5%|
[sorbs_spam](#sorbs_spam)|60429|61096|153|0.2%|0.5%|
[sorbs_recent_spam](#sorbs_recent_spam)|60429|61096|153|0.2%|0.5%|
[sorbs_new_spam](#sorbs_new_spam)|60429|61096|153|0.2%|0.5%|
[blocklist_de_mail](#blocklist_de_mail)|17317|17317|147|0.8%|0.5%|
[blocklist_de_apache](#blocklist_de_apache)|15454|15454|139|0.8%|0.4%|
[nixspam](#nixspam)|28015|28015|133|0.4%|0.4%|
[blocklist_de_strongips](#blocklist_de_strongips)|183|183|118|64.4%|0.4%|
[alienvault_reputation](#alienvault_reputation)|182721|182721|93|0.0%|0.3%|
[php_dictionary](#php_dictionary)|702|702|88|12.5%|0.2%|
[php_spammers](#php_spammers)|700|700|87|12.4%|0.2%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4090|4090|66|1.6%|0.2%|
[php_harvesters](#php_harvesters)|392|392|61|15.5%|0.2%|
[dragon_http](#dragon_http)|1044|273664|37|0.0%|0.1%|
[openbl_60d](#openbl_60d)|7012|7012|27|0.3%|0.0%|
[sorbs_web](#sorbs_web)|432|433|24|5.5%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|18|0.0%|0.0%|
[voipbl](#voipbl)|10533|10945|14|0.1%|0.0%|
[iw_spamlist](#iw_spamlist)|3703|3703|12|0.3%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|11|1.6%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|9|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|1380|1380|7|0.5%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3531|3531|6|0.1%|0.0%|
[et_compromised](#et_compromised)|1721|1721|5|0.2%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|4|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1706|1706|4|0.2%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2412|2412|3|0.1%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|2|0.1%|0.0%|
[dshield](#dshield)|20|5120|2|0.0%|0.0%|
[zeus_badips](#zeus_badips)|202|202|1|0.4%|0.0%|
[zeus](#zeus)|230|230|1|0.4%|0.0%|
[shunlist](#shunlist)|1234|1234|1|0.0%|0.0%|
[openbl_30d](#openbl_30d)|2835|2835|1|0.0%|0.0%|
[iw_wormlist](#iw_wormlist)|33|33|1|3.0%|0.0%|
[ciarmy](#ciarmy)|469|469|1|0.2%|0.0%|

## tor_exits

[TorProject.org](https://www.torproject.org) list of all current TOR exit points (TorDNSEL)

Source is downloaded from [this link](https://check.torproject.org/exit-addresses).

The last time downloaded was found to be dated: Wed Jun 10 23:02:51 UTC 2015.

The ipset `tor_exits` has **1128** entries, **1128** unique IPs.

The following table shows the overlaps of `tor_exits` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `tor_exits`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `tor_exits`.
- ` this % ` is the percentage **of this ipset (`tor_exits`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_anonymous](#firehol_anonymous)|19001|83032|1128|1.3%|100.0%|
[firehol_level3](#firehol_level3)|110224|9627969|1097|0.0%|97.2%|
[snort_ipfilter](#snort_ipfilter)|10158|10158|1094|10.7%|96.9%|
[bm_tor](#bm_tor)|6473|6473|1021|15.7%|90.5%|
[dm_tor](#dm_tor)|6459|6459|1017|15.7%|90.1%|
[et_tor](#et_tor)|6400|6400|999|15.6%|88.5%|
[stopforumspam_30d](#stopforumspam_30d)|94424|94424|633|0.6%|56.1%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|528|1.7%|46.8%|
[firehol_level2](#firehol_level2)|23356|34994|408|1.1%|36.1%|
[stopforumspam_1d](#stopforumspam_1d)|6755|6755|398|5.8%|35.2%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|231|44.0%|20.4%|
[firehol_proxies](#firehol_proxies)|12463|12723|231|1.8%|20.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|128|0.0%|11.3%|
[php_commenters](#php_commenters)|430|430|51|11.8%|4.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|39|0.0%|3.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|38|0.0%|3.3%|
[alienvault_reputation](#alienvault_reputation)|182721|182721|30|0.0%|2.6%|
[blocklist_de](#blocklist_de)|29619|29619|29|0.0%|2.5%|
[blocklist_de_apache](#blocklist_de_apache)|15454|15454|28|0.1%|2.4%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4090|4090|26|0.6%|2.3%|
[openbl_60d](#openbl_60d)|7012|7012|20|0.2%|1.7%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|8|0.0%|0.7%|
[php_harvesters](#php_harvesters)|392|392|6|1.5%|0.5%|
[nixspam](#nixspam)|28015|28015|6|0.0%|0.5%|
[sorbs_spam](#sorbs_spam)|60429|61096|5|0.0%|0.4%|
[sorbs_recent_spam](#sorbs_recent_spam)|60429|61096|5|0.0%|0.4%|
[sorbs_new_spam](#sorbs_new_spam)|60429|61096|5|0.0%|0.4%|
[php_spammers](#php_spammers)|700|700|5|0.7%|0.4%|
[php_dictionary](#php_dictionary)|702|702|4|0.5%|0.3%|
[dragon_http](#dragon_http)|1044|273664|3|0.0%|0.2%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|2|0.0%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2|0.0%|0.1%|
[firehol_level1](#firehol_level1)|5135|688894845|2|0.0%|0.1%|
[et_block](#et_block)|1000|18344011|2|0.0%|0.1%|
[blocklist_de_mail](#blocklist_de_mail)|17317|17317|2|0.0%|0.1%|
[shunlist](#shunlist)|1234|1234|1|0.0%|0.0%|
[iw_spamlist](#iw_spamlist)|3703|3703|1|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|2949|2949|1|0.0%|0.0%|

## virbl

[VirBL](http://virbl.bit.nl/) is a project of which the idea was born during the RIPE-48 meeting. The plan was to get reports of virusscanning mailservers, and put the IP-addresses that were reported to send viruses on a blacklist.

Source is downloaded from [this link](http://virbl.bit.nl/download/virbl.dnsbl.bit.nl.txt).

The last time downloaded was found to be dated: Wed Jun 10 23:42:03 UTC 2015.

The ipset `virbl` has **31** entries, **31** unique IPs.

The following table shows the overlaps of `virbl` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `virbl`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `virbl`.
- ` this % ` is the percentage **of this ipset (`virbl`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level3](#firehol_level3)|110224|9627969|31|0.0%|100.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|4|0.0%|12.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|2|0.0%|6.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|2|0.0%|6.4%|
[stopforumspam_30d](#stopforumspam_30d)|94424|94424|1|0.0%|3.2%|
[snort_ipfilter](#snort_ipfilter)|10158|10158|1|0.0%|3.2%|
[nixspam](#nixspam)|28015|28015|1|0.0%|3.2%|
[fullbogons](#fullbogons)|3770|670213096|1|0.0%|3.2%|
[firehol_level1](#firehol_level1)|5135|688894845|1|0.0%|3.2%|

## voipbl

[VoIPBL.org](http://www.voipbl.org/) a distributed VoIP blacklist that is aimed to protects against VoIP Fraud and minimizing abuse for network that have publicly accessible PBX's. Several algorithms, external sources and manual confirmation are used before they categorize something as an attack and determine the threat level.

Source is downloaded from [this link](http://www.voipbl.org/update/).

The last time downloaded was found to be dated: Wed Jun 10 22:50:03 UTC 2015.

The ipset `voipbl` has **10533** entries, **10945** unique IPs.

The following table shows the overlaps of `voipbl` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `voipbl`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `voipbl`.
- ` this % ` is the percentage **of this ipset (`voipbl`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|1605|0.0%|14.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|434|0.0%|3.9%|
[firehol_level1](#firehol_level1)|5135|688894845|333|0.0%|3.0%|
[fullbogons](#fullbogons)|3770|670213096|319|0.0%|2.9%|
[bogons](#bogons)|13|592708608|319|0.0%|2.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|299|0.0%|2.7%|
[alienvault_reputation](#alienvault_reputation)|182721|182721|183|0.1%|1.6%|
[firehol_anonymous](#firehol_anonymous)|19001|83032|79|0.0%|0.7%|
[firehol_level3](#firehol_level3)|110224|9627969|57|0.0%|0.5%|
[firehol_level2](#firehol_level2)|23356|34994|36|0.1%|0.3%|
[stopforumspam_30d](#stopforumspam_30d)|94424|94424|35|0.0%|0.3%|
[blocklist_de](#blocklist_de)|29619|29619|32|0.1%|0.2%|
[blocklist_de_sip](#blocklist_de_sip)|79|79|26|32.9%|0.2%|
[dragon_http](#dragon_http)|1044|273664|25|0.0%|0.2%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|14|0.0%|0.1%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|14|0.0%|0.1%|
[et_block](#et_block)|1000|18344011|14|0.0%|0.1%|
[shunlist](#shunlist)|1234|1234|12|0.9%|0.1%|
[openbl_60d](#openbl_60d)|7012|7012|8|0.1%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6755|6755|4|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|4|0.0%|0.0%|
[openbl_30d](#openbl_30d)|2835|2835|3|0.1%|0.0%|
[et_tor](#et_tor)|6400|6400|3|0.0%|0.0%|
[et_compromised](#et_compromised)|1721|1721|3|0.1%|0.0%|
[dm_tor](#dm_tor)|6459|6459|3|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1706|1706|3|0.1%|0.0%|
[bm_tor](#bm_tor)|6473|6473|3|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3531|3531|3|0.0%|0.0%|
[sorbs_spam](#sorbs_spam)|60429|61096|2|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|60429|61096|2|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|60429|61096|2|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|2|0.3%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|2|0.0%|0.0%|
[firehol_proxies](#firehol_proxies)|12463|12723|2|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|15454|15454|2|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|10158|10158|1|0.0%|0.0%|
[nixspam](#nixspam)|28015|28015|1|0.0%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.0%|
[ciarmy](#ciarmy)|469|469|1|0.2%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|17317|17317|1|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4090|4090|1|0.0%|0.0%|

## xroxy

[xroxy.com](http://www.xroxy.com) open proxies (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.xroxy.com/proxyrss.xml).

The last time downloaded was found to be dated: Wed Jun 10 23:33:01 UTC 2015.

The ipset `xroxy` has **2159** entries, **2159** unique IPs.

The following table shows the overlaps of `xroxy` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `xroxy`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `xroxy`.
- ` this % ` is the percentage **of this ipset (`xroxy`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_proxies](#firehol_proxies)|12463|12723|2159|16.9%|100.0%|
[firehol_anonymous](#firehol_anonymous)|19001|83032|2159|2.6%|100.0%|
[firehol_level3](#firehol_level3)|110224|9627969|1292|0.0%|59.8%|
[stopforumspam_30d](#stopforumspam_30d)|94424|94424|1276|1.3%|59.1%|
[ri_web_proxies](#ri_web_proxies)|7624|7624|953|12.5%|44.1%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|626|2.1%|28.9%|
[proxz](#proxz)|1244|1244|442|35.5%|20.4%|
[ri_connect_proxies](#ri_connect_proxies)|2751|2751|391|14.2%|18.1%|
[proxyrss](#proxyrss)|1675|1675|337|20.1%|15.6%|
[firehol_level2](#firehol_level2)|23356|34994|333|0.9%|15.4%|
[stopforumspam_1d](#stopforumspam_1d)|6755|6755|234|3.4%|10.8%|
[blocklist_de](#blocklist_de)|29619|29619|206|0.6%|9.5%|
[blocklist_de_bots](#blocklist_de_bots)|2949|2949|153|5.1%|7.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|110|0.0%|5.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|104|0.0%|4.8%|
[sorbs_spam](#sorbs_spam)|60429|61096|73|0.1%|3.3%|
[sorbs_recent_spam](#sorbs_recent_spam)|60429|61096|73|0.1%|3.3%|
[sorbs_new_spam](#sorbs_new_spam)|60429|61096|73|0.1%|3.3%|
[nixspam](#nixspam)|28015|28015|66|0.2%|3.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|58|0.0%|2.6%|
[blocklist_de_mail](#blocklist_de_mail)|17317|17317|53|0.3%|2.4%|
[snort_ipfilter](#snort_ipfilter)|10158|10158|41|0.4%|1.8%|
[php_dictionary](#php_dictionary)|702|702|39|5.5%|1.8%|
[php_spammers](#php_spammers)|700|700|32|4.5%|1.4%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|13|1.9%|0.6%|
[sorbs_web](#sorbs_web)|432|433|11|2.5%|0.5%|
[php_commenters](#php_commenters)|430|430|10|2.3%|0.4%|
[dragon_http](#dragon_http)|1044|273664|8|0.0%|0.3%|
[blocklist_de_strongips](#blocklist_de_strongips)|183|183|5|2.7%|0.2%|
[alienvault_reputation](#alienvault_reputation)|182721|182721|5|0.0%|0.2%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|3|0.5%|0.1%|
[iw_spamlist](#iw_spamlist)|3703|3703|3|0.0%|0.1%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|3|0.0%|0.1%|
[php_harvesters](#php_harvesters)|392|392|2|0.5%|0.0%|
[dm_tor](#dm_tor)|6459|6459|2|0.0%|0.0%|
[bm_tor](#bm_tor)|6473|6473|2|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.0%|
[et_tor](#et_tor)|6400|6400|1|0.0%|0.0%|
[et_compromised](#et_compromised)|1721|1721|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1706|1706|1|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2412|2412|1|0.0%|0.0%|

## zeus

[Abuse.ch Zeus tracker](https://zeustracker.abuse.ch) standard, contains the same data as the ZeuS IP blocklist (zeus_badips) but with the slight difference that it doesn't exclude hijacked websites (level 2) and free web hosting providers (level 3). This means that this blocklist contains all IPv4 addresses associated with ZeuS C&Cs which are currently being tracked by ZeuS Tracker. Hence this blocklist will likely cause some false positives. - **excellent list**

Source is downloaded from [this link](https://zeustracker.abuse.ch/blocklist.php?download=ipblocklist).

The last time downloaded was found to be dated: Wed Jun 10 12:10:34 UTC 2015.

The ipset `zeus` has **230** entries, **230** unique IPs.

The following table shows the overlaps of `zeus` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `zeus`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `zeus`.
- ` this % ` is the percentage **of this ipset (`zeus`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level1](#firehol_level1)|5135|688894845|230|0.0%|100.0%|
[et_block](#et_block)|1000|18344011|228|0.0%|99.1%|
[firehol_level3](#firehol_level3)|110224|9627969|203|0.0%|88.2%|
[zeus_badips](#zeus_badips)|202|202|202|100.0%|87.8%|
[snort_ipfilter](#snort_ipfilter)|10158|10158|200|1.9%|86.9%|
[alienvault_reputation](#alienvault_reputation)|182721|182721|61|0.0%|26.5%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|15|0.0%|6.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|14|0.0%|6.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|10|0.0%|4.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|9|0.0%|3.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|7|0.0%|3.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|5|0.0%|2.1%|
[firehol_level2](#firehol_level2)|23356|34994|3|0.0%|1.3%|
[dragon_http](#dragon_http)|1044|273664|3|0.0%|1.3%|
[stopforumspam_30d](#stopforumspam_30d)|94424|94424|2|0.0%|0.8%|
[openbl_60d](#openbl_60d)|7012|7012|2|0.0%|0.8%|
[openbl_30d](#openbl_30d)|2835|2835|2|0.0%|0.8%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|1|0.0%|0.4%|
[stopforumspam_1d](#stopforumspam_1d)|6755|6755|1|0.0%|0.4%|
[php_commenters](#php_commenters)|430|430|1|0.2%|0.4%|
[openbl_7d](#openbl_7d)|679|679|1|0.1%|0.4%|
[openbl_1d](#openbl_1d)|152|152|1|0.6%|0.4%|
[nixspam](#nixspam)|28015|28015|1|0.0%|0.4%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|1|0.0%|0.4%|
[iw_spamlist](#iw_spamlist)|3703|3703|1|0.0%|0.4%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.4%|
[blocklist_de_mail](#blocklist_de_mail)|17317|17317|1|0.0%|0.4%|
[blocklist_de](#blocklist_de)|29619|29619|1|0.0%|0.4%|

## zeus_badips

[Abuse.ch Zeus tracker](https://zeustracker.abuse.ch) badips includes IPv4 addresses that are used by the ZeuS trojan. It is the recommened blocklist if you want to block only ZeuS IPs. It excludes IP addresses that ZeuS Tracker believes to be hijacked (level 2) or belong to a free web hosting provider (level 3). Hence the false postive rate should be much lower compared to the standard ZeuS IP blocklist. **excellent list**

Source is downloaded from [this link](https://zeustracker.abuse.ch/blocklist.php?download=badips).

The last time downloaded was found to be dated: Wed Jun 10 23:54:17 UTC 2015.

The ipset `zeus_badips` has **202** entries, **202** unique IPs.

The following table shows the overlaps of `zeus_badips` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `zeus_badips`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `zeus_badips`.
- ` this % ` is the percentage **of this ipset (`zeus_badips`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[zeus](#zeus)|230|230|202|87.8%|100.0%|
[firehol_level1](#firehol_level1)|5135|688894845|202|0.0%|100.0%|
[et_block](#et_block)|1000|18344011|202|0.0%|100.0%|
[firehol_level3](#firehol_level3)|110224|9627969|180|0.0%|89.1%|
[snort_ipfilter](#snort_ipfilter)|10158|10158|178|1.7%|88.1%|
[alienvault_reputation](#alienvault_reputation)|182721|182721|37|0.0%|18.3%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|15|0.0%|7.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|10|0.0%|4.9%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|10|0.0%|4.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|8|0.0%|3.9%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|5|0.0%|2.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|4|0.0%|1.9%|
[firehol_level2](#firehol_level2)|23356|34994|3|0.0%|1.4%|
[dragon_http](#dragon_http)|1044|273664|3|0.0%|1.4%|
[stopforumspam_30d](#stopforumspam_30d)|94424|94424|2|0.0%|0.9%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|1|0.0%|0.4%|
[stopforumspam_1d](#stopforumspam_1d)|6755|6755|1|0.0%|0.4%|
[php_commenters](#php_commenters)|430|430|1|0.2%|0.4%|
[openbl_7d](#openbl_7d)|679|679|1|0.1%|0.4%|
[openbl_60d](#openbl_60d)|7012|7012|1|0.0%|0.4%|
[openbl_30d](#openbl_30d)|2835|2835|1|0.0%|0.4%|
[openbl_1d](#openbl_1d)|152|152|1|0.6%|0.4%|
[nixspam](#nixspam)|28015|28015|1|0.0%|0.4%|
[iw_spamlist](#iw_spamlist)|3703|3703|1|0.0%|0.4%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.4%|
[blocklist_de_mail](#blocklist_de_mail)|17317|17317|1|0.0%|0.4%|
[blocklist_de](#blocklist_de)|29619|29619|1|0.0%|0.4%|
