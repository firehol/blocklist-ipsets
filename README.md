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

The following list was automatically generated on Fri Jun 12 12:21:41 UTC 2015.

The update frequency is the maximum allowed by internal configuration. A list will never be downloaded sooner than the update frequency stated. A list may also not be downloaded, after this frequency expired, if it has not been modified on the server (as reported by HTTP `IF_MODIFIED_SINCE` method).

name|info|type|entries|update|
:--:|:--:|:--:|:-----:|:----:|
[alienvault_reputation](#alienvault_reputation)|[AlienVault.com](https://www.alienvault.com/) IP reputation database (this list seems to include port scanning hosts and to be updated regularly, but we found no information about its retention policy)|ipv4 hash:ip|189179 unique IPs|updated every 6 hours  from [this link](https://reputation.alienvault.com/reputation.generic)
[blocklist_de](#blocklist_de)|[Blocklist.de](https://www.blocklist.de/) IPs that have been detected by fail2ban in the last 48 hours - **excellent list**|ipv4 hash:ip|27919 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/all.txt)
[blocklist_de_apache](#blocklist_de_apache)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service Apache, Apache-DDOS, RFI-Attacks.|ipv4 hash:ip|13988 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/apache.txt)
[blocklist_de_bots](#blocklist_de_bots)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the RFI-Attacks, REG-Bots, IRC-Bots or BadBots (BadBots = he has posted a Spam-Comment on a open Forum or Wiki).|ipv4 hash:ip|3014 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/bots.txt)
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|[Blocklist.de](https://www.blocklist.de/) All IPs which attacks Joomlas, Wordpress and other Web-Logins with Brute-Force Logins.|ipv4 hash:ip|2599 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/bruteforcelogin.txt)
[blocklist_de_ftp](#blocklist_de_ftp)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours for attacks on the Service FTP.|ipv4 hash:ip|1500 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/ftp.txt)
[blocklist_de_imap](#blocklist_de_imap)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours for attacks on the Service imap, sasl, pop3, etc.|ipv4 hash:ip|3043 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/imap.txt)
[blocklist_de_mail](#blocklist_de_mail)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service Mail, Postfix.|ipv4 hash:ip|18003 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/mail.txt)
[blocklist_de_sip](#blocklist_de_sip)|[Blocklist.de](https://www.blocklist.de/) All IP addresses that tried to login in a SIP, VOIP or Asterisk Server and are included in the IPs list from [infiltrated.net](www.infiltrated.net)|ipv4 hash:ip|81 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/sip.txt)
[blocklist_de_ssh](#blocklist_de_ssh)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service SSH.|ipv4 hash:ip|2474 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/ssh.txt)
[blocklist_de_strongips](#blocklist_de_strongips)|[Blocklist.de](https://www.blocklist.de/) All IPs which are older then 2 month and have more then 5.000 attacks.|ipv4 hash:ip|169 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/strongips.txt)
[bm_tor](#bm_tor)|[torstatus.blutmagie.de](https://torstatus.blutmagie.de) list of all TOR network servers|ipv4 hash:ip|6496 unique IPs|updated every 30 mins  from [this link](https://torstatus.blutmagie.de/ip_list_all.php/Tor_ip_list_ALL.csv)
[bogons](#bogons)|[Team-Cymru.org](http://www.team-cymru.org) private and reserved addresses defined by RFC 1918, RFC 5735, and RFC 6598 and netblocks that have not been allocated to a regional internet registry - **excellent list - use it only your internet interface**|ipv4 hash:net|13 subnets, 592708608 unique IPs|updated every 1 day  from [this link](http://www.team-cymru.org/Services/Bogons/bogon-bn-agg.txt)
[bruteforceblocker](#bruteforceblocker)|[danger.rulez.sk](http://danger.rulez.sk/) IPs detected by [bruteforceblocker](http://danger.rulez.sk/index.php/bruteforceblocker/) (fail2ban alternative for SSH on OpenBSD). This is an automatically generated list from users reporting failed authentication attempts. An IP seems to be included if 3 or more users report it. Its retention pocily seems 30 days.|ipv4 hash:ip|1696 unique IPs|updated every 3 hours  from [this link](http://danger.rulez.sk/projects/bruteforceblocker/blist.php)
[ciarmy](#ciarmy)|[CIArmy.com](http://ciarmy.com/) IPs with poor Rogue Packet score that have not yet been identified as malicious by the community|ipv4 hash:ip|421 unique IPs|updated every 3 hours  from [this link](http://cinsscore.com/list/ci-badguys.txt)
[cleanmx_viruses](#cleanmx_viruses)|[Clean-MX.de](http://support.clean-mx.de/clean-mx/viruses.php) IPs with viruses|ipv4 hash:ip|511 unique IPs|updated every 12 hours  from [this link](http://support.clean-mx.de/clean-mx/xmlviruses.php?sort=id%20desc&response=alive)
[dm_tor](#dm_tor)|[dan.me.uk](https://www.dan.me.uk) dynamic list of TOR nodes|ipv4 hash:ip|6521 unique IPs|updated every 30 mins  from [this link](https://www.dan.me.uk/torlist/)
[dragon_http](#dragon_http)|[Dragon Search Group](http://www.dragonresearchgroup.org/) IPs that have been seen sending HTTP requests to Dragon Research Pods in the last 7 days. This report lists hosts that are highly suspicious and are likely conducting malicious HTTP attacks. LEGITIMATE SEARCH ENGINE BOTS MAY BE IN THIS LIST. This report is informational.  It is not a blacklist, but some operators may choose to use it to help protect their networks and hosts in the forms of automated reporting and mitigation services.|ipv4 hash:net|1021 subnets, 268288 unique IPs|updated every 1 hour  from [this link](http://www.dragonresearchgroup.org/insight/http-report.txt)
[dragon_sshpauth](#dragon_sshpauth)|[Dragon Search Group](http://www.dragonresearchgroup.org/) IP address that has been seen attempting to remotely login to a host using SSH password authentication, in the last 7 days. This report lists hosts that are highly suspicious and are likely conducting malicious SSH password authentication attacks.|ipv4 hash:net|1589 subnets, 1653 unique IPs|updated every 1 hour  from [this link](https://www.dragonresearchgroup.org/insight/sshpwauth.txt)
[dragon_vncprobe](#dragon_vncprobe)|[Dragon Search Group](http://www.dragonresearchgroup.org/) IP address that has been seen attempting to remotely connect to a host running the VNC application service, in the last 7 days. This report lists hosts that are highly suspicious and are likely conducting malicious VNC probes or VNC brute force attacks.|ipv4 hash:net|89 subnets, 89 unique IPs|updated every 1 hour  from [this link](https://www.dragonresearchgroup.org/insight/vncprobe.txt)
[dshield](#dshield)|[DShield.org](https://dshield.org/) top 20 attacking class C (/24) subnets over the last three days - **excellent list**|ipv4 hash:net|20 subnets, 5120 unique IPs|updated every 4 hours  from [this link](http://feeds.dshield.org/block.txt)
[et_block](#et_block)|[EmergingThreats.net](http://www.emergingthreats.net/) default blacklist (at the time of writing includes spamhaus DROP, dshield and abuse.ch trackers, which are available separately too - prefer to use the direct ipsets instead of this, they seem to lag a bit in updates)|ipv4 hash:net|1000 subnets, 18343756 unique IPs|updated every 12 hours  from [this link](http://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt)
[et_botcc](#et_botcc)|[EmergingThreats.net Command and Control IPs](http://doc.emergingthreats.net/bin/view/Main/BotCC) These IPs are updates every 24 hours and should be considered VERY highly reliable indications that a host is communicating with a known and active Bot or Malware command and control server - (although they say this includes abuse.ch trackers, it does not - most probably it is the shadowserver.org C&C list)|ipv4 hash:ip|505 unique IPs|updated every 12 hours  from [this link](http://rules.emergingthreats.net/fwrules/emerging-PIX-CC.rules)
[et_compromised](#et_compromised)|[EmergingThreats.net compromised hosts](http://doc.emergingthreats.net/bin/view/Main/CompromisedHost) - (this seems to be based on bruteforceblocker)|ipv4 hash:ip|1704 unique IPs|updated every 12 hours  from [this link](http://rules.emergingthreats.net/blockrules/compromised-ips.txt)
et_dshield|[EmergingThreats.net](http://www.emergingthreats.net/) dshield blocklist|ipv4 hash:net|disabled|updated every 12 hours  from [this link](http://rules.emergingthreats.net/fwrules/emerging-PIX-DSHIELD.rules)
et_spamhaus|[EmergingThreats.net](http://www.emergingthreats.net/) spamhaus blocklist|ipv4 hash:net|disabled|updated every 12 hours  from [this link](http://rules.emergingthreats.net/fwrules/emerging-PIX-DROP.rules)
[et_tor](#et_tor)|[EmergingThreats.net](http://www.emergingthreats.net/) [list](http://doc.emergingthreats.net/bin/view/Main/TorRules) of TOR network IPs|ipv4 hash:ip|6500 unique IPs|updated every 12 hours  from [this link](http://rules.emergingthreats.net/blockrules/emerging-tor.rules)
[feodo](#feodo)|[Abuse.ch Feodo tracker](https://feodotracker.abuse.ch) trojan includes IPs which are being used by Feodo (also known as Cridex or Bugat) which commits ebanking fraud - **excellent list**|ipv4 hash:ip|0 unique IPs|updated every 30 mins  from [this link](https://feodotracker.abuse.ch/blocklist/?download=ipblocklist)
[firehol_anonymous](#firehol_anonymous)|**FireHOL Anonymous** - Known anonymizing IPs. (includes: firehol_proxies anonymous bm_tor dm_tor tor_exits)|ipv4 hash:net|19277 subnets, 83325 unique IPs|
[firehol_level1](#firehol_level1)|**FireHOL Level 1** - Maximum protection without false positives. (includes: fullbogons dshield feodo palevo sslbl zeus spamhaus_drop spamhaus_edrop)|ipv4 hash:net|5070 subnets, 688775051 unique IPs|
[firehol_level2](#firehol_level2)|**FireHOL Level 2** - Maximum protection from attacks took place in the last 48 hours. (includes: openbl_1d blocklist_de stopforumspam_1d)|ipv4 hash:net|21534 subnets, 33114 unique IPs|
[firehol_level3](#firehol_level3)|**FireHOL Level 3** - All the bad IPs in last 30 days. (includes: openbl_30d stopforumspam_30d virbl malc0de shunlist malwaredomainlist bruteforceblocker ciarmy cleanmx_viruses snort_ipfilter ib_bluetack_spyware ib_bluetack_hijacked ib_bluetack_webexploit php_commenters php_dictionary php_harvesters php_spammers iw_wormlist)|ipv4 hash:net|109554 subnets, 9627189 unique IPs|
[firehol_proxies](#firehol_proxies)|**FireHOL Proxies** - Known open proxies in the last 30 days. (includes: ib_bluetack_proxies maxmind_proxy_fraud proxyrss proxz ri_connect_proxies ri_web_proxies xroxy)|ipv4 hash:net|12718 subnets, 12994 unique IPs|
[fullbogons](#fullbogons)|[Team-Cymru.org](http://www.team-cymru.org) IP space that has been allocated to an RIR, but not assigned by that RIR to an actual ISP or other end-user - **excellent list - use it only your internet interface**|ipv4 hash:net|3788 subnets, 670093640 unique IPs|updated every 1 day  from [this link](http://www.team-cymru.org/Services/Bogons/fullbogons-ipv4.txt)
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
[iw_spamlist](#iw_spamlist)|[ImproWare Antispam](http://antispam.imp.ch/) IPs sending spam, in the last 3 days|ipv4 hash:ip|3418 unique IPs|updated every 1 hour  from [this link](http://antispam.imp.ch/spamlist)
[iw_wormlist](#iw_wormlist)|[ImproWare Antispam](http://antispam.imp.ch/) IPs sending emails with viruses or worms, in the last 3 days|ipv4 hash:ip|23 unique IPs|updated every 1 hour  from [this link](http://antispam.imp.ch/wormlist)
lashback_ubl|[The LashBack UBL](http://blacklist.lashback.com/) The Unsubscribe Blacklist (UBL) is a real-time blacklist of IP addresses which are sending email to names harvested from suppression files (this is a big list, more than 500.000 IPs)|ipv4 hash:ip|disabled|updated every 1 day  from [this link](http://www.unsubscore.com/blacklist.txt)
[malc0de](#malc0de)|[Malc0de.com](http://malc0de.com) malicious IPs of the last 30 days|ipv4 hash:ip|276 unique IPs|updated every 1 day  from [this link](http://malc0de.com/bl/IP_Blacklist.txt)
[malwaredomainlist](#malwaredomainlist)|[malwaredomainlist.com](http://www.malwaredomainlist.com) list of malware active ip addresses|ipv4 hash:ip|1288 unique IPs|updated every 12 hours  from [this link](http://www.malwaredomainlist.com/hostslist/ip.txt)
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|[MaxMind.com](https://www.maxmind.com/en/anonymous-proxy-fraudulent-ip-address-list) list of anonymous proxy fraudelent IP addresses.|ipv4 hash:ip|524 unique IPs|updated every 4 hours  from [this link](https://www.maxmind.com/en/anonymous-proxy-fraudulent-ip-address-list)
[nixspam](#nixspam)|[NiX Spam](http://www.heise.de/ix/NiX-Spam-DNSBL-and-blacklist-for-download-499637.html) IP addresses that sent spam in the last hour - automatically generated entries without distinguishing open proxies from relays, dialup gateways, and so on. All IPs are removed after 12 hours if there is no spam from there.|ipv4 hash:ip|21496 unique IPs|updated every 15 mins  from [this link](http://www.dnsbl.manitu.net/download/nixspam-ip.dump.gz)
[nt_malware_http](#nt_malware_http)|[No Think](http://www.nothink.org/) Malware HTTP|ipv4 hash:ip|69 unique IPs|updated every 1 hour  from [this link](http://www.nothink.org/blacklist/blacklist_malware_http.txt)
[nt_malware_irc](#nt_malware_irc)|[No Think](http://www.nothink.org/) Malware IRC|ipv4 hash:ip|43 unique IPs|updated every 1 hour  from [this link](http://www.nothink.org/blacklist/blacklist_malware_irc.txt)
[nt_ssh_7d](#nt_ssh_7d)|[No Think](http://www.nothink.org/) Last 7 days SSH attacks|ipv4 hash:ip|0 unique IPs|updated every 1 hour  from [this link](http://www.nothink.org/blacklist/blacklist_ssh_week.txt)
openbl|[OpenBL.org](http://www.openbl.org/) default blacklist (currently it is the same with 90 days). OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications - **excellent list**|ipv4 hash:ip|disabled|updated every 4 hours  from [this link](http://www.openbl.org/lists/base.txt)
openbl_180d|[OpenBL.org](http://www.openbl.org/) last 180 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|disabled|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_180days.txt)
[openbl_1d](#openbl_1d)|[OpenBL.org](http://www.openbl.org/) last 24 hours IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|131 unique IPs|updated every 1 hour  from [this link](http://www.openbl.org/lists/base_1days.txt)
[openbl_30d](#openbl_30d)|[OpenBL.org](http://www.openbl.org/) last 30 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|2789 unique IPs|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_30days.txt)
openbl_360d|[OpenBL.org](http://www.openbl.org/) last 360 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|disabled|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_360days.txt)
[openbl_60d](#openbl_60d)|[OpenBL.org](http://www.openbl.org/) last 60 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|6959 unique IPs|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_60days.txt)
[openbl_7d](#openbl_7d)|[OpenBL.org](http://www.openbl.org/) last 7 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|637 unique IPs|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_7days.txt)
openbl_90d|[OpenBL.org](http://www.openbl.org/) last 90 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|disabled|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_90days.txt)
openbl_all|[OpenBL.org](http://www.openbl.org/) last all IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|disabled|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_all.txt)
[palevo](#palevo)|[Abuse.ch Palevo tracker](https://palevotracker.abuse.ch) worm includes IPs which are being used as botnet C&C for the Palevo crimeware - **excellent list**|ipv4 hash:ip|0 unique IPs|updated every 30 mins  from [this link](https://palevotracker.abuse.ch/blocklists.php?download=ipblocklist)
php_bad|[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) bad web hosts (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|disabled|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=b&rss=1)
[php_commenters](#php_commenters)|[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) comment spammers (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|458 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=c&rss=1)
[php_dictionary](#php_dictionary)|[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) directory attackers (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|777 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=d&rss=1)
[php_harvesters](#php_harvesters)|[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) harvesters (IPs that surf the internet looking for email addresses) (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|408 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=h&rss=1)
[php_spammers](#php_spammers)|[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) spam servers (IPs used by spammers to send messages) (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|777 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=s&rss=1)
[proxyrss](#proxyrss)|[proxyrss.com](http://www.proxyrss.com) open proxies syndicated from multiple sources.|ipv4 hash:ip|1455 unique IPs|updated every 4 hours  from [this link](http://www.proxyrss.com/proxylists/all.gz)
[proxz](#proxz)|[proxz.com](http://www.proxz.com) open proxies (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|1367 unique IPs|updated every 1 hour  from [this link](http://www.proxz.com/proxylists.xml)
[ri_connect_proxies](#ri_connect_proxies)|[rosinstrument.com](http://www.rosinstrument.com) open CONNECT proxies (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|2876 unique IPs|updated every 1 hour  from [this link](http://tools.rosinstrument.com/proxy/plab100.xml)
[ri_web_proxies](#ri_web_proxies)|[rosinstrument.com](http://www.rosinstrument.com) open HTTP proxies (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|7996 unique IPs|updated every 1 hour  from [this link](http://tools.rosinstrument.com/proxy/l100.xml)
[shunlist](#shunlist)|[AutoShun.org](http://autoshun.org/) IPs identified as hostile by correlating logs from distributed snort installations running the autoshun plugin|ipv4 hash:ip|1201 unique IPs|updated every 4 hours  from [this link](http://www.autoshun.org/files/shunlist.csv)
[snort_ipfilter](#snort_ipfilter)|[labs.snort.org](https://labs.snort.org/) supplied IP blacklist (this list seems to be updated frequently, but we found no information about it)|ipv4 hash:ip|9136 unique IPs|updated every 12 hours  from [this link](http://labs.snort.org/feeds/ip-filter.blf)
[sorbs_dul](#sorbs_dul)|[Sorbs.net](https://www.sorbs.net/) DUL, Dynamic User IPs extracted from deltas.|ipv4 hash:net|10 subnets, 4864 unique IPs|
[sorbs_http](#sorbs_http)|[Sorbs.net](https://www.sorbs.net/) HTTP proxies, extracted from deltas.|ipv4 hash:net|7 subnets, 7 unique IPs|
[sorbs_misc](#sorbs_misc)|[Sorbs.net](https://www.sorbs.net/) MISC proxies, extracted from deltas.|ipv4 hash:net|7 subnets, 7 unique IPs|
[sorbs_new_spam](#sorbs_new_spam)|[Sorbs.net](https://www.sorbs.net/) NEW Spam senders, extracted from deltas.|ipv4 hash:net|64467 subnets, 65300 unique IPs|
[sorbs_recent_spam](#sorbs_recent_spam)|[Sorbs.net](https://www.sorbs.net/) RECENT Spam senders, extracted from deltas.|ipv4 hash:net|64467 subnets, 65300 unique IPs|
[sorbs_smtp](#sorbs_smtp)|[Sorbs.net](https://www.sorbs.net/) SMTP Open Relays, extracted from deltas.|ipv4 hash:net|6 subnets, 6 unique IPs|
[sorbs_socks](#sorbs_socks)|[Sorbs.net](https://www.sorbs.net/) SOCKS proxies, extracted from deltas.|ipv4 hash:net|7 subnets, 7 unique IPs|
[sorbs_spam](#sorbs_spam)|[Sorbs.net](https://www.sorbs.net/) Spam senders, extracted from deltas.|ipv4 hash:net|64701 subnets, 65536 unique IPs|
[sorbs_web](#sorbs_web)|[Sorbs.net](https://www.sorbs.net/) WEB exploits, extracted from deltas.|ipv4 hash:net|643 subnets, 644 unique IPs|
[spamhaus_drop](#spamhaus_drop)|[Spamhaus.org](http://www.spamhaus.org) DROP list (according to their site this list should be dropped at tier-1 ISPs globaly) - **excellent list**|ipv4 hash:net|653 subnets, 18340608 unique IPs|updated every 12 hours  from [this link](http://www.spamhaus.org/drop/drop.txt)
[spamhaus_edrop](#spamhaus_edrop)|[Spamhaus.org](http://www.spamhaus.org) EDROP (extended matches that should be used with DROP) - **excellent list**|ipv4 hash:net|56 subnets, 487424 unique IPs|updated every 12 hours  from [this link](http://www.spamhaus.org/drop/edrop.txt)
[sslbl](#sslbl)|[Abuse.ch SSL Blacklist](https://sslbl.abuse.ch/) bad SSL traffic related to malware or botnet activities - **excellent list**|ipv4 hash:ip|370 unique IPs|updated every 30 mins  from [this link](https://sslbl.abuse.ch/blacklist/sslipblacklist.csv)
stopforumspam_180d|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 180 days)|ipv4 hash:ip|disabled|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/listed_ip_180.zip)
[stopforumspam_1d](#stopforumspam_1d)|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers in the last 24 hours - **excellent list**|ipv4 hash:ip|6629 unique IPs|updated every 1 hour  from [this link](http://www.stopforumspam.com/downloads/listed_ip_1.zip)
[stopforumspam_30d](#stopforumspam_30d)|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 30 days)|ipv4 hash:ip|94236 unique IPs|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/listed_ip_30.zip)
stopforumspam_365d|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 365 days)|ipv4 hash:ip|disabled|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/listed_ip_365.zip)
[stopforumspam_7d](#stopforumspam_7d)|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 7 days)|ipv4 hash:ip|29017 unique IPs|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/listed_ip_7.zip)
stopforumspam_90d|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 90 days)|ipv4 hash:ip|disabled|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/listed_ip_90.zip)
stopforumspam_ever|[StopForumSpam.com](http://www.stopforumspam.com) all IPs used by forum spammers, **ever** (normally you don't want to use this ipset, use the hourly one which includes last 24 hours IPs or the 7 days one)|ipv4 hash:ip|disabled|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/bannedips.zip)
[tor_exits](#tor_exits)|[TorProject.org](https://www.torproject.org) list of all current TOR exit points (TorDNSEL)|ipv4 hash:ip|1106 unique IPs|updated every 30 mins  from [this link](https://check.torproject.org/exit-addresses)
[virbl](#virbl)|[VirBL](http://virbl.bit.nl/) is a project of which the idea was born during the RIPE-48 meeting. The plan was to get reports of virusscanning mailservers, and put the IP-addresses that were reported to send viruses on a blacklist.|ipv4 hash:ip|23 unique IPs|updated every 1 hour  from [this link](http://virbl.bit.nl/download/virbl.dnsbl.bit.nl.txt)
[voipbl](#voipbl)|[VoIPBL.org](http://www.voipbl.org/) a distributed VoIP blacklist that is aimed to protects against VoIP Fraud and minimizing abuse for network that have publicly accessible PBX's. Several algorithms, external sources and manual confirmation are used before they categorize something as an attack and determine the threat level.|ipv4 hash:net|10586 subnets, 10998 unique IPs|updated every 4 hours  from [this link](http://www.voipbl.org/update/)
[xroxy](#xroxy)|[xroxy.com](http://www.xroxy.com) open proxies (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|2175 unique IPs|updated every 1 hour  from [this link](http://www.xroxy.com/proxyrss.xml)
[zeus](#zeus)|[Abuse.ch Zeus tracker](https://zeustracker.abuse.ch) standard, contains the same data as the ZeuS IP blocklist (zeus_badips) but with the slight difference that it doesn't exclude hijacked websites (level 2) and free web hosting providers (level 3). This means that this blocklist contains all IPv4 addresses associated with ZeuS C&Cs which are currently being tracked by ZeuS Tracker. Hence this blocklist will likely cause some false positives. - **excellent list**|ipv4 hash:ip|230 unique IPs|updated every 30 mins  from [this link](https://zeustracker.abuse.ch/blocklist.php?download=ipblocklist)
[zeus_badips](#zeus_badips)|[Abuse.ch Zeus tracker](https://zeustracker.abuse.ch) badips includes IPv4 addresses that are used by the ZeuS trojan. It is the recommened blocklist if you want to block only ZeuS IPs. It excludes IP addresses that ZeuS Tracker believes to be hijacked (level 2) or belong to a free web hosting provider (level 3). Hence the false postive rate should be much lower compared to the standard ZeuS IP blocklist. **excellent list**|ipv4 hash:ip|202 unique IPs|updated every 30 mins  from [this link](https://zeustracker.abuse.ch/blocklist.php?download=badips)

# Comparison of ipsets

Below we compare each ipset against all other.


## alienvault_reputation

[AlienVault.com](https://www.alienvault.com/) IP reputation database (this list seems to include port scanning hosts and to be updated regularly, but we found no information about its retention policy)

Source is downloaded from [this link](https://reputation.alienvault.com/reputation.generic).

The last time downloaded was found to be dated: Fri Jun 12 10:01:29 UTC 2015.

The ipset `alienvault_reputation` has **189179** entries, **189179** unique IPs.

The following table shows the overlaps of `alienvault_reputation` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `alienvault_reputation`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `alienvault_reputation`.
- ` this % ` is the percentage **of this ipset (`alienvault_reputation`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|14342|0.0%|7.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|7255|0.0%|3.8%|
[openbl_60d](#openbl_60d)|6959|6959|6933|99.6%|3.6%|
[firehol_level1](#firehol_level1)|5070|688775051|6387|0.0%|3.3%|
[dragon_http](#dragon_http)|1021|268288|6153|2.2%|3.2%|
[dshield](#dshield)|20|5120|5120|100.0%|2.7%|
[firehol_level3](#firehol_level3)|109554|9627189|4838|0.0%|2.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|4188|0.0%|2.2%|
[et_block](#et_block)|1000|18343756|3752|0.0%|1.9%|
[openbl_30d](#openbl_30d)|2789|2789|2768|99.2%|1.4%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|1385|0.0%|0.7%|
[shunlist](#shunlist)|1201|1201|1178|98.0%|0.6%|
[firehol_level2](#firehol_level2)|21534|33114|1148|3.4%|0.6%|
[blocklist_de](#blocklist_de)|27919|27919|1101|3.9%|0.5%|
[et_compromised](#et_compromised)|1704|1704|1086|63.7%|0.5%|
[bruteforceblocker](#bruteforceblocker)|1696|1696|1074|63.3%|0.5%|
[blocklist_de_ssh](#blocklist_de_ssh)|2474|2474|895|36.1%|0.4%|
[dragon_sshpauth](#dragon_sshpauth)|1589|1653|864|52.2%|0.4%|
[openbl_7d](#openbl_7d)|637|637|629|98.7%|0.3%|
[ciarmy](#ciarmy)|421|421|418|99.2%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|293|0.0%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|278|0.0%|0.1%|
[voipbl](#voipbl)|10586|10998|176|1.6%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|94236|94236|166|0.1%|0.0%|
[openbl_1d](#openbl_1d)|131|131|127|96.9%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13988|13988|121|0.8%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9136|9136|107|1.1%|0.0%|
[sorbs_spam](#sorbs_spam)|64701|65536|91|0.1%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|91|0.1%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|91|0.1%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|88|0.3%|0.0%|
[sslbl](#sslbl)|370|370|65|17.5%|0.0%|
[zeus](#zeus)|230|230|61|26.5%|0.0%|
[firehol_anonymous](#firehol_anonymous)|19277|83325|58|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|18003|18003|47|0.2%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6629|6629|43|0.6%|0.0%|
[et_tor](#et_tor)|6500|6500|42|0.6%|0.0%|
[dm_tor](#dm_tor)|6521|6521|42|0.6%|0.0%|
[bm_tor](#bm_tor)|6496|6496|42|0.6%|0.0%|
[firehol_proxies](#firehol_proxies)|12718|12994|39|0.3%|0.0%|
[zeus_badips](#zeus_badips)|202|202|37|18.3%|0.0%|
[nixspam](#nixspam)|21496|21496|37|0.1%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|169|169|34|20.1%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|3043|3043|34|1.1%|0.0%|
[tor_exits](#tor_exits)|1106|1106|30|2.7%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|29|5.5%|0.0%|
[dragon_vncprobe](#dragon_vncprobe)|89|89|29|32.5%|0.0%|
[iw_spamlist](#iw_spamlist)|3418|3418|24|0.7%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3014|3014|21|0.6%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|81|81|20|24.6%|0.0%|
[php_commenters](#php_commenters)|458|458|19|4.1%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|15|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|14|0.0%|0.0%|
[php_harvesters](#php_harvesters)|408|408|12|2.9%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2599|2599|12|0.4%|0.0%|
[malc0de](#malc0de)|276|276|9|3.2%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|8|0.6%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|1500|1500|8|0.5%|0.0%|
[php_dictionary](#php_dictionary)|777|777|7|0.9%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|6|0.4%|0.0%|
[xroxy](#xroxy)|2175|2175|5|0.2%|0.0%|
[php_spammers](#php_spammers)|777|777|5|0.6%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7996|7996|4|0.0%|0.0%|
[proxz](#proxz)|1367|1367|4|0.2%|0.0%|
[et_botcc](#et_botcc)|505|505|4|0.7%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|511|511|4|0.7%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2876|2876|3|0.1%|0.0%|
[nt_malware_irc](#nt_malware_irc)|43|43|2|4.6%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|2|0.3%|0.0%|
[sorbs_web](#sorbs_web)|643|644|1|0.1%|0.0%|
[proxyrss](#proxyrss)|1455|1455|1|0.0%|0.0%|
[nt_malware_http](#nt_malware_http)|69|69|1|1.4%|0.0%|

## blocklist_de

[Blocklist.de](https://www.blocklist.de/) IPs that have been detected by fail2ban in the last 48 hours - **excellent list**

Source is downloaded from [this link](http://lists.blocklist.de/lists/all.txt).

The last time downloaded was found to be dated: Fri Jun 12 11:56:03 UTC 2015.

The ipset `blocklist_de` has **27919** entries, **27919** unique IPs.

The following table shows the overlaps of `blocklist_de` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de`.
- ` this % ` is the percentage **of this ipset (`blocklist_de`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|21534|33114|27919|84.3%|100.0%|
[blocklist_de_mail](#blocklist_de_mail)|18003|18003|17925|99.5%|64.2%|
[blocklist_de_apache](#blocklist_de_apache)|13988|13988|13988|100.0%|50.1%|
[firehol_level3](#firehol_level3)|109554|9627189|3894|0.0%|13.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|3605|0.0%|12.9%|
[blocklist_de_imap](#blocklist_de_imap)|3043|3043|3016|99.1%|10.8%|
[blocklist_de_bots](#blocklist_de_bots)|3014|3014|3014|100.0%|10.7%|
[stopforumspam_30d](#stopforumspam_30d)|94236|94236|2853|3.0%|10.2%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2599|2599|2599|100.0%|9.3%|
[blocklist_de_ssh](#blocklist_de_ssh)|2474|2474|2473|99.9%|8.8%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|2340|8.0%|8.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|1577|0.0%|5.6%|
[blocklist_de_ftp](#blocklist_de_ftp)|1500|1500|1491|99.4%|5.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|1455|0.0%|5.2%|
[stopforumspam_1d](#stopforumspam_1d)|6629|6629|1453|21.9%|5.2%|
[alienvault_reputation](#alienvault_reputation)|189179|189179|1101|0.5%|3.9%|
[sorbs_spam](#sorbs_spam)|64701|65536|818|1.2%|2.9%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|810|1.2%|2.9%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|810|1.2%|2.9%|
[openbl_60d](#openbl_60d)|6959|6959|763|10.9%|2.7%|
[firehol_anonymous](#firehol_anonymous)|19277|83325|667|0.8%|2.3%|
[firehol_proxies](#firehol_proxies)|12718|12994|646|4.9%|2.3%|
[openbl_30d](#openbl_30d)|2789|2789|639|22.9%|2.2%|
[dragon_sshpauth](#dragon_sshpauth)|1589|1653|632|38.2%|2.2%|
[nixspam](#nixspam)|21496|21496|606|2.8%|2.1%|
[bruteforceblocker](#bruteforceblocker)|1696|1696|554|32.6%|1.9%|
[et_compromised](#et_compromised)|1704|1704|532|31.2%|1.9%|
[ri_web_proxies](#ri_web_proxies)|7996|7996|480|6.0%|1.7%|
[openbl_7d](#openbl_7d)|637|637|378|59.3%|1.3%|
[shunlist](#shunlist)|1201|1201|345|28.7%|1.2%|
[xroxy](#xroxy)|2175|2175|228|10.4%|0.8%|
[proxyrss](#proxyrss)|1455|1455|208|14.2%|0.7%|
[firehol_level1](#firehol_level1)|5070|688775051|207|0.0%|0.7%|
[snort_ipfilter](#snort_ipfilter)|9136|9136|201|2.2%|0.7%|
[proxz](#proxz)|1367|1367|200|14.6%|0.7%|
[et_block](#et_block)|1000|18343756|195|0.0%|0.6%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|178|0.0%|0.6%|
[blocklist_de_strongips](#blocklist_de_strongips)|169|169|169|100.0%|0.6%|
[iw_spamlist](#iw_spamlist)|3418|3418|122|3.5%|0.4%|
[php_dictionary](#php_dictionary)|777|777|114|14.6%|0.4%|
[openbl_1d](#openbl_1d)|131|131|112|85.4%|0.4%|
[php_spammers](#php_spammers)|777|777|109|14.0%|0.3%|
[php_commenters](#php_commenters)|458|458|107|23.3%|0.3%|
[dshield](#dshield)|20|5120|82|1.6%|0.2%|
[ri_connect_proxies](#ri_connect_proxies)|2876|2876|73|2.5%|0.2%|
[sorbs_web](#sorbs_web)|643|644|70|10.8%|0.2%|
[blocklist_de_sip](#blocklist_de_sip)|81|81|62|76.5%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|54|0.0%|0.1%|
[dragon_http](#dragon_http)|1021|268288|48|0.0%|0.1%|
[voipbl](#voipbl)|10586|10998|39|0.3%|0.1%|
[php_harvesters](#php_harvesters)|408|408|36|8.8%|0.1%|
[ciarmy](#ciarmy)|421|421|36|8.5%|0.1%|
[tor_exits](#tor_exits)|1106|1106|16|1.4%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|15|0.0%|0.0%|
[et_tor](#et_tor)|6500|6500|13|0.2%|0.0%|
[bm_tor](#bm_tor)|6496|6496|10|0.1%|0.0%|
[dm_tor](#dm_tor)|6521|6521|8|0.1%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|5|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|5|0.9%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|5|0.7%|0.0%|
[dragon_vncprobe](#dragon_vncprobe)|89|89|5|5.6%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|4|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|2|0.1%|0.0%|
[virbl](#virbl)|23|23|1|4.3%|0.0%|
[sorbs_socks](#sorbs_socks)|7|7|1|14.2%|0.0%|
[sorbs_misc](#sorbs_misc)|7|7|1|14.2%|0.0%|
[sorbs_http](#sorbs_http)|7|7|1|14.2%|0.0%|

## blocklist_de_apache

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service Apache, Apache-DDOS, RFI-Attacks.

Source is downloaded from [this link](http://lists.blocklist.de/lists/apache.txt).

The last time downloaded was found to be dated: Fri Jun 12 11:56:08 UTC 2015.

The ipset `blocklist_de_apache` has **13988** entries, **13988** unique IPs.

The following table shows the overlaps of `blocklist_de_apache` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_apache`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_apache`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_apache`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|21534|33114|13988|42.2%|100.0%|
[blocklist_de](#blocklist_de)|27919|27919|13988|50.1%|100.0%|
[blocklist_de_mail](#blocklist_de_mail)|18003|18003|11060|61.4%|79.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2599|2599|2599|100.0%|18.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|2299|0.0%|16.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|1320|0.0%|9.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|1075|0.0%|7.6%|
[firehol_level3](#firehol_level3)|109554|9627189|268|0.0%|1.9%|
[stopforumspam_30d](#stopforumspam_30d)|94236|94236|190|0.2%|1.3%|
[alienvault_reputation](#alienvault_reputation)|189179|189179|121|0.0%|0.8%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|108|0.3%|0.7%|
[stopforumspam_1d](#stopforumspam_1d)|6629|6629|57|0.8%|0.4%|
[sorbs_spam](#sorbs_spam)|64701|65536|46|0.0%|0.3%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|46|0.0%|0.3%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|46|0.0%|0.3%|
[shunlist](#shunlist)|1201|1201|35|2.9%|0.2%|
[blocklist_de_strongips](#blocklist_de_strongips)|169|169|31|18.3%|0.2%|
[snort_ipfilter](#snort_ipfilter)|9136|9136|30|0.3%|0.2%|
[ciarmy](#ciarmy)|421|421|30|7.1%|0.2%|
[php_commenters](#php_commenters)|458|458|28|6.1%|0.2%|
[blocklist_de_bots](#blocklist_de_bots)|3014|3014|23|0.7%|0.1%|
[nixspam](#nixspam)|21496|21496|22|0.1%|0.1%|
[firehol_anonymous](#firehol_anonymous)|19277|83325|19|0.0%|0.1%|
[tor_exits](#tor_exits)|1106|1106|16|1.4%|0.1%|
[et_tor](#et_tor)|6500|6500|13|0.2%|0.0%|
[dragon_http](#dragon_http)|1021|268288|11|0.0%|0.0%|
[bm_tor](#bm_tor)|6496|6496|10|0.1%|0.0%|
[dm_tor](#dm_tor)|6521|6521|8|0.1%|0.0%|
[openbl_60d](#openbl_60d)|6959|6959|7|0.1%|0.0%|
[firehol_level1](#firehol_level1)|5070|688775051|7|0.0%|0.0%|
[et_block](#et_block)|1000|18343756|7|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|5|0.0%|0.0%|
[php_spammers](#php_spammers)|777|777|5|0.6%|0.0%|
[openbl_30d](#openbl_30d)|2789|2789|4|0.1%|0.0%|
[iw_spamlist](#iw_spamlist)|3418|3418|3|0.0%|0.0%|
[voipbl](#voipbl)|10586|10998|2|0.0%|0.0%|
[php_harvesters](#php_harvesters)|408|408|2|0.4%|0.0%|
[php_dictionary](#php_dictionary)|777|777|2|0.2%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|2|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|2|0.0%|0.0%|
[firehol_proxies](#firehol_proxies)|12718|12994|2|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|1|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2876|2876|1|0.0%|0.0%|
[openbl_7d](#openbl_7d)|637|637|1|0.1%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|1|0.1%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.0%|
[dshield](#dshield)|20|5120|1|0.0%|0.0%|
[dragon_vncprobe](#dragon_vncprobe)|89|89|1|1.1%|0.0%|

## blocklist_de_bots

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the RFI-Attacks, REG-Bots, IRC-Bots or BadBots (BadBots = he has posted a Spam-Comment on a open Forum or Wiki).

Source is downloaded from [this link](http://lists.blocklist.de/lists/bots.txt).

The last time downloaded was found to be dated: Fri Jun 12 11:56:10 UTC 2015.

The ipset `blocklist_de_bots` has **3014** entries, **3014** unique IPs.

The following table shows the overlaps of `blocklist_de_bots` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_bots`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_bots`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_bots`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|21534|33114|3014|9.1%|100.0%|
[blocklist_de](#blocklist_de)|27919|27919|3014|10.7%|100.0%|
[firehol_level3](#firehol_level3)|109554|9627189|2532|0.0%|84.0%|
[stopforumspam_30d](#stopforumspam_30d)|94236|94236|2514|2.6%|83.4%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|2168|7.4%|71.9%|
[stopforumspam_1d](#stopforumspam_1d)|6629|6629|1395|21.0%|46.2%|
[firehol_anonymous](#firehol_anonymous)|19277|83325|525|0.6%|17.4%|
[firehol_proxies](#firehol_proxies)|12718|12994|524|4.0%|17.3%|
[ri_web_proxies](#ri_web_proxies)|7996|7996|394|4.9%|13.0%|
[proxyrss](#proxyrss)|1455|1455|208|14.2%|6.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|188|0.0%|6.2%|
[xroxy](#xroxy)|2175|2175|177|8.1%|5.8%|
[proxz](#proxz)|1367|1367|171|12.5%|5.6%|
[blocklist_de_strongips](#blocklist_de_strongips)|169|169|130|76.9%|4.3%|
[php_commenters](#php_commenters)|458|458|86|18.7%|2.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|74|0.0%|2.4%|
[ri_connect_proxies](#ri_connect_proxies)|2876|2876|70|2.4%|2.3%|
[firehol_level1](#firehol_level1)|5070|688775051|57|0.0%|1.8%|
[et_block](#et_block)|1000|18343756|56|0.0%|1.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|53|0.0%|1.7%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|47|0.0%|1.5%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|41|0.0%|1.3%|
[nixspam](#nixspam)|21496|21496|34|0.1%|1.1%|
[sorbs_spam](#sorbs_spam)|64701|65536|27|0.0%|0.8%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|27|0.0%|0.8%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|27|0.0%|0.8%|
[php_harvesters](#php_harvesters)|408|408|27|6.6%|0.8%|
[php_spammers](#php_spammers)|777|777|23|2.9%|0.7%|
[blocklist_de_mail](#blocklist_de_mail)|18003|18003|23|0.1%|0.7%|
[blocklist_de_apache](#blocklist_de_apache)|13988|13988|23|0.1%|0.7%|
[alienvault_reputation](#alienvault_reputation)|189179|189179|21|0.0%|0.6%|
[snort_ipfilter](#snort_ipfilter)|9136|9136|20|0.2%|0.6%|
[php_dictionary](#php_dictionary)|777|777|17|2.1%|0.5%|
[dshield](#dshield)|20|5120|8|0.1%|0.2%|
[sorbs_web](#sorbs_web)|643|644|4|0.6%|0.1%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|4|0.7%|0.1%|
[iw_spamlist](#iw_spamlist)|3418|3418|3|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|3|0.4%|0.0%|
[dragon_http](#dragon_http)|1021|268288|3|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|2|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|2|0.1%|0.0%|
[voipbl](#voipbl)|10586|10998|1|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|1|0.0%|0.0%|

## blocklist_de_bruteforce

[Blocklist.de](https://www.blocklist.de/) All IPs which attacks Joomlas, Wordpress and other Web-Logins with Brute-Force Logins.

Source is downloaded from [this link](http://lists.blocklist.de/lists/bruteforcelogin.txt).

The last time downloaded was found to be dated: Fri Jun 12 12:14:11 UTC 2015.

The ipset `blocklist_de_bruteforce` has **2599** entries, **2599** unique IPs.

The following table shows the overlaps of `blocklist_de_bruteforce` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_bruteforce`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_bruteforce`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_bruteforce`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|21534|33114|2599|7.8%|100.0%|
[blocklist_de_apache](#blocklist_de_apache)|13988|13988|2599|18.5%|100.0%|
[blocklist_de](#blocklist_de)|27919|27919|2599|9.3%|100.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|203|0.0%|7.8%|
[firehol_level3](#firehol_level3)|109554|9627189|75|0.0%|2.8%|
[stopforumspam_30d](#stopforumspam_30d)|94236|94236|58|0.0%|2.2%|
[sorbs_spam](#sorbs_spam)|64701|65536|45|0.0%|1.7%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|45|0.0%|1.7%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|45|0.0%|1.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|40|0.0%|1.5%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|37|0.1%|1.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|33|0.0%|1.2%|
[snort_ipfilter](#snort_ipfilter)|9136|9136|28|0.3%|1.0%|
[stopforumspam_1d](#stopforumspam_1d)|6629|6629|21|0.3%|0.8%|
[nixspam](#nixspam)|21496|21496|19|0.0%|0.7%|
[firehol_anonymous](#firehol_anonymous)|19277|83325|15|0.0%|0.5%|
[tor_exits](#tor_exits)|1106|1106|14|1.2%|0.5%|
[alienvault_reputation](#alienvault_reputation)|189179|189179|12|0.0%|0.4%|
[et_tor](#et_tor)|6500|6500|10|0.1%|0.3%|
[bm_tor](#bm_tor)|6496|6496|7|0.1%|0.2%|
[blocklist_de_strongips](#blocklist_de_strongips)|169|169|7|4.1%|0.2%|
[php_commenters](#php_commenters)|458|458|6|1.3%|0.2%|
[dm_tor](#dm_tor)|6521|6521|6|0.0%|0.2%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|5|0.0%|0.1%|
[php_spammers](#php_spammers)|777|777|5|0.6%|0.1%|
[firehol_level1](#firehol_level1)|5070|688775051|5|0.0%|0.1%|
[et_block](#et_block)|1000|18343756|5|0.0%|0.1%|
[dragon_http](#dragon_http)|1021|268288|4|0.0%|0.1%|
[iw_spamlist](#iw_spamlist)|3418|3418|3|0.0%|0.1%|
[php_dictionary](#php_dictionary)|777|777|2|0.2%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|2|0.0%|0.0%|
[shunlist](#shunlist)|1201|1201|1|0.0%|0.0%|
[php_harvesters](#php_harvesters)|408|408|1|0.2%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.0%|

## blocklist_de_ftp

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours for attacks on the Service FTP.

Source is downloaded from [this link](http://lists.blocklist.de/lists/ftp.txt).

The last time downloaded was found to be dated: Fri Jun 12 12:14:08 UTC 2015.

The ipset `blocklist_de_ftp` has **1500** entries, **1500** unique IPs.

The following table shows the overlaps of `blocklist_de_ftp` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_ftp`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_ftp`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_ftp`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|21534|33114|1491|4.5%|99.4%|
[blocklist_de](#blocklist_de)|27919|27919|1491|5.3%|99.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|113|0.0%|7.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|26|0.0%|1.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|21|0.0%|1.4%|
[firehol_level3](#firehol_level3)|109554|9627189|20|0.0%|1.3%|
[sorbs_spam](#sorbs_spam)|64701|65536|15|0.0%|1.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|15|0.0%|1.0%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|15|0.0%|1.0%|
[nixspam](#nixspam)|21496|21496|15|0.0%|1.0%|
[stopforumspam_30d](#stopforumspam_30d)|94236|94236|14|0.0%|0.9%|
[alienvault_reputation](#alienvault_reputation)|189179|189179|8|0.0%|0.5%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|6|0.0%|0.4%|
[dragon_http](#dragon_http)|1021|268288|6|0.0%|0.4%|
[stopforumspam_1d](#stopforumspam_1d)|6629|6629|4|0.0%|0.2%|
[php_harvesters](#php_harvesters)|408|408|3|0.7%|0.2%|
[firehol_anonymous](#firehol_anonymous)|19277|83325|3|0.0%|0.2%|
[openbl_7d](#openbl_7d)|637|637|2|0.3%|0.1%|
[openbl_60d](#openbl_60d)|6959|6959|2|0.0%|0.1%|
[openbl_30d](#openbl_30d)|2789|2789|2|0.0%|0.1%|
[iw_spamlist](#iw_spamlist)|3418|3418|2|0.0%|0.1%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|1|0.0%|0.0%|
[sorbs_web](#sorbs_web)|643|644|1|0.1%|0.0%|
[shunlist](#shunlist)|1201|1201|1|0.0%|0.0%|
[php_spammers](#php_spammers)|777|777|1|0.1%|0.0%|
[php_dictionary](#php_dictionary)|777|777|1|0.1%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|1|0.0%|0.0%|
[firehol_level1](#firehol_level1)|5070|688775051|1|0.0%|0.0%|
[et_compromised](#et_compromised)|1704|1704|1|0.0%|0.0%|
[et_block](#et_block)|1000|18343756|1|0.0%|0.0%|
[dragon_sshpauth](#dragon_sshpauth)|1589|1653|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1696|1696|1|0.0%|0.0%|

## blocklist_de_imap

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours for attacks on the Service imap, sasl, pop3, etc.

Source is downloaded from [this link](http://lists.blocklist.de/lists/imap.txt).

The last time downloaded was found to be dated: Fri Jun 12 12:14:07 UTC 2015.

The ipset `blocklist_de_imap` has **3043** entries, **3043** unique IPs.

The following table shows the overlaps of `blocklist_de_imap` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_imap`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_imap`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_imap`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de_mail](#blocklist_de_mail)|18003|18003|3043|16.9%|100.0%|
[firehol_level2](#firehol_level2)|21534|33114|3016|9.1%|99.1%|
[blocklist_de](#blocklist_de)|27919|27919|3016|10.8%|99.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|370|0.0%|12.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|74|0.0%|2.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|65|0.0%|2.1%|
[nixspam](#nixspam)|21496|21496|41|0.1%|1.3%|
[firehol_level3](#firehol_level3)|109554|9627189|39|0.0%|1.2%|
[alienvault_reputation](#alienvault_reputation)|189179|189179|34|0.0%|1.1%|
[sorbs_spam](#sorbs_spam)|64701|65536|31|0.0%|1.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|30|0.0%|0.9%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|30|0.0%|0.9%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|17|0.0%|0.5%|
[firehol_level1](#firehol_level1)|5070|688775051|17|0.0%|0.5%|
[et_block](#et_block)|1000|18343756|17|0.0%|0.5%|
[stopforumspam_30d](#stopforumspam_30d)|94236|94236|16|0.0%|0.5%|
[openbl_60d](#openbl_60d)|6959|6959|15|0.2%|0.4%|
[openbl_30d](#openbl_30d)|2789|2789|11|0.3%|0.3%|
[openbl_7d](#openbl_7d)|637|637|7|1.0%|0.2%|
[dragon_http](#dragon_http)|1021|268288|7|0.0%|0.2%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|6|0.0%|0.1%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|5|0.0%|0.1%|
[iw_spamlist](#iw_spamlist)|3418|3418|4|0.1%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|4|0.0%|0.1%|
[et_compromised](#et_compromised)|1704|1704|4|0.2%|0.1%|
[bruteforceblocker](#bruteforceblocker)|1696|1696|4|0.2%|0.1%|
[shunlist](#shunlist)|1201|1201|3|0.2%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9136|9136|2|0.0%|0.0%|
[php_harvesters](#php_harvesters)|408|408|2|0.4%|0.0%|
[voipbl](#voipbl)|10586|10998|1|0.0%|0.0%|
[virbl](#virbl)|23|23|1|4.3%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6629|6629|1|0.0%|0.0%|
[openbl_1d](#openbl_1d)|131|131|1|0.7%|0.0%|
[dragon_vncprobe](#dragon_vncprobe)|89|89|1|1.1%|0.0%|
[dragon_sshpauth](#dragon_sshpauth)|1589|1653|1|0.0%|0.0%|
[ciarmy](#ciarmy)|421|421|1|0.2%|0.0%|

## blocklist_de_mail

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service Mail, Postfix.

Source is downloaded from [this link](http://lists.blocklist.de/lists/mail.txt).

The last time downloaded was found to be dated: Fri Jun 12 12:14:05 UTC 2015.

The ipset `blocklist_de_mail` has **18003** entries, **18003** unique IPs.

The following table shows the overlaps of `blocklist_de_mail` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_mail`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_mail`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_mail`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|21534|33114|17925|54.1%|99.5%|
[blocklist_de](#blocklist_de)|27919|27919|17925|64.2%|99.5%|
[blocklist_de_apache](#blocklist_de_apache)|13988|13988|11060|79.0%|61.4%|
[blocklist_de_imap](#blocklist_de_imap)|3043|3043|3043|100.0%|16.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|2714|0.0%|15.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|1407|0.0%|7.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|1214|0.0%|6.7%|
[sorbs_spam](#sorbs_spam)|64701|65536|731|1.1%|4.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|722|1.1%|4.0%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|722|1.1%|4.0%|
[nixspam](#nixspam)|21496|21496|553|2.5%|3.0%|
[firehol_level3](#firehol_level3)|109554|9627189|377|0.0%|2.0%|
[stopforumspam_30d](#stopforumspam_30d)|94236|94236|249|0.2%|1.3%|
[snort_ipfilter](#snort_ipfilter)|9136|9136|152|1.6%|0.8%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|132|0.4%|0.7%|
[firehol_anonymous](#firehol_anonymous)|19277|83325|121|0.1%|0.6%|
[firehol_proxies](#firehol_proxies)|12718|12994|119|0.9%|0.6%|
[iw_spamlist](#iw_spamlist)|3418|3418|114|3.3%|0.6%|
[php_dictionary](#php_dictionary)|777|777|93|11.9%|0.5%|
[ri_web_proxies](#ri_web_proxies)|7996|7996|84|1.0%|0.4%|
[php_spammers](#php_spammers)|777|777|78|10.0%|0.4%|
[sorbs_web](#sorbs_web)|643|644|65|10.0%|0.3%|
[xroxy](#xroxy)|2175|2175|51|2.3%|0.2%|
[alienvault_reputation](#alienvault_reputation)|189179|189179|47|0.0%|0.2%|
[stopforumspam_1d](#stopforumspam_1d)|6629|6629|43|0.6%|0.2%|
[php_commenters](#php_commenters)|458|458|30|6.5%|0.1%|
[proxz](#proxz)|1367|1367|29|2.1%|0.1%|
[firehol_level1](#firehol_level1)|5070|688775051|25|0.0%|0.1%|
[et_block](#et_block)|1000|18343756|24|0.0%|0.1%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|23|0.0%|0.1%|
[blocklist_de_bots](#blocklist_de_bots)|3014|3014|23|0.7%|0.1%|
[blocklist_de_strongips](#blocklist_de_strongips)|169|169|21|12.4%|0.1%|
[openbl_60d](#openbl_60d)|6959|6959|19|0.2%|0.1%|
[openbl_30d](#openbl_30d)|2789|2789|14|0.5%|0.0%|
[dragon_http](#dragon_http)|1021|268288|13|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|10|0.0%|0.0%|
[openbl_7d](#openbl_7d)|637|637|8|1.2%|0.0%|
[php_harvesters](#php_harvesters)|408|408|5|1.2%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|5|0.0%|0.0%|
[shunlist](#shunlist)|1201|1201|4|0.3%|0.0%|
[et_compromised](#et_compromised)|1704|1704|4|0.2%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1696|1696|4|0.2%|0.0%|
[et_tor](#et_tor)|6500|6500|3|0.0%|0.0%|
[ciarmy](#ciarmy)|421|421|3|0.7%|0.0%|
[bm_tor](#bm_tor)|6496|6496|3|0.0%|0.0%|
[voipbl](#voipbl)|10586|10998|2|0.0%|0.0%|
[tor_exits](#tor_exits)|1106|1106|2|0.1%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|2|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2876|2876|2|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|2|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|2|0.3%|0.0%|
[dragon_vncprobe](#dragon_vncprobe)|89|89|2|2.2%|0.0%|
[dm_tor](#dm_tor)|6521|6521|2|0.0%|0.0%|
[virbl](#virbl)|23|23|1|4.3%|0.0%|
[sorbs_socks](#sorbs_socks)|7|7|1|14.2%|0.0%|
[sorbs_misc](#sorbs_misc)|7|7|1|14.2%|0.0%|
[sorbs_http](#sorbs_http)|7|7|1|14.2%|0.0%|
[openbl_1d](#openbl_1d)|131|131|1|0.7%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|1|0.1%|0.0%|
[dragon_sshpauth](#dragon_sshpauth)|1589|1653|1|0.0%|0.0%|

## blocklist_de_sip

[Blocklist.de](https://www.blocklist.de/) All IP addresses that tried to login in a SIP, VOIP or Asterisk Server and are included in the IPs list from [infiltrated.net](www.infiltrated.net)

Source is downloaded from [this link](http://lists.blocklist.de/lists/sip.txt).

The last time downloaded was found to be dated: Fri Jun 12 12:10:08 UTC 2015.

The ipset `blocklist_de_sip` has **81** entries, **81** unique IPs.

The following table shows the overlaps of `blocklist_de_sip` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_sip`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_sip`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_sip`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|21534|33114|62|0.1%|76.5%|
[blocklist_de](#blocklist_de)|27919|27919|62|0.2%|76.5%|
[voipbl](#voipbl)|10586|10998|32|0.2%|39.5%|
[alienvault_reputation](#alienvault_reputation)|189179|189179|20|0.0%|24.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|17|0.0%|20.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|4|0.0%|4.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|4|0.0%|4.9%|
[firehol_level3](#firehol_level3)|109554|9627189|4|0.0%|4.9%|
[dragon_http](#dragon_http)|1021|268288|3|0.0%|3.7%|
[shunlist](#shunlist)|1201|1201|2|0.1%|2.4%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|2|0.0%|2.4%|
[et_botcc](#et_botcc)|505|505|1|0.1%|1.2%|

## blocklist_de_ssh

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service SSH.

Source is downloaded from [this link](http://lists.blocklist.de/lists/ssh.txt).

The last time downloaded was found to be dated: Fri Jun 12 11:56:04 UTC 2015.

The ipset `blocklist_de_ssh` has **2474** entries, **2474** unique IPs.

The following table shows the overlaps of `blocklist_de_ssh` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_ssh`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_ssh`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_ssh`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|21534|33114|2473|7.4%|99.9%|
[blocklist_de](#blocklist_de)|27919|27919|2473|8.8%|99.9%|
[alienvault_reputation](#alienvault_reputation)|189179|189179|895|0.4%|36.1%|
[firehol_level3](#firehol_level3)|109554|9627189|828|0.0%|33.4%|
[openbl_60d](#openbl_60d)|6959|6959|734|10.5%|29.6%|
[dragon_sshpauth](#dragon_sshpauth)|1589|1653|629|38.0%|25.4%|
[openbl_30d](#openbl_30d)|2789|2789|618|22.1%|24.9%|
[bruteforceblocker](#bruteforceblocker)|1696|1696|548|32.3%|22.1%|
[et_compromised](#et_compromised)|1704|1704|526|30.8%|21.2%|
[openbl_7d](#openbl_7d)|637|637|367|57.6%|14.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|363|0.0%|14.6%|
[shunlist](#shunlist)|1201|1201|303|25.2%|12.2%|
[firehol_level1](#firehol_level1)|5070|688775051|117|0.0%|4.7%|
[openbl_1d](#openbl_1d)|131|131|111|84.7%|4.4%|
[et_block](#et_block)|1000|18343756|107|0.0%|4.3%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|102|0.0%|4.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|93|0.0%|3.7%|
[dshield](#dshield)|20|5120|73|1.4%|2.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|45|0.0%|1.8%|
[blocklist_de_strongips](#blocklist_de_strongips)|169|169|27|15.9%|1.0%|
[stopforumspam_30d](#stopforumspam_30d)|94236|94236|19|0.0%|0.7%|
[dragon_http](#dragon_http)|1021|268288|13|0.0%|0.5%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|7|0.0%|0.2%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|5|0.0%|0.2%|
[sorbs_spam](#sorbs_spam)|64701|65536|3|0.0%|0.1%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|3|0.0%|0.1%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|3|0.0%|0.1%|
[ciarmy](#ciarmy)|421|421|3|0.7%|0.1%|
[voipbl](#voipbl)|10586|10998|2|0.0%|0.0%|
[nixspam](#nixspam)|21496|21496|2|0.0%|0.0%|
[dragon_vncprobe](#dragon_vncprobe)|89|89|2|2.2%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6629|6629|1|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7996|7996|1|0.0%|0.0%|
[php_spammers](#php_spammers)|777|777|1|0.1%|0.0%|
[php_harvesters](#php_harvesters)|408|408|1|0.2%|0.0%|
[php_commenters](#php_commenters)|458|458|1|0.2%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|1|0.0%|0.0%|
[firehol_proxies](#firehol_proxies)|12718|12994|1|0.0%|0.0%|
[firehol_anonymous](#firehol_anonymous)|19277|83325|1|0.0%|0.0%|

## blocklist_de_strongips

[Blocklist.de](https://www.blocklist.de/) All IPs which are older then 2 month and have more then 5.000 attacks.

Source is downloaded from [this link](http://lists.blocklist.de/lists/strongips.txt).

The last time downloaded was found to be dated: Fri Jun 12 12:14:10 UTC 2015.

The ipset `blocklist_de_strongips` has **169** entries, **169** unique IPs.

The following table shows the overlaps of `blocklist_de_strongips` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_strongips`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_strongips`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_strongips`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|21534|33114|169|0.5%|100.0%|
[blocklist_de](#blocklist_de)|27919|27919|169|0.6%|100.0%|
[firehol_level3](#firehol_level3)|109554|9627189|156|0.0%|92.3%|
[stopforumspam_30d](#stopforumspam_30d)|94236|94236|131|0.1%|77.5%|
[blocklist_de_bots](#blocklist_de_bots)|3014|3014|130|4.3%|76.9%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|116|0.3%|68.6%|
[stopforumspam_1d](#stopforumspam_1d)|6629|6629|102|1.5%|60.3%|
[php_commenters](#php_commenters)|458|458|44|9.6%|26.0%|
[alienvault_reputation](#alienvault_reputation)|189179|189179|34|0.0%|20.1%|
[blocklist_de_apache](#blocklist_de_apache)|13988|13988|31|0.2%|18.3%|
[blocklist_de_ssh](#blocklist_de_ssh)|2474|2474|27|1.0%|15.9%|
[openbl_60d](#openbl_60d)|6959|6959|24|0.3%|14.2%|
[openbl_30d](#openbl_30d)|2789|2789|23|0.8%|13.6%|
[openbl_7d](#openbl_7d)|637|637|22|3.4%|13.0%|
[blocklist_de_mail](#blocklist_de_mail)|18003|18003|21|0.1%|12.4%|
[firehol_level1](#firehol_level1)|5070|688775051|20|0.0%|11.8%|
[dragon_sshpauth](#dragon_sshpauth)|1589|1653|20|1.2%|11.8%|
[shunlist](#shunlist)|1201|1201|19|1.5%|11.2%|
[openbl_1d](#openbl_1d)|131|131|17|12.9%|10.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|17|0.0%|10.0%|
[et_block](#et_block)|1000|18343756|14|0.0%|8.2%|
[dshield](#dshield)|20|5120|12|0.2%|7.1%|
[php_spammers](#php_spammers)|777|777|10|1.2%|5.9%|
[firehol_proxies](#firehol_proxies)|12718|12994|9|0.0%|5.3%|
[firehol_anonymous](#firehol_anonymous)|19277|83325|9|0.0%|5.3%|
[ri_web_proxies](#ri_web_proxies)|7996|7996|8|0.1%|4.7%|
[xroxy](#xroxy)|2175|2175|7|0.3%|4.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|7|0.0%|4.1%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2599|2599|7|0.2%|4.1%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|6|0.0%|3.5%|
[proxz](#proxz)|1367|1367|6|0.4%|3.5%|
[proxyrss](#proxyrss)|1455|1455|6|0.4%|3.5%|
[php_dictionary](#php_dictionary)|777|777|5|0.6%|2.9%|
[php_harvesters](#php_harvesters)|408|408|3|0.7%|1.7%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|1.7%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|2|0.0%|1.1%|
[sorbs_web](#sorbs_web)|643|644|2|0.3%|1.1%|
[sorbs_spam](#sorbs_spam)|64701|65536|2|0.0%|1.1%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|2|0.0%|1.1%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|2|0.0%|1.1%|
[snort_ipfilter](#snort_ipfilter)|9136|9136|2|0.0%|1.1%|
[nixspam](#nixspam)|21496|21496|2|0.0%|1.1%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|2|0.1%|1.1%|
[dragon_http](#dragon_http)|1021|268288|2|0.0%|1.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|1|0.0%|0.5%|
[et_compromised](#et_compromised)|1704|1704|1|0.0%|0.5%|
[ciarmy](#ciarmy)|421|421|1|0.2%|0.5%|
[bruteforceblocker](#bruteforceblocker)|1696|1696|1|0.0%|0.5%|

## bm_tor

[torstatus.blutmagie.de](https://torstatus.blutmagie.de) list of all TOR network servers

Source is downloaded from [this link](https://torstatus.blutmagie.de/ip_list_all.php/Tor_ip_list_ALL.csv).

The last time downloaded was found to be dated: Fri Jun 12 11:54:02 UTC 2015.

The ipset `bm_tor` has **6496** entries, **6496** unique IPs.

The following table shows the overlaps of `bm_tor` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `bm_tor`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `bm_tor`.
- ` this % ` is the percentage **of this ipset (`bm_tor`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_anonymous](#firehol_anonymous)|19277|83325|6496|7.7%|100.0%|
[dm_tor](#dm_tor)|6521|6521|6417|98.4%|98.7%|
[et_tor](#et_tor)|6500|6500|5736|88.2%|88.3%|
[firehol_level3](#firehol_level3)|109554|9627189|1081|0.0%|16.6%|
[snort_ipfilter](#snort_ipfilter)|9136|9136|1043|11.4%|16.0%|
[tor_exits](#tor_exits)|1106|1106|1008|91.1%|15.5%|
[stopforumspam_30d](#stopforumspam_30d)|94236|94236|644|0.6%|9.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|629|0.0%|9.6%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|528|1.8%|8.1%|
[firehol_level2](#firehol_level2)|21534|33114|325|0.9%|5.0%|
[stopforumspam_1d](#stopforumspam_1d)|6629|6629|320|4.8%|4.9%|
[firehol_proxies](#firehol_proxies)|12718|12994|234|1.8%|3.6%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|229|43.7%|3.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|186|0.0%|2.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|171|0.0%|2.6%|
[php_commenters](#php_commenters)|458|458|54|11.7%|0.8%|
[alienvault_reputation](#alienvault_reputation)|189179|189179|42|0.0%|0.6%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|22|0.0%|0.3%|
[openbl_60d](#openbl_60d)|6959|6959|20|0.2%|0.3%|
[dragon_http](#dragon_http)|1021|268288|16|0.0%|0.2%|
[blocklist_de_apache](#blocklist_de_apache)|13988|13988|10|0.0%|0.1%|
[blocklist_de](#blocklist_de)|27919|27919|10|0.0%|0.1%|
[php_harvesters](#php_harvesters)|408|408|7|1.7%|0.1%|
[nixspam](#nixspam)|21496|21496|7|0.0%|0.1%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2599|2599|7|0.2%|0.1%|
[ri_web_proxies](#ri_web_proxies)|7996|7996|5|0.0%|0.0%|
[php_spammers](#php_spammers)|777|777|5|0.6%|0.0%|
[firehol_level1](#firehol_level1)|5070|688775051|5|0.0%|0.0%|
[sorbs_spam](#sorbs_spam)|64701|65536|4|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|4|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|4|0.0%|0.0%|
[php_dictionary](#php_dictionary)|777|777|4|0.5%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|4|0.0%|0.0%|
[et_block](#et_block)|1000|18343756|4|0.0%|0.0%|
[voipbl](#voipbl)|10586|10998|3|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|3|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|18003|18003|3|0.0%|0.0%|
[xroxy](#xroxy)|2175|2175|2|0.0%|0.0%|
[dshield](#dshield)|20|5120|2|0.0%|0.0%|
[shunlist](#shunlist)|1201|1201|1|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2876|2876|1|0.0%|0.0%|

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
[fullbogons](#fullbogons)|3788|670093640|592708608|88.4%|100.0%|
[firehol_level1](#firehol_level1)|5070|688775051|592708608|86.0%|100.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|4194304|3.0%|0.7%|
[voipbl](#voipbl)|10586|10998|319|2.9%|0.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|5|0.0%|0.0%|
[iw_spamlist](#iw_spamlist)|3418|3418|3|0.0%|0.0%|
[firehol_level3](#firehol_level3)|109554|9627189|3|0.0%|0.0%|
[php_harvesters](#php_harvesters)|408|408|1|0.2%|0.0%|
[php_commenters](#php_commenters)|458|458|1|0.2%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.0%|
[ciarmy](#ciarmy)|421|421|1|0.2%|0.0%|

## bruteforceblocker

[danger.rulez.sk](http://danger.rulez.sk/) IPs detected by [bruteforceblocker](http://danger.rulez.sk/index.php/bruteforceblocker/) (fail2ban alternative for SSH on OpenBSD). This is an automatically generated list from users reporting failed authentication attempts. An IP seems to be included if 3 or more users report it. Its retention pocily seems 30 days.

Source is downloaded from [this link](http://danger.rulez.sk/projects/bruteforceblocker/blist.php).

The last time downloaded was found to be dated: Fri Jun 12 12:09:43 UTC 2015.

The ipset `bruteforceblocker` has **1696** entries, **1696** unique IPs.

The following table shows the overlaps of `bruteforceblocker` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `bruteforceblocker`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `bruteforceblocker`.
- ` this % ` is the percentage **of this ipset (`bruteforceblocker`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level3](#firehol_level3)|109554|9627189|1696|0.0%|100.0%|
[et_compromised](#et_compromised)|1704|1704|1652|96.9%|97.4%|
[alienvault_reputation](#alienvault_reputation)|189179|189179|1074|0.5%|63.3%|
[openbl_60d](#openbl_60d)|6959|6959|964|13.8%|56.8%|
[openbl_30d](#openbl_30d)|2789|2789|903|32.3%|53.2%|
[dragon_sshpauth](#dragon_sshpauth)|1589|1653|637|38.5%|37.5%|
[firehol_level2](#firehol_level2)|21534|33114|555|1.6%|32.7%|
[blocklist_de](#blocklist_de)|27919|27919|554|1.9%|32.6%|
[blocklist_de_ssh](#blocklist_de_ssh)|2474|2474|548|22.1%|32.3%|
[shunlist](#shunlist)|1201|1201|345|28.7%|20.3%|
[openbl_7d](#openbl_7d)|637|637|310|48.6%|18.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|157|0.0%|9.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|86|0.0%|5.0%|
[firehol_level1](#firehol_level1)|5070|688775051|67|0.0%|3.9%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|61|0.0%|3.5%|
[et_block](#et_block)|1000|18343756|61|0.0%|3.5%|
[openbl_1d](#openbl_1d)|131|131|59|45.0%|3.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|53|0.0%|3.1%|
[dshield](#dshield)|20|5120|25|0.4%|1.4%|
[dragon_http](#dragon_http)|1021|268288|14|0.0%|0.8%|
[stopforumspam_30d](#stopforumspam_30d)|94236|94236|9|0.0%|0.5%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|5|0.0%|0.2%|
[blocklist_de_mail](#blocklist_de_mail)|18003|18003|4|0.0%|0.2%|
[blocklist_de_imap](#blocklist_de_imap)|3043|3043|4|0.1%|0.2%|
[voipbl](#voipbl)|10586|10998|3|0.0%|0.1%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|3|0.0%|0.1%|
[sorbs_spam](#sorbs_spam)|64701|65536|3|0.0%|0.1%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|3|0.0%|0.1%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|3|0.0%|0.1%|
[firehol_proxies](#firehol_proxies)|12718|12994|3|0.0%|0.1%|
[firehol_anonymous](#firehol_anonymous)|19277|83325|3|0.0%|0.1%|
[ciarmy](#ciarmy)|421|421|3|0.7%|0.1%|
[proxz](#proxz)|1367|1367|2|0.1%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|2|0.0%|0.1%|
[xroxy](#xroxy)|2175|2175|1|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6629|6629|1|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7996|7996|1|0.0%|0.0%|
[proxyrss](#proxyrss)|1455|1455|1|0.0%|0.0%|
[php_spammers](#php_spammers)|777|777|1|0.1%|0.0%|
[php_commenters](#php_commenters)|458|458|1|0.2%|0.0%|
[nixspam](#nixspam)|21496|21496|1|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|169|169|1|0.5%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|1500|1500|1|0.0%|0.0%|

## ciarmy

[CIArmy.com](http://ciarmy.com/) IPs with poor Rogue Packet score that have not yet been identified as malicious by the community

Source is downloaded from [this link](http://cinsscore.com/list/ci-badguys.txt).

The last time downloaded was found to be dated: Fri Jun 12 10:15:06 UTC 2015.

The ipset `ciarmy` has **421** entries, **421** unique IPs.

The following table shows the overlaps of `ciarmy` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ciarmy`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ciarmy`.
- ` this % ` is the percentage **of this ipset (`ciarmy`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level3](#firehol_level3)|109554|9627189|421|0.0%|100.0%|
[alienvault_reputation](#alienvault_reputation)|189179|189179|418|0.2%|99.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|70|0.0%|16.6%|
[firehol_level2](#firehol_level2)|21534|33114|37|0.1%|8.7%|
[blocklist_de](#blocklist_de)|27919|27919|36|0.1%|8.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|34|0.0%|8.0%|
[blocklist_de_apache](#blocklist_de_apache)|13988|13988|30|0.2%|7.1%|
[shunlist](#shunlist)|1201|1201|29|2.4%|6.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|22|0.0%|5.2%|
[dragon_http](#dragon_http)|1021|268288|12|0.0%|2.8%|
[firehol_level1](#firehol_level1)|5070|688775051|6|0.0%|1.4%|
[dshield](#dshield)|20|5120|5|0.0%|1.1%|
[et_compromised](#et_compromised)|1704|1704|3|0.1%|0.7%|
[bruteforceblocker](#bruteforceblocker)|1696|1696|3|0.1%|0.7%|
[blocklist_de_ssh](#blocklist_de_ssh)|2474|2474|3|0.1%|0.7%|
[blocklist_de_mail](#blocklist_de_mail)|18003|18003|3|0.0%|0.7%|
[voipbl](#voipbl)|10586|10998|2|0.0%|0.4%|
[stopforumspam_30d](#stopforumspam_30d)|94236|94236|2|0.0%|0.4%|
[openbl_7d](#openbl_7d)|637|637|2|0.3%|0.4%|
[openbl_60d](#openbl_60d)|6959|6959|2|0.0%|0.4%|
[openbl_30d](#openbl_30d)|2789|2789|2|0.0%|0.4%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|1|0.0%|0.2%|
[openbl_1d](#openbl_1d)|131|131|1|0.7%|0.2%|
[fullbogons](#fullbogons)|3788|670093640|1|0.0%|0.2%|
[et_block](#et_block)|1000|18343756|1|0.0%|0.2%|
[dragon_vncprobe](#dragon_vncprobe)|89|89|1|1.1%|0.2%|
[dragon_sshpauth](#dragon_sshpauth)|1589|1653|1|0.0%|0.2%|
[bogons](#bogons)|13|592708608|1|0.0%|0.2%|
[blocklist_de_strongips](#blocklist_de_strongips)|169|169|1|0.5%|0.2%|
[blocklist_de_imap](#blocklist_de_imap)|3043|3043|1|0.0%|0.2%|

## cleanmx_viruses

[Clean-MX.de](http://support.clean-mx.de/clean-mx/viruses.php) IPs with viruses

Source is downloaded from [this link](http://support.clean-mx.de/clean-mx/xmlviruses.php?sort=id%20desc&response=alive).

The last time downloaded was found to be dated: Fri Jun 12 09:28:18 UTC 2015.

The ipset `cleanmx_viruses` has **511** entries, **511** unique IPs.

The following table shows the overlaps of `cleanmx_viruses` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `cleanmx_viruses`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `cleanmx_viruses`.
- ` this % ` is the percentage **of this ipset (`cleanmx_viruses`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level3](#firehol_level3)|109554|9627189|511|0.0%|100.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|58|0.0%|11.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|28|0.0%|5.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|25|0.0%|4.8%|
[malc0de](#malc0de)|276|276|8|2.8%|1.5%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|4|0.3%|0.7%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|4|0.0%|0.7%|
[alienvault_reputation](#alienvault_reputation)|189179|189179|4|0.0%|0.7%|
[stopforumspam_30d](#stopforumspam_30d)|94236|94236|1|0.0%|0.1%|
[sorbs_spam](#sorbs_spam)|64701|65536|1|0.0%|0.1%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|1|0.0%|0.1%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|1|0.0%|0.1%|
[snort_ipfilter](#snort_ipfilter)|9136|9136|1|0.0%|0.1%|
[nixspam](#nixspam)|21496|21496|1|0.0%|0.1%|

## dm_tor

[dan.me.uk](https://www.dan.me.uk) dynamic list of TOR nodes

Source is downloaded from [this link](https://www.dan.me.uk/torlist/).

The last time downloaded was found to be dated: Fri Jun 12 12:09:09 UTC 2015.

The ipset `dm_tor` has **6521** entries, **6521** unique IPs.

The following table shows the overlaps of `dm_tor` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `dm_tor`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `dm_tor`.
- ` this % ` is the percentage **of this ipset (`dm_tor`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_anonymous](#firehol_anonymous)|19277|83325|6521|7.8%|100.0%|
[bm_tor](#bm_tor)|6496|6496|6417|98.7%|98.4%|
[et_tor](#et_tor)|6500|6500|5734|88.2%|87.9%|
[firehol_level3](#firehol_level3)|109554|9627189|1079|0.0%|16.5%|
[snort_ipfilter](#snort_ipfilter)|9136|9136|1041|11.3%|15.9%|
[tor_exits](#tor_exits)|1106|1106|1018|92.0%|15.6%|
[stopforumspam_30d](#stopforumspam_30d)|94236|94236|644|0.6%|9.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|626|0.0%|9.5%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|528|1.8%|8.0%|
[firehol_level2](#firehol_level2)|21534|33114|325|0.9%|4.9%|
[stopforumspam_1d](#stopforumspam_1d)|6629|6629|321|4.8%|4.9%|
[firehol_proxies](#firehol_proxies)|12718|12994|235|1.8%|3.6%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|230|43.8%|3.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|186|0.0%|2.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|171|0.0%|2.6%|
[php_commenters](#php_commenters)|458|458|54|11.7%|0.8%|
[alienvault_reputation](#alienvault_reputation)|189179|189179|42|0.0%|0.6%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|22|0.0%|0.3%|
[openbl_60d](#openbl_60d)|6959|6959|20|0.2%|0.3%|
[dragon_http](#dragon_http)|1021|268288|16|0.0%|0.2%|
[nixspam](#nixspam)|21496|21496|8|0.0%|0.1%|
[blocklist_de_apache](#blocklist_de_apache)|13988|13988|8|0.0%|0.1%|
[blocklist_de](#blocklist_de)|27919|27919|8|0.0%|0.1%|
[php_harvesters](#php_harvesters)|408|408|7|1.7%|0.1%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2599|2599|6|0.2%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7996|7996|5|0.0%|0.0%|
[php_spammers](#php_spammers)|777|777|5|0.6%|0.0%|
[firehol_level1](#firehol_level1)|5070|688775051|5|0.0%|0.0%|
[sorbs_spam](#sorbs_spam)|64701|65536|4|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|4|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|4|0.0%|0.0%|
[php_dictionary](#php_dictionary)|777|777|4|0.5%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|4|0.0%|0.0%|
[et_block](#et_block)|1000|18343756|4|0.0%|0.0%|
[voipbl](#voipbl)|10586|10998|3|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|3|0.0%|0.0%|
[xroxy](#xroxy)|2175|2175|2|0.0%|0.0%|
[dshield](#dshield)|20|5120|2|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|18003|18003|2|0.0%|0.0%|
[shunlist](#shunlist)|1201|1201|1|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2876|2876|1|0.0%|0.0%|

## dragon_http

[Dragon Search Group](http://www.dragonresearchgroup.org/) IPs that have been seen sending HTTP requests to Dragon Research Pods in the last 7 days. This report lists hosts that are highly suspicious and are likely conducting malicious HTTP attacks. LEGITIMATE SEARCH ENGINE BOTS MAY BE IN THIS LIST. This report is informational.  It is not a blacklist, but some operators may choose to use it to help protect their networks and hosts in the forms of automated reporting and mitigation services.

Source is downloaded from [this link](http://www.dragonresearchgroup.org/insight/http-report.txt).

The last time downloaded was found to be dated: Fri Jun 12 02:00:05 UTC 2015.

The ipset `dragon_http` has **1021** entries, **268288** unique IPs.

The following table shows the overlaps of `dragon_http` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `dragon_http`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `dragon_http`.
- ` this % ` is the percentage **of this ipset (`dragon_http`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|20480|0.0%|7.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|11992|0.0%|4.4%|
[alienvault_reputation](#alienvault_reputation)|189179|189179|6153|3.2%|2.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|5989|0.0%|2.2%|
[firehol_level1](#firehol_level1)|5070|688775051|1025|0.0%|0.3%|
[et_block](#et_block)|1000|18343756|1024|0.0%|0.3%|
[dshield](#dshield)|20|5120|768|15.0%|0.2%|
[firehol_level3](#firehol_level3)|109554|9627189|562|0.0%|0.2%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|256|0.0%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|256|0.0%|0.0%|
[openbl_60d](#openbl_60d)|6959|6959|213|3.0%|0.0%|
[openbl_30d](#openbl_30d)|2789|2789|146|5.2%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|94236|94236|110|0.1%|0.0%|
[sorbs_spam](#sorbs_spam)|64701|65536|72|0.1%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|71|0.1%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|71|0.1%|0.0%|
[firehol_level2](#firehol_level2)|21534|33114|60|0.1%|0.0%|
[openbl_7d](#openbl_7d)|637|637|52|8.1%|0.0%|
[blocklist_de](#blocklist_de)|27919|27919|48|0.1%|0.0%|
[firehol_anonymous](#firehol_anonymous)|19277|83325|47|0.0%|0.0%|
[firehol_proxies](#firehol_proxies)|12718|12994|34|0.2%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|32|0.1%|0.0%|
[nixspam](#nixspam)|21496|21496|32|0.1%|0.0%|
[voipbl](#voipbl)|10586|10998|29|0.2%|0.0%|
[shunlist](#shunlist)|1201|1201|26|2.1%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|25|0.0%|0.0%|
[dragon_vncprobe](#dragon_vncprobe)|89|89|24|26.9%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7996|7996|21|0.2%|0.0%|
[et_tor](#et_tor)|6500|6500|16|0.2%|0.0%|
[dm_tor](#dm_tor)|6521|6521|16|0.2%|0.0%|
[bm_tor](#bm_tor)|6496|6496|16|0.2%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1696|1696|14|0.8%|0.0%|
[et_compromised](#et_compromised)|1704|1704|13|0.7%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2474|2474|13|0.5%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|18003|18003|13|0.0%|0.0%|
[ciarmy](#ciarmy)|421|421|12|2.8%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9136|9136|11|0.1%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13988|13988|11|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6629|6629|8|0.1%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|3043|3043|7|0.2%|0.0%|
[xroxy](#xroxy)|2175|2175|6|0.2%|0.0%|
[openbl_1d](#openbl_1d)|131|131|6|4.5%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|6|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|1500|1500|6|0.4%|0.0%|
[tor_exits](#tor_exits)|1106|1106|5|0.4%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2876|2876|4|0.1%|0.0%|
[proxz](#proxz)|1367|1367|4|0.2%|0.0%|
[php_commenters](#php_commenters)|458|458|4|0.8%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|4|0.7%|0.0%|
[dragon_sshpauth](#dragon_sshpauth)|1589|1653|4|0.2%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2599|2599|4|0.1%|0.0%|
[zeus_badips](#zeus_badips)|202|202|3|1.4%|0.0%|
[zeus](#zeus)|230|230|3|1.3%|0.0%|
[proxyrss](#proxyrss)|1455|1455|3|0.2%|0.0%|
[malc0de](#malc0de)|276|276|3|1.0%|0.0%|
[et_botcc](#et_botcc)|505|505|3|0.5%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|81|81|3|3.7%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3014|3014|3|0.0%|0.0%|
[php_dictionary](#php_dictionary)|777|777|2|0.2%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|2|0.1%|0.0%|
[iw_spamlist](#iw_spamlist)|3418|3418|2|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|2|0.1%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|169|169|2|1.1%|0.0%|
[sslbl](#sslbl)|370|370|1|0.2%|0.0%|
[sorbs_web](#sorbs_web)|643|644|1|0.1%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|1|0.1%|0.0%|

## dragon_sshpauth

[Dragon Search Group](http://www.dragonresearchgroup.org/) IP address that has been seen attempting to remotely login to a host using SSH password authentication, in the last 7 days. This report lists hosts that are highly suspicious and are likely conducting malicious SSH password authentication attacks.

Source is downloaded from [this link](https://www.dragonresearchgroup.org/insight/sshpwauth.txt).

The last time downloaded was found to be dated: Fri Jun 12 12:04:25 UTC 2015.

The ipset `dragon_sshpauth` has **1589** entries, **1653** unique IPs.

The following table shows the overlaps of `dragon_sshpauth` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `dragon_sshpauth`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `dragon_sshpauth`.
- ` this % ` is the percentage **of this ipset (`dragon_sshpauth`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[alienvault_reputation](#alienvault_reputation)|189179|189179|864|0.4%|52.2%|
[firehol_level3](#firehol_level3)|109554|9627189|858|0.0%|51.9%|
[openbl_60d](#openbl_60d)|6959|6959|779|11.1%|47.1%|
[openbl_30d](#openbl_30d)|2789|2789|697|24.9%|42.1%|
[bruteforceblocker](#bruteforceblocker)|1696|1696|637|37.5%|38.5%|
[firehol_level2](#firehol_level2)|21534|33114|633|1.9%|38.2%|
[blocklist_de](#blocklist_de)|27919|27919|632|2.2%|38.2%|
[et_compromised](#et_compromised)|1704|1704|629|36.9%|38.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2474|2474|629|25.4%|38.0%|
[shunlist](#shunlist)|1201|1201|380|31.6%|22.9%|
[openbl_7d](#openbl_7d)|637|637|348|54.6%|21.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|125|0.0%|7.5%|
[firehol_level1](#firehol_level1)|5070|688775051|107|0.0%|6.4%|
[et_block](#et_block)|1000|18343756|100|0.0%|6.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|99|0.0%|5.9%|
[openbl_1d](#openbl_1d)|131|131|84|64.1%|5.0%|
[dshield](#dshield)|20|5120|80|1.5%|4.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|71|0.0%|4.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|32|0.0%|1.9%|
[blocklist_de_strongips](#blocklist_de_strongips)|169|169|20|11.8%|1.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|5|0.0%|0.3%|
[stopforumspam_30d](#stopforumspam_30d)|94236|94236|4|0.0%|0.2%|
[dragon_http](#dragon_http)|1021|268288|4|0.0%|0.2%|
[voipbl](#voipbl)|10586|10998|1|0.0%|0.0%|
[sslbl](#sslbl)|370|370|1|0.2%|0.0%|
[sorbs_spam](#sorbs_spam)|64701|65536|1|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|1|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|1|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|1|0.0%|0.0%|
[ciarmy](#ciarmy)|421|421|1|0.2%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|18003|18003|1|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|3043|3043|1|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|1500|1500|1|0.0%|0.0%|

## dragon_vncprobe

[Dragon Search Group](http://www.dragonresearchgroup.org/) IP address that has been seen attempting to remotely connect to a host running the VNC application service, in the last 7 days. This report lists hosts that are highly suspicious and are likely conducting malicious VNC probes or VNC brute force attacks.

Source is downloaded from [this link](https://www.dragonresearchgroup.org/insight/vncprobe.txt).

The last time downloaded was found to be dated: Fri Jun 12 12:04:01 UTC 2015.

The ipset `dragon_vncprobe` has **89** entries, **89** unique IPs.

The following table shows the overlaps of `dragon_vncprobe` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `dragon_vncprobe`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `dragon_vncprobe`.
- ` this % ` is the percentage **of this ipset (`dragon_vncprobe`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[alienvault_reputation](#alienvault_reputation)|189179|189179|29|0.0%|32.5%|
[dragon_http](#dragon_http)|1021|268288|24|0.0%|26.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|13|0.0%|14.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|8|0.0%|8.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|5|0.0%|5.6%|
[firehol_level2](#firehol_level2)|21534|33114|5|0.0%|5.6%|
[blocklist_de](#blocklist_de)|27919|27919|5|0.0%|5.6%|
[firehol_level3](#firehol_level3)|109554|9627189|4|0.0%|4.4%|
[et_block](#et_block)|1000|18343756|4|0.0%|4.4%|
[shunlist](#shunlist)|1201|1201|2|0.1%|2.2%|
[firehol_level1](#firehol_level1)|5070|688775051|2|0.0%|2.2%|
[blocklist_de_ssh](#blocklist_de_ssh)|2474|2474|2|0.0%|2.2%|
[blocklist_de_mail](#blocklist_de_mail)|18003|18003|2|0.0%|2.2%|
[voipbl](#voipbl)|10586|10998|1|0.0%|1.1%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|1|0.0%|1.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|1.1%|
[dshield](#dshield)|20|5120|1|0.0%|1.1%|
[ciarmy](#ciarmy)|421|421|1|0.2%|1.1%|
[blocklist_de_imap](#blocklist_de_imap)|3043|3043|1|0.0%|1.1%|
[blocklist_de_apache](#blocklist_de_apache)|13988|13988|1|0.0%|1.1%|

## dshield

[DShield.org](https://dshield.org/) top 20 attacking class C (/24) subnets over the last three days - **excellent list**

Source is downloaded from [this link](http://feeds.dshield.org/block.txt).

The last time downloaded was found to be dated: Fri Jun 12 08:27:00 UTC 2015.

The ipset `dshield` has **20** entries, **5120** unique IPs.

The following table shows the overlaps of `dshield` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `dshield`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `dshield`.
- ` this % ` is the percentage **of this ipset (`dshield`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level1](#firehol_level1)|5070|688775051|5120|0.0%|100.0%|
[alienvault_reputation](#alienvault_reputation)|189179|189179|5120|2.7%|100.0%|
[et_block](#et_block)|1000|18343756|1536|0.0%|30.0%|
[dragon_http](#dragon_http)|1021|268288|768|0.2%|15.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|256|0.0%|5.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|256|0.0%|5.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|256|0.0%|5.0%|
[firehol_level3](#firehol_level3)|109554|9627189|123|0.0%|2.4%|
[openbl_60d](#openbl_60d)|6959|6959|84|1.2%|1.6%|
[shunlist](#shunlist)|1201|1201|83|6.9%|1.6%|
[firehol_level2](#firehol_level2)|21534|33114|83|0.2%|1.6%|
[blocklist_de](#blocklist_de)|27919|27919|82|0.2%|1.6%|
[openbl_30d](#openbl_30d)|2789|2789|80|2.8%|1.5%|
[dragon_sshpauth](#dragon_sshpauth)|1589|1653|80|4.8%|1.5%|
[blocklist_de_ssh](#blocklist_de_ssh)|2474|2474|73|2.9%|1.4%|
[et_compromised](#et_compromised)|1704|1704|29|1.7%|0.5%|
[bruteforceblocker](#bruteforceblocker)|1696|1696|25|1.4%|0.4%|
[openbl_7d](#openbl_7d)|637|637|21|3.2%|0.4%|
[stopforumspam_30d](#stopforumspam_30d)|94236|94236|20|0.0%|0.3%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|15|0.0%|0.2%|
[blocklist_de_strongips](#blocklist_de_strongips)|169|169|12|7.1%|0.2%|
[stopforumspam_1d](#stopforumspam_1d)|6629|6629|9|0.1%|0.1%|
[blocklist_de_bots](#blocklist_de_bots)|3014|3014|8|0.2%|0.1%|
[openbl_1d](#openbl_1d)|131|131|5|3.8%|0.0%|
[ciarmy](#ciarmy)|421|421|5|1.1%|0.0%|
[firehol_anonymous](#firehol_anonymous)|19277|83325|2|0.0%|0.0%|
[et_tor](#et_tor)|6500|6500|2|0.0%|0.0%|
[dm_tor](#dm_tor)|6521|6521|2|0.0%|0.0%|
[bm_tor](#bm_tor)|6496|6496|2|0.0%|0.0%|
[tor_exits](#tor_exits)|1106|1106|1|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9136|9136|1|0.0%|0.0%|
[php_commenters](#php_commenters)|458|458|1|0.2%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|1|0.1%|0.0%|
[firehol_proxies](#firehol_proxies)|12718|12994|1|0.0%|0.0%|
[dragon_vncprobe](#dragon_vncprobe)|89|89|1|1.1%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13988|13988|1|0.0%|0.0%|

## et_block

[EmergingThreats.net](http://www.emergingthreats.net/) default blacklist (at the time of writing includes spamhaus DROP, dshield and abuse.ch trackers, which are available separately too - prefer to use the direct ipsets instead of this, they seem to lag a bit in updates)

Source is downloaded from [this link](http://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt).

The last time downloaded was found to be dated: Thu Jun 11 04:30:01 UTC 2015.

The ipset `et_block` has **1000** entries, **18343756** unique IPs.

The following table shows the overlaps of `et_block` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `et_block`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `et_block`.
- ` this % ` is the percentage **of this ipset (`et_block`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level1](#firehol_level1)|5070|688775051|18340092|2.6%|99.9%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|18338560|99.9%|99.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|8532776|2.4%|46.5%|
[firehol_level3](#firehol_level3)|109554|9627189|6933360|72.0%|37.7%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|6932480|75.5%|37.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|2272787|0.2%|12.3%|
[fullbogons](#fullbogons)|3788|670093640|151552|0.0%|0.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|130650|0.0%|0.7%|
[alienvault_reputation](#alienvault_reputation)|189179|189179|3752|1.9%|0.0%|
[dshield](#dshield)|20|5120|1536|30.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1041|0.3%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|94236|94236|1026|1.0%|0.0%|
[dragon_http](#dragon_http)|1021|268288|1024|0.3%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|517|0.1%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9136|9136|297|3.2%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|283|0.9%|0.0%|
[firehol_level2](#firehol_level2)|21534|33114|261|0.7%|0.0%|
[openbl_60d](#openbl_60d)|6959|6959|244|3.5%|0.0%|
[zeus](#zeus)|230|230|229|99.5%|0.0%|
[zeus_badips](#zeus_badips)|202|202|202|100.0%|0.0%|
[blocklist_de](#blocklist_de)|27919|27919|195|0.6%|0.0%|
[openbl_30d](#openbl_30d)|2789|2789|125|4.4%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2474|2474|107|4.3%|0.0%|
[shunlist](#shunlist)|1201|1201|102|8.4%|0.0%|
[dragon_sshpauth](#dragon_sshpauth)|1589|1653|100|6.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6629|6629|93|1.4%|0.0%|
[et_compromised](#et_compromised)|1704|1704|65|3.8%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1696|1696|61|3.5%|0.0%|
[openbl_7d](#openbl_7d)|637|637|57|8.9%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3014|3014|56|1.8%|0.0%|
[sslbl](#sslbl)|370|370|39|10.5%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|30|2.3%|0.0%|
[php_commenters](#php_commenters)|458|458|29|6.3%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|18003|18003|24|0.1%|0.0%|
[nixspam](#nixspam)|21496|21496|22|0.1%|0.0%|
[sorbs_spam](#sorbs_spam)|64701|65536|20|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|20|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|20|0.0%|0.0%|
[voipbl](#voipbl)|10586|10998|18|0.1%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|3043|3043|17|0.5%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|169|169|14|8.2%|0.0%|
[firehol_anonymous](#firehol_anonymous)|19277|83325|8|0.0%|0.0%|
[openbl_1d](#openbl_1d)|131|131|7|5.3%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13988|13988|7|0.0%|0.0%|
[php_dictionary](#php_dictionary)|777|777|6|0.7%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|6|0.4%|0.0%|
[php_spammers](#php_spammers)|777|777|5|0.6%|0.0%|
[malc0de](#malc0de)|276|276|5|1.8%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|5|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2599|2599|5|0.1%|0.0%|
[nt_malware_http](#nt_malware_http)|69|69|4|5.7%|0.0%|
[firehol_proxies](#firehol_proxies)|12718|12994|4|0.0%|0.0%|
[et_tor](#et_tor)|6500|6500|4|0.0%|0.0%|
[dragon_vncprobe](#dragon_vncprobe)|89|89|4|4.4%|0.0%|
[dm_tor](#dm_tor)|6521|6521|4|0.0%|0.0%|
[bm_tor](#bm_tor)|6496|6496|4|0.0%|0.0%|
[nt_malware_irc](#nt_malware_irc)|43|43|3|6.9%|0.0%|
[iw_spamlist](#iw_spamlist)|3418|3418|3|0.0%|0.0%|
[tor_exits](#tor_exits)|1106|1106|2|0.1%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|2|0.3%|0.0%|
[virbl](#virbl)|23|23|1|4.3%|0.0%|
[proxz](#proxz)|1367|1367|1|0.0%|0.0%|
[php_harvesters](#php_harvesters)|408|408|1|0.2%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|1|0.1%|0.0%|
[et_botcc](#et_botcc)|505|505|1|0.1%|0.0%|
[ciarmy](#ciarmy)|421|421|1|0.2%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|1500|1500|1|0.0%|0.0%|

## et_botcc

[EmergingThreats.net Command and Control IPs](http://doc.emergingthreats.net/bin/view/Main/BotCC) These IPs are updates every 24 hours and should be considered VERY highly reliable indications that a host is communicating with a known and active Bot or Malware command and control server - (although they say this includes abuse.ch trackers, it does not - most probably it is the shadowserver.org C&C list)

Source is downloaded from [this link](http://rules.emergingthreats.net/fwrules/emerging-PIX-CC.rules).

The last time downloaded was found to be dated: Thu Jun 11 04:30:01 UTC 2015.

The ipset `et_botcc` has **505** entries, **505** unique IPs.

The following table shows the overlaps of `et_botcc` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `et_botcc`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `et_botcc`.
- ` this % ` is the percentage **of this ipset (`et_botcc`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|76|0.0%|15.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|39|0.0%|7.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|22|0.0%|4.3%|
[alienvault_reputation](#alienvault_reputation)|189179|189179|4|0.0%|0.7%|
[firehol_level3](#firehol_level3)|109554|9627189|3|0.0%|0.5%|
[dragon_http](#dragon_http)|1021|268288|3|0.0%|0.5%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|1|0.0%|0.1%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|1|0.0%|0.1%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|1|0.0%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.1%|
[firehol_level1](#firehol_level1)|5070|688775051|1|0.0%|0.1%|
[et_block](#et_block)|1000|18343756|1|0.0%|0.1%|
[blocklist_de_sip](#blocklist_de_sip)|81|81|1|1.2%|0.1%|

## et_compromised

[EmergingThreats.net compromised hosts](http://doc.emergingthreats.net/bin/view/Main/CompromisedHost) - (this seems to be based on bruteforceblocker)

Source is downloaded from [this link](http://rules.emergingthreats.net/blockrules/compromised-ips.txt).

The last time downloaded was found to be dated: Thu Jun 11 04:30:07 UTC 2015.

The ipset `et_compromised` has **1704** entries, **1704** unique IPs.

The following table shows the overlaps of `et_compromised` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `et_compromised`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `et_compromised`.
- ` this % ` is the percentage **of this ipset (`et_compromised`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level3](#firehol_level3)|109554|9627189|1671|0.0%|98.0%|
[bruteforceblocker](#bruteforceblocker)|1696|1696|1652|97.4%|96.9%|
[alienvault_reputation](#alienvault_reputation)|189179|189179|1086|0.5%|63.7%|
[openbl_60d](#openbl_60d)|6959|6959|977|14.0%|57.3%|
[openbl_30d](#openbl_30d)|2789|2789|907|32.5%|53.2%|
[dragon_sshpauth](#dragon_sshpauth)|1589|1653|629|38.0%|36.9%|
[firehol_level2](#firehol_level2)|21534|33114|533|1.6%|31.2%|
[blocklist_de](#blocklist_de)|27919|27919|532|1.9%|31.2%|
[blocklist_de_ssh](#blocklist_de_ssh)|2474|2474|526|21.2%|30.8%|
[shunlist](#shunlist)|1201|1201|343|28.5%|20.1%|
[openbl_7d](#openbl_7d)|637|637|305|47.8%|17.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|157|0.0%|9.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|89|0.0%|5.2%|
[firehol_level1](#firehol_level1)|5070|688775051|71|0.0%|4.1%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|65|0.0%|3.8%|
[et_block](#et_block)|1000|18343756|65|0.0%|3.8%|
[openbl_1d](#openbl_1d)|131|131|54|41.2%|3.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|54|0.0%|3.1%|
[dshield](#dshield)|20|5120|29|0.5%|1.7%|
[dragon_http](#dragon_http)|1021|268288|13|0.0%|0.7%|
[stopforumspam_30d](#stopforumspam_30d)|94236|94236|10|0.0%|0.5%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|5|0.0%|0.2%|
[blocklist_de_mail](#blocklist_de_mail)|18003|18003|4|0.0%|0.2%|
[blocklist_de_imap](#blocklist_de_imap)|3043|3043|4|0.1%|0.2%|
[voipbl](#voipbl)|10586|10998|3|0.0%|0.1%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|3|0.0%|0.1%|
[sorbs_spam](#sorbs_spam)|64701|65536|3|0.0%|0.1%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|3|0.0%|0.1%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|3|0.0%|0.1%|
[firehol_proxies](#firehol_proxies)|12718|12994|3|0.0%|0.1%|
[firehol_anonymous](#firehol_anonymous)|19277|83325|3|0.0%|0.1%|
[ciarmy](#ciarmy)|421|421|3|0.7%|0.1%|
[proxz](#proxz)|1367|1367|2|0.1%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|2|0.0%|0.1%|
[xroxy](#xroxy)|2175|2175|1|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6629|6629|1|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7996|7996|1|0.0%|0.0%|
[proxyrss](#proxyrss)|1455|1455|1|0.0%|0.0%|
[php_spammers](#php_spammers)|777|777|1|0.1%|0.0%|
[php_commenters](#php_commenters)|458|458|1|0.2%|0.0%|
[nixspam](#nixspam)|21496|21496|1|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|169|169|1|0.5%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|1500|1500|1|0.0%|0.0%|

## et_tor

[EmergingThreats.net](http://www.emergingthreats.net/) [list](http://doc.emergingthreats.net/bin/view/Main/TorRules) of TOR network IPs

Source is downloaded from [this link](http://rules.emergingthreats.net/blockrules/emerging-tor.rules).

The last time downloaded was found to be dated: Thu Jun 11 04:30:09 UTC 2015.

The ipset `et_tor` has **6500** entries, **6500** unique IPs.

The following table shows the overlaps of `et_tor` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `et_tor`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `et_tor`.
- ` this % ` is the percentage **of this ipset (`et_tor`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_anonymous](#firehol_anonymous)|19277|83325|5778|6.9%|88.8%|
[bm_tor](#bm_tor)|6496|6496|5736|88.3%|88.2%|
[dm_tor](#dm_tor)|6521|6521|5734|87.9%|88.2%|
[firehol_level3](#firehol_level3)|109554|9627189|1123|0.0%|17.2%|
[snort_ipfilter](#snort_ipfilter)|9136|9136|1088|11.9%|16.7%|
[tor_exits](#tor_exits)|1106|1106|968|87.5%|14.8%|
[stopforumspam_30d](#stopforumspam_30d)|94236|94236|662|0.7%|10.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|636|0.0%|9.7%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|547|1.8%|8.4%|
[firehol_level2](#firehol_level2)|21534|33114|329|0.9%|5.0%|
[stopforumspam_1d](#stopforumspam_1d)|6629|6629|322|4.8%|4.9%|
[firehol_proxies](#firehol_proxies)|12718|12994|238|1.8%|3.6%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|233|44.4%|3.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|182|0.0%|2.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|168|0.0%|2.5%|
[php_commenters](#php_commenters)|458|458|54|11.7%|0.8%|
[alienvault_reputation](#alienvault_reputation)|189179|189179|42|0.0%|0.6%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|22|0.0%|0.3%|
[openbl_60d](#openbl_60d)|6959|6959|20|0.2%|0.3%|
[dragon_http](#dragon_http)|1021|268288|16|0.0%|0.2%|
[blocklist_de_apache](#blocklist_de_apache)|13988|13988|13|0.0%|0.2%|
[blocklist_de](#blocklist_de)|27919|27919|13|0.0%|0.2%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2599|2599|10|0.3%|0.1%|
[php_harvesters](#php_harvesters)|408|408|7|1.7%|0.1%|
[nixspam](#nixspam)|21496|21496|6|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7996|7996|5|0.0%|0.0%|
[php_spammers](#php_spammers)|777|777|5|0.6%|0.0%|
[firehol_level1](#firehol_level1)|5070|688775051|5|0.0%|0.0%|
[sorbs_spam](#sorbs_spam)|64701|65536|4|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|4|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|4|0.0%|0.0%|
[php_dictionary](#php_dictionary)|777|777|4|0.5%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|4|0.0%|0.0%|
[et_block](#et_block)|1000|18343756|4|0.0%|0.0%|
[voipbl](#voipbl)|10586|10998|3|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|3|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|18003|18003|3|0.0%|0.0%|
[xroxy](#xroxy)|2175|2175|2|0.0%|0.0%|
[dshield](#dshield)|20|5120|2|0.0%|0.0%|
[shunlist](#shunlist)|1201|1201|1|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2876|2876|1|0.0%|0.0%|

## feodo

[Abuse.ch Feodo tracker](https://feodotracker.abuse.ch) trojan includes IPs which are being used by Feodo (also known as Cridex or Bugat) which commits ebanking fraud - **excellent list**

Source is downloaded from [this link](https://feodotracker.abuse.ch/blocklist/?download=ipblocklist).

The last time downloaded was found to be dated: Fri Jun 12 12:20:39 UTC 2015.

The ipset `feodo` has **0** entries, **0** unique IPs.

The following table shows the overlaps of `feodo` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `feodo`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `feodo`.
- ` this % ` is the percentage **of this ipset (`feodo`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|

## firehol_anonymous

**FireHOL Anonymous** - Known anonymizing IPs. (includes: firehol_proxies anonymous bm_tor dm_tor tor_exits)

Source is downloaded from [this link]().

The last time downloaded was found to be dated: Sun Jun  7 22:20:34 UTC 2015.

The ipset `firehol_anonymous` has **19277** entries, **83325** unique IPs.

The following table shows the overlaps of `firehol_anonymous` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `firehol_anonymous`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `firehol_anonymous`.
- ` this % ` is the percentage **of this ipset (`firehol_anonymous`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_proxies](#firehol_proxies)|12718|12994|12994|100.0%|15.5%|
[ri_web_proxies](#ri_web_proxies)|7996|7996|7996|100.0%|9.5%|
[firehol_level3](#firehol_level3)|109554|9627189|6861|0.0%|8.2%|
[dm_tor](#dm_tor)|6521|6521|6521|100.0%|7.8%|
[bm_tor](#bm_tor)|6496|6496|6496|100.0%|7.7%|
[stopforumspam_30d](#stopforumspam_30d)|94236|94236|6314|6.7%|7.5%|
[et_tor](#et_tor)|6500|6500|5778|88.8%|6.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|3445|0.0%|4.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|2900|0.0%|3.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|2877|0.0%|3.4%|
[ri_connect_proxies](#ri_connect_proxies)|2876|2876|2876|100.0%|3.4%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|2730|9.4%|3.2%|
[xroxy](#xroxy)|2175|2175|2175|100.0%|2.6%|
[proxyrss](#proxyrss)|1455|1455|1455|100.0%|1.7%|
[proxz](#proxz)|1367|1367|1367|100.0%|1.6%|
[firehol_level2](#firehol_level2)|21534|33114|1322|3.9%|1.5%|
[snort_ipfilter](#snort_ipfilter)|9136|9136|1217|13.3%|1.4%|
[tor_exits](#tor_exits)|1106|1106|1106|100.0%|1.3%|
[stopforumspam_1d](#stopforumspam_1d)|6629|6629|953|14.3%|1.1%|
[blocklist_de](#blocklist_de)|27919|27919|667|2.3%|0.8%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|663|100.0%|0.7%|
[blocklist_de_bots](#blocklist_de_bots)|3014|3014|525|17.4%|0.6%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|524|100.0%|0.6%|
[sorbs_spam](#sorbs_spam)|64701|65536|201|0.3%|0.2%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|201|0.3%|0.2%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|201|0.3%|0.2%|
[nixspam](#nixspam)|21496|21496|142|0.6%|0.1%|
[blocklist_de_mail](#blocklist_de_mail)|18003|18003|121|0.6%|0.1%|
[php_dictionary](#php_dictionary)|777|777|101|12.9%|0.1%|
[php_commenters](#php_commenters)|458|458|89|19.4%|0.1%|
[php_spammers](#php_spammers)|777|777|84|10.8%|0.1%|
[voipbl](#voipbl)|10586|10998|79|0.7%|0.0%|
[alienvault_reputation](#alienvault_reputation)|189179|189179|58|0.0%|0.0%|
[dragon_http](#dragon_http)|1021|268288|47|0.0%|0.0%|
[sorbs_web](#sorbs_web)|643|644|31|4.8%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|29|0.0%|0.0%|
[openbl_60d](#openbl_60d)|6959|6959|23|0.3%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13988|13988|19|0.1%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|15|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2599|2599|15|0.5%|0.0%|
[php_harvesters](#php_harvesters)|408|408|12|2.9%|0.0%|
[firehol_level1](#firehol_level1)|5070|688775051|9|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|169|169|9|5.3%|0.0%|
[et_block](#et_block)|1000|18343756|8|0.0%|0.0%|
[iw_spamlist](#iw_spamlist)|3418|3418|7|0.2%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|7|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|6|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|3|0.2%|0.0%|
[et_compromised](#et_compromised)|1704|1704|3|0.1%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1696|1696|3|0.1%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|1500|1500|3|0.2%|0.0%|
[dshield](#dshield)|20|5120|2|0.0%|0.0%|
[sslbl](#sslbl)|370|370|1|0.2%|0.0%|
[shunlist](#shunlist)|1201|1201|1|0.0%|0.0%|
[openbl_30d](#openbl_30d)|2789|2789|1|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2474|2474|1|0.0%|0.0%|

## firehol_level1

**FireHOL Level 1** - Maximum protection without false positives. (includes: fullbogons dshield feodo palevo sslbl zeus spamhaus_drop spamhaus_edrop)

Source is downloaded from [this link]().

The last time downloaded was found to be dated: Sun Jun  7 22:15:43 UTC 2015.

The ipset `firehol_level1` has **5070** entries, **688775051** unique IPs.

The following table shows the overlaps of `firehol_level1` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `firehol_level1`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `firehol_level1`.
- ` this % ` is the percentage **of this ipset (`firehol_level1`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[fullbogons](#fullbogons)|3788|670093640|670093640|100.0%|97.2%|
[bogons](#bogons)|13|592708608|592708608|100.0%|86.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|18340608|100.0%|2.6%|
[et_block](#et_block)|1000|18343756|18340092|99.9%|2.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|8867711|2.5%|1.2%|
[firehol_level3](#firehol_level3)|109554|9627189|7500137|77.9%|1.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|7498240|81.6%|1.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|4637594|3.3%|0.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|2570559|0.3%|0.3%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|487424|100.0%|0.0%|
[alienvault_reputation](#alienvault_reputation)|189179|189179|6387|3.3%|0.0%|
[dshield](#dshield)|20|5120|5120|100.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1930|0.5%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|94236|94236|1102|1.1%|0.0%|
[dragon_http](#dragon_http)|1021|268288|1025|0.3%|0.0%|
[sslbl](#sslbl)|370|370|370|100.0%|0.0%|
[voipbl](#voipbl)|10586|10998|333|3.0%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|291|1.0%|0.0%|
[firehol_level2](#firehol_level2)|21534|33114|276|0.8%|0.0%|
[openbl_60d](#openbl_60d)|6959|6959|253|3.6%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9136|9136|237|2.5%|0.0%|
[zeus](#zeus)|230|230|230|100.0%|0.0%|
[blocklist_de](#blocklist_de)|27919|27919|207|0.7%|0.0%|
[zeus_badips](#zeus_badips)|202|202|202|100.0%|0.0%|
[shunlist](#shunlist)|1201|1201|160|13.3%|0.0%|
[openbl_30d](#openbl_30d)|2789|2789|135|4.8%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2474|2474|117|4.7%|0.0%|
[dragon_sshpauth](#dragon_sshpauth)|1589|1653|107|6.4%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6629|6629|98|1.4%|0.0%|
[et_compromised](#et_compromised)|1704|1704|71|4.1%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1696|1696|67|3.9%|0.0%|
[openbl_7d](#openbl_7d)|637|637|60|9.4%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3014|3014|57|1.8%|0.0%|
[php_commenters](#php_commenters)|458|458|39|8.5%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|39|3.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|39|2.6%|0.0%|
[sorbs_spam](#sorbs_spam)|64701|65536|25|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|25|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|25|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|18003|18003|25|0.1%|0.0%|
[nixspam](#nixspam)|21496|21496|23|0.1%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|169|169|20|11.8%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|18|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|3043|3043|17|0.5%|0.0%|
[openbl_1d](#openbl_1d)|131|131|11|8.3%|0.0%|
[firehol_anonymous](#firehol_anonymous)|19277|83325|9|0.0%|0.0%|
[nt_malware_http](#nt_malware_http)|69|69|8|11.5%|0.0%|
[iw_spamlist](#iw_spamlist)|3418|3418|7|0.2%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13988|13988|7|0.0%|0.0%|
[php_dictionary](#php_dictionary)|777|777|6|0.7%|0.0%|
[ciarmy](#ciarmy)|421|421|6|1.4%|0.0%|
[php_spammers](#php_spammers)|777|777|5|0.6%|0.0%|
[malc0de](#malc0de)|276|276|5|1.8%|0.0%|
[firehol_proxies](#firehol_proxies)|12718|12994|5|0.0%|0.0%|
[et_tor](#et_tor)|6500|6500|5|0.0%|0.0%|
[dm_tor](#dm_tor)|6521|6521|5|0.0%|0.0%|
[bm_tor](#bm_tor)|6496|6496|5|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2599|2599|5|0.1%|0.0%|
[tor_exits](#tor_exits)|1106|1106|3|0.2%|0.0%|
[php_harvesters](#php_harvesters)|408|408|3|0.7%|0.0%|
[nt_malware_irc](#nt_malware_irc)|43|43|3|6.9%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|2|0.3%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|2|0.3%|0.0%|
[dragon_vncprobe](#dragon_vncprobe)|89|89|2|2.2%|0.0%|
[virbl](#virbl)|23|23|1|4.3%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7996|7996|1|0.0%|0.0%|
[et_botcc](#et_botcc)|505|505|1|0.1%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|1500|1500|1|0.0%|0.0%|

## firehol_level2

**FireHOL Level 2** - Maximum protection from attacks took place in the last 48 hours. (includes: openbl_1d blocklist_de stopforumspam_1d)

Source is downloaded from [this link]().

The last time downloaded was found to be dated: Sun Jun  7 22:20:34 UTC 2015.

The ipset `firehol_level2` has **21534** entries, **33114** unique IPs.

The following table shows the overlaps of `firehol_level2` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `firehol_level2`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `firehol_level2`.
- ` this % ` is the percentage **of this ipset (`firehol_level2`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|27919|27919|27919|100.0%|84.3%|
[blocklist_de_mail](#blocklist_de_mail)|18003|18003|17925|99.5%|54.1%|
[blocklist_de_apache](#blocklist_de_apache)|13988|13988|13988|100.0%|42.2%|
[firehol_level3](#firehol_level3)|109554|9627189|9089|0.0%|27.4%|
[stopforumspam_30d](#stopforumspam_30d)|94236|94236|8029|8.5%|24.2%|
[stopforumspam_1d](#stopforumspam_1d)|6629|6629|6629|100.0%|20.0%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|6322|21.7%|19.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|4011|0.0%|12.1%|
[blocklist_de_imap](#blocklist_de_imap)|3043|3043|3016|99.1%|9.1%|
[blocklist_de_bots](#blocklist_de_bots)|3014|3014|3014|100.0%|9.1%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2599|2599|2599|100.0%|7.8%|
[blocklist_de_ssh](#blocklist_de_ssh)|2474|2474|2473|99.9%|7.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|1673|0.0%|5.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|1593|0.0%|4.8%|
[blocklist_de_ftp](#blocklist_de_ftp)|1500|1500|1491|99.4%|4.5%|
[firehol_anonymous](#firehol_anonymous)|19277|83325|1322|1.5%|3.9%|
[firehol_proxies](#firehol_proxies)|12718|12994|1156|8.8%|3.4%|
[alienvault_reputation](#alienvault_reputation)|189179|189179|1148|0.6%|3.4%|
[sorbs_spam](#sorbs_spam)|64701|65536|832|1.2%|2.5%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|824|1.2%|2.4%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|824|1.2%|2.4%|
[openbl_60d](#openbl_60d)|6959|6959|801|11.5%|2.4%|
[ri_web_proxies](#ri_web_proxies)|7996|7996|667|8.3%|2.0%|
[openbl_30d](#openbl_30d)|2789|2789|659|23.6%|1.9%|
[dragon_sshpauth](#dragon_sshpauth)|1589|1653|633|38.2%|1.9%|
[nixspam](#nixspam)|21496|21496|627|2.9%|1.8%|
[bruteforceblocker](#bruteforceblocker)|1696|1696|555|32.7%|1.6%|
[et_compromised](#et_compromised)|1704|1704|533|31.2%|1.6%|
[snort_ipfilter](#snort_ipfilter)|9136|9136|526|5.7%|1.5%|
[openbl_7d](#openbl_7d)|637|637|397|62.3%|1.1%|
[proxyrss](#proxyrss)|1455|1455|375|25.7%|1.1%|
[shunlist](#shunlist)|1201|1201|349|29.0%|1.0%|
[tor_exits](#tor_exits)|1106|1106|337|30.4%|1.0%|
[et_tor](#et_tor)|6500|6500|329|5.0%|0.9%|
[dm_tor](#dm_tor)|6521|6521|325|4.9%|0.9%|
[bm_tor](#bm_tor)|6496|6496|325|5.0%|0.9%|
[xroxy](#xroxy)|2175|2175|302|13.8%|0.9%|
[firehol_level1](#firehol_level1)|5070|688775051|276|0.0%|0.8%|
[proxz](#proxz)|1367|1367|265|19.3%|0.8%|
[et_block](#et_block)|1000|18343756|261|0.0%|0.7%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|244|0.0%|0.7%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|201|38.3%|0.6%|
[php_commenters](#php_commenters)|458|458|194|42.3%|0.5%|
[blocklist_de_strongips](#blocklist_de_strongips)|169|169|169|100.0%|0.5%|
[ri_connect_proxies](#ri_connect_proxies)|2876|2876|154|5.3%|0.4%|
[openbl_1d](#openbl_1d)|131|131|131|100.0%|0.3%|
[iw_spamlist](#iw_spamlist)|3418|3418|122|3.5%|0.3%|
[php_dictionary](#php_dictionary)|777|777|121|15.5%|0.3%|
[php_spammers](#php_spammers)|777|777|120|15.4%|0.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|91|0.0%|0.2%|
[dshield](#dshield)|20|5120|83|1.6%|0.2%|
[sorbs_web](#sorbs_web)|643|644|70|10.8%|0.2%|
[blocklist_de_sip](#blocklist_de_sip)|81|81|62|76.5%|0.1%|
[dragon_http](#dragon_http)|1021|268288|60|0.0%|0.1%|
[php_harvesters](#php_harvesters)|408|408|54|13.2%|0.1%|
[voipbl](#voipbl)|10586|10998|43|0.3%|0.1%|
[ciarmy](#ciarmy)|421|421|37|8.7%|0.1%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|16|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|11|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|7|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|7|1.0%|0.0%|
[dragon_vncprobe](#dragon_vncprobe)|89|89|5|5.6%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|2|0.1%|0.0%|
[zeus_badips](#zeus_badips)|202|202|1|0.4%|0.0%|
[zeus](#zeus)|230|230|1|0.4%|0.0%|
[virbl](#virbl)|23|23|1|4.3%|0.0%|
[sorbs_socks](#sorbs_socks)|7|7|1|14.2%|0.0%|
[sorbs_misc](#sorbs_misc)|7|7|1|14.2%|0.0%|
[sorbs_http](#sorbs_http)|7|7|1|14.2%|0.0%|
[fullbogons](#fullbogons)|3788|670093640|1|0.0%|0.0%|

## firehol_level3

**FireHOL Level 3** - All the bad IPs in last 30 days. (includes: openbl_30d stopforumspam_30d virbl malc0de shunlist malwaredomainlist bruteforceblocker ciarmy cleanmx_viruses snort_ipfilter ib_bluetack_spyware ib_bluetack_hijacked ib_bluetack_webexploit php_commenters php_dictionary php_harvesters php_spammers iw_wormlist)

Source is downloaded from [this link]().

The last time downloaded was found to be dated: Sun Jun  7 22:20:34 UTC 2015.

The ipset `firehol_level3` has **109554** entries, **9627189** unique IPs.

The following table shows the overlaps of `firehol_level3` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `firehol_level3`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `firehol_level3`.
- ` this % ` is the percentage **of this ipset (`firehol_level3`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|9177856|100.0%|95.3%|
[firehol_level1](#firehol_level1)|5070|688775051|7500137|1.0%|77.9%|
[et_block](#et_block)|1000|18343756|6933360|37.7%|72.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|6933046|37.8%|72.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|2537278|0.7%|26.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|919981|0.1%|9.5%|
[fullbogons](#fullbogons)|3788|670093640|566692|0.0%|5.8%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|339173|100.0%|3.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|161605|0.1%|1.6%|
[stopforumspam_30d](#stopforumspam_30d)|94236|94236|94236|100.0%|0.9%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|29017|100.0%|0.3%|
[snort_ipfilter](#snort_ipfilter)|9136|9136|9136|100.0%|0.0%|
[firehol_level2](#firehol_level2)|21534|33114|9089|27.4%|0.0%|
[firehol_anonymous](#firehol_anonymous)|19277|83325|6861|8.2%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6629|6629|6629|100.0%|0.0%|
[firehol_proxies](#firehol_proxies)|12718|12994|5762|44.3%|0.0%|
[alienvault_reputation](#alienvault_reputation)|189179|189179|4838|2.5%|0.0%|
[blocklist_de](#blocklist_de)|27919|27919|3894|13.9%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7996|7996|3788|47.3%|0.0%|
[openbl_60d](#openbl_60d)|6959|6959|2916|41.9%|0.0%|
[openbl_30d](#openbl_30d)|2789|2789|2789|100.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3014|3014|2532|84.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1696|1696|1696|100.0%|0.0%|
[et_compromised](#et_compromised)|1704|1704|1671|98.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2876|2876|1603|55.7%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|1450|100.0%|0.0%|
[xroxy](#xroxy)|2175|2175|1299|59.7%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|1288|100.0%|0.0%|
[sorbs_spam](#sorbs_spam)|64701|65536|1235|1.8%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|1231|1.8%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|1231|1.8%|0.0%|
[shunlist](#shunlist)|1201|1201|1201|100.0%|0.0%|
[et_tor](#et_tor)|6500|6500|1123|17.2%|0.0%|
[bm_tor](#bm_tor)|6496|6496|1081|16.6%|0.0%|
[dm_tor](#dm_tor)|6521|6521|1079|16.5%|0.0%|
[tor_exits](#tor_exits)|1106|1106|1064|96.2%|0.0%|
[dragon_sshpauth](#dragon_sshpauth)|1589|1653|858|51.9%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2474|2474|828|33.4%|0.0%|
[proxz](#proxz)|1367|1367|818|59.8%|0.0%|
[php_spammers](#php_spammers)|777|777|777|100.0%|0.0%|
[php_dictionary](#php_dictionary)|777|777|777|100.0%|0.0%|
[proxyrss](#proxyrss)|1455|1455|706|48.5%|0.0%|
[openbl_7d](#openbl_7d)|637|637|637|100.0%|0.0%|
[dragon_http](#dragon_http)|1021|268288|562|0.2%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|511|511|511|100.0%|0.0%|
[php_commenters](#php_commenters)|458|458|458|100.0%|0.0%|
[nixspam](#nixspam)|21496|21496|432|2.0%|0.0%|
[ciarmy](#ciarmy)|421|421|421|100.0%|0.0%|
[php_harvesters](#php_harvesters)|408|408|408|100.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|18003|18003|377|2.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|347|66.2%|0.0%|
[malc0de](#malc0de)|276|276|276|100.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13988|13988|268|1.9%|0.0%|
[zeus](#zeus)|230|230|203|88.2%|0.0%|
[zeus_badips](#zeus_badips)|202|202|180|89.1%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|169|169|156|92.3%|0.0%|
[openbl_1d](#openbl_1d)|131|131|131|100.0%|0.0%|
[dshield](#dshield)|20|5120|123|2.4%|0.0%|
[sslbl](#sslbl)|370|370|89|24.0%|0.0%|
[iw_spamlist](#iw_spamlist)|3418|3418|83|2.4%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|82|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2599|2599|75|2.8%|0.0%|
[sorbs_web](#sorbs_web)|643|644|74|11.4%|0.0%|
[voipbl](#voipbl)|10586|10998|58|0.5%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|3043|3043|39|1.2%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|25|3.7%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|24|0.0%|0.0%|
[virbl](#virbl)|23|23|23|100.0%|0.0%|
[iw_wormlist](#iw_wormlist)|23|23|23|100.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|1500|1500|20|1.3%|0.0%|
[sorbs_socks](#sorbs_socks)|7|7|4|57.1%|0.0%|
[sorbs_misc](#sorbs_misc)|7|7|4|57.1%|0.0%|
[sorbs_http](#sorbs_http)|7|7|4|57.1%|0.0%|
[dragon_vncprobe](#dragon_vncprobe)|89|89|4|4.4%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|81|81|4|4.9%|0.0%|
[nt_malware_http](#nt_malware_http)|69|69|3|4.3%|0.0%|
[et_botcc](#et_botcc)|505|505|3|0.5%|0.0%|
[bogons](#bogons)|13|592708608|3|0.0%|0.0%|
[nt_malware_irc](#nt_malware_irc)|43|43|1|2.3%|0.0%|

## firehol_proxies

**FireHOL Proxies** - Known open proxies in the last 30 days. (includes: ib_bluetack_proxies maxmind_proxy_fraud proxyrss proxz ri_connect_proxies ri_web_proxies xroxy)

Source is downloaded from [this link]().

The last time downloaded was found to be dated: Sun Jun  7 22:20:34 UTC 2015.

The ipset `firehol_proxies` has **12718** entries, **12994** unique IPs.

The following table shows the overlaps of `firehol_proxies` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `firehol_proxies`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `firehol_proxies`.
- ` this % ` is the percentage **of this ipset (`firehol_proxies`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_anonymous](#firehol_anonymous)|19277|83325|12994|15.5%|100.0%|
[ri_web_proxies](#ri_web_proxies)|7996|7996|7996|100.0%|61.5%|
[firehol_level3](#firehol_level3)|109554|9627189|5762|0.0%|44.3%|
[stopforumspam_30d](#stopforumspam_30d)|94236|94236|5702|6.0%|43.8%|
[ri_connect_proxies](#ri_connect_proxies)|2876|2876|2876|100.0%|22.1%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|2366|8.1%|18.2%|
[xroxy](#xroxy)|2175|2175|2175|100.0%|16.7%|
[proxyrss](#proxyrss)|1455|1455|1455|100.0%|11.1%|
[proxz](#proxz)|1367|1367|1367|100.0%|10.5%|
[firehol_level2](#firehol_level2)|21534|33114|1156|3.4%|8.8%|
[stopforumspam_1d](#stopforumspam_1d)|6629|6629|800|12.0%|6.1%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|663|100.0%|5.1%|
[blocklist_de](#blocklist_de)|27919|27919|646|2.3%|4.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|529|0.0%|4.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|524|100.0%|4.0%|
[blocklist_de_bots](#blocklist_de_bots)|3014|3014|524|17.3%|4.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|393|0.0%|3.0%|
[snort_ipfilter](#snort_ipfilter)|9136|9136|327|3.5%|2.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|289|0.0%|2.2%|
[et_tor](#et_tor)|6500|6500|238|3.6%|1.8%|
[dm_tor](#dm_tor)|6521|6521|235|3.6%|1.8%|
[bm_tor](#bm_tor)|6496|6496|234|3.6%|1.8%|
[tor_exits](#tor_exits)|1106|1106|230|20.7%|1.7%|
[sorbs_spam](#sorbs_spam)|64701|65536|196|0.2%|1.5%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|196|0.3%|1.5%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|196|0.3%|1.5%|
[nixspam](#nixspam)|21496|21496|134|0.6%|1.0%|
[blocklist_de_mail](#blocklist_de_mail)|18003|18003|119|0.6%|0.9%|
[php_dictionary](#php_dictionary)|777|777|100|12.8%|0.7%|
[php_commenters](#php_commenters)|458|458|85|18.5%|0.6%|
[php_spammers](#php_spammers)|777|777|82|10.5%|0.6%|
[alienvault_reputation](#alienvault_reputation)|189179|189179|39|0.0%|0.3%|
[dragon_http](#dragon_http)|1021|268288|34|0.0%|0.2%|
[sorbs_web](#sorbs_web)|643|644|31|4.8%|0.2%|
[openbl_60d](#openbl_60d)|6959|6959|20|0.2%|0.1%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|15|0.0%|0.1%|
[php_harvesters](#php_harvesters)|408|408|12|2.9%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|11|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|169|169|9|5.3%|0.0%|
[iw_spamlist](#iw_spamlist)|3418|3418|7|0.2%|0.0%|
[firehol_level1](#firehol_level1)|5070|688775051|5|0.0%|0.0%|
[et_block](#et_block)|1000|18343756|4|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|3|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|3|0.2%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|0.0%|
[et_compromised](#et_compromised)|1704|1704|3|0.1%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1696|1696|3|0.1%|0.0%|
[voipbl](#voipbl)|10586|10998|2|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13988|13988|2|0.0%|0.0%|
[sslbl](#sslbl)|370|370|1|0.2%|0.0%|
[shunlist](#shunlist)|1201|1201|1|0.0%|0.0%|
[dshield](#dshield)|20|5120|1|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2474|2474|1|0.0%|0.0%|

## fullbogons

[Team-Cymru.org](http://www.team-cymru.org) IP space that has been allocated to an RIR, but not assigned by that RIR to an actual ISP or other end-user - **excellent list - use it only your internet interface**

Source is downloaded from [this link](http://www.team-cymru.org/Services/Bogons/fullbogons-ipv4.txt).

The last time downloaded was found to be dated: Fri Jun 12 09:35:09 UTC 2015.

The ipset `fullbogons` has **3788** entries, **670093640** unique IPs.

The following table shows the overlaps of `fullbogons` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `fullbogons`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `fullbogons`.
- ` this % ` is the percentage **of this ipset (`fullbogons`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level1](#firehol_level1)|5070|688775051|670093640|97.2%|100.0%|
[bogons](#bogons)|13|592708608|592708608|100.0%|88.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|4236143|3.0%|0.6%|
[firehol_level3](#firehol_level3)|109554|9627189|566692|5.8%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|565760|6.1%|0.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|264873|0.0%|0.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|252671|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|151552|0.8%|0.0%|
[et_block](#et_block)|1000|18343756|151552|0.8%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|890|0.2%|0.0%|
[voipbl](#voipbl)|10586|10998|319|2.9%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|33|2.2%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|13|0.0%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|9|0.6%|0.0%|
[nt_malware_http](#nt_malware_http)|69|69|4|5.7%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|94236|94236|3|0.0%|0.0%|
[iw_spamlist](#iw_spamlist)|3418|3418|3|0.0%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|2|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6629|6629|1|0.0%|0.0%|
[php_harvesters](#php_harvesters)|408|408|1|0.2%|0.0%|
[php_commenters](#php_commenters)|458|458|1|0.2%|0.0%|
[firehol_level2](#firehol_level2)|21534|33114|1|0.0%|0.0%|
[ciarmy](#ciarmy)|421|421|1|0.2%|0.0%|

## ib_bluetack_badpeers

[iBlocklist.com](https://www.iblocklist.com/) free version of [BlueTack.co.uk](http://www.bluetack.co.uk/) IPs that have been reported for bad deeds in p2p

Source is downloaded from [this link](http://list.iblocklist.com/?list=cwworuawihqvocglcoss&fileformat=p2p&archiveformat=gz).

The last time downloaded was found to be dated: Fri Jun 12 05:50:39 UTC 2015.

The ipset `ib_bluetack_badpeers` has **47940** entries, **47940** unique IPs.

The following table shows the overlaps of `ib_bluetack_badpeers` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ib_bluetack_badpeers`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ib_bluetack_badpeers`.
- ` this % ` is the percentage **of this ipset (`ib_bluetack_badpeers`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|1172|0.0%|2.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|394|0.0%|0.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|226|0.0%|0.4%|
[dragon_http](#dragon_http)|1021|268288|25|0.0%|0.0%|
[firehol_level3](#firehol_level3)|109554|9627189|24|0.0%|0.0%|
[firehol_level1](#firehol_level1)|5070|688775051|18|0.0%|0.0%|
[sorbs_spam](#sorbs_spam)|64701|65536|17|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|17|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|17|0.0%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|94236|94236|16|0.0%|0.0%|
[firehol_level2](#firehol_level2)|21534|33114|16|0.0%|0.0%|
[firehol_proxies](#firehol_proxies)|12718|12994|15|0.1%|0.0%|
[firehol_anonymous](#firehol_anonymous)|19277|83325|15|0.0%|0.0%|
[blocklist_de](#blocklist_de)|27919|27919|15|0.0%|0.0%|
[alienvault_reputation](#alienvault_reputation)|189179|189179|15|0.0%|0.0%|
[fullbogons](#fullbogons)|3788|670093640|13|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|11|1.6%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|18003|18003|10|0.0%|0.0%|
[nixspam](#nixspam)|21496|21496|9|0.0%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|7|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|5|0.0%|0.0%|
[et_block](#et_block)|1000|18343756|5|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|3043|3043|5|0.1%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7996|7996|4|0.0%|0.0%|
[xroxy](#xroxy)|2175|2175|3|0.1%|0.0%|
[php_dictionary](#php_dictionary)|777|777|3|0.3%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|3|0.0%|0.0%|
[voipbl](#voipbl)|10586|10998|2|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6629|6629|2|0.0%|0.0%|
[sorbs_web](#sorbs_web)|643|644|2|0.3%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9136|9136|2|0.0%|0.0%|
[php_harvesters](#php_harvesters)|408|408|2|0.4%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2599|2599|2|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13988|13988|2|0.0%|0.0%|
[proxz](#proxz)|1367|1367|1|0.0%|0.0%|
[php_spammers](#php_spammers)|777|777|1|0.1%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|1|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2474|2474|1|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|1500|1500|1|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3014|3014|1|0.0%|0.0%|

## ib_bluetack_hijacked

[iBlocklist.com](https://www.iblocklist.com/) free version of [BlueTack.co.uk](http://www.bluetack.co.uk/) hijacked IP-Blocks Hijacked IP space are IP blocks that are being used without permission

Source is downloaded from [this link](http://list.iblocklist.com/?list=usrcshglbiilevmyfhse&fileformat=p2p&archiveformat=gz).

The last time downloaded was found to be dated: Fri Jun 12 06:20:02 UTC 2015.

The ipset `ib_bluetack_hijacked` has **535** entries, **9177856** unique IPs.

The following table shows the overlaps of `ib_bluetack_hijacked` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ib_bluetack_hijacked`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ib_bluetack_hijacked`.
- ` this % ` is the percentage **of this ipset (`ib_bluetack_hijacked`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level3](#firehol_level3)|109554|9627189|9177856|95.3%|100.0%|
[firehol_level1](#firehol_level1)|5070|688775051|7498240|1.0%|81.6%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|6932480|37.7%|75.5%|
[et_block](#et_block)|1000|18343756|6932480|37.7%|75.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|2526625|0.7%|27.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|904796|0.1%|9.8%|
[fullbogons](#fullbogons)|3788|670093640|565760|0.0%|6.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|145472|0.1%|1.5%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1036|0.3%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|94236|94236|724|0.7%|0.0%|
[alienvault_reputation](#alienvault_reputation)|189179|189179|278|0.1%|0.0%|
[dragon_http](#dragon_http)|1021|268288|256|0.0%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|154|0.5%|0.0%|
[firehol_level2](#firehol_level2)|21534|33114|91|0.2%|0.0%|
[blocklist_de](#blocklist_de)|27919|27919|54|0.1%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6629|6629|45|0.6%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3014|3014|41|1.3%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|27|2.0%|0.0%|
[nixspam](#nixspam)|21496|21496|21|0.0%|0.0%|
[openbl_60d](#openbl_60d)|6959|6959|16|0.2%|0.0%|
[openbl_30d](#openbl_30d)|2789|2789|12|0.4%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9136|9136|11|0.1%|0.0%|
[zeus_badips](#zeus_badips)|202|202|10|4.9%|0.0%|
[zeus](#zeus)|230|230|10|4.3%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|7|0.4%|0.0%|
[firehol_anonymous](#firehol_anonymous)|19277|83325|7|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2474|2474|7|0.2%|0.0%|
[et_compromised](#et_compromised)|1704|1704|5|0.2%|0.0%|
[dragon_sshpauth](#dragon_sshpauth)|1589|1653|5|0.3%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1696|1696|5|0.2%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|18003|18003|5|0.0%|0.0%|
[php_dictionary](#php_dictionary)|777|777|4|0.5%|0.0%|
[openbl_7d](#openbl_7d)|637|637|4|0.6%|0.0%|
[et_tor](#et_tor)|6500|6500|4|0.0%|0.0%|
[dm_tor](#dm_tor)|6521|6521|4|0.0%|0.0%|
[bm_tor](#bm_tor)|6496|6496|4|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|3043|3043|4|0.1%|0.0%|
[php_spammers](#php_spammers)|777|777|3|0.3%|0.0%|
[nt_malware_http](#nt_malware_http)|69|69|3|4.3%|0.0%|
[firehol_proxies](#firehol_proxies)|12718|12994|3|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|169|169|3|1.7%|0.0%|
[tor_exits](#tor_exits)|1106|1106|2|0.1%|0.0%|
[shunlist](#shunlist)|1201|1201|2|0.1%|0.0%|
[openbl_1d](#openbl_1d)|131|131|2|1.5%|0.0%|
[iw_spamlist](#iw_spamlist)|3418|3418|2|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|2|0.3%|0.0%|
[voipbl](#voipbl)|10586|10998|1|0.0%|0.0%|
[virbl](#virbl)|23|23|1|4.3%|0.0%|
[sorbs_spam](#sorbs_spam)|64701|65536|1|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|1|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|1|0.0%|0.0%|
[php_harvesters](#php_harvesters)|408|408|1|0.2%|0.0%|
[php_commenters](#php_commenters)|458|458|1|0.2%|0.0%|
[nt_malware_irc](#nt_malware_irc)|43|43|1|2.3%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|1|0.1%|0.0%|
[et_botcc](#et_botcc)|505|505|1|0.1%|0.0%|
[dragon_vncprobe](#dragon_vncprobe)|89|89|1|1.1%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2599|2599|1|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13988|13988|1|0.0%|0.0%|

## ib_bluetack_level1

[iBlocklist.com](https://www.iblocklist.com/) free version of [BlueTack.co.uk](http://www.bluetack.co.uk/) Level 1 (for use in p2p): Companies or organizations who are clearly involved with trying to stop filesharing (e.g. Baytsp, MediaDefender, Mediasentry a.o.). Companies which anti-p2p activity has been seen from. Companies that produce or have a strong financial interest in copyrighted material (e.g. music, movie, software industries a.o.). Government ranges or companies that have a strong financial interest in doing work for governments. Legal industry ranges. IPs or ranges of ISPs from which anti-p2p activity has been observed. Basically this list will block all kinds of internet connections that most people would rather not have during their internet travels.

Source is downloaded from [this link](http://list.iblocklist.com/?list=ydxerpxkpcfqjaybcssw&fileformat=p2p&archiveformat=gz).

The last time downloaded was found to be dated: Fri Jun 12 09:40:43 UTC 2015.

The ipset `ib_bluetack_level1` has **218307** entries, **764993634** unique IPs.

The following table shows the overlaps of `ib_bluetack_level1` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ib_bluetack_level1`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ib_bluetack_level1`.
- ` this % ` is the percentage **of this ipset (`ib_bluetack_level1`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|16302420|4.6%|2.1%|
[firehol_level1](#firehol_level1)|5070|688775051|2570559|0.3%|0.3%|
[et_block](#et_block)|1000|18343756|2272787|12.3%|0.2%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|2272265|12.3%|0.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|1354507|0.9%|0.1%|
[firehol_level3](#firehol_level3)|109554|9627189|919981|9.5%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|904796|9.8%|0.1%|
[fullbogons](#fullbogons)|3788|670093640|264873|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|33155|6.8%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|13247|3.9%|0.0%|
[dragon_http](#dragon_http)|1021|268288|5989|2.2%|0.0%|
[alienvault_reputation](#alienvault_reputation)|189179|189179|4188|2.2%|0.0%|
[firehol_anonymous](#firehol_anonymous)|19277|83325|3445|4.1%|0.0%|
[firehol_level2](#firehol_level2)|21534|33114|1673|5.0%|0.0%|
[blocklist_de](#blocklist_de)|27919|27919|1577|5.6%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|94236|94236|1526|1.6%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|18003|18003|1407|7.8%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13988|13988|1320|9.4%|0.0%|
[sorbs_spam](#sorbs_spam)|64701|65536|1208|1.8%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|1205|1.8%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|1205|1.8%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|510|1.7%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|394|0.8%|0.0%|
[nixspam](#nixspam)|21496|21496|341|1.5%|0.0%|
[voipbl](#voipbl)|10586|10998|302|2.7%|0.0%|
[firehol_proxies](#firehol_proxies)|12718|12994|289|2.2%|0.0%|
[dshield](#dshield)|20|5120|256|5.0%|0.0%|
[dm_tor](#dm_tor)|6521|6521|171|2.6%|0.0%|
[bm_tor](#bm_tor)|6496|6496|171|2.6%|0.0%|
[et_tor](#et_tor)|6500|6500|168|2.5%|0.0%|
[openbl_60d](#openbl_60d)|6959|6959|161|2.3%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7996|7996|156|1.9%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6629|6629|127|1.9%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9136|9136|114|1.2%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|97|6.6%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2876|2876|86|2.9%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|3043|3043|74|2.4%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|66|5.1%|0.0%|
[openbl_30d](#openbl_30d)|2789|2789|65|2.3%|0.0%|
[iw_spamlist](#iw_spamlist)|3418|3418|62|1.8%|0.0%|
[xroxy](#xroxy)|2175|2175|58|2.6%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|56|8.4%|0.0%|
[et_compromised](#et_compromised)|1704|1704|54|3.1%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1696|1696|53|3.1%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3014|3014|53|1.7%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2474|2474|45|1.8%|0.0%|
[proxz](#proxz)|1367|1367|44|3.2%|0.0%|
[et_botcc](#et_botcc)|505|505|39|7.7%|0.0%|
[tor_exits](#tor_exits)|1106|1106|37|3.3%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2599|2599|33|1.2%|0.0%|
[dragon_sshpauth](#dragon_sshpauth)|1589|1653|32|1.9%|0.0%|
[proxyrss](#proxyrss)|1455|1455|28|1.9%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|511|511|28|5.4%|0.0%|
[shunlist](#shunlist)|1201|1201|27|2.2%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|1500|1500|26|1.7%|0.0%|
[ciarmy](#ciarmy)|421|421|22|5.2%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|21|4.0%|0.0%|
[sorbs_web](#sorbs_web)|643|644|16|2.4%|0.0%|
[openbl_7d](#openbl_7d)|637|637|14|2.1%|0.0%|
[php_harvesters](#php_harvesters)|408|408|12|2.9%|0.0%|
[php_dictionary](#php_dictionary)|777|777|12|1.5%|0.0%|
[php_spammers](#php_spammers)|777|777|11|1.4%|0.0%|
[php_commenters](#php_commenters)|458|458|10|2.1%|0.0%|
[malc0de](#malc0de)|276|276|10|3.6%|0.0%|
[zeus](#zeus)|230|230|7|3.0%|0.0%|
[nt_malware_http](#nt_malware_http)|69|69|7|10.1%|0.0%|
[nt_malware_irc](#nt_malware_irc)|43|43|5|11.6%|0.0%|
[dragon_vncprobe](#dragon_vncprobe)|89|89|5|5.6%|0.0%|
[bogons](#bogons)|13|592708608|5|0.0%|0.0%|
[zeus_badips](#zeus_badips)|202|202|4|1.9%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|81|81|4|4.9%|0.0%|
[sslbl](#sslbl)|370|370|3|0.8%|0.0%|
[openbl_1d](#openbl_1d)|131|131|2|1.5%|0.0%|
[iw_wormlist](#iw_wormlist)|23|23|1|4.3%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|169|169|1|0.5%|0.0%|

## ib_bluetack_level2

[iBlocklist.com](https://www.iblocklist.com/) free version of BlueTack.co.uk Level 2 (for use in p2p). General corporate ranges. Ranges used by labs or researchers. Proxies.

Source is downloaded from [this link](http://list.iblocklist.com/?list=gyisgnzbhppbvsphucsw&fileformat=p2p&archiveformat=gz).

The last time downloaded was found to be dated: Fri Jun 12 06:20:42 UTC 2015.

The ipset `ib_bluetack_level2` has **72950** entries, **348710251** unique IPs.

The following table shows the overlaps of `ib_bluetack_level2` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ib_bluetack_level2`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ib_bluetack_level2`.
- ` this % ` is the percentage **of this ipset (`ib_bluetack_level2`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|16302420|2.1%|4.6%|
[firehol_level1](#firehol_level1)|5070|688775051|8867711|1.2%|2.5%|
[et_block](#et_block)|1000|18343756|8532776|46.5%|2.4%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|8532506|46.5%|2.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|2830203|2.0%|0.8%|
[firehol_level3](#firehol_level3)|109554|9627189|2537278|26.3%|0.7%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2526625|27.5%|0.7%|
[fullbogons](#fullbogons)|3788|670093640|252671|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|98904|20.2%|0.0%|
[dragon_http](#dragon_http)|1021|268288|11992|4.4%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|7728|2.2%|0.0%|
[alienvault_reputation](#alienvault_reputation)|189179|189179|7255|3.8%|0.0%|
[firehol_anonymous](#firehol_anonymous)|19277|83325|2900|3.4%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|94236|94236|2463|2.6%|0.0%|
[sorbs_spam](#sorbs_spam)|64701|65536|1740|2.6%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|1736|2.6%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|1736|2.6%|0.0%|
[firehol_level2](#firehol_level2)|21534|33114|1593|4.8%|0.0%|
[blocklist_de](#blocklist_de)|27919|27919|1455|5.2%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|18003|18003|1214|6.7%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13988|13988|1075|7.6%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|736|2.5%|0.0%|
[nixspam](#nixspam)|21496|21496|576|2.6%|0.0%|
[voipbl](#voipbl)|10586|10998|436|3.9%|0.0%|
[firehol_proxies](#firehol_proxies)|12718|12994|393|3.0%|0.0%|
[openbl_60d](#openbl_60d)|6959|6959|318|4.5%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|226|0.4%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7996|7996|225|2.8%|0.0%|
[dm_tor](#dm_tor)|6521|6521|186|2.8%|0.0%|
[bm_tor](#bm_tor)|6496|6496|186|2.8%|0.0%|
[et_tor](#et_tor)|6500|6500|182|2.8%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6629|6629|171|2.5%|0.0%|
[openbl_30d](#openbl_30d)|2789|2789|147|5.2%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9136|9136|141|1.5%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2876|2876|106|3.6%|0.0%|
[xroxy](#xroxy)|2175|2175|104|4.7%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2474|2474|93|3.7%|0.0%|
[et_compromised](#et_compromised)|1704|1704|89|5.2%|0.0%|
[iw_spamlist](#iw_spamlist)|3418|3418|88|2.5%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1696|1696|86|5.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3014|3014|74|2.4%|0.0%|
[dragon_sshpauth](#dragon_sshpauth)|1589|1653|71|4.2%|0.0%|
[shunlist](#shunlist)|1201|1201|70|5.8%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|3043|3043|65|2.1%|0.0%|
[php_spammers](#php_spammers)|777|777|60|7.7%|0.0%|
[proxz](#proxz)|1367|1367|56|4.0%|0.0%|
[proxyrss](#proxyrss)|1455|1455|53|3.6%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|45|3.1%|0.0%|
[tor_exits](#tor_exits)|1106|1106|40|3.6%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2599|2599|40|1.5%|0.0%|
[openbl_7d](#openbl_7d)|637|637|38|5.9%|0.0%|
[ciarmy](#ciarmy)|421|421|34|8.0%|0.0%|
[php_dictionary](#php_dictionary)|777|777|30|3.8%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|29|5.5%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|26|2.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|26|3.9%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|511|511|25|4.8%|0.0%|
[sorbs_web](#sorbs_web)|643|644|23|3.5%|0.0%|
[et_botcc](#et_botcc)|505|505|22|4.3%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|1500|1500|21|1.4%|0.0%|
[php_commenters](#php_commenters)|458|458|19|4.1%|0.0%|
[malc0de](#malc0de)|276|276|16|5.7%|0.0%|
[zeus](#zeus)|230|230|9|3.9%|0.0%|
[php_harvesters](#php_harvesters)|408|408|9|2.2%|0.0%|
[zeus_badips](#zeus_badips)|202|202|8|3.9%|0.0%|
[dragon_vncprobe](#dragon_vncprobe)|89|89|8|8.9%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|169|169|7|4.1%|0.0%|
[sslbl](#sslbl)|370|370|6|1.6%|0.0%|
[openbl_1d](#openbl_1d)|131|131|6|4.5%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|81|81|4|4.9%|0.0%|
[nt_malware_irc](#nt_malware_irc)|43|43|2|4.6%|0.0%|
[nt_malware_http](#nt_malware_http)|69|69|2|2.8%|0.0%|

## ib_bluetack_level3

[iBlocklist.com](https://www.iblocklist.com/) free version of BlueTack.co.uk Level 3 (for use in p2p). Many portal-type websites. ISP ranges that may be dodgy for some reason. Ranges that belong to an individual, but which have not been determined to be used by a particular company. Ranges for things that are unusual in some way. The L3 list is aka the paranoid list.

Source is downloaded from [this link](http://list.iblocklist.com/?list=uwnukjqktoggdknzrhgh&fileformat=p2p&archiveformat=gz).

The last time downloaded was found to be dated: Fri Jun 12 06:20:51 UTC 2015.

The ipset `ib_bluetack_level3` has **17812** entries, **139104927** unique IPs.

The following table shows the overlaps of `ib_bluetack_level3` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ib_bluetack_level3`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ib_bluetack_level3`.
- ` this % ` is the percentage **of this ipset (`ib_bluetack_level3`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level1](#firehol_level1)|5070|688775051|4637594|0.6%|3.3%|
[fullbogons](#fullbogons)|3788|670093640|4236143|0.6%|3.0%|
[bogons](#bogons)|13|592708608|4194304|0.7%|3.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|2830203|0.8%|2.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|1354507|0.1%|0.9%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|270785|55.5%|0.1%|
[firehol_level3](#firehol_level3)|109554|9627189|161605|1.6%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|145472|1.5%|0.1%|
[et_block](#et_block)|1000|18343756|130650|0.7%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|130368|0.7%|0.0%|
[dragon_http](#dragon_http)|1021|268288|20480|7.6%|0.0%|
[alienvault_reputation](#alienvault_reputation)|189179|189179|14342|7.5%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|9226|2.7%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|94236|94236|5843|6.2%|0.0%|
[firehol_level2](#firehol_level2)|21534|33114|4011|12.1%|0.0%|
[blocklist_de](#blocklist_de)|27919|27919|3605|12.9%|0.0%|
[firehol_anonymous](#firehol_anonymous)|19277|83325|2877|3.4%|0.0%|
[sorbs_spam](#sorbs_spam)|64701|65536|2860|4.3%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|2851|4.3%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|2851|4.3%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|18003|18003|2714|15.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13988|13988|2299|16.4%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|1961|6.7%|0.0%|
[voipbl](#voipbl)|10586|10998|1613|14.6%|0.0%|
[nixspam](#nixspam)|21496|21496|1316|6.1%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|1172|2.4%|0.0%|
[openbl_60d](#openbl_60d)|6959|6959|738|10.6%|0.0%|
[et_tor](#et_tor)|6500|6500|636|9.7%|0.0%|
[bm_tor](#bm_tor)|6496|6496|629|9.6%|0.0%|
[dm_tor](#dm_tor)|6521|6521|626|9.5%|0.0%|
[firehol_proxies](#firehol_proxies)|12718|12994|529|4.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6629|6629|490|7.3%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|3043|3043|370|12.1%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2474|2474|363|14.6%|0.0%|
[openbl_30d](#openbl_30d)|2789|2789|286|10.2%|0.0%|
[dshield](#dshield)|20|5120|256|5.0%|0.0%|
[iw_spamlist](#iw_spamlist)|3418|3418|249|7.2%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9136|9136|240|2.6%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7996|7996|221|2.7%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2599|2599|203|7.8%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3014|3014|188|6.2%|0.0%|
[et_compromised](#et_compromised)|1704|1704|157|9.2%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1696|1696|157|9.2%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|150|28.6%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|147|11.4%|0.0%|
[tor_exits](#tor_exits)|1106|1106|126|11.3%|0.0%|
[dragon_sshpauth](#dragon_sshpauth)|1589|1653|125|7.5%|0.0%|
[shunlist](#shunlist)|1201|1201|121|10.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|1500|1500|113|7.5%|0.0%|
[xroxy](#xroxy)|2175|2175|112|5.1%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|108|7.4%|0.0%|
[proxz](#proxz)|1367|1367|106|7.7%|0.0%|
[et_botcc](#et_botcc)|505|505|76|15.0%|0.0%|
[ciarmy](#ciarmy)|421|421|70|16.6%|0.0%|
[openbl_7d](#openbl_7d)|637|637|66|10.3%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2876|2876|58|2.0%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|511|511|58|11.3%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|51|7.6%|0.0%|
[proxyrss](#proxyrss)|1455|1455|48|3.2%|0.0%|
[php_spammers](#php_spammers)|777|777|44|5.6%|0.0%|
[malc0de](#malc0de)|276|276|44|15.9%|0.0%|
[php_dictionary](#php_dictionary)|777|777|39|5.0%|0.0%|
[sorbs_web](#sorbs_web)|643|644|33|5.1%|0.0%|
[php_commenters](#php_commenters)|458|458|29|6.3%|0.0%|
[sslbl](#sslbl)|370|370|28|7.5%|0.0%|
[php_harvesters](#php_harvesters)|408|408|20|4.9%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|169|169|17|10.0%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|81|81|17|20.9%|0.0%|
[zeus](#zeus)|230|230|14|6.0%|0.0%|
[openbl_1d](#openbl_1d)|131|131|13|9.9%|0.0%|
[dragon_vncprobe](#dragon_vncprobe)|89|89|13|14.6%|0.0%|
[zeus_badips](#zeus_badips)|202|202|10|4.9%|0.0%|
[nt_malware_http](#nt_malware_http)|69|69|5|7.2%|0.0%|
[sorbs_socks](#sorbs_socks)|7|7|2|28.5%|0.0%|
[sorbs_misc](#sorbs_misc)|7|7|2|28.5%|0.0%|
[sorbs_http](#sorbs_http)|7|7|2|28.5%|0.0%|
[iw_wormlist](#iw_wormlist)|23|23|2|8.6%|0.0%|
[virbl](#virbl)|23|23|1|4.3%|0.0%|
[nt_malware_irc](#nt_malware_irc)|43|43|1|2.3%|0.0%|

## ib_bluetack_proxies

[iBlocklist.com](https://www.iblocklist.com/) free version of [BlueTack.co.uk](http://www.bluetack.co.uk/) Open Proxies IPs list (without TOR)

Source is downloaded from [this link](http://list.iblocklist.com/?list=xoebmbyexwuiogmbyprb&fileformat=p2p&archiveformat=gz).

The last time downloaded was found to be dated: Fri Jun 12 06:20:02 UTC 2015.

The ipset `ib_bluetack_proxies` has **663** entries, **663** unique IPs.

The following table shows the overlaps of `ib_bluetack_proxies` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ib_bluetack_proxies`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ib_bluetack_proxies`.
- ` this % ` is the percentage **of this ipset (`ib_bluetack_proxies`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_proxies](#firehol_proxies)|12718|12994|663|5.1%|100.0%|
[firehol_anonymous](#firehol_anonymous)|19277|83325|663|0.7%|100.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|56|0.0%|8.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|51|0.0%|7.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|26|0.0%|3.9%|
[firehol_level3](#firehol_level3)|109554|9627189|25|0.0%|3.7%|
[stopforumspam_30d](#stopforumspam_30d)|94236|94236|20|0.0%|3.0%|
[ri_web_proxies](#ri_web_proxies)|7996|7996|15|0.1%|2.2%|
[xroxy](#xroxy)|2175|2175|13|0.5%|1.9%|
[proxyrss](#proxyrss)|1455|1455|12|0.8%|1.8%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|11|0.0%|1.6%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|10|0.0%|1.5%|
[ri_connect_proxies](#ri_connect_proxies)|2876|2876|7|0.2%|1.0%|
[proxz](#proxz)|1367|1367|7|0.5%|1.0%|
[firehol_level2](#firehol_level2)|21534|33114|7|0.0%|1.0%|
[blocklist_de](#blocklist_de)|27919|27919|5|0.0%|0.7%|
[stopforumspam_1d](#stopforumspam_1d)|6629|6629|4|0.0%|0.6%|
[blocklist_de_bots](#blocklist_de_bots)|3014|3014|3|0.0%|0.4%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|2|0.0%|0.3%|
[php_dictionary](#php_dictionary)|777|777|2|0.2%|0.3%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|2|0.1%|0.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2|0.0%|0.3%|
[firehol_level1](#firehol_level1)|5070|688775051|2|0.0%|0.3%|
[et_block](#et_block)|1000|18343756|2|0.0%|0.3%|
[blocklist_de_mail](#blocklist_de_mail)|18003|18003|2|0.0%|0.3%|
[alienvault_reputation](#alienvault_reputation)|189179|189179|2|0.0%|0.3%|
[sorbs_spam](#sorbs_spam)|64701|65536|1|0.0%|0.1%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|1|0.0%|0.1%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|1|0.0%|0.1%|
[snort_ipfilter](#snort_ipfilter)|9136|9136|1|0.0%|0.1%|
[php_spammers](#php_spammers)|777|777|1|0.1%|0.1%|
[nixspam](#nixspam)|21496|21496|1|0.0%|0.1%|
[dragon_http](#dragon_http)|1021|268288|1|0.0%|0.1%|

## ib_bluetack_spyware

[iBlocklist.com](https://www.iblocklist.com/) free version of [BlueTack.co.uk](http://www.bluetack.co.uk/) known malicious SPYWARE and ADWARE IP Address ranges

Source is downloaded from [this link](http://list.iblocklist.com/?list=llvtlsjyoyiczbkjsxpf&fileformat=p2p&archiveformat=gz).

The last time downloaded was found to be dated: Fri Jun 12 05:50:02 UTC 2015.

The ipset `ib_bluetack_spyware` has **3267** entries, **339173** unique IPs.

The following table shows the overlaps of `ib_bluetack_spyware` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ib_bluetack_spyware`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ib_bluetack_spyware`.
- ` this % ` is the percentage **of this ipset (`ib_bluetack_spyware`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level3](#firehol_level3)|109554|9627189|339173|3.5%|100.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|13247|0.0%|3.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|9226|0.0%|2.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|7728|0.0%|2.2%|
[firehol_level1](#firehol_level1)|5070|688775051|1930|0.0%|0.5%|
[et_block](#et_block)|1000|18343756|1041|0.0%|0.3%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|1037|0.0%|0.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1036|0.0%|0.3%|
[fullbogons](#fullbogons)|3788|670093640|890|0.0%|0.2%|
[alienvault_reputation](#alienvault_reputation)|189179|189179|293|0.1%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|94236|94236|52|0.0%|0.0%|
[sorbs_spam](#sorbs_spam)|64701|65536|38|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|37|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|37|0.0%|0.0%|
[firehol_anonymous](#firehol_anonymous)|19277|83325|29|0.0%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|27|2.0%|0.0%|
[et_tor](#et_tor)|6500|6500|22|0.3%|0.0%|
[dm_tor](#dm_tor)|6521|6521|22|0.3%|0.0%|
[bm_tor](#bm_tor)|6496|6496|22|0.3%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|21|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|19|1.3%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9136|9136|14|0.1%|0.0%|
[firehol_proxies](#firehol_proxies)|12718|12994|11|0.0%|0.0%|
[firehol_level2](#firehol_level2)|21534|33114|11|0.0%|0.0%|
[tor_exits](#tor_exits)|1106|1106|8|0.7%|0.0%|
[nixspam](#nixspam)|21496|21496|8|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6629|6629|7|0.1%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7996|7996|6|0.0%|0.0%|
[dragon_http](#dragon_http)|1021|268288|6|0.0%|0.0%|
[openbl_60d](#openbl_60d)|6959|6959|5|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|5|0.9%|0.0%|
[voipbl](#voipbl)|10586|10998|4|0.0%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|511|511|4|0.7%|0.0%|
[blocklist_de](#blocklist_de)|27919|27919|4|0.0%|0.0%|
[openbl_30d](#openbl_30d)|2789|2789|3|0.1%|0.0%|
[iw_spamlist](#iw_spamlist)|3418|3418|3|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|3|0.0%|0.0%|
[malc0de](#malc0de)|276|276|2|0.7%|0.0%|
[et_compromised](#et_compromised)|1704|1704|2|0.1%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1696|1696|2|0.1%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|81|81|2|2.4%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|18003|18003|2|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13988|13988|2|0.0%|0.0%|
[zeus_badips](#zeus_badips)|202|202|1|0.4%|0.0%|
[zeus](#zeus)|230|230|1|0.4%|0.0%|
[xroxy](#xroxy)|2175|2175|1|0.0%|0.0%|
[sslbl](#sslbl)|370|370|1|0.2%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|1|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2876|2876|1|0.0%|0.0%|
[proxz](#proxz)|1367|1367|1|0.0%|0.0%|
[proxyrss](#proxyrss)|1455|1455|1|0.0%|0.0%|
[php_harvesters](#php_harvesters)|408|408|1|0.2%|0.0%|
[php_dictionary](#php_dictionary)|777|777|1|0.1%|0.0%|
[php_commenters](#php_commenters)|458|458|1|0.2%|0.0%|
[nt_malware_http](#nt_malware_http)|69|69|1|1.4%|0.0%|
[bogons](#bogons)|13|592708608|1|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2599|2599|1|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3014|3014|1|0.0%|0.0%|

## ib_bluetack_webexploit

[iBlocklist.com](https://www.iblocklist.com/) free version of [BlueTack.co.uk](http://www.bluetack.co.uk/) web server hack and exploit attempts

Source is downloaded from [this link](http://list.iblocklist.com/?list=ghlzqtqxnzctvvajwwag&fileformat=p2p&archiveformat=gz).

The last time downloaded was found to be dated: Fri Jun 12 05:50:38 UTC 2015.

The ipset `ib_bluetack_webexploit` has **1450** entries, **1450** unique IPs.

The following table shows the overlaps of `ib_bluetack_webexploit` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ib_bluetack_webexploit`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ib_bluetack_webexploit`.
- ` this % ` is the percentage **of this ipset (`ib_bluetack_webexploit`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level3](#firehol_level3)|109554|9627189|1450|0.0%|100.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|108|0.0%|7.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|97|0.0%|6.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|45|0.0%|3.1%|
[firehol_level1](#firehol_level1)|5070|688775051|39|0.0%|2.6%|
[fullbogons](#fullbogons)|3788|670093640|33|0.0%|2.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|19|0.0%|1.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|7|0.0%|0.4%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|6|0.0%|0.4%|
[et_block](#et_block)|1000|18343756|6|0.0%|0.4%|
[alienvault_reputation](#alienvault_reputation)|189179|189179|6|0.0%|0.4%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|3|0.2%|0.2%|
[firehol_proxies](#firehol_proxies)|12718|12994|3|0.0%|0.2%|
[firehol_anonymous](#firehol_anonymous)|19277|83325|3|0.0%|0.2%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|2|0.0%|0.1%|
[stopforumspam_30d](#stopforumspam_30d)|94236|94236|2|0.0%|0.1%|
[sorbs_spam](#sorbs_spam)|64701|65536|2|0.0%|0.1%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|2|0.0%|0.1%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|2|0.0%|0.1%|
[openbl_60d](#openbl_60d)|6959|6959|2|0.0%|0.1%|
[openbl_30d](#openbl_30d)|2789|2789|2|0.0%|0.1%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|2|0.3%|0.1%|
[firehol_level2](#firehol_level2)|21534|33114|2|0.0%|0.1%|
[dragon_http](#dragon_http)|1021|268288|2|0.0%|0.1%|
[blocklist_de_strongips](#blocklist_de_strongips)|169|169|2|1.1%|0.1%|
[blocklist_de_bots](#blocklist_de_bots)|3014|3014|2|0.0%|0.1%|
[blocklist_de](#blocklist_de)|27919|27919|2|0.0%|0.1%|
[stopforumspam_1d](#stopforumspam_1d)|6629|6629|1|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9136|9136|1|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7996|7996|1|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|1|0.0%|0.0%|
[et_botcc](#et_botcc)|505|505|1|0.1%|0.0%|
[dragon_sshpauth](#dragon_sshpauth)|1589|1653|1|0.0%|0.0%|

## iw_spamlist

[ImproWare Antispam](http://antispam.imp.ch/) IPs sending spam, in the last 3 days

Source is downloaded from [this link](http://antispam.imp.ch/spamlist).

The last time downloaded was found to be dated: Fri Jun 12 11:20:04 UTC 2015.

The ipset `iw_spamlist` has **3418** entries, **3418** unique IPs.

The following table shows the overlaps of `iw_spamlist` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `iw_spamlist`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `iw_spamlist`.
- ` this % ` is the percentage **of this ipset (`iw_spamlist`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[sorbs_spam](#sorbs_spam)|64701|65536|799|1.2%|23.3%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|794|1.2%|23.2%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|794|1.2%|23.2%|
[nixspam](#nixspam)|21496|21496|632|2.9%|18.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|249|0.0%|7.2%|
[firehol_level2](#firehol_level2)|21534|33114|122|0.3%|3.5%|
[blocklist_de](#blocklist_de)|27919|27919|122|0.4%|3.5%|
[blocklist_de_mail](#blocklist_de_mail)|18003|18003|114|0.6%|3.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|88|0.0%|2.5%|
[firehol_level3](#firehol_level3)|109554|9627189|83|0.0%|2.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|62|0.0%|1.8%|
[snort_ipfilter](#snort_ipfilter)|9136|9136|44|0.4%|1.2%|
[sorbs_web](#sorbs_web)|643|644|26|4.0%|0.7%|
[alienvault_reputation](#alienvault_reputation)|189179|189179|24|0.0%|0.7%|
[stopforumspam_30d](#stopforumspam_30d)|94236|94236|22|0.0%|0.6%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|13|0.0%|0.3%|
[iw_wormlist](#iw_wormlist)|23|23|7|30.4%|0.2%|
[firehol_proxies](#firehol_proxies)|12718|12994|7|0.0%|0.2%|
[firehol_level1](#firehol_level1)|5070|688775051|7|0.0%|0.2%|
[firehol_anonymous](#firehol_anonymous)|19277|83325|7|0.0%|0.2%|
[ri_web_proxies](#ri_web_proxies)|7996|7996|6|0.0%|0.1%|
[php_dictionary](#php_dictionary)|777|777|6|0.7%|0.1%|
[php_spammers](#php_spammers)|777|777|4|0.5%|0.1%|
[php_harvesters](#php_harvesters)|408|408|4|0.9%|0.1%|
[blocklist_de_imap](#blocklist_de_imap)|3043|3043|4|0.1%|0.1%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|3|0.0%|0.0%|
[php_commenters](#php_commenters)|458|458|3|0.6%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|3|0.0%|0.0%|
[fullbogons](#fullbogons)|3788|670093640|3|0.0%|0.0%|
[et_block](#et_block)|1000|18343756|3|0.0%|0.0%|
[bogons](#bogons)|13|592708608|3|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2599|2599|3|0.1%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3014|3014|3|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13988|13988|3|0.0%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2|0.0%|0.0%|
[dragon_http](#dragon_http)|1021|268288|2|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|1500|1500|2|0.1%|0.0%|
[xroxy](#xroxy)|2175|2175|1|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6629|6629|1|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|1|0.0%|0.0%|
[sorbs_socks](#sorbs_socks)|7|7|1|14.2%|0.0%|
[sorbs_misc](#sorbs_misc)|7|7|1|14.2%|0.0%|
[sorbs_http](#sorbs_http)|7|7|1|14.2%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2876|2876|1|0.0%|0.0%|
[proxz](#proxz)|1367|1367|1|0.0%|0.0%|
[proxyrss](#proxyrss)|1455|1455|1|0.0%|0.0%|

## iw_wormlist

[ImproWare Antispam](http://antispam.imp.ch/) IPs sending emails with viruses or worms, in the last 3 days

Source is downloaded from [this link](http://antispam.imp.ch/wormlist).

The last time downloaded was found to be dated: Fri Jun 12 11:20:04 UTC 2015.

The ipset `iw_wormlist` has **23** entries, **23** unique IPs.

The following table shows the overlaps of `iw_wormlist` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `iw_wormlist`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `iw_wormlist`.
- ` this % ` is the percentage **of this ipset (`iw_wormlist`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level3](#firehol_level3)|109554|9627189|23|0.0%|100.0%|
[iw_spamlist](#iw_spamlist)|3418|3418|7|0.2%|30.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|2|0.0%|8.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|1|0.0%|4.3%|

## malc0de

[Malc0de.com](http://malc0de.com) malicious IPs of the last 30 days

Source is downloaded from [this link](http://malc0de.com/bl/IP_Blacklist.txt).

The last time downloaded was found to be dated: Thu Jun 11 13:17:02 UTC 2015.

The ipset `malc0de` has **276** entries, **276** unique IPs.

The following table shows the overlaps of `malc0de` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `malc0de`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `malc0de`.
- ` this % ` is the percentage **of this ipset (`malc0de`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level3](#firehol_level3)|109554|9627189|276|0.0%|100.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|44|0.0%|15.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|16|0.0%|5.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|10|0.0%|3.6%|
[alienvault_reputation](#alienvault_reputation)|189179|189179|9|0.0%|3.2%|
[cleanmx_viruses](#cleanmx_viruses)|511|511|8|1.5%|2.8%|
[firehol_level1](#firehol_level1)|5070|688775051|5|0.0%|1.8%|
[et_block](#et_block)|1000|18343756|5|0.0%|1.8%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|4|0.0%|1.4%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|4|0.3%|1.4%|
[dragon_http](#dragon_http)|1021|268288|3|0.0%|1.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|2|0.0%|0.7%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|1|0.0%|0.3%|
[sorbs_spam](#sorbs_spam)|64701|65536|1|0.0%|0.3%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|1|0.0%|0.3%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|1|0.0%|0.3%|

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
[firehol_level3](#firehol_level3)|109554|9627189|1288|0.0%|100.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|147|0.0%|11.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|66|0.0%|5.1%|
[firehol_level1](#firehol_level1)|5070|688775051|39|0.0%|3.0%|
[et_block](#et_block)|1000|18343756|30|0.0%|2.3%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|29|0.0%|2.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|27|0.0%|2.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|27|0.0%|2.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|26|0.0%|2.0%|
[snort_ipfilter](#snort_ipfilter)|9136|9136|11|0.1%|0.8%|
[fullbogons](#fullbogons)|3788|670093640|9|0.0%|0.6%|
[alienvault_reputation](#alienvault_reputation)|189179|189179|8|0.0%|0.6%|
[malc0de](#malc0de)|276|276|4|1.4%|0.3%|
[cleanmx_viruses](#cleanmx_viruses)|511|511|4|0.7%|0.3%|
[stopforumspam_30d](#stopforumspam_30d)|94236|94236|3|0.0%|0.2%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|3|0.2%|0.2%|
[dragon_http](#dragon_http)|1021|268288|2|0.0%|0.1%|
[zeus](#zeus)|230|230|1|0.4%|0.0%|
[nixspam](#nixspam)|21496|21496|1|0.0%|0.0%|
[et_botcc](#et_botcc)|505|505|1|0.1%|0.0%|

## maxmind_proxy_fraud

[MaxMind.com](https://www.maxmind.com/en/anonymous-proxy-fraudulent-ip-address-list) list of anonymous proxy fraudelent IP addresses.

Source is downloaded from [this link](https://www.maxmind.com/en/anonymous-proxy-fraudulent-ip-address-list).

The last time downloaded was found to be dated: Fri Jun 12 12:00:34 UTC 2015.

The ipset `maxmind_proxy_fraud` has **524** entries, **524** unique IPs.

The following table shows the overlaps of `maxmind_proxy_fraud` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `maxmind_proxy_fraud`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `maxmind_proxy_fraud`.
- ` this % ` is the percentage **of this ipset (`maxmind_proxy_fraud`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_proxies](#firehol_proxies)|12718|12994|524|4.0%|100.0%|
[firehol_anonymous](#firehol_anonymous)|19277|83325|524|0.6%|100.0%|
[firehol_level3](#firehol_level3)|109554|9627189|347|0.0%|66.2%|
[stopforumspam_30d](#stopforumspam_30d)|94236|94236|346|0.3%|66.0%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|277|0.9%|52.8%|
[snort_ipfilter](#snort_ipfilter)|9136|9136|237|2.5%|45.2%|
[et_tor](#et_tor)|6500|6500|233|3.5%|44.4%|
[tor_exits](#tor_exits)|1106|1106|230|20.7%|43.8%|
[dm_tor](#dm_tor)|6521|6521|230|3.5%|43.8%|
[bm_tor](#bm_tor)|6496|6496|229|3.5%|43.7%|
[firehol_level2](#firehol_level2)|21534|33114|201|0.6%|38.3%|
[stopforumspam_1d](#stopforumspam_1d)|6629|6629|199|3.0%|37.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|150|0.0%|28.6%|
[php_commenters](#php_commenters)|458|458|53|11.5%|10.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|29|0.0%|5.5%|
[alienvault_reputation](#alienvault_reputation)|189179|189179|29|0.0%|5.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|21|0.0%|4.0%|
[openbl_60d](#openbl_60d)|6959|6959|20|0.2%|3.8%|
[ri_web_proxies](#ri_web_proxies)|7996|7996|10|0.1%|1.9%|
[php_harvesters](#php_harvesters)|408|408|7|1.7%|1.3%|
[php_spammers](#php_spammers)|777|777|6|0.7%|1.1%|
[php_dictionary](#php_dictionary)|777|777|5|0.6%|0.9%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|5|0.0%|0.9%|
[blocklist_de](#blocklist_de)|27919|27919|5|0.0%|0.9%|
[dragon_http](#dragon_http)|1021|268288|4|0.0%|0.7%|
[blocklist_de_bots](#blocklist_de_bots)|3014|3014|4|0.1%|0.7%|
[xroxy](#xroxy)|2175|2175|3|0.1%|0.5%|
[voipbl](#voipbl)|10586|10998|2|0.0%|0.3%|
[proxz](#proxz)|1367|1367|2|0.1%|0.3%|
[nixspam](#nixspam)|21496|21496|2|0.0%|0.3%|
[firehol_level1](#firehol_level1)|5070|688775051|2|0.0%|0.3%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|1|0.0%|0.1%|
[sorbs_spam](#sorbs_spam)|64701|65536|1|0.0%|0.1%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|1|0.0%|0.1%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|1|0.0%|0.1%|
[shunlist](#shunlist)|1201|1201|1|0.0%|0.1%|
[ri_connect_proxies](#ri_connect_proxies)|2876|2876|1|0.0%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.1%|
[et_block](#et_block)|1000|18343756|1|0.0%|0.1%|
[dshield](#dshield)|20|5120|1|0.0%|0.1%|
[blocklist_de_mail](#blocklist_de_mail)|18003|18003|1|0.0%|0.1%|
[blocklist_de_apache](#blocklist_de_apache)|13988|13988|1|0.0%|0.1%|

## nixspam

[NiX Spam](http://www.heise.de/ix/NiX-Spam-DNSBL-and-blacklist-for-download-499637.html) IP addresses that sent spam in the last hour - automatically generated entries without distinguishing open proxies from relays, dialup gateways, and so on. All IPs are removed after 12 hours if there is no spam from there.

Source is downloaded from [this link](http://www.dnsbl.manitu.net/download/nixspam-ip.dump.gz).

The last time downloaded was found to be dated: Fri Jun 12 12:15:02 UTC 2015.

The ipset `nixspam` has **21496** entries, **21496** unique IPs.

The following table shows the overlaps of `nixspam` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `nixspam`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `nixspam`.
- ` this % ` is the percentage **of this ipset (`nixspam`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[sorbs_spam](#sorbs_spam)|64701|65536|1947|2.9%|9.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|1929|2.9%|8.9%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|1929|2.9%|8.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|1316|0.0%|6.1%|
[iw_spamlist](#iw_spamlist)|3418|3418|632|18.4%|2.9%|
[firehol_level2](#firehol_level2)|21534|33114|627|1.8%|2.9%|
[blocklist_de](#blocklist_de)|27919|27919|606|2.1%|2.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|576|0.0%|2.6%|
[blocklist_de_mail](#blocklist_de_mail)|18003|18003|553|3.0%|2.5%|
[firehol_level3](#firehol_level3)|109554|9627189|432|0.0%|2.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|341|0.0%|1.5%|
[stopforumspam_30d](#stopforumspam_30d)|94236|94236|241|0.2%|1.1%|
[snort_ipfilter](#snort_ipfilter)|9136|9136|178|1.9%|0.8%|
[firehol_anonymous](#firehol_anonymous)|19277|83325|142|0.1%|0.6%|
[firehol_proxies](#firehol_proxies)|12718|12994|134|1.0%|0.6%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|131|0.4%|0.6%|
[php_dictionary](#php_dictionary)|777|777|120|15.4%|0.5%|
[php_spammers](#php_spammers)|777|777|108|13.8%|0.5%|
[sorbs_web](#sorbs_web)|643|644|104|16.1%|0.4%|
[ri_web_proxies](#ri_web_proxies)|7996|7996|94|1.1%|0.4%|
[xroxy](#xroxy)|2175|2175|61|2.8%|0.2%|
[stopforumspam_1d](#stopforumspam_1d)|6629|6629|53|0.7%|0.2%|
[proxz](#proxz)|1367|1367|46|3.3%|0.2%|
[blocklist_de_imap](#blocklist_de_imap)|3043|3043|41|1.3%|0.1%|
[alienvault_reputation](#alienvault_reputation)|189179|189179|37|0.0%|0.1%|
[blocklist_de_bots](#blocklist_de_bots)|3014|3014|34|1.1%|0.1%|
[dragon_http](#dragon_http)|1021|268288|32|0.0%|0.1%|
[firehol_level1](#firehol_level1)|5070|688775051|23|0.0%|0.1%|
[et_block](#et_block)|1000|18343756|22|0.0%|0.1%|
[blocklist_de_apache](#blocklist_de_apache)|13988|13988|22|0.1%|0.1%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|21|0.0%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|21|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2599|2599|19|0.7%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2876|2876|16|0.5%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|1500|1500|15|1.0%|0.0%|
[php_commenters](#php_commenters)|458|458|13|2.8%|0.0%|
[tor_exits](#tor_exits)|1106|1106|9|0.8%|0.0%|
[proxyrss](#proxyrss)|1455|1455|9|0.6%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|9|0.0%|0.0%|
[php_harvesters](#php_harvesters)|408|408|8|1.9%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|8|0.0%|0.0%|
[dm_tor](#dm_tor)|6521|6521|8|0.1%|0.0%|
[openbl_60d](#openbl_60d)|6959|6959|7|0.1%|0.0%|
[bm_tor](#bm_tor)|6496|6496|7|0.1%|0.0%|
[et_tor](#et_tor)|6500|6500|6|0.0%|0.0%|
[openbl_30d](#openbl_30d)|2789|2789|2|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|2|0.3%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|169|169|2|1.1%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2474|2474|2|0.0%|0.0%|
[zeus_badips](#zeus_badips)|202|202|1|0.4%|0.0%|
[zeus](#zeus)|230|230|1|0.4%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|1|0.0%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|1|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|1|0.1%|0.0%|
[et_compromised](#et_compromised)|1704|1704|1|0.0%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|511|511|1|0.1%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1696|1696|1|0.0%|0.0%|

## nt_malware_http

[No Think](http://www.nothink.org/) Malware HTTP

Source is downloaded from [this link](http://www.nothink.org/blacklist/blacklist_malware_http.txt).

The last time downloaded was found to be dated: Thu Jun 11 22:05:06 UTC 2015.

The ipset `nt_malware_http` has **69** entries, **69** unique IPs.

The following table shows the overlaps of `nt_malware_http` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `nt_malware_http`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `nt_malware_http`.
- ` this % ` is the percentage **of this ipset (`nt_malware_http`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level1](#firehol_level1)|5070|688775051|8|0.0%|11.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|7|0.0%|10.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|5|0.0%|7.2%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|4|0.0%|5.7%|
[fullbogons](#fullbogons)|3788|670093640|4|0.0%|5.7%|
[et_block](#et_block)|1000|18343756|4|0.0%|5.7%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|4.3%|
[firehol_level3](#firehol_level3)|109554|9627189|3|0.0%|4.3%|
[stopforumspam_30d](#stopforumspam_30d)|94236|94236|2|0.0%|2.8%|
[nt_malware_irc](#nt_malware_irc)|43|43|2|4.6%|2.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|2|0.0%|2.8%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|1.4%|
[alienvault_reputation](#alienvault_reputation)|189179|189179|1|0.0%|1.4%|

## nt_malware_irc

[No Think](http://www.nothink.org/) Malware IRC

Source is downloaded from [this link](http://www.nothink.org/blacklist/blacklist_malware_irc.txt).

The last time downloaded was found to be dated: Thu Jun 11 22:05:06 UTC 2015.

The ipset `nt_malware_irc` has **43** entries, **43** unique IPs.

The following table shows the overlaps of `nt_malware_irc` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `nt_malware_irc`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `nt_malware_irc`.
- ` this % ` is the percentage **of this ipset (`nt_malware_irc`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|5|0.0%|11.6%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|3|0.0%|6.9%|
[firehol_level1](#firehol_level1)|5070|688775051|3|0.0%|6.9%|
[et_block](#et_block)|1000|18343756|3|0.0%|6.9%|
[nt_malware_http](#nt_malware_http)|69|69|2|2.8%|4.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|2|0.0%|4.6%|
[alienvault_reputation](#alienvault_reputation)|189179|189179|2|0.0%|4.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|1|0.0%|2.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|2.3%|
[firehol_level3](#firehol_level3)|109554|9627189|1|0.0%|2.3%|

## nt_ssh_7d

[No Think](http://www.nothink.org/) Last 7 days SSH attacks

Source is downloaded from [this link](http://www.nothink.org/blacklist/blacklist_ssh_week.txt).

The last time downloaded was found to be dated: Thu Jun 11 22:05:06 UTC 2015.

The ipset `nt_ssh_7d` has **0** entries, **0** unique IPs.

The following table shows the overlaps of `nt_ssh_7d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `nt_ssh_7d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `nt_ssh_7d`.
- ` this % ` is the percentage **of this ipset (`nt_ssh_7d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|

## openbl_1d

[OpenBL.org](http://www.openbl.org/) last 24 hours IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.

Source is downloaded from [this link](http://www.openbl.org/lists/base_1days.txt).

The last time downloaded was found to be dated: Fri Jun 12 11:32:00 UTC 2015.

The ipset `openbl_1d` has **131** entries, **131** unique IPs.

The following table shows the overlaps of `openbl_1d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl_1d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl_1d`.
- ` this % ` is the percentage **of this ipset (`openbl_1d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[openbl_7d](#openbl_7d)|637|637|131|20.5%|100.0%|
[openbl_60d](#openbl_60d)|6959|6959|131|1.8%|100.0%|
[openbl_30d](#openbl_30d)|2789|2789|131|4.6%|100.0%|
[firehol_level3](#firehol_level3)|109554|9627189|131|0.0%|100.0%|
[firehol_level2](#firehol_level2)|21534|33114|131|0.3%|100.0%|
[alienvault_reputation](#alienvault_reputation)|189179|189179|127|0.0%|96.9%|
[blocklist_de](#blocklist_de)|27919|27919|112|0.4%|85.4%|
[blocklist_de_ssh](#blocklist_de_ssh)|2474|2474|111|4.4%|84.7%|
[dragon_sshpauth](#dragon_sshpauth)|1589|1653|84|5.0%|64.1%|
[shunlist](#shunlist)|1201|1201|61|5.0%|46.5%|
[bruteforceblocker](#bruteforceblocker)|1696|1696|59|3.4%|45.0%|
[et_compromised](#et_compromised)|1704|1704|54|3.1%|41.2%|
[blocklist_de_strongips](#blocklist_de_strongips)|169|169|17|10.0%|12.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|13|0.0%|9.9%|
[firehol_level1](#firehol_level1)|5070|688775051|11|0.0%|8.3%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|7|0.0%|5.3%|
[et_block](#et_block)|1000|18343756|7|0.0%|5.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|6|0.0%|4.5%|
[dragon_http](#dragon_http)|1021|268288|6|0.0%|4.5%|
[dshield](#dshield)|20|5120|5|0.0%|3.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|2|0.0%|1.5%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2|0.0%|1.5%|
[stopforumspam_30d](#stopforumspam_30d)|94236|94236|1|0.0%|0.7%|
[php_spammers](#php_spammers)|777|777|1|0.1%|0.7%|
[php_commenters](#php_commenters)|458|458|1|0.2%|0.7%|
[ciarmy](#ciarmy)|421|421|1|0.2%|0.7%|
[blocklist_de_mail](#blocklist_de_mail)|18003|18003|1|0.0%|0.7%|
[blocklist_de_imap](#blocklist_de_imap)|3043|3043|1|0.0%|0.7%|

## openbl_30d

[OpenBL.org](http://www.openbl.org/) last 30 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.

Source is downloaded from [this link](http://www.openbl.org/lists/base_30days.txt).

The last time downloaded was found to be dated: Fri Jun 12 12:07:00 UTC 2015.

The ipset `openbl_30d` has **2789** entries, **2789** unique IPs.

The following table shows the overlaps of `openbl_30d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl_30d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl_30d`.
- ` this % ` is the percentage **of this ipset (`openbl_30d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[openbl_60d](#openbl_60d)|6959|6959|2789|40.0%|100.0%|
[firehol_level3](#firehol_level3)|109554|9627189|2789|0.0%|100.0%|
[alienvault_reputation](#alienvault_reputation)|189179|189179|2768|1.4%|99.2%|
[et_compromised](#et_compromised)|1704|1704|907|53.2%|32.5%|
[bruteforceblocker](#bruteforceblocker)|1696|1696|903|53.2%|32.3%|
[dragon_sshpauth](#dragon_sshpauth)|1589|1653|697|42.1%|24.9%|
[firehol_level2](#firehol_level2)|21534|33114|659|1.9%|23.6%|
[blocklist_de](#blocklist_de)|27919|27919|639|2.2%|22.9%|
[openbl_7d](#openbl_7d)|637|637|637|100.0%|22.8%|
[blocklist_de_ssh](#blocklist_de_ssh)|2474|2474|618|24.9%|22.1%|
[shunlist](#shunlist)|1201|1201|439|36.5%|15.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|286|0.0%|10.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|147|0.0%|5.2%|
[dragon_http](#dragon_http)|1021|268288|146|0.0%|5.2%|
[firehol_level1](#firehol_level1)|5070|688775051|135|0.0%|4.8%|
[openbl_1d](#openbl_1d)|131|131|131|100.0%|4.6%|
[et_block](#et_block)|1000|18343756|125|0.0%|4.4%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|119|0.0%|4.2%|
[dshield](#dshield)|20|5120|80|1.5%|2.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|65|0.0%|2.3%|
[blocklist_de_strongips](#blocklist_de_strongips)|169|169|23|13.6%|0.8%|
[blocklist_de_mail](#blocklist_de_mail)|18003|18003|14|0.0%|0.5%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|12|0.0%|0.4%|
[blocklist_de_imap](#blocklist_de_imap)|3043|3043|11|0.3%|0.3%|
[stopforumspam_30d](#stopforumspam_30d)|94236|94236|5|0.0%|0.1%|
[blocklist_de_apache](#blocklist_de_apache)|13988|13988|4|0.0%|0.1%|
[voipbl](#voipbl)|10586|10998|3|0.0%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|3|0.0%|0.1%|
[zeus](#zeus)|230|230|2|0.8%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9136|9136|2|0.0%|0.0%|
[nixspam](#nixspam)|21496|21496|2|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|2|0.1%|0.0%|
[ciarmy](#ciarmy)|421|421|2|0.4%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|1500|1500|2|0.1%|0.0%|
[zeus_badips](#zeus_badips)|202|202|1|0.4%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|1|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6629|6629|1|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|1|0.0%|0.0%|
[php_spammers](#php_spammers)|777|777|1|0.1%|0.0%|
[php_commenters](#php_commenters)|458|458|1|0.2%|0.0%|
[firehol_anonymous](#firehol_anonymous)|19277|83325|1|0.0%|0.0%|

## openbl_60d

[OpenBL.org](http://www.openbl.org/) last 60 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.

Source is downloaded from [this link](http://www.openbl.org/lists/base_60days.txt).

The last time downloaded was found to be dated: Fri Jun 12 12:07:00 UTC 2015.

The ipset `openbl_60d` has **6959** entries, **6959** unique IPs.

The following table shows the overlaps of `openbl_60d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl_60d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl_60d`.
- ` this % ` is the percentage **of this ipset (`openbl_60d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[alienvault_reputation](#alienvault_reputation)|189179|189179|6933|3.6%|99.6%|
[firehol_level3](#firehol_level3)|109554|9627189|2916|0.0%|41.9%|
[openbl_30d](#openbl_30d)|2789|2789|2789|100.0%|40.0%|
[et_compromised](#et_compromised)|1704|1704|977|57.3%|14.0%|
[bruteforceblocker](#bruteforceblocker)|1696|1696|964|56.8%|13.8%|
[firehol_level2](#firehol_level2)|21534|33114|801|2.4%|11.5%|
[dragon_sshpauth](#dragon_sshpauth)|1589|1653|779|47.1%|11.1%|
[blocklist_de](#blocklist_de)|27919|27919|763|2.7%|10.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|738|0.0%|10.6%|
[blocklist_de_ssh](#blocklist_de_ssh)|2474|2474|734|29.6%|10.5%|
[openbl_7d](#openbl_7d)|637|637|637|100.0%|9.1%|
[shunlist](#shunlist)|1201|1201|465|38.7%|6.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|318|0.0%|4.5%|
[firehol_level1](#firehol_level1)|5070|688775051|253|0.0%|3.6%|
[et_block](#et_block)|1000|18343756|244|0.0%|3.5%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|235|0.0%|3.3%|
[dragon_http](#dragon_http)|1021|268288|213|0.0%|3.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|161|0.0%|2.3%|
[openbl_1d](#openbl_1d)|131|131|131|100.0%|1.8%|
[dshield](#dshield)|20|5120|84|1.6%|1.2%|
[stopforumspam_30d](#stopforumspam_30d)|94236|94236|47|0.0%|0.6%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|26|0.0%|0.3%|
[snort_ipfilter](#snort_ipfilter)|9136|9136|24|0.2%|0.3%|
[blocklist_de_strongips](#blocklist_de_strongips)|169|169|24|14.2%|0.3%|
[firehol_anonymous](#firehol_anonymous)|19277|83325|23|0.0%|0.3%|
[tor_exits](#tor_exits)|1106|1106|20|1.8%|0.2%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|20|3.8%|0.2%|
[firehol_proxies](#firehol_proxies)|12718|12994|20|0.1%|0.2%|
[et_tor](#et_tor)|6500|6500|20|0.3%|0.2%|
[dm_tor](#dm_tor)|6521|6521|20|0.3%|0.2%|
[bm_tor](#bm_tor)|6496|6496|20|0.3%|0.2%|
[stopforumspam_1d](#stopforumspam_1d)|6629|6629|19|0.2%|0.2%|
[blocklist_de_mail](#blocklist_de_mail)|18003|18003|19|0.1%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|16|0.0%|0.2%|
[blocklist_de_imap](#blocklist_de_imap)|3043|3043|15|0.4%|0.2%|
[php_commenters](#php_commenters)|458|458|12|2.6%|0.1%|
[voipbl](#voipbl)|10586|10998|8|0.0%|0.1%|
[nixspam](#nixspam)|21496|21496|7|0.0%|0.1%|
[blocklist_de_apache](#blocklist_de_apache)|13988|13988|7|0.0%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|5|0.0%|0.0%|
[zeus](#zeus)|230|230|2|0.8%|0.0%|
[sorbs_spam](#sorbs_spam)|64701|65536|2|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|2|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|2|0.0%|0.0%|
[php_harvesters](#php_harvesters)|408|408|2|0.4%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|2|0.1%|0.0%|
[ciarmy](#ciarmy)|421|421|2|0.4%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|1500|1500|2|0.1%|0.0%|
[zeus_badips](#zeus_badips)|202|202|1|0.4%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|1|0.0%|0.0%|
[php_spammers](#php_spammers)|777|777|1|0.1%|0.0%|

## openbl_7d

[OpenBL.org](http://www.openbl.org/) last 7 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.

Source is downloaded from [this link](http://www.openbl.org/lists/base_7days.txt).

The last time downloaded was found to be dated: Fri Jun 12 12:07:00 UTC 2015.

The ipset `openbl_7d` has **637** entries, **637** unique IPs.

The following table shows the overlaps of `openbl_7d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl_7d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl_7d`.
- ` this % ` is the percentage **of this ipset (`openbl_7d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[openbl_60d](#openbl_60d)|6959|6959|637|9.1%|100.0%|
[openbl_30d](#openbl_30d)|2789|2789|637|22.8%|100.0%|
[firehol_level3](#firehol_level3)|109554|9627189|637|0.0%|100.0%|
[alienvault_reputation](#alienvault_reputation)|189179|189179|629|0.3%|98.7%|
[firehol_level2](#firehol_level2)|21534|33114|397|1.1%|62.3%|
[blocklist_de](#blocklist_de)|27919|27919|378|1.3%|59.3%|
[blocklist_de_ssh](#blocklist_de_ssh)|2474|2474|367|14.8%|57.6%|
[dragon_sshpauth](#dragon_sshpauth)|1589|1653|348|21.0%|54.6%|
[bruteforceblocker](#bruteforceblocker)|1696|1696|310|18.2%|48.6%|
[et_compromised](#et_compromised)|1704|1704|305|17.8%|47.8%|
[shunlist](#shunlist)|1201|1201|208|17.3%|32.6%|
[openbl_1d](#openbl_1d)|131|131|131|100.0%|20.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|66|0.0%|10.3%|
[firehol_level1](#firehol_level1)|5070|688775051|60|0.0%|9.4%|
[et_block](#et_block)|1000|18343756|57|0.0%|8.9%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|53|0.0%|8.3%|
[dragon_http](#dragon_http)|1021|268288|52|0.0%|8.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|38|0.0%|5.9%|
[blocklist_de_strongips](#blocklist_de_strongips)|169|169|22|13.0%|3.4%|
[dshield](#dshield)|20|5120|21|0.4%|3.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|14|0.0%|2.1%|
[blocklist_de_mail](#blocklist_de_mail)|18003|18003|8|0.0%|1.2%|
[blocklist_de_imap](#blocklist_de_imap)|3043|3043|7|0.2%|1.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|4|0.0%|0.6%|
[stopforumspam_30d](#stopforumspam_30d)|94236|94236|2|0.0%|0.3%|
[ciarmy](#ciarmy)|421|421|2|0.4%|0.3%|
[blocklist_de_ftp](#blocklist_de_ftp)|1500|1500|2|0.1%|0.3%|
[zeus_badips](#zeus_badips)|202|202|1|0.4%|0.1%|
[zeus](#zeus)|230|230|1|0.4%|0.1%|
[snort_ipfilter](#snort_ipfilter)|9136|9136|1|0.0%|0.1%|
[php_spammers](#php_spammers)|777|777|1|0.1%|0.1%|
[php_commenters](#php_commenters)|458|458|1|0.2%|0.1%|
[blocklist_de_apache](#blocklist_de_apache)|13988|13988|1|0.0%|0.1%|

## palevo

[Abuse.ch Palevo tracker](https://palevotracker.abuse.ch) worm includes IPs which are being used as botnet C&C for the Palevo crimeware - **excellent list**

Source is downloaded from [this link](https://palevotracker.abuse.ch/blocklists.php?download=ipblocklist).

The last time downloaded was found to be dated: Fri Jun 12 11:54:17 UTC 2015.

The ipset `palevo` has **0** entries, **0** unique IPs.

The following table shows the overlaps of `palevo` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `palevo`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `palevo`.
- ` this % ` is the percentage **of this ipset (`palevo`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|

## php_commenters

[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) comment spammers (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=c&rss=1).

The last time downloaded was found to be dated: Fri Jun 12 12:20:44 UTC 2015.

The ipset `php_commenters` has **458** entries, **458** unique IPs.

The following table shows the overlaps of `php_commenters` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `php_commenters`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `php_commenters`.
- ` this % ` is the percentage **of this ipset (`php_commenters`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level3](#firehol_level3)|109554|9627189|458|0.0%|100.0%|
[stopforumspam_30d](#stopforumspam_30d)|94236|94236|336|0.3%|73.3%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|248|0.8%|54.1%|
[firehol_level2](#firehol_level2)|21534|33114|194|0.5%|42.3%|
[stopforumspam_1d](#stopforumspam_1d)|6629|6629|165|2.4%|36.0%|
[blocklist_de](#blocklist_de)|27919|27919|107|0.3%|23.3%|
[firehol_anonymous](#firehol_anonymous)|19277|83325|89|0.1%|19.4%|
[blocklist_de_bots](#blocklist_de_bots)|3014|3014|86|2.8%|18.7%|
[firehol_proxies](#firehol_proxies)|12718|12994|85|0.6%|18.5%|
[snort_ipfilter](#snort_ipfilter)|9136|9136|71|0.7%|15.5%|
[php_spammers](#php_spammers)|777|777|55|7.0%|12.0%|
[tor_exits](#tor_exits)|1106|1106|54|4.8%|11.7%|
[et_tor](#et_tor)|6500|6500|54|0.8%|11.7%|
[dm_tor](#dm_tor)|6521|6521|54|0.8%|11.7%|
[bm_tor](#bm_tor)|6496|6496|54|0.8%|11.7%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|53|10.1%|11.5%|
[blocklist_de_strongips](#blocklist_de_strongips)|169|169|44|26.0%|9.6%|
[firehol_level1](#firehol_level1)|5070|688775051|39|0.0%|8.5%|
[php_dictionary](#php_dictionary)|777|777|38|4.8%|8.2%|
[ri_web_proxies](#ri_web_proxies)|7996|7996|30|0.3%|6.5%|
[blocklist_de_mail](#blocklist_de_mail)|18003|18003|30|0.1%|6.5%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|29|0.0%|6.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|29|0.0%|6.3%|
[et_block](#et_block)|1000|18343756|29|0.0%|6.3%|
[blocklist_de_apache](#blocklist_de_apache)|13988|13988|28|0.2%|6.1%|
[sorbs_spam](#sorbs_spam)|64701|65536|27|0.0%|5.8%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|27|0.0%|5.8%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|27|0.0%|5.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|19|0.0%|4.1%|
[alienvault_reputation](#alienvault_reputation)|189179|189179|19|0.0%|4.1%|
[php_harvesters](#php_harvesters)|408|408|15|3.6%|3.2%|
[xroxy](#xroxy)|2175|2175|13|0.5%|2.8%|
[nixspam](#nixspam)|21496|21496|13|0.0%|2.8%|
[openbl_60d](#openbl_60d)|6959|6959|12|0.1%|2.6%|
[proxz](#proxz)|1367|1367|10|0.7%|2.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|10|0.0%|2.1%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|8|0.0%|1.7%|
[ri_connect_proxies](#ri_connect_proxies)|2876|2876|6|0.2%|1.3%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2599|2599|6|0.2%|1.3%|
[sorbs_web](#sorbs_web)|643|644|4|0.6%|0.8%|
[proxyrss](#proxyrss)|1455|1455|4|0.2%|0.8%|
[dragon_http](#dragon_http)|1021|268288|4|0.0%|0.8%|
[iw_spamlist](#iw_spamlist)|3418|3418|3|0.0%|0.6%|
[zeus_badips](#zeus_badips)|202|202|1|0.4%|0.2%|
[zeus](#zeus)|230|230|1|0.4%|0.2%|
[openbl_7d](#openbl_7d)|637|637|1|0.1%|0.2%|
[openbl_30d](#openbl_30d)|2789|2789|1|0.0%|0.2%|
[openbl_1d](#openbl_1d)|131|131|1|0.7%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.2%|
[fullbogons](#fullbogons)|3788|670093640|1|0.0%|0.2%|
[et_compromised](#et_compromised)|1704|1704|1|0.0%|0.2%|
[dshield](#dshield)|20|5120|1|0.0%|0.2%|
[bruteforceblocker](#bruteforceblocker)|1696|1696|1|0.0%|0.2%|
[bogons](#bogons)|13|592708608|1|0.0%|0.2%|
[blocklist_de_ssh](#blocklist_de_ssh)|2474|2474|1|0.0%|0.2%|

## php_dictionary

[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) directory attackers (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=d&rss=1).

The last time downloaded was found to be dated: Fri Jun 12 12:20:44 UTC 2015.

The ipset `php_dictionary` has **777** entries, **777** unique IPs.

The following table shows the overlaps of `php_dictionary` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `php_dictionary`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `php_dictionary`.
- ` this % ` is the percentage **of this ipset (`php_dictionary`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level3](#firehol_level3)|109554|9627189|777|0.0%|100.0%|
[php_spammers](#php_spammers)|777|777|350|45.0%|45.0%|
[sorbs_spam](#sorbs_spam)|64701|65536|217|0.3%|27.9%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|217|0.3%|27.9%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|217|0.3%|27.9%|
[stopforumspam_30d](#stopforumspam_30d)|94236|94236|142|0.1%|18.2%|
[firehol_level2](#firehol_level2)|21534|33114|121|0.3%|15.5%|
[nixspam](#nixspam)|21496|21496|120|0.5%|15.4%|
[blocklist_de](#blocklist_de)|27919|27919|114|0.4%|14.6%|
[firehol_anonymous](#firehol_anonymous)|19277|83325|101|0.1%|12.9%|
[firehol_proxies](#firehol_proxies)|12718|12994|100|0.7%|12.8%|
[snort_ipfilter](#snort_ipfilter)|9136|9136|97|1.0%|12.4%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|95|0.3%|12.2%|
[blocklist_de_mail](#blocklist_de_mail)|18003|18003|93|0.5%|11.9%|
[ri_web_proxies](#ri_web_proxies)|7996|7996|69|0.8%|8.8%|
[xroxy](#xroxy)|2175|2175|42|1.9%|5.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|39|0.0%|5.0%|
[php_commenters](#php_commenters)|458|458|38|8.2%|4.8%|
[sorbs_web](#sorbs_web)|643|644|35|5.4%|4.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|30|0.0%|3.8%|
[stopforumspam_1d](#stopforumspam_1d)|6629|6629|29|0.4%|3.7%|
[proxz](#proxz)|1367|1367|26|1.9%|3.3%|
[blocklist_de_bots](#blocklist_de_bots)|3014|3014|17|0.5%|2.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|12|0.0%|1.5%|
[ri_connect_proxies](#ri_connect_proxies)|2876|2876|7|0.2%|0.9%|
[alienvault_reputation](#alienvault_reputation)|189179|189179|7|0.0%|0.9%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|6|0.0%|0.7%|
[iw_spamlist](#iw_spamlist)|3418|3418|6|0.1%|0.7%|
[firehol_level1](#firehol_level1)|5070|688775051|6|0.0%|0.7%|
[et_block](#et_block)|1000|18343756|6|0.0%|0.7%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|5|0.9%|0.6%|
[blocklist_de_strongips](#blocklist_de_strongips)|169|169|5|2.9%|0.6%|
[tor_exits](#tor_exits)|1106|1106|4|0.3%|0.5%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|4|0.0%|0.5%|
[et_tor](#et_tor)|6500|6500|4|0.0%|0.5%|
[dm_tor](#dm_tor)|6521|6521|4|0.0%|0.5%|
[bm_tor](#bm_tor)|6496|6496|4|0.0%|0.5%|
[php_harvesters](#php_harvesters)|408|408|3|0.7%|0.3%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|3|0.0%|0.3%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|2|0.3%|0.2%|
[dragon_http](#dragon_http)|1021|268288|2|0.0%|0.2%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2599|2599|2|0.0%|0.2%|
[blocklist_de_apache](#blocklist_de_apache)|13988|13988|2|0.0%|0.2%|
[sorbs_socks](#sorbs_socks)|7|7|1|14.2%|0.1%|
[sorbs_misc](#sorbs_misc)|7|7|1|14.2%|0.1%|
[sorbs_http](#sorbs_http)|7|7|1|14.2%|0.1%|
[proxyrss](#proxyrss)|1455|1455|1|0.0%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.1%|
[blocklist_de_ftp](#blocklist_de_ftp)|1500|1500|1|0.0%|0.1%|

## php_harvesters

[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) harvesters (IPs that surf the internet looking for email addresses) (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=h&rss=1).

The last time downloaded was found to be dated: Fri Jun 12 12:20:42 UTC 2015.

The ipset `php_harvesters` has **408** entries, **408** unique IPs.

The following table shows the overlaps of `php_harvesters` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `php_harvesters`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `php_harvesters`.
- ` this % ` is the percentage **of this ipset (`php_harvesters`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level3](#firehol_level3)|109554|9627189|408|0.0%|100.0%|
[stopforumspam_30d](#stopforumspam_30d)|94236|94236|87|0.0%|21.3%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|65|0.2%|15.9%|
[firehol_level2](#firehol_level2)|21534|33114|54|0.1%|13.2%|
[stopforumspam_1d](#stopforumspam_1d)|6629|6629|42|0.6%|10.2%|
[blocklist_de](#blocklist_de)|27919|27919|36|0.1%|8.8%|
[blocklist_de_bots](#blocklist_de_bots)|3014|3014|27|0.8%|6.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|20|0.0%|4.9%|
[sorbs_spam](#sorbs_spam)|64701|65536|16|0.0%|3.9%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|16|0.0%|3.9%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|16|0.0%|3.9%|
[php_commenters](#php_commenters)|458|458|15|3.2%|3.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|12|0.0%|2.9%|
[firehol_proxies](#firehol_proxies)|12718|12994|12|0.0%|2.9%|
[firehol_anonymous](#firehol_anonymous)|19277|83325|12|0.0%|2.9%|
[alienvault_reputation](#alienvault_reputation)|189179|189179|12|0.0%|2.9%|
[snort_ipfilter](#snort_ipfilter)|9136|9136|11|0.1%|2.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|9|0.0%|2.2%|
[nixspam](#nixspam)|21496|21496|8|0.0%|1.9%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|7|1.3%|1.7%|
[et_tor](#et_tor)|6500|6500|7|0.1%|1.7%|
[dm_tor](#dm_tor)|6521|6521|7|0.1%|1.7%|
[bm_tor](#bm_tor)|6496|6496|7|0.1%|1.7%|
[tor_exits](#tor_exits)|1106|1106|6|0.5%|1.4%|
[blocklist_de_mail](#blocklist_de_mail)|18003|18003|5|0.0%|1.2%|
[iw_spamlist](#iw_spamlist)|3418|3418|4|0.1%|0.9%|
[php_spammers](#php_spammers)|777|777|3|0.3%|0.7%|
[php_dictionary](#php_dictionary)|777|777|3|0.3%|0.7%|
[firehol_level1](#firehol_level1)|5070|688775051|3|0.0%|0.7%|
[blocklist_de_strongips](#blocklist_de_strongips)|169|169|3|1.7%|0.7%|
[blocklist_de_ftp](#blocklist_de_ftp)|1500|1500|3|0.2%|0.7%|
[xroxy](#xroxy)|2175|2175|2|0.0%|0.4%|
[ri_web_proxies](#ri_web_proxies)|7996|7996|2|0.0%|0.4%|
[openbl_60d](#openbl_60d)|6959|6959|2|0.0%|0.4%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|2|0.0%|0.4%|
[blocklist_de_imap](#blocklist_de_imap)|3043|3043|2|0.0%|0.4%|
[blocklist_de_apache](#blocklist_de_apache)|13988|13988|2|0.0%|0.4%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|1|0.0%|0.2%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|1|0.0%|0.2%|
[sorbs_web](#sorbs_web)|643|644|1|0.1%|0.2%|
[ri_connect_proxies](#ri_connect_proxies)|2876|2876|1|0.0%|0.2%|
[proxyrss](#proxyrss)|1455|1455|1|0.0%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.2%|
[fullbogons](#fullbogons)|3788|670093640|1|0.0%|0.2%|
[et_block](#et_block)|1000|18343756|1|0.0%|0.2%|
[bogons](#bogons)|13|592708608|1|0.0%|0.2%|
[blocklist_de_ssh](#blocklist_de_ssh)|2474|2474|1|0.0%|0.2%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2599|2599|1|0.0%|0.2%|

## php_spammers

[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) spam servers (IPs used by spammers to send messages) (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=s&rss=1).

The last time downloaded was found to be dated: Fri Jun 12 12:20:43 UTC 2015.

The ipset `php_spammers` has **777** entries, **777** unique IPs.

The following table shows the overlaps of `php_spammers` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `php_spammers`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `php_spammers`.
- ` this % ` is the percentage **of this ipset (`php_spammers`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level3](#firehol_level3)|109554|9627189|777|0.0%|100.0%|
[php_dictionary](#php_dictionary)|777|777|350|45.0%|45.0%|
[sorbs_spam](#sorbs_spam)|64701|65536|190|0.2%|24.4%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|190|0.2%|24.4%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|190|0.2%|24.4%|
[stopforumspam_30d](#stopforumspam_30d)|94236|94236|155|0.1%|19.9%|
[firehol_level2](#firehol_level2)|21534|33114|120|0.3%|15.4%|
[blocklist_de](#blocklist_de)|27919|27919|109|0.3%|14.0%|
[nixspam](#nixspam)|21496|21496|108|0.5%|13.8%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|96|0.3%|12.3%|
[snort_ipfilter](#snort_ipfilter)|9136|9136|86|0.9%|11.0%|
[firehol_anonymous](#firehol_anonymous)|19277|83325|84|0.1%|10.8%|
[firehol_proxies](#firehol_proxies)|12718|12994|82|0.6%|10.5%|
[blocklist_de_mail](#blocklist_de_mail)|18003|18003|78|0.4%|10.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|60|0.0%|7.7%|
[ri_web_proxies](#ri_web_proxies)|7996|7996|56|0.7%|7.2%|
[php_commenters](#php_commenters)|458|458|55|12.0%|7.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|44|0.0%|5.6%|
[stopforumspam_1d](#stopforumspam_1d)|6629|6629|42|0.6%|5.4%|
[xroxy](#xroxy)|2175|2175|35|1.6%|4.5%|
[sorbs_web](#sorbs_web)|643|644|28|4.3%|3.6%|
[proxz](#proxz)|1367|1367|23|1.6%|2.9%|
[blocklist_de_bots](#blocklist_de_bots)|3014|3014|23|0.7%|2.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|11|0.0%|1.4%|
[blocklist_de_strongips](#blocklist_de_strongips)|169|169|10|5.9%|1.2%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|6|1.1%|0.7%|
[tor_exits](#tor_exits)|1106|1106|5|0.4%|0.6%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|5|0.0%|0.6%|
[firehol_level1](#firehol_level1)|5070|688775051|5|0.0%|0.6%|
[et_tor](#et_tor)|6500|6500|5|0.0%|0.6%|
[et_block](#et_block)|1000|18343756|5|0.0%|0.6%|
[dm_tor](#dm_tor)|6521|6521|5|0.0%|0.6%|
[bm_tor](#bm_tor)|6496|6496|5|0.0%|0.6%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2599|2599|5|0.1%|0.6%|
[blocklist_de_apache](#blocklist_de_apache)|13988|13988|5|0.0%|0.6%|
[alienvault_reputation](#alienvault_reputation)|189179|189179|5|0.0%|0.6%|
[ri_connect_proxies](#ri_connect_proxies)|2876|2876|4|0.1%|0.5%|
[iw_spamlist](#iw_spamlist)|3418|3418|4|0.1%|0.5%|
[php_harvesters](#php_harvesters)|408|408|3|0.7%|0.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|0.3%|
[proxyrss](#proxyrss)|1455|1455|2|0.1%|0.2%|
[openbl_7d](#openbl_7d)|637|637|1|0.1%|0.1%|
[openbl_60d](#openbl_60d)|6959|6959|1|0.0%|0.1%|
[openbl_30d](#openbl_30d)|2789|2789|1|0.0%|0.1%|
[openbl_1d](#openbl_1d)|131|131|1|0.7%|0.1%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|1|0.1%|0.1%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|1|0.0%|0.1%|
[et_compromised](#et_compromised)|1704|1704|1|0.0%|0.1%|
[bruteforceblocker](#bruteforceblocker)|1696|1696|1|0.0%|0.1%|
[blocklist_de_ssh](#blocklist_de_ssh)|2474|2474|1|0.0%|0.1%|
[blocklist_de_ftp](#blocklist_de_ftp)|1500|1500|1|0.0%|0.1%|

## proxyrss

[proxyrss.com](http://www.proxyrss.com) open proxies syndicated from multiple sources.

Source is downloaded from [this link](http://www.proxyrss.com/proxylists/all.gz).

The last time downloaded was found to be dated: Fri Jun 12 09:21:27 UTC 2015.

The ipset `proxyrss` has **1455** entries, **1455** unique IPs.

The following table shows the overlaps of `proxyrss` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `proxyrss`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `proxyrss`.
- ` this % ` is the percentage **of this ipset (`proxyrss`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_proxies](#firehol_proxies)|12718|12994|1455|11.1%|100.0%|
[firehol_anonymous](#firehol_anonymous)|19277|83325|1455|1.7%|100.0%|
[stopforumspam_30d](#stopforumspam_30d)|94236|94236|706|0.7%|48.5%|
[firehol_level3](#firehol_level3)|109554|9627189|706|0.0%|48.5%|
[ri_web_proxies](#ri_web_proxies)|7996|7996|603|7.5%|41.4%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|528|1.8%|36.2%|
[firehol_level2](#firehol_level2)|21534|33114|375|1.1%|25.7%|
[xroxy](#xroxy)|2175|2175|355|16.3%|24.3%|
[stopforumspam_1d](#stopforumspam_1d)|6629|6629|310|4.6%|21.3%|
[proxz](#proxz)|1367|1367|283|20.7%|19.4%|
[blocklist_de_bots](#blocklist_de_bots)|3014|3014|208|6.9%|14.2%|
[blocklist_de](#blocklist_de)|27919|27919|208|0.7%|14.2%|
[ri_connect_proxies](#ri_connect_proxies)|2876|2876|193|6.7%|13.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|53|0.0%|3.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|48|0.0%|3.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|28|0.0%|1.9%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|12|1.8%|0.8%|
[nixspam](#nixspam)|21496|21496|9|0.0%|0.6%|
[sorbs_spam](#sorbs_spam)|64701|65536|7|0.0%|0.4%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|7|0.0%|0.4%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|7|0.0%|0.4%|
[blocklist_de_strongips](#blocklist_de_strongips)|169|169|6|3.5%|0.4%|
[php_commenters](#php_commenters)|458|458|4|0.8%|0.2%|
[dragon_http](#dragon_http)|1021|268288|3|0.0%|0.2%|
[snort_ipfilter](#snort_ipfilter)|9136|9136|2|0.0%|0.1%|
[php_spammers](#php_spammers)|777|777|2|0.2%|0.1%|
[sorbs_web](#sorbs_web)|643|644|1|0.1%|0.0%|
[php_harvesters](#php_harvesters)|408|408|1|0.2%|0.0%|
[php_dictionary](#php_dictionary)|777|777|1|0.1%|0.0%|
[iw_spamlist](#iw_spamlist)|3418|3418|1|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.0%|
[et_compromised](#et_compromised)|1704|1704|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1696|1696|1|0.0%|0.0%|
[alienvault_reputation](#alienvault_reputation)|189179|189179|1|0.0%|0.0%|

## proxz

[proxz.com](http://www.proxz.com) open proxies (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.proxz.com/proxylists.xml).

The last time downloaded was found to be dated: Fri Jun 12 11:41:28 UTC 2015.

The ipset `proxz` has **1367** entries, **1367** unique IPs.

The following table shows the overlaps of `proxz` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `proxz`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `proxz`.
- ` this % ` is the percentage **of this ipset (`proxz`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_proxies](#firehol_proxies)|12718|12994|1367|10.5%|100.0%|
[firehol_anonymous](#firehol_anonymous)|19277|83325|1367|1.6%|100.0%|
[firehol_level3](#firehol_level3)|109554|9627189|818|0.0%|59.8%|
[stopforumspam_30d](#stopforumspam_30d)|94236|94236|812|0.8%|59.4%|
[ri_web_proxies](#ri_web_proxies)|7996|7996|625|7.8%|45.7%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|515|1.7%|37.6%|
[xroxy](#xroxy)|2175|2175|469|21.5%|34.3%|
[proxyrss](#proxyrss)|1455|1455|283|19.4%|20.7%|
[firehol_level2](#firehol_level2)|21534|33114|265|0.8%|19.3%|
[ri_connect_proxies](#ri_connect_proxies)|2876|2876|240|8.3%|17.5%|
[blocklist_de](#blocklist_de)|27919|27919|200|0.7%|14.6%|
[blocklist_de_bots](#blocklist_de_bots)|3014|3014|171|5.6%|12.5%|
[stopforumspam_1d](#stopforumspam_1d)|6629|6629|169|2.5%|12.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|106|0.0%|7.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|56|0.0%|4.0%|
[nixspam](#nixspam)|21496|21496|46|0.2%|3.3%|
[sorbs_spam](#sorbs_spam)|64701|65536|44|0.0%|3.2%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|44|0.0%|3.2%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|44|0.0%|3.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|44|0.0%|3.2%|
[snort_ipfilter](#snort_ipfilter)|9136|9136|29|0.3%|2.1%|
[blocklist_de_mail](#blocklist_de_mail)|18003|18003|29|0.1%|2.1%|
[php_dictionary](#php_dictionary)|777|777|26|3.3%|1.9%|
[php_spammers](#php_spammers)|777|777|23|2.9%|1.6%|
[php_commenters](#php_commenters)|458|458|10|2.1%|0.7%|
[sorbs_web](#sorbs_web)|643|644|8|1.2%|0.5%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|7|1.0%|0.5%|
[blocklist_de_strongips](#blocklist_de_strongips)|169|169|6|3.5%|0.4%|
[dragon_http](#dragon_http)|1021|268288|4|0.0%|0.2%|
[alienvault_reputation](#alienvault_reputation)|189179|189179|4|0.0%|0.2%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|2|0.3%|0.1%|
[et_compromised](#et_compromised)|1704|1704|2|0.1%|0.1%|
[bruteforceblocker](#bruteforceblocker)|1696|1696|2|0.1%|0.1%|
[iw_spamlist](#iw_spamlist)|3418|3418|1|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|1|0.0%|0.0%|
[et_block](#et_block)|1000|18343756|1|0.0%|0.0%|

## ri_connect_proxies

[rosinstrument.com](http://www.rosinstrument.com) open CONNECT proxies (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://tools.rosinstrument.com/proxy/plab100.xml).

The last time downloaded was found to be dated: Fri Jun 12 11:28:02 UTC 2015.

The ipset `ri_connect_proxies` has **2876** entries, **2876** unique IPs.

The following table shows the overlaps of `ri_connect_proxies` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ri_connect_proxies`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ri_connect_proxies`.
- ` this % ` is the percentage **of this ipset (`ri_connect_proxies`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_proxies](#firehol_proxies)|12718|12994|2876|22.1%|100.0%|
[firehol_anonymous](#firehol_anonymous)|19277|83325|2876|3.4%|100.0%|
[firehol_level3](#firehol_level3)|109554|9627189|1603|0.0%|55.7%|
[stopforumspam_30d](#stopforumspam_30d)|94236|94236|1602|1.6%|55.7%|
[ri_web_proxies](#ri_web_proxies)|7996|7996|1220|15.2%|42.4%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|535|1.8%|18.6%|
[xroxy](#xroxy)|2175|2175|397|18.2%|13.8%|
[proxz](#proxz)|1367|1367|240|17.5%|8.3%|
[proxyrss](#proxyrss)|1455|1455|193|13.2%|6.7%|
[firehol_level2](#firehol_level2)|21534|33114|154|0.4%|5.3%|
[stopforumspam_1d](#stopforumspam_1d)|6629|6629|111|1.6%|3.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|106|0.0%|3.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|86|0.0%|2.9%|
[blocklist_de](#blocklist_de)|27919|27919|73|0.2%|2.5%|
[blocklist_de_bots](#blocklist_de_bots)|3014|3014|70|2.3%|2.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|58|0.0%|2.0%|
[sorbs_spam](#sorbs_spam)|64701|65536|18|0.0%|0.6%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|18|0.0%|0.6%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|18|0.0%|0.6%|
[nixspam](#nixspam)|21496|21496|16|0.0%|0.5%|
[php_dictionary](#php_dictionary)|777|777|7|0.9%|0.2%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|7|1.0%|0.2%|
[snort_ipfilter](#snort_ipfilter)|9136|9136|6|0.0%|0.2%|
[php_commenters](#php_commenters)|458|458|6|1.3%|0.2%|
[php_spammers](#php_spammers)|777|777|4|0.5%|0.1%|
[dragon_http](#dragon_http)|1021|268288|4|0.0%|0.1%|
[alienvault_reputation](#alienvault_reputation)|189179|189179|3|0.0%|0.1%|
[blocklist_de_mail](#blocklist_de_mail)|18003|18003|2|0.0%|0.0%|
[sorbs_web](#sorbs_web)|643|644|1|0.1%|0.0%|
[php_harvesters](#php_harvesters)|408|408|1|0.2%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|1|0.1%|0.0%|
[iw_spamlist](#iw_spamlist)|3418|3418|1|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.0%|
[et_tor](#et_tor)|6500|6500|1|0.0%|0.0%|
[dm_tor](#dm_tor)|6521|6521|1|0.0%|0.0%|
[bm_tor](#bm_tor)|6496|6496|1|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13988|13988|1|0.0%|0.0%|

## ri_web_proxies

[rosinstrument.com](http://www.rosinstrument.com) open HTTP proxies (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://tools.rosinstrument.com/proxy/l100.xml).

The last time downloaded was found to be dated: Fri Jun 12 11:26:24 UTC 2015.

The ipset `ri_web_proxies` has **7996** entries, **7996** unique IPs.

The following table shows the overlaps of `ri_web_proxies` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ri_web_proxies`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ri_web_proxies`.
- ` this % ` is the percentage **of this ipset (`ri_web_proxies`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_proxies](#firehol_proxies)|12718|12994|7996|61.5%|100.0%|
[firehol_anonymous](#firehol_anonymous)|19277|83325|7996|9.5%|100.0%|
[firehol_level3](#firehol_level3)|109554|9627189|3788|0.0%|47.3%|
[stopforumspam_30d](#stopforumspam_30d)|94236|94236|3745|3.9%|46.8%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|1490|5.1%|18.6%|
[ri_connect_proxies](#ri_connect_proxies)|2876|2876|1220|42.4%|15.2%|
[xroxy](#xroxy)|2175|2175|966|44.4%|12.0%|
[firehol_level2](#firehol_level2)|21534|33114|667|2.0%|8.3%|
[proxz](#proxz)|1367|1367|625|45.7%|7.8%|
[proxyrss](#proxyrss)|1455|1455|603|41.4%|7.5%|
[blocklist_de](#blocklist_de)|27919|27919|480|1.7%|6.0%|
[stopforumspam_1d](#stopforumspam_1d)|6629|6629|415|6.2%|5.1%|
[blocklist_de_bots](#blocklist_de_bots)|3014|3014|394|13.0%|4.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|225|0.0%|2.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|221|0.0%|2.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|156|0.0%|1.9%|
[sorbs_spam](#sorbs_spam)|64701|65536|145|0.2%|1.8%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|145|0.2%|1.8%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|145|0.2%|1.8%|
[nixspam](#nixspam)|21496|21496|94|0.4%|1.1%|
[blocklist_de_mail](#blocklist_de_mail)|18003|18003|84|0.4%|1.0%|
[php_dictionary](#php_dictionary)|777|777|69|8.8%|0.8%|
[snort_ipfilter](#snort_ipfilter)|9136|9136|63|0.6%|0.7%|
[php_spammers](#php_spammers)|777|777|56|7.2%|0.7%|
[php_commenters](#php_commenters)|458|458|30|6.5%|0.3%|
[sorbs_web](#sorbs_web)|643|644|22|3.4%|0.2%|
[dragon_http](#dragon_http)|1021|268288|21|0.0%|0.2%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|15|2.2%|0.1%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|10|1.9%|0.1%|
[blocklist_de_strongips](#blocklist_de_strongips)|169|169|8|4.7%|0.1%|
[iw_spamlist](#iw_spamlist)|3418|3418|6|0.1%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|6|0.0%|0.0%|
[et_tor](#et_tor)|6500|6500|5|0.0%|0.0%|
[dm_tor](#dm_tor)|6521|6521|5|0.0%|0.0%|
[bm_tor](#bm_tor)|6496|6496|5|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|4|0.0%|0.0%|
[alienvault_reputation](#alienvault_reputation)|189179|189179|4|0.0%|0.0%|
[php_harvesters](#php_harvesters)|408|408|2|0.4%|0.0%|
[sslbl](#sslbl)|370|370|1|0.2%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|1|0.0%|0.0%|
[firehol_level1](#firehol_level1)|5070|688775051|1|0.0%|0.0%|
[et_compromised](#et_compromised)|1704|1704|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1696|1696|1|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2474|2474|1|0.0%|0.0%|

## shunlist

[AutoShun.org](http://autoshun.org/) IPs identified as hostile by correlating logs from distributed snort installations running the autoshun plugin

Source is downloaded from [this link](http://www.autoshun.org/files/shunlist.csv).

The last time downloaded was found to be dated: Fri Jun 12 11:30:03 UTC 2015.

The ipset `shunlist` has **1201** entries, **1201** unique IPs.

The following table shows the overlaps of `shunlist` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `shunlist`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `shunlist`.
- ` this % ` is the percentage **of this ipset (`shunlist`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level3](#firehol_level3)|109554|9627189|1201|0.0%|100.0%|
[alienvault_reputation](#alienvault_reputation)|189179|189179|1178|0.6%|98.0%|
[openbl_60d](#openbl_60d)|6959|6959|465|6.6%|38.7%|
[openbl_30d](#openbl_30d)|2789|2789|439|15.7%|36.5%|
[dragon_sshpauth](#dragon_sshpauth)|1589|1653|380|22.9%|31.6%|
[firehol_level2](#firehol_level2)|21534|33114|349|1.0%|29.0%|
[bruteforceblocker](#bruteforceblocker)|1696|1696|345|20.3%|28.7%|
[blocklist_de](#blocklist_de)|27919|27919|345|1.2%|28.7%|
[et_compromised](#et_compromised)|1704|1704|343|20.1%|28.5%|
[blocklist_de_ssh](#blocklist_de_ssh)|2474|2474|303|12.2%|25.2%|
[openbl_7d](#openbl_7d)|637|637|208|32.6%|17.3%|
[firehol_level1](#firehol_level1)|5070|688775051|160|0.0%|13.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|121|0.0%|10.0%|
[et_block](#et_block)|1000|18343756|102|0.0%|8.4%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|91|0.0%|7.5%|
[dshield](#dshield)|20|5120|83|1.6%|6.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|70|0.0%|5.8%|
[openbl_1d](#openbl_1d)|131|131|61|46.5%|5.0%|
[sslbl](#sslbl)|370|370|58|15.6%|4.8%|
[blocklist_de_apache](#blocklist_de_apache)|13988|13988|35|0.2%|2.9%|
[ciarmy](#ciarmy)|421|421|29|6.8%|2.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|27|0.0%|2.2%|
[dragon_http](#dragon_http)|1021|268288|26|0.0%|2.1%|
[blocklist_de_strongips](#blocklist_de_strongips)|169|169|19|11.2%|1.5%|
[voipbl](#voipbl)|10586|10998|14|0.1%|1.1%|
[stopforumspam_30d](#stopforumspam_30d)|94236|94236|4|0.0%|0.3%|
[blocklist_de_mail](#blocklist_de_mail)|18003|18003|4|0.0%|0.3%|
[blocklist_de_imap](#blocklist_de_imap)|3043|3043|3|0.0%|0.2%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|2|0.0%|0.1%|
[sorbs_spam](#sorbs_spam)|64701|65536|2|0.0%|0.1%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|2|0.0%|0.1%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|2|0.0%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2|0.0%|0.1%|
[dragon_vncprobe](#dragon_vncprobe)|89|89|2|2.2%|0.1%|
[blocklist_de_sip](#blocklist_de_sip)|81|81|2|2.4%|0.1%|
[tor_exits](#tor_exits)|1106|1106|1|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6629|6629|1|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9136|9136|1|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|1|0.1%|0.0%|
[firehol_proxies](#firehol_proxies)|12718|12994|1|0.0%|0.0%|
[firehol_anonymous](#firehol_anonymous)|19277|83325|1|0.0%|0.0%|
[et_tor](#et_tor)|6500|6500|1|0.0%|0.0%|
[dm_tor](#dm_tor)|6521|6521|1|0.0%|0.0%|
[bm_tor](#bm_tor)|6496|6496|1|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|1500|1500|1|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2599|2599|1|0.0%|0.0%|

## snort_ipfilter

[labs.snort.org](https://labs.snort.org/) supplied IP blacklist (this list seems to be updated frequently, but we found no information about it)

Source is downloaded from [this link](http://labs.snort.org/feeds/ip-filter.blf).

The last time downloaded was found to be dated: Fri Jun 12 04:00:00 UTC 2015.

The ipset `snort_ipfilter` has **9136** entries, **9136** unique IPs.

The following table shows the overlaps of `snort_ipfilter` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `snort_ipfilter`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `snort_ipfilter`.
- ` this % ` is the percentage **of this ipset (`snort_ipfilter`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level3](#firehol_level3)|109554|9627189|9136|0.0%|100.0%|
[firehol_anonymous](#firehol_anonymous)|19277|83325|1217|1.4%|13.3%|
[et_tor](#et_tor)|6500|6500|1088|16.7%|11.9%|
[tor_exits](#tor_exits)|1106|1106|1060|95.8%|11.6%|
[bm_tor](#bm_tor)|6496|6496|1043|16.0%|11.4%|
[dm_tor](#dm_tor)|6521|6521|1041|15.9%|11.3%|
[stopforumspam_30d](#stopforumspam_30d)|94236|94236|820|0.8%|8.9%|
[sorbs_spam](#sorbs_spam)|64701|65536|816|1.2%|8.9%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|814|1.2%|8.9%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|814|1.2%|8.9%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|667|2.2%|7.3%|
[firehol_level2](#firehol_level2)|21534|33114|526|1.5%|5.7%|
[stopforumspam_1d](#stopforumspam_1d)|6629|6629|355|5.3%|3.8%|
[firehol_proxies](#firehol_proxies)|12718|12994|327|2.5%|3.5%|
[et_block](#et_block)|1000|18343756|297|0.0%|3.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|240|0.0%|2.6%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|237|45.2%|2.5%|
[firehol_level1](#firehol_level1)|5070|688775051|237|0.0%|2.5%|
[blocklist_de](#blocklist_de)|27919|27919|201|0.7%|2.2%|
[zeus](#zeus)|230|230|200|86.9%|2.1%|
[zeus_badips](#zeus_badips)|202|202|178|88.1%|1.9%|
[nixspam](#nixspam)|21496|21496|178|0.8%|1.9%|
[blocklist_de_mail](#blocklist_de_mail)|18003|18003|152|0.8%|1.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|141|0.0%|1.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|114|0.0%|1.2%|
[alienvault_reputation](#alienvault_reputation)|189179|189179|107|0.0%|1.1%|
[php_dictionary](#php_dictionary)|777|777|97|12.4%|1.0%|
[php_spammers](#php_spammers)|777|777|86|11.0%|0.9%|
[php_commenters](#php_commenters)|458|458|71|15.5%|0.7%|
[ri_web_proxies](#ri_web_proxies)|7996|7996|63|0.7%|0.6%|
[sorbs_web](#sorbs_web)|643|644|56|8.6%|0.6%|
[iw_spamlist](#iw_spamlist)|3418|3418|44|1.2%|0.4%|
[xroxy](#xroxy)|2175|2175|42|1.9%|0.4%|
[sslbl](#sslbl)|370|370|31|8.3%|0.3%|
[blocklist_de_apache](#blocklist_de_apache)|13988|13988|30|0.2%|0.3%|
[proxz](#proxz)|1367|1367|29|2.1%|0.3%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2599|2599|28|1.0%|0.3%|
[openbl_60d](#openbl_60d)|6959|6959|24|0.3%|0.2%|
[blocklist_de_bots](#blocklist_de_bots)|3014|3014|20|0.6%|0.2%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|18|0.0%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|14|0.0%|0.1%|
[php_harvesters](#php_harvesters)|408|408|11|2.6%|0.1%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|11|0.8%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|11|0.0%|0.1%|
[dragon_http](#dragon_http)|1021|268288|11|0.0%|0.1%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|6|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2876|2876|6|0.2%|0.0%|
[sorbs_socks](#sorbs_socks)|7|7|4|57.1%|0.0%|
[sorbs_misc](#sorbs_misc)|7|7|4|57.1%|0.0%|
[sorbs_http](#sorbs_http)|7|7|4|57.1%|0.0%|
[proxyrss](#proxyrss)|1455|1455|2|0.1%|0.0%|
[openbl_30d](#openbl_30d)|2789|2789|2|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|2|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|169|169|2|1.1%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|3043|3043|2|0.0%|0.0%|
[shunlist](#shunlist)|1201|1201|1|0.0%|0.0%|
[openbl_7d](#openbl_7d)|637|637|1|0.1%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|1|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|1|0.1%|0.0%|
[dshield](#dshield)|20|5120|1|0.0%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|511|511|1|0.1%|0.0%|

## sorbs_dul

[Sorbs.net](https://www.sorbs.net/) DUL, Dynamic User IPs extracted from deltas.

Source is downloaded from [this link]().

The last time downloaded was found to be dated: Thu Jun 11 13:04:23 UTC 2015.

The ipset `sorbs_dul` has **10** entries, **4864** unique IPs.

The following table shows the overlaps of `sorbs_dul` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `sorbs_dul`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `sorbs_dul`.
- ` this % ` is the percentage **of this ipset (`sorbs_dul`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|

## sorbs_http

[Sorbs.net](https://www.sorbs.net/) HTTP proxies, extracted from deltas.

Source is downloaded from [this link]().

The last time downloaded was found to be dated: Thu Jun 11 13:04:22 UTC 2015.

The ipset `sorbs_http` has **7** entries, **7** unique IPs.

The following table shows the overlaps of `sorbs_http` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `sorbs_http`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `sorbs_http`.
- ` this % ` is the percentage **of this ipset (`sorbs_http`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[sorbs_spam](#sorbs_spam)|64701|65536|7|0.0%|100.0%|
[sorbs_socks](#sorbs_socks)|7|7|7|100.0%|100.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|7|0.0%|100.0%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|7|0.0%|100.0%|
[sorbs_misc](#sorbs_misc)|7|7|7|100.0%|100.0%|
[snort_ipfilter](#snort_ipfilter)|9136|9136|4|0.0%|57.1%|
[firehol_level3](#firehol_level3)|109554|9627189|4|0.0%|57.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|2|0.0%|28.5%|
[php_dictionary](#php_dictionary)|777|777|1|0.1%|14.2%|
[iw_spamlist](#iw_spamlist)|3418|3418|1|0.0%|14.2%|
[firehol_level2](#firehol_level2)|21534|33114|1|0.0%|14.2%|
[blocklist_de_mail](#blocklist_de_mail)|18003|18003|1|0.0%|14.2%|
[blocklist_de](#blocklist_de)|27919|27919|1|0.0%|14.2%|

## sorbs_misc

[Sorbs.net](https://www.sorbs.net/) MISC proxies, extracted from deltas.

Source is downloaded from [this link]().

The last time downloaded was found to be dated: Thu Jun 11 13:04:22 UTC 2015.

The ipset `sorbs_misc` has **7** entries, **7** unique IPs.

The following table shows the overlaps of `sorbs_misc` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `sorbs_misc`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `sorbs_misc`.
- ` this % ` is the percentage **of this ipset (`sorbs_misc`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[sorbs_spam](#sorbs_spam)|64701|65536|7|0.0%|100.0%|
[sorbs_socks](#sorbs_socks)|7|7|7|100.0%|100.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|7|0.0%|100.0%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|7|0.0%|100.0%|
[sorbs_http](#sorbs_http)|7|7|7|100.0%|100.0%|
[snort_ipfilter](#snort_ipfilter)|9136|9136|4|0.0%|57.1%|
[firehol_level3](#firehol_level3)|109554|9627189|4|0.0%|57.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|2|0.0%|28.5%|
[php_dictionary](#php_dictionary)|777|777|1|0.1%|14.2%|
[iw_spamlist](#iw_spamlist)|3418|3418|1|0.0%|14.2%|
[firehol_level2](#firehol_level2)|21534|33114|1|0.0%|14.2%|
[blocklist_de_mail](#blocklist_de_mail)|18003|18003|1|0.0%|14.2%|
[blocklist_de](#blocklist_de)|27919|27919|1|0.0%|14.2%|

## sorbs_new_spam

[Sorbs.net](https://www.sorbs.net/) NEW Spam senders, extracted from deltas.

Source is downloaded from [this link]().

The last time downloaded was found to be dated: Thu Jun 11 14:04:23 UTC 2015.

The ipset `sorbs_new_spam` has **64467** entries, **65300** unique IPs.

The following table shows the overlaps of `sorbs_new_spam` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `sorbs_new_spam`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `sorbs_new_spam`.
- ` this % ` is the percentage **of this ipset (`sorbs_new_spam`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|65300|100.0%|100.0%|
[sorbs_spam](#sorbs_spam)|64701|65536|65291|99.6%|99.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|2851|0.0%|4.3%|
[nixspam](#nixspam)|21496|21496|1929|8.9%|2.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|1736|0.0%|2.6%|
[firehol_level3](#firehol_level3)|109554|9627189|1231|0.0%|1.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|1205|0.0%|1.8%|
[firehol_level2](#firehol_level2)|21534|33114|824|2.4%|1.2%|
[snort_ipfilter](#snort_ipfilter)|9136|9136|814|8.9%|1.2%|
[blocklist_de](#blocklist_de)|27919|27919|810|2.9%|1.2%|
[iw_spamlist](#iw_spamlist)|3418|3418|794|23.2%|1.2%|
[blocklist_de_mail](#blocklist_de_mail)|18003|18003|722|4.0%|1.1%|
[stopforumspam_30d](#stopforumspam_30d)|94236|94236|326|0.3%|0.4%|
[sorbs_web](#sorbs_web)|643|644|307|47.6%|0.4%|
[php_dictionary](#php_dictionary)|777|777|217|27.9%|0.3%|
[firehol_anonymous](#firehol_anonymous)|19277|83325|201|0.2%|0.3%|
[firehol_proxies](#firehol_proxies)|12718|12994|196|1.5%|0.3%|
[php_spammers](#php_spammers)|777|777|190|24.4%|0.2%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|173|0.5%|0.2%|
[ri_web_proxies](#ri_web_proxies)|7996|7996|145|1.8%|0.2%|
[alienvault_reputation](#alienvault_reputation)|189179|189179|91|0.0%|0.1%|
[xroxy](#xroxy)|2175|2175|76|3.4%|0.1%|
[dragon_http](#dragon_http)|1021|268288|71|0.0%|0.1%|
[blocklist_de_apache](#blocklist_de_apache)|13988|13988|46|0.3%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6629|6629|45|0.6%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2599|2599|45|1.7%|0.0%|
[proxz](#proxz)|1367|1367|44|3.2%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|37|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|3043|3043|30|0.9%|0.0%|
[php_commenters](#php_commenters)|458|458|27|5.8%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3014|3014|27|0.8%|0.0%|
[firehol_level1](#firehol_level1)|5070|688775051|25|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|20|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|20|0.0%|0.0%|
[et_block](#et_block)|1000|18343756|20|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2876|2876|18|0.6%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|17|0.0%|0.0%|
[php_harvesters](#php_harvesters)|408|408|16|3.9%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|1500|1500|15|1.0%|0.0%|
[sorbs_socks](#sorbs_socks)|7|7|7|100.0%|0.0%|
[sorbs_misc](#sorbs_misc)|7|7|7|100.0%|0.0%|
[sorbs_http](#sorbs_http)|7|7|7|100.0%|0.0%|
[proxyrss](#proxyrss)|1455|1455|7|0.4%|0.0%|
[sorbs_smtp](#sorbs_smtp)|6|6|6|100.0%|0.0%|
[tor_exits](#tor_exits)|1106|1106|5|0.4%|0.0%|
[et_tor](#et_tor)|6500|6500|4|0.0%|0.0%|
[dm_tor](#dm_tor)|6521|6521|4|0.0%|0.0%|
[bm_tor](#bm_tor)|6496|6496|4|0.0%|0.0%|
[voipbl](#voipbl)|10586|10998|3|0.0%|0.0%|
[et_compromised](#et_compromised)|1704|1704|3|0.1%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1696|1696|3|0.1%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2474|2474|3|0.1%|0.0%|
[shunlist](#shunlist)|1201|1201|2|0.1%|0.0%|
[openbl_60d](#openbl_60d)|6959|6959|2|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|2|0.1%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|169|169|2|1.1%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|1|0.1%|0.0%|
[malc0de](#malc0de)|276|276|1|0.3%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|1|0.1%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.0%|
[dragon_sshpauth](#dragon_sshpauth)|1589|1653|1|0.0%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|511|511|1|0.1%|0.0%|

## sorbs_recent_spam

[Sorbs.net](https://www.sorbs.net/) RECENT Spam senders, extracted from deltas.

Source is downloaded from [this link]().

The last time downloaded was found to be dated: Thu Jun 11 14:04:23 UTC 2015.

The ipset `sorbs_recent_spam` has **64467** entries, **65300** unique IPs.

The following table shows the overlaps of `sorbs_recent_spam` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `sorbs_recent_spam`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `sorbs_recent_spam`.
- ` this % ` is the percentage **of this ipset (`sorbs_recent_spam`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|65300|100.0%|100.0%|
[sorbs_spam](#sorbs_spam)|64701|65536|65291|99.6%|99.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|2851|0.0%|4.3%|
[nixspam](#nixspam)|21496|21496|1929|8.9%|2.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|1736|0.0%|2.6%|
[firehol_level3](#firehol_level3)|109554|9627189|1231|0.0%|1.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|1205|0.0%|1.8%|
[firehol_level2](#firehol_level2)|21534|33114|824|2.4%|1.2%|
[snort_ipfilter](#snort_ipfilter)|9136|9136|814|8.9%|1.2%|
[blocklist_de](#blocklist_de)|27919|27919|810|2.9%|1.2%|
[iw_spamlist](#iw_spamlist)|3418|3418|794|23.2%|1.2%|
[blocklist_de_mail](#blocklist_de_mail)|18003|18003|722|4.0%|1.1%|
[stopforumspam_30d](#stopforumspam_30d)|94236|94236|326|0.3%|0.4%|
[sorbs_web](#sorbs_web)|643|644|307|47.6%|0.4%|
[php_dictionary](#php_dictionary)|777|777|217|27.9%|0.3%|
[firehol_anonymous](#firehol_anonymous)|19277|83325|201|0.2%|0.3%|
[firehol_proxies](#firehol_proxies)|12718|12994|196|1.5%|0.3%|
[php_spammers](#php_spammers)|777|777|190|24.4%|0.2%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|173|0.5%|0.2%|
[ri_web_proxies](#ri_web_proxies)|7996|7996|145|1.8%|0.2%|
[alienvault_reputation](#alienvault_reputation)|189179|189179|91|0.0%|0.1%|
[xroxy](#xroxy)|2175|2175|76|3.4%|0.1%|
[dragon_http](#dragon_http)|1021|268288|71|0.0%|0.1%|
[blocklist_de_apache](#blocklist_de_apache)|13988|13988|46|0.3%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6629|6629|45|0.6%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2599|2599|45|1.7%|0.0%|
[proxz](#proxz)|1367|1367|44|3.2%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|37|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|3043|3043|30|0.9%|0.0%|
[php_commenters](#php_commenters)|458|458|27|5.8%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3014|3014|27|0.8%|0.0%|
[firehol_level1](#firehol_level1)|5070|688775051|25|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|20|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|20|0.0%|0.0%|
[et_block](#et_block)|1000|18343756|20|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2876|2876|18|0.6%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|17|0.0%|0.0%|
[php_harvesters](#php_harvesters)|408|408|16|3.9%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|1500|1500|15|1.0%|0.0%|
[sorbs_socks](#sorbs_socks)|7|7|7|100.0%|0.0%|
[sorbs_misc](#sorbs_misc)|7|7|7|100.0%|0.0%|
[sorbs_http](#sorbs_http)|7|7|7|100.0%|0.0%|
[proxyrss](#proxyrss)|1455|1455|7|0.4%|0.0%|
[sorbs_smtp](#sorbs_smtp)|6|6|6|100.0%|0.0%|
[tor_exits](#tor_exits)|1106|1106|5|0.4%|0.0%|
[et_tor](#et_tor)|6500|6500|4|0.0%|0.0%|
[dm_tor](#dm_tor)|6521|6521|4|0.0%|0.0%|
[bm_tor](#bm_tor)|6496|6496|4|0.0%|0.0%|
[voipbl](#voipbl)|10586|10998|3|0.0%|0.0%|
[et_compromised](#et_compromised)|1704|1704|3|0.1%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1696|1696|3|0.1%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2474|2474|3|0.1%|0.0%|
[shunlist](#shunlist)|1201|1201|2|0.1%|0.0%|
[openbl_60d](#openbl_60d)|6959|6959|2|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|2|0.1%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|169|169|2|1.1%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|1|0.1%|0.0%|
[malc0de](#malc0de)|276|276|1|0.3%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|1|0.1%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.0%|
[dragon_sshpauth](#dragon_sshpauth)|1589|1653|1|0.0%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|511|511|1|0.1%|0.0%|

## sorbs_smtp

[Sorbs.net](https://www.sorbs.net/) SMTP Open Relays, extracted from deltas.

Source is downloaded from [this link]().

The last time downloaded was found to be dated: Thu Jun 11 19:04:05 UTC 2015.

The ipset `sorbs_smtp` has **6** entries, **6** unique IPs.

The following table shows the overlaps of `sorbs_smtp` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `sorbs_smtp`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `sorbs_smtp`.
- ` this % ` is the percentage **of this ipset (`sorbs_smtp`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|6|0.0%|100.0%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|6|0.0%|100.0%|
[sorbs_spam](#sorbs_spam)|64701|65536|5|0.0%|83.3%|

## sorbs_socks

[Sorbs.net](https://www.sorbs.net/) SOCKS proxies, extracted from deltas.

Source is downloaded from [this link]().

The last time downloaded was found to be dated: Thu Jun 11 13:04:23 UTC 2015.

The ipset `sorbs_socks` has **7** entries, **7** unique IPs.

The following table shows the overlaps of `sorbs_socks` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `sorbs_socks`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `sorbs_socks`.
- ` this % ` is the percentage **of this ipset (`sorbs_socks`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[sorbs_spam](#sorbs_spam)|64701|65536|7|0.0%|100.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|7|0.0%|100.0%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|7|0.0%|100.0%|
[sorbs_misc](#sorbs_misc)|7|7|7|100.0%|100.0%|
[sorbs_http](#sorbs_http)|7|7|7|100.0%|100.0%|
[snort_ipfilter](#snort_ipfilter)|9136|9136|4|0.0%|57.1%|
[firehol_level3](#firehol_level3)|109554|9627189|4|0.0%|57.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|2|0.0%|28.5%|
[php_dictionary](#php_dictionary)|777|777|1|0.1%|14.2%|
[iw_spamlist](#iw_spamlist)|3418|3418|1|0.0%|14.2%|
[firehol_level2](#firehol_level2)|21534|33114|1|0.0%|14.2%|
[blocklist_de_mail](#blocklist_de_mail)|18003|18003|1|0.0%|14.2%|
[blocklist_de](#blocklist_de)|27919|27919|1|0.0%|14.2%|

## sorbs_spam

[Sorbs.net](https://www.sorbs.net/) Spam senders, extracted from deltas.

Source is downloaded from [this link]().

The last time downloaded was found to be dated: Thu Jun 11 15:04:08 UTC 2015.

The ipset `sorbs_spam` has **64701** entries, **65536** unique IPs.

The following table shows the overlaps of `sorbs_spam` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `sorbs_spam`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `sorbs_spam`.
- ` this % ` is the percentage **of this ipset (`sorbs_spam`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|65291|99.9%|99.6%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|65291|99.9%|99.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|2860|0.0%|4.3%|
[nixspam](#nixspam)|21496|21496|1947|9.0%|2.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|1740|0.0%|2.6%|
[firehol_level3](#firehol_level3)|109554|9627189|1235|0.0%|1.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|1208|0.0%|1.8%|
[firehol_level2](#firehol_level2)|21534|33114|832|2.5%|1.2%|
[blocklist_de](#blocklist_de)|27919|27919|818|2.9%|1.2%|
[snort_ipfilter](#snort_ipfilter)|9136|9136|816|8.9%|1.2%|
[iw_spamlist](#iw_spamlist)|3418|3418|799|23.3%|1.2%|
[blocklist_de_mail](#blocklist_de_mail)|18003|18003|731|4.0%|1.1%|
[stopforumspam_30d](#stopforumspam_30d)|94236|94236|326|0.3%|0.4%|
[sorbs_web](#sorbs_web)|643|644|308|47.8%|0.4%|
[php_dictionary](#php_dictionary)|777|777|217|27.9%|0.3%|
[firehol_anonymous](#firehol_anonymous)|19277|83325|201|0.2%|0.3%|
[firehol_proxies](#firehol_proxies)|12718|12994|196|1.5%|0.2%|
[php_spammers](#php_spammers)|777|777|190|24.4%|0.2%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|173|0.5%|0.2%|
[ri_web_proxies](#ri_web_proxies)|7996|7996|145|1.8%|0.2%|
[alienvault_reputation](#alienvault_reputation)|189179|189179|91|0.0%|0.1%|
[xroxy](#xroxy)|2175|2175|76|3.4%|0.1%|
[dragon_http](#dragon_http)|1021|268288|72|0.0%|0.1%|
[blocklist_de_apache](#blocklist_de_apache)|13988|13988|46|0.3%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6629|6629|45|0.6%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2599|2599|45|1.7%|0.0%|
[proxz](#proxz)|1367|1367|44|3.2%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|38|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|3043|3043|31|1.0%|0.0%|
[php_commenters](#php_commenters)|458|458|27|5.8%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3014|3014|27|0.8%|0.0%|
[firehol_level1](#firehol_level1)|5070|688775051|25|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|20|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|20|0.0%|0.0%|
[et_block](#et_block)|1000|18343756|20|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2876|2876|18|0.6%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|17|0.0%|0.0%|
[php_harvesters](#php_harvesters)|408|408|16|3.9%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|1500|1500|15|1.0%|0.0%|
[sorbs_socks](#sorbs_socks)|7|7|7|100.0%|0.0%|
[sorbs_misc](#sorbs_misc)|7|7|7|100.0%|0.0%|
[sorbs_http](#sorbs_http)|7|7|7|100.0%|0.0%|
[proxyrss](#proxyrss)|1455|1455|7|0.4%|0.0%|
[tor_exits](#tor_exits)|1106|1106|5|0.4%|0.0%|
[sorbs_smtp](#sorbs_smtp)|6|6|5|83.3%|0.0%|
[et_tor](#et_tor)|6500|6500|4|0.0%|0.0%|
[dm_tor](#dm_tor)|6521|6521|4|0.0%|0.0%|
[bm_tor](#bm_tor)|6496|6496|4|0.0%|0.0%|
[voipbl](#voipbl)|10586|10998|3|0.0%|0.0%|
[et_compromised](#et_compromised)|1704|1704|3|0.1%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1696|1696|3|0.1%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2474|2474|3|0.1%|0.0%|
[shunlist](#shunlist)|1201|1201|2|0.1%|0.0%|
[openbl_60d](#openbl_60d)|6959|6959|2|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|2|0.1%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|169|169|2|1.1%|0.0%|
[virbl](#virbl)|23|23|1|4.3%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|1|0.1%|0.0%|
[malc0de](#malc0de)|276|276|1|0.3%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|1|0.1%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.0%|
[dragon_sshpauth](#dragon_sshpauth)|1589|1653|1|0.0%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|511|511|1|0.1%|0.0%|

## sorbs_web

[Sorbs.net](https://www.sorbs.net/) WEB exploits, extracted from deltas.

Source is downloaded from [this link]().

The last time downloaded was found to be dated: Fri Jun 12 12:04:04 UTC 2015.

The ipset `sorbs_web` has **643** entries, **644** unique IPs.

The following table shows the overlaps of `sorbs_web` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `sorbs_web`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `sorbs_web`.
- ` this % ` is the percentage **of this ipset (`sorbs_web`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[sorbs_spam](#sorbs_spam)|64701|65536|308|0.4%|47.8%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|307|0.4%|47.6%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|307|0.4%|47.6%|
[nixspam](#nixspam)|21496|21496|104|0.4%|16.1%|
[firehol_level3](#firehol_level3)|109554|9627189|74|0.0%|11.4%|
[firehol_level2](#firehol_level2)|21534|33114|70|0.2%|10.8%|
[blocklist_de](#blocklist_de)|27919|27919|70|0.2%|10.8%|
[blocklist_de_mail](#blocklist_de_mail)|18003|18003|65|0.3%|10.0%|
[snort_ipfilter](#snort_ipfilter)|9136|9136|56|0.6%|8.6%|
[stopforumspam_30d](#stopforumspam_30d)|94236|94236|49|0.0%|7.6%|
[php_dictionary](#php_dictionary)|777|777|35|4.5%|5.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|33|0.0%|5.1%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|32|0.1%|4.9%|
[firehol_proxies](#firehol_proxies)|12718|12994|31|0.2%|4.8%|
[firehol_anonymous](#firehol_anonymous)|19277|83325|31|0.0%|4.8%|
[php_spammers](#php_spammers)|777|777|28|3.6%|4.3%|
[iw_spamlist](#iw_spamlist)|3418|3418|26|0.7%|4.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|23|0.0%|3.5%|
[ri_web_proxies](#ri_web_proxies)|7996|7996|22|0.2%|3.4%|
[xroxy](#xroxy)|2175|2175|16|0.7%|2.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|16|0.0%|2.4%|
[proxz](#proxz)|1367|1367|8|0.5%|1.2%|
[stopforumspam_1d](#stopforumspam_1d)|6629|6629|5|0.0%|0.7%|
[php_commenters](#php_commenters)|458|458|4|0.8%|0.6%|
[blocklist_de_bots](#blocklist_de_bots)|3014|3014|4|0.1%|0.6%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|2|0.0%|0.3%|
[blocklist_de_strongips](#blocklist_de_strongips)|169|169|2|1.1%|0.3%|
[ri_connect_proxies](#ri_connect_proxies)|2876|2876|1|0.0%|0.1%|
[proxyrss](#proxyrss)|1455|1455|1|0.0%|0.1%|
[php_harvesters](#php_harvesters)|408|408|1|0.2%|0.1%|
[dragon_http](#dragon_http)|1021|268288|1|0.0%|0.1%|
[blocklist_de_ftp](#blocklist_de_ftp)|1500|1500|1|0.0%|0.1%|
[alienvault_reputation](#alienvault_reputation)|189179|189179|1|0.0%|0.1%|

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
[firehol_level1](#firehol_level1)|5070|688775051|18340608|2.6%|100.0%|
[et_block](#et_block)|1000|18343756|18338560|99.9%|99.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|8532506|2.4%|46.5%|
[firehol_level3](#firehol_level3)|109554|9627189|6933046|72.0%|37.8%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|6932480|75.5%|37.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|2272265|0.2%|12.3%|
[fullbogons](#fullbogons)|3788|670093640|151552|0.0%|0.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|130368|0.0%|0.7%|
[alienvault_reputation](#alienvault_reputation)|189179|189179|1385|0.7%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1037|0.3%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|94236|94236|1008|1.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|512|0.1%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|269|0.9%|0.0%|
[dshield](#dshield)|20|5120|256|5.0%|0.0%|
[dragon_http](#dragon_http)|1021|268288|256|0.0%|0.0%|
[firehol_level2](#firehol_level2)|21534|33114|244|0.7%|0.0%|
[openbl_60d](#openbl_60d)|6959|6959|235|3.3%|0.0%|
[blocklist_de](#blocklist_de)|27919|27919|178|0.6%|0.0%|
[openbl_30d](#openbl_30d)|2789|2789|119|4.2%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2474|2474|102|4.1%|0.0%|
[dragon_sshpauth](#dragon_sshpauth)|1589|1653|99|5.9%|0.0%|
[shunlist](#shunlist)|1201|1201|91|7.5%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6629|6629|85|1.2%|0.0%|
[et_compromised](#et_compromised)|1704|1704|65|3.8%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1696|1696|61|3.5%|0.0%|
[openbl_7d](#openbl_7d)|637|637|53|8.3%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3014|3014|47|1.5%|0.0%|
[php_commenters](#php_commenters)|458|458|29|6.3%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|29|2.2%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|18003|18003|23|0.1%|0.0%|
[nixspam](#nixspam)|21496|21496|21|0.0%|0.0%|
[sorbs_spam](#sorbs_spam)|64701|65536|20|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|20|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|20|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9136|9136|18|0.1%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|3043|3043|17|0.5%|0.0%|
[zeus_badips](#zeus_badips)|202|202|15|7.4%|0.0%|
[zeus](#zeus)|230|230|15|6.5%|0.0%|
[voipbl](#voipbl)|10586|10998|14|0.1%|0.0%|
[openbl_1d](#openbl_1d)|131|131|7|5.3%|0.0%|
[php_dictionary](#php_dictionary)|777|777|6|0.7%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|6|0.4%|0.0%|
[firehol_anonymous](#firehol_anonymous)|19277|83325|6|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|169|169|6|3.5%|0.0%|
[php_spammers](#php_spammers)|777|777|5|0.6%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|5|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2599|2599|5|0.1%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13988|13988|5|0.0%|0.0%|
[nt_malware_http](#nt_malware_http)|69|69|4|5.7%|0.0%|
[malc0de](#malc0de)|276|276|4|1.4%|0.0%|
[nt_malware_irc](#nt_malware_irc)|43|43|3|6.9%|0.0%|
[iw_spamlist](#iw_spamlist)|3418|3418|3|0.0%|0.0%|
[firehol_proxies](#firehol_proxies)|12718|12994|3|0.0%|0.0%|
[et_tor](#et_tor)|6500|6500|3|0.0%|0.0%|
[dm_tor](#dm_tor)|6521|6521|3|0.0%|0.0%|
[bm_tor](#bm_tor)|6496|6496|3|0.0%|0.0%|
[tor_exits](#tor_exits)|1106|1106|2|0.1%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|2|0.3%|0.0%|
[virbl](#virbl)|23|23|1|4.3%|0.0%|
[sslbl](#sslbl)|370|370|1|0.2%|0.0%|
[php_harvesters](#php_harvesters)|408|408|1|0.2%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|1|0.1%|0.0%|
[et_botcc](#et_botcc)|505|505|1|0.1%|0.0%|
[dragon_vncprobe](#dragon_vncprobe)|89|89|1|1.1%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|1500|1500|1|0.0%|0.0%|

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
[firehol_level1](#firehol_level1)|5070|688775051|487424|0.0%|100.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|270785|0.1%|55.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|98904|0.0%|20.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|33155|0.0%|6.8%|
[et_block](#et_block)|1000|18343756|517|0.0%|0.1%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|512|0.0%|0.1%|
[firehol_level3](#firehol_level3)|109554|9627189|82|0.0%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|94236|94236|73|0.0%|0.0%|
[sorbs_spam](#sorbs_spam)|64701|65536|20|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|20|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|20|0.0%|0.0%|
[alienvault_reputation](#alienvault_reputation)|189179|189179|14|0.0%|0.0%|
[php_commenters](#php_commenters)|458|458|8|1.7%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|7|0.0%|0.0%|
[firehol_level2](#firehol_level2)|21534|33114|7|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9136|9136|6|0.0%|0.0%|
[zeus_badips](#zeus_badips)|202|202|5|2.4%|0.0%|
[zeus](#zeus)|230|230|5|2.1%|0.0%|
[blocklist_de](#blocklist_de)|27919|27919|5|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6629|6629|4|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|169|169|2|1.1%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|18003|18003|2|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3014|3014|2|0.0%|0.0%|
[php_harvesters](#php_harvesters)|408|408|1|0.2%|0.0%|
[openbl_60d](#openbl_60d)|6959|6959|1|0.0%|0.0%|
[openbl_30d](#openbl_30d)|2789|2789|1|0.0%|0.0%|
[nixspam](#nixspam)|21496|21496|1|0.0%|0.0%|
[malc0de](#malc0de)|276|276|1|0.3%|0.0%|
[iw_spamlist](#iw_spamlist)|3418|3418|1|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13988|13988|1|0.0%|0.0%|

## sslbl

[Abuse.ch SSL Blacklist](https://sslbl.abuse.ch/) bad SSL traffic related to malware or botnet activities - **excellent list**

Source is downloaded from [this link](https://sslbl.abuse.ch/blacklist/sslipblacklist.csv).

The last time downloaded was found to be dated: Fri Jun 12 12:00:04 UTC 2015.

The ipset `sslbl` has **370** entries, **370** unique IPs.

The following table shows the overlaps of `sslbl` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `sslbl`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `sslbl`.
- ` this % ` is the percentage **of this ipset (`sslbl`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level1](#firehol_level1)|5070|688775051|370|0.0%|100.0%|
[firehol_level3](#firehol_level3)|109554|9627189|89|0.0%|24.0%|
[alienvault_reputation](#alienvault_reputation)|189179|189179|65|0.0%|17.5%|
[shunlist](#shunlist)|1201|1201|58|4.8%|15.6%|
[et_block](#et_block)|1000|18343756|39|0.0%|10.5%|
[snort_ipfilter](#snort_ipfilter)|9136|9136|31|0.3%|8.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|28|0.0%|7.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|6|0.0%|1.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|3|0.0%|0.8%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|1|0.0%|0.2%|
[ri_web_proxies](#ri_web_proxies)|7996|7996|1|0.0%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.2%|
[firehol_proxies](#firehol_proxies)|12718|12994|1|0.0%|0.2%|
[firehol_anonymous](#firehol_anonymous)|19277|83325|1|0.0%|0.2%|
[dragon_sshpauth](#dragon_sshpauth)|1589|1653|1|0.0%|0.2%|
[dragon_http](#dragon_http)|1021|268288|1|0.0%|0.2%|

## stopforumspam_1d

[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers in the last 24 hours - **excellent list**

Source is downloaded from [this link](http://www.stopforumspam.com/downloads/listed_ip_1.zip).

The last time downloaded was found to be dated: Fri Jun 12 12:00:02 UTC 2015.

The ipset `stopforumspam_1d` has **6629** entries, **6629** unique IPs.

The following table shows the overlaps of `stopforumspam_1d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `stopforumspam_1d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `stopforumspam_1d`.
- ` this % ` is the percentage **of this ipset (`stopforumspam_1d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_30d](#stopforumspam_30d)|94236|94236|6629|7.0%|100.0%|
[firehol_level3](#firehol_level3)|109554|9627189|6629|0.0%|100.0%|
[firehol_level2](#firehol_level2)|21534|33114|6629|20.0%|100.0%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|5282|18.2%|79.6%|
[blocklist_de](#blocklist_de)|27919|27919|1453|5.2%|21.9%|
[blocklist_de_bots](#blocklist_de_bots)|3014|3014|1395|46.2%|21.0%|
[firehol_anonymous](#firehol_anonymous)|19277|83325|953|1.1%|14.3%|
[firehol_proxies](#firehol_proxies)|12718|12994|800|6.1%|12.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|490|0.0%|7.3%|
[ri_web_proxies](#ri_web_proxies)|7996|7996|415|5.1%|6.2%|
[snort_ipfilter](#snort_ipfilter)|9136|9136|355|3.8%|5.3%|
[tor_exits](#tor_exits)|1106|1106|328|29.6%|4.9%|
[et_tor](#et_tor)|6500|6500|322|4.9%|4.8%|
[dm_tor](#dm_tor)|6521|6521|321|4.9%|4.8%|
[bm_tor](#bm_tor)|6496|6496|320|4.9%|4.8%|
[proxyrss](#proxyrss)|1455|1455|310|21.3%|4.6%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|199|37.9%|3.0%|
[xroxy](#xroxy)|2175|2175|194|8.9%|2.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|171|0.0%|2.5%|
[proxz](#proxz)|1367|1367|169|12.3%|2.5%|
[php_commenters](#php_commenters)|458|458|165|36.0%|2.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|127|0.0%|1.9%|
[ri_connect_proxies](#ri_connect_proxies)|2876|2876|111|3.8%|1.6%|
[blocklist_de_strongips](#blocklist_de_strongips)|169|169|102|60.3%|1.5%|
[firehol_level1](#firehol_level1)|5070|688775051|98|0.0%|1.4%|
[et_block](#et_block)|1000|18343756|93|0.0%|1.4%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|85|0.0%|1.2%|
[blocklist_de_apache](#blocklist_de_apache)|13988|13988|57|0.4%|0.8%|
[nixspam](#nixspam)|21496|21496|53|0.2%|0.7%|
[sorbs_spam](#sorbs_spam)|64701|65536|45|0.0%|0.6%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|45|0.0%|0.6%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|45|0.0%|0.6%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|45|0.0%|0.6%|
[blocklist_de_mail](#blocklist_de_mail)|18003|18003|43|0.2%|0.6%|
[alienvault_reputation](#alienvault_reputation)|189179|189179|43|0.0%|0.6%|
[php_spammers](#php_spammers)|777|777|42|5.4%|0.6%|
[php_harvesters](#php_harvesters)|408|408|42|10.2%|0.6%|
[php_dictionary](#php_dictionary)|777|777|29|3.7%|0.4%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2599|2599|21|0.8%|0.3%|
[openbl_60d](#openbl_60d)|6959|6959|19|0.2%|0.2%|
[dshield](#dshield)|20|5120|9|0.1%|0.1%|
[dragon_http](#dragon_http)|1021|268288|8|0.0%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|7|0.0%|0.1%|
[voipbl](#voipbl)|10586|10998|5|0.0%|0.0%|
[sorbs_web](#sorbs_web)|643|644|5|0.7%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|4|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|4|0.6%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|1500|1500|4|0.2%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|2|0.0%|0.0%|
[zeus_badips](#zeus_badips)|202|202|1|0.4%|0.0%|
[zeus](#zeus)|230|230|1|0.4%|0.0%|
[shunlist](#shunlist)|1201|1201|1|0.0%|0.0%|
[openbl_30d](#openbl_30d)|2789|2789|1|0.0%|0.0%|
[iw_spamlist](#iw_spamlist)|3418|3418|1|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|1|0.0%|0.0%|
[fullbogons](#fullbogons)|3788|670093640|1|0.0%|0.0%|
[et_compromised](#et_compromised)|1704|1704|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1696|1696|1|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2474|2474|1|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|3043|3043|1|0.0%|0.0%|

## stopforumspam_30d

[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 30 days)

Source is downloaded from [this link](http://www.stopforumspam.com/downloads/listed_ip_30.zip).

The last time downloaded was found to be dated: Fri Jun 12 12:00:32 UTC 2015.

The ipset `stopforumspam_30d` has **94236** entries, **94236** unique IPs.

The following table shows the overlaps of `stopforumspam_30d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `stopforumspam_30d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `stopforumspam_30d`.
- ` this % ` is the percentage **of this ipset (`stopforumspam_30d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level3](#firehol_level3)|109554|9627189|94236|0.9%|100.0%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|29017|100.0%|30.7%|
[firehol_level2](#firehol_level2)|21534|33114|8029|24.2%|8.5%|
[stopforumspam_1d](#stopforumspam_1d)|6629|6629|6629|100.0%|7.0%|
[firehol_anonymous](#firehol_anonymous)|19277|83325|6314|7.5%|6.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|5843|0.0%|6.2%|
[firehol_proxies](#firehol_proxies)|12718|12994|5702|43.8%|6.0%|
[ri_web_proxies](#ri_web_proxies)|7996|7996|3745|46.8%|3.9%|
[blocklist_de](#blocklist_de)|27919|27919|2853|10.2%|3.0%|
[blocklist_de_bots](#blocklist_de_bots)|3014|3014|2514|83.4%|2.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|2463|0.0%|2.6%|
[ri_connect_proxies](#ri_connect_proxies)|2876|2876|1602|55.7%|1.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|1526|0.0%|1.6%|
[xroxy](#xroxy)|2175|2175|1284|59.0%|1.3%|
[firehol_level1](#firehol_level1)|5070|688775051|1102|0.0%|1.1%|
[et_block](#et_block)|1000|18343756|1026|0.0%|1.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|1008|0.0%|1.0%|
[snort_ipfilter](#snort_ipfilter)|9136|9136|820|8.9%|0.8%|
[proxz](#proxz)|1367|1367|812|59.4%|0.8%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|724|0.0%|0.7%|
[proxyrss](#proxyrss)|1455|1455|706|48.5%|0.7%|
[et_tor](#et_tor)|6500|6500|662|10.1%|0.7%|
[dm_tor](#dm_tor)|6521|6521|644|9.8%|0.6%|
[bm_tor](#bm_tor)|6496|6496|644|9.9%|0.6%|
[tor_exits](#tor_exits)|1106|1106|632|57.1%|0.6%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|346|66.0%|0.3%|
[php_commenters](#php_commenters)|458|458|336|73.3%|0.3%|
[sorbs_spam](#sorbs_spam)|64701|65536|326|0.4%|0.3%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|326|0.4%|0.3%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|326|0.4%|0.3%|
[blocklist_de_mail](#blocklist_de_mail)|18003|18003|249|1.3%|0.2%|
[nixspam](#nixspam)|21496|21496|241|1.1%|0.2%|
[blocklist_de_apache](#blocklist_de_apache)|13988|13988|190|1.3%|0.2%|
[alienvault_reputation](#alienvault_reputation)|189179|189179|166|0.0%|0.1%|
[php_spammers](#php_spammers)|777|777|155|19.9%|0.1%|
[php_dictionary](#php_dictionary)|777|777|142|18.2%|0.1%|
[blocklist_de_strongips](#blocklist_de_strongips)|169|169|131|77.5%|0.1%|
[dragon_http](#dragon_http)|1021|268288|110|0.0%|0.1%|
[php_harvesters](#php_harvesters)|408|408|87|21.3%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|73|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2599|2599|58|2.2%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|52|0.0%|0.0%|
[sorbs_web](#sorbs_web)|643|644|49|7.6%|0.0%|
[openbl_60d](#openbl_60d)|6959|6959|47|0.6%|0.0%|
[voipbl](#voipbl)|10586|10998|35|0.3%|0.0%|
[iw_spamlist](#iw_spamlist)|3418|3418|22|0.6%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|20|3.0%|0.0%|
[dshield](#dshield)|20|5120|20|0.3%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2474|2474|19|0.7%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|16|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|3043|3043|16|0.5%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|1500|1500|14|0.9%|0.0%|
[et_compromised](#et_compromised)|1704|1704|10|0.5%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1696|1696|9|0.5%|0.0%|
[openbl_30d](#openbl_30d)|2789|2789|5|0.1%|0.0%|
[shunlist](#shunlist)|1201|1201|4|0.3%|0.0%|
[dragon_sshpauth](#dragon_sshpauth)|1589|1653|4|0.2%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|3|0.2%|0.0%|
[fullbogons](#fullbogons)|3788|670093640|3|0.0%|0.0%|
[zeus_badips](#zeus_badips)|202|202|2|0.9%|0.0%|
[zeus](#zeus)|230|230|2|0.8%|0.0%|
[openbl_7d](#openbl_7d)|637|637|2|0.3%|0.0%|
[nt_malware_http](#nt_malware_http)|69|69|2|2.8%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|2|0.1%|0.0%|
[ciarmy](#ciarmy)|421|421|2|0.4%|0.0%|
[openbl_1d](#openbl_1d)|131|131|1|0.7%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|511|511|1|0.1%|0.0%|

## stopforumspam_7d

[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 7 days)

Source is downloaded from [this link](http://www.stopforumspam.com/downloads/listed_ip_7.zip).

The last time downloaded was found to be dated: Fri Jun 12 01:02:34 UTC 2015.

The ipset `stopforumspam_7d` has **29017** entries, **29017** unique IPs.

The following table shows the overlaps of `stopforumspam_7d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `stopforumspam_7d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `stopforumspam_7d`.
- ` this % ` is the percentage **of this ipset (`stopforumspam_7d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_30d](#stopforumspam_30d)|94236|94236|29017|30.7%|100.0%|
[firehol_level3](#firehol_level3)|109554|9627189|29017|0.3%|100.0%|
[firehol_level2](#firehol_level2)|21534|33114|6322|19.0%|21.7%|
[stopforumspam_1d](#stopforumspam_1d)|6629|6629|5282|79.6%|18.2%|
[firehol_anonymous](#firehol_anonymous)|19277|83325|2730|3.2%|9.4%|
[firehol_proxies](#firehol_proxies)|12718|12994|2366|18.2%|8.1%|
[blocklist_de](#blocklist_de)|27919|27919|2340|8.3%|8.0%|
[blocklist_de_bots](#blocklist_de_bots)|3014|3014|2168|71.9%|7.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|1961|0.0%|6.7%|
[ri_web_proxies](#ri_web_proxies)|7996|7996|1490|18.6%|5.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|736|0.0%|2.5%|
[snort_ipfilter](#snort_ipfilter)|9136|9136|667|7.3%|2.2%|
[xroxy](#xroxy)|2175|2175|586|26.9%|2.0%|
[et_tor](#et_tor)|6500|6500|547|8.4%|1.8%|
[tor_exits](#tor_exits)|1106|1106|537|48.5%|1.8%|
[ri_connect_proxies](#ri_connect_proxies)|2876|2876|535|18.6%|1.8%|
[proxyrss](#proxyrss)|1455|1455|528|36.2%|1.8%|
[dm_tor](#dm_tor)|6521|6521|528|8.0%|1.8%|
[bm_tor](#bm_tor)|6496|6496|528|8.1%|1.8%|
[proxz](#proxz)|1367|1367|515|37.6%|1.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|510|0.0%|1.7%|
[firehol_level1](#firehol_level1)|5070|688775051|291|0.0%|1.0%|
[et_block](#et_block)|1000|18343756|283|0.0%|0.9%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|277|52.8%|0.9%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|269|0.0%|0.9%|
[php_commenters](#php_commenters)|458|458|248|54.1%|0.8%|
[sorbs_spam](#sorbs_spam)|64701|65536|173|0.2%|0.5%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|173|0.2%|0.5%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|173|0.2%|0.5%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|154|0.0%|0.5%|
[blocklist_de_mail](#blocklist_de_mail)|18003|18003|132|0.7%|0.4%|
[nixspam](#nixspam)|21496|21496|131|0.6%|0.4%|
[blocklist_de_strongips](#blocklist_de_strongips)|169|169|116|68.6%|0.3%|
[blocklist_de_apache](#blocklist_de_apache)|13988|13988|108|0.7%|0.3%|
[php_spammers](#php_spammers)|777|777|96|12.3%|0.3%|
[php_dictionary](#php_dictionary)|777|777|95|12.2%|0.3%|
[alienvault_reputation](#alienvault_reputation)|189179|189179|88|0.0%|0.3%|
[php_harvesters](#php_harvesters)|408|408|65|15.9%|0.2%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2599|2599|37|1.4%|0.1%|
[sorbs_web](#sorbs_web)|643|644|32|4.9%|0.1%|
[dragon_http](#dragon_http)|1021|268288|32|0.0%|0.1%|
[openbl_60d](#openbl_60d)|6959|6959|26|0.3%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|21|0.0%|0.0%|
[voipbl](#voipbl)|10586|10998|15|0.1%|0.0%|
[dshield](#dshield)|20|5120|15|0.2%|0.0%|
[iw_spamlist](#iw_spamlist)|3418|3418|13|0.3%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|10|1.5%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|7|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|7|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|3043|3043|6|0.1%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|1500|1500|6|0.4%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2474|2474|5|0.2%|0.0%|
[et_compromised](#et_compromised)|1704|1704|3|0.1%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1696|1696|3|0.1%|0.0%|
[shunlist](#shunlist)|1201|1201|2|0.1%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|2|0.1%|0.0%|
[fullbogons](#fullbogons)|3788|670093640|2|0.0%|0.0%|
[zeus_badips](#zeus_badips)|202|202|1|0.4%|0.0%|
[zeus](#zeus)|230|230|1|0.4%|0.0%|
[openbl_30d](#openbl_30d)|2789|2789|1|0.0%|0.0%|
[ciarmy](#ciarmy)|421|421|1|0.2%|0.0%|

## tor_exits

[TorProject.org](https://www.torproject.org) list of all current TOR exit points (TorDNSEL)

Source is downloaded from [this link](https://check.torproject.org/exit-addresses).

The last time downloaded was found to be dated: Fri Jun 12 12:02:20 UTC 2015.

The ipset `tor_exits` has **1106** entries, **1106** unique IPs.

The following table shows the overlaps of `tor_exits` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `tor_exits`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `tor_exits`.
- ` this % ` is the percentage **of this ipset (`tor_exits`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_anonymous](#firehol_anonymous)|19277|83325|1106|1.3%|100.0%|
[firehol_level3](#firehol_level3)|109554|9627189|1064|0.0%|96.2%|
[snort_ipfilter](#snort_ipfilter)|9136|9136|1060|11.6%|95.8%|
[dm_tor](#dm_tor)|6521|6521|1018|15.6%|92.0%|
[bm_tor](#bm_tor)|6496|6496|1008|15.5%|91.1%|
[et_tor](#et_tor)|6500|6500|968|14.8%|87.5%|
[stopforumspam_30d](#stopforumspam_30d)|94236|94236|632|0.6%|57.1%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|537|1.8%|48.5%|
[firehol_level2](#firehol_level2)|21534|33114|337|1.0%|30.4%|
[stopforumspam_1d](#stopforumspam_1d)|6629|6629|328|4.9%|29.6%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|230|43.8%|20.7%|
[firehol_proxies](#firehol_proxies)|12718|12994|230|1.7%|20.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|126|0.0%|11.3%|
[php_commenters](#php_commenters)|458|458|54|11.7%|4.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|40|0.0%|3.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|37|0.0%|3.3%|
[alienvault_reputation](#alienvault_reputation)|189179|189179|30|0.0%|2.7%|
[openbl_60d](#openbl_60d)|6959|6959|20|0.2%|1.8%|
[blocklist_de_apache](#blocklist_de_apache)|13988|13988|16|0.1%|1.4%|
[blocklist_de](#blocklist_de)|27919|27919|16|0.0%|1.4%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2599|2599|14|0.5%|1.2%|
[nixspam](#nixspam)|21496|21496|9|0.0%|0.8%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|8|0.0%|0.7%|
[php_harvesters](#php_harvesters)|408|408|6|1.4%|0.5%|
[sorbs_spam](#sorbs_spam)|64701|65536|5|0.0%|0.4%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|5|0.0%|0.4%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|5|0.0%|0.4%|
[php_spammers](#php_spammers)|777|777|5|0.6%|0.4%|
[dragon_http](#dragon_http)|1021|268288|5|0.0%|0.4%|
[php_dictionary](#php_dictionary)|777|777|4|0.5%|0.3%|
[firehol_level1](#firehol_level1)|5070|688775051|3|0.0%|0.2%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|2|0.0%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2|0.0%|0.1%|
[et_block](#et_block)|1000|18343756|2|0.0%|0.1%|
[blocklist_de_mail](#blocklist_de_mail)|18003|18003|2|0.0%|0.1%|
[shunlist](#shunlist)|1201|1201|1|0.0%|0.0%|
[dshield](#dshield)|20|5120|1|0.0%|0.0%|

## virbl

[VirBL](http://virbl.bit.nl/) is a project of which the idea was born during the RIPE-48 meeting. The plan was to get reports of virusscanning mailservers, and put the IP-addresses that were reported to send viruses on a blacklist.

Source is downloaded from [this link](http://virbl.bit.nl/download/virbl.dnsbl.bit.nl.txt).

The last time downloaded was found to be dated: Fri Jun 12 11:42:04 UTC 2015.

The ipset `virbl` has **23** entries, **23** unique IPs.

The following table shows the overlaps of `virbl` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `virbl`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `virbl`.
- ` this % ` is the percentage **of this ipset (`virbl`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level3](#firehol_level3)|109554|9627189|23|0.0%|100.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|1|0.0%|4.3%|
[sorbs_spam](#sorbs_spam)|64701|65536|1|0.0%|4.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|1|0.0%|4.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|4.3%|
[firehol_level2](#firehol_level2)|21534|33114|1|0.0%|4.3%|
[firehol_level1](#firehol_level1)|5070|688775051|1|0.0%|4.3%|
[et_block](#et_block)|1000|18343756|1|0.0%|4.3%|
[blocklist_de_mail](#blocklist_de_mail)|18003|18003|1|0.0%|4.3%|
[blocklist_de_imap](#blocklist_de_imap)|3043|3043|1|0.0%|4.3%|
[blocklist_de](#blocklist_de)|27919|27919|1|0.0%|4.3%|

## voipbl

[VoIPBL.org](http://www.voipbl.org/) a distributed VoIP blacklist that is aimed to protects against VoIP Fraud and minimizing abuse for network that have publicly accessible PBX's. Several algorithms, external sources and manual confirmation are used before they categorize something as an attack and determine the threat level.

Source is downloaded from [this link](http://www.voipbl.org/update/).

The last time downloaded was found to be dated: Fri Jun 12 12:00:37 UTC 2015.

The ipset `voipbl` has **10586** entries, **10998** unique IPs.

The following table shows the overlaps of `voipbl` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `voipbl`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `voipbl`.
- ` this % ` is the percentage **of this ipset (`voipbl`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|1613|0.0%|14.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|436|0.0%|3.9%|
[firehol_level1](#firehol_level1)|5070|688775051|333|0.0%|3.0%|
[fullbogons](#fullbogons)|3788|670093640|319|0.0%|2.9%|
[bogons](#bogons)|13|592708608|319|0.0%|2.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|302|0.0%|2.7%|
[alienvault_reputation](#alienvault_reputation)|189179|189179|176|0.0%|1.6%|
[firehol_anonymous](#firehol_anonymous)|19277|83325|79|0.0%|0.7%|
[firehol_level3](#firehol_level3)|109554|9627189|58|0.0%|0.5%|
[firehol_level2](#firehol_level2)|21534|33114|43|0.1%|0.3%|
[blocklist_de](#blocklist_de)|27919|27919|39|0.1%|0.3%|
[stopforumspam_30d](#stopforumspam_30d)|94236|94236|35|0.0%|0.3%|
[blocklist_de_sip](#blocklist_de_sip)|81|81|32|39.5%|0.2%|
[dragon_http](#dragon_http)|1021|268288|29|0.0%|0.2%|
[et_block](#et_block)|1000|18343756|18|0.0%|0.1%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|15|0.0%|0.1%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|14|0.0%|0.1%|
[shunlist](#shunlist)|1201|1201|14|1.1%|0.1%|
[openbl_60d](#openbl_60d)|6959|6959|8|0.1%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6629|6629|5|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|4|0.0%|0.0%|
[sorbs_spam](#sorbs_spam)|64701|65536|3|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|3|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|3|0.0%|0.0%|
[openbl_30d](#openbl_30d)|2789|2789|3|0.1%|0.0%|
[et_tor](#et_tor)|6500|6500|3|0.0%|0.0%|
[et_compromised](#et_compromised)|1704|1704|3|0.1%|0.0%|
[dm_tor](#dm_tor)|6521|6521|3|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1696|1696|3|0.1%|0.0%|
[bm_tor](#bm_tor)|6496|6496|3|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|2|0.3%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|2|0.0%|0.0%|
[firehol_proxies](#firehol_proxies)|12718|12994|2|0.0%|0.0%|
[ciarmy](#ciarmy)|421|421|2|0.4%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2474|2474|2|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|18003|18003|2|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13988|13988|2|0.0%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.0%|
[dragon_vncprobe](#dragon_vncprobe)|89|89|1|1.1%|0.0%|
[dragon_sshpauth](#dragon_sshpauth)|1589|1653|1|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|3043|3043|1|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3014|3014|1|0.0%|0.0%|

## xroxy

[xroxy.com](http://www.xroxy.com) open proxies (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.xroxy.com/proxyrss.xml).

The last time downloaded was found to be dated: Fri Jun 12 11:33:02 UTC 2015.

The ipset `xroxy` has **2175** entries, **2175** unique IPs.

The following table shows the overlaps of `xroxy` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `xroxy`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `xroxy`.
- ` this % ` is the percentage **of this ipset (`xroxy`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_proxies](#firehol_proxies)|12718|12994|2175|16.7%|100.0%|
[firehol_anonymous](#firehol_anonymous)|19277|83325|2175|2.6%|100.0%|
[firehol_level3](#firehol_level3)|109554|9627189|1299|0.0%|59.7%|
[stopforumspam_30d](#stopforumspam_30d)|94236|94236|1284|1.3%|59.0%|
[ri_web_proxies](#ri_web_proxies)|7996|7996|966|12.0%|44.4%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|586|2.0%|26.9%|
[proxz](#proxz)|1367|1367|469|34.3%|21.5%|
[ri_connect_proxies](#ri_connect_proxies)|2876|2876|397|13.8%|18.2%|
[proxyrss](#proxyrss)|1455|1455|355|24.3%|16.3%|
[firehol_level2](#firehol_level2)|21534|33114|302|0.9%|13.8%|
[blocklist_de](#blocklist_de)|27919|27919|228|0.8%|10.4%|
[stopforumspam_1d](#stopforumspam_1d)|6629|6629|194|2.9%|8.9%|
[blocklist_de_bots](#blocklist_de_bots)|3014|3014|177|5.8%|8.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|112|0.0%|5.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|104|0.0%|4.7%|
[sorbs_spam](#sorbs_spam)|64701|65536|76|0.1%|3.4%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|76|0.1%|3.4%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|76|0.1%|3.4%|
[nixspam](#nixspam)|21496|21496|61|0.2%|2.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|58|0.0%|2.6%|
[blocklist_de_mail](#blocklist_de_mail)|18003|18003|51|0.2%|2.3%|
[snort_ipfilter](#snort_ipfilter)|9136|9136|42|0.4%|1.9%|
[php_dictionary](#php_dictionary)|777|777|42|5.4%|1.9%|
[php_spammers](#php_spammers)|777|777|35|4.5%|1.6%|
[sorbs_web](#sorbs_web)|643|644|16|2.4%|0.7%|
[php_commenters](#php_commenters)|458|458|13|2.8%|0.5%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|13|1.9%|0.5%|
[blocklist_de_strongips](#blocklist_de_strongips)|169|169|7|4.1%|0.3%|
[dragon_http](#dragon_http)|1021|268288|6|0.0%|0.2%|
[alienvault_reputation](#alienvault_reputation)|189179|189179|5|0.0%|0.2%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|3|0.5%|0.1%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|3|0.0%|0.1%|
[php_harvesters](#php_harvesters)|408|408|2|0.4%|0.0%|
[et_tor](#et_tor)|6500|6500|2|0.0%|0.0%|
[dm_tor](#dm_tor)|6521|6521|2|0.0%|0.0%|
[bm_tor](#bm_tor)|6496|6496|2|0.0%|0.0%|
[iw_spamlist](#iw_spamlist)|3418|3418|1|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.0%|
[et_compromised](#et_compromised)|1704|1704|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1696|1696|1|0.0%|0.0%|

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
[firehol_level1](#firehol_level1)|5070|688775051|230|0.0%|100.0%|
[et_block](#et_block)|1000|18343756|229|0.0%|99.5%|
[firehol_level3](#firehol_level3)|109554|9627189|203|0.0%|88.2%|
[zeus_badips](#zeus_badips)|202|202|202|100.0%|87.8%|
[snort_ipfilter](#snort_ipfilter)|9136|9136|200|2.1%|86.9%|
[alienvault_reputation](#alienvault_reputation)|189179|189179|61|0.0%|26.5%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|15|0.0%|6.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|14|0.0%|6.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|10|0.0%|4.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|9|0.0%|3.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|7|0.0%|3.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|5|0.0%|2.1%|
[dragon_http](#dragon_http)|1021|268288|3|0.0%|1.3%|
[stopforumspam_30d](#stopforumspam_30d)|94236|94236|2|0.0%|0.8%|
[openbl_60d](#openbl_60d)|6959|6959|2|0.0%|0.8%|
[openbl_30d](#openbl_30d)|2789|2789|2|0.0%|0.8%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|1|0.0%|0.4%|
[stopforumspam_1d](#stopforumspam_1d)|6629|6629|1|0.0%|0.4%|
[php_commenters](#php_commenters)|458|458|1|0.2%|0.4%|
[openbl_7d](#openbl_7d)|637|637|1|0.1%|0.4%|
[nixspam](#nixspam)|21496|21496|1|0.0%|0.4%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|1|0.0%|0.4%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.4%|
[firehol_level2](#firehol_level2)|21534|33114|1|0.0%|0.4%|

## zeus_badips

[Abuse.ch Zeus tracker](https://zeustracker.abuse.ch) badips includes IPv4 addresses that are used by the ZeuS trojan. It is the recommened blocklist if you want to block only ZeuS IPs. It excludes IP addresses that ZeuS Tracker believes to be hijacked (level 2) or belong to a free web hosting provider (level 3). Hence the false postive rate should be much lower compared to the standard ZeuS IP blocklist. **excellent list**

Source is downloaded from [this link](https://zeustracker.abuse.ch/blocklist.php?download=badips).

The last time downloaded was found to be dated: Fri Jun 12 11:54:15 UTC 2015.

The ipset `zeus_badips` has **202** entries, **202** unique IPs.

The following table shows the overlaps of `zeus_badips` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `zeus_badips`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `zeus_badips`.
- ` this % ` is the percentage **of this ipset (`zeus_badips`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[zeus](#zeus)|230|230|202|87.8%|100.0%|
[firehol_level1](#firehol_level1)|5070|688775051|202|0.0%|100.0%|
[et_block](#et_block)|1000|18343756|202|0.0%|100.0%|
[firehol_level3](#firehol_level3)|109554|9627189|180|0.0%|89.1%|
[snort_ipfilter](#snort_ipfilter)|9136|9136|178|1.9%|88.1%|
[alienvault_reputation](#alienvault_reputation)|189179|189179|37|0.0%|18.3%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|15|0.0%|7.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|10|0.0%|4.9%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|10|0.0%|4.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|8|0.0%|3.9%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|5|0.0%|2.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|4|0.0%|1.9%|
[dragon_http](#dragon_http)|1021|268288|3|0.0%|1.4%|
[stopforumspam_30d](#stopforumspam_30d)|94236|94236|2|0.0%|0.9%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|1|0.0%|0.4%|
[stopforumspam_1d](#stopforumspam_1d)|6629|6629|1|0.0%|0.4%|
[php_commenters](#php_commenters)|458|458|1|0.2%|0.4%|
[openbl_7d](#openbl_7d)|637|637|1|0.1%|0.4%|
[openbl_60d](#openbl_60d)|6959|6959|1|0.0%|0.4%|
[openbl_30d](#openbl_30d)|2789|2789|1|0.0%|0.4%|
[nixspam](#nixspam)|21496|21496|1|0.0%|0.4%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.4%|
[firehol_level2](#firehol_level2)|21534|33114|1|0.0%|0.4%|
