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

The following list was automatically generated on Fri Jun 12 09:38:06 UTC 2015.

The update frequency is the maximum allowed by internal configuration. A list will never be downloaded sooner than the update frequency stated. A list may also not be downloaded, after this frequency expired, if it has not been modified on the server (as reported by HTTP `IF_MODIFIED_SINCE` method).

name|info|type|entries|update|
:--:|:--:|:--:|:-----:|:----:|
[alienvault_reputation](#alienvault_reputation)|[AlienVault.com](https://www.alienvault.com/) IP reputation database (this list seems to include port scanning hosts and to be updated regularly, but we found no information about its retention policy)|ipv4 hash:ip|189146 unique IPs|updated every 6 hours  from [this link](https://reputation.alienvault.com/reputation.generic)
[blocklist_de](#blocklist_de)|[Blocklist.de](https://www.blocklist.de/) IPs that have been detected by fail2ban in the last 48 hours - **excellent list**|ipv4 hash:ip|26985 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/all.txt)
[blocklist_de_apache](#blocklist_de_apache)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service Apache, Apache-DDOS, RFI-Attacks.|ipv4 hash:ip|13845 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/apache.txt)
[blocklist_de_bots](#blocklist_de_bots)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the RFI-Attacks, REG-Bots, IRC-Bots or BadBots (BadBots = he has posted a Spam-Comment on a open Forum or Wiki).|ipv4 hash:ip|2972 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/bots.txt)
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|[Blocklist.de](https://www.blocklist.de/) All IPs which attacks Joomlas, Wordpress and other Web-Logins with Brute-Force Logins.|ipv4 hash:ip|2446 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/bruteforcelogin.txt)
[blocklist_de_ftp](#blocklist_de_ftp)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours for attacks on the Service FTP.|ipv4 hash:ip|1523 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/ftp.txt)
[blocklist_de_imap](#blocklist_de_imap)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours for attacks on the Service imap, sasl, pop3, etc.|ipv4 hash:ip|2726 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/imap.txt)
[blocklist_de_mail](#blocklist_de_mail)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service Mail, Postfix.|ipv4 hash:ip|17750 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/mail.txt)
[blocklist_de_sip](#blocklist_de_sip)|[Blocklist.de](https://www.blocklist.de/) All IP addresses that tried to login in a SIP, VOIP or Asterisk Server and are included in the IPs list from [infiltrated.net](www.infiltrated.net)|ipv4 hash:ip|83 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/sip.txt)
[blocklist_de_ssh](#blocklist_de_ssh)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service SSH.|ipv4 hash:ip|1901 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/ssh.txt)
[blocklist_de_strongips](#blocklist_de_strongips)|[Blocklist.de](https://www.blocklist.de/) All IPs which are older then 2 month and have more then 5.000 attacks.|ipv4 hash:ip|170 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/strongips.txt)
[bm_tor](#bm_tor)|[torstatus.blutmagie.de](https://torstatus.blutmagie.de) list of all TOR network servers|ipv4 hash:ip|6471 unique IPs|updated every 30 mins  from [this link](https://torstatus.blutmagie.de/ip_list_all.php/Tor_ip_list_ALL.csv)
[bogons](#bogons)|[Team-Cymru.org](http://www.team-cymru.org) private and reserved addresses defined by RFC 1918, RFC 5735, and RFC 6598 and netblocks that have not been allocated to a regional internet registry - **excellent list - use it only your internet interface**|ipv4 hash:net|13 subnets, 592708608 unique IPs|updated every 1 day  from [this link](http://www.team-cymru.org/Services/Bogons/bogon-bn-agg.txt)
[bruteforceblocker](#bruteforceblocker)|[danger.rulez.sk](http://danger.rulez.sk/) IPs detected by [bruteforceblocker](http://danger.rulez.sk/index.php/bruteforceblocker/) (fail2ban alternative for SSH on OpenBSD). This is an automatically generated list from users reporting failed authentication attempts. An IP seems to be included if 3 or more users report it. Its retention pocily seems 30 days.|ipv4 hash:ip|1694 unique IPs|updated every 3 hours  from [this link](http://danger.rulez.sk/projects/bruteforceblocker/blist.php)
[ciarmy](#ciarmy)|[CIArmy.com](http://ciarmy.com/) IPs with poor Rogue Packet score that have not yet been identified as malicious by the community|ipv4 hash:ip|416 unique IPs|updated every 3 hours  from [this link](http://cinsscore.com/list/ci-badguys.txt)
[cleanmx_viruses](#cleanmx_viruses)|[Clean-MX.de](http://support.clean-mx.de/clean-mx/viruses.php) IPs with viruses|ipv4 hash:ip|511 unique IPs|updated every 12 hours  from [this link](http://support.clean-mx.de/clean-mx/xmlviruses.php?sort=id%20desc&response=alive)
[dm_tor](#dm_tor)|[dan.me.uk](https://www.dan.me.uk) dynamic list of TOR nodes|ipv4 hash:ip|6468 unique IPs|updated every 30 mins  from [this link](https://www.dan.me.uk/torlist/)
[dragon_http](#dragon_http)|[Dragon Search Group](http://www.dragonresearchgroup.org/) IPs that have been seen sending HTTP requests to Dragon Research Pods in the last 7 days. This report lists hosts that are highly suspicious and are likely conducting malicious HTTP attacks. LEGITIMATE SEARCH ENGINE BOTS MAY BE IN THIS LIST. This report is informational.  It is not a blacklist, but some operators may choose to use it to help protect their networks and hosts in the forms of automated reporting and mitigation services.|ipv4 hash:net|1021 subnets, 268288 unique IPs|updated every 1 hour  from [this link](http://www.dragonresearchgroup.org/insight/http-report.txt)
[dragon_sshpauth](#dragon_sshpauth)|[Dragon Search Group](http://www.dragonresearchgroup.org/) IP address that has been seen attempting to remotely login to a host using SSH password authentication, in the last 7 days. This report lists hosts that are highly suspicious and are likely conducting malicious SSH password authentication attacks.|ipv4 hash:net|1589 subnets, 1653 unique IPs|updated every 1 hour  from [this link](https://www.dragonresearchgroup.org/insight/sshpwauth.txt)
[dragon_vncprobe](#dragon_vncprobe)|[Dragon Search Group](http://www.dragonresearchgroup.org/) IP address that has been seen attempting to remotely connect to a host running the VNC application service, in the last 7 days. This report lists hosts that are highly suspicious and are likely conducting malicious VNC probes or VNC brute force attacks.|ipv4 hash:net|87 subnets, 87 unique IPs|updated every 1 hour  from [this link](https://www.dragonresearchgroup.org/insight/vncprobe.txt)
[dshield](#dshield)|[DShield.org](https://dshield.org/) top 20 attacking class C (/24) subnets over the last three days - **excellent list**|ipv4 hash:net|20 subnets, 5120 unique IPs|updated every 4 hours  from [this link](http://feeds.dshield.org/block.txt)
[et_block](#et_block)|[EmergingThreats.net](http://www.emergingthreats.net/) default blacklist (at the time of writing includes spamhaus DROP, dshield and abuse.ch trackers, which are available separately too - prefer to use the direct ipsets instead of this, they seem to lag a bit in updates)|ipv4 hash:net|1000 subnets, 18343756 unique IPs|updated every 12 hours  from [this link](http://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt)
[et_botcc](#et_botcc)|[EmergingThreats.net Command and Control IPs](http://doc.emergingthreats.net/bin/view/Main/BotCC) These IPs are updates every 24 hours and should be considered VERY highly reliable indications that a host is communicating with a known and active Bot or Malware command and control server - (although they say this includes abuse.ch trackers, it does not - most probably it is the shadowserver.org C&C list)|ipv4 hash:ip|505 unique IPs|updated every 12 hours  from [this link](http://rules.emergingthreats.net/fwrules/emerging-PIX-CC.rules)
[et_compromised](#et_compromised)|[EmergingThreats.net compromised hosts](http://doc.emergingthreats.net/bin/view/Main/CompromisedHost) - (this seems to be based on bruteforceblocker)|ipv4 hash:ip|1704 unique IPs|updated every 12 hours  from [this link](http://rules.emergingthreats.net/blockrules/compromised-ips.txt)
et_dshield|[EmergingThreats.net](http://www.emergingthreats.net/) dshield blocklist|ipv4 hash:net|disabled|updated every 12 hours  from [this link](http://rules.emergingthreats.net/fwrules/emerging-PIX-DSHIELD.rules)
et_spamhaus|[EmergingThreats.net](http://www.emergingthreats.net/) spamhaus blocklist|ipv4 hash:net|disabled|updated every 12 hours  from [this link](http://rules.emergingthreats.net/fwrules/emerging-PIX-DROP.rules)
[et_tor](#et_tor)|[EmergingThreats.net](http://www.emergingthreats.net/) [list](http://doc.emergingthreats.net/bin/view/Main/TorRules) of TOR network IPs|ipv4 hash:ip|6500 unique IPs|updated every 12 hours  from [this link](http://rules.emergingthreats.net/blockrules/emerging-tor.rules)
[feodo](#feodo)|[Abuse.ch Feodo tracker](https://feodotracker.abuse.ch) trojan includes IPs which are being used by Feodo (also known as Cridex or Bugat) which commits ebanking fraud - **excellent list**|ipv4 hash:ip|0 unique IPs|updated every 30 mins  from [this link](https://feodotracker.abuse.ch/blocklist/?download=ipblocklist)
[firehol_anonymous](#firehol_anonymous)|**FireHOL Anonymous** - Known anonymizing IPs. (includes: firehol_proxies anonymous bm_tor dm_tor tor_exits)|ipv4 hash:net|19172 subnets, 83219 unique IPs|
[firehol_level1](#firehol_level1)|**FireHOL Level 1** - Maximum protection without false positives. (includes: fullbogons dshield feodo palevo sslbl zeus spamhaus_drop spamhaus_edrop)|ipv4 hash:net|5070 subnets, 688854680 unique IPs|
[firehol_level2](#firehol_level2)|**FireHOL Level 2** - Maximum protection from attacks took place in the last 48 hours. (includes: openbl_1d blocklist_de stopforumspam_1d)|ipv4 hash:net|20666 subnets, 32229 unique IPs|
[firehol_level3](#firehol_level3)|**FireHOL Level 3** - All the bad IPs in last 30 days. (includes: openbl_30d stopforumspam_30d virbl malc0de shunlist malwaredomainlist bruteforceblocker ciarmy cleanmx_viruses snort_ipfilter ib_bluetack_spyware ib_bluetack_hijacked ib_bluetack_webexploit php_commenters php_dictionary php_harvesters php_spammers iw_wormlist)|ipv4 hash:net|109549 subnets, 9627220 unique IPs|
[firehol_proxies](#firehol_proxies)|**FireHOL Proxies** - Known open proxies in the last 30 days. (includes: ib_bluetack_proxies maxmind_proxy_fraud proxyrss proxz ri_connect_proxies ri_web_proxies xroxy)|ipv4 hash:net|12734 subnets, 13010 unique IPs|
[fullbogons](#fullbogons)|[Team-Cymru.org](http://www.team-cymru.org) IP space that has been allocated to an RIR, but not assigned by that RIR to an actual ISP or other end-user - **excellent list - use it only your internet interface**|ipv4 hash:net|3775 subnets, 670173256 unique IPs|updated every 1 day  from [this link](http://www.team-cymru.org/Services/Bogons/fullbogons-ipv4.txt)
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
[iw_spamlist](#iw_spamlist)|[ImproWare Antispam](http://antispam.imp.ch/) IPs sending spam, in the last 3 days|ipv4 hash:ip|3648 unique IPs|updated every 1 hour  from [this link](http://antispam.imp.ch/spamlist)
[iw_wormlist](#iw_wormlist)|[ImproWare Antispam](http://antispam.imp.ch/) IPs sending emails with viruses or worms, in the last 3 days|ipv4 hash:ip|34 unique IPs|updated every 1 hour  from [this link](http://antispam.imp.ch/wormlist)
lashback_ubl|[The LashBack UBL](http://blacklist.lashback.com/) The Unsubscribe Blacklist (UBL) is a real-time blacklist of IP addresses which are sending email to names harvested from suppression files (this is a big list, more than 500.000 IPs)|ipv4 hash:ip|disabled|updated every 1 day  from [this link](http://www.unsubscore.com/blacklist.txt)
[malc0de](#malc0de)|[Malc0de.com](http://malc0de.com) malicious IPs of the last 30 days|ipv4 hash:ip|276 unique IPs|updated every 1 day  from [this link](http://malc0de.com/bl/IP_Blacklist.txt)
[malwaredomainlist](#malwaredomainlist)|[malwaredomainlist.com](http://www.malwaredomainlist.com) list of malware active ip addresses|ipv4 hash:ip|1288 unique IPs|updated every 12 hours  from [this link](http://www.malwaredomainlist.com/hostslist/ip.txt)
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|[MaxMind.com](https://www.maxmind.com/en/anonymous-proxy-fraudulent-ip-address-list) list of anonymous proxy fraudelent IP addresses.|ipv4 hash:ip|524 unique IPs|updated every 4 hours  from [this link](https://www.maxmind.com/en/anonymous-proxy-fraudulent-ip-address-list)
[nixspam](#nixspam)|[NiX Spam](http://www.heise.de/ix/NiX-Spam-DNSBL-and-blacklist-for-download-499637.html) IP addresses that sent spam in the last hour - automatically generated entries without distinguishing open proxies from relays, dialup gateways, and so on. All IPs are removed after 12 hours if there is no spam from there.|ipv4 hash:ip|18198 unique IPs|updated every 15 mins  from [this link](http://www.dnsbl.manitu.net/download/nixspam-ip.dump.gz)
[nt_malware_http](#nt_malware_http)|[No Think](http://www.nothink.org/) Malware HTTP|ipv4 hash:ip|69 unique IPs|updated every 1 hour  from [this link](http://www.nothink.org/blacklist/blacklist_malware_http.txt)
[nt_malware_irc](#nt_malware_irc)|[No Think](http://www.nothink.org/) Malware IRC|ipv4 hash:ip|43 unique IPs|updated every 1 hour  from [this link](http://www.nothink.org/blacklist/blacklist_malware_irc.txt)
[nt_ssh_7d](#nt_ssh_7d)|[No Think](http://www.nothink.org/) Last 7 days SSH attacks|ipv4 hash:ip|0 unique IPs|updated every 1 hour  from [this link](http://www.nothink.org/blacklist/blacklist_ssh_week.txt)
openbl|[OpenBL.org](http://www.openbl.org/) default blacklist (currently it is the same with 90 days). OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications - **excellent list**|ipv4 hash:ip|disabled|updated every 4 hours  from [this link](http://www.openbl.org/lists/base.txt)
openbl_180d|[OpenBL.org](http://www.openbl.org/) last 180 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|disabled|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_180days.txt)
[openbl_1d](#openbl_1d)|[OpenBL.org](http://www.openbl.org/) last 24 hours IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|124 unique IPs|updated every 1 hour  from [this link](http://www.openbl.org/lists/base_1days.txt)
[openbl_30d](#openbl_30d)|[OpenBL.org](http://www.openbl.org/) last 30 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|2792 unique IPs|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_30days.txt)
openbl_360d|[OpenBL.org](http://www.openbl.org/) last 360 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|disabled|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_360days.txt)
[openbl_60d](#openbl_60d)|[OpenBL.org](http://www.openbl.org/) last 60 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|6960 unique IPs|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_60days.txt)
[openbl_7d](#openbl_7d)|[OpenBL.org](http://www.openbl.org/) last 7 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|629 unique IPs|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_7days.txt)
openbl_90d|[OpenBL.org](http://www.openbl.org/) last 90 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|disabled|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_90days.txt)
openbl_all|[OpenBL.org](http://www.openbl.org/) last all IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|disabled|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_all.txt)
[palevo](#palevo)|[Abuse.ch Palevo tracker](https://palevotracker.abuse.ch) worm includes IPs which are being used as botnet C&C for the Palevo crimeware - **excellent list**|ipv4 hash:ip|13 unique IPs|updated every 30 mins  from [this link](https://palevotracker.abuse.ch/blocklists.php?download=ipblocklist)
php_bad|[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) bad web hosts (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|disabled|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=b&rss=1)
[php_commenters](#php_commenters)|[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) comment spammers (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|458 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=c&rss=1)
[php_dictionary](#php_dictionary)|[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) directory attackers (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|737 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=d&rss=1)
[php_harvesters](#php_harvesters)|[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) harvesters (IPs that surf the internet looking for email addresses) (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|408 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=h&rss=1)
[php_spammers](#php_spammers)|[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) spam servers (IPs used by spammers to send messages) (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|735 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=s&rss=1)
[proxyrss](#proxyrss)|[proxyrss.com](http://www.proxyrss.com) open proxies syndicated from multiple sources.|ipv4 hash:ip|1570 unique IPs|updated every 4 hours  from [this link](http://www.proxyrss.com/proxylists/all.gz)
[proxz](#proxz)|[proxz.com](http://www.proxz.com) open proxies (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|1356 unique IPs|updated every 1 hour  from [this link](http://www.proxz.com/proxylists.xml)
[ri_connect_proxies](#ri_connect_proxies)|[rosinstrument.com](http://www.rosinstrument.com) open CONNECT proxies (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|2855 unique IPs|updated every 1 hour  from [this link](http://tools.rosinstrument.com/proxy/plab100.xml)
[ri_web_proxies](#ri_web_proxies)|[rosinstrument.com](http://www.rosinstrument.com) open HTTP proxies (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|7952 unique IPs|updated every 1 hour  from [this link](http://tools.rosinstrument.com/proxy/l100.xml)
[shunlist](#shunlist)|[AutoShun.org](http://autoshun.org/) IPs identified as hostile by correlating logs from distributed snort installations running the autoshun plugin|ipv4 hash:ip|1185 unique IPs|updated every 4 hours  from [this link](http://www.autoshun.org/files/shunlist.csv)
[snort_ipfilter](#snort_ipfilter)|[labs.snort.org](https://labs.snort.org/) supplied IP blacklist (this list seems to be updated frequently, but we found no information about it)|ipv4 hash:ip|9136 unique IPs|updated every 12 hours  from [this link](http://labs.snort.org/feeds/ip-filter.blf)
[sorbs_dul](#sorbs_dul)|[Sorbs.net](https://www.sorbs.net/) DUL, Dynamic User IPs extracted from deltas.|ipv4 hash:net|10 subnets, 4864 unique IPs|
[sorbs_http](#sorbs_http)|[Sorbs.net](https://www.sorbs.net/) HTTP proxies, extracted from deltas.|ipv4 hash:net|7 subnets, 7 unique IPs|
[sorbs_misc](#sorbs_misc)|[Sorbs.net](https://www.sorbs.net/) MISC proxies, extracted from deltas.|ipv4 hash:net|7 subnets, 7 unique IPs|
[sorbs_new_spam](#sorbs_new_spam)|[Sorbs.net](https://www.sorbs.net/) NEW Spam senders, extracted from deltas.|ipv4 hash:net|64467 subnets, 65300 unique IPs|
[sorbs_recent_spam](#sorbs_recent_spam)|[Sorbs.net](https://www.sorbs.net/) RECENT Spam senders, extracted from deltas.|ipv4 hash:net|64467 subnets, 65300 unique IPs|
[sorbs_smtp](#sorbs_smtp)|[Sorbs.net](https://www.sorbs.net/) SMTP Open Relays, extracted from deltas.|ipv4 hash:net|6 subnets, 6 unique IPs|
[sorbs_socks](#sorbs_socks)|[Sorbs.net](https://www.sorbs.net/) SOCKS proxies, extracted from deltas.|ipv4 hash:net|7 subnets, 7 unique IPs|
[sorbs_spam](#sorbs_spam)|[Sorbs.net](https://www.sorbs.net/) Spam senders, extracted from deltas.|ipv4 hash:net|64701 subnets, 65536 unique IPs|
[sorbs_web](#sorbs_web)|[Sorbs.net](https://www.sorbs.net/) WEB exploits, extracted from deltas.|ipv4 hash:net|628 subnets, 629 unique IPs|
[spamhaus_drop](#spamhaus_drop)|[Spamhaus.org](http://www.spamhaus.org) DROP list (according to their site this list should be dropped at tier-1 ISPs globaly) - **excellent list**|ipv4 hash:net|653 subnets, 18340608 unique IPs|updated every 12 hours  from [this link](http://www.spamhaus.org/drop/drop.txt)
[spamhaus_edrop](#spamhaus_edrop)|[Spamhaus.org](http://www.spamhaus.org) EDROP (extended matches that should be used with DROP) - **excellent list**|ipv4 hash:net|56 subnets, 487424 unique IPs|updated every 12 hours  from [this link](http://www.spamhaus.org/drop/edrop.txt)
[sslbl](#sslbl)|[Abuse.ch SSL Blacklist](https://sslbl.abuse.ch/) bad SSL traffic related to malware or botnet activities - **excellent list**|ipv4 hash:ip|370 unique IPs|updated every 30 mins  from [this link](https://sslbl.abuse.ch/blacklist/sslipblacklist.csv)
stopforumspam_180d|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 180 days)|ipv4 hash:ip|disabled|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/listed_ip_180.zip)
[stopforumspam_1d](#stopforumspam_1d)|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers in the last 24 hours - **excellent list**|ipv4 hash:ip|6669 unique IPs|updated every 1 hour  from [this link](http://www.stopforumspam.com/downloads/listed_ip_1.zip)
[stopforumspam_30d](#stopforumspam_30d)|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 30 days)|ipv4 hash:ip|94309 unique IPs|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/listed_ip_30.zip)
stopforumspam_365d|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 365 days)|ipv4 hash:ip|disabled|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/listed_ip_365.zip)
[stopforumspam_7d](#stopforumspam_7d)|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 7 days)|ipv4 hash:ip|29017 unique IPs|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/listed_ip_7.zip)
stopforumspam_90d|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 90 days)|ipv4 hash:ip|disabled|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/listed_ip_90.zip)
stopforumspam_ever|[StopForumSpam.com](http://www.stopforumspam.com) all IPs used by forum spammers, **ever** (normally you don't want to use this ipset, use the hourly one which includes last 24 hours IPs or the 7 days one)|ipv4 hash:ip|disabled|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/bannedips.zip)
[tor_exits](#tor_exits)|[TorProject.org](https://www.torproject.org) list of all current TOR exit points (TorDNSEL)|ipv4 hash:ip|1106 unique IPs|updated every 30 mins  from [this link](https://check.torproject.org/exit-addresses)
[virbl](#virbl)|[VirBL](http://virbl.bit.nl/) is a project of which the idea was born during the RIPE-48 meeting. The plan was to get reports of virusscanning mailservers, and put the IP-addresses that were reported to send viruses on a blacklist.|ipv4 hash:ip|22 unique IPs|updated every 1 hour  from [this link](http://virbl.bit.nl/download/virbl.dnsbl.bit.nl.txt)
[voipbl](#voipbl)|[VoIPBL.org](http://www.voipbl.org/) a distributed VoIP blacklist that is aimed to protects against VoIP Fraud and minimizing abuse for network that have publicly accessible PBX's. Several algorithms, external sources and manual confirmation are used before they categorize something as an attack and determine the threat level.|ipv4 hash:net|10586 subnets, 10998 unique IPs|updated every 4 hours  from [this link](http://www.voipbl.org/update/)
[xroxy](#xroxy)|[xroxy.com](http://www.xroxy.com) open proxies (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|2175 unique IPs|updated every 1 hour  from [this link](http://www.xroxy.com/proxyrss.xml)
[zeus](#zeus)|[Abuse.ch Zeus tracker](https://zeustracker.abuse.ch) standard, contains the same data as the ZeuS IP blocklist (zeus_badips) but with the slight difference that it doesn't exclude hijacked websites (level 2) and free web hosting providers (level 3). This means that this blocklist contains all IPv4 addresses associated with ZeuS C&Cs which are currently being tracked by ZeuS Tracker. Hence this blocklist will likely cause some false positives. - **excellent list**|ipv4 hash:ip|230 unique IPs|updated every 30 mins  from [this link](https://zeustracker.abuse.ch/blocklist.php?download=ipblocklist)
[zeus_badips](#zeus_badips)|[Abuse.ch Zeus tracker](https://zeustracker.abuse.ch) badips includes IPv4 addresses that are used by the ZeuS trojan. It is the recommened blocklist if you want to block only ZeuS IPs. It excludes IP addresses that ZeuS Tracker believes to be hijacked (level 2) or belong to a free web hosting provider (level 3). Hence the false postive rate should be much lower compared to the standard ZeuS IP blocklist. **excellent list**|ipv4 hash:ip|202 unique IPs|updated every 30 mins  from [this link](https://zeustracker.abuse.ch/blocklist.php?download=badips)

# Comparison of ipsets

Below we compare each ipset against all other.


## alienvault_reputation

[AlienVault.com](https://www.alienvault.com/) IP reputation database (this list seems to include port scanning hosts and to be updated regularly, but we found no information about its retention policy)

Source is downloaded from [this link](https://reputation.alienvault.com/reputation.generic).

The last time downloaded was found to be dated: Fri Jun 12 04:00:38 UTC 2015.

The ipset `alienvault_reputation` has **189146** entries, **189146** unique IPs.

The following table shows the overlaps of `alienvault_reputation` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `alienvault_reputation`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `alienvault_reputation`.
- ` this % ` is the percentage **of this ipset (`alienvault_reputation`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|14337|0.0%|7.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|7251|0.0%|3.8%|
[openbl_60d](#openbl_60d)|6960|6960|6935|99.6%|3.6%|
[firehol_level1](#firehol_level1)|5070|688854680|6387|0.0%|3.3%|
[dragon_http](#dragon_http)|1021|268288|6152|2.2%|3.2%|
[dshield](#dshield)|20|5120|5120|100.0%|2.7%|
[firehol_level3](#firehol_level3)|109549|9627220|4814|0.0%|2.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|4185|0.0%|2.2%|
[et_block](#et_block)|1000|18343756|3752|0.0%|1.9%|
[openbl_30d](#openbl_30d)|2792|2792|2772|99.2%|1.4%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|1385|0.0%|0.7%|
[shunlist](#shunlist)|1185|1185|1165|98.3%|0.6%|
[firehol_level2](#firehol_level2)|20666|32229|1091|3.3%|0.5%|
[et_compromised](#et_compromised)|1704|1704|1084|63.6%|0.5%|
[bruteforceblocker](#bruteforceblocker)|1694|1694|1070|63.1%|0.5%|
[blocklist_de](#blocklist_de)|26985|26985|1046|3.8%|0.5%|
[dragon_sshpauth](#dragon_sshpauth)|1589|1653|862|52.1%|0.4%|
[blocklist_de_ssh](#blocklist_de_ssh)|1901|1901|839|44.1%|0.4%|
[openbl_7d](#openbl_7d)|629|629|622|98.8%|0.3%|
[ciarmy](#ciarmy)|416|416|400|96.1%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|293|0.0%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|278|0.0%|0.1%|
[voipbl](#voipbl)|10586|10998|176|1.6%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|168|0.1%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13845|13845|120|0.8%|0.0%|
[openbl_1d](#openbl_1d)|124|124|115|92.7%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9136|9136|107|1.1%|0.0%|
[sorbs_spam](#sorbs_spam)|64701|65536|91|0.1%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|91|0.1%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|91|0.1%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|88|0.3%|0.0%|
[sslbl](#sslbl)|370|370|65|17.5%|0.0%|
[zeus](#zeus)|230|230|61|26.5%|0.0%|
[firehol_anonymous](#firehol_anonymous)|19172|83219|57|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|17750|17750|46|0.2%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6669|6669|44|0.6%|0.0%|
[nixspam](#nixspam)|18198|18198|44|0.2%|0.0%|
[et_tor](#et_tor)|6500|6500|42|0.6%|0.0%|
[dm_tor](#dm_tor)|6468|6468|42|0.6%|0.0%|
[bm_tor](#bm_tor)|6471|6471|42|0.6%|0.0%|
[firehol_proxies](#firehol_proxies)|12734|13010|38|0.2%|0.0%|
[zeus_badips](#zeus_badips)|202|202|37|18.3%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|170|170|35|20.5%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2726|2726|32|1.1%|0.0%|
[tor_exits](#tor_exits)|1106|1106|30|2.7%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|29|5.5%|0.0%|
[dragon_vncprobe](#dragon_vncprobe)|87|87|27|31.0%|0.0%|
[iw_spamlist](#iw_spamlist)|3648|3648|24|0.6%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|2972|2972|21|0.7%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|83|83|20|24.0%|0.0%|
[php_commenters](#php_commenters)|458|458|19|4.1%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|15|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|14|0.0%|0.0%|
[php_harvesters](#php_harvesters)|408|408|12|2.9%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2446|2446|12|0.4%|0.0%|
[malc0de](#malc0de)|276|276|9|3.2%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|8|0.6%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|1523|1523|8|0.5%|0.0%|
[php_dictionary](#php_dictionary)|737|737|7|0.9%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|6|0.4%|0.0%|
[xroxy](#xroxy)|2175|2175|5|0.2%|0.0%|
[php_spammers](#php_spammers)|735|735|5|0.6%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7952|7952|4|0.0%|0.0%|
[et_botcc](#et_botcc)|505|505|4|0.7%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|511|511|4|0.7%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2855|2855|3|0.1%|0.0%|
[proxz](#proxz)|1356|1356|3|0.2%|0.0%|
[nt_malware_irc](#nt_malware_irc)|43|43|2|4.6%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|2|0.3%|0.0%|
[sorbs_web](#sorbs_web)|628|629|1|0.1%|0.0%|
[proxyrss](#proxyrss)|1570|1570|1|0.0%|0.0%|
[nt_malware_http](#nt_malware_http)|69|69|1|1.4%|0.0%|

## blocklist_de

[Blocklist.de](https://www.blocklist.de/) IPs that have been detected by fail2ban in the last 48 hours - **excellent list**

Source is downloaded from [this link](http://lists.blocklist.de/lists/all.txt).

The last time downloaded was found to be dated: Fri Jun 12 09:28:04 UTC 2015.

The ipset `blocklist_de` has **26985** entries, **26985** unique IPs.

The following table shows the overlaps of `blocklist_de` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de`.
- ` this % ` is the percentage **of this ipset (`blocklist_de`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|20666|32229|26985|83.7%|100.0%|
[blocklist_de_mail](#blocklist_de_mail)|17750|17750|17699|99.7%|65.5%|
[blocklist_de_apache](#blocklist_de_apache)|13845|13845|13828|99.8%|51.2%|
[firehol_level3](#firehol_level3)|109549|9627220|3656|0.0%|13.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|3282|0.0%|12.1%|
[blocklist_de_bots](#blocklist_de_bots)|2972|2972|2961|99.6%|10.9%|
[blocklist_de_imap](#blocklist_de_imap)|2726|2726|2715|99.5%|10.0%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|2613|2.7%|9.6%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2446|2446|2446|100.0%|9.0%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|2346|8.0%|8.6%|
[blocklist_de_ssh](#blocklist_de_ssh)|1901|1901|1876|98.6%|6.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|1580|0.0%|5.8%|
[blocklist_de_ftp](#blocklist_de_ftp)|1523|1523|1508|99.0%|5.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|1461|0.0%|5.4%|
[stopforumspam_1d](#stopforumspam_1d)|6669|6669|1444|21.6%|5.3%|
[alienvault_reputation](#alienvault_reputation)|189146|189146|1046|0.5%|3.8%|
[sorbs_spam](#sorbs_spam)|64701|65536|983|1.4%|3.6%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|975|1.4%|3.6%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|975|1.4%|3.6%|
[openbl_60d](#openbl_60d)|6960|6960|723|10.3%|2.6%|
[firehol_anonymous](#firehol_anonymous)|19172|83219|664|0.7%|2.4%|
[firehol_proxies](#firehol_proxies)|12734|13010|640|4.9%|2.3%|
[dragon_sshpauth](#dragon_sshpauth)|1589|1653|638|38.5%|2.3%|
[openbl_30d](#openbl_30d)|2792|2792|631|22.6%|2.3%|
[bruteforceblocker](#bruteforceblocker)|1694|1694|554|32.7%|2.0%|
[et_compromised](#et_compromised)|1704|1704|534|31.3%|1.9%|
[nixspam](#nixspam)|18198|18198|497|2.7%|1.8%|
[ri_web_proxies](#ri_web_proxies)|7952|7952|471|5.9%|1.7%|
[openbl_7d](#openbl_7d)|629|629|370|58.8%|1.3%|
[shunlist](#shunlist)|1185|1185|348|29.3%|1.2%|
[xroxy](#xroxy)|2175|2175|227|10.4%|0.8%|
[proxyrss](#proxyrss)|1570|1570|213|13.5%|0.7%|
[firehol_level1](#firehol_level1)|5070|688854680|212|0.0%|0.7%|
[snort_ipfilter](#snort_ipfilter)|9136|9136|205|2.2%|0.7%|
[et_block](#et_block)|1000|18343756|202|0.0%|0.7%|
[proxz](#proxz)|1356|1356|198|14.6%|0.7%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|183|0.0%|0.6%|
[blocklist_de_strongips](#blocklist_de_strongips)|170|170|170|100.0%|0.6%|
[iw_spamlist](#iw_spamlist)|3648|3648|122|3.3%|0.4%|
[php_dictionary](#php_dictionary)|737|737|114|15.4%|0.4%|
[php_commenters](#php_commenters)|458|458|106|23.1%|0.3%|
[php_spammers](#php_spammers)|735|735|105|14.2%|0.3%|
[openbl_1d](#openbl_1d)|124|124|105|84.6%|0.3%|
[dshield](#dshield)|20|5120|84|1.6%|0.3%|
[sorbs_web](#sorbs_web)|628|629|71|11.2%|0.2%|
[ri_connect_proxies](#ri_connect_proxies)|2855|2855|68|2.3%|0.2%|
[blocklist_de_sip](#blocklist_de_sip)|83|83|64|77.1%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|55|0.0%|0.2%|
[dragon_http](#dragon_http)|1021|268288|49|0.0%|0.1%|
[voipbl](#voipbl)|10586|10998|41|0.3%|0.1%|
[php_harvesters](#php_harvesters)|408|408|37|9.0%|0.1%|
[ciarmy](#ciarmy)|416|416|35|8.4%|0.1%|
[tor_exits](#tor_exits)|1106|1106|19|1.7%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|15|0.0%|0.0%|
[et_tor](#et_tor)|6500|6500|13|0.2%|0.0%|
[dm_tor](#dm_tor)|6468|6468|11|0.1%|0.0%|
[bm_tor](#bm_tor)|6471|6471|11|0.1%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|5|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|5|0.9%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|5|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|5|0.7%|0.0%|
[dragon_vncprobe](#dragon_vncprobe)|87|87|5|5.7%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|2|0.1%|0.0%|
[virbl](#virbl)|22|22|1|4.5%|0.0%|
[sorbs_socks](#sorbs_socks)|7|7|1|14.2%|0.0%|
[sorbs_misc](#sorbs_misc)|7|7|1|14.2%|0.0%|
[sorbs_http](#sorbs_http)|7|7|1|14.2%|0.0%|
[iw_wormlist](#iw_wormlist)|34|34|1|2.9%|0.0%|

## blocklist_de_apache

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service Apache, Apache-DDOS, RFI-Attacks.

Source is downloaded from [this link](http://lists.blocklist.de/lists/apache.txt).

The last time downloaded was found to be dated: Fri Jun 12 09:14:08 UTC 2015.

The ipset `blocklist_de_apache` has **13845** entries, **13845** unique IPs.

The following table shows the overlaps of `blocklist_de_apache` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_apache`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_apache`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_apache`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|20666|32229|13828|42.9%|99.8%|
[blocklist_de](#blocklist_de)|26985|26985|13828|51.2%|99.8%|
[blocklist_de_mail](#blocklist_de_mail)|17750|17750|11059|62.3%|79.8%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2446|2446|2446|100.0%|17.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|2284|0.0%|16.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|1319|0.0%|9.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|1073|0.0%|7.7%|
[firehol_level3](#firehol_level3)|109549|9627220|270|0.0%|1.9%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|186|0.1%|1.3%|
[alienvault_reputation](#alienvault_reputation)|189146|189146|120|0.0%|0.8%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|108|0.3%|0.7%|
[stopforumspam_1d](#stopforumspam_1d)|6669|6669|53|0.7%|0.3%|
[sorbs_spam](#sorbs_spam)|64701|65536|44|0.0%|0.3%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|44|0.0%|0.3%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|44|0.0%|0.3%|
[shunlist](#shunlist)|1185|1185|37|3.1%|0.2%|
[blocklist_de_strongips](#blocklist_de_strongips)|170|170|31|18.2%|0.2%|
[snort_ipfilter](#snort_ipfilter)|9136|9136|30|0.3%|0.2%|
[ciarmy](#ciarmy)|416|416|30|7.2%|0.2%|
[php_commenters](#php_commenters)|458|458|28|6.1%|0.2%|
[blocklist_de_bots](#blocklist_de_bots)|2972|2972|23|0.7%|0.1%|
[firehol_anonymous](#firehol_anonymous)|19172|83219|21|0.0%|0.1%|
[tor_exits](#tor_exits)|1106|1106|19|1.7%|0.1%|
[nixspam](#nixspam)|18198|18198|17|0.0%|0.1%|
[et_tor](#et_tor)|6500|6500|13|0.2%|0.0%|
[dragon_http](#dragon_http)|1021|268288|11|0.0%|0.0%|
[dm_tor](#dm_tor)|6468|6468|11|0.1%|0.0%|
[bm_tor](#bm_tor)|6471|6471|11|0.1%|0.0%|
[et_block](#et_block)|1000|18343756|9|0.0%|0.0%|
[openbl_60d](#openbl_60d)|6960|6960|8|0.1%|0.0%|
[firehol_level1](#firehol_level1)|5070|688854680|7|0.0%|0.0%|
[php_spammers](#php_spammers)|735|735|6|0.8%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|5|0.0%|0.0%|
[openbl_30d](#openbl_30d)|2792|2792|5|0.1%|0.0%|
[php_dictionary](#php_dictionary)|737|737|3|0.4%|0.0%|
[iw_spamlist](#iw_spamlist)|3648|3648|3|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|3|0.0%|0.0%|
[voipbl](#voipbl)|10586|10998|2|0.0%|0.0%|
[php_harvesters](#php_harvesters)|408|408|2|0.4%|0.0%|
[openbl_7d](#openbl_7d)|629|629|2|0.3%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|2|0.0%|0.0%|
[firehol_proxies](#firehol_proxies)|12734|13010|2|0.0%|0.0%|
[dragon_vncprobe](#dragon_vncprobe)|87|87|2|2.2%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|1|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2855|2855|1|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|1|0.1%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.0%|
[dshield](#dshield)|20|5120|1|0.0%|0.0%|

## blocklist_de_bots

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the RFI-Attacks, REG-Bots, IRC-Bots or BadBots (BadBots = he has posted a Spam-Comment on a open Forum or Wiki).

Source is downloaded from [this link](http://lists.blocklist.de/lists/bots.txt).

The last time downloaded was found to be dated: Fri Jun 12 09:14:10 UTC 2015.

The ipset `blocklist_de_bots` has **2972** entries, **2972** unique IPs.

The following table shows the overlaps of `blocklist_de_bots` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_bots`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_bots`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_bots`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|20666|32229|2966|9.2%|99.7%|
[blocklist_de](#blocklist_de)|26985|26985|2961|10.9%|99.6%|
[firehol_level3](#firehol_level3)|109549|9627220|2317|0.0%|77.9%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|2294|2.4%|77.1%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|2180|7.5%|73.3%|
[stopforumspam_1d](#stopforumspam_1d)|6669|6669|1392|20.8%|46.8%|
[firehol_anonymous](#firehol_anonymous)|19172|83219|517|0.6%|17.3%|
[firehol_proxies](#firehol_proxies)|12734|13010|516|3.9%|17.3%|
[ri_web_proxies](#ri_web_proxies)|7952|7952|382|4.8%|12.8%|
[proxyrss](#proxyrss)|1570|1570|214|13.6%|7.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|182|0.0%|6.1%|
[xroxy](#xroxy)|2175|2175|175|8.0%|5.8%|
[proxz](#proxz)|1356|1356|168|12.3%|5.6%|
[blocklist_de_strongips](#blocklist_de_strongips)|170|170|130|76.4%|4.3%|
[php_commenters](#php_commenters)|458|458|86|18.7%|2.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|77|0.0%|2.5%|
[ri_connect_proxies](#ri_connect_proxies)|2855|2855|64|2.2%|2.1%|
[firehol_level1](#firehol_level1)|5070|688854680|59|0.0%|1.9%|
[et_block](#et_block)|1000|18343756|58|0.0%|1.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|52|0.0%|1.7%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|49|0.0%|1.6%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|42|0.0%|1.4%|
[nixspam](#nixspam)|18198|18198|40|0.2%|1.3%|
[sorbs_spam](#sorbs_spam)|64701|65536|28|0.0%|0.9%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|28|0.0%|0.9%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|28|0.0%|0.9%|
[php_harvesters](#php_harvesters)|408|408|27|6.6%|0.9%|
[php_spammers](#php_spammers)|735|735|23|3.1%|0.7%|
[blocklist_de_mail](#blocklist_de_mail)|17750|17750|23|0.1%|0.7%|
[blocklist_de_apache](#blocklist_de_apache)|13845|13845|23|0.1%|0.7%|
[alienvault_reputation](#alienvault_reputation)|189146|189146|21|0.0%|0.7%|
[snort_ipfilter](#snort_ipfilter)|9136|9136|20|0.2%|0.6%|
[php_dictionary](#php_dictionary)|737|737|17|2.3%|0.5%|
[dshield](#dshield)|20|5120|8|0.1%|0.2%|
[sorbs_web](#sorbs_web)|628|629|6|0.9%|0.2%|
[iw_spamlist](#iw_spamlist)|3648|3648|5|0.1%|0.1%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|4|0.7%|0.1%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|4|0.6%|0.1%|
[dragon_http](#dragon_http)|1021|268288|3|0.0%|0.1%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|2|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|2|0.1%|0.0%|
[voipbl](#voipbl)|10586|10998|1|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.0%|

## blocklist_de_bruteforce

[Blocklist.de](https://www.blocklist.de/) All IPs which attacks Joomlas, Wordpress and other Web-Logins with Brute-Force Logins.

Source is downloaded from [this link](http://lists.blocklist.de/lists/bruteforcelogin.txt).

The last time downloaded was found to be dated: Fri Jun 12 09:28:10 UTC 2015.

The ipset `blocklist_de_bruteforce` has **2446** entries, **2446** unique IPs.

The following table shows the overlaps of `blocklist_de_bruteforce` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_bruteforce`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_bruteforce`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_bruteforce`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|20666|32229|2446|7.5%|100.0%|
[blocklist_de_apache](#blocklist_de_apache)|13845|13845|2446|17.6%|100.0%|
[blocklist_de](#blocklist_de)|26985|26985|2446|9.0%|100.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|186|0.0%|7.6%|
[firehol_level3](#firehol_level3)|109549|9627220|75|0.0%|3.0%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|56|0.0%|2.2%|
[sorbs_spam](#sorbs_spam)|64701|65536|44|0.0%|1.7%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|44|0.0%|1.7%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|44|0.0%|1.7%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|39|0.1%|1.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|39|0.0%|1.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|33|0.0%|1.3%|
[snort_ipfilter](#snort_ipfilter)|9136|9136|28|0.3%|1.1%|
[stopforumspam_1d](#stopforumspam_1d)|6669|6669|20|0.2%|0.8%|
[tor_exits](#tor_exits)|1106|1106|17|1.5%|0.6%|
[firehol_anonymous](#firehol_anonymous)|19172|83219|17|0.0%|0.6%|
[nixspam](#nixspam)|18198|18198|15|0.0%|0.6%|
[alienvault_reputation](#alienvault_reputation)|189146|189146|12|0.0%|0.4%|
[et_tor](#et_tor)|6500|6500|10|0.1%|0.4%|
[dm_tor](#dm_tor)|6468|6468|8|0.1%|0.3%|
[bm_tor](#bm_tor)|6471|6471|8|0.1%|0.3%|
[blocklist_de_strongips](#blocklist_de_strongips)|170|170|7|4.1%|0.2%|
[php_spammers](#php_spammers)|735|735|6|0.8%|0.2%|
[php_commenters](#php_commenters)|458|458|6|1.3%|0.2%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|5|0.0%|0.2%|
[firehol_level1](#firehol_level1)|5070|688854680|5|0.0%|0.2%|
[et_block](#et_block)|1000|18343756|5|0.0%|0.2%|
[dragon_http](#dragon_http)|1021|268288|4|0.0%|0.1%|
[php_dictionary](#php_dictionary)|737|737|3|0.4%|0.1%|
[iw_spamlist](#iw_spamlist)|3648|3648|3|0.0%|0.1%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|2|0.0%|0.0%|
[shunlist](#shunlist)|1185|1185|1|0.0%|0.0%|
[php_harvesters](#php_harvesters)|408|408|1|0.2%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.0%|

## blocklist_de_ftp

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours for attacks on the Service FTP.

Source is downloaded from [this link](http://lists.blocklist.de/lists/ftp.txt).

The last time downloaded was found to be dated: Fri Jun 12 09:10:07 UTC 2015.

The ipset `blocklist_de_ftp` has **1523** entries, **1523** unique IPs.

The following table shows the overlaps of `blocklist_de_ftp` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_ftp`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_ftp`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_ftp`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|20666|32229|1508|4.6%|99.0%|
[blocklist_de](#blocklist_de)|26985|26985|1508|5.5%|99.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|110|0.0%|7.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|27|0.0%|1.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|21|0.0%|1.3%|
[firehol_level3](#firehol_level3)|109549|9627220|16|0.0%|1.0%|
[sorbs_spam](#sorbs_spam)|64701|65536|15|0.0%|0.9%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|15|0.0%|0.9%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|15|0.0%|0.9%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|11|0.0%|0.7%|
[nixspam](#nixspam)|18198|18198|11|0.0%|0.7%|
[alienvault_reputation](#alienvault_reputation)|189146|189146|8|0.0%|0.5%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|6|0.0%|0.3%|
[dragon_http](#dragon_http)|1021|268288|6|0.0%|0.3%|
[firehol_anonymous](#firehol_anonymous)|19172|83219|4|0.0%|0.2%|
[stopforumspam_1d](#stopforumspam_1d)|6669|6669|3|0.0%|0.1%|
[php_harvesters](#php_harvesters)|408|408|3|0.7%|0.1%|
[openbl_60d](#openbl_60d)|6960|6960|2|0.0%|0.1%|
[iw_spamlist](#iw_spamlist)|3648|3648|2|0.0%|0.1%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|2|0.0%|0.1%|
[sorbs_web](#sorbs_web)|628|629|1|0.1%|0.0%|
[php_spammers](#php_spammers)|735|735|1|0.1%|0.0%|
[php_dictionary](#php_dictionary)|737|737|1|0.1%|0.0%|
[openbl_7d](#openbl_7d)|629|629|1|0.1%|0.0%|
[openbl_30d](#openbl_30d)|2792|2792|1|0.0%|0.0%|

## blocklist_de_imap

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours for attacks on the Service imap, sasl, pop3, etc.

Source is downloaded from [this link](http://lists.blocklist.de/lists/imap.txt).

The last time downloaded was found to be dated: Fri Jun 12 09:14:09 UTC 2015.

The ipset `blocklist_de_imap` has **2726** entries, **2726** unique IPs.

The following table shows the overlaps of `blocklist_de_imap` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_imap`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_imap`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_imap`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de_mail](#blocklist_de_mail)|17750|17750|2726|15.3%|100.0%|
[firehol_level2](#firehol_level2)|20666|32229|2715|8.4%|99.5%|
[blocklist_de](#blocklist_de)|26985|26985|2715|10.0%|99.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|283|0.0%|10.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|78|0.0%|2.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|61|0.0%|2.2%|
[firehol_level3](#firehol_level3)|109549|9627220|36|0.0%|1.3%|
[alienvault_reputation](#alienvault_reputation)|189146|189146|32|0.0%|1.1%|
[sorbs_spam](#sorbs_spam)|64701|65536|27|0.0%|0.9%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|26|0.0%|0.9%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|26|0.0%|0.9%|
[nixspam](#nixspam)|18198|18198|25|0.1%|0.9%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|16|0.0%|0.5%|
[firehol_level1](#firehol_level1)|5070|688854680|16|0.0%|0.5%|
[et_block](#et_block)|1000|18343756|16|0.0%|0.5%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|15|0.0%|0.5%|
[openbl_60d](#openbl_60d)|6960|6960|15|0.2%|0.5%|
[openbl_30d](#openbl_30d)|2792|2792|9|0.3%|0.3%|
[dragon_http](#dragon_http)|1021|268288|7|0.0%|0.2%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|6|0.0%|0.2%|
[openbl_7d](#openbl_7d)|629|629|5|0.7%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|4|0.0%|0.1%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|4|0.0%|0.1%|
[et_compromised](#et_compromised)|1704|1704|4|0.2%|0.1%|
[bruteforceblocker](#bruteforceblocker)|1694|1694|4|0.2%|0.1%|
[stopforumspam_1d](#stopforumspam_1d)|6669|6669|2|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9136|9136|2|0.0%|0.0%|
[shunlist](#shunlist)|1185|1185|2|0.1%|0.0%|
[php_harvesters](#php_harvesters)|408|408|2|0.4%|0.0%|
[iw_spamlist](#iw_spamlist)|3648|3648|2|0.0%|0.0%|
[voipbl](#voipbl)|10586|10998|1|0.0%|0.0%|
[virbl](#virbl)|22|22|1|4.5%|0.0%|
[openbl_1d](#openbl_1d)|124|124|1|0.8%|0.0%|
[dragon_vncprobe](#dragon_vncprobe)|87|87|1|1.1%|0.0%|
[dragon_sshpauth](#dragon_sshpauth)|1589|1653|1|0.0%|0.0%|
[ciarmy](#ciarmy)|416|416|1|0.2%|0.0%|

## blocklist_de_mail

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service Mail, Postfix.

Source is downloaded from [this link](http://lists.blocklist.de/lists/mail.txt).

The last time downloaded was found to be dated: Fri Jun 12 09:14:07 UTC 2015.

The ipset `blocklist_de_mail` has **17750** entries, **17750** unique IPs.

The following table shows the overlaps of `blocklist_de_mail` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_mail`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_mail`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_mail`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|20666|32229|17699|54.9%|99.7%|
[blocklist_de](#blocklist_de)|26985|26985|17699|65.5%|99.7%|
[blocklist_de_apache](#blocklist_de_apache)|13845|13845|11059|79.8%|62.3%|
[blocklist_de_imap](#blocklist_de_imap)|2726|2726|2726|100.0%|15.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|2576|0.0%|14.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|1419|0.0%|7.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|1226|0.0%|6.9%|
[sorbs_spam](#sorbs_spam)|64701|65536|917|1.3%|5.1%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|909|1.3%|5.1%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|909|1.3%|5.1%|
[nixspam](#nixspam)|18198|18198|425|2.3%|2.3%|
[firehol_level3](#firehol_level3)|109549|9627220|382|0.0%|2.1%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|252|0.2%|1.4%|
[snort_ipfilter](#snort_ipfilter)|9136|9136|157|1.7%|0.8%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|135|0.4%|0.7%|
[firehol_anonymous](#firehol_anonymous)|19172|83219|124|0.1%|0.6%|
[firehol_proxies](#firehol_proxies)|12734|13010|122|0.9%|0.6%|
[iw_spamlist](#iw_spamlist)|3648|3648|112|3.0%|0.6%|
[php_dictionary](#php_dictionary)|737|737|93|12.6%|0.5%|
[ri_web_proxies](#ri_web_proxies)|7952|7952|87|1.0%|0.4%|
[php_spammers](#php_spammers)|735|735|74|10.0%|0.4%|
[sorbs_web](#sorbs_web)|628|629|64|10.1%|0.3%|
[xroxy](#xroxy)|2175|2175|52|2.3%|0.2%|
[stopforumspam_1d](#stopforumspam_1d)|6669|6669|46|0.6%|0.2%|
[alienvault_reputation](#alienvault_reputation)|189146|189146|46|0.0%|0.2%|
[proxz](#proxz)|1356|1356|30|2.2%|0.1%|
[php_commenters](#php_commenters)|458|458|29|6.3%|0.1%|
[firehol_level1](#firehol_level1)|5070|688854680|24|0.0%|0.1%|
[et_block](#et_block)|1000|18343756|23|0.0%|0.1%|
[blocklist_de_bots](#blocklist_de_bots)|2972|2972|23|0.7%|0.1%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|22|0.0%|0.1%|
[blocklist_de_strongips](#blocklist_de_strongips)|170|170|21|12.3%|0.1%|
[openbl_60d](#openbl_60d)|6960|6960|18|0.2%|0.1%|
[openbl_30d](#openbl_30d)|2792|2792|12|0.4%|0.0%|
[dragon_http](#dragon_http)|1021|268288|12|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|10|0.0%|0.0%|
[openbl_7d](#openbl_7d)|629|629|6|0.9%|0.0%|
[php_harvesters](#php_harvesters)|408|408|5|1.2%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|5|0.0%|0.0%|
[et_compromised](#et_compromised)|1704|1704|4|0.2%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1694|1694|4|0.2%|0.0%|
[shunlist](#shunlist)|1185|1185|3|0.2%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2855|2855|3|0.1%|0.0%|
[et_tor](#et_tor)|6500|6500|3|0.0%|0.0%|
[dm_tor](#dm_tor)|6468|6468|3|0.0%|0.0%|
[ciarmy](#ciarmy)|416|416|3|0.7%|0.0%|
[bm_tor](#bm_tor)|6471|6471|3|0.0%|0.0%|
[voipbl](#voipbl)|10586|10998|2|0.0%|0.0%|
[tor_exits](#tor_exits)|1106|1106|2|0.1%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|2|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|2|0.0%|0.0%|
[dragon_vncprobe](#dragon_vncprobe)|87|87|2|2.2%|0.0%|
[virbl](#virbl)|22|22|1|4.5%|0.0%|
[sorbs_socks](#sorbs_socks)|7|7|1|14.2%|0.0%|
[sorbs_misc](#sorbs_misc)|7|7|1|14.2%|0.0%|
[sorbs_http](#sorbs_http)|7|7|1|14.2%|0.0%|
[openbl_1d](#openbl_1d)|124|124|1|0.8%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|1|0.1%|0.0%|
[iw_wormlist](#iw_wormlist)|34|34|1|2.9%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|1|0.1%|0.0%|
[dragon_sshpauth](#dragon_sshpauth)|1589|1653|1|0.0%|0.0%|

## blocklist_de_sip

[Blocklist.de](https://www.blocklist.de/) All IP addresses that tried to login in a SIP, VOIP or Asterisk Server and are included in the IPs list from [infiltrated.net](www.infiltrated.net)

Source is downloaded from [this link](http://lists.blocklist.de/lists/sip.txt).

The last time downloaded was found to be dated: Fri Jun 12 09:14:09 UTC 2015.

The ipset `blocklist_de_sip` has **83** entries, **83** unique IPs.

The following table shows the overlaps of `blocklist_de_sip` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_sip`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_sip`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_sip`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|20666|32229|64|0.1%|77.1%|
[blocklist_de](#blocklist_de)|26985|26985|64|0.2%|77.1%|
[voipbl](#voipbl)|10586|10998|34|0.3%|40.9%|
[alienvault_reputation](#alienvault_reputation)|189146|189146|20|0.0%|24.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|15|0.0%|18.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|5|0.0%|6.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|4|0.0%|4.8%|
[firehol_level3](#firehol_level3)|109549|9627220|4|0.0%|4.8%|
[dragon_http](#dragon_http)|1021|268288|3|0.0%|3.6%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|2|0.0%|2.4%|
[shunlist](#shunlist)|1185|1185|2|0.1%|2.4%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|2|0.0%|2.4%|
[firehol_level1](#firehol_level1)|5070|688854680|2|0.0%|2.4%|
[et_block](#et_block)|1000|18343756|2|0.0%|2.4%|
[et_botcc](#et_botcc)|505|505|1|0.1%|1.2%|

## blocklist_de_ssh

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service SSH.

Source is downloaded from [this link](http://lists.blocklist.de/lists/ssh.txt).

The last time downloaded was found to be dated: Fri Jun 12 09:10:04 UTC 2015.

The ipset `blocklist_de_ssh` has **1901** entries, **1901** unique IPs.

The following table shows the overlaps of `blocklist_de_ssh` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_ssh`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_ssh`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_ssh`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|20666|32229|1876|5.8%|98.6%|
[blocklist_de](#blocklist_de)|26985|26985|1876|6.9%|98.6%|
[alienvault_reputation](#alienvault_reputation)|189146|189146|839|0.4%|44.1%|
[firehol_level3](#firehol_level3)|109549|9627220|813|0.0%|42.7%|
[openbl_60d](#openbl_60d)|6960|6960|693|9.9%|36.4%|
[dragon_sshpauth](#dragon_sshpauth)|1589|1653|635|38.4%|33.4%|
[openbl_30d](#openbl_30d)|2792|2792|612|21.9%|32.1%|
[bruteforceblocker](#bruteforceblocker)|1694|1694|548|32.3%|28.8%|
[et_compromised](#et_compromised)|1704|1704|528|30.9%|27.7%|
[openbl_7d](#openbl_7d)|629|629|361|57.3%|18.9%|
[shunlist](#shunlist)|1185|1185|306|25.8%|16.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|186|0.0%|9.7%|
[firehol_level1](#firehol_level1)|5070|688854680|121|0.0%|6.3%|
[et_block](#et_block)|1000|18343756|111|0.0%|5.8%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|106|0.0%|5.5%|
[openbl_1d](#openbl_1d)|124|124|103|83.0%|5.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|92|0.0%|4.8%|
[dshield](#dshield)|20|5120|76|1.4%|3.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|42|0.0%|2.2%|
[blocklist_de_strongips](#blocklist_de_strongips)|170|170|28|16.4%|1.4%|
[dragon_http](#dragon_http)|1021|268288|14|0.0%|0.7%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|12|0.0%|0.6%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|7|0.0%|0.3%|
[sorbs_spam](#sorbs_spam)|64701|65536|4|0.0%|0.2%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|4|0.0%|0.2%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|4|0.0%|0.2%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|3|0.0%|0.1%|
[ciarmy](#ciarmy)|416|416|3|0.7%|0.1%|
[voipbl](#voipbl)|10586|10998|2|0.0%|0.1%|
[ri_web_proxies](#ri_web_proxies)|7952|7952|1|0.0%|0.0%|
[php_spammers](#php_spammers)|735|735|1|0.1%|0.0%|
[php_harvesters](#php_harvesters)|408|408|1|0.2%|0.0%|
[php_commenters](#php_commenters)|458|458|1|0.2%|0.0%|
[nixspam](#nixspam)|18198|18198|1|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|1|0.0%|0.0%|
[firehol_proxies](#firehol_proxies)|12734|13010|1|0.0%|0.0%|
[firehol_anonymous](#firehol_anonymous)|19172|83219|1|0.0%|0.0%|
[dragon_vncprobe](#dragon_vncprobe)|87|87|1|1.1%|0.0%|

## blocklist_de_strongips

[Blocklist.de](https://www.blocklist.de/) All IPs which are older then 2 month and have more then 5.000 attacks.

Source is downloaded from [this link](http://lists.blocklist.de/lists/strongips.txt).

The last time downloaded was found to be dated: Fri Jun 12 09:14:12 UTC 2015.

The ipset `blocklist_de_strongips` has **170** entries, **170** unique IPs.

The following table shows the overlaps of `blocklist_de_strongips` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_strongips`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_strongips`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_strongips`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|20666|32229|170|0.5%|100.0%|
[blocklist_de](#blocklist_de)|26985|26985|170|0.6%|100.0%|
[firehol_level3](#firehol_level3)|109549|9627220|156|0.0%|91.7%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|130|0.1%|76.4%|
[blocklist_de_bots](#blocklist_de_bots)|2972|2972|130|4.3%|76.4%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|116|0.3%|68.2%|
[stopforumspam_1d](#stopforumspam_1d)|6669|6669|101|1.5%|59.4%|
[php_commenters](#php_commenters)|458|458|44|9.6%|25.8%|
[alienvault_reputation](#alienvault_reputation)|189146|189146|35|0.0%|20.5%|
[blocklist_de_apache](#blocklist_de_apache)|13845|13845|31|0.2%|18.2%|
[blocklist_de_ssh](#blocklist_de_ssh)|1901|1901|28|1.4%|16.4%|
[openbl_60d](#openbl_60d)|6960|6960|24|0.3%|14.1%|
[openbl_30d](#openbl_30d)|2792|2792|23|0.8%|13.5%|
[openbl_7d](#openbl_7d)|629|629|22|3.4%|12.9%|
[blocklist_de_mail](#blocklist_de_mail)|17750|17750|21|0.1%|12.3%|
[firehol_level1](#firehol_level1)|5070|688854680|20|0.0%|11.7%|
[dragon_sshpauth](#dragon_sshpauth)|1589|1653|20|1.2%|11.7%|
[shunlist](#shunlist)|1185|1185|19|1.6%|11.1%|
[openbl_1d](#openbl_1d)|124|124|18|14.5%|10.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|17|0.0%|10.0%|
[et_block](#et_block)|1000|18343756|14|0.0%|8.2%|
[dshield](#dshield)|20|5120|12|0.2%|7.0%|
[php_spammers](#php_spammers)|735|735|10|1.3%|5.8%|
[firehol_proxies](#firehol_proxies)|12734|13010|9|0.0%|5.2%|
[firehol_anonymous](#firehol_anonymous)|19172|83219|9|0.0%|5.2%|
[ri_web_proxies](#ri_web_proxies)|7952|7952|8|0.1%|4.7%|
[xroxy](#xroxy)|2175|2175|7|0.3%|4.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|7|0.0%|4.1%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2446|2446|7|0.2%|4.1%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|6|0.0%|3.5%|
[proxz](#proxz)|1356|1356|6|0.4%|3.5%|
[proxyrss](#proxyrss)|1570|1570|6|0.3%|3.5%|
[php_dictionary](#php_dictionary)|737|737|5|0.6%|2.9%|
[php_harvesters](#php_harvesters)|408|408|3|0.7%|1.7%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|1.7%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|2|0.0%|1.1%|
[sorbs_web](#sorbs_web)|628|629|2|0.3%|1.1%|
[sorbs_spam](#sorbs_spam)|64701|65536|2|0.0%|1.1%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|2|0.0%|1.1%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|2|0.0%|1.1%|
[snort_ipfilter](#snort_ipfilter)|9136|9136|2|0.0%|1.1%|
[nixspam](#nixspam)|18198|18198|2|0.0%|1.1%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|2|0.1%|1.1%|
[dragon_http](#dragon_http)|1021|268288|2|0.0%|1.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|1|0.0%|0.5%|
[et_compromised](#et_compromised)|1704|1704|1|0.0%|0.5%|
[ciarmy](#ciarmy)|416|416|1|0.2%|0.5%|
[bruteforceblocker](#bruteforceblocker)|1694|1694|1|0.0%|0.5%|

## bm_tor

[torstatus.blutmagie.de](https://torstatus.blutmagie.de) list of all TOR network servers

Source is downloaded from [this link](https://torstatus.blutmagie.de/ip_list_all.php/Tor_ip_list_ALL.csv).

The last time downloaded was found to be dated: Fri Jun 12 09:36:04 UTC 2015.

The ipset `bm_tor` has **6471** entries, **6471** unique IPs.

The following table shows the overlaps of `bm_tor` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `bm_tor`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `bm_tor`.
- ` this % ` is the percentage **of this ipset (`bm_tor`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_anonymous](#firehol_anonymous)|19172|83219|6471|7.7%|100.0%|
[dm_tor](#dm_tor)|6468|6468|6468|100.0%|99.9%|
[et_tor](#et_tor)|6500|6500|5755|88.5%|88.9%|
[firehol_level3](#firehol_level3)|109549|9627220|1087|0.0%|16.7%|
[snort_ipfilter](#snort_ipfilter)|9136|9136|1050|11.4%|16.2%|
[tor_exits](#tor_exits)|1106|1106|1017|91.9%|15.7%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|631|0.6%|9.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|629|0.0%|9.7%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|529|1.8%|8.1%|
[firehol_level2](#firehol_level2)|20666|32229|318|0.9%|4.9%|
[stopforumspam_1d](#stopforumspam_1d)|6669|6669|312|4.6%|4.8%|
[firehol_proxies](#firehol_proxies)|12734|13010|234|1.7%|3.6%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|229|43.7%|3.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|186|0.0%|2.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|171|0.0%|2.6%|
[php_commenters](#php_commenters)|458|458|54|11.7%|0.8%|
[alienvault_reputation](#alienvault_reputation)|189146|189146|42|0.0%|0.6%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|22|0.0%|0.3%|
[openbl_60d](#openbl_60d)|6960|6960|20|0.2%|0.3%|
[dragon_http](#dragon_http)|1021|268288|16|0.0%|0.2%|
[blocklist_de_apache](#blocklist_de_apache)|13845|13845|11|0.0%|0.1%|
[blocklist_de](#blocklist_de)|26985|26985|11|0.0%|0.1%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2446|2446|8|0.3%|0.1%|
[php_harvesters](#php_harvesters)|408|408|7|1.7%|0.1%|
[nixspam](#nixspam)|18198|18198|6|0.0%|0.0%|
[firehol_level1](#firehol_level1)|5070|688854680|6|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7952|7952|5|0.0%|0.0%|
[php_spammers](#php_spammers)|735|735|5|0.6%|0.0%|
[sorbs_spam](#sorbs_spam)|64701|65536|4|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|4|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|4|0.0%|0.0%|
[php_dictionary](#php_dictionary)|737|737|4|0.5%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|4|0.0%|0.0%|
[et_block](#et_block)|1000|18343756|4|0.0%|0.0%|
[voipbl](#voipbl)|10586|10998|3|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|3|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|17750|17750|3|0.0%|0.0%|
[xroxy](#xroxy)|2175|2175|2|0.0%|0.0%|
[dshield](#dshield)|20|5120|2|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|1|0.0%|0.0%|
[shunlist](#shunlist)|1185|1185|1|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2855|2855|1|0.0%|0.0%|
[proxyrss](#proxyrss)|1570|1570|1|0.0%|0.0%|

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
[fullbogons](#fullbogons)|3775|670173256|592708608|88.4%|100.0%|
[firehol_level1](#firehol_level1)|5070|688854680|592708608|86.0%|100.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|4194304|3.0%|0.7%|
[voipbl](#voipbl)|10586|10998|319|2.9%|0.0%|
[iw_spamlist](#iw_spamlist)|3648|3648|5|0.1%|0.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|5|0.0%|0.0%|
[firehol_level3](#firehol_level3)|109549|9627220|3|0.0%|0.0%|
[php_harvesters](#php_harvesters)|408|408|1|0.2%|0.0%|
[php_commenters](#php_commenters)|458|458|1|0.2%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.0%|
[ciarmy](#ciarmy)|416|416|1|0.2%|0.0%|

## bruteforceblocker

[danger.rulez.sk](http://danger.rulez.sk/) IPs detected by [bruteforceblocker](http://danger.rulez.sk/index.php/bruteforceblocker/) (fail2ban alternative for SSH on OpenBSD). This is an automatically generated list from users reporting failed authentication attempts. An IP seems to be included if 3 or more users report it. Its retention pocily seems 30 days.

Source is downloaded from [this link](http://danger.rulez.sk/projects/bruteforceblocker/blist.php).

The last time downloaded was found to be dated: Fri Jun 12 09:01:26 UTC 2015.

The ipset `bruteforceblocker` has **1694** entries, **1694** unique IPs.

The following table shows the overlaps of `bruteforceblocker` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `bruteforceblocker`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `bruteforceblocker`.
- ` this % ` is the percentage **of this ipset (`bruteforceblocker`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level3](#firehol_level3)|109549|9627220|1694|0.0%|100.0%|
[et_compromised](#et_compromised)|1704|1704|1654|97.0%|97.6%|
[alienvault_reputation](#alienvault_reputation)|189146|189146|1070|0.5%|63.1%|
[openbl_60d](#openbl_60d)|6960|6960|963|13.8%|56.8%|
[openbl_30d](#openbl_30d)|2792|2792|904|32.3%|53.3%|
[dragon_sshpauth](#dragon_sshpauth)|1589|1653|636|38.4%|37.5%|
[firehol_level2](#firehol_level2)|20666|32229|555|1.7%|32.7%|
[blocklist_de](#blocklist_de)|26985|26985|554|2.0%|32.7%|
[blocklist_de_ssh](#blocklist_de_ssh)|1901|1901|548|28.8%|32.3%|
[shunlist](#shunlist)|1185|1185|342|28.8%|20.1%|
[openbl_7d](#openbl_7d)|629|629|308|48.9%|18.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|157|0.0%|9.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|86|0.0%|5.0%|
[firehol_level1](#firehol_level1)|5070|688854680|67|0.0%|3.9%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|61|0.0%|3.6%|
[et_block](#et_block)|1000|18343756|61|0.0%|3.6%|
[openbl_1d](#openbl_1d)|124|124|56|45.1%|3.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|53|0.0%|3.1%|
[dshield](#dshield)|20|5120|25|0.4%|1.4%|
[dragon_http](#dragon_http)|1021|268288|13|0.0%|0.7%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|9|0.0%|0.5%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|5|0.0%|0.2%|
[blocklist_de_mail](#blocklist_de_mail)|17750|17750|4|0.0%|0.2%|
[blocklist_de_imap](#blocklist_de_imap)|2726|2726|4|0.1%|0.2%|
[voipbl](#voipbl)|10586|10998|3|0.0%|0.1%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|3|0.0%|0.1%|
[sorbs_spam](#sorbs_spam)|64701|65536|3|0.0%|0.1%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|3|0.0%|0.1%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|3|0.0%|0.1%|
[firehol_proxies](#firehol_proxies)|12734|13010|3|0.0%|0.1%|
[firehol_anonymous](#firehol_anonymous)|19172|83219|3|0.0%|0.1%|
[ciarmy](#ciarmy)|416|416|3|0.7%|0.1%|
[proxz](#proxz)|1356|1356|2|0.1%|0.1%|
[nixspam](#nixspam)|18198|18198|2|0.0%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|2|0.0%|0.1%|
[xroxy](#xroxy)|2175|2175|1|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6669|6669|1|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7952|7952|1|0.0%|0.0%|
[proxyrss](#proxyrss)|1570|1570|1|0.0%|0.0%|
[php_spammers](#php_spammers)|735|735|1|0.1%|0.0%|
[php_commenters](#php_commenters)|458|458|1|0.2%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|170|170|1|0.5%|0.0%|

## ciarmy

[CIArmy.com](http://ciarmy.com/) IPs with poor Rogue Packet score that have not yet been identified as malicious by the community

Source is downloaded from [this link](http://cinsscore.com/list/ci-badguys.txt).

The last time downloaded was found to be dated: Fri Jun 12 07:15:06 UTC 2015.

The ipset `ciarmy` has **416** entries, **416** unique IPs.

The following table shows the overlaps of `ciarmy` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ciarmy`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ciarmy`.
- ` this % ` is the percentage **of this ipset (`ciarmy`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level3](#firehol_level3)|109549|9627220|416|0.0%|100.0%|
[alienvault_reputation](#alienvault_reputation)|189146|189146|400|0.2%|96.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|70|0.0%|16.8%|
[firehol_level2](#firehol_level2)|20666|32229|36|0.1%|8.6%|
[blocklist_de](#blocklist_de)|26985|26985|35|0.1%|8.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|33|0.0%|7.9%|
[blocklist_de_apache](#blocklist_de_apache)|13845|13845|30|0.2%|7.2%|
[shunlist](#shunlist)|1185|1185|29|2.4%|6.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|21|0.0%|5.0%|
[dragon_http](#dragon_http)|1021|268288|12|0.0%|2.8%|
[firehol_level1](#firehol_level1)|5070|688854680|6|0.0%|1.4%|
[dshield](#dshield)|20|5120|5|0.0%|1.2%|
[et_compromised](#et_compromised)|1704|1704|3|0.1%|0.7%|
[bruteforceblocker](#bruteforceblocker)|1694|1694|3|0.1%|0.7%|
[blocklist_de_ssh](#blocklist_de_ssh)|1901|1901|3|0.1%|0.7%|
[blocklist_de_mail](#blocklist_de_mail)|17750|17750|3|0.0%|0.7%|
[voipbl](#voipbl)|10586|10998|2|0.0%|0.4%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|2|0.0%|0.4%|
[openbl_7d](#openbl_7d)|629|629|2|0.3%|0.4%|
[openbl_60d](#openbl_60d)|6960|6960|2|0.0%|0.4%|
[openbl_30d](#openbl_30d)|2792|2792|2|0.0%|0.4%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|1|0.0%|0.2%|
[openbl_1d](#openbl_1d)|124|124|1|0.8%|0.2%|
[fullbogons](#fullbogons)|3775|670173256|1|0.0%|0.2%|
[et_block](#et_block)|1000|18343756|1|0.0%|0.2%|
[dragon_vncprobe](#dragon_vncprobe)|87|87|1|1.1%|0.2%|
[dragon_sshpauth](#dragon_sshpauth)|1589|1653|1|0.0%|0.2%|
[bogons](#bogons)|13|592708608|1|0.0%|0.2%|
[blocklist_de_strongips](#blocklist_de_strongips)|170|170|1|0.5%|0.2%|
[blocklist_de_imap](#blocklist_de_imap)|2726|2726|1|0.0%|0.2%|

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
[firehol_level3](#firehol_level3)|109549|9627220|511|0.0%|100.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|58|0.0%|11.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|28|0.0%|5.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|25|0.0%|4.8%|
[malc0de](#malc0de)|276|276|8|2.8%|1.5%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|4|0.3%|0.7%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|4|0.0%|0.7%|
[alienvault_reputation](#alienvault_reputation)|189146|189146|4|0.0%|0.7%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|1|0.0%|0.1%|
[sorbs_spam](#sorbs_spam)|64701|65536|1|0.0%|0.1%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|1|0.0%|0.1%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|1|0.0%|0.1%|
[snort_ipfilter](#snort_ipfilter)|9136|9136|1|0.0%|0.1%|
[nixspam](#nixspam)|18198|18198|1|0.0%|0.1%|

## dm_tor

[dan.me.uk](https://www.dan.me.uk) dynamic list of TOR nodes

Source is downloaded from [this link](https://www.dan.me.uk/torlist/).

The last time downloaded was found to be dated: Fri Jun 12 09:18:04 UTC 2015.

The ipset `dm_tor` has **6468** entries, **6468** unique IPs.

The following table shows the overlaps of `dm_tor` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `dm_tor`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `dm_tor`.
- ` this % ` is the percentage **of this ipset (`dm_tor`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_anonymous](#firehol_anonymous)|19172|83219|6468|7.7%|100.0%|
[bm_tor](#bm_tor)|6471|6471|6468|99.9%|100.0%|
[et_tor](#et_tor)|6500|6500|5752|88.4%|88.9%|
[firehol_level3](#firehol_level3)|109549|9627220|1086|0.0%|16.7%|
[snort_ipfilter](#snort_ipfilter)|9136|9136|1049|11.4%|16.2%|
[tor_exits](#tor_exits)|1106|1106|1016|91.8%|15.7%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|631|0.6%|9.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|629|0.0%|9.7%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|529|1.8%|8.1%|
[firehol_level2](#firehol_level2)|20666|32229|318|0.9%|4.9%|
[stopforumspam_1d](#stopforumspam_1d)|6669|6669|312|4.6%|4.8%|
[firehol_proxies](#firehol_proxies)|12734|13010|234|1.7%|3.6%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|229|43.7%|3.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|186|0.0%|2.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|171|0.0%|2.6%|
[php_commenters](#php_commenters)|458|458|54|11.7%|0.8%|
[alienvault_reputation](#alienvault_reputation)|189146|189146|42|0.0%|0.6%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|22|0.0%|0.3%|
[openbl_60d](#openbl_60d)|6960|6960|20|0.2%|0.3%|
[dragon_http](#dragon_http)|1021|268288|16|0.0%|0.2%|
[blocklist_de_apache](#blocklist_de_apache)|13845|13845|11|0.0%|0.1%|
[blocklist_de](#blocklist_de)|26985|26985|11|0.0%|0.1%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2446|2446|8|0.3%|0.1%|
[php_harvesters](#php_harvesters)|408|408|7|1.7%|0.1%|
[nixspam](#nixspam)|18198|18198|6|0.0%|0.0%|
[firehol_level1](#firehol_level1)|5070|688854680|6|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7952|7952|5|0.0%|0.0%|
[php_spammers](#php_spammers)|735|735|5|0.6%|0.0%|
[sorbs_spam](#sorbs_spam)|64701|65536|4|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|4|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|4|0.0%|0.0%|
[php_dictionary](#php_dictionary)|737|737|4|0.5%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|4|0.0%|0.0%|
[et_block](#et_block)|1000|18343756|4|0.0%|0.0%|
[voipbl](#voipbl)|10586|10998|3|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|3|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|17750|17750|3|0.0%|0.0%|
[xroxy](#xroxy)|2175|2175|2|0.0%|0.0%|
[dshield](#dshield)|20|5120|2|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|1|0.0%|0.0%|
[shunlist](#shunlist)|1185|1185|1|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2855|2855|1|0.0%|0.0%|
[proxyrss](#proxyrss)|1570|1570|1|0.0%|0.0%|

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
[alienvault_reputation](#alienvault_reputation)|189146|189146|6152|3.2%|2.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|5989|0.0%|2.2%|
[firehol_level1](#firehol_level1)|5070|688854680|1025|0.0%|0.3%|
[et_block](#et_block)|1000|18343756|1024|0.0%|0.3%|
[dshield](#dshield)|20|5120|768|15.0%|0.2%|
[firehol_level3](#firehol_level3)|109549|9627220|560|0.0%|0.2%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|256|0.0%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|256|0.0%|0.0%|
[openbl_60d](#openbl_60d)|6960|6960|213|3.0%|0.0%|
[openbl_30d](#openbl_30d)|2792|2792|146|5.2%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|108|0.1%|0.0%|
[sorbs_spam](#sorbs_spam)|64701|65536|72|0.1%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|71|0.1%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|71|0.1%|0.0%|
[firehol_level2](#firehol_level2)|20666|32229|60|0.1%|0.0%|
[openbl_7d](#openbl_7d)|629|629|51|8.1%|0.0%|
[blocklist_de](#blocklist_de)|26985|26985|49|0.1%|0.0%|
[firehol_anonymous](#firehol_anonymous)|19172|83219|45|0.0%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|32|0.1%|0.0%|
[firehol_proxies](#firehol_proxies)|12734|13010|32|0.2%|0.0%|
[voipbl](#voipbl)|10586|10998|29|0.2%|0.0%|
[nixspam](#nixspam)|18198|18198|27|0.1%|0.0%|
[shunlist](#shunlist)|1185|1185|26|2.1%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|25|0.0%|0.0%|
[dragon_vncprobe](#dragon_vncprobe)|87|87|24|27.5%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7952|7952|20|0.2%|0.0%|
[et_tor](#et_tor)|6500|6500|16|0.2%|0.0%|
[dm_tor](#dm_tor)|6468|6468|16|0.2%|0.0%|
[bm_tor](#bm_tor)|6471|6471|16|0.2%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1901|1901|14|0.7%|0.0%|
[et_compromised](#et_compromised)|1704|1704|13|0.7%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1694|1694|13|0.7%|0.0%|
[ciarmy](#ciarmy)|416|416|12|2.8%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|17750|17750|12|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9136|9136|11|0.1%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13845|13845|11|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6669|6669|7|0.1%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2726|2726|7|0.2%|0.0%|
[xroxy](#xroxy)|2175|2175|6|0.2%|0.0%|
[openbl_1d](#openbl_1d)|124|124|6|4.8%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|6|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|1523|1523|6|0.3%|0.0%|
[tor_exits](#tor_exits)|1106|1106|5|0.4%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2855|2855|4|0.1%|0.0%|
[proxz](#proxz)|1356|1356|4|0.2%|0.0%|
[php_commenters](#php_commenters)|458|458|4|0.8%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|4|0.7%|0.0%|
[dragon_sshpauth](#dragon_sshpauth)|1589|1653|4|0.2%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2446|2446|4|0.1%|0.0%|
[zeus_badips](#zeus_badips)|202|202|3|1.4%|0.0%|
[zeus](#zeus)|230|230|3|1.3%|0.0%|
[proxyrss](#proxyrss)|1570|1570|3|0.1%|0.0%|
[malc0de](#malc0de)|276|276|3|1.0%|0.0%|
[et_botcc](#et_botcc)|505|505|3|0.5%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|83|83|3|3.6%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|2972|2972|3|0.1%|0.0%|
[php_dictionary](#php_dictionary)|737|737|2|0.2%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|2|0.1%|0.0%|
[iw_spamlist](#iw_spamlist)|3648|3648|2|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|2|0.1%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|170|170|2|1.1%|0.0%|
[sslbl](#sslbl)|370|370|1|0.2%|0.0%|
[sorbs_web](#sorbs_web)|628|629|1|0.1%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|1|0.1%|0.0%|

## dragon_sshpauth

[Dragon Search Group](http://www.dragonresearchgroup.org/) IP address that has been seen attempting to remotely login to a host using SSH password authentication, in the last 7 days. This report lists hosts that are highly suspicious and are likely conducting malicious SSH password authentication attacks.

Source is downloaded from [this link](https://www.dragonresearchgroup.org/insight/sshpwauth.txt).

The last time downloaded was found to be dated: Fri Jun 12 09:04:08 UTC 2015.

The ipset `dragon_sshpauth` has **1589** entries, **1653** unique IPs.

The following table shows the overlaps of `dragon_sshpauth` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `dragon_sshpauth`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `dragon_sshpauth`.
- ` this % ` is the percentage **of this ipset (`dragon_sshpauth`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[alienvault_reputation](#alienvault_reputation)|189146|189146|862|0.4%|52.1%|
[firehol_level3](#firehol_level3)|109549|9627220|858|0.0%|51.9%|
[openbl_60d](#openbl_60d)|6960|6960|780|11.2%|47.1%|
[openbl_30d](#openbl_30d)|2792|2792|698|25.0%|42.2%|
[firehol_level2](#firehol_level2)|20666|32229|639|1.9%|38.6%|
[blocklist_de](#blocklist_de)|26985|26985|638|2.3%|38.5%|
[bruteforceblocker](#bruteforceblocker)|1694|1694|636|37.5%|38.4%|
[blocklist_de_ssh](#blocklist_de_ssh)|1901|1901|635|33.4%|38.4%|
[et_compromised](#et_compromised)|1704|1704|630|36.9%|38.1%|
[shunlist](#shunlist)|1185|1185|380|32.0%|22.9%|
[openbl_7d](#openbl_7d)|629|629|346|55.0%|20.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|125|0.0%|7.5%|
[firehol_level1](#firehol_level1)|5070|688854680|107|0.0%|6.4%|
[et_block](#et_block)|1000|18343756|100|0.0%|6.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|99|0.0%|5.9%|
[openbl_1d](#openbl_1d)|124|124|81|65.3%|4.9%|
[dshield](#dshield)|20|5120|80|1.5%|4.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|71|0.0%|4.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|32|0.0%|1.9%|
[blocklist_de_strongips](#blocklist_de_strongips)|170|170|20|11.7%|1.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|5|0.0%|0.3%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|4|0.0%|0.2%|
[dragon_http](#dragon_http)|1021|268288|4|0.0%|0.2%|
[voipbl](#voipbl)|10586|10998|1|0.0%|0.0%|
[sslbl](#sslbl)|370|370|1|0.2%|0.0%|
[sorbs_spam](#sorbs_spam)|64701|65536|1|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|1|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|1|0.0%|0.0%|
[nixspam](#nixspam)|18198|18198|1|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|1|0.0%|0.0%|
[ciarmy](#ciarmy)|416|416|1|0.2%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|17750|17750|1|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2726|2726|1|0.0%|0.0%|

## dragon_vncprobe

[Dragon Search Group](http://www.dragonresearchgroup.org/) IP address that has been seen attempting to remotely connect to a host running the VNC application service, in the last 7 days. This report lists hosts that are highly suspicious and are likely conducting malicious VNC probes or VNC brute force attacks.

Source is downloaded from [this link](https://www.dragonresearchgroup.org/insight/vncprobe.txt).

The last time downloaded was found to be dated: Fri Jun 12 09:04:02 UTC 2015.

The ipset `dragon_vncprobe` has **87** entries, **87** unique IPs.

The following table shows the overlaps of `dragon_vncprobe` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `dragon_vncprobe`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `dragon_vncprobe`.
- ` this % ` is the percentage **of this ipset (`dragon_vncprobe`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[alienvault_reputation](#alienvault_reputation)|189146|189146|27|0.0%|31.0%|
[dragon_http](#dragon_http)|1021|268288|24|0.0%|27.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|12|0.0%|13.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|7|0.0%|8.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|5|0.0%|5.7%|
[firehol_level2](#firehol_level2)|20666|32229|5|0.0%|5.7%|
[blocklist_de](#blocklist_de)|26985|26985|5|0.0%|5.7%|
[firehol_level3](#firehol_level3)|109549|9627220|4|0.0%|4.5%|
[et_block](#et_block)|1000|18343756|4|0.0%|4.5%|
[shunlist](#shunlist)|1185|1185|2|0.1%|2.2%|
[firehol_level1](#firehol_level1)|5070|688854680|2|0.0%|2.2%|
[blocklist_de_mail](#blocklist_de_mail)|17750|17750|2|0.0%|2.2%|
[blocklist_de_apache](#blocklist_de_apache)|13845|13845|2|0.0%|2.2%|
[voipbl](#voipbl)|10586|10998|1|0.0%|1.1%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|1|0.0%|1.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|1.1%|
[dshield](#dshield)|20|5120|1|0.0%|1.1%|
[ciarmy](#ciarmy)|416|416|1|0.2%|1.1%|
[blocklist_de_ssh](#blocklist_de_ssh)|1901|1901|1|0.0%|1.1%|
[blocklist_de_imap](#blocklist_de_imap)|2726|2726|1|0.0%|1.1%|

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
[firehol_level1](#firehol_level1)|5070|688854680|5120|0.0%|100.0%|
[alienvault_reputation](#alienvault_reputation)|189146|189146|5120|2.7%|100.0%|
[et_block](#et_block)|1000|18343756|1536|0.0%|30.0%|
[dragon_http](#dragon_http)|1021|268288|768|0.2%|15.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|256|0.0%|5.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|256|0.0%|5.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|256|0.0%|5.0%|
[firehol_level3](#firehol_level3)|109549|9627220|124|0.0%|2.4%|
[firehol_level2](#firehol_level2)|20666|32229|85|0.2%|1.6%|
[openbl_60d](#openbl_60d)|6960|6960|84|1.2%|1.6%|
[blocklist_de](#blocklist_de)|26985|26985|84|0.3%|1.6%|
[shunlist](#shunlist)|1185|1185|83|7.0%|1.6%|
[openbl_30d](#openbl_30d)|2792|2792|80|2.8%|1.5%|
[dragon_sshpauth](#dragon_sshpauth)|1589|1653|80|4.8%|1.5%|
[blocklist_de_ssh](#blocklist_de_ssh)|1901|1901|76|3.9%|1.4%|
[et_compromised](#et_compromised)|1704|1704|29|1.7%|0.5%|
[bruteforceblocker](#bruteforceblocker)|1694|1694|25|1.4%|0.4%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|21|0.0%|0.4%|
[openbl_7d](#openbl_7d)|629|629|21|3.3%|0.4%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|15|0.0%|0.2%|
[blocklist_de_strongips](#blocklist_de_strongips)|170|170|12|7.0%|0.2%|
[stopforumspam_1d](#stopforumspam_1d)|6669|6669|9|0.1%|0.1%|
[blocklist_de_bots](#blocklist_de_bots)|2972|2972|8|0.2%|0.1%|
[openbl_1d](#openbl_1d)|124|124|6|4.8%|0.1%|
[ciarmy](#ciarmy)|416|416|5|1.2%|0.0%|
[firehol_anonymous](#firehol_anonymous)|19172|83219|2|0.0%|0.0%|
[et_tor](#et_tor)|6500|6500|2|0.0%|0.0%|
[dm_tor](#dm_tor)|6468|6468|2|0.0%|0.0%|
[bm_tor](#bm_tor)|6471|6471|2|0.0%|0.0%|
[tor_exits](#tor_exits)|1106|1106|1|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9136|9136|1|0.0%|0.0%|
[php_commenters](#php_commenters)|458|458|1|0.2%|0.0%|
[nixspam](#nixspam)|18198|18198|1|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|1|0.1%|0.0%|
[firehol_proxies](#firehol_proxies)|12734|13010|1|0.0%|0.0%|
[dragon_vncprobe](#dragon_vncprobe)|87|87|1|1.1%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13845|13845|1|0.0%|0.0%|

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
[firehol_level1](#firehol_level1)|5070|688854680|18340104|2.6%|99.9%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|18338560|99.9%|99.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|8532776|2.4%|46.5%|
[firehol_level3](#firehol_level3)|109549|9627220|6933353|72.0%|37.7%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|6932480|75.5%|37.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|2272787|0.2%|12.3%|
[fullbogons](#fullbogons)|3775|670173256|151552|0.0%|0.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|130650|0.0%|0.7%|
[alienvault_reputation](#alienvault_reputation)|189146|189146|3752|1.9%|0.0%|
[dshield](#dshield)|20|5120|1536|30.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1041|0.3%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|1032|1.0%|0.0%|
[dragon_http](#dragon_http)|1021|268288|1024|0.3%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|517|0.1%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9136|9136|297|3.2%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|283|0.9%|0.0%|
[firehol_level2](#firehol_level2)|20666|32229|264|0.8%|0.0%|
[openbl_60d](#openbl_60d)|6960|6960|244|3.5%|0.0%|
[zeus](#zeus)|230|230|229|99.5%|0.0%|
[zeus_badips](#zeus_badips)|202|202|202|100.0%|0.0%|
[blocklist_de](#blocklist_de)|26985|26985|202|0.7%|0.0%|
[openbl_30d](#openbl_30d)|2792|2792|125|4.4%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1901|1901|111|5.8%|0.0%|
[shunlist](#shunlist)|1185|1185|101|8.5%|0.0%|
[dragon_sshpauth](#dragon_sshpauth)|1589|1653|100|6.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6669|6669|82|1.2%|0.0%|
[et_compromised](#et_compromised)|1704|1704|65|3.8%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1694|1694|61|3.6%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|2972|2972|58|1.9%|0.0%|
[openbl_7d](#openbl_7d)|629|629|57|9.0%|0.0%|
[sslbl](#sslbl)|370|370|39|10.5%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|30|2.3%|0.0%|
[php_commenters](#php_commenters)|458|458|29|6.3%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|17750|17750|23|0.1%|0.0%|
[nixspam](#nixspam)|18198|18198|22|0.1%|0.0%|
[sorbs_spam](#sorbs_spam)|64701|65536|20|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|20|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|20|0.0%|0.0%|
[voipbl](#voipbl)|10586|10998|18|0.1%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2726|2726|16|0.5%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|170|170|14|8.2%|0.0%|
[palevo](#palevo)|13|13|12|92.3%|0.0%|
[openbl_1d](#openbl_1d)|124|124|9|7.2%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13845|13845|9|0.0%|0.0%|
[firehol_anonymous](#firehol_anonymous)|19172|83219|8|0.0%|0.0%|
[php_dictionary](#php_dictionary)|737|737|6|0.8%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|6|0.4%|0.0%|
[malc0de](#malc0de)|276|276|5|1.8%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|5|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2446|2446|5|0.2%|0.0%|
[php_spammers](#php_spammers)|735|735|4|0.5%|0.0%|
[nt_malware_http](#nt_malware_http)|69|69|4|5.7%|0.0%|
[firehol_proxies](#firehol_proxies)|12734|13010|4|0.0%|0.0%|
[et_tor](#et_tor)|6500|6500|4|0.0%|0.0%|
[dragon_vncprobe](#dragon_vncprobe)|87|87|4|4.5%|0.0%|
[dm_tor](#dm_tor)|6468|6468|4|0.0%|0.0%|
[bm_tor](#bm_tor)|6471|6471|4|0.0%|0.0%|
[nt_malware_irc](#nt_malware_irc)|43|43|3|6.9%|0.0%|
[iw_spamlist](#iw_spamlist)|3648|3648|3|0.0%|0.0%|
[tor_exits](#tor_exits)|1106|1106|2|0.1%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|2|0.3%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|83|83|2|2.4%|0.0%|
[virbl](#virbl)|22|22|1|4.5%|0.0%|
[proxz](#proxz)|1356|1356|1|0.0%|0.0%|
[php_harvesters](#php_harvesters)|408|408|1|0.2%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|1|0.1%|0.0%|
[et_botcc](#et_botcc)|505|505|1|0.1%|0.0%|
[ciarmy](#ciarmy)|416|416|1|0.2%|0.0%|

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
[alienvault_reputation](#alienvault_reputation)|189146|189146|4|0.0%|0.7%|
[firehol_level3](#firehol_level3)|109549|9627220|3|0.0%|0.5%|
[dragon_http](#dragon_http)|1021|268288|3|0.0%|0.5%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|1|0.0%|0.1%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|1|0.0%|0.1%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|1|0.0%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.1%|
[firehol_level1](#firehol_level1)|5070|688854680|1|0.0%|0.1%|
[et_block](#et_block)|1000|18343756|1|0.0%|0.1%|
[blocklist_de_sip](#blocklist_de_sip)|83|83|1|1.2%|0.1%|

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
[firehol_level3](#firehol_level3)|109549|9627220|1673|0.0%|98.1%|
[bruteforceblocker](#bruteforceblocker)|1694|1694|1654|97.6%|97.0%|
[alienvault_reputation](#alienvault_reputation)|189146|189146|1084|0.5%|63.6%|
[openbl_60d](#openbl_60d)|6960|6960|977|14.0%|57.3%|
[openbl_30d](#openbl_30d)|2792|2792|910|32.5%|53.4%|
[dragon_sshpauth](#dragon_sshpauth)|1589|1653|630|38.1%|36.9%|
[firehol_level2](#firehol_level2)|20666|32229|535|1.6%|31.3%|
[blocklist_de](#blocklist_de)|26985|26985|534|1.9%|31.3%|
[blocklist_de_ssh](#blocklist_de_ssh)|1901|1901|528|27.7%|30.9%|
[shunlist](#shunlist)|1185|1185|341|28.7%|20.0%|
[openbl_7d](#openbl_7d)|629|629|305|48.4%|17.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|157|0.0%|9.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|89|0.0%|5.2%|
[firehol_level1](#firehol_level1)|5070|688854680|71|0.0%|4.1%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|65|0.0%|3.8%|
[et_block](#et_block)|1000|18343756|65|0.0%|3.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|54|0.0%|3.1%|
[openbl_1d](#openbl_1d)|124|124|52|41.9%|3.0%|
[dshield](#dshield)|20|5120|29|0.5%|1.7%|
[dragon_http](#dragon_http)|1021|268288|13|0.0%|0.7%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|10|0.0%|0.5%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|5|0.0%|0.2%|
[blocklist_de_mail](#blocklist_de_mail)|17750|17750|4|0.0%|0.2%|
[blocklist_de_imap](#blocklist_de_imap)|2726|2726|4|0.1%|0.2%|
[voipbl](#voipbl)|10586|10998|3|0.0%|0.1%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|3|0.0%|0.1%|
[sorbs_spam](#sorbs_spam)|64701|65536|3|0.0%|0.1%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|3|0.0%|0.1%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|3|0.0%|0.1%|
[firehol_proxies](#firehol_proxies)|12734|13010|3|0.0%|0.1%|
[firehol_anonymous](#firehol_anonymous)|19172|83219|3|0.0%|0.1%|
[ciarmy](#ciarmy)|416|416|3|0.7%|0.1%|
[proxz](#proxz)|1356|1356|2|0.1%|0.1%|
[nixspam](#nixspam)|18198|18198|2|0.0%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|2|0.0%|0.1%|
[xroxy](#xroxy)|2175|2175|1|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6669|6669|1|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7952|7952|1|0.0%|0.0%|
[proxyrss](#proxyrss)|1570|1570|1|0.0%|0.0%|
[php_spammers](#php_spammers)|735|735|1|0.1%|0.0%|
[php_commenters](#php_commenters)|458|458|1|0.2%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|170|170|1|0.5%|0.0%|

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
[firehol_anonymous](#firehol_anonymous)|19172|83219|5779|6.9%|88.9%|
[bm_tor](#bm_tor)|6471|6471|5755|88.9%|88.5%|
[dm_tor](#dm_tor)|6468|6468|5752|88.9%|88.4%|
[firehol_level3](#firehol_level3)|109549|9627220|1123|0.0%|17.2%|
[snort_ipfilter](#snort_ipfilter)|9136|9136|1088|11.9%|16.7%|
[tor_exits](#tor_exits)|1106|1106|971|87.7%|14.9%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|651|0.6%|10.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|636|0.0%|9.7%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|547|1.8%|8.4%|
[firehol_level2](#firehol_level2)|20666|32229|324|1.0%|4.9%|
[stopforumspam_1d](#stopforumspam_1d)|6669|6669|316|4.7%|4.8%|
[firehol_proxies](#firehol_proxies)|12734|13010|238|1.8%|3.6%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|233|44.4%|3.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|182|0.0%|2.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|168|0.0%|2.5%|
[php_commenters](#php_commenters)|458|458|54|11.7%|0.8%|
[alienvault_reputation](#alienvault_reputation)|189146|189146|42|0.0%|0.6%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|22|0.0%|0.3%|
[openbl_60d](#openbl_60d)|6960|6960|20|0.2%|0.3%|
[dragon_http](#dragon_http)|1021|268288|16|0.0%|0.2%|
[blocklist_de_apache](#blocklist_de_apache)|13845|13845|13|0.0%|0.2%|
[blocklist_de](#blocklist_de)|26985|26985|13|0.0%|0.2%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2446|2446|10|0.4%|0.1%|
[php_harvesters](#php_harvesters)|408|408|7|1.7%|0.1%|
[ri_web_proxies](#ri_web_proxies)|7952|7952|5|0.0%|0.0%|
[php_spammers](#php_spammers)|735|735|5|0.6%|0.0%|
[nixspam](#nixspam)|18198|18198|5|0.0%|0.0%|
[firehol_level1](#firehol_level1)|5070|688854680|5|0.0%|0.0%|
[sorbs_spam](#sorbs_spam)|64701|65536|4|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|4|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|4|0.0%|0.0%|
[php_dictionary](#php_dictionary)|737|737|4|0.5%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|4|0.0%|0.0%|
[et_block](#et_block)|1000|18343756|4|0.0%|0.0%|
[voipbl](#voipbl)|10586|10998|3|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|3|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|17750|17750|3|0.0%|0.0%|
[xroxy](#xroxy)|2175|2175|2|0.0%|0.0%|
[dshield](#dshield)|20|5120|2|0.0%|0.0%|
[shunlist](#shunlist)|1185|1185|1|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2855|2855|1|0.0%|0.0%|
[proxyrss](#proxyrss)|1570|1570|1|0.0%|0.0%|

## feodo

[Abuse.ch Feodo tracker](https://feodotracker.abuse.ch) trojan includes IPs which are being used by Feodo (also known as Cridex or Bugat) which commits ebanking fraud - **excellent list**

Source is downloaded from [this link](https://feodotracker.abuse.ch/blocklist/?download=ipblocklist).

The last time downloaded was found to be dated: Fri Jun 12 09:36:55 UTC 2015.

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

The ipset `firehol_anonymous` has **19172** entries, **83219** unique IPs.

The following table shows the overlaps of `firehol_anonymous` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `firehol_anonymous`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `firehol_anonymous`.
- ` this % ` is the percentage **of this ipset (`firehol_anonymous`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_proxies](#firehol_proxies)|12734|13010|13010|100.0%|15.6%|
[ri_web_proxies](#ri_web_proxies)|7952|7952|7952|100.0%|9.5%|
[firehol_level3](#firehol_level3)|109549|9627220|6786|0.0%|8.1%|
[bm_tor](#bm_tor)|6471|6471|6471|100.0%|7.7%|
[dm_tor](#dm_tor)|6468|6468|6468|100.0%|7.7%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|6220|6.5%|7.4%|
[et_tor](#et_tor)|6500|6500|5779|88.9%|6.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|3445|0.0%|4.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|2895|0.0%|3.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|2877|0.0%|3.4%|
[ri_connect_proxies](#ri_connect_proxies)|2855|2855|2855|100.0%|3.4%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|2729|9.4%|3.2%|
[xroxy](#xroxy)|2175|2175|2175|100.0%|2.6%|
[proxyrss](#proxyrss)|1570|1570|1570|100.0%|1.8%|
[proxz](#proxz)|1356|1356|1356|100.0%|1.6%|
[firehol_level2](#firehol_level2)|20666|32229|1321|4.0%|1.5%|
[snort_ipfilter](#snort_ipfilter)|9136|9136|1224|13.3%|1.4%|
[tor_exits](#tor_exits)|1106|1106|1106|100.0%|1.3%|
[stopforumspam_1d](#stopforumspam_1d)|6669|6669|955|14.3%|1.1%|
[blocklist_de](#blocklist_de)|26985|26985|664|2.4%|0.7%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|663|100.0%|0.7%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|524|100.0%|0.6%|
[blocklist_de_bots](#blocklist_de_bots)|2972|2972|517|17.3%|0.6%|
[sorbs_spam](#sorbs_spam)|64701|65536|201|0.3%|0.2%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|201|0.3%|0.2%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|201|0.3%|0.2%|
[nixspam](#nixspam)|18198|18198|149|0.8%|0.1%|
[blocklist_de_mail](#blocklist_de_mail)|17750|17750|124|0.6%|0.1%|
[php_dictionary](#php_dictionary)|737|737|98|13.2%|0.1%|
[php_commenters](#php_commenters)|458|458|90|19.6%|0.1%|
[php_spammers](#php_spammers)|735|735|81|11.0%|0.0%|
[voipbl](#voipbl)|10586|10998|79|0.7%|0.0%|
[alienvault_reputation](#alienvault_reputation)|189146|189146|57|0.0%|0.0%|
[dragon_http](#dragon_http)|1021|268288|45|0.0%|0.0%|
[sorbs_web](#sorbs_web)|628|629|31|4.9%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|30|0.0%|0.0%|
[openbl_60d](#openbl_60d)|6960|6960|23|0.3%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13845|13845|21|0.1%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2446|2446|17|0.6%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|15|0.0%|0.0%|
[php_harvesters](#php_harvesters)|408|408|12|2.9%|0.0%|
[firehol_level1](#firehol_level1)|5070|688854680|10|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|170|170|9|5.2%|0.0%|
[iw_spamlist](#iw_spamlist)|3648|3648|8|0.2%|0.0%|
[et_block](#et_block)|1000|18343756|8|0.0%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|7|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|6|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|1523|1523|4|0.2%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|3|0.2%|0.0%|
[et_compromised](#et_compromised)|1704|1704|3|0.1%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1694|1694|3|0.1%|0.0%|
[dshield](#dshield)|20|5120|2|0.0%|0.0%|
[sslbl](#sslbl)|370|370|1|0.2%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|1|0.0%|0.0%|
[shunlist](#shunlist)|1185|1185|1|0.0%|0.0%|
[openbl_30d](#openbl_30d)|2792|2792|1|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1901|1901|1|0.0%|0.0%|

## firehol_level1

**FireHOL Level 1** - Maximum protection without false positives. (includes: fullbogons dshield feodo palevo sslbl zeus spamhaus_drop spamhaus_edrop)

Source is downloaded from [this link]().

The last time downloaded was found to be dated: Sun Jun  7 22:15:43 UTC 2015.

The ipset `firehol_level1` has **5070** entries, **688854680** unique IPs.

The following table shows the overlaps of `firehol_level1` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `firehol_level1`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `firehol_level1`.
- ` this % ` is the percentage **of this ipset (`firehol_level1`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[fullbogons](#fullbogons)|3775|670173256|670173256|100.0%|97.2%|
[bogons](#bogons)|13|592708608|592708608|100.0%|86.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|18340608|100.0%|2.6%|
[et_block](#et_block)|1000|18343756|18340104|99.9%|2.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|8867713|2.5%|1.2%|
[firehol_level3](#firehol_level3)|109549|9627220|7500146|77.9%|1.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|7498240|81.6%|1.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|4637595|3.3%|0.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|2570559|0.3%|0.3%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|487424|100.0%|0.0%|
[alienvault_reputation](#alienvault_reputation)|189146|189146|6387|3.3%|0.0%|
[dshield](#dshield)|20|5120|5120|100.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1931|0.5%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|1111|1.1%|0.0%|
[dragon_http](#dragon_http)|1021|268288|1025|0.3%|0.0%|
[sslbl](#sslbl)|370|370|370|100.0%|0.0%|
[voipbl](#voipbl)|10586|10998|333|3.0%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|291|1.0%|0.0%|
[firehol_level2](#firehol_level2)|20666|32229|277|0.8%|0.0%|
[openbl_60d](#openbl_60d)|6960|6960|253|3.6%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9136|9136|248|2.7%|0.0%|
[zeus](#zeus)|230|230|230|100.0%|0.0%|
[blocklist_de](#blocklist_de)|26985|26985|212|0.7%|0.0%|
[zeus_badips](#zeus_badips)|202|202|202|100.0%|0.0%|
[shunlist](#shunlist)|1185|1185|159|13.4%|0.0%|
[openbl_30d](#openbl_30d)|2792|2792|135|4.8%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1901|1901|121|6.3%|0.0%|
[dragon_sshpauth](#dragon_sshpauth)|1589|1653|107|6.4%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6669|6669|86|1.2%|0.0%|
[et_compromised](#et_compromised)|1704|1704|71|4.1%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1694|1694|67|3.9%|0.0%|
[openbl_7d](#openbl_7d)|629|629|60|9.5%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|2972|2972|59|1.9%|0.0%|
[php_commenters](#php_commenters)|458|458|39|8.5%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|39|3.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|39|2.6%|0.0%|
[sorbs_spam](#sorbs_spam)|64701|65536|25|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|25|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|25|0.0%|0.0%|
[nixspam](#nixspam)|18198|18198|24|0.1%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|17750|17750|24|0.1%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|170|170|20|11.7%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|18|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2726|2726|16|0.5%|0.0%|
[palevo](#palevo)|13|13|13|100.0%|0.0%|
[openbl_1d](#openbl_1d)|124|124|13|10.4%|0.0%|
[firehol_anonymous](#firehol_anonymous)|19172|83219|10|0.0%|0.0%|
[iw_spamlist](#iw_spamlist)|3648|3648|9|0.2%|0.0%|
[nt_malware_http](#nt_malware_http)|69|69|8|11.5%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13845|13845|7|0.0%|0.0%|
[php_dictionary](#php_dictionary)|737|737|6|0.8%|0.0%|
[dm_tor](#dm_tor)|6468|6468|6|0.0%|0.0%|
[ciarmy](#ciarmy)|416|416|6|1.4%|0.0%|
[bm_tor](#bm_tor)|6471|6471|6|0.0%|0.0%|
[malc0de](#malc0de)|276|276|5|1.8%|0.0%|
[firehol_proxies](#firehol_proxies)|12734|13010|5|0.0%|0.0%|
[et_tor](#et_tor)|6500|6500|5|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2446|2446|5|0.2%|0.0%|
[php_spammers](#php_spammers)|735|735|4|0.5%|0.0%|
[tor_exits](#tor_exits)|1106|1106|3|0.2%|0.0%|
[php_harvesters](#php_harvesters)|408|408|3|0.7%|0.0%|
[nt_malware_irc](#nt_malware_irc)|43|43|3|6.9%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|2|0.3%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|2|0.3%|0.0%|
[dragon_vncprobe](#dragon_vncprobe)|87|87|2|2.2%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|83|83|2|2.4%|0.0%|
[virbl](#virbl)|22|22|1|4.5%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7952|7952|1|0.0%|0.0%|
[et_botcc](#et_botcc)|505|505|1|0.1%|0.0%|

## firehol_level2

**FireHOL Level 2** - Maximum protection from attacks took place in the last 48 hours. (includes: openbl_1d blocklist_de stopforumspam_1d)

Source is downloaded from [this link]().

The last time downloaded was found to be dated: Sun Jun  7 22:20:34 UTC 2015.

The ipset `firehol_level2` has **20666** entries, **32229** unique IPs.

The following table shows the overlaps of `firehol_level2` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `firehol_level2`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `firehol_level2`.
- ` this % ` is the percentage **of this ipset (`firehol_level2`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|26985|26985|26985|100.0%|83.7%|
[blocklist_de_mail](#blocklist_de_mail)|17750|17750|17699|99.7%|54.9%|
[blocklist_de_apache](#blocklist_de_apache)|13845|13845|13828|99.8%|42.9%|
[firehol_level3](#firehol_level3)|109549|9627220|6942|0.0%|21.5%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|6697|23.0%|20.7%|
[stopforumspam_1d](#stopforumspam_1d)|6669|6669|6669|100.0%|20.6%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|5850|6.2%|18.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|3685|0.0%|11.4%|
[blocklist_de_bots](#blocklist_de_bots)|2972|2972|2966|99.7%|9.2%|
[blocklist_de_imap](#blocklist_de_imap)|2726|2726|2715|99.5%|8.4%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2446|2446|2446|100.0%|7.5%|
[blocklist_de_ssh](#blocklist_de_ssh)|1901|1901|1876|98.6%|5.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|1679|0.0%|5.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|1604|0.0%|4.9%|
[blocklist_de_ftp](#blocklist_de_ftp)|1523|1523|1508|99.0%|4.6%|
[firehol_anonymous](#firehol_anonymous)|19172|83219|1321|1.5%|4.0%|
[firehol_proxies](#firehol_proxies)|12734|13010|1155|8.8%|3.5%|
[alienvault_reputation](#alienvault_reputation)|189146|189146|1091|0.5%|3.3%|
[sorbs_spam](#sorbs_spam)|64701|65536|995|1.5%|3.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|987|1.5%|3.0%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|987|1.5%|3.0%|
[openbl_60d](#openbl_60d)|6960|6960|758|10.8%|2.3%|
[ri_web_proxies](#ri_web_proxies)|7952|7952|664|8.3%|2.0%|
[openbl_30d](#openbl_30d)|2792|2792|647|23.1%|2.0%|
[dragon_sshpauth](#dragon_sshpauth)|1589|1653|639|38.6%|1.9%|
[bruteforceblocker](#bruteforceblocker)|1694|1694|555|32.7%|1.7%|
[et_compromised](#et_compromised)|1704|1704|535|31.3%|1.6%|
[snort_ipfilter](#snort_ipfilter)|9136|9136|526|5.7%|1.6%|
[nixspam](#nixspam)|18198|18198|517|2.8%|1.6%|
[proxyrss](#proxyrss)|1570|1570|387|24.6%|1.2%|
[openbl_7d](#openbl_7d)|629|629|384|61.0%|1.1%|
[shunlist](#shunlist)|1185|1185|353|29.7%|1.0%|
[tor_exits](#tor_exits)|1106|1106|333|30.1%|1.0%|
[et_tor](#et_tor)|6500|6500|324|4.9%|1.0%|
[dm_tor](#dm_tor)|6468|6468|318|4.9%|0.9%|
[bm_tor](#bm_tor)|6471|6471|318|4.9%|0.9%|
[xroxy](#xroxy)|2175|2175|305|14.0%|0.9%|
[firehol_level1](#firehol_level1)|5070|688854680|277|0.0%|0.8%|
[proxz](#proxz)|1356|1356|270|19.9%|0.8%|
[et_block](#et_block)|1000|18343756|264|0.0%|0.8%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|245|0.0%|0.7%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|197|37.5%|0.6%|
[php_commenters](#php_commenters)|458|458|194|42.3%|0.6%|
[blocklist_de_strongips](#blocklist_de_strongips)|170|170|170|100.0%|0.5%|
[ri_connect_proxies](#ri_connect_proxies)|2855|2855|148|5.1%|0.4%|
[openbl_1d](#openbl_1d)|124|124|124|100.0%|0.3%|
[iw_spamlist](#iw_spamlist)|3648|3648|122|3.3%|0.3%|
[php_dictionary](#php_dictionary)|737|737|121|16.4%|0.3%|
[php_spammers](#php_spammers)|735|735|115|15.6%|0.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|90|0.0%|0.2%|
[dshield](#dshield)|20|5120|85|1.6%|0.2%|
[sorbs_web](#sorbs_web)|628|629|71|11.2%|0.2%|
[blocklist_de_sip](#blocklist_de_sip)|83|83|64|77.1%|0.1%|
[dragon_http](#dragon_http)|1021|268288|60|0.0%|0.1%|
[php_harvesters](#php_harvesters)|408|408|57|13.9%|0.1%|
[voipbl](#voipbl)|10586|10998|44|0.4%|0.1%|
[ciarmy](#ciarmy)|416|416|36|8.6%|0.1%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|16|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|12|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|8|1.2%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|7|0.0%|0.0%|
[dragon_vncprobe](#dragon_vncprobe)|87|87|5|5.7%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|2|0.1%|0.0%|
[zeus_badips](#zeus_badips)|202|202|1|0.4%|0.0%|
[zeus](#zeus)|230|230|1|0.4%|0.0%|
[virbl](#virbl)|22|22|1|4.5%|0.0%|
[sorbs_socks](#sorbs_socks)|7|7|1|14.2%|0.0%|
[sorbs_misc](#sorbs_misc)|7|7|1|14.2%|0.0%|
[sorbs_http](#sorbs_http)|7|7|1|14.2%|0.0%|
[iw_wormlist](#iw_wormlist)|34|34|1|2.9%|0.0%|
[fullbogons](#fullbogons)|3775|670173256|1|0.0%|0.0%|

## firehol_level3

**FireHOL Level 3** - All the bad IPs in last 30 days. (includes: openbl_30d stopforumspam_30d virbl malc0de shunlist malwaredomainlist bruteforceblocker ciarmy cleanmx_viruses snort_ipfilter ib_bluetack_spyware ib_bluetack_hijacked ib_bluetack_webexploit php_commenters php_dictionary php_harvesters php_spammers iw_wormlist)

Source is downloaded from [this link]().

The last time downloaded was found to be dated: Sun Jun  7 22:20:34 UTC 2015.

The ipset `firehol_level3` has **109549** entries, **9627220** unique IPs.

The following table shows the overlaps of `firehol_level3` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `firehol_level3`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `firehol_level3`.
- ` this % ` is the percentage **of this ipset (`firehol_level3`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|9177856|100.0%|95.3%|
[firehol_level1](#firehol_level1)|5070|688854680|7500146|1.0%|77.9%|
[et_block](#et_block)|1000|18343756|6933353|37.7%|72.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|6933039|37.8%|72.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|2537277|0.7%|26.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|919976|0.1%|9.5%|
[fullbogons](#fullbogons)|3775|670173256|566692|0.0%|5.8%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|339173|100.0%|3.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|161594|0.1%|1.6%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|94309|100.0%|0.9%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|27643|95.2%|0.2%|
[snort_ipfilter](#snort_ipfilter)|9136|9136|9136|100.0%|0.0%|
[firehol_level2](#firehol_level2)|20666|32229|6942|21.5%|0.0%|
[firehol_anonymous](#firehol_anonymous)|19172|83219|6786|8.1%|0.0%|
[firehol_proxies](#firehol_proxies)|12734|13010|5683|43.6%|0.0%|
[alienvault_reputation](#alienvault_reputation)|189146|189146|4814|2.5%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6669|6669|4514|67.6%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7952|7952|3755|47.2%|0.0%|
[blocklist_de](#blocklist_de)|26985|26985|3656|13.5%|0.0%|
[openbl_60d](#openbl_60d)|6960|6960|2917|41.9%|0.0%|
[openbl_30d](#openbl_30d)|2792|2792|2792|100.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|2972|2972|2317|77.9%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1694|1694|1694|100.0%|0.0%|
[et_compromised](#et_compromised)|1704|1704|1673|98.1%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2855|2855|1592|55.7%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|1450|100.0%|0.0%|
[xroxy](#xroxy)|2175|2175|1302|59.8%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|1288|100.0%|0.0%|
[sorbs_spam](#sorbs_spam)|64701|65536|1227|1.8%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|1223|1.8%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|1223|1.8%|0.0%|
[shunlist](#shunlist)|1185|1185|1185|100.0%|0.0%|
[et_tor](#et_tor)|6500|6500|1123|17.2%|0.0%|
[bm_tor](#bm_tor)|6471|6471|1087|16.7%|0.0%|
[dm_tor](#dm_tor)|6468|6468|1086|16.7%|0.0%|
[tor_exits](#tor_exits)|1106|1106|1069|96.6%|0.0%|
[dragon_sshpauth](#dragon_sshpauth)|1589|1653|858|51.9%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1901|1901|813|42.7%|0.0%|
[proxz](#proxz)|1356|1356|800|58.9%|0.0%|
[php_dictionary](#php_dictionary)|737|737|737|100.0%|0.0%|
[php_spammers](#php_spammers)|735|735|735|100.0%|0.0%|
[proxyrss](#proxyrss)|1570|1570|681|43.3%|0.0%|
[openbl_7d](#openbl_7d)|629|629|629|100.0%|0.0%|
[dragon_http](#dragon_http)|1021|268288|560|0.2%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|511|511|511|100.0%|0.0%|
[php_commenters](#php_commenters)|458|458|458|100.0%|0.0%|
[nixspam](#nixspam)|18198|18198|418|2.2%|0.0%|
[ciarmy](#ciarmy)|416|416|416|100.0%|0.0%|
[php_harvesters](#php_harvesters)|408|408|408|100.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|17750|17750|382|2.1%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|346|66.0%|0.0%|
[malc0de](#malc0de)|276|276|276|100.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13845|13845|270|1.9%|0.0%|
[zeus](#zeus)|230|230|203|88.2%|0.0%|
[zeus_badips](#zeus_badips)|202|202|180|89.1%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|170|170|156|91.7%|0.0%|
[dshield](#dshield)|20|5120|124|2.4%|0.0%|
[openbl_1d](#openbl_1d)|124|124|120|96.7%|0.0%|
[sslbl](#sslbl)|370|370|89|24.0%|0.0%|
[iw_spamlist](#iw_spamlist)|3648|3648|89|2.4%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|85|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2446|2446|75|3.0%|0.0%|
[sorbs_web](#sorbs_web)|628|629|74|11.7%|0.0%|
[voipbl](#voipbl)|10586|10998|58|0.5%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2726|2726|36|1.3%|0.0%|
[iw_wormlist](#iw_wormlist)|34|34|34|100.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|25|3.7%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|25|0.0%|0.0%|
[virbl](#virbl)|22|22|22|100.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|1523|1523|16|1.0%|0.0%|
[palevo](#palevo)|13|13|11|84.6%|0.0%|
[sorbs_socks](#sorbs_socks)|7|7|4|57.1%|0.0%|
[sorbs_misc](#sorbs_misc)|7|7|4|57.1%|0.0%|
[sorbs_http](#sorbs_http)|7|7|4|57.1%|0.0%|
[dragon_vncprobe](#dragon_vncprobe)|87|87|4|4.5%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|83|83|4|4.8%|0.0%|
[nt_malware_http](#nt_malware_http)|69|69|3|4.3%|0.0%|
[et_botcc](#et_botcc)|505|505|3|0.5%|0.0%|
[bogons](#bogons)|13|592708608|3|0.0%|0.0%|
[nt_malware_irc](#nt_malware_irc)|43|43|1|2.3%|0.0%|

## firehol_proxies

**FireHOL Proxies** - Known open proxies in the last 30 days. (includes: ib_bluetack_proxies maxmind_proxy_fraud proxyrss proxz ri_connect_proxies ri_web_proxies xroxy)

Source is downloaded from [this link]().

The last time downloaded was found to be dated: Sun Jun  7 22:20:34 UTC 2015.

The ipset `firehol_proxies` has **12734** entries, **13010** unique IPs.

The following table shows the overlaps of `firehol_proxies` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `firehol_proxies`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `firehol_proxies`.
- ` this % ` is the percentage **of this ipset (`firehol_proxies`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_anonymous](#firehol_anonymous)|19172|83219|13010|15.6%|100.0%|
[ri_web_proxies](#ri_web_proxies)|7952|7952|7952|100.0%|61.1%|
[firehol_level3](#firehol_level3)|109549|9627220|5683|0.0%|43.6%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|5622|5.9%|43.2%|
[ri_connect_proxies](#ri_connect_proxies)|2855|2855|2855|100.0%|21.9%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|2363|8.1%|18.1%|
[xroxy](#xroxy)|2175|2175|2175|100.0%|16.7%|
[proxyrss](#proxyrss)|1570|1570|1570|100.0%|12.0%|
[proxz](#proxz)|1356|1356|1356|100.0%|10.4%|
[firehol_level2](#firehol_level2)|20666|32229|1155|3.5%|8.8%|
[stopforumspam_1d](#stopforumspam_1d)|6669|6669|805|12.0%|6.1%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|663|100.0%|5.0%|
[blocklist_de](#blocklist_de)|26985|26985|640|2.3%|4.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|531|0.0%|4.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|524|100.0%|4.0%|
[blocklist_de_bots](#blocklist_de_bots)|2972|2972|516|17.3%|3.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|390|0.0%|2.9%|
[snort_ipfilter](#snort_ipfilter)|9136|9136|327|3.5%|2.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|290|0.0%|2.2%|
[et_tor](#et_tor)|6500|6500|238|3.6%|1.8%|
[dm_tor](#dm_tor)|6468|6468|234|3.6%|1.7%|
[bm_tor](#bm_tor)|6471|6471|234|3.6%|1.7%|
[tor_exits](#tor_exits)|1106|1106|228|20.6%|1.7%|
[sorbs_spam](#sorbs_spam)|64701|65536|196|0.2%|1.5%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|196|0.3%|1.5%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|196|0.3%|1.5%|
[nixspam](#nixspam)|18198|18198|142|0.7%|1.0%|
[blocklist_de_mail](#blocklist_de_mail)|17750|17750|122|0.6%|0.9%|
[php_dictionary](#php_dictionary)|737|737|97|13.1%|0.7%|
[php_commenters](#php_commenters)|458|458|86|18.7%|0.6%|
[php_spammers](#php_spammers)|735|735|79|10.7%|0.6%|
[alienvault_reputation](#alienvault_reputation)|189146|189146|38|0.0%|0.2%|
[dragon_http](#dragon_http)|1021|268288|32|0.0%|0.2%|
[sorbs_web](#sorbs_web)|628|629|31|4.9%|0.2%|
[openbl_60d](#openbl_60d)|6960|6960|20|0.2%|0.1%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|15|0.0%|0.1%|
[php_harvesters](#php_harvesters)|408|408|12|2.9%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|12|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|170|170|9|5.2%|0.0%|
[iw_spamlist](#iw_spamlist)|3648|3648|8|0.2%|0.0%|
[firehol_level1](#firehol_level1)|5070|688854680|5|0.0%|0.0%|
[et_block](#et_block)|1000|18343756|4|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|3|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|3|0.2%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|0.0%|
[et_compromised](#et_compromised)|1704|1704|3|0.1%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1694|1694|3|0.1%|0.0%|
[voipbl](#voipbl)|10586|10998|2|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13845|13845|2|0.0%|0.0%|
[sslbl](#sslbl)|370|370|1|0.2%|0.0%|
[shunlist](#shunlist)|1185|1185|1|0.0%|0.0%|
[dshield](#dshield)|20|5120|1|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1901|1901|1|0.0%|0.0%|

## fullbogons

[Team-Cymru.org](http://www.team-cymru.org) IP space that has been allocated to an RIR, but not assigned by that RIR to an actual ISP or other end-user - **excellent list - use it only your internet interface**

Source is downloaded from [this link](http://www.team-cymru.org/Services/Bogons/fullbogons-ipv4.txt).

The last time downloaded was found to be dated: Thu Jun 11 09:35:07 UTC 2015.

The ipset `fullbogons` has **3775** entries, **670173256** unique IPs.

The following table shows the overlaps of `fullbogons` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `fullbogons`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `fullbogons`.
- ` this % ` is the percentage **of this ipset (`fullbogons`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level1](#firehol_level1)|5070|688854680|670173256|97.2%|100.0%|
[bogons](#bogons)|13|592708608|592708608|100.0%|88.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|4236143|3.0%|0.6%|
[firehol_level3](#firehol_level3)|109549|9627220|566692|5.8%|0.0%|
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
[iw_spamlist](#iw_spamlist)|3648|3648|5|0.1%|0.0%|
[nt_malware_http](#nt_malware_http)|69|69|4|5.7%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|2|0.0%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|2|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6669|6669|1|0.0%|0.0%|
[php_harvesters](#php_harvesters)|408|408|1|0.2%|0.0%|
[php_commenters](#php_commenters)|458|458|1|0.2%|0.0%|
[firehol_level2](#firehol_level2)|20666|32229|1|0.0%|0.0%|
[ciarmy](#ciarmy)|416|416|1|0.2%|0.0%|

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
[firehol_level3](#firehol_level3)|109549|9627220|25|0.0%|0.0%|
[dragon_http](#dragon_http)|1021|268288|25|0.0%|0.0%|
[firehol_level1](#firehol_level1)|5070|688854680|18|0.0%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|17|0.0%|0.0%|
[sorbs_spam](#sorbs_spam)|64701|65536|17|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|17|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|17|0.0%|0.0%|
[firehol_level2](#firehol_level2)|20666|32229|16|0.0%|0.0%|
[firehol_proxies](#firehol_proxies)|12734|13010|15|0.1%|0.0%|
[firehol_anonymous](#firehol_anonymous)|19172|83219|15|0.0%|0.0%|
[blocklist_de](#blocklist_de)|26985|26985|15|0.0%|0.0%|
[alienvault_reputation](#alienvault_reputation)|189146|189146|15|0.0%|0.0%|
[fullbogons](#fullbogons)|3775|670173256|13|0.0%|0.0%|
[nixspam](#nixspam)|18198|18198|11|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|11|1.6%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|17750|17750|10|0.0%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|7|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|5|0.0%|0.0%|
[et_block](#et_block)|1000|18343756|5|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7952|7952|4|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2726|2726|4|0.1%|0.0%|
[xroxy](#xroxy)|2175|2175|3|0.1%|0.0%|
[php_dictionary](#php_dictionary)|737|737|3|0.4%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|3|0.0%|0.0%|
[voipbl](#voipbl)|10586|10998|2|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6669|6669|2|0.0%|0.0%|
[sorbs_web](#sorbs_web)|628|629|2|0.3%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9136|9136|2|0.0%|0.0%|
[php_harvesters](#php_harvesters)|408|408|2|0.4%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|1523|1523|2|0.1%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2446|2446|2|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13845|13845|2|0.0%|0.0%|
[proxz](#proxz)|1356|1356|1|0.0%|0.0%|
[php_spammers](#php_spammers)|735|735|1|0.1%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|1|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1901|1901|1|0.0%|0.0%|

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
[firehol_level3](#firehol_level3)|109549|9627220|9177856|95.3%|100.0%|
[firehol_level1](#firehol_level1)|5070|688854680|7498240|1.0%|81.6%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|6932480|37.7%|75.5%|
[et_block](#et_block)|1000|18343756|6932480|37.7%|75.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|2526625|0.7%|27.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|904796|0.1%|9.8%|
[fullbogons](#fullbogons)|3775|670173256|565760|0.0%|6.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|145472|0.1%|1.5%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1036|0.3%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|725|0.7%|0.0%|
[alienvault_reputation](#alienvault_reputation)|189146|189146|278|0.1%|0.0%|
[dragon_http](#dragon_http)|1021|268288|256|0.0%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|154|0.5%|0.0%|
[firehol_level2](#firehol_level2)|20666|32229|90|0.2%|0.0%|
[blocklist_de](#blocklist_de)|26985|26985|55|0.2%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|2972|2972|42|1.4%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6669|6669|35|0.5%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|27|2.0%|0.0%|
[nixspam](#nixspam)|18198|18198|21|0.1%|0.0%|
[openbl_60d](#openbl_60d)|6960|6960|16|0.2%|0.0%|
[openbl_30d](#openbl_30d)|2792|2792|12|0.4%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9136|9136|11|0.1%|0.0%|
[zeus_badips](#zeus_badips)|202|202|10|4.9%|0.0%|
[zeus](#zeus)|230|230|10|4.3%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|7|0.4%|0.0%|
[firehol_anonymous](#firehol_anonymous)|19172|83219|7|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1901|1901|7|0.3%|0.0%|
[et_compromised](#et_compromised)|1704|1704|5|0.2%|0.0%|
[dragon_sshpauth](#dragon_sshpauth)|1589|1653|5|0.3%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1694|1694|5|0.2%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|17750|17750|5|0.0%|0.0%|
[php_dictionary](#php_dictionary)|737|737|4|0.5%|0.0%|
[openbl_7d](#openbl_7d)|629|629|4|0.6%|0.0%|
[et_tor](#et_tor)|6500|6500|4|0.0%|0.0%|
[dm_tor](#dm_tor)|6468|6468|4|0.0%|0.0%|
[bm_tor](#bm_tor)|6471|6471|4|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2726|2726|4|0.1%|0.0%|
[php_spammers](#php_spammers)|735|735|3|0.4%|0.0%|
[openbl_1d](#openbl_1d)|124|124|3|2.4%|0.0%|
[nt_malware_http](#nt_malware_http)|69|69|3|4.3%|0.0%|
[firehol_proxies](#firehol_proxies)|12734|13010|3|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|170|170|3|1.7%|0.0%|
[tor_exits](#tor_exits)|1106|1106|2|0.1%|0.0%|
[shunlist](#shunlist)|1185|1185|2|0.1%|0.0%|
[iw_spamlist](#iw_spamlist)|3648|3648|2|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|2|0.3%|0.0%|
[voipbl](#voipbl)|10586|10998|1|0.0%|0.0%|
[virbl](#virbl)|22|22|1|4.5%|0.0%|
[sorbs_spam](#sorbs_spam)|64701|65536|1|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|1|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|1|0.0%|0.0%|
[php_harvesters](#php_harvesters)|408|408|1|0.2%|0.0%|
[php_commenters](#php_commenters)|458|458|1|0.2%|0.0%|
[nt_malware_irc](#nt_malware_irc)|43|43|1|2.3%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|1|0.1%|0.0%|
[et_botcc](#et_botcc)|505|505|1|0.1%|0.0%|
[dragon_vncprobe](#dragon_vncprobe)|87|87|1|1.1%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2446|2446|1|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13845|13845|1|0.0%|0.0%|

## ib_bluetack_level1

[iBlocklist.com](https://www.iblocklist.com/) free version of [BlueTack.co.uk](http://www.bluetack.co.uk/) Level 1 (for use in p2p): Companies or organizations who are clearly involved with trying to stop filesharing (e.g. Baytsp, MediaDefender, Mediasentry a.o.). Companies which anti-p2p activity has been seen from. Companies that produce or have a strong financial interest in copyrighted material (e.g. music, movie, software industries a.o.). Government ranges or companies that have a strong financial interest in doing work for governments. Legal industry ranges. IPs or ranges of ISPs from which anti-p2p activity has been observed. Basically this list will block all kinds of internet connections that most people would rather not have during their internet travels.

Source is downloaded from [this link](http://list.iblocklist.com/?list=ydxerpxkpcfqjaybcssw&fileformat=p2p&archiveformat=gz).

The last time downloaded was found to be dated: Thu Jun 11 09:31:02 UTC 2015.

The ipset `ib_bluetack_level1` has **218307** entries, **764993634** unique IPs.

The following table shows the overlaps of `ib_bluetack_level1` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ib_bluetack_level1`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ib_bluetack_level1`.
- ` this % ` is the percentage **of this ipset (`ib_bluetack_level1`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|16302420|4.6%|2.1%|
[firehol_level1](#firehol_level1)|5070|688854680|2570559|0.3%|0.3%|
[et_block](#et_block)|1000|18343756|2272787|12.3%|0.2%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|2272265|12.3%|0.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|1354507|0.9%|0.1%|
[firehol_level3](#firehol_level3)|109549|9627220|919976|9.5%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|904796|9.8%|0.1%|
[fullbogons](#fullbogons)|3775|670173256|264873|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|33155|6.8%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|13247|3.9%|0.0%|
[dragon_http](#dragon_http)|1021|268288|5989|2.2%|0.0%|
[alienvault_reputation](#alienvault_reputation)|189146|189146|4185|2.2%|0.0%|
[firehol_anonymous](#firehol_anonymous)|19172|83219|3445|4.1%|0.0%|
[firehol_level2](#firehol_level2)|20666|32229|1679|5.2%|0.0%|
[blocklist_de](#blocklist_de)|26985|26985|1580|5.8%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|1522|1.6%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|17750|17750|1419|7.9%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13845|13845|1319|9.5%|0.0%|
[sorbs_spam](#sorbs_spam)|64701|65536|1208|1.8%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|1205|1.8%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|1205|1.8%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|510|1.7%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|394|0.8%|0.0%|
[nixspam](#nixspam)|18198|18198|303|1.6%|0.0%|
[voipbl](#voipbl)|10586|10998|302|2.7%|0.0%|
[firehol_proxies](#firehol_proxies)|12734|13010|290|2.2%|0.0%|
[dshield](#dshield)|20|5120|256|5.0%|0.0%|
[dm_tor](#dm_tor)|6468|6468|171|2.6%|0.0%|
[bm_tor](#bm_tor)|6471|6471|171|2.6%|0.0%|
[et_tor](#et_tor)|6500|6500|168|2.5%|0.0%|
[openbl_60d](#openbl_60d)|6960|6960|161|2.3%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7952|7952|156|1.9%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6669|6669|129|1.9%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9136|9136|114|1.2%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|97|6.6%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2855|2855|86|3.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2726|2726|78|2.8%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|66|5.1%|0.0%|
[openbl_30d](#openbl_30d)|2792|2792|65|2.3%|0.0%|
[iw_spamlist](#iw_spamlist)|3648|3648|65|1.7%|0.0%|
[xroxy](#xroxy)|2175|2175|58|2.6%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|56|8.4%|0.0%|
[et_compromised](#et_compromised)|1704|1704|54|3.1%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1694|1694|53|3.1%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|2972|2972|52|1.7%|0.0%|
[proxz](#proxz)|1356|1356|44|3.2%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1901|1901|42|2.2%|0.0%|
[et_botcc](#et_botcc)|505|505|39|7.7%|0.0%|
[tor_exits](#tor_exits)|1106|1106|37|3.3%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2446|2446|33|1.3%|0.0%|
[dragon_sshpauth](#dragon_sshpauth)|1589|1653|32|1.9%|0.0%|
[proxyrss](#proxyrss)|1570|1570|30|1.9%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|511|511|28|5.4%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|1523|1523|27|1.7%|0.0%|
[shunlist](#shunlist)|1185|1185|26|2.1%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|21|4.0%|0.0%|
[ciarmy](#ciarmy)|416|416|21|5.0%|0.0%|
[sorbs_web](#sorbs_web)|628|629|16|2.5%|0.0%|
[openbl_7d](#openbl_7d)|629|629|13|2.0%|0.0%|
[php_harvesters](#php_harvesters)|408|408|12|2.9%|0.0%|
[php_dictionary](#php_dictionary)|737|737|12|1.6%|0.0%|
[php_spammers](#php_spammers)|735|735|11|1.4%|0.0%|
[php_commenters](#php_commenters)|458|458|10|2.1%|0.0%|
[malc0de](#malc0de)|276|276|10|3.6%|0.0%|
[zeus](#zeus)|230|230|7|3.0%|0.0%|
[nt_malware_http](#nt_malware_http)|69|69|7|10.1%|0.0%|
[nt_malware_irc](#nt_malware_irc)|43|43|5|11.6%|0.0%|
[dragon_vncprobe](#dragon_vncprobe)|87|87|5|5.7%|0.0%|
[bogons](#bogons)|13|592708608|5|0.0%|0.0%|
[zeus_badips](#zeus_badips)|202|202|4|1.9%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|83|83|4|4.8%|0.0%|
[sslbl](#sslbl)|370|370|3|0.8%|0.0%|
[openbl_1d](#openbl_1d)|124|124|1|0.8%|0.0%|
[iw_wormlist](#iw_wormlist)|34|34|1|2.9%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|170|170|1|0.5%|0.0%|

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
[firehol_level1](#firehol_level1)|5070|688854680|8867713|1.2%|2.5%|
[et_block](#et_block)|1000|18343756|8532776|46.5%|2.4%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|8532506|46.5%|2.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|2830203|2.0%|0.8%|
[firehol_level3](#firehol_level3)|109549|9627220|2537277|26.3%|0.7%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2526625|27.5%|0.7%|
[fullbogons](#fullbogons)|3775|670173256|252671|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|98904|20.2%|0.0%|
[dragon_http](#dragon_http)|1021|268288|11992|4.4%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|7728|2.2%|0.0%|
[alienvault_reputation](#alienvault_reputation)|189146|189146|7251|3.8%|0.0%|
[firehol_anonymous](#firehol_anonymous)|19172|83219|2895|3.4%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|2476|2.6%|0.0%|
[sorbs_spam](#sorbs_spam)|64701|65536|1740|2.6%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|1736|2.6%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|1736|2.6%|0.0%|
[firehol_level2](#firehol_level2)|20666|32229|1604|4.9%|0.0%|
[blocklist_de](#blocklist_de)|26985|26985|1461|5.4%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|17750|17750|1226|6.9%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13845|13845|1073|7.7%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|736|2.5%|0.0%|
[nixspam](#nixspam)|18198|18198|485|2.6%|0.0%|
[voipbl](#voipbl)|10586|10998|436|3.9%|0.0%|
[firehol_proxies](#firehol_proxies)|12734|13010|390|2.9%|0.0%|
[openbl_60d](#openbl_60d)|6960|6960|319|4.5%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|226|0.4%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7952|7952|225|2.8%|0.0%|
[dm_tor](#dm_tor)|6468|6468|186|2.8%|0.0%|
[bm_tor](#bm_tor)|6471|6471|186|2.8%|0.0%|
[et_tor](#et_tor)|6500|6500|182|2.8%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6669|6669|176|2.6%|0.0%|
[openbl_30d](#openbl_30d)|2792|2792|146|5.2%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9136|9136|141|1.5%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2855|2855|106|3.7%|0.0%|
[xroxy](#xroxy)|2175|2175|104|4.7%|0.0%|
[iw_spamlist](#iw_spamlist)|3648|3648|92|2.5%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1901|1901|92|4.8%|0.0%|
[et_compromised](#et_compromised)|1704|1704|89|5.2%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1694|1694|86|5.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|2972|2972|77|2.5%|0.0%|
[dragon_sshpauth](#dragon_sshpauth)|1589|1653|71|4.2%|0.0%|
[shunlist](#shunlist)|1185|1185|70|5.9%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2726|2726|61|2.2%|0.0%|
[proxz](#proxz)|1356|1356|56|4.1%|0.0%|
[proxyrss](#proxyrss)|1570|1570|55|3.5%|0.0%|
[php_spammers](#php_spammers)|735|735|54|7.3%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|45|3.1%|0.0%|
[tor_exits](#tor_exits)|1106|1106|40|3.6%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2446|2446|39|1.5%|0.0%|
[openbl_7d](#openbl_7d)|629|629|36|5.7%|0.0%|
[ciarmy](#ciarmy)|416|416|33|7.9%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|29|5.5%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|26|2.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|26|3.9%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|511|511|25|4.8%|0.0%|
[sorbs_web](#sorbs_web)|628|629|23|3.6%|0.0%|
[php_dictionary](#php_dictionary)|737|737|23|3.1%|0.0%|
[et_botcc](#et_botcc)|505|505|22|4.3%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|1523|1523|21|1.3%|0.0%|
[php_commenters](#php_commenters)|458|458|19|4.1%|0.0%|
[malc0de](#malc0de)|276|276|16|5.7%|0.0%|
[zeus](#zeus)|230|230|9|3.9%|0.0%|
[php_harvesters](#php_harvesters)|408|408|9|2.2%|0.0%|
[zeus_badips](#zeus_badips)|202|202|8|3.9%|0.0%|
[dragon_vncprobe](#dragon_vncprobe)|87|87|7|8.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|170|170|7|4.1%|0.0%|
[sslbl](#sslbl)|370|370|6|1.6%|0.0%|
[openbl_1d](#openbl_1d)|124|124|5|4.0%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|83|83|5|6.0%|0.0%|
[palevo](#palevo)|13|13|2|15.3%|0.0%|
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
[firehol_level1](#firehol_level1)|5070|688854680|4637595|0.6%|3.3%|
[fullbogons](#fullbogons)|3775|670173256|4236143|0.6%|3.0%|
[bogons](#bogons)|13|592708608|4194304|0.7%|3.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|2830203|0.8%|2.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|1354507|0.1%|0.9%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|270785|55.5%|0.1%|
[firehol_level3](#firehol_level3)|109549|9627220|161594|1.6%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|145472|1.5%|0.1%|
[et_block](#et_block)|1000|18343756|130650|0.7%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|130368|0.7%|0.0%|
[dragon_http](#dragon_http)|1021|268288|20480|7.6%|0.0%|
[alienvault_reputation](#alienvault_reputation)|189146|189146|14337|7.5%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|9226|2.7%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|5830|6.1%|0.0%|
[firehol_level2](#firehol_level2)|20666|32229|3685|11.4%|0.0%|
[blocklist_de](#blocklist_de)|26985|26985|3282|12.1%|0.0%|
[firehol_anonymous](#firehol_anonymous)|19172|83219|2877|3.4%|0.0%|
[sorbs_spam](#sorbs_spam)|64701|65536|2860|4.3%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|2851|4.3%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|2851|4.3%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|17750|17750|2576|14.5%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13845|13845|2284|16.4%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|1961|6.7%|0.0%|
[voipbl](#voipbl)|10586|10998|1613|14.6%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|1172|2.4%|0.0%|
[nixspam](#nixspam)|18198|18198|1025|5.6%|0.0%|
[openbl_60d](#openbl_60d)|6960|6960|740|10.6%|0.0%|
[et_tor](#et_tor)|6500|6500|636|9.7%|0.0%|
[dm_tor](#dm_tor)|6468|6468|629|9.7%|0.0%|
[bm_tor](#bm_tor)|6471|6471|629|9.7%|0.0%|
[firehol_proxies](#firehol_proxies)|12734|13010|531|4.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6669|6669|488|7.3%|0.0%|
[openbl_30d](#openbl_30d)|2792|2792|286|10.2%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2726|2726|283|10.3%|0.0%|
[iw_spamlist](#iw_spamlist)|3648|3648|260|7.1%|0.0%|
[dshield](#dshield)|20|5120|256|5.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9136|9136|240|2.6%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7952|7952|221|2.7%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1901|1901|186|9.7%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2446|2446|186|7.6%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|2972|2972|182|6.1%|0.0%|
[et_compromised](#et_compromised)|1704|1704|157|9.2%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1694|1694|157|9.2%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|150|28.6%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|147|11.4%|0.0%|
[tor_exits](#tor_exits)|1106|1106|126|11.3%|0.0%|
[dragon_sshpauth](#dragon_sshpauth)|1589|1653|125|7.5%|0.0%|
[shunlist](#shunlist)|1185|1185|120|10.1%|0.0%|
[xroxy](#xroxy)|2175|2175|112|5.1%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|1523|1523|110|7.2%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|108|7.4%|0.0%|
[proxz](#proxz)|1356|1356|106|7.8%|0.0%|
[et_botcc](#et_botcc)|505|505|76|15.0%|0.0%|
[ciarmy](#ciarmy)|416|416|70|16.8%|0.0%|
[openbl_7d](#openbl_7d)|629|629|66|10.4%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|511|511|58|11.3%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2855|2855|57|1.9%|0.0%|
[proxyrss](#proxyrss)|1570|1570|53|3.3%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|51|7.6%|0.0%|
[php_spammers](#php_spammers)|735|735|44|5.9%|0.0%|
[malc0de](#malc0de)|276|276|44|15.9%|0.0%|
[php_dictionary](#php_dictionary)|737|737|39|5.2%|0.0%|
[sorbs_web](#sorbs_web)|628|629|32|5.0%|0.0%|
[php_commenters](#php_commenters)|458|458|29|6.3%|0.0%|
[sslbl](#sslbl)|370|370|28|7.5%|0.0%|
[php_harvesters](#php_harvesters)|408|408|20|4.9%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|170|170|17|10.0%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|83|83|15|18.0%|0.0%|
[zeus](#zeus)|230|230|14|6.0%|0.0%|
[openbl_1d](#openbl_1d)|124|124|12|9.6%|0.0%|
[dragon_vncprobe](#dragon_vncprobe)|87|87|12|13.7%|0.0%|
[zeus_badips](#zeus_badips)|202|202|10|4.9%|0.0%|
[nt_malware_http](#nt_malware_http)|69|69|5|7.2%|0.0%|
[sorbs_socks](#sorbs_socks)|7|7|2|28.5%|0.0%|
[sorbs_misc](#sorbs_misc)|7|7|2|28.5%|0.0%|
[sorbs_http](#sorbs_http)|7|7|2|28.5%|0.0%|
[iw_wormlist](#iw_wormlist)|34|34|2|5.8%|0.0%|
[virbl](#virbl)|22|22|1|4.5%|0.0%|
[palevo](#palevo)|13|13|1|7.6%|0.0%|
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
[firehol_proxies](#firehol_proxies)|12734|13010|663|5.0%|100.0%|
[firehol_anonymous](#firehol_anonymous)|19172|83219|663|0.7%|100.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|56|0.0%|8.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|51|0.0%|7.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|26|0.0%|3.9%|
[firehol_level3](#firehol_level3)|109549|9627220|25|0.0%|3.7%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|20|0.0%|3.0%|
[ri_web_proxies](#ri_web_proxies)|7952|7952|15|0.1%|2.2%|
[xroxy](#xroxy)|2175|2175|13|0.5%|1.9%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|11|0.0%|1.6%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|10|0.0%|1.5%|
[proxyrss](#proxyrss)|1570|1570|10|0.6%|1.5%|
[firehol_level2](#firehol_level2)|20666|32229|8|0.0%|1.2%|
[ri_connect_proxies](#ri_connect_proxies)|2855|2855|7|0.2%|1.0%|
[proxz](#proxz)|1356|1356|7|0.5%|1.0%|
[stopforumspam_1d](#stopforumspam_1d)|6669|6669|5|0.0%|0.7%|
[blocklist_de](#blocklist_de)|26985|26985|5|0.0%|0.7%|
[blocklist_de_bots](#blocklist_de_bots)|2972|2972|4|0.1%|0.6%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|2|0.0%|0.3%|
[php_dictionary](#php_dictionary)|737|737|2|0.2%|0.3%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|2|0.1%|0.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2|0.0%|0.3%|
[firehol_level1](#firehol_level1)|5070|688854680|2|0.0%|0.3%|
[et_block](#et_block)|1000|18343756|2|0.0%|0.3%|
[alienvault_reputation](#alienvault_reputation)|189146|189146|2|0.0%|0.3%|
[sorbs_spam](#sorbs_spam)|64701|65536|1|0.0%|0.1%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|1|0.0%|0.1%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|1|0.0%|0.1%|
[snort_ipfilter](#snort_ipfilter)|9136|9136|1|0.0%|0.1%|
[php_spammers](#php_spammers)|735|735|1|0.1%|0.1%|
[nixspam](#nixspam)|18198|18198|1|0.0%|0.1%|
[dragon_http](#dragon_http)|1021|268288|1|0.0%|0.1%|
[blocklist_de_mail](#blocklist_de_mail)|17750|17750|1|0.0%|0.1%|

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
[firehol_level3](#firehol_level3)|109549|9627220|339173|3.5%|100.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|13247|0.0%|3.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|9226|0.0%|2.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|7728|0.0%|2.2%|
[firehol_level1](#firehol_level1)|5070|688854680|1931|0.0%|0.5%|
[et_block](#et_block)|1000|18343756|1041|0.0%|0.3%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|1037|0.0%|0.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1036|0.0%|0.3%|
[fullbogons](#fullbogons)|3775|670173256|890|0.0%|0.2%|
[alienvault_reputation](#alienvault_reputation)|189146|189146|293|0.1%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|52|0.0%|0.0%|
[sorbs_spam](#sorbs_spam)|64701|65536|38|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|37|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|37|0.0%|0.0%|
[firehol_anonymous](#firehol_anonymous)|19172|83219|30|0.0%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|27|2.0%|0.0%|
[et_tor](#et_tor)|6500|6500|22|0.3%|0.0%|
[dm_tor](#dm_tor)|6468|6468|22|0.3%|0.0%|
[bm_tor](#bm_tor)|6471|6471|22|0.3%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|21|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|19|1.3%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9136|9136|14|0.1%|0.0%|
[firehol_proxies](#firehol_proxies)|12734|13010|12|0.0%|0.0%|
[firehol_level2](#firehol_level2)|20666|32229|12|0.0%|0.0%|
[nixspam](#nixspam)|18198|18198|11|0.0%|0.0%|
[tor_exits](#tor_exits)|1106|1106|8|0.7%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6669|6669|7|0.1%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7952|7952|6|0.0%|0.0%|
[dragon_http](#dragon_http)|1021|268288|6|0.0%|0.0%|
[openbl_60d](#openbl_60d)|6960|6960|5|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|5|0.9%|0.0%|
[blocklist_de](#blocklist_de)|26985|26985|5|0.0%|0.0%|
[voipbl](#voipbl)|10586|10998|4|0.0%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|511|511|4|0.7%|0.0%|
[openbl_30d](#openbl_30d)|2792|2792|3|0.1%|0.0%|
[iw_spamlist](#iw_spamlist)|3648|3648|3|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|3|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13845|13845|3|0.0%|0.0%|
[proxyrss](#proxyrss)|1570|1570|2|0.1%|0.0%|
[malc0de](#malc0de)|276|276|2|0.7%|0.0%|
[et_compromised](#et_compromised)|1704|1704|2|0.1%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1694|1694|2|0.1%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|83|83|2|2.4%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|17750|17750|2|0.0%|0.0%|
[zeus_badips](#zeus_badips)|202|202|1|0.4%|0.0%|
[zeus](#zeus)|230|230|1|0.4%|0.0%|
[xroxy](#xroxy)|2175|2175|1|0.0%|0.0%|
[sslbl](#sslbl)|370|370|1|0.2%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|1|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2855|2855|1|0.0%|0.0%|
[proxz](#proxz)|1356|1356|1|0.0%|0.0%|
[php_harvesters](#php_harvesters)|408|408|1|0.2%|0.0%|
[php_dictionary](#php_dictionary)|737|737|1|0.1%|0.0%|
[php_commenters](#php_commenters)|458|458|1|0.2%|0.0%|
[palevo](#palevo)|13|13|1|7.6%|0.0%|
[nt_malware_http](#nt_malware_http)|69|69|1|1.4%|0.0%|
[bogons](#bogons)|13|592708608|1|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1901|1901|1|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2446|2446|1|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|2972|2972|1|0.0%|0.0%|

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
[firehol_level3](#firehol_level3)|109549|9627220|1450|0.0%|100.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|108|0.0%|7.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|97|0.0%|6.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|45|0.0%|3.1%|
[firehol_level1](#firehol_level1)|5070|688854680|39|0.0%|2.6%|
[fullbogons](#fullbogons)|3775|670173256|33|0.0%|2.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|19|0.0%|1.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|7|0.0%|0.4%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|6|0.0%|0.4%|
[et_block](#et_block)|1000|18343756|6|0.0%|0.4%|
[alienvault_reputation](#alienvault_reputation)|189146|189146|6|0.0%|0.4%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|3|0.2%|0.2%|
[firehol_proxies](#firehol_proxies)|12734|13010|3|0.0%|0.2%|
[firehol_anonymous](#firehol_anonymous)|19172|83219|3|0.0%|0.2%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|2|0.0%|0.1%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|2|0.0%|0.1%|
[sorbs_spam](#sorbs_spam)|64701|65536|2|0.0%|0.1%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|2|0.0%|0.1%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|2|0.0%|0.1%|
[openbl_60d](#openbl_60d)|6960|6960|2|0.0%|0.1%|
[openbl_30d](#openbl_30d)|2792|2792|2|0.0%|0.1%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|2|0.3%|0.1%|
[firehol_level2](#firehol_level2)|20666|32229|2|0.0%|0.1%|
[dragon_http](#dragon_http)|1021|268288|2|0.0%|0.1%|
[blocklist_de_strongips](#blocklist_de_strongips)|170|170|2|1.1%|0.1%|
[blocklist_de_bots](#blocklist_de_bots)|2972|2972|2|0.0%|0.1%|
[blocklist_de](#blocklist_de)|26985|26985|2|0.0%|0.1%|
[stopforumspam_1d](#stopforumspam_1d)|6669|6669|1|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9136|9136|1|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7952|7952|1|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|1|0.0%|0.0%|
[et_botcc](#et_botcc)|505|505|1|0.1%|0.0%|
[dragon_sshpauth](#dragon_sshpauth)|1589|1653|1|0.0%|0.0%|

## iw_spamlist

[ImproWare Antispam](http://antispam.imp.ch/) IPs sending spam, in the last 3 days

Source is downloaded from [this link](http://antispam.imp.ch/spamlist).

The last time downloaded was found to be dated: Fri Jun 12 09:20:04 UTC 2015.

The ipset `iw_spamlist` has **3648** entries, **3648** unique IPs.

The following table shows the overlaps of `iw_spamlist` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `iw_spamlist`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `iw_spamlist`.
- ` this % ` is the percentage **of this ipset (`iw_spamlist`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[sorbs_spam](#sorbs_spam)|64701|65536|955|1.4%|26.1%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|950|1.4%|26.0%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|950|1.4%|26.0%|
[nixspam](#nixspam)|18198|18198|508|2.7%|13.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|260|0.0%|7.1%|
[firehol_level2](#firehol_level2)|20666|32229|122|0.3%|3.3%|
[blocklist_de](#blocklist_de)|26985|26985|122|0.4%|3.3%|
[blocklist_de_mail](#blocklist_de_mail)|17750|17750|112|0.6%|3.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|92|0.0%|2.5%|
[firehol_level3](#firehol_level3)|109549|9627220|89|0.0%|2.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|65|0.0%|1.7%|
[snort_ipfilter](#snort_ipfilter)|9136|9136|48|0.5%|1.3%|
[alienvault_reputation](#alienvault_reputation)|189146|189146|24|0.0%|0.6%|
[sorbs_web](#sorbs_web)|628|629|23|3.6%|0.6%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|20|0.0%|0.5%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|12|0.0%|0.3%|
[iw_wormlist](#iw_wormlist)|34|34|12|35.2%|0.3%|
[firehol_level1](#firehol_level1)|5070|688854680|9|0.0%|0.2%|
[firehol_proxies](#firehol_proxies)|12734|13010|8|0.0%|0.2%|
[firehol_anonymous](#firehol_anonymous)|19172|83219|8|0.0%|0.2%|
[ri_web_proxies](#ri_web_proxies)|7952|7952|6|0.0%|0.1%|
[php_dictionary](#php_dictionary)|737|737|6|0.8%|0.1%|
[fullbogons](#fullbogons)|3775|670173256|5|0.0%|0.1%|
[bogons](#bogons)|13|592708608|5|0.0%|0.1%|
[blocklist_de_bots](#blocklist_de_bots)|2972|2972|5|0.1%|0.1%|
[php_spammers](#php_spammers)|735|735|4|0.5%|0.1%|
[php_harvesters](#php_harvesters)|408|408|4|0.9%|0.1%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|3|0.0%|0.0%|
[php_commenters](#php_commenters)|458|458|3|0.6%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|3|0.0%|0.0%|
[et_block](#et_block)|1000|18343756|3|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2446|2446|3|0.1%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13845|13845|3|0.0%|0.0%|
[xroxy](#xroxy)|2175|2175|2|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6669|6669|2|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2855|2855|2|0.0%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2|0.0%|0.0%|
[dragon_http](#dragon_http)|1021|268288|2|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2726|2726|2|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|1523|1523|2|0.1%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|1|0.0%|0.0%|
[sorbs_socks](#sorbs_socks)|7|7|1|14.2%|0.0%|
[sorbs_misc](#sorbs_misc)|7|7|1|14.2%|0.0%|
[sorbs_http](#sorbs_http)|7|7|1|14.2%|0.0%|
[proxz](#proxz)|1356|1356|1|0.0%|0.0%|

## iw_wormlist

[ImproWare Antispam](http://antispam.imp.ch/) IPs sending emails with viruses or worms, in the last 3 days

Source is downloaded from [this link](http://antispam.imp.ch/wormlist).

The last time downloaded was found to be dated: Fri Jun 12 09:20:04 UTC 2015.

The ipset `iw_wormlist` has **34** entries, **34** unique IPs.

The following table shows the overlaps of `iw_wormlist` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `iw_wormlist`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `iw_wormlist`.
- ` this % ` is the percentage **of this ipset (`iw_wormlist`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level3](#firehol_level3)|109549|9627220|34|0.0%|100.0%|
[iw_spamlist](#iw_spamlist)|3648|3648|12|0.3%|35.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|2|0.0%|5.8%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|1|0.0%|2.9%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|1|0.0%|2.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|1|0.0%|2.9%|
[firehol_level2](#firehol_level2)|20666|32229|1|0.0%|2.9%|
[blocklist_de_mail](#blocklist_de_mail)|17750|17750|1|0.0%|2.9%|
[blocklist_de](#blocklist_de)|26985|26985|1|0.0%|2.9%|

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
[firehol_level3](#firehol_level3)|109549|9627220|276|0.0%|100.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|44|0.0%|15.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|16|0.0%|5.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|10|0.0%|3.6%|
[alienvault_reputation](#alienvault_reputation)|189146|189146|9|0.0%|3.2%|
[cleanmx_viruses](#cleanmx_viruses)|511|511|8|1.5%|2.8%|
[firehol_level1](#firehol_level1)|5070|688854680|5|0.0%|1.8%|
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
[firehol_level3](#firehol_level3)|109549|9627220|1288|0.0%|100.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|147|0.0%|11.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|66|0.0%|5.1%|
[firehol_level1](#firehol_level1)|5070|688854680|39|0.0%|3.0%|
[et_block](#et_block)|1000|18343756|30|0.0%|2.3%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|29|0.0%|2.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|27|0.0%|2.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|27|0.0%|2.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|26|0.0%|2.0%|
[snort_ipfilter](#snort_ipfilter)|9136|9136|11|0.1%|0.8%|
[fullbogons](#fullbogons)|3775|670173256|9|0.0%|0.6%|
[alienvault_reputation](#alienvault_reputation)|189146|189146|8|0.0%|0.6%|
[malc0de](#malc0de)|276|276|4|1.4%|0.3%|
[cleanmx_viruses](#cleanmx_viruses)|511|511|4|0.7%|0.3%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|3|0.0%|0.2%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|3|0.2%|0.2%|
[dragon_http](#dragon_http)|1021|268288|2|0.0%|0.1%|
[zeus](#zeus)|230|230|1|0.4%|0.0%|
[nixspam](#nixspam)|18198|18198|1|0.0%|0.0%|
[et_botcc](#et_botcc)|505|505|1|0.1%|0.0%|

## maxmind_proxy_fraud

[MaxMind.com](https://www.maxmind.com/en/anonymous-proxy-fraudulent-ip-address-list) list of anonymous proxy fraudelent IP addresses.

Source is downloaded from [this link](https://www.maxmind.com/en/anonymous-proxy-fraudulent-ip-address-list).

The last time downloaded was found to be dated: Fri Jun 12 07:54:21 UTC 2015.

The ipset `maxmind_proxy_fraud` has **524** entries, **524** unique IPs.

The following table shows the overlaps of `maxmind_proxy_fraud` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `maxmind_proxy_fraud`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `maxmind_proxy_fraud`.
- ` this % ` is the percentage **of this ipset (`maxmind_proxy_fraud`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_proxies](#firehol_proxies)|12734|13010|524|4.0%|100.0%|
[firehol_anonymous](#firehol_anonymous)|19172|83219|524|0.6%|100.0%|
[firehol_level3](#firehol_level3)|109549|9627220|346|0.0%|66.0%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|345|0.3%|65.8%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|277|0.9%|52.8%|
[snort_ipfilter](#snort_ipfilter)|9136|9136|237|2.5%|45.2%|
[et_tor](#et_tor)|6500|6500|233|3.5%|44.4%|
[dm_tor](#dm_tor)|6468|6468|229|3.5%|43.7%|
[bm_tor](#bm_tor)|6471|6471|229|3.5%|43.7%|
[tor_exits](#tor_exits)|1106|1106|228|20.6%|43.5%|
[firehol_level2](#firehol_level2)|20666|32229|197|0.6%|37.5%|
[stopforumspam_1d](#stopforumspam_1d)|6669|6669|195|2.9%|37.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|150|0.0%|28.6%|
[php_commenters](#php_commenters)|458|458|53|11.5%|10.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|29|0.0%|5.5%|
[alienvault_reputation](#alienvault_reputation)|189146|189146|29|0.0%|5.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|21|0.0%|4.0%|
[openbl_60d](#openbl_60d)|6960|6960|20|0.2%|3.8%|
[ri_web_proxies](#ri_web_proxies)|7952|7952|10|0.1%|1.9%|
[php_harvesters](#php_harvesters)|408|408|7|1.7%|1.3%|
[php_spammers](#php_spammers)|735|735|6|0.8%|1.1%|
[php_dictionary](#php_dictionary)|737|737|5|0.6%|0.9%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|5|0.0%|0.9%|
[blocklist_de](#blocklist_de)|26985|26985|5|0.0%|0.9%|
[dragon_http](#dragon_http)|1021|268288|4|0.0%|0.7%|
[blocklist_de_bots](#blocklist_de_bots)|2972|2972|4|0.1%|0.7%|
[xroxy](#xroxy)|2175|2175|3|0.1%|0.5%|
[voipbl](#voipbl)|10586|10998|2|0.0%|0.3%|
[proxz](#proxz)|1356|1356|2|0.1%|0.3%|
[nixspam](#nixspam)|18198|18198|2|0.0%|0.3%|
[firehol_level1](#firehol_level1)|5070|688854680|2|0.0%|0.3%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|1|0.0%|0.1%|
[sorbs_spam](#sorbs_spam)|64701|65536|1|0.0%|0.1%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|1|0.0%|0.1%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|1|0.0%|0.1%|
[shunlist](#shunlist)|1185|1185|1|0.0%|0.1%|
[ri_connect_proxies](#ri_connect_proxies)|2855|2855|1|0.0%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.1%|
[et_block](#et_block)|1000|18343756|1|0.0%|0.1%|
[dshield](#dshield)|20|5120|1|0.0%|0.1%|
[blocklist_de_mail](#blocklist_de_mail)|17750|17750|1|0.0%|0.1%|
[blocklist_de_apache](#blocklist_de_apache)|13845|13845|1|0.0%|0.1%|

## nixspam

[NiX Spam](http://www.heise.de/ix/NiX-Spam-DNSBL-and-blacklist-for-download-499637.html) IP addresses that sent spam in the last hour - automatically generated entries without distinguishing open proxies from relays, dialup gateways, and so on. All IPs are removed after 12 hours if there is no spam from there.

Source is downloaded from [this link](http://www.dnsbl.manitu.net/download/nixspam-ip.dump.gz).

The last time downloaded was found to be dated: Fri Jun 12 09:30:02 UTC 2015.

The ipset `nixspam` has **18198** entries, **18198** unique IPs.

The following table shows the overlaps of `nixspam` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `nixspam`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `nixspam`.
- ` this % ` is the percentage **of this ipset (`nixspam`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[sorbs_spam](#sorbs_spam)|64701|65536|1377|2.1%|7.5%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|1367|2.0%|7.5%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|1367|2.0%|7.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|1025|0.0%|5.6%|
[firehol_level2](#firehol_level2)|20666|32229|517|1.6%|2.8%|
[iw_spamlist](#iw_spamlist)|3648|3648|508|13.9%|2.7%|
[blocklist_de](#blocklist_de)|26985|26985|497|1.8%|2.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|485|0.0%|2.6%|
[blocklist_de_mail](#blocklist_de_mail)|17750|17750|425|2.3%|2.3%|
[firehol_level3](#firehol_level3)|109549|9627220|418|0.0%|2.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|303|0.0%|1.6%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|231|0.2%|1.2%|
[snort_ipfilter](#snort_ipfilter)|9136|9136|191|2.0%|1.0%|
[firehol_anonymous](#firehol_anonymous)|19172|83219|149|0.1%|0.8%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|143|0.4%|0.7%|
[firehol_proxies](#firehol_proxies)|12734|13010|142|1.0%|0.7%|
[php_dictionary](#php_dictionary)|737|737|107|14.5%|0.5%|
[ri_web_proxies](#ri_web_proxies)|7952|7952|97|1.2%|0.5%|
[php_spammers](#php_spammers)|735|735|92|12.5%|0.5%|
[sorbs_web](#sorbs_web)|628|629|88|13.9%|0.4%|
[xroxy](#xroxy)|2175|2175|67|3.0%|0.3%|
[stopforumspam_1d](#stopforumspam_1d)|6669|6669|61|0.9%|0.3%|
[proxz](#proxz)|1356|1356|48|3.5%|0.2%|
[alienvault_reputation](#alienvault_reputation)|189146|189146|44|0.0%|0.2%|
[blocklist_de_bots](#blocklist_de_bots)|2972|2972|40|1.3%|0.2%|
[dragon_http](#dragon_http)|1021|268288|27|0.0%|0.1%|
[blocklist_de_imap](#blocklist_de_imap)|2726|2726|25|0.9%|0.1%|
[firehol_level1](#firehol_level1)|5070|688854680|24|0.0%|0.1%|
[et_block](#et_block)|1000|18343756|22|0.0%|0.1%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|21|0.0%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|21|0.0%|0.1%|
[ri_connect_proxies](#ri_connect_proxies)|2855|2855|18|0.6%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13845|13845|17|0.1%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2446|2446|15|0.6%|0.0%|
[php_commenters](#php_commenters)|458|458|13|2.8%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|11|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|11|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|1523|1523|11|0.7%|0.0%|
[proxyrss](#proxyrss)|1570|1570|10|0.6%|0.0%|
[openbl_60d](#openbl_60d)|6960|6960|9|0.1%|0.0%|
[tor_exits](#tor_exits)|1106|1106|8|0.7%|0.0%|
[php_harvesters](#php_harvesters)|408|408|8|1.9%|0.0%|
[dm_tor](#dm_tor)|6468|6468|6|0.0%|0.0%|
[bm_tor](#bm_tor)|6471|6471|6|0.0%|0.0%|
[et_tor](#et_tor)|6500|6500|5|0.0%|0.0%|
[openbl_30d](#openbl_30d)|2792|2792|4|0.1%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|2|0.3%|0.0%|
[et_compromised](#et_compromised)|1704|1704|2|0.1%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1694|1694|2|0.1%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|170|170|2|1.1%|0.0%|
[zeus_badips](#zeus_badips)|202|202|1|0.4%|0.0%|
[zeus](#zeus)|230|230|1|0.4%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|1|0.0%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|1|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|1|0.1%|0.0%|
[dshield](#dshield)|20|5120|1|0.0%|0.0%|
[dragon_sshpauth](#dragon_sshpauth)|1589|1653|1|0.0%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|511|511|1|0.1%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1901|1901|1|0.0%|0.0%|

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
[firehol_level1](#firehol_level1)|5070|688854680|8|0.0%|11.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|7|0.0%|10.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|5|0.0%|7.2%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|4|0.0%|5.7%|
[fullbogons](#fullbogons)|3775|670173256|4|0.0%|5.7%|
[et_block](#et_block)|1000|18343756|4|0.0%|5.7%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|4.3%|
[firehol_level3](#firehol_level3)|109549|9627220|3|0.0%|4.3%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|2|0.0%|2.8%|
[nt_malware_irc](#nt_malware_irc)|43|43|2|4.6%|2.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|2|0.0%|2.8%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|1.4%|
[alienvault_reputation](#alienvault_reputation)|189146|189146|1|0.0%|1.4%|

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
[firehol_level1](#firehol_level1)|5070|688854680|3|0.0%|6.9%|
[et_block](#et_block)|1000|18343756|3|0.0%|6.9%|
[nt_malware_http](#nt_malware_http)|69|69|2|2.8%|4.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|2|0.0%|4.6%|
[alienvault_reputation](#alienvault_reputation)|189146|189146|2|0.0%|4.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|1|0.0%|2.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|2.3%|
[firehol_level3](#firehol_level3)|109549|9627220|1|0.0%|2.3%|

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

The last time downloaded was found to be dated: Fri Jun 12 09:32:00 UTC 2015.

The ipset `openbl_1d` has **124** entries, **124** unique IPs.

The following table shows the overlaps of `openbl_1d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl_1d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl_1d`.
- ` this % ` is the percentage **of this ipset (`openbl_1d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|20666|32229|124|0.3%|100.0%|
[openbl_60d](#openbl_60d)|6960|6960|121|1.7%|97.5%|
[openbl_30d](#openbl_30d)|2792|2792|120|4.2%|96.7%|
[firehol_level3](#firehol_level3)|109549|9627220|120|0.0%|96.7%|
[openbl_7d](#openbl_7d)|629|629|118|18.7%|95.1%|
[alienvault_reputation](#alienvault_reputation)|189146|189146|115|0.0%|92.7%|
[blocklist_de](#blocklist_de)|26985|26985|105|0.3%|84.6%|
[blocklist_de_ssh](#blocklist_de_ssh)|1901|1901|103|5.4%|83.0%|
[dragon_sshpauth](#dragon_sshpauth)|1589|1653|81|4.9%|65.3%|
[shunlist](#shunlist)|1185|1185|66|5.5%|53.2%|
[bruteforceblocker](#bruteforceblocker)|1694|1694|56|3.3%|45.1%|
[et_compromised](#et_compromised)|1704|1704|52|3.0%|41.9%|
[blocklist_de_strongips](#blocklist_de_strongips)|170|170|18|10.5%|14.5%|
[firehol_level1](#firehol_level1)|5070|688854680|13|0.0%|10.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|12|0.0%|9.6%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|9|0.0%|7.2%|
[et_block](#et_block)|1000|18343756|9|0.0%|7.2%|
[dshield](#dshield)|20|5120|6|0.1%|4.8%|
[dragon_http](#dragon_http)|1021|268288|6|0.0%|4.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|5|0.0%|4.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|2.4%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|1|0.0%|0.8%|
[php_spammers](#php_spammers)|735|735|1|0.1%|0.8%|
[php_commenters](#php_commenters)|458|458|1|0.2%|0.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|1|0.0%|0.8%|
[ciarmy](#ciarmy)|416|416|1|0.2%|0.8%|
[blocklist_de_mail](#blocklist_de_mail)|17750|17750|1|0.0%|0.8%|
[blocklist_de_imap](#blocklist_de_imap)|2726|2726|1|0.0%|0.8%|

## openbl_30d

[OpenBL.org](http://www.openbl.org/) last 30 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.

Source is downloaded from [this link](http://www.openbl.org/lists/base_30days.txt).

The last time downloaded was found to be dated: Fri Jun 12 08:07:00 UTC 2015.

The ipset `openbl_30d` has **2792** entries, **2792** unique IPs.

The following table shows the overlaps of `openbl_30d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl_30d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl_30d`.
- ` this % ` is the percentage **of this ipset (`openbl_30d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[openbl_60d](#openbl_60d)|6960|6960|2792|40.1%|100.0%|
[firehol_level3](#firehol_level3)|109549|9627220|2792|0.0%|100.0%|
[alienvault_reputation](#alienvault_reputation)|189146|189146|2772|1.4%|99.2%|
[et_compromised](#et_compromised)|1704|1704|910|53.4%|32.5%|
[bruteforceblocker](#bruteforceblocker)|1694|1694|904|53.3%|32.3%|
[dragon_sshpauth](#dragon_sshpauth)|1589|1653|698|42.2%|25.0%|
[firehol_level2](#firehol_level2)|20666|32229|647|2.0%|23.1%|
[blocklist_de](#blocklist_de)|26985|26985|631|2.3%|22.6%|
[openbl_7d](#openbl_7d)|629|629|629|100.0%|22.5%|
[blocklist_de_ssh](#blocklist_de_ssh)|1901|1901|612|32.1%|21.9%|
[shunlist](#shunlist)|1185|1185|439|37.0%|15.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|286|0.0%|10.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|146|0.0%|5.2%|
[dragon_http](#dragon_http)|1021|268288|146|0.0%|5.2%|
[firehol_level1](#firehol_level1)|5070|688854680|135|0.0%|4.8%|
[et_block](#et_block)|1000|18343756|125|0.0%|4.4%|
[openbl_1d](#openbl_1d)|124|124|120|96.7%|4.2%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|119|0.0%|4.2%|
[dshield](#dshield)|20|5120|80|1.5%|2.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|65|0.0%|2.3%|
[blocklist_de_strongips](#blocklist_de_strongips)|170|170|23|13.5%|0.8%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|12|0.0%|0.4%|
[blocklist_de_mail](#blocklist_de_mail)|17750|17750|12|0.0%|0.4%|
[blocklist_de_imap](#blocklist_de_imap)|2726|2726|9|0.3%|0.3%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|5|0.0%|0.1%|
[blocklist_de_apache](#blocklist_de_apache)|13845|13845|5|0.0%|0.1%|
[nixspam](#nixspam)|18198|18198|4|0.0%|0.1%|
[voipbl](#voipbl)|10586|10998|3|0.0%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|3|0.0%|0.1%|
[zeus](#zeus)|230|230|2|0.8%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9136|9136|2|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|2|0.1%|0.0%|
[ciarmy](#ciarmy)|416|416|2|0.4%|0.0%|
[zeus_badips](#zeus_badips)|202|202|1|0.4%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|1|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6669|6669|1|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|1|0.0%|0.0%|
[php_spammers](#php_spammers)|735|735|1|0.1%|0.0%|
[php_commenters](#php_commenters)|458|458|1|0.2%|0.0%|
[firehol_anonymous](#firehol_anonymous)|19172|83219|1|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|1523|1523|1|0.0%|0.0%|

## openbl_60d

[OpenBL.org](http://www.openbl.org/) last 60 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.

Source is downloaded from [this link](http://www.openbl.org/lists/base_60days.txt).

The last time downloaded was found to be dated: Fri Jun 12 08:07:00 UTC 2015.

The ipset `openbl_60d` has **6960** entries, **6960** unique IPs.

The following table shows the overlaps of `openbl_60d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl_60d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl_60d`.
- ` this % ` is the percentage **of this ipset (`openbl_60d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[alienvault_reputation](#alienvault_reputation)|189146|189146|6935|3.6%|99.6%|
[firehol_level3](#firehol_level3)|109549|9627220|2917|0.0%|41.9%|
[openbl_30d](#openbl_30d)|2792|2792|2792|100.0%|40.1%|
[et_compromised](#et_compromised)|1704|1704|977|57.3%|14.0%|
[bruteforceblocker](#bruteforceblocker)|1694|1694|963|56.8%|13.8%|
[dragon_sshpauth](#dragon_sshpauth)|1589|1653|780|47.1%|11.2%|
[firehol_level2](#firehol_level2)|20666|32229|758|2.3%|10.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|740|0.0%|10.6%|
[blocklist_de](#blocklist_de)|26985|26985|723|2.6%|10.3%|
[blocklist_de_ssh](#blocklist_de_ssh)|1901|1901|693|36.4%|9.9%|
[openbl_7d](#openbl_7d)|629|629|629|100.0%|9.0%|
[shunlist](#shunlist)|1185|1185|464|39.1%|6.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|319|0.0%|4.5%|
[firehol_level1](#firehol_level1)|5070|688854680|253|0.0%|3.6%|
[et_block](#et_block)|1000|18343756|244|0.0%|3.5%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|235|0.0%|3.3%|
[dragon_http](#dragon_http)|1021|268288|213|0.0%|3.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|161|0.0%|2.3%|
[openbl_1d](#openbl_1d)|124|124|121|97.5%|1.7%|
[dshield](#dshield)|20|5120|84|1.6%|1.2%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|47|0.0%|0.6%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|26|0.0%|0.3%|
[snort_ipfilter](#snort_ipfilter)|9136|9136|24|0.2%|0.3%|
[blocklist_de_strongips](#blocklist_de_strongips)|170|170|24|14.1%|0.3%|
[firehol_anonymous](#firehol_anonymous)|19172|83219|23|0.0%|0.3%|
[tor_exits](#tor_exits)|1106|1106|20|1.8%|0.2%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|20|3.8%|0.2%|
[firehol_proxies](#firehol_proxies)|12734|13010|20|0.1%|0.2%|
[et_tor](#et_tor)|6500|6500|20|0.3%|0.2%|
[dm_tor](#dm_tor)|6468|6468|20|0.3%|0.2%|
[bm_tor](#bm_tor)|6471|6471|20|0.3%|0.2%|
[stopforumspam_1d](#stopforumspam_1d)|6669|6669|19|0.2%|0.2%|
[blocklist_de_mail](#blocklist_de_mail)|17750|17750|18|0.1%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|16|0.0%|0.2%|
[blocklist_de_imap](#blocklist_de_imap)|2726|2726|15|0.5%|0.2%|
[php_commenters](#php_commenters)|458|458|12|2.6%|0.1%|
[nixspam](#nixspam)|18198|18198|9|0.0%|0.1%|
[voipbl](#voipbl)|10586|10998|8|0.0%|0.1%|
[blocklist_de_apache](#blocklist_de_apache)|13845|13845|8|0.0%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|5|0.0%|0.0%|
[zeus](#zeus)|230|230|2|0.8%|0.0%|
[sorbs_spam](#sorbs_spam)|64701|65536|2|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|2|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|2|0.0%|0.0%|
[php_harvesters](#php_harvesters)|408|408|2|0.4%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|2|0.1%|0.0%|
[ciarmy](#ciarmy)|416|416|2|0.4%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|1523|1523|2|0.1%|0.0%|
[zeus_badips](#zeus_badips)|202|202|1|0.4%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|1|0.0%|0.0%|
[php_spammers](#php_spammers)|735|735|1|0.1%|0.0%|

## openbl_7d

[OpenBL.org](http://www.openbl.org/) last 7 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.

Source is downloaded from [this link](http://www.openbl.org/lists/base_7days.txt).

The last time downloaded was found to be dated: Fri Jun 12 08:07:00 UTC 2015.

The ipset `openbl_7d` has **629** entries, **629** unique IPs.

The following table shows the overlaps of `openbl_7d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl_7d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl_7d`.
- ` this % ` is the percentage **of this ipset (`openbl_7d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[openbl_60d](#openbl_60d)|6960|6960|629|9.0%|100.0%|
[openbl_30d](#openbl_30d)|2792|2792|629|22.5%|100.0%|
[firehol_level3](#firehol_level3)|109549|9627220|629|0.0%|100.0%|
[alienvault_reputation](#alienvault_reputation)|189146|189146|622|0.3%|98.8%|
[firehol_level2](#firehol_level2)|20666|32229|384|1.1%|61.0%|
[blocklist_de](#blocklist_de)|26985|26985|370|1.3%|58.8%|
[blocklist_de_ssh](#blocklist_de_ssh)|1901|1901|361|18.9%|57.3%|
[dragon_sshpauth](#dragon_sshpauth)|1589|1653|346|20.9%|55.0%|
[bruteforceblocker](#bruteforceblocker)|1694|1694|308|18.1%|48.9%|
[et_compromised](#et_compromised)|1704|1704|305|17.8%|48.4%|
[shunlist](#shunlist)|1185|1185|207|17.4%|32.9%|
[openbl_1d](#openbl_1d)|124|124|118|95.1%|18.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|66|0.0%|10.4%|
[firehol_level1](#firehol_level1)|5070|688854680|60|0.0%|9.5%|
[et_block](#et_block)|1000|18343756|57|0.0%|9.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|53|0.0%|8.4%|
[dragon_http](#dragon_http)|1021|268288|51|0.0%|8.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|36|0.0%|5.7%|
[blocklist_de_strongips](#blocklist_de_strongips)|170|170|22|12.9%|3.4%|
[dshield](#dshield)|20|5120|21|0.4%|3.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|13|0.0%|2.0%|
[blocklist_de_mail](#blocklist_de_mail)|17750|17750|6|0.0%|0.9%|
[blocklist_de_imap](#blocklist_de_imap)|2726|2726|5|0.1%|0.7%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|4|0.0%|0.6%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|2|0.0%|0.3%|
[ciarmy](#ciarmy)|416|416|2|0.4%|0.3%|
[blocklist_de_apache](#blocklist_de_apache)|13845|13845|2|0.0%|0.3%|
[zeus_badips](#zeus_badips)|202|202|1|0.4%|0.1%|
[zeus](#zeus)|230|230|1|0.4%|0.1%|
[snort_ipfilter](#snort_ipfilter)|9136|9136|1|0.0%|0.1%|
[php_spammers](#php_spammers)|735|735|1|0.1%|0.1%|
[php_commenters](#php_commenters)|458|458|1|0.2%|0.1%|
[blocklist_de_ftp](#blocklist_de_ftp)|1523|1523|1|0.0%|0.1%|

## palevo

[Abuse.ch Palevo tracker](https://palevotracker.abuse.ch) worm includes IPs which are being used as botnet C&C for the Palevo crimeware - **excellent list**

Source is downloaded from [this link](https://palevotracker.abuse.ch/blocklists.php?download=ipblocklist).

The last time downloaded was found to be dated: Fri Jun 12 08:27:07 UTC 2015.

The ipset `palevo` has **13** entries, **13** unique IPs.

The following table shows the overlaps of `palevo` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `palevo`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `palevo`.
- ` this % ` is the percentage **of this ipset (`palevo`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level1](#firehol_level1)|5070|688854680|13|0.0%|100.0%|
[et_block](#et_block)|1000|18343756|12|0.0%|92.3%|
[snort_ipfilter](#snort_ipfilter)|9136|9136|11|0.1%|84.6%|
[firehol_level3](#firehol_level3)|109549|9627220|11|0.0%|84.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|2|0.0%|15.3%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|7.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|1|0.0%|7.6%|

## php_commenters

[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) comment spammers (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=c&rss=1).

The last time downloaded was found to be dated: Fri Jun 12 09:01:25 UTC 2015.

The ipset `php_commenters` has **458** entries, **458** unique IPs.

The following table shows the overlaps of `php_commenters` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `php_commenters`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `php_commenters`.
- ` this % ` is the percentage **of this ipset (`php_commenters`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level3](#firehol_level3)|109549|9627220|458|0.0%|100.0%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|334|0.3%|72.9%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|248|0.8%|54.1%|
[firehol_level2](#firehol_level2)|20666|32229|194|0.6%|42.3%|
[stopforumspam_1d](#stopforumspam_1d)|6669|6669|167|2.5%|36.4%|
[blocklist_de](#blocklist_de)|26985|26985|106|0.3%|23.1%|
[firehol_anonymous](#firehol_anonymous)|19172|83219|90|0.1%|19.6%|
[firehol_proxies](#firehol_proxies)|12734|13010|86|0.6%|18.7%|
[blocklist_de_bots](#blocklist_de_bots)|2972|2972|86|2.8%|18.7%|
[snort_ipfilter](#snort_ipfilter)|9136|9136|71|0.7%|15.5%|
[tor_exits](#tor_exits)|1106|1106|54|4.8%|11.7%|
[php_spammers](#php_spammers)|735|735|54|7.3%|11.7%|
[et_tor](#et_tor)|6500|6500|54|0.8%|11.7%|
[dm_tor](#dm_tor)|6468|6468|54|0.8%|11.7%|
[bm_tor](#bm_tor)|6471|6471|54|0.8%|11.7%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|53|10.1%|11.5%|
[blocklist_de_strongips](#blocklist_de_strongips)|170|170|44|25.8%|9.6%|
[firehol_level1](#firehol_level1)|5070|688854680|39|0.0%|8.5%|
[php_dictionary](#php_dictionary)|737|737|38|5.1%|8.2%|
[ri_web_proxies](#ri_web_proxies)|7952|7952|30|0.3%|6.5%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|29|0.0%|6.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|29|0.0%|6.3%|
[et_block](#et_block)|1000|18343756|29|0.0%|6.3%|
[blocklist_de_mail](#blocklist_de_mail)|17750|17750|29|0.1%|6.3%|
[blocklist_de_apache](#blocklist_de_apache)|13845|13845|28|0.2%|6.1%|
[sorbs_spam](#sorbs_spam)|64701|65536|27|0.0%|5.8%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|27|0.0%|5.8%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|27|0.0%|5.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|19|0.0%|4.1%|
[alienvault_reputation](#alienvault_reputation)|189146|189146|19|0.0%|4.1%|
[php_harvesters](#php_harvesters)|408|408|15|3.6%|3.2%|
[xroxy](#xroxy)|2175|2175|13|0.5%|2.8%|
[nixspam](#nixspam)|18198|18198|13|0.0%|2.8%|
[openbl_60d](#openbl_60d)|6960|6960|12|0.1%|2.6%|
[proxz](#proxz)|1356|1356|10|0.7%|2.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|10|0.0%|2.1%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|8|0.0%|1.7%|
[ri_connect_proxies](#ri_connect_proxies)|2855|2855|6|0.2%|1.3%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2446|2446|6|0.2%|1.3%|
[proxyrss](#proxyrss)|1570|1570|5|0.3%|1.0%|
[sorbs_web](#sorbs_web)|628|629|4|0.6%|0.8%|
[dragon_http](#dragon_http)|1021|268288|4|0.0%|0.8%|
[iw_spamlist](#iw_spamlist)|3648|3648|3|0.0%|0.6%|
[zeus_badips](#zeus_badips)|202|202|1|0.4%|0.2%|
[zeus](#zeus)|230|230|1|0.4%|0.2%|
[openbl_7d](#openbl_7d)|629|629|1|0.1%|0.2%|
[openbl_30d](#openbl_30d)|2792|2792|1|0.0%|0.2%|
[openbl_1d](#openbl_1d)|124|124|1|0.8%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.2%|
[fullbogons](#fullbogons)|3775|670173256|1|0.0%|0.2%|
[et_compromised](#et_compromised)|1704|1704|1|0.0%|0.2%|
[dshield](#dshield)|20|5120|1|0.0%|0.2%|
[bruteforceblocker](#bruteforceblocker)|1694|1694|1|0.0%|0.2%|
[bogons](#bogons)|13|592708608|1|0.0%|0.2%|
[blocklist_de_ssh](#blocklist_de_ssh)|1901|1901|1|0.0%|0.2%|

## php_dictionary

[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) directory attackers (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=d&rss=1).

The last time downloaded was found to be dated: Fri Jun 12 09:01:25 UTC 2015.

The ipset `php_dictionary` has **737** entries, **737** unique IPs.

The following table shows the overlaps of `php_dictionary` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `php_dictionary`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `php_dictionary`.
- ` this % ` is the percentage **of this ipset (`php_dictionary`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level3](#firehol_level3)|109549|9627220|737|0.0%|100.0%|
[php_spammers](#php_spammers)|735|735|322|43.8%|43.6%|
[sorbs_spam](#sorbs_spam)|64701|65536|214|0.3%|29.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|214|0.3%|29.0%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|214|0.3%|29.0%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|139|0.1%|18.8%|
[firehol_level2](#firehol_level2)|20666|32229|121|0.3%|16.4%|
[blocklist_de](#blocklist_de)|26985|26985|114|0.4%|15.4%|
[nixspam](#nixspam)|18198|18198|107|0.5%|14.5%|
[firehol_anonymous](#firehol_anonymous)|19172|83219|98|0.1%|13.2%|
[firehol_proxies](#firehol_proxies)|12734|13010|97|0.7%|13.1%|
[snort_ipfilter](#snort_ipfilter)|9136|9136|95|1.0%|12.8%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|93|0.3%|12.6%|
[blocklist_de_mail](#blocklist_de_mail)|17750|17750|93|0.5%|12.6%|
[ri_web_proxies](#ri_web_proxies)|7952|7952|67|0.8%|9.0%|
[xroxy](#xroxy)|2175|2175|41|1.8%|5.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|39|0.0%|5.2%|
[php_commenters](#php_commenters)|458|458|38|8.2%|5.1%|
[sorbs_web](#sorbs_web)|628|629|34|5.4%|4.6%|
[stopforumspam_1d](#stopforumspam_1d)|6669|6669|30|0.4%|4.0%|
[proxz](#proxz)|1356|1356|25|1.8%|3.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|23|0.0%|3.1%|
[blocklist_de_bots](#blocklist_de_bots)|2972|2972|17|0.5%|2.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|12|0.0%|1.6%|
[alienvault_reputation](#alienvault_reputation)|189146|189146|7|0.0%|0.9%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|6|0.0%|0.8%|
[iw_spamlist](#iw_spamlist)|3648|3648|6|0.1%|0.8%|
[firehol_level1](#firehol_level1)|5070|688854680|6|0.0%|0.8%|
[et_block](#et_block)|1000|18343756|6|0.0%|0.8%|
[ri_connect_proxies](#ri_connect_proxies)|2855|2855|5|0.1%|0.6%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|5|0.9%|0.6%|
[blocklist_de_strongips](#blocklist_de_strongips)|170|170|5|2.9%|0.6%|
[tor_exits](#tor_exits)|1106|1106|4|0.3%|0.5%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|4|0.0%|0.5%|
[et_tor](#et_tor)|6500|6500|4|0.0%|0.5%|
[dm_tor](#dm_tor)|6468|6468|4|0.0%|0.5%|
[bm_tor](#bm_tor)|6471|6471|4|0.0%|0.5%|
[php_harvesters](#php_harvesters)|408|408|3|0.7%|0.4%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|3|0.0%|0.4%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2446|2446|3|0.1%|0.4%|
[blocklist_de_apache](#blocklist_de_apache)|13845|13845|3|0.0%|0.4%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|2|0.3%|0.2%|
[dragon_http](#dragon_http)|1021|268288|2|0.0%|0.2%|
[sorbs_socks](#sorbs_socks)|7|7|1|14.2%|0.1%|
[sorbs_misc](#sorbs_misc)|7|7|1|14.2%|0.1%|
[sorbs_http](#sorbs_http)|7|7|1|14.2%|0.1%|
[proxyrss](#proxyrss)|1570|1570|1|0.0%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.1%|
[blocklist_de_ftp](#blocklist_de_ftp)|1523|1523|1|0.0%|0.1%|

## php_harvesters

[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) harvesters (IPs that surf the internet looking for email addresses) (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=h&rss=1).

The last time downloaded was found to be dated: Fri Jun 12 09:01:23 UTC 2015.

The ipset `php_harvesters` has **408** entries, **408** unique IPs.

The following table shows the overlaps of `php_harvesters` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `php_harvesters`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `php_harvesters`.
- ` this % ` is the percentage **of this ipset (`php_harvesters`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level3](#firehol_level3)|109549|9627220|408|0.0%|100.0%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|87|0.0%|21.3%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|65|0.2%|15.9%|
[firehol_level2](#firehol_level2)|20666|32229|57|0.1%|13.9%|
[stopforumspam_1d](#stopforumspam_1d)|6669|6669|44|0.6%|10.7%|
[blocklist_de](#blocklist_de)|26985|26985|37|0.1%|9.0%|
[blocklist_de_bots](#blocklist_de_bots)|2972|2972|27|0.9%|6.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|20|0.0%|4.9%|
[sorbs_spam](#sorbs_spam)|64701|65536|16|0.0%|3.9%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|16|0.0%|3.9%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|16|0.0%|3.9%|
[php_commenters](#php_commenters)|458|458|15|3.2%|3.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|12|0.0%|2.9%|
[firehol_proxies](#firehol_proxies)|12734|13010|12|0.0%|2.9%|
[firehol_anonymous](#firehol_anonymous)|19172|83219|12|0.0%|2.9%|
[alienvault_reputation](#alienvault_reputation)|189146|189146|12|0.0%|2.9%|
[snort_ipfilter](#snort_ipfilter)|9136|9136|11|0.1%|2.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|9|0.0%|2.2%|
[nixspam](#nixspam)|18198|18198|8|0.0%|1.9%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|7|1.3%|1.7%|
[et_tor](#et_tor)|6500|6500|7|0.1%|1.7%|
[dm_tor](#dm_tor)|6468|6468|7|0.1%|1.7%|
[bm_tor](#bm_tor)|6471|6471|7|0.1%|1.7%|
[tor_exits](#tor_exits)|1106|1106|6|0.5%|1.4%|
[blocklist_de_mail](#blocklist_de_mail)|17750|17750|5|0.0%|1.2%|
[iw_spamlist](#iw_spamlist)|3648|3648|4|0.1%|0.9%|
[php_spammers](#php_spammers)|735|735|3|0.4%|0.7%|
[php_dictionary](#php_dictionary)|737|737|3|0.4%|0.7%|
[firehol_level1](#firehol_level1)|5070|688854680|3|0.0%|0.7%|
[blocklist_de_strongips](#blocklist_de_strongips)|170|170|3|1.7%|0.7%|
[blocklist_de_ftp](#blocklist_de_ftp)|1523|1523|3|0.1%|0.7%|
[xroxy](#xroxy)|2175|2175|2|0.0%|0.4%|
[ri_web_proxies](#ri_web_proxies)|7952|7952|2|0.0%|0.4%|
[openbl_60d](#openbl_60d)|6960|6960|2|0.0%|0.4%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|2|0.0%|0.4%|
[blocklist_de_imap](#blocklist_de_imap)|2726|2726|2|0.0%|0.4%|
[blocklist_de_apache](#blocklist_de_apache)|13845|13845|2|0.0%|0.4%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|1|0.0%|0.2%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|1|0.0%|0.2%|
[sorbs_web](#sorbs_web)|628|629|1|0.1%|0.2%|
[ri_connect_proxies](#ri_connect_proxies)|2855|2855|1|0.0%|0.2%|
[proxyrss](#proxyrss)|1570|1570|1|0.0%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.2%|
[fullbogons](#fullbogons)|3775|670173256|1|0.0%|0.2%|
[et_block](#et_block)|1000|18343756|1|0.0%|0.2%|
[bogons](#bogons)|13|592708608|1|0.0%|0.2%|
[blocklist_de_ssh](#blocklist_de_ssh)|1901|1901|1|0.0%|0.2%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2446|2446|1|0.0%|0.2%|

## php_spammers

[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) spam servers (IPs used by spammers to send messages) (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=s&rss=1).

The last time downloaded was found to be dated: Fri Jun 12 09:01:24 UTC 2015.

The ipset `php_spammers` has **735** entries, **735** unique IPs.

The following table shows the overlaps of `php_spammers` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `php_spammers`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `php_spammers`.
- ` this % ` is the percentage **of this ipset (`php_spammers`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level3](#firehol_level3)|109549|9627220|735|0.0%|100.0%|
[php_dictionary](#php_dictionary)|737|737|322|43.6%|43.8%|
[sorbs_spam](#sorbs_spam)|64701|65536|184|0.2%|25.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|184|0.2%|25.0%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|184|0.2%|25.0%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|151|0.1%|20.5%|
[firehol_level2](#firehol_level2)|20666|32229|115|0.3%|15.6%|
[blocklist_de](#blocklist_de)|26985|26985|105|0.3%|14.2%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|93|0.3%|12.6%|
[nixspam](#nixspam)|18198|18198|92|0.5%|12.5%|
[snort_ipfilter](#snort_ipfilter)|9136|9136|84|0.9%|11.4%|
[firehol_anonymous](#firehol_anonymous)|19172|83219|81|0.0%|11.0%|
[firehol_proxies](#firehol_proxies)|12734|13010|79|0.6%|10.7%|
[blocklist_de_mail](#blocklist_de_mail)|17750|17750|74|0.4%|10.0%|
[ri_web_proxies](#ri_web_proxies)|7952|7952|54|0.6%|7.3%|
[php_commenters](#php_commenters)|458|458|54|11.7%|7.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|54|0.0%|7.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|44|0.0%|5.9%|
[stopforumspam_1d](#stopforumspam_1d)|6669|6669|40|0.5%|5.4%|
[xroxy](#xroxy)|2175|2175|34|1.5%|4.6%|
[sorbs_web](#sorbs_web)|628|629|27|4.2%|3.6%|
[blocklist_de_bots](#blocklist_de_bots)|2972|2972|23|0.7%|3.1%|
[proxz](#proxz)|1356|1356|22|1.6%|2.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|11|0.0%|1.4%|
[blocklist_de_strongips](#blocklist_de_strongips)|170|170|10|5.8%|1.3%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|6|1.1%|0.8%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2446|2446|6|0.2%|0.8%|
[blocklist_de_apache](#blocklist_de_apache)|13845|13845|6|0.0%|0.8%|
[tor_exits](#tor_exits)|1106|1106|5|0.4%|0.6%|
[et_tor](#et_tor)|6500|6500|5|0.0%|0.6%|
[dm_tor](#dm_tor)|6468|6468|5|0.0%|0.6%|
[bm_tor](#bm_tor)|6471|6471|5|0.0%|0.6%|
[alienvault_reputation](#alienvault_reputation)|189146|189146|5|0.0%|0.6%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|4|0.0%|0.5%|
[iw_spamlist](#iw_spamlist)|3648|3648|4|0.1%|0.5%|
[firehol_level1](#firehol_level1)|5070|688854680|4|0.0%|0.5%|
[et_block](#et_block)|1000|18343756|4|0.0%|0.5%|
[ri_connect_proxies](#ri_connect_proxies)|2855|2855|3|0.1%|0.4%|
[php_harvesters](#php_harvesters)|408|408|3|0.7%|0.4%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|0.4%|
[proxyrss](#proxyrss)|1570|1570|1|0.0%|0.1%|
[openbl_7d](#openbl_7d)|629|629|1|0.1%|0.1%|
[openbl_60d](#openbl_60d)|6960|6960|1|0.0%|0.1%|
[openbl_30d](#openbl_30d)|2792|2792|1|0.0%|0.1%|
[openbl_1d](#openbl_1d)|124|124|1|0.8%|0.1%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|1|0.1%|0.1%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|1|0.0%|0.1%|
[et_compromised](#et_compromised)|1704|1704|1|0.0%|0.1%|
[bruteforceblocker](#bruteforceblocker)|1694|1694|1|0.0%|0.1%|
[blocklist_de_ssh](#blocklist_de_ssh)|1901|1901|1|0.0%|0.1%|
[blocklist_de_ftp](#blocklist_de_ftp)|1523|1523|1|0.0%|0.1%|

## proxyrss

[proxyrss.com](http://www.proxyrss.com) open proxies syndicated from multiple sources.

Source is downloaded from [this link](http://www.proxyrss.com/proxylists/all.gz).

The last time downloaded was found to be dated: Fri Jun 12 07:01:25 UTC 2015.

The ipset `proxyrss` has **1570** entries, **1570** unique IPs.

The following table shows the overlaps of `proxyrss` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `proxyrss`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `proxyrss`.
- ` this % ` is the percentage **of this ipset (`proxyrss`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_proxies](#firehol_proxies)|12734|13010|1570|12.0%|100.0%|
[firehol_anonymous](#firehol_anonymous)|19172|83219|1570|1.8%|100.0%|
[firehol_level3](#firehol_level3)|109549|9627220|681|0.0%|43.3%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|680|0.7%|43.3%|
[ri_web_proxies](#ri_web_proxies)|7952|7952|626|7.8%|39.8%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|549|1.8%|34.9%|
[firehol_level2](#firehol_level2)|20666|32229|387|1.2%|24.6%|
[xroxy](#xroxy)|2175|2175|349|16.0%|22.2%|
[stopforumspam_1d](#stopforumspam_1d)|6669|6669|317|4.7%|20.1%|
[proxz](#proxz)|1356|1356|291|21.4%|18.5%|
[blocklist_de_bots](#blocklist_de_bots)|2972|2972|214|7.2%|13.6%|
[blocklist_de](#blocklist_de)|26985|26985|213|0.7%|13.5%|
[ri_connect_proxies](#ri_connect_proxies)|2855|2855|212|7.4%|13.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|55|0.0%|3.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|53|0.0%|3.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|30|0.0%|1.9%|
[nixspam](#nixspam)|18198|18198|10|0.0%|0.6%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|10|1.5%|0.6%|
[blocklist_de_strongips](#blocklist_de_strongips)|170|170|6|3.5%|0.3%|
[php_commenters](#php_commenters)|458|458|5|1.0%|0.3%|
[sorbs_spam](#sorbs_spam)|64701|65536|3|0.0%|0.1%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|3|0.0%|0.1%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|3|0.0%|0.1%|
[dragon_http](#dragon_http)|1021|268288|3|0.0%|0.1%|
[snort_ipfilter](#snort_ipfilter)|9136|9136|2|0.0%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|2|0.0%|0.1%|
[sorbs_web](#sorbs_web)|628|629|1|0.1%|0.0%|
[php_spammers](#php_spammers)|735|735|1|0.1%|0.0%|
[php_harvesters](#php_harvesters)|408|408|1|0.2%|0.0%|
[php_dictionary](#php_dictionary)|737|737|1|0.1%|0.0%|
[et_tor](#et_tor)|6500|6500|1|0.0%|0.0%|
[et_compromised](#et_compromised)|1704|1704|1|0.0%|0.0%|
[dm_tor](#dm_tor)|6468|6468|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1694|1694|1|0.0%|0.0%|
[bm_tor](#bm_tor)|6471|6471|1|0.0%|0.0%|
[alienvault_reputation](#alienvault_reputation)|189146|189146|1|0.0%|0.0%|

## proxz

[proxz.com](http://www.proxz.com) open proxies (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.proxz.com/proxylists.xml).

The last time downloaded was found to be dated: Fri Jun 12 07:01:30 UTC 2015.

The ipset `proxz` has **1356** entries, **1356** unique IPs.

The following table shows the overlaps of `proxz` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `proxz`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `proxz`.
- ` this % ` is the percentage **of this ipset (`proxz`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_proxies](#firehol_proxies)|12734|13010|1356|10.4%|100.0%|
[firehol_anonymous](#firehol_anonymous)|19172|83219|1356|1.6%|100.0%|
[firehol_level3](#firehol_level3)|109549|9627220|800|0.0%|58.9%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|794|0.8%|58.5%|
[ri_web_proxies](#ri_web_proxies)|7952|7952|619|7.7%|45.6%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|507|1.7%|37.3%|
[xroxy](#xroxy)|2175|2175|468|21.5%|34.5%|
[proxyrss](#proxyrss)|1570|1570|291|18.5%|21.4%|
[firehol_level2](#firehol_level2)|20666|32229|270|0.8%|19.9%|
[ri_connect_proxies](#ri_connect_proxies)|2855|2855|234|8.1%|17.2%|
[blocklist_de](#blocklist_de)|26985|26985|198|0.7%|14.6%|
[stopforumspam_1d](#stopforumspam_1d)|6669|6669|174|2.6%|12.8%|
[blocklist_de_bots](#blocklist_de_bots)|2972|2972|168|5.6%|12.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|106|0.0%|7.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|56|0.0%|4.1%|
[nixspam](#nixspam)|18198|18198|48|0.2%|3.5%|
[sorbs_spam](#sorbs_spam)|64701|65536|44|0.0%|3.2%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|44|0.0%|3.2%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|44|0.0%|3.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|44|0.0%|3.2%|
[blocklist_de_mail](#blocklist_de_mail)|17750|17750|30|0.1%|2.2%|
[snort_ipfilter](#snort_ipfilter)|9136|9136|29|0.3%|2.1%|
[php_dictionary](#php_dictionary)|737|737|25|3.3%|1.8%|
[php_spammers](#php_spammers)|735|735|22|2.9%|1.6%|
[php_commenters](#php_commenters)|458|458|10|2.1%|0.7%|
[sorbs_web](#sorbs_web)|628|629|8|1.2%|0.5%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|7|1.0%|0.5%|
[blocklist_de_strongips](#blocklist_de_strongips)|170|170|6|3.5%|0.4%|
[dragon_http](#dragon_http)|1021|268288|4|0.0%|0.2%|
[alienvault_reputation](#alienvault_reputation)|189146|189146|3|0.0%|0.2%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|2|0.3%|0.1%|
[et_compromised](#et_compromised)|1704|1704|2|0.1%|0.1%|
[bruteforceblocker](#bruteforceblocker)|1694|1694|2|0.1%|0.1%|
[iw_spamlist](#iw_spamlist)|3648|3648|1|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|1|0.0%|0.0%|
[et_block](#et_block)|1000|18343756|1|0.0%|0.0%|

## ri_connect_proxies

[rosinstrument.com](http://www.rosinstrument.com) open CONNECT proxies (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://tools.rosinstrument.com/proxy/plab100.xml).

The last time downloaded was found to be dated: Fri Jun 12 04:09:40 UTC 2015.

The ipset `ri_connect_proxies` has **2855** entries, **2855** unique IPs.

The following table shows the overlaps of `ri_connect_proxies` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ri_connect_proxies`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ri_connect_proxies`.
- ` this % ` is the percentage **of this ipset (`ri_connect_proxies`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_proxies](#firehol_proxies)|12734|13010|2855|21.9%|100.0%|
[firehol_anonymous](#firehol_anonymous)|19172|83219|2855|3.4%|100.0%|
[firehol_level3](#firehol_level3)|109549|9627220|1592|0.0%|55.7%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|1591|1.6%|55.7%|
[ri_web_proxies](#ri_web_proxies)|7952|7952|1213|15.2%|42.4%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|531|1.8%|18.5%|
[xroxy](#xroxy)|2175|2175|396|18.2%|13.8%|
[proxz](#proxz)|1356|1356|234|17.2%|8.1%|
[proxyrss](#proxyrss)|1570|1570|212|13.5%|7.4%|
[firehol_level2](#firehol_level2)|20666|32229|148|0.4%|5.1%|
[stopforumspam_1d](#stopforumspam_1d)|6669|6669|108|1.6%|3.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|106|0.0%|3.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|86|0.0%|3.0%|
[blocklist_de](#blocklist_de)|26985|26985|68|0.2%|2.3%|
[blocklist_de_bots](#blocklist_de_bots)|2972|2972|64|2.1%|2.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|57|0.0%|1.9%|
[sorbs_spam](#sorbs_spam)|64701|65536|18|0.0%|0.6%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|18|0.0%|0.6%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|18|0.0%|0.6%|
[nixspam](#nixspam)|18198|18198|18|0.0%|0.6%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|7|1.0%|0.2%|
[snort_ipfilter](#snort_ipfilter)|9136|9136|6|0.0%|0.2%|
[php_commenters](#php_commenters)|458|458|6|1.3%|0.2%|
[php_dictionary](#php_dictionary)|737|737|5|0.6%|0.1%|
[dragon_http](#dragon_http)|1021|268288|4|0.0%|0.1%|
[php_spammers](#php_spammers)|735|735|3|0.4%|0.1%|
[blocklist_de_mail](#blocklist_de_mail)|17750|17750|3|0.0%|0.1%|
[alienvault_reputation](#alienvault_reputation)|189146|189146|3|0.0%|0.1%|
[iw_spamlist](#iw_spamlist)|3648|3648|2|0.0%|0.0%|
[sorbs_web](#sorbs_web)|628|629|1|0.1%|0.0%|
[php_harvesters](#php_harvesters)|408|408|1|0.2%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|1|0.1%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.0%|
[et_tor](#et_tor)|6500|6500|1|0.0%|0.0%|
[dm_tor](#dm_tor)|6468|6468|1|0.0%|0.0%|
[bm_tor](#bm_tor)|6471|6471|1|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13845|13845|1|0.0%|0.0%|

## ri_web_proxies

[rosinstrument.com](http://www.rosinstrument.com) open HTTP proxies (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://tools.rosinstrument.com/proxy/l100.xml).

The last time downloaded was found to be dated: Fri Jun 12 06:23:55 UTC 2015.

The ipset `ri_web_proxies` has **7952** entries, **7952** unique IPs.

The following table shows the overlaps of `ri_web_proxies` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ri_web_proxies`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ri_web_proxies`.
- ` this % ` is the percentage **of this ipset (`ri_web_proxies`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_proxies](#firehol_proxies)|12734|13010|7952|61.1%|100.0%|
[firehol_anonymous](#firehol_anonymous)|19172|83219|7952|9.5%|100.0%|
[firehol_level3](#firehol_level3)|109549|9627220|3755|0.0%|47.2%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|3712|3.9%|46.6%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|1487|5.1%|18.6%|
[ri_connect_proxies](#ri_connect_proxies)|2855|2855|1213|42.4%|15.2%|
[xroxy](#xroxy)|2175|2175|965|44.3%|12.1%|
[firehol_level2](#firehol_level2)|20666|32229|664|2.0%|8.3%|
[proxyrss](#proxyrss)|1570|1570|626|39.8%|7.8%|
[proxz](#proxz)|1356|1356|619|45.6%|7.7%|
[blocklist_de](#blocklist_de)|26985|26985|471|1.7%|5.9%|
[stopforumspam_1d](#stopforumspam_1d)|6669|6669|421|6.3%|5.2%|
[blocklist_de_bots](#blocklist_de_bots)|2972|2972|382|12.8%|4.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|225|0.0%|2.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|221|0.0%|2.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|156|0.0%|1.9%|
[sorbs_spam](#sorbs_spam)|64701|65536|145|0.2%|1.8%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|145|0.2%|1.8%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|145|0.2%|1.8%|
[nixspam](#nixspam)|18198|18198|97|0.5%|1.2%|
[blocklist_de_mail](#blocklist_de_mail)|17750|17750|87|0.4%|1.0%|
[php_dictionary](#php_dictionary)|737|737|67|9.0%|0.8%|
[snort_ipfilter](#snort_ipfilter)|9136|9136|63|0.6%|0.7%|
[php_spammers](#php_spammers)|735|735|54|7.3%|0.6%|
[php_commenters](#php_commenters)|458|458|30|6.5%|0.3%|
[sorbs_web](#sorbs_web)|628|629|22|3.4%|0.2%|
[dragon_http](#dragon_http)|1021|268288|20|0.0%|0.2%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|15|2.2%|0.1%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|10|1.9%|0.1%|
[blocklist_de_strongips](#blocklist_de_strongips)|170|170|8|4.7%|0.1%|
[iw_spamlist](#iw_spamlist)|3648|3648|6|0.1%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|6|0.0%|0.0%|
[et_tor](#et_tor)|6500|6500|5|0.0%|0.0%|
[dm_tor](#dm_tor)|6468|6468|5|0.0%|0.0%|
[bm_tor](#bm_tor)|6471|6471|5|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|4|0.0%|0.0%|
[alienvault_reputation](#alienvault_reputation)|189146|189146|4|0.0%|0.0%|
[php_harvesters](#php_harvesters)|408|408|2|0.4%|0.0%|
[sslbl](#sslbl)|370|370|1|0.2%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|1|0.0%|0.0%|
[firehol_level1](#firehol_level1)|5070|688854680|1|0.0%|0.0%|
[et_compromised](#et_compromised)|1704|1704|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1694|1694|1|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1901|1901|1|0.0%|0.0%|

## shunlist

[AutoShun.org](http://autoshun.org/) IPs identified as hostile by correlating logs from distributed snort installations running the autoshun plugin

Source is downloaded from [this link](http://www.autoshun.org/files/shunlist.csv).

The last time downloaded was found to be dated: Fri Jun 12 07:30:03 UTC 2015.

The ipset `shunlist` has **1185** entries, **1185** unique IPs.

The following table shows the overlaps of `shunlist` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `shunlist`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `shunlist`.
- ` this % ` is the percentage **of this ipset (`shunlist`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level3](#firehol_level3)|109549|9627220|1185|0.0%|100.0%|
[alienvault_reputation](#alienvault_reputation)|189146|189146|1165|0.6%|98.3%|
[openbl_60d](#openbl_60d)|6960|6960|464|6.6%|39.1%|
[openbl_30d](#openbl_30d)|2792|2792|439|15.7%|37.0%|
[dragon_sshpauth](#dragon_sshpauth)|1589|1653|380|22.9%|32.0%|
[firehol_level2](#firehol_level2)|20666|32229|353|1.0%|29.7%|
[blocklist_de](#blocklist_de)|26985|26985|348|1.2%|29.3%|
[bruteforceblocker](#bruteforceblocker)|1694|1694|342|20.1%|28.8%|
[et_compromised](#et_compromised)|1704|1704|341|20.0%|28.7%|
[blocklist_de_ssh](#blocklist_de_ssh)|1901|1901|306|16.0%|25.8%|
[openbl_7d](#openbl_7d)|629|629|207|32.9%|17.4%|
[firehol_level1](#firehol_level1)|5070|688854680|159|0.0%|13.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|120|0.0%|10.1%|
[et_block](#et_block)|1000|18343756|101|0.0%|8.5%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|90|0.0%|7.5%|
[dshield](#dshield)|20|5120|83|1.6%|7.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|70|0.0%|5.9%|
[openbl_1d](#openbl_1d)|124|124|66|53.2%|5.5%|
[sslbl](#sslbl)|370|370|58|15.6%|4.8%|
[blocklist_de_apache](#blocklist_de_apache)|13845|13845|37|0.2%|3.1%|
[ciarmy](#ciarmy)|416|416|29|6.9%|2.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|26|0.0%|2.1%|
[dragon_http](#dragon_http)|1021|268288|26|0.0%|2.1%|
[blocklist_de_strongips](#blocklist_de_strongips)|170|170|19|11.1%|1.6%|
[voipbl](#voipbl)|10586|10998|14|0.1%|1.1%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|4|0.0%|0.3%|
[blocklist_de_mail](#blocklist_de_mail)|17750|17750|3|0.0%|0.2%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|2|0.0%|0.1%|
[stopforumspam_1d](#stopforumspam_1d)|6669|6669|2|0.0%|0.1%|
[sorbs_spam](#sorbs_spam)|64701|65536|2|0.0%|0.1%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|2|0.0%|0.1%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|2|0.0%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2|0.0%|0.1%|
[dragon_vncprobe](#dragon_vncprobe)|87|87|2|2.2%|0.1%|
[blocklist_de_sip](#blocklist_de_sip)|83|83|2|2.4%|0.1%|
[blocklist_de_imap](#blocklist_de_imap)|2726|2726|2|0.0%|0.1%|
[tor_exits](#tor_exits)|1106|1106|1|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9136|9136|1|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|1|0.1%|0.0%|
[firehol_proxies](#firehol_proxies)|12734|13010|1|0.0%|0.0%|
[firehol_anonymous](#firehol_anonymous)|19172|83219|1|0.0%|0.0%|
[et_tor](#et_tor)|6500|6500|1|0.0%|0.0%|
[dm_tor](#dm_tor)|6468|6468|1|0.0%|0.0%|
[bm_tor](#bm_tor)|6471|6471|1|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2446|2446|1|0.0%|0.0%|

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
[firehol_level3](#firehol_level3)|109549|9627220|9136|0.0%|100.0%|
[firehol_anonymous](#firehol_anonymous)|19172|83219|1224|1.4%|13.3%|
[et_tor](#et_tor)|6500|6500|1088|16.7%|11.9%|
[tor_exits](#tor_exits)|1106|1106|1067|96.4%|11.6%|
[bm_tor](#bm_tor)|6471|6471|1050|16.2%|11.4%|
[dm_tor](#dm_tor)|6468|6468|1049|16.2%|11.4%|
[sorbs_spam](#sorbs_spam)|64701|65536|816|1.2%|8.9%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|814|1.2%|8.9%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|814|1.2%|8.9%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|804|0.8%|8.8%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|667|2.2%|7.3%|
[firehol_level2](#firehol_level2)|20666|32229|526|1.6%|5.7%|
[stopforumspam_1d](#stopforumspam_1d)|6669|6669|353|5.2%|3.8%|
[firehol_proxies](#firehol_proxies)|12734|13010|327|2.5%|3.5%|
[et_block](#et_block)|1000|18343756|297|0.0%|3.2%|
[firehol_level1](#firehol_level1)|5070|688854680|248|0.0%|2.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|240|0.0%|2.6%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|237|45.2%|2.5%|
[blocklist_de](#blocklist_de)|26985|26985|205|0.7%|2.2%|
[zeus](#zeus)|230|230|200|86.9%|2.1%|
[nixspam](#nixspam)|18198|18198|191|1.0%|2.0%|
[zeus_badips](#zeus_badips)|202|202|178|88.1%|1.9%|
[blocklist_de_mail](#blocklist_de_mail)|17750|17750|157|0.8%|1.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|141|0.0%|1.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|114|0.0%|1.2%|
[alienvault_reputation](#alienvault_reputation)|189146|189146|107|0.0%|1.1%|
[php_dictionary](#php_dictionary)|737|737|95|12.8%|1.0%|
[php_spammers](#php_spammers)|735|735|84|11.4%|0.9%|
[php_commenters](#php_commenters)|458|458|71|15.5%|0.7%|
[ri_web_proxies](#ri_web_proxies)|7952|7952|63|0.7%|0.6%|
[sorbs_web](#sorbs_web)|628|629|56|8.9%|0.6%|
[iw_spamlist](#iw_spamlist)|3648|3648|48|1.3%|0.5%|
[xroxy](#xroxy)|2175|2175|42|1.9%|0.4%|
[sslbl](#sslbl)|370|370|31|8.3%|0.3%|
[blocklist_de_apache](#blocklist_de_apache)|13845|13845|30|0.2%|0.3%|
[proxz](#proxz)|1356|1356|29|2.1%|0.3%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2446|2446|28|1.1%|0.3%|
[openbl_60d](#openbl_60d)|6960|6960|24|0.3%|0.2%|
[blocklist_de_bots](#blocklist_de_bots)|2972|2972|20|0.6%|0.2%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|18|0.0%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|14|0.0%|0.1%|
[php_harvesters](#php_harvesters)|408|408|11|2.6%|0.1%|
[palevo](#palevo)|13|13|11|84.6%|0.1%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|11|0.8%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|11|0.0%|0.1%|
[dragon_http](#dragon_http)|1021|268288|11|0.0%|0.1%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|6|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2855|2855|6|0.2%|0.0%|
[sorbs_socks](#sorbs_socks)|7|7|4|57.1%|0.0%|
[sorbs_misc](#sorbs_misc)|7|7|4|57.1%|0.0%|
[sorbs_http](#sorbs_http)|7|7|4|57.1%|0.0%|
[proxyrss](#proxyrss)|1570|1570|2|0.1%|0.0%|
[openbl_30d](#openbl_30d)|2792|2792|2|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|2|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|170|170|2|1.1%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2726|2726|2|0.0%|0.0%|
[shunlist](#shunlist)|1185|1185|1|0.0%|0.0%|
[openbl_7d](#openbl_7d)|629|629|1|0.1%|0.0%|
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
[firehol_level3](#firehol_level3)|109549|9627220|4|0.0%|57.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|2|0.0%|28.5%|
[php_dictionary](#php_dictionary)|737|737|1|0.1%|14.2%|
[iw_spamlist](#iw_spamlist)|3648|3648|1|0.0%|14.2%|
[firehol_level2](#firehol_level2)|20666|32229|1|0.0%|14.2%|
[blocklist_de_mail](#blocklist_de_mail)|17750|17750|1|0.0%|14.2%|
[blocklist_de](#blocklist_de)|26985|26985|1|0.0%|14.2%|

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
[firehol_level3](#firehol_level3)|109549|9627220|4|0.0%|57.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|2|0.0%|28.5%|
[php_dictionary](#php_dictionary)|737|737|1|0.1%|14.2%|
[iw_spamlist](#iw_spamlist)|3648|3648|1|0.0%|14.2%|
[firehol_level2](#firehol_level2)|20666|32229|1|0.0%|14.2%|
[blocklist_de_mail](#blocklist_de_mail)|17750|17750|1|0.0%|14.2%|
[blocklist_de](#blocklist_de)|26985|26985|1|0.0%|14.2%|

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
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|1736|0.0%|2.6%|
[nixspam](#nixspam)|18198|18198|1367|7.5%|2.0%|
[firehol_level3](#firehol_level3)|109549|9627220|1223|0.0%|1.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|1205|0.0%|1.8%|
[firehol_level2](#firehol_level2)|20666|32229|987|3.0%|1.5%|
[blocklist_de](#blocklist_de)|26985|26985|975|3.6%|1.4%|
[iw_spamlist](#iw_spamlist)|3648|3648|950|26.0%|1.4%|
[blocklist_de_mail](#blocklist_de_mail)|17750|17750|909|5.1%|1.3%|
[snort_ipfilter](#snort_ipfilter)|9136|9136|814|8.9%|1.2%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|320|0.3%|0.4%|
[sorbs_web](#sorbs_web)|628|629|303|48.1%|0.4%|
[php_dictionary](#php_dictionary)|737|737|214|29.0%|0.3%|
[firehol_anonymous](#firehol_anonymous)|19172|83219|201|0.2%|0.3%|
[firehol_proxies](#firehol_proxies)|12734|13010|196|1.5%|0.3%|
[php_spammers](#php_spammers)|735|735|184|25.0%|0.2%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|173|0.5%|0.2%|
[ri_web_proxies](#ri_web_proxies)|7952|7952|145|1.8%|0.2%|
[alienvault_reputation](#alienvault_reputation)|189146|189146|91|0.0%|0.1%|
[xroxy](#xroxy)|2175|2175|76|3.4%|0.1%|
[dragon_http](#dragon_http)|1021|268288|71|0.0%|0.1%|
[stopforumspam_1d](#stopforumspam_1d)|6669|6669|45|0.6%|0.0%|
[proxz](#proxz)|1356|1356|44|3.2%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2446|2446|44|1.7%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13845|13845|44|0.3%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|37|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|2972|2972|28|0.9%|0.0%|
[php_commenters](#php_commenters)|458|458|27|5.8%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2726|2726|26|0.9%|0.0%|
[firehol_level1](#firehol_level1)|5070|688854680|25|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|20|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|20|0.0%|0.0%|
[et_block](#et_block)|1000|18343756|20|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2855|2855|18|0.6%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|17|0.0%|0.0%|
[php_harvesters](#php_harvesters)|408|408|16|3.9%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|1523|1523|15|0.9%|0.0%|
[sorbs_socks](#sorbs_socks)|7|7|7|100.0%|0.0%|
[sorbs_misc](#sorbs_misc)|7|7|7|100.0%|0.0%|
[sorbs_http](#sorbs_http)|7|7|7|100.0%|0.0%|
[sorbs_smtp](#sorbs_smtp)|6|6|6|100.0%|0.0%|
[tor_exits](#tor_exits)|1106|1106|5|0.4%|0.0%|
[et_tor](#et_tor)|6500|6500|4|0.0%|0.0%|
[dm_tor](#dm_tor)|6468|6468|4|0.0%|0.0%|
[bm_tor](#bm_tor)|6471|6471|4|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1901|1901|4|0.2%|0.0%|
[voipbl](#voipbl)|10586|10998|3|0.0%|0.0%|
[proxyrss](#proxyrss)|1570|1570|3|0.1%|0.0%|
[et_compromised](#et_compromised)|1704|1704|3|0.1%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1694|1694|3|0.1%|0.0%|
[shunlist](#shunlist)|1185|1185|2|0.1%|0.0%|
[openbl_60d](#openbl_60d)|6960|6960|2|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|2|0.1%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|170|170|2|1.1%|0.0%|
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
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|1736|0.0%|2.6%|
[nixspam](#nixspam)|18198|18198|1367|7.5%|2.0%|
[firehol_level3](#firehol_level3)|109549|9627220|1223|0.0%|1.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|1205|0.0%|1.8%|
[firehol_level2](#firehol_level2)|20666|32229|987|3.0%|1.5%|
[blocklist_de](#blocklist_de)|26985|26985|975|3.6%|1.4%|
[iw_spamlist](#iw_spamlist)|3648|3648|950|26.0%|1.4%|
[blocklist_de_mail](#blocklist_de_mail)|17750|17750|909|5.1%|1.3%|
[snort_ipfilter](#snort_ipfilter)|9136|9136|814|8.9%|1.2%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|320|0.3%|0.4%|
[sorbs_web](#sorbs_web)|628|629|303|48.1%|0.4%|
[php_dictionary](#php_dictionary)|737|737|214|29.0%|0.3%|
[firehol_anonymous](#firehol_anonymous)|19172|83219|201|0.2%|0.3%|
[firehol_proxies](#firehol_proxies)|12734|13010|196|1.5%|0.3%|
[php_spammers](#php_spammers)|735|735|184|25.0%|0.2%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|173|0.5%|0.2%|
[ri_web_proxies](#ri_web_proxies)|7952|7952|145|1.8%|0.2%|
[alienvault_reputation](#alienvault_reputation)|189146|189146|91|0.0%|0.1%|
[xroxy](#xroxy)|2175|2175|76|3.4%|0.1%|
[dragon_http](#dragon_http)|1021|268288|71|0.0%|0.1%|
[stopforumspam_1d](#stopforumspam_1d)|6669|6669|45|0.6%|0.0%|
[proxz](#proxz)|1356|1356|44|3.2%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2446|2446|44|1.7%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13845|13845|44|0.3%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|37|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|2972|2972|28|0.9%|0.0%|
[php_commenters](#php_commenters)|458|458|27|5.8%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2726|2726|26|0.9%|0.0%|
[firehol_level1](#firehol_level1)|5070|688854680|25|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|20|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|20|0.0%|0.0%|
[et_block](#et_block)|1000|18343756|20|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2855|2855|18|0.6%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|17|0.0%|0.0%|
[php_harvesters](#php_harvesters)|408|408|16|3.9%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|1523|1523|15|0.9%|0.0%|
[sorbs_socks](#sorbs_socks)|7|7|7|100.0%|0.0%|
[sorbs_misc](#sorbs_misc)|7|7|7|100.0%|0.0%|
[sorbs_http](#sorbs_http)|7|7|7|100.0%|0.0%|
[sorbs_smtp](#sorbs_smtp)|6|6|6|100.0%|0.0%|
[tor_exits](#tor_exits)|1106|1106|5|0.4%|0.0%|
[et_tor](#et_tor)|6500|6500|4|0.0%|0.0%|
[dm_tor](#dm_tor)|6468|6468|4|0.0%|0.0%|
[bm_tor](#bm_tor)|6471|6471|4|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1901|1901|4|0.2%|0.0%|
[voipbl](#voipbl)|10586|10998|3|0.0%|0.0%|
[proxyrss](#proxyrss)|1570|1570|3|0.1%|0.0%|
[et_compromised](#et_compromised)|1704|1704|3|0.1%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1694|1694|3|0.1%|0.0%|
[shunlist](#shunlist)|1185|1185|2|0.1%|0.0%|
[openbl_60d](#openbl_60d)|6960|6960|2|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|2|0.1%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|170|170|2|1.1%|0.0%|
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
[firehol_level3](#firehol_level3)|109549|9627220|4|0.0%|57.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|2|0.0%|28.5%|
[php_dictionary](#php_dictionary)|737|737|1|0.1%|14.2%|
[iw_spamlist](#iw_spamlist)|3648|3648|1|0.0%|14.2%|
[firehol_level2](#firehol_level2)|20666|32229|1|0.0%|14.2%|
[blocklist_de_mail](#blocklist_de_mail)|17750|17750|1|0.0%|14.2%|
[blocklist_de](#blocklist_de)|26985|26985|1|0.0%|14.2%|

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
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|1740|0.0%|2.6%|
[nixspam](#nixspam)|18198|18198|1377|7.5%|2.1%|
[firehol_level3](#firehol_level3)|109549|9627220|1227|0.0%|1.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|1208|0.0%|1.8%|
[firehol_level2](#firehol_level2)|20666|32229|995|3.0%|1.5%|
[blocklist_de](#blocklist_de)|26985|26985|983|3.6%|1.4%|
[iw_spamlist](#iw_spamlist)|3648|3648|955|26.1%|1.4%|
[blocklist_de_mail](#blocklist_de_mail)|17750|17750|917|5.1%|1.3%|
[snort_ipfilter](#snort_ipfilter)|9136|9136|816|8.9%|1.2%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|320|0.3%|0.4%|
[sorbs_web](#sorbs_web)|628|629|304|48.3%|0.4%|
[php_dictionary](#php_dictionary)|737|737|214|29.0%|0.3%|
[firehol_anonymous](#firehol_anonymous)|19172|83219|201|0.2%|0.3%|
[firehol_proxies](#firehol_proxies)|12734|13010|196|1.5%|0.2%|
[php_spammers](#php_spammers)|735|735|184|25.0%|0.2%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|173|0.5%|0.2%|
[ri_web_proxies](#ri_web_proxies)|7952|7952|145|1.8%|0.2%|
[alienvault_reputation](#alienvault_reputation)|189146|189146|91|0.0%|0.1%|
[xroxy](#xroxy)|2175|2175|76|3.4%|0.1%|
[dragon_http](#dragon_http)|1021|268288|72|0.0%|0.1%|
[stopforumspam_1d](#stopforumspam_1d)|6669|6669|45|0.6%|0.0%|
[proxz](#proxz)|1356|1356|44|3.2%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2446|2446|44|1.7%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13845|13845|44|0.3%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|38|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|2972|2972|28|0.9%|0.0%|
[php_commenters](#php_commenters)|458|458|27|5.8%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2726|2726|27|0.9%|0.0%|
[firehol_level1](#firehol_level1)|5070|688854680|25|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|20|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|20|0.0%|0.0%|
[et_block](#et_block)|1000|18343756|20|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2855|2855|18|0.6%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|17|0.0%|0.0%|
[php_harvesters](#php_harvesters)|408|408|16|3.9%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|1523|1523|15|0.9%|0.0%|
[sorbs_socks](#sorbs_socks)|7|7|7|100.0%|0.0%|
[sorbs_misc](#sorbs_misc)|7|7|7|100.0%|0.0%|
[sorbs_http](#sorbs_http)|7|7|7|100.0%|0.0%|
[tor_exits](#tor_exits)|1106|1106|5|0.4%|0.0%|
[sorbs_smtp](#sorbs_smtp)|6|6|5|83.3%|0.0%|
[et_tor](#et_tor)|6500|6500|4|0.0%|0.0%|
[dm_tor](#dm_tor)|6468|6468|4|0.0%|0.0%|
[bm_tor](#bm_tor)|6471|6471|4|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1901|1901|4|0.2%|0.0%|
[voipbl](#voipbl)|10586|10998|3|0.0%|0.0%|
[proxyrss](#proxyrss)|1570|1570|3|0.1%|0.0%|
[et_compromised](#et_compromised)|1704|1704|3|0.1%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1694|1694|3|0.1%|0.0%|
[shunlist](#shunlist)|1185|1185|2|0.1%|0.0%|
[openbl_60d](#openbl_60d)|6960|6960|2|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|2|0.1%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|170|170|2|1.1%|0.0%|
[virbl](#virbl)|22|22|1|4.5%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|1|0.1%|0.0%|
[malc0de](#malc0de)|276|276|1|0.3%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|1|0.1%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.0%|
[dragon_sshpauth](#dragon_sshpauth)|1589|1653|1|0.0%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|511|511|1|0.1%|0.0%|

## sorbs_web

[Sorbs.net](https://www.sorbs.net/) WEB exploits, extracted from deltas.

Source is downloaded from [this link]().

The last time downloaded was found to be dated: Fri Jun 12 09:04:04 UTC 2015.

The ipset `sorbs_web` has **628** entries, **629** unique IPs.

The following table shows the overlaps of `sorbs_web` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `sorbs_web`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `sorbs_web`.
- ` this % ` is the percentage **of this ipset (`sorbs_web`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[sorbs_spam](#sorbs_spam)|64701|65536|304|0.4%|48.3%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|303|0.4%|48.1%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|303|0.4%|48.1%|
[nixspam](#nixspam)|18198|18198|88|0.4%|13.9%|
[firehol_level3](#firehol_level3)|109549|9627220|74|0.0%|11.7%|
[firehol_level2](#firehol_level2)|20666|32229|71|0.2%|11.2%|
[blocklist_de](#blocklist_de)|26985|26985|71|0.2%|11.2%|
[blocklist_de_mail](#blocklist_de_mail)|17750|17750|64|0.3%|10.1%|
[snort_ipfilter](#snort_ipfilter)|9136|9136|56|0.6%|8.9%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|48|0.0%|7.6%|
[php_dictionary](#php_dictionary)|737|737|34|4.6%|5.4%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|32|0.1%|5.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|32|0.0%|5.0%|
[firehol_proxies](#firehol_proxies)|12734|13010|31|0.2%|4.9%|
[firehol_anonymous](#firehol_anonymous)|19172|83219|31|0.0%|4.9%|
[php_spammers](#php_spammers)|735|735|27|3.6%|4.2%|
[iw_spamlist](#iw_spamlist)|3648|3648|23|0.6%|3.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|23|0.0%|3.6%|
[ri_web_proxies](#ri_web_proxies)|7952|7952|22|0.2%|3.4%|
[xroxy](#xroxy)|2175|2175|16|0.7%|2.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|16|0.0%|2.5%|
[proxz](#proxz)|1356|1356|8|0.5%|1.2%|
[stopforumspam_1d](#stopforumspam_1d)|6669|6669|6|0.0%|0.9%|
[blocklist_de_bots](#blocklist_de_bots)|2972|2972|6|0.2%|0.9%|
[php_commenters](#php_commenters)|458|458|4|0.8%|0.6%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|2|0.0%|0.3%|
[blocklist_de_strongips](#blocklist_de_strongips)|170|170|2|1.1%|0.3%|
[ri_connect_proxies](#ri_connect_proxies)|2855|2855|1|0.0%|0.1%|
[proxyrss](#proxyrss)|1570|1570|1|0.0%|0.1%|
[php_harvesters](#php_harvesters)|408|408|1|0.2%|0.1%|
[dragon_http](#dragon_http)|1021|268288|1|0.0%|0.1%|
[blocklist_de_ftp](#blocklist_de_ftp)|1523|1523|1|0.0%|0.1%|
[alienvault_reputation](#alienvault_reputation)|189146|189146|1|0.0%|0.1%|

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
[firehol_level1](#firehol_level1)|5070|688854680|18340608|2.6%|100.0%|
[et_block](#et_block)|1000|18343756|18338560|99.9%|99.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|8532506|2.4%|46.5%|
[firehol_level3](#firehol_level3)|109549|9627220|6933039|72.0%|37.8%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|6932480|75.5%|37.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|2272265|0.2%|12.3%|
[fullbogons](#fullbogons)|3775|670173256|151552|0.0%|0.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|130368|0.0%|0.7%|
[alienvault_reputation](#alienvault_reputation)|189146|189146|1385|0.7%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1037|0.3%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|1014|1.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|512|0.1%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|269|0.9%|0.0%|
[dshield](#dshield)|20|5120|256|5.0%|0.0%|
[dragon_http](#dragon_http)|1021|268288|256|0.0%|0.0%|
[firehol_level2](#firehol_level2)|20666|32229|245|0.7%|0.0%|
[openbl_60d](#openbl_60d)|6960|6960|235|3.3%|0.0%|
[blocklist_de](#blocklist_de)|26985|26985|183|0.6%|0.0%|
[openbl_30d](#openbl_30d)|2792|2792|119|4.2%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1901|1901|106|5.5%|0.0%|
[dragon_sshpauth](#dragon_sshpauth)|1589|1653|99|5.9%|0.0%|
[shunlist](#shunlist)|1185|1185|90|7.5%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6669|6669|74|1.1%|0.0%|
[et_compromised](#et_compromised)|1704|1704|65|3.8%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1694|1694|61|3.6%|0.0%|
[openbl_7d](#openbl_7d)|629|629|53|8.4%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|2972|2972|49|1.6%|0.0%|
[php_commenters](#php_commenters)|458|458|29|6.3%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|29|2.2%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|17750|17750|22|0.1%|0.0%|
[nixspam](#nixspam)|18198|18198|21|0.1%|0.0%|
[sorbs_spam](#sorbs_spam)|64701|65536|20|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|20|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|20|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9136|9136|18|0.1%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2726|2726|16|0.5%|0.0%|
[zeus_badips](#zeus_badips)|202|202|15|7.4%|0.0%|
[zeus](#zeus)|230|230|15|6.5%|0.0%|
[voipbl](#voipbl)|10586|10998|14|0.1%|0.0%|
[openbl_1d](#openbl_1d)|124|124|9|7.2%|0.0%|
[php_dictionary](#php_dictionary)|737|737|6|0.8%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|6|0.4%|0.0%|
[firehol_anonymous](#firehol_anonymous)|19172|83219|6|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|170|170|6|3.5%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|5|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2446|2446|5|0.2%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13845|13845|5|0.0%|0.0%|
[php_spammers](#php_spammers)|735|735|4|0.5%|0.0%|
[nt_malware_http](#nt_malware_http)|69|69|4|5.7%|0.0%|
[malc0de](#malc0de)|276|276|4|1.4%|0.0%|
[nt_malware_irc](#nt_malware_irc)|43|43|3|6.9%|0.0%|
[iw_spamlist](#iw_spamlist)|3648|3648|3|0.0%|0.0%|
[firehol_proxies](#firehol_proxies)|12734|13010|3|0.0%|0.0%|
[et_tor](#et_tor)|6500|6500|3|0.0%|0.0%|
[dm_tor](#dm_tor)|6468|6468|3|0.0%|0.0%|
[bm_tor](#bm_tor)|6471|6471|3|0.0%|0.0%|
[tor_exits](#tor_exits)|1106|1106|2|0.1%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|2|0.3%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|83|83|2|2.4%|0.0%|
[virbl](#virbl)|22|22|1|4.5%|0.0%|
[sslbl](#sslbl)|370|370|1|0.2%|0.0%|
[php_harvesters](#php_harvesters)|408|408|1|0.2%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|1|0.1%|0.0%|
[et_botcc](#et_botcc)|505|505|1|0.1%|0.0%|
[dragon_vncprobe](#dragon_vncprobe)|87|87|1|1.1%|0.0%|

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
[firehol_level1](#firehol_level1)|5070|688854680|487424|0.0%|100.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|270785|0.1%|55.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|98904|0.0%|20.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|33155|0.0%|6.8%|
[et_block](#et_block)|1000|18343756|517|0.0%|0.1%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|512|0.0%|0.1%|
[firehol_level3](#firehol_level3)|109549|9627220|85|0.0%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|75|0.0%|0.0%|
[sorbs_spam](#sorbs_spam)|64701|65536|20|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|20|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|20|0.0%|0.0%|
[alienvault_reputation](#alienvault_reputation)|189146|189146|14|0.0%|0.0%|
[php_commenters](#php_commenters)|458|458|8|1.7%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|7|0.0%|0.0%|
[firehol_level2](#firehol_level2)|20666|32229|7|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9136|9136|6|0.0%|0.0%|
[zeus_badips](#zeus_badips)|202|202|5|2.4%|0.0%|
[zeus](#zeus)|230|230|5|2.1%|0.0%|
[blocklist_de](#blocklist_de)|26985|26985|5|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6669|6669|3|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|170|170|2|1.1%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|17750|17750|2|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|2972|2972|2|0.0%|0.0%|
[php_harvesters](#php_harvesters)|408|408|1|0.2%|0.0%|
[openbl_60d](#openbl_60d)|6960|6960|1|0.0%|0.0%|
[openbl_30d](#openbl_30d)|2792|2792|1|0.0%|0.0%|
[nixspam](#nixspam)|18198|18198|1|0.0%|0.0%|
[malc0de](#malc0de)|276|276|1|0.3%|0.0%|
[iw_spamlist](#iw_spamlist)|3648|3648|1|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.0%|
[firehol_anonymous](#firehol_anonymous)|19172|83219|1|0.0%|0.0%|
[dm_tor](#dm_tor)|6468|6468|1|0.0%|0.0%|
[bm_tor](#bm_tor)|6471|6471|1|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13845|13845|1|0.0%|0.0%|

## sslbl

[Abuse.ch SSL Blacklist](https://sslbl.abuse.ch/) bad SSL traffic related to malware or botnet activities - **excellent list**

Source is downloaded from [this link](https://sslbl.abuse.ch/blacklist/sslipblacklist.csv).

The last time downloaded was found to be dated: Fri Jun 12 09:30:04 UTC 2015.

The ipset `sslbl` has **370** entries, **370** unique IPs.

The following table shows the overlaps of `sslbl` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `sslbl`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `sslbl`.
- ` this % ` is the percentage **of this ipset (`sslbl`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level1](#firehol_level1)|5070|688854680|370|0.0%|100.0%|
[firehol_level3](#firehol_level3)|109549|9627220|89|0.0%|24.0%|
[alienvault_reputation](#alienvault_reputation)|189146|189146|65|0.0%|17.5%|
[shunlist](#shunlist)|1185|1185|58|4.8%|15.6%|
[et_block](#et_block)|1000|18343756|39|0.0%|10.5%|
[snort_ipfilter](#snort_ipfilter)|9136|9136|31|0.3%|8.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|28|0.0%|7.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|6|0.0%|1.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|3|0.0%|0.8%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|1|0.0%|0.2%|
[ri_web_proxies](#ri_web_proxies)|7952|7952|1|0.0%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.2%|
[firehol_proxies](#firehol_proxies)|12734|13010|1|0.0%|0.2%|
[firehol_anonymous](#firehol_anonymous)|19172|83219|1|0.0%|0.2%|
[dragon_sshpauth](#dragon_sshpauth)|1589|1653|1|0.0%|0.2%|
[dragon_http](#dragon_http)|1021|268288|1|0.0%|0.2%|

## stopforumspam_1d

[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers in the last 24 hours - **excellent list**

Source is downloaded from [this link](http://www.stopforumspam.com/downloads/listed_ip_1.zip).

The last time downloaded was found to be dated: Fri Jun 12 09:00:01 UTC 2015.

The ipset `stopforumspam_1d` has **6669** entries, **6669** unique IPs.

The following table shows the overlaps of `stopforumspam_1d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `stopforumspam_1d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `stopforumspam_1d`.
- ` this % ` is the percentage **of this ipset (`stopforumspam_1d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|20666|32229|6669|20.6%|100.0%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|5696|19.6%|85.4%|
[firehol_level3](#firehol_level3)|109549|9627220|4514|0.0%|67.6%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|4475|4.7%|67.1%|
[blocklist_de](#blocklist_de)|26985|26985|1444|5.3%|21.6%|
[blocklist_de_bots](#blocklist_de_bots)|2972|2972|1392|46.8%|20.8%|
[firehol_anonymous](#firehol_anonymous)|19172|83219|955|1.1%|14.3%|
[firehol_proxies](#firehol_proxies)|12734|13010|805|6.1%|12.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|488|0.0%|7.3%|
[ri_web_proxies](#ri_web_proxies)|7952|7952|421|5.2%|6.3%|
[snort_ipfilter](#snort_ipfilter)|9136|9136|353|3.8%|5.2%|
[tor_exits](#tor_exits)|1106|1106|322|29.1%|4.8%|
[proxyrss](#proxyrss)|1570|1570|317|20.1%|4.7%|
[et_tor](#et_tor)|6500|6500|316|4.8%|4.7%|
[dm_tor](#dm_tor)|6468|6468|312|4.8%|4.6%|
[bm_tor](#bm_tor)|6471|6471|312|4.8%|4.6%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|195|37.2%|2.9%|
[xroxy](#xroxy)|2175|2175|194|8.9%|2.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|176|0.0%|2.6%|
[proxz](#proxz)|1356|1356|174|12.8%|2.6%|
[php_commenters](#php_commenters)|458|458|167|36.4%|2.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|129|0.0%|1.9%|
[ri_connect_proxies](#ri_connect_proxies)|2855|2855|108|3.7%|1.6%|
[blocklist_de_strongips](#blocklist_de_strongips)|170|170|101|59.4%|1.5%|
[firehol_level1](#firehol_level1)|5070|688854680|86|0.0%|1.2%|
[et_block](#et_block)|1000|18343756|82|0.0%|1.2%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|74|0.0%|1.1%|
[nixspam](#nixspam)|18198|18198|61|0.3%|0.9%|
[blocklist_de_apache](#blocklist_de_apache)|13845|13845|53|0.3%|0.7%|
[blocklist_de_mail](#blocklist_de_mail)|17750|17750|46|0.2%|0.6%|
[sorbs_spam](#sorbs_spam)|64701|65536|45|0.0%|0.6%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|45|0.0%|0.6%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|45|0.0%|0.6%|
[php_harvesters](#php_harvesters)|408|408|44|10.7%|0.6%|
[alienvault_reputation](#alienvault_reputation)|189146|189146|44|0.0%|0.6%|
[php_spammers](#php_spammers)|735|735|40|5.4%|0.5%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|35|0.0%|0.5%|
[php_dictionary](#php_dictionary)|737|737|30|4.0%|0.4%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2446|2446|20|0.8%|0.2%|
[openbl_60d](#openbl_60d)|6960|6960|19|0.2%|0.2%|
[dshield](#dshield)|20|5120|9|0.1%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|7|0.0%|0.1%|
[dragon_http](#dragon_http)|1021|268288|7|0.0%|0.1%|
[sorbs_web](#sorbs_web)|628|629|6|0.9%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|5|0.7%|0.0%|
[voipbl](#voipbl)|10586|10998|4|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|3|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|1523|1523|3|0.1%|0.0%|
[shunlist](#shunlist)|1185|1185|2|0.1%|0.0%|
[iw_spamlist](#iw_spamlist)|3648|3648|2|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|2|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2726|2726|2|0.0%|0.0%|
[zeus_badips](#zeus_badips)|202|202|1|0.4%|0.0%|
[zeus](#zeus)|230|230|1|0.4%|0.0%|
[openbl_30d](#openbl_30d)|2792|2792|1|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|1|0.0%|0.0%|
[fullbogons](#fullbogons)|3775|670173256|1|0.0%|0.0%|
[et_compromised](#et_compromised)|1704|1704|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1694|1694|1|0.0%|0.0%|

## stopforumspam_30d

[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 30 days)

Source is downloaded from [this link](http://www.stopforumspam.com/downloads/listed_ip_30.zip).

The last time downloaded was found to be dated: Thu Jun 11 12:00:33 UTC 2015.

The ipset `stopforumspam_30d` has **94309** entries, **94309** unique IPs.

The following table shows the overlaps of `stopforumspam_30d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `stopforumspam_30d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `stopforumspam_30d`.
- ` this % ` is the percentage **of this ipset (`stopforumspam_30d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level3](#firehol_level3)|109549|9627220|94309|0.9%|100.0%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|27620|95.1%|29.2%|
[firehol_anonymous](#firehol_anonymous)|19172|83219|6220|7.4%|6.5%|
[firehol_level2](#firehol_level2)|20666|32229|5850|18.1%|6.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|5830|0.0%|6.1%|
[firehol_proxies](#firehol_proxies)|12734|13010|5622|43.2%|5.9%|
[stopforumspam_1d](#stopforumspam_1d)|6669|6669|4475|67.1%|4.7%|
[ri_web_proxies](#ri_web_proxies)|7952|7952|3712|46.6%|3.9%|
[blocklist_de](#blocklist_de)|26985|26985|2613|9.6%|2.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|2476|0.0%|2.6%|
[blocklist_de_bots](#blocklist_de_bots)|2972|2972|2294|77.1%|2.4%|
[ri_connect_proxies](#ri_connect_proxies)|2855|2855|1591|55.7%|1.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|1522|0.0%|1.6%|
[xroxy](#xroxy)|2175|2175|1287|59.1%|1.3%|
[firehol_level1](#firehol_level1)|5070|688854680|1111|0.0%|1.1%|
[et_block](#et_block)|1000|18343756|1032|0.0%|1.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|1014|0.0%|1.0%|
[snort_ipfilter](#snort_ipfilter)|9136|9136|804|8.8%|0.8%|
[proxz](#proxz)|1356|1356|794|58.5%|0.8%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|725|0.0%|0.7%|
[proxyrss](#proxyrss)|1570|1570|680|43.3%|0.7%|
[et_tor](#et_tor)|6500|6500|651|10.0%|0.6%|
[dm_tor](#dm_tor)|6468|6468|631|9.7%|0.6%|
[bm_tor](#bm_tor)|6471|6471|631|9.7%|0.6%|
[tor_exits](#tor_exits)|1106|1106|619|55.9%|0.6%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|345|65.8%|0.3%|
[php_commenters](#php_commenters)|458|458|334|72.9%|0.3%|
[sorbs_spam](#sorbs_spam)|64701|65536|320|0.4%|0.3%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|320|0.4%|0.3%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|320|0.4%|0.3%|
[blocklist_de_mail](#blocklist_de_mail)|17750|17750|252|1.4%|0.2%|
[nixspam](#nixspam)|18198|18198|231|1.2%|0.2%|
[blocklist_de_apache](#blocklist_de_apache)|13845|13845|186|1.3%|0.1%|
[alienvault_reputation](#alienvault_reputation)|189146|189146|168|0.0%|0.1%|
[php_spammers](#php_spammers)|735|735|151|20.5%|0.1%|
[php_dictionary](#php_dictionary)|737|737|139|18.8%|0.1%|
[blocklist_de_strongips](#blocklist_de_strongips)|170|170|130|76.4%|0.1%|
[dragon_http](#dragon_http)|1021|268288|108|0.0%|0.1%|
[php_harvesters](#php_harvesters)|408|408|87|21.3%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|75|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2446|2446|56|2.2%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|52|0.0%|0.0%|
[sorbs_web](#sorbs_web)|628|629|48|7.6%|0.0%|
[openbl_60d](#openbl_60d)|6960|6960|47|0.6%|0.0%|
[voipbl](#voipbl)|10586|10998|35|0.3%|0.0%|
[dshield](#dshield)|20|5120|21|0.4%|0.0%|
[iw_spamlist](#iw_spamlist)|3648|3648|20|0.5%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|20|3.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|17|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2726|2726|15|0.5%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1901|1901|12|0.6%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|1523|1523|11|0.7%|0.0%|
[et_compromised](#et_compromised)|1704|1704|10|0.5%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1694|1694|9|0.5%|0.0%|
[openbl_30d](#openbl_30d)|2792|2792|5|0.1%|0.0%|
[shunlist](#shunlist)|1185|1185|4|0.3%|0.0%|
[dragon_sshpauth](#dragon_sshpauth)|1589|1653|4|0.2%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|3|0.2%|0.0%|
[zeus_badips](#zeus_badips)|202|202|2|0.9%|0.0%|
[zeus](#zeus)|230|230|2|0.8%|0.0%|
[openbl_7d](#openbl_7d)|629|629|2|0.3%|0.0%|
[nt_malware_http](#nt_malware_http)|69|69|2|2.8%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|2|0.1%|0.0%|
[fullbogons](#fullbogons)|3775|670173256|2|0.0%|0.0%|
[ciarmy](#ciarmy)|416|416|2|0.4%|0.0%|
[openbl_1d](#openbl_1d)|124|124|1|0.8%|0.0%|
[iw_wormlist](#iw_wormlist)|34|34|1|2.9%|0.0%|
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
[firehol_level3](#firehol_level3)|109549|9627220|27643|0.2%|95.2%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|27620|29.2%|95.1%|
[firehol_level2](#firehol_level2)|20666|32229|6697|20.7%|23.0%|
[stopforumspam_1d](#stopforumspam_1d)|6669|6669|5696|85.4%|19.6%|
[firehol_anonymous](#firehol_anonymous)|19172|83219|2729|3.2%|9.4%|
[firehol_proxies](#firehol_proxies)|12734|13010|2363|18.1%|8.1%|
[blocklist_de](#blocklist_de)|26985|26985|2346|8.6%|8.0%|
[blocklist_de_bots](#blocklist_de_bots)|2972|2972|2180|73.3%|7.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|1961|0.0%|6.7%|
[ri_web_proxies](#ri_web_proxies)|7952|7952|1487|18.6%|5.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|736|0.0%|2.5%|
[snort_ipfilter](#snort_ipfilter)|9136|9136|667|7.3%|2.2%|
[xroxy](#xroxy)|2175|2175|586|26.9%|2.0%|
[proxyrss](#proxyrss)|1570|1570|549|34.9%|1.8%|
[et_tor](#et_tor)|6500|6500|547|8.4%|1.8%|
[tor_exits](#tor_exits)|1106|1106|539|48.7%|1.8%|
[ri_connect_proxies](#ri_connect_proxies)|2855|2855|531|18.5%|1.8%|
[dm_tor](#dm_tor)|6468|6468|529|8.1%|1.8%|
[bm_tor](#bm_tor)|6471|6471|529|8.1%|1.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|510|0.0%|1.7%|
[proxz](#proxz)|1356|1356|507|37.3%|1.7%|
[firehol_level1](#firehol_level1)|5070|688854680|291|0.0%|1.0%|
[et_block](#et_block)|1000|18343756|283|0.0%|0.9%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|277|52.8%|0.9%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|269|0.0%|0.9%|
[php_commenters](#php_commenters)|458|458|248|54.1%|0.8%|
[sorbs_spam](#sorbs_spam)|64701|65536|173|0.2%|0.5%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|173|0.2%|0.5%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|173|0.2%|0.5%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|154|0.0%|0.5%|
[nixspam](#nixspam)|18198|18198|143|0.7%|0.4%|
[blocklist_de_mail](#blocklist_de_mail)|17750|17750|135|0.7%|0.4%|
[blocklist_de_strongips](#blocklist_de_strongips)|170|170|116|68.2%|0.3%|
[blocklist_de_apache](#blocklist_de_apache)|13845|13845|108|0.7%|0.3%|
[php_spammers](#php_spammers)|735|735|93|12.6%|0.3%|
[php_dictionary](#php_dictionary)|737|737|93|12.6%|0.3%|
[alienvault_reputation](#alienvault_reputation)|189146|189146|88|0.0%|0.3%|
[php_harvesters](#php_harvesters)|408|408|65|15.9%|0.2%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2446|2446|39|1.5%|0.1%|
[sorbs_web](#sorbs_web)|628|629|32|5.0%|0.1%|
[dragon_http](#dragon_http)|1021|268288|32|0.0%|0.1%|
[openbl_60d](#openbl_60d)|6960|6960|26|0.3%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|21|0.0%|0.0%|
[voipbl](#voipbl)|10586|10998|15|0.1%|0.0%|
[dshield](#dshield)|20|5120|15|0.2%|0.0%|
[iw_spamlist](#iw_spamlist)|3648|3648|12|0.3%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|10|1.5%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|7|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|7|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2726|2726|6|0.2%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|1523|1523|6|0.3%|0.0%|
[et_compromised](#et_compromised)|1704|1704|3|0.1%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1694|1694|3|0.1%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1901|1901|3|0.1%|0.0%|
[shunlist](#shunlist)|1185|1185|2|0.1%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|2|0.1%|0.0%|
[fullbogons](#fullbogons)|3775|670173256|2|0.0%|0.0%|
[zeus_badips](#zeus_badips)|202|202|1|0.4%|0.0%|
[zeus](#zeus)|230|230|1|0.4%|0.0%|
[openbl_30d](#openbl_30d)|2792|2792|1|0.0%|0.0%|
[iw_wormlist](#iw_wormlist)|34|34|1|2.9%|0.0%|
[ciarmy](#ciarmy)|416|416|1|0.2%|0.0%|

## tor_exits

[TorProject.org](https://www.torproject.org) list of all current TOR exit points (TorDNSEL)

Source is downloaded from [this link](https://check.torproject.org/exit-addresses).

The last time downloaded was found to be dated: Fri Jun 12 09:02:25 UTC 2015.

The ipset `tor_exits` has **1106** entries, **1106** unique IPs.

The following table shows the overlaps of `tor_exits` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `tor_exits`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `tor_exits`.
- ` this % ` is the percentage **of this ipset (`tor_exits`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_anonymous](#firehol_anonymous)|19172|83219|1106|1.3%|100.0%|
[firehol_level3](#firehol_level3)|109549|9627220|1069|0.0%|96.6%|
[snort_ipfilter](#snort_ipfilter)|9136|9136|1067|11.6%|96.4%|
[bm_tor](#bm_tor)|6471|6471|1017|15.7%|91.9%|
[dm_tor](#dm_tor)|6468|6468|1016|15.7%|91.8%|
[et_tor](#et_tor)|6500|6500|971|14.9%|87.7%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|619|0.6%|55.9%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|539|1.8%|48.7%|
[firehol_level2](#firehol_level2)|20666|32229|333|1.0%|30.1%|
[stopforumspam_1d](#stopforumspam_1d)|6669|6669|322|4.8%|29.1%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|228|43.5%|20.6%|
[firehol_proxies](#firehol_proxies)|12734|13010|228|1.7%|20.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|126|0.0%|11.3%|
[php_commenters](#php_commenters)|458|458|54|11.7%|4.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|40|0.0%|3.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|37|0.0%|3.3%|
[alienvault_reputation](#alienvault_reputation)|189146|189146|30|0.0%|2.7%|
[openbl_60d](#openbl_60d)|6960|6960|20|0.2%|1.8%|
[blocklist_de_apache](#blocklist_de_apache)|13845|13845|19|0.1%|1.7%|
[blocklist_de](#blocklist_de)|26985|26985|19|0.0%|1.7%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2446|2446|17|0.6%|1.5%|
[nixspam](#nixspam)|18198|18198|8|0.0%|0.7%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|8|0.0%|0.7%|
[php_harvesters](#php_harvesters)|408|408|6|1.4%|0.5%|
[sorbs_spam](#sorbs_spam)|64701|65536|5|0.0%|0.4%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|5|0.0%|0.4%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|5|0.0%|0.4%|
[php_spammers](#php_spammers)|735|735|5|0.6%|0.4%|
[dragon_http](#dragon_http)|1021|268288|5|0.0%|0.4%|
[php_dictionary](#php_dictionary)|737|737|4|0.5%|0.3%|
[firehol_level1](#firehol_level1)|5070|688854680|3|0.0%|0.2%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|2|0.0%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2|0.0%|0.1%|
[et_block](#et_block)|1000|18343756|2|0.0%|0.1%|
[blocklist_de_mail](#blocklist_de_mail)|17750|17750|2|0.0%|0.1%|
[shunlist](#shunlist)|1185|1185|1|0.0%|0.0%|
[dshield](#dshield)|20|5120|1|0.0%|0.0%|

## virbl

[VirBL](http://virbl.bit.nl/) is a project of which the idea was born during the RIPE-48 meeting. The plan was to get reports of virusscanning mailservers, and put the IP-addresses that were reported to send viruses on a blacklist.

Source is downloaded from [this link](http://virbl.bit.nl/download/virbl.dnsbl.bit.nl.txt).

The last time downloaded was found to be dated: Fri Jun 12 08:42:04 UTC 2015.

The ipset `virbl` has **22** entries, **22** unique IPs.

The following table shows the overlaps of `virbl` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `virbl`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `virbl`.
- ` this % ` is the percentage **of this ipset (`virbl`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level3](#firehol_level3)|109549|9627220|22|0.0%|100.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|1|0.0%|4.5%|
[sorbs_spam](#sorbs_spam)|64701|65536|1|0.0%|4.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|1|0.0%|4.5%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|4.5%|
[firehol_level2](#firehol_level2)|20666|32229|1|0.0%|4.5%|
[firehol_level1](#firehol_level1)|5070|688854680|1|0.0%|4.5%|
[et_block](#et_block)|1000|18343756|1|0.0%|4.5%|
[blocklist_de_mail](#blocklist_de_mail)|17750|17750|1|0.0%|4.5%|
[blocklist_de_imap](#blocklist_de_imap)|2726|2726|1|0.0%|4.5%|
[blocklist_de](#blocklist_de)|26985|26985|1|0.0%|4.5%|

## voipbl

[VoIPBL.org](http://www.voipbl.org/) a distributed VoIP blacklist that is aimed to protects against VoIP Fraud and minimizing abuse for network that have publicly accessible PBX's. Several algorithms, external sources and manual confirmation are used before they categorize something as an attack and determine the threat level.

Source is downloaded from [this link](http://www.voipbl.org/update/).

The last time downloaded was found to be dated: Fri Jun 12 07:54:30 UTC 2015.

The ipset `voipbl` has **10586** entries, **10998** unique IPs.

The following table shows the overlaps of `voipbl` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `voipbl`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `voipbl`.
- ` this % ` is the percentage **of this ipset (`voipbl`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|1613|0.0%|14.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|436|0.0%|3.9%|
[firehol_level1](#firehol_level1)|5070|688854680|333|0.0%|3.0%|
[fullbogons](#fullbogons)|3775|670173256|319|0.0%|2.9%|
[bogons](#bogons)|13|592708608|319|0.0%|2.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|302|0.0%|2.7%|
[alienvault_reputation](#alienvault_reputation)|189146|189146|176|0.0%|1.6%|
[firehol_anonymous](#firehol_anonymous)|19172|83219|79|0.0%|0.7%|
[firehol_level3](#firehol_level3)|109549|9627220|58|0.0%|0.5%|
[firehol_level2](#firehol_level2)|20666|32229|44|0.1%|0.4%|
[blocklist_de](#blocklist_de)|26985|26985|41|0.1%|0.3%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|35|0.0%|0.3%|
[blocklist_de_sip](#blocklist_de_sip)|83|83|34|40.9%|0.3%|
[dragon_http](#dragon_http)|1021|268288|29|0.0%|0.2%|
[et_block](#et_block)|1000|18343756|18|0.0%|0.1%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|15|0.0%|0.1%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|14|0.0%|0.1%|
[shunlist](#shunlist)|1185|1185|14|1.1%|0.1%|
[openbl_60d](#openbl_60d)|6960|6960|8|0.1%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6669|6669|4|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|4|0.0%|0.0%|
[sorbs_spam](#sorbs_spam)|64701|65536|3|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|3|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|3|0.0%|0.0%|
[openbl_30d](#openbl_30d)|2792|2792|3|0.1%|0.0%|
[et_tor](#et_tor)|6500|6500|3|0.0%|0.0%|
[et_compromised](#et_compromised)|1704|1704|3|0.1%|0.0%|
[dm_tor](#dm_tor)|6468|6468|3|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1694|1694|3|0.1%|0.0%|
[bm_tor](#bm_tor)|6471|6471|3|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|2|0.3%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|2|0.0%|0.0%|
[firehol_proxies](#firehol_proxies)|12734|13010|2|0.0%|0.0%|
[ciarmy](#ciarmy)|416|416|2|0.4%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1901|1901|2|0.1%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|17750|17750|2|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13845|13845|2|0.0%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.0%|
[dragon_vncprobe](#dragon_vncprobe)|87|87|1|1.1%|0.0%|
[dragon_sshpauth](#dragon_sshpauth)|1589|1653|1|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2726|2726|1|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|2972|2972|1|0.0%|0.0%|

## xroxy

[xroxy.com](http://www.xroxy.com) open proxies (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.xroxy.com/proxyrss.xml).

The last time downloaded was found to be dated: Fri Jun 12 09:33:06 UTC 2015.

The ipset `xroxy` has **2175** entries, **2175** unique IPs.

The following table shows the overlaps of `xroxy` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `xroxy`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `xroxy`.
- ` this % ` is the percentage **of this ipset (`xroxy`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_proxies](#firehol_proxies)|12734|13010|2175|16.7%|100.0%|
[firehol_anonymous](#firehol_anonymous)|19172|83219|2175|2.6%|100.0%|
[firehol_level3](#firehol_level3)|109549|9627220|1302|0.0%|59.8%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|1287|1.3%|59.1%|
[ri_web_proxies](#ri_web_proxies)|7952|7952|965|12.1%|44.3%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|586|2.0%|26.9%|
[proxz](#proxz)|1356|1356|468|34.5%|21.5%|
[ri_connect_proxies](#ri_connect_proxies)|2855|2855|396|13.8%|18.2%|
[proxyrss](#proxyrss)|1570|1570|349|22.2%|16.0%|
[firehol_level2](#firehol_level2)|20666|32229|305|0.9%|14.0%|
[blocklist_de](#blocklist_de)|26985|26985|227|0.8%|10.4%|
[stopforumspam_1d](#stopforumspam_1d)|6669|6669|194|2.9%|8.9%|
[blocklist_de_bots](#blocklist_de_bots)|2972|2972|175|5.8%|8.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|112|0.0%|5.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|104|0.0%|4.7%|
[sorbs_spam](#sorbs_spam)|64701|65536|76|0.1%|3.4%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|76|0.1%|3.4%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|76|0.1%|3.4%|
[nixspam](#nixspam)|18198|18198|67|0.3%|3.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|58|0.0%|2.6%|
[blocklist_de_mail](#blocklist_de_mail)|17750|17750|52|0.2%|2.3%|
[snort_ipfilter](#snort_ipfilter)|9136|9136|42|0.4%|1.9%|
[php_dictionary](#php_dictionary)|737|737|41|5.5%|1.8%|
[php_spammers](#php_spammers)|735|735|34|4.6%|1.5%|
[sorbs_web](#sorbs_web)|628|629|16|2.5%|0.7%|
[php_commenters](#php_commenters)|458|458|13|2.8%|0.5%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|13|1.9%|0.5%|
[blocklist_de_strongips](#blocklist_de_strongips)|170|170|7|4.1%|0.3%|
[dragon_http](#dragon_http)|1021|268288|6|0.0%|0.2%|
[alienvault_reputation](#alienvault_reputation)|189146|189146|5|0.0%|0.2%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|3|0.5%|0.1%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|3|0.0%|0.1%|
[php_harvesters](#php_harvesters)|408|408|2|0.4%|0.0%|
[iw_spamlist](#iw_spamlist)|3648|3648|2|0.0%|0.0%|
[et_tor](#et_tor)|6500|6500|2|0.0%|0.0%|
[dm_tor](#dm_tor)|6468|6468|2|0.0%|0.0%|
[bm_tor](#bm_tor)|6471|6471|2|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.0%|
[et_compromised](#et_compromised)|1704|1704|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1694|1694|1|0.0%|0.0%|

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
[firehol_level1](#firehol_level1)|5070|688854680|230|0.0%|100.0%|
[et_block](#et_block)|1000|18343756|229|0.0%|99.5%|
[firehol_level3](#firehol_level3)|109549|9627220|203|0.0%|88.2%|
[zeus_badips](#zeus_badips)|202|202|202|100.0%|87.8%|
[snort_ipfilter](#snort_ipfilter)|9136|9136|200|2.1%|86.9%|
[alienvault_reputation](#alienvault_reputation)|189146|189146|61|0.0%|26.5%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|15|0.0%|6.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|14|0.0%|6.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|10|0.0%|4.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|9|0.0%|3.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|7|0.0%|3.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|5|0.0%|2.1%|
[dragon_http](#dragon_http)|1021|268288|3|0.0%|1.3%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|2|0.0%|0.8%|
[openbl_60d](#openbl_60d)|6960|6960|2|0.0%|0.8%|
[openbl_30d](#openbl_30d)|2792|2792|2|0.0%|0.8%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|1|0.0%|0.4%|
[stopforumspam_1d](#stopforumspam_1d)|6669|6669|1|0.0%|0.4%|
[php_commenters](#php_commenters)|458|458|1|0.2%|0.4%|
[openbl_7d](#openbl_7d)|629|629|1|0.1%|0.4%|
[nixspam](#nixspam)|18198|18198|1|0.0%|0.4%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|1|0.0%|0.4%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.4%|
[firehol_level2](#firehol_level2)|20666|32229|1|0.0%|0.4%|

## zeus_badips

[Abuse.ch Zeus tracker](https://zeustracker.abuse.ch) badips includes IPv4 addresses that are used by the ZeuS trojan. It is the recommened blocklist if you want to block only ZeuS IPs. It excludes IP addresses that ZeuS Tracker believes to be hijacked (level 2) or belong to a free web hosting provider (level 3). Hence the false postive rate should be much lower compared to the standard ZeuS IP blocklist. **excellent list**

Source is downloaded from [this link](https://zeustracker.abuse.ch/blocklist.php?download=badips).

The last time downloaded was found to be dated: Fri Jun 12 09:36:13 UTC 2015.

The ipset `zeus_badips` has **202** entries, **202** unique IPs.

The following table shows the overlaps of `zeus_badips` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `zeus_badips`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `zeus_badips`.
- ` this % ` is the percentage **of this ipset (`zeus_badips`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[zeus](#zeus)|230|230|202|87.8%|100.0%|
[firehol_level1](#firehol_level1)|5070|688854680|202|0.0%|100.0%|
[et_block](#et_block)|1000|18343756|202|0.0%|100.0%|
[firehol_level3](#firehol_level3)|109549|9627220|180|0.0%|89.1%|
[snort_ipfilter](#snort_ipfilter)|9136|9136|178|1.9%|88.1%|
[alienvault_reputation](#alienvault_reputation)|189146|189146|37|0.0%|18.3%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|15|0.0%|7.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|10|0.0%|4.9%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|10|0.0%|4.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|8|0.0%|3.9%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|5|0.0%|2.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|4|0.0%|1.9%|
[dragon_http](#dragon_http)|1021|268288|3|0.0%|1.4%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|2|0.0%|0.9%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|1|0.0%|0.4%|
[stopforumspam_1d](#stopforumspam_1d)|6669|6669|1|0.0%|0.4%|
[php_commenters](#php_commenters)|458|458|1|0.2%|0.4%|
[openbl_7d](#openbl_7d)|629|629|1|0.1%|0.4%|
[openbl_60d](#openbl_60d)|6960|6960|1|0.0%|0.4%|
[openbl_30d](#openbl_30d)|2792|2792|1|0.0%|0.4%|
[nixspam](#nixspam)|18198|18198|1|0.0%|0.4%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.4%|
[firehol_level2](#firehol_level2)|20666|32229|1|0.0%|0.4%|
