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

The following list was automatically generated on Fri Jun 12 08:28:03 UTC 2015.

The update frequency is the maximum allowed by internal configuration. A list will never be downloaded sooner than the update frequency stated. A list may also not be downloaded, after this frequency expired, if it has not been modified on the server (as reported by HTTP `IF_MODIFIED_SINCE` method).

name|info|type|entries|update|
:--:|:--:|:--:|:-----:|:----:|
[alienvault_reputation](#alienvault_reputation)|[AlienVault.com](https://www.alienvault.com/) IP reputation database (this list seems to include port scanning hosts and to be updated regularly, but we found no information about its retention policy)|ipv4 hash:ip|189146 unique IPs|updated every 6 hours  from [this link](https://reputation.alienvault.com/reputation.generic)
[blocklist_de](#blocklist_de)|[Blocklist.de](https://www.blocklist.de/) IPs that have been detected by fail2ban in the last 48 hours - **excellent list**|ipv4 hash:ip|27144 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/all.txt)
[blocklist_de_apache](#blocklist_de_apache)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service Apache, Apache-DDOS, RFI-Attacks.|ipv4 hash:ip|13852 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/apache.txt)
[blocklist_de_bots](#blocklist_de_bots)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the RFI-Attacks, REG-Bots, IRC-Bots or BadBots (BadBots = he has posted a Spam-Comment on a open Forum or Wiki).|ipv4 hash:ip|2979 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/bots.txt)
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|[Blocklist.de](https://www.blocklist.de/) All IPs which attacks Joomlas, Wordpress and other Web-Logins with Brute-Force Logins.|ipv4 hash:ip|2473 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/bruteforcelogin.txt)
[blocklist_de_ftp](#blocklist_de_ftp)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours for attacks on the Service FTP.|ipv4 hash:ip|1525 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/ftp.txt)
[blocklist_de_imap](#blocklist_de_imap)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours for attacks on the Service imap, sasl, pop3, etc.|ipv4 hash:ip|2719 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/imap.txt)
[blocklist_de_mail](#blocklist_de_mail)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service Mail, Postfix.|ipv4 hash:ip|17849 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/mail.txt)
[blocklist_de_sip](#blocklist_de_sip)|[Blocklist.de](https://www.blocklist.de/) All IP addresses that tried to login in a SIP, VOIP or Asterisk Server and are included in the IPs list from [infiltrated.net](www.infiltrated.net)|ipv4 hash:ip|84 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/sip.txt)
[blocklist_de_ssh](#blocklist_de_ssh)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service SSH.|ipv4 hash:ip|1969 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/ssh.txt)
[blocklist_de_strongips](#blocklist_de_strongips)|[Blocklist.de](https://www.blocklist.de/) All IPs which are older then 2 month and have more then 5.000 attacks.|ipv4 hash:ip|170 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/strongips.txt)
[bm_tor](#bm_tor)|[torstatus.blutmagie.de](https://torstatus.blutmagie.de) list of all TOR network servers|ipv4 hash:ip|6338 unique IPs|updated every 30 mins  from [this link](https://torstatus.blutmagie.de/ip_list_all.php/Tor_ip_list_ALL.csv)
[bogons](#bogons)|[Team-Cymru.org](http://www.team-cymru.org) private and reserved addresses defined by RFC 1918, RFC 5735, and RFC 6598 and netblocks that have not been allocated to a regional internet registry - **excellent list - use it only your internet interface**|ipv4 hash:net|13 subnets, 592708608 unique IPs|updated every 1 day  from [this link](http://www.team-cymru.org/Services/Bogons/bogon-bn-agg.txt)
[bruteforceblocker](#bruteforceblocker)|[danger.rulez.sk](http://danger.rulez.sk/) IPs detected by [bruteforceblocker](http://danger.rulez.sk/index.php/bruteforceblocker/) (fail2ban alternative for SSH on OpenBSD). This is an automatically generated list from users reporting failed authentication attempts. An IP seems to be included if 3 or more users report it. Its retention pocily seems 30 days.|ipv4 hash:ip|1697 unique IPs|updated every 3 hours  from [this link](http://danger.rulez.sk/projects/bruteforceblocker/blist.php)
[ciarmy](#ciarmy)|[CIArmy.com](http://ciarmy.com/) IPs with poor Rogue Packet score that have not yet been identified as malicious by the community|ipv4 hash:ip|416 unique IPs|updated every 3 hours  from [this link](http://cinsscore.com/list/ci-badguys.txt)
[cleanmx_viruses](#cleanmx_viruses)|[Clean-MX.de](http://support.clean-mx.de/clean-mx/viruses.php) IPs with viruses|ipv4 hash:ip|121 unique IPs|updated every 12 hours  from [this link](http://support.clean-mx.de/clean-mx/xmlviruses.php?sort=id%20desc&response=alive)
[dm_tor](#dm_tor)|[dan.me.uk](https://www.dan.me.uk) dynamic list of TOR nodes|ipv4 hash:ip|6455 unique IPs|updated every 30 mins  from [this link](https://www.dan.me.uk/torlist/)
[dragon_http](#dragon_http)|[Dragon Search Group](http://www.dragonresearchgroup.org/) IPs that have been seen sending HTTP requests to Dragon Research Pods in the last 7 days. This report lists hosts that are highly suspicious and are likely conducting malicious HTTP attacks. LEGITIMATE SEARCH ENGINE BOTS MAY BE IN THIS LIST. This report is informational.  It is not a blacklist, but some operators may choose to use it to help protect their networks and hosts in the forms of automated reporting and mitigation services.|ipv4 hash:net|1021 subnets, 268288 unique IPs|updated every 1 hour  from [this link](http://www.dragonresearchgroup.org/insight/http-report.txt)
[dragon_sshpauth](#dragon_sshpauth)|[Dragon Search Group](http://www.dragonresearchgroup.org/) IP address that has been seen attempting to remotely login to a host using SSH password authentication, in the last 7 days. This report lists hosts that are highly suspicious and are likely conducting malicious SSH password authentication attacks.|ipv4 hash:net|1595 subnets, 1659 unique IPs|updated every 1 hour  from [this link](https://www.dragonresearchgroup.org/insight/sshpwauth.txt)
[dragon_vncprobe](#dragon_vncprobe)|[Dragon Search Group](http://www.dragonresearchgroup.org/) IP address that has been seen attempting to remotely connect to a host running the VNC application service, in the last 7 days. This report lists hosts that are highly suspicious and are likely conducting malicious VNC probes or VNC brute force attacks.|ipv4 hash:net|87 subnets, 87 unique IPs|updated every 1 hour  from [this link](https://www.dragonresearchgroup.org/insight/vncprobe.txt)
[dshield](#dshield)|[DShield.org](https://dshield.org/) top 20 attacking class C (/24) subnets over the last three days - **excellent list**|ipv4 hash:net|20 subnets, 5120 unique IPs|updated every 4 hours  from [this link](http://feeds.dshield.org/block.txt)
[et_block](#et_block)|[EmergingThreats.net](http://www.emergingthreats.net/) default blacklist (at the time of writing includes spamhaus DROP, dshield and abuse.ch trackers, which are available separately too - prefer to use the direct ipsets instead of this, they seem to lag a bit in updates)|ipv4 hash:net|1000 subnets, 18343756 unique IPs|updated every 12 hours  from [this link](http://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt)
[et_botcc](#et_botcc)|[EmergingThreats.net Command and Control IPs](http://doc.emergingthreats.net/bin/view/Main/BotCC) These IPs are updates every 24 hours and should be considered VERY highly reliable indications that a host is communicating with a known and active Bot or Malware command and control server - (although they say this includes abuse.ch trackers, it does not - most probably it is the shadowserver.org C&C list)|ipv4 hash:ip|505 unique IPs|updated every 12 hours  from [this link](http://rules.emergingthreats.net/fwrules/emerging-PIX-CC.rules)
[et_compromised](#et_compromised)|[EmergingThreats.net compromised hosts](http://doc.emergingthreats.net/bin/view/Main/CompromisedHost) - (this seems to be based on bruteforceblocker)|ipv4 hash:ip|1704 unique IPs|updated every 12 hours  from [this link](http://rules.emergingthreats.net/blockrules/compromised-ips.txt)
et_dshield|[EmergingThreats.net](http://www.emergingthreats.net/) dshield blocklist|ipv4 hash:net|disabled|updated every 12 hours  from [this link](http://rules.emergingthreats.net/fwrules/emerging-PIX-DSHIELD.rules)
et_spamhaus|[EmergingThreats.net](http://www.emergingthreats.net/) spamhaus blocklist|ipv4 hash:net|disabled|updated every 12 hours  from [this link](http://rules.emergingthreats.net/fwrules/emerging-PIX-DROP.rules)
[et_tor](#et_tor)|[EmergingThreats.net](http://www.emergingthreats.net/) [list](http://doc.emergingthreats.net/bin/view/Main/TorRules) of TOR network IPs|ipv4 hash:ip|6500 unique IPs|updated every 12 hours  from [this link](http://rules.emergingthreats.net/blockrules/emerging-tor.rules)
[feodo](#feodo)|[Abuse.ch Feodo tracker](https://feodotracker.abuse.ch) trojan includes IPs which are being used by Feodo (also known as Cridex or Bugat) which commits ebanking fraud - **excellent list**|ipv4 hash:ip|105 unique IPs|updated every 30 mins  from [this link](https://feodotracker.abuse.ch/blocklist/?download=ipblocklist)
[firehol_anonymous](#firehol_anonymous)|**FireHOL Anonymous** - Known anonymizing IPs. (includes: firehol_proxies anonymous bm_tor dm_tor tor_exits)|ipv4 hash:net|19294 subnets, 83353 unique IPs|
[firehol_level1](#firehol_level1)|**FireHOL Level 1** - Maximum protection without false positives. (includes: fullbogons dshield feodo palevo sslbl zeus spamhaus_drop spamhaus_edrop)|ipv4 hash:net|5137 subnets, 688854747 unique IPs|
[firehol_level2](#firehol_level2)|**FireHOL Level 2** - Maximum protection from attacks took place in the last 48 hours. (includes: openbl_1d blocklist_de stopforumspam_1d)|ipv4 hash:net|20803 subnets, 32382 unique IPs|
[firehol_level3](#firehol_level3)|**FireHOL Level 3** - All the bad IPs in last 30 days. (includes: openbl_30d stopforumspam_30d virbl malc0de shunlist malwaredomainlist bruteforceblocker ciarmy cleanmx_viruses snort_ipfilter ib_bluetack_spyware ib_bluetack_hijacked ib_bluetack_webexploit php_commenters php_dictionary php_harvesters php_spammers iw_wormlist)|ipv4 hash:net|109170 subnets, 9626833 unique IPs|
[firehol_proxies](#firehol_proxies)|**FireHOL Proxies** - Known open proxies in the last 30 days. (includes: ib_bluetack_proxies maxmind_proxy_fraud proxyrss proxz ri_connect_proxies ri_web_proxies xroxy)|ipv4 hash:net|12828 subnets, 13116 unique IPs|
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
[iw_spamlist](#iw_spamlist)|[ImproWare Antispam](http://antispam.imp.ch/) IPs sending spam, in the last 3 days|ipv4 hash:ip|3787 unique IPs|updated every 1 hour  from [this link](http://antispam.imp.ch/spamlist)
[iw_wormlist](#iw_wormlist)|[ImproWare Antispam](http://antispam.imp.ch/) IPs sending emails with viruses or worms, in the last 3 days|ipv4 hash:ip|34 unique IPs|updated every 1 hour  from [this link](http://antispam.imp.ch/wormlist)
lashback_ubl|[The LashBack UBL](http://blacklist.lashback.com/) The Unsubscribe Blacklist (UBL) is a real-time blacklist of IP addresses which are sending email to names harvested from suppression files (this is a big list, more than 500.000 IPs)|ipv4 hash:ip|disabled|updated every 1 day  from [this link](http://www.unsubscore.com/blacklist.txt)
[malc0de](#malc0de)|[Malc0de.com](http://malc0de.com) malicious IPs of the last 30 days|ipv4 hash:ip|276 unique IPs|updated every 1 day  from [this link](http://malc0de.com/bl/IP_Blacklist.txt)
[malwaredomainlist](#malwaredomainlist)|[malwaredomainlist.com](http://www.malwaredomainlist.com) list of malware active ip addresses|ipv4 hash:ip|1288 unique IPs|updated every 12 hours  from [this link](http://www.malwaredomainlist.com/hostslist/ip.txt)
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|[MaxMind.com](https://www.maxmind.com/en/anonymous-proxy-fraudulent-ip-address-list) list of anonymous proxy fraudelent IP addresses.|ipv4 hash:ip|524 unique IPs|updated every 4 hours  from [this link](https://www.maxmind.com/en/anonymous-proxy-fraudulent-ip-address-list)
[nixspam](#nixspam)|[NiX Spam](http://www.heise.de/ix/NiX-Spam-DNSBL-and-blacklist-for-download-499637.html) IP addresses that sent spam in the last hour - automatically generated entries without distinguishing open proxies from relays, dialup gateways, and so on. All IPs are removed after 12 hours if there is no spam from there.|ipv4 hash:ip|18020 unique IPs|updated every 15 mins  from [this link](http://www.dnsbl.manitu.net/download/nixspam-ip.dump.gz)
[nt_malware_http](#nt_malware_http)|[No Think](http://www.nothink.org/) Malware HTTP|ipv4 hash:ip|69 unique IPs|updated every 1 hour  from [this link](http://www.nothink.org/blacklist/blacklist_malware_http.txt)
[nt_malware_irc](#nt_malware_irc)|[No Think](http://www.nothink.org/) Malware IRC|ipv4 hash:ip|43 unique IPs|updated every 1 hour  from [this link](http://www.nothink.org/blacklist/blacklist_malware_irc.txt)
[nt_ssh_7d](#nt_ssh_7d)|[No Think](http://www.nothink.org/) Last 7 days SSH attacks|ipv4 hash:ip|0 unique IPs|updated every 1 hour  from [this link](http://www.nothink.org/blacklist/blacklist_ssh_week.txt)
openbl|[OpenBL.org](http://www.openbl.org/) default blacklist (currently it is the same with 90 days). OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications - **excellent list**|ipv4 hash:ip|disabled|updated every 4 hours  from [this link](http://www.openbl.org/lists/base.txt)
openbl_180d|[OpenBL.org](http://www.openbl.org/) last 180 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|disabled|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_180days.txt)
[openbl_1d](#openbl_1d)|[OpenBL.org](http://www.openbl.org/) last 24 hours IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|126 unique IPs|updated every 1 hour  from [this link](http://www.openbl.org/lists/base_1days.txt)
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
[proxyrss](#proxyrss)|[proxyrss.com](http://www.proxyrss.com) open proxies syndicated from multiple sources.|ipv4 hash:ip|1735 unique IPs|updated every 4 hours  from [this link](http://www.proxyrss.com/proxylists/all.gz)
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
[sorbs_web](#sorbs_web)|[Sorbs.net](https://www.sorbs.net/) WEB exploits, extracted from deltas.|ipv4 hash:net|626 subnets, 627 unique IPs|
[spamhaus_drop](#spamhaus_drop)|[Spamhaus.org](http://www.spamhaus.org) DROP list (according to their site this list should be dropped at tier-1 ISPs globaly) - **excellent list**|ipv4 hash:net|653 subnets, 18340608 unique IPs|updated every 12 hours  from [this link](http://www.spamhaus.org/drop/drop.txt)
[spamhaus_edrop](#spamhaus_edrop)|[Spamhaus.org](http://www.spamhaus.org) EDROP (extended matches that should be used with DROP) - **excellent list**|ipv4 hash:net|56 subnets, 487424 unique IPs|updated every 12 hours  from [this link](http://www.spamhaus.org/drop/edrop.txt)
[sslbl](#sslbl)|[Abuse.ch SSL Blacklist](https://sslbl.abuse.ch/) bad SSL traffic related to malware or botnet activities - **excellent list**|ipv4 hash:ip|370 unique IPs|updated every 30 mins  from [this link](https://sslbl.abuse.ch/blacklist/sslipblacklist.csv)
stopforumspam_180d|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 180 days)|ipv4 hash:ip|disabled|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/listed_ip_180.zip)
[stopforumspam_1d](#stopforumspam_1d)|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers in the last 24 hours - **excellent list**|ipv4 hash:ip|6690 unique IPs|updated every 1 hour  from [this link](http://www.stopforumspam.com/downloads/listed_ip_1.zip)
[stopforumspam_30d](#stopforumspam_30d)|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 30 days)|ipv4 hash:ip|94309 unique IPs|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/listed_ip_30.zip)
stopforumspam_365d|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 365 days)|ipv4 hash:ip|disabled|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/listed_ip_365.zip)
[stopforumspam_7d](#stopforumspam_7d)|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 7 days)|ipv4 hash:ip|29017 unique IPs|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/listed_ip_7.zip)
stopforumspam_90d|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 90 days)|ipv4 hash:ip|disabled|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/listed_ip_90.zip)
stopforumspam_ever|[StopForumSpam.com](http://www.stopforumspam.com) all IPs used by forum spammers, **ever** (normally you don't want to use this ipset, use the hourly one which includes last 24 hours IPs or the 7 days one)|ipv4 hash:ip|disabled|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/bannedips.zip)
[tor_exits](#tor_exits)|[TorProject.org](https://www.torproject.org) list of all current TOR exit points (TorDNSEL)|ipv4 hash:ip|1101 unique IPs|updated every 30 mins  from [this link](https://check.torproject.org/exit-addresses)
[virbl](#virbl)|[VirBL](http://virbl.bit.nl/) is a project of which the idea was born during the RIPE-48 meeting. The plan was to get reports of virusscanning mailservers, and put the IP-addresses that were reported to send viruses on a blacklist.|ipv4 hash:ip|22 unique IPs|updated every 1 hour  from [this link](http://virbl.bit.nl/download/virbl.dnsbl.bit.nl.txt)
[voipbl](#voipbl)|[VoIPBL.org](http://www.voipbl.org/) a distributed VoIP blacklist that is aimed to protects against VoIP Fraud and minimizing abuse for network that have publicly accessible PBX's. Several algorithms, external sources and manual confirmation are used before they categorize something as an attack and determine the threat level.|ipv4 hash:net|10586 subnets, 10998 unique IPs|updated every 4 hours  from [this link](http://www.voipbl.org/update/)
[xroxy](#xroxy)|[xroxy.com](http://www.xroxy.com) open proxies (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|2174 unique IPs|updated every 1 hour  from [this link](http://www.xroxy.com/proxyrss.xml)
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
[firehol_level1](#firehol_level1)|5137|688854747|6389|0.0%|3.3%|
[dragon_http](#dragon_http)|1021|268288|6152|2.2%|3.2%|
[dshield](#dshield)|20|5120|5120|100.0%|2.7%|
[firehol_level3](#firehol_level3)|109170|9626833|4814|0.0%|2.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|4185|0.0%|2.2%|
[et_block](#et_block)|1000|18343756|3752|0.0%|1.9%|
[openbl_30d](#openbl_30d)|2792|2792|2772|99.2%|1.4%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|1385|0.0%|0.7%|
[shunlist](#shunlist)|1185|1185|1165|98.3%|0.6%|
[firehol_level2](#firehol_level2)|20803|32382|1097|3.3%|0.5%|
[et_compromised](#et_compromised)|1704|1704|1084|63.6%|0.5%|
[bruteforceblocker](#bruteforceblocker)|1697|1697|1071|63.1%|0.5%|
[blocklist_de](#blocklist_de)|27144|27144|1054|3.8%|0.5%|
[dragon_sshpauth](#dragon_sshpauth)|1595|1659|867|52.2%|0.4%|
[blocklist_de_ssh](#blocklist_de_ssh)|1969|1969|857|43.5%|0.4%|
[openbl_7d](#openbl_7d)|629|629|622|98.8%|0.3%|
[ciarmy](#ciarmy)|416|416|400|96.1%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|293|0.0%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|278|0.0%|0.1%|
[voipbl](#voipbl)|10586|10998|176|1.6%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|168|0.1%|0.0%|
[openbl_1d](#openbl_1d)|126|126|120|95.2%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13852|13852|118|0.8%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9136|9136|107|1.1%|0.0%|
[sorbs_spam](#sorbs_spam)|64701|65536|91|0.1%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|91|0.1%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|91|0.1%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|88|0.3%|0.0%|
[sslbl](#sslbl)|370|370|65|17.5%|0.0%|
[zeus](#zeus)|230|230|61|26.5%|0.0%|
[firehol_anonymous](#firehol_anonymous)|19294|83353|57|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|17849|17849|45|0.2%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6690|6690|43|0.6%|0.0%|
[et_tor](#et_tor)|6500|6500|42|0.6%|0.0%|
[dm_tor](#dm_tor)|6455|6455|42|0.6%|0.0%|
[bm_tor](#bm_tor)|6338|6338|42|0.6%|0.0%|
[nixspam](#nixspam)|18020|18020|41|0.2%|0.0%|
[firehol_proxies](#firehol_proxies)|12828|13116|38|0.2%|0.0%|
[zeus_badips](#zeus_badips)|202|202|37|18.3%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|170|170|35|20.5%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2719|2719|31|1.1%|0.0%|
[tor_exits](#tor_exits)|1101|1101|30|2.7%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|29|5.5%|0.0%|
[dragon_vncprobe](#dragon_vncprobe)|87|87|27|31.0%|0.0%|
[iw_spamlist](#iw_spamlist)|3787|3787|24|0.6%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|2979|2979|21|0.7%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|84|84|20|23.8%|0.0%|
[php_commenters](#php_commenters)|458|458|19|4.1%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|15|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|14|0.0%|0.0%|
[php_harvesters](#php_harvesters)|408|408|12|2.9%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2473|2473|12|0.4%|0.0%|
[malc0de](#malc0de)|276|276|9|3.2%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|8|0.6%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|1525|1525|8|0.5%|0.0%|
[php_dictionary](#php_dictionary)|737|737|7|0.9%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|6|0.4%|0.0%|
[xroxy](#xroxy)|2174|2174|5|0.2%|0.0%|
[php_spammers](#php_spammers)|735|735|5|0.6%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7952|7952|4|0.0%|0.0%|
[et_botcc](#et_botcc)|505|505|4|0.7%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2855|2855|3|0.1%|0.0%|
[proxz](#proxz)|1356|1356|3|0.2%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|121|121|3|2.4%|0.0%|
[nt_malware_irc](#nt_malware_irc)|43|43|2|4.6%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|2|0.3%|0.0%|
[feodo](#feodo)|105|105|2|1.9%|0.0%|
[sorbs_web](#sorbs_web)|626|627|1|0.1%|0.0%|
[proxyrss](#proxyrss)|1735|1735|1|0.0%|0.0%|
[nt_malware_http](#nt_malware_http)|69|69|1|1.4%|0.0%|

## blocklist_de

[Blocklist.de](https://www.blocklist.de/) IPs that have been detected by fail2ban in the last 48 hours - **excellent list**

Source is downloaded from [this link](http://lists.blocklist.de/lists/all.txt).

The last time downloaded was found to be dated: Fri Jun 12 08:14:03 UTC 2015.

The ipset `blocklist_de` has **27144** entries, **27144** unique IPs.

The following table shows the overlaps of `blocklist_de` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de`.
- ` this % ` is the percentage **of this ipset (`blocklist_de`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|20803|32382|27144|83.8%|100.0%|
[blocklist_de_mail](#blocklist_de_mail)|17849|17849|17849|100.0%|65.7%|
[blocklist_de_apache](#blocklist_de_apache)|13852|13852|13849|99.9%|51.0%|
[firehol_level3](#firehol_level3)|109170|9626833|3685|0.0%|13.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|3285|0.0%|12.1%|
[blocklist_de_bots](#blocklist_de_bots)|2979|2979|2979|100.0%|10.9%|
[blocklist_de_imap](#blocklist_de_imap)|2719|2719|2710|99.6%|9.9%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|2631|2.7%|9.6%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2473|2473|2472|99.9%|9.1%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|2365|8.1%|8.7%|
[blocklist_de_ssh](#blocklist_de_ssh)|1969|1969|1947|98.8%|7.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|1584|0.0%|5.8%|
[blocklist_de_ftp](#blocklist_de_ftp)|1525|1525|1513|99.2%|5.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|1482|0.0%|5.4%|
[stopforumspam_1d](#stopforumspam_1d)|6690|6690|1467|21.9%|5.4%|
[sorbs_spam](#sorbs_spam)|64701|65536|1099|1.6%|4.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|1091|1.6%|4.0%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|1091|1.6%|4.0%|
[alienvault_reputation](#alienvault_reputation)|189146|189146|1054|0.5%|3.8%|
[openbl_60d](#openbl_60d)|6960|6960|733|10.5%|2.7%|
[firehol_anonymous](#firehol_anonymous)|19294|83353|673|0.8%|2.4%|
[dragon_sshpauth](#dragon_sshpauth)|1595|1659|651|39.2%|2.3%|
[firehol_proxies](#firehol_proxies)|12828|13116|650|4.9%|2.3%|
[openbl_30d](#openbl_30d)|2792|2792|639|22.8%|2.3%|
[bruteforceblocker](#bruteforceblocker)|1697|1697|559|32.9%|2.0%|
[et_compromised](#et_compromised)|1704|1704|540|31.6%|1.9%|
[nixspam](#nixspam)|18020|18020|494|2.7%|1.8%|
[ri_web_proxies](#ri_web_proxies)|7952|7952|468|5.8%|1.7%|
[openbl_7d](#openbl_7d)|629|629|376|59.7%|1.3%|
[shunlist](#shunlist)|1185|1185|351|29.6%|1.2%|
[proxyrss](#proxyrss)|1735|1735|232|13.3%|0.8%|
[xroxy](#xroxy)|2174|2174|224|10.3%|0.8%|
[firehol_level1](#firehol_level1)|5137|688854747|217|0.0%|0.7%|
[et_block](#et_block)|1000|18343756|207|0.0%|0.7%|
[snort_ipfilter](#snort_ipfilter)|9136|9136|206|2.2%|0.7%|
[proxz](#proxz)|1356|1356|196|14.4%|0.7%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|188|0.0%|0.6%|
[blocklist_de_strongips](#blocklist_de_strongips)|170|170|170|100.0%|0.6%|
[iw_spamlist](#iw_spamlist)|3787|3787|122|3.2%|0.4%|
[php_dictionary](#php_dictionary)|737|737|115|15.6%|0.4%|
[openbl_1d](#openbl_1d)|126|126|111|88.0%|0.4%|
[php_commenters](#php_commenters)|458|458|106|23.1%|0.3%|
[php_spammers](#php_spammers)|735|735|105|14.2%|0.3%|
[dshield](#dshield)|20|5120|88|1.7%|0.3%|
[sorbs_web](#sorbs_web)|626|627|71|11.3%|0.2%|
[ri_connect_proxies](#ri_connect_proxies)|2855|2855|69|2.4%|0.2%|
[blocklist_de_sip](#blocklist_de_sip)|84|84|65|77.3%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|55|0.0%|0.2%|
[dragon_http](#dragon_http)|1021|268288|48|0.0%|0.1%|
[voipbl](#voipbl)|10586|10998|42|0.3%|0.1%|
[php_harvesters](#php_harvesters)|408|408|36|8.8%|0.1%|
[ciarmy](#ciarmy)|416|416|35|8.4%|0.1%|
[tor_exits](#tor_exits)|1101|1101|18|1.6%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|15|0.0%|0.0%|
[et_tor](#et_tor)|6500|6500|13|0.2%|0.0%|
[dm_tor](#dm_tor)|6455|6455|11|0.1%|0.0%|
[bm_tor](#bm_tor)|6338|6338|11|0.1%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|6|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|5|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|5|0.9%|0.0%|
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

The last time downloaded was found to be dated: Fri Jun 12 07:56:05 UTC 2015.

The ipset `blocklist_de_apache` has **13852** entries, **13852** unique IPs.

The following table shows the overlaps of `blocklist_de_apache` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_apache`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_apache`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_apache`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|20803|32382|13849|42.7%|99.9%|
[blocklist_de](#blocklist_de)|27144|27144|13849|51.0%|99.9%|
[blocklist_de_mail](#blocklist_de_mail)|17849|17849|11059|61.9%|79.8%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2473|2473|2473|100.0%|17.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|2283|0.0%|16.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|1319|0.0%|9.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|1072|0.0%|7.7%|
[firehol_level3](#firehol_level3)|109170|9626833|270|0.0%|1.9%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|186|0.1%|1.3%|
[alienvault_reputation](#alienvault_reputation)|189146|189146|118|0.0%|0.8%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|107|0.3%|0.7%|
[stopforumspam_1d](#stopforumspam_1d)|6690|6690|54|0.8%|0.3%|
[sorbs_spam](#sorbs_spam)|64701|65536|44|0.0%|0.3%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|44|0.0%|0.3%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|44|0.0%|0.3%|
[shunlist](#shunlist)|1185|1185|37|3.1%|0.2%|
[blocklist_de_strongips](#blocklist_de_strongips)|170|170|32|18.8%|0.2%|
[snort_ipfilter](#snort_ipfilter)|9136|9136|30|0.3%|0.2%|
[ciarmy](#ciarmy)|416|416|30|7.2%|0.2%|
[php_commenters](#php_commenters)|458|458|28|6.1%|0.2%|
[blocklist_de_bots](#blocklist_de_bots)|2979|2979|25|0.8%|0.1%|
[firehol_anonymous](#firehol_anonymous)|19294|83353|20|0.0%|0.1%|
[tor_exits](#tor_exits)|1101|1101|18|1.6%|0.1%|
[nixspam](#nixspam)|18020|18020|17|0.0%|0.1%|
[et_tor](#et_tor)|6500|6500|13|0.2%|0.0%|
[dm_tor](#dm_tor)|6455|6455|11|0.1%|0.0%|
[bm_tor](#bm_tor)|6338|6338|11|0.1%|0.0%|
[dragon_http](#dragon_http)|1021|268288|10|0.0%|0.0%|
[et_block](#et_block)|1000|18343756|9|0.0%|0.0%|
[openbl_60d](#openbl_60d)|6960|6960|8|0.1%|0.0%|
[firehol_level1](#firehol_level1)|5137|688854747|7|0.0%|0.0%|
[php_spammers](#php_spammers)|735|735|6|0.8%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|5|0.0%|0.0%|
[openbl_30d](#openbl_30d)|2792|2792|5|0.1%|0.0%|
[php_dictionary](#php_dictionary)|737|737|3|0.4%|0.0%|
[iw_spamlist](#iw_spamlist)|3787|3787|3|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|3|0.0%|0.0%|
[voipbl](#voipbl)|10586|10998|2|0.0%|0.0%|
[php_harvesters](#php_harvesters)|408|408|2|0.4%|0.0%|
[openbl_7d](#openbl_7d)|629|629|2|0.3%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|2|0.0%|0.0%|
[firehol_proxies](#firehol_proxies)|12828|13116|2|0.0%|0.0%|
[dragon_vncprobe](#dragon_vncprobe)|87|87|2|2.2%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|1|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2855|2855|1|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|1|0.1%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.0%|
[dshield](#dshield)|20|5120|1|0.0%|0.0%|

## blocklist_de_bots

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the RFI-Attacks, REG-Bots, IRC-Bots or BadBots (BadBots = he has posted a Spam-Comment on a open Forum or Wiki).

Source is downloaded from [this link](http://lists.blocklist.de/lists/bots.txt).

The last time downloaded was found to be dated: Fri Jun 12 08:14:10 UTC 2015.

The ipset `blocklist_de_bots` has **2979** entries, **2979** unique IPs.

The following table shows the overlaps of `blocklist_de_bots` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_bots`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_bots`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_bots`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|20803|32382|2979|9.1%|100.0%|
[blocklist_de](#blocklist_de)|27144|27144|2979|10.9%|100.0%|
[firehol_level3](#firehol_level3)|109170|9626833|2328|0.0%|78.1%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|2307|2.4%|77.4%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|2194|7.5%|73.6%|
[stopforumspam_1d](#stopforumspam_1d)|6690|6690|1414|21.1%|47.4%|
[firehol_anonymous](#firehol_anonymous)|19294|83353|526|0.6%|17.6%|
[firehol_proxies](#firehol_proxies)|12828|13116|525|4.0%|17.6%|
[ri_web_proxies](#ri_web_proxies)|7952|7952|380|4.7%|12.7%|
[proxyrss](#proxyrss)|1735|1735|232|13.3%|7.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|184|0.0%|6.1%|
[xroxy](#xroxy)|2174|2174|171|7.8%|5.7%|
[proxz](#proxz)|1356|1356|165|12.1%|5.5%|
[blocklist_de_strongips](#blocklist_de_strongips)|170|170|130|76.4%|4.3%|
[php_commenters](#php_commenters)|458|458|87|18.9%|2.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|79|0.0%|2.6%|
[ri_connect_proxies](#ri_connect_proxies)|2855|2855|65|2.2%|2.1%|
[firehol_level1](#firehol_level1)|5137|688854747|60|0.0%|2.0%|
[et_block](#et_block)|1000|18343756|58|0.0%|1.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|53|0.0%|1.7%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|49|0.0%|1.6%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|41|0.0%|1.3%|
[nixspam](#nixspam)|18020|18020|39|0.2%|1.3%|
[sorbs_spam](#sorbs_spam)|64701|65536|26|0.0%|0.8%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|26|0.0%|0.8%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|26|0.0%|0.8%|
[php_harvesters](#php_harvesters)|408|408|26|6.3%|0.8%|
[blocklist_de_apache](#blocklist_de_apache)|13852|13852|25|0.1%|0.8%|
[php_spammers](#php_spammers)|735|735|24|3.2%|0.8%|
[blocklist_de_mail](#blocklist_de_mail)|17849|17849|23|0.1%|0.7%|
[alienvault_reputation](#alienvault_reputation)|189146|189146|21|0.0%|0.7%|
[snort_ipfilter](#snort_ipfilter)|9136|9136|19|0.2%|0.6%|
[php_dictionary](#php_dictionary)|737|737|17|2.3%|0.5%|
[dshield](#dshield)|20|5120|8|0.1%|0.2%|
[sorbs_web](#sorbs_web)|626|627|6|0.9%|0.2%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|4|0.7%|0.1%|
[iw_spamlist](#iw_spamlist)|3787|3787|4|0.1%|0.1%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|4|0.6%|0.1%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|3|0.0%|0.1%|
[dragon_http](#dragon_http)|1021|268288|3|0.0%|0.1%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|2|0.1%|0.0%|
[voipbl](#voipbl)|10586|10998|1|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.0%|

## blocklist_de_bruteforce

[Blocklist.de](https://www.blocklist.de/) All IPs which attacks Joomlas, Wordpress and other Web-Logins with Brute-Force Logins.

Source is downloaded from [this link](http://lists.blocklist.de/lists/bruteforcelogin.txt).

The last time downloaded was found to be dated: Fri Jun 12 07:56:11 UTC 2015.

The ipset `blocklist_de_bruteforce` has **2473** entries, **2473** unique IPs.

The following table shows the overlaps of `blocklist_de_bruteforce` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_bruteforce`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_bruteforce`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_bruteforce`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de_apache](#blocklist_de_apache)|13852|13852|2473|17.8%|100.0%|
[firehol_level2](#firehol_level2)|20803|32382|2472|7.6%|99.9%|
[blocklist_de](#blocklist_de)|27144|27144|2472|9.1%|99.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|190|0.0%|7.6%|
[firehol_level3](#firehol_level3)|109170|9626833|77|0.0%|3.1%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|57|0.0%|2.3%|
[sorbs_spam](#sorbs_spam)|64701|65536|44|0.0%|1.7%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|44|0.0%|1.7%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|44|0.0%|1.7%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|40|0.1%|1.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|39|0.0%|1.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|33|0.0%|1.3%|
[snort_ipfilter](#snort_ipfilter)|9136|9136|28|0.3%|1.1%|
[stopforumspam_1d](#stopforumspam_1d)|6690|6690|21|0.3%|0.8%|
[tor_exits](#tor_exits)|1101|1101|16|1.4%|0.6%|
[firehol_anonymous](#firehol_anonymous)|19294|83353|16|0.0%|0.6%|
[nixspam](#nixspam)|18020|18020|15|0.0%|0.6%|
[alienvault_reputation](#alienvault_reputation)|189146|189146|12|0.0%|0.4%|
[et_tor](#et_tor)|6500|6500|10|0.1%|0.4%|
[dm_tor](#dm_tor)|6455|6455|8|0.1%|0.3%|
[bm_tor](#bm_tor)|6338|6338|8|0.1%|0.3%|
[blocklist_de_strongips](#blocklist_de_strongips)|170|170|8|4.7%|0.3%|
[php_spammers](#php_spammers)|735|735|6|0.8%|0.2%|
[php_commenters](#php_commenters)|458|458|6|1.3%|0.2%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|5|0.0%|0.2%|
[firehol_level1](#firehol_level1)|5137|688854747|5|0.0%|0.2%|
[et_block](#et_block)|1000|18343756|5|0.0%|0.2%|
[dragon_http](#dragon_http)|1021|268288|4|0.0%|0.1%|
[php_dictionary](#php_dictionary)|737|737|3|0.4%|0.1%|
[iw_spamlist](#iw_spamlist)|3787|3787|3|0.0%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|2|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|2|0.0%|0.0%|
[shunlist](#shunlist)|1185|1185|1|0.0%|0.0%|
[php_harvesters](#php_harvesters)|408|408|1|0.2%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.0%|

## blocklist_de_ftp

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours for attacks on the Service FTP.

Source is downloaded from [this link](http://lists.blocklist.de/lists/ftp.txt).

The last time downloaded was found to be dated: Fri Jun 12 07:56:06 UTC 2015.

The ipset `blocklist_de_ftp` has **1525** entries, **1525** unique IPs.

The following table shows the overlaps of `blocklist_de_ftp` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_ftp`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_ftp`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_ftp`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|20803|32382|1513|4.6%|99.2%|
[blocklist_de](#blocklist_de)|27144|27144|1513|5.5%|99.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|111|0.0%|7.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|27|0.0%|1.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|21|0.0%|1.3%|
[firehol_level3](#firehol_level3)|109170|9626833|18|0.0%|1.1%|
[sorbs_spam](#sorbs_spam)|64701|65536|15|0.0%|0.9%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|15|0.0%|0.9%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|15|0.0%|0.9%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|12|0.0%|0.7%|
[nixspam](#nixspam)|18020|18020|11|0.0%|0.7%|
[alienvault_reputation](#alienvault_reputation)|189146|189146|8|0.0%|0.5%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|7|0.0%|0.4%|
[dragon_http](#dragon_http)|1021|268288|6|0.0%|0.3%|
[firehol_anonymous](#firehol_anonymous)|19294|83353|4|0.0%|0.2%|
[stopforumspam_1d](#stopforumspam_1d)|6690|6690|3|0.0%|0.1%|
[php_harvesters](#php_harvesters)|408|408|3|0.7%|0.1%|
[openbl_60d](#openbl_60d)|6960|6960|2|0.0%|0.1%|
[iw_spamlist](#iw_spamlist)|3787|3787|2|0.0%|0.1%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|2|0.0%|0.1%|
[sorbs_web](#sorbs_web)|626|627|1|0.1%|0.0%|
[php_spammers](#php_spammers)|735|735|1|0.1%|0.0%|
[php_dictionary](#php_dictionary)|737|737|1|0.1%|0.0%|
[openbl_7d](#openbl_7d)|629|629|1|0.1%|0.0%|
[openbl_30d](#openbl_30d)|2792|2792|1|0.0%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.0%|

## blocklist_de_imap

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours for attacks on the Service imap, sasl, pop3, etc.

Source is downloaded from [this link](http://lists.blocklist.de/lists/imap.txt).

The last time downloaded was found to be dated: Fri Jun 12 07:56:06 UTC 2015.

The ipset `blocklist_de_imap` has **2719** entries, **2719** unique IPs.

The following table shows the overlaps of `blocklist_de_imap` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_imap`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_imap`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_imap`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|20803|32382|2710|8.3%|99.6%|
[blocklist_de_mail](#blocklist_de_mail)|17849|17849|2710|15.1%|99.6%|
[blocklist_de](#blocklist_de)|27144|27144|2710|9.9%|99.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|285|0.0%|10.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|78|0.0%|2.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|61|0.0%|2.2%|
[firehol_level3](#firehol_level3)|109170|9626833|36|0.0%|1.3%|
[alienvault_reputation](#alienvault_reputation)|189146|189146|31|0.0%|1.1%|
[sorbs_spam](#sorbs_spam)|64701|65536|29|0.0%|1.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|28|0.0%|1.0%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|28|0.0%|1.0%|
[nixspam](#nixspam)|18020|18020|25|0.1%|0.9%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|15|0.0%|0.5%|
[openbl_60d](#openbl_60d)|6960|6960|15|0.2%|0.5%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|14|0.0%|0.5%|
[firehol_level1](#firehol_level1)|5137|688854747|14|0.0%|0.5%|
[et_block](#et_block)|1000|18343756|14|0.0%|0.5%|
[openbl_30d](#openbl_30d)|2792|2792|9|0.3%|0.3%|
[dragon_http](#dragon_http)|1021|268288|7|0.0%|0.2%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|6|0.0%|0.2%|
[openbl_7d](#openbl_7d)|629|629|5|0.7%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|4|0.0%|0.1%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|4|0.0%|0.1%|
[et_compromised](#et_compromised)|1704|1704|4|0.2%|0.1%|
[bruteforceblocker](#bruteforceblocker)|1697|1697|4|0.2%|0.1%|
[iw_spamlist](#iw_spamlist)|3787|3787|3|0.0%|0.1%|
[stopforumspam_1d](#stopforumspam_1d)|6690|6690|2|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9136|9136|2|0.0%|0.0%|
[shunlist](#shunlist)|1185|1185|2|0.1%|0.0%|
[php_harvesters](#php_harvesters)|408|408|2|0.4%|0.0%|
[voipbl](#voipbl)|10586|10998|1|0.0%|0.0%|
[virbl](#virbl)|22|22|1|4.5%|0.0%|
[openbl_1d](#openbl_1d)|126|126|1|0.7%|0.0%|
[dragon_vncprobe](#dragon_vncprobe)|87|87|1|1.1%|0.0%|
[dragon_sshpauth](#dragon_sshpauth)|1595|1659|1|0.0%|0.0%|
[ciarmy](#ciarmy)|416|416|1|0.2%|0.0%|

## blocklist_de_mail

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service Mail, Postfix.

Source is downloaded from [this link](http://lists.blocklist.de/lists/mail.txt).

The last time downloaded was found to be dated: Fri Jun 12 08:14:06 UTC 2015.

The ipset `blocklist_de_mail` has **17849** entries, **17849** unique IPs.

The following table shows the overlaps of `blocklist_de_mail` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_mail`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_mail`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_mail`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|20803|32382|17849|55.1%|100.0%|
[blocklist_de](#blocklist_de)|27144|27144|17849|65.7%|100.0%|
[blocklist_de_apache](#blocklist_de_apache)|13852|13852|11059|79.8%|61.9%|
[blocklist_de_imap](#blocklist_de_imap)|2719|2719|2710|99.6%|15.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|2581|0.0%|14.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|1420|0.0%|7.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|1238|0.0%|6.9%|
[sorbs_spam](#sorbs_spam)|64701|65536|1010|1.5%|5.6%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|1002|1.5%|5.6%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|1002|1.5%|5.6%|
[nixspam](#nixspam)|18020|18020|426|2.3%|2.3%|
[firehol_level3](#firehol_level3)|109170|9626833|386|0.0%|2.1%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|253|0.2%|1.4%|
[snort_ipfilter](#snort_ipfilter)|9136|9136|159|1.7%|0.8%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|135|0.4%|0.7%|
[firehol_anonymous](#firehol_anonymous)|19294|83353|125|0.1%|0.7%|
[firehol_proxies](#firehol_proxies)|12828|13116|123|0.9%|0.6%|
[iw_spamlist](#iw_spamlist)|3787|3787|113|2.9%|0.6%|
[php_dictionary](#php_dictionary)|737|737|94|12.7%|0.5%|
[ri_web_proxies](#ri_web_proxies)|7952|7952|87|1.0%|0.4%|
[php_spammers](#php_spammers)|735|735|73|9.9%|0.4%|
[sorbs_web](#sorbs_web)|626|627|64|10.2%|0.3%|
[xroxy](#xroxy)|2174|2174|53|2.4%|0.2%|
[stopforumspam_1d](#stopforumspam_1d)|6690|6690|46|0.6%|0.2%|
[alienvault_reputation](#alienvault_reputation)|189146|189146|45|0.0%|0.2%|
[proxz](#proxz)|1356|1356|31|2.2%|0.1%|
[php_commenters](#php_commenters)|458|458|29|6.3%|0.1%|
[firehol_level1](#firehol_level1)|5137|688854747|25|0.0%|0.1%|
[et_block](#et_block)|1000|18343756|24|0.0%|0.1%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|23|0.0%|0.1%|
[blocklist_de_bots](#blocklist_de_bots)|2979|2979|23|0.7%|0.1%|
[blocklist_de_strongips](#blocklist_de_strongips)|170|170|21|12.3%|0.1%|
[openbl_60d](#openbl_60d)|6960|6960|18|0.2%|0.1%|
[openbl_30d](#openbl_30d)|2792|2792|12|0.4%|0.0%|
[dragon_http](#dragon_http)|1021|268288|12|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|10|0.0%|0.0%|
[openbl_7d](#openbl_7d)|629|629|6|0.9%|0.0%|
[php_harvesters](#php_harvesters)|408|408|5|1.2%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|5|0.0%|0.0%|
[et_compromised](#et_compromised)|1704|1704|4|0.2%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1697|1697|4|0.2%|0.0%|
[shunlist](#shunlist)|1185|1185|3|0.2%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2855|2855|3|0.1%|0.0%|
[et_tor](#et_tor)|6500|6500|3|0.0%|0.0%|
[dm_tor](#dm_tor)|6455|6455|3|0.0%|0.0%|
[ciarmy](#ciarmy)|416|416|3|0.7%|0.0%|
[bm_tor](#bm_tor)|6338|6338|3|0.0%|0.0%|
[voipbl](#voipbl)|10586|10998|2|0.0%|0.0%|
[tor_exits](#tor_exits)|1101|1101|2|0.1%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|2|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|2|0.0%|0.0%|
[dragon_vncprobe](#dragon_vncprobe)|87|87|2|2.2%|0.0%|
[virbl](#virbl)|22|22|1|4.5%|0.0%|
[sorbs_socks](#sorbs_socks)|7|7|1|14.2%|0.0%|
[sorbs_misc](#sorbs_misc)|7|7|1|14.2%|0.0%|
[sorbs_http](#sorbs_http)|7|7|1|14.2%|0.0%|
[openbl_1d](#openbl_1d)|126|126|1|0.7%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|1|0.1%|0.0%|
[iw_wormlist](#iw_wormlist)|34|34|1|2.9%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|1|0.1%|0.0%|
[dragon_sshpauth](#dragon_sshpauth)|1595|1659|1|0.0%|0.0%|

## blocklist_de_sip

[Blocklist.de](https://www.blocklist.de/) All IP addresses that tried to login in a SIP, VOIP or Asterisk Server and are included in the IPs list from [infiltrated.net](www.infiltrated.net)

Source is downloaded from [this link](http://lists.blocklist.de/lists/sip.txt).

The last time downloaded was found to be dated: Fri Jun 12 08:09:53 UTC 2015.

The ipset `blocklist_de_sip` has **84** entries, **84** unique IPs.

The following table shows the overlaps of `blocklist_de_sip` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_sip`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_sip`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_sip`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|20803|32382|65|0.2%|77.3%|
[blocklist_de](#blocklist_de)|27144|27144|65|0.2%|77.3%|
[voipbl](#voipbl)|10586|10998|35|0.3%|41.6%|
[alienvault_reputation](#alienvault_reputation)|189146|189146|20|0.0%|23.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|15|0.0%|17.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|5|0.0%|5.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|4|0.0%|4.7%|
[firehol_level3](#firehol_level3)|109170|9626833|4|0.0%|4.7%|
[dragon_http](#dragon_http)|1021|268288|3|0.0%|3.5%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|2|0.0%|2.3%|
[shunlist](#shunlist)|1185|1185|2|0.1%|2.3%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|2|0.0%|2.3%|
[firehol_level1](#firehol_level1)|5137|688854747|2|0.0%|2.3%|
[et_block](#et_block)|1000|18343756|2|0.0%|2.3%|
[et_botcc](#et_botcc)|505|505|1|0.1%|1.1%|

## blocklist_de_ssh

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service SSH.

Source is downloaded from [this link](http://lists.blocklist.de/lists/ssh.txt).

The last time downloaded was found to be dated: Fri Jun 12 07:56:03 UTC 2015.

The ipset `blocklist_de_ssh` has **1969** entries, **1969** unique IPs.

The following table shows the overlaps of `blocklist_de_ssh` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_ssh`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_ssh`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_ssh`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|20803|32382|1947|6.0%|98.8%|
[blocklist_de](#blocklist_de)|27144|27144|1947|7.1%|98.8%|
[alienvault_reputation](#alienvault_reputation)|189146|189146|857|0.4%|43.5%|
[firehol_level3](#firehol_level3)|109170|9626833|822|0.0%|41.7%|
[openbl_60d](#openbl_60d)|6960|6960|706|10.1%|35.8%|
[dragon_sshpauth](#dragon_sshpauth)|1595|1659|650|39.1%|33.0%|
[openbl_30d](#openbl_30d)|2792|2792|621|22.2%|31.5%|
[bruteforceblocker](#bruteforceblocker)|1697|1697|556|32.7%|28.2%|
[et_compromised](#et_compromised)|1704|1704|537|31.5%|27.2%|
[openbl_7d](#openbl_7d)|629|629|369|58.6%|18.7%|
[shunlist](#shunlist)|1185|1185|309|26.0%|15.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|188|0.0%|9.5%|
[firehol_level1](#firehol_level1)|5137|688854747|124|0.0%|6.2%|
[et_block](#et_block)|1000|18343756|114|0.0%|5.7%|
[openbl_1d](#openbl_1d)|126|126|110|87.3%|5.5%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|109|0.0%|5.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|96|0.0%|4.8%|
[dshield](#dshield)|20|5120|79|1.5%|4.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|44|0.0%|2.2%|
[blocklist_de_strongips](#blocklist_de_strongips)|170|170|28|16.4%|1.4%|
[dragon_http](#dragon_http)|1021|268288|13|0.0%|0.6%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|11|0.0%|0.5%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|7|0.0%|0.3%|
[sorbs_spam](#sorbs_spam)|64701|65536|4|0.0%|0.2%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|4|0.0%|0.2%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|4|0.0%|0.2%|
[ciarmy](#ciarmy)|416|416|4|0.9%|0.2%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|3|0.0%|0.1%|
[voipbl](#voipbl)|10586|10998|2|0.0%|0.1%|
[ri_web_proxies](#ri_web_proxies)|7952|7952|1|0.0%|0.0%|
[php_spammers](#php_spammers)|735|735|1|0.1%|0.0%|
[php_harvesters](#php_harvesters)|408|408|1|0.2%|0.0%|
[php_commenters](#php_commenters)|458|458|1|0.2%|0.0%|
[nixspam](#nixspam)|18020|18020|1|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|1|0.0%|0.0%|
[firehol_proxies](#firehol_proxies)|12828|13116|1|0.0%|0.0%|
[firehol_anonymous](#firehol_anonymous)|19294|83353|1|0.0%|0.0%|
[dragon_vncprobe](#dragon_vncprobe)|87|87|1|1.1%|0.0%|

## blocklist_de_strongips

[Blocklist.de](https://www.blocklist.de/) All IPs which are older then 2 month and have more then 5.000 attacks.

Source is downloaded from [this link](http://lists.blocklist.de/lists/strongips.txt).

The last time downloaded was found to be dated: Fri Jun 12 07:56:10 UTC 2015.

The ipset `blocklist_de_strongips` has **170** entries, **170** unique IPs.

The following table shows the overlaps of `blocklist_de_strongips` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_strongips`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_strongips`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_strongips`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|20803|32382|170|0.5%|100.0%|
[blocklist_de](#blocklist_de)|27144|27144|170|0.6%|100.0%|
[firehol_level3](#firehol_level3)|109170|9626833|156|0.0%|91.7%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|130|0.1%|76.4%|
[blocklist_de_bots](#blocklist_de_bots)|2979|2979|130|4.3%|76.4%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|116|0.3%|68.2%|
[stopforumspam_1d](#stopforumspam_1d)|6690|6690|100|1.4%|58.8%|
[php_commenters](#php_commenters)|458|458|44|9.6%|25.8%|
[alienvault_reputation](#alienvault_reputation)|189146|189146|35|0.0%|20.5%|
[blocklist_de_apache](#blocklist_de_apache)|13852|13852|32|0.2%|18.8%|
[blocklist_de_ssh](#blocklist_de_ssh)|1969|1969|28|1.4%|16.4%|
[openbl_60d](#openbl_60d)|6960|6960|24|0.3%|14.1%|
[openbl_30d](#openbl_30d)|2792|2792|23|0.8%|13.5%|
[openbl_7d](#openbl_7d)|629|629|22|3.4%|12.9%|
[blocklist_de_mail](#blocklist_de_mail)|17849|17849|21|0.1%|12.3%|
[firehol_level1](#firehol_level1)|5137|688854747|20|0.0%|11.7%|
[dragon_sshpauth](#dragon_sshpauth)|1595|1659|20|1.2%|11.7%|
[shunlist](#shunlist)|1185|1185|19|1.6%|11.1%|
[openbl_1d](#openbl_1d)|126|126|18|14.2%|10.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|17|0.0%|10.0%|
[et_block](#et_block)|1000|18343756|14|0.0%|8.2%|
[dshield](#dshield)|20|5120|12|0.2%|7.0%|
[php_spammers](#php_spammers)|735|735|10|1.3%|5.8%|
[firehol_proxies](#firehol_proxies)|12828|13116|9|0.0%|5.2%|
[firehol_anonymous](#firehol_anonymous)|19294|83353|9|0.0%|5.2%|
[ri_web_proxies](#ri_web_proxies)|7952|7952|8|0.1%|4.7%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2473|2473|8|0.3%|4.7%|
[xroxy](#xroxy)|2174|2174|7|0.3%|4.1%|
[proxyrss](#proxyrss)|1735|1735|7|0.4%|4.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|7|0.0%|4.1%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|6|0.0%|3.5%|
[proxz](#proxz)|1356|1356|6|0.4%|3.5%|
[php_dictionary](#php_dictionary)|737|737|5|0.6%|2.9%|
[php_harvesters](#php_harvesters)|408|408|3|0.7%|1.7%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|1.7%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|2|0.0%|1.1%|
[sorbs_web](#sorbs_web)|626|627|2|0.3%|1.1%|
[sorbs_spam](#sorbs_spam)|64701|65536|2|0.0%|1.1%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|2|0.0%|1.1%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|2|0.0%|1.1%|
[snort_ipfilter](#snort_ipfilter)|9136|9136|2|0.0%|1.1%|
[nixspam](#nixspam)|18020|18020|2|0.0%|1.1%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|2|0.1%|1.1%|
[dragon_http](#dragon_http)|1021|268288|2|0.0%|1.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|1|0.0%|0.5%|
[et_compromised](#et_compromised)|1704|1704|1|0.0%|0.5%|
[ciarmy](#ciarmy)|416|416|1|0.2%|0.5%|
[bruteforceblocker](#bruteforceblocker)|1697|1697|1|0.0%|0.5%|

## bm_tor

[torstatus.blutmagie.de](https://torstatus.blutmagie.de) list of all TOR network servers

Source is downloaded from [this link](https://torstatus.blutmagie.de/ip_list_all.php/Tor_ip_list_ALL.csv).

The last time downloaded was found to be dated: Fri Jun 12 08:27:04 UTC 2015.

The ipset `bm_tor` has **6338** entries, **6338** unique IPs.

The following table shows the overlaps of `bm_tor` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `bm_tor`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `bm_tor`.
- ` this % ` is the percentage **of this ipset (`bm_tor`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_anonymous](#firehol_anonymous)|19294|83353|6338|7.6%|100.0%|
[dm_tor](#dm_tor)|6455|6455|6278|97.2%|99.0%|
[et_tor](#et_tor)|6500|6500|5700|87.6%|89.9%|
[firehol_level3](#firehol_level3)|109170|9626833|1074|0.0%|16.9%|
[snort_ipfilter](#snort_ipfilter)|9136|9136|1037|11.3%|16.3%|
[tor_exits](#tor_exits)|1101|1101|1004|91.1%|15.8%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|633|0.6%|9.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|621|0.0%|9.7%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|530|1.8%|8.3%|
[firehol_level2](#firehol_level2)|20803|32382|310|0.9%|4.8%|
[stopforumspam_1d](#stopforumspam_1d)|6690|6690|304|4.5%|4.7%|
[firehol_proxies](#firehol_proxies)|12828|13116|234|1.7%|3.6%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|229|43.7%|3.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|186|0.0%|2.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|166|0.0%|2.6%|
[php_commenters](#php_commenters)|458|458|54|11.7%|0.8%|
[alienvault_reputation](#alienvault_reputation)|189146|189146|42|0.0%|0.6%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|22|0.0%|0.3%|
[openbl_60d](#openbl_60d)|6960|6960|20|0.2%|0.3%|
[dragon_http](#dragon_http)|1021|268288|16|0.0%|0.2%|
[blocklist_de_apache](#blocklist_de_apache)|13852|13852|11|0.0%|0.1%|
[blocklist_de](#blocklist_de)|27144|27144|11|0.0%|0.1%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2473|2473|8|0.3%|0.1%|
[php_harvesters](#php_harvesters)|408|408|7|1.7%|0.1%|
[nixspam](#nixspam)|18020|18020|6|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7952|7952|5|0.0%|0.0%|
[php_spammers](#php_spammers)|735|735|5|0.6%|0.0%|
[firehol_level1](#firehol_level1)|5137|688854747|5|0.0%|0.0%|
[sorbs_spam](#sorbs_spam)|64701|65536|4|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|4|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|4|0.0%|0.0%|
[php_dictionary](#php_dictionary)|737|737|4|0.5%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|4|0.0%|0.0%|
[et_block](#et_block)|1000|18343756|4|0.0%|0.0%|
[voipbl](#voipbl)|10586|10998|3|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|3|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|17849|17849|3|0.0%|0.0%|
[xroxy](#xroxy)|2174|2174|2|0.0%|0.0%|
[dshield](#dshield)|20|5120|2|0.0%|0.0%|
[shunlist](#shunlist)|1185|1185|1|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2855|2855|1|0.0%|0.0%|
[proxyrss](#proxyrss)|1735|1735|1|0.0%|0.0%|

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
[firehol_level1](#firehol_level1)|5137|688854747|592708608|86.0%|100.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|4194304|3.0%|0.7%|
[voipbl](#voipbl)|10586|10998|319|2.9%|0.0%|
[iw_spamlist](#iw_spamlist)|3787|3787|5|0.1%|0.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|5|0.0%|0.0%|
[firehol_level3](#firehol_level3)|109170|9626833|3|0.0%|0.0%|
[php_harvesters](#php_harvesters)|408|408|1|0.2%|0.0%|
[php_commenters](#php_commenters)|458|458|1|0.2%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.0%|
[ciarmy](#ciarmy)|416|416|1|0.2%|0.0%|

## bruteforceblocker

[danger.rulez.sk](http://danger.rulez.sk/) IPs detected by [bruteforceblocker](http://danger.rulez.sk/index.php/bruteforceblocker/) (fail2ban alternative for SSH on OpenBSD). This is an automatically generated list from users reporting failed authentication attempts. An IP seems to be included if 3 or more users report it. Its retention pocily seems 30 days.

Source is downloaded from [this link](http://danger.rulez.sk/projects/bruteforceblocker/blist.php).

The last time downloaded was found to be dated: Fri Jun 12 05:54:26 UTC 2015.

The ipset `bruteforceblocker` has **1697** entries, **1697** unique IPs.

The following table shows the overlaps of `bruteforceblocker` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `bruteforceblocker`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `bruteforceblocker`.
- ` this % ` is the percentage **of this ipset (`bruteforceblocker`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level3](#firehol_level3)|109170|9626833|1697|0.0%|100.0%|
[et_compromised](#et_compromised)|1704|1704|1660|97.4%|97.8%|
[alienvault_reputation](#alienvault_reputation)|189146|189146|1071|0.5%|63.1%|
[openbl_60d](#openbl_60d)|6960|6960|965|13.8%|56.8%|
[openbl_30d](#openbl_30d)|2792|2792|905|32.4%|53.3%|
[dragon_sshpauth](#dragon_sshpauth)|1595|1659|639|38.5%|37.6%|
[firehol_level2](#firehol_level2)|20803|32382|561|1.7%|33.0%|
[blocklist_de](#blocklist_de)|27144|27144|559|2.0%|32.9%|
[blocklist_de_ssh](#blocklist_de_ssh)|1969|1969|556|28.2%|32.7%|
[shunlist](#shunlist)|1185|1185|341|28.7%|20.0%|
[openbl_7d](#openbl_7d)|629|629|308|48.9%|18.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|157|0.0%|9.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|87|0.0%|5.1%|
[firehol_level1](#firehol_level1)|5137|688854747|67|0.0%|3.9%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|61|0.0%|3.5%|
[et_block](#et_block)|1000|18343756|61|0.0%|3.5%|
[openbl_1d](#openbl_1d)|126|126|60|47.6%|3.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|53|0.0%|3.1%|
[dshield](#dshield)|20|5120|25|0.4%|1.4%|
[dragon_http](#dragon_http)|1021|268288|13|0.0%|0.7%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|9|0.0%|0.5%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|5|0.0%|0.2%|
[blocklist_de_mail](#blocklist_de_mail)|17849|17849|4|0.0%|0.2%|
[blocklist_de_imap](#blocklist_de_imap)|2719|2719|4|0.1%|0.2%|
[voipbl](#voipbl)|10586|10998|3|0.0%|0.1%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|3|0.0%|0.1%|
[sorbs_spam](#sorbs_spam)|64701|65536|3|0.0%|0.1%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|3|0.0%|0.1%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|3|0.0%|0.1%|
[firehol_proxies](#firehol_proxies)|12828|13116|3|0.0%|0.1%|
[firehol_anonymous](#firehol_anonymous)|19294|83353|3|0.0%|0.1%|
[ciarmy](#ciarmy)|416|416|3|0.7%|0.1%|
[stopforumspam_1d](#stopforumspam_1d)|6690|6690|2|0.0%|0.1%|
[proxz](#proxz)|1356|1356|2|0.1%|0.1%|
[nixspam](#nixspam)|18020|18020|2|0.0%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|2|0.0%|0.1%|
[xroxy](#xroxy)|2174|2174|1|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7952|7952|1|0.0%|0.0%|
[proxyrss](#proxyrss)|1735|1735|1|0.0%|0.0%|
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
[firehol_level3](#firehol_level3)|109170|9626833|416|0.0%|100.0%|
[alienvault_reputation](#alienvault_reputation)|189146|189146|400|0.2%|96.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|70|0.0%|16.8%|
[firehol_level2](#firehol_level2)|20803|32382|36|0.1%|8.6%|
[blocklist_de](#blocklist_de)|27144|27144|35|0.1%|8.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|33|0.0%|7.9%|
[blocklist_de_apache](#blocklist_de_apache)|13852|13852|30|0.2%|7.2%|
[shunlist](#shunlist)|1185|1185|29|2.4%|6.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|21|0.0%|5.0%|
[dragon_http](#dragon_http)|1021|268288|12|0.0%|2.8%|
[firehol_level1](#firehol_level1)|5137|688854747|6|0.0%|1.4%|
[dshield](#dshield)|20|5120|5|0.0%|1.2%|
[blocklist_de_ssh](#blocklist_de_ssh)|1969|1969|4|0.2%|0.9%|
[et_compromised](#et_compromised)|1704|1704|3|0.1%|0.7%|
[bruteforceblocker](#bruteforceblocker)|1697|1697|3|0.1%|0.7%|
[blocklist_de_mail](#blocklist_de_mail)|17849|17849|3|0.0%|0.7%|
[voipbl](#voipbl)|10586|10998|2|0.0%|0.4%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|2|0.0%|0.4%|
[openbl_7d](#openbl_7d)|629|629|2|0.3%|0.4%|
[openbl_60d](#openbl_60d)|6960|6960|2|0.0%|0.4%|
[openbl_30d](#openbl_30d)|2792|2792|2|0.0%|0.4%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|1|0.0%|0.2%|
[openbl_1d](#openbl_1d)|126|126|1|0.7%|0.2%|
[fullbogons](#fullbogons)|3775|670173256|1|0.0%|0.2%|
[et_block](#et_block)|1000|18343756|1|0.0%|0.2%|
[dragon_vncprobe](#dragon_vncprobe)|87|87|1|1.1%|0.2%|
[dragon_sshpauth](#dragon_sshpauth)|1595|1659|1|0.0%|0.2%|
[bogons](#bogons)|13|592708608|1|0.0%|0.2%|
[blocklist_de_strongips](#blocklist_de_strongips)|170|170|1|0.5%|0.2%|
[blocklist_de_imap](#blocklist_de_imap)|2719|2719|1|0.0%|0.2%|

## cleanmx_viruses

[Clean-MX.de](http://support.clean-mx.de/clean-mx/viruses.php) IPs with viruses

Source is downloaded from [this link](http://support.clean-mx.de/clean-mx/xmlviruses.php?sort=id%20desc&response=alive).

The last time downloaded was found to be dated: Thu Jun 11 21:18:50 UTC 2015.

The ipset `cleanmx_viruses` has **121** entries, **121** unique IPs.

The following table shows the overlaps of `cleanmx_viruses` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `cleanmx_viruses`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `cleanmx_viruses`.
- ` this % ` is the percentage **of this ipset (`cleanmx_viruses`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level3](#firehol_level3)|109170|9626833|121|0.0%|100.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|19|0.0%|15.7%|
[malc0de](#malc0de)|276|276|16|5.7%|13.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|6|0.0%|4.9%|
[alienvault_reputation](#alienvault_reputation)|189146|189146|3|0.0%|2.4%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|2|0.1%|1.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|2|0.0%|1.6%|
[snort_ipfilter](#snort_ipfilter)|9136|9136|1|0.0%|0.8%|
[nixspam](#nixspam)|18020|18020|1|0.0%|0.8%|

## dm_tor

[dan.me.uk](https://www.dan.me.uk) dynamic list of TOR nodes

Source is downloaded from [this link](https://www.dan.me.uk/torlist/).

The last time downloaded was found to be dated: Fri Jun 12 08:09:10 UTC 2015.

The ipset `dm_tor` has **6455** entries, **6455** unique IPs.

The following table shows the overlaps of `dm_tor` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `dm_tor`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `dm_tor`.
- ` this % ` is the percentage **of this ipset (`dm_tor`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_anonymous](#firehol_anonymous)|19294|83353|6455|7.7%|100.0%|
[bm_tor](#bm_tor)|6338|6338|6278|99.0%|97.2%|
[et_tor](#et_tor)|6500|6500|5768|88.7%|89.3%|
[firehol_level3](#firehol_level3)|109170|9626833|1088|0.0%|16.8%|
[snort_ipfilter](#snort_ipfilter)|9136|9136|1051|11.5%|16.2%|
[tor_exits](#tor_exits)|1101|1101|1019|92.5%|15.7%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|633|0.6%|9.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|631|0.0%|9.7%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|530|1.8%|8.2%|
[firehol_level2](#firehol_level2)|20803|32382|312|0.9%|4.8%|
[stopforumspam_1d](#stopforumspam_1d)|6690|6690|306|4.5%|4.7%|
[firehol_proxies](#firehol_proxies)|12828|13116|234|1.7%|3.6%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|229|43.7%|3.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|185|0.0%|2.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|169|0.0%|2.6%|
[php_commenters](#php_commenters)|458|458|54|11.7%|0.8%|
[alienvault_reputation](#alienvault_reputation)|189146|189146|42|0.0%|0.6%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|22|0.0%|0.3%|
[openbl_60d](#openbl_60d)|6960|6960|20|0.2%|0.3%|
[dragon_http](#dragon_http)|1021|268288|16|0.0%|0.2%|
[blocklist_de_apache](#blocklist_de_apache)|13852|13852|11|0.0%|0.1%|
[blocklist_de](#blocklist_de)|27144|27144|11|0.0%|0.1%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2473|2473|8|0.3%|0.1%|
[php_harvesters](#php_harvesters)|408|408|7|1.7%|0.1%|
[nixspam](#nixspam)|18020|18020|7|0.0%|0.1%|
[ri_web_proxies](#ri_web_proxies)|7952|7952|5|0.0%|0.0%|
[php_spammers](#php_spammers)|735|735|5|0.6%|0.0%|
[firehol_level1](#firehol_level1)|5137|688854747|5|0.0%|0.0%|
[sorbs_spam](#sorbs_spam)|64701|65536|4|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|4|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|4|0.0%|0.0%|
[php_dictionary](#php_dictionary)|737|737|4|0.5%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|4|0.0%|0.0%|
[et_block](#et_block)|1000|18343756|4|0.0%|0.0%|
[voipbl](#voipbl)|10586|10998|3|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|3|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|17849|17849|3|0.0%|0.0%|
[xroxy](#xroxy)|2174|2174|2|0.0%|0.0%|
[dshield](#dshield)|20|5120|2|0.0%|0.0%|
[shunlist](#shunlist)|1185|1185|1|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2855|2855|1|0.0%|0.0%|
[proxyrss](#proxyrss)|1735|1735|1|0.0%|0.0%|

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
[firehol_level1](#firehol_level1)|5137|688854747|1025|0.0%|0.3%|
[et_block](#et_block)|1000|18343756|1024|0.0%|0.3%|
[dshield](#dshield)|20|5120|768|15.0%|0.2%|
[firehol_level3](#firehol_level3)|109170|9626833|560|0.0%|0.2%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|256|0.0%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|256|0.0%|0.0%|
[openbl_60d](#openbl_60d)|6960|6960|213|3.0%|0.0%|
[openbl_30d](#openbl_30d)|2792|2792|146|5.2%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|108|0.1%|0.0%|
[sorbs_spam](#sorbs_spam)|64701|65536|72|0.1%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|71|0.1%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|71|0.1%|0.0%|
[firehol_level2](#firehol_level2)|20803|32382|60|0.1%|0.0%|
[openbl_7d](#openbl_7d)|629|629|51|8.1%|0.0%|
[blocklist_de](#blocklist_de)|27144|27144|48|0.1%|0.0%|
[firehol_anonymous](#firehol_anonymous)|19294|83353|45|0.0%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|32|0.1%|0.0%|
[firehol_proxies](#firehol_proxies)|12828|13116|32|0.2%|0.0%|
[nixspam](#nixspam)|18020|18020|30|0.1%|0.0%|
[voipbl](#voipbl)|10586|10998|29|0.2%|0.0%|
[shunlist](#shunlist)|1185|1185|26|2.1%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|25|0.0%|0.0%|
[dragon_vncprobe](#dragon_vncprobe)|87|87|24|27.5%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7952|7952|20|0.2%|0.0%|
[et_tor](#et_tor)|6500|6500|16|0.2%|0.0%|
[dm_tor](#dm_tor)|6455|6455|16|0.2%|0.0%|
[bm_tor](#bm_tor)|6338|6338|16|0.2%|0.0%|
[et_compromised](#et_compromised)|1704|1704|13|0.7%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1697|1697|13|0.7%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1969|1969|13|0.6%|0.0%|
[ciarmy](#ciarmy)|416|416|12|2.8%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|17849|17849|12|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9136|9136|11|0.1%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13852|13852|10|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6690|6690|9|0.1%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2719|2719|7|0.2%|0.0%|
[xroxy](#xroxy)|2174|2174|6|0.2%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|6|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|1525|1525|6|0.3%|0.0%|
[tor_exits](#tor_exits)|1101|1101|5|0.4%|0.0%|
[openbl_1d](#openbl_1d)|126|126|5|3.9%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2855|2855|4|0.1%|0.0%|
[proxz](#proxz)|1356|1356|4|0.2%|0.0%|
[proxyrss](#proxyrss)|1735|1735|4|0.2%|0.0%|
[php_commenters](#php_commenters)|458|458|4|0.8%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|4|0.7%|0.0%|
[dragon_sshpauth](#dragon_sshpauth)|1595|1659|4|0.2%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2473|2473|4|0.1%|0.0%|
[zeus_badips](#zeus_badips)|202|202|3|1.4%|0.0%|
[zeus](#zeus)|230|230|3|1.3%|0.0%|
[malc0de](#malc0de)|276|276|3|1.0%|0.0%|
[et_botcc](#et_botcc)|505|505|3|0.5%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|84|84|3|3.5%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|2979|2979|3|0.1%|0.0%|
[php_dictionary](#php_dictionary)|737|737|2|0.2%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|2|0.1%|0.0%|
[iw_spamlist](#iw_spamlist)|3787|3787|2|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|2|0.1%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|170|170|2|1.1%|0.0%|
[sslbl](#sslbl)|370|370|1|0.2%|0.0%|
[sorbs_web](#sorbs_web)|626|627|1|0.1%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|1|0.1%|0.0%|

## dragon_sshpauth

[Dragon Search Group](http://www.dragonresearchgroup.org/) IP address that has been seen attempting to remotely login to a host using SSH password authentication, in the last 7 days. This report lists hosts that are highly suspicious and are likely conducting malicious SSH password authentication attacks.

Source is downloaded from [this link](https://www.dragonresearchgroup.org/insight/sshpwauth.txt).

The last time downloaded was found to be dated: Fri Jun 12 08:04:26 UTC 2015.

The ipset `dragon_sshpauth` has **1595** entries, **1659** unique IPs.

The following table shows the overlaps of `dragon_sshpauth` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `dragon_sshpauth`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `dragon_sshpauth`.
- ` this % ` is the percentage **of this ipset (`dragon_sshpauth`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[alienvault_reputation](#alienvault_reputation)|189146|189146|867|0.4%|52.2%|
[firehol_level3](#firehol_level3)|109170|9626833|862|0.0%|51.9%|
[openbl_60d](#openbl_60d)|6960|6960|784|11.2%|47.2%|
[openbl_30d](#openbl_30d)|2792|2792|702|25.1%|42.3%|
[firehol_level2](#firehol_level2)|20803|32382|652|2.0%|39.3%|
[blocklist_de](#blocklist_de)|27144|27144|651|2.3%|39.2%|
[blocklist_de_ssh](#blocklist_de_ssh)|1969|1969|650|33.0%|39.1%|
[bruteforceblocker](#bruteforceblocker)|1697|1697|639|37.6%|38.5%|
[et_compromised](#et_compromised)|1704|1704|634|37.2%|38.2%|
[shunlist](#shunlist)|1185|1185|381|32.1%|22.9%|
[openbl_7d](#openbl_7d)|629|629|346|55.0%|20.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|125|0.0%|7.5%|
[firehol_level1](#firehol_level1)|5137|688854747|107|0.0%|6.4%|
[et_block](#et_block)|1000|18343756|100|0.0%|6.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|99|0.0%|5.9%|
[openbl_1d](#openbl_1d)|126|126|85|67.4%|5.1%|
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
[nixspam](#nixspam)|18020|18020|1|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|1|0.0%|0.0%|
[ciarmy](#ciarmy)|416|416|1|0.2%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|17849|17849|1|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2719|2719|1|0.0%|0.0%|

## dragon_vncprobe

[Dragon Search Group](http://www.dragonresearchgroup.org/) IP address that has been seen attempting to remotely connect to a host running the VNC application service, in the last 7 days. This report lists hosts that are highly suspicious and are likely conducting malicious VNC probes or VNC brute force attacks.

Source is downloaded from [this link](https://www.dragonresearchgroup.org/insight/vncprobe.txt).

The last time downloaded was found to be dated: Fri Jun 12 08:04:01 UTC 2015.

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
[firehol_level2](#firehol_level2)|20803|32382|5|0.0%|5.7%|
[blocklist_de](#blocklist_de)|27144|27144|5|0.0%|5.7%|
[firehol_level3](#firehol_level3)|109170|9626833|4|0.0%|4.5%|
[et_block](#et_block)|1000|18343756|4|0.0%|4.5%|
[shunlist](#shunlist)|1185|1185|2|0.1%|2.2%|
[firehol_level1](#firehol_level1)|5137|688854747|2|0.0%|2.2%|
[blocklist_de_mail](#blocklist_de_mail)|17849|17849|2|0.0%|2.2%|
[blocklist_de_apache](#blocklist_de_apache)|13852|13852|2|0.0%|2.2%|
[voipbl](#voipbl)|10586|10998|1|0.0%|1.1%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|1|0.0%|1.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|1.1%|
[dshield](#dshield)|20|5120|1|0.0%|1.1%|
[ciarmy](#ciarmy)|416|416|1|0.2%|1.1%|
[blocklist_de_ssh](#blocklist_de_ssh)|1969|1969|1|0.0%|1.1%|
[blocklist_de_imap](#blocklist_de_imap)|2719|2719|1|0.0%|1.1%|

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
[firehol_level1](#firehol_level1)|5137|688854747|5120|0.0%|100.0%|
[alienvault_reputation](#alienvault_reputation)|189146|189146|5120|2.7%|100.0%|
[et_block](#et_block)|1000|18343756|1536|0.0%|30.0%|
[dragon_http](#dragon_http)|1021|268288|768|0.2%|15.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|256|0.0%|5.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|256|0.0%|5.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|256|0.0%|5.0%|
[firehol_level3](#firehol_level3)|109170|9626833|124|0.0%|2.4%|
[firehol_level2](#firehol_level2)|20803|32382|89|0.2%|1.7%|
[blocklist_de](#blocklist_de)|27144|27144|88|0.3%|1.7%|
[openbl_60d](#openbl_60d)|6960|6960|84|1.2%|1.6%|
[shunlist](#shunlist)|1185|1185|83|7.0%|1.6%|
[openbl_30d](#openbl_30d)|2792|2792|80|2.8%|1.5%|
[dragon_sshpauth](#dragon_sshpauth)|1595|1659|80|4.8%|1.5%|
[blocklist_de_ssh](#blocklist_de_ssh)|1969|1969|79|4.0%|1.5%|
[et_compromised](#et_compromised)|1704|1704|29|1.7%|0.5%|
[bruteforceblocker](#bruteforceblocker)|1697|1697|25|1.4%|0.4%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|21|0.0%|0.4%|
[openbl_7d](#openbl_7d)|629|629|21|3.3%|0.4%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|15|0.0%|0.2%|
[blocklist_de_strongips](#blocklist_de_strongips)|170|170|12|7.0%|0.2%|
[stopforumspam_1d](#stopforumspam_1d)|6690|6690|9|0.1%|0.1%|
[blocklist_de_bots](#blocklist_de_bots)|2979|2979|8|0.2%|0.1%|
[openbl_1d](#openbl_1d)|126|126|7|5.5%|0.1%|
[ciarmy](#ciarmy)|416|416|5|1.2%|0.0%|
[firehol_anonymous](#firehol_anonymous)|19294|83353|2|0.0%|0.0%|
[et_tor](#et_tor)|6500|6500|2|0.0%|0.0%|
[dm_tor](#dm_tor)|6455|6455|2|0.0%|0.0%|
[bm_tor](#bm_tor)|6338|6338|2|0.0%|0.0%|
[tor_exits](#tor_exits)|1101|1101|1|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9136|9136|1|0.0%|0.0%|
[php_commenters](#php_commenters)|458|458|1|0.2%|0.0%|
[nixspam](#nixspam)|18020|18020|1|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|1|0.1%|0.0%|
[firehol_proxies](#firehol_proxies)|12828|13116|1|0.0%|0.0%|
[dragon_vncprobe](#dragon_vncprobe)|87|87|1|1.1%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13852|13852|1|0.0%|0.0%|

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
[firehol_level1](#firehol_level1)|5137|688854747|18340171|2.6%|99.9%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|18338560|99.9%|99.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|8532776|2.4%|46.5%|
[firehol_level3](#firehol_level3)|109170|9626833|6933353|72.0%|37.7%|
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
[firehol_level2](#firehol_level2)|20803|32382|270|0.8%|0.0%|
[openbl_60d](#openbl_60d)|6960|6960|244|3.5%|0.0%|
[zeus](#zeus)|230|230|229|99.5%|0.0%|
[blocklist_de](#blocklist_de)|27144|27144|207|0.7%|0.0%|
[zeus_badips](#zeus_badips)|202|202|202|100.0%|0.0%|
[openbl_30d](#openbl_30d)|2792|2792|125|4.4%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1969|1969|114|5.7%|0.0%|
[feodo](#feodo)|105|105|105|100.0%|0.0%|
[shunlist](#shunlist)|1185|1185|101|8.5%|0.0%|
[dragon_sshpauth](#dragon_sshpauth)|1595|1659|100|6.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6690|6690|83|1.2%|0.0%|
[et_compromised](#et_compromised)|1704|1704|65|3.8%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1697|1697|61|3.5%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|2979|2979|58|1.9%|0.0%|
[openbl_7d](#openbl_7d)|629|629|57|9.0%|0.0%|
[sslbl](#sslbl)|370|370|39|10.5%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|30|2.3%|0.0%|
[php_commenters](#php_commenters)|458|458|29|6.3%|0.0%|
[nixspam](#nixspam)|18020|18020|29|0.1%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|17849|17849|24|0.1%|0.0%|
[sorbs_spam](#sorbs_spam)|64701|65536|20|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|20|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|20|0.0%|0.0%|
[voipbl](#voipbl)|10586|10998|18|0.1%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|170|170|14|8.2%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2719|2719|14|0.5%|0.0%|
[palevo](#palevo)|13|13|12|92.3%|0.0%|
[openbl_1d](#openbl_1d)|126|126|12|9.5%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13852|13852|9|0.0%|0.0%|
[firehol_anonymous](#firehol_anonymous)|19294|83353|8|0.0%|0.0%|
[php_dictionary](#php_dictionary)|737|737|6|0.8%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|6|0.4%|0.0%|
[malc0de](#malc0de)|276|276|5|1.8%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|5|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2473|2473|5|0.2%|0.0%|
[php_spammers](#php_spammers)|735|735|4|0.5%|0.0%|
[nt_malware_http](#nt_malware_http)|69|69|4|5.7%|0.0%|
[firehol_proxies](#firehol_proxies)|12828|13116|4|0.0%|0.0%|
[et_tor](#et_tor)|6500|6500|4|0.0%|0.0%|
[dragon_vncprobe](#dragon_vncprobe)|87|87|4|4.5%|0.0%|
[dm_tor](#dm_tor)|6455|6455|4|0.0%|0.0%|
[bm_tor](#bm_tor)|6338|6338|4|0.0%|0.0%|
[nt_malware_irc](#nt_malware_irc)|43|43|3|6.9%|0.0%|
[iw_spamlist](#iw_spamlist)|3787|3787|3|0.0%|0.0%|
[tor_exits](#tor_exits)|1101|1101|2|0.1%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|2|0.3%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|84|84|2|2.3%|0.0%|
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
[firehol_level3](#firehol_level3)|109170|9626833|3|0.0%|0.5%|
[dragon_http](#dragon_http)|1021|268288|3|0.0%|0.5%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|1|0.0%|0.1%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|1|0.0%|0.1%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|1|0.0%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.1%|
[firehol_level1](#firehol_level1)|5137|688854747|1|0.0%|0.1%|
[et_block](#et_block)|1000|18343756|1|0.0%|0.1%|
[blocklist_de_sip](#blocklist_de_sip)|84|84|1|1.1%|0.1%|

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
[firehol_level3](#firehol_level3)|109170|9626833|1677|0.0%|98.4%|
[bruteforceblocker](#bruteforceblocker)|1697|1697|1660|97.8%|97.4%|
[alienvault_reputation](#alienvault_reputation)|189146|189146|1084|0.5%|63.6%|
[openbl_60d](#openbl_60d)|6960|6960|977|14.0%|57.3%|
[openbl_30d](#openbl_30d)|2792|2792|910|32.5%|53.4%|
[dragon_sshpauth](#dragon_sshpauth)|1595|1659|634|38.2%|37.2%|
[firehol_level2](#firehol_level2)|20803|32382|542|1.6%|31.8%|
[blocklist_de](#blocklist_de)|27144|27144|540|1.9%|31.6%|
[blocklist_de_ssh](#blocklist_de_ssh)|1969|1969|537|27.2%|31.5%|
[shunlist](#shunlist)|1185|1185|341|28.7%|20.0%|
[openbl_7d](#openbl_7d)|629|629|305|48.4%|17.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|157|0.0%|9.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|89|0.0%|5.2%|
[firehol_level1](#firehol_level1)|5137|688854747|71|0.0%|4.1%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|65|0.0%|3.8%|
[et_block](#et_block)|1000|18343756|65|0.0%|3.8%|
[openbl_1d](#openbl_1d)|126|126|56|44.4%|3.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|54|0.0%|3.1%|
[dshield](#dshield)|20|5120|29|0.5%|1.7%|
[dragon_http](#dragon_http)|1021|268288|13|0.0%|0.7%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|10|0.0%|0.5%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|5|0.0%|0.2%|
[blocklist_de_mail](#blocklist_de_mail)|17849|17849|4|0.0%|0.2%|
[blocklist_de_imap](#blocklist_de_imap)|2719|2719|4|0.1%|0.2%|
[voipbl](#voipbl)|10586|10998|3|0.0%|0.1%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|3|0.0%|0.1%|
[sorbs_spam](#sorbs_spam)|64701|65536|3|0.0%|0.1%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|3|0.0%|0.1%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|3|0.0%|0.1%|
[firehol_proxies](#firehol_proxies)|12828|13116|3|0.0%|0.1%|
[firehol_anonymous](#firehol_anonymous)|19294|83353|3|0.0%|0.1%|
[ciarmy](#ciarmy)|416|416|3|0.7%|0.1%|
[stopforumspam_1d](#stopforumspam_1d)|6690|6690|2|0.0%|0.1%|
[proxz](#proxz)|1356|1356|2|0.1%|0.1%|
[nixspam](#nixspam)|18020|18020|2|0.0%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|2|0.0%|0.1%|
[xroxy](#xroxy)|2174|2174|1|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7952|7952|1|0.0%|0.0%|
[proxyrss](#proxyrss)|1735|1735|1|0.0%|0.0%|
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
[firehol_anonymous](#firehol_anonymous)|19294|83353|5803|6.9%|89.2%|
[dm_tor](#dm_tor)|6455|6455|5768|89.3%|88.7%|
[bm_tor](#bm_tor)|6338|6338|5700|89.9%|87.6%|
[firehol_level3](#firehol_level3)|109170|9626833|1123|0.0%|17.2%|
[snort_ipfilter](#snort_ipfilter)|9136|9136|1088|11.9%|16.7%|
[tor_exits](#tor_exits)|1101|1101|971|88.1%|14.9%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|651|0.6%|10.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|636|0.0%|9.7%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|547|1.8%|8.4%|
[firehol_level2](#firehol_level2)|20803|32382|319|0.9%|4.9%|
[stopforumspam_1d](#stopforumspam_1d)|6690|6690|311|4.6%|4.7%|
[firehol_proxies](#firehol_proxies)|12828|13116|238|1.8%|3.6%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|233|44.4%|3.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|182|0.0%|2.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|168|0.0%|2.5%|
[php_commenters](#php_commenters)|458|458|54|11.7%|0.8%|
[alienvault_reputation](#alienvault_reputation)|189146|189146|42|0.0%|0.6%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|22|0.0%|0.3%|
[openbl_60d](#openbl_60d)|6960|6960|20|0.2%|0.3%|
[dragon_http](#dragon_http)|1021|268288|16|0.0%|0.2%|
[blocklist_de_apache](#blocklist_de_apache)|13852|13852|13|0.0%|0.2%|
[blocklist_de](#blocklist_de)|27144|27144|13|0.0%|0.2%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2473|2473|10|0.4%|0.1%|
[php_harvesters](#php_harvesters)|408|408|7|1.7%|0.1%|
[ri_web_proxies](#ri_web_proxies)|7952|7952|5|0.0%|0.0%|
[php_spammers](#php_spammers)|735|735|5|0.6%|0.0%|
[nixspam](#nixspam)|18020|18020|5|0.0%|0.0%|
[firehol_level1](#firehol_level1)|5137|688854747|5|0.0%|0.0%|
[sorbs_spam](#sorbs_spam)|64701|65536|4|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|4|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|4|0.0%|0.0%|
[php_dictionary](#php_dictionary)|737|737|4|0.5%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|4|0.0%|0.0%|
[et_block](#et_block)|1000|18343756|4|0.0%|0.0%|
[voipbl](#voipbl)|10586|10998|3|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|3|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|17849|17849|3|0.0%|0.0%|
[xroxy](#xroxy)|2174|2174|2|0.0%|0.0%|
[dshield](#dshield)|20|5120|2|0.0%|0.0%|
[shunlist](#shunlist)|1185|1185|1|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2855|2855|1|0.0%|0.0%|
[proxyrss](#proxyrss)|1735|1735|1|0.0%|0.0%|

## feodo

[Abuse.ch Feodo tracker](https://feodotracker.abuse.ch) trojan includes IPs which are being used by Feodo (also known as Cridex or Bugat) which commits ebanking fraud - **excellent list**

Source is downloaded from [this link](https://feodotracker.abuse.ch/blocklist/?download=ipblocklist).

The last time downloaded was found to be dated: Fri Jun 12 08:27:10 UTC 2015.

The ipset `feodo` has **105** entries, **105** unique IPs.

The following table shows the overlaps of `feodo` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `feodo`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `feodo`.
- ` this % ` is the percentage **of this ipset (`feodo`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level1](#firehol_level1)|5137|688854747|105|0.0%|100.0%|
[et_block](#et_block)|1000|18343756|105|0.0%|100.0%|
[snort_ipfilter](#snort_ipfilter)|9136|9136|83|0.9%|79.0%|
[firehol_level3](#firehol_level3)|109170|9626833|83|0.0%|79.0%|
[sslbl](#sslbl)|370|370|38|10.2%|36.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|11|0.0%|10.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|3|0.0%|2.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|3|0.0%|2.8%|
[alienvault_reputation](#alienvault_reputation)|189146|189146|2|0.0%|1.9%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.9%|

## firehol_anonymous

**FireHOL Anonymous** - Known anonymizing IPs. (includes: firehol_proxies anonymous bm_tor dm_tor tor_exits)

Source is downloaded from [this link]().

The last time downloaded was found to be dated: Sun Jun  7 22:20:34 UTC 2015.

The ipset `firehol_anonymous` has **19294** entries, **83353** unique IPs.

The following table shows the overlaps of `firehol_anonymous` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `firehol_anonymous`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `firehol_anonymous`.
- ` this % ` is the percentage **of this ipset (`firehol_anonymous`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_proxies](#firehol_proxies)|12828|13116|13116|100.0%|15.7%|
[ri_web_proxies](#ri_web_proxies)|7952|7952|7952|100.0%|9.5%|
[firehol_level3](#firehol_level3)|109170|9626833|6816|0.0%|8.1%|
[dm_tor](#dm_tor)|6455|6455|6455|100.0%|7.7%|
[bm_tor](#bm_tor)|6338|6338|6338|100.0%|7.6%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|6248|6.6%|7.4%|
[et_tor](#et_tor)|6500|6500|5803|89.2%|6.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|3444|0.0%|4.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|2894|0.0%|3.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|2879|0.0%|3.4%|
[ri_connect_proxies](#ri_connect_proxies)|2855|2855|2855|100.0%|3.4%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|2751|9.4%|3.3%|
[xroxy](#xroxy)|2174|2174|2174|100.0%|2.6%|
[proxyrss](#proxyrss)|1735|1735|1735|100.0%|2.0%|
[proxz](#proxz)|1356|1356|1356|100.0%|1.6%|
[firehol_level2](#firehol_level2)|20803|32382|1332|4.1%|1.5%|
[snort_ipfilter](#snort_ipfilter)|9136|9136|1226|13.4%|1.4%|
[tor_exits](#tor_exits)|1101|1101|1101|100.0%|1.3%|
[stopforumspam_1d](#stopforumspam_1d)|6690|6690|957|14.3%|1.1%|
[blocklist_de](#blocklist_de)|27144|27144|673|2.4%|0.8%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|663|100.0%|0.7%|
[blocklist_de_bots](#blocklist_de_bots)|2979|2979|526|17.6%|0.6%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|524|100.0%|0.6%|
[sorbs_spam](#sorbs_spam)|64701|65536|201|0.3%|0.2%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|201|0.3%|0.2%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|201|0.3%|0.2%|
[nixspam](#nixspam)|18020|18020|152|0.8%|0.1%|
[blocklist_de_mail](#blocklist_de_mail)|17849|17849|125|0.7%|0.1%|
[php_dictionary](#php_dictionary)|737|737|98|13.2%|0.1%|
[php_commenters](#php_commenters)|458|458|90|19.6%|0.1%|
[php_spammers](#php_spammers)|735|735|82|11.1%|0.0%|
[voipbl](#voipbl)|10586|10998|79|0.7%|0.0%|
[alienvault_reputation](#alienvault_reputation)|189146|189146|57|0.0%|0.0%|
[dragon_http](#dragon_http)|1021|268288|45|0.0%|0.0%|
[sorbs_web](#sorbs_web)|626|627|31|4.9%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|30|0.0%|0.0%|
[openbl_60d](#openbl_60d)|6960|6960|23|0.3%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13852|13852|20|0.1%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2473|2473|16|0.6%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|15|0.0%|0.0%|
[php_harvesters](#php_harvesters)|408|408|12|2.9%|0.0%|
[iw_spamlist](#iw_spamlist)|3787|3787|9|0.2%|0.0%|
[firehol_level1](#firehol_level1)|5137|688854747|9|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|170|170|9|5.2%|0.0%|
[et_block](#et_block)|1000|18343756|8|0.0%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|7|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|6|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|1525|1525|4|0.2%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|3|0.2%|0.0%|
[et_compromised](#et_compromised)|1704|1704|3|0.1%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1697|1697|3|0.1%|0.0%|
[dshield](#dshield)|20|5120|2|0.0%|0.0%|
[sslbl](#sslbl)|370|370|1|0.2%|0.0%|
[shunlist](#shunlist)|1185|1185|1|0.0%|0.0%|
[openbl_30d](#openbl_30d)|2792|2792|1|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1969|1969|1|0.0%|0.0%|

## firehol_level1

**FireHOL Level 1** - Maximum protection without false positives. (includes: fullbogons dshield feodo palevo sslbl zeus spamhaus_drop spamhaus_edrop)

Source is downloaded from [this link]().

The last time downloaded was found to be dated: Sun Jun  7 22:15:43 UTC 2015.

The ipset `firehol_level1` has **5137** entries, **688854747** unique IPs.

The following table shows the overlaps of `firehol_level1` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `firehol_level1`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `firehol_level1`.
- ` this % ` is the percentage **of this ipset (`firehol_level1`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[fullbogons](#fullbogons)|3775|670173256|670173256|100.0%|97.2%|
[bogons](#bogons)|13|592708608|592708608|100.0%|86.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|18340608|100.0%|2.6%|
[et_block](#et_block)|1000|18343756|18340171|99.9%|2.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|8867716|2.5%|1.2%|
[firehol_level3](#firehol_level3)|109170|9626833|7500198|77.9%|1.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|7498240|81.6%|1.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|4637602|3.3%|0.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|2570562|0.3%|0.3%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|487424|100.0%|0.0%|
[alienvault_reputation](#alienvault_reputation)|189146|189146|6389|3.3%|0.0%|
[dshield](#dshield)|20|5120|5120|100.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1931|0.5%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|1111|1.1%|0.0%|
[dragon_http](#dragon_http)|1021|268288|1025|0.3%|0.0%|
[sslbl](#sslbl)|370|370|370|100.0%|0.0%|
[voipbl](#voipbl)|10586|10998|333|3.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9136|9136|300|3.2%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|291|1.0%|0.0%|
[firehol_level2](#firehol_level2)|20803|32382|283|0.8%|0.0%|
[openbl_60d](#openbl_60d)|6960|6960|253|3.6%|0.0%|
[zeus](#zeus)|230|230|230|100.0%|0.0%|
[blocklist_de](#blocklist_de)|27144|27144|217|0.7%|0.0%|
[zeus_badips](#zeus_badips)|202|202|202|100.0%|0.0%|
[shunlist](#shunlist)|1185|1185|159|13.4%|0.0%|
[openbl_30d](#openbl_30d)|2792|2792|135|4.8%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1969|1969|124|6.2%|0.0%|
[dragon_sshpauth](#dragon_sshpauth)|1595|1659|107|6.4%|0.0%|
[feodo](#feodo)|105|105|105|100.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6690|6690|87|1.3%|0.0%|
[et_compromised](#et_compromised)|1704|1704|71|4.1%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1697|1697|67|3.9%|0.0%|
[openbl_7d](#openbl_7d)|629|629|60|9.5%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|2979|2979|60|2.0%|0.0%|
[php_commenters](#php_commenters)|458|458|39|8.5%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|39|3.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|39|2.6%|0.0%|
[nixspam](#nixspam)|18020|18020|31|0.1%|0.0%|
[sorbs_spam](#sorbs_spam)|64701|65536|25|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|25|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|25|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|17849|17849|25|0.1%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|170|170|20|11.7%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|18|0.0%|0.0%|
[openbl_1d](#openbl_1d)|126|126|16|12.6%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2719|2719|14|0.5%|0.0%|
[palevo](#palevo)|13|13|13|100.0%|0.0%|
[iw_spamlist](#iw_spamlist)|3787|3787|9|0.2%|0.0%|
[firehol_anonymous](#firehol_anonymous)|19294|83353|9|0.0%|0.0%|
[nt_malware_http](#nt_malware_http)|69|69|8|11.5%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13852|13852|7|0.0%|0.0%|
[php_dictionary](#php_dictionary)|737|737|6|0.8%|0.0%|
[ciarmy](#ciarmy)|416|416|6|1.4%|0.0%|
[malc0de](#malc0de)|276|276|5|1.8%|0.0%|
[firehol_proxies](#firehol_proxies)|12828|13116|5|0.0%|0.0%|
[et_tor](#et_tor)|6500|6500|5|0.0%|0.0%|
[dm_tor](#dm_tor)|6455|6455|5|0.0%|0.0%|
[bm_tor](#bm_tor)|6338|6338|5|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2473|2473|5|0.2%|0.0%|
[php_spammers](#php_spammers)|735|735|4|0.5%|0.0%|
[tor_exits](#tor_exits)|1101|1101|3|0.2%|0.0%|
[php_harvesters](#php_harvesters)|408|408|3|0.7%|0.0%|
[nt_malware_irc](#nt_malware_irc)|43|43|3|6.9%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|2|0.3%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|2|0.3%|0.0%|
[dragon_vncprobe](#dragon_vncprobe)|87|87|2|2.2%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|84|84|2|2.3%|0.0%|
[virbl](#virbl)|22|22|1|4.5%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7952|7952|1|0.0%|0.0%|
[et_botcc](#et_botcc)|505|505|1|0.1%|0.0%|

## firehol_level2

**FireHOL Level 2** - Maximum protection from attacks took place in the last 48 hours. (includes: openbl_1d blocklist_de stopforumspam_1d)

Source is downloaded from [this link]().

The last time downloaded was found to be dated: Sun Jun  7 22:20:34 UTC 2015.

The ipset `firehol_level2` has **20803** entries, **32382** unique IPs.

The following table shows the overlaps of `firehol_level2` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `firehol_level2`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `firehol_level2`.
- ` this % ` is the percentage **of this ipset (`firehol_level2`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|27144|27144|27144|100.0%|83.8%|
[blocklist_de_mail](#blocklist_de_mail)|17849|17849|17849|100.0%|55.1%|
[blocklist_de_apache](#blocklist_de_apache)|13852|13852|13849|99.9%|42.7%|
[firehol_level3](#firehol_level3)|109170|9626833|7064|0.0%|21.8%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|6837|23.5%|21.1%|
[stopforumspam_1d](#stopforumspam_1d)|6690|6690|6690|100.0%|20.6%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|5963|6.3%|18.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|3686|0.0%|11.3%|
[blocklist_de_bots](#blocklist_de_bots)|2979|2979|2979|100.0%|9.1%|
[blocklist_de_imap](#blocklist_de_imap)|2719|2719|2710|99.6%|8.3%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2473|2473|2472|99.9%|7.6%|
[blocklist_de_ssh](#blocklist_de_ssh)|1969|1969|1947|98.8%|6.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|1680|0.0%|5.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|1622|0.0%|5.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|1525|1525|1513|99.2%|4.6%|
[firehol_anonymous](#firehol_anonymous)|19294|83353|1332|1.5%|4.1%|
[firehol_proxies](#firehol_proxies)|12828|13116|1172|8.9%|3.6%|
[sorbs_spam](#sorbs_spam)|64701|65536|1111|1.6%|3.4%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|1103|1.6%|3.4%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|1103|1.6%|3.4%|
[alienvault_reputation](#alienvault_reputation)|189146|189146|1097|0.5%|3.3%|
[openbl_60d](#openbl_60d)|6960|6960|766|11.0%|2.3%|
[ri_web_proxies](#ri_web_proxies)|7952|7952|659|8.2%|2.0%|
[openbl_30d](#openbl_30d)|2792|2792|655|23.4%|2.0%|
[dragon_sshpauth](#dragon_sshpauth)|1595|1659|652|39.3%|2.0%|
[bruteforceblocker](#bruteforceblocker)|1697|1697|561|33.0%|1.7%|
[et_compromised](#et_compromised)|1704|1704|542|31.8%|1.6%|
[snort_ipfilter](#snort_ipfilter)|9136|9136|522|5.7%|1.6%|
[nixspam](#nixspam)|18020|18020|516|2.8%|1.5%|
[proxyrss](#proxyrss)|1735|1735|411|23.6%|1.2%|
[openbl_7d](#openbl_7d)|629|629|391|62.1%|1.2%|
[shunlist](#shunlist)|1185|1185|356|30.0%|1.0%|
[tor_exits](#tor_exits)|1101|1101|325|29.5%|1.0%|
[et_tor](#et_tor)|6500|6500|319|4.9%|0.9%|
[dm_tor](#dm_tor)|6455|6455|312|4.8%|0.9%|
[bm_tor](#bm_tor)|6338|6338|310|4.8%|0.9%|
[xroxy](#xroxy)|2174|2174|303|13.9%|0.9%|
[firehol_level1](#firehol_level1)|5137|688854747|283|0.0%|0.8%|
[proxz](#proxz)|1356|1356|271|19.9%|0.8%|
[et_block](#et_block)|1000|18343756|270|0.0%|0.8%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|251|0.0%|0.7%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|194|37.0%|0.5%|
[php_commenters](#php_commenters)|458|458|193|42.1%|0.5%|
[blocklist_de_strongips](#blocklist_de_strongips)|170|170|170|100.0%|0.5%|
[ri_connect_proxies](#ri_connect_proxies)|2855|2855|146|5.1%|0.4%|
[openbl_1d](#openbl_1d)|126|126|126|100.0%|0.3%|
[iw_spamlist](#iw_spamlist)|3787|3787|123|3.2%|0.3%|
[php_dictionary](#php_dictionary)|737|737|122|16.5%|0.3%|
[php_spammers](#php_spammers)|735|735|115|15.6%|0.3%|
[dshield](#dshield)|20|5120|89|1.7%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|88|0.0%|0.2%|
[sorbs_web](#sorbs_web)|626|627|71|11.3%|0.2%|
[blocklist_de_sip](#blocklist_de_sip)|84|84|65|77.3%|0.2%|
[dragon_http](#dragon_http)|1021|268288|60|0.0%|0.1%|
[php_harvesters](#php_harvesters)|408|408|58|14.2%|0.1%|
[voipbl](#voipbl)|10586|10998|46|0.4%|0.1%|
[ciarmy](#ciarmy)|416|416|36|8.6%|0.1%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|16|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|13|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|9|1.3%|0.0%|
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

The ipset `firehol_level3` has **109170** entries, **9626833** unique IPs.

The following table shows the overlaps of `firehol_level3` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `firehol_level3`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `firehol_level3`.
- ` this % ` is the percentage **of this ipset (`firehol_level3`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|9177856|100.0%|95.3%|
[firehol_level1](#firehol_level1)|5137|688854747|7500198|1.0%|77.9%|
[et_block](#et_block)|1000|18343756|6933353|37.7%|72.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|6933039|37.8%|72.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|2537260|0.7%|26.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|919952|0.1%|9.5%|
[fullbogons](#fullbogons)|3775|670173256|566692|0.0%|5.8%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|339173|100.0%|3.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|161554|0.1%|1.6%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|94309|100.0%|0.9%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|27643|95.2%|0.2%|
[snort_ipfilter](#snort_ipfilter)|9136|9136|9136|100.0%|0.0%|
[firehol_level2](#firehol_level2)|20803|32382|7064|21.8%|0.0%|
[firehol_anonymous](#firehol_anonymous)|19294|83353|6816|8.1%|0.0%|
[firehol_proxies](#firehol_proxies)|12828|13116|5711|43.5%|0.0%|
[alienvault_reputation](#alienvault_reputation)|189146|189146|4814|2.5%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6690|6690|4638|69.3%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7952|7952|3755|47.2%|0.0%|
[blocklist_de](#blocklist_de)|27144|27144|3685|13.5%|0.0%|
[openbl_60d](#openbl_60d)|6960|6960|2918|41.9%|0.0%|
[openbl_30d](#openbl_30d)|2792|2792|2792|100.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|2979|2979|2328|78.1%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1697|1697|1697|100.0%|0.0%|
[et_compromised](#et_compromised)|1704|1704|1677|98.4%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2855|2855|1592|55.7%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|1450|100.0%|0.0%|
[xroxy](#xroxy)|2174|2174|1301|59.8%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|1288|100.0%|0.0%|
[sorbs_spam](#sorbs_spam)|64701|65536|1226|1.8%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|1222|1.8%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|1222|1.8%|0.0%|
[shunlist](#shunlist)|1185|1185|1185|100.0%|0.0%|
[et_tor](#et_tor)|6500|6500|1123|17.2%|0.0%|
[dm_tor](#dm_tor)|6455|6455|1088|16.8%|0.0%|
[bm_tor](#bm_tor)|6338|6338|1074|16.9%|0.0%|
[tor_exits](#tor_exits)|1101|1101|1069|97.0%|0.0%|
[dragon_sshpauth](#dragon_sshpauth)|1595|1659|862|51.9%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1969|1969|822|41.7%|0.0%|
[proxz](#proxz)|1356|1356|800|58.9%|0.0%|
[proxyrss](#proxyrss)|1735|1735|745|42.9%|0.0%|
[php_dictionary](#php_dictionary)|737|737|737|100.0%|0.0%|
[php_spammers](#php_spammers)|735|735|735|100.0%|0.0%|
[openbl_7d](#openbl_7d)|629|629|629|100.0%|0.0%|
[dragon_http](#dragon_http)|1021|268288|560|0.2%|0.0%|
[php_commenters](#php_commenters)|458|458|458|100.0%|0.0%|
[nixspam](#nixspam)|18020|18020|426|2.3%|0.0%|
[ciarmy](#ciarmy)|416|416|416|100.0%|0.0%|
[php_harvesters](#php_harvesters)|408|408|408|100.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|17849|17849|386|2.1%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|346|66.0%|0.0%|
[malc0de](#malc0de)|276|276|276|100.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13852|13852|270|1.9%|0.0%|
[zeus](#zeus)|230|230|203|88.2%|0.0%|
[zeus_badips](#zeus_badips)|202|202|180|89.1%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|170|170|156|91.7%|0.0%|
[openbl_1d](#openbl_1d)|126|126|126|100.0%|0.0%|
[dshield](#dshield)|20|5120|124|2.4%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|121|121|121|100.0%|0.0%|
[iw_spamlist](#iw_spamlist)|3787|3787|93|2.4%|0.0%|
[sslbl](#sslbl)|370|370|89|24.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|85|0.0%|0.0%|
[feodo](#feodo)|105|105|83|79.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2473|2473|77|3.1%|0.0%|
[sorbs_web](#sorbs_web)|626|627|74|11.8%|0.0%|
[voipbl](#voipbl)|10586|10998|58|0.5%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2719|2719|36|1.3%|0.0%|
[iw_wormlist](#iw_wormlist)|34|34|34|100.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|25|3.7%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|25|0.0%|0.0%|
[virbl](#virbl)|22|22|22|100.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|1525|1525|18|1.1%|0.0%|
[palevo](#palevo)|13|13|11|84.6%|0.0%|
[sorbs_socks](#sorbs_socks)|7|7|4|57.1%|0.0%|
[sorbs_misc](#sorbs_misc)|7|7|4|57.1%|0.0%|
[sorbs_http](#sorbs_http)|7|7|4|57.1%|0.0%|
[dragon_vncprobe](#dragon_vncprobe)|87|87|4|4.5%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|84|84|4|4.7%|0.0%|
[nt_malware_http](#nt_malware_http)|69|69|3|4.3%|0.0%|
[et_botcc](#et_botcc)|505|505|3|0.5%|0.0%|
[bogons](#bogons)|13|592708608|3|0.0%|0.0%|
[nt_malware_irc](#nt_malware_irc)|43|43|1|2.3%|0.0%|

## firehol_proxies

**FireHOL Proxies** - Known open proxies in the last 30 days. (includes: ib_bluetack_proxies maxmind_proxy_fraud proxyrss proxz ri_connect_proxies ri_web_proxies xroxy)

Source is downloaded from [this link]().

The last time downloaded was found to be dated: Sun Jun  7 22:20:34 UTC 2015.

The ipset `firehol_proxies` has **12828** entries, **13116** unique IPs.

The following table shows the overlaps of `firehol_proxies` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `firehol_proxies`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `firehol_proxies`.
- ` this % ` is the percentage **of this ipset (`firehol_proxies`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_anonymous](#firehol_anonymous)|19294|83353|13116|15.7%|100.0%|
[ri_web_proxies](#ri_web_proxies)|7952|7952|7952|100.0%|60.6%|
[firehol_level3](#firehol_level3)|109170|9626833|5711|0.0%|43.5%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|5650|5.9%|43.0%|
[ri_connect_proxies](#ri_connect_proxies)|2855|2855|2855|100.0%|21.7%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|2385|8.2%|18.1%|
[xroxy](#xroxy)|2174|2174|2174|100.0%|16.5%|
[proxyrss](#proxyrss)|1735|1735|1735|100.0%|13.2%|
[proxz](#proxz)|1356|1356|1356|100.0%|10.3%|
[firehol_level2](#firehol_level2)|20803|32382|1172|3.6%|8.9%|
[stopforumspam_1d](#stopforumspam_1d)|6690|6690|813|12.1%|6.1%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|663|100.0%|5.0%|
[blocklist_de](#blocklist_de)|27144|27144|650|2.3%|4.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|530|0.0%|4.0%|
[blocklist_de_bots](#blocklist_de_bots)|2979|2979|525|17.6%|4.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|524|100.0%|3.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|389|0.0%|2.9%|
[snort_ipfilter](#snort_ipfilter)|9136|9136|327|3.5%|2.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|291|0.0%|2.2%|
[et_tor](#et_tor)|6500|6500|238|3.6%|1.8%|
[dm_tor](#dm_tor)|6455|6455|234|3.6%|1.7%|
[bm_tor](#bm_tor)|6338|6338|234|3.6%|1.7%|
[tor_exits](#tor_exits)|1101|1101|228|20.7%|1.7%|
[sorbs_spam](#sorbs_spam)|64701|65536|196|0.2%|1.4%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|196|0.3%|1.4%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|196|0.3%|1.4%|
[nixspam](#nixspam)|18020|18020|145|0.8%|1.1%|
[blocklist_de_mail](#blocklist_de_mail)|17849|17849|123|0.6%|0.9%|
[php_dictionary](#php_dictionary)|737|737|97|13.1%|0.7%|
[php_commenters](#php_commenters)|458|458|86|18.7%|0.6%|
[php_spammers](#php_spammers)|735|735|80|10.8%|0.6%|
[alienvault_reputation](#alienvault_reputation)|189146|189146|38|0.0%|0.2%|
[dragon_http](#dragon_http)|1021|268288|32|0.0%|0.2%|
[sorbs_web](#sorbs_web)|626|627|31|4.9%|0.2%|
[openbl_60d](#openbl_60d)|6960|6960|20|0.2%|0.1%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|15|0.0%|0.1%|
[php_harvesters](#php_harvesters)|408|408|12|2.9%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|12|0.0%|0.0%|
[iw_spamlist](#iw_spamlist)|3787|3787|9|0.2%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|170|170|9|5.2%|0.0%|
[firehol_level1](#firehol_level1)|5137|688854747|5|0.0%|0.0%|
[et_block](#et_block)|1000|18343756|4|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|3|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|3|0.2%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|0.0%|
[et_compromised](#et_compromised)|1704|1704|3|0.1%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1697|1697|3|0.1%|0.0%|
[voipbl](#voipbl)|10586|10998|2|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13852|13852|2|0.0%|0.0%|
[sslbl](#sslbl)|370|370|1|0.2%|0.0%|
[shunlist](#shunlist)|1185|1185|1|0.0%|0.0%|
[dshield](#dshield)|20|5120|1|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1969|1969|1|0.0%|0.0%|

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
[firehol_level1](#firehol_level1)|5137|688854747|670173256|97.2%|100.0%|
[bogons](#bogons)|13|592708608|592708608|100.0%|88.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|4236143|3.0%|0.6%|
[firehol_level3](#firehol_level3)|109170|9626833|566692|5.8%|0.0%|
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
[iw_spamlist](#iw_spamlist)|3787|3787|5|0.1%|0.0%|
[nt_malware_http](#nt_malware_http)|69|69|4|5.7%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|2|0.0%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|2|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6690|6690|1|0.0%|0.0%|
[php_harvesters](#php_harvesters)|408|408|1|0.2%|0.0%|
[php_commenters](#php_commenters)|458|458|1|0.2%|0.0%|
[firehol_level2](#firehol_level2)|20803|32382|1|0.0%|0.0%|
[ciarmy](#ciarmy)|416|416|1|0.2%|0.0%|

## ib_bluetack_badpeers

[iBlocklist.com](https://www.iblocklist.com/) free version of [BlueTack.co.uk](http://www.bluetack.co.uk/) IPs that have been reported for bad deeds in p2p

Source is downloaded from [this link](http://list.iblocklist.com/?list=cwworuawihqvocglcoss&fileformat=p2p&archiveformat=gz).

The last time downloaded was found to be dated: Thu Jun 11 05:41:00 UTC 2015.

The ipset `ib_bluetack_badpeers` has **47940** entries, **47940** unique IPs.

The following table shows the overlaps of `ib_bluetack_badpeers` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ib_bluetack_badpeers`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ib_bluetack_badpeers`.
- ` this % ` is the percentage **of this ipset (`ib_bluetack_badpeers`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|1172|0.0%|2.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|394|0.0%|0.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|226|0.0%|0.4%|
[firehol_level3](#firehol_level3)|109170|9626833|25|0.0%|0.0%|
[dragon_http](#dragon_http)|1021|268288|25|0.0%|0.0%|
[firehol_level1](#firehol_level1)|5137|688854747|18|0.0%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|17|0.0%|0.0%|
[sorbs_spam](#sorbs_spam)|64701|65536|17|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|17|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|17|0.0%|0.0%|
[firehol_level2](#firehol_level2)|20803|32382|16|0.0%|0.0%|
[firehol_proxies](#firehol_proxies)|12828|13116|15|0.1%|0.0%|
[firehol_anonymous](#firehol_anonymous)|19294|83353|15|0.0%|0.0%|
[blocklist_de](#blocklist_de)|27144|27144|15|0.0%|0.0%|
[alienvault_reputation](#alienvault_reputation)|189146|189146|15|0.0%|0.0%|
[fullbogons](#fullbogons)|3775|670173256|13|0.0%|0.0%|
[nixspam](#nixspam)|18020|18020|11|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|11|1.6%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|17849|17849|10|0.0%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|7|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|5|0.0%|0.0%|
[et_block](#et_block)|1000|18343756|5|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7952|7952|4|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2719|2719|4|0.1%|0.0%|
[xroxy](#xroxy)|2174|2174|3|0.1%|0.0%|
[php_dictionary](#php_dictionary)|737|737|3|0.4%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|3|0.0%|0.0%|
[voipbl](#voipbl)|10586|10998|2|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6690|6690|2|0.0%|0.0%|
[sorbs_web](#sorbs_web)|626|627|2|0.3%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9136|9136|2|0.0%|0.0%|
[php_harvesters](#php_harvesters)|408|408|2|0.4%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|1525|1525|2|0.1%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2473|2473|2|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13852|13852|2|0.0%|0.0%|
[proxz](#proxz)|1356|1356|1|0.0%|0.0%|
[php_spammers](#php_spammers)|735|735|1|0.1%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|1|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1969|1969|1|0.0%|0.0%|

## ib_bluetack_hijacked

[iBlocklist.com](https://www.iblocklist.com/) free version of [BlueTack.co.uk](http://www.bluetack.co.uk/) hijacked IP-Blocks Hijacked IP space are IP blocks that are being used without permission

Source is downloaded from [this link](http://list.iblocklist.com/?list=usrcshglbiilevmyfhse&fileformat=p2p&archiveformat=gz).

The last time downloaded was found to be dated: Thu Jun 11 06:10:14 UTC 2015.

The ipset `ib_bluetack_hijacked` has **535** entries, **9177856** unique IPs.

The following table shows the overlaps of `ib_bluetack_hijacked` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ib_bluetack_hijacked`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ib_bluetack_hijacked`.
- ` this % ` is the percentage **of this ipset (`ib_bluetack_hijacked`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level3](#firehol_level3)|109170|9626833|9177856|95.3%|100.0%|
[firehol_level1](#firehol_level1)|5137|688854747|7498240|1.0%|81.6%|
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
[firehol_level2](#firehol_level2)|20803|32382|88|0.2%|0.0%|
[blocklist_de](#blocklist_de)|27144|27144|55|0.2%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|2979|2979|41|1.3%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6690|6690|33|0.4%|0.0%|
[nixspam](#nixspam)|18020|18020|29|0.1%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|27|2.0%|0.0%|
[openbl_60d](#openbl_60d)|6960|6960|16|0.2%|0.0%|
[openbl_30d](#openbl_30d)|2792|2792|12|0.4%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9136|9136|11|0.1%|0.0%|
[zeus_badips](#zeus_badips)|202|202|10|4.9%|0.0%|
[zeus](#zeus)|230|230|10|4.3%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|7|0.4%|0.0%|
[firehol_anonymous](#firehol_anonymous)|19294|83353|7|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1969|1969|7|0.3%|0.0%|
[et_compromised](#et_compromised)|1704|1704|5|0.2%|0.0%|
[dragon_sshpauth](#dragon_sshpauth)|1595|1659|5|0.3%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1697|1697|5|0.2%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|17849|17849|5|0.0%|0.0%|
[php_dictionary](#php_dictionary)|737|737|4|0.5%|0.0%|
[openbl_7d](#openbl_7d)|629|629|4|0.6%|0.0%|
[et_tor](#et_tor)|6500|6500|4|0.0%|0.0%|
[dm_tor](#dm_tor)|6455|6455|4|0.0%|0.0%|
[bm_tor](#bm_tor)|6338|6338|4|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2719|2719|4|0.1%|0.0%|
[php_spammers](#php_spammers)|735|735|3|0.4%|0.0%|
[openbl_1d](#openbl_1d)|126|126|3|2.3%|0.0%|
[nt_malware_http](#nt_malware_http)|69|69|3|4.3%|0.0%|
[iw_spamlist](#iw_spamlist)|3787|3787|3|0.0%|0.0%|
[firehol_proxies](#firehol_proxies)|12828|13116|3|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|170|170|3|1.7%|0.0%|
[tor_exits](#tor_exits)|1101|1101|2|0.1%|0.0%|
[shunlist](#shunlist)|1185|1185|2|0.1%|0.0%|
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
[blocklist_de_ftp](#blocklist_de_ftp)|1525|1525|1|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2473|2473|1|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13852|13852|1|0.0%|0.0%|

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
[firehol_level1](#firehol_level1)|5137|688854747|2570562|0.3%|0.3%|
[et_block](#et_block)|1000|18343756|2272787|12.3%|0.2%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|2272265|12.3%|0.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|1354507|0.9%|0.1%|
[firehol_level3](#firehol_level3)|109170|9626833|919952|9.5%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|904796|9.8%|0.1%|
[fullbogons](#fullbogons)|3775|670173256|264873|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|33155|6.8%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|13247|3.9%|0.0%|
[dragon_http](#dragon_http)|1021|268288|5989|2.2%|0.0%|
[alienvault_reputation](#alienvault_reputation)|189146|189146|4185|2.2%|0.0%|
[firehol_anonymous](#firehol_anonymous)|19294|83353|3444|4.1%|0.0%|
[firehol_level2](#firehol_level2)|20803|32382|1680|5.1%|0.0%|
[blocklist_de](#blocklist_de)|27144|27144|1584|5.8%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|1522|1.6%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|17849|17849|1420|7.9%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13852|13852|1319|9.5%|0.0%|
[sorbs_spam](#sorbs_spam)|64701|65536|1208|1.8%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|1205|1.8%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|1205|1.8%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|510|1.7%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|394|0.8%|0.0%|
[nixspam](#nixspam)|18020|18020|309|1.7%|0.0%|
[voipbl](#voipbl)|10586|10998|302|2.7%|0.0%|
[firehol_proxies](#firehol_proxies)|12828|13116|291|2.2%|0.0%|
[dshield](#dshield)|20|5120|256|5.0%|0.0%|
[dm_tor](#dm_tor)|6455|6455|169|2.6%|0.0%|
[et_tor](#et_tor)|6500|6500|168|2.5%|0.0%|
[bm_tor](#bm_tor)|6338|6338|166|2.6%|0.0%|
[openbl_60d](#openbl_60d)|6960|6960|161|2.3%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7952|7952|156|1.9%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6690|6690|127|1.8%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9136|9136|114|1.2%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|97|6.6%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2855|2855|86|3.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2719|2719|78|2.8%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|66|5.1%|0.0%|
[iw_spamlist](#iw_spamlist)|3787|3787|66|1.7%|0.0%|
[openbl_30d](#openbl_30d)|2792|2792|65|2.3%|0.0%|
[xroxy](#xroxy)|2174|2174|58|2.6%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|56|8.4%|0.0%|
[et_compromised](#et_compromised)|1704|1704|54|3.1%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1697|1697|53|3.1%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|2979|2979|53|1.7%|0.0%|
[proxz](#proxz)|1356|1356|44|3.2%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1969|1969|44|2.2%|0.0%|
[et_botcc](#et_botcc)|505|505|39|7.7%|0.0%|
[tor_exits](#tor_exits)|1101|1101|37|3.3%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2473|2473|33|1.3%|0.0%|
[dragon_sshpauth](#dragon_sshpauth)|1595|1659|32|1.9%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|1525|1525|27|1.7%|0.0%|
[shunlist](#shunlist)|1185|1185|26|2.1%|0.0%|
[proxyrss](#proxyrss)|1735|1735|26|1.4%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|21|4.0%|0.0%|
[ciarmy](#ciarmy)|416|416|21|5.0%|0.0%|
[sorbs_web](#sorbs_web)|626|627|16|2.5%|0.0%|
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
[blocklist_de_sip](#blocklist_de_sip)|84|84|4|4.7%|0.0%|
[sslbl](#sslbl)|370|370|3|0.8%|0.0%|
[feodo](#feodo)|105|105|3|2.8%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|121|121|2|1.6%|0.0%|
[openbl_1d](#openbl_1d)|126|126|1|0.7%|0.0%|
[iw_wormlist](#iw_wormlist)|34|34|1|2.9%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|170|170|1|0.5%|0.0%|

## ib_bluetack_level2

[iBlocklist.com](https://www.iblocklist.com/) free version of BlueTack.co.uk Level 2 (for use in p2p). General corporate ranges. Ranges used by labs or researchers. Proxies.

Source is downloaded from [this link](http://list.iblocklist.com/?list=gyisgnzbhppbvsphucsw&fileformat=p2p&archiveformat=gz).

The last time downloaded was found to be dated: Thu Jun 11 06:10:59 UTC 2015.

The ipset `ib_bluetack_level2` has **72950** entries, **348710251** unique IPs.

The following table shows the overlaps of `ib_bluetack_level2` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ib_bluetack_level2`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ib_bluetack_level2`.
- ` this % ` is the percentage **of this ipset (`ib_bluetack_level2`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|16302420|2.1%|4.6%|
[firehol_level1](#firehol_level1)|5137|688854747|8867716|1.2%|2.5%|
[et_block](#et_block)|1000|18343756|8532776|46.5%|2.4%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|8532506|46.5%|2.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|2830203|2.0%|0.8%|
[firehol_level3](#firehol_level3)|109170|9626833|2537260|26.3%|0.7%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2526625|27.5%|0.7%|
[fullbogons](#fullbogons)|3775|670173256|252671|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|98904|20.2%|0.0%|
[dragon_http](#dragon_http)|1021|268288|11992|4.4%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|7728|2.2%|0.0%|
[alienvault_reputation](#alienvault_reputation)|189146|189146|7251|3.8%|0.0%|
[firehol_anonymous](#firehol_anonymous)|19294|83353|2894|3.4%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|2476|2.6%|0.0%|
[sorbs_spam](#sorbs_spam)|64701|65536|1740|2.6%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|1736|2.6%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|1736|2.6%|0.0%|
[firehol_level2](#firehol_level2)|20803|32382|1622|5.0%|0.0%|
[blocklist_de](#blocklist_de)|27144|27144|1482|5.4%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|17849|17849|1238|6.9%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13852|13852|1072|7.7%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|736|2.5%|0.0%|
[nixspam](#nixspam)|18020|18020|464|2.5%|0.0%|
[voipbl](#voipbl)|10586|10998|436|3.9%|0.0%|
[firehol_proxies](#firehol_proxies)|12828|13116|389|2.9%|0.0%|
[openbl_60d](#openbl_60d)|6960|6960|319|4.5%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|226|0.4%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7952|7952|225|2.8%|0.0%|
[bm_tor](#bm_tor)|6338|6338|186|2.9%|0.0%|
[dm_tor](#dm_tor)|6455|6455|185|2.8%|0.0%|
[et_tor](#et_tor)|6500|6500|182|2.8%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6690|6690|173|2.5%|0.0%|
[openbl_30d](#openbl_30d)|2792|2792|146|5.2%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9136|9136|141|1.5%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2855|2855|106|3.7%|0.0%|
[xroxy](#xroxy)|2174|2174|104|4.7%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1969|1969|96|4.8%|0.0%|
[iw_spamlist](#iw_spamlist)|3787|3787|93|2.4%|0.0%|
[et_compromised](#et_compromised)|1704|1704|89|5.2%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1697|1697|87|5.1%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|2979|2979|79|2.6%|0.0%|
[dragon_sshpauth](#dragon_sshpauth)|1595|1659|71|4.2%|0.0%|
[shunlist](#shunlist)|1185|1185|70|5.9%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2719|2719|61|2.2%|0.0%|
[proxz](#proxz)|1356|1356|56|4.1%|0.0%|
[php_spammers](#php_spammers)|735|735|54|7.3%|0.0%|
[proxyrss](#proxyrss)|1735|1735|52|2.9%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|45|3.1%|0.0%|
[tor_exits](#tor_exits)|1101|1101|40|3.6%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2473|2473|39|1.5%|0.0%|
[openbl_7d](#openbl_7d)|629|629|36|5.7%|0.0%|
[ciarmy](#ciarmy)|416|416|33|7.9%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|29|5.5%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|26|2.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|26|3.9%|0.0%|
[sorbs_web](#sorbs_web)|626|627|23|3.6%|0.0%|
[php_dictionary](#php_dictionary)|737|737|23|3.1%|0.0%|
[et_botcc](#et_botcc)|505|505|22|4.3%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|1525|1525|21|1.3%|0.0%|
[php_commenters](#php_commenters)|458|458|19|4.1%|0.0%|
[malc0de](#malc0de)|276|276|16|5.7%|0.0%|
[zeus](#zeus)|230|230|9|3.9%|0.0%|
[php_harvesters](#php_harvesters)|408|408|9|2.2%|0.0%|
[zeus_badips](#zeus_badips)|202|202|8|3.9%|0.0%|
[dragon_vncprobe](#dragon_vncprobe)|87|87|7|8.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|170|170|7|4.1%|0.0%|
[sslbl](#sslbl)|370|370|6|1.6%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|121|121|6|4.9%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|84|84|5|5.9%|0.0%|
[openbl_1d](#openbl_1d)|126|126|4|3.1%|0.0%|
[feodo](#feodo)|105|105|3|2.8%|0.0%|
[palevo](#palevo)|13|13|2|15.3%|0.0%|
[nt_malware_irc](#nt_malware_irc)|43|43|2|4.6%|0.0%|
[nt_malware_http](#nt_malware_http)|69|69|2|2.8%|0.0%|

## ib_bluetack_level3

[iBlocklist.com](https://www.iblocklist.com/) free version of BlueTack.co.uk Level 3 (for use in p2p). Many portal-type websites. ISP ranges that may be dodgy for some reason. Ranges that belong to an individual, but which have not been determined to be used by a particular company. Ranges for things that are unusual in some way. The L3 list is aka the paranoid list.

Source is downloaded from [this link](http://list.iblocklist.com/?list=uwnukjqktoggdknzrhgh&fileformat=p2p&archiveformat=gz).

The last time downloaded was found to be dated: Thu Jun 11 06:10:49 UTC 2015.

The ipset `ib_bluetack_level3` has **17812** entries, **139104927** unique IPs.

The following table shows the overlaps of `ib_bluetack_level3` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ib_bluetack_level3`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ib_bluetack_level3`.
- ` this % ` is the percentage **of this ipset (`ib_bluetack_level3`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level1](#firehol_level1)|5137|688854747|4637602|0.6%|3.3%|
[fullbogons](#fullbogons)|3775|670173256|4236143|0.6%|3.0%|
[bogons](#bogons)|13|592708608|4194304|0.7%|3.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|2830203|0.8%|2.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|1354507|0.1%|0.9%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|270785|55.5%|0.1%|
[firehol_level3](#firehol_level3)|109170|9626833|161554|1.6%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|145472|1.5%|0.1%|
[et_block](#et_block)|1000|18343756|130650|0.7%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|130368|0.7%|0.0%|
[dragon_http](#dragon_http)|1021|268288|20480|7.6%|0.0%|
[alienvault_reputation](#alienvault_reputation)|189146|189146|14337|7.5%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|9226|2.7%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|5830|6.1%|0.0%|
[firehol_level2](#firehol_level2)|20803|32382|3686|11.3%|0.0%|
[blocklist_de](#blocklist_de)|27144|27144|3285|12.1%|0.0%|
[firehol_anonymous](#firehol_anonymous)|19294|83353|2879|3.4%|0.0%|
[sorbs_spam](#sorbs_spam)|64701|65536|2860|4.3%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|2851|4.3%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|2851|4.3%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|17849|17849|2581|14.4%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13852|13852|2283|16.4%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|1961|6.7%|0.0%|
[voipbl](#voipbl)|10586|10998|1613|14.6%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|1172|2.4%|0.0%|
[nixspam](#nixspam)|18020|18020|981|5.4%|0.0%|
[openbl_60d](#openbl_60d)|6960|6960|740|10.6%|0.0%|
[et_tor](#et_tor)|6500|6500|636|9.7%|0.0%|
[dm_tor](#dm_tor)|6455|6455|631|9.7%|0.0%|
[bm_tor](#bm_tor)|6338|6338|621|9.7%|0.0%|
[firehol_proxies](#firehol_proxies)|12828|13116|530|4.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6690|6690|490|7.3%|0.0%|
[openbl_30d](#openbl_30d)|2792|2792|286|10.2%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2719|2719|285|10.4%|0.0%|
[iw_spamlist](#iw_spamlist)|3787|3787|275|7.2%|0.0%|
[dshield](#dshield)|20|5120|256|5.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9136|9136|240|2.6%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7952|7952|221|2.7%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2473|2473|190|7.6%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1969|1969|188|9.5%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|2979|2979|184|6.1%|0.0%|
[et_compromised](#et_compromised)|1704|1704|157|9.2%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1697|1697|157|9.2%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|150|28.6%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|147|11.4%|0.0%|
[tor_exits](#tor_exits)|1101|1101|126|11.4%|0.0%|
[dragon_sshpauth](#dragon_sshpauth)|1595|1659|125|7.5%|0.0%|
[shunlist](#shunlist)|1185|1185|120|10.1%|0.0%|
[xroxy](#xroxy)|2174|2174|112|5.1%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|1525|1525|111|7.2%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|108|7.4%|0.0%|
[proxz](#proxz)|1356|1356|106|7.8%|0.0%|
[et_botcc](#et_botcc)|505|505|76|15.0%|0.0%|
[ciarmy](#ciarmy)|416|416|70|16.8%|0.0%|
[openbl_7d](#openbl_7d)|629|629|66|10.4%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2855|2855|57|1.9%|0.0%|
[proxyrss](#proxyrss)|1735|1735|52|2.9%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|51|7.6%|0.0%|
[php_spammers](#php_spammers)|735|735|44|5.9%|0.0%|
[malc0de](#malc0de)|276|276|44|15.9%|0.0%|
[php_dictionary](#php_dictionary)|737|737|39|5.2%|0.0%|
[sorbs_web](#sorbs_web)|626|627|32|5.1%|0.0%|
[php_commenters](#php_commenters)|458|458|29|6.3%|0.0%|
[sslbl](#sslbl)|370|370|28|7.5%|0.0%|
[php_harvesters](#php_harvesters)|408|408|20|4.9%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|121|121|19|15.7%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|170|170|17|10.0%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|84|84|15|17.8%|0.0%|
[zeus](#zeus)|230|230|14|6.0%|0.0%|
[dragon_vncprobe](#dragon_vncprobe)|87|87|12|13.7%|0.0%|
[feodo](#feodo)|105|105|11|10.4%|0.0%|
[zeus_badips](#zeus_badips)|202|202|10|4.9%|0.0%|
[openbl_1d](#openbl_1d)|126|126|10|7.9%|0.0%|
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

The last time downloaded was found to be dated: Thu Jun 11 06:10:35 UTC 2015.

The ipset `ib_bluetack_proxies` has **663** entries, **663** unique IPs.

The following table shows the overlaps of `ib_bluetack_proxies` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ib_bluetack_proxies`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ib_bluetack_proxies`.
- ` this % ` is the percentage **of this ipset (`ib_bluetack_proxies`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_proxies](#firehol_proxies)|12828|13116|663|5.0%|100.0%|
[firehol_anonymous](#firehol_anonymous)|19294|83353|663|0.7%|100.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|56|0.0%|8.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|51|0.0%|7.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|26|0.0%|3.9%|
[firehol_level3](#firehol_level3)|109170|9626833|25|0.0%|3.7%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|20|0.0%|3.0%|
[ri_web_proxies](#ri_web_proxies)|7952|7952|15|0.1%|2.2%|
[xroxy](#xroxy)|2174|2174|13|0.5%|1.9%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|11|0.0%|1.6%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|10|0.0%|1.5%|
[proxyrss](#proxyrss)|1735|1735|9|0.5%|1.3%|
[firehol_level2](#firehol_level2)|20803|32382|9|0.0%|1.3%|
[ri_connect_proxies](#ri_connect_proxies)|2855|2855|7|0.2%|1.0%|
[proxz](#proxz)|1356|1356|7|0.5%|1.0%|
[stopforumspam_1d](#stopforumspam_1d)|6690|6690|6|0.0%|0.9%|
[blocklist_de](#blocklist_de)|27144|27144|5|0.0%|0.7%|
[blocklist_de_bots](#blocklist_de_bots)|2979|2979|4|0.1%|0.6%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|2|0.0%|0.3%|
[php_dictionary](#php_dictionary)|737|737|2|0.2%|0.3%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|2|0.1%|0.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2|0.0%|0.3%|
[firehol_level1](#firehol_level1)|5137|688854747|2|0.0%|0.3%|
[et_block](#et_block)|1000|18343756|2|0.0%|0.3%|
[alienvault_reputation](#alienvault_reputation)|189146|189146|2|0.0%|0.3%|
[sorbs_spam](#sorbs_spam)|64701|65536|1|0.0%|0.1%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|1|0.0%|0.1%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|1|0.0%|0.1%|
[snort_ipfilter](#snort_ipfilter)|9136|9136|1|0.0%|0.1%|
[php_spammers](#php_spammers)|735|735|1|0.1%|0.1%|
[nixspam](#nixspam)|18020|18020|1|0.0%|0.1%|
[dragon_http](#dragon_http)|1021|268288|1|0.0%|0.1%|
[blocklist_de_mail](#blocklist_de_mail)|17849|17849|1|0.0%|0.1%|

## ib_bluetack_spyware

[iBlocklist.com](https://www.iblocklist.com/) free version of [BlueTack.co.uk](http://www.bluetack.co.uk/) known malicious SPYWARE and ADWARE IP Address ranges

Source is downloaded from [this link](http://list.iblocklist.com/?list=llvtlsjyoyiczbkjsxpf&fileformat=p2p&archiveformat=gz).

The last time downloaded was found to be dated: Thu Jun 11 05:40:34 UTC 2015.

The ipset `ib_bluetack_spyware` has **3267** entries, **339173** unique IPs.

The following table shows the overlaps of `ib_bluetack_spyware` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ib_bluetack_spyware`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ib_bluetack_spyware`.
- ` this % ` is the percentage **of this ipset (`ib_bluetack_spyware`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level3](#firehol_level3)|109170|9626833|339173|3.5%|100.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|13247|0.0%|3.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|9226|0.0%|2.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|7728|0.0%|2.2%|
[firehol_level1](#firehol_level1)|5137|688854747|1931|0.0%|0.5%|
[et_block](#et_block)|1000|18343756|1041|0.0%|0.3%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|1037|0.0%|0.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1036|0.0%|0.3%|
[fullbogons](#fullbogons)|3775|670173256|890|0.0%|0.2%|
[alienvault_reputation](#alienvault_reputation)|189146|189146|293|0.1%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|52|0.0%|0.0%|
[sorbs_spam](#sorbs_spam)|64701|65536|38|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|37|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|37|0.0%|0.0%|
[firehol_anonymous](#firehol_anonymous)|19294|83353|30|0.0%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|27|2.0%|0.0%|
[et_tor](#et_tor)|6500|6500|22|0.3%|0.0%|
[dm_tor](#dm_tor)|6455|6455|22|0.3%|0.0%|
[bm_tor](#bm_tor)|6338|6338|22|0.3%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|21|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|19|1.3%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9136|9136|14|0.1%|0.0%|
[firehol_level2](#firehol_level2)|20803|32382|13|0.0%|0.0%|
[nixspam](#nixspam)|18020|18020|12|0.0%|0.0%|
[firehol_proxies](#firehol_proxies)|12828|13116|12|0.0%|0.0%|
[tor_exits](#tor_exits)|1101|1101|8|0.7%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6690|6690|7|0.1%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7952|7952|6|0.0%|0.0%|
[dragon_http](#dragon_http)|1021|268288|6|0.0%|0.0%|
[blocklist_de](#blocklist_de)|27144|27144|6|0.0%|0.0%|
[openbl_60d](#openbl_60d)|6960|6960|5|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|5|0.9%|0.0%|
[voipbl](#voipbl)|10586|10998|4|0.0%|0.0%|
[openbl_30d](#openbl_30d)|2792|2792|3|0.1%|0.0%|
[iw_spamlist](#iw_spamlist)|3787|3787|3|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|3|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13852|13852|3|0.0%|0.0%|
[proxyrss](#proxyrss)|1735|1735|2|0.1%|0.0%|
[malc0de](#malc0de)|276|276|2|0.7%|0.0%|
[et_compromised](#et_compromised)|1704|1704|2|0.1%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1697|1697|2|0.1%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|84|84|2|2.3%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|17849|17849|2|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2473|2473|2|0.0%|0.0%|
[zeus_badips](#zeus_badips)|202|202|1|0.4%|0.0%|
[zeus](#zeus)|230|230|1|0.4%|0.0%|
[xroxy](#xroxy)|2174|2174|1|0.0%|0.0%|
[sslbl](#sslbl)|370|370|1|0.2%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|1|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2855|2855|1|0.0%|0.0%|
[proxz](#proxz)|1356|1356|1|0.0%|0.0%|
[php_harvesters](#php_harvesters)|408|408|1|0.2%|0.0%|
[php_dictionary](#php_dictionary)|737|737|1|0.1%|0.0%|
[php_commenters](#php_commenters)|458|458|1|0.2%|0.0%|
[palevo](#palevo)|13|13|1|7.6%|0.0%|
[nt_malware_http](#nt_malware_http)|69|69|1|1.4%|0.0%|
[feodo](#feodo)|105|105|1|0.9%|0.0%|
[bogons](#bogons)|13|592708608|1|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1969|1969|1|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|2979|2979|1|0.0%|0.0%|

## ib_bluetack_webexploit

[iBlocklist.com](https://www.iblocklist.com/) free version of [BlueTack.co.uk](http://www.bluetack.co.uk/) web server hack and exploit attempts

Source is downloaded from [this link](http://list.iblocklist.com/?list=ghlzqtqxnzctvvajwwag&fileformat=p2p&archiveformat=gz).

The last time downloaded was found to be dated: Thu Jun 11 05:40:34 UTC 2015.

The ipset `ib_bluetack_webexploit` has **1450** entries, **1450** unique IPs.

The following table shows the overlaps of `ib_bluetack_webexploit` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ib_bluetack_webexploit`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ib_bluetack_webexploit`.
- ` this % ` is the percentage **of this ipset (`ib_bluetack_webexploit`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level3](#firehol_level3)|109170|9626833|1450|0.0%|100.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|108|0.0%|7.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|97|0.0%|6.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|45|0.0%|3.1%|
[firehol_level1](#firehol_level1)|5137|688854747|39|0.0%|2.6%|
[fullbogons](#fullbogons)|3775|670173256|33|0.0%|2.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|19|0.0%|1.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|7|0.0%|0.4%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|6|0.0%|0.4%|
[et_block](#et_block)|1000|18343756|6|0.0%|0.4%|
[alienvault_reputation](#alienvault_reputation)|189146|189146|6|0.0%|0.4%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|3|0.2%|0.2%|
[firehol_proxies](#firehol_proxies)|12828|13116|3|0.0%|0.2%|
[firehol_anonymous](#firehol_anonymous)|19294|83353|3|0.0%|0.2%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|2|0.0%|0.1%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|2|0.0%|0.1%|
[sorbs_spam](#sorbs_spam)|64701|65536|2|0.0%|0.1%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|2|0.0%|0.1%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|2|0.0%|0.1%|
[openbl_60d](#openbl_60d)|6960|6960|2|0.0%|0.1%|
[openbl_30d](#openbl_30d)|2792|2792|2|0.0%|0.1%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|2|0.3%|0.1%|
[firehol_level2](#firehol_level2)|20803|32382|2|0.0%|0.1%|
[dragon_http](#dragon_http)|1021|268288|2|0.0%|0.1%|
[blocklist_de_strongips](#blocklist_de_strongips)|170|170|2|1.1%|0.1%|
[blocklist_de_bots](#blocklist_de_bots)|2979|2979|2|0.0%|0.1%|
[blocklist_de](#blocklist_de)|27144|27144|2|0.0%|0.1%|
[stopforumspam_1d](#stopforumspam_1d)|6690|6690|1|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9136|9136|1|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7952|7952|1|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|1|0.0%|0.0%|
[et_botcc](#et_botcc)|505|505|1|0.1%|0.0%|
[dragon_sshpauth](#dragon_sshpauth)|1595|1659|1|0.0%|0.0%|

## iw_spamlist

[ImproWare Antispam](http://antispam.imp.ch/) IPs sending spam, in the last 3 days

Source is downloaded from [this link](http://antispam.imp.ch/spamlist).

The last time downloaded was found to be dated: Fri Jun 12 08:20:05 UTC 2015.

The ipset `iw_spamlist` has **3787** entries, **3787** unique IPs.

The following table shows the overlaps of `iw_spamlist` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `iw_spamlist`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `iw_spamlist`.
- ` this % ` is the percentage **of this ipset (`iw_spamlist`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[sorbs_spam](#sorbs_spam)|64701|65536|1057|1.6%|27.9%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|1052|1.6%|27.7%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|1052|1.6%|27.7%|
[nixspam](#nixspam)|18020|18020|513|2.8%|13.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|275|0.0%|7.2%|
[firehol_level2](#firehol_level2)|20803|32382|123|0.3%|3.2%|
[blocklist_de](#blocklist_de)|27144|27144|122|0.4%|3.2%|
[blocklist_de_mail](#blocklist_de_mail)|17849|17849|113|0.6%|2.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|93|0.0%|2.4%|
[firehol_level3](#firehol_level3)|109170|9626833|93|0.0%|2.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|66|0.0%|1.7%|
[snort_ipfilter](#snort_ipfilter)|9136|9136|50|0.5%|1.3%|
[sorbs_web](#sorbs_web)|626|627|24|3.8%|0.6%|
[alienvault_reputation](#alienvault_reputation)|189146|189146|24|0.0%|0.6%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|20|0.0%|0.5%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|12|0.0%|0.3%|
[iw_wormlist](#iw_wormlist)|34|34|12|35.2%|0.3%|
[firehol_proxies](#firehol_proxies)|12828|13116|9|0.0%|0.2%|
[firehol_level1](#firehol_level1)|5137|688854747|9|0.0%|0.2%|
[firehol_anonymous](#firehol_anonymous)|19294|83353|9|0.0%|0.2%|
[php_dictionary](#php_dictionary)|737|737|8|1.0%|0.2%|
[ri_web_proxies](#ri_web_proxies)|7952|7952|7|0.0%|0.1%|
[php_spammers](#php_spammers)|735|735|6|0.8%|0.1%|
[fullbogons](#fullbogons)|3775|670173256|5|0.0%|0.1%|
[bogons](#bogons)|13|592708608|5|0.0%|0.1%|
[php_harvesters](#php_harvesters)|408|408|4|0.9%|0.1%|
[blocklist_de_bots](#blocklist_de_bots)|2979|2979|4|0.1%|0.1%|
[stopforumspam_1d](#stopforumspam_1d)|6690|6690|3|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|3|0.0%|0.0%|
[php_commenters](#php_commenters)|458|458|3|0.6%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|3|0.0%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|0.0%|
[et_block](#et_block)|1000|18343756|3|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2719|2719|3|0.1%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2473|2473|3|0.1%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13852|13852|3|0.0%|0.0%|
[xroxy](#xroxy)|2174|2174|2|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2855|2855|2|0.0%|0.0%|
[dragon_http](#dragon_http)|1021|268288|2|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|1525|1525|2|0.1%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|1|0.0%|0.0%|
[sorbs_socks](#sorbs_socks)|7|7|1|14.2%|0.0%|
[sorbs_misc](#sorbs_misc)|7|7|1|14.2%|0.0%|
[sorbs_http](#sorbs_http)|7|7|1|14.2%|0.0%|
[proxz](#proxz)|1356|1356|1|0.0%|0.0%|

## iw_wormlist

[ImproWare Antispam](http://antispam.imp.ch/) IPs sending emails with viruses or worms, in the last 3 days

Source is downloaded from [this link](http://antispam.imp.ch/wormlist).

The last time downloaded was found to be dated: Fri Jun 12 08:20:05 UTC 2015.

The ipset `iw_wormlist` has **34** entries, **34** unique IPs.

The following table shows the overlaps of `iw_wormlist` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `iw_wormlist`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `iw_wormlist`.
- ` this % ` is the percentage **of this ipset (`iw_wormlist`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level3](#firehol_level3)|109170|9626833|34|0.0%|100.0%|
[iw_spamlist](#iw_spamlist)|3787|3787|12|0.3%|35.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|2|0.0%|5.8%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|1|0.0%|2.9%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|1|0.0%|2.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|1|0.0%|2.9%|
[firehol_level2](#firehol_level2)|20803|32382|1|0.0%|2.9%|
[blocklist_de_mail](#blocklist_de_mail)|17849|17849|1|0.0%|2.9%|
[blocklist_de](#blocklist_de)|27144|27144|1|0.0%|2.9%|

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
[firehol_level3](#firehol_level3)|109170|9626833|276|0.0%|100.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|44|0.0%|15.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|16|0.0%|5.7%|
[cleanmx_viruses](#cleanmx_viruses)|121|121|16|13.2%|5.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|10|0.0%|3.6%|
[alienvault_reputation](#alienvault_reputation)|189146|189146|9|0.0%|3.2%|
[firehol_level1](#firehol_level1)|5137|688854747|5|0.0%|1.8%|
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
[firehol_level3](#firehol_level3)|109170|9626833|1288|0.0%|100.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|147|0.0%|11.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|66|0.0%|5.1%|
[firehol_level1](#firehol_level1)|5137|688854747|39|0.0%|3.0%|
[et_block](#et_block)|1000|18343756|30|0.0%|2.3%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|29|0.0%|2.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|27|0.0%|2.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|27|0.0%|2.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|26|0.0%|2.0%|
[snort_ipfilter](#snort_ipfilter)|9136|9136|11|0.1%|0.8%|
[fullbogons](#fullbogons)|3775|670173256|9|0.0%|0.6%|
[alienvault_reputation](#alienvault_reputation)|189146|189146|8|0.0%|0.6%|
[malc0de](#malc0de)|276|276|4|1.4%|0.3%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|3|0.0%|0.2%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|3|0.2%|0.2%|
[dragon_http](#dragon_http)|1021|268288|2|0.0%|0.1%|
[cleanmx_viruses](#cleanmx_viruses)|121|121|2|1.6%|0.1%|
[zeus](#zeus)|230|230|1|0.4%|0.0%|
[nixspam](#nixspam)|18020|18020|1|0.0%|0.0%|
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
[firehol_proxies](#firehol_proxies)|12828|13116|524|3.9%|100.0%|
[firehol_anonymous](#firehol_anonymous)|19294|83353|524|0.6%|100.0%|
[firehol_level3](#firehol_level3)|109170|9626833|346|0.0%|66.0%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|345|0.3%|65.8%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|277|0.9%|52.8%|
[snort_ipfilter](#snort_ipfilter)|9136|9136|237|2.5%|45.2%|
[et_tor](#et_tor)|6500|6500|233|3.5%|44.4%|
[dm_tor](#dm_tor)|6455|6455|229|3.5%|43.7%|
[bm_tor](#bm_tor)|6338|6338|229|3.6%|43.7%|
[tor_exits](#tor_exits)|1101|1101|228|20.7%|43.5%|
[firehol_level2](#firehol_level2)|20803|32382|194|0.5%|37.0%|
[stopforumspam_1d](#stopforumspam_1d)|6690|6690|192|2.8%|36.6%|
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
[blocklist_de](#blocklist_de)|27144|27144|5|0.0%|0.9%|
[dragon_http](#dragon_http)|1021|268288|4|0.0%|0.7%|
[blocklist_de_bots](#blocklist_de_bots)|2979|2979|4|0.1%|0.7%|
[xroxy](#xroxy)|2174|2174|3|0.1%|0.5%|
[voipbl](#voipbl)|10586|10998|2|0.0%|0.3%|
[proxz](#proxz)|1356|1356|2|0.1%|0.3%|
[nixspam](#nixspam)|18020|18020|2|0.0%|0.3%|
[firehol_level1](#firehol_level1)|5137|688854747|2|0.0%|0.3%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|1|0.0%|0.1%|
[sorbs_spam](#sorbs_spam)|64701|65536|1|0.0%|0.1%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|1|0.0%|0.1%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|1|0.0%|0.1%|
[shunlist](#shunlist)|1185|1185|1|0.0%|0.1%|
[ri_connect_proxies](#ri_connect_proxies)|2855|2855|1|0.0%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.1%|
[et_block](#et_block)|1000|18343756|1|0.0%|0.1%|
[dshield](#dshield)|20|5120|1|0.0%|0.1%|
[blocklist_de_mail](#blocklist_de_mail)|17849|17849|1|0.0%|0.1%|
[blocklist_de_apache](#blocklist_de_apache)|13852|13852|1|0.0%|0.1%|

## nixspam

[NiX Spam](http://www.heise.de/ix/NiX-Spam-DNSBL-and-blacklist-for-download-499637.html) IP addresses that sent spam in the last hour - automatically generated entries without distinguishing open proxies from relays, dialup gateways, and so on. All IPs are removed after 12 hours if there is no spam from there.

Source is downloaded from [this link](http://www.dnsbl.manitu.net/download/nixspam-ip.dump.gz).

The last time downloaded was found to be dated: Fri Jun 12 08:15:02 UTC 2015.

The ipset `nixspam` has **18020** entries, **18020** unique IPs.

The following table shows the overlaps of `nixspam` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `nixspam`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `nixspam`.
- ` this % ` is the percentage **of this ipset (`nixspam`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[sorbs_spam](#sorbs_spam)|64701|65536|1411|2.1%|7.8%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|1399|2.1%|7.7%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|1399|2.1%|7.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|981|0.0%|5.4%|
[firehol_level2](#firehol_level2)|20803|32382|516|1.5%|2.8%|
[iw_spamlist](#iw_spamlist)|3787|3787|513|13.5%|2.8%|
[blocklist_de](#blocklist_de)|27144|27144|494|1.8%|2.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|464|0.0%|2.5%|
[firehol_level3](#firehol_level3)|109170|9626833|426|0.0%|2.3%|
[blocklist_de_mail](#blocklist_de_mail)|17849|17849|426|2.3%|2.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|309|0.0%|1.7%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|231|0.2%|1.2%|
[snort_ipfilter](#snort_ipfilter)|9136|9136|195|2.1%|1.0%|
[firehol_anonymous](#firehol_anonymous)|19294|83353|152|0.1%|0.8%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|147|0.5%|0.8%|
[firehol_proxies](#firehol_proxies)|12828|13116|145|1.1%|0.8%|
[php_dictionary](#php_dictionary)|737|737|102|13.8%|0.5%|
[ri_web_proxies](#ri_web_proxies)|7952|7952|98|1.2%|0.5%|
[sorbs_web](#sorbs_web)|626|627|90|14.3%|0.4%|
[php_spammers](#php_spammers)|735|735|89|12.1%|0.4%|
[xroxy](#xroxy)|2174|2174|68|3.1%|0.3%|
[stopforumspam_1d](#stopforumspam_1d)|6690|6690|64|0.9%|0.3%|
[proxz](#proxz)|1356|1356|47|3.4%|0.2%|
[alienvault_reputation](#alienvault_reputation)|189146|189146|41|0.0%|0.2%|
[blocklist_de_bots](#blocklist_de_bots)|2979|2979|39|1.3%|0.2%|
[firehol_level1](#firehol_level1)|5137|688854747|31|0.0%|0.1%|
[dragon_http](#dragon_http)|1021|268288|30|0.0%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|29|0.0%|0.1%|
[et_block](#et_block)|1000|18343756|29|0.0%|0.1%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|28|0.0%|0.1%|
[blocklist_de_imap](#blocklist_de_imap)|2719|2719|25|0.9%|0.1%|
[ri_connect_proxies](#ri_connect_proxies)|2855|2855|19|0.6%|0.1%|
[blocklist_de_apache](#blocklist_de_apache)|13852|13852|17|0.1%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2473|2473|15|0.6%|0.0%|
[php_commenters](#php_commenters)|458|458|14|3.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|12|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|11|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|1525|1525|11|0.7%|0.0%|
[proxyrss](#proxyrss)|1735|1735|10|0.5%|0.0%|
[tor_exits](#tor_exits)|1101|1101|8|0.7%|0.0%|
[openbl_60d](#openbl_60d)|6960|6960|8|0.1%|0.0%|
[dm_tor](#dm_tor)|6455|6455|7|0.1%|0.0%|
[php_harvesters](#php_harvesters)|408|408|6|1.4%|0.0%|
[bm_tor](#bm_tor)|6338|6338|6|0.0%|0.0%|
[et_tor](#et_tor)|6500|6500|5|0.0%|0.0%|
[openbl_30d](#openbl_30d)|2792|2792|4|0.1%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|2|0.3%|0.0%|
[et_compromised](#et_compromised)|1704|1704|2|0.1%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1697|1697|2|0.1%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|170|170|2|1.1%|0.0%|
[zeus_badips](#zeus_badips)|202|202|1|0.4%|0.0%|
[zeus](#zeus)|230|230|1|0.4%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|1|0.0%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|1|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|1|0.1%|0.0%|
[dshield](#dshield)|20|5120|1|0.0%|0.0%|
[dragon_sshpauth](#dragon_sshpauth)|1595|1659|1|0.0%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|121|121|1|0.8%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1969|1969|1|0.0%|0.0%|

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
[firehol_level1](#firehol_level1)|5137|688854747|8|0.0%|11.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|7|0.0%|10.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|5|0.0%|7.2%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|4|0.0%|5.7%|
[fullbogons](#fullbogons)|3775|670173256|4|0.0%|5.7%|
[et_block](#et_block)|1000|18343756|4|0.0%|5.7%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|4.3%|
[firehol_level3](#firehol_level3)|109170|9626833|3|0.0%|4.3%|
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
[firehol_level1](#firehol_level1)|5137|688854747|3|0.0%|6.9%|
[et_block](#et_block)|1000|18343756|3|0.0%|6.9%|
[nt_malware_http](#nt_malware_http)|69|69|2|2.8%|4.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|2|0.0%|4.6%|
[alienvault_reputation](#alienvault_reputation)|189146|189146|2|0.0%|4.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|1|0.0%|2.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|2.3%|
[firehol_level3](#firehol_level3)|109170|9626833|1|0.0%|2.3%|

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

The last time downloaded was found to be dated: Fri Jun 12 07:32:00 UTC 2015.

The ipset `openbl_1d` has **126** entries, **126** unique IPs.

The following table shows the overlaps of `openbl_1d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl_1d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl_1d`.
- ` this % ` is the percentage **of this ipset (`openbl_1d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[openbl_7d](#openbl_7d)|629|629|126|20.0%|100.0%|
[openbl_60d](#openbl_60d)|6960|6960|126|1.8%|100.0%|
[openbl_30d](#openbl_30d)|2792|2792|126|4.5%|100.0%|
[firehol_level3](#firehol_level3)|109170|9626833|126|0.0%|100.0%|
[firehol_level2](#firehol_level2)|20803|32382|126|0.3%|100.0%|
[alienvault_reputation](#alienvault_reputation)|189146|189146|120|0.0%|95.2%|
[blocklist_de](#blocklist_de)|27144|27144|111|0.4%|88.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1969|1969|110|5.5%|87.3%|
[dragon_sshpauth](#dragon_sshpauth)|1595|1659|85|5.1%|67.4%|
[shunlist](#shunlist)|1185|1185|69|5.8%|54.7%|
[bruteforceblocker](#bruteforceblocker)|1697|1697|60|3.5%|47.6%|
[et_compromised](#et_compromised)|1704|1704|56|3.2%|44.4%|
[blocklist_de_strongips](#blocklist_de_strongips)|170|170|18|10.5%|14.2%|
[firehol_level1](#firehol_level1)|5137|688854747|16|0.0%|12.6%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|12|0.0%|9.5%|
[et_block](#et_block)|1000|18343756|12|0.0%|9.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|10|0.0%|7.9%|
[dshield](#dshield)|20|5120|7|0.1%|5.5%|
[dragon_http](#dragon_http)|1021|268288|5|0.0%|3.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|4|0.0%|3.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|2.3%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|1|0.0%|0.7%|
[php_spammers](#php_spammers)|735|735|1|0.1%|0.7%|
[php_commenters](#php_commenters)|458|458|1|0.2%|0.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|1|0.0%|0.7%|
[ciarmy](#ciarmy)|416|416|1|0.2%|0.7%|
[blocklist_de_mail](#blocklist_de_mail)|17849|17849|1|0.0%|0.7%|
[blocklist_de_imap](#blocklist_de_imap)|2719|2719|1|0.0%|0.7%|

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
[firehol_level3](#firehol_level3)|109170|9626833|2792|0.0%|100.0%|
[alienvault_reputation](#alienvault_reputation)|189146|189146|2772|1.4%|99.2%|
[et_compromised](#et_compromised)|1704|1704|910|53.4%|32.5%|
[bruteforceblocker](#bruteforceblocker)|1697|1697|905|53.3%|32.4%|
[dragon_sshpauth](#dragon_sshpauth)|1595|1659|702|42.3%|25.1%|
[firehol_level2](#firehol_level2)|20803|32382|655|2.0%|23.4%|
[blocklist_de](#blocklist_de)|27144|27144|639|2.3%|22.8%|
[openbl_7d](#openbl_7d)|629|629|629|100.0%|22.5%|
[blocklist_de_ssh](#blocklist_de_ssh)|1969|1969|621|31.5%|22.2%|
[shunlist](#shunlist)|1185|1185|439|37.0%|15.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|286|0.0%|10.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|146|0.0%|5.2%|
[dragon_http](#dragon_http)|1021|268288|146|0.0%|5.2%|
[firehol_level1](#firehol_level1)|5137|688854747|135|0.0%|4.8%|
[openbl_1d](#openbl_1d)|126|126|126|100.0%|4.5%|
[et_block](#et_block)|1000|18343756|125|0.0%|4.4%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|119|0.0%|4.2%|
[dshield](#dshield)|20|5120|80|1.5%|2.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|65|0.0%|2.3%|
[blocklist_de_strongips](#blocklist_de_strongips)|170|170|23|13.5%|0.8%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|12|0.0%|0.4%|
[blocklist_de_mail](#blocklist_de_mail)|17849|17849|12|0.0%|0.4%|
[blocklist_de_imap](#blocklist_de_imap)|2719|2719|9|0.3%|0.3%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|5|0.0%|0.1%|
[blocklist_de_apache](#blocklist_de_apache)|13852|13852|5|0.0%|0.1%|
[nixspam](#nixspam)|18020|18020|4|0.0%|0.1%|
[voipbl](#voipbl)|10586|10998|3|0.0%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|3|0.0%|0.1%|
[zeus](#zeus)|230|230|2|0.8%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9136|9136|2|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|2|0.1%|0.0%|
[ciarmy](#ciarmy)|416|416|2|0.4%|0.0%|
[zeus_badips](#zeus_badips)|202|202|1|0.4%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|1|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6690|6690|1|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|1|0.0%|0.0%|
[php_spammers](#php_spammers)|735|735|1|0.1%|0.0%|
[php_commenters](#php_commenters)|458|458|1|0.2%|0.0%|
[firehol_anonymous](#firehol_anonymous)|19294|83353|1|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|1525|1525|1|0.0%|0.0%|

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
[firehol_level3](#firehol_level3)|109170|9626833|2918|0.0%|41.9%|
[openbl_30d](#openbl_30d)|2792|2792|2792|100.0%|40.1%|
[et_compromised](#et_compromised)|1704|1704|977|57.3%|14.0%|
[bruteforceblocker](#bruteforceblocker)|1697|1697|965|56.8%|13.8%|
[dragon_sshpauth](#dragon_sshpauth)|1595|1659|784|47.2%|11.2%|
[firehol_level2](#firehol_level2)|20803|32382|766|2.3%|11.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|740|0.0%|10.6%|
[blocklist_de](#blocklist_de)|27144|27144|733|2.7%|10.5%|
[blocklist_de_ssh](#blocklist_de_ssh)|1969|1969|706|35.8%|10.1%|
[openbl_7d](#openbl_7d)|629|629|629|100.0%|9.0%|
[shunlist](#shunlist)|1185|1185|464|39.1%|6.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|319|0.0%|4.5%|
[firehol_level1](#firehol_level1)|5137|688854747|253|0.0%|3.6%|
[et_block](#et_block)|1000|18343756|244|0.0%|3.5%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|235|0.0%|3.3%|
[dragon_http](#dragon_http)|1021|268288|213|0.0%|3.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|161|0.0%|2.3%|
[openbl_1d](#openbl_1d)|126|126|126|100.0%|1.8%|
[dshield](#dshield)|20|5120|84|1.6%|1.2%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|47|0.0%|0.6%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|26|0.0%|0.3%|
[snort_ipfilter](#snort_ipfilter)|9136|9136|24|0.2%|0.3%|
[blocklist_de_strongips](#blocklist_de_strongips)|170|170|24|14.1%|0.3%|
[firehol_anonymous](#firehol_anonymous)|19294|83353|23|0.0%|0.3%|
[tor_exits](#tor_exits)|1101|1101|20|1.8%|0.2%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|20|3.8%|0.2%|
[firehol_proxies](#firehol_proxies)|12828|13116|20|0.1%|0.2%|
[et_tor](#et_tor)|6500|6500|20|0.3%|0.2%|
[dm_tor](#dm_tor)|6455|6455|20|0.3%|0.2%|
[bm_tor](#bm_tor)|6338|6338|20|0.3%|0.2%|
[stopforumspam_1d](#stopforumspam_1d)|6690|6690|18|0.2%|0.2%|
[blocklist_de_mail](#blocklist_de_mail)|17849|17849|18|0.1%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|16|0.0%|0.2%|
[blocklist_de_imap](#blocklist_de_imap)|2719|2719|15|0.5%|0.2%|
[php_commenters](#php_commenters)|458|458|12|2.6%|0.1%|
[voipbl](#voipbl)|10586|10998|8|0.0%|0.1%|
[nixspam](#nixspam)|18020|18020|8|0.0%|0.1%|
[blocklist_de_apache](#blocklist_de_apache)|13852|13852|8|0.0%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|5|0.0%|0.0%|
[zeus](#zeus)|230|230|2|0.8%|0.0%|
[sorbs_spam](#sorbs_spam)|64701|65536|2|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|2|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|2|0.0%|0.0%|
[php_harvesters](#php_harvesters)|408|408|2|0.4%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|2|0.1%|0.0%|
[ciarmy](#ciarmy)|416|416|2|0.4%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|1525|1525|2|0.1%|0.0%|
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
[firehol_level3](#firehol_level3)|109170|9626833|629|0.0%|100.0%|
[alienvault_reputation](#alienvault_reputation)|189146|189146|622|0.3%|98.8%|
[firehol_level2](#firehol_level2)|20803|32382|391|1.2%|62.1%|
[blocklist_de](#blocklist_de)|27144|27144|376|1.3%|59.7%|
[blocklist_de_ssh](#blocklist_de_ssh)|1969|1969|369|18.7%|58.6%|
[dragon_sshpauth](#dragon_sshpauth)|1595|1659|346|20.8%|55.0%|
[bruteforceblocker](#bruteforceblocker)|1697|1697|308|18.1%|48.9%|
[et_compromised](#et_compromised)|1704|1704|305|17.8%|48.4%|
[shunlist](#shunlist)|1185|1185|207|17.4%|32.9%|
[openbl_1d](#openbl_1d)|126|126|126|100.0%|20.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|66|0.0%|10.4%|
[firehol_level1](#firehol_level1)|5137|688854747|60|0.0%|9.5%|
[et_block](#et_block)|1000|18343756|57|0.0%|9.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|53|0.0%|8.4%|
[dragon_http](#dragon_http)|1021|268288|51|0.0%|8.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|36|0.0%|5.7%|
[blocklist_de_strongips](#blocklist_de_strongips)|170|170|22|12.9%|3.4%|
[dshield](#dshield)|20|5120|21|0.4%|3.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|13|0.0%|2.0%|
[blocklist_de_mail](#blocklist_de_mail)|17849|17849|6|0.0%|0.9%|
[blocklist_de_imap](#blocklist_de_imap)|2719|2719|5|0.1%|0.7%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|4|0.0%|0.6%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|2|0.0%|0.3%|
[ciarmy](#ciarmy)|416|416|2|0.4%|0.3%|
[blocklist_de_apache](#blocklist_de_apache)|13852|13852|2|0.0%|0.3%|
[zeus_badips](#zeus_badips)|202|202|1|0.4%|0.1%|
[zeus](#zeus)|230|230|1|0.4%|0.1%|
[snort_ipfilter](#snort_ipfilter)|9136|9136|1|0.0%|0.1%|
[php_spammers](#php_spammers)|735|735|1|0.1%|0.1%|
[php_commenters](#php_commenters)|458|458|1|0.2%|0.1%|
[blocklist_de_ftp](#blocklist_de_ftp)|1525|1525|1|0.0%|0.1%|

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
[firehol_level1](#firehol_level1)|5137|688854747|13|0.0%|100.0%|
[et_block](#et_block)|1000|18343756|12|0.0%|92.3%|
[snort_ipfilter](#snort_ipfilter)|9136|9136|11|0.1%|84.6%|
[firehol_level3](#firehol_level3)|109170|9626833|11|0.0%|84.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|2|0.0%|15.3%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|7.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|1|0.0%|7.6%|

## php_commenters

[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) comment spammers (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=c&rss=1).

The last time downloaded was found to be dated: Fri Jun 12 07:54:24 UTC 2015.

The ipset `php_commenters` has **458** entries, **458** unique IPs.

The following table shows the overlaps of `php_commenters` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `php_commenters`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `php_commenters`.
- ` this % ` is the percentage **of this ipset (`php_commenters`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level3](#firehol_level3)|109170|9626833|458|0.0%|100.0%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|334|0.3%|72.9%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|248|0.8%|54.1%|
[firehol_level2](#firehol_level2)|20803|32382|193|0.5%|42.1%|
[stopforumspam_1d](#stopforumspam_1d)|6690|6690|165|2.4%|36.0%|
[blocklist_de](#blocklist_de)|27144|27144|106|0.3%|23.1%|
[firehol_anonymous](#firehol_anonymous)|19294|83353|90|0.1%|19.6%|
[blocklist_de_bots](#blocklist_de_bots)|2979|2979|87|2.9%|18.9%|
[firehol_proxies](#firehol_proxies)|12828|13116|86|0.6%|18.7%|
[snort_ipfilter](#snort_ipfilter)|9136|9136|71|0.7%|15.5%|
[tor_exits](#tor_exits)|1101|1101|54|4.9%|11.7%|
[php_spammers](#php_spammers)|735|735|54|7.3%|11.7%|
[et_tor](#et_tor)|6500|6500|54|0.8%|11.7%|
[dm_tor](#dm_tor)|6455|6455|54|0.8%|11.7%|
[bm_tor](#bm_tor)|6338|6338|54|0.8%|11.7%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|53|10.1%|11.5%|
[blocklist_de_strongips](#blocklist_de_strongips)|170|170|44|25.8%|9.6%|
[firehol_level1](#firehol_level1)|5137|688854747|39|0.0%|8.5%|
[php_dictionary](#php_dictionary)|737|737|38|5.1%|8.2%|
[ri_web_proxies](#ri_web_proxies)|7952|7952|30|0.3%|6.5%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|29|0.0%|6.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|29|0.0%|6.3%|
[et_block](#et_block)|1000|18343756|29|0.0%|6.3%|
[blocklist_de_mail](#blocklist_de_mail)|17849|17849|29|0.1%|6.3%|
[blocklist_de_apache](#blocklist_de_apache)|13852|13852|28|0.2%|6.1%|
[sorbs_spam](#sorbs_spam)|64701|65536|27|0.0%|5.8%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|27|0.0%|5.8%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|27|0.0%|5.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|19|0.0%|4.1%|
[alienvault_reputation](#alienvault_reputation)|189146|189146|19|0.0%|4.1%|
[php_harvesters](#php_harvesters)|408|408|15|3.6%|3.2%|
[nixspam](#nixspam)|18020|18020|14|0.0%|3.0%|
[xroxy](#xroxy)|2174|2174|13|0.5%|2.8%|
[openbl_60d](#openbl_60d)|6960|6960|12|0.1%|2.6%|
[proxz](#proxz)|1356|1356|10|0.7%|2.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|10|0.0%|2.1%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|8|0.0%|1.7%|
[ri_connect_proxies](#ri_connect_proxies)|2855|2855|6|0.2%|1.3%|
[proxyrss](#proxyrss)|1735|1735|6|0.3%|1.3%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2473|2473|6|0.2%|1.3%|
[sorbs_web](#sorbs_web)|626|627|4|0.6%|0.8%|
[dragon_http](#dragon_http)|1021|268288|4|0.0%|0.8%|
[iw_spamlist](#iw_spamlist)|3787|3787|3|0.0%|0.6%|
[zeus_badips](#zeus_badips)|202|202|1|0.4%|0.2%|
[zeus](#zeus)|230|230|1|0.4%|0.2%|
[openbl_7d](#openbl_7d)|629|629|1|0.1%|0.2%|
[openbl_30d](#openbl_30d)|2792|2792|1|0.0%|0.2%|
[openbl_1d](#openbl_1d)|126|126|1|0.7%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.2%|
[fullbogons](#fullbogons)|3775|670173256|1|0.0%|0.2%|
[et_compromised](#et_compromised)|1704|1704|1|0.0%|0.2%|
[dshield](#dshield)|20|5120|1|0.0%|0.2%|
[bruteforceblocker](#bruteforceblocker)|1697|1697|1|0.0%|0.2%|
[bogons](#bogons)|13|592708608|1|0.0%|0.2%|
[blocklist_de_ssh](#blocklist_de_ssh)|1969|1969|1|0.0%|0.2%|

## php_dictionary

[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) directory attackers (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=d&rss=1).

The last time downloaded was found to be dated: Fri Jun 12 07:54:25 UTC 2015.

The ipset `php_dictionary` has **737** entries, **737** unique IPs.

The following table shows the overlaps of `php_dictionary` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `php_dictionary`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `php_dictionary`.
- ` this % ` is the percentage **of this ipset (`php_dictionary`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level3](#firehol_level3)|109170|9626833|737|0.0%|100.0%|
[php_spammers](#php_spammers)|735|735|322|43.8%|43.6%|
[sorbs_spam](#sorbs_spam)|64701|65536|214|0.3%|29.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|214|0.3%|29.0%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|214|0.3%|29.0%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|139|0.1%|18.8%|
[firehol_level2](#firehol_level2)|20803|32382|122|0.3%|16.5%|
[blocklist_de](#blocklist_de)|27144|27144|115|0.4%|15.6%|
[nixspam](#nixspam)|18020|18020|102|0.5%|13.8%|
[firehol_anonymous](#firehol_anonymous)|19294|83353|98|0.1%|13.2%|
[firehol_proxies](#firehol_proxies)|12828|13116|97|0.7%|13.1%|
[snort_ipfilter](#snort_ipfilter)|9136|9136|95|1.0%|12.8%|
[blocklist_de_mail](#blocklist_de_mail)|17849|17849|94|0.5%|12.7%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|93|0.3%|12.6%|
[ri_web_proxies](#ri_web_proxies)|7952|7952|67|0.8%|9.0%|
[xroxy](#xroxy)|2174|2174|41|1.8%|5.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|39|0.0%|5.2%|
[php_commenters](#php_commenters)|458|458|38|8.2%|5.1%|
[sorbs_web](#sorbs_web)|626|627|34|5.4%|4.6%|
[stopforumspam_1d](#stopforumspam_1d)|6690|6690|30|0.4%|4.0%|
[proxz](#proxz)|1356|1356|25|1.8%|3.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|23|0.0%|3.1%|
[blocklist_de_bots](#blocklist_de_bots)|2979|2979|17|0.5%|2.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|12|0.0%|1.6%|
[iw_spamlist](#iw_spamlist)|3787|3787|8|0.2%|1.0%|
[alienvault_reputation](#alienvault_reputation)|189146|189146|7|0.0%|0.9%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|6|0.0%|0.8%|
[firehol_level1](#firehol_level1)|5137|688854747|6|0.0%|0.8%|
[et_block](#et_block)|1000|18343756|6|0.0%|0.8%|
[ri_connect_proxies](#ri_connect_proxies)|2855|2855|5|0.1%|0.6%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|5|0.9%|0.6%|
[blocklist_de_strongips](#blocklist_de_strongips)|170|170|5|2.9%|0.6%|
[tor_exits](#tor_exits)|1101|1101|4|0.3%|0.5%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|4|0.0%|0.5%|
[et_tor](#et_tor)|6500|6500|4|0.0%|0.5%|
[dm_tor](#dm_tor)|6455|6455|4|0.0%|0.5%|
[bm_tor](#bm_tor)|6338|6338|4|0.0%|0.5%|
[php_harvesters](#php_harvesters)|408|408|3|0.7%|0.4%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|3|0.0%|0.4%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2473|2473|3|0.1%|0.4%|
[blocklist_de_apache](#blocklist_de_apache)|13852|13852|3|0.0%|0.4%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|2|0.3%|0.2%|
[dragon_http](#dragon_http)|1021|268288|2|0.0%|0.2%|
[sorbs_socks](#sorbs_socks)|7|7|1|14.2%|0.1%|
[sorbs_misc](#sorbs_misc)|7|7|1|14.2%|0.1%|
[sorbs_http](#sorbs_http)|7|7|1|14.2%|0.1%|
[proxyrss](#proxyrss)|1735|1735|1|0.0%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.1%|
[blocklist_de_ftp](#blocklist_de_ftp)|1525|1525|1|0.0%|0.1%|

## php_harvesters

[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) harvesters (IPs that surf the internet looking for email addresses) (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=h&rss=1).

The last time downloaded was found to be dated: Fri Jun 12 07:54:23 UTC 2015.

The ipset `php_harvesters` has **408** entries, **408** unique IPs.

The following table shows the overlaps of `php_harvesters` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `php_harvesters`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `php_harvesters`.
- ` this % ` is the percentage **of this ipset (`php_harvesters`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level3](#firehol_level3)|109170|9626833|408|0.0%|100.0%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|87|0.0%|21.3%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|65|0.2%|15.9%|
[firehol_level2](#firehol_level2)|20803|32382|58|0.1%|14.2%|
[stopforumspam_1d](#stopforumspam_1d)|6690|6690|45|0.6%|11.0%|
[blocklist_de](#blocklist_de)|27144|27144|36|0.1%|8.8%|
[blocklist_de_bots](#blocklist_de_bots)|2979|2979|26|0.8%|6.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|20|0.0%|4.9%|
[sorbs_spam](#sorbs_spam)|64701|65536|16|0.0%|3.9%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|16|0.0%|3.9%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|16|0.0%|3.9%|
[php_commenters](#php_commenters)|458|458|15|3.2%|3.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|12|0.0%|2.9%|
[firehol_proxies](#firehol_proxies)|12828|13116|12|0.0%|2.9%|
[firehol_anonymous](#firehol_anonymous)|19294|83353|12|0.0%|2.9%|
[alienvault_reputation](#alienvault_reputation)|189146|189146|12|0.0%|2.9%|
[snort_ipfilter](#snort_ipfilter)|9136|9136|11|0.1%|2.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|9|0.0%|2.2%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|7|1.3%|1.7%|
[et_tor](#et_tor)|6500|6500|7|0.1%|1.7%|
[dm_tor](#dm_tor)|6455|6455|7|0.1%|1.7%|
[bm_tor](#bm_tor)|6338|6338|7|0.1%|1.7%|
[tor_exits](#tor_exits)|1101|1101|6|0.5%|1.4%|
[nixspam](#nixspam)|18020|18020|6|0.0%|1.4%|
[blocklist_de_mail](#blocklist_de_mail)|17849|17849|5|0.0%|1.2%|
[iw_spamlist](#iw_spamlist)|3787|3787|4|0.1%|0.9%|
[php_spammers](#php_spammers)|735|735|3|0.4%|0.7%|
[php_dictionary](#php_dictionary)|737|737|3|0.4%|0.7%|
[firehol_level1](#firehol_level1)|5137|688854747|3|0.0%|0.7%|
[blocklist_de_strongips](#blocklist_de_strongips)|170|170|3|1.7%|0.7%|
[blocklist_de_ftp](#blocklist_de_ftp)|1525|1525|3|0.1%|0.7%|
[xroxy](#xroxy)|2174|2174|2|0.0%|0.4%|
[ri_web_proxies](#ri_web_proxies)|7952|7952|2|0.0%|0.4%|
[openbl_60d](#openbl_60d)|6960|6960|2|0.0%|0.4%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|2|0.0%|0.4%|
[blocklist_de_imap](#blocklist_de_imap)|2719|2719|2|0.0%|0.4%|
[blocklist_de_apache](#blocklist_de_apache)|13852|13852|2|0.0%|0.4%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|1|0.0%|0.2%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|1|0.0%|0.2%|
[sorbs_web](#sorbs_web)|626|627|1|0.1%|0.2%|
[ri_connect_proxies](#ri_connect_proxies)|2855|2855|1|0.0%|0.2%|
[proxyrss](#proxyrss)|1735|1735|1|0.0%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.2%|
[fullbogons](#fullbogons)|3775|670173256|1|0.0%|0.2%|
[et_block](#et_block)|1000|18343756|1|0.0%|0.2%|
[bogons](#bogons)|13|592708608|1|0.0%|0.2%|
[blocklist_de_ssh](#blocklist_de_ssh)|1969|1969|1|0.0%|0.2%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2473|2473|1|0.0%|0.2%|

## php_spammers

[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) spam servers (IPs used by spammers to send messages) (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=s&rss=1).

The last time downloaded was found to be dated: Fri Jun 12 07:54:23 UTC 2015.

The ipset `php_spammers` has **735** entries, **735** unique IPs.

The following table shows the overlaps of `php_spammers` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `php_spammers`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `php_spammers`.
- ` this % ` is the percentage **of this ipset (`php_spammers`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level3](#firehol_level3)|109170|9626833|735|0.0%|100.0%|
[php_dictionary](#php_dictionary)|737|737|322|43.6%|43.8%|
[sorbs_spam](#sorbs_spam)|64701|65536|184|0.2%|25.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|184|0.2%|25.0%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|184|0.2%|25.0%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|151|0.1%|20.5%|
[firehol_level2](#firehol_level2)|20803|32382|115|0.3%|15.6%|
[blocklist_de](#blocklist_de)|27144|27144|105|0.3%|14.2%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|93|0.3%|12.6%|
[nixspam](#nixspam)|18020|18020|89|0.4%|12.1%|
[snort_ipfilter](#snort_ipfilter)|9136|9136|84|0.9%|11.4%|
[firehol_anonymous](#firehol_anonymous)|19294|83353|82|0.0%|11.1%|
[firehol_proxies](#firehol_proxies)|12828|13116|80|0.6%|10.8%|
[blocklist_de_mail](#blocklist_de_mail)|17849|17849|73|0.4%|9.9%|
[ri_web_proxies](#ri_web_proxies)|7952|7952|54|0.6%|7.3%|
[php_commenters](#php_commenters)|458|458|54|11.7%|7.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|54|0.0%|7.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|44|0.0%|5.9%|
[stopforumspam_1d](#stopforumspam_1d)|6690|6690|40|0.5%|5.4%|
[xroxy](#xroxy)|2174|2174|34|1.5%|4.6%|
[sorbs_web](#sorbs_web)|626|627|27|4.3%|3.6%|
[blocklist_de_bots](#blocklist_de_bots)|2979|2979|24|0.8%|3.2%|
[proxz](#proxz)|1356|1356|22|1.6%|2.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|11|0.0%|1.4%|
[blocklist_de_strongips](#blocklist_de_strongips)|170|170|10|5.8%|1.3%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|6|1.1%|0.8%|
[iw_spamlist](#iw_spamlist)|3787|3787|6|0.1%|0.8%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2473|2473|6|0.2%|0.8%|
[blocklist_de_apache](#blocklist_de_apache)|13852|13852|6|0.0%|0.8%|
[tor_exits](#tor_exits)|1101|1101|5|0.4%|0.6%|
[et_tor](#et_tor)|6500|6500|5|0.0%|0.6%|
[dm_tor](#dm_tor)|6455|6455|5|0.0%|0.6%|
[bm_tor](#bm_tor)|6338|6338|5|0.0%|0.6%|
[alienvault_reputation](#alienvault_reputation)|189146|189146|5|0.0%|0.6%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|4|0.0%|0.5%|
[firehol_level1](#firehol_level1)|5137|688854747|4|0.0%|0.5%|
[et_block](#et_block)|1000|18343756|4|0.0%|0.5%|
[ri_connect_proxies](#ri_connect_proxies)|2855|2855|3|0.1%|0.4%|
[php_harvesters](#php_harvesters)|408|408|3|0.7%|0.4%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|0.4%|
[proxyrss](#proxyrss)|1735|1735|2|0.1%|0.2%|
[openbl_7d](#openbl_7d)|629|629|1|0.1%|0.1%|
[openbl_60d](#openbl_60d)|6960|6960|1|0.0%|0.1%|
[openbl_30d](#openbl_30d)|2792|2792|1|0.0%|0.1%|
[openbl_1d](#openbl_1d)|126|126|1|0.7%|0.1%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|1|0.1%|0.1%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|1|0.0%|0.1%|
[et_compromised](#et_compromised)|1704|1704|1|0.0%|0.1%|
[bruteforceblocker](#bruteforceblocker)|1697|1697|1|0.0%|0.1%|
[blocklist_de_ssh](#blocklist_de_ssh)|1969|1969|1|0.0%|0.1%|
[blocklist_de_ftp](#blocklist_de_ftp)|1525|1525|1|0.0%|0.1%|

## proxyrss

[proxyrss.com](http://www.proxyrss.com) open proxies syndicated from multiple sources.

Source is downloaded from [this link](http://www.proxyrss.com/proxylists/all.gz).

The last time downloaded was found to be dated: Fri Jun 12 04:31:22 UTC 2015.

The ipset `proxyrss` has **1735** entries, **1735** unique IPs.

The following table shows the overlaps of `proxyrss` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `proxyrss`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `proxyrss`.
- ` this % ` is the percentage **of this ipset (`proxyrss`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_proxies](#firehol_proxies)|12828|13116|1735|13.2%|100.0%|
[firehol_anonymous](#firehol_anonymous)|19294|83353|1735|2.0%|100.0%|
[firehol_level3](#firehol_level3)|109170|9626833|745|0.0%|42.9%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|744|0.7%|42.8%|
[ri_web_proxies](#ri_web_proxies)|7952|7952|677|8.5%|39.0%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|597|2.0%|34.4%|
[firehol_level2](#firehol_level2)|20803|32382|411|1.2%|23.6%|
[xroxy](#xroxy)|2174|2174|376|17.2%|21.6%|
[stopforumspam_1d](#stopforumspam_1d)|6690|6690|331|4.9%|19.0%|
[proxz](#proxz)|1356|1356|300|22.1%|17.2%|
[blocklist_de_bots](#blocklist_de_bots)|2979|2979|232|7.7%|13.3%|
[blocklist_de](#blocklist_de)|27144|27144|232|0.8%|13.3%|
[ri_connect_proxies](#ri_connect_proxies)|2855|2855|222|7.7%|12.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|52|0.0%|2.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|52|0.0%|2.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|26|0.0%|1.4%|
[nixspam](#nixspam)|18020|18020|10|0.0%|0.5%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|9|1.3%|0.5%|
[blocklist_de_strongips](#blocklist_de_strongips)|170|170|7|4.1%|0.4%|
[php_commenters](#php_commenters)|458|458|6|1.3%|0.3%|
[dragon_http](#dragon_http)|1021|268288|4|0.0%|0.2%|
[sorbs_spam](#sorbs_spam)|64701|65536|3|0.0%|0.1%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|3|0.0%|0.1%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|3|0.0%|0.1%|
[snort_ipfilter](#snort_ipfilter)|9136|9136|2|0.0%|0.1%|
[php_spammers](#php_spammers)|735|735|2|0.2%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|2|0.0%|0.1%|
[sorbs_web](#sorbs_web)|626|627|1|0.1%|0.0%|
[php_harvesters](#php_harvesters)|408|408|1|0.2%|0.0%|
[php_dictionary](#php_dictionary)|737|737|1|0.1%|0.0%|
[et_tor](#et_tor)|6500|6500|1|0.0%|0.0%|
[et_compromised](#et_compromised)|1704|1704|1|0.0%|0.0%|
[dm_tor](#dm_tor)|6455|6455|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1697|1697|1|0.0%|0.0%|
[bm_tor](#bm_tor)|6338|6338|1|0.0%|0.0%|
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
[firehol_proxies](#firehol_proxies)|12828|13116|1356|10.3%|100.0%|
[firehol_anonymous](#firehol_anonymous)|19294|83353|1356|1.6%|100.0%|
[firehol_level3](#firehol_level3)|109170|9626833|800|0.0%|58.9%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|794|0.8%|58.5%|
[ri_web_proxies](#ri_web_proxies)|7952|7952|619|7.7%|45.6%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|507|1.7%|37.3%|
[xroxy](#xroxy)|2174|2174|468|21.5%|34.5%|
[proxyrss](#proxyrss)|1735|1735|300|17.2%|22.1%|
[firehol_level2](#firehol_level2)|20803|32382|271|0.8%|19.9%|
[ri_connect_proxies](#ri_connect_proxies)|2855|2855|234|8.1%|17.2%|
[blocklist_de](#blocklist_de)|27144|27144|196|0.7%|14.4%|
[stopforumspam_1d](#stopforumspam_1d)|6690|6690|176|2.6%|12.9%|
[blocklist_de_bots](#blocklist_de_bots)|2979|2979|165|5.5%|12.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|106|0.0%|7.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|56|0.0%|4.1%|
[nixspam](#nixspam)|18020|18020|47|0.2%|3.4%|
[sorbs_spam](#sorbs_spam)|64701|65536|44|0.0%|3.2%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|44|0.0%|3.2%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|44|0.0%|3.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|44|0.0%|3.2%|
[blocklist_de_mail](#blocklist_de_mail)|17849|17849|31|0.1%|2.2%|
[snort_ipfilter](#snort_ipfilter)|9136|9136|29|0.3%|2.1%|
[php_dictionary](#php_dictionary)|737|737|25|3.3%|1.8%|
[php_spammers](#php_spammers)|735|735|22|2.9%|1.6%|
[php_commenters](#php_commenters)|458|458|10|2.1%|0.7%|
[sorbs_web](#sorbs_web)|626|627|8|1.2%|0.5%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|7|1.0%|0.5%|
[blocklist_de_strongips](#blocklist_de_strongips)|170|170|6|3.5%|0.4%|
[dragon_http](#dragon_http)|1021|268288|4|0.0%|0.2%|
[alienvault_reputation](#alienvault_reputation)|189146|189146|3|0.0%|0.2%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|2|0.3%|0.1%|
[et_compromised](#et_compromised)|1704|1704|2|0.1%|0.1%|
[bruteforceblocker](#bruteforceblocker)|1697|1697|2|0.1%|0.1%|
[iw_spamlist](#iw_spamlist)|3787|3787|1|0.0%|0.0%|
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
[firehol_proxies](#firehol_proxies)|12828|13116|2855|21.7%|100.0%|
[firehol_anonymous](#firehol_anonymous)|19294|83353|2855|3.4%|100.0%|
[firehol_level3](#firehol_level3)|109170|9626833|1592|0.0%|55.7%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|1591|1.6%|55.7%|
[ri_web_proxies](#ri_web_proxies)|7952|7952|1213|15.2%|42.4%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|531|1.8%|18.5%|
[xroxy](#xroxy)|2174|2174|396|18.2%|13.8%|
[proxz](#proxz)|1356|1356|234|17.2%|8.1%|
[proxyrss](#proxyrss)|1735|1735|222|12.7%|7.7%|
[firehol_level2](#firehol_level2)|20803|32382|146|0.4%|5.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|106|0.0%|3.7%|
[stopforumspam_1d](#stopforumspam_1d)|6690|6690|104|1.5%|3.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|86|0.0%|3.0%|
[blocklist_de](#blocklist_de)|27144|27144|69|0.2%|2.4%|
[blocklist_de_bots](#blocklist_de_bots)|2979|2979|65|2.1%|2.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|57|0.0%|1.9%|
[nixspam](#nixspam)|18020|18020|19|0.1%|0.6%|
[sorbs_spam](#sorbs_spam)|64701|65536|18|0.0%|0.6%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|18|0.0%|0.6%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|18|0.0%|0.6%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|7|1.0%|0.2%|
[snort_ipfilter](#snort_ipfilter)|9136|9136|6|0.0%|0.2%|
[php_commenters](#php_commenters)|458|458|6|1.3%|0.2%|
[php_dictionary](#php_dictionary)|737|737|5|0.6%|0.1%|
[dragon_http](#dragon_http)|1021|268288|4|0.0%|0.1%|
[php_spammers](#php_spammers)|735|735|3|0.4%|0.1%|
[blocklist_de_mail](#blocklist_de_mail)|17849|17849|3|0.0%|0.1%|
[alienvault_reputation](#alienvault_reputation)|189146|189146|3|0.0%|0.1%|
[iw_spamlist](#iw_spamlist)|3787|3787|2|0.0%|0.0%|
[sorbs_web](#sorbs_web)|626|627|1|0.1%|0.0%|
[php_harvesters](#php_harvesters)|408|408|1|0.2%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|1|0.1%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.0%|
[et_tor](#et_tor)|6500|6500|1|0.0%|0.0%|
[dm_tor](#dm_tor)|6455|6455|1|0.0%|0.0%|
[bm_tor](#bm_tor)|6338|6338|1|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13852|13852|1|0.0%|0.0%|

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
[firehol_proxies](#firehol_proxies)|12828|13116|7952|60.6%|100.0%|
[firehol_anonymous](#firehol_anonymous)|19294|83353|7952|9.5%|100.0%|
[firehol_level3](#firehol_level3)|109170|9626833|3755|0.0%|47.2%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|3712|3.9%|46.6%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|1487|5.1%|18.6%|
[ri_connect_proxies](#ri_connect_proxies)|2855|2855|1213|42.4%|15.2%|
[xroxy](#xroxy)|2174|2174|965|44.3%|12.1%|
[proxyrss](#proxyrss)|1735|1735|677|39.0%|8.5%|
[firehol_level2](#firehol_level2)|20803|32382|659|2.0%|8.2%|
[proxz](#proxz)|1356|1356|619|45.6%|7.7%|
[blocklist_de](#blocklist_de)|27144|27144|468|1.7%|5.8%|
[stopforumspam_1d](#stopforumspam_1d)|6690|6690|417|6.2%|5.2%|
[blocklist_de_bots](#blocklist_de_bots)|2979|2979|380|12.7%|4.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|225|0.0%|2.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|221|0.0%|2.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|156|0.0%|1.9%|
[sorbs_spam](#sorbs_spam)|64701|65536|145|0.2%|1.8%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|145|0.2%|1.8%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|145|0.2%|1.8%|
[nixspam](#nixspam)|18020|18020|98|0.5%|1.2%|
[blocklist_de_mail](#blocklist_de_mail)|17849|17849|87|0.4%|1.0%|
[php_dictionary](#php_dictionary)|737|737|67|9.0%|0.8%|
[snort_ipfilter](#snort_ipfilter)|9136|9136|63|0.6%|0.7%|
[php_spammers](#php_spammers)|735|735|54|7.3%|0.6%|
[php_commenters](#php_commenters)|458|458|30|6.5%|0.3%|
[sorbs_web](#sorbs_web)|626|627|22|3.5%|0.2%|
[dragon_http](#dragon_http)|1021|268288|20|0.0%|0.2%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|15|2.2%|0.1%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|10|1.9%|0.1%|
[blocklist_de_strongips](#blocklist_de_strongips)|170|170|8|4.7%|0.1%|
[iw_spamlist](#iw_spamlist)|3787|3787|7|0.1%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|6|0.0%|0.0%|
[et_tor](#et_tor)|6500|6500|5|0.0%|0.0%|
[dm_tor](#dm_tor)|6455|6455|5|0.0%|0.0%|
[bm_tor](#bm_tor)|6338|6338|5|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|4|0.0%|0.0%|
[alienvault_reputation](#alienvault_reputation)|189146|189146|4|0.0%|0.0%|
[php_harvesters](#php_harvesters)|408|408|2|0.4%|0.0%|
[sslbl](#sslbl)|370|370|1|0.2%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|1|0.0%|0.0%|
[firehol_level1](#firehol_level1)|5137|688854747|1|0.0%|0.0%|
[et_compromised](#et_compromised)|1704|1704|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1697|1697|1|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1969|1969|1|0.0%|0.0%|

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
[firehol_level3](#firehol_level3)|109170|9626833|1185|0.0%|100.0%|
[alienvault_reputation](#alienvault_reputation)|189146|189146|1165|0.6%|98.3%|
[openbl_60d](#openbl_60d)|6960|6960|464|6.6%|39.1%|
[openbl_30d](#openbl_30d)|2792|2792|439|15.7%|37.0%|
[dragon_sshpauth](#dragon_sshpauth)|1595|1659|381|22.9%|32.1%|
[firehol_level2](#firehol_level2)|20803|32382|356|1.0%|30.0%|
[blocklist_de](#blocklist_de)|27144|27144|351|1.2%|29.6%|
[et_compromised](#et_compromised)|1704|1704|341|20.0%|28.7%|
[bruteforceblocker](#bruteforceblocker)|1697|1697|341|20.0%|28.7%|
[blocklist_de_ssh](#blocklist_de_ssh)|1969|1969|309|15.6%|26.0%|
[openbl_7d](#openbl_7d)|629|629|207|32.9%|17.4%|
[firehol_level1](#firehol_level1)|5137|688854747|159|0.0%|13.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|120|0.0%|10.1%|
[et_block](#et_block)|1000|18343756|101|0.0%|8.5%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|90|0.0%|7.5%|
[dshield](#dshield)|20|5120|83|1.6%|7.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|70|0.0%|5.9%|
[openbl_1d](#openbl_1d)|126|126|69|54.7%|5.8%|
[sslbl](#sslbl)|370|370|58|15.6%|4.8%|
[blocklist_de_apache](#blocklist_de_apache)|13852|13852|37|0.2%|3.1%|
[ciarmy](#ciarmy)|416|416|29|6.9%|2.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|26|0.0%|2.1%|
[dragon_http](#dragon_http)|1021|268288|26|0.0%|2.1%|
[blocklist_de_strongips](#blocklist_de_strongips)|170|170|19|11.1%|1.6%|
[voipbl](#voipbl)|10586|10998|14|0.1%|1.1%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|4|0.0%|0.3%|
[blocklist_de_mail](#blocklist_de_mail)|17849|17849|3|0.0%|0.2%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|2|0.0%|0.1%|
[stopforumspam_1d](#stopforumspam_1d)|6690|6690|2|0.0%|0.1%|
[sorbs_spam](#sorbs_spam)|64701|65536|2|0.0%|0.1%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|2|0.0%|0.1%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|2|0.0%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2|0.0%|0.1%|
[dragon_vncprobe](#dragon_vncprobe)|87|87|2|2.2%|0.1%|
[blocklist_de_sip](#blocklist_de_sip)|84|84|2|2.3%|0.1%|
[blocklist_de_imap](#blocklist_de_imap)|2719|2719|2|0.0%|0.1%|
[tor_exits](#tor_exits)|1101|1101|1|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9136|9136|1|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|1|0.1%|0.0%|
[firehol_proxies](#firehol_proxies)|12828|13116|1|0.0%|0.0%|
[firehol_anonymous](#firehol_anonymous)|19294|83353|1|0.0%|0.0%|
[et_tor](#et_tor)|6500|6500|1|0.0%|0.0%|
[dm_tor](#dm_tor)|6455|6455|1|0.0%|0.0%|
[bm_tor](#bm_tor)|6338|6338|1|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2473|2473|1|0.0%|0.0%|

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
[firehol_level3](#firehol_level3)|109170|9626833|9136|0.0%|100.0%|
[firehol_anonymous](#firehol_anonymous)|19294|83353|1226|1.4%|13.4%|
[et_tor](#et_tor)|6500|6500|1088|16.7%|11.9%|
[tor_exits](#tor_exits)|1101|1101|1067|96.9%|11.6%|
[dm_tor](#dm_tor)|6455|6455|1051|16.2%|11.5%|
[bm_tor](#bm_tor)|6338|6338|1037|16.3%|11.3%|
[sorbs_spam](#sorbs_spam)|64701|65536|816|1.2%|8.9%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|814|1.2%|8.9%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|814|1.2%|8.9%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|804|0.8%|8.8%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|667|2.2%|7.3%|
[firehol_level2](#firehol_level2)|20803|32382|522|1.6%|5.7%|
[stopforumspam_1d](#stopforumspam_1d)|6690|6690|348|5.2%|3.8%|
[firehol_proxies](#firehol_proxies)|12828|13116|327|2.4%|3.5%|
[firehol_level1](#firehol_level1)|5137|688854747|300|0.0%|3.2%|
[et_block](#et_block)|1000|18343756|297|0.0%|3.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|240|0.0%|2.6%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|237|45.2%|2.5%|
[blocklist_de](#blocklist_de)|27144|27144|206|0.7%|2.2%|
[zeus](#zeus)|230|230|200|86.9%|2.1%|
[nixspam](#nixspam)|18020|18020|195|1.0%|2.1%|
[zeus_badips](#zeus_badips)|202|202|178|88.1%|1.9%|
[blocklist_de_mail](#blocklist_de_mail)|17849|17849|159|0.8%|1.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|141|0.0%|1.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|114|0.0%|1.2%|
[alienvault_reputation](#alienvault_reputation)|189146|189146|107|0.0%|1.1%|
[php_dictionary](#php_dictionary)|737|737|95|12.8%|1.0%|
[php_spammers](#php_spammers)|735|735|84|11.4%|0.9%|
[feodo](#feodo)|105|105|83|79.0%|0.9%|
[php_commenters](#php_commenters)|458|458|71|15.5%|0.7%|
[ri_web_proxies](#ri_web_proxies)|7952|7952|63|0.7%|0.6%|
[sorbs_web](#sorbs_web)|626|627|56|8.9%|0.6%|
[iw_spamlist](#iw_spamlist)|3787|3787|50|1.3%|0.5%|
[xroxy](#xroxy)|2174|2174|42|1.9%|0.4%|
[sslbl](#sslbl)|370|370|31|8.3%|0.3%|
[blocklist_de_apache](#blocklist_de_apache)|13852|13852|30|0.2%|0.3%|
[proxz](#proxz)|1356|1356|29|2.1%|0.3%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2473|2473|28|1.1%|0.3%|
[openbl_60d](#openbl_60d)|6960|6960|24|0.3%|0.2%|
[blocklist_de_bots](#blocklist_de_bots)|2979|2979|19|0.6%|0.2%|
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
[proxyrss](#proxyrss)|1735|1735|2|0.1%|0.0%|
[openbl_30d](#openbl_30d)|2792|2792|2|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|2|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|170|170|2|1.1%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2719|2719|2|0.0%|0.0%|
[shunlist](#shunlist)|1185|1185|1|0.0%|0.0%|
[openbl_7d](#openbl_7d)|629|629|1|0.1%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|1|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|1|0.1%|0.0%|
[dshield](#dshield)|20|5120|1|0.0%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|121|121|1|0.8%|0.0%|

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
[firehol_level3](#firehol_level3)|109170|9626833|4|0.0%|57.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|2|0.0%|28.5%|
[php_dictionary](#php_dictionary)|737|737|1|0.1%|14.2%|
[iw_spamlist](#iw_spamlist)|3787|3787|1|0.0%|14.2%|
[firehol_level2](#firehol_level2)|20803|32382|1|0.0%|14.2%|
[blocklist_de_mail](#blocklist_de_mail)|17849|17849|1|0.0%|14.2%|
[blocklist_de](#blocklist_de)|27144|27144|1|0.0%|14.2%|

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
[firehol_level3](#firehol_level3)|109170|9626833|4|0.0%|57.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|2|0.0%|28.5%|
[php_dictionary](#php_dictionary)|737|737|1|0.1%|14.2%|
[iw_spamlist](#iw_spamlist)|3787|3787|1|0.0%|14.2%|
[firehol_level2](#firehol_level2)|20803|32382|1|0.0%|14.2%|
[blocklist_de_mail](#blocklist_de_mail)|17849|17849|1|0.0%|14.2%|
[blocklist_de](#blocklist_de)|27144|27144|1|0.0%|14.2%|

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
[nixspam](#nixspam)|18020|18020|1399|7.7%|2.1%|
[firehol_level3](#firehol_level3)|109170|9626833|1222|0.0%|1.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|1205|0.0%|1.8%|
[firehol_level2](#firehol_level2)|20803|32382|1103|3.4%|1.6%|
[blocklist_de](#blocklist_de)|27144|27144|1091|4.0%|1.6%|
[iw_spamlist](#iw_spamlist)|3787|3787|1052|27.7%|1.6%|
[blocklist_de_mail](#blocklist_de_mail)|17849|17849|1002|5.6%|1.5%|
[snort_ipfilter](#snort_ipfilter)|9136|9136|814|8.9%|1.2%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|320|0.3%|0.4%|
[sorbs_web](#sorbs_web)|626|627|303|48.3%|0.4%|
[php_dictionary](#php_dictionary)|737|737|214|29.0%|0.3%|
[firehol_anonymous](#firehol_anonymous)|19294|83353|201|0.2%|0.3%|
[firehol_proxies](#firehol_proxies)|12828|13116|196|1.4%|0.3%|
[php_spammers](#php_spammers)|735|735|184|25.0%|0.2%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|173|0.5%|0.2%|
[ri_web_proxies](#ri_web_proxies)|7952|7952|145|1.8%|0.2%|
[alienvault_reputation](#alienvault_reputation)|189146|189146|91|0.0%|0.1%|
[xroxy](#xroxy)|2174|2174|76|3.4%|0.1%|
[dragon_http](#dragon_http)|1021|268288|71|0.0%|0.1%|
[stopforumspam_1d](#stopforumspam_1d)|6690|6690|45|0.6%|0.0%|
[proxz](#proxz)|1356|1356|44|3.2%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2473|2473|44|1.7%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13852|13852|44|0.3%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|37|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2719|2719|28|1.0%|0.0%|
[php_commenters](#php_commenters)|458|458|27|5.8%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|2979|2979|26|0.8%|0.0%|
[firehol_level1](#firehol_level1)|5137|688854747|25|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|20|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|20|0.0%|0.0%|
[et_block](#et_block)|1000|18343756|20|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2855|2855|18|0.6%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|17|0.0%|0.0%|
[php_harvesters](#php_harvesters)|408|408|16|3.9%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|1525|1525|15|0.9%|0.0%|
[sorbs_socks](#sorbs_socks)|7|7|7|100.0%|0.0%|
[sorbs_misc](#sorbs_misc)|7|7|7|100.0%|0.0%|
[sorbs_http](#sorbs_http)|7|7|7|100.0%|0.0%|
[sorbs_smtp](#sorbs_smtp)|6|6|6|100.0%|0.0%|
[tor_exits](#tor_exits)|1101|1101|5|0.4%|0.0%|
[et_tor](#et_tor)|6500|6500|4|0.0%|0.0%|
[dm_tor](#dm_tor)|6455|6455|4|0.0%|0.0%|
[bm_tor](#bm_tor)|6338|6338|4|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1969|1969|4|0.2%|0.0%|
[voipbl](#voipbl)|10586|10998|3|0.0%|0.0%|
[proxyrss](#proxyrss)|1735|1735|3|0.1%|0.0%|
[et_compromised](#et_compromised)|1704|1704|3|0.1%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1697|1697|3|0.1%|0.0%|
[shunlist](#shunlist)|1185|1185|2|0.1%|0.0%|
[openbl_60d](#openbl_60d)|6960|6960|2|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|2|0.1%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|170|170|2|1.1%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|1|0.1%|0.0%|
[malc0de](#malc0de)|276|276|1|0.3%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|1|0.1%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.0%|
[dragon_sshpauth](#dragon_sshpauth)|1595|1659|1|0.0%|0.0%|

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
[nixspam](#nixspam)|18020|18020|1399|7.7%|2.1%|
[firehol_level3](#firehol_level3)|109170|9626833|1222|0.0%|1.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|1205|0.0%|1.8%|
[firehol_level2](#firehol_level2)|20803|32382|1103|3.4%|1.6%|
[blocklist_de](#blocklist_de)|27144|27144|1091|4.0%|1.6%|
[iw_spamlist](#iw_spamlist)|3787|3787|1052|27.7%|1.6%|
[blocklist_de_mail](#blocklist_de_mail)|17849|17849|1002|5.6%|1.5%|
[snort_ipfilter](#snort_ipfilter)|9136|9136|814|8.9%|1.2%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|320|0.3%|0.4%|
[sorbs_web](#sorbs_web)|626|627|303|48.3%|0.4%|
[php_dictionary](#php_dictionary)|737|737|214|29.0%|0.3%|
[firehol_anonymous](#firehol_anonymous)|19294|83353|201|0.2%|0.3%|
[firehol_proxies](#firehol_proxies)|12828|13116|196|1.4%|0.3%|
[php_spammers](#php_spammers)|735|735|184|25.0%|0.2%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|173|0.5%|0.2%|
[ri_web_proxies](#ri_web_proxies)|7952|7952|145|1.8%|0.2%|
[alienvault_reputation](#alienvault_reputation)|189146|189146|91|0.0%|0.1%|
[xroxy](#xroxy)|2174|2174|76|3.4%|0.1%|
[dragon_http](#dragon_http)|1021|268288|71|0.0%|0.1%|
[stopforumspam_1d](#stopforumspam_1d)|6690|6690|45|0.6%|0.0%|
[proxz](#proxz)|1356|1356|44|3.2%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2473|2473|44|1.7%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13852|13852|44|0.3%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|37|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2719|2719|28|1.0%|0.0%|
[php_commenters](#php_commenters)|458|458|27|5.8%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|2979|2979|26|0.8%|0.0%|
[firehol_level1](#firehol_level1)|5137|688854747|25|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|20|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|20|0.0%|0.0%|
[et_block](#et_block)|1000|18343756|20|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2855|2855|18|0.6%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|17|0.0%|0.0%|
[php_harvesters](#php_harvesters)|408|408|16|3.9%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|1525|1525|15|0.9%|0.0%|
[sorbs_socks](#sorbs_socks)|7|7|7|100.0%|0.0%|
[sorbs_misc](#sorbs_misc)|7|7|7|100.0%|0.0%|
[sorbs_http](#sorbs_http)|7|7|7|100.0%|0.0%|
[sorbs_smtp](#sorbs_smtp)|6|6|6|100.0%|0.0%|
[tor_exits](#tor_exits)|1101|1101|5|0.4%|0.0%|
[et_tor](#et_tor)|6500|6500|4|0.0%|0.0%|
[dm_tor](#dm_tor)|6455|6455|4|0.0%|0.0%|
[bm_tor](#bm_tor)|6338|6338|4|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1969|1969|4|0.2%|0.0%|
[voipbl](#voipbl)|10586|10998|3|0.0%|0.0%|
[proxyrss](#proxyrss)|1735|1735|3|0.1%|0.0%|
[et_compromised](#et_compromised)|1704|1704|3|0.1%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1697|1697|3|0.1%|0.0%|
[shunlist](#shunlist)|1185|1185|2|0.1%|0.0%|
[openbl_60d](#openbl_60d)|6960|6960|2|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|2|0.1%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|170|170|2|1.1%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|1|0.1%|0.0%|
[malc0de](#malc0de)|276|276|1|0.3%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|1|0.1%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.0%|
[dragon_sshpauth](#dragon_sshpauth)|1595|1659|1|0.0%|0.0%|

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
[firehol_level3](#firehol_level3)|109170|9626833|4|0.0%|57.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|2|0.0%|28.5%|
[php_dictionary](#php_dictionary)|737|737|1|0.1%|14.2%|
[iw_spamlist](#iw_spamlist)|3787|3787|1|0.0%|14.2%|
[firehol_level2](#firehol_level2)|20803|32382|1|0.0%|14.2%|
[blocklist_de_mail](#blocklist_de_mail)|17849|17849|1|0.0%|14.2%|
[blocklist_de](#blocklist_de)|27144|27144|1|0.0%|14.2%|

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
[nixspam](#nixspam)|18020|18020|1411|7.8%|2.1%|
[firehol_level3](#firehol_level3)|109170|9626833|1226|0.0%|1.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|1208|0.0%|1.8%|
[firehol_level2](#firehol_level2)|20803|32382|1111|3.4%|1.6%|
[blocklist_de](#blocklist_de)|27144|27144|1099|4.0%|1.6%|
[iw_spamlist](#iw_spamlist)|3787|3787|1057|27.9%|1.6%|
[blocklist_de_mail](#blocklist_de_mail)|17849|17849|1010|5.6%|1.5%|
[snort_ipfilter](#snort_ipfilter)|9136|9136|816|8.9%|1.2%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|320|0.3%|0.4%|
[sorbs_web](#sorbs_web)|626|627|304|48.4%|0.4%|
[php_dictionary](#php_dictionary)|737|737|214|29.0%|0.3%|
[firehol_anonymous](#firehol_anonymous)|19294|83353|201|0.2%|0.3%|
[firehol_proxies](#firehol_proxies)|12828|13116|196|1.4%|0.2%|
[php_spammers](#php_spammers)|735|735|184|25.0%|0.2%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|173|0.5%|0.2%|
[ri_web_proxies](#ri_web_proxies)|7952|7952|145|1.8%|0.2%|
[alienvault_reputation](#alienvault_reputation)|189146|189146|91|0.0%|0.1%|
[xroxy](#xroxy)|2174|2174|76|3.4%|0.1%|
[dragon_http](#dragon_http)|1021|268288|72|0.0%|0.1%|
[stopforumspam_1d](#stopforumspam_1d)|6690|6690|45|0.6%|0.0%|
[proxz](#proxz)|1356|1356|44|3.2%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2473|2473|44|1.7%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13852|13852|44|0.3%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|38|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2719|2719|29|1.0%|0.0%|
[php_commenters](#php_commenters)|458|458|27|5.8%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|2979|2979|26|0.8%|0.0%|
[firehol_level1](#firehol_level1)|5137|688854747|25|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|20|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|20|0.0%|0.0%|
[et_block](#et_block)|1000|18343756|20|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2855|2855|18|0.6%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|17|0.0%|0.0%|
[php_harvesters](#php_harvesters)|408|408|16|3.9%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|1525|1525|15|0.9%|0.0%|
[sorbs_socks](#sorbs_socks)|7|7|7|100.0%|0.0%|
[sorbs_misc](#sorbs_misc)|7|7|7|100.0%|0.0%|
[sorbs_http](#sorbs_http)|7|7|7|100.0%|0.0%|
[tor_exits](#tor_exits)|1101|1101|5|0.4%|0.0%|
[sorbs_smtp](#sorbs_smtp)|6|6|5|83.3%|0.0%|
[et_tor](#et_tor)|6500|6500|4|0.0%|0.0%|
[dm_tor](#dm_tor)|6455|6455|4|0.0%|0.0%|
[bm_tor](#bm_tor)|6338|6338|4|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1969|1969|4|0.2%|0.0%|
[voipbl](#voipbl)|10586|10998|3|0.0%|0.0%|
[proxyrss](#proxyrss)|1735|1735|3|0.1%|0.0%|
[et_compromised](#et_compromised)|1704|1704|3|0.1%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1697|1697|3|0.1%|0.0%|
[shunlist](#shunlist)|1185|1185|2|0.1%|0.0%|
[openbl_60d](#openbl_60d)|6960|6960|2|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|2|0.1%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|170|170|2|1.1%|0.0%|
[virbl](#virbl)|22|22|1|4.5%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|1|0.1%|0.0%|
[malc0de](#malc0de)|276|276|1|0.3%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|1|0.1%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.0%|
[dragon_sshpauth](#dragon_sshpauth)|1595|1659|1|0.0%|0.0%|

## sorbs_web

[Sorbs.net](https://www.sorbs.net/) WEB exploits, extracted from deltas.

Source is downloaded from [this link]().

The last time downloaded was found to be dated: Fri Jun 12 08:04:04 UTC 2015.

The ipset `sorbs_web` has **626** entries, **627** unique IPs.

The following table shows the overlaps of `sorbs_web` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `sorbs_web`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `sorbs_web`.
- ` this % ` is the percentage **of this ipset (`sorbs_web`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[sorbs_spam](#sorbs_spam)|64701|65536|304|0.4%|48.4%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|303|0.4%|48.3%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|303|0.4%|48.3%|
[nixspam](#nixspam)|18020|18020|90|0.4%|14.3%|
[firehol_level3](#firehol_level3)|109170|9626833|74|0.0%|11.8%|
[firehol_level2](#firehol_level2)|20803|32382|71|0.2%|11.3%|
[blocklist_de](#blocklist_de)|27144|27144|71|0.2%|11.3%|
[blocklist_de_mail](#blocklist_de_mail)|17849|17849|64|0.3%|10.2%|
[snort_ipfilter](#snort_ipfilter)|9136|9136|56|0.6%|8.9%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|48|0.0%|7.6%|
[php_dictionary](#php_dictionary)|737|737|34|4.6%|5.4%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|32|0.1%|5.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|32|0.0%|5.1%|
[firehol_proxies](#firehol_proxies)|12828|13116|31|0.2%|4.9%|
[firehol_anonymous](#firehol_anonymous)|19294|83353|31|0.0%|4.9%|
[php_spammers](#php_spammers)|735|735|27|3.6%|4.3%|
[iw_spamlist](#iw_spamlist)|3787|3787|24|0.6%|3.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|23|0.0%|3.6%|
[ri_web_proxies](#ri_web_proxies)|7952|7952|22|0.2%|3.5%|
[xroxy](#xroxy)|2174|2174|16|0.7%|2.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|16|0.0%|2.5%|
[proxz](#proxz)|1356|1356|8|0.5%|1.2%|
[stopforumspam_1d](#stopforumspam_1d)|6690|6690|6|0.0%|0.9%|
[blocklist_de_bots](#blocklist_de_bots)|2979|2979|6|0.2%|0.9%|
[php_commenters](#php_commenters)|458|458|4|0.8%|0.6%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|2|0.0%|0.3%|
[blocklist_de_strongips](#blocklist_de_strongips)|170|170|2|1.1%|0.3%|
[ri_connect_proxies](#ri_connect_proxies)|2855|2855|1|0.0%|0.1%|
[proxyrss](#proxyrss)|1735|1735|1|0.0%|0.1%|
[php_harvesters](#php_harvesters)|408|408|1|0.2%|0.1%|
[dragon_http](#dragon_http)|1021|268288|1|0.0%|0.1%|
[blocklist_de_ftp](#blocklist_de_ftp)|1525|1525|1|0.0%|0.1%|
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
[firehol_level1](#firehol_level1)|5137|688854747|18340608|2.6%|100.0%|
[et_block](#et_block)|1000|18343756|18338560|99.9%|99.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|8532506|2.4%|46.5%|
[firehol_level3](#firehol_level3)|109170|9626833|6933039|72.0%|37.8%|
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
[firehol_level2](#firehol_level2)|20803|32382|251|0.7%|0.0%|
[openbl_60d](#openbl_60d)|6960|6960|235|3.3%|0.0%|
[blocklist_de](#blocklist_de)|27144|27144|188|0.6%|0.0%|
[openbl_30d](#openbl_30d)|2792|2792|119|4.2%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1969|1969|109|5.5%|0.0%|
[dragon_sshpauth](#dragon_sshpauth)|1595|1659|99|5.9%|0.0%|
[shunlist](#shunlist)|1185|1185|90|7.5%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6690|6690|75|1.1%|0.0%|
[et_compromised](#et_compromised)|1704|1704|65|3.8%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1697|1697|61|3.5%|0.0%|
[openbl_7d](#openbl_7d)|629|629|53|8.4%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|2979|2979|49|1.6%|0.0%|
[php_commenters](#php_commenters)|458|458|29|6.3%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|29|2.2%|0.0%|
[nixspam](#nixspam)|18020|18020|28|0.1%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|17849|17849|23|0.1%|0.0%|
[sorbs_spam](#sorbs_spam)|64701|65536|20|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|20|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|20|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9136|9136|18|0.1%|0.0%|
[zeus_badips](#zeus_badips)|202|202|15|7.4%|0.0%|
[zeus](#zeus)|230|230|15|6.5%|0.0%|
[voipbl](#voipbl)|10586|10998|14|0.1%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2719|2719|14|0.5%|0.0%|
[openbl_1d](#openbl_1d)|126|126|12|9.5%|0.0%|
[php_dictionary](#php_dictionary)|737|737|6|0.8%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|6|0.4%|0.0%|
[firehol_anonymous](#firehol_anonymous)|19294|83353|6|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|170|170|6|3.5%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|5|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2473|2473|5|0.2%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13852|13852|5|0.0%|0.0%|
[php_spammers](#php_spammers)|735|735|4|0.5%|0.0%|
[nt_malware_http](#nt_malware_http)|69|69|4|5.7%|0.0%|
[malc0de](#malc0de)|276|276|4|1.4%|0.0%|
[nt_malware_irc](#nt_malware_irc)|43|43|3|6.9%|0.0%|
[iw_spamlist](#iw_spamlist)|3787|3787|3|0.0%|0.0%|
[firehol_proxies](#firehol_proxies)|12828|13116|3|0.0%|0.0%|
[et_tor](#et_tor)|6500|6500|3|0.0%|0.0%|
[dm_tor](#dm_tor)|6455|6455|3|0.0%|0.0%|
[bm_tor](#bm_tor)|6338|6338|3|0.0%|0.0%|
[tor_exits](#tor_exits)|1101|1101|2|0.1%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|2|0.3%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|84|84|2|2.3%|0.0%|
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
[firehol_level1](#firehol_level1)|5137|688854747|487424|0.0%|100.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|270785|0.1%|55.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|98904|0.0%|20.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|33155|0.0%|6.8%|
[et_block](#et_block)|1000|18343756|517|0.0%|0.1%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|512|0.0%|0.1%|
[firehol_level3](#firehol_level3)|109170|9626833|85|0.0%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|75|0.0%|0.0%|
[sorbs_spam](#sorbs_spam)|64701|65536|20|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|20|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|20|0.0%|0.0%|
[alienvault_reputation](#alienvault_reputation)|189146|189146|14|0.0%|0.0%|
[php_commenters](#php_commenters)|458|458|8|1.7%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|7|0.0%|0.0%|
[firehol_level2](#firehol_level2)|20803|32382|7|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9136|9136|6|0.0%|0.0%|
[zeus_badips](#zeus_badips)|202|202|5|2.4%|0.0%|
[zeus](#zeus)|230|230|5|2.1%|0.0%|
[blocklist_de](#blocklist_de)|27144|27144|5|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6690|6690|3|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|2979|2979|3|0.1%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|170|170|2|1.1%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|17849|17849|2|0.0%|0.0%|
[php_harvesters](#php_harvesters)|408|408|1|0.2%|0.0%|
[openbl_60d](#openbl_60d)|6960|6960|1|0.0%|0.0%|
[openbl_30d](#openbl_30d)|2792|2792|1|0.0%|0.0%|
[nixspam](#nixspam)|18020|18020|1|0.0%|0.0%|
[malc0de](#malc0de)|276|276|1|0.3%|0.0%|
[iw_spamlist](#iw_spamlist)|3787|3787|1|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13852|13852|1|0.0%|0.0%|

## sslbl

[Abuse.ch SSL Blacklist](https://sslbl.abuse.ch/) bad SSL traffic related to malware or botnet activities - **excellent list**

Source is downloaded from [this link](https://sslbl.abuse.ch/blacklist/sslipblacklist.csv).

The last time downloaded was found to be dated: Fri Jun 12 08:15:04 UTC 2015.

The ipset `sslbl` has **370** entries, **370** unique IPs.

The following table shows the overlaps of `sslbl` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `sslbl`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `sslbl`.
- ` this % ` is the percentage **of this ipset (`sslbl`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level1](#firehol_level1)|5137|688854747|370|0.0%|100.0%|
[firehol_level3](#firehol_level3)|109170|9626833|89|0.0%|24.0%|
[alienvault_reputation](#alienvault_reputation)|189146|189146|65|0.0%|17.5%|
[shunlist](#shunlist)|1185|1185|58|4.8%|15.6%|
[et_block](#et_block)|1000|18343756|39|0.0%|10.5%|
[feodo](#feodo)|105|105|38|36.1%|10.2%|
[snort_ipfilter](#snort_ipfilter)|9136|9136|31|0.3%|8.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|28|0.0%|7.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|6|0.0%|1.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|3|0.0%|0.8%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|1|0.0%|0.2%|
[ri_web_proxies](#ri_web_proxies)|7952|7952|1|0.0%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.2%|
[firehol_proxies](#firehol_proxies)|12828|13116|1|0.0%|0.2%|
[firehol_anonymous](#firehol_anonymous)|19294|83353|1|0.0%|0.2%|
[dragon_sshpauth](#dragon_sshpauth)|1595|1659|1|0.0%|0.2%|
[dragon_http](#dragon_http)|1021|268288|1|0.0%|0.2%|

## stopforumspam_1d

[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers in the last 24 hours - **excellent list**

Source is downloaded from [this link](http://www.stopforumspam.com/downloads/listed_ip_1.zip).

The last time downloaded was found to be dated: Fri Jun 12 08:00:02 UTC 2015.

The ipset `stopforumspam_1d` has **6690** entries, **6690** unique IPs.

The following table shows the overlaps of `stopforumspam_1d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `stopforumspam_1d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `stopforumspam_1d`.
- ` this % ` is the percentage **of this ipset (`stopforumspam_1d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|20803|32382|6690|20.6%|100.0%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|5851|20.1%|87.4%|
[firehol_level3](#firehol_level3)|109170|9626833|4638|0.0%|69.3%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|4601|4.8%|68.7%|
[blocklist_de](#blocklist_de)|27144|27144|1467|5.4%|21.9%|
[blocklist_de_bots](#blocklist_de_bots)|2979|2979|1414|47.4%|21.1%|
[firehol_anonymous](#firehol_anonymous)|19294|83353|957|1.1%|14.3%|
[firehol_proxies](#firehol_proxies)|12828|13116|813|6.1%|12.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|490|0.0%|7.3%|
[ri_web_proxies](#ri_web_proxies)|7952|7952|417|5.2%|6.2%|
[snort_ipfilter](#snort_ipfilter)|9136|9136|348|3.8%|5.2%|
[proxyrss](#proxyrss)|1735|1735|331|19.0%|4.9%|
[tor_exits](#tor_exits)|1101|1101|314|28.5%|4.6%|
[et_tor](#et_tor)|6500|6500|311|4.7%|4.6%|
[dm_tor](#dm_tor)|6455|6455|306|4.7%|4.5%|
[bm_tor](#bm_tor)|6338|6338|304|4.7%|4.5%|
[xroxy](#xroxy)|2174|2174|193|8.8%|2.8%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|192|36.6%|2.8%|
[proxz](#proxz)|1356|1356|176|12.9%|2.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|173|0.0%|2.5%|
[php_commenters](#php_commenters)|458|458|165|36.0%|2.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|127|0.0%|1.8%|
[ri_connect_proxies](#ri_connect_proxies)|2855|2855|104|3.6%|1.5%|
[blocklist_de_strongips](#blocklist_de_strongips)|170|170|100|58.8%|1.4%|
[firehol_level1](#firehol_level1)|5137|688854747|87|0.0%|1.3%|
[et_block](#et_block)|1000|18343756|83|0.0%|1.2%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|75|0.0%|1.1%|
[nixspam](#nixspam)|18020|18020|64|0.3%|0.9%|
[blocklist_de_apache](#blocklist_de_apache)|13852|13852|54|0.3%|0.8%|
[blocklist_de_mail](#blocklist_de_mail)|17849|17849|46|0.2%|0.6%|
[sorbs_spam](#sorbs_spam)|64701|65536|45|0.0%|0.6%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|45|0.0%|0.6%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|45|0.0%|0.6%|
[php_harvesters](#php_harvesters)|408|408|45|11.0%|0.6%|
[alienvault_reputation](#alienvault_reputation)|189146|189146|43|0.0%|0.6%|
[php_spammers](#php_spammers)|735|735|40|5.4%|0.5%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|33|0.0%|0.4%|
[php_dictionary](#php_dictionary)|737|737|30|4.0%|0.4%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2473|2473|21|0.8%|0.3%|
[openbl_60d](#openbl_60d)|6960|6960|18|0.2%|0.2%|
[dshield](#dshield)|20|5120|9|0.1%|0.1%|
[dragon_http](#dragon_http)|1021|268288|9|0.0%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|7|0.0%|0.1%|
[sorbs_web](#sorbs_web)|626|627|6|0.9%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|6|0.9%|0.0%|
[voipbl](#voipbl)|10586|10998|5|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|3|0.0%|0.0%|
[iw_spamlist](#iw_spamlist)|3787|3787|3|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|1525|1525|3|0.1%|0.0%|
[shunlist](#shunlist)|1185|1185|2|0.1%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|2|0.0%|0.0%|
[et_compromised](#et_compromised)|1704|1704|2|0.1%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1697|1697|2|0.1%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2719|2719|2|0.0%|0.0%|
[zeus_badips](#zeus_badips)|202|202|1|0.4%|0.0%|
[zeus](#zeus)|230|230|1|0.4%|0.0%|
[openbl_30d](#openbl_30d)|2792|2792|1|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|1|0.0%|0.0%|
[fullbogons](#fullbogons)|3775|670173256|1|0.0%|0.0%|

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
[firehol_level3](#firehol_level3)|109170|9626833|94309|0.9%|100.0%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|27620|95.1%|29.2%|
[firehol_anonymous](#firehol_anonymous)|19294|83353|6248|7.4%|6.6%|
[firehol_level2](#firehol_level2)|20803|32382|5963|18.4%|6.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|5830|0.0%|6.1%|
[firehol_proxies](#firehol_proxies)|12828|13116|5650|43.0%|5.9%|
[stopforumspam_1d](#stopforumspam_1d)|6690|6690|4601|68.7%|4.8%|
[ri_web_proxies](#ri_web_proxies)|7952|7952|3712|46.6%|3.9%|
[blocklist_de](#blocklist_de)|27144|27144|2631|9.6%|2.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|2476|0.0%|2.6%|
[blocklist_de_bots](#blocklist_de_bots)|2979|2979|2307|77.4%|2.4%|
[ri_connect_proxies](#ri_connect_proxies)|2855|2855|1591|55.7%|1.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|1522|0.0%|1.6%|
[xroxy](#xroxy)|2174|2174|1286|59.1%|1.3%|
[firehol_level1](#firehol_level1)|5137|688854747|1111|0.0%|1.1%|
[et_block](#et_block)|1000|18343756|1032|0.0%|1.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|1014|0.0%|1.0%|
[snort_ipfilter](#snort_ipfilter)|9136|9136|804|8.8%|0.8%|
[proxz](#proxz)|1356|1356|794|58.5%|0.8%|
[proxyrss](#proxyrss)|1735|1735|744|42.8%|0.7%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|725|0.0%|0.7%|
[et_tor](#et_tor)|6500|6500|651|10.0%|0.6%|
[dm_tor](#dm_tor)|6455|6455|633|9.8%|0.6%|
[bm_tor](#bm_tor)|6338|6338|633|9.9%|0.6%|
[tor_exits](#tor_exits)|1101|1101|619|56.2%|0.6%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|345|65.8%|0.3%|
[php_commenters](#php_commenters)|458|458|334|72.9%|0.3%|
[sorbs_spam](#sorbs_spam)|64701|65536|320|0.4%|0.3%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|320|0.4%|0.3%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|320|0.4%|0.3%|
[blocklist_de_mail](#blocklist_de_mail)|17849|17849|253|1.4%|0.2%|
[nixspam](#nixspam)|18020|18020|231|1.2%|0.2%|
[blocklist_de_apache](#blocklist_de_apache)|13852|13852|186|1.3%|0.1%|
[alienvault_reputation](#alienvault_reputation)|189146|189146|168|0.0%|0.1%|
[php_spammers](#php_spammers)|735|735|151|20.5%|0.1%|
[php_dictionary](#php_dictionary)|737|737|139|18.8%|0.1%|
[blocklist_de_strongips](#blocklist_de_strongips)|170|170|130|76.4%|0.1%|
[dragon_http](#dragon_http)|1021|268288|108|0.0%|0.1%|
[php_harvesters](#php_harvesters)|408|408|87|21.3%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|75|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2473|2473|57|2.3%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|52|0.0%|0.0%|
[sorbs_web](#sorbs_web)|626|627|48|7.6%|0.0%|
[openbl_60d](#openbl_60d)|6960|6960|47|0.6%|0.0%|
[voipbl](#voipbl)|10586|10998|35|0.3%|0.0%|
[dshield](#dshield)|20|5120|21|0.4%|0.0%|
[iw_spamlist](#iw_spamlist)|3787|3787|20|0.5%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|20|3.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|17|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2719|2719|15|0.5%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|1525|1525|12|0.7%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1969|1969|11|0.5%|0.0%|
[et_compromised](#et_compromised)|1704|1704|10|0.5%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1697|1697|9|0.5%|0.0%|
[openbl_30d](#openbl_30d)|2792|2792|5|0.1%|0.0%|
[shunlist](#shunlist)|1185|1185|4|0.3%|0.0%|
[dragon_sshpauth](#dragon_sshpauth)|1595|1659|4|0.2%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|3|0.2%|0.0%|
[zeus_badips](#zeus_badips)|202|202|2|0.9%|0.0%|
[zeus](#zeus)|230|230|2|0.8%|0.0%|
[openbl_7d](#openbl_7d)|629|629|2|0.3%|0.0%|
[nt_malware_http](#nt_malware_http)|69|69|2|2.8%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|2|0.1%|0.0%|
[fullbogons](#fullbogons)|3775|670173256|2|0.0%|0.0%|
[ciarmy](#ciarmy)|416|416|2|0.4%|0.0%|
[openbl_1d](#openbl_1d)|126|126|1|0.7%|0.0%|
[iw_wormlist](#iw_wormlist)|34|34|1|2.9%|0.0%|

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
[firehol_level3](#firehol_level3)|109170|9626833|27643|0.2%|95.2%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|27620|29.2%|95.1%|
[firehol_level2](#firehol_level2)|20803|32382|6837|21.1%|23.5%|
[stopforumspam_1d](#stopforumspam_1d)|6690|6690|5851|87.4%|20.1%|
[firehol_anonymous](#firehol_anonymous)|19294|83353|2751|3.3%|9.4%|
[firehol_proxies](#firehol_proxies)|12828|13116|2385|18.1%|8.2%|
[blocklist_de](#blocklist_de)|27144|27144|2365|8.7%|8.1%|
[blocklist_de_bots](#blocklist_de_bots)|2979|2979|2194|73.6%|7.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|1961|0.0%|6.7%|
[ri_web_proxies](#ri_web_proxies)|7952|7952|1487|18.6%|5.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|736|0.0%|2.5%|
[snort_ipfilter](#snort_ipfilter)|9136|9136|667|7.3%|2.2%|
[proxyrss](#proxyrss)|1735|1735|597|34.4%|2.0%|
[xroxy](#xroxy)|2174|2174|585|26.9%|2.0%|
[et_tor](#et_tor)|6500|6500|547|8.4%|1.8%|
[tor_exits](#tor_exits)|1101|1101|539|48.9%|1.8%|
[ri_connect_proxies](#ri_connect_proxies)|2855|2855|531|18.5%|1.8%|
[dm_tor](#dm_tor)|6455|6455|530|8.2%|1.8%|
[bm_tor](#bm_tor)|6338|6338|530|8.3%|1.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|510|0.0%|1.7%|
[proxz](#proxz)|1356|1356|507|37.3%|1.7%|
[firehol_level1](#firehol_level1)|5137|688854747|291|0.0%|1.0%|
[et_block](#et_block)|1000|18343756|283|0.0%|0.9%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|277|52.8%|0.9%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|269|0.0%|0.9%|
[php_commenters](#php_commenters)|458|458|248|54.1%|0.8%|
[sorbs_spam](#sorbs_spam)|64701|65536|173|0.2%|0.5%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|173|0.2%|0.5%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|173|0.2%|0.5%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|154|0.0%|0.5%|
[nixspam](#nixspam)|18020|18020|147|0.8%|0.5%|
[blocklist_de_mail](#blocklist_de_mail)|17849|17849|135|0.7%|0.4%|
[blocklist_de_strongips](#blocklist_de_strongips)|170|170|116|68.2%|0.3%|
[blocklist_de_apache](#blocklist_de_apache)|13852|13852|107|0.7%|0.3%|
[php_spammers](#php_spammers)|735|735|93|12.6%|0.3%|
[php_dictionary](#php_dictionary)|737|737|93|12.6%|0.3%|
[alienvault_reputation](#alienvault_reputation)|189146|189146|88|0.0%|0.3%|
[php_harvesters](#php_harvesters)|408|408|65|15.9%|0.2%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2473|2473|40|1.6%|0.1%|
[sorbs_web](#sorbs_web)|626|627|32|5.1%|0.1%|
[dragon_http](#dragon_http)|1021|268288|32|0.0%|0.1%|
[openbl_60d](#openbl_60d)|6960|6960|26|0.3%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|21|0.0%|0.0%|
[voipbl](#voipbl)|10586|10998|15|0.1%|0.0%|
[dshield](#dshield)|20|5120|15|0.2%|0.0%|
[iw_spamlist](#iw_spamlist)|3787|3787|12|0.3%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|10|1.5%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|7|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|7|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|1525|1525|7|0.4%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2719|2719|6|0.2%|0.0%|
[et_compromised](#et_compromised)|1704|1704|3|0.1%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1697|1697|3|0.1%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1969|1969|3|0.1%|0.0%|
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

The last time downloaded was found to be dated: Fri Jun 12 08:03:26 UTC 2015.

The ipset `tor_exits` has **1101** entries, **1101** unique IPs.

The following table shows the overlaps of `tor_exits` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `tor_exits`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `tor_exits`.
- ` this % ` is the percentage **of this ipset (`tor_exits`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_anonymous](#firehol_anonymous)|19294|83353|1101|1.3%|100.0%|
[firehol_level3](#firehol_level3)|109170|9626833|1069|0.0%|97.0%|
[snort_ipfilter](#snort_ipfilter)|9136|9136|1067|11.6%|96.9%|
[dm_tor](#dm_tor)|6455|6455|1019|15.7%|92.5%|
[bm_tor](#bm_tor)|6338|6338|1004|15.8%|91.1%|
[et_tor](#et_tor)|6500|6500|971|14.9%|88.1%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|619|0.6%|56.2%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|539|1.8%|48.9%|
[firehol_level2](#firehol_level2)|20803|32382|325|1.0%|29.5%|
[stopforumspam_1d](#stopforumspam_1d)|6690|6690|314|4.6%|28.5%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|228|43.5%|20.7%|
[firehol_proxies](#firehol_proxies)|12828|13116|228|1.7%|20.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|126|0.0%|11.4%|
[php_commenters](#php_commenters)|458|458|54|11.7%|4.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|40|0.0%|3.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|37|0.0%|3.3%|
[alienvault_reputation](#alienvault_reputation)|189146|189146|30|0.0%|2.7%|
[openbl_60d](#openbl_60d)|6960|6960|20|0.2%|1.8%|
[blocklist_de_apache](#blocklist_de_apache)|13852|13852|18|0.1%|1.6%|
[blocklist_de](#blocklist_de)|27144|27144|18|0.0%|1.6%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2473|2473|16|0.6%|1.4%|
[nixspam](#nixspam)|18020|18020|8|0.0%|0.7%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|8|0.0%|0.7%|
[php_harvesters](#php_harvesters)|408|408|6|1.4%|0.5%|
[sorbs_spam](#sorbs_spam)|64701|65536|5|0.0%|0.4%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|5|0.0%|0.4%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|5|0.0%|0.4%|
[php_spammers](#php_spammers)|735|735|5|0.6%|0.4%|
[dragon_http](#dragon_http)|1021|268288|5|0.0%|0.4%|
[php_dictionary](#php_dictionary)|737|737|4|0.5%|0.3%|
[firehol_level1](#firehol_level1)|5137|688854747|3|0.0%|0.2%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|2|0.0%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2|0.0%|0.1%|
[et_block](#et_block)|1000|18343756|2|0.0%|0.1%|
[blocklist_de_mail](#blocklist_de_mail)|17849|17849|2|0.0%|0.1%|
[shunlist](#shunlist)|1185|1185|1|0.0%|0.0%|
[dshield](#dshield)|20|5120|1|0.0%|0.0%|

## virbl

[VirBL](http://virbl.bit.nl/) is a project of which the idea was born during the RIPE-48 meeting. The plan was to get reports of virusscanning mailservers, and put the IP-addresses that were reported to send viruses on a blacklist.

Source is downloaded from [this link](http://virbl.bit.nl/download/virbl.dnsbl.bit.nl.txt).

The last time downloaded was found to be dated: Fri Jun 12 07:42:03 UTC 2015.

The ipset `virbl` has **22** entries, **22** unique IPs.

The following table shows the overlaps of `virbl` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `virbl`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `virbl`.
- ` this % ` is the percentage **of this ipset (`virbl`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level3](#firehol_level3)|109170|9626833|22|0.0%|100.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|1|0.0%|4.5%|
[sorbs_spam](#sorbs_spam)|64701|65536|1|0.0%|4.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|1|0.0%|4.5%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|4.5%|
[firehol_level2](#firehol_level2)|20803|32382|1|0.0%|4.5%|
[firehol_level1](#firehol_level1)|5137|688854747|1|0.0%|4.5%|
[et_block](#et_block)|1000|18343756|1|0.0%|4.5%|
[blocklist_de_mail](#blocklist_de_mail)|17849|17849|1|0.0%|4.5%|
[blocklist_de_imap](#blocklist_de_imap)|2719|2719|1|0.0%|4.5%|
[blocklist_de](#blocklist_de)|27144|27144|1|0.0%|4.5%|

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
[firehol_level1](#firehol_level1)|5137|688854747|333|0.0%|3.0%|
[fullbogons](#fullbogons)|3775|670173256|319|0.0%|2.9%|
[bogons](#bogons)|13|592708608|319|0.0%|2.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|302|0.0%|2.7%|
[alienvault_reputation](#alienvault_reputation)|189146|189146|176|0.0%|1.6%|
[firehol_anonymous](#firehol_anonymous)|19294|83353|79|0.0%|0.7%|
[firehol_level3](#firehol_level3)|109170|9626833|58|0.0%|0.5%|
[firehol_level2](#firehol_level2)|20803|32382|46|0.1%|0.4%|
[blocklist_de](#blocklist_de)|27144|27144|42|0.1%|0.3%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|35|0.0%|0.3%|
[blocklist_de_sip](#blocklist_de_sip)|84|84|35|41.6%|0.3%|
[dragon_http](#dragon_http)|1021|268288|29|0.0%|0.2%|
[et_block](#et_block)|1000|18343756|18|0.0%|0.1%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|15|0.0%|0.1%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|14|0.0%|0.1%|
[shunlist](#shunlist)|1185|1185|14|1.1%|0.1%|
[openbl_60d](#openbl_60d)|6960|6960|8|0.1%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6690|6690|5|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|4|0.0%|0.0%|
[sorbs_spam](#sorbs_spam)|64701|65536|3|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|3|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|3|0.0%|0.0%|
[openbl_30d](#openbl_30d)|2792|2792|3|0.1%|0.0%|
[et_tor](#et_tor)|6500|6500|3|0.0%|0.0%|
[et_compromised](#et_compromised)|1704|1704|3|0.1%|0.0%|
[dm_tor](#dm_tor)|6455|6455|3|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1697|1697|3|0.1%|0.0%|
[bm_tor](#bm_tor)|6338|6338|3|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|2|0.3%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|2|0.0%|0.0%|
[firehol_proxies](#firehol_proxies)|12828|13116|2|0.0%|0.0%|
[ciarmy](#ciarmy)|416|416|2|0.4%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1969|1969|2|0.1%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|17849|17849|2|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13852|13852|2|0.0%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.0%|
[dragon_vncprobe](#dragon_vncprobe)|87|87|1|1.1%|0.0%|
[dragon_sshpauth](#dragon_sshpauth)|1595|1659|1|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2719|2719|1|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|2979|2979|1|0.0%|0.0%|

## xroxy

[xroxy.com](http://www.xroxy.com) open proxies (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.xroxy.com/proxyrss.xml).

The last time downloaded was found to be dated: Fri Jun 12 07:33:01 UTC 2015.

The ipset `xroxy` has **2174** entries, **2174** unique IPs.

The following table shows the overlaps of `xroxy` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `xroxy`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `xroxy`.
- ` this % ` is the percentage **of this ipset (`xroxy`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_proxies](#firehol_proxies)|12828|13116|2174|16.5%|100.0%|
[firehol_anonymous](#firehol_anonymous)|19294|83353|2174|2.6%|100.0%|
[firehol_level3](#firehol_level3)|109170|9626833|1301|0.0%|59.8%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|1286|1.3%|59.1%|
[ri_web_proxies](#ri_web_proxies)|7952|7952|965|12.1%|44.3%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|585|2.0%|26.9%|
[proxz](#proxz)|1356|1356|468|34.5%|21.5%|
[ri_connect_proxies](#ri_connect_proxies)|2855|2855|396|13.8%|18.2%|
[proxyrss](#proxyrss)|1735|1735|376|21.6%|17.2%|
[firehol_level2](#firehol_level2)|20803|32382|303|0.9%|13.9%|
[blocklist_de](#blocklist_de)|27144|27144|224|0.8%|10.3%|
[stopforumspam_1d](#stopforumspam_1d)|6690|6690|193|2.8%|8.8%|
[blocklist_de_bots](#blocklist_de_bots)|2979|2979|171|5.7%|7.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|112|0.0%|5.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|104|0.0%|4.7%|
[sorbs_spam](#sorbs_spam)|64701|65536|76|0.1%|3.4%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|76|0.1%|3.4%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|76|0.1%|3.4%|
[nixspam](#nixspam)|18020|18020|68|0.3%|3.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|58|0.0%|2.6%|
[blocklist_de_mail](#blocklist_de_mail)|17849|17849|53|0.2%|2.4%|
[snort_ipfilter](#snort_ipfilter)|9136|9136|42|0.4%|1.9%|
[php_dictionary](#php_dictionary)|737|737|41|5.5%|1.8%|
[php_spammers](#php_spammers)|735|735|34|4.6%|1.5%|
[sorbs_web](#sorbs_web)|626|627|16|2.5%|0.7%|
[php_commenters](#php_commenters)|458|458|13|2.8%|0.5%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|13|1.9%|0.5%|
[blocklist_de_strongips](#blocklist_de_strongips)|170|170|7|4.1%|0.3%|
[dragon_http](#dragon_http)|1021|268288|6|0.0%|0.2%|
[alienvault_reputation](#alienvault_reputation)|189146|189146|5|0.0%|0.2%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|3|0.5%|0.1%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|3|0.0%|0.1%|
[php_harvesters](#php_harvesters)|408|408|2|0.4%|0.0%|
[iw_spamlist](#iw_spamlist)|3787|3787|2|0.0%|0.0%|
[et_tor](#et_tor)|6500|6500|2|0.0%|0.0%|
[dm_tor](#dm_tor)|6455|6455|2|0.0%|0.0%|
[bm_tor](#bm_tor)|6338|6338|2|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.0%|
[et_compromised](#et_compromised)|1704|1704|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1697|1697|1|0.0%|0.0%|

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
[firehol_level1](#firehol_level1)|5137|688854747|230|0.0%|100.0%|
[et_block](#et_block)|1000|18343756|229|0.0%|99.5%|
[firehol_level3](#firehol_level3)|109170|9626833|203|0.0%|88.2%|
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
[stopforumspam_1d](#stopforumspam_1d)|6690|6690|1|0.0%|0.4%|
[php_commenters](#php_commenters)|458|458|1|0.2%|0.4%|
[openbl_7d](#openbl_7d)|629|629|1|0.1%|0.4%|
[nixspam](#nixspam)|18020|18020|1|0.0%|0.4%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|1|0.0%|0.4%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.4%|
[firehol_level2](#firehol_level2)|20803|32382|1|0.0%|0.4%|

## zeus_badips

[Abuse.ch Zeus tracker](https://zeustracker.abuse.ch) badips includes IPv4 addresses that are used by the ZeuS trojan. It is the recommened blocklist if you want to block only ZeuS IPs. It excludes IP addresses that ZeuS Tracker believes to be hijacked (level 2) or belong to a free web hosting provider (level 3). Hence the false postive rate should be much lower compared to the standard ZeuS IP blocklist. **excellent list**

Source is downloaded from [this link](https://zeustracker.abuse.ch/blocklist.php?download=badips).

The last time downloaded was found to be dated: Fri Jun 12 08:27:06 UTC 2015.

The ipset `zeus_badips` has **202** entries, **202** unique IPs.

The following table shows the overlaps of `zeus_badips` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `zeus_badips`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `zeus_badips`.
- ` this % ` is the percentage **of this ipset (`zeus_badips`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[zeus](#zeus)|230|230|202|87.8%|100.0%|
[firehol_level1](#firehol_level1)|5137|688854747|202|0.0%|100.0%|
[et_block](#et_block)|1000|18343756|202|0.0%|100.0%|
[firehol_level3](#firehol_level3)|109170|9626833|180|0.0%|89.1%|
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
[stopforumspam_1d](#stopforumspam_1d)|6690|6690|1|0.0%|0.4%|
[php_commenters](#php_commenters)|458|458|1|0.2%|0.4%|
[openbl_7d](#openbl_7d)|629|629|1|0.1%|0.4%|
[openbl_60d](#openbl_60d)|6960|6960|1|0.0%|0.4%|
[openbl_30d](#openbl_30d)|2792|2792|1|0.0%|0.4%|
[nixspam](#nixspam)|18020|18020|1|0.0%|0.4%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.4%|
[firehol_level2](#firehol_level2)|20803|32382|1|0.0%|0.4%|
