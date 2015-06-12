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

The following list was automatically generated on Fri Jun 12 03:55:31 UTC 2015.

The update frequency is the maximum allowed by internal configuration. A list will never be downloaded sooner than the update frequency stated. A list may also not be downloaded, after this frequency expired, if it has not been modified on the server (as reported by HTTP `IF_MODIFIED_SINCE` method).

name|info|type|entries|update|
:--:|:--:|:--:|:-----:|:----:|
[alienvault_reputation](#alienvault_reputation)|[AlienVault.com](https://www.alienvault.com/) IP reputation database (this list seems to include port scanning hosts and to be updated regularly, but we found no information about its retention policy)|ipv4 hash:ip|187341 unique IPs|updated every 6 hours  from [this link](https://reputation.alienvault.com/reputation.generic)
[blocklist_de](#blocklist_de)|[Blocklist.de](https://www.blocklist.de/) IPs that have been detected by fail2ban in the last 48 hours - **excellent list**|ipv4 hash:ip|28132 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/all.txt)
[blocklist_de_apache](#blocklist_de_apache)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service Apache, Apache-DDOS, RFI-Attacks.|ipv4 hash:ip|14292 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/apache.txt)
[blocklist_de_bots](#blocklist_de_bots)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the RFI-Attacks, REG-Bots, IRC-Bots or BadBots (BadBots = he has posted a Spam-Comment on a open Forum or Wiki).|ipv4 hash:ip|2960 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/bots.txt)
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|[Blocklist.de](https://www.blocklist.de/) All IPs which attacks Joomlas, Wordpress and other Web-Logins with Brute-Force Logins.|ipv4 hash:ip|2846 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/bruteforcelogin.txt)
[blocklist_de_ftp](#blocklist_de_ftp)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours for attacks on the Service FTP.|ipv4 hash:ip|1586 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/ftp.txt)
[blocklist_de_imap](#blocklist_de_imap)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours for attacks on the Service imap, sasl, pop3, etc.|ipv4 hash:ip|2800 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/imap.txt)
[blocklist_de_mail](#blocklist_de_mail)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service Mail, Postfix.|ipv4 hash:ip|18158 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/mail.txt)
[blocklist_de_sip](#blocklist_de_sip)|[Blocklist.de](https://www.blocklist.de/) All IP addresses that tried to login in a SIP, VOIP or Asterisk Server and are included in the IPs list from [infiltrated.net](www.infiltrated.net)|ipv4 hash:ip|83 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/sip.txt)
[blocklist_de_ssh](#blocklist_de_ssh)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service SSH.|ipv4 hash:ip|2216 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/ssh.txt)
[blocklist_de_strongips](#blocklist_de_strongips)|[Blocklist.de](https://www.blocklist.de/) All IPs which are older then 2 month and have more then 5.000 attacks.|ipv4 hash:ip|169 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/strongips.txt)
[bm_tor](#bm_tor)|[torstatus.blutmagie.de](https://torstatus.blutmagie.de) list of all TOR network servers|ipv4 hash:ip|6428 unique IPs|updated every 30 mins  from [this link](https://torstatus.blutmagie.de/ip_list_all.php/Tor_ip_list_ALL.csv)
[bogons](#bogons)|[Team-Cymru.org](http://www.team-cymru.org) private and reserved addresses defined by RFC 1918, RFC 5735, and RFC 6598 and netblocks that have not been allocated to a regional internet registry - **excellent list - use it only your internet interface**|ipv4 hash:net|13 subnets, 592708608 unique IPs|updated every 1 day  from [this link](http://www.team-cymru.org/Services/Bogons/bogon-bn-agg.txt)
[bruteforceblocker](#bruteforceblocker)|[danger.rulez.sk](http://danger.rulez.sk/) IPs detected by [bruteforceblocker](http://danger.rulez.sk/index.php/bruteforceblocker/) (fail2ban alternative for SSH on OpenBSD). This is an automatically generated list from users reporting failed authentication attempts. An IP seems to be included if 3 or more users report it. Its retention pocily seems 30 days.|ipv4 hash:ip|1693 unique IPs|updated every 3 hours  from [this link](http://danger.rulez.sk/projects/bruteforceblocker/blist.php)
[ciarmy](#ciarmy)|[CIArmy.com](http://ciarmy.com/) IPs with poor Rogue Packet score that have not yet been identified as malicious by the community|ipv4 hash:ip|397 unique IPs|updated every 3 hours  from [this link](http://cinsscore.com/list/ci-badguys.txt)
[cleanmx_viruses](#cleanmx_viruses)|[Clean-MX.de](http://support.clean-mx.de/clean-mx/viruses.php) IPs with viruses|ipv4 hash:ip|121 unique IPs|updated every 12 hours  from [this link](http://support.clean-mx.de/clean-mx/xmlviruses.php?sort=id%20desc&response=alive)
[dm_tor](#dm_tor)|[dan.me.uk](https://www.dan.me.uk) dynamic list of TOR nodes|ipv4 hash:ip|6407 unique IPs|updated every 30 mins  from [this link](https://www.dan.me.uk/torlist/)
[dragon_http](#dragon_http)|[Dragon Search Group](http://www.dragonresearchgroup.org/) IPs that have been seen sending HTTP requests to Dragon Research Pods in the last 7 days. This report lists hosts that are highly suspicious and are likely conducting malicious HTTP attacks. LEGITIMATE SEARCH ENGINE BOTS MAY BE IN THIS LIST. This report is informational.  It is not a blacklist, but some operators may choose to use it to help protect their networks and hosts in the forms of automated reporting and mitigation services.|ipv4 hash:net|1021 subnets, 268288 unique IPs|updated every 1 hour  from [this link](http://www.dragonresearchgroup.org/insight/http-report.txt)
[dragon_sshpauth](#dragon_sshpauth)|[Dragon Search Group](http://www.dragonresearchgroup.org/) IP address that has been seen attempting to remotely login to a host using SSH password authentication, in the last 7 days. This report lists hosts that are highly suspicious and are likely conducting malicious SSH password authentication attacks.|ipv4 hash:net|1613 subnets, 1675 unique IPs|updated every 1 hour  from [this link](https://www.dragonresearchgroup.org/insight/sshpwauth.txt)
[dragon_vncprobe](#dragon_vncprobe)|[Dragon Search Group](http://www.dragonresearchgroup.org/) IP address that has been seen attempting to remotely connect to a host running the VNC application service, in the last 7 days. This report lists hosts that are highly suspicious and are likely conducting malicious VNC probes or VNC brute force attacks.|ipv4 hash:net|87 subnets, 87 unique IPs|updated every 1 hour  from [this link](https://www.dragonresearchgroup.org/insight/vncprobe.txt)
[dshield](#dshield)|[DShield.org](https://dshield.org/) top 20 attacking class C (/24) subnets over the last three days - **excellent list**|ipv4 hash:net|20 subnets, 5120 unique IPs|updated every 4 hours  from [this link](http://feeds.dshield.org/block.txt)
[et_block](#et_block)|[EmergingThreats.net](http://www.emergingthreats.net/) default blacklist (at the time of writing includes spamhaus DROP, dshield and abuse.ch trackers, which are available separately too - prefer to use the direct ipsets instead of this, they seem to lag a bit in updates)|ipv4 hash:net|1000 subnets, 18343756 unique IPs|updated every 12 hours  from [this link](http://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt)
[et_botcc](#et_botcc)|[EmergingThreats.net Command and Control IPs](http://doc.emergingthreats.net/bin/view/Main/BotCC) These IPs are updates every 24 hours and should be considered VERY highly reliable indications that a host is communicating with a known and active Bot or Malware command and control server - (although they say this includes abuse.ch trackers, it does not - most probably it is the shadowserver.org C&C list)|ipv4 hash:ip|505 unique IPs|updated every 12 hours  from [this link](http://rules.emergingthreats.net/fwrules/emerging-PIX-CC.rules)
[et_compromised](#et_compromised)|[EmergingThreats.net compromised hosts](http://doc.emergingthreats.net/bin/view/Main/CompromisedHost) - (this seems to be based on bruteforceblocker)|ipv4 hash:ip|1704 unique IPs|updated every 12 hours  from [this link](http://rules.emergingthreats.net/blockrules/compromised-ips.txt)
et_dshield|[EmergingThreats.net](http://www.emergingthreats.net/) dshield blocklist|ipv4 hash:net|disabled|updated every 12 hours  from [this link](http://rules.emergingthreats.net/fwrules/emerging-PIX-DSHIELD.rules)
et_spamhaus|[EmergingThreats.net](http://www.emergingthreats.net/) spamhaus blocklist|ipv4 hash:net|disabled|updated every 12 hours  from [this link](http://rules.emergingthreats.net/fwrules/emerging-PIX-DROP.rules)
[et_tor](#et_tor)|[EmergingThreats.net](http://www.emergingthreats.net/) [list](http://doc.emergingthreats.net/bin/view/Main/TorRules) of TOR network IPs|ipv4 hash:ip|6500 unique IPs|updated every 12 hours  from [this link](http://rules.emergingthreats.net/blockrules/emerging-tor.rules)
[feodo](#feodo)|[Abuse.ch Feodo tracker](https://feodotracker.abuse.ch) trojan includes IPs which are being used by Feodo (also known as Cridex or Bugat) which commits ebanking fraud - **excellent list**|ipv4 hash:ip|105 unique IPs|updated every 30 mins  from [this link](https://feodotracker.abuse.ch/blocklist/?download=ipblocklist)
[firehol_anonymous](#firehol_anonymous)|**FireHOL Anonymous** - Known anonymizing IPs. (includes: firehol_proxies anonymous bm_tor dm_tor tor_exits)|ipv4 hash:net|19227 subnets, 83278 unique IPs|
[firehol_level1](#firehol_level1)|**FireHOL Level 1** - Maximum protection without false positives. (includes: fullbogons dshield feodo palevo sslbl zeus spamhaus_drop spamhaus_edrop)|ipv4 hash:net|5137 subnets, 688854747 unique IPs|
[firehol_level2](#firehol_level2)|**FireHOL Level 2** - Maximum protection from attacks took place in the last 48 hours. (includes: openbl_1d blocklist_de stopforumspam_1d)|ipv4 hash:net|21690 subnets, 33293 unique IPs|
[firehol_level3](#firehol_level3)|**FireHOL Level 3** - All the bad IPs in last 30 days. (includes: openbl_30d stopforumspam_30d virbl malc0de shunlist malwaredomainlist bruteforceblocker ciarmy cleanmx_viruses snort_ipfilter ib_bluetack_spyware ib_bluetack_hijacked ib_bluetack_webexploit php_commenters php_dictionary php_harvesters php_spammers iw_wormlist)|ipv4 hash:net|109614 subnets, 9627353 unique IPs|
[firehol_proxies](#firehol_proxies)|**FireHOL Proxies** - Known open proxies in the last 30 days. (includes: ib_bluetack_proxies maxmind_proxy_fraud proxyrss proxz ri_connect_proxies ri_web_proxies xroxy)|ipv4 hash:net|12738 subnets, 13016 unique IPs|
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
[iw_spamlist](#iw_spamlist)|[ImproWare Antispam](http://antispam.imp.ch/) IPs sending spam, in the last 3 days|ipv4 hash:ip|3889 unique IPs|updated every 1 hour  from [this link](http://antispam.imp.ch/spamlist)
[iw_wormlist](#iw_wormlist)|[ImproWare Antispam](http://antispam.imp.ch/) IPs sending emails with viruses or worms, in the last 3 days|ipv4 hash:ip|35 unique IPs|updated every 1 hour  from [this link](http://antispam.imp.ch/wormlist)
lashback_ubl|[The LashBack UBL](http://blacklist.lashback.com/) The Unsubscribe Blacklist (UBL) is a real-time blacklist of IP addresses which are sending email to names harvested from suppression files (this is a big list, more than 500.000 IPs)|ipv4 hash:ip|disabled|updated every 1 day  from [this link](http://www.unsubscore.com/blacklist.txt)
[malc0de](#malc0de)|[Malc0de.com](http://malc0de.com) malicious IPs of the last 30 days|ipv4 hash:ip|276 unique IPs|updated every 1 day  from [this link](http://malc0de.com/bl/IP_Blacklist.txt)
[malwaredomainlist](#malwaredomainlist)|[malwaredomainlist.com](http://www.malwaredomainlist.com) list of malware active ip addresses|ipv4 hash:ip|1288 unique IPs|updated every 12 hours  from [this link](http://www.malwaredomainlist.com/hostslist/ip.txt)
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|[MaxMind.com](https://www.maxmind.com/en/anonymous-proxy-fraudulent-ip-address-list) list of anonymous proxy fraudelent IP addresses.|ipv4 hash:ip|524 unique IPs|updated every 4 hours  from [this link](https://www.maxmind.com/en/anonymous-proxy-fraudulent-ip-address-list)
[nixspam](#nixspam)|[NiX Spam](http://www.heise.de/ix/NiX-Spam-DNSBL-and-blacklist-for-download-499637.html) IP addresses that sent spam in the last hour - automatically generated entries without distinguishing open proxies from relays, dialup gateways, and so on. All IPs are removed after 12 hours if there is no spam from there.|ipv4 hash:ip|18244 unique IPs|updated every 15 mins  from [this link](http://www.dnsbl.manitu.net/download/nixspam-ip.dump.gz)
[nt_malware_http](#nt_malware_http)|[No Think](http://www.nothink.org/) Malware HTTP|ipv4 hash:ip|69 unique IPs|updated every 1 hour  from [this link](http://www.nothink.org/blacklist/blacklist_malware_http.txt)
[nt_malware_irc](#nt_malware_irc)|[No Think](http://www.nothink.org/) Malware IRC|ipv4 hash:ip|43 unique IPs|updated every 1 hour  from [this link](http://www.nothink.org/blacklist/blacklist_malware_irc.txt)
[nt_ssh_7d](#nt_ssh_7d)|[No Think](http://www.nothink.org/) Last 7 days SSH attacks|ipv4 hash:ip|0 unique IPs|updated every 1 hour  from [this link](http://www.nothink.org/blacklist/blacklist_ssh_week.txt)
openbl|[OpenBL.org](http://www.openbl.org/) default blacklist (currently it is the same with 90 days). OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications - **excellent list**|ipv4 hash:ip|disabled|updated every 4 hours  from [this link](http://www.openbl.org/lists/base.txt)
openbl_180d|[OpenBL.org](http://www.openbl.org/) last 180 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|disabled|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_180days.txt)
[openbl_1d](#openbl_1d)|[OpenBL.org](http://www.openbl.org/) last 24 hours IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|140 unique IPs|updated every 1 hour  from [this link](http://www.openbl.org/lists/base_1days.txt)
[openbl_30d](#openbl_30d)|[OpenBL.org](http://www.openbl.org/) last 30 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|2803 unique IPs|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_30days.txt)
openbl_360d|[OpenBL.org](http://www.openbl.org/) last 360 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|disabled|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_360days.txt)
[openbl_60d](#openbl_60d)|[OpenBL.org](http://www.openbl.org/) last 60 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|6974 unique IPs|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_60days.txt)
[openbl_7d](#openbl_7d)|[OpenBL.org](http://www.openbl.org/) last 7 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|633 unique IPs|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_7days.txt)
openbl_90d|[OpenBL.org](http://www.openbl.org/) last 90 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|disabled|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_90days.txt)
openbl_all|[OpenBL.org](http://www.openbl.org/) last all IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|disabled|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_all.txt)
[palevo](#palevo)|[Abuse.ch Palevo tracker](https://palevotracker.abuse.ch) worm includes IPs which are being used as botnet C&C for the Palevo crimeware - **excellent list**|ipv4 hash:ip|13 unique IPs|updated every 30 mins  from [this link](https://palevotracker.abuse.ch/blocklists.php?download=ipblocklist)
php_bad|[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) bad web hosts (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|disabled|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=b&rss=1)
[php_commenters](#php_commenters)|[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) comment spammers (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|458 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=c&rss=1)
[php_dictionary](#php_dictionary)|[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) directory attackers (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|737 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=d&rss=1)
[php_harvesters](#php_harvesters)|[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) harvesters (IPs that surf the internet looking for email addresses) (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|408 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=h&rss=1)
[php_spammers](#php_spammers)|[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) spam servers (IPs used by spammers to send messages) (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|735 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=s&rss=1)
[proxyrss](#proxyrss)|[proxyrss.com](http://www.proxyrss.com) open proxies syndicated from multiple sources.|ipv4 hash:ip|1738 unique IPs|updated every 4 hours  from [this link](http://www.proxyrss.com/proxylists/all.gz)
[proxz](#proxz)|[proxz.com](http://www.proxz.com) open proxies (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|1339 unique IPs|updated every 1 hour  from [this link](http://www.proxz.com/proxylists.xml)
[ri_connect_proxies](#ri_connect_proxies)|[rosinstrument.com](http://www.rosinstrument.com) open CONNECT proxies (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|2828 unique IPs|updated every 1 hour  from [this link](http://tools.rosinstrument.com/proxy/plab100.xml)
[ri_web_proxies](#ri_web_proxies)|[rosinstrument.com](http://www.rosinstrument.com) open HTTP proxies (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|7870 unique IPs|updated every 1 hour  from [this link](http://tools.rosinstrument.com/proxy/l100.xml)
[shunlist](#shunlist)|[AutoShun.org](http://autoshun.org/) IPs identified as hostile by correlating logs from distributed snort installations running the autoshun plugin|ipv4 hash:ip|1172 unique IPs|updated every 4 hours  from [this link](http://www.autoshun.org/files/shunlist.csv)
[snort_ipfilter](#snort_ipfilter)|[labs.snort.org](https://labs.snort.org/) supplied IP blacklist (this list seems to be updated frequently, but we found no information about it)|ipv4 hash:ip|9671 unique IPs|updated every 12 hours  from [this link](http://labs.snort.org/feeds/ip-filter.blf)
[sorbs_dul](#sorbs_dul)|[Sorbs.net](https://www.sorbs.net/) DUL, Dynamic User IPs extracted from deltas.|ipv4 hash:net|10 subnets, 4864 unique IPs|
[sorbs_http](#sorbs_http)|[Sorbs.net](https://www.sorbs.net/) HTTP proxies, extracted from deltas.|ipv4 hash:net|7 subnets, 7 unique IPs|
[sorbs_misc](#sorbs_misc)|[Sorbs.net](https://www.sorbs.net/) MISC proxies, extracted from deltas.|ipv4 hash:net|7 subnets, 7 unique IPs|
[sorbs_new_spam](#sorbs_new_spam)|[Sorbs.net](https://www.sorbs.net/) NEW Spam senders, extracted from deltas.|ipv4 hash:net|64467 subnets, 65300 unique IPs|
[sorbs_recent_spam](#sorbs_recent_spam)|[Sorbs.net](https://www.sorbs.net/) RECENT Spam senders, extracted from deltas.|ipv4 hash:net|64467 subnets, 65300 unique IPs|
[sorbs_smtp](#sorbs_smtp)|[Sorbs.net](https://www.sorbs.net/) SMTP Open Relays, extracted from deltas.|ipv4 hash:net|6 subnets, 6 unique IPs|
[sorbs_socks](#sorbs_socks)|[Sorbs.net](https://www.sorbs.net/) SOCKS proxies, extracted from deltas.|ipv4 hash:net|7 subnets, 7 unique IPs|
[sorbs_spam](#sorbs_spam)|[Sorbs.net](https://www.sorbs.net/) Spam senders, extracted from deltas.|ipv4 hash:net|64701 subnets, 65536 unique IPs|
[sorbs_web](#sorbs_web)|[Sorbs.net](https://www.sorbs.net/) WEB exploits, extracted from deltas.|ipv4 hash:net|598 subnets, 599 unique IPs|
[spamhaus_drop](#spamhaus_drop)|[Spamhaus.org](http://www.spamhaus.org) DROP list (according to their site this list should be dropped at tier-1 ISPs globaly) - **excellent list**|ipv4 hash:net|653 subnets, 18340608 unique IPs|updated every 12 hours  from [this link](http://www.spamhaus.org/drop/drop.txt)
[spamhaus_edrop](#spamhaus_edrop)|[Spamhaus.org](http://www.spamhaus.org) EDROP (extended matches that should be used with DROP) - **excellent list**|ipv4 hash:net|56 subnets, 487424 unique IPs|updated every 12 hours  from [this link](http://www.spamhaus.org/drop/edrop.txt)
[sslbl](#sslbl)|[Abuse.ch SSL Blacklist](https://sslbl.abuse.ch/) bad SSL traffic related to malware or botnet activities - **excellent list**|ipv4 hash:ip|370 unique IPs|updated every 30 mins  from [this link](https://sslbl.abuse.ch/blacklist/sslipblacklist.csv)
stopforumspam_180d|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 180 days)|ipv4 hash:ip|disabled|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/listed_ip_180.zip)
[stopforumspam_1d](#stopforumspam_1d)|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers in the last 24 hours - **excellent list**|ipv4 hash:ip|6683 unique IPs|updated every 1 hour  from [this link](http://www.stopforumspam.com/downloads/listed_ip_1.zip)
[stopforumspam_30d](#stopforumspam_30d)|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 30 days)|ipv4 hash:ip|94309 unique IPs|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/listed_ip_30.zip)
stopforumspam_365d|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 365 days)|ipv4 hash:ip|disabled|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/listed_ip_365.zip)
[stopforumspam_7d](#stopforumspam_7d)|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 7 days)|ipv4 hash:ip|29017 unique IPs|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/listed_ip_7.zip)
stopforumspam_90d|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 90 days)|ipv4 hash:ip|disabled|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/listed_ip_90.zip)
stopforumspam_ever|[StopForumSpam.com](http://www.stopforumspam.com) all IPs used by forum spammers, **ever** (normally you don't want to use this ipset, use the hourly one which includes last 24 hours IPs or the 7 days one)|ipv4 hash:ip|disabled|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/bannedips.zip)
[tor_exits](#tor_exits)|[TorProject.org](https://www.torproject.org) list of all current TOR exit points (TorDNSEL)|ipv4 hash:ip|1111 unique IPs|updated every 30 mins  from [this link](https://check.torproject.org/exit-addresses)
[virbl](#virbl)|[VirBL](http://virbl.bit.nl/) is a project of which the idea was born during the RIPE-48 meeting. The plan was to get reports of virusscanning mailservers, and put the IP-addresses that were reported to send viruses on a blacklist.|ipv4 hash:ip|23 unique IPs|updated every 1 hour  from [this link](http://virbl.bit.nl/download/virbl.dnsbl.bit.nl.txt)
[voipbl](#voipbl)|[VoIPBL.org](http://www.voipbl.org/) a distributed VoIP blacklist that is aimed to protects against VoIP Fraud and minimizing abuse for network that have publicly accessible PBX's. Several algorithms, external sources and manual confirmation are used before they categorize something as an attack and determine the threat level.|ipv4 hash:net|10586 subnets, 10998 unique IPs|updated every 4 hours  from [this link](http://www.voipbl.org/update/)
[xroxy](#xroxy)|[xroxy.com](http://www.xroxy.com) open proxies (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|2171 unique IPs|updated every 1 hour  from [this link](http://www.xroxy.com/proxyrss.xml)
[zeus](#zeus)|[Abuse.ch Zeus tracker](https://zeustracker.abuse.ch) standard, contains the same data as the ZeuS IP blocklist (zeus_badips) but with the slight difference that it doesn't exclude hijacked websites (level 2) and free web hosting providers (level 3). This means that this blocklist contains all IPv4 addresses associated with ZeuS C&Cs which are currently being tracked by ZeuS Tracker. Hence this blocklist will likely cause some false positives. - **excellent list**|ipv4 hash:ip|230 unique IPs|updated every 30 mins  from [this link](https://zeustracker.abuse.ch/blocklist.php?download=ipblocklist)
[zeus_badips](#zeus_badips)|[Abuse.ch Zeus tracker](https://zeustracker.abuse.ch) badips includes IPv4 addresses that are used by the ZeuS trojan. It is the recommened blocklist if you want to block only ZeuS IPs. It excludes IP addresses that ZeuS Tracker believes to be hijacked (level 2) or belong to a free web hosting provider (level 3). Hence the false postive rate should be much lower compared to the standard ZeuS IP blocklist. **excellent list**|ipv4 hash:ip|202 unique IPs|updated every 30 mins  from [this link](https://zeustracker.abuse.ch/blocklist.php?download=badips)

# Comparison of ipsets

Below we compare each ipset against all other.


## alienvault_reputation

[AlienVault.com](https://www.alienvault.com/) IP reputation database (this list seems to include port scanning hosts and to be updated regularly, but we found no information about its retention policy)

Source is downloaded from [this link](https://reputation.alienvault.com/reputation.generic).

The last time downloaded was found to be dated: Thu Jun 11 22:01:54 UTC 2015.

The ipset `alienvault_reputation` has **187341** entries, **187341** unique IPs.

The following table shows the overlaps of `alienvault_reputation` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `alienvault_reputation`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `alienvault_reputation`.
- ` this % ` is the percentage **of this ipset (`alienvault_reputation`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|14084|0.0%|7.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|7251|0.0%|3.8%|
[openbl_60d](#openbl_60d)|6974|6974|6954|99.7%|3.7%|
[dragon_http](#dragon_http)|1021|268288|6150|2.2%|3.2%|
[firehol_level3](#firehol_level3)|109614|9627353|4813|0.0%|2.5%|
[firehol_level1](#firehol_level1)|5137|688854747|4605|0.0%|2.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|4185|0.0%|2.2%|
[et_block](#et_block)|1000|18343756|3752|0.0%|2.0%|
[dshield](#dshield)|20|5120|3336|65.1%|1.7%|
[openbl_30d](#openbl_30d)|2803|2803|2788|99.4%|1.4%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|1385|0.0%|0.7%|
[shunlist](#shunlist)|1172|1172|1154|98.4%|0.6%|
[firehol_level2](#firehol_level2)|21690|33293|1154|3.4%|0.6%|
[blocklist_de](#blocklist_de)|28132|28132|1111|3.9%|0.5%|
[et_compromised](#et_compromised)|1704|1704|1083|63.5%|0.5%|
[bruteforceblocker](#bruteforceblocker)|1693|1693|1068|63.0%|0.5%|
[blocklist_de_ssh](#blocklist_de_ssh)|2216|2216|908|40.9%|0.4%|
[dragon_sshpauth](#dragon_sshpauth)|1613|1675|874|52.1%|0.4%|
[openbl_7d](#openbl_7d)|633|633|631|99.6%|0.3%|
[ciarmy](#ciarmy)|397|397|387|97.4%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|293|0.0%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|278|0.0%|0.1%|
[voipbl](#voipbl)|10586|10998|176|1.6%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|167|0.1%|0.0%|
[openbl_1d](#openbl_1d)|140|140|138|98.5%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14292|14292|118|0.8%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9671|9671|108|1.1%|0.0%|
[sorbs_spam](#sorbs_spam)|64701|65536|91|0.1%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|91|0.1%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|91|0.1%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|87|0.2%|0.0%|
[sslbl](#sslbl)|370|370|65|17.5%|0.0%|
[nixspam](#nixspam)|18244|18244|65|0.3%|0.0%|
[zeus](#zeus)|230|230|61|26.5%|0.0%|
[firehol_anonymous](#firehol_anonymous)|19227|83278|57|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|18158|18158|46|0.2%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6683|6683|42|0.6%|0.0%|
[et_tor](#et_tor)|6500|6500|42|0.6%|0.0%|
[dm_tor](#dm_tor)|6407|6407|42|0.6%|0.0%|
[bm_tor](#bm_tor)|6428|6428|41|0.6%|0.0%|
[firehol_proxies](#firehol_proxies)|12738|13016|38|0.2%|0.0%|
[zeus_badips](#zeus_badips)|202|202|37|18.3%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|169|169|35|20.7%|0.0%|
[tor_exits](#tor_exits)|1111|1111|30|2.7%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2800|2800|30|1.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|29|5.5%|0.0%|
[dragon_vncprobe](#dragon_vncprobe)|87|87|28|32.1%|0.0%|
[iw_spamlist](#iw_spamlist)|3889|3889|23|0.5%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|2960|2960|21|0.7%|0.0%|
[php_commenters](#php_commenters)|458|458|19|4.1%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|83|83|19|22.8%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|15|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|14|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2846|2846|14|0.4%|0.0%|
[php_harvesters](#php_harvesters)|408|408|12|2.9%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|1586|1586|11|0.6%|0.0%|
[malc0de](#malc0de)|276|276|9|3.2%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|8|0.6%|0.0%|
[php_dictionary](#php_dictionary)|737|737|7|0.9%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|6|0.4%|0.0%|
[xroxy](#xroxy)|2171|2171|5|0.2%|0.0%|
[php_spammers](#php_spammers)|735|735|5|0.6%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7870|7870|4|0.0%|0.0%|
[et_botcc](#et_botcc)|505|505|4|0.7%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2828|2828|3|0.1%|0.0%|
[proxz](#proxz)|1339|1339|3|0.2%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|121|121|3|2.4%|0.0%|
[nt_malware_irc](#nt_malware_irc)|43|43|2|4.6%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|2|0.3%|0.0%|
[feodo](#feodo)|105|105|2|1.9%|0.0%|
[sorbs_web](#sorbs_web)|598|599|1|0.1%|0.0%|
[proxyrss](#proxyrss)|1738|1738|1|0.0%|0.0%|
[nt_malware_http](#nt_malware_http)|69|69|1|1.4%|0.0%|

## blocklist_de

[Blocklist.de](https://www.blocklist.de/) IPs that have been detected by fail2ban in the last 48 hours - **excellent list**

Source is downloaded from [this link](http://lists.blocklist.de/lists/all.txt).

The last time downloaded was found to be dated: Fri Jun 12 03:42:06 UTC 2015.

The ipset `blocklist_de` has **28132** entries, **28132** unique IPs.

The following table shows the overlaps of `blocklist_de` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de`.
- ` this % ` is the percentage **of this ipset (`blocklist_de`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|21690|33293|28132|84.4%|100.0%|
[blocklist_de_mail](#blocklist_de_mail)|18158|18158|18158|100.0%|64.5%|
[blocklist_de_apache](#blocklist_de_apache)|14292|14292|14226|99.5%|50.5%|
[firehol_level3](#firehol_level3)|109614|9627353|3799|0.0%|13.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|3362|0.0%|11.9%|
[blocklist_de_bots](#blocklist_de_bots)|2960|2960|2959|99.9%|10.5%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2846|2846|2846|100.0%|10.1%|
[blocklist_de_imap](#blocklist_de_imap)|2800|2800|2800|100.0%|9.9%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|2710|2.8%|9.6%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|2432|8.3%|8.6%|
[blocklist_de_ssh](#blocklist_de_ssh)|2216|2216|2216|100.0%|7.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|1599|0.0%|5.6%|
[blocklist_de_ftp](#blocklist_de_ftp)|1586|1586|1586|100.0%|5.6%|
[stopforumspam_1d](#stopforumspam_1d)|6683|6683|1538|23.0%|5.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|1526|0.0%|5.4%|
[sorbs_spam](#sorbs_spam)|64701|65536|1313|2.0%|4.6%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|1305|1.9%|4.6%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|1305|1.9%|4.6%|
[alienvault_reputation](#alienvault_reputation)|187341|187341|1111|0.5%|3.9%|
[openbl_60d](#openbl_60d)|6974|6974|771|11.0%|2.7%|
[dragon_sshpauth](#dragon_sshpauth)|1613|1675|673|40.1%|2.3%|
[firehol_anonymous](#firehol_anonymous)|19227|83278|669|0.8%|2.3%|
[openbl_30d](#openbl_30d)|2803|2803|650|23.1%|2.3%|
[firehol_proxies](#firehol_proxies)|12738|13016|646|4.9%|2.2%|
[bruteforceblocker](#bruteforceblocker)|1693|1693|569|33.6%|2.0%|
[nixspam](#nixspam)|18244|18244|561|3.0%|1.9%|
[et_compromised](#et_compromised)|1704|1704|553|32.4%|1.9%|
[ri_web_proxies](#ri_web_proxies)|7870|7870|469|5.9%|1.6%|
[openbl_7d](#openbl_7d)|633|633|372|58.7%|1.3%|
[shunlist](#shunlist)|1172|1172|363|30.9%|1.2%|
[xroxy](#xroxy)|2171|2171|228|10.5%|0.8%|
[proxyrss](#proxyrss)|1738|1738|223|12.8%|0.7%|
[firehol_level1](#firehol_level1)|5137|688854747|222|0.0%|0.7%|
[snort_ipfilter](#snort_ipfilter)|9671|9671|214|2.2%|0.7%|
[et_block](#et_block)|1000|18343756|214|0.0%|0.7%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|193|0.0%|0.6%|
[proxz](#proxz)|1339|1339|190|14.1%|0.6%|
[blocklist_de_strongips](#blocklist_de_strongips)|169|169|169|100.0%|0.6%|
[iw_spamlist](#iw_spamlist)|3889|3889|135|3.4%|0.4%|
[openbl_1d](#openbl_1d)|140|140|124|88.5%|0.4%|
[php_dictionary](#php_dictionary)|737|737|118|16.0%|0.4%|
[php_spammers](#php_spammers)|735|735|108|14.6%|0.3%|
[php_commenters](#php_commenters)|458|458|106|23.1%|0.3%|
[dshield](#dshield)|20|5120|92|1.7%|0.3%|
[sorbs_web](#sorbs_web)|598|599|69|11.5%|0.2%|
[ri_connect_proxies](#ri_connect_proxies)|2828|2828|68|2.4%|0.2%|
[blocklist_de_sip](#blocklist_de_sip)|83|83|64|77.1%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|58|0.0%|0.2%|
[dragon_http](#dragon_http)|1021|268288|50|0.0%|0.1%|
[voipbl](#voipbl)|10586|10998|39|0.3%|0.1%|
[php_harvesters](#php_harvesters)|408|408|36|8.8%|0.1%|
[ciarmy](#ciarmy)|397|397|35|8.8%|0.1%|
[tor_exits](#tor_exits)|1111|1111|18|1.6%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|15|0.0%|0.0%|
[et_tor](#et_tor)|6500|6500|13|0.2%|0.0%|
[dm_tor](#dm_tor)|6407|6407|11|0.1%|0.0%|
[bm_tor](#bm_tor)|6428|6428|11|0.1%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|7|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|6|1.1%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|5|0.0%|0.0%|
[dragon_vncprobe](#dragon_vncprobe)|87|87|5|5.7%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|4|0.6%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|3|0.2%|0.0%|
[sorbs_socks](#sorbs_socks)|7|7|1|14.2%|0.0%|
[sorbs_misc](#sorbs_misc)|7|7|1|14.2%|0.0%|
[sorbs_http](#sorbs_http)|7|7|1|14.2%|0.0%|
[iw_wormlist](#iw_wormlist)|35|35|1|2.8%|0.0%|

## blocklist_de_apache

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service Apache, Apache-DDOS, RFI-Attacks.

Source is downloaded from [this link](http://lists.blocklist.de/lists/apache.txt).

The last time downloaded was found to be dated: Fri Jun 12 03:28:06 UTC 2015.

The ipset `blocklist_de_apache` has **14292** entries, **14292** unique IPs.

The following table shows the overlaps of `blocklist_de_apache` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_apache`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_apache`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_apache`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|21690|33293|14226|42.7%|99.5%|
[blocklist_de](#blocklist_de)|28132|28132|14226|50.5%|99.5%|
[blocklist_de_mail](#blocklist_de_mail)|18158|18158|11059|60.9%|77.3%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2846|2846|2846|100.0%|19.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|2308|0.0%|16.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|1323|0.0%|9.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|1084|0.0%|7.5%|
[firehol_level3](#firehol_level3)|109614|9627353|281|0.0%|1.9%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|198|0.2%|1.3%|
[alienvault_reputation](#alienvault_reputation)|187341|187341|118|0.0%|0.8%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|116|0.3%|0.8%|
[stopforumspam_1d](#stopforumspam_1d)|6683|6683|60|0.8%|0.4%|
[sorbs_spam](#sorbs_spam)|64701|65536|46|0.0%|0.3%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|46|0.0%|0.3%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|46|0.0%|0.3%|
[shunlist](#shunlist)|1172|1172|38|3.2%|0.2%|
[blocklist_de_strongips](#blocklist_de_strongips)|169|169|33|19.5%|0.2%|
[snort_ipfilter](#snort_ipfilter)|9671|9671|30|0.3%|0.2%|
[php_commenters](#php_commenters)|458|458|28|6.1%|0.1%|
[ciarmy](#ciarmy)|397|397|28|7.0%|0.1%|
[nixspam](#nixspam)|18244|18244|25|0.1%|0.1%|
[blocklist_de_bots](#blocklist_de_bots)|2960|2960|22|0.7%|0.1%|
[firehol_anonymous](#firehol_anonymous)|19227|83278|20|0.0%|0.1%|
[tor_exits](#tor_exits)|1111|1111|18|1.6%|0.1%|
[et_tor](#et_tor)|6500|6500|13|0.2%|0.0%|
[dragon_http](#dragon_http)|1021|268288|12|0.0%|0.0%|
[dm_tor](#dm_tor)|6407|6407|11|0.1%|0.0%|
[bm_tor](#bm_tor)|6428|6428|11|0.1%|0.0%|
[et_block](#et_block)|1000|18343756|9|0.0%|0.0%|
[openbl_60d](#openbl_60d)|6974|6974|8|0.1%|0.0%|
[firehol_level1](#firehol_level1)|5137|688854747|7|0.0%|0.0%|
[php_spammers](#php_spammers)|735|735|6|0.8%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|5|0.0%|0.0%|
[openbl_30d](#openbl_30d)|2803|2803|5|0.1%|0.0%|
[iw_spamlist](#iw_spamlist)|3889|3889|4|0.1%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|4|0.0%|0.0%|
[php_dictionary](#php_dictionary)|737|737|3|0.4%|0.0%|
[openbl_7d](#openbl_7d)|633|633|3|0.4%|0.0%|
[voipbl](#voipbl)|10586|10998|2|0.0%|0.0%|
[php_harvesters](#php_harvesters)|408|408|2|0.4%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|2|0.3%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|2|0.0%|0.0%|
[firehol_proxies](#firehol_proxies)|12738|13016|2|0.0%|0.0%|
[dragon_vncprobe](#dragon_vncprobe)|87|87|2|2.2%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|1|0.0%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.0%|
[dshield](#dshield)|20|5120|1|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2800|2800|1|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|1586|1586|1|0.0%|0.0%|

## blocklist_de_bots

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the RFI-Attacks, REG-Bots, IRC-Bots or BadBots (BadBots = he has posted a Spam-Comment on a open Forum or Wiki).

Source is downloaded from [this link](http://lists.blocklist.de/lists/bots.txt).

The last time downloaded was found to be dated: Fri Jun 12 03:42:14 UTC 2015.

The ipset `blocklist_de_bots` has **2960** entries, **2960** unique IPs.

The following table shows the overlaps of `blocklist_de_bots` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_bots`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_bots`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_bots`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|21690|33293|2959|8.8%|99.9%|
[blocklist_de](#blocklist_de)|28132|28132|2959|10.5%|99.9%|
[firehol_level3](#firehol_level3)|109614|9627353|2382|0.0%|80.4%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|2358|2.5%|79.6%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|2243|7.7%|75.7%|
[stopforumspam_1d](#stopforumspam_1d)|6683|6683|1473|22.0%|49.7%|
[firehol_anonymous](#firehol_anonymous)|19227|83278|520|0.6%|17.5%|
[firehol_proxies](#firehol_proxies)|12738|13016|519|3.9%|17.5%|
[ri_web_proxies](#ri_web_proxies)|7870|7870|382|4.8%|12.9%|
[proxyrss](#proxyrss)|1738|1738|223|12.8%|7.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|174|0.0%|5.8%|
[xroxy](#xroxy)|2171|2171|172|7.9%|5.8%|
[proxz](#proxz)|1339|1339|157|11.7%|5.3%|
[blocklist_de_strongips](#blocklist_de_strongips)|169|169|126|74.5%|4.2%|
[php_commenters](#php_commenters)|458|458|86|18.7%|2.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|77|0.0%|2.6%|
[ri_connect_proxies](#ri_connect_proxies)|2828|2828|65|2.2%|2.1%|
[firehol_level1](#firehol_level1)|5137|688854747|61|0.0%|2.0%|
[et_block](#et_block)|1000|18343756|60|0.0%|2.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|51|0.0%|1.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|50|0.0%|1.6%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|46|0.0%|1.5%|
[nixspam](#nixspam)|18244|18244|29|0.1%|0.9%|
[php_harvesters](#php_harvesters)|408|408|26|6.3%|0.8%|
[sorbs_spam](#sorbs_spam)|64701|65536|23|0.0%|0.7%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|23|0.0%|0.7%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|23|0.0%|0.7%|
[blocklist_de_mail](#blocklist_de_mail)|18158|18158|22|0.1%|0.7%|
[blocklist_de_apache](#blocklist_de_apache)|14292|14292|22|0.1%|0.7%|
[alienvault_reputation](#alienvault_reputation)|187341|187341|21|0.0%|0.7%|
[php_spammers](#php_spammers)|735|735|19|2.5%|0.6%|
[snort_ipfilter](#snort_ipfilter)|9671|9671|14|0.1%|0.4%|
[php_dictionary](#php_dictionary)|737|737|13|1.7%|0.4%|
[dshield](#dshield)|20|5120|8|0.1%|0.2%|
[sorbs_web](#sorbs_web)|598|599|5|0.8%|0.1%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|4|0.7%|0.1%|
[iw_spamlist](#iw_spamlist)|3889|3889|4|0.1%|0.1%|
[dragon_http](#dragon_http)|1021|268288|3|0.0%|0.1%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|2|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|2|0.1%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|2|0.3%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.0%|

## blocklist_de_bruteforce

[Blocklist.de](https://www.blocklist.de/) All IPs which attacks Joomlas, Wordpress and other Web-Logins with Brute-Force Logins.

Source is downloaded from [this link](http://lists.blocklist.de/lists/bruteforcelogin.txt).

The last time downloaded was found to be dated: Fri Jun 12 03:42:19 UTC 2015.

The ipset `blocklist_de_bruteforce` has **2846** entries, **2846** unique IPs.

The following table shows the overlaps of `blocklist_de_bruteforce` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_bruteforce`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_bruteforce`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_bruteforce`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|21690|33293|2846|8.5%|100.0%|
[blocklist_de_apache](#blocklist_de_apache)|14292|14292|2846|19.9%|100.0%|
[blocklist_de](#blocklist_de)|28132|28132|2846|10.1%|100.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|213|0.0%|7.4%|
[firehol_level3](#firehol_level3)|109614|9627353|84|0.0%|2.9%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|66|0.0%|2.3%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|48|0.1%|1.6%|
[sorbs_spam](#sorbs_spam)|64701|65536|46|0.0%|1.6%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|46|0.0%|1.6%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|46|0.0%|1.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|46|0.0%|1.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|36|0.0%|1.2%|
[stopforumspam_1d](#stopforumspam_1d)|6683|6683|27|0.4%|0.9%|
[snort_ipfilter](#snort_ipfilter)|9671|9671|27|0.2%|0.9%|
[nixspam](#nixspam)|18244|18244|23|0.1%|0.8%|
[firehol_anonymous](#firehol_anonymous)|19227|83278|17|0.0%|0.5%|
[tor_exits](#tor_exits)|1111|1111|16|1.4%|0.5%|
[alienvault_reputation](#alienvault_reputation)|187341|187341|14|0.0%|0.4%|
[et_tor](#et_tor)|6500|6500|10|0.1%|0.3%|
[dm_tor](#dm_tor)|6407|6407|8|0.1%|0.2%|
[bm_tor](#bm_tor)|6428|6428|8|0.1%|0.2%|
[blocklist_de_strongips](#blocklist_de_strongips)|169|169|8|4.7%|0.2%|
[php_spammers](#php_spammers)|735|735|6|0.8%|0.2%|
[php_commenters](#php_commenters)|458|458|6|1.3%|0.2%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|5|0.0%|0.1%|
[firehol_level1](#firehol_level1)|5137|688854747|5|0.0%|0.1%|
[et_block](#et_block)|1000|18343756|5|0.0%|0.1%|
[iw_spamlist](#iw_spamlist)|3889|3889|4|0.1%|0.1%|
[dragon_http](#dragon_http)|1021|268288|4|0.0%|0.1%|
[php_dictionary](#php_dictionary)|737|737|3|0.4%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|3|0.0%|0.1%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|2|0.0%|0.0%|
[shunlist](#shunlist)|1172|1172|1|0.0%|0.0%|
[php_harvesters](#php_harvesters)|408|408|1|0.2%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|1|0.1%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.0%|
[firehol_proxies](#firehol_proxies)|12738|13016|1|0.0%|0.0%|

## blocklist_de_ftp

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours for attacks on the Service FTP.

Source is downloaded from [this link](http://lists.blocklist.de/lists/ftp.txt).

The last time downloaded was found to be dated: Fri Jun 12 03:42:12 UTC 2015.

The ipset `blocklist_de_ftp` has **1586** entries, **1586** unique IPs.

The following table shows the overlaps of `blocklist_de_ftp` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_ftp`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_ftp`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_ftp`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|21690|33293|1586|4.7%|100.0%|
[blocklist_de](#blocklist_de)|28132|28132|1586|5.6%|100.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|127|0.0%|8.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|28|0.0%|1.7%|
[firehol_level3](#firehol_level3)|109614|9627353|22|0.0%|1.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|21|0.0%|1.3%|
[sorbs_spam](#sorbs_spam)|64701|65536|17|0.0%|1.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|17|0.0%|1.0%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|17|0.0%|1.0%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|14|0.0%|0.8%|
[alienvault_reputation](#alienvault_reputation)|187341|187341|11|0.0%|0.6%|
[nixspam](#nixspam)|18244|18244|10|0.0%|0.6%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|6|0.0%|0.3%|
[dragon_http](#dragon_http)|1021|268288|6|0.0%|0.3%|
[iw_spamlist](#iw_spamlist)|3889|3889|4|0.1%|0.2%|
[firehol_anonymous](#firehol_anonymous)|19227|83278|4|0.0%|0.2%|
[stopforumspam_1d](#stopforumspam_1d)|6683|6683|3|0.0%|0.1%|
[php_harvesters](#php_harvesters)|408|408|3|0.7%|0.1%|
[openbl_60d](#openbl_60d)|6974|6974|3|0.0%|0.1%|
[openbl_7d](#openbl_7d)|633|633|2|0.3%|0.1%|
[openbl_30d](#openbl_30d)|2803|2803|2|0.0%|0.1%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|2|0.0%|0.1%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|1|0.0%|0.0%|
[sorbs_web](#sorbs_web)|598|599|1|0.1%|0.0%|
[php_spammers](#php_spammers)|735|735|1|0.1%|0.0%|
[php_dictionary](#php_dictionary)|737|737|1|0.1%|0.0%|
[openbl_1d](#openbl_1d)|140|140|1|0.7%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.0%|
[firehol_level1](#firehol_level1)|5137|688854747|1|0.0%|0.0%|
[et_compromised](#et_compromised)|1704|1704|1|0.0%|0.0%|
[et_block](#et_block)|1000|18343756|1|0.0%|0.0%|
[ciarmy](#ciarmy)|397|397|1|0.2%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1693|1693|1|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14292|14292|1|0.0%|0.0%|

## blocklist_de_imap

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours for attacks on the Service imap, sasl, pop3, etc.

Source is downloaded from [this link](http://lists.blocklist.de/lists/imap.txt).

The last time downloaded was found to be dated: Fri Jun 12 03:42:12 UTC 2015.

The ipset `blocklist_de_imap` has **2800** entries, **2800** unique IPs.

The following table shows the overlaps of `blocklist_de_imap` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_imap`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_imap`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_imap`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|21690|33293|2800|8.4%|100.0%|
[blocklist_de_mail](#blocklist_de_mail)|18158|18158|2800|15.4%|100.0%|
[blocklist_de](#blocklist_de)|28132|28132|2800|9.9%|100.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|294|0.0%|10.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|80|0.0%|2.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|67|0.0%|2.3%|
[firehol_level3](#firehol_level3)|109614|9627353|35|0.0%|1.2%|
[sorbs_spam](#sorbs_spam)|64701|65536|30|0.0%|1.0%|
[alienvault_reputation](#alienvault_reputation)|187341|187341|30|0.0%|1.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|29|0.0%|1.0%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|29|0.0%|1.0%|
[nixspam](#nixspam)|18244|18244|22|0.1%|0.7%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|17|0.0%|0.6%|
[openbl_60d](#openbl_60d)|6974|6974|14|0.2%|0.5%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|10|0.0%|0.3%|
[firehol_level1](#firehol_level1)|5137|688854747|10|0.0%|0.3%|
[et_block](#et_block)|1000|18343756|10|0.0%|0.3%|
[openbl_30d](#openbl_30d)|2803|2803|9|0.3%|0.3%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|6|0.0%|0.2%|
[dragon_http](#dragon_http)|1021|268288|6|0.0%|0.2%|
[openbl_7d](#openbl_7d)|633|633|5|0.7%|0.1%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|4|0.0%|0.1%|
[et_compromised](#et_compromised)|1704|1704|4|0.2%|0.1%|
[bruteforceblocker](#bruteforceblocker)|1693|1693|4|0.2%|0.1%|
[snort_ipfilter](#snort_ipfilter)|9671|9671|3|0.0%|0.1%|
[stopforumspam_1d](#stopforumspam_1d)|6683|6683|2|0.0%|0.0%|
[shunlist](#shunlist)|1172|1172|2|0.1%|0.0%|
[php_harvesters](#php_harvesters)|408|408|2|0.4%|0.0%|
[iw_spamlist](#iw_spamlist)|3889|3889|2|0.0%|0.0%|
[voipbl](#voipbl)|10586|10998|1|0.0%|0.0%|
[openbl_1d](#openbl_1d)|140|140|1|0.7%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.0%|
[dragon_vncprobe](#dragon_vncprobe)|87|87|1|1.1%|0.0%|
[dragon_sshpauth](#dragon_sshpauth)|1613|1675|1|0.0%|0.0%|
[ciarmy](#ciarmy)|397|397|1|0.2%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14292|14292|1|0.0%|0.0%|

## blocklist_de_mail

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service Mail, Postfix.

Source is downloaded from [this link](http://lists.blocklist.de/lists/mail.txt).

The last time downloaded was found to be dated: Fri Jun 12 03:42:09 UTC 2015.

The ipset `blocklist_de_mail` has **18158** entries, **18158** unique IPs.

The following table shows the overlaps of `blocklist_de_mail` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_mail`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_mail`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_mail`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|21690|33293|18158|54.5%|100.0%|
[blocklist_de](#blocklist_de)|28132|28132|18158|64.5%|100.0%|
[blocklist_de_apache](#blocklist_de_apache)|14292|14292|11059|77.3%|60.9%|
[blocklist_de_imap](#blocklist_de_imap)|2800|2800|2800|100.0%|15.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|2593|0.0%|14.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|1431|0.0%|7.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|1262|0.0%|6.9%|
[sorbs_spam](#sorbs_spam)|64701|65536|1222|1.8%|6.7%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|1214|1.8%|6.6%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|1214|1.8%|6.6%|
[nixspam](#nixspam)|18244|18244|495|2.7%|2.7%|
[firehol_level3](#firehol_level3)|109614|9627353|404|0.0%|2.2%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|261|0.2%|1.4%|
[snort_ipfilter](#snort_ipfilter)|9671|9671|173|1.7%|0.9%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|142|0.4%|0.7%|
[firehol_anonymous](#firehol_anonymous)|19227|83278|127|0.1%|0.6%|
[firehol_proxies](#firehol_proxies)|12738|13016|125|0.9%|0.6%|
[iw_spamlist](#iw_spamlist)|3889|3889|123|3.1%|0.6%|
[php_dictionary](#php_dictionary)|737|737|101|13.7%|0.5%|
[ri_web_proxies](#ri_web_proxies)|7870|7870|86|1.0%|0.4%|
[php_spammers](#php_spammers)|735|735|81|11.0%|0.4%|
[sorbs_web](#sorbs_web)|598|599|63|10.5%|0.3%|
[xroxy](#xroxy)|2171|2171|56|2.5%|0.3%|
[stopforumspam_1d](#stopforumspam_1d)|6683|6683|48|0.7%|0.2%|
[alienvault_reputation](#alienvault_reputation)|187341|187341|46|0.0%|0.2%|
[proxz](#proxz)|1339|1339|33|2.4%|0.1%|
[php_commenters](#php_commenters)|458|458|29|6.3%|0.1%|
[firehol_level1](#firehol_level1)|5137|688854747|24|0.0%|0.1%|
[et_block](#et_block)|1000|18343756|23|0.0%|0.1%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|22|0.0%|0.1%|
[blocklist_de_strongips](#blocklist_de_strongips)|169|169|22|13.0%|0.1%|
[blocklist_de_bots](#blocklist_de_bots)|2960|2960|22|0.7%|0.1%|
[openbl_60d](#openbl_60d)|6974|6974|19|0.2%|0.1%|
[openbl_30d](#openbl_30d)|2803|2803|12|0.4%|0.0%|
[dragon_http](#dragon_http)|1021|268288|11|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|10|0.0%|0.0%|
[openbl_7d](#openbl_7d)|633|633|6|0.9%|0.0%|
[php_harvesters](#php_harvesters)|408|408|5|1.2%|0.0%|
[et_compromised](#et_compromised)|1704|1704|4|0.2%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1693|1693|4|0.2%|0.0%|
[shunlist](#shunlist)|1172|1172|3|0.2%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2828|2828|3|0.1%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|0.0%|
[et_tor](#et_tor)|6500|6500|3|0.0%|0.0%|
[dm_tor](#dm_tor)|6407|6407|3|0.0%|0.0%|
[ciarmy](#ciarmy)|397|397|3|0.7%|0.0%|
[bm_tor](#bm_tor)|6428|6428|3|0.0%|0.0%|
[voipbl](#voipbl)|10586|10998|2|0.0%|0.0%|
[tor_exits](#tor_exits)|1111|1111|2|0.1%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|2|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|2|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|2|0.3%|0.0%|
[dragon_vncprobe](#dragon_vncprobe)|87|87|2|2.2%|0.0%|
[sorbs_socks](#sorbs_socks)|7|7|1|14.2%|0.0%|
[sorbs_misc](#sorbs_misc)|7|7|1|14.2%|0.0%|
[sorbs_http](#sorbs_http)|7|7|1|14.2%|0.0%|
[openbl_1d](#openbl_1d)|140|140|1|0.7%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|1|0.1%|0.0%|
[iw_wormlist](#iw_wormlist)|35|35|1|2.8%|0.0%|
[dragon_sshpauth](#dragon_sshpauth)|1613|1675|1|0.0%|0.0%|

## blocklist_de_sip

[Blocklist.de](https://www.blocklist.de/) All IP addresses that tried to login in a SIP, VOIP or Asterisk Server and are included in the IPs list from [infiltrated.net](www.infiltrated.net)

Source is downloaded from [this link](http://lists.blocklist.de/lists/sip.txt).

The last time downloaded was found to be dated: Fri Jun 12 03:42:12 UTC 2015.

The ipset `blocklist_de_sip` has **83** entries, **83** unique IPs.

The following table shows the overlaps of `blocklist_de_sip` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_sip`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_sip`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_sip`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|21690|33293|64|0.1%|77.1%|
[blocklist_de](#blocklist_de)|28132|28132|64|0.2%|77.1%|
[voipbl](#voipbl)|10586|10998|33|0.3%|39.7%|
[alienvault_reputation](#alienvault_reputation)|187341|187341|19|0.0%|22.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|15|0.0%|18.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|5|0.0%|6.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|3|0.0%|3.6%|
[firehol_level3](#firehol_level3)|109614|9627353|3|0.0%|3.6%|
[dragon_http](#dragon_http)|1021|268288|3|0.0%|3.6%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|2|0.0%|2.4%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|2|0.0%|2.4%|
[firehol_level1](#firehol_level1)|5137|688854747|2|0.0%|2.4%|
[et_block](#et_block)|1000|18343756|2|0.0%|2.4%|
[shunlist](#shunlist)|1172|1172|1|0.0%|1.2%|
[et_botcc](#et_botcc)|505|505|1|0.1%|1.2%|

## blocklist_de_ssh

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service SSH.

Source is downloaded from [this link](http://lists.blocklist.de/lists/ssh.txt).

The last time downloaded was found to be dated: Fri Jun 12 03:42:07 UTC 2015.

The ipset `blocklist_de_ssh` has **2216** entries, **2216** unique IPs.

The following table shows the overlaps of `blocklist_de_ssh` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_ssh`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_ssh`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_ssh`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|21690|33293|2216|6.6%|100.0%|
[blocklist_de](#blocklist_de)|28132|28132|2216|7.8%|100.0%|
[alienvault_reputation](#alienvault_reputation)|187341|187341|908|0.4%|40.9%|
[firehol_level3](#firehol_level3)|109614|9627353|845|0.0%|38.1%|
[openbl_60d](#openbl_60d)|6974|6974|740|10.6%|33.3%|
[dragon_sshpauth](#dragon_sshpauth)|1613|1675|671|40.0%|30.2%|
[openbl_30d](#openbl_30d)|2803|2803|630|22.4%|28.4%|
[bruteforceblocker](#bruteforceblocker)|1693|1693|563|33.2%|25.4%|
[et_compromised](#et_compromised)|1704|1704|547|32.1%|24.6%|
[openbl_7d](#openbl_7d)|633|633|361|57.0%|16.2%|
[shunlist](#shunlist)|1172|1172|321|27.3%|14.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|223|0.0%|10.0%|
[firehol_level1](#firehol_level1)|5137|688854747|127|0.0%|5.7%|
[openbl_1d](#openbl_1d)|140|140|122|87.1%|5.5%|
[et_block](#et_block)|1000|18343756|119|0.0%|5.3%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|112|0.0%|5.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|109|0.0%|4.9%|
[dshield](#dshield)|20|5120|83|1.6%|3.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|47|0.0%|2.1%|
[blocklist_de_strongips](#blocklist_de_strongips)|169|169|28|16.5%|1.2%|
[dragon_http](#dragon_http)|1021|268288|15|0.0%|0.6%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|14|0.0%|0.6%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|7|0.0%|0.3%|
[sorbs_spam](#sorbs_spam)|64701|65536|5|0.0%|0.2%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|5|0.0%|0.2%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|5|0.0%|0.2%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|3|0.0%|0.1%|
[ciarmy](#ciarmy)|397|397|3|0.7%|0.1%|
[voipbl](#voipbl)|10586|10998|2|0.0%|0.0%|
[nixspam](#nixspam)|18244|18244|2|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7870|7870|1|0.0%|0.0%|
[php_spammers](#php_spammers)|735|735|1|0.1%|0.0%|
[php_harvesters](#php_harvesters)|408|408|1|0.2%|0.0%|
[php_commenters](#php_commenters)|458|458|1|0.2%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|1|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|1|0.0%|0.0%|
[firehol_proxies](#firehol_proxies)|12738|13016|1|0.0%|0.0%|
[firehol_anonymous](#firehol_anonymous)|19227|83278|1|0.0%|0.0%|
[dragon_vncprobe](#dragon_vncprobe)|87|87|1|1.1%|0.0%|

## blocklist_de_strongips

[Blocklist.de](https://www.blocklist.de/) All IPs which are older then 2 month and have more then 5.000 attacks.

Source is downloaded from [this link](http://lists.blocklist.de/lists/strongips.txt).

The last time downloaded was found to be dated: Fri Jun 12 03:42:16 UTC 2015.

The ipset `blocklist_de_strongips` has **169** entries, **169** unique IPs.

The following table shows the overlaps of `blocklist_de_strongips` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_strongips`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_strongips`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_strongips`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|21690|33293|169|0.5%|100.0%|
[blocklist_de](#blocklist_de)|28132|28132|169|0.6%|100.0%|
[firehol_level3](#firehol_level3)|109614|9627353|156|0.0%|92.3%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|130|0.1%|76.9%|
[blocklist_de_bots](#blocklist_de_bots)|2960|2960|126|4.2%|74.5%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|116|0.3%|68.6%|
[stopforumspam_1d](#stopforumspam_1d)|6683|6683|102|1.5%|60.3%|
[php_commenters](#php_commenters)|458|458|44|9.6%|26.0%|
[alienvault_reputation](#alienvault_reputation)|187341|187341|35|0.0%|20.7%|
[blocklist_de_apache](#blocklist_de_apache)|14292|14292|33|0.2%|19.5%|
[blocklist_de_ssh](#blocklist_de_ssh)|2216|2216|28|1.2%|16.5%|
[openbl_60d](#openbl_60d)|6974|6974|24|0.3%|14.2%|
[openbl_30d](#openbl_30d)|2803|2803|23|0.8%|13.6%|
[openbl_7d](#openbl_7d)|633|633|22|3.4%|13.0%|
[blocklist_de_mail](#blocklist_de_mail)|18158|18158|22|0.1%|13.0%|
[firehol_level1](#firehol_level1)|5137|688854747|20|0.0%|11.8%|
[dragon_sshpauth](#dragon_sshpauth)|1613|1675|20|1.1%|11.8%|
[shunlist](#shunlist)|1172|1172|19|1.6%|11.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|17|0.0%|10.0%|
[openbl_1d](#openbl_1d)|140|140|16|11.4%|9.4%|
[et_block](#et_block)|1000|18343756|14|0.0%|8.2%|
[dshield](#dshield)|20|5120|12|0.2%|7.1%|
[php_spammers](#php_spammers)|735|735|10|1.3%|5.9%|
[firehol_proxies](#firehol_proxies)|12738|13016|9|0.0%|5.3%|
[firehol_anonymous](#firehol_anonymous)|19227|83278|9|0.0%|5.3%|
[ri_web_proxies](#ri_web_proxies)|7870|7870|8|0.1%|4.7%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2846|2846|8|0.2%|4.7%|
[xroxy](#xroxy)|2171|2171|7|0.3%|4.1%|
[proxyrss](#proxyrss)|1738|1738|7|0.4%|4.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|7|0.0%|4.1%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|6|0.0%|3.5%|
[proxz](#proxz)|1339|1339|6|0.4%|3.5%|
[php_dictionary](#php_dictionary)|737|737|5|0.6%|2.9%|
[php_harvesters](#php_harvesters)|408|408|3|0.7%|1.7%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|1.7%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|2|0.0%|1.1%|
[sorbs_web](#sorbs_web)|598|599|2|0.3%|1.1%|
[sorbs_spam](#sorbs_spam)|64701|65536|2|0.0%|1.1%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|2|0.0%|1.1%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|2|0.0%|1.1%|
[snort_ipfilter](#snort_ipfilter)|9671|9671|2|0.0%|1.1%|
[nixspam](#nixspam)|18244|18244|2|0.0%|1.1%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|2|0.1%|1.1%|
[dragon_http](#dragon_http)|1021|268288|2|0.0%|1.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|1|0.0%|0.5%|
[et_compromised](#et_compromised)|1704|1704|1|0.0%|0.5%|
[ciarmy](#ciarmy)|397|397|1|0.2%|0.5%|
[bruteforceblocker](#bruteforceblocker)|1693|1693|1|0.0%|0.5%|

## bm_tor

[torstatus.blutmagie.de](https://torstatus.blutmagie.de) list of all TOR network servers

Source is downloaded from [this link](https://torstatus.blutmagie.de/ip_list_all.php/Tor_ip_list_ALL.csv).

The last time downloaded was found to be dated: Fri Jun 12 03:54:03 UTC 2015.

The ipset `bm_tor` has **6428** entries, **6428** unique IPs.

The following table shows the overlaps of `bm_tor` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `bm_tor`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `bm_tor`.
- ` this % ` is the percentage **of this ipset (`bm_tor`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_anonymous](#firehol_anonymous)|19227|83278|6428|7.7%|100.0%|
[dm_tor](#dm_tor)|6407|6407|6315|98.5%|98.2%|
[et_tor](#et_tor)|6500|6500|5886|90.5%|91.5%|
[firehol_level3](#firehol_level3)|109614|9627353|1085|0.0%|16.8%|
[snort_ipfilter](#snort_ipfilter)|9671|9671|1048|10.8%|16.3%|
[tor_exits](#tor_exits)|1111|1111|1013|91.1%|15.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|632|0.0%|9.8%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|630|0.6%|9.8%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|525|1.8%|8.1%|
[firehol_level2](#firehol_level2)|21690|33293|295|0.8%|4.5%|
[stopforumspam_1d](#stopforumspam_1d)|6683|6683|289|4.3%|4.4%|
[firehol_proxies](#firehol_proxies)|12738|13016|234|1.7%|3.6%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|229|43.7%|3.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|186|0.0%|2.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|168|0.0%|2.6%|
[php_commenters](#php_commenters)|458|458|54|11.7%|0.8%|
[alienvault_reputation](#alienvault_reputation)|187341|187341|41|0.0%|0.6%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|22|0.0%|0.3%|
[openbl_60d](#openbl_60d)|6974|6974|19|0.2%|0.2%|
[dragon_http](#dragon_http)|1021|268288|16|0.0%|0.2%|
[blocklist_de_apache](#blocklist_de_apache)|14292|14292|11|0.0%|0.1%|
[blocklist_de](#blocklist_de)|28132|28132|11|0.0%|0.1%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2846|2846|8|0.2%|0.1%|
[php_harvesters](#php_harvesters)|408|408|7|1.7%|0.1%|
[nixspam](#nixspam)|18244|18244|6|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7870|7870|5|0.0%|0.0%|
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
[blocklist_de_mail](#blocklist_de_mail)|18158|18158|3|0.0%|0.0%|
[xroxy](#xroxy)|2171|2171|2|0.0%|0.0%|
[dshield](#dshield)|20|5120|2|0.0%|0.0%|
[shunlist](#shunlist)|1172|1172|1|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2828|2828|1|0.0%|0.0%|
[proxyrss](#proxyrss)|1738|1738|1|0.0%|0.0%|
[iw_spamlist](#iw_spamlist)|3889|3889|1|0.0%|0.0%|

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
[iw_spamlist](#iw_spamlist)|3889|3889|5|0.1%|0.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|5|0.0%|0.0%|
[firehol_level3](#firehol_level3)|109614|9627353|3|0.0%|0.0%|
[php_harvesters](#php_harvesters)|408|408|1|0.2%|0.0%|
[php_commenters](#php_commenters)|458|458|1|0.2%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.0%|
[ciarmy](#ciarmy)|397|397|1|0.2%|0.0%|

## bruteforceblocker

[danger.rulez.sk](http://danger.rulez.sk/) IPs detected by [bruteforceblocker](http://danger.rulez.sk/index.php/bruteforceblocker/) (fail2ban alternative for SSH on OpenBSD). This is an automatically generated list from users reporting failed authentication attempts. An IP seems to be included if 3 or more users report it. Its retention pocily seems 30 days.

Source is downloaded from [this link](http://danger.rulez.sk/projects/bruteforceblocker/blist.php).

The last time downloaded was found to be dated: Fri Jun 12 02:45:14 UTC 2015.

The ipset `bruteforceblocker` has **1693** entries, **1693** unique IPs.

The following table shows the overlaps of `bruteforceblocker` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `bruteforceblocker`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `bruteforceblocker`.
- ` this % ` is the percentage **of this ipset (`bruteforceblocker`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level3](#firehol_level3)|109614|9627353|1693|0.0%|100.0%|
[et_compromised](#et_compromised)|1704|1704|1661|97.4%|98.1%|
[alienvault_reputation](#alienvault_reputation)|187341|187341|1068|0.5%|63.0%|
[openbl_60d](#openbl_60d)|6974|6974|962|13.7%|56.8%|
[openbl_30d](#openbl_30d)|2803|2803|902|32.1%|53.2%|
[dragon_sshpauth](#dragon_sshpauth)|1613|1675|641|38.2%|37.8%|
[firehol_level2](#firehol_level2)|21690|33293|572|1.7%|33.7%|
[blocklist_de](#blocklist_de)|28132|28132|569|2.0%|33.6%|
[blocklist_de_ssh](#blocklist_de_ssh)|2216|2216|563|25.4%|33.2%|
[shunlist](#shunlist)|1172|1172|338|28.8%|19.9%|
[openbl_7d](#openbl_7d)|633|633|308|48.6%|18.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|156|0.0%|9.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|87|0.0%|5.1%|
[openbl_1d](#openbl_1d)|140|140|74|52.8%|4.3%|
[firehol_level1](#firehol_level1)|5137|688854747|67|0.0%|3.9%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|61|0.0%|3.6%|
[et_block](#et_block)|1000|18343756|61|0.0%|3.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|54|0.0%|3.1%|
[dshield](#dshield)|20|5120|25|0.4%|1.4%|
[dragon_http](#dragon_http)|1021|268288|13|0.0%|0.7%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|9|0.0%|0.5%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|5|0.0%|0.2%|
[blocklist_de_mail](#blocklist_de_mail)|18158|18158|4|0.0%|0.2%|
[blocklist_de_imap](#blocklist_de_imap)|2800|2800|4|0.1%|0.2%|
[voipbl](#voipbl)|10586|10998|3|0.0%|0.1%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|3|0.0%|0.1%|
[sorbs_spam](#sorbs_spam)|64701|65536|3|0.0%|0.1%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|3|0.0%|0.1%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|3|0.0%|0.1%|
[firehol_proxies](#firehol_proxies)|12738|13016|3|0.0%|0.1%|
[firehol_anonymous](#firehol_anonymous)|19227|83278|3|0.0%|0.1%|
[ciarmy](#ciarmy)|397|397|3|0.7%|0.1%|
[stopforumspam_1d](#stopforumspam_1d)|6683|6683|2|0.0%|0.1%|
[proxz](#proxz)|1339|1339|2|0.1%|0.1%|
[nixspam](#nixspam)|18244|18244|2|0.0%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|2|0.0%|0.1%|
[xroxy](#xroxy)|2171|2171|1|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7870|7870|1|0.0%|0.0%|
[proxyrss](#proxyrss)|1738|1738|1|0.0%|0.0%|
[php_spammers](#php_spammers)|735|735|1|0.1%|0.0%|
[php_commenters](#php_commenters)|458|458|1|0.2%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|169|169|1|0.5%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|1586|1586|1|0.0%|0.0%|

## ciarmy

[CIArmy.com](http://ciarmy.com/) IPs with poor Rogue Packet score that have not yet been identified as malicious by the community

Source is downloaded from [this link](http://cinsscore.com/list/ci-badguys.txt).

The last time downloaded was found to be dated: Fri Jun 12 01:15:07 UTC 2015.

The ipset `ciarmy` has **397** entries, **397** unique IPs.

The following table shows the overlaps of `ciarmy` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ciarmy`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ciarmy`.
- ` this % ` is the percentage **of this ipset (`ciarmy`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level3](#firehol_level3)|109614|9627353|397|0.0%|100.0%|
[alienvault_reputation](#alienvault_reputation)|187341|187341|387|0.2%|97.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|69|0.0%|17.3%|
[firehol_level2](#firehol_level2)|21690|33293|36|0.1%|9.0%|
[blocklist_de](#blocklist_de)|28132|28132|35|0.1%|8.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|31|0.0%|7.8%|
[blocklist_de_apache](#blocklist_de_apache)|14292|14292|28|0.1%|7.0%|
[shunlist](#shunlist)|1172|1172|25|2.1%|6.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|20|0.0%|5.0%|
[dragon_http](#dragon_http)|1021|268288|11|0.0%|2.7%|
[firehol_level1](#firehol_level1)|5137|688854747|6|0.0%|1.5%|
[dshield](#dshield)|20|5120|5|0.0%|1.2%|
[et_compromised](#et_compromised)|1704|1704|3|0.1%|0.7%|
[bruteforceblocker](#bruteforceblocker)|1693|1693|3|0.1%|0.7%|
[blocklist_de_ssh](#blocklist_de_ssh)|2216|2216|3|0.1%|0.7%|
[blocklist_de_mail](#blocklist_de_mail)|18158|18158|3|0.0%|0.7%|
[voipbl](#voipbl)|10586|10998|2|0.0%|0.5%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|2|0.0%|0.5%|
[openbl_7d](#openbl_7d)|633|633|2|0.3%|0.5%|
[openbl_60d](#openbl_60d)|6974|6974|2|0.0%|0.5%|
[openbl_30d](#openbl_30d)|2803|2803|2|0.0%|0.5%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|1|0.0%|0.2%|
[openbl_1d](#openbl_1d)|140|140|1|0.7%|0.2%|
[fullbogons](#fullbogons)|3775|670173256|1|0.0%|0.2%|
[et_block](#et_block)|1000|18343756|1|0.0%|0.2%|
[dragon_vncprobe](#dragon_vncprobe)|87|87|1|1.1%|0.2%|
[dragon_sshpauth](#dragon_sshpauth)|1613|1675|1|0.0%|0.2%|
[bogons](#bogons)|13|592708608|1|0.0%|0.2%|
[blocklist_de_strongips](#blocklist_de_strongips)|169|169|1|0.5%|0.2%|
[blocklist_de_imap](#blocklist_de_imap)|2800|2800|1|0.0%|0.2%|
[blocklist_de_ftp](#blocklist_de_ftp)|1586|1586|1|0.0%|0.2%|

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
[firehol_level3](#firehol_level3)|109614|9627353|121|0.0%|100.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|19|0.0%|15.7%|
[malc0de](#malc0de)|276|276|16|5.7%|13.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|6|0.0%|4.9%|
[alienvault_reputation](#alienvault_reputation)|187341|187341|3|0.0%|2.4%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|2|0.1%|1.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|2|0.0%|1.6%|
[snort_ipfilter](#snort_ipfilter)|9671|9671|1|0.0%|0.8%|
[nixspam](#nixspam)|18244|18244|1|0.0%|0.8%|

## dm_tor

[dan.me.uk](https://www.dan.me.uk) dynamic list of TOR nodes

Source is downloaded from [this link](https://www.dan.me.uk/torlist/).

The last time downloaded was found to be dated: Fri Jun 12 03:36:06 UTC 2015.

The ipset `dm_tor` has **6407** entries, **6407** unique IPs.

The following table shows the overlaps of `dm_tor` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `dm_tor`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `dm_tor`.
- ` this % ` is the percentage **of this ipset (`dm_tor`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_anonymous](#firehol_anonymous)|19227|83278|6407|7.6%|100.0%|
[bm_tor](#bm_tor)|6428|6428|6315|98.2%|98.5%|
[et_tor](#et_tor)|6500|6500|5821|89.5%|90.8%|
[firehol_level3](#firehol_level3)|109614|9627353|1077|0.0%|16.8%|
[snort_ipfilter](#snort_ipfilter)|9671|9671|1040|10.7%|16.2%|
[tor_exits](#tor_exits)|1111|1111|1004|90.3%|15.6%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|633|0.6%|9.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|629|0.0%|9.8%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|528|1.8%|8.2%|
[firehol_level2](#firehol_level2)|21690|33293|295|0.8%|4.6%|
[stopforumspam_1d](#stopforumspam_1d)|6683|6683|289|4.3%|4.5%|
[firehol_proxies](#firehol_proxies)|12738|13016|234|1.7%|3.6%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|229|43.7%|3.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|187|0.0%|2.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|169|0.0%|2.6%|
[php_commenters](#php_commenters)|458|458|54|11.7%|0.8%|
[alienvault_reputation](#alienvault_reputation)|187341|187341|42|0.0%|0.6%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|22|0.0%|0.3%|
[openbl_60d](#openbl_60d)|6974|6974|20|0.2%|0.3%|
[dragon_http](#dragon_http)|1021|268288|16|0.0%|0.2%|
[blocklist_de_apache](#blocklist_de_apache)|14292|14292|11|0.0%|0.1%|
[blocklist_de](#blocklist_de)|28132|28132|11|0.0%|0.1%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2846|2846|8|0.2%|0.1%|
[php_harvesters](#php_harvesters)|408|408|7|1.7%|0.1%|
[nixspam](#nixspam)|18244|18244|6|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7870|7870|5|0.0%|0.0%|
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
[blocklist_de_mail](#blocklist_de_mail)|18158|18158|3|0.0%|0.0%|
[xroxy](#xroxy)|2171|2171|2|0.0%|0.0%|
[dshield](#dshield)|20|5120|2|0.0%|0.0%|
[shunlist](#shunlist)|1172|1172|1|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2828|2828|1|0.0%|0.0%|
[proxyrss](#proxyrss)|1738|1738|1|0.0%|0.0%|
[iw_spamlist](#iw_spamlist)|3889|3889|1|0.0%|0.0%|

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
[alienvault_reputation](#alienvault_reputation)|187341|187341|6150|3.2%|2.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|5989|0.0%|2.2%|
[firehol_level1](#firehol_level1)|5137|688854747|1025|0.0%|0.3%|
[et_block](#et_block)|1000|18343756|1024|0.0%|0.3%|
[dshield](#dshield)|20|5120|768|15.0%|0.2%|
[firehol_level3](#firehol_level3)|109614|9627353|557|0.0%|0.2%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|256|0.0%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|256|0.0%|0.0%|
[openbl_60d](#openbl_60d)|6974|6974|213|3.0%|0.0%|
[openbl_30d](#openbl_30d)|2803|2803|146|5.2%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|108|0.1%|0.0%|
[sorbs_spam](#sorbs_spam)|64701|65536|72|0.1%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|71|0.1%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|71|0.1%|0.0%|
[firehol_level2](#firehol_level2)|21690|33293|64|0.1%|0.0%|
[openbl_7d](#openbl_7d)|633|633|54|8.5%|0.0%|
[blocklist_de](#blocklist_de)|28132|28132|50|0.1%|0.0%|
[firehol_anonymous](#firehol_anonymous)|19227|83278|45|0.0%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|32|0.1%|0.0%|
[firehol_proxies](#firehol_proxies)|12738|13016|32|0.2%|0.0%|
[voipbl](#voipbl)|10586|10998|29|0.2%|0.0%|
[nixspam](#nixspam)|18244|18244|26|0.1%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|25|0.0%|0.0%|
[shunlist](#shunlist)|1172|1172|24|2.0%|0.0%|
[dragon_vncprobe](#dragon_vncprobe)|87|87|24|27.5%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7870|7870|20|0.2%|0.0%|
[et_tor](#et_tor)|6500|6500|16|0.2%|0.0%|
[dm_tor](#dm_tor)|6407|6407|16|0.2%|0.0%|
[bm_tor](#bm_tor)|6428|6428|16|0.2%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2216|2216|15|0.6%|0.0%|
[et_compromised](#et_compromised)|1704|1704|13|0.7%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1693|1693|13|0.7%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14292|14292|12|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6683|6683|11|0.1%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9671|9671|11|0.1%|0.0%|
[ciarmy](#ciarmy)|397|397|11|2.7%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|18158|18158|11|0.0%|0.0%|
[xroxy](#xroxy)|2171|2171|6|0.2%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|6|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2800|2800|6|0.2%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|1586|1586|6|0.3%|0.0%|
[tor_exits](#tor_exits)|1111|1111|5|0.4%|0.0%|
[openbl_1d](#openbl_1d)|140|140|5|3.5%|0.0%|
[dragon_sshpauth](#dragon_sshpauth)|1613|1675|5|0.2%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2828|2828|4|0.1%|0.0%|
[proxz](#proxz)|1339|1339|4|0.2%|0.0%|
[proxyrss](#proxyrss)|1738|1738|4|0.2%|0.0%|
[php_commenters](#php_commenters)|458|458|4|0.8%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|4|0.7%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2846|2846|4|0.1%|0.0%|
[zeus_badips](#zeus_badips)|202|202|3|1.4%|0.0%|
[zeus](#zeus)|230|230|3|1.3%|0.0%|
[malc0de](#malc0de)|276|276|3|1.0%|0.0%|
[et_botcc](#et_botcc)|505|505|3|0.5%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|83|83|3|3.6%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|2960|2960|3|0.1%|0.0%|
[php_dictionary](#php_dictionary)|737|737|2|0.2%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|2|0.1%|0.0%|
[iw_spamlist](#iw_spamlist)|3889|3889|2|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|2|0.1%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|169|169|2|1.1%|0.0%|
[sslbl](#sslbl)|370|370|1|0.2%|0.0%|
[sorbs_web](#sorbs_web)|598|599|1|0.1%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|1|0.1%|0.0%|

## dragon_sshpauth

[Dragon Search Group](http://www.dragonresearchgroup.org/) IP address that has been seen attempting to remotely login to a host using SSH password authentication, in the last 7 days. This report lists hosts that are highly suspicious and are likely conducting malicious SSH password authentication attacks.

Source is downloaded from [this link](https://www.dragonresearchgroup.org/insight/sshpwauth.txt).

The last time downloaded was found to be dated: Fri Jun 12 03:04:26 UTC 2015.

The ipset `dragon_sshpauth` has **1613** entries, **1675** unique IPs.

The following table shows the overlaps of `dragon_sshpauth` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `dragon_sshpauth`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `dragon_sshpauth`.
- ` this % ` is the percentage **of this ipset (`dragon_sshpauth`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[alienvault_reputation](#alienvault_reputation)|187341|187341|874|0.4%|52.1%|
[firehol_level3](#firehol_level3)|109614|9627353|867|0.0%|51.7%|
[openbl_60d](#openbl_60d)|6974|6974|788|11.2%|47.0%|
[openbl_30d](#openbl_30d)|2803|2803|705|25.1%|42.0%|
[firehol_level2](#firehol_level2)|21690|33293|674|2.0%|40.2%|
[blocklist_de](#blocklist_de)|28132|28132|673|2.3%|40.1%|
[blocklist_de_ssh](#blocklist_de_ssh)|2216|2216|671|30.2%|40.0%|
[bruteforceblocker](#bruteforceblocker)|1693|1693|641|37.8%|38.2%|
[et_compromised](#et_compromised)|1704|1704|637|37.3%|38.0%|
[shunlist](#shunlist)|1172|1172|380|32.4%|22.6%|
[openbl_7d](#openbl_7d)|633|633|345|54.5%|20.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|127|0.0%|7.5%|
[firehol_level1](#firehol_level1)|5137|688854747|106|0.0%|6.3%|
[et_block](#et_block)|1000|18343756|99|0.0%|5.9%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|98|0.0%|5.8%|
[openbl_1d](#openbl_1d)|140|140|91|65.0%|5.4%|
[dshield](#dshield)|20|5120|80|1.5%|4.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|72|0.0%|4.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|32|0.0%|1.9%|
[blocklist_de_strongips](#blocklist_de_strongips)|169|169|20|11.8%|1.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|5|0.0%|0.2%|
[dragon_http](#dragon_http)|1021|268288|5|0.0%|0.2%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|4|0.0%|0.2%|
[sslbl](#sslbl)|370|370|1|0.2%|0.0%|
[sorbs_spam](#sorbs_spam)|64701|65536|1|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|1|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|1|0.0%|0.0%|
[nixspam](#nixspam)|18244|18244|1|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|1|0.0%|0.0%|
[ciarmy](#ciarmy)|397|397|1|0.2%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|18158|18158|1|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2800|2800|1|0.0%|0.0%|

## dragon_vncprobe

[Dragon Search Group](http://www.dragonresearchgroup.org/) IP address that has been seen attempting to remotely connect to a host running the VNC application service, in the last 7 days. This report lists hosts that are highly suspicious and are likely conducting malicious VNC probes or VNC brute force attacks.

Source is downloaded from [this link](https://www.dragonresearchgroup.org/insight/vncprobe.txt).

The last time downloaded was found to be dated: Fri Jun 12 03:04:02 UTC 2015.

The ipset `dragon_vncprobe` has **87** entries, **87** unique IPs.

The following table shows the overlaps of `dragon_vncprobe` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `dragon_vncprobe`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `dragon_vncprobe`.
- ` this % ` is the percentage **of this ipset (`dragon_vncprobe`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[alienvault_reputation](#alienvault_reputation)|187341|187341|28|0.0%|32.1%|
[dragon_http](#dragon_http)|1021|268288|24|0.0%|27.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|12|0.0%|13.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|7|0.0%|8.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|5|0.0%|5.7%|
[firehol_level3](#firehol_level3)|109614|9627353|5|0.0%|5.7%|
[firehol_level2](#firehol_level2)|21690|33293|5|0.0%|5.7%|
[blocklist_de](#blocklist_de)|28132|28132|5|0.0%|5.7%|
[et_block](#et_block)|1000|18343756|4|0.0%|4.5%|
[shunlist](#shunlist)|1172|1172|2|0.1%|2.2%|
[firehol_level1](#firehol_level1)|5137|688854747|2|0.0%|2.2%|
[blocklist_de_mail](#blocklist_de_mail)|18158|18158|2|0.0%|2.2%|
[blocklist_de_apache](#blocklist_de_apache)|14292|14292|2|0.0%|2.2%|
[voipbl](#voipbl)|10586|10998|1|0.0%|1.1%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|1|0.0%|1.1%|
[openbl_60d](#openbl_60d)|6974|6974|1|0.0%|1.1%|
[openbl_30d](#openbl_30d)|2803|2803|1|0.0%|1.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|1.1%|
[dshield](#dshield)|20|5120|1|0.0%|1.1%|
[ciarmy](#ciarmy)|397|397|1|0.2%|1.1%|
[blocklist_de_ssh](#blocklist_de_ssh)|2216|2216|1|0.0%|1.1%|
[blocklist_de_imap](#blocklist_de_imap)|2800|2800|1|0.0%|1.1%|

## dshield

[DShield.org](https://dshield.org/) top 20 attacking class C (/24) subnets over the last three days - **excellent list**

Source is downloaded from [this link](http://feeds.dshield.org/block.txt).

The last time downloaded was found to be dated: Fri Jun 12 00:11:22 UTC 2015.

The ipset `dshield` has **20** entries, **5120** unique IPs.

The following table shows the overlaps of `dshield` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `dshield`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `dshield`.
- ` this % ` is the percentage **of this ipset (`dshield`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level1](#firehol_level1)|5137|688854747|5120|0.0%|100.0%|
[alienvault_reputation](#alienvault_reputation)|187341|187341|3336|1.7%|65.1%|
[et_block](#et_block)|1000|18343756|1536|0.0%|30.0%|
[dragon_http](#dragon_http)|1021|268288|768|0.2%|15.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|256|0.0%|5.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|256|0.0%|5.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|256|0.0%|5.0%|
[firehol_level3](#firehol_level3)|109614|9627353|124|0.0%|2.4%|
[firehol_level2](#firehol_level2)|21690|33293|93|0.2%|1.8%|
[blocklist_de](#blocklist_de)|28132|28132|92|0.3%|1.7%|
[openbl_60d](#openbl_60d)|6974|6974|84|1.2%|1.6%|
[shunlist](#shunlist)|1172|1172|83|7.0%|1.6%|
[blocklist_de_ssh](#blocklist_de_ssh)|2216|2216|83|3.7%|1.6%|
[openbl_30d](#openbl_30d)|2803|2803|80|2.8%|1.5%|
[dragon_sshpauth](#dragon_sshpauth)|1613|1675|80|4.7%|1.5%|
[et_compromised](#et_compromised)|1704|1704|29|1.7%|0.5%|
[bruteforceblocker](#bruteforceblocker)|1693|1693|25|1.4%|0.4%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|21|0.0%|0.4%|
[openbl_7d](#openbl_7d)|633|633|21|3.3%|0.4%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|15|0.0%|0.2%|
[blocklist_de_strongips](#blocklist_de_strongips)|169|169|12|7.1%|0.2%|
[stopforumspam_1d](#stopforumspam_1d)|6683|6683|9|0.1%|0.1%|
[blocklist_de_bots](#blocklist_de_bots)|2960|2960|8|0.2%|0.1%|
[openbl_1d](#openbl_1d)|140|140|6|4.2%|0.1%|
[ciarmy](#ciarmy)|397|397|5|1.2%|0.0%|
[firehol_anonymous](#firehol_anonymous)|19227|83278|2|0.0%|0.0%|
[et_tor](#et_tor)|6500|6500|2|0.0%|0.0%|
[dm_tor](#dm_tor)|6407|6407|2|0.0%|0.0%|
[bm_tor](#bm_tor)|6428|6428|2|0.0%|0.0%|
[tor_exits](#tor_exits)|1111|1111|1|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9671|9671|1|0.0%|0.0%|
[php_commenters](#php_commenters)|458|458|1|0.2%|0.0%|
[nixspam](#nixspam)|18244|18244|1|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|1|0.1%|0.0%|
[firehol_proxies](#firehol_proxies)|12738|13016|1|0.0%|0.0%|
[dragon_vncprobe](#dragon_vncprobe)|87|87|1|1.1%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14292|14292|1|0.0%|0.0%|

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
[firehol_level1](#firehol_level1)|5137|688854747|18340172|2.6%|99.9%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|18338560|99.9%|99.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|8532776|2.4%|46.5%|
[firehol_level3](#firehol_level3)|109614|9627353|6933353|72.0%|37.7%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|6932480|75.5%|37.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|2272787|0.2%|12.3%|
[fullbogons](#fullbogons)|3775|670173256|151552|0.0%|0.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|130650|0.0%|0.7%|
[alienvault_reputation](#alienvault_reputation)|187341|187341|3752|2.0%|0.0%|
[dshield](#dshield)|20|5120|1536|30.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1041|0.3%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|1032|1.0%|0.0%|
[dragon_http](#dragon_http)|1021|268288|1024|0.3%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|517|0.1%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9671|9671|297|3.0%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|283|0.9%|0.0%|
[firehol_level2](#firehol_level2)|21690|33293|279|0.8%|0.0%|
[openbl_60d](#openbl_60d)|6974|6974|245|3.5%|0.0%|
[zeus](#zeus)|230|230|229|99.5%|0.0%|
[blocklist_de](#blocklist_de)|28132|28132|214|0.7%|0.0%|
[zeus_badips](#zeus_badips)|202|202|202|100.0%|0.0%|
[openbl_30d](#openbl_30d)|2803|2803|125|4.4%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2216|2216|119|5.3%|0.0%|
[feodo](#feodo)|105|105|105|100.0%|0.0%|
[shunlist](#shunlist)|1172|1172|101|8.6%|0.0%|
[dragon_sshpauth](#dragon_sshpauth)|1613|1675|99|5.9%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6683|6683|88|1.3%|0.0%|
[et_compromised](#et_compromised)|1704|1704|65|3.8%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1693|1693|61|3.6%|0.0%|
[nixspam](#nixspam)|18244|18244|60|0.3%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|2960|2960|60|2.0%|0.0%|
[openbl_7d](#openbl_7d)|633|633|56|8.8%|0.0%|
[sslbl](#sslbl)|370|370|39|10.5%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|30|2.3%|0.0%|
[php_commenters](#php_commenters)|458|458|29|6.3%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|18158|18158|23|0.1%|0.0%|
[sorbs_spam](#sorbs_spam)|64701|65536|20|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|20|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|20|0.0%|0.0%|
[openbl_1d](#openbl_1d)|140|140|20|14.2%|0.0%|
[voipbl](#voipbl)|10586|10998|18|0.1%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|169|169|14|8.2%|0.0%|
[palevo](#palevo)|13|13|13|100.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2800|2800|10|0.3%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14292|14292|9|0.0%|0.0%|
[firehol_anonymous](#firehol_anonymous)|19227|83278|8|0.0%|0.0%|
[php_dictionary](#php_dictionary)|737|737|6|0.8%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|6|0.4%|0.0%|
[malc0de](#malc0de)|276|276|5|1.8%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|5|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2846|2846|5|0.1%|0.0%|
[php_spammers](#php_spammers)|735|735|4|0.5%|0.0%|
[nt_malware_http](#nt_malware_http)|69|69|4|5.7%|0.0%|
[firehol_proxies](#firehol_proxies)|12738|13016|4|0.0%|0.0%|
[et_tor](#et_tor)|6500|6500|4|0.0%|0.0%|
[dragon_vncprobe](#dragon_vncprobe)|87|87|4|4.5%|0.0%|
[dm_tor](#dm_tor)|6407|6407|4|0.0%|0.0%|
[bm_tor](#bm_tor)|6428|6428|4|0.0%|0.0%|
[nt_malware_irc](#nt_malware_irc)|43|43|3|6.9%|0.0%|
[iw_spamlist](#iw_spamlist)|3889|3889|3|0.0%|0.0%|
[tor_exits](#tor_exits)|1111|1111|2|0.1%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|2|0.3%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|83|83|2|2.4%|0.0%|
[virbl](#virbl)|23|23|1|4.3%|0.0%|
[proxz](#proxz)|1339|1339|1|0.0%|0.0%|
[php_harvesters](#php_harvesters)|408|408|1|0.2%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|1|0.1%|0.0%|
[et_botcc](#et_botcc)|505|505|1|0.1%|0.0%|
[ciarmy](#ciarmy)|397|397|1|0.2%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|1586|1586|1|0.0%|0.0%|

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
[alienvault_reputation](#alienvault_reputation)|187341|187341|4|0.0%|0.7%|
[firehol_level3](#firehol_level3)|109614|9627353|3|0.0%|0.5%|
[dragon_http](#dragon_http)|1021|268288|3|0.0%|0.5%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|1|0.0%|0.1%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|1|0.0%|0.1%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|1|0.0%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.1%|
[firehol_level1](#firehol_level1)|5137|688854747|1|0.0%|0.1%|
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
[firehol_level3](#firehol_level3)|109614|9627353|1678|0.0%|98.4%|
[bruteforceblocker](#bruteforceblocker)|1693|1693|1661|98.1%|97.4%|
[alienvault_reputation](#alienvault_reputation)|187341|187341|1083|0.5%|63.5%|
[openbl_60d](#openbl_60d)|6974|6974|976|13.9%|57.2%|
[openbl_30d](#openbl_30d)|2803|2803|910|32.4%|53.4%|
[dragon_sshpauth](#dragon_sshpauth)|1613|1675|637|38.0%|37.3%|
[firehol_level2](#firehol_level2)|21690|33293|556|1.6%|32.6%|
[blocklist_de](#blocklist_de)|28132|28132|553|1.9%|32.4%|
[blocklist_de_ssh](#blocklist_de_ssh)|2216|2216|547|24.6%|32.1%|
[shunlist](#shunlist)|1172|1172|338|28.8%|19.8%|
[openbl_7d](#openbl_7d)|633|633|307|48.4%|18.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|157|0.0%|9.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|89|0.0%|5.2%|
[openbl_1d](#openbl_1d)|140|140|72|51.4%|4.2%|
[firehol_level1](#firehol_level1)|5137|688854747|71|0.0%|4.1%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|65|0.0%|3.8%|
[et_block](#et_block)|1000|18343756|65|0.0%|3.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|54|0.0%|3.1%|
[dshield](#dshield)|20|5120|29|0.5%|1.7%|
[dragon_http](#dragon_http)|1021|268288|13|0.0%|0.7%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|10|0.0%|0.5%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|5|0.0%|0.2%|
[blocklist_de_mail](#blocklist_de_mail)|18158|18158|4|0.0%|0.2%|
[blocklist_de_imap](#blocklist_de_imap)|2800|2800|4|0.1%|0.2%|
[voipbl](#voipbl)|10586|10998|3|0.0%|0.1%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|3|0.0%|0.1%|
[sorbs_spam](#sorbs_spam)|64701|65536|3|0.0%|0.1%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|3|0.0%|0.1%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|3|0.0%|0.1%|
[firehol_proxies](#firehol_proxies)|12738|13016|3|0.0%|0.1%|
[firehol_anonymous](#firehol_anonymous)|19227|83278|3|0.0%|0.1%|
[ciarmy](#ciarmy)|397|397|3|0.7%|0.1%|
[stopforumspam_1d](#stopforumspam_1d)|6683|6683|2|0.0%|0.1%|
[proxz](#proxz)|1339|1339|2|0.1%|0.1%|
[nixspam](#nixspam)|18244|18244|2|0.0%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|2|0.0%|0.1%|
[xroxy](#xroxy)|2171|2171|1|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7870|7870|1|0.0%|0.0%|
[proxyrss](#proxyrss)|1738|1738|1|0.0%|0.0%|
[php_spammers](#php_spammers)|735|735|1|0.1%|0.0%|
[php_commenters](#php_commenters)|458|458|1|0.2%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|169|169|1|0.5%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|1586|1586|1|0.0%|0.0%|

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
[firehol_anonymous](#firehol_anonymous)|19227|83278|5924|7.1%|91.1%|
[bm_tor](#bm_tor)|6428|6428|5886|91.5%|90.5%|
[dm_tor](#dm_tor)|6407|6407|5821|90.8%|89.5%|
[firehol_level3](#firehol_level3)|109614|9627353|1127|0.0%|17.3%|
[snort_ipfilter](#snort_ipfilter)|9671|9671|1092|11.2%|16.8%|
[tor_exits](#tor_exits)|1111|1111|985|88.6%|15.1%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|651|0.6%|10.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|636|0.0%|9.7%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|547|1.8%|8.4%|
[firehol_level2](#firehol_level2)|21690|33293|306|0.9%|4.7%|
[stopforumspam_1d](#stopforumspam_1d)|6683|6683|298|4.4%|4.5%|
[firehol_proxies](#firehol_proxies)|12738|13016|238|1.8%|3.6%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|233|44.4%|3.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|182|0.0%|2.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|168|0.0%|2.5%|
[php_commenters](#php_commenters)|458|458|54|11.7%|0.8%|
[alienvault_reputation](#alienvault_reputation)|187341|187341|42|0.0%|0.6%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|22|0.0%|0.3%|
[openbl_60d](#openbl_60d)|6974|6974|20|0.2%|0.3%|
[dragon_http](#dragon_http)|1021|268288|16|0.0%|0.2%|
[blocklist_de_apache](#blocklist_de_apache)|14292|14292|13|0.0%|0.2%|
[blocklist_de](#blocklist_de)|28132|28132|13|0.0%|0.2%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2846|2846|10|0.3%|0.1%|
[php_harvesters](#php_harvesters)|408|408|7|1.7%|0.1%|
[ri_web_proxies](#ri_web_proxies)|7870|7870|5|0.0%|0.0%|
[php_spammers](#php_spammers)|735|735|5|0.6%|0.0%|
[nixspam](#nixspam)|18244|18244|5|0.0%|0.0%|
[firehol_level1](#firehol_level1)|5137|688854747|5|0.0%|0.0%|
[sorbs_spam](#sorbs_spam)|64701|65536|4|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|4|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|4|0.0%|0.0%|
[php_dictionary](#php_dictionary)|737|737|4|0.5%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|4|0.0%|0.0%|
[et_block](#et_block)|1000|18343756|4|0.0%|0.0%|
[voipbl](#voipbl)|10586|10998|3|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|3|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|18158|18158|3|0.0%|0.0%|
[xroxy](#xroxy)|2171|2171|2|0.0%|0.0%|
[dshield](#dshield)|20|5120|2|0.0%|0.0%|
[shunlist](#shunlist)|1172|1172|1|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2828|2828|1|0.0%|0.0%|
[proxyrss](#proxyrss)|1738|1738|1|0.0%|0.0%|
[iw_spamlist](#iw_spamlist)|3889|3889|1|0.0%|0.0%|

## feodo

[Abuse.ch Feodo tracker](https://feodotracker.abuse.ch) trojan includes IPs which are being used by Feodo (also known as Cridex or Bugat) which commits ebanking fraud - **excellent list**

Source is downloaded from [this link](https://feodotracker.abuse.ch/blocklist/?download=ipblocklist).

The last time downloaded was found to be dated: Fri Jun 12 03:54:26 UTC 2015.

The ipset `feodo` has **105** entries, **105** unique IPs.

The following table shows the overlaps of `feodo` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `feodo`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `feodo`.
- ` this % ` is the percentage **of this ipset (`feodo`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level1](#firehol_level1)|5137|688854747|105|0.0%|100.0%|
[et_block](#et_block)|1000|18343756|105|0.0%|100.0%|
[snort_ipfilter](#snort_ipfilter)|9671|9671|83|0.8%|79.0%|
[firehol_level3](#firehol_level3)|109614|9627353|83|0.0%|79.0%|
[sslbl](#sslbl)|370|370|38|10.2%|36.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|11|0.0%|10.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|3|0.0%|2.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|3|0.0%|2.8%|
[alienvault_reputation](#alienvault_reputation)|187341|187341|2|0.0%|1.9%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.9%|

## firehol_anonymous

**FireHOL Anonymous** - Known anonymizing IPs. (includes: firehol_proxies anonymous bm_tor dm_tor tor_exits)

Source is downloaded from [this link]().

The last time downloaded was found to be dated: Sun Jun  7 22:20:34 UTC 2015.

The ipset `firehol_anonymous` has **19227** entries, **83278** unique IPs.

The following table shows the overlaps of `firehol_anonymous` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `firehol_anonymous`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `firehol_anonymous`.
- ` this % ` is the percentage **of this ipset (`firehol_anonymous`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_proxies](#firehol_proxies)|12738|13016|13016|100.0%|15.6%|
[ri_web_proxies](#ri_web_proxies)|7870|7870|7870|100.0%|9.4%|
[firehol_level3](#firehol_level3)|109614|9627353|6812|0.0%|8.1%|
[bm_tor](#bm_tor)|6428|6428|6428|100.0%|7.7%|
[dm_tor](#dm_tor)|6407|6407|6407|100.0%|7.6%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|6238|6.6%|7.4%|
[et_tor](#et_tor)|6500|6500|5924|91.1%|7.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|3446|0.0%|4.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|2898|0.0%|3.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|2880|0.0%|3.4%|
[ri_connect_proxies](#ri_connect_proxies)|2828|2828|2828|100.0%|3.3%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|2753|9.4%|3.3%|
[xroxy](#xroxy)|2171|2171|2171|100.0%|2.6%|
[proxyrss](#proxyrss)|1738|1738|1738|100.0%|2.0%|
[proxz](#proxz)|1339|1339|1339|100.0%|1.6%|
[firehol_level2](#firehol_level2)|21690|33293|1298|3.8%|1.5%|
[snort_ipfilter](#snort_ipfilter)|9671|9671|1233|12.7%|1.4%|
[tor_exits](#tor_exits)|1111|1111|1111|100.0%|1.3%|
[stopforumspam_1d](#stopforumspam_1d)|6683|6683|946|14.1%|1.1%|
[blocklist_de](#blocklist_de)|28132|28132|669|2.3%|0.8%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|663|100.0%|0.7%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|524|100.0%|0.6%|
[blocklist_de_bots](#blocklist_de_bots)|2960|2960|520|17.5%|0.6%|
[sorbs_spam](#sorbs_spam)|64701|65536|202|0.3%|0.2%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|202|0.3%|0.2%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|202|0.3%|0.2%|
[nixspam](#nixspam)|18244|18244|163|0.8%|0.1%|
[blocklist_de_mail](#blocklist_de_mail)|18158|18158|127|0.6%|0.1%|
[php_dictionary](#php_dictionary)|737|737|99|13.4%|0.1%|
[php_commenters](#php_commenters)|458|458|90|19.6%|0.1%|
[php_spammers](#php_spammers)|735|735|83|11.2%|0.0%|
[voipbl](#voipbl)|10586|10998|79|0.7%|0.0%|
[alienvault_reputation](#alienvault_reputation)|187341|187341|57|0.0%|0.0%|
[dragon_http](#dragon_http)|1021|268288|45|0.0%|0.0%|
[sorbs_web](#sorbs_web)|598|599|30|5.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|30|0.0%|0.0%|
[openbl_60d](#openbl_60d)|6974|6974|23|0.3%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14292|14292|20|0.1%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2846|2846|17|0.5%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|15|0.0%|0.0%|
[php_harvesters](#php_harvesters)|408|408|12|2.9%|0.0%|
[iw_spamlist](#iw_spamlist)|3889|3889|12|0.3%|0.0%|
[firehol_level1](#firehol_level1)|5137|688854747|9|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|169|169|9|5.3%|0.0%|
[et_block](#et_block)|1000|18343756|8|0.0%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|7|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|6|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|1586|1586|4|0.2%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|3|0.2%|0.0%|
[et_compromised](#et_compromised)|1704|1704|3|0.1%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1693|1693|3|0.1%|0.0%|
[dshield](#dshield)|20|5120|2|0.0%|0.0%|
[sslbl](#sslbl)|370|370|1|0.2%|0.0%|
[shunlist](#shunlist)|1172|1172|1|0.0%|0.0%|
[openbl_30d](#openbl_30d)|2803|2803|1|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2216|2216|1|0.0%|0.0%|

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
[et_block](#et_block)|1000|18343756|18340172|99.9%|2.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|8867717|2.5%|1.2%|
[firehol_level3](#firehol_level3)|109614|9627353|7500198|77.9%|1.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|7498240|81.6%|1.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|4637602|3.3%|0.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|2570562|0.3%|0.3%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|487424|100.0%|0.0%|
[dshield](#dshield)|20|5120|5120|100.0%|0.0%|
[alienvault_reputation](#alienvault_reputation)|187341|187341|4605|2.4%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1932|0.5%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|1111|1.1%|0.0%|
[dragon_http](#dragon_http)|1021|268288|1025|0.3%|0.0%|
[sslbl](#sslbl)|370|370|370|100.0%|0.0%|
[voipbl](#voipbl)|10586|10998|333|3.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9671|9671|300|3.1%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|291|1.0%|0.0%|
[firehol_level2](#firehol_level2)|21690|33293|290|0.8%|0.0%|
[openbl_60d](#openbl_60d)|6974|6974|253|3.6%|0.0%|
[zeus](#zeus)|230|230|230|100.0%|0.0%|
[blocklist_de](#blocklist_de)|28132|28132|222|0.7%|0.0%|
[zeus_badips](#zeus_badips)|202|202|202|100.0%|0.0%|
[shunlist](#shunlist)|1172|1172|159|13.5%|0.0%|
[openbl_30d](#openbl_30d)|2803|2803|135|4.8%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2216|2216|127|5.7%|0.0%|
[dragon_sshpauth](#dragon_sshpauth)|1613|1675|106|6.3%|0.0%|
[feodo](#feodo)|105|105|105|100.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6683|6683|92|1.3%|0.0%|
[et_compromised](#et_compromised)|1704|1704|71|4.1%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1693|1693|67|3.9%|0.0%|
[nixspam](#nixspam)|18244|18244|65|0.3%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|2960|2960|61|2.0%|0.0%|
[openbl_7d](#openbl_7d)|633|633|59|9.3%|0.0%|
[php_commenters](#php_commenters)|458|458|39|8.5%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|39|3.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|39|2.6%|0.0%|
[sorbs_spam](#sorbs_spam)|64701|65536|25|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|25|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|25|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|18158|18158|24|0.1%|0.0%|
[openbl_1d](#openbl_1d)|140|140|23|16.4%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|169|169|20|11.8%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|18|0.0%|0.0%|
[palevo](#palevo)|13|13|13|100.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2800|2800|10|0.3%|0.0%|
[iw_spamlist](#iw_spamlist)|3889|3889|9|0.2%|0.0%|
[firehol_anonymous](#firehol_anonymous)|19227|83278|9|0.0%|0.0%|
[nt_malware_http](#nt_malware_http)|69|69|8|11.5%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14292|14292|7|0.0%|0.0%|
[php_dictionary](#php_dictionary)|737|737|6|0.8%|0.0%|
[ciarmy](#ciarmy)|397|397|6|1.5%|0.0%|
[malc0de](#malc0de)|276|276|5|1.8%|0.0%|
[firehol_proxies](#firehol_proxies)|12738|13016|5|0.0%|0.0%|
[et_tor](#et_tor)|6500|6500|5|0.0%|0.0%|
[dm_tor](#dm_tor)|6407|6407|5|0.0%|0.0%|
[bm_tor](#bm_tor)|6428|6428|5|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2846|2846|5|0.1%|0.0%|
[php_spammers](#php_spammers)|735|735|4|0.5%|0.0%|
[tor_exits](#tor_exits)|1111|1111|3|0.2%|0.0%|
[php_harvesters](#php_harvesters)|408|408|3|0.7%|0.0%|
[nt_malware_irc](#nt_malware_irc)|43|43|3|6.9%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|2|0.3%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|2|0.3%|0.0%|
[dragon_vncprobe](#dragon_vncprobe)|87|87|2|2.2%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|83|83|2|2.4%|0.0%|
[virbl](#virbl)|23|23|1|4.3%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7870|7870|1|0.0%|0.0%|
[et_botcc](#et_botcc)|505|505|1|0.1%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|1586|1586|1|0.0%|0.0%|

## firehol_level2

**FireHOL Level 2** - Maximum protection from attacks took place in the last 48 hours. (includes: openbl_1d blocklist_de stopforumspam_1d)

Source is downloaded from [this link]().

The last time downloaded was found to be dated: Sun Jun  7 22:20:34 UTC 2015.

The ipset `firehol_level2` has **21690** entries, **33293** unique IPs.

The following table shows the overlaps of `firehol_level2` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `firehol_level2`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `firehol_level2`.
- ` this % ` is the percentage **of this ipset (`firehol_level2`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|28132|28132|28132|100.0%|84.4%|
[blocklist_de_mail](#blocklist_de_mail)|18158|18158|18158|100.0%|54.5%|
[blocklist_de_apache](#blocklist_de_apache)|14292|14292|14226|99.5%|42.7%|
[firehol_level3](#firehol_level3)|109614|9627353|7590|0.0%|22.7%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|7415|25.5%|22.2%|
[stopforumspam_1d](#stopforumspam_1d)|6683|6683|6683|100.0%|20.0%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|6463|6.8%|19.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|3769|0.0%|11.3%|
[blocklist_de_bots](#blocklist_de_bots)|2960|2960|2959|99.9%|8.8%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2846|2846|2846|100.0%|8.5%|
[blocklist_de_imap](#blocklist_de_imap)|2800|2800|2800|100.0%|8.4%|
[blocklist_de_ssh](#blocklist_de_ssh)|2216|2216|2216|100.0%|6.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|1697|0.0%|5.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|1663|0.0%|4.9%|
[blocklist_de_ftp](#blocklist_de_ftp)|1586|1586|1586|100.0%|4.7%|
[sorbs_spam](#sorbs_spam)|64701|65536|1326|2.0%|3.9%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|1318|2.0%|3.9%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|1318|2.0%|3.9%|
[firehol_anonymous](#firehol_anonymous)|19227|83278|1298|1.5%|3.8%|
[alienvault_reputation](#alienvault_reputation)|187341|187341|1154|0.6%|3.4%|
[firehol_proxies](#firehol_proxies)|12738|13016|1152|8.8%|3.4%|
[openbl_60d](#openbl_60d)|6974|6974|802|11.4%|2.4%|
[dragon_sshpauth](#dragon_sshpauth)|1613|1675|674|40.2%|2.0%|
[openbl_30d](#openbl_30d)|2803|2803|666|23.7%|2.0%|
[ri_web_proxies](#ri_web_proxies)|7870|7870|648|8.2%|1.9%|
[nixspam](#nixspam)|18244|18244|581|3.1%|1.7%|
[bruteforceblocker](#bruteforceblocker)|1693|1693|572|33.7%|1.7%|
[et_compromised](#et_compromised)|1704|1704|556|32.6%|1.6%|
[snort_ipfilter](#snort_ipfilter)|9671|9671|515|5.3%|1.5%|
[proxyrss](#proxyrss)|1738|1738|402|23.1%|1.2%|
[openbl_7d](#openbl_7d)|633|633|387|61.1%|1.1%|
[shunlist](#shunlist)|1172|1172|368|31.3%|1.1%|
[tor_exits](#tor_exits)|1111|1111|314|28.2%|0.9%|
[xroxy](#xroxy)|2171|2171|312|14.3%|0.9%|
[et_tor](#et_tor)|6500|6500|306|4.7%|0.9%|
[dm_tor](#dm_tor)|6407|6407|295|4.6%|0.8%|
[bm_tor](#bm_tor)|6428|6428|295|4.5%|0.8%|
[firehol_level1](#firehol_level1)|5137|688854747|290|0.0%|0.8%|
[et_block](#et_block)|1000|18343756|279|0.0%|0.8%|
[proxz](#proxz)|1339|1339|274|20.4%|0.8%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|258|0.0%|0.7%|
[php_commenters](#php_commenters)|458|458|196|42.7%|0.5%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|196|37.4%|0.5%|
[blocklist_de_strongips](#blocklist_de_strongips)|169|169|169|100.0%|0.5%|
[ri_connect_proxies](#ri_connect_proxies)|2828|2828|142|5.0%|0.4%|
[openbl_1d](#openbl_1d)|140|140|140|100.0%|0.4%|
[iw_spamlist](#iw_spamlist)|3889|3889|137|3.5%|0.4%|
[php_dictionary](#php_dictionary)|737|737|125|16.9%|0.3%|
[php_spammers](#php_spammers)|735|735|118|16.0%|0.3%|
[dshield](#dshield)|20|5120|93|1.8%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|86|0.0%|0.2%|
[sorbs_web](#sorbs_web)|598|599|69|11.5%|0.2%|
[dragon_http](#dragon_http)|1021|268288|64|0.0%|0.1%|
[blocklist_de_sip](#blocklist_de_sip)|83|83|64|77.1%|0.1%|
[php_harvesters](#php_harvesters)|408|408|58|14.2%|0.1%|
[voipbl](#voipbl)|10586|10998|43|0.3%|0.1%|
[ciarmy](#ciarmy)|397|397|36|9.0%|0.1%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|16|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|14|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|8|1.2%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|7|0.0%|0.0%|
[dragon_vncprobe](#dragon_vncprobe)|87|87|5|5.7%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|3|0.2%|0.0%|
[zeus_badips](#zeus_badips)|202|202|1|0.4%|0.0%|
[zeus](#zeus)|230|230|1|0.4%|0.0%|
[sorbs_socks](#sorbs_socks)|7|7|1|14.2%|0.0%|
[sorbs_misc](#sorbs_misc)|7|7|1|14.2%|0.0%|
[sorbs_http](#sorbs_http)|7|7|1|14.2%|0.0%|
[iw_wormlist](#iw_wormlist)|35|35|1|2.8%|0.0%|
[fullbogons](#fullbogons)|3775|670173256|1|0.0%|0.0%|

## firehol_level3

**FireHOL Level 3** - All the bad IPs in last 30 days. (includes: openbl_30d stopforumspam_30d virbl malc0de shunlist malwaredomainlist bruteforceblocker ciarmy cleanmx_viruses snort_ipfilter ib_bluetack_spyware ib_bluetack_hijacked ib_bluetack_webexploit php_commenters php_dictionary php_harvesters php_spammers iw_wormlist)

Source is downloaded from [this link]().

The last time downloaded was found to be dated: Sun Jun  7 22:20:34 UTC 2015.

The ipset `firehol_level3` has **109614** entries, **9627353** unique IPs.

The following table shows the overlaps of `firehol_level3` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `firehol_level3`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `firehol_level3`.
- ` this % ` is the percentage **of this ipset (`firehol_level3`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|9177856|100.0%|95.3%|
[firehol_level1](#firehol_level1)|5137|688854747|7500198|1.0%|77.9%|
[et_block](#et_block)|1000|18343756|6933353|37.7%|72.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|6933039|37.8%|72.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|2537252|0.7%|26.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|919953|0.1%|9.5%|
[fullbogons](#fullbogons)|3775|670173256|566692|0.0%|5.8%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|339173|100.0%|3.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|161551|0.1%|1.6%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|94309|100.0%|0.9%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|27642|95.2%|0.2%|
[snort_ipfilter](#snort_ipfilter)|9671|9671|9671|100.0%|0.1%|
[firehol_level2](#firehol_level2)|21690|33293|7590|22.7%|0.0%|
[firehol_anonymous](#firehol_anonymous)|19227|83278|6812|8.1%|0.0%|
[firehol_proxies](#firehol_proxies)|12738|13016|5703|43.8%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6683|6683|5168|77.3%|0.0%|
[alienvault_reputation](#alienvault_reputation)|187341|187341|4813|2.5%|0.0%|
[blocklist_de](#blocklist_de)|28132|28132|3799|13.5%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7870|7870|3745|47.5%|0.0%|
[openbl_60d](#openbl_60d)|6974|6974|2929|41.9%|0.0%|
[openbl_30d](#openbl_30d)|2803|2803|2803|100.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|2960|2960|2382|80.4%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1693|1693|1693|100.0%|0.0%|
[et_compromised](#et_compromised)|1704|1704|1678|98.4%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2828|2828|1586|56.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|1450|100.0%|0.0%|
[xroxy](#xroxy)|2171|2171|1301|59.9%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|1288|100.0%|0.0%|
[sorbs_spam](#sorbs_spam)|64701|65536|1254|1.9%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|1252|1.9%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|1252|1.9%|0.0%|
[shunlist](#shunlist)|1172|1172|1172|100.0%|0.0%|
[et_tor](#et_tor)|6500|6500|1127|17.3%|0.0%|
[bm_tor](#bm_tor)|6428|6428|1085|16.8%|0.0%|
[dm_tor](#dm_tor)|6407|6407|1077|16.8%|0.0%|
[tor_exits](#tor_exits)|1111|1111|1072|96.4%|0.0%|
[dragon_sshpauth](#dragon_sshpauth)|1613|1675|867|51.7%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2216|2216|845|38.1%|0.0%|
[proxz](#proxz)|1339|1339|792|59.1%|0.0%|
[proxyrss](#proxyrss)|1738|1738|758|43.6%|0.0%|
[php_dictionary](#php_dictionary)|737|737|737|100.0%|0.0%|
[php_spammers](#php_spammers)|735|735|735|100.0%|0.0%|
[openbl_7d](#openbl_7d)|633|633|633|100.0%|0.0%|
[dragon_http](#dragon_http)|1021|268288|557|0.2%|0.0%|
[php_commenters](#php_commenters)|458|458|458|100.0%|0.0%|
[nixspam](#nixspam)|18244|18244|428|2.3%|0.0%|
[php_harvesters](#php_harvesters)|408|408|408|100.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|18158|18158|404|2.2%|0.0%|
[ciarmy](#ciarmy)|397|397|397|100.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|346|66.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14292|14292|281|1.9%|0.0%|
[malc0de](#malc0de)|276|276|276|100.0%|0.0%|
[zeus](#zeus)|230|230|203|88.2%|0.0%|
[zeus_badips](#zeus_badips)|202|202|180|89.1%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|169|169|156|92.3%|0.0%|
[openbl_1d](#openbl_1d)|140|140|139|99.2%|0.0%|
[dshield](#dshield)|20|5120|124|2.4%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|121|121|121|100.0%|0.0%|
[sslbl](#sslbl)|370|370|89|24.0%|0.0%|
[iw_spamlist](#iw_spamlist)|3889|3889|88|2.2%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|85|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2846|2846|84|2.9%|0.0%|
[feodo](#feodo)|105|105|83|79.0%|0.0%|
[sorbs_web](#sorbs_web)|598|599|73|12.1%|0.0%|
[voipbl](#voipbl)|10586|10998|57|0.5%|0.0%|
[iw_wormlist](#iw_wormlist)|35|35|35|100.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2800|2800|35|1.2%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|25|3.7%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|25|0.0%|0.0%|
[virbl](#virbl)|23|23|23|100.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|1586|1586|22|1.3%|0.0%|
[palevo](#palevo)|13|13|11|84.6%|0.0%|
[dragon_vncprobe](#dragon_vncprobe)|87|87|5|5.7%|0.0%|
[sorbs_socks](#sorbs_socks)|7|7|4|57.1%|0.0%|
[sorbs_misc](#sorbs_misc)|7|7|4|57.1%|0.0%|
[sorbs_http](#sorbs_http)|7|7|4|57.1%|0.0%|
[nt_malware_http](#nt_malware_http)|69|69|3|4.3%|0.0%|
[et_botcc](#et_botcc)|505|505|3|0.5%|0.0%|
[bogons](#bogons)|13|592708608|3|0.0%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|83|83|3|3.6%|0.0%|
[nt_malware_irc](#nt_malware_irc)|43|43|1|2.3%|0.0%|

## firehol_proxies

**FireHOL Proxies** - Known open proxies in the last 30 days. (includes: ib_bluetack_proxies maxmind_proxy_fraud proxyrss proxz ri_connect_proxies ri_web_proxies xroxy)

Source is downloaded from [this link]().

The last time downloaded was found to be dated: Sun Jun  7 22:20:34 UTC 2015.

The ipset `firehol_proxies` has **12738** entries, **13016** unique IPs.

The following table shows the overlaps of `firehol_proxies` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `firehol_proxies`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `firehol_proxies`.
- ` this % ` is the percentage **of this ipset (`firehol_proxies`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_anonymous](#firehol_anonymous)|19227|83278|13016|15.6%|100.0%|
[ri_web_proxies](#ri_web_proxies)|7870|7870|7870|100.0%|60.4%|
[firehol_level3](#firehol_level3)|109614|9627353|5703|0.0%|43.8%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|5636|5.9%|43.3%|
[ri_connect_proxies](#ri_connect_proxies)|2828|2828|2828|100.0%|21.7%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|2384|8.2%|18.3%|
[xroxy](#xroxy)|2171|2171|2171|100.0%|16.6%|
[proxyrss](#proxyrss)|1738|1738|1738|100.0%|13.3%|
[proxz](#proxz)|1339|1339|1339|100.0%|10.2%|
[firehol_level2](#firehol_level2)|21690|33293|1152|3.4%|8.8%|
[stopforumspam_1d](#stopforumspam_1d)|6683|6683|816|12.2%|6.2%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|663|100.0%|5.0%|
[blocklist_de](#blocklist_de)|28132|28132|646|2.2%|4.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|529|0.0%|4.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|524|100.0%|4.0%|
[blocklist_de_bots](#blocklist_de_bots)|2960|2960|519|17.5%|3.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|392|0.0%|3.0%|
[snort_ipfilter](#snort_ipfilter)|9671|9671|330|3.4%|2.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|292|0.0%|2.2%|
[et_tor](#et_tor)|6500|6500|238|3.6%|1.8%|
[dm_tor](#dm_tor)|6407|6407|234|3.6%|1.7%|
[bm_tor](#bm_tor)|6428|6428|234|3.6%|1.7%|
[tor_exits](#tor_exits)|1111|1111|230|20.7%|1.7%|
[sorbs_spam](#sorbs_spam)|64701|65536|197|0.3%|1.5%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|197|0.3%|1.5%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|197|0.3%|1.5%|
[nixspam](#nixspam)|18244|18244|157|0.8%|1.2%|
[blocklist_de_mail](#blocklist_de_mail)|18158|18158|125|0.6%|0.9%|
[php_dictionary](#php_dictionary)|737|737|98|13.2%|0.7%|
[php_commenters](#php_commenters)|458|458|86|18.7%|0.6%|
[php_spammers](#php_spammers)|735|735|81|11.0%|0.6%|
[alienvault_reputation](#alienvault_reputation)|187341|187341|38|0.0%|0.2%|
[dragon_http](#dragon_http)|1021|268288|32|0.0%|0.2%|
[sorbs_web](#sorbs_web)|598|599|30|5.0%|0.2%|
[openbl_60d](#openbl_60d)|6974|6974|20|0.2%|0.1%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|15|0.0%|0.1%|
[php_harvesters](#php_harvesters)|408|408|12|2.9%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|12|0.0%|0.0%|
[iw_spamlist](#iw_spamlist)|3889|3889|11|0.2%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|169|169|9|5.3%|0.0%|
[firehol_level1](#firehol_level1)|5137|688854747|5|0.0%|0.0%|
[et_block](#et_block)|1000|18343756|4|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|3|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|3|0.2%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|0.0%|
[et_compromised](#et_compromised)|1704|1704|3|0.1%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1693|1693|3|0.1%|0.0%|
[voipbl](#voipbl)|10586|10998|2|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14292|14292|2|0.0%|0.0%|
[sslbl](#sslbl)|370|370|1|0.2%|0.0%|
[shunlist](#shunlist)|1172|1172|1|0.0%|0.0%|
[dshield](#dshield)|20|5120|1|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2216|2216|1|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2846|2846|1|0.0%|0.0%|

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
[firehol_level3](#firehol_level3)|109614|9627353|566692|5.8%|0.0%|
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
[iw_spamlist](#iw_spamlist)|3889|3889|5|0.1%|0.0%|
[nt_malware_http](#nt_malware_http)|69|69|4|5.7%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|2|0.0%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|2|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6683|6683|1|0.0%|0.0%|
[php_harvesters](#php_harvesters)|408|408|1|0.2%|0.0%|
[php_commenters](#php_commenters)|458|458|1|0.2%|0.0%|
[firehol_level2](#firehol_level2)|21690|33293|1|0.0%|0.0%|
[ciarmy](#ciarmy)|397|397|1|0.2%|0.0%|

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
[firehol_level3](#firehol_level3)|109614|9627353|25|0.0%|0.0%|
[dragon_http](#dragon_http)|1021|268288|25|0.0%|0.0%|
[firehol_level1](#firehol_level1)|5137|688854747|18|0.0%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|17|0.0%|0.0%|
[sorbs_spam](#sorbs_spam)|64701|65536|17|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|17|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|17|0.0%|0.0%|
[firehol_level2](#firehol_level2)|21690|33293|16|0.0%|0.0%|
[firehol_proxies](#firehol_proxies)|12738|13016|15|0.1%|0.0%|
[firehol_anonymous](#firehol_anonymous)|19227|83278|15|0.0%|0.0%|
[blocklist_de](#blocklist_de)|28132|28132|15|0.0%|0.0%|
[alienvault_reputation](#alienvault_reputation)|187341|187341|15|0.0%|0.0%|
[fullbogons](#fullbogons)|3775|670173256|13|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|11|1.6%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|18158|18158|10|0.0%|0.0%|
[nixspam](#nixspam)|18244|18244|8|0.0%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|7|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|5|0.0%|0.0%|
[et_block](#et_block)|1000|18343756|5|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7870|7870|4|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2800|2800|4|0.1%|0.0%|
[xroxy](#xroxy)|2171|2171|3|0.1%|0.0%|
[php_dictionary](#php_dictionary)|737|737|3|0.4%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|3|0.0%|0.0%|
[voipbl](#voipbl)|10586|10998|2|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6683|6683|2|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9671|9671|2|0.0%|0.0%|
[php_harvesters](#php_harvesters)|408|408|2|0.4%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|1586|1586|2|0.1%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2846|2846|2|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14292|14292|2|0.0%|0.0%|
[sorbs_web](#sorbs_web)|598|599|1|0.1%|0.0%|
[proxz](#proxz)|1339|1339|1|0.0%|0.0%|
[php_spammers](#php_spammers)|735|735|1|0.1%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|1|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2216|2216|1|0.0%|0.0%|

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
[firehol_level3](#firehol_level3)|109614|9627353|9177856|95.3%|100.0%|
[firehol_level1](#firehol_level1)|5137|688854747|7498240|1.0%|81.6%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|6932480|37.7%|75.5%|
[et_block](#et_block)|1000|18343756|6932480|37.7%|75.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|2526625|0.7%|27.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|904796|0.1%|9.8%|
[fullbogons](#fullbogons)|3775|670173256|565760|0.0%|6.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|145472|0.1%|1.5%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1036|0.3%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|725|0.7%|0.0%|
[alienvault_reputation](#alienvault_reputation)|187341|187341|278|0.1%|0.0%|
[dragon_http](#dragon_http)|1021|268288|256|0.0%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|154|0.5%|0.0%|
[firehol_level2](#firehol_level2)|21690|33293|86|0.2%|0.0%|
[nixspam](#nixspam)|18244|18244|60|0.3%|0.0%|
[blocklist_de](#blocklist_de)|28132|28132|58|0.2%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|2960|2960|46|1.5%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6683|6683|31|0.4%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|27|2.0%|0.0%|
[openbl_60d](#openbl_60d)|6974|6974|16|0.2%|0.0%|
[openbl_30d](#openbl_30d)|2803|2803|12|0.4%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9671|9671|11|0.1%|0.0%|
[zeus_badips](#zeus_badips)|202|202|10|4.9%|0.0%|
[zeus](#zeus)|230|230|10|4.3%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|7|0.4%|0.0%|
[firehol_anonymous](#firehol_anonymous)|19227|83278|7|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2216|2216|7|0.3%|0.0%|
[et_compromised](#et_compromised)|1704|1704|5|0.2%|0.0%|
[dragon_sshpauth](#dragon_sshpauth)|1613|1675|5|0.2%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1693|1693|5|0.2%|0.0%|
[php_dictionary](#php_dictionary)|737|737|4|0.5%|0.0%|
[openbl_7d](#openbl_7d)|633|633|4|0.6%|0.0%|
[et_tor](#et_tor)|6500|6500|4|0.0%|0.0%|
[dm_tor](#dm_tor)|6407|6407|4|0.0%|0.0%|
[bm_tor](#bm_tor)|6428|6428|4|0.0%|0.0%|
[php_spammers](#php_spammers)|735|735|3|0.4%|0.0%|
[openbl_1d](#openbl_1d)|140|140|3|2.1%|0.0%|
[nt_malware_http](#nt_malware_http)|69|69|3|4.3%|0.0%|
[iw_spamlist](#iw_spamlist)|3889|3889|3|0.0%|0.0%|
[firehol_proxies](#firehol_proxies)|12738|13016|3|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|169|169|3|1.7%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|18158|18158|3|0.0%|0.0%|
[tor_exits](#tor_exits)|1111|1111|2|0.1%|0.0%|
[shunlist](#shunlist)|1172|1172|2|0.1%|0.0%|
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
[dragon_vncprobe](#dragon_vncprobe)|87|87|1|1.1%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2800|2800|1|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|1586|1586|1|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2846|2846|1|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14292|14292|1|0.0%|0.0%|

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
[firehol_level3](#firehol_level3)|109614|9627353|919953|9.5%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|904796|9.8%|0.1%|
[fullbogons](#fullbogons)|3775|670173256|264873|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|33155|6.8%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|13247|3.9%|0.0%|
[dragon_http](#dragon_http)|1021|268288|5989|2.2%|0.0%|
[alienvault_reputation](#alienvault_reputation)|187341|187341|4185|2.2%|0.0%|
[firehol_anonymous](#firehol_anonymous)|19227|83278|3446|4.1%|0.0%|
[firehol_level2](#firehol_level2)|21690|33293|1697|5.0%|0.0%|
[blocklist_de](#blocklist_de)|28132|28132|1599|5.6%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|1522|1.6%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|18158|18158|1431|7.8%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14292|14292|1323|9.2%|0.0%|
[sorbs_spam](#sorbs_spam)|64701|65536|1208|1.8%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|1205|1.8%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|1205|1.8%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|510|1.7%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|394|0.8%|0.0%|
[nixspam](#nixspam)|18244|18244|348|1.9%|0.0%|
[voipbl](#voipbl)|10586|10998|302|2.7%|0.0%|
[firehol_proxies](#firehol_proxies)|12738|13016|292|2.2%|0.0%|
[dshield](#dshield)|20|5120|256|5.0%|0.0%|
[dm_tor](#dm_tor)|6407|6407|169|2.6%|0.0%|
[et_tor](#et_tor)|6500|6500|168|2.5%|0.0%|
[bm_tor](#bm_tor)|6428|6428|168|2.6%|0.0%|
[openbl_60d](#openbl_60d)|6974|6974|163|2.3%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7870|7870|156|1.9%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6683|6683|126|1.8%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9671|9671|116|1.1%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|97|6.6%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2828|2828|86|3.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2800|2800|80|2.8%|0.0%|
[iw_spamlist](#iw_spamlist)|3889|3889|70|1.7%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|66|5.1%|0.0%|
[openbl_30d](#openbl_30d)|2803|2803|65|2.3%|0.0%|
[xroxy](#xroxy)|2171|2171|58|2.6%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|56|8.4%|0.0%|
[et_compromised](#et_compromised)|1704|1704|54|3.1%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1693|1693|54|3.1%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|2960|2960|50|1.6%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2216|2216|47|2.1%|0.0%|
[proxz](#proxz)|1339|1339|44|3.2%|0.0%|
[et_botcc](#et_botcc)|505|505|39|7.7%|0.0%|
[tor_exits](#tor_exits)|1111|1111|37|3.3%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2846|2846|36|1.2%|0.0%|
[dragon_sshpauth](#dragon_sshpauth)|1613|1675|32|1.9%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|1586|1586|28|1.7%|0.0%|
[proxyrss](#proxyrss)|1738|1738|26|1.4%|0.0%|
[shunlist](#shunlist)|1172|1172|25|2.1%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|21|4.0%|0.0%|
[ciarmy](#ciarmy)|397|397|20|5.0%|0.0%|
[sorbs_web](#sorbs_web)|598|599|15|2.5%|0.0%|
[openbl_7d](#openbl_7d)|633|633|14|2.2%|0.0%|
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
[sslbl](#sslbl)|370|370|3|0.8%|0.0%|
[feodo](#feodo)|105|105|3|2.8%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|83|83|3|3.6%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|121|121|2|1.6%|0.0%|
[openbl_1d](#openbl_1d)|140|140|1|0.7%|0.0%|
[iw_wormlist](#iw_wormlist)|35|35|1|2.8%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|169|169|1|0.5%|0.0%|

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
[firehol_level1](#firehol_level1)|5137|688854747|8867717|1.2%|2.5%|
[et_block](#et_block)|1000|18343756|8532776|46.5%|2.4%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|8532506|46.5%|2.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|2830203|2.0%|0.8%|
[firehol_level3](#firehol_level3)|109614|9627353|2537252|26.3%|0.7%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2526625|27.5%|0.7%|
[fullbogons](#fullbogons)|3775|670173256|252671|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|98904|20.2%|0.0%|
[dragon_http](#dragon_http)|1021|268288|11992|4.4%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|7728|2.2%|0.0%|
[alienvault_reputation](#alienvault_reputation)|187341|187341|7251|3.8%|0.0%|
[firehol_anonymous](#firehol_anonymous)|19227|83278|2898|3.4%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|2476|2.6%|0.0%|
[sorbs_spam](#sorbs_spam)|64701|65536|1740|2.6%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|1736|2.6%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|1736|2.6%|0.0%|
[firehol_level2](#firehol_level2)|21690|33293|1663|4.9%|0.0%|
[blocklist_de](#blocklist_de)|28132|28132|1526|5.4%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|18158|18158|1262|6.9%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14292|14292|1084|7.5%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|736|2.5%|0.0%|
[nixspam](#nixspam)|18244|18244|511|2.8%|0.0%|
[voipbl](#voipbl)|10586|10998|436|3.9%|0.0%|
[firehol_proxies](#firehol_proxies)|12738|13016|392|3.0%|0.0%|
[openbl_60d](#openbl_60d)|6974|6974|319|4.5%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|226|0.4%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7870|7870|224|2.8%|0.0%|
[dm_tor](#dm_tor)|6407|6407|187|2.9%|0.0%|
[bm_tor](#bm_tor)|6428|6428|186|2.8%|0.0%|
[et_tor](#et_tor)|6500|6500|182|2.8%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6683|6683|180|2.6%|0.0%|
[openbl_30d](#openbl_30d)|2803|2803|146|5.2%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9671|9671|138|1.4%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2216|2216|109|4.9%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2828|2828|106|3.7%|0.0%|
[xroxy](#xroxy)|2171|2171|104|4.7%|0.0%|
[iw_spamlist](#iw_spamlist)|3889|3889|95|2.4%|0.0%|
[et_compromised](#et_compromised)|1704|1704|89|5.2%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1693|1693|87|5.1%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|2960|2960|77|2.6%|0.0%|
[dragon_sshpauth](#dragon_sshpauth)|1613|1675|72|4.2%|0.0%|
[shunlist](#shunlist)|1172|1172|69|5.8%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2800|2800|67|2.3%|0.0%|
[proxyrss](#proxyrss)|1738|1738|62|3.5%|0.0%|
[proxz](#proxz)|1339|1339|56|4.1%|0.0%|
[php_spammers](#php_spammers)|735|735|54|7.3%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2846|2846|46|1.6%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|45|3.1%|0.0%|
[tor_exits](#tor_exits)|1111|1111|40|3.6%|0.0%|
[openbl_7d](#openbl_7d)|633|633|38|6.0%|0.0%|
[ciarmy](#ciarmy)|397|397|31|7.8%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|29|5.5%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|26|2.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|26|3.9%|0.0%|
[sorbs_web](#sorbs_web)|598|599|23|3.8%|0.0%|
[php_dictionary](#php_dictionary)|737|737|23|3.1%|0.0%|
[et_botcc](#et_botcc)|505|505|22|4.3%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|1586|1586|21|1.3%|0.0%|
[php_commenters](#php_commenters)|458|458|19|4.1%|0.0%|
[malc0de](#malc0de)|276|276|16|5.7%|0.0%|
[zeus](#zeus)|230|230|9|3.9%|0.0%|
[php_harvesters](#php_harvesters)|408|408|9|2.2%|0.0%|
[zeus_badips](#zeus_badips)|202|202|8|3.9%|0.0%|
[dragon_vncprobe](#dragon_vncprobe)|87|87|7|8.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|169|169|7|4.1%|0.0%|
[sslbl](#sslbl)|370|370|6|1.6%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|121|121|6|4.9%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|83|83|5|6.0%|0.0%|
[palevo](#palevo)|13|13|3|23.0%|0.0%|
[openbl_1d](#openbl_1d)|140|140|3|2.1%|0.0%|
[feodo](#feodo)|105|105|3|2.8%|0.0%|
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
[firehol_level3](#firehol_level3)|109614|9627353|161551|1.6%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|145472|1.5%|0.1%|
[et_block](#et_block)|1000|18343756|130650|0.7%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|130368|0.7%|0.0%|
[dragon_http](#dragon_http)|1021|268288|20480|7.6%|0.0%|
[alienvault_reputation](#alienvault_reputation)|187341|187341|14084|7.5%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|9226|2.7%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|5830|6.1%|0.0%|
[firehol_level2](#firehol_level2)|21690|33293|3769|11.3%|0.0%|
[blocklist_de](#blocklist_de)|28132|28132|3362|11.9%|0.0%|
[firehol_anonymous](#firehol_anonymous)|19227|83278|2880|3.4%|0.0%|
[sorbs_spam](#sorbs_spam)|64701|65536|2860|4.3%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|2851|4.3%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|2851|4.3%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|18158|18158|2593|14.2%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14292|14292|2308|16.1%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|1961|6.7%|0.0%|
[voipbl](#voipbl)|10586|10998|1613|14.6%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|1172|2.4%|0.0%|
[nixspam](#nixspam)|18244|18244|837|4.5%|0.0%|
[openbl_60d](#openbl_60d)|6974|6974|741|10.6%|0.0%|
[et_tor](#et_tor)|6500|6500|636|9.7%|0.0%|
[bm_tor](#bm_tor)|6428|6428|632|9.8%|0.0%|
[dm_tor](#dm_tor)|6407|6407|629|9.8%|0.0%|
[firehol_proxies](#firehol_proxies)|12738|13016|529|4.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6683|6683|516|7.7%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2800|2800|294|10.5%|0.0%|
[openbl_30d](#openbl_30d)|2803|2803|285|10.1%|0.0%|
[iw_spamlist](#iw_spamlist)|3889|3889|268|6.8%|0.0%|
[dshield](#dshield)|20|5120|256|5.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9671|9671|241|2.4%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2216|2216|223|10.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7870|7870|220|2.7%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2846|2846|213|7.4%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|2960|2960|174|5.8%|0.0%|
[et_compromised](#et_compromised)|1704|1704|157|9.2%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1693|1693|156|9.2%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|150|28.6%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|147|11.4%|0.0%|
[dragon_sshpauth](#dragon_sshpauth)|1613|1675|127|7.5%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|1586|1586|127|8.0%|0.0%|
[tor_exits](#tor_exits)|1111|1111|126|11.3%|0.0%|
[shunlist](#shunlist)|1172|1172|118|10.0%|0.0%|
[xroxy](#xroxy)|2171|2171|111|5.1%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|108|7.4%|0.0%|
[proxz](#proxz)|1339|1339|105|7.8%|0.0%|
[et_botcc](#et_botcc)|505|505|76|15.0%|0.0%|
[ciarmy](#ciarmy)|397|397|69|17.3%|0.0%|
[openbl_7d](#openbl_7d)|633|633|65|10.2%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2828|2828|57|2.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|51|7.6%|0.0%|
[proxyrss](#proxyrss)|1738|1738|47|2.7%|0.0%|
[php_spammers](#php_spammers)|735|735|44|5.9%|0.0%|
[malc0de](#malc0de)|276|276|44|15.9%|0.0%|
[php_dictionary](#php_dictionary)|737|737|39|5.2%|0.0%|
[php_commenters](#php_commenters)|458|458|29|6.3%|0.0%|
[sslbl](#sslbl)|370|370|28|7.5%|0.0%|
[sorbs_web](#sorbs_web)|598|599|28|4.6%|0.0%|
[php_harvesters](#php_harvesters)|408|408|20|4.9%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|121|121|19|15.7%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|169|169|17|10.0%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|83|83|15|18.0%|0.0%|
[zeus](#zeus)|230|230|14|6.0%|0.0%|
[dragon_vncprobe](#dragon_vncprobe)|87|87|12|13.7%|0.0%|
[feodo](#feodo)|105|105|11|10.4%|0.0%|
[zeus_badips](#zeus_badips)|202|202|10|4.9%|0.0%|
[openbl_1d](#openbl_1d)|140|140|10|7.1%|0.0%|
[nt_malware_http](#nt_malware_http)|69|69|5|7.2%|0.0%|
[sorbs_socks](#sorbs_socks)|7|7|2|28.5%|0.0%|
[sorbs_misc](#sorbs_misc)|7|7|2|28.5%|0.0%|
[sorbs_http](#sorbs_http)|7|7|2|28.5%|0.0%|
[iw_wormlist](#iw_wormlist)|35|35|2|5.7%|0.0%|
[virbl](#virbl)|23|23|1|4.3%|0.0%|
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
[firehol_proxies](#firehol_proxies)|12738|13016|663|5.0%|100.0%|
[firehol_anonymous](#firehol_anonymous)|19227|83278|663|0.7%|100.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|56|0.0%|8.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|51|0.0%|7.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|26|0.0%|3.9%|
[firehol_level3](#firehol_level3)|109614|9627353|25|0.0%|3.7%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|20|0.0%|3.0%|
[ri_web_proxies](#ri_web_proxies)|7870|7870|15|0.1%|2.2%|
[xroxy](#xroxy)|2171|2171|13|0.5%|1.9%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|11|0.0%|1.6%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|10|0.0%|1.5%|
[proxyrss](#proxyrss)|1738|1738|8|0.4%|1.2%|
[firehol_level2](#firehol_level2)|21690|33293|8|0.0%|1.2%|
[ri_connect_proxies](#ri_connect_proxies)|2828|2828|7|0.2%|1.0%|
[proxz](#proxz)|1339|1339|6|0.4%|0.9%|
[stopforumspam_1d](#stopforumspam_1d)|6683|6683|5|0.0%|0.7%|
[blocklist_de](#blocklist_de)|28132|28132|4|0.0%|0.6%|
[nixspam](#nixspam)|18244|18244|3|0.0%|0.4%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|2|0.0%|0.3%|
[php_dictionary](#php_dictionary)|737|737|2|0.2%|0.3%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|2|0.1%|0.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2|0.0%|0.3%|
[firehol_level1](#firehol_level1)|5137|688854747|2|0.0%|0.3%|
[et_block](#et_block)|1000|18343756|2|0.0%|0.3%|
[blocklist_de_mail](#blocklist_de_mail)|18158|18158|2|0.0%|0.3%|
[blocklist_de_bots](#blocklist_de_bots)|2960|2960|2|0.0%|0.3%|
[alienvault_reputation](#alienvault_reputation)|187341|187341|2|0.0%|0.3%|
[sorbs_spam](#sorbs_spam)|64701|65536|1|0.0%|0.1%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|1|0.0%|0.1%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|1|0.0%|0.1%|
[snort_ipfilter](#snort_ipfilter)|9671|9671|1|0.0%|0.1%|
[php_spammers](#php_spammers)|735|735|1|0.1%|0.1%|
[dragon_http](#dragon_http)|1021|268288|1|0.0%|0.1%|

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
[firehol_level3](#firehol_level3)|109614|9627353|339173|3.5%|100.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|13247|0.0%|3.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|9226|0.0%|2.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|7728|0.0%|2.2%|
[firehol_level1](#firehol_level1)|5137|688854747|1932|0.0%|0.5%|
[et_block](#et_block)|1000|18343756|1041|0.0%|0.3%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|1037|0.0%|0.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1036|0.0%|0.3%|
[fullbogons](#fullbogons)|3775|670173256|890|0.0%|0.2%|
[alienvault_reputation](#alienvault_reputation)|187341|187341|293|0.1%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|52|0.0%|0.0%|
[sorbs_spam](#sorbs_spam)|64701|65536|38|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|37|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|37|0.0%|0.0%|
[firehol_anonymous](#firehol_anonymous)|19227|83278|30|0.0%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|27|2.0%|0.0%|
[et_tor](#et_tor)|6500|6500|22|0.3%|0.0%|
[dm_tor](#dm_tor)|6407|6407|22|0.3%|0.0%|
[bm_tor](#bm_tor)|6428|6428|22|0.3%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|21|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|19|1.3%|0.0%|
[nixspam](#nixspam)|18244|18244|17|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9671|9671|14|0.1%|0.0%|
[firehol_level2](#firehol_level2)|21690|33293|14|0.0%|0.0%|
[firehol_proxies](#firehol_proxies)|12738|13016|12|0.0%|0.0%|
[tor_exits](#tor_exits)|1111|1111|8|0.7%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6683|6683|7|0.1%|0.0%|
[blocklist_de](#blocklist_de)|28132|28132|7|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7870|7870|6|0.0%|0.0%|
[dragon_http](#dragon_http)|1021|268288|6|0.0%|0.0%|
[openbl_60d](#openbl_60d)|6974|6974|5|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|5|0.9%|0.0%|
[voipbl](#voipbl)|10586|10998|4|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14292|14292|4|0.0%|0.0%|
[openbl_30d](#openbl_30d)|2803|2803|3|0.1%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|3|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2846|2846|3|0.1%|0.0%|
[proxyrss](#proxyrss)|1738|1738|2|0.1%|0.0%|
[palevo](#palevo)|13|13|2|15.3%|0.0%|
[malc0de](#malc0de)|276|276|2|0.7%|0.0%|
[iw_spamlist](#iw_spamlist)|3889|3889|2|0.0%|0.0%|
[et_compromised](#et_compromised)|1704|1704|2|0.1%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1693|1693|2|0.1%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|83|83|2|2.4%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|18158|18158|2|0.0%|0.0%|
[zeus_badips](#zeus_badips)|202|202|1|0.4%|0.0%|
[zeus](#zeus)|230|230|1|0.4%|0.0%|
[xroxy](#xroxy)|2171|2171|1|0.0%|0.0%|
[sslbl](#sslbl)|370|370|1|0.2%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|1|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2828|2828|1|0.0%|0.0%|
[proxz](#proxz)|1339|1339|1|0.0%|0.0%|
[php_harvesters](#php_harvesters)|408|408|1|0.2%|0.0%|
[php_dictionary](#php_dictionary)|737|737|1|0.1%|0.0%|
[php_commenters](#php_commenters)|458|458|1|0.2%|0.0%|
[nt_malware_http](#nt_malware_http)|69|69|1|1.4%|0.0%|
[feodo](#feodo)|105|105|1|0.9%|0.0%|
[bogons](#bogons)|13|592708608|1|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2216|2216|1|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|2960|2960|1|0.0%|0.0%|

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
[firehol_level3](#firehol_level3)|109614|9627353|1450|0.0%|100.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|108|0.0%|7.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|97|0.0%|6.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|45|0.0%|3.1%|
[firehol_level1](#firehol_level1)|5137|688854747|39|0.0%|2.6%|
[fullbogons](#fullbogons)|3775|670173256|33|0.0%|2.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|19|0.0%|1.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|7|0.0%|0.4%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|6|0.0%|0.4%|
[et_block](#et_block)|1000|18343756|6|0.0%|0.4%|
[alienvault_reputation](#alienvault_reputation)|187341|187341|6|0.0%|0.4%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|3|0.2%|0.2%|
[firehol_proxies](#firehol_proxies)|12738|13016|3|0.0%|0.2%|
[firehol_level2](#firehol_level2)|21690|33293|3|0.0%|0.2%|
[firehol_anonymous](#firehol_anonymous)|19227|83278|3|0.0%|0.2%|
[blocklist_de](#blocklist_de)|28132|28132|3|0.0%|0.2%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|2|0.0%|0.1%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|2|0.0%|0.1%|
[sorbs_spam](#sorbs_spam)|64701|65536|2|0.0%|0.1%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|2|0.0%|0.1%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|2|0.0%|0.1%|
[openbl_60d](#openbl_60d)|6974|6974|2|0.0%|0.1%|
[openbl_30d](#openbl_30d)|2803|2803|2|0.0%|0.1%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|2|0.3%|0.1%|
[dragon_http](#dragon_http)|1021|268288|2|0.0%|0.1%|
[blocklist_de_strongips](#blocklist_de_strongips)|169|169|2|1.1%|0.1%|
[blocklist_de_bots](#blocklist_de_bots)|2960|2960|2|0.0%|0.1%|
[snort_ipfilter](#snort_ipfilter)|9671|9671|1|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7870|7870|1|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|1|0.0%|0.0%|
[et_botcc](#et_botcc)|505|505|1|0.1%|0.0%|
[dragon_sshpauth](#dragon_sshpauth)|1613|1675|1|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2216|2216|1|0.0%|0.0%|

## iw_spamlist

[ImproWare Antispam](http://antispam.imp.ch/) IPs sending spam, in the last 3 days

Source is downloaded from [this link](http://antispam.imp.ch/spamlist).

The last time downloaded was found to be dated: Fri Jun 12 03:20:04 UTC 2015.

The ipset `iw_spamlist` has **3889** entries, **3889** unique IPs.

The following table shows the overlaps of `iw_spamlist` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `iw_spamlist`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `iw_spamlist`.
- ` this % ` is the percentage **of this ipset (`iw_spamlist`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[sorbs_spam](#sorbs_spam)|64701|65536|1182|1.8%|30.3%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|1176|1.8%|30.2%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|1176|1.8%|30.2%|
[nixspam](#nixspam)|18244|18244|566|3.1%|14.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|268|0.0%|6.8%|
[firehol_level2](#firehol_level2)|21690|33293|137|0.4%|3.5%|
[blocklist_de](#blocklist_de)|28132|28132|135|0.4%|3.4%|
[blocklist_de_mail](#blocklist_de_mail)|18158|18158|123|0.6%|3.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|95|0.0%|2.4%|
[firehol_level3](#firehol_level3)|109614|9627353|88|0.0%|2.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|70|0.0%|1.7%|
[snort_ipfilter](#snort_ipfilter)|9671|9671|49|0.5%|1.2%|
[sorbs_web](#sorbs_web)|598|599|26|4.3%|0.6%|
[alienvault_reputation](#alienvault_reputation)|187341|187341|23|0.0%|0.5%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|20|0.0%|0.5%|
[iw_wormlist](#iw_wormlist)|35|35|13|37.1%|0.3%|
[firehol_anonymous](#firehol_anonymous)|19227|83278|12|0.0%|0.3%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|11|0.0%|0.2%|
[firehol_proxies](#firehol_proxies)|12738|13016|11|0.0%|0.2%|
[ri_web_proxies](#ri_web_proxies)|7870|7870|9|0.1%|0.2%|
[firehol_level1](#firehol_level1)|5137|688854747|9|0.0%|0.2%|
[php_spammers](#php_spammers)|735|735|6|0.8%|0.1%|
[php_dictionary](#php_dictionary)|737|737|6|0.8%|0.1%|
[fullbogons](#fullbogons)|3775|670173256|5|0.0%|0.1%|
[bogons](#bogons)|13|592708608|5|0.0%|0.1%|
[stopforumspam_1d](#stopforumspam_1d)|6683|6683|4|0.0%|0.1%|
[blocklist_de_ftp](#blocklist_de_ftp)|1586|1586|4|0.2%|0.1%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2846|2846|4|0.1%|0.1%|
[blocklist_de_bots](#blocklist_de_bots)|2960|2960|4|0.1%|0.1%|
[blocklist_de_apache](#blocklist_de_apache)|14292|14292|4|0.0%|0.1%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|3|0.0%|0.0%|
[php_harvesters](#php_harvesters)|408|408|3|0.7%|0.0%|
[php_commenters](#php_commenters)|458|458|3|0.6%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|0.0%|
[et_block](#et_block)|1000|18343756|3|0.0%|0.0%|
[xroxy](#xroxy)|2171|2171|2|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2828|2828|2|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|2|0.0%|0.0%|
[dragon_http](#dragon_http)|1021|268288|2|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2800|2800|2|0.0%|0.0%|
[tor_exits](#tor_exits)|1111|1111|1|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|1|0.0%|0.0%|
[sorbs_socks](#sorbs_socks)|7|7|1|14.2%|0.0%|
[sorbs_misc](#sorbs_misc)|7|7|1|14.2%|0.0%|
[sorbs_http](#sorbs_http)|7|7|1|14.2%|0.0%|
[proxz](#proxz)|1339|1339|1|0.0%|0.0%|
[et_tor](#et_tor)|6500|6500|1|0.0%|0.0%|
[dm_tor](#dm_tor)|6407|6407|1|0.0%|0.0%|
[bm_tor](#bm_tor)|6428|6428|1|0.0%|0.0%|

## iw_wormlist

[ImproWare Antispam](http://antispam.imp.ch/) IPs sending emails with viruses or worms, in the last 3 days

Source is downloaded from [this link](http://antispam.imp.ch/wormlist).

The last time downloaded was found to be dated: Fri Jun 12 03:20:04 UTC 2015.

The ipset `iw_wormlist` has **35** entries, **35** unique IPs.

The following table shows the overlaps of `iw_wormlist` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `iw_wormlist`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `iw_wormlist`.
- ` this % ` is the percentage **of this ipset (`iw_wormlist`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level3](#firehol_level3)|109614|9627353|35|0.0%|100.0%|
[iw_spamlist](#iw_spamlist)|3889|3889|13|0.3%|37.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|2|0.0%|5.7%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|1|0.0%|2.8%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|1|0.0%|2.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|1|0.0%|2.8%|
[firehol_level2](#firehol_level2)|21690|33293|1|0.0%|2.8%|
[blocklist_de_mail](#blocklist_de_mail)|18158|18158|1|0.0%|2.8%|
[blocklist_de](#blocklist_de)|28132|28132|1|0.0%|2.8%|

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
[firehol_level3](#firehol_level3)|109614|9627353|276|0.0%|100.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|44|0.0%|15.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|16|0.0%|5.7%|
[cleanmx_viruses](#cleanmx_viruses)|121|121|16|13.2%|5.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|10|0.0%|3.6%|
[alienvault_reputation](#alienvault_reputation)|187341|187341|9|0.0%|3.2%|
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
[firehol_level3](#firehol_level3)|109614|9627353|1288|0.0%|100.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|147|0.0%|11.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|66|0.0%|5.1%|
[firehol_level1](#firehol_level1)|5137|688854747|39|0.0%|3.0%|
[et_block](#et_block)|1000|18343756|30|0.0%|2.3%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|29|0.0%|2.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|27|0.0%|2.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|27|0.0%|2.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|26|0.0%|2.0%|
[snort_ipfilter](#snort_ipfilter)|9671|9671|11|0.1%|0.8%|
[fullbogons](#fullbogons)|3775|670173256|9|0.0%|0.6%|
[alienvault_reputation](#alienvault_reputation)|187341|187341|8|0.0%|0.6%|
[malc0de](#malc0de)|276|276|4|1.4%|0.3%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|3|0.0%|0.2%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|3|0.2%|0.2%|
[dragon_http](#dragon_http)|1021|268288|2|0.0%|0.1%|
[cleanmx_viruses](#cleanmx_viruses)|121|121|2|1.6%|0.1%|
[zeus](#zeus)|230|230|1|0.4%|0.0%|
[nixspam](#nixspam)|18244|18244|1|0.0%|0.0%|
[et_botcc](#et_botcc)|505|505|1|0.1%|0.0%|

## maxmind_proxy_fraud

[MaxMind.com](https://www.maxmind.com/en/anonymous-proxy-fraudulent-ip-address-list) list of anonymous proxy fraudelent IP addresses.

Source is downloaded from [this link](https://www.maxmind.com/en/anonymous-proxy-fraudulent-ip-address-list).

The last time downloaded was found to be dated: Fri Jun 12 03:45:11 UTC 2015.

The ipset `maxmind_proxy_fraud` has **524** entries, **524** unique IPs.

The following table shows the overlaps of `maxmind_proxy_fraud` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `maxmind_proxy_fraud`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `maxmind_proxy_fraud`.
- ` this % ` is the percentage **of this ipset (`maxmind_proxy_fraud`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_proxies](#firehol_proxies)|12738|13016|524|4.0%|100.0%|
[firehol_anonymous](#firehol_anonymous)|19227|83278|524|0.6%|100.0%|
[firehol_level3](#firehol_level3)|109614|9627353|346|0.0%|66.0%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|345|0.3%|65.8%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|277|0.9%|52.8%|
[snort_ipfilter](#snort_ipfilter)|9671|9671|237|2.4%|45.2%|
[et_tor](#et_tor)|6500|6500|233|3.5%|44.4%|
[tor_exits](#tor_exits)|1111|1111|230|20.7%|43.8%|
[dm_tor](#dm_tor)|6407|6407|229|3.5%|43.7%|
[bm_tor](#bm_tor)|6428|6428|229|3.5%|43.7%|
[firehol_level2](#firehol_level2)|21690|33293|196|0.5%|37.4%|
[stopforumspam_1d](#stopforumspam_1d)|6683|6683|194|2.9%|37.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|150|0.0%|28.6%|
[php_commenters](#php_commenters)|458|458|53|11.5%|10.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|29|0.0%|5.5%|
[alienvault_reputation](#alienvault_reputation)|187341|187341|29|0.0%|5.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|21|0.0%|4.0%|
[openbl_60d](#openbl_60d)|6974|6974|20|0.2%|3.8%|
[ri_web_proxies](#ri_web_proxies)|7870|7870|10|0.1%|1.9%|
[php_harvesters](#php_harvesters)|408|408|7|1.7%|1.3%|
[php_spammers](#php_spammers)|735|735|6|0.8%|1.1%|
[blocklist_de](#blocklist_de)|28132|28132|6|0.0%|1.1%|
[php_dictionary](#php_dictionary)|737|737|5|0.6%|0.9%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|5|0.0%|0.9%|
[dragon_http](#dragon_http)|1021|268288|4|0.0%|0.7%|
[blocklist_de_bots](#blocklist_de_bots)|2960|2960|4|0.1%|0.7%|
[xroxy](#xroxy)|2171|2171|3|0.1%|0.5%|
[voipbl](#voipbl)|10586|10998|2|0.0%|0.3%|
[proxz](#proxz)|1339|1339|2|0.1%|0.3%|
[nixspam](#nixspam)|18244|18244|2|0.0%|0.3%|
[firehol_level1](#firehol_level1)|5137|688854747|2|0.0%|0.3%|
[blocklist_de_apache](#blocklist_de_apache)|14292|14292|2|0.0%|0.3%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|1|0.0%|0.1%|
[sorbs_spam](#sorbs_spam)|64701|65536|1|0.0%|0.1%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|1|0.0%|0.1%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|1|0.0%|0.1%|
[shunlist](#shunlist)|1172|1172|1|0.0%|0.1%|
[ri_connect_proxies](#ri_connect_proxies)|2828|2828|1|0.0%|0.1%|
[proxyrss](#proxyrss)|1738|1738|1|0.0%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.1%|
[et_block](#et_block)|1000|18343756|1|0.0%|0.1%|
[dshield](#dshield)|20|5120|1|0.0%|0.1%|
[blocklist_de_mail](#blocklist_de_mail)|18158|18158|1|0.0%|0.1%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2846|2846|1|0.0%|0.1%|

## nixspam

[NiX Spam](http://www.heise.de/ix/NiX-Spam-DNSBL-and-blacklist-for-download-499637.html) IP addresses that sent spam in the last hour - automatically generated entries without distinguishing open proxies from relays, dialup gateways, and so on. All IPs are removed after 12 hours if there is no spam from there.

Source is downloaded from [this link](http://www.dnsbl.manitu.net/download/nixspam-ip.dump.gz).

The last time downloaded was found to be dated: Fri Jun 12 03:45:02 UTC 2015.

The ipset `nixspam` has **18244** entries, **18244** unique IPs.

The following table shows the overlaps of `nixspam` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `nixspam`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `nixspam`.
- ` this % ` is the percentage **of this ipset (`nixspam`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[sorbs_spam](#sorbs_spam)|64701|65536|1716|2.6%|9.4%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|1695|2.5%|9.2%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|1695|2.5%|9.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|837|0.0%|4.5%|
[firehol_level2](#firehol_level2)|21690|33293|581|1.7%|3.1%|
[iw_spamlist](#iw_spamlist)|3889|3889|566|14.5%|3.1%|
[blocklist_de](#blocklist_de)|28132|28132|561|1.9%|3.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|511|0.0%|2.8%|
[blocklist_de_mail](#blocklist_de_mail)|18158|18158|495|2.7%|2.7%|
[firehol_level3](#firehol_level3)|109614|9627353|428|0.0%|2.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|348|0.0%|1.9%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|216|0.2%|1.1%|
[snort_ipfilter](#snort_ipfilter)|9671|9671|174|1.7%|0.9%|
[firehol_anonymous](#firehol_anonymous)|19227|83278|163|0.1%|0.8%|
[firehol_proxies](#firehol_proxies)|12738|13016|157|1.2%|0.8%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|140|0.4%|0.7%|
[ri_web_proxies](#ri_web_proxies)|7870|7870|110|1.3%|0.6%|
[php_dictionary](#php_dictionary)|737|737|107|14.5%|0.5%|
[php_spammers](#php_spammers)|735|735|92|12.5%|0.5%|
[sorbs_web](#sorbs_web)|598|599|90|15.0%|0.4%|
[xroxy](#xroxy)|2171|2171|68|3.1%|0.3%|
[firehol_level1](#firehol_level1)|5137|688854747|65|0.0%|0.3%|
[alienvault_reputation](#alienvault_reputation)|187341|187341|65|0.0%|0.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|60|0.0%|0.3%|
[et_block](#et_block)|1000|18343756|60|0.0%|0.3%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|59|0.0%|0.3%|
[stopforumspam_1d](#stopforumspam_1d)|6683|6683|58|0.8%|0.3%|
[proxz](#proxz)|1339|1339|41|3.0%|0.2%|
[blocklist_de_bots](#blocklist_de_bots)|2960|2960|29|0.9%|0.1%|
[dragon_http](#dragon_http)|1021|268288|26|0.0%|0.1%|
[blocklist_de_apache](#blocklist_de_apache)|14292|14292|25|0.1%|0.1%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2846|2846|23|0.8%|0.1%|
[blocklist_de_imap](#blocklist_de_imap)|2800|2800|22|0.7%|0.1%|
[ri_connect_proxies](#ri_connect_proxies)|2828|2828|17|0.6%|0.0%|
[php_commenters](#php_commenters)|458|458|17|3.7%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|17|0.0%|0.0%|
[proxyrss](#proxyrss)|1738|1738|12|0.6%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|1586|1586|10|0.6%|0.0%|
[php_harvesters](#php_harvesters)|408|408|8|1.9%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|8|0.0%|0.0%|
[tor_exits](#tor_exits)|1111|1111|6|0.5%|0.0%|
[openbl_60d](#openbl_60d)|6974|6974|6|0.0%|0.0%|
[dm_tor](#dm_tor)|6407|6407|6|0.0%|0.0%|
[bm_tor](#bm_tor)|6428|6428|6|0.0%|0.0%|
[et_tor](#et_tor)|6500|6500|5|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|4|0.0%|0.0%|
[openbl_30d](#openbl_30d)|2803|2803|3|0.1%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|3|0.4%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|2|0.3%|0.0%|
[et_compromised](#et_compromised)|1704|1704|2|0.1%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1693|1693|2|0.1%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|169|169|2|1.1%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2216|2216|2|0.0%|0.0%|
[zeus_badips](#zeus_badips)|202|202|1|0.4%|0.0%|
[zeus](#zeus)|230|230|1|0.4%|0.0%|
[voipbl](#voipbl)|10586|10998|1|0.0%|0.0%|
[sorbs_socks](#sorbs_socks)|7|7|1|14.2%|0.0%|
[sorbs_misc](#sorbs_misc)|7|7|1|14.2%|0.0%|
[sorbs_http](#sorbs_http)|7|7|1|14.2%|0.0%|
[openbl_7d](#openbl_7d)|633|633|1|0.1%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|1|0.0%|0.0%|
[dshield](#dshield)|20|5120|1|0.0%|0.0%|
[dragon_sshpauth](#dragon_sshpauth)|1613|1675|1|0.0%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|121|121|1|0.8%|0.0%|

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
[firehol_level3](#firehol_level3)|109614|9627353|3|0.0%|4.3%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|2|0.0%|2.8%|
[nt_malware_irc](#nt_malware_irc)|43|43|2|4.6%|2.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|2|0.0%|2.8%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|1.4%|
[alienvault_reputation](#alienvault_reputation)|187341|187341|1|0.0%|1.4%|

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
[alienvault_reputation](#alienvault_reputation)|187341|187341|2|0.0%|4.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|1|0.0%|2.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|2.3%|
[firehol_level3](#firehol_level3)|109614|9627353|1|0.0%|2.3%|

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

The last time downloaded was found to be dated: Fri Jun 12 03:32:00 UTC 2015.

The ipset `openbl_1d` has **140** entries, **140** unique IPs.

The following table shows the overlaps of `openbl_1d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl_1d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl_1d`.
- ` this % ` is the percentage **of this ipset (`openbl_1d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|21690|33293|140|0.4%|100.0%|
[openbl_60d](#openbl_60d)|6974|6974|139|1.9%|99.2%|
[openbl_30d](#openbl_30d)|2803|2803|139|4.9%|99.2%|
[firehol_level3](#firehol_level3)|109614|9627353|139|0.0%|99.2%|
[alienvault_reputation](#alienvault_reputation)|187341|187341|138|0.0%|98.5%|
[openbl_7d](#openbl_7d)|633|633|135|21.3%|96.4%|
[blocklist_de](#blocklist_de)|28132|28132|124|0.4%|88.5%|
[blocklist_de_ssh](#blocklist_de_ssh)|2216|2216|122|5.5%|87.1%|
[dragon_sshpauth](#dragon_sshpauth)|1613|1675|91|5.4%|65.0%|
[bruteforceblocker](#bruteforceblocker)|1693|1693|74|4.3%|52.8%|
[shunlist](#shunlist)|1172|1172|73|6.2%|52.1%|
[et_compromised](#et_compromised)|1704|1704|72|4.2%|51.4%|
[firehol_level1](#firehol_level1)|5137|688854747|23|0.0%|16.4%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|20|0.0%|14.2%|
[et_block](#et_block)|1000|18343756|20|0.0%|14.2%|
[blocklist_de_strongips](#blocklist_de_strongips)|169|169|16|9.4%|11.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|10|0.0%|7.1%|
[dshield](#dshield)|20|5120|6|0.1%|4.2%|
[dragon_http](#dragon_http)|1021|268288|5|0.0%|3.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|3|0.0%|2.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|2.1%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|1|0.0%|0.7%|
[php_spammers](#php_spammers)|735|735|1|0.1%|0.7%|
[php_commenters](#php_commenters)|458|458|1|0.2%|0.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|1|0.0%|0.7%|
[ciarmy](#ciarmy)|397|397|1|0.2%|0.7%|
[blocklist_de_mail](#blocklist_de_mail)|18158|18158|1|0.0%|0.7%|
[blocklist_de_imap](#blocklist_de_imap)|2800|2800|1|0.0%|0.7%|
[blocklist_de_ftp](#blocklist_de_ftp)|1586|1586|1|0.0%|0.7%|

## openbl_30d

[OpenBL.org](http://www.openbl.org/) last 30 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.

Source is downloaded from [this link](http://www.openbl.org/lists/base_30days.txt).

The last time downloaded was found to be dated: Fri Jun 12 00:07:00 UTC 2015.

The ipset `openbl_30d` has **2803** entries, **2803** unique IPs.

The following table shows the overlaps of `openbl_30d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl_30d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl_30d`.
- ` this % ` is the percentage **of this ipset (`openbl_30d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[openbl_60d](#openbl_60d)|6974|6974|2803|40.1%|100.0%|
[firehol_level3](#firehol_level3)|109614|9627353|2803|0.0%|100.0%|
[alienvault_reputation](#alienvault_reputation)|187341|187341|2788|1.4%|99.4%|
[et_compromised](#et_compromised)|1704|1704|910|53.4%|32.4%|
[bruteforceblocker](#bruteforceblocker)|1693|1693|902|53.2%|32.1%|
[dragon_sshpauth](#dragon_sshpauth)|1613|1675|705|42.0%|25.1%|
[firehol_level2](#firehol_level2)|21690|33293|666|2.0%|23.7%|
[blocklist_de](#blocklist_de)|28132|28132|650|2.3%|23.1%|
[openbl_7d](#openbl_7d)|633|633|633|100.0%|22.5%|
[blocklist_de_ssh](#blocklist_de_ssh)|2216|2216|630|28.4%|22.4%|
[shunlist](#shunlist)|1172|1172|433|36.9%|15.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|285|0.0%|10.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|146|0.0%|5.2%|
[dragon_http](#dragon_http)|1021|268288|146|0.0%|5.2%|
[openbl_1d](#openbl_1d)|140|140|139|99.2%|4.9%|
[firehol_level1](#firehol_level1)|5137|688854747|135|0.0%|4.8%|
[et_block](#et_block)|1000|18343756|125|0.0%|4.4%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|119|0.0%|4.2%|
[dshield](#dshield)|20|5120|80|1.5%|2.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|65|0.0%|2.3%|
[blocklist_de_strongips](#blocklist_de_strongips)|169|169|23|13.6%|0.8%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|12|0.0%|0.4%|
[blocklist_de_mail](#blocklist_de_mail)|18158|18158|12|0.0%|0.4%|
[blocklist_de_imap](#blocklist_de_imap)|2800|2800|9|0.3%|0.3%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|5|0.0%|0.1%|
[blocklist_de_apache](#blocklist_de_apache)|14292|14292|5|0.0%|0.1%|
[voipbl](#voipbl)|10586|10998|3|0.0%|0.1%|
[nixspam](#nixspam)|18244|18244|3|0.0%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|3|0.0%|0.1%|
[zeus](#zeus)|230|230|2|0.8%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9671|9671|2|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|2|0.1%|0.0%|
[ciarmy](#ciarmy)|397|397|2|0.5%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|1586|1586|2|0.1%|0.0%|
[zeus_badips](#zeus_badips)|202|202|1|0.4%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|1|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6683|6683|1|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|1|0.0%|0.0%|
[php_spammers](#php_spammers)|735|735|1|0.1%|0.0%|
[php_commenters](#php_commenters)|458|458|1|0.2%|0.0%|
[firehol_anonymous](#firehol_anonymous)|19227|83278|1|0.0%|0.0%|
[dragon_vncprobe](#dragon_vncprobe)|87|87|1|1.1%|0.0%|

## openbl_60d

[OpenBL.org](http://www.openbl.org/) last 60 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.

Source is downloaded from [this link](http://www.openbl.org/lists/base_60days.txt).

The last time downloaded was found to be dated: Fri Jun 12 00:07:00 UTC 2015.

The ipset `openbl_60d` has **6974** entries, **6974** unique IPs.

The following table shows the overlaps of `openbl_60d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl_60d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl_60d`.
- ` this % ` is the percentage **of this ipset (`openbl_60d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[alienvault_reputation](#alienvault_reputation)|187341|187341|6954|3.7%|99.7%|
[firehol_level3](#firehol_level3)|109614|9627353|2929|0.0%|41.9%|
[openbl_30d](#openbl_30d)|2803|2803|2803|100.0%|40.1%|
[et_compromised](#et_compromised)|1704|1704|976|57.2%|13.9%|
[bruteforceblocker](#bruteforceblocker)|1693|1693|962|56.8%|13.7%|
[firehol_level2](#firehol_level2)|21690|33293|802|2.4%|11.4%|
[dragon_sshpauth](#dragon_sshpauth)|1613|1675|788|47.0%|11.2%|
[blocklist_de](#blocklist_de)|28132|28132|771|2.7%|11.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|741|0.0%|10.6%|
[blocklist_de_ssh](#blocklist_de_ssh)|2216|2216|740|33.3%|10.6%|
[openbl_7d](#openbl_7d)|633|633|633|100.0%|9.0%|
[shunlist](#shunlist)|1172|1172|459|39.1%|6.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|319|0.0%|4.5%|
[firehol_level1](#firehol_level1)|5137|688854747|253|0.0%|3.6%|
[et_block](#et_block)|1000|18343756|245|0.0%|3.5%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|235|0.0%|3.3%|
[dragon_http](#dragon_http)|1021|268288|213|0.0%|3.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|163|0.0%|2.3%|
[openbl_1d](#openbl_1d)|140|140|139|99.2%|1.9%|
[dshield](#dshield)|20|5120|84|1.6%|1.2%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|47|0.0%|0.6%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|26|0.0%|0.3%|
[snort_ipfilter](#snort_ipfilter)|9671|9671|24|0.2%|0.3%|
[blocklist_de_strongips](#blocklist_de_strongips)|169|169|24|14.2%|0.3%|
[firehol_anonymous](#firehol_anonymous)|19227|83278|23|0.0%|0.3%|
[tor_exits](#tor_exits)|1111|1111|20|1.8%|0.2%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|20|3.8%|0.2%|
[firehol_proxies](#firehol_proxies)|12738|13016|20|0.1%|0.2%|
[et_tor](#et_tor)|6500|6500|20|0.3%|0.2%|
[dm_tor](#dm_tor)|6407|6407|20|0.3%|0.2%|
[bm_tor](#bm_tor)|6428|6428|19|0.2%|0.2%|
[blocklist_de_mail](#blocklist_de_mail)|18158|18158|19|0.1%|0.2%|
[stopforumspam_1d](#stopforumspam_1d)|6683|6683|16|0.2%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|16|0.0%|0.2%|
[blocklist_de_imap](#blocklist_de_imap)|2800|2800|14|0.5%|0.2%|
[php_commenters](#php_commenters)|458|458|12|2.6%|0.1%|
[voipbl](#voipbl)|10586|10998|8|0.0%|0.1%|
[blocklist_de_apache](#blocklist_de_apache)|14292|14292|8|0.0%|0.1%|
[nixspam](#nixspam)|18244|18244|6|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|5|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|1586|1586|3|0.1%|0.0%|
[zeus](#zeus)|230|230|2|0.8%|0.0%|
[sorbs_spam](#sorbs_spam)|64701|65536|2|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|2|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|2|0.0%|0.0%|
[php_harvesters](#php_harvesters)|408|408|2|0.4%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|2|0.1%|0.0%|
[ciarmy](#ciarmy)|397|397|2|0.5%|0.0%|
[zeus_badips](#zeus_badips)|202|202|1|0.4%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|1|0.0%|0.0%|
[php_spammers](#php_spammers)|735|735|1|0.1%|0.0%|
[dragon_vncprobe](#dragon_vncprobe)|87|87|1|1.1%|0.0%|

## openbl_7d

[OpenBL.org](http://www.openbl.org/) last 7 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.

Source is downloaded from [this link](http://www.openbl.org/lists/base_7days.txt).

The last time downloaded was found to be dated: Fri Jun 12 00:07:00 UTC 2015.

The ipset `openbl_7d` has **633** entries, **633** unique IPs.

The following table shows the overlaps of `openbl_7d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl_7d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl_7d`.
- ` this % ` is the percentage **of this ipset (`openbl_7d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[openbl_60d](#openbl_60d)|6974|6974|633|9.0%|100.0%|
[openbl_30d](#openbl_30d)|2803|2803|633|22.5%|100.0%|
[firehol_level3](#firehol_level3)|109614|9627353|633|0.0%|100.0%|
[alienvault_reputation](#alienvault_reputation)|187341|187341|631|0.3%|99.6%|
[firehol_level2](#firehol_level2)|21690|33293|387|1.1%|61.1%|
[blocklist_de](#blocklist_de)|28132|28132|372|1.3%|58.7%|
[blocklist_de_ssh](#blocklist_de_ssh)|2216|2216|361|16.2%|57.0%|
[dragon_sshpauth](#dragon_sshpauth)|1613|1675|345|20.5%|54.5%|
[bruteforceblocker](#bruteforceblocker)|1693|1693|308|18.1%|48.6%|
[et_compromised](#et_compromised)|1704|1704|307|18.0%|48.4%|
[shunlist](#shunlist)|1172|1172|201|17.1%|31.7%|
[openbl_1d](#openbl_1d)|140|140|135|96.4%|21.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|65|0.0%|10.2%|
[firehol_level1](#firehol_level1)|5137|688854747|59|0.0%|9.3%|
[et_block](#et_block)|1000|18343756|56|0.0%|8.8%|
[dragon_http](#dragon_http)|1021|268288|54|0.0%|8.5%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|52|0.0%|8.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|38|0.0%|6.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|169|169|22|13.0%|3.4%|
[dshield](#dshield)|20|5120|21|0.4%|3.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|14|0.0%|2.2%|
[blocklist_de_mail](#blocklist_de_mail)|18158|18158|6|0.0%|0.9%|
[blocklist_de_imap](#blocklist_de_imap)|2800|2800|5|0.1%|0.7%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|4|0.0%|0.6%|
[blocklist_de_apache](#blocklist_de_apache)|14292|14292|3|0.0%|0.4%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|2|0.0%|0.3%|
[ciarmy](#ciarmy)|397|397|2|0.5%|0.3%|
[blocklist_de_ftp](#blocklist_de_ftp)|1586|1586|2|0.1%|0.3%|
[zeus_badips](#zeus_badips)|202|202|1|0.4%|0.1%|
[zeus](#zeus)|230|230|1|0.4%|0.1%|
[snort_ipfilter](#snort_ipfilter)|9671|9671|1|0.0%|0.1%|
[php_spammers](#php_spammers)|735|735|1|0.1%|0.1%|
[php_commenters](#php_commenters)|458|458|1|0.2%|0.1%|
[nixspam](#nixspam)|18244|18244|1|0.0%|0.1%|

## palevo

[Abuse.ch Palevo tracker](https://palevotracker.abuse.ch) worm includes IPs which are being used as botnet C&C for the Palevo crimeware - **excellent list**

Source is downloaded from [this link](https://palevotracker.abuse.ch/blocklists.php?download=ipblocklist).

The last time downloaded was found to be dated: Fri Jun 12 03:54:23 UTC 2015.

The ipset `palevo` has **13** entries, **13** unique IPs.

The following table shows the overlaps of `palevo` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `palevo`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `palevo`.
- ` this % ` is the percentage **of this ipset (`palevo`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level1](#firehol_level1)|5137|688854747|13|0.0%|100.0%|
[et_block](#et_block)|1000|18343756|13|0.0%|100.0%|
[snort_ipfilter](#snort_ipfilter)|9671|9671|11|0.1%|84.6%|
[firehol_level3](#firehol_level3)|109614|9627353|11|0.0%|84.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|3|0.0%|23.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|2|0.0%|15.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|1|0.0%|7.6%|

## php_commenters

[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) comment spammers (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=c&rss=1).

The last time downloaded was found to be dated: Fri Jun 12 03:18:34 UTC 2015.

The ipset `php_commenters` has **458** entries, **458** unique IPs.

The following table shows the overlaps of `php_commenters` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `php_commenters`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `php_commenters`.
- ` this % ` is the percentage **of this ipset (`php_commenters`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level3](#firehol_level3)|109614|9627353|458|0.0%|100.0%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|334|0.3%|72.9%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|248|0.8%|54.1%|
[firehol_level2](#firehol_level2)|21690|33293|196|0.5%|42.7%|
[stopforumspam_1d](#stopforumspam_1d)|6683|6683|171|2.5%|37.3%|
[blocklist_de](#blocklist_de)|28132|28132|106|0.3%|23.1%|
[firehol_anonymous](#firehol_anonymous)|19227|83278|90|0.1%|19.6%|
[firehol_proxies](#firehol_proxies)|12738|13016|86|0.6%|18.7%|
[blocklist_de_bots](#blocklist_de_bots)|2960|2960|86|2.9%|18.7%|
[snort_ipfilter](#snort_ipfilter)|9671|9671|71|0.7%|15.5%|
[tor_exits](#tor_exits)|1111|1111|54|4.8%|11.7%|
[php_spammers](#php_spammers)|735|735|54|7.3%|11.7%|
[et_tor](#et_tor)|6500|6500|54|0.8%|11.7%|
[dm_tor](#dm_tor)|6407|6407|54|0.8%|11.7%|
[bm_tor](#bm_tor)|6428|6428|54|0.8%|11.7%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|53|10.1%|11.5%|
[blocklist_de_strongips](#blocklist_de_strongips)|169|169|44|26.0%|9.6%|
[firehol_level1](#firehol_level1)|5137|688854747|39|0.0%|8.5%|
[php_dictionary](#php_dictionary)|737|737|38|5.1%|8.2%|
[ri_web_proxies](#ri_web_proxies)|7870|7870|30|0.3%|6.5%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|29|0.0%|6.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|29|0.0%|6.3%|
[et_block](#et_block)|1000|18343756|29|0.0%|6.3%|
[blocklist_de_mail](#blocklist_de_mail)|18158|18158|29|0.1%|6.3%|
[blocklist_de_apache](#blocklist_de_apache)|14292|14292|28|0.1%|6.1%|
[sorbs_spam](#sorbs_spam)|64701|65536|27|0.0%|5.8%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|27|0.0%|5.8%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|27|0.0%|5.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|19|0.0%|4.1%|
[alienvault_reputation](#alienvault_reputation)|187341|187341|19|0.0%|4.1%|
[nixspam](#nixspam)|18244|18244|17|0.0%|3.7%|
[php_harvesters](#php_harvesters)|408|408|15|3.6%|3.2%|
[xroxy](#xroxy)|2171|2171|13|0.5%|2.8%|
[openbl_60d](#openbl_60d)|6974|6974|12|0.1%|2.6%|
[proxz](#proxz)|1339|1339|10|0.7%|2.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|10|0.0%|2.1%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|8|0.0%|1.7%|
[ri_connect_proxies](#ri_connect_proxies)|2828|2828|6|0.2%|1.3%|
[proxyrss](#proxyrss)|1738|1738|6|0.3%|1.3%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2846|2846|6|0.2%|1.3%|
[dragon_http](#dragon_http)|1021|268288|4|0.0%|0.8%|
[sorbs_web](#sorbs_web)|598|599|3|0.5%|0.6%|
[iw_spamlist](#iw_spamlist)|3889|3889|3|0.0%|0.6%|
[zeus_badips](#zeus_badips)|202|202|1|0.4%|0.2%|
[zeus](#zeus)|230|230|1|0.4%|0.2%|
[openbl_7d](#openbl_7d)|633|633|1|0.1%|0.2%|
[openbl_30d](#openbl_30d)|2803|2803|1|0.0%|0.2%|
[openbl_1d](#openbl_1d)|140|140|1|0.7%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.2%|
[fullbogons](#fullbogons)|3775|670173256|1|0.0%|0.2%|
[et_compromised](#et_compromised)|1704|1704|1|0.0%|0.2%|
[dshield](#dshield)|20|5120|1|0.0%|0.2%|
[bruteforceblocker](#bruteforceblocker)|1693|1693|1|0.0%|0.2%|
[bogons](#bogons)|13|592708608|1|0.0%|0.2%|
[blocklist_de_ssh](#blocklist_de_ssh)|2216|2216|1|0.0%|0.2%|

## php_dictionary

[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) directory attackers (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=d&rss=1).

The last time downloaded was found to be dated: Fri Jun 12 03:18:35 UTC 2015.

The ipset `php_dictionary` has **737** entries, **737** unique IPs.

The following table shows the overlaps of `php_dictionary` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `php_dictionary`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `php_dictionary`.
- ` this % ` is the percentage **of this ipset (`php_dictionary`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level3](#firehol_level3)|109614|9627353|737|0.0%|100.0%|
[php_spammers](#php_spammers)|735|735|322|43.8%|43.6%|
[sorbs_spam](#sorbs_spam)|64701|65536|214|0.3%|29.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|214|0.3%|29.0%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|214|0.3%|29.0%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|139|0.1%|18.8%|
[firehol_level2](#firehol_level2)|21690|33293|125|0.3%|16.9%|
[blocklist_de](#blocklist_de)|28132|28132|118|0.4%|16.0%|
[nixspam](#nixspam)|18244|18244|107|0.5%|14.5%|
[blocklist_de_mail](#blocklist_de_mail)|18158|18158|101|0.5%|13.7%|
[firehol_anonymous](#firehol_anonymous)|19227|83278|99|0.1%|13.4%|
[firehol_proxies](#firehol_proxies)|12738|13016|98|0.7%|13.2%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|93|0.3%|12.6%|
[snort_ipfilter](#snort_ipfilter)|9671|9671|91|0.9%|12.3%|
[ri_web_proxies](#ri_web_proxies)|7870|7870|67|0.8%|9.0%|
[xroxy](#xroxy)|2171|2171|41|1.8%|5.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|39|0.0%|5.2%|
[php_commenters](#php_commenters)|458|458|38|8.2%|5.1%|
[sorbs_web](#sorbs_web)|598|599|33|5.5%|4.4%|
[stopforumspam_1d](#stopforumspam_1d)|6683|6683|31|0.4%|4.2%|
[proxz](#proxz)|1339|1339|25|1.8%|3.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|23|0.0%|3.1%|
[blocklist_de_bots](#blocklist_de_bots)|2960|2960|13|0.4%|1.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|12|0.0%|1.6%|
[alienvault_reputation](#alienvault_reputation)|187341|187341|7|0.0%|0.9%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|6|0.0%|0.8%|
[iw_spamlist](#iw_spamlist)|3889|3889|6|0.1%|0.8%|
[firehol_level1](#firehol_level1)|5137|688854747|6|0.0%|0.8%|
[et_block](#et_block)|1000|18343756|6|0.0%|0.8%|
[ri_connect_proxies](#ri_connect_proxies)|2828|2828|5|0.1%|0.6%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|5|0.9%|0.6%|
[blocklist_de_strongips](#blocklist_de_strongips)|169|169|5|2.9%|0.6%|
[tor_exits](#tor_exits)|1111|1111|4|0.3%|0.5%|
[proxyrss](#proxyrss)|1738|1738|4|0.2%|0.5%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|4|0.0%|0.5%|
[et_tor](#et_tor)|6500|6500|4|0.0%|0.5%|
[dm_tor](#dm_tor)|6407|6407|4|0.0%|0.5%|
[bm_tor](#bm_tor)|6428|6428|4|0.0%|0.5%|
[php_harvesters](#php_harvesters)|408|408|3|0.7%|0.4%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|3|0.0%|0.4%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2846|2846|3|0.1%|0.4%|
[blocklist_de_apache](#blocklist_de_apache)|14292|14292|3|0.0%|0.4%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|2|0.3%|0.2%|
[dragon_http](#dragon_http)|1021|268288|2|0.0%|0.2%|
[sorbs_socks](#sorbs_socks)|7|7|1|14.2%|0.1%|
[sorbs_misc](#sorbs_misc)|7|7|1|14.2%|0.1%|
[sorbs_http](#sorbs_http)|7|7|1|14.2%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.1%|
[blocklist_de_ftp](#blocklist_de_ftp)|1586|1586|1|0.0%|0.1%|

## php_harvesters

[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) harvesters (IPs that surf the internet looking for email addresses) (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=h&rss=1).

The last time downloaded was found to be dated: Fri Jun 12 03:18:33 UTC 2015.

The ipset `php_harvesters` has **408** entries, **408** unique IPs.

The following table shows the overlaps of `php_harvesters` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `php_harvesters`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `php_harvesters`.
- ` this % ` is the percentage **of this ipset (`php_harvesters`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level3](#firehol_level3)|109614|9627353|408|0.0%|100.0%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|87|0.0%|21.3%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|65|0.2%|15.9%|
[firehol_level2](#firehol_level2)|21690|33293|58|0.1%|14.2%|
[stopforumspam_1d](#stopforumspam_1d)|6683|6683|47|0.7%|11.5%|
[blocklist_de](#blocklist_de)|28132|28132|36|0.1%|8.8%|
[blocklist_de_bots](#blocklist_de_bots)|2960|2960|26|0.8%|6.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|20|0.0%|4.9%|
[sorbs_spam](#sorbs_spam)|64701|65536|16|0.0%|3.9%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|16|0.0%|3.9%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|16|0.0%|3.9%|
[php_commenters](#php_commenters)|458|458|15|3.2%|3.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|12|0.0%|2.9%|
[firehol_proxies](#firehol_proxies)|12738|13016|12|0.0%|2.9%|
[firehol_anonymous](#firehol_anonymous)|19227|83278|12|0.0%|2.9%|
[alienvault_reputation](#alienvault_reputation)|187341|187341|12|0.0%|2.9%|
[snort_ipfilter](#snort_ipfilter)|9671|9671|11|0.1%|2.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|9|0.0%|2.2%|
[nixspam](#nixspam)|18244|18244|8|0.0%|1.9%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|7|1.3%|1.7%|
[et_tor](#et_tor)|6500|6500|7|0.1%|1.7%|
[dm_tor](#dm_tor)|6407|6407|7|0.1%|1.7%|
[bm_tor](#bm_tor)|6428|6428|7|0.1%|1.7%|
[tor_exits](#tor_exits)|1111|1111|6|0.5%|1.4%|
[blocklist_de_mail](#blocklist_de_mail)|18158|18158|5|0.0%|1.2%|
[php_spammers](#php_spammers)|735|735|3|0.4%|0.7%|
[php_dictionary](#php_dictionary)|737|737|3|0.4%|0.7%|
[iw_spamlist](#iw_spamlist)|3889|3889|3|0.0%|0.7%|
[firehol_level1](#firehol_level1)|5137|688854747|3|0.0%|0.7%|
[blocklist_de_strongips](#blocklist_de_strongips)|169|169|3|1.7%|0.7%|
[blocklist_de_ftp](#blocklist_de_ftp)|1586|1586|3|0.1%|0.7%|
[xroxy](#xroxy)|2171|2171|2|0.0%|0.4%|
[ri_web_proxies](#ri_web_proxies)|7870|7870|2|0.0%|0.4%|
[openbl_60d](#openbl_60d)|6974|6974|2|0.0%|0.4%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|2|0.0%|0.4%|
[blocklist_de_imap](#blocklist_de_imap)|2800|2800|2|0.0%|0.4%|
[blocklist_de_apache](#blocklist_de_apache)|14292|14292|2|0.0%|0.4%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|1|0.0%|0.2%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|1|0.0%|0.2%|
[ri_connect_proxies](#ri_connect_proxies)|2828|2828|1|0.0%|0.2%|
[proxyrss](#proxyrss)|1738|1738|1|0.0%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.2%|
[fullbogons](#fullbogons)|3775|670173256|1|0.0%|0.2%|
[et_block](#et_block)|1000|18343756|1|0.0%|0.2%|
[bogons](#bogons)|13|592708608|1|0.0%|0.2%|
[blocklist_de_ssh](#blocklist_de_ssh)|2216|2216|1|0.0%|0.2%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2846|2846|1|0.0%|0.2%|

## php_spammers

[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) spam servers (IPs used by spammers to send messages) (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=s&rss=1).

The last time downloaded was found to be dated: Fri Jun 12 03:18:33 UTC 2015.

The ipset `php_spammers` has **735** entries, **735** unique IPs.

The following table shows the overlaps of `php_spammers` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `php_spammers`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `php_spammers`.
- ` this % ` is the percentage **of this ipset (`php_spammers`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level3](#firehol_level3)|109614|9627353|735|0.0%|100.0%|
[php_dictionary](#php_dictionary)|737|737|322|43.6%|43.8%|
[sorbs_spam](#sorbs_spam)|64701|65536|184|0.2%|25.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|184|0.2%|25.0%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|184|0.2%|25.0%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|151|0.1%|20.5%|
[firehol_level2](#firehol_level2)|21690|33293|118|0.3%|16.0%|
[blocklist_de](#blocklist_de)|28132|28132|108|0.3%|14.6%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|93|0.3%|12.6%|
[nixspam](#nixspam)|18244|18244|92|0.5%|12.5%|
[snort_ipfilter](#snort_ipfilter)|9671|9671|85|0.8%|11.5%|
[firehol_anonymous](#firehol_anonymous)|19227|83278|83|0.0%|11.2%|
[firehol_proxies](#firehol_proxies)|12738|13016|81|0.6%|11.0%|
[blocklist_de_mail](#blocklist_de_mail)|18158|18158|81|0.4%|11.0%|
[ri_web_proxies](#ri_web_proxies)|7870|7870|54|0.6%|7.3%|
[php_commenters](#php_commenters)|458|458|54|11.7%|7.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|54|0.0%|7.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|44|0.0%|5.9%|
[stopforumspam_1d](#stopforumspam_1d)|6683|6683|40|0.5%|5.4%|
[xroxy](#xroxy)|2171|2171|34|1.5%|4.6%|
[sorbs_web](#sorbs_web)|598|599|27|4.5%|3.6%|
[proxz](#proxz)|1339|1339|22|1.6%|2.9%|
[blocklist_de_bots](#blocklist_de_bots)|2960|2960|19|0.6%|2.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|11|0.0%|1.4%|
[blocklist_de_strongips](#blocklist_de_strongips)|169|169|10|5.9%|1.3%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|6|1.1%|0.8%|
[iw_spamlist](#iw_spamlist)|3889|3889|6|0.1%|0.8%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2846|2846|6|0.2%|0.8%|
[blocklist_de_apache](#blocklist_de_apache)|14292|14292|6|0.0%|0.8%|
[tor_exits](#tor_exits)|1111|1111|5|0.4%|0.6%|
[proxyrss](#proxyrss)|1738|1738|5|0.2%|0.6%|
[et_tor](#et_tor)|6500|6500|5|0.0%|0.6%|
[dm_tor](#dm_tor)|6407|6407|5|0.0%|0.6%|
[bm_tor](#bm_tor)|6428|6428|5|0.0%|0.6%|
[alienvault_reputation](#alienvault_reputation)|187341|187341|5|0.0%|0.6%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|4|0.0%|0.5%|
[firehol_level1](#firehol_level1)|5137|688854747|4|0.0%|0.5%|
[et_block](#et_block)|1000|18343756|4|0.0%|0.5%|
[ri_connect_proxies](#ri_connect_proxies)|2828|2828|3|0.1%|0.4%|
[php_harvesters](#php_harvesters)|408|408|3|0.7%|0.4%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|0.4%|
[openbl_7d](#openbl_7d)|633|633|1|0.1%|0.1%|
[openbl_60d](#openbl_60d)|6974|6974|1|0.0%|0.1%|
[openbl_30d](#openbl_30d)|2803|2803|1|0.0%|0.1%|
[openbl_1d](#openbl_1d)|140|140|1|0.7%|0.1%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|1|0.1%|0.1%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|1|0.0%|0.1%|
[et_compromised](#et_compromised)|1704|1704|1|0.0%|0.1%|
[bruteforceblocker](#bruteforceblocker)|1693|1693|1|0.0%|0.1%|
[blocklist_de_ssh](#blocklist_de_ssh)|2216|2216|1|0.0%|0.1%|
[blocklist_de_ftp](#blocklist_de_ftp)|1586|1586|1|0.0%|0.1%|

## proxyrss

[proxyrss.com](http://www.proxyrss.com) open proxies syndicated from multiple sources.

Source is downloaded from [this link](http://www.proxyrss.com/proxylists/all.gz).

The last time downloaded was found to be dated: Fri Jun 12 01:51:25 UTC 2015.

The ipset `proxyrss` has **1738** entries, **1738** unique IPs.

The following table shows the overlaps of `proxyrss` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `proxyrss`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `proxyrss`.
- ` this % ` is the percentage **of this ipset (`proxyrss`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_proxies](#firehol_proxies)|12738|13016|1738|13.3%|100.0%|
[firehol_anonymous](#firehol_anonymous)|19227|83278|1738|2.0%|100.0%|
[firehol_level3](#firehol_level3)|109614|9627353|758|0.0%|43.6%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|756|0.8%|43.4%|
[ri_web_proxies](#ri_web_proxies)|7870|7870|681|8.6%|39.1%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|613|2.1%|35.2%|
[firehol_level2](#firehol_level2)|21690|33293|402|1.2%|23.1%|
[xroxy](#xroxy)|2171|2171|383|17.6%|22.0%|
[stopforumspam_1d](#stopforumspam_1d)|6683|6683|338|5.0%|19.4%|
[proxz](#proxz)|1339|1339|296|22.1%|17.0%|
[ri_connect_proxies](#ri_connect_proxies)|2828|2828|233|8.2%|13.4%|
[blocklist_de_bots](#blocklist_de_bots)|2960|2960|223|7.5%|12.8%|
[blocklist_de](#blocklist_de)|28132|28132|223|0.7%|12.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|62|0.0%|3.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|47|0.0%|2.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|26|0.0%|1.4%|
[nixspam](#nixspam)|18244|18244|12|0.0%|0.6%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|8|1.2%|0.4%|
[sorbs_spam](#sorbs_spam)|64701|65536|7|0.0%|0.4%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|7|0.0%|0.4%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|7|0.0%|0.4%|
[blocklist_de_strongips](#blocklist_de_strongips)|169|169|7|4.1%|0.4%|
[php_commenters](#php_commenters)|458|458|6|1.3%|0.3%|
[php_spammers](#php_spammers)|735|735|5|0.6%|0.2%|
[php_dictionary](#php_dictionary)|737|737|4|0.5%|0.2%|
[dragon_http](#dragon_http)|1021|268288|4|0.0%|0.2%|
[snort_ipfilter](#snort_ipfilter)|9671|9671|3|0.0%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|2|0.0%|0.1%|
[sorbs_web](#sorbs_web)|598|599|1|0.1%|0.0%|
[php_harvesters](#php_harvesters)|408|408|1|0.2%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|1|0.1%|0.0%|
[et_tor](#et_tor)|6500|6500|1|0.0%|0.0%|
[et_compromised](#et_compromised)|1704|1704|1|0.0%|0.0%|
[dm_tor](#dm_tor)|6407|6407|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1693|1693|1|0.0%|0.0%|
[bm_tor](#bm_tor)|6428|6428|1|0.0%|0.0%|
[alienvault_reputation](#alienvault_reputation)|187341|187341|1|0.0%|0.0%|

## proxz

[proxz.com](http://www.proxz.com) open proxies (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.proxz.com/proxylists.xml).

The last time downloaded was found to be dated: Fri Jun 12 01:51:31 UTC 2015.

The ipset `proxz` has **1339** entries, **1339** unique IPs.

The following table shows the overlaps of `proxz` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `proxz`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `proxz`.
- ` this % ` is the percentage **of this ipset (`proxz`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_proxies](#firehol_proxies)|12738|13016|1339|10.2%|100.0%|
[firehol_anonymous](#firehol_anonymous)|19227|83278|1339|1.6%|100.0%|
[firehol_level3](#firehol_level3)|109614|9627353|792|0.0%|59.1%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|786|0.8%|58.7%|
[ri_web_proxies](#ri_web_proxies)|7870|7870|612|7.7%|45.7%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|504|1.7%|37.6%|
[xroxy](#xroxy)|2171|2171|462|21.2%|34.5%|
[proxyrss](#proxyrss)|1738|1738|296|17.0%|22.1%|
[firehol_level2](#firehol_level2)|21690|33293|274|0.8%|20.4%|
[ri_connect_proxies](#ri_connect_proxies)|2828|2828|231|8.1%|17.2%|
[blocklist_de](#blocklist_de)|28132|28132|190|0.6%|14.1%|
[stopforumspam_1d](#stopforumspam_1d)|6683|6683|189|2.8%|14.1%|
[blocklist_de_bots](#blocklist_de_bots)|2960|2960|157|5.3%|11.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|105|0.0%|7.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|56|0.0%|4.1%|
[sorbs_spam](#sorbs_spam)|64701|65536|44|0.0%|3.2%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|44|0.0%|3.2%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|44|0.0%|3.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|44|0.0%|3.2%|
[nixspam](#nixspam)|18244|18244|41|0.2%|3.0%|
[blocklist_de_mail](#blocklist_de_mail)|18158|18158|33|0.1%|2.4%|
[snort_ipfilter](#snort_ipfilter)|9671|9671|27|0.2%|2.0%|
[php_dictionary](#php_dictionary)|737|737|25|3.3%|1.8%|
[php_spammers](#php_spammers)|735|735|22|2.9%|1.6%|
[php_commenters](#php_commenters)|458|458|10|2.1%|0.7%|
[sorbs_web](#sorbs_web)|598|599|8|1.3%|0.5%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|6|0.9%|0.4%|
[blocklist_de_strongips](#blocklist_de_strongips)|169|169|6|3.5%|0.4%|
[dragon_http](#dragon_http)|1021|268288|4|0.0%|0.2%|
[alienvault_reputation](#alienvault_reputation)|187341|187341|3|0.0%|0.2%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|2|0.3%|0.1%|
[et_compromised](#et_compromised)|1704|1704|2|0.1%|0.1%|
[bruteforceblocker](#bruteforceblocker)|1693|1693|2|0.1%|0.1%|
[iw_spamlist](#iw_spamlist)|3889|3889|1|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|1|0.0%|0.0%|
[et_block](#et_block)|1000|18343756|1|0.0%|0.0%|

## ri_connect_proxies

[rosinstrument.com](http://www.rosinstrument.com) open CONNECT proxies (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://tools.rosinstrument.com/proxy/plab100.xml).

The last time downloaded was found to be dated: Thu Jun 11 21:56:23 UTC 2015.

The ipset `ri_connect_proxies` has **2828** entries, **2828** unique IPs.

The following table shows the overlaps of `ri_connect_proxies` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ri_connect_proxies`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ri_connect_proxies`.
- ` this % ` is the percentage **of this ipset (`ri_connect_proxies`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_proxies](#firehol_proxies)|12738|13016|2828|21.7%|100.0%|
[firehol_anonymous](#firehol_anonymous)|19227|83278|2828|3.3%|100.0%|
[firehol_level3](#firehol_level3)|109614|9627353|1586|0.0%|56.0%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|1585|1.6%|56.0%|
[ri_web_proxies](#ri_web_proxies)|7870|7870|1207|15.3%|42.6%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|526|1.8%|18.5%|
[xroxy](#xroxy)|2171|2171|396|18.2%|14.0%|
[proxyrss](#proxyrss)|1738|1738|233|13.4%|8.2%|
[proxz](#proxz)|1339|1339|231|17.2%|8.1%|
[firehol_level2](#firehol_level2)|21690|33293|142|0.4%|5.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|106|0.0%|3.7%|
[stopforumspam_1d](#stopforumspam_1d)|6683|6683|101|1.5%|3.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|86|0.0%|3.0%|
[blocklist_de](#blocklist_de)|28132|28132|68|0.2%|2.4%|
[blocklist_de_bots](#blocklist_de_bots)|2960|2960|65|2.1%|2.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|57|0.0%|2.0%|
[sorbs_spam](#sorbs_spam)|64701|65536|18|0.0%|0.6%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|18|0.0%|0.6%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|18|0.0%|0.6%|
[nixspam](#nixspam)|18244|18244|17|0.0%|0.6%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|7|1.0%|0.2%|
[snort_ipfilter](#snort_ipfilter)|9671|9671|6|0.0%|0.2%|
[php_commenters](#php_commenters)|458|458|6|1.3%|0.2%|
[php_dictionary](#php_dictionary)|737|737|5|0.6%|0.1%|
[dragon_http](#dragon_http)|1021|268288|4|0.0%|0.1%|
[php_spammers](#php_spammers)|735|735|3|0.4%|0.1%|
[blocklist_de_mail](#blocklist_de_mail)|18158|18158|3|0.0%|0.1%|
[alienvault_reputation](#alienvault_reputation)|187341|187341|3|0.0%|0.1%|
[iw_spamlist](#iw_spamlist)|3889|3889|2|0.0%|0.0%|
[sorbs_web](#sorbs_web)|598|599|1|0.1%|0.0%|
[php_harvesters](#php_harvesters)|408|408|1|0.2%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|1|0.1%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.0%|
[et_tor](#et_tor)|6500|6500|1|0.0%|0.0%|
[dm_tor](#dm_tor)|6407|6407|1|0.0%|0.0%|
[bm_tor](#bm_tor)|6428|6428|1|0.0%|0.0%|

## ri_web_proxies

[rosinstrument.com](http://www.rosinstrument.com) open HTTP proxies (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://tools.rosinstrument.com/proxy/l100.xml).

The last time downloaded was found to be dated: Fri Jun 12 03:29:31 UTC 2015.

The ipset `ri_web_proxies` has **7870** entries, **7870** unique IPs.

The following table shows the overlaps of `ri_web_proxies` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ri_web_proxies`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ri_web_proxies`.
- ` this % ` is the percentage **of this ipset (`ri_web_proxies`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_proxies](#firehol_proxies)|12738|13016|7870|60.4%|100.0%|
[firehol_anonymous](#firehol_anonymous)|19227|83278|7870|9.4%|100.0%|
[firehol_level3](#firehol_level3)|109614|9627353|3745|0.0%|47.5%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|3698|3.9%|46.9%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|1477|5.0%|18.7%|
[ri_connect_proxies](#ri_connect_proxies)|2828|2828|1207|42.6%|15.3%|
[xroxy](#xroxy)|2171|2171|963|44.3%|12.2%|
[proxyrss](#proxyrss)|1738|1738|681|39.1%|8.6%|
[firehol_level2](#firehol_level2)|21690|33293|648|1.9%|8.2%|
[proxz](#proxz)|1339|1339|612|45.7%|7.7%|
[blocklist_de](#blocklist_de)|28132|28132|469|1.6%|5.9%|
[stopforumspam_1d](#stopforumspam_1d)|6683|6683|417|6.2%|5.2%|
[blocklist_de_bots](#blocklist_de_bots)|2960|2960|382|12.9%|4.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|224|0.0%|2.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|220|0.0%|2.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|156|0.0%|1.9%|
[sorbs_spam](#sorbs_spam)|64701|65536|145|0.2%|1.8%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|145|0.2%|1.8%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|145|0.2%|1.8%|
[nixspam](#nixspam)|18244|18244|110|0.6%|1.3%|
[blocklist_de_mail](#blocklist_de_mail)|18158|18158|86|0.4%|1.0%|
[php_dictionary](#php_dictionary)|737|737|67|9.0%|0.8%|
[snort_ipfilter](#snort_ipfilter)|9671|9671|64|0.6%|0.8%|
[php_spammers](#php_spammers)|735|735|54|7.3%|0.6%|
[php_commenters](#php_commenters)|458|458|30|6.5%|0.3%|
[sorbs_web](#sorbs_web)|598|599|22|3.6%|0.2%|
[dragon_http](#dragon_http)|1021|268288|20|0.0%|0.2%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|15|2.2%|0.1%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|10|1.9%|0.1%|
[iw_spamlist](#iw_spamlist)|3889|3889|9|0.2%|0.1%|
[blocklist_de_strongips](#blocklist_de_strongips)|169|169|8|4.7%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|6|0.0%|0.0%|
[et_tor](#et_tor)|6500|6500|5|0.0%|0.0%|
[dm_tor](#dm_tor)|6407|6407|5|0.0%|0.0%|
[bm_tor](#bm_tor)|6428|6428|5|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|4|0.0%|0.0%|
[alienvault_reputation](#alienvault_reputation)|187341|187341|4|0.0%|0.0%|
[php_harvesters](#php_harvesters)|408|408|2|0.4%|0.0%|
[sslbl](#sslbl)|370|370|1|0.2%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|1|0.0%|0.0%|
[firehol_level1](#firehol_level1)|5137|688854747|1|0.0%|0.0%|
[et_compromised](#et_compromised)|1704|1704|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1693|1693|1|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2216|2216|1|0.0%|0.0%|

## shunlist

[AutoShun.org](http://autoshun.org/) IPs identified as hostile by correlating logs from distributed snort installations running the autoshun plugin

Source is downloaded from [this link](http://www.autoshun.org/files/shunlist.csv).

The last time downloaded was found to be dated: Fri Jun 12 03:30:03 UTC 2015.

The ipset `shunlist` has **1172** entries, **1172** unique IPs.

The following table shows the overlaps of `shunlist` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `shunlist`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `shunlist`.
- ` this % ` is the percentage **of this ipset (`shunlist`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level3](#firehol_level3)|109614|9627353|1172|0.0%|100.0%|
[alienvault_reputation](#alienvault_reputation)|187341|187341|1154|0.6%|98.4%|
[openbl_60d](#openbl_60d)|6974|6974|459|6.5%|39.1%|
[openbl_30d](#openbl_30d)|2803|2803|433|15.4%|36.9%|
[dragon_sshpauth](#dragon_sshpauth)|1613|1675|380|22.6%|32.4%|
[firehol_level2](#firehol_level2)|21690|33293|368|1.1%|31.3%|
[blocklist_de](#blocklist_de)|28132|28132|363|1.2%|30.9%|
[et_compromised](#et_compromised)|1704|1704|338|19.8%|28.8%|
[bruteforceblocker](#bruteforceblocker)|1693|1693|338|19.9%|28.8%|
[blocklist_de_ssh](#blocklist_de_ssh)|2216|2216|321|14.4%|27.3%|
[openbl_7d](#openbl_7d)|633|633|201|31.7%|17.1%|
[firehol_level1](#firehol_level1)|5137|688854747|159|0.0%|13.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|118|0.0%|10.0%|
[et_block](#et_block)|1000|18343756|101|0.0%|8.6%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|90|0.0%|7.6%|
[dshield](#dshield)|20|5120|83|1.6%|7.0%|
[openbl_1d](#openbl_1d)|140|140|73|52.1%|6.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|69|0.0%|5.8%|
[sslbl](#sslbl)|370|370|58|15.6%|4.9%|
[blocklist_de_apache](#blocklist_de_apache)|14292|14292|38|0.2%|3.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|25|0.0%|2.1%|
[ciarmy](#ciarmy)|397|397|25|6.2%|2.1%|
[dragon_http](#dragon_http)|1021|268288|24|0.0%|2.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|169|169|19|11.2%|1.6%|
[voipbl](#voipbl)|10586|10998|13|0.1%|1.1%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|4|0.0%|0.3%|
[blocklist_de_mail](#blocklist_de_mail)|18158|18158|3|0.0%|0.2%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|2|0.0%|0.1%|
[stopforumspam_1d](#stopforumspam_1d)|6683|6683|2|0.0%|0.1%|
[sorbs_spam](#sorbs_spam)|64701|65536|2|0.0%|0.1%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|2|0.0%|0.1%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|2|0.0%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2|0.0%|0.1%|
[dragon_vncprobe](#dragon_vncprobe)|87|87|2|2.2%|0.1%|
[blocklist_de_imap](#blocklist_de_imap)|2800|2800|2|0.0%|0.1%|
[tor_exits](#tor_exits)|1111|1111|1|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9671|9671|1|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|1|0.1%|0.0%|
[firehol_proxies](#firehol_proxies)|12738|13016|1|0.0%|0.0%|
[firehol_anonymous](#firehol_anonymous)|19227|83278|1|0.0%|0.0%|
[et_tor](#et_tor)|6500|6500|1|0.0%|0.0%|
[dm_tor](#dm_tor)|6407|6407|1|0.0%|0.0%|
[bm_tor](#bm_tor)|6428|6428|1|0.0%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|83|83|1|1.2%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2846|2846|1|0.0%|0.0%|

## snort_ipfilter

[labs.snort.org](https://labs.snort.org/) supplied IP blacklist (this list seems to be updated frequently, but we found no information about it)

Source is downloaded from [this link](http://labs.snort.org/feeds/ip-filter.blf).

The last time downloaded was found to be dated: Thu Jun 11 16:00:00 UTC 2015.

The ipset `snort_ipfilter` has **9671** entries, **9671** unique IPs.

The following table shows the overlaps of `snort_ipfilter` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `snort_ipfilter`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `snort_ipfilter`.
- ` this % ` is the percentage **of this ipset (`snort_ipfilter`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level3](#firehol_level3)|109614|9627353|9671|0.1%|100.0%|
[firehol_anonymous](#firehol_anonymous)|19227|83278|1233|1.4%|12.7%|
[et_tor](#et_tor)|6500|6500|1092|16.8%|11.2%|
[tor_exits](#tor_exits)|1111|1111|1070|96.3%|11.0%|
[bm_tor](#bm_tor)|6428|6428|1048|16.3%|10.8%|
[dm_tor](#dm_tor)|6407|6407|1040|16.2%|10.7%|
[sorbs_spam](#sorbs_spam)|64701|65536|846|1.2%|8.7%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|846|1.2%|8.7%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|846|1.2%|8.7%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|812|0.8%|8.3%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|673|2.3%|6.9%|
[firehol_level2](#firehol_level2)|21690|33293|515|1.5%|5.3%|
[stopforumspam_1d](#stopforumspam_1d)|6683|6683|330|4.9%|3.4%|
[firehol_proxies](#firehol_proxies)|12738|13016|330|2.5%|3.4%|
[firehol_level1](#firehol_level1)|5137|688854747|300|0.0%|3.1%|
[et_block](#et_block)|1000|18343756|297|0.0%|3.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|241|0.0%|2.4%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|237|45.2%|2.4%|
[blocklist_de](#blocklist_de)|28132|28132|214|0.7%|2.2%|
[zeus](#zeus)|230|230|200|86.9%|2.0%|
[zeus_badips](#zeus_badips)|202|202|178|88.1%|1.8%|
[nixspam](#nixspam)|18244|18244|174|0.9%|1.7%|
[blocklist_de_mail](#blocklist_de_mail)|18158|18158|173|0.9%|1.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|138|0.0%|1.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|116|0.0%|1.1%|
[alienvault_reputation](#alienvault_reputation)|187341|187341|108|0.0%|1.1%|
[php_dictionary](#php_dictionary)|737|737|91|12.3%|0.9%|
[php_spammers](#php_spammers)|735|735|85|11.5%|0.8%|
[feodo](#feodo)|105|105|83|79.0%|0.8%|
[php_commenters](#php_commenters)|458|458|71|15.5%|0.7%|
[ri_web_proxies](#ri_web_proxies)|7870|7870|64|0.8%|0.6%|
[sorbs_web](#sorbs_web)|598|599|55|9.1%|0.5%|
[iw_spamlist](#iw_spamlist)|3889|3889|49|1.2%|0.5%|
[xroxy](#xroxy)|2171|2171|41|1.8%|0.4%|
[sslbl](#sslbl)|370|370|31|8.3%|0.3%|
[blocklist_de_apache](#blocklist_de_apache)|14292|14292|30|0.2%|0.3%|
[proxz](#proxz)|1339|1339|27|2.0%|0.2%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2846|2846|27|0.9%|0.2%|
[openbl_60d](#openbl_60d)|6974|6974|24|0.3%|0.2%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|18|0.0%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|14|0.0%|0.1%|
[blocklist_de_bots](#blocklist_de_bots)|2960|2960|14|0.4%|0.1%|
[php_harvesters](#php_harvesters)|408|408|11|2.6%|0.1%|
[palevo](#palevo)|13|13|11|84.6%|0.1%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|11|0.8%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|11|0.0%|0.1%|
[dragon_http](#dragon_http)|1021|268288|11|0.0%|0.1%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|6|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2828|2828|6|0.2%|0.0%|
[sorbs_socks](#sorbs_socks)|7|7|4|57.1%|0.0%|
[sorbs_misc](#sorbs_misc)|7|7|4|57.1%|0.0%|
[sorbs_http](#sorbs_http)|7|7|4|57.1%|0.0%|
[proxyrss](#proxyrss)|1738|1738|3|0.1%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2800|2800|3|0.1%|0.0%|
[openbl_30d](#openbl_30d)|2803|2803|2|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|2|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|169|169|2|1.1%|0.0%|
[shunlist](#shunlist)|1172|1172|1|0.0%|0.0%|
[openbl_7d](#openbl_7d)|633|633|1|0.1%|0.0%|
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
[snort_ipfilter](#snort_ipfilter)|9671|9671|4|0.0%|57.1%|
[firehol_level3](#firehol_level3)|109614|9627353|4|0.0%|57.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|2|0.0%|28.5%|
[php_dictionary](#php_dictionary)|737|737|1|0.1%|14.2%|
[nixspam](#nixspam)|18244|18244|1|0.0%|14.2%|
[iw_spamlist](#iw_spamlist)|3889|3889|1|0.0%|14.2%|
[firehol_level2](#firehol_level2)|21690|33293|1|0.0%|14.2%|
[blocklist_de_mail](#blocklist_de_mail)|18158|18158|1|0.0%|14.2%|
[blocklist_de](#blocklist_de)|28132|28132|1|0.0%|14.2%|

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
[snort_ipfilter](#snort_ipfilter)|9671|9671|4|0.0%|57.1%|
[firehol_level3](#firehol_level3)|109614|9627353|4|0.0%|57.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|2|0.0%|28.5%|
[php_dictionary](#php_dictionary)|737|737|1|0.1%|14.2%|
[nixspam](#nixspam)|18244|18244|1|0.0%|14.2%|
[iw_spamlist](#iw_spamlist)|3889|3889|1|0.0%|14.2%|
[firehol_level2](#firehol_level2)|21690|33293|1|0.0%|14.2%|
[blocklist_de_mail](#blocklist_de_mail)|18158|18158|1|0.0%|14.2%|
[blocklist_de](#blocklist_de)|28132|28132|1|0.0%|14.2%|

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
[nixspam](#nixspam)|18244|18244|1695|9.2%|2.5%|
[firehol_level2](#firehol_level2)|21690|33293|1318|3.9%|2.0%|
[blocklist_de](#blocklist_de)|28132|28132|1305|4.6%|1.9%|
[firehol_level3](#firehol_level3)|109614|9627353|1252|0.0%|1.9%|
[blocklist_de_mail](#blocklist_de_mail)|18158|18158|1214|6.6%|1.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|1205|0.0%|1.8%|
[iw_spamlist](#iw_spamlist)|3889|3889|1176|30.2%|1.8%|
[snort_ipfilter](#snort_ipfilter)|9671|9671|846|8.7%|1.2%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|320|0.3%|0.4%|
[sorbs_web](#sorbs_web)|598|599|299|49.9%|0.4%|
[php_dictionary](#php_dictionary)|737|737|214|29.0%|0.3%|
[firehol_anonymous](#firehol_anonymous)|19227|83278|202|0.2%|0.3%|
[firehol_proxies](#firehol_proxies)|12738|13016|197|1.5%|0.3%|
[php_spammers](#php_spammers)|735|735|184|25.0%|0.2%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|173|0.5%|0.2%|
[ri_web_proxies](#ri_web_proxies)|7870|7870|145|1.8%|0.2%|
[alienvault_reputation](#alienvault_reputation)|187341|187341|91|0.0%|0.1%|
[xroxy](#xroxy)|2171|2171|76|3.5%|0.1%|
[dragon_http](#dragon_http)|1021|268288|71|0.0%|0.1%|
[stopforumspam_1d](#stopforumspam_1d)|6683|6683|48|0.7%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2846|2846|46|1.6%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14292|14292|46|0.3%|0.0%|
[proxz](#proxz)|1339|1339|44|3.2%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|37|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2800|2800|29|1.0%|0.0%|
[php_commenters](#php_commenters)|458|458|27|5.8%|0.0%|
[firehol_level1](#firehol_level1)|5137|688854747|25|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|2960|2960|23|0.7%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|20|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|20|0.0%|0.0%|
[et_block](#et_block)|1000|18343756|20|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2828|2828|18|0.6%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|17|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|1586|1586|17|1.0%|0.0%|
[php_harvesters](#php_harvesters)|408|408|16|3.9%|0.0%|
[sorbs_socks](#sorbs_socks)|7|7|7|100.0%|0.0%|
[sorbs_misc](#sorbs_misc)|7|7|7|100.0%|0.0%|
[sorbs_http](#sorbs_http)|7|7|7|100.0%|0.0%|
[proxyrss](#proxyrss)|1738|1738|7|0.4%|0.0%|
[sorbs_smtp](#sorbs_smtp)|6|6|6|100.0%|0.0%|
[tor_exits](#tor_exits)|1111|1111|5|0.4%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2216|2216|5|0.2%|0.0%|
[et_tor](#et_tor)|6500|6500|4|0.0%|0.0%|
[dm_tor](#dm_tor)|6407|6407|4|0.0%|0.0%|
[bm_tor](#bm_tor)|6428|6428|4|0.0%|0.0%|
[voipbl](#voipbl)|10586|10998|3|0.0%|0.0%|
[et_compromised](#et_compromised)|1704|1704|3|0.1%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1693|1693|3|0.1%|0.0%|
[shunlist](#shunlist)|1172|1172|2|0.1%|0.0%|
[openbl_60d](#openbl_60d)|6974|6974|2|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|2|0.1%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|169|169|2|1.1%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|1|0.1%|0.0%|
[malc0de](#malc0de)|276|276|1|0.3%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|1|0.1%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.0%|
[dragon_sshpauth](#dragon_sshpauth)|1613|1675|1|0.0%|0.0%|

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
[nixspam](#nixspam)|18244|18244|1695|9.2%|2.5%|
[firehol_level2](#firehol_level2)|21690|33293|1318|3.9%|2.0%|
[blocklist_de](#blocklist_de)|28132|28132|1305|4.6%|1.9%|
[firehol_level3](#firehol_level3)|109614|9627353|1252|0.0%|1.9%|
[blocklist_de_mail](#blocklist_de_mail)|18158|18158|1214|6.6%|1.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|1205|0.0%|1.8%|
[iw_spamlist](#iw_spamlist)|3889|3889|1176|30.2%|1.8%|
[snort_ipfilter](#snort_ipfilter)|9671|9671|846|8.7%|1.2%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|320|0.3%|0.4%|
[sorbs_web](#sorbs_web)|598|599|299|49.9%|0.4%|
[php_dictionary](#php_dictionary)|737|737|214|29.0%|0.3%|
[firehol_anonymous](#firehol_anonymous)|19227|83278|202|0.2%|0.3%|
[firehol_proxies](#firehol_proxies)|12738|13016|197|1.5%|0.3%|
[php_spammers](#php_spammers)|735|735|184|25.0%|0.2%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|173|0.5%|0.2%|
[ri_web_proxies](#ri_web_proxies)|7870|7870|145|1.8%|0.2%|
[alienvault_reputation](#alienvault_reputation)|187341|187341|91|0.0%|0.1%|
[xroxy](#xroxy)|2171|2171|76|3.5%|0.1%|
[dragon_http](#dragon_http)|1021|268288|71|0.0%|0.1%|
[stopforumspam_1d](#stopforumspam_1d)|6683|6683|48|0.7%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2846|2846|46|1.6%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14292|14292|46|0.3%|0.0%|
[proxz](#proxz)|1339|1339|44|3.2%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|37|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2800|2800|29|1.0%|0.0%|
[php_commenters](#php_commenters)|458|458|27|5.8%|0.0%|
[firehol_level1](#firehol_level1)|5137|688854747|25|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|2960|2960|23|0.7%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|20|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|20|0.0%|0.0%|
[et_block](#et_block)|1000|18343756|20|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2828|2828|18|0.6%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|17|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|1586|1586|17|1.0%|0.0%|
[php_harvesters](#php_harvesters)|408|408|16|3.9%|0.0%|
[sorbs_socks](#sorbs_socks)|7|7|7|100.0%|0.0%|
[sorbs_misc](#sorbs_misc)|7|7|7|100.0%|0.0%|
[sorbs_http](#sorbs_http)|7|7|7|100.0%|0.0%|
[proxyrss](#proxyrss)|1738|1738|7|0.4%|0.0%|
[sorbs_smtp](#sorbs_smtp)|6|6|6|100.0%|0.0%|
[tor_exits](#tor_exits)|1111|1111|5|0.4%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2216|2216|5|0.2%|0.0%|
[et_tor](#et_tor)|6500|6500|4|0.0%|0.0%|
[dm_tor](#dm_tor)|6407|6407|4|0.0%|0.0%|
[bm_tor](#bm_tor)|6428|6428|4|0.0%|0.0%|
[voipbl](#voipbl)|10586|10998|3|0.0%|0.0%|
[et_compromised](#et_compromised)|1704|1704|3|0.1%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1693|1693|3|0.1%|0.0%|
[shunlist](#shunlist)|1172|1172|2|0.1%|0.0%|
[openbl_60d](#openbl_60d)|6974|6974|2|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|2|0.1%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|169|169|2|1.1%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|1|0.1%|0.0%|
[malc0de](#malc0de)|276|276|1|0.3%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|1|0.1%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.0%|
[dragon_sshpauth](#dragon_sshpauth)|1613|1675|1|0.0%|0.0%|

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
[snort_ipfilter](#snort_ipfilter)|9671|9671|4|0.0%|57.1%|
[firehol_level3](#firehol_level3)|109614|9627353|4|0.0%|57.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|2|0.0%|28.5%|
[php_dictionary](#php_dictionary)|737|737|1|0.1%|14.2%|
[nixspam](#nixspam)|18244|18244|1|0.0%|14.2%|
[iw_spamlist](#iw_spamlist)|3889|3889|1|0.0%|14.2%|
[firehol_level2](#firehol_level2)|21690|33293|1|0.0%|14.2%|
[blocklist_de_mail](#blocklist_de_mail)|18158|18158|1|0.0%|14.2%|
[blocklist_de](#blocklist_de)|28132|28132|1|0.0%|14.2%|

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
[nixspam](#nixspam)|18244|18244|1716|9.4%|2.6%|
[firehol_level2](#firehol_level2)|21690|33293|1326|3.9%|2.0%|
[blocklist_de](#blocklist_de)|28132|28132|1313|4.6%|2.0%|
[firehol_level3](#firehol_level3)|109614|9627353|1254|0.0%|1.9%|
[blocklist_de_mail](#blocklist_de_mail)|18158|18158|1222|6.7%|1.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|1208|0.0%|1.8%|
[iw_spamlist](#iw_spamlist)|3889|3889|1182|30.3%|1.8%|
[snort_ipfilter](#snort_ipfilter)|9671|9671|846|8.7%|1.2%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|320|0.3%|0.4%|
[sorbs_web](#sorbs_web)|598|599|300|50.0%|0.4%|
[php_dictionary](#php_dictionary)|737|737|214|29.0%|0.3%|
[firehol_anonymous](#firehol_anonymous)|19227|83278|202|0.2%|0.3%|
[firehol_proxies](#firehol_proxies)|12738|13016|197|1.5%|0.3%|
[php_spammers](#php_spammers)|735|735|184|25.0%|0.2%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|173|0.5%|0.2%|
[ri_web_proxies](#ri_web_proxies)|7870|7870|145|1.8%|0.2%|
[alienvault_reputation](#alienvault_reputation)|187341|187341|91|0.0%|0.1%|
[xroxy](#xroxy)|2171|2171|76|3.5%|0.1%|
[dragon_http](#dragon_http)|1021|268288|72|0.0%|0.1%|
[stopforumspam_1d](#stopforumspam_1d)|6683|6683|48|0.7%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2846|2846|46|1.6%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14292|14292|46|0.3%|0.0%|
[proxz](#proxz)|1339|1339|44|3.2%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|38|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2800|2800|30|1.0%|0.0%|
[php_commenters](#php_commenters)|458|458|27|5.8%|0.0%|
[firehol_level1](#firehol_level1)|5137|688854747|25|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|2960|2960|23|0.7%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|20|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|20|0.0%|0.0%|
[et_block](#et_block)|1000|18343756|20|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2828|2828|18|0.6%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|17|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|1586|1586|17|1.0%|0.0%|
[php_harvesters](#php_harvesters)|408|408|16|3.9%|0.0%|
[sorbs_socks](#sorbs_socks)|7|7|7|100.0%|0.0%|
[sorbs_misc](#sorbs_misc)|7|7|7|100.0%|0.0%|
[sorbs_http](#sorbs_http)|7|7|7|100.0%|0.0%|
[proxyrss](#proxyrss)|1738|1738|7|0.4%|0.0%|
[tor_exits](#tor_exits)|1111|1111|5|0.4%|0.0%|
[sorbs_smtp](#sorbs_smtp)|6|6|5|83.3%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2216|2216|5|0.2%|0.0%|
[et_tor](#et_tor)|6500|6500|4|0.0%|0.0%|
[dm_tor](#dm_tor)|6407|6407|4|0.0%|0.0%|
[bm_tor](#bm_tor)|6428|6428|4|0.0%|0.0%|
[voipbl](#voipbl)|10586|10998|3|0.0%|0.0%|
[et_compromised](#et_compromised)|1704|1704|3|0.1%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1693|1693|3|0.1%|0.0%|
[shunlist](#shunlist)|1172|1172|2|0.1%|0.0%|
[openbl_60d](#openbl_60d)|6974|6974|2|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|2|0.1%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|169|169|2|1.1%|0.0%|
[virbl](#virbl)|23|23|1|4.3%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|1|0.1%|0.0%|
[malc0de](#malc0de)|276|276|1|0.3%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|1|0.1%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.0%|
[dragon_sshpauth](#dragon_sshpauth)|1613|1675|1|0.0%|0.0%|

## sorbs_web

[Sorbs.net](https://www.sorbs.net/) WEB exploits, extracted from deltas.

Source is downloaded from [this link]().

The last time downloaded was found to be dated: Fri Jun 12 03:04:04 UTC 2015.

The ipset `sorbs_web` has **598** entries, **599** unique IPs.

The following table shows the overlaps of `sorbs_web` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `sorbs_web`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `sorbs_web`.
- ` this % ` is the percentage **of this ipset (`sorbs_web`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[sorbs_spam](#sorbs_spam)|64701|65536|300|0.4%|50.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|299|0.4%|49.9%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|299|0.4%|49.9%|
[nixspam](#nixspam)|18244|18244|90|0.4%|15.0%|
[firehol_level3](#firehol_level3)|109614|9627353|73|0.0%|12.1%|
[firehol_level2](#firehol_level2)|21690|33293|69|0.2%|11.5%|
[blocklist_de](#blocklist_de)|28132|28132|69|0.2%|11.5%|
[blocklist_de_mail](#blocklist_de_mail)|18158|18158|63|0.3%|10.5%|
[snort_ipfilter](#snort_ipfilter)|9671|9671|55|0.5%|9.1%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|47|0.0%|7.8%|
[php_dictionary](#php_dictionary)|737|737|33|4.4%|5.5%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|31|0.1%|5.1%|
[firehol_proxies](#firehol_proxies)|12738|13016|30|0.2%|5.0%|
[firehol_anonymous](#firehol_anonymous)|19227|83278|30|0.0%|5.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|28|0.0%|4.6%|
[php_spammers](#php_spammers)|735|735|27|3.6%|4.5%|
[iw_spamlist](#iw_spamlist)|3889|3889|26|0.6%|4.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|23|0.0%|3.8%|
[ri_web_proxies](#ri_web_proxies)|7870|7870|22|0.2%|3.6%|
[xroxy](#xroxy)|2171|2171|15|0.6%|2.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|15|0.0%|2.5%|
[stopforumspam_1d](#stopforumspam_1d)|6683|6683|8|0.1%|1.3%|
[proxz](#proxz)|1339|1339|8|0.5%|1.3%|
[blocklist_de_bots](#blocklist_de_bots)|2960|2960|5|0.1%|0.8%|
[php_commenters](#php_commenters)|458|458|3|0.6%|0.5%|
[blocklist_de_strongips](#blocklist_de_strongips)|169|169|2|1.1%|0.3%|
[ri_connect_proxies](#ri_connect_proxies)|2828|2828|1|0.0%|0.1%|
[proxyrss](#proxyrss)|1738|1738|1|0.0%|0.1%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|1|0.0%|0.1%|
[dragon_http](#dragon_http)|1021|268288|1|0.0%|0.1%|
[blocklist_de_ftp](#blocklist_de_ftp)|1586|1586|1|0.0%|0.1%|
[alienvault_reputation](#alienvault_reputation)|187341|187341|1|0.0%|0.1%|

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
[firehol_level3](#firehol_level3)|109614|9627353|6933039|72.0%|37.8%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|6932480|75.5%|37.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|2272265|0.2%|12.3%|
[fullbogons](#fullbogons)|3775|670173256|151552|0.0%|0.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|130368|0.0%|0.7%|
[alienvault_reputation](#alienvault_reputation)|187341|187341|1385|0.7%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1037|0.3%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|1014|1.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|512|0.1%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|269|0.9%|0.0%|
[firehol_level2](#firehol_level2)|21690|33293|258|0.7%|0.0%|
[dshield](#dshield)|20|5120|256|5.0%|0.0%|
[dragon_http](#dragon_http)|1021|268288|256|0.0%|0.0%|
[openbl_60d](#openbl_60d)|6974|6974|235|3.3%|0.0%|
[blocklist_de](#blocklist_de)|28132|28132|193|0.6%|0.0%|
[openbl_30d](#openbl_30d)|2803|2803|119|4.2%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2216|2216|112|5.0%|0.0%|
[dragon_sshpauth](#dragon_sshpauth)|1613|1675|98|5.8%|0.0%|
[shunlist](#shunlist)|1172|1172|90|7.6%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6683|6683|80|1.1%|0.0%|
[et_compromised](#et_compromised)|1704|1704|65|3.8%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1693|1693|61|3.6%|0.0%|
[nixspam](#nixspam)|18244|18244|59|0.3%|0.0%|
[openbl_7d](#openbl_7d)|633|633|52|8.2%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|2960|2960|51|1.7%|0.0%|
[php_commenters](#php_commenters)|458|458|29|6.3%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|29|2.2%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|18158|18158|22|0.1%|0.0%|
[sorbs_spam](#sorbs_spam)|64701|65536|20|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|20|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|20|0.0%|0.0%|
[openbl_1d](#openbl_1d)|140|140|20|14.2%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9671|9671|18|0.1%|0.0%|
[zeus_badips](#zeus_badips)|202|202|15|7.4%|0.0%|
[zeus](#zeus)|230|230|15|6.5%|0.0%|
[voipbl](#voipbl)|10586|10998|14|0.1%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2800|2800|10|0.3%|0.0%|
[php_dictionary](#php_dictionary)|737|737|6|0.8%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|6|0.4%|0.0%|
[firehol_anonymous](#firehol_anonymous)|19227|83278|6|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|169|169|6|3.5%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|5|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2846|2846|5|0.1%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14292|14292|5|0.0%|0.0%|
[php_spammers](#php_spammers)|735|735|4|0.5%|0.0%|
[nt_malware_http](#nt_malware_http)|69|69|4|5.7%|0.0%|
[malc0de](#malc0de)|276|276|4|1.4%|0.0%|
[nt_malware_irc](#nt_malware_irc)|43|43|3|6.9%|0.0%|
[iw_spamlist](#iw_spamlist)|3889|3889|3|0.0%|0.0%|
[firehol_proxies](#firehol_proxies)|12738|13016|3|0.0%|0.0%|
[et_tor](#et_tor)|6500|6500|3|0.0%|0.0%|
[dm_tor](#dm_tor)|6407|6407|3|0.0%|0.0%|
[bm_tor](#bm_tor)|6428|6428|3|0.0%|0.0%|
[tor_exits](#tor_exits)|1111|1111|2|0.1%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|2|0.3%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|83|83|2|2.4%|0.0%|
[virbl](#virbl)|23|23|1|4.3%|0.0%|
[sslbl](#sslbl)|370|370|1|0.2%|0.0%|
[php_harvesters](#php_harvesters)|408|408|1|0.2%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|1|0.1%|0.0%|
[et_botcc](#et_botcc)|505|505|1|0.1%|0.0%|
[dragon_vncprobe](#dragon_vncprobe)|87|87|1|1.1%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|1586|1586|1|0.0%|0.0%|

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
[firehol_level3](#firehol_level3)|109614|9627353|85|0.0%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|75|0.0%|0.0%|
[sorbs_spam](#sorbs_spam)|64701|65536|20|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|20|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|20|0.0%|0.0%|
[alienvault_reputation](#alienvault_reputation)|187341|187341|14|0.0%|0.0%|
[php_commenters](#php_commenters)|458|458|8|1.7%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|7|0.0%|0.0%|
[firehol_level2](#firehol_level2)|21690|33293|7|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9671|9671|6|0.0%|0.0%|
[zeus_badips](#zeus_badips)|202|202|5|2.4%|0.0%|
[zeus](#zeus)|230|230|5|2.1%|0.0%|
[blocklist_de](#blocklist_de)|28132|28132|5|0.0%|0.0%|
[nixspam](#nixspam)|18244|18244|4|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6683|6683|3|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|169|169|2|1.1%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|18158|18158|2|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|2960|2960|2|0.0%|0.0%|
[php_harvesters](#php_harvesters)|408|408|1|0.2%|0.0%|
[openbl_60d](#openbl_60d)|6974|6974|1|0.0%|0.0%|
[openbl_30d](#openbl_30d)|2803|2803|1|0.0%|0.0%|
[malc0de](#malc0de)|276|276|1|0.3%|0.0%|
[iw_spamlist](#iw_spamlist)|3889|3889|1|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14292|14292|1|0.0%|0.0%|

## sslbl

[Abuse.ch SSL Blacklist](https://sslbl.abuse.ch/) bad SSL traffic related to malware or botnet activities - **excellent list**

Source is downloaded from [this link](https://sslbl.abuse.ch/blacklist/sslipblacklist.csv).

The last time downloaded was found to be dated: Fri Jun 12 03:45:04 UTC 2015.

The ipset `sslbl` has **370** entries, **370** unique IPs.

The following table shows the overlaps of `sslbl` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `sslbl`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `sslbl`.
- ` this % ` is the percentage **of this ipset (`sslbl`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level1](#firehol_level1)|5137|688854747|370|0.0%|100.0%|
[firehol_level3](#firehol_level3)|109614|9627353|89|0.0%|24.0%|
[alienvault_reputation](#alienvault_reputation)|187341|187341|65|0.0%|17.5%|
[shunlist](#shunlist)|1172|1172|58|4.9%|15.6%|
[et_block](#et_block)|1000|18343756|39|0.0%|10.5%|
[feodo](#feodo)|105|105|38|36.1%|10.2%|
[snort_ipfilter](#snort_ipfilter)|9671|9671|31|0.3%|8.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|28|0.0%|7.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|6|0.0%|1.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|3|0.0%|0.8%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|1|0.0%|0.2%|
[ri_web_proxies](#ri_web_proxies)|7870|7870|1|0.0%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.2%|
[firehol_proxies](#firehol_proxies)|12738|13016|1|0.0%|0.2%|
[firehol_anonymous](#firehol_anonymous)|19227|83278|1|0.0%|0.2%|
[dragon_sshpauth](#dragon_sshpauth)|1613|1675|1|0.0%|0.2%|
[dragon_http](#dragon_http)|1021|268288|1|0.0%|0.2%|

## stopforumspam_1d

[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers in the last 24 hours - **excellent list**

Source is downloaded from [this link](http://www.stopforumspam.com/downloads/listed_ip_1.zip).

The last time downloaded was found to be dated: Fri Jun 12 03:00:02 UTC 2015.

The ipset `stopforumspam_1d` has **6683** entries, **6683** unique IPs.

The following table shows the overlaps of `stopforumspam_1d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `stopforumspam_1d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `stopforumspam_1d`.
- ` this % ` is the percentage **of this ipset (`stopforumspam_1d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|21690|33293|6683|20.0%|100.0%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|6494|22.3%|97.1%|
[firehol_level3](#firehol_level3)|109614|9627353|5168|0.0%|77.3%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|5142|5.4%|76.9%|
[blocklist_de](#blocklist_de)|28132|28132|1538|5.4%|23.0%|
[blocklist_de_bots](#blocklist_de_bots)|2960|2960|1473|49.7%|22.0%|
[firehol_anonymous](#firehol_anonymous)|19227|83278|946|1.1%|14.1%|
[firehol_proxies](#firehol_proxies)|12738|13016|816|6.2%|12.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|516|0.0%|7.7%|
[ri_web_proxies](#ri_web_proxies)|7870|7870|417|5.2%|6.2%|
[proxyrss](#proxyrss)|1738|1738|338|19.4%|5.0%|
[snort_ipfilter](#snort_ipfilter)|9671|9671|330|3.4%|4.9%|
[tor_exits](#tor_exits)|1111|1111|303|27.2%|4.5%|
[et_tor](#et_tor)|6500|6500|298|4.5%|4.4%|
[dm_tor](#dm_tor)|6407|6407|289|4.5%|4.3%|
[bm_tor](#bm_tor)|6428|6428|289|4.4%|4.3%|
[xroxy](#xroxy)|2171|2171|203|9.3%|3.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|194|37.0%|2.9%|
[proxz](#proxz)|1339|1339|189|14.1%|2.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|180|0.0%|2.6%|
[php_commenters](#php_commenters)|458|458|171|37.3%|2.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|126|0.0%|1.8%|
[blocklist_de_strongips](#blocklist_de_strongips)|169|169|102|60.3%|1.5%|
[ri_connect_proxies](#ri_connect_proxies)|2828|2828|101|3.5%|1.5%|
[firehol_level1](#firehol_level1)|5137|688854747|92|0.0%|1.3%|
[et_block](#et_block)|1000|18343756|88|0.0%|1.3%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|80|0.0%|1.1%|
[blocklist_de_apache](#blocklist_de_apache)|14292|14292|60|0.4%|0.8%|
[nixspam](#nixspam)|18244|18244|58|0.3%|0.8%|
[sorbs_spam](#sorbs_spam)|64701|65536|48|0.0%|0.7%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|48|0.0%|0.7%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|48|0.0%|0.7%|
[blocklist_de_mail](#blocklist_de_mail)|18158|18158|48|0.2%|0.7%|
[php_harvesters](#php_harvesters)|408|408|47|11.5%|0.7%|
[alienvault_reputation](#alienvault_reputation)|187341|187341|42|0.0%|0.6%|
[php_spammers](#php_spammers)|735|735|40|5.4%|0.5%|
[php_dictionary](#php_dictionary)|737|737|31|4.2%|0.4%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|31|0.0%|0.4%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2846|2846|27|0.9%|0.4%|
[openbl_60d](#openbl_60d)|6974|6974|16|0.2%|0.2%|
[dragon_http](#dragon_http)|1021|268288|11|0.0%|0.1%|
[dshield](#dshield)|20|5120|9|0.1%|0.1%|
[sorbs_web](#sorbs_web)|598|599|8|1.3%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|7|0.0%|0.1%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|5|0.7%|0.0%|
[voipbl](#voipbl)|10586|10998|4|0.0%|0.0%|
[iw_spamlist](#iw_spamlist)|3889|3889|4|0.1%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|3|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|1586|1586|3|0.1%|0.0%|
[shunlist](#shunlist)|1172|1172|2|0.1%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|2|0.0%|0.0%|
[et_compromised](#et_compromised)|1704|1704|2|0.1%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1693|1693|2|0.1%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2800|2800|2|0.0%|0.0%|
[zeus_badips](#zeus_badips)|202|202|1|0.4%|0.0%|
[zeus](#zeus)|230|230|1|0.4%|0.0%|
[openbl_30d](#openbl_30d)|2803|2803|1|0.0%|0.0%|
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
[firehol_level3](#firehol_level3)|109614|9627353|94309|0.9%|100.0%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|27620|95.1%|29.2%|
[firehol_level2](#firehol_level2)|21690|33293|6463|19.4%|6.8%|
[firehol_anonymous](#firehol_anonymous)|19227|83278|6238|7.4%|6.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|5830|0.0%|6.1%|
[firehol_proxies](#firehol_proxies)|12738|13016|5636|43.3%|5.9%|
[stopforumspam_1d](#stopforumspam_1d)|6683|6683|5142|76.9%|5.4%|
[ri_web_proxies](#ri_web_proxies)|7870|7870|3698|46.9%|3.9%|
[blocklist_de](#blocklist_de)|28132|28132|2710|9.6%|2.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|2476|0.0%|2.6%|
[blocklist_de_bots](#blocklist_de_bots)|2960|2960|2358|79.6%|2.5%|
[ri_connect_proxies](#ri_connect_proxies)|2828|2828|1585|56.0%|1.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|1522|0.0%|1.6%|
[xroxy](#xroxy)|2171|2171|1285|59.1%|1.3%|
[firehol_level1](#firehol_level1)|5137|688854747|1111|0.0%|1.1%|
[et_block](#et_block)|1000|18343756|1032|0.0%|1.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|1014|0.0%|1.0%|
[snort_ipfilter](#snort_ipfilter)|9671|9671|812|8.3%|0.8%|
[proxz](#proxz)|1339|1339|786|58.7%|0.8%|
[proxyrss](#proxyrss)|1738|1738|756|43.4%|0.8%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|725|0.0%|0.7%|
[et_tor](#et_tor)|6500|6500|651|10.0%|0.6%|
[dm_tor](#dm_tor)|6407|6407|633|9.8%|0.6%|
[bm_tor](#bm_tor)|6428|6428|630|9.8%|0.6%|
[tor_exits](#tor_exits)|1111|1111|624|56.1%|0.6%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|345|65.8%|0.3%|
[php_commenters](#php_commenters)|458|458|334|72.9%|0.3%|
[sorbs_spam](#sorbs_spam)|64701|65536|320|0.4%|0.3%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|320|0.4%|0.3%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|320|0.4%|0.3%|
[blocklist_de_mail](#blocklist_de_mail)|18158|18158|261|1.4%|0.2%|
[nixspam](#nixspam)|18244|18244|216|1.1%|0.2%|
[blocklist_de_apache](#blocklist_de_apache)|14292|14292|198|1.3%|0.2%|
[alienvault_reputation](#alienvault_reputation)|187341|187341|167|0.0%|0.1%|
[php_spammers](#php_spammers)|735|735|151|20.5%|0.1%|
[php_dictionary](#php_dictionary)|737|737|139|18.8%|0.1%|
[blocklist_de_strongips](#blocklist_de_strongips)|169|169|130|76.9%|0.1%|
[dragon_http](#dragon_http)|1021|268288|108|0.0%|0.1%|
[php_harvesters](#php_harvesters)|408|408|87|21.3%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|75|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2846|2846|66|2.3%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|52|0.0%|0.0%|
[sorbs_web](#sorbs_web)|598|599|47|7.8%|0.0%|
[openbl_60d](#openbl_60d)|6974|6974|47|0.6%|0.0%|
[voipbl](#voipbl)|10586|10998|35|0.3%|0.0%|
[dshield](#dshield)|20|5120|21|0.4%|0.0%|
[iw_spamlist](#iw_spamlist)|3889|3889|20|0.5%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|20|3.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|17|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2800|2800|17|0.6%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2216|2216|14|0.6%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|1586|1586|14|0.8%|0.0%|
[et_compromised](#et_compromised)|1704|1704|10|0.5%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1693|1693|9|0.5%|0.0%|
[openbl_30d](#openbl_30d)|2803|2803|5|0.1%|0.0%|
[shunlist](#shunlist)|1172|1172|4|0.3%|0.0%|
[dragon_sshpauth](#dragon_sshpauth)|1613|1675|4|0.2%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|3|0.2%|0.0%|
[zeus_badips](#zeus_badips)|202|202|2|0.9%|0.0%|
[zeus](#zeus)|230|230|2|0.8%|0.0%|
[openbl_7d](#openbl_7d)|633|633|2|0.3%|0.0%|
[nt_malware_http](#nt_malware_http)|69|69|2|2.8%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|2|0.1%|0.0%|
[fullbogons](#fullbogons)|3775|670173256|2|0.0%|0.0%|
[ciarmy](#ciarmy)|397|397|2|0.5%|0.0%|
[openbl_1d](#openbl_1d)|140|140|1|0.7%|0.0%|
[iw_wormlist](#iw_wormlist)|35|35|1|2.8%|0.0%|

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
[firehol_level3](#firehol_level3)|109614|9627353|27642|0.2%|95.2%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|27620|29.2%|95.1%|
[firehol_level2](#firehol_level2)|21690|33293|7415|22.2%|25.5%|
[stopforumspam_1d](#stopforumspam_1d)|6683|6683|6494|97.1%|22.3%|
[firehol_anonymous](#firehol_anonymous)|19227|83278|2753|3.3%|9.4%|
[blocklist_de](#blocklist_de)|28132|28132|2432|8.6%|8.3%|
[firehol_proxies](#firehol_proxies)|12738|13016|2384|18.3%|8.2%|
[blocklist_de_bots](#blocklist_de_bots)|2960|2960|2243|75.7%|7.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|1961|0.0%|6.7%|
[ri_web_proxies](#ri_web_proxies)|7870|7870|1477|18.7%|5.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|736|0.0%|2.5%|
[snort_ipfilter](#snort_ipfilter)|9671|9671|673|6.9%|2.3%|
[proxyrss](#proxyrss)|1738|1738|613|35.2%|2.1%|
[xroxy](#xroxy)|2171|2171|585|26.9%|2.0%|
[et_tor](#et_tor)|6500|6500|547|8.4%|1.8%|
[tor_exits](#tor_exits)|1111|1111|543|48.8%|1.8%|
[dm_tor](#dm_tor)|6407|6407|528|8.2%|1.8%|
[ri_connect_proxies](#ri_connect_proxies)|2828|2828|526|18.5%|1.8%|
[bm_tor](#bm_tor)|6428|6428|525|8.1%|1.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|510|0.0%|1.7%|
[proxz](#proxz)|1339|1339|504|37.6%|1.7%|
[firehol_level1](#firehol_level1)|5137|688854747|291|0.0%|1.0%|
[et_block](#et_block)|1000|18343756|283|0.0%|0.9%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|277|52.8%|0.9%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|269|0.0%|0.9%|
[php_commenters](#php_commenters)|458|458|248|54.1%|0.8%|
[sorbs_spam](#sorbs_spam)|64701|65536|173|0.2%|0.5%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|173|0.2%|0.5%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|173|0.2%|0.5%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|154|0.0%|0.5%|
[blocklist_de_mail](#blocklist_de_mail)|18158|18158|142|0.7%|0.4%|
[nixspam](#nixspam)|18244|18244|140|0.7%|0.4%|
[blocklist_de_strongips](#blocklist_de_strongips)|169|169|116|68.6%|0.3%|
[blocklist_de_apache](#blocklist_de_apache)|14292|14292|116|0.8%|0.3%|
[php_spammers](#php_spammers)|735|735|93|12.6%|0.3%|
[php_dictionary](#php_dictionary)|737|737|93|12.6%|0.3%|
[alienvault_reputation](#alienvault_reputation)|187341|187341|87|0.0%|0.2%|
[php_harvesters](#php_harvesters)|408|408|65|15.9%|0.2%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2846|2846|48|1.6%|0.1%|
[dragon_http](#dragon_http)|1021|268288|32|0.0%|0.1%|
[sorbs_web](#sorbs_web)|598|599|31|5.1%|0.1%|
[openbl_60d](#openbl_60d)|6974|6974|26|0.3%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|21|0.0%|0.0%|
[voipbl](#voipbl)|10586|10998|15|0.1%|0.0%|
[dshield](#dshield)|20|5120|15|0.2%|0.0%|
[iw_spamlist](#iw_spamlist)|3889|3889|11|0.2%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|10|1.5%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|7|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|7|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2800|2800|6|0.2%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|1586|1586|6|0.3%|0.0%|
[et_compromised](#et_compromised)|1704|1704|3|0.1%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1693|1693|3|0.1%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2216|2216|3|0.1%|0.0%|
[shunlist](#shunlist)|1172|1172|2|0.1%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|2|0.1%|0.0%|
[fullbogons](#fullbogons)|3775|670173256|2|0.0%|0.0%|
[zeus_badips](#zeus_badips)|202|202|1|0.4%|0.0%|
[zeus](#zeus)|230|230|1|0.4%|0.0%|
[openbl_30d](#openbl_30d)|2803|2803|1|0.0%|0.0%|
[iw_wormlist](#iw_wormlist)|35|35|1|2.8%|0.0%|
[ciarmy](#ciarmy)|397|397|1|0.2%|0.0%|

## tor_exits

[TorProject.org](https://www.torproject.org) list of all current TOR exit points (TorDNSEL)

Source is downloaded from [this link](https://check.torproject.org/exit-addresses).

The last time downloaded was found to be dated: Fri Jun 12 03:03:29 UTC 2015.

The ipset `tor_exits` has **1111** entries, **1111** unique IPs.

The following table shows the overlaps of `tor_exits` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `tor_exits`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `tor_exits`.
- ` this % ` is the percentage **of this ipset (`tor_exits`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_anonymous](#firehol_anonymous)|19227|83278|1111|1.3%|100.0%|
[firehol_level3](#firehol_level3)|109614|9627353|1072|0.0%|96.4%|
[snort_ipfilter](#snort_ipfilter)|9671|9671|1070|11.0%|96.3%|
[bm_tor](#bm_tor)|6428|6428|1013|15.7%|91.1%|
[dm_tor](#dm_tor)|6407|6407|1004|15.6%|90.3%|
[et_tor](#et_tor)|6500|6500|985|15.1%|88.6%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|624|0.6%|56.1%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|543|1.8%|48.8%|
[firehol_level2](#firehol_level2)|21690|33293|314|0.9%|28.2%|
[stopforumspam_1d](#stopforumspam_1d)|6683|6683|303|4.5%|27.2%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|230|43.8%|20.7%|
[firehol_proxies](#firehol_proxies)|12738|13016|230|1.7%|20.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|126|0.0%|11.3%|
[php_commenters](#php_commenters)|458|458|54|11.7%|4.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|40|0.0%|3.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|37|0.0%|3.3%|
[alienvault_reputation](#alienvault_reputation)|187341|187341|30|0.0%|2.7%|
[openbl_60d](#openbl_60d)|6974|6974|20|0.2%|1.8%|
[blocklist_de_apache](#blocklist_de_apache)|14292|14292|18|0.1%|1.6%|
[blocklist_de](#blocklist_de)|28132|28132|18|0.0%|1.6%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2846|2846|16|0.5%|1.4%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|8|0.0%|0.7%|
[php_harvesters](#php_harvesters)|408|408|6|1.4%|0.5%|
[nixspam](#nixspam)|18244|18244|6|0.0%|0.5%|
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
[blocklist_de_mail](#blocklist_de_mail)|18158|18158|2|0.0%|0.1%|
[shunlist](#shunlist)|1172|1172|1|0.0%|0.0%|
[iw_spamlist](#iw_spamlist)|3889|3889|1|0.0%|0.0%|
[dshield](#dshield)|20|5120|1|0.0%|0.0%|

## virbl

[VirBL](http://virbl.bit.nl/) is a project of which the idea was born during the RIPE-48 meeting. The plan was to get reports of virusscanning mailservers, and put the IP-addresses that were reported to send viruses on a blacklist.

Source is downloaded from [this link](http://virbl.bit.nl/download/virbl.dnsbl.bit.nl.txt).

The last time downloaded was found to be dated: Fri Jun 12 03:42:03 UTC 2015.

The ipset `virbl` has **23** entries, **23** unique IPs.

The following table shows the overlaps of `virbl` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `virbl`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `virbl`.
- ` this % ` is the percentage **of this ipset (`virbl`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level3](#firehol_level3)|109614|9627353|23|0.0%|100.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|1|0.0%|4.3%|
[sorbs_spam](#sorbs_spam)|64701|65536|1|0.0%|4.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|1|0.0%|4.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|4.3%|
[firehol_level1](#firehol_level1)|5137|688854747|1|0.0%|4.3%|
[et_block](#et_block)|1000|18343756|1|0.0%|4.3%|

## voipbl

[VoIPBL.org](http://www.voipbl.org/) a distributed VoIP blacklist that is aimed to protects against VoIP Fraud and minimizing abuse for network that have publicly accessible PBX's. Several algorithms, external sources and manual confirmation are used before they categorize something as an attack and determine the threat level.

Source is downloaded from [this link](http://www.voipbl.org/update/).

The last time downloaded was found to be dated: Fri Jun 12 03:45:15 UTC 2015.

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
[alienvault_reputation](#alienvault_reputation)|187341|187341|176|0.0%|1.6%|
[firehol_anonymous](#firehol_anonymous)|19227|83278|79|0.0%|0.7%|
[firehol_level3](#firehol_level3)|109614|9627353|57|0.0%|0.5%|
[firehol_level2](#firehol_level2)|21690|33293|43|0.1%|0.3%|
[blocklist_de](#blocklist_de)|28132|28132|39|0.1%|0.3%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|35|0.0%|0.3%|
[blocklist_de_sip](#blocklist_de_sip)|83|83|33|39.7%|0.3%|
[dragon_http](#dragon_http)|1021|268288|29|0.0%|0.2%|
[et_block](#et_block)|1000|18343756|18|0.0%|0.1%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|15|0.0%|0.1%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|14|0.0%|0.1%|
[shunlist](#shunlist)|1172|1172|13|1.1%|0.1%|
[openbl_60d](#openbl_60d)|6974|6974|8|0.1%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6683|6683|4|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|4|0.0%|0.0%|
[sorbs_spam](#sorbs_spam)|64701|65536|3|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|3|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|3|0.0%|0.0%|
[openbl_30d](#openbl_30d)|2803|2803|3|0.1%|0.0%|
[et_tor](#et_tor)|6500|6500|3|0.0%|0.0%|
[et_compromised](#et_compromised)|1704|1704|3|0.1%|0.0%|
[dm_tor](#dm_tor)|6407|6407|3|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1693|1693|3|0.1%|0.0%|
[bm_tor](#bm_tor)|6428|6428|3|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|2|0.3%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|2|0.0%|0.0%|
[firehol_proxies](#firehol_proxies)|12738|13016|2|0.0%|0.0%|
[ciarmy](#ciarmy)|397|397|2|0.5%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2216|2216|2|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|18158|18158|2|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14292|14292|2|0.0%|0.0%|
[nixspam](#nixspam)|18244|18244|1|0.0%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.0%|
[dragon_vncprobe](#dragon_vncprobe)|87|87|1|1.1%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2800|2800|1|0.0%|0.0%|

## xroxy

[xroxy.com](http://www.xroxy.com) open proxies (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.xroxy.com/proxyrss.xml).

The last time downloaded was found to be dated: Fri Jun 12 03:33:01 UTC 2015.

The ipset `xroxy` has **2171** entries, **2171** unique IPs.

The following table shows the overlaps of `xroxy` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `xroxy`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `xroxy`.
- ` this % ` is the percentage **of this ipset (`xroxy`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_proxies](#firehol_proxies)|12738|13016|2171|16.6%|100.0%|
[firehol_anonymous](#firehol_anonymous)|19227|83278|2171|2.6%|100.0%|
[firehol_level3](#firehol_level3)|109614|9627353|1301|0.0%|59.9%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|1285|1.3%|59.1%|
[ri_web_proxies](#ri_web_proxies)|7870|7870|963|12.2%|44.3%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|585|2.0%|26.9%|
[proxz](#proxz)|1339|1339|462|34.5%|21.2%|
[ri_connect_proxies](#ri_connect_proxies)|2828|2828|396|14.0%|18.2%|
[proxyrss](#proxyrss)|1738|1738|383|22.0%|17.6%|
[firehol_level2](#firehol_level2)|21690|33293|312|0.9%|14.3%|
[blocklist_de](#blocklist_de)|28132|28132|228|0.8%|10.5%|
[stopforumspam_1d](#stopforumspam_1d)|6683|6683|203|3.0%|9.3%|
[blocklist_de_bots](#blocklist_de_bots)|2960|2960|172|5.8%|7.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|111|0.0%|5.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|104|0.0%|4.7%|
[sorbs_spam](#sorbs_spam)|64701|65536|76|0.1%|3.5%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|76|0.1%|3.5%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|76|0.1%|3.5%|
[nixspam](#nixspam)|18244|18244|68|0.3%|3.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|58|0.0%|2.6%|
[blocklist_de_mail](#blocklist_de_mail)|18158|18158|56|0.3%|2.5%|
[snort_ipfilter](#snort_ipfilter)|9671|9671|41|0.4%|1.8%|
[php_dictionary](#php_dictionary)|737|737|41|5.5%|1.8%|
[php_spammers](#php_spammers)|735|735|34|4.6%|1.5%|
[sorbs_web](#sorbs_web)|598|599|15|2.5%|0.6%|
[php_commenters](#php_commenters)|458|458|13|2.8%|0.5%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|13|1.9%|0.5%|
[blocklist_de_strongips](#blocklist_de_strongips)|169|169|7|4.1%|0.3%|
[dragon_http](#dragon_http)|1021|268288|6|0.0%|0.2%|
[alienvault_reputation](#alienvault_reputation)|187341|187341|5|0.0%|0.2%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|3|0.5%|0.1%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|3|0.0%|0.1%|
[php_harvesters](#php_harvesters)|408|408|2|0.4%|0.0%|
[iw_spamlist](#iw_spamlist)|3889|3889|2|0.0%|0.0%|
[et_tor](#et_tor)|6500|6500|2|0.0%|0.0%|
[dm_tor](#dm_tor)|6407|6407|2|0.0%|0.0%|
[bm_tor](#bm_tor)|6428|6428|2|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.0%|
[et_compromised](#et_compromised)|1704|1704|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1693|1693|1|0.0%|0.0%|

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
[firehol_level3](#firehol_level3)|109614|9627353|203|0.0%|88.2%|
[zeus_badips](#zeus_badips)|202|202|202|100.0%|87.8%|
[snort_ipfilter](#snort_ipfilter)|9671|9671|200|2.0%|86.9%|
[alienvault_reputation](#alienvault_reputation)|187341|187341|61|0.0%|26.5%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|15|0.0%|6.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|14|0.0%|6.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|10|0.0%|4.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|9|0.0%|3.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|7|0.0%|3.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|5|0.0%|2.1%|
[dragon_http](#dragon_http)|1021|268288|3|0.0%|1.3%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|2|0.0%|0.8%|
[openbl_60d](#openbl_60d)|6974|6974|2|0.0%|0.8%|
[openbl_30d](#openbl_30d)|2803|2803|2|0.0%|0.8%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|1|0.0%|0.4%|
[stopforumspam_1d](#stopforumspam_1d)|6683|6683|1|0.0%|0.4%|
[php_commenters](#php_commenters)|458|458|1|0.2%|0.4%|
[openbl_7d](#openbl_7d)|633|633|1|0.1%|0.4%|
[nixspam](#nixspam)|18244|18244|1|0.0%|0.4%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|1|0.0%|0.4%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.4%|
[firehol_level2](#firehol_level2)|21690|33293|1|0.0%|0.4%|

## zeus_badips

[Abuse.ch Zeus tracker](https://zeustracker.abuse.ch) badips includes IPv4 addresses that are used by the ZeuS trojan. It is the recommened blocklist if you want to block only ZeuS IPs. It excludes IP addresses that ZeuS Tracker believes to be hijacked (level 2) or belong to a free web hosting provider (level 3). Hence the false postive rate should be much lower compared to the standard ZeuS IP blocklist. **excellent list**

Source is downloaded from [this link](https://zeustracker.abuse.ch/blocklist.php?download=badips).

The last time downloaded was found to be dated: Fri Jun 12 03:54:21 UTC 2015.

The ipset `zeus_badips` has **202** entries, **202** unique IPs.

The following table shows the overlaps of `zeus_badips` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `zeus_badips`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `zeus_badips`.
- ` this % ` is the percentage **of this ipset (`zeus_badips`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[zeus](#zeus)|230|230|202|87.8%|100.0%|
[firehol_level1](#firehol_level1)|5137|688854747|202|0.0%|100.0%|
[et_block](#et_block)|1000|18343756|202|0.0%|100.0%|
[firehol_level3](#firehol_level3)|109614|9627353|180|0.0%|89.1%|
[snort_ipfilter](#snort_ipfilter)|9671|9671|178|1.8%|88.1%|
[alienvault_reputation](#alienvault_reputation)|187341|187341|37|0.0%|18.3%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|15|0.0%|7.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|10|0.0%|4.9%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|10|0.0%|4.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|8|0.0%|3.9%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|5|0.0%|2.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|4|0.0%|1.9%|
[dragon_http](#dragon_http)|1021|268288|3|0.0%|1.4%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|2|0.0%|0.9%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|1|0.0%|0.4%|
[stopforumspam_1d](#stopforumspam_1d)|6683|6683|1|0.0%|0.4%|
[php_commenters](#php_commenters)|458|458|1|0.2%|0.4%|
[openbl_7d](#openbl_7d)|633|633|1|0.1%|0.4%|
[openbl_60d](#openbl_60d)|6974|6974|1|0.0%|0.4%|
[openbl_30d](#openbl_30d)|2803|2803|1|0.0%|0.4%|
[nixspam](#nixspam)|18244|18244|1|0.0%|0.4%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.4%|
[firehol_level2](#firehol_level2)|21690|33293|1|0.0%|0.4%|
