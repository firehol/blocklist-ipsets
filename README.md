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

The following list was automatically generated on Fri Jun 12 16:11:25 UTC 2015.

The update frequency is the maximum allowed by internal configuration. A list will never be downloaded sooner than the update frequency stated. A list may also not be downloaded, after this frequency expired, if it has not been modified on the server (as reported by HTTP `IF_MODIFIED_SINCE` method).

name|info|type|entries|update|
:--:|:--:|:--:|:-----:|:----:|
[alienvault_reputation](#alienvault_reputation)|[AlienVault.com](https://www.alienvault.com/) IP reputation database (this list seems to include port scanning hosts and to be updated regularly, but we found no information about its retention policy)|ipv4 hash:ip|189217 unique IPs|updated every 6 hours  from [this link](https://reputation.alienvault.com/reputation.generic)
[blocklist_de](#blocklist_de)|[Blocklist.de](https://www.blocklist.de/) IPs that have been detected by fail2ban in the last 48 hours - **excellent list**|ipv4 hash:ip|29129 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/all.txt)
[blocklist_de_apache](#blocklist_de_apache)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service Apache, Apache-DDOS, RFI-Attacks.|ipv4 hash:ip|14109 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/apache.txt)
[blocklist_de_bots](#blocklist_de_bots)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the RFI-Attacks, REG-Bots, IRC-Bots or BadBots (BadBots = he has posted a Spam-Comment on a open Forum or Wiki).|ipv4 hash:ip|3035 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/bots.txt)
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|[Blocklist.de](https://www.blocklist.de/) All IPs which attacks Joomlas, Wordpress and other Web-Logins with Brute-Force Logins.|ipv4 hash:ip|2714 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/bruteforcelogin.txt)
[blocklist_de_ftp](#blocklist_de_ftp)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours for attacks on the Service FTP.|ipv4 hash:ip|1509 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/ftp.txt)
[blocklist_de_imap](#blocklist_de_imap)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours for attacks on the Service imap, sasl, pop3, etc.|ipv4 hash:ip|3535 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/imap.txt)
[blocklist_de_mail](#blocklist_de_mail)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service Mail, Postfix.|ipv4 hash:ip|18292 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/mail.txt)
[blocklist_de_sip](#blocklist_de_sip)|[Blocklist.de](https://www.blocklist.de/) All IP addresses that tried to login in a SIP, VOIP or Asterisk Server and are included in the IPs list from [infiltrated.net](www.infiltrated.net)|ipv4 hash:ip|80 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/sip.txt)
[blocklist_de_ssh](#blocklist_de_ssh)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service SSH.|ipv4 hash:ip|3204 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/ssh.txt)
[blocklist_de_strongips](#blocklist_de_strongips)|[Blocklist.de](https://www.blocklist.de/) All IPs which are older then 2 month and have more then 5.000 attacks.|ipv4 hash:ip|168 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/strongips.txt)
[bm_tor](#bm_tor)|[torstatus.blutmagie.de](https://torstatus.blutmagie.de) list of all TOR network servers|ipv4 hash:ip|6533 unique IPs|updated every 30 mins  from [this link](https://torstatus.blutmagie.de/ip_list_all.php/Tor_ip_list_ALL.csv)
[bogons](#bogons)|[Team-Cymru.org](http://www.team-cymru.org) private and reserved addresses defined by RFC 1918, RFC 5735, and RFC 6598 and netblocks that have not been allocated to a regional internet registry - **excellent list - use it only your internet interface**|ipv4 hash:net|13 subnets, 592708608 unique IPs|updated every 1 day  from [this link](http://www.team-cymru.org/Services/Bogons/bogon-bn-agg.txt)
[bruteforceblocker](#bruteforceblocker)|[danger.rulez.sk](http://danger.rulez.sk/) IPs detected by [bruteforceblocker](http://danger.rulez.sk/index.php/bruteforceblocker/) (fail2ban alternative for SSH on OpenBSD). This is an automatically generated list from users reporting failed authentication attempts. An IP seems to be included if 3 or more users report it. Its retention pocily seems 30 days.|ipv4 hash:ip|1700 unique IPs|updated every 3 hours  from [this link](http://danger.rulez.sk/projects/bruteforceblocker/blist.php)
[ciarmy](#ciarmy)|[CIArmy.com](http://ciarmy.com/) IPs with poor Rogue Packet score that have not yet been identified as malicious by the community|ipv4 hash:ip|428 unique IPs|updated every 3 hours  from [this link](http://cinsscore.com/list/ci-badguys.txt)
[cleanmx_viruses](#cleanmx_viruses)|[Clean-MX.de](http://support.clean-mx.de/clean-mx/viruses.php) IPs with viruses|ipv4 hash:ip|511 unique IPs|updated every 12 hours  from [this link](http://support.clean-mx.de/clean-mx/xmlviruses.php?sort=id%20desc&response=alive)
[dm_tor](#dm_tor)|[dan.me.uk](https://www.dan.me.uk) dynamic list of TOR nodes|ipv4 hash:ip|6559 unique IPs|updated every 30 mins  from [this link](https://www.dan.me.uk/torlist/)
[dragon_http](#dragon_http)|[Dragon Search Group](http://www.dragonresearchgroup.org/) IPs that have been seen sending HTTP requests to Dragon Research Pods in the last 7 days. This report lists hosts that are highly suspicious and are likely conducting malicious HTTP attacks. LEGITIMATE SEARCH ENGINE BOTS MAY BE IN THIS LIST. This report is informational.  It is not a blacklist, but some operators may choose to use it to help protect their networks and hosts in the forms of automated reporting and mitigation services.|ipv4 hash:net|1021 subnets, 268288 unique IPs|updated every 1 hour  from [this link](http://www.dragonresearchgroup.org/insight/http-report.txt)
[dragon_sshpauth](#dragon_sshpauth)|[Dragon Search Group](http://www.dragonresearchgroup.org/) IP address that has been seen attempting to remotely login to a host using SSH password authentication, in the last 7 days. This report lists hosts that are highly suspicious and are likely conducting malicious SSH password authentication attacks.|ipv4 hash:net|1568 subnets, 1632 unique IPs|updated every 1 hour  from [this link](https://www.dragonresearchgroup.org/insight/sshpwauth.txt)
[dragon_vncprobe](#dragon_vncprobe)|[Dragon Search Group](http://www.dragonresearchgroup.org/) IP address that has been seen attempting to remotely connect to a host running the VNC application service, in the last 7 days. This report lists hosts that are highly suspicious and are likely conducting malicious VNC probes or VNC brute force attacks.|ipv4 hash:net|85 subnets, 85 unique IPs|updated every 1 hour  from [this link](https://www.dragonresearchgroup.org/insight/vncprobe.txt)
[dshield](#dshield)|[DShield.org](https://dshield.org/) top 20 attacking class C (/24) subnets over the last three days - **excellent list**|ipv4 hash:net|20 subnets, 5120 unique IPs|updated every 4 hours  from [this link](http://feeds.dshield.org/block.txt)
[et_block](#et_block)|[EmergingThreats.net](http://www.emergingthreats.net/) default blacklist (at the time of writing includes spamhaus DROP, dshield and abuse.ch trackers, which are available separately too - prefer to use the direct ipsets instead of this, they seem to lag a bit in updates)|ipv4 hash:net|1000 subnets, 18343756 unique IPs|updated every 12 hours  from [this link](http://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt)
[et_botcc](#et_botcc)|[EmergingThreats.net Command and Control IPs](http://doc.emergingthreats.net/bin/view/Main/BotCC) These IPs are updates every 24 hours and should be considered VERY highly reliable indications that a host is communicating with a known and active Bot or Malware command and control server - (although they say this includes abuse.ch trackers, it does not - most probably it is the shadowserver.org C&C list)|ipv4 hash:ip|505 unique IPs|updated every 12 hours  from [this link](http://rules.emergingthreats.net/fwrules/emerging-PIX-CC.rules)
[et_compromised](#et_compromised)|[EmergingThreats.net compromised hosts](http://doc.emergingthreats.net/bin/view/Main/CompromisedHost) - (this seems to be based on bruteforceblocker)|ipv4 hash:ip|1704 unique IPs|updated every 12 hours  from [this link](http://rules.emergingthreats.net/blockrules/compromised-ips.txt)
et_dshield|[EmergingThreats.net](http://www.emergingthreats.net/) dshield blocklist|ipv4 hash:net|disabled|updated every 12 hours  from [this link](http://rules.emergingthreats.net/fwrules/emerging-PIX-DSHIELD.rules)
et_spamhaus|[EmergingThreats.net](http://www.emergingthreats.net/) spamhaus blocklist|ipv4 hash:net|disabled|updated every 12 hours  from [this link](http://rules.emergingthreats.net/fwrules/emerging-PIX-DROP.rules)
[et_tor](#et_tor)|[EmergingThreats.net](http://www.emergingthreats.net/) [list](http://doc.emergingthreats.net/bin/view/Main/TorRules) of TOR network IPs|ipv4 hash:ip|6500 unique IPs|updated every 12 hours  from [this link](http://rules.emergingthreats.net/blockrules/emerging-tor.rules)
[feodo](#feodo)|[Abuse.ch Feodo tracker](https://feodotracker.abuse.ch) trojan includes IPs which are being used by Feodo (also known as Cridex or Bugat) which commits ebanking fraud - **excellent list**|ipv4 hash:ip|0 unique IPs|updated every 30 mins  from [this link](https://feodotracker.abuse.ch/blocklist/?download=ipblocklist)
[firehol_anonymous](#firehol_anonymous)|**FireHOL Anonymous** - Known anonymizing IPs. (includes: firehol_proxies anonymous bm_tor dm_tor tor_exits)|ipv4 hash:net|19320 subnets, 83371 unique IPs|
[firehol_level1](#firehol_level1)|**FireHOL Level 1** - Maximum protection without false positives. (includes: fullbogons dshield feodo palevo sslbl zeus spamhaus_drop spamhaus_edrop)|ipv4 hash:net|5068 subnets, 688775049 unique IPs|
[firehol_level2](#firehol_level2)|**FireHOL Level 2** - Maximum protection from attacks took place in the last 48 hours. (includes: openbl_1d blocklist_de stopforumspam_1d)|ipv4 hash:net|22948 subnets, 34548 unique IPs|
[firehol_level3](#firehol_level3)|**FireHOL Level 3** - All the bad IPs in last 30 days. (includes: openbl_30d stopforumspam_30d virbl malc0de shunlist malwaredomainlist bruteforceblocker ciarmy cleanmx_viruses snort_ipfilter ib_bluetack_spyware ib_bluetack_hijacked ib_bluetack_webexploit php_commenters php_dictionary php_harvesters php_spammers iw_wormlist)|ipv4 hash:net|108767 subnets, 9626344 unique IPs|
[firehol_proxies](#firehol_proxies)|**FireHOL Proxies** - Known open proxies in the last 30 days. (includes: ib_bluetack_proxies maxmind_proxy_fraud proxyrss proxz ri_connect_proxies ri_web_proxies xroxy)|ipv4 hash:net|12732 subnets, 13012 unique IPs|
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
[iw_spamlist](#iw_spamlist)|[ImproWare Antispam](http://antispam.imp.ch/) IPs sending spam, in the last 3 days|ipv4 hash:ip|3266 unique IPs|updated every 1 hour  from [this link](http://antispam.imp.ch/spamlist)
[iw_wormlist](#iw_wormlist)|[ImproWare Antispam](http://antispam.imp.ch/) IPs sending emails with viruses or worms, in the last 3 days|ipv4 hash:ip|4 unique IPs|updated every 1 hour  from [this link](http://antispam.imp.ch/wormlist)
lashback_ubl|[The LashBack UBL](http://blacklist.lashback.com/) The Unsubscribe Blacklist (UBL) is a real-time blacklist of IP addresses which are sending email to names harvested from suppression files (this is a big list, more than 500.000 IPs)|ipv4 hash:ip|disabled|updated every 1 day  from [this link](http://www.unsubscore.com/blacklist.txt)
[malc0de](#malc0de)|[Malc0de.com](http://malc0de.com) malicious IPs of the last 30 days|ipv4 hash:ip|238 unique IPs|updated every 1 day  from [this link](http://malc0de.com/bl/IP_Blacklist.txt)
[malwaredomainlist](#malwaredomainlist)|[malwaredomainlist.com](http://www.malwaredomainlist.com) list of malware active ip addresses|ipv4 hash:ip|1288 unique IPs|updated every 12 hours  from [this link](http://www.malwaredomainlist.com/hostslist/ip.txt)
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|[MaxMind.com](https://www.maxmind.com/en/anonymous-proxy-fraudulent-ip-address-list) list of anonymous proxy fraudelent IP addresses.|ipv4 hash:ip|524 unique IPs|updated every 4 hours  from [this link](https://www.maxmind.com/en/anonymous-proxy-fraudulent-ip-address-list)
[nixspam](#nixspam)|[NiX Spam](http://www.heise.de/ix/NiX-Spam-DNSBL-and-blacklist-for-download-499637.html) IP addresses that sent spam in the last hour - automatically generated entries without distinguishing open proxies from relays, dialup gateways, and so on. All IPs are removed after 12 hours if there is no spam from there.|ipv4 hash:ip|22540 unique IPs|updated every 15 mins  from [this link](http://www.dnsbl.manitu.net/download/nixspam-ip.dump.gz)
[nt_malware_http](#nt_malware_http)|[No Think](http://www.nothink.org/) Malware HTTP|ipv4 hash:ip|69 unique IPs|updated every 1 hour  from [this link](http://www.nothink.org/blacklist/blacklist_malware_http.txt)
[nt_malware_irc](#nt_malware_irc)|[No Think](http://www.nothink.org/) Malware IRC|ipv4 hash:ip|43 unique IPs|updated every 1 hour  from [this link](http://www.nothink.org/blacklist/blacklist_malware_irc.txt)
[nt_ssh_7d](#nt_ssh_7d)|[No Think](http://www.nothink.org/) Last 7 days SSH attacks|ipv4 hash:ip|0 unique IPs|updated every 1 hour  from [this link](http://www.nothink.org/blacklist/blacklist_ssh_week.txt)
openbl|[OpenBL.org](http://www.openbl.org/) default blacklist (currently it is the same with 90 days). OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications - **excellent list**|ipv4 hash:ip|disabled|updated every 4 hours  from [this link](http://www.openbl.org/lists/base.txt)
openbl_180d|[OpenBL.org](http://www.openbl.org/) last 180 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|disabled|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_180days.txt)
[openbl_1d](#openbl_1d)|[OpenBL.org](http://www.openbl.org/) last 24 hours IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|155 unique IPs|updated every 1 hour  from [this link](http://www.openbl.org/lists/base_1days.txt)
[openbl_30d](#openbl_30d)|[OpenBL.org](http://www.openbl.org/) last 30 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|2791 unique IPs|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_30days.txt)
openbl_360d|[OpenBL.org](http://www.openbl.org/) last 360 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|disabled|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_360days.txt)
[openbl_60d](#openbl_60d)|[OpenBL.org](http://www.openbl.org/) last 60 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|6959 unique IPs|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_60days.txt)
[openbl_7d](#openbl_7d)|[OpenBL.org](http://www.openbl.org/) last 7 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|638 unique IPs|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_7days.txt)
openbl_90d|[OpenBL.org](http://www.openbl.org/) last 90 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|disabled|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_90days.txt)
openbl_all|[OpenBL.org](http://www.openbl.org/) last all IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|disabled|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_all.txt)
[palevo](#palevo)|[Abuse.ch Palevo tracker](https://palevotracker.abuse.ch) worm includes IPs which are being used as botnet C&C for the Palevo crimeware - **excellent list**|ipv4 hash:ip|0 unique IPs|updated every 30 mins  from [this link](https://palevotracker.abuse.ch/blocklists.php?download=ipblocklist)
php_bad|[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) bad web hosts (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|disabled|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=b&rss=1)
[php_commenters](#php_commenters)|[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) comment spammers (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|458 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=c&rss=1)
[php_dictionary](#php_dictionary)|[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) directory attackers (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|777 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=d&rss=1)
[php_harvesters](#php_harvesters)|[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) harvesters (IPs that surf the internet looking for email addresses) (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|408 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=h&rss=1)
[php_spammers](#php_spammers)|[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) spam servers (IPs used by spammers to send messages) (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|777 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=s&rss=1)
[proxyrss](#proxyrss)|[proxyrss.com](http://www.proxyrss.com) open proxies syndicated from multiple sources.|ipv4 hash:ip|1402 unique IPs|updated every 4 hours  from [this link](http://www.proxyrss.com/proxylists/all.gz)
[proxz](#proxz)|[proxz.com](http://www.proxz.com) open proxies (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|1385 unique IPs|updated every 1 hour  from [this link](http://www.proxz.com/proxylists.xml)
[ri_connect_proxies](#ri_connect_proxies)|[rosinstrument.com](http://www.rosinstrument.com) open CONNECT proxies (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|2902 unique IPs|updated every 1 hour  from [this link](http://tools.rosinstrument.com/proxy/plab100.xml)
[ri_web_proxies](#ri_web_proxies)|[rosinstrument.com](http://www.rosinstrument.com) open HTTP proxies (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|8035 unique IPs|updated every 1 hour  from [this link](http://tools.rosinstrument.com/proxy/l100.xml)
[shunlist](#shunlist)|[AutoShun.org](http://autoshun.org/) IPs identified as hostile by correlating logs from distributed snort installations running the autoshun plugin|ipv4 hash:ip|1129 unique IPs|updated every 4 hours  from [this link](http://www.autoshun.org/files/shunlist.csv)
[snort_ipfilter](#snort_ipfilter)|[labs.snort.org](https://labs.snort.org/) supplied IP blacklist (this list seems to be updated frequently, but we found no information about it)|ipv4 hash:ip|8373 unique IPs|updated every 12 hours  from [this link](http://labs.snort.org/feeds/ip-filter.blf)
[sorbs_dul](#sorbs_dul)|[Sorbs.net](https://www.sorbs.net/) DUL, Dynamic User IPs extracted from deltas.|ipv4 hash:net|10 subnets, 4864 unique IPs|
[sorbs_http](#sorbs_http)|[Sorbs.net](https://www.sorbs.net/) HTTP proxies, extracted from deltas.|ipv4 hash:net|7 subnets, 7 unique IPs|
[sorbs_misc](#sorbs_misc)|[Sorbs.net](https://www.sorbs.net/) MISC proxies, extracted from deltas.|ipv4 hash:net|7 subnets, 7 unique IPs|
[sorbs_new_spam](#sorbs_new_spam)|[Sorbs.net](https://www.sorbs.net/) NEW Spam senders, extracted from deltas.|ipv4 hash:net|64467 subnets, 65300 unique IPs|
[sorbs_recent_spam](#sorbs_recent_spam)|[Sorbs.net](https://www.sorbs.net/) RECENT Spam senders, extracted from deltas.|ipv4 hash:net|64467 subnets, 65300 unique IPs|
[sorbs_smtp](#sorbs_smtp)|[Sorbs.net](https://www.sorbs.net/) SMTP Open Relays, extracted from deltas.|ipv4 hash:net|6 subnets, 6 unique IPs|
[sorbs_socks](#sorbs_socks)|[Sorbs.net](https://www.sorbs.net/) SOCKS proxies, extracted from deltas.|ipv4 hash:net|7 subnets, 7 unique IPs|
[sorbs_spam](#sorbs_spam)|[Sorbs.net](https://www.sorbs.net/) Spam senders, extracted from deltas.|ipv4 hash:net|64701 subnets, 65536 unique IPs|
[sorbs_web](#sorbs_web)|[Sorbs.net](https://www.sorbs.net/) WEB exploits, extracted from deltas.|ipv4 hash:net|667 subnets, 668 unique IPs|
[spamhaus_drop](#spamhaus_drop)|[Spamhaus.org](http://www.spamhaus.org) DROP list (according to their site this list should be dropped at tier-1 ISPs globaly) - **excellent list**|ipv4 hash:net|653 subnets, 18340608 unique IPs|updated every 12 hours  from [this link](http://www.spamhaus.org/drop/drop.txt)
[spamhaus_edrop](#spamhaus_edrop)|[Spamhaus.org](http://www.spamhaus.org) EDROP (extended matches that should be used with DROP) - **excellent list**|ipv4 hash:net|56 subnets, 487424 unique IPs|updated every 12 hours  from [this link](http://www.spamhaus.org/drop/edrop.txt)
[sslbl](#sslbl)|[Abuse.ch SSL Blacklist](https://sslbl.abuse.ch/) bad SSL traffic related to malware or botnet activities - **excellent list**|ipv4 hash:ip|368 unique IPs|updated every 30 mins  from [this link](https://sslbl.abuse.ch/blacklist/sslipblacklist.csv)
stopforumspam_180d|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 180 days)|ipv4 hash:ip|disabled|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/listed_ip_180.zip)
[stopforumspam_1d](#stopforumspam_1d)|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers in the last 24 hours - **excellent list**|ipv4 hash:ip|6864 unique IPs|updated every 1 hour  from [this link](http://www.stopforumspam.com/downloads/listed_ip_1.zip)
[stopforumspam_30d](#stopforumspam_30d)|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 30 days)|ipv4 hash:ip|94236 unique IPs|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/listed_ip_30.zip)
stopforumspam_365d|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 365 days)|ipv4 hash:ip|disabled|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/listed_ip_365.zip)
[stopforumspam_7d](#stopforumspam_7d)|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 7 days)|ipv4 hash:ip|29017 unique IPs|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/listed_ip_7.zip)
stopforumspam_90d|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 90 days)|ipv4 hash:ip|disabled|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/listed_ip_90.zip)
stopforumspam_ever|[StopForumSpam.com](http://www.stopforumspam.com) all IPs used by forum spammers, **ever** (normally you don't want to use this ipset, use the hourly one which includes last 24 hours IPs or the 7 days one)|ipv4 hash:ip|disabled|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/bannedips.zip)
[tor_exits](#tor_exits)|[TorProject.org](https://www.torproject.org) list of all current TOR exit points (TorDNSEL)|ipv4 hash:ip|1106 unique IPs|updated every 30 mins  from [this link](https://check.torproject.org/exit-addresses)
[virbl](#virbl)|[VirBL](http://virbl.bit.nl/) is a project of which the idea was born during the RIPE-48 meeting. The plan was to get reports of virusscanning mailservers, and put the IP-addresses that were reported to send viruses on a blacklist.|ipv4 hash:ip|15 unique IPs|updated every 1 hour  from [this link](http://virbl.bit.nl/download/virbl.dnsbl.bit.nl.txt)
[voipbl](#voipbl)|[VoIPBL.org](http://www.voipbl.org/) a distributed VoIP blacklist that is aimed to protects against VoIP Fraud and minimizing abuse for network that have publicly accessible PBX's. Several algorithms, external sources and manual confirmation are used before they categorize something as an attack and determine the threat level.|ipv4 hash:net|10607 subnets, 11019 unique IPs|updated every 4 hours  from [this link](http://www.voipbl.org/update/)
[xroxy](#xroxy)|[xroxy.com](http://www.xroxy.com) open proxies (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|2176 unique IPs|updated every 1 hour  from [this link](http://www.xroxy.com/proxyrss.xml)
[zeus](#zeus)|[Abuse.ch Zeus tracker](https://zeustracker.abuse.ch) standard, contains the same data as the ZeuS IP blocklist (zeus_badips) but with the slight difference that it doesn't exclude hijacked websites (level 2) and free web hosting providers (level 3). This means that this blocklist contains all IPv4 addresses associated with ZeuS C&Cs which are currently being tracked by ZeuS Tracker. Hence this blocklist will likely cause some false positives. - **excellent list**|ipv4 hash:ip|230 unique IPs|updated every 30 mins  from [this link](https://zeustracker.abuse.ch/blocklist.php?download=ipblocklist)
[zeus_badips](#zeus_badips)|[Abuse.ch Zeus tracker](https://zeustracker.abuse.ch) badips includes IPv4 addresses that are used by the ZeuS trojan. It is the recommened blocklist if you want to block only ZeuS IPs. It excludes IP addresses that ZeuS Tracker believes to be hijacked (level 2) or belong to a free web hosting provider (level 3). Hence the false postive rate should be much lower compared to the standard ZeuS IP blocklist. **excellent list**|ipv4 hash:ip|202 unique IPs|updated every 30 mins  from [this link](https://zeustracker.abuse.ch/blocklist.php?download=badips)

# Comparison of ipsets

Below we compare each ipset against all other.


## alienvault_reputation

[AlienVault.com](https://www.alienvault.com/) IP reputation database (this list seems to include port scanning hosts and to be updated regularly, but we found no information about its retention policy)

Source is downloaded from [this link](https://reputation.alienvault.com/reputation.generic).

The last time downloaded was found to be dated: Fri Jun 12 16:00:20 UTC 2015.

The ipset `alienvault_reputation` has **189217** entries, **189217** unique IPs.

The following table shows the overlaps of `alienvault_reputation` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `alienvault_reputation`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `alienvault_reputation`.
- ` this % ` is the percentage **of this ipset (`alienvault_reputation`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|14346|0.0%|7.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|7256|0.0%|3.8%|
[openbl_60d](#openbl_60d)|6959|6959|6937|99.6%|3.6%|
[firehol_level1](#firehol_level1)|5068|688775049|6387|0.0%|3.3%|
[dragon_http](#dragon_http)|1021|268288|6157|2.2%|3.2%|
[dshield](#dshield)|20|5120|5120|100.0%|2.7%|
[firehol_level3](#firehol_level3)|108767|9626344|4825|0.0%|2.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|4191|0.0%|2.2%|
[et_block](#et_block)|1000|18343756|3752|0.0%|1.9%|
[openbl_30d](#openbl_30d)|2791|2791|2774|99.3%|1.4%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|1385|0.0%|0.7%|
[firehol_level2](#firehol_level2)|22948|34548|1203|3.4%|0.6%|
[blocklist_de](#blocklist_de)|29129|29129|1141|3.9%|0.6%|
[shunlist](#shunlist)|1129|1129|1105|97.8%|0.5%|
[et_compromised](#et_compromised)|1704|1704|1086|63.7%|0.5%|
[bruteforceblocker](#bruteforceblocker)|1700|1700|1074|63.1%|0.5%|
[blocklist_de_ssh](#blocklist_de_ssh)|3204|3204|931|29.0%|0.4%|
[dragon_sshpauth](#dragon_sshpauth)|1568|1632|858|52.5%|0.4%|
[openbl_7d](#openbl_7d)|638|638|635|99.5%|0.3%|
[ciarmy](#ciarmy)|428|428|426|99.5%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|293|0.0%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|278|0.0%|0.1%|
[voipbl](#voipbl)|10607|11019|176|1.5%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|94236|94236|166|0.1%|0.0%|
[openbl_1d](#openbl_1d)|155|155|152|98.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14109|14109|127|0.9%|0.0%|
[snort_ipfilter](#snort_ipfilter)|8373|8373|106|1.2%|0.0%|
[sorbs_spam](#sorbs_spam)|64701|65536|91|0.1%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|91|0.1%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|91|0.1%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|88|0.3%|0.0%|
[sslbl](#sslbl)|368|368|65|17.6%|0.0%|
[zeus](#zeus)|230|230|61|26.5%|0.0%|
[firehol_anonymous](#firehol_anonymous)|19320|83371|58|0.0%|0.0%|
[nixspam](#nixspam)|22540|22540|53|0.2%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|18292|18292|48|0.2%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6864|6864|46|0.6%|0.0%|
[et_tor](#et_tor)|6500|6500|42|0.6%|0.0%|
[dm_tor](#dm_tor)|6559|6559|42|0.6%|0.0%|
[bm_tor](#bm_tor)|6533|6533|41|0.6%|0.0%|
[firehol_proxies](#firehol_proxies)|12732|13012|39|0.2%|0.0%|
[zeus_badips](#zeus_badips)|202|202|37|18.3%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|3535|3535|34|0.9%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|168|168|33|19.6%|0.0%|
[tor_exits](#tor_exits)|1106|1106|30|2.7%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|29|5.5%|0.0%|
[dragon_vncprobe](#dragon_vncprobe)|85|85|28|32.9%|0.0%|
[iw_spamlist](#iw_spamlist)|3266|3266|25|0.7%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3035|3035|21|0.6%|0.0%|
[php_commenters](#php_commenters)|458|458|19|4.1%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|80|80|19|23.7%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|15|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|14|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2714|2714|13|0.4%|0.0%|
[php_harvesters](#php_harvesters)|408|408|12|2.9%|0.0%|
[malc0de](#malc0de)|238|238|9|3.7%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|8|0.6%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|1509|1509|8|0.5%|0.0%|
[php_dictionary](#php_dictionary)|777|777|7|0.9%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|6|0.4%|0.0%|
[xroxy](#xroxy)|2176|2176|5|0.2%|0.0%|
[php_spammers](#php_spammers)|777|777|5|0.6%|0.0%|
[ri_web_proxies](#ri_web_proxies)|8035|8035|4|0.0%|0.0%|
[proxz](#proxz)|1385|1385|4|0.2%|0.0%|
[et_botcc](#et_botcc)|505|505|4|0.7%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|511|511|4|0.7%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2902|2902|3|0.1%|0.0%|
[proxyrss](#proxyrss)|1402|1402|2|0.1%|0.0%|
[nt_malware_irc](#nt_malware_irc)|43|43|2|4.6%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|2|0.3%|0.0%|
[sorbs_web](#sorbs_web)|667|668|1|0.1%|0.0%|
[nt_malware_http](#nt_malware_http)|69|69|1|1.4%|0.0%|

## blocklist_de

[Blocklist.de](https://www.blocklist.de/) IPs that have been detected by fail2ban in the last 48 hours - **excellent list**

Source is downloaded from [this link](http://lists.blocklist.de/lists/all.txt).

The last time downloaded was found to be dated: Fri Jun 12 15:56:04 UTC 2015.

The ipset `blocklist_de` has **29129** entries, **29129** unique IPs.

The following table shows the overlaps of `blocklist_de` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de`.
- ` this % ` is the percentage **of this ipset (`blocklist_de`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|22948|34548|29129|84.3%|100.0%|
[blocklist_de_mail](#blocklist_de_mail)|18292|18292|18292|100.0%|62.7%|
[blocklist_de_apache](#blocklist_de_apache)|14109|14109|14109|100.0%|48.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|3961|0.0%|13.5%|
[firehol_level3](#firehol_level3)|108767|9626344|3889|0.0%|13.3%|
[blocklist_de_imap](#blocklist_de_imap)|3535|3535|3526|99.7%|12.1%|
[blocklist_de_ssh](#blocklist_de_ssh)|3204|3204|3199|99.8%|10.9%|
[blocklist_de_bots](#blocklist_de_bots)|3035|3035|3023|99.6%|10.3%|
[stopforumspam_30d](#stopforumspam_30d)|94236|94236|2843|3.0%|9.7%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2714|2714|2714|100.0%|9.3%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|2310|7.9%|7.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|1582|0.0%|5.4%|
[blocklist_de_ftp](#blocklist_de_ftp)|1509|1509|1496|99.1%|5.1%|
[stopforumspam_1d](#stopforumspam_1d)|6864|6864|1475|21.4%|5.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|1452|0.0%|4.9%|
[alienvault_reputation](#alienvault_reputation)|189217|189217|1141|0.6%|3.9%|
[openbl_60d](#openbl_60d)|6959|6959|789|11.3%|2.7%|
[nixspam](#nixspam)|22540|22540|760|3.3%|2.6%|
[sorbs_spam](#sorbs_spam)|64701|65536|740|1.1%|2.5%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|731|1.1%|2.5%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|731|1.1%|2.5%|
[firehol_anonymous](#firehol_anonymous)|19320|83371|674|0.8%|2.3%|
[firehol_proxies](#firehol_proxies)|12732|13012|656|5.0%|2.2%|
[openbl_30d](#openbl_30d)|2791|2791|633|22.6%|2.1%|
[dragon_sshpauth](#dragon_sshpauth)|1568|1632|605|37.0%|2.0%|
[bruteforceblocker](#bruteforceblocker)|1700|1700|546|32.1%|1.8%|
[et_compromised](#et_compromised)|1704|1704|520|30.5%|1.7%|
[ri_web_proxies](#ri_web_proxies)|8035|8035|484|6.0%|1.6%|
[openbl_7d](#openbl_7d)|638|638|369|57.8%|1.2%|
[shunlist](#shunlist)|1129|1129|329|29.1%|1.1%|
[xroxy](#xroxy)|2176|2176|235|10.7%|0.8%|
[snort_ipfilter](#snort_ipfilter)|8373|8373|215|2.5%|0.7%|
[proxz](#proxz)|1385|1385|210|15.1%|0.7%|
[proxyrss](#proxyrss)|1402|1402|201|14.3%|0.6%|
[firehol_level1](#firehol_level1)|5068|688775049|198|0.0%|0.6%|
[et_block](#et_block)|1000|18343756|185|0.0%|0.6%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|168|0.0%|0.5%|
[blocklist_de_strongips](#blocklist_de_strongips)|168|168|168|100.0%|0.5%|
[iw_spamlist](#iw_spamlist)|3266|3266|136|4.1%|0.4%|
[openbl_1d](#openbl_1d)|155|155|125|80.6%|0.4%|
[php_dictionary](#php_dictionary)|777|777|111|14.2%|0.3%|
[php_spammers](#php_spammers)|777|777|108|13.8%|0.3%|
[php_commenters](#php_commenters)|458|458|107|23.3%|0.3%|
[ri_connect_proxies](#ri_connect_proxies)|2902|2902|77|2.6%|0.2%|
[sorbs_web](#sorbs_web)|667|668|76|11.3%|0.2%|
[dshield](#dshield)|20|5120|71|1.3%|0.2%|
[blocklist_de_sip](#blocklist_de_sip)|80|80|60|75.0%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|54|0.0%|0.1%|
[dragon_http](#dragon_http)|1021|268288|49|0.0%|0.1%|
[voipbl](#voipbl)|10607|11019|39|0.3%|0.1%|
[php_harvesters](#php_harvesters)|408|408|38|9.3%|0.1%|
[ciarmy](#ciarmy)|428|428|36|8.4%|0.1%|
[tor_exits](#tor_exits)|1106|1106|15|1.3%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|14|0.0%|0.0%|
[et_tor](#et_tor)|6500|6500|13|0.2%|0.0%|
[dm_tor](#dm_tor)|6559|6559|8|0.1%|0.0%|
[bm_tor](#bm_tor)|6533|6533|7|0.1%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|6|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|5|0.9%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|5|0.7%|0.0%|
[dragon_vncprobe](#dragon_vncprobe)|85|85|5|5.8%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|3|0.0%|0.0%|
[virbl](#virbl)|15|15|2|13.3%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|2|0.1%|0.0%|
[sorbs_socks](#sorbs_socks)|7|7|1|14.2%|0.0%|
[sorbs_misc](#sorbs_misc)|7|7|1|14.2%|0.0%|
[sorbs_http](#sorbs_http)|7|7|1|14.2%|0.0%|

## blocklist_de_apache

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service Apache, Apache-DDOS, RFI-Attacks.

Source is downloaded from [this link](http://lists.blocklist.de/lists/apache.txt).

The last time downloaded was found to be dated: Fri Jun 12 15:56:08 UTC 2015.

The ipset `blocklist_de_apache` has **14109** entries, **14109** unique IPs.

The following table shows the overlaps of `blocklist_de_apache` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_apache`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_apache`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_apache`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|22948|34548|14109|40.8%|100.0%|
[blocklist_de](#blocklist_de)|29129|29129|14109|48.4%|100.0%|
[blocklist_de_mail](#blocklist_de_mail)|18292|18292|11059|60.4%|78.3%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2714|2714|2714|100.0%|19.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|2311|0.0%|16.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|1323|0.0%|9.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|1077|0.0%|7.6%|
[firehol_level3](#firehol_level3)|108767|9626344|283|0.0%|2.0%|
[stopforumspam_30d](#stopforumspam_30d)|94236|94236|202|0.2%|1.4%|
[alienvault_reputation](#alienvault_reputation)|189217|189217|127|0.0%|0.9%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|120|0.4%|0.8%|
[stopforumspam_1d](#stopforumspam_1d)|6864|6864|65|0.9%|0.4%|
[sorbs_spam](#sorbs_spam)|64701|65536|48|0.0%|0.3%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|48|0.0%|0.3%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|48|0.0%|0.3%|
[shunlist](#shunlist)|1129|1129|37|3.2%|0.2%|
[snort_ipfilter](#snort_ipfilter)|8373|8373|33|0.3%|0.2%|
[blocklist_de_strongips](#blocklist_de_strongips)|168|168|31|18.4%|0.2%|
[ciarmy](#ciarmy)|428|428|29|6.7%|0.2%|
[php_commenters](#php_commenters)|458|458|27|5.8%|0.1%|
[nixspam](#nixspam)|22540|22540|22|0.0%|0.1%|
[blocklist_de_bots](#blocklist_de_bots)|3035|3035|22|0.7%|0.1%|
[firehol_anonymous](#firehol_anonymous)|19320|83371|21|0.0%|0.1%|
[tor_exits](#tor_exits)|1106|1106|15|1.3%|0.1%|
[et_tor](#et_tor)|6500|6500|13|0.2%|0.0%|
[dragon_http](#dragon_http)|1021|268288|10|0.0%|0.0%|
[dm_tor](#dm_tor)|6559|6559|8|0.1%|0.0%|
[firehol_proxies](#firehol_proxies)|12732|13012|7|0.0%|0.0%|
[et_block](#et_block)|1000|18343756|7|0.0%|0.0%|
[bm_tor](#bm_tor)|6533|6533|7|0.1%|0.0%|
[php_spammers](#php_spammers)|777|777|6|0.7%|0.0%|
[openbl_60d](#openbl_60d)|6959|6959|6|0.0%|0.0%|
[firehol_level1](#firehol_level1)|5068|688775049|6|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|5|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|8035|8035|4|0.0%|0.0%|
[php_dictionary](#php_dictionary)|777|777|3|0.3%|0.0%|
[openbl_30d](#openbl_30d)|2791|2791|3|0.1%|0.0%|
[iw_spamlist](#iw_spamlist)|3266|3266|3|0.0%|0.0%|
[voipbl](#voipbl)|10607|11019|2|0.0%|0.0%|
[php_harvesters](#php_harvesters)|408|408|2|0.4%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|2|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|2|0.0%|0.0%|
[xroxy](#xroxy)|2176|2176|1|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2902|2902|1|0.0%|0.0%|
[proxz](#proxz)|1385|1385|1|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|1|0.1%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.0%|
[dshield](#dshield)|20|5120|1|0.0%|0.0%|
[dragon_vncprobe](#dragon_vncprobe)|85|85|1|1.1%|0.0%|

## blocklist_de_bots

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the RFI-Attacks, REG-Bots, IRC-Bots or BadBots (BadBots = he has posted a Spam-Comment on a open Forum or Wiki).

Source is downloaded from [this link](http://lists.blocklist.de/lists/bots.txt).

The last time downloaded was found to be dated: Fri Jun 12 15:42:10 UTC 2015.

The ipset `blocklist_de_bots` has **3035** entries, **3035** unique IPs.

The following table shows the overlaps of `blocklist_de_bots` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_bots`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_bots`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_bots`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|22948|34548|3025|8.7%|99.6%|
[blocklist_de](#blocklist_de)|29129|29129|3023|10.3%|99.6%|
[firehol_level3](#firehol_level3)|108767|9626344|2512|0.0%|82.7%|
[stopforumspam_30d](#stopforumspam_30d)|94236|94236|2491|2.6%|82.0%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|2127|7.3%|70.0%|
[stopforumspam_1d](#stopforumspam_1d)|6864|6864|1406|20.4%|46.3%|
[firehol_anonymous](#firehol_anonymous)|19320|83371|531|0.6%|17.4%|
[firehol_proxies](#firehol_proxies)|12732|13012|530|4.0%|17.4%|
[ri_web_proxies](#ri_web_proxies)|8035|8035|397|4.9%|13.0%|
[proxyrss](#proxyrss)|1402|1402|199|14.1%|6.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|188|0.0%|6.1%|
[xroxy](#xroxy)|2176|2176|182|8.3%|5.9%|
[proxz](#proxz)|1385|1385|180|12.9%|5.9%|
[blocklist_de_strongips](#blocklist_de_strongips)|168|168|129|76.7%|4.2%|
[php_commenters](#php_commenters)|458|458|88|19.2%|2.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|75|0.0%|2.4%|
[ri_connect_proxies](#ri_connect_proxies)|2902|2902|74|2.5%|2.4%|
[firehol_level1](#firehol_level1)|5068|688775049|60|0.0%|1.9%|
[et_block](#et_block)|1000|18343756|58|0.0%|1.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|54|0.0%|1.7%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|49|0.0%|1.6%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|42|0.0%|1.3%|
[nixspam](#nixspam)|22540|22540|39|0.1%|1.2%|
[sorbs_spam](#sorbs_spam)|64701|65536|29|0.0%|0.9%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|29|0.0%|0.9%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|29|0.0%|0.9%|
[php_harvesters](#php_harvesters)|408|408|28|6.8%|0.9%|
[php_spammers](#php_spammers)|777|777|24|3.0%|0.7%|
[blocklist_de_mail](#blocklist_de_mail)|18292|18292|22|0.1%|0.7%|
[blocklist_de_apache](#blocklist_de_apache)|14109|14109|22|0.1%|0.7%|
[alienvault_reputation](#alienvault_reputation)|189217|189217|21|0.0%|0.6%|
[snort_ipfilter](#snort_ipfilter)|8373|8373|20|0.2%|0.6%|
[php_dictionary](#php_dictionary)|777|777|18|2.3%|0.5%|
[dshield](#dshield)|20|5120|8|0.1%|0.2%|
[sorbs_web](#sorbs_web)|667|668|7|1.0%|0.2%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|4|0.7%|0.1%|
[iw_spamlist](#iw_spamlist)|3266|3266|4|0.1%|0.1%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|3|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|3|0.4%|0.0%|
[dragon_http](#dragon_http)|1021|268288|3|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|2|0.1%|0.0%|
[voipbl](#voipbl)|10607|11019|1|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|1|0.0%|0.0%|

## blocklist_de_bruteforce

[Blocklist.de](https://www.blocklist.de/) All IPs which attacks Joomlas, Wordpress and other Web-Logins with Brute-Force Logins.

Source is downloaded from [this link](http://lists.blocklist.de/lists/bruteforcelogin.txt).

The last time downloaded was found to be dated: Fri Jun 12 15:42:16 UTC 2015.

The ipset `blocklist_de_bruteforce` has **2714** entries, **2714** unique IPs.

The following table shows the overlaps of `blocklist_de_bruteforce` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_bruteforce`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_bruteforce`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_bruteforce`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|22948|34548|2714|7.8%|100.0%|
[blocklist_de_apache](#blocklist_de_apache)|14109|14109|2714|19.2%|100.0%|
[blocklist_de](#blocklist_de)|29129|29129|2714|9.3%|100.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|215|0.0%|7.9%|
[firehol_level3](#firehol_level3)|108767|9626344|90|0.0%|3.3%|
[stopforumspam_30d](#stopforumspam_30d)|94236|94236|71|0.0%|2.6%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|50|0.1%|1.8%|
[sorbs_spam](#sorbs_spam)|64701|65536|48|0.0%|1.7%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|48|0.0%|1.7%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|48|0.0%|1.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|42|0.0%|1.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|35|0.0%|1.2%|
[stopforumspam_1d](#stopforumspam_1d)|6864|6864|33|0.4%|1.2%|
[snort_ipfilter](#snort_ipfilter)|8373|8373|31|0.3%|1.1%|
[nixspam](#nixspam)|22540|22540|21|0.0%|0.7%|
[firehol_anonymous](#firehol_anonymous)|19320|83371|18|0.0%|0.6%|
[tor_exits](#tor_exits)|1106|1106|13|1.1%|0.4%|
[alienvault_reputation](#alienvault_reputation)|189217|189217|13|0.0%|0.4%|
[et_tor](#et_tor)|6500|6500|10|0.1%|0.3%|
[blocklist_de_strongips](#blocklist_de_strongips)|168|168|8|4.7%|0.2%|
[php_spammers](#php_spammers)|777|777|6|0.7%|0.2%|
[php_commenters](#php_commenters)|458|458|6|1.3%|0.2%|
[dm_tor](#dm_tor)|6559|6559|6|0.0%|0.2%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|5|0.0%|0.1%|
[firehol_proxies](#firehol_proxies)|12732|13012|5|0.0%|0.1%|
[firehol_level1](#firehol_level1)|5068|688775049|5|0.0%|0.1%|
[et_block](#et_block)|1000|18343756|5|0.0%|0.1%|
[bm_tor](#bm_tor)|6533|6533|5|0.0%|0.1%|
[ri_web_proxies](#ri_web_proxies)|8035|8035|4|0.0%|0.1%|
[dragon_http](#dragon_http)|1021|268288|4|0.0%|0.1%|
[php_dictionary](#php_dictionary)|777|777|3|0.3%|0.1%|
[iw_spamlist](#iw_spamlist)|3266|3266|3|0.0%|0.1%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|2|0.0%|0.0%|
[xroxy](#xroxy)|2176|2176|1|0.0%|0.0%|
[shunlist](#shunlist)|1129|1129|1|0.0%|0.0%|
[proxz](#proxz)|1385|1385|1|0.0%|0.0%|
[php_harvesters](#php_harvesters)|408|408|1|0.2%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.0%|

## blocklist_de_ftp

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours for attacks on the Service FTP.

Source is downloaded from [this link](http://lists.blocklist.de/lists/ftp.txt).

The last time downloaded was found to be dated: Fri Jun 12 15:42:09 UTC 2015.

The ipset `blocklist_de_ftp` has **1509** entries, **1509** unique IPs.

The following table shows the overlaps of `blocklist_de_ftp` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_ftp`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_ftp`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_ftp`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|22948|34548|1496|4.3%|99.1%|
[blocklist_de](#blocklist_de)|29129|29129|1496|5.1%|99.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|118|0.0%|7.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|26|0.0%|1.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|24|0.0%|1.5%|
[firehol_level3](#firehol_level3)|108767|9626344|17|0.0%|1.1%|
[sorbs_spam](#sorbs_spam)|64701|65536|15|0.0%|0.9%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|15|0.0%|0.9%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|15|0.0%|0.9%|
[nixspam](#nixspam)|22540|22540|15|0.0%|0.9%|
[stopforumspam_30d](#stopforumspam_30d)|94236|94236|12|0.0%|0.7%|
[alienvault_reputation](#alienvault_reputation)|189217|189217|8|0.0%|0.5%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|6|0.0%|0.3%|
[dragon_http](#dragon_http)|1021|268288|6|0.0%|0.3%|
[php_harvesters](#php_harvesters)|408|408|3|0.7%|0.1%|
[iw_spamlist](#iw_spamlist)|3266|3266|3|0.0%|0.1%|
[firehol_anonymous](#firehol_anonymous)|19320|83371|3|0.0%|0.1%|
[stopforumspam_1d](#stopforumspam_1d)|6864|6864|1|0.0%|0.0%|
[sorbs_web](#sorbs_web)|667|668|1|0.1%|0.0%|
[php_spammers](#php_spammers)|777|777|1|0.1%|0.0%|
[php_dictionary](#php_dictionary)|777|777|1|0.1%|0.0%|
[openbl_7d](#openbl_7d)|638|638|1|0.1%|0.0%|
[openbl_60d](#openbl_60d)|6959|6959|1|0.0%|0.0%|
[openbl_30d](#openbl_30d)|2791|2791|1|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|1|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|18292|18292|1|0.0%|0.0%|

## blocklist_de_imap

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours for attacks on the Service imap, sasl, pop3, etc.

Source is downloaded from [this link](http://lists.blocklist.de/lists/imap.txt).

The last time downloaded was found to be dated: Fri Jun 12 15:42:08 UTC 2015.

The ipset `blocklist_de_imap` has **3535** entries, **3535** unique IPs.

The following table shows the overlaps of `blocklist_de_imap` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_imap`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_imap`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_imap`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|22948|34548|3526|10.2%|99.7%|
[blocklist_de_mail](#blocklist_de_mail)|18292|18292|3526|19.2%|99.7%|
[blocklist_de](#blocklist_de)|29129|29129|3526|12.1%|99.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|431|0.0%|12.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|75|0.0%|2.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|71|0.0%|2.0%|
[nixspam](#nixspam)|22540|22540|62|0.2%|1.7%|
[firehol_level3](#firehol_level3)|108767|9626344|42|0.0%|1.1%|
[alienvault_reputation](#alienvault_reputation)|189217|189217|34|0.0%|0.9%|
[sorbs_spam](#sorbs_spam)|64701|65536|33|0.0%|0.9%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|32|0.0%|0.9%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|32|0.0%|0.9%|
[stopforumspam_30d](#stopforumspam_30d)|94236|94236|20|0.0%|0.5%|
[openbl_60d](#openbl_60d)|6959|6959|16|0.2%|0.4%|
[firehol_level1](#firehol_level1)|5068|688775049|16|0.0%|0.4%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|15|0.0%|0.4%|
[et_block](#et_block)|1000|18343756|15|0.0%|0.4%|
[openbl_30d](#openbl_30d)|2791|2791|11|0.3%|0.3%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|8|0.0%|0.2%|
[dragon_http](#dragon_http)|1021|268288|8|0.0%|0.2%|
[openbl_7d](#openbl_7d)|638|638|7|1.0%|0.1%|
[iw_spamlist](#iw_spamlist)|3266|3266|6|0.1%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|5|0.0%|0.1%|
[et_compromised](#et_compromised)|1704|1704|5|0.2%|0.1%|
[bruteforceblocker](#bruteforceblocker)|1700|1700|5|0.2%|0.1%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|4|0.0%|0.1%|
[stopforumspam_1d](#stopforumspam_1d)|6864|6864|3|0.0%|0.0%|
[php_harvesters](#php_harvesters)|408|408|3|0.7%|0.0%|
[shunlist](#shunlist)|1129|1129|2|0.1%|0.0%|
[voipbl](#voipbl)|10607|11019|1|0.0%|0.0%|
[virbl](#virbl)|15|15|1|6.6%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|1|0.0%|0.0%|
[sorbs_web](#sorbs_web)|667|668|1|0.1%|0.0%|
[snort_ipfilter](#snort_ipfilter)|8373|8373|1|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2902|2902|1|0.0%|0.0%|
[openbl_1d](#openbl_1d)|155|155|1|0.6%|0.0%|
[firehol_proxies](#firehol_proxies)|12732|13012|1|0.0%|0.0%|
[firehol_anonymous](#firehol_anonymous)|19320|83371|1|0.0%|0.0%|
[dragon_vncprobe](#dragon_vncprobe)|85|85|1|1.1%|0.0%|
[dragon_sshpauth](#dragon_sshpauth)|1568|1632|1|0.0%|0.0%|
[ciarmy](#ciarmy)|428|428|1|0.2%|0.0%|

## blocklist_de_mail

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service Mail, Postfix.

Source is downloaded from [this link](http://lists.blocklist.de/lists/mail.txt).

The last time downloaded was found to be dated: Fri Jun 12 15:56:08 UTC 2015.

The ipset `blocklist_de_mail` has **18292** entries, **18292** unique IPs.

The following table shows the overlaps of `blocklist_de_mail` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_mail`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_mail`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_mail`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|22948|34548|18292|52.9%|100.0%|
[blocklist_de](#blocklist_de)|29129|29129|18292|62.7%|100.0%|
[blocklist_de_apache](#blocklist_de_apache)|14109|14109|11059|78.3%|60.4%|
[blocklist_de_imap](#blocklist_de_imap)|3535|3535|3526|99.7%|19.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|2771|0.0%|15.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|1407|0.0%|7.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|1211|0.0%|6.6%|
[nixspam](#nixspam)|22540|22540|681|3.0%|3.7%|
[sorbs_spam](#sorbs_spam)|64701|65536|645|0.9%|3.5%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|636|0.9%|3.4%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|636|0.9%|3.4%|
[firehol_level3](#firehol_level3)|108767|9626344|386|0.0%|2.1%|
[stopforumspam_30d](#stopforumspam_30d)|94236|94236|252|0.2%|1.3%|
[snort_ipfilter](#snort_ipfilter)|8373|8373|164|1.9%|0.8%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|134|0.4%|0.7%|
[iw_spamlist](#iw_spamlist)|3266|3266|126|3.8%|0.6%|
[firehol_anonymous](#firehol_anonymous)|19320|83371|120|0.1%|0.6%|
[firehol_proxies](#firehol_proxies)|12732|13012|119|0.9%|0.6%|
[php_dictionary](#php_dictionary)|777|777|89|11.4%|0.4%|
[ri_web_proxies](#ri_web_proxies)|8035|8035|83|1.0%|0.4%|
[php_spammers](#php_spammers)|777|777|76|9.7%|0.4%|
[sorbs_web](#sorbs_web)|667|668|68|10.1%|0.3%|
[xroxy](#xroxy)|2176|2176|52|2.3%|0.2%|
[alienvault_reputation](#alienvault_reputation)|189217|189217|48|0.0%|0.2%|
[stopforumspam_1d](#stopforumspam_1d)|6864|6864|38|0.5%|0.2%|
[proxz](#proxz)|1385|1385|29|2.0%|0.1%|
[php_commenters](#php_commenters)|458|458|29|6.3%|0.1%|
[firehol_level1](#firehol_level1)|5068|688775049|27|0.0%|0.1%|
[et_block](#et_block)|1000|18343756|25|0.0%|0.1%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|24|0.0%|0.1%|
[blocklist_de_bots](#blocklist_de_bots)|3035|3035|22|0.7%|0.1%|
[openbl_60d](#openbl_60d)|6959|6959|20|0.2%|0.1%|
[blocklist_de_strongips](#blocklist_de_strongips)|168|168|20|11.9%|0.1%|
[openbl_30d](#openbl_30d)|2791|2791|14|0.5%|0.0%|
[dragon_http](#dragon_http)|1021|268288|14|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|9|0.0%|0.0%|
[openbl_7d](#openbl_7d)|638|638|7|1.0%|0.0%|
[php_harvesters](#php_harvesters)|408|408|6|1.4%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|6|0.0%|0.0%|
[et_compromised](#et_compromised)|1704|1704|5|0.2%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1700|1700|5|0.2%|0.0%|
[shunlist](#shunlist)|1129|1129|4|0.3%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|3|0.0%|0.0%|
[et_tor](#et_tor)|6500|6500|3|0.0%|0.0%|
[ciarmy](#ciarmy)|428|428|3|0.7%|0.0%|
[voipbl](#voipbl)|10607|11019|2|0.0%|0.0%|
[virbl](#virbl)|15|15|2|13.3%|0.0%|
[tor_exits](#tor_exits)|1106|1106|2|0.1%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2902|2902|2|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|2|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|2|0.3%|0.0%|
[dragon_vncprobe](#dragon_vncprobe)|85|85|2|2.3%|0.0%|
[dm_tor](#dm_tor)|6559|6559|2|0.0%|0.0%|
[bm_tor](#bm_tor)|6533|6533|2|0.0%|0.0%|
[sorbs_socks](#sorbs_socks)|7|7|1|14.2%|0.0%|
[sorbs_misc](#sorbs_misc)|7|7|1|14.2%|0.0%|
[sorbs_http](#sorbs_http)|7|7|1|14.2%|0.0%|
[openbl_1d](#openbl_1d)|155|155|1|0.6%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|1|0.1%|0.0%|
[dragon_sshpauth](#dragon_sshpauth)|1568|1632|1|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|1509|1509|1|0.0%|0.0%|

## blocklist_de_sip

[Blocklist.de](https://www.blocklist.de/) All IP addresses that tried to login in a SIP, VOIP or Asterisk Server and are included in the IPs list from [infiltrated.net](www.infiltrated.net)

Source is downloaded from [this link](http://lists.blocklist.de/lists/sip.txt).

The last time downloaded was found to be dated: Fri Jun 12 15:42:09 UTC 2015.

The ipset `blocklist_de_sip` has **80** entries, **80** unique IPs.

The following table shows the overlaps of `blocklist_de_sip` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_sip`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_sip`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_sip`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|22948|34548|60|0.1%|75.0%|
[blocklist_de](#blocklist_de)|29129|29129|60|0.2%|75.0%|
[voipbl](#voipbl)|10607|11019|32|0.2%|40.0%|
[alienvault_reputation](#alienvault_reputation)|189217|189217|19|0.0%|23.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|18|0.0%|22.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|5|0.0%|6.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|4|0.0%|5.0%|
[firehol_level3](#firehol_level3)|108767|9626344|4|0.0%|5.0%|
[dragon_http](#dragon_http)|1021|268288|3|0.0%|3.7%|
[shunlist](#shunlist)|1129|1129|2|0.1%|2.5%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|2|0.0%|2.5%|
[et_botcc](#et_botcc)|505|505|1|0.1%|1.2%|

## blocklist_de_ssh

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service SSH.

Source is downloaded from [this link](http://lists.blocklist.de/lists/ssh.txt).

The last time downloaded was found to be dated: Fri Jun 12 15:42:05 UTC 2015.

The ipset `blocklist_de_ssh` has **3204** entries, **3204** unique IPs.

The following table shows the overlaps of `blocklist_de_ssh` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_ssh`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_ssh`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_ssh`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|22948|34548|3199|9.2%|99.8%|
[blocklist_de](#blocklist_de)|29129|29129|3199|10.9%|99.8%|
[alienvault_reputation](#alienvault_reputation)|189217|189217|931|0.4%|29.0%|
[firehol_level3](#firehol_level3)|108767|9626344|827|0.0%|25.8%|
[openbl_60d](#openbl_60d)|6959|6959|763|10.9%|23.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|626|0.0%|19.5%|
[openbl_30d](#openbl_30d)|2791|2791|616|22.0%|19.2%|
[dragon_sshpauth](#dragon_sshpauth)|1568|1632|604|37.0%|18.8%|
[bruteforceblocker](#bruteforceblocker)|1700|1700|539|31.7%|16.8%|
[et_compromised](#et_compromised)|1704|1704|515|30.2%|16.0%|
[openbl_7d](#openbl_7d)|638|638|362|56.7%|11.2%|
[shunlist](#shunlist)|1129|1129|286|25.3%|8.9%|
[openbl_1d](#openbl_1d)|155|155|124|80.0%|3.8%|
[firehol_level1](#firehol_level1)|5068|688775049|105|0.0%|3.2%|
[et_block](#et_block)|1000|18343756|95|0.0%|2.9%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|90|0.0%|2.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|86|0.0%|2.6%|
[dshield](#dshield)|20|5120|62|1.2%|1.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|49|0.0%|1.5%|
[blocklist_de_strongips](#blocklist_de_strongips)|168|168|26|15.4%|0.8%|
[stopforumspam_30d](#stopforumspam_30d)|94236|94236|24|0.0%|0.7%|
[dragon_http](#dragon_http)|1021|268288|13|0.0%|0.4%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|6|0.0%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|5|0.0%|0.1%|
[ciarmy](#ciarmy)|428|428|4|0.9%|0.1%|
[voipbl](#voipbl)|10607|11019|3|0.0%|0.0%|
[sorbs_spam](#sorbs_spam)|64701|65536|3|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|3|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|3|0.0%|0.0%|
[nixspam](#nixspam)|22540|22540|3|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6864|6864|2|0.0%|0.0%|
[dragon_vncprobe](#dragon_vncprobe)|85|85|2|2.3%|0.0%|
[php_spammers](#php_spammers)|777|777|1|0.1%|0.0%|
[php_harvesters](#php_harvesters)|408|408|1|0.2%|0.0%|
[php_commenters](#php_commenters)|458|458|1|0.2%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|1|0.0%|0.0%|

## blocklist_de_strongips

[Blocklist.de](https://www.blocklist.de/) All IPs which are older then 2 month and have more then 5.000 attacks.

Source is downloaded from [this link](http://lists.blocklist.de/lists/strongips.txt).

The last time downloaded was found to be dated: Fri Jun 12 15:42:15 UTC 2015.

The ipset `blocklist_de_strongips` has **168** entries, **168** unique IPs.

The following table shows the overlaps of `blocklist_de_strongips` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_strongips`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_strongips`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_strongips`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|22948|34548|168|0.4%|100.0%|
[blocklist_de](#blocklist_de)|29129|29129|168|0.5%|100.0%|
[firehol_level3](#firehol_level3)|108767|9626344|155|0.0%|92.2%|
[stopforumspam_30d](#stopforumspam_30d)|94236|94236|131|0.1%|77.9%|
[blocklist_de_bots](#blocklist_de_bots)|3035|3035|129|4.2%|76.7%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|116|0.3%|69.0%|
[stopforumspam_1d](#stopforumspam_1d)|6864|6864|97|1.4%|57.7%|
[php_commenters](#php_commenters)|458|458|43|9.3%|25.5%|
[alienvault_reputation](#alienvault_reputation)|189217|189217|33|0.0%|19.6%|
[blocklist_de_apache](#blocklist_de_apache)|14109|14109|31|0.2%|18.4%|
[blocklist_de_ssh](#blocklist_de_ssh)|3204|3204|26|0.8%|15.4%|
[openbl_60d](#openbl_60d)|6959|6959|23|0.3%|13.6%|
[openbl_7d](#openbl_7d)|638|638|22|3.4%|13.0%|
[openbl_30d](#openbl_30d)|2791|2791|22|0.7%|13.0%|
[dragon_sshpauth](#dragon_sshpauth)|1568|1632|20|1.2%|11.9%|
[blocklist_de_mail](#blocklist_de_mail)|18292|18292|20|0.1%|11.9%|
[shunlist](#shunlist)|1129|1129|19|1.6%|11.3%|
[openbl_1d](#openbl_1d)|155|155|19|12.2%|11.3%|
[firehol_level1](#firehol_level1)|5068|688775049|19|0.0%|11.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|17|0.0%|10.1%|
[et_block](#et_block)|1000|18343756|13|0.0%|7.7%|
[dshield](#dshield)|20|5120|12|0.2%|7.1%|
[php_spammers](#php_spammers)|777|777|10|1.2%|5.9%|
[firehol_proxies](#firehol_proxies)|12732|13012|9|0.0%|5.3%|
[firehol_anonymous](#firehol_anonymous)|19320|83371|9|0.0%|5.3%|
[ri_web_proxies](#ri_web_proxies)|8035|8035|8|0.0%|4.7%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2714|2714|8|0.2%|4.7%|
[xroxy](#xroxy)|2176|2176|7|0.3%|4.1%|
[proxyrss](#proxyrss)|1402|1402|7|0.4%|4.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|7|0.0%|4.1%|
[proxz](#proxz)|1385|1385|6|0.4%|3.5%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|5|0.0%|2.9%|
[php_dictionary](#php_dictionary)|777|777|5|0.6%|2.9%|
[php_harvesters](#php_harvesters)|408|408|3|0.7%|1.7%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|2|0.0%|1.1%|
[sorbs_web](#sorbs_web)|667|668|2|0.2%|1.1%|
[sorbs_spam](#sorbs_spam)|64701|65536|2|0.0%|1.1%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|2|0.0%|1.1%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|2|0.0%|1.1%|
[snort_ipfilter](#snort_ipfilter)|8373|8373|2|0.0%|1.1%|
[nixspam](#nixspam)|22540|22540|2|0.0%|1.1%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|2|0.1%|1.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|2|0.0%|1.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2|0.0%|1.1%|
[dragon_http](#dragon_http)|1021|268288|2|0.0%|1.1%|
[et_compromised](#et_compromised)|1704|1704|1|0.0%|0.5%|
[ciarmy](#ciarmy)|428|428|1|0.2%|0.5%|
[bruteforceblocker](#bruteforceblocker)|1700|1700|1|0.0%|0.5%|

## bm_tor

[torstatus.blutmagie.de](https://torstatus.blutmagie.de) list of all TOR network servers

Source is downloaded from [this link](https://torstatus.blutmagie.de/ip_list_all.php/Tor_ip_list_ALL.csv).

The last time downloaded was found to be dated: Fri Jun 12 15:54:03 UTC 2015.

The ipset `bm_tor` has **6533** entries, **6533** unique IPs.

The following table shows the overlaps of `bm_tor` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `bm_tor`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `bm_tor`.
- ` this % ` is the percentage **of this ipset (`bm_tor`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_anonymous](#firehol_anonymous)|19320|83371|6533|7.8%|100.0%|
[dm_tor](#dm_tor)|6559|6559|6454|98.3%|98.7%|
[et_tor](#et_tor)|6500|6500|5713|87.8%|87.4%|
[firehol_level3](#firehol_level3)|108767|9626344|1111|0.0%|17.0%|
[snort_ipfilter](#snort_ipfilter)|8373|8373|1074|12.8%|16.4%|
[tor_exits](#tor_exits)|1106|1106|1028|92.9%|15.7%|
[stopforumspam_30d](#stopforumspam_30d)|94236|94236|643|0.6%|9.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|629|0.0%|9.6%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|527|1.8%|8.0%|
[firehol_level2](#firehol_level2)|22948|34548|345|0.9%|5.2%|
[stopforumspam_1d](#stopforumspam_1d)|6864|6864|342|4.9%|5.2%|
[firehol_proxies](#firehol_proxies)|12732|13012|234|1.7%|3.5%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|229|43.7%|3.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|184|0.0%|2.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|170|0.0%|2.6%|
[php_commenters](#php_commenters)|458|458|54|11.7%|0.8%|
[alienvault_reputation](#alienvault_reputation)|189217|189217|41|0.0%|0.6%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|22|0.0%|0.3%|
[openbl_60d](#openbl_60d)|6959|6959|20|0.2%|0.3%|
[dragon_http](#dragon_http)|1021|268288|16|0.0%|0.2%|
[php_harvesters](#php_harvesters)|408|408|7|1.7%|0.1%|
[nixspam](#nixspam)|22540|22540|7|0.0%|0.1%|
[blocklist_de_apache](#blocklist_de_apache)|14109|14109|7|0.0%|0.1%|
[blocklist_de](#blocklist_de)|29129|29129|7|0.0%|0.1%|
[ri_web_proxies](#ri_web_proxies)|8035|8035|5|0.0%|0.0%|
[php_spammers](#php_spammers)|777|777|5|0.6%|0.0%|
[firehol_level1](#firehol_level1)|5068|688775049|5|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2714|2714|5|0.1%|0.0%|
[sorbs_spam](#sorbs_spam)|64701|65536|4|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|4|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|4|0.0%|0.0%|
[php_dictionary](#php_dictionary)|777|777|4|0.5%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|4|0.0%|0.0%|
[et_block](#et_block)|1000|18343756|4|0.0%|0.0%|
[voipbl](#voipbl)|10607|11019|3|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|3|0.0%|0.0%|
[xroxy](#xroxy)|2176|2176|2|0.0%|0.0%|
[shunlist](#shunlist)|1129|1129|2|0.1%|0.0%|
[dshield](#dshield)|20|5120|2|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|18292|18292|2|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2902|2902|1|0.0%|0.0%|

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
[firehol_level1](#firehol_level1)|5068|688775049|592708608|86.0%|100.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|4194304|3.0%|0.7%|
[voipbl](#voipbl)|10607|11019|319|2.8%|0.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|5|0.0%|0.0%|
[firehol_level3](#firehol_level3)|108767|9626344|3|0.0%|0.0%|
[iw_spamlist](#iw_spamlist)|3266|3266|2|0.0%|0.0%|
[php_harvesters](#php_harvesters)|408|408|1|0.2%|0.0%|
[php_commenters](#php_commenters)|458|458|1|0.2%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.0%|
[ciarmy](#ciarmy)|428|428|1|0.2%|0.0%|

## bruteforceblocker

[danger.rulez.sk](http://danger.rulez.sk/) IPs detected by [bruteforceblocker](http://danger.rulez.sk/index.php/bruteforceblocker/) (fail2ban alternative for SSH on OpenBSD). This is an automatically generated list from users reporting failed authentication attempts. An IP seems to be included if 3 or more users report it. Its retention pocily seems 30 days.

Source is downloaded from [this link](http://danger.rulez.sk/projects/bruteforceblocker/blist.php).

The last time downloaded was found to be dated: Fri Jun 12 15:18:30 UTC 2015.

The ipset `bruteforceblocker` has **1700** entries, **1700** unique IPs.

The following table shows the overlaps of `bruteforceblocker` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `bruteforceblocker`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `bruteforceblocker`.
- ` this % ` is the percentage **of this ipset (`bruteforceblocker`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level3](#firehol_level3)|108767|9626344|1700|0.0%|100.0%|
[et_compromised](#et_compromised)|1704|1704|1652|96.9%|97.1%|
[alienvault_reputation](#alienvault_reputation)|189217|189217|1074|0.5%|63.1%|
[openbl_60d](#openbl_60d)|6959|6959|964|13.8%|56.7%|
[openbl_30d](#openbl_30d)|2791|2791|904|32.3%|53.1%|
[dragon_sshpauth](#dragon_sshpauth)|1568|1632|632|38.7%|37.1%|
[firehol_level2](#firehol_level2)|22948|34548|547|1.5%|32.1%|
[blocklist_de](#blocklist_de)|29129|29129|546|1.8%|32.1%|
[blocklist_de_ssh](#blocklist_de_ssh)|3204|3204|539|16.8%|31.7%|
[shunlist](#shunlist)|1129|1129|312|27.6%|18.3%|
[openbl_7d](#openbl_7d)|638|638|306|47.9%|18.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|157|0.0%|9.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|86|0.0%|5.0%|
[openbl_1d](#openbl_1d)|155|155|67|43.2%|3.9%|
[firehol_level1](#firehol_level1)|5068|688775049|67|0.0%|3.9%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|61|0.0%|3.5%|
[et_block](#et_block)|1000|18343756|61|0.0%|3.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|53|0.0%|3.1%|
[dshield](#dshield)|20|5120|25|0.4%|1.4%|
[dragon_http](#dragon_http)|1021|268288|14|0.0%|0.8%|
[stopforumspam_30d](#stopforumspam_30d)|94236|94236|9|0.0%|0.5%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|5|0.0%|0.2%|
[blocklist_de_mail](#blocklist_de_mail)|18292|18292|5|0.0%|0.2%|
[blocklist_de_imap](#blocklist_de_imap)|3535|3535|5|0.1%|0.2%|
[voipbl](#voipbl)|10607|11019|3|0.0%|0.1%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|3|0.0%|0.1%|
[sorbs_spam](#sorbs_spam)|64701|65536|3|0.0%|0.1%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|3|0.0%|0.1%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|3|0.0%|0.1%|
[firehol_proxies](#firehol_proxies)|12732|13012|3|0.0%|0.1%|
[firehol_anonymous](#firehol_anonymous)|19320|83371|3|0.0%|0.1%|
[ciarmy](#ciarmy)|428|428|3|0.7%|0.1%|
[stopforumspam_1d](#stopforumspam_1d)|6864|6864|2|0.0%|0.1%|
[proxz](#proxz)|1385|1385|2|0.1%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|2|0.0%|0.1%|
[xroxy](#xroxy)|2176|2176|1|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|8035|8035|1|0.0%|0.0%|
[proxyrss](#proxyrss)|1402|1402|1|0.0%|0.0%|
[php_spammers](#php_spammers)|777|777|1|0.1%|0.0%|
[php_commenters](#php_commenters)|458|458|1|0.2%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|168|168|1|0.5%|0.0%|

## ciarmy

[CIArmy.com](http://ciarmy.com/) IPs with poor Rogue Packet score that have not yet been identified as malicious by the community

Source is downloaded from [this link](http://cinsscore.com/list/ci-badguys.txt).

The last time downloaded was found to be dated: Fri Jun 12 13:15:07 UTC 2015.

The ipset `ciarmy` has **428** entries, **428** unique IPs.

The following table shows the overlaps of `ciarmy` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ciarmy`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ciarmy`.
- ` this % ` is the percentage **of this ipset (`ciarmy`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level3](#firehol_level3)|108767|9626344|428|0.0%|100.0%|
[alienvault_reputation](#alienvault_reputation)|189217|189217|426|0.2%|99.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|70|0.0%|16.3%|
[firehol_level2](#firehol_level2)|22948|34548|36|0.1%|8.4%|
[blocklist_de](#blocklist_de)|29129|29129|36|0.1%|8.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|34|0.0%|7.9%|
[shunlist](#shunlist)|1129|1129|30|2.6%|7.0%|
[blocklist_de_apache](#blocklist_de_apache)|14109|14109|29|0.2%|6.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|23|0.0%|5.3%|
[dragon_http](#dragon_http)|1021|268288|12|0.0%|2.8%|
[firehol_level1](#firehol_level1)|5068|688775049|6|0.0%|1.4%|
[dshield](#dshield)|20|5120|5|0.0%|1.1%|
[blocklist_de_ssh](#blocklist_de_ssh)|3204|3204|4|0.1%|0.9%|
[et_compromised](#et_compromised)|1704|1704|3|0.1%|0.7%|
[bruteforceblocker](#bruteforceblocker)|1700|1700|3|0.1%|0.7%|
[blocklist_de_mail](#blocklist_de_mail)|18292|18292|3|0.0%|0.7%|
[voipbl](#voipbl)|10607|11019|2|0.0%|0.4%|
[stopforumspam_30d](#stopforumspam_30d)|94236|94236|2|0.0%|0.4%|
[openbl_7d](#openbl_7d)|638|638|2|0.3%|0.4%|
[openbl_60d](#openbl_60d)|6959|6959|2|0.0%|0.4%|
[openbl_30d](#openbl_30d)|2791|2791|2|0.0%|0.4%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|1|0.0%|0.2%|
[fullbogons](#fullbogons)|3788|670093640|1|0.0%|0.2%|
[et_block](#et_block)|1000|18343756|1|0.0%|0.2%|
[dragon_vncprobe](#dragon_vncprobe)|85|85|1|1.1%|0.2%|
[dragon_sshpauth](#dragon_sshpauth)|1568|1632|1|0.0%|0.2%|
[bogons](#bogons)|13|592708608|1|0.0%|0.2%|
[blocklist_de_strongips](#blocklist_de_strongips)|168|168|1|0.5%|0.2%|
[blocklist_de_imap](#blocklist_de_imap)|3535|3535|1|0.0%|0.2%|

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
[firehol_level3](#firehol_level3)|108767|9626344|511|0.0%|100.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|58|0.0%|11.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|28|0.0%|5.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|25|0.0%|4.8%|
[malc0de](#malc0de)|238|238|7|2.9%|1.3%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|4|0.3%|0.7%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|4|0.0%|0.7%|
[alienvault_reputation](#alienvault_reputation)|189217|189217|4|0.0%|0.7%|
[stopforumspam_30d](#stopforumspam_30d)|94236|94236|1|0.0%|0.1%|
[sorbs_spam](#sorbs_spam)|64701|65536|1|0.0%|0.1%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|1|0.0%|0.1%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|1|0.0%|0.1%|
[snort_ipfilter](#snort_ipfilter)|8373|8373|1|0.0%|0.1%|

## dm_tor

[dan.me.uk](https://www.dan.me.uk) dynamic list of TOR nodes

Source is downloaded from [this link](https://www.dan.me.uk/torlist/).

The last time downloaded was found to be dated: Fri Jun 12 16:09:10 UTC 2015.

The ipset `dm_tor` has **6559** entries, **6559** unique IPs.

The following table shows the overlaps of `dm_tor` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `dm_tor`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `dm_tor`.
- ` this % ` is the percentage **of this ipset (`dm_tor`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_anonymous](#firehol_anonymous)|19320|83371|6559|7.8%|100.0%|
[bm_tor](#bm_tor)|6533|6533|6454|98.7%|98.3%|
[et_tor](#et_tor)|6500|6500|5719|87.9%|87.1%|
[firehol_level3](#firehol_level3)|108767|9626344|1107|0.0%|16.8%|
[snort_ipfilter](#snort_ipfilter)|8373|8373|1069|12.7%|16.2%|
[tor_exits](#tor_exits)|1106|1106|1022|92.4%|15.5%|
[stopforumspam_30d](#stopforumspam_30d)|94236|94236|645|0.6%|9.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|632|0.0%|9.6%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|528|1.8%|8.0%|
[firehol_level2](#firehol_level2)|22948|34548|345|0.9%|5.2%|
[stopforumspam_1d](#stopforumspam_1d)|6864|6864|341|4.9%|5.1%|
[firehol_proxies](#firehol_proxies)|12732|13012|234|1.7%|3.5%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|229|43.7%|3.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|185|0.0%|2.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|170|0.0%|2.5%|
[php_commenters](#php_commenters)|458|458|54|11.7%|0.8%|
[alienvault_reputation](#alienvault_reputation)|189217|189217|42|0.0%|0.6%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|22|0.0%|0.3%|
[openbl_60d](#openbl_60d)|6959|6959|20|0.2%|0.3%|
[dragon_http](#dragon_http)|1021|268288|16|0.0%|0.2%|
[blocklist_de_apache](#blocklist_de_apache)|14109|14109|8|0.0%|0.1%|
[blocklist_de](#blocklist_de)|29129|29129|8|0.0%|0.1%|
[php_harvesters](#php_harvesters)|408|408|7|1.7%|0.1%|
[nixspam](#nixspam)|22540|22540|7|0.0%|0.1%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2714|2714|6|0.2%|0.0%|
[ri_web_proxies](#ri_web_proxies)|8035|8035|5|0.0%|0.0%|
[php_spammers](#php_spammers)|777|777|5|0.6%|0.0%|
[firehol_level1](#firehol_level1)|5068|688775049|5|0.0%|0.0%|
[sorbs_spam](#sorbs_spam)|64701|65536|4|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|4|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|4|0.0%|0.0%|
[php_dictionary](#php_dictionary)|777|777|4|0.5%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|4|0.0%|0.0%|
[et_block](#et_block)|1000|18343756|4|0.0%|0.0%|
[voipbl](#voipbl)|10607|11019|3|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|3|0.0%|0.0%|
[xroxy](#xroxy)|2176|2176|2|0.0%|0.0%|
[shunlist](#shunlist)|1129|1129|2|0.1%|0.0%|
[dshield](#dshield)|20|5120|2|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|18292|18292|2|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2902|2902|1|0.0%|0.0%|

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
[alienvault_reputation](#alienvault_reputation)|189217|189217|6157|3.2%|2.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|5989|0.0%|2.2%|
[firehol_level1](#firehol_level1)|5068|688775049|1025|0.0%|0.3%|
[et_block](#et_block)|1000|18343756|1024|0.0%|0.3%|
[dshield](#dshield)|20|5120|768|15.0%|0.2%|
[firehol_level3](#firehol_level3)|108767|9626344|564|0.0%|0.2%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|256|0.0%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|256|0.0%|0.0%|
[openbl_60d](#openbl_60d)|6959|6959|214|3.0%|0.0%|
[openbl_30d](#openbl_30d)|2791|2791|148|5.3%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|94236|94236|110|0.1%|0.0%|
[sorbs_spam](#sorbs_spam)|64701|65536|72|0.1%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|71|0.1%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|71|0.1%|0.0%|
[firehol_level2](#firehol_level2)|22948|34548|62|0.1%|0.0%|
[openbl_7d](#openbl_7d)|638|638|54|8.4%|0.0%|
[blocklist_de](#blocklist_de)|29129|29129|49|0.1%|0.0%|
[firehol_anonymous](#firehol_anonymous)|19320|83371|46|0.0%|0.0%|
[nixspam](#nixspam)|22540|22540|33|0.1%|0.0%|
[firehol_proxies](#firehol_proxies)|12732|13012|33|0.2%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|32|0.1%|0.0%|
[voipbl](#voipbl)|10607|11019|29|0.2%|0.0%|
[shunlist](#shunlist)|1129|1129|26|2.3%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|25|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|8035|8035|21|0.2%|0.0%|
[dragon_vncprobe](#dragon_vncprobe)|85|85|20|23.5%|0.0%|
[et_tor](#et_tor)|6500|6500|16|0.2%|0.0%|
[dm_tor](#dm_tor)|6559|6559|16|0.2%|0.0%|
[bm_tor](#bm_tor)|6533|6533|16|0.2%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1700|1700|14|0.8%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|18292|18292|14|0.0%|0.0%|
[et_compromised](#et_compromised)|1704|1704|13|0.7%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3204|3204|13|0.4%|0.0%|
[ciarmy](#ciarmy)|428|428|12|2.8%|0.0%|
[snort_ipfilter](#snort_ipfilter)|8373|8373|11|0.1%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14109|14109|10|0.0%|0.0%|
[openbl_1d](#openbl_1d)|155|155|9|5.8%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|3535|3535|8|0.2%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6864|6864|7|0.1%|0.0%|
[xroxy](#xroxy)|2176|2176|6|0.2%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|6|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|1509|1509|6|0.3%|0.0%|
[tor_exits](#tor_exits)|1106|1106|5|0.4%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2902|2902|4|0.1%|0.0%|
[proxz](#proxz)|1385|1385|4|0.2%|0.0%|
[php_commenters](#php_commenters)|458|458|4|0.8%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|4|0.7%|0.0%|
[dragon_sshpauth](#dragon_sshpauth)|1568|1632|4|0.2%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2714|2714|4|0.1%|0.0%|
[zeus_badips](#zeus_badips)|202|202|3|1.4%|0.0%|
[zeus](#zeus)|230|230|3|1.3%|0.0%|
[malc0de](#malc0de)|238|238|3|1.2%|0.0%|
[et_botcc](#et_botcc)|505|505|3|0.5%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|80|80|3|3.7%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3035|3035|3|0.0%|0.0%|
[proxyrss](#proxyrss)|1402|1402|2|0.1%|0.0%|
[php_dictionary](#php_dictionary)|777|777|2|0.2%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|2|0.1%|0.0%|
[iw_spamlist](#iw_spamlist)|3266|3266|2|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|2|0.1%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|168|168|2|1.1%|0.0%|
[sslbl](#sslbl)|368|368|1|0.2%|0.0%|
[sorbs_web](#sorbs_web)|667|668|1|0.1%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|1|0.1%|0.0%|

## dragon_sshpauth

[Dragon Search Group](http://www.dragonresearchgroup.org/) IP address that has been seen attempting to remotely login to a host using SSH password authentication, in the last 7 days. This report lists hosts that are highly suspicious and are likely conducting malicious SSH password authentication attacks.

Source is downloaded from [this link](https://www.dragonresearchgroup.org/insight/sshpwauth.txt).

The last time downloaded was found to be dated: Fri Jun 12 16:04:25 UTC 2015.

The ipset `dragon_sshpauth` has **1568** entries, **1632** unique IPs.

The following table shows the overlaps of `dragon_sshpauth` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `dragon_sshpauth`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `dragon_sshpauth`.
- ` this % ` is the percentage **of this ipset (`dragon_sshpauth`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[alienvault_reputation](#alienvault_reputation)|189217|189217|858|0.4%|52.5%|
[firehol_level3](#firehol_level3)|108767|9626344|854|0.0%|52.3%|
[openbl_60d](#openbl_60d)|6959|6959|775|11.1%|47.4%|
[openbl_30d](#openbl_30d)|2791|2791|693|24.8%|42.4%|
[bruteforceblocker](#bruteforceblocker)|1700|1700|632|37.1%|38.7%|
[et_compromised](#et_compromised)|1704|1704|622|36.5%|38.1%|
[firehol_level2](#firehol_level2)|22948|34548|606|1.7%|37.1%|
[blocklist_de](#blocklist_de)|29129|29129|605|2.0%|37.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3204|3204|604|18.8%|37.0%|
[shunlist](#shunlist)|1129|1129|355|31.4%|21.7%|
[openbl_7d](#openbl_7d)|638|638|344|53.9%|21.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|126|0.0%|7.7%|
[firehol_level1](#firehol_level1)|5068|688775049|107|0.0%|6.5%|
[et_block](#et_block)|1000|18343756|100|0.0%|6.1%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|99|0.0%|6.0%|
[openbl_1d](#openbl_1d)|155|155|94|60.6%|5.7%|
[dshield](#dshield)|20|5120|80|1.5%|4.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|72|0.0%|4.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|32|0.0%|1.9%|
[blocklist_de_strongips](#blocklist_de_strongips)|168|168|20|11.9%|1.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|5|0.0%|0.3%|
[stopforumspam_30d](#stopforumspam_30d)|94236|94236|4|0.0%|0.2%|
[dragon_http](#dragon_http)|1021|268288|4|0.0%|0.2%|
[voipbl](#voipbl)|10607|11019|1|0.0%|0.0%|
[sslbl](#sslbl)|368|368|1|0.2%|0.0%|
[sorbs_spam](#sorbs_spam)|64701|65536|1|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|1|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|1|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|1|0.0%|0.0%|
[ciarmy](#ciarmy)|428|428|1|0.2%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|18292|18292|1|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|3535|3535|1|0.0%|0.0%|

## dragon_vncprobe

[Dragon Search Group](http://www.dragonresearchgroup.org/) IP address that has been seen attempting to remotely connect to a host running the VNC application service, in the last 7 days. This report lists hosts that are highly suspicious and are likely conducting malicious VNC probes or VNC brute force attacks.

Source is downloaded from [this link](https://www.dragonresearchgroup.org/insight/vncprobe.txt).

The last time downloaded was found to be dated: Fri Jun 12 16:04:01 UTC 2015.

The ipset `dragon_vncprobe` has **85** entries, **85** unique IPs.

The following table shows the overlaps of `dragon_vncprobe` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `dragon_vncprobe`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `dragon_vncprobe`.
- ` this % ` is the percentage **of this ipset (`dragon_vncprobe`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[alienvault_reputation](#alienvault_reputation)|189217|189217|28|0.0%|32.9%|
[dragon_http](#dragon_http)|1021|268288|20|0.0%|23.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|13|0.0%|15.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|8|0.0%|9.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|5|0.0%|5.8%|
[firehol_level2](#firehol_level2)|22948|34548|5|0.0%|5.8%|
[blocklist_de](#blocklist_de)|29129|29129|5|0.0%|5.8%|
[firehol_level3](#firehol_level3)|108767|9626344|4|0.0%|4.7%|
[et_block](#et_block)|1000|18343756|4|0.0%|4.7%|
[shunlist](#shunlist)|1129|1129|2|0.1%|2.3%|
[firehol_level1](#firehol_level1)|5068|688775049|2|0.0%|2.3%|
[blocklist_de_ssh](#blocklist_de_ssh)|3204|3204|2|0.0%|2.3%|
[blocklist_de_mail](#blocklist_de_mail)|18292|18292|2|0.0%|2.3%|
[voipbl](#voipbl)|10607|11019|1|0.0%|1.1%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|1|0.0%|1.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|1.1%|
[dshield](#dshield)|20|5120|1|0.0%|1.1%|
[ciarmy](#ciarmy)|428|428|1|0.2%|1.1%|
[blocklist_de_imap](#blocklist_de_imap)|3535|3535|1|0.0%|1.1%|
[blocklist_de_apache](#blocklist_de_apache)|14109|14109|1|0.0%|1.1%|

## dshield

[DShield.org](https://dshield.org/) top 20 attacking class C (/24) subnets over the last three days - **excellent list**

Source is downloaded from [this link](http://feeds.dshield.org/block.txt).

The last time downloaded was found to be dated: Fri Jun 12 12:27:03 UTC 2015.

The ipset `dshield` has **20** entries, **5120** unique IPs.

The following table shows the overlaps of `dshield` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `dshield`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `dshield`.
- ` this % ` is the percentage **of this ipset (`dshield`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level1](#firehol_level1)|5068|688775049|5120|0.0%|100.0%|
[alienvault_reputation](#alienvault_reputation)|189217|189217|5120|2.7%|100.0%|
[et_block](#et_block)|1000|18343756|1536|0.0%|30.0%|
[dragon_http](#dragon_http)|1021|268288|768|0.2%|15.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|256|0.0%|5.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|256|0.0%|5.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|256|0.0%|5.0%|
[firehol_level3](#firehol_level3)|108767|9626344|121|0.0%|2.3%|
[openbl_60d](#openbl_60d)|6959|6959|84|1.2%|1.6%|
[openbl_30d](#openbl_30d)|2791|2791|80|2.8%|1.5%|
[dragon_sshpauth](#dragon_sshpauth)|1568|1632|80|4.9%|1.5%|
[shunlist](#shunlist)|1129|1129|78|6.9%|1.5%|
[firehol_level2](#firehol_level2)|22948|34548|75|0.2%|1.4%|
[blocklist_de](#blocklist_de)|29129|29129|71|0.2%|1.3%|
[blocklist_de_ssh](#blocklist_de_ssh)|3204|3204|62|1.9%|1.2%|
[et_compromised](#et_compromised)|1704|1704|29|1.7%|0.5%|
[bruteforceblocker](#bruteforceblocker)|1700|1700|25|1.4%|0.4%|
[openbl_7d](#openbl_7d)|638|638|22|3.4%|0.4%|
[stopforumspam_30d](#stopforumspam_30d)|94236|94236|20|0.0%|0.3%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|15|0.0%|0.2%|
[blocklist_de_strongips](#blocklist_de_strongips)|168|168|12|7.1%|0.2%|
[stopforumspam_1d](#stopforumspam_1d)|6864|6864|11|0.1%|0.2%|
[blocklist_de_bots](#blocklist_de_bots)|3035|3035|8|0.2%|0.1%|
[openbl_1d](#openbl_1d)|155|155|5|3.2%|0.0%|
[ciarmy](#ciarmy)|428|428|5|1.1%|0.0%|
[firehol_anonymous](#firehol_anonymous)|19320|83371|2|0.0%|0.0%|
[et_tor](#et_tor)|6500|6500|2|0.0%|0.0%|
[dm_tor](#dm_tor)|6559|6559|2|0.0%|0.0%|
[bm_tor](#bm_tor)|6533|6533|2|0.0%|0.0%|
[tor_exits](#tor_exits)|1106|1106|1|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|8373|8373|1|0.0%|0.0%|
[php_commenters](#php_commenters)|458|458|1|0.2%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|1|0.1%|0.0%|
[firehol_proxies](#firehol_proxies)|12732|13012|1|0.0%|0.0%|
[dragon_vncprobe](#dragon_vncprobe)|85|85|1|1.1%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14109|14109|1|0.0%|0.0%|

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
[firehol_level1](#firehol_level1)|5068|688775049|18340091|2.6%|99.9%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|18338560|99.9%|99.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|8532776|2.4%|46.5%|
[firehol_level3](#firehol_level3)|108767|9626344|6933353|72.0%|37.7%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|6932480|75.5%|37.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|2272787|0.2%|12.3%|
[fullbogons](#fullbogons)|3788|670093640|151552|0.0%|0.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|130650|0.0%|0.7%|
[alienvault_reputation](#alienvault_reputation)|189217|189217|3752|1.9%|0.0%|
[dshield](#dshield)|20|5120|1536|30.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1041|0.3%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|94236|94236|1026|1.0%|0.0%|
[dragon_http](#dragon_http)|1021|268288|1024|0.3%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|517|0.1%|0.0%|
[snort_ipfilter](#snort_ipfilter)|8373|8373|297|3.5%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|283|0.9%|0.0%|
[firehol_level2](#firehol_level2)|22948|34548|252|0.7%|0.0%|
[openbl_60d](#openbl_60d)|6959|6959|244|3.5%|0.0%|
[zeus](#zeus)|230|230|229|99.5%|0.0%|
[zeus_badips](#zeus_badips)|202|202|202|100.0%|0.0%|
[blocklist_de](#blocklist_de)|29129|29129|185|0.6%|0.0%|
[openbl_30d](#openbl_30d)|2791|2791|125|4.4%|0.0%|
[dragon_sshpauth](#dragon_sshpauth)|1568|1632|100|6.1%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6864|6864|96|1.3%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3204|3204|95|2.9%|0.0%|
[shunlist](#shunlist)|1129|1129|93|8.2%|0.0%|
[et_compromised](#et_compromised)|1704|1704|65|3.8%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1700|1700|61|3.5%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3035|3035|58|1.9%|0.0%|
[openbl_7d](#openbl_7d)|638|638|57|8.9%|0.0%|
[sslbl](#sslbl)|368|368|38|10.3%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|30|2.3%|0.0%|
[php_commenters](#php_commenters)|458|458|29|6.3%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|18292|18292|25|0.1%|0.0%|
[sorbs_spam](#sorbs_spam)|64701|65536|20|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|20|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|20|0.0%|0.0%|
[nixspam](#nixspam)|22540|22540|20|0.0%|0.0%|
[voipbl](#voipbl)|10607|11019|18|0.1%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|3535|3535|15|0.4%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|168|168|13|7.7%|0.0%|
[openbl_1d](#openbl_1d)|155|155|10|6.4%|0.0%|
[firehol_anonymous](#firehol_anonymous)|19320|83371|8|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14109|14109|7|0.0%|0.0%|
[php_dictionary](#php_dictionary)|777|777|6|0.7%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|6|0.4%|0.0%|
[php_spammers](#php_spammers)|777|777|5|0.6%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|5|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2714|2714|5|0.1%|0.0%|
[nt_malware_http](#nt_malware_http)|69|69|4|5.7%|0.0%|
[iw_spamlist](#iw_spamlist)|3266|3266|4|0.1%|0.0%|
[firehol_proxies](#firehol_proxies)|12732|13012|4|0.0%|0.0%|
[et_tor](#et_tor)|6500|6500|4|0.0%|0.0%|
[dragon_vncprobe](#dragon_vncprobe)|85|85|4|4.7%|0.0%|
[dm_tor](#dm_tor)|6559|6559|4|0.0%|0.0%|
[bm_tor](#bm_tor)|6533|6533|4|0.0%|0.0%|
[nt_malware_irc](#nt_malware_irc)|43|43|3|6.9%|0.0%|
[tor_exits](#tor_exits)|1106|1106|2|0.1%|0.0%|
[malc0de](#malc0de)|238|238|2|0.8%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|2|0.3%|0.0%|
[virbl](#virbl)|15|15|1|6.6%|0.0%|
[proxz](#proxz)|1385|1385|1|0.0%|0.0%|
[php_harvesters](#php_harvesters)|408|408|1|0.2%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|1|0.1%|0.0%|
[et_botcc](#et_botcc)|505|505|1|0.1%|0.0%|
[ciarmy](#ciarmy)|428|428|1|0.2%|0.0%|

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
[alienvault_reputation](#alienvault_reputation)|189217|189217|4|0.0%|0.7%|
[firehol_level3](#firehol_level3)|108767|9626344|3|0.0%|0.5%|
[dragon_http](#dragon_http)|1021|268288|3|0.0%|0.5%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|1|0.0%|0.1%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|1|0.0%|0.1%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|1|0.0%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.1%|
[firehol_level1](#firehol_level1)|5068|688775049|1|0.0%|0.1%|
[et_block](#et_block)|1000|18343756|1|0.0%|0.1%|
[blocklist_de_sip](#blocklist_de_sip)|80|80|1|1.2%|0.1%|

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
[firehol_level3](#firehol_level3)|108767|9626344|1671|0.0%|98.0%|
[bruteforceblocker](#bruteforceblocker)|1700|1700|1652|97.1%|96.9%|
[alienvault_reputation](#alienvault_reputation)|189217|189217|1086|0.5%|63.7%|
[openbl_60d](#openbl_60d)|6959|6959|977|14.0%|57.3%|
[openbl_30d](#openbl_30d)|2791|2791|908|32.5%|53.2%|
[dragon_sshpauth](#dragon_sshpauth)|1568|1632|622|38.1%|36.5%|
[firehol_level2](#firehol_level2)|22948|34548|521|1.5%|30.5%|
[blocklist_de](#blocklist_de)|29129|29129|520|1.7%|30.5%|
[blocklist_de_ssh](#blocklist_de_ssh)|3204|3204|515|16.0%|30.2%|
[shunlist](#shunlist)|1129|1129|309|27.3%|18.1%|
[openbl_7d](#openbl_7d)|638|638|301|47.1%|17.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|157|0.0%|9.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|89|0.0%|5.2%|
[firehol_level1](#firehol_level1)|5068|688775049|71|0.0%|4.1%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|65|0.0%|3.8%|
[et_block](#et_block)|1000|18343756|65|0.0%|3.8%|
[openbl_1d](#openbl_1d)|155|155|62|40.0%|3.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|54|0.0%|3.1%|
[dshield](#dshield)|20|5120|29|0.5%|1.7%|
[dragon_http](#dragon_http)|1021|268288|13|0.0%|0.7%|
[stopforumspam_30d](#stopforumspam_30d)|94236|94236|10|0.0%|0.5%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|5|0.0%|0.2%|
[blocklist_de_mail](#blocklist_de_mail)|18292|18292|5|0.0%|0.2%|
[blocklist_de_imap](#blocklist_de_imap)|3535|3535|5|0.1%|0.2%|
[voipbl](#voipbl)|10607|11019|3|0.0%|0.1%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|3|0.0%|0.1%|
[sorbs_spam](#sorbs_spam)|64701|65536|3|0.0%|0.1%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|3|0.0%|0.1%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|3|0.0%|0.1%|
[firehol_proxies](#firehol_proxies)|12732|13012|3|0.0%|0.1%|
[firehol_anonymous](#firehol_anonymous)|19320|83371|3|0.0%|0.1%|
[ciarmy](#ciarmy)|428|428|3|0.7%|0.1%|
[stopforumspam_1d](#stopforumspam_1d)|6864|6864|2|0.0%|0.1%|
[proxz](#proxz)|1385|1385|2|0.1%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|2|0.0%|0.1%|
[xroxy](#xroxy)|2176|2176|1|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|8035|8035|1|0.0%|0.0%|
[proxyrss](#proxyrss)|1402|1402|1|0.0%|0.0%|
[php_spammers](#php_spammers)|777|777|1|0.1%|0.0%|
[php_commenters](#php_commenters)|458|458|1|0.2%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|168|168|1|0.5%|0.0%|

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
[firehol_anonymous](#firehol_anonymous)|19320|83371|5756|6.9%|88.5%|
[dm_tor](#dm_tor)|6559|6559|5719|87.1%|87.9%|
[bm_tor](#bm_tor)|6533|6533|5713|87.4%|87.8%|
[firehol_level3](#firehol_level3)|108767|9626344|1123|0.0%|17.2%|
[snort_ipfilter](#snort_ipfilter)|8373|8373|1088|12.9%|16.7%|
[tor_exits](#tor_exits)|1106|1106|966|87.3%|14.8%|
[stopforumspam_30d](#stopforumspam_30d)|94236|94236|662|0.7%|10.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|636|0.0%|9.7%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|547|1.8%|8.4%|
[firehol_level2](#firehol_level2)|22948|34548|348|1.0%|5.3%|
[stopforumspam_1d](#stopforumspam_1d)|6864|6864|341|4.9%|5.2%|
[firehol_proxies](#firehol_proxies)|12732|13012|238|1.8%|3.6%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|233|44.4%|3.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|182|0.0%|2.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|168|0.0%|2.5%|
[php_commenters](#php_commenters)|458|458|54|11.7%|0.8%|
[alienvault_reputation](#alienvault_reputation)|189217|189217|42|0.0%|0.6%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|22|0.0%|0.3%|
[openbl_60d](#openbl_60d)|6959|6959|20|0.2%|0.3%|
[dragon_http](#dragon_http)|1021|268288|16|0.0%|0.2%|
[blocklist_de_apache](#blocklist_de_apache)|14109|14109|13|0.0%|0.2%|
[blocklist_de](#blocklist_de)|29129|29129|13|0.0%|0.2%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2714|2714|10|0.3%|0.1%|
[php_harvesters](#php_harvesters)|408|408|7|1.7%|0.1%|
[ri_web_proxies](#ri_web_proxies)|8035|8035|5|0.0%|0.0%|
[php_spammers](#php_spammers)|777|777|5|0.6%|0.0%|
[nixspam](#nixspam)|22540|22540|5|0.0%|0.0%|
[firehol_level1](#firehol_level1)|5068|688775049|5|0.0%|0.0%|
[sorbs_spam](#sorbs_spam)|64701|65536|4|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|4|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|4|0.0%|0.0%|
[php_dictionary](#php_dictionary)|777|777|4|0.5%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|4|0.0%|0.0%|
[et_block](#et_block)|1000|18343756|4|0.0%|0.0%|
[voipbl](#voipbl)|10607|11019|3|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|3|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|18292|18292|3|0.0%|0.0%|
[xroxy](#xroxy)|2176|2176|2|0.0%|0.0%|
[shunlist](#shunlist)|1129|1129|2|0.1%|0.0%|
[dshield](#dshield)|20|5120|2|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2902|2902|1|0.0%|0.0%|

## feodo

[Abuse.ch Feodo tracker](https://feodotracker.abuse.ch) trojan includes IPs which are being used by Feodo (also known as Cridex or Bugat) which commits ebanking fraud - **excellent list**

Source is downloaded from [this link](https://feodotracker.abuse.ch/blocklist/?download=ipblocklist).

The last time downloaded was found to be dated: Fri Jun 12 15:45:14 UTC 2015.

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

The ipset `firehol_anonymous` has **19320** entries, **83371** unique IPs.

The following table shows the overlaps of `firehol_anonymous` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `firehol_anonymous`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `firehol_anonymous`.
- ` this % ` is the percentage **of this ipset (`firehol_anonymous`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_proxies](#firehol_proxies)|12732|13012|13012|100.0%|15.6%|
[ri_web_proxies](#ri_web_proxies)|8035|8035|8035|100.0%|9.6%|
[firehol_level3](#firehol_level3)|108767|9626344|6858|0.0%|8.2%|
[dm_tor](#dm_tor)|6559|6559|6559|100.0%|7.8%|
[bm_tor](#bm_tor)|6533|6533|6533|100.0%|7.8%|
[stopforumspam_30d](#stopforumspam_30d)|94236|94236|6281|6.6%|7.5%|
[et_tor](#et_tor)|6500|6500|5756|88.5%|6.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|3448|0.0%|4.1%|
[ri_connect_proxies](#ri_connect_proxies)|2902|2902|2902|100.0%|3.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|2896|0.0%|3.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|2881|0.0%|3.4%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|2710|9.3%|3.2%|
[xroxy](#xroxy)|2176|2176|2176|100.0%|2.6%|
[proxyrss](#proxyrss)|1402|1402|1402|100.0%|1.6%|
[proxz](#proxz)|1385|1385|1385|100.0%|1.6%|
[firehol_level2](#firehol_level2)|22948|34548|1332|3.8%|1.5%|
[snort_ipfilter](#snort_ipfilter)|8373|8373|1246|14.8%|1.4%|
[tor_exits](#tor_exits)|1106|1106|1106|100.0%|1.3%|
[stopforumspam_1d](#stopforumspam_1d)|6864|6864|955|13.9%|1.1%|
[blocklist_de](#blocklist_de)|29129|29129|674|2.3%|0.8%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|663|100.0%|0.7%|
[blocklist_de_bots](#blocklist_de_bots)|3035|3035|531|17.4%|0.6%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|524|100.0%|0.6%|
[sorbs_spam](#sorbs_spam)|64701|65536|201|0.3%|0.2%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|201|0.3%|0.2%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|201|0.3%|0.2%|
[nixspam](#nixspam)|22540|22540|135|0.5%|0.1%|
[blocklist_de_mail](#blocklist_de_mail)|18292|18292|120|0.6%|0.1%|
[php_dictionary](#php_dictionary)|777|777|102|13.1%|0.1%|
[php_commenters](#php_commenters)|458|458|89|19.4%|0.1%|
[php_spammers](#php_spammers)|777|777|85|10.9%|0.1%|
[voipbl](#voipbl)|10607|11019|79|0.7%|0.0%|
[alienvault_reputation](#alienvault_reputation)|189217|189217|58|0.0%|0.0%|
[dragon_http](#dragon_http)|1021|268288|46|0.0%|0.0%|
[sorbs_web](#sorbs_web)|667|668|31|4.6%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|29|0.0%|0.0%|
[openbl_60d](#openbl_60d)|6959|6959|23|0.3%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14109|14109|21|0.1%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2714|2714|18|0.6%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|17|0.0%|0.0%|
[php_harvesters](#php_harvesters)|408|408|12|2.9%|0.0%|
[firehol_level1](#firehol_level1)|5068|688775049|9|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|168|168|9|5.3%|0.0%|
[et_block](#et_block)|1000|18343756|8|0.0%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|7|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|6|0.0%|0.0%|
[iw_spamlist](#iw_spamlist)|3266|3266|6|0.1%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|3|0.2%|0.0%|
[et_compromised](#et_compromised)|1704|1704|3|0.1%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1700|1700|3|0.1%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|1509|1509|3|0.1%|0.0%|
[shunlist](#shunlist)|1129|1129|2|0.1%|0.0%|
[dshield](#dshield)|20|5120|2|0.0%|0.0%|
[sslbl](#sslbl)|368|368|1|0.2%|0.0%|
[openbl_30d](#openbl_30d)|2791|2791|1|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|3535|3535|1|0.0%|0.0%|

## firehol_level1

**FireHOL Level 1** - Maximum protection without false positives. (includes: fullbogons dshield feodo palevo sslbl zeus spamhaus_drop spamhaus_edrop)

Source is downloaded from [this link]().

The last time downloaded was found to be dated: Sun Jun  7 22:15:43 UTC 2015.

The ipset `firehol_level1` has **5068** entries, **688775049** unique IPs.

The following table shows the overlaps of `firehol_level1` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `firehol_level1`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `firehol_level1`.
- ` this % ` is the percentage **of this ipset (`firehol_level1`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[fullbogons](#fullbogons)|3788|670093640|670093640|100.0%|97.2%|
[bogons](#bogons)|13|592708608|592708608|100.0%|86.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|18340608|100.0%|2.6%|
[et_block](#et_block)|1000|18343756|18340091|99.9%|2.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|8867711|2.5%|1.2%|
[firehol_level3](#firehol_level3)|108767|9626344|7500132|77.9%|1.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|7498240|81.6%|1.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|4637594|3.3%|0.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|2570559|0.3%|0.3%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|487424|100.0%|0.0%|
[alienvault_reputation](#alienvault_reputation)|189217|189217|6387|3.3%|0.0%|
[dshield](#dshield)|20|5120|5120|100.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1930|0.5%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|94236|94236|1102|1.1%|0.0%|
[dragon_http](#dragon_http)|1021|268288|1025|0.3%|0.0%|
[sslbl](#sslbl)|368|368|368|100.0%|0.0%|
[voipbl](#voipbl)|10607|11019|333|3.0%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|291|1.0%|0.0%|
[firehol_level2](#firehol_level2)|22948|34548|267|0.7%|0.0%|
[openbl_60d](#openbl_60d)|6959|6959|253|3.6%|0.0%|
[snort_ipfilter](#snort_ipfilter)|8373|8373|237|2.8%|0.0%|
[zeus](#zeus)|230|230|230|100.0%|0.0%|
[zeus_badips](#zeus_badips)|202|202|202|100.0%|0.0%|
[blocklist_de](#blocklist_de)|29129|29129|198|0.6%|0.0%|
[shunlist](#shunlist)|1129|1129|153|13.5%|0.0%|
[openbl_30d](#openbl_30d)|2791|2791|135|4.8%|0.0%|
[dragon_sshpauth](#dragon_sshpauth)|1568|1632|107|6.5%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3204|3204|105|3.2%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6864|6864|101|1.4%|0.0%|
[et_compromised](#et_compromised)|1704|1704|71|4.1%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1700|1700|67|3.9%|0.0%|
[openbl_7d](#openbl_7d)|638|638|60|9.4%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3035|3035|60|1.9%|0.0%|
[php_commenters](#php_commenters)|458|458|39|8.5%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|39|3.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|39|2.6%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|18292|18292|27|0.1%|0.0%|
[sorbs_spam](#sorbs_spam)|64701|65536|25|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|25|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|25|0.0%|0.0%|
[nixspam](#nixspam)|22540|22540|22|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|168|168|19|11.3%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|18|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|3535|3535|16|0.4%|0.0%|
[openbl_1d](#openbl_1d)|155|155|13|8.3%|0.0%|
[firehol_anonymous](#firehol_anonymous)|19320|83371|9|0.0%|0.0%|
[nt_malware_http](#nt_malware_http)|69|69|8|11.5%|0.0%|
[iw_spamlist](#iw_spamlist)|3266|3266|7|0.2%|0.0%|
[php_dictionary](#php_dictionary)|777|777|6|0.7%|0.0%|
[ciarmy](#ciarmy)|428|428|6|1.4%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14109|14109|6|0.0%|0.0%|
[php_spammers](#php_spammers)|777|777|5|0.6%|0.0%|
[firehol_proxies](#firehol_proxies)|12732|13012|5|0.0%|0.0%|
[et_tor](#et_tor)|6500|6500|5|0.0%|0.0%|
[dm_tor](#dm_tor)|6559|6559|5|0.0%|0.0%|
[bm_tor](#bm_tor)|6533|6533|5|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2714|2714|5|0.1%|0.0%|
[tor_exits](#tor_exits)|1106|1106|3|0.2%|0.0%|
[php_harvesters](#php_harvesters)|408|408|3|0.7%|0.0%|
[nt_malware_irc](#nt_malware_irc)|43|43|3|6.9%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|2|0.3%|0.0%|
[malc0de](#malc0de)|238|238|2|0.8%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|2|0.3%|0.0%|
[dragon_vncprobe](#dragon_vncprobe)|85|85|2|2.3%|0.0%|
[virbl](#virbl)|15|15|1|6.6%|0.0%|
[ri_web_proxies](#ri_web_proxies)|8035|8035|1|0.0%|0.0%|
[et_botcc](#et_botcc)|505|505|1|0.1%|0.0%|

## firehol_level2

**FireHOL Level 2** - Maximum protection from attacks took place in the last 48 hours. (includes: openbl_1d blocklist_de stopforumspam_1d)

Source is downloaded from [this link]().

The last time downloaded was found to be dated: Sun Jun  7 22:20:34 UTC 2015.

The ipset `firehol_level2` has **22948** entries, **34548** unique IPs.

The following table shows the overlaps of `firehol_level2` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `firehol_level2`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `firehol_level2`.
- ` this % ` is the percentage **of this ipset (`firehol_level2`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|29129|29129|29129|100.0%|84.3%|
[blocklist_de_mail](#blocklist_de_mail)|18292|18292|18292|100.0%|52.9%|
[blocklist_de_apache](#blocklist_de_apache)|14109|14109|14109|100.0%|40.8%|
[firehol_level3](#firehol_level3)|108767|9626344|8807|0.0%|25.4%|
[stopforumspam_30d](#stopforumspam_30d)|94236|94236|7725|8.1%|22.3%|
[stopforumspam_1d](#stopforumspam_1d)|6864|6864|6864|100.0%|19.8%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|5917|20.3%|17.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|4398|0.0%|12.7%|
[blocklist_de_imap](#blocklist_de_imap)|3535|3535|3526|99.7%|10.2%|
[blocklist_de_ssh](#blocklist_de_ssh)|3204|3204|3199|99.8%|9.2%|
[blocklist_de_bots](#blocklist_de_bots)|3035|3035|3025|99.6%|8.7%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2714|2714|2714|100.0%|7.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|1685|0.0%|4.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|1594|0.0%|4.6%|
[blocklist_de_ftp](#blocklist_de_ftp)|1509|1509|1496|99.1%|4.3%|
[firehol_anonymous](#firehol_anonymous)|19320|83371|1332|1.5%|3.8%|
[alienvault_reputation](#alienvault_reputation)|189217|189217|1203|0.6%|3.4%|
[firehol_proxies](#firehol_proxies)|12732|13012|1158|8.8%|3.3%|
[openbl_60d](#openbl_60d)|6959|6959|839|12.0%|2.4%|
[nixspam](#nixspam)|22540|22540|776|3.4%|2.2%|
[sorbs_spam](#sorbs_spam)|64701|65536|748|1.1%|2.1%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|739|1.1%|2.1%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|739|1.1%|2.1%|
[ri_web_proxies](#ri_web_proxies)|8035|8035|672|8.3%|1.9%|
[openbl_30d](#openbl_30d)|2791|2791|664|23.7%|1.9%|
[dragon_sshpauth](#dragon_sshpauth)|1568|1632|606|37.1%|1.7%|
[snort_ipfilter](#snort_ipfilter)|8373|8373|565|6.7%|1.6%|
[bruteforceblocker](#bruteforceblocker)|1700|1700|547|32.1%|1.5%|
[et_compromised](#et_compromised)|1704|1704|521|30.5%|1.5%|
[openbl_7d](#openbl_7d)|638|638|399|62.5%|1.1%|
[tor_exits](#tor_exits)|1106|1106|356|32.1%|1.0%|
[et_tor](#et_tor)|6500|6500|348|5.3%|1.0%|
[proxyrss](#proxyrss)|1402|1402|347|24.7%|1.0%|
[dm_tor](#dm_tor)|6559|6559|345|5.2%|0.9%|
[bm_tor](#bm_tor)|6533|6533|345|5.2%|0.9%|
[shunlist](#shunlist)|1129|1129|335|29.6%|0.9%|
[xroxy](#xroxy)|2176|2176|310|14.2%|0.8%|
[proxz](#proxz)|1385|1385|276|19.9%|0.7%|
[firehol_level1](#firehol_level1)|5068|688775049|267|0.0%|0.7%|
[et_block](#et_block)|1000|18343756|252|0.0%|0.7%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|232|0.0%|0.6%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|208|39.6%|0.6%|
[php_commenters](#php_commenters)|458|458|197|43.0%|0.5%|
[blocklist_de_strongips](#blocklist_de_strongips)|168|168|168|100.0%|0.4%|
[ri_connect_proxies](#ri_connect_proxies)|2902|2902|157|5.4%|0.4%|
[openbl_1d](#openbl_1d)|155|155|155|100.0%|0.4%|
[iw_spamlist](#iw_spamlist)|3266|3266|137|4.1%|0.3%|
[php_dictionary](#php_dictionary)|777|777|118|15.1%|0.3%|
[php_spammers](#php_spammers)|777|777|117|15.0%|0.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|80|0.0%|0.2%|
[sorbs_web](#sorbs_web)|667|668|76|11.3%|0.2%|
[dshield](#dshield)|20|5120|75|1.4%|0.2%|
[dragon_http](#dragon_http)|1021|268288|62|0.0%|0.1%|
[blocklist_de_sip](#blocklist_de_sip)|80|80|60|75.0%|0.1%|
[php_harvesters](#php_harvesters)|408|408|54|13.2%|0.1%|
[voipbl](#voipbl)|10607|11019|42|0.3%|0.1%|
[ciarmy](#ciarmy)|428|428|36|8.4%|0.1%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|15|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|12|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|8|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|7|1.0%|0.0%|
[dragon_vncprobe](#dragon_vncprobe)|85|85|5|5.8%|0.0%|
[virbl](#virbl)|15|15|2|13.3%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|2|0.1%|0.0%|
[zeus_badips](#zeus_badips)|202|202|1|0.4%|0.0%|
[zeus](#zeus)|230|230|1|0.4%|0.0%|
[sorbs_socks](#sorbs_socks)|7|7|1|14.2%|0.0%|
[sorbs_misc](#sorbs_misc)|7|7|1|14.2%|0.0%|
[sorbs_http](#sorbs_http)|7|7|1|14.2%|0.0%|
[fullbogons](#fullbogons)|3788|670093640|1|0.0%|0.0%|

## firehol_level3

**FireHOL Level 3** - All the bad IPs in last 30 days. (includes: openbl_30d stopforumspam_30d virbl malc0de shunlist malwaredomainlist bruteforceblocker ciarmy cleanmx_viruses snort_ipfilter ib_bluetack_spyware ib_bluetack_hijacked ib_bluetack_webexploit php_commenters php_dictionary php_harvesters php_spammers iw_wormlist)

Source is downloaded from [this link]().

The last time downloaded was found to be dated: Sun Jun  7 22:20:34 UTC 2015.

The ipset `firehol_level3` has **108767** entries, **9626344** unique IPs.

The following table shows the overlaps of `firehol_level3` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `firehol_level3`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `firehol_level3`.
- ` this % ` is the percentage **of this ipset (`firehol_level3`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|9177856|100.0%|95.3%|
[firehol_level1](#firehol_level1)|5068|688775049|7500132|1.0%|77.9%|
[et_block](#et_block)|1000|18343756|6933353|37.7%|72.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|6933043|37.8%|72.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|2537261|0.7%|26.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|919962|0.1%|9.5%|
[fullbogons](#fullbogons)|3788|670093640|566692|0.0%|5.8%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|339173|100.0%|3.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|161585|0.1%|1.6%|
[stopforumspam_30d](#stopforumspam_30d)|94236|94236|94236|100.0%|0.9%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|29017|100.0%|0.3%|
[firehol_level2](#firehol_level2)|22948|34548|8807|25.4%|0.0%|
[snort_ipfilter](#snort_ipfilter)|8373|8373|8373|100.0%|0.0%|
[firehol_anonymous](#firehol_anonymous)|19320|83371|6858|8.2%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6864|6864|6330|92.2%|0.0%|
[firehol_proxies](#firehol_proxies)|12732|13012|5733|44.0%|0.0%|
[alienvault_reputation](#alienvault_reputation)|189217|189217|4825|2.5%|0.0%|
[blocklist_de](#blocklist_de)|29129|29129|3889|13.3%|0.0%|
[ri_web_proxies](#ri_web_proxies)|8035|8035|3796|47.2%|0.0%|
[openbl_60d](#openbl_60d)|6959|6959|2915|41.8%|0.0%|
[openbl_30d](#openbl_30d)|2791|2791|2791|100.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3035|3035|2512|82.7%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1700|1700|1700|100.0%|0.0%|
[et_compromised](#et_compromised)|1704|1704|1671|98.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2902|2902|1608|55.4%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|1450|100.0%|0.0%|
[xroxy](#xroxy)|2176|2176|1300|59.7%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|1288|100.0%|0.0%|
[shunlist](#shunlist)|1129|1129|1129|100.0%|0.0%|
[et_tor](#et_tor)|6500|6500|1123|17.2%|0.0%|
[bm_tor](#bm_tor)|6533|6533|1111|17.0%|0.0%|
[dm_tor](#dm_tor)|6559|6559|1107|16.8%|0.0%|
[tor_exits](#tor_exits)|1106|1106|1092|98.7%|0.0%|
[sorbs_spam](#sorbs_spam)|64701|65536|877|1.3%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|874|1.3%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|874|1.3%|0.0%|
[dragon_sshpauth](#dragon_sshpauth)|1568|1632|854|52.3%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3204|3204|827|25.8%|0.0%|
[proxz](#proxz)|1385|1385|824|59.4%|0.0%|
[php_spammers](#php_spammers)|777|777|777|100.0%|0.0%|
[php_dictionary](#php_dictionary)|777|777|777|100.0%|0.0%|
[proxyrss](#proxyrss)|1402|1402|651|46.4%|0.0%|
[openbl_7d](#openbl_7d)|638|638|638|100.0%|0.0%|
[dragon_http](#dragon_http)|1021|268288|564|0.2%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|511|511|511|100.0%|0.0%|
[nixspam](#nixspam)|22540|22540|496|2.2%|0.0%|
[php_commenters](#php_commenters)|458|458|458|100.0%|0.0%|
[ciarmy](#ciarmy)|428|428|428|100.0%|0.0%|
[php_harvesters](#php_harvesters)|408|408|408|100.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|18292|18292|386|2.1%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|347|66.2%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14109|14109|283|2.0%|0.0%|
[malc0de](#malc0de)|238|238|238|100.0%|0.0%|
[zeus](#zeus)|230|230|203|88.2%|0.0%|
[zeus_badips](#zeus_badips)|202|202|180|89.1%|0.0%|
[openbl_1d](#openbl_1d)|155|155|155|100.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|168|168|155|92.2%|0.0%|
[dshield](#dshield)|20|5120|121|2.3%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2714|2714|90|3.3%|0.0%|
[sslbl](#sslbl)|368|368|89|24.1%|0.0%|
[iw_spamlist](#iw_spamlist)|3266|3266|86|2.6%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|82|0.0%|0.0%|
[sorbs_web](#sorbs_web)|667|668|73|10.9%|0.0%|
[voipbl](#voipbl)|10607|11019|57|0.5%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|3535|3535|42|1.1%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|25|3.7%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|24|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|1509|1509|17|1.1%|0.0%|
[virbl](#virbl)|15|15|15|100.0%|0.0%|
[iw_wormlist](#iw_wormlist)|4|4|4|100.0%|0.0%|
[dragon_vncprobe](#dragon_vncprobe)|85|85|4|4.7%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|80|80|4|5.0%|0.0%|
[sorbs_socks](#sorbs_socks)|7|7|3|42.8%|0.0%|
[sorbs_misc](#sorbs_misc)|7|7|3|42.8%|0.0%|
[sorbs_http](#sorbs_http)|7|7|3|42.8%|0.0%|
[nt_malware_http](#nt_malware_http)|69|69|3|4.3%|0.0%|
[et_botcc](#et_botcc)|505|505|3|0.5%|0.0%|
[bogons](#bogons)|13|592708608|3|0.0%|0.0%|
[nt_malware_irc](#nt_malware_irc)|43|43|1|2.3%|0.0%|

## firehol_proxies

**FireHOL Proxies** - Known open proxies in the last 30 days. (includes: ib_bluetack_proxies maxmind_proxy_fraud proxyrss proxz ri_connect_proxies ri_web_proxies xroxy)

Source is downloaded from [this link]().

The last time downloaded was found to be dated: Sun Jun  7 22:20:34 UTC 2015.

The ipset `firehol_proxies` has **12732** entries, **13012** unique IPs.

The following table shows the overlaps of `firehol_proxies` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `firehol_proxies`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `firehol_proxies`.
- ` this % ` is the percentage **of this ipset (`firehol_proxies`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_anonymous](#firehol_anonymous)|19320|83371|13012|15.6%|100.0%|
[ri_web_proxies](#ri_web_proxies)|8035|8035|8035|100.0%|61.7%|
[firehol_level3](#firehol_level3)|108767|9626344|5733|0.0%|44.0%|
[stopforumspam_30d](#stopforumspam_30d)|94236|94236|5671|6.0%|43.5%|
[ri_connect_proxies](#ri_connect_proxies)|2902|2902|2902|100.0%|22.3%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|2350|8.0%|18.0%|
[xroxy](#xroxy)|2176|2176|2176|100.0%|16.7%|
[proxyrss](#proxyrss)|1402|1402|1402|100.0%|10.7%|
[proxz](#proxz)|1385|1385|1385|100.0%|10.6%|
[firehol_level2](#firehol_level2)|22948|34548|1158|3.3%|8.8%|
[stopforumspam_1d](#stopforumspam_1d)|6864|6864|790|11.5%|6.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|663|100.0%|5.0%|
[blocklist_de](#blocklist_de)|29129|29129|656|2.2%|5.0%|
[blocklist_de_bots](#blocklist_de_bots)|3035|3035|530|17.4%|4.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|529|0.0%|4.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|524|100.0%|4.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|390|0.0%|2.9%|
[snort_ipfilter](#snort_ipfilter)|8373|8373|329|3.9%|2.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|294|0.0%|2.2%|
[et_tor](#et_tor)|6500|6500|238|3.6%|1.8%|
[dm_tor](#dm_tor)|6559|6559|234|3.5%|1.7%|
[bm_tor](#bm_tor)|6533|6533|234|3.5%|1.7%|
[tor_exits](#tor_exits)|1106|1106|230|20.7%|1.7%|
[sorbs_spam](#sorbs_spam)|64701|65536|196|0.2%|1.5%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|196|0.3%|1.5%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|196|0.3%|1.5%|
[nixspam](#nixspam)|22540|22540|128|0.5%|0.9%|
[blocklist_de_mail](#blocklist_de_mail)|18292|18292|119|0.6%|0.9%|
[php_dictionary](#php_dictionary)|777|777|101|12.9%|0.7%|
[php_commenters](#php_commenters)|458|458|85|18.5%|0.6%|
[php_spammers](#php_spammers)|777|777|83|10.6%|0.6%|
[alienvault_reputation](#alienvault_reputation)|189217|189217|39|0.0%|0.2%|
[dragon_http](#dragon_http)|1021|268288|33|0.0%|0.2%|
[sorbs_web](#sorbs_web)|667|668|31|4.6%|0.2%|
[openbl_60d](#openbl_60d)|6959|6959|20|0.2%|0.1%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|17|0.0%|0.1%|
[php_harvesters](#php_harvesters)|408|408|12|2.9%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|11|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|168|168|9|5.3%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14109|14109|7|0.0%|0.0%|
[iw_spamlist](#iw_spamlist)|3266|3266|6|0.1%|0.0%|
[firehol_level1](#firehol_level1)|5068|688775049|5|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2714|2714|5|0.1%|0.0%|
[et_block](#et_block)|1000|18343756|4|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|3|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|3|0.2%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|0.0%|
[et_compromised](#et_compromised)|1704|1704|3|0.1%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1700|1700|3|0.1%|0.0%|
[voipbl](#voipbl)|10607|11019|2|0.0%|0.0%|
[shunlist](#shunlist)|1129|1129|2|0.1%|0.0%|
[sslbl](#sslbl)|368|368|1|0.2%|0.0%|
[dshield](#dshield)|20|5120|1|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|3535|3535|1|0.0%|0.0%|

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
[firehol_level1](#firehol_level1)|5068|688775049|670093640|97.2%|100.0%|
[bogons](#bogons)|13|592708608|592708608|100.0%|88.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|4236143|3.0%|0.6%|
[firehol_level3](#firehol_level3)|108767|9626344|566692|5.8%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|565760|6.1%|0.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|264873|0.0%|0.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|252671|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|151552|0.8%|0.0%|
[et_block](#et_block)|1000|18343756|151552|0.8%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|890|0.2%|0.0%|
[voipbl](#voipbl)|10607|11019|319|2.8%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|33|2.2%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|13|0.0%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|9|0.6%|0.0%|
[nt_malware_http](#nt_malware_http)|69|69|4|5.7%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|94236|94236|3|0.0%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|2|0.0%|0.0%|
[iw_spamlist](#iw_spamlist)|3266|3266|2|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6864|6864|1|0.0%|0.0%|
[php_harvesters](#php_harvesters)|408|408|1|0.2%|0.0%|
[php_commenters](#php_commenters)|458|458|1|0.2%|0.0%|
[firehol_level2](#firehol_level2)|22948|34548|1|0.0%|0.0%|
[ciarmy](#ciarmy)|428|428|1|0.2%|0.0%|

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
[firehol_level3](#firehol_level3)|108767|9626344|24|0.0%|0.0%|
[firehol_level1](#firehol_level1)|5068|688775049|18|0.0%|0.0%|
[sorbs_spam](#sorbs_spam)|64701|65536|17|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|17|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|17|0.0%|0.0%|
[firehol_proxies](#firehol_proxies)|12732|13012|17|0.1%|0.0%|
[firehol_anonymous](#firehol_anonymous)|19320|83371|17|0.0%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|94236|94236|16|0.0%|0.0%|
[firehol_level2](#firehol_level2)|22948|34548|15|0.0%|0.0%|
[alienvault_reputation](#alienvault_reputation)|189217|189217|15|0.0%|0.0%|
[blocklist_de](#blocklist_de)|29129|29129|14|0.0%|0.0%|
[fullbogons](#fullbogons)|3788|670093640|13|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|11|1.6%|0.0%|
[nixspam](#nixspam)|22540|22540|9|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|18292|18292|9|0.0%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|7|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|5|0.0%|0.0%|
[et_block](#et_block)|1000|18343756|5|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|8035|8035|4|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|3535|3535|4|0.1%|0.0%|
[xroxy](#xroxy)|2176|2176|3|0.1%|0.0%|
[php_dictionary](#php_dictionary)|777|777|3|0.3%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|3|0.0%|0.0%|
[voipbl](#voipbl)|10607|11019|2|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6864|6864|2|0.0%|0.0%|
[sorbs_web](#sorbs_web)|667|668|2|0.2%|0.0%|
[snort_ipfilter](#snort_ipfilter)|8373|8373|2|0.0%|0.0%|
[php_harvesters](#php_harvesters)|408|408|2|0.4%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2714|2714|2|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14109|14109|2|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2902|2902|1|0.0%|0.0%|
[proxz](#proxz)|1385|1385|1|0.0%|0.0%|
[proxyrss](#proxyrss)|1402|1402|1|0.0%|0.0%|
[php_spammers](#php_spammers)|777|777|1|0.1%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|1|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3204|3204|1|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|1509|1509|1|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3035|3035|1|0.0%|0.0%|

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
[firehol_level3](#firehol_level3)|108767|9626344|9177856|95.3%|100.0%|
[firehol_level1](#firehol_level1)|5068|688775049|7498240|1.0%|81.6%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|6932480|37.7%|75.5%|
[et_block](#et_block)|1000|18343756|6932480|37.7%|75.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|2526625|0.7%|27.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|904796|0.1%|9.8%|
[fullbogons](#fullbogons)|3788|670093640|565760|0.0%|6.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|145472|0.1%|1.5%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1036|0.3%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|94236|94236|724|0.7%|0.0%|
[alienvault_reputation](#alienvault_reputation)|189217|189217|278|0.1%|0.0%|
[dragon_http](#dragon_http)|1021|268288|256|0.0%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|154|0.5%|0.0%|
[firehol_level2](#firehol_level2)|22948|34548|80|0.2%|0.0%|
[blocklist_de](#blocklist_de)|29129|29129|54|0.1%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3035|3035|42|1.3%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6864|6864|38|0.5%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|27|2.0%|0.0%|
[nixspam](#nixspam)|22540|22540|19|0.0%|0.0%|
[openbl_60d](#openbl_60d)|6959|6959|16|0.2%|0.0%|
[openbl_30d](#openbl_30d)|2791|2791|12|0.4%|0.0%|
[snort_ipfilter](#snort_ipfilter)|8373|8373|11|0.1%|0.0%|
[zeus_badips](#zeus_badips)|202|202|10|4.9%|0.0%|
[zeus](#zeus)|230|230|10|4.3%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|7|0.4%|0.0%|
[firehol_anonymous](#firehol_anonymous)|19320|83371|7|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|18292|18292|6|0.0%|0.0%|
[et_compromised](#et_compromised)|1704|1704|5|0.2%|0.0%|
[dragon_sshpauth](#dragon_sshpauth)|1568|1632|5|0.3%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1700|1700|5|0.2%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3204|3204|5|0.1%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|3535|3535|5|0.1%|0.0%|
[php_dictionary](#php_dictionary)|777|777|4|0.5%|0.0%|
[openbl_7d](#openbl_7d)|638|638|4|0.6%|0.0%|
[et_tor](#et_tor)|6500|6500|4|0.0%|0.0%|
[dm_tor](#dm_tor)|6559|6559|4|0.0%|0.0%|
[bm_tor](#bm_tor)|6533|6533|4|0.0%|0.0%|
[php_spammers](#php_spammers)|777|777|3|0.3%|0.0%|
[openbl_1d](#openbl_1d)|155|155|3|1.9%|0.0%|
[nt_malware_http](#nt_malware_http)|69|69|3|4.3%|0.0%|
[firehol_proxies](#firehol_proxies)|12732|13012|3|0.0%|0.0%|
[tor_exits](#tor_exits)|1106|1106|2|0.1%|0.0%|
[shunlist](#shunlist)|1129|1129|2|0.1%|0.0%|
[iw_spamlist](#iw_spamlist)|3266|3266|2|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|2|0.3%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|168|168|2|1.1%|0.0%|
[voipbl](#voipbl)|10607|11019|1|0.0%|0.0%|
[virbl](#virbl)|15|15|1|6.6%|0.0%|
[sorbs_spam](#sorbs_spam)|64701|65536|1|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|1|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|1|0.0%|0.0%|
[php_harvesters](#php_harvesters)|408|408|1|0.2%|0.0%|
[php_commenters](#php_commenters)|458|458|1|0.2%|0.0%|
[nt_malware_irc](#nt_malware_irc)|43|43|1|2.3%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|1|0.1%|0.0%|
[et_botcc](#et_botcc)|505|505|1|0.1%|0.0%|
[dragon_vncprobe](#dragon_vncprobe)|85|85|1|1.1%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2714|2714|1|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14109|14109|1|0.0%|0.0%|

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
[firehol_level1](#firehol_level1)|5068|688775049|2570559|0.3%|0.3%|
[et_block](#et_block)|1000|18343756|2272787|12.3%|0.2%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|2272265|12.3%|0.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|1354507|0.9%|0.1%|
[firehol_level3](#firehol_level3)|108767|9626344|919962|9.5%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|904796|9.8%|0.1%|
[fullbogons](#fullbogons)|3788|670093640|264873|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|33155|6.8%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|13247|3.9%|0.0%|
[dragon_http](#dragon_http)|1021|268288|5989|2.2%|0.0%|
[alienvault_reputation](#alienvault_reputation)|189217|189217|4191|2.2%|0.0%|
[firehol_anonymous](#firehol_anonymous)|19320|83371|3448|4.1%|0.0%|
[firehol_level2](#firehol_level2)|22948|34548|1685|4.8%|0.0%|
[blocklist_de](#blocklist_de)|29129|29129|1582|5.4%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|94236|94236|1526|1.6%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|18292|18292|1407|7.6%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14109|14109|1323|9.3%|0.0%|
[sorbs_spam](#sorbs_spam)|64701|65536|1208|1.8%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|1205|1.8%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|1205|1.8%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|510|1.7%|0.0%|
[nixspam](#nixspam)|22540|22540|405|1.7%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|394|0.8%|0.0%|
[voipbl](#voipbl)|10607|11019|302|2.7%|0.0%|
[firehol_proxies](#firehol_proxies)|12732|13012|294|2.2%|0.0%|
[dshield](#dshield)|20|5120|256|5.0%|0.0%|
[dm_tor](#dm_tor)|6559|6559|170|2.5%|0.0%|
[bm_tor](#bm_tor)|6533|6533|170|2.6%|0.0%|
[et_tor](#et_tor)|6500|6500|168|2.5%|0.0%|
[openbl_60d](#openbl_60d)|6959|6959|163|2.3%|0.0%|
[ri_web_proxies](#ri_web_proxies)|8035|8035|156|1.9%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6864|6864|132|1.9%|0.0%|
[snort_ipfilter](#snort_ipfilter)|8373|8373|99|1.1%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|97|6.6%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2902|2902|87|2.9%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|3535|3535|75|2.1%|0.0%|
[openbl_30d](#openbl_30d)|2791|2791|66|2.3%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|66|5.1%|0.0%|
[iw_spamlist](#iw_spamlist)|3266|3266|59|1.8%|0.0%|
[xroxy](#xroxy)|2176|2176|58|2.6%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|56|8.4%|0.0%|
[et_compromised](#et_compromised)|1704|1704|54|3.1%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3035|3035|54|1.7%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1700|1700|53|3.1%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3204|3204|49|1.5%|0.0%|
[proxz](#proxz)|1385|1385|45|3.2%|0.0%|
[et_botcc](#et_botcc)|505|505|39|7.7%|0.0%|
[tor_exits](#tor_exits)|1106|1106|36|3.2%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2714|2714|35|1.2%|0.0%|
[proxyrss](#proxyrss)|1402|1402|34|2.4%|0.0%|
[dragon_sshpauth](#dragon_sshpauth)|1568|1632|32|1.9%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|511|511|28|5.4%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|1509|1509|26|1.7%|0.0%|
[shunlist](#shunlist)|1129|1129|25|2.2%|0.0%|
[ciarmy](#ciarmy)|428|428|23|5.3%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|21|4.0%|0.0%|
[sorbs_web](#sorbs_web)|667|668|16|2.3%|0.0%|
[openbl_7d](#openbl_7d)|638|638|16|2.5%|0.0%|
[php_harvesters](#php_harvesters)|408|408|12|2.9%|0.0%|
[php_dictionary](#php_dictionary)|777|777|12|1.5%|0.0%|
[php_spammers](#php_spammers)|777|777|11|1.4%|0.0%|
[php_commenters](#php_commenters)|458|458|10|2.1%|0.0%|
[zeus](#zeus)|230|230|7|3.0%|0.0%|
[nt_malware_http](#nt_malware_http)|69|69|7|10.1%|0.0%|
[malc0de](#malc0de)|238|238|7|2.9%|0.0%|
[nt_malware_irc](#nt_malware_irc)|43|43|5|11.6%|0.0%|
[dragon_vncprobe](#dragon_vncprobe)|85|85|5|5.8%|0.0%|
[bogons](#bogons)|13|592708608|5|0.0%|0.0%|
[zeus_badips](#zeus_badips)|202|202|4|1.9%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|80|80|4|5.0%|0.0%|
[sslbl](#sslbl)|368|368|3|0.8%|0.0%|
[openbl_1d](#openbl_1d)|155|155|3|1.9%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|168|168|2|1.1%|0.0%|

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
[firehol_level1](#firehol_level1)|5068|688775049|8867711|1.2%|2.5%|
[et_block](#et_block)|1000|18343756|8532776|46.5%|2.4%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|8532506|46.5%|2.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|2830203|2.0%|0.8%|
[firehol_level3](#firehol_level3)|108767|9626344|2537261|26.3%|0.7%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2526625|27.5%|0.7%|
[fullbogons](#fullbogons)|3788|670093640|252671|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|98904|20.2%|0.0%|
[dragon_http](#dragon_http)|1021|268288|11992|4.4%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|7728|2.2%|0.0%|
[alienvault_reputation](#alienvault_reputation)|189217|189217|7256|3.8%|0.0%|
[firehol_anonymous](#firehol_anonymous)|19320|83371|2896|3.4%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|94236|94236|2463|2.6%|0.0%|
[sorbs_spam](#sorbs_spam)|64701|65536|1740|2.6%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|1736|2.6%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|1736|2.6%|0.0%|
[firehol_level2](#firehol_level2)|22948|34548|1594|4.6%|0.0%|
[blocklist_de](#blocklist_de)|29129|29129|1452|4.9%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|18292|18292|1211|6.6%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14109|14109|1077|7.6%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|736|2.5%|0.0%|
[nixspam](#nixspam)|22540|22540|576|2.5%|0.0%|
[voipbl](#voipbl)|10607|11019|437|3.9%|0.0%|
[firehol_proxies](#firehol_proxies)|12732|13012|390|2.9%|0.0%|
[openbl_60d](#openbl_60d)|6959|6959|318|4.5%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|226|0.4%|0.0%|
[ri_web_proxies](#ri_web_proxies)|8035|8035|225|2.8%|0.0%|
[dm_tor](#dm_tor)|6559|6559|185|2.8%|0.0%|
[bm_tor](#bm_tor)|6533|6533|184|2.8%|0.0%|
[et_tor](#et_tor)|6500|6500|182|2.8%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6864|6864|178|2.5%|0.0%|
[openbl_30d](#openbl_30d)|2791|2791|147|5.2%|0.0%|
[snort_ipfilter](#snort_ipfilter)|8373|8373|128|1.5%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2902|2902|106|3.6%|0.0%|
[xroxy](#xroxy)|2176|2176|104|4.7%|0.0%|
[et_compromised](#et_compromised)|1704|1704|89|5.2%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1700|1700|86|5.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3204|3204|86|2.6%|0.0%|
[iw_spamlist](#iw_spamlist)|3266|3266|85|2.6%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3035|3035|75|2.4%|0.0%|
[dragon_sshpauth](#dragon_sshpauth)|1568|1632|72|4.4%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|3535|3535|71|2.0%|0.0%|
[shunlist](#shunlist)|1129|1129|66|5.8%|0.0%|
[php_spammers](#php_spammers)|777|777|60|7.7%|0.0%|
[proxz](#proxz)|1385|1385|57|4.1%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|45|3.1%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2714|2714|42|1.5%|0.0%|
[tor_exits](#tor_exits)|1106|1106|40|3.6%|0.0%|
[proxyrss](#proxyrss)|1402|1402|39|2.7%|0.0%|
[openbl_7d](#openbl_7d)|638|638|39|6.1%|0.0%|
[ciarmy](#ciarmy)|428|428|34|7.9%|0.0%|
[php_dictionary](#php_dictionary)|777|777|30|3.8%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|29|5.5%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|26|2.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|26|3.9%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|511|511|25|4.8%|0.0%|
[sorbs_web](#sorbs_web)|667|668|24|3.5%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|1509|1509|24|1.5%|0.0%|
[et_botcc](#et_botcc)|505|505|22|4.3%|0.0%|
[php_commenters](#php_commenters)|458|458|19|4.1%|0.0%|
[malc0de](#malc0de)|238|238|16|6.7%|0.0%|
[zeus](#zeus)|230|230|9|3.9%|0.0%|
[php_harvesters](#php_harvesters)|408|408|9|2.2%|0.0%|
[zeus_badips](#zeus_badips)|202|202|8|3.9%|0.0%|
[dragon_vncprobe](#dragon_vncprobe)|85|85|8|9.4%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|168|168|7|4.1%|0.0%|
[sslbl](#sslbl)|368|368|6|1.6%|0.0%|
[openbl_1d](#openbl_1d)|155|155|5|3.2%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|80|80|5|6.2%|0.0%|
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
[firehol_level1](#firehol_level1)|5068|688775049|4637594|0.6%|3.3%|
[fullbogons](#fullbogons)|3788|670093640|4236143|0.6%|3.0%|
[bogons](#bogons)|13|592708608|4194304|0.7%|3.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|2830203|0.8%|2.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|1354507|0.1%|0.9%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|270785|55.5%|0.1%|
[firehol_level3](#firehol_level3)|108767|9626344|161585|1.6%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|145472|1.5%|0.1%|
[et_block](#et_block)|1000|18343756|130650|0.7%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|130368|0.7%|0.0%|
[dragon_http](#dragon_http)|1021|268288|20480|7.6%|0.0%|
[alienvault_reputation](#alienvault_reputation)|189217|189217|14346|7.5%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|9226|2.7%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|94236|94236|5843|6.2%|0.0%|
[firehol_level2](#firehol_level2)|22948|34548|4398|12.7%|0.0%|
[blocklist_de](#blocklist_de)|29129|29129|3961|13.5%|0.0%|
[firehol_anonymous](#firehol_anonymous)|19320|83371|2881|3.4%|0.0%|
[sorbs_spam](#sorbs_spam)|64701|65536|2860|4.3%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|2851|4.3%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|2851|4.3%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|18292|18292|2771|15.1%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14109|14109|2311|16.3%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|1961|6.7%|0.0%|
[voipbl](#voipbl)|10607|11019|1616|14.6%|0.0%|
[nixspam](#nixspam)|22540|22540|1502|6.6%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|1172|2.4%|0.0%|
[openbl_60d](#openbl_60d)|6959|6959|738|10.6%|0.0%|
[et_tor](#et_tor)|6500|6500|636|9.7%|0.0%|
[dm_tor](#dm_tor)|6559|6559|632|9.6%|0.0%|
[bm_tor](#bm_tor)|6533|6533|629|9.6%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3204|3204|626|19.5%|0.0%|
[firehol_proxies](#firehol_proxies)|12732|13012|529|4.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6864|6864|518|7.5%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|3535|3535|431|12.1%|0.0%|
[openbl_30d](#openbl_30d)|2791|2791|287|10.2%|0.0%|
[dshield](#dshield)|20|5120|256|5.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|8373|8373|234|2.7%|0.0%|
[iw_spamlist](#iw_spamlist)|3266|3266|232|7.1%|0.0%|
[ri_web_proxies](#ri_web_proxies)|8035|8035|221|2.7%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2714|2714|215|7.9%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3035|3035|188|6.1%|0.0%|
[et_compromised](#et_compromised)|1704|1704|157|9.2%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1700|1700|157|9.2%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|150|28.6%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|147|11.4%|0.0%|
[tor_exits](#tor_exits)|1106|1106|126|11.3%|0.0%|
[dragon_sshpauth](#dragon_sshpauth)|1568|1632|126|7.7%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|1509|1509|118|7.8%|0.0%|
[shunlist](#shunlist)|1129|1129|113|10.0%|0.0%|
[xroxy](#xroxy)|2176|2176|112|5.1%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|108|7.4%|0.0%|
[proxz](#proxz)|1385|1385|106|7.6%|0.0%|
[et_botcc](#et_botcc)|505|505|76|15.0%|0.0%|
[ciarmy](#ciarmy)|428|428|70|16.3%|0.0%|
[openbl_7d](#openbl_7d)|638|638|63|9.8%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2902|2902|58|1.9%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|511|511|58|11.3%|0.0%|
[proxyrss](#proxyrss)|1402|1402|56|3.9%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|51|7.6%|0.0%|
[php_spammers](#php_spammers)|777|777|44|5.6%|0.0%|
[php_dictionary](#php_dictionary)|777|777|39|5.0%|0.0%|
[sorbs_web](#sorbs_web)|667|668|37|5.5%|0.0%|
[malc0de](#malc0de)|238|238|35|14.7%|0.0%|
[php_commenters](#php_commenters)|458|458|29|6.3%|0.0%|
[sslbl](#sslbl)|368|368|28|7.6%|0.0%|
[php_harvesters](#php_harvesters)|408|408|20|4.9%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|80|80|18|22.5%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|168|168|17|10.1%|0.0%|
[zeus](#zeus)|230|230|14|6.0%|0.0%|
[dragon_vncprobe](#dragon_vncprobe)|85|85|13|15.2%|0.0%|
[openbl_1d](#openbl_1d)|155|155|12|7.7%|0.0%|
[zeus_badips](#zeus_badips)|202|202|10|4.9%|0.0%|
[nt_malware_http](#nt_malware_http)|69|69|5|7.2%|0.0%|
[sorbs_socks](#sorbs_socks)|7|7|2|28.5%|0.0%|
[sorbs_misc](#sorbs_misc)|7|7|2|28.5%|0.0%|
[sorbs_http](#sorbs_http)|7|7|2|28.5%|0.0%|
[virbl](#virbl)|15|15|1|6.6%|0.0%|
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
[firehol_proxies](#firehol_proxies)|12732|13012|663|5.0%|100.0%|
[firehol_anonymous](#firehol_anonymous)|19320|83371|663|0.7%|100.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|56|0.0%|8.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|51|0.0%|7.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|26|0.0%|3.9%|
[firehol_level3](#firehol_level3)|108767|9626344|25|0.0%|3.7%|
[stopforumspam_30d](#stopforumspam_30d)|94236|94236|20|0.0%|3.0%|
[ri_web_proxies](#ri_web_proxies)|8035|8035|15|0.1%|2.2%|
[xroxy](#xroxy)|2176|2176|13|0.5%|1.9%|
[proxyrss](#proxyrss)|1402|1402|12|0.8%|1.8%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|11|0.0%|1.6%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|10|0.0%|1.5%|
[ri_connect_proxies](#ri_connect_proxies)|2902|2902|7|0.2%|1.0%|
[proxz](#proxz)|1385|1385|7|0.5%|1.0%|
[firehol_level2](#firehol_level2)|22948|34548|7|0.0%|1.0%|
[blocklist_de](#blocklist_de)|29129|29129|5|0.0%|0.7%|
[stopforumspam_1d](#stopforumspam_1d)|6864|6864|4|0.0%|0.6%|
[blocklist_de_bots](#blocklist_de_bots)|3035|3035|3|0.0%|0.4%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|2|0.0%|0.3%|
[php_dictionary](#php_dictionary)|777|777|2|0.2%|0.3%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|2|0.1%|0.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2|0.0%|0.3%|
[firehol_level1](#firehol_level1)|5068|688775049|2|0.0%|0.3%|
[et_block](#et_block)|1000|18343756|2|0.0%|0.3%|
[blocklist_de_mail](#blocklist_de_mail)|18292|18292|2|0.0%|0.3%|
[alienvault_reputation](#alienvault_reputation)|189217|189217|2|0.0%|0.3%|
[sorbs_spam](#sorbs_spam)|64701|65536|1|0.0%|0.1%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|1|0.0%|0.1%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|1|0.0%|0.1%|
[snort_ipfilter](#snort_ipfilter)|8373|8373|1|0.0%|0.1%|
[php_spammers](#php_spammers)|777|777|1|0.1%|0.1%|
[nixspam](#nixspam)|22540|22540|1|0.0%|0.1%|
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
[firehol_level3](#firehol_level3)|108767|9626344|339173|3.5%|100.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|13247|0.0%|3.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|9226|0.0%|2.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|7728|0.0%|2.2%|
[firehol_level1](#firehol_level1)|5068|688775049|1930|0.0%|0.5%|
[et_block](#et_block)|1000|18343756|1041|0.0%|0.3%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|1037|0.0%|0.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1036|0.0%|0.3%|
[fullbogons](#fullbogons)|3788|670093640|890|0.0%|0.2%|
[alienvault_reputation](#alienvault_reputation)|189217|189217|293|0.1%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|94236|94236|52|0.0%|0.0%|
[sorbs_spam](#sorbs_spam)|64701|65536|38|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|37|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|37|0.0%|0.0%|
[firehol_anonymous](#firehol_anonymous)|19320|83371|29|0.0%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|27|2.0%|0.0%|
[et_tor](#et_tor)|6500|6500|22|0.3%|0.0%|
[dm_tor](#dm_tor)|6559|6559|22|0.3%|0.0%|
[bm_tor](#bm_tor)|6533|6533|22|0.3%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|21|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|19|1.3%|0.0%|
[snort_ipfilter](#snort_ipfilter)|8373|8373|15|0.1%|0.0%|
[firehol_level2](#firehol_level2)|22948|34548|12|0.0%|0.0%|
[firehol_proxies](#firehol_proxies)|12732|13012|11|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6864|6864|9|0.1%|0.0%|
[tor_exits](#tor_exits)|1106|1106|8|0.7%|0.0%|
[nixspam](#nixspam)|22540|22540|8|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|8035|8035|6|0.0%|0.0%|
[dragon_http](#dragon_http)|1021|268288|6|0.0%|0.0%|
[openbl_60d](#openbl_60d)|6959|6959|5|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|5|0.9%|0.0%|
[voipbl](#voipbl)|10607|11019|4|0.0%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|511|511|4|0.7%|0.0%|
[openbl_30d](#openbl_30d)|2791|2791|3|0.1%|0.0%|
[iw_spamlist](#iw_spamlist)|3266|3266|3|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|3|0.0%|0.0%|
[blocklist_de](#blocklist_de)|29129|29129|3|0.0%|0.0%|
[malc0de](#malc0de)|238|238|2|0.8%|0.0%|
[et_compromised](#et_compromised)|1704|1704|2|0.1%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1700|1700|2|0.1%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|80|80|2|2.5%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|18292|18292|2|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14109|14109|2|0.0%|0.0%|
[zeus_badips](#zeus_badips)|202|202|1|0.4%|0.0%|
[zeus](#zeus)|230|230|1|0.4%|0.0%|
[xroxy](#xroxy)|2176|2176|1|0.0%|0.0%|
[sslbl](#sslbl)|368|368|1|0.2%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|1|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2902|2902|1|0.0%|0.0%|
[proxz](#proxz)|1385|1385|1|0.0%|0.0%|
[proxyrss](#proxyrss)|1402|1402|1|0.0%|0.0%|
[php_harvesters](#php_harvesters)|408|408|1|0.2%|0.0%|
[php_dictionary](#php_dictionary)|777|777|1|0.1%|0.0%|
[php_commenters](#php_commenters)|458|458|1|0.2%|0.0%|
[nt_malware_http](#nt_malware_http)|69|69|1|1.4%|0.0%|
[bogons](#bogons)|13|592708608|1|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2714|2714|1|0.0%|0.0%|

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
[firehol_level3](#firehol_level3)|108767|9626344|1450|0.0%|100.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|108|0.0%|7.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|97|0.0%|6.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|45|0.0%|3.1%|
[firehol_level1](#firehol_level1)|5068|688775049|39|0.0%|2.6%|
[fullbogons](#fullbogons)|3788|670093640|33|0.0%|2.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|19|0.0%|1.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|7|0.0%|0.4%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|6|0.0%|0.4%|
[et_block](#et_block)|1000|18343756|6|0.0%|0.4%|
[alienvault_reputation](#alienvault_reputation)|189217|189217|6|0.0%|0.4%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|3|0.2%|0.2%|
[firehol_proxies](#firehol_proxies)|12732|13012|3|0.0%|0.2%|
[firehol_anonymous](#firehol_anonymous)|19320|83371|3|0.0%|0.2%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|2|0.0%|0.1%|
[stopforumspam_30d](#stopforumspam_30d)|94236|94236|2|0.0%|0.1%|
[sorbs_spam](#sorbs_spam)|64701|65536|2|0.0%|0.1%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|2|0.0%|0.1%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|2|0.0%|0.1%|
[openbl_60d](#openbl_60d)|6959|6959|2|0.0%|0.1%|
[openbl_30d](#openbl_30d)|2791|2791|2|0.0%|0.1%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|2|0.3%|0.1%|
[firehol_level2](#firehol_level2)|22948|34548|2|0.0%|0.1%|
[dragon_http](#dragon_http)|1021|268288|2|0.0%|0.1%|
[blocklist_de_strongips](#blocklist_de_strongips)|168|168|2|1.1%|0.1%|
[blocklist_de_bots](#blocklist_de_bots)|3035|3035|2|0.0%|0.1%|
[blocklist_de](#blocklist_de)|29129|29129|2|0.0%|0.1%|
[stopforumspam_1d](#stopforumspam_1d)|6864|6864|1|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|8373|8373|1|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|8035|8035|1|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|1|0.0%|0.0%|
[et_botcc](#et_botcc)|505|505|1|0.1%|0.0%|
[dragon_sshpauth](#dragon_sshpauth)|1568|1632|1|0.0%|0.0%|

## iw_spamlist

[ImproWare Antispam](http://antispam.imp.ch/) IPs sending spam, in the last 3 days

Source is downloaded from [this link](http://antispam.imp.ch/spamlist).

The last time downloaded was found to be dated: Fri Jun 12 15:20:04 UTC 2015.

The ipset `iw_spamlist` has **3266** entries, **3266** unique IPs.

The following table shows the overlaps of `iw_spamlist` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `iw_spamlist`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `iw_spamlist`.
- ` this % ` is the percentage **of this ipset (`iw_spamlist`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[nixspam](#nixspam)|22540|22540|745|3.3%|22.8%|
[sorbs_spam](#sorbs_spam)|64701|65536|635|0.9%|19.4%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|630|0.9%|19.2%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|630|0.9%|19.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|232|0.0%|7.1%|
[firehol_level2](#firehol_level2)|22948|34548|137|0.3%|4.1%|
[blocklist_de](#blocklist_de)|29129|29129|136|0.4%|4.1%|
[blocklist_de_mail](#blocklist_de_mail)|18292|18292|126|0.6%|3.8%|
[firehol_level3](#firehol_level3)|108767|9626344|86|0.0%|2.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|85|0.0%|2.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|59|0.0%|1.8%|
[snort_ipfilter](#snort_ipfilter)|8373|8373|55|0.6%|1.6%|
[sorbs_web](#sorbs_web)|667|668|28|4.1%|0.8%|
[alienvault_reputation](#alienvault_reputation)|189217|189217|25|0.0%|0.7%|
[stopforumspam_30d](#stopforumspam_30d)|94236|94236|22|0.0%|0.6%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|13|0.0%|0.3%|
[php_spammers](#php_spammers)|777|777|8|1.0%|0.2%|
[php_dictionary](#php_dictionary)|777|777|8|1.0%|0.2%|
[firehol_level1](#firehol_level1)|5068|688775049|7|0.0%|0.2%|
[firehol_proxies](#firehol_proxies)|12732|13012|6|0.0%|0.1%|
[firehol_anonymous](#firehol_anonymous)|19320|83371|6|0.0%|0.1%|
[blocklist_de_imap](#blocklist_de_imap)|3535|3535|6|0.1%|0.1%|
[stopforumspam_1d](#stopforumspam_1d)|6864|6864|4|0.0%|0.1%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|4|0.0%|0.1%|
[ri_web_proxies](#ri_web_proxies)|8035|8035|4|0.0%|0.1%|
[php_commenters](#php_commenters)|458|458|4|0.8%|0.1%|
[et_block](#et_block)|1000|18343756|4|0.0%|0.1%|
[blocklist_de_bots](#blocklist_de_bots)|3035|3035|4|0.1%|0.1%|
[php_harvesters](#php_harvesters)|408|408|3|0.7%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|3|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|1509|1509|3|0.1%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2714|2714|3|0.1%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14109|14109|3|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2902|2902|2|0.0%|0.0%|
[proxz](#proxz)|1385|1385|2|0.1%|0.0%|
[proxyrss](#proxyrss)|1402|1402|2|0.1%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2|0.0%|0.0%|
[fullbogons](#fullbogons)|3788|670093640|2|0.0%|0.0%|
[dragon_http](#dragon_http)|1021|268288|2|0.0%|0.0%|
[bogons](#bogons)|13|592708608|2|0.0%|0.0%|
[xroxy](#xroxy)|2176|2176|1|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|1|0.0%|0.0%|
[sorbs_socks](#sorbs_socks)|7|7|1|14.2%|0.0%|
[sorbs_misc](#sorbs_misc)|7|7|1|14.2%|0.0%|
[sorbs_http](#sorbs_http)|7|7|1|14.2%|0.0%|

## iw_wormlist

[ImproWare Antispam](http://antispam.imp.ch/) IPs sending emails with viruses or worms, in the last 3 days

Source is downloaded from [this link](http://antispam.imp.ch/wormlist).

The last time downloaded was found to be dated: Fri Jun 12 15:20:04 UTC 2015.

The ipset `iw_wormlist` has **4** entries, **4** unique IPs.

The following table shows the overlaps of `iw_wormlist` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `iw_wormlist`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `iw_wormlist`.
- ` this % ` is the percentage **of this ipset (`iw_wormlist`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level3](#firehol_level3)|108767|9626344|4|0.0%|100.0%|

## malc0de

[Malc0de.com](http://malc0de.com) malicious IPs of the last 30 days

Source is downloaded from [this link](http://malc0de.com/bl/IP_Blacklist.txt).

The last time downloaded was found to be dated: Fri Jun 12 13:17:02 UTC 2015.

The ipset `malc0de` has **238** entries, **238** unique IPs.

The following table shows the overlaps of `malc0de` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `malc0de`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `malc0de`.
- ` this % ` is the percentage **of this ipset (`malc0de`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level3](#firehol_level3)|108767|9626344|238|0.0%|100.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|35|0.0%|14.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|16|0.0%|6.7%|
[alienvault_reputation](#alienvault_reputation)|189217|189217|9|0.0%|3.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|7|0.0%|2.9%|
[cleanmx_viruses](#cleanmx_viruses)|511|511|7|1.3%|2.9%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|4|0.3%|1.6%|
[dragon_http](#dragon_http)|1021|268288|3|0.0%|1.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|2|0.0%|0.8%|
[firehol_level1](#firehol_level1)|5068|688775049|2|0.0%|0.8%|
[et_block](#et_block)|1000|18343756|2|0.0%|0.8%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|1|0.0%|0.4%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|1|0.0%|0.4%|
[sorbs_spam](#sorbs_spam)|64701|65536|1|0.0%|0.4%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|1|0.0%|0.4%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|1|0.0%|0.4%|

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
[firehol_level3](#firehol_level3)|108767|9626344|1288|0.0%|100.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|147|0.0%|11.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|66|0.0%|5.1%|
[firehol_level1](#firehol_level1)|5068|688775049|39|0.0%|3.0%|
[et_block](#et_block)|1000|18343756|30|0.0%|2.3%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|29|0.0%|2.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|27|0.0%|2.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|27|0.0%|2.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|26|0.0%|2.0%|
[snort_ipfilter](#snort_ipfilter)|8373|8373|12|0.1%|0.9%|
[fullbogons](#fullbogons)|3788|670093640|9|0.0%|0.6%|
[alienvault_reputation](#alienvault_reputation)|189217|189217|8|0.0%|0.6%|
[malc0de](#malc0de)|238|238|4|1.6%|0.3%|
[cleanmx_viruses](#cleanmx_viruses)|511|511|4|0.7%|0.3%|
[stopforumspam_30d](#stopforumspam_30d)|94236|94236|3|0.0%|0.2%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|3|0.2%|0.2%|
[dragon_http](#dragon_http)|1021|268288|2|0.0%|0.1%|
[zeus](#zeus)|230|230|1|0.4%|0.0%|
[nixspam](#nixspam)|22540|22540|1|0.0%|0.0%|
[et_botcc](#et_botcc)|505|505|1|0.1%|0.0%|

## maxmind_proxy_fraud

[MaxMind.com](https://www.maxmind.com/en/anonymous-proxy-fraudulent-ip-address-list) list of anonymous proxy fraudelent IP addresses.

Source is downloaded from [this link](https://www.maxmind.com/en/anonymous-proxy-fraudulent-ip-address-list).

The last time downloaded was found to be dated: Fri Jun 12 16:09:27 UTC 2015.

The ipset `maxmind_proxy_fraud` has **524** entries, **524** unique IPs.

The following table shows the overlaps of `maxmind_proxy_fraud` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `maxmind_proxy_fraud`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `maxmind_proxy_fraud`.
- ` this % ` is the percentage **of this ipset (`maxmind_proxy_fraud`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_proxies](#firehol_proxies)|12732|13012|524|4.0%|100.0%|
[firehol_anonymous](#firehol_anonymous)|19320|83371|524|0.6%|100.0%|
[firehol_level3](#firehol_level3)|108767|9626344|347|0.0%|66.2%|
[stopforumspam_30d](#stopforumspam_30d)|94236|94236|346|0.3%|66.0%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|277|0.9%|52.8%|
[snort_ipfilter](#snort_ipfilter)|8373|8373|237|2.8%|45.2%|
[et_tor](#et_tor)|6500|6500|233|3.5%|44.4%|
[tor_exits](#tor_exits)|1106|1106|230|20.7%|43.8%|
[dm_tor](#dm_tor)|6559|6559|229|3.4%|43.7%|
[bm_tor](#bm_tor)|6533|6533|229|3.5%|43.7%|
[firehol_level2](#firehol_level2)|22948|34548|208|0.6%|39.6%|
[stopforumspam_1d](#stopforumspam_1d)|6864|6864|206|3.0%|39.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|150|0.0%|28.6%|
[php_commenters](#php_commenters)|458|458|53|11.5%|10.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|29|0.0%|5.5%|
[alienvault_reputation](#alienvault_reputation)|189217|189217|29|0.0%|5.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|21|0.0%|4.0%|
[openbl_60d](#openbl_60d)|6959|6959|20|0.2%|3.8%|
[ri_web_proxies](#ri_web_proxies)|8035|8035|10|0.1%|1.9%|
[php_harvesters](#php_harvesters)|408|408|7|1.7%|1.3%|
[php_spammers](#php_spammers)|777|777|6|0.7%|1.1%|
[php_dictionary](#php_dictionary)|777|777|5|0.6%|0.9%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|5|0.0%|0.9%|
[blocklist_de](#blocklist_de)|29129|29129|5|0.0%|0.9%|
[dragon_http](#dragon_http)|1021|268288|4|0.0%|0.7%|
[blocklist_de_bots](#blocklist_de_bots)|3035|3035|4|0.1%|0.7%|
[xroxy](#xroxy)|2176|2176|3|0.1%|0.5%|
[voipbl](#voipbl)|10607|11019|2|0.0%|0.3%|
[shunlist](#shunlist)|1129|1129|2|0.1%|0.3%|
[proxz](#proxz)|1385|1385|2|0.1%|0.3%|
[nixspam](#nixspam)|22540|22540|2|0.0%|0.3%|
[firehol_level1](#firehol_level1)|5068|688775049|2|0.0%|0.3%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|1|0.0%|0.1%|
[sorbs_spam](#sorbs_spam)|64701|65536|1|0.0%|0.1%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|1|0.0%|0.1%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|1|0.0%|0.1%|
[ri_connect_proxies](#ri_connect_proxies)|2902|2902|1|0.0%|0.1%|
[proxyrss](#proxyrss)|1402|1402|1|0.0%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.1%|
[et_block](#et_block)|1000|18343756|1|0.0%|0.1%|
[dshield](#dshield)|20|5120|1|0.0%|0.1%|
[blocklist_de_mail](#blocklist_de_mail)|18292|18292|1|0.0%|0.1%|
[blocklist_de_apache](#blocklist_de_apache)|14109|14109|1|0.0%|0.1%|

## nixspam

[NiX Spam](http://www.heise.de/ix/NiX-Spam-DNSBL-and-blacklist-for-download-499637.html) IP addresses that sent spam in the last hour - automatically generated entries without distinguishing open proxies from relays, dialup gateways, and so on. All IPs are removed after 12 hours if there is no spam from there.

Source is downloaded from [this link](http://www.dnsbl.manitu.net/download/nixspam-ip.dump.gz).

The last time downloaded was found to be dated: Fri Jun 12 16:00:02 UTC 2015.

The ipset `nixspam` has **22540** entries, **22540** unique IPs.

The following table shows the overlaps of `nixspam` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `nixspam`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `nixspam`.
- ` this % ` is the percentage **of this ipset (`nixspam`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[sorbs_spam](#sorbs_spam)|64701|65536|2280|3.4%|10.1%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|2260|3.4%|10.0%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|2260|3.4%|10.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|1502|0.0%|6.6%|
[firehol_level2](#firehol_level2)|22948|34548|776|2.2%|3.4%|
[blocklist_de](#blocklist_de)|29129|29129|760|2.6%|3.3%|
[iw_spamlist](#iw_spamlist)|3266|3266|745|22.8%|3.3%|
[blocklist_de_mail](#blocklist_de_mail)|18292|18292|681|3.7%|3.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|576|0.0%|2.5%|
[firehol_level3](#firehol_level3)|108767|9626344|496|0.0%|2.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|405|0.0%|1.7%|
[snort_ipfilter](#snort_ipfilter)|8373|8373|269|3.2%|1.1%|
[stopforumspam_30d](#stopforumspam_30d)|94236|94236|231|0.2%|1.0%|
[firehol_anonymous](#firehol_anonymous)|19320|83371|135|0.1%|0.5%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|128|0.4%|0.5%|
[firehol_proxies](#firehol_proxies)|12732|13012|128|0.9%|0.5%|
[php_dictionary](#php_dictionary)|777|777|125|16.0%|0.5%|
[sorbs_web](#sorbs_web)|667|668|114|17.0%|0.5%|
[php_spammers](#php_spammers)|777|777|109|14.0%|0.4%|
[ri_web_proxies](#ri_web_proxies)|8035|8035|90|1.1%|0.3%|
[blocklist_de_imap](#blocklist_de_imap)|3535|3535|62|1.7%|0.2%|
[xroxy](#xroxy)|2176|2176|58|2.6%|0.2%|
[stopforumspam_1d](#stopforumspam_1d)|6864|6864|53|0.7%|0.2%|
[alienvault_reputation](#alienvault_reputation)|189217|189217|53|0.0%|0.2%|
[proxz](#proxz)|1385|1385|46|3.3%|0.2%|
[blocklist_de_bots](#blocklist_de_bots)|3035|3035|39|1.2%|0.1%|
[dragon_http](#dragon_http)|1021|268288|33|0.0%|0.1%|
[firehol_level1](#firehol_level1)|5068|688775049|22|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14109|14109|22|0.1%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2714|2714|21|0.7%|0.0%|
[et_block](#et_block)|1000|18343756|20|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|19|0.0%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|19|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2902|2902|18|0.6%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|1509|1509|15|0.9%|0.0%|
[php_commenters](#php_commenters)|458|458|11|2.4%|0.0%|
[proxyrss](#proxyrss)|1402|1402|10|0.7%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|9|0.0%|0.0%|
[tor_exits](#tor_exits)|1106|1106|8|0.7%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|8|0.0%|0.0%|
[php_harvesters](#php_harvesters)|408|408|7|1.7%|0.0%|
[dm_tor](#dm_tor)|6559|6559|7|0.1%|0.0%|
[bm_tor](#bm_tor)|6533|6533|7|0.1%|0.0%|
[openbl_60d](#openbl_60d)|6959|6959|5|0.0%|0.0%|
[et_tor](#et_tor)|6500|6500|5|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3204|3204|3|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|2|0.0%|0.0%|
[openbl_30d](#openbl_30d)|2791|2791|2|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|2|0.3%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|168|168|2|1.1%|0.0%|
[zeus_badips](#zeus_badips)|202|202|1|0.4%|0.0%|
[zeus](#zeus)|230|230|1|0.4%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|1|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|1|0.1%|0.0%|

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
[firehol_level1](#firehol_level1)|5068|688775049|8|0.0%|11.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|7|0.0%|10.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|5|0.0%|7.2%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|4|0.0%|5.7%|
[fullbogons](#fullbogons)|3788|670093640|4|0.0%|5.7%|
[et_block](#et_block)|1000|18343756|4|0.0%|5.7%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|4.3%|
[firehol_level3](#firehol_level3)|108767|9626344|3|0.0%|4.3%|
[stopforumspam_30d](#stopforumspam_30d)|94236|94236|2|0.0%|2.8%|
[nt_malware_irc](#nt_malware_irc)|43|43|2|4.6%|2.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|2|0.0%|2.8%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|1.4%|
[alienvault_reputation](#alienvault_reputation)|189217|189217|1|0.0%|1.4%|

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
[firehol_level1](#firehol_level1)|5068|688775049|3|0.0%|6.9%|
[et_block](#et_block)|1000|18343756|3|0.0%|6.9%|
[nt_malware_http](#nt_malware_http)|69|69|2|2.8%|4.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|2|0.0%|4.6%|
[alienvault_reputation](#alienvault_reputation)|189217|189217|2|0.0%|4.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|1|0.0%|2.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|2.3%|
[firehol_level3](#firehol_level3)|108767|9626344|1|0.0%|2.3%|

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

The last time downloaded was found to be dated: Fri Jun 12 15:32:00 UTC 2015.

The ipset `openbl_1d` has **155** entries, **155** unique IPs.

The following table shows the overlaps of `openbl_1d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl_1d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl_1d`.
- ` this % ` is the percentage **of this ipset (`openbl_1d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[openbl_7d](#openbl_7d)|638|638|155|24.2%|100.0%|
[openbl_60d](#openbl_60d)|6959|6959|155|2.2%|100.0%|
[openbl_30d](#openbl_30d)|2791|2791|155|5.5%|100.0%|
[firehol_level3](#firehol_level3)|108767|9626344|155|0.0%|100.0%|
[firehol_level2](#firehol_level2)|22948|34548|155|0.4%|100.0%|
[alienvault_reputation](#alienvault_reputation)|189217|189217|152|0.0%|98.0%|
[blocklist_de](#blocklist_de)|29129|29129|125|0.4%|80.6%|
[blocklist_de_ssh](#blocklist_de_ssh)|3204|3204|124|3.8%|80.0%|
[dragon_sshpauth](#dragon_sshpauth)|1568|1632|94|5.7%|60.6%|
[bruteforceblocker](#bruteforceblocker)|1700|1700|67|3.9%|43.2%|
[shunlist](#shunlist)|1129|1129|66|5.8%|42.5%|
[et_compromised](#et_compromised)|1704|1704|62|3.6%|40.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|168|168|19|11.3%|12.2%|
[firehol_level1](#firehol_level1)|5068|688775049|13|0.0%|8.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|12|0.0%|7.7%|
[et_block](#et_block)|1000|18343756|10|0.0%|6.4%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|9|0.0%|5.8%|
[dragon_http](#dragon_http)|1021|268288|9|0.0%|5.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|5|0.0%|3.2%|
[dshield](#dshield)|20|5120|5|0.0%|3.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|3|0.0%|1.9%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|1.9%|
[stopforumspam_30d](#stopforumspam_30d)|94236|94236|1|0.0%|0.6%|
[php_spammers](#php_spammers)|777|777|1|0.1%|0.6%|
[php_commenters](#php_commenters)|458|458|1|0.2%|0.6%|
[blocklist_de_mail](#blocklist_de_mail)|18292|18292|1|0.0%|0.6%|
[blocklist_de_imap](#blocklist_de_imap)|3535|3535|1|0.0%|0.6%|

## openbl_30d

[OpenBL.org](http://www.openbl.org/) last 30 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.

Source is downloaded from [this link](http://www.openbl.org/lists/base_30days.txt).

The last time downloaded was found to be dated: Fri Jun 12 16:07:00 UTC 2015.

The ipset `openbl_30d` has **2791** entries, **2791** unique IPs.

The following table shows the overlaps of `openbl_30d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl_30d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl_30d`.
- ` this % ` is the percentage **of this ipset (`openbl_30d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[openbl_60d](#openbl_60d)|6959|6959|2791|40.1%|100.0%|
[firehol_level3](#firehol_level3)|108767|9626344|2791|0.0%|100.0%|
[alienvault_reputation](#alienvault_reputation)|189217|189217|2774|1.4%|99.3%|
[et_compromised](#et_compromised)|1704|1704|908|53.2%|32.5%|
[bruteforceblocker](#bruteforceblocker)|1700|1700|904|53.1%|32.3%|
[dragon_sshpauth](#dragon_sshpauth)|1568|1632|693|42.4%|24.8%|
[firehol_level2](#firehol_level2)|22948|34548|664|1.9%|23.7%|
[openbl_7d](#openbl_7d)|638|638|638|100.0%|22.8%|
[blocklist_de](#blocklist_de)|29129|29129|633|2.1%|22.6%|
[blocklist_de_ssh](#blocklist_de_ssh)|3204|3204|616|19.2%|22.0%|
[shunlist](#shunlist)|1129|1129|402|35.6%|14.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|287|0.0%|10.2%|
[openbl_1d](#openbl_1d)|155|155|155|100.0%|5.5%|
[dragon_http](#dragon_http)|1021|268288|148|0.0%|5.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|147|0.0%|5.2%|
[firehol_level1](#firehol_level1)|5068|688775049|135|0.0%|4.8%|
[et_block](#et_block)|1000|18343756|125|0.0%|4.4%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|119|0.0%|4.2%|
[dshield](#dshield)|20|5120|80|1.5%|2.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|66|0.0%|2.3%|
[blocklist_de_strongips](#blocklist_de_strongips)|168|168|22|13.0%|0.7%|
[blocklist_de_mail](#blocklist_de_mail)|18292|18292|14|0.0%|0.5%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|12|0.0%|0.4%|
[blocklist_de_imap](#blocklist_de_imap)|3535|3535|11|0.3%|0.3%|
[stopforumspam_30d](#stopforumspam_30d)|94236|94236|5|0.0%|0.1%|
[voipbl](#voipbl)|10607|11019|3|0.0%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|3|0.0%|0.1%|
[blocklist_de_apache](#blocklist_de_apache)|14109|14109|3|0.0%|0.1%|
[zeus](#zeus)|230|230|2|0.8%|0.0%|
[snort_ipfilter](#snort_ipfilter)|8373|8373|2|0.0%|0.0%|
[nixspam](#nixspam)|22540|22540|2|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|2|0.1%|0.0%|
[ciarmy](#ciarmy)|428|428|2|0.4%|0.0%|
[zeus_badips](#zeus_badips)|202|202|1|0.4%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|1|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6864|6864|1|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|1|0.0%|0.0%|
[php_spammers](#php_spammers)|777|777|1|0.1%|0.0%|
[php_commenters](#php_commenters)|458|458|1|0.2%|0.0%|
[firehol_anonymous](#firehol_anonymous)|19320|83371|1|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|1509|1509|1|0.0%|0.0%|

## openbl_60d

[OpenBL.org](http://www.openbl.org/) last 60 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.

Source is downloaded from [this link](http://www.openbl.org/lists/base_60days.txt).

The last time downloaded was found to be dated: Fri Jun 12 16:07:00 UTC 2015.

The ipset `openbl_60d` has **6959** entries, **6959** unique IPs.

The following table shows the overlaps of `openbl_60d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl_60d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl_60d`.
- ` this % ` is the percentage **of this ipset (`openbl_60d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[alienvault_reputation](#alienvault_reputation)|189217|189217|6937|3.6%|99.6%|
[firehol_level3](#firehol_level3)|108767|9626344|2915|0.0%|41.8%|
[openbl_30d](#openbl_30d)|2791|2791|2791|100.0%|40.1%|
[et_compromised](#et_compromised)|1704|1704|977|57.3%|14.0%|
[bruteforceblocker](#bruteforceblocker)|1700|1700|964|56.7%|13.8%|
[firehol_level2](#firehol_level2)|22948|34548|839|2.4%|12.0%|
[blocklist_de](#blocklist_de)|29129|29129|789|2.7%|11.3%|
[dragon_sshpauth](#dragon_sshpauth)|1568|1632|775|47.4%|11.1%|
[blocklist_de_ssh](#blocklist_de_ssh)|3204|3204|763|23.8%|10.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|738|0.0%|10.6%|
[openbl_7d](#openbl_7d)|638|638|638|100.0%|9.1%|
[shunlist](#shunlist)|1129|1129|424|37.5%|6.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|318|0.0%|4.5%|
[firehol_level1](#firehol_level1)|5068|688775049|253|0.0%|3.6%|
[et_block](#et_block)|1000|18343756|244|0.0%|3.5%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|235|0.0%|3.3%|
[dragon_http](#dragon_http)|1021|268288|214|0.0%|3.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|163|0.0%|2.3%|
[openbl_1d](#openbl_1d)|155|155|155|100.0%|2.2%|
[dshield](#dshield)|20|5120|84|1.6%|1.2%|
[stopforumspam_30d](#stopforumspam_30d)|94236|94236|47|0.0%|0.6%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|26|0.0%|0.3%|
[snort_ipfilter](#snort_ipfilter)|8373|8373|23|0.2%|0.3%|
[firehol_anonymous](#firehol_anonymous)|19320|83371|23|0.0%|0.3%|
[blocklist_de_strongips](#blocklist_de_strongips)|168|168|23|13.6%|0.3%|
[tor_exits](#tor_exits)|1106|1106|20|1.8%|0.2%|
[stopforumspam_1d](#stopforumspam_1d)|6864|6864|20|0.2%|0.2%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|20|3.8%|0.2%|
[firehol_proxies](#firehol_proxies)|12732|13012|20|0.1%|0.2%|
[et_tor](#et_tor)|6500|6500|20|0.3%|0.2%|
[dm_tor](#dm_tor)|6559|6559|20|0.3%|0.2%|
[bm_tor](#bm_tor)|6533|6533|20|0.3%|0.2%|
[blocklist_de_mail](#blocklist_de_mail)|18292|18292|20|0.1%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|16|0.0%|0.2%|
[blocklist_de_imap](#blocklist_de_imap)|3535|3535|16|0.4%|0.2%|
[php_commenters](#php_commenters)|458|458|12|2.6%|0.1%|
[voipbl](#voipbl)|10607|11019|8|0.0%|0.1%|
[blocklist_de_apache](#blocklist_de_apache)|14109|14109|6|0.0%|0.0%|
[nixspam](#nixspam)|22540|22540|5|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|5|0.0%|0.0%|
[zeus](#zeus)|230|230|2|0.8%|0.0%|
[sorbs_spam](#sorbs_spam)|64701|65536|2|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|2|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|2|0.0%|0.0%|
[php_harvesters](#php_harvesters)|408|408|2|0.4%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|2|0.1%|0.0%|
[ciarmy](#ciarmy)|428|428|2|0.4%|0.0%|
[zeus_badips](#zeus_badips)|202|202|1|0.4%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|1|0.0%|0.0%|
[php_spammers](#php_spammers)|777|777|1|0.1%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|1509|1509|1|0.0%|0.0%|

## openbl_7d

[OpenBL.org](http://www.openbl.org/) last 7 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.

Source is downloaded from [this link](http://www.openbl.org/lists/base_7days.txt).

The last time downloaded was found to be dated: Fri Jun 12 16:07:00 UTC 2015.

The ipset `openbl_7d` has **638** entries, **638** unique IPs.

The following table shows the overlaps of `openbl_7d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl_7d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl_7d`.
- ` this % ` is the percentage **of this ipset (`openbl_7d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[openbl_60d](#openbl_60d)|6959|6959|638|9.1%|100.0%|
[openbl_30d](#openbl_30d)|2791|2791|638|22.8%|100.0%|
[firehol_level3](#firehol_level3)|108767|9626344|638|0.0%|100.0%|
[alienvault_reputation](#alienvault_reputation)|189217|189217|635|0.3%|99.5%|
[firehol_level2](#firehol_level2)|22948|34548|399|1.1%|62.5%|
[blocklist_de](#blocklist_de)|29129|29129|369|1.2%|57.8%|
[blocklist_de_ssh](#blocklist_de_ssh)|3204|3204|362|11.2%|56.7%|
[dragon_sshpauth](#dragon_sshpauth)|1568|1632|344|21.0%|53.9%|
[bruteforceblocker](#bruteforceblocker)|1700|1700|306|18.0%|47.9%|
[et_compromised](#et_compromised)|1704|1704|301|17.6%|47.1%|
[shunlist](#shunlist)|1129|1129|198|17.5%|31.0%|
[openbl_1d](#openbl_1d)|155|155|155|100.0%|24.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|63|0.0%|9.8%|
[firehol_level1](#firehol_level1)|5068|688775049|60|0.0%|9.4%|
[et_block](#et_block)|1000|18343756|57|0.0%|8.9%|
[dragon_http](#dragon_http)|1021|268288|54|0.0%|8.4%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|53|0.0%|8.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|39|0.0%|6.1%|
[dshield](#dshield)|20|5120|22|0.4%|3.4%|
[blocklist_de_strongips](#blocklist_de_strongips)|168|168|22|13.0%|3.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|16|0.0%|2.5%|
[blocklist_de_mail](#blocklist_de_mail)|18292|18292|7|0.0%|1.0%|
[blocklist_de_imap](#blocklist_de_imap)|3535|3535|7|0.1%|1.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|4|0.0%|0.6%|
[stopforumspam_30d](#stopforumspam_30d)|94236|94236|2|0.0%|0.3%|
[ciarmy](#ciarmy)|428|428|2|0.4%|0.3%|
[zeus_badips](#zeus_badips)|202|202|1|0.4%|0.1%|
[zeus](#zeus)|230|230|1|0.4%|0.1%|
[snort_ipfilter](#snort_ipfilter)|8373|8373|1|0.0%|0.1%|
[php_spammers](#php_spammers)|777|777|1|0.1%|0.1%|
[php_commenters](#php_commenters)|458|458|1|0.2%|0.1%|
[blocklist_de_ftp](#blocklist_de_ftp)|1509|1509|1|0.0%|0.1%|

## palevo

[Abuse.ch Palevo tracker](https://palevotracker.abuse.ch) worm includes IPs which are being used as botnet C&C for the Palevo crimeware - **excellent list**

Source is downloaded from [this link](https://palevotracker.abuse.ch/blocklists.php?download=ipblocklist).

The last time downloaded was found to be dated: Fri Jun 12 15:54:15 UTC 2015.

The ipset `palevo` has **0** entries, **0** unique IPs.

The following table shows the overlaps of `palevo` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `palevo`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `palevo`.
- ` this % ` is the percentage **of this ipset (`palevo`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|

## php_commenters

[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) comment spammers (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=c&rss=1).

The last time downloaded was found to be dated: Fri Jun 12 15:45:29 UTC 2015.

The ipset `php_commenters` has **458** entries, **458** unique IPs.

The following table shows the overlaps of `php_commenters` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `php_commenters`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `php_commenters`.
- ` this % ` is the percentage **of this ipset (`php_commenters`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level3](#firehol_level3)|108767|9626344|458|0.0%|100.0%|
[stopforumspam_30d](#stopforumspam_30d)|94236|94236|336|0.3%|73.3%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|248|0.8%|54.1%|
[firehol_level2](#firehol_level2)|22948|34548|197|0.5%|43.0%|
[stopforumspam_1d](#stopforumspam_1d)|6864|6864|159|2.3%|34.7%|
[blocklist_de](#blocklist_de)|29129|29129|107|0.3%|23.3%|
[firehol_anonymous](#firehol_anonymous)|19320|83371|89|0.1%|19.4%|
[blocklist_de_bots](#blocklist_de_bots)|3035|3035|88|2.8%|19.2%|
[firehol_proxies](#firehol_proxies)|12732|13012|85|0.6%|18.5%|
[snort_ipfilter](#snort_ipfilter)|8373|8373|69|0.8%|15.0%|
[php_spammers](#php_spammers)|777|777|55|7.0%|12.0%|
[tor_exits](#tor_exits)|1106|1106|54|4.8%|11.7%|
[et_tor](#et_tor)|6500|6500|54|0.8%|11.7%|
[dm_tor](#dm_tor)|6559|6559|54|0.8%|11.7%|
[bm_tor](#bm_tor)|6533|6533|54|0.8%|11.7%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|53|10.1%|11.5%|
[blocklist_de_strongips](#blocklist_de_strongips)|168|168|43|25.5%|9.3%|
[firehol_level1](#firehol_level1)|5068|688775049|39|0.0%|8.5%|
[php_dictionary](#php_dictionary)|777|777|38|4.8%|8.2%|
[ri_web_proxies](#ri_web_proxies)|8035|8035|30|0.3%|6.5%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|29|0.0%|6.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|29|0.0%|6.3%|
[et_block](#et_block)|1000|18343756|29|0.0%|6.3%|
[blocklist_de_mail](#blocklist_de_mail)|18292|18292|29|0.1%|6.3%|
[sorbs_spam](#sorbs_spam)|64701|65536|27|0.0%|5.8%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|27|0.0%|5.8%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|27|0.0%|5.8%|
[blocklist_de_apache](#blocklist_de_apache)|14109|14109|27|0.1%|5.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|19|0.0%|4.1%|
[alienvault_reputation](#alienvault_reputation)|189217|189217|19|0.0%|4.1%|
[php_harvesters](#php_harvesters)|408|408|15|3.6%|3.2%|
[xroxy](#xroxy)|2176|2176|13|0.5%|2.8%|
[openbl_60d](#openbl_60d)|6959|6959|12|0.1%|2.6%|
[nixspam](#nixspam)|22540|22540|11|0.0%|2.4%|
[proxz](#proxz)|1385|1385|10|0.7%|2.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|10|0.0%|2.1%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|8|0.0%|1.7%|
[ri_connect_proxies](#ri_connect_proxies)|2902|2902|6|0.2%|1.3%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2714|2714|6|0.2%|1.3%|
[proxyrss](#proxyrss)|1402|1402|5|0.3%|1.0%|
[sorbs_web](#sorbs_web)|667|668|4|0.5%|0.8%|
[iw_spamlist](#iw_spamlist)|3266|3266|4|0.1%|0.8%|
[dragon_http](#dragon_http)|1021|268288|4|0.0%|0.8%|
[zeus_badips](#zeus_badips)|202|202|1|0.4%|0.2%|
[zeus](#zeus)|230|230|1|0.4%|0.2%|
[shunlist](#shunlist)|1129|1129|1|0.0%|0.2%|
[openbl_7d](#openbl_7d)|638|638|1|0.1%|0.2%|
[openbl_30d](#openbl_30d)|2791|2791|1|0.0%|0.2%|
[openbl_1d](#openbl_1d)|155|155|1|0.6%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.2%|
[fullbogons](#fullbogons)|3788|670093640|1|0.0%|0.2%|
[et_compromised](#et_compromised)|1704|1704|1|0.0%|0.2%|
[dshield](#dshield)|20|5120|1|0.0%|0.2%|
[bruteforceblocker](#bruteforceblocker)|1700|1700|1|0.0%|0.2%|
[bogons](#bogons)|13|592708608|1|0.0%|0.2%|
[blocklist_de_ssh](#blocklist_de_ssh)|3204|3204|1|0.0%|0.2%|

## php_dictionary

[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) directory attackers (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=d&rss=1).

The last time downloaded was found to be dated: Fri Jun 12 15:45:30 UTC 2015.

The ipset `php_dictionary` has **777** entries, **777** unique IPs.

The following table shows the overlaps of `php_dictionary` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `php_dictionary`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `php_dictionary`.
- ` this % ` is the percentage **of this ipset (`php_dictionary`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level3](#firehol_level3)|108767|9626344|777|0.0%|100.0%|
[php_spammers](#php_spammers)|777|777|350|45.0%|45.0%|
[sorbs_spam](#sorbs_spam)|64701|65536|217|0.3%|27.9%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|217|0.3%|27.9%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|217|0.3%|27.9%|
[stopforumspam_30d](#stopforumspam_30d)|94236|94236|142|0.1%|18.2%|
[nixspam](#nixspam)|22540|22540|125|0.5%|16.0%|
[firehol_level2](#firehol_level2)|22948|34548|118|0.3%|15.1%|
[blocklist_de](#blocklist_de)|29129|29129|111|0.3%|14.2%|
[firehol_anonymous](#firehol_anonymous)|19320|83371|102|0.1%|13.1%|
[snort_ipfilter](#snort_ipfilter)|8373|8373|101|1.2%|12.9%|
[firehol_proxies](#firehol_proxies)|12732|13012|101|0.7%|12.9%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|95|0.3%|12.2%|
[blocklist_de_mail](#blocklist_de_mail)|18292|18292|89|0.4%|11.4%|
[ri_web_proxies](#ri_web_proxies)|8035|8035|70|0.8%|9.0%|
[xroxy](#xroxy)|2176|2176|42|1.9%|5.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|39|0.0%|5.0%|
[php_commenters](#php_commenters)|458|458|38|8.2%|4.8%|
[sorbs_web](#sorbs_web)|667|668|35|5.2%|4.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|30|0.0%|3.8%|
[stopforumspam_1d](#stopforumspam_1d)|6864|6864|27|0.3%|3.4%|
[proxz](#proxz)|1385|1385|26|1.8%|3.3%|
[blocklist_de_bots](#blocklist_de_bots)|3035|3035|18|0.5%|2.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|12|0.0%|1.5%|
[iw_spamlist](#iw_spamlist)|3266|3266|8|0.2%|1.0%|
[ri_connect_proxies](#ri_connect_proxies)|2902|2902|7|0.2%|0.9%|
[alienvault_reputation](#alienvault_reputation)|189217|189217|7|0.0%|0.9%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|6|0.0%|0.7%|
[firehol_level1](#firehol_level1)|5068|688775049|6|0.0%|0.7%|
[et_block](#et_block)|1000|18343756|6|0.0%|0.7%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|5|0.9%|0.6%|
[blocklist_de_strongips](#blocklist_de_strongips)|168|168|5|2.9%|0.6%|
[tor_exits](#tor_exits)|1106|1106|4|0.3%|0.5%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|4|0.0%|0.5%|
[et_tor](#et_tor)|6500|6500|4|0.0%|0.5%|
[dm_tor](#dm_tor)|6559|6559|4|0.0%|0.5%|
[bm_tor](#bm_tor)|6533|6533|4|0.0%|0.5%|
[php_harvesters](#php_harvesters)|408|408|3|0.7%|0.3%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|3|0.0%|0.3%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2714|2714|3|0.1%|0.3%|
[blocklist_de_apache](#blocklist_de_apache)|14109|14109|3|0.0%|0.3%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|2|0.3%|0.2%|
[dragon_http](#dragon_http)|1021|268288|2|0.0%|0.2%|
[sorbs_socks](#sorbs_socks)|7|7|1|14.2%|0.1%|
[sorbs_misc](#sorbs_misc)|7|7|1|14.2%|0.1%|
[sorbs_http](#sorbs_http)|7|7|1|14.2%|0.1%|
[proxyrss](#proxyrss)|1402|1402|1|0.0%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.1%|
[blocklist_de_ftp](#blocklist_de_ftp)|1509|1509|1|0.0%|0.1%|

## php_harvesters

[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) harvesters (IPs that surf the internet looking for email addresses) (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=h&rss=1).

The last time downloaded was found to be dated: Fri Jun 12 15:45:26 UTC 2015.

The ipset `php_harvesters` has **408** entries, **408** unique IPs.

The following table shows the overlaps of `php_harvesters` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `php_harvesters`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `php_harvesters`.
- ` this % ` is the percentage **of this ipset (`php_harvesters`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level3](#firehol_level3)|108767|9626344|408|0.0%|100.0%|
[stopforumspam_30d](#stopforumspam_30d)|94236|94236|87|0.0%|21.3%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|65|0.2%|15.9%|
[firehol_level2](#firehol_level2)|22948|34548|54|0.1%|13.2%|
[stopforumspam_1d](#stopforumspam_1d)|6864|6864|40|0.5%|9.8%|
[blocklist_de](#blocklist_de)|29129|29129|38|0.1%|9.3%|
[blocklist_de_bots](#blocklist_de_bots)|3035|3035|28|0.9%|6.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|20|0.0%|4.9%|
[sorbs_spam](#sorbs_spam)|64701|65536|16|0.0%|3.9%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|16|0.0%|3.9%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|16|0.0%|3.9%|
[php_commenters](#php_commenters)|458|458|15|3.2%|3.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|12|0.0%|2.9%|
[firehol_proxies](#firehol_proxies)|12732|13012|12|0.0%|2.9%|
[firehol_anonymous](#firehol_anonymous)|19320|83371|12|0.0%|2.9%|
[alienvault_reputation](#alienvault_reputation)|189217|189217|12|0.0%|2.9%|
[snort_ipfilter](#snort_ipfilter)|8373|8373|10|0.1%|2.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|9|0.0%|2.2%|
[nixspam](#nixspam)|22540|22540|7|0.0%|1.7%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|7|1.3%|1.7%|
[et_tor](#et_tor)|6500|6500|7|0.1%|1.7%|
[dm_tor](#dm_tor)|6559|6559|7|0.1%|1.7%|
[bm_tor](#bm_tor)|6533|6533|7|0.1%|1.7%|
[tor_exits](#tor_exits)|1106|1106|6|0.5%|1.4%|
[blocklist_de_mail](#blocklist_de_mail)|18292|18292|6|0.0%|1.4%|
[php_spammers](#php_spammers)|777|777|3|0.3%|0.7%|
[php_dictionary](#php_dictionary)|777|777|3|0.3%|0.7%|
[iw_spamlist](#iw_spamlist)|3266|3266|3|0.0%|0.7%|
[firehol_level1](#firehol_level1)|5068|688775049|3|0.0%|0.7%|
[blocklist_de_strongips](#blocklist_de_strongips)|168|168|3|1.7%|0.7%|
[blocklist_de_imap](#blocklist_de_imap)|3535|3535|3|0.0%|0.7%|
[blocklist_de_ftp](#blocklist_de_ftp)|1509|1509|3|0.1%|0.7%|
[xroxy](#xroxy)|2176|2176|2|0.0%|0.4%|
[ri_web_proxies](#ri_web_proxies)|8035|8035|2|0.0%|0.4%|
[proxyrss](#proxyrss)|1402|1402|2|0.1%|0.4%|
[openbl_60d](#openbl_60d)|6959|6959|2|0.0%|0.4%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|2|0.0%|0.4%|
[blocklist_de_apache](#blocklist_de_apache)|14109|14109|2|0.0%|0.4%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|1|0.0%|0.2%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|1|0.0%|0.2%|
[sorbs_web](#sorbs_web)|667|668|1|0.1%|0.2%|
[shunlist](#shunlist)|1129|1129|1|0.0%|0.2%|
[ri_connect_proxies](#ri_connect_proxies)|2902|2902|1|0.0%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.2%|
[fullbogons](#fullbogons)|3788|670093640|1|0.0%|0.2%|
[et_block](#et_block)|1000|18343756|1|0.0%|0.2%|
[bogons](#bogons)|13|592708608|1|0.0%|0.2%|
[blocklist_de_ssh](#blocklist_de_ssh)|3204|3204|1|0.0%|0.2%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2714|2714|1|0.0%|0.2%|

## php_spammers

[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) spam servers (IPs used by spammers to send messages) (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=s&rss=1).

The last time downloaded was found to be dated: Fri Jun 12 15:45:28 UTC 2015.

The ipset `php_spammers` has **777** entries, **777** unique IPs.

The following table shows the overlaps of `php_spammers` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `php_spammers`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `php_spammers`.
- ` this % ` is the percentage **of this ipset (`php_spammers`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level3](#firehol_level3)|108767|9626344|777|0.0%|100.0%|
[php_dictionary](#php_dictionary)|777|777|350|45.0%|45.0%|
[sorbs_spam](#sorbs_spam)|64701|65536|190|0.2%|24.4%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|190|0.2%|24.4%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|190|0.2%|24.4%|
[stopforumspam_30d](#stopforumspam_30d)|94236|94236|155|0.1%|19.9%|
[firehol_level2](#firehol_level2)|22948|34548|117|0.3%|15.0%|
[nixspam](#nixspam)|22540|22540|109|0.4%|14.0%|
[blocklist_de](#blocklist_de)|29129|29129|108|0.3%|13.8%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|96|0.3%|12.3%|
[snort_ipfilter](#snort_ipfilter)|8373|8373|90|1.0%|11.5%|
[firehol_anonymous](#firehol_anonymous)|19320|83371|85|0.1%|10.9%|
[firehol_proxies](#firehol_proxies)|12732|13012|83|0.6%|10.6%|
[blocklist_de_mail](#blocklist_de_mail)|18292|18292|76|0.4%|9.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|60|0.0%|7.7%|
[ri_web_proxies](#ri_web_proxies)|8035|8035|56|0.6%|7.2%|
[php_commenters](#php_commenters)|458|458|55|12.0%|7.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|44|0.0%|5.6%|
[stopforumspam_1d](#stopforumspam_1d)|6864|6864|40|0.5%|5.1%|
[xroxy](#xroxy)|2176|2176|35|1.6%|4.5%|
[sorbs_web](#sorbs_web)|667|668|28|4.1%|3.6%|
[blocklist_de_bots](#blocklist_de_bots)|3035|3035|24|0.7%|3.0%|
[proxz](#proxz)|1385|1385|23|1.6%|2.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|11|0.0%|1.4%|
[blocklist_de_strongips](#blocklist_de_strongips)|168|168|10|5.9%|1.2%|
[iw_spamlist](#iw_spamlist)|3266|3266|8|0.2%|1.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|6|1.1%|0.7%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2714|2714|6|0.2%|0.7%|
[blocklist_de_apache](#blocklist_de_apache)|14109|14109|6|0.0%|0.7%|
[tor_exits](#tor_exits)|1106|1106|5|0.4%|0.6%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|5|0.0%|0.6%|
[firehol_level1](#firehol_level1)|5068|688775049|5|0.0%|0.6%|
[et_tor](#et_tor)|6500|6500|5|0.0%|0.6%|
[et_block](#et_block)|1000|18343756|5|0.0%|0.6%|
[dm_tor](#dm_tor)|6559|6559|5|0.0%|0.6%|
[bm_tor](#bm_tor)|6533|6533|5|0.0%|0.6%|
[alienvault_reputation](#alienvault_reputation)|189217|189217|5|0.0%|0.6%|
[ri_connect_proxies](#ri_connect_proxies)|2902|2902|4|0.1%|0.5%|
[proxyrss](#proxyrss)|1402|1402|3|0.2%|0.3%|
[php_harvesters](#php_harvesters)|408|408|3|0.7%|0.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|0.3%|
[openbl_7d](#openbl_7d)|638|638|1|0.1%|0.1%|
[openbl_60d](#openbl_60d)|6959|6959|1|0.0%|0.1%|
[openbl_30d](#openbl_30d)|2791|2791|1|0.0%|0.1%|
[openbl_1d](#openbl_1d)|155|155|1|0.6%|0.1%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|1|0.1%|0.1%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|1|0.0%|0.1%|
[et_compromised](#et_compromised)|1704|1704|1|0.0%|0.1%|
[bruteforceblocker](#bruteforceblocker)|1700|1700|1|0.0%|0.1%|
[blocklist_de_ssh](#blocklist_de_ssh)|3204|3204|1|0.0%|0.1%|
[blocklist_de_ftp](#blocklist_de_ftp)|1509|1509|1|0.0%|0.1%|

## proxyrss

[proxyrss.com](http://www.proxyrss.com) open proxies syndicated from multiple sources.

Source is downloaded from [this link](http://www.proxyrss.com/proxylists/all.gz).

The last time downloaded was found to be dated: Fri Jun 12 15:41:23 UTC 2015.

The ipset `proxyrss` has **1402** entries, **1402** unique IPs.

The following table shows the overlaps of `proxyrss` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `proxyrss`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `proxyrss`.
- ` this % ` is the percentage **of this ipset (`proxyrss`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_proxies](#firehol_proxies)|12732|13012|1402|10.7%|100.0%|
[firehol_anonymous](#firehol_anonymous)|19320|83371|1402|1.6%|100.0%|
[stopforumspam_30d](#stopforumspam_30d)|94236|94236|651|0.6%|46.4%|
[firehol_level3](#firehol_level3)|108767|9626344|651|0.0%|46.4%|
[ri_web_proxies](#ri_web_proxies)|8035|8035|576|7.1%|41.0%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|500|1.7%|35.6%|
[xroxy](#xroxy)|2176|2176|356|16.3%|25.3%|
[firehol_level2](#firehol_level2)|22948|34548|347|1.0%|24.7%|
[proxz](#proxz)|1385|1385|292|21.0%|20.8%|
[stopforumspam_1d](#stopforumspam_1d)|6864|6864|288|4.1%|20.5%|
[blocklist_de](#blocklist_de)|29129|29129|201|0.6%|14.3%|
[ri_connect_proxies](#ri_connect_proxies)|2902|2902|199|6.8%|14.1%|
[blocklist_de_bots](#blocklist_de_bots)|3035|3035|199|6.5%|14.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|56|0.0%|3.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|39|0.0%|2.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|34|0.0%|2.4%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|12|1.8%|0.8%|
[nixspam](#nixspam)|22540|22540|10|0.0%|0.7%|
[blocklist_de_strongips](#blocklist_de_strongips)|168|168|7|4.1%|0.4%|
[php_commenters](#php_commenters)|458|458|5|1.0%|0.3%|
[sorbs_spam](#sorbs_spam)|64701|65536|4|0.0%|0.2%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|4|0.0%|0.2%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|4|0.0%|0.2%|
[php_spammers](#php_spammers)|777|777|3|0.3%|0.2%|
[snort_ipfilter](#snort_ipfilter)|8373|8373|2|0.0%|0.1%|
[php_harvesters](#php_harvesters)|408|408|2|0.4%|0.1%|
[iw_spamlist](#iw_spamlist)|3266|3266|2|0.0%|0.1%|
[dragon_http](#dragon_http)|1021|268288|2|0.0%|0.1%|
[alienvault_reputation](#alienvault_reputation)|189217|189217|2|0.0%|0.1%|
[php_dictionary](#php_dictionary)|777|777|1|0.1%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|1|0.1%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|1|0.0%|0.0%|
[et_compromised](#et_compromised)|1704|1704|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1700|1700|1|0.0%|0.0%|

## proxz

[proxz.com](http://www.proxz.com) open proxies (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.proxz.com/proxylists.xml).

The last time downloaded was found to be dated: Fri Jun 12 15:41:28 UTC 2015.

The ipset `proxz` has **1385** entries, **1385** unique IPs.

The following table shows the overlaps of `proxz` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `proxz`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `proxz`.
- ` this % ` is the percentage **of this ipset (`proxz`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_proxies](#firehol_proxies)|12732|13012|1385|10.6%|100.0%|
[firehol_anonymous](#firehol_anonymous)|19320|83371|1385|1.6%|100.0%|
[firehol_level3](#firehol_level3)|108767|9626344|824|0.0%|59.4%|
[stopforumspam_30d](#stopforumspam_30d)|94236|94236|818|0.8%|59.0%|
[ri_web_proxies](#ri_web_proxies)|8035|8035|631|7.8%|45.5%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|521|1.7%|37.6%|
[xroxy](#xroxy)|2176|2176|475|21.8%|34.2%|
[proxyrss](#proxyrss)|1402|1402|292|20.8%|21.0%|
[firehol_level2](#firehol_level2)|22948|34548|276|0.7%|19.9%|
[ri_connect_proxies](#ri_connect_proxies)|2902|2902|241|8.3%|17.4%|
[blocklist_de](#blocklist_de)|29129|29129|210|0.7%|15.1%|
[blocklist_de_bots](#blocklist_de_bots)|3035|3035|180|5.9%|12.9%|
[stopforumspam_1d](#stopforumspam_1d)|6864|6864|172|2.5%|12.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|106|0.0%|7.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|57|0.0%|4.1%|
[nixspam](#nixspam)|22540|22540|46|0.2%|3.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|45|0.0%|3.2%|
[sorbs_spam](#sorbs_spam)|64701|65536|44|0.0%|3.1%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|44|0.0%|3.1%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|44|0.0%|3.1%|
[snort_ipfilter](#snort_ipfilter)|8373|8373|29|0.3%|2.0%|
[blocklist_de_mail](#blocklist_de_mail)|18292|18292|29|0.1%|2.0%|
[php_dictionary](#php_dictionary)|777|777|26|3.3%|1.8%|
[php_spammers](#php_spammers)|777|777|23|2.9%|1.6%|
[php_commenters](#php_commenters)|458|458|10|2.1%|0.7%|
[sorbs_web](#sorbs_web)|667|668|8|1.1%|0.5%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|7|1.0%|0.5%|
[blocklist_de_strongips](#blocklist_de_strongips)|168|168|6|3.5%|0.4%|
[dragon_http](#dragon_http)|1021|268288|4|0.0%|0.2%|
[alienvault_reputation](#alienvault_reputation)|189217|189217|4|0.0%|0.2%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|2|0.3%|0.1%|
[iw_spamlist](#iw_spamlist)|3266|3266|2|0.0%|0.1%|
[et_compromised](#et_compromised)|1704|1704|2|0.1%|0.1%|
[bruteforceblocker](#bruteforceblocker)|1700|1700|2|0.1%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|1|0.0%|0.0%|
[et_block](#et_block)|1000|18343756|1|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2714|2714|1|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14109|14109|1|0.0%|0.0%|

## ri_connect_proxies

[rosinstrument.com](http://www.rosinstrument.com) open CONNECT proxies (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://tools.rosinstrument.com/proxy/plab100.xml).

The last time downloaded was found to be dated: Fri Jun 12 14:19:47 UTC 2015.

The ipset `ri_connect_proxies` has **2902** entries, **2902** unique IPs.

The following table shows the overlaps of `ri_connect_proxies` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ri_connect_proxies`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ri_connect_proxies`.
- ` this % ` is the percentage **of this ipset (`ri_connect_proxies`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_proxies](#firehol_proxies)|12732|13012|2902|22.3%|100.0%|
[firehol_anonymous](#firehol_anonymous)|19320|83371|2902|3.4%|100.0%|
[firehol_level3](#firehol_level3)|108767|9626344|1608|0.0%|55.4%|
[stopforumspam_30d](#stopforumspam_30d)|94236|94236|1607|1.7%|55.3%|
[ri_web_proxies](#ri_web_proxies)|8035|8035|1227|15.2%|42.2%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|538|1.8%|18.5%|
[xroxy](#xroxy)|2176|2176|397|18.2%|13.6%|
[proxz](#proxz)|1385|1385|241|17.4%|8.3%|
[proxyrss](#proxyrss)|1402|1402|199|14.1%|6.8%|
[firehol_level2](#firehol_level2)|22948|34548|157|0.4%|5.4%|
[stopforumspam_1d](#stopforumspam_1d)|6864|6864|109|1.5%|3.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|106|0.0%|3.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|87|0.0%|2.9%|
[blocklist_de](#blocklist_de)|29129|29129|77|0.2%|2.6%|
[blocklist_de_bots](#blocklist_de_bots)|3035|3035|74|2.4%|2.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|58|0.0%|1.9%|
[sorbs_spam](#sorbs_spam)|64701|65536|18|0.0%|0.6%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|18|0.0%|0.6%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|18|0.0%|0.6%|
[nixspam](#nixspam)|22540|22540|18|0.0%|0.6%|
[php_dictionary](#php_dictionary)|777|777|7|0.9%|0.2%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|7|1.0%|0.2%|
[snort_ipfilter](#snort_ipfilter)|8373|8373|6|0.0%|0.2%|
[php_commenters](#php_commenters)|458|458|6|1.3%|0.2%|
[php_spammers](#php_spammers)|777|777|4|0.5%|0.1%|
[dragon_http](#dragon_http)|1021|268288|4|0.0%|0.1%|
[alienvault_reputation](#alienvault_reputation)|189217|189217|3|0.0%|0.1%|
[iw_spamlist](#iw_spamlist)|3266|3266|2|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|18292|18292|2|0.0%|0.0%|
[sorbs_web](#sorbs_web)|667|668|1|0.1%|0.0%|
[php_harvesters](#php_harvesters)|408|408|1|0.2%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|1|0.1%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|1|0.0%|0.0%|
[et_tor](#et_tor)|6500|6500|1|0.0%|0.0%|
[dm_tor](#dm_tor)|6559|6559|1|0.0%|0.0%|
[bm_tor](#bm_tor)|6533|6533|1|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|3535|3535|1|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14109|14109|1|0.0%|0.0%|

## ri_web_proxies

[rosinstrument.com](http://www.rosinstrument.com) open HTTP proxies (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://tools.rosinstrument.com/proxy/l100.xml).

The last time downloaded was found to be dated: Fri Jun 12 14:19:38 UTC 2015.

The ipset `ri_web_proxies` has **8035** entries, **8035** unique IPs.

The following table shows the overlaps of `ri_web_proxies` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ri_web_proxies`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ri_web_proxies`.
- ` this % ` is the percentage **of this ipset (`ri_web_proxies`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_proxies](#firehol_proxies)|12732|13012|8035|61.7%|100.0%|
[firehol_anonymous](#firehol_anonymous)|19320|83371|8035|9.6%|100.0%|
[firehol_level3](#firehol_level3)|108767|9626344|3796|0.0%|47.2%|
[stopforumspam_30d](#stopforumspam_30d)|94236|94236|3751|3.9%|46.6%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|1494|5.1%|18.5%|
[ri_connect_proxies](#ri_connect_proxies)|2902|2902|1227|42.2%|15.2%|
[xroxy](#xroxy)|2176|2176|966|44.3%|12.0%|
[firehol_level2](#firehol_level2)|22948|34548|672|1.9%|8.3%|
[proxz](#proxz)|1385|1385|631|45.5%|7.8%|
[proxyrss](#proxyrss)|1402|1402|576|41.0%|7.1%|
[blocklist_de](#blocklist_de)|29129|29129|484|1.6%|6.0%|
[stopforumspam_1d](#stopforumspam_1d)|6864|6864|412|6.0%|5.1%|
[blocklist_de_bots](#blocklist_de_bots)|3035|3035|397|13.0%|4.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|225|0.0%|2.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|221|0.0%|2.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|156|0.0%|1.9%|
[sorbs_spam](#sorbs_spam)|64701|65536|145|0.2%|1.8%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|145|0.2%|1.8%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|145|0.2%|1.8%|
[nixspam](#nixspam)|22540|22540|90|0.3%|1.1%|
[blocklist_de_mail](#blocklist_de_mail)|18292|18292|83|0.4%|1.0%|
[php_dictionary](#php_dictionary)|777|777|70|9.0%|0.8%|
[snort_ipfilter](#snort_ipfilter)|8373|8373|64|0.7%|0.7%|
[php_spammers](#php_spammers)|777|777|56|7.2%|0.6%|
[php_commenters](#php_commenters)|458|458|30|6.5%|0.3%|
[sorbs_web](#sorbs_web)|667|668|22|3.2%|0.2%|
[dragon_http](#dragon_http)|1021|268288|21|0.0%|0.2%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|15|2.2%|0.1%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|10|1.9%|0.1%|
[blocklist_de_strongips](#blocklist_de_strongips)|168|168|8|4.7%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|6|0.0%|0.0%|
[et_tor](#et_tor)|6500|6500|5|0.0%|0.0%|
[dm_tor](#dm_tor)|6559|6559|5|0.0%|0.0%|
[bm_tor](#bm_tor)|6533|6533|5|0.0%|0.0%|
[iw_spamlist](#iw_spamlist)|3266|3266|4|0.1%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|4|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2714|2714|4|0.1%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14109|14109|4|0.0%|0.0%|
[alienvault_reputation](#alienvault_reputation)|189217|189217|4|0.0%|0.0%|
[php_harvesters](#php_harvesters)|408|408|2|0.4%|0.0%|
[sslbl](#sslbl)|368|368|1|0.2%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|1|0.0%|0.0%|
[firehol_level1](#firehol_level1)|5068|688775049|1|0.0%|0.0%|
[et_compromised](#et_compromised)|1704|1704|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1700|1700|1|0.0%|0.0%|

## shunlist

[AutoShun.org](http://autoshun.org/) IPs identified as hostile by correlating logs from distributed snort installations running the autoshun plugin

Source is downloaded from [this link](http://www.autoshun.org/files/shunlist.csv).

The last time downloaded was found to be dated: Fri Jun 12 15:30:05 UTC 2015.

The ipset `shunlist` has **1129** entries, **1129** unique IPs.

The following table shows the overlaps of `shunlist` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `shunlist`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `shunlist`.
- ` this % ` is the percentage **of this ipset (`shunlist`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level3](#firehol_level3)|108767|9626344|1129|0.0%|100.0%|
[alienvault_reputation](#alienvault_reputation)|189217|189217|1105|0.5%|97.8%|
[openbl_60d](#openbl_60d)|6959|6959|424|6.0%|37.5%|
[openbl_30d](#openbl_30d)|2791|2791|402|14.4%|35.6%|
[dragon_sshpauth](#dragon_sshpauth)|1568|1632|355|21.7%|31.4%|
[firehol_level2](#firehol_level2)|22948|34548|335|0.9%|29.6%|
[blocklist_de](#blocklist_de)|29129|29129|329|1.1%|29.1%|
[bruteforceblocker](#bruteforceblocker)|1700|1700|312|18.3%|27.6%|
[et_compromised](#et_compromised)|1704|1704|309|18.1%|27.3%|
[blocklist_de_ssh](#blocklist_de_ssh)|3204|3204|286|8.9%|25.3%|
[openbl_7d](#openbl_7d)|638|638|198|31.0%|17.5%|
[firehol_level1](#firehol_level1)|5068|688775049|153|0.0%|13.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|113|0.0%|10.0%|
[et_block](#et_block)|1000|18343756|93|0.0%|8.2%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|86|0.0%|7.6%|
[dshield](#dshield)|20|5120|78|1.5%|6.9%|
[openbl_1d](#openbl_1d)|155|155|66|42.5%|5.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|66|0.0%|5.8%|
[sslbl](#sslbl)|368|368|58|15.7%|5.1%|
[blocklist_de_apache](#blocklist_de_apache)|14109|14109|37|0.2%|3.2%|
[ciarmy](#ciarmy)|428|428|30|7.0%|2.6%|
[dragon_http](#dragon_http)|1021|268288|26|0.0%|2.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|25|0.0%|2.2%|
[blocklist_de_strongips](#blocklist_de_strongips)|168|168|19|11.3%|1.6%|
[voipbl](#voipbl)|10607|11019|13|0.1%|1.1%|
[stopforumspam_30d](#stopforumspam_30d)|94236|94236|5|0.0%|0.4%|
[blocklist_de_mail](#blocklist_de_mail)|18292|18292|4|0.0%|0.3%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|3|0.0%|0.2%|
[stopforumspam_1d](#stopforumspam_1d)|6864|6864|2|0.0%|0.1%|
[snort_ipfilter](#snort_ipfilter)|8373|8373|2|0.0%|0.1%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|2|0.3%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2|0.0%|0.1%|
[firehol_proxies](#firehol_proxies)|12732|13012|2|0.0%|0.1%|
[firehol_anonymous](#firehol_anonymous)|19320|83371|2|0.0%|0.1%|
[et_tor](#et_tor)|6500|6500|2|0.0%|0.1%|
[dragon_vncprobe](#dragon_vncprobe)|85|85|2|2.3%|0.1%|
[dm_tor](#dm_tor)|6559|6559|2|0.0%|0.1%|
[bm_tor](#bm_tor)|6533|6533|2|0.0%|0.1%|
[blocklist_de_sip](#blocklist_de_sip)|80|80|2|2.5%|0.1%|
[blocklist_de_imap](#blocklist_de_imap)|3535|3535|2|0.0%|0.1%|
[tor_exits](#tor_exits)|1106|1106|1|0.0%|0.0%|
[php_harvesters](#php_harvesters)|408|408|1|0.2%|0.0%|
[php_commenters](#php_commenters)|458|458|1|0.2%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2714|2714|1|0.0%|0.0%|

## snort_ipfilter

[labs.snort.org](https://labs.snort.org/) supplied IP blacklist (this list seems to be updated frequently, but we found no information about it)

Source is downloaded from [this link](http://labs.snort.org/feeds/ip-filter.blf).

The last time downloaded was found to be dated: Fri Jun 12 16:00:00 UTC 2015.

The ipset `snort_ipfilter` has **8373** entries, **8373** unique IPs.

The following table shows the overlaps of `snort_ipfilter` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `snort_ipfilter`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `snort_ipfilter`.
- ` this % ` is the percentage **of this ipset (`snort_ipfilter`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level3](#firehol_level3)|108767|9626344|8373|0.0%|100.0%|
[firehol_anonymous](#firehol_anonymous)|19320|83371|1246|1.4%|14.8%|
[tor_exits](#tor_exits)|1106|1106|1090|98.5%|13.0%|
[et_tor](#et_tor)|6500|6500|1088|16.7%|12.9%|
[bm_tor](#bm_tor)|6533|6533|1074|16.4%|12.8%|
[dm_tor](#dm_tor)|6559|6559|1069|16.2%|12.7%|
[stopforumspam_30d](#stopforumspam_30d)|94236|94236|818|0.8%|9.7%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|660|2.2%|7.8%|
[firehol_level2](#firehol_level2)|22948|34548|565|1.6%|6.7%|
[sorbs_spam](#sorbs_spam)|64701|65536|457|0.6%|5.4%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|455|0.6%|5.4%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|455|0.6%|5.4%|
[stopforumspam_1d](#stopforumspam_1d)|6864|6864|381|5.5%|4.5%|
[firehol_proxies](#firehol_proxies)|12732|13012|329|2.5%|3.9%|
[et_block](#et_block)|1000|18343756|297|0.0%|3.5%|
[nixspam](#nixspam)|22540|22540|269|1.1%|3.2%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|237|45.2%|2.8%|
[firehol_level1](#firehol_level1)|5068|688775049|237|0.0%|2.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|234|0.0%|2.7%|
[blocklist_de](#blocklist_de)|29129|29129|215|0.7%|2.5%|
[zeus](#zeus)|230|230|200|86.9%|2.3%|
[zeus_badips](#zeus_badips)|202|202|178|88.1%|2.1%|
[blocklist_de_mail](#blocklist_de_mail)|18292|18292|164|0.8%|1.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|128|0.0%|1.5%|
[alienvault_reputation](#alienvault_reputation)|189217|189217|106|0.0%|1.2%|
[php_dictionary](#php_dictionary)|777|777|101|12.9%|1.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|99|0.0%|1.1%|
[php_spammers](#php_spammers)|777|777|90|11.5%|1.0%|
[php_commenters](#php_commenters)|458|458|69|15.0%|0.8%|
[ri_web_proxies](#ri_web_proxies)|8035|8035|64|0.7%|0.7%|
[sorbs_web](#sorbs_web)|667|668|56|8.3%|0.6%|
[iw_spamlist](#iw_spamlist)|3266|3266|55|1.6%|0.6%|
[xroxy](#xroxy)|2176|2176|42|1.9%|0.5%|
[blocklist_de_apache](#blocklist_de_apache)|14109|14109|33|0.2%|0.3%|
[sslbl](#sslbl)|368|368|31|8.4%|0.3%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2714|2714|31|1.1%|0.3%|
[proxz](#proxz)|1385|1385|29|2.0%|0.3%|
[openbl_60d](#openbl_60d)|6959|6959|23|0.3%|0.2%|
[blocklist_de_bots](#blocklist_de_bots)|3035|3035|20|0.6%|0.2%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|18|0.0%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|15|0.0%|0.1%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|12|0.9%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|11|0.0%|0.1%|
[dragon_http](#dragon_http)|1021|268288|11|0.0%|0.1%|
[php_harvesters](#php_harvesters)|408|408|10|2.4%|0.1%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|6|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2902|2902|6|0.2%|0.0%|
[sorbs_socks](#sorbs_socks)|7|7|2|28.5%|0.0%|
[sorbs_misc](#sorbs_misc)|7|7|2|28.5%|0.0%|
[sorbs_http](#sorbs_http)|7|7|2|28.5%|0.0%|
[shunlist](#shunlist)|1129|1129|2|0.1%|0.0%|
[proxyrss](#proxyrss)|1402|1402|2|0.1%|0.0%|
[openbl_30d](#openbl_30d)|2791|2791|2|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|2|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|168|168|2|1.1%|0.0%|
[openbl_7d](#openbl_7d)|638|638|1|0.1%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|1|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|1|0.1%|0.0%|
[dshield](#dshield)|20|5120|1|0.0%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|511|511|1|0.1%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|3535|3535|1|0.0%|0.0%|

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
[firehol_level3](#firehol_level3)|108767|9626344|3|0.0%|42.8%|
[snort_ipfilter](#snort_ipfilter)|8373|8373|2|0.0%|28.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|2|0.0%|28.5%|
[php_dictionary](#php_dictionary)|777|777|1|0.1%|14.2%|
[iw_spamlist](#iw_spamlist)|3266|3266|1|0.0%|14.2%|
[firehol_level2](#firehol_level2)|22948|34548|1|0.0%|14.2%|
[blocklist_de_mail](#blocklist_de_mail)|18292|18292|1|0.0%|14.2%|
[blocklist_de](#blocklist_de)|29129|29129|1|0.0%|14.2%|

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
[firehol_level3](#firehol_level3)|108767|9626344|3|0.0%|42.8%|
[snort_ipfilter](#snort_ipfilter)|8373|8373|2|0.0%|28.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|2|0.0%|28.5%|
[php_dictionary](#php_dictionary)|777|777|1|0.1%|14.2%|
[iw_spamlist](#iw_spamlist)|3266|3266|1|0.0%|14.2%|
[firehol_level2](#firehol_level2)|22948|34548|1|0.0%|14.2%|
[blocklist_de_mail](#blocklist_de_mail)|18292|18292|1|0.0%|14.2%|
[blocklist_de](#blocklist_de)|29129|29129|1|0.0%|14.2%|

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
[nixspam](#nixspam)|22540|22540|2260|10.0%|3.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|1736|0.0%|2.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|1205|0.0%|1.8%|
[firehol_level3](#firehol_level3)|108767|9626344|874|0.0%|1.3%|
[firehol_level2](#firehol_level2)|22948|34548|739|2.1%|1.1%|
[blocklist_de](#blocklist_de)|29129|29129|731|2.5%|1.1%|
[blocklist_de_mail](#blocklist_de_mail)|18292|18292|636|3.4%|0.9%|
[iw_spamlist](#iw_spamlist)|3266|3266|630|19.2%|0.9%|
[snort_ipfilter](#snort_ipfilter)|8373|8373|455|5.4%|0.6%|
[stopforumspam_30d](#stopforumspam_30d)|94236|94236|326|0.3%|0.4%|
[sorbs_web](#sorbs_web)|667|668|310|46.4%|0.4%|
[php_dictionary](#php_dictionary)|777|777|217|27.9%|0.3%|
[firehol_anonymous](#firehol_anonymous)|19320|83371|201|0.2%|0.3%|
[firehol_proxies](#firehol_proxies)|12732|13012|196|1.5%|0.3%|
[php_spammers](#php_spammers)|777|777|190|24.4%|0.2%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|173|0.5%|0.2%|
[ri_web_proxies](#ri_web_proxies)|8035|8035|145|1.8%|0.2%|
[alienvault_reputation](#alienvault_reputation)|189217|189217|91|0.0%|0.1%|
[xroxy](#xroxy)|2176|2176|76|3.4%|0.1%|
[dragon_http](#dragon_http)|1021|268288|71|0.0%|0.1%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2714|2714|48|1.7%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14109|14109|48|0.3%|0.0%|
[proxz](#proxz)|1385|1385|44|3.1%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6864|6864|38|0.5%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|37|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|3535|3535|32|0.9%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3035|3035|29|0.9%|0.0%|
[php_commenters](#php_commenters)|458|458|27|5.8%|0.0%|
[firehol_level1](#firehol_level1)|5068|688775049|25|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|20|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|20|0.0%|0.0%|
[et_block](#et_block)|1000|18343756|20|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2902|2902|18|0.6%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|17|0.0%|0.0%|
[php_harvesters](#php_harvesters)|408|408|16|3.9%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|1509|1509|15|0.9%|0.0%|
[sorbs_socks](#sorbs_socks)|7|7|7|100.0%|0.0%|
[sorbs_misc](#sorbs_misc)|7|7|7|100.0%|0.0%|
[sorbs_http](#sorbs_http)|7|7|7|100.0%|0.0%|
[sorbs_smtp](#sorbs_smtp)|6|6|6|100.0%|0.0%|
[tor_exits](#tor_exits)|1106|1106|5|0.4%|0.0%|
[proxyrss](#proxyrss)|1402|1402|4|0.2%|0.0%|
[et_tor](#et_tor)|6500|6500|4|0.0%|0.0%|
[dm_tor](#dm_tor)|6559|6559|4|0.0%|0.0%|
[bm_tor](#bm_tor)|6533|6533|4|0.0%|0.0%|
[voipbl](#voipbl)|10607|11019|3|0.0%|0.0%|
[et_compromised](#et_compromised)|1704|1704|3|0.1%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1700|1700|3|0.1%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3204|3204|3|0.0%|0.0%|
[openbl_60d](#openbl_60d)|6959|6959|2|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|2|0.1%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|168|168|2|1.1%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|1|0.1%|0.0%|
[malc0de](#malc0de)|238|238|1|0.4%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|1|0.1%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.0%|
[dragon_sshpauth](#dragon_sshpauth)|1568|1632|1|0.0%|0.0%|
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
[nixspam](#nixspam)|22540|22540|2260|10.0%|3.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|1736|0.0%|2.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|1205|0.0%|1.8%|
[firehol_level3](#firehol_level3)|108767|9626344|874|0.0%|1.3%|
[firehol_level2](#firehol_level2)|22948|34548|739|2.1%|1.1%|
[blocklist_de](#blocklist_de)|29129|29129|731|2.5%|1.1%|
[blocklist_de_mail](#blocklist_de_mail)|18292|18292|636|3.4%|0.9%|
[iw_spamlist](#iw_spamlist)|3266|3266|630|19.2%|0.9%|
[snort_ipfilter](#snort_ipfilter)|8373|8373|455|5.4%|0.6%|
[stopforumspam_30d](#stopforumspam_30d)|94236|94236|326|0.3%|0.4%|
[sorbs_web](#sorbs_web)|667|668|310|46.4%|0.4%|
[php_dictionary](#php_dictionary)|777|777|217|27.9%|0.3%|
[firehol_anonymous](#firehol_anonymous)|19320|83371|201|0.2%|0.3%|
[firehol_proxies](#firehol_proxies)|12732|13012|196|1.5%|0.3%|
[php_spammers](#php_spammers)|777|777|190|24.4%|0.2%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|173|0.5%|0.2%|
[ri_web_proxies](#ri_web_proxies)|8035|8035|145|1.8%|0.2%|
[alienvault_reputation](#alienvault_reputation)|189217|189217|91|0.0%|0.1%|
[xroxy](#xroxy)|2176|2176|76|3.4%|0.1%|
[dragon_http](#dragon_http)|1021|268288|71|0.0%|0.1%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2714|2714|48|1.7%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14109|14109|48|0.3%|0.0%|
[proxz](#proxz)|1385|1385|44|3.1%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6864|6864|38|0.5%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|37|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|3535|3535|32|0.9%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3035|3035|29|0.9%|0.0%|
[php_commenters](#php_commenters)|458|458|27|5.8%|0.0%|
[firehol_level1](#firehol_level1)|5068|688775049|25|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|20|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|20|0.0%|0.0%|
[et_block](#et_block)|1000|18343756|20|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2902|2902|18|0.6%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|17|0.0%|0.0%|
[php_harvesters](#php_harvesters)|408|408|16|3.9%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|1509|1509|15|0.9%|0.0%|
[sorbs_socks](#sorbs_socks)|7|7|7|100.0%|0.0%|
[sorbs_misc](#sorbs_misc)|7|7|7|100.0%|0.0%|
[sorbs_http](#sorbs_http)|7|7|7|100.0%|0.0%|
[sorbs_smtp](#sorbs_smtp)|6|6|6|100.0%|0.0%|
[tor_exits](#tor_exits)|1106|1106|5|0.4%|0.0%|
[proxyrss](#proxyrss)|1402|1402|4|0.2%|0.0%|
[et_tor](#et_tor)|6500|6500|4|0.0%|0.0%|
[dm_tor](#dm_tor)|6559|6559|4|0.0%|0.0%|
[bm_tor](#bm_tor)|6533|6533|4|0.0%|0.0%|
[voipbl](#voipbl)|10607|11019|3|0.0%|0.0%|
[et_compromised](#et_compromised)|1704|1704|3|0.1%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1700|1700|3|0.1%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3204|3204|3|0.0%|0.0%|
[openbl_60d](#openbl_60d)|6959|6959|2|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|2|0.1%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|168|168|2|1.1%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|1|0.1%|0.0%|
[malc0de](#malc0de)|238|238|1|0.4%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|1|0.1%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.0%|
[dragon_sshpauth](#dragon_sshpauth)|1568|1632|1|0.0%|0.0%|
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
[firehol_level3](#firehol_level3)|108767|9626344|3|0.0%|42.8%|
[snort_ipfilter](#snort_ipfilter)|8373|8373|2|0.0%|28.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|2|0.0%|28.5%|
[php_dictionary](#php_dictionary)|777|777|1|0.1%|14.2%|
[iw_spamlist](#iw_spamlist)|3266|3266|1|0.0%|14.2%|
[firehol_level2](#firehol_level2)|22948|34548|1|0.0%|14.2%|
[blocklist_de_mail](#blocklist_de_mail)|18292|18292|1|0.0%|14.2%|
[blocklist_de](#blocklist_de)|29129|29129|1|0.0%|14.2%|

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
[nixspam](#nixspam)|22540|22540|2280|10.1%|3.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|1740|0.0%|2.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|1208|0.0%|1.8%|
[firehol_level3](#firehol_level3)|108767|9626344|877|0.0%|1.3%|
[firehol_level2](#firehol_level2)|22948|34548|748|2.1%|1.1%|
[blocklist_de](#blocklist_de)|29129|29129|740|2.5%|1.1%|
[blocklist_de_mail](#blocklist_de_mail)|18292|18292|645|3.5%|0.9%|
[iw_spamlist](#iw_spamlist)|3266|3266|635|19.4%|0.9%|
[snort_ipfilter](#snort_ipfilter)|8373|8373|457|5.4%|0.6%|
[stopforumspam_30d](#stopforumspam_30d)|94236|94236|326|0.3%|0.4%|
[sorbs_web](#sorbs_web)|667|668|311|46.5%|0.4%|
[php_dictionary](#php_dictionary)|777|777|217|27.9%|0.3%|
[firehol_anonymous](#firehol_anonymous)|19320|83371|201|0.2%|0.3%|
[firehol_proxies](#firehol_proxies)|12732|13012|196|1.5%|0.2%|
[php_spammers](#php_spammers)|777|777|190|24.4%|0.2%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|173|0.5%|0.2%|
[ri_web_proxies](#ri_web_proxies)|8035|8035|145|1.8%|0.2%|
[alienvault_reputation](#alienvault_reputation)|189217|189217|91|0.0%|0.1%|
[xroxy](#xroxy)|2176|2176|76|3.4%|0.1%|
[dragon_http](#dragon_http)|1021|268288|72|0.0%|0.1%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2714|2714|48|1.7%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14109|14109|48|0.3%|0.0%|
[proxz](#proxz)|1385|1385|44|3.1%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6864|6864|38|0.5%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|38|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|3535|3535|33|0.9%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3035|3035|29|0.9%|0.0%|
[php_commenters](#php_commenters)|458|458|27|5.8%|0.0%|
[firehol_level1](#firehol_level1)|5068|688775049|25|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|20|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|20|0.0%|0.0%|
[et_block](#et_block)|1000|18343756|20|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2902|2902|18|0.6%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|17|0.0%|0.0%|
[php_harvesters](#php_harvesters)|408|408|16|3.9%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|1509|1509|15|0.9%|0.0%|
[sorbs_socks](#sorbs_socks)|7|7|7|100.0%|0.0%|
[sorbs_misc](#sorbs_misc)|7|7|7|100.0%|0.0%|
[sorbs_http](#sorbs_http)|7|7|7|100.0%|0.0%|
[tor_exits](#tor_exits)|1106|1106|5|0.4%|0.0%|
[sorbs_smtp](#sorbs_smtp)|6|6|5|83.3%|0.0%|
[proxyrss](#proxyrss)|1402|1402|4|0.2%|0.0%|
[et_tor](#et_tor)|6500|6500|4|0.0%|0.0%|
[dm_tor](#dm_tor)|6559|6559|4|0.0%|0.0%|
[bm_tor](#bm_tor)|6533|6533|4|0.0%|0.0%|
[voipbl](#voipbl)|10607|11019|3|0.0%|0.0%|
[et_compromised](#et_compromised)|1704|1704|3|0.1%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1700|1700|3|0.1%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3204|3204|3|0.0%|0.0%|
[openbl_60d](#openbl_60d)|6959|6959|2|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|2|0.1%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|168|168|2|1.1%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|1|0.1%|0.0%|
[malc0de](#malc0de)|238|238|1|0.4%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|1|0.1%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.0%|
[dragon_sshpauth](#dragon_sshpauth)|1568|1632|1|0.0%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|511|511|1|0.1%|0.0%|

## sorbs_web

[Sorbs.net](https://www.sorbs.net/) WEB exploits, extracted from deltas.

Source is downloaded from [this link]().

The last time downloaded was found to be dated: Fri Jun 12 16:04:06 UTC 2015.

The ipset `sorbs_web` has **667** entries, **668** unique IPs.

The following table shows the overlaps of `sorbs_web` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `sorbs_web`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `sorbs_web`.
- ` this % ` is the percentage **of this ipset (`sorbs_web`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[sorbs_spam](#sorbs_spam)|64701|65536|311|0.4%|46.5%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|310|0.4%|46.4%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|310|0.4%|46.4%|
[nixspam](#nixspam)|22540|22540|114|0.5%|17.0%|
[firehol_level2](#firehol_level2)|22948|34548|76|0.2%|11.3%|
[blocklist_de](#blocklist_de)|29129|29129|76|0.2%|11.3%|
[firehol_level3](#firehol_level3)|108767|9626344|73|0.0%|10.9%|
[blocklist_de_mail](#blocklist_de_mail)|18292|18292|68|0.3%|10.1%|
[snort_ipfilter](#snort_ipfilter)|8373|8373|56|0.6%|8.3%|
[stopforumspam_30d](#stopforumspam_30d)|94236|94236|49|0.0%|7.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|37|0.0%|5.5%|
[php_dictionary](#php_dictionary)|777|777|35|4.5%|5.2%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|32|0.1%|4.7%|
[firehol_proxies](#firehol_proxies)|12732|13012|31|0.2%|4.6%|
[firehol_anonymous](#firehol_anonymous)|19320|83371|31|0.0%|4.6%|
[php_spammers](#php_spammers)|777|777|28|3.6%|4.1%|
[iw_spamlist](#iw_spamlist)|3266|3266|28|0.8%|4.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|24|0.0%|3.5%|
[ri_web_proxies](#ri_web_proxies)|8035|8035|22|0.2%|3.2%|
[xroxy](#xroxy)|2176|2176|16|0.7%|2.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|16|0.0%|2.3%|
[proxz](#proxz)|1385|1385|8|0.5%|1.1%|
[blocklist_de_bots](#blocklist_de_bots)|3035|3035|7|0.2%|1.0%|
[stopforumspam_1d](#stopforumspam_1d)|6864|6864|5|0.0%|0.7%|
[php_commenters](#php_commenters)|458|458|4|0.8%|0.5%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|2|0.0%|0.2%|
[blocklist_de_strongips](#blocklist_de_strongips)|168|168|2|1.1%|0.2%|
[ri_connect_proxies](#ri_connect_proxies)|2902|2902|1|0.0%|0.1%|
[php_harvesters](#php_harvesters)|408|408|1|0.2%|0.1%|
[dragon_http](#dragon_http)|1021|268288|1|0.0%|0.1%|
[blocklist_de_imap](#blocklist_de_imap)|3535|3535|1|0.0%|0.1%|
[blocklist_de_ftp](#blocklist_de_ftp)|1509|1509|1|0.0%|0.1%|
[alienvault_reputation](#alienvault_reputation)|189217|189217|1|0.0%|0.1%|

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
[firehol_level1](#firehol_level1)|5068|688775049|18340608|2.6%|100.0%|
[et_block](#et_block)|1000|18343756|18338560|99.9%|99.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|8532506|2.4%|46.5%|
[firehol_level3](#firehol_level3)|108767|9626344|6933043|72.0%|37.8%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|6932480|75.5%|37.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|2272265|0.2%|12.3%|
[fullbogons](#fullbogons)|3788|670093640|151552|0.0%|0.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|130368|0.0%|0.7%|
[alienvault_reputation](#alienvault_reputation)|189217|189217|1385|0.7%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1037|0.3%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|94236|94236|1008|1.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|512|0.1%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|269|0.9%|0.0%|
[dshield](#dshield)|20|5120|256|5.0%|0.0%|
[dragon_http](#dragon_http)|1021|268288|256|0.0%|0.0%|
[openbl_60d](#openbl_60d)|6959|6959|235|3.3%|0.0%|
[firehol_level2](#firehol_level2)|22948|34548|232|0.6%|0.0%|
[blocklist_de](#blocklist_de)|29129|29129|168|0.5%|0.0%|
[openbl_30d](#openbl_30d)|2791|2791|119|4.2%|0.0%|
[dragon_sshpauth](#dragon_sshpauth)|1568|1632|99|6.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3204|3204|90|2.8%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6864|6864|86|1.2%|0.0%|
[shunlist](#shunlist)|1129|1129|86|7.6%|0.0%|
[et_compromised](#et_compromised)|1704|1704|65|3.8%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1700|1700|61|3.5%|0.0%|
[openbl_7d](#openbl_7d)|638|638|53|8.3%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3035|3035|49|1.6%|0.0%|
[php_commenters](#php_commenters)|458|458|29|6.3%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|29|2.2%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|18292|18292|24|0.1%|0.0%|
[sorbs_spam](#sorbs_spam)|64701|65536|20|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|20|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|20|0.0%|0.0%|
[nixspam](#nixspam)|22540|22540|19|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|8373|8373|18|0.2%|0.0%|
[zeus_badips](#zeus_badips)|202|202|15|7.4%|0.0%|
[zeus](#zeus)|230|230|15|6.5%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|3535|3535|15|0.4%|0.0%|
[voipbl](#voipbl)|10607|11019|14|0.1%|0.0%|
[openbl_1d](#openbl_1d)|155|155|9|5.8%|0.0%|
[php_dictionary](#php_dictionary)|777|777|6|0.7%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|6|0.4%|0.0%|
[firehol_anonymous](#firehol_anonymous)|19320|83371|6|0.0%|0.0%|
[php_spammers](#php_spammers)|777|777|5|0.6%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|5|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|168|168|5|2.9%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2714|2714|5|0.1%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14109|14109|5|0.0%|0.0%|
[nt_malware_http](#nt_malware_http)|69|69|4|5.7%|0.0%|
[iw_spamlist](#iw_spamlist)|3266|3266|4|0.1%|0.0%|
[nt_malware_irc](#nt_malware_irc)|43|43|3|6.9%|0.0%|
[firehol_proxies](#firehol_proxies)|12732|13012|3|0.0%|0.0%|
[et_tor](#et_tor)|6500|6500|3|0.0%|0.0%|
[dm_tor](#dm_tor)|6559|6559|3|0.0%|0.0%|
[bm_tor](#bm_tor)|6533|6533|3|0.0%|0.0%|
[tor_exits](#tor_exits)|1106|1106|2|0.1%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|2|0.3%|0.0%|
[virbl](#virbl)|15|15|1|6.6%|0.0%|
[sslbl](#sslbl)|368|368|1|0.2%|0.0%|
[php_harvesters](#php_harvesters)|408|408|1|0.2%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|1|0.1%|0.0%|
[malc0de](#malc0de)|238|238|1|0.4%|0.0%|
[et_botcc](#et_botcc)|505|505|1|0.1%|0.0%|
[dragon_vncprobe](#dragon_vncprobe)|85|85|1|1.1%|0.0%|

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
[firehol_level1](#firehol_level1)|5068|688775049|487424|0.0%|100.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|270785|0.1%|55.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|98904|0.0%|20.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|33155|0.0%|6.8%|
[et_block](#et_block)|1000|18343756|517|0.0%|0.1%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|512|0.0%|0.1%|
[firehol_level3](#firehol_level3)|108767|9626344|82|0.0%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|94236|94236|73|0.0%|0.0%|
[sorbs_spam](#sorbs_spam)|64701|65536|20|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|20|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|20|0.0%|0.0%|
[alienvault_reputation](#alienvault_reputation)|189217|189217|14|0.0%|0.0%|
[php_commenters](#php_commenters)|458|458|8|1.7%|0.0%|
[firehol_level2](#firehol_level2)|22948|34548|8|0.0%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|7|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|8373|8373|6|0.0%|0.0%|
[blocklist_de](#blocklist_de)|29129|29129|6|0.0%|0.0%|
[zeus_badips](#zeus_badips)|202|202|5|2.4%|0.0%|
[zeus](#zeus)|230|230|5|2.1%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6864|6864|4|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|18292|18292|3|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3035|3035|3|0.0%|0.0%|
[nixspam](#nixspam)|22540|22540|2|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|168|168|2|1.1%|0.0%|
[php_harvesters](#php_harvesters)|408|408|1|0.2%|0.0%|
[openbl_60d](#openbl_60d)|6959|6959|1|0.0%|0.0%|
[openbl_30d](#openbl_30d)|2791|2791|1|0.0%|0.0%|
[malc0de](#malc0de)|238|238|1|0.4%|0.0%|
[iw_spamlist](#iw_spamlist)|3266|3266|1|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|3535|3535|1|0.0%|0.0%|

## sslbl

[Abuse.ch SSL Blacklist](https://sslbl.abuse.ch/) bad SSL traffic related to malware or botnet activities - **excellent list**

Source is downloaded from [this link](https://sslbl.abuse.ch/blacklist/sslipblacklist.csv).

The last time downloaded was found to be dated: Fri Jun 12 16:00:05 UTC 2015.

The ipset `sslbl` has **368** entries, **368** unique IPs.

The following table shows the overlaps of `sslbl` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `sslbl`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `sslbl`.
- ` this % ` is the percentage **of this ipset (`sslbl`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level1](#firehol_level1)|5068|688775049|368|0.0%|100.0%|
[firehol_level3](#firehol_level3)|108767|9626344|89|0.0%|24.1%|
[alienvault_reputation](#alienvault_reputation)|189217|189217|65|0.0%|17.6%|
[shunlist](#shunlist)|1129|1129|58|5.1%|15.7%|
[et_block](#et_block)|1000|18343756|38|0.0%|10.3%|
[snort_ipfilter](#snort_ipfilter)|8373|8373|31|0.3%|8.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|28|0.0%|7.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|6|0.0%|1.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|3|0.0%|0.8%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|1|0.0%|0.2%|
[ri_web_proxies](#ri_web_proxies)|8035|8035|1|0.0%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.2%|
[firehol_proxies](#firehol_proxies)|12732|13012|1|0.0%|0.2%|
[firehol_anonymous](#firehol_anonymous)|19320|83371|1|0.0%|0.2%|
[dragon_sshpauth](#dragon_sshpauth)|1568|1632|1|0.0%|0.2%|
[dragon_http](#dragon_http)|1021|268288|1|0.0%|0.2%|

## stopforumspam_1d

[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers in the last 24 hours - **excellent list**

Source is downloaded from [this link](http://www.stopforumspam.com/downloads/listed_ip_1.zip).

The last time downloaded was found to be dated: Fri Jun 12 16:00:01 UTC 2015.

The ipset `stopforumspam_1d` has **6864** entries, **6864** unique IPs.

The following table shows the overlaps of `stopforumspam_1d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `stopforumspam_1d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `stopforumspam_1d`.
- ` this % ` is the percentage **of this ipset (`stopforumspam_1d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|22948|34548|6864|19.8%|100.0%|
[firehol_level3](#firehol_level3)|108767|9626344|6330|0.0%|92.2%|
[stopforumspam_30d](#stopforumspam_30d)|94236|94236|6319|6.7%|92.0%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|4877|16.8%|71.0%|
[blocklist_de](#blocklist_de)|29129|29129|1475|5.0%|21.4%|
[blocklist_de_bots](#blocklist_de_bots)|3035|3035|1406|46.3%|20.4%|
[firehol_anonymous](#firehol_anonymous)|19320|83371|955|1.1%|13.9%|
[firehol_proxies](#firehol_proxies)|12732|13012|790|6.0%|11.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|518|0.0%|7.5%|
[ri_web_proxies](#ri_web_proxies)|8035|8035|412|5.1%|6.0%|
[snort_ipfilter](#snort_ipfilter)|8373|8373|381|4.5%|5.5%|
[tor_exits](#tor_exits)|1106|1106|350|31.6%|5.0%|
[bm_tor](#bm_tor)|6533|6533|342|5.2%|4.9%|
[et_tor](#et_tor)|6500|6500|341|5.2%|4.9%|
[dm_tor](#dm_tor)|6559|6559|341|5.1%|4.9%|
[proxyrss](#proxyrss)|1402|1402|288|20.5%|4.1%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|206|39.3%|3.0%|
[xroxy](#xroxy)|2176|2176|198|9.0%|2.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|178|0.0%|2.5%|
[proxz](#proxz)|1385|1385|172|12.4%|2.5%|
[php_commenters](#php_commenters)|458|458|159|34.7%|2.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|132|0.0%|1.9%|
[ri_connect_proxies](#ri_connect_proxies)|2902|2902|109|3.7%|1.5%|
[firehol_level1](#firehol_level1)|5068|688775049|101|0.0%|1.4%|
[blocklist_de_strongips](#blocklist_de_strongips)|168|168|97|57.7%|1.4%|
[et_block](#et_block)|1000|18343756|96|0.0%|1.3%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|86|0.0%|1.2%|
[blocklist_de_apache](#blocklist_de_apache)|14109|14109|65|0.4%|0.9%|
[nixspam](#nixspam)|22540|22540|53|0.2%|0.7%|
[alienvault_reputation](#alienvault_reputation)|189217|189217|46|0.0%|0.6%|
[php_spammers](#php_spammers)|777|777|40|5.1%|0.5%|
[php_harvesters](#php_harvesters)|408|408|40|9.8%|0.5%|
[sorbs_spam](#sorbs_spam)|64701|65536|38|0.0%|0.5%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|38|0.0%|0.5%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|38|0.0%|0.5%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|38|0.0%|0.5%|
[blocklist_de_mail](#blocklist_de_mail)|18292|18292|38|0.2%|0.5%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2714|2714|33|1.2%|0.4%|
[php_dictionary](#php_dictionary)|777|777|27|3.4%|0.3%|
[openbl_60d](#openbl_60d)|6959|6959|20|0.2%|0.2%|
[dshield](#dshield)|20|5120|11|0.2%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|9|0.0%|0.1%|
[dragon_http](#dragon_http)|1021|268288|7|0.0%|0.1%|
[sorbs_web](#sorbs_web)|667|668|5|0.7%|0.0%|
[voipbl](#voipbl)|10607|11019|4|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|4|0.0%|0.0%|
[iw_spamlist](#iw_spamlist)|3266|3266|4|0.1%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|4|0.6%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|3535|3535|3|0.0%|0.0%|
[shunlist](#shunlist)|1129|1129|2|0.1%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|2|0.0%|0.0%|
[et_compromised](#et_compromised)|1704|1704|2|0.1%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1700|1700|2|0.1%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3204|3204|2|0.0%|0.0%|
[zeus_badips](#zeus_badips)|202|202|1|0.4%|0.0%|
[zeus](#zeus)|230|230|1|0.4%|0.0%|
[openbl_30d](#openbl_30d)|2791|2791|1|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|1|0.0%|0.0%|
[fullbogons](#fullbogons)|3788|670093640|1|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|1509|1509|1|0.0%|0.0%|

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
[firehol_level3](#firehol_level3)|108767|9626344|94236|0.9%|100.0%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|29017|100.0%|30.7%|
[firehol_level2](#firehol_level2)|22948|34548|7725|22.3%|8.1%|
[stopforumspam_1d](#stopforumspam_1d)|6864|6864|6319|92.0%|6.7%|
[firehol_anonymous](#firehol_anonymous)|19320|83371|6281|7.5%|6.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|5843|0.0%|6.2%|
[firehol_proxies](#firehol_proxies)|12732|13012|5671|43.5%|6.0%|
[ri_web_proxies](#ri_web_proxies)|8035|8035|3751|46.6%|3.9%|
[blocklist_de](#blocklist_de)|29129|29129|2843|9.7%|3.0%|
[blocklist_de_bots](#blocklist_de_bots)|3035|3035|2491|82.0%|2.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|2463|0.0%|2.6%|
[ri_connect_proxies](#ri_connect_proxies)|2902|2902|1607|55.3%|1.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|1526|0.0%|1.6%|
[xroxy](#xroxy)|2176|2176|1285|59.0%|1.3%|
[firehol_level1](#firehol_level1)|5068|688775049|1102|0.0%|1.1%|
[et_block](#et_block)|1000|18343756|1026|0.0%|1.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|1008|0.0%|1.0%|
[snort_ipfilter](#snort_ipfilter)|8373|8373|818|9.7%|0.8%|
[proxz](#proxz)|1385|1385|818|59.0%|0.8%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|724|0.0%|0.7%|
[et_tor](#et_tor)|6500|6500|662|10.1%|0.7%|
[proxyrss](#proxyrss)|1402|1402|651|46.4%|0.6%|
[dm_tor](#dm_tor)|6559|6559|645|9.8%|0.6%|
[bm_tor](#bm_tor)|6533|6533|643|9.8%|0.6%|
[tor_exits](#tor_exits)|1106|1106|631|57.0%|0.6%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|346|66.0%|0.3%|
[php_commenters](#php_commenters)|458|458|336|73.3%|0.3%|
[sorbs_spam](#sorbs_spam)|64701|65536|326|0.4%|0.3%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|326|0.4%|0.3%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|326|0.4%|0.3%|
[blocklist_de_mail](#blocklist_de_mail)|18292|18292|252|1.3%|0.2%|
[nixspam](#nixspam)|22540|22540|231|1.0%|0.2%|
[blocklist_de_apache](#blocklist_de_apache)|14109|14109|202|1.4%|0.2%|
[alienvault_reputation](#alienvault_reputation)|189217|189217|166|0.0%|0.1%|
[php_spammers](#php_spammers)|777|777|155|19.9%|0.1%|
[php_dictionary](#php_dictionary)|777|777|142|18.2%|0.1%|
[blocklist_de_strongips](#blocklist_de_strongips)|168|168|131|77.9%|0.1%|
[dragon_http](#dragon_http)|1021|268288|110|0.0%|0.1%|
[php_harvesters](#php_harvesters)|408|408|87|21.3%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|73|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2714|2714|71|2.6%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|52|0.0%|0.0%|
[sorbs_web](#sorbs_web)|667|668|49|7.3%|0.0%|
[openbl_60d](#openbl_60d)|6959|6959|47|0.6%|0.0%|
[voipbl](#voipbl)|10607|11019|35|0.3%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3204|3204|24|0.7%|0.0%|
[iw_spamlist](#iw_spamlist)|3266|3266|22|0.6%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|20|3.0%|0.0%|
[dshield](#dshield)|20|5120|20|0.3%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|3535|3535|20|0.5%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|16|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|1509|1509|12|0.7%|0.0%|
[et_compromised](#et_compromised)|1704|1704|10|0.5%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1700|1700|9|0.5%|0.0%|
[shunlist](#shunlist)|1129|1129|5|0.4%|0.0%|
[openbl_30d](#openbl_30d)|2791|2791|5|0.1%|0.0%|
[dragon_sshpauth](#dragon_sshpauth)|1568|1632|4|0.2%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|3|0.2%|0.0%|
[fullbogons](#fullbogons)|3788|670093640|3|0.0%|0.0%|
[zeus_badips](#zeus_badips)|202|202|2|0.9%|0.0%|
[zeus](#zeus)|230|230|2|0.8%|0.0%|
[openbl_7d](#openbl_7d)|638|638|2|0.3%|0.0%|
[nt_malware_http](#nt_malware_http)|69|69|2|2.8%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|2|0.1%|0.0%|
[ciarmy](#ciarmy)|428|428|2|0.4%|0.0%|
[openbl_1d](#openbl_1d)|155|155|1|0.6%|0.0%|
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
[firehol_level3](#firehol_level3)|108767|9626344|29017|0.3%|100.0%|
[firehol_level2](#firehol_level2)|22948|34548|5917|17.1%|20.3%|
[stopforumspam_1d](#stopforumspam_1d)|6864|6864|4877|71.0%|16.8%|
[firehol_anonymous](#firehol_anonymous)|19320|83371|2710|3.2%|9.3%|
[firehol_proxies](#firehol_proxies)|12732|13012|2350|18.0%|8.0%|
[blocklist_de](#blocklist_de)|29129|29129|2310|7.9%|7.9%|
[blocklist_de_bots](#blocklist_de_bots)|3035|3035|2127|70.0%|7.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|1961|0.0%|6.7%|
[ri_web_proxies](#ri_web_proxies)|8035|8035|1494|18.5%|5.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|736|0.0%|2.5%|
[snort_ipfilter](#snort_ipfilter)|8373|8373|660|7.8%|2.2%|
[xroxy](#xroxy)|2176|2176|586|26.9%|2.0%|
[et_tor](#et_tor)|6500|6500|547|8.4%|1.8%|
[ri_connect_proxies](#ri_connect_proxies)|2902|2902|538|18.5%|1.8%|
[tor_exits](#tor_exits)|1106|1106|535|48.3%|1.8%|
[dm_tor](#dm_tor)|6559|6559|528|8.0%|1.8%|
[bm_tor](#bm_tor)|6533|6533|527|8.0%|1.8%|
[proxz](#proxz)|1385|1385|521|37.6%|1.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|510|0.0%|1.7%|
[proxyrss](#proxyrss)|1402|1402|500|35.6%|1.7%|
[firehol_level1](#firehol_level1)|5068|688775049|291|0.0%|1.0%|
[et_block](#et_block)|1000|18343756|283|0.0%|0.9%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|277|52.8%|0.9%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|269|0.0%|0.9%|
[php_commenters](#php_commenters)|458|458|248|54.1%|0.8%|
[sorbs_spam](#sorbs_spam)|64701|65536|173|0.2%|0.5%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|173|0.2%|0.5%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|173|0.2%|0.5%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|154|0.0%|0.5%|
[blocklist_de_mail](#blocklist_de_mail)|18292|18292|134|0.7%|0.4%|
[nixspam](#nixspam)|22540|22540|128|0.5%|0.4%|
[blocklist_de_apache](#blocklist_de_apache)|14109|14109|120|0.8%|0.4%|
[blocklist_de_strongips](#blocklist_de_strongips)|168|168|116|69.0%|0.3%|
[php_spammers](#php_spammers)|777|777|96|12.3%|0.3%|
[php_dictionary](#php_dictionary)|777|777|95|12.2%|0.3%|
[alienvault_reputation](#alienvault_reputation)|189217|189217|88|0.0%|0.3%|
[php_harvesters](#php_harvesters)|408|408|65|15.9%|0.2%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2714|2714|50|1.8%|0.1%|
[sorbs_web](#sorbs_web)|667|668|32|4.7%|0.1%|
[dragon_http](#dragon_http)|1021|268288|32|0.0%|0.1%|
[openbl_60d](#openbl_60d)|6959|6959|26|0.3%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|21|0.0%|0.0%|
[voipbl](#voipbl)|10607|11019|15|0.1%|0.0%|
[dshield](#dshield)|20|5120|15|0.2%|0.0%|
[iw_spamlist](#iw_spamlist)|3266|3266|13|0.3%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|10|1.5%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|3535|3535|8|0.2%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|7|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|7|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3204|3204|6|0.1%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|1509|1509|6|0.3%|0.0%|
[shunlist](#shunlist)|1129|1129|3|0.2%|0.0%|
[et_compromised](#et_compromised)|1704|1704|3|0.1%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1700|1700|3|0.1%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|2|0.1%|0.0%|
[fullbogons](#fullbogons)|3788|670093640|2|0.0%|0.0%|
[zeus_badips](#zeus_badips)|202|202|1|0.4%|0.0%|
[zeus](#zeus)|230|230|1|0.4%|0.0%|
[openbl_30d](#openbl_30d)|2791|2791|1|0.0%|0.0%|
[ciarmy](#ciarmy)|428|428|1|0.2%|0.0%|

## tor_exits

[TorProject.org](https://www.torproject.org) list of all current TOR exit points (TorDNSEL)

Source is downloaded from [this link](https://check.torproject.org/exit-addresses).

The last time downloaded was found to be dated: Fri Jun 12 15:02:18 UTC 2015.

The ipset `tor_exits` has **1106** entries, **1106** unique IPs.

The following table shows the overlaps of `tor_exits` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `tor_exits`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `tor_exits`.
- ` this % ` is the percentage **of this ipset (`tor_exits`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_anonymous](#firehol_anonymous)|19320|83371|1106|1.3%|100.0%|
[firehol_level3](#firehol_level3)|108767|9626344|1092|0.0%|98.7%|
[snort_ipfilter](#snort_ipfilter)|8373|8373|1090|13.0%|98.5%|
[bm_tor](#bm_tor)|6533|6533|1028|15.7%|92.9%|
[dm_tor](#dm_tor)|6559|6559|1022|15.5%|92.4%|
[et_tor](#et_tor)|6500|6500|966|14.8%|87.3%|
[stopforumspam_30d](#stopforumspam_30d)|94236|94236|631|0.6%|57.0%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|535|1.8%|48.3%|
[firehol_level2](#firehol_level2)|22948|34548|356|1.0%|32.1%|
[stopforumspam_1d](#stopforumspam_1d)|6864|6864|350|5.0%|31.6%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|230|43.8%|20.7%|
[firehol_proxies](#firehol_proxies)|12732|13012|230|1.7%|20.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|126|0.0%|11.3%|
[php_commenters](#php_commenters)|458|458|54|11.7%|4.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|40|0.0%|3.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|36|0.0%|3.2%|
[alienvault_reputation](#alienvault_reputation)|189217|189217|30|0.0%|2.7%|
[openbl_60d](#openbl_60d)|6959|6959|20|0.2%|1.8%|
[blocklist_de_apache](#blocklist_de_apache)|14109|14109|15|0.1%|1.3%|
[blocklist_de](#blocklist_de)|29129|29129|15|0.0%|1.3%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2714|2714|13|0.4%|1.1%|
[nixspam](#nixspam)|22540|22540|8|0.0%|0.7%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|8|0.0%|0.7%|
[php_harvesters](#php_harvesters)|408|408|6|1.4%|0.5%|
[sorbs_spam](#sorbs_spam)|64701|65536|5|0.0%|0.4%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|5|0.0%|0.4%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|5|0.0%|0.4%|
[php_spammers](#php_spammers)|777|777|5|0.6%|0.4%|
[dragon_http](#dragon_http)|1021|268288|5|0.0%|0.4%|
[php_dictionary](#php_dictionary)|777|777|4|0.5%|0.3%|
[firehol_level1](#firehol_level1)|5068|688775049|3|0.0%|0.2%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|2|0.0%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2|0.0%|0.1%|
[et_block](#et_block)|1000|18343756|2|0.0%|0.1%|
[blocklist_de_mail](#blocklist_de_mail)|18292|18292|2|0.0%|0.1%|
[shunlist](#shunlist)|1129|1129|1|0.0%|0.0%|
[dshield](#dshield)|20|5120|1|0.0%|0.0%|

## virbl

[VirBL](http://virbl.bit.nl/) is a project of which the idea was born during the RIPE-48 meeting. The plan was to get reports of virusscanning mailservers, and put the IP-addresses that were reported to send viruses on a blacklist.

Source is downloaded from [this link](http://virbl.bit.nl/download/virbl.dnsbl.bit.nl.txt).

The last time downloaded was found to be dated: Fri Jun 12 15:42:03 UTC 2015.

The ipset `virbl` has **15** entries, **15** unique IPs.

The following table shows the overlaps of `virbl` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `virbl`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `virbl`.
- ` this % ` is the percentage **of this ipset (`virbl`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level3](#firehol_level3)|108767|9626344|15|0.0%|100.0%|
[firehol_level2](#firehol_level2)|22948|34548|2|0.0%|13.3%|
[blocklist_de_mail](#blocklist_de_mail)|18292|18292|2|0.0%|13.3%|
[blocklist_de](#blocklist_de)|29129|29129|2|0.0%|13.3%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|1|0.0%|6.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|1|0.0%|6.6%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|6.6%|
[firehol_level1](#firehol_level1)|5068|688775049|1|0.0%|6.6%|
[et_block](#et_block)|1000|18343756|1|0.0%|6.6%|
[blocklist_de_imap](#blocklist_de_imap)|3535|3535|1|0.0%|6.6%|

## voipbl

[VoIPBL.org](http://www.voipbl.org/) a distributed VoIP blacklist that is aimed to protects against VoIP Fraud and minimizing abuse for network that have publicly accessible PBX's. Several algorithms, external sources and manual confirmation are used before they categorize something as an attack and determine the threat level.

Source is downloaded from [this link](http://www.voipbl.org/update/).

The last time downloaded was found to be dated: Fri Jun 12 16:10:11 UTC 2015.

The ipset `voipbl` has **10607** entries, **11019** unique IPs.

The following table shows the overlaps of `voipbl` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `voipbl`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `voipbl`.
- ` this % ` is the percentage **of this ipset (`voipbl`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|1616|0.0%|14.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|437|0.0%|3.9%|
[firehol_level1](#firehol_level1)|5068|688775049|333|0.0%|3.0%|
[fullbogons](#fullbogons)|3788|670093640|319|0.0%|2.8%|
[bogons](#bogons)|13|592708608|319|0.0%|2.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|302|0.0%|2.7%|
[alienvault_reputation](#alienvault_reputation)|189217|189217|176|0.0%|1.5%|
[firehol_anonymous](#firehol_anonymous)|19320|83371|79|0.0%|0.7%|
[firehol_level3](#firehol_level3)|108767|9626344|57|0.0%|0.5%|
[firehol_level2](#firehol_level2)|22948|34548|42|0.1%|0.3%|
[blocklist_de](#blocklist_de)|29129|29129|39|0.1%|0.3%|
[stopforumspam_30d](#stopforumspam_30d)|94236|94236|35|0.0%|0.3%|
[blocklist_de_sip](#blocklist_de_sip)|80|80|32|40.0%|0.2%|
[dragon_http](#dragon_http)|1021|268288|29|0.0%|0.2%|
[et_block](#et_block)|1000|18343756|18|0.0%|0.1%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|15|0.0%|0.1%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|14|0.0%|0.1%|
[shunlist](#shunlist)|1129|1129|13|1.1%|0.1%|
[openbl_60d](#openbl_60d)|6959|6959|8|0.1%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6864|6864|4|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|4|0.0%|0.0%|
[sorbs_spam](#sorbs_spam)|64701|65536|3|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|3|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|3|0.0%|0.0%|
[openbl_30d](#openbl_30d)|2791|2791|3|0.1%|0.0%|
[et_tor](#et_tor)|6500|6500|3|0.0%|0.0%|
[et_compromised](#et_compromised)|1704|1704|3|0.1%|0.0%|
[dm_tor](#dm_tor)|6559|6559|3|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1700|1700|3|0.1%|0.0%|
[bm_tor](#bm_tor)|6533|6533|3|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3204|3204|3|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|2|0.3%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|2|0.0%|0.0%|
[firehol_proxies](#firehol_proxies)|12732|13012|2|0.0%|0.0%|
[ciarmy](#ciarmy)|428|428|2|0.4%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|18292|18292|2|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14109|14109|2|0.0%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.0%|
[dragon_vncprobe](#dragon_vncprobe)|85|85|1|1.1%|0.0%|
[dragon_sshpauth](#dragon_sshpauth)|1568|1632|1|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|3535|3535|1|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3035|3035|1|0.0%|0.0%|

## xroxy

[xroxy.com](http://www.xroxy.com) open proxies (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.xroxy.com/proxyrss.xml).

The last time downloaded was found to be dated: Fri Jun 12 15:33:01 UTC 2015.

The ipset `xroxy` has **2176** entries, **2176** unique IPs.

The following table shows the overlaps of `xroxy` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `xroxy`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `xroxy`.
- ` this % ` is the percentage **of this ipset (`xroxy`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_proxies](#firehol_proxies)|12732|13012|2176|16.7%|100.0%|
[firehol_anonymous](#firehol_anonymous)|19320|83371|2176|2.6%|100.0%|
[firehol_level3](#firehol_level3)|108767|9626344|1300|0.0%|59.7%|
[stopforumspam_30d](#stopforumspam_30d)|94236|94236|1285|1.3%|59.0%|
[ri_web_proxies](#ri_web_proxies)|8035|8035|966|12.0%|44.3%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|586|2.0%|26.9%|
[proxz](#proxz)|1385|1385|475|34.2%|21.8%|
[ri_connect_proxies](#ri_connect_proxies)|2902|2902|397|13.6%|18.2%|
[proxyrss](#proxyrss)|1402|1402|356|25.3%|16.3%|
[firehol_level2](#firehol_level2)|22948|34548|310|0.8%|14.2%|
[blocklist_de](#blocklist_de)|29129|29129|235|0.8%|10.7%|
[stopforumspam_1d](#stopforumspam_1d)|6864|6864|198|2.8%|9.0%|
[blocklist_de_bots](#blocklist_de_bots)|3035|3035|182|5.9%|8.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|112|0.0%|5.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|104|0.0%|4.7%|
[sorbs_spam](#sorbs_spam)|64701|65536|76|0.1%|3.4%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|76|0.1%|3.4%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|76|0.1%|3.4%|
[nixspam](#nixspam)|22540|22540|58|0.2%|2.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|58|0.0%|2.6%|
[blocklist_de_mail](#blocklist_de_mail)|18292|18292|52|0.2%|2.3%|
[snort_ipfilter](#snort_ipfilter)|8373|8373|42|0.5%|1.9%|
[php_dictionary](#php_dictionary)|777|777|42|5.4%|1.9%|
[php_spammers](#php_spammers)|777|777|35|4.5%|1.6%|
[sorbs_web](#sorbs_web)|667|668|16|2.3%|0.7%|
[php_commenters](#php_commenters)|458|458|13|2.8%|0.5%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|13|1.9%|0.5%|
[blocklist_de_strongips](#blocklist_de_strongips)|168|168|7|4.1%|0.3%|
[dragon_http](#dragon_http)|1021|268288|6|0.0%|0.2%|
[alienvault_reputation](#alienvault_reputation)|189217|189217|5|0.0%|0.2%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|3|0.5%|0.1%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|3|0.0%|0.1%|
[php_harvesters](#php_harvesters)|408|408|2|0.4%|0.0%|
[et_tor](#et_tor)|6500|6500|2|0.0%|0.0%|
[dm_tor](#dm_tor)|6559|6559|2|0.0%|0.0%|
[bm_tor](#bm_tor)|6533|6533|2|0.0%|0.0%|
[iw_spamlist](#iw_spamlist)|3266|3266|1|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.0%|
[et_compromised](#et_compromised)|1704|1704|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1700|1700|1|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2714|2714|1|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14109|14109|1|0.0%|0.0%|

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
[firehol_level1](#firehol_level1)|5068|688775049|230|0.0%|100.0%|
[et_block](#et_block)|1000|18343756|229|0.0%|99.5%|
[firehol_level3](#firehol_level3)|108767|9626344|203|0.0%|88.2%|
[zeus_badips](#zeus_badips)|202|202|202|100.0%|87.8%|
[snort_ipfilter](#snort_ipfilter)|8373|8373|200|2.3%|86.9%|
[alienvault_reputation](#alienvault_reputation)|189217|189217|61|0.0%|26.5%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|15|0.0%|6.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|14|0.0%|6.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|10|0.0%|4.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|9|0.0%|3.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|7|0.0%|3.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|5|0.0%|2.1%|
[dragon_http](#dragon_http)|1021|268288|3|0.0%|1.3%|
[stopforumspam_30d](#stopforumspam_30d)|94236|94236|2|0.0%|0.8%|
[openbl_60d](#openbl_60d)|6959|6959|2|0.0%|0.8%|
[openbl_30d](#openbl_30d)|2791|2791|2|0.0%|0.8%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|1|0.0%|0.4%|
[stopforumspam_1d](#stopforumspam_1d)|6864|6864|1|0.0%|0.4%|
[php_commenters](#php_commenters)|458|458|1|0.2%|0.4%|
[openbl_7d](#openbl_7d)|638|638|1|0.1%|0.4%|
[nixspam](#nixspam)|22540|22540|1|0.0%|0.4%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|1|0.0%|0.4%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.4%|
[firehol_level2](#firehol_level2)|22948|34548|1|0.0%|0.4%|

## zeus_badips

[Abuse.ch Zeus tracker](https://zeustracker.abuse.ch) badips includes IPv4 addresses that are used by the ZeuS trojan. It is the recommened blocklist if you want to block only ZeuS IPs. It excludes IP addresses that ZeuS Tracker believes to be hijacked (level 2) or belong to a free web hosting provider (level 3). Hence the false postive rate should be much lower compared to the standard ZeuS IP blocklist. **excellent list**

Source is downloaded from [this link](https://zeustracker.abuse.ch/blocklist.php?download=badips).

The last time downloaded was found to be dated: Fri Jun 12 15:54:13 UTC 2015.

The ipset `zeus_badips` has **202** entries, **202** unique IPs.

The following table shows the overlaps of `zeus_badips` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `zeus_badips`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `zeus_badips`.
- ` this % ` is the percentage **of this ipset (`zeus_badips`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[zeus](#zeus)|230|230|202|87.8%|100.0%|
[firehol_level1](#firehol_level1)|5068|688775049|202|0.0%|100.0%|
[et_block](#et_block)|1000|18343756|202|0.0%|100.0%|
[firehol_level3](#firehol_level3)|108767|9626344|180|0.0%|89.1%|
[snort_ipfilter](#snort_ipfilter)|8373|8373|178|2.1%|88.1%|
[alienvault_reputation](#alienvault_reputation)|189217|189217|37|0.0%|18.3%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|15|0.0%|7.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|10|0.0%|4.9%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|10|0.0%|4.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|8|0.0%|3.9%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|5|0.0%|2.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|4|0.0%|1.9%|
[dragon_http](#dragon_http)|1021|268288|3|0.0%|1.4%|
[stopforumspam_30d](#stopforumspam_30d)|94236|94236|2|0.0%|0.9%|
[stopforumspam_7d](#stopforumspam_7d)|29017|29017|1|0.0%|0.4%|
[stopforumspam_1d](#stopforumspam_1d)|6864|6864|1|0.0%|0.4%|
[php_commenters](#php_commenters)|458|458|1|0.2%|0.4%|
[openbl_7d](#openbl_7d)|638|638|1|0.1%|0.4%|
[openbl_60d](#openbl_60d)|6959|6959|1|0.0%|0.4%|
[openbl_30d](#openbl_30d)|2791|2791|1|0.0%|0.4%|
[nixspam](#nixspam)|22540|22540|1|0.0%|0.4%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.4%|
[firehol_level2](#firehol_level2)|22948|34548|1|0.0%|0.4%|
