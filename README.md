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

The following list was automatically generated on Thu Jun 11 22:37:16 UTC 2015.

The update frequency is the maximum allowed by internal configuration. A list will never be downloaded sooner than the update frequency stated. A list may also not be downloaded, after this frequency expired, if it has not been modified on the server (as reported by HTTP `IF_MODIFIED_SINCE` method).

name|info|type|entries|update|
:--:|:--:|:--:|:-----:|:----:|
[alienvault_reputation](#alienvault_reputation)|[AlienVault.com](https://www.alienvault.com/) IP reputation database (this list seems to include port scanning hosts and to be updated regularly, but we found no information about its retention policy)|ipv4 hash:ip|187341 unique IPs|updated every 6 hours  from [this link](https://reputation.alienvault.com/reputation.generic)
[blocklist_de](#blocklist_de)|[Blocklist.de](https://www.blocklist.de/) IPs that have been detected by fail2ban in the last 48 hours - **excellent list**|ipv4 hash:ip|28426 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/all.txt)
[blocklist_de_apache](#blocklist_de_apache)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service Apache, Apache-DDOS, RFI-Attacks.|ipv4 hash:ip|14346 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/apache.txt)
[blocklist_de_bots](#blocklist_de_bots)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the RFI-Attacks, REG-Bots, IRC-Bots or BadBots (BadBots = he has posted a Spam-Comment on a open Forum or Wiki).|ipv4 hash:ip|2960 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/bots.txt)
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|[Blocklist.de](https://www.blocklist.de/) All IPs which attacks Joomlas, Wordpress and other Web-Logins with Brute-Force Logins.|ipv4 hash:ip|2901 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/bruteforcelogin.txt)
[blocklist_de_ftp](#blocklist_de_ftp)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours for attacks on the Service FTP.|ipv4 hash:ip|1526 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/ftp.txt)
[blocklist_de_imap](#blocklist_de_imap)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours for attacks on the Service imap, sasl, pop3, etc.|ipv4 hash:ip|2839 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/imap.txt)
[blocklist_de_mail](#blocklist_de_mail)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service Mail, Postfix.|ipv4 hash:ip|18299 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/mail.txt)
[blocklist_de_sip](#blocklist_de_sip)|[Blocklist.de](https://www.blocklist.de/) All IP addresses that tried to login in a SIP, VOIP or Asterisk Server and are included in the IPs list from [infiltrated.net](www.infiltrated.net)|ipv4 hash:ip|84 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/sip.txt)
[blocklist_de_ssh](#blocklist_de_ssh)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service SSH.|ipv4 hash:ip|2423 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/ssh.txt)
[blocklist_de_strongips](#blocklist_de_strongips)|[Blocklist.de](https://www.blocklist.de/) All IPs which are older then 2 month and have more then 5.000 attacks.|ipv4 hash:ip|172 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/strongips.txt)
[bm_tor](#bm_tor)|[torstatus.blutmagie.de](https://torstatus.blutmagie.de) list of all TOR network servers|ipv4 hash:ip|6525 unique IPs|updated every 30 mins  from [this link](https://torstatus.blutmagie.de/ip_list_all.php/Tor_ip_list_ALL.csv)
[bogons](#bogons)|[Team-Cymru.org](http://www.team-cymru.org) private and reserved addresses defined by RFC 1918, RFC 5735, and RFC 6598 and netblocks that have not been allocated to a regional internet registry - **excellent list - use it only your internet interface**|ipv4 hash:net|13 subnets, 592708608 unique IPs|updated every 1 day  from [this link](http://www.team-cymru.org/Services/Bogons/bogon-bn-agg.txt)
[bruteforceblocker](#bruteforceblocker)|[danger.rulez.sk](http://danger.rulez.sk/) IPs detected by [bruteforceblocker](http://danger.rulez.sk/index.php/bruteforceblocker/) (fail2ban alternative for SSH on OpenBSD). This is an automatically generated list from users reporting failed authentication attempts. An IP seems to be included if 3 or more users report it. Its retention pocily seems 30 days.|ipv4 hash:ip|1695 unique IPs|updated every 3 hours  from [this link](http://danger.rulez.sk/projects/bruteforceblocker/blist.php)
[ciarmy](#ciarmy)|[CIArmy.com](http://ciarmy.com/) IPs with poor Rogue Packet score that have not yet been identified as malicious by the community|ipv4 hash:ip|488 unique IPs|updated every 3 hours  from [this link](http://cinsscore.com/list/ci-badguys.txt)
[cleanmx_viruses](#cleanmx_viruses)|[Clean-MX.de](http://support.clean-mx.de/clean-mx/viruses.php) IPs with viruses|ipv4 hash:ip|121 unique IPs|updated every 12 hours  from [this link](http://support.clean-mx.de/clean-mx/xmlviruses.php?sort=id%20desc&response=alive)
[dm_tor](#dm_tor)|[dan.me.uk](https://www.dan.me.uk) dynamic list of TOR nodes|ipv4 hash:ip|6521 unique IPs|updated every 30 mins  from [this link](https://www.dan.me.uk/torlist/)
[dragon_http](#dragon_http)|[Dragon Search Group](http://www.dragonresearchgroup.org/) IPs that have been seen sending HTTP requests to Dragon Research Pods in the last 7 days. This report lists hosts that are highly suspicious and are likely conducting malicious HTTP attacks. LEGITIMATE SEARCH ENGINE BOTS MAY BE IN THIS LIST. This report is informational.  It is not a blacklist, but some operators may choose to use it to help protect their networks and hosts in the forms of automated reporting and mitigation services.|ipv4 hash:net|1029 subnets, 270336 unique IPs|updated every 1 day  from [this link](http://www.dragonresearchgroup.org/insight/http-report.txt)
[dragon_sshpauth](#dragon_sshpauth)|[Dragon Search Group](http://www.dragonresearchgroup.org/) IP address that has been seen attempting to remotely login to a host using SSH password authentication, in the last 7 days. This report lists hosts that are highly suspicious and are likely conducting malicious SSH password authentication attacks.|ipv4 hash:net|1633 subnets, 1695 unique IPs|updated every 1 hour  from [this link](https://www.dragonresearchgroup.org/insight/sshpwauth.txt)
[dragon_vncprobe](#dragon_vncprobe)|[Dragon Search Group](http://www.dragonresearchgroup.org/) IP address that has been seen attempting to remotely connect to a host running the VNC application service, in the last 7 days. This report lists hosts that are highly suspicious and are likely conducting malicious VNC probes or VNC brute force attacks.|ipv4 hash:net|88 subnets, 88 unique IPs|updated every 1 hour  from [this link](https://www.dragonresearchgroup.org/insight/vncprobe.txt)
[dshield](#dshield)|[DShield.org](https://dshield.org/) top 20 attacking class C (/24) subnets over the last three days - **excellent list**|ipv4 hash:net|20 subnets, 5120 unique IPs|updated every 4 hours  from [this link](http://feeds.dshield.org/block.txt)
[et_block](#et_block)|[EmergingThreats.net](http://www.emergingthreats.net/) default blacklist (at the time of writing includes spamhaus DROP, dshield and abuse.ch trackers, which are available separately too - prefer to use the direct ipsets instead of this, they seem to lag a bit in updates)|ipv4 hash:net|1000 subnets, 18344011 unique IPs|updated every 12 hours  from [this link](http://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt)
[et_botcc](#et_botcc)|[EmergingThreats.net Command and Control IPs](http://doc.emergingthreats.net/bin/view/Main/BotCC) These IPs are updates every 24 hours and should be considered VERY highly reliable indications that a host is communicating with a known and active Bot or Malware command and control server - (although they say this includes abuse.ch trackers, it does not - most probably it is the shadowserver.org C&C list)|ipv4 hash:ip|506 unique IPs|updated every 12 hours  from [this link](http://rules.emergingthreats.net/fwrules/emerging-PIX-CC.rules)
[et_compromised](#et_compromised)|[EmergingThreats.net compromised hosts](http://doc.emergingthreats.net/bin/view/Main/CompromisedHost) - (this seems to be based on bruteforceblocker)|ipv4 hash:ip|1721 unique IPs|updated every 12 hours  from [this link](http://rules.emergingthreats.net/blockrules/compromised-ips.txt)
et_dshield|[EmergingThreats.net](http://www.emergingthreats.net/) dshield blocklist|ipv4 hash:net|disabled|updated every 12 hours  from [this link](http://rules.emergingthreats.net/fwrules/emerging-PIX-DSHIELD.rules)
et_spamhaus|[EmergingThreats.net](http://www.emergingthreats.net/) spamhaus blocklist|ipv4 hash:net|disabled|updated every 12 hours  from [this link](http://rules.emergingthreats.net/fwrules/emerging-PIX-DROP.rules)
[et_tor](#et_tor)|[EmergingThreats.net](http://www.emergingthreats.net/) [list](http://doc.emergingthreats.net/bin/view/Main/TorRules) of TOR network IPs|ipv4 hash:ip|6400 unique IPs|updated every 12 hours  from [this link](http://rules.emergingthreats.net/blockrules/emerging-tor.rules)
[feodo](#feodo)|[Abuse.ch Feodo tracker](https://feodotracker.abuse.ch) trojan includes IPs which are being used by Feodo (also known as Cridex or Bugat) which commits ebanking fraud - **excellent list**|ipv4 hash:ip|105 unique IPs|updated every 30 mins  from [this link](https://feodotracker.abuse.ch/blocklist/?download=ipblocklist)
[firehol_anonymous](#firehol_anonymous)|**FireHOL Anonymous** - Known anonymizing IPs. (includes: firehol_proxies anonymous bm_tor dm_tor tor_exits)|ipv4 hash:net|19168 subnets, 83212 unique IPs|
[firehol_level1](#firehol_level1)|**FireHOL Level 1** - Maximum protection without false positives. (includes: fullbogons dshield feodo palevo sslbl zeus spamhaus_drop spamhaus_edrop)|ipv4 hash:net|5138 subnets, 688854748 unique IPs|
[firehol_level2](#firehol_level2)|**FireHOL Level 2** - Maximum protection from attacks took place in the last 48 hours. (includes: openbl_1d blocklist_de stopforumspam_1d)|ipv4 hash:net|22007 subnets, 33621 unique IPs|
[firehol_level3](#firehol_level3)|**FireHOL Level 3** - All the bad IPs in last 30 days. (includes: openbl_30d stopforumspam_30d virbl malc0de shunlist malwaredomainlist bruteforceblocker ciarmy cleanmx_viruses snort_ipfilter ib_bluetack_spyware ib_bluetack_hijacked ib_bluetack_webexploit php_commenters php_dictionary php_harvesters php_spammers iw_wormlist)|ipv4 hash:net|109658 subnets, 9627424 unique IPs|
[firehol_proxies](#firehol_proxies)|**FireHOL Proxies** - Known open proxies in the last 30 days. (includes: ib_bluetack_proxies maxmind_proxy_fraud proxyrss proxz ri_connect_proxies ri_web_proxies xroxy)|ipv4 hash:net|12674 subnets, 12945 unique IPs|
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
[iw_spamlist](#iw_spamlist)|[ImproWare Antispam](http://antispam.imp.ch/) IPs sending spam, in the last 3 days|ipv4 hash:ip|3878 unique IPs|updated every 1 hour  from [this link](http://antispam.imp.ch/spamlist)
[iw_wormlist](#iw_wormlist)|[ImproWare Antispam](http://antispam.imp.ch/) IPs sending emails with viruses or worms, in the last 3 days|ipv4 hash:ip|35 unique IPs|updated every 1 hour  from [this link](http://antispam.imp.ch/wormlist)
lashback_ubl|[The LashBack UBL](http://blacklist.lashback.com/) The Unsubscribe Blacklist (UBL) is a real-time blacklist of IP addresses which are sending email to names harvested from suppression files (this is a big list, more than 500.000 IPs)|ipv4 hash:ip|disabled|updated every 1 day  from [this link](http://www.unsubscore.com/blacklist.txt)
[malc0de](#malc0de)|[Malc0de.com](http://malc0de.com) malicious IPs of the last 30 days|ipv4 hash:ip|276 unique IPs|updated every 1 day  from [this link](http://malc0de.com/bl/IP_Blacklist.txt)
[malwaredomainlist](#malwaredomainlist)|[malwaredomainlist.com](http://www.malwaredomainlist.com) list of malware active ip addresses|ipv4 hash:ip|1288 unique IPs|updated every 12 hours  from [this link](http://www.malwaredomainlist.com/hostslist/ip.txt)
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|[MaxMind.com](https://www.maxmind.com/en/anonymous-proxy-fraudulent-ip-address-list) list of anonymous proxy fraudelent IP addresses.|ipv4 hash:ip|524 unique IPs|updated every 4 hours  from [this link](https://www.maxmind.com/en/anonymous-proxy-fraudulent-ip-address-list)
[nixspam](#nixspam)|[NiX Spam](http://www.heise.de/ix/NiX-Spam-DNSBL-and-blacklist-for-download-499637.html) IP addresses that sent spam in the last hour - automatically generated entries without distinguishing open proxies from relays, dialup gateways, and so on. All IPs are removed after 12 hours if there is no spam from there.|ipv4 hash:ip|22818 unique IPs|updated every 15 mins  from [this link](http://www.dnsbl.manitu.net/download/nixspam-ip.dump.gz)
[nt_malware_http](#nt_malware_http)|[No Think](http://www.nothink.org/) Malware HTTP|ipv4 hash:ip|69 unique IPs|updated every 1 hour  from [this link](http://www.nothink.org/blacklist/blacklist_malware_http.txt)
[nt_malware_irc](#nt_malware_irc)|[No Think](http://www.nothink.org/) Malware IRC|ipv4 hash:ip|43 unique IPs|updated every 1 hour  from [this link](http://www.nothink.org/blacklist/blacklist_malware_irc.txt)
[nt_ssh_7d](#nt_ssh_7d)|[No Think](http://www.nothink.org/) Last 7 days SSH attacks|ipv4 hash:ip|0 unique IPs|updated every 1 hour  from [this link](http://www.nothink.org/blacklist/blacklist_ssh_week.txt)
openbl|[OpenBL.org](http://www.openbl.org/) default blacklist (currently it is the same with 90 days). OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications - **excellent list**|ipv4 hash:ip|disabled|updated every 4 hours  from [this link](http://www.openbl.org/lists/base.txt)
openbl_180d|[OpenBL.org](http://www.openbl.org/) last 180 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|disabled|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_180days.txt)
[openbl_1d](#openbl_1d)|[OpenBL.org](http://www.openbl.org/) last 24 hours IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|148 unique IPs|updated every 1 hour  from [this link](http://www.openbl.org/lists/base_1days.txt)
[openbl_30d](#openbl_30d)|[OpenBL.org](http://www.openbl.org/) last 30 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|2805 unique IPs|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_30days.txt)
openbl_360d|[OpenBL.org](http://www.openbl.org/) last 360 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|disabled|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_360days.txt)
[openbl_60d](#openbl_60d)|[OpenBL.org](http://www.openbl.org/) last 60 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|6978 unique IPs|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_60days.txt)
[openbl_7d](#openbl_7d)|[OpenBL.org](http://www.openbl.org/) last 7 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|635 unique IPs|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_7days.txt)
openbl_90d|[OpenBL.org](http://www.openbl.org/) last 90 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|disabled|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_90days.txt)
openbl_all|[OpenBL.org](http://www.openbl.org/) last all IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|disabled|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_all.txt)
[palevo](#palevo)|[Abuse.ch Palevo tracker](https://palevotracker.abuse.ch) worm includes IPs which are being used as botnet C&C for the Palevo crimeware - **excellent list**|ipv4 hash:ip|13 unique IPs|updated every 30 mins  from [this link](https://palevotracker.abuse.ch/blocklists.php?download=ipblocklist)
php_bad|[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) bad web hosts (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|disabled|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=b&rss=1)
[php_commenters](#php_commenters)|[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) comment spammers (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|458 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=c&rss=1)
[php_dictionary](#php_dictionary)|[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) directory attackers (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|737 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=d&rss=1)
[php_harvesters](#php_harvesters)|[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) harvesters (IPs that surf the internet looking for email addresses) (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|408 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=h&rss=1)
[php_spammers](#php_spammers)|[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) spam servers (IPs used by spammers to send messages) (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|735 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=s&rss=1)
[proxyrss](#proxyrss)|[proxyrss.com](http://www.proxyrss.com) open proxies syndicated from multiple sources.|ipv4 hash:ip|1638 unique IPs|updated every 4 hours  from [this link](http://www.proxyrss.com/proxylists/all.gz)
[proxz](#proxz)|[proxz.com](http://www.proxz.com) open proxies (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|1323 unique IPs|updated every 1 hour  from [this link](http://www.proxz.com/proxylists.xml)
[ri_connect_proxies](#ri_connect_proxies)|[rosinstrument.com](http://www.rosinstrument.com) open CONNECT proxies (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|2828 unique IPs|updated every 1 hour  from [this link](http://tools.rosinstrument.com/proxy/plab100.xml)
[ri_web_proxies](#ri_web_proxies)|[rosinstrument.com](http://www.rosinstrument.com) open HTTP proxies (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|7852 unique IPs|updated every 1 hour  from [this link](http://tools.rosinstrument.com/proxy/l100.xml)
[shunlist](#shunlist)|[AutoShun.org](http://autoshun.org/) IPs identified as hostile by correlating logs from distributed snort installations running the autoshun plugin|ipv4 hash:ip|1151 unique IPs|updated every 4 hours  from [this link](http://www.autoshun.org/files/shunlist.csv)
[snort_ipfilter](#snort_ipfilter)|[labs.snort.org](https://labs.snort.org/) supplied IP blacklist (this list seems to be updated frequently, but we found no information about it)|ipv4 hash:ip|9671 unique IPs|updated every 12 hours  from [this link](http://labs.snort.org/feeds/ip-filter.blf)
[sorbs_dul](#sorbs_dul)|[Sorbs.net](https://www.sorbs.net/) DUL, Dynamic User IPs extracted from deltas.|ipv4 hash:net|10 subnets, 4864 unique IPs|
[sorbs_http](#sorbs_http)|[Sorbs.net](https://www.sorbs.net/) HTTP proxies, extracted from deltas.|ipv4 hash:net|7 subnets, 7 unique IPs|
[sorbs_misc](#sorbs_misc)|[Sorbs.net](https://www.sorbs.net/) MISC proxies, extracted from deltas.|ipv4 hash:net|7 subnets, 7 unique IPs|
[sorbs_new_spam](#sorbs_new_spam)|[Sorbs.net](https://www.sorbs.net/) NEW Spam senders, extracted from deltas.|ipv4 hash:net|64467 subnets, 65300 unique IPs|
[sorbs_recent_spam](#sorbs_recent_spam)|[Sorbs.net](https://www.sorbs.net/) RECENT Spam senders, extracted from deltas.|ipv4 hash:net|64467 subnets, 65300 unique IPs|
[sorbs_smtp](#sorbs_smtp)|[Sorbs.net](https://www.sorbs.net/) SMTP Open Relays, extracted from deltas.|ipv4 hash:net|6 subnets, 6 unique IPs|
[sorbs_socks](#sorbs_socks)|[Sorbs.net](https://www.sorbs.net/) SOCKS proxies, extracted from deltas.|ipv4 hash:net|7 subnets, 7 unique IPs|
[sorbs_spam](#sorbs_spam)|[Sorbs.net](https://www.sorbs.net/) Spam senders, extracted from deltas.|ipv4 hash:net|64701 subnets, 65536 unique IPs|
[sorbs_web](#sorbs_web)|[Sorbs.net](https://www.sorbs.net/) WEB exploits, extracted from deltas.|ipv4 hash:net|568 subnets, 569 unique IPs|
[spamhaus_drop](#spamhaus_drop)|[Spamhaus.org](http://www.spamhaus.org) DROP list (according to their site this list should be dropped at tier-1 ISPs globaly) - **excellent list**|ipv4 hash:net|653 subnets, 18340608 unique IPs|updated every 12 hours  from [this link](http://www.spamhaus.org/drop/drop.txt)
[spamhaus_edrop](#spamhaus_edrop)|[Spamhaus.org](http://www.spamhaus.org) EDROP (extended matches that should be used with DROP) - **excellent list**|ipv4 hash:net|56 subnets, 487424 unique IPs|updated every 12 hours  from [this link](http://www.spamhaus.org/drop/edrop.txt)
[sslbl](#sslbl)|[Abuse.ch SSL Blacklist](https://sslbl.abuse.ch/) bad SSL traffic related to malware or botnet activities - **excellent list**|ipv4 hash:ip|371 unique IPs|updated every 30 mins  from [this link](https://sslbl.abuse.ch/blacklist/sslipblacklist.csv)
stopforumspam_180d|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 180 days)|ipv4 hash:ip|disabled|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/listed_ip_180.zip)
[stopforumspam_1d](#stopforumspam_1d)|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers in the last 24 hours - **excellent list**|ipv4 hash:ip|6697 unique IPs|updated every 1 hour  from [this link](http://www.stopforumspam.com/downloads/listed_ip_1.zip)
[stopforumspam_30d](#stopforumspam_30d)|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 30 days)|ipv4 hash:ip|94309 unique IPs|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/listed_ip_30.zip)
stopforumspam_365d|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 365 days)|ipv4 hash:ip|disabled|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/listed_ip_365.zip)
[stopforumspam_7d](#stopforumspam_7d)|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 7 days)|ipv4 hash:ip|29185 unique IPs|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/listed_ip_7.zip)
stopforumspam_90d|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 90 days)|ipv4 hash:ip|disabled|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/listed_ip_90.zip)
stopforumspam_ever|[StopForumSpam.com](http://www.stopforumspam.com) all IPs used by forum spammers, **ever** (normally you don't want to use this ipset, use the hourly one which includes last 24 hours IPs or the 7 days one)|ipv4 hash:ip|disabled|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/bannedips.zip)
[tor_exits](#tor_exits)|[TorProject.org](https://www.torproject.org) list of all current TOR exit points (TorDNSEL)|ipv4 hash:ip|1112 unique IPs|updated every 30 mins  from [this link](https://check.torproject.org/exit-addresses)
[virbl](#virbl)|[VirBL](http://virbl.bit.nl/) is a project of which the idea was born during the RIPE-48 meeting. The plan was to get reports of virusscanning mailservers, and put the IP-addresses that were reported to send viruses on a blacklist.|ipv4 hash:ip|19 unique IPs|updated every 1 hour  from [this link](http://virbl.bit.nl/download/virbl.dnsbl.bit.nl.txt)
[voipbl](#voipbl)|[VoIPBL.org](http://www.voipbl.org/) a distributed VoIP blacklist that is aimed to protects against VoIP Fraud and minimizing abuse for network that have publicly accessible PBX's. Several algorithms, external sources and manual confirmation are used before they categorize something as an attack and determine the threat level.|ipv4 hash:net|10586 subnets, 10998 unique IPs|updated every 4 hours  from [this link](http://www.voipbl.org/update/)
[xroxy](#xroxy)|[xroxy.com](http://www.xroxy.com) open proxies (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|2169 unique IPs|updated every 1 hour  from [this link](http://www.xroxy.com/proxyrss.xml)
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
[openbl_60d](#openbl_60d)|6978|6978|6959|99.7%|3.7%|
[dragon_http](#dragon_http)|1029|270336|5896|2.1%|3.1%|
[firehol_level3](#firehol_level3)|109658|9627424|4903|0.0%|2.6%|
[et_block](#et_block)|1000|18344011|4777|0.0%|2.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|4185|0.0%|2.2%|
[firehol_level1](#firehol_level1)|5138|688854748|3833|0.0%|2.0%|
[openbl_30d](#openbl_30d)|2805|2805|2791|99.5%|1.4%|
[dshield](#dshield)|20|5120|2564|50.0%|1.3%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|1385|0.0%|0.7%|
[firehol_level2](#firehol_level2)|22007|33621|1200|3.5%|0.6%|
[blocklist_de](#blocklist_de)|28426|28426|1150|4.0%|0.6%|
[shunlist](#shunlist)|1151|1151|1144|99.3%|0.6%|
[et_compromised](#et_compromised)|1721|1721|1116|64.8%|0.5%|
[bruteforceblocker](#bruteforceblocker)|1695|1695|1072|63.2%|0.5%|
[blocklist_de_ssh](#blocklist_de_ssh)|2423|2423|948|39.1%|0.5%|
[dragon_sshpauth](#dragon_sshpauth)|1633|1695|875|51.6%|0.4%|
[openbl_7d](#openbl_7d)|635|635|634|99.8%|0.3%|
[ciarmy](#ciarmy)|488|488|482|98.7%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|293|0.0%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|278|0.0%|0.1%|
[voipbl](#voipbl)|10586|10998|176|1.6%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|167|0.1%|0.0%|
[openbl_1d](#openbl_1d)|148|148|147|99.3%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14346|14346|118|0.8%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9671|9671|108|1.1%|0.0%|
[sorbs_spam](#sorbs_spam)|64701|65536|91|0.1%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|91|0.1%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|91|0.1%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|89|0.3%|0.0%|
[nixspam](#nixspam)|22818|22818|77|0.3%|0.0%|
[sslbl](#sslbl)|371|371|65|17.5%|0.0%|
[zeus](#zeus)|230|230|61|26.5%|0.0%|
[firehol_anonymous](#firehol_anonymous)|19168|83212|57|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|18299|18299|47|0.2%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6697|6697|46|0.6%|0.0%|
[dm_tor](#dm_tor)|6521|6521|42|0.6%|0.0%|
[bm_tor](#bm_tor)|6525|6525|42|0.6%|0.0%|
[et_tor](#et_tor)|6400|6400|39|0.6%|0.0%|
[firehol_proxies](#firehol_proxies)|12674|12945|38|0.2%|0.0%|
[zeus_badips](#zeus_badips)|202|202|37|18.3%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|172|172|35|20.3%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2839|2839|32|1.1%|0.0%|
[tor_exits](#tor_exits)|1112|1112|30|2.6%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|29|5.5%|0.0%|
[dragon_vncprobe](#dragon_vncprobe)|88|88|29|32.9%|0.0%|
[iw_spamlist](#iw_spamlist)|3878|3878|20|0.5%|0.0%|
[php_commenters](#php_commenters)|458|458|19|4.1%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|84|84|19|22.6%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|2960|2960|19|0.6%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2901|2901|18|0.6%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|15|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|14|0.0%|0.0%|
[php_harvesters](#php_harvesters)|408|408|12|2.9%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|1526|1526|11|0.7%|0.0%|
[malc0de](#malc0de)|276|276|9|3.2%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|8|0.6%|0.0%|
[php_dictionary](#php_dictionary)|737|737|7|0.9%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|6|0.4%|0.0%|
[xroxy](#xroxy)|2169|2169|5|0.2%|0.0%|
[php_spammers](#php_spammers)|735|735|5|0.6%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7852|7852|4|0.0%|0.0%|
[et_botcc](#et_botcc)|506|506|4|0.7%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2828|2828|3|0.1%|0.0%|
[proxz](#proxz)|1323|1323|3|0.2%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|121|121|3|2.4%|0.0%|
[nt_malware_irc](#nt_malware_irc)|43|43|2|4.6%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|2|0.3%|0.0%|
[feodo](#feodo)|105|105|2|1.9%|0.0%|
[sorbs_web](#sorbs_web)|568|569|1|0.1%|0.0%|
[proxyrss](#proxyrss)|1638|1638|1|0.0%|0.0%|
[nt_malware_http](#nt_malware_http)|69|69|1|1.4%|0.0%|

## blocklist_de

[Blocklist.de](https://www.blocklist.de/) IPs that have been detected by fail2ban in the last 48 hours - **excellent list**

Source is downloaded from [this link](http://lists.blocklist.de/lists/all.txt).

The last time downloaded was found to be dated: Thu Jun 11 22:10:04 UTC 2015.

The ipset `blocklist_de` has **28426** entries, **28426** unique IPs.

The following table shows the overlaps of `blocklist_de` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de`.
- ` this % ` is the percentage **of this ipset (`blocklist_de`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|22007|33621|28426|84.5%|100.0%|
[blocklist_de_mail](#blocklist_de_mail)|18299|18299|18290|99.9%|64.3%|
[blocklist_de_apache](#blocklist_de_apache)|14346|14346|14240|99.2%|50.0%|
[firehol_level3](#firehol_level3)|109658|9627424|3857|0.0%|13.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|3397|0.0%|11.9%|
[blocklist_de_bots](#blocklist_de_bots)|2960|2960|2954|99.7%|10.3%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2901|2901|2869|98.8%|10.0%|
[blocklist_de_imap](#blocklist_de_imap)|2839|2839|2839|100.0%|9.9%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|2742|2.9%|9.6%|
[blocklist_de_ssh](#blocklist_de_ssh)|2423|2423|2423|100.0%|8.5%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|2194|7.5%|7.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|1600|0.0%|5.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|1549|0.0%|5.4%|
[blocklist_de_ftp](#blocklist_de_ftp)|1526|1526|1526|100.0%|5.3%|
[stopforumspam_1d](#stopforumspam_1d)|6697|6697|1520|22.6%|5.3%|
[sorbs_spam](#sorbs_spam)|64701|65536|1401|2.1%|4.9%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|1393|2.1%|4.9%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|1393|2.1%|4.9%|
[alienvault_reputation](#alienvault_reputation)|187341|187341|1150|0.6%|4.0%|
[openbl_60d](#openbl_60d)|6978|6978|806|11.5%|2.8%|
[dragon_sshpauth](#dragon_sshpauth)|1633|1695|694|40.9%|2.4%|
[nixspam](#nixspam)|22818|22818|687|3.0%|2.4%|
[firehol_anonymous](#firehol_anonymous)|19168|83212|685|0.8%|2.4%|
[openbl_30d](#openbl_30d)|2805|2805|673|23.9%|2.3%|
[firehol_proxies](#firehol_proxies)|12674|12945|658|5.0%|2.3%|
[bruteforceblocker](#bruteforceblocker)|1695|1695|580|34.2%|2.0%|
[et_compromised](#et_compromised)|1721|1721|567|32.9%|1.9%|
[ri_web_proxies](#ri_web_proxies)|7852|7852|476|6.0%|1.6%|
[openbl_7d](#openbl_7d)|635|635|380|59.8%|1.3%|
[shunlist](#shunlist)|1151|1151|360|31.2%|1.2%|
[xroxy](#xroxy)|2169|2169|226|10.4%|0.7%|
[snort_ipfilter](#snort_ipfilter)|9671|9671|222|2.2%|0.7%|
[et_block](#et_block)|1000|18344011|221|0.0%|0.7%|
[proxyrss](#proxyrss)|1638|1638|219|13.3%|0.7%|
[firehol_level1](#firehol_level1)|5138|688854748|211|0.0%|0.7%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|197|0.0%|0.6%|
[proxz](#proxz)|1323|1323|194|14.6%|0.6%|
[blocklist_de_strongips](#blocklist_de_strongips)|172|172|172|100.0%|0.6%|
[iw_spamlist](#iw_spamlist)|3878|3878|147|3.7%|0.5%|
[openbl_1d](#openbl_1d)|148|148|130|87.8%|0.4%|
[php_dictionary](#php_dictionary)|737|737|119|16.1%|0.4%|
[php_commenters](#php_commenters)|458|458|111|24.2%|0.3%|
[php_spammers](#php_spammers)|735|735|108|14.6%|0.3%|
[dshield](#dshield)|20|5120|80|1.5%|0.2%|
[ri_connect_proxies](#ri_connect_proxies)|2828|2828|74|2.6%|0.2%|
[sorbs_web](#sorbs_web)|568|569|68|11.9%|0.2%|
[blocklist_de_sip](#blocklist_de_sip)|84|84|65|77.3%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|58|0.0%|0.2%|
[dragon_http](#dragon_http)|1029|270336|48|0.0%|0.1%|
[voipbl](#voipbl)|10586|10998|42|0.3%|0.1%|
[php_harvesters](#php_harvesters)|408|408|40|9.8%|0.1%|
[ciarmy](#ciarmy)|488|488|37|7.5%|0.1%|
[tor_exits](#tor_exits)|1112|1112|22|1.9%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|15|0.0%|0.0%|
[et_tor](#et_tor)|6400|6400|15|0.2%|0.0%|
[dm_tor](#dm_tor)|6521|6521|12|0.1%|0.0%|
[bm_tor](#bm_tor)|6525|6525|12|0.1%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|7|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|7|1.3%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|7|0.0%|0.0%|
[dragon_vncprobe](#dragon_vncprobe)|88|88|5|5.6%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|4|0.6%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|3|0.2%|0.0%|
[sorbs_socks](#sorbs_socks)|7|7|1|14.2%|0.0%|
[sorbs_misc](#sorbs_misc)|7|7|1|14.2%|0.0%|
[sorbs_http](#sorbs_http)|7|7|1|14.2%|0.0%|
[iw_wormlist](#iw_wormlist)|35|35|1|2.8%|0.0%|

## blocklist_de_apache

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service Apache, Apache-DDOS, RFI-Attacks.

Source is downloaded from [this link](http://lists.blocklist.de/lists/apache.txt).

The last time downloaded was found to be dated: Thu Jun 11 22:28:05 UTC 2015.

The ipset `blocklist_de_apache` has **14346** entries, **14346** unique IPs.

The following table shows the overlaps of `blocklist_de_apache` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_apache`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_apache`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_apache`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|22007|33621|14240|42.3%|99.2%|
[blocklist_de](#blocklist_de)|28426|28426|14240|50.0%|99.2%|
[blocklist_de_mail](#blocklist_de_mail)|18299|18299|11059|60.4%|77.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2901|2901|2901|100.0%|20.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|2310|0.0%|16.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|1324|0.0%|9.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|1093|0.0%|7.6%|
[firehol_level3](#firehol_level3)|109658|9627424|287|0.0%|2.0%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|207|0.2%|1.4%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|119|0.4%|0.8%|
[alienvault_reputation](#alienvault_reputation)|187341|187341|118|0.0%|0.8%|
[stopforumspam_1d](#stopforumspam_1d)|6697|6697|61|0.9%|0.4%|
[sorbs_spam](#sorbs_spam)|64701|65536|46|0.0%|0.3%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|46|0.0%|0.3%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|46|0.0%|0.3%|
[snort_ipfilter](#snort_ipfilter)|9671|9671|35|0.3%|0.2%|
[shunlist](#shunlist)|1151|1151|34|2.9%|0.2%|
[blocklist_de_strongips](#blocklist_de_strongips)|172|172|33|19.1%|0.2%|
[nixspam](#nixspam)|22818|22818|32|0.1%|0.2%|
[php_commenters](#php_commenters)|458|458|30|6.5%|0.2%|
[ciarmy](#ciarmy)|488|488|30|6.1%|0.2%|
[firehol_anonymous](#firehol_anonymous)|19168|83212|25|0.0%|0.1%|
[blocklist_de_bots](#blocklist_de_bots)|2960|2960|23|0.7%|0.1%|
[tor_exits](#tor_exits)|1112|1112|22|1.9%|0.1%|
[et_tor](#et_tor)|6400|6400|15|0.2%|0.1%|
[dragon_http](#dragon_http)|1029|270336|12|0.0%|0.0%|
[dm_tor](#dm_tor)|6521|6521|12|0.1%|0.0%|
[bm_tor](#bm_tor)|6525|6525|12|0.1%|0.0%|
[et_block](#et_block)|1000|18344011|10|0.0%|0.0%|
[firehol_level1](#firehol_level1)|5138|688854748|9|0.0%|0.0%|
[openbl_60d](#openbl_60d)|6978|6978|8|0.1%|0.0%|
[openbl_30d](#openbl_30d)|2805|2805|6|0.2%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|5|0.0%|0.0%|
[php_spammers](#php_spammers)|735|735|5|0.6%|0.0%|
[openbl_7d](#openbl_7d)|635|635|5|0.7%|0.0%|
[iw_spamlist](#iw_spamlist)|3878|3878|4|0.1%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|4|0.0%|0.0%|
[dshield](#dshield)|20|5120|4|0.0%|0.0%|
[voipbl](#voipbl)|10586|10998|3|0.0%|0.0%|
[php_dictionary](#php_dictionary)|737|737|3|0.4%|0.0%|
[firehol_proxies](#firehol_proxies)|12674|12945|3|0.0%|0.0%|
[php_harvesters](#php_harvesters)|408|408|2|0.4%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|2|0.3%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|2|0.0%|0.0%|
[dragon_vncprobe](#dragon_vncprobe)|88|88|2|2.2%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2839|2839|2|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7852|7852|1|0.0%|0.0%|
[openbl_1d](#openbl_1d)|148|148|1|0.6%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.0%|

## blocklist_de_bots

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the RFI-Attacks, REG-Bots, IRC-Bots or BadBots (BadBots = he has posted a Spam-Comment on a open Forum or Wiki).

Source is downloaded from [this link](http://lists.blocklist.de/lists/bots.txt).

The last time downloaded was found to be dated: Thu Jun 11 22:14:13 UTC 2015.

The ipset `blocklist_de_bots` has **2960** entries, **2960** unique IPs.

The following table shows the overlaps of `blocklist_de_bots` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_bots`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_bots`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_bots`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|22007|33621|2955|8.7%|99.8%|
[blocklist_de](#blocklist_de)|28426|28426|2954|10.3%|99.7%|
[firehol_level3](#firehol_level3)|109658|9627424|2412|0.0%|81.4%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|2387|2.5%|80.6%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|2008|6.8%|67.8%|
[stopforumspam_1d](#stopforumspam_1d)|6697|6697|1457|21.7%|49.2%|
[firehol_anonymous](#firehol_anonymous)|19168|83212|533|0.6%|18.0%|
[firehol_proxies](#firehol_proxies)|12674|12945|532|4.1%|17.9%|
[ri_web_proxies](#ri_web_proxies)|7852|7852|390|4.9%|13.1%|
[proxyrss](#proxyrss)|1638|1638|220|13.4%|7.4%|
[xroxy](#xroxy)|2169|2169|170|7.8%|5.7%|
[proxz](#proxz)|1323|1323|161|12.1%|5.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|161|0.0%|5.4%|
[blocklist_de_strongips](#blocklist_de_strongips)|172|172|128|74.4%|4.3%|
[php_commenters](#php_commenters)|458|458|88|19.2%|2.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|77|0.0%|2.6%|
[ri_connect_proxies](#ri_connect_proxies)|2828|2828|70|2.4%|2.3%|
[firehol_level1](#firehol_level1)|5138|688854748|54|0.0%|1.8%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|49|0.0%|1.6%|
[et_block](#et_block)|1000|18344011|49|0.0%|1.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|48|0.0%|1.6%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|45|0.0%|1.5%|
[php_harvesters](#php_harvesters)|408|408|28|6.8%|0.9%|
[nixspam](#nixspam)|22818|22818|27|0.1%|0.9%|
[sorbs_spam](#sorbs_spam)|64701|65536|25|0.0%|0.8%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|25|0.0%|0.8%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|25|0.0%|0.8%|
[blocklist_de_apache](#blocklist_de_apache)|14346|14346|23|0.1%|0.7%|
[blocklist_de_mail](#blocklist_de_mail)|18299|18299|22|0.1%|0.7%|
[php_spammers](#php_spammers)|735|735|21|2.8%|0.7%|
[alienvault_reputation](#alienvault_reputation)|187341|187341|19|0.0%|0.6%|
[snort_ipfilter](#snort_ipfilter)|9671|9671|15|0.1%|0.5%|
[php_dictionary](#php_dictionary)|737|737|15|2.0%|0.5%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|5|0.0%|0.1%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|5|0.9%|0.1%|
[sorbs_web](#sorbs_web)|568|569|3|0.5%|0.1%|
[iw_spamlist](#iw_spamlist)|3878|3878|3|0.0%|0.1%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|3|0.4%|0.1%|
[dragon_http](#dragon_http)|1029|270336|3|0.0%|0.1%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|2|0.1%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.0%|

## blocklist_de_bruteforce

[Blocklist.de](https://www.blocklist.de/) All IPs which attacks Joomlas, Wordpress and other Web-Logins with Brute-Force Logins.

Source is downloaded from [this link](http://lists.blocklist.de/lists/bruteforcelogin.txt).

The last time downloaded was found to be dated: Thu Jun 11 22:14:15 UTC 2015.

The ipset `blocklist_de_bruteforce` has **2901** entries, **2901** unique IPs.

The following table shows the overlaps of `blocklist_de_bruteforce` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_bruteforce`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_bruteforce`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_bruteforce`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de_apache](#blocklist_de_apache)|14346|14346|2901|20.2%|100.0%|
[firehol_level2](#firehol_level2)|22007|33621|2869|8.5%|98.8%|
[blocklist_de](#blocklist_de)|28426|28426|2869|10.0%|98.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|211|0.0%|7.2%|
[firehol_level3](#firehol_level3)|109658|9627424|93|0.0%|3.2%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|74|0.0%|2.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|57|0.0%|1.9%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|50|0.1%|1.7%|
[sorbs_spam](#sorbs_spam)|64701|65536|46|0.0%|1.5%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|46|0.0%|1.5%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|46|0.0%|1.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|36|0.0%|1.2%|
[snort_ipfilter](#snort_ipfilter)|9671|9671|32|0.3%|1.1%|
[nixspam](#nixspam)|22818|22818|30|0.1%|1.0%|
[stopforumspam_1d](#stopforumspam_1d)|6697|6697|28|0.4%|0.9%|
[firehol_anonymous](#firehol_anonymous)|19168|83212|22|0.0%|0.7%|
[tor_exits](#tor_exits)|1112|1112|20|1.7%|0.6%|
[alienvault_reputation](#alienvault_reputation)|187341|187341|18|0.0%|0.6%|
[et_tor](#et_tor)|6400|6400|13|0.2%|0.4%|
[php_commenters](#php_commenters)|458|458|9|1.9%|0.3%|
[dm_tor](#dm_tor)|6521|6521|9|0.1%|0.3%|
[bm_tor](#bm_tor)|6525|6525|9|0.1%|0.3%|
[blocklist_de_strongips](#blocklist_de_strongips)|172|172|9|5.2%|0.3%|
[et_block](#et_block)|1000|18344011|6|0.0%|0.2%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|5|0.0%|0.1%|
[php_spammers](#php_spammers)|735|735|5|0.6%|0.1%|
[firehol_level1](#firehol_level1)|5138|688854748|5|0.0%|0.1%|
[dragon_http](#dragon_http)|1029|270336|4|0.0%|0.1%|
[php_dictionary](#php_dictionary)|737|737|3|0.4%|0.1%|
[iw_spamlist](#iw_spamlist)|3878|3878|3|0.0%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|3|0.0%|0.1%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|2|0.0%|0.0%|
[firehol_proxies](#firehol_proxies)|12674|12945|2|0.0%|0.0%|
[voipbl](#voipbl)|10586|10998|1|0.0%|0.0%|
[shunlist](#shunlist)|1151|1151|1|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7852|7852|1|0.0%|0.0%|
[php_harvesters](#php_harvesters)|408|408|1|0.2%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|1|0.1%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.0%|

## blocklist_de_ftp

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours for attacks on the Service FTP.

Source is downloaded from [this link](http://lists.blocklist.de/lists/ftp.txt).

The last time downloaded was found to be dated: Thu Jun 11 22:14:11 UTC 2015.

The ipset `blocklist_de_ftp` has **1526** entries, **1526** unique IPs.

The following table shows the overlaps of `blocklist_de_ftp` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_ftp`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_ftp`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_ftp`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|22007|33621|1526|4.5%|100.0%|
[blocklist_de](#blocklist_de)|28426|28426|1526|5.3%|100.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|126|0.0%|8.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|27|0.0%|1.7%|
[firehol_level3](#firehol_level3)|109658|9627424|22|0.0%|1.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|21|0.0%|1.3%|
[sorbs_spam](#sorbs_spam)|64701|65536|15|0.0%|0.9%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|15|0.0%|0.9%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|15|0.0%|0.9%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|14|0.0%|0.9%|
[nixspam](#nixspam)|22818|22818|13|0.0%|0.8%|
[alienvault_reputation](#alienvault_reputation)|187341|187341|11|0.0%|0.7%|
[dragon_http](#dragon_http)|1029|270336|6|0.0%|0.3%|
[php_harvesters](#php_harvesters)|408|408|4|0.9%|0.2%|
[firehol_anonymous](#firehol_anonymous)|19168|83212|4|0.0%|0.2%|
[stopforumspam_1d](#stopforumspam_1d)|6697|6697|3|0.0%|0.1%|
[iw_spamlist](#iw_spamlist)|3878|3878|3|0.0%|0.1%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|2|0.0%|0.1%|
[openbl_60d](#openbl_60d)|6978|6978|2|0.0%|0.1%|
[sorbs_web](#sorbs_web)|568|569|1|0.1%|0.0%|
[php_spammers](#php_spammers)|735|735|1|0.1%|0.0%|
[php_dictionary](#php_dictionary)|737|737|1|0.1%|0.0%|
[openbl_7d](#openbl_7d)|635|635|1|0.1%|0.0%|
[openbl_30d](#openbl_30d)|2805|2805|1|0.0%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|1|0.0%|0.0%|
[ciarmy](#ciarmy)|488|488|1|0.2%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|172|172|1|0.5%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|18299|18299|1|0.0%|0.0%|

## blocklist_de_imap

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours for attacks on the Service imap, sasl, pop3, etc.

Source is downloaded from [this link](http://lists.blocklist.de/lists/imap.txt).

The last time downloaded was found to be dated: Thu Jun 11 22:10:06 UTC 2015.

The ipset `blocklist_de_imap` has **2839** entries, **2839** unique IPs.

The following table shows the overlaps of `blocklist_de_imap` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_imap`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_imap`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_imap`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|22007|33621|2839|8.4%|100.0%|
[blocklist_de](#blocklist_de)|28426|28426|2839|9.9%|100.0%|
[blocklist_de_mail](#blocklist_de_mail)|18299|18299|2838|15.5%|99.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|305|0.0%|10.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|76|0.0%|2.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|70|0.0%|2.4%|
[firehol_level3](#firehol_level3)|109658|9627424|37|0.0%|1.3%|
[sorbs_spam](#sorbs_spam)|64701|65536|33|0.0%|1.1%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|32|0.0%|1.1%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|32|0.0%|1.1%|
[alienvault_reputation](#alienvault_reputation)|187341|187341|32|0.0%|1.1%|
[nixspam](#nixspam)|22818|22818|30|0.1%|1.0%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|17|0.0%|0.5%|
[openbl_60d](#openbl_60d)|6978|6978|16|0.2%|0.5%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|10|0.0%|0.3%|
[firehol_level1](#firehol_level1)|5138|688854748|10|0.0%|0.3%|
[et_block](#et_block)|1000|18344011|10|0.0%|0.3%|
[openbl_30d](#openbl_30d)|2805|2805|9|0.3%|0.3%|
[dragon_http](#dragon_http)|1029|270336|7|0.0%|0.2%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|6|0.0%|0.2%|
[openbl_7d](#openbl_7d)|635|635|6|0.9%|0.2%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|4|0.0%|0.1%|
[et_compromised](#et_compromised)|1721|1721|4|0.2%|0.1%|
[bruteforceblocker](#bruteforceblocker)|1695|1695|4|0.2%|0.1%|
[shunlist](#shunlist)|1151|1151|3|0.2%|0.1%|
[snort_ipfilter](#snort_ipfilter)|9671|9671|2|0.0%|0.0%|
[php_harvesters](#php_harvesters)|408|408|2|0.4%|0.0%|
[iw_spamlist](#iw_spamlist)|3878|3878|2|0.0%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2|0.0%|0.0%|
[ciarmy](#ciarmy)|488|488|2|0.4%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14346|14346|2|0.0%|0.0%|
[voipbl](#voipbl)|10586|10998|1|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6697|6697|1|0.0%|0.0%|
[openbl_1d](#openbl_1d)|148|148|1|0.6%|0.0%|
[dragon_vncprobe](#dragon_vncprobe)|88|88|1|1.1%|0.0%|
[dragon_sshpauth](#dragon_sshpauth)|1633|1695|1|0.0%|0.0%|

## blocklist_de_mail

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service Mail, Postfix.

Source is downloaded from [this link](http://lists.blocklist.de/lists/mail.txt).

The last time downloaded was found to be dated: Thu Jun 11 22:28:04 UTC 2015.

The ipset `blocklist_de_mail` has **18299** entries, **18299** unique IPs.

The following table shows the overlaps of `blocklist_de_mail` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_mail`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_mail`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_mail`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|22007|33621|18290|54.4%|99.9%|
[blocklist_de](#blocklist_de)|28426|28426|18290|64.3%|99.9%|
[blocklist_de_apache](#blocklist_de_apache)|14346|14346|11059|77.0%|60.4%|
[blocklist_de_imap](#blocklist_de_imap)|2839|2839|2838|99.9%|15.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|2609|0.0%|14.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|1430|0.0%|7.8%|
[sorbs_spam](#sorbs_spam)|64701|65536|1312|2.0%|7.1%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|1304|1.9%|7.1%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|1304|1.9%|7.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|1268|0.0%|6.9%|
[nixspam](#nixspam)|22818|22818|617|2.7%|3.3%|
[firehol_level3](#firehol_level3)|109658|9627424|407|0.0%|2.2%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|259|0.2%|1.4%|
[snort_ipfilter](#snort_ipfilter)|9671|9671|175|1.8%|0.9%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|146|0.5%|0.7%|
[iw_spamlist](#iw_spamlist)|3878|3878|138|3.5%|0.7%|
[firehol_anonymous](#firehol_anonymous)|19168|83212|126|0.1%|0.6%|
[firehol_proxies](#firehol_proxies)|12674|12945|124|0.9%|0.6%|
[php_dictionary](#php_dictionary)|737|737|100|13.5%|0.5%|
[ri_web_proxies](#ri_web_proxies)|7852|7852|84|1.0%|0.4%|
[php_spammers](#php_spammers)|735|735|80|10.8%|0.4%|
[sorbs_web](#sorbs_web)|568|569|64|11.2%|0.3%|
[xroxy](#xroxy)|2169|2169|56|2.5%|0.3%|
[stopforumspam_1d](#stopforumspam_1d)|6697|6697|47|0.7%|0.2%|
[alienvault_reputation](#alienvault_reputation)|187341|187341|47|0.0%|0.2%|
[proxz](#proxz)|1323|1323|33|2.4%|0.1%|
[php_commenters](#php_commenters)|458|458|30|6.5%|0.1%|
[firehol_level1](#firehol_level1)|5138|688854748|24|0.0%|0.1%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|22|0.0%|0.1%|
[et_block](#et_block)|1000|18344011|22|0.0%|0.1%|
[blocklist_de_strongips](#blocklist_de_strongips)|172|172|22|12.7%|0.1%|
[blocklist_de_bots](#blocklist_de_bots)|2960|2960|22|0.7%|0.1%|
[openbl_60d](#openbl_60d)|6978|6978|20|0.2%|0.1%|
[dragon_http](#dragon_http)|1029|270336|13|0.0%|0.0%|
[openbl_30d](#openbl_30d)|2805|2805|12|0.4%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|11|0.0%|0.0%|
[openbl_7d](#openbl_7d)|635|635|7|1.1%|0.0%|
[php_harvesters](#php_harvesters)|408|408|6|1.4%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2828|2828|4|0.1%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|4|0.0%|0.0%|
[et_compromised](#et_compromised)|1721|1721|4|0.2%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1695|1695|4|0.2%|0.0%|
[shunlist](#shunlist)|1151|1151|3|0.2%|0.0%|
[dm_tor](#dm_tor)|6521|6521|3|0.0%|0.0%|
[ciarmy](#ciarmy)|488|488|3|0.6%|0.0%|
[bm_tor](#bm_tor)|6525|6525|3|0.0%|0.0%|
[voipbl](#voipbl)|10586|10998|2|0.0%|0.0%|
[tor_exits](#tor_exits)|1112|1112|2|0.1%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|2|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|2|0.0%|0.0%|
[et_tor](#et_tor)|6400|6400|2|0.0%|0.0%|
[dragon_vncprobe](#dragon_vncprobe)|88|88|2|2.2%|0.0%|
[sorbs_socks](#sorbs_socks)|7|7|1|14.2%|0.0%|
[sorbs_misc](#sorbs_misc)|7|7|1|14.2%|0.0%|
[sorbs_http](#sorbs_http)|7|7|1|14.2%|0.0%|
[openbl_1d](#openbl_1d)|148|148|1|0.6%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|1|0.1%|0.0%|
[iw_wormlist](#iw_wormlist)|35|35|1|2.8%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|1|0.1%|0.0%|
[dragon_sshpauth](#dragon_sshpauth)|1633|1695|1|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|1526|1526|1|0.0%|0.0%|

## blocklist_de_sip

[Blocklist.de](https://www.blocklist.de/) All IP addresses that tried to login in a SIP, VOIP or Asterisk Server and are included in the IPs list from [infiltrated.net](www.infiltrated.net)

Source is downloaded from [this link](http://lists.blocklist.de/lists/sip.txt).

The last time downloaded was found to be dated: Thu Jun 11 22:14:11 UTC 2015.

The ipset `blocklist_de_sip` has **84** entries, **84** unique IPs.

The following table shows the overlaps of `blocklist_de_sip` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_sip`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_sip`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_sip`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|22007|33621|65|0.1%|77.3%|
[blocklist_de](#blocklist_de)|28426|28426|65|0.2%|77.3%|
[voipbl](#voipbl)|10586|10998|35|0.3%|41.6%|
[alienvault_reputation](#alienvault_reputation)|187341|187341|19|0.0%|22.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|14|0.0%|16.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|5|0.0%|5.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|4|0.0%|4.7%|
[firehol_level3](#firehol_level3)|109658|9627424|4|0.0%|4.7%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|2|0.0%|2.3%|
[shunlist](#shunlist)|1151|1151|2|0.1%|2.3%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|2|0.0%|2.3%|
[firehol_level1](#firehol_level1)|5138|688854748|2|0.0%|2.3%|
[et_block](#et_block)|1000|18344011|2|0.0%|2.3%|
[dragon_http](#dragon_http)|1029|270336|2|0.0%|2.3%|
[et_botcc](#et_botcc)|506|506|1|0.1%|1.1%|

## blocklist_de_ssh

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service SSH.

Source is downloaded from [this link](http://lists.blocklist.de/lists/ssh.txt).

The last time downloaded was found to be dated: Thu Jun 11 22:14:03 UTC 2015.

The ipset `blocklist_de_ssh` has **2423** entries, **2423** unique IPs.

The following table shows the overlaps of `blocklist_de_ssh` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_ssh`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_ssh`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_ssh`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|22007|33621|2423|7.2%|100.0%|
[blocklist_de](#blocklist_de)|28426|28426|2423|8.5%|100.0%|
[alienvault_reputation](#alienvault_reputation)|187341|187341|948|0.5%|39.1%|
[firehol_level3](#firehol_level3)|109658|9627424|870|0.0%|35.9%|
[openbl_60d](#openbl_60d)|6978|6978|775|11.1%|31.9%|
[dragon_sshpauth](#dragon_sshpauth)|1633|1695|692|40.8%|28.5%|
[openbl_30d](#openbl_30d)|2805|2805|653|23.2%|26.9%|
[bruteforceblocker](#bruteforceblocker)|1695|1695|575|33.9%|23.7%|
[et_compromised](#et_compromised)|1721|1721|562|32.6%|23.1%|
[openbl_7d](#openbl_7d)|635|635|367|57.7%|15.1%|
[shunlist](#shunlist)|1151|1151|321|27.8%|13.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|263|0.0%|10.8%|
[et_block](#et_block)|1000|18344011|138|0.0%|5.6%|
[openbl_1d](#openbl_1d)|148|148|128|86.4%|5.2%|
[firehol_level1](#firehol_level1)|5138|688854748|122|0.0%|5.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|119|0.0%|4.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|113|0.0%|4.6%|
[dshield](#dshield)|20|5120|76|1.4%|3.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|50|0.0%|2.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|172|172|28|16.2%|1.1%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|16|0.0%|0.6%|
[dragon_http](#dragon_http)|1029|270336|12|0.0%|0.4%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|7|0.0%|0.2%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|4|0.0%|0.1%|
[sorbs_spam](#sorbs_spam)|64701|65536|4|0.0%|0.1%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|4|0.0%|0.1%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|4|0.0%|0.1%|
[ciarmy](#ciarmy)|488|488|4|0.8%|0.1%|
[voipbl](#voipbl)|10586|10998|2|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7852|7852|1|0.0%|0.0%|
[php_spammers](#php_spammers)|735|735|1|0.1%|0.0%|
[php_harvesters](#php_harvesters)|408|408|1|0.2%|0.0%|
[php_commenters](#php_commenters)|458|458|1|0.2%|0.0%|
[nixspam](#nixspam)|22818|22818|1|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|1|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|1|0.0%|0.0%|
[firehol_proxies](#firehol_proxies)|12674|12945|1|0.0%|0.0%|
[firehol_anonymous](#firehol_anonymous)|19168|83212|1|0.0%|0.0%|
[dragon_vncprobe](#dragon_vncprobe)|88|88|1|1.1%|0.0%|

## blocklist_de_strongips

[Blocklist.de](https://www.blocklist.de/) All IPs which are older then 2 month and have more then 5.000 attacks.

Source is downloaded from [this link](http://lists.blocklist.de/lists/strongips.txt).

The last time downloaded was found to be dated: Thu Jun 11 22:14:14 UTC 2015.

The ipset `blocklist_de_strongips` has **172** entries, **172** unique IPs.

The following table shows the overlaps of `blocklist_de_strongips` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_strongips`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_strongips`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_strongips`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|22007|33621|172|0.5%|100.0%|
[blocklist_de](#blocklist_de)|28426|28426|172|0.6%|100.0%|
[firehol_level3](#firehol_level3)|109658|9627424|159|0.0%|92.4%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|133|0.1%|77.3%|
[blocklist_de_bots](#blocklist_de_bots)|2960|2960|128|4.3%|74.4%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|118|0.4%|68.6%|
[stopforumspam_1d](#stopforumspam_1d)|6697|6697|104|1.5%|60.4%|
[php_commenters](#php_commenters)|458|458|45|9.8%|26.1%|
[alienvault_reputation](#alienvault_reputation)|187341|187341|35|0.0%|20.3%|
[blocklist_de_apache](#blocklist_de_apache)|14346|14346|33|0.2%|19.1%|
[blocklist_de_ssh](#blocklist_de_ssh)|2423|2423|28|1.1%|16.2%|
[openbl_60d](#openbl_60d)|6978|6978|24|0.3%|13.9%|
[openbl_30d](#openbl_30d)|2805|2805|23|0.8%|13.3%|
[openbl_7d](#openbl_7d)|635|635|22|3.4%|12.7%|
[blocklist_de_mail](#blocklist_de_mail)|18299|18299|22|0.1%|12.7%|
[dragon_sshpauth](#dragon_sshpauth)|1633|1695|20|1.1%|11.6%|
[shunlist](#shunlist)|1151|1151|19|1.6%|11.0%|
[openbl_1d](#openbl_1d)|148|148|16|10.8%|9.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|16|0.0%|9.3%|
[php_spammers](#php_spammers)|735|735|10|1.3%|5.8%|
[firehol_proxies](#firehol_proxies)|12674|12945|9|0.0%|5.2%|
[firehol_level1](#firehol_level1)|5138|688854748|9|0.0%|5.2%|
[firehol_anonymous](#firehol_anonymous)|19168|83212|9|0.0%|5.2%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2901|2901|9|0.3%|5.2%|
[ri_web_proxies](#ri_web_proxies)|7852|7852|8|0.1%|4.6%|
[xroxy](#xroxy)|2169|2169|7|0.3%|4.0%|
[proxyrss](#proxyrss)|1638|1638|7|0.4%|4.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|7|0.0%|4.0%|
[et_block](#et_block)|1000|18344011|7|0.0%|4.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|6|0.0%|3.4%|
[proxz](#proxz)|1323|1323|6|0.4%|3.4%|
[php_dictionary](#php_dictionary)|737|737|5|0.6%|2.9%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|3|0.0%|1.7%|
[php_harvesters](#php_harvesters)|408|408|3|0.7%|1.7%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|1.7%|
[sorbs_web](#sorbs_web)|568|569|2|0.3%|1.1%|
[sorbs_spam](#sorbs_spam)|64701|65536|2|0.0%|1.1%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|2|0.0%|1.1%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|2|0.0%|1.1%|
[snort_ipfilter](#snort_ipfilter)|9671|9671|2|0.0%|1.1%|
[nixspam](#nixspam)|22818|22818|2|0.0%|1.1%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|2|0.1%|1.1%|
[dragon_http](#dragon_http)|1029|270336|2|0.0%|1.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|1|0.0%|0.5%|
[et_compromised](#et_compromised)|1721|1721|1|0.0%|0.5%|
[ciarmy](#ciarmy)|488|488|1|0.2%|0.5%|
[bruteforceblocker](#bruteforceblocker)|1695|1695|1|0.0%|0.5%|
[blocklist_de_ftp](#blocklist_de_ftp)|1526|1526|1|0.0%|0.5%|

## bm_tor

[torstatus.blutmagie.de](https://torstatus.blutmagie.de) list of all TOR network servers

Source is downloaded from [this link](https://torstatus.blutmagie.de/ip_list_all.php/Tor_ip_list_ALL.csv).

The last time downloaded was found to be dated: Thu Jun 11 22:09:03 UTC 2015.

The ipset `bm_tor` has **6525** entries, **6525** unique IPs.

The following table shows the overlaps of `bm_tor` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `bm_tor`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `bm_tor`.
- ` this % ` is the percentage **of this ipset (`bm_tor`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_anonymous](#firehol_anonymous)|19168|83212|6525|7.8%|100.0%|
[dm_tor](#dm_tor)|6521|6521|6521|100.0%|99.9%|
[et_tor](#et_tor)|6400|6400|5635|88.0%|86.3%|
[firehol_level3](#firehol_level3)|109658|9627424|1096|0.0%|16.7%|
[snort_ipfilter](#snort_ipfilter)|9671|9671|1061|10.9%|16.2%|
[tor_exits](#tor_exits)|1112|1112|1017|91.4%|15.5%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|634|0.6%|9.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|625|0.0%|9.5%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|526|1.8%|8.0%|
[firehol_level2](#firehol_level2)|22007|33621|313|0.9%|4.7%|
[stopforumspam_1d](#stopforumspam_1d)|6697|6697|305|4.5%|4.6%|
[firehol_proxies](#firehol_proxies)|12674|12945|236|1.8%|3.6%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|231|44.0%|3.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|185|0.0%|2.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|169|0.0%|2.5%|
[php_commenters](#php_commenters)|458|458|54|11.7%|0.8%|
[alienvault_reputation](#alienvault_reputation)|187341|187341|42|0.0%|0.6%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|22|0.0%|0.3%|
[openbl_60d](#openbl_60d)|6978|6978|20|0.2%|0.3%|
[dragon_http](#dragon_http)|1029|270336|14|0.0%|0.2%|
[blocklist_de_apache](#blocklist_de_apache)|14346|14346|12|0.0%|0.1%|
[blocklist_de](#blocklist_de)|28426|28426|12|0.0%|0.1%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2901|2901|9|0.3%|0.1%|
[php_harvesters](#php_harvesters)|408|408|7|1.7%|0.1%|
[nixspam](#nixspam)|22818|22818|7|0.0%|0.1%|
[ri_web_proxies](#ri_web_proxies)|7852|7852|5|0.0%|0.0%|
[php_spammers](#php_spammers)|735|735|5|0.6%|0.0%|
[sorbs_spam](#sorbs_spam)|64701|65536|4|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|4|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|4|0.0%|0.0%|
[php_dictionary](#php_dictionary)|737|737|4|0.5%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|4|0.0%|0.0%|
[voipbl](#voipbl)|10586|10998|3|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|3|0.0%|0.0%|
[firehol_level1](#firehol_level1)|5138|688854748|3|0.0%|0.0%|
[et_block](#et_block)|1000|18344011|3|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|18299|18299|3|0.0%|0.0%|
[xroxy](#xroxy)|2169|2169|2|0.0%|0.0%|
[shunlist](#shunlist)|1151|1151|1|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2828|2828|1|0.0%|0.0%|
[iw_spamlist](#iw_spamlist)|3878|3878|1|0.0%|0.0%|

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
[firehol_level1](#firehol_level1)|5138|688854748|592708608|86.0%|100.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|4194304|3.0%|0.7%|
[voipbl](#voipbl)|10586|10998|319|2.9%|0.0%|
[iw_spamlist](#iw_spamlist)|3878|3878|5|0.1%|0.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|5|0.0%|0.0%|
[firehol_level3](#firehol_level3)|109658|9627424|3|0.0%|0.0%|
[php_harvesters](#php_harvesters)|408|408|1|0.2%|0.0%|
[php_commenters](#php_commenters)|458|458|1|0.2%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.0%|
[ciarmy](#ciarmy)|488|488|1|0.2%|0.0%|

## bruteforceblocker

[danger.rulez.sk](http://danger.rulez.sk/) IPs detected by [bruteforceblocker](http://danger.rulez.sk/index.php/bruteforceblocker/) (fail2ban alternative for SSH on OpenBSD). This is an automatically generated list from users reporting failed authentication attempts. An IP seems to be included if 3 or more users report it. Its retention pocily seems 30 days.

Source is downloaded from [this link](http://danger.rulez.sk/projects/bruteforceblocker/blist.php).

The last time downloaded was found to be dated: Thu Jun 11 20:27:21 UTC 2015.

The ipset `bruteforceblocker` has **1695** entries, **1695** unique IPs.

The following table shows the overlaps of `bruteforceblocker` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `bruteforceblocker`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `bruteforceblocker`.
- ` this % ` is the percentage **of this ipset (`bruteforceblocker`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level3](#firehol_level3)|109658|9627424|1695|0.0%|100.0%|
[et_compromised](#et_compromised)|1721|1721|1624|94.3%|95.8%|
[alienvault_reputation](#alienvault_reputation)|187341|187341|1072|0.5%|63.2%|
[openbl_60d](#openbl_60d)|6978|6978|964|13.8%|56.8%|
[openbl_30d](#openbl_30d)|2805|2805|904|32.2%|53.3%|
[dragon_sshpauth](#dragon_sshpauth)|1633|1695|638|37.6%|37.6%|
[firehol_level2](#firehol_level2)|22007|33621|582|1.7%|34.3%|
[blocklist_de](#blocklist_de)|28426|28426|580|2.0%|34.2%|
[blocklist_de_ssh](#blocklist_de_ssh)|2423|2423|575|23.7%|33.9%|
[shunlist](#shunlist)|1151|1151|333|28.9%|19.6%|
[openbl_7d](#openbl_7d)|635|635|308|48.5%|18.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|156|0.0%|9.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|87|0.0%|5.1%|
[openbl_1d](#openbl_1d)|148|148|77|52.0%|4.5%|
[et_block](#et_block)|1000|18344011|69|0.0%|4.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|61|0.0%|3.5%|
[firehol_level1](#firehol_level1)|5138|688854748|61|0.0%|3.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|55|0.0%|3.2%|
[dshield](#dshield)|20|5120|19|0.3%|1.1%|
[dragon_http](#dragon_http)|1029|270336|12|0.0%|0.7%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|10|0.0%|0.5%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|5|0.0%|0.2%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|4|0.0%|0.2%|
[blocklist_de_mail](#blocklist_de_mail)|18299|18299|4|0.0%|0.2%|
[blocklist_de_imap](#blocklist_de_imap)|2839|2839|4|0.1%|0.2%|
[voipbl](#voipbl)|10586|10998|3|0.0%|0.1%|
[sorbs_spam](#sorbs_spam)|64701|65536|3|0.0%|0.1%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|3|0.0%|0.1%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|3|0.0%|0.1%|
[firehol_proxies](#firehol_proxies)|12674|12945|3|0.0%|0.1%|
[firehol_anonymous](#firehol_anonymous)|19168|83212|3|0.0%|0.1%|
[ciarmy](#ciarmy)|488|488|3|0.6%|0.1%|
[proxz](#proxz)|1323|1323|2|0.1%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|2|0.0%|0.1%|
[xroxy](#xroxy)|2169|2169|1|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6697|6697|1|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7852|7852|1|0.0%|0.0%|
[proxyrss](#proxyrss)|1638|1638|1|0.0%|0.0%|
[php_spammers](#php_spammers)|735|735|1|0.1%|0.0%|
[php_commenters](#php_commenters)|458|458|1|0.2%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|172|172|1|0.5%|0.0%|

## ciarmy

[CIArmy.com](http://ciarmy.com/) IPs with poor Rogue Packet score that have not yet been identified as malicious by the community

Source is downloaded from [this link](http://cinsscore.com/list/ci-badguys.txt).

The last time downloaded was found to be dated: Thu Jun 11 22:15:06 UTC 2015.

The ipset `ciarmy` has **488** entries, **488** unique IPs.

The following table shows the overlaps of `ciarmy` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ciarmy`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ciarmy`.
- ` this % ` is the percentage **of this ipset (`ciarmy`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level3](#firehol_level3)|109658|9627424|488|0.0%|100.0%|
[alienvault_reputation](#alienvault_reputation)|187341|187341|482|0.2%|98.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|105|0.0%|21.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|49|0.0%|10.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|39|0.0%|7.9%|
[firehol_level2](#firehol_level2)|22007|33621|38|0.1%|7.7%|
[blocklist_de](#blocklist_de)|28426|28426|37|0.1%|7.5%|
[blocklist_de_apache](#blocklist_de_apache)|14346|14346|30|0.2%|6.1%|
[shunlist](#shunlist)|1151|1151|29|2.5%|5.9%|
[dragon_http](#dragon_http)|1029|270336|9|0.0%|1.8%|
[et_block](#et_block)|1000|18344011|6|0.0%|1.2%|
[firehol_level1](#firehol_level1)|5138|688854748|5|0.0%|1.0%|
[dshield](#dshield)|20|5120|4|0.0%|0.8%|
[blocklist_de_ssh](#blocklist_de_ssh)|2423|2423|4|0.1%|0.8%|
[openbl_7d](#openbl_7d)|635|635|3|0.4%|0.6%|
[openbl_60d](#openbl_60d)|6978|6978|3|0.0%|0.6%|
[openbl_30d](#openbl_30d)|2805|2805|3|0.1%|0.6%|
[et_compromised](#et_compromised)|1721|1721|3|0.1%|0.6%|
[bruteforceblocker](#bruteforceblocker)|1695|1695|3|0.1%|0.6%|
[blocklist_de_mail](#blocklist_de_mail)|18299|18299|3|0.0%|0.6%|
[voipbl](#voipbl)|10586|10998|2|0.0%|0.4%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|2|0.0%|0.4%|
[openbl_1d](#openbl_1d)|148|148|2|1.3%|0.4%|
[blocklist_de_imap](#blocklist_de_imap)|2839|2839|2|0.0%|0.4%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|1|0.0%|0.2%|
[fullbogons](#fullbogons)|3775|670173256|1|0.0%|0.2%|
[dragon_vncprobe](#dragon_vncprobe)|88|88|1|1.1%|0.2%|
[dragon_sshpauth](#dragon_sshpauth)|1633|1695|1|0.0%|0.2%|
[bogons](#bogons)|13|592708608|1|0.0%|0.2%|
[blocklist_de_strongips](#blocklist_de_strongips)|172|172|1|0.5%|0.2%|
[blocklist_de_ftp](#blocklist_de_ftp)|1526|1526|1|0.0%|0.2%|

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
[firehol_level3](#firehol_level3)|109658|9627424|121|0.0%|100.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|19|0.0%|15.7%|
[malc0de](#malc0de)|276|276|16|5.7%|13.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|6|0.0%|4.9%|
[alienvault_reputation](#alienvault_reputation)|187341|187341|3|0.0%|2.4%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|2|0.1%|1.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|2|0.0%|1.6%|
[snort_ipfilter](#snort_ipfilter)|9671|9671|1|0.0%|0.8%|
[nixspam](#nixspam)|22818|22818|1|0.0%|0.8%|

## dm_tor

[dan.me.uk](https://www.dan.me.uk) dynamic list of TOR nodes

Source is downloaded from [this link](https://www.dan.me.uk/torlist/).

The last time downloaded was found to be dated: Thu Jun 11 22:27:05 UTC 2015.

The ipset `dm_tor` has **6521** entries, **6521** unique IPs.

The following table shows the overlaps of `dm_tor` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `dm_tor`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `dm_tor`.
- ` this % ` is the percentage **of this ipset (`dm_tor`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_anonymous](#firehol_anonymous)|19168|83212|6521|7.8%|100.0%|
[bm_tor](#bm_tor)|6525|6525|6521|99.9%|100.0%|
[et_tor](#et_tor)|6400|6400|5632|88.0%|86.3%|
[firehol_level3](#firehol_level3)|109658|9627424|1095|0.0%|16.7%|
[snort_ipfilter](#snort_ipfilter)|9671|9671|1060|10.9%|16.2%|
[tor_exits](#tor_exits)|1112|1112|1016|91.3%|15.5%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|634|0.6%|9.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|625|0.0%|9.5%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|526|1.8%|8.0%|
[firehol_level2](#firehol_level2)|22007|33621|313|0.9%|4.7%|
[stopforumspam_1d](#stopforumspam_1d)|6697|6697|305|4.5%|4.6%|
[firehol_proxies](#firehol_proxies)|12674|12945|236|1.8%|3.6%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|231|44.0%|3.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|185|0.0%|2.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|169|0.0%|2.5%|
[php_commenters](#php_commenters)|458|458|54|11.7%|0.8%|
[alienvault_reputation](#alienvault_reputation)|187341|187341|42|0.0%|0.6%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|22|0.0%|0.3%|
[openbl_60d](#openbl_60d)|6978|6978|20|0.2%|0.3%|
[dragon_http](#dragon_http)|1029|270336|14|0.0%|0.2%|
[blocklist_de_apache](#blocklist_de_apache)|14346|14346|12|0.0%|0.1%|
[blocklist_de](#blocklist_de)|28426|28426|12|0.0%|0.1%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2901|2901|9|0.3%|0.1%|
[php_harvesters](#php_harvesters)|408|408|7|1.7%|0.1%|
[nixspam](#nixspam)|22818|22818|7|0.0%|0.1%|
[ri_web_proxies](#ri_web_proxies)|7852|7852|5|0.0%|0.0%|
[php_spammers](#php_spammers)|735|735|5|0.6%|0.0%|
[sorbs_spam](#sorbs_spam)|64701|65536|4|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|4|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|4|0.0%|0.0%|
[php_dictionary](#php_dictionary)|737|737|4|0.5%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|4|0.0%|0.0%|
[voipbl](#voipbl)|10586|10998|3|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|3|0.0%|0.0%|
[firehol_level1](#firehol_level1)|5138|688854748|3|0.0%|0.0%|
[et_block](#et_block)|1000|18344011|3|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|18299|18299|3|0.0%|0.0%|
[xroxy](#xroxy)|2169|2169|2|0.0%|0.0%|
[shunlist](#shunlist)|1151|1151|1|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2828|2828|1|0.0%|0.0%|
[iw_spamlist](#iw_spamlist)|3878|3878|1|0.0%|0.0%|

## dragon_http

[Dragon Search Group](http://www.dragonresearchgroup.org/) IPs that have been seen sending HTTP requests to Dragon Research Pods in the last 7 days. This report lists hosts that are highly suspicious and are likely conducting malicious HTTP attacks. LEGITIMATE SEARCH ENGINE BOTS MAY BE IN THIS LIST. This report is informational.  It is not a blacklist, but some operators may choose to use it to help protect their networks and hosts in the forms of automated reporting and mitigation services.

Source is downloaded from [this link](http://www.dragonresearchgroup.org/insight/http-report.txt).

The last time downloaded was found to be dated: Thu Jun 11 02:00:07 UTC 2015.

The ipset `dragon_http` has **1029** entries, **270336** unique IPs.

The following table shows the overlaps of `dragon_http` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `dragon_http`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `dragon_http`.
- ` this % ` is the percentage **of this ipset (`dragon_http`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|20480|0.0%|7.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|11960|0.0%|4.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|6284|0.0%|2.3%|
[alienvault_reputation](#alienvault_reputation)|187341|187341|5896|3.1%|2.1%|
[et_block](#et_block)|1000|18344011|1024|0.0%|0.3%|
[firehol_level1](#firehol_level1)|5138|688854748|769|0.0%|0.2%|
[firehol_level3](#firehol_level3)|109658|9627424|558|0.0%|0.2%|
[dshield](#dshield)|20|5120|512|10.0%|0.1%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|256|0.0%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|256|0.0%|0.0%|
[openbl_60d](#openbl_60d)|6978|6978|219|3.1%|0.0%|
[openbl_30d](#openbl_30d)|2805|2805|148|5.2%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|111|0.1%|0.0%|
[sorbs_spam](#sorbs_spam)|64701|65536|71|0.1%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|70|0.1%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|70|0.1%|0.0%|
[firehol_level2](#firehol_level2)|22007|33621|62|0.1%|0.0%|
[openbl_7d](#openbl_7d)|635|635|53|8.3%|0.0%|
[blocklist_de](#blocklist_de)|28426|28426|48|0.1%|0.0%|
[firehol_anonymous](#firehol_anonymous)|19168|83212|41|0.0%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|36|0.1%|0.0%|
[nixspam](#nixspam)|22818|22818|31|0.1%|0.0%|
[firehol_proxies](#firehol_proxies)|12674|12945|30|0.2%|0.0%|
[voipbl](#voipbl)|10586|10998|27|0.2%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|26|0.0%|0.0%|
[dragon_vncprobe](#dragon_vncprobe)|88|88|25|28.4%|0.0%|
[shunlist](#shunlist)|1151|1151|22|1.9%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7852|7852|18|0.2%|0.0%|
[et_tor](#et_tor)|6400|6400|15|0.2%|0.0%|
[dm_tor](#dm_tor)|6521|6521|14|0.2%|0.0%|
[bm_tor](#bm_tor)|6525|6525|14|0.2%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|18299|18299|13|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6697|6697|12|0.1%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1695|1695|12|0.7%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2423|2423|12|0.4%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14346|14346|12|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9671|9671|11|0.1%|0.0%|
[et_compromised](#et_compromised)|1721|1721|11|0.6%|0.0%|
[ciarmy](#ciarmy)|488|488|9|1.8%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2839|2839|7|0.2%|0.0%|
[xroxy](#xroxy)|2169|2169|6|0.2%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|6|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|1526|1526|6|0.3%|0.0%|
[tor_exits](#tor_exits)|1112|1112|5|0.4%|0.0%|
[openbl_1d](#openbl_1d)|148|148|5|3.3%|0.0%|
[dragon_sshpauth](#dragon_sshpauth)|1633|1695|5|0.2%|0.0%|
[proxz](#proxz)|1323|1323|4|0.3%|0.0%|
[php_commenters](#php_commenters)|458|458|4|0.8%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|4|0.7%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2901|2901|4|0.1%|0.0%|
[zeus_badips](#zeus_badips)|202|202|3|1.4%|0.0%|
[zeus](#zeus)|230|230|3|1.3%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2828|2828|3|0.1%|0.0%|
[malc0de](#malc0de)|276|276|3|1.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|3|0.2%|0.0%|
[et_botcc](#et_botcc)|506|506|3|0.5%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|2960|2960|3|0.1%|0.0%|
[php_dictionary](#php_dictionary)|737|737|2|0.2%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|2|0.1%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|172|172|2|1.1%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|84|84|2|2.3%|0.0%|
[sslbl](#sslbl)|371|371|1|0.2%|0.0%|
[sorbs_web](#sorbs_web)|568|569|1|0.1%|0.0%|
[proxyrss](#proxyrss)|1638|1638|1|0.0%|0.0%|
[iw_spamlist](#iw_spamlist)|3878|3878|1|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|1|0.1%|0.0%|

## dragon_sshpauth

[Dragon Search Group](http://www.dragonresearchgroup.org/) IP address that has been seen attempting to remotely login to a host using SSH password authentication, in the last 7 days. This report lists hosts that are highly suspicious and are likely conducting malicious SSH password authentication attacks.

Source is downloaded from [this link](https://www.dragonresearchgroup.org/insight/sshpwauth.txt).

The last time downloaded was found to be dated: Thu Jun 11 22:04:02 UTC 2015.

The ipset `dragon_sshpauth` has **1633** entries, **1695** unique IPs.

The following table shows the overlaps of `dragon_sshpauth` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `dragon_sshpauth`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `dragon_sshpauth`.
- ` this % ` is the percentage **of this ipset (`dragon_sshpauth`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[alienvault_reputation](#alienvault_reputation)|187341|187341|875|0.4%|51.6%|
[firehol_level3](#firehol_level3)|109658|9627424|864|0.0%|50.9%|
[openbl_60d](#openbl_60d)|6978|6978|791|11.3%|46.6%|
[openbl_30d](#openbl_30d)|2805|2805|707|25.2%|41.7%|
[firehol_level2](#firehol_level2)|22007|33621|695|2.0%|41.0%|
[blocklist_de](#blocklist_de)|28426|28426|694|2.4%|40.9%|
[blocklist_de_ssh](#blocklist_de_ssh)|2423|2423|692|28.5%|40.8%|
[et_compromised](#et_compromised)|1721|1721|657|38.1%|38.7%|
[bruteforceblocker](#bruteforceblocker)|1695|1695|638|37.6%|37.6%|
[shunlist](#shunlist)|1151|1151|375|32.5%|22.1%|
[openbl_7d](#openbl_7d)|635|635|346|54.4%|20.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|127|0.0%|7.4%|
[et_block](#et_block)|1000|18344011|102|0.0%|6.0%|
[openbl_1d](#openbl_1d)|148|148|100|67.5%|5.8%|
[firehol_level1](#firehol_level1)|5138|688854748|99|0.0%|5.8%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|98|0.0%|5.7%|
[dshield](#dshield)|20|5120|73|1.4%|4.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|72|0.0%|4.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|31|0.0%|1.8%|
[blocklist_de_strongips](#blocklist_de_strongips)|172|172|20|11.6%|1.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|5|0.0%|0.2%|
[dragon_http](#dragon_http)|1029|270336|5|0.0%|0.2%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|4|0.0%|0.2%|
[sslbl](#sslbl)|371|371|1|0.2%|0.0%|
[sorbs_spam](#sorbs_spam)|64701|65536|1|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|1|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|1|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|1|0.0%|0.0%|
[ciarmy](#ciarmy)|488|488|1|0.2%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|18299|18299|1|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2839|2839|1|0.0%|0.0%|

## dragon_vncprobe

[Dragon Search Group](http://www.dragonresearchgroup.org/) IP address that has been seen attempting to remotely connect to a host running the VNC application service, in the last 7 days. This report lists hosts that are highly suspicious and are likely conducting malicious VNC probes or VNC brute force attacks.

Source is downloaded from [this link](https://www.dragonresearchgroup.org/insight/vncprobe.txt).

The last time downloaded was found to be dated: Thu Jun 11 22:04:01 UTC 2015.

The ipset `dragon_vncprobe` has **88** entries, **88** unique IPs.

The following table shows the overlaps of `dragon_vncprobe` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `dragon_vncprobe`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `dragon_vncprobe`.
- ` this % ` is the percentage **of this ipset (`dragon_vncprobe`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[alienvault_reputation](#alienvault_reputation)|187341|187341|29|0.0%|32.9%|
[dragon_http](#dragon_http)|1029|270336|25|0.0%|28.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|12|0.0%|13.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|7|0.0%|7.9%|
[firehol_level3](#firehol_level3)|109658|9627424|6|0.0%|6.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|5|0.0%|5.6%|
[firehol_level2](#firehol_level2)|22007|33621|5|0.0%|5.6%|
[et_block](#et_block)|1000|18344011|5|0.0%|5.6%|
[blocklist_de](#blocklist_de)|28426|28426|5|0.0%|5.6%|
[firehol_level1](#firehol_level1)|5138|688854748|4|0.0%|4.5%|
[shunlist](#shunlist)|1151|1151|3|0.2%|3.4%|
[dshield](#dshield)|20|5120|3|0.0%|3.4%|
[blocklist_de_mail](#blocklist_de_mail)|18299|18299|2|0.0%|2.2%|
[blocklist_de_apache](#blocklist_de_apache)|14346|14346|2|0.0%|2.2%|
[voipbl](#voipbl)|10586|10998|1|0.0%|1.1%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|1|0.0%|1.1%|
[openbl_7d](#openbl_7d)|635|635|1|0.1%|1.1%|
[openbl_60d](#openbl_60d)|6978|6978|1|0.0%|1.1%|
[openbl_30d](#openbl_30d)|2805|2805|1|0.0%|1.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|1.1%|
[ciarmy](#ciarmy)|488|488|1|0.2%|1.1%|
[blocklist_de_ssh](#blocklist_de_ssh)|2423|2423|1|0.0%|1.1%|
[blocklist_de_imap](#blocklist_de_imap)|2839|2839|1|0.0%|1.1%|

## dshield

[DShield.org](https://dshield.org/) top 20 attacking class C (/24) subnets over the last three days - **excellent list**

Source is downloaded from [this link](http://feeds.dshield.org/block.txt).

The last time downloaded was found to be dated: Thu Jun 11 19:56:20 UTC 2015.

The ipset `dshield` has **20** entries, **5120** unique IPs.

The following table shows the overlaps of `dshield` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `dshield`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `dshield`.
- ` this % ` is the percentage **of this ipset (`dshield`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level1](#firehol_level1)|5138|688854748|5120|0.0%|100.0%|
[alienvault_reputation](#alienvault_reputation)|187341|187341|2564|1.3%|50.0%|
[et_block](#et_block)|1000|18344011|1024|0.0%|20.0%|
[dragon_http](#dragon_http)|1029|270336|512|0.1%|10.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|256|0.0%|5.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|256|0.0%|5.0%|
[firehol_level3](#firehol_level3)|109658|9627424|88|0.0%|1.7%|
[firehol_level2](#firehol_level2)|22007|33621|80|0.2%|1.5%|
[blocklist_de](#blocklist_de)|28426|28426|80|0.2%|1.5%|
[openbl_60d](#openbl_60d)|6978|6978|78|1.1%|1.5%|
[shunlist](#shunlist)|1151|1151|77|6.6%|1.5%|
[blocklist_de_ssh](#blocklist_de_ssh)|2423|2423|76|3.1%|1.4%|
[dragon_sshpauth](#dragon_sshpauth)|1633|1695|73|4.3%|1.4%|
[openbl_30d](#openbl_30d)|2805|2805|70|2.4%|1.3%|
[et_compromised](#et_compromised)|1721|1721|59|3.4%|1.1%|
[bruteforceblocker](#bruteforceblocker)|1695|1695|19|1.1%|0.3%|
[openbl_7d](#openbl_7d)|635|635|15|2.3%|0.2%|
[openbl_1d](#openbl_1d)|148|148|4|2.7%|0.0%|
[ciarmy](#ciarmy)|488|488|4|0.8%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14346|14346|4|0.0%|0.0%|
[dragon_vncprobe](#dragon_vncprobe)|88|88|3|3.4%|0.0%|
[sorbs_spam](#sorbs_spam)|64701|65536|2|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|2|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|2|0.0%|0.0%|
[nixspam](#nixspam)|22818|22818|2|0.0%|0.0%|
[malc0de](#malc0de)|276|276|1|0.3%|0.0%|

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
[firehol_level1](#firehol_level1)|5138|688854748|18339658|2.6%|99.9%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|18338560|99.9%|99.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|8532520|2.4%|46.5%|
[firehol_level3](#firehol_level3)|109658|9627424|6933381|72.0%|37.7%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|6932480|75.5%|37.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|2272548|0.2%|12.3%|
[fullbogons](#fullbogons)|3775|670173256|151552|0.0%|0.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|130394|0.0%|0.7%|
[alienvault_reputation](#alienvault_reputation)|187341|187341|4777|2.5%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1042|0.3%|0.0%|
[dshield](#dshield)|20|5120|1024|20.0%|0.0%|
[dragon_http](#dragon_http)|1029|270336|1024|0.3%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|1018|1.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|517|0.1%|0.0%|
[openbl_60d](#openbl_60d)|6978|6978|299|4.2%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9671|9671|297|3.0%|0.0%|
[firehol_level2](#firehol_level2)|22007|33621|286|0.8%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|272|0.9%|0.0%|
[zeus](#zeus)|230|230|228|99.1%|0.0%|
[blocklist_de](#blocklist_de)|28426|28426|221|0.7%|0.0%|
[zeus_badips](#zeus_badips)|202|202|202|100.0%|0.0%|
[openbl_30d](#openbl_30d)|2805|2805|163|5.8%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2423|2423|138|5.6%|0.0%|
[et_compromised](#et_compromised)|1721|1721|109|6.3%|0.0%|
[feodo](#feodo)|105|105|104|99.0%|0.0%|
[dragon_sshpauth](#dragon_sshpauth)|1633|1695|102|6.0%|0.0%|
[shunlist](#shunlist)|1151|1151|98|8.5%|0.0%|
[nixspam](#nixspam)|22818|22818|81|0.3%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6697|6697|79|1.1%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1695|1695|69|4.0%|0.0%|
[openbl_7d](#openbl_7d)|635|635|62|9.7%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|2960|2960|49|1.6%|0.0%|
[sslbl](#sslbl)|371|371|38|10.2%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|30|2.3%|0.0%|
[php_commenters](#php_commenters)|458|458|29|6.3%|0.0%|
[sorbs_spam](#sorbs_spam)|64701|65536|22|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|22|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|22|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|18299|18299|22|0.1%|0.0%|
[openbl_1d](#openbl_1d)|148|148|21|14.1%|0.0%|
[voipbl](#voipbl)|10586|10998|14|0.1%|0.0%|
[palevo](#palevo)|13|13|13|100.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2839|2839|10|0.3%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14346|14346|10|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|172|172|7|4.0%|0.0%|
[php_dictionary](#php_dictionary)|737|737|6|0.8%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|6|0.4%|0.0%|
[firehol_anonymous](#firehol_anonymous)|19168|83212|6|0.0%|0.0%|
[ciarmy](#ciarmy)|488|488|6|1.2%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2901|2901|6|0.2%|0.0%|
[malc0de](#malc0de)|276|276|5|1.8%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|5|0.0%|0.0%|
[dragon_vncprobe](#dragon_vncprobe)|88|88|5|5.6%|0.0%|
[php_spammers](#php_spammers)|735|735|4|0.5%|0.0%|
[nt_malware_http](#nt_malware_http)|69|69|4|5.7%|0.0%|
[nt_malware_irc](#nt_malware_irc)|43|43|3|6.9%|0.0%|
[iw_spamlist](#iw_spamlist)|3878|3878|3|0.0%|0.0%|
[firehol_proxies](#firehol_proxies)|12674|12945|3|0.0%|0.0%|
[et_tor](#et_tor)|6400|6400|3|0.0%|0.0%|
[dm_tor](#dm_tor)|6521|6521|3|0.0%|0.0%|
[bm_tor](#bm_tor)|6525|6525|3|0.0%|0.0%|
[tor_exits](#tor_exits)|1112|1112|2|0.1%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|2|0.3%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|84|84|2|2.3%|0.0%|
[php_harvesters](#php_harvesters)|408|408|1|0.2%|0.0%|
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
[alienvault_reputation](#alienvault_reputation)|187341|187341|4|0.0%|0.7%|
[firehol_level3](#firehol_level3)|109658|9627424|3|0.0%|0.5%|
[dragon_http](#dragon_http)|1029|270336|3|0.0%|0.5%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|1|0.0%|0.1%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|1|0.0%|0.1%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|1|0.0%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.1%|
[firehol_level1](#firehol_level1)|5138|688854748|1|0.0%|0.1%|
[et_block](#et_block)|1000|18344011|1|0.0%|0.1%|
[blocklist_de_sip](#blocklist_de_sip)|84|84|1|1.1%|0.1%|

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
[firehol_level3](#firehol_level3)|109658|9627424|1684|0.0%|97.8%|
[bruteforceblocker](#bruteforceblocker)|1695|1695|1624|95.8%|94.3%|
[alienvault_reputation](#alienvault_reputation)|187341|187341|1116|0.5%|64.8%|
[openbl_60d](#openbl_60d)|6978|6978|1014|14.5%|58.9%|
[openbl_30d](#openbl_30d)|2805|2805|944|33.6%|54.8%|
[dragon_sshpauth](#dragon_sshpauth)|1633|1695|657|38.7%|38.1%|
[firehol_level2](#firehol_level2)|22007|33621|569|1.6%|33.0%|
[blocklist_de](#blocklist_de)|28426|28426|567|1.9%|32.9%|
[blocklist_de_ssh](#blocklist_de_ssh)|2423|2423|562|23.1%|32.6%|
[shunlist](#shunlist)|1151|1151|368|31.9%|21.3%|
[openbl_7d](#openbl_7d)|635|635|311|48.9%|18.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|152|0.0%|8.8%|
[et_block](#et_block)|1000|18344011|109|0.0%|6.3%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|101|0.0%|5.8%|
[firehol_level1](#firehol_level1)|5138|688854748|101|0.0%|5.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|85|0.0%|4.9%|
[openbl_1d](#openbl_1d)|148|148|76|51.3%|4.4%|
[dshield](#dshield)|20|5120|59|1.1%|3.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|52|0.0%|3.0%|
[dragon_http](#dragon_http)|1029|270336|11|0.0%|0.6%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|10|0.0%|0.5%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|5|0.0%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|5|0.0%|0.2%|
[blocklist_de_mail](#blocklist_de_mail)|18299|18299|4|0.0%|0.2%|
[blocklist_de_imap](#blocklist_de_imap)|2839|2839|4|0.1%|0.2%|
[voipbl](#voipbl)|10586|10998|3|0.0%|0.1%|
[sorbs_spam](#sorbs_spam)|64701|65536|3|0.0%|0.1%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|3|0.0%|0.1%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|3|0.0%|0.1%|
[firehol_proxies](#firehol_proxies)|12674|12945|3|0.0%|0.1%|
[firehol_anonymous](#firehol_anonymous)|19168|83212|3|0.0%|0.1%|
[ciarmy](#ciarmy)|488|488|3|0.6%|0.1%|
[proxz](#proxz)|1323|1323|2|0.1%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|2|0.0%|0.1%|
[xroxy](#xroxy)|2169|2169|1|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6697|6697|1|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7852|7852|1|0.0%|0.0%|
[proxyrss](#proxyrss)|1638|1638|1|0.0%|0.0%|
[php_spammers](#php_spammers)|735|735|1|0.1%|0.0%|
[php_commenters](#php_commenters)|458|458|1|0.2%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|172|172|1|0.5%|0.0%|

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
[firehol_anonymous](#firehol_anonymous)|19168|83212|5668|6.8%|88.5%|
[bm_tor](#bm_tor)|6525|6525|5635|86.3%|88.0%|
[dm_tor](#dm_tor)|6521|6521|5632|86.3%|88.0%|
[firehol_level3](#firehol_level3)|109658|9627424|1124|0.0%|17.5%|
[snort_ipfilter](#snort_ipfilter)|9671|9671|1088|11.2%|17.0%|
[tor_exits](#tor_exits)|1112|1112|959|86.2%|14.9%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|653|0.6%|10.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|625|0.0%|9.7%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|547|1.8%|8.5%|
[firehol_level2](#firehol_level2)|22007|33621|319|0.9%|4.9%|
[stopforumspam_1d](#stopforumspam_1d)|6697|6697|307|4.5%|4.7%|
[firehol_proxies](#firehol_proxies)|12674|12945|238|1.8%|3.7%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|234|44.6%|3.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|181|0.0%|2.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|165|0.0%|2.5%|
[php_commenters](#php_commenters)|458|458|54|11.7%|0.8%|
[alienvault_reputation](#alienvault_reputation)|187341|187341|39|0.0%|0.6%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|22|0.0%|0.3%|
[openbl_60d](#openbl_60d)|6978|6978|20|0.2%|0.3%|
[dragon_http](#dragon_http)|1029|270336|15|0.0%|0.2%|
[blocklist_de_apache](#blocklist_de_apache)|14346|14346|15|0.1%|0.2%|
[blocklist_de](#blocklist_de)|28426|28426|15|0.0%|0.2%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2901|2901|13|0.4%|0.2%|
[php_harvesters](#php_harvesters)|408|408|7|1.7%|0.1%|
[php_spammers](#php_spammers)|735|735|5|0.6%|0.0%|
[nixspam](#nixspam)|22818|22818|5|0.0%|0.0%|
[sorbs_spam](#sorbs_spam)|64701|65536|4|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|4|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|4|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7852|7852|4|0.0%|0.0%|
[php_dictionary](#php_dictionary)|737|737|4|0.5%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|4|0.0%|0.0%|
[voipbl](#voipbl)|10586|10998|3|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|3|0.0%|0.0%|
[firehol_level1](#firehol_level1)|5138|688854748|3|0.0%|0.0%|
[et_block](#et_block)|1000|18344011|3|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|18299|18299|2|0.0%|0.0%|
[xroxy](#xroxy)|2169|2169|1|0.0%|0.0%|
[shunlist](#shunlist)|1151|1151|1|0.0%|0.0%|
[iw_spamlist](#iw_spamlist)|3878|3878|1|0.0%|0.0%|

## feodo

[Abuse.ch Feodo tracker](https://feodotracker.abuse.ch) trojan includes IPs which are being used by Feodo (also known as Cridex or Bugat) which commits ebanking fraud - **excellent list**

Source is downloaded from [this link](https://feodotracker.abuse.ch/blocklist/?download=ipblocklist).

The last time downloaded was found to be dated: Thu Jun 11 22:09:19 UTC 2015.

The ipset `feodo` has **105** entries, **105** unique IPs.

The following table shows the overlaps of `feodo` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `feodo`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `feodo`.
- ` this % ` is the percentage **of this ipset (`feodo`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level1](#firehol_level1)|5138|688854748|105|0.0%|100.0%|
[et_block](#et_block)|1000|18344011|104|0.0%|99.0%|
[snort_ipfilter](#snort_ipfilter)|9671|9671|83|0.8%|79.0%|
[firehol_level3](#firehol_level3)|109658|9627424|83|0.0%|79.0%|
[sslbl](#sslbl)|371|371|38|10.2%|36.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|11|0.0%|10.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|3|0.0%|2.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|3|0.0%|2.8%|
[alienvault_reputation](#alienvault_reputation)|187341|187341|2|0.0%|1.9%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.9%|

## firehol_anonymous

**FireHOL Anonymous** - Known anonymizing IPs. (includes: firehol_proxies anonymous bm_tor dm_tor tor_exits)

Source is downloaded from [this link]().

The last time downloaded was found to be dated: Sun Jun  7 22:20:34 UTC 2015.

The ipset `firehol_anonymous` has **19168** entries, **83212** unique IPs.

The following table shows the overlaps of `firehol_anonymous` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `firehol_anonymous`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `firehol_anonymous`.
- ` this % ` is the percentage **of this ipset (`firehol_anonymous`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_proxies](#firehol_proxies)|12674|12945|12945|100.0%|15.5%|
[ri_web_proxies](#ri_web_proxies)|7852|7852|7852|100.0%|9.4%|
[firehol_level3](#firehol_level3)|109658|9627424|6796|0.0%|8.1%|
[bm_tor](#bm_tor)|6525|6525|6525|100.0%|7.8%|
[dm_tor](#dm_tor)|6521|6521|6521|100.0%|7.8%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|6215|6.5%|7.4%|
[et_tor](#et_tor)|6400|6400|5668|88.5%|6.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|3450|0.0%|4.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|2899|0.0%|3.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|2868|0.0%|3.4%|
[ri_connect_proxies](#ri_connect_proxies)|2828|2828|2828|100.0%|3.3%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|2758|9.4%|3.3%|
[xroxy](#xroxy)|2169|2169|2169|100.0%|2.6%|
[proxyrss](#proxyrss)|1638|1638|1638|100.0%|1.9%|
[firehol_level2](#firehol_level2)|22007|33621|1330|3.9%|1.5%|
[proxz](#proxz)|1323|1323|1323|100.0%|1.5%|
[snort_ipfilter](#snort_ipfilter)|9671|9671|1246|12.8%|1.4%|
[tor_exits](#tor_exits)|1112|1112|1112|100.0%|1.3%|
[stopforumspam_1d](#stopforumspam_1d)|6697|6697|972|14.5%|1.1%|
[blocklist_de](#blocklist_de)|28426|28426|685|2.4%|0.8%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|663|100.0%|0.7%|
[blocklist_de_bots](#blocklist_de_bots)|2960|2960|533|18.0%|0.6%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|524|100.0%|0.6%|
[sorbs_spam](#sorbs_spam)|64701|65536|201|0.3%|0.2%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|201|0.3%|0.2%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|201|0.3%|0.2%|
[nixspam](#nixspam)|22818|22818|174|0.7%|0.2%|
[blocklist_de_mail](#blocklist_de_mail)|18299|18299|126|0.6%|0.1%|
[php_dictionary](#php_dictionary)|737|737|98|13.2%|0.1%|
[php_commenters](#php_commenters)|458|458|90|19.6%|0.1%|
[php_spammers](#php_spammers)|735|735|82|11.1%|0.0%|
[voipbl](#voipbl)|10586|10998|79|0.7%|0.0%|
[alienvault_reputation](#alienvault_reputation)|187341|187341|57|0.0%|0.0%|
[dragon_http](#dragon_http)|1029|270336|41|0.0%|0.0%|
[sorbs_web](#sorbs_web)|568|569|29|5.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|29|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14346|14346|25|0.1%|0.0%|
[openbl_60d](#openbl_60d)|6978|6978|23|0.3%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2901|2901|22|0.7%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|16|0.0%|0.0%|
[iw_spamlist](#iw_spamlist)|3878|3878|14|0.3%|0.0%|
[php_harvesters](#php_harvesters)|408|408|12|2.9%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|172|172|9|5.2%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|7|0.0%|0.0%|
[firehol_level1](#firehol_level1)|5138|688854748|7|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|6|0.0%|0.0%|
[et_block](#et_block)|1000|18344011|6|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|1526|1526|4|0.2%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|3|0.2%|0.0%|
[et_compromised](#et_compromised)|1721|1721|3|0.1%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1695|1695|3|0.1%|0.0%|
[sslbl](#sslbl)|371|371|1|0.2%|0.0%|
[shunlist](#shunlist)|1151|1151|1|0.0%|0.0%|
[openbl_30d](#openbl_30d)|2805|2805|1|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2423|2423|1|0.0%|0.0%|

## firehol_level1

**FireHOL Level 1** - Maximum protection without false positives. (includes: fullbogons dshield feodo palevo sslbl zeus spamhaus_drop spamhaus_edrop)

Source is downloaded from [this link]().

The last time downloaded was found to be dated: Sun Jun  7 22:15:43 UTC 2015.

The ipset `firehol_level1` has **5138** entries, **688854748** unique IPs.

The following table shows the overlaps of `firehol_level1` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `firehol_level1`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `firehol_level1`.
- ` this % ` is the percentage **of this ipset (`firehol_level1`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[fullbogons](#fullbogons)|3775|670173256|670173256|100.0%|97.2%|
[bogons](#bogons)|13|592708608|592708608|100.0%|86.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|18340608|100.0%|2.6%|
[et_block](#et_block)|1000|18344011|18339658|99.9%|2.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|8867973|2.5%|1.2%|
[firehol_level3](#firehol_level3)|109658|9627424|7500162|77.9%|1.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|7498240|81.6%|1.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|4637346|3.3%|0.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|2570306|0.3%|0.3%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|487424|100.0%|0.0%|
[dshield](#dshield)|20|5120|5120|100.0%|0.0%|
[alienvault_reputation](#alienvault_reputation)|187341|187341|3833|2.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1932|0.5%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|1090|1.1%|0.0%|
[dragon_http](#dragon_http)|1029|270336|769|0.2%|0.0%|
[sslbl](#sslbl)|371|371|371|100.0%|0.0%|
[voipbl](#voipbl)|10586|10998|333|3.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9671|9671|299|3.0%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|278|0.9%|0.0%|
[firehol_level2](#firehol_level2)|22007|33621|277|0.8%|0.0%|
[openbl_60d](#openbl_60d)|6978|6978|247|3.5%|0.0%|
[zeus](#zeus)|230|230|230|100.0%|0.0%|
[blocklist_de](#blocklist_de)|28426|28426|211|0.7%|0.0%|
[zeus_badips](#zeus_badips)|202|202|202|100.0%|0.0%|
[shunlist](#shunlist)|1151|1151|153|13.2%|0.0%|
[openbl_30d](#openbl_30d)|2805|2805|125|4.4%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2423|2423|122|5.0%|0.0%|
[feodo](#feodo)|105|105|105|100.0%|0.0%|
[et_compromised](#et_compromised)|1721|1721|101|5.8%|0.0%|
[dragon_sshpauth](#dragon_sshpauth)|1633|1695|99|5.8%|0.0%|
[nixspam](#nixspam)|22818|22818|86|0.3%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6697|6697|81|1.2%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1695|1695|61|3.5%|0.0%|
[openbl_7d](#openbl_7d)|635|635|54|8.5%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|2960|2960|54|1.8%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|39|3.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|39|2.6%|0.0%|
[php_commenters](#php_commenters)|458|458|38|8.2%|0.0%|
[sorbs_spam](#sorbs_spam)|64701|65536|27|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|27|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|27|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|18299|18299|24|0.1%|0.0%|
[openbl_1d](#openbl_1d)|148|148|20|13.5%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|18|0.0%|0.0%|
[palevo](#palevo)|13|13|13|100.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2839|2839|10|0.3%|0.0%|
[iw_spamlist](#iw_spamlist)|3878|3878|9|0.2%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|172|172|9|5.2%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14346|14346|9|0.0%|0.0%|
[nt_malware_http](#nt_malware_http)|69|69|8|11.5%|0.0%|
[firehol_anonymous](#firehol_anonymous)|19168|83212|7|0.0%|0.0%|
[php_dictionary](#php_dictionary)|737|737|6|0.8%|0.0%|
[malc0de](#malc0de)|276|276|6|2.1%|0.0%|
[ciarmy](#ciarmy)|488|488|5|1.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2901|2901|5|0.1%|0.0%|
[php_spammers](#php_spammers)|735|735|4|0.5%|0.0%|
[firehol_proxies](#firehol_proxies)|12674|12945|4|0.0%|0.0%|
[dragon_vncprobe](#dragon_vncprobe)|88|88|4|4.5%|0.0%|
[php_harvesters](#php_harvesters)|408|408|3|0.7%|0.0%|
[nt_malware_irc](#nt_malware_irc)|43|43|3|6.9%|0.0%|
[et_tor](#et_tor)|6400|6400|3|0.0%|0.0%|
[dm_tor](#dm_tor)|6521|6521|3|0.0%|0.0%|
[bm_tor](#bm_tor)|6525|6525|3|0.0%|0.0%|
[tor_exits](#tor_exits)|1112|1112|2|0.1%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|2|0.3%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|84|84|2|2.3%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7852|7852|1|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|1|0.1%|0.0%|
[et_botcc](#et_botcc)|506|506|1|0.1%|0.0%|

## firehol_level2

**FireHOL Level 2** - Maximum protection from attacks took place in the last 48 hours. (includes: openbl_1d blocklist_de stopforumspam_1d)

Source is downloaded from [this link]().

The last time downloaded was found to be dated: Sun Jun  7 22:20:34 UTC 2015.

The ipset `firehol_level2` has **22007** entries, **33621** unique IPs.

The following table shows the overlaps of `firehol_level2` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `firehol_level2`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `firehol_level2`.
- ` this % ` is the percentage **of this ipset (`firehol_level2`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|28426|28426|28426|100.0%|84.5%|
[blocklist_de_mail](#blocklist_de_mail)|18299|18299|18290|99.9%|54.4%|
[blocklist_de_apache](#blocklist_de_apache)|14346|14346|14240|99.2%|42.3%|
[firehol_level3](#firehol_level3)|109658|9627424|8083|0.0%|24.0%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|6935|7.3%|20.6%|
[stopforumspam_1d](#stopforumspam_1d)|6697|6697|6697|100.0%|19.9%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|4915|16.8%|14.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|3818|0.0%|11.3%|
[blocklist_de_bots](#blocklist_de_bots)|2960|2960|2955|99.8%|8.7%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2901|2901|2869|98.8%|8.5%|
[blocklist_de_imap](#blocklist_de_imap)|2839|2839|2839|100.0%|8.4%|
[blocklist_de_ssh](#blocklist_de_ssh)|2423|2423|2423|100.0%|7.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|1699|0.0%|5.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|1688|0.0%|5.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|1526|1526|1526|100.0%|4.5%|
[sorbs_spam](#sorbs_spam)|64701|65536|1415|2.1%|4.2%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|1407|2.1%|4.1%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|1407|2.1%|4.1%|
[firehol_anonymous](#firehol_anonymous)|19168|83212|1330|1.5%|3.9%|
[alienvault_reputation](#alienvault_reputation)|187341|187341|1200|0.6%|3.5%|
[firehol_proxies](#firehol_proxies)|12674|12945|1179|9.1%|3.5%|
[openbl_60d](#openbl_60d)|6978|6978|841|12.0%|2.5%|
[nixspam](#nixspam)|22818|22818|705|3.0%|2.0%|
[dragon_sshpauth](#dragon_sshpauth)|1633|1695|695|41.0%|2.0%|
[openbl_30d](#openbl_30d)|2805|2805|690|24.5%|2.0%|
[ri_web_proxies](#ri_web_proxies)|7852|7852|659|8.3%|1.9%|
[bruteforceblocker](#bruteforceblocker)|1695|1695|582|34.3%|1.7%|
[et_compromised](#et_compromised)|1721|1721|569|33.0%|1.6%|
[snort_ipfilter](#snort_ipfilter)|9671|9671|537|5.5%|1.5%|
[openbl_7d](#openbl_7d)|635|635|395|62.2%|1.1%|
[proxyrss](#proxyrss)|1638|1638|388|23.6%|1.1%|
[shunlist](#shunlist)|1151|1151|365|31.7%|1.0%|
[tor_exits](#tor_exits)|1112|1112|331|29.7%|0.9%|
[et_tor](#et_tor)|6400|6400|319|4.9%|0.9%|
[xroxy](#xroxy)|2169|2169|315|14.5%|0.9%|
[dm_tor](#dm_tor)|6521|6521|313|4.7%|0.9%|
[bm_tor](#bm_tor)|6525|6525|313|4.7%|0.9%|
[et_block](#et_block)|1000|18344011|286|0.0%|0.8%|
[proxz](#proxz)|1323|1323|283|21.3%|0.8%|
[firehol_level1](#firehol_level1)|5138|688854748|277|0.0%|0.8%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|262|0.0%|0.7%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|209|39.8%|0.6%|
[php_commenters](#php_commenters)|458|458|200|43.6%|0.5%|
[blocklist_de_strongips](#blocklist_de_strongips)|172|172|172|100.0%|0.5%|
[ri_connect_proxies](#ri_connect_proxies)|2828|2828|154|5.4%|0.4%|
[openbl_1d](#openbl_1d)|148|148|148|100.0%|0.4%|
[iw_spamlist](#iw_spamlist)|3878|3878|148|3.8%|0.4%|
[php_dictionary](#php_dictionary)|737|737|127|17.2%|0.3%|
[php_spammers](#php_spammers)|735|735|117|15.9%|0.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|85|0.0%|0.2%|
[dshield](#dshield)|20|5120|80|1.5%|0.2%|
[sorbs_web](#sorbs_web)|568|569|68|11.9%|0.2%|
[blocklist_de_sip](#blocklist_de_sip)|84|84|65|77.3%|0.1%|
[dragon_http](#dragon_http)|1029|270336|62|0.0%|0.1%|
[php_harvesters](#php_harvesters)|408|408|59|14.4%|0.1%|
[voipbl](#voipbl)|10586|10998|46|0.4%|0.1%|
[ciarmy](#ciarmy)|488|488|38|7.7%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|15|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|15|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|9|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|8|1.2%|0.0%|
[dragon_vncprobe](#dragon_vncprobe)|88|88|5|5.6%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|3|0.2%|0.0%|
[zeus_badips](#zeus_badips)|202|202|1|0.4%|0.0%|
[zeus](#zeus)|230|230|1|0.4%|0.0%|
[sorbs_socks](#sorbs_socks)|7|7|1|14.2%|0.0%|
[sorbs_misc](#sorbs_misc)|7|7|1|14.2%|0.0%|
[sorbs_http](#sorbs_http)|7|7|1|14.2%|0.0%|
[iw_wormlist](#iw_wormlist)|35|35|1|2.8%|0.0%|

## firehol_level3

**FireHOL Level 3** - All the bad IPs in last 30 days. (includes: openbl_30d stopforumspam_30d virbl malc0de shunlist malwaredomainlist bruteforceblocker ciarmy cleanmx_viruses snort_ipfilter ib_bluetack_spyware ib_bluetack_hijacked ib_bluetack_webexploit php_commenters php_dictionary php_harvesters php_spammers iw_wormlist)

Source is downloaded from [this link]().

The last time downloaded was found to be dated: Sun Jun  7 22:20:34 UTC 2015.

The ipset `firehol_level3` has **109658** entries, **9627424** unique IPs.

The following table shows the overlaps of `firehol_level3` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `firehol_level3`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `firehol_level3`.
- ` this % ` is the percentage **of this ipset (`firehol_level3`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|9177856|100.0%|95.3%|
[firehol_level1](#firehol_level1)|5138|688854748|7500162|1.0%|77.9%|
[et_block](#et_block)|1000|18344011|6933381|37.7%|72.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|6933039|37.8%|72.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|2537271|0.7%|26.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|919973|0.1%|9.5%|
[fullbogons](#fullbogons)|3775|670173256|566692|0.0%|5.8%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|339173|100.0%|3.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|161583|0.1%|1.6%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|94309|100.0%|0.9%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|29184|99.9%|0.3%|
[snort_ipfilter](#snort_ipfilter)|9671|9671|9671|100.0%|0.1%|
[firehol_level2](#firehol_level2)|22007|33621|8083|24.0%|0.0%|
[firehol_anonymous](#firehol_anonymous)|19168|83212|6796|8.1%|0.0%|
[firehol_proxies](#firehol_proxies)|12674|12945|5676|43.8%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6697|6697|5631|84.0%|0.0%|
[alienvault_reputation](#alienvault_reputation)|187341|187341|4903|2.6%|0.0%|
[blocklist_de](#blocklist_de)|28426|28426|3857|13.5%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7852|7852|3743|47.6%|0.0%|
[openbl_60d](#openbl_60d)|6978|6978|2931|42.0%|0.0%|
[openbl_30d](#openbl_30d)|2805|2805|2805|100.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|2960|2960|2412|81.4%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1695|1695|1695|100.0%|0.0%|
[et_compromised](#et_compromised)|1721|1721|1684|97.8%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2828|2828|1586|56.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|1450|100.0%|0.0%|
[xroxy](#xroxy)|2169|2169|1301|59.9%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|1288|100.0%|0.0%|
[sorbs_spam](#sorbs_spam)|64701|65536|1254|1.9%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|1252|1.9%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|1252|1.9%|0.0%|
[shunlist](#shunlist)|1151|1151|1151|100.0%|0.0%|
[et_tor](#et_tor)|6400|6400|1124|17.5%|0.0%|
[bm_tor](#bm_tor)|6525|6525|1096|16.7%|0.0%|
[dm_tor](#dm_tor)|6521|6521|1095|16.7%|0.0%|
[tor_exits](#tor_exits)|1112|1112|1086|97.6%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2423|2423|870|35.9%|0.0%|
[dragon_sshpauth](#dragon_sshpauth)|1633|1695|864|50.9%|0.0%|
[proxz](#proxz)|1323|1323|782|59.1%|0.0%|
[php_dictionary](#php_dictionary)|737|737|737|100.0%|0.0%|
[php_spammers](#php_spammers)|735|735|735|100.0%|0.0%|
[proxyrss](#proxyrss)|1638|1638|709|43.2%|0.0%|
[openbl_7d](#openbl_7d)|635|635|635|100.0%|0.0%|
[dragon_http](#dragon_http)|1029|270336|558|0.2%|0.0%|
[nixspam](#nixspam)|22818|22818|501|2.1%|0.0%|
[ciarmy](#ciarmy)|488|488|488|100.0%|0.0%|
[php_commenters](#php_commenters)|458|458|458|100.0%|0.0%|
[php_harvesters](#php_harvesters)|408|408|408|100.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|18299|18299|407|2.2%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|346|66.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14346|14346|287|2.0%|0.0%|
[malc0de](#malc0de)|276|276|276|100.0%|0.0%|
[zeus](#zeus)|230|230|203|88.2%|0.0%|
[zeus_badips](#zeus_badips)|202|202|180|89.1%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|172|172|159|92.4%|0.0%|
[openbl_1d](#openbl_1d)|148|148|145|97.9%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|121|121|121|100.0%|0.0%|
[iw_spamlist](#iw_spamlist)|3878|3878|93|2.3%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2901|2901|93|3.2%|0.0%|
[sslbl](#sslbl)|371|371|89|23.9%|0.0%|
[dshield](#dshield)|20|5120|88|1.7%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|85|0.0%|0.0%|
[feodo](#feodo)|105|105|83|79.0%|0.0%|
[sorbs_web](#sorbs_web)|568|569|69|12.1%|0.0%|
[voipbl](#voipbl)|10586|10998|57|0.5%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2839|2839|37|1.3%|0.0%|
[iw_wormlist](#iw_wormlist)|35|35|35|100.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|25|3.7%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|25|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|1526|1526|22|1.4%|0.0%|
[virbl](#virbl)|19|19|19|100.0%|0.0%|
[palevo](#palevo)|13|13|11|84.6%|0.0%|
[dragon_vncprobe](#dragon_vncprobe)|88|88|6|6.8%|0.0%|
[sorbs_socks](#sorbs_socks)|7|7|4|57.1%|0.0%|
[sorbs_misc](#sorbs_misc)|7|7|4|57.1%|0.0%|
[sorbs_http](#sorbs_http)|7|7|4|57.1%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|84|84|4|4.7%|0.0%|
[nt_malware_http](#nt_malware_http)|69|69|3|4.3%|0.0%|
[et_botcc](#et_botcc)|506|506|3|0.5%|0.0%|
[bogons](#bogons)|13|592708608|3|0.0%|0.0%|
[nt_malware_irc](#nt_malware_irc)|43|43|1|2.3%|0.0%|

## firehol_proxies

**FireHOL Proxies** - Known open proxies in the last 30 days. (includes: ib_bluetack_proxies maxmind_proxy_fraud proxyrss proxz ri_connect_proxies ri_web_proxies xroxy)

Source is downloaded from [this link]().

The last time downloaded was found to be dated: Sun Jun  7 22:20:34 UTC 2015.

The ipset `firehol_proxies` has **12674** entries, **12945** unique IPs.

The following table shows the overlaps of `firehol_proxies` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `firehol_proxies`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `firehol_proxies`.
- ` this % ` is the percentage **of this ipset (`firehol_proxies`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_anonymous](#firehol_anonymous)|19168|83212|12945|15.5%|100.0%|
[ri_web_proxies](#ri_web_proxies)|7852|7852|7852|100.0%|60.6%|
[firehol_level3](#firehol_level3)|109658|9627424|5676|0.0%|43.8%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|5611|5.9%|43.3%|
[ri_connect_proxies](#ri_connect_proxies)|2828|2828|2828|100.0%|21.8%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|2390|8.1%|18.4%|
[xroxy](#xroxy)|2169|2169|2169|100.0%|16.7%|
[proxyrss](#proxyrss)|1638|1638|1638|100.0%|12.6%|
[proxz](#proxz)|1323|1323|1323|100.0%|10.2%|
[firehol_level2](#firehol_level2)|22007|33621|1179|3.5%|9.1%|
[stopforumspam_1d](#stopforumspam_1d)|6697|6697|841|12.5%|6.4%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|663|100.0%|5.1%|
[blocklist_de](#blocklist_de)|28426|28426|658|2.3%|5.0%|
[blocklist_de_bots](#blocklist_de_bots)|2960|2960|532|17.9%|4.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|525|0.0%|4.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|524|100.0%|4.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|394|0.0%|3.0%|
[snort_ipfilter](#snort_ipfilter)|9671|9671|330|3.4%|2.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|296|0.0%|2.2%|
[et_tor](#et_tor)|6400|6400|238|3.7%|1.8%|
[dm_tor](#dm_tor)|6521|6521|236|3.6%|1.8%|
[bm_tor](#bm_tor)|6525|6525|236|3.6%|1.8%|
[tor_exits](#tor_exits)|1112|1112|230|20.6%|1.7%|
[sorbs_spam](#sorbs_spam)|64701|65536|196|0.2%|1.5%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|196|0.3%|1.5%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|196|0.3%|1.5%|
[nixspam](#nixspam)|22818|22818|166|0.7%|1.2%|
[blocklist_de_mail](#blocklist_de_mail)|18299|18299|124|0.6%|0.9%|
[php_dictionary](#php_dictionary)|737|737|97|13.1%|0.7%|
[php_commenters](#php_commenters)|458|458|86|18.7%|0.6%|
[php_spammers](#php_spammers)|735|735|80|10.8%|0.6%|
[alienvault_reputation](#alienvault_reputation)|187341|187341|38|0.0%|0.2%|
[dragon_http](#dragon_http)|1029|270336|30|0.0%|0.2%|
[sorbs_web](#sorbs_web)|568|569|29|5.0%|0.2%|
[openbl_60d](#openbl_60d)|6978|6978|20|0.2%|0.1%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|16|0.0%|0.1%|
[iw_spamlist](#iw_spamlist)|3878|3878|13|0.3%|0.1%|
[php_harvesters](#php_harvesters)|408|408|12|2.9%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|11|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|172|172|9|5.2%|0.0%|
[firehol_level1](#firehol_level1)|5138|688854748|4|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|3|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|3|0.2%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|0.0%|
[et_compromised](#et_compromised)|1721|1721|3|0.1%|0.0%|
[et_block](#et_block)|1000|18344011|3|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1695|1695|3|0.1%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14346|14346|3|0.0%|0.0%|
[voipbl](#voipbl)|10586|10998|2|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2901|2901|2|0.0%|0.0%|
[sslbl](#sslbl)|371|371|1|0.2%|0.0%|
[shunlist](#shunlist)|1151|1151|1|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2423|2423|1|0.0%|0.0%|

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
[firehol_level1](#firehol_level1)|5138|688854748|670173256|97.2%|100.0%|
[bogons](#bogons)|13|592708608|592708608|100.0%|88.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|4236143|3.0%|0.6%|
[firehol_level3](#firehol_level3)|109658|9627424|566692|5.8%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|565760|6.1%|0.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|264873|0.0%|0.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|252671|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|151552|0.8%|0.0%|
[et_block](#et_block)|1000|18344011|151552|0.8%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|890|0.2%|0.0%|
[voipbl](#voipbl)|10586|10998|319|2.9%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|33|2.2%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|13|0.0%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|9|0.6%|0.0%|
[iw_spamlist](#iw_spamlist)|3878|3878|5|0.1%|0.0%|
[nt_malware_http](#nt_malware_http)|69|69|4|5.7%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|2|0.0%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|1|0.0%|0.0%|
[php_harvesters](#php_harvesters)|408|408|1|0.2%|0.0%|
[php_commenters](#php_commenters)|458|458|1|0.2%|0.0%|
[ciarmy](#ciarmy)|488|488|1|0.2%|0.0%|

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
[dragon_http](#dragon_http)|1029|270336|26|0.0%|0.0%|
[firehol_level3](#firehol_level3)|109658|9627424|25|0.0%|0.0%|
[firehol_level1](#firehol_level1)|5138|688854748|18|0.0%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|17|0.0%|0.0%|
[sorbs_spam](#sorbs_spam)|64701|65536|17|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|17|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|17|0.0%|0.0%|
[firehol_proxies](#firehol_proxies)|12674|12945|16|0.1%|0.0%|
[firehol_anonymous](#firehol_anonymous)|19168|83212|16|0.0%|0.0%|
[firehol_level2](#firehol_level2)|22007|33621|15|0.0%|0.0%|
[blocklist_de](#blocklist_de)|28426|28426|15|0.0%|0.0%|
[alienvault_reputation](#alienvault_reputation)|187341|187341|15|0.0%|0.0%|
[fullbogons](#fullbogons)|3775|670173256|13|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|11|1.6%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|18299|18299|11|0.0%|0.0%|
[nixspam](#nixspam)|22818|22818|9|0.0%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|7|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|5|0.0%|0.0%|
[et_block](#et_block)|1000|18344011|5|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7852|7852|4|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2839|2839|4|0.1%|0.0%|
[xroxy](#xroxy)|2169|2169|3|0.1%|0.0%|
[php_dictionary](#php_dictionary)|737|737|3|0.4%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|3|0.0%|0.0%|
[voipbl](#voipbl)|10586|10998|2|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9671|9671|2|0.0%|0.0%|
[php_harvesters](#php_harvesters)|408|408|2|0.4%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2901|2901|2|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14346|14346|2|0.0%|0.0%|
[sorbs_web](#sorbs_web)|568|569|1|0.1%|0.0%|
[proxz](#proxz)|1323|1323|1|0.0%|0.0%|
[proxyrss](#proxyrss)|1638|1638|1|0.0%|0.0%|
[php_spammers](#php_spammers)|735|735|1|0.1%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|1|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2423|2423|1|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|1526|1526|1|0.0%|0.0%|

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
[firehol_level3](#firehol_level3)|109658|9627424|9177856|95.3%|100.0%|
[firehol_level1](#firehol_level1)|5138|688854748|7498240|1.0%|81.6%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|6932480|37.7%|75.5%|
[et_block](#et_block)|1000|18344011|6932480|37.7%|75.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|2526625|0.7%|27.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|904796|0.1%|9.8%|
[fullbogons](#fullbogons)|3775|670173256|565760|0.0%|6.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|145472|0.1%|1.5%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1036|0.3%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|725|0.7%|0.0%|
[alienvault_reputation](#alienvault_reputation)|187341|187341|278|0.1%|0.0%|
[dragon_http](#dragon_http)|1029|270336|256|0.0%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|147|0.5%|0.0%|
[firehol_level2](#firehol_level2)|22007|33621|85|0.2%|0.0%|
[nixspam](#nixspam)|22818|22818|81|0.3%|0.0%|
[blocklist_de](#blocklist_de)|28426|28426|58|0.2%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|2960|2960|45|1.5%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6697|6697|31|0.4%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|27|2.0%|0.0%|
[openbl_60d](#openbl_60d)|6978|6978|16|0.2%|0.0%|
[openbl_30d](#openbl_30d)|2805|2805|12|0.4%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9671|9671|11|0.1%|0.0%|
[zeus_badips](#zeus_badips)|202|202|10|4.9%|0.0%|
[zeus](#zeus)|230|230|10|4.3%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|7|0.4%|0.0%|
[firehol_anonymous](#firehol_anonymous)|19168|83212|7|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2423|2423|7|0.2%|0.0%|
[et_compromised](#et_compromised)|1721|1721|5|0.2%|0.0%|
[dragon_sshpauth](#dragon_sshpauth)|1633|1695|5|0.2%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1695|1695|5|0.2%|0.0%|
[php_dictionary](#php_dictionary)|737|737|4|0.5%|0.0%|
[openbl_7d](#openbl_7d)|635|635|4|0.6%|0.0%|
[et_tor](#et_tor)|6400|6400|4|0.0%|0.0%|
[dm_tor](#dm_tor)|6521|6521|4|0.0%|0.0%|
[bm_tor](#bm_tor)|6525|6525|4|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|18299|18299|4|0.0%|0.0%|
[php_spammers](#php_spammers)|735|735|3|0.4%|0.0%|
[nt_malware_http](#nt_malware_http)|69|69|3|4.3%|0.0%|
[iw_spamlist](#iw_spamlist)|3878|3878|3|0.0%|0.0%|
[firehol_proxies](#firehol_proxies)|12674|12945|3|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|172|172|3|1.7%|0.0%|
[tor_exits](#tor_exits)|1112|1112|2|0.1%|0.0%|
[shunlist](#shunlist)|1151|1151|2|0.1%|0.0%|
[openbl_1d](#openbl_1d)|148|148|2|1.3%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|2|0.3%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2839|2839|2|0.0%|0.0%|
[voipbl](#voipbl)|10586|10998|1|0.0%|0.0%|
[sorbs_spam](#sorbs_spam)|64701|65536|1|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|1|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|1|0.0%|0.0%|
[php_harvesters](#php_harvesters)|408|408|1|0.2%|0.0%|
[php_commenters](#php_commenters)|458|458|1|0.2%|0.0%|
[nt_malware_irc](#nt_malware_irc)|43|43|1|2.3%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|1|0.1%|0.0%|
[et_botcc](#et_botcc)|506|506|1|0.1%|0.0%|
[dragon_vncprobe](#dragon_vncprobe)|88|88|1|1.1%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|1526|1526|1|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2901|2901|1|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14346|14346|1|0.0%|0.0%|

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
[firehol_level1](#firehol_level1)|5138|688854748|2570306|0.3%|0.3%|
[et_block](#et_block)|1000|18344011|2272548|12.3%|0.2%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|2272265|12.3%|0.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|1354507|0.9%|0.1%|
[firehol_level3](#firehol_level3)|109658|9627424|919973|9.5%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|904796|9.8%|0.1%|
[fullbogons](#fullbogons)|3775|670173256|264873|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|33155|6.8%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|13247|3.9%|0.0%|
[dragon_http](#dragon_http)|1029|270336|6284|2.3%|0.0%|
[alienvault_reputation](#alienvault_reputation)|187341|187341|4185|2.2%|0.0%|
[firehol_anonymous](#firehol_anonymous)|19168|83212|3450|4.1%|0.0%|
[firehol_level2](#firehol_level2)|22007|33621|1699|5.0%|0.0%|
[blocklist_de](#blocklist_de)|28426|28426|1600|5.6%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|1522|1.6%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|18299|18299|1430|7.8%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14346|14346|1324|9.2%|0.0%|
[sorbs_spam](#sorbs_spam)|64701|65536|1208|1.8%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|1205|1.8%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|1205|1.8%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|506|1.7%|0.0%|
[nixspam](#nixspam)|22818|22818|495|2.1%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|394|0.8%|0.0%|
[voipbl](#voipbl)|10586|10998|302|2.7%|0.0%|
[firehol_proxies](#firehol_proxies)|12674|12945|296|2.2%|0.0%|
[dm_tor](#dm_tor)|6521|6521|169|2.5%|0.0%|
[bm_tor](#bm_tor)|6525|6525|169|2.5%|0.0%|
[et_tor](#et_tor)|6400|6400|165|2.5%|0.0%|
[openbl_60d](#openbl_60d)|6978|6978|163|2.3%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7852|7852|156|1.9%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6697|6697|123|1.8%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9671|9671|116|1.1%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|97|6.6%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2828|2828|86|3.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2839|2839|76|2.6%|0.0%|
[iw_spamlist](#iw_spamlist)|3878|3878|72|1.8%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|66|5.1%|0.0%|
[openbl_30d](#openbl_30d)|2805|2805|65|2.3%|0.0%|
[xroxy](#xroxy)|2169|2169|58|2.6%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|56|8.4%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1695|1695|55|3.2%|0.0%|
[et_compromised](#et_compromised)|1721|1721|52|3.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2423|2423|50|2.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|2960|2960|48|1.6%|0.0%|
[proxz](#proxz)|1323|1323|44|3.3%|0.0%|
[et_botcc](#et_botcc)|506|506|40|7.9%|0.0%|
[ciarmy](#ciarmy)|488|488|39|7.9%|0.0%|
[tor_exits](#tor_exits)|1112|1112|37|3.3%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2901|2901|36|1.2%|0.0%|
[proxyrss](#proxyrss)|1638|1638|35|2.1%|0.0%|
[dragon_sshpauth](#dragon_sshpauth)|1633|1695|31|1.8%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|1526|1526|27|1.7%|0.0%|
[shunlist](#shunlist)|1151|1151|25|2.1%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|21|4.0%|0.0%|
[sorbs_web](#sorbs_web)|568|569|14|2.4%|0.0%|
[openbl_7d](#openbl_7d)|635|635|14|2.2%|0.0%|
[php_harvesters](#php_harvesters)|408|408|12|2.9%|0.0%|
[php_dictionary](#php_dictionary)|737|737|12|1.6%|0.0%|
[php_spammers](#php_spammers)|735|735|11|1.4%|0.0%|
[php_commenters](#php_commenters)|458|458|10|2.1%|0.0%|
[malc0de](#malc0de)|276|276|10|3.6%|0.0%|
[zeus](#zeus)|230|230|7|3.0%|0.0%|
[nt_malware_http](#nt_malware_http)|69|69|7|10.1%|0.0%|
[nt_malware_irc](#nt_malware_irc)|43|43|5|11.6%|0.0%|
[dragon_vncprobe](#dragon_vncprobe)|88|88|5|5.6%|0.0%|
[bogons](#bogons)|13|592708608|5|0.0%|0.0%|
[zeus_badips](#zeus_badips)|202|202|4|1.9%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|84|84|4|4.7%|0.0%|
[sslbl](#sslbl)|371|371|3|0.8%|0.0%|
[openbl_1d](#openbl_1d)|148|148|3|2.0%|0.0%|
[feodo](#feodo)|105|105|3|2.8%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|121|121|2|1.6%|0.0%|
[iw_wormlist](#iw_wormlist)|35|35|1|2.8%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|172|172|1|0.5%|0.0%|

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
[firehol_level1](#firehol_level1)|5138|688854748|8867973|1.2%|2.5%|
[et_block](#et_block)|1000|18344011|8532520|46.5%|2.4%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|8532506|46.5%|2.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|2830203|2.0%|0.8%|
[firehol_level3](#firehol_level3)|109658|9627424|2537271|26.3%|0.7%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2526625|27.5%|0.7%|
[fullbogons](#fullbogons)|3775|670173256|252671|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|98904|20.2%|0.0%|
[dragon_http](#dragon_http)|1029|270336|11960|4.4%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|7728|2.2%|0.0%|
[alienvault_reputation](#alienvault_reputation)|187341|187341|7251|3.8%|0.0%|
[firehol_anonymous](#firehol_anonymous)|19168|83212|2899|3.4%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|2476|2.6%|0.0%|
[sorbs_spam](#sorbs_spam)|64701|65536|1740|2.6%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|1736|2.6%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|1736|2.6%|0.0%|
[firehol_level2](#firehol_level2)|22007|33621|1688|5.0%|0.0%|
[blocklist_de](#blocklist_de)|28426|28426|1549|5.4%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|18299|18299|1268|6.9%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14346|14346|1093|7.6%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|768|2.6%|0.0%|
[nixspam](#nixspam)|22818|22818|720|3.1%|0.0%|
[voipbl](#voipbl)|10586|10998|436|3.9%|0.0%|
[firehol_proxies](#firehol_proxies)|12674|12945|394|3.0%|0.0%|
[openbl_60d](#openbl_60d)|6978|6978|319|4.5%|0.0%|
[dshield](#dshield)|20|5120|256|5.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|226|0.4%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7852|7852|224|2.8%|0.0%|
[dm_tor](#dm_tor)|6521|6521|185|2.8%|0.0%|
[bm_tor](#bm_tor)|6525|6525|185|2.8%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6697|6697|182|2.7%|0.0%|
[et_tor](#et_tor)|6400|6400|181|2.8%|0.0%|
[openbl_30d](#openbl_30d)|2805|2805|147|5.2%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9671|9671|138|1.4%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2423|2423|113|4.6%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2828|2828|106|3.7%|0.0%|
[xroxy](#xroxy)|2169|2169|104|4.7%|0.0%|
[iw_spamlist](#iw_spamlist)|3878|3878|94|2.4%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1695|1695|87|5.1%|0.0%|
[et_compromised](#et_compromised)|1721|1721|85|4.9%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|2960|2960|77|2.6%|0.0%|
[dragon_sshpauth](#dragon_sshpauth)|1633|1695|72|4.2%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2839|2839|70|2.4%|0.0%|
[shunlist](#shunlist)|1151|1151|69|5.9%|0.0%|
[proxyrss](#proxyrss)|1638|1638|58|3.5%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2901|2901|57|1.9%|0.0%|
[proxz](#proxz)|1323|1323|54|4.0%|0.0%|
[php_spammers](#php_spammers)|735|735|54|7.3%|0.0%|
[ciarmy](#ciarmy)|488|488|49|10.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|45|3.1%|0.0%|
[tor_exits](#tor_exits)|1112|1112|40|3.5%|0.0%|
[openbl_7d](#openbl_7d)|635|635|38|5.9%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|29|5.5%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|26|2.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|26|3.9%|0.0%|
[sorbs_web](#sorbs_web)|568|569|23|4.0%|0.0%|
[php_dictionary](#php_dictionary)|737|737|23|3.1%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|1526|1526|21|1.3%|0.0%|
[et_botcc](#et_botcc)|506|506|20|3.9%|0.0%|
[php_commenters](#php_commenters)|458|458|19|4.1%|0.0%|
[malc0de](#malc0de)|276|276|16|5.7%|0.0%|
[zeus](#zeus)|230|230|9|3.9%|0.0%|
[php_harvesters](#php_harvesters)|408|408|9|2.2%|0.0%|
[zeus_badips](#zeus_badips)|202|202|8|3.9%|0.0%|
[dragon_vncprobe](#dragon_vncprobe)|88|88|7|7.9%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|172|172|7|4.0%|0.0%|
[sslbl](#sslbl)|371|371|6|1.6%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|121|121|6|4.9%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|84|84|5|5.9%|0.0%|
[palevo](#palevo)|13|13|3|23.0%|0.0%|
[openbl_1d](#openbl_1d)|148|148|3|2.0%|0.0%|
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
[firehol_level1](#firehol_level1)|5138|688854748|4637346|0.6%|3.3%|
[fullbogons](#fullbogons)|3775|670173256|4236143|0.6%|3.0%|
[bogons](#bogons)|13|592708608|4194304|0.7%|3.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|2830203|0.8%|2.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|1354507|0.1%|0.9%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|270785|55.5%|0.1%|
[firehol_level3](#firehol_level3)|109658|9627424|161583|1.6%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|145472|1.5%|0.1%|
[et_block](#et_block)|1000|18344011|130394|0.7%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|130368|0.7%|0.0%|
[dragon_http](#dragon_http)|1029|270336|20480|7.5%|0.0%|
[alienvault_reputation](#alienvault_reputation)|187341|187341|14084|7.5%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|9226|2.7%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|5830|6.1%|0.0%|
[firehol_level2](#firehol_level2)|22007|33621|3818|11.3%|0.0%|
[blocklist_de](#blocklist_de)|28426|28426|3397|11.9%|0.0%|
[firehol_anonymous](#firehol_anonymous)|19168|83212|2868|3.4%|0.0%|
[sorbs_spam](#sorbs_spam)|64701|65536|2860|4.3%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|2851|4.3%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|2851|4.3%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|18299|18299|2609|14.2%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14346|14346|2310|16.1%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|1953|6.6%|0.0%|
[voipbl](#voipbl)|10586|10998|1613|14.6%|0.0%|
[nixspam](#nixspam)|22818|22818|1286|5.6%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|1172|2.4%|0.0%|
[openbl_60d](#openbl_60d)|6978|6978|741|10.6%|0.0%|
[et_tor](#et_tor)|6400|6400|625|9.7%|0.0%|
[dm_tor](#dm_tor)|6521|6521|625|9.5%|0.0%|
[bm_tor](#bm_tor)|6525|6525|625|9.5%|0.0%|
[firehol_proxies](#firehol_proxies)|12674|12945|525|4.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6697|6697|523|7.8%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2839|2839|305|10.7%|0.0%|
[openbl_30d](#openbl_30d)|2805|2805|285|10.1%|0.0%|
[iw_spamlist](#iw_spamlist)|3878|3878|264|6.8%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2423|2423|263|10.8%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9671|9671|241|2.4%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7852|7852|220|2.8%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2901|2901|211|7.2%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|2960|2960|161|5.4%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1695|1695|156|9.2%|0.0%|
[et_compromised](#et_compromised)|1721|1721|152|8.8%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|150|28.6%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|147|11.4%|0.0%|
[tor_exits](#tor_exits)|1112|1112|128|11.5%|0.0%|
[dragon_sshpauth](#dragon_sshpauth)|1633|1695|127|7.4%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|1526|1526|126|8.2%|0.0%|
[shunlist](#shunlist)|1151|1151|115|9.9%|0.0%|
[xroxy](#xroxy)|2169|2169|111|5.1%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|108|7.4%|0.0%|
[proxz](#proxz)|1323|1323|105|7.9%|0.0%|
[ciarmy](#ciarmy)|488|488|105|21.5%|0.0%|
[et_botcc](#et_botcc)|506|506|77|15.2%|0.0%|
[openbl_7d](#openbl_7d)|635|635|64|10.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2828|2828|57|2.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|51|7.6%|0.0%|
[proxyrss](#proxyrss)|1638|1638|46|2.8%|0.0%|
[php_spammers](#php_spammers)|735|735|44|5.9%|0.0%|
[malc0de](#malc0de)|276|276|44|15.9%|0.0%|
[php_dictionary](#php_dictionary)|737|737|39|5.2%|0.0%|
[php_commenters](#php_commenters)|458|458|29|6.3%|0.0%|
[sslbl](#sslbl)|371|371|28|7.5%|0.0%|
[sorbs_web](#sorbs_web)|568|569|27|4.7%|0.0%|
[php_harvesters](#php_harvesters)|408|408|20|4.9%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|121|121|19|15.7%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|172|172|16|9.3%|0.0%|
[zeus](#zeus)|230|230|14|6.0%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|84|84|14|16.6%|0.0%|
[dragon_vncprobe](#dragon_vncprobe)|88|88|12|13.6%|0.0%|
[feodo](#feodo)|105|105|11|10.4%|0.0%|
[zeus_badips](#zeus_badips)|202|202|10|4.9%|0.0%|
[openbl_1d](#openbl_1d)|148|148|9|6.0%|0.0%|
[nt_malware_http](#nt_malware_http)|69|69|5|7.2%|0.0%|
[sorbs_socks](#sorbs_socks)|7|7|2|28.5%|0.0%|
[sorbs_misc](#sorbs_misc)|7|7|2|28.5%|0.0%|
[sorbs_http](#sorbs_http)|7|7|2|28.5%|0.0%|
[iw_wormlist](#iw_wormlist)|35|35|2|5.7%|0.0%|
[virbl](#virbl)|19|19|1|5.2%|0.0%|
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
[firehol_proxies](#firehol_proxies)|12674|12945|663|5.1%|100.0%|
[firehol_anonymous](#firehol_anonymous)|19168|83212|663|0.7%|100.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|56|0.0%|8.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|51|0.0%|7.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|26|0.0%|3.9%|
[firehol_level3](#firehol_level3)|109658|9627424|25|0.0%|3.7%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|20|0.0%|3.0%|
[ri_web_proxies](#ri_web_proxies)|7852|7852|15|0.1%|2.2%|
[xroxy](#xroxy)|2169|2169|13|0.5%|1.9%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|11|0.0%|1.6%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|11|0.0%|1.6%|
[proxyrss](#proxyrss)|1638|1638|9|0.5%|1.3%|
[firehol_level2](#firehol_level2)|22007|33621|8|0.0%|1.2%|
[ri_connect_proxies](#ri_connect_proxies)|2828|2828|7|0.2%|1.0%|
[proxz](#proxz)|1323|1323|6|0.4%|0.9%|
[stopforumspam_1d](#stopforumspam_1d)|6697|6697|5|0.0%|0.7%|
[blocklist_de](#blocklist_de)|28426|28426|4|0.0%|0.6%|
[nixspam](#nixspam)|22818|22818|3|0.0%|0.4%|
[blocklist_de_bots](#blocklist_de_bots)|2960|2960|3|0.1%|0.4%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|2|0.0%|0.3%|
[php_dictionary](#php_dictionary)|737|737|2|0.2%|0.3%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|2|0.1%|0.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2|0.0%|0.3%|
[firehol_level1](#firehol_level1)|5138|688854748|2|0.0%|0.3%|
[et_block](#et_block)|1000|18344011|2|0.0%|0.3%|
[alienvault_reputation](#alienvault_reputation)|187341|187341|2|0.0%|0.3%|
[sorbs_spam](#sorbs_spam)|64701|65536|1|0.0%|0.1%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|1|0.0%|0.1%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|1|0.0%|0.1%|
[snort_ipfilter](#snort_ipfilter)|9671|9671|1|0.0%|0.1%|
[php_spammers](#php_spammers)|735|735|1|0.1%|0.1%|
[dragon_http](#dragon_http)|1029|270336|1|0.0%|0.1%|
[blocklist_de_mail](#blocklist_de_mail)|18299|18299|1|0.0%|0.1%|

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
[firehol_level3](#firehol_level3)|109658|9627424|339173|3.5%|100.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|13247|0.0%|3.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|9226|0.0%|2.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|7728|0.0%|2.2%|
[firehol_level1](#firehol_level1)|5138|688854748|1932|0.0%|0.5%|
[et_block](#et_block)|1000|18344011|1042|0.0%|0.3%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|1037|0.0%|0.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1036|0.0%|0.3%|
[fullbogons](#fullbogons)|3775|670173256|890|0.0%|0.2%|
[alienvault_reputation](#alienvault_reputation)|187341|187341|293|0.1%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|52|0.0%|0.0%|
[sorbs_spam](#sorbs_spam)|64701|65536|38|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|37|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|37|0.0%|0.0%|
[firehol_anonymous](#firehol_anonymous)|19168|83212|29|0.0%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|27|2.0%|0.0%|
[nixspam](#nixspam)|22818|22818|22|0.0%|0.0%|
[et_tor](#et_tor)|6400|6400|22|0.3%|0.0%|
[dm_tor](#dm_tor)|6521|6521|22|0.3%|0.0%|
[bm_tor](#bm_tor)|6525|6525|22|0.3%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|20|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|19|1.3%|0.0%|
[firehol_level2](#firehol_level2)|22007|33621|15|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9671|9671|14|0.1%|0.0%|
[firehol_proxies](#firehol_proxies)|12674|12945|11|0.0%|0.0%|
[tor_exits](#tor_exits)|1112|1112|8|0.7%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6697|6697|8|0.1%|0.0%|
[blocklist_de](#blocklist_de)|28426|28426|7|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7852|7852|6|0.0%|0.0%|
[dragon_http](#dragon_http)|1029|270336|6|0.0%|0.0%|
[openbl_60d](#openbl_60d)|6978|6978|5|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|5|0.9%|0.0%|
[voipbl](#voipbl)|10586|10998|4|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14346|14346|4|0.0%|0.0%|
[openbl_30d](#openbl_30d)|2805|2805|3|0.1%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|3|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2901|2901|3|0.1%|0.0%|
[palevo](#palevo)|13|13|2|15.3%|0.0%|
[malc0de](#malc0de)|276|276|2|0.7%|0.0%|
[iw_spamlist](#iw_spamlist)|3878|3878|2|0.0%|0.0%|
[et_compromised](#et_compromised)|1721|1721|2|0.1%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1695|1695|2|0.1%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|84|84|2|2.3%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|18299|18299|2|0.0%|0.0%|
[zeus_badips](#zeus_badips)|202|202|1|0.4%|0.0%|
[zeus](#zeus)|230|230|1|0.4%|0.0%|
[xroxy](#xroxy)|2169|2169|1|0.0%|0.0%|
[sslbl](#sslbl)|371|371|1|0.2%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|1|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2828|2828|1|0.0%|0.0%|
[proxz](#proxz)|1323|1323|1|0.0%|0.0%|
[proxyrss](#proxyrss)|1638|1638|1|0.0%|0.0%|
[php_harvesters](#php_harvesters)|408|408|1|0.2%|0.0%|
[php_dictionary](#php_dictionary)|737|737|1|0.1%|0.0%|
[php_commenters](#php_commenters)|458|458|1|0.2%|0.0%|
[nt_malware_http](#nt_malware_http)|69|69|1|1.4%|0.0%|
[feodo](#feodo)|105|105|1|0.9%|0.0%|
[bogons](#bogons)|13|592708608|1|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2423|2423|1|0.0%|0.0%|
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
[firehol_level3](#firehol_level3)|109658|9627424|1450|0.0%|100.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|108|0.0%|7.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|97|0.0%|6.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|45|0.0%|3.1%|
[firehol_level1](#firehol_level1)|5138|688854748|39|0.0%|2.6%|
[fullbogons](#fullbogons)|3775|670173256|33|0.0%|2.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|19|0.0%|1.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|7|0.0%|0.4%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|6|0.0%|0.4%|
[et_block](#et_block)|1000|18344011|6|0.0%|0.4%|
[alienvault_reputation](#alienvault_reputation)|187341|187341|6|0.0%|0.4%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|3|0.2%|0.2%|
[firehol_proxies](#firehol_proxies)|12674|12945|3|0.0%|0.2%|
[firehol_level2](#firehol_level2)|22007|33621|3|0.0%|0.2%|
[firehol_anonymous](#firehol_anonymous)|19168|83212|3|0.0%|0.2%|
[dragon_http](#dragon_http)|1029|270336|3|0.0%|0.2%|
[blocklist_de](#blocklist_de)|28426|28426|3|0.0%|0.2%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|2|0.0%|0.1%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|2|0.0%|0.1%|
[stopforumspam_1d](#stopforumspam_1d)|6697|6697|2|0.0%|0.1%|
[sorbs_spam](#sorbs_spam)|64701|65536|2|0.0%|0.1%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|2|0.0%|0.1%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|2|0.0%|0.1%|
[openbl_60d](#openbl_60d)|6978|6978|2|0.0%|0.1%|
[openbl_30d](#openbl_30d)|2805|2805|2|0.0%|0.1%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|2|0.3%|0.1%|
[blocklist_de_strongips](#blocklist_de_strongips)|172|172|2|1.1%|0.1%|
[blocklist_de_bots](#blocklist_de_bots)|2960|2960|2|0.0%|0.1%|
[snort_ipfilter](#snort_ipfilter)|9671|9671|1|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7852|7852|1|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|1|0.0%|0.0%|
[et_botcc](#et_botcc)|506|506|1|0.1%|0.0%|
[dragon_sshpauth](#dragon_sshpauth)|1633|1695|1|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2423|2423|1|0.0%|0.0%|

## iw_spamlist

[ImproWare Antispam](http://antispam.imp.ch/) IPs sending spam, in the last 3 days

Source is downloaded from [this link](http://antispam.imp.ch/spamlist).

The last time downloaded was found to be dated: Thu Jun 11 22:20:04 UTC 2015.

The ipset `iw_spamlist` has **3878** entries, **3878** unique IPs.

The following table shows the overlaps of `iw_spamlist` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `iw_spamlist`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `iw_spamlist`.
- ` this % ` is the percentage **of this ipset (`iw_spamlist`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[sorbs_spam](#sorbs_spam)|64701|65536|1203|1.8%|31.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|1197|1.8%|30.8%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|1197|1.8%|30.8%|
[nixspam](#nixspam)|22818|22818|696|3.0%|17.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|264|0.0%|6.8%|
[firehol_level2](#firehol_level2)|22007|33621|148|0.4%|3.8%|
[blocklist_de](#blocklist_de)|28426|28426|147|0.5%|3.7%|
[blocklist_de_mail](#blocklist_de_mail)|18299|18299|138|0.7%|3.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|94|0.0%|2.4%|
[firehol_level3](#firehol_level3)|109658|9627424|93|0.0%|2.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|72|0.0%|1.8%|
[snort_ipfilter](#snort_ipfilter)|9671|9671|56|0.5%|1.4%|
[sorbs_web](#sorbs_web)|568|569|25|4.3%|0.6%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|21|0.0%|0.5%|
[alienvault_reputation](#alienvault_reputation)|187341|187341|20|0.0%|0.5%|
[firehol_anonymous](#firehol_anonymous)|19168|83212|14|0.0%|0.3%|
[iw_wormlist](#iw_wormlist)|35|35|13|37.1%|0.3%|
[firehol_proxies](#firehol_proxies)|12674|12945|13|0.1%|0.3%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|12|0.0%|0.3%|
[ri_web_proxies](#ri_web_proxies)|7852|7852|11|0.1%|0.2%|
[firehol_level1](#firehol_level1)|5138|688854748|9|0.0%|0.2%|
[php_spammers](#php_spammers)|735|735|7|0.9%|0.1%|
[php_dictionary](#php_dictionary)|737|737|7|0.9%|0.1%|
[stopforumspam_1d](#stopforumspam_1d)|6697|6697|5|0.0%|0.1%|
[fullbogons](#fullbogons)|3775|670173256|5|0.0%|0.1%|
[bogons](#bogons)|13|592708608|5|0.0%|0.1%|
[php_commenters](#php_commenters)|458|458|4|0.8%|0.1%|
[blocklist_de_apache](#blocklist_de_apache)|14346|14346|4|0.0%|0.1%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|3|0.0%|0.0%|
[php_harvesters](#php_harvesters)|408|408|3|0.7%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|0.0%|
[et_block](#et_block)|1000|18344011|3|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|1526|1526|3|0.1%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2901|2901|3|0.1%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|2960|2960|3|0.1%|0.0%|
[xroxy](#xroxy)|2169|2169|2|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|2|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2839|2839|2|0.0%|0.0%|
[tor_exits](#tor_exits)|1112|1112|1|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|1|0.0%|0.0%|
[sorbs_socks](#sorbs_socks)|7|7|1|14.2%|0.0%|
[sorbs_misc](#sorbs_misc)|7|7|1|14.2%|0.0%|
[sorbs_http](#sorbs_http)|7|7|1|14.2%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2828|2828|1|0.0%|0.0%|
[proxyrss](#proxyrss)|1638|1638|1|0.0%|0.0%|
[et_tor](#et_tor)|6400|6400|1|0.0%|0.0%|
[dragon_http](#dragon_http)|1029|270336|1|0.0%|0.0%|
[dm_tor](#dm_tor)|6521|6521|1|0.0%|0.0%|
[bm_tor](#bm_tor)|6525|6525|1|0.0%|0.0%|

## iw_wormlist

[ImproWare Antispam](http://antispam.imp.ch/) IPs sending emails with viruses or worms, in the last 3 days

Source is downloaded from [this link](http://antispam.imp.ch/wormlist).

The last time downloaded was found to be dated: Thu Jun 11 22:20:04 UTC 2015.

The ipset `iw_wormlist` has **35** entries, **35** unique IPs.

The following table shows the overlaps of `iw_wormlist` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `iw_wormlist`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `iw_wormlist`.
- ` this % ` is the percentage **of this ipset (`iw_wormlist`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level3](#firehol_level3)|109658|9627424|35|0.0%|100.0%|
[iw_spamlist](#iw_spamlist)|3878|3878|13|0.3%|37.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|2|0.0%|5.7%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|1|0.0%|2.8%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|1|0.0%|2.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|1|0.0%|2.8%|
[firehol_level2](#firehol_level2)|22007|33621|1|0.0%|2.8%|
[blocklist_de_mail](#blocklist_de_mail)|18299|18299|1|0.0%|2.8%|
[blocklist_de](#blocklist_de)|28426|28426|1|0.0%|2.8%|

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
[firehol_level3](#firehol_level3)|109658|9627424|276|0.0%|100.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|44|0.0%|15.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|16|0.0%|5.7%|
[cleanmx_viruses](#cleanmx_viruses)|121|121|16|13.2%|5.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|10|0.0%|3.6%|
[alienvault_reputation](#alienvault_reputation)|187341|187341|9|0.0%|3.2%|
[firehol_level1](#firehol_level1)|5138|688854748|6|0.0%|2.1%|
[et_block](#et_block)|1000|18344011|5|0.0%|1.8%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|4|0.0%|1.4%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|4|0.3%|1.4%|
[dragon_http](#dragon_http)|1029|270336|3|0.0%|1.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|2|0.0%|0.7%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|1|0.0%|0.3%|
[sorbs_spam](#sorbs_spam)|64701|65536|1|0.0%|0.3%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|1|0.0%|0.3%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|1|0.0%|0.3%|
[dshield](#dshield)|20|5120|1|0.0%|0.3%|

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
[firehol_level3](#firehol_level3)|109658|9627424|1288|0.0%|100.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|147|0.0%|11.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|66|0.0%|5.1%|
[firehol_level1](#firehol_level1)|5138|688854748|39|0.0%|3.0%|
[et_block](#et_block)|1000|18344011|30|0.0%|2.3%|
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
[dragon_http](#dragon_http)|1029|270336|2|0.0%|0.1%|
[cleanmx_viruses](#cleanmx_viruses)|121|121|2|1.6%|0.1%|
[zeus](#zeus)|230|230|1|0.4%|0.0%|
[et_botcc](#et_botcc)|506|506|1|0.1%|0.0%|

## maxmind_proxy_fraud

[MaxMind.com](https://www.maxmind.com/en/anonymous-proxy-fraudulent-ip-address-list) list of anonymous proxy fraudelent IP addresses.

Source is downloaded from [this link](https://www.maxmind.com/en/anonymous-proxy-fraudulent-ip-address-list).

The last time downloaded was found to be dated: Thu Jun 11 19:27:04 UTC 2015.

The ipset `maxmind_proxy_fraud` has **524** entries, **524** unique IPs.

The following table shows the overlaps of `maxmind_proxy_fraud` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `maxmind_proxy_fraud`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `maxmind_proxy_fraud`.
- ` this % ` is the percentage **of this ipset (`maxmind_proxy_fraud`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_proxies](#firehol_proxies)|12674|12945|524|4.0%|100.0%|
[firehol_anonymous](#firehol_anonymous)|19168|83212|524|0.6%|100.0%|
[firehol_level3](#firehol_level3)|109658|9627424|346|0.0%|66.0%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|345|0.3%|65.8%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|286|0.9%|54.5%|
[snort_ipfilter](#snort_ipfilter)|9671|9671|237|2.4%|45.2%|
[et_tor](#et_tor)|6400|6400|234|3.6%|44.6%|
[dm_tor](#dm_tor)|6521|6521|231|3.5%|44.0%|
[bm_tor](#bm_tor)|6525|6525|231|3.5%|44.0%|
[tor_exits](#tor_exits)|1112|1112|230|20.6%|43.8%|
[firehol_level2](#firehol_level2)|22007|33621|209|0.6%|39.8%|
[stopforumspam_1d](#stopforumspam_1d)|6697|6697|207|3.0%|39.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|150|0.0%|28.6%|
[php_commenters](#php_commenters)|458|458|53|11.5%|10.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|29|0.0%|5.5%|
[alienvault_reputation](#alienvault_reputation)|187341|187341|29|0.0%|5.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|21|0.0%|4.0%|
[openbl_60d](#openbl_60d)|6978|6978|20|0.2%|3.8%|
[ri_web_proxies](#ri_web_proxies)|7852|7852|10|0.1%|1.9%|
[php_harvesters](#php_harvesters)|408|408|7|1.7%|1.3%|
[blocklist_de](#blocklist_de)|28426|28426|7|0.0%|1.3%|
[php_spammers](#php_spammers)|735|735|6|0.8%|1.1%|
[php_dictionary](#php_dictionary)|737|737|5|0.6%|0.9%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|5|0.0%|0.9%|
[blocklist_de_bots](#blocklist_de_bots)|2960|2960|5|0.1%|0.9%|
[dragon_http](#dragon_http)|1029|270336|4|0.0%|0.7%|
[xroxy](#xroxy)|2169|2169|3|0.1%|0.5%|
[voipbl](#voipbl)|10586|10998|2|0.0%|0.3%|
[proxz](#proxz)|1323|1323|2|0.1%|0.3%|
[blocklist_de_apache](#blocklist_de_apache)|14346|14346|2|0.0%|0.3%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|1|0.0%|0.1%|
[sorbs_spam](#sorbs_spam)|64701|65536|1|0.0%|0.1%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|1|0.0%|0.1%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|1|0.0%|0.1%|
[shunlist](#shunlist)|1151|1151|1|0.0%|0.1%|
[ri_connect_proxies](#ri_connect_proxies)|2828|2828|1|0.0%|0.1%|
[nixspam](#nixspam)|22818|22818|1|0.0%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.1%|
[firehol_level1](#firehol_level1)|5138|688854748|1|0.0%|0.1%|
[et_block](#et_block)|1000|18344011|1|0.0%|0.1%|
[blocklist_de_mail](#blocklist_de_mail)|18299|18299|1|0.0%|0.1%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2901|2901|1|0.0%|0.1%|

## nixspam

[NiX Spam](http://www.heise.de/ix/NiX-Spam-DNSBL-and-blacklist-for-download-499637.html) IP addresses that sent spam in the last hour - automatically generated entries without distinguishing open proxies from relays, dialup gateways, and so on. All IPs are removed after 12 hours if there is no spam from there.

Source is downloaded from [this link](http://www.dnsbl.manitu.net/download/nixspam-ip.dump.gz).

The last time downloaded was found to be dated: Thu Jun 11 22:30:02 UTC 2015.

The ipset `nixspam` has **22818** entries, **22818** unique IPs.

The following table shows the overlaps of `nixspam` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `nixspam`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `nixspam`.
- ` this % ` is the percentage **of this ipset (`nixspam`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[sorbs_spam](#sorbs_spam)|64701|65536|3017|4.6%|13.2%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|2910|4.4%|12.7%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|2910|4.4%|12.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|1286|0.0%|5.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|720|0.0%|3.1%|
[firehol_level2](#firehol_level2)|22007|33621|705|2.0%|3.0%|
[iw_spamlist](#iw_spamlist)|3878|3878|696|17.9%|3.0%|
[blocklist_de](#blocklist_de)|28426|28426|687|2.4%|3.0%|
[blocklist_de_mail](#blocklist_de_mail)|18299|18299|617|3.3%|2.7%|
[firehol_level3](#firehol_level3)|109658|9627424|501|0.0%|2.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|495|0.0%|2.1%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|228|0.2%|0.9%|
[snort_ipfilter](#snort_ipfilter)|9671|9671|199|2.0%|0.8%|
[firehol_anonymous](#firehol_anonymous)|19168|83212|174|0.2%|0.7%|
[firehol_proxies](#firehol_proxies)|12674|12945|166|1.2%|0.7%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|136|0.4%|0.5%|
[ri_web_proxies](#ri_web_proxies)|7852|7852|122|1.5%|0.5%|
[php_dictionary](#php_dictionary)|737|737|119|16.1%|0.5%|
[sorbs_web](#sorbs_web)|568|569|117|20.5%|0.5%|
[php_spammers](#php_spammers)|735|735|98|13.3%|0.4%|
[firehol_level1](#firehol_level1)|5138|688854748|86|0.0%|0.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|81|0.0%|0.3%|
[et_block](#et_block)|1000|18344011|81|0.0%|0.3%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|80|0.0%|0.3%|
[alienvault_reputation](#alienvault_reputation)|187341|187341|77|0.0%|0.3%|
[xroxy](#xroxy)|2169|2169|65|2.9%|0.2%|
[stopforumspam_1d](#stopforumspam_1d)|6697|6697|57|0.8%|0.2%|
[proxz](#proxz)|1323|1323|42|3.1%|0.1%|
[blocklist_de_apache](#blocklist_de_apache)|14346|14346|32|0.2%|0.1%|
[dragon_http](#dragon_http)|1029|270336|31|0.0%|0.1%|
[blocklist_de_imap](#blocklist_de_imap)|2839|2839|30|1.0%|0.1%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2901|2901|30|1.0%|0.1%|
[blocklist_de_bots](#blocklist_de_bots)|2960|2960|27|0.9%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|22|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2828|2828|19|0.6%|0.0%|
[php_commenters](#php_commenters)|458|458|18|3.9%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|1526|1526|13|0.8%|0.0%|
[proxyrss](#proxyrss)|1638|1638|11|0.6%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|9|0.0%|0.0%|
[php_harvesters](#php_harvesters)|408|408|8|1.9%|0.0%|
[tor_exits](#tor_exits)|1112|1112|7|0.6%|0.0%|
[dm_tor](#dm_tor)|6521|6521|7|0.1%|0.0%|
[bm_tor](#bm_tor)|6525|6525|7|0.1%|0.0%|
[openbl_60d](#openbl_60d)|6978|6978|6|0.0%|0.0%|
[et_tor](#et_tor)|6400|6400|5|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|3|0.0%|0.0%|
[openbl_30d](#openbl_30d)|2805|2805|3|0.1%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|3|0.4%|0.0%|
[voipbl](#voipbl)|10586|10998|2|0.0%|0.0%|
[sorbs_socks](#sorbs_socks)|7|7|2|28.5%|0.0%|
[sorbs_misc](#sorbs_misc)|7|7|2|28.5%|0.0%|
[sorbs_http](#sorbs_http)|7|7|2|28.5%|0.0%|
[dshield](#dshield)|20|5120|2|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|172|172|2|1.1%|0.0%|
[zeus_badips](#zeus_badips)|202|202|1|0.4%|0.0%|
[zeus](#zeus)|230|230|1|0.4%|0.0%|
[openbl_7d](#openbl_7d)|635|635|1|0.1%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|1|0.1%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|121|121|1|0.8%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2423|2423|1|0.0%|0.0%|

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
[firehol_level1](#firehol_level1)|5138|688854748|8|0.0%|11.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|7|0.0%|10.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|5|0.0%|7.2%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|4|0.0%|5.7%|
[fullbogons](#fullbogons)|3775|670173256|4|0.0%|5.7%|
[et_block](#et_block)|1000|18344011|4|0.0%|5.7%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|4.3%|
[firehol_level3](#firehol_level3)|109658|9627424|3|0.0%|4.3%|
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
[firehol_level1](#firehol_level1)|5138|688854748|3|0.0%|6.9%|
[et_block](#et_block)|1000|18344011|3|0.0%|6.9%|
[nt_malware_http](#nt_malware_http)|69|69|2|2.8%|4.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|2|0.0%|4.6%|
[alienvault_reputation](#alienvault_reputation)|187341|187341|2|0.0%|4.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|1|0.0%|2.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|2.3%|
[firehol_level3](#firehol_level3)|109658|9627424|1|0.0%|2.3%|

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

The last time downloaded was found to be dated: Thu Jun 11 22:32:00 UTC 2015.

The ipset `openbl_1d` has **148** entries, **148** unique IPs.

The following table shows the overlaps of `openbl_1d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl_1d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl_1d`.
- ` this % ` is the percentage **of this ipset (`openbl_1d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|22007|33621|148|0.4%|100.0%|
[alienvault_reputation](#alienvault_reputation)|187341|187341|147|0.0%|99.3%|
[openbl_60d](#openbl_60d)|6978|6978|145|2.0%|97.9%|
[openbl_30d](#openbl_30d)|2805|2805|145|5.1%|97.9%|
[firehol_level3](#firehol_level3)|109658|9627424|145|0.0%|97.9%|
[openbl_7d](#openbl_7d)|635|635|140|22.0%|94.5%|
[blocklist_de](#blocklist_de)|28426|28426|130|0.4%|87.8%|
[blocklist_de_ssh](#blocklist_de_ssh)|2423|2423|128|5.2%|86.4%|
[dragon_sshpauth](#dragon_sshpauth)|1633|1695|100|5.8%|67.5%|
[bruteforceblocker](#bruteforceblocker)|1695|1695|77|4.5%|52.0%|
[shunlist](#shunlist)|1151|1151|76|6.6%|51.3%|
[et_compromised](#et_compromised)|1721|1721|76|4.4%|51.3%|
[et_block](#et_block)|1000|18344011|21|0.0%|14.1%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|20|0.0%|13.5%|
[firehol_level1](#firehol_level1)|5138|688854748|20|0.0%|13.5%|
[blocklist_de_strongips](#blocklist_de_strongips)|172|172|16|9.3%|10.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|9|0.0%|6.0%|
[dragon_http](#dragon_http)|1029|270336|5|0.0%|3.3%|
[dshield](#dshield)|20|5120|4|0.0%|2.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|3|0.0%|2.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|3|0.0%|2.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2|0.0%|1.3%|
[ciarmy](#ciarmy)|488|488|2|0.4%|1.3%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|1|0.0%|0.6%|
[php_spammers](#php_spammers)|735|735|1|0.1%|0.6%|
[php_commenters](#php_commenters)|458|458|1|0.2%|0.6%|
[blocklist_de_mail](#blocklist_de_mail)|18299|18299|1|0.0%|0.6%|
[blocklist_de_imap](#blocklist_de_imap)|2839|2839|1|0.0%|0.6%|
[blocklist_de_apache](#blocklist_de_apache)|14346|14346|1|0.0%|0.6%|

## openbl_30d

[OpenBL.org](http://www.openbl.org/) last 30 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.

Source is downloaded from [this link](http://www.openbl.org/lists/base_30days.txt).

The last time downloaded was found to be dated: Thu Jun 11 20:07:00 UTC 2015.

The ipset `openbl_30d` has **2805** entries, **2805** unique IPs.

The following table shows the overlaps of `openbl_30d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl_30d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl_30d`.
- ` this % ` is the percentage **of this ipset (`openbl_30d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[openbl_60d](#openbl_60d)|6978|6978|2805|40.1%|100.0%|
[firehol_level3](#firehol_level3)|109658|9627424|2805|0.0%|100.0%|
[alienvault_reputation](#alienvault_reputation)|187341|187341|2791|1.4%|99.5%|
[et_compromised](#et_compromised)|1721|1721|944|54.8%|33.6%|
[bruteforceblocker](#bruteforceblocker)|1695|1695|904|53.3%|32.2%|
[dragon_sshpauth](#dragon_sshpauth)|1633|1695|707|41.7%|25.2%|
[firehol_level2](#firehol_level2)|22007|33621|690|2.0%|24.5%|
[blocklist_de](#blocklist_de)|28426|28426|673|2.3%|23.9%|
[blocklist_de_ssh](#blocklist_de_ssh)|2423|2423|653|26.9%|23.2%|
[openbl_7d](#openbl_7d)|635|635|635|100.0%|22.6%|
[shunlist](#shunlist)|1151|1151|428|37.1%|15.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|285|0.0%|10.1%|
[et_block](#et_block)|1000|18344011|163|0.0%|5.8%|
[dragon_http](#dragon_http)|1029|270336|148|0.0%|5.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|147|0.0%|5.2%|
[openbl_1d](#openbl_1d)|148|148|145|97.9%|5.1%|
[firehol_level1](#firehol_level1)|5138|688854748|125|0.0%|4.4%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|119|0.0%|4.2%|
[dshield](#dshield)|20|5120|70|1.3%|2.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|65|0.0%|2.3%|
[blocklist_de_strongips](#blocklist_de_strongips)|172|172|23|13.3%|0.8%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|12|0.0%|0.4%|
[blocklist_de_mail](#blocklist_de_mail)|18299|18299|12|0.0%|0.4%|
[blocklist_de_imap](#blocklist_de_imap)|2839|2839|9|0.3%|0.3%|
[blocklist_de_apache](#blocklist_de_apache)|14346|14346|6|0.0%|0.2%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|5|0.0%|0.1%|
[voipbl](#voipbl)|10586|10998|3|0.0%|0.1%|
[nixspam](#nixspam)|22818|22818|3|0.0%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|3|0.0%|0.1%|
[ciarmy](#ciarmy)|488|488|3|0.6%|0.1%|
[zeus](#zeus)|230|230|2|0.8%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9671|9671|2|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|2|0.1%|0.0%|
[zeus_badips](#zeus_badips)|202|202|1|0.4%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|1|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6697|6697|1|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|1|0.0%|0.0%|
[php_spammers](#php_spammers)|735|735|1|0.1%|0.0%|
[php_commenters](#php_commenters)|458|458|1|0.2%|0.0%|
[firehol_anonymous](#firehol_anonymous)|19168|83212|1|0.0%|0.0%|
[dragon_vncprobe](#dragon_vncprobe)|88|88|1|1.1%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|1526|1526|1|0.0%|0.0%|

## openbl_60d

[OpenBL.org](http://www.openbl.org/) last 60 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.

Source is downloaded from [this link](http://www.openbl.org/lists/base_60days.txt).

The last time downloaded was found to be dated: Thu Jun 11 20:07:00 UTC 2015.

The ipset `openbl_60d` has **6978** entries, **6978** unique IPs.

The following table shows the overlaps of `openbl_60d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl_60d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl_60d`.
- ` this % ` is the percentage **of this ipset (`openbl_60d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[alienvault_reputation](#alienvault_reputation)|187341|187341|6959|3.7%|99.7%|
[firehol_level3](#firehol_level3)|109658|9627424|2931|0.0%|42.0%|
[openbl_30d](#openbl_30d)|2805|2805|2805|100.0%|40.1%|
[et_compromised](#et_compromised)|1721|1721|1014|58.9%|14.5%|
[bruteforceblocker](#bruteforceblocker)|1695|1695|964|56.8%|13.8%|
[firehol_level2](#firehol_level2)|22007|33621|841|2.5%|12.0%|
[blocklist_de](#blocklist_de)|28426|28426|806|2.8%|11.5%|
[dragon_sshpauth](#dragon_sshpauth)|1633|1695|791|46.6%|11.3%|
[blocklist_de_ssh](#blocklist_de_ssh)|2423|2423|775|31.9%|11.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|741|0.0%|10.6%|
[openbl_7d](#openbl_7d)|635|635|635|100.0%|9.1%|
[shunlist](#shunlist)|1151|1151|454|39.4%|6.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|319|0.0%|4.5%|
[et_block](#et_block)|1000|18344011|299|0.0%|4.2%|
[firehol_level1](#firehol_level1)|5138|688854748|247|0.0%|3.5%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|235|0.0%|3.3%|
[dragon_http](#dragon_http)|1029|270336|219|0.0%|3.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|163|0.0%|2.3%|
[openbl_1d](#openbl_1d)|148|148|145|97.9%|2.0%|
[dshield](#dshield)|20|5120|78|1.5%|1.1%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|47|0.0%|0.6%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|27|0.0%|0.3%|
[snort_ipfilter](#snort_ipfilter)|9671|9671|24|0.2%|0.3%|
[blocklist_de_strongips](#blocklist_de_strongips)|172|172|24|13.9%|0.3%|
[firehol_anonymous](#firehol_anonymous)|19168|83212|23|0.0%|0.3%|
[tor_exits](#tor_exits)|1112|1112|20|1.7%|0.2%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|20|3.8%|0.2%|
[firehol_proxies](#firehol_proxies)|12674|12945|20|0.1%|0.2%|
[et_tor](#et_tor)|6400|6400|20|0.3%|0.2%|
[dm_tor](#dm_tor)|6521|6521|20|0.3%|0.2%|
[bm_tor](#bm_tor)|6525|6525|20|0.3%|0.2%|
[blocklist_de_mail](#blocklist_de_mail)|18299|18299|20|0.1%|0.2%|
[stopforumspam_1d](#stopforumspam_1d)|6697|6697|19|0.2%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|16|0.0%|0.2%|
[blocklist_de_imap](#blocklist_de_imap)|2839|2839|16|0.5%|0.2%|
[php_commenters](#php_commenters)|458|458|12|2.6%|0.1%|
[voipbl](#voipbl)|10586|10998|8|0.0%|0.1%|
[blocklist_de_apache](#blocklist_de_apache)|14346|14346|8|0.0%|0.1%|
[nixspam](#nixspam)|22818|22818|6|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|5|0.0%|0.0%|
[ciarmy](#ciarmy)|488|488|3|0.6%|0.0%|
[zeus](#zeus)|230|230|2|0.8%|0.0%|
[sorbs_spam](#sorbs_spam)|64701|65536|2|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|2|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|2|0.0%|0.0%|
[php_harvesters](#php_harvesters)|408|408|2|0.4%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|2|0.1%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|1526|1526|2|0.1%|0.0%|
[zeus_badips](#zeus_badips)|202|202|1|0.4%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|1|0.0%|0.0%|
[php_spammers](#php_spammers)|735|735|1|0.1%|0.0%|
[dragon_vncprobe](#dragon_vncprobe)|88|88|1|1.1%|0.0%|

## openbl_7d

[OpenBL.org](http://www.openbl.org/) last 7 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.

Source is downloaded from [this link](http://www.openbl.org/lists/base_7days.txt).

The last time downloaded was found to be dated: Thu Jun 11 20:07:00 UTC 2015.

The ipset `openbl_7d` has **635** entries, **635** unique IPs.

The following table shows the overlaps of `openbl_7d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl_7d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl_7d`.
- ` this % ` is the percentage **of this ipset (`openbl_7d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[openbl_60d](#openbl_60d)|6978|6978|635|9.1%|100.0%|
[openbl_30d](#openbl_30d)|2805|2805|635|22.6%|100.0%|
[firehol_level3](#firehol_level3)|109658|9627424|635|0.0%|100.0%|
[alienvault_reputation](#alienvault_reputation)|187341|187341|634|0.3%|99.8%|
[firehol_level2](#firehol_level2)|22007|33621|395|1.1%|62.2%|
[blocklist_de](#blocklist_de)|28426|28426|380|1.3%|59.8%|
[blocklist_de_ssh](#blocklist_de_ssh)|2423|2423|367|15.1%|57.7%|
[dragon_sshpauth](#dragon_sshpauth)|1633|1695|346|20.4%|54.4%|
[et_compromised](#et_compromised)|1721|1721|311|18.0%|48.9%|
[bruteforceblocker](#bruteforceblocker)|1695|1695|308|18.1%|48.5%|
[shunlist](#shunlist)|1151|1151|196|17.0%|30.8%|
[openbl_1d](#openbl_1d)|148|148|140|94.5%|22.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|64|0.0%|10.0%|
[et_block](#et_block)|1000|18344011|62|0.0%|9.7%|
[firehol_level1](#firehol_level1)|5138|688854748|54|0.0%|8.5%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|53|0.0%|8.3%|
[dragon_http](#dragon_http)|1029|270336|53|0.0%|8.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|38|0.0%|5.9%|
[blocklist_de_strongips](#blocklist_de_strongips)|172|172|22|12.7%|3.4%|
[dshield](#dshield)|20|5120|15|0.2%|2.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|14|0.0%|2.2%|
[blocklist_de_mail](#blocklist_de_mail)|18299|18299|7|0.0%|1.1%|
[blocklist_de_imap](#blocklist_de_imap)|2839|2839|6|0.2%|0.9%|
[blocklist_de_apache](#blocklist_de_apache)|14346|14346|5|0.0%|0.7%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|4|0.0%|0.6%|
[ciarmy](#ciarmy)|488|488|3|0.6%|0.4%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|2|0.0%|0.3%|
[zeus_badips](#zeus_badips)|202|202|1|0.4%|0.1%|
[zeus](#zeus)|230|230|1|0.4%|0.1%|
[snort_ipfilter](#snort_ipfilter)|9671|9671|1|0.0%|0.1%|
[php_spammers](#php_spammers)|735|735|1|0.1%|0.1%|
[php_commenters](#php_commenters)|458|458|1|0.2%|0.1%|
[nixspam](#nixspam)|22818|22818|1|0.0%|0.1%|
[dragon_vncprobe](#dragon_vncprobe)|88|88|1|1.1%|0.1%|
[blocklist_de_ftp](#blocklist_de_ftp)|1526|1526|1|0.0%|0.1%|

## palevo

[Abuse.ch Palevo tracker](https://palevotracker.abuse.ch) worm includes IPs which are being used as botnet C&C for the Palevo crimeware - **excellent list**

Source is downloaded from [this link](https://palevotracker.abuse.ch/blocklists.php?download=ipblocklist).

The last time downloaded was found to be dated: Thu Jun 11 22:09:17 UTC 2015.

The ipset `palevo` has **13** entries, **13** unique IPs.

The following table shows the overlaps of `palevo` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `palevo`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `palevo`.
- ` this % ` is the percentage **of this ipset (`palevo`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level1](#firehol_level1)|5138|688854748|13|0.0%|100.0%|
[et_block](#et_block)|1000|18344011|13|0.0%|100.0%|
[snort_ipfilter](#snort_ipfilter)|9671|9671|11|0.1%|84.6%|
[firehol_level3](#firehol_level3)|109658|9627424|11|0.0%|84.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|3|0.0%|23.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|2|0.0%|15.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|1|0.0%|7.6%|

## php_commenters

[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) comment spammers (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=c&rss=1).

The last time downloaded was found to be dated: Thu Jun 11 21:36:29 UTC 2015.

The ipset `php_commenters` has **458** entries, **458** unique IPs.

The following table shows the overlaps of `php_commenters` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `php_commenters`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `php_commenters`.
- ` this % ` is the percentage **of this ipset (`php_commenters`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level3](#firehol_level3)|109658|9627424|458|0.0%|100.0%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|334|0.3%|72.9%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|249|0.8%|54.3%|
[firehol_level2](#firehol_level2)|22007|33621|200|0.5%|43.6%|
[stopforumspam_1d](#stopforumspam_1d)|6697|6697|172|2.5%|37.5%|
[blocklist_de](#blocklist_de)|28426|28426|111|0.3%|24.2%|
[firehol_anonymous](#firehol_anonymous)|19168|83212|90|0.1%|19.6%|
[blocklist_de_bots](#blocklist_de_bots)|2960|2960|88|2.9%|19.2%|
[firehol_proxies](#firehol_proxies)|12674|12945|86|0.6%|18.7%|
[snort_ipfilter](#snort_ipfilter)|9671|9671|71|0.7%|15.5%|
[tor_exits](#tor_exits)|1112|1112|54|4.8%|11.7%|
[php_spammers](#php_spammers)|735|735|54|7.3%|11.7%|
[et_tor](#et_tor)|6400|6400|54|0.8%|11.7%|
[dm_tor](#dm_tor)|6521|6521|54|0.8%|11.7%|
[bm_tor](#bm_tor)|6525|6525|54|0.8%|11.7%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|53|10.1%|11.5%|
[blocklist_de_strongips](#blocklist_de_strongips)|172|172|45|26.1%|9.8%|
[php_dictionary](#php_dictionary)|737|737|38|5.1%|8.2%|
[firehol_level1](#firehol_level1)|5138|688854748|38|0.0%|8.2%|
[ri_web_proxies](#ri_web_proxies)|7852|7852|30|0.3%|6.5%|
[blocklist_de_mail](#blocklist_de_mail)|18299|18299|30|0.1%|6.5%|
[blocklist_de_apache](#blocklist_de_apache)|14346|14346|30|0.2%|6.5%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|29|0.0%|6.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|29|0.0%|6.3%|
[et_block](#et_block)|1000|18344011|29|0.0%|6.3%|
[sorbs_spam](#sorbs_spam)|64701|65536|27|0.0%|5.8%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|27|0.0%|5.8%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|27|0.0%|5.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|19|0.0%|4.1%|
[alienvault_reputation](#alienvault_reputation)|187341|187341|19|0.0%|4.1%|
[nixspam](#nixspam)|22818|22818|18|0.0%|3.9%|
[php_harvesters](#php_harvesters)|408|408|15|3.6%|3.2%|
[xroxy](#xroxy)|2169|2169|13|0.5%|2.8%|
[openbl_60d](#openbl_60d)|6978|6978|12|0.1%|2.6%|
[proxz](#proxz)|1323|1323|10|0.7%|2.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|10|0.0%|2.1%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2901|2901|9|0.3%|1.9%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|8|0.0%|1.7%|
[ri_connect_proxies](#ri_connect_proxies)|2828|2828|6|0.2%|1.3%|
[proxyrss](#proxyrss)|1638|1638|6|0.3%|1.3%|
[iw_spamlist](#iw_spamlist)|3878|3878|4|0.1%|0.8%|
[dragon_http](#dragon_http)|1029|270336|4|0.0%|0.8%|
[sorbs_web](#sorbs_web)|568|569|3|0.5%|0.6%|
[zeus_badips](#zeus_badips)|202|202|1|0.4%|0.2%|
[zeus](#zeus)|230|230|1|0.4%|0.2%|
[openbl_7d](#openbl_7d)|635|635|1|0.1%|0.2%|
[openbl_30d](#openbl_30d)|2805|2805|1|0.0%|0.2%|
[openbl_1d](#openbl_1d)|148|148|1|0.6%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.2%|
[fullbogons](#fullbogons)|3775|670173256|1|0.0%|0.2%|
[et_compromised](#et_compromised)|1721|1721|1|0.0%|0.2%|
[bruteforceblocker](#bruteforceblocker)|1695|1695|1|0.0%|0.2%|
[bogons](#bogons)|13|592708608|1|0.0%|0.2%|
[blocklist_de_ssh](#blocklist_de_ssh)|2423|2423|1|0.0%|0.2%|

## php_dictionary

[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) directory attackers (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=d&rss=1).

The last time downloaded was found to be dated: Thu Jun 11 21:36:33 UTC 2015.

The ipset `php_dictionary` has **737** entries, **737** unique IPs.

The following table shows the overlaps of `php_dictionary` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `php_dictionary`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `php_dictionary`.
- ` this % ` is the percentage **of this ipset (`php_dictionary`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level3](#firehol_level3)|109658|9627424|737|0.0%|100.0%|
[php_spammers](#php_spammers)|735|735|322|43.8%|43.6%|
[sorbs_spam](#sorbs_spam)|64701|65536|214|0.3%|29.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|214|0.3%|29.0%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|214|0.3%|29.0%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|139|0.1%|18.8%|
[firehol_level2](#firehol_level2)|22007|33621|127|0.3%|17.2%|
[nixspam](#nixspam)|22818|22818|119|0.5%|16.1%|
[blocklist_de](#blocklist_de)|28426|28426|119|0.4%|16.1%|
[blocklist_de_mail](#blocklist_de_mail)|18299|18299|100|0.5%|13.5%|
[firehol_anonymous](#firehol_anonymous)|19168|83212|98|0.1%|13.2%|
[firehol_proxies](#firehol_proxies)|12674|12945|97|0.7%|13.1%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|94|0.3%|12.7%|
[snort_ipfilter](#snort_ipfilter)|9671|9671|91|0.9%|12.3%|
[ri_web_proxies](#ri_web_proxies)|7852|7852|67|0.8%|9.0%|
[xroxy](#xroxy)|2169|2169|41|1.8%|5.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|39|0.0%|5.2%|
[php_commenters](#php_commenters)|458|458|38|8.2%|5.1%|
[stopforumspam_1d](#stopforumspam_1d)|6697|6697|36|0.5%|4.8%|
[sorbs_web](#sorbs_web)|568|569|32|5.6%|4.3%|
[proxz](#proxz)|1323|1323|25|1.8%|3.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|23|0.0%|3.1%|
[blocklist_de_bots](#blocklist_de_bots)|2960|2960|15|0.5%|2.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|12|0.0%|1.6%|
[iw_spamlist](#iw_spamlist)|3878|3878|7|0.1%|0.9%|
[alienvault_reputation](#alienvault_reputation)|187341|187341|7|0.0%|0.9%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|6|0.0%|0.8%|
[firehol_level1](#firehol_level1)|5138|688854748|6|0.0%|0.8%|
[et_block](#et_block)|1000|18344011|6|0.0%|0.8%|
[ri_connect_proxies](#ri_connect_proxies)|2828|2828|5|0.1%|0.6%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|5|0.9%|0.6%|
[blocklist_de_strongips](#blocklist_de_strongips)|172|172|5|2.9%|0.6%|
[tor_exits](#tor_exits)|1112|1112|4|0.3%|0.5%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|4|0.0%|0.5%|
[et_tor](#et_tor)|6400|6400|4|0.0%|0.5%|
[dm_tor](#dm_tor)|6521|6521|4|0.0%|0.5%|
[bm_tor](#bm_tor)|6525|6525|4|0.0%|0.5%|
[proxyrss](#proxyrss)|1638|1638|3|0.1%|0.4%|
[php_harvesters](#php_harvesters)|408|408|3|0.7%|0.4%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|3|0.0%|0.4%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2901|2901|3|0.1%|0.4%|
[blocklist_de_apache](#blocklist_de_apache)|14346|14346|3|0.0%|0.4%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|2|0.3%|0.2%|
[dragon_http](#dragon_http)|1029|270336|2|0.0%|0.2%|
[sorbs_socks](#sorbs_socks)|7|7|1|14.2%|0.1%|
[sorbs_misc](#sorbs_misc)|7|7|1|14.2%|0.1%|
[sorbs_http](#sorbs_http)|7|7|1|14.2%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.1%|
[blocklist_de_ftp](#blocklist_de_ftp)|1526|1526|1|0.0%|0.1%|

## php_harvesters

[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) harvesters (IPs that surf the internet looking for email addresses) (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=h&rss=1).

The last time downloaded was found to be dated: Thu Jun 11 21:36:24 UTC 2015.

The ipset `php_harvesters` has **408** entries, **408** unique IPs.

The following table shows the overlaps of `php_harvesters` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `php_harvesters`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `php_harvesters`.
- ` this % ` is the percentage **of this ipset (`php_harvesters`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level3](#firehol_level3)|109658|9627424|408|0.0%|100.0%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|87|0.0%|21.3%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|61|0.2%|14.9%|
[firehol_level2](#firehol_level2)|22007|33621|59|0.1%|14.4%|
[stopforumspam_1d](#stopforumspam_1d)|6697|6697|44|0.6%|10.7%|
[blocklist_de](#blocklist_de)|28426|28426|40|0.1%|9.8%|
[blocklist_de_bots](#blocklist_de_bots)|2960|2960|28|0.9%|6.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|20|0.0%|4.9%|
[sorbs_spam](#sorbs_spam)|64701|65536|16|0.0%|3.9%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|16|0.0%|3.9%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|16|0.0%|3.9%|
[php_commenters](#php_commenters)|458|458|15|3.2%|3.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|12|0.0%|2.9%|
[firehol_proxies](#firehol_proxies)|12674|12945|12|0.0%|2.9%|
[firehol_anonymous](#firehol_anonymous)|19168|83212|12|0.0%|2.9%|
[alienvault_reputation](#alienvault_reputation)|187341|187341|12|0.0%|2.9%|
[snort_ipfilter](#snort_ipfilter)|9671|9671|11|0.1%|2.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|9|0.0%|2.2%|
[nixspam](#nixspam)|22818|22818|8|0.0%|1.9%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|7|1.3%|1.7%|
[et_tor](#et_tor)|6400|6400|7|0.1%|1.7%|
[dm_tor](#dm_tor)|6521|6521|7|0.1%|1.7%|
[bm_tor](#bm_tor)|6525|6525|7|0.1%|1.7%|
[tor_exits](#tor_exits)|1112|1112|6|0.5%|1.4%|
[blocklist_de_mail](#blocklist_de_mail)|18299|18299|6|0.0%|1.4%|
[blocklist_de_ftp](#blocklist_de_ftp)|1526|1526|4|0.2%|0.9%|
[php_spammers](#php_spammers)|735|735|3|0.4%|0.7%|
[php_dictionary](#php_dictionary)|737|737|3|0.4%|0.7%|
[iw_spamlist](#iw_spamlist)|3878|3878|3|0.0%|0.7%|
[firehol_level1](#firehol_level1)|5138|688854748|3|0.0%|0.7%|
[blocklist_de_strongips](#blocklist_de_strongips)|172|172|3|1.7%|0.7%|
[xroxy](#xroxy)|2169|2169|2|0.0%|0.4%|
[ri_web_proxies](#ri_web_proxies)|7852|7852|2|0.0%|0.4%|
[openbl_60d](#openbl_60d)|6978|6978|2|0.0%|0.4%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|2|0.0%|0.4%|
[blocklist_de_imap](#blocklist_de_imap)|2839|2839|2|0.0%|0.4%|
[blocklist_de_apache](#blocklist_de_apache)|14346|14346|2|0.0%|0.4%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|1|0.0%|0.2%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|1|0.0%|0.2%|
[ri_connect_proxies](#ri_connect_proxies)|2828|2828|1|0.0%|0.2%|
[proxyrss](#proxyrss)|1638|1638|1|0.0%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.2%|
[fullbogons](#fullbogons)|3775|670173256|1|0.0%|0.2%|
[et_block](#et_block)|1000|18344011|1|0.0%|0.2%|
[bogons](#bogons)|13|592708608|1|0.0%|0.2%|
[blocklist_de_ssh](#blocklist_de_ssh)|2423|2423|1|0.0%|0.2%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2901|2901|1|0.0%|0.2%|

## php_spammers

[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) spam servers (IPs used by spammers to send messages) (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=s&rss=1).

The last time downloaded was found to be dated: Thu Jun 11 21:36:28 UTC 2015.

The ipset `php_spammers` has **735** entries, **735** unique IPs.

The following table shows the overlaps of `php_spammers` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `php_spammers`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `php_spammers`.
- ` this % ` is the percentage **of this ipset (`php_spammers`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level3](#firehol_level3)|109658|9627424|735|0.0%|100.0%|
[php_dictionary](#php_dictionary)|737|737|322|43.6%|43.8%|
[sorbs_spam](#sorbs_spam)|64701|65536|184|0.2%|25.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|184|0.2%|25.0%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|184|0.2%|25.0%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|151|0.1%|20.5%|
[firehol_level2](#firehol_level2)|22007|33621|117|0.3%|15.9%|
[blocklist_de](#blocklist_de)|28426|28426|108|0.3%|14.6%|
[nixspam](#nixspam)|22818|22818|98|0.4%|13.3%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|95|0.3%|12.9%|
[snort_ipfilter](#snort_ipfilter)|9671|9671|85|0.8%|11.5%|
[firehol_anonymous](#firehol_anonymous)|19168|83212|82|0.0%|11.1%|
[firehol_proxies](#firehol_proxies)|12674|12945|80|0.6%|10.8%|
[blocklist_de_mail](#blocklist_de_mail)|18299|18299|80|0.4%|10.8%|
[ri_web_proxies](#ri_web_proxies)|7852|7852|54|0.6%|7.3%|
[php_commenters](#php_commenters)|458|458|54|11.7%|7.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|54|0.0%|7.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|44|0.0%|5.9%|
[stopforumspam_1d](#stopforumspam_1d)|6697|6697|41|0.6%|5.5%|
[xroxy](#xroxy)|2169|2169|34|1.5%|4.6%|
[sorbs_web](#sorbs_web)|568|569|27|4.7%|3.6%|
[proxz](#proxz)|1323|1323|22|1.6%|2.9%|
[blocklist_de_bots](#blocklist_de_bots)|2960|2960|21|0.7%|2.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|11|0.0%|1.4%|
[blocklist_de_strongips](#blocklist_de_strongips)|172|172|10|5.8%|1.3%|
[iw_spamlist](#iw_spamlist)|3878|3878|7|0.1%|0.9%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|6|1.1%|0.8%|
[tor_exits](#tor_exits)|1112|1112|5|0.4%|0.6%|
[et_tor](#et_tor)|6400|6400|5|0.0%|0.6%|
[dm_tor](#dm_tor)|6521|6521|5|0.0%|0.6%|
[bm_tor](#bm_tor)|6525|6525|5|0.0%|0.6%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2901|2901|5|0.1%|0.6%|
[blocklist_de_apache](#blocklist_de_apache)|14346|14346|5|0.0%|0.6%|
[alienvault_reputation](#alienvault_reputation)|187341|187341|5|0.0%|0.6%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|4|0.0%|0.5%|
[firehol_level1](#firehol_level1)|5138|688854748|4|0.0%|0.5%|
[et_block](#et_block)|1000|18344011|4|0.0%|0.5%|
[ri_connect_proxies](#ri_connect_proxies)|2828|2828|3|0.1%|0.4%|
[php_harvesters](#php_harvesters)|408|408|3|0.7%|0.4%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|0.4%|
[proxyrss](#proxyrss)|1638|1638|2|0.1%|0.2%|
[openbl_7d](#openbl_7d)|635|635|1|0.1%|0.1%|
[openbl_60d](#openbl_60d)|6978|6978|1|0.0%|0.1%|
[openbl_30d](#openbl_30d)|2805|2805|1|0.0%|0.1%|
[openbl_1d](#openbl_1d)|148|148|1|0.6%|0.1%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|1|0.1%|0.1%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|1|0.0%|0.1%|
[et_compromised](#et_compromised)|1721|1721|1|0.0%|0.1%|
[bruteforceblocker](#bruteforceblocker)|1695|1695|1|0.0%|0.1%|
[blocklist_de_ssh](#blocklist_de_ssh)|2423|2423|1|0.0%|0.1%|
[blocklist_de_ftp](#blocklist_de_ftp)|1526|1526|1|0.0%|0.1%|

## proxyrss

[proxyrss.com](http://www.proxyrss.com) open proxies syndicated from multiple sources.

Source is downloaded from [this link](http://www.proxyrss.com/proxylists/all.gz).

The last time downloaded was found to be dated: Thu Jun 11 18:51:22 UTC 2015.

The ipset `proxyrss` has **1638** entries, **1638** unique IPs.

The following table shows the overlaps of `proxyrss` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `proxyrss`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `proxyrss`.
- ` this % ` is the percentage **of this ipset (`proxyrss`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_proxies](#firehol_proxies)|12674|12945|1638|12.6%|100.0%|
[firehol_anonymous](#firehol_anonymous)|19168|83212|1638|1.9%|100.0%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|709|0.7%|43.2%|
[firehol_level3](#firehol_level3)|109658|9627424|709|0.0%|43.2%|
[ri_web_proxies](#ri_web_proxies)|7852|7852|630|8.0%|38.4%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|507|1.7%|30.9%|
[firehol_level2](#firehol_level2)|22007|33621|388|1.1%|23.6%|
[xroxy](#xroxy)|2169|2169|345|15.9%|21.0%|
[stopforumspam_1d](#stopforumspam_1d)|6697|6697|321|4.7%|19.5%|
[proxz](#proxz)|1323|1323|294|22.2%|17.9%|
[ri_connect_proxies](#ri_connect_proxies)|2828|2828|227|8.0%|13.8%|
[blocklist_de_bots](#blocklist_de_bots)|2960|2960|220|7.4%|13.4%|
[blocklist_de](#blocklist_de)|28426|28426|219|0.7%|13.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|58|0.0%|3.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|46|0.0%|2.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|35|0.0%|2.1%|
[nixspam](#nixspam)|22818|22818|11|0.0%|0.6%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|9|1.3%|0.5%|
[sorbs_spam](#sorbs_spam)|64701|65536|7|0.0%|0.4%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|7|0.0%|0.4%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|7|0.0%|0.4%|
[blocklist_de_strongips](#blocklist_de_strongips)|172|172|7|4.0%|0.4%|
[php_commenters](#php_commenters)|458|458|6|1.3%|0.3%|
[php_dictionary](#php_dictionary)|737|737|3|0.4%|0.1%|
[snort_ipfilter](#snort_ipfilter)|9671|9671|2|0.0%|0.1%|
[php_spammers](#php_spammers)|735|735|2|0.2%|0.1%|
[php_harvesters](#php_harvesters)|408|408|1|0.2%|0.0%|
[iw_spamlist](#iw_spamlist)|3878|3878|1|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|1|0.0%|0.0%|
[et_compromised](#et_compromised)|1721|1721|1|0.0%|0.0%|
[dragon_http](#dragon_http)|1029|270336|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1695|1695|1|0.0%|0.0%|
[alienvault_reputation](#alienvault_reputation)|187341|187341|1|0.0%|0.0%|

## proxz

[proxz.com](http://www.proxz.com) open proxies (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.proxz.com/proxylists.xml).

The last time downloaded was found to be dated: Thu Jun 11 21:11:23 UTC 2015.

The ipset `proxz` has **1323** entries, **1323** unique IPs.

The following table shows the overlaps of `proxz` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `proxz`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `proxz`.
- ` this % ` is the percentage **of this ipset (`proxz`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_proxies](#firehol_proxies)|12674|12945|1323|10.2%|100.0%|
[firehol_anonymous](#firehol_anonymous)|19168|83212|1323|1.5%|100.0%|
[firehol_level3](#firehol_level3)|109658|9627424|782|0.0%|59.1%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|776|0.8%|58.6%|
[ri_web_proxies](#ri_web_proxies)|7852|7852|605|7.7%|45.7%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|503|1.7%|38.0%|
[xroxy](#xroxy)|2169|2169|459|21.1%|34.6%|
[proxyrss](#proxyrss)|1638|1638|294|17.9%|22.2%|
[firehol_level2](#firehol_level2)|22007|33621|283|0.8%|21.3%|
[ri_connect_proxies](#ri_connect_proxies)|2828|2828|229|8.0%|17.3%|
[stopforumspam_1d](#stopforumspam_1d)|6697|6697|196|2.9%|14.8%|
[blocklist_de](#blocklist_de)|28426|28426|194|0.6%|14.6%|
[blocklist_de_bots](#blocklist_de_bots)|2960|2960|161|5.4%|12.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|105|0.0%|7.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|54|0.0%|4.0%|
[sorbs_spam](#sorbs_spam)|64701|65536|44|0.0%|3.3%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|44|0.0%|3.3%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|44|0.0%|3.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|44|0.0%|3.3%|
[nixspam](#nixspam)|22818|22818|42|0.1%|3.1%|
[blocklist_de_mail](#blocklist_de_mail)|18299|18299|33|0.1%|2.4%|
[snort_ipfilter](#snort_ipfilter)|9671|9671|27|0.2%|2.0%|
[php_dictionary](#php_dictionary)|737|737|25|3.3%|1.8%|
[php_spammers](#php_spammers)|735|735|22|2.9%|1.6%|
[php_commenters](#php_commenters)|458|458|10|2.1%|0.7%|
[sorbs_web](#sorbs_web)|568|569|8|1.4%|0.6%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|6|0.9%|0.4%|
[blocklist_de_strongips](#blocklist_de_strongips)|172|172|6|3.4%|0.4%|
[dragon_http](#dragon_http)|1029|270336|4|0.0%|0.3%|
[alienvault_reputation](#alienvault_reputation)|187341|187341|3|0.0%|0.2%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|2|0.3%|0.1%|
[et_compromised](#et_compromised)|1721|1721|2|0.1%|0.1%|
[bruteforceblocker](#bruteforceblocker)|1695|1695|2|0.1%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|1|0.0%|0.0%|

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
[firehol_proxies](#firehol_proxies)|12674|12945|2828|21.8%|100.0%|
[firehol_anonymous](#firehol_anonymous)|19168|83212|2828|3.3%|100.0%|
[firehol_level3](#firehol_level3)|109658|9627424|1586|0.0%|56.0%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|1585|1.6%|56.0%|
[ri_web_proxies](#ri_web_proxies)|7852|7852|1207|15.3%|42.6%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|563|1.9%|19.9%|
[xroxy](#xroxy)|2169|2169|396|18.2%|14.0%|
[proxz](#proxz)|1323|1323|229|17.3%|8.0%|
[proxyrss](#proxyrss)|1638|1638|227|13.8%|8.0%|
[firehol_level2](#firehol_level2)|22007|33621|154|0.4%|5.4%|
[stopforumspam_1d](#stopforumspam_1d)|6697|6697|114|1.7%|4.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|106|0.0%|3.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|86|0.0%|3.0%|
[blocklist_de](#blocklist_de)|28426|28426|74|0.2%|2.6%|
[blocklist_de_bots](#blocklist_de_bots)|2960|2960|70|2.3%|2.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|57|0.0%|2.0%|
[nixspam](#nixspam)|22818|22818|19|0.0%|0.6%|
[sorbs_spam](#sorbs_spam)|64701|65536|18|0.0%|0.6%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|18|0.0%|0.6%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|18|0.0%|0.6%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|7|1.0%|0.2%|
[snort_ipfilter](#snort_ipfilter)|9671|9671|6|0.0%|0.2%|
[php_commenters](#php_commenters)|458|458|6|1.3%|0.2%|
[php_dictionary](#php_dictionary)|737|737|5|0.6%|0.1%|
[blocklist_de_mail](#blocklist_de_mail)|18299|18299|4|0.0%|0.1%|
[php_spammers](#php_spammers)|735|735|3|0.4%|0.1%|
[dragon_http](#dragon_http)|1029|270336|3|0.0%|0.1%|
[alienvault_reputation](#alienvault_reputation)|187341|187341|3|0.0%|0.1%|
[sorbs_web](#sorbs_web)|568|569|1|0.1%|0.0%|
[php_harvesters](#php_harvesters)|408|408|1|0.2%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|1|0.1%|0.0%|
[iw_spamlist](#iw_spamlist)|3878|3878|1|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.0%|
[dm_tor](#dm_tor)|6521|6521|1|0.0%|0.0%|
[bm_tor](#bm_tor)|6525|6525|1|0.0%|0.0%|

## ri_web_proxies

[rosinstrument.com](http://www.rosinstrument.com) open HTTP proxies (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://tools.rosinstrument.com/proxy/l100.xml).

The last time downloaded was found to be dated: Thu Jun 11 21:54:52 UTC 2015.

The ipset `ri_web_proxies` has **7852** entries, **7852** unique IPs.

The following table shows the overlaps of `ri_web_proxies` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ri_web_proxies`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ri_web_proxies`.
- ` this % ` is the percentage **of this ipset (`ri_web_proxies`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_proxies](#firehol_proxies)|12674|12945|7852|60.6%|100.0%|
[firehol_anonymous](#firehol_anonymous)|19168|83212|7852|9.4%|100.0%|
[firehol_level3](#firehol_level3)|109658|9627424|3743|0.0%|47.6%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|3696|3.9%|47.0%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|1531|5.2%|19.4%|
[ri_connect_proxies](#ri_connect_proxies)|2828|2828|1207|42.6%|15.3%|
[xroxy](#xroxy)|2169|2169|963|44.3%|12.2%|
[firehol_level2](#firehol_level2)|22007|33621|659|1.9%|8.3%|
[proxyrss](#proxyrss)|1638|1638|630|38.4%|8.0%|
[proxz](#proxz)|1323|1323|605|45.7%|7.7%|
[blocklist_de](#blocklist_de)|28426|28426|476|1.6%|6.0%|
[stopforumspam_1d](#stopforumspam_1d)|6697|6697|432|6.4%|5.5%|
[blocklist_de_bots](#blocklist_de_bots)|2960|2960|390|13.1%|4.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|224|0.0%|2.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|220|0.0%|2.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|156|0.0%|1.9%|
[sorbs_spam](#sorbs_spam)|64701|65536|145|0.2%|1.8%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|145|0.2%|1.8%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|145|0.2%|1.8%|
[nixspam](#nixspam)|22818|22818|122|0.5%|1.5%|
[blocklist_de_mail](#blocklist_de_mail)|18299|18299|84|0.4%|1.0%|
[php_dictionary](#php_dictionary)|737|737|67|9.0%|0.8%|
[snort_ipfilter](#snort_ipfilter)|9671|9671|64|0.6%|0.8%|
[php_spammers](#php_spammers)|735|735|54|7.3%|0.6%|
[php_commenters](#php_commenters)|458|458|30|6.5%|0.3%|
[sorbs_web](#sorbs_web)|568|569|21|3.6%|0.2%|
[dragon_http](#dragon_http)|1029|270336|18|0.0%|0.2%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|15|2.2%|0.1%|
[iw_spamlist](#iw_spamlist)|3878|3878|11|0.2%|0.1%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|10|1.9%|0.1%|
[blocklist_de_strongips](#blocklist_de_strongips)|172|172|8|4.6%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|6|0.0%|0.0%|
[dm_tor](#dm_tor)|6521|6521|5|0.0%|0.0%|
[bm_tor](#bm_tor)|6525|6525|5|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|4|0.0%|0.0%|
[et_tor](#et_tor)|6400|6400|4|0.0%|0.0%|
[alienvault_reputation](#alienvault_reputation)|187341|187341|4|0.0%|0.0%|
[php_harvesters](#php_harvesters)|408|408|2|0.4%|0.0%|
[sslbl](#sslbl)|371|371|1|0.2%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|1|0.0%|0.0%|
[firehol_level1](#firehol_level1)|5138|688854748|1|0.0%|0.0%|
[et_compromised](#et_compromised)|1721|1721|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1695|1695|1|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2423|2423|1|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2901|2901|1|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14346|14346|1|0.0%|0.0%|

## shunlist

[AutoShun.org](http://autoshun.org/) IPs identified as hostile by correlating logs from distributed snort installations running the autoshun plugin

Source is downloaded from [this link](http://www.autoshun.org/files/shunlist.csv).

The last time downloaded was found to be dated: Thu Jun 11 19:30:02 UTC 2015.

The ipset `shunlist` has **1151** entries, **1151** unique IPs.

The following table shows the overlaps of `shunlist` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `shunlist`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `shunlist`.
- ` this % ` is the percentage **of this ipset (`shunlist`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level3](#firehol_level3)|109658|9627424|1151|0.0%|100.0%|
[alienvault_reputation](#alienvault_reputation)|187341|187341|1144|0.6%|99.3%|
[openbl_60d](#openbl_60d)|6978|6978|454|6.5%|39.4%|
[openbl_30d](#openbl_30d)|2805|2805|428|15.2%|37.1%|
[dragon_sshpauth](#dragon_sshpauth)|1633|1695|375|22.1%|32.5%|
[et_compromised](#et_compromised)|1721|1721|368|21.3%|31.9%|
[firehol_level2](#firehol_level2)|22007|33621|365|1.0%|31.7%|
[blocklist_de](#blocklist_de)|28426|28426|360|1.2%|31.2%|
[bruteforceblocker](#bruteforceblocker)|1695|1695|333|19.6%|28.9%|
[blocklist_de_ssh](#blocklist_de_ssh)|2423|2423|321|13.2%|27.8%|
[openbl_7d](#openbl_7d)|635|635|196|30.8%|17.0%|
[firehol_level1](#firehol_level1)|5138|688854748|153|0.0%|13.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|115|0.0%|9.9%|
[et_block](#et_block)|1000|18344011|98|0.0%|8.5%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|90|0.0%|7.8%|
[dshield](#dshield)|20|5120|77|1.5%|6.6%|
[openbl_1d](#openbl_1d)|148|148|76|51.3%|6.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|69|0.0%|5.9%|
[sslbl](#sslbl)|371|371|58|15.6%|5.0%|
[blocklist_de_apache](#blocklist_de_apache)|14346|14346|34|0.2%|2.9%|
[ciarmy](#ciarmy)|488|488|29|5.9%|2.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|25|0.0%|2.1%|
[dragon_http](#dragon_http)|1029|270336|22|0.0%|1.9%|
[blocklist_de_strongips](#blocklist_de_strongips)|172|172|19|11.0%|1.6%|
[voipbl](#voipbl)|10586|10998|13|0.1%|1.1%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|4|0.0%|0.3%|
[dragon_vncprobe](#dragon_vncprobe)|88|88|3|3.4%|0.2%|
[blocklist_de_mail](#blocklist_de_mail)|18299|18299|3|0.0%|0.2%|
[blocklist_de_imap](#blocklist_de_imap)|2839|2839|3|0.1%|0.2%|
[stopforumspam_1d](#stopforumspam_1d)|6697|6697|2|0.0%|0.1%|
[sorbs_spam](#sorbs_spam)|64701|65536|2|0.0%|0.1%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|2|0.0%|0.1%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|2|0.0%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2|0.0%|0.1%|
[blocklist_de_sip](#blocklist_de_sip)|84|84|2|2.3%|0.1%|
[tor_exits](#tor_exits)|1112|1112|1|0.0%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|1|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9671|9671|1|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|1|0.1%|0.0%|
[firehol_proxies](#firehol_proxies)|12674|12945|1|0.0%|0.0%|
[firehol_anonymous](#firehol_anonymous)|19168|83212|1|0.0%|0.0%|
[et_tor](#et_tor)|6400|6400|1|0.0%|0.0%|
[dm_tor](#dm_tor)|6521|6521|1|0.0%|0.0%|
[bm_tor](#bm_tor)|6525|6525|1|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2901|2901|1|0.0%|0.0%|

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
[firehol_level3](#firehol_level3)|109658|9627424|9671|0.1%|100.0%|
[firehol_anonymous](#firehol_anonymous)|19168|83212|1246|1.4%|12.8%|
[et_tor](#et_tor)|6400|6400|1088|17.0%|11.2%|
[tor_exits](#tor_exits)|1112|1112|1085|97.5%|11.2%|
[bm_tor](#bm_tor)|6525|6525|1061|16.2%|10.9%|
[dm_tor](#dm_tor)|6521|6521|1060|16.2%|10.9%|
[sorbs_spam](#sorbs_spam)|64701|65536|846|1.2%|8.7%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|846|1.2%|8.7%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|846|1.2%|8.7%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|812|0.8%|8.3%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|667|2.2%|6.8%|
[firehol_level2](#firehol_level2)|22007|33621|537|1.5%|5.5%|
[stopforumspam_1d](#stopforumspam_1d)|6697|6697|350|5.2%|3.6%|
[firehol_proxies](#firehol_proxies)|12674|12945|330|2.5%|3.4%|
[firehol_level1](#firehol_level1)|5138|688854748|299|0.0%|3.0%|
[et_block](#et_block)|1000|18344011|297|0.0%|3.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|241|0.0%|2.4%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|237|45.2%|2.4%|
[blocklist_de](#blocklist_de)|28426|28426|222|0.7%|2.2%|
[zeus](#zeus)|230|230|200|86.9%|2.0%|
[nixspam](#nixspam)|22818|22818|199|0.8%|2.0%|
[zeus_badips](#zeus_badips)|202|202|178|88.1%|1.8%|
[blocklist_de_mail](#blocklist_de_mail)|18299|18299|175|0.9%|1.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|138|0.0%|1.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|116|0.0%|1.1%|
[alienvault_reputation](#alienvault_reputation)|187341|187341|108|0.0%|1.1%|
[php_dictionary](#php_dictionary)|737|737|91|12.3%|0.9%|
[php_spammers](#php_spammers)|735|735|85|11.5%|0.8%|
[feodo](#feodo)|105|105|83|79.0%|0.8%|
[php_commenters](#php_commenters)|458|458|71|15.5%|0.7%|
[ri_web_proxies](#ri_web_proxies)|7852|7852|64|0.8%|0.6%|
[iw_spamlist](#iw_spamlist)|3878|3878|56|1.4%|0.5%|
[sorbs_web](#sorbs_web)|568|569|51|8.9%|0.5%|
[xroxy](#xroxy)|2169|2169|41|1.8%|0.4%|
[blocklist_de_apache](#blocklist_de_apache)|14346|14346|35|0.2%|0.3%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2901|2901|32|1.1%|0.3%|
[sslbl](#sslbl)|371|371|31|8.3%|0.3%|
[proxz](#proxz)|1323|1323|27|2.0%|0.2%|
[openbl_60d](#openbl_60d)|6978|6978|24|0.3%|0.2%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|18|0.0%|0.1%|
[blocklist_de_bots](#blocklist_de_bots)|2960|2960|15|0.5%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|14|0.0%|0.1%|
[php_harvesters](#php_harvesters)|408|408|11|2.6%|0.1%|
[palevo](#palevo)|13|13|11|84.6%|0.1%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|11|0.8%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|11|0.0%|0.1%|
[dragon_http](#dragon_http)|1029|270336|11|0.0%|0.1%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|6|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2828|2828|6|0.2%|0.0%|
[sorbs_socks](#sorbs_socks)|7|7|4|57.1%|0.0%|
[sorbs_misc](#sorbs_misc)|7|7|4|57.1%|0.0%|
[sorbs_http](#sorbs_http)|7|7|4|57.1%|0.0%|
[proxyrss](#proxyrss)|1638|1638|2|0.1%|0.0%|
[openbl_30d](#openbl_30d)|2805|2805|2|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|2|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|172|172|2|1.1%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2839|2839|2|0.0%|0.0%|
[shunlist](#shunlist)|1151|1151|1|0.0%|0.0%|
[openbl_7d](#openbl_7d)|635|635|1|0.1%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|1|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|1|0.1%|0.0%|
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
[firehol_level3](#firehol_level3)|109658|9627424|4|0.0%|57.1%|
[nixspam](#nixspam)|22818|22818|2|0.0%|28.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|2|0.0%|28.5%|
[php_dictionary](#php_dictionary)|737|737|1|0.1%|14.2%|
[iw_spamlist](#iw_spamlist)|3878|3878|1|0.0%|14.2%|
[firehol_level2](#firehol_level2)|22007|33621|1|0.0%|14.2%|
[blocklist_de_mail](#blocklist_de_mail)|18299|18299|1|0.0%|14.2%|
[blocklist_de](#blocklist_de)|28426|28426|1|0.0%|14.2%|

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
[firehol_level3](#firehol_level3)|109658|9627424|4|0.0%|57.1%|
[nixspam](#nixspam)|22818|22818|2|0.0%|28.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|2|0.0%|28.5%|
[php_dictionary](#php_dictionary)|737|737|1|0.1%|14.2%|
[iw_spamlist](#iw_spamlist)|3878|3878|1|0.0%|14.2%|
[firehol_level2](#firehol_level2)|22007|33621|1|0.0%|14.2%|
[blocklist_de_mail](#blocklist_de_mail)|18299|18299|1|0.0%|14.2%|
[blocklist_de](#blocklist_de)|28426|28426|1|0.0%|14.2%|

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
[nixspam](#nixspam)|22818|22818|2910|12.7%|4.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|2851|0.0%|4.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|1736|0.0%|2.6%|
[firehol_level2](#firehol_level2)|22007|33621|1407|4.1%|2.1%|
[blocklist_de](#blocklist_de)|28426|28426|1393|4.9%|2.1%|
[blocklist_de_mail](#blocklist_de_mail)|18299|18299|1304|7.1%|1.9%|
[firehol_level3](#firehol_level3)|109658|9627424|1252|0.0%|1.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|1205|0.0%|1.8%|
[iw_spamlist](#iw_spamlist)|3878|3878|1197|30.8%|1.8%|
[snort_ipfilter](#snort_ipfilter)|9671|9671|846|8.7%|1.2%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|320|0.3%|0.4%|
[sorbs_web](#sorbs_web)|568|569|290|50.9%|0.4%|
[php_dictionary](#php_dictionary)|737|737|214|29.0%|0.3%|
[firehol_anonymous](#firehol_anonymous)|19168|83212|201|0.2%|0.3%|
[firehol_proxies](#firehol_proxies)|12674|12945|196|1.5%|0.3%|
[php_spammers](#php_spammers)|735|735|184|25.0%|0.2%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|169|0.5%|0.2%|
[ri_web_proxies](#ri_web_proxies)|7852|7852|145|1.8%|0.2%|
[alienvault_reputation](#alienvault_reputation)|187341|187341|91|0.0%|0.1%|
[xroxy](#xroxy)|2169|2169|76|3.5%|0.1%|
[dragon_http](#dragon_http)|1029|270336|70|0.0%|0.1%|
[stopforumspam_1d](#stopforumspam_1d)|6697|6697|52|0.7%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2901|2901|46|1.5%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14346|14346|46|0.3%|0.0%|
[proxz](#proxz)|1323|1323|44|3.3%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|37|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2839|2839|32|1.1%|0.0%|
[php_commenters](#php_commenters)|458|458|27|5.8%|0.0%|
[firehol_level1](#firehol_level1)|5138|688854748|27|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|2960|2960|25|0.8%|0.0%|
[et_block](#et_block)|1000|18344011|22|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|20|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|20|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2828|2828|18|0.6%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|17|0.0%|0.0%|
[php_harvesters](#php_harvesters)|408|408|16|3.9%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|1526|1526|15|0.9%|0.0%|
[sorbs_socks](#sorbs_socks)|7|7|7|100.0%|0.0%|
[sorbs_misc](#sorbs_misc)|7|7|7|100.0%|0.0%|
[sorbs_http](#sorbs_http)|7|7|7|100.0%|0.0%|
[proxyrss](#proxyrss)|1638|1638|7|0.4%|0.0%|
[sorbs_smtp](#sorbs_smtp)|6|6|6|100.0%|0.0%|
[tor_exits](#tor_exits)|1112|1112|5|0.4%|0.0%|
[et_tor](#et_tor)|6400|6400|4|0.0%|0.0%|
[dm_tor](#dm_tor)|6521|6521|4|0.0%|0.0%|
[bm_tor](#bm_tor)|6525|6525|4|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2423|2423|4|0.1%|0.0%|
[voipbl](#voipbl)|10586|10998|3|0.0%|0.0%|
[et_compromised](#et_compromised)|1721|1721|3|0.1%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1695|1695|3|0.1%|0.0%|
[shunlist](#shunlist)|1151|1151|2|0.1%|0.0%|
[openbl_60d](#openbl_60d)|6978|6978|2|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|2|0.1%|0.0%|
[dshield](#dshield)|20|5120|2|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|172|172|2|1.1%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|1|0.1%|0.0%|
[malc0de](#malc0de)|276|276|1|0.3%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|1|0.1%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.0%|
[dragon_sshpauth](#dragon_sshpauth)|1633|1695|1|0.0%|0.0%|

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
[nixspam](#nixspam)|22818|22818|2910|12.7%|4.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|2851|0.0%|4.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|1736|0.0%|2.6%|
[firehol_level2](#firehol_level2)|22007|33621|1407|4.1%|2.1%|
[blocklist_de](#blocklist_de)|28426|28426|1393|4.9%|2.1%|
[blocklist_de_mail](#blocklist_de_mail)|18299|18299|1304|7.1%|1.9%|
[firehol_level3](#firehol_level3)|109658|9627424|1252|0.0%|1.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|1205|0.0%|1.8%|
[iw_spamlist](#iw_spamlist)|3878|3878|1197|30.8%|1.8%|
[snort_ipfilter](#snort_ipfilter)|9671|9671|846|8.7%|1.2%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|320|0.3%|0.4%|
[sorbs_web](#sorbs_web)|568|569|290|50.9%|0.4%|
[php_dictionary](#php_dictionary)|737|737|214|29.0%|0.3%|
[firehol_anonymous](#firehol_anonymous)|19168|83212|201|0.2%|0.3%|
[firehol_proxies](#firehol_proxies)|12674|12945|196|1.5%|0.3%|
[php_spammers](#php_spammers)|735|735|184|25.0%|0.2%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|169|0.5%|0.2%|
[ri_web_proxies](#ri_web_proxies)|7852|7852|145|1.8%|0.2%|
[alienvault_reputation](#alienvault_reputation)|187341|187341|91|0.0%|0.1%|
[xroxy](#xroxy)|2169|2169|76|3.5%|0.1%|
[dragon_http](#dragon_http)|1029|270336|70|0.0%|0.1%|
[stopforumspam_1d](#stopforumspam_1d)|6697|6697|52|0.7%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2901|2901|46|1.5%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14346|14346|46|0.3%|0.0%|
[proxz](#proxz)|1323|1323|44|3.3%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|37|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2839|2839|32|1.1%|0.0%|
[php_commenters](#php_commenters)|458|458|27|5.8%|0.0%|
[firehol_level1](#firehol_level1)|5138|688854748|27|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|2960|2960|25|0.8%|0.0%|
[et_block](#et_block)|1000|18344011|22|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|20|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|20|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2828|2828|18|0.6%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|17|0.0%|0.0%|
[php_harvesters](#php_harvesters)|408|408|16|3.9%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|1526|1526|15|0.9%|0.0%|
[sorbs_socks](#sorbs_socks)|7|7|7|100.0%|0.0%|
[sorbs_misc](#sorbs_misc)|7|7|7|100.0%|0.0%|
[sorbs_http](#sorbs_http)|7|7|7|100.0%|0.0%|
[proxyrss](#proxyrss)|1638|1638|7|0.4%|0.0%|
[sorbs_smtp](#sorbs_smtp)|6|6|6|100.0%|0.0%|
[tor_exits](#tor_exits)|1112|1112|5|0.4%|0.0%|
[et_tor](#et_tor)|6400|6400|4|0.0%|0.0%|
[dm_tor](#dm_tor)|6521|6521|4|0.0%|0.0%|
[bm_tor](#bm_tor)|6525|6525|4|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2423|2423|4|0.1%|0.0%|
[voipbl](#voipbl)|10586|10998|3|0.0%|0.0%|
[et_compromised](#et_compromised)|1721|1721|3|0.1%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1695|1695|3|0.1%|0.0%|
[shunlist](#shunlist)|1151|1151|2|0.1%|0.0%|
[openbl_60d](#openbl_60d)|6978|6978|2|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|2|0.1%|0.0%|
[dshield](#dshield)|20|5120|2|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|172|172|2|1.1%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|1|0.1%|0.0%|
[malc0de](#malc0de)|276|276|1|0.3%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|1|0.1%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.0%|
[dragon_sshpauth](#dragon_sshpauth)|1633|1695|1|0.0%|0.0%|

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
[firehol_level3](#firehol_level3)|109658|9627424|4|0.0%|57.1%|
[nixspam](#nixspam)|22818|22818|2|0.0%|28.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|2|0.0%|28.5%|
[php_dictionary](#php_dictionary)|737|737|1|0.1%|14.2%|
[iw_spamlist](#iw_spamlist)|3878|3878|1|0.0%|14.2%|
[firehol_level2](#firehol_level2)|22007|33621|1|0.0%|14.2%|
[blocklist_de_mail](#blocklist_de_mail)|18299|18299|1|0.0%|14.2%|
[blocklist_de](#blocklist_de)|28426|28426|1|0.0%|14.2%|

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
[nixspam](#nixspam)|22818|22818|3017|13.2%|4.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|2860|0.0%|4.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|1740|0.0%|2.6%|
[firehol_level2](#firehol_level2)|22007|33621|1415|4.2%|2.1%|
[blocklist_de](#blocklist_de)|28426|28426|1401|4.9%|2.1%|
[blocklist_de_mail](#blocklist_de_mail)|18299|18299|1312|7.1%|2.0%|
[firehol_level3](#firehol_level3)|109658|9627424|1254|0.0%|1.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|1208|0.0%|1.8%|
[iw_spamlist](#iw_spamlist)|3878|3878|1203|31.0%|1.8%|
[snort_ipfilter](#snort_ipfilter)|9671|9671|846|8.7%|1.2%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|320|0.3%|0.4%|
[sorbs_web](#sorbs_web)|568|569|291|51.1%|0.4%|
[php_dictionary](#php_dictionary)|737|737|214|29.0%|0.3%|
[firehol_anonymous](#firehol_anonymous)|19168|83212|201|0.2%|0.3%|
[firehol_proxies](#firehol_proxies)|12674|12945|196|1.5%|0.2%|
[php_spammers](#php_spammers)|735|735|184|25.0%|0.2%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|169|0.5%|0.2%|
[ri_web_proxies](#ri_web_proxies)|7852|7852|145|1.8%|0.2%|
[alienvault_reputation](#alienvault_reputation)|187341|187341|91|0.0%|0.1%|
[xroxy](#xroxy)|2169|2169|76|3.5%|0.1%|
[dragon_http](#dragon_http)|1029|270336|71|0.0%|0.1%|
[stopforumspam_1d](#stopforumspam_1d)|6697|6697|52|0.7%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2901|2901|46|1.5%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14346|14346|46|0.3%|0.0%|
[proxz](#proxz)|1323|1323|44|3.3%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|38|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2839|2839|33|1.1%|0.0%|
[php_commenters](#php_commenters)|458|458|27|5.8%|0.0%|
[firehol_level1](#firehol_level1)|5138|688854748|27|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|2960|2960|25|0.8%|0.0%|
[et_block](#et_block)|1000|18344011|22|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|20|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|20|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2828|2828|18|0.6%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|17|0.0%|0.0%|
[php_harvesters](#php_harvesters)|408|408|16|3.9%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|1526|1526|15|0.9%|0.0%|
[sorbs_socks](#sorbs_socks)|7|7|7|100.0%|0.0%|
[sorbs_misc](#sorbs_misc)|7|7|7|100.0%|0.0%|
[sorbs_http](#sorbs_http)|7|7|7|100.0%|0.0%|
[proxyrss](#proxyrss)|1638|1638|7|0.4%|0.0%|
[tor_exits](#tor_exits)|1112|1112|5|0.4%|0.0%|
[sorbs_smtp](#sorbs_smtp)|6|6|5|83.3%|0.0%|
[et_tor](#et_tor)|6400|6400|4|0.0%|0.0%|
[dm_tor](#dm_tor)|6521|6521|4|0.0%|0.0%|
[bm_tor](#bm_tor)|6525|6525|4|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2423|2423|4|0.1%|0.0%|
[voipbl](#voipbl)|10586|10998|3|0.0%|0.0%|
[et_compromised](#et_compromised)|1721|1721|3|0.1%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1695|1695|3|0.1%|0.0%|
[shunlist](#shunlist)|1151|1151|2|0.1%|0.0%|
[openbl_60d](#openbl_60d)|6978|6978|2|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|2|0.1%|0.0%|
[dshield](#dshield)|20|5120|2|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|172|172|2|1.1%|0.0%|
[virbl](#virbl)|19|19|1|5.2%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|1|0.1%|0.0%|
[malc0de](#malc0de)|276|276|1|0.3%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|1|0.1%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.0%|
[dragon_sshpauth](#dragon_sshpauth)|1633|1695|1|0.0%|0.0%|

## sorbs_web

[Sorbs.net](https://www.sorbs.net/) WEB exploits, extracted from deltas.

Source is downloaded from [this link]().

The last time downloaded was found to be dated: Thu Jun 11 22:04:07 UTC 2015.

The ipset `sorbs_web` has **568** entries, **569** unique IPs.

The following table shows the overlaps of `sorbs_web` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `sorbs_web`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `sorbs_web`.
- ` this % ` is the percentage **of this ipset (`sorbs_web`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[sorbs_spam](#sorbs_spam)|64701|65536|291|0.4%|51.1%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|290|0.4%|50.9%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|290|0.4%|50.9%|
[nixspam](#nixspam)|22818|22818|117|0.5%|20.5%|
[firehol_level3](#firehol_level3)|109658|9627424|69|0.0%|12.1%|
[firehol_level2](#firehol_level2)|22007|33621|68|0.2%|11.9%|
[blocklist_de](#blocklist_de)|28426|28426|68|0.2%|11.9%|
[blocklist_de_mail](#blocklist_de_mail)|18299|18299|64|0.3%|11.2%|
[snort_ipfilter](#snort_ipfilter)|9671|9671|51|0.5%|8.9%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|45|0.0%|7.9%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|32|0.1%|5.6%|
[php_dictionary](#php_dictionary)|737|737|32|4.3%|5.6%|
[firehol_proxies](#firehol_proxies)|12674|12945|29|0.2%|5.0%|
[firehol_anonymous](#firehol_anonymous)|19168|83212|29|0.0%|5.0%|
[php_spammers](#php_spammers)|735|735|27|3.6%|4.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|27|0.0%|4.7%|
[iw_spamlist](#iw_spamlist)|3878|3878|25|0.6%|4.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|23|0.0%|4.0%|
[ri_web_proxies](#ri_web_proxies)|7852|7852|21|0.2%|3.6%|
[xroxy](#xroxy)|2169|2169|15|0.6%|2.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|14|0.0%|2.4%|
[stopforumspam_1d](#stopforumspam_1d)|6697|6697|8|0.1%|1.4%|
[proxz](#proxz)|1323|1323|8|0.6%|1.4%|
[php_commenters](#php_commenters)|458|458|3|0.6%|0.5%|
[blocklist_de_bots](#blocklist_de_bots)|2960|2960|3|0.1%|0.5%|
[blocklist_de_strongips](#blocklist_de_strongips)|172|172|2|1.1%|0.3%|
[ri_connect_proxies](#ri_connect_proxies)|2828|2828|1|0.0%|0.1%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|1|0.0%|0.1%|
[dragon_http](#dragon_http)|1029|270336|1|0.0%|0.1%|
[blocklist_de_ftp](#blocklist_de_ftp)|1526|1526|1|0.0%|0.1%|
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
[firehol_level1](#firehol_level1)|5138|688854748|18340608|2.6%|100.0%|
[et_block](#et_block)|1000|18344011|18338560|99.9%|99.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|8532506|2.4%|46.5%|
[firehol_level3](#firehol_level3)|109658|9627424|6933039|72.0%|37.8%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|6932480|75.5%|37.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|2272265|0.2%|12.3%|
[fullbogons](#fullbogons)|3775|670173256|151552|0.0%|0.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|130368|0.0%|0.7%|
[alienvault_reputation](#alienvault_reputation)|187341|187341|1385|0.7%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1037|0.3%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|1014|1.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|512|0.1%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|271|0.9%|0.0%|
[firehol_level2](#firehol_level2)|22007|33621|262|0.7%|0.0%|
[dshield](#dshield)|20|5120|256|5.0%|0.0%|
[dragon_http](#dragon_http)|1029|270336|256|0.0%|0.0%|
[openbl_60d](#openbl_60d)|6978|6978|235|3.3%|0.0%|
[blocklist_de](#blocklist_de)|28426|28426|197|0.6%|0.0%|
[openbl_30d](#openbl_30d)|2805|2805|119|4.2%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2423|2423|119|4.9%|0.0%|
[et_compromised](#et_compromised)|1721|1721|101|5.8%|0.0%|
[dragon_sshpauth](#dragon_sshpauth)|1633|1695|98|5.7%|0.0%|
[shunlist](#shunlist)|1151|1151|90|7.8%|0.0%|
[nixspam](#nixspam)|22818|22818|80|0.3%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6697|6697|79|1.1%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1695|1695|61|3.5%|0.0%|
[openbl_7d](#openbl_7d)|635|635|53|8.3%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|2960|2960|49|1.6%|0.0%|
[php_commenters](#php_commenters)|458|458|29|6.3%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|29|2.2%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|18299|18299|22|0.1%|0.0%|
[sorbs_spam](#sorbs_spam)|64701|65536|20|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|20|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|20|0.0%|0.0%|
[openbl_1d](#openbl_1d)|148|148|20|13.5%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9671|9671|18|0.1%|0.0%|
[zeus_badips](#zeus_badips)|202|202|15|7.4%|0.0%|
[zeus](#zeus)|230|230|15|6.5%|0.0%|
[voipbl](#voipbl)|10586|10998|14|0.1%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2839|2839|10|0.3%|0.0%|
[php_dictionary](#php_dictionary)|737|737|6|0.8%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|6|0.4%|0.0%|
[firehol_anonymous](#firehol_anonymous)|19168|83212|6|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|172|172|6|3.4%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|5|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2901|2901|5|0.1%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14346|14346|5|0.0%|0.0%|
[php_spammers](#php_spammers)|735|735|4|0.5%|0.0%|
[nt_malware_http](#nt_malware_http)|69|69|4|5.7%|0.0%|
[malc0de](#malc0de)|276|276|4|1.4%|0.0%|
[nt_malware_irc](#nt_malware_irc)|43|43|3|6.9%|0.0%|
[iw_spamlist](#iw_spamlist)|3878|3878|3|0.0%|0.0%|
[firehol_proxies](#firehol_proxies)|12674|12945|3|0.0%|0.0%|
[et_tor](#et_tor)|6400|6400|3|0.0%|0.0%|
[dm_tor](#dm_tor)|6521|6521|3|0.0%|0.0%|
[bm_tor](#bm_tor)|6525|6525|3|0.0%|0.0%|
[tor_exits](#tor_exits)|1112|1112|2|0.1%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|2|0.3%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|84|84|2|2.3%|0.0%|
[sslbl](#sslbl)|371|371|1|0.2%|0.0%|
[php_harvesters](#php_harvesters)|408|408|1|0.2%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|1|0.1%|0.0%|
[et_botcc](#et_botcc)|506|506|1|0.1%|0.0%|
[dragon_vncprobe](#dragon_vncprobe)|88|88|1|1.1%|0.0%|

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
[firehol_level1](#firehol_level1)|5138|688854748|487424|0.0%|100.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|270785|0.1%|55.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|98904|0.0%|20.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|33155|0.0%|6.8%|
[et_block](#et_block)|1000|18344011|517|0.0%|0.1%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|512|0.0%|0.1%|
[firehol_level3](#firehol_level3)|109658|9627424|85|0.0%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|75|0.0%|0.0%|
[sorbs_spam](#sorbs_spam)|64701|65536|20|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|20|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|20|0.0%|0.0%|
[alienvault_reputation](#alienvault_reputation)|187341|187341|14|0.0%|0.0%|
[firehol_level2](#firehol_level2)|22007|33621|9|0.0%|0.0%|
[php_commenters](#php_commenters)|458|458|8|1.7%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|7|0.0%|0.0%|
[blocklist_de](#blocklist_de)|28426|28426|7|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9671|9671|6|0.0%|0.0%|
[zeus_badips](#zeus_badips)|202|202|5|2.4%|0.0%|
[zeus](#zeus)|230|230|5|2.1%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|2960|2960|5|0.1%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6697|6697|3|0.0%|0.0%|
[nixspam](#nixspam)|22818|22818|3|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|172|172|3|1.7%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|18299|18299|2|0.0%|0.0%|
[php_harvesters](#php_harvesters)|408|408|1|0.2%|0.0%|
[openbl_60d](#openbl_60d)|6978|6978|1|0.0%|0.0%|
[openbl_30d](#openbl_30d)|2805|2805|1|0.0%|0.0%|
[malc0de](#malc0de)|276|276|1|0.3%|0.0%|
[iw_spamlist](#iw_spamlist)|3878|3878|1|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.0%|

## sslbl

[Abuse.ch SSL Blacklist](https://sslbl.abuse.ch/) bad SSL traffic related to malware or botnet activities - **excellent list**

Source is downloaded from [this link](https://sslbl.abuse.ch/blacklist/sslipblacklist.csv).

The last time downloaded was found to be dated: Thu Jun 11 22:15:04 UTC 2015.

The ipset `sslbl` has **371** entries, **371** unique IPs.

The following table shows the overlaps of `sslbl` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `sslbl`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `sslbl`.
- ` this % ` is the percentage **of this ipset (`sslbl`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level1](#firehol_level1)|5138|688854748|371|0.0%|100.0%|
[firehol_level3](#firehol_level3)|109658|9627424|89|0.0%|23.9%|
[alienvault_reputation](#alienvault_reputation)|187341|187341|65|0.0%|17.5%|
[shunlist](#shunlist)|1151|1151|58|5.0%|15.6%|
[feodo](#feodo)|105|105|38|36.1%|10.2%|
[et_block](#et_block)|1000|18344011|38|0.0%|10.2%|
[snort_ipfilter](#snort_ipfilter)|9671|9671|31|0.3%|8.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|28|0.0%|7.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|6|0.0%|1.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|3|0.0%|0.8%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|1|0.0%|0.2%|
[ri_web_proxies](#ri_web_proxies)|7852|7852|1|0.0%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.2%|
[firehol_proxies](#firehol_proxies)|12674|12945|1|0.0%|0.2%|
[firehol_anonymous](#firehol_anonymous)|19168|83212|1|0.0%|0.2%|
[dragon_sshpauth](#dragon_sshpauth)|1633|1695|1|0.0%|0.2%|
[dragon_http](#dragon_http)|1029|270336|1|0.0%|0.2%|

## stopforumspam_1d

[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers in the last 24 hours - **excellent list**

Source is downloaded from [this link](http://www.stopforumspam.com/downloads/listed_ip_1.zip).

The last time downloaded was found to be dated: Thu Jun 11 22:00:02 UTC 2015.

The ipset `stopforumspam_1d` has **6697** entries, **6697** unique IPs.

The following table shows the overlaps of `stopforumspam_1d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `stopforumspam_1d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `stopforumspam_1d`.
- ` this % ` is the percentage **of this ipset (`stopforumspam_1d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|22007|33621|6697|19.9%|100.0%|
[firehol_level3](#firehol_level3)|109658|9627424|5631|0.0%|84.0%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|5613|5.9%|83.8%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|3957|13.5%|59.0%|
[blocklist_de](#blocklist_de)|28426|28426|1520|5.3%|22.6%|
[blocklist_de_bots](#blocklist_de_bots)|2960|2960|1457|49.2%|21.7%|
[firehol_anonymous](#firehol_anonymous)|19168|83212|972|1.1%|14.5%|
[firehol_proxies](#firehol_proxies)|12674|12945|841|6.4%|12.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|523|0.0%|7.8%|
[ri_web_proxies](#ri_web_proxies)|7852|7852|432|5.5%|6.4%|
[snort_ipfilter](#snort_ipfilter)|9671|9671|350|3.6%|5.2%|
[proxyrss](#proxyrss)|1638|1638|321|19.5%|4.7%|
[tor_exits](#tor_exits)|1112|1112|316|28.4%|4.7%|
[et_tor](#et_tor)|6400|6400|307|4.7%|4.5%|
[dm_tor](#dm_tor)|6521|6521|305|4.6%|4.5%|
[bm_tor](#bm_tor)|6525|6525|305|4.6%|4.5%|
[xroxy](#xroxy)|2169|2169|214|9.8%|3.1%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|207|39.5%|3.0%|
[proxz](#proxz)|1323|1323|196|14.8%|2.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|182|0.0%|2.7%|
[php_commenters](#php_commenters)|458|458|172|37.5%|2.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|123|0.0%|1.8%|
[ri_connect_proxies](#ri_connect_proxies)|2828|2828|114|4.0%|1.7%|
[blocklist_de_strongips](#blocklist_de_strongips)|172|172|104|60.4%|1.5%|
[firehol_level1](#firehol_level1)|5138|688854748|81|0.0%|1.2%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|79|0.0%|1.1%|
[et_block](#et_block)|1000|18344011|79|0.0%|1.1%|
[blocklist_de_apache](#blocklist_de_apache)|14346|14346|61|0.4%|0.9%|
[nixspam](#nixspam)|22818|22818|57|0.2%|0.8%|
[sorbs_spam](#sorbs_spam)|64701|65536|52|0.0%|0.7%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|52|0.0%|0.7%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|52|0.0%|0.7%|
[blocklist_de_mail](#blocklist_de_mail)|18299|18299|47|0.2%|0.7%|
[alienvault_reputation](#alienvault_reputation)|187341|187341|46|0.0%|0.6%|
[php_harvesters](#php_harvesters)|408|408|44|10.7%|0.6%|
[php_spammers](#php_spammers)|735|735|41|5.5%|0.6%|
[php_dictionary](#php_dictionary)|737|737|36|4.8%|0.5%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|31|0.0%|0.4%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2901|2901|28|0.9%|0.4%|
[openbl_60d](#openbl_60d)|6978|6978|19|0.2%|0.2%|
[dragon_http](#dragon_http)|1029|270336|12|0.0%|0.1%|
[sorbs_web](#sorbs_web)|568|569|8|1.4%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|8|0.0%|0.1%|
[iw_spamlist](#iw_spamlist)|3878|3878|5|0.1%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|5|0.7%|0.0%|
[voipbl](#voipbl)|10586|10998|4|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|3|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|1526|1526|3|0.1%|0.0%|
[shunlist](#shunlist)|1151|1151|2|0.1%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|2|0.1%|0.0%|
[zeus_badips](#zeus_badips)|202|202|1|0.4%|0.0%|
[zeus](#zeus)|230|230|1|0.4%|0.0%|
[openbl_30d](#openbl_30d)|2805|2805|1|0.0%|0.0%|
[et_compromised](#et_compromised)|1721|1721|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1695|1695|1|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2839|2839|1|0.0%|0.0%|

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
[firehol_level3](#firehol_level3)|109658|9627424|94309|0.9%|100.0%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|29184|99.9%|30.9%|
[firehol_level2](#firehol_level2)|22007|33621|6935|20.6%|7.3%|
[firehol_anonymous](#firehol_anonymous)|19168|83212|6215|7.4%|6.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|5830|0.0%|6.1%|
[stopforumspam_1d](#stopforumspam_1d)|6697|6697|5613|83.8%|5.9%|
[firehol_proxies](#firehol_proxies)|12674|12945|5611|43.3%|5.9%|
[ri_web_proxies](#ri_web_proxies)|7852|7852|3696|47.0%|3.9%|
[blocklist_de](#blocklist_de)|28426|28426|2742|9.6%|2.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|2476|0.0%|2.6%|
[blocklist_de_bots](#blocklist_de_bots)|2960|2960|2387|80.6%|2.5%|
[ri_connect_proxies](#ri_connect_proxies)|2828|2828|1585|56.0%|1.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|1522|0.0%|1.6%|
[xroxy](#xroxy)|2169|2169|1285|59.2%|1.3%|
[firehol_level1](#firehol_level1)|5138|688854748|1090|0.0%|1.1%|
[et_block](#et_block)|1000|18344011|1018|0.0%|1.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|1014|0.0%|1.0%|
[snort_ipfilter](#snort_ipfilter)|9671|9671|812|8.3%|0.8%|
[proxz](#proxz)|1323|1323|776|58.6%|0.8%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|725|0.0%|0.7%|
[proxyrss](#proxyrss)|1638|1638|709|43.2%|0.7%|
[et_tor](#et_tor)|6400|6400|653|10.2%|0.6%|
[dm_tor](#dm_tor)|6521|6521|634|9.7%|0.6%|
[bm_tor](#bm_tor)|6525|6525|634|9.7%|0.6%|
[tor_exits](#tor_exits)|1112|1112|629|56.5%|0.6%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|345|65.8%|0.3%|
[php_commenters](#php_commenters)|458|458|334|72.9%|0.3%|
[sorbs_spam](#sorbs_spam)|64701|65536|320|0.4%|0.3%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|320|0.4%|0.3%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|320|0.4%|0.3%|
[blocklist_de_mail](#blocklist_de_mail)|18299|18299|259|1.4%|0.2%|
[nixspam](#nixspam)|22818|22818|228|0.9%|0.2%|
[blocklist_de_apache](#blocklist_de_apache)|14346|14346|207|1.4%|0.2%|
[alienvault_reputation](#alienvault_reputation)|187341|187341|167|0.0%|0.1%|
[php_spammers](#php_spammers)|735|735|151|20.5%|0.1%|
[php_dictionary](#php_dictionary)|737|737|139|18.8%|0.1%|
[blocklist_de_strongips](#blocklist_de_strongips)|172|172|133|77.3%|0.1%|
[dragon_http](#dragon_http)|1029|270336|111|0.0%|0.1%|
[php_harvesters](#php_harvesters)|408|408|87|21.3%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|75|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2901|2901|74|2.5%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|52|0.0%|0.0%|
[openbl_60d](#openbl_60d)|6978|6978|47|0.6%|0.0%|
[sorbs_web](#sorbs_web)|568|569|45|7.9%|0.0%|
[voipbl](#voipbl)|10586|10998|35|0.3%|0.0%|
[iw_spamlist](#iw_spamlist)|3878|3878|21|0.5%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|20|3.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|17|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2839|2839|17|0.5%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2423|2423|16|0.6%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|1526|1526|14|0.9%|0.0%|
[et_compromised](#et_compromised)|1721|1721|10|0.5%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1695|1695|10|0.5%|0.0%|
[openbl_30d](#openbl_30d)|2805|2805|5|0.1%|0.0%|
[shunlist](#shunlist)|1151|1151|4|0.3%|0.0%|
[dragon_sshpauth](#dragon_sshpauth)|1633|1695|4|0.2%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|3|0.2%|0.0%|
[zeus_badips](#zeus_badips)|202|202|2|0.9%|0.0%|
[zeus](#zeus)|230|230|2|0.8%|0.0%|
[openbl_7d](#openbl_7d)|635|635|2|0.3%|0.0%|
[nt_malware_http](#nt_malware_http)|69|69|2|2.8%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|2|0.1%|0.0%|
[fullbogons](#fullbogons)|3775|670173256|2|0.0%|0.0%|
[ciarmy](#ciarmy)|488|488|2|0.4%|0.0%|
[openbl_1d](#openbl_1d)|148|148|1|0.6%|0.0%|
[iw_wormlist](#iw_wormlist)|35|35|1|2.8%|0.0%|

## stopforumspam_7d

[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 7 days)

Source is downloaded from [this link](http://www.stopforumspam.com/downloads/listed_ip_7.zip).

The last time downloaded was found to be dated: Thu Jun 11 01:03:22 UTC 2015.

The ipset `stopforumspam_7d` has **29185** entries, **29185** unique IPs.

The following table shows the overlaps of `stopforumspam_7d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `stopforumspam_7d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `stopforumspam_7d`.
- ` this % ` is the percentage **of this ipset (`stopforumspam_7d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|29184|30.9%|99.9%|
[firehol_level3](#firehol_level3)|109658|9627424|29184|0.3%|99.9%|
[firehol_level2](#firehol_level2)|22007|33621|4915|14.6%|16.8%|
[stopforumspam_1d](#stopforumspam_1d)|6697|6697|3957|59.0%|13.5%|
[firehol_anonymous](#firehol_anonymous)|19168|83212|2758|3.3%|9.4%|
[firehol_proxies](#firehol_proxies)|12674|12945|2390|18.4%|8.1%|
[blocklist_de](#blocklist_de)|28426|28426|2194|7.7%|7.5%|
[blocklist_de_bots](#blocklist_de_bots)|2960|2960|2008|67.8%|6.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|1953|0.0%|6.6%|
[ri_web_proxies](#ri_web_proxies)|7852|7852|1531|19.4%|5.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|768|0.0%|2.6%|
[snort_ipfilter](#snort_ipfilter)|9671|9671|667|6.8%|2.2%|
[xroxy](#xroxy)|2169|2169|612|28.2%|2.0%|
[ri_connect_proxies](#ri_connect_proxies)|2828|2828|563|19.9%|1.9%|
[et_tor](#et_tor)|6400|6400|547|8.5%|1.8%|
[tor_exits](#tor_exits)|1112|1112|542|48.7%|1.8%|
[dm_tor](#dm_tor)|6521|6521|526|8.0%|1.8%|
[bm_tor](#bm_tor)|6525|6525|526|8.0%|1.8%|
[proxyrss](#proxyrss)|1638|1638|507|30.9%|1.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|506|0.0%|1.7%|
[proxz](#proxz)|1323|1323|503|38.0%|1.7%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|286|54.5%|0.9%|
[firehol_level1](#firehol_level1)|5138|688854748|278|0.0%|0.9%|
[et_block](#et_block)|1000|18344011|272|0.0%|0.9%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|271|0.0%|0.9%|
[php_commenters](#php_commenters)|458|458|249|54.3%|0.8%|
[sorbs_spam](#sorbs_spam)|64701|65536|169|0.2%|0.5%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|169|0.2%|0.5%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|169|0.2%|0.5%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|147|0.0%|0.5%|
[blocklist_de_mail](#blocklist_de_mail)|18299|18299|146|0.7%|0.5%|
[nixspam](#nixspam)|22818|22818|136|0.5%|0.4%|
[blocklist_de_apache](#blocklist_de_apache)|14346|14346|119|0.8%|0.4%|
[blocklist_de_strongips](#blocklist_de_strongips)|172|172|118|68.6%|0.4%|
[php_spammers](#php_spammers)|735|735|95|12.9%|0.3%|
[php_dictionary](#php_dictionary)|737|737|94|12.7%|0.3%|
[alienvault_reputation](#alienvault_reputation)|187341|187341|89|0.0%|0.3%|
[php_harvesters](#php_harvesters)|408|408|61|14.9%|0.2%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2901|2901|50|1.7%|0.1%|
[dragon_http](#dragon_http)|1029|270336|36|0.0%|0.1%|
[sorbs_web](#sorbs_web)|568|569|32|5.6%|0.1%|
[openbl_60d](#openbl_60d)|6978|6978|27|0.3%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|20|0.0%|0.0%|
[voipbl](#voipbl)|10586|10998|14|0.1%|0.0%|
[iw_spamlist](#iw_spamlist)|3878|3878|12|0.3%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|11|1.6%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|7|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|7|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2839|2839|6|0.2%|0.0%|
[et_compromised](#et_compromised)|1721|1721|5|0.2%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1695|1695|4|0.2%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2423|2423|4|0.1%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|2|0.1%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|1526|1526|2|0.1%|0.0%|
[zeus_badips](#zeus_badips)|202|202|1|0.4%|0.0%|
[zeus](#zeus)|230|230|1|0.4%|0.0%|
[shunlist](#shunlist)|1151|1151|1|0.0%|0.0%|
[openbl_30d](#openbl_30d)|2805|2805|1|0.0%|0.0%|
[iw_wormlist](#iw_wormlist)|35|35|1|2.8%|0.0%|
[fullbogons](#fullbogons)|3775|670173256|1|0.0%|0.0%|
[ciarmy](#ciarmy)|488|488|1|0.2%|0.0%|

## tor_exits

[TorProject.org](https://www.torproject.org) list of all current TOR exit points (TorDNSEL)

Source is downloaded from [this link](https://check.torproject.org/exit-addresses).

The last time downloaded was found to be dated: Thu Jun 11 22:02:32 UTC 2015.

The ipset `tor_exits` has **1112** entries, **1112** unique IPs.

The following table shows the overlaps of `tor_exits` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `tor_exits`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `tor_exits`.
- ` this % ` is the percentage **of this ipset (`tor_exits`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_anonymous](#firehol_anonymous)|19168|83212|1112|1.3%|100.0%|
[firehol_level3](#firehol_level3)|109658|9627424|1086|0.0%|97.6%|
[snort_ipfilter](#snort_ipfilter)|9671|9671|1085|11.2%|97.5%|
[bm_tor](#bm_tor)|6525|6525|1017|15.5%|91.4%|
[dm_tor](#dm_tor)|6521|6521|1016|15.5%|91.3%|
[et_tor](#et_tor)|6400|6400|959|14.9%|86.2%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|629|0.6%|56.5%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|542|1.8%|48.7%|
[firehol_level2](#firehol_level2)|22007|33621|331|0.9%|29.7%|
[stopforumspam_1d](#stopforumspam_1d)|6697|6697|316|4.7%|28.4%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|230|43.8%|20.6%|
[firehol_proxies](#firehol_proxies)|12674|12945|230|1.7%|20.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|128|0.0%|11.5%|
[php_commenters](#php_commenters)|458|458|54|11.7%|4.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|40|0.0%|3.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|37|0.0%|3.3%|
[alienvault_reputation](#alienvault_reputation)|187341|187341|30|0.0%|2.6%|
[blocklist_de_apache](#blocklist_de_apache)|14346|14346|22|0.1%|1.9%|
[blocklist_de](#blocklist_de)|28426|28426|22|0.0%|1.9%|
[openbl_60d](#openbl_60d)|6978|6978|20|0.2%|1.7%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2901|2901|20|0.6%|1.7%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|8|0.0%|0.7%|
[nixspam](#nixspam)|22818|22818|7|0.0%|0.6%|
[php_harvesters](#php_harvesters)|408|408|6|1.4%|0.5%|
[sorbs_spam](#sorbs_spam)|64701|65536|5|0.0%|0.4%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|5|0.0%|0.4%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|5|0.0%|0.4%|
[php_spammers](#php_spammers)|735|735|5|0.6%|0.4%|
[dragon_http](#dragon_http)|1029|270336|5|0.0%|0.4%|
[php_dictionary](#php_dictionary)|737|737|4|0.5%|0.3%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|2|0.0%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2|0.0%|0.1%|
[firehol_level1](#firehol_level1)|5138|688854748|2|0.0%|0.1%|
[et_block](#et_block)|1000|18344011|2|0.0%|0.1%|
[blocklist_de_mail](#blocklist_de_mail)|18299|18299|2|0.0%|0.1%|
[shunlist](#shunlist)|1151|1151|1|0.0%|0.0%|
[iw_spamlist](#iw_spamlist)|3878|3878|1|0.0%|0.0%|

## virbl

[VirBL](http://virbl.bit.nl/) is a project of which the idea was born during the RIPE-48 meeting. The plan was to get reports of virusscanning mailservers, and put the IP-addresses that were reported to send viruses on a blacklist.

Source is downloaded from [this link](http://virbl.bit.nl/download/virbl.dnsbl.bit.nl.txt).

The last time downloaded was found to be dated: Thu Jun 11 21:42:04 UTC 2015.

The ipset `virbl` has **19** entries, **19** unique IPs.

The following table shows the overlaps of `virbl` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `virbl`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `virbl`.
- ` this % ` is the percentage **of this ipset (`virbl`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level3](#firehol_level3)|109658|9627424|19|0.0%|100.0%|
[sorbs_spam](#sorbs_spam)|64701|65536|1|0.0%|5.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|1|0.0%|5.2%|

## voipbl

[VoIPBL.org](http://www.voipbl.org/) a distributed VoIP blacklist that is aimed to protects against VoIP Fraud and minimizing abuse for network that have publicly accessible PBX's. Several algorithms, external sources and manual confirmation are used before they categorize something as an attack and determine the threat level.

Source is downloaded from [this link](http://www.voipbl.org/update/).

The last time downloaded was found to be dated: Thu Jun 11 19:27:10 UTC 2015.

The ipset `voipbl` has **10586** entries, **10998** unique IPs.

The following table shows the overlaps of `voipbl` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `voipbl`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `voipbl`.
- ` this % ` is the percentage **of this ipset (`voipbl`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|1613|0.0%|14.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|436|0.0%|3.9%|
[firehol_level1](#firehol_level1)|5138|688854748|333|0.0%|3.0%|
[fullbogons](#fullbogons)|3775|670173256|319|0.0%|2.9%|
[bogons](#bogons)|13|592708608|319|0.0%|2.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|302|0.0%|2.7%|
[alienvault_reputation](#alienvault_reputation)|187341|187341|176|0.0%|1.6%|
[firehol_anonymous](#firehol_anonymous)|19168|83212|79|0.0%|0.7%|
[firehol_level3](#firehol_level3)|109658|9627424|57|0.0%|0.5%|
[firehol_level2](#firehol_level2)|22007|33621|46|0.1%|0.4%|
[blocklist_de](#blocklist_de)|28426|28426|42|0.1%|0.3%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|35|0.0%|0.3%|
[blocklist_de_sip](#blocklist_de_sip)|84|84|35|41.6%|0.3%|
[dragon_http](#dragon_http)|1029|270336|27|0.0%|0.2%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|14|0.0%|0.1%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|14|0.0%|0.1%|
[et_block](#et_block)|1000|18344011|14|0.0%|0.1%|
[shunlist](#shunlist)|1151|1151|13|1.1%|0.1%|
[openbl_60d](#openbl_60d)|6978|6978|8|0.1%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6697|6697|4|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|4|0.0%|0.0%|
[sorbs_spam](#sorbs_spam)|64701|65536|3|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|3|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|3|0.0%|0.0%|
[openbl_30d](#openbl_30d)|2805|2805|3|0.1%|0.0%|
[et_tor](#et_tor)|6400|6400|3|0.0%|0.0%|
[et_compromised](#et_compromised)|1721|1721|3|0.1%|0.0%|
[dm_tor](#dm_tor)|6521|6521|3|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1695|1695|3|0.1%|0.0%|
[bm_tor](#bm_tor)|6525|6525|3|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14346|14346|3|0.0%|0.0%|
[nixspam](#nixspam)|22818|22818|2|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|2|0.3%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|2|0.0%|0.0%|
[firehol_proxies](#firehol_proxies)|12674|12945|2|0.0%|0.0%|
[ciarmy](#ciarmy)|488|488|2|0.4%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2423|2423|2|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|18299|18299|2|0.0%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.0%|
[dragon_vncprobe](#dragon_vncprobe)|88|88|1|1.1%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2839|2839|1|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2901|2901|1|0.0%|0.0%|

## xroxy

[xroxy.com](http://www.xroxy.com) open proxies (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.xroxy.com/proxyrss.xml).

The last time downloaded was found to be dated: Thu Jun 11 22:33:01 UTC 2015.

The ipset `xroxy` has **2169** entries, **2169** unique IPs.

The following table shows the overlaps of `xroxy` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `xroxy`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `xroxy`.
- ` this % ` is the percentage **of this ipset (`xroxy`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_proxies](#firehol_proxies)|12674|12945|2169|16.7%|100.0%|
[firehol_anonymous](#firehol_anonymous)|19168|83212|2169|2.6%|100.0%|
[firehol_level3](#firehol_level3)|109658|9627424|1301|0.0%|59.9%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|1285|1.3%|59.2%|
[ri_web_proxies](#ri_web_proxies)|7852|7852|963|12.2%|44.3%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|612|2.0%|28.2%|
[proxz](#proxz)|1323|1323|459|34.6%|21.1%|
[ri_connect_proxies](#ri_connect_proxies)|2828|2828|396|14.0%|18.2%|
[proxyrss](#proxyrss)|1638|1638|345|21.0%|15.9%|
[firehol_level2](#firehol_level2)|22007|33621|315|0.9%|14.5%|
[blocklist_de](#blocklist_de)|28426|28426|226|0.7%|10.4%|
[stopforumspam_1d](#stopforumspam_1d)|6697|6697|214|3.1%|9.8%|
[blocklist_de_bots](#blocklist_de_bots)|2960|2960|170|5.7%|7.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|111|0.0%|5.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|104|0.0%|4.7%|
[sorbs_spam](#sorbs_spam)|64701|65536|76|0.1%|3.5%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|76|0.1%|3.5%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|76|0.1%|3.5%|
[nixspam](#nixspam)|22818|22818|65|0.2%|2.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|58|0.0%|2.6%|
[blocklist_de_mail](#blocklist_de_mail)|18299|18299|56|0.3%|2.5%|
[snort_ipfilter](#snort_ipfilter)|9671|9671|41|0.4%|1.8%|
[php_dictionary](#php_dictionary)|737|737|41|5.5%|1.8%|
[php_spammers](#php_spammers)|735|735|34|4.6%|1.5%|
[sorbs_web](#sorbs_web)|568|569|15|2.6%|0.6%|
[php_commenters](#php_commenters)|458|458|13|2.8%|0.5%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|13|1.9%|0.5%|
[blocklist_de_strongips](#blocklist_de_strongips)|172|172|7|4.0%|0.3%|
[dragon_http](#dragon_http)|1029|270336|6|0.0%|0.2%|
[alienvault_reputation](#alienvault_reputation)|187341|187341|5|0.0%|0.2%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|3|0.5%|0.1%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|3|0.0%|0.1%|
[php_harvesters](#php_harvesters)|408|408|2|0.4%|0.0%|
[iw_spamlist](#iw_spamlist)|3878|3878|2|0.0%|0.0%|
[dm_tor](#dm_tor)|6521|6521|2|0.0%|0.0%|
[bm_tor](#bm_tor)|6525|6525|2|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.0%|
[et_tor](#et_tor)|6400|6400|1|0.0%|0.0%|
[et_compromised](#et_compromised)|1721|1721|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1695|1695|1|0.0%|0.0%|

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
[firehol_level1](#firehol_level1)|5138|688854748|230|0.0%|100.0%|
[et_block](#et_block)|1000|18344011|228|0.0%|99.1%|
[firehol_level3](#firehol_level3)|109658|9627424|203|0.0%|88.2%|
[zeus_badips](#zeus_badips)|202|202|202|100.0%|87.8%|
[snort_ipfilter](#snort_ipfilter)|9671|9671|200|2.0%|86.9%|
[alienvault_reputation](#alienvault_reputation)|187341|187341|61|0.0%|26.5%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|15|0.0%|6.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|14|0.0%|6.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|10|0.0%|4.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|9|0.0%|3.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|7|0.0%|3.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|5|0.0%|2.1%|
[dragon_http](#dragon_http)|1029|270336|3|0.0%|1.3%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|2|0.0%|0.8%|
[openbl_60d](#openbl_60d)|6978|6978|2|0.0%|0.8%|
[openbl_30d](#openbl_30d)|2805|2805|2|0.0%|0.8%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|1|0.0%|0.4%|
[stopforumspam_1d](#stopforumspam_1d)|6697|6697|1|0.0%|0.4%|
[php_commenters](#php_commenters)|458|458|1|0.2%|0.4%|
[openbl_7d](#openbl_7d)|635|635|1|0.1%|0.4%|
[nixspam](#nixspam)|22818|22818|1|0.0%|0.4%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|1|0.0%|0.4%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.4%|
[firehol_level2](#firehol_level2)|22007|33621|1|0.0%|0.4%|

## zeus_badips

[Abuse.ch Zeus tracker](https://zeustracker.abuse.ch) badips includes IPv4 addresses that are used by the ZeuS trojan. It is the recommened blocklist if you want to block only ZeuS IPs. It excludes IP addresses that ZeuS Tracker believes to be hijacked (level 2) or belong to a free web hosting provider (level 3). Hence the false postive rate should be much lower compared to the standard ZeuS IP blocklist. **excellent list**

Source is downloaded from [this link](https://zeustracker.abuse.ch/blocklist.php?download=badips).

The last time downloaded was found to be dated: Thu Jun 11 22:09:15 UTC 2015.

The ipset `zeus_badips` has **202** entries, **202** unique IPs.

The following table shows the overlaps of `zeus_badips` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `zeus_badips`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `zeus_badips`.
- ` this % ` is the percentage **of this ipset (`zeus_badips`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[zeus](#zeus)|230|230|202|87.8%|100.0%|
[firehol_level1](#firehol_level1)|5138|688854748|202|0.0%|100.0%|
[et_block](#et_block)|1000|18344011|202|0.0%|100.0%|
[firehol_level3](#firehol_level3)|109658|9627424|180|0.0%|89.1%|
[snort_ipfilter](#snort_ipfilter)|9671|9671|178|1.8%|88.1%|
[alienvault_reputation](#alienvault_reputation)|187341|187341|37|0.0%|18.3%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|15|0.0%|7.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|10|0.0%|4.9%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|10|0.0%|4.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|8|0.0%|3.9%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|5|0.0%|2.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|4|0.0%|1.9%|
[dragon_http](#dragon_http)|1029|270336|3|0.0%|1.4%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|2|0.0%|0.9%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|1|0.0%|0.4%|
[stopforumspam_1d](#stopforumspam_1d)|6697|6697|1|0.0%|0.4%|
[php_commenters](#php_commenters)|458|458|1|0.2%|0.4%|
[openbl_7d](#openbl_7d)|635|635|1|0.1%|0.4%|
[openbl_60d](#openbl_60d)|6978|6978|1|0.0%|0.4%|
[openbl_30d](#openbl_30d)|2805|2805|1|0.0%|0.4%|
[nixspam](#nixspam)|22818|22818|1|0.0%|0.4%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.4%|
[firehol_level2](#firehol_level2)|22007|33621|1|0.0%|0.4%|
