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

The following list was automatically generated on Thu Jun 11 15:10:11 UTC 2015.

The update frequency is the maximum allowed by internal configuration. A list will never be downloaded sooner than the update frequency stated. A list may also not be downloaded, after this frequency expired, if it has not been modified on the server (as reported by HTTP `IF_MODIFIED_SINCE` method).

name|info|type|entries|update|
:--:|:--:|:--:|:-----:|:----:|
[alienvault_reputation](#alienvault_reputation)|[AlienVault.com](https://www.alienvault.com/) IP reputation database (this list seems to include port scanning hosts and to be updated regularly, but we found no information about its retention policy)|ipv4 hash:ip|188722 unique IPs|updated every 6 hours  from [this link](https://reputation.alienvault.com/reputation.generic)
[blocklist_de](#blocklist_de)|[Blocklist.de](https://www.blocklist.de/) IPs that have been detected by fail2ban in the last 48 hours - **excellent list**|ipv4 hash:ip|27522 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/all.txt)
[blocklist_de_apache](#blocklist_de_apache)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service Apache, Apache-DDOS, RFI-Attacks.|ipv4 hash:ip|14218 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/apache.txt)
[blocklist_de_bots](#blocklist_de_bots)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the RFI-Attacks, REG-Bots, IRC-Bots or BadBots (BadBots = he has posted a Spam-Comment on a open Forum or Wiki).|ipv4 hash:ip|2942 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/bots.txt)
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|[Blocklist.de](https://www.blocklist.de/) All IPs which attacks Joomlas, Wordpress and other Web-Logins with Brute-Force Logins.|ipv4 hash:ip|2852 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/bruteforcelogin.txt)
[blocklist_de_ftp](#blocklist_de_ftp)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours for attacks on the Service FTP.|ipv4 hash:ip|1418 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/ftp.txt)
[blocklist_de_imap](#blocklist_de_imap)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours for attacks on the Service imap, sasl, pop3, etc.|ipv4 hash:ip|2296 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/imap.txt)
[blocklist_de_mail](#blocklist_de_mail)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service Mail, Postfix.|ipv4 hash:ip|16621 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/mail.txt)
[blocklist_de_sip](#blocklist_de_sip)|[Blocklist.de](https://www.blocklist.de/) All IP addresses that tried to login in a SIP, VOIP or Asterisk Server and are included in the IPs list from [infiltrated.net](www.infiltrated.net)|ipv4 hash:ip|84 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/sip.txt)
[blocklist_de_ssh](#blocklist_de_ssh)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service SSH.|ipv4 hash:ip|3334 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/ssh.txt)
[blocklist_de_strongips](#blocklist_de_strongips)|[Blocklist.de](https://www.blocklist.de/) All IPs which are older then 2 month and have more then 5.000 attacks.|ipv4 hash:ip|177 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/strongips.txt)
[bm_tor](#bm_tor)|[torstatus.blutmagie.de](https://torstatus.blutmagie.de) list of all TOR network servers|ipv4 hash:ip|6492 unique IPs|updated every 30 mins  from [this link](https://torstatus.blutmagie.de/ip_list_all.php/Tor_ip_list_ALL.csv)
[bogons](#bogons)|[Team-Cymru.org](http://www.team-cymru.org) private and reserved addresses defined by RFC 1918, RFC 5735, and RFC 6598 and netblocks that have not been allocated to a regional internet registry - **excellent list - use it only your internet interface**|ipv4 hash:net|13 subnets, 592708608 unique IPs|updated every 1 day  from [this link](http://www.team-cymru.org/Services/Bogons/bogon-bn-agg.txt)
[bruteforceblocker](#bruteforceblocker)|[danger.rulez.sk](http://danger.rulez.sk/) IPs detected by [bruteforceblocker](http://danger.rulez.sk/index.php/bruteforceblocker/) (fail2ban alternative for SSH on OpenBSD). This is an automatically generated list from users reporting failed authentication attempts. An IP seems to be included if 3 or more users report it. Its retention pocily seems 30 days.|ipv4 hash:ip|1701 unique IPs|updated every 3 hours  from [this link](http://danger.rulez.sk/projects/bruteforceblocker/blist.php)
[ciarmy](#ciarmy)|[CIArmy.com](http://ciarmy.com/) IPs with poor Rogue Packet score that have not yet been identified as malicious by the community|ipv4 hash:ip|457 unique IPs|updated every 3 hours  from [this link](http://cinsscore.com/list/ci-badguys.txt)
[cleanmx_viruses](#cleanmx_viruses)|[Clean-MX.de](http://support.clean-mx.de/clean-mx/viruses.php) IPs with viruses|ipv4 hash:ip|115 unique IPs|updated every 12 hours  from [this link](http://support.clean-mx.de/clean-mx/xmlviruses.php?sort=id%20desc&response=alive)
[dm_tor](#dm_tor)|[dan.me.uk](https://www.dan.me.uk) dynamic list of TOR nodes|ipv4 hash:ip|6490 unique IPs|updated every 30 mins  from [this link](https://www.dan.me.uk/torlist/)
[dragon_http](#dragon_http)|[Dragon Search Group](http://www.dragonresearchgroup.org/) IPs that have been seen sending HTTP requests to Dragon Research Pods in the last 7 days. This report lists hosts that are highly suspicious and are likely conducting malicious HTTP attacks. LEGITIMATE SEARCH ENGINE BOTS MAY BE IN THIS LIST. This report is informational.  It is not a blacklist, but some operators may choose to use it to help protect their networks and hosts in the forms of automated reporting and mitigation services.|ipv4 hash:net|1029 subnets, 270336 unique IPs|updated every 1 day  from [this link](http://www.dragonresearchgroup.org/insight/http-report.txt)
[dshield](#dshield)|[DShield.org](https://dshield.org/) top 20 attacking class C (/24) subnets over the last three days - **excellent list**|ipv4 hash:net|20 subnets, 5120 unique IPs|updated every 4 hours  from [this link](http://feeds.dshield.org/block.txt)
[et_block](#et_block)|[EmergingThreats.net](http://www.emergingthreats.net/) default blacklist (at the time of writing includes spamhaus DROP, dshield and abuse.ch trackers, which are available separately too - prefer to use the direct ipsets instead of this, they seem to lag a bit in updates)|ipv4 hash:net|1000 subnets, 18344011 unique IPs|updated every 12 hours  from [this link](http://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt)
[et_botcc](#et_botcc)|[EmergingThreats.net Command and Control IPs](http://doc.emergingthreats.net/bin/view/Main/BotCC) These IPs are updates every 24 hours and should be considered VERY highly reliable indications that a host is communicating with a known and active Bot or Malware command and control server - (although they say this includes abuse.ch trackers, it does not - most probably it is the shadowserver.org C&C list)|ipv4 hash:ip|506 unique IPs|updated every 12 hours  from [this link](http://rules.emergingthreats.net/fwrules/emerging-PIX-CC.rules)
[et_compromised](#et_compromised)|[EmergingThreats.net compromised hosts](http://doc.emergingthreats.net/bin/view/Main/CompromisedHost) - (this seems to be based on bruteforceblocker)|ipv4 hash:ip|1721 unique IPs|updated every 12 hours  from [this link](http://rules.emergingthreats.net/blockrules/compromised-ips.txt)
et_dshield|[EmergingThreats.net](http://www.emergingthreats.net/) dshield blocklist|ipv4 hash:net|disabled|updated every 12 hours  from [this link](http://rules.emergingthreats.net/fwrules/emerging-PIX-DSHIELD.rules)
et_spamhaus|[EmergingThreats.net](http://www.emergingthreats.net/) spamhaus blocklist|ipv4 hash:net|disabled|updated every 12 hours  from [this link](http://rules.emergingthreats.net/fwrules/emerging-PIX-DROP.rules)
[et_tor](#et_tor)|[EmergingThreats.net](http://www.emergingthreats.net/) [list](http://doc.emergingthreats.net/bin/view/Main/TorRules) of TOR network IPs|ipv4 hash:ip|6400 unique IPs|updated every 12 hours  from [this link](http://rules.emergingthreats.net/blockrules/emerging-tor.rules)
[feodo](#feodo)|[Abuse.ch Feodo tracker](https://feodotracker.abuse.ch) trojan includes IPs which are being used by Feodo (also known as Cridex or Bugat) which commits ebanking fraud - **excellent list**|ipv4 hash:ip|105 unique IPs|updated every 30 mins  from [this link](https://feodotracker.abuse.ch/blocklist/?download=ipblocklist)
[firehol_anonymous](#firehol_anonymous)|**FireHOL Anonymous** - Known anonymizing IPs. (includes: firehol_proxies anonymous bm_tor dm_tor tor_exits)|ipv4 hash:net|18927 subnets, 82965 unique IPs|
[firehol_level1](#firehol_level1)|**FireHOL Level 1** - Maximum protection without false positives. (includes: fullbogons dshield feodo palevo sslbl zeus spamhaus_drop spamhaus_edrop)|ipv4 hash:net|5136 subnets, 688854491 unique IPs|
[firehol_level2](#firehol_level2)|**FireHOL Level 2** - Maximum protection from attacks took place in the last 48 hours. (includes: openbl_1d blocklist_de stopforumspam_1d)|ipv4 hash:net|21182 subnets, 32799 unique IPs|
[firehol_level3](#firehol_level3)|**FireHOL Level 3** - All the bad IPs in last 30 days. (includes: openbl_30d stopforumspam_30d virbl malc0de shunlist malwaredomainlist bruteforceblocker ciarmy cleanmx_viruses snort_ipfilter ib_bluetack_spyware ib_bluetack_hijacked ib_bluetack_webexploit php_commenters php_dictionary php_harvesters php_spammers iw_wormlist)|ipv4 hash:net|109880 subnets, 9627672 unique IPs|
[firehol_proxies](#firehol_proxies)|**FireHOL Proxies** - Known open proxies in the last 30 days. (includes: ib_bluetack_proxies maxmind_proxy_fraud proxyrss proxz ri_connect_proxies ri_web_proxies xroxy)|ipv4 hash:net|12374 subnets, 12641 unique IPs|
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
[iw_spamlist](#iw_spamlist)|[ImproWare Antispam](http://antispam.imp.ch/) IPs sending spam, in the last 3 days|ipv4 hash:ip|3772 unique IPs|updated every 1 hour  from [this link](http://antispam.imp.ch/spamlist)
[iw_wormlist](#iw_wormlist)|[ImproWare Antispam](http://antispam.imp.ch/) IPs sending emails with viruses or worms, in the last 3 days|ipv4 hash:ip|33 unique IPs|updated every 1 hour  from [this link](http://antispam.imp.ch/wormlist)
lashback_ubl|[The LashBack UBL](http://blacklist.lashback.com/) The Unsubscribe Blacklist (UBL) is a real-time blacklist of IP addresses which are sending email to names harvested from suppression files (this is a big list, more than 500.000 IPs)|ipv4 hash:ip|disabled|updated every 1 day  from [this link](http://www.unsubscore.com/blacklist.txt)
[malc0de](#malc0de)|[Malc0de.com](http://malc0de.com) malicious IPs of the last 30 days|ipv4 hash:ip|276 unique IPs|updated every 1 day  from [this link](http://malc0de.com/bl/IP_Blacklist.txt)
[malwaredomainlist](#malwaredomainlist)|[malwaredomainlist.com](http://www.malwaredomainlist.com) list of malware active ip addresses|ipv4 hash:ip|1288 unique IPs|updated every 12 hours  from [this link](http://www.malwaredomainlist.com/hostslist/ip.txt)
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|[MaxMind.com](https://www.maxmind.com/en/anonymous-proxy-fraudulent-ip-address-list) list of anonymous proxy fraudelent IP addresses.|ipv4 hash:ip|524 unique IPs|updated every 4 hours  from [this link](https://www.maxmind.com/en/anonymous-proxy-fraudulent-ip-address-list)
[nixspam](#nixspam)|[NiX Spam](http://www.heise.de/ix/NiX-Spam-DNSBL-and-blacklist-for-download-499637.html) IP addresses that sent spam in the last hour - automatically generated entries without distinguishing open proxies from relays, dialup gateways, and so on. All IPs are removed after 12 hours if there is no spam from there.|ipv4 hash:ip|24663 unique IPs|updated every 15 mins  from [this link](http://www.dnsbl.manitu.net/download/nixspam-ip.dump.gz)
[nt_malware_http](#nt_malware_http)|[No Think](http://www.nothink.org/) Malware HTTP|ipv4 hash:ip|69 unique IPs|updated every 1 hour  from [this link](http://www.nothink.org/blacklist/blacklist_malware_http.txt)
[nt_malware_irc](#nt_malware_irc)|[No Think](http://www.nothink.org/) Malware IRC|ipv4 hash:ip|43 unique IPs|updated every 1 hour  from [this link](http://www.nothink.org/blacklist/blacklist_malware_irc.txt)
[nt_ssh_7d](#nt_ssh_7d)|[No Think](http://www.nothink.org/) Last 7 days SSH attacks|ipv4 hash:ip|0 unique IPs|updated every 1 hour  from [this link](http://www.nothink.org/blacklist/blacklist_ssh_week.txt)
openbl|[OpenBL.org](http://www.openbl.org/) default blacklist (currently it is the same with 90 days). OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications - **excellent list**|ipv4 hash:ip|disabled|updated every 4 hours  from [this link](http://www.openbl.org/lists/base.txt)
openbl_180d|[OpenBL.org](http://www.openbl.org/) last 180 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|disabled|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_180days.txt)
[openbl_1d](#openbl_1d)|[OpenBL.org](http://www.openbl.org/) last 24 hours IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|140 unique IPs|updated every 1 hour  from [this link](http://www.openbl.org/lists/base_1days.txt)
[openbl_30d](#openbl_30d)|[OpenBL.org](http://www.openbl.org/) last 30 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|2813 unique IPs|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_30days.txt)
openbl_360d|[OpenBL.org](http://www.openbl.org/) last 360 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|disabled|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_360days.txt)
[openbl_60d](#openbl_60d)|[OpenBL.org](http://www.openbl.org/) last 60 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|6989 unique IPs|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_60days.txt)
[openbl_7d](#openbl_7d)|[OpenBL.org](http://www.openbl.org/) last 7 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|641 unique IPs|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_7days.txt)
openbl_90d|[OpenBL.org](http://www.openbl.org/) last 90 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|disabled|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_90days.txt)
openbl_all|[OpenBL.org](http://www.openbl.org/) last all IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|disabled|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_all.txt)
[palevo](#palevo)|[Abuse.ch Palevo tracker](https://palevotracker.abuse.ch) worm includes IPs which are being used as botnet C&C for the Palevo crimeware - **excellent list**|ipv4 hash:ip|12 unique IPs|updated every 30 mins  from [this link](https://palevotracker.abuse.ch/blocklists.php?download=ipblocklist)
php_bad|[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) bad web hosts (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|disabled|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=b&rss=1)
[php_commenters](#php_commenters)|[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) comment spammers (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|430 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=c&rss=1)
[php_dictionary](#php_dictionary)|[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) directory attackers (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|737 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=d&rss=1)
[php_harvesters](#php_harvesters)|[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) harvesters (IPs that surf the internet looking for email addresses) (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|392 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=h&rss=1)
[php_spammers](#php_spammers)|[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) spam servers (IPs used by spammers to send messages) (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|735 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=s&rss=1)
[proxyrss](#proxyrss)|[proxyrss.com](http://www.proxyrss.com) open proxies syndicated from multiple sources.|ipv4 hash:ip|1373 unique IPs|updated every 4 hours  from [this link](http://www.proxyrss.com/proxylists/all.gz)
[proxz](#proxz)|[proxz.com](http://www.proxz.com) open proxies (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|1297 unique IPs|updated every 1 hour  from [this link](http://www.proxz.com/proxylists.xml)
[ri_connect_proxies](#ri_connect_proxies)|[rosinstrument.com](http://www.rosinstrument.com) open CONNECT proxies (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|2811 unique IPs|updated every 1 hour  from [this link](http://tools.rosinstrument.com/proxy/plab100.xml)
[ri_web_proxies](#ri_web_proxies)|[rosinstrument.com](http://www.rosinstrument.com) open HTTP proxies (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|7800 unique IPs|updated every 1 hour  from [this link](http://tools.rosinstrument.com/proxy/l100.xml)
[shunlist](#shunlist)|[AutoShun.org](http://autoshun.org/) IPs identified as hostile by correlating logs from distributed snort installations running the autoshun plugin|ipv4 hash:ip|1263 unique IPs|updated every 4 hours  from [this link](http://www.autoshun.org/files/shunlist.csv)
[snort_ipfilter](#snort_ipfilter)|[labs.snort.org](https://labs.snort.org/) supplied IP blacklist (this list seems to be updated frequently, but we found no information about it)|ipv4 hash:ip|9945 unique IPs|updated every 12 hours  from [this link](http://labs.snort.org/feeds/ip-filter.blf)
[sorbs_dul](#sorbs_dul)|[Sorbs.net](https://www.sorbs.net/) DUL, Dynamic User IPs extracted from deltas.|ipv4 hash:net|10 subnets, 4864 unique IPs|
[sorbs_http](#sorbs_http)|[Sorbs.net](https://www.sorbs.net/) HTTP proxies, extracted from deltas.|ipv4 hash:net|7 subnets, 7 unique IPs|
[sorbs_misc](#sorbs_misc)|[Sorbs.net](https://www.sorbs.net/) MISC proxies, extracted from deltas.|ipv4 hash:net|7 subnets, 7 unique IPs|
[sorbs_new_spam](#sorbs_new_spam)|[Sorbs.net](https://www.sorbs.net/) NEW Spam senders, extracted from deltas.|ipv4 hash:net|64467 subnets, 65300 unique IPs|
[sorbs_recent_spam](#sorbs_recent_spam)|[Sorbs.net](https://www.sorbs.net/) RECENT Spam senders, extracted from deltas.|ipv4 hash:net|64467 subnets, 65300 unique IPs|
[sorbs_smtp](#sorbs_smtp)|[Sorbs.net](https://www.sorbs.net/) SMTP Open Relays, extracted from deltas.|ipv4 hash:net|5 subnets, 5 unique IPs|
[sorbs_socks](#sorbs_socks)|[Sorbs.net](https://www.sorbs.net/) SOCKS proxies, extracted from deltas.|ipv4 hash:net|7 subnets, 7 unique IPs|
[sorbs_spam](#sorbs_spam)|[Sorbs.net](https://www.sorbs.net/) Spam senders, extracted from deltas.|ipv4 hash:net|64701 subnets, 65536 unique IPs|
[sorbs_web](#sorbs_web)|[Sorbs.net](https://www.sorbs.net/) WEB exploits, extracted from deltas.|ipv4 hash:net|531 subnets, 532 unique IPs|
[spamhaus_drop](#spamhaus_drop)|[Spamhaus.org](http://www.spamhaus.org) DROP list (according to their site this list should be dropped at tier-1 ISPs globaly) - **excellent list**|ipv4 hash:net|653 subnets, 18340608 unique IPs|updated every 12 hours  from [this link](http://www.spamhaus.org/drop/drop.txt)
[spamhaus_edrop](#spamhaus_edrop)|[Spamhaus.org](http://www.spamhaus.org) EDROP (extended matches that should be used with DROP) - **excellent list**|ipv4 hash:net|56 subnets, 487424 unique IPs|updated every 12 hours  from [this link](http://www.spamhaus.org/drop/edrop.txt)
[sslbl](#sslbl)|[Abuse.ch SSL Blacklist](https://sslbl.abuse.ch/) bad SSL traffic related to malware or botnet activities - **excellent list**|ipv4 hash:ip|371 unique IPs|updated every 30 mins  from [this link](https://sslbl.abuse.ch/blacklist/sslipblacklist.csv)
stopforumspam_180d|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 180 days)|ipv4 hash:ip|disabled|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/listed_ip_180.zip)
[stopforumspam_1d](#stopforumspam_1d)|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers in the last 24 hours - **excellent list**|ipv4 hash:ip|6710 unique IPs|updated every 1 hour  from [this link](http://www.stopforumspam.com/downloads/listed_ip_1.zip)
[stopforumspam_30d](#stopforumspam_30d)|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 30 days)|ipv4 hash:ip|94309 unique IPs|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/listed_ip_30.zip)
stopforumspam_365d|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 365 days)|ipv4 hash:ip|disabled|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/listed_ip_365.zip)
[stopforumspam_7d](#stopforumspam_7d)|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 7 days)|ipv4 hash:ip|29185 unique IPs|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/listed_ip_7.zip)
stopforumspam_90d|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 90 days)|ipv4 hash:ip|disabled|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/listed_ip_90.zip)
stopforumspam_ever|[StopForumSpam.com](http://www.stopforumspam.com) all IPs used by forum spammers, **ever** (normally you don't want to use this ipset, use the hourly one which includes last 24 hours IPs or the 7 days one)|ipv4 hash:ip|disabled|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/bannedips.zip)
[tor_exits](#tor_exits)|[TorProject.org](https://www.torproject.org) list of all current TOR exit points (TorDNSEL)|ipv4 hash:ip|1121 unique IPs|updated every 30 mins  from [this link](https://check.torproject.org/exit-addresses)
[virbl](#virbl)|[VirBL](http://virbl.bit.nl/) is a project of which the idea was born during the RIPE-48 meeting. The plan was to get reports of virusscanning mailservers, and put the IP-addresses that were reported to send viruses on a blacklist.|ipv4 hash:ip|28 unique IPs|updated every 1 hour  from [this link](http://virbl.bit.nl/download/virbl.dnsbl.bit.nl.txt)
[voipbl](#voipbl)|[VoIPBL.org](http://www.voipbl.org/) a distributed VoIP blacklist that is aimed to protects against VoIP Fraud and minimizing abuse for network that have publicly accessible PBX's. Several algorithms, external sources and manual confirmation are used before they categorize something as an attack and determine the threat level.|ipv4 hash:net|10533 subnets, 10945 unique IPs|updated every 4 hours  from [this link](http://www.voipbl.org/update/)
[xroxy](#xroxy)|[xroxy.com](http://www.xroxy.com) open proxies (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|2165 unique IPs|updated every 1 hour  from [this link](http://www.xroxy.com/proxyrss.xml)
[zeus](#zeus)|[Abuse.ch Zeus tracker](https://zeustracker.abuse.ch) standard, contains the same data as the ZeuS IP blocklist (zeus_badips) but with the slight difference that it doesn't exclude hijacked websites (level 2) and free web hosting providers (level 3). This means that this blocklist contains all IPv4 addresses associated with ZeuS C&Cs which are currently being tracked by ZeuS Tracker. Hence this blocklist will likely cause some false positives. - **excellent list**|ipv4 hash:ip|230 unique IPs|updated every 30 mins  from [this link](https://zeustracker.abuse.ch/blocklist.php?download=ipblocklist)
[zeus_badips](#zeus_badips)|[Abuse.ch Zeus tracker](https://zeustracker.abuse.ch) badips includes IPv4 addresses that are used by the ZeuS trojan. It is the recommened blocklist if you want to block only ZeuS IPs. It excludes IP addresses that ZeuS Tracker believes to be hijacked (level 2) or belong to a free web hosting provider (level 3). Hence the false postive rate should be much lower compared to the standard ZeuS IP blocklist. **excellent list**|ipv4 hash:ip|202 unique IPs|updated every 30 mins  from [this link](https://zeustracker.abuse.ch/blocklist.php?download=badips)

# Comparison of ipsets

Below we compare each ipset against all other.


## alienvault_reputation

[AlienVault.com](https://www.alienvault.com/) IP reputation database (this list seems to include port scanning hosts and to be updated regularly, but we found no information about its retention policy)

Source is downloaded from [this link](https://reputation.alienvault.com/reputation.generic).

The last time downloaded was found to be dated: Thu Jun 11 10:00:41 UTC 2015.

The ipset `alienvault_reputation` has **188722** entries, **188722** unique IPs.

The following table shows the overlaps of `alienvault_reputation` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `alienvault_reputation`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `alienvault_reputation`.
- ` this % ` is the percentage **of this ipset (`alienvault_reputation`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|14338|0.0%|7.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|7000|0.0%|3.7%|
[openbl_60d](#openbl_60d)|6989|6989|6967|99.6%|3.6%|
[dragon_http](#dragon_http)|1029|270336|6149|2.2%|3.2%|
[firehol_level3](#firehol_level3)|109880|9627672|4882|0.0%|2.5%|
[et_block](#et_block)|1000|18344011|4764|0.0%|2.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|4448|0.0%|2.3%|
[firehol_level1](#firehol_level1)|5136|688854491|3321|0.0%|1.7%|
[openbl_30d](#openbl_30d)|2813|2813|2796|99.3%|1.4%|
[dshield](#dshield)|20|5120|2321|45.3%|1.2%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|1372|0.0%|0.7%|
[firehol_level2](#firehol_level2)|21182|32799|1308|3.9%|0.6%|
[blocklist_de](#blocklist_de)|27522|27522|1263|4.5%|0.6%|
[shunlist](#shunlist)|1263|1263|1252|99.1%|0.6%|
[et_compromised](#et_compromised)|1721|1721|1116|64.8%|0.5%|
[bruteforceblocker](#bruteforceblocker)|1701|1701|1076|63.2%|0.5%|
[blocklist_de_ssh](#blocklist_de_ssh)|3334|3334|1057|31.7%|0.5%|
[openbl_7d](#openbl_7d)|641|641|637|99.3%|0.3%|
[ciarmy](#ciarmy)|457|457|445|97.3%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|291|0.0%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|265|0.0%|0.1%|
[voipbl](#voipbl)|10533|10945|183|1.6%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|168|0.1%|0.0%|
[openbl_1d](#openbl_1d)|140|140|136|97.1%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14218|14218|124|0.8%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9945|9945|108|1.0%|0.0%|
[sorbs_spam](#sorbs_spam)|64701|65536|91|0.1%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|91|0.1%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|91|0.1%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|89|0.3%|0.0%|
[sslbl](#sslbl)|371|371|65|17.5%|0.0%|
[zeus](#zeus)|230|230|61|26.5%|0.0%|
[firehol_anonymous](#firehol_anonymous)|18927|82965|57|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6710|6710|49|0.7%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|16621|16621|47|0.2%|0.0%|
[nixspam](#nixspam)|24663|24663|45|0.1%|0.0%|
[dm_tor](#dm_tor)|6490|6490|42|0.6%|0.0%|
[bm_tor](#bm_tor)|6492|6492|42|0.6%|0.0%|
[et_tor](#et_tor)|6400|6400|39|0.6%|0.0%|
[firehol_proxies](#firehol_proxies)|12374|12641|38|0.3%|0.0%|
[zeus_badips](#zeus_badips)|202|202|37|18.3%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|177|177|36|20.3%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2296|2296|31|1.3%|0.0%|
[tor_exits](#tor_exits)|1121|1121|30|2.6%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|29|5.5%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|84|84|19|22.6%|0.0%|
[php_commenters](#php_commenters)|430|430|18|4.1%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2852|2852|18|0.6%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|2942|2942|17|0.5%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|15|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|14|0.0%|0.0%|
[iw_spamlist](#iw_spamlist)|3772|3772|14|0.3%|0.0%|
[php_harvesters](#php_harvesters)|392|392|12|3.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|1418|1418|10|0.7%|0.0%|
[malc0de](#malc0de)|276|276|9|3.2%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|8|0.6%|0.0%|
[php_dictionary](#php_dictionary)|737|737|7|0.9%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|115|115|7|6.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|6|0.4%|0.0%|
[xroxy](#xroxy)|2165|2165|5|0.2%|0.0%|
[php_spammers](#php_spammers)|735|735|5|0.6%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7800|7800|4|0.0%|0.0%|
[et_botcc](#et_botcc)|506|506|4|0.7%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2811|2811|3|0.1%|0.0%|
[proxz](#proxz)|1297|1297|3|0.2%|0.0%|
[nt_malware_irc](#nt_malware_irc)|43|43|2|4.6%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|2|0.3%|0.0%|
[feodo](#feodo)|105|105|2|1.9%|0.0%|
[sorbs_web](#sorbs_web)|531|532|1|0.1%|0.0%|
[nt_malware_http](#nt_malware_http)|69|69|1|1.4%|0.0%|

## blocklist_de

[Blocklist.de](https://www.blocklist.de/) IPs that have been detected by fail2ban in the last 48 hours - **excellent list**

Source is downloaded from [this link](http://lists.blocklist.de/lists/all.txt).

The last time downloaded was found to be dated: Thu Jun 11 14:42:04 UTC 2015.

The ipset `blocklist_de` has **27522** entries, **27522** unique IPs.

The following table shows the overlaps of `blocklist_de` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de`.
- ` this % ` is the percentage **of this ipset (`blocklist_de`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|21182|32799|27522|83.9%|100.0%|
[blocklist_de_mail](#blocklist_de_mail)|16621|16621|16621|100.0%|60.3%|
[blocklist_de_apache](#blocklist_de_apache)|14218|14218|14215|99.9%|51.6%|
[firehol_level3](#firehol_level3)|109880|9627672|3965|0.0%|14.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|3519|0.0%|12.7%|
[blocklist_de_ssh](#blocklist_de_ssh)|3334|3334|3334|100.0%|12.1%|
[blocklist_de_bots](#blocklist_de_bots)|2942|2942|2942|100.0%|10.6%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2852|2852|2852|100.0%|10.3%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|2803|2.9%|10.1%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|2296|7.8%|8.3%|
[blocklist_de_imap](#blocklist_de_imap)|2296|2296|2288|99.6%|8.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|1589|0.0%|5.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|1541|0.0%|5.5%|
[stopforumspam_1d](#stopforumspam_1d)|6710|6710|1445|21.5%|5.2%|
[blocklist_de_ftp](#blocklist_de_ftp)|1418|1418|1418|100.0%|5.1%|
[sorbs_spam](#sorbs_spam)|64701|65536|1342|2.0%|4.8%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|1336|2.0%|4.8%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|1336|2.0%|4.8%|
[alienvault_reputation](#alienvault_reputation)|188722|188722|1263|0.6%|4.5%|
[openbl_60d](#openbl_60d)|6989|6989|886|12.6%|3.2%|
[nixspam](#nixspam)|24663|24663|727|2.9%|2.6%|
[openbl_30d](#openbl_30d)|2813|2813|708|25.1%|2.5%|
[firehol_anonymous](#firehol_anonymous)|18927|82965|664|0.8%|2.4%|
[firehol_proxies](#firehol_proxies)|12374|12641|636|5.0%|2.3%|
[bruteforceblocker](#bruteforceblocker)|1701|1701|593|34.8%|2.1%|
[et_compromised](#et_compromised)|1721|1721|584|33.9%|2.1%|
[ri_web_proxies](#ri_web_proxies)|7800|7800|467|5.9%|1.6%|
[shunlist](#shunlist)|1263|1263|401|31.7%|1.4%|
[openbl_7d](#openbl_7d)|641|641|390|60.8%|1.4%|
[xroxy](#xroxy)|2165|2165|225|10.3%|0.8%|
[et_block](#et_block)|1000|18344011|223|0.0%|0.8%|
[snort_ipfilter](#snort_ipfilter)|9945|9945|217|2.1%|0.7%|
[firehol_level1](#firehol_level1)|5136|688854491|216|0.0%|0.7%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|197|0.0%|0.7%|
[proxyrss](#proxyrss)|1373|1373|196|14.2%|0.7%|
[proxz](#proxz)|1297|1297|184|14.1%|0.6%|
[blocklist_de_strongips](#blocklist_de_strongips)|177|177|177|100.0%|0.6%|
[openbl_1d](#openbl_1d)|140|140|128|91.4%|0.4%|
[iw_spamlist](#iw_spamlist)|3772|3772|125|3.3%|0.4%|
[dshield](#dshield)|20|5120|124|2.4%|0.4%|
[php_dictionary](#php_dictionary)|737|737|123|16.6%|0.4%|
[php_spammers](#php_spammers)|735|735|110|14.9%|0.3%|
[php_commenters](#php_commenters)|430|430|102|23.7%|0.3%|
[ri_connect_proxies](#ri_connect_proxies)|2811|2811|70|2.4%|0.2%|
[blocklist_de_sip](#blocklist_de_sip)|84|84|65|77.3%|0.2%|
[sorbs_web](#sorbs_web)|531|532|64|12.0%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|59|0.0%|0.2%|
[dragon_http](#dragon_http)|1029|270336|52|0.0%|0.1%|
[php_harvesters](#php_harvesters)|392|392|40|10.2%|0.1%|
[ciarmy](#ciarmy)|457|457|38|8.3%|0.1%|
[voipbl](#voipbl)|10533|10945|35|0.3%|0.1%|
[tor_exits](#tor_exits)|1121|1121|24|2.1%|0.0%|
[et_tor](#et_tor)|6400|6400|15|0.2%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|12|0.0%|0.0%|
[dm_tor](#dm_tor)|6490|6490|12|0.1%|0.0%|
[bm_tor](#bm_tor)|6492|6492|12|0.1%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|7|1.3%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|7|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|4|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|4|0.6%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|3|0.2%|0.0%|
[sorbs_socks](#sorbs_socks)|7|7|1|14.2%|0.0%|
[sorbs_misc](#sorbs_misc)|7|7|1|14.2%|0.0%|
[sorbs_http](#sorbs_http)|7|7|1|14.2%|0.0%|
[iw_wormlist](#iw_wormlist)|33|33|1|3.0%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|115|115|1|0.8%|0.0%|

## blocklist_de_apache

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service Apache, Apache-DDOS, RFI-Attacks.

Source is downloaded from [this link](http://lists.blocklist.de/lists/apache.txt).

The last time downloaded was found to be dated: Thu Jun 11 14:56:07 UTC 2015.

The ipset `blocklist_de_apache` has **14218** entries, **14218** unique IPs.

The following table shows the overlaps of `blocklist_de_apache` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_apache`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_apache`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_apache`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|21182|32799|14215|43.3%|99.9%|
[blocklist_de](#blocklist_de)|27522|27522|14215|51.6%|99.9%|
[blocklist_de_mail](#blocklist_de_mail)|16621|16621|11059|66.5%|77.7%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2852|2852|2852|100.0%|20.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|2299|0.0%|16.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|1323|0.0%|9.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|1090|0.0%|7.6%|
[firehol_level3](#firehol_level3)|109880|9627672|290|0.0%|2.0%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|206|0.2%|1.4%|
[alienvault_reputation](#alienvault_reputation)|188722|188722|124|0.0%|0.8%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|123|0.4%|0.8%|
[stopforumspam_1d](#stopforumspam_1d)|6710|6710|68|1.0%|0.4%|
[sorbs_spam](#sorbs_spam)|64701|65536|46|0.0%|0.3%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|46|0.0%|0.3%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|46|0.0%|0.3%|
[shunlist](#shunlist)|1263|1263|36|2.8%|0.2%|
[snort_ipfilter](#snort_ipfilter)|9945|9945|34|0.3%|0.2%|
[blocklist_de_strongips](#blocklist_de_strongips)|177|177|34|19.2%|0.2%|
[php_commenters](#php_commenters)|430|430|31|7.2%|0.2%|
[ciarmy](#ciarmy)|457|457|30|6.5%|0.2%|
[firehol_anonymous](#firehol_anonymous)|18927|82965|26|0.0%|0.1%|
[tor_exits](#tor_exits)|1121|1121|23|2.0%|0.1%|
[blocklist_de_bots](#blocklist_de_bots)|2942|2942|22|0.7%|0.1%|
[nixspam](#nixspam)|24663|24663|21|0.0%|0.1%|
[et_tor](#et_tor)|6400|6400|15|0.2%|0.1%|
[dragon_http](#dragon_http)|1029|270336|15|0.0%|0.1%|
[dm_tor](#dm_tor)|6490|6490|12|0.1%|0.0%|
[bm_tor](#bm_tor)|6492|6492|12|0.1%|0.0%|
[firehol_level1](#firehol_level1)|5136|688854491|11|0.0%|0.0%|
[et_block](#et_block)|1000|18344011|11|0.0%|0.0%|
[openbl_60d](#openbl_60d)|6989|6989|7|0.1%|0.0%|
[php_spammers](#php_spammers)|735|735|6|0.8%|0.0%|
[openbl_30d](#openbl_30d)|2813|2813|6|0.2%|0.0%|
[dshield](#dshield)|20|5120|6|0.1%|0.0%|
[openbl_7d](#openbl_7d)|641|641|5|0.7%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|4|0.0%|0.0%|
[iw_spamlist](#iw_spamlist)|3772|3772|4|0.1%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|4|0.0%|0.0%|
[php_dictionary](#php_dictionary)|737|737|3|0.4%|0.0%|
[firehol_proxies](#firehol_proxies)|12374|12641|3|0.0%|0.0%|
[voipbl](#voipbl)|10533|10945|2|0.0%|0.0%|
[php_harvesters](#php_harvesters)|392|392|2|0.5%|0.0%|
[openbl_1d](#openbl_1d)|140|140|2|1.4%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|2|0.3%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|2|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|1|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7800|7800|1|0.0%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|115|115|1|0.8%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2296|2296|1|0.0%|0.0%|

## blocklist_de_bots

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the RFI-Attacks, REG-Bots, IRC-Bots or BadBots (BadBots = he has posted a Spam-Comment on a open Forum or Wiki).

Source is downloaded from [this link](http://lists.blocklist.de/lists/bots.txt).

The last time downloaded was found to be dated: Thu Jun 11 14:42:09 UTC 2015.

The ipset `blocklist_de_bots` has **2942** entries, **2942** unique IPs.

The following table shows the overlaps of `blocklist_de_bots` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_bots`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_bots`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_bots`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|21182|32799|2942|8.9%|100.0%|
[blocklist_de](#blocklist_de)|27522|27522|2942|10.6%|100.0%|
[firehol_level3](#firehol_level3)|109880|9627672|2461|0.0%|83.6%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|2436|2.5%|82.8%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|2097|7.1%|71.2%|
[stopforumspam_1d](#stopforumspam_1d)|6710|6710|1378|20.5%|46.8%|
[firehol_anonymous](#firehol_anonymous)|18927|82965|511|0.6%|17.3%|
[firehol_proxies](#firehol_proxies)|12374|12641|509|4.0%|17.3%|
[ri_web_proxies](#ri_web_proxies)|7800|7800|381|4.8%|12.9%|
[proxyrss](#proxyrss)|1373|1373|196|14.2%|6.6%|
[xroxy](#xroxy)|2165|2165|168|7.7%|5.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|161|0.0%|5.4%|
[proxz](#proxz)|1297|1297|154|11.8%|5.2%|
[blocklist_de_strongips](#blocklist_de_strongips)|177|177|130|73.4%|4.4%|
[php_commenters](#php_commenters)|430|430|81|18.8%|2.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|75|0.0%|2.5%|
[ri_connect_proxies](#ri_connect_proxies)|2811|2811|67|2.3%|2.2%|
[firehol_level1](#firehol_level1)|5136|688854491|53|0.0%|1.8%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|50|0.0%|1.6%|
[et_block](#et_block)|1000|18344011|50|0.0%|1.6%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|47|0.0%|1.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|44|0.0%|1.4%|
[sorbs_spam](#sorbs_spam)|64701|65536|30|0.0%|1.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|30|0.0%|1.0%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|30|0.0%|1.0%|
[nixspam](#nixspam)|24663|24663|29|0.1%|0.9%|
[php_harvesters](#php_harvesters)|392|392|28|7.1%|0.9%|
[php_spammers](#php_spammers)|735|735|24|3.2%|0.8%|
[snort_ipfilter](#snort_ipfilter)|9945|9945|23|0.2%|0.7%|
[blocklist_de_mail](#blocklist_de_mail)|16621|16621|22|0.1%|0.7%|
[blocklist_de_apache](#blocklist_de_apache)|14218|14218|22|0.1%|0.7%|
[php_dictionary](#php_dictionary)|737|737|18|2.4%|0.6%|
[alienvault_reputation](#alienvault_reputation)|188722|188722|17|0.0%|0.5%|
[sorbs_web](#sorbs_web)|531|532|5|0.9%|0.1%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|5|0.9%|0.1%|
[iw_spamlist](#iw_spamlist)|3772|3772|5|0.1%|0.1%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|3|0.0%|0.1%|
[dragon_http](#dragon_http)|1029|270336|3|0.0%|0.1%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|2|0.1%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|2|0.3%|0.0%|
[tor_exits](#tor_exits)|1121|1121|1|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|1|0.0%|0.0%|
[et_compromised](#et_compromised)|1721|1721|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1701|1701|1|0.0%|0.0%|

## blocklist_de_bruteforce

[Blocklist.de](https://www.blocklist.de/) All IPs which attacks Joomlas, Wordpress and other Web-Logins with Brute-Force Logins.

Source is downloaded from [this link](http://lists.blocklist.de/lists/bruteforcelogin.txt).

The last time downloaded was found to be dated: Thu Jun 11 14:42:11 UTC 2015.

The ipset `blocklist_de_bruteforce` has **2852** entries, **2852** unique IPs.

The following table shows the overlaps of `blocklist_de_bruteforce` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_bruteforce`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_bruteforce`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_bruteforce`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|21182|32799|2852|8.6%|100.0%|
[blocklist_de_apache](#blocklist_de_apache)|14218|14218|2852|20.0%|100.0%|
[blocklist_de](#blocklist_de)|27522|27522|2852|10.3%|100.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|211|0.0%|7.3%|
[firehol_level3](#firehol_level3)|109880|9627672|93|0.0%|3.2%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|75|0.0%|2.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|59|0.0%|2.0%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|55|0.1%|1.9%|
[sorbs_spam](#sorbs_spam)|64701|65536|46|0.0%|1.6%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|46|0.0%|1.6%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|46|0.0%|1.6%|
[stopforumspam_1d](#stopforumspam_1d)|6710|6710|37|0.5%|1.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|34|0.0%|1.1%|
[snort_ipfilter](#snort_ipfilter)|9945|9945|31|0.3%|1.0%|
[firehol_anonymous](#firehol_anonymous)|18927|82965|23|0.0%|0.8%|
[tor_exits](#tor_exits)|1121|1121|21|1.8%|0.7%|
[nixspam](#nixspam)|24663|24663|21|0.0%|0.7%|
[alienvault_reputation](#alienvault_reputation)|188722|188722|18|0.0%|0.6%|
[et_tor](#et_tor)|6400|6400|13|0.2%|0.4%|
[php_commenters](#php_commenters)|430|430|10|2.3%|0.3%|
[dm_tor](#dm_tor)|6490|6490|9|0.1%|0.3%|
[bm_tor](#bm_tor)|6492|6492|9|0.1%|0.3%|
[blocklist_de_strongips](#blocklist_de_strongips)|177|177|9|5.0%|0.3%|
[php_spammers](#php_spammers)|735|735|6|0.8%|0.2%|
[et_block](#et_block)|1000|18344011|5|0.0%|0.1%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|4|0.0%|0.1%|
[iw_spamlist](#iw_spamlist)|3772|3772|4|0.1%|0.1%|
[firehol_level1](#firehol_level1)|5136|688854491|4|0.0%|0.1%|
[dragon_http](#dragon_http)|1029|270336|4|0.0%|0.1%|
[php_dictionary](#php_dictionary)|737|737|3|0.4%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|3|0.0%|0.1%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|2|0.0%|0.0%|
[firehol_proxies](#firehol_proxies)|12374|12641|2|0.0%|0.0%|
[voipbl](#voipbl)|10533|10945|1|0.0%|0.0%|
[shunlist](#shunlist)|1263|1263|1|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7800|7800|1|0.0%|0.0%|
[php_harvesters](#php_harvesters)|392|392|1|0.2%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|1|0.1%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.0%|

## blocklist_de_ftp

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours for attacks on the Service FTP.

Source is downloaded from [this link](http://lists.blocklist.de/lists/ftp.txt).

The last time downloaded was found to be dated: Thu Jun 11 14:42:08 UTC 2015.

The ipset `blocklist_de_ftp` has **1418** entries, **1418** unique IPs.

The following table shows the overlaps of `blocklist_de_ftp` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_ftp`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_ftp`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_ftp`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|21182|32799|1418|4.3%|100.0%|
[blocklist_de](#blocklist_de)|27522|27522|1418|5.1%|100.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|122|0.0%|8.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|25|0.0%|1.7%|
[firehol_level3](#firehol_level3)|109880|9627672|24|0.0%|1.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|20|0.0%|1.4%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|16|0.0%|1.1%|
[sorbs_spam](#sorbs_spam)|64701|65536|16|0.0%|1.1%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|16|0.0%|1.1%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|16|0.0%|1.1%|
[nixspam](#nixspam)|24663|24663|12|0.0%|0.8%|
[alienvault_reputation](#alienvault_reputation)|188722|188722|10|0.0%|0.7%|
[dragon_http](#dragon_http)|1029|270336|6|0.0%|0.4%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|5|0.0%|0.3%|
[php_harvesters](#php_harvesters)|392|392|4|1.0%|0.2%|
[firehol_anonymous](#firehol_anonymous)|18927|82965|3|0.0%|0.2%|
[openbl_60d](#openbl_60d)|6989|6989|2|0.0%|0.1%|
[iw_spamlist](#iw_spamlist)|3772|3772|2|0.0%|0.1%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|2|0.0%|0.1%|
[blocklist_de_strongips](#blocklist_de_strongips)|177|177|2|1.1%|0.1%|
[stopforumspam_1d](#stopforumspam_1d)|6710|6710|1|0.0%|0.0%|
[sorbs_web](#sorbs_web)|531|532|1|0.1%|0.0%|
[php_spammers](#php_spammers)|735|735|1|0.1%|0.0%|
[php_dictionary](#php_dictionary)|737|737|1|0.1%|0.0%|
[openbl_7d](#openbl_7d)|641|641|1|0.1%|0.0%|
[openbl_30d](#openbl_30d)|2813|2813|1|0.0%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.0%|
[ciarmy](#ciarmy)|457|457|1|0.2%|0.0%|

## blocklist_de_imap

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours for attacks on the Service imap, sasl, pop3, etc.

Source is downloaded from [this link](http://lists.blocklist.de/lists/imap.txt).

The last time downloaded was found to be dated: Thu Jun 11 14:56:06 UTC 2015.

The ipset `blocklist_de_imap` has **2296** entries, **2296** unique IPs.

The following table shows the overlaps of `blocklist_de_imap` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_imap`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_imap`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_imap`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|21182|32799|2288|6.9%|99.6%|
[blocklist_de_mail](#blocklist_de_mail)|16621|16621|2288|13.7%|99.6%|
[blocklist_de](#blocklist_de)|27522|27522|2288|8.3%|99.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|272|0.0%|11.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|68|0.0%|2.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|59|0.0%|2.5%|
[firehol_level3](#firehol_level3)|109880|9627672|36|0.0%|1.5%|
[nixspam](#nixspam)|24663|24663|34|0.1%|1.4%|
[alienvault_reputation](#alienvault_reputation)|188722|188722|31|0.0%|1.3%|
[sorbs_spam](#sorbs_spam)|64701|65536|25|0.0%|1.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|25|0.0%|1.0%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|25|0.0%|1.0%|
[openbl_60d](#openbl_60d)|6989|6989|16|0.2%|0.6%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|15|0.0%|0.6%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|10|0.0%|0.4%|
[firehol_level1](#firehol_level1)|5136|688854491|10|0.0%|0.4%|
[et_block](#et_block)|1000|18344011|10|0.0%|0.4%|
[openbl_30d](#openbl_30d)|2813|2813|9|0.3%|0.3%|
[openbl_7d](#openbl_7d)|641|641|7|1.0%|0.3%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|5|0.0%|0.2%|
[dragon_http](#dragon_http)|1029|270336|5|0.0%|0.2%|
[snort_ipfilter](#snort_ipfilter)|9945|9945|4|0.0%|0.1%|
[et_compromised](#et_compromised)|1721|1721|4|0.2%|0.1%|
[bruteforceblocker](#bruteforceblocker)|1701|1701|4|0.2%|0.1%|
[shunlist](#shunlist)|1263|1263|3|0.2%|0.1%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|3|0.0%|0.1%|
[stopforumspam_1d](#stopforumspam_1d)|6710|6710|2|0.0%|0.0%|
[php_harvesters](#php_harvesters)|392|392|2|0.5%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2|0.0%|0.0%|
[ciarmy](#ciarmy)|457|457|2|0.4%|0.0%|
[voipbl](#voipbl)|10533|10945|1|0.0%|0.0%|
[openbl_1d](#openbl_1d)|140|140|1|0.7%|0.0%|
[iw_spamlist](#iw_spamlist)|3772|3772|1|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14218|14218|1|0.0%|0.0%|

## blocklist_de_mail

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service Mail, Postfix.

Source is downloaded from [this link](http://lists.blocklist.de/lists/mail.txt).

The last time downloaded was found to be dated: Thu Jun 11 14:42:06 UTC 2015.

The ipset `blocklist_de_mail` has **16621** entries, **16621** unique IPs.

The following table shows the overlaps of `blocklist_de_mail` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_mail`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_mail`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_mail`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|21182|32799|16621|50.6%|100.0%|
[blocklist_de](#blocklist_de)|27522|27522|16621|60.3%|100.0%|
[blocklist_de_apache](#blocklist_de_apache)|14218|14218|11059|77.7%|66.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|2497|0.0%|15.0%|
[blocklist_de_imap](#blocklist_de_imap)|2296|2296|2288|99.6%|13.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|1418|0.0%|8.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|1254|0.0%|7.5%|
[sorbs_spam](#sorbs_spam)|64701|65536|1245|1.8%|7.4%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|1239|1.8%|7.4%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|1239|1.8%|7.4%|
[nixspam](#nixspam)|24663|24663|664|2.6%|3.9%|
[firehol_level3](#firehol_level3)|109880|9627672|404|0.0%|2.4%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|256|0.2%|1.5%|
[snort_ipfilter](#snort_ipfilter)|9945|9945|163|1.6%|0.9%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|145|0.4%|0.8%|
[firehol_anonymous](#firehol_anonymous)|18927|82965|126|0.1%|0.7%|
[firehol_proxies](#firehol_proxies)|12374|12641|124|0.9%|0.7%|
[iw_spamlist](#iw_spamlist)|3772|3772|114|3.0%|0.6%|
[php_dictionary](#php_dictionary)|737|737|101|13.7%|0.6%|
[ri_web_proxies](#ri_web_proxies)|7800|7800|84|1.0%|0.5%|
[php_spammers](#php_spammers)|735|735|78|10.6%|0.4%|
[sorbs_web](#sorbs_web)|531|532|58|10.9%|0.3%|
[xroxy](#xroxy)|2165|2165|57|2.6%|0.3%|
[alienvault_reputation](#alienvault_reputation)|188722|188722|47|0.0%|0.2%|
[stopforumspam_1d](#stopforumspam_1d)|6710|6710|43|0.6%|0.2%|
[proxz](#proxz)|1297|1297|30|2.3%|0.1%|
[php_commenters](#php_commenters)|430|430|27|6.2%|0.1%|
[openbl_60d](#openbl_60d)|6989|6989|23|0.3%|0.1%|
[blocklist_de_bots](#blocklist_de_bots)|2942|2942|22|0.7%|0.1%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|21|0.0%|0.1%|
[firehol_level1](#firehol_level1)|5136|688854491|21|0.0%|0.1%|
[et_block](#et_block)|1000|18344011|21|0.0%|0.1%|
[blocklist_de_strongips](#blocklist_de_strongips)|177|177|21|11.8%|0.1%|
[openbl_30d](#openbl_30d)|2813|2813|15|0.5%|0.0%|
[dragon_http](#dragon_http)|1029|270336|12|0.0%|0.0%|
[openbl_7d](#openbl_7d)|641|641|9|1.4%|0.0%|
[php_harvesters](#php_harvesters)|392|392|6|1.5%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|6|0.0%|0.0%|
[et_compromised](#et_compromised)|1721|1721|5|0.2%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1701|1701|5|0.2%|0.0%|
[shunlist](#shunlist)|1263|1263|4|0.3%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|4|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2811|2811|3|0.1%|0.0%|
[openbl_1d](#openbl_1d)|140|140|3|2.1%|0.0%|
[dm_tor](#dm_tor)|6490|6490|3|0.0%|0.0%|
[bm_tor](#bm_tor)|6492|6492|3|0.0%|0.0%|
[voipbl](#voipbl)|10533|10945|2|0.0%|0.0%|
[tor_exits](#tor_exits)|1121|1121|2|0.1%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|2|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|2|0.3%|0.0%|
[et_tor](#et_tor)|6400|6400|2|0.0%|0.0%|
[ciarmy](#ciarmy)|457|457|2|0.4%|0.0%|
[sorbs_socks](#sorbs_socks)|7|7|1|14.2%|0.0%|
[sorbs_misc](#sorbs_misc)|7|7|1|14.2%|0.0%|
[sorbs_http](#sorbs_http)|7|7|1|14.2%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|1|0.1%|0.0%|
[iw_wormlist](#iw_wormlist)|33|33|1|3.0%|0.0%|

## blocklist_de_sip

[Blocklist.de](https://www.blocklist.de/) All IP addresses that tried to login in a SIP, VOIP or Asterisk Server and are included in the IPs list from [infiltrated.net](www.infiltrated.net)

Source is downloaded from [this link](http://lists.blocklist.de/lists/sip.txt).

The last time downloaded was found to be dated: Thu Jun 11 14:42:08 UTC 2015.

The ipset `blocklist_de_sip` has **84** entries, **84** unique IPs.

The following table shows the overlaps of `blocklist_de_sip` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_sip`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_sip`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_sip`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|21182|32799|65|0.1%|77.3%|
[blocklist_de](#blocklist_de)|27522|27522|65|0.2%|77.3%|
[voipbl](#voipbl)|10533|10945|29|0.2%|34.5%|
[alienvault_reputation](#alienvault_reputation)|188722|188722|19|0.0%|22.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|13|0.0%|15.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|5|0.0%|5.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|5|0.0%|5.9%|
[firehol_level3](#firehol_level3)|109880|9627672|4|0.0%|4.7%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|2|0.0%|2.3%|
[shunlist](#shunlist)|1263|1263|2|0.1%|2.3%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|2|0.0%|2.3%|
[firehol_level1](#firehol_level1)|5136|688854491|2|0.0%|2.3%|
[et_block](#et_block)|1000|18344011|2|0.0%|2.3%|
[dragon_http](#dragon_http)|1029|270336|2|0.0%|2.3%|
[et_botcc](#et_botcc)|506|506|1|0.1%|1.1%|

## blocklist_de_ssh

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service SSH.

Source is downloaded from [this link](http://lists.blocklist.de/lists/ssh.txt).

The last time downloaded was found to be dated: Thu Jun 11 14:42:05 UTC 2015.

The ipset `blocklist_de_ssh` has **3334** entries, **3334** unique IPs.

The following table shows the overlaps of `blocklist_de_ssh` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_ssh`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_ssh`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_ssh`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|21182|32799|3334|10.1%|100.0%|
[blocklist_de](#blocklist_de)|27522|27522|3334|12.1%|100.0%|
[alienvault_reputation](#alienvault_reputation)|188722|188722|1057|0.5%|31.7%|
[firehol_level3](#firehol_level3)|109880|9627672|919|0.0%|27.5%|
[openbl_60d](#openbl_60d)|6989|6989|853|12.2%|25.5%|
[openbl_30d](#openbl_30d)|2813|2813|685|24.3%|20.5%|
[bruteforceblocker](#bruteforceblocker)|1701|1701|586|34.4%|17.5%|
[et_compromised](#et_compromised)|1721|1721|577|33.5%|17.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|501|0.0%|15.0%|
[openbl_7d](#openbl_7d)|641|641|375|58.5%|11.2%|
[shunlist](#shunlist)|1263|1263|359|28.4%|10.7%|
[et_block](#et_block)|1000|18344011|139|0.0%|4.1%|
[firehol_level1](#firehol_level1)|5136|688854491|129|0.0%|3.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|124|0.0%|3.7%|
[openbl_1d](#openbl_1d)|140|140|123|87.8%|3.6%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|120|0.0%|3.5%|
[dshield](#dshield)|20|5120|118|2.3%|3.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|56|0.0%|1.6%|
[blocklist_de_strongips](#blocklist_de_strongips)|177|177|30|16.9%|0.8%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|24|0.0%|0.7%|
[dragon_http](#dragon_http)|1029|270336|14|0.0%|0.4%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|6|0.0%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|6|0.0%|0.1%|
[sorbs_spam](#sorbs_spam)|64701|65536|5|0.0%|0.1%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|5|0.0%|0.1%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|5|0.0%|0.1%|
[ciarmy](#ciarmy)|457|457|4|0.8%|0.1%|
[voipbl](#voipbl)|10533|10945|2|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7800|7800|1|0.0%|0.0%|
[php_spammers](#php_spammers)|735|735|1|0.1%|0.0%|
[php_harvesters](#php_harvesters)|392|392|1|0.2%|0.0%|
[php_commenters](#php_commenters)|430|430|1|0.2%|0.0%|
[nixspam](#nixspam)|24663|24663|1|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|1|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|1|0.0%|0.0%|
[firehol_proxies](#firehol_proxies)|12374|12641|1|0.0%|0.0%|
[firehol_anonymous](#firehol_anonymous)|18927|82965|1|0.0%|0.0%|

## blocklist_de_strongips

[Blocklist.de](https://www.blocklist.de/) All IPs which are older then 2 month and have more then 5.000 attacks.

Source is downloaded from [this link](http://lists.blocklist.de/lists/strongips.txt).

The last time downloaded was found to be dated: Thu Jun 11 14:42:10 UTC 2015.

The ipset `blocklist_de_strongips` has **177** entries, **177** unique IPs.

The following table shows the overlaps of `blocklist_de_strongips` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_strongips`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_strongips`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_strongips`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|21182|32799|177|0.5%|100.0%|
[blocklist_de](#blocklist_de)|27522|27522|177|0.6%|100.0%|
[firehol_level3](#firehol_level3)|109880|9627672|163|0.0%|92.0%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|136|0.1%|76.8%|
[blocklist_de_bots](#blocklist_de_bots)|2942|2942|130|4.4%|73.4%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|121|0.4%|68.3%|
[stopforumspam_1d](#stopforumspam_1d)|6710|6710|105|1.5%|59.3%|
[php_commenters](#php_commenters)|430|430|46|10.6%|25.9%|
[alienvault_reputation](#alienvault_reputation)|188722|188722|36|0.0%|20.3%|
[blocklist_de_apache](#blocklist_de_apache)|14218|14218|34|0.2%|19.2%|
[blocklist_de_ssh](#blocklist_de_ssh)|3334|3334|30|0.8%|16.9%|
[openbl_60d](#openbl_60d)|6989|6989|25|0.3%|14.1%|
[openbl_30d](#openbl_30d)|2813|2813|24|0.8%|13.5%|
[openbl_7d](#openbl_7d)|641|641|23|3.5%|12.9%|
[blocklist_de_mail](#blocklist_de_mail)|16621|16621|21|0.1%|11.8%|
[shunlist](#shunlist)|1263|1263|19|1.5%|10.7%|
[openbl_1d](#openbl_1d)|140|140|17|12.1%|9.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|16|0.0%|9.0%|
[firehol_level1](#firehol_level1)|5136|688854491|11|0.0%|6.2%|
[php_spammers](#php_spammers)|735|735|10|1.3%|5.6%|
[et_block](#et_block)|1000|18344011|9|0.0%|5.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2852|2852|9|0.3%|5.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|8|0.0%|4.5%|
[firehol_proxies](#firehol_proxies)|12374|12641|8|0.0%|4.5%|
[firehol_anonymous](#firehol_anonymous)|18927|82965|8|0.0%|4.5%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|7|0.0%|3.9%|
[ri_web_proxies](#ri_web_proxies)|7800|7800|7|0.0%|3.9%|
[xroxy](#xroxy)|2165|2165|6|0.2%|3.3%|
[proxz](#proxz)|1297|1297|6|0.4%|3.3%|
[proxyrss](#proxyrss)|1373|1373|6|0.4%|3.3%|
[php_dictionary](#php_dictionary)|737|737|5|0.6%|2.8%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|3|0.0%|1.6%|
[php_harvesters](#php_harvesters)|392|392|3|0.7%|1.6%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|1.6%|
[sorbs_web](#sorbs_web)|531|532|2|0.3%|1.1%|
[sorbs_spam](#sorbs_spam)|64701|65536|2|0.0%|1.1%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|2|0.0%|1.1%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|2|0.0%|1.1%|
[snort_ipfilter](#snort_ipfilter)|9945|9945|2|0.0%|1.1%|
[nixspam](#nixspam)|24663|24663|2|0.0%|1.1%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|2|0.1%|1.1%|
[dragon_http](#dragon_http)|1029|270336|2|0.0%|1.1%|
[blocklist_de_ftp](#blocklist_de_ftp)|1418|1418|2|0.1%|1.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|1|0.0%|0.5%|
[et_compromised](#et_compromised)|1721|1721|1|0.0%|0.5%|
[dshield](#dshield)|20|5120|1|0.0%|0.5%|
[ciarmy](#ciarmy)|457|457|1|0.2%|0.5%|
[bruteforceblocker](#bruteforceblocker)|1701|1701|1|0.0%|0.5%|

## bm_tor

[torstatus.blutmagie.de](https://torstatus.blutmagie.de) list of all TOR network servers

Source is downloaded from [this link](https://torstatus.blutmagie.de/ip_list_all.php/Tor_ip_list_ALL.csv).

The last time downloaded was found to be dated: Thu Jun 11 14:45:03 UTC 2015.

The ipset `bm_tor` has **6492** entries, **6492** unique IPs.

The following table shows the overlaps of `bm_tor` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `bm_tor`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `bm_tor`.
- ` this % ` is the percentage **of this ipset (`bm_tor`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_anonymous](#firehol_anonymous)|18927|82965|6492|7.8%|100.0%|
[dm_tor](#dm_tor)|6490|6490|6401|98.6%|98.5%|
[et_tor](#et_tor)|6400|6400|5690|88.9%|87.6%|
[firehol_level3](#firehol_level3)|109880|9627672|1086|0.0%|16.7%|
[snort_ipfilter](#snort_ipfilter)|9945|9945|1050|10.5%|16.1%|
[tor_exits](#tor_exits)|1121|1121|1019|90.9%|15.6%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|640|0.6%|9.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|629|0.0%|9.6%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|532|1.8%|8.1%|
[firehol_level2](#firehol_level2)|21182|32799|341|1.0%|5.2%|
[stopforumspam_1d](#stopforumspam_1d)|6710|6710|336|5.0%|5.1%|
[firehol_proxies](#firehol_proxies)|12374|12641|237|1.8%|3.6%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|232|44.2%|3.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|184|0.0%|2.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|167|0.0%|2.5%|
[php_commenters](#php_commenters)|430|430|51|11.8%|0.7%|
[alienvault_reputation](#alienvault_reputation)|188722|188722|42|0.0%|0.6%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|22|0.0%|0.3%|
[openbl_60d](#openbl_60d)|6989|6989|20|0.2%|0.3%|
[dragon_http](#dragon_http)|1029|270336|16|0.0%|0.2%|
[blocklist_de_apache](#blocklist_de_apache)|14218|14218|12|0.0%|0.1%|
[blocklist_de](#blocklist_de)|27522|27522|12|0.0%|0.1%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2852|2852|9|0.3%|0.1%|
[php_harvesters](#php_harvesters)|392|392|7|1.7%|0.1%|
[nixspam](#nixspam)|24663|24663|7|0.0%|0.1%|
[ri_web_proxies](#ri_web_proxies)|7800|7800|5|0.0%|0.0%|
[php_spammers](#php_spammers)|735|735|5|0.6%|0.0%|
[sorbs_spam](#sorbs_spam)|64701|65536|4|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|4|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|4|0.0%|0.0%|
[php_dictionary](#php_dictionary)|737|737|4|0.5%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|4|0.0%|0.0%|
[voipbl](#voipbl)|10533|10945|3|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|3|0.0%|0.0%|
[firehol_level1](#firehol_level1)|5136|688854491|3|0.0%|0.0%|
[et_block](#et_block)|1000|18344011|3|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|16621|16621|3|0.0%|0.0%|
[xroxy](#xroxy)|2165|2165|2|0.0%|0.0%|
[shunlist](#shunlist)|1263|1263|1|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2811|2811|1|0.0%|0.0%|
[iw_spamlist](#iw_spamlist)|3772|3772|1|0.0%|0.0%|

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
[firehol_level1](#firehol_level1)|5136|688854491|592708608|86.0%|100.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|4194304|3.0%|0.7%|
[voipbl](#voipbl)|10533|10945|319|2.9%|0.0%|
[iw_spamlist](#iw_spamlist)|3772|3772|5|0.1%|0.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|5|0.0%|0.0%|
[firehol_level3](#firehol_level3)|109880|9627672|3|0.0%|0.0%|
[php_harvesters](#php_harvesters)|392|392|1|0.2%|0.0%|
[php_commenters](#php_commenters)|430|430|1|0.2%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.0%|
[ciarmy](#ciarmy)|457|457|1|0.2%|0.0%|

## bruteforceblocker

[danger.rulez.sk](http://danger.rulez.sk/) IPs detected by [bruteforceblocker](http://danger.rulez.sk/index.php/bruteforceblocker/) (fail2ban alternative for SSH on OpenBSD). This is an automatically generated list from users reporting failed authentication attempts. An IP seems to be included if 3 or more users report it. Its retention pocily seems 30 days.

Source is downloaded from [this link](http://danger.rulez.sk/projects/bruteforceblocker/blist.php).

The last time downloaded was found to be dated: Thu Jun 11 14:09:29 UTC 2015.

The ipset `bruteforceblocker` has **1701** entries, **1701** unique IPs.

The following table shows the overlaps of `bruteforceblocker` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `bruteforceblocker`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `bruteforceblocker`.
- ` this % ` is the percentage **of this ipset (`bruteforceblocker`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level3](#firehol_level3)|109880|9627672|1701|0.0%|100.0%|
[et_compromised](#et_compromised)|1721|1721|1639|95.2%|96.3%|
[alienvault_reputation](#alienvault_reputation)|188722|188722|1076|0.5%|63.2%|
[openbl_60d](#openbl_60d)|6989|6989|968|13.8%|56.9%|
[openbl_30d](#openbl_30d)|2813|2813|907|32.2%|53.3%|
[firehol_level2](#firehol_level2)|21182|32799|594|1.8%|34.9%|
[blocklist_de](#blocklist_de)|27522|27522|593|2.1%|34.8%|
[blocklist_de_ssh](#blocklist_de_ssh)|3334|3334|586|17.5%|34.4%|
[shunlist](#shunlist)|1263|1263|393|31.1%|23.1%|
[openbl_7d](#openbl_7d)|641|641|310|48.3%|18.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|157|0.0%|9.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|88|0.0%|5.1%|
[openbl_1d](#openbl_1d)|140|140|77|55.0%|4.5%|
[et_block](#et_block)|1000|18344011|69|0.0%|4.0%|
[firehol_level1](#firehol_level1)|5136|688854491|68|0.0%|3.9%|
[dshield](#dshield)|20|5120|62|1.2%|3.6%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|61|0.0%|3.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|54|0.0%|3.1%|
[dragon_http](#dragon_http)|1029|270336|12|0.0%|0.7%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|10|0.0%|0.5%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|5|0.0%|0.2%|
[blocklist_de_mail](#blocklist_de_mail)|16621|16621|5|0.0%|0.2%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|4|0.0%|0.2%|
[blocklist_de_imap](#blocklist_de_imap)|2296|2296|4|0.1%|0.2%|
[voipbl](#voipbl)|10533|10945|3|0.0%|0.1%|
[sorbs_spam](#sorbs_spam)|64701|65536|3|0.0%|0.1%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|3|0.0%|0.1%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|3|0.0%|0.1%|
[firehol_proxies](#firehol_proxies)|12374|12641|3|0.0%|0.1%|
[firehol_anonymous](#firehol_anonymous)|18927|82965|3|0.0%|0.1%|
[ciarmy](#ciarmy)|457|457|3|0.6%|0.1%|
[proxz](#proxz)|1297|1297|2|0.1%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|2|0.0%|0.1%|
[xroxy](#xroxy)|2165|2165|1|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6710|6710|1|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7800|7800|1|0.0%|0.0%|
[php_spammers](#php_spammers)|735|735|1|0.1%|0.0%|
[php_commenters](#php_commenters)|430|430|1|0.2%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|177|177|1|0.5%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|2942|2942|1|0.0%|0.0%|

## ciarmy

[CIArmy.com](http://ciarmy.com/) IPs with poor Rogue Packet score that have not yet been identified as malicious by the community

Source is downloaded from [this link](http://cinsscore.com/list/ci-badguys.txt).

The last time downloaded was found to be dated: Thu Jun 11 13:15:06 UTC 2015.

The ipset `ciarmy` has **457** entries, **457** unique IPs.

The following table shows the overlaps of `ciarmy` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ciarmy`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ciarmy`.
- ` this % ` is the percentage **of this ipset (`ciarmy`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level3](#firehol_level3)|109880|9627672|457|0.0%|100.0%|
[alienvault_reputation](#alienvault_reputation)|188722|188722|445|0.2%|97.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|100|0.0%|21.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|47|0.0%|10.2%|
[firehol_level2](#firehol_level2)|21182|32799|39|0.1%|8.5%|
[blocklist_de](#blocklist_de)|27522|27522|38|0.1%|8.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|37|0.0%|8.0%|
[blocklist_de_apache](#blocklist_de_apache)|14218|14218|30|0.2%|6.5%|
[shunlist](#shunlist)|1263|1263|26|2.0%|5.6%|
[dragon_http](#dragon_http)|1029|270336|8|0.0%|1.7%|
[et_block](#et_block)|1000|18344011|6|0.0%|1.3%|
[firehol_level1](#firehol_level1)|5136|688854491|4|0.0%|0.8%|
[blocklist_de_ssh](#blocklist_de_ssh)|3334|3334|4|0.1%|0.8%|
[openbl_7d](#openbl_7d)|641|641|3|0.4%|0.6%|
[openbl_60d](#openbl_60d)|6989|6989|3|0.0%|0.6%|
[openbl_30d](#openbl_30d)|2813|2813|3|0.1%|0.6%|
[et_compromised](#et_compromised)|1721|1721|3|0.1%|0.6%|
[dshield](#dshield)|20|5120|3|0.0%|0.6%|
[bruteforceblocker](#bruteforceblocker)|1701|1701|3|0.1%|0.6%|
[openbl_1d](#openbl_1d)|140|140|2|1.4%|0.4%|
[blocklist_de_mail](#blocklist_de_mail)|16621|16621|2|0.0%|0.4%|
[blocklist_de_imap](#blocklist_de_imap)|2296|2296|2|0.0%|0.4%|
[voipbl](#voipbl)|10533|10945|1|0.0%|0.2%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|1|0.0%|0.2%|
[fullbogons](#fullbogons)|3775|670173256|1|0.0%|0.2%|
[bogons](#bogons)|13|592708608|1|0.0%|0.2%|
[blocklist_de_strongips](#blocklist_de_strongips)|177|177|1|0.5%|0.2%|
[blocklist_de_ftp](#blocklist_de_ftp)|1418|1418|1|0.0%|0.2%|

## cleanmx_viruses

[Clean-MX.de](http://support.clean-mx.de/clean-mx/viruses.php) IPs with viruses

Source is downloaded from [this link](http://support.clean-mx.de/clean-mx/xmlviruses.php?sort=id%20desc&response=alive).

The last time downloaded was found to be dated: Thu Jun 11 09:09:08 UTC 2015.

The ipset `cleanmx_viruses` has **115** entries, **115** unique IPs.

The following table shows the overlaps of `cleanmx_viruses` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `cleanmx_viruses`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `cleanmx_viruses`.
- ` this % ` is the percentage **of this ipset (`cleanmx_viruses`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level3](#firehol_level3)|109880|9627672|115|0.0%|100.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|20|0.0%|17.3%|
[malc0de](#malc0de)|276|276|9|3.2%|7.8%|
[alienvault_reputation](#alienvault_reputation)|188722|188722|7|0.0%|6.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|6|0.0%|5.2%|
[snort_ipfilter](#snort_ipfilter)|9945|9945|4|0.0%|3.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|4|0.0%|3.4%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.8%|
[firehol_level2](#firehol_level2)|21182|32799|1|0.0%|0.8%|
[firehol_level1](#firehol_level1)|5136|688854491|1|0.0%|0.8%|
[dshield](#dshield)|20|5120|1|0.0%|0.8%|
[blocklist_de_apache](#blocklist_de_apache)|14218|14218|1|0.0%|0.8%|
[blocklist_de](#blocklist_de)|27522|27522|1|0.0%|0.8%|

## dm_tor

[dan.me.uk](https://www.dan.me.uk) dynamic list of TOR nodes

Source is downloaded from [this link](https://www.dan.me.uk/torlist/).

The last time downloaded was found to be dated: Thu Jun 11 15:00:04 UTC 2015.

The ipset `dm_tor` has **6490** entries, **6490** unique IPs.

The following table shows the overlaps of `dm_tor` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `dm_tor`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `dm_tor`.
- ` this % ` is the percentage **of this ipset (`dm_tor`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_anonymous](#firehol_anonymous)|18927|82965|6490|7.8%|100.0%|
[bm_tor](#bm_tor)|6492|6492|6401|98.5%|98.6%|
[et_tor](#et_tor)|6400|6400|5681|88.7%|87.5%|
[firehol_level3](#firehol_level3)|109880|9627672|1078|0.0%|16.6%|
[snort_ipfilter](#snort_ipfilter)|9945|9945|1042|10.4%|16.0%|
[tor_exits](#tor_exits)|1121|1121|1013|90.3%|15.6%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|637|0.6%|9.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|630|0.0%|9.7%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|528|1.8%|8.1%|
[firehol_level2](#firehol_level2)|21182|32799|340|1.0%|5.2%|
[stopforumspam_1d](#stopforumspam_1d)|6710|6710|335|4.9%|5.1%|
[firehol_proxies](#firehol_proxies)|12374|12641|236|1.8%|3.6%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|231|44.0%|3.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|184|0.0%|2.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|168|0.0%|2.5%|
[php_commenters](#php_commenters)|430|430|51|11.8%|0.7%|
[alienvault_reputation](#alienvault_reputation)|188722|188722|42|0.0%|0.6%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|22|0.0%|0.3%|
[openbl_60d](#openbl_60d)|6989|6989|20|0.2%|0.3%|
[dragon_http](#dragon_http)|1029|270336|16|0.0%|0.2%|
[blocklist_de_apache](#blocklist_de_apache)|14218|14218|12|0.0%|0.1%|
[blocklist_de](#blocklist_de)|27522|27522|12|0.0%|0.1%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2852|2852|9|0.3%|0.1%|
[php_harvesters](#php_harvesters)|392|392|7|1.7%|0.1%|
[nixspam](#nixspam)|24663|24663|6|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7800|7800|5|0.0%|0.0%|
[php_spammers](#php_spammers)|735|735|5|0.6%|0.0%|
[sorbs_spam](#sorbs_spam)|64701|65536|4|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|4|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|4|0.0%|0.0%|
[php_dictionary](#php_dictionary)|737|737|4|0.5%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|4|0.0%|0.0%|
[voipbl](#voipbl)|10533|10945|3|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|3|0.0%|0.0%|
[firehol_level1](#firehol_level1)|5136|688854491|3|0.0%|0.0%|
[et_block](#et_block)|1000|18344011|3|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|16621|16621|3|0.0%|0.0%|
[xroxy](#xroxy)|2165|2165|2|0.0%|0.0%|
[shunlist](#shunlist)|1263|1263|1|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2811|2811|1|0.0%|0.0%|
[iw_spamlist](#iw_spamlist)|3772|3772|1|0.0%|0.0%|

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
[alienvault_reputation](#alienvault_reputation)|188722|188722|6149|3.2%|2.2%|
[firehol_level1](#firehol_level1)|5136|688854491|1025|0.0%|0.3%|
[et_block](#et_block)|1000|18344011|1024|0.0%|0.3%|
[dshield](#dshield)|20|5120|768|15.0%|0.2%|
[firehol_level3](#firehol_level3)|109880|9627672|557|0.0%|0.2%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|256|0.0%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|256|0.0%|0.0%|
[openbl_60d](#openbl_60d)|6989|6989|218|3.1%|0.0%|
[openbl_30d](#openbl_30d)|2813|2813|148|5.2%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|111|0.1%|0.0%|
[sorbs_spam](#sorbs_spam)|64701|65536|71|0.1%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|70|0.1%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|70|0.1%|0.0%|
[firehol_level2](#firehol_level2)|21182|32799|62|0.1%|0.0%|
[openbl_7d](#openbl_7d)|641|641|54|8.4%|0.0%|
[blocklist_de](#blocklist_de)|27522|27522|52|0.1%|0.0%|
[firehol_anonymous](#firehol_anonymous)|18927|82965|43|0.0%|0.0%|
[shunlist](#shunlist)|1263|1263|37|2.9%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|36|0.1%|0.0%|
[firehol_proxies](#firehol_proxies)|12374|12641|30|0.2%|0.0%|
[nixspam](#nixspam)|24663|24663|27|0.1%|0.0%|
[voipbl](#voipbl)|10533|10945|26|0.2%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|26|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7800|7800|18|0.2%|0.0%|
[dm_tor](#dm_tor)|6490|6490|16|0.2%|0.0%|
[bm_tor](#bm_tor)|6492|6492|16|0.2%|0.0%|
[et_tor](#et_tor)|6400|6400|15|0.2%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14218|14218|15|0.1%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3334|3334|14|0.4%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1701|1701|12|0.7%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|16621|16621|12|0.0%|0.0%|
[et_compromised](#et_compromised)|1721|1721|11|0.6%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6710|6710|10|0.1%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9945|9945|10|0.1%|0.0%|
[ciarmy](#ciarmy)|457|457|8|1.7%|0.0%|
[xroxy](#xroxy)|2165|2165|6|0.2%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|6|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|1418|1418|6|0.4%|0.0%|
[tor_exits](#tor_exits)|1121|1121|5|0.4%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2296|2296|5|0.2%|0.0%|
[proxz](#proxz)|1297|1297|4|0.3%|0.0%|
[php_commenters](#php_commenters)|430|430|4|0.9%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|4|0.7%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2852|2852|4|0.1%|0.0%|
[zeus_badips](#zeus_badips)|202|202|3|1.4%|0.0%|
[zeus](#zeus)|230|230|3|1.3%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2811|2811|3|0.1%|0.0%|
[malc0de](#malc0de)|276|276|3|1.0%|0.0%|
[iw_spamlist](#iw_spamlist)|3772|3772|3|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|3|0.2%|0.0%|
[et_botcc](#et_botcc)|506|506|3|0.5%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|2942|2942|3|0.1%|0.0%|
[php_dictionary](#php_dictionary)|737|737|2|0.2%|0.0%|
[openbl_1d](#openbl_1d)|140|140|2|1.4%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|2|0.1%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|177|177|2|1.1%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|84|84|2|2.3%|0.0%|
[sslbl](#sslbl)|371|371|1|0.2%|0.0%|
[sorbs_web](#sorbs_web)|531|532|1|0.1%|0.0%|
[proxyrss](#proxyrss)|1373|1373|1|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|1|0.1%|0.0%|

## dshield

[DShield.org](https://dshield.org/) top 20 attacking class C (/24) subnets over the last three days - **excellent list**

Source is downloaded from [this link](http://feeds.dshield.org/block.txt).

The last time downloaded was found to be dated: Thu Jun 11 11:56:01 UTC 2015.

The ipset `dshield` has **20** entries, **5120** unique IPs.

The following table shows the overlaps of `dshield` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `dshield`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `dshield`.
- ` this % ` is the percentage **of this ipset (`dshield`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level1](#firehol_level1)|5136|688854491|5120|0.0%|100.0%|
[alienvault_reputation](#alienvault_reputation)|188722|188722|2321|1.2%|45.3%|
[et_block](#et_block)|1000|18344011|1792|0.0%|35.0%|
[dragon_http](#dragon_http)|1029|270336|768|0.2%|15.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|512|0.0%|10.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|512|0.0%|10.0%|
[firehol_level3](#firehol_level3)|109880|9627672|157|0.0%|3.0%|
[openbl_60d](#openbl_60d)|6989|6989|151|2.1%|2.9%|
[openbl_30d](#openbl_30d)|2813|2813|136|4.8%|2.6%|
[firehol_level2](#firehol_level2)|21182|32799|124|0.3%|2.4%|
[blocklist_de](#blocklist_de)|27522|27522|124|0.4%|2.4%|
[blocklist_de_ssh](#blocklist_de_ssh)|3334|3334|118|3.5%|2.3%|
[shunlist](#shunlist)|1263|1263|113|8.9%|2.2%|
[et_compromised](#et_compromised)|1721|1721|102|5.9%|1.9%|
[bruteforceblocker](#bruteforceblocker)|1701|1701|62|3.6%|1.2%|
[openbl_7d](#openbl_7d)|641|641|50|7.8%|0.9%|
[openbl_1d](#openbl_1d)|140|140|17|12.1%|0.3%|
[blocklist_de_apache](#blocklist_de_apache)|14218|14218|6|0.0%|0.1%|
[ciarmy](#ciarmy)|457|457|3|0.6%|0.0%|
[malc0de](#malc0de)|276|276|2|0.7%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|115|115|1|0.8%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|177|177|1|0.5%|0.0%|

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
[firehol_level1](#firehol_level1)|5136|688854491|18340169|2.6%|99.9%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|18338560|99.9%|99.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|8532520|2.4%|46.5%|
[firehol_level3](#firehol_level3)|109880|9627672|6933381|72.0%|37.7%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|6932480|75.5%|37.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|2272548|0.2%|12.3%|
[fullbogons](#fullbogons)|3775|670173256|151552|0.0%|0.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|130394|0.0%|0.7%|
[alienvault_reputation](#alienvault_reputation)|188722|188722|4764|2.5%|0.0%|
[dshield](#dshield)|20|5120|1792|35.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1042|0.3%|0.0%|
[dragon_http](#dragon_http)|1029|270336|1024|0.3%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|1018|1.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|517|0.1%|0.0%|
[openbl_60d](#openbl_60d)|6989|6989|300|4.2%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9945|9945|298|2.9%|0.0%|
[firehol_level2](#firehol_level2)|21182|32799|286|0.8%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|272|0.9%|0.0%|
[zeus](#zeus)|230|230|228|99.1%|0.0%|
[blocklist_de](#blocklist_de)|27522|27522|223|0.8%|0.0%|
[zeus_badips](#zeus_badips)|202|202|202|100.0%|0.0%|
[openbl_30d](#openbl_30d)|2813|2813|163|5.7%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3334|3334|139|4.1%|0.0%|
[shunlist](#shunlist)|1263|1263|115|9.1%|0.0%|
[et_compromised](#et_compromised)|1721|1721|109|6.3%|0.0%|
[feodo](#feodo)|105|105|104|99.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6710|6710|79|1.1%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1701|1701|69|4.0%|0.0%|
[openbl_7d](#openbl_7d)|641|641|61|9.5%|0.0%|
[nixspam](#nixspam)|24663|24663|55|0.2%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|2942|2942|50|1.6%|0.0%|
[sslbl](#sslbl)|371|371|38|10.2%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|30|2.3%|0.0%|
[php_commenters](#php_commenters)|430|430|29|6.7%|0.0%|
[sorbs_spam](#sorbs_spam)|64701|65536|22|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|22|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|22|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|16621|16621|21|0.1%|0.0%|
[openbl_1d](#openbl_1d)|140|140|18|12.8%|0.0%|
[voipbl](#voipbl)|10533|10945|14|0.1%|0.0%|
[palevo](#palevo)|12|12|12|100.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14218|14218|11|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2296|2296|10|0.4%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|177|177|9|5.0%|0.0%|
[php_dictionary](#php_dictionary)|737|737|6|0.8%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|6|0.4%|0.0%|
[firehol_anonymous](#firehol_anonymous)|18927|82965|6|0.0%|0.0%|
[ciarmy](#ciarmy)|457|457|6|1.3%|0.0%|
[malc0de](#malc0de)|276|276|5|1.8%|0.0%|
[iw_spamlist](#iw_spamlist)|3772|3772|5|0.1%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|5|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2852|2852|5|0.1%|0.0%|
[php_spammers](#php_spammers)|735|735|4|0.5%|0.0%|
[nt_malware_http](#nt_malware_http)|69|69|4|5.7%|0.0%|
[nt_malware_irc](#nt_malware_irc)|43|43|3|6.9%|0.0%|
[firehol_proxies](#firehol_proxies)|12374|12641|3|0.0%|0.0%|
[et_tor](#et_tor)|6400|6400|3|0.0%|0.0%|
[dm_tor](#dm_tor)|6490|6490|3|0.0%|0.0%|
[bm_tor](#bm_tor)|6492|6492|3|0.0%|0.0%|
[tor_exits](#tor_exits)|1121|1121|2|0.1%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|2|0.3%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|84|84|2|2.3%|0.0%|
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
[alienvault_reputation](#alienvault_reputation)|188722|188722|4|0.0%|0.7%|
[firehol_level3](#firehol_level3)|109880|9627672|3|0.0%|0.5%|
[dragon_http](#dragon_http)|1029|270336|3|0.0%|0.5%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|1|0.0%|0.1%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|1|0.0%|0.1%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|1|0.0%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.1%|
[firehol_level1](#firehol_level1)|5136|688854491|1|0.0%|0.1%|
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
[firehol_level3](#firehol_level3)|109880|9627672|1695|0.0%|98.4%|
[bruteforceblocker](#bruteforceblocker)|1701|1701|1639|96.3%|95.2%|
[alienvault_reputation](#alienvault_reputation)|188722|188722|1116|0.5%|64.8%|
[openbl_60d](#openbl_60d)|6989|6989|1014|14.5%|58.9%|
[openbl_30d](#openbl_30d)|2813|2813|945|33.5%|54.9%|
[firehol_level2](#firehol_level2)|21182|32799|585|1.7%|33.9%|
[blocklist_de](#blocklist_de)|27522|27522|584|2.1%|33.9%|
[blocklist_de_ssh](#blocklist_de_ssh)|3334|3334|577|17.3%|33.5%|
[shunlist](#shunlist)|1263|1263|429|33.9%|24.9%|
[openbl_7d](#openbl_7d)|641|641|313|48.8%|18.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|152|0.0%|8.8%|
[et_block](#et_block)|1000|18344011|109|0.0%|6.3%|
[firehol_level1](#firehol_level1)|5136|688854491|108|0.0%|6.2%|
[dshield](#dshield)|20|5120|102|1.9%|5.9%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|101|0.0%|5.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|85|0.0%|4.9%|
[openbl_1d](#openbl_1d)|140|140|75|53.5%|4.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|52|0.0%|3.0%|
[dragon_http](#dragon_http)|1029|270336|11|0.0%|0.6%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|10|0.0%|0.5%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|5|0.0%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|5|0.0%|0.2%|
[blocklist_de_mail](#blocklist_de_mail)|16621|16621|5|0.0%|0.2%|
[blocklist_de_imap](#blocklist_de_imap)|2296|2296|4|0.1%|0.2%|
[voipbl](#voipbl)|10533|10945|3|0.0%|0.1%|
[sorbs_spam](#sorbs_spam)|64701|65536|3|0.0%|0.1%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|3|0.0%|0.1%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|3|0.0%|0.1%|
[firehol_proxies](#firehol_proxies)|12374|12641|3|0.0%|0.1%|
[firehol_anonymous](#firehol_anonymous)|18927|82965|3|0.0%|0.1%|
[ciarmy](#ciarmy)|457|457|3|0.6%|0.1%|
[proxz](#proxz)|1297|1297|2|0.1%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|2|0.0%|0.1%|
[xroxy](#xroxy)|2165|2165|1|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6710|6710|1|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7800|7800|1|0.0%|0.0%|
[php_spammers](#php_spammers)|735|735|1|0.1%|0.0%|
[php_commenters](#php_commenters)|430|430|1|0.2%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|177|177|1|0.5%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|2942|2942|1|0.0%|0.0%|

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
[firehol_anonymous](#firehol_anonymous)|18927|82965|5744|6.9%|89.7%|
[bm_tor](#bm_tor)|6492|6492|5690|87.6%|88.9%|
[dm_tor](#dm_tor)|6490|6490|5681|87.5%|88.7%|
[firehol_level3](#firehol_level3)|109880|9627672|1125|0.0%|17.5%|
[snort_ipfilter](#snort_ipfilter)|9945|9945|1089|10.9%|17.0%|
[tor_exits](#tor_exits)|1121|1121|970|86.5%|15.1%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|653|0.6%|10.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|625|0.0%|9.7%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|547|1.8%|8.5%|
[firehol_level2](#firehol_level2)|21182|32799|344|1.0%|5.3%|
[stopforumspam_1d](#stopforumspam_1d)|6710|6710|335|4.9%|5.2%|
[firehol_proxies](#firehol_proxies)|12374|12641|238|1.8%|3.7%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|234|44.6%|3.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|181|0.0%|2.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|165|0.0%|2.5%|
[php_commenters](#php_commenters)|430|430|51|11.8%|0.7%|
[alienvault_reputation](#alienvault_reputation)|188722|188722|39|0.0%|0.6%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|22|0.0%|0.3%|
[openbl_60d](#openbl_60d)|6989|6989|20|0.2%|0.3%|
[dragon_http](#dragon_http)|1029|270336|15|0.0%|0.2%|
[blocklist_de_apache](#blocklist_de_apache)|14218|14218|15|0.1%|0.2%|
[blocklist_de](#blocklist_de)|27522|27522|15|0.0%|0.2%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2852|2852|13|0.4%|0.2%|
[php_harvesters](#php_harvesters)|392|392|7|1.7%|0.1%|
[nixspam](#nixspam)|24663|24663|6|0.0%|0.0%|
[php_spammers](#php_spammers)|735|735|5|0.6%|0.0%|
[sorbs_spam](#sorbs_spam)|64701|65536|4|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|4|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|4|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7800|7800|4|0.0%|0.0%|
[php_dictionary](#php_dictionary)|737|737|4|0.5%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|4|0.0%|0.0%|
[voipbl](#voipbl)|10533|10945|3|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|3|0.0%|0.0%|
[firehol_level1](#firehol_level1)|5136|688854491|3|0.0%|0.0%|
[et_block](#et_block)|1000|18344011|3|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|16621|16621|2|0.0%|0.0%|
[xroxy](#xroxy)|2165|2165|1|0.0%|0.0%|
[shunlist](#shunlist)|1263|1263|1|0.0%|0.0%|
[iw_spamlist](#iw_spamlist)|3772|3772|1|0.0%|0.0%|

## feodo

[Abuse.ch Feodo tracker](https://feodotracker.abuse.ch) trojan includes IPs which are being used by Feodo (also known as Cridex or Bugat) which commits ebanking fraud - **excellent list**

Source is downloaded from [this link](https://feodotracker.abuse.ch/blocklist/?download=ipblocklist).

The last time downloaded was found to be dated: Thu Jun 11 14:45:13 UTC 2015.

The ipset `feodo` has **105** entries, **105** unique IPs.

The following table shows the overlaps of `feodo` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `feodo`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `feodo`.
- ` this % ` is the percentage **of this ipset (`feodo`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level1](#firehol_level1)|5136|688854491|105|0.0%|100.0%|
[et_block](#et_block)|1000|18344011|104|0.0%|99.0%|
[snort_ipfilter](#snort_ipfilter)|9945|9945|83|0.8%|79.0%|
[firehol_level3](#firehol_level3)|109880|9627672|83|0.0%|79.0%|
[sslbl](#sslbl)|371|371|38|10.2%|36.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|11|0.0%|10.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|3|0.0%|2.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|3|0.0%|2.8%|
[alienvault_reputation](#alienvault_reputation)|188722|188722|2|0.0%|1.9%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.9%|

## firehol_anonymous

**FireHOL Anonymous** - Known anonymizing IPs. (includes: firehol_proxies anonymous bm_tor dm_tor tor_exits)

Source is downloaded from [this link]().

The last time downloaded was found to be dated: Sun Jun  7 22:20:34 UTC 2015.

The ipset `firehol_anonymous` has **18927** entries, **82965** unique IPs.

The following table shows the overlaps of `firehol_anonymous` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `firehol_anonymous`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `firehol_anonymous`.
- ` this % ` is the percentage **of this ipset (`firehol_anonymous`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_proxies](#firehol_proxies)|12374|12641|12641|100.0%|15.2%|
[ri_web_proxies](#ri_web_proxies)|7800|7800|7800|100.0%|9.4%|
[firehol_level3](#firehol_level3)|109880|9627672|6752|0.0%|8.1%|
[bm_tor](#bm_tor)|6492|6492|6492|100.0%|7.8%|
[dm_tor](#dm_tor)|6490|6490|6490|100.0%|7.8%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|6196|6.5%|7.4%|
[et_tor](#et_tor)|6400|6400|5744|89.7%|6.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|3446|0.0%|4.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|2897|0.0%|3.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|2876|0.0%|3.4%|
[ri_connect_proxies](#ri_connect_proxies)|2811|2811|2811|100.0%|3.3%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|2750|9.4%|3.3%|
[xroxy](#xroxy)|2165|2165|2165|100.0%|2.6%|
[proxyrss](#proxyrss)|1373|1373|1373|100.0%|1.6%|
[firehol_level2](#firehol_level2)|21182|32799|1346|4.1%|1.6%|
[proxz](#proxz)|1297|1297|1297|100.0%|1.5%|
[snort_ipfilter](#snort_ipfilter)|9945|9945|1224|12.3%|1.4%|
[tor_exits](#tor_exits)|1121|1121|1121|100.0%|1.3%|
[stopforumspam_1d](#stopforumspam_1d)|6710|6710|987|14.7%|1.1%|
[blocklist_de](#blocklist_de)|27522|27522|664|2.4%|0.8%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|663|100.0%|0.7%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|524|100.0%|0.6%|
[blocklist_de_bots](#blocklist_de_bots)|2942|2942|511|17.3%|0.6%|
[sorbs_spam](#sorbs_spam)|64701|65536|201|0.3%|0.2%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|201|0.3%|0.2%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|201|0.3%|0.2%|
[nixspam](#nixspam)|24663|24663|190|0.7%|0.2%|
[blocklist_de_mail](#blocklist_de_mail)|16621|16621|126|0.7%|0.1%|
[php_dictionary](#php_dictionary)|737|737|98|13.2%|0.1%|
[php_spammers](#php_spammers)|735|735|81|11.0%|0.0%|
[php_commenters](#php_commenters)|430|430|81|18.8%|0.0%|
[voipbl](#voipbl)|10533|10945|79|0.7%|0.0%|
[alienvault_reputation](#alienvault_reputation)|188722|188722|57|0.0%|0.0%|
[dragon_http](#dragon_http)|1029|270336|43|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|29|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14218|14218|26|0.1%|0.0%|
[sorbs_web](#sorbs_web)|531|532|25|4.6%|0.0%|
[openbl_60d](#openbl_60d)|6989|6989|23|0.3%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2852|2852|23|0.8%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|15|0.0%|0.0%|
[iw_spamlist](#iw_spamlist)|3772|3772|14|0.3%|0.0%|
[php_harvesters](#php_harvesters)|392|392|12|3.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|177|177|8|4.5%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|7|0.0%|0.0%|
[firehol_level1](#firehol_level1)|5136|688854491|7|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|6|0.0%|0.0%|
[et_block](#et_block)|1000|18344011|6|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|3|0.2%|0.0%|
[et_compromised](#et_compromised)|1721|1721|3|0.1%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1701|1701|3|0.1%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|1418|1418|3|0.2%|0.0%|
[sslbl](#sslbl)|371|371|1|0.2%|0.0%|
[shunlist](#shunlist)|1263|1263|1|0.0%|0.0%|
[openbl_30d](#openbl_30d)|2813|2813|1|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3334|3334|1|0.0%|0.0%|

## firehol_level1

**FireHOL Level 1** - Maximum protection without false positives. (includes: fullbogons dshield feodo palevo sslbl zeus spamhaus_drop spamhaus_edrop)

Source is downloaded from [this link]().

The last time downloaded was found to be dated: Sun Jun  7 22:15:43 UTC 2015.

The ipset `firehol_level1` has **5136** entries, **688854491** unique IPs.

The following table shows the overlaps of `firehol_level1` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `firehol_level1`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `firehol_level1`.
- ` this % ` is the percentage **of this ipset (`firehol_level1`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[fullbogons](#fullbogons)|3775|670173256|670173256|100.0%|97.2%|
[bogons](#bogons)|13|592708608|592708608|100.0%|86.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|18340608|100.0%|2.6%|
[et_block](#et_block)|1000|18344011|18340169|99.9%|2.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|8867717|2.5%|1.2%|
[firehol_level3](#firehol_level3)|109880|9627672|7500199|77.9%|1.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|7498240|81.6%|1.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|4637858|3.3%|0.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|2570306|0.3%|0.3%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|487424|100.0%|0.0%|
[dshield](#dshield)|20|5120|5120|100.0%|0.0%|
[alienvault_reputation](#alienvault_reputation)|188722|188722|3321|1.7%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1932|0.5%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|1090|1.1%|0.0%|
[dragon_http](#dragon_http)|1029|270336|1025|0.3%|0.0%|
[sslbl](#sslbl)|371|371|371|100.0%|0.0%|
[voipbl](#voipbl)|10533|10945|333|3.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9945|9945|299|3.0%|0.0%|
[openbl_60d](#openbl_60d)|6989|6989|284|4.0%|0.0%|
[firehol_level2](#firehol_level2)|21182|32799|281|0.8%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|278|0.9%|0.0%|
[zeus](#zeus)|230|230|230|100.0%|0.0%|
[blocklist_de](#blocklist_de)|27522|27522|216|0.7%|0.0%|
[zeus_badips](#zeus_badips)|202|202|202|100.0%|0.0%|
[shunlist](#shunlist)|1263|1263|176|13.9%|0.0%|
[openbl_30d](#openbl_30d)|2813|2813|155|5.5%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3334|3334|129|3.8%|0.0%|
[et_compromised](#et_compromised)|1721|1721|108|6.2%|0.0%|
[feodo](#feodo)|105|105|105|100.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6710|6710|82|1.2%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1701|1701|68|3.9%|0.0%|
[openbl_7d](#openbl_7d)|641|641|56|8.7%|0.0%|
[nixspam](#nixspam)|24663|24663|55|0.2%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|2942|2942|53|1.8%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|39|3.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|39|2.6%|0.0%|
[php_commenters](#php_commenters)|430|430|38|8.8%|0.0%|
[sorbs_spam](#sorbs_spam)|64701|65536|25|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|25|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|25|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|16621|16621|21|0.1%|0.0%|
[openbl_1d](#openbl_1d)|140|140|18|12.8%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|18|0.0%|0.0%|
[palevo](#palevo)|12|12|12|100.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|177|177|11|6.2%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14218|14218|11|0.0%|0.0%|
[iw_spamlist](#iw_spamlist)|3772|3772|10|0.2%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2296|2296|10|0.4%|0.0%|
[nt_malware_http](#nt_malware_http)|69|69|8|11.5%|0.0%|
[malc0de](#malc0de)|276|276|7|2.5%|0.0%|
[firehol_anonymous](#firehol_anonymous)|18927|82965|7|0.0%|0.0%|
[php_dictionary](#php_dictionary)|737|737|6|0.8%|0.0%|
[php_spammers](#php_spammers)|735|735|4|0.5%|0.0%|
[firehol_proxies](#firehol_proxies)|12374|12641|4|0.0%|0.0%|
[ciarmy](#ciarmy)|457|457|4|0.8%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2852|2852|4|0.1%|0.0%|
[php_harvesters](#php_harvesters)|392|392|3|0.7%|0.0%|
[nt_malware_irc](#nt_malware_irc)|43|43|3|6.9%|0.0%|
[et_tor](#et_tor)|6400|6400|3|0.0%|0.0%|
[dm_tor](#dm_tor)|6490|6490|3|0.0%|0.0%|
[bm_tor](#bm_tor)|6492|6492|3|0.0%|0.0%|
[tor_exits](#tor_exits)|1121|1121|2|0.1%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|2|0.3%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|84|84|2|2.3%|0.0%|
[virbl](#virbl)|28|28|1|3.5%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7800|7800|1|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|1|0.1%|0.0%|
[et_botcc](#et_botcc)|506|506|1|0.1%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|115|115|1|0.8%|0.0%|

## firehol_level2

**FireHOL Level 2** - Maximum protection from attacks took place in the last 48 hours. (includes: openbl_1d blocklist_de stopforumspam_1d)

Source is downloaded from [this link]().

The last time downloaded was found to be dated: Sun Jun  7 22:20:34 UTC 2015.

The ipset `firehol_level2` has **21182** entries, **32799** unique IPs.

The following table shows the overlaps of `firehol_level2` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `firehol_level2`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `firehol_level2`.
- ` this % ` is the percentage **of this ipset (`firehol_level2`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|27522|27522|27522|100.0%|83.9%|
[blocklist_de_mail](#blocklist_de_mail)|16621|16621|16621|100.0%|50.6%|
[blocklist_de_apache](#blocklist_de_apache)|14218|14218|14215|99.9%|43.3%|
[firehol_level3](#firehol_level3)|109880|9627672|8926|0.0%|27.2%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|7744|8.2%|23.6%|
[stopforumspam_1d](#stopforumspam_1d)|6710|6710|6710|100.0%|20.4%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|5873|20.1%|17.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|3934|0.0%|11.9%|
[blocklist_de_ssh](#blocklist_de_ssh)|3334|3334|3334|100.0%|10.1%|
[blocklist_de_bots](#blocklist_de_bots)|2942|2942|2942|100.0%|8.9%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2852|2852|2852|100.0%|8.6%|
[blocklist_de_imap](#blocklist_de_imap)|2296|2296|2288|99.6%|6.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|1705|0.0%|5.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|1677|0.0%|5.1%|
[blocklist_de_ftp](#blocklist_de_ftp)|1418|1418|1418|100.0%|4.3%|
[sorbs_spam](#sorbs_spam)|64701|65536|1354|2.0%|4.1%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|1348|2.0%|4.1%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|1348|2.0%|4.1%|
[firehol_anonymous](#firehol_anonymous)|18927|82965|1346|1.6%|4.1%|
[alienvault_reputation](#alienvault_reputation)|188722|188722|1308|0.6%|3.9%|
[firehol_proxies](#firehol_proxies)|12374|12641|1174|9.2%|3.5%|
[openbl_60d](#openbl_60d)|6989|6989|917|13.1%|2.7%|
[nixspam](#nixspam)|24663|24663|745|3.0%|2.2%|
[openbl_30d](#openbl_30d)|2813|2813|720|25.5%|2.1%|
[ri_web_proxies](#ri_web_proxies)|7800|7800|678|8.6%|2.0%|
[bruteforceblocker](#bruteforceblocker)|1701|1701|594|34.9%|1.8%|
[et_compromised](#et_compromised)|1721|1721|585|33.9%|1.7%|
[snort_ipfilter](#snort_ipfilter)|9945|9945|557|5.6%|1.6%|
[shunlist](#shunlist)|1263|1263|405|32.0%|1.2%|
[openbl_7d](#openbl_7d)|641|641|401|62.5%|1.2%|
[proxyrss](#proxyrss)|1373|1373|364|26.5%|1.1%|
[tor_exits](#tor_exits)|1121|1121|360|32.1%|1.0%|
[et_tor](#et_tor)|6400|6400|344|5.3%|1.0%|
[bm_tor](#bm_tor)|6492|6492|341|5.2%|1.0%|
[dm_tor](#dm_tor)|6490|6490|340|5.2%|1.0%|
[xroxy](#xroxy)|2165|2165|327|15.1%|0.9%|
[et_block](#et_block)|1000|18344011|286|0.0%|0.8%|
[firehol_level1](#firehol_level1)|5136|688854491|281|0.0%|0.8%|
[proxz](#proxz)|1297|1297|280|21.5%|0.8%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|260|0.0%|0.7%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|215|41.0%|0.6%|
[php_commenters](#php_commenters)|430|430|189|43.9%|0.5%|
[blocklist_de_strongips](#blocklist_de_strongips)|177|177|177|100.0%|0.5%|
[ri_connect_proxies](#ri_connect_proxies)|2811|2811|151|5.3%|0.4%|
[openbl_1d](#openbl_1d)|140|140|140|100.0%|0.4%|
[php_dictionary](#php_dictionary)|737|737|128|17.3%|0.3%|
[iw_spamlist](#iw_spamlist)|3772|3772|127|3.3%|0.3%|
[dshield](#dshield)|20|5120|124|2.4%|0.3%|
[php_spammers](#php_spammers)|735|735|120|16.3%|0.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|84|0.0%|0.2%|
[blocklist_de_sip](#blocklist_de_sip)|84|84|65|77.3%|0.1%|
[sorbs_web](#sorbs_web)|531|532|64|12.0%|0.1%|
[dragon_http](#dragon_http)|1029|270336|62|0.0%|0.1%|
[php_harvesters](#php_harvesters)|392|392|59|15.0%|0.1%|
[voipbl](#voipbl)|10533|10945|40|0.3%|0.1%|
[ciarmy](#ciarmy)|457|457|39|8.5%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|17|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|13|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|8|1.2%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|5|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|3|0.2%|0.0%|
[zeus_badips](#zeus_badips)|202|202|1|0.4%|0.0%|
[zeus](#zeus)|230|230|1|0.4%|0.0%|
[sorbs_socks](#sorbs_socks)|7|7|1|14.2%|0.0%|
[sorbs_misc](#sorbs_misc)|7|7|1|14.2%|0.0%|
[sorbs_http](#sorbs_http)|7|7|1|14.2%|0.0%|
[iw_wormlist](#iw_wormlist)|33|33|1|3.0%|0.0%|
[fullbogons](#fullbogons)|3775|670173256|1|0.0%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|115|115|1|0.8%|0.0%|

## firehol_level3

**FireHOL Level 3** - All the bad IPs in last 30 days. (includes: openbl_30d stopforumspam_30d virbl malc0de shunlist malwaredomainlist bruteforceblocker ciarmy cleanmx_viruses snort_ipfilter ib_bluetack_spyware ib_bluetack_hijacked ib_bluetack_webexploit php_commenters php_dictionary php_harvesters php_spammers iw_wormlist)

Source is downloaded from [this link]().

The last time downloaded was found to be dated: Sun Jun  7 22:20:34 UTC 2015.

The ipset `firehol_level3` has **109880** entries, **9627672** unique IPs.

The following table shows the overlaps of `firehol_level3` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `firehol_level3`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `firehol_level3`.
- ` this % ` is the percentage **of this ipset (`firehol_level3`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|9177856|100.0%|95.3%|
[firehol_level1](#firehol_level1)|5136|688854491|7500199|1.0%|77.9%|
[et_block](#et_block)|1000|18344011|6933381|37.7%|72.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|6933040|37.8%|72.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|2537273|0.7%|26.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|919969|0.1%|9.5%|
[fullbogons](#fullbogons)|3775|670173256|566693|0.0%|5.8%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|339173|100.0%|3.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|161586|0.1%|1.6%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|94309|100.0%|0.9%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|29184|99.9%|0.3%|
[snort_ipfilter](#snort_ipfilter)|9945|9945|9945|100.0%|0.1%|
[firehol_level2](#firehol_level2)|21182|32799|8926|27.2%|0.0%|
[firehol_anonymous](#firehol_anonymous)|18927|82965|6752|8.1%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6710|6710|6372|94.9%|0.0%|
[firehol_proxies](#firehol_proxies)|12374|12641|5648|44.6%|0.0%|
[alienvault_reputation](#alienvault_reputation)|188722|188722|4882|2.5%|0.0%|
[blocklist_de](#blocklist_de)|27522|27522|3965|14.4%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7800|7800|3725|47.7%|0.0%|
[openbl_60d](#openbl_60d)|6989|6989|2941|42.0%|0.0%|
[openbl_30d](#openbl_30d)|2813|2813|2813|100.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|2942|2942|2461|83.6%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1701|1701|1701|100.0%|0.0%|
[et_compromised](#et_compromised)|1721|1721|1695|98.4%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2811|2811|1584|56.3%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|1450|100.0%|0.0%|
[sorbs_spam](#sorbs_spam)|64701|65536|1303|1.9%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|1301|1.9%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|1301|1.9%|0.0%|
[xroxy](#xroxy)|2165|2165|1299|60.0%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|1288|100.0%|0.0%|
[shunlist](#shunlist)|1263|1263|1263|100.0%|0.0%|
[et_tor](#et_tor)|6400|6400|1125|17.5%|0.0%|
[bm_tor](#bm_tor)|6492|6492|1086|16.7%|0.0%|
[dm_tor](#dm_tor)|6490|6490|1078|16.6%|0.0%|
[tor_exits](#tor_exits)|1121|1121|1067|95.1%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3334|3334|919|27.5%|0.0%|
[proxz](#proxz)|1297|1297|772|59.5%|0.0%|
[php_dictionary](#php_dictionary)|737|737|737|100.0%|0.0%|
[php_spammers](#php_spammers)|735|735|735|100.0%|0.0%|
[proxyrss](#proxyrss)|1373|1373|683|49.7%|0.0%|
[openbl_7d](#openbl_7d)|641|641|641|100.0%|0.0%|
[dragon_http](#dragon_http)|1029|270336|557|0.2%|0.0%|
[nixspam](#nixspam)|24663|24663|488|1.9%|0.0%|
[ciarmy](#ciarmy)|457|457|457|100.0%|0.0%|
[php_commenters](#php_commenters)|430|430|430|100.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|16621|16621|404|2.4%|0.0%|
[php_harvesters](#php_harvesters)|392|392|392|100.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|346|66.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14218|14218|290|2.0%|0.0%|
[malc0de](#malc0de)|276|276|276|100.0%|0.0%|
[zeus](#zeus)|230|230|203|88.2%|0.0%|
[zeus_badips](#zeus_badips)|202|202|180|89.1%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|177|177|163|92.0%|0.0%|
[dshield](#dshield)|20|5120|157|3.0%|0.0%|
[openbl_1d](#openbl_1d)|140|140|138|98.5%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|115|115|115|100.0%|0.0%|
[iw_spamlist](#iw_spamlist)|3772|3772|94|2.4%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2852|2852|93|3.2%|0.0%|
[sslbl](#sslbl)|371|371|92|24.7%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|85|0.0%|0.0%|
[feodo](#feodo)|105|105|83|79.0%|0.0%|
[sorbs_web](#sorbs_web)|531|532|65|12.2%|0.0%|
[voipbl](#voipbl)|10533|10945|57|0.5%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2296|2296|36|1.5%|0.0%|
[iw_wormlist](#iw_wormlist)|33|33|33|100.0%|0.0%|
[virbl](#virbl)|28|28|28|100.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|25|3.7%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|25|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|1418|1418|24|1.6%|0.0%|
[palevo](#palevo)|12|12|10|83.3%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|84|84|4|4.7%|0.0%|
[nt_malware_http](#nt_malware_http)|69|69|3|4.3%|0.0%|
[et_botcc](#et_botcc)|506|506|3|0.5%|0.0%|
[bogons](#bogons)|13|592708608|3|0.0%|0.0%|
[sorbs_socks](#sorbs_socks)|7|7|1|14.2%|0.0%|
[sorbs_misc](#sorbs_misc)|7|7|1|14.2%|0.0%|
[sorbs_http](#sorbs_http)|7|7|1|14.2%|0.0%|
[nt_malware_irc](#nt_malware_irc)|43|43|1|2.3%|0.0%|

## firehol_proxies

**FireHOL Proxies** - Known open proxies in the last 30 days. (includes: ib_bluetack_proxies maxmind_proxy_fraud proxyrss proxz ri_connect_proxies ri_web_proxies xroxy)

Source is downloaded from [this link]().

The last time downloaded was found to be dated: Sun Jun  7 22:20:34 UTC 2015.

The ipset `firehol_proxies` has **12374** entries, **12641** unique IPs.

The following table shows the overlaps of `firehol_proxies` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `firehol_proxies`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `firehol_proxies`.
- ` this % ` is the percentage **of this ipset (`firehol_proxies`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_anonymous](#firehol_anonymous)|18927|82965|12641|15.2%|100.0%|
[ri_web_proxies](#ri_web_proxies)|7800|7800|7800|100.0%|61.7%|
[firehol_level3](#firehol_level3)|109880|9627672|5648|0.0%|44.6%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|5587|5.9%|44.1%|
[ri_connect_proxies](#ri_connect_proxies)|2811|2811|2811|100.0%|22.2%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|2379|8.1%|18.8%|
[xroxy](#xroxy)|2165|2165|2165|100.0%|17.1%|
[proxyrss](#proxyrss)|1373|1373|1373|100.0%|10.8%|
[proxz](#proxz)|1297|1297|1297|100.0%|10.2%|
[firehol_level2](#firehol_level2)|21182|32799|1174|3.5%|9.2%|
[stopforumspam_1d](#stopforumspam_1d)|6710|6710|831|12.3%|6.5%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|663|100.0%|5.2%|
[blocklist_de](#blocklist_de)|27522|27522|636|2.3%|5.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|526|0.0%|4.1%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|524|100.0%|4.1%|
[blocklist_de_bots](#blocklist_de_bots)|2942|2942|509|17.3%|4.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|394|0.0%|3.1%|
[snort_ipfilter](#snort_ipfilter)|9945|9945|325|3.2%|2.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|295|0.0%|2.3%|
[et_tor](#et_tor)|6400|6400|238|3.7%|1.8%|
[bm_tor](#bm_tor)|6492|6492|237|3.6%|1.8%|
[dm_tor](#dm_tor)|6490|6490|236|3.6%|1.8%|
[tor_exits](#tor_exits)|1121|1121|231|20.6%|1.8%|
[sorbs_spam](#sorbs_spam)|64701|65536|196|0.2%|1.5%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|196|0.3%|1.5%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|196|0.3%|1.5%|
[nixspam](#nixspam)|24663|24663|183|0.7%|1.4%|
[blocklist_de_mail](#blocklist_de_mail)|16621|16621|124|0.7%|0.9%|
[php_dictionary](#php_dictionary)|737|737|97|13.1%|0.7%|
[php_spammers](#php_spammers)|735|735|79|10.7%|0.6%|
[php_commenters](#php_commenters)|430|430|79|18.3%|0.6%|
[alienvault_reputation](#alienvault_reputation)|188722|188722|38|0.0%|0.3%|
[dragon_http](#dragon_http)|1029|270336|30|0.0%|0.2%|
[sorbs_web](#sorbs_web)|531|532|25|4.6%|0.1%|
[openbl_60d](#openbl_60d)|6989|6989|20|0.2%|0.1%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|15|0.0%|0.1%|
[iw_spamlist](#iw_spamlist)|3772|3772|13|0.3%|0.1%|
[php_harvesters](#php_harvesters)|392|392|12|3.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|11|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|177|177|8|4.5%|0.0%|
[firehol_level1](#firehol_level1)|5136|688854491|4|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|3|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|3|0.2%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|0.0%|
[et_compromised](#et_compromised)|1721|1721|3|0.1%|0.0%|
[et_block](#et_block)|1000|18344011|3|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1701|1701|3|0.1%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14218|14218|3|0.0%|0.0%|
[voipbl](#voipbl)|10533|10945|2|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2852|2852|2|0.0%|0.0%|
[sslbl](#sslbl)|371|371|1|0.2%|0.0%|
[shunlist](#shunlist)|1263|1263|1|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3334|3334|1|0.0%|0.0%|

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
[firehol_level1](#firehol_level1)|5136|688854491|670173256|97.2%|100.0%|
[bogons](#bogons)|13|592708608|592708608|100.0%|88.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|4236143|3.0%|0.6%|
[firehol_level3](#firehol_level3)|109880|9627672|566693|5.8%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|565760|6.1%|0.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|264873|0.0%|0.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|252671|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|151552|0.8%|0.0%|
[et_block](#et_block)|1000|18344011|151552|0.8%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|890|0.2%|0.0%|
[voipbl](#voipbl)|10533|10945|319|2.9%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|33|2.2%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|13|0.0%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|9|0.6%|0.0%|
[iw_spamlist](#iw_spamlist)|3772|3772|5|0.1%|0.0%|
[nt_malware_http](#nt_malware_http)|69|69|4|5.7%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|2|0.0%|0.0%|
[virbl](#virbl)|28|28|1|3.5%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|1|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6710|6710|1|0.0%|0.0%|
[php_harvesters](#php_harvesters)|392|392|1|0.2%|0.0%|
[php_commenters](#php_commenters)|430|430|1|0.2%|0.0%|
[firehol_level2](#firehol_level2)|21182|32799|1|0.0%|0.0%|
[ciarmy](#ciarmy)|457|457|1|0.2%|0.0%|

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
[firehol_level3](#firehol_level3)|109880|9627672|25|0.0%|0.0%|
[firehol_level1](#firehol_level1)|5136|688854491|18|0.0%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|17|0.0%|0.0%|
[sorbs_spam](#sorbs_spam)|64701|65536|17|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|17|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|17|0.0%|0.0%|
[firehol_proxies](#firehol_proxies)|12374|12641|15|0.1%|0.0%|
[firehol_anonymous](#firehol_anonymous)|18927|82965|15|0.0%|0.0%|
[alienvault_reputation](#alienvault_reputation)|188722|188722|15|0.0%|0.0%|
[fullbogons](#fullbogons)|3775|670173256|13|0.0%|0.0%|
[firehol_level2](#firehol_level2)|21182|32799|13|0.0%|0.0%|
[blocklist_de](#blocklist_de)|27522|27522|12|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|11|1.6%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|7|0.0%|0.0%|
[nixspam](#nixspam)|24663|24663|7|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|16621|16621|6|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|5|0.0%|0.0%|
[et_block](#et_block)|1000|18344011|5|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7800|7800|4|0.0%|0.0%|
[xroxy](#xroxy)|2165|2165|3|0.1%|0.0%|
[php_dictionary](#php_dictionary)|737|737|3|0.4%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|3|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2296|2296|3|0.1%|0.0%|
[voipbl](#voipbl)|10533|10945|2|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9945|9945|2|0.0%|0.0%|
[php_harvesters](#php_harvesters)|392|392|2|0.5%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|1418|1418|2|0.1%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2852|2852|2|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14218|14218|2|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6710|6710|1|0.0%|0.0%|
[sorbs_web](#sorbs_web)|531|532|1|0.1%|0.0%|
[proxz](#proxz)|1297|1297|1|0.0%|0.0%|
[php_spammers](#php_spammers)|735|735|1|0.1%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|1|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3334|3334|1|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|2942|2942|1|0.0%|0.0%|

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
[firehol_level3](#firehol_level3)|109880|9627672|9177856|95.3%|100.0%|
[firehol_level1](#firehol_level1)|5136|688854491|7498240|1.0%|81.6%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|6932480|37.7%|75.5%|
[et_block](#et_block)|1000|18344011|6932480|37.7%|75.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|2526625|0.7%|27.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|904796|0.1%|9.8%|
[fullbogons](#fullbogons)|3775|670173256|565760|0.0%|6.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|145472|0.1%|1.5%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1036|0.3%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|725|0.7%|0.0%|
[alienvault_reputation](#alienvault_reputation)|188722|188722|265|0.1%|0.0%|
[dragon_http](#dragon_http)|1029|270336|256|0.0%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|147|0.5%|0.0%|
[firehol_level2](#firehol_level2)|21182|32799|84|0.2%|0.0%|
[blocklist_de](#blocklist_de)|27522|27522|59|0.2%|0.0%|
[nixspam](#nixspam)|24663|24663|57|0.2%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|2942|2942|47|1.5%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6710|6710|31|0.4%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|27|2.0%|0.0%|
[openbl_60d](#openbl_60d)|6989|6989|16|0.2%|0.0%|
[openbl_30d](#openbl_30d)|2813|2813|12|0.4%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9945|9945|11|0.1%|0.0%|
[zeus_badips](#zeus_badips)|202|202|10|4.9%|0.0%|
[zeus](#zeus)|230|230|10|4.3%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|7|0.4%|0.0%|
[firehol_anonymous](#firehol_anonymous)|18927|82965|7|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3334|3334|6|0.1%|0.0%|
[et_compromised](#et_compromised)|1721|1721|5|0.2%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1701|1701|5|0.2%|0.0%|
[php_dictionary](#php_dictionary)|737|737|4|0.5%|0.0%|
[openbl_7d](#openbl_7d)|641|641|4|0.6%|0.0%|
[iw_spamlist](#iw_spamlist)|3772|3772|4|0.1%|0.0%|
[et_tor](#et_tor)|6400|6400|4|0.0%|0.0%|
[dm_tor](#dm_tor)|6490|6490|4|0.0%|0.0%|
[bm_tor](#bm_tor)|6492|6492|4|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|16621|16621|4|0.0%|0.0%|
[shunlist](#shunlist)|1263|1263|3|0.2%|0.0%|
[php_spammers](#php_spammers)|735|735|3|0.4%|0.0%|
[nt_malware_http](#nt_malware_http)|69|69|3|4.3%|0.0%|
[firehol_proxies](#firehol_proxies)|12374|12641|3|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|177|177|3|1.6%|0.0%|
[tor_exits](#tor_exits)|1121|1121|2|0.1%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|2|0.3%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2296|2296|2|0.0%|0.0%|
[voipbl](#voipbl)|10533|10945|1|0.0%|0.0%|
[sorbs_spam](#sorbs_spam)|64701|65536|1|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|1|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|1|0.0%|0.0%|
[php_harvesters](#php_harvesters)|392|392|1|0.2%|0.0%|
[php_commenters](#php_commenters)|430|430|1|0.2%|0.0%|
[openbl_1d](#openbl_1d)|140|140|1|0.7%|0.0%|
[nt_malware_irc](#nt_malware_irc)|43|43|1|2.3%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|1|0.1%|0.0%|
[et_botcc](#et_botcc)|506|506|1|0.1%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|1418|1418|1|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2852|2852|1|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14218|14218|1|0.0%|0.0%|

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
[firehol_level1](#firehol_level1)|5136|688854491|2570306|0.3%|0.3%|
[et_block](#et_block)|1000|18344011|2272548|12.3%|0.2%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|2272265|12.3%|0.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|1354507|0.9%|0.1%|
[firehol_level3](#firehol_level3)|109880|9627672|919969|9.5%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|904796|9.8%|0.1%|
[fullbogons](#fullbogons)|3775|670173256|264873|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|33155|6.8%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|13247|3.9%|0.0%|
[dragon_http](#dragon_http)|1029|270336|6284|2.3%|0.0%|
[alienvault_reputation](#alienvault_reputation)|188722|188722|4448|2.3%|0.0%|
[firehol_anonymous](#firehol_anonymous)|18927|82965|3446|4.1%|0.0%|
[firehol_level2](#firehol_level2)|21182|32799|1705|5.1%|0.0%|
[blocklist_de](#blocklist_de)|27522|27522|1589|5.7%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|1522|1.6%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|16621|16621|1418|8.5%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14218|14218|1323|9.3%|0.0%|
[sorbs_spam](#sorbs_spam)|64701|65536|1208|1.8%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|1205|1.8%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|1205|1.8%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|506|1.7%|0.0%|
[nixspam](#nixspam)|24663|24663|471|1.9%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|394|0.8%|0.0%|
[voipbl](#voipbl)|10533|10945|299|2.7%|0.0%|
[firehol_proxies](#firehol_proxies)|12374|12641|295|2.3%|0.0%|
[dm_tor](#dm_tor)|6490|6490|168|2.5%|0.0%|
[bm_tor](#bm_tor)|6492|6492|167|2.5%|0.0%|
[et_tor](#et_tor)|6400|6400|165|2.5%|0.0%|
[openbl_60d](#openbl_60d)|6989|6989|163|2.3%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7800|7800|156|2.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6710|6710|143|2.1%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9945|9945|114|1.1%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|97|6.6%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2811|2811|86|3.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2296|2296|68|2.9%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|66|5.1%|0.0%|
[openbl_30d](#openbl_30d)|2813|2813|65|2.3%|0.0%|
[iw_spamlist](#iw_spamlist)|3772|3772|65|1.7%|0.0%|
[xroxy](#xroxy)|2165|2165|58|2.6%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|56|8.4%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3334|3334|56|1.6%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1701|1701|54|3.1%|0.0%|
[et_compromised](#et_compromised)|1721|1721|52|3.0%|0.0%|
[proxz](#proxz)|1297|1297|44|3.3%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|2942|2942|44|1.4%|0.0%|
[et_botcc](#et_botcc)|506|506|40|7.9%|0.0%|
[ciarmy](#ciarmy)|457|457|37|8.0%|0.0%|
[tor_exits](#tor_exits)|1121|1121|36|3.2%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2852|2852|34|1.1%|0.0%|
[proxyrss](#proxyrss)|1373|1373|30|2.1%|0.0%|
[shunlist](#shunlist)|1263|1263|25|1.9%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|1418|1418|25|1.7%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|21|4.0%|0.0%|
[openbl_7d](#openbl_7d)|641|641|15|2.3%|0.0%|
[sorbs_web](#sorbs_web)|531|532|13|2.4%|0.0%|
[php_harvesters](#php_harvesters)|392|392|12|3.0%|0.0%|
[php_dictionary](#php_dictionary)|737|737|12|1.6%|0.0%|
[php_spammers](#php_spammers)|735|735|11|1.4%|0.0%|
[php_commenters](#php_commenters)|430|430|10|2.3%|0.0%|
[malc0de](#malc0de)|276|276|10|3.6%|0.0%|
[zeus](#zeus)|230|230|7|3.0%|0.0%|
[nt_malware_http](#nt_malware_http)|69|69|7|10.1%|0.0%|
[nt_malware_irc](#nt_malware_irc)|43|43|5|11.6%|0.0%|
[bogons](#bogons)|13|592708608|5|0.0%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|84|84|5|5.9%|0.0%|
[zeus_badips](#zeus_badips)|202|202|4|1.9%|0.0%|
[openbl_1d](#openbl_1d)|140|140|4|2.8%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|115|115|4|3.4%|0.0%|
[sslbl](#sslbl)|371|371|3|0.8%|0.0%|
[feodo](#feodo)|105|105|3|2.8%|0.0%|
[iw_wormlist](#iw_wormlist)|33|33|1|3.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|177|177|1|0.5%|0.0%|

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
[firehol_level1](#firehol_level1)|5136|688854491|8867717|1.2%|2.5%|
[et_block](#et_block)|1000|18344011|8532520|46.5%|2.4%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|8532506|46.5%|2.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|2830203|2.0%|0.8%|
[firehol_level3](#firehol_level3)|109880|9627672|2537273|26.3%|0.7%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2526625|27.5%|0.7%|
[fullbogons](#fullbogons)|3775|670173256|252671|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|98904|20.2%|0.0%|
[dragon_http](#dragon_http)|1029|270336|11960|4.4%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|7728|2.2%|0.0%|
[alienvault_reputation](#alienvault_reputation)|188722|188722|7000|3.7%|0.0%|
[firehol_anonymous](#firehol_anonymous)|18927|82965|2897|3.4%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|2476|2.6%|0.0%|
[sorbs_spam](#sorbs_spam)|64701|65536|1740|2.6%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|1736|2.6%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|1736|2.6%|0.0%|
[firehol_level2](#firehol_level2)|21182|32799|1677|5.1%|0.0%|
[blocklist_de](#blocklist_de)|27522|27522|1541|5.5%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|16621|16621|1254|7.5%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14218|14218|1090|7.6%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|768|2.6%|0.0%|
[nixspam](#nixspam)|24663|24663|748|3.0%|0.0%|
[voipbl](#voipbl)|10533|10945|434|3.9%|0.0%|
[firehol_proxies](#firehol_proxies)|12374|12641|394|3.1%|0.0%|
[openbl_60d](#openbl_60d)|6989|6989|319|4.5%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|226|0.4%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7800|7800|223|2.8%|0.0%|
[dm_tor](#dm_tor)|6490|6490|184|2.8%|0.0%|
[bm_tor](#bm_tor)|6492|6492|184|2.8%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6710|6710|182|2.7%|0.0%|
[et_tor](#et_tor)|6400|6400|181|2.8%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9945|9945|147|1.4%|0.0%|
[openbl_30d](#openbl_30d)|2813|2813|146|5.1%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3334|3334|124|3.7%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2811|2811|106|3.7%|0.0%|
[xroxy](#xroxy)|2165|2165|104|4.8%|0.0%|
[iw_spamlist](#iw_spamlist)|3772|3772|93|2.4%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1701|1701|88|5.1%|0.0%|
[et_compromised](#et_compromised)|1721|1721|85|4.9%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|2942|2942|75|2.5%|0.0%|
[shunlist](#shunlist)|1263|1263|69|5.4%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2296|2296|59|2.5%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2852|2852|59|2.0%|0.0%|
[proxyrss](#proxyrss)|1373|1373|54|3.9%|0.0%|
[php_spammers](#php_spammers)|735|735|54|7.3%|0.0%|
[proxz](#proxz)|1297|1297|52|4.0%|0.0%|
[ciarmy](#ciarmy)|457|457|47|10.2%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|45|3.1%|0.0%|
[tor_exits](#tor_exits)|1121|1121|40|3.5%|0.0%|
[openbl_7d](#openbl_7d)|641|641|39|6.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|29|5.5%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|26|2.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|26|3.9%|0.0%|
[php_dictionary](#php_dictionary)|737|737|23|3.1%|0.0%|
[et_botcc](#et_botcc)|506|506|20|3.9%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|1418|1418|20|1.4%|0.0%|
[sorbs_web](#sorbs_web)|531|532|19|3.5%|0.0%|
[php_commenters](#php_commenters)|430|430|18|4.1%|0.0%|
[malc0de](#malc0de)|276|276|16|5.7%|0.0%|
[zeus](#zeus)|230|230|9|3.9%|0.0%|
[php_harvesters](#php_harvesters)|392|392|9|2.2%|0.0%|
[zeus_badips](#zeus_badips)|202|202|8|3.9%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|177|177|8|4.5%|0.0%|
[openbl_1d](#openbl_1d)|140|140|7|5.0%|0.0%|
[sslbl](#sslbl)|371|371|6|1.6%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|115|115|6|5.2%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|84|84|5|5.9%|0.0%|
[palevo](#palevo)|12|12|3|25.0%|0.0%|
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
[firehol_level1](#firehol_level1)|5136|688854491|4637858|0.6%|3.3%|
[fullbogons](#fullbogons)|3775|670173256|4236143|0.6%|3.0%|
[bogons](#bogons)|13|592708608|4194304|0.7%|3.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|2830203|0.8%|2.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|1354507|0.1%|0.9%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|270785|55.5%|0.1%|
[firehol_level3](#firehol_level3)|109880|9627672|161586|1.6%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|145472|1.5%|0.1%|
[et_block](#et_block)|1000|18344011|130394|0.7%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|130368|0.7%|0.0%|
[dragon_http](#dragon_http)|1029|270336|20480|7.5%|0.0%|
[alienvault_reputation](#alienvault_reputation)|188722|188722|14338|7.5%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|9226|2.7%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|5830|6.1%|0.0%|
[firehol_level2](#firehol_level2)|21182|32799|3934|11.9%|0.0%|
[blocklist_de](#blocklist_de)|27522|27522|3519|12.7%|0.0%|
[firehol_anonymous](#firehol_anonymous)|18927|82965|2876|3.4%|0.0%|
[sorbs_spam](#sorbs_spam)|64701|65536|2860|4.3%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|2851|4.3%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|2851|4.3%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|16621|16621|2497|15.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14218|14218|2299|16.1%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|1953|6.6%|0.0%|
[nixspam](#nixspam)|24663|24663|1736|7.0%|0.0%|
[voipbl](#voipbl)|10533|10945|1605|14.6%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|1172|2.4%|0.0%|
[openbl_60d](#openbl_60d)|6989|6989|743|10.6%|0.0%|
[dm_tor](#dm_tor)|6490|6490|630|9.7%|0.0%|
[bm_tor](#bm_tor)|6492|6492|629|9.6%|0.0%|
[et_tor](#et_tor)|6400|6400|625|9.7%|0.0%|
[firehol_proxies](#firehol_proxies)|12374|12641|526|4.1%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6710|6710|517|7.7%|0.0%|
[dshield](#dshield)|20|5120|512|10.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3334|3334|501|15.0%|0.0%|
[openbl_30d](#openbl_30d)|2813|2813|291|10.3%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2296|2296|272|11.8%|0.0%|
[iw_spamlist](#iw_spamlist)|3772|3772|251|6.6%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9945|9945|241|2.4%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7800|7800|220|2.8%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2852|2852|211|7.3%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|2942|2942|161|5.4%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1701|1701|157|9.2%|0.0%|
[et_compromised](#et_compromised)|1721|1721|152|8.8%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|150|28.6%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|147|11.4%|0.0%|
[tor_exits](#tor_exits)|1121|1121|128|11.4%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|1418|1418|122|8.6%|0.0%|
[shunlist](#shunlist)|1263|1263|120|9.5%|0.0%|
[xroxy](#xroxy)|2165|2165|110|5.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|108|7.4%|0.0%|
[proxz](#proxz)|1297|1297|105|8.0%|0.0%|
[ciarmy](#ciarmy)|457|457|100|21.8%|0.0%|
[et_botcc](#et_botcc)|506|506|77|15.2%|0.0%|
[openbl_7d](#openbl_7d)|641|641|66|10.2%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2811|2811|57|2.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|51|7.6%|0.0%|
[proxyrss](#proxyrss)|1373|1373|48|3.4%|0.0%|
[php_spammers](#php_spammers)|735|735|44|5.9%|0.0%|
[malc0de](#malc0de)|276|276|44|15.9%|0.0%|
[php_dictionary](#php_dictionary)|737|737|39|5.2%|0.0%|
[sslbl](#sslbl)|371|371|28|7.5%|0.0%|
[php_commenters](#php_commenters)|430|430|28|6.5%|0.0%|
[sorbs_web](#sorbs_web)|531|532|25|4.6%|0.0%|
[php_harvesters](#php_harvesters)|392|392|20|5.1%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|115|115|20|17.3%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|177|177|16|9.0%|0.0%|
[zeus](#zeus)|230|230|14|6.0%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|84|84|13|15.4%|0.0%|
[feodo](#feodo)|105|105|11|10.4%|0.0%|
[zeus_badips](#zeus_badips)|202|202|10|4.9%|0.0%|
[openbl_1d](#openbl_1d)|140|140|8|5.7%|0.0%|
[nt_malware_http](#nt_malware_http)|69|69|5|7.2%|0.0%|
[sorbs_socks](#sorbs_socks)|7|7|2|28.5%|0.0%|
[sorbs_misc](#sorbs_misc)|7|7|2|28.5%|0.0%|
[sorbs_http](#sorbs_http)|7|7|2|28.5%|0.0%|
[iw_wormlist](#iw_wormlist)|33|33|2|6.0%|0.0%|
[palevo](#palevo)|12|12|1|8.3%|0.0%|
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
[firehol_proxies](#firehol_proxies)|12374|12641|663|5.2%|100.0%|
[firehol_anonymous](#firehol_anonymous)|18927|82965|663|0.7%|100.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|56|0.0%|8.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|51|0.0%|7.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|26|0.0%|3.9%|
[firehol_level3](#firehol_level3)|109880|9627672|25|0.0%|3.7%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|20|0.0%|3.0%|
[ri_web_proxies](#ri_web_proxies)|7800|7800|15|0.1%|2.2%|
[xroxy](#xroxy)|2165|2165|13|0.6%|1.9%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|11|0.0%|1.6%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|11|0.0%|1.6%|
[proxyrss](#proxyrss)|1373|1373|10|0.7%|1.5%|
[firehol_level2](#firehol_level2)|21182|32799|8|0.0%|1.2%|
[ri_connect_proxies](#ri_connect_proxies)|2811|2811|7|0.2%|1.0%|
[proxz](#proxz)|1297|1297|6|0.4%|0.9%|
[stopforumspam_1d](#stopforumspam_1d)|6710|6710|5|0.0%|0.7%|
[blocklist_de](#blocklist_de)|27522|27522|4|0.0%|0.6%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|2|0.0%|0.3%|
[php_dictionary](#php_dictionary)|737|737|2|0.2%|0.3%|
[nixspam](#nixspam)|24663|24663|2|0.0%|0.3%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|2|0.1%|0.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2|0.0%|0.3%|
[firehol_level1](#firehol_level1)|5136|688854491|2|0.0%|0.3%|
[et_block](#et_block)|1000|18344011|2|0.0%|0.3%|
[blocklist_de_mail](#blocklist_de_mail)|16621|16621|2|0.0%|0.3%|
[blocklist_de_bots](#blocklist_de_bots)|2942|2942|2|0.0%|0.3%|
[alienvault_reputation](#alienvault_reputation)|188722|188722|2|0.0%|0.3%|
[sorbs_spam](#sorbs_spam)|64701|65536|1|0.0%|0.1%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|1|0.0%|0.1%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|1|0.0%|0.1%|
[snort_ipfilter](#snort_ipfilter)|9945|9945|1|0.0%|0.1%|
[php_spammers](#php_spammers)|735|735|1|0.1%|0.1%|
[dragon_http](#dragon_http)|1029|270336|1|0.0%|0.1%|

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
[firehol_level3](#firehol_level3)|109880|9627672|339173|3.5%|100.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|13247|0.0%|3.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|9226|0.0%|2.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|7728|0.0%|2.2%|
[firehol_level1](#firehol_level1)|5136|688854491|1932|0.0%|0.5%|
[et_block](#et_block)|1000|18344011|1042|0.0%|0.3%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|1037|0.0%|0.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1036|0.0%|0.3%|
[fullbogons](#fullbogons)|3775|670173256|890|0.0%|0.2%|
[alienvault_reputation](#alienvault_reputation)|188722|188722|291|0.1%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|52|0.0%|0.0%|
[sorbs_spam](#sorbs_spam)|64701|65536|38|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|37|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|37|0.0%|0.0%|
[firehol_anonymous](#firehol_anonymous)|18927|82965|29|0.0%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|27|2.0%|0.0%|
[et_tor](#et_tor)|6400|6400|22|0.3%|0.0%|
[dm_tor](#dm_tor)|6490|6490|22|0.3%|0.0%|
[bm_tor](#bm_tor)|6492|6492|22|0.3%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|20|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|19|1.3%|0.0%|
[nixspam](#nixspam)|24663|24663|18|0.0%|0.0%|
[firehol_level2](#firehol_level2)|21182|32799|17|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9945|9945|14|0.1%|0.0%|
[firehol_proxies](#firehol_proxies)|12374|12641|11|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6710|6710|10|0.1%|0.0%|
[tor_exits](#tor_exits)|1121|1121|8|0.7%|0.0%|
[blocklist_de](#blocklist_de)|27522|27522|7|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7800|7800|6|0.0%|0.0%|
[dragon_http](#dragon_http)|1029|270336|6|0.0%|0.0%|
[openbl_60d](#openbl_60d)|6989|6989|5|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|5|0.9%|0.0%|
[voipbl](#voipbl)|10533|10945|4|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14218|14218|4|0.0%|0.0%|
[openbl_30d](#openbl_30d)|2813|2813|3|0.1%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|3|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2852|2852|3|0.1%|0.0%|
[palevo](#palevo)|12|12|2|16.6%|0.0%|
[malc0de](#malc0de)|276|276|2|0.7%|0.0%|
[iw_spamlist](#iw_spamlist)|3772|3772|2|0.0%|0.0%|
[et_compromised](#et_compromised)|1721|1721|2|0.1%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1701|1701|2|0.1%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|84|84|2|2.3%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|16621|16621|2|0.0%|0.0%|
[zeus_badips](#zeus_badips)|202|202|1|0.4%|0.0%|
[zeus](#zeus)|230|230|1|0.4%|0.0%|
[xroxy](#xroxy)|2165|2165|1|0.0%|0.0%|
[sslbl](#sslbl)|371|371|1|0.2%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|1|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2811|2811|1|0.0%|0.0%|
[proxz](#proxz)|1297|1297|1|0.0%|0.0%|
[proxyrss](#proxyrss)|1373|1373|1|0.0%|0.0%|
[php_harvesters](#php_harvesters)|392|392|1|0.2%|0.0%|
[php_dictionary](#php_dictionary)|737|737|1|0.1%|0.0%|
[php_commenters](#php_commenters)|430|430|1|0.2%|0.0%|
[nt_malware_http](#nt_malware_http)|69|69|1|1.4%|0.0%|
[feodo](#feodo)|105|105|1|0.9%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|115|115|1|0.8%|0.0%|
[bogons](#bogons)|13|592708608|1|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3334|3334|1|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|2942|2942|1|0.0%|0.0%|

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
[firehol_level3](#firehol_level3)|109880|9627672|1450|0.0%|100.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|108|0.0%|7.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|97|0.0%|6.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|45|0.0%|3.1%|
[firehol_level1](#firehol_level1)|5136|688854491|39|0.0%|2.6%|
[fullbogons](#fullbogons)|3775|670173256|33|0.0%|2.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|19|0.0%|1.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|7|0.0%|0.4%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|6|0.0%|0.4%|
[et_block](#et_block)|1000|18344011|6|0.0%|0.4%|
[alienvault_reputation](#alienvault_reputation)|188722|188722|6|0.0%|0.4%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|3|0.2%|0.2%|
[firehol_proxies](#firehol_proxies)|12374|12641|3|0.0%|0.2%|
[firehol_level2](#firehol_level2)|21182|32799|3|0.0%|0.2%|
[firehol_anonymous](#firehol_anonymous)|18927|82965|3|0.0%|0.2%|
[dragon_http](#dragon_http)|1029|270336|3|0.0%|0.2%|
[blocklist_de](#blocklist_de)|27522|27522|3|0.0%|0.2%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|2|0.0%|0.1%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|2|0.0%|0.1%|
[stopforumspam_1d](#stopforumspam_1d)|6710|6710|2|0.0%|0.1%|
[sorbs_spam](#sorbs_spam)|64701|65536|2|0.0%|0.1%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|2|0.0%|0.1%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|2|0.0%|0.1%|
[openbl_60d](#openbl_60d)|6989|6989|2|0.0%|0.1%|
[openbl_30d](#openbl_30d)|2813|2813|2|0.0%|0.1%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|2|0.3%|0.1%|
[blocklist_de_strongips](#blocklist_de_strongips)|177|177|2|1.1%|0.1%|
[blocklist_de_bots](#blocklist_de_bots)|2942|2942|2|0.0%|0.1%|
[snort_ipfilter](#snort_ipfilter)|9945|9945|1|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7800|7800|1|0.0%|0.0%|
[nixspam](#nixspam)|24663|24663|1|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|1|0.0%|0.0%|
[et_botcc](#et_botcc)|506|506|1|0.1%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3334|3334|1|0.0%|0.0%|

## iw_spamlist

[ImproWare Antispam](http://antispam.imp.ch/) IPs sending spam, in the last 3 days

Source is downloaded from [this link](http://antispam.imp.ch/spamlist).

The last time downloaded was found to be dated: Thu Jun 11 14:20:04 UTC 2015.

The ipset `iw_spamlist` has **3772** entries, **3772** unique IPs.

The following table shows the overlaps of `iw_spamlist` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `iw_spamlist`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `iw_spamlist`.
- ` this % ` is the percentage **of this ipset (`iw_spamlist`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[sorbs_spam](#sorbs_spam)|64701|65536|1211|1.8%|32.1%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|1208|1.8%|32.0%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|1208|1.8%|32.0%|
[nixspam](#nixspam)|24663|24663|706|2.8%|18.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|251|0.0%|6.6%|
[firehol_level2](#firehol_level2)|21182|32799|127|0.3%|3.3%|
[blocklist_de](#blocklist_de)|27522|27522|125|0.4%|3.3%|
[blocklist_de_mail](#blocklist_de_mail)|16621|16621|114|0.6%|3.0%|
[firehol_level3](#firehol_level3)|109880|9627672|94|0.0%|2.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|93|0.0%|2.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|65|0.0%|1.7%|
[snort_ipfilter](#snort_ipfilter)|9945|9945|55|0.5%|1.4%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|23|0.0%|0.6%|
[sorbs_web](#sorbs_web)|531|532|23|4.3%|0.6%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|15|0.0%|0.3%|
[firehol_anonymous](#firehol_anonymous)|18927|82965|14|0.0%|0.3%|
[alienvault_reputation](#alienvault_reputation)|188722|188722|14|0.0%|0.3%|
[iw_wormlist](#iw_wormlist)|33|33|13|39.3%|0.3%|
[firehol_proxies](#firehol_proxies)|12374|12641|13|0.1%|0.3%|
[ri_web_proxies](#ri_web_proxies)|7800|7800|11|0.1%|0.2%|
[firehol_level1](#firehol_level1)|5136|688854491|10|0.0%|0.2%|
[php_spammers](#php_spammers)|735|735|9|1.2%|0.2%|
[php_dictionary](#php_dictionary)|737|737|9|1.2%|0.2%|
[stopforumspam_1d](#stopforumspam_1d)|6710|6710|6|0.0%|0.1%|
[fullbogons](#fullbogons)|3775|670173256|5|0.0%|0.1%|
[et_block](#et_block)|1000|18344011|5|0.0%|0.1%|
[bogons](#bogons)|13|592708608|5|0.0%|0.1%|
[blocklist_de_bots](#blocklist_de_bots)|2942|2942|5|0.1%|0.1%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|4|0.0%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|4|0.0%|0.1%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2852|2852|4|0.1%|0.1%|
[blocklist_de_apache](#blocklist_de_apache)|14218|14218|4|0.0%|0.1%|
[php_commenters](#php_commenters)|430|430|3|0.6%|0.0%|
[dragon_http](#dragon_http)|1029|270336|3|0.0%|0.0%|
[xroxy](#xroxy)|2165|2165|2|0.0%|0.0%|
[php_harvesters](#php_harvesters)|392|392|2|0.5%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|2|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|1418|1418|2|0.1%|0.0%|
[zeus_badips](#zeus_badips)|202|202|1|0.4%|0.0%|
[zeus](#zeus)|230|230|1|0.4%|0.0%|
[tor_exits](#tor_exits)|1121|1121|1|0.0%|0.0%|
[sorbs_socks](#sorbs_socks)|7|7|1|14.2%|0.0%|
[sorbs_misc](#sorbs_misc)|7|7|1|14.2%|0.0%|
[sorbs_http](#sorbs_http)|7|7|1|14.2%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2811|2811|1|0.0%|0.0%|
[proxyrss](#proxyrss)|1373|1373|1|0.0%|0.0%|
[et_tor](#et_tor)|6400|6400|1|0.0%|0.0%|
[dm_tor](#dm_tor)|6490|6490|1|0.0%|0.0%|
[bm_tor](#bm_tor)|6492|6492|1|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2296|2296|1|0.0%|0.0%|

## iw_wormlist

[ImproWare Antispam](http://antispam.imp.ch/) IPs sending emails with viruses or worms, in the last 3 days

Source is downloaded from [this link](http://antispam.imp.ch/wormlist).

The last time downloaded was found to be dated: Thu Jun 11 14:20:04 UTC 2015.

The ipset `iw_wormlist` has **33** entries, **33** unique IPs.

The following table shows the overlaps of `iw_wormlist` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `iw_wormlist`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `iw_wormlist`.
- ` this % ` is the percentage **of this ipset (`iw_wormlist`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level3](#firehol_level3)|109880|9627672|33|0.0%|100.0%|
[iw_spamlist](#iw_spamlist)|3772|3772|13|0.3%|39.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|2|0.0%|6.0%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|1|0.0%|3.0%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|1|0.0%|3.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|1|0.0%|3.0%|
[firehol_level2](#firehol_level2)|21182|32799|1|0.0%|3.0%|
[blocklist_de_mail](#blocklist_de_mail)|16621|16621|1|0.0%|3.0%|
[blocklist_de](#blocklist_de)|27522|27522|1|0.0%|3.0%|

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
[firehol_level3](#firehol_level3)|109880|9627672|276|0.0%|100.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|44|0.0%|15.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|16|0.0%|5.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|10|0.0%|3.6%|
[cleanmx_viruses](#cleanmx_viruses)|115|115|9|7.8%|3.2%|
[alienvault_reputation](#alienvault_reputation)|188722|188722|9|0.0%|3.2%|
[firehol_level1](#firehol_level1)|5136|688854491|7|0.0%|2.5%|
[et_block](#et_block)|1000|18344011|5|0.0%|1.8%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|4|0.0%|1.4%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|4|0.3%|1.4%|
[dragon_http](#dragon_http)|1029|270336|3|0.0%|1.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|2|0.0%|0.7%|
[dshield](#dshield)|20|5120|2|0.0%|0.7%|
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
[firehol_level3](#firehol_level3)|109880|9627672|1288|0.0%|100.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|147|0.0%|11.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|66|0.0%|5.1%|
[firehol_level1](#firehol_level1)|5136|688854491|39|0.0%|3.0%|
[et_block](#et_block)|1000|18344011|30|0.0%|2.3%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|29|0.0%|2.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|27|0.0%|2.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|27|0.0%|2.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|26|0.0%|2.0%|
[snort_ipfilter](#snort_ipfilter)|9945|9945|12|0.1%|0.9%|
[fullbogons](#fullbogons)|3775|670173256|9|0.0%|0.6%|
[alienvault_reputation](#alienvault_reputation)|188722|188722|8|0.0%|0.6%|
[malc0de](#malc0de)|276|276|4|1.4%|0.3%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|3|0.0%|0.2%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|3|0.2%|0.2%|
[dragon_http](#dragon_http)|1029|270336|2|0.0%|0.1%|
[zeus](#zeus)|230|230|1|0.4%|0.0%|
[nixspam](#nixspam)|24663|24663|1|0.0%|0.0%|
[et_botcc](#et_botcc)|506|506|1|0.1%|0.0%|

## maxmind_proxy_fraud

[MaxMind.com](https://www.maxmind.com/en/anonymous-proxy-fraudulent-ip-address-list) list of anonymous proxy fraudelent IP addresses.

Source is downloaded from [this link](https://www.maxmind.com/en/anonymous-proxy-fraudulent-ip-address-list).

The last time downloaded was found to be dated: Thu Jun 11 11:09:06 UTC 2015.

The ipset `maxmind_proxy_fraud` has **524** entries, **524** unique IPs.

The following table shows the overlaps of `maxmind_proxy_fraud` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `maxmind_proxy_fraud`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `maxmind_proxy_fraud`.
- ` this % ` is the percentage **of this ipset (`maxmind_proxy_fraud`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_proxies](#firehol_proxies)|12374|12641|524|4.1%|100.0%|
[firehol_anonymous](#firehol_anonymous)|18927|82965|524|0.6%|100.0%|
[firehol_level3](#firehol_level3)|109880|9627672|346|0.0%|66.0%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|345|0.3%|65.8%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|286|0.9%|54.5%|
[snort_ipfilter](#snort_ipfilter)|9945|9945|237|2.3%|45.2%|
[et_tor](#et_tor)|6400|6400|234|3.6%|44.6%|
[bm_tor](#bm_tor)|6492|6492|232|3.5%|44.2%|
[tor_exits](#tor_exits)|1121|1121|231|20.6%|44.0%|
[dm_tor](#dm_tor)|6490|6490|231|3.5%|44.0%|
[firehol_level2](#firehol_level2)|21182|32799|215|0.6%|41.0%|
[stopforumspam_1d](#stopforumspam_1d)|6710|6710|214|3.1%|40.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|150|0.0%|28.6%|
[php_commenters](#php_commenters)|430|430|52|12.0%|9.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|29|0.0%|5.5%|
[alienvault_reputation](#alienvault_reputation)|188722|188722|29|0.0%|5.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|21|0.0%|4.0%|
[openbl_60d](#openbl_60d)|6989|6989|20|0.2%|3.8%|
[ri_web_proxies](#ri_web_proxies)|7800|7800|10|0.1%|1.9%|
[php_harvesters](#php_harvesters)|392|392|7|1.7%|1.3%|
[blocklist_de](#blocklist_de)|27522|27522|7|0.0%|1.3%|
[php_spammers](#php_spammers)|735|735|6|0.8%|1.1%|
[php_dictionary](#php_dictionary)|737|737|5|0.6%|0.9%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|5|0.0%|0.9%|
[blocklist_de_bots](#blocklist_de_bots)|2942|2942|5|0.1%|0.9%|
[dragon_http](#dragon_http)|1029|270336|4|0.0%|0.7%|
[xroxy](#xroxy)|2165|2165|3|0.1%|0.5%|
[voipbl](#voipbl)|10533|10945|2|0.0%|0.3%|
[proxz](#proxz)|1297|1297|2|0.1%|0.3%|
[nixspam](#nixspam)|24663|24663|2|0.0%|0.3%|
[blocklist_de_apache](#blocklist_de_apache)|14218|14218|2|0.0%|0.3%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|1|0.0%|0.1%|
[sorbs_spam](#sorbs_spam)|64701|65536|1|0.0%|0.1%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|1|0.0%|0.1%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|1|0.0%|0.1%|
[shunlist](#shunlist)|1263|1263|1|0.0%|0.1%|
[ri_connect_proxies](#ri_connect_proxies)|2811|2811|1|0.0%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.1%|
[firehol_level1](#firehol_level1)|5136|688854491|1|0.0%|0.1%|
[et_block](#et_block)|1000|18344011|1|0.0%|0.1%|
[blocklist_de_mail](#blocklist_de_mail)|16621|16621|1|0.0%|0.1%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2852|2852|1|0.0%|0.1%|

## nixspam

[NiX Spam](http://www.heise.de/ix/NiX-Spam-DNSBL-and-blacklist-for-download-499637.html) IP addresses that sent spam in the last hour - automatically generated entries without distinguishing open proxies from relays, dialup gateways, and so on. All IPs are removed after 12 hours if there is no spam from there.

Source is downloaded from [this link](http://www.dnsbl.manitu.net/download/nixspam-ip.dump.gz).

The last time downloaded was found to be dated: Thu Jun 11 15:00:02 UTC 2015.

The ipset `nixspam` has **24663** entries, **24663** unique IPs.

The following table shows the overlaps of `nixspam` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `nixspam`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `nixspam`.
- ` this % ` is the percentage **of this ipset (`nixspam`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[sorbs_spam](#sorbs_spam)|64701|65536|4755|7.2%|19.2%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|4652|7.1%|18.8%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|4652|7.1%|18.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|1736|0.0%|7.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|748|0.0%|3.0%|
[firehol_level2](#firehol_level2)|21182|32799|745|2.2%|3.0%|
[blocklist_de](#blocklist_de)|27522|27522|727|2.6%|2.9%|
[iw_spamlist](#iw_spamlist)|3772|3772|706|18.7%|2.8%|
[blocklist_de_mail](#blocklist_de_mail)|16621|16621|664|3.9%|2.6%|
[firehol_level3](#firehol_level3)|109880|9627672|488|0.0%|1.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|471|0.0%|1.9%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|247|0.2%|1.0%|
[snort_ipfilter](#snort_ipfilter)|9945|9945|192|1.9%|0.7%|
[firehol_anonymous](#firehol_anonymous)|18927|82965|190|0.2%|0.7%|
[firehol_proxies](#firehol_proxies)|12374|12641|183|1.4%|0.7%|
[ri_web_proxies](#ri_web_proxies)|7800|7800|136|1.7%|0.5%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|135|0.4%|0.5%|
[php_dictionary](#php_dictionary)|737|737|128|17.3%|0.5%|
[sorbs_web](#sorbs_web)|531|532|109|20.4%|0.4%|
[php_spammers](#php_spammers)|735|735|108|14.6%|0.4%|
[xroxy](#xroxy)|2165|2165|70|3.2%|0.2%|
[stopforumspam_1d](#stopforumspam_1d)|6710|6710|57|0.8%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|57|0.0%|0.2%|
[firehol_level1](#firehol_level1)|5136|688854491|55|0.0%|0.2%|
[et_block](#et_block)|1000|18344011|55|0.0%|0.2%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|54|0.0%|0.2%|
[proxz](#proxz)|1297|1297|45|3.4%|0.1%|
[alienvault_reputation](#alienvault_reputation)|188722|188722|45|0.0%|0.1%|
[blocklist_de_imap](#blocklist_de_imap)|2296|2296|34|1.4%|0.1%|
[blocklist_de_bots](#blocklist_de_bots)|2942|2942|29|0.9%|0.1%|
[dragon_http](#dragon_http)|1029|270336|27|0.0%|0.1%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2852|2852|21|0.7%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14218|14218|21|0.1%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2811|2811|19|0.6%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|18|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|1418|1418|12|0.8%|0.0%|
[php_commenters](#php_commenters)|430|430|11|2.5%|0.0%|
[proxyrss](#proxyrss)|1373|1373|10|0.7%|0.0%|
[php_harvesters](#php_harvesters)|392|392|10|2.5%|0.0%|
[tor_exits](#tor_exits)|1121|1121|8|0.7%|0.0%|
[openbl_60d](#openbl_60d)|6989|6989|7|0.1%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|7|0.0%|0.0%|
[bm_tor](#bm_tor)|6492|6492|7|0.1%|0.0%|
[et_tor](#et_tor)|6400|6400|6|0.0%|0.0%|
[dm_tor](#dm_tor)|6490|6490|6|0.0%|0.0%|
[sorbs_socks](#sorbs_socks)|7|7|5|71.4%|0.0%|
[sorbs_misc](#sorbs_misc)|7|7|5|71.4%|0.0%|
[sorbs_http](#sorbs_http)|7|7|5|71.4%|0.0%|
[openbl_30d](#openbl_30d)|2813|2813|4|0.1%|0.0%|
[voipbl](#voipbl)|10533|10945|2|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|2|0.3%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|2|0.3%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|177|177|2|1.1%|0.0%|
[zeus_badips](#zeus_badips)|202|202|1|0.4%|0.0%|
[zeus](#zeus)|230|230|1|0.4%|0.0%|
[sorbs_smtp](#sorbs_smtp)|5|5|1|20.0%|0.0%|
[openbl_7d](#openbl_7d)|641|641|1|0.1%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|1|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|1|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3334|3334|1|0.0%|0.0%|

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
[firehol_level1](#firehol_level1)|5136|688854491|8|0.0%|11.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|7|0.0%|10.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|5|0.0%|7.2%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|4|0.0%|5.7%|
[fullbogons](#fullbogons)|3775|670173256|4|0.0%|5.7%|
[et_block](#et_block)|1000|18344011|4|0.0%|5.7%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|4.3%|
[firehol_level3](#firehol_level3)|109880|9627672|3|0.0%|4.3%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|2|0.0%|2.8%|
[nt_malware_irc](#nt_malware_irc)|43|43|2|4.6%|2.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|2|0.0%|2.8%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|1.4%|
[alienvault_reputation](#alienvault_reputation)|188722|188722|1|0.0%|1.4%|

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
[firehol_level1](#firehol_level1)|5136|688854491|3|0.0%|6.9%|
[et_block](#et_block)|1000|18344011|3|0.0%|6.9%|
[nt_malware_http](#nt_malware_http)|69|69|2|2.8%|4.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|2|0.0%|4.6%|
[alienvault_reputation](#alienvault_reputation)|188722|188722|2|0.0%|4.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|1|0.0%|2.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|2.3%|
[firehol_level3](#firehol_level3)|109880|9627672|1|0.0%|2.3%|

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

The last time downloaded was found to be dated: Thu Jun 11 14:32:00 UTC 2015.

The ipset `openbl_1d` has **140** entries, **140** unique IPs.

The following table shows the overlaps of `openbl_1d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl_1d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl_1d`.
- ` this % ` is the percentage **of this ipset (`openbl_1d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|21182|32799|140|0.4%|100.0%|
[openbl_60d](#openbl_60d)|6989|6989|139|1.9%|99.2%|
[openbl_7d](#openbl_7d)|641|641|138|21.5%|98.5%|
[openbl_30d](#openbl_30d)|2813|2813|138|4.9%|98.5%|
[firehol_level3](#firehol_level3)|109880|9627672|138|0.0%|98.5%|
[alienvault_reputation](#alienvault_reputation)|188722|188722|136|0.0%|97.1%|
[blocklist_de](#blocklist_de)|27522|27522|128|0.4%|91.4%|
[blocklist_de_ssh](#blocklist_de_ssh)|3334|3334|123|3.6%|87.8%|
[bruteforceblocker](#bruteforceblocker)|1701|1701|77|4.5%|55.0%|
[et_compromised](#et_compromised)|1721|1721|75|4.3%|53.5%|
[shunlist](#shunlist)|1263|1263|74|5.8%|52.8%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|18|0.0%|12.8%|
[firehol_level1](#firehol_level1)|5136|688854491|18|0.0%|12.8%|
[et_block](#et_block)|1000|18344011|18|0.0%|12.8%|
[dshield](#dshield)|20|5120|17|0.3%|12.1%|
[blocklist_de_strongips](#blocklist_de_strongips)|177|177|17|9.6%|12.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|8|0.0%|5.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|7|0.0%|5.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|4|0.0%|2.8%|
[blocklist_de_mail](#blocklist_de_mail)|16621|16621|3|0.0%|2.1%|
[dragon_http](#dragon_http)|1029|270336|2|0.0%|1.4%|
[ciarmy](#ciarmy)|457|457|2|0.4%|1.4%|
[blocklist_de_apache](#blocklist_de_apache)|14218|14218|2|0.0%|1.4%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|1|0.0%|0.7%|
[php_spammers](#php_spammers)|735|735|1|0.1%|0.7%|
[php_commenters](#php_commenters)|430|430|1|0.2%|0.7%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.7%|
[blocklist_de_imap](#blocklist_de_imap)|2296|2296|1|0.0%|0.7%|

## openbl_30d

[OpenBL.org](http://www.openbl.org/) last 30 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.

Source is downloaded from [this link](http://www.openbl.org/lists/base_30days.txt).

The last time downloaded was found to be dated: Thu Jun 11 12:07:00 UTC 2015.

The ipset `openbl_30d` has **2813** entries, **2813** unique IPs.

The following table shows the overlaps of `openbl_30d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl_30d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl_30d`.
- ` this % ` is the percentage **of this ipset (`openbl_30d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[openbl_60d](#openbl_60d)|6989|6989|2813|40.2%|100.0%|
[firehol_level3](#firehol_level3)|109880|9627672|2813|0.0%|100.0%|
[alienvault_reputation](#alienvault_reputation)|188722|188722|2796|1.4%|99.3%|
[et_compromised](#et_compromised)|1721|1721|945|54.9%|33.5%|
[bruteforceblocker](#bruteforceblocker)|1701|1701|907|53.3%|32.2%|
[firehol_level2](#firehol_level2)|21182|32799|720|2.1%|25.5%|
[blocklist_de](#blocklist_de)|27522|27522|708|2.5%|25.1%|
[blocklist_de_ssh](#blocklist_de_ssh)|3334|3334|685|20.5%|24.3%|
[openbl_7d](#openbl_7d)|641|641|641|100.0%|22.7%|
[shunlist](#shunlist)|1263|1263|510|40.3%|18.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|291|0.0%|10.3%|
[et_block](#et_block)|1000|18344011|163|0.0%|5.7%|
[firehol_level1](#firehol_level1)|5136|688854491|155|0.0%|5.5%|
[dragon_http](#dragon_http)|1029|270336|148|0.0%|5.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|146|0.0%|5.1%|
[openbl_1d](#openbl_1d)|140|140|138|98.5%|4.9%|
[dshield](#dshield)|20|5120|136|2.6%|4.8%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|119|0.0%|4.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|65|0.0%|2.3%|
[blocklist_de_strongips](#blocklist_de_strongips)|177|177|24|13.5%|0.8%|
[blocklist_de_mail](#blocklist_de_mail)|16621|16621|15|0.0%|0.5%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|12|0.0%|0.4%|
[blocklist_de_imap](#blocklist_de_imap)|2296|2296|9|0.3%|0.3%|
[blocklist_de_apache](#blocklist_de_apache)|14218|14218|6|0.0%|0.2%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|5|0.0%|0.1%|
[nixspam](#nixspam)|24663|24663|4|0.0%|0.1%|
[voipbl](#voipbl)|10533|10945|3|0.0%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|3|0.0%|0.1%|
[ciarmy](#ciarmy)|457|457|3|0.6%|0.1%|
[zeus](#zeus)|230|230|2|0.8%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9945|9945|2|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|2|0.1%|0.0%|
[zeus_badips](#zeus_badips)|202|202|1|0.4%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|1|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6710|6710|1|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|1|0.0%|0.0%|
[php_spammers](#php_spammers)|735|735|1|0.1%|0.0%|
[php_commenters](#php_commenters)|430|430|1|0.2%|0.0%|
[firehol_anonymous](#firehol_anonymous)|18927|82965|1|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|1418|1418|1|0.0%|0.0%|

## openbl_60d

[OpenBL.org](http://www.openbl.org/) last 60 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.

Source is downloaded from [this link](http://www.openbl.org/lists/base_60days.txt).

The last time downloaded was found to be dated: Thu Jun 11 12:07:00 UTC 2015.

The ipset `openbl_60d` has **6989** entries, **6989** unique IPs.

The following table shows the overlaps of `openbl_60d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl_60d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl_60d`.
- ` this % ` is the percentage **of this ipset (`openbl_60d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[alienvault_reputation](#alienvault_reputation)|188722|188722|6967|3.6%|99.6%|
[firehol_level3](#firehol_level3)|109880|9627672|2941|0.0%|42.0%|
[openbl_30d](#openbl_30d)|2813|2813|2813|100.0%|40.2%|
[et_compromised](#et_compromised)|1721|1721|1014|58.9%|14.5%|
[bruteforceblocker](#bruteforceblocker)|1701|1701|968|56.9%|13.8%|
[firehol_level2](#firehol_level2)|21182|32799|917|2.7%|13.1%|
[blocklist_de](#blocklist_de)|27522|27522|886|3.2%|12.6%|
[blocklist_de_ssh](#blocklist_de_ssh)|3334|3334|853|25.5%|12.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|743|0.0%|10.6%|
[openbl_7d](#openbl_7d)|641|641|641|100.0%|9.1%|
[shunlist](#shunlist)|1263|1263|541|42.8%|7.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|319|0.0%|4.5%|
[et_block](#et_block)|1000|18344011|300|0.0%|4.2%|
[firehol_level1](#firehol_level1)|5136|688854491|284|0.0%|4.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|235|0.0%|3.3%|
[dragon_http](#dragon_http)|1029|270336|218|0.0%|3.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|163|0.0%|2.3%|
[dshield](#dshield)|20|5120|151|2.9%|2.1%|
[openbl_1d](#openbl_1d)|140|140|139|99.2%|1.9%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|47|0.0%|0.6%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|27|0.0%|0.3%|
[blocklist_de_strongips](#blocklist_de_strongips)|177|177|25|14.1%|0.3%|
[snort_ipfilter](#snort_ipfilter)|9945|9945|24|0.2%|0.3%|
[firehol_anonymous](#firehol_anonymous)|18927|82965|23|0.0%|0.3%|
[blocklist_de_mail](#blocklist_de_mail)|16621|16621|23|0.1%|0.3%|
[tor_exits](#tor_exits)|1121|1121|20|1.7%|0.2%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|20|3.8%|0.2%|
[firehol_proxies](#firehol_proxies)|12374|12641|20|0.1%|0.2%|
[et_tor](#et_tor)|6400|6400|20|0.3%|0.2%|
[dm_tor](#dm_tor)|6490|6490|20|0.3%|0.2%|
[bm_tor](#bm_tor)|6492|6492|20|0.3%|0.2%|
[stopforumspam_1d](#stopforumspam_1d)|6710|6710|19|0.2%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|16|0.0%|0.2%|
[blocklist_de_imap](#blocklist_de_imap)|2296|2296|16|0.6%|0.2%|
[php_commenters](#php_commenters)|430|430|11|2.5%|0.1%|
[voipbl](#voipbl)|10533|10945|8|0.0%|0.1%|
[nixspam](#nixspam)|24663|24663|7|0.0%|0.1%|
[blocklist_de_apache](#blocklist_de_apache)|14218|14218|7|0.0%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|5|0.0%|0.0%|
[ciarmy](#ciarmy)|457|457|3|0.6%|0.0%|
[zeus](#zeus)|230|230|2|0.8%|0.0%|
[sorbs_spam](#sorbs_spam)|64701|65536|2|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|2|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|2|0.0%|0.0%|
[php_harvesters](#php_harvesters)|392|392|2|0.5%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|2|0.1%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|1418|1418|2|0.1%|0.0%|
[zeus_badips](#zeus_badips)|202|202|1|0.4%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|1|0.0%|0.0%|
[php_spammers](#php_spammers)|735|735|1|0.1%|0.0%|

## openbl_7d

[OpenBL.org](http://www.openbl.org/) last 7 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.

Source is downloaded from [this link](http://www.openbl.org/lists/base_7days.txt).

The last time downloaded was found to be dated: Thu Jun 11 12:07:00 UTC 2015.

The ipset `openbl_7d` has **641** entries, **641** unique IPs.

The following table shows the overlaps of `openbl_7d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl_7d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl_7d`.
- ` this % ` is the percentage **of this ipset (`openbl_7d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[openbl_60d](#openbl_60d)|6989|6989|641|9.1%|100.0%|
[openbl_30d](#openbl_30d)|2813|2813|641|22.7%|100.0%|
[firehol_level3](#firehol_level3)|109880|9627672|641|0.0%|100.0%|
[alienvault_reputation](#alienvault_reputation)|188722|188722|637|0.3%|99.3%|
[firehol_level2](#firehol_level2)|21182|32799|401|1.2%|62.5%|
[blocklist_de](#blocklist_de)|27522|27522|390|1.4%|60.8%|
[blocklist_de_ssh](#blocklist_de_ssh)|3334|3334|375|11.2%|58.5%|
[et_compromised](#et_compromised)|1721|1721|313|18.1%|48.8%|
[bruteforceblocker](#bruteforceblocker)|1701|1701|310|18.2%|48.3%|
[shunlist](#shunlist)|1263|1263|212|16.7%|33.0%|
[openbl_1d](#openbl_1d)|140|140|138|98.5%|21.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|66|0.0%|10.2%|
[et_block](#et_block)|1000|18344011|61|0.0%|9.5%|
[firehol_level1](#firehol_level1)|5136|688854491|56|0.0%|8.7%|
[dragon_http](#dragon_http)|1029|270336|54|0.0%|8.4%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|52|0.0%|8.1%|
[dshield](#dshield)|20|5120|50|0.9%|7.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|39|0.0%|6.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|177|177|23|12.9%|3.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|15|0.0%|2.3%|
[blocklist_de_mail](#blocklist_de_mail)|16621|16621|9|0.0%|1.4%|
[blocklist_de_imap](#blocklist_de_imap)|2296|2296|7|0.3%|1.0%|
[blocklist_de_apache](#blocklist_de_apache)|14218|14218|5|0.0%|0.7%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|4|0.0%|0.6%|
[ciarmy](#ciarmy)|457|457|3|0.6%|0.4%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|2|0.0%|0.3%|
[zeus_badips](#zeus_badips)|202|202|1|0.4%|0.1%|
[zeus](#zeus)|230|230|1|0.4%|0.1%|
[snort_ipfilter](#snort_ipfilter)|9945|9945|1|0.0%|0.1%|
[php_spammers](#php_spammers)|735|735|1|0.1%|0.1%|
[php_commenters](#php_commenters)|430|430|1|0.2%|0.1%|
[nixspam](#nixspam)|24663|24663|1|0.0%|0.1%|
[blocklist_de_ftp](#blocklist_de_ftp)|1418|1418|1|0.0%|0.1%|

## palevo

[Abuse.ch Palevo tracker](https://palevotracker.abuse.ch) worm includes IPs which are being used as botnet C&C for the Palevo crimeware - **excellent list**

Source is downloaded from [this link](https://palevotracker.abuse.ch/blocklists.php?download=ipblocklist).

The last time downloaded was found to be dated: Thu Jun 11 14:45:10 UTC 2015.

The ipset `palevo` has **12** entries, **12** unique IPs.

The following table shows the overlaps of `palevo` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `palevo`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `palevo`.
- ` this % ` is the percentage **of this ipset (`palevo`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level1](#firehol_level1)|5136|688854491|12|0.0%|100.0%|
[et_block](#et_block)|1000|18344011|12|0.0%|100.0%|
[snort_ipfilter](#snort_ipfilter)|9945|9945|10|0.1%|83.3%|
[firehol_level3](#firehol_level3)|109880|9627672|10|0.0%|83.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|3|0.0%|25.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|2|0.0%|16.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|1|0.0%|8.3%|

## php_commenters

[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) comment spammers (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=c&rss=1).

The last time downloaded was found to be dated: Thu Jun 11 14:45:22 UTC 2015.

The ipset `php_commenters` has **430** entries, **430** unique IPs.

The following table shows the overlaps of `php_commenters` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `php_commenters`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `php_commenters`.
- ` this % ` is the percentage **of this ipset (`php_commenters`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level3](#firehol_level3)|109880|9627672|430|0.0%|100.0%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|321|0.3%|74.6%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|240|0.8%|55.8%|
[firehol_level2](#firehol_level2)|21182|32799|189|0.5%|43.9%|
[stopforumspam_1d](#stopforumspam_1d)|6710|6710|164|2.4%|38.1%|
[blocklist_de](#blocklist_de)|27522|27522|102|0.3%|23.7%|
[firehol_anonymous](#firehol_anonymous)|18927|82965|81|0.0%|18.8%|
[blocklist_de_bots](#blocklist_de_bots)|2942|2942|81|2.7%|18.8%|
[firehol_proxies](#firehol_proxies)|12374|12641|79|0.6%|18.3%|
[snort_ipfilter](#snort_ipfilter)|9945|9945|64|0.6%|14.8%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|52|9.9%|12.0%|
[tor_exits](#tor_exits)|1121|1121|51|4.5%|11.8%|
[et_tor](#et_tor)|6400|6400|51|0.7%|11.8%|
[dm_tor](#dm_tor)|6490|6490|51|0.7%|11.8%|
[bm_tor](#bm_tor)|6492|6492|51|0.7%|11.8%|
[php_spammers](#php_spammers)|735|735|50|6.8%|11.6%|
[blocklist_de_strongips](#blocklist_de_strongips)|177|177|46|25.9%|10.6%|
[firehol_level1](#firehol_level1)|5136|688854491|38|0.0%|8.8%|
[php_dictionary](#php_dictionary)|737|737|34|4.6%|7.9%|
[blocklist_de_apache](#blocklist_de_apache)|14218|14218|31|0.2%|7.2%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|29|0.0%|6.7%|
[et_block](#et_block)|1000|18344011|29|0.0%|6.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|28|0.0%|6.5%|
[blocklist_de_mail](#blocklist_de_mail)|16621|16621|27|0.1%|6.2%|
[ri_web_proxies](#ri_web_proxies)|7800|7800|25|0.3%|5.8%|
[sorbs_spam](#sorbs_spam)|64701|65536|22|0.0%|5.1%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|22|0.0%|5.1%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|22|0.0%|5.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|18|0.0%|4.1%|
[alienvault_reputation](#alienvault_reputation)|188722|188722|18|0.0%|4.1%|
[php_harvesters](#php_harvesters)|392|392|15|3.8%|3.4%|
[openbl_60d](#openbl_60d)|6989|6989|11|0.1%|2.5%|
[nixspam](#nixspam)|24663|24663|11|0.0%|2.5%|
[xroxy](#xroxy)|2165|2165|10|0.4%|2.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|10|0.0%|2.3%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2852|2852|10|0.3%|2.3%|
[proxz](#proxz)|1297|1297|9|0.6%|2.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|8|0.0%|1.8%|
[ri_connect_proxies](#ri_connect_proxies)|2811|2811|5|0.1%|1.1%|
[dragon_http](#dragon_http)|1029|270336|4|0.0%|0.9%|
[iw_spamlist](#iw_spamlist)|3772|3772|3|0.0%|0.6%|
[sorbs_web](#sorbs_web)|531|532|2|0.3%|0.4%|
[zeus_badips](#zeus_badips)|202|202|1|0.4%|0.2%|
[zeus](#zeus)|230|230|1|0.4%|0.2%|
[proxyrss](#proxyrss)|1373|1373|1|0.0%|0.2%|
[openbl_7d](#openbl_7d)|641|641|1|0.1%|0.2%|
[openbl_30d](#openbl_30d)|2813|2813|1|0.0%|0.2%|
[openbl_1d](#openbl_1d)|140|140|1|0.7%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.2%|
[fullbogons](#fullbogons)|3775|670173256|1|0.0%|0.2%|
[et_compromised](#et_compromised)|1721|1721|1|0.0%|0.2%|
[bruteforceblocker](#bruteforceblocker)|1701|1701|1|0.0%|0.2%|
[bogons](#bogons)|13|592708608|1|0.0%|0.2%|
[blocklist_de_ssh](#blocklist_de_ssh)|3334|3334|1|0.0%|0.2%|

## php_dictionary

[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) directory attackers (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=d&rss=1).

The last time downloaded was found to be dated: Thu Jun 11 14:45:22 UTC 2015.

The ipset `php_dictionary` has **737** entries, **737** unique IPs.

The following table shows the overlaps of `php_dictionary` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `php_dictionary`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `php_dictionary`.
- ` this % ` is the percentage **of this ipset (`php_dictionary`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level3](#firehol_level3)|109880|9627672|737|0.0%|100.0%|
[php_spammers](#php_spammers)|735|735|322|43.8%|43.6%|
[sorbs_spam](#sorbs_spam)|64701|65536|214|0.3%|29.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|214|0.3%|29.0%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|214|0.3%|29.0%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|139|0.1%|18.8%|
[nixspam](#nixspam)|24663|24663|128|0.5%|17.3%|
[firehol_level2](#firehol_level2)|21182|32799|128|0.3%|17.3%|
[blocklist_de](#blocklist_de)|27522|27522|123|0.4%|16.6%|
[blocklist_de_mail](#blocklist_de_mail)|16621|16621|101|0.6%|13.7%|
[firehol_anonymous](#firehol_anonymous)|18927|82965|98|0.1%|13.2%|
[firehol_proxies](#firehol_proxies)|12374|12641|97|0.7%|13.1%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|94|0.3%|12.7%|
[snort_ipfilter](#snort_ipfilter)|9945|9945|85|0.8%|11.5%|
[ri_web_proxies](#ri_web_proxies)|7800|7800|67|0.8%|9.0%|
[xroxy](#xroxy)|2165|2165|41|1.8%|5.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|39|0.0%|5.2%|
[php_commenters](#php_commenters)|430|430|34|7.9%|4.6%|
[stopforumspam_1d](#stopforumspam_1d)|6710|6710|33|0.4%|4.4%|
[sorbs_web](#sorbs_web)|531|532|30|5.6%|4.0%|
[proxz](#proxz)|1297|1297|25|1.9%|3.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|23|0.0%|3.1%|
[blocklist_de_bots](#blocklist_de_bots)|2942|2942|18|0.6%|2.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|12|0.0%|1.6%|
[iw_spamlist](#iw_spamlist)|3772|3772|9|0.2%|1.2%|
[alienvault_reputation](#alienvault_reputation)|188722|188722|7|0.0%|0.9%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|6|0.0%|0.8%|
[firehol_level1](#firehol_level1)|5136|688854491|6|0.0%|0.8%|
[et_block](#et_block)|1000|18344011|6|0.0%|0.8%|
[ri_connect_proxies](#ri_connect_proxies)|2811|2811|5|0.1%|0.6%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|5|0.9%|0.6%|
[blocklist_de_strongips](#blocklist_de_strongips)|177|177|5|2.8%|0.6%|
[tor_exits](#tor_exits)|1121|1121|4|0.3%|0.5%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|4|0.0%|0.5%|
[et_tor](#et_tor)|6400|6400|4|0.0%|0.5%|
[dm_tor](#dm_tor)|6490|6490|4|0.0%|0.5%|
[bm_tor](#bm_tor)|6492|6492|4|0.0%|0.5%|
[php_harvesters](#php_harvesters)|392|392|3|0.7%|0.4%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|3|0.0%|0.4%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2852|2852|3|0.1%|0.4%|
[blocklist_de_apache](#blocklist_de_apache)|14218|14218|3|0.0%|0.4%|
[proxyrss](#proxyrss)|1373|1373|2|0.1%|0.2%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|2|0.3%|0.2%|
[dragon_http](#dragon_http)|1029|270336|2|0.0%|0.2%|
[sorbs_socks](#sorbs_socks)|7|7|1|14.2%|0.1%|
[sorbs_misc](#sorbs_misc)|7|7|1|14.2%|0.1%|
[sorbs_http](#sorbs_http)|7|7|1|14.2%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.1%|
[blocklist_de_ftp](#blocklist_de_ftp)|1418|1418|1|0.0%|0.1%|

## php_harvesters

[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) harvesters (IPs that surf the internet looking for email addresses) (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=h&rss=1).

The last time downloaded was found to be dated: Thu Jun 11 14:45:20 UTC 2015.

The ipset `php_harvesters` has **392** entries, **392** unique IPs.

The following table shows the overlaps of `php_harvesters` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `php_harvesters`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `php_harvesters`.
- ` this % ` is the percentage **of this ipset (`php_harvesters`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level3](#firehol_level3)|109880|9627672|392|0.0%|100.0%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|86|0.0%|21.9%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|61|0.2%|15.5%|
[firehol_level2](#firehol_level2)|21182|32799|59|0.1%|15.0%|
[stopforumspam_1d](#stopforumspam_1d)|6710|6710|44|0.6%|11.2%|
[blocklist_de](#blocklist_de)|27522|27522|40|0.1%|10.2%|
[blocklist_de_bots](#blocklist_de_bots)|2942|2942|28|0.9%|7.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|20|0.0%|5.1%|
[php_commenters](#php_commenters)|430|430|15|3.4%|3.8%|
[sorbs_spam](#sorbs_spam)|64701|65536|14|0.0%|3.5%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|14|0.0%|3.5%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|14|0.0%|3.5%|
[snort_ipfilter](#snort_ipfilter)|9945|9945|12|0.1%|3.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|12|0.0%|3.0%|
[firehol_proxies](#firehol_proxies)|12374|12641|12|0.0%|3.0%|
[firehol_anonymous](#firehol_anonymous)|18927|82965|12|0.0%|3.0%|
[alienvault_reputation](#alienvault_reputation)|188722|188722|12|0.0%|3.0%|
[nixspam](#nixspam)|24663|24663|10|0.0%|2.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|9|0.0%|2.2%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|7|1.3%|1.7%|
[et_tor](#et_tor)|6400|6400|7|0.1%|1.7%|
[dm_tor](#dm_tor)|6490|6490|7|0.1%|1.7%|
[bm_tor](#bm_tor)|6492|6492|7|0.1%|1.7%|
[tor_exits](#tor_exits)|1121|1121|6|0.5%|1.5%|
[blocklist_de_mail](#blocklist_de_mail)|16621|16621|6|0.0%|1.5%|
[blocklist_de_ftp](#blocklist_de_ftp)|1418|1418|4|0.2%|1.0%|
[php_spammers](#php_spammers)|735|735|3|0.4%|0.7%|
[php_dictionary](#php_dictionary)|737|737|3|0.4%|0.7%|
[firehol_level1](#firehol_level1)|5136|688854491|3|0.0%|0.7%|
[blocklist_de_strongips](#blocklist_de_strongips)|177|177|3|1.6%|0.7%|
[xroxy](#xroxy)|2165|2165|2|0.0%|0.5%|
[ri_web_proxies](#ri_web_proxies)|7800|7800|2|0.0%|0.5%|
[openbl_60d](#openbl_60d)|6989|6989|2|0.0%|0.5%|
[iw_spamlist](#iw_spamlist)|3772|3772|2|0.0%|0.5%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|2|0.0%|0.5%|
[blocklist_de_imap](#blocklist_de_imap)|2296|2296|2|0.0%|0.5%|
[blocklist_de_apache](#blocklist_de_apache)|14218|14218|2|0.0%|0.5%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|1|0.0%|0.2%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|1|0.0%|0.2%|
[ri_connect_proxies](#ri_connect_proxies)|2811|2811|1|0.0%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.2%|
[fullbogons](#fullbogons)|3775|670173256|1|0.0%|0.2%|
[et_block](#et_block)|1000|18344011|1|0.0%|0.2%|
[bogons](#bogons)|13|592708608|1|0.0%|0.2%|
[blocklist_de_ssh](#blocklist_de_ssh)|3334|3334|1|0.0%|0.2%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2852|2852|1|0.0%|0.2%|

## php_spammers

[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) spam servers (IPs used by spammers to send messages) (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=s&rss=1).

The last time downloaded was found to be dated: Thu Jun 11 14:45:21 UTC 2015.

The ipset `php_spammers` has **735** entries, **735** unique IPs.

The following table shows the overlaps of `php_spammers` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `php_spammers`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `php_spammers`.
- ` this % ` is the percentage **of this ipset (`php_spammers`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level3](#firehol_level3)|109880|9627672|735|0.0%|100.0%|
[php_dictionary](#php_dictionary)|737|737|322|43.6%|43.8%|
[sorbs_spam](#sorbs_spam)|64701|65536|184|0.2%|25.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|184|0.2%|25.0%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|184|0.2%|25.0%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|151|0.1%|20.5%|
[firehol_level2](#firehol_level2)|21182|32799|120|0.3%|16.3%|
[blocklist_de](#blocklist_de)|27522|27522|110|0.3%|14.9%|
[nixspam](#nixspam)|24663|24663|108|0.4%|14.6%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|95|0.3%|12.9%|
[firehol_anonymous](#firehol_anonymous)|18927|82965|81|0.0%|11.0%|
[snort_ipfilter](#snort_ipfilter)|9945|9945|80|0.8%|10.8%|
[firehol_proxies](#firehol_proxies)|12374|12641|79|0.6%|10.7%|
[blocklist_de_mail](#blocklist_de_mail)|16621|16621|78|0.4%|10.6%|
[ri_web_proxies](#ri_web_proxies)|7800|7800|54|0.6%|7.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|54|0.0%|7.3%|
[php_commenters](#php_commenters)|430|430|50|11.6%|6.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|44|0.0%|5.9%|
[stopforumspam_1d](#stopforumspam_1d)|6710|6710|41|0.6%|5.5%|
[xroxy](#xroxy)|2165|2165|34|1.5%|4.6%|
[sorbs_web](#sorbs_web)|531|532|25|4.6%|3.4%|
[blocklist_de_bots](#blocklist_de_bots)|2942|2942|24|0.8%|3.2%|
[proxz](#proxz)|1297|1297|22|1.6%|2.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|11|0.0%|1.4%|
[blocklist_de_strongips](#blocklist_de_strongips)|177|177|10|5.6%|1.3%|
[iw_spamlist](#iw_spamlist)|3772|3772|9|0.2%|1.2%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|6|1.1%|0.8%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2852|2852|6|0.2%|0.8%|
[blocklist_de_apache](#blocklist_de_apache)|14218|14218|6|0.0%|0.8%|
[tor_exits](#tor_exits)|1121|1121|5|0.4%|0.6%|
[et_tor](#et_tor)|6400|6400|5|0.0%|0.6%|
[dm_tor](#dm_tor)|6490|6490|5|0.0%|0.6%|
[bm_tor](#bm_tor)|6492|6492|5|0.0%|0.6%|
[alienvault_reputation](#alienvault_reputation)|188722|188722|5|0.0%|0.6%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|4|0.0%|0.5%|
[firehol_level1](#firehol_level1)|5136|688854491|4|0.0%|0.5%|
[et_block](#et_block)|1000|18344011|4|0.0%|0.5%|
[ri_connect_proxies](#ri_connect_proxies)|2811|2811|3|0.1%|0.4%|
[php_harvesters](#php_harvesters)|392|392|3|0.7%|0.4%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|0.4%|
[proxyrss](#proxyrss)|1373|1373|1|0.0%|0.1%|
[openbl_7d](#openbl_7d)|641|641|1|0.1%|0.1%|
[openbl_60d](#openbl_60d)|6989|6989|1|0.0%|0.1%|
[openbl_30d](#openbl_30d)|2813|2813|1|0.0%|0.1%|
[openbl_1d](#openbl_1d)|140|140|1|0.7%|0.1%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|1|0.1%|0.1%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|1|0.0%|0.1%|
[et_compromised](#et_compromised)|1721|1721|1|0.0%|0.1%|
[bruteforceblocker](#bruteforceblocker)|1701|1701|1|0.0%|0.1%|
[blocklist_de_ssh](#blocklist_de_ssh)|3334|3334|1|0.0%|0.1%|
[blocklist_de_ftp](#blocklist_de_ftp)|1418|1418|1|0.0%|0.1%|

## proxyrss

[proxyrss.com](http://www.proxyrss.com) open proxies syndicated from multiple sources.

Source is downloaded from [this link](http://www.proxyrss.com/proxylists/all.gz).

The last time downloaded was found to be dated: Thu Jun 11 14:31:24 UTC 2015.

The ipset `proxyrss` has **1373** entries, **1373** unique IPs.

The following table shows the overlaps of `proxyrss` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `proxyrss`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `proxyrss`.
- ` this % ` is the percentage **of this ipset (`proxyrss`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_proxies](#firehol_proxies)|12374|12641|1373|10.8%|100.0%|
[firehol_anonymous](#firehol_anonymous)|18927|82965|1373|1.6%|100.0%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|683|0.7%|49.7%|
[firehol_level3](#firehol_level3)|109880|9627672|683|0.0%|49.7%|
[ri_web_proxies](#ri_web_proxies)|7800|7800|605|7.7%|44.0%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|497|1.7%|36.1%|
[firehol_level2](#firehol_level2)|21182|32799|364|1.1%|26.5%|
[xroxy](#xroxy)|2165|2165|333|15.3%|24.2%|
[stopforumspam_1d](#stopforumspam_1d)|6710|6710|311|4.6%|22.6%|
[proxz](#proxz)|1297|1297|288|22.2%|20.9%|
[ri_connect_proxies](#ri_connect_proxies)|2811|2811|198|7.0%|14.4%|
[blocklist_de_bots](#blocklist_de_bots)|2942|2942|196|6.6%|14.2%|
[blocklist_de](#blocklist_de)|27522|27522|196|0.7%|14.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|54|0.0%|3.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|48|0.0%|3.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|30|0.0%|2.1%|
[nixspam](#nixspam)|24663|24663|10|0.0%|0.7%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|10|1.5%|0.7%|
[sorbs_spam](#sorbs_spam)|64701|65536|7|0.0%|0.5%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|7|0.0%|0.5%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|7|0.0%|0.5%|
[blocklist_de_strongips](#blocklist_de_strongips)|177|177|6|3.3%|0.4%|
[snort_ipfilter](#snort_ipfilter)|9945|9945|3|0.0%|0.2%|
[php_dictionary](#php_dictionary)|737|737|2|0.2%|0.1%|
[php_spammers](#php_spammers)|735|735|1|0.1%|0.0%|
[php_commenters](#php_commenters)|430|430|1|0.2%|0.0%|
[iw_spamlist](#iw_spamlist)|3772|3772|1|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.0%|
[dragon_http](#dragon_http)|1029|270336|1|0.0%|0.0%|

## proxz

[proxz.com](http://www.proxz.com) open proxies (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.proxz.com/proxylists.xml).

The last time downloaded was found to be dated: Thu Jun 11 14:31:28 UTC 2015.

The ipset `proxz` has **1297** entries, **1297** unique IPs.

The following table shows the overlaps of `proxz` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `proxz`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `proxz`.
- ` this % ` is the percentage **of this ipset (`proxz`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_proxies](#firehol_proxies)|12374|12641|1297|10.2%|100.0%|
[firehol_anonymous](#firehol_anonymous)|18927|82965|1297|1.5%|100.0%|
[firehol_level3](#firehol_level3)|109880|9627672|772|0.0%|59.5%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|766|0.8%|59.0%|
[ri_web_proxies](#ri_web_proxies)|7800|7800|595|7.6%|45.8%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|495|1.6%|38.1%|
[xroxy](#xroxy)|2165|2165|454|20.9%|35.0%|
[proxyrss](#proxyrss)|1373|1373|288|20.9%|22.2%|
[firehol_level2](#firehol_level2)|21182|32799|280|0.8%|21.5%|
[ri_connect_proxies](#ri_connect_proxies)|2811|2811|225|8.0%|17.3%|
[stopforumspam_1d](#stopforumspam_1d)|6710|6710|193|2.8%|14.8%|
[blocklist_de](#blocklist_de)|27522|27522|184|0.6%|14.1%|
[blocklist_de_bots](#blocklist_de_bots)|2942|2942|154|5.2%|11.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|105|0.0%|8.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|52|0.0%|4.0%|
[nixspam](#nixspam)|24663|24663|45|0.1%|3.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|44|0.0%|3.3%|
[sorbs_spam](#sorbs_spam)|64701|65536|43|0.0%|3.3%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|43|0.0%|3.3%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|43|0.0%|3.3%|
[blocklist_de_mail](#blocklist_de_mail)|16621|16621|30|0.1%|2.3%|
[snort_ipfilter](#snort_ipfilter)|9945|9945|27|0.2%|2.0%|
[php_dictionary](#php_dictionary)|737|737|25|3.3%|1.9%|
[php_spammers](#php_spammers)|735|735|22|2.9%|1.6%|
[php_commenters](#php_commenters)|430|430|9|2.0%|0.6%|
[sorbs_web](#sorbs_web)|531|532|8|1.5%|0.6%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|6|0.9%|0.4%|
[blocklist_de_strongips](#blocklist_de_strongips)|177|177|6|3.3%|0.4%|
[dragon_http](#dragon_http)|1029|270336|4|0.0%|0.3%|
[alienvault_reputation](#alienvault_reputation)|188722|188722|3|0.0%|0.2%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|2|0.3%|0.1%|
[et_compromised](#et_compromised)|1721|1721|2|0.1%|0.1%|
[bruteforceblocker](#bruteforceblocker)|1701|1701|2|0.1%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|1|0.0%|0.0%|

## ri_connect_proxies

[rosinstrument.com](http://www.rosinstrument.com) open CONNECT proxies (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://tools.rosinstrument.com/proxy/plab100.xml).

The last time downloaded was found to be dated: Thu Jun 11 14:27:18 UTC 2015.

The ipset `ri_connect_proxies` has **2811** entries, **2811** unique IPs.

The following table shows the overlaps of `ri_connect_proxies` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ri_connect_proxies`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ri_connect_proxies`.
- ` this % ` is the percentage **of this ipset (`ri_connect_proxies`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_proxies](#firehol_proxies)|12374|12641|2811|22.2%|100.0%|
[firehol_anonymous](#firehol_anonymous)|18927|82965|2811|3.3%|100.0%|
[firehol_level3](#firehol_level3)|109880|9627672|1584|0.0%|56.3%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|1583|1.6%|56.3%|
[ri_web_proxies](#ri_web_proxies)|7800|7800|1197|15.3%|42.5%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|561|1.9%|19.9%|
[xroxy](#xroxy)|2165|2165|394|18.1%|14.0%|
[proxz](#proxz)|1297|1297|225|17.3%|8.0%|
[proxyrss](#proxyrss)|1373|1373|198|14.4%|7.0%|
[firehol_level2](#firehol_level2)|21182|32799|151|0.4%|5.3%|
[stopforumspam_1d](#stopforumspam_1d)|6710|6710|112|1.6%|3.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|106|0.0%|3.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|86|0.0%|3.0%|
[blocklist_de](#blocklist_de)|27522|27522|70|0.2%|2.4%|
[blocklist_de_bots](#blocklist_de_bots)|2942|2942|67|2.2%|2.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|57|0.0%|2.0%|
[nixspam](#nixspam)|24663|24663|19|0.0%|0.6%|
[sorbs_spam](#sorbs_spam)|64701|65536|18|0.0%|0.6%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|18|0.0%|0.6%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|18|0.0%|0.6%|
[snort_ipfilter](#snort_ipfilter)|9945|9945|7|0.0%|0.2%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|7|1.0%|0.2%|
[php_dictionary](#php_dictionary)|737|737|5|0.6%|0.1%|
[php_commenters](#php_commenters)|430|430|5|1.1%|0.1%|
[php_spammers](#php_spammers)|735|735|3|0.4%|0.1%|
[dragon_http](#dragon_http)|1029|270336|3|0.0%|0.1%|
[blocklist_de_mail](#blocklist_de_mail)|16621|16621|3|0.0%|0.1%|
[alienvault_reputation](#alienvault_reputation)|188722|188722|3|0.0%|0.1%|
[sorbs_web](#sorbs_web)|531|532|1|0.1%|0.0%|
[php_harvesters](#php_harvesters)|392|392|1|0.2%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|1|0.1%|0.0%|
[iw_spamlist](#iw_spamlist)|3772|3772|1|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.0%|
[dm_tor](#dm_tor)|6490|6490|1|0.0%|0.0%|
[bm_tor](#bm_tor)|6492|6492|1|0.0%|0.0%|

## ri_web_proxies

[rosinstrument.com](http://www.rosinstrument.com) open HTTP proxies (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://tools.rosinstrument.com/proxy/l100.xml).

The last time downloaded was found to be dated: Thu Jun 11 14:27:13 UTC 2015.

The ipset `ri_web_proxies` has **7800** entries, **7800** unique IPs.

The following table shows the overlaps of `ri_web_proxies` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ri_web_proxies`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ri_web_proxies`.
- ` this % ` is the percentage **of this ipset (`ri_web_proxies`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_proxies](#firehol_proxies)|12374|12641|7800|61.7%|100.0%|
[firehol_anonymous](#firehol_anonymous)|18927|82965|7800|9.4%|100.0%|
[firehol_level3](#firehol_level3)|109880|9627672|3725|0.0%|47.7%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|3682|3.9%|47.2%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|1518|5.2%|19.4%|
[ri_connect_proxies](#ri_connect_proxies)|2811|2811|1197|42.5%|15.3%|
[xroxy](#xroxy)|2165|2165|960|44.3%|12.3%|
[firehol_level2](#firehol_level2)|21182|32799|678|2.0%|8.6%|
[proxyrss](#proxyrss)|1373|1373|605|44.0%|7.7%|
[proxz](#proxz)|1297|1297|595|45.8%|7.6%|
[blocklist_de](#blocklist_de)|27522|27522|467|1.6%|5.9%|
[stopforumspam_1d](#stopforumspam_1d)|6710|6710|451|6.7%|5.7%|
[blocklist_de_bots](#blocklist_de_bots)|2942|2942|381|12.9%|4.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|223|0.0%|2.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|220|0.0%|2.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|156|0.0%|2.0%|
[sorbs_spam](#sorbs_spam)|64701|65536|144|0.2%|1.8%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|144|0.2%|1.8%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|144|0.2%|1.8%|
[nixspam](#nixspam)|24663|24663|136|0.5%|1.7%|
[blocklist_de_mail](#blocklist_de_mail)|16621|16621|84|0.5%|1.0%|
[php_dictionary](#php_dictionary)|737|737|67|9.0%|0.8%|
[snort_ipfilter](#snort_ipfilter)|9945|9945|61|0.6%|0.7%|
[php_spammers](#php_spammers)|735|735|54|7.3%|0.6%|
[php_commenters](#php_commenters)|430|430|25|5.8%|0.3%|
[sorbs_web](#sorbs_web)|531|532|18|3.3%|0.2%|
[dragon_http](#dragon_http)|1029|270336|18|0.0%|0.2%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|15|2.2%|0.1%|
[iw_spamlist](#iw_spamlist)|3772|3772|11|0.2%|0.1%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|10|1.9%|0.1%|
[blocklist_de_strongips](#blocklist_de_strongips)|177|177|7|3.9%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|6|0.0%|0.0%|
[dm_tor](#dm_tor)|6490|6490|5|0.0%|0.0%|
[bm_tor](#bm_tor)|6492|6492|5|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|4|0.0%|0.0%|
[et_tor](#et_tor)|6400|6400|4|0.0%|0.0%|
[alienvault_reputation](#alienvault_reputation)|188722|188722|4|0.0%|0.0%|
[php_harvesters](#php_harvesters)|392|392|2|0.5%|0.0%|
[sslbl](#sslbl)|371|371|1|0.2%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|1|0.0%|0.0%|
[firehol_level1](#firehol_level1)|5136|688854491|1|0.0%|0.0%|
[et_compromised](#et_compromised)|1721|1721|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1701|1701|1|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3334|3334|1|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2852|2852|1|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14218|14218|1|0.0%|0.0%|

## shunlist

[AutoShun.org](http://autoshun.org/) IPs identified as hostile by correlating logs from distributed snort installations running the autoshun plugin

Source is downloaded from [this link](http://www.autoshun.org/files/shunlist.csv).

The last time downloaded was found to be dated: Thu Jun 11 11:30:06 UTC 2015.

The ipset `shunlist` has **1263** entries, **1263** unique IPs.

The following table shows the overlaps of `shunlist` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `shunlist`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `shunlist`.
- ` this % ` is the percentage **of this ipset (`shunlist`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level3](#firehol_level3)|109880|9627672|1263|0.0%|100.0%|
[alienvault_reputation](#alienvault_reputation)|188722|188722|1252|0.6%|99.1%|
[openbl_60d](#openbl_60d)|6989|6989|541|7.7%|42.8%|
[openbl_30d](#openbl_30d)|2813|2813|510|18.1%|40.3%|
[et_compromised](#et_compromised)|1721|1721|429|24.9%|33.9%|
[firehol_level2](#firehol_level2)|21182|32799|405|1.2%|32.0%|
[blocklist_de](#blocklist_de)|27522|27522|401|1.4%|31.7%|
[bruteforceblocker](#bruteforceblocker)|1701|1701|393|23.1%|31.1%|
[blocklist_de_ssh](#blocklist_de_ssh)|3334|3334|359|10.7%|28.4%|
[openbl_7d](#openbl_7d)|641|641|212|33.0%|16.7%|
[firehol_level1](#firehol_level1)|5136|688854491|176|0.0%|13.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|120|0.0%|9.5%|
[et_block](#et_block)|1000|18344011|115|0.0%|9.1%|
[dshield](#dshield)|20|5120|113|2.2%|8.9%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|94|0.0%|7.4%|
[openbl_1d](#openbl_1d)|140|140|74|52.8%|5.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|69|0.0%|5.4%|
[sslbl](#sslbl)|371|371|61|16.4%|4.8%|
[dragon_http](#dragon_http)|1029|270336|37|0.0%|2.9%|
[blocklist_de_apache](#blocklist_de_apache)|14218|14218|36|0.2%|2.8%|
[ciarmy](#ciarmy)|457|457|26|5.6%|2.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|25|0.0%|1.9%|
[blocklist_de_strongips](#blocklist_de_strongips)|177|177|19|10.7%|1.5%|
[voipbl](#voipbl)|10533|10945|12|0.1%|0.9%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|4|0.0%|0.3%|
[blocklist_de_mail](#blocklist_de_mail)|16621|16621|4|0.0%|0.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|0.2%|
[blocklist_de_imap](#blocklist_de_imap)|2296|2296|3|0.1%|0.2%|
[stopforumspam_1d](#stopforumspam_1d)|6710|6710|2|0.0%|0.1%|
[sorbs_spam](#sorbs_spam)|64701|65536|2|0.0%|0.1%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|2|0.0%|0.1%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|2|0.0%|0.1%|
[blocklist_de_sip](#blocklist_de_sip)|84|84|2|2.3%|0.1%|
[tor_exits](#tor_exits)|1121|1121|1|0.0%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|1|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9945|9945|1|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|1|0.1%|0.0%|
[firehol_proxies](#firehol_proxies)|12374|12641|1|0.0%|0.0%|
[firehol_anonymous](#firehol_anonymous)|18927|82965|1|0.0%|0.0%|
[et_tor](#et_tor)|6400|6400|1|0.0%|0.0%|
[dm_tor](#dm_tor)|6490|6490|1|0.0%|0.0%|
[bm_tor](#bm_tor)|6492|6492|1|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2852|2852|1|0.0%|0.0%|

## snort_ipfilter

[labs.snort.org](https://labs.snort.org/) supplied IP blacklist (this list seems to be updated frequently, but we found no information about it)

Source is downloaded from [this link](http://labs.snort.org/feeds/ip-filter.blf).

The last time downloaded was found to be dated: Thu Jun 11 04:00:00 UTC 2015.

The ipset `snort_ipfilter` has **9945** entries, **9945** unique IPs.

The following table shows the overlaps of `snort_ipfilter` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `snort_ipfilter`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `snort_ipfilter`.
- ` this % ` is the percentage **of this ipset (`snort_ipfilter`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level3](#firehol_level3)|109880|9627672|9945|0.1%|100.0%|
[firehol_anonymous](#firehol_anonymous)|18927|82965|1224|1.4%|12.3%|
[et_tor](#et_tor)|6400|6400|1089|17.0%|10.9%|
[tor_exits](#tor_exits)|1121|1121|1065|95.0%|10.7%|
[bm_tor](#bm_tor)|6492|6492|1050|16.1%|10.5%|
[dm_tor](#dm_tor)|6490|6490|1042|16.0%|10.4%|
[sorbs_spam](#sorbs_spam)|64701|65536|891|1.3%|8.9%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|891|1.3%|8.9%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|891|1.3%|8.9%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|819|0.8%|8.2%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|677|2.3%|6.8%|
[firehol_level2](#firehol_level2)|21182|32799|557|1.6%|5.6%|
[stopforumspam_1d](#stopforumspam_1d)|6710|6710|380|5.6%|3.8%|
[firehol_proxies](#firehol_proxies)|12374|12641|325|2.5%|3.2%|
[firehol_level1](#firehol_level1)|5136|688854491|299|0.0%|3.0%|
[et_block](#et_block)|1000|18344011|298|0.0%|2.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|241|0.0%|2.4%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|237|45.2%|2.3%|
[blocklist_de](#blocklist_de)|27522|27522|217|0.7%|2.1%|
[zeus](#zeus)|230|230|200|86.9%|2.0%|
[nixspam](#nixspam)|24663|24663|192|0.7%|1.9%|
[zeus_badips](#zeus_badips)|202|202|178|88.1%|1.7%|
[blocklist_de_mail](#blocklist_de_mail)|16621|16621|163|0.9%|1.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|147|0.0%|1.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|114|0.0%|1.1%|
[alienvault_reputation](#alienvault_reputation)|188722|188722|108|0.0%|1.0%|
[php_dictionary](#php_dictionary)|737|737|85|11.5%|0.8%|
[feodo](#feodo)|105|105|83|79.0%|0.8%|
[php_spammers](#php_spammers)|735|735|80|10.8%|0.8%|
[php_commenters](#php_commenters)|430|430|64|14.8%|0.6%|
[ri_web_proxies](#ri_web_proxies)|7800|7800|61|0.7%|0.6%|
[iw_spamlist](#iw_spamlist)|3772|3772|55|1.4%|0.5%|
[sorbs_web](#sorbs_web)|531|532|49|9.2%|0.4%|
[xroxy](#xroxy)|2165|2165|41|1.8%|0.4%|
[blocklist_de_apache](#blocklist_de_apache)|14218|14218|34|0.2%|0.3%|
[sslbl](#sslbl)|371|371|31|8.3%|0.3%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2852|2852|31|1.0%|0.3%|
[proxz](#proxz)|1297|1297|27|2.0%|0.2%|
[openbl_60d](#openbl_60d)|6989|6989|24|0.3%|0.2%|
[blocklist_de_bots](#blocklist_de_bots)|2942|2942|23|0.7%|0.2%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|19|0.0%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|14|0.0%|0.1%|
[php_harvesters](#php_harvesters)|392|392|12|3.0%|0.1%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|12|0.9%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|11|0.0%|0.1%|
[palevo](#palevo)|12|12|10|83.3%|0.1%|
[dragon_http](#dragon_http)|1029|270336|10|0.0%|0.1%|
[ri_connect_proxies](#ri_connect_proxies)|2811|2811|7|0.2%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|6|0.0%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|115|115|4|3.4%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2296|2296|4|0.1%|0.0%|
[proxyrss](#proxyrss)|1373|1373|3|0.2%|0.0%|
[openbl_30d](#openbl_30d)|2813|2813|2|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|2|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|177|177|2|1.1%|0.0%|
[voipbl](#voipbl)|10533|10945|1|0.0%|0.0%|
[sorbs_socks](#sorbs_socks)|7|7|1|14.2%|0.0%|
[sorbs_misc](#sorbs_misc)|7|7|1|14.2%|0.0%|
[sorbs_http](#sorbs_http)|7|7|1|14.2%|0.0%|
[shunlist](#shunlist)|1263|1263|1|0.0%|0.0%|
[openbl_7d](#openbl_7d)|641|641|1|0.1%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|1|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|1|0.1%|0.0%|

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
[nixspam](#nixspam)|24663|24663|5|0.0%|71.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|2|0.0%|28.5%|
[snort_ipfilter](#snort_ipfilter)|9945|9945|1|0.0%|14.2%|
[php_dictionary](#php_dictionary)|737|737|1|0.1%|14.2%|
[iw_spamlist](#iw_spamlist)|3772|3772|1|0.0%|14.2%|
[firehol_level3](#firehol_level3)|109880|9627672|1|0.0%|14.2%|
[firehol_level2](#firehol_level2)|21182|32799|1|0.0%|14.2%|
[blocklist_de_mail](#blocklist_de_mail)|16621|16621|1|0.0%|14.2%|
[blocklist_de](#blocklist_de)|27522|27522|1|0.0%|14.2%|

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
[nixspam](#nixspam)|24663|24663|5|0.0%|71.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|2|0.0%|28.5%|
[snort_ipfilter](#snort_ipfilter)|9945|9945|1|0.0%|14.2%|
[php_dictionary](#php_dictionary)|737|737|1|0.1%|14.2%|
[iw_spamlist](#iw_spamlist)|3772|3772|1|0.0%|14.2%|
[firehol_level3](#firehol_level3)|109880|9627672|1|0.0%|14.2%|
[firehol_level2](#firehol_level2)|21182|32799|1|0.0%|14.2%|
[blocklist_de_mail](#blocklist_de_mail)|16621|16621|1|0.0%|14.2%|
[blocklist_de](#blocklist_de)|27522|27522|1|0.0%|14.2%|

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
[nixspam](#nixspam)|24663|24663|4652|18.8%|7.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|2851|0.0%|4.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|1736|0.0%|2.6%|
[firehol_level2](#firehol_level2)|21182|32799|1348|4.1%|2.0%|
[blocklist_de](#blocklist_de)|27522|27522|1336|4.8%|2.0%|
[firehol_level3](#firehol_level3)|109880|9627672|1301|0.0%|1.9%|
[blocklist_de_mail](#blocklist_de_mail)|16621|16621|1239|7.4%|1.8%|
[iw_spamlist](#iw_spamlist)|3772|3772|1208|32.0%|1.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|1205|0.0%|1.8%|
[snort_ipfilter](#snort_ipfilter)|9945|9945|891|8.9%|1.3%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|320|0.3%|0.4%|
[sorbs_web](#sorbs_web)|531|532|278|52.2%|0.4%|
[php_dictionary](#php_dictionary)|737|737|214|29.0%|0.3%|
[firehol_anonymous](#firehol_anonymous)|18927|82965|201|0.2%|0.3%|
[firehol_proxies](#firehol_proxies)|12374|12641|196|1.5%|0.3%|
[php_spammers](#php_spammers)|735|735|184|25.0%|0.2%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|169|0.5%|0.2%|
[ri_web_proxies](#ri_web_proxies)|7800|7800|144|1.8%|0.2%|
[alienvault_reputation](#alienvault_reputation)|188722|188722|91|0.0%|0.1%|
[xroxy](#xroxy)|2165|2165|76|3.5%|0.1%|
[dragon_http](#dragon_http)|1029|270336|70|0.0%|0.1%|
[stopforumspam_1d](#stopforumspam_1d)|6710|6710|50|0.7%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2852|2852|46|1.6%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14218|14218|46|0.3%|0.0%|
[proxz](#proxz)|1297|1297|43|3.3%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|37|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|2942|2942|30|1.0%|0.0%|
[firehol_level1](#firehol_level1)|5136|688854491|25|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2296|2296|25|1.0%|0.0%|
[php_commenters](#php_commenters)|430|430|22|5.1%|0.0%|
[et_block](#et_block)|1000|18344011|22|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|20|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|20|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2811|2811|18|0.6%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|17|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|1418|1418|16|1.1%|0.0%|
[php_harvesters](#php_harvesters)|392|392|14|3.5%|0.0%|
[sorbs_socks](#sorbs_socks)|7|7|7|100.0%|0.0%|
[sorbs_misc](#sorbs_misc)|7|7|7|100.0%|0.0%|
[sorbs_http](#sorbs_http)|7|7|7|100.0%|0.0%|
[proxyrss](#proxyrss)|1373|1373|7|0.5%|0.0%|
[tor_exits](#tor_exits)|1121|1121|5|0.4%|0.0%|
[sorbs_smtp](#sorbs_smtp)|5|5|5|100.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3334|3334|5|0.1%|0.0%|
[et_tor](#et_tor)|6400|6400|4|0.0%|0.0%|
[dm_tor](#dm_tor)|6490|6490|4|0.0%|0.0%|
[bm_tor](#bm_tor)|6492|6492|4|0.0%|0.0%|
[voipbl](#voipbl)|10533|10945|3|0.0%|0.0%|
[et_compromised](#et_compromised)|1721|1721|3|0.1%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1701|1701|3|0.1%|0.0%|
[shunlist](#shunlist)|1263|1263|2|0.1%|0.0%|
[openbl_60d](#openbl_60d)|6989|6989|2|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|2|0.1%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|177|177|2|1.1%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|1|0.1%|0.0%|
[malc0de](#malc0de)|276|276|1|0.3%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|1|0.1%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.0%|

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
[nixspam](#nixspam)|24663|24663|4652|18.8%|7.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|2851|0.0%|4.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|1736|0.0%|2.6%|
[firehol_level2](#firehol_level2)|21182|32799|1348|4.1%|2.0%|
[blocklist_de](#blocklist_de)|27522|27522|1336|4.8%|2.0%|
[firehol_level3](#firehol_level3)|109880|9627672|1301|0.0%|1.9%|
[blocklist_de_mail](#blocklist_de_mail)|16621|16621|1239|7.4%|1.8%|
[iw_spamlist](#iw_spamlist)|3772|3772|1208|32.0%|1.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|1205|0.0%|1.8%|
[snort_ipfilter](#snort_ipfilter)|9945|9945|891|8.9%|1.3%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|320|0.3%|0.4%|
[sorbs_web](#sorbs_web)|531|532|278|52.2%|0.4%|
[php_dictionary](#php_dictionary)|737|737|214|29.0%|0.3%|
[firehol_anonymous](#firehol_anonymous)|18927|82965|201|0.2%|0.3%|
[firehol_proxies](#firehol_proxies)|12374|12641|196|1.5%|0.3%|
[php_spammers](#php_spammers)|735|735|184|25.0%|0.2%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|169|0.5%|0.2%|
[ri_web_proxies](#ri_web_proxies)|7800|7800|144|1.8%|0.2%|
[alienvault_reputation](#alienvault_reputation)|188722|188722|91|0.0%|0.1%|
[xroxy](#xroxy)|2165|2165|76|3.5%|0.1%|
[dragon_http](#dragon_http)|1029|270336|70|0.0%|0.1%|
[stopforumspam_1d](#stopforumspam_1d)|6710|6710|50|0.7%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2852|2852|46|1.6%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14218|14218|46|0.3%|0.0%|
[proxz](#proxz)|1297|1297|43|3.3%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|37|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|2942|2942|30|1.0%|0.0%|
[firehol_level1](#firehol_level1)|5136|688854491|25|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2296|2296|25|1.0%|0.0%|
[php_commenters](#php_commenters)|430|430|22|5.1%|0.0%|
[et_block](#et_block)|1000|18344011|22|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|20|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|20|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2811|2811|18|0.6%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|17|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|1418|1418|16|1.1%|0.0%|
[php_harvesters](#php_harvesters)|392|392|14|3.5%|0.0%|
[sorbs_socks](#sorbs_socks)|7|7|7|100.0%|0.0%|
[sorbs_misc](#sorbs_misc)|7|7|7|100.0%|0.0%|
[sorbs_http](#sorbs_http)|7|7|7|100.0%|0.0%|
[proxyrss](#proxyrss)|1373|1373|7|0.5%|0.0%|
[tor_exits](#tor_exits)|1121|1121|5|0.4%|0.0%|
[sorbs_smtp](#sorbs_smtp)|5|5|5|100.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3334|3334|5|0.1%|0.0%|
[et_tor](#et_tor)|6400|6400|4|0.0%|0.0%|
[dm_tor](#dm_tor)|6490|6490|4|0.0%|0.0%|
[bm_tor](#bm_tor)|6492|6492|4|0.0%|0.0%|
[voipbl](#voipbl)|10533|10945|3|0.0%|0.0%|
[et_compromised](#et_compromised)|1721|1721|3|0.1%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1701|1701|3|0.1%|0.0%|
[shunlist](#shunlist)|1263|1263|2|0.1%|0.0%|
[openbl_60d](#openbl_60d)|6989|6989|2|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|2|0.1%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|177|177|2|1.1%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|1|0.1%|0.0%|
[malc0de](#malc0de)|276|276|1|0.3%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|1|0.1%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.0%|

## sorbs_smtp

[Sorbs.net](https://www.sorbs.net/) SMTP Open Relays, extracted from deltas.

Source is downloaded from [this link]().

The last time downloaded was found to be dated: Thu Jun 11 15:04:09 UTC 2015.

The ipset `sorbs_smtp` has **5** entries, **5** unique IPs.

The following table shows the overlaps of `sorbs_smtp` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `sorbs_smtp`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `sorbs_smtp`.
- ` this % ` is the percentage **of this ipset (`sorbs_smtp`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|5|0.0%|100.0%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|5|0.0%|100.0%|
[sorbs_spam](#sorbs_spam)|64701|65536|4|0.0%|80.0%|
[nixspam](#nixspam)|24663|24663|1|0.0%|20.0%|

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
[nixspam](#nixspam)|24663|24663|5|0.0%|71.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|2|0.0%|28.5%|
[snort_ipfilter](#snort_ipfilter)|9945|9945|1|0.0%|14.2%|
[php_dictionary](#php_dictionary)|737|737|1|0.1%|14.2%|
[iw_spamlist](#iw_spamlist)|3772|3772|1|0.0%|14.2%|
[firehol_level3](#firehol_level3)|109880|9627672|1|0.0%|14.2%|
[firehol_level2](#firehol_level2)|21182|32799|1|0.0%|14.2%|
[blocklist_de_mail](#blocklist_de_mail)|16621|16621|1|0.0%|14.2%|
[blocklist_de](#blocklist_de)|27522|27522|1|0.0%|14.2%|

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
[nixspam](#nixspam)|24663|24663|4755|19.2%|7.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|2860|0.0%|4.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|1740|0.0%|2.6%|
[firehol_level2](#firehol_level2)|21182|32799|1354|4.1%|2.0%|
[blocklist_de](#blocklist_de)|27522|27522|1342|4.8%|2.0%|
[firehol_level3](#firehol_level3)|109880|9627672|1303|0.0%|1.9%|
[blocklist_de_mail](#blocklist_de_mail)|16621|16621|1245|7.4%|1.8%|
[iw_spamlist](#iw_spamlist)|3772|3772|1211|32.1%|1.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|1208|0.0%|1.8%|
[snort_ipfilter](#snort_ipfilter)|9945|9945|891|8.9%|1.3%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|320|0.3%|0.4%|
[sorbs_web](#sorbs_web)|531|532|278|52.2%|0.4%|
[php_dictionary](#php_dictionary)|737|737|214|29.0%|0.3%|
[firehol_anonymous](#firehol_anonymous)|18927|82965|201|0.2%|0.3%|
[firehol_proxies](#firehol_proxies)|12374|12641|196|1.5%|0.2%|
[php_spammers](#php_spammers)|735|735|184|25.0%|0.2%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|169|0.5%|0.2%|
[ri_web_proxies](#ri_web_proxies)|7800|7800|144|1.8%|0.2%|
[alienvault_reputation](#alienvault_reputation)|188722|188722|91|0.0%|0.1%|
[xroxy](#xroxy)|2165|2165|76|3.5%|0.1%|
[dragon_http](#dragon_http)|1029|270336|71|0.0%|0.1%|
[stopforumspam_1d](#stopforumspam_1d)|6710|6710|50|0.7%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2852|2852|46|1.6%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14218|14218|46|0.3%|0.0%|
[proxz](#proxz)|1297|1297|43|3.3%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|38|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|2942|2942|30|1.0%|0.0%|
[firehol_level1](#firehol_level1)|5136|688854491|25|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2296|2296|25|1.0%|0.0%|
[php_commenters](#php_commenters)|430|430|22|5.1%|0.0%|
[et_block](#et_block)|1000|18344011|22|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|20|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|20|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2811|2811|18|0.6%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|17|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|1418|1418|16|1.1%|0.0%|
[php_harvesters](#php_harvesters)|392|392|14|3.5%|0.0%|
[sorbs_socks](#sorbs_socks)|7|7|7|100.0%|0.0%|
[sorbs_misc](#sorbs_misc)|7|7|7|100.0%|0.0%|
[sorbs_http](#sorbs_http)|7|7|7|100.0%|0.0%|
[proxyrss](#proxyrss)|1373|1373|7|0.5%|0.0%|
[tor_exits](#tor_exits)|1121|1121|5|0.4%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3334|3334|5|0.1%|0.0%|
[sorbs_smtp](#sorbs_smtp)|5|5|4|80.0%|0.0%|
[et_tor](#et_tor)|6400|6400|4|0.0%|0.0%|
[dm_tor](#dm_tor)|6490|6490|4|0.0%|0.0%|
[bm_tor](#bm_tor)|6492|6492|4|0.0%|0.0%|
[voipbl](#voipbl)|10533|10945|3|0.0%|0.0%|
[et_compromised](#et_compromised)|1721|1721|3|0.1%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1701|1701|3|0.1%|0.0%|
[shunlist](#shunlist)|1263|1263|2|0.1%|0.0%|
[openbl_60d](#openbl_60d)|6989|6989|2|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|2|0.1%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|177|177|2|1.1%|0.0%|
[virbl](#virbl)|28|28|1|3.5%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|1|0.1%|0.0%|
[malc0de](#malc0de)|276|276|1|0.3%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|1|0.1%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.0%|

## sorbs_web

[Sorbs.net](https://www.sorbs.net/) WEB exploits, extracted from deltas.

Source is downloaded from [this link]().

The last time downloaded was found to be dated: Thu Jun 11 15:04:09 UTC 2015.

The ipset `sorbs_web` has **531** entries, **532** unique IPs.

The following table shows the overlaps of `sorbs_web` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `sorbs_web`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `sorbs_web`.
- ` this % ` is the percentage **of this ipset (`sorbs_web`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[sorbs_spam](#sorbs_spam)|64701|65536|278|0.4%|52.2%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|278|0.4%|52.2%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|278|0.4%|52.2%|
[nixspam](#nixspam)|24663|24663|109|0.4%|20.4%|
[firehol_level3](#firehol_level3)|109880|9627672|65|0.0%|12.2%|
[firehol_level2](#firehol_level2)|21182|32799|64|0.1%|12.0%|
[blocklist_de](#blocklist_de)|27522|27522|64|0.2%|12.0%|
[blocklist_de_mail](#blocklist_de_mail)|16621|16621|58|0.3%|10.9%|
[snort_ipfilter](#snort_ipfilter)|9945|9945|49|0.4%|9.2%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|40|0.0%|7.5%|
[php_dictionary](#php_dictionary)|737|737|30|4.0%|5.6%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|29|0.0%|5.4%|
[php_spammers](#php_spammers)|735|735|25|3.4%|4.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|25|0.0%|4.6%|
[firehol_proxies](#firehol_proxies)|12374|12641|25|0.1%|4.6%|
[firehol_anonymous](#firehol_anonymous)|18927|82965|25|0.0%|4.6%|
[iw_spamlist](#iw_spamlist)|3772|3772|23|0.6%|4.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|19|0.0%|3.5%|
[ri_web_proxies](#ri_web_proxies)|7800|7800|18|0.2%|3.3%|
[xroxy](#xroxy)|2165|2165|13|0.6%|2.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|13|0.0%|2.4%|
[proxz](#proxz)|1297|1297|8|0.6%|1.5%|
[stopforumspam_1d](#stopforumspam_1d)|6710|6710|7|0.1%|1.3%|
[blocklist_de_bots](#blocklist_de_bots)|2942|2942|5|0.1%|0.9%|
[php_commenters](#php_commenters)|430|430|2|0.4%|0.3%|
[blocklist_de_strongips](#blocklist_de_strongips)|177|177|2|1.1%|0.3%|
[ri_connect_proxies](#ri_connect_proxies)|2811|2811|1|0.0%|0.1%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|1|0.0%|0.1%|
[dragon_http](#dragon_http)|1029|270336|1|0.0%|0.1%|
[blocklist_de_ftp](#blocklist_de_ftp)|1418|1418|1|0.0%|0.1%|
[alienvault_reputation](#alienvault_reputation)|188722|188722|1|0.0%|0.1%|

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
[firehol_level1](#firehol_level1)|5136|688854491|18340608|2.6%|100.0%|
[et_block](#et_block)|1000|18344011|18338560|99.9%|99.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|8532506|2.4%|46.5%|
[firehol_level3](#firehol_level3)|109880|9627672|6933040|72.0%|37.8%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|6932480|75.5%|37.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|2272265|0.2%|12.3%|
[fullbogons](#fullbogons)|3775|670173256|151552|0.0%|0.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|130368|0.0%|0.7%|
[alienvault_reputation](#alienvault_reputation)|188722|188722|1372|0.7%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1037|0.3%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|1014|1.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|512|0.1%|0.0%|
[dshield](#dshield)|20|5120|512|10.0%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|271|0.9%|0.0%|
[firehol_level2](#firehol_level2)|21182|32799|260|0.7%|0.0%|
[dragon_http](#dragon_http)|1029|270336|256|0.0%|0.0%|
[openbl_60d](#openbl_60d)|6989|6989|235|3.3%|0.0%|
[blocklist_de](#blocklist_de)|27522|27522|197|0.7%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3334|3334|120|3.5%|0.0%|
[openbl_30d](#openbl_30d)|2813|2813|119|4.2%|0.0%|
[et_compromised](#et_compromised)|1721|1721|101|5.8%|0.0%|
[shunlist](#shunlist)|1263|1263|94|7.4%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6710|6710|79|1.1%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1701|1701|61|3.5%|0.0%|
[nixspam](#nixspam)|24663|24663|54|0.2%|0.0%|
[openbl_7d](#openbl_7d)|641|641|52|8.1%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|2942|2942|50|1.6%|0.0%|
[php_commenters](#php_commenters)|430|430|29|6.7%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|29|2.2%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|16621|16621|21|0.1%|0.0%|
[sorbs_spam](#sorbs_spam)|64701|65536|20|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|20|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|20|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9945|9945|19|0.1%|0.0%|
[openbl_1d](#openbl_1d)|140|140|18|12.8%|0.0%|
[zeus_badips](#zeus_badips)|202|202|15|7.4%|0.0%|
[zeus](#zeus)|230|230|15|6.5%|0.0%|
[voipbl](#voipbl)|10533|10945|14|0.1%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2296|2296|10|0.4%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|177|177|7|3.9%|0.0%|
[php_dictionary](#php_dictionary)|737|737|6|0.8%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|6|0.4%|0.0%|
[firehol_anonymous](#firehol_anonymous)|18927|82965|6|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|5|0.0%|0.0%|
[php_spammers](#php_spammers)|735|735|4|0.5%|0.0%|
[nt_malware_http](#nt_malware_http)|69|69|4|5.7%|0.0%|
[malc0de](#malc0de)|276|276|4|1.4%|0.0%|
[iw_spamlist](#iw_spamlist)|3772|3772|4|0.1%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2852|2852|4|0.1%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14218|14218|4|0.0%|0.0%|
[nt_malware_irc](#nt_malware_irc)|43|43|3|6.9%|0.0%|
[firehol_proxies](#firehol_proxies)|12374|12641|3|0.0%|0.0%|
[et_tor](#et_tor)|6400|6400|3|0.0%|0.0%|
[dm_tor](#dm_tor)|6490|6490|3|0.0%|0.0%|
[bm_tor](#bm_tor)|6492|6492|3|0.0%|0.0%|
[tor_exits](#tor_exits)|1121|1121|2|0.1%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|2|0.3%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|84|84|2|2.3%|0.0%|
[sslbl](#sslbl)|371|371|1|0.2%|0.0%|
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
[firehol_level1](#firehol_level1)|5136|688854491|487424|0.0%|100.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|270785|0.1%|55.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|98904|0.0%|20.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|33155|0.0%|6.8%|
[et_block](#et_block)|1000|18344011|517|0.0%|0.1%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|512|0.0%|0.1%|
[firehol_level3](#firehol_level3)|109880|9627672|85|0.0%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|75|0.0%|0.0%|
[sorbs_spam](#sorbs_spam)|64701|65536|20|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|20|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|20|0.0%|0.0%|
[alienvault_reputation](#alienvault_reputation)|188722|188722|14|0.0%|0.0%|
[php_commenters](#php_commenters)|430|430|8|1.8%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|7|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9945|9945|6|0.0%|0.0%|
[zeus_badips](#zeus_badips)|202|202|5|2.4%|0.0%|
[zeus](#zeus)|230|230|5|2.1%|0.0%|
[firehol_level2](#firehol_level2)|21182|32799|5|0.0%|0.0%|
[blocklist_de](#blocklist_de)|27522|27522|4|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|177|177|3|1.6%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|2942|2942|3|0.1%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6710|6710|2|0.0%|0.0%|
[php_harvesters](#php_harvesters)|392|392|1|0.2%|0.0%|
[openbl_60d](#openbl_60d)|6989|6989|1|0.0%|0.0%|
[openbl_30d](#openbl_30d)|2813|2813|1|0.0%|0.0%|
[malc0de](#malc0de)|276|276|1|0.3%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14218|14218|1|0.0%|0.0%|

## sslbl

[Abuse.ch SSL Blacklist](https://sslbl.abuse.ch/) bad SSL traffic related to malware or botnet activities - **excellent list**

Source is downloaded from [this link](https://sslbl.abuse.ch/blacklist/sslipblacklist.csv).

The last time downloaded was found to be dated: Thu Jun 11 14:45:06 UTC 2015.

The ipset `sslbl` has **371** entries, **371** unique IPs.

The following table shows the overlaps of `sslbl` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `sslbl`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `sslbl`.
- ` this % ` is the percentage **of this ipset (`sslbl`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level1](#firehol_level1)|5136|688854491|371|0.0%|100.0%|
[firehol_level3](#firehol_level3)|109880|9627672|92|0.0%|24.7%|
[alienvault_reputation](#alienvault_reputation)|188722|188722|65|0.0%|17.5%|
[shunlist](#shunlist)|1263|1263|61|4.8%|16.4%|
[feodo](#feodo)|105|105|38|36.1%|10.2%|
[et_block](#et_block)|1000|18344011|38|0.0%|10.2%|
[snort_ipfilter](#snort_ipfilter)|9945|9945|31|0.3%|8.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|28|0.0%|7.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|6|0.0%|1.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|3|0.0%|0.8%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|1|0.0%|0.2%|
[ri_web_proxies](#ri_web_proxies)|7800|7800|1|0.0%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.2%|
[firehol_proxies](#firehol_proxies)|12374|12641|1|0.0%|0.2%|
[firehol_anonymous](#firehol_anonymous)|18927|82965|1|0.0%|0.2%|
[dragon_http](#dragon_http)|1029|270336|1|0.0%|0.2%|

## stopforumspam_1d

[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers in the last 24 hours - **excellent list**

Source is downloaded from [this link](http://www.stopforumspam.com/downloads/listed_ip_1.zip).

The last time downloaded was found to be dated: Thu Jun 11 15:00:02 UTC 2015.

The ipset `stopforumspam_1d` has **6710** entries, **6710** unique IPs.

The following table shows the overlaps of `stopforumspam_1d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `stopforumspam_1d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `stopforumspam_1d`.
- ` this % ` is the percentage **of this ipset (`stopforumspam_1d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|21182|32799|6710|20.4%|100.0%|
[firehol_level3](#firehol_level3)|109880|9627672|6372|0.0%|94.9%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|6362|6.7%|94.8%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|4849|16.6%|72.2%|
[blocklist_de](#blocklist_de)|27522|27522|1445|5.2%|21.5%|
[blocklist_de_bots](#blocklist_de_bots)|2942|2942|1378|46.8%|20.5%|
[firehol_anonymous](#firehol_anonymous)|18927|82965|987|1.1%|14.7%|
[firehol_proxies](#firehol_proxies)|12374|12641|831|6.5%|12.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|517|0.0%|7.7%|
[ri_web_proxies](#ri_web_proxies)|7800|7800|451|5.7%|6.7%|
[snort_ipfilter](#snort_ipfilter)|9945|9945|380|3.8%|5.6%|
[tor_exits](#tor_exits)|1121|1121|348|31.0%|5.1%|
[bm_tor](#bm_tor)|6492|6492|336|5.1%|5.0%|
[et_tor](#et_tor)|6400|6400|335|5.2%|4.9%|
[dm_tor](#dm_tor)|6490|6490|335|5.1%|4.9%|
[proxyrss](#proxyrss)|1373|1373|311|22.6%|4.6%|
[xroxy](#xroxy)|2165|2165|222|10.2%|3.3%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|214|40.8%|3.1%|
[proxz](#proxz)|1297|1297|193|14.8%|2.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|182|0.0%|2.7%|
[php_commenters](#php_commenters)|430|430|164|38.1%|2.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|143|0.0%|2.1%|
[ri_connect_proxies](#ri_connect_proxies)|2811|2811|112|3.9%|1.6%|
[blocklist_de_strongips](#blocklist_de_strongips)|177|177|105|59.3%|1.5%|
[firehol_level1](#firehol_level1)|5136|688854491|82|0.0%|1.2%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|79|0.0%|1.1%|
[et_block](#et_block)|1000|18344011|79|0.0%|1.1%|
[blocklist_de_apache](#blocklist_de_apache)|14218|14218|68|0.4%|1.0%|
[nixspam](#nixspam)|24663|24663|57|0.2%|0.8%|
[sorbs_spam](#sorbs_spam)|64701|65536|50|0.0%|0.7%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|50|0.0%|0.7%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|50|0.0%|0.7%|
[alienvault_reputation](#alienvault_reputation)|188722|188722|49|0.0%|0.7%|
[php_harvesters](#php_harvesters)|392|392|44|11.2%|0.6%|
[blocklist_de_mail](#blocklist_de_mail)|16621|16621|43|0.2%|0.6%|
[php_spammers](#php_spammers)|735|735|41|5.5%|0.6%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2852|2852|37|1.2%|0.5%|
[php_dictionary](#php_dictionary)|737|737|33|4.4%|0.4%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|31|0.0%|0.4%|
[openbl_60d](#openbl_60d)|6989|6989|19|0.2%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|10|0.0%|0.1%|
[dragon_http](#dragon_http)|1029|270336|10|0.0%|0.1%|
[sorbs_web](#sorbs_web)|531|532|7|1.3%|0.1%|
[iw_spamlist](#iw_spamlist)|3772|3772|6|0.1%|0.0%|
[voipbl](#voipbl)|10533|10945|5|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|5|0.7%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|2|0.0%|0.0%|
[shunlist](#shunlist)|1263|1263|2|0.1%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|2|0.1%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2296|2296|2|0.0%|0.0%|
[zeus_badips](#zeus_badips)|202|202|1|0.4%|0.0%|
[zeus](#zeus)|230|230|1|0.4%|0.0%|
[openbl_30d](#openbl_30d)|2813|2813|1|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|1|0.0%|0.0%|
[fullbogons](#fullbogons)|3775|670173256|1|0.0%|0.0%|
[et_compromised](#et_compromised)|1721|1721|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1701|1701|1|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|1418|1418|1|0.0%|0.0%|

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
[firehol_level3](#firehol_level3)|109880|9627672|94309|0.9%|100.0%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|29184|99.9%|30.9%|
[firehol_level2](#firehol_level2)|21182|32799|7744|23.6%|8.2%|
[stopforumspam_1d](#stopforumspam_1d)|6710|6710|6362|94.8%|6.7%|
[firehol_anonymous](#firehol_anonymous)|18927|82965|6196|7.4%|6.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|5830|0.0%|6.1%|
[firehol_proxies](#firehol_proxies)|12374|12641|5587|44.1%|5.9%|
[ri_web_proxies](#ri_web_proxies)|7800|7800|3682|47.2%|3.9%|
[blocklist_de](#blocklist_de)|27522|27522|2803|10.1%|2.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|2476|0.0%|2.6%|
[blocklist_de_bots](#blocklist_de_bots)|2942|2942|2436|82.8%|2.5%|
[ri_connect_proxies](#ri_connect_proxies)|2811|2811|1583|56.3%|1.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|1522|0.0%|1.6%|
[xroxy](#xroxy)|2165|2165|1283|59.2%|1.3%|
[firehol_level1](#firehol_level1)|5136|688854491|1090|0.0%|1.1%|
[et_block](#et_block)|1000|18344011|1018|0.0%|1.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|1014|0.0%|1.0%|
[snort_ipfilter](#snort_ipfilter)|9945|9945|819|8.2%|0.8%|
[proxz](#proxz)|1297|1297|766|59.0%|0.8%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|725|0.0%|0.7%|
[proxyrss](#proxyrss)|1373|1373|683|49.7%|0.7%|
[et_tor](#et_tor)|6400|6400|653|10.2%|0.6%|
[bm_tor](#bm_tor)|6492|6492|640|9.8%|0.6%|
[dm_tor](#dm_tor)|6490|6490|637|9.8%|0.6%|
[tor_exits](#tor_exits)|1121|1121|634|56.5%|0.6%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|345|65.8%|0.3%|
[php_commenters](#php_commenters)|430|430|321|74.6%|0.3%|
[sorbs_spam](#sorbs_spam)|64701|65536|320|0.4%|0.3%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|320|0.4%|0.3%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|320|0.4%|0.3%|
[blocklist_de_mail](#blocklist_de_mail)|16621|16621|256|1.5%|0.2%|
[nixspam](#nixspam)|24663|24663|247|1.0%|0.2%|
[blocklist_de_apache](#blocklist_de_apache)|14218|14218|206|1.4%|0.2%|
[alienvault_reputation](#alienvault_reputation)|188722|188722|168|0.0%|0.1%|
[php_spammers](#php_spammers)|735|735|151|20.5%|0.1%|
[php_dictionary](#php_dictionary)|737|737|139|18.8%|0.1%|
[blocklist_de_strongips](#blocklist_de_strongips)|177|177|136|76.8%|0.1%|
[dragon_http](#dragon_http)|1029|270336|111|0.0%|0.1%|
[php_harvesters](#php_harvesters)|392|392|86|21.9%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|75|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2852|2852|75|2.6%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|52|0.0%|0.0%|
[openbl_60d](#openbl_60d)|6989|6989|47|0.6%|0.0%|
[sorbs_web](#sorbs_web)|531|532|40|7.5%|0.0%|
[voipbl](#voipbl)|10533|10945|35|0.3%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3334|3334|24|0.7%|0.0%|
[iw_spamlist](#iw_spamlist)|3772|3772|23|0.6%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|20|3.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|17|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|1418|1418|16|1.1%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2296|2296|15|0.6%|0.0%|
[et_compromised](#et_compromised)|1721|1721|10|0.5%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1701|1701|10|0.5%|0.0%|
[openbl_30d](#openbl_30d)|2813|2813|5|0.1%|0.0%|
[shunlist](#shunlist)|1263|1263|4|0.3%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|3|0.2%|0.0%|
[zeus_badips](#zeus_badips)|202|202|2|0.9%|0.0%|
[zeus](#zeus)|230|230|2|0.8%|0.0%|
[openbl_7d](#openbl_7d)|641|641|2|0.3%|0.0%|
[nt_malware_http](#nt_malware_http)|69|69|2|2.8%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|2|0.1%|0.0%|
[fullbogons](#fullbogons)|3775|670173256|2|0.0%|0.0%|
[openbl_1d](#openbl_1d)|140|140|1|0.7%|0.0%|
[iw_wormlist](#iw_wormlist)|33|33|1|3.0%|0.0%|
[ciarmy](#ciarmy)|457|457|1|0.2%|0.0%|

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
[firehol_level3](#firehol_level3)|109880|9627672|29184|0.3%|99.9%|
[firehol_level2](#firehol_level2)|21182|32799|5873|17.9%|20.1%|
[stopforumspam_1d](#stopforumspam_1d)|6710|6710|4849|72.2%|16.6%|
[firehol_anonymous](#firehol_anonymous)|18927|82965|2750|3.3%|9.4%|
[firehol_proxies](#firehol_proxies)|12374|12641|2379|18.8%|8.1%|
[blocklist_de](#blocklist_de)|27522|27522|2296|8.3%|7.8%|
[blocklist_de_bots](#blocklist_de_bots)|2942|2942|2097|71.2%|7.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|1953|0.0%|6.6%|
[ri_web_proxies](#ri_web_proxies)|7800|7800|1518|19.4%|5.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|768|0.0%|2.6%|
[snort_ipfilter](#snort_ipfilter)|9945|9945|677|6.8%|2.3%|
[xroxy](#xroxy)|2165|2165|610|28.1%|2.0%|
[ri_connect_proxies](#ri_connect_proxies)|2811|2811|561|19.9%|1.9%|
[et_tor](#et_tor)|6400|6400|547|8.5%|1.8%|
[tor_exits](#tor_exits)|1121|1121|545|48.6%|1.8%|
[bm_tor](#bm_tor)|6492|6492|532|8.1%|1.8%|
[dm_tor](#dm_tor)|6490|6490|528|8.1%|1.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|506|0.0%|1.7%|
[proxyrss](#proxyrss)|1373|1373|497|36.1%|1.7%|
[proxz](#proxz)|1297|1297|495|38.1%|1.6%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|286|54.5%|0.9%|
[firehol_level1](#firehol_level1)|5136|688854491|278|0.0%|0.9%|
[et_block](#et_block)|1000|18344011|272|0.0%|0.9%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|271|0.0%|0.9%|
[php_commenters](#php_commenters)|430|430|240|55.8%|0.8%|
[sorbs_spam](#sorbs_spam)|64701|65536|169|0.2%|0.5%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|169|0.2%|0.5%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|169|0.2%|0.5%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|147|0.0%|0.5%|
[blocklist_de_mail](#blocklist_de_mail)|16621|16621|145|0.8%|0.4%|
[nixspam](#nixspam)|24663|24663|135|0.5%|0.4%|
[blocklist_de_apache](#blocklist_de_apache)|14218|14218|123|0.8%|0.4%|
[blocklist_de_strongips](#blocklist_de_strongips)|177|177|121|68.3%|0.4%|
[php_spammers](#php_spammers)|735|735|95|12.9%|0.3%|
[php_dictionary](#php_dictionary)|737|737|94|12.7%|0.3%|
[alienvault_reputation](#alienvault_reputation)|188722|188722|89|0.0%|0.3%|
[php_harvesters](#php_harvesters)|392|392|61|15.5%|0.2%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2852|2852|55|1.9%|0.1%|
[dragon_http](#dragon_http)|1029|270336|36|0.0%|0.1%|
[sorbs_web](#sorbs_web)|531|532|29|5.4%|0.0%|
[openbl_60d](#openbl_60d)|6989|6989|27|0.3%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|20|0.0%|0.0%|
[iw_spamlist](#iw_spamlist)|3772|3772|15|0.3%|0.0%|
[voipbl](#voipbl)|10533|10945|14|0.1%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|11|1.6%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|7|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|7|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3334|3334|6|0.1%|0.0%|
[et_compromised](#et_compromised)|1721|1721|5|0.2%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2296|2296|5|0.2%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|1418|1418|5|0.3%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1701|1701|4|0.2%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|2|0.1%|0.0%|
[zeus_badips](#zeus_badips)|202|202|1|0.4%|0.0%|
[zeus](#zeus)|230|230|1|0.4%|0.0%|
[shunlist](#shunlist)|1263|1263|1|0.0%|0.0%|
[openbl_30d](#openbl_30d)|2813|2813|1|0.0%|0.0%|
[iw_wormlist](#iw_wormlist)|33|33|1|3.0%|0.0%|
[fullbogons](#fullbogons)|3775|670173256|1|0.0%|0.0%|

## tor_exits

[TorProject.org](https://www.torproject.org) list of all current TOR exit points (TorDNSEL)

Source is downloaded from [this link](https://check.torproject.org/exit-addresses).

The last time downloaded was found to be dated: Thu Jun 11 14:50:33 UTC 2015.

The ipset `tor_exits` has **1121** entries, **1121** unique IPs.

The following table shows the overlaps of `tor_exits` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `tor_exits`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `tor_exits`.
- ` this % ` is the percentage **of this ipset (`tor_exits`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_anonymous](#firehol_anonymous)|18927|82965|1121|1.3%|100.0%|
[firehol_level3](#firehol_level3)|109880|9627672|1067|0.0%|95.1%|
[snort_ipfilter](#snort_ipfilter)|9945|9945|1065|10.7%|95.0%|
[bm_tor](#bm_tor)|6492|6492|1019|15.6%|90.9%|
[dm_tor](#dm_tor)|6490|6490|1013|15.6%|90.3%|
[et_tor](#et_tor)|6400|6400|970|15.1%|86.5%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|634|0.6%|56.5%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|545|1.8%|48.6%|
[firehol_level2](#firehol_level2)|21182|32799|360|1.0%|32.1%|
[stopforumspam_1d](#stopforumspam_1d)|6710|6710|348|5.1%|31.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|231|44.0%|20.6%|
[firehol_proxies](#firehol_proxies)|12374|12641|231|1.8%|20.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|128|0.0%|11.4%|
[php_commenters](#php_commenters)|430|430|51|11.8%|4.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|40|0.0%|3.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|36|0.0%|3.2%|
[alienvault_reputation](#alienvault_reputation)|188722|188722|30|0.0%|2.6%|
[blocklist_de](#blocklist_de)|27522|27522|24|0.0%|2.1%|
[blocklist_de_apache](#blocklist_de_apache)|14218|14218|23|0.1%|2.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2852|2852|21|0.7%|1.8%|
[openbl_60d](#openbl_60d)|6989|6989|20|0.2%|1.7%|
[nixspam](#nixspam)|24663|24663|8|0.0%|0.7%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|8|0.0%|0.7%|
[php_harvesters](#php_harvesters)|392|392|6|1.5%|0.5%|
[sorbs_spam](#sorbs_spam)|64701|65536|5|0.0%|0.4%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|5|0.0%|0.4%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|5|0.0%|0.4%|
[php_spammers](#php_spammers)|735|735|5|0.6%|0.4%|
[dragon_http](#dragon_http)|1029|270336|5|0.0%|0.4%|
[php_dictionary](#php_dictionary)|737|737|4|0.5%|0.3%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|2|0.0%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2|0.0%|0.1%|
[firehol_level1](#firehol_level1)|5136|688854491|2|0.0%|0.1%|
[et_block](#et_block)|1000|18344011|2|0.0%|0.1%|
[blocklist_de_mail](#blocklist_de_mail)|16621|16621|2|0.0%|0.1%|
[shunlist](#shunlist)|1263|1263|1|0.0%|0.0%|
[iw_spamlist](#iw_spamlist)|3772|3772|1|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|2942|2942|1|0.0%|0.0%|

## virbl

[VirBL](http://virbl.bit.nl/) is a project of which the idea was born during the RIPE-48 meeting. The plan was to get reports of virusscanning mailservers, and put the IP-addresses that were reported to send viruses on a blacklist.

Source is downloaded from [this link](http://virbl.bit.nl/download/virbl.dnsbl.bit.nl.txt).

The last time downloaded was found to be dated: Thu Jun 11 14:42:04 UTC 2015.

The ipset `virbl` has **28** entries, **28** unique IPs.

The following table shows the overlaps of `virbl` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `virbl`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `virbl`.
- ` this % ` is the percentage **of this ipset (`virbl`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level3](#firehol_level3)|109880|9627672|28|0.0%|100.0%|
[sorbs_spam](#sorbs_spam)|64701|65536|1|0.0%|3.5%|
[fullbogons](#fullbogons)|3775|670173256|1|0.0%|3.5%|
[firehol_level1](#firehol_level1)|5136|688854491|1|0.0%|3.5%|

## voipbl

[VoIPBL.org](http://www.voipbl.org/) a distributed VoIP blacklist that is aimed to protects against VoIP Fraud and minimizing abuse for network that have publicly accessible PBX's. Several algorithms, external sources and manual confirmation are used before they categorize something as an attack and determine the threat level.

Source is downloaded from [this link](http://www.voipbl.org/update/).

The last time downloaded was found to be dated: Thu Jun 11 11:09:12 UTC 2015.

The ipset `voipbl` has **10533** entries, **10945** unique IPs.

The following table shows the overlaps of `voipbl` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `voipbl`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `voipbl`.
- ` this % ` is the percentage **of this ipset (`voipbl`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|1605|0.0%|14.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|434|0.0%|3.9%|
[firehol_level1](#firehol_level1)|5136|688854491|333|0.0%|3.0%|
[fullbogons](#fullbogons)|3775|670173256|319|0.0%|2.9%|
[bogons](#bogons)|13|592708608|319|0.0%|2.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|299|0.0%|2.7%|
[alienvault_reputation](#alienvault_reputation)|188722|188722|183|0.0%|1.6%|
[firehol_anonymous](#firehol_anonymous)|18927|82965|79|0.0%|0.7%|
[firehol_level3](#firehol_level3)|109880|9627672|57|0.0%|0.5%|
[firehol_level2](#firehol_level2)|21182|32799|40|0.1%|0.3%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|35|0.0%|0.3%|
[blocklist_de](#blocklist_de)|27522|27522|35|0.1%|0.3%|
[blocklist_de_sip](#blocklist_de_sip)|84|84|29|34.5%|0.2%|
[dragon_http](#dragon_http)|1029|270336|26|0.0%|0.2%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|14|0.0%|0.1%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|14|0.0%|0.1%|
[et_block](#et_block)|1000|18344011|14|0.0%|0.1%|
[shunlist](#shunlist)|1263|1263|12|0.9%|0.1%|
[openbl_60d](#openbl_60d)|6989|6989|8|0.1%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6710|6710|5|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|4|0.0%|0.0%|
[sorbs_spam](#sorbs_spam)|64701|65536|3|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|3|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|3|0.0%|0.0%|
[openbl_30d](#openbl_30d)|2813|2813|3|0.1%|0.0%|
[et_tor](#et_tor)|6400|6400|3|0.0%|0.0%|
[et_compromised](#et_compromised)|1721|1721|3|0.1%|0.0%|
[dm_tor](#dm_tor)|6490|6490|3|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1701|1701|3|0.1%|0.0%|
[bm_tor](#bm_tor)|6492|6492|3|0.0%|0.0%|
[nixspam](#nixspam)|24663|24663|2|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|2|0.3%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|2|0.0%|0.0%|
[firehol_proxies](#firehol_proxies)|12374|12641|2|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3334|3334|2|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|16621|16621|2|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14218|14218|2|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9945|9945|1|0.0%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.0%|
[ciarmy](#ciarmy)|457|457|1|0.2%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2296|2296|1|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2852|2852|1|0.0%|0.0%|

## xroxy

[xroxy.com](http://www.xroxy.com) open proxies (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.xroxy.com/proxyrss.xml).

The last time downloaded was found to be dated: Thu Jun 11 14:33:01 UTC 2015.

The ipset `xroxy` has **2165** entries, **2165** unique IPs.

The following table shows the overlaps of `xroxy` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `xroxy`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `xroxy`.
- ` this % ` is the percentage **of this ipset (`xroxy`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_proxies](#firehol_proxies)|12374|12641|2165|17.1%|100.0%|
[firehol_anonymous](#firehol_anonymous)|18927|82965|2165|2.6%|100.0%|
[firehol_level3](#firehol_level3)|109880|9627672|1299|0.0%|60.0%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|1283|1.3%|59.2%|
[ri_web_proxies](#ri_web_proxies)|7800|7800|960|12.3%|44.3%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|610|2.0%|28.1%|
[proxz](#proxz)|1297|1297|454|35.0%|20.9%|
[ri_connect_proxies](#ri_connect_proxies)|2811|2811|394|14.0%|18.1%|
[proxyrss](#proxyrss)|1373|1373|333|24.2%|15.3%|
[firehol_level2](#firehol_level2)|21182|32799|327|0.9%|15.1%|
[blocklist_de](#blocklist_de)|27522|27522|225|0.8%|10.3%|
[stopforumspam_1d](#stopforumspam_1d)|6710|6710|222|3.3%|10.2%|
[blocklist_de_bots](#blocklist_de_bots)|2942|2942|168|5.7%|7.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|110|0.0%|5.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|104|0.0%|4.8%|
[sorbs_spam](#sorbs_spam)|64701|65536|76|0.1%|3.5%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|76|0.1%|3.5%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|76|0.1%|3.5%|
[nixspam](#nixspam)|24663|24663|70|0.2%|3.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|58|0.0%|2.6%|
[blocklist_de_mail](#blocklist_de_mail)|16621|16621|57|0.3%|2.6%|
[snort_ipfilter](#snort_ipfilter)|9945|9945|41|0.4%|1.8%|
[php_dictionary](#php_dictionary)|737|737|41|5.5%|1.8%|
[php_spammers](#php_spammers)|735|735|34|4.6%|1.5%|
[sorbs_web](#sorbs_web)|531|532|13|2.4%|0.6%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|13|1.9%|0.6%|
[php_commenters](#php_commenters)|430|430|10|2.3%|0.4%|
[dragon_http](#dragon_http)|1029|270336|6|0.0%|0.2%|
[blocklist_de_strongips](#blocklist_de_strongips)|177|177|6|3.3%|0.2%|
[alienvault_reputation](#alienvault_reputation)|188722|188722|5|0.0%|0.2%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|3|0.5%|0.1%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|3|0.0%|0.1%|
[php_harvesters](#php_harvesters)|392|392|2|0.5%|0.0%|
[iw_spamlist](#iw_spamlist)|3772|3772|2|0.0%|0.0%|
[dm_tor](#dm_tor)|6490|6490|2|0.0%|0.0%|
[bm_tor](#bm_tor)|6492|6492|2|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.0%|
[et_tor](#et_tor)|6400|6400|1|0.0%|0.0%|
[et_compromised](#et_compromised)|1721|1721|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1701|1701|1|0.0%|0.0%|

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
[firehol_level1](#firehol_level1)|5136|688854491|230|0.0%|100.0%|
[et_block](#et_block)|1000|18344011|228|0.0%|99.1%|
[firehol_level3](#firehol_level3)|109880|9627672|203|0.0%|88.2%|
[zeus_badips](#zeus_badips)|202|202|202|100.0%|87.8%|
[snort_ipfilter](#snort_ipfilter)|9945|9945|200|2.0%|86.9%|
[alienvault_reputation](#alienvault_reputation)|188722|188722|61|0.0%|26.5%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|15|0.0%|6.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|14|0.0%|6.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|10|0.0%|4.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|9|0.0%|3.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|7|0.0%|3.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|5|0.0%|2.1%|
[dragon_http](#dragon_http)|1029|270336|3|0.0%|1.3%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|2|0.0%|0.8%|
[openbl_60d](#openbl_60d)|6989|6989|2|0.0%|0.8%|
[openbl_30d](#openbl_30d)|2813|2813|2|0.0%|0.8%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|1|0.0%|0.4%|
[stopforumspam_1d](#stopforumspam_1d)|6710|6710|1|0.0%|0.4%|
[php_commenters](#php_commenters)|430|430|1|0.2%|0.4%|
[openbl_7d](#openbl_7d)|641|641|1|0.1%|0.4%|
[nixspam](#nixspam)|24663|24663|1|0.0%|0.4%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|1|0.0%|0.4%|
[iw_spamlist](#iw_spamlist)|3772|3772|1|0.0%|0.4%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.4%|
[firehol_level2](#firehol_level2)|21182|32799|1|0.0%|0.4%|

## zeus_badips

[Abuse.ch Zeus tracker](https://zeustracker.abuse.ch) badips includes IPv4 addresses that are used by the ZeuS trojan. It is the recommened blocklist if you want to block only ZeuS IPs. It excludes IP addresses that ZeuS Tracker believes to be hijacked (level 2) or belong to a free web hosting provider (level 3). Hence the false postive rate should be much lower compared to the standard ZeuS IP blocklist. **excellent list**

Source is downloaded from [this link](https://zeustracker.abuse.ch/blocklist.php?download=badips).

The last time downloaded was found to be dated: Thu Jun 11 14:45:08 UTC 2015.

The ipset `zeus_badips` has **202** entries, **202** unique IPs.

The following table shows the overlaps of `zeus_badips` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `zeus_badips`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `zeus_badips`.
- ` this % ` is the percentage **of this ipset (`zeus_badips`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[zeus](#zeus)|230|230|202|87.8%|100.0%|
[firehol_level1](#firehol_level1)|5136|688854491|202|0.0%|100.0%|
[et_block](#et_block)|1000|18344011|202|0.0%|100.0%|
[firehol_level3](#firehol_level3)|109880|9627672|180|0.0%|89.1%|
[snort_ipfilter](#snort_ipfilter)|9945|9945|178|1.7%|88.1%|
[alienvault_reputation](#alienvault_reputation)|188722|188722|37|0.0%|18.3%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|15|0.0%|7.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|10|0.0%|4.9%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|10|0.0%|4.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|8|0.0%|3.9%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|5|0.0%|2.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|4|0.0%|1.9%|
[dragon_http](#dragon_http)|1029|270336|3|0.0%|1.4%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|2|0.0%|0.9%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|1|0.0%|0.4%|
[stopforumspam_1d](#stopforumspam_1d)|6710|6710|1|0.0%|0.4%|
[php_commenters](#php_commenters)|430|430|1|0.2%|0.4%|
[openbl_7d](#openbl_7d)|641|641|1|0.1%|0.4%|
[openbl_60d](#openbl_60d)|6989|6989|1|0.0%|0.4%|
[openbl_30d](#openbl_30d)|2813|2813|1|0.0%|0.4%|
[nixspam](#nixspam)|24663|24663|1|0.0%|0.4%|
[iw_spamlist](#iw_spamlist)|3772|3772|1|0.0%|0.4%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.4%|
[firehol_level2](#firehol_level2)|21182|32799|1|0.0%|0.4%|
