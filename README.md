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

The following list was automatically generated on Wed Jun 10 20:37:48 UTC 2015.

The update frequency is the maximum allowed by internal configuration. A list will never be downloaded sooner than the update frequency stated. A list may also not be downloaded, after this frequency expired, if it has not been modified on the server (as reported by HTTP `IF_MODIFIED_SINCE` method).

name|info|type|entries|update|
:--:|:--:|:--:|:-----:|:----:|
[alienvault_reputation](#alienvault_reputation)|[AlienVault.com](https://www.alienvault.com/) IP reputation database (this list seems to include port scanning hosts and to be updated regularly, but we found no information about its retention policy)|ipv4 hash:ip|187115 unique IPs|updated every 6 hours  from [this link](https://reputation.alienvault.com/reputation.generic)
[blocklist_de](#blocklist_de)|[Blocklist.de](https://www.blocklist.de/) IPs that have been detected by fail2ban in the last 48 hours - **excellent list**|ipv4 hash:ip|29619 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/all.txt)
[blocklist_de_apache](#blocklist_de_apache)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service Apache, Apache-DDOS, RFI-Attacks.|ipv4 hash:ip|15426 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/apache.txt)
[blocklist_de_bots](#blocklist_de_bots)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the RFI-Attacks, REG-Bots, IRC-Bots or BadBots (BadBots = he has posted a Spam-Comment on a open Forum or Wiki).|ipv4 hash:ip|2933 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/bots.txt)
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|[Blocklist.de](https://www.blocklist.de/) All IPs which attacks Joomlas, Wordpress and other Web-Logins with Brute-Force Logins.|ipv4 hash:ip|4071 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/bruteforcelogin.txt)
[blocklist_de_ftp](#blocklist_de_ftp)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours for attacks on the Service FTP.|ipv4 hash:ip|1333 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/ftp.txt)
[blocklist_de_imap](#blocklist_de_imap)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours for attacks on the Service imap, sasl, pop3, etc.|ipv4 hash:ip|2383 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/imap.txt)
[blocklist_de_mail](#blocklist_de_mail)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service Mail, Postfix.|ipv4 hash:ip|17415 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/mail.txt)
[blocklist_de_sip](#blocklist_de_sip)|[Blocklist.de](https://www.blocklist.de/) All IP addresses that tried to login in a SIP, VOIP or Asterisk Server and are included in the IPs list from [infiltrated.net](www.infiltrated.net)|ipv4 hash:ip|79 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/sip.txt)
[blocklist_de_ssh](#blocklist_de_ssh)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service SSH.|ipv4 hash:ip|3530 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/ssh.txt)
[blocklist_de_strongips](#blocklist_de_strongips)|[Blocklist.de](https://www.blocklist.de/) All IPs which are older then 2 month and have more then 5.000 attacks.|ipv4 hash:ip|180 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/strongips.txt)
[bm_tor](#bm_tor)|[torstatus.blutmagie.de](https://torstatus.blutmagie.de) list of all TOR network servers|ipv4 hash:ip|6552 unique IPs|updated every 30 mins  from [this link](https://torstatus.blutmagie.de/ip_list_all.php/Tor_ip_list_ALL.csv)
[bogons](#bogons)|[Team-Cymru.org](http://www.team-cymru.org) private and reserved addresses defined by RFC 1918, RFC 5735, and RFC 6598 and netblocks that have not been allocated to a regional internet registry - **excellent list - use it only your internet interface**|ipv4 hash:net|13 subnets, 592708608 unique IPs|updated every 1 day  from [this link](http://www.team-cymru.org/Services/Bogons/bogon-bn-agg.txt)
[bruteforceblocker](#bruteforceblocker)|[danger.rulez.sk](http://danger.rulez.sk/) IPs detected by [bruteforceblocker](http://danger.rulez.sk/index.php/bruteforceblocker/) (fail2ban alternative for SSH on OpenBSD). This is an automatically generated list from users reporting failed authentication attempts. An IP seems to be included if 3 or more users report it. Its retention pocily seems 30 days.|ipv4 hash:ip|1711 unique IPs|updated every 3 hours  from [this link](http://danger.rulez.sk/projects/bruteforceblocker/blist.php)
[ciarmy](#ciarmy)|[CIArmy.com](http://ciarmy.com/) IPs with poor Rogue Packet score that have not yet been identified as malicious by the community|ipv4 hash:ip|457 unique IPs|updated every 3 hours  from [this link](http://cinsscore.com/list/ci-badguys.txt)
[cleanmx_viruses](#cleanmx_viruses)|[Clean-MX.de](http://support.clean-mx.de/clean-mx/viruses.php) IPs with viruses|ipv4 hash:ip|123 unique IPs|updated every 12 hours  from [this link](http://support.clean-mx.de/clean-mx/xmlviruses.php?sort=id%20desc&response=alive)
[dm_tor](#dm_tor)|[dan.me.uk](https://www.dan.me.uk) dynamic list of TOR exit points|ipv4 hash:ip|6548 unique IPs|updated every 30 mins  from [this link](https://www.dan.me.uk/torlist/)
[dragon_http](#dragon_http)|[Dragon Search Group](http://www.dragonresearchgroup.org/) IPs that have been seen sending HTTP requests to Dragon Research Pods in the last 7 days. This report lists hosts that are highly suspicious and are likely conducting malicious HTTP attacks. LEGITIMATE SEARCH ENGINE BOTS MAY BE IN THIS LIST. This report is informational.  It is not a blacklist, but some operators may choose to use it to help protect their networks and hosts in the forms of automated reporting and mitigation services.|ipv4 hash:net|1044 subnets, 273664 unique IPs|updated every 1 day  from [this link](http://www.dragonresearchgroup.org/insight/http-report.txt)
[dshield](#dshield)|[DShield.org](https://dshield.org/) top 20 attacking class C (/24) subnets over the last three days - **excellent list**|ipv4 hash:net|20 subnets, 5120 unique IPs|updated every 4 hours  from [this link](http://feeds.dshield.org/block.txt)
[et_block](#et_block)|[EmergingThreats.net](http://www.emergingthreats.net/) default blacklist (at the time of writing includes spamhaus DROP, dshield and abuse.ch trackers, which are available separately too - prefer to use the direct ipsets instead of this, they seem to lag a bit in updates)|ipv4 hash:net|1000 subnets, 18344011 unique IPs|updated every 12 hours  from [this link](http://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt)
[et_botcc](#et_botcc)|[EmergingThreats.net Command and Control IPs](http://doc.emergingthreats.net/bin/view/Main/BotCC) These IPs are updates every 24 hours and should be considered VERY highly reliable indications that a host is communicating with a known and active Bot or Malware command and control server - (although they say this includes abuse.ch trackers, it does not - most probably it is the shadowserver.org C&C list)|ipv4 hash:ip|506 unique IPs|updated every 12 hours  from [this link](http://rules.emergingthreats.net/fwrules/emerging-PIX-CC.rules)
[et_compromised](#et_compromised)|[EmergingThreats.net compromised hosts](http://doc.emergingthreats.net/bin/view/Main/CompromisedHost) - (this seems to be based on bruteforceblocker)|ipv4 hash:ip|1721 unique IPs|updated every 12 hours  from [this link](http://rules.emergingthreats.net/blockrules/compromised-ips.txt)
et_dshield|[EmergingThreats.net](http://www.emergingthreats.net/) dshield blocklist|ipv4 hash:net|disabled|updated every 12 hours  from [this link](http://rules.emergingthreats.net/fwrules/emerging-PIX-DSHIELD.rules)
et_spamhaus|[EmergingThreats.net](http://www.emergingthreats.net/) spamhaus blocklist|ipv4 hash:net|disabled|updated every 12 hours  from [this link](http://rules.emergingthreats.net/fwrules/emerging-PIX-DROP.rules)
[et_tor](#et_tor)|[EmergingThreats.net](http://www.emergingthreats.net/) [list](http://doc.emergingthreats.net/bin/view/Main/TorRules) of TOR network IPs|ipv4 hash:ip|6400 unique IPs|updated every 12 hours  from [this link](http://rules.emergingthreats.net/blockrules/emerging-tor.rules)
[feodo](#feodo)|[Abuse.ch Feodo tracker](https://feodotracker.abuse.ch) trojan includes IPs which are being used by Feodo (also known as Cridex or Bugat) which commits ebanking fraud - **excellent list**|ipv4 hash:ip|105 unique IPs|updated every 30 mins  from [this link](https://feodotracker.abuse.ch/blocklist/?download=ipblocklist)
[firehol_anonymous](#firehol_anonymous)|**FireHOL Anonymous** - Known anonymizing IPs. (includes: firehol_proxies anonymous bm_tor dm_tor)|ipv4 hash:net|18837 subnets, 82872 unique IPs|
[firehol_level1](#firehol_level1)|**FireHOL Level 1** - Maximum protection without false positives. (includes: fullbogons dshield feodo palevo sslbl zeus spamhaus_drop spamhaus_edrop)|ipv4 hash:net|5135 subnets, 688894845 unique IPs|
[firehol_level2](#firehol_level2)|**FireHOL Level 2** - Maximum protection from attacks took place in the last 48 hours. (includes: openbl_1d blocklist_de stopforumspam_1d)|ipv4 hash:net|23442 subnets, 35072 unique IPs|
[firehol_level3](#firehol_level3)|**FireHOL Level 3** - All the bad IPs in last 30 days. (includes: openbl_30d stopforumspam_30d virbl malc0de shunlist malwaredomainlist bruteforceblocker ciarmy cleanmx_viruses snort_ipfilter ib_bluetack_spyware ib_bluetack_hijacked ib_bluetack_webexploit php_commenters php_dictionary php_harvesters php_spammers)|ipv4 hash:net|110214 subnets, 9627951 unique IPs|
[firehol_proxies](#firehol_proxies)|**FireHOL Proxies** - Known open proxies in the last 30 days. (includes: ib_bluetack_proxies maxmind_proxy_fraud proxyrss proxz ri_connect_proxies ri_web_proxies xroxy)|ipv4 hash:net|12404 subnets, 12670 unique IPs|
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
lashback_ubl|[The LashBack UBL](http://blacklist.lashback.com/) The Unsubscribe Blacklist (UBL) is a real-time blacklist of IP addresses which are sending email to names harvested from suppression files (this is a big list, more than 500.000 IPs)|ipv4 hash:ip|disabled|updated every 1 day  from [this link](http://www.unsubscore.com/blacklist.txt)
[malc0de](#malc0de)|[Malc0de.com](http://malc0de.com) malicious IPs of the last 30 days|ipv4 hash:ip|313 unique IPs|updated every 1 day  from [this link](http://malc0de.com/bl/IP_Blacklist.txt)
[malwaredomainlist](#malwaredomainlist)|[malwaredomainlist.com](http://www.malwaredomainlist.com) list of malware active ip addresses|ipv4 hash:ip|1288 unique IPs|updated every 12 hours  from [this link](http://www.malwaredomainlist.com/hostslist/ip.txt)
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|[MaxMind.com](https://www.maxmind.com/en/anonymous-proxy-fraudulent-ip-address-list) list of anonymous proxy fraudelent IP addresses.|ipv4 hash:ip|524 unique IPs|updated every 4 hours  from [this link](https://www.maxmind.com/en/anonymous-proxy-fraudulent-ip-address-list)
[nixspam](#nixspam)|[NiX Spam](http://www.heise.de/ix/NiX-Spam-DNSBL-and-blacklist-for-download-499637.html) IP addresses that sent spam in the last hour - automatically generated entries without distinguishing open proxies from relays, dialup gateways, and so on. All IPs are removed after 12 hours if there is no spam from there.|ipv4 hash:ip|39994 unique IPs|updated every 15 mins  from [this link](http://www.dnsbl.manitu.net/download/nixspam-ip.dump.gz)
openbl|[OpenBL.org](http://www.openbl.org/) default blacklist (currently it is the same with 90 days). OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications - **excellent list**|ipv4 hash:ip|disabled|updated every 4 hours  from [this link](http://www.openbl.org/lists/base.txt)
openbl_180d|[OpenBL.org](http://www.openbl.org/) last 180 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|disabled|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_180days.txt)
[openbl_1d](#openbl_1d)|[OpenBL.org](http://www.openbl.org/) last 24 hours IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|158 unique IPs|updated every 1 hour  from [this link](http://www.openbl.org/lists/base_1days.txt)
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
[php_harvesters](#php_harvesters)|[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) harvesters (IPs that surf the internet looking for email addresses) (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|378 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=h&rss=1)
[php_spammers](#php_spammers)|[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) spam servers (IPs used by spammers to send messages) (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|700 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=s&rss=1)
[proxyrss](#proxyrss)|[proxyrss.com](http://www.proxyrss.com) open proxies syndicated from multiple sources.|ipv4 hash:ip|1669 unique IPs|updated every 4 hours  from [this link](http://www.proxyrss.com/proxylists/all.gz)
[proxz](#proxz)|[proxz.com](http://www.proxz.com) open proxies (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|1236 unique IPs|updated every 1 hour  from [this link](http://www.proxz.com/proxylists.xml)
[ri_connect_proxies](#ri_connect_proxies)|[rosinstrument.com](http://www.rosinstrument.com) open CONNECT proxies (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|2737 unique IPs|updated every 1 hour  from [this link](http://tools.rosinstrument.com/proxy/plab100.xml)
[ri_web_proxies](#ri_web_proxies)|[rosinstrument.com](http://www.rosinstrument.com) open HTTP proxies (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|7581 unique IPs|updated every 1 hour  from [this link](http://tools.rosinstrument.com/proxy/l100.xml)
[shunlist](#shunlist)|[AutoShun.org](http://autoshun.org/) IPs identified as hostile by correlating logs from distributed snort installations running the autoshun plugin|ipv4 hash:ip|1225 unique IPs|updated every 4 hours  from [this link](http://www.autoshun.org/files/shunlist.csv)
[snort_ipfilter](#snort_ipfilter)|[labs.snort.org](https://labs.snort.org/) supplied IP blacklist (this list seems to be updated frequently, but we found no information about it)|ipv4 hash:ip|10158 unique IPs|updated every 12 hours  from [this link](http://labs.snort.org/feeds/ip-filter.blf)
[sorbs_dul](#sorbs_dul)|[Sorbs.net](https://www.sorbs.net/) DUL, Dynamic User IPs extracted from deltas.|ipv4 hash:net|9 subnets, 4608 unique IPs|updated every 1 min  from [this link]()
[sorbs_http](#sorbs_http)|[Sorbs.net](https://www.sorbs.net/) HTTP proxies, extracted from deltas.|ipv4 hash:net|2 subnets, 2 unique IPs|updated every 1 min  from [this link]()
[sorbs_misc](#sorbs_misc)|[Sorbs.net](https://www.sorbs.net/) MISC proxies, extracted from deltas.|ipv4 hash:net|2 subnets, 2 unique IPs|updated every 1 min  from [this link]()
[sorbs_new_spam](#sorbs_new_spam)|[Sorbs.net](https://www.sorbs.net/) NEW Spam senders, extracted from deltas.|ipv4 hash:net|59772 subnets, 60402 unique IPs|
[sorbs_recent_spam](#sorbs_recent_spam)|[Sorbs.net](https://www.sorbs.net/) RECENT Spam senders, extracted from deltas.|ipv4 hash:net|59772 subnets, 60402 unique IPs|
[sorbs_smtp](#sorbs_smtp)|[Sorbs.net](https://www.sorbs.net/) SMTP Open Relays, extracted from deltas.|ipv4 hash:net|3 subnets, 3 unique IPs|updated every 1 min  from [this link]()
[sorbs_socks](#sorbs_socks)|[Sorbs.net](https://www.sorbs.net/) SOCKS proxies, extracted from deltas.|ipv4 hash:net|2 subnets, 2 unique IPs|updated every 1 min  from [this link]()
[sorbs_spam](#sorbs_spam)|[Sorbs.net](https://www.sorbs.net/) Spam senders, extracted from deltas.|ipv4 hash:net|59772 subnets, 60402 unique IPs|
[sorbs_web](#sorbs_web)|[Sorbs.net](https://www.sorbs.net/) WEB exploits, extracted from deltas.|ipv4 hash:net|411 subnets, 412 unique IPs|
[spamhaus_drop](#spamhaus_drop)|[Spamhaus.org](http://www.spamhaus.org) DROP list (according to their site this list should be dropped at tier-1 ISPs globaly) - **excellent list**|ipv4 hash:net|653 subnets, 18340608 unique IPs|updated every 12 hours  from [this link](http://www.spamhaus.org/drop/drop.txt)
[spamhaus_edrop](#spamhaus_edrop)|[Spamhaus.org](http://www.spamhaus.org) EDROP (extended matches that should be used with DROP) - **excellent list**|ipv4 hash:net|56 subnets, 487424 unique IPs|updated every 12 hours  from [this link](http://www.spamhaus.org/drop/edrop.txt)
[sslbl](#sslbl)|[Abuse.ch SSL Blacklist](https://sslbl.abuse.ch/) bad SSL traffic related to malware or botnet activities - **excellent list**|ipv4 hash:ip|372 unique IPs|updated every 30 mins  from [this link](https://sslbl.abuse.ch/blacklist/sslipblacklist.csv)
stopforumspam_180d|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 180 days)|ipv4 hash:ip|disabled|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/listed_ip_180.zip)
[stopforumspam_1d](#stopforumspam_1d)|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers in the last 24 hours - **excellent list**|ipv4 hash:ip|6808 unique IPs|updated every 1 hour  from [this link](http://www.stopforumspam.com/downloads/listed_ip_1.zip)
[stopforumspam_30d](#stopforumspam_30d)|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 30 days)|ipv4 hash:ip|94424 unique IPs|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/listed_ip_30.zip)
stopforumspam_365d|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 365 days)|ipv4 hash:ip|disabled|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/listed_ip_365.zip)
[stopforumspam_7d](#stopforumspam_7d)|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 7 days)|ipv4 hash:ip|29338 unique IPs|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/listed_ip_7.zip)
stopforumspam_90d|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 90 days)|ipv4 hash:ip|disabled|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/listed_ip_90.zip)
stopforumspam_ever|[StopForumSpam.com](http://www.stopforumspam.com) all IPs used by forum spammers, **ever** (normally you don't want to use this ipset, use the hourly one which includes last 24 hours IPs or the 7 days one)|ipv4 hash:ip|disabled|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/bannedips.zip)
[virbl](#virbl)|[VirBL](http://virbl.bit.nl/) is a project of which the idea was born during the RIPE-48 meeting. The plan was to get reports of virusscanning mailservers, and put the IP-addresses that were reported to send viruses on a blacklist.|ipv4 hash:ip|30 unique IPs|updated every 1 hour  from [this link](http://virbl.bit.nl/download/virbl.dnsbl.bit.nl.txt)
[voipbl](#voipbl)|[VoIPBL.org](http://www.voipbl.org/) a distributed VoIP blacklist that is aimed to protects against VoIP Fraud and minimizing abuse for network that have publicly accessible PBX's. Several algorithms, external sources and manual confirmation are used before they categorize something as an attack and determine the threat level.|ipv4 hash:net|10533 subnets, 10945 unique IPs|updated every 4 hours  from [this link](http://www.voipbl.org/update/)
[xroxy](#xroxy)|[xroxy.com](http://www.xroxy.com) open proxies (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|2159 unique IPs|updated every 1 hour  from [this link](http://www.xroxy.com/proxyrss.xml)
[zeus](#zeus)|[Abuse.ch Zeus tracker](https://zeustracker.abuse.ch) standard, contains the same data as the ZeuS IP blocklist (zeus_badips) but with the slight difference that it doesn't exclude hijacked websites (level 2) and free web hosting providers (level 3). This means that this blocklist contains all IPv4 addresses associated with ZeuS C&Cs which are currently being tracked by ZeuS Tracker. Hence this blocklist will likely cause some false positives. - **excellent list**|ipv4 hash:ip|230 unique IPs|updated every 30 mins  from [this link](https://zeustracker.abuse.ch/blocklist.php?download=ipblocklist)
[zeus_badips](#zeus_badips)|[Abuse.ch Zeus tracker](https://zeustracker.abuse.ch) badips includes IPv4 addresses that are used by the ZeuS trojan. It is the recommened blocklist if you want to block only ZeuS IPs. It excludes IP addresses that ZeuS Tracker believes to be hijacked (level 2) or belong to a free web hosting provider (level 3). Hence the false postive rate should be much lower compared to the standard ZeuS IP blocklist. **excellent list**|ipv4 hash:ip|202 unique IPs|updated every 30 mins  from [this link](https://zeustracker.abuse.ch/blocklist.php?download=badips)

# Comparison of ipsets

Below we compare each ipset against all other.


## alienvault_reputation

[AlienVault.com](https://www.alienvault.com/) IP reputation database (this list seems to include port scanning hosts and to be updated regularly, but we found no information about its retention policy)

Source is downloaded from [this link](https://reputation.alienvault.com/reputation.generic).

The last time downloaded was found to be dated: Wed Jun 10 16:01:01 UTC 2015.

The ipset `alienvault_reputation` has **187115** entries, **187115** unique IPs.

The following table shows the overlaps of `alienvault_reputation` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `alienvault_reputation`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `alienvault_reputation`.
- ` this % ` is the percentage **of this ipset (`alienvault_reputation`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|13887|0.0%|7.4%|
[openbl_60d](#openbl_60d)|7012|7012|6989|99.6%|3.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|6262|0.0%|3.3%|
[dragon_http](#dragon_http)|1044|273664|5646|2.0%|3.0%|
[firehol_level3](#firehol_level3)|110214|9627951|5166|0.0%|2.7%|
[et_block](#et_block)|1000|18344011|4764|0.0%|2.5%|
[firehol_level1](#firehol_level1)|5135|688894845|4589|0.0%|2.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|4218|0.0%|2.2%|
[dshield](#dshield)|20|5120|3075|60.0%|1.6%|
[openbl_30d](#openbl_30d)|2835|2835|2817|99.3%|1.5%|
[firehol_level2](#firehol_level2)|23442|35072|1405|4.0%|0.7%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|1373|0.0%|0.7%|
[blocklist_de](#blocklist_de)|29619|29619|1337|4.5%|0.7%|
[shunlist](#shunlist)|1225|1225|1213|99.0%|0.6%|
[blocklist_de_ssh](#blocklist_de_ssh)|3530|3530|1123|31.8%|0.6%|
[et_compromised](#et_compromised)|1721|1721|1117|64.9%|0.5%|
[bruteforceblocker](#bruteforceblocker)|1711|1711|1093|63.8%|0.5%|
[openbl_7d](#openbl_7d)|679|679|673|99.1%|0.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|518|0.0%|0.2%|
[ciarmy](#ciarmy)|457|457|450|98.4%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|289|0.0%|0.1%|
[stopforumspam_30d](#stopforumspam_30d)|94424|94424|205|0.2%|0.1%|
[voipbl](#voipbl)|10533|10945|193|1.7%|0.1%|
[openbl_1d](#openbl_1d)|158|158|154|97.4%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|15426|15426|125|0.8%|0.0%|
[snort_ipfilter](#snort_ipfilter)|10158|10158|112|1.1%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|103|0.3%|0.0%|
[sorbs_spam](#sorbs_spam)|59772|60402|85|0.1%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|59772|60402|85|0.1%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|59772|60402|85|0.1%|0.0%|
[nixspam](#nixspam)|39994|39994|70|0.1%|0.0%|
[sslbl](#sslbl)|372|372|66|17.7%|0.0%|
[zeus](#zeus)|230|230|61|26.5%|0.0%|
[firehol_anonymous](#firehol_anonymous)|18837|82872|57|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|17415|17415|52|0.2%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6808|6808|48|0.7%|0.0%|
[dm_tor](#dm_tor)|6548|6548|42|0.6%|0.0%|
[bm_tor](#bm_tor)|6552|6552|42|0.6%|0.0%|
[et_tor](#et_tor)|6400|6400|40|0.6%|0.0%|
[firehol_proxies](#firehol_proxies)|12404|12670|39|0.3%|0.0%|
[zeus_badips](#zeus_badips)|202|202|37|18.3%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2383|2383|37|1.5%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|180|180|35|19.4%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|30|5.7%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4071|4071|22|0.5%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|2933|2933|20|0.6%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|79|79|19|24.0%|0.0%|
[php_commenters](#php_commenters)|430|430|18|4.1%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|16|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|14|0.0%|0.0%|
[php_harvesters](#php_harvesters)|378|378|12|3.1%|0.0%|
[malc0de](#malc0de)|313|313|10|3.1%|0.0%|
[php_dictionary](#php_dictionary)|702|702|9|1.2%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|1333|1333|9|0.6%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|8|0.6%|0.0%|
[php_spammers](#php_spammers)|700|700|6|0.8%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|6|0.4%|0.0%|
[xroxy](#xroxy)|2159|2159|5|0.2%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7581|7581|4|0.0%|0.0%|
[et_botcc](#et_botcc)|506|506|4|0.7%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2737|2737|3|0.1%|0.0%|
[proxz](#proxz)|1236|1236|3|0.2%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|123|123|3|2.4%|0.0%|
[feodo](#feodo)|105|105|2|1.9%|0.0%|
[proxyrss](#proxyrss)|1669|1669|1|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|1|0.1%|0.0%|

## blocklist_de

[Blocklist.de](https://www.blocklist.de/) IPs that have been detected by fail2ban in the last 48 hours - **excellent list**

Source is downloaded from [this link](http://lists.blocklist.de/lists/all.txt).

The last time downloaded was found to be dated: Wed Jun 10 20:10:05 UTC 2015.

The ipset `blocklist_de` has **29619** entries, **29619** unique IPs.

The following table shows the overlaps of `blocklist_de` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de`.
- ` this % ` is the percentage **of this ipset (`blocklist_de`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|23442|35072|29619|84.4%|100.0%|
[blocklist_de_mail](#blocklist_de_mail)|17415|17415|17409|99.9%|58.7%|
[blocklist_de_apache](#blocklist_de_apache)|15426|15426|15425|99.9%|52.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4071|4071|4071|100.0%|13.7%|
[firehol_level3](#firehol_level3)|110214|9627951|3970|0.0%|13.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|3754|0.0%|12.6%|
[blocklist_de_ssh](#blocklist_de_ssh)|3530|3530|3524|99.8%|11.8%|
[blocklist_de_bots](#blocklist_de_bots)|2933|2933|2919|99.5%|9.8%|
[stopforumspam_30d](#stopforumspam_30d)|94424|94424|2720|2.8%|9.1%|
[blocklist_de_imap](#blocklist_de_imap)|2383|2383|2378|99.7%|8.0%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|2181|7.4%|7.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|1583|0.0%|5.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|1548|0.0%|5.2%|
[stopforumspam_1d](#stopforumspam_1d)|6808|6808|1389|20.4%|4.6%|
[alienvault_reputation](#alienvault_reputation)|187115|187115|1337|0.7%|4.5%|
[blocklist_de_ftp](#blocklist_de_ftp)|1333|1333|1331|99.8%|4.4%|
[sorbs_spam](#sorbs_spam)|59772|60402|1302|2.1%|4.3%|
[sorbs_recent_spam](#sorbs_recent_spam)|59772|60402|1302|2.1%|4.3%|
[sorbs_new_spam](#sorbs_new_spam)|59772|60402|1302|2.1%|4.3%|
[openbl_60d](#openbl_60d)|7012|7012|964|13.7%|3.2%|
[nixspam](#nixspam)|39994|39994|862|2.1%|2.9%|
[openbl_30d](#openbl_30d)|2835|2835|769|27.1%|2.5%|
[firehol_anonymous](#firehol_anonymous)|18837|82872|653|0.7%|2.2%|
[et_compromised](#et_compromised)|1721|1721|653|37.9%|2.2%|
[bruteforceblocker](#bruteforceblocker)|1711|1711|647|37.8%|2.1%|
[firehol_proxies](#firehol_proxies)|12404|12670|631|4.9%|2.1%|
[ri_web_proxies](#ri_web_proxies)|7581|7581|447|5.8%|1.5%|
[shunlist](#shunlist)|1225|1225|421|34.3%|1.4%|
[openbl_7d](#openbl_7d)|679|679|390|57.4%|1.3%|
[et_block](#et_block)|1000|18344011|246|0.0%|0.8%|
[firehol_level1](#firehol_level1)|5135|688894845|241|0.0%|0.8%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|218|0.0%|0.7%|
[proxyrss](#proxyrss)|1669|1669|217|13.0%|0.7%|
[snort_ipfilter](#snort_ipfilter)|10158|10158|216|2.1%|0.7%|
[xroxy](#xroxy)|2159|2159|203|9.4%|0.6%|
[blocklist_de_strongips](#blocklist_de_strongips)|180|180|180|100.0%|0.6%|
[proxz](#proxz)|1236|1236|179|14.4%|0.6%|
[openbl_1d](#openbl_1d)|158|158|124|78.4%|0.4%|
[php_dictionary](#php_dictionary)|702|702|108|15.3%|0.3%|
[php_commenters](#php_commenters)|430|430|107|24.8%|0.3%|
[php_spammers](#php_spammers)|700|700|101|14.4%|0.3%|
[ri_connect_proxies](#ri_connect_proxies)|2737|2737|74|2.7%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|66|0.0%|0.2%|
[blocklist_de_sip](#blocklist_de_sip)|79|79|60|75.9%|0.2%|
[dragon_http](#dragon_http)|1044|273664|55|0.0%|0.1%|
[sorbs_web](#sorbs_web)|411|412|54|13.1%|0.1%|
[ciarmy](#ciarmy)|457|457|42|9.1%|0.1%|
[php_harvesters](#php_harvesters)|378|378|38|10.0%|0.1%|
[voipbl](#voipbl)|10533|10945|31|0.2%|0.1%|
[et_tor](#et_tor)|6400|6400|20|0.3%|0.0%|
[dm_tor](#dm_tor)|6548|6548|20|0.3%|0.0%|
[bm_tor](#bm_tor)|6552|6552|20|0.3%|0.0%|
[dshield](#dshield)|20|5120|18|0.3%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|11|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|9|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|7|1.3%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|5|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|5|0.7%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|2|0.1%|0.0%|
[zeus_badips](#zeus_badips)|202|202|1|0.4%|0.0%|
[zeus](#zeus)|230|230|1|0.4%|0.0%|

## blocklist_de_apache

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service Apache, Apache-DDOS, RFI-Attacks.

Source is downloaded from [this link](http://lists.blocklist.de/lists/apache.txt).

The last time downloaded was found to be dated: Wed Jun 10 20:28:47 UTC 2015.

The ipset `blocklist_de_apache` has **15426** entries, **15426** unique IPs.

The following table shows the overlaps of `blocklist_de_apache` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_apache`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_apache`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_apache`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|23442|35072|15425|43.9%|99.9%|
[blocklist_de](#blocklist_de)|29619|29619|15425|52.0%|99.9%|
[blocklist_de_mail](#blocklist_de_mail)|17415|17415|11059|63.5%|71.6%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4071|4071|4071|100.0%|26.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|2392|0.0%|15.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|1335|0.0%|8.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|1105|0.0%|7.1%|
[firehol_level3](#firehol_level3)|110214|9627951|325|0.0%|2.1%|
[stopforumspam_30d](#stopforumspam_30d)|94424|94424|237|0.2%|1.5%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|144|0.4%|0.9%|
[alienvault_reputation](#alienvault_reputation)|187115|187115|125|0.0%|0.8%|
[stopforumspam_1d](#stopforumspam_1d)|6808|6808|84|1.2%|0.5%|
[sorbs_spam](#sorbs_spam)|59772|60402|57|0.0%|0.3%|
[sorbs_recent_spam](#sorbs_recent_spam)|59772|60402|57|0.0%|0.3%|
[sorbs_new_spam](#sorbs_new_spam)|59772|60402|57|0.0%|0.3%|
[snort_ipfilter](#snort_ipfilter)|10158|10158|41|0.4%|0.2%|
[blocklist_de_strongips](#blocklist_de_strongips)|180|180|36|20.0%|0.2%|
[nixspam](#nixspam)|39994|39994|33|0.0%|0.2%|
[ciarmy](#ciarmy)|457|457|33|7.2%|0.2%|
[php_commenters](#php_commenters)|430|430|32|7.4%|0.2%|
[shunlist](#shunlist)|1225|1225|31|2.5%|0.2%|
[firehol_anonymous](#firehol_anonymous)|18837|82872|25|0.0%|0.1%|
[blocklist_de_bots](#blocklist_de_bots)|2933|2933|21|0.7%|0.1%|
[et_tor](#et_tor)|6400|6400|19|0.2%|0.1%|
[dm_tor](#dm_tor)|6548|6548|19|0.2%|0.1%|
[bm_tor](#bm_tor)|6552|6552|19|0.2%|0.1%|
[firehol_level1](#firehol_level1)|5135|688894845|14|0.0%|0.0%|
[et_block](#et_block)|1000|18344011|13|0.0%|0.0%|
[dragon_http](#dragon_http)|1044|273664|13|0.0%|0.0%|
[dshield](#dshield)|20|5120|9|0.1%|0.0%|
[php_spammers](#php_spammers)|700|700|8|1.1%|0.0%|
[openbl_60d](#openbl_60d)|7012|7012|7|0.0%|0.0%|
[openbl_30d](#openbl_30d)|2835|2835|7|0.2%|0.0%|
[firehol_proxies](#firehol_proxies)|12404|12670|7|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|5|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7581|7581|5|0.0%|0.0%|
[openbl_7d](#openbl_7d)|679|679|5|0.7%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|5|0.0%|0.0%|
[php_dictionary](#php_dictionary)|702|702|4|0.5%|0.0%|
[php_harvesters](#php_harvesters)|378|378|3|0.7%|0.0%|
[openbl_1d](#openbl_1d)|158|158|3|1.8%|0.0%|
[voipbl](#voipbl)|10533|10945|2|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|2|0.3%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|2|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2383|2383|1|0.0%|0.0%|

## blocklist_de_bots

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the RFI-Attacks, REG-Bots, IRC-Bots or BadBots (BadBots = he has posted a Spam-Comment on a open Forum or Wiki).

Source is downloaded from [this link](http://lists.blocklist.de/lists/bots.txt).

The last time downloaded was found to be dated: Wed Jun 10 20:28:49 UTC 2015.

The ipset `blocklist_de_bots` has **2933** entries, **2933** unique IPs.

The following table shows the overlaps of `blocklist_de_bots` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_bots`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_bots`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_bots`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|23442|35072|2922|8.3%|99.6%|
[blocklist_de](#blocklist_de)|29619|29619|2919|9.8%|99.5%|
[firehol_level3](#firehol_level3)|110214|9627951|2361|0.0%|80.4%|
[stopforumspam_30d](#stopforumspam_30d)|94424|94424|2323|2.4%|79.2%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|1959|6.6%|66.7%|
[stopforumspam_1d](#stopforumspam_1d)|6808|6808|1311|19.2%|44.6%|
[firehol_anonymous](#firehol_anonymous)|18837|82872|516|0.6%|17.5%|
[firehol_proxies](#firehol_proxies)|12404|12670|515|4.0%|17.5%|
[ri_web_proxies](#ri_web_proxies)|7581|7581|366|4.8%|12.4%|
[proxyrss](#proxyrss)|1669|1669|217|13.0%|7.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|158|0.0%|5.3%|
[proxz](#proxz)|1236|1236|151|12.2%|5.1%|
[xroxy](#xroxy)|2159|2159|150|6.9%|5.1%|
[blocklist_de_strongips](#blocklist_de_strongips)|180|180|131|72.7%|4.4%|
[php_commenters](#php_commenters)|430|430|85|19.7%|2.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|81|0.0%|2.7%|
[ri_connect_proxies](#ri_connect_proxies)|2737|2737|70|2.5%|2.3%|
[firehol_level1](#firehol_level1)|5135|688894845|62|0.0%|2.1%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|58|0.0%|1.9%|
[et_block](#et_block)|1000|18344011|58|0.0%|1.9%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|57|0.0%|1.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|34|0.0%|1.1%|
[sorbs_spam](#sorbs_spam)|59772|60402|32|0.0%|1.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|59772|60402|32|0.0%|1.0%|
[sorbs_new_spam](#sorbs_new_spam)|59772|60402|32|0.0%|1.0%|
[nixspam](#nixspam)|39994|39994|28|0.0%|0.9%|
[php_harvesters](#php_harvesters)|378|378|26|6.8%|0.8%|
[blocklist_de_mail](#blocklist_de_mail)|17415|17415|21|0.1%|0.7%|
[blocklist_de_apache](#blocklist_de_apache)|15426|15426|21|0.1%|0.7%|
[php_spammers](#php_spammers)|700|700|20|2.8%|0.6%|
[alienvault_reputation](#alienvault_reputation)|187115|187115|20|0.0%|0.6%|
[snort_ipfilter](#snort_ipfilter)|10158|10158|18|0.1%|0.6%|
[php_dictionary](#php_dictionary)|702|702|15|2.1%|0.5%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|5|0.0%|0.1%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|4|0.7%|0.1%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|4|0.6%|0.1%|
[dragon_http](#dragon_http)|1044|273664|4|0.0%|0.1%|
[openbl_60d](#openbl_60d)|7012|7012|3|0.0%|0.1%|
[sorbs_web](#sorbs_web)|411|412|2|0.4%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|2|0.0%|0.0%|
[openbl_30d](#openbl_30d)|2835|2835|1|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|1|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|1|0.0%|0.0%|
[et_compromised](#et_compromised)|1721|1721|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1711|1711|1|0.0%|0.0%|

## blocklist_de_bruteforce

[Blocklist.de](https://www.blocklist.de/) All IPs which attacks Joomlas, Wordpress and other Web-Logins with Brute-Force Logins.

Source is downloaded from [this link](http://lists.blocklist.de/lists/bruteforcelogin.txt).

The last time downloaded was found to be dated: Wed Jun 10 20:28:51 UTC 2015.

The ipset `blocklist_de_bruteforce` has **4071** entries, **4071** unique IPs.

The following table shows the overlaps of `blocklist_de_bruteforce` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_bruteforce`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_bruteforce`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_bruteforce`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|23442|35072|4071|11.6%|100.0%|
[blocklist_de_apache](#blocklist_de_apache)|15426|15426|4071|26.3%|100.0%|
[blocklist_de](#blocklist_de)|29619|29619|4071|13.7%|100.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|301|0.0%|7.3%|
[firehol_level3](#firehol_level3)|110214|9627951|121|0.0%|2.9%|
[stopforumspam_30d](#stopforumspam_30d)|94424|94424|94|0.0%|2.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|73|0.0%|1.7%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|68|0.2%|1.6%|
[sorbs_spam](#sorbs_spam)|59772|60402|57|0.0%|1.4%|
[sorbs_recent_spam](#sorbs_recent_spam)|59772|60402|57|0.0%|1.4%|
[sorbs_new_spam](#sorbs_new_spam)|59772|60402|57|0.0%|1.4%|
[stopforumspam_1d](#stopforumspam_1d)|6808|6808|48|0.7%|1.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|46|0.0%|1.1%|
[snort_ipfilter](#snort_ipfilter)|10158|10158|37|0.3%|0.9%|
[nixspam](#nixspam)|39994|39994|32|0.0%|0.7%|
[firehol_anonymous](#firehol_anonymous)|18837|82872|22|0.0%|0.5%|
[alienvault_reputation](#alienvault_reputation)|187115|187115|22|0.0%|0.5%|
[et_tor](#et_tor)|6400|6400|17|0.2%|0.4%|
[dm_tor](#dm_tor)|6548|6548|16|0.2%|0.3%|
[bm_tor](#bm_tor)|6552|6552|16|0.2%|0.3%|
[php_commenters](#php_commenters)|430|430|11|2.5%|0.2%|
[blocklist_de_strongips](#blocklist_de_strongips)|180|180|11|6.1%|0.2%|
[php_spammers](#php_spammers)|700|700|8|1.1%|0.1%|
[firehol_proxies](#firehol_proxies)|12404|12670|6|0.0%|0.1%|
[firehol_level1](#firehol_level1)|5135|688894845|6|0.0%|0.1%|
[et_block](#et_block)|1000|18344011|6|0.0%|0.1%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|5|0.0%|0.1%|
[ri_web_proxies](#ri_web_proxies)|7581|7581|5|0.0%|0.1%|
[php_dictionary](#php_dictionary)|702|702|4|0.5%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|4|0.0%|0.0%|
[dragon_http](#dragon_http)|1044|273664|4|0.0%|0.0%|
[php_harvesters](#php_harvesters)|378|378|2|0.5%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|2|0.0%|0.0%|
[voipbl](#voipbl)|10533|10945|1|0.0%|0.0%|
[shunlist](#shunlist)|1225|1225|1|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|1|0.1%|0.0%|
[dshield](#dshield)|20|5120|1|0.0%|0.0%|

## blocklist_de_ftp

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours for attacks on the Service FTP.

Source is downloaded from [this link](http://lists.blocklist.de/lists/ftp.txt).

The last time downloaded was found to be dated: Wed Jun 10 20:14:08 UTC 2015.

The ipset `blocklist_de_ftp` has **1333** entries, **1333** unique IPs.

The following table shows the overlaps of `blocklist_de_ftp` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_ftp`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_ftp`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_ftp`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|23442|35072|1331|3.7%|99.8%|
[blocklist_de](#blocklist_de)|29619|29619|1331|4.4%|99.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|153|0.0%|11.4%|
[firehol_level3](#firehol_level3)|110214|9627951|26|0.0%|1.9%|
[stopforumspam_30d](#stopforumspam_30d)|94424|94424|18|0.0%|1.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|16|0.0%|1.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|12|0.0%|0.9%|
[alienvault_reputation](#alienvault_reputation)|187115|187115|9|0.0%|0.6%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|7|0.0%|0.5%|
[sorbs_spam](#sorbs_spam)|59772|60402|7|0.0%|0.5%|
[sorbs_recent_spam](#sorbs_recent_spam)|59772|60402|7|0.0%|0.5%|
[sorbs_new_spam](#sorbs_new_spam)|59772|60402|7|0.0%|0.5%|
[nixspam](#nixspam)|39994|39994|6|0.0%|0.4%|
[php_harvesters](#php_harvesters)|378|378|5|1.3%|0.3%|
[dragon_http](#dragon_http)|1044|273664|4|0.0%|0.3%|
[openbl_60d](#openbl_60d)|7012|7012|2|0.0%|0.1%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|2|0.0%|0.1%|
[firehol_anonymous](#firehol_anonymous)|18837|82872|2|0.0%|0.1%|
[blocklist_de_strongips](#blocklist_de_strongips)|180|180|2|1.1%|0.1%|
[sorbs_web](#sorbs_web)|411|412|1|0.2%|0.0%|
[openbl_7d](#openbl_7d)|679|679|1|0.1%|0.0%|
[openbl_30d](#openbl_30d)|2835|2835|1|0.0%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.0%|
[ciarmy](#ciarmy)|457|457|1|0.2%|0.0%|

## blocklist_de_imap

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours for attacks on the Service imap, sasl, pop3, etc.

Source is downloaded from [this link](http://lists.blocklist.de/lists/imap.txt).

The last time downloaded was found to be dated: Wed Jun 10 20:28:47 UTC 2015.

The ipset `blocklist_de_imap` has **2383** entries, **2383** unique IPs.

The following table shows the overlaps of `blocklist_de_imap` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_imap`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_imap`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_imap`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de_mail](#blocklist_de_mail)|17415|17415|2379|13.6%|99.8%|
[firehol_level2](#firehol_level2)|23442|35072|2378|6.7%|99.7%|
[blocklist_de](#blocklist_de)|29619|29619|2378|8.0%|99.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|304|0.0%|12.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|53|0.0%|2.2%|
[firehol_level3](#firehol_level3)|110214|9627951|46|0.0%|1.9%|
[alienvault_reputation](#alienvault_reputation)|187115|187115|37|0.0%|1.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|31|0.0%|1.3%|
[openbl_60d](#openbl_60d)|7012|7012|24|0.3%|1.0%|
[sorbs_spam](#sorbs_spam)|59772|60402|20|0.0%|0.8%|
[sorbs_recent_spam](#sorbs_recent_spam)|59772|60402|20|0.0%|0.8%|
[sorbs_new_spam](#sorbs_new_spam)|59772|60402|20|0.0%|0.8%|
[openbl_30d](#openbl_30d)|2835|2835|19|0.6%|0.7%|
[nixspam](#nixspam)|39994|39994|15|0.0%|0.6%|
[stopforumspam_30d](#stopforumspam_30d)|94424|94424|13|0.0%|0.5%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|9|0.0%|0.3%|
[firehol_level1](#firehol_level1)|5135|688894845|9|0.0%|0.3%|
[et_block](#et_block)|1000|18344011|9|0.0%|0.3%|
[snort_ipfilter](#snort_ipfilter)|10158|10158|7|0.0%|0.2%|
[dragon_http](#dragon_http)|1044|273664|6|0.0%|0.2%|
[openbl_7d](#openbl_7d)|679|679|5|0.7%|0.2%|
[et_compromised](#et_compromised)|1721|1721|4|0.2%|0.1%|
[ciarmy](#ciarmy)|457|457|4|0.8%|0.1%|
[bruteforceblocker](#bruteforceblocker)|1711|1711|4|0.2%|0.1%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|3|0.0%|0.1%|
[shunlist](#shunlist)|1225|1225|2|0.1%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2|0.0%|0.0%|
[xroxy](#xroxy)|2159|2159|1|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6808|6808|1|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2737|2737|1|0.0%|0.0%|
[php_harvesters](#php_harvesters)|378|378|1|0.2%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|1|0.0%|0.0%|
[firehol_proxies](#firehol_proxies)|12404|12670|1|0.0%|0.0%|
[firehol_anonymous](#firehol_anonymous)|18837|82872|1|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|15426|15426|1|0.0%|0.0%|

## blocklist_de_mail

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service Mail, Postfix.

Source is downloaded from [this link](http://lists.blocklist.de/lists/mail.txt).

The last time downloaded was found to be dated: Wed Jun 10 20:14:04 UTC 2015.

The ipset `blocklist_de_mail` has **17415** entries, **17415** unique IPs.

The following table shows the overlaps of `blocklist_de_mail` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_mail`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_mail`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_mail`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|23442|35072|17409|49.6%|99.9%|
[blocklist_de](#blocklist_de)|29619|29619|17409|58.7%|99.9%|
[blocklist_de_apache](#blocklist_de_apache)|15426|15426|11059|71.6%|63.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|2604|0.0%|14.9%|
[blocklist_de_imap](#blocklist_de_imap)|2383|2383|2379|99.8%|13.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|1383|0.0%|7.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|1262|0.0%|7.2%|
[sorbs_spam](#sorbs_spam)|59772|60402|1201|1.9%|6.8%|
[sorbs_recent_spam](#sorbs_recent_spam)|59772|60402|1201|1.9%|6.8%|
[sorbs_new_spam](#sorbs_new_spam)|59772|60402|1201|1.9%|6.8%|
[nixspam](#nixspam)|39994|39994|792|1.9%|4.5%|
[firehol_level3](#firehol_level3)|110214|9627951|404|0.0%|2.3%|
[stopforumspam_30d](#stopforumspam_30d)|94424|94424|257|0.2%|1.4%|
[snort_ipfilter](#snort_ipfilter)|10158|10158|161|1.5%|0.9%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|146|0.4%|0.8%|
[firehol_anonymous](#firehol_anonymous)|18837|82872|111|0.1%|0.6%|
[firehol_proxies](#firehol_proxies)|12404|12670|109|0.8%|0.6%|
[php_dictionary](#php_dictionary)|702|702|89|12.6%|0.5%|
[ri_web_proxies](#ri_web_proxies)|7581|7581|73|0.9%|0.4%|
[php_spammers](#php_spammers)|700|700|72|10.2%|0.4%|
[xroxy](#xroxy)|2159|2159|53|2.4%|0.3%|
[alienvault_reputation](#alienvault_reputation)|187115|187115|52|0.0%|0.2%|
[sorbs_web](#sorbs_web)|411|412|51|12.3%|0.2%|
[stopforumspam_1d](#stopforumspam_1d)|6808|6808|43|0.6%|0.2%|
[proxz](#proxz)|1236|1236|29|2.3%|0.1%|
[openbl_60d](#openbl_60d)|7012|7012|29|0.4%|0.1%|
[php_commenters](#php_commenters)|430|430|27|6.2%|0.1%|
[openbl_30d](#openbl_30d)|2835|2835|23|0.8%|0.1%|
[blocklist_de_strongips](#blocklist_de_strongips)|180|180|22|12.2%|0.1%|
[blocklist_de_bots](#blocklist_de_bots)|2933|2933|21|0.7%|0.1%|
[firehol_level1](#firehol_level1)|5135|688894845|20|0.0%|0.1%|
[et_block](#et_block)|1000|18344011|19|0.0%|0.1%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|18|0.0%|0.1%|
[dragon_http](#dragon_http)|1044|273664|16|0.0%|0.0%|
[openbl_7d](#openbl_7d)|679|679|6|0.8%|0.0%|
[php_harvesters](#php_harvesters)|378|378|5|1.3%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|5|0.0%|0.0%|
[et_compromised](#et_compromised)|1721|1721|5|0.2%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1711|1711|5|0.2%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2737|2737|4|0.1%|0.0%|
[ciarmy](#ciarmy)|457|457|4|0.8%|0.0%|
[shunlist](#shunlist)|1225|1225|3|0.2%|0.0%|
[dm_tor](#dm_tor)|6548|6548|3|0.0%|0.0%|
[bm_tor](#bm_tor)|6552|6552|3|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|2|0.3%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|2|0.0%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2|0.0%|0.0%|
[et_tor](#et_tor)|6400|6400|2|0.0%|0.0%|
[zeus_badips](#zeus_badips)|202|202|1|0.4%|0.0%|
[zeus](#zeus)|230|230|1|0.4%|0.0%|
[proxyrss](#proxyrss)|1669|1669|1|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|1|0.1%|0.0%|
[dshield](#dshield)|20|5120|1|0.0%|0.0%|

## blocklist_de_sip

[Blocklist.de](https://www.blocklist.de/) All IP addresses that tried to login in a SIP, VOIP or Asterisk Server and are included in the IPs list from [infiltrated.net](www.infiltrated.net)

Source is downloaded from [this link](http://lists.blocklist.de/lists/sip.txt).

The last time downloaded was found to be dated: Wed Jun 10 20:14:08 UTC 2015.

The ipset `blocklist_de_sip` has **79** entries, **79** unique IPs.

The following table shows the overlaps of `blocklist_de_sip` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_sip`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_sip`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_sip`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|23442|35072|60|0.1%|75.9%|
[blocklist_de](#blocklist_de)|29619|29619|60|0.2%|75.9%|
[voipbl](#voipbl)|10533|10945|27|0.2%|34.1%|
[alienvault_reputation](#alienvault_reputation)|187115|187115|19|0.0%|24.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|10|0.0%|12.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|7|0.0%|8.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|6|0.0%|7.5%|
[firehol_level3](#firehol_level3)|110214|9627951|3|0.0%|3.7%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|2|0.0%|2.5%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|2|0.0%|2.5%|
[firehol_level1](#firehol_level1)|5135|688894845|2|0.0%|2.5%|
[et_block](#et_block)|1000|18344011|2|0.0%|2.5%|
[dragon_http](#dragon_http)|1044|273664|2|0.0%|2.5%|
[shunlist](#shunlist)|1225|1225|1|0.0%|1.2%|
[et_botcc](#et_botcc)|506|506|1|0.1%|1.2%|

## blocklist_de_ssh

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service SSH.

Source is downloaded from [this link](http://lists.blocklist.de/lists/ssh.txt).

The last time downloaded was found to be dated: Wed Jun 10 20:28:45 UTC 2015.

The ipset `blocklist_de_ssh` has **3530** entries, **3530** unique IPs.

The following table shows the overlaps of `blocklist_de_ssh` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_ssh`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_ssh`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_ssh`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|23442|35072|3524|10.0%|99.8%|
[blocklist_de](#blocklist_de)|29619|29619|3524|11.8%|99.8%|
[alienvault_reputation](#alienvault_reputation)|187115|187115|1123|0.6%|31.8%|
[firehol_level3](#firehol_level3)|110214|9627951|992|0.0%|28.1%|
[openbl_60d](#openbl_60d)|7012|7012|922|13.1%|26.1%|
[openbl_30d](#openbl_30d)|2835|2835|736|25.9%|20.8%|
[et_compromised](#et_compromised)|1721|1721|645|37.4%|18.2%|
[bruteforceblocker](#bruteforceblocker)|1711|1711|639|37.3%|18.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|513|0.0%|14.5%|
[shunlist](#shunlist)|1225|1225|386|31.5%|10.9%|
[openbl_7d](#openbl_7d)|679|679|378|55.6%|10.7%|
[et_block](#et_block)|1000|18344011|153|0.0%|4.3%|
[firehol_level1](#firehol_level1)|5135|688894845|142|0.0%|4.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|138|0.0%|3.9%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|134|0.0%|3.7%|
[openbl_1d](#openbl_1d)|158|158|121|76.5%|3.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|59|0.0%|1.6%|
[blocklist_de_strongips](#blocklist_de_strongips)|180|180|29|16.1%|0.8%|
[stopforumspam_30d](#stopforumspam_30d)|94424|94424|24|0.0%|0.6%|
[dragon_http](#dragon_http)|1044|273664|16|0.0%|0.4%|
[dshield](#dshield)|20|5120|8|0.1%|0.2%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|6|0.0%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|6|0.0%|0.1%|
[sorbs_spam](#sorbs_spam)|59772|60402|4|0.0%|0.1%|
[sorbs_recent_spam](#sorbs_recent_spam)|59772|60402|4|0.0%|0.1%|
[sorbs_new_spam](#sorbs_new_spam)|59772|60402|4|0.0%|0.1%|
[ciarmy](#ciarmy)|457|457|4|0.8%|0.1%|
[nixspam](#nixspam)|39994|39994|3|0.0%|0.0%|
[voipbl](#voipbl)|10533|10945|2|0.0%|0.0%|
[firehol_anonymous](#firehol_anonymous)|18837|82872|2|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7581|7581|1|0.0%|0.0%|
[php_spammers](#php_spammers)|700|700|1|0.1%|0.0%|
[php_commenters](#php_commenters)|430|430|1|0.2%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|1|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|1|0.0%|0.0%|
[firehol_proxies](#firehol_proxies)|12404|12670|1|0.0%|0.0%|
[et_tor](#et_tor)|6400|6400|1|0.0%|0.0%|
[dm_tor](#dm_tor)|6548|6548|1|0.0%|0.0%|
[bm_tor](#bm_tor)|6552|6552|1|0.0%|0.0%|

## blocklist_de_strongips

[Blocklist.de](https://www.blocklist.de/) All IPs which are older then 2 month and have more then 5.000 attacks.

Source is downloaded from [this link](http://lists.blocklist.de/lists/strongips.txt).

The last time downloaded was found to be dated: Wed Jun 10 20:10:11 UTC 2015.

The ipset `blocklist_de_strongips` has **180** entries, **180** unique IPs.

The following table shows the overlaps of `blocklist_de_strongips` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_strongips`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_strongips`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_strongips`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|23442|35072|180|0.5%|100.0%|
[blocklist_de](#blocklist_de)|29619|29619|180|0.6%|100.0%|
[firehol_level3](#firehol_level3)|110214|9627951|163|0.0%|90.5%|
[stopforumspam_30d](#stopforumspam_30d)|94424|94424|137|0.1%|76.1%|
[blocklist_de_bots](#blocklist_de_bots)|2933|2933|131|4.4%|72.7%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|117|0.3%|65.0%|
[stopforumspam_1d](#stopforumspam_1d)|6808|6808|114|1.6%|63.3%|
[php_commenters](#php_commenters)|430|430|47|10.9%|26.1%|
[blocklist_de_apache](#blocklist_de_apache)|15426|15426|36|0.2%|20.0%|
[alienvault_reputation](#alienvault_reputation)|187115|187115|35|0.0%|19.4%|
[blocklist_de_ssh](#blocklist_de_ssh)|3530|3530|29|0.8%|16.1%|
[openbl_60d](#openbl_60d)|7012|7012|25|0.3%|13.8%|
[openbl_7d](#openbl_7d)|679|679|24|3.5%|13.3%|
[openbl_30d](#openbl_30d)|2835|2835|24|0.8%|13.3%|
[blocklist_de_mail](#blocklist_de_mail)|17415|17415|22|0.1%|12.2%|
[shunlist](#shunlist)|1225|1225|19|1.5%|10.5%|
[openbl_1d](#openbl_1d)|158|158|19|12.0%|10.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|16|0.0%|8.8%|
[firehol_level1](#firehol_level1)|5135|688894845|12|0.0%|6.6%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4071|4071|11|0.2%|6.1%|
[et_block](#et_block)|1000|18344011|10|0.0%|5.5%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|8|0.0%|4.4%|
[php_spammers](#php_spammers)|700|700|8|1.1%|4.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|8|0.0%|4.4%|
[firehol_proxies](#firehol_proxies)|12404|12670|6|0.0%|3.3%|
[firehol_anonymous](#firehol_anonymous)|18837|82872|6|0.0%|3.3%|
[xroxy](#xroxy)|2159|2159|5|0.2%|2.7%|
[ri_web_proxies](#ri_web_proxies)|7581|7581|5|0.0%|2.7%|
[proxz](#proxz)|1236|1236|5|0.4%|2.7%|
[proxyrss](#proxyrss)|1669|1669|5|0.2%|2.7%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|4|0.0%|2.2%|
[php_dictionary](#php_dictionary)|702|702|3|0.4%|1.6%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|1.6%|
[sorbs_spam](#sorbs_spam)|59772|60402|2|0.0%|1.1%|
[sorbs_recent_spam](#sorbs_recent_spam)|59772|60402|2|0.0%|1.1%|
[sorbs_new_spam](#sorbs_new_spam)|59772|60402|2|0.0%|1.1%|
[snort_ipfilter](#snort_ipfilter)|10158|10158|2|0.0%|1.1%|
[php_harvesters](#php_harvesters)|378|378|2|0.5%|1.1%|
[nixspam](#nixspam)|39994|39994|2|0.0%|1.1%|
[dragon_http](#dragon_http)|1044|273664|2|0.0%|1.1%|
[blocklist_de_ftp](#blocklist_de_ftp)|1333|1333|2|0.1%|1.1%|
[sorbs_web](#sorbs_web)|411|412|1|0.2%|0.5%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|1|0.0%|0.5%|
[dshield](#dshield)|20|5120|1|0.0%|0.5%|

## bm_tor

[torstatus.blutmagie.de](https://torstatus.blutmagie.de) list of all TOR network servers

Source is downloaded from [this link](https://torstatus.blutmagie.de/ip_list_all.php/Tor_ip_list_ALL.csv).

The last time downloaded was found to be dated: Wed Jun 10 20:27:02 UTC 2015.

The ipset `bm_tor` has **6552** entries, **6552** unique IPs.

The following table shows the overlaps of `bm_tor` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `bm_tor`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `bm_tor`.
- ` this % ` is the percentage **of this ipset (`bm_tor`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_anonymous](#firehol_anonymous)|18837|82872|6552|7.9%|100.0%|
[dm_tor](#dm_tor)|6548|6548|6548|100.0%|99.9%|
[et_tor](#et_tor)|6400|6400|5965|93.2%|91.0%|
[firehol_level3](#firehol_level3)|110214|9627951|1116|0.0%|17.0%|
[snort_ipfilter](#snort_ipfilter)|10158|10158|1079|10.6%|16.4%|
[stopforumspam_30d](#stopforumspam_30d)|94424|94424|645|0.6%|9.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|629|0.0%|9.6%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|523|1.7%|7.9%|
[firehol_level2](#firehol_level2)|23442|35072|391|1.1%|5.9%|
[stopforumspam_1d](#stopforumspam_1d)|6808|6808|379|5.5%|5.7%|
[firehol_proxies](#firehol_proxies)|12404|12670|239|1.8%|3.6%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|234|44.6%|3.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|181|0.0%|2.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|164|0.0%|2.5%|
[php_commenters](#php_commenters)|430|430|51|11.8%|0.7%|
[alienvault_reputation](#alienvault_reputation)|187115|187115|42|0.0%|0.6%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|22|0.0%|0.3%|
[blocklist_de](#blocklist_de)|29619|29619|20|0.0%|0.3%|
[openbl_60d](#openbl_60d)|7012|7012|19|0.2%|0.2%|
[blocklist_de_apache](#blocklist_de_apache)|15426|15426|19|0.1%|0.2%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4071|4071|16|0.3%|0.2%|
[dragon_http](#dragon_http)|1044|273664|10|0.0%|0.1%|
[php_harvesters](#php_harvesters)|378|378|7|1.8%|0.1%|
[ri_web_proxies](#ri_web_proxies)|7581|7581|5|0.0%|0.0%|
[php_spammers](#php_spammers)|700|700|5|0.7%|0.0%|
[sorbs_spam](#sorbs_spam)|59772|60402|4|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|59772|60402|4|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|59772|60402|4|0.0%|0.0%|
[php_dictionary](#php_dictionary)|702|702|4|0.5%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|4|0.0%|0.0%|
[voipbl](#voipbl)|10533|10945|3|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|3|0.0%|0.0%|
[nixspam](#nixspam)|39994|39994|3|0.0%|0.0%|
[firehol_level1](#firehol_level1)|5135|688894845|3|0.0%|0.0%|
[et_block](#et_block)|1000|18344011|3|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|17415|17415|3|0.0%|0.0%|
[xroxy](#xroxy)|2159|2159|2|0.0%|0.0%|
[shunlist](#shunlist)|1225|1225|1|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2737|2737|1|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3530|3530|1|0.0%|0.0%|

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
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|5|0.0%|0.0%|
[firehol_level3](#firehol_level3)|110214|9627951|3|0.0%|0.0%|
[php_harvesters](#php_harvesters)|378|378|1|0.2%|0.0%|
[php_commenters](#php_commenters)|430|430|1|0.2%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.0%|
[ciarmy](#ciarmy)|457|457|1|0.2%|0.0%|

## bruteforceblocker

[danger.rulez.sk](http://danger.rulez.sk/) IPs detected by [bruteforceblocker](http://danger.rulez.sk/index.php/bruteforceblocker/) (fail2ban alternative for SSH on OpenBSD). This is an automatically generated list from users reporting failed authentication attempts. An IP seems to be included if 3 or more users report it. Its retention pocily seems 30 days.

Source is downloaded from [this link](http://danger.rulez.sk/projects/bruteforceblocker/blist.php).

The last time downloaded was found to be dated: Wed Jun 10 19:27:11 UTC 2015.

The ipset `bruteforceblocker` has **1711** entries, **1711** unique IPs.

The following table shows the overlaps of `bruteforceblocker` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `bruteforceblocker`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `bruteforceblocker`.
- ` this % ` is the percentage **of this ipset (`bruteforceblocker`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level3](#firehol_level3)|110214|9627951|1711|0.0%|100.0%|
[et_compromised](#et_compromised)|1721|1721|1676|97.3%|97.9%|
[alienvault_reputation](#alienvault_reputation)|187115|187115|1093|0.5%|63.8%|
[openbl_60d](#openbl_60d)|7012|7012|982|14.0%|57.3%|
[openbl_30d](#openbl_30d)|2835|2835|917|32.3%|53.5%|
[firehol_level2](#firehol_level2)|23442|35072|648|1.8%|37.8%|
[blocklist_de](#blocklist_de)|29619|29619|647|2.1%|37.8%|
[blocklist_de_ssh](#blocklist_de_ssh)|3530|3530|639|18.1%|37.3%|
[shunlist](#shunlist)|1225|1225|395|32.2%|23.0%|
[openbl_7d](#openbl_7d)|679|679|323|47.5%|18.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|156|0.0%|9.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|89|0.0%|5.2%|
[et_block](#et_block)|1000|18344011|82|0.0%|4.7%|
[firehol_level1](#firehol_level1)|5135|688894845|81|0.0%|4.7%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|74|0.0%|4.3%|
[openbl_1d](#openbl_1d)|158|158|64|40.5%|3.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|53|0.0%|3.0%|
[stopforumspam_30d](#stopforumspam_30d)|94424|94424|12|0.0%|0.7%|
[dragon_http](#dragon_http)|1044|273664|12|0.0%|0.7%|
[dshield](#dshield)|20|5120|7|0.1%|0.4%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|5|0.0%|0.2%|
[blocklist_de_mail](#blocklist_de_mail)|17415|17415|5|0.0%|0.2%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|4|0.0%|0.2%|
[blocklist_de_imap](#blocklist_de_imap)|2383|2383|4|0.1%|0.2%|
[voipbl](#voipbl)|10533|10945|3|0.0%|0.1%|
[sorbs_spam](#sorbs_spam)|59772|60402|3|0.0%|0.1%|
[sorbs_recent_spam](#sorbs_recent_spam)|59772|60402|3|0.0%|0.1%|
[sorbs_new_spam](#sorbs_new_spam)|59772|60402|3|0.0%|0.1%|
[nixspam](#nixspam)|39994|39994|3|0.0%|0.1%|
[firehol_proxies](#firehol_proxies)|12404|12670|3|0.0%|0.1%|
[firehol_anonymous](#firehol_anonymous)|18837|82872|3|0.0%|0.1%|
[proxz](#proxz)|1236|1236|2|0.1%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|2|0.0%|0.1%|
[ciarmy](#ciarmy)|457|457|2|0.4%|0.1%|
[xroxy](#xroxy)|2159|2159|1|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6808|6808|1|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|10158|10158|1|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7581|7581|1|0.0%|0.0%|
[proxyrss](#proxyrss)|1669|1669|1|0.0%|0.0%|
[php_spammers](#php_spammers)|700|700|1|0.1%|0.0%|
[php_commenters](#php_commenters)|430|430|1|0.2%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|2933|2933|1|0.0%|0.0%|

## ciarmy

[CIArmy.com](http://ciarmy.com/) IPs with poor Rogue Packet score that have not yet been identified as malicious by the community

Source is downloaded from [this link](http://cinsscore.com/list/ci-badguys.txt).

The last time downloaded was found to be dated: Wed Jun 10 19:15:07 UTC 2015.

The ipset `ciarmy` has **457** entries, **457** unique IPs.

The following table shows the overlaps of `ciarmy` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ciarmy`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ciarmy`.
- ` this % ` is the percentage **of this ipset (`ciarmy`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level3](#firehol_level3)|110214|9627951|457|0.0%|100.0%|
[alienvault_reputation](#alienvault_reputation)|187115|187115|450|0.2%|98.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|100|0.0%|21.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|49|0.0%|10.7%|
[firehol_level2](#firehol_level2)|23442|35072|42|0.1%|9.1%|
[blocklist_de](#blocklist_de)|29619|29619|42|0.1%|9.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|36|0.0%|7.8%|
[blocklist_de_apache](#blocklist_de_apache)|15426|15426|33|0.2%|7.2%|
[shunlist](#shunlist)|1225|1225|30|2.4%|6.5%|
[dragon_http](#dragon_http)|1044|273664|9|0.0%|1.9%|
[et_block](#et_block)|1000|18344011|6|0.0%|1.3%|
[firehol_level1](#firehol_level1)|5135|688894845|5|0.0%|1.0%|
[dshield](#dshield)|20|5120|4|0.0%|0.8%|
[blocklist_de_ssh](#blocklist_de_ssh)|3530|3530|4|0.1%|0.8%|
[blocklist_de_mail](#blocklist_de_mail)|17415|17415|4|0.0%|0.8%|
[blocklist_de_imap](#blocklist_de_imap)|2383|2383|4|0.1%|0.8%|
[stopforumspam_30d](#stopforumspam_30d)|94424|94424|2|0.0%|0.4%|
[openbl_7d](#openbl_7d)|679|679|2|0.2%|0.4%|
[openbl_60d](#openbl_60d)|7012|7012|2|0.0%|0.4%|
[openbl_30d](#openbl_30d)|2835|2835|2|0.0%|0.4%|
[et_compromised](#et_compromised)|1721|1721|2|0.1%|0.4%|
[bruteforceblocker](#bruteforceblocker)|1711|1711|2|0.1%|0.4%|
[voipbl](#voipbl)|10533|10945|1|0.0%|0.2%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|1|0.0%|0.2%|
[openbl_1d](#openbl_1d)|158|158|1|0.6%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.2%|
[fullbogons](#fullbogons)|3770|670213096|1|0.0%|0.2%|
[bogons](#bogons)|13|592708608|1|0.0%|0.2%|
[blocklist_de_ftp](#blocklist_de_ftp)|1333|1333|1|0.0%|0.2%|

## cleanmx_viruses

[Clean-MX.de](http://support.clean-mx.de/clean-mx/viruses.php) IPs with viruses

Source is downloaded from [this link](http://support.clean-mx.de/clean-mx/xmlviruses.php?sort=id%20desc&response=alive).

The last time downloaded was found to be dated: Wed Jun 10 08:54:12 UTC 2015.

The ipset `cleanmx_viruses` has **123** entries, **123** unique IPs.

The following table shows the overlaps of `cleanmx_viruses` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `cleanmx_viruses`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `cleanmx_viruses`.
- ` this % ` is the percentage **of this ipset (`cleanmx_viruses`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level3](#firehol_level3)|110214|9627951|123|0.0%|100.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|16|0.0%|13.0%|
[malc0de](#malc0de)|313|313|13|4.1%|10.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|3|0.0%|2.4%|
[alienvault_reputation](#alienvault_reputation)|187115|187115|3|0.0%|2.4%|
[snort_ipfilter](#snort_ipfilter)|10158|10158|2|0.0%|1.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|2|0.0%|1.6%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|1|0.0%|0.8%|

## dm_tor

[dan.me.uk](https://www.dan.me.uk) dynamic list of TOR exit points

Source is downloaded from [this link](https://www.dan.me.uk/torlist/).

The last time downloaded was found to be dated: Wed Jun 10 20:09:10 UTC 2015.

The ipset `dm_tor` has **6548** entries, **6548** unique IPs.

The following table shows the overlaps of `dm_tor` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `dm_tor`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `dm_tor`.
- ` this % ` is the percentage **of this ipset (`dm_tor`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_anonymous](#firehol_anonymous)|18837|82872|6548|7.9%|100.0%|
[bm_tor](#bm_tor)|6552|6552|6548|99.9%|100.0%|
[et_tor](#et_tor)|6400|6400|5961|93.1%|91.0%|
[firehol_level3](#firehol_level3)|110214|9627951|1115|0.0%|17.0%|
[snort_ipfilter](#snort_ipfilter)|10158|10158|1078|10.6%|16.4%|
[stopforumspam_30d](#stopforumspam_30d)|94424|94424|645|0.6%|9.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|629|0.0%|9.6%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|523|1.7%|7.9%|
[firehol_level2](#firehol_level2)|23442|35072|391|1.1%|5.9%|
[stopforumspam_1d](#stopforumspam_1d)|6808|6808|379|5.5%|5.7%|
[firehol_proxies](#firehol_proxies)|12404|12670|239|1.8%|3.6%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|234|44.6%|3.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|181|0.0%|2.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|164|0.0%|2.5%|
[php_commenters](#php_commenters)|430|430|51|11.8%|0.7%|
[alienvault_reputation](#alienvault_reputation)|187115|187115|42|0.0%|0.6%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|22|0.0%|0.3%|
[blocklist_de](#blocklist_de)|29619|29619|20|0.0%|0.3%|
[openbl_60d](#openbl_60d)|7012|7012|19|0.2%|0.2%|
[blocklist_de_apache](#blocklist_de_apache)|15426|15426|19|0.1%|0.2%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4071|4071|16|0.3%|0.2%|
[dragon_http](#dragon_http)|1044|273664|10|0.0%|0.1%|
[php_harvesters](#php_harvesters)|378|378|7|1.8%|0.1%|
[ri_web_proxies](#ri_web_proxies)|7581|7581|5|0.0%|0.0%|
[php_spammers](#php_spammers)|700|700|5|0.7%|0.0%|
[sorbs_spam](#sorbs_spam)|59772|60402|4|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|59772|60402|4|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|59772|60402|4|0.0%|0.0%|
[php_dictionary](#php_dictionary)|702|702|4|0.5%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|4|0.0%|0.0%|
[voipbl](#voipbl)|10533|10945|3|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|3|0.0%|0.0%|
[nixspam](#nixspam)|39994|39994|3|0.0%|0.0%|
[firehol_level1](#firehol_level1)|5135|688894845|3|0.0%|0.0%|
[et_block](#et_block)|1000|18344011|3|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|17415|17415|3|0.0%|0.0%|
[xroxy](#xroxy)|2159|2159|2|0.0%|0.0%|
[shunlist](#shunlist)|1225|1225|1|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2737|2737|1|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3530|3530|1|0.0%|0.0%|

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
[alienvault_reputation](#alienvault_reputation)|187115|187115|5646|3.0%|2.0%|
[firehol_level1](#firehol_level1)|5135|688894845|1537|0.0%|0.5%|
[dshield](#dshield)|20|5120|1280|25.0%|0.4%|
[et_block](#et_block)|1000|18344011|1024|0.0%|0.3%|
[firehol_level3](#firehol_level3)|110214|9627951|565|0.0%|0.2%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|256|0.0%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|256|0.0%|0.0%|
[openbl_60d](#openbl_60d)|7012|7012|223|3.1%|0.0%|
[openbl_30d](#openbl_30d)|2835|2835|154|5.4%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|94424|94424|115|0.1%|0.0%|
[firehol_level2](#firehol_level2)|23442|35072|65|0.1%|0.0%|
[openbl_7d](#openbl_7d)|679|679|60|8.8%|0.0%|
[sorbs_spam](#sorbs_spam)|59772|60402|58|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|59772|60402|58|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|59772|60402|58|0.0%|0.0%|
[blocklist_de](#blocklist_de)|29619|29619|55|0.1%|0.0%|
[nixspam](#nixspam)|39994|39994|38|0.0%|0.0%|
[firehol_anonymous](#firehol_anonymous)|18837|82872|38|0.0%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|37|0.1%|0.0%|
[shunlist](#shunlist)|1225|1225|37|3.0%|0.0%|
[firehol_proxies](#firehol_proxies)|12404|12670|29|0.2%|0.0%|
[voipbl](#voipbl)|10533|10945|25|0.2%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|24|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7581|7581|16|0.2%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3530|3530|16|0.4%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|17415|17415|16|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|15426|15426|13|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1711|1711|12|0.7%|0.0%|
[et_tor](#et_tor)|6400|6400|11|0.1%|0.0%|
[et_compromised](#et_compromised)|1721|1721|11|0.6%|0.0%|
[openbl_1d](#openbl_1d)|158|158|10|6.3%|0.0%|
[dm_tor](#dm_tor)|6548|6548|10|0.1%|0.0%|
[bm_tor](#bm_tor)|6552|6552|10|0.1%|0.0%|
[ciarmy](#ciarmy)|457|457|9|1.9%|0.0%|
[xroxy](#xroxy)|2159|2159|8|0.3%|0.0%|
[snort_ipfilter](#snort_ipfilter)|10158|10158|7|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6808|6808|6|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|6|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2383|2383|6|0.2%|0.0%|
[proxz](#proxz)|1236|1236|4|0.3%|0.0%|
[et_botcc](#et_botcc)|506|506|4|0.7%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|1333|1333|4|0.3%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4071|4071|4|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|2933|2933|4|0.1%|0.0%|
[zeus_badips](#zeus_badips)|202|202|3|1.4%|0.0%|
[zeus](#zeus)|230|230|3|1.3%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2737|2737|3|0.1%|0.0%|
[malc0de](#malc0de)|313|313|3|0.9%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|3|0.2%|0.0%|
[proxyrss](#proxyrss)|1669|1669|2|0.1%|0.0%|
[php_dictionary](#php_dictionary)|702|702|2|0.2%|0.0%|
[php_commenters](#php_commenters)|430|430|2|0.4%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|2|0.3%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|2|0.1%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|180|180|2|1.1%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|79|79|2|2.5%|0.0%|
[sslbl](#sslbl)|372|372|1|0.2%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|1|0.1%|0.0%|

## dshield

[DShield.org](https://dshield.org/) top 20 attacking class C (/24) subnets over the last three days - **excellent list**

Source is downloaded from [this link](http://feeds.dshield.org/block.txt).

The last time downloaded was found to be dated: Wed Jun 10 19:57:39 UTC 2015.

The ipset `dshield` has **20** entries, **5120** unique IPs.

The following table shows the overlaps of `dshield` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `dshield`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `dshield`.
- ` this % ` is the percentage **of this ipset (`dshield`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level1](#firehol_level1)|5135|688894845|5120|0.0%|100.0%|
[alienvault_reputation](#alienvault_reputation)|187115|187115|3075|1.6%|60.0%|
[et_block](#et_block)|1000|18344011|1536|0.0%|30.0%|
[dragon_http](#dragon_http)|1044|273664|1280|0.4%|25.0%|
[firehol_level3](#firehol_level3)|110214|9627951|49|0.0%|0.9%|
[openbl_60d](#openbl_60d)|7012|7012|45|0.6%|0.8%|
[openbl_30d](#openbl_30d)|2835|2835|33|1.1%|0.6%|
[shunlist](#shunlist)|1225|1225|20|1.6%|0.3%|
[firehol_level2](#firehol_level2)|23442|35072|18|0.0%|0.3%|
[blocklist_de](#blocklist_de)|29619|29619|18|0.0%|0.3%|
[blocklist_de_apache](#blocklist_de_apache)|15426|15426|9|0.0%|0.1%|
[blocklist_de_ssh](#blocklist_de_ssh)|3530|3530|8|0.2%|0.1%|
[et_compromised](#et_compromised)|1721|1721|7|0.4%|0.1%|
[bruteforceblocker](#bruteforceblocker)|1711|1711|7|0.4%|0.1%|
[openbl_7d](#openbl_7d)|679|679|5|0.7%|0.0%|
[ciarmy](#ciarmy)|457|457|4|0.8%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|94424|94424|3|0.0%|0.0%|
[openbl_1d](#openbl_1d)|158|158|3|1.8%|0.0%|
[malc0de](#malc0de)|313|313|2|0.6%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|1|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|10158|10158|1|0.0%|0.0%|
[nixspam](#nixspam)|39994|39994|1|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|180|180|1|0.5%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|17415|17415|1|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4071|4071|1|0.0%|0.0%|

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
[firehol_level1](#firehol_level1)|5135|688894845|18340425|2.6%|99.9%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|18338560|99.9%|99.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|8532520|2.4%|46.5%|
[firehol_level3](#firehol_level3)|110214|9627951|6933378|72.0%|37.7%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|6932480|75.5%|37.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|2272548|0.2%|12.3%|
[fullbogons](#fullbogons)|3770|670213096|151552|0.0%|0.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|130394|0.0%|0.7%|
[alienvault_reputation](#alienvault_reputation)|187115|187115|4764|2.5%|0.0%|
[dshield](#dshield)|20|5120|1536|30.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1042|0.3%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|94424|94424|1025|1.0%|0.0%|
[dragon_http](#dragon_http)|1044|273664|1024|0.3%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|517|0.1%|0.0%|
[firehol_level2](#firehol_level2)|23442|35072|312|0.8%|0.0%|
[openbl_60d](#openbl_60d)|7012|7012|301|4.2%|0.0%|
[snort_ipfilter](#snort_ipfilter)|10158|10158|298|2.9%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|295|1.0%|0.0%|
[blocklist_de](#blocklist_de)|29619|29619|246|0.8%|0.0%|
[zeus](#zeus)|230|230|228|99.1%|0.0%|
[zeus_badips](#zeus_badips)|202|202|202|100.0%|0.0%|
[openbl_30d](#openbl_30d)|2835|2835|163|5.7%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3530|3530|153|4.3%|0.0%|
[shunlist](#shunlist)|1225|1225|113|9.2%|0.0%|
[et_compromised](#et_compromised)|1721|1721|109|6.3%|0.0%|
[feodo](#feodo)|105|105|104|99.0%|0.0%|
[nixspam](#nixspam)|39994|39994|88|0.2%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1711|1711|82|4.7%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6808|6808|79|1.1%|0.0%|
[openbl_7d](#openbl_7d)|679|679|61|8.9%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|2933|2933|58|1.9%|0.0%|
[sslbl](#sslbl)|372|372|38|10.2%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|30|2.3%|0.0%|
[php_commenters](#php_commenters)|430|430|29|6.7%|0.0%|
[sorbs_spam](#sorbs_spam)|59772|60402|22|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|59772|60402|22|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|59772|60402|22|0.0%|0.0%|
[openbl_1d](#openbl_1d)|158|158|19|12.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|17415|17415|19|0.1%|0.0%|
[voipbl](#voipbl)|10533|10945|14|0.1%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|15426|15426|13|0.0%|0.0%|
[palevo](#palevo)|13|13|12|92.3%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|180|180|10|5.5%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2383|2383|9|0.3%|0.0%|
[php_dictionary](#php_dictionary)|702|702|6|0.8%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|6|0.4%|0.0%|
[firehol_anonymous](#firehol_anonymous)|18837|82872|6|0.0%|0.0%|
[ciarmy](#ciarmy)|457|457|6|1.3%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4071|4071|6|0.1%|0.0%|
[malc0de](#malc0de)|313|313|5|1.5%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|5|0.0%|0.0%|
[php_spammers](#php_spammers)|700|700|4|0.5%|0.0%|
[firehol_proxies](#firehol_proxies)|12404|12670|3|0.0%|0.0%|
[et_tor](#et_tor)|6400|6400|3|0.0%|0.0%|
[dm_tor](#dm_tor)|6548|6548|3|0.0%|0.0%|
[bm_tor](#bm_tor)|6552|6552|3|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|2|0.3%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|79|79|2|2.5%|0.0%|
[php_harvesters](#php_harvesters)|378|378|1|0.2%|0.0%|
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
[alienvault_reputation](#alienvault_reputation)|187115|187115|4|0.0%|0.7%|
[firehol_level3](#firehol_level3)|110214|9627951|3|0.0%|0.5%|
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
[firehol_level3](#firehol_level3)|110214|9627951|1709|0.0%|99.3%|
[bruteforceblocker](#bruteforceblocker)|1711|1711|1676|97.9%|97.3%|
[alienvault_reputation](#alienvault_reputation)|187115|187115|1117|0.5%|64.9%|
[openbl_60d](#openbl_60d)|7012|7012|1009|14.3%|58.6%|
[openbl_30d](#openbl_30d)|2835|2835|941|33.1%|54.6%|
[firehol_level2](#firehol_level2)|23442|35072|654|1.8%|38.0%|
[blocklist_de](#blocklist_de)|29619|29619|653|2.2%|37.9%|
[blocklist_de_ssh](#blocklist_de_ssh)|3530|3530|645|18.2%|37.4%|
[shunlist](#shunlist)|1225|1225|421|34.3%|24.4%|
[openbl_7d](#openbl_7d)|679|679|324|47.7%|18.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|152|0.0%|8.8%|
[et_block](#et_block)|1000|18344011|109|0.0%|6.3%|
[firehol_level1](#firehol_level1)|5135|688894845|108|0.0%|6.2%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|101|0.0%|5.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|85|0.0%|4.9%|
[openbl_1d](#openbl_1d)|158|158|64|40.5%|3.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|52|0.0%|3.0%|
[stopforumspam_30d](#stopforumspam_30d)|94424|94424|12|0.0%|0.6%|
[dragon_http](#dragon_http)|1044|273664|11|0.0%|0.6%|
[dshield](#dshield)|20|5120|7|0.1%|0.4%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|5|0.0%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|5|0.0%|0.2%|
[blocklist_de_mail](#blocklist_de_mail)|17415|17415|5|0.0%|0.2%|
[blocklist_de_imap](#blocklist_de_imap)|2383|2383|4|0.1%|0.2%|
[voipbl](#voipbl)|10533|10945|3|0.0%|0.1%|
[sorbs_spam](#sorbs_spam)|59772|60402|3|0.0%|0.1%|
[sorbs_recent_spam](#sorbs_recent_spam)|59772|60402|3|0.0%|0.1%|
[sorbs_new_spam](#sorbs_new_spam)|59772|60402|3|0.0%|0.1%|
[nixspam](#nixspam)|39994|39994|3|0.0%|0.1%|
[firehol_proxies](#firehol_proxies)|12404|12670|3|0.0%|0.1%|
[firehol_anonymous](#firehol_anonymous)|18837|82872|3|0.0%|0.1%|
[proxz](#proxz)|1236|1236|2|0.1%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|2|0.0%|0.1%|
[ciarmy](#ciarmy)|457|457|2|0.4%|0.1%|
[xroxy](#xroxy)|2159|2159|1|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6808|6808|1|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|10158|10158|1|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7581|7581|1|0.0%|0.0%|
[proxyrss](#proxyrss)|1669|1669|1|0.0%|0.0%|
[php_spammers](#php_spammers)|700|700|1|0.1%|0.0%|
[php_commenters](#php_commenters)|430|430|1|0.2%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|2933|2933|1|0.0%|0.0%|

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
[firehol_anonymous](#firehol_anonymous)|18837|82872|5967|7.2%|93.2%|
[bm_tor](#bm_tor)|6552|6552|5965|91.0%|93.2%|
[dm_tor](#dm_tor)|6548|6548|5961|91.0%|93.1%|
[firehol_level3](#firehol_level3)|110214|9627951|1126|0.0%|17.5%|
[snort_ipfilter](#snort_ipfilter)|10158|10158|1089|10.7%|17.0%|
[stopforumspam_30d](#stopforumspam_30d)|94424|94424|649|0.6%|10.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|625|0.0%|9.7%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|530|1.8%|8.2%|
[firehol_level2](#firehol_level2)|23442|35072|394|1.1%|6.1%|
[stopforumspam_1d](#stopforumspam_1d)|6808|6808|381|5.5%|5.9%|
[firehol_proxies](#firehol_proxies)|12404|12670|238|1.8%|3.7%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|234|44.6%|3.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|181|0.0%|2.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|165|0.0%|2.5%|
[php_commenters](#php_commenters)|430|430|51|11.8%|0.7%|
[alienvault_reputation](#alienvault_reputation)|187115|187115|40|0.0%|0.6%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|22|0.0%|0.3%|
[openbl_60d](#openbl_60d)|7012|7012|20|0.2%|0.3%|
[blocklist_de](#blocklist_de)|29619|29619|20|0.0%|0.3%|
[blocklist_de_apache](#blocklist_de_apache)|15426|15426|19|0.1%|0.2%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4071|4071|17|0.4%|0.2%|
[dragon_http](#dragon_http)|1044|273664|11|0.0%|0.1%|
[php_harvesters](#php_harvesters)|378|378|7|1.8%|0.1%|
[php_spammers](#php_spammers)|700|700|5|0.7%|0.0%|
[sorbs_spam](#sorbs_spam)|59772|60402|4|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|59772|60402|4|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|59772|60402|4|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7581|7581|4|0.0%|0.0%|
[php_dictionary](#php_dictionary)|702|702|4|0.5%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|4|0.0%|0.0%|
[voipbl](#voipbl)|10533|10945|3|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|3|0.0%|0.0%|
[nixspam](#nixspam)|39994|39994|3|0.0%|0.0%|
[firehol_level1](#firehol_level1)|5135|688894845|3|0.0%|0.0%|
[et_block](#et_block)|1000|18344011|3|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|17415|17415|2|0.0%|0.0%|
[xroxy](#xroxy)|2159|2159|1|0.0%|0.0%|
[shunlist](#shunlist)|1225|1225|1|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3530|3530|1|0.0%|0.0%|

## feodo

[Abuse.ch Feodo tracker](https://feodotracker.abuse.ch) trojan includes IPs which are being used by Feodo (also known as Cridex or Bugat) which commits ebanking fraud - **excellent list**

Source is downloaded from [this link](https://feodotracker.abuse.ch/blocklist/?download=ipblocklist).

The last time downloaded was found to be dated: Wed Jun 10 20:27:10 UTC 2015.

The ipset `feodo` has **105** entries, **105** unique IPs.

The following table shows the overlaps of `feodo` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `feodo`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `feodo`.
- ` this % ` is the percentage **of this ipset (`feodo`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level1](#firehol_level1)|5135|688894845|105|0.0%|100.0%|
[et_block](#et_block)|1000|18344011|104|0.0%|99.0%|
[snort_ipfilter](#snort_ipfilter)|10158|10158|83|0.8%|79.0%|
[firehol_level3](#firehol_level3)|110214|9627951|83|0.0%|79.0%|
[sslbl](#sslbl)|372|372|38|10.2%|36.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|11|0.0%|10.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|3|0.0%|2.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|3|0.0%|2.8%|
[alienvault_reputation](#alienvault_reputation)|187115|187115|2|0.0%|1.9%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.9%|

## firehol_anonymous

**FireHOL Anonymous** - Known anonymizing IPs. (includes: firehol_proxies anonymous bm_tor dm_tor)

Source is downloaded from [this link]().

The last time downloaded was found to be dated: Sun Jun  7 22:20:34 UTC 2015.

The ipset `firehol_anonymous` has **18837** entries, **82872** unique IPs.

The following table shows the overlaps of `firehol_anonymous` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `firehol_anonymous`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `firehol_anonymous`.
- ` this % ` is the percentage **of this ipset (`firehol_anonymous`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_proxies](#firehol_proxies)|12404|12670|12670|100.0%|15.2%|
[ri_web_proxies](#ri_web_proxies)|7581|7581|7581|100.0%|9.1%|
[firehol_level3](#firehol_level3)|110214|9627951|6614|0.0%|7.9%|
[bm_tor](#bm_tor)|6552|6552|6552|100.0%|7.9%|
[dm_tor](#dm_tor)|6548|6548|6548|100.0%|7.9%|
[stopforumspam_30d](#stopforumspam_30d)|94424|94424|6082|6.4%|7.3%|
[et_tor](#et_tor)|6400|6400|5967|93.2%|7.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|3434|0.0%|4.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|2886|0.0%|3.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|2872|0.0%|3.4%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|2758|9.4%|3.3%|
[ri_connect_proxies](#ri_connect_proxies)|2737|2737|2737|100.0%|3.3%|
[xroxy](#xroxy)|2159|2159|2159|100.0%|2.6%|
[proxyrss](#proxyrss)|1669|1669|1669|100.0%|2.0%|
[firehol_level2](#firehol_level2)|23442|35072|1420|4.0%|1.7%|
[proxz](#proxz)|1236|1236|1236|100.0%|1.4%|
[snort_ipfilter](#snort_ipfilter)|10158|10158|1167|11.4%|1.4%|
[stopforumspam_1d](#stopforumspam_1d)|6808|6808|1045|15.3%|1.2%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|663|100.0%|0.8%|
[blocklist_de](#blocklist_de)|29619|29619|653|2.2%|0.7%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|524|100.0%|0.6%|
[blocklist_de_bots](#blocklist_de_bots)|2933|2933|516|17.5%|0.6%|
[sorbs_spam](#sorbs_spam)|59772|60402|182|0.3%|0.2%|
[sorbs_recent_spam](#sorbs_recent_spam)|59772|60402|182|0.3%|0.2%|
[sorbs_new_spam](#sorbs_new_spam)|59772|60402|182|0.3%|0.2%|
[nixspam](#nixspam)|39994|39994|160|0.4%|0.1%|
[blocklist_de_mail](#blocklist_de_mail)|17415|17415|111|0.6%|0.1%|
[php_dictionary](#php_dictionary)|702|702|95|13.5%|0.1%|
[php_commenters](#php_commenters)|430|430|82|19.0%|0.0%|
[php_spammers](#php_spammers)|700|700|80|11.4%|0.0%|
[voipbl](#voipbl)|10533|10945|79|0.7%|0.0%|
[alienvault_reputation](#alienvault_reputation)|187115|187115|57|0.0%|0.0%|
[dragon_http](#dragon_http)|1044|273664|38|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|28|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|15426|15426|25|0.1%|0.0%|
[openbl_60d](#openbl_60d)|7012|7012|22|0.3%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4071|4071|22|0.5%|0.0%|
[sorbs_web](#sorbs_web)|411|412|19|4.6%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|15|0.0%|0.0%|
[php_harvesters](#php_harvesters)|378|378|12|3.1%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|7|0.0%|0.0%|
[firehol_level1](#firehol_level1)|5135|688894845|7|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|6|0.0%|0.0%|
[et_block](#et_block)|1000|18344011|6|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|180|180|6|3.3%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|3|0.2%|0.0%|
[et_compromised](#et_compromised)|1721|1721|3|0.1%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1711|1711|3|0.1%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3530|3530|2|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|1333|1333|2|0.1%|0.0%|
[sslbl](#sslbl)|372|372|1|0.2%|0.0%|
[shunlist](#shunlist)|1225|1225|1|0.0%|0.0%|
[openbl_30d](#openbl_30d)|2835|2835|1|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2383|2383|1|0.0%|0.0%|

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
[spamhaus_drop](#spamhaus_drop)|653|18340608|18340608|100.0%|2.6%|
[et_block](#et_block)|1000|18344011|18340425|99.9%|2.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|8867460|2.5%|1.2%|
[firehol_level3](#firehol_level3)|110214|9627951|7500204|77.9%|1.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|7498240|81.6%|1.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|4637346|3.3%|0.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|2570274|0.3%|0.3%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|487424|100.0%|0.0%|
[dshield](#dshield)|20|5120|5120|100.0%|0.0%|
[alienvault_reputation](#alienvault_reputation)|187115|187115|4589|2.4%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1931|0.5%|0.0%|
[dragon_http](#dragon_http)|1044|273664|1537|0.5%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|94424|94424|1102|1.1%|0.0%|
[sslbl](#sslbl)|372|372|372|100.0%|0.0%|
[voipbl](#voipbl)|10533|10945|333|3.0%|0.0%|
[firehol_level2](#firehol_level2)|23442|35072|308|0.8%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|303|1.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|10158|10158|302|2.9%|0.0%|
[openbl_60d](#openbl_60d)|7012|7012|283|4.0%|0.0%|
[blocklist_de](#blocklist_de)|29619|29619|241|0.8%|0.0%|
[zeus](#zeus)|230|230|230|100.0%|0.0%|
[zeus_badips](#zeus_badips)|202|202|202|100.0%|0.0%|
[shunlist](#shunlist)|1225|1225|173|14.1%|0.0%|
[openbl_30d](#openbl_30d)|2835|2835|155|5.4%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3530|3530|142|4.0%|0.0%|
[et_compromised](#et_compromised)|1721|1721|108|6.2%|0.0%|
[feodo](#feodo)|105|105|105|100.0%|0.0%|
[nixspam](#nixspam)|39994|39994|91|0.2%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6808|6808|82|1.2%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1711|1711|81|4.7%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|2933|2933|62|2.1%|0.0%|
[openbl_7d](#openbl_7d)|679|679|56|8.2%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|39|3.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|39|2.6%|0.0%|
[php_commenters](#php_commenters)|430|430|38|8.8%|0.0%|
[sorbs_spam](#sorbs_spam)|59772|60402|25|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|59772|60402|25|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|59772|60402|25|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|17415|17415|20|0.1%|0.0%|
[openbl_1d](#openbl_1d)|158|158|18|11.3%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|18|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|15426|15426|14|0.0%|0.0%|
[palevo](#palevo)|13|13|13|100.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|180|180|12|6.6%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2383|2383|9|0.3%|0.0%|
[malc0de](#malc0de)|313|313|7|2.2%|0.0%|
[firehol_anonymous](#firehol_anonymous)|18837|82872|7|0.0%|0.0%|
[php_dictionary](#php_dictionary)|702|702|6|0.8%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4071|4071|6|0.1%|0.0%|
[ciarmy](#ciarmy)|457|457|5|1.0%|0.0%|
[php_spammers](#php_spammers)|700|700|4|0.5%|0.0%|
[firehol_proxies](#firehol_proxies)|12404|12670|4|0.0%|0.0%|
[php_harvesters](#php_harvesters)|378|378|3|0.7%|0.0%|
[et_tor](#et_tor)|6400|6400|3|0.0%|0.0%|
[dm_tor](#dm_tor)|6548|6548|3|0.0%|0.0%|
[bm_tor](#bm_tor)|6552|6552|3|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|2|0.3%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|79|79|2|2.5%|0.0%|
[virbl](#virbl)|30|30|1|3.3%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7581|7581|1|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|1|0.1%|0.0%|
[et_botcc](#et_botcc)|506|506|1|0.1%|0.0%|

## firehol_level2

**FireHOL Level 2** - Maximum protection from attacks took place in the last 48 hours. (includes: openbl_1d blocklist_de stopforumspam_1d)

Source is downloaded from [this link]().

The last time downloaded was found to be dated: Sun Jun  7 22:20:34 UTC 2015.

The ipset `firehol_level2` has **23442** entries, **35072** unique IPs.

The following table shows the overlaps of `firehol_level2` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `firehol_level2`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `firehol_level2`.
- ` this % ` is the percentage **of this ipset (`firehol_level2`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|29619|29619|29619|100.0%|84.4%|
[blocklist_de_mail](#blocklist_de_mail)|17415|17415|17409|99.9%|49.6%|
[blocklist_de_apache](#blocklist_de_apache)|15426|15426|15425|99.9%|43.9%|
[firehol_level3](#firehol_level3)|110214|9627951|8609|0.0%|24.5%|
[stopforumspam_30d](#stopforumspam_30d)|94424|94424|7315|7.7%|20.8%|
[stopforumspam_1d](#stopforumspam_1d)|6808|6808|6808|100.0%|19.4%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|5162|17.5%|14.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|4161|0.0%|11.8%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4071|4071|4071|100.0%|11.6%|
[blocklist_de_ssh](#blocklist_de_ssh)|3530|3530|3524|99.8%|10.0%|
[blocklist_de_bots](#blocklist_de_bots)|2933|2933|2922|99.6%|8.3%|
[blocklist_de_imap](#blocklist_de_imap)|2383|2383|2378|99.7%|6.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|1734|0.0%|4.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|1670|0.0%|4.7%|
[firehol_anonymous](#firehol_anonymous)|18837|82872|1420|1.7%|4.0%|
[alienvault_reputation](#alienvault_reputation)|187115|187115|1405|0.7%|4.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|1333|1333|1331|99.8%|3.7%|
[sorbs_spam](#sorbs_spam)|59772|60402|1315|2.1%|3.7%|
[sorbs_recent_spam](#sorbs_recent_spam)|59772|60402|1315|2.1%|3.7%|
[sorbs_new_spam](#sorbs_new_spam)|59772|60402|1315|2.1%|3.7%|
[firehol_proxies](#firehol_proxies)|12404|12670|1231|9.7%|3.5%|
[openbl_60d](#openbl_60d)|7012|7012|1017|14.5%|2.8%|
[nixspam](#nixspam)|39994|39994|874|2.1%|2.4%|
[openbl_30d](#openbl_30d)|2835|2835|803|28.3%|2.2%|
[ri_web_proxies](#ri_web_proxies)|7581|7581|679|8.9%|1.9%|
[et_compromised](#et_compromised)|1721|1721|654|38.0%|1.8%|
[bruteforceblocker](#bruteforceblocker)|1711|1711|648|37.8%|1.8%|
[snort_ipfilter](#snort_ipfilter)|10158|10158|603|5.9%|1.7%|
[proxyrss](#proxyrss)|1669|1669|427|25.5%|1.2%|
[openbl_7d](#openbl_7d)|679|679|424|62.4%|1.2%|
[shunlist](#shunlist)|1225|1225|423|34.5%|1.2%|
[et_tor](#et_tor)|6400|6400|394|6.1%|1.1%|
[dm_tor](#dm_tor)|6548|6548|391|5.9%|1.1%|
[bm_tor](#bm_tor)|6552|6552|391|5.9%|1.1%|
[xroxy](#xroxy)|2159|2159|330|15.2%|0.9%|
[et_block](#et_block)|1000|18344011|312|0.0%|0.8%|
[firehol_level1](#firehol_level1)|5135|688894845|308|0.0%|0.8%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|282|0.0%|0.8%|
[proxz](#proxz)|1236|1236|264|21.3%|0.7%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|228|43.5%|0.6%|
[php_commenters](#php_commenters)|430|430|197|45.8%|0.5%|
[blocklist_de_strongips](#blocklist_de_strongips)|180|180|180|100.0%|0.5%|
[openbl_1d](#openbl_1d)|158|158|158|100.0%|0.4%|
[ri_connect_proxies](#ri_connect_proxies)|2737|2737|155|5.6%|0.4%|
[php_dictionary](#php_dictionary)|702|702|116|16.5%|0.3%|
[php_spammers](#php_spammers)|700|700|109|15.5%|0.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|91|0.0%|0.2%|
[dragon_http](#dragon_http)|1044|273664|65|0.0%|0.1%|
[php_harvesters](#php_harvesters)|378|378|60|15.8%|0.1%|
[blocklist_de_sip](#blocklist_de_sip)|79|79|60|75.9%|0.1%|
[sorbs_web](#sorbs_web)|411|412|54|13.1%|0.1%|
[ciarmy](#ciarmy)|457|457|42|9.1%|0.1%|
[voipbl](#voipbl)|10533|10945|35|0.3%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|20|0.0%|0.0%|
[dshield](#dshield)|20|5120|18|0.3%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|13|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|7|1.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|6|0.0%|0.0%|
[zeus_badips](#zeus_badips)|202|202|3|1.4%|0.0%|
[zeus](#zeus)|230|230|3|1.3%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|3|0.2%|0.0%|
[fullbogons](#fullbogons)|3770|670213096|1|0.0%|0.0%|

## firehol_level3

**FireHOL Level 3** - All the bad IPs in last 30 days. (includes: openbl_30d stopforumspam_30d virbl malc0de shunlist malwaredomainlist bruteforceblocker ciarmy cleanmx_viruses snort_ipfilter ib_bluetack_spyware ib_bluetack_hijacked ib_bluetack_webexploit php_commenters php_dictionary php_harvesters php_spammers)

Source is downloaded from [this link]().

The last time downloaded was found to be dated: Sun Jun  7 22:20:34 UTC 2015.

The ipset `firehol_level3` has **110214** entries, **9627951** unique IPs.

The following table shows the overlaps of `firehol_level3` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `firehol_level3`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `firehol_level3`.
- ` this % ` is the percentage **of this ipset (`firehol_level3`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|9177856|100.0%|95.3%|
[firehol_level1](#firehol_level1)|5135|688894845|7500204|1.0%|77.9%|
[et_block](#et_block)|1000|18344011|6933378|37.7%|72.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|6933037|37.8%|72.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|2537317|0.7%|26.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|919965|0.1%|9.5%|
[fullbogons](#fullbogons)|3770|670213096|566693|0.0%|5.8%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|339173|100.0%|3.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|161595|0.1%|1.6%|
[stopforumspam_30d](#stopforumspam_30d)|94424|94424|94424|100.0%|0.9%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|29338|100.0%|0.3%|
[snort_ipfilter](#snort_ipfilter)|10158|10158|10158|100.0%|0.1%|
[firehol_level2](#firehol_level2)|23442|35072|8609|24.5%|0.0%|
[firehol_anonymous](#firehol_anonymous)|18837|82872|6614|7.9%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6808|6808|5918|86.9%|0.0%|
[firehol_proxies](#firehol_proxies)|12404|12670|5559|43.8%|0.0%|
[alienvault_reputation](#alienvault_reputation)|187115|187115|5166|2.7%|0.0%|
[blocklist_de](#blocklist_de)|29619|29619|3970|13.4%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7581|7581|3648|48.1%|0.0%|
[openbl_60d](#openbl_60d)|7012|7012|2966|42.2%|0.0%|
[openbl_30d](#openbl_30d)|2835|2835|2835|100.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|2933|2933|2361|80.4%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1711|1711|1711|100.0%|0.0%|
[et_compromised](#et_compromised)|1721|1721|1709|99.3%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2737|2737|1544|56.4%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|1450|100.0%|0.0%|
[sorbs_spam](#sorbs_spam)|59772|60402|1388|2.2%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|59772|60402|1388|2.2%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|59772|60402|1388|2.2%|0.0%|
[xroxy](#xroxy)|2159|2159|1292|59.8%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|1288|100.0%|0.0%|
[shunlist](#shunlist)|1225|1225|1225|100.0%|0.0%|
[et_tor](#et_tor)|6400|6400|1126|17.5%|0.0%|
[bm_tor](#bm_tor)|6552|6552|1116|17.0%|0.0%|
[dm_tor](#dm_tor)|6548|6548|1115|17.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3530|3530|992|28.1%|0.0%|
[proxz](#proxz)|1236|1236|736|59.5%|0.0%|
[php_dictionary](#php_dictionary)|702|702|702|100.0%|0.0%|
[php_spammers](#php_spammers)|700|700|700|100.0%|0.0%|
[proxyrss](#proxyrss)|1669|1669|697|41.7%|0.0%|
[openbl_7d](#openbl_7d)|679|679|679|100.0%|0.0%|
[nixspam](#nixspam)|39994|39994|666|1.6%|0.0%|
[dragon_http](#dragon_http)|1044|273664|565|0.2%|0.0%|
[ciarmy](#ciarmy)|457|457|457|100.0%|0.0%|
[php_commenters](#php_commenters)|430|430|430|100.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|17415|17415|404|2.3%|0.0%|
[php_harvesters](#php_harvesters)|378|378|378|100.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|343|65.4%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|15426|15426|325|2.1%|0.0%|
[malc0de](#malc0de)|313|313|313|100.0%|0.0%|
[zeus](#zeus)|230|230|203|88.2%|0.0%|
[zeus_badips](#zeus_badips)|202|202|180|89.1%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|180|180|163|90.5%|0.0%|
[openbl_1d](#openbl_1d)|158|158|158|100.0%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|123|123|123|100.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4071|4071|121|2.9%|0.0%|
[sslbl](#sslbl)|372|372|93|25.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|88|0.0%|0.0%|
[feodo](#feodo)|105|105|83|79.0%|0.0%|
[voipbl](#voipbl)|10533|10945|57|0.5%|0.0%|
[sorbs_web](#sorbs_web)|411|412|56|13.5%|0.0%|
[dshield](#dshield)|20|5120|49|0.9%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2383|2383|46|1.9%|0.0%|
[virbl](#virbl)|30|30|30|100.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|1333|1333|26|1.9%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|24|3.6%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|24|0.0%|0.0%|
[palevo](#palevo)|13|13|11|84.6%|0.0%|
[et_botcc](#et_botcc)|506|506|3|0.5%|0.0%|
[bogons](#bogons)|13|592708608|3|0.0%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|79|79|3|3.7%|0.0%|

## firehol_proxies

**FireHOL Proxies** - Known open proxies in the last 30 days. (includes: ib_bluetack_proxies maxmind_proxy_fraud proxyrss proxz ri_connect_proxies ri_web_proxies xroxy)

Source is downloaded from [this link]().

The last time downloaded was found to be dated: Sun Jun  7 22:20:34 UTC 2015.

The ipset `firehol_proxies` has **12404** entries, **12670** unique IPs.

The following table shows the overlaps of `firehol_proxies` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `firehol_proxies`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `firehol_proxies`.
- ` this % ` is the percentage **of this ipset (`firehol_proxies`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_anonymous](#firehol_anonymous)|18837|82872|12670|15.2%|100.0%|
[ri_web_proxies](#ri_web_proxies)|7581|7581|7581|100.0%|59.8%|
[firehol_level3](#firehol_level3)|110214|9627951|5559|0.0%|43.8%|
[stopforumspam_30d](#stopforumspam_30d)|94424|94424|5499|5.8%|43.4%|
[ri_connect_proxies](#ri_connect_proxies)|2737|2737|2737|100.0%|21.6%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|2427|8.2%|19.1%|
[xroxy](#xroxy)|2159|2159|2159|100.0%|17.0%|
[proxyrss](#proxyrss)|1669|1669|1669|100.0%|13.1%|
[proxz](#proxz)|1236|1236|1236|100.0%|9.7%|
[firehol_level2](#firehol_level2)|23442|35072|1231|3.5%|9.7%|
[stopforumspam_1d](#stopforumspam_1d)|6808|6808|871|12.7%|6.8%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|663|100.0%|5.2%|
[blocklist_de](#blocklist_de)|29619|29619|631|2.1%|4.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|528|0.0%|4.1%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|524|100.0%|4.1%|
[blocklist_de_bots](#blocklist_de_bots)|2933|2933|515|17.5%|4.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|389|0.0%|3.0%|
[snort_ipfilter](#snort_ipfilter)|10158|10158|320|3.1%|2.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|289|0.0%|2.2%|
[dm_tor](#dm_tor)|6548|6548|239|3.6%|1.8%|
[bm_tor](#bm_tor)|6552|6552|239|3.6%|1.8%|
[et_tor](#et_tor)|6400|6400|238|3.7%|1.8%|
[sorbs_spam](#sorbs_spam)|59772|60402|178|0.2%|1.4%|
[sorbs_recent_spam](#sorbs_recent_spam)|59772|60402|178|0.2%|1.4%|
[sorbs_new_spam](#sorbs_new_spam)|59772|60402|178|0.2%|1.4%|
[nixspam](#nixspam)|39994|39994|157|0.3%|1.2%|
[blocklist_de_mail](#blocklist_de_mail)|17415|17415|109|0.6%|0.8%|
[php_dictionary](#php_dictionary)|702|702|94|13.3%|0.7%|
[php_commenters](#php_commenters)|430|430|80|18.6%|0.6%|
[php_spammers](#php_spammers)|700|700|78|11.1%|0.6%|
[alienvault_reputation](#alienvault_reputation)|187115|187115|39|0.0%|0.3%|
[dragon_http](#dragon_http)|1044|273664|29|0.0%|0.2%|
[openbl_60d](#openbl_60d)|7012|7012|20|0.2%|0.1%|
[sorbs_web](#sorbs_web)|411|412|19|4.6%|0.1%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|15|0.0%|0.1%|
[php_harvesters](#php_harvesters)|378|378|12|3.1%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|11|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|15426|15426|7|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|180|180|6|3.3%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4071|4071|6|0.1%|0.0%|
[firehol_level1](#firehol_level1)|5135|688894845|4|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|3|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|3|0.2%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|0.0%|
[et_compromised](#et_compromised)|1721|1721|3|0.1%|0.0%|
[et_block](#et_block)|1000|18344011|3|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1711|1711|3|0.1%|0.0%|
[voipbl](#voipbl)|10533|10945|2|0.0%|0.0%|
[sslbl](#sslbl)|372|372|1|0.2%|0.0%|
[shunlist](#shunlist)|1225|1225|1|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3530|3530|1|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2383|2383|1|0.0%|0.0%|

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
[firehol_level3](#firehol_level3)|110214|9627951|566693|5.8%|0.0%|
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
[virbl](#virbl)|30|30|1|3.3%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|94424|94424|1|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6808|6808|1|0.0%|0.0%|
[php_harvesters](#php_harvesters)|378|378|1|0.2%|0.0%|
[php_commenters](#php_commenters)|430|430|1|0.2%|0.0%|
[firehol_level2](#firehol_level2)|23442|35072|1|0.0%|0.0%|
[ciarmy](#ciarmy)|457|457|1|0.2%|0.0%|

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
[firehol_level3](#firehol_level3)|110214|9627951|24|0.0%|0.0%|
[dragon_http](#dragon_http)|1044|273664|24|0.0%|0.0%|
[firehol_level1](#firehol_level1)|5135|688894845|18|0.0%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|94424|94424|16|0.0%|0.0%|
[alienvault_reputation](#alienvault_reputation)|187115|187115|16|0.0%|0.0%|
[sorbs_spam](#sorbs_spam)|59772|60402|15|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|59772|60402|15|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|59772|60402|15|0.0%|0.0%|
[firehol_proxies](#firehol_proxies)|12404|12670|15|0.1%|0.0%|
[firehol_anonymous](#firehol_anonymous)|18837|82872|15|0.0%|0.0%|
[fullbogons](#fullbogons)|3770|670213096|13|0.0%|0.0%|
[firehol_level2](#firehol_level2)|23442|35072|13|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|11|1.6%|0.0%|
[blocklist_de](#blocklist_de)|29619|29619|11|0.0%|0.0%|
[nixspam](#nixspam)|39994|39994|10|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|5|0.0%|0.0%|
[et_block](#et_block)|1000|18344011|5|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|17415|17415|5|0.0%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|4|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6808|6808|4|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7581|7581|4|0.0%|0.0%|
[xroxy](#xroxy)|2159|2159|3|0.1%|0.0%|
[php_dictionary](#php_dictionary)|702|702|3|0.4%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|3|0.0%|0.0%|
[voipbl](#voipbl)|10533|10945|2|0.0%|0.0%|
[php_harvesters](#php_harvesters)|378|378|2|0.5%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|1333|1333|2|0.1%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4071|4071|2|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|15426|15426|2|0.0%|0.0%|
[sorbs_web](#sorbs_web)|411|412|1|0.2%|0.0%|
[snort_ipfilter](#snort_ipfilter)|10158|10158|1|0.0%|0.0%|
[proxz](#proxz)|1236|1236|1|0.0%|0.0%|
[php_spammers](#php_spammers)|700|700|1|0.1%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|1|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3530|3530|1|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2383|2383|1|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|2933|2933|1|0.0%|0.0%|

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
[firehol_level3](#firehol_level3)|110214|9627951|9177856|95.3%|100.0%|
[firehol_level1](#firehol_level1)|5135|688894845|7498240|1.0%|81.6%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|6932480|37.7%|75.5%|
[et_block](#et_block)|1000|18344011|6932480|37.7%|75.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|2526625|0.7%|27.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|904796|0.1%|9.8%|
[fullbogons](#fullbogons)|3770|670213096|565760|0.0%|6.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|145472|0.1%|1.5%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1036|0.3%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|94424|94424|731|0.7%|0.0%|
[alienvault_reputation](#alienvault_reputation)|187115|187115|518|0.2%|0.0%|
[dragon_http](#dragon_http)|1044|273664|256|0.0%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|167|0.5%|0.0%|
[firehol_level2](#firehol_level2)|23442|35072|91|0.2%|0.0%|
[nixspam](#nixspam)|39994|39994|87|0.2%|0.0%|
[blocklist_de](#blocklist_de)|29619|29619|66|0.2%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|2933|2933|57|1.9%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6808|6808|28|0.4%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|27|2.0%|0.0%|
[openbl_60d](#openbl_60d)|7012|7012|16|0.2%|0.0%|
[openbl_30d](#openbl_30d)|2835|2835|12|0.4%|0.0%|
[snort_ipfilter](#snort_ipfilter)|10158|10158|11|0.1%|0.0%|
[zeus_badips](#zeus_badips)|202|202|10|4.9%|0.0%|
[zeus](#zeus)|230|230|10|4.3%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|7|0.4%|0.0%|
[firehol_anonymous](#firehol_anonymous)|18837|82872|7|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3530|3530|6|0.1%|0.0%|
[openbl_7d](#openbl_7d)|679|679|5|0.7%|0.0%|
[et_compromised](#et_compromised)|1721|1721|5|0.2%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1711|1711|5|0.2%|0.0%|
[php_dictionary](#php_dictionary)|702|702|4|0.5%|0.0%|
[et_tor](#et_tor)|6400|6400|4|0.0%|0.0%|
[dm_tor](#dm_tor)|6548|6548|4|0.0%|0.0%|
[bm_tor](#bm_tor)|6552|6552|4|0.0%|0.0%|
[shunlist](#shunlist)|1225|1225|3|0.2%|0.0%|
[php_spammers](#php_spammers)|700|700|3|0.4%|0.0%|
[firehol_proxies](#firehol_proxies)|12404|12670|3|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|180|180|3|1.6%|0.0%|
[openbl_1d](#openbl_1d)|158|158|2|1.2%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|2|0.3%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|17415|17415|2|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2383|2383|2|0.0%|0.0%|
[voipbl](#voipbl)|10533|10945|1|0.0%|0.0%|
[sorbs_spam](#sorbs_spam)|59772|60402|1|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|59772|60402|1|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|59772|60402|1|0.0%|0.0%|
[php_harvesters](#php_harvesters)|378|378|1|0.2%|0.0%|
[php_commenters](#php_commenters)|430|430|1|0.2%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|1|0.1%|0.0%|
[et_botcc](#et_botcc)|506|506|1|0.1%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|1333|1333|1|0.0%|0.0%|

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
[firehol_level1](#firehol_level1)|5135|688894845|2570274|0.3%|0.3%|
[et_block](#et_block)|1000|18344011|2272548|12.3%|0.2%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|2272265|12.3%|0.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|1354507|0.9%|0.1%|
[firehol_level3](#firehol_level3)|110214|9627951|919965|9.5%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|904796|9.8%|0.1%|
[fullbogons](#fullbogons)|3770|670213096|264841|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|33155|6.8%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|13247|3.9%|0.0%|
[dragon_http](#dragon_http)|1044|273664|7370|2.6%|0.0%|
[alienvault_reputation](#alienvault_reputation)|187115|187115|4218|2.2%|0.0%|
[firehol_anonymous](#firehol_anonymous)|18837|82872|3434|4.1%|0.0%|
[firehol_level2](#firehol_level2)|23442|35072|1670|4.7%|0.0%|
[blocklist_de](#blocklist_de)|29619|29619|1548|5.2%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|94424|94424|1516|1.6%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|17415|17415|1383|7.9%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|15426|15426|1335|8.6%|0.0%|
[sorbs_spam](#sorbs_spam)|59772|60402|1128|1.8%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|59772|60402|1128|1.8%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|59772|60402|1128|1.8%|0.0%|
[nixspam](#nixspam)|39994|39994|584|1.4%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|529|1.8%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|394|0.8%|0.0%|
[voipbl](#voipbl)|10533|10945|299|2.7%|0.0%|
[firehol_proxies](#firehol_proxies)|12404|12670|289|2.2%|0.0%|
[et_tor](#et_tor)|6400|6400|165|2.5%|0.0%|
[dm_tor](#dm_tor)|6548|6548|164|2.5%|0.0%|
[bm_tor](#bm_tor)|6552|6552|164|2.5%|0.0%|
[openbl_60d](#openbl_60d)|7012|7012|162|2.3%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7581|7581|153|2.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6808|6808|142|2.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|10158|10158|117|1.1%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|97|6.6%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2737|2737|83|3.0%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|66|5.1%|0.0%|
[openbl_30d](#openbl_30d)|2835|2835|63|2.2%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3530|3530|59|1.6%|0.0%|
[xroxy](#xroxy)|2159|2159|58|2.6%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|56|8.4%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1711|1711|53|3.0%|0.0%|
[et_compromised](#et_compromised)|1721|1721|52|3.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4071|4071|46|1.1%|0.0%|
[proxz](#proxz)|1236|1236|43|3.4%|0.0%|
[et_botcc](#et_botcc)|506|506|40|7.9%|0.0%|
[ciarmy](#ciarmy)|457|457|36|7.8%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|2933|2933|34|1.1%|0.0%|
[proxyrss](#proxyrss)|1669|1669|33|1.9%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2383|2383|31|1.3%|0.0%|
[shunlist](#shunlist)|1225|1225|25|2.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|21|4.0%|0.0%|
[openbl_7d](#openbl_7d)|679|679|13|1.9%|0.0%|
[php_dictionary](#php_dictionary)|702|702|12|1.7%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|1333|1333|12|0.9%|0.0%|
[sorbs_web](#sorbs_web)|411|412|11|2.6%|0.0%|
[php_harvesters](#php_harvesters)|378|378|11|2.9%|0.0%|
[malc0de](#malc0de)|313|313|11|3.5%|0.0%|
[php_spammers](#php_spammers)|700|700|10|1.4%|0.0%|
[php_commenters](#php_commenters)|430|430|10|2.3%|0.0%|
[zeus](#zeus)|230|230|7|3.0%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|79|79|6|7.5%|0.0%|
[bogons](#bogons)|13|592708608|5|0.0%|0.0%|
[zeus_badips](#zeus_badips)|202|202|4|1.9%|0.0%|
[sslbl](#sslbl)|372|372|3|0.8%|0.0%|
[feodo](#feodo)|105|105|3|2.8%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|123|123|3|2.4%|0.0%|
[virbl](#virbl)|30|30|2|6.6%|0.0%|
[openbl_1d](#openbl_1d)|158|158|2|1.2%|0.0%|

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
[firehol_level1](#firehol_level1)|5135|688894845|8867460|1.2%|2.5%|
[et_block](#et_block)|1000|18344011|8532520|46.5%|2.4%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|8532506|46.5%|2.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|2830203|2.0%|0.8%|
[firehol_level3](#firehol_level3)|110214|9627951|2537317|26.3%|0.7%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2526625|27.5%|0.7%|
[fullbogons](#fullbogons)|3770|670213096|252415|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|98904|20.2%|0.0%|
[dragon_http](#dragon_http)|1044|273664|12216|4.4%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|7728|2.2%|0.0%|
[alienvault_reputation](#alienvault_reputation)|187115|187115|6262|3.3%|0.0%|
[firehol_anonymous](#firehol_anonymous)|18837|82872|2886|3.4%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|94424|94424|2508|2.6%|0.0%|
[firehol_level2](#firehol_level2)|23442|35072|1734|4.9%|0.0%|
[sorbs_spam](#sorbs_spam)|59772|60402|1617|2.6%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|59772|60402|1617|2.6%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|59772|60402|1617|2.6%|0.0%|
[blocklist_de](#blocklist_de)|29619|29619|1583|5.3%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|17415|17415|1262|7.2%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|15426|15426|1105|7.1%|0.0%|
[nixspam](#nixspam)|39994|39994|1101|2.7%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|790|2.6%|0.0%|
[voipbl](#voipbl)|10533|10945|434|3.9%|0.0%|
[firehol_proxies](#firehol_proxies)|12404|12670|389|3.0%|0.0%|
[openbl_60d](#openbl_60d)|7012|7012|321|4.5%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|226|0.4%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7581|7581|222|2.9%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6808|6808|196|2.8%|0.0%|
[et_tor](#et_tor)|6400|6400|181|2.8%|0.0%|
[dm_tor](#dm_tor)|6548|6548|181|2.7%|0.0%|
[bm_tor](#bm_tor)|6552|6552|181|2.7%|0.0%|
[snort_ipfilter](#snort_ipfilter)|10158|10158|158|1.5%|0.0%|
[openbl_30d](#openbl_30d)|2835|2835|148|5.2%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3530|3530|138|3.9%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2737|2737|105|3.8%|0.0%|
[xroxy](#xroxy)|2159|2159|104|4.8%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1711|1711|89|5.2%|0.0%|
[et_compromised](#et_compromised)|1721|1721|85|4.9%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|2933|2933|81|2.7%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4071|4071|73|1.7%|0.0%|
[shunlist](#shunlist)|1225|1225|68|5.5%|0.0%|
[php_spammers](#php_spammers)|700|700|54|7.7%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2383|2383|53|2.2%|0.0%|
[proxz](#proxz)|1236|1236|51|4.1%|0.0%|
[proxyrss](#proxyrss)|1669|1669|50|2.9%|0.0%|
[ciarmy](#ciarmy)|457|457|49|10.7%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|45|3.1%|0.0%|
[openbl_7d](#openbl_7d)|679|679|40|5.8%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|29|5.5%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|26|2.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|26|3.9%|0.0%|
[php_dictionary](#php_dictionary)|702|702|23|3.2%|0.0%|
[et_botcc](#et_botcc)|506|506|20|3.9%|0.0%|
[php_commenters](#php_commenters)|430|430|18|4.1%|0.0%|
[malc0de](#malc0de)|313|313|16|5.1%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|1333|1333|16|1.2%|0.0%|
[sorbs_web](#sorbs_web)|411|412|13|3.1%|0.0%|
[zeus](#zeus)|230|230|9|3.9%|0.0%|
[php_harvesters](#php_harvesters)|378|378|9|2.3%|0.0%|
[zeus_badips](#zeus_badips)|202|202|8|3.9%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|180|180|8|4.4%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|79|79|7|8.8%|0.0%|
[sslbl](#sslbl)|372|372|6|1.6%|0.0%|
[openbl_1d](#openbl_1d)|158|158|6|3.7%|0.0%|
[feodo](#feodo)|105|105|3|2.8%|0.0%|
[virbl](#virbl)|30|30|2|6.6%|0.0%|
[palevo](#palevo)|13|13|2|15.3%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|123|123|2|1.6%|0.0%|

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
[firehol_level3](#firehol_level3)|110214|9627951|161595|1.6%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|145472|1.5%|0.1%|
[et_block](#et_block)|1000|18344011|130394|0.7%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|130368|0.7%|0.0%|
[dragon_http](#dragon_http)|1044|273664|19712|7.2%|0.0%|
[alienvault_reputation](#alienvault_reputation)|187115|187115|13887|7.4%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|9226|2.7%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|94424|94424|5840|6.1%|0.0%|
[firehol_level2](#firehol_level2)|23442|35072|4161|11.8%|0.0%|
[blocklist_de](#blocklist_de)|29619|29619|3754|12.6%|0.0%|
[firehol_anonymous](#firehol_anonymous)|18837|82872|2872|3.4%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|17415|17415|2604|14.9%|0.0%|
[sorbs_spam](#sorbs_spam)|59772|60402|2477|4.1%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|59772|60402|2477|4.1%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|59772|60402|2477|4.1%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|15426|15426|2392|15.5%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|1913|6.5%|0.0%|
[nixspam](#nixspam)|39994|39994|1719|4.2%|0.0%|
[voipbl](#voipbl)|10533|10945|1605|14.6%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|1172|2.4%|0.0%|
[openbl_60d](#openbl_60d)|7012|7012|747|10.6%|0.0%|
[dm_tor](#dm_tor)|6548|6548|629|9.6%|0.0%|
[bm_tor](#bm_tor)|6552|6552|629|9.6%|0.0%|
[et_tor](#et_tor)|6400|6400|625|9.7%|0.0%|
[firehol_proxies](#firehol_proxies)|12404|12670|528|4.1%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3530|3530|513|14.5%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6808|6808|486|7.1%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2383|2383|304|12.7%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4071|4071|301|7.3%|0.0%|
[openbl_30d](#openbl_30d)|2835|2835|295|10.4%|0.0%|
[snort_ipfilter](#snort_ipfilter)|10158|10158|243|2.3%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7581|7581|218|2.8%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|2933|2933|158|5.3%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1711|1711|156|9.1%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|1333|1333|153|11.4%|0.0%|
[et_compromised](#et_compromised)|1721|1721|152|8.8%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|150|28.6%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|147|11.4%|0.0%|
[shunlist](#shunlist)|1225|1225|116|9.4%|0.0%|
[xroxy](#xroxy)|2159|2159|110|5.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|108|7.4%|0.0%|
[proxz](#proxz)|1236|1236|102|8.2%|0.0%|
[ciarmy](#ciarmy)|457|457|100|21.8%|0.0%|
[openbl_7d](#openbl_7d)|679|679|79|11.6%|0.0%|
[et_botcc](#et_botcc)|506|506|77|15.2%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2737|2737|57|2.0%|0.0%|
[proxyrss](#proxyrss)|1669|1669|52|3.1%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|51|7.6%|0.0%|
[malc0de](#malc0de)|313|313|45|14.3%|0.0%|
[php_spammers](#php_spammers)|700|700|43|6.1%|0.0%|
[php_dictionary](#php_dictionary)|702|702|38|5.4%|0.0%|
[sslbl](#sslbl)|372|372|28|7.5%|0.0%|
[php_commenters](#php_commenters)|430|430|28|6.5%|0.0%|
[php_harvesters](#php_harvesters)|378|378|20|5.2%|0.0%|
[sorbs_web](#sorbs_web)|411|412|18|4.3%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|123|123|16|13.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|180|180|16|8.8%|0.0%|
[zeus](#zeus)|230|230|14|6.0%|0.0%|
[openbl_1d](#openbl_1d)|158|158|14|8.8%|0.0%|
[feodo](#feodo)|105|105|11|10.4%|0.0%|
[zeus_badips](#zeus_badips)|202|202|10|4.9%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|79|79|10|12.6%|0.0%|
[virbl](#virbl)|30|30|4|13.3%|0.0%|
[palevo](#palevo)|13|13|1|7.6%|0.0%|

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
[firehol_proxies](#firehol_proxies)|12404|12670|663|5.2%|100.0%|
[firehol_anonymous](#firehol_anonymous)|18837|82872|663|0.8%|100.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|56|0.0%|8.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|51|0.0%|7.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|26|0.0%|3.9%|
[firehol_level3](#firehol_level3)|110214|9627951|24|0.0%|3.6%|
[stopforumspam_30d](#stopforumspam_30d)|94424|94424|19|0.0%|2.8%|
[ri_web_proxies](#ri_web_proxies)|7581|7581|14|0.1%|2.1%|
[xroxy](#xroxy)|2159|2159|13|0.6%|1.9%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|11|0.0%|1.6%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|11|0.0%|1.6%|
[proxyrss](#proxyrss)|1669|1669|9|0.5%|1.3%|
[ri_connect_proxies](#ri_connect_proxies)|2737|2737|7|0.2%|1.0%|
[firehol_level2](#firehol_level2)|23442|35072|7|0.0%|1.0%|
[proxz](#proxz)|1236|1236|6|0.4%|0.9%|
[blocklist_de](#blocklist_de)|29619|29619|5|0.0%|0.7%|
[stopforumspam_1d](#stopforumspam_1d)|6808|6808|4|0.0%|0.6%|
[blocklist_de_bots](#blocklist_de_bots)|2933|2933|4|0.1%|0.6%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|2|0.0%|0.3%|
[nixspam](#nixspam)|39994|39994|2|0.0%|0.3%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|2|0.1%|0.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2|0.0%|0.3%|
[firehol_level1](#firehol_level1)|5135|688894845|2|0.0%|0.3%|
[et_block](#et_block)|1000|18344011|2|0.0%|0.3%|
[sorbs_spam](#sorbs_spam)|59772|60402|1|0.0%|0.1%|
[sorbs_recent_spam](#sorbs_recent_spam)|59772|60402|1|0.0%|0.1%|
[sorbs_new_spam](#sorbs_new_spam)|59772|60402|1|0.0%|0.1%|
[snort_ipfilter](#snort_ipfilter)|10158|10158|1|0.0%|0.1%|
[php_dictionary](#php_dictionary)|702|702|1|0.1%|0.1%|
[dragon_http](#dragon_http)|1044|273664|1|0.0%|0.1%|
[blocklist_de_mail](#blocklist_de_mail)|17415|17415|1|0.0%|0.1%|
[alienvault_reputation](#alienvault_reputation)|187115|187115|1|0.0%|0.1%|

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
[firehol_level3](#firehol_level3)|110214|9627951|339173|3.5%|100.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|13247|0.0%|3.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|9226|0.0%|2.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|7728|0.0%|2.2%|
[firehol_level1](#firehol_level1)|5135|688894845|1931|0.0%|0.5%|
[et_block](#et_block)|1000|18344011|1042|0.0%|0.3%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|1037|0.0%|0.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1036|0.0%|0.3%|
[fullbogons](#fullbogons)|3770|670213096|890|0.0%|0.2%|
[alienvault_reputation](#alienvault_reputation)|187115|187115|289|0.1%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|94424|94424|49|0.0%|0.0%|
[sorbs_spam](#sorbs_spam)|59772|60402|32|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|59772|60402|32|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|59772|60402|32|0.0%|0.0%|
[nixspam](#nixspam)|39994|39994|29|0.0%|0.0%|
[firehol_anonymous](#firehol_anonymous)|18837|82872|28|0.0%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|27|2.0%|0.0%|
[et_tor](#et_tor)|6400|6400|22|0.3%|0.0%|
[dm_tor](#dm_tor)|6548|6548|22|0.3%|0.0%|
[bm_tor](#bm_tor)|6552|6552|22|0.3%|0.0%|
[firehol_level2](#firehol_level2)|23442|35072|20|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|19|1.3%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|18|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|10158|10158|14|0.1%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6808|6808|11|0.1%|0.0%|
[firehol_proxies](#firehol_proxies)|12404|12670|11|0.0%|0.0%|
[blocklist_de](#blocklist_de)|29619|29619|9|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7581|7581|6|0.0%|0.0%|
[dragon_http](#dragon_http)|1044|273664|6|0.0%|0.0%|
[openbl_60d](#openbl_60d)|7012|7012|5|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|5|0.9%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|15426|15426|5|0.0%|0.0%|
[voipbl](#voipbl)|10533|10945|4|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4071|4071|4|0.0%|0.0%|
[openbl_30d](#openbl_30d)|2835|2835|3|0.1%|0.0%|
[malc0de](#malc0de)|313|313|3|0.9%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|3|0.0%|0.0%|
[et_compromised](#et_compromised)|1721|1721|2|0.1%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1711|1711|2|0.1%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|79|79|2|2.5%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|17415|17415|2|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|2933|2933|2|0.0%|0.0%|
[zeus_badips](#zeus_badips)|202|202|1|0.4%|0.0%|
[zeus](#zeus)|230|230|1|0.4%|0.0%|
[xroxy](#xroxy)|2159|2159|1|0.0%|0.0%|
[sslbl](#sslbl)|372|372|1|0.2%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|1|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2737|2737|1|0.0%|0.0%|
[proxz](#proxz)|1236|1236|1|0.0%|0.0%|
[proxyrss](#proxyrss)|1669|1669|1|0.0%|0.0%|
[php_harvesters](#php_harvesters)|378|378|1|0.2%|0.0%|
[php_dictionary](#php_dictionary)|702|702|1|0.1%|0.0%|
[php_commenters](#php_commenters)|430|430|1|0.2%|0.0%|
[palevo](#palevo)|13|13|1|7.6%|0.0%|
[feodo](#feodo)|105|105|1|0.9%|0.0%|
[ciarmy](#ciarmy)|457|457|1|0.2%|0.0%|
[bogons](#bogons)|13|592708608|1|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3530|3530|1|0.0%|0.0%|

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
[firehol_level3](#firehol_level3)|110214|9627951|1450|0.0%|100.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|108|0.0%|7.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|97|0.0%|6.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|45|0.0%|3.1%|
[firehol_level1](#firehol_level1)|5135|688894845|39|0.0%|2.6%|
[fullbogons](#fullbogons)|3770|670213096|33|0.0%|2.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|19|0.0%|1.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|7|0.0%|0.4%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|6|0.0%|0.4%|
[et_block](#et_block)|1000|18344011|6|0.0%|0.4%|
[alienvault_reputation](#alienvault_reputation)|187115|187115|6|0.0%|0.4%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|3|0.2%|0.2%|
[firehol_proxies](#firehol_proxies)|12404|12670|3|0.0%|0.2%|
[firehol_level2](#firehol_level2)|23442|35072|3|0.0%|0.2%|
[firehol_anonymous](#firehol_anonymous)|18837|82872|3|0.0%|0.2%|
[dragon_http](#dragon_http)|1044|273664|3|0.0%|0.2%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|2|0.0%|0.1%|
[stopforumspam_30d](#stopforumspam_30d)|94424|94424|2|0.0%|0.1%|
[stopforumspam_1d](#stopforumspam_1d)|6808|6808|2|0.0%|0.1%|
[sorbs_spam](#sorbs_spam)|59772|60402|2|0.0%|0.1%|
[sorbs_recent_spam](#sorbs_recent_spam)|59772|60402|2|0.0%|0.1%|
[sorbs_new_spam](#sorbs_new_spam)|59772|60402|2|0.0%|0.1%|
[openbl_60d](#openbl_60d)|7012|7012|2|0.0%|0.1%|
[openbl_30d](#openbl_30d)|2835|2835|2|0.0%|0.1%|
[nixspam](#nixspam)|39994|39994|2|0.0%|0.1%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|2|0.3%|0.1%|
[blocklist_de](#blocklist_de)|29619|29619|2|0.0%|0.1%|
[snort_ipfilter](#snort_ipfilter)|10158|10158|1|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7581|7581|1|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|1|0.0%|0.0%|
[et_botcc](#et_botcc)|506|506|1|0.1%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|180|180|1|0.5%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3530|3530|1|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|2933|2933|1|0.0%|0.0%|

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
[firehol_level3](#firehol_level3)|110214|9627951|313|0.0%|100.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|45|0.0%|14.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|16|0.0%|5.1%|
[cleanmx_viruses](#cleanmx_viruses)|123|123|13|10.5%|4.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|11|0.0%|3.5%|
[alienvault_reputation](#alienvault_reputation)|187115|187115|10|0.0%|3.1%|
[firehol_level1](#firehol_level1)|5135|688894845|7|0.0%|2.2%|
[et_block](#et_block)|1000|18344011|5|0.0%|1.5%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|4|0.0%|1.2%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|4|0.3%|1.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|3|0.0%|0.9%|
[dragon_http](#dragon_http)|1044|273664|3|0.0%|0.9%|
[dshield](#dshield)|20|5120|2|0.0%|0.6%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|1|0.0%|0.3%|
[sorbs_spam](#sorbs_spam)|59772|60402|1|0.0%|0.3%|
[sorbs_recent_spam](#sorbs_recent_spam)|59772|60402|1|0.0%|0.3%|
[sorbs_new_spam](#sorbs_new_spam)|59772|60402|1|0.0%|0.3%|

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
[firehol_level3](#firehol_level3)|110214|9627951|1288|0.0%|100.0%|
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
[alienvault_reputation](#alienvault_reputation)|187115|187115|8|0.0%|0.6%|
[stopforumspam_30d](#stopforumspam_30d)|94424|94424|4|0.0%|0.3%|
[malc0de](#malc0de)|313|313|4|1.2%|0.3%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|3|0.2%|0.2%|
[dragon_http](#dragon_http)|1044|273664|2|0.0%|0.1%|
[zeus](#zeus)|230|230|1|0.4%|0.0%|
[et_botcc](#et_botcc)|506|506|1|0.1%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|123|123|1|0.8%|0.0%|

## maxmind_proxy_fraud

[MaxMind.com](https://www.maxmind.com/en/anonymous-proxy-fraudulent-ip-address-list) list of anonymous proxy fraudelent IP addresses.

Source is downloaded from [this link](https://www.maxmind.com/en/anonymous-proxy-fraudulent-ip-address-list).

The last time downloaded was found to be dated: Wed Jun 10 18:36:24 UTC 2015.

The ipset `maxmind_proxy_fraud` has **524** entries, **524** unique IPs.

The following table shows the overlaps of `maxmind_proxy_fraud` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `maxmind_proxy_fraud`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `maxmind_proxy_fraud`.
- ` this % ` is the percentage **of this ipset (`maxmind_proxy_fraud`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_proxies](#firehol_proxies)|12404|12670|524|4.1%|100.0%|
[firehol_anonymous](#firehol_anonymous)|18837|82872|524|0.6%|100.0%|
[firehol_level3](#firehol_level3)|110214|9627951|343|0.0%|65.4%|
[stopforumspam_30d](#stopforumspam_30d)|94424|94424|342|0.3%|65.2%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|285|0.9%|54.3%|
[snort_ipfilter](#snort_ipfilter)|10158|10158|239|2.3%|45.6%|
[et_tor](#et_tor)|6400|6400|234|3.6%|44.6%|
[dm_tor](#dm_tor)|6548|6548|234|3.5%|44.6%|
[bm_tor](#bm_tor)|6552|6552|234|3.5%|44.6%|
[firehol_level2](#firehol_level2)|23442|35072|228|0.6%|43.5%|
[stopforumspam_1d](#stopforumspam_1d)|6808|6808|225|3.3%|42.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|150|0.0%|28.6%|
[php_commenters](#php_commenters)|430|430|52|12.0%|9.9%|
[alienvault_reputation](#alienvault_reputation)|187115|187115|30|0.0%|5.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|29|0.0%|5.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|21|0.0%|4.0%|
[openbl_60d](#openbl_60d)|7012|7012|20|0.2%|3.8%|
[ri_web_proxies](#ri_web_proxies)|7581|7581|10|0.1%|1.9%|
[php_harvesters](#php_harvesters)|378|378|7|1.8%|1.3%|
[blocklist_de](#blocklist_de)|29619|29619|7|0.0%|1.3%|
[php_spammers](#php_spammers)|700|700|6|0.8%|1.1%|
[php_dictionary](#php_dictionary)|702|702|5|0.7%|0.9%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|5|0.0%|0.9%|
[blocklist_de_bots](#blocklist_de_bots)|2933|2933|4|0.1%|0.7%|
[xroxy](#xroxy)|2159|2159|3|0.1%|0.5%|
[voipbl](#voipbl)|10533|10945|2|0.0%|0.3%|
[proxz](#proxz)|1236|1236|2|0.1%|0.3%|
[dragon_http](#dragon_http)|1044|273664|2|0.0%|0.3%|
[blocklist_de_mail](#blocklist_de_mail)|17415|17415|2|0.0%|0.3%|
[blocklist_de_apache](#blocklist_de_apache)|15426|15426|2|0.0%|0.3%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|1|0.0%|0.1%|
[sorbs_spam](#sorbs_spam)|59772|60402|1|0.0%|0.1%|
[sorbs_recent_spam](#sorbs_recent_spam)|59772|60402|1|0.0%|0.1%|
[sorbs_new_spam](#sorbs_new_spam)|59772|60402|1|0.0%|0.1%|
[shunlist](#shunlist)|1225|1225|1|0.0%|0.1%|
[ri_connect_proxies](#ri_connect_proxies)|2737|2737|1|0.0%|0.1%|
[proxyrss](#proxyrss)|1669|1669|1|0.0%|0.1%|
[nixspam](#nixspam)|39994|39994|1|0.0%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.1%|
[firehol_level1](#firehol_level1)|5135|688894845|1|0.0%|0.1%|
[et_block](#et_block)|1000|18344011|1|0.0%|0.1%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4071|4071|1|0.0%|0.1%|

## nixspam

[NiX Spam](http://www.heise.de/ix/NiX-Spam-DNSBL-and-blacklist-for-download-499637.html) IP addresses that sent spam in the last hour - automatically generated entries without distinguishing open proxies from relays, dialup gateways, and so on. All IPs are removed after 12 hours if there is no spam from there.

Source is downloaded from [this link](http://www.dnsbl.manitu.net/download/nixspam-ip.dump.gz).

The last time downloaded was found to be dated: Wed Jun 10 20:30:02 UTC 2015.

The ipset `nixspam` has **39994** entries, **39994** unique IPs.

The following table shows the overlaps of `nixspam` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `nixspam`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `nixspam`.
- ` this % ` is the percentage **of this ipset (`nixspam`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[sorbs_spam](#sorbs_spam)|59772|60402|10698|17.7%|26.7%|
[sorbs_recent_spam](#sorbs_recent_spam)|59772|60402|10698|17.7%|26.7%|
[sorbs_new_spam](#sorbs_new_spam)|59772|60402|10698|17.7%|26.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|1719|0.0%|4.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|1101|0.0%|2.7%|
[firehol_level2](#firehol_level2)|23442|35072|874|2.4%|2.1%|
[blocklist_de](#blocklist_de)|29619|29619|862|2.9%|2.1%|
[blocklist_de_mail](#blocklist_de_mail)|17415|17415|792|4.5%|1.9%|
[firehol_level3](#firehol_level3)|110214|9627951|666|0.0%|1.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|584|0.0%|1.4%|
[snort_ipfilter](#snort_ipfilter)|10158|10158|341|3.3%|0.8%|
[stopforumspam_30d](#stopforumspam_30d)|94424|94424|222|0.2%|0.5%|
[firehol_anonymous](#firehol_anonymous)|18837|82872|160|0.1%|0.4%|
[firehol_proxies](#firehol_proxies)|12404|12670|157|1.2%|0.3%|
[sorbs_web](#sorbs_web)|411|412|124|30.0%|0.3%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|123|0.4%|0.3%|
[ri_web_proxies](#ri_web_proxies)|7581|7581|118|1.5%|0.2%|
[php_dictionary](#php_dictionary)|702|702|113|16.0%|0.2%|
[php_spammers](#php_spammers)|700|700|91|13.0%|0.2%|
[firehol_level1](#firehol_level1)|5135|688894845|91|0.0%|0.2%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|88|0.0%|0.2%|
[et_block](#et_block)|1000|18344011|88|0.0%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|87|0.0%|0.2%|
[alienvault_reputation](#alienvault_reputation)|187115|187115|70|0.0%|0.1%|
[xroxy](#xroxy)|2159|2159|63|2.9%|0.1%|
[proxz](#proxz)|1236|1236|39|3.1%|0.0%|
[dragon_http](#dragon_http)|1044|273664|38|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6808|6808|37|0.5%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|15426|15426|33|0.2%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4071|4071|32|0.7%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|29|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|2933|2933|28|0.9%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2383|2383|15|0.6%|0.0%|
[php_commenters](#php_commenters)|430|430|13|3.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2737|2737|12|0.4%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|10|0.0%|0.0%|
[openbl_60d](#openbl_60d)|7012|7012|8|0.1%|0.0%|
[proxyrss](#proxyrss)|1669|1669|7|0.4%|0.0%|
[php_harvesters](#php_harvesters)|378|378|6|1.5%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|1333|1333|6|0.4%|0.0%|
[openbl_30d](#openbl_30d)|2835|2835|3|0.1%|0.0%|
[et_tor](#et_tor)|6400|6400|3|0.0%|0.0%|
[et_compromised](#et_compromised)|1721|1721|3|0.1%|0.0%|
[dm_tor](#dm_tor)|6548|6548|3|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1711|1711|3|0.1%|0.0%|
[bm_tor](#bm_tor)|6552|6552|3|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3530|3530|3|0.0%|0.0%|
[voipbl](#voipbl)|10533|10945|2|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|2|0.0%|0.0%|
[sorbs_socks](#sorbs_socks)|2|2|2|100.0%|0.0%|
[sorbs_misc](#sorbs_misc)|2|2|2|100.0%|0.0%|
[sorbs_http](#sorbs_http)|2|2|2|100.0%|0.0%|
[shunlist](#shunlist)|1225|1225|2|0.1%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|2|0.1%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|2|0.3%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|180|180|2|1.1%|0.0%|
[virbl](#virbl)|30|30|1|3.3%|0.0%|
[openbl_7d](#openbl_7d)|679|679|1|0.1%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|1|0.1%|0.0%|
[dshield](#dshield)|20|5120|1|0.0%|0.0%|

## openbl_1d

[OpenBL.org](http://www.openbl.org/) last 24 hours IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.

Source is downloaded from [this link](http://www.openbl.org/lists/base_1days.txt).

The last time downloaded was found to be dated: Wed Jun 10 20:32:00 UTC 2015.

The ipset `openbl_1d` has **158** entries, **158** unique IPs.

The following table shows the overlaps of `openbl_1d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl_1d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl_1d`.
- ` this % ` is the percentage **of this ipset (`openbl_1d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[openbl_60d](#openbl_60d)|7012|7012|158|2.2%|100.0%|
[firehol_level3](#firehol_level3)|110214|9627951|158|0.0%|100.0%|
[firehol_level2](#firehol_level2)|23442|35072|158|0.4%|100.0%|
[openbl_30d](#openbl_30d)|2835|2835|157|5.5%|99.3%|
[openbl_7d](#openbl_7d)|679|679|156|22.9%|98.7%|
[alienvault_reputation](#alienvault_reputation)|187115|187115|154|0.0%|97.4%|
[blocklist_de](#blocklist_de)|29619|29619|124|0.4%|78.4%|
[blocklist_de_ssh](#blocklist_de_ssh)|3530|3530|121|3.4%|76.5%|
[et_compromised](#et_compromised)|1721|1721|64|3.7%|40.5%|
[bruteforceblocker](#bruteforceblocker)|1711|1711|64|3.7%|40.5%|
[shunlist](#shunlist)|1225|1225|57|4.6%|36.0%|
[et_block](#et_block)|1000|18344011|19|0.0%|12.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|180|180|19|10.5%|12.0%|
[firehol_level1](#firehol_level1)|5135|688894845|18|0.0%|11.3%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|14|0.0%|8.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|14|0.0%|8.8%|
[dragon_http](#dragon_http)|1044|273664|10|0.0%|6.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|6|0.0%|3.7%|
[dshield](#dshield)|20|5120|3|0.0%|1.8%|
[blocklist_de_apache](#blocklist_de_apache)|15426|15426|3|0.0%|1.8%|
[stopforumspam_30d](#stopforumspam_30d)|94424|94424|2|0.0%|1.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|2|0.0%|1.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2|0.0%|1.2%|
[zeus_badips](#zeus_badips)|202|202|1|0.4%|0.6%|
[zeus](#zeus)|230|230|1|0.4%|0.6%|
[snort_ipfilter](#snort_ipfilter)|10158|10158|1|0.0%|0.6%|
[php_spammers](#php_spammers)|700|700|1|0.1%|0.6%|
[php_commenters](#php_commenters)|430|430|1|0.2%|0.6%|
[ciarmy](#ciarmy)|457|457|1|0.2%|0.6%|

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
[firehol_level3](#firehol_level3)|110214|9627951|2835|0.0%|100.0%|
[alienvault_reputation](#alienvault_reputation)|187115|187115|2817|1.5%|99.3%|
[et_compromised](#et_compromised)|1721|1721|941|54.6%|33.1%|
[bruteforceblocker](#bruteforceblocker)|1711|1711|917|53.5%|32.3%|
[firehol_level2](#firehol_level2)|23442|35072|803|2.2%|28.3%|
[blocklist_de](#blocklist_de)|29619|29619|769|2.5%|27.1%|
[blocklist_de_ssh](#blocklist_de_ssh)|3530|3530|736|20.8%|25.9%|
[openbl_7d](#openbl_7d)|679|679|679|100.0%|23.9%|
[shunlist](#shunlist)|1225|1225|499|40.7%|17.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|295|0.0%|10.4%|
[et_block](#et_block)|1000|18344011|163|0.0%|5.7%|
[openbl_1d](#openbl_1d)|158|158|157|99.3%|5.5%|
[firehol_level1](#firehol_level1)|5135|688894845|155|0.0%|5.4%|
[dragon_http](#dragon_http)|1044|273664|154|0.0%|5.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|148|0.0%|5.2%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|119|0.0%|4.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|63|0.0%|2.2%|
[dshield](#dshield)|20|5120|33|0.6%|1.1%|
[blocklist_de_strongips](#blocklist_de_strongips)|180|180|24|13.3%|0.8%|
[blocklist_de_mail](#blocklist_de_mail)|17415|17415|23|0.1%|0.8%|
[blocklist_de_imap](#blocklist_de_imap)|2383|2383|19|0.7%|0.6%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|12|0.0%|0.4%|
[blocklist_de_apache](#blocklist_de_apache)|15426|15426|7|0.0%|0.2%|
[stopforumspam_30d](#stopforumspam_30d)|94424|94424|5|0.0%|0.1%|
[voipbl](#voipbl)|10533|10945|3|0.0%|0.1%|
[snort_ipfilter](#snort_ipfilter)|10158|10158|3|0.0%|0.1%|
[nixspam](#nixspam)|39994|39994|3|0.0%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|3|0.0%|0.1%|
[zeus](#zeus)|230|230|2|0.8%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|2|0.1%|0.0%|
[ciarmy](#ciarmy)|457|457|2|0.4%|0.0%|
[zeus_badips](#zeus_badips)|202|202|1|0.4%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|1|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6808|6808|1|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|1|0.0%|0.0%|
[php_spammers](#php_spammers)|700|700|1|0.1%|0.0%|
[php_commenters](#php_commenters)|430|430|1|0.2%|0.0%|
[firehol_anonymous](#firehol_anonymous)|18837|82872|1|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|1333|1333|1|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|2933|2933|1|0.0%|0.0%|

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
[alienvault_reputation](#alienvault_reputation)|187115|187115|6989|3.7%|99.6%|
[firehol_level3](#firehol_level3)|110214|9627951|2966|0.0%|42.2%|
[openbl_30d](#openbl_30d)|2835|2835|2835|100.0%|40.4%|
[firehol_level2](#firehol_level2)|23442|35072|1017|2.8%|14.5%|
[et_compromised](#et_compromised)|1721|1721|1009|58.6%|14.3%|
[bruteforceblocker](#bruteforceblocker)|1711|1711|982|57.3%|14.0%|
[blocklist_de](#blocklist_de)|29619|29619|964|3.2%|13.7%|
[blocklist_de_ssh](#blocklist_de_ssh)|3530|3530|922|26.1%|13.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|747|0.0%|10.6%|
[openbl_7d](#openbl_7d)|679|679|679|100.0%|9.6%|
[shunlist](#shunlist)|1225|1225|528|43.1%|7.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|321|0.0%|4.5%|
[et_block](#et_block)|1000|18344011|301|0.0%|4.2%|
[firehol_level1](#firehol_level1)|5135|688894845|283|0.0%|4.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|235|0.0%|3.3%|
[dragon_http](#dragon_http)|1044|273664|223|0.0%|3.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|162|0.0%|2.3%|
[openbl_1d](#openbl_1d)|158|158|158|100.0%|2.2%|
[stopforumspam_30d](#stopforumspam_30d)|94424|94424|48|0.0%|0.6%|
[dshield](#dshield)|20|5120|45|0.8%|0.6%|
[blocklist_de_mail](#blocklist_de_mail)|17415|17415|29|0.1%|0.4%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|27|0.0%|0.3%|
[snort_ipfilter](#snort_ipfilter)|10158|10158|25|0.2%|0.3%|
[blocklist_de_strongips](#blocklist_de_strongips)|180|180|25|13.8%|0.3%|
[blocklist_de_imap](#blocklist_de_imap)|2383|2383|24|1.0%|0.3%|
[firehol_anonymous](#firehol_anonymous)|18837|82872|22|0.0%|0.3%|
[stopforumspam_1d](#stopforumspam_1d)|6808|6808|20|0.2%|0.2%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|20|3.8%|0.2%|
[firehol_proxies](#firehol_proxies)|12404|12670|20|0.1%|0.2%|
[et_tor](#et_tor)|6400|6400|20|0.3%|0.2%|
[dm_tor](#dm_tor)|6548|6548|19|0.2%|0.2%|
[bm_tor](#bm_tor)|6552|6552|19|0.2%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|16|0.0%|0.2%|
[php_commenters](#php_commenters)|430|430|11|2.5%|0.1%|
[voipbl](#voipbl)|10533|10945|8|0.0%|0.1%|
[nixspam](#nixspam)|39994|39994|8|0.0%|0.1%|
[blocklist_de_apache](#blocklist_de_apache)|15426|15426|7|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|5|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|2933|2933|3|0.1%|0.0%|
[zeus](#zeus)|230|230|2|0.8%|0.0%|
[sorbs_spam](#sorbs_spam)|59772|60402|2|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|59772|60402|2|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|59772|60402|2|0.0%|0.0%|
[php_harvesters](#php_harvesters)|378|378|2|0.5%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|2|0.1%|0.0%|
[ciarmy](#ciarmy)|457|457|2|0.4%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|1333|1333|2|0.1%|0.0%|
[zeus_badips](#zeus_badips)|202|202|1|0.4%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|1|0.0%|0.0%|
[php_spammers](#php_spammers)|700|700|1|0.1%|0.0%|

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
[firehol_level3](#firehol_level3)|110214|9627951|679|0.0%|100.0%|
[alienvault_reputation](#alienvault_reputation)|187115|187115|673|0.3%|99.1%|
[firehol_level2](#firehol_level2)|23442|35072|424|1.2%|62.4%|
[blocklist_de](#blocklist_de)|29619|29619|390|1.3%|57.4%|
[blocklist_de_ssh](#blocklist_de_ssh)|3530|3530|378|10.7%|55.6%|
[et_compromised](#et_compromised)|1721|1721|324|18.8%|47.7%|
[bruteforceblocker](#bruteforceblocker)|1711|1711|323|18.8%|47.5%|
[shunlist](#shunlist)|1225|1225|209|17.0%|30.7%|
[openbl_1d](#openbl_1d)|158|158|156|98.7%|22.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|79|0.0%|11.6%|
[et_block](#et_block)|1000|18344011|61|0.0%|8.9%|
[dragon_http](#dragon_http)|1044|273664|60|0.0%|8.8%|
[firehol_level1](#firehol_level1)|5135|688894845|56|0.0%|8.2%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|50|0.0%|7.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|40|0.0%|5.8%|
[blocklist_de_strongips](#blocklist_de_strongips)|180|180|24|13.3%|3.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|13|0.0%|1.9%|
[blocklist_de_mail](#blocklist_de_mail)|17415|17415|6|0.0%|0.8%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|5|0.0%|0.7%|
[dshield](#dshield)|20|5120|5|0.0%|0.7%|
[blocklist_de_imap](#blocklist_de_imap)|2383|2383|5|0.2%|0.7%|
[blocklist_de_apache](#blocklist_de_apache)|15426|15426|5|0.0%|0.7%|
[stopforumspam_30d](#stopforumspam_30d)|94424|94424|2|0.0%|0.2%|
[ciarmy](#ciarmy)|457|457|2|0.4%|0.2%|
[zeus_badips](#zeus_badips)|202|202|1|0.4%|0.1%|
[zeus](#zeus)|230|230|1|0.4%|0.1%|
[snort_ipfilter](#snort_ipfilter)|10158|10158|1|0.0%|0.1%|
[php_spammers](#php_spammers)|700|700|1|0.1%|0.1%|
[php_commenters](#php_commenters)|430|430|1|0.2%|0.1%|
[nixspam](#nixspam)|39994|39994|1|0.0%|0.1%|
[blocklist_de_ftp](#blocklist_de_ftp)|1333|1333|1|0.0%|0.1%|

## palevo

[Abuse.ch Palevo tracker](https://palevotracker.abuse.ch) worm includes IPs which are being used as botnet C&C for the Palevo crimeware - **excellent list**

Source is downloaded from [this link](https://palevotracker.abuse.ch/blocklists.php?download=ipblocklist).

The last time downloaded was found to be dated: Wed Jun 10 20:27:08 UTC 2015.

The ipset `palevo` has **13** entries, **13** unique IPs.

The following table shows the overlaps of `palevo` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `palevo`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `palevo`.
- ` this % ` is the percentage **of this ipset (`palevo`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level1](#firehol_level1)|5135|688894845|13|0.0%|100.0%|
[et_block](#et_block)|1000|18344011|12|0.0%|92.3%|
[snort_ipfilter](#snort_ipfilter)|10158|10158|11|0.1%|84.6%|
[firehol_level3](#firehol_level3)|110214|9627951|11|0.0%|84.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|2|0.0%|15.3%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|7.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|1|0.0%|7.6%|

## php_commenters

[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) comment spammers (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=c&rss=1).

The last time downloaded was found to be dated: Wed Jun 10 20:36:24 UTC 2015.

The ipset `php_commenters` has **430** entries, **430** unique IPs.

The following table shows the overlaps of `php_commenters` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `php_commenters`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `php_commenters`.
- ` this % ` is the percentage **of this ipset (`php_commenters`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level3](#firehol_level3)|110214|9627951|430|0.0%|100.0%|
[stopforumspam_30d](#stopforumspam_30d)|94424|94424|318|0.3%|73.9%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|237|0.8%|55.1%|
[firehol_level2](#firehol_level2)|23442|35072|197|0.5%|45.8%|
[stopforumspam_1d](#stopforumspam_1d)|6808|6808|172|2.5%|40.0%|
[blocklist_de](#blocklist_de)|29619|29619|107|0.3%|24.8%|
[blocklist_de_bots](#blocklist_de_bots)|2933|2933|85|2.8%|19.7%|
[firehol_anonymous](#firehol_anonymous)|18837|82872|82|0.0%|19.0%|
[firehol_proxies](#firehol_proxies)|12404|12670|80|0.6%|18.6%|
[snort_ipfilter](#snort_ipfilter)|10158|10158|65|0.6%|15.1%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|52|9.9%|12.0%|
[et_tor](#et_tor)|6400|6400|51|0.7%|11.8%|
[dm_tor](#dm_tor)|6548|6548|51|0.7%|11.8%|
[bm_tor](#bm_tor)|6552|6552|51|0.7%|11.8%|
[php_spammers](#php_spammers)|700|700|50|7.1%|11.6%|
[blocklist_de_strongips](#blocklist_de_strongips)|180|180|47|26.1%|10.9%|
[firehol_level1](#firehol_level1)|5135|688894845|38|0.0%|8.8%|
[php_dictionary](#php_dictionary)|702|702|33|4.7%|7.6%|
[blocklist_de_apache](#blocklist_de_apache)|15426|15426|32|0.2%|7.4%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|29|0.0%|6.7%|
[et_block](#et_block)|1000|18344011|29|0.0%|6.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|28|0.0%|6.5%|
[blocklist_de_mail](#blocklist_de_mail)|17415|17415|27|0.1%|6.2%|
[ri_web_proxies](#ri_web_proxies)|7581|7581|25|0.3%|5.8%|
[sorbs_spam](#sorbs_spam)|59772|60402|21|0.0%|4.8%|
[sorbs_recent_spam](#sorbs_recent_spam)|59772|60402|21|0.0%|4.8%|
[sorbs_new_spam](#sorbs_new_spam)|59772|60402|21|0.0%|4.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|18|0.0%|4.1%|
[alienvault_reputation](#alienvault_reputation)|187115|187115|18|0.0%|4.1%|
[php_harvesters](#php_harvesters)|378|378|15|3.9%|3.4%|
[nixspam](#nixspam)|39994|39994|13|0.0%|3.0%|
[openbl_60d](#openbl_60d)|7012|7012|11|0.1%|2.5%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4071|4071|11|0.2%|2.5%|
[xroxy](#xroxy)|2159|2159|10|0.4%|2.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|10|0.0%|2.3%|
[proxz](#proxz)|1236|1236|9|0.7%|2.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|8|0.0%|1.8%|
[ri_connect_proxies](#ri_connect_proxies)|2737|2737|5|0.1%|1.1%|
[proxyrss](#proxyrss)|1669|1669|4|0.2%|0.9%|
[sorbs_web](#sorbs_web)|411|412|2|0.4%|0.4%|
[dragon_http](#dragon_http)|1044|273664|2|0.0%|0.4%|
[zeus_badips](#zeus_badips)|202|202|1|0.4%|0.2%|
[zeus](#zeus)|230|230|1|0.4%|0.2%|
[openbl_7d](#openbl_7d)|679|679|1|0.1%|0.2%|
[openbl_30d](#openbl_30d)|2835|2835|1|0.0%|0.2%|
[openbl_1d](#openbl_1d)|158|158|1|0.6%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.2%|
[fullbogons](#fullbogons)|3770|670213096|1|0.0%|0.2%|
[et_compromised](#et_compromised)|1721|1721|1|0.0%|0.2%|
[bruteforceblocker](#bruteforceblocker)|1711|1711|1|0.0%|0.2%|
[bogons](#bogons)|13|592708608|1|0.0%|0.2%|
[blocklist_de_ssh](#blocklist_de_ssh)|3530|3530|1|0.0%|0.2%|

## php_dictionary

[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) directory attackers (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=d&rss=1).

The last time downloaded was found to be dated: Wed Jun 10 20:36:28 UTC 2015.

The ipset `php_dictionary` has **702** entries, **702** unique IPs.

The following table shows the overlaps of `php_dictionary` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `php_dictionary`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `php_dictionary`.
- ` this % ` is the percentage **of this ipset (`php_dictionary`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level3](#firehol_level3)|110214|9627951|702|0.0%|100.0%|
[php_spammers](#php_spammers)|700|700|296|42.2%|42.1%|
[sorbs_spam](#sorbs_spam)|59772|60402|186|0.3%|26.4%|
[sorbs_recent_spam](#sorbs_recent_spam)|59772|60402|186|0.3%|26.4%|
[sorbs_new_spam](#sorbs_new_spam)|59772|60402|186|0.3%|26.4%|
[stopforumspam_30d](#stopforumspam_30d)|94424|94424|133|0.1%|18.9%|
[firehol_level2](#firehol_level2)|23442|35072|116|0.3%|16.5%|
[nixspam](#nixspam)|39994|39994|113|0.2%|16.0%|
[blocklist_de](#blocklist_de)|29619|29619|108|0.3%|15.3%|
[firehol_anonymous](#firehol_anonymous)|18837|82872|95|0.1%|13.5%|
[firehol_proxies](#firehol_proxies)|12404|12670|94|0.7%|13.3%|
[blocklist_de_mail](#blocklist_de_mail)|17415|17415|89|0.5%|12.6%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|88|0.2%|12.5%|
[snort_ipfilter](#snort_ipfilter)|10158|10158|86|0.8%|12.2%|
[ri_web_proxies](#ri_web_proxies)|7581|7581|65|0.8%|9.2%|
[xroxy](#xroxy)|2159|2159|39|1.8%|5.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|38|0.0%|5.4%|
[php_commenters](#php_commenters)|430|430|33|7.6%|4.7%|
[sorbs_web](#sorbs_web)|411|412|25|6.0%|3.5%|
[stopforumspam_1d](#stopforumspam_1d)|6808|6808|24|0.3%|3.4%|
[proxz](#proxz)|1236|1236|23|1.8%|3.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|23|0.0%|3.2%|
[blocklist_de_bots](#blocklist_de_bots)|2933|2933|15|0.5%|2.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|12|0.0%|1.7%|
[alienvault_reputation](#alienvault_reputation)|187115|187115|9|0.0%|1.2%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|6|0.0%|0.8%|
[firehol_level1](#firehol_level1)|5135|688894845|6|0.0%|0.8%|
[et_block](#et_block)|1000|18344011|6|0.0%|0.8%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|5|0.9%|0.7%|
[ri_connect_proxies](#ri_connect_proxies)|2737|2737|4|0.1%|0.5%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|4|0.0%|0.5%|
[et_tor](#et_tor)|6400|6400|4|0.0%|0.5%|
[dm_tor](#dm_tor)|6548|6548|4|0.0%|0.5%|
[bm_tor](#bm_tor)|6552|6552|4|0.0%|0.5%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4071|4071|4|0.0%|0.5%|
[blocklist_de_apache](#blocklist_de_apache)|15426|15426|4|0.0%|0.5%|
[php_harvesters](#php_harvesters)|378|378|3|0.7%|0.4%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|3|0.0%|0.4%|
[blocklist_de_strongips](#blocklist_de_strongips)|180|180|3|1.6%|0.4%|
[dragon_http](#dragon_http)|1044|273664|2|0.0%|0.2%|
[proxyrss](#proxyrss)|1669|1669|1|0.0%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.1%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|1|0.1%|0.1%|

## php_harvesters

[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) harvesters (IPs that surf the internet looking for email addresses) (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=h&rss=1).

The last time downloaded was found to be dated: Wed Jun 10 20:36:20 UTC 2015.

The ipset `php_harvesters` has **378** entries, **378** unique IPs.

The following table shows the overlaps of `php_harvesters` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `php_harvesters`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `php_harvesters`.
- ` this % ` is the percentage **of this ipset (`php_harvesters`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level3](#firehol_level3)|110214|9627951|378|0.0%|100.0%|
[stopforumspam_30d](#stopforumspam_30d)|94424|94424|83|0.0%|21.9%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|60|0.2%|15.8%|
[firehol_level2](#firehol_level2)|23442|35072|60|0.1%|15.8%|
[stopforumspam_1d](#stopforumspam_1d)|6808|6808|46|0.6%|12.1%|
[blocklist_de](#blocklist_de)|29619|29619|38|0.1%|10.0%|
[blocklist_de_bots](#blocklist_de_bots)|2933|2933|26|0.8%|6.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|20|0.0%|5.2%|
[php_commenters](#php_commenters)|430|430|15|3.4%|3.9%|
[sorbs_spam](#sorbs_spam)|59772|60402|13|0.0%|3.4%|
[sorbs_recent_spam](#sorbs_recent_spam)|59772|60402|13|0.0%|3.4%|
[sorbs_new_spam](#sorbs_new_spam)|59772|60402|13|0.0%|3.4%|
[firehol_proxies](#firehol_proxies)|12404|12670|12|0.0%|3.1%|
[firehol_anonymous](#firehol_anonymous)|18837|82872|12|0.0%|3.1%|
[alienvault_reputation](#alienvault_reputation)|187115|187115|12|0.0%|3.1%|
[snort_ipfilter](#snort_ipfilter)|10158|10158|11|0.1%|2.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|11|0.0%|2.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|9|0.0%|2.3%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|7|1.3%|1.8%|
[et_tor](#et_tor)|6400|6400|7|0.1%|1.8%|
[dm_tor](#dm_tor)|6548|6548|7|0.1%|1.8%|
[bm_tor](#bm_tor)|6552|6552|7|0.1%|1.8%|
[nixspam](#nixspam)|39994|39994|6|0.0%|1.5%|
[blocklist_de_mail](#blocklist_de_mail)|17415|17415|5|0.0%|1.3%|
[blocklist_de_ftp](#blocklist_de_ftp)|1333|1333|5|0.3%|1.3%|
[php_spammers](#php_spammers)|700|700|3|0.4%|0.7%|
[php_dictionary](#php_dictionary)|702|702|3|0.4%|0.7%|
[firehol_level1](#firehol_level1)|5135|688894845|3|0.0%|0.7%|
[blocklist_de_apache](#blocklist_de_apache)|15426|15426|3|0.0%|0.7%|
[xroxy](#xroxy)|2159|2159|2|0.0%|0.5%|
[ri_web_proxies](#ri_web_proxies)|7581|7581|2|0.0%|0.5%|
[proxyrss](#proxyrss)|1669|1669|2|0.1%|0.5%|
[openbl_60d](#openbl_60d)|7012|7012|2|0.0%|0.5%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|2|0.0%|0.5%|
[blocklist_de_strongips](#blocklist_de_strongips)|180|180|2|1.1%|0.5%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4071|4071|2|0.0%|0.5%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|1|0.0%|0.2%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|1|0.0%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.2%|
[fullbogons](#fullbogons)|3770|670213096|1|0.0%|0.2%|
[et_block](#et_block)|1000|18344011|1|0.0%|0.2%|
[bogons](#bogons)|13|592708608|1|0.0%|0.2%|
[blocklist_de_imap](#blocklist_de_imap)|2383|2383|1|0.0%|0.2%|

## php_spammers

[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) spam servers (IPs used by spammers to send messages) (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=s&rss=1).

The last time downloaded was found to be dated: Wed Jun 10 20:36:22 UTC 2015.

The ipset `php_spammers` has **700** entries, **700** unique IPs.

The following table shows the overlaps of `php_spammers` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `php_spammers`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `php_spammers`.
- ` this % ` is the percentage **of this ipset (`php_spammers`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level3](#firehol_level3)|110214|9627951|700|0.0%|100.0%|
[php_dictionary](#php_dictionary)|702|702|296|42.1%|42.2%|
[sorbs_spam](#sorbs_spam)|59772|60402|157|0.2%|22.4%|
[sorbs_recent_spam](#sorbs_recent_spam)|59772|60402|157|0.2%|22.4%|
[sorbs_new_spam](#sorbs_new_spam)|59772|60402|157|0.2%|22.4%|
[stopforumspam_30d](#stopforumspam_30d)|94424|94424|144|0.1%|20.5%|
[firehol_level2](#firehol_level2)|23442|35072|109|0.3%|15.5%|
[blocklist_de](#blocklist_de)|29619|29619|101|0.3%|14.4%|
[nixspam](#nixspam)|39994|39994|91|0.2%|13.0%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|87|0.2%|12.4%|
[snort_ipfilter](#snort_ipfilter)|10158|10158|83|0.8%|11.8%|
[firehol_anonymous](#firehol_anonymous)|18837|82872|80|0.0%|11.4%|
[firehol_proxies](#firehol_proxies)|12404|12670|78|0.6%|11.1%|
[blocklist_de_mail](#blocklist_de_mail)|17415|17415|72|0.4%|10.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|54|0.0%|7.7%|
[ri_web_proxies](#ri_web_proxies)|7581|7581|53|0.6%|7.5%|
[php_commenters](#php_commenters)|430|430|50|11.6%|7.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|43|0.0%|6.1%|
[xroxy](#xroxy)|2159|2159|32|1.4%|4.5%|
[stopforumspam_1d](#stopforumspam_1d)|6808|6808|30|0.4%|4.2%|
[proxz](#proxz)|1236|1236|21|1.6%|3.0%|
[sorbs_web](#sorbs_web)|411|412|20|4.8%|2.8%|
[blocklist_de_bots](#blocklist_de_bots)|2933|2933|20|0.6%|2.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|10|0.0%|1.4%|
[blocklist_de_strongips](#blocklist_de_strongips)|180|180|8|4.4%|1.1%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4071|4071|8|0.1%|1.1%|
[blocklist_de_apache](#blocklist_de_apache)|15426|15426|8|0.0%|1.1%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|6|1.1%|0.8%|
[alienvault_reputation](#alienvault_reputation)|187115|187115|6|0.0%|0.8%|
[et_tor](#et_tor)|6400|6400|5|0.0%|0.7%|
[dm_tor](#dm_tor)|6548|6548|5|0.0%|0.7%|
[bm_tor](#bm_tor)|6552|6552|5|0.0%|0.7%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|4|0.0%|0.5%|
[proxyrss](#proxyrss)|1669|1669|4|0.2%|0.5%|
[firehol_level1](#firehol_level1)|5135|688894845|4|0.0%|0.5%|
[et_block](#et_block)|1000|18344011|4|0.0%|0.5%|
[ri_connect_proxies](#ri_connect_proxies)|2737|2737|3|0.1%|0.4%|
[php_harvesters](#php_harvesters)|378|378|3|0.7%|0.4%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|0.4%|
[openbl_7d](#openbl_7d)|679|679|1|0.1%|0.1%|
[openbl_60d](#openbl_60d)|7012|7012|1|0.0%|0.1%|
[openbl_30d](#openbl_30d)|2835|2835|1|0.0%|0.1%|
[openbl_1d](#openbl_1d)|158|158|1|0.6%|0.1%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|1|0.0%|0.1%|
[et_compromised](#et_compromised)|1721|1721|1|0.0%|0.1%|
[bruteforceblocker](#bruteforceblocker)|1711|1711|1|0.0%|0.1%|
[blocklist_de_ssh](#blocklist_de_ssh)|3530|3530|1|0.0%|0.1%|

## proxyrss

[proxyrss.com](http://www.proxyrss.com) open proxies syndicated from multiple sources.

Source is downloaded from [this link](http://www.proxyrss.com/proxylists/all.gz).

The last time downloaded was found to be dated: Wed Jun 10 17:41:25 UTC 2015.

The ipset `proxyrss` has **1669** entries, **1669** unique IPs.

The following table shows the overlaps of `proxyrss` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `proxyrss`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `proxyrss`.
- ` this % ` is the percentage **of this ipset (`proxyrss`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_proxies](#firehol_proxies)|12404|12670|1669|13.1%|100.0%|
[firehol_anonymous](#firehol_anonymous)|18837|82872|1669|2.0%|100.0%|
[stopforumspam_30d](#stopforumspam_30d)|94424|94424|697|0.7%|41.7%|
[firehol_level3](#firehol_level3)|110214|9627951|697|0.0%|41.7%|
[ri_web_proxies](#ri_web_proxies)|7581|7581|597|7.8%|35.7%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|498|1.6%|29.8%|
[firehol_level2](#firehol_level2)|23442|35072|427|1.2%|25.5%|
[stopforumspam_1d](#stopforumspam_1d)|6808|6808|361|5.3%|21.6%|
[xroxy](#xroxy)|2159|2159|359|16.6%|21.5%|
[proxz](#proxz)|1236|1236|271|21.9%|16.2%|
[blocklist_de_bots](#blocklist_de_bots)|2933|2933|217|7.3%|13.0%|
[blocklist_de](#blocklist_de)|29619|29619|217|0.7%|13.0%|
[ri_connect_proxies](#ri_connect_proxies)|2737|2737|190|6.9%|11.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|52|0.0%|3.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|50|0.0%|2.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|33|0.0%|1.9%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|9|1.3%|0.5%|
[nixspam](#nixspam)|39994|39994|7|0.0%|0.4%|
[sorbs_spam](#sorbs_spam)|59772|60402|6|0.0%|0.3%|
[sorbs_recent_spam](#sorbs_recent_spam)|59772|60402|6|0.0%|0.3%|
[sorbs_new_spam](#sorbs_new_spam)|59772|60402|6|0.0%|0.3%|
[snort_ipfilter](#snort_ipfilter)|10158|10158|6|0.0%|0.3%|
[blocklist_de_strongips](#blocklist_de_strongips)|180|180|5|2.7%|0.2%|
[php_spammers](#php_spammers)|700|700|4|0.5%|0.2%|
[php_commenters](#php_commenters)|430|430|4|0.9%|0.2%|
[php_harvesters](#php_harvesters)|378|378|2|0.5%|0.1%|
[dragon_http](#dragon_http)|1044|273664|2|0.0%|0.1%|
[php_dictionary](#php_dictionary)|702|702|1|0.1%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|1|0.1%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.0%|
[et_compromised](#et_compromised)|1721|1721|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1711|1711|1|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|17415|17415|1|0.0%|0.0%|
[alienvault_reputation](#alienvault_reputation)|187115|187115|1|0.0%|0.0%|

## proxz

[proxz.com](http://www.proxz.com) open proxies (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.proxz.com/proxylists.xml).

The last time downloaded was found to be dated: Wed Jun 10 20:01:31 UTC 2015.

The ipset `proxz` has **1236** entries, **1236** unique IPs.

The following table shows the overlaps of `proxz` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `proxz`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `proxz`.
- ` this % ` is the percentage **of this ipset (`proxz`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_proxies](#firehol_proxies)|12404|12670|1236|9.7%|100.0%|
[firehol_anonymous](#firehol_anonymous)|18837|82872|1236|1.4%|100.0%|
[firehol_level3](#firehol_level3)|110214|9627951|736|0.0%|59.5%|
[stopforumspam_30d](#stopforumspam_30d)|94424|94424|730|0.7%|59.0%|
[ri_web_proxies](#ri_web_proxies)|7581|7581|569|7.5%|46.0%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|494|1.6%|39.9%|
[xroxy](#xroxy)|2159|2159|442|20.4%|35.7%|
[proxyrss](#proxyrss)|1669|1669|271|16.2%|21.9%|
[firehol_level2](#firehol_level2)|23442|35072|264|0.7%|21.3%|
[ri_connect_proxies](#ri_connect_proxies)|2737|2737|212|7.7%|17.1%|
[blocklist_de](#blocklist_de)|29619|29619|179|0.6%|14.4%|
[stopforumspam_1d](#stopforumspam_1d)|6808|6808|175|2.5%|14.1%|
[blocklist_de_bots](#blocklist_de_bots)|2933|2933|151|5.1%|12.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|102|0.0%|8.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|51|0.0%|4.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|43|0.0%|3.4%|
[sorbs_spam](#sorbs_spam)|59772|60402|42|0.0%|3.3%|
[sorbs_recent_spam](#sorbs_recent_spam)|59772|60402|42|0.0%|3.3%|
[sorbs_new_spam](#sorbs_new_spam)|59772|60402|42|0.0%|3.3%|
[nixspam](#nixspam)|39994|39994|39|0.0%|3.1%|
[blocklist_de_mail](#blocklist_de_mail)|17415|17415|29|0.1%|2.3%|
[snort_ipfilter](#snort_ipfilter)|10158|10158|26|0.2%|2.1%|
[php_dictionary](#php_dictionary)|702|702|23|3.2%|1.8%|
[php_spammers](#php_spammers)|700|700|21|3.0%|1.6%|
[php_commenters](#php_commenters)|430|430|9|2.0%|0.7%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|6|0.9%|0.4%|
[sorbs_web](#sorbs_web)|411|412|5|1.2%|0.4%|
[blocklist_de_strongips](#blocklist_de_strongips)|180|180|5|2.7%|0.4%|
[dragon_http](#dragon_http)|1044|273664|4|0.0%|0.3%|
[alienvault_reputation](#alienvault_reputation)|187115|187115|3|0.0%|0.2%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|2|0.3%|0.1%|
[et_compromised](#et_compromised)|1721|1721|2|0.1%|0.1%|
[bruteforceblocker](#bruteforceblocker)|1711|1711|2|0.1%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|1|0.0%|0.0%|

## ri_connect_proxies

[rosinstrument.com](http://www.rosinstrument.com) open CONNECT proxies (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://tools.rosinstrument.com/proxy/plab100.xml).

The last time downloaded was found to be dated: Wed Jun 10 14:29:15 UTC 2015.

The ipset `ri_connect_proxies` has **2737** entries, **2737** unique IPs.

The following table shows the overlaps of `ri_connect_proxies` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ri_connect_proxies`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ri_connect_proxies`.
- ` this % ` is the percentage **of this ipset (`ri_connect_proxies`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_proxies](#firehol_proxies)|12404|12670|2737|21.6%|100.0%|
[firehol_anonymous](#firehol_anonymous)|18837|82872|2737|3.3%|100.0%|
[stopforumspam_30d](#stopforumspam_30d)|94424|94424|1544|1.6%|56.4%|
[firehol_level3](#firehol_level3)|110214|9627951|1544|0.0%|56.4%|
[ri_web_proxies](#ri_web_proxies)|7581|7581|1165|15.3%|42.5%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|590|2.0%|21.5%|
[xroxy](#xroxy)|2159|2159|391|18.1%|14.2%|
[proxz](#proxz)|1236|1236|212|17.1%|7.7%|
[proxyrss](#proxyrss)|1669|1669|190|11.3%|6.9%|
[firehol_level2](#firehol_level2)|23442|35072|155|0.4%|5.6%|
[stopforumspam_1d](#stopforumspam_1d)|6808|6808|107|1.5%|3.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|105|0.0%|3.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|83|0.0%|3.0%|
[blocklist_de](#blocklist_de)|29619|29619|74|0.2%|2.7%|
[blocklist_de_bots](#blocklist_de_bots)|2933|2933|70|2.3%|2.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|57|0.0%|2.0%|
[sorbs_spam](#sorbs_spam)|59772|60402|13|0.0%|0.4%|
[sorbs_recent_spam](#sorbs_recent_spam)|59772|60402|13|0.0%|0.4%|
[sorbs_new_spam](#sorbs_new_spam)|59772|60402|13|0.0%|0.4%|
[nixspam](#nixspam)|39994|39994|12|0.0%|0.4%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|7|1.0%|0.2%|
[php_commenters](#php_commenters)|430|430|5|1.1%|0.1%|
[snort_ipfilter](#snort_ipfilter)|10158|10158|4|0.0%|0.1%|
[php_dictionary](#php_dictionary)|702|702|4|0.5%|0.1%|
[blocklist_de_mail](#blocklist_de_mail)|17415|17415|4|0.0%|0.1%|
[php_spammers](#php_spammers)|700|700|3|0.4%|0.1%|
[dragon_http](#dragon_http)|1044|273664|3|0.0%|0.1%|
[alienvault_reputation](#alienvault_reputation)|187115|187115|3|0.0%|0.1%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|1|0.1%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.0%|
[dm_tor](#dm_tor)|6548|6548|1|0.0%|0.0%|
[bm_tor](#bm_tor)|6552|6552|1|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2383|2383|1|0.0%|0.0%|

## ri_web_proxies

[rosinstrument.com](http://www.rosinstrument.com) open HTTP proxies (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://tools.rosinstrument.com/proxy/l100.xml).

The last time downloaded was found to be dated: Wed Jun 10 17:26:46 UTC 2015.

The ipset `ri_web_proxies` has **7581** entries, **7581** unique IPs.

The following table shows the overlaps of `ri_web_proxies` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ri_web_proxies`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ri_web_proxies`.
- ` this % ` is the percentage **of this ipset (`ri_web_proxies`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_proxies](#firehol_proxies)|12404|12670|7581|59.8%|100.0%|
[firehol_anonymous](#firehol_anonymous)|18837|82872|7581|9.1%|100.0%|
[firehol_level3](#firehol_level3)|110214|9627951|3648|0.0%|48.1%|
[stopforumspam_30d](#stopforumspam_30d)|94424|94424|3605|3.8%|47.5%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|1544|5.2%|20.3%|
[ri_connect_proxies](#ri_connect_proxies)|2737|2737|1165|42.5%|15.3%|
[xroxy](#xroxy)|2159|2159|951|44.0%|12.5%|
[firehol_level2](#firehol_level2)|23442|35072|679|1.9%|8.9%|
[proxyrss](#proxyrss)|1669|1669|597|35.7%|7.8%|
[proxz](#proxz)|1236|1236|569|46.0%|7.5%|
[blocklist_de](#blocklist_de)|29619|29619|447|1.5%|5.8%|
[stopforumspam_1d](#stopforumspam_1d)|6808|6808|446|6.5%|5.8%|
[blocklist_de_bots](#blocklist_de_bots)|2933|2933|366|12.4%|4.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|222|0.0%|2.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|218|0.0%|2.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|153|0.0%|2.0%|
[sorbs_spam](#sorbs_spam)|59772|60402|127|0.2%|1.6%|
[sorbs_recent_spam](#sorbs_recent_spam)|59772|60402|127|0.2%|1.6%|
[sorbs_new_spam](#sorbs_new_spam)|59772|60402|127|0.2%|1.6%|
[nixspam](#nixspam)|39994|39994|118|0.2%|1.5%|
[blocklist_de_mail](#blocklist_de_mail)|17415|17415|73|0.4%|0.9%|
[php_dictionary](#php_dictionary)|702|702|65|9.2%|0.8%|
[snort_ipfilter](#snort_ipfilter)|10158|10158|58|0.5%|0.7%|
[php_spammers](#php_spammers)|700|700|53|7.5%|0.6%|
[php_commenters](#php_commenters)|430|430|25|5.8%|0.3%|
[dragon_http](#dragon_http)|1044|273664|16|0.0%|0.2%|
[sorbs_web](#sorbs_web)|411|412|15|3.6%|0.1%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|14|2.1%|0.1%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|10|1.9%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|6|0.0%|0.0%|
[dm_tor](#dm_tor)|6548|6548|5|0.0%|0.0%|
[bm_tor](#bm_tor)|6552|6552|5|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|180|180|5|2.7%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4071|4071|5|0.1%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|15426|15426|5|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|4|0.0%|0.0%|
[et_tor](#et_tor)|6400|6400|4|0.0%|0.0%|
[alienvault_reputation](#alienvault_reputation)|187115|187115|4|0.0%|0.0%|
[php_harvesters](#php_harvesters)|378|378|2|0.5%|0.0%|
[sslbl](#sslbl)|372|372|1|0.2%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|1|0.0%|0.0%|
[firehol_level1](#firehol_level1)|5135|688894845|1|0.0%|0.0%|
[et_compromised](#et_compromised)|1721|1721|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1711|1711|1|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3530|3530|1|0.0%|0.0%|

## shunlist

[AutoShun.org](http://autoshun.org/) IPs identified as hostile by correlating logs from distributed snort installations running the autoshun plugin

Source is downloaded from [this link](http://www.autoshun.org/files/shunlist.csv).

The last time downloaded was found to be dated: Wed Jun 10 19:30:03 UTC 2015.

The ipset `shunlist` has **1225** entries, **1225** unique IPs.

The following table shows the overlaps of `shunlist` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `shunlist`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `shunlist`.
- ` this % ` is the percentage **of this ipset (`shunlist`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level3](#firehol_level3)|110214|9627951|1225|0.0%|100.0%|
[alienvault_reputation](#alienvault_reputation)|187115|187115|1213|0.6%|99.0%|
[openbl_60d](#openbl_60d)|7012|7012|528|7.5%|43.1%|
[openbl_30d](#openbl_30d)|2835|2835|499|17.6%|40.7%|
[firehol_level2](#firehol_level2)|23442|35072|423|1.2%|34.5%|
[et_compromised](#et_compromised)|1721|1721|421|24.4%|34.3%|
[blocklist_de](#blocklist_de)|29619|29619|421|1.4%|34.3%|
[bruteforceblocker](#bruteforceblocker)|1711|1711|395|23.0%|32.2%|
[blocklist_de_ssh](#blocklist_de_ssh)|3530|3530|386|10.9%|31.5%|
[openbl_7d](#openbl_7d)|679|679|209|30.7%|17.0%|
[firehol_level1](#firehol_level1)|5135|688894845|173|0.0%|14.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|116|0.0%|9.4%|
[et_block](#et_block)|1000|18344011|113|0.0%|9.2%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|92|0.0%|7.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|68|0.0%|5.5%|
[sslbl](#sslbl)|372|372|61|16.3%|4.9%|
[openbl_1d](#openbl_1d)|158|158|57|36.0%|4.6%|
[dragon_http](#dragon_http)|1044|273664|37|0.0%|3.0%|
[blocklist_de_apache](#blocklist_de_apache)|15426|15426|31|0.2%|2.5%|
[ciarmy](#ciarmy)|457|457|30|6.5%|2.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|25|0.0%|2.0%|
[dshield](#dshield)|20|5120|20|0.3%|1.6%|
[blocklist_de_strongips](#blocklist_de_strongips)|180|180|19|10.5%|1.5%|
[voipbl](#voipbl)|10533|10945|12|0.1%|0.9%|
[stopforumspam_30d](#stopforumspam_30d)|94424|94424|3|0.0%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|0.2%|
[blocklist_de_mail](#blocklist_de_mail)|17415|17415|3|0.0%|0.2%|
[sorbs_spam](#sorbs_spam)|59772|60402|2|0.0%|0.1%|
[sorbs_recent_spam](#sorbs_recent_spam)|59772|60402|2|0.0%|0.1%|
[sorbs_new_spam](#sorbs_new_spam)|59772|60402|2|0.0%|0.1%|
[snort_ipfilter](#snort_ipfilter)|10158|10158|2|0.0%|0.1%|
[nixspam](#nixspam)|39994|39994|2|0.0%|0.1%|
[blocklist_de_imap](#blocklist_de_imap)|2383|2383|2|0.0%|0.1%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|1|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6808|6808|1|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|1|0.1%|0.0%|
[firehol_proxies](#firehol_proxies)|12404|12670|1|0.0%|0.0%|
[firehol_anonymous](#firehol_anonymous)|18837|82872|1|0.0%|0.0%|
[et_tor](#et_tor)|6400|6400|1|0.0%|0.0%|
[dm_tor](#dm_tor)|6548|6548|1|0.0%|0.0%|
[bm_tor](#bm_tor)|6552|6552|1|0.0%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|79|79|1|1.2%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4071|4071|1|0.0%|0.0%|

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
[firehol_level3](#firehol_level3)|110214|9627951|10158|0.1%|100.0%|
[firehol_anonymous](#firehol_anonymous)|18837|82872|1167|1.4%|11.4%|
[et_tor](#et_tor)|6400|6400|1089|17.0%|10.7%|
[bm_tor](#bm_tor)|6552|6552|1079|16.4%|10.6%|
[dm_tor](#dm_tor)|6548|6548|1078|16.4%|10.6%|
[sorbs_spam](#sorbs_spam)|59772|60402|1037|1.7%|10.2%|
[sorbs_recent_spam](#sorbs_recent_spam)|59772|60402|1037|1.7%|10.2%|
[sorbs_new_spam](#sorbs_new_spam)|59772|60402|1037|1.7%|10.2%|
[stopforumspam_30d](#stopforumspam_30d)|94424|94424|816|0.8%|8.0%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|658|2.2%|6.4%|
[firehol_level2](#firehol_level2)|23442|35072|603|1.7%|5.9%|
[stopforumspam_1d](#stopforumspam_1d)|6808|6808|422|6.1%|4.1%|
[nixspam](#nixspam)|39994|39994|341|0.8%|3.3%|
[firehol_proxies](#firehol_proxies)|12404|12670|320|2.5%|3.1%|
[firehol_level1](#firehol_level1)|5135|688894845|302|0.0%|2.9%|
[et_block](#et_block)|1000|18344011|298|0.0%|2.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|243|0.0%|2.3%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|239|45.6%|2.3%|
[blocklist_de](#blocklist_de)|29619|29619|216|0.7%|2.1%|
[zeus](#zeus)|230|230|200|86.9%|1.9%|
[zeus_badips](#zeus_badips)|202|202|178|88.1%|1.7%|
[blocklist_de_mail](#blocklist_de_mail)|17415|17415|161|0.9%|1.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|158|0.0%|1.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|117|0.0%|1.1%|
[alienvault_reputation](#alienvault_reputation)|187115|187115|112|0.0%|1.1%|
[php_dictionary](#php_dictionary)|702|702|86|12.2%|0.8%|
[php_spammers](#php_spammers)|700|700|83|11.8%|0.8%|
[feodo](#feodo)|105|105|83|79.0%|0.8%|
[php_commenters](#php_commenters)|430|430|65|15.1%|0.6%|
[ri_web_proxies](#ri_web_proxies)|7581|7581|58|0.7%|0.5%|
[sorbs_web](#sorbs_web)|411|412|46|11.1%|0.4%|
[xroxy](#xroxy)|2159|2159|41|1.8%|0.4%|
[blocklist_de_apache](#blocklist_de_apache)|15426|15426|41|0.2%|0.4%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4071|4071|37|0.9%|0.3%|
[sslbl](#sslbl)|372|372|32|8.6%|0.3%|
[proxz](#proxz)|1236|1236|26|2.1%|0.2%|
[openbl_60d](#openbl_60d)|7012|7012|25|0.3%|0.2%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|19|0.0%|0.1%|
[blocklist_de_bots](#blocklist_de_bots)|2933|2933|18|0.6%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|14|0.0%|0.1%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|12|0.9%|0.1%|
[php_harvesters](#php_harvesters)|378|378|11|2.9%|0.1%|
[palevo](#palevo)|13|13|11|84.6%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|11|0.0%|0.1%|
[dragon_http](#dragon_http)|1044|273664|7|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2383|2383|7|0.2%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|6|0.0%|0.0%|
[proxyrss](#proxyrss)|1669|1669|6|0.3%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2737|2737|4|0.1%|0.0%|
[openbl_30d](#openbl_30d)|2835|2835|3|0.1%|0.0%|
[shunlist](#shunlist)|1225|1225|2|0.1%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|123|123|2|1.6%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|180|180|2|1.1%|0.0%|
[voipbl](#voipbl)|10533|10945|1|0.0%|0.0%|
[virbl](#virbl)|30|30|1|3.3%|0.0%|
[openbl_7d](#openbl_7d)|679|679|1|0.1%|0.0%|
[openbl_1d](#openbl_1d)|158|158|1|0.6%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|1|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|1|0.1%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|1|0.0%|0.0%|
[et_compromised](#et_compromised)|1721|1721|1|0.0%|0.0%|
[dshield](#dshield)|20|5120|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1711|1711|1|0.0%|0.0%|

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

The last time downloaded was found to be dated: Wed Jun 10 18:41:10 UTC 2015.

The ipset `sorbs_http` has **2** entries, **2** unique IPs.

The following table shows the overlaps of `sorbs_http` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `sorbs_http`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `sorbs_http`.
- ` this % ` is the percentage **of this ipset (`sorbs_http`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[sorbs_spam](#sorbs_spam)|59772|60402|2|0.0%|100.0%|
[sorbs_socks](#sorbs_socks)|2|2|2|100.0%|100.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|59772|60402|2|0.0%|100.0%|
[sorbs_new_spam](#sorbs_new_spam)|59772|60402|2|0.0%|100.0%|
[sorbs_misc](#sorbs_misc)|2|2|2|100.0%|100.0%|
[nixspam](#nixspam)|39994|39994|2|0.0%|100.0%|

## sorbs_misc

[Sorbs.net](https://www.sorbs.net/) MISC proxies, extracted from deltas.

Source is downloaded from [this link]().

The last time downloaded was found to be dated: Wed Jun 10 18:41:11 UTC 2015.

The ipset `sorbs_misc` has **2** entries, **2** unique IPs.

The following table shows the overlaps of `sorbs_misc` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `sorbs_misc`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `sorbs_misc`.
- ` this % ` is the percentage **of this ipset (`sorbs_misc`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[sorbs_spam](#sorbs_spam)|59772|60402|2|0.0%|100.0%|
[sorbs_socks](#sorbs_socks)|2|2|2|100.0%|100.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|59772|60402|2|0.0%|100.0%|
[sorbs_new_spam](#sorbs_new_spam)|59772|60402|2|0.0%|100.0%|
[sorbs_http](#sorbs_http)|2|2|2|100.0%|100.0%|
[nixspam](#nixspam)|39994|39994|2|0.0%|100.0%|

## sorbs_new_spam

[Sorbs.net](https://www.sorbs.net/) NEW Spam senders, extracted from deltas.

Source is downloaded from [this link]().

The last time downloaded was found to be dated: Wed Jun 10 20:04:33 UTC 2015.

The ipset `sorbs_new_spam` has **59772** entries, **60402** unique IPs.

The following table shows the overlaps of `sorbs_new_spam` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `sorbs_new_spam`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `sorbs_new_spam`.
- ` this % ` is the percentage **of this ipset (`sorbs_new_spam`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[sorbs_spam](#sorbs_spam)|59772|60402|60402|100.0%|100.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|59772|60402|60402|100.0%|100.0%|
[nixspam](#nixspam)|39994|39994|10698|26.7%|17.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|2477|0.0%|4.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|1617|0.0%|2.6%|
[firehol_level3](#firehol_level3)|110214|9627951|1388|0.0%|2.2%|
[firehol_level2](#firehol_level2)|23442|35072|1315|3.7%|2.1%|
[blocklist_de](#blocklist_de)|29619|29619|1302|4.3%|2.1%|
[blocklist_de_mail](#blocklist_de_mail)|17415|17415|1201|6.8%|1.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|1128|0.0%|1.8%|
[snort_ipfilter](#snort_ipfilter)|10158|10158|1037|10.2%|1.7%|
[stopforumspam_30d](#stopforumspam_30d)|94424|94424|280|0.2%|0.4%|
[sorbs_web](#sorbs_web)|411|412|232|56.3%|0.3%|
[php_dictionary](#php_dictionary)|702|702|186|26.4%|0.3%|
[firehol_anonymous](#firehol_anonymous)|18837|82872|182|0.2%|0.3%|
[firehol_proxies](#firehol_proxies)|12404|12670|178|1.4%|0.2%|
[php_spammers](#php_spammers)|700|700|157|22.4%|0.2%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|151|0.5%|0.2%|
[ri_web_proxies](#ri_web_proxies)|7581|7581|127|1.6%|0.2%|
[alienvault_reputation](#alienvault_reputation)|187115|187115|85|0.0%|0.1%|
[xroxy](#xroxy)|2159|2159|73|3.3%|0.1%|
[dragon_http](#dragon_http)|1044|273664|58|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4071|4071|57|1.4%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|15426|15426|57|0.3%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6808|6808|42|0.6%|0.0%|
[proxz](#proxz)|1236|1236|42|3.3%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|32|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|2933|2933|32|1.0%|0.0%|
[firehol_level1](#firehol_level1)|5135|688894845|25|0.0%|0.0%|
[et_block](#et_block)|1000|18344011|22|0.0%|0.0%|
[php_commenters](#php_commenters)|430|430|21|4.8%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|20|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|20|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2383|2383|20|0.8%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|15|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2737|2737|13|0.4%|0.0%|
[php_harvesters](#php_harvesters)|378|378|13|3.4%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|1333|1333|7|0.5%|0.0%|
[proxyrss](#proxyrss)|1669|1669|6|0.3%|0.0%|
[et_tor](#et_tor)|6400|6400|4|0.0%|0.0%|
[dm_tor](#dm_tor)|6548|6548|4|0.0%|0.0%|
[bm_tor](#bm_tor)|6552|6552|4|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3530|3530|4|0.1%|0.0%|
[sorbs_smtp](#sorbs_smtp)|3|3|3|100.0%|0.0%|
[et_compromised](#et_compromised)|1721|1721|3|0.1%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1711|1711|3|0.1%|0.0%|
[voipbl](#voipbl)|10533|10945|2|0.0%|0.0%|
[sorbs_socks](#sorbs_socks)|2|2|2|100.0%|0.0%|
[sorbs_misc](#sorbs_misc)|2|2|2|100.0%|0.0%|
[sorbs_http](#sorbs_http)|2|2|2|100.0%|0.0%|
[shunlist](#shunlist)|1225|1225|2|0.1%|0.0%|
[openbl_60d](#openbl_60d)|7012|7012|2|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|2|0.1%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|180|180|2|1.1%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|1|0.1%|0.0%|
[malc0de](#malc0de)|313|313|1|0.3%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|1|0.1%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.0%|

## sorbs_recent_spam

[Sorbs.net](https://www.sorbs.net/) RECENT Spam senders, extracted from deltas.

Source is downloaded from [this link]().

The last time downloaded was found to be dated: Wed Jun 10 20:04:32 UTC 2015.

The ipset `sorbs_recent_spam` has **59772** entries, **60402** unique IPs.

The following table shows the overlaps of `sorbs_recent_spam` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `sorbs_recent_spam`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `sorbs_recent_spam`.
- ` this % ` is the percentage **of this ipset (`sorbs_recent_spam`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[sorbs_spam](#sorbs_spam)|59772|60402|60402|100.0%|100.0%|
[sorbs_new_spam](#sorbs_new_spam)|59772|60402|60402|100.0%|100.0%|
[nixspam](#nixspam)|39994|39994|10698|26.7%|17.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|2477|0.0%|4.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|1617|0.0%|2.6%|
[firehol_level3](#firehol_level3)|110214|9627951|1388|0.0%|2.2%|
[firehol_level2](#firehol_level2)|23442|35072|1315|3.7%|2.1%|
[blocklist_de](#blocklist_de)|29619|29619|1302|4.3%|2.1%|
[blocklist_de_mail](#blocklist_de_mail)|17415|17415|1201|6.8%|1.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|1128|0.0%|1.8%|
[snort_ipfilter](#snort_ipfilter)|10158|10158|1037|10.2%|1.7%|
[stopforumspam_30d](#stopforumspam_30d)|94424|94424|280|0.2%|0.4%|
[sorbs_web](#sorbs_web)|411|412|232|56.3%|0.3%|
[php_dictionary](#php_dictionary)|702|702|186|26.4%|0.3%|
[firehol_anonymous](#firehol_anonymous)|18837|82872|182|0.2%|0.3%|
[firehol_proxies](#firehol_proxies)|12404|12670|178|1.4%|0.2%|
[php_spammers](#php_spammers)|700|700|157|22.4%|0.2%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|151|0.5%|0.2%|
[ri_web_proxies](#ri_web_proxies)|7581|7581|127|1.6%|0.2%|
[alienvault_reputation](#alienvault_reputation)|187115|187115|85|0.0%|0.1%|
[xroxy](#xroxy)|2159|2159|73|3.3%|0.1%|
[dragon_http](#dragon_http)|1044|273664|58|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4071|4071|57|1.4%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|15426|15426|57|0.3%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6808|6808|42|0.6%|0.0%|
[proxz](#proxz)|1236|1236|42|3.3%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|32|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|2933|2933|32|1.0%|0.0%|
[firehol_level1](#firehol_level1)|5135|688894845|25|0.0%|0.0%|
[et_block](#et_block)|1000|18344011|22|0.0%|0.0%|
[php_commenters](#php_commenters)|430|430|21|4.8%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|20|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|20|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2383|2383|20|0.8%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|15|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2737|2737|13|0.4%|0.0%|
[php_harvesters](#php_harvesters)|378|378|13|3.4%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|1333|1333|7|0.5%|0.0%|
[proxyrss](#proxyrss)|1669|1669|6|0.3%|0.0%|
[et_tor](#et_tor)|6400|6400|4|0.0%|0.0%|
[dm_tor](#dm_tor)|6548|6548|4|0.0%|0.0%|
[bm_tor](#bm_tor)|6552|6552|4|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3530|3530|4|0.1%|0.0%|
[sorbs_smtp](#sorbs_smtp)|3|3|3|100.0%|0.0%|
[et_compromised](#et_compromised)|1721|1721|3|0.1%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1711|1711|3|0.1%|0.0%|
[voipbl](#voipbl)|10533|10945|2|0.0%|0.0%|
[sorbs_socks](#sorbs_socks)|2|2|2|100.0%|0.0%|
[sorbs_misc](#sorbs_misc)|2|2|2|100.0%|0.0%|
[sorbs_http](#sorbs_http)|2|2|2|100.0%|0.0%|
[shunlist](#shunlist)|1225|1225|2|0.1%|0.0%|
[openbl_60d](#openbl_60d)|7012|7012|2|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|2|0.1%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|180|180|2|1.1%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|1|0.1%|0.0%|
[malc0de](#malc0de)|313|313|1|0.3%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|1|0.1%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.0%|

## sorbs_smtp

[Sorbs.net](https://www.sorbs.net/) SMTP Open Relays, extracted from deltas.

Source is downloaded from [this link]().

The last time downloaded was found to be dated: Wed Jun 10 18:41:13 UTC 2015.

The ipset `sorbs_smtp` has **3** entries, **3** unique IPs.

The following table shows the overlaps of `sorbs_smtp` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `sorbs_smtp`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `sorbs_smtp`.
- ` this % ` is the percentage **of this ipset (`sorbs_smtp`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[sorbs_spam](#sorbs_spam)|59772|60402|3|0.0%|100.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|59772|60402|3|0.0%|100.0%|
[sorbs_new_spam](#sorbs_new_spam)|59772|60402|3|0.0%|100.0%|

## sorbs_socks

[Sorbs.net](https://www.sorbs.net/) SOCKS proxies, extracted from deltas.

Source is downloaded from [this link]().

The last time downloaded was found to be dated: Wed Jun 10 18:41:12 UTC 2015.

The ipset `sorbs_socks` has **2** entries, **2** unique IPs.

The following table shows the overlaps of `sorbs_socks` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `sorbs_socks`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `sorbs_socks`.
- ` this % ` is the percentage **of this ipset (`sorbs_socks`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[sorbs_spam](#sorbs_spam)|59772|60402|2|0.0%|100.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|59772|60402|2|0.0%|100.0%|
[sorbs_new_spam](#sorbs_new_spam)|59772|60402|2|0.0%|100.0%|
[sorbs_misc](#sorbs_misc)|2|2|2|100.0%|100.0%|
[sorbs_http](#sorbs_http)|2|2|2|100.0%|100.0%|
[nixspam](#nixspam)|39994|39994|2|0.0%|100.0%|

## sorbs_spam

[Sorbs.net](https://www.sorbs.net/) Spam senders, extracted from deltas.

Source is downloaded from [this link]().

The last time downloaded was found to be dated: Wed Jun 10 20:04:32 UTC 2015.

The ipset `sorbs_spam` has **59772** entries, **60402** unique IPs.

The following table shows the overlaps of `sorbs_spam` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `sorbs_spam`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `sorbs_spam`.
- ` this % ` is the percentage **of this ipset (`sorbs_spam`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[sorbs_recent_spam](#sorbs_recent_spam)|59772|60402|60402|100.0%|100.0%|
[sorbs_new_spam](#sorbs_new_spam)|59772|60402|60402|100.0%|100.0%|
[nixspam](#nixspam)|39994|39994|10698|26.7%|17.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|2477|0.0%|4.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|1617|0.0%|2.6%|
[firehol_level3](#firehol_level3)|110214|9627951|1388|0.0%|2.2%|
[firehol_level2](#firehol_level2)|23442|35072|1315|3.7%|2.1%|
[blocklist_de](#blocklist_de)|29619|29619|1302|4.3%|2.1%|
[blocklist_de_mail](#blocklist_de_mail)|17415|17415|1201|6.8%|1.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|1128|0.0%|1.8%|
[snort_ipfilter](#snort_ipfilter)|10158|10158|1037|10.2%|1.7%|
[stopforumspam_30d](#stopforumspam_30d)|94424|94424|280|0.2%|0.4%|
[sorbs_web](#sorbs_web)|411|412|232|56.3%|0.3%|
[php_dictionary](#php_dictionary)|702|702|186|26.4%|0.3%|
[firehol_anonymous](#firehol_anonymous)|18837|82872|182|0.2%|0.3%|
[firehol_proxies](#firehol_proxies)|12404|12670|178|1.4%|0.2%|
[php_spammers](#php_spammers)|700|700|157|22.4%|0.2%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|151|0.5%|0.2%|
[ri_web_proxies](#ri_web_proxies)|7581|7581|127|1.6%|0.2%|
[alienvault_reputation](#alienvault_reputation)|187115|187115|85|0.0%|0.1%|
[xroxy](#xroxy)|2159|2159|73|3.3%|0.1%|
[dragon_http](#dragon_http)|1044|273664|58|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4071|4071|57|1.4%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|15426|15426|57|0.3%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6808|6808|42|0.6%|0.0%|
[proxz](#proxz)|1236|1236|42|3.3%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|32|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|2933|2933|32|1.0%|0.0%|
[firehol_level1](#firehol_level1)|5135|688894845|25|0.0%|0.0%|
[et_block](#et_block)|1000|18344011|22|0.0%|0.0%|
[php_commenters](#php_commenters)|430|430|21|4.8%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|20|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|20|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2383|2383|20|0.8%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|15|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2737|2737|13|0.4%|0.0%|
[php_harvesters](#php_harvesters)|378|378|13|3.4%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|1333|1333|7|0.5%|0.0%|
[proxyrss](#proxyrss)|1669|1669|6|0.3%|0.0%|
[et_tor](#et_tor)|6400|6400|4|0.0%|0.0%|
[dm_tor](#dm_tor)|6548|6548|4|0.0%|0.0%|
[bm_tor](#bm_tor)|6552|6552|4|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3530|3530|4|0.1%|0.0%|
[sorbs_smtp](#sorbs_smtp)|3|3|3|100.0%|0.0%|
[et_compromised](#et_compromised)|1721|1721|3|0.1%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1711|1711|3|0.1%|0.0%|
[voipbl](#voipbl)|10533|10945|2|0.0%|0.0%|
[sorbs_socks](#sorbs_socks)|2|2|2|100.0%|0.0%|
[sorbs_misc](#sorbs_misc)|2|2|2|100.0%|0.0%|
[sorbs_http](#sorbs_http)|2|2|2|100.0%|0.0%|
[shunlist](#shunlist)|1225|1225|2|0.1%|0.0%|
[openbl_60d](#openbl_60d)|7012|7012|2|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|2|0.1%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|180|180|2|1.1%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|1|0.1%|0.0%|
[malc0de](#malc0de)|313|313|1|0.3%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|1|0.1%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.0%|

## sorbs_web

[Sorbs.net](https://www.sorbs.net/) WEB exploits, extracted from deltas.

Source is downloaded from [this link]().

The last time downloaded was found to be dated: Wed Jun 10 20:04:32 UTC 2015.

The ipset `sorbs_web` has **411** entries, **412** unique IPs.

The following table shows the overlaps of `sorbs_web` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `sorbs_web`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `sorbs_web`.
- ` this % ` is the percentage **of this ipset (`sorbs_web`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[sorbs_spam](#sorbs_spam)|59772|60402|232|0.3%|56.3%|
[sorbs_recent_spam](#sorbs_recent_spam)|59772|60402|232|0.3%|56.3%|
[sorbs_new_spam](#sorbs_new_spam)|59772|60402|232|0.3%|56.3%|
[nixspam](#nixspam)|39994|39994|124|0.3%|30.0%|
[firehol_level3](#firehol_level3)|110214|9627951|56|0.0%|13.5%|
[firehol_level2](#firehol_level2)|23442|35072|54|0.1%|13.1%|
[blocklist_de](#blocklist_de)|29619|29619|54|0.1%|13.1%|
[blocklist_de_mail](#blocklist_de_mail)|17415|17415|51|0.2%|12.3%|
[snort_ipfilter](#snort_ipfilter)|10158|10158|46|0.4%|11.1%|
[stopforumspam_30d](#stopforumspam_30d)|94424|94424|31|0.0%|7.5%|
[php_dictionary](#php_dictionary)|702|702|25|3.5%|6.0%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|22|0.0%|5.3%|
[php_spammers](#php_spammers)|700|700|20|2.8%|4.8%|
[firehol_proxies](#firehol_proxies)|12404|12670|19|0.1%|4.6%|
[firehol_anonymous](#firehol_anonymous)|18837|82872|19|0.0%|4.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|18|0.0%|4.3%|
[ri_web_proxies](#ri_web_proxies)|7581|7581|15|0.1%|3.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|13|0.0%|3.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|11|0.0%|2.6%|
[xroxy](#xroxy)|2159|2159|9|0.4%|2.1%|
[stopforumspam_1d](#stopforumspam_1d)|6808|6808|5|0.0%|1.2%|
[proxz](#proxz)|1236|1236|5|0.4%|1.2%|
[php_commenters](#php_commenters)|430|430|2|0.4%|0.4%|
[blocklist_de_bots](#blocklist_de_bots)|2933|2933|2|0.0%|0.4%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|1|0.0%|0.2%|
[blocklist_de_strongips](#blocklist_de_strongips)|180|180|1|0.5%|0.2%|
[blocklist_de_ftp](#blocklist_de_ftp)|1333|1333|1|0.0%|0.2%|

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
[firehol_level3](#firehol_level3)|110214|9627951|6933037|72.0%|37.8%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|6932480|75.5%|37.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|2272265|0.2%|12.3%|
[fullbogons](#fullbogons)|3770|670213096|151552|0.0%|0.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|130368|0.0%|0.7%|
[alienvault_reputation](#alienvault_reputation)|187115|187115|1373|0.7%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1037|0.3%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|94424|94424|1021|1.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|512|0.1%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|294|1.0%|0.0%|
[firehol_level2](#firehol_level2)|23442|35072|282|0.8%|0.0%|
[dragon_http](#dragon_http)|1044|273664|256|0.0%|0.0%|
[openbl_60d](#openbl_60d)|7012|7012|235|3.3%|0.0%|
[blocklist_de](#blocklist_de)|29619|29619|218|0.7%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3530|3530|134|3.7%|0.0%|
[openbl_30d](#openbl_30d)|2835|2835|119|4.1%|0.0%|
[et_compromised](#et_compromised)|1721|1721|101|5.8%|0.0%|
[shunlist](#shunlist)|1225|1225|92|7.5%|0.0%|
[nixspam](#nixspam)|39994|39994|88|0.2%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6808|6808|79|1.1%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1711|1711|74|4.3%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|2933|2933|58|1.9%|0.0%|
[openbl_7d](#openbl_7d)|679|679|50|7.3%|0.0%|
[php_commenters](#php_commenters)|430|430|29|6.7%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|29|2.2%|0.0%|
[sorbs_spam](#sorbs_spam)|59772|60402|20|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|59772|60402|20|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|59772|60402|20|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|10158|10158|19|0.1%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|17415|17415|18|0.1%|0.0%|
[zeus_badips](#zeus_badips)|202|202|15|7.4%|0.0%|
[zeus](#zeus)|230|230|15|6.5%|0.0%|
[voipbl](#voipbl)|10533|10945|14|0.1%|0.0%|
[openbl_1d](#openbl_1d)|158|158|14|8.8%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2383|2383|9|0.3%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|180|180|8|4.4%|0.0%|
[php_dictionary](#php_dictionary)|702|702|6|0.8%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|6|0.4%|0.0%|
[firehol_anonymous](#firehol_anonymous)|18837|82872|6|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|5|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4071|4071|5|0.1%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|15426|15426|5|0.0%|0.0%|
[php_spammers](#php_spammers)|700|700|4|0.5%|0.0%|
[malc0de](#malc0de)|313|313|4|1.2%|0.0%|
[firehol_proxies](#firehol_proxies)|12404|12670|3|0.0%|0.0%|
[et_tor](#et_tor)|6400|6400|3|0.0%|0.0%|
[dm_tor](#dm_tor)|6548|6548|3|0.0%|0.0%|
[bm_tor](#bm_tor)|6552|6552|3|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|2|0.3%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|79|79|2|2.5%|0.0%|
[sslbl](#sslbl)|372|372|1|0.2%|0.0%|
[php_harvesters](#php_harvesters)|378|378|1|0.2%|0.0%|
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
[firehol_level3](#firehol_level3)|110214|9627951|88|0.0%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|94424|94424|78|0.0%|0.0%|
[sorbs_spam](#sorbs_spam)|59772|60402|20|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|59772|60402|20|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|59772|60402|20|0.0%|0.0%|
[alienvault_reputation](#alienvault_reputation)|187115|187115|14|0.0%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|9|0.0%|0.0%|
[php_commenters](#php_commenters)|430|430|8|1.8%|0.0%|
[snort_ipfilter](#snort_ipfilter)|10158|10158|6|0.0%|0.0%|
[firehol_level2](#firehol_level2)|23442|35072|6|0.0%|0.0%|
[zeus_badips](#zeus_badips)|202|202|5|2.4%|0.0%|
[zeus](#zeus)|230|230|5|2.1%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|2933|2933|5|0.1%|0.0%|
[blocklist_de](#blocklist_de)|29619|29619|5|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|180|180|4|2.2%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6808|6808|2|0.0%|0.0%|
[nixspam](#nixspam)|39994|39994|2|0.0%|0.0%|
[php_harvesters](#php_harvesters)|378|378|1|0.2%|0.0%|
[openbl_60d](#openbl_60d)|7012|7012|1|0.0%|0.0%|
[openbl_30d](#openbl_30d)|2835|2835|1|0.0%|0.0%|
[malc0de](#malc0de)|313|313|1|0.3%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.0%|

## sslbl

[Abuse.ch SSL Blacklist](https://sslbl.abuse.ch/) bad SSL traffic related to malware or botnet activities - **excellent list**

Source is downloaded from [this link](https://sslbl.abuse.ch/blacklist/sslipblacklist.csv).

The last time downloaded was found to be dated: Wed Jun 10 20:15:07 UTC 2015.

The ipset `sslbl` has **372** entries, **372** unique IPs.

The following table shows the overlaps of `sslbl` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `sslbl`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `sslbl`.
- ` this % ` is the percentage **of this ipset (`sslbl`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level1](#firehol_level1)|5135|688894845|372|0.0%|100.0%|
[firehol_level3](#firehol_level3)|110214|9627951|93|0.0%|25.0%|
[alienvault_reputation](#alienvault_reputation)|187115|187115|66|0.0%|17.7%|
[shunlist](#shunlist)|1225|1225|61|4.9%|16.3%|
[feodo](#feodo)|105|105|38|36.1%|10.2%|
[et_block](#et_block)|1000|18344011|38|0.0%|10.2%|
[snort_ipfilter](#snort_ipfilter)|10158|10158|32|0.3%|8.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|28|0.0%|7.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|6|0.0%|1.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|3|0.0%|0.8%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|1|0.0%|0.2%|
[ri_web_proxies](#ri_web_proxies)|7581|7581|1|0.0%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.2%|
[firehol_proxies](#firehol_proxies)|12404|12670|1|0.0%|0.2%|
[firehol_anonymous](#firehol_anonymous)|18837|82872|1|0.0%|0.2%|
[dragon_http](#dragon_http)|1044|273664|1|0.0%|0.2%|

## stopforumspam_1d

[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers in the last 24 hours - **excellent list**

Source is downloaded from [this link](http://www.stopforumspam.com/downloads/listed_ip_1.zip).

The last time downloaded was found to be dated: Wed Jun 10 20:00:02 UTC 2015.

The ipset `stopforumspam_1d` has **6808** entries, **6808** unique IPs.

The following table shows the overlaps of `stopforumspam_1d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `stopforumspam_1d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `stopforumspam_1d`.
- ` this % ` is the percentage **of this ipset (`stopforumspam_1d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|23442|35072|6808|19.4%|100.0%|
[firehol_level3](#firehol_level3)|110214|9627951|5918|0.0%|86.9%|
[stopforumspam_30d](#stopforumspam_30d)|94424|94424|5903|6.2%|86.7%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|4111|14.0%|60.3%|
[blocklist_de](#blocklist_de)|29619|29619|1389|4.6%|20.4%|
[blocklist_de_bots](#blocklist_de_bots)|2933|2933|1311|44.6%|19.2%|
[firehol_anonymous](#firehol_anonymous)|18837|82872|1045|1.2%|15.3%|
[firehol_proxies](#firehol_proxies)|12404|12670|871|6.8%|12.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|486|0.0%|7.1%|
[ri_web_proxies](#ri_web_proxies)|7581|7581|446|5.8%|6.5%|
[snort_ipfilter](#snort_ipfilter)|10158|10158|422|4.1%|6.1%|
[et_tor](#et_tor)|6400|6400|381|5.9%|5.5%|
[dm_tor](#dm_tor)|6548|6548|379|5.7%|5.5%|
[bm_tor](#bm_tor)|6552|6552|379|5.7%|5.5%|
[proxyrss](#proxyrss)|1669|1669|361|21.6%|5.3%|
[xroxy](#xroxy)|2159|2159|231|10.6%|3.3%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|225|42.9%|3.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|196|0.0%|2.8%|
[proxz](#proxz)|1236|1236|175|14.1%|2.5%|
[php_commenters](#php_commenters)|430|430|172|40.0%|2.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|142|0.0%|2.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|180|180|114|63.3%|1.6%|
[ri_connect_proxies](#ri_connect_proxies)|2737|2737|107|3.9%|1.5%|
[blocklist_de_apache](#blocklist_de_apache)|15426|15426|84|0.5%|1.2%|
[firehol_level1](#firehol_level1)|5135|688894845|82|0.0%|1.2%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|79|0.0%|1.1%|
[et_block](#et_block)|1000|18344011|79|0.0%|1.1%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4071|4071|48|1.1%|0.7%|
[alienvault_reputation](#alienvault_reputation)|187115|187115|48|0.0%|0.7%|
[php_harvesters](#php_harvesters)|378|378|46|12.1%|0.6%|
[blocklist_de_mail](#blocklist_de_mail)|17415|17415|43|0.2%|0.6%|
[sorbs_spam](#sorbs_spam)|59772|60402|42|0.0%|0.6%|
[sorbs_recent_spam](#sorbs_recent_spam)|59772|60402|42|0.0%|0.6%|
[sorbs_new_spam](#sorbs_new_spam)|59772|60402|42|0.0%|0.6%|
[nixspam](#nixspam)|39994|39994|37|0.0%|0.5%|
[php_spammers](#php_spammers)|700|700|30|4.2%|0.4%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|28|0.0%|0.4%|
[php_dictionary](#php_dictionary)|702|702|24|3.4%|0.3%|
[openbl_60d](#openbl_60d)|7012|7012|20|0.2%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|11|0.0%|0.1%|
[dragon_http](#dragon_http)|1044|273664|6|0.0%|0.0%|
[sorbs_web](#sorbs_web)|411|412|5|1.2%|0.0%|
[voipbl](#voipbl)|10533|10945|4|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|4|0.6%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|4|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|2|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|2|0.1%|0.0%|
[zeus_badips](#zeus_badips)|202|202|1|0.4%|0.0%|
[zeus](#zeus)|230|230|1|0.4%|0.0%|
[shunlist](#shunlist)|1225|1225|1|0.0%|0.0%|
[openbl_30d](#openbl_30d)|2835|2835|1|0.0%|0.0%|
[fullbogons](#fullbogons)|3770|670213096|1|0.0%|0.0%|
[et_compromised](#et_compromised)|1721|1721|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1711|1711|1|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2383|2383|1|0.0%|0.0%|

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
[firehol_level3](#firehol_level3)|110214|9627951|94424|0.9%|100.0%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|29338|100.0%|31.0%|
[firehol_level2](#firehol_level2)|23442|35072|7315|20.8%|7.7%|
[firehol_anonymous](#firehol_anonymous)|18837|82872|6082|7.3%|6.4%|
[stopforumspam_1d](#stopforumspam_1d)|6808|6808|5903|86.7%|6.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|5840|0.0%|6.1%|
[firehol_proxies](#firehol_proxies)|12404|12670|5499|43.4%|5.8%|
[ri_web_proxies](#ri_web_proxies)|7581|7581|3605|47.5%|3.8%|
[blocklist_de](#blocklist_de)|29619|29619|2720|9.1%|2.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|2508|0.0%|2.6%|
[blocklist_de_bots](#blocklist_de_bots)|2933|2933|2323|79.2%|2.4%|
[ri_connect_proxies](#ri_connect_proxies)|2737|2737|1544|56.4%|1.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|1516|0.0%|1.6%|
[xroxy](#xroxy)|2159|2159|1276|59.1%|1.3%|
[firehol_level1](#firehol_level1)|5135|688894845|1102|0.0%|1.1%|
[et_block](#et_block)|1000|18344011|1025|0.0%|1.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|1021|0.0%|1.0%|
[snort_ipfilter](#snort_ipfilter)|10158|10158|816|8.0%|0.8%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|731|0.0%|0.7%|
[proxz](#proxz)|1236|1236|730|59.0%|0.7%|
[proxyrss](#proxyrss)|1669|1669|697|41.7%|0.7%|
[et_tor](#et_tor)|6400|6400|649|10.1%|0.6%|
[dm_tor](#dm_tor)|6548|6548|645|9.8%|0.6%|
[bm_tor](#bm_tor)|6552|6552|645|9.8%|0.6%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|342|65.2%|0.3%|
[php_commenters](#php_commenters)|430|430|318|73.9%|0.3%|
[sorbs_spam](#sorbs_spam)|59772|60402|280|0.4%|0.2%|
[sorbs_recent_spam](#sorbs_recent_spam)|59772|60402|280|0.4%|0.2%|
[sorbs_new_spam](#sorbs_new_spam)|59772|60402|280|0.4%|0.2%|
[blocklist_de_mail](#blocklist_de_mail)|17415|17415|257|1.4%|0.2%|
[blocklist_de_apache](#blocklist_de_apache)|15426|15426|237|1.5%|0.2%|
[nixspam](#nixspam)|39994|39994|222|0.5%|0.2%|
[alienvault_reputation](#alienvault_reputation)|187115|187115|205|0.1%|0.2%|
[php_spammers](#php_spammers)|700|700|144|20.5%|0.1%|
[blocklist_de_strongips](#blocklist_de_strongips)|180|180|137|76.1%|0.1%|
[php_dictionary](#php_dictionary)|702|702|133|18.9%|0.1%|
[dragon_http](#dragon_http)|1044|273664|115|0.0%|0.1%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4071|4071|94|2.3%|0.0%|
[php_harvesters](#php_harvesters)|378|378|83|21.9%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|78|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|49|0.0%|0.0%|
[openbl_60d](#openbl_60d)|7012|7012|48|0.6%|0.0%|
[voipbl](#voipbl)|10533|10945|35|0.3%|0.0%|
[sorbs_web](#sorbs_web)|411|412|31|7.5%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3530|3530|24|0.6%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|19|2.8%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|1333|1333|18|1.3%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|16|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2383|2383|13|0.5%|0.0%|
[et_compromised](#et_compromised)|1721|1721|12|0.6%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1711|1711|12|0.7%|0.0%|
[openbl_30d](#openbl_30d)|2835|2835|5|0.1%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|4|0.3%|0.0%|
[shunlist](#shunlist)|1225|1225|3|0.2%|0.0%|
[dshield](#dshield)|20|5120|3|0.0%|0.0%|
[zeus_badips](#zeus_badips)|202|202|2|0.9%|0.0%|
[zeus](#zeus)|230|230|2|0.8%|0.0%|
[openbl_7d](#openbl_7d)|679|679|2|0.2%|0.0%|
[openbl_1d](#openbl_1d)|158|158|2|1.2%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|2|0.1%|0.0%|
[ciarmy](#ciarmy)|457|457|2|0.4%|0.0%|
[virbl](#virbl)|30|30|1|3.3%|0.0%|
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
[firehol_level3](#firehol_level3)|110214|9627951|29338|0.3%|100.0%|
[firehol_level2](#firehol_level2)|23442|35072|5162|14.7%|17.5%|
[stopforumspam_1d](#stopforumspam_1d)|6808|6808|4111|60.3%|14.0%|
[firehol_anonymous](#firehol_anonymous)|18837|82872|2758|3.3%|9.4%|
[firehol_proxies](#firehol_proxies)|12404|12670|2427|19.1%|8.2%|
[blocklist_de](#blocklist_de)|29619|29619|2181|7.3%|7.4%|
[blocklist_de_bots](#blocklist_de_bots)|2933|2933|1959|66.7%|6.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|1913|0.0%|6.5%|
[ri_web_proxies](#ri_web_proxies)|7581|7581|1544|20.3%|5.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|790|0.0%|2.6%|
[snort_ipfilter](#snort_ipfilter)|10158|10158|658|6.4%|2.2%|
[xroxy](#xroxy)|2159|2159|626|28.9%|2.1%|
[ri_connect_proxies](#ri_connect_proxies)|2737|2737|590|21.5%|2.0%|
[et_tor](#et_tor)|6400|6400|530|8.2%|1.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|529|0.0%|1.8%|
[dm_tor](#dm_tor)|6548|6548|523|7.9%|1.7%|
[bm_tor](#bm_tor)|6552|6552|523|7.9%|1.7%|
[proxyrss](#proxyrss)|1669|1669|498|29.8%|1.6%|
[proxz](#proxz)|1236|1236|494|39.9%|1.6%|
[firehol_level1](#firehol_level1)|5135|688894845|303|0.0%|1.0%|
[et_block](#et_block)|1000|18344011|295|0.0%|1.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|294|0.0%|1.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|285|54.3%|0.9%|
[php_commenters](#php_commenters)|430|430|237|55.1%|0.8%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|167|0.0%|0.5%|
[sorbs_spam](#sorbs_spam)|59772|60402|151|0.2%|0.5%|
[sorbs_recent_spam](#sorbs_recent_spam)|59772|60402|151|0.2%|0.5%|
[sorbs_new_spam](#sorbs_new_spam)|59772|60402|151|0.2%|0.5%|
[blocklist_de_mail](#blocklist_de_mail)|17415|17415|146|0.8%|0.4%|
[blocklist_de_apache](#blocklist_de_apache)|15426|15426|144|0.9%|0.4%|
[nixspam](#nixspam)|39994|39994|123|0.3%|0.4%|
[blocklist_de_strongips](#blocklist_de_strongips)|180|180|117|65.0%|0.3%|
[alienvault_reputation](#alienvault_reputation)|187115|187115|103|0.0%|0.3%|
[php_dictionary](#php_dictionary)|702|702|88|12.5%|0.2%|
[php_spammers](#php_spammers)|700|700|87|12.4%|0.2%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4071|4071|68|1.6%|0.2%|
[php_harvesters](#php_harvesters)|378|378|60|15.8%|0.2%|
[dragon_http](#dragon_http)|1044|273664|37|0.0%|0.1%|
[openbl_60d](#openbl_60d)|7012|7012|27|0.3%|0.0%|
[sorbs_web](#sorbs_web)|411|412|22|5.3%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|18|0.0%|0.0%|
[voipbl](#voipbl)|10533|10945|14|0.1%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|11|1.6%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|9|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|1333|1333|7|0.5%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3530|3530|6|0.1%|0.0%|
[et_compromised](#et_compromised)|1721|1721|5|0.2%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|4|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1711|1711|4|0.2%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2383|2383|3|0.1%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|2|0.1%|0.0%|
[zeus_badips](#zeus_badips)|202|202|1|0.4%|0.0%|
[zeus](#zeus)|230|230|1|0.4%|0.0%|
[shunlist](#shunlist)|1225|1225|1|0.0%|0.0%|
[openbl_30d](#openbl_30d)|2835|2835|1|0.0%|0.0%|
[dshield](#dshield)|20|5120|1|0.0%|0.0%|
[ciarmy](#ciarmy)|457|457|1|0.2%|0.0%|

## virbl

[VirBL](http://virbl.bit.nl/) is a project of which the idea was born during the RIPE-48 meeting. The plan was to get reports of virusscanning mailservers, and put the IP-addresses that were reported to send viruses on a blacklist.

Source is downloaded from [this link](http://virbl.bit.nl/download/virbl.dnsbl.bit.nl.txt).

The last time downloaded was found to be dated: Wed Jun 10 19:42:04 UTC 2015.

The ipset `virbl` has **30** entries, **30** unique IPs.

The following table shows the overlaps of `virbl` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `virbl`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `virbl`.
- ` this % ` is the percentage **of this ipset (`virbl`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level3](#firehol_level3)|110214|9627951|30|0.0%|100.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|4|0.0%|13.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|2|0.0%|6.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|2|0.0%|6.6%|
[stopforumspam_30d](#stopforumspam_30d)|94424|94424|1|0.0%|3.3%|
[snort_ipfilter](#snort_ipfilter)|10158|10158|1|0.0%|3.3%|
[nixspam](#nixspam)|39994|39994|1|0.0%|3.3%|
[fullbogons](#fullbogons)|3770|670213096|1|0.0%|3.3%|
[firehol_level1](#firehol_level1)|5135|688894845|1|0.0%|3.3%|

## voipbl

[VoIPBL.org](http://www.voipbl.org/) a distributed VoIP blacklist that is aimed to protects against VoIP Fraud and minimizing abuse for network that have publicly accessible PBX's. Several algorithms, external sources and manual confirmation are used before they categorize something as an attack and determine the threat level.

Source is downloaded from [this link](http://www.voipbl.org/update/).

The last time downloaded was found to be dated: Wed Jun 10 18:44:51 UTC 2015.

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
[alienvault_reputation](#alienvault_reputation)|187115|187115|193|0.1%|1.7%|
[firehol_anonymous](#firehol_anonymous)|18837|82872|79|0.0%|0.7%|
[firehol_level3](#firehol_level3)|110214|9627951|57|0.0%|0.5%|
[stopforumspam_30d](#stopforumspam_30d)|94424|94424|35|0.0%|0.3%|
[firehol_level2](#firehol_level2)|23442|35072|35|0.0%|0.3%|
[blocklist_de](#blocklist_de)|29619|29619|31|0.1%|0.2%|
[blocklist_de_sip](#blocklist_de_sip)|79|79|27|34.1%|0.2%|
[dragon_http](#dragon_http)|1044|273664|25|0.0%|0.2%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|14|0.0%|0.1%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|14|0.0%|0.1%|
[et_block](#et_block)|1000|18344011|14|0.0%|0.1%|
[shunlist](#shunlist)|1225|1225|12|0.9%|0.1%|
[openbl_60d](#openbl_60d)|7012|7012|8|0.1%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6808|6808|4|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|4|0.0%|0.0%|
[openbl_30d](#openbl_30d)|2835|2835|3|0.1%|0.0%|
[et_tor](#et_tor)|6400|6400|3|0.0%|0.0%|
[et_compromised](#et_compromised)|1721|1721|3|0.1%|0.0%|
[dm_tor](#dm_tor)|6548|6548|3|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1711|1711|3|0.1%|0.0%|
[bm_tor](#bm_tor)|6552|6552|3|0.0%|0.0%|
[sorbs_spam](#sorbs_spam)|59772|60402|2|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|59772|60402|2|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|59772|60402|2|0.0%|0.0%|
[nixspam](#nixspam)|39994|39994|2|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|2|0.3%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|2|0.0%|0.0%|
[firehol_proxies](#firehol_proxies)|12404|12670|2|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3530|3530|2|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|15426|15426|2|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|10158|10158|1|0.0%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.0%|
[ciarmy](#ciarmy)|457|457|1|0.2%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4071|4071|1|0.0%|0.0%|

## xroxy

[xroxy.com](http://www.xroxy.com) open proxies (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.xroxy.com/proxyrss.xml).

The last time downloaded was found to be dated: Wed Jun 10 20:33:01 UTC 2015.

The ipset `xroxy` has **2159** entries, **2159** unique IPs.

The following table shows the overlaps of `xroxy` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `xroxy`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `xroxy`.
- ` this % ` is the percentage **of this ipset (`xroxy`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_proxies](#firehol_proxies)|12404|12670|2159|17.0%|100.0%|
[firehol_anonymous](#firehol_anonymous)|18837|82872|2159|2.6%|100.0%|
[firehol_level3](#firehol_level3)|110214|9627951|1292|0.0%|59.8%|
[stopforumspam_30d](#stopforumspam_30d)|94424|94424|1276|1.3%|59.1%|
[ri_web_proxies](#ri_web_proxies)|7581|7581|951|12.5%|44.0%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|626|2.1%|28.9%|
[proxz](#proxz)|1236|1236|442|35.7%|20.4%|
[ri_connect_proxies](#ri_connect_proxies)|2737|2737|391|14.2%|18.1%|
[proxyrss](#proxyrss)|1669|1669|359|21.5%|16.6%|
[firehol_level2](#firehol_level2)|23442|35072|330|0.9%|15.2%|
[stopforumspam_1d](#stopforumspam_1d)|6808|6808|231|3.3%|10.6%|
[blocklist_de](#blocklist_de)|29619|29619|203|0.6%|9.4%|
[blocklist_de_bots](#blocklist_de_bots)|2933|2933|150|5.1%|6.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|110|0.0%|5.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|104|0.0%|4.8%|
[sorbs_spam](#sorbs_spam)|59772|60402|73|0.1%|3.3%|
[sorbs_recent_spam](#sorbs_recent_spam)|59772|60402|73|0.1%|3.3%|
[sorbs_new_spam](#sorbs_new_spam)|59772|60402|73|0.1%|3.3%|
[nixspam](#nixspam)|39994|39994|63|0.1%|2.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|58|0.0%|2.6%|
[blocklist_de_mail](#blocklist_de_mail)|17415|17415|53|0.3%|2.4%|
[snort_ipfilter](#snort_ipfilter)|10158|10158|41|0.4%|1.8%|
[php_dictionary](#php_dictionary)|702|702|39|5.5%|1.8%|
[php_spammers](#php_spammers)|700|700|32|4.5%|1.4%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|13|1.9%|0.6%|
[php_commenters](#php_commenters)|430|430|10|2.3%|0.4%|
[sorbs_web](#sorbs_web)|411|412|9|2.1%|0.4%|
[dragon_http](#dragon_http)|1044|273664|8|0.0%|0.3%|
[blocklist_de_strongips](#blocklist_de_strongips)|180|180|5|2.7%|0.2%|
[alienvault_reputation](#alienvault_reputation)|187115|187115|5|0.0%|0.2%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|3|0.5%|0.1%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|3|0.0%|0.1%|
[php_harvesters](#php_harvesters)|378|378|2|0.5%|0.0%|
[dm_tor](#dm_tor)|6548|6548|2|0.0%|0.0%|
[bm_tor](#bm_tor)|6552|6552|2|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.0%|
[et_tor](#et_tor)|6400|6400|1|0.0%|0.0%|
[et_compromised](#et_compromised)|1721|1721|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1711|1711|1|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2383|2383|1|0.0%|0.0%|

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
[firehol_level3](#firehol_level3)|110214|9627951|203|0.0%|88.2%|
[zeus_badips](#zeus_badips)|202|202|202|100.0%|87.8%|
[snort_ipfilter](#snort_ipfilter)|10158|10158|200|1.9%|86.9%|
[alienvault_reputation](#alienvault_reputation)|187115|187115|61|0.0%|26.5%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|15|0.0%|6.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|14|0.0%|6.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|10|0.0%|4.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|9|0.0%|3.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|7|0.0%|3.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|5|0.0%|2.1%|
[firehol_level2](#firehol_level2)|23442|35072|3|0.0%|1.3%|
[dragon_http](#dragon_http)|1044|273664|3|0.0%|1.3%|
[stopforumspam_30d](#stopforumspam_30d)|94424|94424|2|0.0%|0.8%|
[openbl_60d](#openbl_60d)|7012|7012|2|0.0%|0.8%|
[openbl_30d](#openbl_30d)|2835|2835|2|0.0%|0.8%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|1|0.0%|0.4%|
[stopforumspam_1d](#stopforumspam_1d)|6808|6808|1|0.0%|0.4%|
[php_commenters](#php_commenters)|430|430|1|0.2%|0.4%|
[openbl_7d](#openbl_7d)|679|679|1|0.1%|0.4%|
[openbl_1d](#openbl_1d)|158|158|1|0.6%|0.4%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|1|0.0%|0.4%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.4%|
[blocklist_de_mail](#blocklist_de_mail)|17415|17415|1|0.0%|0.4%|
[blocklist_de](#blocklist_de)|29619|29619|1|0.0%|0.4%|

## zeus_badips

[Abuse.ch Zeus tracker](https://zeustracker.abuse.ch) badips includes IPv4 addresses that are used by the ZeuS trojan. It is the recommened blocklist if you want to block only ZeuS IPs. It excludes IP addresses that ZeuS Tracker believes to be hijacked (level 2) or belong to a free web hosting provider (level 3). Hence the false postive rate should be much lower compared to the standard ZeuS IP blocklist. **excellent list**

Source is downloaded from [this link](https://zeustracker.abuse.ch/blocklist.php?download=badips).

The last time downloaded was found to be dated: Wed Jun 10 20:27:04 UTC 2015.

The ipset `zeus_badips` has **202** entries, **202** unique IPs.

The following table shows the overlaps of `zeus_badips` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `zeus_badips`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `zeus_badips`.
- ` this % ` is the percentage **of this ipset (`zeus_badips`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[zeus](#zeus)|230|230|202|87.8%|100.0%|
[firehol_level1](#firehol_level1)|5135|688894845|202|0.0%|100.0%|
[et_block](#et_block)|1000|18344011|202|0.0%|100.0%|
[firehol_level3](#firehol_level3)|110214|9627951|180|0.0%|89.1%|
[snort_ipfilter](#snort_ipfilter)|10158|10158|178|1.7%|88.1%|
[alienvault_reputation](#alienvault_reputation)|187115|187115|37|0.0%|18.3%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|15|0.0%|7.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|10|0.0%|4.9%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|10|0.0%|4.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|8|0.0%|3.9%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|5|0.0%|2.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|4|0.0%|1.9%|
[firehol_level2](#firehol_level2)|23442|35072|3|0.0%|1.4%|
[dragon_http](#dragon_http)|1044|273664|3|0.0%|1.4%|
[stopforumspam_30d](#stopforumspam_30d)|94424|94424|2|0.0%|0.9%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|1|0.0%|0.4%|
[stopforumspam_1d](#stopforumspam_1d)|6808|6808|1|0.0%|0.4%|
[php_commenters](#php_commenters)|430|430|1|0.2%|0.4%|
[openbl_7d](#openbl_7d)|679|679|1|0.1%|0.4%|
[openbl_60d](#openbl_60d)|7012|7012|1|0.0%|0.4%|
[openbl_30d](#openbl_30d)|2835|2835|1|0.0%|0.4%|
[openbl_1d](#openbl_1d)|158|158|1|0.6%|0.4%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.4%|
[blocklist_de_mail](#blocklist_de_mail)|17415|17415|1|0.0%|0.4%|
[blocklist_de](#blocklist_de)|29619|29619|1|0.0%|0.4%|
