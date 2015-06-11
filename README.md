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

The following list was automatically generated on Thu Jun 11 07:19:40 UTC 2015.

The update frequency is the maximum allowed by internal configuration. A list will never be downloaded sooner than the update frequency stated. A list may also not be downloaded, after this frequency expired, if it has not been modified on the server (as reported by HTTP `IF_MODIFIED_SINCE` method).

name|info|type|entries|update|
:--:|:--:|:--:|:-----:|:----:|
[alienvault_reputation](#alienvault_reputation)|[AlienVault.com](https://www.alienvault.com/) IP reputation database (this list seems to include port scanning hosts and to be updated regularly, but we found no information about its retention policy)|ipv4 hash:ip|184538 unique IPs|updated every 6 hours  from [this link](https://reputation.alienvault.com/reputation.generic)
[blocklist_de](#blocklist_de)|[Blocklist.de](https://www.blocklist.de/) IPs that have been detected by fail2ban in the last 48 hours - **excellent list**|ipv4 hash:ip|27197 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/all.txt)
[blocklist_de_apache](#blocklist_de_apache)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service Apache, Apache-DDOS, RFI-Attacks.|ipv4 hash:ip|14166 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/apache.txt)
[blocklist_de_bots](#blocklist_de_bots)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the RFI-Attacks, REG-Bots, IRC-Bots or BadBots (BadBots = he has posted a Spam-Comment on a open Forum or Wiki).|ipv4 hash:ip|2888 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/bots.txt)
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|[Blocklist.de](https://www.blocklist.de/) All IPs which attacks Joomlas, Wordpress and other Web-Logins with Brute-Force Logins.|ipv4 hash:ip|2798 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/bruteforcelogin.txt)
[blocklist_de_ftp](#blocklist_de_ftp)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours for attacks on the Service FTP.|ipv4 hash:ip|1425 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/ftp.txt)
[blocklist_de_imap](#blocklist_de_imap)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours for attacks on the Service imap, sasl, pop3, etc.|ipv4 hash:ip|1997 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/imap.txt)
[blocklist_de_mail](#blocklist_de_mail)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service Mail, Postfix.|ipv4 hash:ip|16274 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/mail.txt)
[blocklist_de_sip](#blocklist_de_sip)|[Blocklist.de](https://www.blocklist.de/) All IP addresses that tried to login in a SIP, VOIP or Asterisk Server and are included in the IPs list from [infiltrated.net](www.infiltrated.net)|ipv4 hash:ip|80 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/sip.txt)
[blocklist_de_ssh](#blocklist_de_ssh)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service SSH.|ipv4 hash:ip|3474 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/ssh.txt)
[blocklist_de_strongips](#blocklist_de_strongips)|[Blocklist.de](https://www.blocklist.de/) All IPs which are older then 2 month and have more then 5.000 attacks.|ipv4 hash:ip|183 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/strongips.txt)
[bm_tor](#bm_tor)|[torstatus.blutmagie.de](https://torstatus.blutmagie.de) list of all TOR network servers|ipv4 hash:ip|6402 unique IPs|updated every 30 mins  from [this link](https://torstatus.blutmagie.de/ip_list_all.php/Tor_ip_list_ALL.csv)
[bogons](#bogons)|[Team-Cymru.org](http://www.team-cymru.org) private and reserved addresses defined by RFC 1918, RFC 5735, and RFC 6598 and netblocks that have not been allocated to a regional internet registry - **excellent list - use it only your internet interface**|ipv4 hash:net|13 subnets, 592708608 unique IPs|updated every 1 day  from [this link](http://www.team-cymru.org/Services/Bogons/bogon-bn-agg.txt)
[bruteforceblocker](#bruteforceblocker)|[danger.rulez.sk](http://danger.rulez.sk/) IPs detected by [bruteforceblocker](http://danger.rulez.sk/index.php/bruteforceblocker/) (fail2ban alternative for SSH on OpenBSD). This is an automatically generated list from users reporting failed authentication attempts. An IP seems to be included if 3 or more users report it. Its retention pocily seems 30 days.|ipv4 hash:ip|1705 unique IPs|updated every 3 hours  from [this link](http://danger.rulez.sk/projects/bruteforceblocker/blist.php)
[ciarmy](#ciarmy)|[CIArmy.com](http://ciarmy.com/) IPs with poor Rogue Packet score that have not yet been identified as malicious by the community|ipv4 hash:ip|442 unique IPs|updated every 3 hours  from [this link](http://cinsscore.com/list/ci-badguys.txt)
[cleanmx_viruses](#cleanmx_viruses)|[Clean-MX.de](http://support.clean-mx.de/clean-mx/viruses.php) IPs with viruses|ipv4 hash:ip|65 unique IPs|updated every 12 hours  from [this link](http://support.clean-mx.de/clean-mx/xmlviruses.php?sort=id%20desc&response=alive)
[dm_tor](#dm_tor)|[dan.me.uk](https://www.dan.me.uk) dynamic list of TOR nodes|ipv4 hash:ip|6424 unique IPs|updated every 30 mins  from [this link](https://www.dan.me.uk/torlist/)
[dragon_http](#dragon_http)|[Dragon Search Group](http://www.dragonresearchgroup.org/) IPs that have been seen sending HTTP requests to Dragon Research Pods in the last 7 days. This report lists hosts that are highly suspicious and are likely conducting malicious HTTP attacks. LEGITIMATE SEARCH ENGINE BOTS MAY BE IN THIS LIST. This report is informational.  It is not a blacklist, but some operators may choose to use it to help protect their networks and hosts in the forms of automated reporting and mitigation services.|ipv4 hash:net|1044 subnets, 273664 unique IPs|updated every 1 day  from [this link](http://www.dragonresearchgroup.org/insight/http-report.txt)
[dshield](#dshield)|[DShield.org](https://dshield.org/) top 20 attacking class C (/24) subnets over the last three days - **excellent list**|ipv4 hash:net|20 subnets, 5120 unique IPs|updated every 4 hours  from [this link](http://feeds.dshield.org/block.txt)
[et_block](#et_block)|[EmergingThreats.net](http://www.emergingthreats.net/) default blacklist (at the time of writing includes spamhaus DROP, dshield and abuse.ch trackers, which are available separately too - prefer to use the direct ipsets instead of this, they seem to lag a bit in updates)|ipv4 hash:net|1000 subnets, 18344011 unique IPs|updated every 12 hours  from [this link](http://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt)
[et_botcc](#et_botcc)|[EmergingThreats.net Command and Control IPs](http://doc.emergingthreats.net/bin/view/Main/BotCC) These IPs are updates every 24 hours and should be considered VERY highly reliable indications that a host is communicating with a known and active Bot or Malware command and control server - (although they say this includes abuse.ch trackers, it does not - most probably it is the shadowserver.org C&C list)|ipv4 hash:ip|506 unique IPs|updated every 12 hours  from [this link](http://rules.emergingthreats.net/fwrules/emerging-PIX-CC.rules)
[et_compromised](#et_compromised)|[EmergingThreats.net compromised hosts](http://doc.emergingthreats.net/bin/view/Main/CompromisedHost) - (this seems to be based on bruteforceblocker)|ipv4 hash:ip|1721 unique IPs|updated every 12 hours  from [this link](http://rules.emergingthreats.net/blockrules/compromised-ips.txt)
et_dshield|[EmergingThreats.net](http://www.emergingthreats.net/) dshield blocklist|ipv4 hash:net|disabled|updated every 12 hours  from [this link](http://rules.emergingthreats.net/fwrules/emerging-PIX-DSHIELD.rules)
et_spamhaus|[EmergingThreats.net](http://www.emergingthreats.net/) spamhaus blocklist|ipv4 hash:net|disabled|updated every 12 hours  from [this link](http://rules.emergingthreats.net/fwrules/emerging-PIX-DROP.rules)
[et_tor](#et_tor)|[EmergingThreats.net](http://www.emergingthreats.net/) [list](http://doc.emergingthreats.net/bin/view/Main/TorRules) of TOR network IPs|ipv4 hash:ip|6400 unique IPs|updated every 12 hours  from [this link](http://rules.emergingthreats.net/blockrules/emerging-tor.rules)
[feodo](#feodo)|[Abuse.ch Feodo tracker](https://feodotracker.abuse.ch) trojan includes IPs which are being used by Feodo (also known as Cridex or Bugat) which commits ebanking fraud - **excellent list**|ipv4 hash:ip|105 unique IPs|updated every 30 mins  from [this link](https://feodotracker.abuse.ch/blocklist/?download=ipblocklist)
[firehol_anonymous](#firehol_anonymous)|**FireHOL Anonymous** - Known anonymizing IPs. (includes: firehol_proxies anonymous bm_tor dm_tor tor_exits)|ipv4 hash:net|18924 subnets, 82965 unique IPs|
[firehol_level1](#firehol_level1)|**FireHOL Level 1** - Maximum protection without false positives. (includes: fullbogons dshield feodo palevo sslbl zeus spamhaus_drop spamhaus_edrop)|ipv4 hash:net|5133 subnets, 688894588 unique IPs|
[firehol_level2](#firehol_level2)|**FireHOL Level 2** - Maximum protection from attacks took place in the last 48 hours. (includes: openbl_1d blocklist_de stopforumspam_1d)|ipv4 hash:net|20916 subnets, 32554 unique IPs|
[firehol_level3](#firehol_level3)|**FireHOL Level 3** - All the bad IPs in last 30 days. (includes: openbl_30d stopforumspam_30d virbl malc0de shunlist malwaredomainlist bruteforceblocker ciarmy cleanmx_viruses snort_ipfilter ib_bluetack_spyware ib_bluetack_hijacked ib_bluetack_webexploit php_commenters php_dictionary php_harvesters php_spammers iw_wormlist)|ipv4 hash:net|109949 subnets, 9627745 unique IPs|
[firehol_proxies](#firehol_proxies)|**FireHOL Proxies** - Known open proxies in the last 30 days. (includes: ib_bluetack_proxies maxmind_proxy_fraud proxyrss proxz ri_connect_proxies ri_web_proxies xroxy)|ipv4 hash:net|12475 subnets, 12745 unique IPs|
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
[iw_spamlist](#iw_spamlist)|[ImproWare Antispam](http://antispam.imp.ch/) IPs sending spam, in the last 3 days|ipv4 hash:ip|3758 unique IPs|updated every 1 hour  from [this link](http://antispam.imp.ch/spamlist)
[iw_wormlist](#iw_wormlist)|[ImproWare Antispam](http://antispam.imp.ch/) IPs sending emails with viruses or worms, in the last 3 days|ipv4 hash:ip|33 unique IPs|updated every 1 hour  from [this link](http://antispam.imp.ch/wormlist)
lashback_ubl|[The LashBack UBL](http://blacklist.lashback.com/) The Unsubscribe Blacklist (UBL) is a real-time blacklist of IP addresses which are sending email to names harvested from suppression files (this is a big list, more than 500.000 IPs)|ipv4 hash:ip|disabled|updated every 1 day  from [this link](http://www.unsubscore.com/blacklist.txt)
[malc0de](#malc0de)|[Malc0de.com](http://malc0de.com) malicious IPs of the last 30 days|ipv4 hash:ip|313 unique IPs|updated every 1 day  from [this link](http://malc0de.com/bl/IP_Blacklist.txt)
[malwaredomainlist](#malwaredomainlist)|[malwaredomainlist.com](http://www.malwaredomainlist.com) list of malware active ip addresses|ipv4 hash:ip|1288 unique IPs|updated every 12 hours  from [this link](http://www.malwaredomainlist.com/hostslist/ip.txt)
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|[MaxMind.com](https://www.maxmind.com/en/anonymous-proxy-fraudulent-ip-address-list) list of anonymous proxy fraudelent IP addresses.|ipv4 hash:ip|524 unique IPs|updated every 4 hours  from [this link](https://www.maxmind.com/en/anonymous-proxy-fraudulent-ip-address-list)
[nixspam](#nixspam)|[NiX Spam](http://www.heise.de/ix/NiX-Spam-DNSBL-and-blacklist-for-download-499637.html) IP addresses that sent spam in the last hour - automatically generated entries without distinguishing open proxies from relays, dialup gateways, and so on. All IPs are removed after 12 hours if there is no spam from there.|ipv4 hash:ip|16664 unique IPs|updated every 15 mins  from [this link](http://www.dnsbl.manitu.net/download/nixspam-ip.dump.gz)
[nt_malware_http](#nt_malware_http)|[No Think](http://www.nothink.org/) Malware HTTP|ipv4 hash:ip|69 unique IPs|updated every 1 hour  from [this link](http://www.nothink.org/blacklist/blacklist_malware_http.txt)
[nt_malware_irc](#nt_malware_irc)|[No Think](http://www.nothink.org/) Malware IRC|ipv4 hash:ip|43 unique IPs|updated every 1 hour  from [this link](http://www.nothink.org/blacklist/blacklist_malware_irc.txt)
[nt_ssh_7d](#nt_ssh_7d)|[No Think](http://www.nothink.org/) Last 7 days SSH attacks|ipv4 hash:ip|0 unique IPs|updated every 1 hour  from [this link](http://www.nothink.org/blacklist/blacklist_ssh_week.txt)
openbl|[OpenBL.org](http://www.openbl.org/) default blacklist (currently it is the same with 90 days). OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications - **excellent list**|ipv4 hash:ip|disabled|updated every 4 hours  from [this link](http://www.openbl.org/lists/base.txt)
openbl_180d|[OpenBL.org](http://www.openbl.org/) last 180 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|disabled|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_180days.txt)
[openbl_1d](#openbl_1d)|[OpenBL.org](http://www.openbl.org/) last 24 hours IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|144 unique IPs|updated every 1 hour  from [this link](http://www.openbl.org/lists/base_1days.txt)
[openbl_30d](#openbl_30d)|[OpenBL.org](http://www.openbl.org/) last 30 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|2829 unique IPs|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_30days.txt)
openbl_360d|[OpenBL.org](http://www.openbl.org/) last 360 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|disabled|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_360days.txt)
[openbl_60d](#openbl_60d)|[OpenBL.org](http://www.openbl.org/) last 60 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|6997 unique IPs|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_60days.txt)
[openbl_7d](#openbl_7d)|[OpenBL.org](http://www.openbl.org/) last 7 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|669 unique IPs|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_7days.txt)
openbl_90d|[OpenBL.org](http://www.openbl.org/) last 90 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|disabled|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_90days.txt)
openbl_all|[OpenBL.org](http://www.openbl.org/) last all IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|disabled|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_all.txt)
[palevo](#palevo)|[Abuse.ch Palevo tracker](https://palevotracker.abuse.ch) worm includes IPs which are being used as botnet C&C for the Palevo crimeware - **excellent list**|ipv4 hash:ip|13 unique IPs|updated every 30 mins  from [this link](https://palevotracker.abuse.ch/blocklists.php?download=ipblocklist)
php_bad|[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) bad web hosts (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|disabled|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=b&rss=1)
[php_commenters](#php_commenters)|[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) comment spammers (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|430 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=c&rss=1)
[php_dictionary](#php_dictionary)|[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) directory attackers (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|702 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=d&rss=1)
[php_harvesters](#php_harvesters)|[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) harvesters (IPs that surf the internet looking for email addresses) (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|392 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=h&rss=1)
[php_spammers](#php_spammers)|[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) spam servers (IPs used by spammers to send messages) (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|700 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=s&rss=1)
[proxyrss](#proxyrss)|[proxyrss.com](http://www.proxyrss.com) open proxies syndicated from multiple sources.|ipv4 hash:ip|1673 unique IPs|updated every 4 hours  from [this link](http://www.proxyrss.com/proxylists/all.gz)
[proxz](#proxz)|[proxz.com](http://www.proxz.com) open proxies (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|1265 unique IPs|updated every 1 hour  from [this link](http://www.proxz.com/proxylists.xml)
[ri_connect_proxies](#ri_connect_proxies)|[rosinstrument.com](http://www.rosinstrument.com) open CONNECT proxies (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|2784 unique IPs|updated every 1 hour  from [this link](http://tools.rosinstrument.com/proxy/plab100.xml)
[ri_web_proxies](#ri_web_proxies)|[rosinstrument.com](http://www.rosinstrument.com) open HTTP proxies (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|7712 unique IPs|updated every 1 hour  from [this link](http://tools.rosinstrument.com/proxy/l100.xml)
[shunlist](#shunlist)|[AutoShun.org](http://autoshun.org/) IPs identified as hostile by correlating logs from distributed snort installations running the autoshun plugin|ipv4 hash:ip|1243 unique IPs|updated every 4 hours  from [this link](http://www.autoshun.org/files/shunlist.csv)
[snort_ipfilter](#snort_ipfilter)|[labs.snort.org](https://labs.snort.org/) supplied IP blacklist (this list seems to be updated frequently, but we found no information about it)|ipv4 hash:ip|9945 unique IPs|updated every 12 hours  from [this link](http://labs.snort.org/feeds/ip-filter.blf)
[sorbs_dul](#sorbs_dul)|[Sorbs.net](https://www.sorbs.net/) DUL, Dynamic User IPs extracted from deltas.|ipv4 hash:net|9 subnets, 4608 unique IPs|updated every 1 min  from [this link]()
[sorbs_http](#sorbs_http)|[Sorbs.net](https://www.sorbs.net/) HTTP proxies, extracted from deltas.|ipv4 hash:net|5 subnets, 5 unique IPs|
[sorbs_misc](#sorbs_misc)|[Sorbs.net](https://www.sorbs.net/) MISC proxies, extracted from deltas.|ipv4 hash:net|5 subnets, 5 unique IPs|
[sorbs_new_spam](#sorbs_new_spam)|[Sorbs.net](https://www.sorbs.net/) NEW Spam senders, extracted from deltas.|ipv4 hash:net|62018 subnets, 62766 unique IPs|
[sorbs_recent_spam](#sorbs_recent_spam)|[Sorbs.net](https://www.sorbs.net/) RECENT Spam senders, extracted from deltas.|ipv4 hash:net|62018 subnets, 62766 unique IPs|
[sorbs_smtp](#sorbs_smtp)|[Sorbs.net](https://www.sorbs.net/) SMTP Open Relays, extracted from deltas.|ipv4 hash:net|4 subnets, 4 unique IPs|
[sorbs_socks](#sorbs_socks)|[Sorbs.net](https://www.sorbs.net/) SOCKS proxies, extracted from deltas.|ipv4 hash:net|5 subnets, 5 unique IPs|
[sorbs_spam](#sorbs_spam)|[Sorbs.net](https://www.sorbs.net/) Spam senders, extracted from deltas.|ipv4 hash:net|62018 subnets, 62766 unique IPs|
[sorbs_web](#sorbs_web)|[Sorbs.net](https://www.sorbs.net/) WEB exploits, extracted from deltas.|ipv4 hash:net|482 subnets, 483 unique IPs|
[spamhaus_drop](#spamhaus_drop)|[Spamhaus.org](http://www.spamhaus.org) DROP list (according to their site this list should be dropped at tier-1 ISPs globaly) - **excellent list**|ipv4 hash:net|653 subnets, 18340608 unique IPs|updated every 12 hours  from [this link](http://www.spamhaus.org/drop/drop.txt)
[spamhaus_edrop](#spamhaus_edrop)|[Spamhaus.org](http://www.spamhaus.org) EDROP (extended matches that should be used with DROP) - **excellent list**|ipv4 hash:net|56 subnets, 487424 unique IPs|updated every 12 hours  from [this link](http://www.spamhaus.org/drop/edrop.txt)
[sslbl](#sslbl)|[Abuse.ch SSL Blacklist](https://sslbl.abuse.ch/) bad SSL traffic related to malware or botnet activities - **excellent list**|ipv4 hash:ip|371 unique IPs|updated every 30 mins  from [this link](https://sslbl.abuse.ch/blacklist/sslipblacklist.csv)
stopforumspam_180d|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 180 days)|ipv4 hash:ip|disabled|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/listed_ip_180.zip)
[stopforumspam_1d](#stopforumspam_1d)|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers in the last 24 hours - **excellent list**|ipv4 hash:ip|6759 unique IPs|updated every 1 hour  from [this link](http://www.stopforumspam.com/downloads/listed_ip_1.zip)
[stopforumspam_30d](#stopforumspam_30d)|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 30 days)|ipv4 hash:ip|94424 unique IPs|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/listed_ip_30.zip)
stopforumspam_365d|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 365 days)|ipv4 hash:ip|disabled|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/listed_ip_365.zip)
[stopforumspam_7d](#stopforumspam_7d)|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 7 days)|ipv4 hash:ip|29185 unique IPs|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/listed_ip_7.zip)
stopforumspam_90d|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 90 days)|ipv4 hash:ip|disabled|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/listed_ip_90.zip)
stopforumspam_ever|[StopForumSpam.com](http://www.stopforumspam.com) all IPs used by forum spammers, **ever** (normally you don't want to use this ipset, use the hourly one which includes last 24 hours IPs or the 7 days one)|ipv4 hash:ip|disabled|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/bannedips.zip)
[tor_exits](#tor_exits)|[TorProject.org](https://www.torproject.org) list of all current TOR exit points (TorDNSEL)|ipv4 hash:ip|1116 unique IPs|updated every 30 mins  from [this link](https://check.torproject.org/exit-addresses)
[virbl](#virbl)|[VirBL](http://virbl.bit.nl/) is a project of which the idea was born during the RIPE-48 meeting. The plan was to get reports of virusscanning mailservers, and put the IP-addresses that were reported to send viruses on a blacklist.|ipv4 hash:ip|28 unique IPs|updated every 1 hour  from [this link](http://virbl.bit.nl/download/virbl.dnsbl.bit.nl.txt)
[voipbl](#voipbl)|[VoIPBL.org](http://www.voipbl.org/) a distributed VoIP blacklist that is aimed to protects against VoIP Fraud and minimizing abuse for network that have publicly accessible PBX's. Several algorithms, external sources and manual confirmation are used before they categorize something as an attack and determine the threat level.|ipv4 hash:net|10533 subnets, 10945 unique IPs|updated every 4 hours  from [this link](http://www.voipbl.org/update/)
[xroxy](#xroxy)|[xroxy.com](http://www.xroxy.com) open proxies (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|2163 unique IPs|updated every 1 hour  from [this link](http://www.xroxy.com/proxyrss.xml)
[zeus](#zeus)|[Abuse.ch Zeus tracker](https://zeustracker.abuse.ch) standard, contains the same data as the ZeuS IP blocklist (zeus_badips) but with the slight difference that it doesn't exclude hijacked websites (level 2) and free web hosting providers (level 3). This means that this blocklist contains all IPv4 addresses associated with ZeuS C&Cs which are currently being tracked by ZeuS Tracker. Hence this blocklist will likely cause some false positives. - **excellent list**|ipv4 hash:ip|230 unique IPs|updated every 30 mins  from [this link](https://zeustracker.abuse.ch/blocklist.php?download=ipblocklist)
[zeus_badips](#zeus_badips)|[Abuse.ch Zeus tracker](https://zeustracker.abuse.ch) badips includes IPv4 addresses that are used by the ZeuS trojan. It is the recommened blocklist if you want to block only ZeuS IPs. It excludes IP addresses that ZeuS Tracker believes to be hijacked (level 2) or belong to a free web hosting provider (level 3). Hence the false postive rate should be much lower compared to the standard ZeuS IP blocklist. **excellent list**|ipv4 hash:ip|202 unique IPs|updated every 30 mins  from [this link](https://zeustracker.abuse.ch/blocklist.php?download=badips)

# Comparison of ipsets

Below we compare each ipset against all other.


## alienvault_reputation

[AlienVault.com](https://www.alienvault.com/) IP reputation database (this list seems to include port scanning hosts and to be updated regularly, but we found no information about its retention policy)

Source is downloaded from [this link](https://reputation.alienvault.com/reputation.generic).

The last time downloaded was found to be dated: Thu Jun 11 04:00:30 UTC 2015.

The ipset `alienvault_reputation` has **184538** entries, **184538** unique IPs.

The following table shows the overlaps of `alienvault_reputation` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `alienvault_reputation`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `alienvault_reputation`.
- ` this % ` is the percentage **of this ipset (`alienvault_reputation`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|14081|0.0%|7.6%|
[openbl_60d](#openbl_60d)|6997|6997|6978|99.7%|3.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|6489|0.0%|3.5%|
[dragon_http](#dragon_http)|1044|273664|5640|2.0%|3.0%|
[firehol_level3](#firehol_level3)|109949|9627745|4871|0.0%|2.6%|
[et_block](#et_block)|1000|18344011|4764|0.0%|2.5%|
[firehol_level1](#firehol_level1)|5133|688894588|4584|0.0%|2.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|4448|0.0%|2.4%|
[dshield](#dshield)|20|5120|3328|65.0%|1.8%|
[openbl_30d](#openbl_30d)|2829|2829|2815|99.5%|1.5%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|1372|0.0%|0.7%|
[firehol_level2](#firehol_level2)|20916|32554|1362|4.1%|0.7%|
[blocklist_de](#blocklist_de)|27197|27197|1309|4.8%|0.7%|
[shunlist](#shunlist)|1243|1243|1231|99.0%|0.6%|
[et_compromised](#et_compromised)|1721|1721|1116|64.8%|0.6%|
[blocklist_de_ssh](#blocklist_de_ssh)|3474|3474|1100|31.6%|0.5%|
[bruteforceblocker](#bruteforceblocker)|1705|1705|1082|63.4%|0.5%|
[openbl_7d](#openbl_7d)|669|669|668|99.8%|0.3%|
[ciarmy](#ciarmy)|442|442|434|98.1%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|288|0.0%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|265|0.0%|0.1%|
[voipbl](#voipbl)|10533|10945|183|1.6%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|94424|94424|170|0.1%|0.0%|
[openbl_1d](#openbl_1d)|144|144|141|97.9%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14166|14166|125|0.8%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9945|9945|108|1.0%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|89|0.3%|0.0%|
[sorbs_spam](#sorbs_spam)|62018|62766|87|0.1%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|62018|62766|87|0.1%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|62018|62766|87|0.1%|0.0%|
[sslbl](#sslbl)|371|371|65|17.5%|0.0%|
[zeus](#zeus)|230|230|61|26.5%|0.0%|
[firehol_anonymous](#firehol_anonymous)|18924|82965|57|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6759|6759|49|0.7%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|16274|16274|46|0.2%|0.0%|
[dm_tor](#dm_tor)|6424|6424|42|0.6%|0.0%|
[bm_tor](#bm_tor)|6402|6402|42|0.6%|0.0%|
[nixspam](#nixspam)|16664|16664|40|0.2%|0.0%|
[et_tor](#et_tor)|6400|6400|39|0.6%|0.0%|
[firehol_proxies](#firehol_proxies)|12475|12745|38|0.2%|0.0%|
[zeus_badips](#zeus_badips)|202|202|37|18.3%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|183|183|35|19.1%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|1997|1997|31|1.5%|0.0%|
[tor_exits](#tor_exits)|1116|1116|30|2.6%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|29|5.5%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|80|80|19|23.7%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|2888|2888|19|0.6%|0.0%|
[php_commenters](#php_commenters)|430|430|18|4.1%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2798|2798|18|0.6%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|15|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|14|0.0%|0.0%|
[iw_spamlist](#iw_spamlist)|3758|3758|13|0.3%|0.0%|
[php_harvesters](#php_harvesters)|392|392|12|3.0%|0.0%|
[malc0de](#malc0de)|313|313|10|3.1%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|1425|1425|10|0.7%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|8|0.6%|0.0%|
[php_dictionary](#php_dictionary)|702|702|7|0.9%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|6|0.4%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|65|65|6|9.2%|0.0%|
[xroxy](#xroxy)|2163|2163|5|0.2%|0.0%|
[php_spammers](#php_spammers)|700|700|5|0.7%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7712|7712|4|0.0%|0.0%|
[et_botcc](#et_botcc)|506|506|4|0.7%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2784|2784|3|0.1%|0.0%|
[proxz](#proxz)|1265|1265|3|0.2%|0.0%|
[proxyrss](#proxyrss)|1673|1673|2|0.1%|0.0%|
[nt_malware_irc](#nt_malware_irc)|43|43|2|4.6%|0.0%|
[feodo](#feodo)|105|105|2|1.9%|0.0%|
[nt_malware_http](#nt_malware_http)|69|69|1|1.4%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|1|0.1%|0.0%|

## blocklist_de

[Blocklist.de](https://www.blocklist.de/) IPs that have been detected by fail2ban in the last 48 hours - **excellent list**

Source is downloaded from [this link](http://lists.blocklist.de/lists/all.txt).

The last time downloaded was found to be dated: Thu Jun 11 06:56:03 UTC 2015.

The ipset `blocklist_de` has **27197** entries, **27197** unique IPs.

The following table shows the overlaps of `blocklist_de` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de`.
- ` this % ` is the percentage **of this ipset (`blocklist_de`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|20916|32554|27197|83.5%|100.0%|
[blocklist_de_mail](#blocklist_de_mail)|16274|16274|16223|99.6%|59.6%|
[blocklist_de_apache](#blocklist_de_apache)|14166|14166|14163|99.9%|52.0%|
[firehol_level3](#firehol_level3)|109949|9627745|3819|0.0%|14.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|3474|0.0%|12.7%|
[blocklist_de_ssh](#blocklist_de_ssh)|3474|3474|3470|99.8%|12.7%|
[blocklist_de_bots](#blocklist_de_bots)|2888|2888|2876|99.5%|10.5%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2798|2798|2798|100.0%|10.2%|
[stopforumspam_30d](#stopforumspam_30d)|94424|94424|2602|2.7%|9.5%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|2348|8.0%|8.6%|
[blocklist_de_imap](#blocklist_de_imap)|1997|1997|1997|100.0%|7.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|1568|0.0%|5.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|1546|0.0%|5.6%|
[blocklist_de_ftp](#blocklist_de_ftp)|1425|1425|1425|100.0%|5.2%|
[stopforumspam_1d](#stopforumspam_1d)|6759|6759|1423|21.0%|5.2%|
[alienvault_reputation](#alienvault_reputation)|184538|184538|1309|0.7%|4.8%|
[sorbs_spam](#sorbs_spam)|62018|62766|1244|1.9%|4.5%|
[sorbs_recent_spam](#sorbs_recent_spam)|62018|62766|1244|1.9%|4.5%|
[sorbs_new_spam](#sorbs_new_spam)|62018|62766|1244|1.9%|4.5%|
[openbl_60d](#openbl_60d)|6997|6997|927|13.2%|3.4%|
[openbl_30d](#openbl_30d)|2829|2829|741|26.1%|2.7%|
[firehol_anonymous](#firehol_anonymous)|18924|82965|665|0.8%|2.4%|
[firehol_proxies](#firehol_proxies)|12475|12745|637|4.9%|2.3%|
[et_compromised](#et_compromised)|1721|1721|618|35.9%|2.2%|
[bruteforceblocker](#bruteforceblocker)|1705|1705|612|35.8%|2.2%|
[nixspam](#nixspam)|16664|16664|500|3.0%|1.8%|
[ri_web_proxies](#ri_web_proxies)|7712|7712|444|5.7%|1.6%|
[shunlist](#shunlist)|1243|1243|422|33.9%|1.5%|
[openbl_7d](#openbl_7d)|669|669|397|59.3%|1.4%|
[et_block](#et_block)|1000|18344011|242|0.0%|0.8%|
[firehol_level1](#firehol_level1)|5133|688894588|237|0.0%|0.8%|
[proxyrss](#proxyrss)|1673|1673|226|13.5%|0.8%|
[snort_ipfilter](#snort_ipfilter)|9945|9945|221|2.2%|0.8%|
[xroxy](#xroxy)|2163|2163|215|9.9%|0.7%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|214|0.0%|0.7%|
[blocklist_de_strongips](#blocklist_de_strongips)|183|183|183|100.0%|0.6%|
[proxz](#proxz)|1265|1265|178|14.0%|0.6%|
[openbl_1d](#openbl_1d)|144|144|123|85.4%|0.4%|
[iw_spamlist](#iw_spamlist)|3758|3758|119|3.1%|0.4%|
[php_dictionary](#php_dictionary)|702|702|111|15.8%|0.4%|
[php_commenters](#php_commenters)|430|430|106|24.6%|0.3%|
[php_spammers](#php_spammers)|700|700|105|15.0%|0.3%|
[ri_connect_proxies](#ri_connect_proxies)|2784|2784|69|2.4%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|64|0.0%|0.2%|
[blocklist_de_sip](#blocklist_de_sip)|80|80|61|76.2%|0.2%|
[sorbs_web](#sorbs_web)|482|483|59|12.2%|0.2%|
[dshield](#dshield)|20|5120|54|1.0%|0.1%|
[dragon_http](#dragon_http)|1044|273664|54|0.0%|0.1%|
[ciarmy](#ciarmy)|442|442|44|9.9%|0.1%|
[php_harvesters](#php_harvesters)|392|392|37|9.4%|0.1%|
[voipbl](#voipbl)|10533|10945|31|0.2%|0.1%|
[tor_exits](#tor_exits)|1116|1116|24|2.1%|0.0%|
[et_tor](#et_tor)|6400|6400|18|0.2%|0.0%|
[bm_tor](#bm_tor)|6402|6402|15|0.2%|0.0%|
[dm_tor](#dm_tor)|6424|6424|14|0.2%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|12|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|8|1.5%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|8|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|5|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|4|0.6%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|3|0.2%|0.0%|
[zeus_badips](#zeus_badips)|202|202|1|0.4%|0.0%|
[zeus](#zeus)|230|230|1|0.4%|0.0%|
[iw_wormlist](#iw_wormlist)|33|33|1|3.0%|0.0%|

## blocklist_de_apache

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service Apache, Apache-DDOS, RFI-Attacks.

Source is downloaded from [this link](http://lists.blocklist.de/lists/apache.txt).

The last time downloaded was found to be dated: Thu Jun 11 07:14:08 UTC 2015.

The ipset `blocklist_de_apache` has **14166** entries, **14166** unique IPs.

The following table shows the overlaps of `blocklist_de_apache` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_apache`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_apache`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_apache`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|20916|32554|14163|43.5%|99.9%|
[blocklist_de](#blocklist_de)|27197|27197|14163|52.0%|99.9%|
[blocklist_de_mail](#blocklist_de_mail)|16274|16274|11059|67.9%|78.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2798|2798|2797|99.9%|19.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|2301|0.0%|16.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|1319|0.0%|9.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|1088|0.0%|7.6%|
[firehol_level3](#firehol_level3)|109949|9627745|303|0.0%|2.1%|
[stopforumspam_30d](#stopforumspam_30d)|94424|94424|214|0.2%|1.5%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|127|0.4%|0.8%|
[alienvault_reputation](#alienvault_reputation)|184538|184538|125|0.0%|0.8%|
[stopforumspam_1d](#stopforumspam_1d)|6759|6759|69|1.0%|0.4%|
[sorbs_spam](#sorbs_spam)|62018|62766|45|0.0%|0.3%|
[sorbs_recent_spam](#sorbs_recent_spam)|62018|62766|45|0.0%|0.3%|
[sorbs_new_spam](#sorbs_new_spam)|62018|62766|45|0.0%|0.3%|
[snort_ipfilter](#snort_ipfilter)|9945|9945|36|0.3%|0.2%|
[ciarmy](#ciarmy)|442|442|36|8.1%|0.2%|
[blocklist_de_strongips](#blocklist_de_strongips)|183|183|35|19.1%|0.2%|
[shunlist](#shunlist)|1243|1243|33|2.6%|0.2%|
[php_commenters](#php_commenters)|430|430|30|6.9%|0.2%|
[firehol_anonymous](#firehol_anonymous)|18924|82965|27|0.0%|0.1%|
[tor_exits](#tor_exits)|1116|1116|23|2.0%|0.1%|
[blocklist_de_bots](#blocklist_de_bots)|2888|2888|21|0.7%|0.1%|
[et_tor](#et_tor)|6400|6400|17|0.2%|0.1%|
[bm_tor](#bm_tor)|6402|6402|14|0.2%|0.0%|
[et_block](#et_block)|1000|18344011|13|0.0%|0.0%|
[dragon_http](#dragon_http)|1044|273664|13|0.0%|0.0%|
[dm_tor](#dm_tor)|6424|6424|13|0.2%|0.0%|
[nixspam](#nixspam)|16664|16664|11|0.0%|0.0%|
[firehol_level1](#firehol_level1)|5133|688894588|8|0.0%|0.0%|
[openbl_60d](#openbl_60d)|6997|6997|7|0.1%|0.0%|
[openbl_30d](#openbl_30d)|2829|2829|7|0.2%|0.0%|
[php_spammers](#php_spammers)|700|700|6|0.8%|0.0%|
[openbl_7d](#openbl_7d)|669|669|5|0.7%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|4|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|4|0.0%|0.0%|
[dshield](#dshield)|20|5120|4|0.0%|0.0%|
[php_dictionary](#php_dictionary)|702|702|3|0.4%|0.0%|
[firehol_proxies](#firehol_proxies)|12475|12745|3|0.0%|0.0%|
[voipbl](#voipbl)|10533|10945|2|0.0%|0.0%|
[php_harvesters](#php_harvesters)|392|392|2|0.5%|0.0%|
[openbl_1d](#openbl_1d)|144|144|2|1.3%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|2|0.3%|0.0%|
[iw_spamlist](#iw_spamlist)|3758|3758|2|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|2|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7712|7712|1|0.0%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|1997|1997|1|0.0%|0.0%|

## blocklist_de_bots

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the RFI-Attacks, REG-Bots, IRC-Bots or BadBots (BadBots = he has posted a Spam-Comment on a open Forum or Wiki).

Source is downloaded from [this link](http://lists.blocklist.de/lists/bots.txt).

The last time downloaded was found to be dated: Thu Jun 11 07:10:08 UTC 2015.

The ipset `blocklist_de_bots` has **2888** entries, **2888** unique IPs.

The following table shows the overlaps of `blocklist_de_bots` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_bots`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_bots`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_bots`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|20916|32554|2877|8.8%|99.6%|
[blocklist_de](#blocklist_de)|27197|27197|2876|10.5%|99.5%|
[firehol_level3](#firehol_level3)|109949|9627745|2263|0.0%|78.3%|
[stopforumspam_30d](#stopforumspam_30d)|94424|94424|2222|2.3%|76.9%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|2139|7.3%|74.0%|
[stopforumspam_1d](#stopforumspam_1d)|6759|6759|1359|20.1%|47.0%|
[firehol_anonymous](#firehol_anonymous)|18924|82965|513|0.6%|17.7%|
[firehol_proxies](#firehol_proxies)|12475|12745|512|4.0%|17.7%|
[ri_web_proxies](#ri_web_proxies)|7712|7712|362|4.6%|12.5%|
[proxyrss](#proxyrss)|1673|1673|224|13.3%|7.7%|
[xroxy](#xroxy)|2163|2163|158|7.3%|5.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|157|0.0%|5.4%|
[proxz](#proxz)|1265|1265|147|11.6%|5.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|183|183|135|73.7%|4.6%|
[php_commenters](#php_commenters)|430|430|86|20.0%|2.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|75|0.0%|2.5%|
[ri_connect_proxies](#ri_connect_proxies)|2784|2784|64|2.2%|2.2%|
[firehol_level1](#firehol_level1)|5133|688894588|60|0.0%|2.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|56|0.0%|1.9%|
[et_block](#et_block)|1000|18344011|56|0.0%|1.9%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|54|0.0%|1.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|40|0.0%|1.3%|
[sorbs_spam](#sorbs_spam)|62018|62766|29|0.0%|1.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|62018|62766|29|0.0%|1.0%|
[sorbs_new_spam](#sorbs_new_spam)|62018|62766|29|0.0%|1.0%|
[nixspam](#nixspam)|16664|16664|29|0.1%|1.0%|
[php_harvesters](#php_harvesters)|392|392|27|6.8%|0.9%|
[snort_ipfilter](#snort_ipfilter)|9945|9945|24|0.2%|0.8%|
[php_spammers](#php_spammers)|700|700|24|3.4%|0.8%|
[blocklist_de_mail](#blocklist_de_mail)|16274|16274|21|0.1%|0.7%|
[blocklist_de_apache](#blocklist_de_apache)|14166|14166|21|0.1%|0.7%|
[alienvault_reputation](#alienvault_reputation)|184538|184538|19|0.0%|0.6%|
[php_dictionary](#php_dictionary)|702|702|18|2.5%|0.6%|
[sorbs_web](#sorbs_web)|482|483|7|1.4%|0.2%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|5|0.0%|0.1%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|5|0.9%|0.1%|
[iw_spamlist](#iw_spamlist)|3758|3758|5|0.1%|0.1%|
[dragon_http](#dragon_http)|1044|273664|3|0.0%|0.1%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|2|0.1%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|2|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|2|0.3%|0.0%|
[tor_exits](#tor_exits)|1116|1116|1|0.0%|0.0%|
[openbl_60d](#openbl_60d)|6997|6997|1|0.0%|0.0%|
[openbl_30d](#openbl_30d)|2829|2829|1|0.0%|0.0%|
[et_compromised](#et_compromised)|1721|1721|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1705|1705|1|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2798|2798|1|0.0%|0.0%|

## blocklist_de_bruteforce

[Blocklist.de](https://www.blocklist.de/) All IPs which attacks Joomlas, Wordpress and other Web-Logins with Brute-Force Logins.

Source is downloaded from [this link](http://lists.blocklist.de/lists/bruteforcelogin.txt).

The last time downloaded was found to be dated: Thu Jun 11 06:56:14 UTC 2015.

The ipset `blocklist_de_bruteforce` has **2798** entries, **2798** unique IPs.

The following table shows the overlaps of `blocklist_de_bruteforce` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_bruteforce`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_bruteforce`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_bruteforce`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|20916|32554|2798|8.5%|100.0%|
[blocklist_de](#blocklist_de)|27197|27197|2798|10.2%|100.0%|
[blocklist_de_apache](#blocklist_de_apache)|14166|14166|2797|19.7%|99.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|211|0.0%|7.5%|
[firehol_level3](#firehol_level3)|109949|9627745|99|0.0%|3.5%|
[stopforumspam_30d](#stopforumspam_30d)|94424|94424|77|0.0%|2.7%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|61|0.2%|2.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|56|0.0%|2.0%|
[sorbs_spam](#sorbs_spam)|62018|62766|45|0.0%|1.6%|
[sorbs_recent_spam](#sorbs_recent_spam)|62018|62766|45|0.0%|1.6%|
[sorbs_new_spam](#sorbs_new_spam)|62018|62766|45|0.0%|1.6%|
[stopforumspam_1d](#stopforumspam_1d)|6759|6759|40|0.5%|1.4%|
[snort_ipfilter](#snort_ipfilter)|9945|9945|33|0.3%|1.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|30|0.0%|1.0%|
[firehol_anonymous](#firehol_anonymous)|18924|82965|24|0.0%|0.8%|
[tor_exits](#tor_exits)|1116|1116|21|1.8%|0.7%|
[alienvault_reputation](#alienvault_reputation)|184538|184538|18|0.0%|0.6%|
[et_tor](#et_tor)|6400|6400|15|0.2%|0.5%|
[php_commenters](#php_commenters)|430|430|11|2.5%|0.3%|
[bm_tor](#bm_tor)|6402|6402|11|0.1%|0.3%|
[blocklist_de_strongips](#blocklist_de_strongips)|183|183|11|6.0%|0.3%|
[nixspam](#nixspam)|16664|16664|10|0.0%|0.3%|
[dm_tor](#dm_tor)|6424|6424|10|0.1%|0.3%|
[php_spammers](#php_spammers)|700|700|6|0.8%|0.2%|
[et_block](#et_block)|1000|18344011|5|0.0%|0.1%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|4|0.0%|0.1%|
[firehol_level1](#firehol_level1)|5133|688894588|4|0.0%|0.1%|
[php_dictionary](#php_dictionary)|702|702|3|0.4%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|3|0.0%|0.1%|
[dragon_http](#dragon_http)|1044|273664|3|0.0%|0.1%|
[iw_spamlist](#iw_spamlist)|3758|3758|2|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|2|0.0%|0.0%|
[firehol_proxies](#firehol_proxies)|12475|12745|2|0.0%|0.0%|
[voipbl](#voipbl)|10533|10945|1|0.0%|0.0%|
[shunlist](#shunlist)|1243|1243|1|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7712|7712|1|0.0%|0.0%|
[php_harvesters](#php_harvesters)|392|392|1|0.2%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|1|0.1%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|2888|2888|1|0.0%|0.0%|

## blocklist_de_ftp

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours for attacks on the Service FTP.

Source is downloaded from [this link](http://lists.blocklist.de/lists/ftp.txt).

The last time downloaded was found to be dated: Thu Jun 11 06:56:10 UTC 2015.

The ipset `blocklist_de_ftp` has **1425** entries, **1425** unique IPs.

The following table shows the overlaps of `blocklist_de_ftp` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_ftp`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_ftp`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_ftp`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|20916|32554|1425|4.3%|100.0%|
[blocklist_de](#blocklist_de)|27197|27197|1425|5.2%|100.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|140|0.0%|9.8%|
[firehol_level3](#firehol_level3)|109949|9627745|28|0.0%|1.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|26|0.0%|1.8%|
[stopforumspam_30d](#stopforumspam_30d)|94424|94424|20|0.0%|1.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|18|0.0%|1.2%|
[sorbs_spam](#sorbs_spam)|62018|62766|13|0.0%|0.9%|
[sorbs_recent_spam](#sorbs_recent_spam)|62018|62766|13|0.0%|0.9%|
[sorbs_new_spam](#sorbs_new_spam)|62018|62766|13|0.0%|0.9%|
[alienvault_reputation](#alienvault_reputation)|184538|184538|10|0.0%|0.7%|
[dragon_http](#dragon_http)|1044|273664|7|0.0%|0.4%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|6|0.0%|0.4%|
[php_harvesters](#php_harvesters)|392|392|4|1.0%|0.2%|
[nixspam](#nixspam)|16664|16664|4|0.0%|0.2%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|3|0.0%|0.2%|
[openbl_60d](#openbl_60d)|6997|6997|2|0.0%|0.1%|
[firehol_anonymous](#firehol_anonymous)|18924|82965|2|0.0%|0.1%|
[blocklist_de_strongips](#blocklist_de_strongips)|183|183|2|1.0%|0.1%|
[sorbs_web](#sorbs_web)|482|483|1|0.2%|0.0%|
[php_spammers](#php_spammers)|700|700|1|0.1%|0.0%|
[php_dictionary](#php_dictionary)|702|702|1|0.1%|0.0%|
[openbl_7d](#openbl_7d)|669|669|1|0.1%|0.0%|
[openbl_30d](#openbl_30d)|2829|2829|1|0.0%|0.0%|
[iw_spamlist](#iw_spamlist)|3758|3758|1|0.0%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.0%|
[ciarmy](#ciarmy)|442|442|1|0.2%|0.0%|

## blocklist_de_imap

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours for attacks on the Service imap, sasl, pop3, etc.

Source is downloaded from [this link](http://lists.blocklist.de/lists/imap.txt).

The last time downloaded was found to be dated: Thu Jun 11 06:56:10 UTC 2015.

The ipset `blocklist_de_imap` has **1997** entries, **1997** unique IPs.

The following table shows the overlaps of `blocklist_de_imap` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_imap`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_imap`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_imap`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|20916|32554|1997|6.1%|100.0%|
[blocklist_de](#blocklist_de)|27197|27197|1997|7.3%|100.0%|
[blocklist_de_mail](#blocklist_de_mail)|16274|16274|1979|12.1%|99.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|219|0.0%|10.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|57|0.0%|2.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|53|0.0%|2.6%|
[firehol_level3](#firehol_level3)|109949|9627745|33|0.0%|1.6%|
[alienvault_reputation](#alienvault_reputation)|184538|184538|31|0.0%|1.5%|
[sorbs_spam](#sorbs_spam)|62018|62766|20|0.0%|1.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|62018|62766|20|0.0%|1.0%|
[sorbs_new_spam](#sorbs_new_spam)|62018|62766|20|0.0%|1.0%|
[stopforumspam_30d](#stopforumspam_30d)|94424|94424|14|0.0%|0.7%|
[openbl_60d](#openbl_60d)|6997|6997|14|0.2%|0.7%|
[nixspam](#nixspam)|16664|16664|12|0.0%|0.6%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|10|0.0%|0.5%|
[firehol_level1](#firehol_level1)|5133|688894588|10|0.0%|0.5%|
[et_block](#et_block)|1000|18344011|10|0.0%|0.5%|
[openbl_30d](#openbl_30d)|2829|2829|8|0.2%|0.4%|
[openbl_7d](#openbl_7d)|669|669|7|1.0%|0.3%|
[dragon_http](#dragon_http)|1044|273664|6|0.0%|0.3%|
[snort_ipfilter](#snort_ipfilter)|9945|9945|4|0.0%|0.2%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|3|0.0%|0.1%|
[shunlist](#shunlist)|1243|1243|3|0.2%|0.1%|
[et_compromised](#et_compromised)|1721|1721|3|0.1%|0.1%|
[bruteforceblocker](#bruteforceblocker)|1705|1705|3|0.1%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2|0.0%|0.1%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|2|0.0%|0.1%|
[ciarmy](#ciarmy)|442|442|2|0.4%|0.1%|
[stopforumspam_1d](#stopforumspam_1d)|6759|6759|1|0.0%|0.0%|
[php_harvesters](#php_harvesters)|392|392|1|0.2%|0.0%|
[openbl_1d](#openbl_1d)|144|144|1|0.6%|0.0%|
[iw_spamlist](#iw_spamlist)|3758|3758|1|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14166|14166|1|0.0%|0.0%|

## blocklist_de_mail

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service Mail, Postfix.

Source is downloaded from [this link](http://lists.blocklist.de/lists/mail.txt).

The last time downloaded was found to be dated: Thu Jun 11 07:14:06 UTC 2015.

The ipset `blocklist_de_mail` has **16274** entries, **16274** unique IPs.

The following table shows the overlaps of `blocklist_de_mail` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_mail`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_mail`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_mail`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|20916|32554|16223|49.8%|99.6%|
[blocklist_de](#blocklist_de)|27197|27197|16223|59.6%|99.6%|
[blocklist_de_apache](#blocklist_de_apache)|14166|14166|11059|78.0%|67.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|2431|0.0%|14.9%|
[blocklist_de_imap](#blocklist_de_imap)|1997|1997|1979|99.0%|12.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|1404|0.0%|8.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|1252|0.0%|7.6%|
[sorbs_spam](#sorbs_spam)|62018|62766|1154|1.8%|7.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|62018|62766|1154|1.8%|7.0%|
[sorbs_new_spam](#sorbs_new_spam)|62018|62766|1154|1.8%|7.0%|
[nixspam](#nixspam)|16664|16664|470|2.8%|2.8%|
[firehol_level3](#firehol_level3)|109949|9627745|409|0.0%|2.5%|
[stopforumspam_30d](#stopforumspam_30d)|94424|94424|263|0.2%|1.6%|
[snort_ipfilter](#snort_ipfilter)|9945|9945|164|1.6%|1.0%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|147|0.5%|0.9%|
[firehol_anonymous](#firehol_anonymous)|18924|82965|122|0.1%|0.7%|
[firehol_proxies](#firehol_proxies)|12475|12745|120|0.9%|0.7%|
[iw_spamlist](#iw_spamlist)|3758|3758|111|2.9%|0.6%|
[php_dictionary](#php_dictionary)|702|702|90|12.8%|0.5%|
[ri_web_proxies](#ri_web_proxies)|7712|7712|79|1.0%|0.4%|
[php_spammers](#php_spammers)|700|700|73|10.4%|0.4%|
[xroxy](#xroxy)|2163|2163|56|2.5%|0.3%|
[sorbs_web](#sorbs_web)|482|483|51|10.5%|0.3%|
[alienvault_reputation](#alienvault_reputation)|184538|184538|46|0.0%|0.2%|
[stopforumspam_1d](#stopforumspam_1d)|6759|6759|41|0.6%|0.2%|
[proxz](#proxz)|1265|1265|29|2.2%|0.1%|
[php_commenters](#php_commenters)|430|430|27|6.2%|0.1%|
[blocklist_de_strongips](#blocklist_de_strongips)|183|183|22|12.0%|0.1%|
[firehol_level1](#firehol_level1)|5133|688894588|21|0.0%|0.1%|
[et_block](#et_block)|1000|18344011|21|0.0%|0.1%|
[blocklist_de_bots](#blocklist_de_bots)|2888|2888|21|0.7%|0.1%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|20|0.0%|0.1%|
[openbl_60d](#openbl_60d)|6997|6997|20|0.2%|0.1%|
[dragon_http](#dragon_http)|1044|273664|16|0.0%|0.0%|
[openbl_30d](#openbl_30d)|2829|2829|13|0.4%|0.0%|
[openbl_7d](#openbl_7d)|669|669|8|1.1%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|6|0.0%|0.0%|
[php_harvesters](#php_harvesters)|392|392|5|1.2%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2784|2784|4|0.1%|0.0%|
[et_compromised](#et_compromised)|1721|1721|4|0.2%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1705|1705|4|0.2%|0.0%|
[shunlist](#shunlist)|1243|1243|3|0.2%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|0.0%|
[dm_tor](#dm_tor)|6424|6424|3|0.0%|0.0%|
[bm_tor](#bm_tor)|6402|6402|3|0.0%|0.0%|
[tor_exits](#tor_exits)|1116|1116|2|0.1%|0.0%|
[openbl_1d](#openbl_1d)|144|144|2|1.3%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|2|0.3%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|2|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|2|0.3%|0.0%|
[et_tor](#et_tor)|6400|6400|2|0.0%|0.0%|
[ciarmy](#ciarmy)|442|442|2|0.4%|0.0%|
[zeus_badips](#zeus_badips)|202|202|1|0.4%|0.0%|
[zeus](#zeus)|230|230|1|0.4%|0.0%|
[voipbl](#voipbl)|10533|10945|1|0.0%|0.0%|
[proxyrss](#proxyrss)|1673|1673|1|0.0%|0.0%|
[iw_wormlist](#iw_wormlist)|33|33|1|3.0%|0.0%|

## blocklist_de_sip

[Blocklist.de](https://www.blocklist.de/) All IP addresses that tried to login in a SIP, VOIP or Asterisk Server and are included in the IPs list from [infiltrated.net](www.infiltrated.net)

Source is downloaded from [this link](http://lists.blocklist.de/lists/sip.txt).

The last time downloaded was found to be dated: Thu Jun 11 07:14:09 UTC 2015.

The ipset `blocklist_de_sip` has **80** entries, **80** unique IPs.

The following table shows the overlaps of `blocklist_de_sip` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_sip`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_sip`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_sip`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|20916|32554|61|0.1%|76.2%|
[blocklist_de](#blocklist_de)|27197|27197|61|0.2%|76.2%|
[voipbl](#voipbl)|10533|10945|26|0.2%|32.5%|
[alienvault_reputation](#alienvault_reputation)|184538|184538|19|0.0%|23.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|10|0.0%|12.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|7|0.0%|8.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|6|0.0%|7.5%|
[firehol_level3](#firehol_level3)|109949|9627745|4|0.0%|5.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|2|0.0%|2.5%|
[shunlist](#shunlist)|1243|1243|2|0.1%|2.5%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|2|0.0%|2.5%|
[firehol_level1](#firehol_level1)|5133|688894588|2|0.0%|2.5%|
[et_block](#et_block)|1000|18344011|2|0.0%|2.5%|
[dragon_http](#dragon_http)|1044|273664|2|0.0%|2.5%|
[et_botcc](#et_botcc)|506|506|1|0.1%|1.2%|

## blocklist_de_ssh

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service SSH.

Source is downloaded from [this link](http://lists.blocklist.de/lists/ssh.txt).

The last time downloaded was found to be dated: Thu Jun 11 07:10:03 UTC 2015.

The ipset `blocklist_de_ssh` has **3474** entries, **3474** unique IPs.

The following table shows the overlaps of `blocklist_de_ssh` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_ssh`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_ssh`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_ssh`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|20916|32554|3470|10.6%|99.8%|
[blocklist_de](#blocklist_de)|27197|27197|3470|12.7%|99.8%|
[alienvault_reputation](#alienvault_reputation)|184538|184538|1100|0.5%|31.6%|
[firehol_level3](#firehol_level3)|109949|9627745|959|0.0%|27.6%|
[openbl_60d](#openbl_60d)|6997|6997|895|12.7%|25.7%|
[openbl_30d](#openbl_30d)|2829|2829|717|25.3%|20.6%|
[et_compromised](#et_compromised)|1721|1721|613|35.6%|17.6%|
[bruteforceblocker](#bruteforceblocker)|1705|1705|607|35.6%|17.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|512|0.0%|14.7%|
[shunlist](#shunlist)|1243|1243|383|30.8%|11.0%|
[openbl_7d](#openbl_7d)|669|669|383|57.2%|11.0%|
[et_block](#et_block)|1000|18344011|151|0.0%|4.3%|
[firehol_level1](#firehol_level1)|5133|688894588|147|0.0%|4.2%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|133|0.0%|3.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|130|0.0%|3.7%|
[openbl_1d](#openbl_1d)|144|144|119|82.6%|3.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|57|0.0%|1.6%|
[dshield](#dshield)|20|5120|50|0.9%|1.4%|
[blocklist_de_strongips](#blocklist_de_strongips)|183|183|29|15.8%|0.8%|
[stopforumspam_30d](#stopforumspam_30d)|94424|94424|24|0.0%|0.6%|
[dragon_http](#dragon_http)|1044|273664|14|0.0%|0.4%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|6|0.0%|0.1%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|5|0.0%|0.1%|
[ciarmy](#ciarmy)|442|442|5|1.1%|0.1%|
[sorbs_spam](#sorbs_spam)|62018|62766|4|0.0%|0.1%|
[sorbs_recent_spam](#sorbs_recent_spam)|62018|62766|4|0.0%|0.1%|
[sorbs_new_spam](#sorbs_new_spam)|62018|62766|4|0.0%|0.1%|
[nixspam](#nixspam)|16664|16664|3|0.0%|0.0%|
[voipbl](#voipbl)|10533|10945|2|0.0%|0.0%|
[firehol_anonymous](#firehol_anonymous)|18924|82965|2|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7712|7712|1|0.0%|0.0%|
[php_spammers](#php_spammers)|700|700|1|0.1%|0.0%|
[php_commenters](#php_commenters)|430|430|1|0.2%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|1|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|1|0.0%|0.0%|
[firehol_proxies](#firehol_proxies)|12475|12745|1|0.0%|0.0%|
[et_tor](#et_tor)|6400|6400|1|0.0%|0.0%|
[dm_tor](#dm_tor)|6424|6424|1|0.0%|0.0%|
[bm_tor](#bm_tor)|6402|6402|1|0.0%|0.0%|

## blocklist_de_strongips

[Blocklist.de](https://www.blocklist.de/) All IPs which are older then 2 month and have more then 5.000 attacks.

Source is downloaded from [this link](http://lists.blocklist.de/lists/strongips.txt).

The last time downloaded was found to be dated: Thu Jun 11 07:14:11 UTC 2015.

The ipset `blocklist_de_strongips` has **183** entries, **183** unique IPs.

The following table shows the overlaps of `blocklist_de_strongips` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_strongips`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_strongips`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_strongips`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|20916|32554|183|0.5%|100.0%|
[blocklist_de](#blocklist_de)|27197|27197|183|0.6%|100.0%|
[firehol_level3](#firehol_level3)|109949|9627745|164|0.0%|89.6%|
[stopforumspam_30d](#stopforumspam_30d)|94424|94424|138|0.1%|75.4%|
[blocklist_de_bots](#blocklist_de_bots)|2888|2888|135|4.6%|73.7%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|125|0.4%|68.3%|
[stopforumspam_1d](#stopforumspam_1d)|6759|6759|112|1.6%|61.2%|
[php_commenters](#php_commenters)|430|430|47|10.9%|25.6%|
[blocklist_de_apache](#blocklist_de_apache)|14166|14166|35|0.2%|19.1%|
[alienvault_reputation](#alienvault_reputation)|184538|184538|35|0.0%|19.1%|
[blocklist_de_ssh](#blocklist_de_ssh)|3474|3474|29|0.8%|15.8%|
[openbl_60d](#openbl_60d)|6997|6997|25|0.3%|13.6%|
[openbl_7d](#openbl_7d)|669|669|24|3.5%|13.1%|
[openbl_30d](#openbl_30d)|2829|2829|24|0.8%|13.1%|
[blocklist_de_mail](#blocklist_de_mail)|16274|16274|22|0.1%|12.0%|
[shunlist](#shunlist)|1243|1243|19|1.5%|10.3%|
[firehol_level1](#firehol_level1)|5133|688894588|19|0.0%|10.3%|
[openbl_1d](#openbl_1d)|144|144|17|11.8%|9.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|16|0.0%|8.7%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2798|2798|11|0.3%|6.0%|
[php_spammers](#php_spammers)|700|700|10|1.4%|5.4%|
[et_block](#et_block)|1000|18344011|10|0.0%|5.4%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|8|0.0%|4.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|8|0.0%|4.3%|
[firehol_proxies](#firehol_proxies)|12475|12745|8|0.0%|4.3%|
[firehol_anonymous](#firehol_anonymous)|18924|82965|8|0.0%|4.3%|
[dshield](#dshield)|20|5120|8|0.1%|4.3%|
[ri_web_proxies](#ri_web_proxies)|7712|7712|7|0.0%|3.8%|
[xroxy](#xroxy)|2163|2163|6|0.2%|3.2%|
[proxz](#proxz)|1265|1265|6|0.4%|3.2%|
[proxyrss](#proxyrss)|1673|1673|6|0.3%|3.2%|
[php_dictionary](#php_dictionary)|702|702|5|0.7%|2.7%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|4|0.0%|2.1%|
[php_harvesters](#php_harvesters)|392|392|3|0.7%|1.6%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|1.6%|
[sorbs_web](#sorbs_web)|482|483|2|0.4%|1.0%|
[sorbs_spam](#sorbs_spam)|62018|62766|2|0.0%|1.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|62018|62766|2|0.0%|1.0%|
[sorbs_new_spam](#sorbs_new_spam)|62018|62766|2|0.0%|1.0%|
[snort_ipfilter](#snort_ipfilter)|9945|9945|2|0.0%|1.0%|
[nixspam](#nixspam)|16664|16664|2|0.0%|1.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|2|0.1%|1.0%|
[dragon_http](#dragon_http)|1044|273664|2|0.0%|1.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|1425|1425|2|0.1%|1.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|1|0.0%|0.5%|

## bm_tor

[torstatus.blutmagie.de](https://torstatus.blutmagie.de) list of all TOR network servers

Source is downloaded from [this link](https://torstatus.blutmagie.de/ip_list_all.php/Tor_ip_list_ALL.csv).

The last time downloaded was found to be dated: Thu Jun 11 07:18:03 UTC 2015.

The ipset `bm_tor` has **6402** entries, **6402** unique IPs.

The following table shows the overlaps of `bm_tor` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `bm_tor`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `bm_tor`.
- ` this % ` is the percentage **of this ipset (`bm_tor`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_anonymous](#firehol_anonymous)|18924|82965|6402|7.7%|100.0%|
[dm_tor](#dm_tor)|6424|6424|6340|98.6%|99.0%|
[et_tor](#et_tor)|6400|6400|5780|90.3%|90.2%|
[firehol_level3](#firehol_level3)|109949|9627745|1097|0.0%|17.1%|
[snort_ipfilter](#snort_ipfilter)|9945|9945|1061|10.6%|16.5%|
[tor_exits](#tor_exits)|1116|1116|1013|90.7%|15.8%|
[stopforumspam_30d](#stopforumspam_30d)|94424|94424|642|0.6%|10.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|629|0.0%|9.8%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|540|1.8%|8.4%|
[firehol_level2](#firehol_level2)|20916|32554|357|1.0%|5.5%|
[stopforumspam_1d](#stopforumspam_1d)|6759|6759|349|5.1%|5.4%|
[firehol_proxies](#firehol_proxies)|12475|12745|238|1.8%|3.7%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|233|44.4%|3.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|182|0.0%|2.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|167|0.0%|2.6%|
[php_commenters](#php_commenters)|430|430|51|11.8%|0.7%|
[alienvault_reputation](#alienvault_reputation)|184538|184538|42|0.0%|0.6%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|22|0.0%|0.3%|
[openbl_60d](#openbl_60d)|6997|6997|20|0.2%|0.3%|
[blocklist_de](#blocklist_de)|27197|27197|15|0.0%|0.2%|
[blocklist_de_apache](#blocklist_de_apache)|14166|14166|14|0.0%|0.2%|
[dragon_http](#dragon_http)|1044|273664|11|0.0%|0.1%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2798|2798|11|0.3%|0.1%|
[php_harvesters](#php_harvesters)|392|392|7|1.7%|0.1%|
[nixspam](#nixspam)|16664|16664|6|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7712|7712|5|0.0%|0.0%|
[php_spammers](#php_spammers)|700|700|5|0.7%|0.0%|
[sorbs_spam](#sorbs_spam)|62018|62766|4|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|62018|62766|4|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|62018|62766|4|0.0%|0.0%|
[php_dictionary](#php_dictionary)|702|702|4|0.5%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|4|0.0%|0.0%|
[voipbl](#voipbl)|10533|10945|3|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|3|0.0%|0.0%|
[firehol_level1](#firehol_level1)|5133|688894588|3|0.0%|0.0%|
[et_block](#et_block)|1000|18344011|3|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|16274|16274|3|0.0%|0.0%|
[xroxy](#xroxy)|2163|2163|2|0.0%|0.0%|
[shunlist](#shunlist)|1243|1243|1|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2784|2784|1|0.0%|0.0%|
[proxyrss](#proxyrss)|1673|1673|1|0.0%|0.0%|
[iw_spamlist](#iw_spamlist)|3758|3758|1|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3474|3474|1|0.0%|0.0%|

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
[firehol_level1](#firehol_level1)|5133|688894588|592708608|86.0%|100.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|4194304|3.0%|0.7%|
[voipbl](#voipbl)|10533|10945|319|2.9%|0.0%|
[iw_spamlist](#iw_spamlist)|3758|3758|5|0.1%|0.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|5|0.0%|0.0%|
[firehol_level3](#firehol_level3)|109949|9627745|3|0.0%|0.0%|
[php_harvesters](#php_harvesters)|392|392|1|0.2%|0.0%|
[php_commenters](#php_commenters)|430|430|1|0.2%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.0%|
[ciarmy](#ciarmy)|442|442|1|0.2%|0.0%|

## bruteforceblocker

[danger.rulez.sk](http://danger.rulez.sk/) IPs detected by [bruteforceblocker](http://danger.rulez.sk/index.php/bruteforceblocker/) (fail2ban alternative for SSH on OpenBSD). This is an automatically generated list from users reporting failed authentication attempts. An IP seems to be included if 3 or more users report it. Its retention pocily seems 30 days.

Source is downloaded from [this link](http://danger.rulez.sk/projects/bruteforceblocker/blist.php).

The last time downloaded was found to be dated: Thu Jun 11 04:45:11 UTC 2015.

The ipset `bruteforceblocker` has **1705** entries, **1705** unique IPs.

The following table shows the overlaps of `bruteforceblocker` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `bruteforceblocker`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `bruteforceblocker`.
- ` this % ` is the percentage **of this ipset (`bruteforceblocker`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level3](#firehol_level3)|109949|9627745|1705|0.0%|100.0%|
[et_compromised](#et_compromised)|1721|1721|1656|96.2%|97.1%|
[alienvault_reputation](#alienvault_reputation)|184538|184538|1082|0.5%|63.4%|
[openbl_60d](#openbl_60d)|6997|6997|973|13.9%|57.0%|
[openbl_30d](#openbl_30d)|2829|2829|912|32.2%|53.4%|
[firehol_level2](#firehol_level2)|20916|32554|613|1.8%|35.9%|
[blocklist_de](#blocklist_de)|27197|27197|612|2.2%|35.8%|
[blocklist_de_ssh](#blocklist_de_ssh)|3474|3474|607|17.4%|35.6%|
[shunlist](#shunlist)|1243|1243|390|31.3%|22.8%|
[openbl_7d](#openbl_7d)|669|669|323|48.2%|18.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|157|0.0%|9.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|89|0.0%|5.2%|
[et_block](#et_block)|1000|18344011|73|0.0%|4.2%|
[firehol_level1](#firehol_level1)|5133|688894588|71|0.0%|4.1%|
[openbl_1d](#openbl_1d)|144|144|67|46.5%|3.9%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|65|0.0%|3.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|54|0.0%|3.1%|
[dshield](#dshield)|20|5120|42|0.8%|2.4%|
[dragon_http](#dragon_http)|1044|273664|13|0.0%|0.7%|
[stopforumspam_30d](#stopforumspam_30d)|94424|94424|12|0.0%|0.7%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|5|0.0%|0.2%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|4|0.0%|0.2%|
[blocklist_de_mail](#blocklist_de_mail)|16274|16274|4|0.0%|0.2%|
[voipbl](#voipbl)|10533|10945|3|0.0%|0.1%|
[sorbs_spam](#sorbs_spam)|62018|62766|3|0.0%|0.1%|
[sorbs_recent_spam](#sorbs_recent_spam)|62018|62766|3|0.0%|0.1%|
[sorbs_new_spam](#sorbs_new_spam)|62018|62766|3|0.0%|0.1%|
[firehol_proxies](#firehol_proxies)|12475|12745|3|0.0%|0.1%|
[firehol_anonymous](#firehol_anonymous)|18924|82965|3|0.0%|0.1%|
[ciarmy](#ciarmy)|442|442|3|0.6%|0.1%|
[blocklist_de_imap](#blocklist_de_imap)|1997|1997|3|0.1%|0.1%|
[proxz](#proxz)|1265|1265|2|0.1%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|2|0.0%|0.1%|
[xroxy](#xroxy)|2163|2163|1|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6759|6759|1|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7712|7712|1|0.0%|0.0%|
[proxyrss](#proxyrss)|1673|1673|1|0.0%|0.0%|
[php_spammers](#php_spammers)|700|700|1|0.1%|0.0%|
[php_commenters](#php_commenters)|430|430|1|0.2%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|2888|2888|1|0.0%|0.0%|

## ciarmy

[CIArmy.com](http://ciarmy.com/) IPs with poor Rogue Packet score that have not yet been identified as malicious by the community

Source is downloaded from [this link](http://cinsscore.com/list/ci-badguys.txt).

The last time downloaded was found to be dated: Thu Jun 11 07:15:06 UTC 2015.

The ipset `ciarmy` has **442** entries, **442** unique IPs.

The following table shows the overlaps of `ciarmy` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ciarmy`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ciarmy`.
- ` this % ` is the percentage **of this ipset (`ciarmy`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level3](#firehol_level3)|109949|9627745|442|0.0%|100.0%|
[alienvault_reputation](#alienvault_reputation)|184538|184538|434|0.2%|98.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|98|0.0%|22.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|46|0.0%|10.4%|
[firehol_level2](#firehol_level2)|20916|32554|44|0.1%|9.9%|
[blocklist_de](#blocklist_de)|27197|27197|44|0.1%|9.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|36|0.0%|8.1%|
[blocklist_de_apache](#blocklist_de_apache)|14166|14166|36|0.2%|8.1%|
[shunlist](#shunlist)|1243|1243|26|2.0%|5.8%|
[dragon_http](#dragon_http)|1044|273664|8|0.0%|1.8%|
[et_block](#et_block)|1000|18344011|6|0.0%|1.3%|
[firehol_level1](#firehol_level1)|5133|688894588|5|0.0%|1.1%|
[blocklist_de_ssh](#blocklist_de_ssh)|3474|3474|5|0.1%|1.1%|
[dshield](#dshield)|20|5120|4|0.0%|0.9%|
[et_compromised](#et_compromised)|1721|1721|3|0.1%|0.6%|
[bruteforceblocker](#bruteforceblocker)|1705|1705|3|0.1%|0.6%|
[openbl_7d](#openbl_7d)|669|669|2|0.2%|0.4%|
[openbl_60d](#openbl_60d)|6997|6997|2|0.0%|0.4%|
[openbl_30d](#openbl_30d)|2829|2829|2|0.0%|0.4%|
[blocklist_de_mail](#blocklist_de_mail)|16274|16274|2|0.0%|0.4%|
[blocklist_de_imap](#blocklist_de_imap)|1997|1997|2|0.1%|0.4%|
[voipbl](#voipbl)|10533|10945|1|0.0%|0.2%|
[stopforumspam_30d](#stopforumspam_30d)|94424|94424|1|0.0%|0.2%|
[openbl_1d](#openbl_1d)|144|144|1|0.6%|0.2%|
[fullbogons](#fullbogons)|3770|670213096|1|0.0%|0.2%|
[bogons](#bogons)|13|592708608|1|0.0%|0.2%|
[blocklist_de_ftp](#blocklist_de_ftp)|1425|1425|1|0.0%|0.2%|

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
[firehol_level3](#firehol_level3)|109949|9627745|65|0.0%|100.0%|
[alienvault_reputation](#alienvault_reputation)|184538|184538|6|0.0%|9.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|5|0.0%|7.6%|
[snort_ipfilter](#snort_ipfilter)|9945|9945|1|0.0%|1.5%|
[malc0de](#malc0de)|313|313|1|0.3%|1.5%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|1.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|1|0.0%|1.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|1|0.0%|1.5%|

## dm_tor

[dan.me.uk](https://www.dan.me.uk) dynamic list of TOR nodes

Source is downloaded from [this link](https://www.dan.me.uk/torlist/).

The last time downloaded was found to be dated: Thu Jun 11 07:00:04 UTC 2015.

The ipset `dm_tor` has **6424** entries, **6424** unique IPs.

The following table shows the overlaps of `dm_tor` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `dm_tor`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `dm_tor`.
- ` this % ` is the percentage **of this ipset (`dm_tor`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_anonymous](#firehol_anonymous)|18924|82965|6424|7.7%|100.0%|
[bm_tor](#bm_tor)|6402|6402|6340|99.0%|98.6%|
[et_tor](#et_tor)|6400|6400|5765|90.0%|89.7%|
[firehol_level3](#firehol_level3)|109949|9627745|1095|0.0%|17.0%|
[snort_ipfilter](#snort_ipfilter)|9945|9945|1059|10.6%|16.4%|
[tor_exits](#tor_exits)|1116|1116|1021|91.4%|15.8%|
[stopforumspam_30d](#stopforumspam_30d)|94424|94424|640|0.6%|9.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|627|0.0%|9.7%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|538|1.8%|8.3%|
[firehol_level2](#firehol_level2)|20916|32554|356|1.0%|5.5%|
[stopforumspam_1d](#stopforumspam_1d)|6759|6759|349|5.1%|5.4%|
[firehol_proxies](#firehol_proxies)|12475|12745|238|1.8%|3.7%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|233|44.4%|3.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|182|0.0%|2.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|166|0.0%|2.5%|
[php_commenters](#php_commenters)|430|430|51|11.8%|0.7%|
[alienvault_reputation](#alienvault_reputation)|184538|184538|42|0.0%|0.6%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|22|0.0%|0.3%|
[openbl_60d](#openbl_60d)|6997|6997|20|0.2%|0.3%|
[blocklist_de](#blocklist_de)|27197|27197|14|0.0%|0.2%|
[blocklist_de_apache](#blocklist_de_apache)|14166|14166|13|0.0%|0.2%|
[dragon_http](#dragon_http)|1044|273664|11|0.0%|0.1%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2798|2798|10|0.3%|0.1%|
[php_harvesters](#php_harvesters)|392|392|7|1.7%|0.1%|
[nixspam](#nixspam)|16664|16664|6|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7712|7712|5|0.0%|0.0%|
[php_spammers](#php_spammers)|700|700|5|0.7%|0.0%|
[sorbs_spam](#sorbs_spam)|62018|62766|4|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|62018|62766|4|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|62018|62766|4|0.0%|0.0%|
[php_dictionary](#php_dictionary)|702|702|4|0.5%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|4|0.0%|0.0%|
[voipbl](#voipbl)|10533|10945|3|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|3|0.0%|0.0%|
[firehol_level1](#firehol_level1)|5133|688894588|3|0.0%|0.0%|
[et_block](#et_block)|1000|18344011|3|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|16274|16274|3|0.0%|0.0%|
[xroxy](#xroxy)|2163|2163|2|0.0%|0.0%|
[shunlist](#shunlist)|1243|1243|1|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2784|2784|1|0.0%|0.0%|
[proxyrss](#proxyrss)|1673|1673|1|0.0%|0.0%|
[iw_spamlist](#iw_spamlist)|3758|3758|1|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3474|3474|1|0.0%|0.0%|

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
[alienvault_reputation](#alienvault_reputation)|184538|184538|5640|3.0%|2.0%|
[firehol_level1](#firehol_level1)|5133|688894588|1281|0.0%|0.4%|
[et_block](#et_block)|1000|18344011|1024|0.0%|0.3%|
[dshield](#dshield)|20|5120|1024|20.0%|0.3%|
[firehol_level3](#firehol_level3)|109949|9627745|567|0.0%|0.2%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|256|0.0%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|256|0.0%|0.0%|
[openbl_60d](#openbl_60d)|6997|6997|219|3.1%|0.0%|
[openbl_30d](#openbl_30d)|2829|2829|154|5.4%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|94424|94424|115|0.1%|0.0%|
[firehol_level2](#firehol_level2)|20916|32554|64|0.1%|0.0%|
[sorbs_spam](#sorbs_spam)|62018|62766|63|0.1%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|62018|62766|63|0.1%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|62018|62766|63|0.1%|0.0%|
[openbl_7d](#openbl_7d)|669|669|57|8.5%|0.0%|
[blocklist_de](#blocklist_de)|27197|27197|54|0.1%|0.0%|
[firehol_anonymous](#firehol_anonymous)|18924|82965|41|0.0%|0.0%|
[shunlist](#shunlist)|1243|1243|37|2.9%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|36|0.1%|0.0%|
[firehol_proxies](#firehol_proxies)|12475|12745|31|0.2%|0.0%|
[nixspam](#nixspam)|16664|16664|27|0.1%|0.0%|
[voipbl](#voipbl)|10533|10945|25|0.2%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|24|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7712|7712|17|0.2%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|16274|16274|16|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3474|3474|14|0.4%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1705|1705|13|0.7%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14166|14166|13|0.0%|0.0%|
[et_tor](#et_tor)|6400|6400|11|0.1%|0.0%|
[et_compromised](#et_compromised)|1721|1721|11|0.6%|0.0%|
[dm_tor](#dm_tor)|6424|6424|11|0.1%|0.0%|
[bm_tor](#bm_tor)|6402|6402|11|0.1%|0.0%|
[xroxy](#xroxy)|2163|2163|8|0.3%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6759|6759|8|0.1%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9945|9945|8|0.0%|0.0%|
[ciarmy](#ciarmy)|442|442|8|1.8%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|1425|1425|7|0.4%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|6|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|1997|1997|6|0.3%|0.0%|
[proxz](#proxz)|1265|1265|4|0.3%|0.0%|
[openbl_1d](#openbl_1d)|144|144|4|2.7%|0.0%|
[et_botcc](#et_botcc)|506|506|4|0.7%|0.0%|
[zeus_badips](#zeus_badips)|202|202|3|1.4%|0.0%|
[zeus](#zeus)|230|230|3|1.3%|0.0%|
[tor_exits](#tor_exits)|1116|1116|3|0.2%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2784|2784|3|0.1%|0.0%|
[proxyrss](#proxyrss)|1673|1673|3|0.1%|0.0%|
[malc0de](#malc0de)|313|313|3|0.9%|0.0%|
[iw_spamlist](#iw_spamlist)|3758|3758|3|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|3|0.2%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2798|2798|3|0.1%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|2888|2888|3|0.1%|0.0%|
[php_dictionary](#php_dictionary)|702|702|2|0.2%|0.0%|
[php_commenters](#php_commenters)|430|430|2|0.4%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|2|0.3%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|2|0.1%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|183|183|2|1.0%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|80|80|2|2.5%|0.0%|
[sslbl](#sslbl)|371|371|1|0.2%|0.0%|
[sorbs_web](#sorbs_web)|482|483|1|0.2%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|1|0.1%|0.0%|

## dshield

[DShield.org](https://dshield.org/) top 20 attacking class C (/24) subnets over the last three days - **excellent list**

Source is downloaded from [this link](http://feeds.dshield.org/block.txt).

The last time downloaded was found to be dated: Thu Jun 11 03:55:59 UTC 2015.

The ipset `dshield` has **20** entries, **5120** unique IPs.

The following table shows the overlaps of `dshield` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `dshield`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `dshield`.
- ` this % ` is the percentage **of this ipset (`dshield`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level1](#firehol_level1)|5133|688894588|5120|0.0%|100.0%|
[alienvault_reputation](#alienvault_reputation)|184538|184538|3328|1.8%|65.0%|
[et_block](#et_block)|1000|18344011|1536|0.0%|30.0%|
[dragon_http](#dragon_http)|1044|273664|1024|0.3%|20.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|512|0.0%|10.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|265|0.0%|5.1%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|256|0.0%|5.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|256|0.0%|5.0%|
[firehol_level3](#firehol_level3)|109949|9627745|88|0.0%|1.7%|
[openbl_60d](#openbl_60d)|6997|6997|85|1.2%|1.6%|
[openbl_30d](#openbl_30d)|2829|2829|75|2.6%|1.4%|
[firehol_level2](#firehol_level2)|20916|32554|54|0.1%|1.0%|
[blocklist_de](#blocklist_de)|27197|27197|54|0.1%|1.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3474|3474|50|1.4%|0.9%|
[shunlist](#shunlist)|1243|1243|44|3.5%|0.8%|
[openbl_7d](#openbl_7d)|669|669|43|6.4%|0.8%|
[et_compromised](#et_compromised)|1721|1721|42|2.4%|0.8%|
[bruteforceblocker](#bruteforceblocker)|1705|1705|42|2.4%|0.8%|
[openbl_1d](#openbl_1d)|144|144|18|12.5%|0.3%|
[blocklist_de_strongips](#blocklist_de_strongips)|183|183|8|4.3%|0.1%|
[ciarmy](#ciarmy)|442|442|4|0.9%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14166|14166|4|0.0%|0.0%|
[malc0de](#malc0de)|313|313|2|0.6%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|94424|94424|1|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9945|9945|1|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|1|0.1%|0.0%|
[firehol_proxies](#firehol_proxies)|12475|12745|1|0.0%|0.0%|
[firehol_anonymous](#firehol_anonymous)|18924|82965|1|0.0%|0.0%|

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
[firehol_level1](#firehol_level1)|5133|688894588|18340170|2.6%|99.9%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|18338560|99.9%|99.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|8532520|2.4%|46.5%|
[firehol_level3](#firehol_level3)|109949|9627745|6933378|72.0%|37.7%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|6932480|75.5%|37.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|2272548|0.2%|12.3%|
[fullbogons](#fullbogons)|3770|670213096|151552|0.0%|0.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|130394|0.0%|0.7%|
[alienvault_reputation](#alienvault_reputation)|184538|184538|4764|2.5%|0.0%|
[dshield](#dshield)|20|5120|1536|30.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1042|0.3%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|94424|94424|1025|1.0%|0.0%|
[dragon_http](#dragon_http)|1044|273664|1024|0.3%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|517|0.1%|0.0%|
[firehol_level2](#firehol_level2)|20916|32554|303|0.9%|0.0%|
[openbl_60d](#openbl_60d)|6997|6997|300|4.2%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9945|9945|298|2.9%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|272|0.9%|0.0%|
[blocklist_de](#blocklist_de)|27197|27197|242|0.8%|0.0%|
[zeus](#zeus)|230|230|228|99.1%|0.0%|
[zeus_badips](#zeus_badips)|202|202|202|100.0%|0.0%|
[openbl_30d](#openbl_30d)|2829|2829|163|5.7%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3474|3474|151|4.3%|0.0%|
[shunlist](#shunlist)|1243|1243|114|9.1%|0.0%|
[nixspam](#nixspam)|16664|16664|113|0.6%|0.0%|
[et_compromised](#et_compromised)|1721|1721|109|6.3%|0.0%|
[feodo](#feodo)|105|105|104|99.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6759|6759|79|1.1%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1705|1705|73|4.2%|0.0%|
[openbl_7d](#openbl_7d)|669|669|61|9.1%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|2888|2888|56|1.9%|0.0%|
[sslbl](#sslbl)|371|371|38|10.2%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|30|2.3%|0.0%|
[php_commenters](#php_commenters)|430|430|29|6.7%|0.0%|
[sorbs_spam](#sorbs_spam)|62018|62766|22|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|62018|62766|22|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|62018|62766|22|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|16274|16274|21|0.1%|0.0%|
[voipbl](#voipbl)|10533|10945|14|0.1%|0.0%|
[openbl_1d](#openbl_1d)|144|144|14|9.7%|0.0%|
[palevo](#palevo)|13|13|13|100.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14166|14166|13|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|183|183|10|5.4%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|1997|1997|10|0.5%|0.0%|
[php_dictionary](#php_dictionary)|702|702|6|0.8%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|6|0.4%|0.0%|
[firehol_anonymous](#firehol_anonymous)|18924|82965|6|0.0%|0.0%|
[ciarmy](#ciarmy)|442|442|6|1.3%|0.0%|
[malc0de](#malc0de)|313|313|5|1.5%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|5|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2798|2798|5|0.1%|0.0%|
[php_spammers](#php_spammers)|700|700|4|0.5%|0.0%|
[nt_malware_http](#nt_malware_http)|69|69|4|5.7%|0.0%|
[iw_spamlist](#iw_spamlist)|3758|3758|4|0.1%|0.0%|
[nt_malware_irc](#nt_malware_irc)|43|43|3|6.9%|0.0%|
[firehol_proxies](#firehol_proxies)|12475|12745|3|0.0%|0.0%|
[et_tor](#et_tor)|6400|6400|3|0.0%|0.0%|
[dm_tor](#dm_tor)|6424|6424|3|0.0%|0.0%|
[bm_tor](#bm_tor)|6402|6402|3|0.0%|0.0%|
[tor_exits](#tor_exits)|1116|1116|2|0.1%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|2|0.3%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|80|80|2|2.5%|0.0%|
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
[alienvault_reputation](#alienvault_reputation)|184538|184538|4|0.0%|0.7%|
[firehol_level3](#firehol_level3)|109949|9627745|3|0.0%|0.5%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|1|0.0%|0.1%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|1|0.0%|0.1%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|1|0.0%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.1%|
[firehol_level1](#firehol_level1)|5133|688894588|1|0.0%|0.1%|
[et_block](#et_block)|1000|18344011|1|0.0%|0.1%|
[blocklist_de_sip](#blocklist_de_sip)|80|80|1|1.2%|0.1%|

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
[firehol_level3](#firehol_level3)|109949|9627745|1703|0.0%|98.9%|
[bruteforceblocker](#bruteforceblocker)|1705|1705|1656|97.1%|96.2%|
[alienvault_reputation](#alienvault_reputation)|184538|184538|1116|0.6%|64.8%|
[openbl_60d](#openbl_60d)|6997|6997|1012|14.4%|58.8%|
[openbl_30d](#openbl_30d)|2829|2829|946|33.4%|54.9%|
[firehol_level2](#firehol_level2)|20916|32554|619|1.9%|35.9%|
[blocklist_de](#blocklist_de)|27197|27197|618|2.2%|35.9%|
[blocklist_de_ssh](#blocklist_de_ssh)|3474|3474|613|17.6%|35.6%|
[shunlist](#shunlist)|1243|1243|425|34.1%|24.6%|
[openbl_7d](#openbl_7d)|669|669|325|48.5%|18.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|152|0.0%|8.8%|
[et_block](#et_block)|1000|18344011|109|0.0%|6.3%|
[firehol_level1](#firehol_level1)|5133|688894588|107|0.0%|6.2%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|101|0.0%|5.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|85|0.0%|4.9%|
[openbl_1d](#openbl_1d)|144|144|65|45.1%|3.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|52|0.0%|3.0%|
[dshield](#dshield)|20|5120|42|0.8%|2.4%|
[stopforumspam_30d](#stopforumspam_30d)|94424|94424|12|0.0%|0.6%|
[dragon_http](#dragon_http)|1044|273664|11|0.0%|0.6%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|5|0.0%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|5|0.0%|0.2%|
[blocklist_de_mail](#blocklist_de_mail)|16274|16274|4|0.0%|0.2%|
[voipbl](#voipbl)|10533|10945|3|0.0%|0.1%|
[sorbs_spam](#sorbs_spam)|62018|62766|3|0.0%|0.1%|
[sorbs_recent_spam](#sorbs_recent_spam)|62018|62766|3|0.0%|0.1%|
[sorbs_new_spam](#sorbs_new_spam)|62018|62766|3|0.0%|0.1%|
[firehol_proxies](#firehol_proxies)|12475|12745|3|0.0%|0.1%|
[firehol_anonymous](#firehol_anonymous)|18924|82965|3|0.0%|0.1%|
[ciarmy](#ciarmy)|442|442|3|0.6%|0.1%|
[blocklist_de_imap](#blocklist_de_imap)|1997|1997|3|0.1%|0.1%|
[proxz](#proxz)|1265|1265|2|0.1%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|2|0.0%|0.1%|
[xroxy](#xroxy)|2163|2163|1|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6759|6759|1|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7712|7712|1|0.0%|0.0%|
[proxyrss](#proxyrss)|1673|1673|1|0.0%|0.0%|
[php_spammers](#php_spammers)|700|700|1|0.1%|0.0%|
[php_commenters](#php_commenters)|430|430|1|0.2%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|2888|2888|1|0.0%|0.0%|

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
[firehol_anonymous](#firehol_anonymous)|18924|82965|5810|7.0%|90.7%|
[bm_tor](#bm_tor)|6402|6402|5780|90.2%|90.3%|
[dm_tor](#dm_tor)|6424|6424|5765|89.7%|90.0%|
[firehol_level3](#firehol_level3)|109949|9627745|1126|0.0%|17.5%|
[snort_ipfilter](#snort_ipfilter)|9945|9945|1089|10.9%|17.0%|
[tor_exits](#tor_exits)|1116|1116|971|87.0%|15.1%|
[stopforumspam_30d](#stopforumspam_30d)|94424|94424|649|0.6%|10.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|625|0.0%|9.7%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|547|1.8%|8.5%|
[firehol_level2](#firehol_level2)|20916|32554|361|1.1%|5.6%|
[stopforumspam_1d](#stopforumspam_1d)|6759|6759|349|5.1%|5.4%|
[firehol_proxies](#firehol_proxies)|12475|12745|238|1.8%|3.7%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|234|44.6%|3.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|181|0.0%|2.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|165|0.0%|2.5%|
[php_commenters](#php_commenters)|430|430|51|11.8%|0.7%|
[alienvault_reputation](#alienvault_reputation)|184538|184538|39|0.0%|0.6%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|22|0.0%|0.3%|
[openbl_60d](#openbl_60d)|6997|6997|20|0.2%|0.3%|
[blocklist_de](#blocklist_de)|27197|27197|18|0.0%|0.2%|
[blocklist_de_apache](#blocklist_de_apache)|14166|14166|17|0.1%|0.2%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2798|2798|15|0.5%|0.2%|
[dragon_http](#dragon_http)|1044|273664|11|0.0%|0.1%|
[php_harvesters](#php_harvesters)|392|392|7|1.7%|0.1%|
[php_spammers](#php_spammers)|700|700|5|0.7%|0.0%|
[nixspam](#nixspam)|16664|16664|5|0.0%|0.0%|
[sorbs_spam](#sorbs_spam)|62018|62766|4|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|62018|62766|4|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|62018|62766|4|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7712|7712|4|0.0%|0.0%|
[php_dictionary](#php_dictionary)|702|702|4|0.5%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|4|0.0%|0.0%|
[voipbl](#voipbl)|10533|10945|3|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|3|0.0%|0.0%|
[firehol_level1](#firehol_level1)|5133|688894588|3|0.0%|0.0%|
[et_block](#et_block)|1000|18344011|3|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|16274|16274|2|0.0%|0.0%|
[xroxy](#xroxy)|2163|2163|1|0.0%|0.0%|
[shunlist](#shunlist)|1243|1243|1|0.0%|0.0%|
[iw_spamlist](#iw_spamlist)|3758|3758|1|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3474|3474|1|0.0%|0.0%|

## feodo

[Abuse.ch Feodo tracker](https://feodotracker.abuse.ch) trojan includes IPs which are being used by Feodo (also known as Cridex or Bugat) which commits ebanking fraud - **excellent list**

Source is downloaded from [this link](https://feodotracker.abuse.ch/blocklist/?download=ipblocklist).

The last time downloaded was found to be dated: Thu Jun 11 07:18:26 UTC 2015.

The ipset `feodo` has **105** entries, **105** unique IPs.

The following table shows the overlaps of `feodo` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `feodo`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `feodo`.
- ` this % ` is the percentage **of this ipset (`feodo`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level1](#firehol_level1)|5133|688894588|105|0.0%|100.0%|
[et_block](#et_block)|1000|18344011|104|0.0%|99.0%|
[snort_ipfilter](#snort_ipfilter)|9945|9945|83|0.8%|79.0%|
[firehol_level3](#firehol_level3)|109949|9627745|83|0.0%|79.0%|
[sslbl](#sslbl)|371|371|38|10.2%|36.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|11|0.0%|10.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|3|0.0%|2.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|3|0.0%|2.8%|
[alienvault_reputation](#alienvault_reputation)|184538|184538|2|0.0%|1.9%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.9%|

## firehol_anonymous

**FireHOL Anonymous** - Known anonymizing IPs. (includes: firehol_proxies anonymous bm_tor dm_tor tor_exits)

Source is downloaded from [this link]().

The last time downloaded was found to be dated: Sun Jun  7 22:20:34 UTC 2015.

The ipset `firehol_anonymous` has **18924** entries, **82965** unique IPs.

The following table shows the overlaps of `firehol_anonymous` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `firehol_anonymous`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `firehol_anonymous`.
- ` this % ` is the percentage **of this ipset (`firehol_anonymous`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_proxies](#firehol_proxies)|12475|12745|12745|100.0%|15.3%|
[ri_web_proxies](#ri_web_proxies)|7712|7712|7712|100.0%|9.2%|
[firehol_level3](#firehol_level3)|109949|9627745|6747|0.0%|8.1%|
[dm_tor](#dm_tor)|6424|6424|6424|100.0%|7.7%|
[bm_tor](#bm_tor)|6402|6402|6402|100.0%|7.7%|
[stopforumspam_30d](#stopforumspam_30d)|94424|94424|6167|6.5%|7.4%|
[et_tor](#et_tor)|6400|6400|5810|90.7%|7.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|3436|0.0%|4.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|2893|0.0%|3.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|2876|0.0%|3.4%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|2823|9.6%|3.4%|
[ri_connect_proxies](#ri_connect_proxies)|2784|2784|2784|100.0%|3.3%|
[xroxy](#xroxy)|2163|2163|2163|100.0%|2.6%|
[proxyrss](#proxyrss)|1673|1673|1673|100.0%|2.0%|
[firehol_level2](#firehol_level2)|20916|32554|1438|4.4%|1.7%|
[proxz](#proxz)|1265|1265|1265|100.0%|1.5%|
[snort_ipfilter](#snort_ipfilter)|9945|9945|1242|12.4%|1.4%|
[tor_exits](#tor_exits)|1116|1116|1116|100.0%|1.3%|
[stopforumspam_1d](#stopforumspam_1d)|6759|6759|1081|15.9%|1.3%|
[blocklist_de](#blocklist_de)|27197|27197|665|2.4%|0.8%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|663|100.0%|0.7%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|524|100.0%|0.6%|
[blocklist_de_bots](#blocklist_de_bots)|2888|2888|513|17.7%|0.6%|
[sorbs_spam](#sorbs_spam)|62018|62766|194|0.3%|0.2%|
[sorbs_recent_spam](#sorbs_recent_spam)|62018|62766|194|0.3%|0.2%|
[sorbs_new_spam](#sorbs_new_spam)|62018|62766|194|0.3%|0.2%|
[nixspam](#nixspam)|16664|16664|173|1.0%|0.2%|
[blocklist_de_mail](#blocklist_de_mail)|16274|16274|122|0.7%|0.1%|
[php_dictionary](#php_dictionary)|702|702|95|13.5%|0.1%|
[php_commenters](#php_commenters)|430|430|82|19.0%|0.0%|
[voipbl](#voipbl)|10533|10945|79|0.7%|0.0%|
[php_spammers](#php_spammers)|700|700|79|11.2%|0.0%|
[alienvault_reputation](#alienvault_reputation)|184538|184538|57|0.0%|0.0%|
[dragon_http](#dragon_http)|1044|273664|41|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|29|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14166|14166|27|0.1%|0.0%|
[sorbs_web](#sorbs_web)|482|483|25|5.1%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2798|2798|24|0.8%|0.0%|
[openbl_60d](#openbl_60d)|6997|6997|23|0.3%|0.0%|
[iw_spamlist](#iw_spamlist)|3758|3758|15|0.3%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|15|0.0%|0.0%|
[php_harvesters](#php_harvesters)|392|392|12|3.0%|0.0%|
[firehol_level1](#firehol_level1)|5133|688894588|8|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|183|183|8|4.3%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|7|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|6|0.0%|0.0%|
[et_block](#et_block)|1000|18344011|6|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|3|0.2%|0.0%|
[et_compromised](#et_compromised)|1721|1721|3|0.1%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1705|1705|3|0.1%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3474|3474|2|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|1425|1425|2|0.1%|0.0%|
[sslbl](#sslbl)|371|371|1|0.2%|0.0%|
[shunlist](#shunlist)|1243|1243|1|0.0%|0.0%|
[openbl_30d](#openbl_30d)|2829|2829|1|0.0%|0.0%|
[dshield](#dshield)|20|5120|1|0.0%|0.0%|

## firehol_level1

**FireHOL Level 1** - Maximum protection without false positives. (includes: fullbogons dshield feodo palevo sslbl zeus spamhaus_drop spamhaus_edrop)

Source is downloaded from [this link]().

The last time downloaded was found to be dated: Sun Jun  7 22:15:43 UTC 2015.

The ipset `firehol_level1` has **5133** entries, **688894588** unique IPs.

The following table shows the overlaps of `firehol_level1` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `firehol_level1`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `firehol_level1`.
- ` this % ` is the percentage **of this ipset (`firehol_level1`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[fullbogons](#fullbogons)|3770|670213096|670213096|100.0%|97.2%|
[bogons](#bogons)|13|592708608|592708608|100.0%|86.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|18340608|100.0%|2.6%|
[et_block](#et_block)|1000|18344011|18340170|99.9%|2.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|8867973|2.5%|1.2%|
[firehol_level3](#firehol_level3)|109949|9627745|7500206|77.9%|1.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|7498240|81.6%|1.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|4637602|3.3%|0.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|2570539|0.3%|0.3%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|487424|100.0%|0.0%|
[dshield](#dshield)|20|5120|5120|100.0%|0.0%|
[alienvault_reputation](#alienvault_reputation)|184538|184538|4584|2.4%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1932|0.5%|0.0%|
[dragon_http](#dragon_http)|1044|273664|1281|0.4%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|94424|94424|1100|1.1%|0.0%|
[sslbl](#sslbl)|371|371|371|100.0%|0.0%|
[voipbl](#voipbl)|10533|10945|333|3.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9945|9945|301|3.0%|0.0%|
[firehol_level2](#firehol_level2)|20916|32554|300|0.9%|0.0%|
[openbl_60d](#openbl_60d)|6997|6997|287|4.1%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|278|0.9%|0.0%|
[blocklist_de](#blocklist_de)|27197|27197|237|0.8%|0.0%|
[zeus](#zeus)|230|230|230|100.0%|0.0%|
[zeus_badips](#zeus_badips)|202|202|202|100.0%|0.0%|
[shunlist](#shunlist)|1243|1243|181|14.5%|0.0%|
[openbl_30d](#openbl_30d)|2829|2829|161|5.6%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3474|3474|147|4.2%|0.0%|
[nixspam](#nixspam)|16664|16664|113|0.6%|0.0%|
[et_compromised](#et_compromised)|1721|1721|107|6.2%|0.0%|
[feodo](#feodo)|105|105|105|100.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6759|6759|82|1.2%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1705|1705|71|4.1%|0.0%|
[openbl_7d](#openbl_7d)|669|669|63|9.4%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|2888|2888|60|2.0%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|39|3.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|39|2.6%|0.0%|
[php_commenters](#php_commenters)|430|430|38|8.8%|0.0%|
[sorbs_spam](#sorbs_spam)|62018|62766|25|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|62018|62766|25|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|62018|62766|25|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|16274|16274|21|0.1%|0.0%|
[openbl_1d](#openbl_1d)|144|144|20|13.8%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|183|183|19|10.3%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|18|0.0%|0.0%|
[palevo](#palevo)|13|13|13|100.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|1997|1997|10|0.5%|0.0%|
[iw_spamlist](#iw_spamlist)|3758|3758|9|0.2%|0.0%|
[nt_malware_http](#nt_malware_http)|69|69|8|11.5%|0.0%|
[firehol_anonymous](#firehol_anonymous)|18924|82965|8|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14166|14166|8|0.0%|0.0%|
[malc0de](#malc0de)|313|313|7|2.2%|0.0%|
[php_dictionary](#php_dictionary)|702|702|6|0.8%|0.0%|
[firehol_proxies](#firehol_proxies)|12475|12745|5|0.0%|0.0%|
[ciarmy](#ciarmy)|442|442|5|1.1%|0.0%|
[php_spammers](#php_spammers)|700|700|4|0.5%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2798|2798|4|0.1%|0.0%|
[php_harvesters](#php_harvesters)|392|392|3|0.7%|0.0%|
[nt_malware_irc](#nt_malware_irc)|43|43|3|6.9%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|3|0.4%|0.0%|
[et_tor](#et_tor)|6400|6400|3|0.0%|0.0%|
[dm_tor](#dm_tor)|6424|6424|3|0.0%|0.0%|
[bm_tor](#bm_tor)|6402|6402|3|0.0%|0.0%|
[tor_exits](#tor_exits)|1116|1116|2|0.1%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|80|80|2|2.5%|0.0%|
[virbl](#virbl)|28|28|1|3.5%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7712|7712|1|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|1|0.1%|0.0%|
[et_botcc](#et_botcc)|506|506|1|0.1%|0.0%|

## firehol_level2

**FireHOL Level 2** - Maximum protection from attacks took place in the last 48 hours. (includes: openbl_1d blocklist_de stopforumspam_1d)

Source is downloaded from [this link]().

The last time downloaded was found to be dated: Sun Jun  7 22:20:34 UTC 2015.

The ipset `firehol_level2` has **20916** entries, **32554** unique IPs.

The following table shows the overlaps of `firehol_level2` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `firehol_level2`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `firehol_level2`.
- ` this % ` is the percentage **of this ipset (`firehol_level2`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|27197|27197|27197|100.0%|83.5%|
[blocklist_de_mail](#blocklist_de_mail)|16274|16274|16223|99.6%|49.8%|
[blocklist_de_apache](#blocklist_de_apache)|14166|14166|14163|99.9%|43.5%|
[firehol_level3](#firehol_level3)|109949|9627745|7491|0.0%|23.0%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|7037|24.1%|21.6%|
[stopforumspam_1d](#stopforumspam_1d)|6759|6759|6759|100.0%|20.7%|
[stopforumspam_30d](#stopforumspam_30d)|94424|94424|6238|6.6%|19.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|3895|0.0%|11.9%|
[blocklist_de_ssh](#blocklist_de_ssh)|3474|3474|3470|99.8%|10.6%|
[blocklist_de_bots](#blocklist_de_bots)|2888|2888|2877|99.6%|8.8%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2798|2798|2798|100.0%|8.5%|
[blocklist_de_imap](#blocklist_de_imap)|1997|1997|1997|100.0%|6.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|1690|0.0%|5.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|1687|0.0%|5.1%|
[firehol_anonymous](#firehol_anonymous)|18924|82965|1438|1.7%|4.4%|
[blocklist_de_ftp](#blocklist_de_ftp)|1425|1425|1425|100.0%|4.3%|
[alienvault_reputation](#alienvault_reputation)|184538|184538|1362|0.7%|4.1%|
[sorbs_spam](#sorbs_spam)|62018|62766|1255|1.9%|3.8%|
[sorbs_recent_spam](#sorbs_recent_spam)|62018|62766|1255|1.9%|3.8%|
[sorbs_new_spam](#sorbs_new_spam)|62018|62766|1255|1.9%|3.8%|
[firehol_proxies](#firehol_proxies)|12475|12745|1254|9.8%|3.8%|
[openbl_60d](#openbl_60d)|6997|6997|964|13.7%|2.9%|
[openbl_30d](#openbl_30d)|2829|2829|760|26.8%|2.3%|
[ri_web_proxies](#ri_web_proxies)|7712|7712|692|8.9%|2.1%|
[et_compromised](#et_compromised)|1721|1721|619|35.9%|1.9%|
[bruteforceblocker](#bruteforceblocker)|1705|1705|613|35.9%|1.8%|
[snort_ipfilter](#snort_ipfilter)|9945|9945|575|5.7%|1.7%|
[nixspam](#nixspam)|16664|16664|512|3.0%|1.5%|
[proxyrss](#proxyrss)|1673|1673|457|27.3%|1.4%|
[shunlist](#shunlist)|1243|1243|424|34.1%|1.3%|
[openbl_7d](#openbl_7d)|669|669|416|62.1%|1.2%|
[tor_exits](#tor_exits)|1116|1116|370|33.1%|1.1%|
[et_tor](#et_tor)|6400|6400|361|5.6%|1.1%|
[bm_tor](#bm_tor)|6402|6402|357|5.5%|1.0%|
[dm_tor](#dm_tor)|6424|6424|356|5.5%|1.0%|
[xroxy](#xroxy)|2163|2163|344|15.9%|1.0%|
[et_block](#et_block)|1000|18344011|303|0.0%|0.9%|
[firehol_level1](#firehol_level1)|5133|688894588|300|0.0%|0.9%|
[proxz](#proxz)|1265|1265|277|21.8%|0.8%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|274|0.0%|0.8%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|218|41.6%|0.6%|
[php_commenters](#php_commenters)|430|430|189|43.9%|0.5%|
[blocklist_de_strongips](#blocklist_de_strongips)|183|183|183|100.0%|0.5%|
[ri_connect_proxies](#ri_connect_proxies)|2784|2784|166|5.9%|0.5%|
[openbl_1d](#openbl_1d)|144|144|144|100.0%|0.4%|
[iw_spamlist](#iw_spamlist)|3758|3758|122|3.2%|0.3%|
[php_dictionary](#php_dictionary)|702|702|118|16.8%|0.3%|
[php_spammers](#php_spammers)|700|700|114|16.2%|0.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|83|0.0%|0.2%|
[dragon_http](#dragon_http)|1044|273664|64|0.0%|0.1%|
[blocklist_de_sip](#blocklist_de_sip)|80|80|61|76.2%|0.1%|
[sorbs_web](#sorbs_web)|482|483|59|12.2%|0.1%|
[php_harvesters](#php_harvesters)|392|392|56|14.2%|0.1%|
[dshield](#dshield)|20|5120|54|1.0%|0.1%|
[ciarmy](#ciarmy)|442|442|44|9.9%|0.1%|
[voipbl](#voipbl)|10533|10945|35|0.3%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|20|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|13|0.0%|0.0%|
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

The ipset `firehol_level3` has **109949** entries, **9627745** unique IPs.

The following table shows the overlaps of `firehol_level3` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `firehol_level3`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `firehol_level3`.
- ` this % ` is the percentage **of this ipset (`firehol_level3`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|9177856|100.0%|95.3%|
[firehol_level1](#firehol_level1)|5133|688894588|7500206|1.0%|77.9%|
[et_block](#et_block)|1000|18344011|6933378|37.7%|72.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|6933037|37.8%|72.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|2537303|0.7%|26.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|919963|0.1%|9.5%|
[fullbogons](#fullbogons)|3770|670213096|566693|0.0%|5.8%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|339173|100.0%|3.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|161583|0.1%|1.6%|
[stopforumspam_30d](#stopforumspam_30d)|94424|94424|94424|100.0%|0.9%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|27875|95.5%|0.2%|
[snort_ipfilter](#snort_ipfilter)|9945|9945|9945|100.0%|0.1%|
[firehol_level2](#firehol_level2)|20916|32554|7491|23.0%|0.0%|
[firehol_anonymous](#firehol_anonymous)|18924|82965|6747|8.1%|0.0%|
[firehol_proxies](#firehol_proxies)|12475|12745|5623|44.1%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6759|6759|4891|72.3%|0.0%|
[alienvault_reputation](#alienvault_reputation)|184538|184538|4871|2.6%|0.0%|
[blocklist_de](#blocklist_de)|27197|27197|3819|14.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7712|7712|3671|47.6%|0.0%|
[openbl_60d](#openbl_60d)|6997|6997|2957|42.2%|0.0%|
[openbl_30d](#openbl_30d)|2829|2829|2829|100.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|2888|2888|2263|78.3%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1705|1705|1705|100.0%|0.0%|
[et_compromised](#et_compromised)|1721|1721|1703|98.9%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2784|2784|1559|55.9%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|1450|100.0%|0.0%|
[xroxy](#xroxy)|2163|2163|1292|59.7%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|1288|100.0%|0.0%|
[sorbs_spam](#sorbs_spam)|62018|62766|1259|2.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|62018|62766|1259|2.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|62018|62766|1259|2.0%|0.0%|
[shunlist](#shunlist)|1243|1243|1243|100.0%|0.0%|
[et_tor](#et_tor)|6400|6400|1126|17.5%|0.0%|
[bm_tor](#bm_tor)|6402|6402|1097|17.1%|0.0%|
[dm_tor](#dm_tor)|6424|6424|1095|17.0%|0.0%|
[tor_exits](#tor_exits)|1116|1116|1083|97.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3474|3474|959|27.6%|0.0%|
[proxyrss](#proxyrss)|1673|1673|766|45.7%|0.0%|
[proxz](#proxz)|1265|1265|745|58.8%|0.0%|
[php_dictionary](#php_dictionary)|702|702|702|100.0%|0.0%|
[php_spammers](#php_spammers)|700|700|700|100.0%|0.0%|
[openbl_7d](#openbl_7d)|669|669|669|100.0%|0.0%|
[dragon_http](#dragon_http)|1044|273664|567|0.2%|0.0%|
[nixspam](#nixspam)|16664|16664|484|2.9%|0.0%|
[ciarmy](#ciarmy)|442|442|442|100.0%|0.0%|
[php_commenters](#php_commenters)|430|430|430|100.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|16274|16274|409|2.5%|0.0%|
[php_harvesters](#php_harvesters)|392|392|392|100.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|343|65.4%|0.0%|
[malc0de](#malc0de)|313|313|313|100.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14166|14166|303|2.1%|0.0%|
[zeus](#zeus)|230|230|203|88.2%|0.0%|
[zeus_badips](#zeus_badips)|202|202|180|89.1%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|183|183|164|89.6%|0.0%|
[openbl_1d](#openbl_1d)|144|144|142|98.6%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2798|2798|99|3.5%|0.0%|
[iw_spamlist](#iw_spamlist)|3758|3758|98|2.6%|0.0%|
[sslbl](#sslbl)|371|371|92|24.7%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|88|0.0%|0.0%|
[dshield](#dshield)|20|5120|88|1.7%|0.0%|
[feodo](#feodo)|105|105|83|79.0%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|65|65|65|100.0%|0.0%|
[sorbs_web](#sorbs_web)|482|483|62|12.8%|0.0%|
[voipbl](#voipbl)|10533|10945|57|0.5%|0.0%|
[iw_wormlist](#iw_wormlist)|33|33|33|100.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|1997|1997|33|1.6%|0.0%|
[virbl](#virbl)|28|28|28|100.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|1425|1425|28|1.9%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|24|3.6%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|24|0.0%|0.0%|
[palevo](#palevo)|13|13|11|84.6%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|80|80|4|5.0%|0.0%|
[nt_malware_http](#nt_malware_http)|69|69|3|4.3%|0.0%|
[et_botcc](#et_botcc)|506|506|3|0.5%|0.0%|
[bogons](#bogons)|13|592708608|3|0.0%|0.0%|
[sorbs_socks](#sorbs_socks)|5|5|1|20.0%|0.0%|
[sorbs_misc](#sorbs_misc)|5|5|1|20.0%|0.0%|
[sorbs_http](#sorbs_http)|5|5|1|20.0%|0.0%|
[nt_malware_irc](#nt_malware_irc)|43|43|1|2.3%|0.0%|

## firehol_proxies

**FireHOL Proxies** - Known open proxies in the last 30 days. (includes: ib_bluetack_proxies maxmind_proxy_fraud proxyrss proxz ri_connect_proxies ri_web_proxies xroxy)

Source is downloaded from [this link]().

The last time downloaded was found to be dated: Sun Jun  7 22:20:34 UTC 2015.

The ipset `firehol_proxies` has **12475** entries, **12745** unique IPs.

The following table shows the overlaps of `firehol_proxies` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `firehol_proxies`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `firehol_proxies`.
- ` this % ` is the percentage **of this ipset (`firehol_proxies`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_anonymous](#firehol_anonymous)|18924|82965|12745|15.3%|100.0%|
[ri_web_proxies](#ri_web_proxies)|7712|7712|7712|100.0%|60.5%|
[firehol_level3](#firehol_level3)|109949|9627745|5623|0.0%|44.1%|
[stopforumspam_30d](#stopforumspam_30d)|94424|94424|5561|5.8%|43.6%|
[ri_connect_proxies](#ri_connect_proxies)|2784|2784|2784|100.0%|21.8%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|2448|8.3%|19.2%|
[xroxy](#xroxy)|2163|2163|2163|100.0%|16.9%|
[proxyrss](#proxyrss)|1673|1673|1673|100.0%|13.1%|
[proxz](#proxz)|1265|1265|1265|100.0%|9.9%|
[firehol_level2](#firehol_level2)|20916|32554|1254|3.8%|9.8%|
[stopforumspam_1d](#stopforumspam_1d)|6759|6759|912|13.4%|7.1%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|663|100.0%|5.2%|
[blocklist_de](#blocklist_de)|27197|27197|637|2.3%|4.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|528|0.0%|4.1%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|524|100.0%|4.1%|
[blocklist_de_bots](#blocklist_de_bots)|2888|2888|512|17.7%|4.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|391|0.0%|3.0%|
[snort_ipfilter](#snort_ipfilter)|9945|9945|325|3.2%|2.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|286|0.0%|2.2%|
[et_tor](#et_tor)|6400|6400|238|3.7%|1.8%|
[dm_tor](#dm_tor)|6424|6424|238|3.7%|1.8%|
[bm_tor](#bm_tor)|6402|6402|238|3.7%|1.8%|
[tor_exits](#tor_exits)|1116|1116|231|20.6%|1.8%|
[sorbs_spam](#sorbs_spam)|62018|62766|189|0.3%|1.4%|
[sorbs_recent_spam](#sorbs_recent_spam)|62018|62766|189|0.3%|1.4%|
[sorbs_new_spam](#sorbs_new_spam)|62018|62766|189|0.3%|1.4%|
[nixspam](#nixspam)|16664|16664|167|1.0%|1.3%|
[blocklist_de_mail](#blocklist_de_mail)|16274|16274|120|0.7%|0.9%|
[php_dictionary](#php_dictionary)|702|702|94|13.3%|0.7%|
[php_commenters](#php_commenters)|430|430|80|18.6%|0.6%|
[php_spammers](#php_spammers)|700|700|77|11.0%|0.6%|
[alienvault_reputation](#alienvault_reputation)|184538|184538|38|0.0%|0.2%|
[dragon_http](#dragon_http)|1044|273664|31|0.0%|0.2%|
[sorbs_web](#sorbs_web)|482|483|25|5.1%|0.1%|
[openbl_60d](#openbl_60d)|6997|6997|20|0.2%|0.1%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|15|0.0%|0.1%|
[iw_spamlist](#iw_spamlist)|3758|3758|14|0.3%|0.1%|
[php_harvesters](#php_harvesters)|392|392|12|3.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|11|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|183|183|8|4.3%|0.0%|
[firehol_level1](#firehol_level1)|5133|688894588|5|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|3|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|3|0.2%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|0.0%|
[et_compromised](#et_compromised)|1721|1721|3|0.1%|0.0%|
[et_block](#et_block)|1000|18344011|3|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1705|1705|3|0.1%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14166|14166|3|0.0%|0.0%|
[voipbl](#voipbl)|10533|10945|2|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2798|2798|2|0.0%|0.0%|
[sslbl](#sslbl)|371|371|1|0.2%|0.0%|
[shunlist](#shunlist)|1243|1243|1|0.0%|0.0%|
[dshield](#dshield)|20|5120|1|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3474|3474|1|0.0%|0.0%|

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
[firehol_level1](#firehol_level1)|5133|688894588|670213096|97.2%|100.0%|
[bogons](#bogons)|13|592708608|592708608|100.0%|88.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|4236143|3.0%|0.6%|
[firehol_level3](#firehol_level3)|109949|9627745|566693|5.8%|0.0%|
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
[iw_spamlist](#iw_spamlist)|3758|3758|5|0.1%|0.0%|
[nt_malware_http](#nt_malware_http)|69|69|4|5.7%|0.0%|
[virbl](#virbl)|28|28|1|3.5%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|1|0.0%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|94424|94424|1|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6759|6759|1|0.0%|0.0%|
[php_harvesters](#php_harvesters)|392|392|1|0.2%|0.0%|
[php_commenters](#php_commenters)|430|430|1|0.2%|0.0%|
[firehol_level2](#firehol_level2)|20916|32554|1|0.0%|0.0%|
[ciarmy](#ciarmy)|442|442|1|0.2%|0.0%|

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
[firehol_level3](#firehol_level3)|109949|9627745|24|0.0%|0.0%|
[dragon_http](#dragon_http)|1044|273664|24|0.0%|0.0%|
[firehol_level1](#firehol_level1)|5133|688894588|18|0.0%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|94424|94424|16|0.0%|0.0%|
[sorbs_spam](#sorbs_spam)|62018|62766|15|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|62018|62766|15|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|62018|62766|15|0.0%|0.0%|
[firehol_proxies](#firehol_proxies)|12475|12745|15|0.1%|0.0%|
[firehol_anonymous](#firehol_anonymous)|18924|82965|15|0.0%|0.0%|
[alienvault_reputation](#alienvault_reputation)|184538|184538|15|0.0%|0.0%|
[fullbogons](#fullbogons)|3770|670213096|13|0.0%|0.0%|
[firehol_level2](#firehol_level2)|20916|32554|13|0.0%|0.0%|
[blocklist_de](#blocklist_de)|27197|27197|12|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|11|1.6%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|7|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|16274|16274|6|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|5|0.0%|0.0%|
[nixspam](#nixspam)|16664|16664|5|0.0%|0.0%|
[et_block](#et_block)|1000|18344011|5|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7712|7712|4|0.0%|0.0%|
[xroxy](#xroxy)|2163|2163|3|0.1%|0.0%|
[php_dictionary](#php_dictionary)|702|702|3|0.4%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|3|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|1425|1425|3|0.2%|0.0%|
[voipbl](#voipbl)|10533|10945|2|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6759|6759|2|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9945|9945|2|0.0%|0.0%|
[php_harvesters](#php_harvesters)|392|392|2|0.5%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|1997|1997|2|0.1%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2798|2798|2|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14166|14166|2|0.0%|0.0%|
[sorbs_web](#sorbs_web)|482|483|1|0.2%|0.0%|
[proxz](#proxz)|1265|1265|1|0.0%|0.0%|
[php_spammers](#php_spammers)|700|700|1|0.1%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|1|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3474|3474|1|0.0%|0.0%|

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
[firehol_level3](#firehol_level3)|109949|9627745|9177856|95.3%|100.0%|
[firehol_level1](#firehol_level1)|5133|688894588|7498240|1.0%|81.6%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|6932480|37.7%|75.5%|
[et_block](#et_block)|1000|18344011|6932480|37.7%|75.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|2526625|0.7%|27.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|904796|0.1%|9.8%|
[fullbogons](#fullbogons)|3770|670213096|565760|0.0%|6.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|145472|0.1%|1.5%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1036|0.3%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|94424|94424|731|0.7%|0.0%|
[alienvault_reputation](#alienvault_reputation)|184538|184538|265|0.1%|0.0%|
[dragon_http](#dragon_http)|1044|273664|256|0.0%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|147|0.5%|0.0%|
[nixspam](#nixspam)|16664|16664|113|0.6%|0.0%|
[firehol_level2](#firehol_level2)|20916|32554|83|0.2%|0.0%|
[blocklist_de](#blocklist_de)|27197|27197|64|0.2%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|2888|2888|54|1.8%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|27|2.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6759|6759|26|0.3%|0.0%|
[openbl_60d](#openbl_60d)|6997|6997|16|0.2%|0.0%|
[openbl_30d](#openbl_30d)|2829|2829|12|0.4%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9945|9945|11|0.1%|0.0%|
[zeus_badips](#zeus_badips)|202|202|10|4.9%|0.0%|
[zeus](#zeus)|230|230|10|4.3%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|7|0.4%|0.0%|
[firehol_anonymous](#firehol_anonymous)|18924|82965|7|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3474|3474|6|0.1%|0.0%|
[openbl_7d](#openbl_7d)|669|669|5|0.7%|0.0%|
[et_compromised](#et_compromised)|1721|1721|5|0.2%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1705|1705|5|0.2%|0.0%|
[php_dictionary](#php_dictionary)|702|702|4|0.5%|0.0%|
[et_tor](#et_tor)|6400|6400|4|0.0%|0.0%|
[dm_tor](#dm_tor)|6424|6424|4|0.0%|0.0%|
[bm_tor](#bm_tor)|6402|6402|4|0.0%|0.0%|
[shunlist](#shunlist)|1243|1243|3|0.2%|0.0%|
[php_spammers](#php_spammers)|700|700|3|0.4%|0.0%|
[nt_malware_http](#nt_malware_http)|69|69|3|4.3%|0.0%|
[iw_spamlist](#iw_spamlist)|3758|3758|3|0.0%|0.0%|
[firehol_proxies](#firehol_proxies)|12475|12745|3|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|183|183|3|1.6%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|16274|16274|3|0.0%|0.0%|
[tor_exits](#tor_exits)|1116|1116|2|0.1%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|2|0.3%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|1997|1997|2|0.1%|0.0%|
[voipbl](#voipbl)|10533|10945|1|0.0%|0.0%|
[sorbs_spam](#sorbs_spam)|62018|62766|1|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|62018|62766|1|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|62018|62766|1|0.0%|0.0%|
[php_harvesters](#php_harvesters)|392|392|1|0.2%|0.0%|
[php_commenters](#php_commenters)|430|430|1|0.2%|0.0%|
[nt_malware_irc](#nt_malware_irc)|43|43|1|2.3%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|1|0.1%|0.0%|
[et_botcc](#et_botcc)|506|506|1|0.1%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|1425|1425|1|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2798|2798|1|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14166|14166|1|0.0%|0.0%|

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
[firehol_level1](#firehol_level1)|5133|688894588|2570539|0.3%|0.3%|
[et_block](#et_block)|1000|18344011|2272548|12.3%|0.2%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|2272265|12.3%|0.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|1354507|0.9%|0.1%|
[firehol_level3](#firehol_level3)|109949|9627745|919963|9.5%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|904796|9.8%|0.1%|
[fullbogons](#fullbogons)|3770|670213096|264841|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|33155|6.8%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|13247|3.9%|0.0%|
[dragon_http](#dragon_http)|1044|273664|7370|2.6%|0.0%|
[alienvault_reputation](#alienvault_reputation)|184538|184538|4448|2.4%|0.0%|
[firehol_anonymous](#firehol_anonymous)|18924|82965|3436|4.1%|0.0%|
[firehol_level2](#firehol_level2)|20916|32554|1690|5.1%|0.0%|
[blocklist_de](#blocklist_de)|27197|27197|1568|5.7%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|94424|94424|1516|1.6%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|16274|16274|1404|8.6%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14166|14166|1319|9.3%|0.0%|
[sorbs_spam](#sorbs_spam)|62018|62766|1173|1.8%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|62018|62766|1173|1.8%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|62018|62766|1173|1.8%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|506|1.7%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|394|0.8%|0.0%|
[nixspam](#nixspam)|16664|16664|335|2.0%|0.0%|
[voipbl](#voipbl)|10533|10945|299|2.7%|0.0%|
[firehol_proxies](#firehol_proxies)|12475|12745|286|2.2%|0.0%|
[dshield](#dshield)|20|5120|265|5.1%|0.0%|
[bm_tor](#bm_tor)|6402|6402|167|2.6%|0.0%|
[dm_tor](#dm_tor)|6424|6424|166|2.5%|0.0%|
[et_tor](#et_tor)|6400|6400|165|2.5%|0.0%|
[openbl_60d](#openbl_60d)|6997|6997|164|2.3%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7712|7712|154|1.9%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6759|6759|144|2.1%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9945|9945|114|1.1%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|97|6.6%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2784|2784|84|3.0%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|66|5.1%|0.0%|
[openbl_30d](#openbl_30d)|2829|2829|65|2.2%|0.0%|
[iw_spamlist](#iw_spamlist)|3758|3758|62|1.6%|0.0%|
[xroxy](#xroxy)|2163|2163|58|2.6%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3474|3474|57|1.6%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|1997|1997|57|2.8%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|56|8.4%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1705|1705|54|3.1%|0.0%|
[et_compromised](#et_compromised)|1721|1721|52|3.0%|0.0%|
[proxz](#proxz)|1265|1265|43|3.3%|0.0%|
[et_botcc](#et_botcc)|506|506|40|7.9%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|2888|2888|40|1.3%|0.0%|
[tor_exits](#tor_exits)|1116|1116|37|3.3%|0.0%|
[ciarmy](#ciarmy)|442|442|36|8.1%|0.0%|
[proxyrss](#proxyrss)|1673|1673|31|1.8%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2798|2798|30|1.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|1425|1425|26|1.8%|0.0%|
[shunlist](#shunlist)|1243|1243|25|2.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|21|4.0%|0.0%|
[openbl_7d](#openbl_7d)|669|669|16|2.3%|0.0%|
[sorbs_web](#sorbs_web)|482|483|12|2.4%|0.0%|
[php_harvesters](#php_harvesters)|392|392|12|3.0%|0.0%|
[php_dictionary](#php_dictionary)|702|702|12|1.7%|0.0%|
[malc0de](#malc0de)|313|313|11|3.5%|0.0%|
[php_spammers](#php_spammers)|700|700|10|1.4%|0.0%|
[php_commenters](#php_commenters)|430|430|10|2.3%|0.0%|
[zeus](#zeus)|230|230|7|3.0%|0.0%|
[nt_malware_http](#nt_malware_http)|69|69|7|10.1%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|80|80|6|7.5%|0.0%|
[nt_malware_irc](#nt_malware_irc)|43|43|5|11.6%|0.0%|
[bogons](#bogons)|13|592708608|5|0.0%|0.0%|
[zeus_badips](#zeus_badips)|202|202|4|1.9%|0.0%|
[sslbl](#sslbl)|371|371|3|0.8%|0.0%|
[openbl_1d](#openbl_1d)|144|144|3|2.0%|0.0%|
[feodo](#feodo)|105|105|3|2.8%|0.0%|
[virbl](#virbl)|28|28|2|7.1%|0.0%|
[iw_wormlist](#iw_wormlist)|33|33|1|3.0%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|65|65|1|1.5%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|183|183|1|0.5%|0.0%|

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
[firehol_level1](#firehol_level1)|5133|688894588|8867973|1.2%|2.5%|
[et_block](#et_block)|1000|18344011|8532520|46.5%|2.4%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|8532506|46.5%|2.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|2830203|2.0%|0.8%|
[firehol_level3](#firehol_level3)|109949|9627745|2537303|26.3%|0.7%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2526625|27.5%|0.7%|
[fullbogons](#fullbogons)|3770|670213096|252415|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|98904|20.2%|0.0%|
[dragon_http](#dragon_http)|1044|273664|12216|4.4%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|7728|2.2%|0.0%|
[alienvault_reputation](#alienvault_reputation)|184538|184538|6489|3.5%|0.0%|
[firehol_anonymous](#firehol_anonymous)|18924|82965|2893|3.4%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|94424|94424|2508|2.6%|0.0%|
[firehol_level2](#firehol_level2)|20916|32554|1687|5.1%|0.0%|
[sorbs_spam](#sorbs_spam)|62018|62766|1669|2.6%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|62018|62766|1669|2.6%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|62018|62766|1669|2.6%|0.0%|
[blocklist_de](#blocklist_de)|27197|27197|1546|5.6%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|16274|16274|1252|7.6%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14166|14166|1088|7.6%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|768|2.6%|0.0%|
[dshield](#dshield)|20|5120|512|10.0%|0.0%|
[nixspam](#nixspam)|16664|16664|476|2.8%|0.0%|
[voipbl](#voipbl)|10533|10945|434|3.9%|0.0%|
[firehol_proxies](#firehol_proxies)|12475|12745|391|3.0%|0.0%|
[openbl_60d](#openbl_60d)|6997|6997|319|4.5%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|226|0.4%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7712|7712|222|2.8%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6759|6759|185|2.7%|0.0%|
[dm_tor](#dm_tor)|6424|6424|182|2.8%|0.0%|
[bm_tor](#bm_tor)|6402|6402|182|2.8%|0.0%|
[et_tor](#et_tor)|6400|6400|181|2.8%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9945|9945|147|1.4%|0.0%|
[openbl_30d](#openbl_30d)|2829|2829|147|5.1%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3474|3474|130|3.7%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2784|2784|105|3.7%|0.0%|
[xroxy](#xroxy)|2163|2163|104|4.8%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1705|1705|89|5.2%|0.0%|
[iw_spamlist](#iw_spamlist)|3758|3758|86|2.2%|0.0%|
[et_compromised](#et_compromised)|1721|1721|85|4.9%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|2888|2888|75|2.5%|0.0%|
[shunlist](#shunlist)|1243|1243|69|5.5%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2798|2798|56|2.0%|0.0%|
[php_spammers](#php_spammers)|700|700|54|7.7%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|1997|1997|53|2.6%|0.0%|
[proxz](#proxz)|1265|1265|52|4.1%|0.0%|
[ciarmy](#ciarmy)|442|442|46|10.4%|0.0%|
[proxyrss](#proxyrss)|1673|1673|45|2.6%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|45|3.1%|0.0%|
[openbl_7d](#openbl_7d)|669|669|41|6.1%|0.0%|
[tor_exits](#tor_exits)|1116|1116|38|3.4%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|29|5.5%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|26|2.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|26|3.9%|0.0%|
[php_dictionary](#php_dictionary)|702|702|23|3.2%|0.0%|
[et_botcc](#et_botcc)|506|506|20|3.9%|0.0%|
[php_commenters](#php_commenters)|430|430|18|4.1%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|1425|1425|18|1.2%|0.0%|
[sorbs_web](#sorbs_web)|482|483|16|3.3%|0.0%|
[malc0de](#malc0de)|313|313|16|5.1%|0.0%|
[zeus](#zeus)|230|230|9|3.9%|0.0%|
[php_harvesters](#php_harvesters)|392|392|9|2.2%|0.0%|
[zeus_badips](#zeus_badips)|202|202|8|3.9%|0.0%|
[openbl_1d](#openbl_1d)|144|144|8|5.5%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|183|183|8|4.3%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|80|80|7|8.7%|0.0%|
[sslbl](#sslbl)|371|371|6|1.6%|0.0%|
[palevo](#palevo)|13|13|3|23.0%|0.0%|
[feodo](#feodo)|105|105|3|2.8%|0.0%|
[virbl](#virbl)|28|28|2|7.1%|0.0%|
[nt_malware_irc](#nt_malware_irc)|43|43|2|4.6%|0.0%|
[nt_malware_http](#nt_malware_http)|69|69|2|2.8%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|65|65|1|1.5%|0.0%|

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
[firehol_level1](#firehol_level1)|5133|688894588|4637602|0.6%|3.3%|
[fullbogons](#fullbogons)|3770|670213096|4236143|0.6%|3.0%|
[bogons](#bogons)|13|592708608|4194304|0.7%|3.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|2830203|0.8%|2.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|1354507|0.1%|0.9%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|270785|55.5%|0.1%|
[firehol_level3](#firehol_level3)|109949|9627745|161583|1.6%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|145472|1.5%|0.1%|
[et_block](#et_block)|1000|18344011|130394|0.7%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|130368|0.7%|0.0%|
[dragon_http](#dragon_http)|1044|273664|19712|7.2%|0.0%|
[alienvault_reputation](#alienvault_reputation)|184538|184538|14081|7.6%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|9226|2.7%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|94424|94424|5840|6.1%|0.0%|
[firehol_level2](#firehol_level2)|20916|32554|3895|11.9%|0.0%|
[blocklist_de](#blocklist_de)|27197|27197|3474|12.7%|0.0%|
[firehol_anonymous](#firehol_anonymous)|18924|82965|2876|3.4%|0.0%|
[sorbs_spam](#sorbs_spam)|62018|62766|2642|4.2%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|62018|62766|2642|4.2%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|62018|62766|2642|4.2%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|16274|16274|2431|14.9%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14166|14166|2301|16.2%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|1953|6.6%|0.0%|
[voipbl](#voipbl)|10533|10945|1605|14.6%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|1172|2.4%|0.0%|
[nixspam](#nixspam)|16664|16664|992|5.9%|0.0%|
[openbl_60d](#openbl_60d)|6997|6997|743|10.6%|0.0%|
[bm_tor](#bm_tor)|6402|6402|629|9.8%|0.0%|
[dm_tor](#dm_tor)|6424|6424|627|9.7%|0.0%|
[et_tor](#et_tor)|6400|6400|625|9.7%|0.0%|
[firehol_proxies](#firehol_proxies)|12475|12745|528|4.1%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3474|3474|512|14.7%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6759|6759|511|7.5%|0.0%|
[openbl_30d](#openbl_30d)|2829|2829|293|10.3%|0.0%|
[dshield](#dshield)|20|5120|256|5.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9945|9945|241|2.4%|0.0%|
[iw_spamlist](#iw_spamlist)|3758|3758|240|6.3%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|1997|1997|219|10.9%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7712|7712|218|2.8%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2798|2798|211|7.5%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1705|1705|157|9.2%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|2888|2888|157|5.4%|0.0%|
[et_compromised](#et_compromised)|1721|1721|152|8.8%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|150|28.6%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|147|11.4%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|1425|1425|140|9.8%|0.0%|
[tor_exits](#tor_exits)|1116|1116|128|11.4%|0.0%|
[shunlist](#shunlist)|1243|1243|118|9.4%|0.0%|
[xroxy](#xroxy)|2163|2163|110|5.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|108|7.4%|0.0%|
[proxz](#proxz)|1265|1265|103|8.1%|0.0%|
[ciarmy](#ciarmy)|442|442|98|22.1%|0.0%|
[et_botcc](#et_botcc)|506|506|77|15.2%|0.0%|
[openbl_7d](#openbl_7d)|669|669|76|11.3%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2784|2784|57|2.0%|0.0%|
[proxyrss](#proxyrss)|1673|1673|53|3.1%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|51|7.6%|0.0%|
[malc0de](#malc0de)|313|313|45|14.3%|0.0%|
[php_spammers](#php_spammers)|700|700|43|6.1%|0.0%|
[php_dictionary](#php_dictionary)|702|702|38|5.4%|0.0%|
[sslbl](#sslbl)|371|371|28|7.5%|0.0%|
[php_commenters](#php_commenters)|430|430|28|6.5%|0.0%|
[sorbs_web](#sorbs_web)|482|483|21|4.3%|0.0%|
[php_harvesters](#php_harvesters)|392|392|20|5.1%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|183|183|16|8.7%|0.0%|
[zeus](#zeus)|230|230|14|6.0%|0.0%|
[feodo](#feodo)|105|105|11|10.4%|0.0%|
[zeus_badips](#zeus_badips)|202|202|10|4.9%|0.0%|
[openbl_1d](#openbl_1d)|144|144|10|6.9%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|80|80|10|12.5%|0.0%|
[nt_malware_http](#nt_malware_http)|69|69|5|7.2%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|65|65|5|7.6%|0.0%|
[iw_wormlist](#iw_wormlist)|33|33|2|6.0%|0.0%|
[virbl](#virbl)|28|28|1|3.5%|0.0%|
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
[firehol_proxies](#firehol_proxies)|12475|12745|663|5.2%|100.0%|
[firehol_anonymous](#firehol_anonymous)|18924|82965|663|0.7%|100.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|56|0.0%|8.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|51|0.0%|7.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|26|0.0%|3.9%|
[firehol_level3](#firehol_level3)|109949|9627745|24|0.0%|3.6%|
[stopforumspam_30d](#stopforumspam_30d)|94424|94424|19|0.0%|2.8%|
[ri_web_proxies](#ri_web_proxies)|7712|7712|14|0.1%|2.1%|
[xroxy](#xroxy)|2163|2163|13|0.6%|1.9%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|11|0.0%|1.6%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|11|0.0%|1.6%|
[ri_connect_proxies](#ri_connect_proxies)|2784|2784|7|0.2%|1.0%|
[proxyrss](#proxyrss)|1673|1673|7|0.4%|1.0%|
[firehol_level2](#firehol_level2)|20916|32554|7|0.0%|1.0%|
[proxz](#proxz)|1265|1265|6|0.4%|0.9%|
[stopforumspam_1d](#stopforumspam_1d)|6759|6759|4|0.0%|0.6%|
[blocklist_de](#blocklist_de)|27197|27197|4|0.0%|0.6%|
[firehol_level1](#firehol_level1)|5133|688894588|3|0.0%|0.4%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|2|0.0%|0.3%|
[nixspam](#nixspam)|16664|16664|2|0.0%|0.3%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|2|0.1%|0.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2|0.0%|0.3%|
[et_block](#et_block)|1000|18344011|2|0.0%|0.3%|
[blocklist_de_mail](#blocklist_de_mail)|16274|16274|2|0.0%|0.3%|
[blocklist_de_bots](#blocklist_de_bots)|2888|2888|2|0.0%|0.3%|
[sorbs_spam](#sorbs_spam)|62018|62766|1|0.0%|0.1%|
[sorbs_recent_spam](#sorbs_recent_spam)|62018|62766|1|0.0%|0.1%|
[sorbs_new_spam](#sorbs_new_spam)|62018|62766|1|0.0%|0.1%|
[snort_ipfilter](#snort_ipfilter)|9945|9945|1|0.0%|0.1%|
[php_dictionary](#php_dictionary)|702|702|1|0.1%|0.1%|
[dshield](#dshield)|20|5120|1|0.0%|0.1%|
[dragon_http](#dragon_http)|1044|273664|1|0.0%|0.1%|
[alienvault_reputation](#alienvault_reputation)|184538|184538|1|0.0%|0.1%|

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
[firehol_level3](#firehol_level3)|109949|9627745|339173|3.5%|100.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|13247|0.0%|3.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|9226|0.0%|2.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|7728|0.0%|2.2%|
[firehol_level1](#firehol_level1)|5133|688894588|1932|0.0%|0.5%|
[et_block](#et_block)|1000|18344011|1042|0.0%|0.3%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|1037|0.0%|0.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1036|0.0%|0.3%|
[fullbogons](#fullbogons)|3770|670213096|890|0.0%|0.2%|
[alienvault_reputation](#alienvault_reputation)|184538|184538|288|0.1%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|94424|94424|49|0.0%|0.0%|
[sorbs_spam](#sorbs_spam)|62018|62766|34|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|62018|62766|34|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|62018|62766|34|0.0%|0.0%|
[firehol_anonymous](#firehol_anonymous)|18924|82965|29|0.0%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|27|2.0%|0.0%|
[et_tor](#et_tor)|6400|6400|22|0.3%|0.0%|
[dm_tor](#dm_tor)|6424|6424|22|0.3%|0.0%|
[bm_tor](#bm_tor)|6402|6402|22|0.3%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|20|0.0%|0.0%|
[firehol_level2](#firehol_level2)|20916|32554|20|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|19|1.3%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9945|9945|14|0.1%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6759|6759|12|0.1%|0.0%|
[firehol_proxies](#firehol_proxies)|12475|12745|11|0.0%|0.0%|
[nixspam](#nixspam)|16664|16664|9|0.0%|0.0%|
[tor_exits](#tor_exits)|1116|1116|8|0.7%|0.0%|
[blocklist_de](#blocklist_de)|27197|27197|8|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7712|7712|6|0.0%|0.0%|
[dragon_http](#dragon_http)|1044|273664|6|0.0%|0.0%|
[openbl_60d](#openbl_60d)|6997|6997|5|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|5|0.9%|0.0%|
[voipbl](#voipbl)|10533|10945|4|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14166|14166|4|0.0%|0.0%|
[openbl_30d](#openbl_30d)|2829|2829|3|0.1%|0.0%|
[malc0de](#malc0de)|313|313|3|0.9%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|3|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2798|2798|3|0.1%|0.0%|
[proxyrss](#proxyrss)|1673|1673|2|0.1%|0.0%|
[palevo](#palevo)|13|13|2|15.3%|0.0%|
[iw_spamlist](#iw_spamlist)|3758|3758|2|0.0%|0.0%|
[et_compromised](#et_compromised)|1721|1721|2|0.1%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1705|1705|2|0.1%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|80|80|2|2.5%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|16274|16274|2|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|2888|2888|2|0.0%|0.0%|
[zeus_badips](#zeus_badips)|202|202|1|0.4%|0.0%|
[zeus](#zeus)|230|230|1|0.4%|0.0%|
[xroxy](#xroxy)|2163|2163|1|0.0%|0.0%|
[sslbl](#sslbl)|371|371|1|0.2%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|1|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2784|2784|1|0.0%|0.0%|
[proxz](#proxz)|1265|1265|1|0.0%|0.0%|
[php_harvesters](#php_harvesters)|392|392|1|0.2%|0.0%|
[php_dictionary](#php_dictionary)|702|702|1|0.1%|0.0%|
[php_commenters](#php_commenters)|430|430|1|0.2%|0.0%|
[nt_malware_http](#nt_malware_http)|69|69|1|1.4%|0.0%|
[feodo](#feodo)|105|105|1|0.9%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|65|65|1|1.5%|0.0%|
[bogons](#bogons)|13|592708608|1|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3474|3474|1|0.0%|0.0%|

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
[firehol_level3](#firehol_level3)|109949|9627745|1450|0.0%|100.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|108|0.0%|7.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|97|0.0%|6.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|45|0.0%|3.1%|
[firehol_level1](#firehol_level1)|5133|688894588|39|0.0%|2.6%|
[fullbogons](#fullbogons)|3770|670213096|33|0.0%|2.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|19|0.0%|1.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|7|0.0%|0.4%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|6|0.0%|0.4%|
[et_block](#et_block)|1000|18344011|6|0.0%|0.4%|
[alienvault_reputation](#alienvault_reputation)|184538|184538|6|0.0%|0.4%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|3|0.2%|0.2%|
[firehol_proxies](#firehol_proxies)|12475|12745|3|0.0%|0.2%|
[firehol_level2](#firehol_level2)|20916|32554|3|0.0%|0.2%|
[firehol_anonymous](#firehol_anonymous)|18924|82965|3|0.0%|0.2%|
[dragon_http](#dragon_http)|1044|273664|3|0.0%|0.2%|
[blocklist_de](#blocklist_de)|27197|27197|3|0.0%|0.2%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|2|0.0%|0.1%|
[stopforumspam_30d](#stopforumspam_30d)|94424|94424|2|0.0%|0.1%|
[stopforumspam_1d](#stopforumspam_1d)|6759|6759|2|0.0%|0.1%|
[sorbs_spam](#sorbs_spam)|62018|62766|2|0.0%|0.1%|
[sorbs_recent_spam](#sorbs_recent_spam)|62018|62766|2|0.0%|0.1%|
[sorbs_new_spam](#sorbs_new_spam)|62018|62766|2|0.0%|0.1%|
[openbl_60d](#openbl_60d)|6997|6997|2|0.0%|0.1%|
[openbl_30d](#openbl_30d)|2829|2829|2|0.0%|0.1%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|2|0.3%|0.1%|
[blocklist_de_strongips](#blocklist_de_strongips)|183|183|2|1.0%|0.1%|
[blocklist_de_bots](#blocklist_de_bots)|2888|2888|2|0.0%|0.1%|
[snort_ipfilter](#snort_ipfilter)|9945|9945|1|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7712|7712|1|0.0%|0.0%|
[nixspam](#nixspam)|16664|16664|1|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|1|0.0%|0.0%|
[et_botcc](#et_botcc)|506|506|1|0.1%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3474|3474|1|0.0%|0.0%|

## iw_spamlist

[ImproWare Antispam](http://antispam.imp.ch/) IPs sending spam, in the last 3 days

Source is downloaded from [this link](http://antispam.imp.ch/spamlist).

The last time downloaded was found to be dated: Thu Jun 11 06:20:04 UTC 2015.

The ipset `iw_spamlist` has **3758** entries, **3758** unique IPs.

The following table shows the overlaps of `iw_spamlist` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `iw_spamlist`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `iw_spamlist`.
- ` this % ` is the percentage **of this ipset (`iw_spamlist`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[sorbs_spam](#sorbs_spam)|62018|62766|1179|1.8%|31.3%|
[sorbs_recent_spam](#sorbs_recent_spam)|62018|62766|1179|1.8%|31.3%|
[sorbs_new_spam](#sorbs_new_spam)|62018|62766|1179|1.8%|31.3%|
[nixspam](#nixspam)|16664|16664|491|2.9%|13.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|240|0.0%|6.3%|
[firehol_level2](#firehol_level2)|20916|32554|122|0.3%|3.2%|
[blocklist_de](#blocklist_de)|27197|27197|119|0.4%|3.1%|
[blocklist_de_mail](#blocklist_de_mail)|16274|16274|111|0.6%|2.9%|
[firehol_level3](#firehol_level3)|109949|9627745|98|0.0%|2.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|86|0.0%|2.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|62|0.0%|1.6%|
[snort_ipfilter](#snort_ipfilter)|9945|9945|60|0.6%|1.5%|
[sorbs_web](#sorbs_web)|482|483|27|5.5%|0.7%|
[stopforumspam_30d](#stopforumspam_30d)|94424|94424|20|0.0%|0.5%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|18|0.0%|0.4%|
[firehol_anonymous](#firehol_anonymous)|18924|82965|15|0.0%|0.3%|
[iw_wormlist](#iw_wormlist)|33|33|14|42.4%|0.3%|
[firehol_proxies](#firehol_proxies)|12475|12745|14|0.1%|0.3%|
[alienvault_reputation](#alienvault_reputation)|184538|184538|13|0.0%|0.3%|
[ri_web_proxies](#ri_web_proxies)|7712|7712|12|0.1%|0.3%|
[php_spammers](#php_spammers)|700|700|10|1.4%|0.2%|
[firehol_level1](#firehol_level1)|5133|688894588|9|0.0%|0.2%|
[stopforumspam_1d](#stopforumspam_1d)|6759|6759|7|0.1%|0.1%|
[php_dictionary](#php_dictionary)|702|702|7|0.9%|0.1%|
[fullbogons](#fullbogons)|3770|670213096|5|0.0%|0.1%|
[bogons](#bogons)|13|592708608|5|0.0%|0.1%|
[blocklist_de_bots](#blocklist_de_bots)|2888|2888|5|0.1%|0.1%|
[et_block](#et_block)|1000|18344011|4|0.0%|0.1%|
[xroxy](#xroxy)|2163|2163|3|0.1%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|3|0.0%|0.0%|
[php_commenters](#php_commenters)|430|430|3|0.6%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|0.0%|
[dragon_http](#dragon_http)|1044|273664|3|0.0%|0.0%|
[php_harvesters](#php_harvesters)|392|392|2|0.5%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|2|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2798|2798|2|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14166|14166|2|0.0%|0.0%|
[zeus_badips](#zeus_badips)|202|202|1|0.4%|0.0%|
[zeus](#zeus)|230|230|1|0.4%|0.0%|
[tor_exits](#tor_exits)|1116|1116|1|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2784|2784|1|0.0%|0.0%|
[proxz](#proxz)|1265|1265|1|0.0%|0.0%|
[proxyrss](#proxyrss)|1673|1673|1|0.0%|0.0%|
[et_tor](#et_tor)|6400|6400|1|0.0%|0.0%|
[dm_tor](#dm_tor)|6424|6424|1|0.0%|0.0%|
[bm_tor](#bm_tor)|6402|6402|1|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|1997|1997|1|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|1425|1425|1|0.0%|0.0%|

## iw_wormlist

[ImproWare Antispam](http://antispam.imp.ch/) IPs sending emails with viruses or worms, in the last 3 days

Source is downloaded from [this link](http://antispam.imp.ch/wormlist).

The last time downloaded was found to be dated: Thu Jun 11 06:20:05 UTC 2015.

The ipset `iw_wormlist` has **33** entries, **33** unique IPs.

The following table shows the overlaps of `iw_wormlist` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `iw_wormlist`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `iw_wormlist`.
- ` this % ` is the percentage **of this ipset (`iw_wormlist`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level3](#firehol_level3)|109949|9627745|33|0.0%|100.0%|
[iw_spamlist](#iw_spamlist)|3758|3758|14|0.3%|42.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|2|0.0%|6.0%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|1|0.0%|3.0%|
[stopforumspam_30d](#stopforumspam_30d)|94424|94424|1|0.0%|3.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|1|0.0%|3.0%|
[firehol_level2](#firehol_level2)|20916|32554|1|0.0%|3.0%|
[blocklist_de_mail](#blocklist_de_mail)|16274|16274|1|0.0%|3.0%|
[blocklist_de](#blocklist_de)|27197|27197|1|0.0%|3.0%|

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
[firehol_level3](#firehol_level3)|109949|9627745|313|0.0%|100.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|45|0.0%|14.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|16|0.0%|5.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|11|0.0%|3.5%|
[alienvault_reputation](#alienvault_reputation)|184538|184538|10|0.0%|3.1%|
[firehol_level1](#firehol_level1)|5133|688894588|7|0.0%|2.2%|
[et_block](#et_block)|1000|18344011|5|0.0%|1.5%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|4|0.0%|1.2%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|4|0.3%|1.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|3|0.0%|0.9%|
[dragon_http](#dragon_http)|1044|273664|3|0.0%|0.9%|
[dshield](#dshield)|20|5120|2|0.0%|0.6%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|1|0.0%|0.3%|
[sorbs_spam](#sorbs_spam)|62018|62766|1|0.0%|0.3%|
[sorbs_recent_spam](#sorbs_recent_spam)|62018|62766|1|0.0%|0.3%|
[sorbs_new_spam](#sorbs_new_spam)|62018|62766|1|0.0%|0.3%|
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
[firehol_level3](#firehol_level3)|109949|9627745|1288|0.0%|100.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|147|0.0%|11.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|66|0.0%|5.1%|
[firehol_level1](#firehol_level1)|5133|688894588|39|0.0%|3.0%|
[et_block](#et_block)|1000|18344011|30|0.0%|2.3%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|29|0.0%|2.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|27|0.0%|2.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|27|0.0%|2.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|26|0.0%|2.0%|
[snort_ipfilter](#snort_ipfilter)|9945|9945|12|0.1%|0.9%|
[fullbogons](#fullbogons)|3770|670213096|9|0.0%|0.6%|
[alienvault_reputation](#alienvault_reputation)|184538|184538|8|0.0%|0.6%|
[stopforumspam_30d](#stopforumspam_30d)|94424|94424|4|0.0%|0.3%|
[malc0de](#malc0de)|313|313|4|1.2%|0.3%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|3|0.2%|0.2%|
[dragon_http](#dragon_http)|1044|273664|2|0.0%|0.1%|
[zeus](#zeus)|230|230|1|0.4%|0.0%|
[nixspam](#nixspam)|16664|16664|1|0.0%|0.0%|
[et_botcc](#et_botcc)|506|506|1|0.1%|0.0%|

## maxmind_proxy_fraud

[MaxMind.com](https://www.maxmind.com/en/anonymous-proxy-fraudulent-ip-address-list) list of anonymous proxy fraudelent IP addresses.

Source is downloaded from [this link](https://www.maxmind.com/en/anonymous-proxy-fraudulent-ip-address-list).

The last time downloaded was found to be dated: Thu Jun 11 07:00:52 UTC 2015.

The ipset `maxmind_proxy_fraud` has **524** entries, **524** unique IPs.

The following table shows the overlaps of `maxmind_proxy_fraud` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `maxmind_proxy_fraud`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `maxmind_proxy_fraud`.
- ` this % ` is the percentage **of this ipset (`maxmind_proxy_fraud`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_proxies](#firehol_proxies)|12475|12745|524|4.1%|100.0%|
[firehol_anonymous](#firehol_anonymous)|18924|82965|524|0.6%|100.0%|
[firehol_level3](#firehol_level3)|109949|9627745|343|0.0%|65.4%|
[stopforumspam_30d](#stopforumspam_30d)|94424|94424|342|0.3%|65.2%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|286|0.9%|54.5%|
[snort_ipfilter](#snort_ipfilter)|9945|9945|237|2.3%|45.2%|
[et_tor](#et_tor)|6400|6400|234|3.6%|44.6%|
[dm_tor](#dm_tor)|6424|6424|233|3.6%|44.4%|
[bm_tor](#bm_tor)|6402|6402|233|3.6%|44.4%|
[tor_exits](#tor_exits)|1116|1116|231|20.6%|44.0%|
[firehol_level2](#firehol_level2)|20916|32554|218|0.6%|41.6%|
[stopforumspam_1d](#stopforumspam_1d)|6759|6759|215|3.1%|41.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|150|0.0%|28.6%|
[php_commenters](#php_commenters)|430|430|52|12.0%|9.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|29|0.0%|5.5%|
[alienvault_reputation](#alienvault_reputation)|184538|184538|29|0.0%|5.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|21|0.0%|4.0%|
[openbl_60d](#openbl_60d)|6997|6997|20|0.2%|3.8%|
[ri_web_proxies](#ri_web_proxies)|7712|7712|10|0.1%|1.9%|
[blocklist_de](#blocklist_de)|27197|27197|8|0.0%|1.5%|
[php_harvesters](#php_harvesters)|392|392|7|1.7%|1.3%|
[php_spammers](#php_spammers)|700|700|6|0.8%|1.1%|
[php_dictionary](#php_dictionary)|702|702|5|0.7%|0.9%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|5|0.0%|0.9%|
[blocklist_de_bots](#blocklist_de_bots)|2888|2888|5|0.1%|0.9%|
[xroxy](#xroxy)|2163|2163|3|0.1%|0.5%|
[voipbl](#voipbl)|10533|10945|2|0.0%|0.3%|
[proxz](#proxz)|1265|1265|2|0.1%|0.3%|
[nixspam](#nixspam)|16664|16664|2|0.0%|0.3%|
[dragon_http](#dragon_http)|1044|273664|2|0.0%|0.3%|
[blocklist_de_mail](#blocklist_de_mail)|16274|16274|2|0.0%|0.3%|
[blocklist_de_apache](#blocklist_de_apache)|14166|14166|2|0.0%|0.3%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|1|0.0%|0.1%|
[sorbs_spam](#sorbs_spam)|62018|62766|1|0.0%|0.1%|
[sorbs_recent_spam](#sorbs_recent_spam)|62018|62766|1|0.0%|0.1%|
[sorbs_new_spam](#sorbs_new_spam)|62018|62766|1|0.0%|0.1%|
[shunlist](#shunlist)|1243|1243|1|0.0%|0.1%|
[ri_connect_proxies](#ri_connect_proxies)|2784|2784|1|0.0%|0.1%|
[proxyrss](#proxyrss)|1673|1673|1|0.0%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.1%|
[firehol_level1](#firehol_level1)|5133|688894588|1|0.0%|0.1%|
[et_block](#et_block)|1000|18344011|1|0.0%|0.1%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2798|2798|1|0.0%|0.1%|

## nixspam

[NiX Spam](http://www.heise.de/ix/NiX-Spam-DNSBL-and-blacklist-for-download-499637.html) IP addresses that sent spam in the last hour - automatically generated entries without distinguishing open proxies from relays, dialup gateways, and so on. All IPs are removed after 12 hours if there is no spam from there.

Source is downloaded from [this link](http://www.dnsbl.manitu.net/download/nixspam-ip.dump.gz).

The last time downloaded was found to be dated: Thu Jun 11 07:15:02 UTC 2015.

The ipset `nixspam` has **16664** entries, **16664** unique IPs.

The following table shows the overlaps of `nixspam` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `nixspam`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `nixspam`.
- ` this % ` is the percentage **of this ipset (`nixspam`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[sorbs_spam](#sorbs_spam)|62018|62766|3061|4.8%|18.3%|
[sorbs_recent_spam](#sorbs_recent_spam)|62018|62766|3061|4.8%|18.3%|
[sorbs_new_spam](#sorbs_new_spam)|62018|62766|3061|4.8%|18.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|992|0.0%|5.9%|
[firehol_level2](#firehol_level2)|20916|32554|512|1.5%|3.0%|
[blocklist_de](#blocklist_de)|27197|27197|500|1.8%|3.0%|
[iw_spamlist](#iw_spamlist)|3758|3758|491|13.0%|2.9%|
[firehol_level3](#firehol_level3)|109949|9627745|484|0.0%|2.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|476|0.0%|2.8%|
[blocklist_de_mail](#blocklist_de_mail)|16274|16274|470|2.8%|2.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|335|0.0%|2.0%|
[snort_ipfilter](#snort_ipfilter)|9945|9945|205|2.0%|1.2%|
[stopforumspam_30d](#stopforumspam_30d)|94424|94424|203|0.2%|1.2%|
[firehol_anonymous](#firehol_anonymous)|18924|82965|173|0.2%|1.0%|
[firehol_proxies](#firehol_proxies)|12475|12745|167|1.3%|1.0%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|131|0.4%|0.7%|
[ri_web_proxies](#ri_web_proxies)|7712|7712|126|1.6%|0.7%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|113|0.0%|0.6%|
[firehol_level1](#firehol_level1)|5133|688894588|113|0.0%|0.6%|
[et_block](#et_block)|1000|18344011|113|0.0%|0.6%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|112|0.0%|0.6%|
[php_dictionary](#php_dictionary)|702|702|105|14.9%|0.6%|
[php_spammers](#php_spammers)|700|700|90|12.8%|0.5%|
[sorbs_web](#sorbs_web)|482|483|79|16.3%|0.4%|
[xroxy](#xroxy)|2163|2163|66|3.0%|0.3%|
[stopforumspam_1d](#stopforumspam_1d)|6759|6759|42|0.6%|0.2%|
[proxz](#proxz)|1265|1265|42|3.3%|0.2%|
[alienvault_reputation](#alienvault_reputation)|184538|184538|40|0.0%|0.2%|
[blocklist_de_bots](#blocklist_de_bots)|2888|2888|29|1.0%|0.1%|
[dragon_http](#dragon_http)|1044|273664|27|0.0%|0.1%|
[ri_connect_proxies](#ri_connect_proxies)|2784|2784|14|0.5%|0.0%|
[php_commenters](#php_commenters)|430|430|14|3.2%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|1997|1997|12|0.6%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14166|14166|11|0.0%|0.0%|
[proxyrss](#proxyrss)|1673|1673|10|0.5%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2798|2798|10|0.3%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|9|0.0%|0.0%|
[php_harvesters](#php_harvesters)|392|392|8|2.0%|0.0%|
[tor_exits](#tor_exits)|1116|1116|7|0.6%|0.0%|
[dm_tor](#dm_tor)|6424|6424|6|0.0%|0.0%|
[bm_tor](#bm_tor)|6402|6402|6|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|5|0.0%|0.0%|
[et_tor](#et_tor)|6400|6400|5|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|1425|1425|4|0.2%|0.0%|
[sorbs_socks](#sorbs_socks)|5|5|3|60.0%|0.0%|
[sorbs_misc](#sorbs_misc)|5|5|3|60.0%|0.0%|
[sorbs_http](#sorbs_http)|5|5|3|60.0%|0.0%|
[openbl_60d](#openbl_60d)|6997|6997|3|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3474|3474|3|0.0%|0.0%|
[openbl_30d](#openbl_30d)|2829|2829|2|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|2|0.3%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|2|0.3%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|183|183|2|1.0%|0.0%|
[zeus_badips](#zeus_badips)|202|202|1|0.4%|0.0%|
[zeus](#zeus)|230|230|1|0.4%|0.0%|
[voipbl](#voipbl)|10533|10945|1|0.0%|0.0%|
[openbl_7d](#openbl_7d)|669|669|1|0.1%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|1|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|1|0.0%|0.0%|

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
[firehol_level1](#firehol_level1)|5133|688894588|8|0.0%|11.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|7|0.0%|10.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|5|0.0%|7.2%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|4|0.0%|5.7%|
[fullbogons](#fullbogons)|3770|670213096|4|0.0%|5.7%|
[et_block](#et_block)|1000|18344011|4|0.0%|5.7%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|4.3%|
[firehol_level3](#firehol_level3)|109949|9627745|3|0.0%|4.3%|
[stopforumspam_30d](#stopforumspam_30d)|94424|94424|2|0.0%|2.8%|
[nt_malware_irc](#nt_malware_irc)|43|43|2|4.6%|2.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|2|0.0%|2.8%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|1.4%|
[alienvault_reputation](#alienvault_reputation)|184538|184538|1|0.0%|1.4%|

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
[firehol_level1](#firehol_level1)|5133|688894588|3|0.0%|6.9%|
[et_block](#et_block)|1000|18344011|3|0.0%|6.9%|
[nt_malware_http](#nt_malware_http)|69|69|2|2.8%|4.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|2|0.0%|4.6%|
[alienvault_reputation](#alienvault_reputation)|184538|184538|2|0.0%|4.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|1|0.0%|2.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|2.3%|
[firehol_level3](#firehol_level3)|109949|9627745|1|0.0%|2.3%|

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

The last time downloaded was found to be dated: Thu Jun 11 06:32:00 UTC 2015.

The ipset `openbl_1d` has **144** entries, **144** unique IPs.

The following table shows the overlaps of `openbl_1d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl_1d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl_1d`.
- ` this % ` is the percentage **of this ipset (`openbl_1d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|20916|32554|144|0.4%|100.0%|
[firehol_level3](#firehol_level3)|109949|9627745|142|0.0%|98.6%|
[openbl_60d](#openbl_60d)|6997|6997|141|2.0%|97.9%|
[openbl_30d](#openbl_30d)|2829|2829|141|4.9%|97.9%|
[alienvault_reputation](#alienvault_reputation)|184538|184538|141|0.0%|97.9%|
[openbl_7d](#openbl_7d)|669|669|139|20.7%|96.5%|
[blocklist_de](#blocklist_de)|27197|27197|123|0.4%|85.4%|
[blocklist_de_ssh](#blocklist_de_ssh)|3474|3474|119|3.4%|82.6%|
[bruteforceblocker](#bruteforceblocker)|1705|1705|67|3.9%|46.5%|
[shunlist](#shunlist)|1243|1243|65|5.2%|45.1%|
[et_compromised](#et_compromised)|1721|1721|65|3.7%|45.1%|
[firehol_level1](#firehol_level1)|5133|688894588|20|0.0%|13.8%|
[dshield](#dshield)|20|5120|18|0.3%|12.5%|
[blocklist_de_strongips](#blocklist_de_strongips)|183|183|17|9.2%|11.8%|
[et_block](#et_block)|1000|18344011|14|0.0%|9.7%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|13|0.0%|9.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|10|0.0%|6.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|8|0.0%|5.5%|
[dragon_http](#dragon_http)|1044|273664|4|0.0%|2.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|3|0.0%|2.0%|
[blocklist_de_mail](#blocklist_de_mail)|16274|16274|2|0.0%|1.3%|
[blocklist_de_apache](#blocklist_de_apache)|14166|14166|2|0.0%|1.3%|
[zeus_badips](#zeus_badips)|202|202|1|0.4%|0.6%|
[zeus](#zeus)|230|230|1|0.4%|0.6%|
[stopforumspam_30d](#stopforumspam_30d)|94424|94424|1|0.0%|0.6%|
[snort_ipfilter](#snort_ipfilter)|9945|9945|1|0.0%|0.6%|
[php_spammers](#php_spammers)|700|700|1|0.1%|0.6%|
[php_commenters](#php_commenters)|430|430|1|0.2%|0.6%|
[ciarmy](#ciarmy)|442|442|1|0.2%|0.6%|
[blocklist_de_imap](#blocklist_de_imap)|1997|1997|1|0.0%|0.6%|

## openbl_30d

[OpenBL.org](http://www.openbl.org/) last 30 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.

Source is downloaded from [this link](http://www.openbl.org/lists/base_30days.txt).

The last time downloaded was found to be dated: Thu Jun 11 04:07:00 UTC 2015.

The ipset `openbl_30d` has **2829** entries, **2829** unique IPs.

The following table shows the overlaps of `openbl_30d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl_30d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl_30d`.
- ` this % ` is the percentage **of this ipset (`openbl_30d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[openbl_60d](#openbl_60d)|6997|6997|2829|40.4%|100.0%|
[firehol_level3](#firehol_level3)|109949|9627745|2829|0.0%|100.0%|
[alienvault_reputation](#alienvault_reputation)|184538|184538|2815|1.5%|99.5%|
[et_compromised](#et_compromised)|1721|1721|946|54.9%|33.4%|
[bruteforceblocker](#bruteforceblocker)|1705|1705|912|53.4%|32.2%|
[firehol_level2](#firehol_level2)|20916|32554|760|2.3%|26.8%|
[blocklist_de](#blocklist_de)|27197|27197|741|2.7%|26.1%|
[blocklist_de_ssh](#blocklist_de_ssh)|3474|3474|717|20.6%|25.3%|
[openbl_7d](#openbl_7d)|669|669|669|100.0%|23.6%|
[shunlist](#shunlist)|1243|1243|505|40.6%|17.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|293|0.0%|10.3%|
[et_block](#et_block)|1000|18344011|163|0.0%|5.7%|
[firehol_level1](#firehol_level1)|5133|688894588|161|0.0%|5.6%|
[dragon_http](#dragon_http)|1044|273664|154|0.0%|5.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|147|0.0%|5.1%|
[openbl_1d](#openbl_1d)|144|144|141|97.9%|4.9%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|119|0.0%|4.2%|
[dshield](#dshield)|20|5120|75|1.4%|2.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|65|0.0%|2.2%|
[blocklist_de_strongips](#blocklist_de_strongips)|183|183|24|13.1%|0.8%|
[blocklist_de_mail](#blocklist_de_mail)|16274|16274|13|0.0%|0.4%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|12|0.0%|0.4%|
[blocklist_de_imap](#blocklist_de_imap)|1997|1997|8|0.4%|0.2%|
[blocklist_de_apache](#blocklist_de_apache)|14166|14166|7|0.0%|0.2%|
[stopforumspam_30d](#stopforumspam_30d)|94424|94424|5|0.0%|0.1%|
[voipbl](#voipbl)|10533|10945|3|0.0%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|3|0.0%|0.1%|
[zeus](#zeus)|230|230|2|0.8%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9945|9945|2|0.0%|0.0%|
[nixspam](#nixspam)|16664|16664|2|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|2|0.1%|0.0%|
[ciarmy](#ciarmy)|442|442|2|0.4%|0.0%|
[zeus_badips](#zeus_badips)|202|202|1|0.4%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|1|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6759|6759|1|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|1|0.0%|0.0%|
[php_spammers](#php_spammers)|700|700|1|0.1%|0.0%|
[php_commenters](#php_commenters)|430|430|1|0.2%|0.0%|
[firehol_anonymous](#firehol_anonymous)|18924|82965|1|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|1425|1425|1|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|2888|2888|1|0.0%|0.0%|

## openbl_60d

[OpenBL.org](http://www.openbl.org/) last 60 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.

Source is downloaded from [this link](http://www.openbl.org/lists/base_60days.txt).

The last time downloaded was found to be dated: Thu Jun 11 04:07:00 UTC 2015.

The ipset `openbl_60d` has **6997** entries, **6997** unique IPs.

The following table shows the overlaps of `openbl_60d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl_60d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl_60d`.
- ` this % ` is the percentage **of this ipset (`openbl_60d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[alienvault_reputation](#alienvault_reputation)|184538|184538|6978|3.7%|99.7%|
[firehol_level3](#firehol_level3)|109949|9627745|2957|0.0%|42.2%|
[openbl_30d](#openbl_30d)|2829|2829|2829|100.0%|40.4%|
[et_compromised](#et_compromised)|1721|1721|1012|58.8%|14.4%|
[bruteforceblocker](#bruteforceblocker)|1705|1705|973|57.0%|13.9%|
[firehol_level2](#firehol_level2)|20916|32554|964|2.9%|13.7%|
[blocklist_de](#blocklist_de)|27197|27197|927|3.4%|13.2%|
[blocklist_de_ssh](#blocklist_de_ssh)|3474|3474|895|25.7%|12.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|743|0.0%|10.6%|
[openbl_7d](#openbl_7d)|669|669|669|100.0%|9.5%|
[shunlist](#shunlist)|1243|1243|535|43.0%|7.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|319|0.0%|4.5%|
[et_block](#et_block)|1000|18344011|300|0.0%|4.2%|
[firehol_level1](#firehol_level1)|5133|688894588|287|0.0%|4.1%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|235|0.0%|3.3%|
[dragon_http](#dragon_http)|1044|273664|219|0.0%|3.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|164|0.0%|2.3%|
[openbl_1d](#openbl_1d)|144|144|141|97.9%|2.0%|
[dshield](#dshield)|20|5120|85|1.6%|1.2%|
[stopforumspam_30d](#stopforumspam_30d)|94424|94424|48|0.0%|0.6%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|27|0.0%|0.3%|
[blocklist_de_strongips](#blocklist_de_strongips)|183|183|25|13.6%|0.3%|
[snort_ipfilter](#snort_ipfilter)|9945|9945|24|0.2%|0.3%|
[firehol_anonymous](#firehol_anonymous)|18924|82965|23|0.0%|0.3%|
[tor_exits](#tor_exits)|1116|1116|20|1.7%|0.2%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|20|3.8%|0.2%|
[firehol_proxies](#firehol_proxies)|12475|12745|20|0.1%|0.2%|
[et_tor](#et_tor)|6400|6400|20|0.3%|0.2%|
[dm_tor](#dm_tor)|6424|6424|20|0.3%|0.2%|
[bm_tor](#bm_tor)|6402|6402|20|0.3%|0.2%|
[blocklist_de_mail](#blocklist_de_mail)|16274|16274|20|0.1%|0.2%|
[stopforumspam_1d](#stopforumspam_1d)|6759|6759|19|0.2%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|16|0.0%|0.2%|
[blocklist_de_imap](#blocklist_de_imap)|1997|1997|14|0.7%|0.2%|
[php_commenters](#php_commenters)|430|430|11|2.5%|0.1%|
[voipbl](#voipbl)|10533|10945|8|0.0%|0.1%|
[blocklist_de_apache](#blocklist_de_apache)|14166|14166|7|0.0%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|5|0.0%|0.0%|
[nixspam](#nixspam)|16664|16664|3|0.0%|0.0%|
[zeus](#zeus)|230|230|2|0.8%|0.0%|
[sorbs_spam](#sorbs_spam)|62018|62766|2|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|62018|62766|2|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|62018|62766|2|0.0%|0.0%|
[php_harvesters](#php_harvesters)|392|392|2|0.5%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|2|0.1%|0.0%|
[ciarmy](#ciarmy)|442|442|2|0.4%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|1425|1425|2|0.1%|0.0%|
[zeus_badips](#zeus_badips)|202|202|1|0.4%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|1|0.0%|0.0%|
[php_spammers](#php_spammers)|700|700|1|0.1%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|2888|2888|1|0.0%|0.0%|

## openbl_7d

[OpenBL.org](http://www.openbl.org/) last 7 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.

Source is downloaded from [this link](http://www.openbl.org/lists/base_7days.txt).

The last time downloaded was found to be dated: Thu Jun 11 04:07:00 UTC 2015.

The ipset `openbl_7d` has **669** entries, **669** unique IPs.

The following table shows the overlaps of `openbl_7d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl_7d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl_7d`.
- ` this % ` is the percentage **of this ipset (`openbl_7d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[openbl_60d](#openbl_60d)|6997|6997|669|9.5%|100.0%|
[openbl_30d](#openbl_30d)|2829|2829|669|23.6%|100.0%|
[firehol_level3](#firehol_level3)|109949|9627745|669|0.0%|100.0%|
[alienvault_reputation](#alienvault_reputation)|184538|184538|668|0.3%|99.8%|
[firehol_level2](#firehol_level2)|20916|32554|416|1.2%|62.1%|
[blocklist_de](#blocklist_de)|27197|27197|397|1.4%|59.3%|
[blocklist_de_ssh](#blocklist_de_ssh)|3474|3474|383|11.0%|57.2%|
[et_compromised](#et_compromised)|1721|1721|325|18.8%|48.5%|
[bruteforceblocker](#bruteforceblocker)|1705|1705|323|18.9%|48.2%|
[shunlist](#shunlist)|1243|1243|215|17.2%|32.1%|
[openbl_1d](#openbl_1d)|144|144|139|96.5%|20.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|76|0.0%|11.3%|
[firehol_level1](#firehol_level1)|5133|688894588|63|0.0%|9.4%|
[et_block](#et_block)|1000|18344011|61|0.0%|9.1%|
[dragon_http](#dragon_http)|1044|273664|57|0.0%|8.5%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|51|0.0%|7.6%|
[dshield](#dshield)|20|5120|43|0.8%|6.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|41|0.0%|6.1%|
[blocklist_de_strongips](#blocklist_de_strongips)|183|183|24|13.1%|3.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|16|0.0%|2.3%|
[blocklist_de_mail](#blocklist_de_mail)|16274|16274|8|0.0%|1.1%|
[blocklist_de_imap](#blocklist_de_imap)|1997|1997|7|0.3%|1.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|5|0.0%|0.7%|
[blocklist_de_apache](#blocklist_de_apache)|14166|14166|5|0.0%|0.7%|
[stopforumspam_30d](#stopforumspam_30d)|94424|94424|2|0.0%|0.2%|
[ciarmy](#ciarmy)|442|442|2|0.4%|0.2%|
[zeus_badips](#zeus_badips)|202|202|1|0.4%|0.1%|
[zeus](#zeus)|230|230|1|0.4%|0.1%|
[snort_ipfilter](#snort_ipfilter)|9945|9945|1|0.0%|0.1%|
[php_spammers](#php_spammers)|700|700|1|0.1%|0.1%|
[php_commenters](#php_commenters)|430|430|1|0.2%|0.1%|
[nixspam](#nixspam)|16664|16664|1|0.0%|0.1%|
[blocklist_de_ftp](#blocklist_de_ftp)|1425|1425|1|0.0%|0.1%|

## palevo

[Abuse.ch Palevo tracker](https://palevotracker.abuse.ch) worm includes IPs which are being used as botnet C&C for the Palevo crimeware - **excellent list**

Source is downloaded from [this link](https://palevotracker.abuse.ch/blocklists.php?download=ipblocklist).

The last time downloaded was found to be dated: Thu Jun 11 07:18:24 UTC 2015.

The ipset `palevo` has **13** entries, **13** unique IPs.

The following table shows the overlaps of `palevo` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `palevo`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `palevo`.
- ` this % ` is the percentage **of this ipset (`palevo`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level1](#firehol_level1)|5133|688894588|13|0.0%|100.0%|
[et_block](#et_block)|1000|18344011|13|0.0%|100.0%|
[snort_ipfilter](#snort_ipfilter)|9945|9945|11|0.1%|84.6%|
[firehol_level3](#firehol_level3)|109949|9627745|11|0.0%|84.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|3|0.0%|23.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|2|0.0%|15.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|1|0.0%|7.6%|

## php_commenters

[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) comment spammers (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=c&rss=1).

The last time downloaded was found to be dated: Thu Jun 11 06:45:18 UTC 2015.

The ipset `php_commenters` has **430** entries, **430** unique IPs.

The following table shows the overlaps of `php_commenters` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `php_commenters`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `php_commenters`.
- ` this % ` is the percentage **of this ipset (`php_commenters`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level3](#firehol_level3)|109949|9627745|430|0.0%|100.0%|
[stopforumspam_30d](#stopforumspam_30d)|94424|94424|318|0.3%|73.9%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|240|0.8%|55.8%|
[firehol_level2](#firehol_level2)|20916|32554|189|0.5%|43.9%|
[stopforumspam_1d](#stopforumspam_1d)|6759|6759|166|2.4%|38.6%|
[blocklist_de](#blocklist_de)|27197|27197|106|0.3%|24.6%|
[blocklist_de_bots](#blocklist_de_bots)|2888|2888|86|2.9%|20.0%|
[firehol_anonymous](#firehol_anonymous)|18924|82965|82|0.0%|19.0%|
[firehol_proxies](#firehol_proxies)|12475|12745|80|0.6%|18.6%|
[snort_ipfilter](#snort_ipfilter)|9945|9945|64|0.6%|14.8%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|52|9.9%|12.0%|
[tor_exits](#tor_exits)|1116|1116|51|4.5%|11.8%|
[et_tor](#et_tor)|6400|6400|51|0.7%|11.8%|
[dm_tor](#dm_tor)|6424|6424|51|0.7%|11.8%|
[bm_tor](#bm_tor)|6402|6402|51|0.7%|11.8%|
[php_spammers](#php_spammers)|700|700|50|7.1%|11.6%|
[blocklist_de_strongips](#blocklist_de_strongips)|183|183|47|25.6%|10.9%|
[firehol_level1](#firehol_level1)|5133|688894588|38|0.0%|8.8%|
[php_dictionary](#php_dictionary)|702|702|33|4.7%|7.6%|
[blocklist_de_apache](#blocklist_de_apache)|14166|14166|30|0.2%|6.9%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|29|0.0%|6.7%|
[et_block](#et_block)|1000|18344011|29|0.0%|6.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|28|0.0%|6.5%|
[blocklist_de_mail](#blocklist_de_mail)|16274|16274|27|0.1%|6.2%|
[ri_web_proxies](#ri_web_proxies)|7712|7712|25|0.3%|5.8%|
[sorbs_spam](#sorbs_spam)|62018|62766|22|0.0%|5.1%|
[sorbs_recent_spam](#sorbs_recent_spam)|62018|62766|22|0.0%|5.1%|
[sorbs_new_spam](#sorbs_new_spam)|62018|62766|22|0.0%|5.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|18|0.0%|4.1%|
[alienvault_reputation](#alienvault_reputation)|184538|184538|18|0.0%|4.1%|
[php_harvesters](#php_harvesters)|392|392|15|3.8%|3.4%|
[nixspam](#nixspam)|16664|16664|14|0.0%|3.2%|
[openbl_60d](#openbl_60d)|6997|6997|11|0.1%|2.5%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2798|2798|11|0.3%|2.5%|
[xroxy](#xroxy)|2163|2163|10|0.4%|2.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|10|0.0%|2.3%|
[proxz](#proxz)|1265|1265|9|0.7%|2.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|8|0.0%|1.8%|
[ri_connect_proxies](#ri_connect_proxies)|2784|2784|5|0.1%|1.1%|
[proxyrss](#proxyrss)|1673|1673|3|0.1%|0.6%|
[iw_spamlist](#iw_spamlist)|3758|3758|3|0.0%|0.6%|
[sorbs_web](#sorbs_web)|482|483|2|0.4%|0.4%|
[dragon_http](#dragon_http)|1044|273664|2|0.0%|0.4%|
[zeus_badips](#zeus_badips)|202|202|1|0.4%|0.2%|
[zeus](#zeus)|230|230|1|0.4%|0.2%|
[openbl_7d](#openbl_7d)|669|669|1|0.1%|0.2%|
[openbl_30d](#openbl_30d)|2829|2829|1|0.0%|0.2%|
[openbl_1d](#openbl_1d)|144|144|1|0.6%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.2%|
[fullbogons](#fullbogons)|3770|670213096|1|0.0%|0.2%|
[et_compromised](#et_compromised)|1721|1721|1|0.0%|0.2%|
[bruteforceblocker](#bruteforceblocker)|1705|1705|1|0.0%|0.2%|
[bogons](#bogons)|13|592708608|1|0.0%|0.2%|
[blocklist_de_ssh](#blocklist_de_ssh)|3474|3474|1|0.0%|0.2%|

## php_dictionary

[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) directory attackers (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=d&rss=1).

The last time downloaded was found to be dated: Thu Jun 11 06:45:19 UTC 2015.

The ipset `php_dictionary` has **702** entries, **702** unique IPs.

The following table shows the overlaps of `php_dictionary` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `php_dictionary`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `php_dictionary`.
- ` this % ` is the percentage **of this ipset (`php_dictionary`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level3](#firehol_level3)|109949|9627745|702|0.0%|100.0%|
[php_spammers](#php_spammers)|700|700|296|42.2%|42.1%|
[sorbs_spam](#sorbs_spam)|62018|62766|192|0.3%|27.3%|
[sorbs_recent_spam](#sorbs_recent_spam)|62018|62766|192|0.3%|27.3%|
[sorbs_new_spam](#sorbs_new_spam)|62018|62766|192|0.3%|27.3%|
[stopforumspam_30d](#stopforumspam_30d)|94424|94424|133|0.1%|18.9%|
[firehol_level2](#firehol_level2)|20916|32554|118|0.3%|16.8%|
[blocklist_de](#blocklist_de)|27197|27197|111|0.4%|15.8%|
[nixspam](#nixspam)|16664|16664|105|0.6%|14.9%|
[firehol_anonymous](#firehol_anonymous)|18924|82965|95|0.1%|13.5%|
[firehol_proxies](#firehol_proxies)|12475|12745|94|0.7%|13.3%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|90|0.3%|12.8%|
[blocklist_de_mail](#blocklist_de_mail)|16274|16274|90|0.5%|12.8%|
[snort_ipfilter](#snort_ipfilter)|9945|9945|78|0.7%|11.1%|
[ri_web_proxies](#ri_web_proxies)|7712|7712|65|0.8%|9.2%|
[xroxy](#xroxy)|2163|2163|39|1.8%|5.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|38|0.0%|5.4%|
[php_commenters](#php_commenters)|430|430|33|7.6%|4.7%|
[sorbs_web](#sorbs_web)|482|483|29|6.0%|4.1%|
[stopforumspam_1d](#stopforumspam_1d)|6759|6759|26|0.3%|3.7%|
[proxz](#proxz)|1265|1265|23|1.8%|3.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|23|0.0%|3.2%|
[blocklist_de_bots](#blocklist_de_bots)|2888|2888|18|0.6%|2.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|12|0.0%|1.7%|
[iw_spamlist](#iw_spamlist)|3758|3758|7|0.1%|0.9%|
[alienvault_reputation](#alienvault_reputation)|184538|184538|7|0.0%|0.9%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|6|0.0%|0.8%|
[firehol_level1](#firehol_level1)|5133|688894588|6|0.0%|0.8%|
[et_block](#et_block)|1000|18344011|6|0.0%|0.8%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|5|0.9%|0.7%|
[blocklist_de_strongips](#blocklist_de_strongips)|183|183|5|2.7%|0.7%|
[tor_exits](#tor_exits)|1116|1116|4|0.3%|0.5%|
[ri_connect_proxies](#ri_connect_proxies)|2784|2784|4|0.1%|0.5%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|4|0.0%|0.5%|
[et_tor](#et_tor)|6400|6400|4|0.0%|0.5%|
[dm_tor](#dm_tor)|6424|6424|4|0.0%|0.5%|
[bm_tor](#bm_tor)|6402|6402|4|0.0%|0.5%|
[php_harvesters](#php_harvesters)|392|392|3|0.7%|0.4%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|3|0.0%|0.4%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2798|2798|3|0.1%|0.4%|
[blocklist_de_apache](#blocklist_de_apache)|14166|14166|3|0.0%|0.4%|
[dragon_http](#dragon_http)|1044|273664|2|0.0%|0.2%|
[proxyrss](#proxyrss)|1673|1673|1|0.0%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.1%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|1|0.1%|0.1%|
[blocklist_de_ftp](#blocklist_de_ftp)|1425|1425|1|0.0%|0.1%|

## php_harvesters

[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) harvesters (IPs that surf the internet looking for email addresses) (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=h&rss=1).

The last time downloaded was found to be dated: Thu Jun 11 06:45:17 UTC 2015.

The ipset `php_harvesters` has **392** entries, **392** unique IPs.

The following table shows the overlaps of `php_harvesters` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `php_harvesters`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `php_harvesters`.
- ` this % ` is the percentage **of this ipset (`php_harvesters`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level3](#firehol_level3)|109949|9627745|392|0.0%|100.0%|
[stopforumspam_30d](#stopforumspam_30d)|94424|94424|84|0.0%|21.4%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|61|0.2%|15.5%|
[firehol_level2](#firehol_level2)|20916|32554|56|0.1%|14.2%|
[stopforumspam_1d](#stopforumspam_1d)|6759|6759|44|0.6%|11.2%|
[blocklist_de](#blocklist_de)|27197|27197|37|0.1%|9.4%|
[blocklist_de_bots](#blocklist_de_bots)|2888|2888|27|0.9%|6.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|20|0.0%|5.1%|
[php_commenters](#php_commenters)|430|430|15|3.4%|3.8%|
[sorbs_spam](#sorbs_spam)|62018|62766|14|0.0%|3.5%|
[sorbs_recent_spam](#sorbs_recent_spam)|62018|62766|14|0.0%|3.5%|
[sorbs_new_spam](#sorbs_new_spam)|62018|62766|14|0.0%|3.5%|
[snort_ipfilter](#snort_ipfilter)|9945|9945|12|0.1%|3.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|12|0.0%|3.0%|
[firehol_proxies](#firehol_proxies)|12475|12745|12|0.0%|3.0%|
[firehol_anonymous](#firehol_anonymous)|18924|82965|12|0.0%|3.0%|
[alienvault_reputation](#alienvault_reputation)|184538|184538|12|0.0%|3.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|9|0.0%|2.2%|
[nixspam](#nixspam)|16664|16664|8|0.0%|2.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|7|1.3%|1.7%|
[et_tor](#et_tor)|6400|6400|7|0.1%|1.7%|
[dm_tor](#dm_tor)|6424|6424|7|0.1%|1.7%|
[bm_tor](#bm_tor)|6402|6402|7|0.1%|1.7%|
[tor_exits](#tor_exits)|1116|1116|6|0.5%|1.5%|
[blocklist_de_mail](#blocklist_de_mail)|16274|16274|5|0.0%|1.2%|
[blocklist_de_ftp](#blocklist_de_ftp)|1425|1425|4|0.2%|1.0%|
[php_spammers](#php_spammers)|700|700|3|0.4%|0.7%|
[php_dictionary](#php_dictionary)|702|702|3|0.4%|0.7%|
[firehol_level1](#firehol_level1)|5133|688894588|3|0.0%|0.7%|
[blocklist_de_strongips](#blocklist_de_strongips)|183|183|3|1.6%|0.7%|
[xroxy](#xroxy)|2163|2163|2|0.0%|0.5%|
[ri_web_proxies](#ri_web_proxies)|7712|7712|2|0.0%|0.5%|
[openbl_60d](#openbl_60d)|6997|6997|2|0.0%|0.5%|
[iw_spamlist](#iw_spamlist)|3758|3758|2|0.0%|0.5%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|2|0.0%|0.5%|
[blocklist_de_apache](#blocklist_de_apache)|14166|14166|2|0.0%|0.5%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|1|0.0%|0.2%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|1|0.0%|0.2%|
[ri_connect_proxies](#ri_connect_proxies)|2784|2784|1|0.0%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.2%|
[fullbogons](#fullbogons)|3770|670213096|1|0.0%|0.2%|
[et_block](#et_block)|1000|18344011|1|0.0%|0.2%|
[bogons](#bogons)|13|592708608|1|0.0%|0.2%|
[blocklist_de_imap](#blocklist_de_imap)|1997|1997|1|0.0%|0.2%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2798|2798|1|0.0%|0.2%|

## php_spammers

[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) spam servers (IPs used by spammers to send messages) (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=s&rss=1).

The last time downloaded was found to be dated: Thu Jun 11 06:45:18 UTC 2015.

The ipset `php_spammers` has **700** entries, **700** unique IPs.

The following table shows the overlaps of `php_spammers` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `php_spammers`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `php_spammers`.
- ` this % ` is the percentage **of this ipset (`php_spammers`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level3](#firehol_level3)|109949|9627745|700|0.0%|100.0%|
[php_dictionary](#php_dictionary)|702|702|296|42.1%|42.2%|
[sorbs_spam](#sorbs_spam)|62018|62766|166|0.2%|23.7%|
[sorbs_recent_spam](#sorbs_recent_spam)|62018|62766|166|0.2%|23.7%|
[sorbs_new_spam](#sorbs_new_spam)|62018|62766|166|0.2%|23.7%|
[stopforumspam_30d](#stopforumspam_30d)|94424|94424|144|0.1%|20.5%|
[firehol_level2](#firehol_level2)|20916|32554|114|0.3%|16.2%|
[blocklist_de](#blocklist_de)|27197|27197|105|0.3%|15.0%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|91|0.3%|13.0%|
[nixspam](#nixspam)|16664|16664|90|0.5%|12.8%|
[firehol_anonymous](#firehol_anonymous)|18924|82965|79|0.0%|11.2%|
[firehol_proxies](#firehol_proxies)|12475|12745|77|0.6%|11.0%|
[snort_ipfilter](#snort_ipfilter)|9945|9945|76|0.7%|10.8%|
[blocklist_de_mail](#blocklist_de_mail)|16274|16274|73|0.4%|10.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|54|0.0%|7.7%|
[ri_web_proxies](#ri_web_proxies)|7712|7712|53|0.6%|7.5%|
[php_commenters](#php_commenters)|430|430|50|11.6%|7.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|43|0.0%|6.1%|
[stopforumspam_1d](#stopforumspam_1d)|6759|6759|34|0.5%|4.8%|
[xroxy](#xroxy)|2163|2163|32|1.4%|4.5%|
[blocklist_de_bots](#blocklist_de_bots)|2888|2888|24|0.8%|3.4%|
[sorbs_web](#sorbs_web)|482|483|23|4.7%|3.2%|
[proxz](#proxz)|1265|1265|21|1.6%|3.0%|
[iw_spamlist](#iw_spamlist)|3758|3758|10|0.2%|1.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|10|0.0%|1.4%|
[blocklist_de_strongips](#blocklist_de_strongips)|183|183|10|5.4%|1.4%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|6|1.1%|0.8%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2798|2798|6|0.2%|0.8%|
[blocklist_de_apache](#blocklist_de_apache)|14166|14166|6|0.0%|0.8%|
[tor_exits](#tor_exits)|1116|1116|5|0.4%|0.7%|
[et_tor](#et_tor)|6400|6400|5|0.0%|0.7%|
[dm_tor](#dm_tor)|6424|6424|5|0.0%|0.7%|
[bm_tor](#bm_tor)|6402|6402|5|0.0%|0.7%|
[alienvault_reputation](#alienvault_reputation)|184538|184538|5|0.0%|0.7%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|4|0.0%|0.5%|
[firehol_level1](#firehol_level1)|5133|688894588|4|0.0%|0.5%|
[et_block](#et_block)|1000|18344011|4|0.0%|0.5%|
[ri_connect_proxies](#ri_connect_proxies)|2784|2784|3|0.1%|0.4%|
[proxyrss](#proxyrss)|1673|1673|3|0.1%|0.4%|
[php_harvesters](#php_harvesters)|392|392|3|0.7%|0.4%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|0.4%|
[openbl_7d](#openbl_7d)|669|669|1|0.1%|0.1%|
[openbl_60d](#openbl_60d)|6997|6997|1|0.0%|0.1%|
[openbl_30d](#openbl_30d)|2829|2829|1|0.0%|0.1%|
[openbl_1d](#openbl_1d)|144|144|1|0.6%|0.1%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|1|0.0%|0.1%|
[et_compromised](#et_compromised)|1721|1721|1|0.0%|0.1%|
[bruteforceblocker](#bruteforceblocker)|1705|1705|1|0.0%|0.1%|
[blocklist_de_ssh](#blocklist_de_ssh)|3474|3474|1|0.0%|0.1%|
[blocklist_de_ftp](#blocklist_de_ftp)|1425|1425|1|0.0%|0.1%|

## proxyrss

[proxyrss.com](http://www.proxyrss.com) open proxies syndicated from multiple sources.

Source is downloaded from [this link](http://www.proxyrss.com/proxylists/all.gz).

The last time downloaded was found to be dated: Thu Jun 11 03:31:26 UTC 2015.

The ipset `proxyrss` has **1673** entries, **1673** unique IPs.

The following table shows the overlaps of `proxyrss` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `proxyrss`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `proxyrss`.
- ` this % ` is the percentage **of this ipset (`proxyrss`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_proxies](#firehol_proxies)|12475|12745|1673|13.1%|100.0%|
[firehol_anonymous](#firehol_anonymous)|18924|82965|1673|2.0%|100.0%|
[stopforumspam_30d](#stopforumspam_30d)|94424|94424|766|0.8%|45.7%|
[firehol_level3](#firehol_level3)|109949|9627745|766|0.0%|45.7%|
[ri_web_proxies](#ri_web_proxies)|7712|7712|664|8.6%|39.6%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|634|2.1%|37.8%|
[firehol_level2](#firehol_level2)|20916|32554|457|1.4%|27.3%|
[stopforumspam_1d](#stopforumspam_1d)|6759|6759|387|5.7%|23.1%|
[xroxy](#xroxy)|2163|2163|374|17.2%|22.3%|
[proxz](#proxz)|1265|1265|280|22.1%|16.7%|
[ri_connect_proxies](#ri_connect_proxies)|2784|2784|240|8.6%|14.3%|
[blocklist_de](#blocklist_de)|27197|27197|226|0.8%|13.5%|
[blocklist_de_bots](#blocklist_de_bots)|2888|2888|224|7.7%|13.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|53|0.0%|3.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|45|0.0%|2.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|31|0.0%|1.8%|
[nixspam](#nixspam)|16664|16664|10|0.0%|0.5%|
[sorbs_spam](#sorbs_spam)|62018|62766|7|0.0%|0.4%|
[sorbs_recent_spam](#sorbs_recent_spam)|62018|62766|7|0.0%|0.4%|
[sorbs_new_spam](#sorbs_new_spam)|62018|62766|7|0.0%|0.4%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|7|1.0%|0.4%|
[blocklist_de_strongips](#blocklist_de_strongips)|183|183|6|3.2%|0.3%|
[snort_ipfilter](#snort_ipfilter)|9945|9945|4|0.0%|0.2%|
[php_spammers](#php_spammers)|700|700|3|0.4%|0.1%|
[php_commenters](#php_commenters)|430|430|3|0.6%|0.1%|
[dragon_http](#dragon_http)|1044|273664|3|0.0%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|2|0.0%|0.1%|
[alienvault_reputation](#alienvault_reputation)|184538|184538|2|0.0%|0.1%|
[php_dictionary](#php_dictionary)|702|702|1|0.1%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|1|0.1%|0.0%|
[iw_spamlist](#iw_spamlist)|3758|3758|1|0.0%|0.0%|
[et_compromised](#et_compromised)|1721|1721|1|0.0%|0.0%|
[dm_tor](#dm_tor)|6424|6424|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1705|1705|1|0.0%|0.0%|
[bm_tor](#bm_tor)|6402|6402|1|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|16274|16274|1|0.0%|0.0%|

## proxz

[proxz.com](http://www.proxz.com) open proxies (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.proxz.com/proxylists.xml).

The last time downloaded was found to be dated: Thu Jun 11 06:01:25 UTC 2015.

The ipset `proxz` has **1265** entries, **1265** unique IPs.

The following table shows the overlaps of `proxz` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `proxz`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `proxz`.
- ` this % ` is the percentage **of this ipset (`proxz`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_proxies](#firehol_proxies)|12475|12745|1265|9.9%|100.0%|
[firehol_anonymous](#firehol_anonymous)|18924|82965|1265|1.5%|100.0%|
[firehol_level3](#firehol_level3)|109949|9627745|745|0.0%|58.8%|
[stopforumspam_30d](#stopforumspam_30d)|94424|94424|739|0.7%|58.4%|
[ri_web_proxies](#ri_web_proxies)|7712|7712|581|7.5%|45.9%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|483|1.6%|38.1%|
[xroxy](#xroxy)|2163|2163|448|20.7%|35.4%|
[proxyrss](#proxyrss)|1673|1673|280|16.7%|22.1%|
[firehol_level2](#firehol_level2)|20916|32554|277|0.8%|21.8%|
[ri_connect_proxies](#ri_connect_proxies)|2784|2784|219|7.8%|17.3%|
[stopforumspam_1d](#stopforumspam_1d)|6759|6759|191|2.8%|15.0%|
[blocklist_de](#blocklist_de)|27197|27197|178|0.6%|14.0%|
[blocklist_de_bots](#blocklist_de_bots)|2888|2888|147|5.0%|11.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|103|0.0%|8.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|52|0.0%|4.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|43|0.0%|3.3%|
[sorbs_spam](#sorbs_spam)|62018|62766|42|0.0%|3.3%|
[sorbs_recent_spam](#sorbs_recent_spam)|62018|62766|42|0.0%|3.3%|
[sorbs_new_spam](#sorbs_new_spam)|62018|62766|42|0.0%|3.3%|
[nixspam](#nixspam)|16664|16664|42|0.2%|3.3%|
[blocklist_de_mail](#blocklist_de_mail)|16274|16274|29|0.1%|2.2%|
[snort_ipfilter](#snort_ipfilter)|9945|9945|27|0.2%|2.1%|
[php_dictionary](#php_dictionary)|702|702|23|3.2%|1.8%|
[php_spammers](#php_spammers)|700|700|21|3.0%|1.6%|
[php_commenters](#php_commenters)|430|430|9|2.0%|0.7%|
[sorbs_web](#sorbs_web)|482|483|8|1.6%|0.6%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|6|0.9%|0.4%|
[blocklist_de_strongips](#blocklist_de_strongips)|183|183|6|3.2%|0.4%|
[dragon_http](#dragon_http)|1044|273664|4|0.0%|0.3%|
[alienvault_reputation](#alienvault_reputation)|184538|184538|3|0.0%|0.2%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|2|0.3%|0.1%|
[et_compromised](#et_compromised)|1721|1721|2|0.1%|0.1%|
[bruteforceblocker](#bruteforceblocker)|1705|1705|2|0.1%|0.1%|
[iw_spamlist](#iw_spamlist)|3758|3758|1|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|1|0.0%|0.0%|

## ri_connect_proxies

[rosinstrument.com](http://www.rosinstrument.com) open CONNECT proxies (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://tools.rosinstrument.com/proxy/plab100.xml).

The last time downloaded was found to be dated: Thu Jun 11 04:10:15 UTC 2015.

The ipset `ri_connect_proxies` has **2784** entries, **2784** unique IPs.

The following table shows the overlaps of `ri_connect_proxies` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ri_connect_proxies`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ri_connect_proxies`.
- ` this % ` is the percentage **of this ipset (`ri_connect_proxies`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_proxies](#firehol_proxies)|12475|12745|2784|21.8%|100.0%|
[firehol_anonymous](#firehol_anonymous)|18924|82965|2784|3.3%|100.0%|
[firehol_level3](#firehol_level3)|109949|9627745|1559|0.0%|55.9%|
[stopforumspam_30d](#stopforumspam_30d)|94424|94424|1558|1.6%|55.9%|
[ri_web_proxies](#ri_web_proxies)|7712|7712|1182|15.3%|42.4%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|555|1.9%|19.9%|
[xroxy](#xroxy)|2163|2163|393|18.1%|14.1%|
[proxyrss](#proxyrss)|1673|1673|240|14.3%|8.6%|
[proxz](#proxz)|1265|1265|219|17.3%|7.8%|
[firehol_level2](#firehol_level2)|20916|32554|166|0.5%|5.9%|
[stopforumspam_1d](#stopforumspam_1d)|6759|6759|125|1.8%|4.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|105|0.0%|3.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|84|0.0%|3.0%|
[blocklist_de](#blocklist_de)|27197|27197|69|0.2%|2.4%|
[blocklist_de_bots](#blocklist_de_bots)|2888|2888|64|2.2%|2.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|57|0.0%|2.0%|
[sorbs_spam](#sorbs_spam)|62018|62766|17|0.0%|0.6%|
[sorbs_recent_spam](#sorbs_recent_spam)|62018|62766|17|0.0%|0.6%|
[sorbs_new_spam](#sorbs_new_spam)|62018|62766|17|0.0%|0.6%|
[nixspam](#nixspam)|16664|16664|14|0.0%|0.5%|
[snort_ipfilter](#snort_ipfilter)|9945|9945|7|0.0%|0.2%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|7|1.0%|0.2%|
[php_commenters](#php_commenters)|430|430|5|1.1%|0.1%|
[php_dictionary](#php_dictionary)|702|702|4|0.5%|0.1%|
[blocklist_de_mail](#blocklist_de_mail)|16274|16274|4|0.0%|0.1%|
[php_spammers](#php_spammers)|700|700|3|0.4%|0.1%|
[dragon_http](#dragon_http)|1044|273664|3|0.0%|0.1%|
[alienvault_reputation](#alienvault_reputation)|184538|184538|3|0.0%|0.1%|
[sorbs_web](#sorbs_web)|482|483|1|0.2%|0.0%|
[php_harvesters](#php_harvesters)|392|392|1|0.2%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|1|0.1%|0.0%|
[iw_spamlist](#iw_spamlist)|3758|3758|1|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.0%|
[dm_tor](#dm_tor)|6424|6424|1|0.0%|0.0%|
[bm_tor](#bm_tor)|6402|6402|1|0.0%|0.0%|

## ri_web_proxies

[rosinstrument.com](http://www.rosinstrument.com) open HTTP proxies (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://tools.rosinstrument.com/proxy/l100.xml).

The last time downloaded was found to be dated: Thu Jun 11 06:24:51 UTC 2015.

The ipset `ri_web_proxies` has **7712** entries, **7712** unique IPs.

The following table shows the overlaps of `ri_web_proxies` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ri_web_proxies`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ri_web_proxies`.
- ` this % ` is the percentage **of this ipset (`ri_web_proxies`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_proxies](#firehol_proxies)|12475|12745|7712|60.5%|100.0%|
[firehol_anonymous](#firehol_anonymous)|18924|82965|7712|9.2%|100.0%|
[firehol_level3](#firehol_level3)|109949|9627745|3671|0.0%|47.6%|
[stopforumspam_30d](#stopforumspam_30d)|94424|94424|3627|3.8%|47.0%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|1500|5.1%|19.4%|
[ri_connect_proxies](#ri_connect_proxies)|2784|2784|1182|42.4%|15.3%|
[xroxy](#xroxy)|2163|2163|957|44.2%|12.4%|
[firehol_level2](#firehol_level2)|20916|32554|692|2.1%|8.9%|
[proxyrss](#proxyrss)|1673|1673|664|39.6%|8.6%|
[proxz](#proxz)|1265|1265|581|45.9%|7.5%|
[stopforumspam_1d](#stopforumspam_1d)|6759|6759|476|7.0%|6.1%|
[blocklist_de](#blocklist_de)|27197|27197|444|1.6%|5.7%|
[blocklist_de_bots](#blocklist_de_bots)|2888|2888|362|12.5%|4.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|222|0.0%|2.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|218|0.0%|2.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|154|0.0%|1.9%|
[sorbs_spam](#sorbs_spam)|62018|62766|139|0.2%|1.8%|
[sorbs_recent_spam](#sorbs_recent_spam)|62018|62766|139|0.2%|1.8%|
[sorbs_new_spam](#sorbs_new_spam)|62018|62766|139|0.2%|1.8%|
[nixspam](#nixspam)|16664|16664|126|0.7%|1.6%|
[blocklist_de_mail](#blocklist_de_mail)|16274|16274|79|0.4%|1.0%|
[php_dictionary](#php_dictionary)|702|702|65|9.2%|0.8%|
[snort_ipfilter](#snort_ipfilter)|9945|9945|61|0.6%|0.7%|
[php_spammers](#php_spammers)|700|700|53|7.5%|0.6%|
[php_commenters](#php_commenters)|430|430|25|5.8%|0.3%|
[sorbs_web](#sorbs_web)|482|483|18|3.7%|0.2%|
[dragon_http](#dragon_http)|1044|273664|17|0.0%|0.2%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|14|2.1%|0.1%|
[iw_spamlist](#iw_spamlist)|3758|3758|12|0.3%|0.1%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|10|1.9%|0.1%|
[blocklist_de_strongips](#blocklist_de_strongips)|183|183|7|3.8%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|6|0.0%|0.0%|
[dm_tor](#dm_tor)|6424|6424|5|0.0%|0.0%|
[bm_tor](#bm_tor)|6402|6402|5|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|4|0.0%|0.0%|
[et_tor](#et_tor)|6400|6400|4|0.0%|0.0%|
[alienvault_reputation](#alienvault_reputation)|184538|184538|4|0.0%|0.0%|
[php_harvesters](#php_harvesters)|392|392|2|0.5%|0.0%|
[sslbl](#sslbl)|371|371|1|0.2%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|1|0.0%|0.0%|
[firehol_level1](#firehol_level1)|5133|688894588|1|0.0%|0.0%|
[et_compromised](#et_compromised)|1721|1721|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1705|1705|1|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3474|3474|1|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2798|2798|1|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14166|14166|1|0.0%|0.0%|

## shunlist

[AutoShun.org](http://autoshun.org/) IPs identified as hostile by correlating logs from distributed snort installations running the autoshun plugin

Source is downloaded from [this link](http://www.autoshun.org/files/shunlist.csv).

The last time downloaded was found to be dated: Thu Jun 11 03:30:03 UTC 2015.

The ipset `shunlist` has **1243** entries, **1243** unique IPs.

The following table shows the overlaps of `shunlist` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `shunlist`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `shunlist`.
- ` this % ` is the percentage **of this ipset (`shunlist`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level3](#firehol_level3)|109949|9627745|1243|0.0%|100.0%|
[alienvault_reputation](#alienvault_reputation)|184538|184538|1231|0.6%|99.0%|
[openbl_60d](#openbl_60d)|6997|6997|535|7.6%|43.0%|
[openbl_30d](#openbl_30d)|2829|2829|505|17.8%|40.6%|
[et_compromised](#et_compromised)|1721|1721|425|24.6%|34.1%|
[firehol_level2](#firehol_level2)|20916|32554|424|1.3%|34.1%|
[blocklist_de](#blocklist_de)|27197|27197|422|1.5%|33.9%|
[bruteforceblocker](#bruteforceblocker)|1705|1705|390|22.8%|31.3%|
[blocklist_de_ssh](#blocklist_de_ssh)|3474|3474|383|11.0%|30.8%|
[openbl_7d](#openbl_7d)|669|669|215|32.1%|17.2%|
[firehol_level1](#firehol_level1)|5133|688894588|181|0.0%|14.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|118|0.0%|9.4%|
[et_block](#et_block)|1000|18344011|114|0.0%|9.1%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|93|0.0%|7.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|69|0.0%|5.5%|
[openbl_1d](#openbl_1d)|144|144|65|45.1%|5.2%|
[sslbl](#sslbl)|371|371|61|16.4%|4.9%|
[dshield](#dshield)|20|5120|44|0.8%|3.5%|
[dragon_http](#dragon_http)|1044|273664|37|0.0%|2.9%|
[blocklist_de_apache](#blocklist_de_apache)|14166|14166|33|0.2%|2.6%|
[ciarmy](#ciarmy)|442|442|26|5.8%|2.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|25|0.0%|2.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|183|183|19|10.3%|1.5%|
[voipbl](#voipbl)|10533|10945|12|0.1%|0.9%|
[stopforumspam_30d](#stopforumspam_30d)|94424|94424|3|0.0%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|0.2%|
[blocklist_de_mail](#blocklist_de_mail)|16274|16274|3|0.0%|0.2%|
[blocklist_de_imap](#blocklist_de_imap)|1997|1997|3|0.1%|0.2%|
[sorbs_spam](#sorbs_spam)|62018|62766|2|0.0%|0.1%|
[sorbs_recent_spam](#sorbs_recent_spam)|62018|62766|2|0.0%|0.1%|
[sorbs_new_spam](#sorbs_new_spam)|62018|62766|2|0.0%|0.1%|
[blocklist_de_sip](#blocklist_de_sip)|80|80|2|2.5%|0.1%|
[tor_exits](#tor_exits)|1116|1116|1|0.0%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|1|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6759|6759|1|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9945|9945|1|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|1|0.1%|0.0%|
[firehol_proxies](#firehol_proxies)|12475|12745|1|0.0%|0.0%|
[firehol_anonymous](#firehol_anonymous)|18924|82965|1|0.0%|0.0%|
[et_tor](#et_tor)|6400|6400|1|0.0%|0.0%|
[dm_tor](#dm_tor)|6424|6424|1|0.0%|0.0%|
[bm_tor](#bm_tor)|6402|6402|1|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2798|2798|1|0.0%|0.0%|

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
[firehol_level3](#firehol_level3)|109949|9627745|9945|0.1%|100.0%|
[firehol_anonymous](#firehol_anonymous)|18924|82965|1242|1.4%|12.4%|
[et_tor](#et_tor)|6400|6400|1089|17.0%|10.9%|
[tor_exits](#tor_exits)|1116|1116|1082|96.9%|10.8%|
[bm_tor](#bm_tor)|6402|6402|1061|16.5%|10.6%|
[dm_tor](#dm_tor)|6424|6424|1059|16.4%|10.6%|
[sorbs_spam](#sorbs_spam)|62018|62766|883|1.4%|8.8%|
[sorbs_recent_spam](#sorbs_recent_spam)|62018|62766|883|1.4%|8.8%|
[sorbs_new_spam](#sorbs_new_spam)|62018|62766|883|1.4%|8.8%|
[stopforumspam_30d](#stopforumspam_30d)|94424|94424|809|0.8%|8.1%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|677|2.3%|6.8%|
[firehol_level2](#firehol_level2)|20916|32554|575|1.7%|5.7%|
[stopforumspam_1d](#stopforumspam_1d)|6759|6759|387|5.7%|3.8%|
[firehol_proxies](#firehol_proxies)|12475|12745|325|2.5%|3.2%|
[firehol_level1](#firehol_level1)|5133|688894588|301|0.0%|3.0%|
[et_block](#et_block)|1000|18344011|298|0.0%|2.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|241|0.0%|2.4%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|237|45.2%|2.3%|
[blocklist_de](#blocklist_de)|27197|27197|221|0.8%|2.2%|
[nixspam](#nixspam)|16664|16664|205|1.2%|2.0%|
[zeus](#zeus)|230|230|200|86.9%|2.0%|
[zeus_badips](#zeus_badips)|202|202|178|88.1%|1.7%|
[blocklist_de_mail](#blocklist_de_mail)|16274|16274|164|1.0%|1.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|147|0.0%|1.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|114|0.0%|1.1%|
[alienvault_reputation](#alienvault_reputation)|184538|184538|108|0.0%|1.0%|
[feodo](#feodo)|105|105|83|79.0%|0.8%|
[php_dictionary](#php_dictionary)|702|702|78|11.1%|0.7%|
[php_spammers](#php_spammers)|700|700|76|10.8%|0.7%|
[php_commenters](#php_commenters)|430|430|64|14.8%|0.6%|
[ri_web_proxies](#ri_web_proxies)|7712|7712|61|0.7%|0.6%|
[iw_spamlist](#iw_spamlist)|3758|3758|60|1.5%|0.6%|
[sorbs_web](#sorbs_web)|482|483|47|9.7%|0.4%|
[xroxy](#xroxy)|2163|2163|41|1.8%|0.4%|
[blocklist_de_apache](#blocklist_de_apache)|14166|14166|36|0.2%|0.3%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2798|2798|33|1.1%|0.3%|
[sslbl](#sslbl)|371|371|31|8.3%|0.3%|
[proxz](#proxz)|1265|1265|27|2.1%|0.2%|
[openbl_60d](#openbl_60d)|6997|6997|24|0.3%|0.2%|
[blocklist_de_bots](#blocklist_de_bots)|2888|2888|24|0.8%|0.2%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|19|0.0%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|14|0.0%|0.1%|
[php_harvesters](#php_harvesters)|392|392|12|3.0%|0.1%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|12|0.9%|0.1%|
[palevo](#palevo)|13|13|11|84.6%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|11|0.0%|0.1%|
[dragon_http](#dragon_http)|1044|273664|8|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2784|2784|7|0.2%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|6|0.0%|0.0%|
[proxyrss](#proxyrss)|1673|1673|4|0.2%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|1997|1997|4|0.2%|0.0%|
[openbl_30d](#openbl_30d)|2829|2829|2|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|2|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|183|183|2|1.0%|0.0%|
[voipbl](#voipbl)|10533|10945|1|0.0%|0.0%|
[virbl](#virbl)|28|28|1|3.5%|0.0%|
[sorbs_socks](#sorbs_socks)|5|5|1|20.0%|0.0%|
[sorbs_misc](#sorbs_misc)|5|5|1|20.0%|0.0%|
[sorbs_http](#sorbs_http)|5|5|1|20.0%|0.0%|
[shunlist](#shunlist)|1243|1243|1|0.0%|0.0%|
[openbl_7d](#openbl_7d)|669|669|1|0.1%|0.0%|
[openbl_1d](#openbl_1d)|144|144|1|0.6%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|1|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|1|0.1%|0.0%|
[dshield](#dshield)|20|5120|1|0.0%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|65|65|1|1.5%|0.0%|

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

The last time downloaded was found to be dated: Thu Jun 11 07:04:18 UTC 2015.

The ipset `sorbs_http` has **5** entries, **5** unique IPs.

The following table shows the overlaps of `sorbs_http` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `sorbs_http`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `sorbs_http`.
- ` this % ` is the percentage **of this ipset (`sorbs_http`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[sorbs_spam](#sorbs_spam)|62018|62766|5|0.0%|100.0%|
[sorbs_socks](#sorbs_socks)|5|5|5|100.0%|100.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|62018|62766|5|0.0%|100.0%|
[sorbs_new_spam](#sorbs_new_spam)|62018|62766|5|0.0%|100.0%|
[sorbs_misc](#sorbs_misc)|5|5|5|100.0%|100.0%|
[nixspam](#nixspam)|16664|16664|3|0.0%|60.0%|
[snort_ipfilter](#snort_ipfilter)|9945|9945|1|0.0%|20.0%|
[firehol_level3](#firehol_level3)|109949|9627745|1|0.0%|20.0%|

## sorbs_misc

[Sorbs.net](https://www.sorbs.net/) MISC proxies, extracted from deltas.

Source is downloaded from [this link]().

The last time downloaded was found to be dated: Thu Jun 11 07:04:19 UTC 2015.

The ipset `sorbs_misc` has **5** entries, **5** unique IPs.

The following table shows the overlaps of `sorbs_misc` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `sorbs_misc`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `sorbs_misc`.
- ` this % ` is the percentage **of this ipset (`sorbs_misc`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[sorbs_spam](#sorbs_spam)|62018|62766|5|0.0%|100.0%|
[sorbs_socks](#sorbs_socks)|5|5|5|100.0%|100.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|62018|62766|5|0.0%|100.0%|
[sorbs_new_spam](#sorbs_new_spam)|62018|62766|5|0.0%|100.0%|
[sorbs_http](#sorbs_http)|5|5|5|100.0%|100.0%|
[nixspam](#nixspam)|16664|16664|3|0.0%|60.0%|
[snort_ipfilter](#snort_ipfilter)|9945|9945|1|0.0%|20.0%|
[firehol_level3](#firehol_level3)|109949|9627745|1|0.0%|20.0%|

## sorbs_new_spam

[Sorbs.net](https://www.sorbs.net/) NEW Spam senders, extracted from deltas.

Source is downloaded from [this link]().

The last time downloaded was found to be dated: Thu Jun 11 07:04:19 UTC 2015.

The ipset `sorbs_new_spam` has **62018** entries, **62766** unique IPs.

The following table shows the overlaps of `sorbs_new_spam` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `sorbs_new_spam`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `sorbs_new_spam`.
- ` this % ` is the percentage **of this ipset (`sorbs_new_spam`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[sorbs_spam](#sorbs_spam)|62018|62766|62766|100.0%|100.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|62018|62766|62766|100.0%|100.0%|
[nixspam](#nixspam)|16664|16664|3061|18.3%|4.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|2642|0.0%|4.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|1669|0.0%|2.6%|
[firehol_level3](#firehol_level3)|109949|9627745|1259|0.0%|2.0%|
[firehol_level2](#firehol_level2)|20916|32554|1255|3.8%|1.9%|
[blocklist_de](#blocklist_de)|27197|27197|1244|4.5%|1.9%|
[iw_spamlist](#iw_spamlist)|3758|3758|1179|31.3%|1.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|1173|0.0%|1.8%|
[blocklist_de_mail](#blocklist_de_mail)|16274|16274|1154|7.0%|1.8%|
[snort_ipfilter](#snort_ipfilter)|9945|9945|883|8.8%|1.4%|
[stopforumspam_30d](#stopforumspam_30d)|94424|94424|298|0.3%|0.4%|
[sorbs_web](#sorbs_web)|482|483|259|53.6%|0.4%|
[firehol_anonymous](#firehol_anonymous)|18924|82965|194|0.2%|0.3%|
[php_dictionary](#php_dictionary)|702|702|192|27.3%|0.3%|
[firehol_proxies](#firehol_proxies)|12475|12745|189|1.4%|0.3%|
[php_spammers](#php_spammers)|700|700|166|23.7%|0.2%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|162|0.5%|0.2%|
[ri_web_proxies](#ri_web_proxies)|7712|7712|139|1.8%|0.2%|
[alienvault_reputation](#alienvault_reputation)|184538|184538|87|0.0%|0.1%|
[xroxy](#xroxy)|2163|2163|74|3.4%|0.1%|
[dragon_http](#dragon_http)|1044|273664|63|0.0%|0.1%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2798|2798|45|1.6%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14166|14166|45|0.3%|0.0%|
[proxz](#proxz)|1265|1265|42|3.3%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6759|6759|39|0.5%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|34|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|2888|2888|29|1.0%|0.0%|
[firehol_level1](#firehol_level1)|5133|688894588|25|0.0%|0.0%|
[php_commenters](#php_commenters)|430|430|22|5.1%|0.0%|
[et_block](#et_block)|1000|18344011|22|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|20|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|20|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|1997|1997|20|1.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2784|2784|17|0.6%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|15|0.0%|0.0%|
[php_harvesters](#php_harvesters)|392|392|14|3.5%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|1425|1425|13|0.9%|0.0%|
[proxyrss](#proxyrss)|1673|1673|7|0.4%|0.0%|
[tor_exits](#tor_exits)|1116|1116|5|0.4%|0.0%|
[sorbs_socks](#sorbs_socks)|5|5|5|100.0%|0.0%|
[sorbs_misc](#sorbs_misc)|5|5|5|100.0%|0.0%|
[sorbs_http](#sorbs_http)|5|5|5|100.0%|0.0%|
[sorbs_smtp](#sorbs_smtp)|4|4|4|100.0%|0.0%|
[et_tor](#et_tor)|6400|6400|4|0.0%|0.0%|
[dm_tor](#dm_tor)|6424|6424|4|0.0%|0.0%|
[bm_tor](#bm_tor)|6402|6402|4|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3474|3474|4|0.1%|0.0%|
[et_compromised](#et_compromised)|1721|1721|3|0.1%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1705|1705|3|0.1%|0.0%|
[voipbl](#voipbl)|10533|10945|2|0.0%|0.0%|
[shunlist](#shunlist)|1243|1243|2|0.1%|0.0%|
[openbl_60d](#openbl_60d)|6997|6997|2|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|2|0.1%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|183|183|2|1.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|1|0.1%|0.0%|
[malc0de](#malc0de)|313|313|1|0.3%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|1|0.1%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.0%|

## sorbs_recent_spam

[Sorbs.net](https://www.sorbs.net/) RECENT Spam senders, extracted from deltas.

Source is downloaded from [this link]().

The last time downloaded was found to be dated: Thu Jun 11 07:04:19 UTC 2015.

The ipset `sorbs_recent_spam` has **62018** entries, **62766** unique IPs.

The following table shows the overlaps of `sorbs_recent_spam` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `sorbs_recent_spam`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `sorbs_recent_spam`.
- ` this % ` is the percentage **of this ipset (`sorbs_recent_spam`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[sorbs_spam](#sorbs_spam)|62018|62766|62766|100.0%|100.0%|
[sorbs_new_spam](#sorbs_new_spam)|62018|62766|62766|100.0%|100.0%|
[nixspam](#nixspam)|16664|16664|3061|18.3%|4.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|2642|0.0%|4.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|1669|0.0%|2.6%|
[firehol_level3](#firehol_level3)|109949|9627745|1259|0.0%|2.0%|
[firehol_level2](#firehol_level2)|20916|32554|1255|3.8%|1.9%|
[blocklist_de](#blocklist_de)|27197|27197|1244|4.5%|1.9%|
[iw_spamlist](#iw_spamlist)|3758|3758|1179|31.3%|1.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|1173|0.0%|1.8%|
[blocklist_de_mail](#blocklist_de_mail)|16274|16274|1154|7.0%|1.8%|
[snort_ipfilter](#snort_ipfilter)|9945|9945|883|8.8%|1.4%|
[stopforumspam_30d](#stopforumspam_30d)|94424|94424|298|0.3%|0.4%|
[sorbs_web](#sorbs_web)|482|483|259|53.6%|0.4%|
[firehol_anonymous](#firehol_anonymous)|18924|82965|194|0.2%|0.3%|
[php_dictionary](#php_dictionary)|702|702|192|27.3%|0.3%|
[firehol_proxies](#firehol_proxies)|12475|12745|189|1.4%|0.3%|
[php_spammers](#php_spammers)|700|700|166|23.7%|0.2%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|162|0.5%|0.2%|
[ri_web_proxies](#ri_web_proxies)|7712|7712|139|1.8%|0.2%|
[alienvault_reputation](#alienvault_reputation)|184538|184538|87|0.0%|0.1%|
[xroxy](#xroxy)|2163|2163|74|3.4%|0.1%|
[dragon_http](#dragon_http)|1044|273664|63|0.0%|0.1%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2798|2798|45|1.6%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14166|14166|45|0.3%|0.0%|
[proxz](#proxz)|1265|1265|42|3.3%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6759|6759|39|0.5%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|34|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|2888|2888|29|1.0%|0.0%|
[firehol_level1](#firehol_level1)|5133|688894588|25|0.0%|0.0%|
[php_commenters](#php_commenters)|430|430|22|5.1%|0.0%|
[et_block](#et_block)|1000|18344011|22|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|20|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|20|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|1997|1997|20|1.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2784|2784|17|0.6%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|15|0.0%|0.0%|
[php_harvesters](#php_harvesters)|392|392|14|3.5%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|1425|1425|13|0.9%|0.0%|
[proxyrss](#proxyrss)|1673|1673|7|0.4%|0.0%|
[tor_exits](#tor_exits)|1116|1116|5|0.4%|0.0%|
[sorbs_socks](#sorbs_socks)|5|5|5|100.0%|0.0%|
[sorbs_misc](#sorbs_misc)|5|5|5|100.0%|0.0%|
[sorbs_http](#sorbs_http)|5|5|5|100.0%|0.0%|
[sorbs_smtp](#sorbs_smtp)|4|4|4|100.0%|0.0%|
[et_tor](#et_tor)|6400|6400|4|0.0%|0.0%|
[dm_tor](#dm_tor)|6424|6424|4|0.0%|0.0%|
[bm_tor](#bm_tor)|6402|6402|4|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3474|3474|4|0.1%|0.0%|
[et_compromised](#et_compromised)|1721|1721|3|0.1%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1705|1705|3|0.1%|0.0%|
[voipbl](#voipbl)|10533|10945|2|0.0%|0.0%|
[shunlist](#shunlist)|1243|1243|2|0.1%|0.0%|
[openbl_60d](#openbl_60d)|6997|6997|2|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|2|0.1%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|183|183|2|1.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|1|0.1%|0.0%|
[malc0de](#malc0de)|313|313|1|0.3%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|1|0.1%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.0%|

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
[sorbs_spam](#sorbs_spam)|62018|62766|4|0.0%|100.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|62018|62766|4|0.0%|100.0%|
[sorbs_new_spam](#sorbs_new_spam)|62018|62766|4|0.0%|100.0%|

## sorbs_socks

[Sorbs.net](https://www.sorbs.net/) SOCKS proxies, extracted from deltas.

Source is downloaded from [this link]().

The last time downloaded was found to be dated: Thu Jun 11 07:04:19 UTC 2015.

The ipset `sorbs_socks` has **5** entries, **5** unique IPs.

The following table shows the overlaps of `sorbs_socks` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `sorbs_socks`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `sorbs_socks`.
- ` this % ` is the percentage **of this ipset (`sorbs_socks`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[sorbs_spam](#sorbs_spam)|62018|62766|5|0.0%|100.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|62018|62766|5|0.0%|100.0%|
[sorbs_new_spam](#sorbs_new_spam)|62018|62766|5|0.0%|100.0%|
[sorbs_misc](#sorbs_misc)|5|5|5|100.0%|100.0%|
[sorbs_http](#sorbs_http)|5|5|5|100.0%|100.0%|
[nixspam](#nixspam)|16664|16664|3|0.0%|60.0%|
[snort_ipfilter](#snort_ipfilter)|9945|9945|1|0.0%|20.0%|
[firehol_level3](#firehol_level3)|109949|9627745|1|0.0%|20.0%|

## sorbs_spam

[Sorbs.net](https://www.sorbs.net/) Spam senders, extracted from deltas.

Source is downloaded from [this link]().

The last time downloaded was found to be dated: Thu Jun 11 07:04:19 UTC 2015.

The ipset `sorbs_spam` has **62018** entries, **62766** unique IPs.

The following table shows the overlaps of `sorbs_spam` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `sorbs_spam`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `sorbs_spam`.
- ` this % ` is the percentage **of this ipset (`sorbs_spam`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[sorbs_recent_spam](#sorbs_recent_spam)|62018|62766|62766|100.0%|100.0%|
[sorbs_new_spam](#sorbs_new_spam)|62018|62766|62766|100.0%|100.0%|
[nixspam](#nixspam)|16664|16664|3061|18.3%|4.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|2642|0.0%|4.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|1669|0.0%|2.6%|
[firehol_level3](#firehol_level3)|109949|9627745|1259|0.0%|2.0%|
[firehol_level2](#firehol_level2)|20916|32554|1255|3.8%|1.9%|
[blocklist_de](#blocklist_de)|27197|27197|1244|4.5%|1.9%|
[iw_spamlist](#iw_spamlist)|3758|3758|1179|31.3%|1.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|1173|0.0%|1.8%|
[blocklist_de_mail](#blocklist_de_mail)|16274|16274|1154|7.0%|1.8%|
[snort_ipfilter](#snort_ipfilter)|9945|9945|883|8.8%|1.4%|
[stopforumspam_30d](#stopforumspam_30d)|94424|94424|298|0.3%|0.4%|
[sorbs_web](#sorbs_web)|482|483|259|53.6%|0.4%|
[firehol_anonymous](#firehol_anonymous)|18924|82965|194|0.2%|0.3%|
[php_dictionary](#php_dictionary)|702|702|192|27.3%|0.3%|
[firehol_proxies](#firehol_proxies)|12475|12745|189|1.4%|0.3%|
[php_spammers](#php_spammers)|700|700|166|23.7%|0.2%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|162|0.5%|0.2%|
[ri_web_proxies](#ri_web_proxies)|7712|7712|139|1.8%|0.2%|
[alienvault_reputation](#alienvault_reputation)|184538|184538|87|0.0%|0.1%|
[xroxy](#xroxy)|2163|2163|74|3.4%|0.1%|
[dragon_http](#dragon_http)|1044|273664|63|0.0%|0.1%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2798|2798|45|1.6%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14166|14166|45|0.3%|0.0%|
[proxz](#proxz)|1265|1265|42|3.3%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6759|6759|39|0.5%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|34|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|2888|2888|29|1.0%|0.0%|
[firehol_level1](#firehol_level1)|5133|688894588|25|0.0%|0.0%|
[php_commenters](#php_commenters)|430|430|22|5.1%|0.0%|
[et_block](#et_block)|1000|18344011|22|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|20|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|20|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|1997|1997|20|1.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2784|2784|17|0.6%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|15|0.0%|0.0%|
[php_harvesters](#php_harvesters)|392|392|14|3.5%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|1425|1425|13|0.9%|0.0%|
[proxyrss](#proxyrss)|1673|1673|7|0.4%|0.0%|
[tor_exits](#tor_exits)|1116|1116|5|0.4%|0.0%|
[sorbs_socks](#sorbs_socks)|5|5|5|100.0%|0.0%|
[sorbs_misc](#sorbs_misc)|5|5|5|100.0%|0.0%|
[sorbs_http](#sorbs_http)|5|5|5|100.0%|0.0%|
[sorbs_smtp](#sorbs_smtp)|4|4|4|100.0%|0.0%|
[et_tor](#et_tor)|6400|6400|4|0.0%|0.0%|
[dm_tor](#dm_tor)|6424|6424|4|0.0%|0.0%|
[bm_tor](#bm_tor)|6402|6402|4|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3474|3474|4|0.1%|0.0%|
[et_compromised](#et_compromised)|1721|1721|3|0.1%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1705|1705|3|0.1%|0.0%|
[voipbl](#voipbl)|10533|10945|2|0.0%|0.0%|
[shunlist](#shunlist)|1243|1243|2|0.1%|0.0%|
[openbl_60d](#openbl_60d)|6997|6997|2|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|2|0.1%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|183|183|2|1.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|1|0.1%|0.0%|
[malc0de](#malc0de)|313|313|1|0.3%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|1|0.1%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.0%|

## sorbs_web

[Sorbs.net](https://www.sorbs.net/) WEB exploits, extracted from deltas.

Source is downloaded from [this link]().

The last time downloaded was found to be dated: Thu Jun 11 07:04:19 UTC 2015.

The ipset `sorbs_web` has **482** entries, **483** unique IPs.

The following table shows the overlaps of `sorbs_web` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `sorbs_web`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `sorbs_web`.
- ` this % ` is the percentage **of this ipset (`sorbs_web`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[sorbs_spam](#sorbs_spam)|62018|62766|259|0.4%|53.6%|
[sorbs_recent_spam](#sorbs_recent_spam)|62018|62766|259|0.4%|53.6%|
[sorbs_new_spam](#sorbs_new_spam)|62018|62766|259|0.4%|53.6%|
[nixspam](#nixspam)|16664|16664|79|0.4%|16.3%|
[firehol_level3](#firehol_level3)|109949|9627745|62|0.0%|12.8%|
[firehol_level2](#firehol_level2)|20916|32554|59|0.1%|12.2%|
[blocklist_de](#blocklist_de)|27197|27197|59|0.2%|12.2%|
[blocklist_de_mail](#blocklist_de_mail)|16274|16274|51|0.3%|10.5%|
[snort_ipfilter](#snort_ipfilter)|9945|9945|47|0.4%|9.7%|
[stopforumspam_30d](#stopforumspam_30d)|94424|94424|38|0.0%|7.8%|
[php_dictionary](#php_dictionary)|702|702|29|4.1%|6.0%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|28|0.0%|5.7%|
[iw_spamlist](#iw_spamlist)|3758|3758|27|0.7%|5.5%|
[firehol_proxies](#firehol_proxies)|12475|12745|25|0.1%|5.1%|
[firehol_anonymous](#firehol_anonymous)|18924|82965|25|0.0%|5.1%|
[php_spammers](#php_spammers)|700|700|23|3.2%|4.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|21|0.0%|4.3%|
[ri_web_proxies](#ri_web_proxies)|7712|7712|18|0.2%|3.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|16|0.0%|3.3%|
[xroxy](#xroxy)|2163|2163|13|0.6%|2.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|12|0.0%|2.4%|
[proxz](#proxz)|1265|1265|8|0.6%|1.6%|
[blocklist_de_bots](#blocklist_de_bots)|2888|2888|7|0.2%|1.4%|
[stopforumspam_1d](#stopforumspam_1d)|6759|6759|6|0.0%|1.2%|
[php_commenters](#php_commenters)|430|430|2|0.4%|0.4%|
[blocklist_de_strongips](#blocklist_de_strongips)|183|183|2|1.0%|0.4%|
[ri_connect_proxies](#ri_connect_proxies)|2784|2784|1|0.0%|0.2%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|1|0.0%|0.2%|
[dragon_http](#dragon_http)|1044|273664|1|0.0%|0.2%|
[blocklist_de_ftp](#blocklist_de_ftp)|1425|1425|1|0.0%|0.2%|

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
[firehol_level1](#firehol_level1)|5133|688894588|18340608|2.6%|100.0%|
[et_block](#et_block)|1000|18344011|18338560|99.9%|99.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|8532506|2.4%|46.5%|
[firehol_level3](#firehol_level3)|109949|9627745|6933037|72.0%|37.8%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|6932480|75.5%|37.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|2272265|0.2%|12.3%|
[fullbogons](#fullbogons)|3770|670213096|151552|0.0%|0.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|130368|0.0%|0.7%|
[alienvault_reputation](#alienvault_reputation)|184538|184538|1372|0.7%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1037|0.3%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|94424|94424|1021|1.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|512|0.1%|0.0%|
[firehol_level2](#firehol_level2)|20916|32554|274|0.8%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|271|0.9%|0.0%|
[dshield](#dshield)|20|5120|256|5.0%|0.0%|
[dragon_http](#dragon_http)|1044|273664|256|0.0%|0.0%|
[openbl_60d](#openbl_60d)|6997|6997|235|3.3%|0.0%|
[blocklist_de](#blocklist_de)|27197|27197|214|0.7%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3474|3474|133|3.8%|0.0%|
[openbl_30d](#openbl_30d)|2829|2829|119|4.2%|0.0%|
[nixspam](#nixspam)|16664|16664|112|0.6%|0.0%|
[et_compromised](#et_compromised)|1721|1721|101|5.8%|0.0%|
[shunlist](#shunlist)|1243|1243|93|7.4%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6759|6759|79|1.1%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1705|1705|65|3.8%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|2888|2888|56|1.9%|0.0%|
[openbl_7d](#openbl_7d)|669|669|51|7.6%|0.0%|
[php_commenters](#php_commenters)|430|430|29|6.7%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|29|2.2%|0.0%|
[sorbs_spam](#sorbs_spam)|62018|62766|20|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|62018|62766|20|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|62018|62766|20|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|16274|16274|20|0.1%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9945|9945|19|0.1%|0.0%|
[zeus_badips](#zeus_badips)|202|202|15|7.4%|0.0%|
[zeus](#zeus)|230|230|15|6.5%|0.0%|
[voipbl](#voipbl)|10533|10945|14|0.1%|0.0%|
[openbl_1d](#openbl_1d)|144|144|13|9.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|1997|1997|10|0.5%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|183|183|8|4.3%|0.0%|
[php_dictionary](#php_dictionary)|702|702|6|0.8%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|6|0.4%|0.0%|
[firehol_anonymous](#firehol_anonymous)|18924|82965|6|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|5|0.0%|0.0%|
[php_spammers](#php_spammers)|700|700|4|0.5%|0.0%|
[nt_malware_http](#nt_malware_http)|69|69|4|5.7%|0.0%|
[malc0de](#malc0de)|313|313|4|1.2%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2798|2798|4|0.1%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14166|14166|4|0.0%|0.0%|
[nt_malware_irc](#nt_malware_irc)|43|43|3|6.9%|0.0%|
[iw_spamlist](#iw_spamlist)|3758|3758|3|0.0%|0.0%|
[firehol_proxies](#firehol_proxies)|12475|12745|3|0.0%|0.0%|
[et_tor](#et_tor)|6400|6400|3|0.0%|0.0%|
[dm_tor](#dm_tor)|6424|6424|3|0.0%|0.0%|
[bm_tor](#bm_tor)|6402|6402|3|0.0%|0.0%|
[tor_exits](#tor_exits)|1116|1116|2|0.1%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|2|0.3%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|80|80|2|2.5%|0.0%|
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
[firehol_level1](#firehol_level1)|5133|688894588|487424|0.0%|100.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|270785|0.1%|55.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|98904|0.0%|20.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|33155|0.0%|6.8%|
[et_block](#et_block)|1000|18344011|517|0.0%|0.1%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|512|0.0%|0.1%|
[firehol_level3](#firehol_level3)|109949|9627745|88|0.0%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|94424|94424|78|0.0%|0.0%|
[sorbs_spam](#sorbs_spam)|62018|62766|20|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|62018|62766|20|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|62018|62766|20|0.0%|0.0%|
[alienvault_reputation](#alienvault_reputation)|184538|184538|14|0.0%|0.0%|
[php_commenters](#php_commenters)|430|430|8|1.8%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|7|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9945|9945|6|0.0%|0.0%|
[firehol_level2](#firehol_level2)|20916|32554|6|0.0%|0.0%|
[zeus_badips](#zeus_badips)|202|202|5|2.4%|0.0%|
[zeus](#zeus)|230|230|5|2.1%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|2888|2888|5|0.1%|0.0%|
[blocklist_de](#blocklist_de)|27197|27197|5|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|183|183|4|2.1%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6759|6759|2|0.0%|0.0%|
[php_harvesters](#php_harvesters)|392|392|1|0.2%|0.0%|
[openbl_60d](#openbl_60d)|6997|6997|1|0.0%|0.0%|
[openbl_30d](#openbl_30d)|2829|2829|1|0.0%|0.0%|
[malc0de](#malc0de)|313|313|1|0.3%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.0%|

## sslbl

[Abuse.ch SSL Blacklist](https://sslbl.abuse.ch/) bad SSL traffic related to malware or botnet activities - **excellent list**

Source is downloaded from [this link](https://sslbl.abuse.ch/blacklist/sslipblacklist.csv).

The last time downloaded was found to be dated: Thu Jun 11 07:15:06 UTC 2015.

The ipset `sslbl` has **371** entries, **371** unique IPs.

The following table shows the overlaps of `sslbl` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `sslbl`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `sslbl`.
- ` this % ` is the percentage **of this ipset (`sslbl`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level1](#firehol_level1)|5133|688894588|371|0.0%|100.0%|
[firehol_level3](#firehol_level3)|109949|9627745|92|0.0%|24.7%|
[alienvault_reputation](#alienvault_reputation)|184538|184538|65|0.0%|17.5%|
[shunlist](#shunlist)|1243|1243|61|4.9%|16.4%|
[feodo](#feodo)|105|105|38|36.1%|10.2%|
[et_block](#et_block)|1000|18344011|38|0.0%|10.2%|
[snort_ipfilter](#snort_ipfilter)|9945|9945|31|0.3%|8.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|28|0.0%|7.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|6|0.0%|1.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|3|0.0%|0.8%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|1|0.0%|0.2%|
[ri_web_proxies](#ri_web_proxies)|7712|7712|1|0.0%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.2%|
[firehol_proxies](#firehol_proxies)|12475|12745|1|0.0%|0.2%|
[firehol_anonymous](#firehol_anonymous)|18924|82965|1|0.0%|0.2%|
[dragon_http](#dragon_http)|1044|273664|1|0.0%|0.2%|

## stopforumspam_1d

[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers in the last 24 hours - **excellent list**

Source is downloaded from [this link](http://www.stopforumspam.com/downloads/listed_ip_1.zip).

The last time downloaded was found to be dated: Thu Jun 11 07:00:02 UTC 2015.

The ipset `stopforumspam_1d` has **6759** entries, **6759** unique IPs.

The following table shows the overlaps of `stopforumspam_1d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `stopforumspam_1d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `stopforumspam_1d`.
- ` this % ` is the percentage **of this ipset (`stopforumspam_1d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|20916|32554|6759|20.7%|100.0%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|6053|20.7%|89.5%|
[firehol_level3](#firehol_level3)|109949|9627745|4891|0.0%|72.3%|
[stopforumspam_30d](#stopforumspam_30d)|94424|94424|4863|5.1%|71.9%|
[blocklist_de](#blocklist_de)|27197|27197|1423|5.2%|21.0%|
[blocklist_de_bots](#blocklist_de_bots)|2888|2888|1359|47.0%|20.1%|
[firehol_anonymous](#firehol_anonymous)|18924|82965|1081|1.3%|15.9%|
[firehol_proxies](#firehol_proxies)|12475|12745|912|7.1%|13.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|511|0.0%|7.5%|
[ri_web_proxies](#ri_web_proxies)|7712|7712|476|6.1%|7.0%|
[snort_ipfilter](#snort_ipfilter)|9945|9945|387|3.8%|5.7%|
[proxyrss](#proxyrss)|1673|1673|387|23.1%|5.7%|
[tor_exits](#tor_exits)|1116|1116|360|32.2%|5.3%|
[et_tor](#et_tor)|6400|6400|349|5.4%|5.1%|
[dm_tor](#dm_tor)|6424|6424|349|5.4%|5.1%|
[bm_tor](#bm_tor)|6402|6402|349|5.4%|5.1%|
[xroxy](#xroxy)|2163|2163|241|11.1%|3.5%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|215|41.0%|3.1%|
[proxz](#proxz)|1265|1265|191|15.0%|2.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|185|0.0%|2.7%|
[php_commenters](#php_commenters)|430|430|166|38.6%|2.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|144|0.0%|2.1%|
[ri_connect_proxies](#ri_connect_proxies)|2784|2784|125|4.4%|1.8%|
[blocklist_de_strongips](#blocklist_de_strongips)|183|183|112|61.2%|1.6%|
[firehol_level1](#firehol_level1)|5133|688894588|82|0.0%|1.2%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|79|0.0%|1.1%|
[et_block](#et_block)|1000|18344011|79|0.0%|1.1%|
[blocklist_de_apache](#blocklist_de_apache)|14166|14166|69|0.4%|1.0%|
[alienvault_reputation](#alienvault_reputation)|184538|184538|49|0.0%|0.7%|
[php_harvesters](#php_harvesters)|392|392|44|11.2%|0.6%|
[nixspam](#nixspam)|16664|16664|42|0.2%|0.6%|
[blocklist_de_mail](#blocklist_de_mail)|16274|16274|41|0.2%|0.6%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2798|2798|40|1.4%|0.5%|
[sorbs_spam](#sorbs_spam)|62018|62766|39|0.0%|0.5%|
[sorbs_recent_spam](#sorbs_recent_spam)|62018|62766|39|0.0%|0.5%|
[sorbs_new_spam](#sorbs_new_spam)|62018|62766|39|0.0%|0.5%|
[php_spammers](#php_spammers)|700|700|34|4.8%|0.5%|
[php_dictionary](#php_dictionary)|702|702|26|3.7%|0.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|26|0.0%|0.3%|
[openbl_60d](#openbl_60d)|6997|6997|19|0.2%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|12|0.0%|0.1%|
[dragon_http](#dragon_http)|1044|273664|8|0.0%|0.1%|
[iw_spamlist](#iw_spamlist)|3758|3758|7|0.1%|0.1%|
[sorbs_web](#sorbs_web)|482|483|6|1.2%|0.0%|
[voipbl](#voipbl)|10533|10945|4|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|4|0.6%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|2|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|2|0.1%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|2|0.0%|0.0%|
[zeus_badips](#zeus_badips)|202|202|1|0.4%|0.0%|
[zeus](#zeus)|230|230|1|0.4%|0.0%|
[shunlist](#shunlist)|1243|1243|1|0.0%|0.0%|
[openbl_30d](#openbl_30d)|2829|2829|1|0.0%|0.0%|
[fullbogons](#fullbogons)|3770|670213096|1|0.0%|0.0%|
[et_compromised](#et_compromised)|1721|1721|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1705|1705|1|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|1997|1997|1|0.0%|0.0%|

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
[firehol_level3](#firehol_level3)|109949|9627745|94424|0.9%|100.0%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|27851|95.4%|29.4%|
[firehol_level2](#firehol_level2)|20916|32554|6238|19.1%|6.6%|
[firehol_anonymous](#firehol_anonymous)|18924|82965|6167|7.4%|6.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|5840|0.0%|6.1%|
[firehol_proxies](#firehol_proxies)|12475|12745|5561|43.6%|5.8%|
[stopforumspam_1d](#stopforumspam_1d)|6759|6759|4863|71.9%|5.1%|
[ri_web_proxies](#ri_web_proxies)|7712|7712|3627|47.0%|3.8%|
[blocklist_de](#blocklist_de)|27197|27197|2602|9.5%|2.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|2508|0.0%|2.6%|
[blocklist_de_bots](#blocklist_de_bots)|2888|2888|2222|76.9%|2.3%|
[ri_connect_proxies](#ri_connect_proxies)|2784|2784|1558|55.9%|1.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|1516|0.0%|1.6%|
[xroxy](#xroxy)|2163|2163|1276|58.9%|1.3%|
[firehol_level1](#firehol_level1)|5133|688894588|1100|0.0%|1.1%|
[et_block](#et_block)|1000|18344011|1025|0.0%|1.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|1021|0.0%|1.0%|
[snort_ipfilter](#snort_ipfilter)|9945|9945|809|8.1%|0.8%|
[proxyrss](#proxyrss)|1673|1673|766|45.7%|0.8%|
[proxz](#proxz)|1265|1265|739|58.4%|0.7%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|731|0.0%|0.7%|
[et_tor](#et_tor)|6400|6400|649|10.1%|0.6%|
[bm_tor](#bm_tor)|6402|6402|642|10.0%|0.6%|
[dm_tor](#dm_tor)|6424|6424|640|9.9%|0.6%|
[tor_exits](#tor_exits)|1116|1116|627|56.1%|0.6%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|342|65.2%|0.3%|
[php_commenters](#php_commenters)|430|430|318|73.9%|0.3%|
[sorbs_spam](#sorbs_spam)|62018|62766|298|0.4%|0.3%|
[sorbs_recent_spam](#sorbs_recent_spam)|62018|62766|298|0.4%|0.3%|
[sorbs_new_spam](#sorbs_new_spam)|62018|62766|298|0.4%|0.3%|
[blocklist_de_mail](#blocklist_de_mail)|16274|16274|263|1.6%|0.2%|
[blocklist_de_apache](#blocklist_de_apache)|14166|14166|214|1.5%|0.2%|
[nixspam](#nixspam)|16664|16664|203|1.2%|0.2%|
[alienvault_reputation](#alienvault_reputation)|184538|184538|170|0.0%|0.1%|
[php_spammers](#php_spammers)|700|700|144|20.5%|0.1%|
[blocklist_de_strongips](#blocklist_de_strongips)|183|183|138|75.4%|0.1%|
[php_dictionary](#php_dictionary)|702|702|133|18.9%|0.1%|
[dragon_http](#dragon_http)|1044|273664|115|0.0%|0.1%|
[php_harvesters](#php_harvesters)|392|392|84|21.4%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|78|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2798|2798|77|2.7%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|49|0.0%|0.0%|
[openbl_60d](#openbl_60d)|6997|6997|48|0.6%|0.0%|
[sorbs_web](#sorbs_web)|482|483|38|7.8%|0.0%|
[voipbl](#voipbl)|10533|10945|35|0.3%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3474|3474|24|0.6%|0.0%|
[iw_spamlist](#iw_spamlist)|3758|3758|20|0.5%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|1425|1425|20|1.4%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|19|2.8%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|16|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|1997|1997|14|0.7%|0.0%|
[et_compromised](#et_compromised)|1721|1721|12|0.6%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1705|1705|12|0.7%|0.0%|
[openbl_30d](#openbl_30d)|2829|2829|5|0.1%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|4|0.3%|0.0%|
[shunlist](#shunlist)|1243|1243|3|0.2%|0.0%|
[zeus_badips](#zeus_badips)|202|202|2|0.9%|0.0%|
[zeus](#zeus)|230|230|2|0.8%|0.0%|
[openbl_7d](#openbl_7d)|669|669|2|0.2%|0.0%|
[nt_malware_http](#nt_malware_http)|69|69|2|2.8%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|2|0.1%|0.0%|
[virbl](#virbl)|28|28|1|3.5%|0.0%|
[openbl_1d](#openbl_1d)|144|144|1|0.6%|0.0%|
[iw_wormlist](#iw_wormlist)|33|33|1|3.0%|0.0%|
[fullbogons](#fullbogons)|3770|670213096|1|0.0%|0.0%|
[dshield](#dshield)|20|5120|1|0.0%|0.0%|
[ciarmy](#ciarmy)|442|442|1|0.2%|0.0%|

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
[firehol_level3](#firehol_level3)|109949|9627745|27875|0.2%|95.5%|
[stopforumspam_30d](#stopforumspam_30d)|94424|94424|27851|29.4%|95.4%|
[firehol_level2](#firehol_level2)|20916|32554|7037|21.6%|24.1%|
[stopforumspam_1d](#stopforumspam_1d)|6759|6759|6053|89.5%|20.7%|
[firehol_anonymous](#firehol_anonymous)|18924|82965|2823|3.4%|9.6%|
[firehol_proxies](#firehol_proxies)|12475|12745|2448|19.2%|8.3%|
[blocklist_de](#blocklist_de)|27197|27197|2348|8.6%|8.0%|
[blocklist_de_bots](#blocklist_de_bots)|2888|2888|2139|74.0%|7.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|1953|0.0%|6.6%|
[ri_web_proxies](#ri_web_proxies)|7712|7712|1500|19.4%|5.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|768|0.0%|2.6%|
[snort_ipfilter](#snort_ipfilter)|9945|9945|677|6.8%|2.3%|
[proxyrss](#proxyrss)|1673|1673|634|37.8%|2.1%|
[xroxy](#xroxy)|2163|2163|610|28.2%|2.0%|
[ri_connect_proxies](#ri_connect_proxies)|2784|2784|555|19.9%|1.9%|
[tor_exits](#tor_exits)|1116|1116|548|49.1%|1.8%|
[et_tor](#et_tor)|6400|6400|547|8.5%|1.8%|
[bm_tor](#bm_tor)|6402|6402|540|8.4%|1.8%|
[dm_tor](#dm_tor)|6424|6424|538|8.3%|1.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|506|0.0%|1.7%|
[proxz](#proxz)|1265|1265|483|38.1%|1.6%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|286|54.5%|0.9%|
[firehol_level1](#firehol_level1)|5133|688894588|278|0.0%|0.9%|
[et_block](#et_block)|1000|18344011|272|0.0%|0.9%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|271|0.0%|0.9%|
[php_commenters](#php_commenters)|430|430|240|55.8%|0.8%|
[sorbs_spam](#sorbs_spam)|62018|62766|162|0.2%|0.5%|
[sorbs_recent_spam](#sorbs_recent_spam)|62018|62766|162|0.2%|0.5%|
[sorbs_new_spam](#sorbs_new_spam)|62018|62766|162|0.2%|0.5%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|147|0.0%|0.5%|
[blocklist_de_mail](#blocklist_de_mail)|16274|16274|147|0.9%|0.5%|
[nixspam](#nixspam)|16664|16664|131|0.7%|0.4%|
[blocklist_de_apache](#blocklist_de_apache)|14166|14166|127|0.8%|0.4%|
[blocklist_de_strongips](#blocklist_de_strongips)|183|183|125|68.3%|0.4%|
[php_spammers](#php_spammers)|700|700|91|13.0%|0.3%|
[php_dictionary](#php_dictionary)|702|702|90|12.8%|0.3%|
[alienvault_reputation](#alienvault_reputation)|184538|184538|89|0.0%|0.3%|
[php_harvesters](#php_harvesters)|392|392|61|15.5%|0.2%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2798|2798|61|2.1%|0.2%|
[dragon_http](#dragon_http)|1044|273664|36|0.0%|0.1%|
[sorbs_web](#sorbs_web)|482|483|28|5.7%|0.0%|
[openbl_60d](#openbl_60d)|6997|6997|27|0.3%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|20|0.0%|0.0%|
[iw_spamlist](#iw_spamlist)|3758|3758|18|0.4%|0.0%|
[voipbl](#voipbl)|10533|10945|14|0.1%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|11|1.6%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|7|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|7|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|1425|1425|6|0.4%|0.0%|
[et_compromised](#et_compromised)|1721|1721|5|0.2%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3474|3474|5|0.1%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1705|1705|4|0.2%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|1997|1997|3|0.1%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|2|0.1%|0.0%|
[zeus_badips](#zeus_badips)|202|202|1|0.4%|0.0%|
[zeus](#zeus)|230|230|1|0.4%|0.0%|
[shunlist](#shunlist)|1243|1243|1|0.0%|0.0%|
[openbl_30d](#openbl_30d)|2829|2829|1|0.0%|0.0%|
[iw_wormlist](#iw_wormlist)|33|33|1|3.0%|0.0%|
[fullbogons](#fullbogons)|3770|670213096|1|0.0%|0.0%|

## tor_exits

[TorProject.org](https://www.torproject.org) list of all current TOR exit points (TorDNSEL)

Source is downloaded from [this link](https://check.torproject.org/exit-addresses).

The last time downloaded was found to be dated: Thu Jun 11 07:03:46 UTC 2015.

The ipset `tor_exits` has **1116** entries, **1116** unique IPs.

The following table shows the overlaps of `tor_exits` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `tor_exits`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `tor_exits`.
- ` this % ` is the percentage **of this ipset (`tor_exits`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_anonymous](#firehol_anonymous)|18924|82965|1116|1.3%|100.0%|
[firehol_level3](#firehol_level3)|109949|9627745|1083|0.0%|97.0%|
[snort_ipfilter](#snort_ipfilter)|9945|9945|1082|10.8%|96.9%|
[dm_tor](#dm_tor)|6424|6424|1021|15.8%|91.4%|
[bm_tor](#bm_tor)|6402|6402|1013|15.8%|90.7%|
[et_tor](#et_tor)|6400|6400|971|15.1%|87.0%|
[stopforumspam_30d](#stopforumspam_30d)|94424|94424|627|0.6%|56.1%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|548|1.8%|49.1%|
[firehol_level2](#firehol_level2)|20916|32554|370|1.1%|33.1%|
[stopforumspam_1d](#stopforumspam_1d)|6759|6759|360|5.3%|32.2%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|231|44.0%|20.6%|
[firehol_proxies](#firehol_proxies)|12475|12745|231|1.8%|20.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|128|0.0%|11.4%|
[php_commenters](#php_commenters)|430|430|51|11.8%|4.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|38|0.0%|3.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|37|0.0%|3.3%|
[alienvault_reputation](#alienvault_reputation)|184538|184538|30|0.0%|2.6%|
[blocklist_de](#blocklist_de)|27197|27197|24|0.0%|2.1%|
[blocklist_de_apache](#blocklist_de_apache)|14166|14166|23|0.1%|2.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2798|2798|21|0.7%|1.8%|
[openbl_60d](#openbl_60d)|6997|6997|20|0.2%|1.7%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|8|0.0%|0.7%|
[nixspam](#nixspam)|16664|16664|7|0.0%|0.6%|
[php_harvesters](#php_harvesters)|392|392|6|1.5%|0.5%|
[sorbs_spam](#sorbs_spam)|62018|62766|5|0.0%|0.4%|
[sorbs_recent_spam](#sorbs_recent_spam)|62018|62766|5|0.0%|0.4%|
[sorbs_new_spam](#sorbs_new_spam)|62018|62766|5|0.0%|0.4%|
[php_spammers](#php_spammers)|700|700|5|0.7%|0.4%|
[php_dictionary](#php_dictionary)|702|702|4|0.5%|0.3%|
[dragon_http](#dragon_http)|1044|273664|3|0.0%|0.2%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|2|0.0%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2|0.0%|0.1%|
[firehol_level1](#firehol_level1)|5133|688894588|2|0.0%|0.1%|
[et_block](#et_block)|1000|18344011|2|0.0%|0.1%|
[blocklist_de_mail](#blocklist_de_mail)|16274|16274|2|0.0%|0.1%|
[shunlist](#shunlist)|1243|1243|1|0.0%|0.0%|
[iw_spamlist](#iw_spamlist)|3758|3758|1|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|2888|2888|1|0.0%|0.0%|

## virbl

[VirBL](http://virbl.bit.nl/) is a project of which the idea was born during the RIPE-48 meeting. The plan was to get reports of virusscanning mailservers, and put the IP-addresses that were reported to send viruses on a blacklist.

Source is downloaded from [this link](http://virbl.bit.nl/download/virbl.dnsbl.bit.nl.txt).

The last time downloaded was found to be dated: Thu Jun 11 06:42:03 UTC 2015.

The ipset `virbl` has **28** entries, **28** unique IPs.

The following table shows the overlaps of `virbl` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `virbl`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `virbl`.
- ` this % ` is the percentage **of this ipset (`virbl`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level3](#firehol_level3)|109949|9627745|28|0.0%|100.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|2|0.0%|7.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|2|0.0%|7.1%|
[stopforumspam_30d](#stopforumspam_30d)|94424|94424|1|0.0%|3.5%|
[snort_ipfilter](#snort_ipfilter)|9945|9945|1|0.0%|3.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|1|0.0%|3.5%|
[fullbogons](#fullbogons)|3770|670213096|1|0.0%|3.5%|
[firehol_level1](#firehol_level1)|5133|688894588|1|0.0%|3.5%|

## voipbl

[VoIPBL.org](http://www.voipbl.org/) a distributed VoIP blacklist that is aimed to protects against VoIP Fraud and minimizing abuse for network that have publicly accessible PBX's. Several algorithms, external sources and manual confirmation are used before they categorize something as an attack and determine the threat level.

Source is downloaded from [this link](http://www.voipbl.org/update/).

The last time downloaded was found to be dated: Thu Jun 11 07:00:53 UTC 2015.

The ipset `voipbl` has **10533** entries, **10945** unique IPs.

The following table shows the overlaps of `voipbl` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `voipbl`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `voipbl`.
- ` this % ` is the percentage **of this ipset (`voipbl`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|1605|0.0%|14.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|434|0.0%|3.9%|
[firehol_level1](#firehol_level1)|5133|688894588|333|0.0%|3.0%|
[fullbogons](#fullbogons)|3770|670213096|319|0.0%|2.9%|
[bogons](#bogons)|13|592708608|319|0.0%|2.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|299|0.0%|2.7%|
[alienvault_reputation](#alienvault_reputation)|184538|184538|183|0.0%|1.6%|
[firehol_anonymous](#firehol_anonymous)|18924|82965|79|0.0%|0.7%|
[firehol_level3](#firehol_level3)|109949|9627745|57|0.0%|0.5%|
[stopforumspam_30d](#stopforumspam_30d)|94424|94424|35|0.0%|0.3%|
[firehol_level2](#firehol_level2)|20916|32554|35|0.1%|0.3%|
[blocklist_de](#blocklist_de)|27197|27197|31|0.1%|0.2%|
[blocklist_de_sip](#blocklist_de_sip)|80|80|26|32.5%|0.2%|
[dragon_http](#dragon_http)|1044|273664|25|0.0%|0.2%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|14|0.0%|0.1%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|14|0.0%|0.1%|
[et_block](#et_block)|1000|18344011|14|0.0%|0.1%|
[shunlist](#shunlist)|1243|1243|12|0.9%|0.1%|
[openbl_60d](#openbl_60d)|6997|6997|8|0.1%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6759|6759|4|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|4|0.0%|0.0%|
[openbl_30d](#openbl_30d)|2829|2829|3|0.1%|0.0%|
[et_tor](#et_tor)|6400|6400|3|0.0%|0.0%|
[et_compromised](#et_compromised)|1721|1721|3|0.1%|0.0%|
[dm_tor](#dm_tor)|6424|6424|3|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1705|1705|3|0.1%|0.0%|
[bm_tor](#bm_tor)|6402|6402|3|0.0%|0.0%|
[sorbs_spam](#sorbs_spam)|62018|62766|2|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|62018|62766|2|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|62018|62766|2|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|2|0.3%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|2|0.0%|0.0%|
[firehol_proxies](#firehol_proxies)|12475|12745|2|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3474|3474|2|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14166|14166|2|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9945|9945|1|0.0%|0.0%|
[nixspam](#nixspam)|16664|16664|1|0.0%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.0%|
[ciarmy](#ciarmy)|442|442|1|0.2%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|16274|16274|1|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2798|2798|1|0.0%|0.0%|

## xroxy

[xroxy.com](http://www.xroxy.com) open proxies (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.xroxy.com/proxyrss.xml).

The last time downloaded was found to be dated: Thu Jun 11 06:33:02 UTC 2015.

The ipset `xroxy` has **2163** entries, **2163** unique IPs.

The following table shows the overlaps of `xroxy` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `xroxy`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `xroxy`.
- ` this % ` is the percentage **of this ipset (`xroxy`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_proxies](#firehol_proxies)|12475|12745|2163|16.9%|100.0%|
[firehol_anonymous](#firehol_anonymous)|18924|82965|2163|2.6%|100.0%|
[firehol_level3](#firehol_level3)|109949|9627745|1292|0.0%|59.7%|
[stopforumspam_30d](#stopforumspam_30d)|94424|94424|1276|1.3%|58.9%|
[ri_web_proxies](#ri_web_proxies)|7712|7712|957|12.4%|44.2%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|610|2.0%|28.2%|
[proxz](#proxz)|1265|1265|448|35.4%|20.7%|
[ri_connect_proxies](#ri_connect_proxies)|2784|2784|393|14.1%|18.1%|
[proxyrss](#proxyrss)|1673|1673|374|22.3%|17.2%|
[firehol_level2](#firehol_level2)|20916|32554|344|1.0%|15.9%|
[stopforumspam_1d](#stopforumspam_1d)|6759|6759|241|3.5%|11.1%|
[blocklist_de](#blocklist_de)|27197|27197|215|0.7%|9.9%|
[blocklist_de_bots](#blocklist_de_bots)|2888|2888|158|5.4%|7.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|110|0.0%|5.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|104|0.0%|4.8%|
[sorbs_spam](#sorbs_spam)|62018|62766|74|0.1%|3.4%|
[sorbs_recent_spam](#sorbs_recent_spam)|62018|62766|74|0.1%|3.4%|
[sorbs_new_spam](#sorbs_new_spam)|62018|62766|74|0.1%|3.4%|
[nixspam](#nixspam)|16664|16664|66|0.3%|3.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|58|0.0%|2.6%|
[blocklist_de_mail](#blocklist_de_mail)|16274|16274|56|0.3%|2.5%|
[snort_ipfilter](#snort_ipfilter)|9945|9945|41|0.4%|1.8%|
[php_dictionary](#php_dictionary)|702|702|39|5.5%|1.8%|
[php_spammers](#php_spammers)|700|700|32|4.5%|1.4%|
[sorbs_web](#sorbs_web)|482|483|13|2.6%|0.6%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|13|1.9%|0.6%|
[php_commenters](#php_commenters)|430|430|10|2.3%|0.4%|
[dragon_http](#dragon_http)|1044|273664|8|0.0%|0.3%|
[blocklist_de_strongips](#blocklist_de_strongips)|183|183|6|3.2%|0.2%|
[alienvault_reputation](#alienvault_reputation)|184538|184538|5|0.0%|0.2%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|3|0.5%|0.1%|
[iw_spamlist](#iw_spamlist)|3758|3758|3|0.0%|0.1%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|3|0.0%|0.1%|
[php_harvesters](#php_harvesters)|392|392|2|0.5%|0.0%|
[dm_tor](#dm_tor)|6424|6424|2|0.0%|0.0%|
[bm_tor](#bm_tor)|6402|6402|2|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.0%|
[et_tor](#et_tor)|6400|6400|1|0.0%|0.0%|
[et_compromised](#et_compromised)|1721|1721|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1705|1705|1|0.0%|0.0%|

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
[firehol_level1](#firehol_level1)|5133|688894588|230|0.0%|100.0%|
[et_block](#et_block)|1000|18344011|228|0.0%|99.1%|
[firehol_level3](#firehol_level3)|109949|9627745|203|0.0%|88.2%|
[zeus_badips](#zeus_badips)|202|202|202|100.0%|87.8%|
[snort_ipfilter](#snort_ipfilter)|9945|9945|200|2.0%|86.9%|
[alienvault_reputation](#alienvault_reputation)|184538|184538|61|0.0%|26.5%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|15|0.0%|6.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|14|0.0%|6.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|10|0.0%|4.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|9|0.0%|3.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|7|0.0%|3.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|5|0.0%|2.1%|
[firehol_level2](#firehol_level2)|20916|32554|3|0.0%|1.3%|
[dragon_http](#dragon_http)|1044|273664|3|0.0%|1.3%|
[stopforumspam_30d](#stopforumspam_30d)|94424|94424|2|0.0%|0.8%|
[openbl_60d](#openbl_60d)|6997|6997|2|0.0%|0.8%|
[openbl_30d](#openbl_30d)|2829|2829|2|0.0%|0.8%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|1|0.0%|0.4%|
[stopforumspam_1d](#stopforumspam_1d)|6759|6759|1|0.0%|0.4%|
[php_commenters](#php_commenters)|430|430|1|0.2%|0.4%|
[openbl_7d](#openbl_7d)|669|669|1|0.1%|0.4%|
[openbl_1d](#openbl_1d)|144|144|1|0.6%|0.4%|
[nixspam](#nixspam)|16664|16664|1|0.0%|0.4%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|1|0.0%|0.4%|
[iw_spamlist](#iw_spamlist)|3758|3758|1|0.0%|0.4%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.4%|
[blocklist_de_mail](#blocklist_de_mail)|16274|16274|1|0.0%|0.4%|
[blocklist_de](#blocklist_de)|27197|27197|1|0.0%|0.4%|

## zeus_badips

[Abuse.ch Zeus tracker](https://zeustracker.abuse.ch) badips includes IPv4 addresses that are used by the ZeuS trojan. It is the recommened blocklist if you want to block only ZeuS IPs. It excludes IP addresses that ZeuS Tracker believes to be hijacked (level 2) or belong to a free web hosting provider (level 3). Hence the false postive rate should be much lower compared to the standard ZeuS IP blocklist. **excellent list**

Source is downloaded from [this link](https://zeustracker.abuse.ch/blocklist.php?download=badips).

The last time downloaded was found to be dated: Thu Jun 11 07:18:22 UTC 2015.

The ipset `zeus_badips` has **202** entries, **202** unique IPs.

The following table shows the overlaps of `zeus_badips` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `zeus_badips`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `zeus_badips`.
- ` this % ` is the percentage **of this ipset (`zeus_badips`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[zeus](#zeus)|230|230|202|87.8%|100.0%|
[firehol_level1](#firehol_level1)|5133|688894588|202|0.0%|100.0%|
[et_block](#et_block)|1000|18344011|202|0.0%|100.0%|
[firehol_level3](#firehol_level3)|109949|9627745|180|0.0%|89.1%|
[snort_ipfilter](#snort_ipfilter)|9945|9945|178|1.7%|88.1%|
[alienvault_reputation](#alienvault_reputation)|184538|184538|37|0.0%|18.3%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|15|0.0%|7.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|10|0.0%|4.9%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|10|0.0%|4.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|8|0.0%|3.9%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|5|0.0%|2.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|4|0.0%|1.9%|
[firehol_level2](#firehol_level2)|20916|32554|3|0.0%|1.4%|
[dragon_http](#dragon_http)|1044|273664|3|0.0%|1.4%|
[stopforumspam_30d](#stopforumspam_30d)|94424|94424|2|0.0%|0.9%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|1|0.0%|0.4%|
[stopforumspam_1d](#stopforumspam_1d)|6759|6759|1|0.0%|0.4%|
[php_commenters](#php_commenters)|430|430|1|0.2%|0.4%|
[openbl_7d](#openbl_7d)|669|669|1|0.1%|0.4%|
[openbl_60d](#openbl_60d)|6997|6997|1|0.0%|0.4%|
[openbl_30d](#openbl_30d)|2829|2829|1|0.0%|0.4%|
[openbl_1d](#openbl_1d)|144|144|1|0.6%|0.4%|
[nixspam](#nixspam)|16664|16664|1|0.0%|0.4%|
[iw_spamlist](#iw_spamlist)|3758|3758|1|0.0%|0.4%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.4%|
[blocklist_de_mail](#blocklist_de_mail)|16274|16274|1|0.0%|0.4%|
[blocklist_de](#blocklist_de)|27197|27197|1|0.0%|0.4%|
