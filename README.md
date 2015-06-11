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

The following list was automatically generated on Thu Jun 11 17:46:13 UTC 2015.

The update frequency is the maximum allowed by internal configuration. A list will never be downloaded sooner than the update frequency stated. A list may also not be downloaded, after this frequency expired, if it has not been modified on the server (as reported by HTTP `IF_MODIFIED_SINCE` method).

name|info|type|entries|update|
:--:|:--:|:--:|:-----:|:----:|
[alienvault_reputation](#alienvault_reputation)|[AlienVault.com](https://www.alienvault.com/) IP reputation database (this list seems to include port scanning hosts and to be updated regularly, but we found no information about its retention policy)|ipv4 hash:ip|192275 unique IPs|updated every 6 hours  from [this link](https://reputation.alienvault.com/reputation.generic)
[blocklist_de](#blocklist_de)|[Blocklist.de](https://www.blocklist.de/) IPs that have been detected by fail2ban in the last 48 hours - **excellent list**|ipv4 hash:ip|28768 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/all.txt)
[blocklist_de_apache](#blocklist_de_apache)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service Apache, Apache-DDOS, RFI-Attacks.|ipv4 hash:ip|14231 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/apache.txt)
[blocklist_de_bots](#blocklist_de_bots)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the RFI-Attacks, REG-Bots, IRC-Bots or BadBots (BadBots = he has posted a Spam-Comment on a open Forum or Wiki).|ipv4 hash:ip|2925 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/bots.txt)
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|[Blocklist.de](https://www.blocklist.de/) All IPs which attacks Joomlas, Wordpress and other Web-Logins with Brute-Force Logins.|ipv4 hash:ip|2863 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/bruteforcelogin.txt)
[blocklist_de_ftp](#blocklist_de_ftp)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours for attacks on the Service FTP.|ipv4 hash:ip|1448 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/ftp.txt)
[blocklist_de_imap](#blocklist_de_imap)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours for attacks on the Service imap, sasl, pop3, etc.|ipv4 hash:ip|2597 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/imap.txt)
[blocklist_de_mail](#blocklist_de_mail)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service Mail, Postfix.|ipv4 hash:ip|17874 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/mail.txt)
[blocklist_de_sip](#blocklist_de_sip)|[Blocklist.de](https://www.blocklist.de/) All IP addresses that tried to login in a SIP, VOIP or Asterisk Server and are included in the IPs list from [infiltrated.net](www.infiltrated.net)|ipv4 hash:ip|84 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/sip.txt)
[blocklist_de_ssh](#blocklist_de_ssh)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service SSH.|ipv4 hash:ip|3225 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/ssh.txt)
[blocklist_de_strongips](#blocklist_de_strongips)|[Blocklist.de](https://www.blocklist.de/) All IPs which are older then 2 month and have more then 5.000 attacks.|ipv4 hash:ip|175 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/strongips.txt)
[bm_tor](#bm_tor)|[torstatus.blutmagie.de](https://torstatus.blutmagie.de) list of all TOR network servers|ipv4 hash:ip|6528 unique IPs|updated every 30 mins  from [this link](https://torstatus.blutmagie.de/ip_list_all.php/Tor_ip_list_ALL.csv)
[bogons](#bogons)|[Team-Cymru.org](http://www.team-cymru.org) private and reserved addresses defined by RFC 1918, RFC 5735, and RFC 6598 and netblocks that have not been allocated to a regional internet registry - **excellent list - use it only your internet interface**|ipv4 hash:net|13 subnets, 592708608 unique IPs|updated every 1 day  from [this link](http://www.team-cymru.org/Services/Bogons/bogon-bn-agg.txt)
[bruteforceblocker](#bruteforceblocker)|[danger.rulez.sk](http://danger.rulez.sk/) IPs detected by [bruteforceblocker](http://danger.rulez.sk/index.php/bruteforceblocker/) (fail2ban alternative for SSH on OpenBSD). This is an automatically generated list from users reporting failed authentication attempts. An IP seems to be included if 3 or more users report it. Its retention pocily seems 30 days.|ipv4 hash:ip|1700 unique IPs|updated every 3 hours  from [this link](http://danger.rulez.sk/projects/bruteforceblocker/blist.php)
[ciarmy](#ciarmy)|[CIArmy.com](http://ciarmy.com/) IPs with poor Rogue Packet score that have not yet been identified as malicious by the community|ipv4 hash:ip|473 unique IPs|updated every 3 hours  from [this link](http://cinsscore.com/list/ci-badguys.txt)
[cleanmx_viruses](#cleanmx_viruses)|[Clean-MX.de](http://support.clean-mx.de/clean-mx/viruses.php) IPs with viruses|ipv4 hash:ip|115 unique IPs|updated every 12 hours  from [this link](http://support.clean-mx.de/clean-mx/xmlviruses.php?sort=id%20desc&response=alive)
[dm_tor](#dm_tor)|[dan.me.uk](https://www.dan.me.uk) dynamic list of TOR nodes|ipv4 hash:ip|6506 unique IPs|updated every 30 mins  from [this link](https://www.dan.me.uk/torlist/)
[dragon_http](#dragon_http)|[Dragon Search Group](http://www.dragonresearchgroup.org/) IPs that have been seen sending HTTP requests to Dragon Research Pods in the last 7 days. This report lists hosts that are highly suspicious and are likely conducting malicious HTTP attacks. LEGITIMATE SEARCH ENGINE BOTS MAY BE IN THIS LIST. This report is informational.  It is not a blacklist, but some operators may choose to use it to help protect their networks and hosts in the forms of automated reporting and mitigation services.|ipv4 hash:net|1029 subnets, 270336 unique IPs|updated every 1 day  from [this link](http://www.dragonresearchgroup.org/insight/http-report.txt)
[dshield](#dshield)|[DShield.org](https://dshield.org/) top 20 attacking class C (/24) subnets over the last three days - **excellent list**|ipv4 hash:net|20 subnets, 5120 unique IPs|updated every 4 hours  from [this link](http://feeds.dshield.org/block.txt)
[et_block](#et_block)|[EmergingThreats.net](http://www.emergingthreats.net/) default blacklist (at the time of writing includes spamhaus DROP, dshield and abuse.ch trackers, which are available separately too - prefer to use the direct ipsets instead of this, they seem to lag a bit in updates)|ipv4 hash:net|1000 subnets, 18344011 unique IPs|updated every 12 hours  from [this link](http://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt)
[et_botcc](#et_botcc)|[EmergingThreats.net Command and Control IPs](http://doc.emergingthreats.net/bin/view/Main/BotCC) These IPs are updates every 24 hours and should be considered VERY highly reliable indications that a host is communicating with a known and active Bot or Malware command and control server - (although they say this includes abuse.ch trackers, it does not - most probably it is the shadowserver.org C&C list)|ipv4 hash:ip|506 unique IPs|updated every 12 hours  from [this link](http://rules.emergingthreats.net/fwrules/emerging-PIX-CC.rules)
[et_compromised](#et_compromised)|[EmergingThreats.net compromised hosts](http://doc.emergingthreats.net/bin/view/Main/CompromisedHost) - (this seems to be based on bruteforceblocker)|ipv4 hash:ip|1721 unique IPs|updated every 12 hours  from [this link](http://rules.emergingthreats.net/blockrules/compromised-ips.txt)
et_dshield|[EmergingThreats.net](http://www.emergingthreats.net/) dshield blocklist|ipv4 hash:net|disabled|updated every 12 hours  from [this link](http://rules.emergingthreats.net/fwrules/emerging-PIX-DSHIELD.rules)
et_spamhaus|[EmergingThreats.net](http://www.emergingthreats.net/) spamhaus blocklist|ipv4 hash:net|disabled|updated every 12 hours  from [this link](http://rules.emergingthreats.net/fwrules/emerging-PIX-DROP.rules)
[et_tor](#et_tor)|[EmergingThreats.net](http://www.emergingthreats.net/) [list](http://doc.emergingthreats.net/bin/view/Main/TorRules) of TOR network IPs|ipv4 hash:ip|6400 unique IPs|updated every 12 hours  from [this link](http://rules.emergingthreats.net/blockrules/emerging-tor.rules)
[feodo](#feodo)|[Abuse.ch Feodo tracker](https://feodotracker.abuse.ch) trojan includes IPs which are being used by Feodo (also known as Cridex or Bugat) which commits ebanking fraud - **excellent list**|ipv4 hash:ip|105 unique IPs|updated every 30 mins  from [this link](https://feodotracker.abuse.ch/blocklist/?download=ipblocklist)
[firehol_anonymous](#firehol_anonymous)|**FireHOL Anonymous** - Known anonymizing IPs. (includes: firehol_proxies anonymous bm_tor dm_tor tor_exits)|ipv4 hash:net|18960 subnets, 82998 unique IPs|
[firehol_level1](#firehol_level1)|**FireHOL Level 1** - Maximum protection without false positives. (includes: fullbogons dshield feodo palevo sslbl zeus spamhaus_drop spamhaus_edrop)|ipv4 hash:net|5137 subnets, 688854492 unique IPs|
[firehol_level2](#firehol_level2)|**FireHOL Level 2** - Maximum protection from attacks took place in the last 48 hours. (includes: openbl_1d blocklist_de stopforumspam_1d)|ipv4 hash:net|22462 subnets, 34082 unique IPs|
[firehol_level3](#firehol_level3)|**FireHOL Level 3** - All the bad IPs in last 30 days. (includes: openbl_30d stopforumspam_30d virbl malc0de shunlist malwaredomainlist bruteforceblocker ciarmy cleanmx_viruses snort_ipfilter ib_bluetack_spyware ib_bluetack_hijacked ib_bluetack_webexploit php_commenters php_dictionary php_harvesters php_spammers iw_wormlist)|ipv4 hash:net|109650 subnets, 9627417 unique IPs|
[firehol_proxies](#firehol_proxies)|**FireHOL Proxies** - Known open proxies in the last 30 days. (includes: ib_bluetack_proxies maxmind_proxy_fraud proxyrss proxz ri_connect_proxies ri_web_proxies xroxy)|ipv4 hash:net|12379 subnets, 12646 unique IPs|
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
[iw_spamlist](#iw_spamlist)|[ImproWare Antispam](http://antispam.imp.ch/) IPs sending spam, in the last 3 days|ipv4 hash:ip|3818 unique IPs|updated every 1 hour  from [this link](http://antispam.imp.ch/spamlist)
[iw_wormlist](#iw_wormlist)|[ImproWare Antispam](http://antispam.imp.ch/) IPs sending emails with viruses or worms, in the last 3 days|ipv4 hash:ip|34 unique IPs|updated every 1 hour  from [this link](http://antispam.imp.ch/wormlist)
lashback_ubl|[The LashBack UBL](http://blacklist.lashback.com/) The Unsubscribe Blacklist (UBL) is a real-time blacklist of IP addresses which are sending email to names harvested from suppression files (this is a big list, more than 500.000 IPs)|ipv4 hash:ip|disabled|updated every 1 day  from [this link](http://www.unsubscore.com/blacklist.txt)
[malc0de](#malc0de)|[Malc0de.com](http://malc0de.com) malicious IPs of the last 30 days|ipv4 hash:ip|276 unique IPs|updated every 1 day  from [this link](http://malc0de.com/bl/IP_Blacklist.txt)
[malwaredomainlist](#malwaredomainlist)|[malwaredomainlist.com](http://www.malwaredomainlist.com) list of malware active ip addresses|ipv4 hash:ip|1288 unique IPs|updated every 12 hours  from [this link](http://www.malwaredomainlist.com/hostslist/ip.txt)
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|[MaxMind.com](https://www.maxmind.com/en/anonymous-proxy-fraudulent-ip-address-list) list of anonymous proxy fraudelent IP addresses.|ipv4 hash:ip|524 unique IPs|updated every 4 hours  from [this link](https://www.maxmind.com/en/anonymous-proxy-fraudulent-ip-address-list)
[nixspam](#nixspam)|[NiX Spam](http://www.heise.de/ix/NiX-Spam-DNSBL-and-blacklist-for-download-499637.html) IP addresses that sent spam in the last hour - automatically generated entries without distinguishing open proxies from relays, dialup gateways, and so on. All IPs are removed after 12 hours if there is no spam from there.|ipv4 hash:ip|25392 unique IPs|updated every 15 mins  from [this link](http://www.dnsbl.manitu.net/download/nixspam-ip.dump.gz)
[nt_malware_http](#nt_malware_http)|[No Think](http://www.nothink.org/) Malware HTTP|ipv4 hash:ip|69 unique IPs|updated every 1 hour  from [this link](http://www.nothink.org/blacklist/blacklist_malware_http.txt)
[nt_malware_irc](#nt_malware_irc)|[No Think](http://www.nothink.org/) Malware IRC|ipv4 hash:ip|43 unique IPs|updated every 1 hour  from [this link](http://www.nothink.org/blacklist/blacklist_malware_irc.txt)
[nt_ssh_7d](#nt_ssh_7d)|[No Think](http://www.nothink.org/) Last 7 days SSH attacks|ipv4 hash:ip|0 unique IPs|updated every 1 hour  from [this link](http://www.nothink.org/blacklist/blacklist_ssh_week.txt)
openbl|[OpenBL.org](http://www.openbl.org/) default blacklist (currently it is the same with 90 days). OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications - **excellent list**|ipv4 hash:ip|disabled|updated every 4 hours  from [this link](http://www.openbl.org/lists/base.txt)
openbl_180d|[OpenBL.org](http://www.openbl.org/) last 180 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|disabled|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_180days.txt)
[openbl_1d](#openbl_1d)|[OpenBL.org](http://www.openbl.org/) last 24 hours IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|141 unique IPs|updated every 1 hour  from [this link](http://www.openbl.org/lists/base_1days.txt)
[openbl_30d](#openbl_30d)|[OpenBL.org](http://www.openbl.org/) last 30 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|2809 unique IPs|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_30days.txt)
openbl_360d|[OpenBL.org](http://www.openbl.org/) last 360 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|disabled|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_360days.txt)
[openbl_60d](#openbl_60d)|[OpenBL.org](http://www.openbl.org/) last 60 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|6984 unique IPs|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_60days.txt)
[openbl_7d](#openbl_7d)|[OpenBL.org](http://www.openbl.org/) last 7 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|628 unique IPs|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_7days.txt)
openbl_90d|[OpenBL.org](http://www.openbl.org/) last 90 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|disabled|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_90days.txt)
openbl_all|[OpenBL.org](http://www.openbl.org/) last all IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|disabled|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_all.txt)
[palevo](#palevo)|[Abuse.ch Palevo tracker](https://palevotracker.abuse.ch) worm includes IPs which are being used as botnet C&C for the Palevo crimeware - **excellent list**|ipv4 hash:ip|13 unique IPs|updated every 30 mins  from [this link](https://palevotracker.abuse.ch/blocklists.php?download=ipblocklist)
php_bad|[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) bad web hosts (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|disabled|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=b&rss=1)
[php_commenters](#php_commenters)|[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) comment spammers (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|430 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=c&rss=1)
[php_dictionary](#php_dictionary)|[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) directory attackers (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|737 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=d&rss=1)
[php_harvesters](#php_harvesters)|[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) harvesters (IPs that surf the internet looking for email addresses) (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|392 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=h&rss=1)
[php_spammers](#php_spammers)|[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) spam servers (IPs used by spammers to send messages) (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|735 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=s&rss=1)
[proxyrss](#proxyrss)|[proxyrss.com](http://www.proxyrss.com) open proxies syndicated from multiple sources.|ipv4 hash:ip|1373 unique IPs|updated every 4 hours  from [this link](http://www.proxyrss.com/proxylists/all.gz)
[proxz](#proxz)|[proxz.com](http://www.proxz.com) open proxies (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|1307 unique IPs|updated every 1 hour  from [this link](http://www.proxz.com/proxylists.xml)
[ri_connect_proxies](#ri_connect_proxies)|[rosinstrument.com](http://www.rosinstrument.com) open CONNECT proxies (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|2811 unique IPs|updated every 1 hour  from [this link](http://tools.rosinstrument.com/proxy/plab100.xml)
[ri_web_proxies](#ri_web_proxies)|[rosinstrument.com](http://www.rosinstrument.com) open HTTP proxies (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|7800 unique IPs|updated every 1 hour  from [this link](http://tools.rosinstrument.com/proxy/l100.xml)
[shunlist](#shunlist)|[AutoShun.org](http://autoshun.org/) IPs identified as hostile by correlating logs from distributed snort installations running the autoshun plugin|ipv4 hash:ip|1278 unique IPs|updated every 4 hours  from [this link](http://www.autoshun.org/files/shunlist.csv)
[snort_ipfilter](#snort_ipfilter)|[labs.snort.org](https://labs.snort.org/) supplied IP blacklist (this list seems to be updated frequently, but we found no information about it)|ipv4 hash:ip|9671 unique IPs|updated every 12 hours  from [this link](http://labs.snort.org/feeds/ip-filter.blf)
[sorbs_dul](#sorbs_dul)|[Sorbs.net](https://www.sorbs.net/) DUL, Dynamic User IPs extracted from deltas.|ipv4 hash:net|10 subnets, 4864 unique IPs|
[sorbs_http](#sorbs_http)|[Sorbs.net](https://www.sorbs.net/) HTTP proxies, extracted from deltas.|ipv4 hash:net|7 subnets, 7 unique IPs|
[sorbs_misc](#sorbs_misc)|[Sorbs.net](https://www.sorbs.net/) MISC proxies, extracted from deltas.|ipv4 hash:net|7 subnets, 7 unique IPs|
[sorbs_new_spam](#sorbs_new_spam)|[Sorbs.net](https://www.sorbs.net/) NEW Spam senders, extracted from deltas.|ipv4 hash:net|64467 subnets, 65300 unique IPs|
[sorbs_recent_spam](#sorbs_recent_spam)|[Sorbs.net](https://www.sorbs.net/) RECENT Spam senders, extracted from deltas.|ipv4 hash:net|64467 subnets, 65300 unique IPs|
[sorbs_smtp](#sorbs_smtp)|[Sorbs.net](https://www.sorbs.net/) SMTP Open Relays, extracted from deltas.|ipv4 hash:net|5 subnets, 5 unique IPs|
[sorbs_socks](#sorbs_socks)|[Sorbs.net](https://www.sorbs.net/) SOCKS proxies, extracted from deltas.|ipv4 hash:net|7 subnets, 7 unique IPs|
[sorbs_spam](#sorbs_spam)|[Sorbs.net](https://www.sorbs.net/) Spam senders, extracted from deltas.|ipv4 hash:net|64701 subnets, 65536 unique IPs|
[sorbs_web](#sorbs_web)|[Sorbs.net](https://www.sorbs.net/) WEB exploits, extracted from deltas.|ipv4 hash:net|544 subnets, 545 unique IPs|
[spamhaus_drop](#spamhaus_drop)|[Spamhaus.org](http://www.spamhaus.org) DROP list (according to their site this list should be dropped at tier-1 ISPs globaly) - **excellent list**|ipv4 hash:net|653 subnets, 18340608 unique IPs|updated every 12 hours  from [this link](http://www.spamhaus.org/drop/drop.txt)
[spamhaus_edrop](#spamhaus_edrop)|[Spamhaus.org](http://www.spamhaus.org) EDROP (extended matches that should be used with DROP) - **excellent list**|ipv4 hash:net|56 subnets, 487424 unique IPs|updated every 12 hours  from [this link](http://www.spamhaus.org/drop/edrop.txt)
[sslbl](#sslbl)|[Abuse.ch SSL Blacklist](https://sslbl.abuse.ch/) bad SSL traffic related to malware or botnet activities - **excellent list**|ipv4 hash:ip|371 unique IPs|updated every 30 mins  from [this link](https://sslbl.abuse.ch/blacklist/sslipblacklist.csv)
stopforumspam_180d|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 180 days)|ipv4 hash:ip|disabled|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/listed_ip_180.zip)
[stopforumspam_1d](#stopforumspam_1d)|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers in the last 24 hours - **excellent list**|ipv4 hash:ip|6745 unique IPs|updated every 1 hour  from [this link](http://www.stopforumspam.com/downloads/listed_ip_1.zip)
[stopforumspam_30d](#stopforumspam_30d)|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 30 days)|ipv4 hash:ip|94309 unique IPs|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/listed_ip_30.zip)
stopforumspam_365d|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 365 days)|ipv4 hash:ip|disabled|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/listed_ip_365.zip)
[stopforumspam_7d](#stopforumspam_7d)|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 7 days)|ipv4 hash:ip|29185 unique IPs|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/listed_ip_7.zip)
stopforumspam_90d|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 90 days)|ipv4 hash:ip|disabled|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/listed_ip_90.zip)
stopforumspam_ever|[StopForumSpam.com](http://www.stopforumspam.com) all IPs used by forum spammers, **ever** (normally you don't want to use this ipset, use the hourly one which includes last 24 hours IPs or the 7 days one)|ipv4 hash:ip|disabled|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/bannedips.zip)
[tor_exits](#tor_exits)|[TorProject.org](https://www.torproject.org) list of all current TOR exit points (TorDNSEL)|ipv4 hash:ip|1116 unique IPs|updated every 30 mins  from [this link](https://check.torproject.org/exit-addresses)
[virbl](#virbl)|[VirBL](http://virbl.bit.nl/) is a project of which the idea was born during the RIPE-48 meeting. The plan was to get reports of virusscanning mailservers, and put the IP-addresses that were reported to send viruses on a blacklist.|ipv4 hash:ip|19 unique IPs|updated every 1 hour  from [this link](http://virbl.bit.nl/download/virbl.dnsbl.bit.nl.txt)
[voipbl](#voipbl)|[VoIPBL.org](http://www.voipbl.org/) a distributed VoIP blacklist that is aimed to protects against VoIP Fraud and minimizing abuse for network that have publicly accessible PBX's. Several algorithms, external sources and manual confirmation are used before they categorize something as an attack and determine the threat level.|ipv4 hash:net|10586 subnets, 10998 unique IPs|updated every 4 hours  from [this link](http://www.voipbl.org/update/)
[xroxy](#xroxy)|[xroxy.com](http://www.xroxy.com) open proxies (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|2168 unique IPs|updated every 1 hour  from [this link](http://www.xroxy.com/proxyrss.xml)
[zeus](#zeus)|[Abuse.ch Zeus tracker](https://zeustracker.abuse.ch) standard, contains the same data as the ZeuS IP blocklist (zeus_badips) but with the slight difference that it doesn't exclude hijacked websites (level 2) and free web hosting providers (level 3). This means that this blocklist contains all IPv4 addresses associated with ZeuS C&Cs which are currently being tracked by ZeuS Tracker. Hence this blocklist will likely cause some false positives. - **excellent list**|ipv4 hash:ip|230 unique IPs|updated every 30 mins  from [this link](https://zeustracker.abuse.ch/blocklist.php?download=ipblocklist)
[zeus_badips](#zeus_badips)|[Abuse.ch Zeus tracker](https://zeustracker.abuse.ch) badips includes IPv4 addresses that are used by the ZeuS trojan. It is the recommened blocklist if you want to block only ZeuS IPs. It excludes IP addresses that ZeuS Tracker believes to be hijacked (level 2) or belong to a free web hosting provider (level 3). Hence the false postive rate should be much lower compared to the standard ZeuS IP blocklist. **excellent list**|ipv4 hash:ip|202 unique IPs|updated every 30 mins  from [this link](https://zeustracker.abuse.ch/blocklist.php?download=badips)

# Comparison of ipsets

Below we compare each ipset against all other.


## alienvault_reputation

[AlienVault.com](https://www.alienvault.com/) IP reputation database (this list seems to include port scanning hosts and to be updated regularly, but we found no information about its retention policy)

Source is downloaded from [this link](https://reputation.alienvault.com/reputation.generic).

The last time downloaded was found to be dated: Thu Jun 11 16:00:40 UTC 2015.

The ipset `alienvault_reputation` has **192275** entries, **192275** unique IPs.

The following table shows the overlaps of `alienvault_reputation` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `alienvault_reputation`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `alienvault_reputation`.
- ` this % ` is the percentage **of this ipset (`alienvault_reputation`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|14343|0.0%|7.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|7003|0.0%|3.6%|
[openbl_60d](#openbl_60d)|6984|6984|6964|99.7%|3.6%|
[dragon_http](#dragon_http)|1029|270336|6149|2.2%|3.1%|
[firehol_level3](#firehol_level3)|109650|9627417|5167|0.0%|2.6%|
[firehol_level1](#firehol_level1)|5137|688854492|5096|0.0%|2.6%|
[et_block](#et_block)|1000|18344011|5020|0.0%|2.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|4451|0.0%|2.3%|
[dshield](#dshield)|20|5120|3840|75.0%|1.9%|
[openbl_30d](#openbl_30d)|2809|2809|2794|99.4%|1.4%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|1628|0.0%|0.8%|
[firehol_level2](#firehol_level2)|22462|34082|1309|3.8%|0.6%|
[shunlist](#shunlist)|1278|1278|1269|99.2%|0.6%|
[blocklist_de](#blocklist_de)|28768|28768|1261|4.3%|0.6%|
[et_compromised](#et_compromised)|1721|1721|1117|64.9%|0.5%|
[bruteforceblocker](#bruteforceblocker)|1700|1700|1078|63.4%|0.5%|
[blocklist_de_ssh](#blocklist_de_ssh)|3225|3225|1049|32.5%|0.5%|
[openbl_7d](#openbl_7d)|628|628|626|99.6%|0.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|521|0.0%|0.2%|
[ciarmy](#ciarmy)|473|473|464|98.0%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|292|0.0%|0.1%|
[voipbl](#voipbl)|10586|10998|186|1.6%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|168|0.1%|0.0%|
[openbl_1d](#openbl_1d)|141|141|138|97.8%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14231|14231|130|0.9%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9671|9671|107|1.1%|0.0%|
[sorbs_spam](#sorbs_spam)|64701|65536|91|0.1%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|91|0.1%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|91|0.1%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|89|0.3%|0.0%|
[sslbl](#sslbl)|371|371|65|17.5%|0.0%|
[zeus](#zeus)|230|230|61|26.5%|0.0%|
[nixspam](#nixspam)|25392|25392|58|0.2%|0.0%|
[firehol_anonymous](#firehol_anonymous)|18960|82998|57|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6745|6745|48|0.7%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|17874|17874|46|0.2%|0.0%|
[dm_tor](#dm_tor)|6506|6506|42|0.6%|0.0%|
[bm_tor](#bm_tor)|6528|6528|42|0.6%|0.0%|
[et_tor](#et_tor)|6400|6400|39|0.6%|0.0%|
[firehol_proxies](#firehol_proxies)|12379|12646|38|0.3%|0.0%|
[zeus_badips](#zeus_badips)|202|202|37|18.3%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|175|175|36|20.5%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2597|2597|31|1.1%|0.0%|
[tor_exits](#tor_exits)|1116|1116|30|2.6%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|29|5.5%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|84|84|19|22.6%|0.0%|
[php_commenters](#php_commenters)|430|430|18|4.1%|0.0%|
[iw_spamlist](#iw_spamlist)|3818|3818|18|0.4%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2863|2863|18|0.6%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|2925|2925|17|0.5%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|15|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|14|0.0%|0.0%|
[php_harvesters](#php_harvesters)|392|392|12|3.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|1448|1448|11|0.7%|0.0%|
[malc0de](#malc0de)|276|276|9|3.2%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|8|0.6%|0.0%|
[php_dictionary](#php_dictionary)|737|737|7|0.9%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|115|115|7|6.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|6|0.4%|0.0%|
[xroxy](#xroxy)|2168|2168|5|0.2%|0.0%|
[php_spammers](#php_spammers)|735|735|5|0.6%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7800|7800|4|0.0%|0.0%|
[et_botcc](#et_botcc)|506|506|4|0.7%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2811|2811|3|0.1%|0.0%|
[proxz](#proxz)|1307|1307|3|0.2%|0.0%|
[nt_malware_irc](#nt_malware_irc)|43|43|2|4.6%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|2|0.3%|0.0%|
[feodo](#feodo)|105|105|2|1.9%|0.0%|
[sorbs_web](#sorbs_web)|544|545|1|0.1%|0.0%|
[nt_malware_http](#nt_malware_http)|69|69|1|1.4%|0.0%|

## blocklist_de

[Blocklist.de](https://www.blocklist.de/) IPs that have been detected by fail2ban in the last 48 hours - **excellent list**

Source is downloaded from [this link](http://lists.blocklist.de/lists/all.txt).

The last time downloaded was found to be dated: Thu Jun 11 17:28:04 UTC 2015.

The ipset `blocklist_de` has **28768** entries, **28768** unique IPs.

The following table shows the overlaps of `blocklist_de` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de`.
- ` this % ` is the percentage **of this ipset (`blocklist_de`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|22462|34082|28768|84.4%|100.0%|
[blocklist_de_mail](#blocklist_de_mail)|17874|17874|17845|99.8%|62.0%|
[blocklist_de_apache](#blocklist_de_apache)|14231|14231|14231|100.0%|49.4%|
[firehol_level3](#firehol_level3)|109650|9627417|3926|0.0%|13.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|3594|0.0%|12.4%|
[blocklist_de_ssh](#blocklist_de_ssh)|3225|3225|3225|100.0%|11.2%|
[blocklist_de_bots](#blocklist_de_bots)|2925|2925|2925|100.0%|10.1%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2863|2863|2863|100.0%|9.9%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|2773|2.9%|9.6%|
[blocklist_de_imap](#blocklist_de_imap)|2597|2597|2597|100.0%|9.0%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|2248|7.7%|7.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|1604|0.0%|5.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|1565|0.0%|5.4%|
[stopforumspam_1d](#stopforumspam_1d)|6745|6745|1448|21.4%|5.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|1448|1448|1448|100.0%|5.0%|
[sorbs_spam](#sorbs_spam)|64701|65536|1358|2.0%|4.7%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|1350|2.0%|4.6%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|1350|2.0%|4.6%|
[alienvault_reputation](#alienvault_reputation)|192275|192275|1261|0.6%|4.3%|
[openbl_60d](#openbl_60d)|6984|6984|876|12.5%|3.0%|
[nixspam](#nixspam)|25392|25392|750|2.9%|2.6%|
[openbl_30d](#openbl_30d)|2809|2809|698|24.8%|2.4%|
[firehol_anonymous](#firehol_anonymous)|18960|82998|667|0.8%|2.3%|
[firehol_proxies](#firehol_proxies)|12379|12646|638|5.0%|2.2%|
[bruteforceblocker](#bruteforceblocker)|1700|1700|588|34.5%|2.0%|
[et_compromised](#et_compromised)|1721|1721|576|33.4%|2.0%|
[ri_web_proxies](#ri_web_proxies)|7800|7800|467|5.9%|1.6%|
[shunlist](#shunlist)|1278|1278|398|31.1%|1.3%|
[openbl_7d](#openbl_7d)|628|628|384|61.1%|1.3%|
[firehol_level1](#firehol_level1)|5137|688854492|236|0.0%|0.8%|
[xroxy](#xroxy)|2168|2168|229|10.5%|0.7%|
[et_block](#et_block)|1000|18344011|226|0.0%|0.7%|
[snort_ipfilter](#snort_ipfilter)|9671|9671|223|2.3%|0.7%|
[proxyrss](#proxyrss)|1373|1373|203|14.7%|0.7%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|200|0.0%|0.6%|
[proxz](#proxz)|1307|1307|186|14.2%|0.6%|
[blocklist_de_strongips](#blocklist_de_strongips)|175|175|175|100.0%|0.6%|
[dshield](#dshield)|20|5120|138|2.6%|0.4%|
[iw_spamlist](#iw_spamlist)|3818|3818|128|3.3%|0.4%|
[openbl_1d](#openbl_1d)|141|141|124|87.9%|0.4%|
[php_dictionary](#php_dictionary)|737|737|121|16.4%|0.4%|
[php_spammers](#php_spammers)|735|735|109|14.8%|0.3%|
[php_commenters](#php_commenters)|430|430|101|23.4%|0.3%|
[ri_connect_proxies](#ri_connect_proxies)|2811|2811|70|2.4%|0.2%|
[blocklist_de_sip](#blocklist_de_sip)|84|84|65|77.3%|0.2%|
[sorbs_web](#sorbs_web)|544|545|61|11.1%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|61|0.0%|0.2%|
[dragon_http](#dragon_http)|1029|270336|52|0.0%|0.1%|
[voipbl](#voipbl)|10586|10998|42|0.3%|0.1%|
[ciarmy](#ciarmy)|473|473|41|8.6%|0.1%|
[php_harvesters](#php_harvesters)|392|392|39|9.9%|0.1%|
[tor_exits](#tor_exits)|1116|1116|24|2.1%|0.0%|
[et_tor](#et_tor)|6400|6400|15|0.2%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|14|0.0%|0.0%|
[dm_tor](#dm_tor)|6506|6506|12|0.1%|0.0%|
[bm_tor](#bm_tor)|6528|6528|12|0.1%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|7|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|7|1.3%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|7|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|4|0.6%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|3|0.2%|0.0%|
[sorbs_socks](#sorbs_socks)|7|7|1|14.2%|0.0%|
[sorbs_misc](#sorbs_misc)|7|7|1|14.2%|0.0%|
[sorbs_http](#sorbs_http)|7|7|1|14.2%|0.0%|
[iw_wormlist](#iw_wormlist)|34|34|1|2.9%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|115|115|1|0.8%|0.0%|

## blocklist_de_apache

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service Apache, Apache-DDOS, RFI-Attacks.

Source is downloaded from [this link](http://lists.blocklist.de/lists/apache.txt).

The last time downloaded was found to be dated: Thu Jun 11 17:28:07 UTC 2015.

The ipset `blocklist_de_apache` has **14231** entries, **14231** unique IPs.

The following table shows the overlaps of `blocklist_de_apache` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_apache`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_apache`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_apache`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|22462|34082|14231|41.7%|100.0%|
[blocklist_de](#blocklist_de)|28768|28768|14231|49.4%|100.0%|
[blocklist_de_mail](#blocklist_de_mail)|17874|17874|11059|61.8%|77.7%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2863|2863|2863|100.0%|20.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|2302|0.0%|16.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|1325|0.0%|9.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|1094|0.0%|7.6%|
[firehol_level3](#firehol_level3)|109650|9627417|293|0.0%|2.0%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|205|0.2%|1.4%|
[alienvault_reputation](#alienvault_reputation)|192275|192275|130|0.0%|0.9%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|120|0.4%|0.8%|
[stopforumspam_1d](#stopforumspam_1d)|6745|6745|67|0.9%|0.4%|
[sorbs_spam](#sorbs_spam)|64701|65536|46|0.0%|0.3%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|46|0.0%|0.3%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|46|0.0%|0.3%|
[snort_ipfilter](#snort_ipfilter)|9671|9671|36|0.3%|0.2%|
[shunlist](#shunlist)|1278|1278|36|2.8%|0.2%|
[ciarmy](#ciarmy)|473|473|34|7.1%|0.2%|
[blocklist_de_strongips](#blocklist_de_strongips)|175|175|32|18.2%|0.2%|
[php_commenters](#php_commenters)|430|430|30|6.9%|0.2%|
[nixspam](#nixspam)|25392|25392|27|0.1%|0.1%|
[firehol_anonymous](#firehol_anonymous)|18960|82998|26|0.0%|0.1%|
[tor_exits](#tor_exits)|1116|1116|23|2.0%|0.1%|
[blocklist_de_bots](#blocklist_de_bots)|2925|2925|22|0.7%|0.1%|
[et_tor](#et_tor)|6400|6400|15|0.2%|0.1%|
[dragon_http](#dragon_http)|1029|270336|15|0.0%|0.1%|
[et_block](#et_block)|1000|18344011|12|0.0%|0.0%|
[dm_tor](#dm_tor)|6506|6506|12|0.1%|0.0%|
[bm_tor](#bm_tor)|6528|6528|12|0.1%|0.0%|
[firehol_level1](#firehol_level1)|5137|688854492|9|0.0%|0.0%|
[openbl_60d](#openbl_60d)|6984|6984|7|0.1%|0.0%|
[openbl_30d](#openbl_30d)|2809|2809|6|0.2%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|5|0.0%|0.0%|
[php_spammers](#php_spammers)|735|735|5|0.6%|0.0%|
[openbl_7d](#openbl_7d)|628|628|5|0.7%|0.0%|
[iw_spamlist](#iw_spamlist)|3818|3818|4|0.1%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|4|0.0%|0.0%|
[dshield](#dshield)|20|5120|4|0.0%|0.0%|
[voipbl](#voipbl)|10586|10998|3|0.0%|0.0%|
[php_dictionary](#php_dictionary)|737|737|3|0.4%|0.0%|
[firehol_proxies](#firehol_proxies)|12379|12646|3|0.0%|0.0%|
[php_harvesters](#php_harvesters)|392|392|2|0.5%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|2|0.3%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|2|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7800|7800|1|0.0%|0.0%|
[openbl_1d](#openbl_1d)|141|141|1|0.7%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|115|115|1|0.8%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2597|2597|1|0.0%|0.0%|

## blocklist_de_bots

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the RFI-Attacks, REG-Bots, IRC-Bots or BadBots (BadBots = he has posted a Spam-Comment on a open Forum or Wiki).

Source is downloaded from [this link](http://lists.blocklist.de/lists/bots.txt).

The last time downloaded was found to be dated: Thu Jun 11 17:28:09 UTC 2015.

The ipset `blocklist_de_bots` has **2925** entries, **2925** unique IPs.

The following table shows the overlaps of `blocklist_de_bots` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_bots`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_bots`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_bots`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|22462|34082|2925|8.5%|100.0%|
[blocklist_de](#blocklist_de)|28768|28768|2925|10.1%|100.0%|
[firehol_level3](#firehol_level3)|109650|9627417|2433|0.0%|83.1%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|2407|2.5%|82.2%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|2054|7.0%|70.2%|
[stopforumspam_1d](#stopforumspam_1d)|6745|6745|1381|20.4%|47.2%|
[firehol_anonymous](#firehol_anonymous)|18960|82998|513|0.6%|17.5%|
[firehol_proxies](#firehol_proxies)|12379|12646|511|4.0%|17.4%|
[ri_web_proxies](#ri_web_proxies)|7800|7800|381|4.8%|13.0%|
[proxyrss](#proxyrss)|1373|1373|203|14.7%|6.9%|
[xroxy](#xroxy)|2168|2168|172|7.9%|5.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|158|0.0%|5.4%|
[proxz](#proxz)|1307|1307|156|11.9%|5.3%|
[blocklist_de_strongips](#blocklist_de_strongips)|175|175|131|74.8%|4.4%|
[php_commenters](#php_commenters)|430|430|81|18.8%|2.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|75|0.0%|2.5%|
[ri_connect_proxies](#ri_connect_proxies)|2811|2811|67|2.3%|2.2%|
[firehol_level1](#firehol_level1)|5137|688854492|57|0.0%|1.9%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|52|0.0%|1.7%|
[et_block](#et_block)|1000|18344011|52|0.0%|1.7%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|49|0.0%|1.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|46|0.0%|1.5%|
[nixspam](#nixspam)|25392|25392|31|0.1%|1.0%|
[sorbs_spam](#sorbs_spam)|64701|65536|30|0.0%|1.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|30|0.0%|1.0%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|30|0.0%|1.0%|
[php_harvesters](#php_harvesters)|392|392|27|6.8%|0.9%|
[php_spammers](#php_spammers)|735|735|24|3.2%|0.8%|
[blocklist_de_mail](#blocklist_de_mail)|17874|17874|23|0.1%|0.7%|
[blocklist_de_apache](#blocklist_de_apache)|14231|14231|22|0.1%|0.7%|
[snort_ipfilter](#snort_ipfilter)|9671|9671|21|0.2%|0.7%|
[php_dictionary](#php_dictionary)|737|737|17|2.3%|0.5%|
[alienvault_reputation](#alienvault_reputation)|192275|192275|17|0.0%|0.5%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|5|0.0%|0.1%|
[sorbs_web](#sorbs_web)|544|545|5|0.9%|0.1%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|5|0.9%|0.1%|
[iw_spamlist](#iw_spamlist)|3818|3818|5|0.1%|0.1%|
[dragon_http](#dragon_http)|1029|270336|3|0.0%|0.1%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|2|0.1%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|2|0.3%|0.0%|
[tor_exits](#tor_exits)|1116|1116|1|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|1|0.0%|0.0%|
[et_compromised](#et_compromised)|1721|1721|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1700|1700|1|0.0%|0.0%|

## blocklist_de_bruteforce

[Blocklist.de](https://www.blocklist.de/) All IPs which attacks Joomlas, Wordpress and other Web-Logins with Brute-Force Logins.

Source is downloaded from [this link](http://lists.blocklist.de/lists/bruteforcelogin.txt).

The last time downloaded was found to be dated: Thu Jun 11 17:28:12 UTC 2015.

The ipset `blocklist_de_bruteforce` has **2863** entries, **2863** unique IPs.

The following table shows the overlaps of `blocklist_de_bruteforce` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_bruteforce`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_bruteforce`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_bruteforce`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|22462|34082|2863|8.4%|100.0%|
[blocklist_de_apache](#blocklist_de_apache)|14231|14231|2863|20.1%|100.0%|
[blocklist_de](#blocklist_de)|28768|28768|2863|9.9%|100.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|211|0.0%|7.3%|
[firehol_level3](#firehol_level3)|109650|9627417|93|0.0%|3.2%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|73|0.0%|2.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|59|0.0%|2.0%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|52|0.1%|1.8%|
[sorbs_spam](#sorbs_spam)|64701|65536|46|0.0%|1.6%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|46|0.0%|1.6%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|46|0.0%|1.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|36|0.0%|1.2%|
[stopforumspam_1d](#stopforumspam_1d)|6745|6745|35|0.5%|1.2%|
[snort_ipfilter](#snort_ipfilter)|9671|9671|33|0.3%|1.1%|
[nixspam](#nixspam)|25392|25392|27|0.1%|0.9%|
[firehol_anonymous](#firehol_anonymous)|18960|82998|23|0.0%|0.8%|
[tor_exits](#tor_exits)|1116|1116|21|1.8%|0.7%|
[alienvault_reputation](#alienvault_reputation)|192275|192275|18|0.0%|0.6%|
[et_tor](#et_tor)|6400|6400|13|0.2%|0.4%|
[php_commenters](#php_commenters)|430|430|9|2.0%|0.3%|
[dm_tor](#dm_tor)|6506|6506|9|0.1%|0.3%|
[bm_tor](#bm_tor)|6528|6528|9|0.1%|0.3%|
[blocklist_de_strongips](#blocklist_de_strongips)|175|175|8|4.5%|0.2%|
[et_block](#et_block)|1000|18344011|6|0.0%|0.2%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|5|0.0%|0.1%|
[php_spammers](#php_spammers)|735|735|5|0.6%|0.1%|
[firehol_level1](#firehol_level1)|5137|688854492|5|0.0%|0.1%|
[iw_spamlist](#iw_spamlist)|3818|3818|4|0.1%|0.1%|
[dragon_http](#dragon_http)|1029|270336|4|0.0%|0.1%|
[php_dictionary](#php_dictionary)|737|737|3|0.4%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|3|0.0%|0.1%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|2|0.0%|0.0%|
[firehol_proxies](#firehol_proxies)|12379|12646|2|0.0%|0.0%|
[voipbl](#voipbl)|10586|10998|1|0.0%|0.0%|
[shunlist](#shunlist)|1278|1278|1|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7800|7800|1|0.0%|0.0%|
[php_harvesters](#php_harvesters)|392|392|1|0.2%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|1|0.1%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.0%|

## blocklist_de_ftp

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours for attacks on the Service FTP.

Source is downloaded from [this link](http://lists.blocklist.de/lists/ftp.txt).

The last time downloaded was found to be dated: Thu Jun 11 17:28:08 UTC 2015.

The ipset `blocklist_de_ftp` has **1448** entries, **1448** unique IPs.

The following table shows the overlaps of `blocklist_de_ftp` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_ftp`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_ftp`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_ftp`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|22462|34082|1448|4.2%|100.0%|
[blocklist_de](#blocklist_de)|28768|28768|1448|5.0%|100.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|125|0.0%|8.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|25|0.0%|1.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|21|0.0%|1.4%|
[firehol_level3](#firehol_level3)|109650|9627417|21|0.0%|1.4%|
[sorbs_spam](#sorbs_spam)|64701|65536|15|0.0%|1.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|15|0.0%|1.0%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|15|0.0%|1.0%|
[nixspam](#nixspam)|25392|25392|15|0.0%|1.0%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|13|0.0%|0.8%|
[alienvault_reputation](#alienvault_reputation)|192275|192275|11|0.0%|0.7%|
[dragon_http](#dragon_http)|1029|270336|6|0.0%|0.4%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|4|0.0%|0.2%|
[php_harvesters](#php_harvesters)|392|392|4|1.0%|0.2%|
[firehol_anonymous](#firehol_anonymous)|18960|82998|4|0.0%|0.2%|
[iw_spamlist](#iw_spamlist)|3818|3818|3|0.0%|0.2%|
[openbl_60d](#openbl_60d)|6984|6984|2|0.0%|0.1%|
[stopforumspam_1d](#stopforumspam_1d)|6745|6745|1|0.0%|0.0%|
[sorbs_web](#sorbs_web)|544|545|1|0.1%|0.0%|
[php_spammers](#php_spammers)|735|735|1|0.1%|0.0%|
[php_dictionary](#php_dictionary)|737|737|1|0.1%|0.0%|
[openbl_7d](#openbl_7d)|628|628|1|0.1%|0.0%|
[openbl_30d](#openbl_30d)|2809|2809|1|0.0%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|1|0.0%|0.0%|
[ciarmy](#ciarmy)|473|473|1|0.2%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|175|175|1|0.5%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|17874|17874|1|0.0%|0.0%|

## blocklist_de_imap

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours for attacks on the Service imap, sasl, pop3, etc.

Source is downloaded from [this link](http://lists.blocklist.de/lists/imap.txt).

The last time downloaded was found to be dated: Thu Jun 11 17:28:07 UTC 2015.

The ipset `blocklist_de_imap` has **2597** entries, **2597** unique IPs.

The following table shows the overlaps of `blocklist_de_imap` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_imap`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_imap`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_imap`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|22462|34082|2597|7.6%|100.0%|
[blocklist_de](#blocklist_de)|28768|28768|2597|9.0%|100.0%|
[blocklist_de_mail](#blocklist_de_mail)|17874|17874|2588|14.4%|99.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|296|0.0%|11.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|72|0.0%|2.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|64|0.0%|2.4%|
[nixspam](#nixspam)|25392|25392|37|0.1%|1.4%|
[firehol_level3](#firehol_level3)|109650|9627417|35|0.0%|1.3%|
[alienvault_reputation](#alienvault_reputation)|192275|192275|31|0.0%|1.1%|
[sorbs_spam](#sorbs_spam)|64701|65536|29|0.0%|1.1%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|29|0.0%|1.1%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|29|0.0%|1.1%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|16|0.0%|0.6%|
[openbl_60d](#openbl_60d)|6984|6984|15|0.2%|0.5%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|10|0.0%|0.3%|
[firehol_level1](#firehol_level1)|5137|688854492|10|0.0%|0.3%|
[et_block](#et_block)|1000|18344011|10|0.0%|0.3%|
[openbl_30d](#openbl_30d)|2809|2809|8|0.2%|0.3%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|6|0.0%|0.2%|
[openbl_7d](#openbl_7d)|628|628|6|0.9%|0.2%|
[dragon_http](#dragon_http)|1029|270336|5|0.0%|0.1%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|4|0.0%|0.1%|
[et_compromised](#et_compromised)|1721|1721|4|0.2%|0.1%|
[bruteforceblocker](#bruteforceblocker)|1700|1700|4|0.2%|0.1%|
[snort_ipfilter](#snort_ipfilter)|9671|9671|3|0.0%|0.1%|
[shunlist](#shunlist)|1278|1278|3|0.2%|0.1%|
[stopforumspam_1d](#stopforumspam_1d)|6745|6745|2|0.0%|0.0%|
[php_harvesters](#php_harvesters)|392|392|2|0.5%|0.0%|
[iw_spamlist](#iw_spamlist)|3818|3818|2|0.0%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2|0.0%|0.0%|
[ciarmy](#ciarmy)|473|473|2|0.4%|0.0%|
[voipbl](#voipbl)|10586|10998|1|0.0%|0.0%|
[openbl_1d](#openbl_1d)|141|141|1|0.7%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14231|14231|1|0.0%|0.0%|

## blocklist_de_mail

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service Mail, Postfix.

Source is downloaded from [this link](http://lists.blocklist.de/lists/mail.txt).

The last time downloaded was found to be dated: Thu Jun 11 17:14:05 UTC 2015.

The ipset `blocklist_de_mail` has **17874** entries, **17874** unique IPs.

The following table shows the overlaps of `blocklist_de_mail` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_mail`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_mail`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_mail`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|22462|34082|17845|52.3%|99.8%|
[blocklist_de](#blocklist_de)|28768|28768|17845|62.0%|99.8%|
[blocklist_de_apache](#blocklist_de_apache)|14231|14231|11059|77.7%|61.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|2590|0.0%|14.4%|
[blocklist_de_imap](#blocklist_de_imap)|2597|2597|2588|99.6%|14.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|1428|0.0%|7.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|1273|0.0%|7.1%|
[sorbs_spam](#sorbs_spam)|64701|65536|1265|1.9%|7.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|1257|1.9%|7.0%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|1257|1.9%|7.0%|
[nixspam](#nixspam)|25392|25392|672|2.6%|3.7%|
[firehol_level3](#firehol_level3)|109650|9627417|406|0.0%|2.2%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|260|0.2%|1.4%|
[snort_ipfilter](#snort_ipfilter)|9671|9671|169|1.7%|0.9%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|146|0.5%|0.8%|
[firehol_anonymous](#firehol_anonymous)|18960|82998|127|0.1%|0.7%|
[firehol_proxies](#firehol_proxies)|12379|12646|125|0.9%|0.6%|
[iw_spamlist](#iw_spamlist)|3818|3818|116|3.0%|0.6%|
[php_dictionary](#php_dictionary)|737|737|101|13.7%|0.5%|
[ri_web_proxies](#ri_web_proxies)|7800|7800|85|1.0%|0.4%|
[php_spammers](#php_spammers)|735|735|78|10.6%|0.4%|
[xroxy](#xroxy)|2168|2168|57|2.6%|0.3%|
[sorbs_web](#sorbs_web)|544|545|56|10.2%|0.3%|
[alienvault_reputation](#alienvault_reputation)|192275|192275|46|0.0%|0.2%|
[stopforumspam_1d](#stopforumspam_1d)|6745|6745|45|0.6%|0.2%|
[proxz](#proxz)|1307|1307|30|2.2%|0.1%|
[php_commenters](#php_commenters)|430|430|27|6.2%|0.1%|
[firehol_level1](#firehol_level1)|5137|688854492|24|0.0%|0.1%|
[blocklist_de_bots](#blocklist_de_bots)|2925|2925|23|0.7%|0.1%|
[openbl_60d](#openbl_60d)|6984|6984|22|0.3%|0.1%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|21|0.0%|0.1%|
[et_block](#et_block)|1000|18344011|21|0.0%|0.1%|
[blocklist_de_strongips](#blocklist_de_strongips)|175|175|21|12.0%|0.1%|
[openbl_30d](#openbl_30d)|2809|2809|14|0.4%|0.0%|
[dragon_http](#dragon_http)|1029|270336|12|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|9|0.0%|0.0%|
[openbl_7d](#openbl_7d)|628|628|8|1.2%|0.0%|
[php_harvesters](#php_harvesters)|392|392|6|1.5%|0.0%|
[et_compromised](#et_compromised)|1721|1721|5|0.2%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1700|1700|5|0.2%|0.0%|
[shunlist](#shunlist)|1278|1278|4|0.3%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|4|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2811|2811|3|0.1%|0.0%|
[dm_tor](#dm_tor)|6506|6506|3|0.0%|0.0%|
[bm_tor](#bm_tor)|6528|6528|3|0.0%|0.0%|
[voipbl](#voipbl)|10586|10998|2|0.0%|0.0%|
[tor_exits](#tor_exits)|1116|1116|2|0.1%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|2|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|2|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|2|0.3%|0.0%|
[et_tor](#et_tor)|6400|6400|2|0.0%|0.0%|
[ciarmy](#ciarmy)|473|473|2|0.4%|0.0%|
[sorbs_socks](#sorbs_socks)|7|7|1|14.2%|0.0%|
[sorbs_misc](#sorbs_misc)|7|7|1|14.2%|0.0%|
[sorbs_http](#sorbs_http)|7|7|1|14.2%|0.0%|
[openbl_1d](#openbl_1d)|141|141|1|0.7%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|1|0.1%|0.0%|
[iw_wormlist](#iw_wormlist)|34|34|1|2.9%|0.0%|
[dshield](#dshield)|20|5120|1|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3225|3225|1|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|1448|1448|1|0.0%|0.0%|

## blocklist_de_sip

[Blocklist.de](https://www.blocklist.de/) All IP addresses that tried to login in a SIP, VOIP or Asterisk Server and are included in the IPs list from [infiltrated.net](www.infiltrated.net)

Source is downloaded from [this link](http://lists.blocklist.de/lists/sip.txt).

The last time downloaded was found to be dated: Thu Jun 11 17:14:14 UTC 2015.

The ipset `blocklist_de_sip` has **84** entries, **84** unique IPs.

The following table shows the overlaps of `blocklist_de_sip` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_sip`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_sip`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_sip`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|22462|34082|65|0.1%|77.3%|
[blocklist_de](#blocklist_de)|28768|28768|65|0.2%|77.3%|
[voipbl](#voipbl)|10586|10998|34|0.3%|40.4%|
[alienvault_reputation](#alienvault_reputation)|192275|192275|19|0.0%|22.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|13|0.0%|15.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|5|0.0%|5.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|5|0.0%|5.9%|
[firehol_level3](#firehol_level3)|109650|9627417|4|0.0%|4.7%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|2|0.0%|2.3%|
[shunlist](#shunlist)|1278|1278|2|0.1%|2.3%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|2|0.0%|2.3%|
[firehol_level1](#firehol_level1)|5137|688854492|2|0.0%|2.3%|
[et_block](#et_block)|1000|18344011|2|0.0%|2.3%|
[dragon_http](#dragon_http)|1029|270336|2|0.0%|2.3%|
[et_botcc](#et_botcc)|506|506|1|0.1%|1.1%|

## blocklist_de_ssh

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service SSH.

Source is downloaded from [this link](http://lists.blocklist.de/lists/ssh.txt).

The last time downloaded was found to be dated: Thu Jun 11 17:28:05 UTC 2015.

The ipset `blocklist_de_ssh` has **3225** entries, **3225** unique IPs.

The following table shows the overlaps of `blocklist_de_ssh` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_ssh`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_ssh`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_ssh`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|22462|34082|3225|9.4%|100.0%|
[blocklist_de](#blocklist_de)|28768|28768|3225|11.2%|100.0%|
[alienvault_reputation](#alienvault_reputation)|192275|192275|1049|0.5%|32.5%|
[firehol_level3](#firehol_level3)|109650|9627417|910|0.0%|28.2%|
[openbl_60d](#openbl_60d)|6984|6984|845|12.0%|26.2%|
[openbl_30d](#openbl_30d)|2809|2809|677|24.1%|20.9%|
[bruteforceblocker](#bruteforceblocker)|1700|1700|582|34.2%|18.0%|
[et_compromised](#et_compromised)|1721|1721|570|33.1%|17.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|479|0.0%|14.8%|
[openbl_7d](#openbl_7d)|628|628|371|59.0%|11.5%|
[shunlist](#shunlist)|1278|1278|357|27.9%|11.0%|
[firehol_level1](#firehol_level1)|5137|688854492|144|0.0%|4.4%|
[et_block](#et_block)|1000|18344011|139|0.0%|4.3%|
[dshield](#dshield)|20|5120|133|2.5%|4.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|126|0.0%|3.9%|
[openbl_1d](#openbl_1d)|141|141|122|86.5%|3.7%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|120|0.0%|3.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|57|0.0%|1.7%|
[blocklist_de_strongips](#blocklist_de_strongips)|175|175|30|17.1%|0.9%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|25|0.0%|0.7%|
[dragon_http](#dragon_http)|1029|270336|14|0.0%|0.4%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|6|0.0%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|6|0.0%|0.1%|
[sorbs_spam](#sorbs_spam)|64701|65536|5|0.0%|0.1%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|5|0.0%|0.1%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|5|0.0%|0.1%|
[ciarmy](#ciarmy)|473|473|4|0.8%|0.1%|
[voipbl](#voipbl)|10586|10998|2|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7800|7800|1|0.0%|0.0%|
[php_spammers](#php_spammers)|735|735|1|0.1%|0.0%|
[php_harvesters](#php_harvesters)|392|392|1|0.2%|0.0%|
[php_commenters](#php_commenters)|430|430|1|0.2%|0.0%|
[nixspam](#nixspam)|25392|25392|1|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|1|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|1|0.0%|0.0%|
[firehol_proxies](#firehol_proxies)|12379|12646|1|0.0%|0.0%|
[firehol_anonymous](#firehol_anonymous)|18960|82998|1|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|17874|17874|1|0.0%|0.0%|

## blocklist_de_strongips

[Blocklist.de](https://www.blocklist.de/) All IPs which are older then 2 month and have more then 5.000 attacks.

Source is downloaded from [this link](http://lists.blocklist.de/lists/strongips.txt).

The last time downloaded was found to be dated: Thu Jun 11 17:28:11 UTC 2015.

The ipset `blocklist_de_strongips` has **175** entries, **175** unique IPs.

The following table shows the overlaps of `blocklist_de_strongips` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_strongips`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_strongips`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_strongips`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|22462|34082|175|0.5%|100.0%|
[blocklist_de](#blocklist_de)|28768|28768|175|0.6%|100.0%|
[firehol_level3](#firehol_level3)|109650|9627417|162|0.0%|92.5%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|135|0.1%|77.1%|
[blocklist_de_bots](#blocklist_de_bots)|2925|2925|131|4.4%|74.8%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|120|0.4%|68.5%|
[stopforumspam_1d](#stopforumspam_1d)|6745|6745|105|1.5%|60.0%|
[php_commenters](#php_commenters)|430|430|45|10.4%|25.7%|
[alienvault_reputation](#alienvault_reputation)|192275|192275|36|0.0%|20.5%|
[blocklist_de_apache](#blocklist_de_apache)|14231|14231|32|0.2%|18.2%|
[blocklist_de_ssh](#blocklist_de_ssh)|3225|3225|30|0.9%|17.1%|
[openbl_60d](#openbl_60d)|6984|6984|25|0.3%|14.2%|
[openbl_30d](#openbl_30d)|2809|2809|24|0.8%|13.7%|
[openbl_7d](#openbl_7d)|628|628|23|3.6%|13.1%|
[blocklist_de_mail](#blocklist_de_mail)|17874|17874|21|0.1%|12.0%|
[shunlist](#shunlist)|1278|1278|19|1.4%|10.8%|
[firehol_level1](#firehol_level1)|5137|688854492|18|0.0%|10.2%|
[openbl_1d](#openbl_1d)|141|141|16|11.3%|9.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|16|0.0%|9.1%|
[php_spammers](#php_spammers)|735|735|10|1.3%|5.7%|
[firehol_proxies](#firehol_proxies)|12379|12646|9|0.0%|5.1%|
[firehol_anonymous](#firehol_anonymous)|18960|82998|9|0.0%|5.1%|
[et_block](#et_block)|1000|18344011|9|0.0%|5.1%|
[ri_web_proxies](#ri_web_proxies)|7800|7800|8|0.1%|4.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|8|0.0%|4.5%|
[dshield](#dshield)|20|5120|8|0.1%|4.5%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2863|2863|8|0.2%|4.5%|
[xroxy](#xroxy)|2168|2168|7|0.3%|4.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|7|0.0%|4.0%|
[proxyrss](#proxyrss)|1373|1373|7|0.5%|4.0%|
[proxz](#proxz)|1307|1307|6|0.4%|3.4%|
[php_dictionary](#php_dictionary)|737|737|5|0.6%|2.8%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|3|0.0%|1.7%|
[php_harvesters](#php_harvesters)|392|392|3|0.7%|1.7%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|1.7%|
[sorbs_web](#sorbs_web)|544|545|2|0.3%|1.1%|
[sorbs_spam](#sorbs_spam)|64701|65536|2|0.0%|1.1%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|2|0.0%|1.1%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|2|0.0%|1.1%|
[snort_ipfilter](#snort_ipfilter)|9671|9671|2|0.0%|1.1%|
[nixspam](#nixspam)|25392|25392|2|0.0%|1.1%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|2|0.1%|1.1%|
[dragon_http](#dragon_http)|1029|270336|2|0.0%|1.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|1|0.0%|0.5%|
[et_compromised](#et_compromised)|1721|1721|1|0.0%|0.5%|
[ciarmy](#ciarmy)|473|473|1|0.2%|0.5%|
[bruteforceblocker](#bruteforceblocker)|1700|1700|1|0.0%|0.5%|
[blocklist_de_ftp](#blocklist_de_ftp)|1448|1448|1|0.0%|0.5%|

## bm_tor

[torstatus.blutmagie.de](https://torstatus.blutmagie.de) list of all TOR network servers

Source is downloaded from [this link](https://torstatus.blutmagie.de/ip_list_all.php/Tor_ip_list_ALL.csv).

The last time downloaded was found to be dated: Thu Jun 11 17:36:04 UTC 2015.

The ipset `bm_tor` has **6528** entries, **6528** unique IPs.

The following table shows the overlaps of `bm_tor` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `bm_tor`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `bm_tor`.
- ` this % ` is the percentage **of this ipset (`bm_tor`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_anonymous](#firehol_anonymous)|18960|82998|6528|7.8%|100.0%|
[dm_tor](#dm_tor)|6506|6506|6420|98.6%|98.3%|
[et_tor](#et_tor)|6400|6400|5667|88.5%|86.8%|
[firehol_level3](#firehol_level3)|109650|9627417|1106|0.0%|16.9%|
[snort_ipfilter](#snort_ipfilter)|9671|9671|1071|11.0%|16.4%|
[tor_exits](#tor_exits)|1116|1116|1017|91.1%|15.5%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|637|0.6%|9.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|630|0.0%|9.6%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|528|1.8%|8.0%|
[firehol_level2](#firehol_level2)|22462|34082|332|0.9%|5.0%|
[stopforumspam_1d](#stopforumspam_1d)|6745|6745|327|4.8%|5.0%|
[firehol_proxies](#firehol_proxies)|12379|12646|237|1.8%|3.6%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|232|44.2%|3.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|186|0.0%|2.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|168|0.0%|2.5%|
[php_commenters](#php_commenters)|430|430|51|11.8%|0.7%|
[alienvault_reputation](#alienvault_reputation)|192275|192275|42|0.0%|0.6%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|22|0.0%|0.3%|
[openbl_60d](#openbl_60d)|6984|6984|20|0.2%|0.3%|
[dragon_http](#dragon_http)|1029|270336|14|0.0%|0.2%|
[blocklist_de_apache](#blocklist_de_apache)|14231|14231|12|0.0%|0.1%|
[blocklist_de](#blocklist_de)|28768|28768|12|0.0%|0.1%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2863|2863|9|0.3%|0.1%|
[php_harvesters](#php_harvesters)|392|392|7|1.7%|0.1%|
[nixspam](#nixspam)|25392|25392|7|0.0%|0.1%|
[ri_web_proxies](#ri_web_proxies)|7800|7800|5|0.0%|0.0%|
[php_spammers](#php_spammers)|735|735|5|0.6%|0.0%|
[sorbs_spam](#sorbs_spam)|64701|65536|4|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|4|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|4|0.0%|0.0%|
[php_dictionary](#php_dictionary)|737|737|4|0.5%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|4|0.0%|0.0%|
[voipbl](#voipbl)|10586|10998|3|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|3|0.0%|0.0%|
[firehol_level1](#firehol_level1)|5137|688854492|3|0.0%|0.0%|
[et_block](#et_block)|1000|18344011|3|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|17874|17874|3|0.0%|0.0%|
[xroxy](#xroxy)|2168|2168|2|0.0%|0.0%|
[shunlist](#shunlist)|1278|1278|1|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2811|2811|1|0.0%|0.0%|
[iw_spamlist](#iw_spamlist)|3818|3818|1|0.0%|0.0%|

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
[firehol_level1](#firehol_level1)|5137|688854492|592708608|86.0%|100.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|4194304|3.0%|0.7%|
[voipbl](#voipbl)|10586|10998|319|2.9%|0.0%|
[iw_spamlist](#iw_spamlist)|3818|3818|5|0.1%|0.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|5|0.0%|0.0%|
[firehol_level3](#firehol_level3)|109650|9627417|3|0.0%|0.0%|
[php_harvesters](#php_harvesters)|392|392|1|0.2%|0.0%|
[php_commenters](#php_commenters)|430|430|1|0.2%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.0%|
[ciarmy](#ciarmy)|473|473|1|0.2%|0.0%|

## bruteforceblocker

[danger.rulez.sk](http://danger.rulez.sk/) IPs detected by [bruteforceblocker](http://danger.rulez.sk/index.php/bruteforceblocker/) (fail2ban alternative for SSH on OpenBSD). This is an automatically generated list from users reporting failed authentication attempts. An IP seems to be included if 3 or more users report it. Its retention pocily seems 30 days.

Source is downloaded from [this link](http://danger.rulez.sk/projects/bruteforceblocker/blist.php).

The last time downloaded was found to be dated: Thu Jun 11 17:18:30 UTC 2015.

The ipset `bruteforceblocker` has **1700** entries, **1700** unique IPs.

The following table shows the overlaps of `bruteforceblocker` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `bruteforceblocker`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `bruteforceblocker`.
- ` this % ` is the percentage **of this ipset (`bruteforceblocker`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level3](#firehol_level3)|109650|9627417|1700|0.0%|100.0%|
[et_compromised](#et_compromised)|1721|1721|1634|94.9%|96.1%|
[alienvault_reputation](#alienvault_reputation)|192275|192275|1078|0.5%|63.4%|
[openbl_60d](#openbl_60d)|6984|6984|969|13.8%|57.0%|
[openbl_30d](#openbl_30d)|2809|2809|908|32.3%|53.4%|
[firehol_level2](#firehol_level2)|22462|34082|589|1.7%|34.6%|
[blocklist_de](#blocklist_de)|28768|28768|588|2.0%|34.5%|
[blocklist_de_ssh](#blocklist_de_ssh)|3225|3225|582|18.0%|34.2%|
[shunlist](#shunlist)|1278|1278|395|30.9%|23.2%|
[openbl_7d](#openbl_7d)|628|628|307|48.8%|18.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|157|0.0%|9.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|88|0.0%|5.1%|
[openbl_1d](#openbl_1d)|141|141|76|53.9%|4.4%|
[firehol_level1](#firehol_level1)|5137|688854492|71|0.0%|4.1%|
[et_block](#et_block)|1000|18344011|69|0.0%|4.0%|
[dshield](#dshield)|20|5120|65|1.2%|3.8%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|61|0.0%|3.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|55|0.0%|3.2%|
[dragon_http](#dragon_http)|1029|270336|12|0.0%|0.7%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|10|0.0%|0.5%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|5|0.0%|0.2%|
[blocklist_de_mail](#blocklist_de_mail)|17874|17874|5|0.0%|0.2%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|4|0.0%|0.2%|
[blocklist_de_imap](#blocklist_de_imap)|2597|2597|4|0.1%|0.2%|
[voipbl](#voipbl)|10586|10998|3|0.0%|0.1%|
[sorbs_spam](#sorbs_spam)|64701|65536|3|0.0%|0.1%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|3|0.0%|0.1%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|3|0.0%|0.1%|
[firehol_proxies](#firehol_proxies)|12379|12646|3|0.0%|0.1%|
[firehol_anonymous](#firehol_anonymous)|18960|82998|3|0.0%|0.1%|
[ciarmy](#ciarmy)|473|473|3|0.6%|0.1%|
[proxz](#proxz)|1307|1307|2|0.1%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|2|0.0%|0.1%|
[xroxy](#xroxy)|2168|2168|1|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6745|6745|1|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7800|7800|1|0.0%|0.0%|
[php_spammers](#php_spammers)|735|735|1|0.1%|0.0%|
[php_commenters](#php_commenters)|430|430|1|0.2%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|175|175|1|0.5%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|2925|2925|1|0.0%|0.0%|

## ciarmy

[CIArmy.com](http://ciarmy.com/) IPs with poor Rogue Packet score that have not yet been identified as malicious by the community

Source is downloaded from [this link](http://cinsscore.com/list/ci-badguys.txt).

The last time downloaded was found to be dated: Thu Jun 11 16:15:07 UTC 2015.

The ipset `ciarmy` has **473** entries, **473** unique IPs.

The following table shows the overlaps of `ciarmy` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ciarmy`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ciarmy`.
- ` this % ` is the percentage **of this ipset (`ciarmy`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level3](#firehol_level3)|109650|9627417|473|0.0%|100.0%|
[alienvault_reputation](#alienvault_reputation)|192275|192275|464|0.2%|98.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|102|0.0%|21.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|49|0.0%|10.3%|
[firehol_level2](#firehol_level2)|22462|34082|42|0.1%|8.8%|
[blocklist_de](#blocklist_de)|28768|28768|41|0.1%|8.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|38|0.0%|8.0%|
[blocklist_de_apache](#blocklist_de_apache)|14231|14231|34|0.2%|7.1%|
[shunlist](#shunlist)|1278|1278|28|2.1%|5.9%|
[dragon_http](#dragon_http)|1029|270336|8|0.0%|1.6%|
[et_block](#et_block)|1000|18344011|6|0.0%|1.2%|
[firehol_level1](#firehol_level1)|5137|688854492|4|0.0%|0.8%|
[blocklist_de_ssh](#blocklist_de_ssh)|3225|3225|4|0.1%|0.8%|
[openbl_7d](#openbl_7d)|628|628|3|0.4%|0.6%|
[openbl_60d](#openbl_60d)|6984|6984|3|0.0%|0.6%|
[openbl_30d](#openbl_30d)|2809|2809|3|0.1%|0.6%|
[et_compromised](#et_compromised)|1721|1721|3|0.1%|0.6%|
[dshield](#dshield)|20|5120|3|0.0%|0.6%|
[bruteforceblocker](#bruteforceblocker)|1700|1700|3|0.1%|0.6%|
[voipbl](#voipbl)|10586|10998|2|0.0%|0.4%|
[openbl_1d](#openbl_1d)|141|141|2|1.4%|0.4%|
[blocklist_de_mail](#blocklist_de_mail)|17874|17874|2|0.0%|0.4%|
[blocklist_de_imap](#blocklist_de_imap)|2597|2597|2|0.0%|0.4%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|1|0.0%|0.2%|
[fullbogons](#fullbogons)|3775|670173256|1|0.0%|0.2%|
[bogons](#bogons)|13|592708608|1|0.0%|0.2%|
[blocklist_de_strongips](#blocklist_de_strongips)|175|175|1|0.5%|0.2%|
[blocklist_de_ftp](#blocklist_de_ftp)|1448|1448|1|0.0%|0.2%|

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
[firehol_level3](#firehol_level3)|109650|9627417|115|0.0%|100.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|20|0.0%|17.3%|
[malc0de](#malc0de)|276|276|9|3.2%|7.8%|
[alienvault_reputation](#alienvault_reputation)|192275|192275|7|0.0%|6.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|6|0.0%|5.2%|
[snort_ipfilter](#snort_ipfilter)|9671|9671|4|0.0%|3.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|4|0.0%|3.4%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.8%|
[firehol_level2](#firehol_level2)|22462|34082|1|0.0%|0.8%|
[blocklist_de_apache](#blocklist_de_apache)|14231|14231|1|0.0%|0.8%|
[blocklist_de](#blocklist_de)|28768|28768|1|0.0%|0.8%|

## dm_tor

[dan.me.uk](https://www.dan.me.uk) dynamic list of TOR nodes

Source is downloaded from [this link](https://www.dan.me.uk/torlist/).

The last time downloaded was found to be dated: Thu Jun 11 17:18:05 UTC 2015.

The ipset `dm_tor` has **6506** entries, **6506** unique IPs.

The following table shows the overlaps of `dm_tor` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `dm_tor`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `dm_tor`.
- ` this % ` is the percentage **of this ipset (`dm_tor`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_anonymous](#firehol_anonymous)|18960|82998|6506|7.8%|100.0%|
[bm_tor](#bm_tor)|6528|6528|6420|98.3%|98.6%|
[et_tor](#et_tor)|6400|6400|5675|88.6%|87.2%|
[firehol_level3](#firehol_level3)|109650|9627417|1104|0.0%|16.9%|
[snort_ipfilter](#snort_ipfilter)|9671|9671|1069|11.0%|16.4%|
[tor_exits](#tor_exits)|1116|1116|1018|91.2%|15.6%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|639|0.6%|9.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|629|0.0%|9.6%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|530|1.8%|8.1%|
[firehol_level2](#firehol_level2)|22462|34082|333|0.9%|5.1%|
[stopforumspam_1d](#stopforumspam_1d)|6745|6745|328|4.8%|5.0%|
[firehol_proxies](#firehol_proxies)|12379|12646|237|1.8%|3.6%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|232|44.2%|3.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|184|0.0%|2.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|168|0.0%|2.5%|
[php_commenters](#php_commenters)|430|430|51|11.8%|0.7%|
[alienvault_reputation](#alienvault_reputation)|192275|192275|42|0.0%|0.6%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|22|0.0%|0.3%|
[openbl_60d](#openbl_60d)|6984|6984|20|0.2%|0.3%|
[dragon_http](#dragon_http)|1029|270336|14|0.0%|0.2%|
[blocklist_de_apache](#blocklist_de_apache)|14231|14231|12|0.0%|0.1%|
[blocklist_de](#blocklist_de)|28768|28768|12|0.0%|0.1%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2863|2863|9|0.3%|0.1%|
[php_harvesters](#php_harvesters)|392|392|7|1.7%|0.1%|
[nixspam](#nixspam)|25392|25392|7|0.0%|0.1%|
[ri_web_proxies](#ri_web_proxies)|7800|7800|5|0.0%|0.0%|
[php_spammers](#php_spammers)|735|735|5|0.6%|0.0%|
[sorbs_spam](#sorbs_spam)|64701|65536|4|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|4|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|4|0.0%|0.0%|
[php_dictionary](#php_dictionary)|737|737|4|0.5%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|4|0.0%|0.0%|
[voipbl](#voipbl)|10586|10998|3|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|3|0.0%|0.0%|
[firehol_level1](#firehol_level1)|5137|688854492|3|0.0%|0.0%|
[et_block](#et_block)|1000|18344011|3|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|17874|17874|3|0.0%|0.0%|
[xroxy](#xroxy)|2168|2168|2|0.0%|0.0%|
[shunlist](#shunlist)|1278|1278|1|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2811|2811|1|0.0%|0.0%|
[iw_spamlist](#iw_spamlist)|3818|3818|1|0.0%|0.0%|

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
[alienvault_reputation](#alienvault_reputation)|192275|192275|6149|3.1%|2.2%|
[firehol_level1](#firehol_level1)|5137|688854492|1025|0.0%|0.3%|
[et_block](#et_block)|1000|18344011|1024|0.0%|0.3%|
[dshield](#dshield)|20|5120|768|15.0%|0.2%|
[firehol_level3](#firehol_level3)|109650|9627417|558|0.0%|0.2%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|256|0.0%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|256|0.0%|0.0%|
[openbl_60d](#openbl_60d)|6984|6984|219|3.1%|0.0%|
[openbl_30d](#openbl_30d)|2809|2809|148|5.2%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|111|0.1%|0.0%|
[sorbs_spam](#sorbs_spam)|64701|65536|71|0.1%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|70|0.1%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|70|0.1%|0.0%|
[firehol_level2](#firehol_level2)|22462|34082|64|0.1%|0.0%|
[openbl_7d](#openbl_7d)|628|628|54|8.5%|0.0%|
[blocklist_de](#blocklist_de)|28768|28768|52|0.1%|0.0%|
[firehol_anonymous](#firehol_anonymous)|18960|82998|41|0.0%|0.0%|
[shunlist](#shunlist)|1278|1278|37|2.8%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|36|0.1%|0.0%|
[firehol_proxies](#firehol_proxies)|12379|12646|30|0.2%|0.0%|
[nixspam](#nixspam)|25392|25392|28|0.1%|0.0%|
[voipbl](#voipbl)|10586|10998|27|0.2%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|26|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7800|7800|18|0.2%|0.0%|
[et_tor](#et_tor)|6400|6400|15|0.2%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14231|14231|15|0.1%|0.0%|
[dm_tor](#dm_tor)|6506|6506|14|0.2%|0.0%|
[bm_tor](#bm_tor)|6528|6528|14|0.2%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3225|3225|14|0.4%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1700|1700|12|0.7%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|17874|17874|12|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6745|6745|11|0.1%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9671|9671|11|0.1%|0.0%|
[et_compromised](#et_compromised)|1721|1721|11|0.6%|0.0%|
[ciarmy](#ciarmy)|473|473|8|1.6%|0.0%|
[xroxy](#xroxy)|2168|2168|6|0.2%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|6|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|1448|1448|6|0.4%|0.0%|
[tor_exits](#tor_exits)|1116|1116|5|0.4%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2597|2597|5|0.1%|0.0%|
[proxz](#proxz)|1307|1307|4|0.3%|0.0%|
[php_commenters](#php_commenters)|430|430|4|0.9%|0.0%|
[openbl_1d](#openbl_1d)|141|141|4|2.8%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|4|0.7%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2863|2863|4|0.1%|0.0%|
[zeus_badips](#zeus_badips)|202|202|3|1.4%|0.0%|
[zeus](#zeus)|230|230|3|1.3%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2811|2811|3|0.1%|0.0%|
[malc0de](#malc0de)|276|276|3|1.0%|0.0%|
[iw_spamlist](#iw_spamlist)|3818|3818|3|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|3|0.2%|0.0%|
[et_botcc](#et_botcc)|506|506|3|0.5%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|2925|2925|3|0.1%|0.0%|
[php_dictionary](#php_dictionary)|737|737|2|0.2%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|2|0.1%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|175|175|2|1.1%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|84|84|2|2.3%|0.0%|
[sslbl](#sslbl)|371|371|1|0.2%|0.0%|
[sorbs_web](#sorbs_web)|544|545|1|0.1%|0.0%|
[proxyrss](#proxyrss)|1373|1373|1|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|1|0.1%|0.0%|

## dshield

[DShield.org](https://dshield.org/) top 20 attacking class C (/24) subnets over the last three days - **excellent list**

Source is downloaded from [this link](http://feeds.dshield.org/block.txt).

The last time downloaded was found to be dated: Thu Jun 11 15:56:18 UTC 2015.

The ipset `dshield` has **20** entries, **5120** unique IPs.

The following table shows the overlaps of `dshield` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `dshield`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `dshield`.
- ` this % ` is the percentage **of this ipset (`dshield`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level1](#firehol_level1)|5137|688854492|5120|0.0%|100.0%|
[alienvault_reputation](#alienvault_reputation)|192275|192275|3840|1.9%|75.0%|
[et_block](#et_block)|1000|18344011|2048|0.0%|40.0%|
[dragon_http](#dragon_http)|1029|270336|768|0.2%|15.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|512|0.0%|10.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|257|0.0%|5.0%|
[firehol_level3](#firehol_level3)|109650|9627417|170|0.0%|3.3%|
[openbl_60d](#openbl_60d)|6984|6984|166|2.3%|3.2%|
[openbl_30d](#openbl_30d)|2809|2809|148|5.2%|2.8%|
[firehol_level2](#firehol_level2)|22462|34082|138|0.4%|2.6%|
[blocklist_de](#blocklist_de)|28768|28768|138|0.4%|2.6%|
[blocklist_de_ssh](#blocklist_de_ssh)|3225|3225|133|4.1%|2.5%|
[shunlist](#shunlist)|1278|1278|120|9.3%|2.3%|
[et_compromised](#et_compromised)|1721|1721|104|6.0%|2.0%|
[bruteforceblocker](#bruteforceblocker)|1700|1700|65|3.8%|1.2%|
[openbl_7d](#openbl_7d)|628|628|60|9.5%|1.1%|
[openbl_1d](#openbl_1d)|141|141|24|17.0%|0.4%|
[blocklist_de_strongips](#blocklist_de_strongips)|175|175|8|4.5%|0.1%|
[blocklist_de_apache](#blocklist_de_apache)|14231|14231|4|0.0%|0.0%|
[ciarmy](#ciarmy)|473|473|3|0.6%|0.0%|
[malc0de](#malc0de)|276|276|2|0.7%|0.0%|
[voipbl](#voipbl)|10586|10998|1|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|1|0.1%|0.0%|
[firehol_proxies](#firehol_proxies)|12379|12646|1|0.0%|0.0%|
[firehol_anonymous](#firehol_anonymous)|18960|82998|1|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|17874|17874|1|0.0%|0.0%|

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
[firehol_level1](#firehol_level1)|5137|688854492|18340426|2.6%|99.9%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|18338560|99.9%|99.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|8532520|2.4%|46.5%|
[firehol_level3](#firehol_level3)|109650|9627417|6933380|72.0%|37.7%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|6932480|75.5%|37.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|2272548|0.2%|12.3%|
[fullbogons](#fullbogons)|3775|670173256|151552|0.0%|0.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|130394|0.0%|0.7%|
[alienvault_reputation](#alienvault_reputation)|192275|192275|5020|2.6%|0.0%|
[dshield](#dshield)|20|5120|2048|40.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1042|0.3%|0.0%|
[dragon_http](#dragon_http)|1029|270336|1024|0.3%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|1018|1.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|517|0.1%|0.0%|
[openbl_60d](#openbl_60d)|6984|6984|299|4.2%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9671|9671|297|3.0%|0.0%|
[firehol_level2](#firehol_level2)|22462|34082|291|0.8%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|272|0.9%|0.0%|
[zeus](#zeus)|230|230|228|99.1%|0.0%|
[blocklist_de](#blocklist_de)|28768|28768|226|0.7%|0.0%|
[zeus_badips](#zeus_badips)|202|202|202|100.0%|0.0%|
[openbl_30d](#openbl_30d)|2809|2809|163|5.8%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3225|3225|139|4.3%|0.0%|
[shunlist](#shunlist)|1278|1278|115|8.9%|0.0%|
[et_compromised](#et_compromised)|1721|1721|109|6.3%|0.0%|
[feodo](#feodo)|105|105|104|99.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6745|6745|80|1.1%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1700|1700|69|4.0%|0.0%|
[openbl_7d](#openbl_7d)|628|628|61|9.7%|0.0%|
[nixspam](#nixspam)|25392|25392|56|0.2%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|2925|2925|52|1.7%|0.0%|
[sslbl](#sslbl)|371|371|38|10.2%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|30|2.3%|0.0%|
[php_commenters](#php_commenters)|430|430|29|6.7%|0.0%|
[sorbs_spam](#sorbs_spam)|64701|65536|22|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|22|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|22|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|17874|17874|21|0.1%|0.0%|
[openbl_1d](#openbl_1d)|141|141|18|12.7%|0.0%|
[voipbl](#voipbl)|10586|10998|14|0.1%|0.0%|
[palevo](#palevo)|13|13|13|100.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14231|14231|12|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2597|2597|10|0.3%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|175|175|9|5.1%|0.0%|
[php_dictionary](#php_dictionary)|737|737|6|0.8%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|6|0.4%|0.0%|
[firehol_anonymous](#firehol_anonymous)|18960|82998|6|0.0%|0.0%|
[ciarmy](#ciarmy)|473|473|6|1.2%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2863|2863|6|0.2%|0.0%|
[malc0de](#malc0de)|276|276|5|1.8%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|5|0.0%|0.0%|
[php_spammers](#php_spammers)|735|735|4|0.5%|0.0%|
[nt_malware_http](#nt_malware_http)|69|69|4|5.7%|0.0%|
[iw_spamlist](#iw_spamlist)|3818|3818|4|0.1%|0.0%|
[nt_malware_irc](#nt_malware_irc)|43|43|3|6.9%|0.0%|
[firehol_proxies](#firehol_proxies)|12379|12646|3|0.0%|0.0%|
[et_tor](#et_tor)|6400|6400|3|0.0%|0.0%|
[dm_tor](#dm_tor)|6506|6506|3|0.0%|0.0%|
[bm_tor](#bm_tor)|6528|6528|3|0.0%|0.0%|
[tor_exits](#tor_exits)|1116|1116|2|0.1%|0.0%|
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
[alienvault_reputation](#alienvault_reputation)|192275|192275|4|0.0%|0.7%|
[firehol_level3](#firehol_level3)|109650|9627417|3|0.0%|0.5%|
[dragon_http](#dragon_http)|1029|270336|3|0.0%|0.5%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|1|0.0%|0.1%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|1|0.0%|0.1%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|1|0.0%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.1%|
[firehol_level1](#firehol_level1)|5137|688854492|1|0.0%|0.1%|
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
[firehol_level3](#firehol_level3)|109650|9627417|1691|0.0%|98.2%|
[bruteforceblocker](#bruteforceblocker)|1700|1700|1634|96.1%|94.9%|
[alienvault_reputation](#alienvault_reputation)|192275|192275|1117|0.5%|64.9%|
[openbl_60d](#openbl_60d)|6984|6984|1014|14.5%|58.9%|
[openbl_30d](#openbl_30d)|2809|2809|945|33.6%|54.9%|
[firehol_level2](#firehol_level2)|22462|34082|577|1.6%|33.5%|
[blocklist_de](#blocklist_de)|28768|28768|576|2.0%|33.4%|
[blocklist_de_ssh](#blocklist_de_ssh)|3225|3225|570|17.6%|33.1%|
[shunlist](#shunlist)|1278|1278|430|33.6%|24.9%|
[openbl_7d](#openbl_7d)|628|628|308|49.0%|17.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|152|0.0%|8.8%|
[firehol_level1](#firehol_level1)|5137|688854492|110|0.0%|6.3%|
[et_block](#et_block)|1000|18344011|109|0.0%|6.3%|
[dshield](#dshield)|20|5120|104|2.0%|6.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|101|0.0%|5.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|85|0.0%|4.9%|
[openbl_1d](#openbl_1d)|141|141|73|51.7%|4.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|52|0.0%|3.0%|
[dragon_http](#dragon_http)|1029|270336|11|0.0%|0.6%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|10|0.0%|0.5%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|5|0.0%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|5|0.0%|0.2%|
[blocklist_de_mail](#blocklist_de_mail)|17874|17874|5|0.0%|0.2%|
[blocklist_de_imap](#blocklist_de_imap)|2597|2597|4|0.1%|0.2%|
[voipbl](#voipbl)|10586|10998|3|0.0%|0.1%|
[sorbs_spam](#sorbs_spam)|64701|65536|3|0.0%|0.1%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|3|0.0%|0.1%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|3|0.0%|0.1%|
[firehol_proxies](#firehol_proxies)|12379|12646|3|0.0%|0.1%|
[firehol_anonymous](#firehol_anonymous)|18960|82998|3|0.0%|0.1%|
[ciarmy](#ciarmy)|473|473|3|0.6%|0.1%|
[proxz](#proxz)|1307|1307|2|0.1%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|2|0.0%|0.1%|
[xroxy](#xroxy)|2168|2168|1|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6745|6745|1|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7800|7800|1|0.0%|0.0%|
[php_spammers](#php_spammers)|735|735|1|0.1%|0.0%|
[php_commenters](#php_commenters)|430|430|1|0.2%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|175|175|1|0.5%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|2925|2925|1|0.0%|0.0%|

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
[firehol_anonymous](#firehol_anonymous)|18960|82998|5724|6.8%|89.4%|
[dm_tor](#dm_tor)|6506|6506|5675|87.2%|88.6%|
[bm_tor](#bm_tor)|6528|6528|5667|86.8%|88.5%|
[firehol_level3](#firehol_level3)|109650|9627417|1124|0.0%|17.5%|
[snort_ipfilter](#snort_ipfilter)|9671|9671|1088|11.2%|17.0%|
[tor_exits](#tor_exits)|1116|1116|965|86.4%|15.0%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|653|0.6%|10.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|625|0.0%|9.7%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|547|1.8%|8.5%|
[firehol_level2](#firehol_level2)|22462|34082|337|0.9%|5.2%|
[stopforumspam_1d](#stopforumspam_1d)|6745|6745|328|4.8%|5.1%|
[firehol_proxies](#firehol_proxies)|12379|12646|238|1.8%|3.7%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|234|44.6%|3.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|181|0.0%|2.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|165|0.0%|2.5%|
[php_commenters](#php_commenters)|430|430|51|11.8%|0.7%|
[alienvault_reputation](#alienvault_reputation)|192275|192275|39|0.0%|0.6%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|22|0.0%|0.3%|
[openbl_60d](#openbl_60d)|6984|6984|20|0.2%|0.3%|
[dragon_http](#dragon_http)|1029|270336|15|0.0%|0.2%|
[blocklist_de_apache](#blocklist_de_apache)|14231|14231|15|0.1%|0.2%|
[blocklist_de](#blocklist_de)|28768|28768|15|0.0%|0.2%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2863|2863|13|0.4%|0.2%|
[php_harvesters](#php_harvesters)|392|392|7|1.7%|0.1%|
[nixspam](#nixspam)|25392|25392|7|0.0%|0.1%|
[php_spammers](#php_spammers)|735|735|5|0.6%|0.0%|
[sorbs_spam](#sorbs_spam)|64701|65536|4|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|4|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|4|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7800|7800|4|0.0%|0.0%|
[php_dictionary](#php_dictionary)|737|737|4|0.5%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|4|0.0%|0.0%|
[voipbl](#voipbl)|10586|10998|3|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|3|0.0%|0.0%|
[firehol_level1](#firehol_level1)|5137|688854492|3|0.0%|0.0%|
[et_block](#et_block)|1000|18344011|3|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|17874|17874|2|0.0%|0.0%|
[xroxy](#xroxy)|2168|2168|1|0.0%|0.0%|
[shunlist](#shunlist)|1278|1278|1|0.0%|0.0%|
[iw_spamlist](#iw_spamlist)|3818|3818|1|0.0%|0.0%|

## feodo

[Abuse.ch Feodo tracker](https://feodotracker.abuse.ch) trojan includes IPs which are being used by Feodo (also known as Cridex or Bugat) which commits ebanking fraud - **excellent list**

Source is downloaded from [this link](https://feodotracker.abuse.ch/blocklist/?download=ipblocklist).

The last time downloaded was found to be dated: Thu Jun 11 17:36:31 UTC 2015.

The ipset `feodo` has **105** entries, **105** unique IPs.

The following table shows the overlaps of `feodo` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `feodo`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `feodo`.
- ` this % ` is the percentage **of this ipset (`feodo`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level1](#firehol_level1)|5137|688854492|105|0.0%|100.0%|
[et_block](#et_block)|1000|18344011|104|0.0%|99.0%|
[snort_ipfilter](#snort_ipfilter)|9671|9671|83|0.8%|79.0%|
[firehol_level3](#firehol_level3)|109650|9627417|83|0.0%|79.0%|
[sslbl](#sslbl)|371|371|38|10.2%|36.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|11|0.0%|10.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|3|0.0%|2.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|3|0.0%|2.8%|
[alienvault_reputation](#alienvault_reputation)|192275|192275|2|0.0%|1.9%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.9%|

## firehol_anonymous

**FireHOL Anonymous** - Known anonymizing IPs. (includes: firehol_proxies anonymous bm_tor dm_tor tor_exits)

Source is downloaded from [this link]().

The last time downloaded was found to be dated: Sun Jun  7 22:20:34 UTC 2015.

The ipset `firehol_anonymous` has **18960** entries, **82998** unique IPs.

The following table shows the overlaps of `firehol_anonymous` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `firehol_anonymous`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `firehol_anonymous`.
- ` this % ` is the percentage **of this ipset (`firehol_anonymous`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_proxies](#firehol_proxies)|12379|12646|12646|100.0%|15.2%|
[ri_web_proxies](#ri_web_proxies)|7800|7800|7800|100.0%|9.3%|
[firehol_level3](#firehol_level3)|109650|9627417|6785|0.0%|8.1%|
[bm_tor](#bm_tor)|6528|6528|6528|100.0%|7.8%|
[dm_tor](#dm_tor)|6506|6506|6506|100.0%|7.8%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|6196|6.5%|7.4%|
[et_tor](#et_tor)|6400|6400|5724|89.4%|6.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|3448|0.0%|4.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|2899|0.0%|3.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|2878|0.0%|3.4%|
[ri_connect_proxies](#ri_connect_proxies)|2811|2811|2811|100.0%|3.3%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|2750|9.4%|3.3%|
[xroxy](#xroxy)|2168|2168|2168|100.0%|2.6%|
[proxyrss](#proxyrss)|1373|1373|1373|100.0%|1.6%|
[firehol_level2](#firehol_level2)|22462|34082|1333|3.9%|1.6%|
[proxz](#proxz)|1307|1307|1307|100.0%|1.5%|
[snort_ipfilter](#snort_ipfilter)|9671|9671|1259|13.0%|1.5%|
[tor_exits](#tor_exits)|1116|1116|1116|100.0%|1.3%|
[stopforumspam_1d](#stopforumspam_1d)|6745|6745|981|14.5%|1.1%|
[blocklist_de](#blocklist_de)|28768|28768|667|2.3%|0.8%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|663|100.0%|0.7%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|524|100.0%|0.6%|
[blocklist_de_bots](#blocklist_de_bots)|2925|2925|513|17.5%|0.6%|
[sorbs_spam](#sorbs_spam)|64701|65536|201|0.3%|0.2%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|201|0.3%|0.2%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|201|0.3%|0.2%|
[nixspam](#nixspam)|25392|25392|180|0.7%|0.2%|
[blocklist_de_mail](#blocklist_de_mail)|17874|17874|127|0.7%|0.1%|
[php_dictionary](#php_dictionary)|737|737|98|13.2%|0.1%|
[php_spammers](#php_spammers)|735|735|81|11.0%|0.0%|
[php_commenters](#php_commenters)|430|430|81|18.8%|0.0%|
[voipbl](#voipbl)|10586|10998|79|0.7%|0.0%|
[alienvault_reputation](#alienvault_reputation)|192275|192275|57|0.0%|0.0%|
[dragon_http](#dragon_http)|1029|270336|41|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|29|0.0%|0.0%|
[sorbs_web](#sorbs_web)|544|545|26|4.7%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14231|14231|26|0.1%|0.0%|
[openbl_60d](#openbl_60d)|6984|6984|23|0.3%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2863|2863|23|0.8%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|15|0.0%|0.0%|
[iw_spamlist](#iw_spamlist)|3818|3818|14|0.3%|0.0%|
[php_harvesters](#php_harvesters)|392|392|12|3.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|175|175|9|5.1%|0.0%|
[firehol_level1](#firehol_level1)|5137|688854492|8|0.0%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|7|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|6|0.0%|0.0%|
[et_block](#et_block)|1000|18344011|6|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|1448|1448|4|0.2%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|3|0.2%|0.0%|
[et_compromised](#et_compromised)|1721|1721|3|0.1%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1700|1700|3|0.1%|0.0%|
[sslbl](#sslbl)|371|371|1|0.2%|0.0%|
[shunlist](#shunlist)|1278|1278|1|0.0%|0.0%|
[openbl_30d](#openbl_30d)|2809|2809|1|0.0%|0.0%|
[dshield](#dshield)|20|5120|1|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3225|3225|1|0.0%|0.0%|

## firehol_level1

**FireHOL Level 1** - Maximum protection without false positives. (includes: fullbogons dshield feodo palevo sslbl zeus spamhaus_drop spamhaus_edrop)

Source is downloaded from [this link]().

The last time downloaded was found to be dated: Sun Jun  7 22:15:43 UTC 2015.

The ipset `firehol_level1` has **5137** entries, **688854492** unique IPs.

The following table shows the overlaps of `firehol_level1` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `firehol_level1`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `firehol_level1`.
- ` this % ` is the percentage **of this ipset (`firehol_level1`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[fullbogons](#fullbogons)|3775|670173256|670173256|100.0%|97.2%|
[bogons](#bogons)|13|592708608|592708608|100.0%|86.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|18340608|100.0%|2.6%|
[et_block](#et_block)|1000|18344011|18340426|99.9%|2.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|8867717|2.5%|1.2%|
[firehol_level3](#firehol_level3)|109650|9627417|7500211|77.9%|1.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|7498240|81.6%|1.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|4637346|3.3%|0.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|2570563|0.3%|0.3%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|487424|100.0%|0.0%|
[dshield](#dshield)|20|5120|5120|100.0%|0.0%|
[alienvault_reputation](#alienvault_reputation)|192275|192275|5096|2.6%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1932|0.5%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|1090|1.1%|0.0%|
[dragon_http](#dragon_http)|1029|270336|1025|0.3%|0.0%|
[sslbl](#sslbl)|371|371|371|100.0%|0.0%|
[voipbl](#voipbl)|10586|10998|334|3.0%|0.0%|
[firehol_level2](#firehol_level2)|22462|34082|303|0.8%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9671|9671|299|3.0%|0.0%|
[openbl_60d](#openbl_60d)|6984|6984|299|4.2%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|278|0.9%|0.0%|
[blocklist_de](#blocklist_de)|28768|28768|236|0.8%|0.0%|
[zeus](#zeus)|230|230|230|100.0%|0.0%|
[zeus_badips](#zeus_badips)|202|202|202|100.0%|0.0%|
[shunlist](#shunlist)|1278|1278|183|14.3%|0.0%|
[openbl_30d](#openbl_30d)|2809|2809|167|5.9%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3225|3225|144|4.4%|0.0%|
[et_compromised](#et_compromised)|1721|1721|110|6.3%|0.0%|
[feodo](#feodo)|105|105|105|100.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6745|6745|83|1.2%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1700|1700|71|4.1%|0.0%|
[openbl_7d](#openbl_7d)|628|628|66|10.5%|0.0%|
[nixspam](#nixspam)|25392|25392|59|0.2%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|2925|2925|57|1.9%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|39|3.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|39|2.6%|0.0%|
[php_commenters](#php_commenters)|430|430|38|8.8%|0.0%|
[sorbs_spam](#sorbs_spam)|64701|65536|25|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|25|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|25|0.0%|0.0%|
[openbl_1d](#openbl_1d)|141|141|25|17.7%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|17874|17874|24|0.1%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|18|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|175|175|18|10.2%|0.0%|
[palevo](#palevo)|13|13|13|100.0%|0.0%|
[iw_spamlist](#iw_spamlist)|3818|3818|10|0.2%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2597|2597|10|0.3%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14231|14231|9|0.0%|0.0%|
[nt_malware_http](#nt_malware_http)|69|69|8|11.5%|0.0%|
[firehol_anonymous](#firehol_anonymous)|18960|82998|8|0.0%|0.0%|
[malc0de](#malc0de)|276|276|7|2.5%|0.0%|
[php_dictionary](#php_dictionary)|737|737|6|0.8%|0.0%|
[firehol_proxies](#firehol_proxies)|12379|12646|5|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2863|2863|5|0.1%|0.0%|
[php_spammers](#php_spammers)|735|735|4|0.5%|0.0%|
[ciarmy](#ciarmy)|473|473|4|0.8%|0.0%|
[php_harvesters](#php_harvesters)|392|392|3|0.7%|0.0%|
[nt_malware_irc](#nt_malware_irc)|43|43|3|6.9%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|3|0.4%|0.0%|
[et_tor](#et_tor)|6400|6400|3|0.0%|0.0%|
[dm_tor](#dm_tor)|6506|6506|3|0.0%|0.0%|
[bm_tor](#bm_tor)|6528|6528|3|0.0%|0.0%|
[tor_exits](#tor_exits)|1116|1116|2|0.1%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|84|84|2|2.3%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7800|7800|1|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|1|0.1%|0.0%|
[et_botcc](#et_botcc)|506|506|1|0.1%|0.0%|

## firehol_level2

**FireHOL Level 2** - Maximum protection from attacks took place in the last 48 hours. (includes: openbl_1d blocklist_de stopforumspam_1d)

Source is downloaded from [this link]().

The last time downloaded was found to be dated: Sun Jun  7 22:20:34 UTC 2015.

The ipset `firehol_level2` has **22462** entries, **34082** unique IPs.

The following table shows the overlaps of `firehol_level2` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `firehol_level2`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `firehol_level2`.
- ` this % ` is the percentage **of this ipset (`firehol_level2`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|28768|28768|28768|100.0%|84.4%|
[blocklist_de_mail](#blocklist_de_mail)|17874|17874|17845|99.8%|52.3%|
[blocklist_de_apache](#blocklist_de_apache)|14231|14231|14231|100.0%|41.7%|
[firehol_level3](#firehol_level3)|109650|9627417|8680|0.0%|25.4%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|7499|7.9%|22.0%|
[stopforumspam_1d](#stopforumspam_1d)|6745|6745|6745|100.0%|19.7%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|5577|19.1%|16.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|4018|0.0%|11.7%|
[blocklist_de_ssh](#blocklist_de_ssh)|3225|3225|3225|100.0%|9.4%|
[blocklist_de_bots](#blocklist_de_bots)|2925|2925|2925|100.0%|8.5%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2863|2863|2863|100.0%|8.4%|
[blocklist_de_imap](#blocklist_de_imap)|2597|2597|2597|100.0%|7.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|1719|0.0%|5.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|1699|0.0%|4.9%|
[blocklist_de_ftp](#blocklist_de_ftp)|1448|1448|1448|100.0%|4.2%|
[sorbs_spam](#sorbs_spam)|64701|65536|1373|2.0%|4.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|1365|2.0%|4.0%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|1365|2.0%|4.0%|
[firehol_anonymous](#firehol_anonymous)|18960|82998|1333|1.6%|3.9%|
[alienvault_reputation](#alienvault_reputation)|192275|192275|1309|0.6%|3.8%|
[firehol_proxies](#firehol_proxies)|12379|12646|1167|9.2%|3.4%|
[openbl_60d](#openbl_60d)|6984|6984|910|13.0%|2.6%|
[nixspam](#nixspam)|25392|25392|768|3.0%|2.2%|
[openbl_30d](#openbl_30d)|2809|2809|714|25.4%|2.0%|
[ri_web_proxies](#ri_web_proxies)|7800|7800|670|8.5%|1.9%|
[bruteforceblocker](#bruteforceblocker)|1700|1700|589|34.6%|1.7%|
[et_compromised](#et_compromised)|1721|1721|577|33.5%|1.6%|
[snort_ipfilter](#snort_ipfilter)|9671|9671|557|5.7%|1.6%|
[shunlist](#shunlist)|1278|1278|402|31.4%|1.1%|
[openbl_7d](#openbl_7d)|628|628|399|63.5%|1.1%|
[proxyrss](#proxyrss)|1373|1373|366|26.6%|1.0%|
[tor_exits](#tor_exits)|1116|1116|353|31.6%|1.0%|
[et_tor](#et_tor)|6400|6400|337|5.2%|0.9%|
[dm_tor](#dm_tor)|6506|6506|333|5.1%|0.9%|
[bm_tor](#bm_tor)|6528|6528|332|5.0%|0.9%|
[xroxy](#xroxy)|2168|2168|324|14.9%|0.9%|
[firehol_level1](#firehol_level1)|5137|688854492|303|0.0%|0.8%|
[et_block](#et_block)|1000|18344011|291|0.0%|0.8%|
[proxz](#proxz)|1307|1307|276|21.1%|0.8%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|265|0.0%|0.7%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|214|40.8%|0.6%|
[php_commenters](#php_commenters)|430|430|192|44.6%|0.5%|
[blocklist_de_strongips](#blocklist_de_strongips)|175|175|175|100.0%|0.5%|
[ri_connect_proxies](#ri_connect_proxies)|2811|2811|153|5.4%|0.4%|
[openbl_1d](#openbl_1d)|141|141|141|100.0%|0.4%|
[dshield](#dshield)|20|5120|138|2.6%|0.4%|
[iw_spamlist](#iw_spamlist)|3818|3818|130|3.4%|0.3%|
[php_dictionary](#php_dictionary)|737|737|128|17.3%|0.3%|
[php_spammers](#php_spammers)|735|735|119|16.1%|0.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|89|0.0%|0.2%|
[blocklist_de_sip](#blocklist_de_sip)|84|84|65|77.3%|0.1%|
[dragon_http](#dragon_http)|1029|270336|64|0.0%|0.1%|
[sorbs_web](#sorbs_web)|544|545|61|11.1%|0.1%|
[php_harvesters](#php_harvesters)|392|392|59|15.0%|0.1%|
[voipbl](#voipbl)|10586|10998|47|0.4%|0.1%|
[ciarmy](#ciarmy)|473|473|42|8.8%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|16|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|15|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|9|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|8|1.2%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|3|0.2%|0.0%|
[zeus_badips](#zeus_badips)|202|202|1|0.4%|0.0%|
[zeus](#zeus)|230|230|1|0.4%|0.0%|
[sorbs_socks](#sorbs_socks)|7|7|1|14.2%|0.0%|
[sorbs_misc](#sorbs_misc)|7|7|1|14.2%|0.0%|
[sorbs_http](#sorbs_http)|7|7|1|14.2%|0.0%|
[iw_wormlist](#iw_wormlist)|34|34|1|2.9%|0.0%|
[fullbogons](#fullbogons)|3775|670173256|1|0.0%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|115|115|1|0.8%|0.0%|

## firehol_level3

**FireHOL Level 3** - All the bad IPs in last 30 days. (includes: openbl_30d stopforumspam_30d virbl malc0de shunlist malwaredomainlist bruteforceblocker ciarmy cleanmx_viruses snort_ipfilter ib_bluetack_spyware ib_bluetack_hijacked ib_bluetack_webexploit php_commenters php_dictionary php_harvesters php_spammers iw_wormlist)

Source is downloaded from [this link]().

The last time downloaded was found to be dated: Sun Jun  7 22:20:34 UTC 2015.

The ipset `firehol_level3` has **109650** entries, **9627417** unique IPs.

The following table shows the overlaps of `firehol_level3` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `firehol_level3`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `firehol_level3`.
- ` this % ` is the percentage **of this ipset (`firehol_level3`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|9177856|100.0%|95.3%|
[firehol_level1](#firehol_level1)|5137|688854492|7500211|1.0%|77.9%|
[et_block](#et_block)|1000|18344011|6933380|37.7%|72.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|6933039|37.8%|72.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|2537269|0.7%|26.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|919973|0.1%|9.5%|
[fullbogons](#fullbogons)|3775|670173256|566692|0.0%|5.8%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|339173|100.0%|3.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|161590|0.1%|1.6%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|94309|100.0%|0.9%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|29184|99.9%|0.3%|
[snort_ipfilter](#snort_ipfilter)|9671|9671|9671|100.0%|0.1%|
[firehol_level2](#firehol_level2)|22462|34082|8680|25.4%|0.0%|
[firehol_anonymous](#firehol_anonymous)|18960|82998|6785|8.1%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6745|6745|6143|91.0%|0.0%|
[firehol_proxies](#firehol_proxies)|12379|12646|5652|44.6%|0.0%|
[alienvault_reputation](#alienvault_reputation)|192275|192275|5167|2.6%|0.0%|
[blocklist_de](#blocklist_de)|28768|28768|3926|13.6%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7800|7800|3728|47.7%|0.0%|
[openbl_60d](#openbl_60d)|6984|6984|2937|42.0%|0.0%|
[openbl_30d](#openbl_30d)|2809|2809|2809|100.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|2925|2925|2433|83.1%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1700|1700|1700|100.0%|0.0%|
[et_compromised](#et_compromised)|1721|1721|1691|98.2%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2811|2811|1584|56.3%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|1450|100.0%|0.0%|
[xroxy](#xroxy)|2168|2168|1301|60.0%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|1288|100.0%|0.0%|
[shunlist](#shunlist)|1278|1278|1278|100.0%|0.0%|
[sorbs_spam](#sorbs_spam)|64701|65536|1252|1.9%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|1250|1.9%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|1250|1.9%|0.0%|
[et_tor](#et_tor)|6400|6400|1124|17.5%|0.0%|
[bm_tor](#bm_tor)|6528|6528|1106|16.9%|0.0%|
[dm_tor](#dm_tor)|6506|6506|1104|16.9%|0.0%|
[tor_exits](#tor_exits)|1116|1116|1100|98.5%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3225|3225|910|28.2%|0.0%|
[proxz](#proxz)|1307|1307|778|59.5%|0.0%|
[php_dictionary](#php_dictionary)|737|737|737|100.0%|0.0%|
[php_spammers](#php_spammers)|735|735|735|100.0%|0.0%|
[proxyrss](#proxyrss)|1373|1373|683|49.7%|0.0%|
[openbl_7d](#openbl_7d)|628|628|628|100.0%|0.0%|
[dragon_http](#dragon_http)|1029|270336|558|0.2%|0.0%|
[nixspam](#nixspam)|25392|25392|504|1.9%|0.0%|
[ciarmy](#ciarmy)|473|473|473|100.0%|0.0%|
[php_commenters](#php_commenters)|430|430|430|100.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|17874|17874|406|2.2%|0.0%|
[php_harvesters](#php_harvesters)|392|392|392|100.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|346|66.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14231|14231|293|2.0%|0.0%|
[malc0de](#malc0de)|276|276|276|100.0%|0.0%|
[zeus](#zeus)|230|230|203|88.2%|0.0%|
[zeus_badips](#zeus_badips)|202|202|180|89.1%|0.0%|
[dshield](#dshield)|20|5120|170|3.3%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|175|175|162|92.5%|0.0%|
[openbl_1d](#openbl_1d)|141|141|139|98.5%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|115|115|115|100.0%|0.0%|
[iw_spamlist](#iw_spamlist)|3818|3818|100|2.6%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2863|2863|93|3.2%|0.0%|
[sslbl](#sslbl)|371|371|92|24.7%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|85|0.0%|0.0%|
[feodo](#feodo)|105|105|83|79.0%|0.0%|
[sorbs_web](#sorbs_web)|544|545|63|11.5%|0.0%|
[voipbl](#voipbl)|10586|10998|57|0.5%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2597|2597|35|1.3%|0.0%|
[iw_wormlist](#iw_wormlist)|34|34|34|100.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|25|3.7%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|25|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|1448|1448|21|1.4%|0.0%|
[virbl](#virbl)|19|19|19|100.0%|0.0%|
[palevo](#palevo)|13|13|11|84.6%|0.0%|
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

The ipset `firehol_proxies` has **12379** entries, **12646** unique IPs.

The following table shows the overlaps of `firehol_proxies` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `firehol_proxies`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `firehol_proxies`.
- ` this % ` is the percentage **of this ipset (`firehol_proxies`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_anonymous](#firehol_anonymous)|18960|82998|12646|15.2%|100.0%|
[ri_web_proxies](#ri_web_proxies)|7800|7800|7800|100.0%|61.6%|
[firehol_level3](#firehol_level3)|109650|9627417|5652|0.0%|44.6%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|5588|5.9%|44.1%|
[ri_connect_proxies](#ri_connect_proxies)|2811|2811|2811|100.0%|22.2%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|2379|8.1%|18.8%|
[xroxy](#xroxy)|2168|2168|2168|100.0%|17.1%|
[proxyrss](#proxyrss)|1373|1373|1373|100.0%|10.8%|
[proxz](#proxz)|1307|1307|1307|100.0%|10.3%|
[firehol_level2](#firehol_level2)|22462|34082|1167|3.4%|9.2%|
[stopforumspam_1d](#stopforumspam_1d)|6745|6745|832|12.3%|6.5%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|663|100.0%|5.2%|
[blocklist_de](#blocklist_de)|28768|28768|638|2.2%|5.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|526|0.0%|4.1%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|524|100.0%|4.1%|
[blocklist_de_bots](#blocklist_de_bots)|2925|2925|511|17.4%|4.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|394|0.0%|3.1%|
[snort_ipfilter](#snort_ipfilter)|9671|9671|330|3.4%|2.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|295|0.0%|2.3%|
[et_tor](#et_tor)|6400|6400|238|3.7%|1.8%|
[dm_tor](#dm_tor)|6506|6506|237|3.6%|1.8%|
[bm_tor](#bm_tor)|6528|6528|237|3.6%|1.8%|
[tor_exits](#tor_exits)|1116|1116|231|20.6%|1.8%|
[sorbs_spam](#sorbs_spam)|64701|65536|196|0.2%|1.5%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|196|0.3%|1.5%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|196|0.3%|1.5%|
[nixspam](#nixspam)|25392|25392|172|0.6%|1.3%|
[blocklist_de_mail](#blocklist_de_mail)|17874|17874|125|0.6%|0.9%|
[php_dictionary](#php_dictionary)|737|737|97|13.1%|0.7%|
[php_spammers](#php_spammers)|735|735|79|10.7%|0.6%|
[php_commenters](#php_commenters)|430|430|79|18.3%|0.6%|
[alienvault_reputation](#alienvault_reputation)|192275|192275|38|0.0%|0.3%|
[dragon_http](#dragon_http)|1029|270336|30|0.0%|0.2%|
[sorbs_web](#sorbs_web)|544|545|26|4.7%|0.2%|
[openbl_60d](#openbl_60d)|6984|6984|20|0.2%|0.1%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|15|0.0%|0.1%|
[iw_spamlist](#iw_spamlist)|3818|3818|13|0.3%|0.1%|
[php_harvesters](#php_harvesters)|392|392|12|3.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|11|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|175|175|9|5.1%|0.0%|
[firehol_level1](#firehol_level1)|5137|688854492|5|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|3|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|3|0.2%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|0.0%|
[et_compromised](#et_compromised)|1721|1721|3|0.1%|0.0%|
[et_block](#et_block)|1000|18344011|3|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1700|1700|3|0.1%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14231|14231|3|0.0%|0.0%|
[voipbl](#voipbl)|10586|10998|2|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2863|2863|2|0.0%|0.0%|
[sslbl](#sslbl)|371|371|1|0.2%|0.0%|
[shunlist](#shunlist)|1278|1278|1|0.0%|0.0%|
[dshield](#dshield)|20|5120|1|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3225|3225|1|0.0%|0.0%|

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
[firehol_level1](#firehol_level1)|5137|688854492|670173256|97.2%|100.0%|
[bogons](#bogons)|13|592708608|592708608|100.0%|88.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|4236143|3.0%|0.6%|
[firehol_level3](#firehol_level3)|109650|9627417|566692|5.8%|0.0%|
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
[iw_spamlist](#iw_spamlist)|3818|3818|5|0.1%|0.0%|
[nt_malware_http](#nt_malware_http)|69|69|4|5.7%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|2|0.0%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|1|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6745|6745|1|0.0%|0.0%|
[php_harvesters](#php_harvesters)|392|392|1|0.2%|0.0%|
[php_commenters](#php_commenters)|430|430|1|0.2%|0.0%|
[firehol_level2](#firehol_level2)|22462|34082|1|0.0%|0.0%|
[ciarmy](#ciarmy)|473|473|1|0.2%|0.0%|

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
[firehol_level3](#firehol_level3)|109650|9627417|25|0.0%|0.0%|
[firehol_level1](#firehol_level1)|5137|688854492|18|0.0%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|17|0.0%|0.0%|
[sorbs_spam](#sorbs_spam)|64701|65536|17|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|17|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|17|0.0%|0.0%|
[firehol_proxies](#firehol_proxies)|12379|12646|15|0.1%|0.0%|
[firehol_level2](#firehol_level2)|22462|34082|15|0.0%|0.0%|
[firehol_anonymous](#firehol_anonymous)|18960|82998|15|0.0%|0.0%|
[alienvault_reputation](#alienvault_reputation)|192275|192275|15|0.0%|0.0%|
[blocklist_de](#blocklist_de)|28768|28768|14|0.0%|0.0%|
[fullbogons](#fullbogons)|3775|670173256|13|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|11|1.6%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|17874|17874|9|0.0%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|7|0.0%|0.0%|
[nixspam](#nixspam)|25392|25392|6|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|5|0.0%|0.0%|
[et_block](#et_block)|1000|18344011|5|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7800|7800|4|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2597|2597|4|0.1%|0.0%|
[xroxy](#xroxy)|2168|2168|3|0.1%|0.0%|
[php_dictionary](#php_dictionary)|737|737|3|0.4%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|3|0.0%|0.0%|
[voipbl](#voipbl)|10586|10998|2|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9671|9671|2|0.0%|0.0%|
[php_harvesters](#php_harvesters)|392|392|2|0.5%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2863|2863|2|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14231|14231|2|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6745|6745|1|0.0%|0.0%|
[sorbs_web](#sorbs_web)|544|545|1|0.1%|0.0%|
[proxz](#proxz)|1307|1307|1|0.0%|0.0%|
[php_spammers](#php_spammers)|735|735|1|0.1%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|1|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3225|3225|1|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|1448|1448|1|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|2925|2925|1|0.0%|0.0%|

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
[firehol_level3](#firehol_level3)|109650|9627417|9177856|95.3%|100.0%|
[firehol_level1](#firehol_level1)|5137|688854492|7498240|1.0%|81.6%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|6932480|37.7%|75.5%|
[et_block](#et_block)|1000|18344011|6932480|37.7%|75.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|2526625|0.7%|27.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|904796|0.1%|9.8%|
[fullbogons](#fullbogons)|3775|670173256|565760|0.0%|6.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|145472|0.1%|1.5%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1036|0.3%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|725|0.7%|0.0%|
[alienvault_reputation](#alienvault_reputation)|192275|192275|521|0.2%|0.0%|
[dragon_http](#dragon_http)|1029|270336|256|0.0%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|147|0.5%|0.0%|
[firehol_level2](#firehol_level2)|22462|34082|89|0.2%|0.0%|
[blocklist_de](#blocklist_de)|28768|28768|61|0.2%|0.0%|
[nixspam](#nixspam)|25392|25392|58|0.2%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|2925|2925|49|1.6%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6745|6745|33|0.4%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|27|2.0%|0.0%|
[openbl_60d](#openbl_60d)|6984|6984|16|0.2%|0.0%|
[openbl_30d](#openbl_30d)|2809|2809|12|0.4%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9671|9671|11|0.1%|0.0%|
[zeus_badips](#zeus_badips)|202|202|10|4.9%|0.0%|
[zeus](#zeus)|230|230|10|4.3%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|7|0.4%|0.0%|
[firehol_anonymous](#firehol_anonymous)|18960|82998|7|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3225|3225|6|0.1%|0.0%|
[et_compromised](#et_compromised)|1721|1721|5|0.2%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1700|1700|5|0.2%|0.0%|
[php_dictionary](#php_dictionary)|737|737|4|0.5%|0.0%|
[openbl_7d](#openbl_7d)|628|628|4|0.6%|0.0%|
[iw_spamlist](#iw_spamlist)|3818|3818|4|0.1%|0.0%|
[et_tor](#et_tor)|6400|6400|4|0.0%|0.0%|
[dm_tor](#dm_tor)|6506|6506|4|0.0%|0.0%|
[bm_tor](#bm_tor)|6528|6528|4|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|17874|17874|4|0.0%|0.0%|
[shunlist](#shunlist)|1278|1278|3|0.2%|0.0%|
[php_spammers](#php_spammers)|735|735|3|0.4%|0.0%|
[nt_malware_http](#nt_malware_http)|69|69|3|4.3%|0.0%|
[firehol_proxies](#firehol_proxies)|12379|12646|3|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|175|175|3|1.7%|0.0%|
[tor_exits](#tor_exits)|1116|1116|2|0.1%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|2|0.3%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2597|2597|2|0.0%|0.0%|
[voipbl](#voipbl)|10586|10998|1|0.0%|0.0%|
[sorbs_spam](#sorbs_spam)|64701|65536|1|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|1|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|1|0.0%|0.0%|
[php_harvesters](#php_harvesters)|392|392|1|0.2%|0.0%|
[php_commenters](#php_commenters)|430|430|1|0.2%|0.0%|
[openbl_1d](#openbl_1d)|141|141|1|0.7%|0.0%|
[nt_malware_irc](#nt_malware_irc)|43|43|1|2.3%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|1|0.1%|0.0%|
[et_botcc](#et_botcc)|506|506|1|0.1%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|1448|1448|1|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2863|2863|1|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14231|14231|1|0.0%|0.0%|

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
[firehol_level1](#firehol_level1)|5137|688854492|2570563|0.3%|0.3%|
[et_block](#et_block)|1000|18344011|2272548|12.3%|0.2%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|2272265|12.3%|0.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|1354507|0.9%|0.1%|
[firehol_level3](#firehol_level3)|109650|9627417|919973|9.5%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|904796|9.8%|0.1%|
[fullbogons](#fullbogons)|3775|670173256|264873|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|33155|6.8%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|13247|3.9%|0.0%|
[dragon_http](#dragon_http)|1029|270336|6284|2.3%|0.0%|
[alienvault_reputation](#alienvault_reputation)|192275|192275|4451|2.3%|0.0%|
[firehol_anonymous](#firehol_anonymous)|18960|82998|3448|4.1%|0.0%|
[firehol_level2](#firehol_level2)|22462|34082|1719|5.0%|0.0%|
[blocklist_de](#blocklist_de)|28768|28768|1604|5.5%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|1522|1.6%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|17874|17874|1428|7.9%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14231|14231|1325|9.3%|0.0%|
[sorbs_spam](#sorbs_spam)|64701|65536|1208|1.8%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|1205|1.8%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|1205|1.8%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|506|1.7%|0.0%|
[nixspam](#nixspam)|25392|25392|486|1.9%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|394|0.8%|0.0%|
[voipbl](#voipbl)|10586|10998|302|2.7%|0.0%|
[firehol_proxies](#firehol_proxies)|12379|12646|295|2.3%|0.0%|
[dshield](#dshield)|20|5120|257|5.0%|0.0%|
[dm_tor](#dm_tor)|6506|6506|168|2.5%|0.0%|
[bm_tor](#bm_tor)|6528|6528|168|2.5%|0.0%|
[et_tor](#et_tor)|6400|6400|165|2.5%|0.0%|
[openbl_60d](#openbl_60d)|6984|6984|163|2.3%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7800|7800|156|2.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6745|6745|139|2.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9671|9671|116|1.1%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|97|6.6%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2811|2811|86|3.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2597|2597|72|2.7%|0.0%|
[iw_spamlist](#iw_spamlist)|3818|3818|69|1.8%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|66|5.1%|0.0%|
[openbl_30d](#openbl_30d)|2809|2809|65|2.3%|0.0%|
[xroxy](#xroxy)|2168|2168|58|2.6%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3225|3225|57|1.7%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|56|8.4%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1700|1700|55|3.2%|0.0%|
[et_compromised](#et_compromised)|1721|1721|52|3.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|2925|2925|46|1.5%|0.0%|
[proxz](#proxz)|1307|1307|44|3.3%|0.0%|
[et_botcc](#et_botcc)|506|506|40|7.9%|0.0%|
[ciarmy](#ciarmy)|473|473|38|8.0%|0.0%|
[tor_exits](#tor_exits)|1116|1116|37|3.3%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2863|2863|36|1.2%|0.0%|
[proxyrss](#proxyrss)|1373|1373|30|2.1%|0.0%|
[shunlist](#shunlist)|1278|1278|27|2.1%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|1448|1448|25|1.7%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|21|4.0%|0.0%|
[openbl_7d](#openbl_7d)|628|628|14|2.2%|0.0%|
[sorbs_web](#sorbs_web)|544|545|13|2.3%|0.0%|
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
[openbl_1d](#openbl_1d)|141|141|4|2.8%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|115|115|4|3.4%|0.0%|
[sslbl](#sslbl)|371|371|3|0.8%|0.0%|
[feodo](#feodo)|105|105|3|2.8%|0.0%|
[iw_wormlist](#iw_wormlist)|34|34|1|2.9%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|175|175|1|0.5%|0.0%|

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
[firehol_level1](#firehol_level1)|5137|688854492|8867717|1.2%|2.5%|
[et_block](#et_block)|1000|18344011|8532520|46.5%|2.4%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|8532506|46.5%|2.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|2830203|2.0%|0.8%|
[firehol_level3](#firehol_level3)|109650|9627417|2537269|26.3%|0.7%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2526625|27.5%|0.7%|
[fullbogons](#fullbogons)|3775|670173256|252671|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|98904|20.2%|0.0%|
[dragon_http](#dragon_http)|1029|270336|11960|4.4%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|7728|2.2%|0.0%|
[alienvault_reputation](#alienvault_reputation)|192275|192275|7003|3.6%|0.0%|
[firehol_anonymous](#firehol_anonymous)|18960|82998|2899|3.4%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|2476|2.6%|0.0%|
[sorbs_spam](#sorbs_spam)|64701|65536|1740|2.6%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|1736|2.6%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|1736|2.6%|0.0%|
[firehol_level2](#firehol_level2)|22462|34082|1699|4.9%|0.0%|
[blocklist_de](#blocklist_de)|28768|28768|1565|5.4%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|17874|17874|1273|7.1%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14231|14231|1094|7.6%|0.0%|
[nixspam](#nixspam)|25392|25392|782|3.0%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|768|2.6%|0.0%|
[voipbl](#voipbl)|10586|10998|436|3.9%|0.0%|
[firehol_proxies](#firehol_proxies)|12379|12646|394|3.1%|0.0%|
[openbl_60d](#openbl_60d)|6984|6984|320|4.5%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|226|0.4%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7800|7800|223|2.8%|0.0%|
[bm_tor](#bm_tor)|6528|6528|186|2.8%|0.0%|
[dm_tor](#dm_tor)|6506|6506|184|2.8%|0.0%|
[et_tor](#et_tor)|6400|6400|181|2.8%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6745|6745|178|2.6%|0.0%|
[openbl_30d](#openbl_30d)|2809|2809|147|5.2%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9671|9671|138|1.4%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3225|3225|126|3.9%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2811|2811|106|3.7%|0.0%|
[xroxy](#xroxy)|2168|2168|104|4.7%|0.0%|
[iw_spamlist](#iw_spamlist)|3818|3818|92|2.4%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1700|1700|88|5.1%|0.0%|
[et_compromised](#et_compromised)|1721|1721|85|4.9%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|2925|2925|75|2.5%|0.0%|
[shunlist](#shunlist)|1278|1278|73|5.7%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2597|2597|64|2.4%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2863|2863|59|2.0%|0.0%|
[proxyrss](#proxyrss)|1373|1373|54|3.9%|0.0%|
[php_spammers](#php_spammers)|735|735|54|7.3%|0.0%|
[proxz](#proxz)|1307|1307|52|3.9%|0.0%|
[ciarmy](#ciarmy)|473|473|49|10.3%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|45|3.1%|0.0%|
[tor_exits](#tor_exits)|1116|1116|40|3.5%|0.0%|
[openbl_7d](#openbl_7d)|628|628|39|6.2%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|29|5.5%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|26|2.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|26|3.9%|0.0%|
[php_dictionary](#php_dictionary)|737|737|23|3.1%|0.0%|
[sorbs_web](#sorbs_web)|544|545|21|3.8%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|1448|1448|21|1.4%|0.0%|
[et_botcc](#et_botcc)|506|506|20|3.9%|0.0%|
[php_commenters](#php_commenters)|430|430|18|4.1%|0.0%|
[malc0de](#malc0de)|276|276|16|5.7%|0.0%|
[zeus](#zeus)|230|230|9|3.9%|0.0%|
[php_harvesters](#php_harvesters)|392|392|9|2.2%|0.0%|
[zeus_badips](#zeus_badips)|202|202|8|3.9%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|175|175|8|4.5%|0.0%|
[sslbl](#sslbl)|371|371|6|1.6%|0.0%|
[openbl_1d](#openbl_1d)|141|141|6|4.2%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|115|115|6|5.2%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|84|84|5|5.9%|0.0%|
[palevo](#palevo)|13|13|3|23.0%|0.0%|
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
[firehol_level1](#firehol_level1)|5137|688854492|4637346|0.6%|3.3%|
[fullbogons](#fullbogons)|3775|670173256|4236143|0.6%|3.0%|
[bogons](#bogons)|13|592708608|4194304|0.7%|3.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|2830203|0.8%|2.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|1354507|0.1%|0.9%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|270785|55.5%|0.1%|
[firehol_level3](#firehol_level3)|109650|9627417|161590|1.6%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|145472|1.5%|0.1%|
[et_block](#et_block)|1000|18344011|130394|0.7%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|130368|0.7%|0.0%|
[dragon_http](#dragon_http)|1029|270336|20480|7.5%|0.0%|
[alienvault_reputation](#alienvault_reputation)|192275|192275|14343|7.4%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|9226|2.7%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|5830|6.1%|0.0%|
[firehol_level2](#firehol_level2)|22462|34082|4018|11.7%|0.0%|
[blocklist_de](#blocklist_de)|28768|28768|3594|12.4%|0.0%|
[firehol_anonymous](#firehol_anonymous)|18960|82998|2878|3.4%|0.0%|
[sorbs_spam](#sorbs_spam)|64701|65536|2860|4.3%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|2851|4.3%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|2851|4.3%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|17874|17874|2590|14.4%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14231|14231|2302|16.1%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|1953|6.6%|0.0%|
[nixspam](#nixspam)|25392|25392|1737|6.8%|0.0%|
[voipbl](#voipbl)|10586|10998|1613|14.6%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|1172|2.4%|0.0%|
[openbl_60d](#openbl_60d)|6984|6984|743|10.6%|0.0%|
[bm_tor](#bm_tor)|6528|6528|630|9.6%|0.0%|
[dm_tor](#dm_tor)|6506|6506|629|9.6%|0.0%|
[et_tor](#et_tor)|6400|6400|625|9.7%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6745|6745|528|7.8%|0.0%|
[firehol_proxies](#firehol_proxies)|12379|12646|526|4.1%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3225|3225|479|14.8%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2597|2597|296|11.3%|0.0%|
[openbl_30d](#openbl_30d)|2809|2809|291|10.3%|0.0%|
[iw_spamlist](#iw_spamlist)|3818|3818|262|6.8%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9671|9671|241|2.4%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7800|7800|220|2.8%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2863|2863|211|7.3%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|2925|2925|158|5.4%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1700|1700|157|9.2%|0.0%|
[et_compromised](#et_compromised)|1721|1721|152|8.8%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|150|28.6%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|147|11.4%|0.0%|
[tor_exits](#tor_exits)|1116|1116|128|11.4%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|1448|1448|125|8.6%|0.0%|
[shunlist](#shunlist)|1278|1278|123|9.6%|0.0%|
[xroxy](#xroxy)|2168|2168|111|5.1%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|108|7.4%|0.0%|
[proxz](#proxz)|1307|1307|105|8.0%|0.0%|
[ciarmy](#ciarmy)|473|473|102|21.5%|0.0%|
[et_botcc](#et_botcc)|506|506|77|15.2%|0.0%|
[openbl_7d](#openbl_7d)|628|628|65|10.3%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2811|2811|57|2.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|51|7.6%|0.0%|
[proxyrss](#proxyrss)|1373|1373|48|3.4%|0.0%|
[php_spammers](#php_spammers)|735|735|44|5.9%|0.0%|
[malc0de](#malc0de)|276|276|44|15.9%|0.0%|
[php_dictionary](#php_dictionary)|737|737|39|5.2%|0.0%|
[sslbl](#sslbl)|371|371|28|7.5%|0.0%|
[php_commenters](#php_commenters)|430|430|28|6.5%|0.0%|
[sorbs_web](#sorbs_web)|544|545|26|4.7%|0.0%|
[php_harvesters](#php_harvesters)|392|392|20|5.1%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|115|115|20|17.3%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|175|175|16|9.1%|0.0%|
[zeus](#zeus)|230|230|14|6.0%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|84|84|13|15.4%|0.0%|
[feodo](#feodo)|105|105|11|10.4%|0.0%|
[zeus_badips](#zeus_badips)|202|202|10|4.9%|0.0%|
[openbl_1d](#openbl_1d)|141|141|9|6.3%|0.0%|
[nt_malware_http](#nt_malware_http)|69|69|5|7.2%|0.0%|
[sorbs_socks](#sorbs_socks)|7|7|2|28.5%|0.0%|
[sorbs_misc](#sorbs_misc)|7|7|2|28.5%|0.0%|
[sorbs_http](#sorbs_http)|7|7|2|28.5%|0.0%|
[iw_wormlist](#iw_wormlist)|34|34|2|5.8%|0.0%|
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
[firehol_proxies](#firehol_proxies)|12379|12646|663|5.2%|100.0%|
[firehol_anonymous](#firehol_anonymous)|18960|82998|663|0.7%|100.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|56|0.0%|8.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|51|0.0%|7.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|26|0.0%|3.9%|
[firehol_level3](#firehol_level3)|109650|9627417|25|0.0%|3.7%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|20|0.0%|3.0%|
[ri_web_proxies](#ri_web_proxies)|7800|7800|15|0.1%|2.2%|
[xroxy](#xroxy)|2168|2168|13|0.5%|1.9%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|11|0.0%|1.6%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|11|0.0%|1.6%|
[proxyrss](#proxyrss)|1373|1373|10|0.7%|1.5%|
[firehol_level2](#firehol_level2)|22462|34082|8|0.0%|1.2%|
[ri_connect_proxies](#ri_connect_proxies)|2811|2811|7|0.2%|1.0%|
[proxz](#proxz)|1307|1307|6|0.4%|0.9%|
[stopforumspam_1d](#stopforumspam_1d)|6745|6745|5|0.0%|0.7%|
[blocklist_de](#blocklist_de)|28768|28768|4|0.0%|0.6%|
[nixspam](#nixspam)|25392|25392|3|0.0%|0.4%|
[firehol_level1](#firehol_level1)|5137|688854492|3|0.0%|0.4%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|2|0.0%|0.3%|
[php_dictionary](#php_dictionary)|737|737|2|0.2%|0.3%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|2|0.1%|0.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2|0.0%|0.3%|
[et_block](#et_block)|1000|18344011|2|0.0%|0.3%|
[blocklist_de_mail](#blocklist_de_mail)|17874|17874|2|0.0%|0.3%|
[blocklist_de_bots](#blocklist_de_bots)|2925|2925|2|0.0%|0.3%|
[alienvault_reputation](#alienvault_reputation)|192275|192275|2|0.0%|0.3%|
[sorbs_spam](#sorbs_spam)|64701|65536|1|0.0%|0.1%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|1|0.0%|0.1%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|1|0.0%|0.1%|
[snort_ipfilter](#snort_ipfilter)|9671|9671|1|0.0%|0.1%|
[php_spammers](#php_spammers)|735|735|1|0.1%|0.1%|
[dshield](#dshield)|20|5120|1|0.0%|0.1%|
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
[firehol_level3](#firehol_level3)|109650|9627417|339173|3.5%|100.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|13247|0.0%|3.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|9226|0.0%|2.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|7728|0.0%|2.2%|
[firehol_level1](#firehol_level1)|5137|688854492|1932|0.0%|0.5%|
[et_block](#et_block)|1000|18344011|1042|0.0%|0.3%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|1037|0.0%|0.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1036|0.0%|0.3%|
[fullbogons](#fullbogons)|3775|670173256|890|0.0%|0.2%|
[alienvault_reputation](#alienvault_reputation)|192275|192275|292|0.1%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|52|0.0%|0.0%|
[sorbs_spam](#sorbs_spam)|64701|65536|38|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|37|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|37|0.0%|0.0%|
[firehol_anonymous](#firehol_anonymous)|18960|82998|29|0.0%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|27|2.0%|0.0%|
[et_tor](#et_tor)|6400|6400|22|0.3%|0.0%|
[dm_tor](#dm_tor)|6506|6506|22|0.3%|0.0%|
[bm_tor](#bm_tor)|6528|6528|22|0.3%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|20|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|19|1.3%|0.0%|
[nixspam](#nixspam)|25392|25392|18|0.0%|0.0%|
[firehol_level2](#firehol_level2)|22462|34082|16|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9671|9671|14|0.1%|0.0%|
[firehol_proxies](#firehol_proxies)|12379|12646|11|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6745|6745|9|0.1%|0.0%|
[tor_exits](#tor_exits)|1116|1116|8|0.7%|0.0%|
[blocklist_de](#blocklist_de)|28768|28768|7|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7800|7800|6|0.0%|0.0%|
[dragon_http](#dragon_http)|1029|270336|6|0.0%|0.0%|
[openbl_60d](#openbl_60d)|6984|6984|5|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|5|0.9%|0.0%|
[voipbl](#voipbl)|10586|10998|4|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14231|14231|4|0.0%|0.0%|
[openbl_30d](#openbl_30d)|2809|2809|3|0.1%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|3|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2863|2863|3|0.1%|0.0%|
[palevo](#palevo)|13|13|2|15.3%|0.0%|
[malc0de](#malc0de)|276|276|2|0.7%|0.0%|
[iw_spamlist](#iw_spamlist)|3818|3818|2|0.0%|0.0%|
[et_compromised](#et_compromised)|1721|1721|2|0.1%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1700|1700|2|0.1%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|84|84|2|2.3%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|17874|17874|2|0.0%|0.0%|
[zeus_badips](#zeus_badips)|202|202|1|0.4%|0.0%|
[zeus](#zeus)|230|230|1|0.4%|0.0%|
[xroxy](#xroxy)|2168|2168|1|0.0%|0.0%|
[sslbl](#sslbl)|371|371|1|0.2%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|1|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2811|2811|1|0.0%|0.0%|
[proxz](#proxz)|1307|1307|1|0.0%|0.0%|
[proxyrss](#proxyrss)|1373|1373|1|0.0%|0.0%|
[php_harvesters](#php_harvesters)|392|392|1|0.2%|0.0%|
[php_dictionary](#php_dictionary)|737|737|1|0.1%|0.0%|
[php_commenters](#php_commenters)|430|430|1|0.2%|0.0%|
[nt_malware_http](#nt_malware_http)|69|69|1|1.4%|0.0%|
[feodo](#feodo)|105|105|1|0.9%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|115|115|1|0.8%|0.0%|
[bogons](#bogons)|13|592708608|1|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3225|3225|1|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|2925|2925|1|0.0%|0.0%|

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
[firehol_level3](#firehol_level3)|109650|9627417|1450|0.0%|100.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|108|0.0%|7.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|97|0.0%|6.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|45|0.0%|3.1%|
[firehol_level1](#firehol_level1)|5137|688854492|39|0.0%|2.6%|
[fullbogons](#fullbogons)|3775|670173256|33|0.0%|2.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|19|0.0%|1.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|7|0.0%|0.4%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|6|0.0%|0.4%|
[et_block](#et_block)|1000|18344011|6|0.0%|0.4%|
[alienvault_reputation](#alienvault_reputation)|192275|192275|6|0.0%|0.4%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|3|0.2%|0.2%|
[firehol_proxies](#firehol_proxies)|12379|12646|3|0.0%|0.2%|
[firehol_level2](#firehol_level2)|22462|34082|3|0.0%|0.2%|
[firehol_anonymous](#firehol_anonymous)|18960|82998|3|0.0%|0.2%|
[dragon_http](#dragon_http)|1029|270336|3|0.0%|0.2%|
[blocklist_de](#blocklist_de)|28768|28768|3|0.0%|0.2%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|2|0.0%|0.1%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|2|0.0%|0.1%|
[stopforumspam_1d](#stopforumspam_1d)|6745|6745|2|0.0%|0.1%|
[sorbs_spam](#sorbs_spam)|64701|65536|2|0.0%|0.1%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|2|0.0%|0.1%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|2|0.0%|0.1%|
[openbl_60d](#openbl_60d)|6984|6984|2|0.0%|0.1%|
[openbl_30d](#openbl_30d)|2809|2809|2|0.0%|0.1%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|2|0.3%|0.1%|
[blocklist_de_strongips](#blocklist_de_strongips)|175|175|2|1.1%|0.1%|
[blocklist_de_bots](#blocklist_de_bots)|2925|2925|2|0.0%|0.1%|
[snort_ipfilter](#snort_ipfilter)|9671|9671|1|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7800|7800|1|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|1|0.0%|0.0%|
[et_botcc](#et_botcc)|506|506|1|0.1%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3225|3225|1|0.0%|0.0%|

## iw_spamlist

[ImproWare Antispam](http://antispam.imp.ch/) IPs sending spam, in the last 3 days

Source is downloaded from [this link](http://antispam.imp.ch/spamlist).

The last time downloaded was found to be dated: Thu Jun 11 17:20:04 UTC 2015.

The ipset `iw_spamlist` has **3818** entries, **3818** unique IPs.

The following table shows the overlaps of `iw_spamlist` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `iw_spamlist`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `iw_spamlist`.
- ` this % ` is the percentage **of this ipset (`iw_spamlist`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[sorbs_spam](#sorbs_spam)|64701|65536|1217|1.8%|31.8%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|1212|1.8%|31.7%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|1212|1.8%|31.7%|
[nixspam](#nixspam)|25392|25392|747|2.9%|19.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|262|0.0%|6.8%|
[firehol_level2](#firehol_level2)|22462|34082|130|0.3%|3.4%|
[blocklist_de](#blocklist_de)|28768|28768|128|0.4%|3.3%|
[blocklist_de_mail](#blocklist_de_mail)|17874|17874|116|0.6%|3.0%|
[firehol_level3](#firehol_level3)|109650|9627417|100|0.0%|2.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|92|0.0%|2.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|69|0.0%|1.8%|
[snort_ipfilter](#snort_ipfilter)|9671|9671|60|0.6%|1.5%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|23|0.0%|0.6%|
[sorbs_web](#sorbs_web)|544|545|23|4.2%|0.6%|
[alienvault_reputation](#alienvault_reputation)|192275|192275|18|0.0%|0.4%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|14|0.0%|0.3%|
[firehol_anonymous](#firehol_anonymous)|18960|82998|14|0.0%|0.3%|
[iw_wormlist](#iw_wormlist)|34|34|13|38.2%|0.3%|
[firehol_proxies](#firehol_proxies)|12379|12646|13|0.1%|0.3%|
[ri_web_proxies](#ri_web_proxies)|7800|7800|11|0.1%|0.2%|
[firehol_level1](#firehol_level1)|5137|688854492|10|0.0%|0.2%|
[php_dictionary](#php_dictionary)|737|737|8|1.0%|0.2%|
[php_spammers](#php_spammers)|735|735|7|0.9%|0.1%|
[stopforumspam_1d](#stopforumspam_1d)|6745|6745|6|0.0%|0.1%|
[fullbogons](#fullbogons)|3775|670173256|5|0.0%|0.1%|
[bogons](#bogons)|13|592708608|5|0.0%|0.1%|
[blocklist_de_bots](#blocklist_de_bots)|2925|2925|5|0.1%|0.1%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|4|0.0%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|4|0.0%|0.1%|
[et_block](#et_block)|1000|18344011|4|0.0%|0.1%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2863|2863|4|0.1%|0.1%|
[blocklist_de_apache](#blocklist_de_apache)|14231|14231|4|0.0%|0.1%|
[php_harvesters](#php_harvesters)|392|392|3|0.7%|0.0%|
[dragon_http](#dragon_http)|1029|270336|3|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|1448|1448|3|0.2%|0.0%|
[xroxy](#xroxy)|2168|2168|2|0.0%|0.0%|
[php_commenters](#php_commenters)|430|430|2|0.4%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|2|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2597|2597|2|0.0%|0.0%|
[tor_exits](#tor_exits)|1116|1116|1|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|1|0.0%|0.0%|
[sorbs_socks](#sorbs_socks)|7|7|1|14.2%|0.0%|
[sorbs_misc](#sorbs_misc)|7|7|1|14.2%|0.0%|
[sorbs_http](#sorbs_http)|7|7|1|14.2%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2811|2811|1|0.0%|0.0%|
[proxyrss](#proxyrss)|1373|1373|1|0.0%|0.0%|
[et_tor](#et_tor)|6400|6400|1|0.0%|0.0%|
[dm_tor](#dm_tor)|6506|6506|1|0.0%|0.0%|
[bm_tor](#bm_tor)|6528|6528|1|0.0%|0.0%|

## iw_wormlist

[ImproWare Antispam](http://antispam.imp.ch/) IPs sending emails with viruses or worms, in the last 3 days

Source is downloaded from [this link](http://antispam.imp.ch/wormlist).

The last time downloaded was found to be dated: Thu Jun 11 17:20:04 UTC 2015.

The ipset `iw_wormlist` has **34** entries, **34** unique IPs.

The following table shows the overlaps of `iw_wormlist` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `iw_wormlist`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `iw_wormlist`.
- ` this % ` is the percentage **of this ipset (`iw_wormlist`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level3](#firehol_level3)|109650|9627417|34|0.0%|100.0%|
[iw_spamlist](#iw_spamlist)|3818|3818|13|0.3%|38.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|2|0.0%|5.8%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|1|0.0%|2.9%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|1|0.0%|2.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|1|0.0%|2.9%|
[firehol_level2](#firehol_level2)|22462|34082|1|0.0%|2.9%|
[blocklist_de_mail](#blocklist_de_mail)|17874|17874|1|0.0%|2.9%|
[blocklist_de](#blocklist_de)|28768|28768|1|0.0%|2.9%|

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
[firehol_level3](#firehol_level3)|109650|9627417|276|0.0%|100.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|44|0.0%|15.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|16|0.0%|5.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|10|0.0%|3.6%|
[cleanmx_viruses](#cleanmx_viruses)|115|115|9|7.8%|3.2%|
[alienvault_reputation](#alienvault_reputation)|192275|192275|9|0.0%|3.2%|
[firehol_level1](#firehol_level1)|5137|688854492|7|0.0%|2.5%|
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
[firehol_level3](#firehol_level3)|109650|9627417|1288|0.0%|100.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|147|0.0%|11.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|66|0.0%|5.1%|
[firehol_level1](#firehol_level1)|5137|688854492|39|0.0%|3.0%|
[et_block](#et_block)|1000|18344011|30|0.0%|2.3%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|29|0.0%|2.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|27|0.0%|2.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|27|0.0%|2.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|26|0.0%|2.0%|
[snort_ipfilter](#snort_ipfilter)|9671|9671|11|0.1%|0.8%|
[fullbogons](#fullbogons)|3775|670173256|9|0.0%|0.6%|
[alienvault_reputation](#alienvault_reputation)|192275|192275|8|0.0%|0.6%|
[malc0de](#malc0de)|276|276|4|1.4%|0.3%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|3|0.0%|0.2%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|3|0.2%|0.2%|
[dragon_http](#dragon_http)|1029|270336|2|0.0%|0.1%|
[zeus](#zeus)|230|230|1|0.4%|0.0%|
[nixspam](#nixspam)|25392|25392|1|0.0%|0.0%|
[et_botcc](#et_botcc)|506|506|1|0.1%|0.0%|

## maxmind_proxy_fraud

[MaxMind.com](https://www.maxmind.com/en/anonymous-proxy-fraudulent-ip-address-list) list of anonymous proxy fraudelent IP addresses.

Source is downloaded from [this link](https://www.maxmind.com/en/anonymous-proxy-fraudulent-ip-address-list).

The last time downloaded was found to be dated: Thu Jun 11 15:18:28 UTC 2015.

The ipset `maxmind_proxy_fraud` has **524** entries, **524** unique IPs.

The following table shows the overlaps of `maxmind_proxy_fraud` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `maxmind_proxy_fraud`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `maxmind_proxy_fraud`.
- ` this % ` is the percentage **of this ipset (`maxmind_proxy_fraud`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_proxies](#firehol_proxies)|12379|12646|524|4.1%|100.0%|
[firehol_anonymous](#firehol_anonymous)|18960|82998|524|0.6%|100.0%|
[firehol_level3](#firehol_level3)|109650|9627417|346|0.0%|66.0%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|345|0.3%|65.8%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|286|0.9%|54.5%|
[snort_ipfilter](#snort_ipfilter)|9671|9671|237|2.4%|45.2%|
[et_tor](#et_tor)|6400|6400|234|3.6%|44.6%|
[dm_tor](#dm_tor)|6506|6506|232|3.5%|44.2%|
[bm_tor](#bm_tor)|6528|6528|232|3.5%|44.2%|
[tor_exits](#tor_exits)|1116|1116|231|20.6%|44.0%|
[firehol_level2](#firehol_level2)|22462|34082|214|0.6%|40.8%|
[stopforumspam_1d](#stopforumspam_1d)|6745|6745|213|3.1%|40.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|150|0.0%|28.6%|
[php_commenters](#php_commenters)|430|430|52|12.0%|9.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|29|0.0%|5.5%|
[alienvault_reputation](#alienvault_reputation)|192275|192275|29|0.0%|5.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|21|0.0%|4.0%|
[openbl_60d](#openbl_60d)|6984|6984|20|0.2%|3.8%|
[ri_web_proxies](#ri_web_proxies)|7800|7800|10|0.1%|1.9%|
[php_harvesters](#php_harvesters)|392|392|7|1.7%|1.3%|
[blocklist_de](#blocklist_de)|28768|28768|7|0.0%|1.3%|
[php_spammers](#php_spammers)|735|735|6|0.8%|1.1%|
[php_dictionary](#php_dictionary)|737|737|5|0.6%|0.9%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|5|0.0%|0.9%|
[blocklist_de_bots](#blocklist_de_bots)|2925|2925|5|0.1%|0.9%|
[dragon_http](#dragon_http)|1029|270336|4|0.0%|0.7%|
[xroxy](#xroxy)|2168|2168|3|0.1%|0.5%|
[voipbl](#voipbl)|10586|10998|2|0.0%|0.3%|
[proxz](#proxz)|1307|1307|2|0.1%|0.3%|
[nixspam](#nixspam)|25392|25392|2|0.0%|0.3%|
[blocklist_de_apache](#blocklist_de_apache)|14231|14231|2|0.0%|0.3%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|1|0.0%|0.1%|
[sorbs_spam](#sorbs_spam)|64701|65536|1|0.0%|0.1%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|1|0.0%|0.1%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|1|0.0%|0.1%|
[shunlist](#shunlist)|1278|1278|1|0.0%|0.1%|
[ri_connect_proxies](#ri_connect_proxies)|2811|2811|1|0.0%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.1%|
[firehol_level1](#firehol_level1)|5137|688854492|1|0.0%|0.1%|
[et_block](#et_block)|1000|18344011|1|0.0%|0.1%|
[blocklist_de_mail](#blocklist_de_mail)|17874|17874|1|0.0%|0.1%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2863|2863|1|0.0%|0.1%|

## nixspam

[NiX Spam](http://www.heise.de/ix/NiX-Spam-DNSBL-and-blacklist-for-download-499637.html) IP addresses that sent spam in the last hour - automatically generated entries without distinguishing open proxies from relays, dialup gateways, and so on. All IPs are removed after 12 hours if there is no spam from there.

Source is downloaded from [this link](http://www.dnsbl.manitu.net/download/nixspam-ip.dump.gz).

The last time downloaded was found to be dated: Thu Jun 11 17:30:02 UTC 2015.

The ipset `nixspam` has **25392** entries, **25392** unique IPs.

The following table shows the overlaps of `nixspam` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `nixspam`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `nixspam`.
- ` this % ` is the percentage **of this ipset (`nixspam`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[sorbs_spam](#sorbs_spam)|64701|65536|4504|6.8%|17.7%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|4394|6.7%|17.3%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|4394|6.7%|17.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|1737|0.0%|6.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|782|0.0%|3.0%|
[firehol_level2](#firehol_level2)|22462|34082|768|2.2%|3.0%|
[blocklist_de](#blocklist_de)|28768|28768|750|2.6%|2.9%|
[iw_spamlist](#iw_spamlist)|3818|3818|747|19.5%|2.9%|
[blocklist_de_mail](#blocklist_de_mail)|17874|17874|672|3.7%|2.6%|
[firehol_level3](#firehol_level3)|109650|9627417|504|0.0%|1.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|486|0.0%|1.9%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|247|0.2%|0.9%|
[snort_ipfilter](#snort_ipfilter)|9671|9671|217|2.2%|0.8%|
[firehol_anonymous](#firehol_anonymous)|18960|82998|180|0.2%|0.7%|
[firehol_proxies](#firehol_proxies)|12379|12646|172|1.3%|0.6%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|136|0.4%|0.5%|
[ri_web_proxies](#ri_web_proxies)|7800|7800|130|1.6%|0.5%|
[php_dictionary](#php_dictionary)|737|737|122|16.5%|0.4%|
[sorbs_web](#sorbs_web)|544|545|112|20.5%|0.4%|
[php_spammers](#php_spammers)|735|735|106|14.4%|0.4%|
[xroxy](#xroxy)|2168|2168|62|2.8%|0.2%|
[firehol_level1](#firehol_level1)|5137|688854492|59|0.0%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|58|0.0%|0.2%|
[alienvault_reputation](#alienvault_reputation)|192275|192275|58|0.0%|0.2%|
[stopforumspam_1d](#stopforumspam_1d)|6745|6745|57|0.8%|0.2%|
[et_block](#et_block)|1000|18344011|56|0.0%|0.2%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|55|0.0%|0.2%|
[proxz](#proxz)|1307|1307|43|3.2%|0.1%|
[blocklist_de_imap](#blocklist_de_imap)|2597|2597|37|1.4%|0.1%|
[blocklist_de_bots](#blocklist_de_bots)|2925|2925|31|1.0%|0.1%|
[dragon_http](#dragon_http)|1029|270336|28|0.0%|0.1%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2863|2863|27|0.9%|0.1%|
[blocklist_de_apache](#blocklist_de_apache)|14231|14231|27|0.1%|0.1%|
[ri_connect_proxies](#ri_connect_proxies)|2811|2811|19|0.6%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|18|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|1448|1448|15|1.0%|0.0%|
[proxyrss](#proxyrss)|1373|1373|10|0.7%|0.0%|
[php_commenters](#php_commenters)|430|430|10|2.3%|0.0%|
[tor_exits](#tor_exits)|1116|1116|9|0.8%|0.0%|
[php_harvesters](#php_harvesters)|392|392|9|2.2%|0.0%|
[openbl_60d](#openbl_60d)|6984|6984|7|0.1%|0.0%|
[et_tor](#et_tor)|6400|6400|7|0.1%|0.0%|
[dm_tor](#dm_tor)|6506|6506|7|0.1%|0.0%|
[bm_tor](#bm_tor)|6528|6528|7|0.1%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|6|0.0%|0.0%|
[sorbs_socks](#sorbs_socks)|7|7|4|57.1%|0.0%|
[sorbs_misc](#sorbs_misc)|7|7|4|57.1%|0.0%|
[sorbs_http](#sorbs_http)|7|7|4|57.1%|0.0%|
[openbl_30d](#openbl_30d)|2809|2809|4|0.1%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|3|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|3|0.4%|0.0%|
[voipbl](#voipbl)|10586|10998|2|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|2|0.3%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|175|175|2|1.1%|0.0%|
[zeus_badips](#zeus_badips)|202|202|1|0.4%|0.0%|
[zeus](#zeus)|230|230|1|0.4%|0.0%|
[sorbs_smtp](#sorbs_smtp)|5|5|1|20.0%|0.0%|
[openbl_7d](#openbl_7d)|628|628|1|0.1%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|1|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3225|3225|1|0.0%|0.0%|

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
[firehol_level1](#firehol_level1)|5137|688854492|8|0.0%|11.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|7|0.0%|10.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|5|0.0%|7.2%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|4|0.0%|5.7%|
[fullbogons](#fullbogons)|3775|670173256|4|0.0%|5.7%|
[et_block](#et_block)|1000|18344011|4|0.0%|5.7%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|4.3%|
[firehol_level3](#firehol_level3)|109650|9627417|3|0.0%|4.3%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|2|0.0%|2.8%|
[nt_malware_irc](#nt_malware_irc)|43|43|2|4.6%|2.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|2|0.0%|2.8%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|1.4%|
[alienvault_reputation](#alienvault_reputation)|192275|192275|1|0.0%|1.4%|

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
[firehol_level1](#firehol_level1)|5137|688854492|3|0.0%|6.9%|
[et_block](#et_block)|1000|18344011|3|0.0%|6.9%|
[nt_malware_http](#nt_malware_http)|69|69|2|2.8%|4.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|2|0.0%|4.6%|
[alienvault_reputation](#alienvault_reputation)|192275|192275|2|0.0%|4.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|1|0.0%|2.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|2.3%|
[firehol_level3](#firehol_level3)|109650|9627417|1|0.0%|2.3%|

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

The last time downloaded was found to be dated: Thu Jun 11 17:32:00 UTC 2015.

The ipset `openbl_1d` has **141** entries, **141** unique IPs.

The following table shows the overlaps of `openbl_1d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl_1d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl_1d`.
- ` this % ` is the percentage **of this ipset (`openbl_1d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|22462|34082|141|0.4%|100.0%|
[openbl_60d](#openbl_60d)|6984|6984|139|1.9%|98.5%|
[openbl_30d](#openbl_30d)|2809|2809|139|4.9%|98.5%|
[firehol_level3](#firehol_level3)|109650|9627417|139|0.0%|98.5%|
[openbl_7d](#openbl_7d)|628|628|138|21.9%|97.8%|
[alienvault_reputation](#alienvault_reputation)|192275|192275|138|0.0%|97.8%|
[blocklist_de](#blocklist_de)|28768|28768|124|0.4%|87.9%|
[blocklist_de_ssh](#blocklist_de_ssh)|3225|3225|122|3.7%|86.5%|
[bruteforceblocker](#bruteforceblocker)|1700|1700|76|4.4%|53.9%|
[shunlist](#shunlist)|1278|1278|73|5.7%|51.7%|
[et_compromised](#et_compromised)|1721|1721|73|4.2%|51.7%|
[firehol_level1](#firehol_level1)|5137|688854492|25|0.0%|17.7%|
[dshield](#dshield)|20|5120|24|0.4%|17.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|18|0.0%|12.7%|
[et_block](#et_block)|1000|18344011|18|0.0%|12.7%|
[blocklist_de_strongips](#blocklist_de_strongips)|175|175|16|9.1%|11.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|9|0.0%|6.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|6|0.0%|4.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|4|0.0%|2.8%|
[dragon_http](#dragon_http)|1029|270336|4|0.0%|2.8%|
[ciarmy](#ciarmy)|473|473|2|0.4%|1.4%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|1|0.0%|0.7%|
[php_spammers](#php_spammers)|735|735|1|0.1%|0.7%|
[php_commenters](#php_commenters)|430|430|1|0.2%|0.7%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.7%|
[blocklist_de_mail](#blocklist_de_mail)|17874|17874|1|0.0%|0.7%|
[blocklist_de_imap](#blocklist_de_imap)|2597|2597|1|0.0%|0.7%|
[blocklist_de_apache](#blocklist_de_apache)|14231|14231|1|0.0%|0.7%|

## openbl_30d

[OpenBL.org](http://www.openbl.org/) last 30 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.

Source is downloaded from [this link](http://www.openbl.org/lists/base_30days.txt).

The last time downloaded was found to be dated: Thu Jun 11 16:07:00 UTC 2015.

The ipset `openbl_30d` has **2809** entries, **2809** unique IPs.

The following table shows the overlaps of `openbl_30d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl_30d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl_30d`.
- ` this % ` is the percentage **of this ipset (`openbl_30d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[openbl_60d](#openbl_60d)|6984|6984|2809|40.2%|100.0%|
[firehol_level3](#firehol_level3)|109650|9627417|2809|0.0%|100.0%|
[alienvault_reputation](#alienvault_reputation)|192275|192275|2794|1.4%|99.4%|
[et_compromised](#et_compromised)|1721|1721|945|54.9%|33.6%|
[bruteforceblocker](#bruteforceblocker)|1700|1700|908|53.4%|32.3%|
[firehol_level2](#firehol_level2)|22462|34082|714|2.0%|25.4%|
[blocklist_de](#blocklist_de)|28768|28768|698|2.4%|24.8%|
[blocklist_de_ssh](#blocklist_de_ssh)|3225|3225|677|20.9%|24.1%|
[openbl_7d](#openbl_7d)|628|628|628|100.0%|22.3%|
[shunlist](#shunlist)|1278|1278|511|39.9%|18.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|291|0.0%|10.3%|
[firehol_level1](#firehol_level1)|5137|688854492|167|0.0%|5.9%|
[et_block](#et_block)|1000|18344011|163|0.0%|5.8%|
[dshield](#dshield)|20|5120|148|2.8%|5.2%|
[dragon_http](#dragon_http)|1029|270336|148|0.0%|5.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|147|0.0%|5.2%|
[openbl_1d](#openbl_1d)|141|141|139|98.5%|4.9%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|119|0.0%|4.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|65|0.0%|2.3%|
[blocklist_de_strongips](#blocklist_de_strongips)|175|175|24|13.7%|0.8%|
[blocklist_de_mail](#blocklist_de_mail)|17874|17874|14|0.0%|0.4%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|12|0.0%|0.4%|
[blocklist_de_imap](#blocklist_de_imap)|2597|2597|8|0.3%|0.2%|
[blocklist_de_apache](#blocklist_de_apache)|14231|14231|6|0.0%|0.2%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|5|0.0%|0.1%|
[nixspam](#nixspam)|25392|25392|4|0.0%|0.1%|
[voipbl](#voipbl)|10586|10998|3|0.0%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|3|0.0%|0.1%|
[ciarmy](#ciarmy)|473|473|3|0.6%|0.1%|
[zeus](#zeus)|230|230|2|0.8%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9671|9671|2|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|2|0.1%|0.0%|
[zeus_badips](#zeus_badips)|202|202|1|0.4%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|1|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6745|6745|1|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|1|0.0%|0.0%|
[php_spammers](#php_spammers)|735|735|1|0.1%|0.0%|
[php_commenters](#php_commenters)|430|430|1|0.2%|0.0%|
[firehol_anonymous](#firehol_anonymous)|18960|82998|1|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|1448|1448|1|0.0%|0.0%|

## openbl_60d

[OpenBL.org](http://www.openbl.org/) last 60 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.

Source is downloaded from [this link](http://www.openbl.org/lists/base_60days.txt).

The last time downloaded was found to be dated: Thu Jun 11 16:07:00 UTC 2015.

The ipset `openbl_60d` has **6984** entries, **6984** unique IPs.

The following table shows the overlaps of `openbl_60d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl_60d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl_60d`.
- ` this % ` is the percentage **of this ipset (`openbl_60d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[alienvault_reputation](#alienvault_reputation)|192275|192275|6964|3.6%|99.7%|
[firehol_level3](#firehol_level3)|109650|9627417|2937|0.0%|42.0%|
[openbl_30d](#openbl_30d)|2809|2809|2809|100.0%|40.2%|
[et_compromised](#et_compromised)|1721|1721|1014|58.9%|14.5%|
[bruteforceblocker](#bruteforceblocker)|1700|1700|969|57.0%|13.8%|
[firehol_level2](#firehol_level2)|22462|34082|910|2.6%|13.0%|
[blocklist_de](#blocklist_de)|28768|28768|876|3.0%|12.5%|
[blocklist_de_ssh](#blocklist_de_ssh)|3225|3225|845|26.2%|12.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|743|0.0%|10.6%|
[openbl_7d](#openbl_7d)|628|628|628|100.0%|8.9%|
[shunlist](#shunlist)|1278|1278|543|42.4%|7.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|320|0.0%|4.5%|
[firehol_level1](#firehol_level1)|5137|688854492|299|0.0%|4.2%|
[et_block](#et_block)|1000|18344011|299|0.0%|4.2%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|235|0.0%|3.3%|
[dragon_http](#dragon_http)|1029|270336|219|0.0%|3.1%|
[dshield](#dshield)|20|5120|166|3.2%|2.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|163|0.0%|2.3%|
[openbl_1d](#openbl_1d)|141|141|139|98.5%|1.9%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|47|0.0%|0.6%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|27|0.0%|0.3%|
[blocklist_de_strongips](#blocklist_de_strongips)|175|175|25|14.2%|0.3%|
[snort_ipfilter](#snort_ipfilter)|9671|9671|24|0.2%|0.3%|
[firehol_anonymous](#firehol_anonymous)|18960|82998|23|0.0%|0.3%|
[blocklist_de_mail](#blocklist_de_mail)|17874|17874|22|0.1%|0.3%|
[tor_exits](#tor_exits)|1116|1116|20|1.7%|0.2%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|20|3.8%|0.2%|
[firehol_proxies](#firehol_proxies)|12379|12646|20|0.1%|0.2%|
[et_tor](#et_tor)|6400|6400|20|0.3%|0.2%|
[dm_tor](#dm_tor)|6506|6506|20|0.3%|0.2%|
[bm_tor](#bm_tor)|6528|6528|20|0.3%|0.2%|
[stopforumspam_1d](#stopforumspam_1d)|6745|6745|19|0.2%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|16|0.0%|0.2%|
[blocklist_de_imap](#blocklist_de_imap)|2597|2597|15|0.5%|0.2%|
[php_commenters](#php_commenters)|430|430|11|2.5%|0.1%|
[voipbl](#voipbl)|10586|10998|8|0.0%|0.1%|
[nixspam](#nixspam)|25392|25392|7|0.0%|0.1%|
[blocklist_de_apache](#blocklist_de_apache)|14231|14231|7|0.0%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|5|0.0%|0.0%|
[ciarmy](#ciarmy)|473|473|3|0.6%|0.0%|
[zeus](#zeus)|230|230|2|0.8%|0.0%|
[sorbs_spam](#sorbs_spam)|64701|65536|2|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|2|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|2|0.0%|0.0%|
[php_harvesters](#php_harvesters)|392|392|2|0.5%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|2|0.1%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|1448|1448|2|0.1%|0.0%|
[zeus_badips](#zeus_badips)|202|202|1|0.4%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|1|0.0%|0.0%|
[php_spammers](#php_spammers)|735|735|1|0.1%|0.0%|

## openbl_7d

[OpenBL.org](http://www.openbl.org/) last 7 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.

Source is downloaded from [this link](http://www.openbl.org/lists/base_7days.txt).

The last time downloaded was found to be dated: Thu Jun 11 16:07:00 UTC 2015.

The ipset `openbl_7d` has **628** entries, **628** unique IPs.

The following table shows the overlaps of `openbl_7d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl_7d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl_7d`.
- ` this % ` is the percentage **of this ipset (`openbl_7d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[openbl_60d](#openbl_60d)|6984|6984|628|8.9%|100.0%|
[openbl_30d](#openbl_30d)|2809|2809|628|22.3%|100.0%|
[firehol_level3](#firehol_level3)|109650|9627417|628|0.0%|100.0%|
[alienvault_reputation](#alienvault_reputation)|192275|192275|626|0.3%|99.6%|
[firehol_level2](#firehol_level2)|22462|34082|399|1.1%|63.5%|
[blocklist_de](#blocklist_de)|28768|28768|384|1.3%|61.1%|
[blocklist_de_ssh](#blocklist_de_ssh)|3225|3225|371|11.5%|59.0%|
[et_compromised](#et_compromised)|1721|1721|308|17.8%|49.0%|
[bruteforceblocker](#bruteforceblocker)|1700|1700|307|18.0%|48.8%|
[shunlist](#shunlist)|1278|1278|210|16.4%|33.4%|
[openbl_1d](#openbl_1d)|141|141|138|97.8%|21.9%|
[firehol_level1](#firehol_level1)|5137|688854492|66|0.0%|10.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|65|0.0%|10.3%|
[et_block](#et_block)|1000|18344011|61|0.0%|9.7%|
[dshield](#dshield)|20|5120|60|1.1%|9.5%|
[dragon_http](#dragon_http)|1029|270336|54|0.0%|8.5%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|52|0.0%|8.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|39|0.0%|6.2%|
[blocklist_de_strongips](#blocklist_de_strongips)|175|175|23|13.1%|3.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|14|0.0%|2.2%|
[blocklist_de_mail](#blocklist_de_mail)|17874|17874|8|0.0%|1.2%|
[blocklist_de_imap](#blocklist_de_imap)|2597|2597|6|0.2%|0.9%|
[blocklist_de_apache](#blocklist_de_apache)|14231|14231|5|0.0%|0.7%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|4|0.0%|0.6%|
[ciarmy](#ciarmy)|473|473|3|0.6%|0.4%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|2|0.0%|0.3%|
[zeus_badips](#zeus_badips)|202|202|1|0.4%|0.1%|
[zeus](#zeus)|230|230|1|0.4%|0.1%|
[snort_ipfilter](#snort_ipfilter)|9671|9671|1|0.0%|0.1%|
[php_spammers](#php_spammers)|735|735|1|0.1%|0.1%|
[php_commenters](#php_commenters)|430|430|1|0.2%|0.1%|
[nixspam](#nixspam)|25392|25392|1|0.0%|0.1%|
[blocklist_de_ftp](#blocklist_de_ftp)|1448|1448|1|0.0%|0.1%|

## palevo

[Abuse.ch Palevo tracker](https://palevotracker.abuse.ch) worm includes IPs which are being used as botnet C&C for the Palevo crimeware - **excellent list**

Source is downloaded from [this link](https://palevotracker.abuse.ch/blocklists.php?download=ipblocklist).

The last time downloaded was found to be dated: Thu Jun 11 17:36:27 UTC 2015.

The ipset `palevo` has **13** entries, **13** unique IPs.

The following table shows the overlaps of `palevo` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `palevo`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `palevo`.
- ` this % ` is the percentage **of this ipset (`palevo`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level1](#firehol_level1)|5137|688854492|13|0.0%|100.0%|
[et_block](#et_block)|1000|18344011|13|0.0%|100.0%|
[snort_ipfilter](#snort_ipfilter)|9671|9671|11|0.1%|84.6%|
[firehol_level3](#firehol_level3)|109650|9627417|11|0.0%|84.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|3|0.0%|23.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|2|0.0%|15.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|1|0.0%|7.6%|

## php_commenters

[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) comment spammers (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=c&rss=1).

The last time downloaded was found to be dated: Thu Jun 11 17:00:23 UTC 2015.

The ipset `php_commenters` has **430** entries, **430** unique IPs.

The following table shows the overlaps of `php_commenters` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `php_commenters`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `php_commenters`.
- ` this % ` is the percentage **of this ipset (`php_commenters`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level3](#firehol_level3)|109650|9627417|430|0.0%|100.0%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|321|0.3%|74.6%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|240|0.8%|55.8%|
[firehol_level2](#firehol_level2)|22462|34082|192|0.5%|44.6%|
[stopforumspam_1d](#stopforumspam_1d)|6745|6745|168|2.4%|39.0%|
[blocklist_de](#blocklist_de)|28768|28768|101|0.3%|23.4%|
[firehol_anonymous](#firehol_anonymous)|18960|82998|81|0.0%|18.8%|
[blocklist_de_bots](#blocklist_de_bots)|2925|2925|81|2.7%|18.8%|
[firehol_proxies](#firehol_proxies)|12379|12646|79|0.6%|18.3%|
[snort_ipfilter](#snort_ipfilter)|9671|9671|64|0.6%|14.8%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|52|9.9%|12.0%|
[tor_exits](#tor_exits)|1116|1116|51|4.5%|11.8%|
[et_tor](#et_tor)|6400|6400|51|0.7%|11.8%|
[dm_tor](#dm_tor)|6506|6506|51|0.7%|11.8%|
[bm_tor](#bm_tor)|6528|6528|51|0.7%|11.8%|
[php_spammers](#php_spammers)|735|735|50|6.8%|11.6%|
[blocklist_de_strongips](#blocklist_de_strongips)|175|175|45|25.7%|10.4%|
[firehol_level1](#firehol_level1)|5137|688854492|38|0.0%|8.8%|
[php_dictionary](#php_dictionary)|737|737|34|4.6%|7.9%|
[blocklist_de_apache](#blocklist_de_apache)|14231|14231|30|0.2%|6.9%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|29|0.0%|6.7%|
[et_block](#et_block)|1000|18344011|29|0.0%|6.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|28|0.0%|6.5%|
[blocklist_de_mail](#blocklist_de_mail)|17874|17874|27|0.1%|6.2%|
[ri_web_proxies](#ri_web_proxies)|7800|7800|25|0.3%|5.8%|
[sorbs_spam](#sorbs_spam)|64701|65536|22|0.0%|5.1%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|22|0.0%|5.1%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|22|0.0%|5.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|18|0.0%|4.1%|
[alienvault_reputation](#alienvault_reputation)|192275|192275|18|0.0%|4.1%|
[php_harvesters](#php_harvesters)|392|392|15|3.8%|3.4%|
[openbl_60d](#openbl_60d)|6984|6984|11|0.1%|2.5%|
[xroxy](#xroxy)|2168|2168|10|0.4%|2.3%|
[nixspam](#nixspam)|25392|25392|10|0.0%|2.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|10|0.0%|2.3%|
[proxz](#proxz)|1307|1307|9|0.6%|2.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2863|2863|9|0.3%|2.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|8|0.0%|1.8%|
[ri_connect_proxies](#ri_connect_proxies)|2811|2811|5|0.1%|1.1%|
[dragon_http](#dragon_http)|1029|270336|4|0.0%|0.9%|
[sorbs_web](#sorbs_web)|544|545|2|0.3%|0.4%|
[iw_spamlist](#iw_spamlist)|3818|3818|2|0.0%|0.4%|
[zeus_badips](#zeus_badips)|202|202|1|0.4%|0.2%|
[zeus](#zeus)|230|230|1|0.4%|0.2%|
[proxyrss](#proxyrss)|1373|1373|1|0.0%|0.2%|
[openbl_7d](#openbl_7d)|628|628|1|0.1%|0.2%|
[openbl_30d](#openbl_30d)|2809|2809|1|0.0%|0.2%|
[openbl_1d](#openbl_1d)|141|141|1|0.7%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.2%|
[fullbogons](#fullbogons)|3775|670173256|1|0.0%|0.2%|
[et_compromised](#et_compromised)|1721|1721|1|0.0%|0.2%|
[bruteforceblocker](#bruteforceblocker)|1700|1700|1|0.0%|0.2%|
[bogons](#bogons)|13|592708608|1|0.0%|0.2%|
[blocklist_de_ssh](#blocklist_de_ssh)|3225|3225|1|0.0%|0.2%|

## php_dictionary

[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) directory attackers (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=d&rss=1).

The last time downloaded was found to be dated: Thu Jun 11 17:00:24 UTC 2015.

The ipset `php_dictionary` has **737** entries, **737** unique IPs.

The following table shows the overlaps of `php_dictionary` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `php_dictionary`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `php_dictionary`.
- ` this % ` is the percentage **of this ipset (`php_dictionary`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level3](#firehol_level3)|109650|9627417|737|0.0%|100.0%|
[php_spammers](#php_spammers)|735|735|322|43.8%|43.6%|
[sorbs_spam](#sorbs_spam)|64701|65536|214|0.3%|29.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|214|0.3%|29.0%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|214|0.3%|29.0%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|139|0.1%|18.8%|
[firehol_level2](#firehol_level2)|22462|34082|128|0.3%|17.3%|
[nixspam](#nixspam)|25392|25392|122|0.4%|16.5%|
[blocklist_de](#blocklist_de)|28768|28768|121|0.4%|16.4%|
[blocklist_de_mail](#blocklist_de_mail)|17874|17874|101|0.5%|13.7%|
[firehol_anonymous](#firehol_anonymous)|18960|82998|98|0.1%|13.2%|
[firehol_proxies](#firehol_proxies)|12379|12646|97|0.7%|13.1%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|94|0.3%|12.7%|
[snort_ipfilter](#snort_ipfilter)|9671|9671|91|0.9%|12.3%|
[ri_web_proxies](#ri_web_proxies)|7800|7800|67|0.8%|9.0%|
[xroxy](#xroxy)|2168|2168|41|1.8%|5.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|39|0.0%|5.2%|
[stopforumspam_1d](#stopforumspam_1d)|6745|6745|35|0.5%|4.7%|
[php_commenters](#php_commenters)|430|430|34|7.9%|4.6%|
[sorbs_web](#sorbs_web)|544|545|30|5.5%|4.0%|
[proxz](#proxz)|1307|1307|25|1.9%|3.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|23|0.0%|3.1%|
[blocklist_de_bots](#blocklist_de_bots)|2925|2925|17|0.5%|2.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|12|0.0%|1.6%|
[iw_spamlist](#iw_spamlist)|3818|3818|8|0.2%|1.0%|
[alienvault_reputation](#alienvault_reputation)|192275|192275|7|0.0%|0.9%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|6|0.0%|0.8%|
[firehol_level1](#firehol_level1)|5137|688854492|6|0.0%|0.8%|
[et_block](#et_block)|1000|18344011|6|0.0%|0.8%|
[ri_connect_proxies](#ri_connect_proxies)|2811|2811|5|0.1%|0.6%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|5|0.9%|0.6%|
[blocklist_de_strongips](#blocklist_de_strongips)|175|175|5|2.8%|0.6%|
[tor_exits](#tor_exits)|1116|1116|4|0.3%|0.5%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|4|0.0%|0.5%|
[et_tor](#et_tor)|6400|6400|4|0.0%|0.5%|
[dm_tor](#dm_tor)|6506|6506|4|0.0%|0.5%|
[bm_tor](#bm_tor)|6528|6528|4|0.0%|0.5%|
[php_harvesters](#php_harvesters)|392|392|3|0.7%|0.4%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|3|0.0%|0.4%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2863|2863|3|0.1%|0.4%|
[blocklist_de_apache](#blocklist_de_apache)|14231|14231|3|0.0%|0.4%|
[proxyrss](#proxyrss)|1373|1373|2|0.1%|0.2%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|2|0.3%|0.2%|
[dragon_http](#dragon_http)|1029|270336|2|0.0%|0.2%|
[sorbs_socks](#sorbs_socks)|7|7|1|14.2%|0.1%|
[sorbs_misc](#sorbs_misc)|7|7|1|14.2%|0.1%|
[sorbs_http](#sorbs_http)|7|7|1|14.2%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.1%|
[blocklist_de_ftp](#blocklist_de_ftp)|1448|1448|1|0.0%|0.1%|

## php_harvesters

[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) harvesters (IPs that surf the internet looking for email addresses) (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=h&rss=1).

The last time downloaded was found to be dated: Thu Jun 11 17:00:22 UTC 2015.

The ipset `php_harvesters` has **392** entries, **392** unique IPs.

The following table shows the overlaps of `php_harvesters` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `php_harvesters`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `php_harvesters`.
- ` this % ` is the percentage **of this ipset (`php_harvesters`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level3](#firehol_level3)|109650|9627417|392|0.0%|100.0%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|86|0.0%|21.9%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|61|0.2%|15.5%|
[firehol_level2](#firehol_level2)|22462|34082|59|0.1%|15.0%|
[stopforumspam_1d](#stopforumspam_1d)|6745|6745|44|0.6%|11.2%|
[blocklist_de](#blocklist_de)|28768|28768|39|0.1%|9.9%|
[blocklist_de_bots](#blocklist_de_bots)|2925|2925|27|0.9%|6.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|20|0.0%|5.1%|
[php_commenters](#php_commenters)|430|430|15|3.4%|3.8%|
[sorbs_spam](#sorbs_spam)|64701|65536|14|0.0%|3.5%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|14|0.0%|3.5%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|14|0.0%|3.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|12|0.0%|3.0%|
[firehol_proxies](#firehol_proxies)|12379|12646|12|0.0%|3.0%|
[firehol_anonymous](#firehol_anonymous)|18960|82998|12|0.0%|3.0%|
[alienvault_reputation](#alienvault_reputation)|192275|192275|12|0.0%|3.0%|
[snort_ipfilter](#snort_ipfilter)|9671|9671|11|0.1%|2.8%|
[nixspam](#nixspam)|25392|25392|9|0.0%|2.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|9|0.0%|2.2%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|7|1.3%|1.7%|
[et_tor](#et_tor)|6400|6400|7|0.1%|1.7%|
[dm_tor](#dm_tor)|6506|6506|7|0.1%|1.7%|
[bm_tor](#bm_tor)|6528|6528|7|0.1%|1.7%|
[tor_exits](#tor_exits)|1116|1116|6|0.5%|1.5%|
[blocklist_de_mail](#blocklist_de_mail)|17874|17874|6|0.0%|1.5%|
[blocklist_de_ftp](#blocklist_de_ftp)|1448|1448|4|0.2%|1.0%|
[php_spammers](#php_spammers)|735|735|3|0.4%|0.7%|
[php_dictionary](#php_dictionary)|737|737|3|0.4%|0.7%|
[iw_spamlist](#iw_spamlist)|3818|3818|3|0.0%|0.7%|
[firehol_level1](#firehol_level1)|5137|688854492|3|0.0%|0.7%|
[blocklist_de_strongips](#blocklist_de_strongips)|175|175|3|1.7%|0.7%|
[xroxy](#xroxy)|2168|2168|2|0.0%|0.5%|
[ri_web_proxies](#ri_web_proxies)|7800|7800|2|0.0%|0.5%|
[openbl_60d](#openbl_60d)|6984|6984|2|0.0%|0.5%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|2|0.0%|0.5%|
[blocklist_de_imap](#blocklist_de_imap)|2597|2597|2|0.0%|0.5%|
[blocklist_de_apache](#blocklist_de_apache)|14231|14231|2|0.0%|0.5%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|1|0.0%|0.2%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|1|0.0%|0.2%|
[ri_connect_proxies](#ri_connect_proxies)|2811|2811|1|0.0%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.2%|
[fullbogons](#fullbogons)|3775|670173256|1|0.0%|0.2%|
[et_block](#et_block)|1000|18344011|1|0.0%|0.2%|
[bogons](#bogons)|13|592708608|1|0.0%|0.2%|
[blocklist_de_ssh](#blocklist_de_ssh)|3225|3225|1|0.0%|0.2%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2863|2863|1|0.0%|0.2%|

## php_spammers

[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) spam servers (IPs used by spammers to send messages) (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=s&rss=1).

The last time downloaded was found to be dated: Thu Jun 11 17:00:23 UTC 2015.

The ipset `php_spammers` has **735** entries, **735** unique IPs.

The following table shows the overlaps of `php_spammers` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `php_spammers`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `php_spammers`.
- ` this % ` is the percentage **of this ipset (`php_spammers`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level3](#firehol_level3)|109650|9627417|735|0.0%|100.0%|
[php_dictionary](#php_dictionary)|737|737|322|43.6%|43.8%|
[sorbs_spam](#sorbs_spam)|64701|65536|184|0.2%|25.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|184|0.2%|25.0%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|184|0.2%|25.0%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|151|0.1%|20.5%|
[firehol_level2](#firehol_level2)|22462|34082|119|0.3%|16.1%|
[blocklist_de](#blocklist_de)|28768|28768|109|0.3%|14.8%|
[nixspam](#nixspam)|25392|25392|106|0.4%|14.4%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|95|0.3%|12.9%|
[snort_ipfilter](#snort_ipfilter)|9671|9671|85|0.8%|11.5%|
[firehol_anonymous](#firehol_anonymous)|18960|82998|81|0.0%|11.0%|
[firehol_proxies](#firehol_proxies)|12379|12646|79|0.6%|10.7%|
[blocklist_de_mail](#blocklist_de_mail)|17874|17874|78|0.4%|10.6%|
[ri_web_proxies](#ri_web_proxies)|7800|7800|54|0.6%|7.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|54|0.0%|7.3%|
[php_commenters](#php_commenters)|430|430|50|11.6%|6.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|44|0.0%|5.9%|
[stopforumspam_1d](#stopforumspam_1d)|6745|6745|41|0.6%|5.5%|
[xroxy](#xroxy)|2168|2168|34|1.5%|4.6%|
[sorbs_web](#sorbs_web)|544|545|25|4.5%|3.4%|
[blocklist_de_bots](#blocklist_de_bots)|2925|2925|24|0.8%|3.2%|
[proxz](#proxz)|1307|1307|22|1.6%|2.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|11|0.0%|1.4%|
[blocklist_de_strongips](#blocklist_de_strongips)|175|175|10|5.7%|1.3%|
[iw_spamlist](#iw_spamlist)|3818|3818|7|0.1%|0.9%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|6|1.1%|0.8%|
[tor_exits](#tor_exits)|1116|1116|5|0.4%|0.6%|
[et_tor](#et_tor)|6400|6400|5|0.0%|0.6%|
[dm_tor](#dm_tor)|6506|6506|5|0.0%|0.6%|
[bm_tor](#bm_tor)|6528|6528|5|0.0%|0.6%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2863|2863|5|0.1%|0.6%|
[blocklist_de_apache](#blocklist_de_apache)|14231|14231|5|0.0%|0.6%|
[alienvault_reputation](#alienvault_reputation)|192275|192275|5|0.0%|0.6%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|4|0.0%|0.5%|
[firehol_level1](#firehol_level1)|5137|688854492|4|0.0%|0.5%|
[et_block](#et_block)|1000|18344011|4|0.0%|0.5%|
[ri_connect_proxies](#ri_connect_proxies)|2811|2811|3|0.1%|0.4%|
[php_harvesters](#php_harvesters)|392|392|3|0.7%|0.4%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|0.4%|
[proxyrss](#proxyrss)|1373|1373|1|0.0%|0.1%|
[openbl_7d](#openbl_7d)|628|628|1|0.1%|0.1%|
[openbl_60d](#openbl_60d)|6984|6984|1|0.0%|0.1%|
[openbl_30d](#openbl_30d)|2809|2809|1|0.0%|0.1%|
[openbl_1d](#openbl_1d)|141|141|1|0.7%|0.1%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|1|0.1%|0.1%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|1|0.0%|0.1%|
[et_compromised](#et_compromised)|1721|1721|1|0.0%|0.1%|
[bruteforceblocker](#bruteforceblocker)|1700|1700|1|0.0%|0.1%|
[blocklist_de_ssh](#blocklist_de_ssh)|3225|3225|1|0.0%|0.1%|
[blocklist_de_ftp](#blocklist_de_ftp)|1448|1448|1|0.0%|0.1%|

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
[firehol_proxies](#firehol_proxies)|12379|12646|1373|10.8%|100.0%|
[firehol_anonymous](#firehol_anonymous)|18960|82998|1373|1.6%|100.0%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|683|0.7%|49.7%|
[firehol_level3](#firehol_level3)|109650|9627417|683|0.0%|49.7%|
[ri_web_proxies](#ri_web_proxies)|7800|7800|605|7.7%|44.0%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|497|1.7%|36.1%|
[firehol_level2](#firehol_level2)|22462|34082|366|1.0%|26.6%|
[xroxy](#xroxy)|2168|2168|333|15.3%|24.2%|
[stopforumspam_1d](#stopforumspam_1d)|6745|6745|311|4.6%|22.6%|
[proxz](#proxz)|1307|1307|290|22.1%|21.1%|
[blocklist_de_bots](#blocklist_de_bots)|2925|2925|203|6.9%|14.7%|
[blocklist_de](#blocklist_de)|28768|28768|203|0.7%|14.7%|
[ri_connect_proxies](#ri_connect_proxies)|2811|2811|198|7.0%|14.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|54|0.0%|3.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|48|0.0%|3.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|30|0.0%|2.1%|
[nixspam](#nixspam)|25392|25392|10|0.0%|0.7%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|10|1.5%|0.7%|
[sorbs_spam](#sorbs_spam)|64701|65536|7|0.0%|0.5%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|7|0.0%|0.5%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|7|0.0%|0.5%|
[blocklist_de_strongips](#blocklist_de_strongips)|175|175|7|4.0%|0.5%|
[snort_ipfilter](#snort_ipfilter)|9671|9671|2|0.0%|0.1%|
[php_dictionary](#php_dictionary)|737|737|2|0.2%|0.1%|
[php_spammers](#php_spammers)|735|735|1|0.1%|0.0%|
[php_commenters](#php_commenters)|430|430|1|0.2%|0.0%|
[iw_spamlist](#iw_spamlist)|3818|3818|1|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.0%|
[dragon_http](#dragon_http)|1029|270336|1|0.0%|0.0%|

## proxz

[proxz.com](http://www.proxz.com) open proxies (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.proxz.com/proxylists.xml).

The last time downloaded was found to be dated: Thu Jun 11 16:21:24 UTC 2015.

The ipset `proxz` has **1307** entries, **1307** unique IPs.

The following table shows the overlaps of `proxz` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `proxz`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `proxz`.
- ` this % ` is the percentage **of this ipset (`proxz`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_proxies](#firehol_proxies)|12379|12646|1307|10.3%|100.0%|
[firehol_anonymous](#firehol_anonymous)|18960|82998|1307|1.5%|100.0%|
[firehol_level3](#firehol_level3)|109650|9627417|778|0.0%|59.5%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|772|0.8%|59.0%|
[ri_web_proxies](#ri_web_proxies)|7800|7800|600|7.6%|45.9%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|500|1.7%|38.2%|
[xroxy](#xroxy)|2168|2168|455|20.9%|34.8%|
[proxyrss](#proxyrss)|1373|1373|290|21.1%|22.1%|
[firehol_level2](#firehol_level2)|22462|34082|276|0.8%|21.1%|
[ri_connect_proxies](#ri_connect_proxies)|2811|2811|228|8.1%|17.4%|
[stopforumspam_1d](#stopforumspam_1d)|6745|6745|192|2.8%|14.6%|
[blocklist_de](#blocklist_de)|28768|28768|186|0.6%|14.2%|
[blocklist_de_bots](#blocklist_de_bots)|2925|2925|156|5.3%|11.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|105|0.0%|8.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|52|0.0%|3.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|44|0.0%|3.3%|
[sorbs_spam](#sorbs_spam)|64701|65536|43|0.0%|3.2%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|43|0.0%|3.2%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|43|0.0%|3.2%|
[nixspam](#nixspam)|25392|25392|43|0.1%|3.2%|
[blocklist_de_mail](#blocklist_de_mail)|17874|17874|30|0.1%|2.2%|
[snort_ipfilter](#snort_ipfilter)|9671|9671|27|0.2%|2.0%|
[php_dictionary](#php_dictionary)|737|737|25|3.3%|1.9%|
[php_spammers](#php_spammers)|735|735|22|2.9%|1.6%|
[php_commenters](#php_commenters)|430|430|9|2.0%|0.6%|
[sorbs_web](#sorbs_web)|544|545|8|1.4%|0.6%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|6|0.9%|0.4%|
[blocklist_de_strongips](#blocklist_de_strongips)|175|175|6|3.4%|0.4%|
[dragon_http](#dragon_http)|1029|270336|4|0.0%|0.3%|
[alienvault_reputation](#alienvault_reputation)|192275|192275|3|0.0%|0.2%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|2|0.3%|0.1%|
[et_compromised](#et_compromised)|1721|1721|2|0.1%|0.1%|
[bruteforceblocker](#bruteforceblocker)|1700|1700|2|0.1%|0.1%|
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
[firehol_proxies](#firehol_proxies)|12379|12646|2811|22.2%|100.0%|
[firehol_anonymous](#firehol_anonymous)|18960|82998|2811|3.3%|100.0%|
[firehol_level3](#firehol_level3)|109650|9627417|1584|0.0%|56.3%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|1583|1.6%|56.3%|
[ri_web_proxies](#ri_web_proxies)|7800|7800|1197|15.3%|42.5%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|561|1.9%|19.9%|
[xroxy](#xroxy)|2168|2168|395|18.2%|14.0%|
[proxz](#proxz)|1307|1307|228|17.4%|8.1%|
[proxyrss](#proxyrss)|1373|1373|198|14.4%|7.0%|
[firehol_level2](#firehol_level2)|22462|34082|153|0.4%|5.4%|
[stopforumspam_1d](#stopforumspam_1d)|6745|6745|115|1.7%|4.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|106|0.0%|3.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|86|0.0%|3.0%|
[blocklist_de](#blocklist_de)|28768|28768|70|0.2%|2.4%|
[blocklist_de_bots](#blocklist_de_bots)|2925|2925|67|2.2%|2.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|57|0.0%|2.0%|
[nixspam](#nixspam)|25392|25392|19|0.0%|0.6%|
[sorbs_spam](#sorbs_spam)|64701|65536|18|0.0%|0.6%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|18|0.0%|0.6%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|18|0.0%|0.6%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|7|1.0%|0.2%|
[snort_ipfilter](#snort_ipfilter)|9671|9671|6|0.0%|0.2%|
[php_dictionary](#php_dictionary)|737|737|5|0.6%|0.1%|
[php_commenters](#php_commenters)|430|430|5|1.1%|0.1%|
[php_spammers](#php_spammers)|735|735|3|0.4%|0.1%|
[dragon_http](#dragon_http)|1029|270336|3|0.0%|0.1%|
[blocklist_de_mail](#blocklist_de_mail)|17874|17874|3|0.0%|0.1%|
[alienvault_reputation](#alienvault_reputation)|192275|192275|3|0.0%|0.1%|
[sorbs_web](#sorbs_web)|544|545|1|0.1%|0.0%|
[php_harvesters](#php_harvesters)|392|392|1|0.2%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|1|0.1%|0.0%|
[iw_spamlist](#iw_spamlist)|3818|3818|1|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.0%|
[dm_tor](#dm_tor)|6506|6506|1|0.0%|0.0%|
[bm_tor](#bm_tor)|6528|6528|1|0.0%|0.0%|

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
[firehol_proxies](#firehol_proxies)|12379|12646|7800|61.6%|100.0%|
[firehol_anonymous](#firehol_anonymous)|18960|82998|7800|9.3%|100.0%|
[firehol_level3](#firehol_level3)|109650|9627417|3728|0.0%|47.7%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|3682|3.9%|47.2%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|1518|5.2%|19.4%|
[ri_connect_proxies](#ri_connect_proxies)|2811|2811|1197|42.5%|15.3%|
[xroxy](#xroxy)|2168|2168|961|44.3%|12.3%|
[firehol_level2](#firehol_level2)|22462|34082|670|1.9%|8.5%|
[proxyrss](#proxyrss)|1373|1373|605|44.0%|7.7%|
[proxz](#proxz)|1307|1307|600|45.9%|7.6%|
[blocklist_de](#blocklist_de)|28768|28768|467|1.6%|5.9%|
[stopforumspam_1d](#stopforumspam_1d)|6745|6745|444|6.5%|5.6%|
[blocklist_de_bots](#blocklist_de_bots)|2925|2925|381|13.0%|4.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|223|0.0%|2.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|220|0.0%|2.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|156|0.0%|2.0%|
[sorbs_spam](#sorbs_spam)|64701|65536|144|0.2%|1.8%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|144|0.2%|1.8%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|144|0.2%|1.8%|
[nixspam](#nixspam)|25392|25392|130|0.5%|1.6%|
[blocklist_de_mail](#blocklist_de_mail)|17874|17874|85|0.4%|1.0%|
[php_dictionary](#php_dictionary)|737|737|67|9.0%|0.8%|
[snort_ipfilter](#snort_ipfilter)|9671|9671|64|0.6%|0.8%|
[php_spammers](#php_spammers)|735|735|54|7.3%|0.6%|
[php_commenters](#php_commenters)|430|430|25|5.8%|0.3%|
[sorbs_web](#sorbs_web)|544|545|18|3.3%|0.2%|
[dragon_http](#dragon_http)|1029|270336|18|0.0%|0.2%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|15|2.2%|0.1%|
[iw_spamlist](#iw_spamlist)|3818|3818|11|0.2%|0.1%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|10|1.9%|0.1%|
[blocklist_de_strongips](#blocklist_de_strongips)|175|175|8|4.5%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|6|0.0%|0.0%|
[dm_tor](#dm_tor)|6506|6506|5|0.0%|0.0%|
[bm_tor](#bm_tor)|6528|6528|5|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|4|0.0%|0.0%|
[et_tor](#et_tor)|6400|6400|4|0.0%|0.0%|
[alienvault_reputation](#alienvault_reputation)|192275|192275|4|0.0%|0.0%|
[php_harvesters](#php_harvesters)|392|392|2|0.5%|0.0%|
[sslbl](#sslbl)|371|371|1|0.2%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|1|0.0%|0.0%|
[firehol_level1](#firehol_level1)|5137|688854492|1|0.0%|0.0%|
[et_compromised](#et_compromised)|1721|1721|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1700|1700|1|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3225|3225|1|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2863|2863|1|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14231|14231|1|0.0%|0.0%|

## shunlist

[AutoShun.org](http://autoshun.org/) IPs identified as hostile by correlating logs from distributed snort installations running the autoshun plugin

Source is downloaded from [this link](http://www.autoshun.org/files/shunlist.csv).

The last time downloaded was found to be dated: Thu Jun 11 15:30:03 UTC 2015.

The ipset `shunlist` has **1278** entries, **1278** unique IPs.

The following table shows the overlaps of `shunlist` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `shunlist`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `shunlist`.
- ` this % ` is the percentage **of this ipset (`shunlist`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level3](#firehol_level3)|109650|9627417|1278|0.0%|100.0%|
[alienvault_reputation](#alienvault_reputation)|192275|192275|1269|0.6%|99.2%|
[openbl_60d](#openbl_60d)|6984|6984|543|7.7%|42.4%|
[openbl_30d](#openbl_30d)|2809|2809|511|18.1%|39.9%|
[et_compromised](#et_compromised)|1721|1721|430|24.9%|33.6%|
[firehol_level2](#firehol_level2)|22462|34082|402|1.1%|31.4%|
[blocklist_de](#blocklist_de)|28768|28768|398|1.3%|31.1%|
[bruteforceblocker](#bruteforceblocker)|1700|1700|395|23.2%|30.9%|
[blocklist_de_ssh](#blocklist_de_ssh)|3225|3225|357|11.0%|27.9%|
[openbl_7d](#openbl_7d)|628|628|210|33.4%|16.4%|
[firehol_level1](#firehol_level1)|5137|688854492|183|0.0%|14.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|123|0.0%|9.6%|
[dshield](#dshield)|20|5120|120|2.3%|9.3%|
[et_block](#et_block)|1000|18344011|115|0.0%|8.9%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|94|0.0%|7.3%|
[openbl_1d](#openbl_1d)|141|141|73|51.7%|5.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|73|0.0%|5.7%|
[sslbl](#sslbl)|371|371|61|16.4%|4.7%|
[dragon_http](#dragon_http)|1029|270336|37|0.0%|2.8%|
[blocklist_de_apache](#blocklist_de_apache)|14231|14231|36|0.2%|2.8%|
[ciarmy](#ciarmy)|473|473|28|5.9%|2.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|27|0.0%|2.1%|
[blocklist_de_strongips](#blocklist_de_strongips)|175|175|19|10.8%|1.4%|
[voipbl](#voipbl)|10586|10998|13|0.1%|1.0%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|4|0.0%|0.3%|
[blocklist_de_mail](#blocklist_de_mail)|17874|17874|4|0.0%|0.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|0.2%|
[blocklist_de_imap](#blocklist_de_imap)|2597|2597|3|0.1%|0.2%|
[stopforumspam_1d](#stopforumspam_1d)|6745|6745|2|0.0%|0.1%|
[sorbs_spam](#sorbs_spam)|64701|65536|2|0.0%|0.1%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|2|0.0%|0.1%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|2|0.0%|0.1%|
[blocklist_de_sip](#blocklist_de_sip)|84|84|2|2.3%|0.1%|
[tor_exits](#tor_exits)|1116|1116|1|0.0%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|1|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9671|9671|1|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|1|0.1%|0.0%|
[firehol_proxies](#firehol_proxies)|12379|12646|1|0.0%|0.0%|
[firehol_anonymous](#firehol_anonymous)|18960|82998|1|0.0%|0.0%|
[et_tor](#et_tor)|6400|6400|1|0.0%|0.0%|
[dm_tor](#dm_tor)|6506|6506|1|0.0%|0.0%|
[bm_tor](#bm_tor)|6528|6528|1|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2863|2863|1|0.0%|0.0%|

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
[firehol_level3](#firehol_level3)|109650|9627417|9671|0.1%|100.0%|
[firehol_anonymous](#firehol_anonymous)|18960|82998|1259|1.5%|13.0%|
[tor_exits](#tor_exits)|1116|1116|1099|98.4%|11.3%|
[et_tor](#et_tor)|6400|6400|1088|17.0%|11.2%|
[bm_tor](#bm_tor)|6528|6528|1071|16.4%|11.0%|
[dm_tor](#dm_tor)|6506|6506|1069|16.4%|11.0%|
[sorbs_spam](#sorbs_spam)|64701|65536|846|1.2%|8.7%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|846|1.2%|8.7%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|846|1.2%|8.7%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|812|0.8%|8.3%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|667|2.2%|6.8%|
[firehol_level2](#firehol_level2)|22462|34082|557|1.6%|5.7%|
[stopforumspam_1d](#stopforumspam_1d)|6745|6745|376|5.5%|3.8%|
[firehol_proxies](#firehol_proxies)|12379|12646|330|2.6%|3.4%|
[firehol_level1](#firehol_level1)|5137|688854492|299|0.0%|3.0%|
[et_block](#et_block)|1000|18344011|297|0.0%|3.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|241|0.0%|2.4%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|237|45.2%|2.4%|
[blocklist_de](#blocklist_de)|28768|28768|223|0.7%|2.3%|
[nixspam](#nixspam)|25392|25392|217|0.8%|2.2%|
[zeus](#zeus)|230|230|200|86.9%|2.0%|
[zeus_badips](#zeus_badips)|202|202|178|88.1%|1.8%|
[blocklist_de_mail](#blocklist_de_mail)|17874|17874|169|0.9%|1.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|138|0.0%|1.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|116|0.0%|1.1%|
[alienvault_reputation](#alienvault_reputation)|192275|192275|107|0.0%|1.1%|
[php_dictionary](#php_dictionary)|737|737|91|12.3%|0.9%|
[php_spammers](#php_spammers)|735|735|85|11.5%|0.8%|
[feodo](#feodo)|105|105|83|79.0%|0.8%|
[ri_web_proxies](#ri_web_proxies)|7800|7800|64|0.8%|0.6%|
[php_commenters](#php_commenters)|430|430|64|14.8%|0.6%|
[iw_spamlist](#iw_spamlist)|3818|3818|60|1.5%|0.6%|
[sorbs_web](#sorbs_web)|544|545|47|8.6%|0.4%|
[xroxy](#xroxy)|2168|2168|41|1.8%|0.4%|
[blocklist_de_apache](#blocklist_de_apache)|14231|14231|36|0.2%|0.3%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2863|2863|33|1.1%|0.3%|
[sslbl](#sslbl)|371|371|31|8.3%|0.3%|
[proxz](#proxz)|1307|1307|27|2.0%|0.2%|
[openbl_60d](#openbl_60d)|6984|6984|24|0.3%|0.2%|
[blocklist_de_bots](#blocklist_de_bots)|2925|2925|21|0.7%|0.2%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|18|0.0%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|14|0.0%|0.1%|
[php_harvesters](#php_harvesters)|392|392|11|2.8%|0.1%|
[palevo](#palevo)|13|13|11|84.6%|0.1%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|11|0.8%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|11|0.0%|0.1%|
[dragon_http](#dragon_http)|1029|270336|11|0.0%|0.1%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|6|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2811|2811|6|0.2%|0.0%|
[sorbs_socks](#sorbs_socks)|7|7|4|57.1%|0.0%|
[sorbs_misc](#sorbs_misc)|7|7|4|57.1%|0.0%|
[sorbs_http](#sorbs_http)|7|7|4|57.1%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|115|115|4|3.4%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2597|2597|3|0.1%|0.0%|
[proxyrss](#proxyrss)|1373|1373|2|0.1%|0.0%|
[openbl_30d](#openbl_30d)|2809|2809|2|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|2|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|175|175|2|1.1%|0.0%|
[shunlist](#shunlist)|1278|1278|1|0.0%|0.0%|
[openbl_7d](#openbl_7d)|628|628|1|0.1%|0.0%|
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
[snort_ipfilter](#snort_ipfilter)|9671|9671|4|0.0%|57.1%|
[nixspam](#nixspam)|25392|25392|4|0.0%|57.1%|
[firehol_level3](#firehol_level3)|109650|9627417|4|0.0%|57.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|2|0.0%|28.5%|
[php_dictionary](#php_dictionary)|737|737|1|0.1%|14.2%|
[iw_spamlist](#iw_spamlist)|3818|3818|1|0.0%|14.2%|
[firehol_level2](#firehol_level2)|22462|34082|1|0.0%|14.2%|
[blocklist_de_mail](#blocklist_de_mail)|17874|17874|1|0.0%|14.2%|
[blocklist_de](#blocklist_de)|28768|28768|1|0.0%|14.2%|

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
[nixspam](#nixspam)|25392|25392|4|0.0%|57.1%|
[firehol_level3](#firehol_level3)|109650|9627417|4|0.0%|57.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|2|0.0%|28.5%|
[php_dictionary](#php_dictionary)|737|737|1|0.1%|14.2%|
[iw_spamlist](#iw_spamlist)|3818|3818|1|0.0%|14.2%|
[firehol_level2](#firehol_level2)|22462|34082|1|0.0%|14.2%|
[blocklist_de_mail](#blocklist_de_mail)|17874|17874|1|0.0%|14.2%|
[blocklist_de](#blocklist_de)|28768|28768|1|0.0%|14.2%|

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
[nixspam](#nixspam)|25392|25392|4394|17.3%|6.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|2851|0.0%|4.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|1736|0.0%|2.6%|
[firehol_level2](#firehol_level2)|22462|34082|1365|4.0%|2.0%|
[blocklist_de](#blocklist_de)|28768|28768|1350|4.6%|2.0%|
[blocklist_de_mail](#blocklist_de_mail)|17874|17874|1257|7.0%|1.9%|
[firehol_level3](#firehol_level3)|109650|9627417|1250|0.0%|1.9%|
[iw_spamlist](#iw_spamlist)|3818|3818|1212|31.7%|1.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|1205|0.0%|1.8%|
[snort_ipfilter](#snort_ipfilter)|9671|9671|846|8.7%|1.2%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|320|0.3%|0.4%|
[sorbs_web](#sorbs_web)|544|545|280|51.3%|0.4%|
[php_dictionary](#php_dictionary)|737|737|214|29.0%|0.3%|
[firehol_anonymous](#firehol_anonymous)|18960|82998|201|0.2%|0.3%|
[firehol_proxies](#firehol_proxies)|12379|12646|196|1.5%|0.3%|
[php_spammers](#php_spammers)|735|735|184|25.0%|0.2%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|169|0.5%|0.2%|
[ri_web_proxies](#ri_web_proxies)|7800|7800|144|1.8%|0.2%|
[alienvault_reputation](#alienvault_reputation)|192275|192275|91|0.0%|0.1%|
[xroxy](#xroxy)|2168|2168|76|3.5%|0.1%|
[dragon_http](#dragon_http)|1029|270336|70|0.0%|0.1%|
[stopforumspam_1d](#stopforumspam_1d)|6745|6745|54|0.8%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2863|2863|46|1.6%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14231|14231|46|0.3%|0.0%|
[proxz](#proxz)|1307|1307|43|3.2%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|37|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|2925|2925|30|1.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2597|2597|29|1.1%|0.0%|
[firehol_level1](#firehol_level1)|5137|688854492|25|0.0%|0.0%|
[php_commenters](#php_commenters)|430|430|22|5.1%|0.0%|
[et_block](#et_block)|1000|18344011|22|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|20|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|20|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2811|2811|18|0.6%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|17|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|1448|1448|15|1.0%|0.0%|
[php_harvesters](#php_harvesters)|392|392|14|3.5%|0.0%|
[sorbs_socks](#sorbs_socks)|7|7|7|100.0%|0.0%|
[sorbs_misc](#sorbs_misc)|7|7|7|100.0%|0.0%|
[sorbs_http](#sorbs_http)|7|7|7|100.0%|0.0%|
[proxyrss](#proxyrss)|1373|1373|7|0.5%|0.0%|
[tor_exits](#tor_exits)|1116|1116|5|0.4%|0.0%|
[sorbs_smtp](#sorbs_smtp)|5|5|5|100.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3225|3225|5|0.1%|0.0%|
[et_tor](#et_tor)|6400|6400|4|0.0%|0.0%|
[dm_tor](#dm_tor)|6506|6506|4|0.0%|0.0%|
[bm_tor](#bm_tor)|6528|6528|4|0.0%|0.0%|
[voipbl](#voipbl)|10586|10998|3|0.0%|0.0%|
[et_compromised](#et_compromised)|1721|1721|3|0.1%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1700|1700|3|0.1%|0.0%|
[shunlist](#shunlist)|1278|1278|2|0.1%|0.0%|
[openbl_60d](#openbl_60d)|6984|6984|2|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|2|0.1%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|175|175|2|1.1%|0.0%|
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
[nixspam](#nixspam)|25392|25392|4394|17.3%|6.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|2851|0.0%|4.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|1736|0.0%|2.6%|
[firehol_level2](#firehol_level2)|22462|34082|1365|4.0%|2.0%|
[blocklist_de](#blocklist_de)|28768|28768|1350|4.6%|2.0%|
[blocklist_de_mail](#blocklist_de_mail)|17874|17874|1257|7.0%|1.9%|
[firehol_level3](#firehol_level3)|109650|9627417|1250|0.0%|1.9%|
[iw_spamlist](#iw_spamlist)|3818|3818|1212|31.7%|1.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|1205|0.0%|1.8%|
[snort_ipfilter](#snort_ipfilter)|9671|9671|846|8.7%|1.2%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|320|0.3%|0.4%|
[sorbs_web](#sorbs_web)|544|545|280|51.3%|0.4%|
[php_dictionary](#php_dictionary)|737|737|214|29.0%|0.3%|
[firehol_anonymous](#firehol_anonymous)|18960|82998|201|0.2%|0.3%|
[firehol_proxies](#firehol_proxies)|12379|12646|196|1.5%|0.3%|
[php_spammers](#php_spammers)|735|735|184|25.0%|0.2%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|169|0.5%|0.2%|
[ri_web_proxies](#ri_web_proxies)|7800|7800|144|1.8%|0.2%|
[alienvault_reputation](#alienvault_reputation)|192275|192275|91|0.0%|0.1%|
[xroxy](#xroxy)|2168|2168|76|3.5%|0.1%|
[dragon_http](#dragon_http)|1029|270336|70|0.0%|0.1%|
[stopforumspam_1d](#stopforumspam_1d)|6745|6745|54|0.8%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2863|2863|46|1.6%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14231|14231|46|0.3%|0.0%|
[proxz](#proxz)|1307|1307|43|3.2%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|37|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|2925|2925|30|1.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2597|2597|29|1.1%|0.0%|
[firehol_level1](#firehol_level1)|5137|688854492|25|0.0%|0.0%|
[php_commenters](#php_commenters)|430|430|22|5.1%|0.0%|
[et_block](#et_block)|1000|18344011|22|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|20|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|20|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2811|2811|18|0.6%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|17|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|1448|1448|15|1.0%|0.0%|
[php_harvesters](#php_harvesters)|392|392|14|3.5%|0.0%|
[sorbs_socks](#sorbs_socks)|7|7|7|100.0%|0.0%|
[sorbs_misc](#sorbs_misc)|7|7|7|100.0%|0.0%|
[sorbs_http](#sorbs_http)|7|7|7|100.0%|0.0%|
[proxyrss](#proxyrss)|1373|1373|7|0.5%|0.0%|
[tor_exits](#tor_exits)|1116|1116|5|0.4%|0.0%|
[sorbs_smtp](#sorbs_smtp)|5|5|5|100.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3225|3225|5|0.1%|0.0%|
[et_tor](#et_tor)|6400|6400|4|0.0%|0.0%|
[dm_tor](#dm_tor)|6506|6506|4|0.0%|0.0%|
[bm_tor](#bm_tor)|6528|6528|4|0.0%|0.0%|
[voipbl](#voipbl)|10586|10998|3|0.0%|0.0%|
[et_compromised](#et_compromised)|1721|1721|3|0.1%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1700|1700|3|0.1%|0.0%|
[shunlist](#shunlist)|1278|1278|2|0.1%|0.0%|
[openbl_60d](#openbl_60d)|6984|6984|2|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|2|0.1%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|175|175|2|1.1%|0.0%|
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
[nixspam](#nixspam)|25392|25392|1|0.0%|20.0%|

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
[nixspam](#nixspam)|25392|25392|4|0.0%|57.1%|
[firehol_level3](#firehol_level3)|109650|9627417|4|0.0%|57.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|2|0.0%|28.5%|
[php_dictionary](#php_dictionary)|737|737|1|0.1%|14.2%|
[iw_spamlist](#iw_spamlist)|3818|3818|1|0.0%|14.2%|
[firehol_level2](#firehol_level2)|22462|34082|1|0.0%|14.2%|
[blocklist_de_mail](#blocklist_de_mail)|17874|17874|1|0.0%|14.2%|
[blocklist_de](#blocklist_de)|28768|28768|1|0.0%|14.2%|

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
[nixspam](#nixspam)|25392|25392|4504|17.7%|6.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|2860|0.0%|4.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|1740|0.0%|2.6%|
[firehol_level2](#firehol_level2)|22462|34082|1373|4.0%|2.0%|
[blocklist_de](#blocklist_de)|28768|28768|1358|4.7%|2.0%|
[blocklist_de_mail](#blocklist_de_mail)|17874|17874|1265|7.0%|1.9%|
[firehol_level3](#firehol_level3)|109650|9627417|1252|0.0%|1.9%|
[iw_spamlist](#iw_spamlist)|3818|3818|1217|31.8%|1.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|1208|0.0%|1.8%|
[snort_ipfilter](#snort_ipfilter)|9671|9671|846|8.7%|1.2%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|320|0.3%|0.4%|
[sorbs_web](#sorbs_web)|544|545|281|51.5%|0.4%|
[php_dictionary](#php_dictionary)|737|737|214|29.0%|0.3%|
[firehol_anonymous](#firehol_anonymous)|18960|82998|201|0.2%|0.3%|
[firehol_proxies](#firehol_proxies)|12379|12646|196|1.5%|0.2%|
[php_spammers](#php_spammers)|735|735|184|25.0%|0.2%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|169|0.5%|0.2%|
[ri_web_proxies](#ri_web_proxies)|7800|7800|144|1.8%|0.2%|
[alienvault_reputation](#alienvault_reputation)|192275|192275|91|0.0%|0.1%|
[xroxy](#xroxy)|2168|2168|76|3.5%|0.1%|
[dragon_http](#dragon_http)|1029|270336|71|0.0%|0.1%|
[stopforumspam_1d](#stopforumspam_1d)|6745|6745|54|0.8%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2863|2863|46|1.6%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14231|14231|46|0.3%|0.0%|
[proxz](#proxz)|1307|1307|43|3.2%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|38|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|2925|2925|30|1.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2597|2597|29|1.1%|0.0%|
[firehol_level1](#firehol_level1)|5137|688854492|25|0.0%|0.0%|
[php_commenters](#php_commenters)|430|430|22|5.1%|0.0%|
[et_block](#et_block)|1000|18344011|22|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|20|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|20|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2811|2811|18|0.6%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|17|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|1448|1448|15|1.0%|0.0%|
[php_harvesters](#php_harvesters)|392|392|14|3.5%|0.0%|
[sorbs_socks](#sorbs_socks)|7|7|7|100.0%|0.0%|
[sorbs_misc](#sorbs_misc)|7|7|7|100.0%|0.0%|
[sorbs_http](#sorbs_http)|7|7|7|100.0%|0.0%|
[proxyrss](#proxyrss)|1373|1373|7|0.5%|0.0%|
[tor_exits](#tor_exits)|1116|1116|5|0.4%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3225|3225|5|0.1%|0.0%|
[sorbs_smtp](#sorbs_smtp)|5|5|4|80.0%|0.0%|
[et_tor](#et_tor)|6400|6400|4|0.0%|0.0%|
[dm_tor](#dm_tor)|6506|6506|4|0.0%|0.0%|
[bm_tor](#bm_tor)|6528|6528|4|0.0%|0.0%|
[voipbl](#voipbl)|10586|10998|3|0.0%|0.0%|
[et_compromised](#et_compromised)|1721|1721|3|0.1%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1700|1700|3|0.1%|0.0%|
[shunlist](#shunlist)|1278|1278|2|0.1%|0.0%|
[openbl_60d](#openbl_60d)|6984|6984|2|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|2|0.1%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|175|175|2|1.1%|0.0%|
[virbl](#virbl)|19|19|1|5.2%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|1|0.1%|0.0%|
[malc0de](#malc0de)|276|276|1|0.3%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|1|0.1%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.0%|

## sorbs_web

[Sorbs.net](https://www.sorbs.net/) WEB exploits, extracted from deltas.

Source is downloaded from [this link]().

The last time downloaded was found to be dated: Thu Jun 11 17:04:05 UTC 2015.

The ipset `sorbs_web` has **544** entries, **545** unique IPs.

The following table shows the overlaps of `sorbs_web` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `sorbs_web`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `sorbs_web`.
- ` this % ` is the percentage **of this ipset (`sorbs_web`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[sorbs_spam](#sorbs_spam)|64701|65536|281|0.4%|51.5%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|280|0.4%|51.3%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|280|0.4%|51.3%|
[nixspam](#nixspam)|25392|25392|112|0.4%|20.5%|
[firehol_level3](#firehol_level3)|109650|9627417|63|0.0%|11.5%|
[firehol_level2](#firehol_level2)|22462|34082|61|0.1%|11.1%|
[blocklist_de](#blocklist_de)|28768|28768|61|0.2%|11.1%|
[blocklist_de_mail](#blocklist_de_mail)|17874|17874|56|0.3%|10.2%|
[snort_ipfilter](#snort_ipfilter)|9671|9671|47|0.4%|8.6%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|40|0.0%|7.3%|
[php_dictionary](#php_dictionary)|737|737|30|4.0%|5.5%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|29|0.0%|5.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|26|0.0%|4.7%|
[firehol_proxies](#firehol_proxies)|12379|12646|26|0.2%|4.7%|
[firehol_anonymous](#firehol_anonymous)|18960|82998|26|0.0%|4.7%|
[php_spammers](#php_spammers)|735|735|25|3.4%|4.5%|
[iw_spamlist](#iw_spamlist)|3818|3818|23|0.6%|4.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|21|0.0%|3.8%|
[ri_web_proxies](#ri_web_proxies)|7800|7800|18|0.2%|3.3%|
[xroxy](#xroxy)|2168|2168|14|0.6%|2.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|13|0.0%|2.3%|
[proxz](#proxz)|1307|1307|8|0.6%|1.4%|
[stopforumspam_1d](#stopforumspam_1d)|6745|6745|7|0.1%|1.2%|
[blocklist_de_bots](#blocklist_de_bots)|2925|2925|5|0.1%|0.9%|
[php_commenters](#php_commenters)|430|430|2|0.4%|0.3%|
[blocklist_de_strongips](#blocklist_de_strongips)|175|175|2|1.1%|0.3%|
[ri_connect_proxies](#ri_connect_proxies)|2811|2811|1|0.0%|0.1%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|1|0.0%|0.1%|
[dragon_http](#dragon_http)|1029|270336|1|0.0%|0.1%|
[blocklist_de_ftp](#blocklist_de_ftp)|1448|1448|1|0.0%|0.1%|
[alienvault_reputation](#alienvault_reputation)|192275|192275|1|0.0%|0.1%|

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
[firehol_level1](#firehol_level1)|5137|688854492|18340608|2.6%|100.0%|
[et_block](#et_block)|1000|18344011|18338560|99.9%|99.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|8532506|2.4%|46.5%|
[firehol_level3](#firehol_level3)|109650|9627417|6933039|72.0%|37.8%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|6932480|75.5%|37.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|2272265|0.2%|12.3%|
[fullbogons](#fullbogons)|3775|670173256|151552|0.0%|0.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|130368|0.0%|0.7%|
[alienvault_reputation](#alienvault_reputation)|192275|192275|1628|0.8%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1037|0.3%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|1014|1.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|512|0.1%|0.0%|
[dshield](#dshield)|20|5120|512|10.0%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|271|0.9%|0.0%|
[firehol_level2](#firehol_level2)|22462|34082|265|0.7%|0.0%|
[dragon_http](#dragon_http)|1029|270336|256|0.0%|0.0%|
[openbl_60d](#openbl_60d)|6984|6984|235|3.3%|0.0%|
[blocklist_de](#blocklist_de)|28768|28768|200|0.6%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3225|3225|120|3.7%|0.0%|
[openbl_30d](#openbl_30d)|2809|2809|119|4.2%|0.0%|
[et_compromised](#et_compromised)|1721|1721|101|5.8%|0.0%|
[shunlist](#shunlist)|1278|1278|94|7.3%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6745|6745|80|1.1%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1700|1700|61|3.5%|0.0%|
[nixspam](#nixspam)|25392|25392|55|0.2%|0.0%|
[openbl_7d](#openbl_7d)|628|628|52|8.2%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|2925|2925|52|1.7%|0.0%|
[php_commenters](#php_commenters)|430|430|29|6.7%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|29|2.2%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|17874|17874|21|0.1%|0.0%|
[sorbs_spam](#sorbs_spam)|64701|65536|20|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|20|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|20|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9671|9671|18|0.1%|0.0%|
[openbl_1d](#openbl_1d)|141|141|18|12.7%|0.0%|
[zeus_badips](#zeus_badips)|202|202|15|7.4%|0.0%|
[zeus](#zeus)|230|230|15|6.5%|0.0%|
[voipbl](#voipbl)|10586|10998|14|0.1%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2597|2597|10|0.3%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|175|175|7|4.0%|0.0%|
[php_dictionary](#php_dictionary)|737|737|6|0.8%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|6|0.4%|0.0%|
[firehol_anonymous](#firehol_anonymous)|18960|82998|6|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|5|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2863|2863|5|0.1%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14231|14231|5|0.0%|0.0%|
[php_spammers](#php_spammers)|735|735|4|0.5%|0.0%|
[nt_malware_http](#nt_malware_http)|69|69|4|5.7%|0.0%|
[malc0de](#malc0de)|276|276|4|1.4%|0.0%|
[iw_spamlist](#iw_spamlist)|3818|3818|4|0.1%|0.0%|
[nt_malware_irc](#nt_malware_irc)|43|43|3|6.9%|0.0%|
[firehol_proxies](#firehol_proxies)|12379|12646|3|0.0%|0.0%|
[et_tor](#et_tor)|6400|6400|3|0.0%|0.0%|
[dm_tor](#dm_tor)|6506|6506|3|0.0%|0.0%|
[bm_tor](#bm_tor)|6528|6528|3|0.0%|0.0%|
[tor_exits](#tor_exits)|1116|1116|2|0.1%|0.0%|
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
[firehol_level1](#firehol_level1)|5137|688854492|487424|0.0%|100.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|270785|0.1%|55.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|98904|0.0%|20.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|33155|0.0%|6.8%|
[et_block](#et_block)|1000|18344011|517|0.0%|0.1%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|512|0.0%|0.1%|
[firehol_level3](#firehol_level3)|109650|9627417|85|0.0%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|75|0.0%|0.0%|
[sorbs_spam](#sorbs_spam)|64701|65536|20|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|20|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|20|0.0%|0.0%|
[alienvault_reputation](#alienvault_reputation)|192275|192275|14|0.0%|0.0%|
[firehol_level2](#firehol_level2)|22462|34082|9|0.0%|0.0%|
[php_commenters](#php_commenters)|430|430|8|1.8%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|7|0.0%|0.0%|
[blocklist_de](#blocklist_de)|28768|28768|7|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9671|9671|6|0.0%|0.0%|
[zeus_badips](#zeus_badips)|202|202|5|2.4%|0.0%|
[zeus](#zeus)|230|230|5|2.1%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|2925|2925|5|0.1%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6745|6745|3|0.0%|0.0%|
[nixspam](#nixspam)|25392|25392|3|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|175|175|3|1.7%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|17874|17874|2|0.0%|0.0%|
[php_harvesters](#php_harvesters)|392|392|1|0.2%|0.0%|
[openbl_60d](#openbl_60d)|6984|6984|1|0.0%|0.0%|
[openbl_30d](#openbl_30d)|2809|2809|1|0.0%|0.0%|
[malc0de](#malc0de)|276|276|1|0.3%|0.0%|
[iw_spamlist](#iw_spamlist)|3818|3818|1|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.0%|

## sslbl

[Abuse.ch SSL Blacklist](https://sslbl.abuse.ch/) bad SSL traffic related to malware or botnet activities - **excellent list**

Source is downloaded from [this link](https://sslbl.abuse.ch/blacklist/sslipblacklist.csv).

The last time downloaded was found to be dated: Thu Jun 11 17:15:05 UTC 2015.

The ipset `sslbl` has **371** entries, **371** unique IPs.

The following table shows the overlaps of `sslbl` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `sslbl`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `sslbl`.
- ` this % ` is the percentage **of this ipset (`sslbl`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level1](#firehol_level1)|5137|688854492|371|0.0%|100.0%|
[firehol_level3](#firehol_level3)|109650|9627417|92|0.0%|24.7%|
[alienvault_reputation](#alienvault_reputation)|192275|192275|65|0.0%|17.5%|
[shunlist](#shunlist)|1278|1278|61|4.7%|16.4%|
[feodo](#feodo)|105|105|38|36.1%|10.2%|
[et_block](#et_block)|1000|18344011|38|0.0%|10.2%|
[snort_ipfilter](#snort_ipfilter)|9671|9671|31|0.3%|8.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|28|0.0%|7.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|6|0.0%|1.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|3|0.0%|0.8%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|1|0.0%|0.2%|
[ri_web_proxies](#ri_web_proxies)|7800|7800|1|0.0%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.2%|
[firehol_proxies](#firehol_proxies)|12379|12646|1|0.0%|0.2%|
[firehol_anonymous](#firehol_anonymous)|18960|82998|1|0.0%|0.2%|
[dragon_http](#dragon_http)|1029|270336|1|0.0%|0.2%|

## stopforumspam_1d

[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers in the last 24 hours - **excellent list**

Source is downloaded from [this link](http://www.stopforumspam.com/downloads/listed_ip_1.zip).

The last time downloaded was found to be dated: Thu Jun 11 17:00:02 UTC 2015.

The ipset `stopforumspam_1d` has **6745** entries, **6745** unique IPs.

The following table shows the overlaps of `stopforumspam_1d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `stopforumspam_1d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `stopforumspam_1d`.
- ` this % ` is the percentage **of this ipset (`stopforumspam_1d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|22462|34082|6745|19.7%|100.0%|
[firehol_level3](#firehol_level3)|109650|9627417|6143|0.0%|91.0%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|6129|6.4%|90.8%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|4577|15.6%|67.8%|
[blocklist_de](#blocklist_de)|28768|28768|1448|5.0%|21.4%|
[blocklist_de_bots](#blocklist_de_bots)|2925|2925|1381|47.2%|20.4%|
[firehol_anonymous](#firehol_anonymous)|18960|82998|981|1.1%|14.5%|
[firehol_proxies](#firehol_proxies)|12379|12646|832|6.5%|12.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|528|0.0%|7.8%|
[ri_web_proxies](#ri_web_proxies)|7800|7800|444|5.6%|6.5%|
[snort_ipfilter](#snort_ipfilter)|9671|9671|376|3.8%|5.5%|
[tor_exits](#tor_exits)|1116|1116|341|30.5%|5.0%|
[et_tor](#et_tor)|6400|6400|328|5.1%|4.8%|
[dm_tor](#dm_tor)|6506|6506|328|5.0%|4.8%|
[bm_tor](#bm_tor)|6528|6528|327|5.0%|4.8%|
[proxyrss](#proxyrss)|1373|1373|311|22.6%|4.6%|
[xroxy](#xroxy)|2168|2168|220|10.1%|3.2%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|213|40.6%|3.1%|
[proxz](#proxz)|1307|1307|192|14.6%|2.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|178|0.0%|2.6%|
[php_commenters](#php_commenters)|430|430|168|39.0%|2.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|139|0.0%|2.0%|
[ri_connect_proxies](#ri_connect_proxies)|2811|2811|115|4.0%|1.7%|
[blocklist_de_strongips](#blocklist_de_strongips)|175|175|105|60.0%|1.5%|
[firehol_level1](#firehol_level1)|5137|688854492|83|0.0%|1.2%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|80|0.0%|1.1%|
[et_block](#et_block)|1000|18344011|80|0.0%|1.1%|
[blocklist_de_apache](#blocklist_de_apache)|14231|14231|67|0.4%|0.9%|
[nixspam](#nixspam)|25392|25392|57|0.2%|0.8%|
[sorbs_spam](#sorbs_spam)|64701|65536|54|0.0%|0.8%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|54|0.0%|0.8%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|54|0.0%|0.8%|
[alienvault_reputation](#alienvault_reputation)|192275|192275|48|0.0%|0.7%|
[blocklist_de_mail](#blocklist_de_mail)|17874|17874|45|0.2%|0.6%|
[php_harvesters](#php_harvesters)|392|392|44|11.2%|0.6%|
[php_spammers](#php_spammers)|735|735|41|5.5%|0.6%|
[php_dictionary](#php_dictionary)|737|737|35|4.7%|0.5%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2863|2863|35|1.2%|0.5%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|33|0.0%|0.4%|
[openbl_60d](#openbl_60d)|6984|6984|19|0.2%|0.2%|
[dragon_http](#dragon_http)|1029|270336|11|0.0%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|9|0.0%|0.1%|
[sorbs_web](#sorbs_web)|544|545|7|1.2%|0.1%|
[iw_spamlist](#iw_spamlist)|3818|3818|6|0.1%|0.0%|
[voipbl](#voipbl)|10586|10998|5|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|5|0.7%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|3|0.0%|0.0%|
[shunlist](#shunlist)|1278|1278|2|0.1%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|2|0.1%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2597|2597|2|0.0%|0.0%|
[zeus_badips](#zeus_badips)|202|202|1|0.4%|0.0%|
[zeus](#zeus)|230|230|1|0.4%|0.0%|
[openbl_30d](#openbl_30d)|2809|2809|1|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|1|0.0%|0.0%|
[fullbogons](#fullbogons)|3775|670173256|1|0.0%|0.0%|
[et_compromised](#et_compromised)|1721|1721|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1700|1700|1|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|1448|1448|1|0.0%|0.0%|

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
[firehol_level3](#firehol_level3)|109650|9627417|94309|0.9%|100.0%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|29184|99.9%|30.9%|
[firehol_level2](#firehol_level2)|22462|34082|7499|22.0%|7.9%|
[firehol_anonymous](#firehol_anonymous)|18960|82998|6196|7.4%|6.5%|
[stopforumspam_1d](#stopforumspam_1d)|6745|6745|6129|90.8%|6.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|5830|0.0%|6.1%|
[firehol_proxies](#firehol_proxies)|12379|12646|5588|44.1%|5.9%|
[ri_web_proxies](#ri_web_proxies)|7800|7800|3682|47.2%|3.9%|
[blocklist_de](#blocklist_de)|28768|28768|2773|9.6%|2.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|2476|0.0%|2.6%|
[blocklist_de_bots](#blocklist_de_bots)|2925|2925|2407|82.2%|2.5%|
[ri_connect_proxies](#ri_connect_proxies)|2811|2811|1583|56.3%|1.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|1522|0.0%|1.6%|
[xroxy](#xroxy)|2168|2168|1285|59.2%|1.3%|
[firehol_level1](#firehol_level1)|5137|688854492|1090|0.0%|1.1%|
[et_block](#et_block)|1000|18344011|1018|0.0%|1.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|1014|0.0%|1.0%|
[snort_ipfilter](#snort_ipfilter)|9671|9671|812|8.3%|0.8%|
[proxz](#proxz)|1307|1307|772|59.0%|0.8%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|725|0.0%|0.7%|
[proxyrss](#proxyrss)|1373|1373|683|49.7%|0.7%|
[et_tor](#et_tor)|6400|6400|653|10.2%|0.6%|
[dm_tor](#dm_tor)|6506|6506|639|9.8%|0.6%|
[bm_tor](#bm_tor)|6528|6528|637|9.7%|0.6%|
[tor_exits](#tor_exits)|1116|1116|633|56.7%|0.6%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|345|65.8%|0.3%|
[php_commenters](#php_commenters)|430|430|321|74.6%|0.3%|
[sorbs_spam](#sorbs_spam)|64701|65536|320|0.4%|0.3%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|320|0.4%|0.3%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|320|0.4%|0.3%|
[blocklist_de_mail](#blocklist_de_mail)|17874|17874|260|1.4%|0.2%|
[nixspam](#nixspam)|25392|25392|247|0.9%|0.2%|
[blocklist_de_apache](#blocklist_de_apache)|14231|14231|205|1.4%|0.2%|
[alienvault_reputation](#alienvault_reputation)|192275|192275|168|0.0%|0.1%|
[php_spammers](#php_spammers)|735|735|151|20.5%|0.1%|
[php_dictionary](#php_dictionary)|737|737|139|18.8%|0.1%|
[blocklist_de_strongips](#blocklist_de_strongips)|175|175|135|77.1%|0.1%|
[dragon_http](#dragon_http)|1029|270336|111|0.0%|0.1%|
[php_harvesters](#php_harvesters)|392|392|86|21.9%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|75|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2863|2863|73|2.5%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|52|0.0%|0.0%|
[openbl_60d](#openbl_60d)|6984|6984|47|0.6%|0.0%|
[sorbs_web](#sorbs_web)|544|545|40|7.3%|0.0%|
[voipbl](#voipbl)|10586|10998|35|0.3%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3225|3225|25|0.7%|0.0%|
[iw_spamlist](#iw_spamlist)|3818|3818|23|0.6%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|20|3.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|17|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2597|2597|16|0.6%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|1448|1448|13|0.8%|0.0%|
[et_compromised](#et_compromised)|1721|1721|10|0.5%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1700|1700|10|0.5%|0.0%|
[openbl_30d](#openbl_30d)|2809|2809|5|0.1%|0.0%|
[shunlist](#shunlist)|1278|1278|4|0.3%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|3|0.2%|0.0%|
[zeus_badips](#zeus_badips)|202|202|2|0.9%|0.0%|
[zeus](#zeus)|230|230|2|0.8%|0.0%|
[openbl_7d](#openbl_7d)|628|628|2|0.3%|0.0%|
[nt_malware_http](#nt_malware_http)|69|69|2|2.8%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|2|0.1%|0.0%|
[fullbogons](#fullbogons)|3775|670173256|2|0.0%|0.0%|
[openbl_1d](#openbl_1d)|141|141|1|0.7%|0.0%|
[iw_wormlist](#iw_wormlist)|34|34|1|2.9%|0.0%|
[ciarmy](#ciarmy)|473|473|1|0.2%|0.0%|

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
[firehol_level3](#firehol_level3)|109650|9627417|29184|0.3%|99.9%|
[firehol_level2](#firehol_level2)|22462|34082|5577|16.3%|19.1%|
[stopforumspam_1d](#stopforumspam_1d)|6745|6745|4577|67.8%|15.6%|
[firehol_anonymous](#firehol_anonymous)|18960|82998|2750|3.3%|9.4%|
[firehol_proxies](#firehol_proxies)|12379|12646|2379|18.8%|8.1%|
[blocklist_de](#blocklist_de)|28768|28768|2248|7.8%|7.7%|
[blocklist_de_bots](#blocklist_de_bots)|2925|2925|2054|70.2%|7.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|1953|0.0%|6.6%|
[ri_web_proxies](#ri_web_proxies)|7800|7800|1518|19.4%|5.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|768|0.0%|2.6%|
[snort_ipfilter](#snort_ipfilter)|9671|9671|667|6.8%|2.2%|
[xroxy](#xroxy)|2168|2168|612|28.2%|2.0%|
[ri_connect_proxies](#ri_connect_proxies)|2811|2811|561|19.9%|1.9%|
[et_tor](#et_tor)|6400|6400|547|8.5%|1.8%|
[tor_exits](#tor_exits)|1116|1116|545|48.8%|1.8%|
[dm_tor](#dm_tor)|6506|6506|530|8.1%|1.8%|
[bm_tor](#bm_tor)|6528|6528|528|8.0%|1.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|506|0.0%|1.7%|
[proxz](#proxz)|1307|1307|500|38.2%|1.7%|
[proxyrss](#proxyrss)|1373|1373|497|36.1%|1.7%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|286|54.5%|0.9%|
[firehol_level1](#firehol_level1)|5137|688854492|278|0.0%|0.9%|
[et_block](#et_block)|1000|18344011|272|0.0%|0.9%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|271|0.0%|0.9%|
[php_commenters](#php_commenters)|430|430|240|55.8%|0.8%|
[sorbs_spam](#sorbs_spam)|64701|65536|169|0.2%|0.5%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|169|0.2%|0.5%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|169|0.2%|0.5%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|147|0.0%|0.5%|
[blocklist_de_mail](#blocklist_de_mail)|17874|17874|146|0.8%|0.5%|
[nixspam](#nixspam)|25392|25392|136|0.5%|0.4%|
[blocklist_de_strongips](#blocklist_de_strongips)|175|175|120|68.5%|0.4%|
[blocklist_de_apache](#blocklist_de_apache)|14231|14231|120|0.8%|0.4%|
[php_spammers](#php_spammers)|735|735|95|12.9%|0.3%|
[php_dictionary](#php_dictionary)|737|737|94|12.7%|0.3%|
[alienvault_reputation](#alienvault_reputation)|192275|192275|89|0.0%|0.3%|
[php_harvesters](#php_harvesters)|392|392|61|15.5%|0.2%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2863|2863|52|1.8%|0.1%|
[dragon_http](#dragon_http)|1029|270336|36|0.0%|0.1%|
[sorbs_web](#sorbs_web)|544|545|29|5.3%|0.0%|
[openbl_60d](#openbl_60d)|6984|6984|27|0.3%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|20|0.0%|0.0%|
[voipbl](#voipbl)|10586|10998|14|0.1%|0.0%|
[iw_spamlist](#iw_spamlist)|3818|3818|14|0.3%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|11|1.6%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|7|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|7|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3225|3225|6|0.1%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2597|2597|6|0.2%|0.0%|
[et_compromised](#et_compromised)|1721|1721|5|0.2%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1700|1700|4|0.2%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|1448|1448|4|0.2%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|2|0.1%|0.0%|
[zeus_badips](#zeus_badips)|202|202|1|0.4%|0.0%|
[zeus](#zeus)|230|230|1|0.4%|0.0%|
[shunlist](#shunlist)|1278|1278|1|0.0%|0.0%|
[openbl_30d](#openbl_30d)|2809|2809|1|0.0%|0.0%|
[iw_wormlist](#iw_wormlist)|34|34|1|2.9%|0.0%|
[fullbogons](#fullbogons)|3775|670173256|1|0.0%|0.0%|

## tor_exits

[TorProject.org](https://www.torproject.org) list of all current TOR exit points (TorDNSEL)

Source is downloaded from [this link](https://check.torproject.org/exit-addresses).

The last time downloaded was found to be dated: Thu Jun 11 17:03:38 UTC 2015.

The ipset `tor_exits` has **1116** entries, **1116** unique IPs.

The following table shows the overlaps of `tor_exits` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `tor_exits`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `tor_exits`.
- ` this % ` is the percentage **of this ipset (`tor_exits`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_anonymous](#firehol_anonymous)|18960|82998|1116|1.3%|100.0%|
[firehol_level3](#firehol_level3)|109650|9627417|1100|0.0%|98.5%|
[snort_ipfilter](#snort_ipfilter)|9671|9671|1099|11.3%|98.4%|
[dm_tor](#dm_tor)|6506|6506|1018|15.6%|91.2%|
[bm_tor](#bm_tor)|6528|6528|1017|15.5%|91.1%|
[et_tor](#et_tor)|6400|6400|965|15.0%|86.4%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|633|0.6%|56.7%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|545|1.8%|48.8%|
[firehol_level2](#firehol_level2)|22462|34082|353|1.0%|31.6%|
[stopforumspam_1d](#stopforumspam_1d)|6745|6745|341|5.0%|30.5%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|231|44.0%|20.6%|
[firehol_proxies](#firehol_proxies)|12379|12646|231|1.8%|20.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|128|0.0%|11.4%|
[php_commenters](#php_commenters)|430|430|51|11.8%|4.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|40|0.0%|3.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|37|0.0%|3.3%|
[alienvault_reputation](#alienvault_reputation)|192275|192275|30|0.0%|2.6%|
[blocklist_de](#blocklist_de)|28768|28768|24|0.0%|2.1%|
[blocklist_de_apache](#blocklist_de_apache)|14231|14231|23|0.1%|2.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2863|2863|21|0.7%|1.8%|
[openbl_60d](#openbl_60d)|6984|6984|20|0.2%|1.7%|
[nixspam](#nixspam)|25392|25392|9|0.0%|0.8%|
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
[firehol_level1](#firehol_level1)|5137|688854492|2|0.0%|0.1%|
[et_block](#et_block)|1000|18344011|2|0.0%|0.1%|
[blocklist_de_mail](#blocklist_de_mail)|17874|17874|2|0.0%|0.1%|
[shunlist](#shunlist)|1278|1278|1|0.0%|0.0%|
[iw_spamlist](#iw_spamlist)|3818|3818|1|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|2925|2925|1|0.0%|0.0%|

## virbl

[VirBL](http://virbl.bit.nl/) is a project of which the idea was born during the RIPE-48 meeting. The plan was to get reports of virusscanning mailservers, and put the IP-addresses that were reported to send viruses on a blacklist.

Source is downloaded from [this link](http://virbl.bit.nl/download/virbl.dnsbl.bit.nl.txt).

The last time downloaded was found to be dated: Thu Jun 11 17:42:03 UTC 2015.

The ipset `virbl` has **19** entries, **19** unique IPs.

The following table shows the overlaps of `virbl` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `virbl`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `virbl`.
- ` this % ` is the percentage **of this ipset (`virbl`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level3](#firehol_level3)|109650|9627417|19|0.0%|100.0%|
[sorbs_spam](#sorbs_spam)|64701|65536|1|0.0%|5.2%|

## voipbl

[VoIPBL.org](http://www.voipbl.org/) a distributed VoIP blacklist that is aimed to protects against VoIP Fraud and minimizing abuse for network that have publicly accessible PBX's. Several algorithms, external sources and manual confirmation are used before they categorize something as an attack and determine the threat level.

Source is downloaded from [this link](http://www.voipbl.org/update/).

The last time downloaded was found to be dated: Thu Jun 11 15:18:34 UTC 2015.

The ipset `voipbl` has **10586** entries, **10998** unique IPs.

The following table shows the overlaps of `voipbl` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `voipbl`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `voipbl`.
- ` this % ` is the percentage **of this ipset (`voipbl`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|1613|0.0%|14.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|436|0.0%|3.9%|
[firehol_level1](#firehol_level1)|5137|688854492|334|0.0%|3.0%|
[fullbogons](#fullbogons)|3775|670173256|319|0.0%|2.9%|
[bogons](#bogons)|13|592708608|319|0.0%|2.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|302|0.0%|2.7%|
[alienvault_reputation](#alienvault_reputation)|192275|192275|186|0.0%|1.6%|
[firehol_anonymous](#firehol_anonymous)|18960|82998|79|0.0%|0.7%|
[firehol_level3](#firehol_level3)|109650|9627417|57|0.0%|0.5%|
[firehol_level2](#firehol_level2)|22462|34082|47|0.1%|0.4%|
[blocklist_de](#blocklist_de)|28768|28768|42|0.1%|0.3%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|35|0.0%|0.3%|
[blocklist_de_sip](#blocklist_de_sip)|84|84|34|40.4%|0.3%|
[dragon_http](#dragon_http)|1029|270336|27|0.0%|0.2%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|14|0.0%|0.1%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|14|0.0%|0.1%|
[et_block](#et_block)|1000|18344011|14|0.0%|0.1%|
[shunlist](#shunlist)|1278|1278|13|1.0%|0.1%|
[openbl_60d](#openbl_60d)|6984|6984|8|0.1%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6745|6745|5|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|4|0.0%|0.0%|
[sorbs_spam](#sorbs_spam)|64701|65536|3|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|3|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|3|0.0%|0.0%|
[openbl_30d](#openbl_30d)|2809|2809|3|0.1%|0.0%|
[et_tor](#et_tor)|6400|6400|3|0.0%|0.0%|
[et_compromised](#et_compromised)|1721|1721|3|0.1%|0.0%|
[dm_tor](#dm_tor)|6506|6506|3|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1700|1700|3|0.1%|0.0%|
[bm_tor](#bm_tor)|6528|6528|3|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14231|14231|3|0.0%|0.0%|
[nixspam](#nixspam)|25392|25392|2|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|2|0.3%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|2|0.0%|0.0%|
[firehol_proxies](#firehol_proxies)|12379|12646|2|0.0%|0.0%|
[ciarmy](#ciarmy)|473|473|2|0.4%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3225|3225|2|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|17874|17874|2|0.0%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.0%|
[dshield](#dshield)|20|5120|1|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2597|2597|1|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2863|2863|1|0.0%|0.0%|

## xroxy

[xroxy.com](http://www.xroxy.com) open proxies (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.xroxy.com/proxyrss.xml).

The last time downloaded was found to be dated: Thu Jun 11 17:33:01 UTC 2015.

The ipset `xroxy` has **2168** entries, **2168** unique IPs.

The following table shows the overlaps of `xroxy` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `xroxy`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `xroxy`.
- ` this % ` is the percentage **of this ipset (`xroxy`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_proxies](#firehol_proxies)|12379|12646|2168|17.1%|100.0%|
[firehol_anonymous](#firehol_anonymous)|18960|82998|2168|2.6%|100.0%|
[firehol_level3](#firehol_level3)|109650|9627417|1301|0.0%|60.0%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|1285|1.3%|59.2%|
[ri_web_proxies](#ri_web_proxies)|7800|7800|961|12.3%|44.3%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|612|2.0%|28.2%|
[proxz](#proxz)|1307|1307|455|34.8%|20.9%|
[ri_connect_proxies](#ri_connect_proxies)|2811|2811|395|14.0%|18.2%|
[proxyrss](#proxyrss)|1373|1373|333|24.2%|15.3%|
[firehol_level2](#firehol_level2)|22462|34082|324|0.9%|14.9%|
[blocklist_de](#blocklist_de)|28768|28768|229|0.7%|10.5%|
[stopforumspam_1d](#stopforumspam_1d)|6745|6745|220|3.2%|10.1%|
[blocklist_de_bots](#blocklist_de_bots)|2925|2925|172|5.8%|7.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|111|0.0%|5.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|104|0.0%|4.7%|
[sorbs_spam](#sorbs_spam)|64701|65536|76|0.1%|3.5%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|76|0.1%|3.5%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|76|0.1%|3.5%|
[nixspam](#nixspam)|25392|25392|62|0.2%|2.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|58|0.0%|2.6%|
[blocklist_de_mail](#blocklist_de_mail)|17874|17874|57|0.3%|2.6%|
[snort_ipfilter](#snort_ipfilter)|9671|9671|41|0.4%|1.8%|
[php_dictionary](#php_dictionary)|737|737|41|5.5%|1.8%|
[php_spammers](#php_spammers)|735|735|34|4.6%|1.5%|
[sorbs_web](#sorbs_web)|544|545|14|2.5%|0.6%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|13|1.9%|0.5%|
[php_commenters](#php_commenters)|430|430|10|2.3%|0.4%|
[blocklist_de_strongips](#blocklist_de_strongips)|175|175|7|4.0%|0.3%|
[dragon_http](#dragon_http)|1029|270336|6|0.0%|0.2%|
[alienvault_reputation](#alienvault_reputation)|192275|192275|5|0.0%|0.2%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|3|0.5%|0.1%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|3|0.0%|0.1%|
[php_harvesters](#php_harvesters)|392|392|2|0.5%|0.0%|
[iw_spamlist](#iw_spamlist)|3818|3818|2|0.0%|0.0%|
[dm_tor](#dm_tor)|6506|6506|2|0.0%|0.0%|
[bm_tor](#bm_tor)|6528|6528|2|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.0%|
[et_tor](#et_tor)|6400|6400|1|0.0%|0.0%|
[et_compromised](#et_compromised)|1721|1721|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1700|1700|1|0.0%|0.0%|

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
[firehol_level1](#firehol_level1)|5137|688854492|230|0.0%|100.0%|
[et_block](#et_block)|1000|18344011|228|0.0%|99.1%|
[firehol_level3](#firehol_level3)|109650|9627417|203|0.0%|88.2%|
[zeus_badips](#zeus_badips)|202|202|202|100.0%|87.8%|
[snort_ipfilter](#snort_ipfilter)|9671|9671|200|2.0%|86.9%|
[alienvault_reputation](#alienvault_reputation)|192275|192275|61|0.0%|26.5%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|15|0.0%|6.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|14|0.0%|6.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|10|0.0%|4.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|9|0.0%|3.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|7|0.0%|3.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|5|0.0%|2.1%|
[dragon_http](#dragon_http)|1029|270336|3|0.0%|1.3%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|2|0.0%|0.8%|
[openbl_60d](#openbl_60d)|6984|6984|2|0.0%|0.8%|
[openbl_30d](#openbl_30d)|2809|2809|2|0.0%|0.8%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|1|0.0%|0.4%|
[stopforumspam_1d](#stopforumspam_1d)|6745|6745|1|0.0%|0.4%|
[php_commenters](#php_commenters)|430|430|1|0.2%|0.4%|
[openbl_7d](#openbl_7d)|628|628|1|0.1%|0.4%|
[nixspam](#nixspam)|25392|25392|1|0.0%|0.4%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|1|0.0%|0.4%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.4%|
[firehol_level2](#firehol_level2)|22462|34082|1|0.0%|0.4%|

## zeus_badips

[Abuse.ch Zeus tracker](https://zeustracker.abuse.ch) badips includes IPv4 addresses that are used by the ZeuS trojan. It is the recommened blocklist if you want to block only ZeuS IPs. It excludes IP addresses that ZeuS Tracker believes to be hijacked (level 2) or belong to a free web hosting provider (level 3). Hence the false postive rate should be much lower compared to the standard ZeuS IP blocklist. **excellent list**

Source is downloaded from [this link](https://zeustracker.abuse.ch/blocklist.php?download=badips).

The last time downloaded was found to be dated: Thu Jun 11 17:36:26 UTC 2015.

The ipset `zeus_badips` has **202** entries, **202** unique IPs.

The following table shows the overlaps of `zeus_badips` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `zeus_badips`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `zeus_badips`.
- ` this % ` is the percentage **of this ipset (`zeus_badips`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[zeus](#zeus)|230|230|202|87.8%|100.0%|
[firehol_level1](#firehol_level1)|5137|688854492|202|0.0%|100.0%|
[et_block](#et_block)|1000|18344011|202|0.0%|100.0%|
[firehol_level3](#firehol_level3)|109650|9627417|180|0.0%|89.1%|
[snort_ipfilter](#snort_ipfilter)|9671|9671|178|1.8%|88.1%|
[alienvault_reputation](#alienvault_reputation)|192275|192275|37|0.0%|18.3%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|15|0.0%|7.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|10|0.0%|4.9%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|10|0.0%|4.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|8|0.0%|3.9%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|5|0.0%|2.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|4|0.0%|1.9%|
[dragon_http](#dragon_http)|1029|270336|3|0.0%|1.4%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|2|0.0%|0.9%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|1|0.0%|0.4%|
[stopforumspam_1d](#stopforumspam_1d)|6745|6745|1|0.0%|0.4%|
[php_commenters](#php_commenters)|430|430|1|0.2%|0.4%|
[openbl_7d](#openbl_7d)|628|628|1|0.1%|0.4%|
[openbl_60d](#openbl_60d)|6984|6984|1|0.0%|0.4%|
[openbl_30d](#openbl_30d)|2809|2809|1|0.0%|0.4%|
[nixspam](#nixspam)|25392|25392|1|0.0%|0.4%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.4%|
[firehol_level2](#firehol_level2)|22462|34082|1|0.0%|0.4%|
