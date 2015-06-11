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

The following list was automatically generated on Thu Jun 11 15:55:15 UTC 2015.

The update frequency is the maximum allowed by internal configuration. A list will never be downloaded sooner than the update frequency stated. A list may also not be downloaded, after this frequency expired, if it has not been modified on the server (as reported by HTTP `IF_MODIFIED_SINCE` method).

name|info|type|entries|update|
:--:|:--:|:--:|:-----:|:----:|
[alienvault_reputation](#alienvault_reputation)|[AlienVault.com](https://www.alienvault.com/) IP reputation database (this list seems to include port scanning hosts and to be updated regularly, but we found no information about its retention policy)|ipv4 hash:ip|188722 unique IPs|updated every 6 hours  from [this link](https://reputation.alienvault.com/reputation.generic)
[blocklist_de](#blocklist_de)|[Blocklist.de](https://www.blocklist.de/) IPs that have been detected by fail2ban in the last 48 hours - **excellent list**|ipv4 hash:ip|28020 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/all.txt)
[blocklist_de_apache](#blocklist_de_apache)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service Apache, Apache-DDOS, RFI-Attacks.|ipv4 hash:ip|14213 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/apache.txt)
[blocklist_de_bots](#blocklist_de_bots)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the RFI-Attacks, REG-Bots, IRC-Bots or BadBots (BadBots = he has posted a Spam-Comment on a open Forum or Wiki).|ipv4 hash:ip|2921 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/bots.txt)
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|[Blocklist.de](https://www.blocklist.de/) All IPs which attacks Joomlas, Wordpress and other Web-Logins with Brute-Force Logins.|ipv4 hash:ip|2845 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/bruteforcelogin.txt)
[blocklist_de_ftp](#blocklist_de_ftp)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours for attacks on the Service FTP.|ipv4 hash:ip|1421 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/ftp.txt)
[blocklist_de_imap](#blocklist_de_imap)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours for attacks on the Service imap, sasl, pop3, etc.|ipv4 hash:ip|2801 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/imap.txt)
[blocklist_de_mail](#blocklist_de_mail)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service Mail, Postfix.|ipv4 hash:ip|17167 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/mail.txt)
[blocklist_de_sip](#blocklist_de_sip)|[Blocklist.de](https://www.blocklist.de/) All IP addresses that tried to login in a SIP, VOIP or Asterisk Server and are included in the IPs list from [infiltrated.net](www.infiltrated.net)|ipv4 hash:ip|85 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/sip.txt)
[blocklist_de_ssh](#blocklist_de_ssh)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service SSH.|ipv4 hash:ip|3301 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/ssh.txt)
[blocklist_de_strongips](#blocklist_de_strongips)|[Blocklist.de](https://www.blocklist.de/) All IPs which are older then 2 month and have more then 5.000 attacks.|ipv4 hash:ip|176 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/strongips.txt)
[bm_tor](#bm_tor)|[torstatus.blutmagie.de](https://torstatus.blutmagie.de) list of all TOR network servers|ipv4 hash:ip|6492 unique IPs|updated every 30 mins  from [this link](https://torstatus.blutmagie.de/ip_list_all.php/Tor_ip_list_ALL.csv)
[bogons](#bogons)|[Team-Cymru.org](http://www.team-cymru.org) private and reserved addresses defined by RFC 1918, RFC 5735, and RFC 6598 and netblocks that have not been allocated to a regional internet registry - **excellent list - use it only your internet interface**|ipv4 hash:net|13 subnets, 592708608 unique IPs|updated every 1 day  from [this link](http://www.team-cymru.org/Services/Bogons/bogon-bn-agg.txt)
[bruteforceblocker](#bruteforceblocker)|[danger.rulez.sk](http://danger.rulez.sk/) IPs detected by [bruteforceblocker](http://danger.rulez.sk/index.php/bruteforceblocker/) (fail2ban alternative for SSH on OpenBSD). This is an automatically generated list from users reporting failed authentication attempts. An IP seems to be included if 3 or more users report it. Its retention pocily seems 30 days.|ipv4 hash:ip|1701 unique IPs|updated every 3 hours  from [this link](http://danger.rulez.sk/projects/bruteforceblocker/blist.php)
[ciarmy](#ciarmy)|[CIArmy.com](http://ciarmy.com/) IPs with poor Rogue Packet score that have not yet been identified as malicious by the community|ipv4 hash:ip|457 unique IPs|updated every 3 hours  from [this link](http://cinsscore.com/list/ci-badguys.txt)
[cleanmx_viruses](#cleanmx_viruses)|[Clean-MX.de](http://support.clean-mx.de/clean-mx/viruses.php) IPs with viruses|ipv4 hash:ip|115 unique IPs|updated every 12 hours  from [this link](http://support.clean-mx.de/clean-mx/xmlviruses.php?sort=id%20desc&response=alive)
[dm_tor](#dm_tor)|[dan.me.uk](https://www.dan.me.uk) dynamic list of TOR nodes|ipv4 hash:ip|6492 unique IPs|updated every 30 mins  from [this link](https://www.dan.me.uk/torlist/)
[dragon_http](#dragon_http)|[Dragon Search Group](http://www.dragonresearchgroup.org/) IPs that have been seen sending HTTP requests to Dragon Research Pods in the last 7 days. This report lists hosts that are highly suspicious and are likely conducting malicious HTTP attacks. LEGITIMATE SEARCH ENGINE BOTS MAY BE IN THIS LIST. This report is informational.  It is not a blacklist, but some operators may choose to use it to help protect their networks and hosts in the forms of automated reporting and mitigation services.|ipv4 hash:net|1029 subnets, 270336 unique IPs|updated every 1 day  from [this link](http://www.dragonresearchgroup.org/insight/http-report.txt)
[dshield](#dshield)|[DShield.org](https://dshield.org/) top 20 attacking class C (/24) subnets over the last three days - **excellent list**|ipv4 hash:net|20 subnets, 5120 unique IPs|updated every 4 hours  from [this link](http://feeds.dshield.org/block.txt)
[et_block](#et_block)|[EmergingThreats.net](http://www.emergingthreats.net/) default blacklist (at the time of writing includes spamhaus DROP, dshield and abuse.ch trackers, which are available separately too - prefer to use the direct ipsets instead of this, they seem to lag a bit in updates)|ipv4 hash:net|1000 subnets, 18344011 unique IPs|updated every 12 hours  from [this link](http://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt)
[et_botcc](#et_botcc)|[EmergingThreats.net Command and Control IPs](http://doc.emergingthreats.net/bin/view/Main/BotCC) These IPs are updates every 24 hours and should be considered VERY highly reliable indications that a host is communicating with a known and active Bot or Malware command and control server - (although they say this includes abuse.ch trackers, it does not - most probably it is the shadowserver.org C&C list)|ipv4 hash:ip|506 unique IPs|updated every 12 hours  from [this link](http://rules.emergingthreats.net/fwrules/emerging-PIX-CC.rules)
[et_compromised](#et_compromised)|[EmergingThreats.net compromised hosts](http://doc.emergingthreats.net/bin/view/Main/CompromisedHost) - (this seems to be based on bruteforceblocker)|ipv4 hash:ip|1721 unique IPs|updated every 12 hours  from [this link](http://rules.emergingthreats.net/blockrules/compromised-ips.txt)
et_dshield|[EmergingThreats.net](http://www.emergingthreats.net/) dshield blocklist|ipv4 hash:net|disabled|updated every 12 hours  from [this link](http://rules.emergingthreats.net/fwrules/emerging-PIX-DSHIELD.rules)
et_spamhaus|[EmergingThreats.net](http://www.emergingthreats.net/) spamhaus blocklist|ipv4 hash:net|disabled|updated every 12 hours  from [this link](http://rules.emergingthreats.net/fwrules/emerging-PIX-DROP.rules)
[et_tor](#et_tor)|[EmergingThreats.net](http://www.emergingthreats.net/) [list](http://doc.emergingthreats.net/bin/view/Main/TorRules) of TOR network IPs|ipv4 hash:ip|6400 unique IPs|updated every 12 hours  from [this link](http://rules.emergingthreats.net/blockrules/emerging-tor.rules)
[feodo](#feodo)|[Abuse.ch Feodo tracker](https://feodotracker.abuse.ch) trojan includes IPs which are being used by Feodo (also known as Cridex or Bugat) which commits ebanking fraud - **excellent list**|ipv4 hash:ip|105 unique IPs|updated every 30 mins  from [this link](https://feodotracker.abuse.ch/blocklist/?download=ipblocklist)
[firehol_anonymous](#firehol_anonymous)|**FireHOL Anonymous** - Known anonymizing IPs. (includes: firehol_proxies anonymous bm_tor dm_tor tor_exits)|ipv4 hash:net|18973 subnets, 83011 unique IPs|
[firehol_level1](#firehol_level1)|**FireHOL Level 1** - Maximum protection without false positives. (includes: fullbogons dshield feodo palevo sslbl zeus spamhaus_drop spamhaus_edrop)|ipv4 hash:net|5136 subnets, 688854491 unique IPs|
[firehol_level2](#firehol_level2)|**FireHOL Level 2** - Maximum protection from attacks took place in the last 48 hours. (includes: openbl_1d blocklist_de stopforumspam_1d)|ipv4 hash:net|21681 subnets, 33301 unique IPs|
[firehol_level3](#firehol_level3)|**FireHOL Level 3** - All the bad IPs in last 30 days. (includes: openbl_30d stopforumspam_30d virbl malc0de shunlist malwaredomainlist bruteforceblocker ciarmy cleanmx_viruses snort_ipfilter ib_bluetack_spyware ib_bluetack_hijacked ib_bluetack_webexploit php_commenters php_dictionary php_harvesters php_spammers iw_wormlist)|ipv4 hash:net|109889 subnets, 9627682 unique IPs|
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
[iw_spamlist](#iw_spamlist)|[ImproWare Antispam](http://antispam.imp.ch/) IPs sending spam, in the last 3 days|ipv4 hash:ip|3795 unique IPs|updated every 1 hour  from [this link](http://antispam.imp.ch/spamlist)
[iw_wormlist](#iw_wormlist)|[ImproWare Antispam](http://antispam.imp.ch/) IPs sending emails with viruses or worms, in the last 3 days|ipv4 hash:ip|33 unique IPs|updated every 1 hour  from [this link](http://antispam.imp.ch/wormlist)
lashback_ubl|[The LashBack UBL](http://blacklist.lashback.com/) The Unsubscribe Blacklist (UBL) is a real-time blacklist of IP addresses which are sending email to names harvested from suppression files (this is a big list, more than 500.000 IPs)|ipv4 hash:ip|disabled|updated every 1 day  from [this link](http://www.unsubscore.com/blacklist.txt)
[malc0de](#malc0de)|[Malc0de.com](http://malc0de.com) malicious IPs of the last 30 days|ipv4 hash:ip|276 unique IPs|updated every 1 day  from [this link](http://malc0de.com/bl/IP_Blacklist.txt)
[malwaredomainlist](#malwaredomainlist)|[malwaredomainlist.com](http://www.malwaredomainlist.com) list of malware active ip addresses|ipv4 hash:ip|1288 unique IPs|updated every 12 hours  from [this link](http://www.malwaredomainlist.com/hostslist/ip.txt)
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|[MaxMind.com](https://www.maxmind.com/en/anonymous-proxy-fraudulent-ip-address-list) list of anonymous proxy fraudelent IP addresses.|ipv4 hash:ip|524 unique IPs|updated every 4 hours  from [this link](https://www.maxmind.com/en/anonymous-proxy-fraudulent-ip-address-list)
[nixspam](#nixspam)|[NiX Spam](http://www.heise.de/ix/NiX-Spam-DNSBL-and-blacklist-for-download-499637.html) IP addresses that sent spam in the last hour - automatically generated entries without distinguishing open proxies from relays, dialup gateways, and so on. All IPs are removed after 12 hours if there is no spam from there.|ipv4 hash:ip|25075 unique IPs|updated every 15 mins  from [this link](http://www.dnsbl.manitu.net/download/nixspam-ip.dump.gz)
[nt_malware_http](#nt_malware_http)|[No Think](http://www.nothink.org/) Malware HTTP|ipv4 hash:ip|69 unique IPs|updated every 1 hour  from [this link](http://www.nothink.org/blacklist/blacklist_malware_http.txt)
[nt_malware_irc](#nt_malware_irc)|[No Think](http://www.nothink.org/) Malware IRC|ipv4 hash:ip|43 unique IPs|updated every 1 hour  from [this link](http://www.nothink.org/blacklist/blacklist_malware_irc.txt)
[nt_ssh_7d](#nt_ssh_7d)|[No Think](http://www.nothink.org/) Last 7 days SSH attacks|ipv4 hash:ip|0 unique IPs|updated every 1 hour  from [this link](http://www.nothink.org/blacklist/blacklist_ssh_week.txt)
openbl|[OpenBL.org](http://www.openbl.org/) default blacklist (currently it is the same with 90 days). OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications - **excellent list**|ipv4 hash:ip|disabled|updated every 4 hours  from [this link](http://www.openbl.org/lists/base.txt)
openbl_180d|[OpenBL.org](http://www.openbl.org/) last 180 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|disabled|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_180days.txt)
[openbl_1d](#openbl_1d)|[OpenBL.org](http://www.openbl.org/) last 24 hours IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|136 unique IPs|updated every 1 hour  from [this link](http://www.openbl.org/lists/base_1days.txt)
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
[shunlist](#shunlist)|[AutoShun.org](http://autoshun.org/) IPs identified as hostile by correlating logs from distributed snort installations running the autoshun plugin|ipv4 hash:ip|1278 unique IPs|updated every 4 hours  from [this link](http://www.autoshun.org/files/shunlist.csv)
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
[virbl](#virbl)|[VirBL](http://virbl.bit.nl/) is a project of which the idea was born during the RIPE-48 meeting. The plan was to get reports of virusscanning mailservers, and put the IP-addresses that were reported to send viruses on a blacklist.|ipv4 hash:ip|25 unique IPs|updated every 1 hour  from [this link](http://virbl.bit.nl/download/virbl.dnsbl.bit.nl.txt)
[voipbl](#voipbl)|[VoIPBL.org](http://www.voipbl.org/) a distributed VoIP blacklist that is aimed to protects against VoIP Fraud and minimizing abuse for network that have publicly accessible PBX's. Several algorithms, external sources and manual confirmation are used before they categorize something as an attack and determine the threat level.|ipv4 hash:net|10586 subnets, 10998 unique IPs|updated every 4 hours  from [this link](http://www.voipbl.org/update/)
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
[firehol_level3](#firehol_level3)|109889|9627682|4886|0.0%|2.5%|
[et_block](#et_block)|1000|18344011|4764|0.0%|2.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|4448|0.0%|2.3%|
[firehol_level1](#firehol_level1)|5136|688854491|3321|0.0%|1.7%|
[openbl_30d](#openbl_30d)|2813|2813|2796|99.3%|1.4%|
[dshield](#dshield)|20|5120|2321|45.3%|1.2%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|1372|0.0%|0.7%|
[firehol_level2](#firehol_level2)|21681|33301|1301|3.9%|0.6%|
[shunlist](#shunlist)|1278|1278|1258|98.4%|0.6%|
[blocklist_de](#blocklist_de)|28020|28020|1254|4.4%|0.6%|
[et_compromised](#et_compromised)|1721|1721|1116|64.8%|0.5%|
[bruteforceblocker](#bruteforceblocker)|1701|1701|1076|63.2%|0.5%|
[blocklist_de_ssh](#blocklist_de_ssh)|3301|3301|1048|31.7%|0.5%|
[openbl_7d](#openbl_7d)|641|641|637|99.3%|0.3%|
[ciarmy](#ciarmy)|457|457|445|97.3%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|291|0.0%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|265|0.0%|0.1%|
[voipbl](#voipbl)|10586|10998|184|1.6%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|168|0.1%|0.0%|
[openbl_1d](#openbl_1d)|136|136|132|97.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14213|14213|125|0.8%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9945|9945|108|1.0%|0.0%|
[sorbs_spam](#sorbs_spam)|64701|65536|91|0.1%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|91|0.1%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|91|0.1%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|89|0.3%|0.0%|
[sslbl](#sslbl)|371|371|65|17.5%|0.0%|
[zeus](#zeus)|230|230|61|26.5%|0.0%|
[firehol_anonymous](#firehol_anonymous)|18973|83011|57|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6710|6710|49|0.7%|0.0%|
[nixspam](#nixspam)|25075|25075|48|0.1%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|17167|17167|46|0.2%|0.0%|
[dm_tor](#dm_tor)|6492|6492|42|0.6%|0.0%|
[bm_tor](#bm_tor)|6492|6492|42|0.6%|0.0%|
[et_tor](#et_tor)|6400|6400|39|0.6%|0.0%|
[firehol_proxies](#firehol_proxies)|12374|12641|38|0.3%|0.0%|
[zeus_badips](#zeus_badips)|202|202|37|18.3%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|176|176|36|20.4%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2801|2801|31|1.1%|0.0%|
[tor_exits](#tor_exits)|1121|1121|30|2.6%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|29|5.5%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|85|85|19|22.3%|0.0%|
[php_commenters](#php_commenters)|430|430|18|4.1%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2845|2845|18|0.6%|0.0%|
[iw_spamlist](#iw_spamlist)|3795|3795|17|0.4%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|2921|2921|17|0.5%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|15|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|14|0.0%|0.0%|
[php_harvesters](#php_harvesters)|392|392|12|3.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|1421|1421|10|0.7%|0.0%|
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

The last time downloaded was found to be dated: Thu Jun 11 15:30:06 UTC 2015.

The ipset `blocklist_de` has **28020** entries, **28020** unique IPs.

The following table shows the overlaps of `blocklist_de` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de`.
- ` this % ` is the percentage **of this ipset (`blocklist_de`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|21681|33301|28020|84.1%|100.0%|
[blocklist_de_mail](#blocklist_de_mail)|17167|17167|17165|99.9%|61.2%|
[blocklist_de_apache](#blocklist_de_apache)|14213|14213|14213|100.0%|50.7%|
[firehol_level3](#firehol_level3)|109889|9627682|3948|0.0%|14.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|3547|0.0%|12.6%|
[blocklist_de_ssh](#blocklist_de_ssh)|3301|3301|3299|99.9%|11.7%|
[blocklist_de_bots](#blocklist_de_bots)|2921|2921|2913|99.7%|10.3%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2845|2845|2845|100.0%|10.1%|
[blocklist_de_imap](#blocklist_de_imap)|2801|2801|2799|99.9%|9.9%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|2791|2.9%|9.9%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|2278|7.8%|8.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|1592|0.0%|5.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|1555|0.0%|5.5%|
[stopforumspam_1d](#stopforumspam_1d)|6710|6710|1443|21.5%|5.1%|
[blocklist_de_ftp](#blocklist_de_ftp)|1421|1421|1421|100.0%|5.0%|
[sorbs_spam](#sorbs_spam)|64701|65536|1348|2.0%|4.8%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|1342|2.0%|4.7%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|1342|2.0%|4.7%|
[alienvault_reputation](#alienvault_reputation)|188722|188722|1254|0.6%|4.4%|
[openbl_60d](#openbl_60d)|6989|6989|880|12.5%|3.1%|
[nixspam](#nixspam)|25075|25075|738|2.9%|2.6%|
[openbl_30d](#openbl_30d)|2813|2813|703|24.9%|2.5%|
[firehol_anonymous](#firehol_anonymous)|18973|83011|665|0.8%|2.3%|
[firehol_proxies](#firehol_proxies)|12374|12641|637|5.0%|2.2%|
[bruteforceblocker](#bruteforceblocker)|1701|1701|591|34.7%|2.1%|
[et_compromised](#et_compromised)|1721|1721|582|33.8%|2.0%|
[ri_web_proxies](#ri_web_proxies)|7800|7800|468|6.0%|1.6%|
[shunlist](#shunlist)|1278|1278|401|31.3%|1.4%|
[openbl_7d](#openbl_7d)|641|641|388|60.5%|1.3%|
[xroxy](#xroxy)|2165|2165|226|10.4%|0.8%|
[et_block](#et_block)|1000|18344011|223|0.0%|0.7%|
[snort_ipfilter](#snort_ipfilter)|9945|9945|217|2.1%|0.7%|
[firehol_level1](#firehol_level1)|5136|688854491|217|0.0%|0.7%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|197|0.0%|0.7%|
[proxyrss](#proxyrss)|1373|1373|197|14.3%|0.7%|
[proxz](#proxz)|1297|1297|184|14.1%|0.6%|
[blocklist_de_strongips](#blocklist_de_strongips)|176|176|176|100.0%|0.6%|
[dshield](#dshield)|20|5120|124|2.4%|0.4%|
[iw_spamlist](#iw_spamlist)|3795|3795|123|3.2%|0.4%|
[php_dictionary](#php_dictionary)|737|737|122|16.5%|0.4%|
[openbl_1d](#openbl_1d)|136|136|122|89.7%|0.4%|
[php_spammers](#php_spammers)|735|735|109|14.8%|0.3%|
[php_commenters](#php_commenters)|430|430|102|23.7%|0.3%|
[ri_connect_proxies](#ri_connect_proxies)|2811|2811|70|2.4%|0.2%|
[blocklist_de_sip](#blocklist_de_sip)|85|85|66|77.6%|0.2%|
[sorbs_web](#sorbs_web)|531|532|63|11.8%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|59|0.0%|0.2%|
[dragon_http](#dragon_http)|1029|270336|52|0.0%|0.1%|
[voipbl](#voipbl)|10586|10998|41|0.3%|0.1%|
[php_harvesters](#php_harvesters)|392|392|40|10.2%|0.1%|
[ciarmy](#ciarmy)|457|457|37|8.0%|0.1%|
[tor_exits](#tor_exits)|1121|1121|24|2.1%|0.0%|
[et_tor](#et_tor)|6400|6400|15|0.2%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|13|0.0%|0.0%|
[dm_tor](#dm_tor)|6492|6492|12|0.1%|0.0%|
[bm_tor](#bm_tor)|6492|6492|12|0.1%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|7|1.3%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|7|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|5|0.0%|0.0%|
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

The last time downloaded was found to be dated: Thu Jun 11 15:30:10 UTC 2015.

The ipset `blocklist_de_apache` has **14213** entries, **14213** unique IPs.

The following table shows the overlaps of `blocklist_de_apache` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_apache`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_apache`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_apache`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|21681|33301|14213|42.6%|100.0%|
[blocklist_de](#blocklist_de)|28020|28020|14213|50.7%|100.0%|
[blocklist_de_mail](#blocklist_de_mail)|17167|17167|11059|64.4%|77.8%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2845|2845|2845|100.0%|20.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|2300|0.0%|16.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|1322|0.0%|9.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|1092|0.0%|7.6%|
[firehol_level3](#firehol_level3)|109889|9627682|290|0.0%|2.0%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|205|0.2%|1.4%|
[alienvault_reputation](#alienvault_reputation)|188722|188722|125|0.0%|0.8%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|122|0.4%|0.8%|
[stopforumspam_1d](#stopforumspam_1d)|6710|6710|68|1.0%|0.4%|
[sorbs_spam](#sorbs_spam)|64701|65536|46|0.0%|0.3%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|46|0.0%|0.3%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|46|0.0%|0.3%|
[shunlist](#shunlist)|1278|1278|37|2.8%|0.2%|
[snort_ipfilter](#snort_ipfilter)|9945|9945|34|0.3%|0.2%|
[blocklist_de_strongips](#blocklist_de_strongips)|176|176|34|19.3%|0.2%|
[php_commenters](#php_commenters)|430|430|31|7.2%|0.2%|
[ciarmy](#ciarmy)|457|457|30|6.5%|0.2%|
[firehol_anonymous](#firehol_anonymous)|18973|83011|26|0.0%|0.1%|
[tor_exits](#tor_exits)|1121|1121|23|2.0%|0.1%|
[nixspam](#nixspam)|25075|25075|23|0.0%|0.1%|
[blocklist_de_bots](#blocklist_de_bots)|2921|2921|22|0.7%|0.1%|
[et_tor](#et_tor)|6400|6400|15|0.2%|0.1%|
[dragon_http](#dragon_http)|1029|270336|15|0.0%|0.1%|
[dm_tor](#dm_tor)|6492|6492|12|0.1%|0.0%|
[bm_tor](#bm_tor)|6492|6492|12|0.1%|0.0%|
[firehol_level1](#firehol_level1)|5136|688854491|11|0.0%|0.0%|
[et_block](#et_block)|1000|18344011|11|0.0%|0.0%|
[openbl_60d](#openbl_60d)|6989|6989|7|0.1%|0.0%|
[php_spammers](#php_spammers)|735|735|6|0.8%|0.0%|
[openbl_30d](#openbl_30d)|2813|2813|6|0.2%|0.0%|
[dshield](#dshield)|20|5120|6|0.1%|0.0%|
[openbl_7d](#openbl_7d)|641|641|5|0.7%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|4|0.0%|0.0%|
[iw_spamlist](#iw_spamlist)|3795|3795|4|0.1%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|4|0.0%|0.0%|
[voipbl](#voipbl)|10586|10998|3|0.0%|0.0%|
[php_dictionary](#php_dictionary)|737|737|3|0.4%|0.0%|
[firehol_proxies](#firehol_proxies)|12374|12641|3|0.0%|0.0%|
[php_harvesters](#php_harvesters)|392|392|2|0.5%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|2|0.3%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|2|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|1|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7800|7800|1|0.0%|0.0%|
[openbl_1d](#openbl_1d)|136|136|1|0.7%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|115|115|1|0.8%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2801|2801|1|0.0%|0.0%|

## blocklist_de_bots

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the RFI-Attacks, REG-Bots, IRC-Bots or BadBots (BadBots = he has posted a Spam-Comment on a open Forum or Wiki).

Source is downloaded from [this link](http://lists.blocklist.de/lists/bots.txt).

The last time downloaded was found to be dated: Thu Jun 11 15:42:09 UTC 2015.

The ipset `blocklist_de_bots` has **2921** entries, **2921** unique IPs.

The following table shows the overlaps of `blocklist_de_bots` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_bots`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_bots`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_bots`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|21681|33301|2915|8.7%|99.7%|
[blocklist_de](#blocklist_de)|28020|28020|2913|10.3%|99.7%|
[firehol_level3](#firehol_level3)|109889|9627682|2447|0.0%|83.7%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|2422|2.5%|82.9%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|2074|7.1%|71.0%|
[stopforumspam_1d](#stopforumspam_1d)|6710|6710|1375|20.4%|47.0%|
[firehol_anonymous](#firehol_anonymous)|18973|83011|509|0.6%|17.4%|
[firehol_proxies](#firehol_proxies)|12374|12641|507|4.0%|17.3%|
[ri_web_proxies](#ri_web_proxies)|7800|7800|381|4.8%|13.0%|
[proxyrss](#proxyrss)|1373|1373|197|14.3%|6.7%|
[xroxy](#xroxy)|2165|2165|168|7.7%|5.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|157|0.0%|5.3%|
[proxz](#proxz)|1297|1297|152|11.7%|5.2%|
[blocklist_de_strongips](#blocklist_de_strongips)|176|176|129|73.2%|4.4%|
[php_commenters](#php_commenters)|430|430|81|18.8%|2.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|74|0.0%|2.5%|
[ri_connect_proxies](#ri_connect_proxies)|2811|2811|66|2.3%|2.2%|
[firehol_level1](#firehol_level1)|5136|688854491|54|0.0%|1.8%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|50|0.0%|1.7%|
[et_block](#et_block)|1000|18344011|50|0.0%|1.7%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|47|0.0%|1.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|44|0.0%|1.5%|
[sorbs_spam](#sorbs_spam)|64701|65536|28|0.0%|0.9%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|28|0.0%|0.9%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|28|0.0%|0.9%|
[php_harvesters](#php_harvesters)|392|392|28|7.1%|0.9%|
[nixspam](#nixspam)|25075|25075|27|0.1%|0.9%|
[blocklist_de_mail](#blocklist_de_mail)|17167|17167|22|0.1%|0.7%|
[blocklist_de_apache](#blocklist_de_apache)|14213|14213|22|0.1%|0.7%|
[snort_ipfilter](#snort_ipfilter)|9945|9945|21|0.2%|0.7%|
[php_spammers](#php_spammers)|735|735|21|2.8%|0.7%|
[alienvault_reputation](#alienvault_reputation)|188722|188722|17|0.0%|0.5%|
[php_dictionary](#php_dictionary)|737|737|15|2.0%|0.5%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|5|0.9%|0.1%|
[iw_spamlist](#iw_spamlist)|3795|3795|5|0.1%|0.1%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|4|0.0%|0.1%|
[sorbs_web](#sorbs_web)|531|532|4|0.7%|0.1%|
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

The last time downloaded was found to be dated: Thu Jun 11 15:42:11 UTC 2015.

The ipset `blocklist_de_bruteforce` has **2845** entries, **2845** unique IPs.

The following table shows the overlaps of `blocklist_de_bruteforce` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_bruteforce`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_bruteforce`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_bruteforce`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|21681|33301|2845|8.5%|100.0%|
[blocklist_de_apache](#blocklist_de_apache)|14213|14213|2845|20.0%|100.0%|
[blocklist_de](#blocklist_de)|28020|28020|2845|10.1%|100.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|210|0.0%|7.3%|
[firehol_level3](#firehol_level3)|109889|9627682|91|0.0%|3.1%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|73|0.0%|2.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|59|0.0%|2.0%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|53|0.1%|1.8%|
[sorbs_spam](#sorbs_spam)|64701|65536|46|0.0%|1.6%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|46|0.0%|1.6%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|46|0.0%|1.6%|
[stopforumspam_1d](#stopforumspam_1d)|6710|6710|36|0.5%|1.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|34|0.0%|1.1%|
[snort_ipfilter](#snort_ipfilter)|9945|9945|31|0.3%|1.0%|
[nixspam](#nixspam)|25075|25075|23|0.0%|0.8%|
[firehol_anonymous](#firehol_anonymous)|18973|83011|23|0.0%|0.8%|
[tor_exits](#tor_exits)|1121|1121|21|1.8%|0.7%|
[alienvault_reputation](#alienvault_reputation)|188722|188722|18|0.0%|0.6%|
[et_tor](#et_tor)|6400|6400|13|0.2%|0.4%|
[php_commenters](#php_commenters)|430|430|10|2.3%|0.3%|
[dm_tor](#dm_tor)|6492|6492|9|0.1%|0.3%|
[bm_tor](#bm_tor)|6492|6492|9|0.1%|0.3%|
[blocklist_de_strongips](#blocklist_de_strongips)|176|176|9|5.1%|0.3%|
[php_spammers](#php_spammers)|735|735|6|0.8%|0.2%|
[et_block](#et_block)|1000|18344011|5|0.0%|0.1%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|4|0.0%|0.1%|
[iw_spamlist](#iw_spamlist)|3795|3795|4|0.1%|0.1%|
[firehol_level1](#firehol_level1)|5136|688854491|4|0.0%|0.1%|
[dragon_http](#dragon_http)|1029|270336|4|0.0%|0.1%|
[php_dictionary](#php_dictionary)|737|737|3|0.4%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|3|0.0%|0.1%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|2|0.0%|0.0%|
[firehol_proxies](#firehol_proxies)|12374|12641|2|0.0%|0.0%|
[voipbl](#voipbl)|10586|10998|1|0.0%|0.0%|
[shunlist](#shunlist)|1278|1278|1|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7800|7800|1|0.0%|0.0%|
[php_harvesters](#php_harvesters)|392|392|1|0.2%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|1|0.1%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.0%|

## blocklist_de_ftp

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours for attacks on the Service FTP.

Source is downloaded from [this link](http://lists.blocklist.de/lists/ftp.txt).

The last time downloaded was found to be dated: Thu Jun 11 15:30:11 UTC 2015.

The ipset `blocklist_de_ftp` has **1421** entries, **1421** unique IPs.

The following table shows the overlaps of `blocklist_de_ftp` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_ftp`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_ftp`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_ftp`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|21681|33301|1421|4.2%|100.0%|
[blocklist_de](#blocklist_de)|28020|28020|1421|5.0%|100.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|123|0.0%|8.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|24|0.0%|1.6%|
[firehol_level3](#firehol_level3)|109889|9627682|24|0.0%|1.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|20|0.0%|1.4%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|16|0.0%|1.1%|
[sorbs_spam](#sorbs_spam)|64701|65536|15|0.0%|1.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|15|0.0%|1.0%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|15|0.0%|1.0%|
[nixspam](#nixspam)|25075|25075|12|0.0%|0.8%|
[alienvault_reputation](#alienvault_reputation)|188722|188722|10|0.0%|0.7%|
[dragon_http](#dragon_http)|1029|270336|6|0.0%|0.4%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|5|0.0%|0.3%|
[php_harvesters](#php_harvesters)|392|392|4|1.0%|0.2%|
[iw_spamlist](#iw_spamlist)|3795|3795|3|0.0%|0.2%|
[firehol_anonymous](#firehol_anonymous)|18973|83011|3|0.0%|0.2%|
[openbl_60d](#openbl_60d)|6989|6989|2|0.0%|0.1%|
[blocklist_de_strongips](#blocklist_de_strongips)|176|176|2|1.1%|0.1%|
[stopforumspam_1d](#stopforumspam_1d)|6710|6710|1|0.0%|0.0%|
[sorbs_web](#sorbs_web)|531|532|1|0.1%|0.0%|
[php_spammers](#php_spammers)|735|735|1|0.1%|0.0%|
[php_dictionary](#php_dictionary)|737|737|1|0.1%|0.0%|
[openbl_7d](#openbl_7d)|641|641|1|0.1%|0.0%|
[openbl_30d](#openbl_30d)|2813|2813|1|0.0%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|1|0.0%|0.0%|
[ciarmy](#ciarmy)|457|457|1|0.2%|0.0%|

## blocklist_de_imap

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours for attacks on the Service imap, sasl, pop3, etc.

Source is downloaded from [this link](http://lists.blocklist.de/lists/imap.txt).

The last time downloaded was found to be dated: Thu Jun 11 15:30:10 UTC 2015.

The ipset `blocklist_de_imap` has **2801** entries, **2801** unique IPs.

The following table shows the overlaps of `blocklist_de_imap` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_imap`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_imap`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_imap`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de_mail](#blocklist_de_mail)|17167|17167|2801|16.3%|100.0%|
[firehol_level2](#firehol_level2)|21681|33301|2799|8.4%|99.9%|
[blocklist_de](#blocklist_de)|28020|28020|2799|9.9%|99.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|309|0.0%|11.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|72|0.0%|2.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|70|0.0%|2.4%|
[nixspam](#nixspam)|25075|25075|43|0.1%|1.5%|
[firehol_level3](#firehol_level3)|109889|9627682|37|0.0%|1.3%|
[sorbs_spam](#sorbs_spam)|64701|65536|33|0.0%|1.1%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|32|0.0%|1.1%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|32|0.0%|1.1%|
[alienvault_reputation](#alienvault_reputation)|188722|188722|31|0.0%|1.1%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|16|0.0%|0.5%|
[openbl_60d](#openbl_60d)|6989|6989|16|0.2%|0.5%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|10|0.0%|0.3%|
[firehol_level1](#firehol_level1)|5136|688854491|10|0.0%|0.3%|
[et_block](#et_block)|1000|18344011|10|0.0%|0.3%|
[openbl_30d](#openbl_30d)|2813|2813|9|0.3%|0.3%|
[openbl_7d](#openbl_7d)|641|641|7|1.0%|0.2%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|6|0.0%|0.2%|
[dragon_http](#dragon_http)|1029|270336|5|0.0%|0.1%|
[snort_ipfilter](#snort_ipfilter)|9945|9945|4|0.0%|0.1%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|4|0.0%|0.1%|
[et_compromised](#et_compromised)|1721|1721|4|0.2%|0.1%|
[bruteforceblocker](#bruteforceblocker)|1701|1701|4|0.2%|0.1%|
[shunlist](#shunlist)|1278|1278|3|0.2%|0.1%|
[stopforumspam_1d](#stopforumspam_1d)|6710|6710|2|0.0%|0.0%|
[php_harvesters](#php_harvesters)|392|392|2|0.5%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2|0.0%|0.0%|
[ciarmy](#ciarmy)|457|457|2|0.4%|0.0%|
[voipbl](#voipbl)|10586|10998|1|0.0%|0.0%|
[openbl_1d](#openbl_1d)|136|136|1|0.7%|0.0%|
[iw_spamlist](#iw_spamlist)|3795|3795|1|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14213|14213|1|0.0%|0.0%|

## blocklist_de_mail

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service Mail, Postfix.

Source is downloaded from [this link](http://lists.blocklist.de/lists/mail.txt).

The last time downloaded was found to be dated: Thu Jun 11 15:30:08 UTC 2015.

The ipset `blocklist_de_mail` has **17167** entries, **17167** unique IPs.

The following table shows the overlaps of `blocklist_de_mail` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_mail`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_mail`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_mail`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|21681|33301|17165|51.5%|99.9%|
[blocklist_de](#blocklist_de)|28020|28020|17165|61.2%|99.9%|
[blocklist_de_apache](#blocklist_de_apache)|14213|14213|11059|77.8%|64.4%|
[blocklist_de_imap](#blocklist_de_imap)|2801|2801|2801|100.0%|16.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|2534|0.0%|14.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|1423|0.0%|8.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|1266|0.0%|7.3%|
[sorbs_spam](#sorbs_spam)|64701|65536|1253|1.9%|7.2%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|1247|1.9%|7.2%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|1247|1.9%|7.2%|
[nixspam](#nixspam)|25075|25075|674|2.6%|3.9%|
[firehol_level3](#firehol_level3)|109889|9627682|406|0.0%|2.3%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|257|0.2%|1.4%|
[snort_ipfilter](#snort_ipfilter)|9945|9945|164|1.6%|0.9%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|146|0.5%|0.8%|
[firehol_anonymous](#firehol_anonymous)|18973|83011|126|0.1%|0.7%|
[firehol_proxies](#firehol_proxies)|12374|12641|124|0.9%|0.7%|
[iw_spamlist](#iw_spamlist)|3795|3795|111|2.9%|0.6%|
[php_dictionary](#php_dictionary)|737|737|102|13.8%|0.5%|
[ri_web_proxies](#ri_web_proxies)|7800|7800|84|1.0%|0.4%|
[php_spammers](#php_spammers)|735|735|79|10.7%|0.4%|
[sorbs_web](#sorbs_web)|531|532|58|10.9%|0.3%|
[xroxy](#xroxy)|2165|2165|57|2.6%|0.3%|
[alienvault_reputation](#alienvault_reputation)|188722|188722|46|0.0%|0.2%|
[stopforumspam_1d](#stopforumspam_1d)|6710|6710|44|0.6%|0.2%|
[proxz](#proxz)|1297|1297|30|2.3%|0.1%|
[php_commenters](#php_commenters)|430|430|27|6.2%|0.1%|
[openbl_60d](#openbl_60d)|6989|6989|23|0.3%|0.1%|
[blocklist_de_bots](#blocklist_de_bots)|2921|2921|22|0.7%|0.1%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|21|0.0%|0.1%|
[firehol_level1](#firehol_level1)|5136|688854491|21|0.0%|0.1%|
[et_block](#et_block)|1000|18344011|21|0.0%|0.1%|
[blocklist_de_strongips](#blocklist_de_strongips)|176|176|21|11.9%|0.1%|
[openbl_30d](#openbl_30d)|2813|2813|15|0.5%|0.0%|
[dragon_http](#dragon_http)|1029|270336|12|0.0%|0.0%|
[openbl_7d](#openbl_7d)|641|641|9|1.4%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|8|0.0%|0.0%|
[php_harvesters](#php_harvesters)|392|392|6|1.5%|0.0%|
[et_compromised](#et_compromised)|1721|1721|5|0.2%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1701|1701|5|0.2%|0.0%|
[shunlist](#shunlist)|1278|1278|4|0.3%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|4|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2811|2811|3|0.1%|0.0%|
[openbl_1d](#openbl_1d)|136|136|3|2.2%|0.0%|
[dm_tor](#dm_tor)|6492|6492|3|0.0%|0.0%|
[bm_tor](#bm_tor)|6492|6492|3|0.0%|0.0%|
[voipbl](#voipbl)|10586|10998|2|0.0%|0.0%|
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

The last time downloaded was found to be dated: Thu Jun 11 15:42:08 UTC 2015.

The ipset `blocklist_de_sip` has **85** entries, **85** unique IPs.

The following table shows the overlaps of `blocklist_de_sip` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_sip`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_sip`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_sip`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|21681|33301|66|0.1%|77.6%|
[blocklist_de](#blocklist_de)|28020|28020|66|0.2%|77.6%|
[voipbl](#voipbl)|10586|10998|34|0.3%|40.0%|
[alienvault_reputation](#alienvault_reputation)|188722|188722|19|0.0%|22.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|13|0.0%|15.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|5|0.0%|5.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|5|0.0%|5.8%|
[firehol_level3](#firehol_level3)|109889|9627682|4|0.0%|4.7%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|2|0.0%|2.3%|
[shunlist](#shunlist)|1278|1278|2|0.1%|2.3%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|2|0.0%|2.3%|
[firehol_level1](#firehol_level1)|5136|688854491|2|0.0%|2.3%|
[et_block](#et_block)|1000|18344011|2|0.0%|2.3%|
[dragon_http](#dragon_http)|1029|270336|2|0.0%|2.3%|
[et_botcc](#et_botcc)|506|506|1|0.1%|1.1%|

## blocklist_de_ssh

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service SSH.

Source is downloaded from [this link](http://lists.blocklist.de/lists/ssh.txt).

The last time downloaded was found to be dated: Thu Jun 11 15:42:04 UTC 2015.

The ipset `blocklist_de_ssh` has **3301** entries, **3301** unique IPs.

The following table shows the overlaps of `blocklist_de_ssh` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_ssh`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_ssh`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_ssh`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|21681|33301|3299|9.9%|99.9%|
[blocklist_de](#blocklist_de)|28020|28020|3299|11.7%|99.9%|
[alienvault_reputation](#alienvault_reputation)|188722|188722|1048|0.5%|31.7%|
[firehol_level3](#firehol_level3)|109889|9627682|914|0.0%|27.6%|
[openbl_60d](#openbl_60d)|6989|6989|847|12.1%|25.6%|
[openbl_30d](#openbl_30d)|2813|2813|680|24.1%|20.5%|
[bruteforceblocker](#bruteforceblocker)|1701|1701|584|34.3%|17.6%|
[et_compromised](#et_compromised)|1721|1721|575|33.4%|17.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|495|0.0%|14.9%|
[openbl_7d](#openbl_7d)|641|641|373|58.1%|11.2%|
[shunlist](#shunlist)|1278|1278|358|28.0%|10.8%|
[et_block](#et_block)|1000|18344011|139|0.0%|4.2%|
[firehol_level1](#firehol_level1)|5136|688854491|129|0.0%|3.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|124|0.0%|3.7%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|120|0.0%|3.6%|
[openbl_1d](#openbl_1d)|136|136|118|86.7%|3.5%|
[dshield](#dshield)|20|5120|118|2.3%|3.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|56|0.0%|1.6%|
[blocklist_de_strongips](#blocklist_de_strongips)|176|176|30|17.0%|0.9%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|25|0.0%|0.7%|
[dragon_http](#dragon_http)|1029|270336|14|0.0%|0.4%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|6|0.0%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|6|0.0%|0.1%|
[sorbs_spam](#sorbs_spam)|64701|65536|5|0.0%|0.1%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|5|0.0%|0.1%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|5|0.0%|0.1%|
[ciarmy](#ciarmy)|457|457|4|0.8%|0.1%|
[voipbl](#voipbl)|10586|10998|2|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7800|7800|1|0.0%|0.0%|
[php_spammers](#php_spammers)|735|735|1|0.1%|0.0%|
[php_harvesters](#php_harvesters)|392|392|1|0.2%|0.0%|
[php_commenters](#php_commenters)|430|430|1|0.2%|0.0%|
[nixspam](#nixspam)|25075|25075|1|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|1|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|1|0.0%|0.0%|
[firehol_proxies](#firehol_proxies)|12374|12641|1|0.0%|0.0%|
[firehol_anonymous](#firehol_anonymous)|18973|83011|1|0.0%|0.0%|

## blocklist_de_strongips

[Blocklist.de](https://www.blocklist.de/) All IPs which are older then 2 month and have more then 5.000 attacks.

Source is downloaded from [this link](http://lists.blocklist.de/lists/strongips.txt).

The last time downloaded was found to be dated: Thu Jun 11 15:42:10 UTC 2015.

The ipset `blocklist_de_strongips` has **176** entries, **176** unique IPs.

The following table shows the overlaps of `blocklist_de_strongips` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_strongips`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_strongips`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_strongips`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|21681|33301|176|0.5%|100.0%|
[blocklist_de](#blocklist_de)|28020|28020|176|0.6%|100.0%|
[firehol_level3](#firehol_level3)|109889|9627682|162|0.0%|92.0%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|135|0.1%|76.7%|
[blocklist_de_bots](#blocklist_de_bots)|2921|2921|129|4.4%|73.2%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|120|0.4%|68.1%|
[stopforumspam_1d](#stopforumspam_1d)|6710|6710|104|1.5%|59.0%|
[php_commenters](#php_commenters)|430|430|45|10.4%|25.5%|
[alienvault_reputation](#alienvault_reputation)|188722|188722|36|0.0%|20.4%|
[blocklist_de_apache](#blocklist_de_apache)|14213|14213|34|0.2%|19.3%|
[blocklist_de_ssh](#blocklist_de_ssh)|3301|3301|30|0.9%|17.0%|
[openbl_60d](#openbl_60d)|6989|6989|25|0.3%|14.2%|
[openbl_30d](#openbl_30d)|2813|2813|24|0.8%|13.6%|
[openbl_7d](#openbl_7d)|641|641|23|3.5%|13.0%|
[blocklist_de_mail](#blocklist_de_mail)|17167|17167|21|0.1%|11.9%|
[shunlist](#shunlist)|1278|1278|19|1.4%|10.7%|
[openbl_1d](#openbl_1d)|136|136|17|12.5%|9.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|16|0.0%|9.0%|
[firehol_level1](#firehol_level1)|5136|688854491|11|0.0%|6.2%|
[php_spammers](#php_spammers)|735|735|10|1.3%|5.6%|
[et_block](#et_block)|1000|18344011|9|0.0%|5.1%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2845|2845|9|0.3%|5.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|8|0.0%|4.5%|
[firehol_proxies](#firehol_proxies)|12374|12641|8|0.0%|4.5%|
[firehol_anonymous](#firehol_anonymous)|18973|83011|8|0.0%|4.5%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|7|0.0%|3.9%|
[ri_web_proxies](#ri_web_proxies)|7800|7800|7|0.0%|3.9%|
[xroxy](#xroxy)|2165|2165|6|0.2%|3.4%|
[proxz](#proxz)|1297|1297|6|0.4%|3.4%|
[proxyrss](#proxyrss)|1373|1373|6|0.4%|3.4%|
[php_dictionary](#php_dictionary)|737|737|5|0.6%|2.8%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|3|0.0%|1.7%|
[php_harvesters](#php_harvesters)|392|392|3|0.7%|1.7%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|1.7%|
[sorbs_web](#sorbs_web)|531|532|2|0.3%|1.1%|
[sorbs_spam](#sorbs_spam)|64701|65536|2|0.0%|1.1%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|2|0.0%|1.1%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|2|0.0%|1.1%|
[snort_ipfilter](#snort_ipfilter)|9945|9945|2|0.0%|1.1%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|2|0.1%|1.1%|
[dragon_http](#dragon_http)|1029|270336|2|0.0%|1.1%|
[blocklist_de_ftp](#blocklist_de_ftp)|1421|1421|2|0.1%|1.1%|
[nixspam](#nixspam)|25075|25075|1|0.0%|0.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|1|0.0%|0.5%|
[et_compromised](#et_compromised)|1721|1721|1|0.0%|0.5%|
[dshield](#dshield)|20|5120|1|0.0%|0.5%|
[ciarmy](#ciarmy)|457|457|1|0.2%|0.5%|
[bruteforceblocker](#bruteforceblocker)|1701|1701|1|0.0%|0.5%|

## bm_tor

[torstatus.blutmagie.de](https://torstatus.blutmagie.de) list of all TOR network servers

Source is downloaded from [this link](https://torstatus.blutmagie.de/ip_list_all.php/Tor_ip_list_ALL.csv).

The last time downloaded was found to be dated: Thu Jun 11 15:54:02 UTC 2015.

The ipset `bm_tor` has **6492** entries, **6492** unique IPs.

The following table shows the overlaps of `bm_tor` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `bm_tor`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `bm_tor`.
- ` this % ` is the percentage **of this ipset (`bm_tor`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_anonymous](#firehol_anonymous)|18973|83011|6492|7.8%|100.0%|
[dm_tor](#dm_tor)|6492|6492|6353|97.8%|97.8%|
[et_tor](#et_tor)|6400|6400|5690|88.9%|87.6%|
[firehol_level3](#firehol_level3)|109889|9627682|1086|0.0%|16.7%|
[snort_ipfilter](#snort_ipfilter)|9945|9945|1050|10.5%|16.1%|
[tor_exits](#tor_exits)|1121|1121|1019|90.9%|15.6%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|640|0.6%|9.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|629|0.0%|9.6%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|532|1.8%|8.1%|
[firehol_level2](#firehol_level2)|21681|33301|341|1.0%|5.2%|
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
[blocklist_de_apache](#blocklist_de_apache)|14213|14213|12|0.0%|0.1%|
[blocklist_de](#blocklist_de)|28020|28020|12|0.0%|0.1%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2845|2845|9|0.3%|0.1%|
[php_harvesters](#php_harvesters)|392|392|7|1.7%|0.1%|
[nixspam](#nixspam)|25075|25075|7|0.0%|0.1%|
[ri_web_proxies](#ri_web_proxies)|7800|7800|5|0.0%|0.0%|
[php_spammers](#php_spammers)|735|735|5|0.6%|0.0%|
[sorbs_spam](#sorbs_spam)|64701|65536|4|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|4|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|4|0.0%|0.0%|
[php_dictionary](#php_dictionary)|737|737|4|0.5%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|4|0.0%|0.0%|
[voipbl](#voipbl)|10586|10998|3|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|3|0.0%|0.0%|
[firehol_level1](#firehol_level1)|5136|688854491|3|0.0%|0.0%|
[et_block](#et_block)|1000|18344011|3|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|17167|17167|3|0.0%|0.0%|
[xroxy](#xroxy)|2165|2165|2|0.0%|0.0%|
[shunlist](#shunlist)|1278|1278|1|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2811|2811|1|0.0%|0.0%|
[iw_spamlist](#iw_spamlist)|3795|3795|1|0.0%|0.0%|

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
[voipbl](#voipbl)|10586|10998|319|2.9%|0.0%|
[iw_spamlist](#iw_spamlist)|3795|3795|5|0.1%|0.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|5|0.0%|0.0%|
[firehol_level3](#firehol_level3)|109889|9627682|3|0.0%|0.0%|
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
[firehol_level3](#firehol_level3)|109889|9627682|1701|0.0%|100.0%|
[et_compromised](#et_compromised)|1721|1721|1639|95.2%|96.3%|
[alienvault_reputation](#alienvault_reputation)|188722|188722|1076|0.5%|63.2%|
[openbl_60d](#openbl_60d)|6989|6989|968|13.8%|56.9%|
[openbl_30d](#openbl_30d)|2813|2813|907|32.2%|53.3%|
[firehol_level2](#firehol_level2)|21681|33301|592|1.7%|34.8%|
[blocklist_de](#blocklist_de)|28020|28020|591|2.1%|34.7%|
[blocklist_de_ssh](#blocklist_de_ssh)|3301|3301|584|17.6%|34.3%|
[shunlist](#shunlist)|1278|1278|394|30.8%|23.1%|
[openbl_7d](#openbl_7d)|641|641|310|48.3%|18.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|157|0.0%|9.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|88|0.0%|5.1%|
[openbl_1d](#openbl_1d)|136|136|75|55.1%|4.4%|
[et_block](#et_block)|1000|18344011|69|0.0%|4.0%|
[firehol_level1](#firehol_level1)|5136|688854491|68|0.0%|3.9%|
[dshield](#dshield)|20|5120|62|1.2%|3.6%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|61|0.0%|3.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|54|0.0%|3.1%|
[dragon_http](#dragon_http)|1029|270336|12|0.0%|0.7%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|10|0.0%|0.5%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|5|0.0%|0.2%|
[blocklist_de_mail](#blocklist_de_mail)|17167|17167|5|0.0%|0.2%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|4|0.0%|0.2%|
[blocklist_de_imap](#blocklist_de_imap)|2801|2801|4|0.1%|0.2%|
[voipbl](#voipbl)|10586|10998|3|0.0%|0.1%|
[sorbs_spam](#sorbs_spam)|64701|65536|3|0.0%|0.1%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|3|0.0%|0.1%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|3|0.0%|0.1%|
[firehol_proxies](#firehol_proxies)|12374|12641|3|0.0%|0.1%|
[firehol_anonymous](#firehol_anonymous)|18973|83011|3|0.0%|0.1%|
[ciarmy](#ciarmy)|457|457|3|0.6%|0.1%|
[proxz](#proxz)|1297|1297|2|0.1%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|2|0.0%|0.1%|
[xroxy](#xroxy)|2165|2165|1|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6710|6710|1|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7800|7800|1|0.0%|0.0%|
[php_spammers](#php_spammers)|735|735|1|0.1%|0.0%|
[php_commenters](#php_commenters)|430|430|1|0.2%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|176|176|1|0.5%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|2921|2921|1|0.0%|0.0%|

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
[firehol_level3](#firehol_level3)|109889|9627682|457|0.0%|100.0%|
[alienvault_reputation](#alienvault_reputation)|188722|188722|445|0.2%|97.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|100|0.0%|21.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|47|0.0%|10.2%|
[firehol_level2](#firehol_level2)|21681|33301|38|0.1%|8.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|37|0.0%|8.0%|
[blocklist_de](#blocklist_de)|28020|28020|37|0.1%|8.0%|
[blocklist_de_apache](#blocklist_de_apache)|14213|14213|30|0.2%|6.5%|
[shunlist](#shunlist)|1278|1278|26|2.0%|5.6%|
[dragon_http](#dragon_http)|1029|270336|8|0.0%|1.7%|
[et_block](#et_block)|1000|18344011|6|0.0%|1.3%|
[firehol_level1](#firehol_level1)|5136|688854491|4|0.0%|0.8%|
[blocklist_de_ssh](#blocklist_de_ssh)|3301|3301|4|0.1%|0.8%|
[openbl_7d](#openbl_7d)|641|641|3|0.4%|0.6%|
[openbl_60d](#openbl_60d)|6989|6989|3|0.0%|0.6%|
[openbl_30d](#openbl_30d)|2813|2813|3|0.1%|0.6%|
[et_compromised](#et_compromised)|1721|1721|3|0.1%|0.6%|
[dshield](#dshield)|20|5120|3|0.0%|0.6%|
[bruteforceblocker](#bruteforceblocker)|1701|1701|3|0.1%|0.6%|
[openbl_1d](#openbl_1d)|136|136|2|1.4%|0.4%|
[blocklist_de_mail](#blocklist_de_mail)|17167|17167|2|0.0%|0.4%|
[blocklist_de_imap](#blocklist_de_imap)|2801|2801|2|0.0%|0.4%|
[voipbl](#voipbl)|10586|10998|1|0.0%|0.2%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|1|0.0%|0.2%|
[fullbogons](#fullbogons)|3775|670173256|1|0.0%|0.2%|
[bogons](#bogons)|13|592708608|1|0.0%|0.2%|
[blocklist_de_strongips](#blocklist_de_strongips)|176|176|1|0.5%|0.2%|
[blocklist_de_ftp](#blocklist_de_ftp)|1421|1421|1|0.0%|0.2%|

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
[firehol_level3](#firehol_level3)|109889|9627682|115|0.0%|100.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|20|0.0%|17.3%|
[malc0de](#malc0de)|276|276|9|3.2%|7.8%|
[alienvault_reputation](#alienvault_reputation)|188722|188722|7|0.0%|6.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|6|0.0%|5.2%|
[snort_ipfilter](#snort_ipfilter)|9945|9945|4|0.0%|3.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|4|0.0%|3.4%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.8%|
[firehol_level2](#firehol_level2)|21681|33301|1|0.0%|0.8%|
[firehol_level1](#firehol_level1)|5136|688854491|1|0.0%|0.8%|
[dshield](#dshield)|20|5120|1|0.0%|0.8%|
[blocklist_de_apache](#blocklist_de_apache)|14213|14213|1|0.0%|0.8%|
[blocklist_de](#blocklist_de)|28020|28020|1|0.0%|0.8%|

## dm_tor

[dan.me.uk](https://www.dan.me.uk) dynamic list of TOR nodes

Source is downloaded from [this link](https://www.dan.me.uk/torlist/).

The last time downloaded was found to be dated: Thu Jun 11 15:36:06 UTC 2015.

The ipset `dm_tor` has **6492** entries, **6492** unique IPs.

The following table shows the overlaps of `dm_tor` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `dm_tor`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `dm_tor`.
- ` this % ` is the percentage **of this ipset (`dm_tor`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_anonymous](#firehol_anonymous)|18973|83011|6492|7.8%|100.0%|
[bm_tor](#bm_tor)|6492|6492|6353|97.8%|97.8%|
[et_tor](#et_tor)|6400|6400|5682|88.7%|87.5%|
[firehol_level3](#firehol_level3)|109889|9627682|1078|0.0%|16.6%|
[snort_ipfilter](#snort_ipfilter)|9945|9945|1042|10.4%|16.0%|
[tor_exits](#tor_exits)|1121|1121|1013|90.3%|15.6%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|639|0.6%|9.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|630|0.0%|9.7%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|530|1.8%|8.1%|
[firehol_level2](#firehol_level2)|21681|33301|340|1.0%|5.2%|
[stopforumspam_1d](#stopforumspam_1d)|6710|6710|335|4.9%|5.1%|
[firehol_proxies](#firehol_proxies)|12374|12641|237|1.8%|3.6%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|232|44.2%|3.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|184|0.0%|2.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|168|0.0%|2.5%|
[php_commenters](#php_commenters)|430|430|51|11.8%|0.7%|
[alienvault_reputation](#alienvault_reputation)|188722|188722|42|0.0%|0.6%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|22|0.0%|0.3%|
[openbl_60d](#openbl_60d)|6989|6989|20|0.2%|0.3%|
[dragon_http](#dragon_http)|1029|270336|14|0.0%|0.2%|
[blocklist_de_apache](#blocklist_de_apache)|14213|14213|12|0.0%|0.1%|
[blocklist_de](#blocklist_de)|28020|28020|12|0.0%|0.1%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2845|2845|9|0.3%|0.1%|
[php_harvesters](#php_harvesters)|392|392|7|1.7%|0.1%|
[nixspam](#nixspam)|25075|25075|7|0.0%|0.1%|
[ri_web_proxies](#ri_web_proxies)|7800|7800|5|0.0%|0.0%|
[php_spammers](#php_spammers)|735|735|5|0.6%|0.0%|
[sorbs_spam](#sorbs_spam)|64701|65536|4|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|4|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|4|0.0%|0.0%|
[php_dictionary](#php_dictionary)|737|737|4|0.5%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|4|0.0%|0.0%|
[voipbl](#voipbl)|10586|10998|3|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|3|0.0%|0.0%|
[firehol_level1](#firehol_level1)|5136|688854491|3|0.0%|0.0%|
[et_block](#et_block)|1000|18344011|3|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|17167|17167|3|0.0%|0.0%|
[xroxy](#xroxy)|2165|2165|2|0.0%|0.0%|
[shunlist](#shunlist)|1278|1278|1|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2811|2811|1|0.0%|0.0%|
[iw_spamlist](#iw_spamlist)|3795|3795|1|0.0%|0.0%|

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
[firehol_level3](#firehol_level3)|109889|9627682|557|0.0%|0.2%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|256|0.0%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|256|0.0%|0.0%|
[openbl_60d](#openbl_60d)|6989|6989|218|3.1%|0.0%|
[openbl_30d](#openbl_30d)|2813|2813|148|5.2%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|111|0.1%|0.0%|
[sorbs_spam](#sorbs_spam)|64701|65536|71|0.1%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|70|0.1%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|70|0.1%|0.0%|
[firehol_level2](#firehol_level2)|21681|33301|63|0.1%|0.0%|
[openbl_7d](#openbl_7d)|641|641|54|8.4%|0.0%|
[blocklist_de](#blocklist_de)|28020|28020|52|0.1%|0.0%|
[firehol_anonymous](#firehol_anonymous)|18973|83011|43|0.0%|0.0%|
[shunlist](#shunlist)|1278|1278|37|2.8%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|36|0.1%|0.0%|
[firehol_proxies](#firehol_proxies)|12374|12641|30|0.2%|0.0%|
[nixspam](#nixspam)|25075|25075|28|0.1%|0.0%|
[voipbl](#voipbl)|10586|10998|27|0.2%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|26|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7800|7800|18|0.2%|0.0%|
[bm_tor](#bm_tor)|6492|6492|16|0.2%|0.0%|
[et_tor](#et_tor)|6400|6400|15|0.2%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14213|14213|15|0.1%|0.0%|
[dm_tor](#dm_tor)|6492|6492|14|0.2%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3301|3301|14|0.4%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1701|1701|12|0.7%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|17167|17167|12|0.0%|0.0%|
[et_compromised](#et_compromised)|1721|1721|11|0.6%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6710|6710|10|0.1%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9945|9945|10|0.1%|0.0%|
[ciarmy](#ciarmy)|457|457|8|1.7%|0.0%|
[xroxy](#xroxy)|2165|2165|6|0.2%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|6|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|1421|1421|6|0.4%|0.0%|
[tor_exits](#tor_exits)|1121|1121|5|0.4%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2801|2801|5|0.1%|0.0%|
[proxz](#proxz)|1297|1297|4|0.3%|0.0%|
[php_commenters](#php_commenters)|430|430|4|0.9%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|4|0.7%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2845|2845|4|0.1%|0.0%|
[zeus_badips](#zeus_badips)|202|202|3|1.4%|0.0%|
[zeus](#zeus)|230|230|3|1.3%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2811|2811|3|0.1%|0.0%|
[openbl_1d](#openbl_1d)|136|136|3|2.2%|0.0%|
[malc0de](#malc0de)|276|276|3|1.0%|0.0%|
[iw_spamlist](#iw_spamlist)|3795|3795|3|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|3|0.2%|0.0%|
[et_botcc](#et_botcc)|506|506|3|0.5%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|2921|2921|3|0.1%|0.0%|
[php_dictionary](#php_dictionary)|737|737|2|0.2%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|2|0.1%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|176|176|2|1.1%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|85|85|2|2.3%|0.0%|
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
[firehol_level3](#firehol_level3)|109889|9627682|157|0.0%|3.0%|
[openbl_60d](#openbl_60d)|6989|6989|151|2.1%|2.9%|
[openbl_30d](#openbl_30d)|2813|2813|136|4.8%|2.6%|
[firehol_level2](#firehol_level2)|21681|33301|124|0.3%|2.4%|
[blocklist_de](#blocklist_de)|28020|28020|124|0.4%|2.4%|
[blocklist_de_ssh](#blocklist_de_ssh)|3301|3301|118|3.5%|2.3%|
[shunlist](#shunlist)|1278|1278|113|8.8%|2.2%|
[et_compromised](#et_compromised)|1721|1721|102|5.9%|1.9%|
[bruteforceblocker](#bruteforceblocker)|1701|1701|62|3.6%|1.2%|
[openbl_7d](#openbl_7d)|641|641|50|7.8%|0.9%|
[openbl_1d](#openbl_1d)|136|136|17|12.5%|0.3%|
[blocklist_de_apache](#blocklist_de_apache)|14213|14213|6|0.0%|0.1%|
[ciarmy](#ciarmy)|457|457|3|0.6%|0.0%|
[malc0de](#malc0de)|276|276|2|0.7%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|115|115|1|0.8%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|176|176|1|0.5%|0.0%|

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
[firehol_level3](#firehol_level3)|109889|9627682|6933381|72.0%|37.7%|
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
[firehol_level2](#firehol_level2)|21681|33301|286|0.8%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|272|0.9%|0.0%|
[zeus](#zeus)|230|230|228|99.1%|0.0%|
[blocklist_de](#blocklist_de)|28020|28020|223|0.7%|0.0%|
[zeus_badips](#zeus_badips)|202|202|202|100.0%|0.0%|
[openbl_30d](#openbl_30d)|2813|2813|163|5.7%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3301|3301|139|4.2%|0.0%|
[shunlist](#shunlist)|1278|1278|115|8.9%|0.0%|
[et_compromised](#et_compromised)|1721|1721|109|6.3%|0.0%|
[feodo](#feodo)|105|105|104|99.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6710|6710|79|1.1%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1701|1701|69|4.0%|0.0%|
[openbl_7d](#openbl_7d)|641|641|61|9.5%|0.0%|
[nixspam](#nixspam)|25075|25075|57|0.2%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|2921|2921|50|1.7%|0.0%|
[sslbl](#sslbl)|371|371|38|10.2%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|30|2.3%|0.0%|
[php_commenters](#php_commenters)|430|430|29|6.7%|0.0%|
[sorbs_spam](#sorbs_spam)|64701|65536|22|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|22|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|22|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|17167|17167|21|0.1%|0.0%|
[openbl_1d](#openbl_1d)|136|136|18|13.2%|0.0%|
[voipbl](#voipbl)|10586|10998|14|0.1%|0.0%|
[palevo](#palevo)|12|12|12|100.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14213|14213|11|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2801|2801|10|0.3%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|176|176|9|5.1%|0.0%|
[php_dictionary](#php_dictionary)|737|737|6|0.8%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|6|0.4%|0.0%|
[firehol_anonymous](#firehol_anonymous)|18973|83011|6|0.0%|0.0%|
[ciarmy](#ciarmy)|457|457|6|1.3%|0.0%|
[malc0de](#malc0de)|276|276|5|1.8%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|5|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2845|2845|5|0.1%|0.0%|
[php_spammers](#php_spammers)|735|735|4|0.5%|0.0%|
[nt_malware_http](#nt_malware_http)|69|69|4|5.7%|0.0%|
[iw_spamlist](#iw_spamlist)|3795|3795|4|0.1%|0.0%|
[nt_malware_irc](#nt_malware_irc)|43|43|3|6.9%|0.0%|
[firehol_proxies](#firehol_proxies)|12374|12641|3|0.0%|0.0%|
[et_tor](#et_tor)|6400|6400|3|0.0%|0.0%|
[dm_tor](#dm_tor)|6492|6492|3|0.0%|0.0%|
[bm_tor](#bm_tor)|6492|6492|3|0.0%|0.0%|
[tor_exits](#tor_exits)|1121|1121|2|0.1%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|2|0.3%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|85|85|2|2.3%|0.0%|
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
[firehol_level3](#firehol_level3)|109889|9627682|3|0.0%|0.5%|
[dragon_http](#dragon_http)|1029|270336|3|0.0%|0.5%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|1|0.0%|0.1%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|1|0.0%|0.1%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|1|0.0%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.1%|
[firehol_level1](#firehol_level1)|5136|688854491|1|0.0%|0.1%|
[et_block](#et_block)|1000|18344011|1|0.0%|0.1%|
[blocklist_de_sip](#blocklist_de_sip)|85|85|1|1.1%|0.1%|

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
[firehol_level3](#firehol_level3)|109889|9627682|1695|0.0%|98.4%|
[bruteforceblocker](#bruteforceblocker)|1701|1701|1639|96.3%|95.2%|
[alienvault_reputation](#alienvault_reputation)|188722|188722|1116|0.5%|64.8%|
[openbl_60d](#openbl_60d)|6989|6989|1014|14.5%|58.9%|
[openbl_30d](#openbl_30d)|2813|2813|945|33.5%|54.9%|
[firehol_level2](#firehol_level2)|21681|33301|583|1.7%|33.8%|
[blocklist_de](#blocklist_de)|28020|28020|582|2.0%|33.8%|
[blocklist_de_ssh](#blocklist_de_ssh)|3301|3301|575|17.4%|33.4%|
[shunlist](#shunlist)|1278|1278|430|33.6%|24.9%|
[openbl_7d](#openbl_7d)|641|641|313|48.8%|18.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|152|0.0%|8.8%|
[et_block](#et_block)|1000|18344011|109|0.0%|6.3%|
[firehol_level1](#firehol_level1)|5136|688854491|108|0.0%|6.2%|
[dshield](#dshield)|20|5120|102|1.9%|5.9%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|101|0.0%|5.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|85|0.0%|4.9%|
[openbl_1d](#openbl_1d)|136|136|73|53.6%|4.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|52|0.0%|3.0%|
[dragon_http](#dragon_http)|1029|270336|11|0.0%|0.6%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|10|0.0%|0.5%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|5|0.0%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|5|0.0%|0.2%|
[blocklist_de_mail](#blocklist_de_mail)|17167|17167|5|0.0%|0.2%|
[blocklist_de_imap](#blocklist_de_imap)|2801|2801|4|0.1%|0.2%|
[voipbl](#voipbl)|10586|10998|3|0.0%|0.1%|
[sorbs_spam](#sorbs_spam)|64701|65536|3|0.0%|0.1%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|3|0.0%|0.1%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|3|0.0%|0.1%|
[firehol_proxies](#firehol_proxies)|12374|12641|3|0.0%|0.1%|
[firehol_anonymous](#firehol_anonymous)|18973|83011|3|0.0%|0.1%|
[ciarmy](#ciarmy)|457|457|3|0.6%|0.1%|
[proxz](#proxz)|1297|1297|2|0.1%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|2|0.0%|0.1%|
[xroxy](#xroxy)|2165|2165|1|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6710|6710|1|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7800|7800|1|0.0%|0.0%|
[php_spammers](#php_spammers)|735|735|1|0.1%|0.0%|
[php_commenters](#php_commenters)|430|430|1|0.2%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|176|176|1|0.5%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|2921|2921|1|0.0%|0.0%|

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
[firehol_anonymous](#firehol_anonymous)|18973|83011|5755|6.9%|89.9%|
[bm_tor](#bm_tor)|6492|6492|5690|87.6%|88.9%|
[dm_tor](#dm_tor)|6492|6492|5682|87.5%|88.7%|
[firehol_level3](#firehol_level3)|109889|9627682|1125|0.0%|17.5%|
[snort_ipfilter](#snort_ipfilter)|9945|9945|1089|10.9%|17.0%|
[tor_exits](#tor_exits)|1121|1121|970|86.5%|15.1%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|653|0.6%|10.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|625|0.0%|9.7%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|547|1.8%|8.5%|
[firehol_level2](#firehol_level2)|21681|33301|344|1.0%|5.3%|
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
[blocklist_de_apache](#blocklist_de_apache)|14213|14213|15|0.1%|0.2%|
[blocklist_de](#blocklist_de)|28020|28020|15|0.0%|0.2%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2845|2845|13|0.4%|0.2%|
[php_harvesters](#php_harvesters)|392|392|7|1.7%|0.1%|
[nixspam](#nixspam)|25075|25075|6|0.0%|0.0%|
[php_spammers](#php_spammers)|735|735|5|0.6%|0.0%|
[sorbs_spam](#sorbs_spam)|64701|65536|4|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|4|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|4|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7800|7800|4|0.0%|0.0%|
[php_dictionary](#php_dictionary)|737|737|4|0.5%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|4|0.0%|0.0%|
[voipbl](#voipbl)|10586|10998|3|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|3|0.0%|0.0%|
[firehol_level1](#firehol_level1)|5136|688854491|3|0.0%|0.0%|
[et_block](#et_block)|1000|18344011|3|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|17167|17167|2|0.0%|0.0%|
[xroxy](#xroxy)|2165|2165|1|0.0%|0.0%|
[shunlist](#shunlist)|1278|1278|1|0.0%|0.0%|
[iw_spamlist](#iw_spamlist)|3795|3795|1|0.0%|0.0%|

## feodo

[Abuse.ch Feodo tracker](https://feodotracker.abuse.ch) trojan includes IPs which are being used by Feodo (also known as Cridex or Bugat) which commits ebanking fraud - **excellent list**

Source is downloaded from [this link](https://feodotracker.abuse.ch/blocklist/?download=ipblocklist).

The last time downloaded was found to be dated: Thu Jun 11 15:54:15 UTC 2015.

The ipset `feodo` has **105** entries, **105** unique IPs.

The following table shows the overlaps of `feodo` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `feodo`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `feodo`.
- ` this % ` is the percentage **of this ipset (`feodo`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level1](#firehol_level1)|5136|688854491|105|0.0%|100.0%|
[et_block](#et_block)|1000|18344011|104|0.0%|99.0%|
[snort_ipfilter](#snort_ipfilter)|9945|9945|83|0.8%|79.0%|
[firehol_level3](#firehol_level3)|109889|9627682|83|0.0%|79.0%|
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

The ipset `firehol_anonymous` has **18973** entries, **83011** unique IPs.

The following table shows the overlaps of `firehol_anonymous` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `firehol_anonymous`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `firehol_anonymous`.
- ` this % ` is the percentage **of this ipset (`firehol_anonymous`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_proxies](#firehol_proxies)|12374|12641|12641|100.0%|15.2%|
[ri_web_proxies](#ri_web_proxies)|7800|7800|7800|100.0%|9.3%|
[firehol_level3](#firehol_level3)|109889|9627682|6752|0.0%|8.1%|
[dm_tor](#dm_tor)|6492|6492|6492|100.0%|7.8%|
[bm_tor](#bm_tor)|6492|6492|6492|100.0%|7.8%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|6196|6.5%|7.4%|
[et_tor](#et_tor)|6400|6400|5755|89.9%|6.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|3447|0.0%|4.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|2898|0.0%|3.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|2878|0.0%|3.4%|
[ri_connect_proxies](#ri_connect_proxies)|2811|2811|2811|100.0%|3.3%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|2750|9.4%|3.3%|
[xroxy](#xroxy)|2165|2165|2165|100.0%|2.6%|
[proxyrss](#proxyrss)|1373|1373|1373|100.0%|1.6%|
[firehol_level2](#firehol_level2)|21681|33301|1346|4.0%|1.6%|
[proxz](#proxz)|1297|1297|1297|100.0%|1.5%|
[snort_ipfilter](#snort_ipfilter)|9945|9945|1224|12.3%|1.4%|
[tor_exits](#tor_exits)|1121|1121|1121|100.0%|1.3%|
[stopforumspam_1d](#stopforumspam_1d)|6710|6710|987|14.7%|1.1%|
[blocklist_de](#blocklist_de)|28020|28020|665|2.3%|0.8%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|663|100.0%|0.7%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|524|100.0%|0.6%|
[blocklist_de_bots](#blocklist_de_bots)|2921|2921|509|17.4%|0.6%|
[sorbs_spam](#sorbs_spam)|64701|65536|201|0.3%|0.2%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|201|0.3%|0.2%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|201|0.3%|0.2%|
[nixspam](#nixspam)|25075|25075|183|0.7%|0.2%|
[blocklist_de_mail](#blocklist_de_mail)|17167|17167|126|0.7%|0.1%|
[php_dictionary](#php_dictionary)|737|737|98|13.2%|0.1%|
[php_spammers](#php_spammers)|735|735|81|11.0%|0.0%|
[php_commenters](#php_commenters)|430|430|81|18.8%|0.0%|
[voipbl](#voipbl)|10586|10998|79|0.7%|0.0%|
[alienvault_reputation](#alienvault_reputation)|188722|188722|57|0.0%|0.0%|
[dragon_http](#dragon_http)|1029|270336|43|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|29|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14213|14213|26|0.1%|0.0%|
[sorbs_web](#sorbs_web)|531|532|25|4.6%|0.0%|
[openbl_60d](#openbl_60d)|6989|6989|23|0.3%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2845|2845|23|0.8%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|15|0.0%|0.0%|
[iw_spamlist](#iw_spamlist)|3795|3795|14|0.3%|0.0%|
[php_harvesters](#php_harvesters)|392|392|12|3.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|176|176|8|4.5%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|7|0.0%|0.0%|
[firehol_level1](#firehol_level1)|5136|688854491|7|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|6|0.0%|0.0%|
[et_block](#et_block)|1000|18344011|6|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|3|0.2%|0.0%|
[et_compromised](#et_compromised)|1721|1721|3|0.1%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1701|1701|3|0.1%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|1421|1421|3|0.2%|0.0%|
[sslbl](#sslbl)|371|371|1|0.2%|0.0%|
[shunlist](#shunlist)|1278|1278|1|0.0%|0.0%|
[openbl_30d](#openbl_30d)|2813|2813|1|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3301|3301|1|0.0%|0.0%|

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
[firehol_level3](#firehol_level3)|109889|9627682|7500199|77.9%|1.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|7498240|81.6%|1.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|4637857|3.3%|0.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|2570306|0.3%|0.3%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|487424|100.0%|0.0%|
[dshield](#dshield)|20|5120|5120|100.0%|0.0%|
[alienvault_reputation](#alienvault_reputation)|188722|188722|3321|1.7%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1932|0.5%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|1090|1.1%|0.0%|
[dragon_http](#dragon_http)|1029|270336|1025|0.3%|0.0%|
[sslbl](#sslbl)|371|371|371|100.0%|0.0%|
[voipbl](#voipbl)|10586|10998|333|3.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9945|9945|299|3.0%|0.0%|
[openbl_60d](#openbl_60d)|6989|6989|284|4.0%|0.0%|
[firehol_level2](#firehol_level2)|21681|33301|282|0.8%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|278|0.9%|0.0%|
[zeus](#zeus)|230|230|230|100.0%|0.0%|
[blocklist_de](#blocklist_de)|28020|28020|217|0.7%|0.0%|
[zeus_badips](#zeus_badips)|202|202|202|100.0%|0.0%|
[shunlist](#shunlist)|1278|1278|176|13.7%|0.0%|
[openbl_30d](#openbl_30d)|2813|2813|155|5.5%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3301|3301|129|3.9%|0.0%|
[et_compromised](#et_compromised)|1721|1721|108|6.2%|0.0%|
[feodo](#feodo)|105|105|105|100.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6710|6710|82|1.2%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1701|1701|68|3.9%|0.0%|
[nixspam](#nixspam)|25075|25075|58|0.2%|0.0%|
[openbl_7d](#openbl_7d)|641|641|56|8.7%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|2921|2921|54|1.8%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|39|3.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|39|2.6%|0.0%|
[php_commenters](#php_commenters)|430|430|38|8.8%|0.0%|
[sorbs_spam](#sorbs_spam)|64701|65536|25|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|25|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|25|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|17167|17167|21|0.1%|0.0%|
[openbl_1d](#openbl_1d)|136|136|18|13.2%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|18|0.0%|0.0%|
[palevo](#palevo)|12|12|12|100.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|176|176|11|6.2%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14213|14213|11|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2801|2801|10|0.3%|0.0%|
[iw_spamlist](#iw_spamlist)|3795|3795|9|0.2%|0.0%|
[nt_malware_http](#nt_malware_http)|69|69|8|11.5%|0.0%|
[malc0de](#malc0de)|276|276|7|2.5%|0.0%|
[firehol_anonymous](#firehol_anonymous)|18973|83011|7|0.0%|0.0%|
[php_dictionary](#php_dictionary)|737|737|6|0.8%|0.0%|
[php_spammers](#php_spammers)|735|735|4|0.5%|0.0%|
[firehol_proxies](#firehol_proxies)|12374|12641|4|0.0%|0.0%|
[ciarmy](#ciarmy)|457|457|4|0.8%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2845|2845|4|0.1%|0.0%|
[php_harvesters](#php_harvesters)|392|392|3|0.7%|0.0%|
[nt_malware_irc](#nt_malware_irc)|43|43|3|6.9%|0.0%|
[et_tor](#et_tor)|6400|6400|3|0.0%|0.0%|
[dm_tor](#dm_tor)|6492|6492|3|0.0%|0.0%|
[bm_tor](#bm_tor)|6492|6492|3|0.0%|0.0%|
[tor_exits](#tor_exits)|1121|1121|2|0.1%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|2|0.3%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|85|85|2|2.3%|0.0%|
[virbl](#virbl)|25|25|1|4.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7800|7800|1|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|1|0.1%|0.0%|
[et_botcc](#et_botcc)|506|506|1|0.1%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|115|115|1|0.8%|0.0%|

## firehol_level2

**FireHOL Level 2** - Maximum protection from attacks took place in the last 48 hours. (includes: openbl_1d blocklist_de stopforumspam_1d)

Source is downloaded from [this link]().

The last time downloaded was found to be dated: Sun Jun  7 22:20:34 UTC 2015.

The ipset `firehol_level2` has **21681** entries, **33301** unique IPs.

The following table shows the overlaps of `firehol_level2` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `firehol_level2`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `firehol_level2`.
- ` this % ` is the percentage **of this ipset (`firehol_level2`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|28020|28020|28020|100.0%|84.1%|
[blocklist_de_mail](#blocklist_de_mail)|17167|17167|17165|99.9%|51.5%|
[blocklist_de_apache](#blocklist_de_apache)|14213|14213|14213|100.0%|42.6%|
[firehol_level3](#firehol_level3)|109889|9627682|8914|0.0%|26.7%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|7735|8.2%|23.2%|
[stopforumspam_1d](#stopforumspam_1d)|6710|6710|6710|100.0%|20.1%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|5858|20.0%|17.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|3962|0.0%|11.8%|
[blocklist_de_ssh](#blocklist_de_ssh)|3301|3301|3299|99.9%|9.9%|
[blocklist_de_bots](#blocklist_de_bots)|2921|2921|2915|99.7%|8.7%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2845|2845|2845|100.0%|8.5%|
[blocklist_de_imap](#blocklist_de_imap)|2801|2801|2799|99.9%|8.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|1709|0.0%|5.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|1691|0.0%|5.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|1421|1421|1421|100.0%|4.2%|
[sorbs_spam](#sorbs_spam)|64701|65536|1360|2.0%|4.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|1354|2.0%|4.0%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|1354|2.0%|4.0%|
[firehol_anonymous](#firehol_anonymous)|18973|83011|1346|1.6%|4.0%|
[alienvault_reputation](#alienvault_reputation)|188722|188722|1301|0.6%|3.9%|
[firehol_proxies](#firehol_proxies)|12374|12641|1174|9.2%|3.5%|
[openbl_60d](#openbl_60d)|6989|6989|913|13.0%|2.7%|
[nixspam](#nixspam)|25075|25075|756|3.0%|2.2%|
[openbl_30d](#openbl_30d)|2813|2813|717|25.4%|2.1%|
[ri_web_proxies](#ri_web_proxies)|7800|7800|678|8.6%|2.0%|
[bruteforceblocker](#bruteforceblocker)|1701|1701|592|34.8%|1.7%|
[et_compromised](#et_compromised)|1721|1721|583|33.8%|1.7%|
[snort_ipfilter](#snort_ipfilter)|9945|9945|557|5.6%|1.6%|
[shunlist](#shunlist)|1278|1278|405|31.6%|1.2%|
[openbl_7d](#openbl_7d)|641|641|401|62.5%|1.2%|
[proxyrss](#proxyrss)|1373|1373|365|26.5%|1.0%|
[tor_exits](#tor_exits)|1121|1121|360|32.1%|1.0%|
[et_tor](#et_tor)|6400|6400|344|5.3%|1.0%|
[bm_tor](#bm_tor)|6492|6492|341|5.2%|1.0%|
[dm_tor](#dm_tor)|6492|6492|340|5.2%|1.0%|
[xroxy](#xroxy)|2165|2165|327|15.1%|0.9%|
[et_block](#et_block)|1000|18344011|286|0.0%|0.8%|
[firehol_level1](#firehol_level1)|5136|688854491|282|0.0%|0.8%|
[proxz](#proxz)|1297|1297|280|21.5%|0.8%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|260|0.0%|0.7%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|215|41.0%|0.6%|
[php_commenters](#php_commenters)|430|430|189|43.9%|0.5%|
[blocklist_de_strongips](#blocklist_de_strongips)|176|176|176|100.0%|0.5%|
[ri_connect_proxies](#ri_connect_proxies)|2811|2811|151|5.3%|0.4%|
[openbl_1d](#openbl_1d)|136|136|136|100.0%|0.4%|
[php_dictionary](#php_dictionary)|737|737|127|17.2%|0.3%|
[iw_spamlist](#iw_spamlist)|3795|3795|125|3.2%|0.3%|
[dshield](#dshield)|20|5120|124|2.4%|0.3%|
[php_spammers](#php_spammers)|735|735|119|16.1%|0.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|84|0.0%|0.2%|
[blocklist_de_sip](#blocklist_de_sip)|85|85|66|77.6%|0.1%|
[sorbs_web](#sorbs_web)|531|532|63|11.8%|0.1%|
[dragon_http](#dragon_http)|1029|270336|63|0.0%|0.1%|
[php_harvesters](#php_harvesters)|392|392|59|15.0%|0.1%|
[voipbl](#voipbl)|10586|10998|46|0.4%|0.1%|
[ciarmy](#ciarmy)|457|457|38|8.3%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|17|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|14|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|8|1.2%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|6|0.0%|0.0%|
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

The ipset `firehol_level3` has **109889** entries, **9627682** unique IPs.

The following table shows the overlaps of `firehol_level3` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `firehol_level3`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `firehol_level3`.
- ` this % ` is the percentage **of this ipset (`firehol_level3`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|9177856|100.0%|95.3%|
[firehol_level1](#firehol_level1)|5136|688854491|7500199|1.0%|77.9%|
[et_block](#et_block)|1000|18344011|6933381|37.7%|72.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|6933040|37.8%|72.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|2537277|0.7%|26.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|919971|0.1%|9.5%|
[fullbogons](#fullbogons)|3775|670173256|566693|0.0%|5.8%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|339173|100.0%|3.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|161589|0.1%|1.6%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|94309|100.0%|0.9%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|29184|99.9%|0.3%|
[snort_ipfilter](#snort_ipfilter)|9945|9945|9945|100.0%|0.1%|
[firehol_level2](#firehol_level2)|21681|33301|8914|26.7%|0.0%|
[firehol_anonymous](#firehol_anonymous)|18973|83011|6752|8.1%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6710|6710|6372|94.9%|0.0%|
[firehol_proxies](#firehol_proxies)|12374|12641|5648|44.6%|0.0%|
[alienvault_reputation](#alienvault_reputation)|188722|188722|4886|2.5%|0.0%|
[blocklist_de](#blocklist_de)|28020|28020|3948|14.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7800|7800|3725|47.7%|0.0%|
[openbl_60d](#openbl_60d)|6989|6989|2941|42.0%|0.0%|
[openbl_30d](#openbl_30d)|2813|2813|2813|100.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|2921|2921|2447|83.7%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1701|1701|1701|100.0%|0.0%|
[et_compromised](#et_compromised)|1721|1721|1695|98.4%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2811|2811|1584|56.3%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|1450|100.0%|0.0%|
[sorbs_spam](#sorbs_spam)|64701|65536|1303|1.9%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|1301|1.9%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|1301|1.9%|0.0%|
[xroxy](#xroxy)|2165|2165|1299|60.0%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|1288|100.0%|0.0%|
[shunlist](#shunlist)|1278|1278|1278|100.0%|0.0%|
[et_tor](#et_tor)|6400|6400|1125|17.5%|0.0%|
[bm_tor](#bm_tor)|6492|6492|1086|16.7%|0.0%|
[dm_tor](#dm_tor)|6492|6492|1078|16.6%|0.0%|
[tor_exits](#tor_exits)|1121|1121|1067|95.1%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3301|3301|914|27.6%|0.0%|
[proxz](#proxz)|1297|1297|772|59.5%|0.0%|
[php_dictionary](#php_dictionary)|737|737|737|100.0%|0.0%|
[php_spammers](#php_spammers)|735|735|735|100.0%|0.0%|
[proxyrss](#proxyrss)|1373|1373|683|49.7%|0.0%|
[openbl_7d](#openbl_7d)|641|641|641|100.0%|0.0%|
[dragon_http](#dragon_http)|1029|270336|557|0.2%|0.0%|
[nixspam](#nixspam)|25075|25075|488|1.9%|0.0%|
[ciarmy](#ciarmy)|457|457|457|100.0%|0.0%|
[php_commenters](#php_commenters)|430|430|430|100.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|17167|17167|406|2.3%|0.0%|
[php_harvesters](#php_harvesters)|392|392|392|100.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|346|66.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14213|14213|290|2.0%|0.0%|
[malc0de](#malc0de)|276|276|276|100.0%|0.0%|
[zeus](#zeus)|230|230|203|88.2%|0.0%|
[zeus_badips](#zeus_badips)|202|202|180|89.1%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|176|176|162|92.0%|0.0%|
[dshield](#dshield)|20|5120|157|3.0%|0.0%|
[openbl_1d](#openbl_1d)|136|136|134|98.5%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|115|115|115|100.0%|0.0%|
[iw_spamlist](#iw_spamlist)|3795|3795|94|2.4%|0.0%|
[sslbl](#sslbl)|371|371|92|24.7%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2845|2845|91|3.1%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|85|0.0%|0.0%|
[feodo](#feodo)|105|105|83|79.0%|0.0%|
[sorbs_web](#sorbs_web)|531|532|65|12.2%|0.0%|
[voipbl](#voipbl)|10586|10998|58|0.5%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2801|2801|37|1.3%|0.0%|
[iw_wormlist](#iw_wormlist)|33|33|33|100.0%|0.0%|
[virbl](#virbl)|25|25|25|100.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|25|3.7%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|25|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|1421|1421|24|1.6%|0.0%|
[palevo](#palevo)|12|12|10|83.3%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|85|85|4|4.7%|0.0%|
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
[firehol_anonymous](#firehol_anonymous)|18973|83011|12641|15.2%|100.0%|
[ri_web_proxies](#ri_web_proxies)|7800|7800|7800|100.0%|61.7%|
[firehol_level3](#firehol_level3)|109889|9627682|5648|0.0%|44.6%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|5587|5.9%|44.1%|
[ri_connect_proxies](#ri_connect_proxies)|2811|2811|2811|100.0%|22.2%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|2379|8.1%|18.8%|
[xroxy](#xroxy)|2165|2165|2165|100.0%|17.1%|
[proxyrss](#proxyrss)|1373|1373|1373|100.0%|10.8%|
[proxz](#proxz)|1297|1297|1297|100.0%|10.2%|
[firehol_level2](#firehol_level2)|21681|33301|1174|3.5%|9.2%|
[stopforumspam_1d](#stopforumspam_1d)|6710|6710|831|12.3%|6.5%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|663|100.0%|5.2%|
[blocklist_de](#blocklist_de)|28020|28020|637|2.2%|5.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|526|0.0%|4.1%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|524|100.0%|4.1%|
[blocklist_de_bots](#blocklist_de_bots)|2921|2921|507|17.3%|4.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|394|0.0%|3.1%|
[snort_ipfilter](#snort_ipfilter)|9945|9945|325|3.2%|2.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|295|0.0%|2.3%|
[et_tor](#et_tor)|6400|6400|238|3.7%|1.8%|
[dm_tor](#dm_tor)|6492|6492|237|3.6%|1.8%|
[bm_tor](#bm_tor)|6492|6492|237|3.6%|1.8%|
[tor_exits](#tor_exits)|1121|1121|231|20.6%|1.8%|
[sorbs_spam](#sorbs_spam)|64701|65536|196|0.2%|1.5%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|196|0.3%|1.5%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|196|0.3%|1.5%|
[nixspam](#nixspam)|25075|25075|176|0.7%|1.3%|
[blocklist_de_mail](#blocklist_de_mail)|17167|17167|124|0.7%|0.9%|
[php_dictionary](#php_dictionary)|737|737|97|13.1%|0.7%|
[php_spammers](#php_spammers)|735|735|79|10.7%|0.6%|
[php_commenters](#php_commenters)|430|430|79|18.3%|0.6%|
[alienvault_reputation](#alienvault_reputation)|188722|188722|38|0.0%|0.3%|
[dragon_http](#dragon_http)|1029|270336|30|0.0%|0.2%|
[sorbs_web](#sorbs_web)|531|532|25|4.6%|0.1%|
[openbl_60d](#openbl_60d)|6989|6989|20|0.2%|0.1%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|15|0.0%|0.1%|
[iw_spamlist](#iw_spamlist)|3795|3795|13|0.3%|0.1%|
[php_harvesters](#php_harvesters)|392|392|12|3.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|11|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|176|176|8|4.5%|0.0%|
[firehol_level1](#firehol_level1)|5136|688854491|4|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|3|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|3|0.2%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|0.0%|
[et_compromised](#et_compromised)|1721|1721|3|0.1%|0.0%|
[et_block](#et_block)|1000|18344011|3|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1701|1701|3|0.1%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14213|14213|3|0.0%|0.0%|
[voipbl](#voipbl)|10586|10998|2|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2845|2845|2|0.0%|0.0%|
[sslbl](#sslbl)|371|371|1|0.2%|0.0%|
[shunlist](#shunlist)|1278|1278|1|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3301|3301|1|0.0%|0.0%|

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
[firehol_level3](#firehol_level3)|109889|9627682|566693|5.8%|0.0%|
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
[iw_spamlist](#iw_spamlist)|3795|3795|5|0.1%|0.0%|
[nt_malware_http](#nt_malware_http)|69|69|4|5.7%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|2|0.0%|0.0%|
[virbl](#virbl)|25|25|1|4.0%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|1|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6710|6710|1|0.0%|0.0%|
[php_harvesters](#php_harvesters)|392|392|1|0.2%|0.0%|
[php_commenters](#php_commenters)|430|430|1|0.2%|0.0%|
[firehol_level2](#firehol_level2)|21681|33301|1|0.0%|0.0%|
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
[firehol_level3](#firehol_level3)|109889|9627682|25|0.0%|0.0%|
[firehol_level1](#firehol_level1)|5136|688854491|18|0.0%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|17|0.0%|0.0%|
[sorbs_spam](#sorbs_spam)|64701|65536|17|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|17|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|17|0.0%|0.0%|
[firehol_proxies](#firehol_proxies)|12374|12641|15|0.1%|0.0%|
[firehol_anonymous](#firehol_anonymous)|18973|83011|15|0.0%|0.0%|
[alienvault_reputation](#alienvault_reputation)|188722|188722|15|0.0%|0.0%|
[firehol_level2](#firehol_level2)|21681|33301|14|0.0%|0.0%|
[fullbogons](#fullbogons)|3775|670173256|13|0.0%|0.0%|
[blocklist_de](#blocklist_de)|28020|28020|13|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|11|1.6%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|17167|17167|8|0.0%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|7|0.0%|0.0%|
[nixspam](#nixspam)|25075|25075|6|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|5|0.0%|0.0%|
[et_block](#et_block)|1000|18344011|5|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7800|7800|4|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2801|2801|4|0.1%|0.0%|
[xroxy](#xroxy)|2165|2165|3|0.1%|0.0%|
[php_dictionary](#php_dictionary)|737|737|3|0.4%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|3|0.0%|0.0%|
[voipbl](#voipbl)|10586|10998|2|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9945|9945|2|0.0%|0.0%|
[php_harvesters](#php_harvesters)|392|392|2|0.5%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2845|2845|2|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14213|14213|2|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6710|6710|1|0.0%|0.0%|
[sorbs_web](#sorbs_web)|531|532|1|0.1%|0.0%|
[proxz](#proxz)|1297|1297|1|0.0%|0.0%|
[php_spammers](#php_spammers)|735|735|1|0.1%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|1|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3301|3301|1|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|1421|1421|1|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|2921|2921|1|0.0%|0.0%|

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
[firehol_level3](#firehol_level3)|109889|9627682|9177856|95.3%|100.0%|
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
[firehol_level2](#firehol_level2)|21681|33301|84|0.2%|0.0%|
[nixspam](#nixspam)|25075|25075|59|0.2%|0.0%|
[blocklist_de](#blocklist_de)|28020|28020|59|0.2%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|2921|2921|47|1.6%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6710|6710|31|0.4%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|27|2.0%|0.0%|
[openbl_60d](#openbl_60d)|6989|6989|16|0.2%|0.0%|
[openbl_30d](#openbl_30d)|2813|2813|12|0.4%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9945|9945|11|0.1%|0.0%|
[zeus_badips](#zeus_badips)|202|202|10|4.9%|0.0%|
[zeus](#zeus)|230|230|10|4.3%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|7|0.4%|0.0%|
[firehol_anonymous](#firehol_anonymous)|18973|83011|7|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3301|3301|6|0.1%|0.0%|
[et_compromised](#et_compromised)|1721|1721|5|0.2%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1701|1701|5|0.2%|0.0%|
[php_dictionary](#php_dictionary)|737|737|4|0.5%|0.0%|
[openbl_7d](#openbl_7d)|641|641|4|0.6%|0.0%|
[iw_spamlist](#iw_spamlist)|3795|3795|4|0.1%|0.0%|
[et_tor](#et_tor)|6400|6400|4|0.0%|0.0%|
[dm_tor](#dm_tor)|6492|6492|4|0.0%|0.0%|
[bm_tor](#bm_tor)|6492|6492|4|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|17167|17167|4|0.0%|0.0%|
[shunlist](#shunlist)|1278|1278|3|0.2%|0.0%|
[php_spammers](#php_spammers)|735|735|3|0.4%|0.0%|
[nt_malware_http](#nt_malware_http)|69|69|3|4.3%|0.0%|
[firehol_proxies](#firehol_proxies)|12374|12641|3|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|176|176|3|1.7%|0.0%|
[tor_exits](#tor_exits)|1121|1121|2|0.1%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|2|0.3%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2801|2801|2|0.0%|0.0%|
[voipbl](#voipbl)|10586|10998|1|0.0%|0.0%|
[sorbs_spam](#sorbs_spam)|64701|65536|1|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|1|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|1|0.0%|0.0%|
[php_harvesters](#php_harvesters)|392|392|1|0.2%|0.0%|
[php_commenters](#php_commenters)|430|430|1|0.2%|0.0%|
[openbl_1d](#openbl_1d)|136|136|1|0.7%|0.0%|
[nt_malware_irc](#nt_malware_irc)|43|43|1|2.3%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|1|0.1%|0.0%|
[et_botcc](#et_botcc)|506|506|1|0.1%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|1421|1421|1|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2845|2845|1|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14213|14213|1|0.0%|0.0%|

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
[firehol_level3](#firehol_level3)|109889|9627682|919971|9.5%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|904796|9.8%|0.1%|
[fullbogons](#fullbogons)|3775|670173256|264873|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|33155|6.8%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|13247|3.9%|0.0%|
[dragon_http](#dragon_http)|1029|270336|6284|2.3%|0.0%|
[alienvault_reputation](#alienvault_reputation)|188722|188722|4448|2.3%|0.0%|
[firehol_anonymous](#firehol_anonymous)|18973|83011|3447|4.1%|0.0%|
[firehol_level2](#firehol_level2)|21681|33301|1709|5.1%|0.0%|
[blocklist_de](#blocklist_de)|28020|28020|1592|5.6%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|1522|1.6%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|17167|17167|1423|8.2%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14213|14213|1322|9.3%|0.0%|
[sorbs_spam](#sorbs_spam)|64701|65536|1208|1.8%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|1205|1.8%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|1205|1.8%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|506|1.7%|0.0%|
[nixspam](#nixspam)|25075|25075|478|1.9%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|394|0.8%|0.0%|
[voipbl](#voipbl)|10586|10998|302|2.7%|0.0%|
[firehol_proxies](#firehol_proxies)|12374|12641|295|2.3%|0.0%|
[dm_tor](#dm_tor)|6492|6492|168|2.5%|0.0%|
[bm_tor](#bm_tor)|6492|6492|167|2.5%|0.0%|
[et_tor](#et_tor)|6400|6400|165|2.5%|0.0%|
[openbl_60d](#openbl_60d)|6989|6989|163|2.3%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7800|7800|156|2.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6710|6710|143|2.1%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9945|9945|114|1.1%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|97|6.6%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2811|2811|86|3.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2801|2801|72|2.5%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|66|5.1%|0.0%|
[openbl_30d](#openbl_30d)|2813|2813|65|2.3%|0.0%|
[iw_spamlist](#iw_spamlist)|3795|3795|65|1.7%|0.0%|
[xroxy](#xroxy)|2165|2165|58|2.6%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|56|8.4%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3301|3301|56|1.6%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1701|1701|54|3.1%|0.0%|
[et_compromised](#et_compromised)|1721|1721|52|3.0%|0.0%|
[proxz](#proxz)|1297|1297|44|3.3%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|2921|2921|44|1.5%|0.0%|
[et_botcc](#et_botcc)|506|506|40|7.9%|0.0%|
[ciarmy](#ciarmy)|457|457|37|8.0%|0.0%|
[tor_exits](#tor_exits)|1121|1121|36|3.2%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2845|2845|34|1.1%|0.0%|
[proxyrss](#proxyrss)|1373|1373|30|2.1%|0.0%|
[shunlist](#shunlist)|1278|1278|27|2.1%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|1421|1421|24|1.6%|0.0%|
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
[blocklist_de_sip](#blocklist_de_sip)|85|85|5|5.8%|0.0%|
[zeus_badips](#zeus_badips)|202|202|4|1.9%|0.0%|
[openbl_1d](#openbl_1d)|136|136|4|2.9%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|115|115|4|3.4%|0.0%|
[sslbl](#sslbl)|371|371|3|0.8%|0.0%|
[feodo](#feodo)|105|105|3|2.8%|0.0%|
[iw_wormlist](#iw_wormlist)|33|33|1|3.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|176|176|1|0.5%|0.0%|

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
[firehol_level3](#firehol_level3)|109889|9627682|2537277|26.3%|0.7%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2526625|27.5%|0.7%|
[fullbogons](#fullbogons)|3775|670173256|252671|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|98904|20.2%|0.0%|
[dragon_http](#dragon_http)|1029|270336|11960|4.4%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|7728|2.2%|0.0%|
[alienvault_reputation](#alienvault_reputation)|188722|188722|7000|3.7%|0.0%|
[firehol_anonymous](#firehol_anonymous)|18973|83011|2898|3.4%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|2476|2.6%|0.0%|
[sorbs_spam](#sorbs_spam)|64701|65536|1740|2.6%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|1736|2.6%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|1736|2.6%|0.0%|
[firehol_level2](#firehol_level2)|21681|33301|1691|5.0%|0.0%|
[blocklist_de](#blocklist_de)|28020|28020|1555|5.5%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|17167|17167|1266|7.3%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14213|14213|1092|7.6%|0.0%|
[nixspam](#nixspam)|25075|25075|779|3.1%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|768|2.6%|0.0%|
[voipbl](#voipbl)|10586|10998|436|3.9%|0.0%|
[firehol_proxies](#firehol_proxies)|12374|12641|394|3.1%|0.0%|
[openbl_60d](#openbl_60d)|6989|6989|319|4.5%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|226|0.4%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7800|7800|223|2.8%|0.0%|
[dm_tor](#dm_tor)|6492|6492|184|2.8%|0.0%|
[bm_tor](#bm_tor)|6492|6492|184|2.8%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6710|6710|182|2.7%|0.0%|
[et_tor](#et_tor)|6400|6400|181|2.8%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9945|9945|147|1.4%|0.0%|
[openbl_30d](#openbl_30d)|2813|2813|146|5.1%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3301|3301|124|3.7%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2811|2811|106|3.7%|0.0%|
[xroxy](#xroxy)|2165|2165|104|4.8%|0.0%|
[iw_spamlist](#iw_spamlist)|3795|3795|94|2.4%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1701|1701|88|5.1%|0.0%|
[et_compromised](#et_compromised)|1721|1721|85|4.9%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|2921|2921|74|2.5%|0.0%|
[shunlist](#shunlist)|1278|1278|73|5.7%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2801|2801|70|2.4%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2845|2845|59|2.0%|0.0%|
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
[blocklist_de_ftp](#blocklist_de_ftp)|1421|1421|20|1.4%|0.0%|
[sorbs_web](#sorbs_web)|531|532|19|3.5%|0.0%|
[php_commenters](#php_commenters)|430|430|18|4.1%|0.0%|
[malc0de](#malc0de)|276|276|16|5.7%|0.0%|
[zeus](#zeus)|230|230|9|3.9%|0.0%|
[php_harvesters](#php_harvesters)|392|392|9|2.2%|0.0%|
[zeus_badips](#zeus_badips)|202|202|8|3.9%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|176|176|8|4.5%|0.0%|
[openbl_1d](#openbl_1d)|136|136|7|5.1%|0.0%|
[sslbl](#sslbl)|371|371|6|1.6%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|115|115|6|5.2%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|85|85|5|5.8%|0.0%|
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
[firehol_level1](#firehol_level1)|5136|688854491|4637857|0.6%|3.3%|
[fullbogons](#fullbogons)|3775|670173256|4236143|0.6%|3.0%|
[bogons](#bogons)|13|592708608|4194304|0.7%|3.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|2830203|0.8%|2.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|1354507|0.1%|0.9%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|270785|55.5%|0.1%|
[firehol_level3](#firehol_level3)|109889|9627682|161589|1.6%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|145472|1.5%|0.1%|
[et_block](#et_block)|1000|18344011|130394|0.7%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|130368|0.7%|0.0%|
[dragon_http](#dragon_http)|1029|270336|20480|7.5%|0.0%|
[alienvault_reputation](#alienvault_reputation)|188722|188722|14338|7.5%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|9226|2.7%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|5830|6.1%|0.0%|
[firehol_level2](#firehol_level2)|21681|33301|3962|11.8%|0.0%|
[blocklist_de](#blocklist_de)|28020|28020|3547|12.6%|0.0%|
[firehol_anonymous](#firehol_anonymous)|18973|83011|2878|3.4%|0.0%|
[sorbs_spam](#sorbs_spam)|64701|65536|2860|4.3%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|2851|4.3%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|2851|4.3%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|17167|17167|2534|14.7%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14213|14213|2300|16.1%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|1953|6.6%|0.0%|
[nixspam](#nixspam)|25075|25075|1760|7.0%|0.0%|
[voipbl](#voipbl)|10586|10998|1613|14.6%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|1172|2.4%|0.0%|
[openbl_60d](#openbl_60d)|6989|6989|743|10.6%|0.0%|
[dm_tor](#dm_tor)|6492|6492|630|9.7%|0.0%|
[bm_tor](#bm_tor)|6492|6492|629|9.6%|0.0%|
[et_tor](#et_tor)|6400|6400|625|9.7%|0.0%|
[firehol_proxies](#firehol_proxies)|12374|12641|526|4.1%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6710|6710|517|7.7%|0.0%|
[dshield](#dshield)|20|5120|512|10.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3301|3301|495|14.9%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2801|2801|309|11.0%|0.0%|
[openbl_30d](#openbl_30d)|2813|2813|291|10.3%|0.0%|
[iw_spamlist](#iw_spamlist)|3795|3795|256|6.7%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9945|9945|241|2.4%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7800|7800|220|2.8%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2845|2845|210|7.3%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1701|1701|157|9.2%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|2921|2921|157|5.3%|0.0%|
[et_compromised](#et_compromised)|1721|1721|152|8.8%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|150|28.6%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|147|11.4%|0.0%|
[tor_exits](#tor_exits)|1121|1121|128|11.4%|0.0%|
[shunlist](#shunlist)|1278|1278|123|9.6%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|1421|1421|123|8.6%|0.0%|
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
[blocklist_de_strongips](#blocklist_de_strongips)|176|176|16|9.0%|0.0%|
[zeus](#zeus)|230|230|14|6.0%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|85|85|13|15.2%|0.0%|
[feodo](#feodo)|105|105|11|10.4%|0.0%|
[zeus_badips](#zeus_badips)|202|202|10|4.9%|0.0%|
[openbl_1d](#openbl_1d)|136|136|8|5.8%|0.0%|
[nt_malware_http](#nt_malware_http)|69|69|5|7.2%|0.0%|
[sorbs_socks](#sorbs_socks)|7|7|2|28.5%|0.0%|
[sorbs_misc](#sorbs_misc)|7|7|2|28.5%|0.0%|
[sorbs_http](#sorbs_http)|7|7|2|28.5%|0.0%|
[iw_wormlist](#iw_wormlist)|33|33|2|6.0%|0.0%|
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
[firehol_anonymous](#firehol_anonymous)|18973|83011|663|0.7%|100.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|56|0.0%|8.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|51|0.0%|7.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|26|0.0%|3.9%|
[firehol_level3](#firehol_level3)|109889|9627682|25|0.0%|3.7%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|20|0.0%|3.0%|
[ri_web_proxies](#ri_web_proxies)|7800|7800|15|0.1%|2.2%|
[xroxy](#xroxy)|2165|2165|13|0.6%|1.9%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|11|0.0%|1.6%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|11|0.0%|1.6%|
[proxyrss](#proxyrss)|1373|1373|10|0.7%|1.5%|
[firehol_level2](#firehol_level2)|21681|33301|8|0.0%|1.2%|
[ri_connect_proxies](#ri_connect_proxies)|2811|2811|7|0.2%|1.0%|
[proxz](#proxz)|1297|1297|6|0.4%|0.9%|
[stopforumspam_1d](#stopforumspam_1d)|6710|6710|5|0.0%|0.7%|
[blocklist_de](#blocklist_de)|28020|28020|4|0.0%|0.6%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|2|0.0%|0.3%|
[php_dictionary](#php_dictionary)|737|737|2|0.2%|0.3%|
[nixspam](#nixspam)|25075|25075|2|0.0%|0.3%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|2|0.1%|0.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2|0.0%|0.3%|
[firehol_level1](#firehol_level1)|5136|688854491|2|0.0%|0.3%|
[et_block](#et_block)|1000|18344011|2|0.0%|0.3%|
[blocklist_de_mail](#blocklist_de_mail)|17167|17167|2|0.0%|0.3%|
[blocklist_de_bots](#blocklist_de_bots)|2921|2921|2|0.0%|0.3%|
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
[firehol_level3](#firehol_level3)|109889|9627682|339173|3.5%|100.0%|
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
[firehol_anonymous](#firehol_anonymous)|18973|83011|29|0.0%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|27|2.0%|0.0%|
[et_tor](#et_tor)|6400|6400|22|0.3%|0.0%|
[dm_tor](#dm_tor)|6492|6492|22|0.3%|0.0%|
[bm_tor](#bm_tor)|6492|6492|22|0.3%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|20|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|19|1.3%|0.0%|
[nixspam](#nixspam)|25075|25075|17|0.0%|0.0%|
[firehol_level2](#firehol_level2)|21681|33301|17|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9945|9945|14|0.1%|0.0%|
[firehol_proxies](#firehol_proxies)|12374|12641|11|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6710|6710|10|0.1%|0.0%|
[tor_exits](#tor_exits)|1121|1121|8|0.7%|0.0%|
[blocklist_de](#blocklist_de)|28020|28020|7|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7800|7800|6|0.0%|0.0%|
[dragon_http](#dragon_http)|1029|270336|6|0.0%|0.0%|
[openbl_60d](#openbl_60d)|6989|6989|5|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|5|0.9%|0.0%|
[voipbl](#voipbl)|10586|10998|4|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14213|14213|4|0.0%|0.0%|
[openbl_30d](#openbl_30d)|2813|2813|3|0.1%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|3|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2845|2845|3|0.1%|0.0%|
[palevo](#palevo)|12|12|2|16.6%|0.0%|
[malc0de](#malc0de)|276|276|2|0.7%|0.0%|
[iw_spamlist](#iw_spamlist)|3795|3795|2|0.0%|0.0%|
[et_compromised](#et_compromised)|1721|1721|2|0.1%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1701|1701|2|0.1%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|85|85|2|2.3%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|17167|17167|2|0.0%|0.0%|
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
[blocklist_de_ssh](#blocklist_de_ssh)|3301|3301|1|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|2921|2921|1|0.0%|0.0%|

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
[firehol_level3](#firehol_level3)|109889|9627682|1450|0.0%|100.0%|
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
[firehol_level2](#firehol_level2)|21681|33301|3|0.0%|0.2%|
[firehol_anonymous](#firehol_anonymous)|18973|83011|3|0.0%|0.2%|
[dragon_http](#dragon_http)|1029|270336|3|0.0%|0.2%|
[blocklist_de](#blocklist_de)|28020|28020|3|0.0%|0.2%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|2|0.0%|0.1%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|2|0.0%|0.1%|
[stopforumspam_1d](#stopforumspam_1d)|6710|6710|2|0.0%|0.1%|
[sorbs_spam](#sorbs_spam)|64701|65536|2|0.0%|0.1%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|2|0.0%|0.1%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|2|0.0%|0.1%|
[openbl_60d](#openbl_60d)|6989|6989|2|0.0%|0.1%|
[openbl_30d](#openbl_30d)|2813|2813|2|0.0%|0.1%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|2|0.3%|0.1%|
[blocklist_de_strongips](#blocklist_de_strongips)|176|176|2|1.1%|0.1%|
[blocklist_de_bots](#blocklist_de_bots)|2921|2921|2|0.0%|0.1%|
[snort_ipfilter](#snort_ipfilter)|9945|9945|1|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7800|7800|1|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|1|0.0%|0.0%|
[et_botcc](#et_botcc)|506|506|1|0.1%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3301|3301|1|0.0%|0.0%|

## iw_spamlist

[ImproWare Antispam](http://antispam.imp.ch/) IPs sending spam, in the last 3 days

Source is downloaded from [this link](http://antispam.imp.ch/spamlist).

The last time downloaded was found to be dated: Thu Jun 11 15:20:04 UTC 2015.

The ipset `iw_spamlist` has **3795** entries, **3795** unique IPs.

The following table shows the overlaps of `iw_spamlist` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `iw_spamlist`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `iw_spamlist`.
- ` this % ` is the percentage **of this ipset (`iw_spamlist`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[sorbs_spam](#sorbs_spam)|64701|65536|1210|1.8%|31.8%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|1205|1.8%|31.7%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|1205|1.8%|31.7%|
[nixspam](#nixspam)|25075|25075|726|2.8%|19.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|256|0.0%|6.7%|
[firehol_level2](#firehol_level2)|21681|33301|125|0.3%|3.2%|
[blocklist_de](#blocklist_de)|28020|28020|123|0.4%|3.2%|
[blocklist_de_mail](#blocklist_de_mail)|17167|17167|111|0.6%|2.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|94|0.0%|2.4%|
[firehol_level3](#firehol_level3)|109889|9627682|94|0.0%|2.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|65|0.0%|1.7%|
[snort_ipfilter](#snort_ipfilter)|9945|9945|55|0.5%|1.4%|
[sorbs_web](#sorbs_web)|531|532|23|4.3%|0.6%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|22|0.0%|0.5%|
[alienvault_reputation](#alienvault_reputation)|188722|188722|17|0.0%|0.4%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|14|0.0%|0.3%|
[firehol_anonymous](#firehol_anonymous)|18973|83011|14|0.0%|0.3%|
[iw_wormlist](#iw_wormlist)|33|33|13|39.3%|0.3%|
[firehol_proxies](#firehol_proxies)|12374|12641|13|0.1%|0.3%|
[ri_web_proxies](#ri_web_proxies)|7800|7800|11|0.1%|0.2%|
[php_spammers](#php_spammers)|735|735|9|1.2%|0.2%|
[php_dictionary](#php_dictionary)|737|737|9|1.2%|0.2%|
[firehol_level1](#firehol_level1)|5136|688854491|9|0.0%|0.2%|
[stopforumspam_1d](#stopforumspam_1d)|6710|6710|6|0.0%|0.1%|
[fullbogons](#fullbogons)|3775|670173256|5|0.0%|0.1%|
[bogons](#bogons)|13|592708608|5|0.0%|0.1%|
[blocklist_de_bots](#blocklist_de_bots)|2921|2921|5|0.1%|0.1%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|4|0.0%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|4|0.0%|0.1%|
[et_block](#et_block)|1000|18344011|4|0.0%|0.1%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2845|2845|4|0.1%|0.1%|
[blocklist_de_apache](#blocklist_de_apache)|14213|14213|4|0.0%|0.1%|
[php_commenters](#php_commenters)|430|430|3|0.6%|0.0%|
[dragon_http](#dragon_http)|1029|270336|3|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|1421|1421|3|0.2%|0.0%|
[xroxy](#xroxy)|2165|2165|2|0.0%|0.0%|
[php_harvesters](#php_harvesters)|392|392|2|0.5%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|2|0.0%|0.0%|
[tor_exits](#tor_exits)|1121|1121|1|0.0%|0.0%|
[sorbs_socks](#sorbs_socks)|7|7|1|14.2%|0.0%|
[sorbs_misc](#sorbs_misc)|7|7|1|14.2%|0.0%|
[sorbs_http](#sorbs_http)|7|7|1|14.2%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2811|2811|1|0.0%|0.0%|
[proxyrss](#proxyrss)|1373|1373|1|0.0%|0.0%|
[et_tor](#et_tor)|6400|6400|1|0.0%|0.0%|
[dm_tor](#dm_tor)|6492|6492|1|0.0%|0.0%|
[bm_tor](#bm_tor)|6492|6492|1|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2801|2801|1|0.0%|0.0%|

## iw_wormlist

[ImproWare Antispam](http://antispam.imp.ch/) IPs sending emails with viruses or worms, in the last 3 days

Source is downloaded from [this link](http://antispam.imp.ch/wormlist).

The last time downloaded was found to be dated: Thu Jun 11 15:20:04 UTC 2015.

The ipset `iw_wormlist` has **33** entries, **33** unique IPs.

The following table shows the overlaps of `iw_wormlist` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `iw_wormlist`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `iw_wormlist`.
- ` this % ` is the percentage **of this ipset (`iw_wormlist`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level3](#firehol_level3)|109889|9627682|33|0.0%|100.0%|
[iw_spamlist](#iw_spamlist)|3795|3795|13|0.3%|39.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|2|0.0%|6.0%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|1|0.0%|3.0%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|1|0.0%|3.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|1|0.0%|3.0%|
[firehol_level2](#firehol_level2)|21681|33301|1|0.0%|3.0%|
[blocklist_de_mail](#blocklist_de_mail)|17167|17167|1|0.0%|3.0%|
[blocklist_de](#blocklist_de)|28020|28020|1|0.0%|3.0%|

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
[firehol_level3](#firehol_level3)|109889|9627682|276|0.0%|100.0%|
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
[firehol_level3](#firehol_level3)|109889|9627682|1288|0.0%|100.0%|
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
[nixspam](#nixspam)|25075|25075|1|0.0%|0.0%|
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
[firehol_proxies](#firehol_proxies)|12374|12641|524|4.1%|100.0%|
[firehol_anonymous](#firehol_anonymous)|18973|83011|524|0.6%|100.0%|
[firehol_level3](#firehol_level3)|109889|9627682|346|0.0%|66.0%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|345|0.3%|65.8%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|286|0.9%|54.5%|
[snort_ipfilter](#snort_ipfilter)|9945|9945|237|2.3%|45.2%|
[et_tor](#et_tor)|6400|6400|234|3.6%|44.6%|
[dm_tor](#dm_tor)|6492|6492|232|3.5%|44.2%|
[bm_tor](#bm_tor)|6492|6492|232|3.5%|44.2%|
[tor_exits](#tor_exits)|1121|1121|231|20.6%|44.0%|
[firehol_level2](#firehol_level2)|21681|33301|215|0.6%|41.0%|
[stopforumspam_1d](#stopforumspam_1d)|6710|6710|214|3.1%|40.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|150|0.0%|28.6%|
[php_commenters](#php_commenters)|430|430|52|12.0%|9.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|29|0.0%|5.5%|
[alienvault_reputation](#alienvault_reputation)|188722|188722|29|0.0%|5.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|21|0.0%|4.0%|
[openbl_60d](#openbl_60d)|6989|6989|20|0.2%|3.8%|
[ri_web_proxies](#ri_web_proxies)|7800|7800|10|0.1%|1.9%|
[php_harvesters](#php_harvesters)|392|392|7|1.7%|1.3%|
[blocklist_de](#blocklist_de)|28020|28020|7|0.0%|1.3%|
[php_spammers](#php_spammers)|735|735|6|0.8%|1.1%|
[php_dictionary](#php_dictionary)|737|737|5|0.6%|0.9%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|5|0.0%|0.9%|
[blocklist_de_bots](#blocklist_de_bots)|2921|2921|5|0.1%|0.9%|
[dragon_http](#dragon_http)|1029|270336|4|0.0%|0.7%|
[xroxy](#xroxy)|2165|2165|3|0.1%|0.5%|
[voipbl](#voipbl)|10586|10998|2|0.0%|0.3%|
[proxz](#proxz)|1297|1297|2|0.1%|0.3%|
[nixspam](#nixspam)|25075|25075|2|0.0%|0.3%|
[blocklist_de_apache](#blocklist_de_apache)|14213|14213|2|0.0%|0.3%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|1|0.0%|0.1%|
[sorbs_spam](#sorbs_spam)|64701|65536|1|0.0%|0.1%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|1|0.0%|0.1%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|1|0.0%|0.1%|
[shunlist](#shunlist)|1278|1278|1|0.0%|0.1%|
[ri_connect_proxies](#ri_connect_proxies)|2811|2811|1|0.0%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.1%|
[firehol_level1](#firehol_level1)|5136|688854491|1|0.0%|0.1%|
[et_block](#et_block)|1000|18344011|1|0.0%|0.1%|
[blocklist_de_mail](#blocklist_de_mail)|17167|17167|1|0.0%|0.1%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2845|2845|1|0.0%|0.1%|

## nixspam

[NiX Spam](http://www.heise.de/ix/NiX-Spam-DNSBL-and-blacklist-for-download-499637.html) IP addresses that sent spam in the last hour - automatically generated entries without distinguishing open proxies from relays, dialup gateways, and so on. All IPs are removed after 12 hours if there is no spam from there.

Source is downloaded from [this link](http://www.dnsbl.manitu.net/download/nixspam-ip.dump.gz).

The last time downloaded was found to be dated: Thu Jun 11 15:45:01 UTC 2015.

The ipset `nixspam` has **25075** entries, **25075** unique IPs.

The following table shows the overlaps of `nixspam` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `nixspam`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `nixspam`.
- ` this % ` is the percentage **of this ipset (`nixspam`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[sorbs_spam](#sorbs_spam)|64701|65536|4713|7.1%|18.7%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|4605|7.0%|18.3%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|4605|7.0%|18.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|1760|0.0%|7.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|779|0.0%|3.1%|
[firehol_level2](#firehol_level2)|21681|33301|756|2.2%|3.0%|
[blocklist_de](#blocklist_de)|28020|28020|738|2.6%|2.9%|
[iw_spamlist](#iw_spamlist)|3795|3795|726|19.1%|2.8%|
[blocklist_de_mail](#blocklist_de_mail)|17167|17167|674|3.9%|2.6%|
[firehol_level3](#firehol_level3)|109889|9627682|488|0.0%|1.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|478|0.0%|1.9%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|246|0.2%|0.9%|
[snort_ipfilter](#snort_ipfilter)|9945|9945|189|1.9%|0.7%|
[firehol_anonymous](#firehol_anonymous)|18973|83011|183|0.2%|0.7%|
[firehol_proxies](#firehol_proxies)|12374|12641|176|1.3%|0.7%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|134|0.4%|0.5%|
[ri_web_proxies](#ri_web_proxies)|7800|7800|130|1.6%|0.5%|
[php_dictionary](#php_dictionary)|737|737|127|17.2%|0.5%|
[sorbs_web](#sorbs_web)|531|532|110|20.6%|0.4%|
[php_spammers](#php_spammers)|735|735|104|14.1%|0.4%|
[xroxy](#xroxy)|2165|2165|66|3.0%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|59|0.0%|0.2%|
[firehol_level1](#firehol_level1)|5136|688854491|58|0.0%|0.2%|
[et_block](#et_block)|1000|18344011|57|0.0%|0.2%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|56|0.0%|0.2%|
[stopforumspam_1d](#stopforumspam_1d)|6710|6710|54|0.8%|0.2%|
[alienvault_reputation](#alienvault_reputation)|188722|188722|48|0.0%|0.1%|
[proxz](#proxz)|1297|1297|44|3.3%|0.1%|
[blocklist_de_imap](#blocklist_de_imap)|2801|2801|43|1.5%|0.1%|
[dragon_http](#dragon_http)|1029|270336|28|0.0%|0.1%|
[blocklist_de_bots](#blocklist_de_bots)|2921|2921|27|0.9%|0.1%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2845|2845|23|0.8%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14213|14213|23|0.1%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2811|2811|18|0.6%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|17|0.0%|0.0%|
[php_commenters](#php_commenters)|430|430|12|2.7%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|1421|1421|12|0.8%|0.0%|
[proxyrss](#proxyrss)|1373|1373|10|0.7%|0.0%|
[php_harvesters](#php_harvesters)|392|392|10|2.5%|0.0%|
[tor_exits](#tor_exits)|1121|1121|8|0.7%|0.0%|
[openbl_60d](#openbl_60d)|6989|6989|7|0.1%|0.0%|
[dm_tor](#dm_tor)|6492|6492|7|0.1%|0.0%|
[bm_tor](#bm_tor)|6492|6492|7|0.1%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|6|0.0%|0.0%|
[et_tor](#et_tor)|6400|6400|6|0.0%|0.0%|
[sorbs_socks](#sorbs_socks)|7|7|5|71.4%|0.0%|
[sorbs_misc](#sorbs_misc)|7|7|5|71.4%|0.0%|
[sorbs_http](#sorbs_http)|7|7|5|71.4%|0.0%|
[openbl_30d](#openbl_30d)|2813|2813|4|0.1%|0.0%|
[voipbl](#voipbl)|10586|10998|2|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|2|0.3%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|2|0.3%|0.0%|
[zeus_badips](#zeus_badips)|202|202|1|0.4%|0.0%|
[zeus](#zeus)|230|230|1|0.4%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|1|0.0%|0.0%|
[sorbs_smtp](#sorbs_smtp)|5|5|1|20.0%|0.0%|
[openbl_7d](#openbl_7d)|641|641|1|0.1%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|1|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|176|176|1|0.5%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3301|3301|1|0.0%|0.0%|

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
[firehol_level3](#firehol_level3)|109889|9627682|3|0.0%|4.3%|
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
[firehol_level3](#firehol_level3)|109889|9627682|1|0.0%|2.3%|

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

The last time downloaded was found to be dated: Thu Jun 11 15:32:00 UTC 2015.

The ipset `openbl_1d` has **136** entries, **136** unique IPs.

The following table shows the overlaps of `openbl_1d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl_1d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl_1d`.
- ` this % ` is the percentage **of this ipset (`openbl_1d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|21681|33301|136|0.4%|100.0%|
[openbl_60d](#openbl_60d)|6989|6989|135|1.9%|99.2%|
[openbl_7d](#openbl_7d)|641|641|134|20.9%|98.5%|
[openbl_30d](#openbl_30d)|2813|2813|134|4.7%|98.5%|
[firehol_level3](#firehol_level3)|109889|9627682|134|0.0%|98.5%|
[alienvault_reputation](#alienvault_reputation)|188722|188722|132|0.0%|97.0%|
[blocklist_de](#blocklist_de)|28020|28020|122|0.4%|89.7%|
[blocklist_de_ssh](#blocklist_de_ssh)|3301|3301|118|3.5%|86.7%|
[bruteforceblocker](#bruteforceblocker)|1701|1701|75|4.4%|55.1%|
[et_compromised](#et_compromised)|1721|1721|73|4.2%|53.6%|
[shunlist](#shunlist)|1278|1278|71|5.5%|52.2%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|18|0.0%|13.2%|
[firehol_level1](#firehol_level1)|5136|688854491|18|0.0%|13.2%|
[et_block](#et_block)|1000|18344011|18|0.0%|13.2%|
[dshield](#dshield)|20|5120|17|0.3%|12.5%|
[blocklist_de_strongips](#blocklist_de_strongips)|176|176|17|9.6%|12.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|8|0.0%|5.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|7|0.0%|5.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|4|0.0%|2.9%|
[dragon_http](#dragon_http)|1029|270336|3|0.0%|2.2%|
[blocklist_de_mail](#blocklist_de_mail)|17167|17167|3|0.0%|2.2%|
[ciarmy](#ciarmy)|457|457|2|0.4%|1.4%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|1|0.0%|0.7%|
[php_spammers](#php_spammers)|735|735|1|0.1%|0.7%|
[php_commenters](#php_commenters)|430|430|1|0.2%|0.7%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.7%|
[blocklist_de_imap](#blocklist_de_imap)|2801|2801|1|0.0%|0.7%|
[blocklist_de_apache](#blocklist_de_apache)|14213|14213|1|0.0%|0.7%|

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
[firehol_level3](#firehol_level3)|109889|9627682|2813|0.0%|100.0%|
[alienvault_reputation](#alienvault_reputation)|188722|188722|2796|1.4%|99.3%|
[et_compromised](#et_compromised)|1721|1721|945|54.9%|33.5%|
[bruteforceblocker](#bruteforceblocker)|1701|1701|907|53.3%|32.2%|
[firehol_level2](#firehol_level2)|21681|33301|717|2.1%|25.4%|
[blocklist_de](#blocklist_de)|28020|28020|703|2.5%|24.9%|
[blocklist_de_ssh](#blocklist_de_ssh)|3301|3301|680|20.5%|24.1%|
[openbl_7d](#openbl_7d)|641|641|641|100.0%|22.7%|
[shunlist](#shunlist)|1278|1278|511|39.9%|18.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|291|0.0%|10.3%|
[et_block](#et_block)|1000|18344011|163|0.0%|5.7%|
[firehol_level1](#firehol_level1)|5136|688854491|155|0.0%|5.5%|
[dragon_http](#dragon_http)|1029|270336|148|0.0%|5.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|146|0.0%|5.1%|
[dshield](#dshield)|20|5120|136|2.6%|4.8%|
[openbl_1d](#openbl_1d)|136|136|134|98.5%|4.7%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|119|0.0%|4.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|65|0.0%|2.3%|
[blocklist_de_strongips](#blocklist_de_strongips)|176|176|24|13.6%|0.8%|
[blocklist_de_mail](#blocklist_de_mail)|17167|17167|15|0.0%|0.5%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|12|0.0%|0.4%|
[blocklist_de_imap](#blocklist_de_imap)|2801|2801|9|0.3%|0.3%|
[blocklist_de_apache](#blocklist_de_apache)|14213|14213|6|0.0%|0.2%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|5|0.0%|0.1%|
[nixspam](#nixspam)|25075|25075|4|0.0%|0.1%|
[voipbl](#voipbl)|10586|10998|3|0.0%|0.1%|
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
[firehol_anonymous](#firehol_anonymous)|18973|83011|1|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|1421|1421|1|0.0%|0.0%|

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
[firehol_level3](#firehol_level3)|109889|9627682|2941|0.0%|42.0%|
[openbl_30d](#openbl_30d)|2813|2813|2813|100.0%|40.2%|
[et_compromised](#et_compromised)|1721|1721|1014|58.9%|14.5%|
[bruteforceblocker](#bruteforceblocker)|1701|1701|968|56.9%|13.8%|
[firehol_level2](#firehol_level2)|21681|33301|913|2.7%|13.0%|
[blocklist_de](#blocklist_de)|28020|28020|880|3.1%|12.5%|
[blocklist_de_ssh](#blocklist_de_ssh)|3301|3301|847|25.6%|12.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|743|0.0%|10.6%|
[openbl_7d](#openbl_7d)|641|641|641|100.0%|9.1%|
[shunlist](#shunlist)|1278|1278|543|42.4%|7.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|319|0.0%|4.5%|
[et_block](#et_block)|1000|18344011|300|0.0%|4.2%|
[firehol_level1](#firehol_level1)|5136|688854491|284|0.0%|4.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|235|0.0%|3.3%|
[dragon_http](#dragon_http)|1029|270336|218|0.0%|3.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|163|0.0%|2.3%|
[dshield](#dshield)|20|5120|151|2.9%|2.1%|
[openbl_1d](#openbl_1d)|136|136|135|99.2%|1.9%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|47|0.0%|0.6%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|27|0.0%|0.3%|
[blocklist_de_strongips](#blocklist_de_strongips)|176|176|25|14.2%|0.3%|
[snort_ipfilter](#snort_ipfilter)|9945|9945|24|0.2%|0.3%|
[firehol_anonymous](#firehol_anonymous)|18973|83011|23|0.0%|0.3%|
[blocklist_de_mail](#blocklist_de_mail)|17167|17167|23|0.1%|0.3%|
[tor_exits](#tor_exits)|1121|1121|20|1.7%|0.2%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|20|3.8%|0.2%|
[firehol_proxies](#firehol_proxies)|12374|12641|20|0.1%|0.2%|
[et_tor](#et_tor)|6400|6400|20|0.3%|0.2%|
[dm_tor](#dm_tor)|6492|6492|20|0.3%|0.2%|
[bm_tor](#bm_tor)|6492|6492|20|0.3%|0.2%|
[stopforumspam_1d](#stopforumspam_1d)|6710|6710|19|0.2%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|16|0.0%|0.2%|
[blocklist_de_imap](#blocklist_de_imap)|2801|2801|16|0.5%|0.2%|
[php_commenters](#php_commenters)|430|430|11|2.5%|0.1%|
[voipbl](#voipbl)|10586|10998|8|0.0%|0.1%|
[nixspam](#nixspam)|25075|25075|7|0.0%|0.1%|
[blocklist_de_apache](#blocklist_de_apache)|14213|14213|7|0.0%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|5|0.0%|0.0%|
[ciarmy](#ciarmy)|457|457|3|0.6%|0.0%|
[zeus](#zeus)|230|230|2|0.8%|0.0%|
[sorbs_spam](#sorbs_spam)|64701|65536|2|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|2|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|2|0.0%|0.0%|
[php_harvesters](#php_harvesters)|392|392|2|0.5%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|2|0.1%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|1421|1421|2|0.1%|0.0%|
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
[firehol_level3](#firehol_level3)|109889|9627682|641|0.0%|100.0%|
[alienvault_reputation](#alienvault_reputation)|188722|188722|637|0.3%|99.3%|
[firehol_level2](#firehol_level2)|21681|33301|401|1.2%|62.5%|
[blocklist_de](#blocklist_de)|28020|28020|388|1.3%|60.5%|
[blocklist_de_ssh](#blocklist_de_ssh)|3301|3301|373|11.2%|58.1%|
[et_compromised](#et_compromised)|1721|1721|313|18.1%|48.8%|
[bruteforceblocker](#bruteforceblocker)|1701|1701|310|18.2%|48.3%|
[shunlist](#shunlist)|1278|1278|213|16.6%|33.2%|
[openbl_1d](#openbl_1d)|136|136|134|98.5%|20.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|66|0.0%|10.2%|
[et_block](#et_block)|1000|18344011|61|0.0%|9.5%|
[firehol_level1](#firehol_level1)|5136|688854491|56|0.0%|8.7%|
[dragon_http](#dragon_http)|1029|270336|54|0.0%|8.4%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|52|0.0%|8.1%|
[dshield](#dshield)|20|5120|50|0.9%|7.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|39|0.0%|6.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|176|176|23|13.0%|3.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|15|0.0%|2.3%|
[blocklist_de_mail](#blocklist_de_mail)|17167|17167|9|0.0%|1.4%|
[blocklist_de_imap](#blocklist_de_imap)|2801|2801|7|0.2%|1.0%|
[blocklist_de_apache](#blocklist_de_apache)|14213|14213|5|0.0%|0.7%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|4|0.0%|0.6%|
[ciarmy](#ciarmy)|457|457|3|0.6%|0.4%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|2|0.0%|0.3%|
[zeus_badips](#zeus_badips)|202|202|1|0.4%|0.1%|
[zeus](#zeus)|230|230|1|0.4%|0.1%|
[snort_ipfilter](#snort_ipfilter)|9945|9945|1|0.0%|0.1%|
[php_spammers](#php_spammers)|735|735|1|0.1%|0.1%|
[php_commenters](#php_commenters)|430|430|1|0.2%|0.1%|
[nixspam](#nixspam)|25075|25075|1|0.0%|0.1%|
[blocklist_de_ftp](#blocklist_de_ftp)|1421|1421|1|0.0%|0.1%|

## palevo

[Abuse.ch Palevo tracker](https://palevotracker.abuse.ch) worm includes IPs which are being used as botnet C&C for the Palevo crimeware - **excellent list**

Source is downloaded from [this link](https://palevotracker.abuse.ch/blocklists.php?download=ipblocklist).

The last time downloaded was found to be dated: Thu Jun 11 15:54:12 UTC 2015.

The ipset `palevo` has **12** entries, **12** unique IPs.

The following table shows the overlaps of `palevo` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `palevo`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `palevo`.
- ` this % ` is the percentage **of this ipset (`palevo`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level1](#firehol_level1)|5136|688854491|12|0.0%|100.0%|
[et_block](#et_block)|1000|18344011|12|0.0%|100.0%|
[snort_ipfilter](#snort_ipfilter)|9945|9945|10|0.1%|83.3%|
[firehol_level3](#firehol_level3)|109889|9627682|10|0.0%|83.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|3|0.0%|25.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|2|0.0%|16.6%|

## php_commenters

[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) comment spammers (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=c&rss=1).

The last time downloaded was found to be dated: Thu Jun 11 15:54:19 UTC 2015.

The ipset `php_commenters` has **430** entries, **430** unique IPs.

The following table shows the overlaps of `php_commenters` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `php_commenters`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `php_commenters`.
- ` this % ` is the percentage **of this ipset (`php_commenters`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level3](#firehol_level3)|109889|9627682|430|0.0%|100.0%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|321|0.3%|74.6%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|240|0.8%|55.8%|
[firehol_level2](#firehol_level2)|21681|33301|189|0.5%|43.9%|
[stopforumspam_1d](#stopforumspam_1d)|6710|6710|164|2.4%|38.1%|
[blocklist_de](#blocklist_de)|28020|28020|102|0.3%|23.7%|
[firehol_anonymous](#firehol_anonymous)|18973|83011|81|0.0%|18.8%|
[blocklist_de_bots](#blocklist_de_bots)|2921|2921|81|2.7%|18.8%|
[firehol_proxies](#firehol_proxies)|12374|12641|79|0.6%|18.3%|
[snort_ipfilter](#snort_ipfilter)|9945|9945|64|0.6%|14.8%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|52|9.9%|12.0%|
[tor_exits](#tor_exits)|1121|1121|51|4.5%|11.8%|
[et_tor](#et_tor)|6400|6400|51|0.7%|11.8%|
[dm_tor](#dm_tor)|6492|6492|51|0.7%|11.8%|
[bm_tor](#bm_tor)|6492|6492|51|0.7%|11.8%|
[php_spammers](#php_spammers)|735|735|50|6.8%|11.6%|
[blocklist_de_strongips](#blocklist_de_strongips)|176|176|45|25.5%|10.4%|
[firehol_level1](#firehol_level1)|5136|688854491|38|0.0%|8.8%|
[php_dictionary](#php_dictionary)|737|737|34|4.6%|7.9%|
[blocklist_de_apache](#blocklist_de_apache)|14213|14213|31|0.2%|7.2%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|29|0.0%|6.7%|
[et_block](#et_block)|1000|18344011|29|0.0%|6.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|28|0.0%|6.5%|
[blocklist_de_mail](#blocklist_de_mail)|17167|17167|27|0.1%|6.2%|
[ri_web_proxies](#ri_web_proxies)|7800|7800|25|0.3%|5.8%|
[sorbs_spam](#sorbs_spam)|64701|65536|22|0.0%|5.1%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|22|0.0%|5.1%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|22|0.0%|5.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|18|0.0%|4.1%|
[alienvault_reputation](#alienvault_reputation)|188722|188722|18|0.0%|4.1%|
[php_harvesters](#php_harvesters)|392|392|15|3.8%|3.4%|
[nixspam](#nixspam)|25075|25075|12|0.0%|2.7%|
[openbl_60d](#openbl_60d)|6989|6989|11|0.1%|2.5%|
[xroxy](#xroxy)|2165|2165|10|0.4%|2.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|10|0.0%|2.3%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2845|2845|10|0.3%|2.3%|
[proxz](#proxz)|1297|1297|9|0.6%|2.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|8|0.0%|1.8%|
[ri_connect_proxies](#ri_connect_proxies)|2811|2811|5|0.1%|1.1%|
[dragon_http](#dragon_http)|1029|270336|4|0.0%|0.9%|
[iw_spamlist](#iw_spamlist)|3795|3795|3|0.0%|0.6%|
[sorbs_web](#sorbs_web)|531|532|2|0.3%|0.4%|
[zeus_badips](#zeus_badips)|202|202|1|0.4%|0.2%|
[zeus](#zeus)|230|230|1|0.4%|0.2%|
[proxyrss](#proxyrss)|1373|1373|1|0.0%|0.2%|
[openbl_7d](#openbl_7d)|641|641|1|0.1%|0.2%|
[openbl_30d](#openbl_30d)|2813|2813|1|0.0%|0.2%|
[openbl_1d](#openbl_1d)|136|136|1|0.7%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.2%|
[fullbogons](#fullbogons)|3775|670173256|1|0.0%|0.2%|
[et_compromised](#et_compromised)|1721|1721|1|0.0%|0.2%|
[bruteforceblocker](#bruteforceblocker)|1701|1701|1|0.0%|0.2%|
[bogons](#bogons)|13|592708608|1|0.0%|0.2%|
[blocklist_de_ssh](#blocklist_de_ssh)|3301|3301|1|0.0%|0.2%|

## php_dictionary

[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) directory attackers (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=d&rss=1).

The last time downloaded was found to be dated: Thu Jun 11 15:54:20 UTC 2015.

The ipset `php_dictionary` has **737** entries, **737** unique IPs.

The following table shows the overlaps of `php_dictionary` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `php_dictionary`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `php_dictionary`.
- ` this % ` is the percentage **of this ipset (`php_dictionary`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level3](#firehol_level3)|109889|9627682|737|0.0%|100.0%|
[php_spammers](#php_spammers)|735|735|322|43.8%|43.6%|
[sorbs_spam](#sorbs_spam)|64701|65536|214|0.3%|29.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|214|0.3%|29.0%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|214|0.3%|29.0%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|139|0.1%|18.8%|
[nixspam](#nixspam)|25075|25075|127|0.5%|17.2%|
[firehol_level2](#firehol_level2)|21681|33301|127|0.3%|17.2%|
[blocklist_de](#blocklist_de)|28020|28020|122|0.4%|16.5%|
[blocklist_de_mail](#blocklist_de_mail)|17167|17167|102|0.5%|13.8%|
[firehol_anonymous](#firehol_anonymous)|18973|83011|98|0.1%|13.2%|
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
[blocklist_de_bots](#blocklist_de_bots)|2921|2921|15|0.5%|2.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|12|0.0%|1.6%|
[iw_spamlist](#iw_spamlist)|3795|3795|9|0.2%|1.2%|
[alienvault_reputation](#alienvault_reputation)|188722|188722|7|0.0%|0.9%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|6|0.0%|0.8%|
[firehol_level1](#firehol_level1)|5136|688854491|6|0.0%|0.8%|
[et_block](#et_block)|1000|18344011|6|0.0%|0.8%|
[ri_connect_proxies](#ri_connect_proxies)|2811|2811|5|0.1%|0.6%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|5|0.9%|0.6%|
[blocklist_de_strongips](#blocklist_de_strongips)|176|176|5|2.8%|0.6%|
[tor_exits](#tor_exits)|1121|1121|4|0.3%|0.5%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|4|0.0%|0.5%|
[et_tor](#et_tor)|6400|6400|4|0.0%|0.5%|
[dm_tor](#dm_tor)|6492|6492|4|0.0%|0.5%|
[bm_tor](#bm_tor)|6492|6492|4|0.0%|0.5%|
[php_harvesters](#php_harvesters)|392|392|3|0.7%|0.4%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|3|0.0%|0.4%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2845|2845|3|0.1%|0.4%|
[blocklist_de_apache](#blocklist_de_apache)|14213|14213|3|0.0%|0.4%|
[proxyrss](#proxyrss)|1373|1373|2|0.1%|0.2%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|2|0.3%|0.2%|
[dragon_http](#dragon_http)|1029|270336|2|0.0%|0.2%|
[sorbs_socks](#sorbs_socks)|7|7|1|14.2%|0.1%|
[sorbs_misc](#sorbs_misc)|7|7|1|14.2%|0.1%|
[sorbs_http](#sorbs_http)|7|7|1|14.2%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.1%|
[blocklist_de_ftp](#blocklist_de_ftp)|1421|1421|1|0.0%|0.1%|

## php_harvesters

[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) harvesters (IPs that surf the internet looking for email addresses) (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=h&rss=1).

The last time downloaded was found to be dated: Thu Jun 11 15:54:17 UTC 2015.

The ipset `php_harvesters` has **392** entries, **392** unique IPs.

The following table shows the overlaps of `php_harvesters` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `php_harvesters`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `php_harvesters`.
- ` this % ` is the percentage **of this ipset (`php_harvesters`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level3](#firehol_level3)|109889|9627682|392|0.0%|100.0%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|86|0.0%|21.9%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|61|0.2%|15.5%|
[firehol_level2](#firehol_level2)|21681|33301|59|0.1%|15.0%|
[stopforumspam_1d](#stopforumspam_1d)|6710|6710|44|0.6%|11.2%|
[blocklist_de](#blocklist_de)|28020|28020|40|0.1%|10.2%|
[blocklist_de_bots](#blocklist_de_bots)|2921|2921|28|0.9%|7.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|20|0.0%|5.1%|
[php_commenters](#php_commenters)|430|430|15|3.4%|3.8%|
[sorbs_spam](#sorbs_spam)|64701|65536|14|0.0%|3.5%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|14|0.0%|3.5%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|14|0.0%|3.5%|
[snort_ipfilter](#snort_ipfilter)|9945|9945|12|0.1%|3.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|12|0.0%|3.0%|
[firehol_proxies](#firehol_proxies)|12374|12641|12|0.0%|3.0%|
[firehol_anonymous](#firehol_anonymous)|18973|83011|12|0.0%|3.0%|
[alienvault_reputation](#alienvault_reputation)|188722|188722|12|0.0%|3.0%|
[nixspam](#nixspam)|25075|25075|10|0.0%|2.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|9|0.0%|2.2%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|7|1.3%|1.7%|
[et_tor](#et_tor)|6400|6400|7|0.1%|1.7%|
[dm_tor](#dm_tor)|6492|6492|7|0.1%|1.7%|
[bm_tor](#bm_tor)|6492|6492|7|0.1%|1.7%|
[tor_exits](#tor_exits)|1121|1121|6|0.5%|1.5%|
[blocklist_de_mail](#blocklist_de_mail)|17167|17167|6|0.0%|1.5%|
[blocklist_de_ftp](#blocklist_de_ftp)|1421|1421|4|0.2%|1.0%|
[php_spammers](#php_spammers)|735|735|3|0.4%|0.7%|
[php_dictionary](#php_dictionary)|737|737|3|0.4%|0.7%|
[firehol_level1](#firehol_level1)|5136|688854491|3|0.0%|0.7%|
[blocklist_de_strongips](#blocklist_de_strongips)|176|176|3|1.7%|0.7%|
[xroxy](#xroxy)|2165|2165|2|0.0%|0.5%|
[ri_web_proxies](#ri_web_proxies)|7800|7800|2|0.0%|0.5%|
[openbl_60d](#openbl_60d)|6989|6989|2|0.0%|0.5%|
[iw_spamlist](#iw_spamlist)|3795|3795|2|0.0%|0.5%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|2|0.0%|0.5%|
[blocklist_de_imap](#blocklist_de_imap)|2801|2801|2|0.0%|0.5%|
[blocklist_de_apache](#blocklist_de_apache)|14213|14213|2|0.0%|0.5%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|1|0.0%|0.2%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|1|0.0%|0.2%|
[ri_connect_proxies](#ri_connect_proxies)|2811|2811|1|0.0%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.2%|
[fullbogons](#fullbogons)|3775|670173256|1|0.0%|0.2%|
[et_block](#et_block)|1000|18344011|1|0.0%|0.2%|
[bogons](#bogons)|13|592708608|1|0.0%|0.2%|
[blocklist_de_ssh](#blocklist_de_ssh)|3301|3301|1|0.0%|0.2%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2845|2845|1|0.0%|0.2%|

## php_spammers

[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) spam servers (IPs used by spammers to send messages) (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=s&rss=1).

The last time downloaded was found to be dated: Thu Jun 11 15:54:18 UTC 2015.

The ipset `php_spammers` has **735** entries, **735** unique IPs.

The following table shows the overlaps of `php_spammers` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `php_spammers`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `php_spammers`.
- ` this % ` is the percentage **of this ipset (`php_spammers`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level3](#firehol_level3)|109889|9627682|735|0.0%|100.0%|
[php_dictionary](#php_dictionary)|737|737|322|43.6%|43.8%|
[sorbs_spam](#sorbs_spam)|64701|65536|184|0.2%|25.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|184|0.2%|25.0%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|184|0.2%|25.0%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|151|0.1%|20.5%|
[firehol_level2](#firehol_level2)|21681|33301|119|0.3%|16.1%|
[blocklist_de](#blocklist_de)|28020|28020|109|0.3%|14.8%|
[nixspam](#nixspam)|25075|25075|104|0.4%|14.1%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|95|0.3%|12.9%|
[firehol_anonymous](#firehol_anonymous)|18973|83011|81|0.0%|11.0%|
[snort_ipfilter](#snort_ipfilter)|9945|9945|80|0.8%|10.8%|
[firehol_proxies](#firehol_proxies)|12374|12641|79|0.6%|10.7%|
[blocklist_de_mail](#blocklist_de_mail)|17167|17167|79|0.4%|10.7%|
[ri_web_proxies](#ri_web_proxies)|7800|7800|54|0.6%|7.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|54|0.0%|7.3%|
[php_commenters](#php_commenters)|430|430|50|11.6%|6.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|44|0.0%|5.9%|
[stopforumspam_1d](#stopforumspam_1d)|6710|6710|41|0.6%|5.5%|
[xroxy](#xroxy)|2165|2165|34|1.5%|4.6%|
[sorbs_web](#sorbs_web)|531|532|25|4.6%|3.4%|
[proxz](#proxz)|1297|1297|22|1.6%|2.9%|
[blocklist_de_bots](#blocklist_de_bots)|2921|2921|21|0.7%|2.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|11|0.0%|1.4%|
[blocklist_de_strongips](#blocklist_de_strongips)|176|176|10|5.6%|1.3%|
[iw_spamlist](#iw_spamlist)|3795|3795|9|0.2%|1.2%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|6|1.1%|0.8%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2845|2845|6|0.2%|0.8%|
[blocklist_de_apache](#blocklist_de_apache)|14213|14213|6|0.0%|0.8%|
[tor_exits](#tor_exits)|1121|1121|5|0.4%|0.6%|
[et_tor](#et_tor)|6400|6400|5|0.0%|0.6%|
[dm_tor](#dm_tor)|6492|6492|5|0.0%|0.6%|
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
[openbl_1d](#openbl_1d)|136|136|1|0.7%|0.1%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|1|0.1%|0.1%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|1|0.0%|0.1%|
[et_compromised](#et_compromised)|1721|1721|1|0.0%|0.1%|
[bruteforceblocker](#bruteforceblocker)|1701|1701|1|0.0%|0.1%|
[blocklist_de_ssh](#blocklist_de_ssh)|3301|3301|1|0.0%|0.1%|
[blocklist_de_ftp](#blocklist_de_ftp)|1421|1421|1|0.0%|0.1%|

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
[firehol_anonymous](#firehol_anonymous)|18973|83011|1373|1.6%|100.0%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|683|0.7%|49.7%|
[firehol_level3](#firehol_level3)|109889|9627682|683|0.0%|49.7%|
[ri_web_proxies](#ri_web_proxies)|7800|7800|605|7.7%|44.0%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|497|1.7%|36.1%|
[firehol_level2](#firehol_level2)|21681|33301|365|1.0%|26.5%|
[xroxy](#xroxy)|2165|2165|333|15.3%|24.2%|
[stopforumspam_1d](#stopforumspam_1d)|6710|6710|311|4.6%|22.6%|
[proxz](#proxz)|1297|1297|288|22.2%|20.9%|
[ri_connect_proxies](#ri_connect_proxies)|2811|2811|198|7.0%|14.4%|
[blocklist_de_bots](#blocklist_de_bots)|2921|2921|197|6.7%|14.3%|
[blocklist_de](#blocklist_de)|28020|28020|197|0.7%|14.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|54|0.0%|3.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|48|0.0%|3.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|30|0.0%|2.1%|
[nixspam](#nixspam)|25075|25075|10|0.0%|0.7%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|10|1.5%|0.7%|
[sorbs_spam](#sorbs_spam)|64701|65536|7|0.0%|0.5%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|7|0.0%|0.5%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|7|0.0%|0.5%|
[blocklist_de_strongips](#blocklist_de_strongips)|176|176|6|3.4%|0.4%|
[snort_ipfilter](#snort_ipfilter)|9945|9945|3|0.0%|0.2%|
[php_dictionary](#php_dictionary)|737|737|2|0.2%|0.1%|
[php_spammers](#php_spammers)|735|735|1|0.1%|0.0%|
[php_commenters](#php_commenters)|430|430|1|0.2%|0.0%|
[iw_spamlist](#iw_spamlist)|3795|3795|1|0.0%|0.0%|
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
[firehol_anonymous](#firehol_anonymous)|18973|83011|1297|1.5%|100.0%|
[firehol_level3](#firehol_level3)|109889|9627682|772|0.0%|59.5%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|766|0.8%|59.0%|
[ri_web_proxies](#ri_web_proxies)|7800|7800|595|7.6%|45.8%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|495|1.6%|38.1%|
[xroxy](#xroxy)|2165|2165|454|20.9%|35.0%|
[proxyrss](#proxyrss)|1373|1373|288|20.9%|22.2%|
[firehol_level2](#firehol_level2)|21681|33301|280|0.8%|21.5%|
[ri_connect_proxies](#ri_connect_proxies)|2811|2811|225|8.0%|17.3%|
[stopforumspam_1d](#stopforumspam_1d)|6710|6710|193|2.8%|14.8%|
[blocklist_de](#blocklist_de)|28020|28020|184|0.6%|14.1%|
[blocklist_de_bots](#blocklist_de_bots)|2921|2921|152|5.2%|11.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|105|0.0%|8.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|52|0.0%|4.0%|
[nixspam](#nixspam)|25075|25075|44|0.1%|3.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|44|0.0%|3.3%|
[sorbs_spam](#sorbs_spam)|64701|65536|43|0.0%|3.3%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|43|0.0%|3.3%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|43|0.0%|3.3%|
[blocklist_de_mail](#blocklist_de_mail)|17167|17167|30|0.1%|2.3%|
[snort_ipfilter](#snort_ipfilter)|9945|9945|27|0.2%|2.0%|
[php_dictionary](#php_dictionary)|737|737|25|3.3%|1.9%|
[php_spammers](#php_spammers)|735|735|22|2.9%|1.6%|
[php_commenters](#php_commenters)|430|430|9|2.0%|0.6%|
[sorbs_web](#sorbs_web)|531|532|8|1.5%|0.6%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|6|0.9%|0.4%|
[blocklist_de_strongips](#blocklist_de_strongips)|176|176|6|3.4%|0.4%|
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
[firehol_anonymous](#firehol_anonymous)|18973|83011|2811|3.3%|100.0%|
[firehol_level3](#firehol_level3)|109889|9627682|1584|0.0%|56.3%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|1583|1.6%|56.3%|
[ri_web_proxies](#ri_web_proxies)|7800|7800|1197|15.3%|42.5%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|561|1.9%|19.9%|
[xroxy](#xroxy)|2165|2165|394|18.1%|14.0%|
[proxz](#proxz)|1297|1297|225|17.3%|8.0%|
[proxyrss](#proxyrss)|1373|1373|198|14.4%|7.0%|
[firehol_level2](#firehol_level2)|21681|33301|151|0.4%|5.3%|
[stopforumspam_1d](#stopforumspam_1d)|6710|6710|112|1.6%|3.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|106|0.0%|3.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|86|0.0%|3.0%|
[blocklist_de](#blocklist_de)|28020|28020|70|0.2%|2.4%|
[blocklist_de_bots](#blocklist_de_bots)|2921|2921|66|2.2%|2.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|57|0.0%|2.0%|
[sorbs_spam](#sorbs_spam)|64701|65536|18|0.0%|0.6%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|18|0.0%|0.6%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|18|0.0%|0.6%|
[nixspam](#nixspam)|25075|25075|18|0.0%|0.6%|
[snort_ipfilter](#snort_ipfilter)|9945|9945|7|0.0%|0.2%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|7|1.0%|0.2%|
[php_dictionary](#php_dictionary)|737|737|5|0.6%|0.1%|
[php_commenters](#php_commenters)|430|430|5|1.1%|0.1%|
[php_spammers](#php_spammers)|735|735|3|0.4%|0.1%|
[dragon_http](#dragon_http)|1029|270336|3|0.0%|0.1%|
[blocklist_de_mail](#blocklist_de_mail)|17167|17167|3|0.0%|0.1%|
[alienvault_reputation](#alienvault_reputation)|188722|188722|3|0.0%|0.1%|
[sorbs_web](#sorbs_web)|531|532|1|0.1%|0.0%|
[php_harvesters](#php_harvesters)|392|392|1|0.2%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|1|0.1%|0.0%|
[iw_spamlist](#iw_spamlist)|3795|3795|1|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.0%|
[dm_tor](#dm_tor)|6492|6492|1|0.0%|0.0%|
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
[firehol_anonymous](#firehol_anonymous)|18973|83011|7800|9.3%|100.0%|
[firehol_level3](#firehol_level3)|109889|9627682|3725|0.0%|47.7%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|3682|3.9%|47.2%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|1518|5.2%|19.4%|
[ri_connect_proxies](#ri_connect_proxies)|2811|2811|1197|42.5%|15.3%|
[xroxy](#xroxy)|2165|2165|960|44.3%|12.3%|
[firehol_level2](#firehol_level2)|21681|33301|678|2.0%|8.6%|
[proxyrss](#proxyrss)|1373|1373|605|44.0%|7.7%|
[proxz](#proxz)|1297|1297|595|45.8%|7.6%|
[blocklist_de](#blocklist_de)|28020|28020|468|1.6%|6.0%|
[stopforumspam_1d](#stopforumspam_1d)|6710|6710|451|6.7%|5.7%|
[blocklist_de_bots](#blocklist_de_bots)|2921|2921|381|13.0%|4.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|223|0.0%|2.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|220|0.0%|2.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|156|0.0%|2.0%|
[sorbs_spam](#sorbs_spam)|64701|65536|144|0.2%|1.8%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|144|0.2%|1.8%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|144|0.2%|1.8%|
[nixspam](#nixspam)|25075|25075|130|0.5%|1.6%|
[blocklist_de_mail](#blocklist_de_mail)|17167|17167|84|0.4%|1.0%|
[php_dictionary](#php_dictionary)|737|737|67|9.0%|0.8%|
[snort_ipfilter](#snort_ipfilter)|9945|9945|61|0.6%|0.7%|
[php_spammers](#php_spammers)|735|735|54|7.3%|0.6%|
[php_commenters](#php_commenters)|430|430|25|5.8%|0.3%|
[sorbs_web](#sorbs_web)|531|532|18|3.3%|0.2%|
[dragon_http](#dragon_http)|1029|270336|18|0.0%|0.2%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|15|2.2%|0.1%|
[iw_spamlist](#iw_spamlist)|3795|3795|11|0.2%|0.1%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|10|1.9%|0.1%|
[blocklist_de_strongips](#blocklist_de_strongips)|176|176|7|3.9%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|6|0.0%|0.0%|
[dm_tor](#dm_tor)|6492|6492|5|0.0%|0.0%|
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
[blocklist_de_ssh](#blocklist_de_ssh)|3301|3301|1|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2845|2845|1|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14213|14213|1|0.0%|0.0%|

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
[firehol_level3](#firehol_level3)|109889|9627682|1278|0.0%|100.0%|
[alienvault_reputation](#alienvault_reputation)|188722|188722|1258|0.6%|98.4%|
[openbl_60d](#openbl_60d)|6989|6989|543|7.7%|42.4%|
[openbl_30d](#openbl_30d)|2813|2813|511|18.1%|39.9%|
[et_compromised](#et_compromised)|1721|1721|430|24.9%|33.6%|
[firehol_level2](#firehol_level2)|21681|33301|405|1.2%|31.6%|
[blocklist_de](#blocklist_de)|28020|28020|401|1.4%|31.3%|
[bruteforceblocker](#bruteforceblocker)|1701|1701|394|23.1%|30.8%|
[blocklist_de_ssh](#blocklist_de_ssh)|3301|3301|358|10.8%|28.0%|
[openbl_7d](#openbl_7d)|641|641|213|33.2%|16.6%|
[firehol_level1](#firehol_level1)|5136|688854491|176|0.0%|13.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|123|0.0%|9.6%|
[et_block](#et_block)|1000|18344011|115|0.0%|8.9%|
[dshield](#dshield)|20|5120|113|2.2%|8.8%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|94|0.0%|7.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|73|0.0%|5.7%|
[openbl_1d](#openbl_1d)|136|136|71|52.2%|5.5%|
[sslbl](#sslbl)|371|371|61|16.4%|4.7%|
[dragon_http](#dragon_http)|1029|270336|37|0.0%|2.8%|
[blocklist_de_apache](#blocklist_de_apache)|14213|14213|37|0.2%|2.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|27|0.0%|2.1%|
[ciarmy](#ciarmy)|457|457|26|5.6%|2.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|176|176|19|10.7%|1.4%|
[voipbl](#voipbl)|10586|10998|13|0.1%|1.0%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|4|0.0%|0.3%|
[blocklist_de_mail](#blocklist_de_mail)|17167|17167|4|0.0%|0.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|0.2%|
[blocklist_de_imap](#blocklist_de_imap)|2801|2801|3|0.1%|0.2%|
[stopforumspam_1d](#stopforumspam_1d)|6710|6710|2|0.0%|0.1%|
[sorbs_spam](#sorbs_spam)|64701|65536|2|0.0%|0.1%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|2|0.0%|0.1%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|2|0.0%|0.1%|
[blocklist_de_sip](#blocklist_de_sip)|85|85|2|2.3%|0.1%|
[tor_exits](#tor_exits)|1121|1121|1|0.0%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|1|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9945|9945|1|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|1|0.1%|0.0%|
[firehol_proxies](#firehol_proxies)|12374|12641|1|0.0%|0.0%|
[firehol_anonymous](#firehol_anonymous)|18973|83011|1|0.0%|0.0%|
[et_tor](#et_tor)|6400|6400|1|0.0%|0.0%|
[dm_tor](#dm_tor)|6492|6492|1|0.0%|0.0%|
[bm_tor](#bm_tor)|6492|6492|1|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2845|2845|1|0.0%|0.0%|

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
[firehol_level3](#firehol_level3)|109889|9627682|9945|0.1%|100.0%|
[firehol_anonymous](#firehol_anonymous)|18973|83011|1224|1.4%|12.3%|
[et_tor](#et_tor)|6400|6400|1089|17.0%|10.9%|
[tor_exits](#tor_exits)|1121|1121|1065|95.0%|10.7%|
[bm_tor](#bm_tor)|6492|6492|1050|16.1%|10.5%|
[dm_tor](#dm_tor)|6492|6492|1042|16.0%|10.4%|
[sorbs_spam](#sorbs_spam)|64701|65536|891|1.3%|8.9%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|891|1.3%|8.9%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|891|1.3%|8.9%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|819|0.8%|8.2%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|677|2.3%|6.8%|
[firehol_level2](#firehol_level2)|21681|33301|557|1.6%|5.6%|
[stopforumspam_1d](#stopforumspam_1d)|6710|6710|380|5.6%|3.8%|
[firehol_proxies](#firehol_proxies)|12374|12641|325|2.5%|3.2%|
[firehol_level1](#firehol_level1)|5136|688854491|299|0.0%|3.0%|
[et_block](#et_block)|1000|18344011|298|0.0%|2.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|241|0.0%|2.4%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|237|45.2%|2.3%|
[blocklist_de](#blocklist_de)|28020|28020|217|0.7%|2.1%|
[zeus](#zeus)|230|230|200|86.9%|2.0%|
[nixspam](#nixspam)|25075|25075|189|0.7%|1.9%|
[zeus_badips](#zeus_badips)|202|202|178|88.1%|1.7%|
[blocklist_de_mail](#blocklist_de_mail)|17167|17167|164|0.9%|1.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|147|0.0%|1.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|114|0.0%|1.1%|
[alienvault_reputation](#alienvault_reputation)|188722|188722|108|0.0%|1.0%|
[php_dictionary](#php_dictionary)|737|737|85|11.5%|0.8%|
[feodo](#feodo)|105|105|83|79.0%|0.8%|
[php_spammers](#php_spammers)|735|735|80|10.8%|0.8%|
[php_commenters](#php_commenters)|430|430|64|14.8%|0.6%|
[ri_web_proxies](#ri_web_proxies)|7800|7800|61|0.7%|0.6%|
[iw_spamlist](#iw_spamlist)|3795|3795|55|1.4%|0.5%|
[sorbs_web](#sorbs_web)|531|532|49|9.2%|0.4%|
[xroxy](#xroxy)|2165|2165|41|1.8%|0.4%|
[blocklist_de_apache](#blocklist_de_apache)|14213|14213|34|0.2%|0.3%|
[sslbl](#sslbl)|371|371|31|8.3%|0.3%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2845|2845|31|1.0%|0.3%|
[proxz](#proxz)|1297|1297|27|2.0%|0.2%|
[openbl_60d](#openbl_60d)|6989|6989|24|0.3%|0.2%|
[blocklist_de_bots](#blocklist_de_bots)|2921|2921|21|0.7%|0.2%|
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
[blocklist_de_imap](#blocklist_de_imap)|2801|2801|4|0.1%|0.0%|
[proxyrss](#proxyrss)|1373|1373|3|0.2%|0.0%|
[openbl_30d](#openbl_30d)|2813|2813|2|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|2|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|176|176|2|1.1%|0.0%|
[voipbl](#voipbl)|10586|10998|1|0.0%|0.0%|
[sorbs_socks](#sorbs_socks)|7|7|1|14.2%|0.0%|
[sorbs_misc](#sorbs_misc)|7|7|1|14.2%|0.0%|
[sorbs_http](#sorbs_http)|7|7|1|14.2%|0.0%|
[shunlist](#shunlist)|1278|1278|1|0.0%|0.0%|
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
[nixspam](#nixspam)|25075|25075|5|0.0%|71.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|2|0.0%|28.5%|
[snort_ipfilter](#snort_ipfilter)|9945|9945|1|0.0%|14.2%|
[php_dictionary](#php_dictionary)|737|737|1|0.1%|14.2%|
[iw_spamlist](#iw_spamlist)|3795|3795|1|0.0%|14.2%|
[firehol_level3](#firehol_level3)|109889|9627682|1|0.0%|14.2%|
[firehol_level2](#firehol_level2)|21681|33301|1|0.0%|14.2%|
[blocklist_de_mail](#blocklist_de_mail)|17167|17167|1|0.0%|14.2%|
[blocklist_de](#blocklist_de)|28020|28020|1|0.0%|14.2%|

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
[nixspam](#nixspam)|25075|25075|5|0.0%|71.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|2|0.0%|28.5%|
[snort_ipfilter](#snort_ipfilter)|9945|9945|1|0.0%|14.2%|
[php_dictionary](#php_dictionary)|737|737|1|0.1%|14.2%|
[iw_spamlist](#iw_spamlist)|3795|3795|1|0.0%|14.2%|
[firehol_level3](#firehol_level3)|109889|9627682|1|0.0%|14.2%|
[firehol_level2](#firehol_level2)|21681|33301|1|0.0%|14.2%|
[blocklist_de_mail](#blocklist_de_mail)|17167|17167|1|0.0%|14.2%|
[blocklist_de](#blocklist_de)|28020|28020|1|0.0%|14.2%|

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
[nixspam](#nixspam)|25075|25075|4605|18.3%|7.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|2851|0.0%|4.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|1736|0.0%|2.6%|
[firehol_level2](#firehol_level2)|21681|33301|1354|4.0%|2.0%|
[blocklist_de](#blocklist_de)|28020|28020|1342|4.7%|2.0%|
[firehol_level3](#firehol_level3)|109889|9627682|1301|0.0%|1.9%|
[blocklist_de_mail](#blocklist_de_mail)|17167|17167|1247|7.2%|1.9%|
[iw_spamlist](#iw_spamlist)|3795|3795|1205|31.7%|1.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|1205|0.0%|1.8%|
[snort_ipfilter](#snort_ipfilter)|9945|9945|891|8.9%|1.3%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|320|0.3%|0.4%|
[sorbs_web](#sorbs_web)|531|532|278|52.2%|0.4%|
[php_dictionary](#php_dictionary)|737|737|214|29.0%|0.3%|
[firehol_anonymous](#firehol_anonymous)|18973|83011|201|0.2%|0.3%|
[firehol_proxies](#firehol_proxies)|12374|12641|196|1.5%|0.3%|
[php_spammers](#php_spammers)|735|735|184|25.0%|0.2%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|169|0.5%|0.2%|
[ri_web_proxies](#ri_web_proxies)|7800|7800|144|1.8%|0.2%|
[alienvault_reputation](#alienvault_reputation)|188722|188722|91|0.0%|0.1%|
[xroxy](#xroxy)|2165|2165|76|3.5%|0.1%|
[dragon_http](#dragon_http)|1029|270336|70|0.0%|0.1%|
[stopforumspam_1d](#stopforumspam_1d)|6710|6710|50|0.7%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2845|2845|46|1.6%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14213|14213|46|0.3%|0.0%|
[proxz](#proxz)|1297|1297|43|3.3%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|37|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2801|2801|32|1.1%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|2921|2921|28|0.9%|0.0%|
[firehol_level1](#firehol_level1)|5136|688854491|25|0.0%|0.0%|
[php_commenters](#php_commenters)|430|430|22|5.1%|0.0%|
[et_block](#et_block)|1000|18344011|22|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|20|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|20|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2811|2811|18|0.6%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|17|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|1421|1421|15|1.0%|0.0%|
[php_harvesters](#php_harvesters)|392|392|14|3.5%|0.0%|
[sorbs_socks](#sorbs_socks)|7|7|7|100.0%|0.0%|
[sorbs_misc](#sorbs_misc)|7|7|7|100.0%|0.0%|
[sorbs_http](#sorbs_http)|7|7|7|100.0%|0.0%|
[proxyrss](#proxyrss)|1373|1373|7|0.5%|0.0%|
[tor_exits](#tor_exits)|1121|1121|5|0.4%|0.0%|
[sorbs_smtp](#sorbs_smtp)|5|5|5|100.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3301|3301|5|0.1%|0.0%|
[et_tor](#et_tor)|6400|6400|4|0.0%|0.0%|
[dm_tor](#dm_tor)|6492|6492|4|0.0%|0.0%|
[bm_tor](#bm_tor)|6492|6492|4|0.0%|0.0%|
[voipbl](#voipbl)|10586|10998|3|0.0%|0.0%|
[et_compromised](#et_compromised)|1721|1721|3|0.1%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1701|1701|3|0.1%|0.0%|
[shunlist](#shunlist)|1278|1278|2|0.1%|0.0%|
[openbl_60d](#openbl_60d)|6989|6989|2|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|2|0.1%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|176|176|2|1.1%|0.0%|
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
[nixspam](#nixspam)|25075|25075|4605|18.3%|7.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|2851|0.0%|4.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|1736|0.0%|2.6%|
[firehol_level2](#firehol_level2)|21681|33301|1354|4.0%|2.0%|
[blocklist_de](#blocklist_de)|28020|28020|1342|4.7%|2.0%|
[firehol_level3](#firehol_level3)|109889|9627682|1301|0.0%|1.9%|
[blocklist_de_mail](#blocklist_de_mail)|17167|17167|1247|7.2%|1.9%|
[iw_spamlist](#iw_spamlist)|3795|3795|1205|31.7%|1.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|1205|0.0%|1.8%|
[snort_ipfilter](#snort_ipfilter)|9945|9945|891|8.9%|1.3%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|320|0.3%|0.4%|
[sorbs_web](#sorbs_web)|531|532|278|52.2%|0.4%|
[php_dictionary](#php_dictionary)|737|737|214|29.0%|0.3%|
[firehol_anonymous](#firehol_anonymous)|18973|83011|201|0.2%|0.3%|
[firehol_proxies](#firehol_proxies)|12374|12641|196|1.5%|0.3%|
[php_spammers](#php_spammers)|735|735|184|25.0%|0.2%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|169|0.5%|0.2%|
[ri_web_proxies](#ri_web_proxies)|7800|7800|144|1.8%|0.2%|
[alienvault_reputation](#alienvault_reputation)|188722|188722|91|0.0%|0.1%|
[xroxy](#xroxy)|2165|2165|76|3.5%|0.1%|
[dragon_http](#dragon_http)|1029|270336|70|0.0%|0.1%|
[stopforumspam_1d](#stopforumspam_1d)|6710|6710|50|0.7%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2845|2845|46|1.6%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14213|14213|46|0.3%|0.0%|
[proxz](#proxz)|1297|1297|43|3.3%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|37|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2801|2801|32|1.1%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|2921|2921|28|0.9%|0.0%|
[firehol_level1](#firehol_level1)|5136|688854491|25|0.0%|0.0%|
[php_commenters](#php_commenters)|430|430|22|5.1%|0.0%|
[et_block](#et_block)|1000|18344011|22|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|20|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|20|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2811|2811|18|0.6%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|17|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|1421|1421|15|1.0%|0.0%|
[php_harvesters](#php_harvesters)|392|392|14|3.5%|0.0%|
[sorbs_socks](#sorbs_socks)|7|7|7|100.0%|0.0%|
[sorbs_misc](#sorbs_misc)|7|7|7|100.0%|0.0%|
[sorbs_http](#sorbs_http)|7|7|7|100.0%|0.0%|
[proxyrss](#proxyrss)|1373|1373|7|0.5%|0.0%|
[tor_exits](#tor_exits)|1121|1121|5|0.4%|0.0%|
[sorbs_smtp](#sorbs_smtp)|5|5|5|100.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3301|3301|5|0.1%|0.0%|
[et_tor](#et_tor)|6400|6400|4|0.0%|0.0%|
[dm_tor](#dm_tor)|6492|6492|4|0.0%|0.0%|
[bm_tor](#bm_tor)|6492|6492|4|0.0%|0.0%|
[voipbl](#voipbl)|10586|10998|3|0.0%|0.0%|
[et_compromised](#et_compromised)|1721|1721|3|0.1%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1701|1701|3|0.1%|0.0%|
[shunlist](#shunlist)|1278|1278|2|0.1%|0.0%|
[openbl_60d](#openbl_60d)|6989|6989|2|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|2|0.1%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|176|176|2|1.1%|0.0%|
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
[nixspam](#nixspam)|25075|25075|1|0.0%|20.0%|

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
[nixspam](#nixspam)|25075|25075|5|0.0%|71.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|2|0.0%|28.5%|
[snort_ipfilter](#snort_ipfilter)|9945|9945|1|0.0%|14.2%|
[php_dictionary](#php_dictionary)|737|737|1|0.1%|14.2%|
[iw_spamlist](#iw_spamlist)|3795|3795|1|0.0%|14.2%|
[firehol_level3](#firehol_level3)|109889|9627682|1|0.0%|14.2%|
[firehol_level2](#firehol_level2)|21681|33301|1|0.0%|14.2%|
[blocklist_de_mail](#blocklist_de_mail)|17167|17167|1|0.0%|14.2%|
[blocklist_de](#blocklist_de)|28020|28020|1|0.0%|14.2%|

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
[nixspam](#nixspam)|25075|25075|4713|18.7%|7.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|2860|0.0%|4.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|1740|0.0%|2.6%|
[firehol_level2](#firehol_level2)|21681|33301|1360|4.0%|2.0%|
[blocklist_de](#blocklist_de)|28020|28020|1348|4.8%|2.0%|
[firehol_level3](#firehol_level3)|109889|9627682|1303|0.0%|1.9%|
[blocklist_de_mail](#blocklist_de_mail)|17167|17167|1253|7.2%|1.9%|
[iw_spamlist](#iw_spamlist)|3795|3795|1210|31.8%|1.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|1208|0.0%|1.8%|
[snort_ipfilter](#snort_ipfilter)|9945|9945|891|8.9%|1.3%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|320|0.3%|0.4%|
[sorbs_web](#sorbs_web)|531|532|278|52.2%|0.4%|
[php_dictionary](#php_dictionary)|737|737|214|29.0%|0.3%|
[firehol_anonymous](#firehol_anonymous)|18973|83011|201|0.2%|0.3%|
[firehol_proxies](#firehol_proxies)|12374|12641|196|1.5%|0.2%|
[php_spammers](#php_spammers)|735|735|184|25.0%|0.2%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|169|0.5%|0.2%|
[ri_web_proxies](#ri_web_proxies)|7800|7800|144|1.8%|0.2%|
[alienvault_reputation](#alienvault_reputation)|188722|188722|91|0.0%|0.1%|
[xroxy](#xroxy)|2165|2165|76|3.5%|0.1%|
[dragon_http](#dragon_http)|1029|270336|71|0.0%|0.1%|
[stopforumspam_1d](#stopforumspam_1d)|6710|6710|50|0.7%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2845|2845|46|1.6%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14213|14213|46|0.3%|0.0%|
[proxz](#proxz)|1297|1297|43|3.3%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|38|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2801|2801|33|1.1%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|2921|2921|28|0.9%|0.0%|
[firehol_level1](#firehol_level1)|5136|688854491|25|0.0%|0.0%|
[php_commenters](#php_commenters)|430|430|22|5.1%|0.0%|
[et_block](#et_block)|1000|18344011|22|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|20|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|20|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2811|2811|18|0.6%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|17|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|1421|1421|15|1.0%|0.0%|
[php_harvesters](#php_harvesters)|392|392|14|3.5%|0.0%|
[sorbs_socks](#sorbs_socks)|7|7|7|100.0%|0.0%|
[sorbs_misc](#sorbs_misc)|7|7|7|100.0%|0.0%|
[sorbs_http](#sorbs_http)|7|7|7|100.0%|0.0%|
[proxyrss](#proxyrss)|1373|1373|7|0.5%|0.0%|
[tor_exits](#tor_exits)|1121|1121|5|0.4%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3301|3301|5|0.1%|0.0%|
[sorbs_smtp](#sorbs_smtp)|5|5|4|80.0%|0.0%|
[et_tor](#et_tor)|6400|6400|4|0.0%|0.0%|
[dm_tor](#dm_tor)|6492|6492|4|0.0%|0.0%|
[bm_tor](#bm_tor)|6492|6492|4|0.0%|0.0%|
[voipbl](#voipbl)|10586|10998|3|0.0%|0.0%|
[et_compromised](#et_compromised)|1721|1721|3|0.1%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1701|1701|3|0.1%|0.0%|
[shunlist](#shunlist)|1278|1278|2|0.1%|0.0%|
[openbl_60d](#openbl_60d)|6989|6989|2|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|2|0.1%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|176|176|2|1.1%|0.0%|
[virbl](#virbl)|25|25|1|4.0%|0.0%|
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
[nixspam](#nixspam)|25075|25075|110|0.4%|20.6%|
[firehol_level3](#firehol_level3)|109889|9627682|65|0.0%|12.2%|
[firehol_level2](#firehol_level2)|21681|33301|63|0.1%|11.8%|
[blocklist_de](#blocklist_de)|28020|28020|63|0.2%|11.8%|
[blocklist_de_mail](#blocklist_de_mail)|17167|17167|58|0.3%|10.9%|
[snort_ipfilter](#snort_ipfilter)|9945|9945|49|0.4%|9.2%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|40|0.0%|7.5%|
[php_dictionary](#php_dictionary)|737|737|30|4.0%|5.6%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|29|0.0%|5.4%|
[php_spammers](#php_spammers)|735|735|25|3.4%|4.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|25|0.0%|4.6%|
[firehol_proxies](#firehol_proxies)|12374|12641|25|0.1%|4.6%|
[firehol_anonymous](#firehol_anonymous)|18973|83011|25|0.0%|4.6%|
[iw_spamlist](#iw_spamlist)|3795|3795|23|0.6%|4.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|19|0.0%|3.5%|
[ri_web_proxies](#ri_web_proxies)|7800|7800|18|0.2%|3.3%|
[xroxy](#xroxy)|2165|2165|13|0.6%|2.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|13|0.0%|2.4%|
[proxz](#proxz)|1297|1297|8|0.6%|1.5%|
[stopforumspam_1d](#stopforumspam_1d)|6710|6710|7|0.1%|1.3%|
[blocklist_de_bots](#blocklist_de_bots)|2921|2921|4|0.1%|0.7%|
[php_commenters](#php_commenters)|430|430|2|0.4%|0.3%|
[blocklist_de_strongips](#blocklist_de_strongips)|176|176|2|1.1%|0.3%|
[ri_connect_proxies](#ri_connect_proxies)|2811|2811|1|0.0%|0.1%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|1|0.0%|0.1%|
[dragon_http](#dragon_http)|1029|270336|1|0.0%|0.1%|
[blocklist_de_ftp](#blocklist_de_ftp)|1421|1421|1|0.0%|0.1%|
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
[firehol_level3](#firehol_level3)|109889|9627682|6933040|72.0%|37.8%|
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
[firehol_level2](#firehol_level2)|21681|33301|260|0.7%|0.0%|
[dragon_http](#dragon_http)|1029|270336|256|0.0%|0.0%|
[openbl_60d](#openbl_60d)|6989|6989|235|3.3%|0.0%|
[blocklist_de](#blocklist_de)|28020|28020|197|0.7%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3301|3301|120|3.6%|0.0%|
[openbl_30d](#openbl_30d)|2813|2813|119|4.2%|0.0%|
[et_compromised](#et_compromised)|1721|1721|101|5.8%|0.0%|
[shunlist](#shunlist)|1278|1278|94|7.3%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6710|6710|79|1.1%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1701|1701|61|3.5%|0.0%|
[nixspam](#nixspam)|25075|25075|56|0.2%|0.0%|
[openbl_7d](#openbl_7d)|641|641|52|8.1%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|2921|2921|50|1.7%|0.0%|
[php_commenters](#php_commenters)|430|430|29|6.7%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|29|2.2%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|17167|17167|21|0.1%|0.0%|
[sorbs_spam](#sorbs_spam)|64701|65536|20|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|20|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|20|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9945|9945|19|0.1%|0.0%|
[openbl_1d](#openbl_1d)|136|136|18|13.2%|0.0%|
[zeus_badips](#zeus_badips)|202|202|15|7.4%|0.0%|
[zeus](#zeus)|230|230|15|6.5%|0.0%|
[voipbl](#voipbl)|10586|10998|14|0.1%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2801|2801|10|0.3%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|176|176|7|3.9%|0.0%|
[php_dictionary](#php_dictionary)|737|737|6|0.8%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|6|0.4%|0.0%|
[firehol_anonymous](#firehol_anonymous)|18973|83011|6|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|5|0.0%|0.0%|
[php_spammers](#php_spammers)|735|735|4|0.5%|0.0%|
[nt_malware_http](#nt_malware_http)|69|69|4|5.7%|0.0%|
[malc0de](#malc0de)|276|276|4|1.4%|0.0%|
[iw_spamlist](#iw_spamlist)|3795|3795|4|0.1%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2845|2845|4|0.1%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14213|14213|4|0.0%|0.0%|
[nt_malware_irc](#nt_malware_irc)|43|43|3|6.9%|0.0%|
[firehol_proxies](#firehol_proxies)|12374|12641|3|0.0%|0.0%|
[et_tor](#et_tor)|6400|6400|3|0.0%|0.0%|
[dm_tor](#dm_tor)|6492|6492|3|0.0%|0.0%|
[bm_tor](#bm_tor)|6492|6492|3|0.0%|0.0%|
[tor_exits](#tor_exits)|1121|1121|2|0.1%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|2|0.3%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|85|85|2|2.3%|0.0%|
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
[firehol_level3](#firehol_level3)|109889|9627682|85|0.0%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|75|0.0%|0.0%|
[sorbs_spam](#sorbs_spam)|64701|65536|20|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|20|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|20|0.0%|0.0%|
[alienvault_reputation](#alienvault_reputation)|188722|188722|14|0.0%|0.0%|
[php_commenters](#php_commenters)|430|430|8|1.8%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|7|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9945|9945|6|0.0%|0.0%|
[firehol_level2](#firehol_level2)|21681|33301|6|0.0%|0.0%|
[zeus_badips](#zeus_badips)|202|202|5|2.4%|0.0%|
[zeus](#zeus)|230|230|5|2.1%|0.0%|
[blocklist_de](#blocklist_de)|28020|28020|5|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|2921|2921|4|0.1%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|176|176|3|1.7%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6710|6710|2|0.0%|0.0%|
[php_harvesters](#php_harvesters)|392|392|1|0.2%|0.0%|
[openbl_60d](#openbl_60d)|6989|6989|1|0.0%|0.0%|
[openbl_30d](#openbl_30d)|2813|2813|1|0.0%|0.0%|
[nixspam](#nixspam)|25075|25075|1|0.0%|0.0%|
[malc0de](#malc0de)|276|276|1|0.3%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14213|14213|1|0.0%|0.0%|

## sslbl

[Abuse.ch SSL Blacklist](https://sslbl.abuse.ch/) bad SSL traffic related to malware or botnet activities - **excellent list**

Source is downloaded from [this link](https://sslbl.abuse.ch/blacklist/sslipblacklist.csv).

The last time downloaded was found to be dated: Thu Jun 11 15:45:06 UTC 2015.

The ipset `sslbl` has **371** entries, **371** unique IPs.

The following table shows the overlaps of `sslbl` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `sslbl`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `sslbl`.
- ` this % ` is the percentage **of this ipset (`sslbl`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level1](#firehol_level1)|5136|688854491|371|0.0%|100.0%|
[firehol_level3](#firehol_level3)|109889|9627682|92|0.0%|24.7%|
[alienvault_reputation](#alienvault_reputation)|188722|188722|65|0.0%|17.5%|
[shunlist](#shunlist)|1278|1278|61|4.7%|16.4%|
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
[firehol_anonymous](#firehol_anonymous)|18973|83011|1|0.0%|0.2%|
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
[firehol_level2](#firehol_level2)|21681|33301|6710|20.1%|100.0%|
[firehol_level3](#firehol_level3)|109889|9627682|6372|0.0%|94.9%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|6362|6.7%|94.8%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|4849|16.6%|72.2%|
[blocklist_de](#blocklist_de)|28020|28020|1443|5.1%|21.5%|
[blocklist_de_bots](#blocklist_de_bots)|2921|2921|1375|47.0%|20.4%|
[firehol_anonymous](#firehol_anonymous)|18973|83011|987|1.1%|14.7%|
[firehol_proxies](#firehol_proxies)|12374|12641|831|6.5%|12.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|517|0.0%|7.7%|
[ri_web_proxies](#ri_web_proxies)|7800|7800|451|5.7%|6.7%|
[snort_ipfilter](#snort_ipfilter)|9945|9945|380|3.8%|5.6%|
[tor_exits](#tor_exits)|1121|1121|348|31.0%|5.1%|
[bm_tor](#bm_tor)|6492|6492|336|5.1%|5.0%|
[et_tor](#et_tor)|6400|6400|335|5.2%|4.9%|
[dm_tor](#dm_tor)|6492|6492|335|5.1%|4.9%|
[proxyrss](#proxyrss)|1373|1373|311|22.6%|4.6%|
[xroxy](#xroxy)|2165|2165|222|10.2%|3.3%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|214|40.8%|3.1%|
[proxz](#proxz)|1297|1297|193|14.8%|2.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|182|0.0%|2.7%|
[php_commenters](#php_commenters)|430|430|164|38.1%|2.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|143|0.0%|2.1%|
[ri_connect_proxies](#ri_connect_proxies)|2811|2811|112|3.9%|1.6%|
[blocklist_de_strongips](#blocklist_de_strongips)|176|176|104|59.0%|1.5%|
[firehol_level1](#firehol_level1)|5136|688854491|82|0.0%|1.2%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|79|0.0%|1.1%|
[et_block](#et_block)|1000|18344011|79|0.0%|1.1%|
[blocklist_de_apache](#blocklist_de_apache)|14213|14213|68|0.4%|1.0%|
[nixspam](#nixspam)|25075|25075|54|0.2%|0.8%|
[sorbs_spam](#sorbs_spam)|64701|65536|50|0.0%|0.7%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|50|0.0%|0.7%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|50|0.0%|0.7%|
[alienvault_reputation](#alienvault_reputation)|188722|188722|49|0.0%|0.7%|
[php_harvesters](#php_harvesters)|392|392|44|11.2%|0.6%|
[blocklist_de_mail](#blocklist_de_mail)|17167|17167|44|0.2%|0.6%|
[php_spammers](#php_spammers)|735|735|41|5.5%|0.6%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2845|2845|36|1.2%|0.5%|
[php_dictionary](#php_dictionary)|737|737|33|4.4%|0.4%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|31|0.0%|0.4%|
[openbl_60d](#openbl_60d)|6989|6989|19|0.2%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|10|0.0%|0.1%|
[dragon_http](#dragon_http)|1029|270336|10|0.0%|0.1%|
[sorbs_web](#sorbs_web)|531|532|7|1.3%|0.1%|
[iw_spamlist](#iw_spamlist)|3795|3795|6|0.1%|0.0%|
[voipbl](#voipbl)|10586|10998|5|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|5|0.7%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|2|0.0%|0.0%|
[shunlist](#shunlist)|1278|1278|2|0.1%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|2|0.1%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2801|2801|2|0.0%|0.0%|
[zeus_badips](#zeus_badips)|202|202|1|0.4%|0.0%|
[zeus](#zeus)|230|230|1|0.4%|0.0%|
[openbl_30d](#openbl_30d)|2813|2813|1|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|1|0.0%|0.0%|
[fullbogons](#fullbogons)|3775|670173256|1|0.0%|0.0%|
[et_compromised](#et_compromised)|1721|1721|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1701|1701|1|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|1421|1421|1|0.0%|0.0%|

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
[firehol_level3](#firehol_level3)|109889|9627682|94309|0.9%|100.0%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|29184|99.9%|30.9%|
[firehol_level2](#firehol_level2)|21681|33301|7735|23.2%|8.2%|
[stopforumspam_1d](#stopforumspam_1d)|6710|6710|6362|94.8%|6.7%|
[firehol_anonymous](#firehol_anonymous)|18973|83011|6196|7.4%|6.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|5830|0.0%|6.1%|
[firehol_proxies](#firehol_proxies)|12374|12641|5587|44.1%|5.9%|
[ri_web_proxies](#ri_web_proxies)|7800|7800|3682|47.2%|3.9%|
[blocklist_de](#blocklist_de)|28020|28020|2791|9.9%|2.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|2476|0.0%|2.6%|
[blocklist_de_bots](#blocklist_de_bots)|2921|2921|2422|82.9%|2.5%|
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
[dm_tor](#dm_tor)|6492|6492|639|9.8%|0.6%|
[tor_exits](#tor_exits)|1121|1121|634|56.5%|0.6%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|345|65.8%|0.3%|
[php_commenters](#php_commenters)|430|430|321|74.6%|0.3%|
[sorbs_spam](#sorbs_spam)|64701|65536|320|0.4%|0.3%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|320|0.4%|0.3%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|320|0.4%|0.3%|
[blocklist_de_mail](#blocklist_de_mail)|17167|17167|257|1.4%|0.2%|
[nixspam](#nixspam)|25075|25075|246|0.9%|0.2%|
[blocklist_de_apache](#blocklist_de_apache)|14213|14213|205|1.4%|0.2%|
[alienvault_reputation](#alienvault_reputation)|188722|188722|168|0.0%|0.1%|
[php_spammers](#php_spammers)|735|735|151|20.5%|0.1%|
[php_dictionary](#php_dictionary)|737|737|139|18.8%|0.1%|
[blocklist_de_strongips](#blocklist_de_strongips)|176|176|135|76.7%|0.1%|
[dragon_http](#dragon_http)|1029|270336|111|0.0%|0.1%|
[php_harvesters](#php_harvesters)|392|392|86|21.9%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|75|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2845|2845|73|2.5%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|52|0.0%|0.0%|
[openbl_60d](#openbl_60d)|6989|6989|47|0.6%|0.0%|
[sorbs_web](#sorbs_web)|531|532|40|7.5%|0.0%|
[voipbl](#voipbl)|10586|10998|35|0.3%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3301|3301|25|0.7%|0.0%|
[iw_spamlist](#iw_spamlist)|3795|3795|22|0.5%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|20|3.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|17|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2801|2801|16|0.5%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|1421|1421|16|1.1%|0.0%|
[et_compromised](#et_compromised)|1721|1721|10|0.5%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1701|1701|10|0.5%|0.0%|
[openbl_30d](#openbl_30d)|2813|2813|5|0.1%|0.0%|
[shunlist](#shunlist)|1278|1278|4|0.3%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|3|0.2%|0.0%|
[zeus_badips](#zeus_badips)|202|202|2|0.9%|0.0%|
[zeus](#zeus)|230|230|2|0.8%|0.0%|
[openbl_7d](#openbl_7d)|641|641|2|0.3%|0.0%|
[nt_malware_http](#nt_malware_http)|69|69|2|2.8%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|2|0.1%|0.0%|
[fullbogons](#fullbogons)|3775|670173256|2|0.0%|0.0%|
[openbl_1d](#openbl_1d)|136|136|1|0.7%|0.0%|
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
[firehol_level3](#firehol_level3)|109889|9627682|29184|0.3%|99.9%|
[firehol_level2](#firehol_level2)|21681|33301|5858|17.5%|20.0%|
[stopforumspam_1d](#stopforumspam_1d)|6710|6710|4849|72.2%|16.6%|
[firehol_anonymous](#firehol_anonymous)|18973|83011|2750|3.3%|9.4%|
[firehol_proxies](#firehol_proxies)|12374|12641|2379|18.8%|8.1%|
[blocklist_de](#blocklist_de)|28020|28020|2278|8.1%|7.8%|
[blocklist_de_bots](#blocklist_de_bots)|2921|2921|2074|71.0%|7.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|1953|0.0%|6.6%|
[ri_web_proxies](#ri_web_proxies)|7800|7800|1518|19.4%|5.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|768|0.0%|2.6%|
[snort_ipfilter](#snort_ipfilter)|9945|9945|677|6.8%|2.3%|
[xroxy](#xroxy)|2165|2165|610|28.1%|2.0%|
[ri_connect_proxies](#ri_connect_proxies)|2811|2811|561|19.9%|1.9%|
[et_tor](#et_tor)|6400|6400|547|8.5%|1.8%|
[tor_exits](#tor_exits)|1121|1121|545|48.6%|1.8%|
[bm_tor](#bm_tor)|6492|6492|532|8.1%|1.8%|
[dm_tor](#dm_tor)|6492|6492|530|8.1%|1.8%|
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
[blocklist_de_mail](#blocklist_de_mail)|17167|17167|146|0.8%|0.5%|
[nixspam](#nixspam)|25075|25075|134|0.5%|0.4%|
[blocklist_de_apache](#blocklist_de_apache)|14213|14213|122|0.8%|0.4%|
[blocklist_de_strongips](#blocklist_de_strongips)|176|176|120|68.1%|0.4%|
[php_spammers](#php_spammers)|735|735|95|12.9%|0.3%|
[php_dictionary](#php_dictionary)|737|737|94|12.7%|0.3%|
[alienvault_reputation](#alienvault_reputation)|188722|188722|89|0.0%|0.3%|
[php_harvesters](#php_harvesters)|392|392|61|15.5%|0.2%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2845|2845|53|1.8%|0.1%|
[dragon_http](#dragon_http)|1029|270336|36|0.0%|0.1%|
[sorbs_web](#sorbs_web)|531|532|29|5.4%|0.0%|
[openbl_60d](#openbl_60d)|6989|6989|27|0.3%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|20|0.0%|0.0%|
[voipbl](#voipbl)|10586|10998|14|0.1%|0.0%|
[iw_spamlist](#iw_spamlist)|3795|3795|14|0.3%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|11|1.6%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|7|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|7|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3301|3301|6|0.1%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2801|2801|6|0.2%|0.0%|
[et_compromised](#et_compromised)|1721|1721|5|0.2%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|1421|1421|5|0.3%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1701|1701|4|0.2%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|2|0.1%|0.0%|
[zeus_badips](#zeus_badips)|202|202|1|0.4%|0.0%|
[zeus](#zeus)|230|230|1|0.4%|0.0%|
[shunlist](#shunlist)|1278|1278|1|0.0%|0.0%|
[openbl_30d](#openbl_30d)|2813|2813|1|0.0%|0.0%|
[iw_wormlist](#iw_wormlist)|33|33|1|3.0%|0.0%|
[fullbogons](#fullbogons)|3775|670173256|1|0.0%|0.0%|

## tor_exits

[TorProject.org](https://www.torproject.org) list of all current TOR exit points (TorDNSEL)

Source is downloaded from [this link](https://check.torproject.org/exit-addresses).

The last time downloaded was found to be dated: Thu Jun 11 15:02:38 UTC 2015.

The ipset `tor_exits` has **1121** entries, **1121** unique IPs.

The following table shows the overlaps of `tor_exits` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `tor_exits`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `tor_exits`.
- ` this % ` is the percentage **of this ipset (`tor_exits`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_anonymous](#firehol_anonymous)|18973|83011|1121|1.3%|100.0%|
[firehol_level3](#firehol_level3)|109889|9627682|1067|0.0%|95.1%|
[snort_ipfilter](#snort_ipfilter)|9945|9945|1065|10.7%|95.0%|
[bm_tor](#bm_tor)|6492|6492|1019|15.6%|90.9%|
[dm_tor](#dm_tor)|6492|6492|1013|15.6%|90.3%|
[et_tor](#et_tor)|6400|6400|970|15.1%|86.5%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|634|0.6%|56.5%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|545|1.8%|48.6%|
[firehol_level2](#firehol_level2)|21681|33301|360|1.0%|32.1%|
[stopforumspam_1d](#stopforumspam_1d)|6710|6710|348|5.1%|31.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|231|44.0%|20.6%|
[firehol_proxies](#firehol_proxies)|12374|12641|231|1.8%|20.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|128|0.0%|11.4%|
[php_commenters](#php_commenters)|430|430|51|11.8%|4.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|40|0.0%|3.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|36|0.0%|3.2%|
[alienvault_reputation](#alienvault_reputation)|188722|188722|30|0.0%|2.6%|
[blocklist_de](#blocklist_de)|28020|28020|24|0.0%|2.1%|
[blocklist_de_apache](#blocklist_de_apache)|14213|14213|23|0.1%|2.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2845|2845|21|0.7%|1.8%|
[openbl_60d](#openbl_60d)|6989|6989|20|0.2%|1.7%|
[nixspam](#nixspam)|25075|25075|8|0.0%|0.7%|
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
[blocklist_de_mail](#blocklist_de_mail)|17167|17167|2|0.0%|0.1%|
[shunlist](#shunlist)|1278|1278|1|0.0%|0.0%|
[iw_spamlist](#iw_spamlist)|3795|3795|1|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|2921|2921|1|0.0%|0.0%|

## virbl

[VirBL](http://virbl.bit.nl/) is a project of which the idea was born during the RIPE-48 meeting. The plan was to get reports of virusscanning mailservers, and put the IP-addresses that were reported to send viruses on a blacklist.

Source is downloaded from [this link](http://virbl.bit.nl/download/virbl.dnsbl.bit.nl.txt).

The last time downloaded was found to be dated: Thu Jun 11 15:42:04 UTC 2015.

The ipset `virbl` has **25** entries, **25** unique IPs.

The following table shows the overlaps of `virbl` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `virbl`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `virbl`.
- ` this % ` is the percentage **of this ipset (`virbl`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level3](#firehol_level3)|109889|9627682|25|0.0%|100.0%|
[sorbs_spam](#sorbs_spam)|64701|65536|1|0.0%|4.0%|
[fullbogons](#fullbogons)|3775|670173256|1|0.0%|4.0%|
[firehol_level1](#firehol_level1)|5136|688854491|1|0.0%|4.0%|

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
[firehol_level1](#firehol_level1)|5136|688854491|333|0.0%|3.0%|
[fullbogons](#fullbogons)|3775|670173256|319|0.0%|2.9%|
[bogons](#bogons)|13|592708608|319|0.0%|2.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|302|0.0%|2.7%|
[alienvault_reputation](#alienvault_reputation)|188722|188722|184|0.0%|1.6%|
[firehol_anonymous](#firehol_anonymous)|18973|83011|79|0.0%|0.7%|
[firehol_level3](#firehol_level3)|109889|9627682|58|0.0%|0.5%|
[firehol_level2](#firehol_level2)|21681|33301|46|0.1%|0.4%|
[blocklist_de](#blocklist_de)|28020|28020|41|0.1%|0.3%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|35|0.0%|0.3%|
[blocklist_de_sip](#blocklist_de_sip)|85|85|34|40.0%|0.3%|
[dragon_http](#dragon_http)|1029|270336|27|0.0%|0.2%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|14|0.0%|0.1%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|14|0.0%|0.1%|
[et_block](#et_block)|1000|18344011|14|0.0%|0.1%|
[shunlist](#shunlist)|1278|1278|13|1.0%|0.1%|
[openbl_60d](#openbl_60d)|6989|6989|8|0.1%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6710|6710|5|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|4|0.0%|0.0%|
[sorbs_spam](#sorbs_spam)|64701|65536|3|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|3|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|3|0.0%|0.0%|
[openbl_30d](#openbl_30d)|2813|2813|3|0.1%|0.0%|
[et_tor](#et_tor)|6400|6400|3|0.0%|0.0%|
[et_compromised](#et_compromised)|1721|1721|3|0.1%|0.0%|
[dm_tor](#dm_tor)|6492|6492|3|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1701|1701|3|0.1%|0.0%|
[bm_tor](#bm_tor)|6492|6492|3|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14213|14213|3|0.0%|0.0%|
[nixspam](#nixspam)|25075|25075|2|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|2|0.3%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|2|0.0%|0.0%|
[firehol_proxies](#firehol_proxies)|12374|12641|2|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3301|3301|2|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|17167|17167|2|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9945|9945|1|0.0%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.0%|
[ciarmy](#ciarmy)|457|457|1|0.2%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2801|2801|1|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2845|2845|1|0.0%|0.0%|

## xroxy

[xroxy.com](http://www.xroxy.com) open proxies (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.xroxy.com/proxyrss.xml).

The last time downloaded was found to be dated: Thu Jun 11 15:33:02 UTC 2015.

The ipset `xroxy` has **2165** entries, **2165** unique IPs.

The following table shows the overlaps of `xroxy` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `xroxy`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `xroxy`.
- ` this % ` is the percentage **of this ipset (`xroxy`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_proxies](#firehol_proxies)|12374|12641|2165|17.1%|100.0%|
[firehol_anonymous](#firehol_anonymous)|18973|83011|2165|2.6%|100.0%|
[firehol_level3](#firehol_level3)|109889|9627682|1299|0.0%|60.0%|
[stopforumspam_30d](#stopforumspam_30d)|94309|94309|1283|1.3%|59.2%|
[ri_web_proxies](#ri_web_proxies)|7800|7800|960|12.3%|44.3%|
[stopforumspam_7d](#stopforumspam_7d)|29185|29185|610|2.0%|28.1%|
[proxz](#proxz)|1297|1297|454|35.0%|20.9%|
[ri_connect_proxies](#ri_connect_proxies)|2811|2811|394|14.0%|18.1%|
[proxyrss](#proxyrss)|1373|1373|333|24.2%|15.3%|
[firehol_level2](#firehol_level2)|21681|33301|327|0.9%|15.1%|
[blocklist_de](#blocklist_de)|28020|28020|226|0.8%|10.4%|
[stopforumspam_1d](#stopforumspam_1d)|6710|6710|222|3.3%|10.2%|
[blocklist_de_bots](#blocklist_de_bots)|2921|2921|168|5.7%|7.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|110|0.0%|5.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|104|0.0%|4.8%|
[sorbs_spam](#sorbs_spam)|64701|65536|76|0.1%|3.5%|
[sorbs_recent_spam](#sorbs_recent_spam)|64467|65300|76|0.1%|3.5%|
[sorbs_new_spam](#sorbs_new_spam)|64467|65300|76|0.1%|3.5%|
[nixspam](#nixspam)|25075|25075|66|0.2%|3.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|58|0.0%|2.6%|
[blocklist_de_mail](#blocklist_de_mail)|17167|17167|57|0.3%|2.6%|
[snort_ipfilter](#snort_ipfilter)|9945|9945|41|0.4%|1.8%|
[php_dictionary](#php_dictionary)|737|737|41|5.5%|1.8%|
[php_spammers](#php_spammers)|735|735|34|4.6%|1.5%|
[sorbs_web](#sorbs_web)|531|532|13|2.4%|0.6%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|13|1.9%|0.6%|
[php_commenters](#php_commenters)|430|430|10|2.3%|0.4%|
[dragon_http](#dragon_http)|1029|270336|6|0.0%|0.2%|
[blocklist_de_strongips](#blocklist_de_strongips)|176|176|6|3.4%|0.2%|
[alienvault_reputation](#alienvault_reputation)|188722|188722|5|0.0%|0.2%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|3|0.5%|0.1%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|3|0.0%|0.1%|
[php_harvesters](#php_harvesters)|392|392|2|0.5%|0.0%|
[iw_spamlist](#iw_spamlist)|3795|3795|2|0.0%|0.0%|
[dm_tor](#dm_tor)|6492|6492|2|0.0%|0.0%|
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
[firehol_level3](#firehol_level3)|109889|9627682|203|0.0%|88.2%|
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
[nixspam](#nixspam)|25075|25075|1|0.0%|0.4%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|1|0.0%|0.4%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.4%|
[firehol_level2](#firehol_level2)|21681|33301|1|0.0%|0.4%|

## zeus_badips

[Abuse.ch Zeus tracker](https://zeustracker.abuse.ch) badips includes IPv4 addresses that are used by the ZeuS trojan. It is the recommened blocklist if you want to block only ZeuS IPs. It excludes IP addresses that ZeuS Tracker believes to be hijacked (level 2) or belong to a free web hosting provider (level 3). Hence the false postive rate should be much lower compared to the standard ZeuS IP blocklist. **excellent list**

Source is downloaded from [this link](https://zeustracker.abuse.ch/blocklist.php?download=badips).

The last time downloaded was found to be dated: Thu Jun 11 15:54:10 UTC 2015.

The ipset `zeus_badips` has **202** entries, **202** unique IPs.

The following table shows the overlaps of `zeus_badips` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `zeus_badips`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `zeus_badips`.
- ` this % ` is the percentage **of this ipset (`zeus_badips`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[zeus](#zeus)|230|230|202|87.8%|100.0%|
[firehol_level1](#firehol_level1)|5136|688854491|202|0.0%|100.0%|
[et_block](#et_block)|1000|18344011|202|0.0%|100.0%|
[firehol_level3](#firehol_level3)|109889|9627682|180|0.0%|89.1%|
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
[nixspam](#nixspam)|25075|25075|1|0.0%|0.4%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.4%|
[firehol_level2](#firehol_level2)|21681|33301|1|0.0%|0.4%|
