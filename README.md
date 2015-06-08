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

The following list was automatically generated on Mon Jun  8 10:37:02 UTC 2015.

The update frequency is the maximum allowed by internal configuration. A list will never be downloaded sooner than the update frequency stated. A list may also not be downloaded, after this frequency expired, if it has not been modified on the server (as reported by HTTP `IF_MODIFIED_SINCE` method).

name|info|type|entries|update|
:--:|:--:|:--:|:-----:|:----:|
[alienvault_reputation](#alienvault_reputation)|[AlienVault.com](https://www.alienvault.com/) IP reputation database (this list seems to include port scanning hosts and to be updated regularly, but we found no information about its retention policy)|ipv4 hash:ip|181932 unique IPs|updated every 6 hours  from [this link](https://reputation.alienvault.com/reputation.generic)
[blocklist_de](#blocklist_de)|[Blocklist.de](https://www.blocklist.de/) IPs that have been detected by fail2ban in the last 48 hours - **excellent list**|ipv4 hash:ip|31099 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/all.txt)
[blocklist_de_apache](#blocklist_de_apache)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service Apache, Apache-DDOS, RFI-Attacks.|ipv4 hash:ip|16201 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/apache.txt)
[blocklist_de_bots](#blocklist_de_bots)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the RFI-Attacks, REG-Bots, IRC-Bots or BadBots (BadBots = he has posted a Spam-Comment on a open Forum or Wiki).|ipv4 hash:ip|3421 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/bots.txt)
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|[Blocklist.de](https://www.blocklist.de/) All IPs which attacks Joomlas, Wordpress and other Web-Logins with Brute-Force Logins.|ipv4 hash:ip|4840 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/bruteforcelogin.txt)
[blocklist_de_ftp](#blocklist_de_ftp)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours for attacks on the Service FTP.|ipv4 hash:ip|320 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/ftp.txt)
[blocklist_de_imap](#blocklist_de_imap)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours for attacks on the Service imap, sasl, pop3, etc.|ipv4 hash:ip|2813 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/imap.txt)
[blocklist_de_mail](#blocklist_de_mail)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service Mail, Postfix.|ipv4 hash:ip|18693 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/mail.txt)
[blocklist_de_sip](#blocklist_de_sip)|[Blocklist.de](https://www.blocklist.de/) All IP addresses that tried to login in a SIP, VOIP or Asterisk Server and are included in the IPs list from [infiltrated.net](www.infiltrated.net)|ipv4 hash:ip|90 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/sip.txt)
[blocklist_de_ssh](#blocklist_de_ssh)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service SSH.|ipv4 hash:ip|3473 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/ssh.txt)
[blocklist_de_strongips](#blocklist_de_strongips)|[Blocklist.de](https://www.blocklist.de/) All IPs which are older then 2 month and have more then 5.000 attacks.|ipv4 hash:ip|158 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/strongips.txt)
[bm_tor](#bm_tor)|[torstatus.blutmagie.de](https://torstatus.blutmagie.de) list of all TOR network servers|ipv4 hash:ip|6458 unique IPs|updated every 30 mins  from [this link](https://torstatus.blutmagie.de/ip_list_all.php/Tor_ip_list_ALL.csv)
[bogons](#bogons)|[Team-Cymru.org](http://www.team-cymru.org) private and reserved addresses defined by RFC 1918, RFC 5735, and RFC 6598 and netblocks that have not been allocated to a regional internet registry - **excellent list - use it only your internet interface**|ipv4 hash:net|13 subnets, 592708608 unique IPs|updated every 1 day  from [this link](http://www.team-cymru.org/Services/Bogons/bogon-bn-agg.txt)
[bruteforceblocker](#bruteforceblocker)|[danger.rulez.sk](http://danger.rulez.sk/) IPs detected by [bruteforceblocker](http://danger.rulez.sk/index.php/bruteforceblocker/) (fail2ban alternative for SSH on OpenBSD). This is an automatically generated list from users reporting failed authentication attempts. An IP seems to be included if 3 or more users report it. Its retention pocily seems 30 days.|ipv4 hash:ip|1692 unique IPs|updated every 3 hours  from [this link](http://danger.rulez.sk/projects/bruteforceblocker/blist.php)
[ciarmy](#ciarmy)|[CIArmy.com](http://ciarmy.com/) IPs with poor Rogue Packet score that have not yet been identified as malicious by the community|ipv4 hash:ip|422 unique IPs|updated every 3 hours  from [this link](http://cinsscore.com/list/ci-badguys.txt)
[cleanmx_viruses](#cleanmx_viruses)|[Clean-MX.de](http://support.clean-mx.de/clean-mx/viruses.php) IPs with viruses|ipv4 hash:ip|319 unique IPs|updated every 12 hours  from [this link](http://support.clean-mx.de/clean-mx/xmlviruses.php?sort=id%20desc&response=alive)
[dm_tor](#dm_tor)|[dan.me.uk](https://www.dan.me.uk) dynamic list of TOR exit points|ipv4 hash:ip|6454 unique IPs|updated every 30 mins  from [this link](https://www.dan.me.uk/torlist/)
[dshield](#dshield)|[DShield.org](https://dshield.org/) top 20 attacking class C (/24) subnets over the last three days - **excellent list**|ipv4 hash:net|20 subnets, 5120 unique IPs|updated every 4 hours  from [this link](http://feeds.dshield.org/block.txt)
[et_block](#et_block)|[EmergingThreats.net](http://www.emergingthreats.net/) default blacklist (at the time of writing includes spamhaus DROP, dshield and abuse.ch trackers, which are available separately too - prefer to use the direct ipsets instead of this, they seem to lag a bit in updates)|ipv4 hash:net|1023 subnets, 18338662 unique IPs|updated every 12 hours  from [this link](http://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt)
[et_botcc](#et_botcc)|[EmergingThreats.net Command and Control IPs](http://doc.emergingthreats.net/bin/view/Main/BotCC) These IPs are updates every 24 hours and should be considered VERY highly reliable indications that a host is communicating with a known and active Bot or Malware command and control server - (although they say this includes abuse.ch trackers, it does not - most probably it is the shadowserver.org C&C list)|ipv4 hash:ip|0 unique IPs|updated every 12 hours  from [this link](http://rules.emergingthreats.net/fwrules/emerging-PIX-CC.rules)
[et_compromised](#et_compromised)|[EmergingThreats.net compromised hosts](http://doc.emergingthreats.net/bin/view/Main/CompromisedHost) - (this seems to be based on bruteforceblocker)|ipv4 hash:ip|2016 unique IPs|updated every 12 hours  from [this link](http://rules.emergingthreats.net/blockrules/compromised-ips.txt)
et_dshield|[EmergingThreats.net](http://www.emergingthreats.net/) dshield blocklist|ipv4 hash:net|disabled|updated every 12 hours  from [this link](http://rules.emergingthreats.net/fwrules/emerging-PIX-DSHIELD.rules)
et_spamhaus|[EmergingThreats.net](http://www.emergingthreats.net/) spamhaus blocklist|ipv4 hash:net|disabled|updated every 12 hours  from [this link](http://rules.emergingthreats.net/fwrules/emerging-PIX-DROP.rules)
[et_tor](#et_tor)|[EmergingThreats.net](http://www.emergingthreats.net/) [list](http://doc.emergingthreats.net/bin/view/Main/TorRules) of TOR network IPs|ipv4 hash:ip|6470 unique IPs|updated every 12 hours  from [this link](http://rules.emergingthreats.net/blockrules/emerging-tor.rules)
[feodo](#feodo)|[Abuse.ch Feodo tracker](https://feodotracker.abuse.ch) trojan includes IPs which are being used by Feodo (also known as Cridex or Bugat) which commits ebanking fraud - **excellent list**|ipv4 hash:ip|99 unique IPs|updated every 30 mins  from [this link](https://feodotracker.abuse.ch/blocklist/?download=ipblocklist)
[firehol_anonymous](#firehol_anonymous)|**FireHOL Anonymous** - Known anonymizing IPs. (includes: firehol_proxies anonymous bm_tor dm_tor)|ipv4 hash:net|17786 subnets, 81795 unique IPs|updated every 1 min  from [this link]()
[firehol_level1](#firehol_level1)|**FireHOL Level 1** - Maximum protection without false positives. (includes: fullbogons dshield feodo palevo sslbl zeus spamhaus_drop spamhaus_edrop)|ipv4 hash:net|5086 subnets, 688943154 unique IPs|updated every 1 min  from [this link]()
[firehol_level2](#firehol_level2)|**FireHOL Level 2** - Maximum protection from attacks took place in the last 48 hours. (includes: openbl_1d blocklist_de stopforumspam_1d)|ipv4 hash:net|24806 subnets, 36416 unique IPs|updated every 1 min  from [this link]()
[firehol_level3](#firehol_level3)|**FireHOL Level 3** - All the bad IPs in last 30 days. (includes: openbl_30d stopforumspam_30d virbl malc0de shunlist malwaredomainlist bruteforceblocker ciarmy cleanmx_viruses snort_ipfilter ib_bluetack_spyware ib_bluetack_hijacked ib_bluetack_webexploit php_commenters php_dictionary php_harvesters php_spammers)|ipv4 hash:net|107712 subnets, 9625222 unique IPs|updated every 1 min  from [this link]()
[firehol_proxies](#firehol_proxies)|**FireHOL Proxies** - Known open proxies in the last 30 days. (includes: ib_bluetack_proxies maxmind_proxy_fraud proxyrss proxz ri_connect_proxies ri_web_proxies xroxy)|ipv4 hash:net|11379 subnets, 11603 unique IPs|updated every 1 min  from [this link]()
[fullbogons](#fullbogons)|[Team-Cymru.org](http://www.team-cymru.org) IP space that has been allocated to an RIR, but not assigned by that RIR to an actual ISP or other end-user - **excellent list - use it only your internet interface**|ipv4 hash:net|3720 subnets, 670264216 unique IPs|updated every 1 day  from [this link](http://www.team-cymru.org/Services/Bogons/fullbogons-ipv4.txt)
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
lashback_ubl|[The LashBack UBL](http://blacklist.lashback.com/) The Unsubscribe Blacklist (UBL) is a real-time blacklist of IP addresses which are sending email to names harvested from suppression files (this is a big list, more than 500.000 IPs)|ipv4 hash:ip|disabled|updated every 1 day  from [this link](http://www.unsubscore.com/blacklist.txt)
[malc0de](#malc0de)|[Malc0de.com](http://malc0de.com) malicious IPs of the last 30 days|ipv4 hash:ip|351 unique IPs|updated every 1 day  from [this link](http://malc0de.com/bl/IP_Blacklist.txt)
[malwaredomainlist](#malwaredomainlist)|[malwaredomainlist.com](http://www.malwaredomainlist.com) list of malware active ip addresses|ipv4 hash:ip|1288 unique IPs|updated every 12 hours  from [this link](http://www.malwaredomainlist.com/hostslist/ip.txt)
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|[MaxMind.com](https://www.maxmind.com/en/anonymous-proxy-fraudulent-ip-address-list) list of anonymous proxy fraudelent IP addresses.|ipv4 hash:ip|372 unique IPs|updated every 4 hours  from [this link](https://www.maxmind.com/en/anonymous-proxy-fraudulent-ip-address-list)
[nixspam](#nixspam)|[NiX Spam](http://www.heise.de/ix/NiX-Spam-DNSBL-and-blacklist-for-download-499637.html) IP addresses that sent spam in the last hour - automatically generated entries without distinguishing open proxies from relays, dialup gateways, and so on. All IPs are removed after 12 hours if there is no spam from there.|ipv4 hash:ip|20667 unique IPs|updated every 15 mins  from [this link](http://www.dnsbl.manitu.net/download/nixspam-ip.dump.gz)
openbl|[OpenBL.org](http://www.openbl.org/) default blacklist (currently it is the same with 90 days). OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications - **excellent list**|ipv4 hash:ip|disabled|updated every 4 hours  from [this link](http://www.openbl.org/lists/base.txt)
openbl_180d|[OpenBL.org](http://www.openbl.org/) last 180 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|disabled|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_180days.txt)
[openbl_1d](#openbl_1d)|[OpenBL.org](http://www.openbl.org/) last 24 hours IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|112 unique IPs|updated every 1 hour  from [this link](http://www.openbl.org/lists/base_1days.txt)
[openbl_30d](#openbl_30d)|[OpenBL.org](http://www.openbl.org/) last 30 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|2969 unique IPs|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_30days.txt)
openbl_360d|[OpenBL.org](http://www.openbl.org/) last 360 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|disabled|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_360days.txt)
[openbl_60d](#openbl_60d)|[OpenBL.org](http://www.openbl.org/) last 60 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|7242 unique IPs|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_60days.txt)
[openbl_7d](#openbl_7d)|[OpenBL.org](http://www.openbl.org/) last 7 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|825 unique IPs|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_7days.txt)
openbl_90d|[OpenBL.org](http://www.openbl.org/) last 90 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|disabled|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_90days.txt)
openbl_all|[OpenBL.org](http://www.openbl.org/) last all IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|disabled|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_all.txt)
[palevo](#palevo)|[Abuse.ch Palevo tracker](https://palevotracker.abuse.ch) worm includes IPs which are being used as botnet C&C for the Palevo crimeware - **excellent list**|ipv4 hash:ip|13 unique IPs|updated every 30 mins  from [this link](https://palevotracker.abuse.ch/blocklists.php?download=ipblocklist)
php_bad|[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) bad web hosts (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|disabled|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=b&rss=1)
[php_commenters](#php_commenters)|[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) comment spammers (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|373 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=c&rss=1)
[php_dictionary](#php_dictionary)|[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) directory attackers (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|589 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=d&rss=1)
[php_harvesters](#php_harvesters)|[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) harvesters (IPs that surf the internet looking for email addresses) (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|341 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=h&rss=1)
[php_spammers](#php_spammers)|[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) spam servers (IPs used by spammers to send messages) (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|580 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=s&rss=1)
[proxyrss](#proxyrss)|[proxyrss.com](http://www.proxyrss.com) open proxies syndicated from multiple sources.|ipv4 hash:ip|1481 unique IPs|updated every 4 hours  from [this link](http://www.proxyrss.com/proxylists/all.gz)
[proxz](#proxz)|[proxz.com](http://www.proxz.com) open proxies (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|1039 unique IPs|updated every 1 hour  from [this link](http://www.proxz.com/proxylists.xml)
[ri_connect_proxies](#ri_connect_proxies)|[rosinstrument.com](http://www.rosinstrument.com) open CONNECT proxies (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|2581 unique IPs|updated every 1 hour  from [this link](http://tools.rosinstrument.com/proxy/plab100.xml)
[ri_web_proxies](#ri_web_proxies)|[rosinstrument.com](http://www.rosinstrument.com) open HTTP proxies (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|7066 unique IPs|updated every 1 hour  from [this link](http://tools.rosinstrument.com/proxy/l100.xml)
[shunlist](#shunlist)|[AutoShun.org](http://autoshun.org/) IPs identified as hostile by correlating logs from distributed snort installations running the autoshun plugin|ipv4 hash:ip|1230 unique IPs|updated every 4 hours  from [this link](http://www.autoshun.org/files/shunlist.csv)
[snort_ipfilter](#snort_ipfilter)|[labs.snort.org](https://labs.snort.org/) supplied IP blacklist (this list seems to be updated frequently, but we found no information about it)|ipv4 hash:ip|9492 unique IPs|updated every 12 hours  from [this link](http://labs.snort.org/feeds/ip-filter.blf)
[spamhaus_drop](#spamhaus_drop)|[Spamhaus.org](http://www.spamhaus.org) DROP list (according to their site this list should be dropped at tier-1 ISPs globaly) - **excellent list**|ipv4 hash:net|652 subnets, 18338560 unique IPs|updated every 12 hours  from [this link](http://www.spamhaus.org/drop/drop.txt)
[spamhaus_edrop](#spamhaus_edrop)|[Spamhaus.org](http://www.spamhaus.org) EDROP (extended matches that should be used with DROP) - **excellent list**|ipv4 hash:net|56 subnets, 487424 unique IPs|updated every 12 hours  from [this link](http://www.spamhaus.org/drop/edrop.txt)
[sslbl](#sslbl)|[Abuse.ch SSL Blacklist](https://sslbl.abuse.ch/) bad SSL traffic related to malware or botnet activities - **excellent list**|ipv4 hash:ip|379 unique IPs|updated every 30 mins  from [this link](https://sslbl.abuse.ch/blacklist/sslipblacklist.csv)
stopforumspam_180d|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 180 days)|ipv4 hash:ip|disabled|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/listed_ip_180.zip)
[stopforumspam_1d](#stopforumspam_1d)|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers in the last 24 hours - **excellent list**|ipv4 hash:ip|6697 unique IPs|updated every 1 hour  from [this link](http://www.stopforumspam.com/downloads/listed_ip_1.zip)
[stopforumspam_30d](#stopforumspam_30d)|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 30 days)|ipv4 hash:ip|92247 unique IPs|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/listed_ip_30.zip)
stopforumspam_365d|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 365 days)|ipv4 hash:ip|disabled|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/listed_ip_365.zip)
[stopforumspam_7d](#stopforumspam_7d)|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 7 days)|ipv4 hash:ip|29278 unique IPs|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/listed_ip_7.zip)
stopforumspam_90d|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 90 days)|ipv4 hash:ip|disabled|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/listed_ip_90.zip)
stopforumspam_ever|[StopForumSpam.com](http://www.stopforumspam.com) all IPs used by forum spammers, **ever** (normally you don't want to use this ipset, use the hourly one which includes last 24 hours IPs or the 7 days one)|ipv4 hash:ip|disabled|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/bannedips.zip)
[virbl](#virbl)|[VirBL](http://virbl.bit.nl/) is a project of which the idea was born during the RIPE-48 meeting. The plan was to get reports of virusscanning mailservers, and put the IP-addresses that were reported to send viruses on a blacklist.|ipv4 hash:ip|4 unique IPs|updated every 1 hour  from [this link](http://virbl.bit.nl/download/virbl.dnsbl.bit.nl.txt)
[voipbl](#voipbl)|[VoIPBL.org](http://www.voipbl.org/) a distributed VoIP blacklist that is aimed to protects against VoIP Fraud and minimizing abuse for network that have publicly accessible PBX's. Several algorithms, external sources and manual confirmation are used before they categorize something as an attack and determine the threat level.|ipv4 hash:net|10491 subnets, 10902 unique IPs|updated every 4 hours  from [this link](http://www.voipbl.org/update/)
[xroxy](#xroxy)|[xroxy.com](http://www.xroxy.com) open proxies (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|2121 unique IPs|updated every 1 hour  from [this link](http://www.xroxy.com/proxyrss.xml)
[zeus](#zeus)|[Abuse.ch Zeus tracker](https://zeustracker.abuse.ch) standard, contains the same data as the ZeuS IP blocklist (zeus_badips) but with the slight difference that it doesn't exclude hijacked websites (level 2) and free web hosting providers (level 3). This means that this blocklist contains all IPv4 addresses associated with ZeuS C&Cs which are currently being tracked by ZeuS Tracker. Hence this blocklist will likely cause some false positives. - **excellent list**|ipv4 hash:ip|233 unique IPs|updated every 30 mins  from [this link](https://zeustracker.abuse.ch/blocklist.php?download=ipblocklist)
[zeus_badips](#zeus_badips)|[Abuse.ch Zeus tracker](https://zeustracker.abuse.ch) badips includes IPv4 addresses that are used by the ZeuS trojan. It is the recommened blocklist if you want to block only ZeuS IPs. It excludes IP addresses that ZeuS Tracker believes to be hijacked (level 2) or belong to a free web hosting provider (level 3). Hence the false postive rate should be much lower compared to the standard ZeuS IP blocklist. **excellent list**|ipv4 hash:ip|204 unique IPs|updated every 30 mins  from [this link](https://zeustracker.abuse.ch/blocklist.php?download=badips)

# Comparison of ipsets

Below we compare each ipset against all other.


## alienvault_reputation

[AlienVault.com](https://www.alienvault.com/) IP reputation database (this list seems to include port scanning hosts and to be updated regularly, but we found no information about its retention policy)

Source is downloaded from [this link](https://reputation.alienvault.com/reputation.generic).

The last time downloaded was found to be dated: Mon Jun  8 10:00:40 UTC 2015.

The ipset `alienvault_reputation` has **181932** entries, **181932** unique IPs.

The following table shows the overlaps of `alienvault_reputation` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `alienvault_reputation`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `alienvault_reputation`.
- ` this % ` is the percentage **of this ipset (`alienvault_reputation`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|13876|0.0%|7.6%|
[openbl_60d](#openbl_60d)|7242|7242|7222|99.7%|3.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|6767|0.0%|3.7%|
[et_block](#et_block)|1023|18338662|5278|0.0%|2.9%|
[firehol_level3](#firehol_level3)|107712|9625222|5246|0.0%|2.8%|
[firehol_level1](#firehol_level1)|5086|688943154|4589|0.0%|2.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|4119|0.0%|2.2%|
[dshield](#dshield)|20|5120|3588|70.0%|1.9%|
[openbl_30d](#openbl_30d)|2969|2969|2955|99.5%|1.6%|
[firehol_level2](#firehol_level2)|24806|36416|1559|4.2%|0.8%|
[blocklist_de](#blocklist_de)|31099|31099|1489|4.7%|0.8%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|1374|0.0%|0.7%|
[et_compromised](#et_compromised)|2016|2016|1323|65.6%|0.7%|
[blocklist_de_ssh](#blocklist_de_ssh)|3473|3473|1265|36.4%|0.6%|
[shunlist](#shunlist)|1230|1230|1223|99.4%|0.6%|
[bruteforceblocker](#bruteforceblocker)|1692|1692|1080|63.8%|0.5%|
[openbl_7d](#openbl_7d)|825|825|820|99.3%|0.4%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|518|0.0%|0.2%|
[ciarmy](#ciarmy)|422|422|420|99.5%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|288|0.0%|0.1%|
[stopforumspam_30d](#stopforumspam_30d)|92247|92247|198|0.2%|0.1%|
[voipbl](#voipbl)|10491|10902|196|1.7%|0.1%|
[blocklist_de_apache](#blocklist_de_apache)|16201|16201|122|0.7%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9492|9492|116|1.2%|0.0%|
[openbl_1d](#openbl_1d)|112|112|111|99.1%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29278|29278|95|0.3%|0.0%|
[sslbl](#sslbl)|379|379|64|16.8%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|18693|18693|64|0.3%|0.0%|
[zeus](#zeus)|233|233|62|26.6%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6697|6697|52|0.7%|0.0%|
[firehol_anonymous](#firehol_anonymous)|17786|81795|51|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2813|2813|45|1.5%|0.0%|
[et_tor](#et_tor)|6470|6470|40|0.6%|0.0%|
[dm_tor](#dm_tor)|6454|6454|39|0.6%|0.0%|
[bm_tor](#bm_tor)|6458|6458|39|0.6%|0.0%|
[zeus_badips](#zeus_badips)|204|204|38|18.6%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|158|158|36|22.7%|0.0%|
[firehol_proxies](#firehol_proxies)|11379|11603|32|0.2%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3421|3421|27|0.7%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|26|6.9%|0.0%|
[nixspam](#nixspam)|20667|20667|23|0.1%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4840|4840|19|0.3%|0.0%|
[php_commenters](#php_commenters)|373|373|17|4.5%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|15|0.0%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|90|90|15|16.6%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|14|0.0%|0.0%|
[php_harvesters](#php_harvesters)|341|341|10|2.9%|0.0%|
[malc0de](#malc0de)|351|351|10|2.8%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|10|0.6%|0.0%|
[php_dictionary](#php_dictionary)|589|589|8|1.3%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|320|320|8|2.5%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|7|0.5%|0.0%|
[php_spammers](#php_spammers)|580|580|5|0.8%|0.0%|
[xroxy](#xroxy)|2121|2121|4|0.1%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|319|319|4|1.2%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7066|7066|3|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2581|2581|3|0.1%|0.0%|
[proxz](#proxz)|1039|1039|3|0.2%|0.0%|
[feodo](#feodo)|99|99|2|2.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|1|0.1%|0.0%|

## blocklist_de

[Blocklist.de](https://www.blocklist.de/) IPs that have been detected by fail2ban in the last 48 hours - **excellent list**

Source is downloaded from [this link](http://lists.blocklist.de/lists/all.txt).

The last time downloaded was found to be dated: Mon Jun  8 10:14:05 UTC 2015.

The ipset `blocklist_de` has **31099** entries, **31099** unique IPs.

The following table shows the overlaps of `blocklist_de` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de`.
- ` this % ` is the percentage **of this ipset (`blocklist_de`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|24806|36416|31099|85.3%|100.0%|
[blocklist_de_mail](#blocklist_de_mail)|18693|18693|18693|100.0%|60.1%|
[blocklist_de_apache](#blocklist_de_apache)|16201|16201|16200|99.9%|52.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4840|4840|4840|100.0%|15.5%|
[firehol_level3](#firehol_level3)|107712|9625222|3858|0.0%|12.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|3788|0.0%|12.1%|
[blocklist_de_ssh](#blocklist_de_ssh)|3473|3473|3467|99.8%|11.1%|
[blocklist_de_bots](#blocklist_de_bots)|3421|3421|3421|100.0%|11.0%|
[blocklist_de_imap](#blocklist_de_imap)|2813|2813|2813|100.0%|9.0%|
[stopforumspam_30d](#stopforumspam_30d)|92247|92247|2521|2.7%|8.1%|
[stopforumspam_7d](#stopforumspam_7d)|29278|29278|2142|7.3%|6.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|1562|0.0%|5.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|1550|0.0%|4.9%|
[alienvault_reputation](#alienvault_reputation)|181932|181932|1489|0.8%|4.7%|
[stopforumspam_1d](#stopforumspam_1d)|6697|6697|1409|21.0%|4.5%|
[openbl_60d](#openbl_60d)|7242|7242|1158|15.9%|3.7%|
[openbl_30d](#openbl_30d)|2969|2969|890|29.9%|2.8%|
[nixspam](#nixspam)|20667|20667|890|4.3%|2.8%|
[et_compromised](#et_compromised)|2016|2016|757|37.5%|2.4%|
[bruteforceblocker](#bruteforceblocker)|1692|1692|715|42.2%|2.2%|
[firehol_anonymous](#firehol_anonymous)|17786|81795|600|0.7%|1.9%|
[firehol_proxies](#firehol_proxies)|11379|11603|595|5.1%|1.9%|
[shunlist](#shunlist)|1230|1230|421|34.2%|1.3%|
[openbl_7d](#openbl_7d)|825|825|415|50.3%|1.3%|
[ri_web_proxies](#ri_web_proxies)|7066|7066|404|5.7%|1.2%|
[blocklist_de_ftp](#blocklist_de_ftp)|320|320|320|100.0%|1.0%|
[proxyrss](#proxyrss)|1481|1481|219|14.7%|0.7%|
[snort_ipfilter](#snort_ipfilter)|9492|9492|205|2.1%|0.6%|
[xroxy](#xroxy)|2121|2121|202|9.5%|0.6%|
[firehol_level1](#firehol_level1)|5086|688943154|193|0.0%|0.6%|
[et_block](#et_block)|1023|18338662|185|0.0%|0.5%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|175|0.0%|0.5%|
[blocklist_de_strongips](#blocklist_de_strongips)|158|158|158|100.0%|0.5%|
[proxz](#proxz)|1039|1039|152|14.6%|0.4%|
[dshield](#dshield)|20|5120|113|2.2%|0.3%|
[php_commenters](#php_commenters)|373|373|90|24.1%|0.2%|
[openbl_1d](#openbl_1d)|112|112|83|74.1%|0.2%|
[php_dictionary](#php_dictionary)|589|589|77|13.0%|0.2%|
[ri_connect_proxies](#ri_connect_proxies)|2581|2581|72|2.7%|0.2%|
[php_spammers](#php_spammers)|580|580|71|12.2%|0.2%|
[blocklist_de_sip](#blocklist_de_sip)|90|90|71|78.8%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|45|0.0%|0.1%|
[php_harvesters](#php_harvesters)|341|341|40|11.7%|0.1%|
[voipbl](#voipbl)|10491|10902|34|0.3%|0.1%|
[ciarmy](#ciarmy)|422|422|34|8.0%|0.1%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|12|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|6|0.0%|0.0%|
[et_tor](#et_tor)|6470|6470|5|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|3|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|2|0.1%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|2|0.3%|0.0%|
[dm_tor](#dm_tor)|6454|6454|2|0.0%|0.0%|
[bm_tor](#bm_tor)|6458|6458|2|0.0%|0.0%|
[zeus_badips](#zeus_badips)|204|204|1|0.4%|0.0%|
[zeus](#zeus)|233|233|1|0.4%|0.0%|
[sslbl](#sslbl)|379|379|1|0.2%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|

## blocklist_de_apache

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service Apache, Apache-DDOS, RFI-Attacks.

Source is downloaded from [this link](http://lists.blocklist.de/lists/apache.txt).

The last time downloaded was found to be dated: Mon Jun  8 10:14:12 UTC 2015.

The ipset `blocklist_de_apache` has **16201** entries, **16201** unique IPs.

The following table shows the overlaps of `blocklist_de_apache` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_apache`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_apache`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_apache`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|24806|36416|16200|44.4%|99.9%|
[blocklist_de](#blocklist_de)|31099|31099|16200|52.0%|99.9%|
[blocklist_de_mail](#blocklist_de_mail)|18693|18693|11059|59.1%|68.2%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4840|4840|4840|100.0%|29.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|2450|0.0%|15.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|1311|0.0%|8.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|1082|0.0%|6.6%|
[firehol_level3](#firehol_level3)|107712|9625222|261|0.0%|1.6%|
[stopforumspam_30d](#stopforumspam_30d)|92247|92247|195|0.2%|1.2%|
[alienvault_reputation](#alienvault_reputation)|181932|181932|122|0.0%|0.7%|
[stopforumspam_7d](#stopforumspam_7d)|29278|29278|113|0.3%|0.6%|
[stopforumspam_1d](#stopforumspam_1d)|6697|6697|49|0.7%|0.3%|
[ciarmy](#ciarmy)|422|422|31|7.3%|0.1%|
[blocklist_de_strongips](#blocklist_de_strongips)|158|158|31|19.6%|0.1%|
[shunlist](#shunlist)|1230|1230|29|2.3%|0.1%|
[php_commenters](#php_commenters)|373|373|24|6.4%|0.1%|
[blocklist_de_bots](#blocklist_de_bots)|3421|3421|21|0.6%|0.1%|
[nixspam](#nixspam)|20667|20667|17|0.0%|0.1%|
[snort_ipfilter](#snort_ipfilter)|9492|9492|9|0.0%|0.0%|
[firehol_level1](#firehol_level1)|5086|688943154|8|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|7|0.0%|0.0%|
[et_block](#et_block)|1023|18338662|7|0.0%|0.0%|
[voipbl](#voipbl)|10491|10902|4|0.0%|0.0%|
[php_spammers](#php_spammers)|580|580|4|0.6%|0.0%|
[php_dictionary](#php_dictionary)|589|589|4|0.6%|0.0%|
[openbl_60d](#openbl_60d)|7242|7242|4|0.0%|0.0%|
[et_tor](#et_tor)|6470|6470|4|0.0%|0.0%|
[dshield](#dshield)|20|5120|4|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|3|0.0%|0.0%|
[openbl_30d](#openbl_30d)|2969|2969|3|0.1%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|3|0.0%|0.0%|
[firehol_proxies](#firehol_proxies)|11379|11603|3|0.0%|0.0%|
[firehol_anonymous](#firehol_anonymous)|17786|81795|3|0.0%|0.0%|
[xroxy](#xroxy)|2121|2121|2|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7066|7066|2|0.0%|0.0%|
[proxz](#proxz)|1039|1039|2|0.1%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|1|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2581|2581|1|0.0%|0.0%|
[proxyrss](#proxyrss)|1481|1481|1|0.0%|0.0%|
[php_harvesters](#php_harvesters)|341|341|1|0.2%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|1|0.1%|0.0%|
[dm_tor](#dm_tor)|6454|6454|1|0.0%|0.0%|
[bm_tor](#bm_tor)|6458|6458|1|0.0%|0.0%|

## blocklist_de_bots

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the RFI-Attacks, REG-Bots, IRC-Bots or BadBots (BadBots = he has posted a Spam-Comment on a open Forum or Wiki).

Source is downloaded from [this link](http://lists.blocklist.de/lists/bots.txt).

The last time downloaded was found to be dated: Mon Jun  8 10:14:14 UTC 2015.

The ipset `blocklist_de_bots` has **3421** entries, **3421** unique IPs.

The following table shows the overlaps of `blocklist_de_bots` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_bots`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_bots`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_bots`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|24806|36416|3421|9.3%|100.0%|
[blocklist_de](#blocklist_de)|31099|31099|3421|11.0%|100.0%|
[firehol_level3](#firehol_level3)|107712|9625222|2235|0.0%|65.3%|
[stopforumspam_30d](#stopforumspam_30d)|92247|92247|2214|2.4%|64.7%|
[stopforumspam_7d](#stopforumspam_7d)|29278|29278|1977|6.7%|57.7%|
[stopforumspam_1d](#stopforumspam_1d)|6697|6697|1356|20.2%|39.6%|
[firehol_anonymous](#firehol_anonymous)|17786|81795|510|0.6%|14.9%|
[firehol_proxies](#firehol_proxies)|11379|11603|505|4.3%|14.7%|
[ri_web_proxies](#ri_web_proxies)|7066|7066|344|4.8%|10.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|226|0.0%|6.6%|
[proxyrss](#proxyrss)|1481|1481|217|14.6%|6.3%|
[xroxy](#xroxy)|2121|2121|160|7.5%|4.6%|
[proxz](#proxz)|1039|1039|130|12.5%|3.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|128|0.0%|3.7%|
[blocklist_de_strongips](#blocklist_de_strongips)|158|158|119|75.3%|3.4%|
[php_commenters](#php_commenters)|373|373|75|20.1%|2.1%|
[ri_connect_proxies](#ri_connect_proxies)|2581|2581|68|2.6%|1.9%|
[firehol_level1](#firehol_level1)|5086|688943154|44|0.0%|1.2%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|43|0.0%|1.2%|
[et_block](#et_block)|1023|18338662|43|0.0%|1.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|34|0.0%|0.9%|
[nixspam](#nixspam)|20667|20667|31|0.1%|0.9%|
[php_harvesters](#php_harvesters)|341|341|29|8.5%|0.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|28|0.0%|0.8%|
[alienvault_reputation](#alienvault_reputation)|181932|181932|27|0.0%|0.7%|
[snort_ipfilter](#snort_ipfilter)|9492|9492|21|0.2%|0.6%|
[php_dictionary](#php_dictionary)|589|589|21|3.5%|0.6%|
[blocklist_de_mail](#blocklist_de_mail)|18693|18693|21|0.1%|0.6%|
[blocklist_de_apache](#blocklist_de_apache)|16201|16201|21|0.1%|0.6%|
[php_spammers](#php_spammers)|580|580|19|3.2%|0.5%|
[openbl_60d](#openbl_60d)|7242|7242|11|0.1%|0.3%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|1|0.0%|0.0%|
[openbl_30d](#openbl_30d)|2969|2969|1|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|1|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|1|0.1%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|1|0.0%|0.0%|
[et_tor](#et_tor)|6470|6470|1|0.0%|0.0%|
[dm_tor](#dm_tor)|6454|6454|1|0.0%|0.0%|
[bm_tor](#bm_tor)|6458|6458|1|0.0%|0.0%|

## blocklist_de_bruteforce

[Blocklist.de](https://www.blocklist.de/) All IPs which attacks Joomlas, Wordpress and other Web-Logins with Brute-Force Logins.

Source is downloaded from [this link](http://lists.blocklist.de/lists/bruteforcelogin.txt).

The last time downloaded was found to be dated: Mon Jun  8 10:10:11 UTC 2015.

The ipset `blocklist_de_bruteforce` has **4840** entries, **4840** unique IPs.

The following table shows the overlaps of `blocklist_de_bruteforce` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_bruteforce`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_bruteforce`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_bruteforce`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|24806|36416|4840|13.2%|100.0%|
[blocklist_de_apache](#blocklist_de_apache)|16201|16201|4840|29.8%|100.0%|
[blocklist_de](#blocklist_de)|31099|31099|4840|15.5%|100.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|352|0.0%|7.2%|
[firehol_level3](#firehol_level3)|107712|9625222|56|0.0%|1.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|51|0.0%|1.0%|
[stopforumspam_30d](#stopforumspam_30d)|92247|92247|45|0.0%|0.9%|
[stopforumspam_7d](#stopforumspam_7d)|29278|29278|28|0.0%|0.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|24|0.0%|0.4%|
[alienvault_reputation](#alienvault_reputation)|181932|181932|19|0.0%|0.3%|
[nixspam](#nixspam)|20667|20667|15|0.0%|0.3%|
[stopforumspam_1d](#stopforumspam_1d)|6697|6697|13|0.1%|0.2%|
[php_commenters](#php_commenters)|373|373|7|1.8%|0.1%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|6|0.0%|0.1%|
[blocklist_de_strongips](#blocklist_de_strongips)|158|158|6|3.7%|0.1%|
[snort_ipfilter](#snort_ipfilter)|9492|9492|5|0.0%|0.1%|
[php_spammers](#php_spammers)|580|580|4|0.6%|0.0%|
[php_dictionary](#php_dictionary)|589|589|4|0.6%|0.0%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|3|0.0%|0.0%|
[firehol_level1](#firehol_level1)|5086|688943154|3|0.0%|0.0%|
[et_block](#et_block)|1023|18338662|3|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|2|0.0%|0.0%|
[xroxy](#xroxy)|2121|2121|1|0.0%|0.0%|
[voipbl](#voipbl)|10491|10902|1|0.0%|0.0%|
[shunlist](#shunlist)|1230|1230|1|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7066|7066|1|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2581|2581|1|0.0%|0.0%|
[proxz](#proxz)|1039|1039|1|0.0%|0.0%|
[firehol_proxies](#firehol_proxies)|11379|11603|1|0.0%|0.0%|
[firehol_anonymous](#firehol_anonymous)|17786|81795|1|0.0%|0.0%|
[ciarmy](#ciarmy)|422|422|1|0.2%|0.0%|

## blocklist_de_ftp

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours for attacks on the Service FTP.

Source is downloaded from [this link](http://lists.blocklist.de/lists/ftp.txt).

The last time downloaded was found to be dated: Mon Jun  8 10:14:13 UTC 2015.

The ipset `blocklist_de_ftp` has **320** entries, **320** unique IPs.

The following table shows the overlaps of `blocklist_de_ftp` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_ftp`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_ftp`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_ftp`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|24806|36416|320|0.8%|100.0%|
[blocklist_de](#blocklist_de)|31099|31099|320|1.0%|100.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|27|0.0%|8.4%|
[firehol_level3](#firehol_level3)|107712|9625222|14|0.0%|4.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|10|0.0%|3.1%|
[alienvault_reputation](#alienvault_reputation)|181932|181932|8|0.0%|2.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|7|0.0%|2.1%|
[stopforumspam_30d](#stopforumspam_30d)|92247|92247|6|0.0%|1.8%|
[php_harvesters](#php_harvesters)|341|341|6|1.7%|1.8%|
[stopforumspam_7d](#stopforumspam_7d)|29278|29278|2|0.0%|0.6%|
[openbl_60d](#openbl_60d)|7242|7242|2|0.0%|0.6%|
[stopforumspam_1d](#stopforumspam_1d)|6697|6697|1|0.0%|0.3%|
[snort_ipfilter](#snort_ipfilter)|9492|9492|1|0.0%|0.3%|
[openbl_7d](#openbl_7d)|825|825|1|0.1%|0.3%|
[openbl_30d](#openbl_30d)|2969|2969|1|0.0%|0.3%|
[blocklist_de_strongips](#blocklist_de_strongips)|158|158|1|0.6%|0.3%|

## blocklist_de_imap

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours for attacks on the Service imap, sasl, pop3, etc.

Source is downloaded from [this link](http://lists.blocklist.de/lists/imap.txt).

The last time downloaded was found to be dated: Mon Jun  8 10:10:07 UTC 2015.

The ipset `blocklist_de_imap` has **2813** entries, **2813** unique IPs.

The following table shows the overlaps of `blocklist_de_imap` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_imap`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_imap`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_imap`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|24806|36416|2813|7.7%|100.0%|
[blocklist_de_mail](#blocklist_de_mail)|18693|18693|2813|15.0%|100.0%|
[blocklist_de](#blocklist_de)|31099|31099|2813|9.0%|100.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|229|0.0%|8.1%|
[firehol_level3](#firehol_level3)|107712|9625222|57|0.0%|2.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|49|0.0%|1.7%|
[alienvault_reputation](#alienvault_reputation)|181932|181932|45|0.0%|1.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|36|0.0%|1.2%|
[openbl_60d](#openbl_60d)|7242|7242|34|0.4%|1.2%|
[openbl_30d](#openbl_30d)|2969|2969|30|1.0%|1.0%|
[firehol_level1](#firehol_level1)|5086|688943154|17|0.0%|0.6%|
[et_block](#et_block)|1023|18338662|17|0.0%|0.6%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|16|0.0%|0.5%|
[stopforumspam_30d](#stopforumspam_30d)|92247|92247|14|0.0%|0.4%|
[openbl_7d](#openbl_7d)|825|825|10|1.2%|0.3%|
[firehol_proxies](#firehol_proxies)|11379|11603|10|0.0%|0.3%|
[firehol_anonymous](#firehol_anonymous)|17786|81795|10|0.0%|0.3%|
[ri_web_proxies](#ri_web_proxies)|7066|7066|9|0.1%|0.3%|
[et_compromised](#et_compromised)|2016|2016|8|0.3%|0.2%|
[stopforumspam_7d](#stopforumspam_7d)|29278|29278|7|0.0%|0.2%|
[bruteforceblocker](#bruteforceblocker)|1692|1692|7|0.4%|0.2%|
[snort_ipfilter](#snort_ipfilter)|9492|9492|6|0.0%|0.2%|
[nixspam](#nixspam)|20667|20667|6|0.0%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|0.1%|
[php_dictionary](#php_dictionary)|589|589|2|0.3%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|2|0.0%|0.0%|
[dshield](#dshield)|20|5120|2|0.0%|0.0%|
[zeus_badips](#zeus_badips)|204|204|1|0.4%|0.0%|
[zeus](#zeus)|233|233|1|0.4%|0.0%|
[shunlist](#shunlist)|1230|1230|1|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2581|2581|1|0.0%|0.0%|
[php_spammers](#php_spammers)|580|580|1|0.1%|0.0%|
[php_harvesters](#php_harvesters)|341|341|1|0.2%|0.0%|
[php_commenters](#php_commenters)|373|373|1|0.2%|0.0%|
[openbl_1d](#openbl_1d)|112|112|1|0.8%|0.0%|
[ciarmy](#ciarmy)|422|422|1|0.2%|0.0%|

## blocklist_de_mail

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service Mail, Postfix.

Source is downloaded from [this link](http://lists.blocklist.de/lists/mail.txt).

The last time downloaded was found to be dated: Mon Jun  8 10:14:11 UTC 2015.

The ipset `blocklist_de_mail` has **18693** entries, **18693** unique IPs.

The following table shows the overlaps of `blocklist_de_mail` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_mail`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_mail`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_mail`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|24806|36416|18693|51.3%|100.0%|
[blocklist_de](#blocklist_de)|31099|31099|18693|60.1%|100.0%|
[blocklist_de_apache](#blocklist_de_apache)|16201|16201|11059|68.2%|59.1%|
[blocklist_de_imap](#blocklist_de_imap)|2813|2813|2813|100.0%|15.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|2624|0.0%|14.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|1414|0.0%|7.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|1205|0.0%|6.4%|
[nixspam](#nixspam)|20667|20667|839|4.0%|4.4%|
[firehol_level3](#firehol_level3)|107712|9625222|421|0.0%|2.2%|
[stopforumspam_30d](#stopforumspam_30d)|92247|92247|240|0.2%|1.2%|
[snort_ipfilter](#snort_ipfilter)|9492|9492|177|1.8%|0.9%|
[stopforumspam_7d](#stopforumspam_7d)|29278|29278|138|0.4%|0.7%|
[firehol_proxies](#firehol_proxies)|11379|11603|88|0.7%|0.4%|
[firehol_anonymous](#firehol_anonymous)|17786|81795|88|0.1%|0.4%|
[alienvault_reputation](#alienvault_reputation)|181932|181932|64|0.0%|0.3%|
[ri_web_proxies](#ri_web_proxies)|7066|7066|58|0.8%|0.3%|
[stopforumspam_1d](#stopforumspam_1d)|6697|6697|53|0.7%|0.2%|
[php_dictionary](#php_dictionary)|589|589|52|8.8%|0.2%|
[php_spammers](#php_spammers)|580|580|47|8.1%|0.2%|
[openbl_60d](#openbl_60d)|7242|7242|43|0.5%|0.2%|
[xroxy](#xroxy)|2121|2121|40|1.8%|0.2%|
[openbl_30d](#openbl_30d)|2969|2969|38|1.2%|0.2%|
[php_commenters](#php_commenters)|373|373|22|5.8%|0.1%|
[firehol_level1](#firehol_level1)|5086|688943154|22|0.0%|0.1%|
[et_block](#et_block)|1023|18338662|22|0.0%|0.1%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|21|0.0%|0.1%|
[blocklist_de_strongips](#blocklist_de_strongips)|158|158|21|13.2%|0.1%|
[blocklist_de_bots](#blocklist_de_bots)|3421|3421|21|0.6%|0.1%|
[proxz](#proxz)|1039|1039|20|1.9%|0.1%|
[et_compromised](#et_compromised)|2016|2016|13|0.6%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1692|1692|13|0.7%|0.0%|
[openbl_7d](#openbl_7d)|825|825|12|1.4%|0.0%|
[php_harvesters](#php_harvesters)|341|341|5|1.4%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|5|0.0%|0.0%|
[et_tor](#et_tor)|6470|6470|4|0.0%|0.0%|
[shunlist](#shunlist)|1230|1230|3|0.2%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2581|2581|3|0.1%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|3|0.0%|0.0%|
[dshield](#dshield)|20|5120|3|0.0%|0.0%|
[zeus_badips](#zeus_badips)|204|204|1|0.4%|0.0%|
[zeus](#zeus)|233|233|1|0.4%|0.0%|
[proxyrss](#proxyrss)|1481|1481|1|0.0%|0.0%|
[openbl_1d](#openbl_1d)|112|112|1|0.8%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.0%|
[dm_tor](#dm_tor)|6454|6454|1|0.0%|0.0%|
[ciarmy](#ciarmy)|422|422|1|0.2%|0.0%|
[bm_tor](#bm_tor)|6458|6458|1|0.0%|0.0%|

## blocklist_de_sip

[Blocklist.de](https://www.blocklist.de/) All IP addresses that tried to login in a SIP, VOIP or Asterisk Server and are included in the IPs list from [infiltrated.net](www.infiltrated.net)

Source is downloaded from [this link](http://lists.blocklist.de/lists/sip.txt).

The last time downloaded was found to be dated: Mon Jun  8 10:14:13 UTC 2015.

The ipset `blocklist_de_sip` has **90** entries, **90** unique IPs.

The following table shows the overlaps of `blocklist_de_sip` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_sip`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_sip`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_sip`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|24806|36416|71|0.1%|78.8%|
[blocklist_de](#blocklist_de)|31099|31099|71|0.2%|78.8%|
[voipbl](#voipbl)|10491|10902|30|0.2%|33.3%|
[alienvault_reputation](#alienvault_reputation)|181932|181932|15|0.0%|16.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|12|0.0%|13.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|8|0.0%|8.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|6|0.0%|6.6%|
[firehol_level3](#firehol_level3)|107712|9625222|3|0.0%|3.3%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|2|0.0%|2.2%|
[et_block](#et_block)|1023|18338662|2|0.0%|2.2%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|1|0.0%|1.1%|
[shunlist](#shunlist)|1230|1230|1|0.0%|1.1%|
[firehol_level1](#firehol_level1)|5086|688943154|1|0.0%|1.1%|

## blocklist_de_ssh

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service SSH.

Source is downloaded from [this link](http://lists.blocklist.de/lists/ssh.txt).

The last time downloaded was found to be dated: Mon Jun  8 10:28:05 UTC 2015.

The ipset `blocklist_de_ssh` has **3473** entries, **3473** unique IPs.

The following table shows the overlaps of `blocklist_de_ssh` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_ssh`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_ssh`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_ssh`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|24806|36416|3467|9.5%|99.8%|
[blocklist_de](#blocklist_de)|31099|31099|3467|11.1%|99.8%|
[alienvault_reputation](#alienvault_reputation)|181932|181932|1265|0.6%|36.4%|
[openbl_60d](#openbl_60d)|7242|7242|1098|15.1%|31.6%|
[firehol_level3](#firehol_level3)|107712|9625222|1078|0.0%|31.0%|
[openbl_30d](#openbl_30d)|2969|2969|847|28.5%|24.3%|
[et_compromised](#et_compromised)|2016|2016|743|36.8%|21.3%|
[bruteforceblocker](#bruteforceblocker)|1692|1692|701|41.4%|20.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|525|0.0%|15.1%|
[openbl_7d](#openbl_7d)|825|825|401|48.6%|11.5%|
[shunlist](#shunlist)|1230|1230|388|31.5%|11.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|144|0.0%|4.1%|
[firehol_level1](#firehol_level1)|5086|688943154|118|0.0%|3.3%|
[et_block](#et_block)|1023|18338662|111|0.0%|3.1%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|107|0.0%|3.0%|
[dshield](#dshield)|20|5120|106|2.0%|3.0%|
[openbl_1d](#openbl_1d)|112|112|82|73.2%|2.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|78|0.0%|2.2%|
[blocklist_de_strongips](#blocklist_de_strongips)|158|158|28|17.7%|0.8%|
[stopforumspam_30d](#stopforumspam_30d)|92247|92247|17|0.0%|0.4%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|6|0.0%|0.1%|
[nixspam](#nixspam)|20667|20667|3|0.0%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29278|29278|2|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|2|0.0%|0.0%|
[ciarmy](#ciarmy)|422|422|2|0.4%|0.0%|
[sslbl](#sslbl)|379|379|1|0.2%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|1|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9492|9492|1|0.0%|0.0%|
[php_spammers](#php_spammers)|580|580|1|0.1%|0.0%|
[php_commenters](#php_commenters)|373|373|1|0.2%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|1|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|1|0.0%|0.0%|

## blocklist_de_strongips

[Blocklist.de](https://www.blocklist.de/) All IPs which are older then 2 month and have more then 5.000 attacks.

Source is downloaded from [this link](http://lists.blocklist.de/lists/strongips.txt).

The last time downloaded was found to be dated: Mon Jun  8 10:10:10 UTC 2015.

The ipset `blocklist_de_strongips` has **158** entries, **158** unique IPs.

The following table shows the overlaps of `blocklist_de_strongips` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_strongips`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_strongips`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_strongips`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|24806|36416|158|0.4%|100.0%|
[blocklist_de](#blocklist_de)|31099|31099|158|0.5%|100.0%|
[firehol_level3](#firehol_level3)|107712|9625222|142|0.0%|89.8%|
[blocklist_de_bots](#blocklist_de_bots)|3421|3421|119|3.4%|75.3%|
[stopforumspam_30d](#stopforumspam_30d)|92247|92247|114|0.1%|72.1%|
[stopforumspam_7d](#stopforumspam_7d)|29278|29278|105|0.3%|66.4%|
[stopforumspam_1d](#stopforumspam_1d)|6697|6697|99|1.4%|62.6%|
[alienvault_reputation](#alienvault_reputation)|181932|181932|36|0.0%|22.7%|
[php_commenters](#php_commenters)|373|373|35|9.3%|22.1%|
[blocklist_de_apache](#blocklist_de_apache)|16201|16201|31|0.1%|19.6%|
[blocklist_de_ssh](#blocklist_de_ssh)|3473|3473|28|0.8%|17.7%|
[openbl_60d](#openbl_60d)|7242|7242|25|0.3%|15.8%|
[openbl_7d](#openbl_7d)|825|825|24|2.9%|15.1%|
[openbl_30d](#openbl_30d)|2969|2969|24|0.8%|15.1%|
[shunlist](#shunlist)|1230|1230|21|1.7%|13.2%|
[blocklist_de_mail](#blocklist_de_mail)|18693|18693|21|0.1%|13.2%|
[openbl_1d](#openbl_1d)|112|112|19|16.9%|12.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|16|0.0%|10.1%|
[firehol_level1](#firehol_level1)|5086|688943154|12|0.0%|7.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|6|0.0%|3.7%|
[et_block](#et_block)|1023|18338662|6|0.0%|3.7%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4840|4840|6|0.1%|3.7%|
[xroxy](#xroxy)|2121|2121|5|0.2%|3.1%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|5|0.0%|3.1%|
[php_spammers](#php_spammers)|580|580|5|0.8%|3.1%|
[firehol_proxies](#firehol_proxies)|11379|11603|5|0.0%|3.1%|
[firehol_anonymous](#firehol_anonymous)|17786|81795|5|0.0%|3.1%|
[dshield](#dshield)|20|5120|5|0.0%|3.1%|
[proxyrss](#proxyrss)|1481|1481|4|0.2%|2.5%|
[ri_web_proxies](#ri_web_proxies)|7066|7066|3|0.0%|1.8%|
[proxz](#proxz)|1039|1039|3|0.2%|1.8%|
[php_dictionary](#php_dictionary)|589|589|3|0.5%|1.8%|
[nixspam](#nixspam)|20667|20667|3|0.0%|1.8%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|1.8%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|2|0.0%|1.2%|
[php_harvesters](#php_harvesters)|341|341|2|0.5%|1.2%|
[snort_ipfilter](#snort_ipfilter)|9492|9492|1|0.0%|0.6%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|1|0.0%|0.6%|
[bruteforceblocker](#bruteforceblocker)|1692|1692|1|0.0%|0.6%|
[blocklist_de_ftp](#blocklist_de_ftp)|320|320|1|0.3%|0.6%|

## bm_tor

[torstatus.blutmagie.de](https://torstatus.blutmagie.de) list of all TOR network servers

Source is downloaded from [this link](https://torstatus.blutmagie.de/ip_list_all.php/Tor_ip_list_ALL.csv).

The last time downloaded was found to be dated: Mon Jun  8 10:36:02 UTC 2015.

The ipset `bm_tor` has **6458** entries, **6458** unique IPs.

The following table shows the overlaps of `bm_tor` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `bm_tor`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `bm_tor`.
- ` this % ` is the percentage **of this ipset (`bm_tor`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_anonymous](#firehol_anonymous)|17786|81795|6458|7.8%|100.0%|
[dm_tor](#dm_tor)|6454|6454|6454|100.0%|99.9%|
[et_tor](#et_tor)|6470|6470|5568|86.0%|86.2%|
[firehol_level3](#firehol_level3)|107712|9625222|1093|0.0%|16.9%|
[snort_ipfilter](#snort_ipfilter)|9492|9492|1055|11.1%|16.3%|
[stopforumspam_30d](#stopforumspam_30d)|92247|92247|640|0.6%|9.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|622|0.0%|9.6%|
[stopforumspam_7d](#stopforumspam_7d)|29278|29278|513|1.7%|7.9%|
[firehol_level2](#firehol_level2)|24806|36416|349|0.9%|5.4%|
[stopforumspam_1d](#stopforumspam_1d)|6697|6697|348|5.1%|5.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|185|0.0%|2.8%|
[firehol_proxies](#firehol_proxies)|11379|11603|168|1.4%|2.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|167|0.0%|2.5%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|165|44.3%|2.5%|
[php_commenters](#php_commenters)|373|373|42|11.2%|0.6%|
[alienvault_reputation](#alienvault_reputation)|181932|181932|39|0.0%|0.6%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|22|0.0%|0.3%|
[openbl_60d](#openbl_60d)|7242|7242|20|0.2%|0.3%|
[php_harvesters](#php_harvesters)|341|341|7|2.0%|0.1%|
[et_block](#et_block)|1023|18338662|5|0.0%|0.0%|
[php_spammers](#php_spammers)|580|580|4|0.6%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|4|0.0%|0.0%|
[voipbl](#voipbl)|10491|10902|3|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|3|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7066|7066|3|0.0%|0.0%|
[php_dictionary](#php_dictionary)|589|589|3|0.5%|0.0%|
[firehol_level1](#firehol_level1)|5086|688943154|3|0.0%|0.0%|
[blocklist_de](#blocklist_de)|31099|31099|2|0.0%|0.0%|
[xroxy](#xroxy)|2121|2121|1|0.0%|0.0%|
[shunlist](#shunlist)|1230|1230|1|0.0%|0.0%|
[nixspam](#nixspam)|20667|20667|1|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|18693|18693|1|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3421|3421|1|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|16201|16201|1|0.0%|0.0%|

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
[fullbogons](#fullbogons)|3720|670264216|592708608|88.4%|100.0%|
[firehol_level1](#firehol_level1)|5086|688943154|592708608|86.0%|100.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|4194304|3.0%|0.7%|
[voipbl](#voipbl)|10491|10902|319|2.9%|0.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|5|0.0%|0.0%|
[firehol_level3](#firehol_level3)|107712|9625222|5|0.0%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92247|92247|1|0.0%|0.0%|
[php_harvesters](#php_harvesters)|341|341|1|0.2%|0.0%|
[php_commenters](#php_commenters)|373|373|1|0.2%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.0%|
[ciarmy](#ciarmy)|422|422|1|0.2%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1692|1692|1|0.0%|0.0%|

## bruteforceblocker

[danger.rulez.sk](http://danger.rulez.sk/) IPs detected by [bruteforceblocker](http://danger.rulez.sk/index.php/bruteforceblocker/) (fail2ban alternative for SSH on OpenBSD). This is an automatically generated list from users reporting failed authentication attempts. An IP seems to be included if 3 or more users report it. Its retention pocily seems 30 days.

Source is downloaded from [this link](http://danger.rulez.sk/projects/bruteforceblocker/blist.php).

The last time downloaded was found to be dated: Mon Jun  8 07:45:57 UTC 2015.

The ipset `bruteforceblocker` has **1692** entries, **1692** unique IPs.

The following table shows the overlaps of `bruteforceblocker` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `bruteforceblocker`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `bruteforceblocker`.
- ` this % ` is the percentage **of this ipset (`bruteforceblocker`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level3](#firehol_level3)|107712|9625222|1692|0.0%|100.0%|
[et_compromised](#et_compromised)|2016|2016|1586|78.6%|93.7%|
[alienvault_reputation](#alienvault_reputation)|181932|181932|1080|0.5%|63.8%|
[openbl_60d](#openbl_60d)|7242|7242|983|13.5%|58.0%|
[openbl_30d](#openbl_30d)|2969|2969|936|31.5%|55.3%|
[firehol_level2](#firehol_level2)|24806|36416|719|1.9%|42.4%|
[blocklist_de](#blocklist_de)|31099|31099|715|2.2%|42.2%|
[blocklist_de_ssh](#blocklist_de_ssh)|3473|3473|701|20.1%|41.4%|
[shunlist](#shunlist)|1230|1230|411|33.4%|24.2%|
[openbl_7d](#openbl_7d)|825|825|319|38.6%|18.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|153|0.0%|9.0%|
[firehol_level1](#firehol_level1)|5086|688943154|102|0.0%|6.0%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|101|0.0%|5.9%|
[et_block](#et_block)|1023|18338662|101|0.0%|5.9%|
[dshield](#dshield)|20|5120|95|1.8%|5.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|88|0.0%|5.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|47|0.0%|2.7%|
[openbl_1d](#openbl_1d)|112|112|35|31.2%|2.0%|
[stopforumspam_30d](#stopforumspam_30d)|92247|92247|13|0.0%|0.7%|
[blocklist_de_mail](#blocklist_de_mail)|18693|18693|13|0.0%|0.7%|
[blocklist_de_imap](#blocklist_de_imap)|2813|2813|7|0.2%|0.4%|
[stopforumspam_7d](#stopforumspam_7d)|29278|29278|6|0.0%|0.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|5|0.0%|0.2%|
[firehol_proxies](#firehol_proxies)|11379|11603|3|0.0%|0.1%|
[firehol_anonymous](#firehol_anonymous)|17786|81795|3|0.0%|0.1%|
[voipbl](#voipbl)|10491|10902|2|0.0%|0.1%|
[stopforumspam_1d](#stopforumspam_1d)|6697|6697|2|0.0%|0.1%|
[proxz](#proxz)|1039|1039|2|0.1%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|2|0.0%|0.1%|
[xroxy](#xroxy)|2121|2121|1|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7066|7066|1|0.0%|0.0%|
[php_spammers](#php_spammers)|580|580|1|0.1%|0.0%|
[php_commenters](#php_commenters)|373|373|1|0.2%|0.0%|
[fullbogons](#fullbogons)|3720|670264216|1|0.0%|0.0%|
[ciarmy](#ciarmy)|422|422|1|0.2%|0.0%|
[bogons](#bogons)|13|592708608|1|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|158|158|1|0.6%|0.0%|

## ciarmy

[CIArmy.com](http://ciarmy.com/) IPs with poor Rogue Packet score that have not yet been identified as malicious by the community

Source is downloaded from [this link](http://cinsscore.com/list/ci-badguys.txt).

The last time downloaded was found to be dated: Mon Jun  8 10:15:16 UTC 2015.

The ipset `ciarmy` has **422** entries, **422** unique IPs.

The following table shows the overlaps of `ciarmy` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ciarmy`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ciarmy`.
- ` this % ` is the percentage **of this ipset (`ciarmy`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level3](#firehol_level3)|107712|9625222|422|0.0%|100.0%|
[alienvault_reputation](#alienvault_reputation)|181932|181932|420|0.2%|99.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|82|0.0%|19.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|45|0.0%|10.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|35|0.0%|8.2%|
[firehol_level2](#firehol_level2)|24806|36416|34|0.0%|8.0%|
[blocklist_de](#blocklist_de)|31099|31099|34|0.1%|8.0%|
[shunlist](#shunlist)|1230|1230|33|2.6%|7.8%|
[blocklist_de_apache](#blocklist_de_apache)|16201|16201|31|0.1%|7.3%|
[firehol_level1](#firehol_level1)|5086|688943154|6|0.0%|1.4%|
[et_block](#et_block)|1023|18338662|5|0.0%|1.1%|
[dshield](#dshield)|20|5120|5|0.0%|1.1%|
[voipbl](#voipbl)|10491|10902|4|0.0%|0.9%|
[blocklist_de_ssh](#blocklist_de_ssh)|3473|3473|2|0.0%|0.4%|
[stopforumspam_7d](#stopforumspam_7d)|29278|29278|1|0.0%|0.2%|
[stopforumspam_30d](#stopforumspam_30d)|92247|92247|1|0.0%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.2%|
[fullbogons](#fullbogons)|3720|670264216|1|0.0%|0.2%|
[et_compromised](#et_compromised)|2016|2016|1|0.0%|0.2%|
[bruteforceblocker](#bruteforceblocker)|1692|1692|1|0.0%|0.2%|
[bogons](#bogons)|13|592708608|1|0.0%|0.2%|
[blocklist_de_mail](#blocklist_de_mail)|18693|18693|1|0.0%|0.2%|
[blocklist_de_imap](#blocklist_de_imap)|2813|2813|1|0.0%|0.2%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4840|4840|1|0.0%|0.2%|

## cleanmx_viruses

[Clean-MX.de](http://support.clean-mx.de/clean-mx/viruses.php) IPs with viruses

Source is downloaded from [this link](http://support.clean-mx.de/clean-mx/xmlviruses.php?sort=id%20desc&response=alive).

The last time downloaded was found to be dated: Mon Jun  8 08:18:29 UTC 2015.

The ipset `cleanmx_viruses` has **319** entries, **319** unique IPs.

The following table shows the overlaps of `cleanmx_viruses` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `cleanmx_viruses`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `cleanmx_viruses`.
- ` this % ` is the percentage **of this ipset (`cleanmx_viruses`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level3](#firehol_level3)|107712|9625222|319|0.0%|100.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|36|0.0%|11.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|25|0.0%|7.8%|
[malc0de](#malc0de)|351|351|10|2.8%|3.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|10|0.0%|3.1%|
[alienvault_reputation](#alienvault_reputation)|181932|181932|4|0.0%|1.2%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|3|0.2%|0.9%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|2|0.0%|0.6%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|1|0.0%|0.3%|
[snort_ipfilter](#snort_ipfilter)|9492|9492|1|0.0%|0.3%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|1|0.0%|0.3%|
[firehol_level1](#firehol_level1)|5086|688943154|1|0.0%|0.3%|
[firehol_anonymous](#firehol_anonymous)|17786|81795|1|0.0%|0.3%|

## dm_tor

[dan.me.uk](https://www.dan.me.uk) dynamic list of TOR exit points

Source is downloaded from [this link](https://www.dan.me.uk/torlist/).

The last time downloaded was found to be dated: Mon Jun  8 10:18:04 UTC 2015.

The ipset `dm_tor` has **6454** entries, **6454** unique IPs.

The following table shows the overlaps of `dm_tor` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `dm_tor`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `dm_tor`.
- ` this % ` is the percentage **of this ipset (`dm_tor`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_anonymous](#firehol_anonymous)|17786|81795|6454|7.8%|100.0%|
[bm_tor](#bm_tor)|6458|6458|6454|99.9%|100.0%|
[et_tor](#et_tor)|6470|6470|5566|86.0%|86.2%|
[firehol_level3](#firehol_level3)|107712|9625222|1092|0.0%|16.9%|
[snort_ipfilter](#snort_ipfilter)|9492|9492|1054|11.1%|16.3%|
[stopforumspam_30d](#stopforumspam_30d)|92247|92247|640|0.6%|9.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|622|0.0%|9.6%|
[stopforumspam_7d](#stopforumspam_7d)|29278|29278|513|1.7%|7.9%|
[firehol_level2](#firehol_level2)|24806|36416|349|0.9%|5.4%|
[stopforumspam_1d](#stopforumspam_1d)|6697|6697|348|5.1%|5.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|185|0.0%|2.8%|
[firehol_proxies](#firehol_proxies)|11379|11603|168|1.4%|2.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|167|0.0%|2.5%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|165|44.3%|2.5%|
[php_commenters](#php_commenters)|373|373|42|11.2%|0.6%|
[alienvault_reputation](#alienvault_reputation)|181932|181932|39|0.0%|0.6%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|22|0.0%|0.3%|
[openbl_60d](#openbl_60d)|7242|7242|20|0.2%|0.3%|
[php_harvesters](#php_harvesters)|341|341|7|2.0%|0.1%|
[et_block](#et_block)|1023|18338662|5|0.0%|0.0%|
[php_spammers](#php_spammers)|580|580|4|0.6%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|4|0.0%|0.0%|
[voipbl](#voipbl)|10491|10902|3|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|3|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7066|7066|3|0.0%|0.0%|
[php_dictionary](#php_dictionary)|589|589|3|0.5%|0.0%|
[firehol_level1](#firehol_level1)|5086|688943154|3|0.0%|0.0%|
[blocklist_de](#blocklist_de)|31099|31099|2|0.0%|0.0%|
[xroxy](#xroxy)|2121|2121|1|0.0%|0.0%|
[shunlist](#shunlist)|1230|1230|1|0.0%|0.0%|
[nixspam](#nixspam)|20667|20667|1|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|18693|18693|1|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3421|3421|1|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|16201|16201|1|0.0%|0.0%|

## dshield

[DShield.org](https://dshield.org/) top 20 attacking class C (/24) subnets over the last three days - **excellent list**

Source is downloaded from [this link](http://feeds.dshield.org/block.txt).

The last time downloaded was found to be dated: Mon Jun  8 07:56:42 UTC 2015.

The ipset `dshield` has **20** entries, **5120** unique IPs.

The following table shows the overlaps of `dshield` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `dshield`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `dshield`.
- ` this % ` is the percentage **of this ipset (`dshield`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level1](#firehol_level1)|5086|688943154|5120|0.0%|100.0%|
[alienvault_reputation](#alienvault_reputation)|181932|181932|3588|1.9%|70.0%|
[et_block](#et_block)|1023|18338662|1792|0.0%|35.0%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|768|0.0%|15.0%|
[firehol_level3](#firehol_level3)|107712|9625222|379|0.0%|7.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|256|0.0%|5.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|256|0.0%|5.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|256|0.0%|5.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|256|0.0%|5.0%|
[firehol_level2](#firehol_level2)|24806|36416|113|0.3%|2.2%|
[blocklist_de](#blocklist_de)|31099|31099|113|0.3%|2.2%|
[openbl_60d](#openbl_60d)|7242|7242|112|1.5%|2.1%|
[openbl_30d](#openbl_30d)|2969|2969|112|3.7%|2.1%|
[blocklist_de_ssh](#blocklist_de_ssh)|3473|3473|106|3.0%|2.0%|
[shunlist](#shunlist)|1230|1230|101|8.2%|1.9%|
[bruteforceblocker](#bruteforceblocker)|1692|1692|95|5.6%|1.8%|
[et_compromised](#et_compromised)|2016|2016|94|4.6%|1.8%|
[openbl_7d](#openbl_7d)|825|825|41|4.9%|0.8%|
[openbl_1d](#openbl_1d)|112|112|10|8.9%|0.1%|
[ciarmy](#ciarmy)|422|422|5|1.1%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|158|158|5|3.1%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|16201|16201|4|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|18693|18693|3|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2813|2813|2|0.0%|0.0%|
[malc0de](#malc0de)|351|351|1|0.2%|0.0%|

## et_block

[EmergingThreats.net](http://www.emergingthreats.net/) default blacklist (at the time of writing includes spamhaus DROP, dshield and abuse.ch trackers, which are available separately too - prefer to use the direct ipsets instead of this, they seem to lag a bit in updates)

Source is downloaded from [this link](http://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt).

The last time downloaded was found to be dated: Fri Jun  5 04:30:01 UTC 2015.

The ipset `et_block` has **1023** entries, **18338662** unique IPs.

The following table shows the overlaps of `et_block` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `et_block`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `et_block`.
- ` this % ` is the percentage **of this ipset (`et_block`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level1](#firehol_level1)|5086|688943154|18056248|2.6%|98.4%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|18054912|98.4%|98.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|8598311|2.4%|46.8%|
[firehol_level3](#firehol_level3)|107712|9625222|7080788|73.5%|38.6%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|7079936|77.1%|38.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|2272276|0.2%|12.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|195933|0.1%|1.0%|
[fullbogons](#fullbogons)|3720|670264216|20480|0.0%|0.1%|
[alienvault_reputation](#alienvault_reputation)|181932|181932|5278|2.9%|0.0%|
[dshield](#dshield)|20|5120|1792|35.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1040|0.3%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92247|92247|1008|1.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|517|0.1%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9492|9492|315|3.3%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29278|29278|304|1.0%|0.0%|
[openbl_60d](#openbl_60d)|7242|7242|250|3.4%|0.0%|
[firehol_level2](#firehol_level2)|24806|36416|249|0.6%|0.0%|
[zeus](#zeus)|233|233|222|95.2%|0.0%|
[zeus_badips](#zeus_badips)|204|204|200|98.0%|0.0%|
[blocklist_de](#blocklist_de)|31099|31099|185|0.5%|0.0%|
[openbl_30d](#openbl_30d)|2969|2969|129|4.3%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3473|3473|111|3.1%|0.0%|
[shunlist](#shunlist)|1230|1230|108|8.7%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1692|1692|101|5.9%|0.0%|
[et_compromised](#et_compromised)|2016|2016|100|4.9%|0.0%|
[feodo](#feodo)|99|99|94|94.9%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6697|6697|82|1.2%|0.0%|
[openbl_7d](#openbl_7d)|825|825|46|5.5%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3421|3421|43|1.2%|0.0%|
[sslbl](#sslbl)|379|379|35|9.2%|0.0%|
[php_commenters](#php_commenters)|373|373|29|7.7%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|29|2.2%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|18693|18693|22|0.1%|0.0%|
[voipbl](#voipbl)|10491|10902|18|0.1%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2813|2813|17|0.6%|0.0%|
[palevo](#palevo)|13|13|12|92.3%|0.0%|
[firehol_anonymous](#firehol_anonymous)|17786|81795|8|0.0%|0.0%|
[openbl_1d](#openbl_1d)|112|112|7|6.2%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|16201|16201|7|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|6|0.4%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|158|158|6|3.7%|0.0%|
[php_dictionary](#php_dictionary)|589|589|5|0.8%|0.0%|
[malc0de](#malc0de)|351|351|5|1.4%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|5|0.0%|0.0%|
[dm_tor](#dm_tor)|6454|6454|5|0.0%|0.0%|
[ciarmy](#ciarmy)|422|422|5|1.1%|0.0%|
[bm_tor](#bm_tor)|6458|6458|5|0.0%|0.0%|
[et_tor](#et_tor)|6470|6470|4|0.0%|0.0%|
[php_spammers](#php_spammers)|580|580|3|0.5%|0.0%|
[firehol_proxies](#firehol_proxies)|11379|11603|3|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4840|4840|3|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|2|0.3%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|90|90|2|2.2%|0.0%|
[php_harvesters](#php_harvesters)|341|341|1|0.2%|0.0%|
[nixspam](#nixspam)|20667|20667|1|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|

## et_botcc

[EmergingThreats.net Command and Control IPs](http://doc.emergingthreats.net/bin/view/Main/BotCC) These IPs are updates every 24 hours and should be considered VERY highly reliable indications that a host is communicating with a known and active Bot or Malware command and control server - (although they say this includes abuse.ch trackers, it does not - most probably it is the shadowserver.org C&C list)

Source is downloaded from [this link](http://rules.emergingthreats.net/fwrules/emerging-PIX-CC.rules).

The last time downloaded was found to be dated: Fri Jun  5 04:30:01 UTC 2015.

The ipset `et_botcc` has **0** entries, **0** unique IPs.

The following table shows the overlaps of `et_botcc` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `et_botcc`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `et_botcc`.
- ` this % ` is the percentage **of this ipset (`et_botcc`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|

## et_compromised

[EmergingThreats.net compromised hosts](http://doc.emergingthreats.net/bin/view/Main/CompromisedHost) - (this seems to be based on bruteforceblocker)

Source is downloaded from [this link](http://rules.emergingthreats.net/blockrules/compromised-ips.txt).

The last time downloaded was found to be dated: Fri Jun  5 04:30:08 UTC 2015.

The ipset `et_compromised` has **2016** entries, **2016** unique IPs.

The following table shows the overlaps of `et_compromised` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `et_compromised`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `et_compromised`.
- ` this % ` is the percentage **of this ipset (`et_compromised`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level3](#firehol_level3)|107712|9625222|1785|0.0%|88.5%|
[bruteforceblocker](#bruteforceblocker)|1692|1692|1586|93.7%|78.6%|
[alienvault_reputation](#alienvault_reputation)|181932|181932|1323|0.7%|65.6%|
[openbl_60d](#openbl_60d)|7242|7242|1222|16.8%|60.6%|
[openbl_30d](#openbl_30d)|2969|2969|1104|37.1%|54.7%|
[firehol_level2](#firehol_level2)|24806|36416|759|2.0%|37.6%|
[blocklist_de](#blocklist_de)|31099|31099|757|2.4%|37.5%|
[blocklist_de_ssh](#blocklist_de_ssh)|3473|3473|743|21.3%|36.8%|
[shunlist](#shunlist)|1230|1230|429|34.8%|21.2%|
[openbl_7d](#openbl_7d)|825|825|338|40.9%|16.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|199|0.0%|9.8%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|100|0.0%|4.9%|
[firehol_level1](#firehol_level1)|5086|688943154|100|0.0%|4.9%|
[et_block](#et_block)|1023|18338662|100|0.0%|4.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|97|0.0%|4.8%|
[dshield](#dshield)|20|5120|94|1.8%|4.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|52|0.0%|2.5%|
[openbl_1d](#openbl_1d)|112|112|34|30.3%|1.6%|
[blocklist_de_mail](#blocklist_de_mail)|18693|18693|13|0.0%|0.6%|
[stopforumspam_30d](#stopforumspam_30d)|92247|92247|11|0.0%|0.5%|
[blocklist_de_imap](#blocklist_de_imap)|2813|2813|8|0.2%|0.3%|
[stopforumspam_7d](#stopforumspam_7d)|29278|29278|6|0.0%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|5|0.0%|0.2%|
[firehol_proxies](#firehol_proxies)|11379|11603|3|0.0%|0.1%|
[firehol_anonymous](#firehol_anonymous)|17786|81795|3|0.0%|0.1%|
[voipbl](#voipbl)|10491|10902|2|0.0%|0.0%|
[proxz](#proxz)|1039|1039|2|0.1%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|2|0.0%|0.0%|
[xroxy](#xroxy)|2121|2121|1|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6697|6697|1|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7066|7066|1|0.0%|0.0%|
[ciarmy](#ciarmy)|422|422|1|0.2%|0.0%|

## et_tor

[EmergingThreats.net](http://www.emergingthreats.net/) [list](http://doc.emergingthreats.net/bin/view/Main/TorRules) of TOR network IPs

Source is downloaded from [this link](http://rules.emergingthreats.net/blockrules/emerging-tor.rules).

The last time downloaded was found to be dated: Fri Jun  5 04:30:10 UTC 2015.

The ipset `et_tor` has **6470** entries, **6470** unique IPs.

The following table shows the overlaps of `et_tor` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `et_tor`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `et_tor`.
- ` this % ` is the percentage **of this ipset (`et_tor`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_anonymous](#firehol_anonymous)|17786|81795|5575|6.8%|86.1%|
[bm_tor](#bm_tor)|6458|6458|5568|86.2%|86.0%|
[dm_tor](#dm_tor)|6454|6454|5566|86.2%|86.0%|
[firehol_level3](#firehol_level3)|107712|9625222|1103|0.0%|17.0%|
[snort_ipfilter](#snort_ipfilter)|9492|9492|1059|11.1%|16.3%|
[stopforumspam_30d](#stopforumspam_30d)|92247|92247|660|0.7%|10.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|633|0.0%|9.7%|
[stopforumspam_7d](#stopforumspam_7d)|29278|29278|530|1.8%|8.1%|
[firehol_level2](#firehol_level2)|24806|36416|345|0.9%|5.3%|
[stopforumspam_1d](#stopforumspam_1d)|6697|6697|341|5.0%|5.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|189|0.0%|2.9%|
[firehol_proxies](#firehol_proxies)|11379|11603|173|1.4%|2.6%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|168|45.1%|2.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|168|0.0%|2.5%|
[php_commenters](#php_commenters)|373|373|43|11.5%|0.6%|
[alienvault_reputation](#alienvault_reputation)|181932|181932|40|0.0%|0.6%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|22|0.0%|0.3%|
[openbl_60d](#openbl_60d)|7242|7242|20|0.2%|0.3%|
[php_harvesters](#php_harvesters)|341|341|7|2.0%|0.1%|
[php_spammers](#php_spammers)|580|580|6|1.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7066|7066|5|0.0%|0.0%|
[php_dictionary](#php_dictionary)|589|589|5|0.8%|0.0%|
[blocklist_de](#blocklist_de)|31099|31099|5|0.0%|0.0%|
[et_block](#et_block)|1023|18338662|4|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|18693|18693|4|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|16201|16201|4|0.0%|0.0%|
[voipbl](#voipbl)|10491|10902|3|0.0%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|0.0%|
[xroxy](#xroxy)|2121|2121|2|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|2|0.0%|0.0%|
[firehol_level1](#firehol_level1)|5086|688943154|2|0.0%|0.0%|
[shunlist](#shunlist)|1230|1230|1|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2581|2581|1|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3421|3421|1|0.0%|0.0%|

## feodo

[Abuse.ch Feodo tracker](https://feodotracker.abuse.ch) trojan includes IPs which are being used by Feodo (also known as Cridex or Bugat) which commits ebanking fraud - **excellent list**

Source is downloaded from [this link](https://feodotracker.abuse.ch/blocklist/?download=ipblocklist).

The last time downloaded was found to be dated: Mon Jun  8 10:36:10 UTC 2015.

The ipset `feodo` has **99** entries, **99** unique IPs.

The following table shows the overlaps of `feodo` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `feodo`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `feodo`.
- ` this % ` is the percentage **of this ipset (`feodo`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level1](#firehol_level1)|5086|688943154|99|0.0%|100.0%|
[et_block](#et_block)|1023|18338662|94|0.0%|94.9%|
[snort_ipfilter](#snort_ipfilter)|9492|9492|79|0.8%|79.7%|
[firehol_level3](#firehol_level3)|107712|9625222|79|0.0%|79.7%|
[sslbl](#sslbl)|379|379|36|9.4%|36.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|11|0.0%|11.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|3|0.0%|3.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|3|0.0%|3.0%|
[alienvault_reputation](#alienvault_reputation)|181932|181932|2|0.0%|2.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|1.0%|

## firehol_anonymous

**FireHOL Anonymous** - Known anonymizing IPs. (includes: firehol_proxies anonymous bm_tor dm_tor)

Source is downloaded from [this link]().

The last time downloaded was found to be dated: Sun Jun  7 22:20:34 UTC 2015.

The ipset `firehol_anonymous` has **17786** entries, **81795** unique IPs.

The following table shows the overlaps of `firehol_anonymous` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `firehol_anonymous`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `firehol_anonymous`.
- ` this % ` is the percentage **of this ipset (`firehol_anonymous`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_proxies](#firehol_proxies)|11379|11603|11603|100.0%|14.1%|
[ri_web_proxies](#ri_web_proxies)|7066|7066|7066|100.0%|8.6%|
[bm_tor](#bm_tor)|6458|6458|6458|100.0%|7.8%|
[dm_tor](#dm_tor)|6454|6454|6454|100.0%|7.8%|
[firehol_level3](#firehol_level3)|107712|9625222|6256|0.0%|7.6%|
[stopforumspam_30d](#stopforumspam_30d)|92247|92247|5743|6.2%|7.0%|
[et_tor](#et_tor)|6470|6470|5575|86.1%|6.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|3420|0.0%|4.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|2866|0.0%|3.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|2828|0.0%|3.4%|
[stopforumspam_7d](#stopforumspam_7d)|29278|29278|2816|9.6%|3.4%|
[ri_connect_proxies](#ri_connect_proxies)|2581|2581|2581|100.0%|3.1%|
[xroxy](#xroxy)|2121|2121|2121|100.0%|2.5%|
[proxyrss](#proxyrss)|1481|1481|1481|100.0%|1.8%|
[firehol_level2](#firehol_level2)|24806|36416|1353|3.7%|1.6%|
[snort_ipfilter](#snort_ipfilter)|9492|9492|1143|12.0%|1.3%|
[stopforumspam_1d](#stopforumspam_1d)|6697|6697|1060|15.8%|1.2%|
[proxz](#proxz)|1039|1039|1039|100.0%|1.2%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|663|100.0%|0.8%|
[blocklist_de](#blocklist_de)|31099|31099|600|1.9%|0.7%|
[blocklist_de_bots](#blocklist_de_bots)|3421|3421|510|14.9%|0.6%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|372|100.0%|0.4%|
[blocklist_de_mail](#blocklist_de_mail)|18693|18693|88|0.4%|0.1%|
[nixspam](#nixspam)|20667|20667|79|0.3%|0.0%|
[voipbl](#voipbl)|10491|10902|78|0.7%|0.0%|
[php_dictionary](#php_dictionary)|589|589|75|12.7%|0.0%|
[php_commenters](#php_commenters)|373|373|70|18.7%|0.0%|
[php_spammers](#php_spammers)|580|580|64|11.0%|0.0%|
[alienvault_reputation](#alienvault_reputation)|181932|181932|51|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|27|0.0%|0.0%|
[openbl_60d](#openbl_60d)|7242|7242|23|0.3%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|15|0.0%|0.0%|
[php_harvesters](#php_harvesters)|341|341|13|3.8%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2813|2813|10|0.3%|0.0%|
[et_block](#et_block)|1023|18338662|8|0.0%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|7|0.0%|0.0%|
[firehol_level1](#firehol_level1)|5086|688943154|7|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|6|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|158|158|5|3.1%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|3|0.2%|0.0%|
[et_compromised](#et_compromised)|2016|2016|3|0.1%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1692|1692|3|0.1%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|16201|16201|3|0.0%|0.0%|
[sslbl](#sslbl)|379|379|1|0.2%|0.0%|
[shunlist](#shunlist)|1230|1230|1|0.0%|0.0%|
[openbl_30d](#openbl_30d)|2969|2969|1|0.0%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|319|319|1|0.3%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4840|4840|1|0.0%|0.0%|

## firehol_level1

**FireHOL Level 1** - Maximum protection without false positives. (includes: fullbogons dshield feodo palevo sslbl zeus spamhaus_drop spamhaus_edrop)

Source is downloaded from [this link]().

The last time downloaded was found to be dated: Sun Jun  7 22:15:43 UTC 2015.

The ipset `firehol_level1` has **5086** entries, **688943154** unique IPs.

The following table shows the overlaps of `firehol_level1` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `firehol_level1`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `firehol_level1`.
- ` this % ` is the percentage **of this ipset (`firehol_level1`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[fullbogons](#fullbogons)|3720|670264216|670264216|100.0%|97.2%|
[bogons](#bogons)|13|592708608|592708608|100.0%|86.0%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|18338560|100.0%|2.6%|
[et_block](#et_block)|1023|18338662|18056248|98.4%|2.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|8864387|2.5%|1.2%|
[firehol_level3](#firehol_level3)|107712|9625222|7499647|77.9%|1.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|7497728|81.6%|1.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|4637283|3.3%|0.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|2545681|0.3%|0.3%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|487424|100.0%|0.0%|
[dshield](#dshield)|20|5120|5120|100.0%|0.0%|
[alienvault_reputation](#alienvault_reputation)|181932|181932|4589|2.5%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1932|0.5%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92247|92247|1098|1.1%|0.0%|
[sslbl](#sslbl)|379|379|379|100.0%|0.0%|
[voipbl](#voipbl)|10491|10902|333|3.0%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29278|29278|321|1.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9492|9492|300|3.1%|0.0%|
[firehol_level2](#firehol_level2)|24806|36416|264|0.7%|0.0%|
[openbl_60d](#openbl_60d)|7242|7242|250|3.4%|0.0%|
[zeus](#zeus)|233|233|233|100.0%|0.0%|
[zeus_badips](#zeus_badips)|204|204|204|100.0%|0.0%|
[blocklist_de](#blocklist_de)|31099|31099|193|0.6%|0.0%|
[shunlist](#shunlist)|1230|1230|161|13.0%|0.0%|
[openbl_30d](#openbl_30d)|2969|2969|134|4.5%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3473|3473|118|3.3%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1692|1692|102|6.0%|0.0%|
[et_compromised](#et_compromised)|2016|2016|100|4.9%|0.0%|
[feodo](#feodo)|99|99|99|100.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6697|6697|90|1.3%|0.0%|
[openbl_7d](#openbl_7d)|825|825|48|5.8%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3421|3421|44|1.2%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|39|2.6%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|38|2.9%|0.0%|
[php_commenters](#php_commenters)|373|373|37|9.9%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|18693|18693|22|0.1%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|18|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2813|2813|17|0.6%|0.0%|
[palevo](#palevo)|13|13|13|100.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|158|158|12|7.5%|0.0%|
[openbl_1d](#openbl_1d)|112|112|11|9.8%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|16201|16201|8|0.0%|0.0%|
[firehol_anonymous](#firehol_anonymous)|17786|81795|7|0.0%|0.0%|
[malc0de](#malc0de)|351|351|6|1.7%|0.0%|
[ciarmy](#ciarmy)|422|422|6|1.4%|0.0%|
[php_dictionary](#php_dictionary)|589|589|5|0.8%|0.0%|
[php_spammers](#php_spammers)|580|580|4|0.6%|0.0%|
[php_harvesters](#php_harvesters)|341|341|3|0.8%|0.0%|
[firehol_proxies](#firehol_proxies)|11379|11603|3|0.0%|0.0%|
[dm_tor](#dm_tor)|6454|6454|3|0.0%|0.0%|
[bm_tor](#bm_tor)|6458|6458|3|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4840|4840|3|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|2|0.3%|0.0%|
[et_tor](#et_tor)|6470|6470|2|0.0%|0.0%|
[virbl](#virbl)|4|4|1|25.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7066|7066|1|0.0%|0.0%|
[nixspam](#nixspam)|20667|20667|1|0.0%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|319|319|1|0.3%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|90|90|1|1.1%|0.0%|

## firehol_level2

**FireHOL Level 2** - Maximum protection from attacks took place in the last 48 hours. (includes: openbl_1d blocklist_de stopforumspam_1d)

Source is downloaded from [this link]().

The last time downloaded was found to be dated: Sun Jun  7 22:20:34 UTC 2015.

The ipset `firehol_level2` has **24806** entries, **36416** unique IPs.

The following table shows the overlaps of `firehol_level2` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `firehol_level2`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `firehol_level2`.
- ` this % ` is the percentage **of this ipset (`firehol_level2`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|31099|31099|31099|100.0%|85.3%|
[blocklist_de_mail](#blocklist_de_mail)|18693|18693|18693|100.0%|51.3%|
[blocklist_de_apache](#blocklist_de_apache)|16201|16201|16200|99.9%|44.4%|
[firehol_level3](#firehol_level3)|107712|9625222|8259|0.0%|22.6%|
[stopforumspam_30d](#stopforumspam_30d)|92247|92247|6884|7.4%|18.9%|
[stopforumspam_1d](#stopforumspam_1d)|6697|6697|6697|100.0%|18.3%|
[stopforumspam_7d](#stopforumspam_7d)|29278|29278|6355|21.7%|17.4%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4840|4840|4840|100.0%|13.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|4219|0.0%|11.5%|
[blocklist_de_ssh](#blocklist_de_ssh)|3473|3473|3467|99.8%|9.5%|
[blocklist_de_bots](#blocklist_de_bots)|3421|3421|3421|100.0%|9.3%|
[blocklist_de_imap](#blocklist_de_imap)|2813|2813|2813|100.0%|7.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|1685|0.0%|4.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|1677|0.0%|4.6%|
[alienvault_reputation](#alienvault_reputation)|181932|181932|1559|0.8%|4.2%|
[firehol_anonymous](#firehol_anonymous)|17786|81795|1353|1.6%|3.7%|
[openbl_60d](#openbl_60d)|7242|7242|1206|16.6%|3.3%|
[firehol_proxies](#firehol_proxies)|11379|11603|1146|9.8%|3.1%|
[openbl_30d](#openbl_30d)|2969|2969|918|30.9%|2.5%|
[nixspam](#nixspam)|20667|20667|895|4.3%|2.4%|
[et_compromised](#et_compromised)|2016|2016|759|37.6%|2.0%|
[bruteforceblocker](#bruteforceblocker)|1692|1692|719|42.4%|1.9%|
[ri_web_proxies](#ri_web_proxies)|7066|7066|697|9.8%|1.9%|
[snort_ipfilter](#snort_ipfilter)|9492|9492|565|5.9%|1.5%|
[openbl_7d](#openbl_7d)|825|825|443|53.6%|1.2%|
[shunlist](#shunlist)|1230|1230|425|34.5%|1.1%|
[proxyrss](#proxyrss)|1481|1481|399|26.9%|1.0%|
[xroxy](#xroxy)|2121|2121|360|16.9%|0.9%|
[dm_tor](#dm_tor)|6454|6454|349|5.4%|0.9%|
[bm_tor](#bm_tor)|6458|6458|349|5.4%|0.9%|
[et_tor](#et_tor)|6470|6470|345|5.3%|0.9%|
[blocklist_de_ftp](#blocklist_de_ftp)|320|320|320|100.0%|0.8%|
[firehol_level1](#firehol_level1)|5086|688943154|264|0.0%|0.7%|
[et_block](#et_block)|1023|18338662|249|0.0%|0.6%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|244|0.0%|0.6%|
[proxz](#proxz)|1039|1039|239|23.0%|0.6%|
[ri_connect_proxies](#ri_connect_proxies)|2581|2581|192|7.4%|0.5%|
[php_commenters](#php_commenters)|373|373|169|45.3%|0.4%|
[blocklist_de_strongips](#blocklist_de_strongips)|158|158|158|100.0%|0.4%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|157|42.2%|0.4%|
[dshield](#dshield)|20|5120|113|2.2%|0.3%|
[openbl_1d](#openbl_1d)|112|112|112|100.0%|0.3%|
[php_dictionary](#php_dictionary)|589|589|83|14.0%|0.2%|
[php_spammers](#php_spammers)|580|580|78|13.4%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|77|0.0%|0.2%|
[blocklist_de_sip](#blocklist_de_sip)|90|90|71|78.8%|0.1%|
[php_harvesters](#php_harvesters)|341|341|55|16.1%|0.1%|
[voipbl](#voipbl)|10491|10902|37|0.3%|0.1%|
[ciarmy](#ciarmy)|422|422|34|8.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|13|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|12|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|6|0.9%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|5|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|3|0.2%|0.0%|
[zeus_badips](#zeus_badips)|204|204|2|0.9%|0.0%|
[zeus](#zeus)|233|233|2|0.8%|0.0%|
[sslbl](#sslbl)|379|379|1|0.2%|0.0%|

## firehol_level3

**FireHOL Level 3** - All the bad IPs in last 30 days. (includes: openbl_30d stopforumspam_30d virbl malc0de shunlist malwaredomainlist bruteforceblocker ciarmy cleanmx_viruses snort_ipfilter ib_bluetack_spyware ib_bluetack_hijacked ib_bluetack_webexploit php_commenters php_dictionary php_harvesters php_spammers)

Source is downloaded from [this link]().

The last time downloaded was found to be dated: Sun Jun  7 22:20:34 UTC 2015.

The ipset `firehol_level3` has **107712** entries, **9625222** unique IPs.

The following table shows the overlaps of `firehol_level3` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `firehol_level3`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `firehol_level3`.
- ` this % ` is the percentage **of this ipset (`firehol_level3`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|9177856|100.0%|95.3%|
[firehol_level1](#firehol_level1)|5086|688943154|7499647|1.0%|77.9%|
[et_block](#et_block)|1023|18338662|7080788|38.6%|73.5%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|6933025|37.8%|72.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|2537272|0.7%|26.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|919945|0.1%|9.5%|
[fullbogons](#fullbogons)|3720|670264216|566182|0.0%|5.8%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|339173|100.0%|3.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|161471|0.1%|1.6%|
[stopforumspam_30d](#stopforumspam_30d)|92247|92247|92247|100.0%|0.9%|
[stopforumspam_7d](#stopforumspam_7d)|29278|29278|29205|99.7%|0.3%|
[snort_ipfilter](#snort_ipfilter)|9492|9492|9492|100.0%|0.0%|
[firehol_level2](#firehol_level2)|24806|36416|8259|22.6%|0.0%|
[firehol_anonymous](#firehol_anonymous)|17786|81795|6256|7.6%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6697|6697|5665|84.5%|0.0%|
[alienvault_reputation](#alienvault_reputation)|181932|181932|5246|2.8%|0.0%|
[firehol_proxies](#firehol_proxies)|11379|11603|5155|44.4%|0.0%|
[blocklist_de](#blocklist_de)|31099|31099|3858|12.4%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7066|7066|3411|48.2%|0.0%|
[openbl_60d](#openbl_60d)|7242|7242|3088|42.6%|0.0%|
[openbl_30d](#openbl_30d)|2969|2969|2969|100.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3421|3421|2235|65.3%|0.0%|
[et_compromised](#et_compromised)|2016|2016|1785|88.5%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1692|1692|1692|100.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2581|2581|1474|57.1%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|1450|100.0%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|1288|100.0%|0.0%|
[xroxy](#xroxy)|2121|2121|1268|59.7%|0.0%|
[shunlist](#shunlist)|1230|1230|1230|100.0%|0.0%|
[et_tor](#et_tor)|6470|6470|1103|17.0%|0.0%|
[bm_tor](#bm_tor)|6458|6458|1093|16.9%|0.0%|
[dm_tor](#dm_tor)|6454|6454|1092|16.9%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3473|3473|1078|31.0%|0.0%|
[openbl_7d](#openbl_7d)|825|825|825|100.0%|0.0%|
[proxyrss](#proxyrss)|1481|1481|724|48.8%|0.0%|
[proxz](#proxz)|1039|1039|632|60.8%|0.0%|
[php_dictionary](#php_dictionary)|589|589|589|100.0%|0.0%|
[php_spammers](#php_spammers)|580|580|580|100.0%|0.0%|
[nixspam](#nixspam)|20667|20667|506|2.4%|0.0%|
[ciarmy](#ciarmy)|422|422|422|100.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|18693|18693|421|2.2%|0.0%|
[dshield](#dshield)|20|5120|379|7.4%|0.0%|
[php_commenters](#php_commenters)|373|373|373|100.0%|0.0%|
[malc0de](#malc0de)|351|351|351|100.0%|0.0%|
[php_harvesters](#php_harvesters)|341|341|341|100.0%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|319|319|319|100.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|16201|16201|261|1.6%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|233|62.6%|0.0%|
[zeus](#zeus)|233|233|205|87.9%|0.0%|
[zeus_badips](#zeus_badips)|204|204|182|89.2%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|158|158|142|89.8%|0.0%|
[openbl_1d](#openbl_1d)|112|112|110|98.2%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|90|0.0%|0.0%|
[sslbl](#sslbl)|379|379|89|23.4%|0.0%|
[feodo](#feodo)|99|99|79|79.7%|0.0%|
[voipbl](#voipbl)|10491|10902|60|0.5%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2813|2813|57|2.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4840|4840|56|1.1%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|25|3.7%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|25|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|320|320|14|4.3%|0.0%|
[palevo](#palevo)|13|13|11|84.6%|0.0%|
[bogons](#bogons)|13|592708608|5|0.0%|0.0%|
[virbl](#virbl)|4|4|4|100.0%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|90|90|3|3.3%|0.0%|

## firehol_proxies

**FireHOL Proxies** - Known open proxies in the last 30 days. (includes: ib_bluetack_proxies maxmind_proxy_fraud proxyrss proxz ri_connect_proxies ri_web_proxies xroxy)

Source is downloaded from [this link]().

The last time downloaded was found to be dated: Sun Jun  7 22:20:34 UTC 2015.

The ipset `firehol_proxies` has **11379** entries, **11603** unique IPs.

The following table shows the overlaps of `firehol_proxies` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `firehol_proxies`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `firehol_proxies`.
- ` this % ` is the percentage **of this ipset (`firehol_proxies`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_anonymous](#firehol_anonymous)|17786|81795|11603|14.1%|100.0%|
[ri_web_proxies](#ri_web_proxies)|7066|7066|7066|100.0%|60.8%|
[firehol_level3](#firehol_level3)|107712|9625222|5155|0.0%|44.4%|
[stopforumspam_30d](#stopforumspam_30d)|92247|92247|5098|5.5%|43.9%|
[ri_connect_proxies](#ri_connect_proxies)|2581|2581|2581|100.0%|22.2%|
[stopforumspam_7d](#stopforumspam_7d)|29278|29278|2418|8.2%|20.8%|
[xroxy](#xroxy)|2121|2121|2121|100.0%|18.2%|
[proxyrss](#proxyrss)|1481|1481|1481|100.0%|12.7%|
[firehol_level2](#firehol_level2)|24806|36416|1146|3.1%|9.8%|
[proxz](#proxz)|1039|1039|1039|100.0%|8.9%|
[stopforumspam_1d](#stopforumspam_1d)|6697|6697|857|12.7%|7.3%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|663|100.0%|5.7%|
[blocklist_de](#blocklist_de)|31099|31099|595|1.9%|5.1%|
[blocklist_de_bots](#blocklist_de_bots)|3421|3421|505|14.7%|4.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|481|0.0%|4.1%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|372|100.0%|3.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|360|0.0%|3.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|272|0.0%|2.3%|
[snort_ipfilter](#snort_ipfilter)|9492|9492|252|2.6%|2.1%|
[et_tor](#et_tor)|6470|6470|173|2.6%|1.4%|
[dm_tor](#dm_tor)|6454|6454|168|2.6%|1.4%|
[bm_tor](#bm_tor)|6458|6458|168|2.6%|1.4%|
[blocklist_de_mail](#blocklist_de_mail)|18693|18693|88|0.4%|0.7%|
[nixspam](#nixspam)|20667|20667|78|0.3%|0.6%|
[php_dictionary](#php_dictionary)|589|589|74|12.5%|0.6%|
[php_commenters](#php_commenters)|373|373|64|17.1%|0.5%|
[php_spammers](#php_spammers)|580|580|62|10.6%|0.5%|
[alienvault_reputation](#alienvault_reputation)|181932|181932|32|0.0%|0.2%|
[openbl_60d](#openbl_60d)|7242|7242|18|0.2%|0.1%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|15|0.0%|0.1%|
[php_harvesters](#php_harvesters)|341|341|12|3.5%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|10|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2813|2813|10|0.3%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|158|158|5|3.1%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|3|0.2%|0.0%|
[firehol_level1](#firehol_level1)|5086|688943154|3|0.0%|0.0%|
[et_compromised](#et_compromised)|2016|2016|3|0.1%|0.0%|
[et_block](#et_block)|1023|18338662|3|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1692|1692|3|0.1%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|16201|16201|3|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|2|0.0%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2|0.0%|0.0%|
[voipbl](#voipbl)|10491|10902|1|0.0%|0.0%|
[sslbl](#sslbl)|379|379|1|0.2%|0.0%|
[shunlist](#shunlist)|1230|1230|1|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4840|4840|1|0.0%|0.0%|

## fullbogons

[Team-Cymru.org](http://www.team-cymru.org) IP space that has been allocated to an RIR, but not assigned by that RIR to an actual ISP or other end-user - **excellent list - use it only your internet interface**

Source is downloaded from [this link](http://www.team-cymru.org/Services/Bogons/fullbogons-ipv4.txt).

The last time downloaded was found to be dated: Mon Jun  8 09:35:05 UTC 2015.

The ipset `fullbogons` has **3720** entries, **670264216** unique IPs.

The following table shows the overlaps of `fullbogons` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `fullbogons`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `fullbogons`.
- ` this % ` is the percentage **of this ipset (`fullbogons`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level1](#firehol_level1)|5086|688943154|670264216|97.2%|100.0%|
[bogons](#bogons)|13|592708608|592708608|100.0%|88.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|4235823|3.0%|0.6%|
[firehol_level3](#firehol_level3)|107712|9625222|566182|5.8%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|565248|6.1%|0.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|249087|0.0%|0.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|239993|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|151552|0.8%|0.0%|
[et_block](#et_block)|1023|18338662|20480|0.1%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|890|0.2%|0.0%|
[voipbl](#voipbl)|10491|10902|319|2.9%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|33|2.2%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|13|0.0%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|9|0.6%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92247|92247|2|0.0%|0.0%|
[php_harvesters](#php_harvesters)|341|341|1|0.2%|0.0%|
[php_commenters](#php_commenters)|373|373|1|0.2%|0.0%|
[ciarmy](#ciarmy)|422|422|1|0.2%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1692|1692|1|0.0%|0.0%|

## ib_bluetack_badpeers

[iBlocklist.com](https://www.iblocklist.com/) free version of [BlueTack.co.uk](http://www.bluetack.co.uk/) IPs that have been reported for bad deeds in p2p

Source is downloaded from [this link](http://list.iblocklist.com/?list=cwworuawihqvocglcoss&fileformat=p2p&archiveformat=gz).

The last time downloaded was found to be dated: Mon Jun  8 05:10:44 UTC 2015.

The ipset `ib_bluetack_badpeers` has **47940** entries, **47940** unique IPs.

The following table shows the overlaps of `ib_bluetack_badpeers` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ib_bluetack_badpeers`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ib_bluetack_badpeers`.
- ` this % ` is the percentage **of this ipset (`ib_bluetack_badpeers`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|1172|0.0%|2.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|394|0.0%|0.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|226|0.0%|0.4%|
[firehol_level3](#firehol_level3)|107712|9625222|25|0.0%|0.0%|
[firehol_level1](#firehol_level1)|5086|688943154|18|0.0%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92247|92247|15|0.0%|0.0%|
[firehol_proxies](#firehol_proxies)|11379|11603|15|0.1%|0.0%|
[firehol_anonymous](#firehol_anonymous)|17786|81795|15|0.0%|0.0%|
[alienvault_reputation](#alienvault_reputation)|181932|181932|14|0.0%|0.0%|
[fullbogons](#fullbogons)|3720|670264216|13|0.0%|0.0%|
[firehol_level2](#firehol_level2)|24806|36416|12|0.0%|0.0%|
[blocklist_de](#blocklist_de)|31099|31099|12|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|11|1.6%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|16201|16201|7|0.0%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29278|29278|6|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4840|4840|6|0.1%|0.0%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|5|0.0%|0.0%|
[et_block](#et_block)|1023|18338662|5|0.0%|0.0%|
[nixspam](#nixspam)|20667|20667|4|0.0%|0.0%|
[xroxy](#xroxy)|2121|2121|3|0.1%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9492|9492|3|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7066|7066|3|0.0%|0.0%|
[php_dictionary](#php_dictionary)|589|589|3|0.5%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|3|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|18693|18693|3|0.0%|0.0%|
[voipbl](#voipbl)|10491|10902|2|0.0%|0.0%|
[php_harvesters](#php_harvesters)|341|341|2|0.5%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2813|2813|2|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6697|6697|1|0.0%|0.0%|
[proxz](#proxz)|1039|1039|1|0.0%|0.0%|
[php_spammers](#php_spammers)|580|580|1|0.1%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|1|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3473|3473|1|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3421|3421|1|0.0%|0.0%|

## ib_bluetack_hijacked

[iBlocklist.com](https://www.iblocklist.com/) free version of [BlueTack.co.uk](http://www.bluetack.co.uk/) hijacked IP-Blocks Hijacked IP space are IP blocks that are being used without permission

Source is downloaded from [this link](http://list.iblocklist.com/?list=usrcshglbiilevmyfhse&fileformat=p2p&archiveformat=gz).

The last time downloaded was found to be dated: Mon Jun  8 05:40:38 UTC 2015.

The ipset `ib_bluetack_hijacked` has **535** entries, **9177856** unique IPs.

The following table shows the overlaps of `ib_bluetack_hijacked` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ib_bluetack_hijacked`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ib_bluetack_hijacked`.
- ` this % ` is the percentage **of this ipset (`ib_bluetack_hijacked`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level3](#firehol_level3)|107712|9625222|9177856|95.3%|100.0%|
[firehol_level1](#firehol_level1)|5086|688943154|7497728|1.0%|81.6%|
[et_block](#et_block)|1023|18338662|7079936|38.6%|77.1%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|6932480|37.8%|75.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|2526625|0.7%|27.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|904796|0.1%|9.8%|
[fullbogons](#fullbogons)|3720|670264216|565248|0.0%|6.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|145472|0.1%|1.5%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1036|0.3%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92247|92247|732|0.7%|0.0%|
[alienvault_reputation](#alienvault_reputation)|181932|181932|518|0.2%|0.0%|
[dshield](#dshield)|20|5120|256|5.0%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29278|29278|158|0.5%|0.0%|
[firehol_level2](#firehol_level2)|24806|36416|77|0.2%|0.0%|
[blocklist_de](#blocklist_de)|31099|31099|45|0.1%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6697|6697|40|0.5%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3421|3421|34|0.9%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|27|2.0%|0.0%|
[openbl_60d](#openbl_60d)|7242|7242|17|0.2%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9492|9492|12|0.1%|0.0%|
[openbl_30d](#openbl_30d)|2969|2969|12|0.4%|0.0%|
[zeus_badips](#zeus_badips)|204|204|10|4.9%|0.0%|
[zeus](#zeus)|233|233|10|4.2%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|7|0.4%|0.0%|
[firehol_anonymous](#firehol_anonymous)|17786|81795|7|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3473|3473|6|0.1%|0.0%|
[openbl_7d](#openbl_7d)|825|825|5|0.6%|0.0%|
[et_compromised](#et_compromised)|2016|2016|5|0.2%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1692|1692|5|0.2%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|18693|18693|5|0.0%|0.0%|
[dm_tor](#dm_tor)|6454|6454|4|0.0%|0.0%|
[bm_tor](#bm_tor)|6458|6458|4|0.0%|0.0%|
[shunlist](#shunlist)|1230|1230|3|0.2%|0.0%|
[php_spammers](#php_spammers)|580|580|3|0.5%|0.0%|
[php_dictionary](#php_dictionary)|589|589|3|0.5%|0.0%|
[et_tor](#et_tor)|6470|6470|3|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|158|158|3|1.8%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2813|2813|3|0.1%|0.0%|
[openbl_1d](#openbl_1d)|112|112|2|1.7%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|2|0.3%|0.0%|
[firehol_proxies](#firehol_proxies)|11379|11603|2|0.0%|0.0%|
[voipbl](#voipbl)|10491|10902|1|0.0%|0.0%|
[php_harvesters](#php_harvesters)|341|341|1|0.2%|0.0%|
[php_commenters](#php_commenters)|373|373|1|0.2%|0.0%|

## ib_bluetack_level1

[iBlocklist.com](https://www.iblocklist.com/) free version of [BlueTack.co.uk](http://www.bluetack.co.uk/) Level 1 (for use in p2p): Companies or organizations who are clearly involved with trying to stop filesharing (e.g. Baytsp, MediaDefender, Mediasentry a.o.). Companies which anti-p2p activity has been seen from. Companies that produce or have a strong financial interest in copyrighted material (e.g. music, movie, software industries a.o.). Government ranges or companies that have a strong financial interest in doing work for governments. Legal industry ranges. IPs or ranges of ISPs from which anti-p2p activity has been observed. Basically this list will block all kinds of internet connections that most people would rather not have during their internet travels.

Source is downloaded from [this link](http://list.iblocklist.com/?list=ydxerpxkpcfqjaybcssw&fileformat=p2p&archiveformat=gz).

The last time downloaded was found to be dated: Mon Jun  8 09:48:28 UTC 2015.

The ipset `ib_bluetack_level1` has **218307** entries, **764993634** unique IPs.

The following table shows the overlaps of `ib_bluetack_level1` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ib_bluetack_level1`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ib_bluetack_level1`.
- ` this % ` is the percentage **of this ipset (`ib_bluetack_level1`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|16302420|4.6%|2.1%|
[firehol_level1](#firehol_level1)|5086|688943154|2545681|0.3%|0.3%|
[et_block](#et_block)|1023|18338662|2272276|12.3%|0.2%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|2272265|12.3%|0.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|1354507|0.9%|0.1%|
[firehol_level3](#firehol_level3)|107712|9625222|919945|9.5%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|904796|9.8%|0.1%|
[fullbogons](#fullbogons)|3720|670264216|239993|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|33155|6.8%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|13247|3.9%|0.0%|
[alienvault_reputation](#alienvault_reputation)|181932|181932|4119|2.2%|0.0%|
[firehol_anonymous](#firehol_anonymous)|17786|81795|3420|4.1%|0.0%|
[firehol_level2](#firehol_level2)|24806|36416|1677|4.6%|0.0%|
[blocklist_de](#blocklist_de)|31099|31099|1562|5.0%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92247|92247|1511|1.6%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|18693|18693|1414|7.5%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|16201|16201|1311|8.0%|0.0%|
[nixspam](#nixspam)|20667|20667|582|2.8%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29278|29278|558|1.9%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|394|0.8%|0.0%|
[voipbl](#voipbl)|10491|10902|299|2.7%|0.0%|
[firehol_proxies](#firehol_proxies)|11379|11603|272|2.3%|0.0%|
[dshield](#dshield)|20|5120|256|5.0%|0.0%|
[et_tor](#et_tor)|6470|6470|168|2.5%|0.0%|
[openbl_60d](#openbl_60d)|7242|7242|167|2.3%|0.0%|
[dm_tor](#dm_tor)|6454|6454|167|2.5%|0.0%|
[bm_tor](#bm_tor)|6458|6458|167|2.5%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7066|7066|137|1.9%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6697|6697|129|1.9%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|97|6.6%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9492|9492|87|0.9%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2581|2581|79|3.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3473|3473|78|2.2%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|66|5.1%|0.0%|
[openbl_30d](#openbl_30d)|2969|2969|64|2.1%|0.0%|
[xroxy](#xroxy)|2121|2121|58|2.7%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|56|8.4%|0.0%|
[et_compromised](#et_compromised)|2016|2016|52|2.5%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1692|1692|47|2.7%|0.0%|
[proxz](#proxz)|1039|1039|37|3.5%|0.0%|
[proxyrss](#proxyrss)|1481|1481|36|2.4%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2813|2813|36|1.2%|0.0%|
[ciarmy](#ciarmy)|422|422|35|8.2%|0.0%|
[shunlist](#shunlist)|1230|1230|28|2.2%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3421|3421|28|0.8%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|319|319|25|7.8%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4840|4840|24|0.4%|0.0%|
[openbl_7d](#openbl_7d)|825|825|18|2.1%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|17|4.5%|0.0%|
[php_harvesters](#php_harvesters)|341|341|11|3.2%|0.0%|
[php_dictionary](#php_dictionary)|589|589|11|1.8%|0.0%|
[malc0de](#malc0de)|351|351|11|3.1%|0.0%|
[php_commenters](#php_commenters)|373|373|9|2.4%|0.0%|
[php_spammers](#php_spammers)|580|580|8|1.3%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|320|320|7|2.1%|0.0%|
[zeus](#zeus)|233|233|6|2.5%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|90|90|6|6.6%|0.0%|
[bogons](#bogons)|13|592708608|5|0.0%|0.0%|
[zeus_badips](#zeus_badips)|204|204|4|1.9%|0.0%|
[sslbl](#sslbl)|379|379|3|0.7%|0.0%|
[feodo](#feodo)|99|99|3|3.0%|0.0%|

## ib_bluetack_level2

[iBlocklist.com](https://www.iblocklist.com/) free version of BlueTack.co.uk Level 2 (for use in p2p). General corporate ranges. Ranges used by labs or researchers. Proxies.

Source is downloaded from [this link](http://list.iblocklist.com/?list=gyisgnzbhppbvsphucsw&fileformat=p2p&archiveformat=gz).

The last time downloaded was found to be dated: Mon Jun  8 05:40:33 UTC 2015.

The ipset `ib_bluetack_level2` has **72950** entries, **348710251** unique IPs.

The following table shows the overlaps of `ib_bluetack_level2` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ib_bluetack_level2`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ib_bluetack_level2`.
- ` this % ` is the percentage **of this ipset (`ib_bluetack_level2`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|16302420|2.1%|4.6%|
[firehol_level1](#firehol_level1)|5086|688943154|8864387|1.2%|2.5%|
[et_block](#et_block)|1023|18338662|8598311|46.8%|2.4%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|8532506|46.5%|2.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|2830203|2.0%|0.8%|
[firehol_level3](#firehol_level3)|107712|9625222|2537272|26.3%|0.7%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2526625|27.5%|0.7%|
[fullbogons](#fullbogons)|3720|670264216|249087|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|98904|20.2%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|7728|2.2%|0.0%|
[alienvault_reputation](#alienvault_reputation)|181932|181932|6767|3.7%|0.0%|
[firehol_anonymous](#firehol_anonymous)|17786|81795|2866|3.5%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92247|92247|2489|2.6%|0.0%|
[firehol_level2](#firehol_level2)|24806|36416|1685|4.6%|0.0%|
[blocklist_de](#blocklist_de)|31099|31099|1550|4.9%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|18693|18693|1205|6.4%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|16201|16201|1082|6.6%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29278|29278|853|2.9%|0.0%|
[nixspam](#nixspam)|20667|20667|725|3.5%|0.0%|
[voipbl](#voipbl)|10491|10902|434|3.9%|0.0%|
[firehol_proxies](#firehol_proxies)|11379|11603|360|3.1%|0.0%|
[openbl_60d](#openbl_60d)|7242|7242|328|4.5%|0.0%|
[dshield](#dshield)|20|5120|256|5.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|226|0.4%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7066|7066|205|2.9%|0.0%|
[et_tor](#et_tor)|6470|6470|189|2.9%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6697|6697|188|2.8%|0.0%|
[dm_tor](#dm_tor)|6454|6454|185|2.8%|0.0%|
[bm_tor](#bm_tor)|6458|6458|185|2.8%|0.0%|
[openbl_30d](#openbl_30d)|2969|2969|152|5.1%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3473|3473|144|4.1%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3421|3421|128|3.7%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9492|9492|122|1.2%|0.0%|
[xroxy](#xroxy)|2121|2121|104|4.9%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2581|2581|99|3.8%|0.0%|
[et_compromised](#et_compromised)|2016|2016|97|4.8%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1692|1692|88|5.2%|0.0%|
[shunlist](#shunlist)|1230|1230|65|5.2%|0.0%|
[proxyrss](#proxyrss)|1481|1481|51|3.4%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4840|4840|51|1.0%|0.0%|
[php_spammers](#php_spammers)|580|580|49|8.4%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2813|2813|49|1.7%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|45|3.1%|0.0%|
[ciarmy](#ciarmy)|422|422|45|10.6%|0.0%|
[openbl_7d](#openbl_7d)|825|825|44|5.3%|0.0%|
[proxz](#proxz)|1039|1039|41|3.9%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|26|2.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|26|3.9%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|21|5.6%|0.0%|
[malc0de](#malc0de)|351|351|21|5.9%|0.0%|
[php_dictionary](#php_dictionary)|589|589|20|3.3%|0.0%|
[php_commenters](#php_commenters)|373|373|15|4.0%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|319|319|10|3.1%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|320|320|10|3.1%|0.0%|
[zeus](#zeus)|233|233|9|3.8%|0.0%|
[php_harvesters](#php_harvesters)|341|341|9|2.6%|0.0%|
[zeus_badips](#zeus_badips)|204|204|8|3.9%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|90|90|8|8.8%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|158|158|6|3.7%|0.0%|
[sslbl](#sslbl)|379|379|4|1.0%|0.0%|
[palevo](#palevo)|13|13|3|23.0%|0.0%|
[openbl_1d](#openbl_1d)|112|112|3|2.6%|0.0%|
[feodo](#feodo)|99|99|3|3.0%|0.0%|

## ib_bluetack_level3

[iBlocklist.com](https://www.iblocklist.com/) free version of BlueTack.co.uk Level 3 (for use in p2p). Many portal-type websites. ISP ranges that may be dodgy for some reason. Ranges that belong to an individual, but which have not been determined to be used by a particular company. Ranges for things that are unusual in some way. The L3 list is aka the paranoid list.

Source is downloaded from [this link](http://list.iblocklist.com/?list=uwnukjqktoggdknzrhgh&fileformat=p2p&archiveformat=gz).

The last time downloaded was found to be dated: Mon Jun  8 05:40:42 UTC 2015.

The ipset `ib_bluetack_level3` has **17812** entries, **139104927** unique IPs.

The following table shows the overlaps of `ib_bluetack_level3` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ib_bluetack_level3`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ib_bluetack_level3`.
- ` this % ` is the percentage **of this ipset (`ib_bluetack_level3`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level1](#firehol_level1)|5086|688943154|4637283|0.6%|3.3%|
[fullbogons](#fullbogons)|3720|670264216|4235823|0.6%|3.0%|
[bogons](#bogons)|13|592708608|4194304|0.7%|3.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|2830203|0.8%|2.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|1354507|0.1%|0.9%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|270785|55.5%|0.1%|
[et_block](#et_block)|1023|18338662|195933|1.0%|0.1%|
[firehol_level3](#firehol_level3)|107712|9625222|161471|1.6%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|145472|1.5%|0.1%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|130368|0.7%|0.0%|
[alienvault_reputation](#alienvault_reputation)|181932|181932|13876|7.6%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|9226|2.7%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92247|92247|5743|6.2%|0.0%|
[firehol_level2](#firehol_level2)|24806|36416|4219|11.5%|0.0%|
[blocklist_de](#blocklist_de)|31099|31099|3788|12.1%|0.0%|
[firehol_anonymous](#firehol_anonymous)|17786|81795|2828|3.4%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|18693|18693|2624|14.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|16201|16201|2450|15.1%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29278|29278|1899|6.4%|0.0%|
[voipbl](#voipbl)|10491|10902|1600|14.6%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|1172|2.4%|0.0%|
[nixspam](#nixspam)|20667|20667|798|3.8%|0.0%|
[openbl_60d](#openbl_60d)|7242|7242|741|10.2%|0.0%|
[et_tor](#et_tor)|6470|6470|633|9.7%|0.0%|
[dm_tor](#dm_tor)|6454|6454|622|9.6%|0.0%|
[bm_tor](#bm_tor)|6458|6458|622|9.6%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3473|3473|525|15.1%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6697|6697|493|7.3%|0.0%|
[firehol_proxies](#firehol_proxies)|11379|11603|481|4.1%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4840|4840|352|7.2%|0.0%|
[openbl_30d](#openbl_30d)|2969|2969|300|10.1%|0.0%|
[dshield](#dshield)|20|5120|256|5.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9492|9492|230|2.4%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2813|2813|229|8.1%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3421|3421|226|6.6%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7066|7066|199|2.8%|0.0%|
[et_compromised](#et_compromised)|2016|2016|199|9.8%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1692|1692|153|9.0%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|147|11.4%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|125|33.6%|0.0%|
[shunlist](#shunlist)|1230|1230|113|9.1%|0.0%|
[openbl_7d](#openbl_7d)|825|825|112|13.5%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|108|7.4%|0.0%|
[xroxy](#xroxy)|2121|2121|100|4.7%|0.0%|
[proxz](#proxz)|1039|1039|87|8.3%|0.0%|
[ciarmy](#ciarmy)|422|422|82|19.4%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2581|2581|54|2.0%|0.0%|
[proxyrss](#proxyrss)|1481|1481|54|3.6%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|51|7.6%|0.0%|
[malc0de](#malc0de)|351|351|48|13.6%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|319|319|36|11.2%|0.0%|
[php_spammers](#php_spammers)|580|580|32|5.5%|0.0%|
[php_dictionary](#php_dictionary)|589|589|31|5.2%|0.0%|
[sslbl](#sslbl)|379|379|29|7.6%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|320|320|27|8.4%|0.0%|
[php_commenters](#php_commenters)|373|373|24|6.4%|0.0%|
[php_harvesters](#php_harvesters)|341|341|18|5.2%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|158|158|16|10.1%|0.0%|
[zeus](#zeus)|233|233|14|6.0%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|90|90|12|13.3%|0.0%|
[feodo](#feodo)|99|99|11|11.1%|0.0%|
[zeus_badips](#zeus_badips)|204|204|10|4.9%|0.0%|
[openbl_1d](#openbl_1d)|112|112|8|7.1%|0.0%|
[palevo](#palevo)|13|13|1|7.6%|0.0%|

## ib_bluetack_proxies

[iBlocklist.com](https://www.iblocklist.com/) free version of [BlueTack.co.uk](http://www.bluetack.co.uk/) Open Proxies IPs list (without TOR)

Source is downloaded from [this link](http://list.iblocklist.com/?list=xoebmbyexwuiogmbyprb&fileformat=p2p&archiveformat=gz).

The last time downloaded was found to be dated: Mon Jun  8 05:40:40 UTC 2015.

The ipset `ib_bluetack_proxies` has **663** entries, **663** unique IPs.

The following table shows the overlaps of `ib_bluetack_proxies` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ib_bluetack_proxies`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ib_bluetack_proxies`.
- ` this % ` is the percentage **of this ipset (`ib_bluetack_proxies`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_proxies](#firehol_proxies)|11379|11603|663|5.7%|100.0%|
[firehol_anonymous](#firehol_anonymous)|17786|81795|663|0.8%|100.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|56|0.0%|8.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|51|0.0%|7.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|26|0.0%|3.9%|
[firehol_level3](#firehol_level3)|107712|9625222|25|0.0%|3.7%|
[stopforumspam_30d](#stopforumspam_30d)|92247|92247|20|0.0%|3.0%|
[xroxy](#xroxy)|2121|2121|13|0.6%|1.9%|
[stopforumspam_7d](#stopforumspam_7d)|29278|29278|13|0.0%|1.9%|
[ri_web_proxies](#ri_web_proxies)|7066|7066|13|0.1%|1.9%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|11|0.0%|1.6%|
[ri_connect_proxies](#ri_connect_proxies)|2581|2581|7|0.2%|1.0%|
[stopforumspam_1d](#stopforumspam_1d)|6697|6697|6|0.0%|0.9%|
[proxz](#proxz)|1039|1039|6|0.5%|0.9%|
[proxyrss](#proxyrss)|1481|1481|6|0.4%|0.9%|
[firehol_level2](#firehol_level2)|24806|36416|6|0.0%|0.9%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|2|0.0%|0.3%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|2|0.1%|0.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2|0.0%|0.3%|
[firehol_level1](#firehol_level1)|5086|688943154|2|0.0%|0.3%|
[et_block](#et_block)|1023|18338662|2|0.0%|0.3%|
[blocklist_de](#blocklist_de)|31099|31099|2|0.0%|0.3%|
[snort_ipfilter](#snort_ipfilter)|9492|9492|1|0.0%|0.1%|
[php_dictionary](#php_dictionary)|589|589|1|0.1%|0.1%|
[nixspam](#nixspam)|20667|20667|1|0.0%|0.1%|
[blocklist_de_bots](#blocklist_de_bots)|3421|3421|1|0.0%|0.1%|
[blocklist_de_apache](#blocklist_de_apache)|16201|16201|1|0.0%|0.1%|
[alienvault_reputation](#alienvault_reputation)|181932|181932|1|0.0%|0.1%|

## ib_bluetack_spyware

[iBlocklist.com](https://www.iblocklist.com/) free version of [BlueTack.co.uk](http://www.bluetack.co.uk/) known malicious SPYWARE and ADWARE IP Address ranges

Source is downloaded from [this link](http://list.iblocklist.com/?list=llvtlsjyoyiczbkjsxpf&fileformat=p2p&archiveformat=gz).

The last time downloaded was found to be dated: Mon Jun  8 05:10:02 UTC 2015.

The ipset `ib_bluetack_spyware` has **3267** entries, **339173** unique IPs.

The following table shows the overlaps of `ib_bluetack_spyware` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ib_bluetack_spyware`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ib_bluetack_spyware`.
- ` this % ` is the percentage **of this ipset (`ib_bluetack_spyware`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level3](#firehol_level3)|107712|9625222|339173|3.5%|100.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|13247|0.0%|3.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|9226|0.0%|2.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|7728|0.0%|2.2%|
[firehol_level1](#firehol_level1)|5086|688943154|1932|0.0%|0.5%|
[et_block](#et_block)|1023|18338662|1040|0.0%|0.3%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|1037|0.0%|0.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1036|0.0%|0.3%|
[fullbogons](#fullbogons)|3720|670264216|890|0.0%|0.2%|
[alienvault_reputation](#alienvault_reputation)|181932|181932|288|0.1%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92247|92247|46|0.0%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|27|2.0%|0.0%|
[firehol_anonymous](#firehol_anonymous)|17786|81795|27|0.0%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29278|29278|22|0.0%|0.0%|
[et_tor](#et_tor)|6470|6470|22|0.3%|0.0%|
[dm_tor](#dm_tor)|6454|6454|22|0.3%|0.0%|
[bm_tor](#bm_tor)|6458|6458|22|0.3%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|19|1.3%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9492|9492|15|0.1%|0.0%|
[firehol_level2](#firehol_level2)|24806|36416|13|0.0%|0.0%|
[firehol_proxies](#firehol_proxies)|11379|11603|10|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6697|6697|7|0.1%|0.0%|
[blocklist_de](#blocklist_de)|31099|31099|6|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7066|7066|5|0.0%|0.0%|
[openbl_60d](#openbl_60d)|7242|7242|5|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|5|1.3%|0.0%|
[voipbl](#voipbl)|10491|10902|4|0.0%|0.0%|
[openbl_30d](#openbl_30d)|2969|2969|4|0.1%|0.0%|
[malc0de](#malc0de)|351|351|3|0.8%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|3|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|16201|16201|3|0.0%|0.0%|
[palevo](#palevo)|13|13|2|15.3%|0.0%|
[et_compromised](#et_compromised)|2016|2016|2|0.0%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|319|319|2|0.6%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1692|1692|2|0.1%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3473|3473|2|0.0%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|90|90|2|2.2%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4840|4840|2|0.0%|0.0%|
[zeus_badips](#zeus_badips)|204|204|1|0.4%|0.0%|
[zeus](#zeus)|233|233|1|0.4%|0.0%|
[xroxy](#xroxy)|2121|2121|1|0.0%|0.0%|
[sslbl](#sslbl)|379|379|1|0.2%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|1|0.0%|0.0%|
[shunlist](#shunlist)|1230|1230|1|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2581|2581|1|0.0%|0.0%|
[php_harvesters](#php_harvesters)|341|341|1|0.2%|0.0%|
[php_dictionary](#php_dictionary)|589|589|1|0.1%|0.0%|
[php_commenters](#php_commenters)|373|373|1|0.2%|0.0%|
[feodo](#feodo)|99|99|1|1.0%|0.0%|
[ciarmy](#ciarmy)|422|422|1|0.2%|0.0%|
[bogons](#bogons)|13|592708608|1|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|18693|18693|1|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3421|3421|1|0.0%|0.0%|

## ib_bluetack_webexploit

[iBlocklist.com](https://www.iblocklist.com/) free version of [BlueTack.co.uk](http://www.bluetack.co.uk/) web server hack and exploit attempts

Source is downloaded from [this link](http://list.iblocklist.com/?list=ghlzqtqxnzctvvajwwag&fileformat=p2p&archiveformat=gz).

The last time downloaded was found to be dated: Mon Jun  8 05:10:14 UTC 2015.

The ipset `ib_bluetack_webexploit` has **1450** entries, **1450** unique IPs.

The following table shows the overlaps of `ib_bluetack_webexploit` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ib_bluetack_webexploit`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ib_bluetack_webexploit`.
- ` this % ` is the percentage **of this ipset (`ib_bluetack_webexploit`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level3](#firehol_level3)|107712|9625222|1450|0.0%|100.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|108|0.0%|7.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|97|0.0%|6.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|45|0.0%|3.1%|
[firehol_level1](#firehol_level1)|5086|688943154|39|0.0%|2.6%|
[fullbogons](#fullbogons)|3720|670264216|33|0.0%|2.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|19|0.0%|1.3%|
[alienvault_reputation](#alienvault_reputation)|181932|181932|10|0.0%|0.6%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|7|0.0%|0.4%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|6|0.0%|0.4%|
[et_block](#et_block)|1023|18338662|6|0.0%|0.4%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|3|0.2%|0.2%|
[firehol_proxies](#firehol_proxies)|11379|11603|3|0.0%|0.2%|
[firehol_level2](#firehol_level2)|24806|36416|3|0.0%|0.2%|
[firehol_anonymous](#firehol_anonymous)|17786|81795|3|0.0%|0.2%|
[stopforumspam_7d](#stopforumspam_7d)|29278|29278|2|0.0%|0.1%|
[stopforumspam_30d](#stopforumspam_30d)|92247|92247|2|0.0%|0.1%|
[openbl_60d](#openbl_60d)|7242|7242|2|0.0%|0.1%|
[openbl_30d](#openbl_30d)|2969|2969|2|0.0%|0.1%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|2|0.3%|0.1%|
[blocklist_de](#blocklist_de)|31099|31099|2|0.0%|0.1%|
[stopforumspam_1d](#stopforumspam_1d)|6697|6697|1|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9492|9492|1|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7066|7066|1|0.0%|0.0%|
[openbl_7d](#openbl_7d)|825|825|1|0.1%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|1|0.0%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|319|319|1|0.3%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|158|158|1|0.6%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3473|3473|1|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3421|3421|1|0.0%|0.0%|

## malc0de

[Malc0de.com](http://malc0de.com) malicious IPs of the last 30 days

Source is downloaded from [this link](http://malc0de.com/bl/IP_Blacklist.txt).

The last time downloaded was found to be dated: Sun Jun  7 13:17:02 UTC 2015.

The ipset `malc0de` has **351** entries, **351** unique IPs.

The following table shows the overlaps of `malc0de` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `malc0de`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `malc0de`.
- ` this % ` is the percentage **of this ipset (`malc0de`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level3](#firehol_level3)|107712|9625222|351|0.0%|100.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|48|0.0%|13.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|21|0.0%|5.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|11|0.0%|3.1%|
[cleanmx_viruses](#cleanmx_viruses)|319|319|10|3.1%|2.8%|
[alienvault_reputation](#alienvault_reputation)|181932|181932|10|0.0%|2.8%|
[firehol_level1](#firehol_level1)|5086|688943154|6|0.0%|1.7%|
[et_block](#et_block)|1023|18338662|5|0.0%|1.4%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|4|0.0%|1.1%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|4|0.3%|1.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|3|0.0%|0.8%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|1|0.0%|0.2%|
[dshield](#dshield)|20|5120|1|0.0%|0.2%|

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
[firehol_level3](#firehol_level3)|107712|9625222|1288|0.0%|100.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|147|0.0%|11.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|66|0.0%|5.1%|
[firehol_level1](#firehol_level1)|5086|688943154|38|0.0%|2.9%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|29|0.0%|2.2%|
[et_block](#et_block)|1023|18338662|29|0.0%|2.2%|
[snort_ipfilter](#snort_ipfilter)|9492|9492|28|0.2%|2.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|27|0.0%|2.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|27|0.0%|2.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|26|0.0%|2.0%|
[fullbogons](#fullbogons)|3720|670264216|9|0.0%|0.6%|
[alienvault_reputation](#alienvault_reputation)|181932|181932|7|0.0%|0.5%|
[stopforumspam_30d](#stopforumspam_30d)|92247|92247|4|0.0%|0.3%|
[malc0de](#malc0de)|351|351|4|1.1%|0.3%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|3|0.2%|0.2%|
[cleanmx_viruses](#cleanmx_viruses)|319|319|3|0.9%|0.2%|
[stopforumspam_7d](#stopforumspam_7d)|29278|29278|1|0.0%|0.0%|

## maxmind_proxy_fraud

[MaxMind.com](https://www.maxmind.com/en/anonymous-proxy-fraudulent-ip-address-list) list of anonymous proxy fraudelent IP addresses.

Source is downloaded from [this link](https://www.maxmind.com/en/anonymous-proxy-fraudulent-ip-address-list).

The last time downloaded was found to be dated: Mon Jun  8 08:36:14 UTC 2015.

The ipset `maxmind_proxy_fraud` has **372** entries, **372** unique IPs.

The following table shows the overlaps of `maxmind_proxy_fraud` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `maxmind_proxy_fraud`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `maxmind_proxy_fraud`.
- ` this % ` is the percentage **of this ipset (`maxmind_proxy_fraud`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_proxies](#firehol_proxies)|11379|11603|372|3.2%|100.0%|
[firehol_anonymous](#firehol_anonymous)|17786|81795|372|0.4%|100.0%|
[firehol_level3](#firehol_level3)|107712|9625222|233|0.0%|62.6%|
[stopforumspam_30d](#stopforumspam_30d)|92247|92247|232|0.2%|62.3%|
[stopforumspam_7d](#stopforumspam_7d)|29278|29278|190|0.6%|51.0%|
[snort_ipfilter](#snort_ipfilter)|9492|9492|174|1.8%|46.7%|
[et_tor](#et_tor)|6470|6470|168|2.5%|45.1%|
[dm_tor](#dm_tor)|6454|6454|165|2.5%|44.3%|
[bm_tor](#bm_tor)|6458|6458|165|2.5%|44.3%|
[stopforumspam_1d](#stopforumspam_1d)|6697|6697|157|2.3%|42.2%|
[firehol_level2](#firehol_level2)|24806|36416|157|0.4%|42.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|125|0.0%|33.6%|
[php_commenters](#php_commenters)|373|373|39|10.4%|10.4%|
[alienvault_reputation](#alienvault_reputation)|181932|181932|26|0.0%|6.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|21|0.0%|5.6%|
[openbl_60d](#openbl_60d)|7242|7242|18|0.2%|4.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|17|0.0%|4.5%|
[php_harvesters](#php_harvesters)|341|341|6|1.7%|1.6%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|5|0.0%|1.3%|
[ri_web_proxies](#ri_web_proxies)|7066|7066|4|0.0%|1.0%|
[php_spammers](#php_spammers)|580|580|4|0.6%|1.0%|
[php_dictionary](#php_dictionary)|589|589|4|0.6%|1.0%|
[xroxy](#xroxy)|2121|2121|1|0.0%|0.2%|
[voipbl](#voipbl)|10491|10902|1|0.0%|0.2%|
[shunlist](#shunlist)|1230|1230|1|0.0%|0.2%|
[ri_connect_proxies](#ri_connect_proxies)|2581|2581|1|0.0%|0.2%|
[et_block](#et_block)|1023|18338662|1|0.0%|0.2%|
[blocklist_de_mail](#blocklist_de_mail)|18693|18693|1|0.0%|0.2%|
[blocklist_de_apache](#blocklist_de_apache)|16201|16201|1|0.0%|0.2%|
[blocklist_de](#blocklist_de)|31099|31099|1|0.0%|0.2%|

## nixspam

[NiX Spam](http://www.heise.de/ix/NiX-Spam-DNSBL-and-blacklist-for-download-499637.html) IP addresses that sent spam in the last hour - automatically generated entries without distinguishing open proxies from relays, dialup gateways, and so on. All IPs are removed after 12 hours if there is no spam from there.

Source is downloaded from [this link](http://www.dnsbl.manitu.net/download/nixspam-ip.dump.gz).

The last time downloaded was found to be dated: Mon Jun  8 10:30:02 UTC 2015.

The ipset `nixspam` has **20667** entries, **20667** unique IPs.

The following table shows the overlaps of `nixspam` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `nixspam`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `nixspam`.
- ` this % ` is the percentage **of this ipset (`nixspam`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|24806|36416|895|2.4%|4.3%|
[blocklist_de](#blocklist_de)|31099|31099|890|2.8%|4.3%|
[blocklist_de_mail](#blocklist_de_mail)|18693|18693|839|4.4%|4.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|798|0.0%|3.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|725|0.0%|3.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|582|0.0%|2.8%|
[firehol_level3](#firehol_level3)|107712|9625222|506|0.0%|2.4%|
[snort_ipfilter](#snort_ipfilter)|9492|9492|426|4.4%|2.0%|
[stopforumspam_30d](#stopforumspam_30d)|92247|92247|117|0.1%|0.5%|
[php_dictionary](#php_dictionary)|589|589|81|13.7%|0.3%|
[stopforumspam_7d](#stopforumspam_7d)|29278|29278|80|0.2%|0.3%|
[firehol_anonymous](#firehol_anonymous)|17786|81795|79|0.0%|0.3%|
[firehol_proxies](#firehol_proxies)|11379|11603|78|0.6%|0.3%|
[php_spammers](#php_spammers)|580|580|67|11.5%|0.3%|
[ri_web_proxies](#ri_web_proxies)|7066|7066|49|0.6%|0.2%|
[stopforumspam_1d](#stopforumspam_1d)|6697|6697|41|0.6%|0.1%|
[xroxy](#xroxy)|2121|2121|40|1.8%|0.1%|
[blocklist_de_bots](#blocklist_de_bots)|3421|3421|31|0.9%|0.1%|
[proxz](#proxz)|1039|1039|27|2.5%|0.1%|
[alienvault_reputation](#alienvault_reputation)|181932|181932|23|0.0%|0.1%|
[blocklist_de_apache](#blocklist_de_apache)|16201|16201|17|0.1%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4840|4840|15|0.3%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2581|2581|8|0.3%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2813|2813|6|0.2%|0.0%|
[proxyrss](#proxyrss)|1481|1481|5|0.3%|0.0%|
[php_commenters](#php_commenters)|373|373|5|1.3%|0.0%|
[openbl_60d](#openbl_60d)|7242|7242|5|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|4|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|158|158|3|1.8%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3473|3473|3|0.0%|0.0%|
[voipbl](#voipbl)|10491|10902|2|0.0%|0.0%|
[php_harvesters](#php_harvesters)|341|341|2|0.5%|0.0%|
[zeus_badips](#zeus_badips)|204|204|1|0.4%|0.0%|
[zeus](#zeus)|233|233|1|0.4%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|1|0.1%|0.0%|
[firehol_level1](#firehol_level1)|5086|688943154|1|0.0%|0.0%|
[et_block](#et_block)|1023|18338662|1|0.0%|0.0%|
[dm_tor](#dm_tor)|6454|6454|1|0.0%|0.0%|
[bm_tor](#bm_tor)|6458|6458|1|0.0%|0.0%|

## openbl_1d

[OpenBL.org](http://www.openbl.org/) last 24 hours IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.

Source is downloaded from [this link](http://www.openbl.org/lists/base_1days.txt).

The last time downloaded was found to be dated: Mon Jun  8 10:07:00 UTC 2015.

The ipset `openbl_1d` has **112** entries, **112** unique IPs.

The following table shows the overlaps of `openbl_1d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl_1d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl_1d`.
- ` this % ` is the percentage **of this ipset (`openbl_1d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|24806|36416|112|0.3%|100.0%|
[alienvault_reputation](#alienvault_reputation)|181932|181932|111|0.0%|99.1%|
[openbl_60d](#openbl_60d)|7242|7242|110|1.5%|98.2%|
[firehol_level3](#firehol_level3)|107712|9625222|110|0.0%|98.2%|
[openbl_30d](#openbl_30d)|2969|2969|109|3.6%|97.3%|
[openbl_7d](#openbl_7d)|825|825|107|12.9%|95.5%|
[blocklist_de](#blocklist_de)|31099|31099|83|0.2%|74.1%|
[blocklist_de_ssh](#blocklist_de_ssh)|3473|3473|82|2.3%|73.2%|
[shunlist](#shunlist)|1230|1230|47|3.8%|41.9%|
[bruteforceblocker](#bruteforceblocker)|1692|1692|35|2.0%|31.2%|
[et_compromised](#et_compromised)|2016|2016|34|1.6%|30.3%|
[blocklist_de_strongips](#blocklist_de_strongips)|158|158|19|12.0%|16.9%|
[firehol_level1](#firehol_level1)|5086|688943154|11|0.0%|9.8%|
[dshield](#dshield)|20|5120|10|0.1%|8.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|8|0.0%|7.1%|
[et_block](#et_block)|1023|18338662|7|0.0%|6.2%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|6|0.0%|5.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|3|0.0%|2.6%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2|0.0%|1.7%|
[stopforumspam_30d](#stopforumspam_30d)|92247|92247|1|0.0%|0.8%|
[php_spammers](#php_spammers)|580|580|1|0.1%|0.8%|
[php_commenters](#php_commenters)|373|373|1|0.2%|0.8%|
[blocklist_de_mail](#blocklist_de_mail)|18693|18693|1|0.0%|0.8%|
[blocklist_de_imap](#blocklist_de_imap)|2813|2813|1|0.0%|0.8%|

## openbl_30d

[OpenBL.org](http://www.openbl.org/) last 30 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.

Source is downloaded from [this link](http://www.openbl.org/lists/base_30days.txt).

The last time downloaded was found to be dated: Mon Jun  8 08:07:00 UTC 2015.

The ipset `openbl_30d` has **2969** entries, **2969** unique IPs.

The following table shows the overlaps of `openbl_30d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl_30d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl_30d`.
- ` this % ` is the percentage **of this ipset (`openbl_30d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[openbl_60d](#openbl_60d)|7242|7242|2969|40.9%|100.0%|
[firehol_level3](#firehol_level3)|107712|9625222|2969|0.0%|100.0%|
[alienvault_reputation](#alienvault_reputation)|181932|181932|2955|1.6%|99.5%|
[et_compromised](#et_compromised)|2016|2016|1104|54.7%|37.1%|
[bruteforceblocker](#bruteforceblocker)|1692|1692|936|55.3%|31.5%|
[firehol_level2](#firehol_level2)|24806|36416|918|2.5%|30.9%|
[blocklist_de](#blocklist_de)|31099|31099|890|2.8%|29.9%|
[blocklist_de_ssh](#blocklist_de_ssh)|3473|3473|847|24.3%|28.5%|
[openbl_7d](#openbl_7d)|825|825|825|100.0%|27.7%|
[shunlist](#shunlist)|1230|1230|514|41.7%|17.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|300|0.0%|10.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|152|0.0%|5.1%|
[firehol_level1](#firehol_level1)|5086|688943154|134|0.0%|4.5%|
[et_block](#et_block)|1023|18338662|129|0.0%|4.3%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|123|0.0%|4.1%|
[dshield](#dshield)|20|5120|112|2.1%|3.7%|
[openbl_1d](#openbl_1d)|112|112|109|97.3%|3.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|64|0.0%|2.1%|
[blocklist_de_mail](#blocklist_de_mail)|18693|18693|38|0.2%|1.2%|
[blocklist_de_imap](#blocklist_de_imap)|2813|2813|30|1.0%|1.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|158|158|24|15.1%|0.8%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|12|0.0%|0.4%|
[stopforumspam_30d](#stopforumspam_30d)|92247|92247|4|0.0%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|4|0.0%|0.1%|
[voipbl](#voipbl)|10491|10902|3|0.0%|0.1%|
[snort_ipfilter](#snort_ipfilter)|9492|9492|3|0.0%|0.1%|
[blocklist_de_apache](#blocklist_de_apache)|16201|16201|3|0.0%|0.1%|
[zeus](#zeus)|233|233|2|0.8%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|2|0.1%|0.0%|
[zeus_badips](#zeus_badips)|204|204|1|0.4%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29278|29278|1|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6697|6697|1|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|1|0.0%|0.0%|
[php_spammers](#php_spammers)|580|580|1|0.1%|0.0%|
[php_commenters](#php_commenters)|373|373|1|0.2%|0.0%|
[firehol_anonymous](#firehol_anonymous)|17786|81795|1|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|320|320|1|0.3%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3421|3421|1|0.0%|0.0%|

## openbl_60d

[OpenBL.org](http://www.openbl.org/) last 60 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.

Source is downloaded from [this link](http://www.openbl.org/lists/base_60days.txt).

The last time downloaded was found to be dated: Mon Jun  8 08:07:00 UTC 2015.

The ipset `openbl_60d` has **7242** entries, **7242** unique IPs.

The following table shows the overlaps of `openbl_60d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl_60d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl_60d`.
- ` this % ` is the percentage **of this ipset (`openbl_60d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[alienvault_reputation](#alienvault_reputation)|181932|181932|7222|3.9%|99.7%|
[firehol_level3](#firehol_level3)|107712|9625222|3088|0.0%|42.6%|
[openbl_30d](#openbl_30d)|2969|2969|2969|100.0%|40.9%|
[et_compromised](#et_compromised)|2016|2016|1222|60.6%|16.8%|
[firehol_level2](#firehol_level2)|24806|36416|1206|3.3%|16.6%|
[blocklist_de](#blocklist_de)|31099|31099|1158|3.7%|15.9%|
[blocklist_de_ssh](#blocklist_de_ssh)|3473|3473|1098|31.6%|15.1%|
[bruteforceblocker](#bruteforceblocker)|1692|1692|983|58.0%|13.5%|
[openbl_7d](#openbl_7d)|825|825|825|100.0%|11.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|741|0.0%|10.2%|
[shunlist](#shunlist)|1230|1230|535|43.4%|7.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|328|0.0%|4.5%|
[firehol_level1](#firehol_level1)|5086|688943154|250|0.0%|3.4%|
[et_block](#et_block)|1023|18338662|250|0.0%|3.4%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|239|0.0%|3.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|167|0.0%|2.3%|
[dshield](#dshield)|20|5120|112|2.1%|1.5%|
[openbl_1d](#openbl_1d)|112|112|110|98.2%|1.5%|
[stopforumspam_30d](#stopforumspam_30d)|92247|92247|54|0.0%|0.7%|
[blocklist_de_mail](#blocklist_de_mail)|18693|18693|43|0.2%|0.5%|
[blocklist_de_imap](#blocklist_de_imap)|2813|2813|34|1.2%|0.4%|
[blocklist_de_strongips](#blocklist_de_strongips)|158|158|25|15.8%|0.3%|
[stopforumspam_7d](#stopforumspam_7d)|29278|29278|24|0.0%|0.3%|
[snort_ipfilter](#snort_ipfilter)|9492|9492|24|0.2%|0.3%|
[firehol_anonymous](#firehol_anonymous)|17786|81795|23|0.0%|0.3%|
[stopforumspam_1d](#stopforumspam_1d)|6697|6697|20|0.2%|0.2%|
[et_tor](#et_tor)|6470|6470|20|0.3%|0.2%|
[dm_tor](#dm_tor)|6454|6454|20|0.3%|0.2%|
[bm_tor](#bm_tor)|6458|6458|20|0.3%|0.2%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|18|4.8%|0.2%|
[firehol_proxies](#firehol_proxies)|11379|11603|18|0.1%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|17|0.0%|0.2%|
[blocklist_de_bots](#blocklist_de_bots)|3421|3421|11|0.3%|0.1%|
[php_commenters](#php_commenters)|373|373|10|2.6%|0.1%|
[voipbl](#voipbl)|10491|10902|8|0.0%|0.1%|
[nixspam](#nixspam)|20667|20667|5|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|5|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|16201|16201|4|0.0%|0.0%|
[zeus](#zeus)|233|233|2|0.8%|0.0%|
[php_harvesters](#php_harvesters)|341|341|2|0.5%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|2|0.1%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|320|320|2|0.6%|0.0%|
[zeus_badips](#zeus_badips)|204|204|1|0.4%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|1|0.0%|0.0%|
[php_spammers](#php_spammers)|580|580|1|0.1%|0.0%|

## openbl_7d

[OpenBL.org](http://www.openbl.org/) last 7 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.

Source is downloaded from [this link](http://www.openbl.org/lists/base_7days.txt).

The last time downloaded was found to be dated: Mon Jun  8 08:07:00 UTC 2015.

The ipset `openbl_7d` has **825** entries, **825** unique IPs.

The following table shows the overlaps of `openbl_7d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl_7d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl_7d`.
- ` this % ` is the percentage **of this ipset (`openbl_7d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[openbl_60d](#openbl_60d)|7242|7242|825|11.3%|100.0%|
[openbl_30d](#openbl_30d)|2969|2969|825|27.7%|100.0%|
[firehol_level3](#firehol_level3)|107712|9625222|825|0.0%|100.0%|
[alienvault_reputation](#alienvault_reputation)|181932|181932|820|0.4%|99.3%|
[firehol_level2](#firehol_level2)|24806|36416|443|1.2%|53.6%|
[blocklist_de](#blocklist_de)|31099|31099|415|1.3%|50.3%|
[blocklist_de_ssh](#blocklist_de_ssh)|3473|3473|401|11.5%|48.6%|
[et_compromised](#et_compromised)|2016|2016|338|16.7%|40.9%|
[bruteforceblocker](#bruteforceblocker)|1692|1692|319|18.8%|38.6%|
[shunlist](#shunlist)|1230|1230|216|17.5%|26.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|112|0.0%|13.5%|
[openbl_1d](#openbl_1d)|112|112|107|95.5%|12.9%|
[firehol_level1](#firehol_level1)|5086|688943154|48|0.0%|5.8%|
[et_block](#et_block)|1023|18338662|46|0.0%|5.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|44|0.0%|5.3%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|43|0.0%|5.2%|
[dshield](#dshield)|20|5120|41|0.8%|4.9%|
[blocklist_de_strongips](#blocklist_de_strongips)|158|158|24|15.1%|2.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|18|0.0%|2.1%|
[blocklist_de_mail](#blocklist_de_mail)|18693|18693|12|0.0%|1.4%|
[blocklist_de_imap](#blocklist_de_imap)|2813|2813|10|0.3%|1.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|5|0.0%|0.6%|
[stopforumspam_30d](#stopforumspam_30d)|92247|92247|3|0.0%|0.3%|
[php_spammers](#php_spammers)|580|580|1|0.1%|0.1%|
[php_commenters](#php_commenters)|373|373|1|0.2%|0.1%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|1|0.0%|0.1%|
[blocklist_de_ftp](#blocklist_de_ftp)|320|320|1|0.3%|0.1%|

## palevo

[Abuse.ch Palevo tracker](https://palevotracker.abuse.ch) worm includes IPs which are being used as botnet C&C for the Palevo crimeware - **excellent list**

Source is downloaded from [this link](https://palevotracker.abuse.ch/blocklists.php?download=ipblocklist).

The last time downloaded was found to be dated: Mon Jun  8 10:36:07 UTC 2015.

The ipset `palevo` has **13** entries, **13** unique IPs.

The following table shows the overlaps of `palevo` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `palevo`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `palevo`.
- ` this % ` is the percentage **of this ipset (`palevo`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level1](#firehol_level1)|5086|688943154|13|0.0%|100.0%|
[et_block](#et_block)|1023|18338662|12|0.0%|92.3%|
[snort_ipfilter](#snort_ipfilter)|9492|9492|11|0.1%|84.6%|
[firehol_level3](#firehol_level3)|107712|9625222|11|0.0%|84.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|3|0.0%|23.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|2|0.0%|15.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|1|0.0%|7.6%|

## php_commenters

[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) comment spammers (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=c&rss=1).

The last time downloaded was found to be dated: Mon Jun  8 10:18:27 UTC 2015.

The ipset `php_commenters` has **373** entries, **373** unique IPs.

The following table shows the overlaps of `php_commenters` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `php_commenters`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `php_commenters`.
- ` this % ` is the percentage **of this ipset (`php_commenters`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level3](#firehol_level3)|107712|9625222|373|0.0%|100.0%|
[stopforumspam_30d](#stopforumspam_30d)|92247|92247|277|0.3%|74.2%|
[stopforumspam_7d](#stopforumspam_7d)|29278|29278|206|0.7%|55.2%|
[firehol_level2](#firehol_level2)|24806|36416|169|0.4%|45.3%|
[stopforumspam_1d](#stopforumspam_1d)|6697|6697|149|2.2%|39.9%|
[blocklist_de](#blocklist_de)|31099|31099|90|0.2%|24.1%|
[blocklist_de_bots](#blocklist_de_bots)|3421|3421|75|2.1%|20.1%|
[firehol_anonymous](#firehol_anonymous)|17786|81795|70|0.0%|18.7%|
[firehol_proxies](#firehol_proxies)|11379|11603|64|0.5%|17.1%|
[snort_ipfilter](#snort_ipfilter)|9492|9492|50|0.5%|13.4%|
[et_tor](#et_tor)|6470|6470|43|0.6%|11.5%|
[dm_tor](#dm_tor)|6454|6454|42|0.6%|11.2%|
[bm_tor](#bm_tor)|6458|6458|42|0.6%|11.2%|
[php_spammers](#php_spammers)|580|580|40|6.8%|10.7%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|39|10.4%|10.4%|
[firehol_level1](#firehol_level1)|5086|688943154|37|0.0%|9.9%|
[blocklist_de_strongips](#blocklist_de_strongips)|158|158|35|22.1%|9.3%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|29|0.0%|7.7%|
[et_block](#et_block)|1023|18338662|29|0.0%|7.7%|
[php_dictionary](#php_dictionary)|589|589|25|4.2%|6.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|24|0.0%|6.4%|
[blocklist_de_apache](#blocklist_de_apache)|16201|16201|24|0.1%|6.4%|
[ri_web_proxies](#ri_web_proxies)|7066|7066|23|0.3%|6.1%|
[blocklist_de_mail](#blocklist_de_mail)|18693|18693|22|0.1%|5.8%|
[alienvault_reputation](#alienvault_reputation)|181932|181932|17|0.0%|4.5%|
[php_harvesters](#php_harvesters)|341|341|15|4.3%|4.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|15|0.0%|4.0%|
[openbl_60d](#openbl_60d)|7242|7242|10|0.1%|2.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|9|0.0%|2.4%|
[xroxy](#xroxy)|2121|2121|8|0.3%|2.1%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|7|0.0%|1.8%|
[proxz](#proxz)|1039|1039|7|0.6%|1.8%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4840|4840|7|0.1%|1.8%|
[ri_connect_proxies](#ri_connect_proxies)|2581|2581|5|0.1%|1.3%|
[nixspam](#nixspam)|20667|20667|5|0.0%|1.3%|
[proxyrss](#proxyrss)|1481|1481|4|0.2%|1.0%|
[zeus_badips](#zeus_badips)|204|204|1|0.4%|0.2%|
[zeus](#zeus)|233|233|1|0.4%|0.2%|
[openbl_7d](#openbl_7d)|825|825|1|0.1%|0.2%|
[openbl_30d](#openbl_30d)|2969|2969|1|0.0%|0.2%|
[openbl_1d](#openbl_1d)|112|112|1|0.8%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.2%|
[fullbogons](#fullbogons)|3720|670264216|1|0.0%|0.2%|
[bruteforceblocker](#bruteforceblocker)|1692|1692|1|0.0%|0.2%|
[bogons](#bogons)|13|592708608|1|0.0%|0.2%|
[blocklist_de_ssh](#blocklist_de_ssh)|3473|3473|1|0.0%|0.2%|
[blocklist_de_imap](#blocklist_de_imap)|2813|2813|1|0.0%|0.2%|

## php_dictionary

[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) directory attackers (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=d&rss=1).

The last time downloaded was found to be dated: Mon Jun  8 10:18:27 UTC 2015.

The ipset `php_dictionary` has **589** entries, **589** unique IPs.

The following table shows the overlaps of `php_dictionary` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `php_dictionary`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `php_dictionary`.
- ` this % ` is the percentage **of this ipset (`php_dictionary`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level3](#firehol_level3)|107712|9625222|589|0.0%|100.0%|
[php_spammers](#php_spammers)|580|580|211|36.3%|35.8%|
[stopforumspam_30d](#stopforumspam_30d)|92247|92247|111|0.1%|18.8%|
[firehol_level2](#firehol_level2)|24806|36416|83|0.2%|14.0%|
[nixspam](#nixspam)|20667|20667|81|0.3%|13.7%|
[blocklist_de](#blocklist_de)|31099|31099|77|0.2%|13.0%|
[firehol_anonymous](#firehol_anonymous)|17786|81795|75|0.0%|12.7%|
[stopforumspam_7d](#stopforumspam_7d)|29278|29278|74|0.2%|12.5%|
[firehol_proxies](#firehol_proxies)|11379|11603|74|0.6%|12.5%|
[snort_ipfilter](#snort_ipfilter)|9492|9492|71|0.7%|12.0%|
[blocklist_de_mail](#blocklist_de_mail)|18693|18693|52|0.2%|8.8%|
[ri_web_proxies](#ri_web_proxies)|7066|7066|47|0.6%|7.9%|
[xroxy](#xroxy)|2121|2121|35|1.6%|5.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|31|0.0%|5.2%|
[stopforumspam_1d](#stopforumspam_1d)|6697|6697|26|0.3%|4.4%|
[php_commenters](#php_commenters)|373|373|25|6.7%|4.2%|
[blocklist_de_bots](#blocklist_de_bots)|3421|3421|21|0.6%|3.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|20|0.0%|3.3%|
[proxz](#proxz)|1039|1039|18|1.7%|3.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|11|0.0%|1.8%|
[alienvault_reputation](#alienvault_reputation)|181932|181932|8|0.0%|1.3%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|5|0.0%|0.8%|
[firehol_level1](#firehol_level1)|5086|688943154|5|0.0%|0.8%|
[et_tor](#et_tor)|6470|6470|5|0.0%|0.8%|
[et_block](#et_block)|1023|18338662|5|0.0%|0.8%|
[ri_connect_proxies](#ri_connect_proxies)|2581|2581|4|0.1%|0.6%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|4|1.0%|0.6%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4840|4840|4|0.0%|0.6%|
[blocklist_de_apache](#blocklist_de_apache)|16201|16201|4|0.0%|0.6%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|0.5%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|3|0.0%|0.5%|
[dm_tor](#dm_tor)|6454|6454|3|0.0%|0.5%|
[bm_tor](#bm_tor)|6458|6458|3|0.0%|0.5%|
[blocklist_de_strongips](#blocklist_de_strongips)|158|158|3|1.8%|0.5%|
[php_harvesters](#php_harvesters)|341|341|2|0.5%|0.3%|
[blocklist_de_imap](#blocklist_de_imap)|2813|2813|2|0.0%|0.3%|
[proxyrss](#proxyrss)|1481|1481|1|0.0%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.1%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|1|0.1%|0.1%|

## php_harvesters

[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) harvesters (IPs that surf the internet looking for email addresses) (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=h&rss=1).

The last time downloaded was found to be dated: Mon Jun  8 10:18:25 UTC 2015.

The ipset `php_harvesters` has **341** entries, **341** unique IPs.

The following table shows the overlaps of `php_harvesters` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `php_harvesters`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `php_harvesters`.
- ` this % ` is the percentage **of this ipset (`php_harvesters`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level3](#firehol_level3)|107712|9625222|341|0.0%|100.0%|
[stopforumspam_30d](#stopforumspam_30d)|92247|92247|78|0.0%|22.8%|
[stopforumspam_7d](#stopforumspam_7d)|29278|29278|59|0.2%|17.3%|
[firehol_level2](#firehol_level2)|24806|36416|55|0.1%|16.1%|
[stopforumspam_1d](#stopforumspam_1d)|6697|6697|41|0.6%|12.0%|
[blocklist_de](#blocklist_de)|31099|31099|40|0.1%|11.7%|
[blocklist_de_bots](#blocklist_de_bots)|3421|3421|29|0.8%|8.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|18|0.0%|5.2%|
[php_commenters](#php_commenters)|373|373|15|4.0%|4.3%|
[firehol_anonymous](#firehol_anonymous)|17786|81795|13|0.0%|3.8%|
[snort_ipfilter](#snort_ipfilter)|9492|9492|12|0.1%|3.5%|
[firehol_proxies](#firehol_proxies)|11379|11603|12|0.1%|3.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|11|0.0%|3.2%|
[alienvault_reputation](#alienvault_reputation)|181932|181932|10|0.0%|2.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|9|0.0%|2.6%|
[et_tor](#et_tor)|6470|6470|7|0.1%|2.0%|
[dm_tor](#dm_tor)|6454|6454|7|0.1%|2.0%|
[bm_tor](#bm_tor)|6458|6458|7|0.1%|2.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|6|1.6%|1.7%|
[blocklist_de_ftp](#blocklist_de_ftp)|320|320|6|1.8%|1.7%|
[blocklist_de_mail](#blocklist_de_mail)|18693|18693|5|0.0%|1.4%|
[proxyrss](#proxyrss)|1481|1481|3|0.2%|0.8%|
[firehol_level1](#firehol_level1)|5086|688943154|3|0.0%|0.8%|
[xroxy](#xroxy)|2121|2121|2|0.0%|0.5%|
[ri_web_proxies](#ri_web_proxies)|7066|7066|2|0.0%|0.5%|
[php_spammers](#php_spammers)|580|580|2|0.3%|0.5%|
[php_dictionary](#php_dictionary)|589|589|2|0.3%|0.5%|
[openbl_60d](#openbl_60d)|7242|7242|2|0.0%|0.5%|
[nixspam](#nixspam)|20667|20667|2|0.0%|0.5%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|2|0.0%|0.5%|
[blocklist_de_strongips](#blocklist_de_strongips)|158|158|2|1.2%|0.5%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|1|0.0%|0.2%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|1|0.0%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.2%|
[fullbogons](#fullbogons)|3720|670264216|1|0.0%|0.2%|
[et_block](#et_block)|1023|18338662|1|0.0%|0.2%|
[bogons](#bogons)|13|592708608|1|0.0%|0.2%|
[blocklist_de_imap](#blocklist_de_imap)|2813|2813|1|0.0%|0.2%|
[blocklist_de_apache](#blocklist_de_apache)|16201|16201|1|0.0%|0.2%|

## php_spammers

[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) spam servers (IPs used by spammers to send messages) (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=s&rss=1).

The last time downloaded was found to be dated: Mon Jun  8 10:18:26 UTC 2015.

The ipset `php_spammers` has **580** entries, **580** unique IPs.

The following table shows the overlaps of `php_spammers` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `php_spammers`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `php_spammers`.
- ` this % ` is the percentage **of this ipset (`php_spammers`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level3](#firehol_level3)|107712|9625222|580|0.0%|100.0%|
[php_dictionary](#php_dictionary)|589|589|211|35.8%|36.3%|
[stopforumspam_30d](#stopforumspam_30d)|92247|92247|122|0.1%|21.0%|
[firehol_level2](#firehol_level2)|24806|36416|78|0.2%|13.4%|
[blocklist_de](#blocklist_de)|31099|31099|71|0.2%|12.2%|
[snort_ipfilter](#snort_ipfilter)|9492|9492|70|0.7%|12.0%|
[stopforumspam_7d](#stopforumspam_7d)|29278|29278|68|0.2%|11.7%|
[nixspam](#nixspam)|20667|20667|67|0.3%|11.5%|
[firehol_anonymous](#firehol_anonymous)|17786|81795|64|0.0%|11.0%|
[firehol_proxies](#firehol_proxies)|11379|11603|62|0.5%|10.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|49|0.0%|8.4%|
[blocklist_de_mail](#blocklist_de_mail)|18693|18693|47|0.2%|8.1%|
[ri_web_proxies](#ri_web_proxies)|7066|7066|42|0.5%|7.2%|
[php_commenters](#php_commenters)|373|373|40|10.7%|6.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|32|0.0%|5.5%|
[stopforumspam_1d](#stopforumspam_1d)|6697|6697|31|0.4%|5.3%|
[xroxy](#xroxy)|2121|2121|27|1.2%|4.6%|
[blocklist_de_bots](#blocklist_de_bots)|3421|3421|19|0.5%|3.2%|
[proxz](#proxz)|1039|1039|18|1.7%|3.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|8|0.0%|1.3%|
[et_tor](#et_tor)|6470|6470|6|0.0%|1.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|158|158|5|3.1%|0.8%|
[alienvault_reputation](#alienvault_reputation)|181932|181932|5|0.0%|0.8%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|4|0.0%|0.6%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|4|1.0%|0.6%|
[firehol_level1](#firehol_level1)|5086|688943154|4|0.0%|0.6%|
[dm_tor](#dm_tor)|6454|6454|4|0.0%|0.6%|
[bm_tor](#bm_tor)|6458|6458|4|0.0%|0.6%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4840|4840|4|0.0%|0.6%|
[blocklist_de_apache](#blocklist_de_apache)|16201|16201|4|0.0%|0.6%|
[ri_connect_proxies](#ri_connect_proxies)|2581|2581|3|0.1%|0.5%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|0.5%|
[et_block](#et_block)|1023|18338662|3|0.0%|0.5%|
[proxyrss](#proxyrss)|1481|1481|2|0.1%|0.3%|
[php_harvesters](#php_harvesters)|341|341|2|0.5%|0.3%|
[openbl_7d](#openbl_7d)|825|825|1|0.1%|0.1%|
[openbl_60d](#openbl_60d)|7242|7242|1|0.0%|0.1%|
[openbl_30d](#openbl_30d)|2969|2969|1|0.0%|0.1%|
[openbl_1d](#openbl_1d)|112|112|1|0.8%|0.1%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|1|0.0%|0.1%|
[bruteforceblocker](#bruteforceblocker)|1692|1692|1|0.0%|0.1%|
[blocklist_de_ssh](#blocklist_de_ssh)|3473|3473|1|0.0%|0.1%|
[blocklist_de_imap](#blocklist_de_imap)|2813|2813|1|0.0%|0.1%|

## proxyrss

[proxyrss.com](http://www.proxyrss.com) open proxies syndicated from multiple sources.

Source is downloaded from [this link](http://www.proxyrss.com/proxylists/all.gz).

The last time downloaded was found to be dated: Mon Jun  8 09:01:27 UTC 2015.

The ipset `proxyrss` has **1481** entries, **1481** unique IPs.

The following table shows the overlaps of `proxyrss` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `proxyrss`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `proxyrss`.
- ` this % ` is the percentage **of this ipset (`proxyrss`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_proxies](#firehol_proxies)|11379|11603|1481|12.7%|100.0%|
[firehol_anonymous](#firehol_anonymous)|17786|81795|1481|1.8%|100.0%|
[firehol_level3](#firehol_level3)|107712|9625222|724|0.0%|48.8%|
[stopforumspam_30d](#stopforumspam_30d)|92247|92247|723|0.7%|48.8%|
[ri_web_proxies](#ri_web_proxies)|7066|7066|613|8.6%|41.3%|
[stopforumspam_7d](#stopforumspam_7d)|29278|29278|559|1.9%|37.7%|
[firehol_level2](#firehol_level2)|24806|36416|399|1.0%|26.9%|
[xroxy](#xroxy)|2121|2121|372|17.5%|25.1%|
[stopforumspam_1d](#stopforumspam_1d)|6697|6697|335|5.0%|22.6%|
[proxz](#proxz)|1039|1039|245|23.5%|16.5%|
[ri_connect_proxies](#ri_connect_proxies)|2581|2581|235|9.1%|15.8%|
[blocklist_de](#blocklist_de)|31099|31099|219|0.7%|14.7%|
[blocklist_de_bots](#blocklist_de_bots)|3421|3421|217|6.3%|14.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|54|0.0%|3.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|51|0.0%|3.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|36|0.0%|2.4%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|6|0.9%|0.4%|
[nixspam](#nixspam)|20667|20667|5|0.0%|0.3%|
[php_commenters](#php_commenters)|373|373|4|1.0%|0.2%|
[blocklist_de_strongips](#blocklist_de_strongips)|158|158|4|2.5%|0.2%|
[php_harvesters](#php_harvesters)|341|341|3|0.8%|0.2%|
[php_spammers](#php_spammers)|580|580|2|0.3%|0.1%|
[snort_ipfilter](#snort_ipfilter)|9492|9492|1|0.0%|0.0%|
[php_dictionary](#php_dictionary)|589|589|1|0.1%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|18693|18693|1|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|16201|16201|1|0.0%|0.0%|

## proxz

[proxz.com](http://www.proxz.com) open proxies (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.proxz.com/proxylists.xml).

The last time downloaded was found to be dated: Mon Jun  8 09:01:32 UTC 2015.

The ipset `proxz` has **1039** entries, **1039** unique IPs.

The following table shows the overlaps of `proxz` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `proxz`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `proxz`.
- ` this % ` is the percentage **of this ipset (`proxz`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_proxies](#firehol_proxies)|11379|11603|1039|8.9%|100.0%|
[firehol_anonymous](#firehol_anonymous)|17786|81795|1039|1.2%|100.0%|
[firehol_level3](#firehol_level3)|107712|9625222|632|0.0%|60.8%|
[stopforumspam_30d](#stopforumspam_30d)|92247|92247|626|0.6%|60.2%|
[ri_web_proxies](#ri_web_proxies)|7066|7066|476|6.7%|45.8%|
[stopforumspam_7d](#stopforumspam_7d)|29278|29278|452|1.5%|43.5%|
[xroxy](#xroxy)|2121|2121|382|18.0%|36.7%|
[proxyrss](#proxyrss)|1481|1481|245|16.5%|23.5%|
[firehol_level2](#firehol_level2)|24806|36416|239|0.6%|23.0%|
[stopforumspam_1d](#stopforumspam_1d)|6697|6697|177|2.6%|17.0%|
[ri_connect_proxies](#ri_connect_proxies)|2581|2581|176|6.8%|16.9%|
[blocklist_de](#blocklist_de)|31099|31099|152|0.4%|14.6%|
[blocklist_de_bots](#blocklist_de_bots)|3421|3421|130|3.8%|12.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|87|0.0%|8.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|41|0.0%|3.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|37|0.0%|3.5%|
[nixspam](#nixspam)|20667|20667|27|0.1%|2.5%|
[snort_ipfilter](#snort_ipfilter)|9492|9492|22|0.2%|2.1%|
[blocklist_de_mail](#blocklist_de_mail)|18693|18693|20|0.1%|1.9%|
[php_spammers](#php_spammers)|580|580|18|3.1%|1.7%|
[php_dictionary](#php_dictionary)|589|589|18|3.0%|1.7%|
[php_commenters](#php_commenters)|373|373|7|1.8%|0.6%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|6|0.9%|0.5%|
[blocklist_de_strongips](#blocklist_de_strongips)|158|158|3|1.8%|0.2%|
[alienvault_reputation](#alienvault_reputation)|181932|181932|3|0.0%|0.2%|
[et_compromised](#et_compromised)|2016|2016|2|0.0%|0.1%|
[bruteforceblocker](#bruteforceblocker)|1692|1692|2|0.1%|0.1%|
[blocklist_de_apache](#blocklist_de_apache)|16201|16201|2|0.0%|0.1%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|1|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4840|4840|1|0.0%|0.0%|

## ri_connect_proxies

[rosinstrument.com](http://www.rosinstrument.com) open CONNECT proxies (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://tools.rosinstrument.com/proxy/plab100.xml).

The last time downloaded was found to be dated: Mon Jun  8 05:31:50 UTC 2015.

The ipset `ri_connect_proxies` has **2581** entries, **2581** unique IPs.

The following table shows the overlaps of `ri_connect_proxies` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ri_connect_proxies`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ri_connect_proxies`.
- ` this % ` is the percentage **of this ipset (`ri_connect_proxies`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_proxies](#firehol_proxies)|11379|11603|2581|22.2%|100.0%|
[firehol_anonymous](#firehol_anonymous)|17786|81795|2581|3.1%|100.0%|
[stopforumspam_30d](#stopforumspam_30d)|92247|92247|1474|1.5%|57.1%|
[firehol_level3](#firehol_level3)|107712|9625222|1474|0.0%|57.1%|
[ri_web_proxies](#ri_web_proxies)|7066|7066|1093|15.4%|42.3%|
[stopforumspam_7d](#stopforumspam_7d)|29278|29278|624|2.1%|24.1%|
[xroxy](#xroxy)|2121|2121|378|17.8%|14.6%|
[proxyrss](#proxyrss)|1481|1481|235|15.8%|9.1%|
[firehol_level2](#firehol_level2)|24806|36416|192|0.5%|7.4%|
[proxz](#proxz)|1039|1039|176|16.9%|6.8%|
[stopforumspam_1d](#stopforumspam_1d)|6697|6697|155|2.3%|6.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|99|0.0%|3.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|79|0.0%|3.0%|
[blocklist_de](#blocklist_de)|31099|31099|72|0.2%|2.7%|
[blocklist_de_bots](#blocklist_de_bots)|3421|3421|68|1.9%|2.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|54|0.0%|2.0%|
[nixspam](#nixspam)|20667|20667|8|0.0%|0.3%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|7|1.0%|0.2%|
[php_commenters](#php_commenters)|373|373|5|1.3%|0.1%|
[snort_ipfilter](#snort_ipfilter)|9492|9492|4|0.0%|0.1%|
[php_dictionary](#php_dictionary)|589|589|4|0.6%|0.1%|
[php_spammers](#php_spammers)|580|580|3|0.5%|0.1%|
[blocklist_de_mail](#blocklist_de_mail)|18693|18693|3|0.0%|0.1%|
[alienvault_reputation](#alienvault_reputation)|181932|181932|3|0.0%|0.1%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.0%|
[et_tor](#et_tor)|6470|6470|1|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2813|2813|1|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4840|4840|1|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|16201|16201|1|0.0%|0.0%|

## ri_web_proxies

[rosinstrument.com](http://www.rosinstrument.com) open HTTP proxies (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://tools.rosinstrument.com/proxy/l100.xml).

The last time downloaded was found to be dated: Mon Jun  8 06:38:04 UTC 2015.

The ipset `ri_web_proxies` has **7066** entries, **7066** unique IPs.

The following table shows the overlaps of `ri_web_proxies` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ri_web_proxies`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ri_web_proxies`.
- ` this % ` is the percentage **of this ipset (`ri_web_proxies`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_proxies](#firehol_proxies)|11379|11603|7066|60.8%|100.0%|
[firehol_anonymous](#firehol_anonymous)|17786|81795|7066|8.6%|100.0%|
[firehol_level3](#firehol_level3)|107712|9625222|3411|0.0%|48.2%|
[stopforumspam_30d](#stopforumspam_30d)|92247|92247|3371|3.6%|47.7%|
[stopforumspam_7d](#stopforumspam_7d)|29278|29278|1589|5.4%|22.4%|
[ri_connect_proxies](#ri_connect_proxies)|2581|2581|1093|42.3%|15.4%|
[xroxy](#xroxy)|2121|2121|921|43.4%|13.0%|
[firehol_level2](#firehol_level2)|24806|36416|697|1.9%|9.8%|
[proxyrss](#proxyrss)|1481|1481|613|41.3%|8.6%|
[stopforumspam_1d](#stopforumspam_1d)|6697|6697|515|7.6%|7.2%|
[proxz](#proxz)|1039|1039|476|45.8%|6.7%|
[blocklist_de](#blocklist_de)|31099|31099|404|1.2%|5.7%|
[blocklist_de_bots](#blocklist_de_bots)|3421|3421|344|10.0%|4.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|205|0.0%|2.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|199|0.0%|2.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|137|0.0%|1.9%|
[blocklist_de_mail](#blocklist_de_mail)|18693|18693|58|0.3%|0.8%|
[snort_ipfilter](#snort_ipfilter)|9492|9492|56|0.5%|0.7%|
[nixspam](#nixspam)|20667|20667|49|0.2%|0.6%|
[php_dictionary](#php_dictionary)|589|589|47|7.9%|0.6%|
[php_spammers](#php_spammers)|580|580|42|7.2%|0.5%|
[php_commenters](#php_commenters)|373|373|23|6.1%|0.3%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|13|1.9%|0.1%|
[blocklist_de_imap](#blocklist_de_imap)|2813|2813|9|0.3%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|5|0.0%|0.0%|
[et_tor](#et_tor)|6470|6470|5|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|4|1.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|3|0.0%|0.0%|
[dm_tor](#dm_tor)|6454|6454|3|0.0%|0.0%|
[bm_tor](#bm_tor)|6458|6458|3|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|158|158|3|1.8%|0.0%|
[alienvault_reputation](#alienvault_reputation)|181932|181932|3|0.0%|0.0%|
[php_harvesters](#php_harvesters)|341|341|2|0.5%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|16201|16201|2|0.0%|0.0%|
[sslbl](#sslbl)|379|379|1|0.2%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|1|0.0%|0.0%|
[firehol_level1](#firehol_level1)|5086|688943154|1|0.0%|0.0%|
[et_compromised](#et_compromised)|2016|2016|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1692|1692|1|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4840|4840|1|0.0%|0.0%|

## shunlist

[AutoShun.org](http://autoshun.org/) IPs identified as hostile by correlating logs from distributed snort installations running the autoshun plugin

Source is downloaded from [this link](http://www.autoshun.org/files/shunlist.csv).

The last time downloaded was found to be dated: Mon Jun  8 07:30:04 UTC 2015.

The ipset `shunlist` has **1230** entries, **1230** unique IPs.

The following table shows the overlaps of `shunlist` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `shunlist`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `shunlist`.
- ` this % ` is the percentage **of this ipset (`shunlist`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level3](#firehol_level3)|107712|9625222|1230|0.0%|100.0%|
[alienvault_reputation](#alienvault_reputation)|181932|181932|1223|0.6%|99.4%|
[openbl_60d](#openbl_60d)|7242|7242|535|7.3%|43.4%|
[openbl_30d](#openbl_30d)|2969|2969|514|17.3%|41.7%|
[et_compromised](#et_compromised)|2016|2016|429|21.2%|34.8%|
[firehol_level2](#firehol_level2)|24806|36416|425|1.1%|34.5%|
[blocklist_de](#blocklist_de)|31099|31099|421|1.3%|34.2%|
[bruteforceblocker](#bruteforceblocker)|1692|1692|411|24.2%|33.4%|
[blocklist_de_ssh](#blocklist_de_ssh)|3473|3473|388|11.1%|31.5%|
[openbl_7d](#openbl_7d)|825|825|216|26.1%|17.5%|
[firehol_level1](#firehol_level1)|5086|688943154|161|0.0%|13.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|113|0.0%|9.1%|
[et_block](#et_block)|1023|18338662|108|0.0%|8.7%|
[dshield](#dshield)|20|5120|101|1.9%|8.2%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|93|0.0%|7.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|65|0.0%|5.2%|
[sslbl](#sslbl)|379|379|58|15.3%|4.7%|
[openbl_1d](#openbl_1d)|112|112|47|41.9%|3.8%|
[ciarmy](#ciarmy)|422|422|33|7.8%|2.6%|
[blocklist_de_apache](#blocklist_de_apache)|16201|16201|29|0.1%|2.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|28|0.0%|2.2%|
[blocklist_de_strongips](#blocklist_de_strongips)|158|158|21|13.2%|1.7%|
[voipbl](#voipbl)|10491|10902|12|0.1%|0.9%|
[stopforumspam_30d](#stopforumspam_30d)|92247|92247|4|0.0%|0.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|0.2%|
[blocklist_de_mail](#blocklist_de_mail)|18693|18693|3|0.0%|0.2%|
[snort_ipfilter](#snort_ipfilter)|9492|9492|2|0.0%|0.1%|
[stopforumspam_7d](#stopforumspam_7d)|29278|29278|1|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6697|6697|1|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.0%|
[firehol_proxies](#firehol_proxies)|11379|11603|1|0.0%|0.0%|
[firehol_anonymous](#firehol_anonymous)|17786|81795|1|0.0%|0.0%|
[et_tor](#et_tor)|6470|6470|1|0.0%|0.0%|
[dm_tor](#dm_tor)|6454|6454|1|0.0%|0.0%|
[bm_tor](#bm_tor)|6458|6458|1|0.0%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|90|90|1|1.1%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2813|2813|1|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4840|4840|1|0.0%|0.0%|

## snort_ipfilter

[labs.snort.org](https://labs.snort.org/) supplied IP blacklist (this list seems to be updated frequently, but we found no information about it)

Source is downloaded from [this link](http://labs.snort.org/feeds/ip-filter.blf).

The last time downloaded was found to be dated: Mon Jun  8 04:00:00 UTC 2015.

The ipset `snort_ipfilter` has **9492** entries, **9492** unique IPs.

The following table shows the overlaps of `snort_ipfilter` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `snort_ipfilter`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `snort_ipfilter`.
- ` this % ` is the percentage **of this ipset (`snort_ipfilter`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level3](#firehol_level3)|107712|9625222|9492|0.0%|100.0%|
[firehol_anonymous](#firehol_anonymous)|17786|81795|1143|1.3%|12.0%|
[et_tor](#et_tor)|6470|6470|1059|16.3%|11.1%|
[bm_tor](#bm_tor)|6458|6458|1055|16.3%|11.1%|
[dm_tor](#dm_tor)|6454|6454|1054|16.3%|11.1%|
[stopforumspam_30d](#stopforumspam_30d)|92247|92247|796|0.8%|8.3%|
[stopforumspam_7d](#stopforumspam_7d)|29278|29278|632|2.1%|6.6%|
[firehol_level2](#firehol_level2)|24806|36416|565|1.5%|5.9%|
[nixspam](#nixspam)|20667|20667|426|2.0%|4.4%|
[stopforumspam_1d](#stopforumspam_1d)|6697|6697|385|5.7%|4.0%|
[et_block](#et_block)|1023|18338662|315|0.0%|3.3%|
[firehol_level1](#firehol_level1)|5086|688943154|300|0.0%|3.1%|
[firehol_proxies](#firehol_proxies)|11379|11603|252|2.1%|2.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|230|0.0%|2.4%|
[blocklist_de](#blocklist_de)|31099|31099|205|0.6%|2.1%|
[zeus](#zeus)|233|233|203|87.1%|2.1%|
[zeus_badips](#zeus_badips)|204|204|180|88.2%|1.8%|
[blocklist_de_mail](#blocklist_de_mail)|18693|18693|177|0.9%|1.8%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|174|46.7%|1.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|122|0.0%|1.2%|
[alienvault_reputation](#alienvault_reputation)|181932|181932|116|0.0%|1.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|87|0.0%|0.9%|
[feodo](#feodo)|99|99|79|79.7%|0.8%|
[php_dictionary](#php_dictionary)|589|589|71|12.0%|0.7%|
[php_spammers](#php_spammers)|580|580|70|12.0%|0.7%|
[ri_web_proxies](#ri_web_proxies)|7066|7066|56|0.7%|0.5%|
[php_commenters](#php_commenters)|373|373|50|13.4%|0.5%|
[xroxy](#xroxy)|2121|2121|34|1.6%|0.3%|
[sslbl](#sslbl)|379|379|31|8.1%|0.3%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|28|2.1%|0.2%|
[openbl_60d](#openbl_60d)|7242|7242|24|0.3%|0.2%|
[proxz](#proxz)|1039|1039|22|2.1%|0.2%|
[blocklist_de_bots](#blocklist_de_bots)|3421|3421|21|0.6%|0.2%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|20|0.0%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|15|0.0%|0.1%|
[php_harvesters](#php_harvesters)|341|341|12|3.5%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|12|0.0%|0.1%|
[palevo](#palevo)|13|13|11|84.6%|0.1%|
[blocklist_de_apache](#blocklist_de_apache)|16201|16201|9|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|6|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2813|2813|6|0.2%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4840|4840|5|0.1%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2581|2581|4|0.1%|0.0%|
[openbl_30d](#openbl_30d)|2969|2969|3|0.1%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|3|0.0%|0.0%|
[shunlist](#shunlist)|1230|1230|2|0.1%|0.0%|
[proxyrss](#proxyrss)|1481|1481|1|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|1|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|1|0.1%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|319|319|1|0.3%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|158|158|1|0.6%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3473|3473|1|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|320|320|1|0.3%|0.0%|

## spamhaus_drop

[Spamhaus.org](http://www.spamhaus.org) DROP list (according to their site this list should be dropped at tier-1 ISPs globaly) - **excellent list**

Source is downloaded from [this link](http://www.spamhaus.org/drop/drop.txt).

The last time downloaded was found to be dated: Sun Jun  7 15:31:56 UTC 2015.

The ipset `spamhaus_drop` has **652** entries, **18338560** unique IPs.

The following table shows the overlaps of `spamhaus_drop` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `spamhaus_drop`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `spamhaus_drop`.
- ` this % ` is the percentage **of this ipset (`spamhaus_drop`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level1](#firehol_level1)|5086|688943154|18338560|2.6%|100.0%|
[et_block](#et_block)|1023|18338662|18054912|98.4%|98.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|8532506|2.4%|46.5%|
[firehol_level3](#firehol_level3)|107712|9625222|6933025|72.0%|37.8%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|6932480|75.5%|37.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|2272265|0.2%|12.3%|
[fullbogons](#fullbogons)|3720|670264216|151552|0.0%|0.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|130368|0.0%|0.7%|
[alienvault_reputation](#alienvault_reputation)|181932|181932|1374|0.7%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1037|0.3%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92247|92247|1017|1.1%|0.0%|
[dshield](#dshield)|20|5120|768|15.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|512|0.1%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29278|29278|311|1.0%|0.0%|
[firehol_level2](#firehol_level2)|24806|36416|244|0.6%|0.0%|
[openbl_60d](#openbl_60d)|7242|7242|239|3.3%|0.0%|
[blocklist_de](#blocklist_de)|31099|31099|175|0.5%|0.0%|
[openbl_30d](#openbl_30d)|2969|2969|123|4.1%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3473|3473|107|3.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1692|1692|101|5.9%|0.0%|
[et_compromised](#et_compromised)|2016|2016|100|4.9%|0.0%|
[shunlist](#shunlist)|1230|1230|93|7.5%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6697|6697|88|1.3%|0.0%|
[openbl_7d](#openbl_7d)|825|825|43|5.2%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3421|3421|43|1.2%|0.0%|
[php_commenters](#php_commenters)|373|373|29|7.7%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|29|2.2%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|18693|18693|21|0.1%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9492|9492|20|0.2%|0.0%|
[zeus_badips](#zeus_badips)|204|204|16|7.8%|0.0%|
[zeus](#zeus)|233|233|16|6.8%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2813|2813|16|0.5%|0.0%|
[voipbl](#voipbl)|10491|10902|14|0.1%|0.0%|
[openbl_1d](#openbl_1d)|112|112|6|5.3%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|6|0.4%|0.0%|
[firehol_anonymous](#firehol_anonymous)|17786|81795|6|0.0%|0.0%|
[php_dictionary](#php_dictionary)|589|589|5|0.8%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|5|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|158|158|5|3.1%|0.0%|
[php_spammers](#php_spammers)|580|580|4|0.6%|0.0%|
[malc0de](#malc0de)|351|351|4|1.1%|0.0%|
[dm_tor](#dm_tor)|6454|6454|3|0.0%|0.0%|
[bm_tor](#bm_tor)|6458|6458|3|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4840|4840|3|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|16201|16201|3|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|2|0.3%|0.0%|
[firehol_proxies](#firehol_proxies)|11379|11603|2|0.0%|0.0%|
[et_tor](#et_tor)|6470|6470|2|0.0%|0.0%|
[sslbl](#sslbl)|379|379|1|0.2%|0.0%|
[php_harvesters](#php_harvesters)|341|341|1|0.2%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|90|90|1|1.1%|0.0%|

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
[firehol_level1](#firehol_level1)|5086|688943154|487424|0.0%|100.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|270785|0.1%|55.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|98904|0.0%|20.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|33155|0.0%|6.8%|
[et_block](#et_block)|1023|18338662|517|0.0%|0.1%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|512|0.0%|0.1%|
[firehol_level3](#firehol_level3)|107712|9625222|90|0.0%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92247|92247|79|0.0%|0.0%|
[alienvault_reputation](#alienvault_reputation)|181932|181932|15|0.0%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29278|29278|10|0.0%|0.0%|
[php_commenters](#php_commenters)|373|373|7|1.8%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9492|9492|6|0.0%|0.0%|
[zeus_badips](#zeus_badips)|204|204|5|2.4%|0.0%|
[zeus](#zeus)|233|233|5|2.1%|0.0%|
[firehol_level2](#firehol_level2)|24806|36416|5|0.0%|0.0%|
[blocklist_de](#blocklist_de)|31099|31099|3|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6697|6697|2|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|158|158|2|1.2%|0.0%|
[virbl](#virbl)|4|4|1|25.0%|0.0%|
[php_harvesters](#php_harvesters)|341|341|1|0.2%|0.0%|
[openbl_60d](#openbl_60d)|7242|7242|1|0.0%|0.0%|
[openbl_30d](#openbl_30d)|2969|2969|1|0.0%|0.0%|
[malc0de](#malc0de)|351|351|1|0.2%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|319|319|1|0.3%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3473|3473|1|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3421|3421|1|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|16201|16201|1|0.0%|0.0%|

## sslbl

[Abuse.ch SSL Blacklist](https://sslbl.abuse.ch/) bad SSL traffic related to malware or botnet activities - **excellent list**

Source is downloaded from [this link](https://sslbl.abuse.ch/blacklist/sslipblacklist.csv).

The last time downloaded was found to be dated: Mon Jun  8 10:30:05 UTC 2015.

The ipset `sslbl` has **379** entries, **379** unique IPs.

The following table shows the overlaps of `sslbl` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `sslbl`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `sslbl`.
- ` this % ` is the percentage **of this ipset (`sslbl`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level1](#firehol_level1)|5086|688943154|379|0.0%|100.0%|
[firehol_level3](#firehol_level3)|107712|9625222|89|0.0%|23.4%|
[alienvault_reputation](#alienvault_reputation)|181932|181932|64|0.0%|16.8%|
[shunlist](#shunlist)|1230|1230|58|4.7%|15.3%|
[feodo](#feodo)|99|99|36|36.3%|9.4%|
[et_block](#et_block)|1023|18338662|35|0.0%|9.2%|
[snort_ipfilter](#snort_ipfilter)|9492|9492|31|0.3%|8.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|29|0.0%|7.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|4|0.0%|1.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|3|0.0%|0.7%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|1|0.0%|0.2%|
[ri_web_proxies](#ri_web_proxies)|7066|7066|1|0.0%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.2%|
[firehol_proxies](#firehol_proxies)|11379|11603|1|0.0%|0.2%|
[firehol_level2](#firehol_level2)|24806|36416|1|0.0%|0.2%|
[firehol_anonymous](#firehol_anonymous)|17786|81795|1|0.0%|0.2%|
[blocklist_de_ssh](#blocklist_de_ssh)|3473|3473|1|0.0%|0.2%|
[blocklist_de](#blocklist_de)|31099|31099|1|0.0%|0.2%|

## stopforumspam_1d

[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers in the last 24 hours - **excellent list**

Source is downloaded from [this link](http://www.stopforumspam.com/downloads/listed_ip_1.zip).

The last time downloaded was found to be dated: Mon Jun  8 10:00:02 UTC 2015.

The ipset `stopforumspam_1d` has **6697** entries, **6697** unique IPs.

The following table shows the overlaps of `stopforumspam_1d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `stopforumspam_1d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `stopforumspam_1d`.
- ` this % ` is the percentage **of this ipset (`stopforumspam_1d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|24806|36416|6697|18.3%|100.0%|
[firehol_level3](#firehol_level3)|107712|9625222|5665|0.0%|84.5%|
[stopforumspam_30d](#stopforumspam_30d)|92247|92247|5653|6.1%|84.4%|
[stopforumspam_7d](#stopforumspam_7d)|29278|29278|5484|18.7%|81.8%|
[blocklist_de](#blocklist_de)|31099|31099|1409|4.5%|21.0%|
[blocklist_de_bots](#blocklist_de_bots)|3421|3421|1356|39.6%|20.2%|
[firehol_anonymous](#firehol_anonymous)|17786|81795|1060|1.2%|15.8%|
[firehol_proxies](#firehol_proxies)|11379|11603|857|7.3%|12.7%|
[ri_web_proxies](#ri_web_proxies)|7066|7066|515|7.2%|7.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|493|0.0%|7.3%|
[snort_ipfilter](#snort_ipfilter)|9492|9492|385|4.0%|5.7%|
[dm_tor](#dm_tor)|6454|6454|348|5.3%|5.1%|
[bm_tor](#bm_tor)|6458|6458|348|5.3%|5.1%|
[et_tor](#et_tor)|6470|6470|341|5.2%|5.0%|
[proxyrss](#proxyrss)|1481|1481|335|22.6%|5.0%|
[xroxy](#xroxy)|2121|2121|279|13.1%|4.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|188|0.0%|2.8%|
[proxz](#proxz)|1039|1039|177|17.0%|2.6%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|157|42.2%|2.3%|
[ri_connect_proxies](#ri_connect_proxies)|2581|2581|155|6.0%|2.3%|
[php_commenters](#php_commenters)|373|373|149|39.9%|2.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|129|0.0%|1.9%|
[blocklist_de_strongips](#blocklist_de_strongips)|158|158|99|62.6%|1.4%|
[firehol_level1](#firehol_level1)|5086|688943154|90|0.0%|1.3%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|88|0.0%|1.3%|
[et_block](#et_block)|1023|18338662|82|0.0%|1.2%|
[blocklist_de_mail](#blocklist_de_mail)|18693|18693|53|0.2%|0.7%|
[alienvault_reputation](#alienvault_reputation)|181932|181932|52|0.0%|0.7%|
[blocklist_de_apache](#blocklist_de_apache)|16201|16201|49|0.3%|0.7%|
[php_harvesters](#php_harvesters)|341|341|41|12.0%|0.6%|
[nixspam](#nixspam)|20667|20667|41|0.1%|0.6%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|40|0.0%|0.5%|
[php_spammers](#php_spammers)|580|580|31|5.3%|0.4%|
[php_dictionary](#php_dictionary)|589|589|26|4.4%|0.3%|
[openbl_60d](#openbl_60d)|7242|7242|20|0.2%|0.2%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4840|4840|13|0.2%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|7|0.0%|0.1%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|6|0.9%|0.0%|
[voipbl](#voipbl)|10491|10902|3|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|2|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1692|1692|2|0.1%|0.0%|
[zeus_badips](#zeus_badips)|204|204|1|0.4%|0.0%|
[zeus](#zeus)|233|233|1|0.4%|0.0%|
[shunlist](#shunlist)|1230|1230|1|0.0%|0.0%|
[openbl_30d](#openbl_30d)|2969|2969|1|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|1|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|1|0.0%|0.0%|
[et_compromised](#et_compromised)|2016|2016|1|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|320|320|1|0.3%|0.0%|

## stopforumspam_30d

[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 30 days)

Source is downloaded from [this link](http://www.stopforumspam.com/downloads/listed_ip_30.zip).

The last time downloaded was found to be dated: Mon Jun  8 00:00:34 UTC 2015.

The ipset `stopforumspam_30d` has **92247** entries, **92247** unique IPs.

The following table shows the overlaps of `stopforumspam_30d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `stopforumspam_30d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `stopforumspam_30d`.
- ` this % ` is the percentage **of this ipset (`stopforumspam_30d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level3](#firehol_level3)|107712|9625222|92247|0.9%|100.0%|
[stopforumspam_7d](#stopforumspam_7d)|29278|29278|29202|99.7%|31.6%|
[firehol_level2](#firehol_level2)|24806|36416|6884|18.9%|7.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|5743|0.0%|6.2%|
[firehol_anonymous](#firehol_anonymous)|17786|81795|5743|7.0%|6.2%|
[stopforumspam_1d](#stopforumspam_1d)|6697|6697|5653|84.4%|6.1%|
[firehol_proxies](#firehol_proxies)|11379|11603|5098|43.9%|5.5%|
[ri_web_proxies](#ri_web_proxies)|7066|7066|3371|47.7%|3.6%|
[blocklist_de](#blocklist_de)|31099|31099|2521|8.1%|2.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|2489|0.0%|2.6%|
[blocklist_de_bots](#blocklist_de_bots)|3421|3421|2214|64.7%|2.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|1511|0.0%|1.6%|
[ri_connect_proxies](#ri_connect_proxies)|2581|2581|1474|57.1%|1.5%|
[xroxy](#xroxy)|2121|2121|1254|59.1%|1.3%|
[firehol_level1](#firehol_level1)|5086|688943154|1098|0.0%|1.1%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|1017|0.0%|1.1%|
[et_block](#et_block)|1023|18338662|1008|0.0%|1.0%|
[snort_ipfilter](#snort_ipfilter)|9492|9492|796|8.3%|0.8%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|732|0.0%|0.7%|
[proxyrss](#proxyrss)|1481|1481|723|48.8%|0.7%|
[et_tor](#et_tor)|6470|6470|660|10.2%|0.7%|
[dm_tor](#dm_tor)|6454|6454|640|9.9%|0.6%|
[bm_tor](#bm_tor)|6458|6458|640|9.9%|0.6%|
[proxz](#proxz)|1039|1039|626|60.2%|0.6%|
[php_commenters](#php_commenters)|373|373|277|74.2%|0.3%|
[blocklist_de_mail](#blocklist_de_mail)|18693|18693|240|1.2%|0.2%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|232|62.3%|0.2%|
[alienvault_reputation](#alienvault_reputation)|181932|181932|198|0.1%|0.2%|
[blocklist_de_apache](#blocklist_de_apache)|16201|16201|195|1.2%|0.2%|
[php_spammers](#php_spammers)|580|580|122|21.0%|0.1%|
[nixspam](#nixspam)|20667|20667|117|0.5%|0.1%|
[blocklist_de_strongips](#blocklist_de_strongips)|158|158|114|72.1%|0.1%|
[php_dictionary](#php_dictionary)|589|589|111|18.8%|0.1%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|79|0.0%|0.0%|
[php_harvesters](#php_harvesters)|341|341|78|22.8%|0.0%|
[openbl_60d](#openbl_60d)|7242|7242|54|0.7%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|46|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4840|4840|45|0.9%|0.0%|
[voipbl](#voipbl)|10491|10902|37|0.3%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|20|3.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3473|3473|17|0.4%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|15|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2813|2813|14|0.4%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1692|1692|13|0.7%|0.0%|
[et_compromised](#et_compromised)|2016|2016|11|0.5%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|320|320|6|1.8%|0.0%|
[shunlist](#shunlist)|1230|1230|4|0.3%|0.0%|
[openbl_30d](#openbl_30d)|2969|2969|4|0.1%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|4|0.3%|0.0%|
[openbl_7d](#openbl_7d)|825|825|3|0.3%|0.0%|
[zeus_badips](#zeus_badips)|204|204|2|0.9%|0.0%|
[zeus](#zeus)|233|233|2|0.8%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|2|0.1%|0.0%|
[fullbogons](#fullbogons)|3720|670264216|2|0.0%|0.0%|
[openbl_1d](#openbl_1d)|112|112|1|0.8%|0.0%|
[ciarmy](#ciarmy)|422|422|1|0.2%|0.0%|
[bogons](#bogons)|13|592708608|1|0.0%|0.0%|

## stopforumspam_7d

[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 7 days)

Source is downloaded from [this link](http://www.stopforumspam.com/downloads/listed_ip_7.zip).

The last time downloaded was found to be dated: Mon Jun  8 01:00:09 UTC 2015.

The ipset `stopforumspam_7d` has **29278** entries, **29278** unique IPs.

The following table shows the overlaps of `stopforumspam_7d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `stopforumspam_7d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `stopforumspam_7d`.
- ` this % ` is the percentage **of this ipset (`stopforumspam_7d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level3](#firehol_level3)|107712|9625222|29205|0.3%|99.7%|
[stopforumspam_30d](#stopforumspam_30d)|92247|92247|29202|31.6%|99.7%|
[firehol_level2](#firehol_level2)|24806|36416|6355|17.4%|21.7%|
[stopforumspam_1d](#stopforumspam_1d)|6697|6697|5484|81.8%|18.7%|
[firehol_anonymous](#firehol_anonymous)|17786|81795|2816|3.4%|9.6%|
[firehol_proxies](#firehol_proxies)|11379|11603|2418|20.8%|8.2%|
[blocklist_de](#blocklist_de)|31099|31099|2142|6.8%|7.3%|
[blocklist_de_bots](#blocklist_de_bots)|3421|3421|1977|57.7%|6.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|1899|0.0%|6.4%|
[ri_web_proxies](#ri_web_proxies)|7066|7066|1589|22.4%|5.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|853|0.0%|2.9%|
[xroxy](#xroxy)|2121|2121|667|31.4%|2.2%|
[snort_ipfilter](#snort_ipfilter)|9492|9492|632|6.6%|2.1%|
[ri_connect_proxies](#ri_connect_proxies)|2581|2581|624|24.1%|2.1%|
[proxyrss](#proxyrss)|1481|1481|559|37.7%|1.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|558|0.0%|1.9%|
[et_tor](#et_tor)|6470|6470|530|8.1%|1.8%|
[dm_tor](#dm_tor)|6454|6454|513|7.9%|1.7%|
[bm_tor](#bm_tor)|6458|6458|513|7.9%|1.7%|
[proxz](#proxz)|1039|1039|452|43.5%|1.5%|
[firehol_level1](#firehol_level1)|5086|688943154|321|0.0%|1.0%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|311|0.0%|1.0%|
[et_block](#et_block)|1023|18338662|304|0.0%|1.0%|
[php_commenters](#php_commenters)|373|373|206|55.2%|0.7%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|190|51.0%|0.6%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|158|0.0%|0.5%|
[blocklist_de_mail](#blocklist_de_mail)|18693|18693|138|0.7%|0.4%|
[blocklist_de_apache](#blocklist_de_apache)|16201|16201|113|0.6%|0.3%|
[blocklist_de_strongips](#blocklist_de_strongips)|158|158|105|66.4%|0.3%|
[alienvault_reputation](#alienvault_reputation)|181932|181932|95|0.0%|0.3%|
[nixspam](#nixspam)|20667|20667|80|0.3%|0.2%|
[php_dictionary](#php_dictionary)|589|589|74|12.5%|0.2%|
[php_spammers](#php_spammers)|580|580|68|11.7%|0.2%|
[php_harvesters](#php_harvesters)|341|341|59|17.3%|0.2%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4840|4840|28|0.5%|0.0%|
[openbl_60d](#openbl_60d)|7242|7242|24|0.3%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|22|0.0%|0.0%|
[voipbl](#voipbl)|10491|10902|15|0.1%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|13|1.9%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|10|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2813|2813|7|0.2%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|6|0.0%|0.0%|
[et_compromised](#et_compromised)|2016|2016|6|0.2%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1692|1692|6|0.3%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|2|0.1%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3473|3473|2|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|320|320|2|0.6%|0.0%|
[zeus_badips](#zeus_badips)|204|204|1|0.4%|0.0%|
[zeus](#zeus)|233|233|1|0.4%|0.0%|
[shunlist](#shunlist)|1230|1230|1|0.0%|0.0%|
[openbl_30d](#openbl_30d)|2969|2969|1|0.0%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|1|0.0%|0.0%|
[ciarmy](#ciarmy)|422|422|1|0.2%|0.0%|

## virbl

[VirBL](http://virbl.bit.nl/) is a project of which the idea was born during the RIPE-48 meeting. The plan was to get reports of virusscanning mailservers, and put the IP-addresses that were reported to send viruses on a blacklist.

Source is downloaded from [this link](http://virbl.bit.nl/download/virbl.dnsbl.bit.nl.txt).

The last time downloaded was found to be dated: Mon Jun  8 10:07:02 UTC 2015.

The ipset `virbl` has **4** entries, **4** unique IPs.

The following table shows the overlaps of `virbl` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `virbl`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `virbl`.
- ` this % ` is the percentage **of this ipset (`virbl`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level3](#firehol_level3)|107712|9625222|4|0.0%|100.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|1|0.0%|25.0%|
[firehol_level1](#firehol_level1)|5086|688943154|1|0.0%|25.0%|

## voipbl

[VoIPBL.org](http://www.voipbl.org/) a distributed VoIP blacklist that is aimed to protects against VoIP Fraud and minimizing abuse for network that have publicly accessible PBX's. Several algorithms, external sources and manual confirmation are used before they categorize something as an attack and determine the threat level.

Source is downloaded from [this link](http://www.voipbl.org/update/).

The last time downloaded was found to be dated: Mon Jun  8 08:45:12 UTC 2015.

The ipset `voipbl` has **10491** entries, **10902** unique IPs.

The following table shows the overlaps of `voipbl` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `voipbl`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `voipbl`.
- ` this % ` is the percentage **of this ipset (`voipbl`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|1600|0.0%|14.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|434|0.0%|3.9%|
[firehol_level1](#firehol_level1)|5086|688943154|333|0.0%|3.0%|
[fullbogons](#fullbogons)|3720|670264216|319|0.0%|2.9%|
[bogons](#bogons)|13|592708608|319|0.0%|2.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|299|0.0%|2.7%|
[alienvault_reputation](#alienvault_reputation)|181932|181932|196|0.1%|1.7%|
[firehol_anonymous](#firehol_anonymous)|17786|81795|78|0.0%|0.7%|
[firehol_level3](#firehol_level3)|107712|9625222|60|0.0%|0.5%|
[stopforumspam_30d](#stopforumspam_30d)|92247|92247|37|0.0%|0.3%|
[firehol_level2](#firehol_level2)|24806|36416|37|0.1%|0.3%|
[blocklist_de](#blocklist_de)|31099|31099|34|0.1%|0.3%|
[blocklist_de_sip](#blocklist_de_sip)|90|90|30|33.3%|0.2%|
[et_block](#et_block)|1023|18338662|18|0.0%|0.1%|
[stopforumspam_7d](#stopforumspam_7d)|29278|29278|15|0.0%|0.1%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|14|0.0%|0.1%|
[shunlist](#shunlist)|1230|1230|12|0.9%|0.1%|
[openbl_60d](#openbl_60d)|7242|7242|8|0.1%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|4|0.0%|0.0%|
[ciarmy](#ciarmy)|422|422|4|0.9%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|16201|16201|4|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6697|6697|3|0.0%|0.0%|
[openbl_30d](#openbl_30d)|2969|2969|3|0.1%|0.0%|
[et_tor](#et_tor)|6470|6470|3|0.0%|0.0%|
[dm_tor](#dm_tor)|6454|6454|3|0.0%|0.0%|
[bm_tor](#bm_tor)|6458|6458|3|0.0%|0.0%|
[nixspam](#nixspam)|20667|20667|2|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|2|0.0%|0.0%|
[et_compromised](#et_compromised)|2016|2016|2|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1692|1692|2|0.1%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.0%|
[firehol_proxies](#firehol_proxies)|11379|11603|1|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4840|4840|1|0.0%|0.0%|

## xroxy

[xroxy.com](http://www.xroxy.com) open proxies (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.xroxy.com/proxyrss.xml).

The last time downloaded was found to be dated: Mon Jun  8 10:33:01 UTC 2015.

The ipset `xroxy` has **2121** entries, **2121** unique IPs.

The following table shows the overlaps of `xroxy` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `xroxy`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `xroxy`.
- ` this % ` is the percentage **of this ipset (`xroxy`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_proxies](#firehol_proxies)|11379|11603|2121|18.2%|100.0%|
[firehol_anonymous](#firehol_anonymous)|17786|81795|2121|2.5%|100.0%|
[firehol_level3](#firehol_level3)|107712|9625222|1268|0.0%|59.7%|
[stopforumspam_30d](#stopforumspam_30d)|92247|92247|1254|1.3%|59.1%|
[ri_web_proxies](#ri_web_proxies)|7066|7066|921|13.0%|43.4%|
[stopforumspam_7d](#stopforumspam_7d)|29278|29278|667|2.2%|31.4%|
[proxz](#proxz)|1039|1039|382|36.7%|18.0%|
[ri_connect_proxies](#ri_connect_proxies)|2581|2581|378|14.6%|17.8%|
[proxyrss](#proxyrss)|1481|1481|372|25.1%|17.5%|
[firehol_level2](#firehol_level2)|24806|36416|360|0.9%|16.9%|
[stopforumspam_1d](#stopforumspam_1d)|6697|6697|279|4.1%|13.1%|
[blocklist_de](#blocklist_de)|31099|31099|202|0.6%|9.5%|
[blocklist_de_bots](#blocklist_de_bots)|3421|3421|160|4.6%|7.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|104|0.0%|4.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|100|0.0%|4.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|58|0.0%|2.7%|
[nixspam](#nixspam)|20667|20667|40|0.1%|1.8%|
[blocklist_de_mail](#blocklist_de_mail)|18693|18693|40|0.2%|1.8%|
[php_dictionary](#php_dictionary)|589|589|35|5.9%|1.6%|
[snort_ipfilter](#snort_ipfilter)|9492|9492|34|0.3%|1.6%|
[php_spammers](#php_spammers)|580|580|27|4.6%|1.2%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|13|1.9%|0.6%|
[php_commenters](#php_commenters)|373|373|8|2.1%|0.3%|
[blocklist_de_strongips](#blocklist_de_strongips)|158|158|5|3.1%|0.2%|
[alienvault_reputation](#alienvault_reputation)|181932|181932|4|0.0%|0.1%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|3|0.0%|0.1%|
[php_harvesters](#php_harvesters)|341|341|2|0.5%|0.0%|
[et_tor](#et_tor)|6470|6470|2|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|16201|16201|2|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.0%|
[et_compromised](#et_compromised)|2016|2016|1|0.0%|0.0%|
[dm_tor](#dm_tor)|6454|6454|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1692|1692|1|0.0%|0.0%|
[bm_tor](#bm_tor)|6458|6458|1|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4840|4840|1|0.0%|0.0%|

## zeus

[Abuse.ch Zeus tracker](https://zeustracker.abuse.ch) standard, contains the same data as the ZeuS IP blocklist (zeus_badips) but with the slight difference that it doesn't exclude hijacked websites (level 2) and free web hosting providers (level 3). This means that this blocklist contains all IPv4 addresses associated with ZeuS C&Cs which are currently being tracked by ZeuS Tracker. Hence this blocklist will likely cause some false positives. - **excellent list**

Source is downloaded from [this link](https://zeustracker.abuse.ch/blocklist.php?download=ipblocklist).

The last time downloaded was found to be dated: Mon Jun  8 09:07:30 UTC 2015.

The ipset `zeus` has **233** entries, **233** unique IPs.

The following table shows the overlaps of `zeus` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `zeus`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `zeus`.
- ` this % ` is the percentage **of this ipset (`zeus`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level1](#firehol_level1)|5086|688943154|233|0.0%|100.0%|
[et_block](#et_block)|1023|18338662|222|0.0%|95.2%|
[firehol_level3](#firehol_level3)|107712|9625222|205|0.0%|87.9%|
[zeus_badips](#zeus_badips)|204|204|204|100.0%|87.5%|
[snort_ipfilter](#snort_ipfilter)|9492|9492|203|2.1%|87.1%|
[alienvault_reputation](#alienvault_reputation)|181932|181932|62|0.0%|26.6%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|16|0.0%|6.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|14|0.0%|6.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|10|0.0%|4.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|9|0.0%|3.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|6|0.0%|2.5%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|5|0.0%|2.1%|
[stopforumspam_30d](#stopforumspam_30d)|92247|92247|2|0.0%|0.8%|
[openbl_60d](#openbl_60d)|7242|7242|2|0.0%|0.8%|
[openbl_30d](#openbl_30d)|2969|2969|2|0.0%|0.8%|
[firehol_level2](#firehol_level2)|24806|36416|2|0.0%|0.8%|
[stopforumspam_7d](#stopforumspam_7d)|29278|29278|1|0.0%|0.4%|
[stopforumspam_1d](#stopforumspam_1d)|6697|6697|1|0.0%|0.4%|
[php_commenters](#php_commenters)|373|373|1|0.2%|0.4%|
[nixspam](#nixspam)|20667|20667|1|0.0%|0.4%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.4%|
[blocklist_de_mail](#blocklist_de_mail)|18693|18693|1|0.0%|0.4%|
[blocklist_de_imap](#blocklist_de_imap)|2813|2813|1|0.0%|0.4%|
[blocklist_de](#blocklist_de)|31099|31099|1|0.0%|0.4%|

## zeus_badips

[Abuse.ch Zeus tracker](https://zeustracker.abuse.ch) badips includes IPv4 addresses that are used by the ZeuS trojan. It is the recommened blocklist if you want to block only ZeuS IPs. It excludes IP addresses that ZeuS Tracker believes to be hijacked (level 2) or belong to a free web hosting provider (level 3). Hence the false postive rate should be much lower compared to the standard ZeuS IP blocklist. **excellent list**

Source is downloaded from [this link](https://zeustracker.abuse.ch/blocklist.php?download=badips).

The last time downloaded was found to be dated: Mon Jun  8 10:36:06 UTC 2015.

The ipset `zeus_badips` has **204** entries, **204** unique IPs.

The following table shows the overlaps of `zeus_badips` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `zeus_badips`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `zeus_badips`.
- ` this % ` is the percentage **of this ipset (`zeus_badips`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[zeus](#zeus)|233|233|204|87.5%|100.0%|
[firehol_level1](#firehol_level1)|5086|688943154|204|0.0%|100.0%|
[et_block](#et_block)|1023|18338662|200|0.0%|98.0%|
[firehol_level3](#firehol_level3)|107712|9625222|182|0.0%|89.2%|
[snort_ipfilter](#snort_ipfilter)|9492|9492|180|1.8%|88.2%|
[alienvault_reputation](#alienvault_reputation)|181932|181932|38|0.0%|18.6%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|16|0.0%|7.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|10|0.0%|4.9%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|10|0.0%|4.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|8|0.0%|3.9%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|5|0.0%|2.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|4|0.0%|1.9%|
[stopforumspam_30d](#stopforumspam_30d)|92247|92247|2|0.0%|0.9%|
[firehol_level2](#firehol_level2)|24806|36416|2|0.0%|0.9%|
[stopforumspam_7d](#stopforumspam_7d)|29278|29278|1|0.0%|0.4%|
[stopforumspam_1d](#stopforumspam_1d)|6697|6697|1|0.0%|0.4%|
[php_commenters](#php_commenters)|373|373|1|0.2%|0.4%|
[openbl_60d](#openbl_60d)|7242|7242|1|0.0%|0.4%|
[openbl_30d](#openbl_30d)|2969|2969|1|0.0%|0.4%|
[nixspam](#nixspam)|20667|20667|1|0.0%|0.4%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.4%|
[blocklist_de_mail](#blocklist_de_mail)|18693|18693|1|0.0%|0.4%|
[blocklist_de_imap](#blocklist_de_imap)|2813|2813|1|0.0%|0.4%|
[blocklist_de](#blocklist_de)|31099|31099|1|0.0%|0.4%|
