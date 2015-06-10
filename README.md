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

The following list was automatically generated on Wed Jun 10 03:00:55 UTC 2015.

The update frequency is the maximum allowed by internal configuration. A list will never be downloaded sooner than the update frequency stated. A list may also not be downloaded, after this frequency expired, if it has not been modified on the server (as reported by HTTP `IF_MODIFIED_SINCE` method).

name|info|type|entries|update|
:--:|:--:|:--:|:-----:|:----:|
[alienvault_reputation](#alienvault_reputation)|[AlienVault.com](https://www.alienvault.com/) IP reputation database (this list seems to include port scanning hosts and to be updated regularly, but we found no information about its retention policy)|ipv4 hash:ip|180612 unique IPs|updated every 6 hours  from [this link](https://reputation.alienvault.com/reputation.generic)
[blocklist_de](#blocklist_de)|[Blocklist.de](https://www.blocklist.de/) IPs that have been detected by fail2ban in the last 48 hours - **excellent list**|ipv4 hash:ip|30769 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/all.txt)
[blocklist_de_apache](#blocklist_de_apache)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service Apache, Apache-DDOS, RFI-Attacks.|ipv4 hash:ip|15619 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/apache.txt)
[blocklist_de_bots](#blocklist_de_bots)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the RFI-Attacks, REG-Bots, IRC-Bots or BadBots (BadBots = he has posted a Spam-Comment on a open Forum or Wiki).|ipv4 hash:ip|3122 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/bots.txt)
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|[Blocklist.de](https://www.blocklist.de/) All IPs which attacks Joomlas, Wordpress and other Web-Logins with Brute-Force Logins.|ipv4 hash:ip|4256 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/bruteforcelogin.txt)
[blocklist_de_ftp](#blocklist_de_ftp)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours for attacks on the Service FTP.|ipv4 hash:ip|712 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/ftp.txt)
[blocklist_de_imap](#blocklist_de_imap)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours for attacks on the Service imap, sasl, pop3, etc.|ipv4 hash:ip|2334 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/imap.txt)
[blocklist_de_mail](#blocklist_de_mail)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service Mail, Postfix.|ipv4 hash:ip|19075 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/mail.txt)
[blocklist_de_sip](#blocklist_de_sip)|[Blocklist.de](https://www.blocklist.de/) All IP addresses that tried to login in a SIP, VOIP or Asterisk Server and are included in the IPs list from [infiltrated.net](www.infiltrated.net)|ipv4 hash:ip|81 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/sip.txt)
[blocklist_de_ssh](#blocklist_de_ssh)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service SSH.|ipv4 hash:ip|3255 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/ssh.txt)
[blocklist_de_strongips](#blocklist_de_strongips)|[Blocklist.de](https://www.blocklist.de/) All IPs which are older then 2 month and have more then 5.000 attacks.|ipv4 hash:ip|174 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/strongips.txt)
[bm_tor](#bm_tor)|[torstatus.blutmagie.de](https://torstatus.blutmagie.de) list of all TOR network servers|ipv4 hash:ip|6425 unique IPs|updated every 30 mins  from [this link](https://torstatus.blutmagie.de/ip_list_all.php/Tor_ip_list_ALL.csv)
[bogons](#bogons)|[Team-Cymru.org](http://www.team-cymru.org) private and reserved addresses defined by RFC 1918, RFC 5735, and RFC 6598 and netblocks that have not been allocated to a regional internet registry - **excellent list - use it only your internet interface**|ipv4 hash:net|13 subnets, 592708608 unique IPs|updated every 1 day  from [this link](http://www.team-cymru.org/Services/Bogons/bogon-bn-agg.txt)
[bruteforceblocker](#bruteforceblocker)|[danger.rulez.sk](http://danger.rulez.sk/) IPs detected by [bruteforceblocker](http://danger.rulez.sk/index.php/bruteforceblocker/) (fail2ban alternative for SSH on OpenBSD). This is an automatically generated list from users reporting failed authentication attempts. An IP seems to be included if 3 or more users report it. Its retention pocily seems 30 days.|ipv4 hash:ip|1723 unique IPs|updated every 3 hours  from [this link](http://danger.rulez.sk/projects/bruteforceblocker/blist.php)
[ciarmy](#ciarmy)|[CIArmy.com](http://ciarmy.com/) IPs with poor Rogue Packet score that have not yet been identified as malicious by the community|ipv4 hash:ip|409 unique IPs|updated every 3 hours  from [this link](http://cinsscore.com/list/ci-badguys.txt)
[cleanmx_viruses](#cleanmx_viruses)|[Clean-MX.de](http://support.clean-mx.de/clean-mx/viruses.php) IPs with viruses|ipv4 hash:ip|172 unique IPs|updated every 12 hours  from [this link](http://support.clean-mx.de/clean-mx/xmlviruses.php?sort=id%20desc&response=alive)
[dm_tor](#dm_tor)|[dan.me.uk](https://www.dan.me.uk) dynamic list of TOR exit points|ipv4 hash:ip|6405 unique IPs|updated every 30 mins  from [this link](https://www.dan.me.uk/torlist/)
[dshield](#dshield)|[DShield.org](https://dshield.org/) top 20 attacking class C (/24) subnets over the last three days - **excellent list**|ipv4 hash:net|20 subnets, 5120 unique IPs|updated every 4 hours  from [this link](http://feeds.dshield.org/block.txt)
[et_block](#et_block)|[EmergingThreats.net](http://www.emergingthreats.net/) default blacklist (at the time of writing includes spamhaus DROP, dshield and abuse.ch trackers, which are available separately too - prefer to use the direct ipsets instead of this, they seem to lag a bit in updates)|ipv4 hash:net|999 subnets, 18343755 unique IPs|updated every 12 hours  from [this link](http://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt)
[et_botcc](#et_botcc)|[EmergingThreats.net Command and Control IPs](http://doc.emergingthreats.net/bin/view/Main/BotCC) These IPs are updates every 24 hours and should be considered VERY highly reliable indications that a host is communicating with a known and active Bot or Malware command and control server - (although they say this includes abuse.ch trackers, it does not - most probably it is the shadowserver.org C&C list)|ipv4 hash:ip|509 unique IPs|updated every 12 hours  from [this link](http://rules.emergingthreats.net/fwrules/emerging-PIX-CC.rules)
[et_compromised](#et_compromised)|[EmergingThreats.net compromised hosts](http://doc.emergingthreats.net/bin/view/Main/CompromisedHost) - (this seems to be based on bruteforceblocker)|ipv4 hash:ip|1718 unique IPs|updated every 12 hours  from [this link](http://rules.emergingthreats.net/blockrules/compromised-ips.txt)
et_dshield|[EmergingThreats.net](http://www.emergingthreats.net/) dshield blocklist|ipv4 hash:net|disabled|updated every 12 hours  from [this link](http://rules.emergingthreats.net/fwrules/emerging-PIX-DSHIELD.rules)
et_spamhaus|[EmergingThreats.net](http://www.emergingthreats.net/) spamhaus blocklist|ipv4 hash:net|disabled|updated every 12 hours  from [this link](http://rules.emergingthreats.net/fwrules/emerging-PIX-DROP.rules)
[et_tor](#et_tor)|[EmergingThreats.net](http://www.emergingthreats.net/) [list](http://doc.emergingthreats.net/bin/view/Main/TorRules) of TOR network IPs|ipv4 hash:ip|6340 unique IPs|updated every 12 hours  from [this link](http://rules.emergingthreats.net/blockrules/emerging-tor.rules)
[feodo](#feodo)|[Abuse.ch Feodo tracker](https://feodotracker.abuse.ch) trojan includes IPs which are being used by Feodo (also known as Cridex or Bugat) which commits ebanking fraud - **excellent list**|ipv4 hash:ip|104 unique IPs|updated every 30 mins  from [this link](https://feodotracker.abuse.ch/blocklist/?download=ipblocklist)
[firehol_anonymous](#firehol_anonymous)|**FireHOL Anonymous** - Known anonymizing IPs. (includes: firehol_proxies anonymous bm_tor dm_tor)|ipv4 hash:net|18532 subnets, 82552 unique IPs|updated every 1 min  from [this link]()
[firehol_level1](#firehol_level1)|**FireHOL Level 1** - Maximum protection without false positives. (includes: fullbogons dshield feodo palevo sslbl zeus spamhaus_drop spamhaus_edrop)|ipv4 hash:net|5146 subnets, 688981121 unique IPs|updated every 1 min  from [this link]()
[firehol_level2](#firehol_level2)|**FireHOL Level 2** - Maximum protection from attacks took place in the last 48 hours. (includes: openbl_1d blocklist_de stopforumspam_1d)|ipv4 hash:net|24709 subnets, 36348 unique IPs|updated every 1 min  from [this link]()
[firehol_level3](#firehol_level3)|**FireHOL Level 3** - All the bad IPs in last 30 days. (includes: openbl_30d stopforumspam_30d virbl malc0de shunlist malwaredomainlist bruteforceblocker ciarmy cleanmx_viruses snort_ipfilter ib_bluetack_spyware ib_bluetack_hijacked ib_bluetack_webexploit php_commenters php_dictionary php_harvesters php_spammers)|ipv4 hash:net|109859 subnets, 9627471 unique IPs|updated every 1 min  from [this link]()
[firehol_proxies](#firehol_proxies)|**FireHOL Proxies** - Known open proxies in the last 30 days. (includes: ib_bluetack_proxies maxmind_proxy_fraud proxyrss proxz ri_connect_proxies ri_web_proxies xroxy)|ipv4 hash:net|11968 subnets, 12206 unique IPs|updated every 1 min  from [this link]()
[fullbogons](#fullbogons)|[Team-Cymru.org](http://www.team-cymru.org) IP space that has been allocated to an RIR, but not assigned by that RIR to an actual ISP or other end-user - **excellent list - use it only your internet interface**|ipv4 hash:net|3778 subnets, 670299624 unique IPs|updated every 1 day  from [this link](http://www.team-cymru.org/Services/Bogons/fullbogons-ipv4.txt)
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
[malc0de](#malc0de)|[Malc0de.com](http://malc0de.com) malicious IPs of the last 30 days|ipv4 hash:ip|338 unique IPs|updated every 1 day  from [this link](http://malc0de.com/bl/IP_Blacklist.txt)
[malwaredomainlist](#malwaredomainlist)|[malwaredomainlist.com](http://www.malwaredomainlist.com) list of malware active ip addresses|ipv4 hash:ip|1288 unique IPs|updated every 12 hours  from [this link](http://www.malwaredomainlist.com/hostslist/ip.txt)
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|[MaxMind.com](https://www.maxmind.com/en/anonymous-proxy-fraudulent-ip-address-list) list of anonymous proxy fraudelent IP addresses.|ipv4 hash:ip|372 unique IPs|updated every 4 hours  from [this link](https://www.maxmind.com/en/anonymous-proxy-fraudulent-ip-address-list)
[nixspam](#nixspam)|[NiX Spam](http://www.heise.de/ix/NiX-Spam-DNSBL-and-blacklist-for-download-499637.html) IP addresses that sent spam in the last hour - automatically generated entries without distinguishing open proxies from relays, dialup gateways, and so on. All IPs are removed after 12 hours if there is no spam from there.|ipv4 hash:ip|23906 unique IPs|updated every 15 mins  from [this link](http://www.dnsbl.manitu.net/download/nixspam-ip.dump.gz)
openbl|[OpenBL.org](http://www.openbl.org/) default blacklist (currently it is the same with 90 days). OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications - **excellent list**|ipv4 hash:ip|disabled|updated every 4 hours  from [this link](http://www.openbl.org/lists/base.txt)
openbl_180d|[OpenBL.org](http://www.openbl.org/) last 180 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|disabled|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_180days.txt)
[openbl_1d](#openbl_1d)|[OpenBL.org](http://www.openbl.org/) last 24 hours IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|161 unique IPs|updated every 1 hour  from [this link](http://www.openbl.org/lists/base_1days.txt)
[openbl_30d](#openbl_30d)|[OpenBL.org](http://www.openbl.org/) last 30 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|2857 unique IPs|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_30days.txt)
openbl_360d|[OpenBL.org](http://www.openbl.org/) last 360 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|disabled|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_360days.txt)
[openbl_60d](#openbl_60d)|[OpenBL.org](http://www.openbl.org/) last 60 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|7023 unique IPs|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_60days.txt)
[openbl_7d](#openbl_7d)|[OpenBL.org](http://www.openbl.org/) last 7 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|708 unique IPs|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_7days.txt)
openbl_90d|[OpenBL.org](http://www.openbl.org/) last 90 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|disabled|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_90days.txt)
openbl_all|[OpenBL.org](http://www.openbl.org/) last all IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|disabled|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_all.txt)
[palevo](#palevo)|[Abuse.ch Palevo tracker](https://palevotracker.abuse.ch) worm includes IPs which are being used as botnet C&C for the Palevo crimeware - **excellent list**|ipv4 hash:ip|13 unique IPs|updated every 30 mins  from [this link](https://palevotracker.abuse.ch/blocklists.php?download=ipblocklist)
php_bad|[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) bad web hosts (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|disabled|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=b&rss=1)
[php_commenters](#php_commenters)|[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) comment spammers (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|403 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=c&rss=1)
[php_dictionary](#php_dictionary)|[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) directory attackers (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|666 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=d&rss=1)
[php_harvesters](#php_harvesters)|[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) harvesters (IPs that surf the internet looking for email addresses) (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|378 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=h&rss=1)
[php_spammers](#php_spammers)|[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) spam servers (IPs used by spammers to send messages) (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|661 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=s&rss=1)
[proxyrss](#proxyrss)|[proxyrss.com](http://www.proxyrss.com) open proxies syndicated from multiple sources.|ipv4 hash:ip|1602 unique IPs|updated every 4 hours  from [this link](http://www.proxyrss.com/proxylists/all.gz)
[proxz](#proxz)|[proxz.com](http://www.proxz.com) open proxies (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|1173 unique IPs|updated every 1 hour  from [this link](http://www.proxz.com/proxylists.xml)
[ri_connect_proxies](#ri_connect_proxies)|[rosinstrument.com](http://www.rosinstrument.com) open CONNECT proxies (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|2695 unique IPs|updated every 1 hour  from [this link](http://tools.rosinstrument.com/proxy/plab100.xml)
[ri_web_proxies](#ri_web_proxies)|[rosinstrument.com](http://www.rosinstrument.com) open HTTP proxies (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|7435 unique IPs|updated every 1 hour  from [this link](http://tools.rosinstrument.com/proxy/l100.xml)
[shunlist](#shunlist)|[AutoShun.org](http://autoshun.org/) IPs identified as hostile by correlating logs from distributed snort installations running the autoshun plugin|ipv4 hash:ip|1315 unique IPs|updated every 4 hours  from [this link](http://www.autoshun.org/files/shunlist.csv)
[snort_ipfilter](#snort_ipfilter)|[labs.snort.org](https://labs.snort.org/) supplied IP blacklist (this list seems to be updated frequently, but we found no information about it)|ipv4 hash:ip|10136 unique IPs|updated every 12 hours  from [this link](http://labs.snort.org/feeds/ip-filter.blf)
[spamhaus_drop](#spamhaus_drop)|[Spamhaus.org](http://www.spamhaus.org) DROP list (according to their site this list should be dropped at tier-1 ISPs globaly) - **excellent list**|ipv4 hash:net|653 subnets, 18340608 unique IPs|updated every 12 hours  from [this link](http://www.spamhaus.org/drop/drop.txt)
[spamhaus_edrop](#spamhaus_edrop)|[Spamhaus.org](http://www.spamhaus.org) EDROP (extended matches that should be used with DROP) - **excellent list**|ipv4 hash:net|56 subnets, 487424 unique IPs|updated every 12 hours  from [this link](http://www.spamhaus.org/drop/edrop.txt)
[sslbl](#sslbl)|[Abuse.ch SSL Blacklist](https://sslbl.abuse.ch/) bad SSL traffic related to malware or botnet activities - **excellent list**|ipv4 hash:ip|376 unique IPs|updated every 30 mins  from [this link](https://sslbl.abuse.ch/blacklist/sslipblacklist.csv)
stopforumspam_180d|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 180 days)|ipv4 hash:ip|disabled|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/listed_ip_180.zip)
[stopforumspam_1d](#stopforumspam_1d)|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers in the last 24 hours - **excellent list**|ipv4 hash:ip|6943 unique IPs|updated every 1 hour  from [this link](http://www.stopforumspam.com/downloads/listed_ip_1.zip)
[stopforumspam_30d](#stopforumspam_30d)|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 30 days)|ipv4 hash:ip|93938 unique IPs|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/listed_ip_30.zip)
stopforumspam_365d|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 365 days)|ipv4 hash:ip|disabled|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/listed_ip_365.zip)
[stopforumspam_7d](#stopforumspam_7d)|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 7 days)|ipv4 hash:ip|29338 unique IPs|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/listed_ip_7.zip)
stopforumspam_90d|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 90 days)|ipv4 hash:ip|disabled|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/listed_ip_90.zip)
stopforumspam_ever|[StopForumSpam.com](http://www.stopforumspam.com) all IPs used by forum spammers, **ever** (normally you don't want to use this ipset, use the hourly one which includes last 24 hours IPs or the 7 days one)|ipv4 hash:ip|disabled|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/bannedips.zip)
[virbl](#virbl)|[VirBL](http://virbl.bit.nl/) is a project of which the idea was born during the RIPE-48 meeting. The plan was to get reports of virusscanning mailservers, and put the IP-addresses that were reported to send viruses on a blacklist.|ipv4 hash:ip|25 unique IPs|updated every 1 hour  from [this link](http://virbl.bit.nl/download/virbl.dnsbl.bit.nl.txt)
[voipbl](#voipbl)|[VoIPBL.org](http://www.voipbl.org/) a distributed VoIP blacklist that is aimed to protects against VoIP Fraud and minimizing abuse for network that have publicly accessible PBX's. Several algorithms, external sources and manual confirmation are used before they categorize something as an attack and determine the threat level.|ipv4 hash:net|10522 subnets, 10934 unique IPs|updated every 4 hours  from [this link](http://www.voipbl.org/update/)
[xroxy](#xroxy)|[xroxy.com](http://www.xroxy.com) open proxies (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|2147 unique IPs|updated every 1 hour  from [this link](http://www.xroxy.com/proxyrss.xml)
[zeus](#zeus)|[Abuse.ch Zeus tracker](https://zeustracker.abuse.ch) standard, contains the same data as the ZeuS IP blocklist (zeus_badips) but with the slight difference that it doesn't exclude hijacked websites (level 2) and free web hosting providers (level 3). This means that this blocklist contains all IPv4 addresses associated with ZeuS C&Cs which are currently being tracked by ZeuS Tracker. Hence this blocklist will likely cause some false positives. - **excellent list**|ipv4 hash:ip|231 unique IPs|updated every 30 mins  from [this link](https://zeustracker.abuse.ch/blocklist.php?download=ipblocklist)
[zeus_badips](#zeus_badips)|[Abuse.ch Zeus tracker](https://zeustracker.abuse.ch) badips includes IPv4 addresses that are used by the ZeuS trojan. It is the recommened blocklist if you want to block only ZeuS IPs. It excludes IP addresses that ZeuS Tracker believes to be hijacked (level 2) or belong to a free web hosting provider (level 3). Hence the false postive rate should be much lower compared to the standard ZeuS IP blocklist. **excellent list**|ipv4 hash:ip|203 unique IPs|updated every 30 mins  from [this link](https://zeustracker.abuse.ch/blocklist.php?download=badips)

# Comparison of ipsets

Below we compare each ipset against all other.


## alienvault_reputation

[AlienVault.com](https://www.alienvault.com/) IP reputation database (this list seems to include port scanning hosts and to be updated regularly, but we found no information about its retention policy)

Source is downloaded from [this link](https://reputation.alienvault.com/reputation.generic).

The last time downloaded was found to be dated: Tue Jun  9 22:01:34 UTC 2015.

The ipset `alienvault_reputation` has **180612** entries, **180612** unique IPs.

The following table shows the overlaps of `alienvault_reputation` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `alienvault_reputation`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `alienvault_reputation`.
- ` this % ` is the percentage **of this ipset (`alienvault_reputation`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|13614|0.0%|7.5%|
[openbl_60d](#openbl_60d)|7023|7023|6988|99.5%|3.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|6256|0.0%|3.4%|
[et_block](#et_block)|999|18343755|6045|0.0%|3.3%|
[firehol_level3](#firehol_level3)|109859|9627471|5169|0.0%|2.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|4216|0.0%|2.3%|
[firehol_level1](#firehol_level1)|5146|688981121|3820|0.0%|2.1%|
[openbl_30d](#openbl_30d)|2857|2857|2828|98.9%|1.5%|
[dshield](#dshield)|20|5120|2562|50.0%|1.4%|
[firehol_level2](#firehol_level2)|24709|36348|1458|4.0%|0.8%|
[blocklist_de](#blocklist_de)|30769|30769|1402|4.5%|0.7%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|1373|0.0%|0.7%|
[shunlist](#shunlist)|1315|1315|1299|98.7%|0.7%|
[blocklist_de_ssh](#blocklist_de_ssh)|3255|3255|1166|35.8%|0.6%|
[bruteforceblocker](#bruteforceblocker)|1723|1723|1109|64.3%|0.6%|
[et_compromised](#et_compromised)|1718|1718|1104|64.2%|0.6%|
[openbl_7d](#openbl_7d)|708|708|691|97.5%|0.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|518|0.0%|0.2%|
[ciarmy](#ciarmy)|409|409|396|96.8%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|288|0.0%|0.1%|
[stopforumspam_30d](#stopforumspam_30d)|93938|93938|205|0.2%|0.1%|
[voipbl](#voipbl)|10522|10934|192|1.7%|0.1%|
[openbl_1d](#openbl_1d)|161|161|146|90.6%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|15619|15619|130|0.8%|0.0%|
[snort_ipfilter](#snort_ipfilter)|10136|10136|118|1.1%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|103|0.3%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|19075|19075|67|0.3%|0.0%|
[sslbl](#sslbl)|376|376|66|17.5%|0.0%|
[zeus](#zeus)|231|231|62|26.8%|0.0%|
[firehol_anonymous](#firehol_anonymous)|18532|82552|54|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6943|6943|49|0.7%|0.0%|
[nixspam](#nixspam)|23906|23906|44|0.1%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2334|2334|42|1.7%|0.0%|
[et_tor](#et_tor)|6340|6340|39|0.6%|0.0%|
[dm_tor](#dm_tor)|6405|6405|39|0.6%|0.0%|
[bm_tor](#bm_tor)|6425|6425|39|0.6%|0.0%|
[zeus_badips](#zeus_badips)|203|203|38|18.7%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|174|174|35|20.1%|0.0%|
[firehol_proxies](#firehol_proxies)|11968|12206|34|0.2%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|26|6.9%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|81|81|21|25.9%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4256|4256|21|0.4%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3122|3122|19|0.6%|0.0%|
[php_commenters](#php_commenters)|403|403|18|4.4%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|15|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|14|0.0%|0.0%|
[php_harvesters](#php_harvesters)|378|378|12|3.1%|0.0%|
[malc0de](#malc0de)|338|338|11|3.2%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|712|712|11|1.5%|0.0%|
[php_dictionary](#php_dictionary)|666|666|8|1.2%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|8|0.6%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|6|0.4%|0.0%|
[xroxy](#xroxy)|2147|2147|5|0.2%|0.0%|
[php_spammers](#php_spammers)|661|661|5|0.7%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7435|7435|4|0.0%|0.0%|
[et_botcc](#et_botcc)|509|509|4|0.7%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|172|172|4|2.3%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2695|2695|3|0.1%|0.0%|
[proxz](#proxz)|1173|1173|3|0.2%|0.0%|
[feodo](#feodo)|104|104|2|1.9%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|1|0.1%|0.0%|

## blocklist_de

[Blocklist.de](https://www.blocklist.de/) IPs that have been detected by fail2ban in the last 48 hours - **excellent list**

Source is downloaded from [this link](http://lists.blocklist.de/lists/all.txt).

The last time downloaded was found to be dated: Wed Jun 10 02:42:05 UTC 2015.

The ipset `blocklist_de` has **30769** entries, **30769** unique IPs.

The following table shows the overlaps of `blocklist_de` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de`.
- ` this % ` is the percentage **of this ipset (`blocklist_de`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|24709|36348|30769|84.6%|100.0%|
[blocklist_de_mail](#blocklist_de_mail)|19075|19075|19075|100.0%|61.9%|
[blocklist_de_apache](#blocklist_de_apache)|15619|15619|15619|100.0%|50.7%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4256|4256|4256|100.0%|13.8%|
[firehol_level3](#firehol_level3)|109859|9627471|3982|0.0%|12.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|3879|0.0%|12.6%|
[blocklist_de_ssh](#blocklist_de_ssh)|3255|3255|3255|100.0%|10.5%|
[blocklist_de_bots](#blocklist_de_bots)|3122|3122|3122|100.0%|10.1%|
[stopforumspam_30d](#stopforumspam_30d)|93938|93938|2630|2.7%|8.5%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|2343|7.9%|7.6%|
[blocklist_de_imap](#blocklist_de_imap)|2334|2334|2334|100.0%|7.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|1601|0.0%|5.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|1553|0.0%|5.0%|
[alienvault_reputation](#alienvault_reputation)|180612|180612|1402|0.7%|4.5%|
[stopforumspam_1d](#stopforumspam_1d)|6943|6943|1395|20.0%|4.5%|
[openbl_60d](#openbl_60d)|7023|7023|1034|14.7%|3.3%|
[openbl_30d](#openbl_30d)|2857|2857|837|29.2%|2.7%|
[bruteforceblocker](#bruteforceblocker)|1723|1723|730|42.3%|2.3%|
[blocklist_de_ftp](#blocklist_de_ftp)|712|712|712|100.0%|2.3%|
[et_compromised](#et_compromised)|1718|1718|700|40.7%|2.2%|
[firehol_anonymous](#firehol_anonymous)|18532|82552|615|0.7%|1.9%|
[firehol_proxies](#firehol_proxies)|11968|12206|601|4.9%|1.9%|
[nixspam](#nixspam)|23906|23906|590|2.4%|1.9%|
[shunlist](#shunlist)|1315|1315|463|35.2%|1.5%|
[ri_web_proxies](#ri_web_proxies)|7435|7435|422|5.6%|1.3%|
[openbl_7d](#openbl_7d)|708|708|407|57.4%|1.3%|
[firehol_level1](#firehol_level1)|5146|688981121|232|0.0%|0.7%|
[snort_ipfilter](#snort_ipfilter)|10136|10136|220|2.1%|0.7%|
[proxyrss](#proxyrss)|1602|1602|215|13.4%|0.6%|
[et_block](#et_block)|999|18343755|214|0.0%|0.6%|
[xroxy](#xroxy)|2147|2147|205|9.5%|0.6%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|204|0.0%|0.6%|
[proxz](#proxz)|1173|1173|174|14.8%|0.5%|
[blocklist_de_strongips](#blocklist_de_strongips)|174|174|174|100.0%|0.5%|
[openbl_1d](#openbl_1d)|161|161|130|80.7%|0.4%|
[php_dictionary](#php_dictionary)|666|666|102|15.3%|0.3%|
[php_commenters](#php_commenters)|403|403|99|24.5%|0.3%|
[php_spammers](#php_spammers)|661|661|96|14.5%|0.3%|
[dshield](#dshield)|20|5120|91|1.7%|0.2%|
[ri_connect_proxies](#ri_connect_proxies)|2695|2695|73|2.7%|0.2%|
[blocklist_de_sip](#blocklist_de_sip)|81|81|62|76.5%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|60|0.0%|0.1%|
[php_harvesters](#php_harvesters)|378|378|38|10.0%|0.1%|
[ciarmy](#ciarmy)|409|409|37|9.0%|0.1%|
[voipbl](#voipbl)|10522|10934|28|0.2%|0.0%|
[bm_tor](#bm_tor)|6425|6425|13|0.2%|0.0%|
[dm_tor](#dm_tor)|6405|6405|12|0.1%|0.0%|
[et_tor](#et_tor)|6340|6340|11|0.1%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|8|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|8|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|6|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|3|0.4%|0.0%|
[zeus_badips](#zeus_badips)|203|203|1|0.4%|0.0%|
[zeus](#zeus)|231|231|1|0.4%|0.0%|
[sslbl](#sslbl)|376|376|1|0.2%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|1|0.0%|0.0%|

## blocklist_de_apache

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service Apache, Apache-DDOS, RFI-Attacks.

Source is downloaded from [this link](http://lists.blocklist.de/lists/apache.txt).

The last time downloaded was found to be dated: Wed Jun 10 02:42:08 UTC 2015.

The ipset `blocklist_de_apache` has **15619** entries, **15619** unique IPs.

The following table shows the overlaps of `blocklist_de_apache` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_apache`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_apache`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_apache`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|24709|36348|15619|42.9%|100.0%|
[blocklist_de](#blocklist_de)|30769|30769|15619|50.7%|100.0%|
[blocklist_de_mail](#blocklist_de_mail)|19075|19075|11059|57.9%|70.8%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4256|4256|4256|100.0%|27.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|2386|0.0%|15.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|1337|0.0%|8.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|1107|0.0%|7.0%|
[firehol_level3](#firehol_level3)|109859|9627471|302|0.0%|1.9%|
[stopforumspam_30d](#stopforumspam_30d)|93938|93938|219|0.2%|1.4%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|132|0.4%|0.8%|
[alienvault_reputation](#alienvault_reputation)|180612|180612|130|0.0%|0.8%|
[stopforumspam_1d](#stopforumspam_1d)|6943|6943|69|0.9%|0.4%|
[blocklist_de_strongips](#blocklist_de_strongips)|174|174|34|19.5%|0.2%|
[php_commenters](#php_commenters)|403|403|32|7.9%|0.2%|
[ciarmy](#ciarmy)|409|409|32|7.8%|0.2%|
[shunlist](#shunlist)|1315|1315|31|2.3%|0.1%|
[nixspam](#nixspam)|23906|23906|30|0.1%|0.1%|
[snort_ipfilter](#snort_ipfilter)|10136|10136|25|0.2%|0.1%|
[blocklist_de_bots](#blocklist_de_bots)|3122|3122|22|0.7%|0.1%|
[firehol_anonymous](#firehol_anonymous)|18532|82552|17|0.0%|0.1%|
[firehol_level1](#firehol_level1)|5146|688981121|14|0.0%|0.0%|
[bm_tor](#bm_tor)|6425|6425|11|0.1%|0.0%|
[dm_tor](#dm_tor)|6405|6405|10|0.1%|0.0%|
[et_tor](#et_tor)|6340|6340|9|0.1%|0.0%|
[et_block](#et_block)|999|18343755|8|0.0%|0.0%|
[dshield](#dshield)|20|5120|8|0.1%|0.0%|
[php_spammers](#php_spammers)|661|661|7|1.0%|0.0%|
[firehol_proxies](#firehol_proxies)|11968|12206|7|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7435|7435|6|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|5|0.0%|0.0%|
[openbl_60d](#openbl_60d)|7023|7023|5|0.0%|0.0%|
[openbl_30d](#openbl_30d)|2857|2857|5|0.1%|0.0%|
[php_dictionary](#php_dictionary)|666|666|4|0.6%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|4|0.0%|0.0%|
[voipbl](#voipbl)|10522|10934|2|0.0%|0.0%|
[php_harvesters](#php_harvesters)|378|378|2|0.5%|0.0%|
[openbl_7d](#openbl_7d)|708|708|2|0.2%|0.0%|
[openbl_1d](#openbl_1d)|161|161|2|1.2%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|1|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|1|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2334|2334|1|0.0%|0.0%|

## blocklist_de_bots

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the RFI-Attacks, REG-Bots, IRC-Bots or BadBots (BadBots = he has posted a Spam-Comment on a open Forum or Wiki).

Source is downloaded from [this link](http://lists.blocklist.de/lists/bots.txt).

The last time downloaded was found to be dated: Wed Jun 10 02:42:10 UTC 2015.

The ipset `blocklist_de_bots` has **3122** entries, **3122** unique IPs.

The following table shows the overlaps of `blocklist_de_bots` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_bots`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_bots`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_bots`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|24709|36348|3122|8.5%|100.0%|
[blocklist_de](#blocklist_de)|30769|30769|3122|10.1%|100.0%|
[firehol_level3](#firehol_level3)|109859|9627471|2306|0.0%|73.8%|
[stopforumspam_30d](#stopforumspam_30d)|93938|93938|2269|2.4%|72.6%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|2139|7.2%|68.5%|
[stopforumspam_1d](#stopforumspam_1d)|6943|6943|1320|19.0%|42.2%|
[firehol_anonymous](#firehol_anonymous)|18532|82552|498|0.6%|15.9%|
[firehol_proxies](#firehol_proxies)|11968|12206|496|4.0%|15.8%|
[ri_web_proxies](#ri_web_proxies)|7435|7435|354|4.7%|11.3%|
[proxyrss](#proxyrss)|1602|1602|214|13.3%|6.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|191|0.0%|6.1%|
[xroxy](#xroxy)|2147|2147|151|7.0%|4.8%|
[proxz](#proxz)|1173|1173|144|12.2%|4.6%|
[blocklist_de_strongips](#blocklist_de_strongips)|174|174|127|72.9%|4.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|100|0.0%|3.2%|
[php_commenters](#php_commenters)|403|403|79|19.6%|2.5%|
[ri_connect_proxies](#ri_connect_proxies)|2695|2695|69|2.5%|2.2%|
[firehol_level1](#firehol_level1)|5146|688981121|61|0.0%|1.9%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|58|0.0%|1.8%|
[et_block](#et_block)|999|18343755|58|0.0%|1.8%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|52|0.0%|1.6%|
[nixspam](#nixspam)|23906|23906|32|0.1%|1.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|31|0.0%|0.9%|
[php_harvesters](#php_harvesters)|378|378|27|7.1%|0.8%|
[blocklist_de_mail](#blocklist_de_mail)|19075|19075|22|0.1%|0.7%|
[blocklist_de_apache](#blocklist_de_apache)|15619|15619|22|0.1%|0.7%|
[snort_ipfilter](#snort_ipfilter)|10136|10136|20|0.1%|0.6%|
[php_spammers](#php_spammers)|661|661|19|2.8%|0.6%|
[php_dictionary](#php_dictionary)|666|666|19|2.8%|0.6%|
[alienvault_reputation](#alienvault_reputation)|180612|180612|19|0.0%|0.6%|
[openbl_60d](#openbl_60d)|7023|7023|5|0.0%|0.1%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|4|0.0%|0.1%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|2|0.3%|0.0%|
[openbl_30d](#openbl_30d)|2857|2857|1|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|1|0.0%|0.0%|
[et_tor](#et_tor)|6340|6340|1|0.0%|0.0%|
[et_compromised](#et_compromised)|1718|1718|1|0.0%|0.0%|
[dm_tor](#dm_tor)|6405|6405|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1723|1723|1|0.0%|0.0%|
[bm_tor](#bm_tor)|6425|6425|1|0.0%|0.0%|

## blocklist_de_bruteforce

[Blocklist.de](https://www.blocklist.de/) All IPs which attacks Joomlas, Wordpress and other Web-Logins with Brute-Force Logins.

Source is downloaded from [this link](http://lists.blocklist.de/lists/bruteforcelogin.txt).

The last time downloaded was found to be dated: Wed Jun 10 02:42:12 UTC 2015.

The ipset `blocklist_de_bruteforce` has **4256** entries, **4256** unique IPs.

The following table shows the overlaps of `blocklist_de_bruteforce` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_bruteforce`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_bruteforce`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_bruteforce`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|24709|36348|4256|11.7%|100.0%|
[blocklist_de_apache](#blocklist_de_apache)|15619|15619|4256|27.2%|100.0%|
[blocklist_de](#blocklist_de)|30769|30769|4256|13.8%|100.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|294|0.0%|6.9%|
[firehol_level3](#firehol_level3)|109859|9627471|92|0.0%|2.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|71|0.0%|1.6%|
[stopforumspam_30d](#stopforumspam_30d)|93938|93938|70|0.0%|1.6%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|55|0.1%|1.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|45|0.0%|1.0%|
[stopforumspam_1d](#stopforumspam_1d)|6943|6943|36|0.5%|0.8%|
[nixspam](#nixspam)|23906|23906|30|0.1%|0.7%|
[snort_ipfilter](#snort_ipfilter)|10136|10136|21|0.2%|0.4%|
[alienvault_reputation](#alienvault_reputation)|180612|180612|21|0.0%|0.4%|
[firehol_anonymous](#firehol_anonymous)|18532|82552|15|0.0%|0.3%|
[php_commenters](#php_commenters)|403|403|11|2.7%|0.2%|
[bm_tor](#bm_tor)|6425|6425|9|0.1%|0.2%|
[et_tor](#et_tor)|6340|6340|8|0.1%|0.1%|
[dm_tor](#dm_tor)|6405|6405|8|0.1%|0.1%|
[blocklist_de_strongips](#blocklist_de_strongips)|174|174|8|4.5%|0.1%|
[php_spammers](#php_spammers)|661|661|7|1.0%|0.1%|
[ri_web_proxies](#ri_web_proxies)|7435|7435|6|0.0%|0.1%|
[firehol_proxies](#firehol_proxies)|11968|12206|6|0.0%|0.1%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|5|0.0%|0.1%|
[firehol_level1](#firehol_level1)|5146|688981121|5|0.0%|0.1%|
[et_block](#et_block)|999|18343755|5|0.0%|0.1%|
[php_dictionary](#php_dictionary)|666|666|4|0.6%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|3|0.0%|0.0%|
[voipbl](#voipbl)|10522|10934|1|0.0%|0.0%|
[shunlist](#shunlist)|1315|1315|1|0.0%|0.0%|
[php_harvesters](#php_harvesters)|378|378|1|0.2%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|1|0.0%|0.0%|

## blocklist_de_ftp

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours for attacks on the Service FTP.

Source is downloaded from [this link](http://lists.blocklist.de/lists/ftp.txt).

The last time downloaded was found to be dated: Wed Jun 10 02:42:09 UTC 2015.

The ipset `blocklist_de_ftp` has **712** entries, **712** unique IPs.

The following table shows the overlaps of `blocklist_de_ftp` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_ftp`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_ftp`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_ftp`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|24709|36348|712|1.9%|100.0%|
[blocklist_de](#blocklist_de)|30769|30769|712|2.3%|100.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|97|0.0%|13.6%|
[firehol_level3](#firehol_level3)|109859|9627471|18|0.0%|2.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|13|0.0%|1.8%|
[stopforumspam_30d](#stopforumspam_30d)|93938|93938|12|0.0%|1.6%|
[alienvault_reputation](#alienvault_reputation)|180612|180612|11|0.0%|1.5%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|8|0.0%|1.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|7|0.0%|0.9%|
[stopforumspam_1d](#stopforumspam_1d)|6943|6943|4|0.0%|0.5%|
[php_harvesters](#php_harvesters)|378|378|3|0.7%|0.4%|
[nixspam](#nixspam)|23906|23906|3|0.0%|0.4%|
[ciarmy](#ciarmy)|409|409|2|0.4%|0.2%|
[blocklist_de_strongips](#blocklist_de_strongips)|174|174|2|1.1%|0.2%|
[openbl_7d](#openbl_7d)|708|708|1|0.1%|0.1%|
[openbl_60d](#openbl_60d)|7023|7023|1|0.0%|0.1%|
[openbl_30d](#openbl_30d)|2857|2857|1|0.0%|0.1%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|1|0.0%|0.1%|
[firehol_anonymous](#firehol_anonymous)|18532|82552|1|0.0%|0.1%|

## blocklist_de_imap

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours for attacks on the Service imap, sasl, pop3, etc.

Source is downloaded from [this link](http://lists.blocklist.de/lists/imap.txt).

The last time downloaded was found to be dated: Wed Jun 10 02:42:09 UTC 2015.

The ipset `blocklist_de_imap` has **2334** entries, **2334** unique IPs.

The following table shows the overlaps of `blocklist_de_imap` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_imap`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_imap`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_imap`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|24709|36348|2334|6.4%|100.0%|
[blocklist_de_mail](#blocklist_de_mail)|19075|19075|2334|12.2%|100.0%|
[blocklist_de](#blocklist_de)|30769|30769|2334|7.5%|100.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|294|0.0%|12.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|51|0.0%|2.1%|
[firehol_level3](#firehol_level3)|109859|9627471|44|0.0%|1.8%|
[alienvault_reputation](#alienvault_reputation)|180612|180612|42|0.0%|1.7%|
[openbl_60d](#openbl_60d)|7023|7023|30|0.4%|1.2%|
[openbl_30d](#openbl_30d)|2857|2857|25|0.8%|1.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|23|0.0%|0.9%|
[nixspam](#nixspam)|23906|23906|15|0.0%|0.6%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|12|0.0%|0.5%|
[firehol_level1](#firehol_level1)|5146|688981121|12|0.0%|0.5%|
[et_block](#et_block)|999|18343755|12|0.0%|0.5%|
[snort_ipfilter](#snort_ipfilter)|10136|10136|9|0.0%|0.3%|
[stopforumspam_30d](#stopforumspam_30d)|93938|93938|8|0.0%|0.3%|
[openbl_7d](#openbl_7d)|708|708|7|0.9%|0.2%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|3|0.0%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|0.1%|
[et_compromised](#et_compromised)|1718|1718|3|0.1%|0.1%|
[bruteforceblocker](#bruteforceblocker)|1723|1723|3|0.1%|0.1%|
[shunlist](#shunlist)|1315|1315|2|0.1%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2695|2695|2|0.0%|0.0%|
[openbl_1d](#openbl_1d)|161|161|2|1.2%|0.0%|
[firehol_proxies](#firehol_proxies)|11968|12206|2|0.0%|0.0%|
[firehol_anonymous](#firehol_anonymous)|18532|82552|2|0.0%|0.0%|
[xroxy](#xroxy)|2147|2147|1|0.0%|0.0%|
[php_harvesters](#php_harvesters)|378|378|1|0.2%|0.0%|
[php_commenters](#php_commenters)|403|403|1|0.2%|0.0%|
[ciarmy](#ciarmy)|409|409|1|0.2%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|15619|15619|1|0.0%|0.0%|

## blocklist_de_mail

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service Mail, Postfix.

Source is downloaded from [this link](http://lists.blocklist.de/lists/mail.txt).

The last time downloaded was found to be dated: Wed Jun 10 02:42:07 UTC 2015.

The ipset `blocklist_de_mail` has **19075** entries, **19075** unique IPs.

The following table shows the overlaps of `blocklist_de_mail` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_mail`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_mail`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_mail`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|24709|36348|19075|52.4%|100.0%|
[blocklist_de](#blocklist_de)|30769|30769|19075|61.9%|100.0%|
[blocklist_de_apache](#blocklist_de_apache)|15619|15619|11059|70.8%|57.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|2803|0.0%|14.6%|
[blocklist_de_imap](#blocklist_de_imap)|2334|2334|2334|100.0%|12.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|1397|0.0%|7.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|1266|0.0%|6.6%|
[nixspam](#nixspam)|23906|23906|519|2.1%|2.7%|
[firehol_level3](#firehol_level3)|109859|9627471|437|0.0%|2.2%|
[stopforumspam_30d](#stopforumspam_30d)|93938|93938|262|0.2%|1.3%|
[snort_ipfilter](#snort_ipfilter)|10136|10136|177|1.7%|0.9%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|144|0.4%|0.7%|
[firehol_anonymous](#firehol_anonymous)|18532|82552|100|0.1%|0.5%|
[firehol_proxies](#firehol_proxies)|11968|12206|99|0.8%|0.5%|
[php_dictionary](#php_dictionary)|666|666|79|11.8%|0.4%|
[php_spammers](#php_spammers)|661|661|69|10.4%|0.3%|
[alienvault_reputation](#alienvault_reputation)|180612|180612|67|0.0%|0.3%|
[ri_web_proxies](#ri_web_proxies)|7435|7435|62|0.8%|0.3%|
[xroxy](#xroxy)|2147|2147|54|2.5%|0.2%|
[stopforumspam_1d](#stopforumspam_1d)|6943|6943|48|0.6%|0.2%|
[openbl_60d](#openbl_60d)|7023|7023|38|0.5%|0.1%|
[openbl_30d](#openbl_30d)|2857|2857|32|1.1%|0.1%|
[proxz](#proxz)|1173|1173|30|2.5%|0.1%|
[php_commenters](#php_commenters)|403|403|25|6.2%|0.1%|
[firehol_level1](#firehol_level1)|5146|688981121|24|0.0%|0.1%|
[et_block](#et_block)|999|18343755|23|0.0%|0.1%|
[blocklist_de_strongips](#blocklist_de_strongips)|174|174|23|13.2%|0.1%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|22|0.0%|0.1%|
[blocklist_de_bots](#blocklist_de_bots)|3122|3122|22|0.7%|0.1%|
[php_harvesters](#php_harvesters)|378|378|7|1.8%|0.0%|
[openbl_7d](#openbl_7d)|708|708|7|0.9%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2695|2695|4|0.1%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|4|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|4|0.0%|0.0%|
[shunlist](#shunlist)|1315|1315|3|0.2%|0.0%|
[et_compromised](#et_compromised)|1718|1718|3|0.1%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1723|1723|3|0.1%|0.0%|
[openbl_1d](#openbl_1d)|161|161|2|1.2%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|2|0.0%|0.0%|
[dm_tor](#dm_tor)|6405|6405|2|0.0%|0.0%|
[bm_tor](#bm_tor)|6425|6425|2|0.0%|0.0%|
[zeus_badips](#zeus_badips)|203|203|1|0.4%|0.0%|
[zeus](#zeus)|231|231|1|0.4%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|1|0.0%|0.0%|
[proxyrss](#proxyrss)|1602|1602|1|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|1|0.1%|0.0%|
[et_tor](#et_tor)|6340|6340|1|0.0%|0.0%|
[ciarmy](#ciarmy)|409|409|1|0.2%|0.0%|

## blocklist_de_sip

[Blocklist.de](https://www.blocklist.de/) All IP addresses that tried to login in a SIP, VOIP or Asterisk Server and are included in the IPs list from [infiltrated.net](www.infiltrated.net)

Source is downloaded from [this link](http://lists.blocklist.de/lists/sip.txt).

The last time downloaded was found to be dated: Wed Jun 10 02:42:09 UTC 2015.

The ipset `blocklist_de_sip` has **81** entries, **81** unique IPs.

The following table shows the overlaps of `blocklist_de_sip` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_sip`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_sip`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_sip`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|24709|36348|62|0.1%|76.5%|
[blocklist_de](#blocklist_de)|30769|30769|62|0.2%|76.5%|
[voipbl](#voipbl)|10522|10934|24|0.2%|29.6%|
[alienvault_reputation](#alienvault_reputation)|180612|180612|21|0.0%|25.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|14|0.0%|17.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|6|0.0%|7.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|6|0.0%|7.4%|
[firehol_level3](#firehol_level3)|109859|9627471|4|0.0%|4.9%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|2|0.0%|2.4%|
[shunlist](#shunlist)|1315|1315|2|0.1%|2.4%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|2|0.0%|2.4%|
[firehol_level1](#firehol_level1)|5146|688981121|2|0.0%|2.4%|
[et_block](#et_block)|999|18343755|2|0.0%|2.4%|
[et_botcc](#et_botcc)|509|509|1|0.1%|1.2%|

## blocklist_de_ssh

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service SSH.

Source is downloaded from [this link](http://lists.blocklist.de/lists/ssh.txt).

The last time downloaded was found to be dated: Wed Jun 10 02:42:05 UTC 2015.

The ipset `blocklist_de_ssh` has **3255** entries, **3255** unique IPs.

The following table shows the overlaps of `blocklist_de_ssh` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_ssh`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_ssh`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_ssh`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|24709|36348|3255|8.9%|100.0%|
[blocklist_de](#blocklist_de)|30769|30769|3255|10.5%|100.0%|
[alienvault_reputation](#alienvault_reputation)|180612|180612|1166|0.6%|35.8%|
[firehol_level3](#firehol_level3)|109859|9627471|1070|0.0%|32.8%|
[openbl_60d](#openbl_60d)|7023|7023|985|14.0%|30.2%|
[openbl_30d](#openbl_30d)|2857|2857|798|27.9%|24.5%|
[bruteforceblocker](#bruteforceblocker)|1723|1723|726|42.1%|22.3%|
[et_compromised](#et_compromised)|1718|1718|696|40.5%|21.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|463|0.0%|14.2%|
[shunlist](#shunlist)|1315|1315|427|32.4%|13.1%|
[openbl_7d](#openbl_7d)|708|708|397|56.0%|12.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|136|0.0%|4.1%|
[firehol_level1](#firehol_level1)|5146|688981121|131|0.0%|4.0%|
[openbl_1d](#openbl_1d)|161|161|126|78.2%|3.8%|
[et_block](#et_block)|999|18343755|123|0.0%|3.7%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|117|0.0%|3.5%|
[dshield](#dshield)|20|5120|83|1.6%|2.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|57|0.0%|1.7%|
[blocklist_de_strongips](#blocklist_de_strongips)|174|174|30|17.2%|0.9%|
[stopforumspam_30d](#stopforumspam_30d)|93938|93938|19|0.0%|0.5%|
[nixspam](#nixspam)|23906|23906|6|0.0%|0.1%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|5|0.0%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|4|0.0%|0.1%|
[voipbl](#voipbl)|10522|10934|2|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|2|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|10136|10136|2|0.0%|0.0%|
[ciarmy](#ciarmy)|409|409|2|0.4%|0.0%|
[sslbl](#sslbl)|376|376|1|0.2%|0.0%|
[php_spammers](#php_spammers)|661|661|1|0.1%|0.0%|
[php_commenters](#php_commenters)|403|403|1|0.2%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|1|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|1|0.0%|0.0%|
[firehol_anonymous](#firehol_anonymous)|18532|82552|1|0.0%|0.0%|
[et_tor](#et_tor)|6340|6340|1|0.0%|0.0%|
[dm_tor](#dm_tor)|6405|6405|1|0.0%|0.0%|
[bm_tor](#bm_tor)|6425|6425|1|0.0%|0.0%|

## blocklist_de_strongips

[Blocklist.de](https://www.blocklist.de/) All IPs which are older then 2 month and have more then 5.000 attacks.

Source is downloaded from [this link](http://lists.blocklist.de/lists/strongips.txt).

The last time downloaded was found to be dated: Wed Jun 10 02:42:11 UTC 2015.

The ipset `blocklist_de_strongips` has **174** entries, **174** unique IPs.

The following table shows the overlaps of `blocklist_de_strongips` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_strongips`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_strongips`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_strongips`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|24709|36348|174|0.4%|100.0%|
[blocklist_de](#blocklist_de)|30769|30769|174|0.5%|100.0%|
[firehol_level3](#firehol_level3)|109859|9627471|155|0.0%|89.0%|
[stopforumspam_30d](#stopforumspam_30d)|93938|93938|129|0.1%|74.1%|
[blocklist_de_bots](#blocklist_de_bots)|3122|3122|127|4.0%|72.9%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|116|0.3%|66.6%|
[stopforumspam_1d](#stopforumspam_1d)|6943|6943|107|1.5%|61.4%|
[php_commenters](#php_commenters)|403|403|45|11.1%|25.8%|
[alienvault_reputation](#alienvault_reputation)|180612|180612|35|0.0%|20.1%|
[blocklist_de_apache](#blocklist_de_apache)|15619|15619|34|0.2%|19.5%|
[blocklist_de_ssh](#blocklist_de_ssh)|3255|3255|30|0.9%|17.2%|
[openbl_60d](#openbl_60d)|7023|7023|25|0.3%|14.3%|
[openbl_30d](#openbl_30d)|2857|2857|24|0.8%|13.7%|
[openbl_7d](#openbl_7d)|708|708|23|3.2%|13.2%|
[blocklist_de_mail](#blocklist_de_mail)|19075|19075|23|0.1%|13.2%|
[shunlist](#shunlist)|1315|1315|20|1.5%|11.4%|
[openbl_1d](#openbl_1d)|161|161|19|11.8%|10.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|16|0.0%|9.1%|
[firehol_level1](#firehol_level1)|5146|688981121|10|0.0%|5.7%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4256|4256|8|0.1%|4.5%|
[php_spammers](#php_spammers)|661|661|7|1.0%|4.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|7|0.0%|4.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|6|0.0%|3.4%|
[firehol_proxies](#firehol_proxies)|11968|12206|6|0.0%|3.4%|
[firehol_anonymous](#firehol_anonymous)|18532|82552|6|0.0%|3.4%|
[et_block](#et_block)|999|18343755|6|0.0%|3.4%|
[xroxy](#xroxy)|2147|2147|5|0.2%|2.8%|
[ri_web_proxies](#ri_web_proxies)|7435|7435|5|0.0%|2.8%|
[proxz](#proxz)|1173|1173|5|0.4%|2.8%|
[proxyrss](#proxyrss)|1602|1602|5|0.3%|2.8%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|4|0.0%|2.2%|
[php_dictionary](#php_dictionary)|666|666|4|0.6%|2.2%|
[nixspam](#nixspam)|23906|23906|3|0.0%|1.7%|
[snort_ipfilter](#snort_ipfilter)|10136|10136|2|0.0%|1.1%|
[php_harvesters](#php_harvesters)|378|378|2|0.5%|1.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2|0.0%|1.1%|
[blocklist_de_ftp](#blocklist_de_ftp)|712|712|2|0.2%|1.1%|
[dshield](#dshield)|20|5120|1|0.0%|0.5%|

## bm_tor

[torstatus.blutmagie.de](https://torstatus.blutmagie.de) list of all TOR network servers

Source is downloaded from [this link](https://torstatus.blutmagie.de/ip_list_all.php/Tor_ip_list_ALL.csv).

The last time downloaded was found to be dated: Wed Jun 10 02:45:03 UTC 2015.

The ipset `bm_tor` has **6425** entries, **6425** unique IPs.

The following table shows the overlaps of `bm_tor` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `bm_tor`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `bm_tor`.
- ` this % ` is the percentage **of this ipset (`bm_tor`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_anonymous](#firehol_anonymous)|18532|82552|6425|7.7%|100.0%|
[dm_tor](#dm_tor)|6405|6405|6219|97.0%|96.7%|
[et_tor](#et_tor)|6340|6340|5877|92.6%|91.4%|
[firehol_level3](#firehol_level3)|109859|9627471|1072|0.0%|16.6%|
[snort_ipfilter](#snort_ipfilter)|10136|10136|1032|10.1%|16.0%|
[stopforumspam_30d](#stopforumspam_30d)|93938|93938|637|0.6%|9.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|623|0.0%|9.6%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|529|1.8%|8.2%|
[firehol_level2](#firehol_level2)|24709|36348|347|0.9%|5.4%|
[stopforumspam_1d](#stopforumspam_1d)|6943|6943|344|4.9%|5.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|180|0.0%|2.8%|
[firehol_proxies](#firehol_proxies)|11968|12206|167|1.3%|2.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|165|0.0%|2.5%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|163|43.8%|2.5%|
[php_commenters](#php_commenters)|403|403|48|11.9%|0.7%|
[alienvault_reputation](#alienvault_reputation)|180612|180612|39|0.0%|0.6%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|22|0.0%|0.3%|
[openbl_60d](#openbl_60d)|7023|7023|20|0.2%|0.3%|
[blocklist_de](#blocklist_de)|30769|30769|13|0.0%|0.2%|
[blocklist_de_apache](#blocklist_de_apache)|15619|15619|11|0.0%|0.1%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4256|4256|9|0.2%|0.1%|
[php_harvesters](#php_harvesters)|378|378|7|1.8%|0.1%|
[et_block](#et_block)|999|18343755|7|0.0%|0.1%|
[ri_web_proxies](#ri_web_proxies)|7435|7435|4|0.0%|0.0%|
[php_spammers](#php_spammers)|661|661|4|0.6%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|4|0.0%|0.0%|
[voipbl](#voipbl)|10522|10934|3|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|3|0.0%|0.0%|
[php_dictionary](#php_dictionary)|666|666|3|0.4%|0.0%|
[nixspam](#nixspam)|23906|23906|3|0.0%|0.0%|
[firehol_level1](#firehol_level1)|5146|688981121|3|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|19075|19075|2|0.0%|0.0%|
[xroxy](#xroxy)|2147|2147|1|0.0%|0.0%|
[shunlist](#shunlist)|1315|1315|1|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3255|3255|1|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3122|3122|1|0.0%|0.0%|

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
[fullbogons](#fullbogons)|3778|670299624|592708608|88.4%|100.0%|
[firehol_level1](#firehol_level1)|5146|688981121|592708608|86.0%|100.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|4194304|3.0%|0.7%|
[voipbl](#voipbl)|10522|10934|319|2.9%|0.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|5|0.0%|0.0%|
[firehol_level3](#firehol_level3)|109859|9627471|5|0.0%|0.0%|
[php_harvesters](#php_harvesters)|378|378|1|0.2%|0.0%|
[php_commenters](#php_commenters)|403|403|1|0.2%|0.0%|
[nixspam](#nixspam)|23906|23906|1|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|172|172|1|0.5%|0.0%|
[ciarmy](#ciarmy)|409|409|1|0.2%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1723|1723|1|0.0%|0.0%|

## bruteforceblocker

[danger.rulez.sk](http://danger.rulez.sk/) IPs detected by [bruteforceblocker](http://danger.rulez.sk/index.php/bruteforceblocker/) (fail2ban alternative for SSH on OpenBSD). This is an automatically generated list from users reporting failed authentication attempts. An IP seems to be included if 3 or more users report it. Its retention pocily seems 30 days.

Source is downloaded from [this link](http://danger.rulez.sk/projects/bruteforceblocker/blist.php).

The last time downloaded was found to be dated: Wed Jun 10 00:36:37 UTC 2015.

The ipset `bruteforceblocker` has **1723** entries, **1723** unique IPs.

The following table shows the overlaps of `bruteforceblocker` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `bruteforceblocker`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `bruteforceblocker`.
- ` this % ` is the percentage **of this ipset (`bruteforceblocker`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level3](#firehol_level3)|109859|9627471|1723|0.0%|100.0%|
[et_compromised](#et_compromised)|1718|1718|1679|97.7%|97.4%|
[alienvault_reputation](#alienvault_reputation)|180612|180612|1109|0.6%|64.3%|
[openbl_60d](#openbl_60d)|7023|7023|1006|14.3%|58.3%|
[openbl_30d](#openbl_30d)|2857|2857|945|33.0%|54.8%|
[firehol_level2](#firehol_level2)|24709|36348|732|2.0%|42.4%|
[blocklist_de](#blocklist_de)|30769|30769|730|2.3%|42.3%|
[blocklist_de_ssh](#blocklist_de_ssh)|3255|3255|726|22.3%|42.1%|
[shunlist](#shunlist)|1315|1315|451|34.2%|26.1%|
[openbl_7d](#openbl_7d)|708|708|330|46.6%|19.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|152|0.0%|8.8%|
[firehol_level1](#firehol_level1)|5146|688981121|108|0.0%|6.2%|
[et_block](#et_block)|999|18343755|103|0.0%|5.9%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|101|0.0%|5.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|84|0.0%|4.8%|
[openbl_1d](#openbl_1d)|161|161|71|44.0%|4.1%|
[dshield](#dshield)|20|5120|65|1.2%|3.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|52|0.0%|3.0%|
[stopforumspam_30d](#stopforumspam_30d)|93938|93938|13|0.0%|0.7%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|5|0.0%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|5|0.0%|0.2%|
[voipbl](#voipbl)|10522|10934|3|0.0%|0.1%|
[firehol_proxies](#firehol_proxies)|11968|12206|3|0.0%|0.1%|
[firehol_anonymous](#firehol_anonymous)|18532|82552|3|0.0%|0.1%|
[blocklist_de_mail](#blocklist_de_mail)|19075|19075|3|0.0%|0.1%|
[blocklist_de_imap](#blocklist_de_imap)|2334|2334|3|0.1%|0.1%|
[proxz](#proxz)|1173|1173|2|0.1%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|2|0.0%|0.1%|
[ciarmy](#ciarmy)|409|409|2|0.4%|0.1%|
[xroxy](#xroxy)|2147|2147|1|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6943|6943|1|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|10136|10136|1|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7435|7435|1|0.0%|0.0%|
[proxyrss](#proxyrss)|1602|1602|1|0.0%|0.0%|
[php_spammers](#php_spammers)|661|661|1|0.1%|0.0%|
[php_commenters](#php_commenters)|403|403|1|0.2%|0.0%|
[fullbogons](#fullbogons)|3778|670299624|1|0.0%|0.0%|
[bogons](#bogons)|13|592708608|1|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3122|3122|1|0.0%|0.0%|

## ciarmy

[CIArmy.com](http://ciarmy.com/) IPs with poor Rogue Packet score that have not yet been identified as malicious by the community

Source is downloaded from [this link](http://cinsscore.com/list/ci-badguys.txt).

The last time downloaded was found to be dated: Wed Jun 10 01:15:17 UTC 2015.

The ipset `ciarmy` has **409** entries, **409** unique IPs.

The following table shows the overlaps of `ciarmy` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ciarmy`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ciarmy`.
- ` this % ` is the percentage **of this ipset (`ciarmy`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level3](#firehol_level3)|109859|9627471|409|0.0%|100.0%|
[alienvault_reputation](#alienvault_reputation)|180612|180612|396|0.2%|96.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|92|0.0%|22.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|46|0.0%|11.2%|
[firehol_level2](#firehol_level2)|24709|36348|38|0.1%|9.2%|
[blocklist_de](#blocklist_de)|30769|30769|37|0.1%|9.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|36|0.0%|8.8%|
[blocklist_de_apache](#blocklist_de_apache)|15619|15619|32|0.2%|7.8%|
[shunlist](#shunlist)|1315|1315|24|1.8%|5.8%|
[firehol_level1](#firehol_level1)|5146|688981121|6|0.0%|1.4%|
[dshield](#dshield)|20|5120|5|0.0%|1.2%|
[et_block](#et_block)|999|18343755|4|0.0%|0.9%|
[stopforumspam_30d](#stopforumspam_30d)|93938|93938|2|0.0%|0.4%|
[openbl_7d](#openbl_7d)|708|708|2|0.2%|0.4%|
[openbl_60d](#openbl_60d)|7023|7023|2|0.0%|0.4%|
[openbl_30d](#openbl_30d)|2857|2857|2|0.0%|0.4%|
[bruteforceblocker](#bruteforceblocker)|1723|1723|2|0.1%|0.4%|
[blocklist_de_ssh](#blocklist_de_ssh)|3255|3255|2|0.0%|0.4%|
[blocklist_de_ftp](#blocklist_de_ftp)|712|712|2|0.2%|0.4%|
[voipbl](#voipbl)|10522|10934|1|0.0%|0.2%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|1|0.0%|0.2%|
[openbl_1d](#openbl_1d)|161|161|1|0.6%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.2%|
[fullbogons](#fullbogons)|3778|670299624|1|0.0%|0.2%|
[et_compromised](#et_compromised)|1718|1718|1|0.0%|0.2%|
[bogons](#bogons)|13|592708608|1|0.0%|0.2%|
[blocklist_de_mail](#blocklist_de_mail)|19075|19075|1|0.0%|0.2%|
[blocklist_de_imap](#blocklist_de_imap)|2334|2334|1|0.0%|0.2%|

## cleanmx_viruses

[Clean-MX.de](http://support.clean-mx.de/clean-mx/viruses.php) IPs with viruses

Source is downloaded from [this link](http://support.clean-mx.de/clean-mx/xmlviruses.php?sort=id%20desc&response=alive).

The last time downloaded was found to be dated: Tue Jun  9 20:45:39 UTC 2015.

The ipset `cleanmx_viruses` has **172** entries, **172** unique IPs.

The following table shows the overlaps of `cleanmx_viruses` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `cleanmx_viruses`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `cleanmx_viruses`.
- ` this % ` is the percentage **of this ipset (`cleanmx_viruses`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level3](#firehol_level3)|109859|9627471|172|0.0%|100.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|22|0.0%|12.7%|
[malc0de](#malc0de)|338|338|20|5.9%|11.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|4|0.0%|2.3%|
[alienvault_reputation](#alienvault_reputation)|180612|180612|4|0.0%|2.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|3|0.0%|1.7%|
[firehol_level1](#firehol_level1)|5146|688981121|2|0.0%|1.1%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|1|0.0%|0.5%|
[snort_ipfilter](#snort_ipfilter)|10136|10136|1|0.0%|0.5%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|1|0.0%|0.5%|
[fullbogons](#fullbogons)|3778|670299624|1|0.0%|0.5%|
[bogons](#bogons)|13|592708608|1|0.0%|0.5%|

## dm_tor

[dan.me.uk](https://www.dan.me.uk) dynamic list of TOR exit points

Source is downloaded from [this link](https://www.dan.me.uk/torlist/).

The last time downloaded was found to be dated: Wed Jun 10 03:00:04 UTC 2015.

The ipset `dm_tor` has **6405** entries, **6405** unique IPs.

The following table shows the overlaps of `dm_tor` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `dm_tor`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `dm_tor`.
- ` this % ` is the percentage **of this ipset (`dm_tor`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_anonymous](#firehol_anonymous)|18532|82552|6405|7.7%|100.0%|
[bm_tor](#bm_tor)|6425|6425|6219|96.7%|97.0%|
[et_tor](#et_tor)|6340|6340|5796|91.4%|90.4%|
[firehol_level3](#firehol_level3)|109859|9627471|1071|0.0%|16.7%|
[snort_ipfilter](#snort_ipfilter)|10136|10136|1030|10.1%|16.0%|
[stopforumspam_30d](#stopforumspam_30d)|93938|93938|639|0.6%|9.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|626|0.0%|9.7%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|530|1.8%|8.2%|
[firehol_level2](#firehol_level2)|24709|36348|348|0.9%|5.4%|
[stopforumspam_1d](#stopforumspam_1d)|6943|6943|345|4.9%|5.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|181|0.0%|2.8%|
[firehol_proxies](#firehol_proxies)|11968|12206|167|1.3%|2.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|164|0.0%|2.5%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|163|43.8%|2.5%|
[php_commenters](#php_commenters)|403|403|48|11.9%|0.7%|
[alienvault_reputation](#alienvault_reputation)|180612|180612|39|0.0%|0.6%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|22|0.0%|0.3%|
[openbl_60d](#openbl_60d)|7023|7023|20|0.2%|0.3%|
[blocklist_de](#blocklist_de)|30769|30769|12|0.0%|0.1%|
[blocklist_de_apache](#blocklist_de_apache)|15619|15619|10|0.0%|0.1%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4256|4256|8|0.1%|0.1%|
[php_harvesters](#php_harvesters)|378|378|7|1.8%|0.1%|
[et_block](#et_block)|999|18343755|7|0.0%|0.1%|
[ri_web_proxies](#ri_web_proxies)|7435|7435|4|0.0%|0.0%|
[php_spammers](#php_spammers)|661|661|4|0.6%|0.0%|
[nixspam](#nixspam)|23906|23906|4|0.0%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|4|0.0%|0.0%|
[voipbl](#voipbl)|10522|10934|3|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|3|0.0%|0.0%|
[php_dictionary](#php_dictionary)|666|666|3|0.4%|0.0%|
[firehol_level1](#firehol_level1)|5146|688981121|3|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|19075|19075|2|0.0%|0.0%|
[xroxy](#xroxy)|2147|2147|1|0.0%|0.0%|
[shunlist](#shunlist)|1315|1315|1|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3255|3255|1|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3122|3122|1|0.0%|0.0%|

## dshield

[DShield.org](https://dshield.org/) top 20 attacking class C (/24) subnets over the last three days - **excellent list**

Source is downloaded from [this link](http://feeds.dshield.org/block.txt).

The last time downloaded was found to be dated: Tue Jun  9 23:57:48 UTC 2015.

The ipset `dshield` has **20** entries, **5120** unique IPs.

The following table shows the overlaps of `dshield` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `dshield`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `dshield`.
- ` this % ` is the percentage **of this ipset (`dshield`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level1](#firehol_level1)|5146|688981121|5120|0.0%|100.0%|
[alienvault_reputation](#alienvault_reputation)|180612|180612|2562|1.4%|50.0%|
[et_block](#et_block)|999|18343755|1280|0.0%|25.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|512|0.0%|10.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|256|0.0%|5.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|256|0.0%|5.0%|
[firehol_level3](#firehol_level3)|109859|9627471|125|0.0%|2.4%|
[openbl_60d](#openbl_60d)|7023|7023|120|1.7%|2.3%|
[openbl_30d](#openbl_30d)|2857|2857|103|3.6%|2.0%|
[shunlist](#shunlist)|1315|1315|98|7.4%|1.9%|
[firehol_level2](#firehol_level2)|24709|36348|91|0.2%|1.7%|
[blocklist_de](#blocklist_de)|30769|30769|91|0.2%|1.7%|
[blocklist_de_ssh](#blocklist_de_ssh)|3255|3255|83|2.5%|1.6%|
[et_compromised](#et_compromised)|1718|1718|65|3.7%|1.2%|
[bruteforceblocker](#bruteforceblocker)|1723|1723|65|3.7%|1.2%|
[openbl_7d](#openbl_7d)|708|708|18|2.5%|0.3%|
[openbl_1d](#openbl_1d)|161|161|9|5.5%|0.1%|
[blocklist_de_apache](#blocklist_de_apache)|15619|15619|8|0.0%|0.1%|
[ciarmy](#ciarmy)|409|409|5|1.2%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|93938|93938|3|0.0%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|1|0.0%|0.0%|
[malc0de](#malc0de)|338|338|1|0.2%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|1|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|174|174|1|0.5%|0.0%|

## et_block

[EmergingThreats.net](http://www.emergingthreats.net/) default blacklist (at the time of writing includes spamhaus DROP, dshield and abuse.ch trackers, which are available separately too - prefer to use the direct ipsets instead of this, they seem to lag a bit in updates)

Source is downloaded from [this link](http://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt).

The last time downloaded was found to be dated: Tue Jun  9 04:30:01 UTC 2015.

The ipset `et_block` has **999** entries, **18343755** unique IPs.

The following table shows the overlaps of `et_block` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `et_block`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `et_block`.
- ` this % ` is the percentage **of this ipset (`et_block`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level1](#firehol_level1)|5146|688981121|18339911|2.6%|99.9%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|18338560|99.9%|99.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|8532519|2.4%|46.5%|
[firehol_level3](#firehol_level3)|109859|9627471|6933346|72.0%|37.7%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|6932480|75.5%|37.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|2272798|0.2%|12.3%|
[fullbogons](#fullbogons)|3778|670299624|151552|0.0%|0.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|130922|0.0%|0.7%|
[alienvault_reputation](#alienvault_reputation)|180612|180612|6045|3.3%|0.0%|
[dshield](#dshield)|20|5120|1280|25.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1043|0.3%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|93938|93938|1029|1.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|517|0.1%|0.0%|
[snort_ipfilter](#snort_ipfilter)|10136|10136|299|2.9%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|297|1.0%|0.0%|
[firehol_level2](#firehol_level2)|24709|36348|286|0.7%|0.0%|
[openbl_60d](#openbl_60d)|7023|7023|247|3.5%|0.0%|
[zeus](#zeus)|231|231|228|98.7%|0.0%|
[blocklist_de](#blocklist_de)|30769|30769|214|0.6%|0.0%|
[zeus_badips](#zeus_badips)|203|203|203|100.0%|0.0%|
[nixspam](#nixspam)|23906|23906|157|0.6%|0.0%|
[openbl_30d](#openbl_30d)|2857|2857|129|4.5%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3255|3255|123|3.7%|0.0%|
[shunlist](#shunlist)|1315|1315|110|8.3%|0.0%|
[et_compromised](#et_compromised)|1718|1718|103|5.9%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1723|1723|103|5.9%|0.0%|
[feodo](#feodo)|104|104|102|98.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6943|6943|89|1.2%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3122|3122|58|1.8%|0.0%|
[openbl_7d](#openbl_7d)|708|708|52|7.3%|0.0%|
[sslbl](#sslbl)|376|376|38|10.1%|0.0%|
[php_commenters](#php_commenters)|403|403|30|7.4%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|29|2.2%|0.0%|
[openbl_1d](#openbl_1d)|161|161|26|16.1%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|19075|19075|23|0.1%|0.0%|
[voipbl](#voipbl)|10522|10934|18|0.1%|0.0%|
[palevo](#palevo)|13|13|13|100.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2334|2334|12|0.5%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|11|0.0%|0.0%|
[firehol_anonymous](#firehol_anonymous)|18532|82552|11|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|8|0.5%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|15619|15619|8|0.0%|0.0%|
[et_tor](#et_tor)|6340|6340|7|0.1%|0.0%|
[dm_tor](#dm_tor)|6405|6405|7|0.1%|0.0%|
[bm_tor](#bm_tor)|6425|6425|7|0.1%|0.0%|
[php_dictionary](#php_dictionary)|666|666|6|0.9%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|174|174|6|3.4%|0.0%|
[malc0de](#malc0de)|338|338|5|1.4%|0.0%|
[firehol_proxies](#firehol_proxies)|11968|12206|5|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4256|4256|5|0.1%|0.0%|
[php_spammers](#php_spammers)|661|661|4|0.6%|0.0%|
[ciarmy](#ciarmy)|409|409|4|0.9%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|2|0.5%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|2|0.3%|0.0%|
[et_botcc](#et_botcc)|509|509|2|0.3%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|81|81|2|2.4%|0.0%|
[xroxy](#xroxy)|2147|2147|1|0.0%|0.0%|
[php_harvesters](#php_harvesters)|378|378|1|0.2%|0.0%|

## et_botcc

[EmergingThreats.net Command and Control IPs](http://doc.emergingthreats.net/bin/view/Main/BotCC) These IPs are updates every 24 hours and should be considered VERY highly reliable indications that a host is communicating with a known and active Bot or Malware command and control server - (although they say this includes abuse.ch trackers, it does not - most probably it is the shadowserver.org C&C list)

Source is downloaded from [this link](http://rules.emergingthreats.net/fwrules/emerging-PIX-CC.rules).

The last time downloaded was found to be dated: Tue Jun  9 04:30:01 UTC 2015.

The ipset `et_botcc` has **509** entries, **509** unique IPs.

The following table shows the overlaps of `et_botcc` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `et_botcc`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `et_botcc`.
- ` this % ` is the percentage **of this ipset (`et_botcc`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|77|0.0%|15.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|39|0.0%|7.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|21|0.0%|4.1%|
[alienvault_reputation](#alienvault_reputation)|180612|180612|4|0.0%|0.7%|
[firehol_level3](#firehol_level3)|109859|9627471|3|0.0%|0.5%|
[et_block](#et_block)|999|18343755|2|0.0%|0.3%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|1|0.0%|0.1%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|1|0.0%|0.1%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|1|0.0%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.1%|
[firehol_level1](#firehol_level1)|5146|688981121|1|0.0%|0.1%|
[blocklist_de_sip](#blocklist_de_sip)|81|81|1|1.2%|0.1%|

## et_compromised

[EmergingThreats.net compromised hosts](http://doc.emergingthreats.net/bin/view/Main/CompromisedHost) - (this seems to be based on bruteforceblocker)

Source is downloaded from [this link](http://rules.emergingthreats.net/blockrules/compromised-ips.txt).

The last time downloaded was found to be dated: Tue Jun  9 04:30:08 UTC 2015.

The ipset `et_compromised` has **1718** entries, **1718** unique IPs.

The following table shows the overlaps of `et_compromised` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `et_compromised`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `et_compromised`.
- ` this % ` is the percentage **of this ipset (`et_compromised`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level3](#firehol_level3)|109859|9627471|1692|0.0%|98.4%|
[bruteforceblocker](#bruteforceblocker)|1723|1723|1679|97.4%|97.7%|
[alienvault_reputation](#alienvault_reputation)|180612|180612|1104|0.6%|64.2%|
[openbl_60d](#openbl_60d)|7023|7023|1002|14.2%|58.3%|
[openbl_30d](#openbl_30d)|2857|2857|938|32.8%|54.5%|
[firehol_level2](#firehol_level2)|24709|36348|702|1.9%|40.8%|
[blocklist_de](#blocklist_de)|30769|30769|700|2.2%|40.7%|
[blocklist_de_ssh](#blocklist_de_ssh)|3255|3255|696|21.3%|40.5%|
[shunlist](#shunlist)|1315|1315|447|33.9%|26.0%|
[openbl_7d](#openbl_7d)|708|708|322|45.4%|18.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|153|0.0%|8.9%|
[firehol_level1](#firehol_level1)|5146|688981121|107|0.0%|6.2%|
[et_block](#et_block)|999|18343755|103|0.0%|5.9%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|101|0.0%|5.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|89|0.0%|5.1%|
[openbl_1d](#openbl_1d)|161|161|67|41.6%|3.8%|
[dshield](#dshield)|20|5120|65|1.2%|3.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|52|0.0%|3.0%|
[stopforumspam_30d](#stopforumspam_30d)|93938|93938|13|0.0%|0.7%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|5|0.0%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|5|0.0%|0.2%|
[firehol_proxies](#firehol_proxies)|11968|12206|3|0.0%|0.1%|
[firehol_anonymous](#firehol_anonymous)|18532|82552|3|0.0%|0.1%|
[blocklist_de_mail](#blocklist_de_mail)|19075|19075|3|0.0%|0.1%|
[blocklist_de_imap](#blocklist_de_imap)|2334|2334|3|0.1%|0.1%|
[voipbl](#voipbl)|10522|10934|2|0.0%|0.1%|
[proxz](#proxz)|1173|1173|2|0.1%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|2|0.0%|0.1%|
[xroxy](#xroxy)|2147|2147|1|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6943|6943|1|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|10136|10136|1|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7435|7435|1|0.0%|0.0%|
[proxyrss](#proxyrss)|1602|1602|1|0.0%|0.0%|
[php_spammers](#php_spammers)|661|661|1|0.1%|0.0%|
[php_commenters](#php_commenters)|403|403|1|0.2%|0.0%|
[ciarmy](#ciarmy)|409|409|1|0.2%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3122|3122|1|0.0%|0.0%|

## et_tor

[EmergingThreats.net](http://www.emergingthreats.net/) [list](http://doc.emergingthreats.net/bin/view/Main/TorRules) of TOR network IPs

Source is downloaded from [this link](http://rules.emergingthreats.net/blockrules/emerging-tor.rules).

The last time downloaded was found to be dated: Tue Jun  9 04:30:09 UTC 2015.

The ipset `et_tor` has **6340** entries, **6340** unique IPs.

The following table shows the overlaps of `et_tor` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `et_tor`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `et_tor`.
- ` this % ` is the percentage **of this ipset (`et_tor`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_anonymous](#firehol_anonymous)|18532|82552|5925|7.1%|93.4%|
[bm_tor](#bm_tor)|6425|6425|5877|91.4%|92.6%|
[dm_tor](#dm_tor)|6405|6405|5796|90.4%|91.4%|
[firehol_level3](#firehol_level3)|109859|9627471|1101|0.0%|17.3%|
[snort_ipfilter](#snort_ipfilter)|10136|10136|1062|10.4%|16.7%|
[stopforumspam_30d](#stopforumspam_30d)|93938|93938|642|0.6%|10.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|614|0.0%|9.6%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|533|1.8%|8.4%|
[firehol_level2](#firehol_level2)|24709|36348|350|0.9%|5.5%|
[stopforumspam_1d](#stopforumspam_1d)|6943|6943|348|5.0%|5.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|183|0.0%|2.8%|
[firehol_proxies](#firehol_proxies)|11968|12206|166|1.3%|2.6%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|163|43.8%|2.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|163|0.0%|2.5%|
[php_commenters](#php_commenters)|403|403|48|11.9%|0.7%|
[alienvault_reputation](#alienvault_reputation)|180612|180612|39|0.0%|0.6%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|22|0.0%|0.3%|
[openbl_60d](#openbl_60d)|7023|7023|20|0.2%|0.3%|
[blocklist_de](#blocklist_de)|30769|30769|11|0.0%|0.1%|
[blocklist_de_apache](#blocklist_de_apache)|15619|15619|9|0.0%|0.1%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4256|4256|8|0.1%|0.1%|
[php_harvesters](#php_harvesters)|378|378|7|1.8%|0.1%|
[et_block](#et_block)|999|18343755|7|0.0%|0.1%|
[php_spammers](#php_spammers)|661|661|4|0.6%|0.0%|
[nixspam](#nixspam)|23906|23906|4|0.0%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|4|0.0%|0.0%|
[voipbl](#voipbl)|10522|10934|3|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|3|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7435|7435|3|0.0%|0.0%|
[php_dictionary](#php_dictionary)|666|666|3|0.4%|0.0%|
[firehol_level1](#firehol_level1)|5146|688981121|3|0.0%|0.0%|
[xroxy](#xroxy)|2147|2147|1|0.0%|0.0%|
[shunlist](#shunlist)|1315|1315|1|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3255|3255|1|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|19075|19075|1|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3122|3122|1|0.0%|0.0%|

## feodo

[Abuse.ch Feodo tracker](https://feodotracker.abuse.ch) trojan includes IPs which are being used by Feodo (also known as Cridex or Bugat) which commits ebanking fraud - **excellent list**

Source is downloaded from [this link](https://feodotracker.abuse.ch/blocklist/?download=ipblocklist).

The last time downloaded was found to be dated: Wed Jun 10 02:45:12 UTC 2015.

The ipset `feodo` has **104** entries, **104** unique IPs.

The following table shows the overlaps of `feodo` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `feodo`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `feodo`.
- ` this % ` is the percentage **of this ipset (`feodo`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level1](#firehol_level1)|5146|688981121|104|0.0%|100.0%|
[et_block](#et_block)|999|18343755|102|0.0%|98.0%|
[snort_ipfilter](#snort_ipfilter)|10136|10136|81|0.7%|77.8%|
[firehol_level3](#firehol_level3)|109859|9627471|81|0.0%|77.8%|
[sslbl](#sslbl)|376|376|37|9.8%|35.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|11|0.0%|10.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|3|0.0%|2.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|3|0.0%|2.8%|
[alienvault_reputation](#alienvault_reputation)|180612|180612|2|0.0%|1.9%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.9%|

## firehol_anonymous

**FireHOL Anonymous** - Known anonymizing IPs. (includes: firehol_proxies anonymous bm_tor dm_tor)

Source is downloaded from [this link]().

The last time downloaded was found to be dated: Sun Jun  7 22:20:34 UTC 2015.

The ipset `firehol_anonymous` has **18532** entries, **82552** unique IPs.

The following table shows the overlaps of `firehol_anonymous` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `firehol_anonymous`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `firehol_anonymous`.
- ` this % ` is the percentage **of this ipset (`firehol_anonymous`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_proxies](#firehol_proxies)|11968|12206|12206|100.0%|14.7%|
[ri_web_proxies](#ri_web_proxies)|7435|7435|7435|100.0%|9.0%|
[firehol_level3](#firehol_level3)|109859|9627471|6461|0.0%|7.8%|
[bm_tor](#bm_tor)|6425|6425|6425|100.0%|7.7%|
[dm_tor](#dm_tor)|6405|6405|6405|100.0%|7.7%|
[stopforumspam_30d](#stopforumspam_30d)|93938|93938|5955|6.3%|7.2%|
[et_tor](#et_tor)|6340|6340|5925|93.4%|7.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|3425|0.0%|4.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|2882|0.0%|3.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|2855|0.0%|3.4%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|2771|9.4%|3.3%|
[ri_connect_proxies](#ri_connect_proxies)|2695|2695|2695|100.0%|3.2%|
[xroxy](#xroxy)|2147|2147|2147|100.0%|2.6%|
[proxyrss](#proxyrss)|1602|1602|1602|100.0%|1.9%|
[firehol_level2](#firehol_level2)|24709|36348|1331|3.6%|1.6%|
[proxz](#proxz)|1173|1173|1173|100.0%|1.4%|
[snort_ipfilter](#snort_ipfilter)|10136|10136|1135|11.1%|1.3%|
[stopforumspam_1d](#stopforumspam_1d)|6943|6943|1005|14.4%|1.2%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|663|100.0%|0.8%|
[blocklist_de](#blocklist_de)|30769|30769|615|1.9%|0.7%|
[blocklist_de_bots](#blocklist_de_bots)|3122|3122|498|15.9%|0.6%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|372|100.0%|0.4%|
[nixspam](#nixspam)|23906|23906|151|0.6%|0.1%|
[blocklist_de_mail](#blocklist_de_mail)|19075|19075|100|0.5%|0.1%|
[php_dictionary](#php_dictionary)|666|666|89|13.3%|0.1%|
[voipbl](#voipbl)|10522|10934|78|0.7%|0.0%|
[php_spammers](#php_spammers)|661|661|76|11.4%|0.0%|
[php_commenters](#php_commenters)|403|403|76|18.8%|0.0%|
[alienvault_reputation](#alienvault_reputation)|180612|180612|54|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|29|0.0%|0.0%|
[openbl_60d](#openbl_60d)|7023|7023|23|0.3%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|15619|15619|17|0.1%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|15|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4256|4256|15|0.3%|0.0%|
[php_harvesters](#php_harvesters)|378|378|11|2.9%|0.0%|
[et_block](#et_block)|999|18343755|11|0.0%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|7|0.0%|0.0%|
[firehol_level1](#firehol_level1)|5146|688981121|7|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|6|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|174|174|6|3.4%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|3|0.2%|0.0%|
[et_compromised](#et_compromised)|1718|1718|3|0.1%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1723|1723|3|0.1%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2334|2334|2|0.0%|0.0%|
[sslbl](#sslbl)|376|376|1|0.2%|0.0%|
[shunlist](#shunlist)|1315|1315|1|0.0%|0.0%|
[openbl_30d](#openbl_30d)|2857|2857|1|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3255|3255|1|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|712|712|1|0.1%|0.0%|

## firehol_level1

**FireHOL Level 1** - Maximum protection without false positives. (includes: fullbogons dshield feodo palevo sslbl zeus spamhaus_drop spamhaus_edrop)

Source is downloaded from [this link]().

The last time downloaded was found to be dated: Sun Jun  7 22:15:43 UTC 2015.

The ipset `firehol_level1` has **5146** entries, **688981121** unique IPs.

The following table shows the overlaps of `firehol_level1` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `firehol_level1`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `firehol_level1`.
- ` this % ` is the percentage **of this ipset (`firehol_level1`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[fullbogons](#fullbogons)|3778|670299624|670299624|100.0%|97.2%|
[bogons](#bogons)|13|592708608|592708608|100.0%|86.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|18340608|100.0%|2.6%|
[et_block](#et_block)|999|18343755|18339911|99.9%|2.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|8867204|2.5%|1.2%|
[firehol_level3](#firehol_level3)|109859|9627471|7500205|77.9%|1.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|7498240|81.6%|1.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|4638626|3.3%|0.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|2569762|0.3%|0.3%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|487424|100.0%|0.0%|
[dshield](#dshield)|20|5120|5120|100.0%|0.0%|
[alienvault_reputation](#alienvault_reputation)|180612|180612|3820|2.1%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1931|0.5%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|93938|93938|1105|1.1%|0.0%|
[sslbl](#sslbl)|376|376|376|100.0%|0.0%|
[voipbl](#voipbl)|10522|10934|333|3.0%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|303|1.0%|0.0%|
[firehol_level2](#firehol_level2)|24709|36348|302|0.8%|0.0%|
[snort_ipfilter](#snort_ipfilter)|10136|10136|299|2.9%|0.0%|
[openbl_60d](#openbl_60d)|7023|7023|289|4.1%|0.0%|
[blocklist_de](#blocklist_de)|30769|30769|232|0.7%|0.0%|
[zeus](#zeus)|231|231|231|100.0%|0.0%|
[zeus_badips](#zeus_badips)|203|203|203|100.0%|0.0%|
[shunlist](#shunlist)|1315|1315|186|14.1%|0.0%|
[nixspam](#nixspam)|23906|23906|159|0.6%|0.0%|
[openbl_30d](#openbl_30d)|2857|2857|157|5.4%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3255|3255|131|4.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1723|1723|108|6.2%|0.0%|
[et_compromised](#et_compromised)|1718|1718|107|6.2%|0.0%|
[feodo](#feodo)|104|104|104|100.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6943|6943|89|1.2%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3122|3122|61|1.9%|0.0%|
[openbl_7d](#openbl_7d)|708|708|53|7.4%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|39|3.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|39|2.6%|0.0%|
[php_commenters](#php_commenters)|403|403|37|9.1%|0.0%|
[openbl_1d](#openbl_1d)|161|161|24|14.9%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|19075|19075|24|0.1%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|19|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|15619|15619|14|0.0%|0.0%|
[palevo](#palevo)|13|13|13|100.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2334|2334|12|0.5%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|174|174|10|5.7%|0.0%|
[firehol_anonymous](#firehol_anonymous)|18532|82552|7|0.0%|0.0%|
[php_dictionary](#php_dictionary)|666|666|6|0.9%|0.0%|
[malc0de](#malc0de)|338|338|6|1.7%|0.0%|
[ciarmy](#ciarmy)|409|409|6|1.4%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4256|4256|5|0.1%|0.0%|
[php_spammers](#php_spammers)|661|661|4|0.6%|0.0%|
[php_harvesters](#php_harvesters)|378|378|3|0.7%|0.0%|
[firehol_proxies](#firehol_proxies)|11968|12206|3|0.0%|0.0%|
[et_tor](#et_tor)|6340|6340|3|0.0%|0.0%|
[dm_tor](#dm_tor)|6405|6405|3|0.0%|0.0%|
[bm_tor](#bm_tor)|6425|6425|3|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|2|0.3%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|172|172|2|1.1%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|81|81|2|2.4%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7435|7435|1|0.0%|0.0%|
[et_botcc](#et_botcc)|509|509|1|0.1%|0.0%|

## firehol_level2

**FireHOL Level 2** - Maximum protection from attacks took place in the last 48 hours. (includes: openbl_1d blocklist_de stopforumspam_1d)

Source is downloaded from [this link]().

The last time downloaded was found to be dated: Sun Jun  7 22:20:34 UTC 2015.

The ipset `firehol_level2` has **24709** entries, **36348** unique IPs.

The following table shows the overlaps of `firehol_level2` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `firehol_level2`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `firehol_level2`.
- ` this % ` is the percentage **of this ipset (`firehol_level2`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|30769|30769|30769|100.0%|84.6%|
[blocklist_de_mail](#blocklist_de_mail)|19075|19075|19075|100.0%|52.4%|
[blocklist_de_apache](#blocklist_de_apache)|15619|15619|15619|100.0%|42.9%|
[firehol_level3](#firehol_level3)|109859|9627471|8293|0.0%|22.8%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|7821|26.6%|21.5%|
[stopforumspam_1d](#stopforumspam_1d)|6943|6943|6943|100.0%|19.1%|
[stopforumspam_30d](#stopforumspam_30d)|93938|93938|6894|7.3%|18.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|4317|0.0%|11.8%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4256|4256|4256|100.0%|11.7%|
[blocklist_de_ssh](#blocklist_de_ssh)|3255|3255|3255|100.0%|8.9%|
[blocklist_de_bots](#blocklist_de_bots)|3122|3122|3122|100.0%|8.5%|
[blocklist_de_imap](#blocklist_de_imap)|2334|2334|2334|100.0%|6.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|1767|0.0%|4.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|1667|0.0%|4.5%|
[alienvault_reputation](#alienvault_reputation)|180612|180612|1458|0.8%|4.0%|
[firehol_anonymous](#firehol_anonymous)|18532|82552|1331|1.6%|3.6%|
[firehol_proxies](#firehol_proxies)|11968|12206|1119|9.1%|3.0%|
[openbl_60d](#openbl_60d)|7023|7023|1084|15.4%|2.9%|
[openbl_30d](#openbl_30d)|2857|2857|866|30.3%|2.3%|
[bruteforceblocker](#bruteforceblocker)|1723|1723|732|42.4%|2.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|712|712|712|100.0%|1.9%|
[et_compromised](#et_compromised)|1718|1718|702|40.8%|1.9%|
[ri_web_proxies](#ri_web_proxies)|7435|7435|657|8.8%|1.8%|
[nixspam](#nixspam)|23906|23906|607|2.5%|1.6%|
[snort_ipfilter](#snort_ipfilter)|10136|10136|564|5.5%|1.5%|
[shunlist](#shunlist)|1315|1315|467|35.5%|1.2%|
[openbl_7d](#openbl_7d)|708|708|436|61.5%|1.1%|
[proxyrss](#proxyrss)|1602|1602|418|26.0%|1.1%|
[et_tor](#et_tor)|6340|6340|350|5.5%|0.9%|
[dm_tor](#dm_tor)|6405|6405|348|5.4%|0.9%|
[bm_tor](#bm_tor)|6425|6425|347|5.4%|0.9%|
[xroxy](#xroxy)|2147|2147|331|15.4%|0.9%|
[firehol_level1](#firehol_level1)|5146|688981121|302|0.0%|0.8%|
[et_block](#et_block)|999|18343755|286|0.0%|0.7%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|273|0.0%|0.7%|
[proxz](#proxz)|1173|1173|260|22.1%|0.7%|
[php_commenters](#php_commenters)|403|403|183|45.4%|0.5%|
[blocklist_de_strongips](#blocklist_de_strongips)|174|174|174|100.0%|0.4%|
[openbl_1d](#openbl_1d)|161|161|161|100.0%|0.4%|
[ri_connect_proxies](#ri_connect_proxies)|2695|2695|151|5.6%|0.4%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|151|40.5%|0.4%|
[php_dictionary](#php_dictionary)|666|666|109|16.3%|0.2%|
[php_spammers](#php_spammers)|661|661|103|15.5%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|94|0.0%|0.2%|
[dshield](#dshield)|20|5120|91|1.7%|0.2%|
[blocklist_de_sip](#blocklist_de_sip)|81|81|62|76.5%|0.1%|
[php_harvesters](#php_harvesters)|378|378|53|14.0%|0.1%|
[ciarmy](#ciarmy)|409|409|38|9.2%|0.1%|
[voipbl](#voipbl)|10522|10934|32|0.2%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|17|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|10|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|8|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|6|0.9%|0.0%|
[zeus_badips](#zeus_badips)|203|203|2|0.9%|0.0%|
[zeus](#zeus)|231|231|2|0.8%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|2|0.1%|0.0%|
[sslbl](#sslbl)|376|376|1|0.2%|0.0%|

## firehol_level3

**FireHOL Level 3** - All the bad IPs in last 30 days. (includes: openbl_30d stopforumspam_30d virbl malc0de shunlist malwaredomainlist bruteforceblocker ciarmy cleanmx_viruses snort_ipfilter ib_bluetack_spyware ib_bluetack_hijacked ib_bluetack_webexploit php_commenters php_dictionary php_harvesters php_spammers)

Source is downloaded from [this link]().

The last time downloaded was found to be dated: Sun Jun  7 22:20:34 UTC 2015.

The ipset `firehol_level3` has **109859** entries, **9627471** unique IPs.

The following table shows the overlaps of `firehol_level3` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `firehol_level3`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `firehol_level3`.
- ` this % ` is the percentage **of this ipset (`firehol_level3`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|9177856|100.0%|95.3%|
[firehol_level1](#firehol_level1)|5146|688981121|7500205|1.0%|77.9%|
[et_block](#et_block)|999|18343755|6933346|37.7%|72.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|6933035|37.8%|72.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|2537325|0.7%|26.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|919969|0.1%|9.5%|
[fullbogons](#fullbogons)|3778|670299624|566694|0.0%|5.8%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|339173|100.0%|3.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|161586|0.1%|1.6%|
[stopforumspam_30d](#stopforumspam_30d)|93938|93938|93938|100.0%|0.9%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|28007|95.4%|0.2%|
[snort_ipfilter](#snort_ipfilter)|10136|10136|10136|100.0%|0.1%|
[firehol_level2](#firehol_level2)|24709|36348|8293|22.8%|0.0%|
[firehol_anonymous](#firehol_anonymous)|18532|82552|6461|7.8%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6943|6943|5550|79.9%|0.0%|
[firehol_proxies](#firehol_proxies)|11968|12206|5369|43.9%|0.0%|
[alienvault_reputation](#alienvault_reputation)|180612|180612|5169|2.8%|0.0%|
[blocklist_de](#blocklist_de)|30769|30769|3982|12.9%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7435|7435|3587|48.2%|0.0%|
[openbl_60d](#openbl_60d)|7023|7023|2989|42.5%|0.0%|
[openbl_30d](#openbl_30d)|2857|2857|2857|100.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3122|3122|2306|73.8%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1723|1723|1723|100.0%|0.0%|
[et_compromised](#et_compromised)|1718|1718|1692|98.4%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2695|2695|1524|56.5%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|1450|100.0%|0.0%|
[shunlist](#shunlist)|1315|1315|1315|100.0%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|1288|100.0%|0.0%|
[xroxy](#xroxy)|2147|2147|1283|59.7%|0.0%|
[et_tor](#et_tor)|6340|6340|1101|17.3%|0.0%|
[bm_tor](#bm_tor)|6425|6425|1072|16.6%|0.0%|
[dm_tor](#dm_tor)|6405|6405|1071|16.7%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3255|3255|1070|32.8%|0.0%|
[proxyrss](#proxyrss)|1602|1602|720|44.9%|0.0%|
[openbl_7d](#openbl_7d)|708|708|708|100.0%|0.0%|
[proxz](#proxz)|1173|1173|704|60.0%|0.0%|
[php_dictionary](#php_dictionary)|666|666|666|100.0%|0.0%|
[php_spammers](#php_spammers)|661|661|661|100.0%|0.0%|
[nixspam](#nixspam)|23906|23906|526|2.2%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|19075|19075|437|2.2%|0.0%|
[ciarmy](#ciarmy)|409|409|409|100.0%|0.0%|
[php_commenters](#php_commenters)|403|403|403|100.0%|0.0%|
[php_harvesters](#php_harvesters)|378|378|378|100.0%|0.0%|
[malc0de](#malc0de)|338|338|338|100.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|15619|15619|302|1.9%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|234|62.9%|0.0%|
[zeus](#zeus)|231|231|204|88.3%|0.0%|
[zeus_badips](#zeus_badips)|203|203|181|89.1%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|172|172|172|100.0%|0.0%|
[openbl_1d](#openbl_1d)|161|161|157|97.5%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|174|174|155|89.0%|0.0%|
[dshield](#dshield)|20|5120|125|2.4%|0.0%|
[sslbl](#sslbl)|376|376|96|25.5%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4256|4256|92|2.1%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|89|0.0%|0.0%|
[feodo](#feodo)|104|104|81|77.8%|0.0%|
[voipbl](#voipbl)|10522|10934|57|0.5%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2334|2334|44|1.8%|0.0%|
[virbl](#virbl)|25|25|25|100.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|23|3.4%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|21|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|712|712|18|2.5%|0.0%|
[palevo](#palevo)|13|13|11|84.6%|0.0%|
[bogons](#bogons)|13|592708608|5|0.0%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|81|81|4|4.9%|0.0%|
[et_botcc](#et_botcc)|509|509|3|0.5%|0.0%|

## firehol_proxies

**FireHOL Proxies** - Known open proxies in the last 30 days. (includes: ib_bluetack_proxies maxmind_proxy_fraud proxyrss proxz ri_connect_proxies ri_web_proxies xroxy)

Source is downloaded from [this link]().

The last time downloaded was found to be dated: Sun Jun  7 22:20:34 UTC 2015.

The ipset `firehol_proxies` has **11968** entries, **12206** unique IPs.

The following table shows the overlaps of `firehol_proxies` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `firehol_proxies`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `firehol_proxies`.
- ` this % ` is the percentage **of this ipset (`firehol_proxies`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_anonymous](#firehol_anonymous)|18532|82552|12206|14.7%|100.0%|
[ri_web_proxies](#ri_web_proxies)|7435|7435|7435|100.0%|60.9%|
[firehol_level3](#firehol_level3)|109859|9627471|5369|0.0%|43.9%|
[stopforumspam_30d](#stopforumspam_30d)|93938|93938|5305|5.6%|43.4%|
[ri_connect_proxies](#ri_connect_proxies)|2695|2695|2695|100.0%|22.0%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|2358|8.0%|19.3%|
[xroxy](#xroxy)|2147|2147|2147|100.0%|17.5%|
[proxyrss](#proxyrss)|1602|1602|1602|100.0%|13.1%|
[proxz](#proxz)|1173|1173|1173|100.0%|9.6%|
[firehol_level2](#firehol_level2)|24709|36348|1119|3.0%|9.1%|
[stopforumspam_1d](#stopforumspam_1d)|6943|6943|798|11.4%|6.5%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|663|100.0%|5.4%|
[blocklist_de](#blocklist_de)|30769|30769|601|1.9%|4.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|502|0.0%|4.1%|
[blocklist_de_bots](#blocklist_de_bots)|3122|3122|496|15.8%|4.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|379|0.0%|3.1%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|372|100.0%|3.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|278|0.0%|2.2%|
[snort_ipfilter](#snort_ipfilter)|10136|10136|253|2.4%|2.0%|
[dm_tor](#dm_tor)|6405|6405|167|2.6%|1.3%|
[bm_tor](#bm_tor)|6425|6425|167|2.5%|1.3%|
[et_tor](#et_tor)|6340|6340|166|2.6%|1.3%|
[nixspam](#nixspam)|23906|23906|148|0.6%|1.2%|
[blocklist_de_mail](#blocklist_de_mail)|19075|19075|99|0.5%|0.8%|
[php_dictionary](#php_dictionary)|666|666|88|13.2%|0.7%|
[php_spammers](#php_spammers)|661|661|74|11.1%|0.6%|
[php_commenters](#php_commenters)|403|403|69|17.1%|0.5%|
[alienvault_reputation](#alienvault_reputation)|180612|180612|34|0.0%|0.2%|
[openbl_60d](#openbl_60d)|7023|7023|18|0.2%|0.1%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|15|0.0%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|12|0.0%|0.0%|
[php_harvesters](#php_harvesters)|378|378|10|2.6%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|15619|15619|7|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|174|174|6|3.4%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4256|4256|6|0.1%|0.0%|
[et_block](#et_block)|999|18343755|5|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|3|0.2%|0.0%|
[firehol_level1](#firehol_level1)|5146|688981121|3|0.0%|0.0%|
[et_compromised](#et_compromised)|1718|1718|3|0.1%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1723|1723|3|0.1%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|2|0.0%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2334|2334|2|0.0%|0.0%|
[voipbl](#voipbl)|10522|10934|1|0.0%|0.0%|
[sslbl](#sslbl)|376|376|1|0.2%|0.0%|
[shunlist](#shunlist)|1315|1315|1|0.0%|0.0%|

## fullbogons

[Team-Cymru.org](http://www.team-cymru.org) IP space that has been allocated to an RIR, but not assigned by that RIR to an actual ISP or other end-user - **excellent list - use it only your internet interface**

Source is downloaded from [this link](http://www.team-cymru.org/Services/Bogons/fullbogons-ipv4.txt).

The last time downloaded was found to be dated: Tue Jun  9 09:35:05 UTC 2015.

The ipset `fullbogons` has **3778** entries, **670299624** unique IPs.

The following table shows the overlaps of `fullbogons` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `fullbogons`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `fullbogons`.
- ` this % ` is the percentage **of this ipset (`fullbogons`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level1](#firehol_level1)|5146|688981121|670299624|97.2%|100.0%|
[bogons](#bogons)|13|592708608|592708608|100.0%|88.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|4237167|3.0%|0.6%|
[firehol_level3](#firehol_level3)|109859|9627471|566694|5.8%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|565760|6.1%|0.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|263817|0.0%|0.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|252159|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|151552|0.8%|0.0%|
[et_block](#et_block)|999|18343755|151552|0.8%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|890|0.2%|0.0%|
[voipbl](#voipbl)|10522|10934|319|2.9%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|33|2.2%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|13|0.0%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|9|0.6%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|93938|93938|1|0.0%|0.0%|
[php_harvesters](#php_harvesters)|378|378|1|0.2%|0.0%|
[php_commenters](#php_commenters)|403|403|1|0.2%|0.0%|
[nixspam](#nixspam)|23906|23906|1|0.0%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|172|172|1|0.5%|0.0%|
[ciarmy](#ciarmy)|409|409|1|0.2%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1723|1723|1|0.0%|0.0%|

## ib_bluetack_badpeers

[iBlocklist.com](https://www.iblocklist.com/) free version of [BlueTack.co.uk](http://www.bluetack.co.uk/) IPs that have been reported for bad deeds in p2p

Source is downloaded from [this link](http://list.iblocklist.com/?list=cwworuawihqvocglcoss&fileformat=p2p&archiveformat=gz).

The last time downloaded was found to be dated: Tue Jun  9 05:20:48 UTC 2015.

The ipset `ib_bluetack_badpeers` has **47940** entries, **47940** unique IPs.

The following table shows the overlaps of `ib_bluetack_badpeers` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ib_bluetack_badpeers`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ib_bluetack_badpeers`.
- ` this % ` is the percentage **of this ipset (`ib_bluetack_badpeers`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|1172|0.0%|2.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|394|0.0%|0.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|226|0.0%|0.4%|
[firehol_level3](#firehol_level3)|109859|9627471|21|0.0%|0.0%|
[firehol_level1](#firehol_level1)|5146|688981121|19|0.0%|0.0%|
[firehol_proxies](#firehol_proxies)|11968|12206|15|0.1%|0.0%|
[firehol_anonymous](#firehol_anonymous)|18532|82552|15|0.0%|0.0%|
[alienvault_reputation](#alienvault_reputation)|180612|180612|15|0.0%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|93938|93938|13|0.0%|0.0%|
[fullbogons](#fullbogons)|3778|670299624|13|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|11|1.6%|0.0%|
[et_block](#et_block)|999|18343755|11|0.0%|0.0%|
[firehol_level2](#firehol_level2)|24709|36348|8|0.0%|0.0%|
[blocklist_de](#blocklist_de)|30769|30769|8|0.0%|0.0%|
[nixspam](#nixspam)|23906|23906|6|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|5|0.0%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|4|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7435|7435|4|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|19075|19075|4|0.0%|0.0%|
[xroxy](#xroxy)|2147|2147|3|0.1%|0.0%|
[php_dictionary](#php_dictionary)|666|666|3|0.4%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|3|0.0%|0.0%|
[voipbl](#voipbl)|10522|10934|2|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|10136|10136|2|0.0%|0.0%|
[php_harvesters](#php_harvesters)|378|378|2|0.5%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6943|6943|1|0.0%|0.0%|
[proxz](#proxz)|1173|1173|1|0.0%|0.0%|
[php_spammers](#php_spammers)|661|661|1|0.1%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|1|0.0%|0.0%|
[dshield](#dshield)|20|5120|1|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3255|3255|1|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|712|712|1|0.1%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4256|4256|1|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3122|3122|1|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|15619|15619|1|0.0%|0.0%|

## ib_bluetack_hijacked

[iBlocklist.com](https://www.iblocklist.com/) free version of [BlueTack.co.uk](http://www.bluetack.co.uk/) hijacked IP-Blocks Hijacked IP space are IP blocks that are being used without permission

Source is downloaded from [this link](http://list.iblocklist.com/?list=usrcshglbiilevmyfhse&fileformat=p2p&archiveformat=gz).

The last time downloaded was found to be dated: Tue Jun  9 05:50:39 UTC 2015.

The ipset `ib_bluetack_hijacked` has **535** entries, **9177856** unique IPs.

The following table shows the overlaps of `ib_bluetack_hijacked` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ib_bluetack_hijacked`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ib_bluetack_hijacked`.
- ` this % ` is the percentage **of this ipset (`ib_bluetack_hijacked`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level3](#firehol_level3)|109859|9627471|9177856|95.3%|100.0%|
[firehol_level1](#firehol_level1)|5146|688981121|7498240|1.0%|81.6%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|6932480|37.7%|75.5%|
[et_block](#et_block)|999|18343755|6932480|37.7%|75.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|2526625|0.7%|27.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|904796|0.1%|9.8%|
[fullbogons](#fullbogons)|3778|670299624|565760|0.0%|6.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|145472|0.1%|1.5%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1036|0.3%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|93938|93938|735|0.7%|0.0%|
[alienvault_reputation](#alienvault_reputation)|180612|180612|518|0.2%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|167|0.5%|0.0%|
[nixspam](#nixspam)|23906|23906|156|0.6%|0.0%|
[firehol_level2](#firehol_level2)|24709|36348|94|0.2%|0.0%|
[blocklist_de](#blocklist_de)|30769|30769|60|0.1%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3122|3122|52|1.6%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6943|6943|40|0.5%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|27|2.0%|0.0%|
[openbl_60d](#openbl_60d)|7023|7023|16|0.2%|0.0%|
[openbl_30d](#openbl_30d)|2857|2857|12|0.4%|0.0%|
[snort_ipfilter](#snort_ipfilter)|10136|10136|11|0.1%|0.0%|
[zeus_badips](#zeus_badips)|203|203|10|4.9%|0.0%|
[zeus](#zeus)|231|231|10|4.3%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|7|0.4%|0.0%|
[firehol_anonymous](#firehol_anonymous)|18532|82552|7|0.0%|0.0%|
[openbl_7d](#openbl_7d)|708|708|5|0.7%|0.0%|
[et_compromised](#et_compromised)|1718|1718|5|0.2%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1723|1723|5|0.2%|0.0%|
[php_dictionary](#php_dictionary)|666|666|4|0.6%|0.0%|
[et_tor](#et_tor)|6340|6340|4|0.0%|0.0%|
[dm_tor](#dm_tor)|6405|6405|4|0.0%|0.0%|
[bm_tor](#bm_tor)|6425|6425|4|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3255|3255|4|0.1%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|19075|19075|4|0.0%|0.0%|
[shunlist](#shunlist)|1315|1315|3|0.2%|0.0%|
[php_spammers](#php_spammers)|661|661|3|0.4%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2334|2334|3|0.1%|0.0%|
[openbl_1d](#openbl_1d)|161|161|2|1.2%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|2|0.3%|0.0%|
[firehol_proxies](#firehol_proxies)|11968|12206|2|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|174|174|2|1.1%|0.0%|
[voipbl](#voipbl)|10522|10934|1|0.0%|0.0%|
[php_harvesters](#php_harvesters)|378|378|1|0.2%|0.0%|
[php_commenters](#php_commenters)|403|403|1|0.2%|0.0%|
[et_botcc](#et_botcc)|509|509|1|0.1%|0.0%|

## ib_bluetack_level1

[iBlocklist.com](https://www.iblocklist.com/) free version of [BlueTack.co.uk](http://www.bluetack.co.uk/) Level 1 (for use in p2p): Companies or organizations who are clearly involved with trying to stop filesharing (e.g. Baytsp, MediaDefender, Mediasentry a.o.). Companies which anti-p2p activity has been seen from. Companies that produce or have a strong financial interest in copyrighted material (e.g. music, movie, software industries a.o.). Government ranges or companies that have a strong financial interest in doing work for governments. Legal industry ranges. IPs or ranges of ISPs from which anti-p2p activity has been observed. Basically this list will block all kinds of internet connections that most people would rather not have during their internet travels.

Source is downloaded from [this link](http://list.iblocklist.com/?list=ydxerpxkpcfqjaybcssw&fileformat=p2p&archiveformat=gz).

The last time downloaded was found to be dated: Tue Jun  9 09:33:00 UTC 2015.

The ipset `ib_bluetack_level1` has **218307** entries, **764993634** unique IPs.

The following table shows the overlaps of `ib_bluetack_level1` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ib_bluetack_level1`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ib_bluetack_level1`.
- ` this % ` is the percentage **of this ipset (`ib_bluetack_level1`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|16302420|4.6%|2.1%|
[firehol_level1](#firehol_level1)|5146|688981121|2569762|0.3%|0.3%|
[et_block](#et_block)|999|18343755|2272798|12.3%|0.2%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|2272265|12.3%|0.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|1354507|0.9%|0.1%|
[firehol_level3](#firehol_level3)|109859|9627471|919969|9.5%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|904796|9.8%|0.1%|
[fullbogons](#fullbogons)|3778|670299624|263817|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|33155|6.8%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|13247|3.9%|0.0%|
[alienvault_reputation](#alienvault_reputation)|180612|180612|4216|2.3%|0.0%|
[firehol_anonymous](#firehol_anonymous)|18532|82552|3425|4.1%|0.0%|
[firehol_level2](#firehol_level2)|24709|36348|1667|4.5%|0.0%|
[blocklist_de](#blocklist_de)|30769|30769|1553|5.0%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|93938|93938|1519|1.6%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|19075|19075|1397|7.3%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|15619|15619|1337|8.5%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|529|1.8%|0.0%|
[dshield](#dshield)|20|5120|512|10.0%|0.0%|
[nixspam](#nixspam)|23906|23906|428|1.7%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|394|0.8%|0.0%|
[voipbl](#voipbl)|10522|10934|299|2.7%|0.0%|
[firehol_proxies](#firehol_proxies)|11968|12206|278|2.2%|0.0%|
[bm_tor](#bm_tor)|6425|6425|165|2.5%|0.0%|
[dm_tor](#dm_tor)|6405|6405|164|2.5%|0.0%|
[openbl_60d](#openbl_60d)|7023|7023|163|2.3%|0.0%|
[et_tor](#et_tor)|6340|6340|163|2.5%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7435|7435|151|2.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6943|6943|126|1.8%|0.0%|
[snort_ipfilter](#snort_ipfilter)|10136|10136|118|1.1%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|97|6.6%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2695|2695|82|3.0%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|66|5.1%|0.0%|
[openbl_30d](#openbl_30d)|2857|2857|64|2.2%|0.0%|
[xroxy](#xroxy)|2147|2147|58|2.7%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3255|3255|57|1.7%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|56|8.4%|0.0%|
[et_compromised](#et_compromised)|1718|1718|52|3.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1723|1723|52|3.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4256|4256|45|1.0%|0.0%|
[proxz](#proxz)|1173|1173|40|3.4%|0.0%|
[et_botcc](#et_botcc)|509|509|39|7.6%|0.0%|
[ciarmy](#ciarmy)|409|409|36|8.8%|0.0%|
[proxyrss](#proxyrss)|1602|1602|31|1.9%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3122|3122|31|0.9%|0.0%|
[shunlist](#shunlist)|1315|1315|26|1.9%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2334|2334|23|0.9%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|17|4.5%|0.0%|
[openbl_7d](#openbl_7d)|708|708|14|1.9%|0.0%|
[php_dictionary](#php_dictionary)|666|666|12|1.8%|0.0%|
[php_harvesters](#php_harvesters)|378|378|11|2.9%|0.0%|
[malc0de](#malc0de)|338|338|11|3.2%|0.0%|
[php_spammers](#php_spammers)|661|661|10|1.5%|0.0%|
[php_commenters](#php_commenters)|403|403|10|2.4%|0.0%|
[zeus](#zeus)|231|231|7|3.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|712|712|7|0.9%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|81|81|6|7.4%|0.0%|
[bogons](#bogons)|13|592708608|5|0.0%|0.0%|
[zeus_badips](#zeus_badips)|203|203|4|1.9%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|172|172|4|2.3%|0.0%|
[sslbl](#sslbl)|376|376|3|0.7%|0.0%|
[feodo](#feodo)|104|104|3|2.8%|0.0%|
[openbl_1d](#openbl_1d)|161|161|2|1.2%|0.0%|
[virbl](#virbl)|25|25|1|4.0%|0.0%|

## ib_bluetack_level2

[iBlocklist.com](https://www.iblocklist.com/) free version of BlueTack.co.uk Level 2 (for use in p2p). General corporate ranges. Ranges used by labs or researchers. Proxies.

Source is downloaded from [this link](http://list.iblocklist.com/?list=gyisgnzbhppbvsphucsw&fileformat=p2p&archiveformat=gz).

The last time downloaded was found to be dated: Tue Jun  9 05:50:42 UTC 2015.

The ipset `ib_bluetack_level2` has **72950** entries, **348710251** unique IPs.

The following table shows the overlaps of `ib_bluetack_level2` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ib_bluetack_level2`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ib_bluetack_level2`.
- ` this % ` is the percentage **of this ipset (`ib_bluetack_level2`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|16302420|2.1%|4.6%|
[firehol_level1](#firehol_level1)|5146|688981121|8867204|1.2%|2.5%|
[et_block](#et_block)|999|18343755|8532519|46.5%|2.4%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|8532506|46.5%|2.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|2830203|2.0%|0.8%|
[firehol_level3](#firehol_level3)|109859|9627471|2537325|26.3%|0.7%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2526625|27.5%|0.7%|
[fullbogons](#fullbogons)|3778|670299624|252159|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|98904|20.2%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|7728|2.2%|0.0%|
[alienvault_reputation](#alienvault_reputation)|180612|180612|6256|3.4%|0.0%|
[firehol_anonymous](#firehol_anonymous)|18532|82552|2882|3.4%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|93938|93938|2502|2.6%|0.0%|
[firehol_level2](#firehol_level2)|24709|36348|1767|4.8%|0.0%|
[blocklist_de](#blocklist_de)|30769|30769|1601|5.2%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|19075|19075|1266|6.6%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|15619|15619|1107|7.0%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|790|2.6%|0.0%|
[nixspam](#nixspam)|23906|23906|753|3.1%|0.0%|
[voipbl](#voipbl)|10522|10934|434|3.9%|0.0%|
[firehol_proxies](#firehol_proxies)|11968|12206|379|3.1%|0.0%|
[openbl_60d](#openbl_60d)|7023|7023|319|4.5%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|226|0.4%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7435|7435|218|2.9%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6943|6943|211|3.0%|0.0%|
[et_tor](#et_tor)|6340|6340|183|2.8%|0.0%|
[dm_tor](#dm_tor)|6405|6405|181|2.8%|0.0%|
[bm_tor](#bm_tor)|6425|6425|180|2.8%|0.0%|
[snort_ipfilter](#snort_ipfilter)|10136|10136|167|1.6%|0.0%|
[openbl_30d](#openbl_30d)|2857|2857|149|5.2%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3255|3255|136|4.1%|0.0%|
[xroxy](#xroxy)|2147|2147|104|4.8%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2695|2695|103|3.8%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3122|3122|100|3.2%|0.0%|
[et_compromised](#et_compromised)|1718|1718|89|5.1%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1723|1723|84|4.8%|0.0%|
[shunlist](#shunlist)|1315|1315|75|5.7%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4256|4256|71|1.6%|0.0%|
[proxyrss](#proxyrss)|1602|1602|65|4.0%|0.0%|
[php_spammers](#php_spammers)|661|661|52|7.8%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2334|2334|51|2.1%|0.0%|
[proxz](#proxz)|1173|1173|48|4.0%|0.0%|
[ciarmy](#ciarmy)|409|409|46|11.2%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|45|3.1%|0.0%|
[openbl_7d](#openbl_7d)|708|708|42|5.9%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|26|2.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|26|3.9%|0.0%|
[php_dictionary](#php_dictionary)|666|666|22|3.3%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|21|5.6%|0.0%|
[et_botcc](#et_botcc)|509|509|21|4.1%|0.0%|
[malc0de](#malc0de)|338|338|19|5.6%|0.0%|
[php_commenters](#php_commenters)|403|403|16|3.9%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|712|712|13|1.8%|0.0%|
[zeus](#zeus)|231|231|9|3.8%|0.0%|
[php_harvesters](#php_harvesters)|378|378|9|2.3%|0.0%|
[zeus_badips](#zeus_badips)|203|203|8|3.9%|0.0%|
[openbl_1d](#openbl_1d)|161|161|8|4.9%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|174|174|7|4.0%|0.0%|
[sslbl](#sslbl)|376|376|6|1.5%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|81|81|6|7.4%|0.0%|
[feodo](#feodo)|104|104|3|2.8%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|172|172|3|1.7%|0.0%|
[virbl](#virbl)|25|25|2|8.0%|0.0%|
[palevo](#palevo)|13|13|2|15.3%|0.0%|

## ib_bluetack_level3

[iBlocklist.com](https://www.iblocklist.com/) free version of BlueTack.co.uk Level 3 (for use in p2p). Many portal-type websites. ISP ranges that may be dodgy for some reason. Ranges that belong to an individual, but which have not been determined to be used by a particular company. Ranges for things that are unusual in some way. The L3 list is aka the paranoid list.

Source is downloaded from [this link](http://list.iblocklist.com/?list=uwnukjqktoggdknzrhgh&fileformat=p2p&archiveformat=gz).

The last time downloaded was found to be dated: Tue Jun  9 05:50:33 UTC 2015.

The ipset `ib_bluetack_level3` has **17812** entries, **139104927** unique IPs.

The following table shows the overlaps of `ib_bluetack_level3` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ib_bluetack_level3`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ib_bluetack_level3`.
- ` this % ` is the percentage **of this ipset (`ib_bluetack_level3`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level1](#firehol_level1)|5146|688981121|4638626|0.6%|3.3%|
[fullbogons](#fullbogons)|3778|670299624|4237167|0.6%|3.0%|
[bogons](#bogons)|13|592708608|4194304|0.7%|3.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|2830203|0.8%|2.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|1354507|0.1%|0.9%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|270785|55.5%|0.1%|
[firehol_level3](#firehol_level3)|109859|9627471|161586|1.6%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|145472|1.5%|0.1%|
[et_block](#et_block)|999|18343755|130922|0.7%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|130368|0.7%|0.0%|
[alienvault_reputation](#alienvault_reputation)|180612|180612|13614|7.5%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|9226|2.7%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|93938|93938|5824|6.1%|0.0%|
[firehol_level2](#firehol_level2)|24709|36348|4317|11.8%|0.0%|
[blocklist_de](#blocklist_de)|30769|30769|3879|12.6%|0.0%|
[firehol_anonymous](#firehol_anonymous)|18532|82552|2855|3.4%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|19075|19075|2803|14.6%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|15619|15619|2386|15.2%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|1913|6.5%|0.0%|
[voipbl](#voipbl)|10522|10934|1602|14.6%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|1172|2.4%|0.0%|
[nixspam](#nixspam)|23906|23906|962|4.0%|0.0%|
[openbl_60d](#openbl_60d)|7023|7023|744|10.5%|0.0%|
[dm_tor](#dm_tor)|6405|6405|626|9.7%|0.0%|
[bm_tor](#bm_tor)|6425|6425|623|9.6%|0.0%|
[et_tor](#et_tor)|6340|6340|614|9.6%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6943|6943|513|7.3%|0.0%|
[firehol_proxies](#firehol_proxies)|11968|12206|502|4.1%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3255|3255|463|14.2%|0.0%|
[openbl_30d](#openbl_30d)|2857|2857|295|10.3%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2334|2334|294|12.5%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4256|4256|294|6.9%|0.0%|
[dshield](#dshield)|20|5120|256|5.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|10136|10136|253|2.4%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7435|7435|213|2.8%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3122|3122|191|6.1%|0.0%|
[et_compromised](#et_compromised)|1718|1718|153|8.9%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1723|1723|152|8.8%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|147|11.4%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|125|33.6%|0.0%|
[shunlist](#shunlist)|1315|1315|119|9.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|108|7.4%|0.0%|
[xroxy](#xroxy)|2147|2147|107|4.9%|0.0%|
[proxz](#proxz)|1173|1173|99|8.4%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|712|712|97|13.6%|0.0%|
[ciarmy](#ciarmy)|409|409|92|22.4%|0.0%|
[openbl_7d](#openbl_7d)|708|708|79|11.1%|0.0%|
[et_botcc](#et_botcc)|509|509|77|15.1%|0.0%|
[proxyrss](#proxyrss)|1602|1602|63|3.9%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2695|2695|57|2.1%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|51|7.6%|0.0%|
[malc0de](#malc0de)|338|338|46|13.6%|0.0%|
[php_spammers](#php_spammers)|661|661|41|6.2%|0.0%|
[php_dictionary](#php_dictionary)|666|666|35|5.2%|0.0%|
[sslbl](#sslbl)|376|376|28|7.4%|0.0%|
[php_commenters](#php_commenters)|403|403|25|6.2%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|172|172|22|12.7%|0.0%|
[php_harvesters](#php_harvesters)|378|378|20|5.2%|0.0%|
[openbl_1d](#openbl_1d)|161|161|16|9.9%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|174|174|16|9.1%|0.0%|
[zeus](#zeus)|231|231|14|6.0%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|81|81|14|17.2%|0.0%|
[feodo](#feodo)|104|104|11|10.5%|0.0%|
[zeus_badips](#zeus_badips)|203|203|10|4.9%|0.0%|
[virbl](#virbl)|25|25|3|12.0%|0.0%|
[palevo](#palevo)|13|13|1|7.6%|0.0%|

## ib_bluetack_proxies

[iBlocklist.com](https://www.iblocklist.com/) free version of [BlueTack.co.uk](http://www.bluetack.co.uk/) Open Proxies IPs list (without TOR)

Source is downloaded from [this link](http://list.iblocklist.com/?list=xoebmbyexwuiogmbyprb&fileformat=p2p&archiveformat=gz).

The last time downloaded was found to be dated: Tue Jun  9 05:50:28 UTC 2015.

The ipset `ib_bluetack_proxies` has **663** entries, **663** unique IPs.

The following table shows the overlaps of `ib_bluetack_proxies` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ib_bluetack_proxies`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ib_bluetack_proxies`.
- ` this % ` is the percentage **of this ipset (`ib_bluetack_proxies`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_proxies](#firehol_proxies)|11968|12206|663|5.4%|100.0%|
[firehol_anonymous](#firehol_anonymous)|18532|82552|663|0.8%|100.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|56|0.0%|8.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|51|0.0%|7.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|26|0.0%|3.9%|
[firehol_level3](#firehol_level3)|109859|9627471|23|0.0%|3.4%|
[stopforumspam_30d](#stopforumspam_30d)|93938|93938|18|0.0%|2.7%|
[ri_web_proxies](#ri_web_proxies)|7435|7435|14|0.1%|2.1%|
[xroxy](#xroxy)|2147|2147|13|0.6%|1.9%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|11|0.0%|1.6%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|11|0.0%|1.6%|
[proxyrss](#proxyrss)|1602|1602|10|0.6%|1.5%|
[ri_connect_proxies](#ri_connect_proxies)|2695|2695|7|0.2%|1.0%|
[proxz](#proxz)|1173|1173|6|0.5%|0.9%|
[firehol_level2](#firehol_level2)|24709|36348|6|0.0%|0.9%|
[stopforumspam_1d](#stopforumspam_1d)|6943|6943|5|0.0%|0.7%|
[blocklist_de](#blocklist_de)|30769|30769|3|0.0%|0.4%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|2|0.0%|0.3%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|2|0.1%|0.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2|0.0%|0.3%|
[firehol_level1](#firehol_level1)|5146|688981121|2|0.0%|0.3%|
[et_block](#et_block)|999|18343755|2|0.0%|0.3%|
[blocklist_de_bots](#blocklist_de_bots)|3122|3122|2|0.0%|0.3%|
[snort_ipfilter](#snort_ipfilter)|10136|10136|1|0.0%|0.1%|
[php_dictionary](#php_dictionary)|666|666|1|0.1%|0.1%|
[nixspam](#nixspam)|23906|23906|1|0.0%|0.1%|
[blocklist_de_mail](#blocklist_de_mail)|19075|19075|1|0.0%|0.1%|
[alienvault_reputation](#alienvault_reputation)|180612|180612|1|0.0%|0.1%|

## ib_bluetack_spyware

[iBlocklist.com](https://www.iblocklist.com/) free version of [BlueTack.co.uk](http://www.bluetack.co.uk/) known malicious SPYWARE and ADWARE IP Address ranges

Source is downloaded from [this link](http://list.iblocklist.com/?list=llvtlsjyoyiczbkjsxpf&fileformat=p2p&archiveformat=gz).

The last time downloaded was found to be dated: Tue Jun  9 05:20:03 UTC 2015.

The ipset `ib_bluetack_spyware` has **3267** entries, **339173** unique IPs.

The following table shows the overlaps of `ib_bluetack_spyware` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ib_bluetack_spyware`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ib_bluetack_spyware`.
- ` this % ` is the percentage **of this ipset (`ib_bluetack_spyware`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level3](#firehol_level3)|109859|9627471|339173|3.5%|100.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|13247|0.0%|3.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|9226|0.0%|2.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|7728|0.0%|2.2%|
[firehol_level1](#firehol_level1)|5146|688981121|1931|0.0%|0.5%|
[et_block](#et_block)|999|18343755|1043|0.0%|0.3%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|1037|0.0%|0.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1036|0.0%|0.3%|
[fullbogons](#fullbogons)|3778|670299624|890|0.0%|0.2%|
[alienvault_reputation](#alienvault_reputation)|180612|180612|288|0.1%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|93938|93938|48|0.0%|0.0%|
[firehol_anonymous](#firehol_anonymous)|18532|82552|29|0.0%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|27|2.0%|0.0%|
[et_tor](#et_tor)|6340|6340|22|0.3%|0.0%|
[dm_tor](#dm_tor)|6405|6405|22|0.3%|0.0%|
[bm_tor](#bm_tor)|6425|6425|22|0.3%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|19|1.3%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|18|0.0%|0.0%|
[nixspam](#nixspam)|23906|23906|17|0.0%|0.0%|
[firehol_level2](#firehol_level2)|24709|36348|17|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|10136|10136|15|0.1%|0.0%|
[firehol_proxies](#firehol_proxies)|11968|12206|12|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6943|6943|11|0.1%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7435|7435|6|0.0%|0.0%|
[blocklist_de](#blocklist_de)|30769|30769|6|0.0%|0.0%|
[openbl_60d](#openbl_60d)|7023|7023|5|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|5|1.3%|0.0%|
[voipbl](#voipbl)|10522|10934|4|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|15619|15619|4|0.0%|0.0%|
[proxyrss](#proxyrss)|1602|1602|3|0.1%|0.0%|
[openbl_30d](#openbl_30d)|2857|2857|3|0.1%|0.0%|
[malc0de](#malc0de)|338|338|3|0.8%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|3|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4256|4256|3|0.0%|0.0%|
[et_compromised](#et_compromised)|1718|1718|2|0.1%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1723|1723|2|0.1%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|81|81|2|2.4%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|19075|19075|2|0.0%|0.0%|
[zeus_badips](#zeus_badips)|203|203|1|0.4%|0.0%|
[zeus](#zeus)|231|231|1|0.4%|0.0%|
[xroxy](#xroxy)|2147|2147|1|0.0%|0.0%|
[sslbl](#sslbl)|376|376|1|0.2%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|1|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2695|2695|1|0.0%|0.0%|
[proxz](#proxz)|1173|1173|1|0.0%|0.0%|
[php_harvesters](#php_harvesters)|378|378|1|0.2%|0.0%|
[php_dictionary](#php_dictionary)|666|666|1|0.1%|0.0%|
[php_commenters](#php_commenters)|403|403|1|0.2%|0.0%|
[palevo](#palevo)|13|13|1|7.6%|0.0%|
[feodo](#feodo)|104|104|1|0.9%|0.0%|
[ciarmy](#ciarmy)|409|409|1|0.2%|0.0%|
[bogons](#bogons)|13|592708608|1|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3122|3122|1|0.0%|0.0%|

## ib_bluetack_webexploit

[iBlocklist.com](https://www.iblocklist.com/) free version of [BlueTack.co.uk](http://www.bluetack.co.uk/) web server hack and exploit attempts

Source is downloaded from [this link](http://list.iblocklist.com/?list=ghlzqtqxnzctvvajwwag&fileformat=p2p&archiveformat=gz).

The last time downloaded was found to be dated: Tue Jun  9 05:20:44 UTC 2015.

The ipset `ib_bluetack_webexploit` has **1450** entries, **1450** unique IPs.

The following table shows the overlaps of `ib_bluetack_webexploit` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ib_bluetack_webexploit`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ib_bluetack_webexploit`.
- ` this % ` is the percentage **of this ipset (`ib_bluetack_webexploit`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level3](#firehol_level3)|109859|9627471|1450|0.0%|100.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|108|0.0%|7.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|97|0.0%|6.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|45|0.0%|3.1%|
[firehol_level1](#firehol_level1)|5146|688981121|39|0.0%|2.6%|
[fullbogons](#fullbogons)|3778|670299624|33|0.0%|2.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|19|0.0%|1.3%|
[et_block](#et_block)|999|18343755|8|0.0%|0.5%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|7|0.0%|0.4%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|6|0.0%|0.4%|
[alienvault_reputation](#alienvault_reputation)|180612|180612|6|0.0%|0.4%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|3|0.2%|0.2%|
[firehol_proxies](#firehol_proxies)|11968|12206|3|0.0%|0.2%|
[firehol_anonymous](#firehol_anonymous)|18532|82552|3|0.0%|0.2%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|2|0.0%|0.1%|
[stopforumspam_30d](#stopforumspam_30d)|93938|93938|2|0.0%|0.1%|
[openbl_60d](#openbl_60d)|7023|7023|2|0.0%|0.1%|
[openbl_30d](#openbl_30d)|2857|2857|2|0.0%|0.1%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|2|0.3%|0.1%|
[firehol_level2](#firehol_level2)|24709|36348|2|0.0%|0.1%|
[stopforumspam_1d](#stopforumspam_1d)|6943|6943|1|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|10136|10136|1|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7435|7435|1|0.0%|0.0%|
[openbl_7d](#openbl_7d)|708|708|1|0.1%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|1|0.0%|0.0%|
[et_botcc](#et_botcc)|509|509|1|0.1%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3255|3255|1|0.0%|0.0%|
[blocklist_de](#blocklist_de)|30769|30769|1|0.0%|0.0%|

## malc0de

[Malc0de.com](http://malc0de.com) malicious IPs of the last 30 days

Source is downloaded from [this link](http://malc0de.com/bl/IP_Blacklist.txt).

The last time downloaded was found to be dated: Tue Jun  9 13:17:02 UTC 2015.

The ipset `malc0de` has **338** entries, **338** unique IPs.

The following table shows the overlaps of `malc0de` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `malc0de`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `malc0de`.
- ` this % ` is the percentage **of this ipset (`malc0de`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level3](#firehol_level3)|109859|9627471|338|0.0%|100.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|46|0.0%|13.6%|
[cleanmx_viruses](#cleanmx_viruses)|172|172|20|11.6%|5.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|19|0.0%|5.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|11|0.0%|3.2%|
[alienvault_reputation](#alienvault_reputation)|180612|180612|11|0.0%|3.2%|
[firehol_level1](#firehol_level1)|5146|688981121|6|0.0%|1.7%|
[et_block](#et_block)|999|18343755|5|0.0%|1.4%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|4|0.0%|1.1%|
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
[firehol_level3](#firehol_level3)|109859|9627471|1288|0.0%|100.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|147|0.0%|11.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|66|0.0%|5.1%|
[firehol_level1](#firehol_level1)|5146|688981121|39|0.0%|3.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|29|0.0%|2.2%|
[et_block](#et_block)|999|18343755|29|0.0%|2.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|27|0.0%|2.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|27|0.0%|2.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|26|0.0%|2.0%|
[snort_ipfilter](#snort_ipfilter)|10136|10136|13|0.1%|1.0%|
[fullbogons](#fullbogons)|3778|670299624|9|0.0%|0.6%|
[alienvault_reputation](#alienvault_reputation)|180612|180612|8|0.0%|0.6%|
[stopforumspam_30d](#stopforumspam_30d)|93938|93938|4|0.0%|0.3%|
[malc0de](#malc0de)|338|338|4|1.1%|0.3%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|3|0.2%|0.2%|
[zeus](#zeus)|231|231|1|0.4%|0.0%|
[nixspam](#nixspam)|23906|23906|1|0.0%|0.0%|
[et_botcc](#et_botcc)|509|509|1|0.1%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|172|172|1|0.5%|0.0%|

## maxmind_proxy_fraud

[MaxMind.com](https://www.maxmind.com/en/anonymous-proxy-fraudulent-ip-address-list) list of anonymous proxy fraudelent IP addresses.

Source is downloaded from [this link](https://www.maxmind.com/en/anonymous-proxy-fraudulent-ip-address-list).

The last time downloaded was found to be dated: Wed Jun 10 02:00:14 UTC 2015.

The ipset `maxmind_proxy_fraud` has **372** entries, **372** unique IPs.

The following table shows the overlaps of `maxmind_proxy_fraud` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `maxmind_proxy_fraud`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `maxmind_proxy_fraud`.
- ` this % ` is the percentage **of this ipset (`maxmind_proxy_fraud`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_proxies](#firehol_proxies)|11968|12206|372|3.0%|100.0%|
[firehol_anonymous](#firehol_anonymous)|18532|82552|372|0.4%|100.0%|
[firehol_level3](#firehol_level3)|109859|9627471|234|0.0%|62.9%|
[stopforumspam_30d](#stopforumspam_30d)|93938|93938|233|0.2%|62.6%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|192|0.6%|51.6%|
[snort_ipfilter](#snort_ipfilter)|10136|10136|171|1.6%|45.9%|
[et_tor](#et_tor)|6340|6340|163|2.5%|43.8%|
[dm_tor](#dm_tor)|6405|6405|163|2.5%|43.8%|
[bm_tor](#bm_tor)|6425|6425|163|2.5%|43.8%|
[stopforumspam_1d](#stopforumspam_1d)|6943|6943|151|2.1%|40.5%|
[firehol_level2](#firehol_level2)|24709|36348|151|0.4%|40.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|125|0.0%|33.6%|
[php_commenters](#php_commenters)|403|403|44|10.9%|11.8%|
[alienvault_reputation](#alienvault_reputation)|180612|180612|26|0.0%|6.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|21|0.0%|5.6%|
[openbl_60d](#openbl_60d)|7023|7023|18|0.2%|4.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|17|0.0%|4.5%|
[php_harvesters](#php_harvesters)|378|378|6|1.5%|1.6%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|5|0.0%|1.3%|
[ri_web_proxies](#ri_web_proxies)|7435|7435|4|0.0%|1.0%|
[php_spammers](#php_spammers)|661|661|4|0.6%|1.0%|
[php_dictionary](#php_dictionary)|666|666|4|0.6%|1.0%|
[et_block](#et_block)|999|18343755|2|0.0%|0.5%|
[xroxy](#xroxy)|2147|2147|1|0.0%|0.2%|
[voipbl](#voipbl)|10522|10934|1|0.0%|0.2%|
[shunlist](#shunlist)|1315|1315|1|0.0%|0.2%|
[ri_connect_proxies](#ri_connect_proxies)|2695|2695|1|0.0%|0.2%|
[nixspam](#nixspam)|23906|23906|1|0.0%|0.2%|
[blocklist_de_mail](#blocklist_de_mail)|19075|19075|1|0.0%|0.2%|
[blocklist_de_apache](#blocklist_de_apache)|15619|15619|1|0.0%|0.2%|
[blocklist_de](#blocklist_de)|30769|30769|1|0.0%|0.2%|

## nixspam

[NiX Spam](http://www.heise.de/ix/NiX-Spam-DNSBL-and-blacklist-for-download-499637.html) IP addresses that sent spam in the last hour - automatically generated entries without distinguishing open proxies from relays, dialup gateways, and so on. All IPs are removed after 12 hours if there is no spam from there.

Source is downloaded from [this link](http://www.dnsbl.manitu.net/download/nixspam-ip.dump.gz).

The last time downloaded was found to be dated: Wed Jun 10 02:45:02 UTC 2015.

The ipset `nixspam` has **23906** entries, **23906** unique IPs.

The following table shows the overlaps of `nixspam` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `nixspam`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `nixspam`.
- ` this % ` is the percentage **of this ipset (`nixspam`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|962|0.0%|4.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|753|0.0%|3.1%|
[firehol_level2](#firehol_level2)|24709|36348|607|1.6%|2.5%|
[blocklist_de](#blocklist_de)|30769|30769|590|1.9%|2.4%|
[firehol_level3](#firehol_level3)|109859|9627471|526|0.0%|2.2%|
[blocklist_de_mail](#blocklist_de_mail)|19075|19075|519|2.7%|2.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|428|0.0%|1.7%|
[stopforumspam_30d](#stopforumspam_30d)|93938|93938|207|0.2%|0.8%|
[snort_ipfilter](#snort_ipfilter)|10136|10136|159|1.5%|0.6%|
[firehol_level1](#firehol_level1)|5146|688981121|159|0.0%|0.6%|
[et_block](#et_block)|999|18343755|157|0.0%|0.6%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|156|0.0%|0.6%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|156|0.0%|0.6%|
[firehol_anonymous](#firehol_anonymous)|18532|82552|151|0.1%|0.6%|
[firehol_proxies](#firehol_proxies)|11968|12206|148|1.2%|0.6%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|129|0.4%|0.5%|
[php_dictionary](#php_dictionary)|666|666|107|16.0%|0.4%|
[ri_web_proxies](#ri_web_proxies)|7435|7435|104|1.3%|0.4%|
[php_spammers](#php_spammers)|661|661|90|13.6%|0.3%|
[xroxy](#xroxy)|2147|2147|64|2.9%|0.2%|
[stopforumspam_1d](#stopforumspam_1d)|6943|6943|54|0.7%|0.2%|
[alienvault_reputation](#alienvault_reputation)|180612|180612|44|0.0%|0.1%|
[proxz](#proxz)|1173|1173|40|3.4%|0.1%|
[blocklist_de_bots](#blocklist_de_bots)|3122|3122|32|1.0%|0.1%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4256|4256|30|0.7%|0.1%|
[blocklist_de_apache](#blocklist_de_apache)|15619|15619|30|0.1%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|17|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2334|2334|15|0.6%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2695|2695|9|0.3%|0.0%|
[proxyrss](#proxyrss)|1602|1602|8|0.4%|0.0%|
[php_commenters](#php_commenters)|403|403|8|1.9%|0.0%|
[php_harvesters](#php_harvesters)|378|378|7|1.8%|0.0%|
[openbl_60d](#openbl_60d)|7023|7023|6|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|6|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3255|3255|6|0.1%|0.0%|
[openbl_30d](#openbl_30d)|2857|2857|4|0.1%|0.0%|
[et_tor](#et_tor)|6340|6340|4|0.0%|0.0%|
[dm_tor](#dm_tor)|6405|6405|4|0.0%|0.0%|
[bm_tor](#bm_tor)|6425|6425|3|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|174|174|3|1.7%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|712|712|3|0.4%|0.0%|
[zeus_badips](#zeus_badips)|203|203|1|0.4%|0.0%|
[zeus](#zeus)|231|231|1|0.4%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|1|0.0%|0.0%|
[openbl_7d](#openbl_7d)|708|708|1|0.1%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|1|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|1|0.1%|0.0%|
[fullbogons](#fullbogons)|3778|670299624|1|0.0%|0.0%|
[bogons](#bogons)|13|592708608|1|0.0%|0.0%|

## openbl_1d

[OpenBL.org](http://www.openbl.org/) last 24 hours IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.

Source is downloaded from [this link](http://www.openbl.org/lists/base_1days.txt).

The last time downloaded was found to be dated: Wed Jun 10 02:32:00 UTC 2015.

The ipset `openbl_1d` has **161** entries, **161** unique IPs.

The following table shows the overlaps of `openbl_1d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl_1d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl_1d`.
- ` this % ` is the percentage **of this ipset (`openbl_1d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|24709|36348|161|0.4%|100.0%|
[openbl_60d](#openbl_60d)|7023|7023|160|2.2%|99.3%|
[openbl_30d](#openbl_30d)|2857|2857|157|5.4%|97.5%|
[firehol_level3](#firehol_level3)|109859|9627471|157|0.0%|97.5%|
[openbl_7d](#openbl_7d)|708|708|154|21.7%|95.6%|
[alienvault_reputation](#alienvault_reputation)|180612|180612|146|0.0%|90.6%|
[blocklist_de](#blocklist_de)|30769|30769|130|0.4%|80.7%|
[blocklist_de_ssh](#blocklist_de_ssh)|3255|3255|126|3.8%|78.2%|
[bruteforceblocker](#bruteforceblocker)|1723|1723|71|4.1%|44.0%|
[shunlist](#shunlist)|1315|1315|69|5.2%|42.8%|
[et_compromised](#et_compromised)|1718|1718|67|3.8%|41.6%|
[et_block](#et_block)|999|18343755|26|0.0%|16.1%|
[firehol_level1](#firehol_level1)|5146|688981121|24|0.0%|14.9%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|22|0.0%|13.6%|
[blocklist_de_strongips](#blocklist_de_strongips)|174|174|19|10.9%|11.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|16|0.0%|9.9%|
[dshield](#dshield)|20|5120|9|0.1%|5.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|8|0.0%|4.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|2|0.0%|1.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2|0.0%|1.2%|
[blocklist_de_mail](#blocklist_de_mail)|19075|19075|2|0.0%|1.2%|
[blocklist_de_imap](#blocklist_de_imap)|2334|2334|2|0.0%|1.2%|
[blocklist_de_apache](#blocklist_de_apache)|15619|15619|2|0.0%|1.2%|
[stopforumspam_30d](#stopforumspam_30d)|93938|93938|1|0.0%|0.6%|
[php_spammers](#php_spammers)|661|661|1|0.1%|0.6%|
[php_commenters](#php_commenters)|403|403|1|0.2%|0.6%|
[ciarmy](#ciarmy)|409|409|1|0.2%|0.6%|

## openbl_30d

[OpenBL.org](http://www.openbl.org/) last 30 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.

Source is downloaded from [this link](http://www.openbl.org/lists/base_30days.txt).

The last time downloaded was found to be dated: Wed Jun 10 00:07:00 UTC 2015.

The ipset `openbl_30d` has **2857** entries, **2857** unique IPs.

The following table shows the overlaps of `openbl_30d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl_30d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl_30d`.
- ` this % ` is the percentage **of this ipset (`openbl_30d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[openbl_60d](#openbl_60d)|7023|7023|2857|40.6%|100.0%|
[firehol_level3](#firehol_level3)|109859|9627471|2857|0.0%|100.0%|
[alienvault_reputation](#alienvault_reputation)|180612|180612|2828|1.5%|98.9%|
[bruteforceblocker](#bruteforceblocker)|1723|1723|945|54.8%|33.0%|
[et_compromised](#et_compromised)|1718|1718|938|54.5%|32.8%|
[firehol_level2](#firehol_level2)|24709|36348|866|2.3%|30.3%|
[blocklist_de](#blocklist_de)|30769|30769|837|2.7%|29.2%|
[blocklist_de_ssh](#blocklist_de_ssh)|3255|3255|798|24.5%|27.9%|
[openbl_7d](#openbl_7d)|708|708|708|100.0%|24.7%|
[shunlist](#shunlist)|1315|1315|541|41.1%|18.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|295|0.0%|10.3%|
[openbl_1d](#openbl_1d)|161|161|157|97.5%|5.4%|
[firehol_level1](#firehol_level1)|5146|688981121|157|0.0%|5.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|149|0.0%|5.2%|
[et_block](#et_block)|999|18343755|129|0.0%|4.5%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|121|0.0%|4.2%|
[dshield](#dshield)|20|5120|103|2.0%|3.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|64|0.0%|2.2%|
[blocklist_de_mail](#blocklist_de_mail)|19075|19075|32|0.1%|1.1%|
[blocklist_de_imap](#blocklist_de_imap)|2334|2334|25|1.0%|0.8%|
[blocklist_de_strongips](#blocklist_de_strongips)|174|174|24|13.7%|0.8%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|12|0.0%|0.4%|
[snort_ipfilter](#snort_ipfilter)|10136|10136|5|0.0%|0.1%|
[blocklist_de_apache](#blocklist_de_apache)|15619|15619|5|0.0%|0.1%|
[stopforumspam_30d](#stopforumspam_30d)|93938|93938|4|0.0%|0.1%|
[nixspam](#nixspam)|23906|23906|4|0.0%|0.1%|
[voipbl](#voipbl)|10522|10934|3|0.0%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|3|0.0%|0.1%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|2|0.1%|0.0%|
[ciarmy](#ciarmy)|409|409|2|0.4%|0.0%|
[zeus](#zeus)|231|231|1|0.4%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|1|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6943|6943|1|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|1|0.0%|0.0%|
[php_spammers](#php_spammers)|661|661|1|0.1%|0.0%|
[php_commenters](#php_commenters)|403|403|1|0.2%|0.0%|
[firehol_anonymous](#firehol_anonymous)|18532|82552|1|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|712|712|1|0.1%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3122|3122|1|0.0%|0.0%|

## openbl_60d

[OpenBL.org](http://www.openbl.org/) last 60 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.

Source is downloaded from [this link](http://www.openbl.org/lists/base_60days.txt).

The last time downloaded was found to be dated: Wed Jun 10 00:07:00 UTC 2015.

The ipset `openbl_60d` has **7023** entries, **7023** unique IPs.

The following table shows the overlaps of `openbl_60d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl_60d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl_60d`.
- ` this % ` is the percentage **of this ipset (`openbl_60d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[alienvault_reputation](#alienvault_reputation)|180612|180612|6988|3.8%|99.5%|
[firehol_level3](#firehol_level3)|109859|9627471|2989|0.0%|42.5%|
[openbl_30d](#openbl_30d)|2857|2857|2857|100.0%|40.6%|
[firehol_level2](#firehol_level2)|24709|36348|1084|2.9%|15.4%|
[blocklist_de](#blocklist_de)|30769|30769|1034|3.3%|14.7%|
[bruteforceblocker](#bruteforceblocker)|1723|1723|1006|58.3%|14.3%|
[et_compromised](#et_compromised)|1718|1718|1002|58.3%|14.2%|
[blocklist_de_ssh](#blocklist_de_ssh)|3255|3255|985|30.2%|14.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|744|0.0%|10.5%|
[openbl_7d](#openbl_7d)|708|708|708|100.0%|10.0%|
[shunlist](#shunlist)|1315|1315|570|43.3%|8.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|319|0.0%|4.5%|
[firehol_level1](#firehol_level1)|5146|688981121|289|0.0%|4.1%|
[et_block](#et_block)|999|18343755|247|0.0%|3.5%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|235|0.0%|3.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|163|0.0%|2.3%|
[openbl_1d](#openbl_1d)|161|161|160|99.3%|2.2%|
[dshield](#dshield)|20|5120|120|2.3%|1.7%|
[stopforumspam_30d](#stopforumspam_30d)|93938|93938|50|0.0%|0.7%|
[blocklist_de_mail](#blocklist_de_mail)|19075|19075|38|0.1%|0.5%|
[blocklist_de_imap](#blocklist_de_imap)|2334|2334|30|1.2%|0.4%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|27|0.0%|0.3%|
[snort_ipfilter](#snort_ipfilter)|10136|10136|27|0.2%|0.3%|
[blocklist_de_strongips](#blocklist_de_strongips)|174|174|25|14.3%|0.3%|
[firehol_anonymous](#firehol_anonymous)|18532|82552|23|0.0%|0.3%|
[stopforumspam_1d](#stopforumspam_1d)|6943|6943|20|0.2%|0.2%|
[et_tor](#et_tor)|6340|6340|20|0.3%|0.2%|
[dm_tor](#dm_tor)|6405|6405|20|0.3%|0.2%|
[bm_tor](#bm_tor)|6425|6425|20|0.3%|0.2%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|18|4.8%|0.2%|
[firehol_proxies](#firehol_proxies)|11968|12206|18|0.1%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|16|0.0%|0.2%|
[php_commenters](#php_commenters)|403|403|11|2.7%|0.1%|
[voipbl](#voipbl)|10522|10934|8|0.0%|0.1%|
[nixspam](#nixspam)|23906|23906|6|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|5|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3122|3122|5|0.1%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|15619|15619|5|0.0%|0.0%|
[zeus](#zeus)|231|231|2|0.8%|0.0%|
[php_harvesters](#php_harvesters)|378|378|2|0.5%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|2|0.1%|0.0%|
[ciarmy](#ciarmy)|409|409|2|0.4%|0.0%|
[zeus_badips](#zeus_badips)|203|203|1|0.4%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|1|0.0%|0.0%|
[php_spammers](#php_spammers)|661|661|1|0.1%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|712|712|1|0.1%|0.0%|

## openbl_7d

[OpenBL.org](http://www.openbl.org/) last 7 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.

Source is downloaded from [this link](http://www.openbl.org/lists/base_7days.txt).

The last time downloaded was found to be dated: Wed Jun 10 00:07:00 UTC 2015.

The ipset `openbl_7d` has **708** entries, **708** unique IPs.

The following table shows the overlaps of `openbl_7d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl_7d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl_7d`.
- ` this % ` is the percentage **of this ipset (`openbl_7d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[openbl_60d](#openbl_60d)|7023|7023|708|10.0%|100.0%|
[openbl_30d](#openbl_30d)|2857|2857|708|24.7%|100.0%|
[firehol_level3](#firehol_level3)|109859|9627471|708|0.0%|100.0%|
[alienvault_reputation](#alienvault_reputation)|180612|180612|691|0.3%|97.5%|
[firehol_level2](#firehol_level2)|24709|36348|436|1.1%|61.5%|
[blocklist_de](#blocklist_de)|30769|30769|407|1.3%|57.4%|
[blocklist_de_ssh](#blocklist_de_ssh)|3255|3255|397|12.1%|56.0%|
[bruteforceblocker](#bruteforceblocker)|1723|1723|330|19.1%|46.6%|
[et_compromised](#et_compromised)|1718|1718|322|18.7%|45.4%|
[shunlist](#shunlist)|1315|1315|229|17.4%|32.3%|
[openbl_1d](#openbl_1d)|161|161|154|95.6%|21.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|79|0.0%|11.1%|
[firehol_level1](#firehol_level1)|5146|688981121|53|0.0%|7.4%|
[et_block](#et_block)|999|18343755|52|0.0%|7.3%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|48|0.0%|6.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|42|0.0%|5.9%|
[blocklist_de_strongips](#blocklist_de_strongips)|174|174|23|13.2%|3.2%|
[dshield](#dshield)|20|5120|18|0.3%|2.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|14|0.0%|1.9%|
[blocklist_de_mail](#blocklist_de_mail)|19075|19075|7|0.0%|0.9%|
[blocklist_de_imap](#blocklist_de_imap)|2334|2334|7|0.2%|0.9%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|5|0.0%|0.7%|
[ciarmy](#ciarmy)|409|409|2|0.4%|0.2%|
[blocklist_de_apache](#blocklist_de_apache)|15619|15619|2|0.0%|0.2%|
[stopforumspam_30d](#stopforumspam_30d)|93938|93938|1|0.0%|0.1%|
[snort_ipfilter](#snort_ipfilter)|10136|10136|1|0.0%|0.1%|
[php_spammers](#php_spammers)|661|661|1|0.1%|0.1%|
[php_commenters](#php_commenters)|403|403|1|0.2%|0.1%|
[nixspam](#nixspam)|23906|23906|1|0.0%|0.1%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|1|0.0%|0.1%|
[blocklist_de_ftp](#blocklist_de_ftp)|712|712|1|0.1%|0.1%|

## palevo

[Abuse.ch Palevo tracker](https://palevotracker.abuse.ch) worm includes IPs which are being used as botnet C&C for the Palevo crimeware - **excellent list**

Source is downloaded from [this link](https://palevotracker.abuse.ch/blocklists.php?download=ipblocklist).

The last time downloaded was found to be dated: Wed Jun 10 02:45:09 UTC 2015.

The ipset `palevo` has **13** entries, **13** unique IPs.

The following table shows the overlaps of `palevo` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `palevo`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `palevo`.
- ` this % ` is the percentage **of this ipset (`palevo`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level1](#firehol_level1)|5146|688981121|13|0.0%|100.0%|
[et_block](#et_block)|999|18343755|13|0.0%|100.0%|
[snort_ipfilter](#snort_ipfilter)|10136|10136|11|0.1%|84.6%|
[firehol_level3](#firehol_level3)|109859|9627471|11|0.0%|84.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|2|0.0%|15.3%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|7.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|1|0.0%|7.6%|

## php_commenters

[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) comment spammers (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=c&rss=1).

The last time downloaded was found to be dated: Wed Jun 10 02:18:24 UTC 2015.

The ipset `php_commenters` has **403** entries, **403** unique IPs.

The following table shows the overlaps of `php_commenters` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `php_commenters`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `php_commenters`.
- ` this % ` is the percentage **of this ipset (`php_commenters`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level3](#firehol_level3)|109859|9627471|403|0.0%|100.0%|
[stopforumspam_30d](#stopforumspam_30d)|93938|93938|302|0.3%|74.9%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|225|0.7%|55.8%|
[firehol_level2](#firehol_level2)|24709|36348|183|0.5%|45.4%|
[stopforumspam_1d](#stopforumspam_1d)|6943|6943|160|2.3%|39.7%|
[blocklist_de](#blocklist_de)|30769|30769|99|0.3%|24.5%|
[blocklist_de_bots](#blocklist_de_bots)|3122|3122|79|2.5%|19.6%|
[firehol_anonymous](#firehol_anonymous)|18532|82552|76|0.0%|18.8%|
[firehol_proxies](#firehol_proxies)|11968|12206|69|0.5%|17.1%|
[snort_ipfilter](#snort_ipfilter)|10136|10136|59|0.5%|14.6%|
[et_tor](#et_tor)|6340|6340|48|0.7%|11.9%|
[dm_tor](#dm_tor)|6405|6405|48|0.7%|11.9%|
[bm_tor](#bm_tor)|6425|6425|48|0.7%|11.9%|
[blocklist_de_strongips](#blocklist_de_strongips)|174|174|45|25.8%|11.1%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|44|11.8%|10.9%|
[php_spammers](#php_spammers)|661|661|43|6.5%|10.6%|
[firehol_level1](#firehol_level1)|5146|688981121|37|0.0%|9.1%|
[blocklist_de_apache](#blocklist_de_apache)|15619|15619|32|0.2%|7.9%|
[et_block](#et_block)|999|18343755|30|0.0%|7.4%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|29|0.0%|7.1%|
[php_dictionary](#php_dictionary)|666|666|28|4.2%|6.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|25|0.0%|6.2%|
[blocklist_de_mail](#blocklist_de_mail)|19075|19075|25|0.1%|6.2%|
[ri_web_proxies](#ri_web_proxies)|7435|7435|23|0.3%|5.7%|
[alienvault_reputation](#alienvault_reputation)|180612|180612|18|0.0%|4.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|16|0.0%|3.9%|
[php_harvesters](#php_harvesters)|378|378|15|3.9%|3.7%|
[openbl_60d](#openbl_60d)|7023|7023|11|0.1%|2.7%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4256|4256|11|0.2%|2.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|10|0.0%|2.4%|
[xroxy](#xroxy)|2147|2147|8|0.3%|1.9%|
[nixspam](#nixspam)|23906|23906|8|0.0%|1.9%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|7|0.0%|1.7%|
[proxz](#proxz)|1173|1173|7|0.5%|1.7%|
[ri_connect_proxies](#ri_connect_proxies)|2695|2695|5|0.1%|1.2%|
[zeus_badips](#zeus_badips)|203|203|1|0.4%|0.2%|
[zeus](#zeus)|231|231|1|0.4%|0.2%|
[proxyrss](#proxyrss)|1602|1602|1|0.0%|0.2%|
[openbl_7d](#openbl_7d)|708|708|1|0.1%|0.2%|
[openbl_30d](#openbl_30d)|2857|2857|1|0.0%|0.2%|
[openbl_1d](#openbl_1d)|161|161|1|0.6%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.2%|
[fullbogons](#fullbogons)|3778|670299624|1|0.0%|0.2%|
[et_compromised](#et_compromised)|1718|1718|1|0.0%|0.2%|
[bruteforceblocker](#bruteforceblocker)|1723|1723|1|0.0%|0.2%|
[bogons](#bogons)|13|592708608|1|0.0%|0.2%|
[blocklist_de_ssh](#blocklist_de_ssh)|3255|3255|1|0.0%|0.2%|
[blocklist_de_imap](#blocklist_de_imap)|2334|2334|1|0.0%|0.2%|

## php_dictionary

[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) directory attackers (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=d&rss=1).

The last time downloaded was found to be dated: Wed Jun 10 02:18:25 UTC 2015.

The ipset `php_dictionary` has **666** entries, **666** unique IPs.

The following table shows the overlaps of `php_dictionary` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `php_dictionary`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `php_dictionary`.
- ` this % ` is the percentage **of this ipset (`php_dictionary`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level3](#firehol_level3)|109859|9627471|666|0.0%|100.0%|
[php_spammers](#php_spammers)|661|661|273|41.3%|40.9%|
[stopforumspam_30d](#stopforumspam_30d)|93938|93938|126|0.1%|18.9%|
[firehol_level2](#firehol_level2)|24709|36348|109|0.2%|16.3%|
[nixspam](#nixspam)|23906|23906|107|0.4%|16.0%|
[blocklist_de](#blocklist_de)|30769|30769|102|0.3%|15.3%|
[firehol_anonymous](#firehol_anonymous)|18532|82552|89|0.1%|13.3%|
[firehol_proxies](#firehol_proxies)|11968|12206|88|0.7%|13.2%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|84|0.2%|12.6%|
[snort_ipfilter](#snort_ipfilter)|10136|10136|83|0.8%|12.4%|
[blocklist_de_mail](#blocklist_de_mail)|19075|19075|79|0.4%|11.8%|
[ri_web_proxies](#ri_web_proxies)|7435|7435|60|0.8%|9.0%|
[xroxy](#xroxy)|2147|2147|39|1.8%|5.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|35|0.0%|5.2%|
[stopforumspam_1d](#stopforumspam_1d)|6943|6943|30|0.4%|4.5%|
[php_commenters](#php_commenters)|403|403|28|6.9%|4.2%|
[proxz](#proxz)|1173|1173|23|1.9%|3.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|22|0.0%|3.3%|
[blocklist_de_bots](#blocklist_de_bots)|3122|3122|19|0.6%|2.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|12|0.0%|1.8%|
[alienvault_reputation](#alienvault_reputation)|180612|180612|8|0.0%|1.2%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|6|0.0%|0.9%|
[firehol_level1](#firehol_level1)|5146|688981121|6|0.0%|0.9%|
[et_block](#et_block)|999|18343755|6|0.0%|0.9%|
[ri_connect_proxies](#ri_connect_proxies)|2695|2695|4|0.1%|0.6%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|4|1.0%|0.6%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|4|0.0%|0.6%|
[blocklist_de_strongips](#blocklist_de_strongips)|174|174|4|2.2%|0.6%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4256|4256|4|0.0%|0.6%|
[blocklist_de_apache](#blocklist_de_apache)|15619|15619|4|0.0%|0.6%|
[php_harvesters](#php_harvesters)|378|378|3|0.7%|0.4%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|3|0.0%|0.4%|
[et_tor](#et_tor)|6340|6340|3|0.0%|0.4%|
[dm_tor](#dm_tor)|6405|6405|3|0.0%|0.4%|
[bm_tor](#bm_tor)|6425|6425|3|0.0%|0.4%|
[proxyrss](#proxyrss)|1602|1602|2|0.1%|0.3%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.1%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|1|0.1%|0.1%|

## php_harvesters

[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) harvesters (IPs that surf the internet looking for email addresses) (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=h&rss=1).

The last time downloaded was found to be dated: Wed Jun 10 02:18:23 UTC 2015.

The ipset `php_harvesters` has **378** entries, **378** unique IPs.

The following table shows the overlaps of `php_harvesters` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `php_harvesters`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `php_harvesters`.
- ` this % ` is the percentage **of this ipset (`php_harvesters`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level3](#firehol_level3)|109859|9627471|378|0.0%|100.0%|
[stopforumspam_30d](#stopforumspam_30d)|93938|93938|81|0.0%|21.4%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|60|0.2%|15.8%|
[firehol_level2](#firehol_level2)|24709|36348|53|0.1%|14.0%|
[blocklist_de](#blocklist_de)|30769|30769|38|0.1%|10.0%|
[stopforumspam_1d](#stopforumspam_1d)|6943|6943|36|0.5%|9.5%|
[blocklist_de_bots](#blocklist_de_bots)|3122|3122|27|0.8%|7.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|20|0.0%|5.2%|
[php_commenters](#php_commenters)|403|403|15|3.7%|3.9%|
[alienvault_reputation](#alienvault_reputation)|180612|180612|12|0.0%|3.1%|
[snort_ipfilter](#snort_ipfilter)|10136|10136|11|0.1%|2.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|11|0.0%|2.9%|
[firehol_anonymous](#firehol_anonymous)|18532|82552|11|0.0%|2.9%|
[firehol_proxies](#firehol_proxies)|11968|12206|10|0.0%|2.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|9|0.0%|2.3%|
[nixspam](#nixspam)|23906|23906|7|0.0%|1.8%|
[et_tor](#et_tor)|6340|6340|7|0.1%|1.8%|
[dm_tor](#dm_tor)|6405|6405|7|0.1%|1.8%|
[bm_tor](#bm_tor)|6425|6425|7|0.1%|1.8%|
[blocklist_de_mail](#blocklist_de_mail)|19075|19075|7|0.0%|1.8%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|6|1.6%|1.5%|
[php_spammers](#php_spammers)|661|661|3|0.4%|0.7%|
[php_dictionary](#php_dictionary)|666|666|3|0.4%|0.7%|
[firehol_level1](#firehol_level1)|5146|688981121|3|0.0%|0.7%|
[blocklist_de_ftp](#blocklist_de_ftp)|712|712|3|0.4%|0.7%|
[xroxy](#xroxy)|2147|2147|2|0.0%|0.5%|
[ri_web_proxies](#ri_web_proxies)|7435|7435|2|0.0%|0.5%|
[openbl_60d](#openbl_60d)|7023|7023|2|0.0%|0.5%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|2|0.0%|0.5%|
[blocklist_de_strongips](#blocklist_de_strongips)|174|174|2|1.1%|0.5%|
[blocklist_de_apache](#blocklist_de_apache)|15619|15619|2|0.0%|0.5%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|1|0.0%|0.2%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|1|0.0%|0.2%|
[proxyrss](#proxyrss)|1602|1602|1|0.0%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.2%|
[fullbogons](#fullbogons)|3778|670299624|1|0.0%|0.2%|
[et_block](#et_block)|999|18343755|1|0.0%|0.2%|
[bogons](#bogons)|13|592708608|1|0.0%|0.2%|
[blocklist_de_imap](#blocklist_de_imap)|2334|2334|1|0.0%|0.2%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4256|4256|1|0.0%|0.2%|

## php_spammers

[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) spam servers (IPs used by spammers to send messages) (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=s&rss=1).

The last time downloaded was found to be dated: Wed Jun 10 02:18:23 UTC 2015.

The ipset `php_spammers` has **661** entries, **661** unique IPs.

The following table shows the overlaps of `php_spammers` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `php_spammers`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `php_spammers`.
- ` this % ` is the percentage **of this ipset (`php_spammers`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level3](#firehol_level3)|109859|9627471|661|0.0%|100.0%|
[php_dictionary](#php_dictionary)|666|666|273|40.9%|41.3%|
[stopforumspam_30d](#stopforumspam_30d)|93938|93938|138|0.1%|20.8%|
[firehol_level2](#firehol_level2)|24709|36348|103|0.2%|15.5%|
[blocklist_de](#blocklist_de)|30769|30769|96|0.3%|14.5%|
[nixspam](#nixspam)|23906|23906|90|0.3%|13.6%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|83|0.2%|12.5%|
[snort_ipfilter](#snort_ipfilter)|10136|10136|78|0.7%|11.8%|
[firehol_anonymous](#firehol_anonymous)|18532|82552|76|0.0%|11.4%|
[firehol_proxies](#firehol_proxies)|11968|12206|74|0.6%|11.1%|
[blocklist_de_mail](#blocklist_de_mail)|19075|19075|69|0.3%|10.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|52|0.0%|7.8%|
[ri_web_proxies](#ri_web_proxies)|7435|7435|50|0.6%|7.5%|
[php_commenters](#php_commenters)|403|403|43|10.6%|6.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|41|0.0%|6.2%|
[stopforumspam_1d](#stopforumspam_1d)|6943|6943|34|0.4%|5.1%|
[xroxy](#xroxy)|2147|2147|32|1.4%|4.8%|
[proxz](#proxz)|1173|1173|21|1.7%|3.1%|
[blocklist_de_bots](#blocklist_de_bots)|3122|3122|19|0.6%|2.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|10|0.0%|1.5%|
[blocklist_de_strongips](#blocklist_de_strongips)|174|174|7|4.0%|1.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4256|4256|7|0.1%|1.0%|
[blocklist_de_apache](#blocklist_de_apache)|15619|15619|7|0.0%|1.0%|
[alienvault_reputation](#alienvault_reputation)|180612|180612|5|0.0%|0.7%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|4|0.0%|0.6%|
[proxyrss](#proxyrss)|1602|1602|4|0.2%|0.6%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|4|1.0%|0.6%|
[firehol_level1](#firehol_level1)|5146|688981121|4|0.0%|0.6%|
[et_tor](#et_tor)|6340|6340|4|0.0%|0.6%|
[et_block](#et_block)|999|18343755|4|0.0%|0.6%|
[dm_tor](#dm_tor)|6405|6405|4|0.0%|0.6%|
[bm_tor](#bm_tor)|6425|6425|4|0.0%|0.6%|
[ri_connect_proxies](#ri_connect_proxies)|2695|2695|3|0.1%|0.4%|
[php_harvesters](#php_harvesters)|378|378|3|0.7%|0.4%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|0.4%|
[openbl_7d](#openbl_7d)|708|708|1|0.1%|0.1%|
[openbl_60d](#openbl_60d)|7023|7023|1|0.0%|0.1%|
[openbl_30d](#openbl_30d)|2857|2857|1|0.0%|0.1%|
[openbl_1d](#openbl_1d)|161|161|1|0.6%|0.1%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|1|0.0%|0.1%|
[et_compromised](#et_compromised)|1718|1718|1|0.0%|0.1%|
[bruteforceblocker](#bruteforceblocker)|1723|1723|1|0.0%|0.1%|
[blocklist_de_ssh](#blocklist_de_ssh)|3255|3255|1|0.0%|0.1%|

## proxyrss

[proxyrss.com](http://www.proxyrss.com) open proxies syndicated from multiple sources.

Source is downloaded from [this link](http://www.proxyrss.com/proxylists/all.gz).

The last time downloaded was found to be dated: Tue Jun  9 23:11:25 UTC 2015.

The ipset `proxyrss` has **1602** entries, **1602** unique IPs.

The following table shows the overlaps of `proxyrss` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `proxyrss`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `proxyrss`.
- ` this % ` is the percentage **of this ipset (`proxyrss`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_proxies](#firehol_proxies)|11968|12206|1602|13.1%|100.0%|
[firehol_anonymous](#firehol_anonymous)|18532|82552|1602|1.9%|100.0%|
[firehol_level3](#firehol_level3)|109859|9627471|720|0.0%|44.9%|
[stopforumspam_30d](#stopforumspam_30d)|93938|93938|718|0.7%|44.8%|
[ri_web_proxies](#ri_web_proxies)|7435|7435|630|8.4%|39.3%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|605|2.0%|37.7%|
[firehol_level2](#firehol_level2)|24709|36348|418|1.1%|26.0%|
[xroxy](#xroxy)|2147|2147|377|17.5%|23.5%|
[stopforumspam_1d](#stopforumspam_1d)|6943|6943|344|4.9%|21.4%|
[proxz](#proxz)|1173|1173|265|22.5%|16.5%|
[ri_connect_proxies](#ri_connect_proxies)|2695|2695|229|8.4%|14.2%|
[blocklist_de](#blocklist_de)|30769|30769|215|0.6%|13.4%|
[blocklist_de_bots](#blocklist_de_bots)|3122|3122|214|6.8%|13.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|65|0.0%|4.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|63|0.0%|3.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|31|0.0%|1.9%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|10|1.5%|0.6%|
[nixspam](#nixspam)|23906|23906|8|0.0%|0.4%|
[snort_ipfilter](#snort_ipfilter)|10136|10136|6|0.0%|0.3%|
[blocklist_de_strongips](#blocklist_de_strongips)|174|174|5|2.8%|0.3%|
[php_spammers](#php_spammers)|661|661|4|0.6%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|3|0.0%|0.1%|
[php_dictionary](#php_dictionary)|666|666|2|0.3%|0.1%|
[php_harvesters](#php_harvesters)|378|378|1|0.2%|0.0%|
[php_commenters](#php_commenters)|403|403|1|0.2%|0.0%|
[et_compromised](#et_compromised)|1718|1718|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1723|1723|1|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|19075|19075|1|0.0%|0.0%|

## proxz

[proxz.com](http://www.proxz.com) open proxies (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.proxz.com/proxylists.xml).

The last time downloaded was found to be dated: Wed Jun 10 01:51:33 UTC 2015.

The ipset `proxz` has **1173** entries, **1173** unique IPs.

The following table shows the overlaps of `proxz` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `proxz`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `proxz`.
- ` this % ` is the percentage **of this ipset (`proxz`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_proxies](#firehol_proxies)|11968|12206|1173|9.6%|100.0%|
[firehol_anonymous](#firehol_anonymous)|18532|82552|1173|1.4%|100.0%|
[firehol_level3](#firehol_level3)|109859|9627471|704|0.0%|60.0%|
[stopforumspam_30d](#stopforumspam_30d)|93938|93938|698|0.7%|59.5%|
[ri_web_proxies](#ri_web_proxies)|7435|7435|537|7.2%|45.7%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|476|1.6%|40.5%|
[xroxy](#xroxy)|2147|2147|423|19.7%|36.0%|
[proxyrss](#proxyrss)|1602|1602|265|16.5%|22.5%|
[firehol_level2](#firehol_level2)|24709|36348|260|0.7%|22.1%|
[ri_connect_proxies](#ri_connect_proxies)|2695|2695|198|7.3%|16.8%|
[stopforumspam_1d](#stopforumspam_1d)|6943|6943|185|2.6%|15.7%|
[blocklist_de](#blocklist_de)|30769|30769|174|0.5%|14.8%|
[blocklist_de_bots](#blocklist_de_bots)|3122|3122|144|4.6%|12.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|99|0.0%|8.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|48|0.0%|4.0%|
[nixspam](#nixspam)|23906|23906|40|0.1%|3.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|40|0.0%|3.4%|
[blocklist_de_mail](#blocklist_de_mail)|19075|19075|30|0.1%|2.5%|
[php_dictionary](#php_dictionary)|666|666|23|3.4%|1.9%|
[snort_ipfilter](#snort_ipfilter)|10136|10136|21|0.2%|1.7%|
[php_spammers](#php_spammers)|661|661|21|3.1%|1.7%|
[php_commenters](#php_commenters)|403|403|7|1.7%|0.5%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|6|0.9%|0.5%|
[blocklist_de_strongips](#blocklist_de_strongips)|174|174|5|2.8%|0.4%|
[alienvault_reputation](#alienvault_reputation)|180612|180612|3|0.0%|0.2%|
[et_compromised](#et_compromised)|1718|1718|2|0.1%|0.1%|
[bruteforceblocker](#bruteforceblocker)|1723|1723|2|0.1%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|1|0.0%|0.0%|

## ri_connect_proxies

[rosinstrument.com](http://www.rosinstrument.com) open CONNECT proxies (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://tools.rosinstrument.com/proxy/plab100.xml).

The last time downloaded was found to be dated: Wed Jun 10 01:14:58 UTC 2015.

The ipset `ri_connect_proxies` has **2695** entries, **2695** unique IPs.

The following table shows the overlaps of `ri_connect_proxies` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ri_connect_proxies`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ri_connect_proxies`.
- ` this % ` is the percentage **of this ipset (`ri_connect_proxies`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_proxies](#firehol_proxies)|11968|12206|2695|22.0%|100.0%|
[firehol_anonymous](#firehol_anonymous)|18532|82552|2695|3.2%|100.0%|
[stopforumspam_30d](#stopforumspam_30d)|93938|93938|1524|1.6%|56.5%|
[firehol_level3](#firehol_level3)|109859|9627471|1524|0.0%|56.5%|
[ri_web_proxies](#ri_web_proxies)|7435|7435|1143|15.3%|42.4%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|577|1.9%|21.4%|
[xroxy](#xroxy)|2147|2147|388|18.0%|14.3%|
[proxyrss](#proxyrss)|1602|1602|229|14.2%|8.4%|
[proxz](#proxz)|1173|1173|198|16.8%|7.3%|
[firehol_level2](#firehol_level2)|24709|36348|151|0.4%|5.6%|
[stopforumspam_1d](#stopforumspam_1d)|6943|6943|108|1.5%|4.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|103|0.0%|3.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|82|0.0%|3.0%|
[blocklist_de](#blocklist_de)|30769|30769|73|0.2%|2.7%|
[blocklist_de_bots](#blocklist_de_bots)|3122|3122|69|2.2%|2.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|57|0.0%|2.1%|
[nixspam](#nixspam)|23906|23906|9|0.0%|0.3%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|7|1.0%|0.2%|
[snort_ipfilter](#snort_ipfilter)|10136|10136|5|0.0%|0.1%|
[php_commenters](#php_commenters)|403|403|5|1.2%|0.1%|
[php_dictionary](#php_dictionary)|666|666|4|0.6%|0.1%|
[blocklist_de_mail](#blocklist_de_mail)|19075|19075|4|0.0%|0.1%|
[php_spammers](#php_spammers)|661|661|3|0.4%|0.1%|
[alienvault_reputation](#alienvault_reputation)|180612|180612|3|0.0%|0.1%|
[blocklist_de_imap](#blocklist_de_imap)|2334|2334|2|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.0%|

## ri_web_proxies

[rosinstrument.com](http://www.rosinstrument.com) open HTTP proxies (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://tools.rosinstrument.com/proxy/l100.xml).

The last time downloaded was found to be dated: Wed Jun 10 01:14:51 UTC 2015.

The ipset `ri_web_proxies` has **7435** entries, **7435** unique IPs.

The following table shows the overlaps of `ri_web_proxies` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ri_web_proxies`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ri_web_proxies`.
- ` this % ` is the percentage **of this ipset (`ri_web_proxies`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_proxies](#firehol_proxies)|11968|12206|7435|60.9%|100.0%|
[firehol_anonymous](#firehol_anonymous)|18532|82552|7435|9.0%|100.0%|
[firehol_level3](#firehol_level3)|109859|9627471|3587|0.0%|48.2%|
[stopforumspam_30d](#stopforumspam_30d)|93938|93938|3539|3.7%|47.5%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|1523|5.1%|20.4%|
[ri_connect_proxies](#ri_connect_proxies)|2695|2695|1143|42.4%|15.3%|
[xroxy](#xroxy)|2147|2147|943|43.9%|12.6%|
[firehol_level2](#firehol_level2)|24709|36348|657|1.8%|8.8%|
[proxyrss](#proxyrss)|1602|1602|630|39.3%|8.4%|
[proxz](#proxz)|1173|1173|537|45.7%|7.2%|
[stopforumspam_1d](#stopforumspam_1d)|6943|6943|456|6.5%|6.1%|
[blocklist_de](#blocklist_de)|30769|30769|422|1.3%|5.6%|
[blocklist_de_bots](#blocklist_de_bots)|3122|3122|354|11.3%|4.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|218|0.0%|2.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|213|0.0%|2.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|151|0.0%|2.0%|
[nixspam](#nixspam)|23906|23906|104|0.4%|1.3%|
[blocklist_de_mail](#blocklist_de_mail)|19075|19075|62|0.3%|0.8%|
[snort_ipfilter](#snort_ipfilter)|10136|10136|60|0.5%|0.8%|
[php_dictionary](#php_dictionary)|666|666|60|9.0%|0.8%|
[php_spammers](#php_spammers)|661|661|50|7.5%|0.6%|
[php_commenters](#php_commenters)|403|403|23|5.7%|0.3%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|14|2.1%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|6|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4256|4256|6|0.1%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|15619|15619|6|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|174|174|5|2.8%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|4|1.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|4|0.0%|0.0%|
[dm_tor](#dm_tor)|6405|6405|4|0.0%|0.0%|
[bm_tor](#bm_tor)|6425|6425|4|0.0%|0.0%|
[alienvault_reputation](#alienvault_reputation)|180612|180612|4|0.0%|0.0%|
[et_tor](#et_tor)|6340|6340|3|0.0%|0.0%|
[php_harvesters](#php_harvesters)|378|378|2|0.5%|0.0%|
[sslbl](#sslbl)|376|376|1|0.2%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|1|0.0%|0.0%|
[firehol_level1](#firehol_level1)|5146|688981121|1|0.0%|0.0%|
[et_compromised](#et_compromised)|1718|1718|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1723|1723|1|0.0%|0.0%|

## shunlist

[AutoShun.org](http://autoshun.org/) IPs identified as hostile by correlating logs from distributed snort installations running the autoshun plugin

Source is downloaded from [this link](http://www.autoshun.org/files/shunlist.csv).

The last time downloaded was found to be dated: Tue Jun  9 23:30:04 UTC 2015.

The ipset `shunlist` has **1315** entries, **1315** unique IPs.

The following table shows the overlaps of `shunlist` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `shunlist`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `shunlist`.
- ` this % ` is the percentage **of this ipset (`shunlist`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level3](#firehol_level3)|109859|9627471|1315|0.0%|100.0%|
[alienvault_reputation](#alienvault_reputation)|180612|180612|1299|0.7%|98.7%|
[openbl_60d](#openbl_60d)|7023|7023|570|8.1%|43.3%|
[openbl_30d](#openbl_30d)|2857|2857|541|18.9%|41.1%|
[firehol_level2](#firehol_level2)|24709|36348|467|1.2%|35.5%|
[blocklist_de](#blocklist_de)|30769|30769|463|1.5%|35.2%|
[bruteforceblocker](#bruteforceblocker)|1723|1723|451|26.1%|34.2%|
[et_compromised](#et_compromised)|1718|1718|447|26.0%|33.9%|
[blocklist_de_ssh](#blocklist_de_ssh)|3255|3255|427|13.1%|32.4%|
[openbl_7d](#openbl_7d)|708|708|229|32.3%|17.4%|
[firehol_level1](#firehol_level1)|5146|688981121|186|0.0%|14.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|119|0.0%|9.0%|
[et_block](#et_block)|999|18343755|110|0.0%|8.3%|
[dshield](#dshield)|20|5120|98|1.9%|7.4%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|97|0.0%|7.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|75|0.0%|5.7%|
[openbl_1d](#openbl_1d)|161|161|69|42.8%|5.2%|
[sslbl](#sslbl)|376|376|64|17.0%|4.8%|
[blocklist_de_apache](#blocklist_de_apache)|15619|15619|31|0.1%|2.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|26|0.0%|1.9%|
[ciarmy](#ciarmy)|409|409|24|5.8%|1.8%|
[blocklist_de_strongips](#blocklist_de_strongips)|174|174|20|11.4%|1.5%|
[voipbl](#voipbl)|10522|10934|13|0.1%|0.9%|
[stopforumspam_30d](#stopforumspam_30d)|93938|93938|4|0.0%|0.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|0.2%|
[blocklist_de_mail](#blocklist_de_mail)|19075|19075|3|0.0%|0.2%|
[snort_ipfilter](#snort_ipfilter)|10136|10136|2|0.0%|0.1%|
[blocklist_de_sip](#blocklist_de_sip)|81|81|2|2.4%|0.1%|
[blocklist_de_imap](#blocklist_de_imap)|2334|2334|2|0.0%|0.1%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|1|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[firehol_proxies](#firehol_proxies)|11968|12206|1|0.0%|0.0%|
[firehol_anonymous](#firehol_anonymous)|18532|82552|1|0.0%|0.0%|
[et_tor](#et_tor)|6340|6340|1|0.0%|0.0%|
[dm_tor](#dm_tor)|6405|6405|1|0.0%|0.0%|
[bm_tor](#bm_tor)|6425|6425|1|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4256|4256|1|0.0%|0.0%|

## snort_ipfilter

[labs.snort.org](https://labs.snort.org/) supplied IP blacklist (this list seems to be updated frequently, but we found no information about it)

Source is downloaded from [this link](http://labs.snort.org/feeds/ip-filter.blf).

The last time downloaded was found to be dated: Tue Jun  9 16:00:00 UTC 2015.

The ipset `snort_ipfilter` has **10136** entries, **10136** unique IPs.

The following table shows the overlaps of `snort_ipfilter` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `snort_ipfilter`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `snort_ipfilter`.
- ` this % ` is the percentage **of this ipset (`snort_ipfilter`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level3](#firehol_level3)|109859|9627471|10136|0.1%|100.0%|
[firehol_anonymous](#firehol_anonymous)|18532|82552|1135|1.3%|11.1%|
[et_tor](#et_tor)|6340|6340|1062|16.7%|10.4%|
[bm_tor](#bm_tor)|6425|6425|1032|16.0%|10.1%|
[dm_tor](#dm_tor)|6405|6405|1030|16.0%|10.1%|
[stopforumspam_30d](#stopforumspam_30d)|93938|93938|806|0.8%|7.9%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|664|2.2%|6.5%|
[firehol_level2](#firehol_level2)|24709|36348|564|1.5%|5.5%|
[stopforumspam_1d](#stopforumspam_1d)|6943|6943|382|5.5%|3.7%|
[firehol_level1](#firehol_level1)|5146|688981121|299|0.0%|2.9%|
[et_block](#et_block)|999|18343755|299|0.0%|2.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|253|0.0%|2.4%|
[firehol_proxies](#firehol_proxies)|11968|12206|253|2.0%|2.4%|
[blocklist_de](#blocklist_de)|30769|30769|220|0.7%|2.1%|
[zeus](#zeus)|231|231|201|87.0%|1.9%|
[zeus_badips](#zeus_badips)|203|203|179|88.1%|1.7%|
[blocklist_de_mail](#blocklist_de_mail)|19075|19075|177|0.9%|1.7%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|171|45.9%|1.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|167|0.0%|1.6%|
[nixspam](#nixspam)|23906|23906|159|0.6%|1.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|118|0.0%|1.1%|
[alienvault_reputation](#alienvault_reputation)|180612|180612|118|0.0%|1.1%|
[php_dictionary](#php_dictionary)|666|666|83|12.4%|0.8%|
[feodo](#feodo)|104|104|81|77.8%|0.7%|
[php_spammers](#php_spammers)|661|661|78|11.8%|0.7%|
[ri_web_proxies](#ri_web_proxies)|7435|7435|60|0.8%|0.5%|
[php_commenters](#php_commenters)|403|403|59|14.6%|0.5%|
[xroxy](#xroxy)|2147|2147|36|1.6%|0.3%|
[sslbl](#sslbl)|376|376|32|8.5%|0.3%|
[openbl_60d](#openbl_60d)|7023|7023|27|0.3%|0.2%|
[blocklist_de_apache](#blocklist_de_apache)|15619|15619|25|0.1%|0.2%|
[proxz](#proxz)|1173|1173|21|1.7%|0.2%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4256|4256|21|0.4%|0.2%|
[blocklist_de_bots](#blocklist_de_bots)|3122|3122|20|0.6%|0.1%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|19|0.0%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|15|0.0%|0.1%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|13|1.0%|0.1%|
[php_harvesters](#php_harvesters)|378|378|11|2.9%|0.1%|
[palevo](#palevo)|13|13|11|84.6%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|11|0.0%|0.1%|
[blocklist_de_imap](#blocklist_de_imap)|2334|2334|9|0.3%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|6|0.0%|0.0%|
[proxyrss](#proxyrss)|1602|1602|6|0.3%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2695|2695|5|0.1%|0.0%|
[openbl_30d](#openbl_30d)|2857|2857|5|0.1%|0.0%|
[shunlist](#shunlist)|1315|1315|2|0.1%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|2|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|174|174|2|1.1%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3255|3255|2|0.0%|0.0%|
[openbl_7d](#openbl_7d)|708|708|1|0.1%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|1|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|1|0.1%|0.0%|
[et_compromised](#et_compromised)|1718|1718|1|0.0%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|172|172|1|0.5%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1723|1723|1|0.0%|0.0%|

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
[firehol_level1](#firehol_level1)|5146|688981121|18340608|2.6%|100.0%|
[et_block](#et_block)|999|18343755|18338560|99.9%|99.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|8532506|2.4%|46.5%|
[firehol_level3](#firehol_level3)|109859|9627471|6933035|72.0%|37.8%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|6932480|75.5%|37.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|2272265|0.2%|12.3%|
[fullbogons](#fullbogons)|3778|670299624|151552|0.0%|0.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|130368|0.0%|0.7%|
[alienvault_reputation](#alienvault_reputation)|180612|180612|1373|0.7%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1037|0.3%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|93938|93938|1023|1.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|512|0.1%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|294|1.0%|0.0%|
[firehol_level2](#firehol_level2)|24709|36348|273|0.7%|0.0%|
[dshield](#dshield)|20|5120|256|5.0%|0.0%|
[openbl_60d](#openbl_60d)|7023|7023|235|3.3%|0.0%|
[blocklist_de](#blocklist_de)|30769|30769|204|0.6%|0.0%|
[nixspam](#nixspam)|23906|23906|156|0.6%|0.0%|
[openbl_30d](#openbl_30d)|2857|2857|121|4.2%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3255|3255|117|3.5%|0.0%|
[et_compromised](#et_compromised)|1718|1718|101|5.8%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1723|1723|101|5.8%|0.0%|
[shunlist](#shunlist)|1315|1315|97|7.3%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6943|6943|87|1.2%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3122|3122|58|1.8%|0.0%|
[openbl_7d](#openbl_7d)|708|708|48|6.7%|0.0%|
[php_commenters](#php_commenters)|403|403|29|7.1%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|29|2.2%|0.0%|
[openbl_1d](#openbl_1d)|161|161|22|13.6%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|19075|19075|22|0.1%|0.0%|
[snort_ipfilter](#snort_ipfilter)|10136|10136|19|0.1%|0.0%|
[zeus_badips](#zeus_badips)|203|203|16|7.8%|0.0%|
[zeus](#zeus)|231|231|16|6.9%|0.0%|
[voipbl](#voipbl)|10522|10934|14|0.1%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2334|2334|12|0.5%|0.0%|
[php_dictionary](#php_dictionary)|666|666|6|0.9%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|6|0.4%|0.0%|
[firehol_anonymous](#firehol_anonymous)|18532|82552|6|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|174|174|6|3.4%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|5|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4256|4256|5|0.1%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|15619|15619|5|0.0%|0.0%|
[php_spammers](#php_spammers)|661|661|4|0.6%|0.0%|
[malc0de](#malc0de)|338|338|4|1.1%|0.0%|
[et_tor](#et_tor)|6340|6340|3|0.0%|0.0%|
[dm_tor](#dm_tor)|6405|6405|3|0.0%|0.0%|
[bm_tor](#bm_tor)|6425|6425|3|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|2|0.3%|0.0%|
[firehol_proxies](#firehol_proxies)|11968|12206|2|0.0%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|81|81|2|2.4%|0.0%|
[sslbl](#sslbl)|376|376|1|0.2%|0.0%|
[php_harvesters](#php_harvesters)|378|378|1|0.2%|0.0%|
[et_botcc](#et_botcc)|509|509|1|0.1%|0.0%|

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
[firehol_level1](#firehol_level1)|5146|688981121|487424|0.0%|100.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|270785|0.1%|55.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|98904|0.0%|20.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|33155|0.0%|6.8%|
[et_block](#et_block)|999|18343755|517|0.0%|0.1%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|512|0.0%|0.1%|
[firehol_level3](#firehol_level3)|109859|9627471|89|0.0%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|93938|93938|79|0.0%|0.0%|
[alienvault_reputation](#alienvault_reputation)|180612|180612|14|0.0%|0.0%|
[firehol_level2](#firehol_level2)|24709|36348|10|0.0%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|9|0.0%|0.0%|
[blocklist_de](#blocklist_de)|30769|30769|8|0.0%|0.0%|
[php_commenters](#php_commenters)|403|403|7|1.7%|0.0%|
[snort_ipfilter](#snort_ipfilter)|10136|10136|6|0.0%|0.0%|
[zeus_badips](#zeus_badips)|203|203|5|2.4%|0.0%|
[zeus](#zeus)|231|231|5|2.1%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|174|174|4|2.2%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3122|3122|4|0.1%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6943|6943|3|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3255|3255|2|0.0%|0.0%|
[php_harvesters](#php_harvesters)|378|378|1|0.2%|0.0%|
[openbl_60d](#openbl_60d)|7023|7023|1|0.0%|0.0%|
[openbl_30d](#openbl_30d)|2857|2857|1|0.0%|0.0%|
[nixspam](#nixspam)|23906|23906|1|0.0%|0.0%|
[malc0de](#malc0de)|338|338|1|0.2%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|172|172|1|0.5%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|19075|19075|1|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|15619|15619|1|0.0%|0.0%|

## sslbl

[Abuse.ch SSL Blacklist](https://sslbl.abuse.ch/) bad SSL traffic related to malware or botnet activities - **excellent list**

Source is downloaded from [this link](https://sslbl.abuse.ch/blacklist/sslipblacklist.csv).

The last time downloaded was found to be dated: Wed Jun 10 02:45:07 UTC 2015.

The ipset `sslbl` has **376** entries, **376** unique IPs.

The following table shows the overlaps of `sslbl` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `sslbl`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `sslbl`.
- ` this % ` is the percentage **of this ipset (`sslbl`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level1](#firehol_level1)|5146|688981121|376|0.0%|100.0%|
[firehol_level3](#firehol_level3)|109859|9627471|96|0.0%|25.5%|
[alienvault_reputation](#alienvault_reputation)|180612|180612|66|0.0%|17.5%|
[shunlist](#shunlist)|1315|1315|64|4.8%|17.0%|
[et_block](#et_block)|999|18343755|38|0.0%|10.1%|
[feodo](#feodo)|104|104|37|35.5%|9.8%|
[snort_ipfilter](#snort_ipfilter)|10136|10136|32|0.3%|8.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|28|0.0%|7.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|6|0.0%|1.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|3|0.0%|0.7%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|1|0.0%|0.2%|
[ri_web_proxies](#ri_web_proxies)|7435|7435|1|0.0%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.2%|
[firehol_proxies](#firehol_proxies)|11968|12206|1|0.0%|0.2%|
[firehol_level2](#firehol_level2)|24709|36348|1|0.0%|0.2%|
[firehol_anonymous](#firehol_anonymous)|18532|82552|1|0.0%|0.2%|
[blocklist_de_ssh](#blocklist_de_ssh)|3255|3255|1|0.0%|0.2%|
[blocklist_de](#blocklist_de)|30769|30769|1|0.0%|0.2%|

## stopforumspam_1d

[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers in the last 24 hours - **excellent list**

Source is downloaded from [this link](http://www.stopforumspam.com/downloads/listed_ip_1.zip).

The last time downloaded was found to be dated: Wed Jun 10 02:00:28 UTC 2015.

The ipset `stopforumspam_1d` has **6943** entries, **6943** unique IPs.

The following table shows the overlaps of `stopforumspam_1d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `stopforumspam_1d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `stopforumspam_1d`.
- ` this % ` is the percentage **of this ipset (`stopforumspam_1d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|24709|36348|6943|19.1%|100.0%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|6862|23.3%|98.8%|
[firehol_level3](#firehol_level3)|109859|9627471|5550|0.0%|79.9%|
[stopforumspam_30d](#stopforumspam_30d)|93938|93938|5529|5.8%|79.6%|
[blocklist_de](#blocklist_de)|30769|30769|1395|4.5%|20.0%|
[blocklist_de_bots](#blocklist_de_bots)|3122|3122|1320|42.2%|19.0%|
[firehol_anonymous](#firehol_anonymous)|18532|82552|1005|1.2%|14.4%|
[firehol_proxies](#firehol_proxies)|11968|12206|798|6.5%|11.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|513|0.0%|7.3%|
[ri_web_proxies](#ri_web_proxies)|7435|7435|456|6.1%|6.5%|
[snort_ipfilter](#snort_ipfilter)|10136|10136|382|3.7%|5.5%|
[et_tor](#et_tor)|6340|6340|348|5.4%|5.0%|
[dm_tor](#dm_tor)|6405|6405|345|5.3%|4.9%|
[proxyrss](#proxyrss)|1602|1602|344|21.4%|4.9%|
[bm_tor](#bm_tor)|6425|6425|344|5.3%|4.9%|
[xroxy](#xroxy)|2147|2147|238|11.0%|3.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|211|0.0%|3.0%|
[proxz](#proxz)|1173|1173|185|15.7%|2.6%|
[php_commenters](#php_commenters)|403|403|160|39.7%|2.3%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|151|40.5%|2.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|126|0.0%|1.8%|
[ri_connect_proxies](#ri_connect_proxies)|2695|2695|108|4.0%|1.5%|
[blocklist_de_strongips](#blocklist_de_strongips)|174|174|107|61.4%|1.5%|
[firehol_level1](#firehol_level1)|5146|688981121|89|0.0%|1.2%|
[et_block](#et_block)|999|18343755|89|0.0%|1.2%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|87|0.0%|1.2%|
[blocklist_de_apache](#blocklist_de_apache)|15619|15619|69|0.4%|0.9%|
[nixspam](#nixspam)|23906|23906|54|0.2%|0.7%|
[alienvault_reputation](#alienvault_reputation)|180612|180612|49|0.0%|0.7%|
[blocklist_de_mail](#blocklist_de_mail)|19075|19075|48|0.2%|0.6%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|40|0.0%|0.5%|
[php_harvesters](#php_harvesters)|378|378|36|9.5%|0.5%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4256|4256|36|0.8%|0.5%|
[php_spammers](#php_spammers)|661|661|34|5.1%|0.4%|
[php_dictionary](#php_dictionary)|666|666|30|4.5%|0.4%|
[openbl_60d](#openbl_60d)|7023|7023|20|0.2%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|11|0.0%|0.1%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|5|0.7%|0.0%|
[voipbl](#voipbl)|10522|10934|4|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|712|712|4|0.5%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|3|0.0%|0.0%|
[zeus_badips](#zeus_badips)|203|203|1|0.4%|0.0%|
[zeus](#zeus)|231|231|1|0.4%|0.0%|
[openbl_30d](#openbl_30d)|2857|2857|1|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|1|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|1|0.0%|0.0%|
[et_compromised](#et_compromised)|1718|1718|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1723|1723|1|0.0%|0.0%|

## stopforumspam_30d

[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 30 days)

Source is downloaded from [this link](http://www.stopforumspam.com/downloads/listed_ip_30.zip).

The last time downloaded was found to be dated: Tue Jun  9 12:00:35 UTC 2015.

The ipset `stopforumspam_30d` has **93938** entries, **93938** unique IPs.

The following table shows the overlaps of `stopforumspam_30d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `stopforumspam_30d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `stopforumspam_30d`.
- ` this % ` is the percentage **of this ipset (`stopforumspam_30d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level3](#firehol_level3)|109859|9627471|93938|0.9%|100.0%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|27990|95.4%|29.7%|
[firehol_level2](#firehol_level2)|24709|36348|6894|18.9%|7.3%|
[firehol_anonymous](#firehol_anonymous)|18532|82552|5955|7.2%|6.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|5824|0.0%|6.1%|
[stopforumspam_1d](#stopforumspam_1d)|6943|6943|5529|79.6%|5.8%|
[firehol_proxies](#firehol_proxies)|11968|12206|5305|43.4%|5.6%|
[ri_web_proxies](#ri_web_proxies)|7435|7435|3539|47.5%|3.7%|
[blocklist_de](#blocklist_de)|30769|30769|2630|8.5%|2.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|2502|0.0%|2.6%|
[blocklist_de_bots](#blocklist_de_bots)|3122|3122|2269|72.6%|2.4%|
[ri_connect_proxies](#ri_connect_proxies)|2695|2695|1524|56.5%|1.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|1519|0.0%|1.6%|
[xroxy](#xroxy)|2147|2147|1269|59.1%|1.3%|
[firehol_level1](#firehol_level1)|5146|688981121|1105|0.0%|1.1%|
[et_block](#et_block)|999|18343755|1029|0.0%|1.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|1023|0.0%|1.0%|
[snort_ipfilter](#snort_ipfilter)|10136|10136|806|7.9%|0.8%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|735|0.0%|0.7%|
[proxyrss](#proxyrss)|1602|1602|718|44.8%|0.7%|
[proxz](#proxz)|1173|1173|698|59.5%|0.7%|
[et_tor](#et_tor)|6340|6340|642|10.1%|0.6%|
[dm_tor](#dm_tor)|6405|6405|639|9.9%|0.6%|
[bm_tor](#bm_tor)|6425|6425|637|9.9%|0.6%|
[php_commenters](#php_commenters)|403|403|302|74.9%|0.3%|
[blocklist_de_mail](#blocklist_de_mail)|19075|19075|262|1.3%|0.2%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|233|62.6%|0.2%|
[blocklist_de_apache](#blocklist_de_apache)|15619|15619|219|1.4%|0.2%|
[nixspam](#nixspam)|23906|23906|207|0.8%|0.2%|
[alienvault_reputation](#alienvault_reputation)|180612|180612|205|0.1%|0.2%|
[php_spammers](#php_spammers)|661|661|138|20.8%|0.1%|
[blocklist_de_strongips](#blocklist_de_strongips)|174|174|129|74.1%|0.1%|
[php_dictionary](#php_dictionary)|666|666|126|18.9%|0.1%|
[php_harvesters](#php_harvesters)|378|378|81|21.4%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|79|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4256|4256|70|1.6%|0.0%|
[openbl_60d](#openbl_60d)|7023|7023|50|0.7%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|48|0.0%|0.0%|
[voipbl](#voipbl)|10522|10934|35|0.3%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3255|3255|19|0.5%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|18|2.7%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|13|0.0%|0.0%|
[et_compromised](#et_compromised)|1718|1718|13|0.7%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1723|1723|13|0.7%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|712|712|12|1.6%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2334|2334|8|0.3%|0.0%|
[shunlist](#shunlist)|1315|1315|4|0.3%|0.0%|
[openbl_30d](#openbl_30d)|2857|2857|4|0.1%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|4|0.3%|0.0%|
[dshield](#dshield)|20|5120|3|0.0%|0.0%|
[zeus_badips](#zeus_badips)|203|203|2|0.9%|0.0%|
[zeus](#zeus)|231|231|2|0.8%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|2|0.1%|0.0%|
[ciarmy](#ciarmy)|409|409|2|0.4%|0.0%|
[openbl_7d](#openbl_7d)|708|708|1|0.1%|0.0%|
[openbl_1d](#openbl_1d)|161|161|1|0.6%|0.0%|
[fullbogons](#fullbogons)|3778|670299624|1|0.0%|0.0%|

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
[firehol_level3](#firehol_level3)|109859|9627471|28007|0.2%|95.4%|
[stopforumspam_30d](#stopforumspam_30d)|93938|93938|27990|29.7%|95.4%|
[firehol_level2](#firehol_level2)|24709|36348|7821|21.5%|26.6%|
[stopforumspam_1d](#stopforumspam_1d)|6943|6943|6862|98.8%|23.3%|
[firehol_anonymous](#firehol_anonymous)|18532|82552|2771|3.3%|9.4%|
[firehol_proxies](#firehol_proxies)|11968|12206|2358|19.3%|8.0%|
[blocklist_de](#blocklist_de)|30769|30769|2343|7.6%|7.9%|
[blocklist_de_bots](#blocklist_de_bots)|3122|3122|2139|68.5%|7.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|1913|0.0%|6.5%|
[ri_web_proxies](#ri_web_proxies)|7435|7435|1523|20.4%|5.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|790|0.0%|2.6%|
[snort_ipfilter](#snort_ipfilter)|10136|10136|664|6.5%|2.2%|
[xroxy](#xroxy)|2147|2147|623|29.0%|2.1%|
[proxyrss](#proxyrss)|1602|1602|605|37.7%|2.0%|
[ri_connect_proxies](#ri_connect_proxies)|2695|2695|577|21.4%|1.9%|
[et_tor](#et_tor)|6340|6340|533|8.4%|1.8%|
[dm_tor](#dm_tor)|6405|6405|530|8.2%|1.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|529|0.0%|1.8%|
[bm_tor](#bm_tor)|6425|6425|529|8.2%|1.8%|
[proxz](#proxz)|1173|1173|476|40.5%|1.6%|
[firehol_level1](#firehol_level1)|5146|688981121|303|0.0%|1.0%|
[et_block](#et_block)|999|18343755|297|0.0%|1.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|294|0.0%|1.0%|
[php_commenters](#php_commenters)|403|403|225|55.8%|0.7%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|192|51.6%|0.6%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|167|0.0%|0.5%|
[blocklist_de_mail](#blocklist_de_mail)|19075|19075|144|0.7%|0.4%|
[blocklist_de_apache](#blocklist_de_apache)|15619|15619|132|0.8%|0.4%|
[nixspam](#nixspam)|23906|23906|129|0.5%|0.4%|
[blocklist_de_strongips](#blocklist_de_strongips)|174|174|116|66.6%|0.3%|
[alienvault_reputation](#alienvault_reputation)|180612|180612|103|0.0%|0.3%|
[php_dictionary](#php_dictionary)|666|666|84|12.6%|0.2%|
[php_spammers](#php_spammers)|661|661|83|12.5%|0.2%|
[php_harvesters](#php_harvesters)|378|378|60|15.8%|0.2%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4256|4256|55|1.2%|0.1%|
[openbl_60d](#openbl_60d)|7023|7023|27|0.3%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|18|0.0%|0.0%|
[voipbl](#voipbl)|10522|10934|14|0.1%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|11|1.6%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|9|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|712|712|8|1.1%|0.0%|
[et_compromised](#et_compromised)|1718|1718|5|0.2%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1723|1723|5|0.2%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3255|3255|5|0.1%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|4|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2334|2334|3|0.1%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|2|0.1%|0.0%|
[zeus_badips](#zeus_badips)|203|203|1|0.4%|0.0%|
[zeus](#zeus)|231|231|1|0.4%|0.0%|
[shunlist](#shunlist)|1315|1315|1|0.0%|0.0%|
[openbl_30d](#openbl_30d)|2857|2857|1|0.0%|0.0%|
[dshield](#dshield)|20|5120|1|0.0%|0.0%|
[ciarmy](#ciarmy)|409|409|1|0.2%|0.0%|

## virbl

[VirBL](http://virbl.bit.nl/) is a project of which the idea was born during the RIPE-48 meeting. The plan was to get reports of virusscanning mailservers, and put the IP-addresses that were reported to send viruses on a blacklist.

Source is downloaded from [this link](http://virbl.bit.nl/download/virbl.dnsbl.bit.nl.txt).

The last time downloaded was found to be dated: Wed Jun 10 02:42:03 UTC 2015.

The ipset `virbl` has **25** entries, **25** unique IPs.

The following table shows the overlaps of `virbl` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `virbl`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `virbl`.
- ` this % ` is the percentage **of this ipset (`virbl`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level3](#firehol_level3)|109859|9627471|25|0.0%|100.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|3|0.0%|12.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|2|0.0%|8.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|1|0.0%|4.0%|

## voipbl

[VoIPBL.org](http://www.voipbl.org/) a distributed VoIP blacklist that is aimed to protects against VoIP Fraud and minimizing abuse for network that have publicly accessible PBX's. Several algorithms, external sources and manual confirmation are used before they categorize something as an attack and determine the threat level.

Source is downloaded from [this link](http://www.voipbl.org/update/).

The last time downloaded was found to be dated: Wed Jun 10 02:09:23 UTC 2015.

The ipset `voipbl` has **10522** entries, **10934** unique IPs.

The following table shows the overlaps of `voipbl` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `voipbl`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `voipbl`.
- ` this % ` is the percentage **of this ipset (`voipbl`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|1602|0.0%|14.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|434|0.0%|3.9%|
[firehol_level1](#firehol_level1)|5146|688981121|333|0.0%|3.0%|
[fullbogons](#fullbogons)|3778|670299624|319|0.0%|2.9%|
[bogons](#bogons)|13|592708608|319|0.0%|2.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|299|0.0%|2.7%|
[alienvault_reputation](#alienvault_reputation)|180612|180612|192|0.1%|1.7%|
[firehol_anonymous](#firehol_anonymous)|18532|82552|78|0.0%|0.7%|
[firehol_level3](#firehol_level3)|109859|9627471|57|0.0%|0.5%|
[stopforumspam_30d](#stopforumspam_30d)|93938|93938|35|0.0%|0.3%|
[firehol_level2](#firehol_level2)|24709|36348|32|0.0%|0.2%|
[blocklist_de](#blocklist_de)|30769|30769|28|0.0%|0.2%|
[blocklist_de_sip](#blocklist_de_sip)|81|81|24|29.6%|0.2%|
[et_block](#et_block)|999|18343755|18|0.0%|0.1%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|14|0.0%|0.1%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|14|0.0%|0.1%|
[shunlist](#shunlist)|1315|1315|13|0.9%|0.1%|
[openbl_60d](#openbl_60d)|7023|7023|8|0.1%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6943|6943|4|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|4|0.0%|0.0%|
[openbl_30d](#openbl_30d)|2857|2857|3|0.1%|0.0%|
[et_tor](#et_tor)|6340|6340|3|0.0%|0.0%|
[dm_tor](#dm_tor)|6405|6405|3|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1723|1723|3|0.1%|0.0%|
[bm_tor](#bm_tor)|6425|6425|3|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|2|0.0%|0.0%|
[et_compromised](#et_compromised)|1718|1718|2|0.1%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3255|3255|2|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|15619|15619|2|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.0%|
[firehol_proxies](#firehol_proxies)|11968|12206|1|0.0%|0.0%|
[ciarmy](#ciarmy)|409|409|1|0.2%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4256|4256|1|0.0%|0.0%|

## xroxy

[xroxy.com](http://www.xroxy.com) open proxies (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.xroxy.com/proxyrss.xml).

The last time downloaded was found to be dated: Wed Jun 10 02:33:01 UTC 2015.

The ipset `xroxy` has **2147** entries, **2147** unique IPs.

The following table shows the overlaps of `xroxy` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `xroxy`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `xroxy`.
- ` this % ` is the percentage **of this ipset (`xroxy`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_proxies](#firehol_proxies)|11968|12206|2147|17.5%|100.0%|
[firehol_anonymous](#firehol_anonymous)|18532|82552|2147|2.6%|100.0%|
[firehol_level3](#firehol_level3)|109859|9627471|1283|0.0%|59.7%|
[stopforumspam_30d](#stopforumspam_30d)|93938|93938|1269|1.3%|59.1%|
[ri_web_proxies](#ri_web_proxies)|7435|7435|943|12.6%|43.9%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|623|2.1%|29.0%|
[proxz](#proxz)|1173|1173|423|36.0%|19.7%|
[ri_connect_proxies](#ri_connect_proxies)|2695|2695|388|14.3%|18.0%|
[proxyrss](#proxyrss)|1602|1602|377|23.5%|17.5%|
[firehol_level2](#firehol_level2)|24709|36348|331|0.9%|15.4%|
[stopforumspam_1d](#stopforumspam_1d)|6943|6943|238|3.4%|11.0%|
[blocklist_de](#blocklist_de)|30769|30769|205|0.6%|9.5%|
[blocklist_de_bots](#blocklist_de_bots)|3122|3122|151|4.8%|7.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|107|0.0%|4.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|104|0.0%|4.8%|
[nixspam](#nixspam)|23906|23906|64|0.2%|2.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|58|0.0%|2.7%|
[blocklist_de_mail](#blocklist_de_mail)|19075|19075|54|0.2%|2.5%|
[php_dictionary](#php_dictionary)|666|666|39|5.8%|1.8%|
[snort_ipfilter](#snort_ipfilter)|10136|10136|36|0.3%|1.6%|
[php_spammers](#php_spammers)|661|661|32|4.8%|1.4%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|13|1.9%|0.6%|
[php_commenters](#php_commenters)|403|403|8|1.9%|0.3%|
[blocklist_de_strongips](#blocklist_de_strongips)|174|174|5|2.8%|0.2%|
[alienvault_reputation](#alienvault_reputation)|180612|180612|5|0.0%|0.2%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|3|0.0%|0.1%|
[php_harvesters](#php_harvesters)|378|378|2|0.5%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.0%|
[et_tor](#et_tor)|6340|6340|1|0.0%|0.0%|
[et_compromised](#et_compromised)|1718|1718|1|0.0%|0.0%|
[et_block](#et_block)|999|18343755|1|0.0%|0.0%|
[dm_tor](#dm_tor)|6405|6405|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1723|1723|1|0.0%|0.0%|
[bm_tor](#bm_tor)|6425|6425|1|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2334|2334|1|0.0%|0.0%|

## zeus

[Abuse.ch Zeus tracker](https://zeustracker.abuse.ch) standard, contains the same data as the ZeuS IP blocklist (zeus_badips) but with the slight difference that it doesn't exclude hijacked websites (level 2) and free web hosting providers (level 3). This means that this blocklist contains all IPv4 addresses associated with ZeuS C&Cs which are currently being tracked by ZeuS Tracker. Hence this blocklist will likely cause some false positives. - **excellent list**

Source is downloaded from [this link](https://zeustracker.abuse.ch/blocklist.php?download=ipblocklist).

The last time downloaded was found to be dated: Wed Jun 10 01:22:23 UTC 2015.

The ipset `zeus` has **231** entries, **231** unique IPs.

The following table shows the overlaps of `zeus` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `zeus`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `zeus`.
- ` this % ` is the percentage **of this ipset (`zeus`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level1](#firehol_level1)|5146|688981121|231|0.0%|100.0%|
[et_block](#et_block)|999|18343755|228|0.0%|98.7%|
[firehol_level3](#firehol_level3)|109859|9627471|204|0.0%|88.3%|
[zeus_badips](#zeus_badips)|203|203|203|100.0%|87.8%|
[snort_ipfilter](#snort_ipfilter)|10136|10136|201|1.9%|87.0%|
[alienvault_reputation](#alienvault_reputation)|180612|180612|62|0.0%|26.8%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|16|0.0%|6.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|14|0.0%|6.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|10|0.0%|4.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|9|0.0%|3.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|7|0.0%|3.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|5|0.0%|2.1%|
[stopforumspam_30d](#stopforumspam_30d)|93938|93938|2|0.0%|0.8%|
[openbl_60d](#openbl_60d)|7023|7023|2|0.0%|0.8%|
[firehol_level2](#firehol_level2)|24709|36348|2|0.0%|0.8%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|1|0.0%|0.4%|
[stopforumspam_1d](#stopforumspam_1d)|6943|6943|1|0.0%|0.4%|
[php_commenters](#php_commenters)|403|403|1|0.2%|0.4%|
[openbl_30d](#openbl_30d)|2857|2857|1|0.0%|0.4%|
[nixspam](#nixspam)|23906|23906|1|0.0%|0.4%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|1|0.0%|0.4%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.4%|
[blocklist_de_mail](#blocklist_de_mail)|19075|19075|1|0.0%|0.4%|
[blocklist_de](#blocklist_de)|30769|30769|1|0.0%|0.4%|

## zeus_badips

[Abuse.ch Zeus tracker](https://zeustracker.abuse.ch) badips includes IPv4 addresses that are used by the ZeuS trojan. It is the recommened blocklist if you want to block only ZeuS IPs. It excludes IP addresses that ZeuS Tracker believes to be hijacked (level 2) or belong to a free web hosting provider (level 3). Hence the false postive rate should be much lower compared to the standard ZeuS IP blocklist. **excellent list**

Source is downloaded from [this link](https://zeustracker.abuse.ch/blocklist.php?download=badips).

The last time downloaded was found to be dated: Wed Jun 10 02:45:07 UTC 2015.

The ipset `zeus_badips` has **203** entries, **203** unique IPs.

The following table shows the overlaps of `zeus_badips` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `zeus_badips`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `zeus_badips`.
- ` this % ` is the percentage **of this ipset (`zeus_badips`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[zeus](#zeus)|231|231|203|87.8%|100.0%|
[firehol_level1](#firehol_level1)|5146|688981121|203|0.0%|100.0%|
[et_block](#et_block)|999|18343755|203|0.0%|100.0%|
[firehol_level3](#firehol_level3)|109859|9627471|181|0.0%|89.1%|
[snort_ipfilter](#snort_ipfilter)|10136|10136|179|1.7%|88.1%|
[alienvault_reputation](#alienvault_reputation)|180612|180612|38|0.0%|18.7%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|16|0.0%|7.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|10|0.0%|4.9%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|10|0.0%|4.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|8|0.0%|3.9%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|5|0.0%|2.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|4|0.0%|1.9%|
[stopforumspam_30d](#stopforumspam_30d)|93938|93938|2|0.0%|0.9%|
[firehol_level2](#firehol_level2)|24709|36348|2|0.0%|0.9%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|1|0.0%|0.4%|
[stopforumspam_1d](#stopforumspam_1d)|6943|6943|1|0.0%|0.4%|
[php_commenters](#php_commenters)|403|403|1|0.2%|0.4%|
[openbl_60d](#openbl_60d)|7023|7023|1|0.0%|0.4%|
[nixspam](#nixspam)|23906|23906|1|0.0%|0.4%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.4%|
[blocklist_de_mail](#blocklist_de_mail)|19075|19075|1|0.0%|0.4%|
[blocklist_de](#blocklist_de)|30769|30769|1|0.0%|0.4%|
