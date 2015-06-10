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

The following list was automatically generated on Wed Jun 10 14:37:17 UTC 2015.

The update frequency is the maximum allowed by internal configuration. A list will never be downloaded sooner than the update frequency stated. A list may also not be downloaded, after this frequency expired, if it has not been modified on the server (as reported by HTTP `IF_MODIFIED_SINCE` method).

name|info|type|entries|update|
:--:|:--:|:--:|:-----:|:----:|
[alienvault_reputation](#alienvault_reputation)|[AlienVault.com](https://www.alienvault.com/) IP reputation database (this list seems to include port scanning hosts and to be updated regularly, but we found no information about its retention policy)|ipv4 hash:ip|185045 unique IPs|updated every 6 hours  from [this link](https://reputation.alienvault.com/reputation.generic)
[blocklist_de](#blocklist_de)|[Blocklist.de](https://www.blocklist.de/) IPs that have been detected by fail2ban in the last 48 hours - **excellent list**|ipv4 hash:ip|29712 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/all.txt)
[blocklist_de_apache](#blocklist_de_apache)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service Apache, Apache-DDOS, RFI-Attacks.|ipv4 hash:ip|14944 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/apache.txt)
[blocklist_de_bots](#blocklist_de_bots)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the RFI-Attacks, REG-Bots, IRC-Bots or BadBots (BadBots = he has posted a Spam-Comment on a open Forum or Wiki).|ipv4 hash:ip|2981 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/bots.txt)
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|[Blocklist.de](https://www.blocklist.de/) All IPs which attacks Joomlas, Wordpress and other Web-Logins with Brute-Force Logins.|ipv4 hash:ip|3592 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/bruteforcelogin.txt)
[blocklist_de_ftp](#blocklist_de_ftp)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours for attacks on the Service FTP.|ipv4 hash:ip|1181 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/ftp.txt)
[blocklist_de_imap](#blocklist_de_imap)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours for attacks on the Service imap, sasl, pop3, etc.|ipv4 hash:ip|2407 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/imap.txt)
[blocklist_de_mail](#blocklist_de_mail)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service Mail, Postfix.|ipv4 hash:ip|18093 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/mail.txt)
[blocklist_de_sip](#blocklist_de_sip)|[Blocklist.de](https://www.blocklist.de/) All IP addresses that tried to login in a SIP, VOIP or Asterisk Server and are included in the IPs list from [infiltrated.net](www.infiltrated.net)|ipv4 hash:ip|82 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/sip.txt)
[blocklist_de_ssh](#blocklist_de_ssh)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service SSH.|ipv4 hash:ip|3507 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/ssh.txt)
[blocklist_de_strongips](#blocklist_de_strongips)|[Blocklist.de](https://www.blocklist.de/) All IPs which are older then 2 month and have more then 5.000 attacks.|ipv4 hash:ip|182 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/strongips.txt)
[bm_tor](#bm_tor)|[torstatus.blutmagie.de](https://torstatus.blutmagie.de) list of all TOR network servers|ipv4 hash:ip|6512 unique IPs|updated every 30 mins  from [this link](https://torstatus.blutmagie.de/ip_list_all.php/Tor_ip_list_ALL.csv)
[bogons](#bogons)|[Team-Cymru.org](http://www.team-cymru.org) private and reserved addresses defined by RFC 1918, RFC 5735, and RFC 6598 and netblocks that have not been allocated to a regional internet registry - **excellent list - use it only your internet interface**|ipv4 hash:net|13 subnets, 592708608 unique IPs|updated every 1 day  from [this link](http://www.team-cymru.org/Services/Bogons/bogon-bn-agg.txt)
[bruteforceblocker](#bruteforceblocker)|[danger.rulez.sk](http://danger.rulez.sk/) IPs detected by [bruteforceblocker](http://danger.rulez.sk/index.php/bruteforceblocker/) (fail2ban alternative for SSH on OpenBSD). This is an automatically generated list from users reporting failed authentication attempts. An IP seems to be included if 3 or more users report it. Its retention pocily seems 30 days.|ipv4 hash:ip|1712 unique IPs|updated every 3 hours  from [this link](http://danger.rulez.sk/projects/bruteforceblocker/blist.php)
[ciarmy](#ciarmy)|[CIArmy.com](http://ciarmy.com/) IPs with poor Rogue Packet score that have not yet been identified as malicious by the community|ipv4 hash:ip|449 unique IPs|updated every 3 hours  from [this link](http://cinsscore.com/list/ci-badguys.txt)
[cleanmx_viruses](#cleanmx_viruses)|[Clean-MX.de](http://support.clean-mx.de/clean-mx/viruses.php) IPs with viruses|ipv4 hash:ip|123 unique IPs|updated every 12 hours  from [this link](http://support.clean-mx.de/clean-mx/xmlviruses.php?sort=id%20desc&response=alive)
[dm_tor](#dm_tor)|[dan.me.uk](https://www.dan.me.uk) dynamic list of TOR exit points|ipv4 hash:ip|6507 unique IPs|updated every 30 mins  from [this link](https://www.dan.me.uk/torlist/)
[dshield](#dshield)|[DShield.org](https://dshield.org/) top 20 attacking class C (/24) subnets over the last three days - **excellent list**|ipv4 hash:net|20 subnets, 5120 unique IPs|updated every 4 hours  from [this link](http://feeds.dshield.org/block.txt)
[et_block](#et_block)|[EmergingThreats.net](http://www.emergingthreats.net/) default blacklist (at the time of writing includes spamhaus DROP, dshield and abuse.ch trackers, which are available separately too - prefer to use the direct ipsets instead of this, they seem to lag a bit in updates)|ipv4 hash:net|999 subnets, 18343755 unique IPs|updated every 12 hours  from [this link](http://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt)
[et_botcc](#et_botcc)|[EmergingThreats.net Command and Control IPs](http://doc.emergingthreats.net/bin/view/Main/BotCC) These IPs are updates every 24 hours and should be considered VERY highly reliable indications that a host is communicating with a known and active Bot or Malware command and control server - (although they say this includes abuse.ch trackers, it does not - most probably it is the shadowserver.org C&C list)|ipv4 hash:ip|509 unique IPs|updated every 12 hours  from [this link](http://rules.emergingthreats.net/fwrules/emerging-PIX-CC.rules)
[et_compromised](#et_compromised)|[EmergingThreats.net compromised hosts](http://doc.emergingthreats.net/bin/view/Main/CompromisedHost) - (this seems to be based on bruteforceblocker)|ipv4 hash:ip|1718 unique IPs|updated every 12 hours  from [this link](http://rules.emergingthreats.net/blockrules/compromised-ips.txt)
et_dshield|[EmergingThreats.net](http://www.emergingthreats.net/) dshield blocklist|ipv4 hash:net|disabled|updated every 12 hours  from [this link](http://rules.emergingthreats.net/fwrules/emerging-PIX-DSHIELD.rules)
et_spamhaus|[EmergingThreats.net](http://www.emergingthreats.net/) spamhaus blocklist|ipv4 hash:net|disabled|updated every 12 hours  from [this link](http://rules.emergingthreats.net/fwrules/emerging-PIX-DROP.rules)
[et_tor](#et_tor)|[EmergingThreats.net](http://www.emergingthreats.net/) [list](http://doc.emergingthreats.net/bin/view/Main/TorRules) of TOR network IPs|ipv4 hash:ip|6340 unique IPs|updated every 12 hours  from [this link](http://rules.emergingthreats.net/blockrules/emerging-tor.rules)
[feodo](#feodo)|[Abuse.ch Feodo tracker](https://feodotracker.abuse.ch) trojan includes IPs which are being used by Feodo (also known as Cridex or Bugat) which commits ebanking fraud - **excellent list**|ipv4 hash:ip|105 unique IPs|updated every 30 mins  from [this link](https://feodotracker.abuse.ch/blocklist/?download=ipblocklist)
[firehol_anonymous](#firehol_anonymous)|**FireHOL Anonymous** - Known anonymizing IPs. (includes: firehol_proxies anonymous bm_tor dm_tor)|ipv4 hash:net|18384 subnets, 82411 unique IPs|updated every 1 min  from [this link]()
[firehol_level1](#firehol_level1)|**FireHOL Level 1** - Maximum protection without false positives. (includes: fullbogons dshield feodo palevo sslbl zeus spamhaus_drop spamhaus_edrop)|ipv4 hash:net|5135 subnets, 688894845 unique IPs|updated every 1 min  from [this link]()
[firehol_level2](#firehol_level2)|**FireHOL Level 2** - Maximum protection from attacks took place in the last 48 hours. (includes: openbl_1d blocklist_de stopforumspam_1d)|ipv4 hash:net|23627 subnets, 35252 unique IPs|updated every 1 min  from [this link]()
[firehol_level3](#firehol_level3)|**FireHOL Level 3** - All the bad IPs in last 30 days. (includes: openbl_30d stopforumspam_30d virbl malc0de shunlist malwaredomainlist bruteforceblocker ciarmy cleanmx_viruses snort_ipfilter ib_bluetack_spyware ib_bluetack_hijacked ib_bluetack_webexploit php_commenters php_dictionary php_harvesters php_spammers)|ipv4 hash:net|110340 subnets, 9628074 unique IPs|updated every 1 min  from [this link]()
[firehol_proxies](#firehol_proxies)|**FireHOL Proxies** - Known open proxies in the last 30 days. (includes: ib_bluetack_proxies maxmind_proxy_fraud proxyrss proxz ri_connect_proxies ri_web_proxies xroxy)|ipv4 hash:net|11989 subnets, 12246 unique IPs|updated every 1 min  from [this link]()
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
[nixspam](#nixspam)|[NiX Spam](http://www.heise.de/ix/NiX-Spam-DNSBL-and-blacklist-for-download-499637.html) IP addresses that sent spam in the last hour - automatically generated entries without distinguishing open proxies from relays, dialup gateways, and so on. All IPs are removed after 12 hours if there is no spam from there.|ipv4 hash:ip|39997 unique IPs|updated every 15 mins  from [this link](http://www.dnsbl.manitu.net/download/nixspam-ip.dump.gz)
openbl|[OpenBL.org](http://www.openbl.org/) default blacklist (currently it is the same with 90 days). OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications - **excellent list**|ipv4 hash:ip|disabled|updated every 4 hours  from [this link](http://www.openbl.org/lists/base.txt)
openbl_180d|[OpenBL.org](http://www.openbl.org/) last 180 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|disabled|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_180days.txt)
[openbl_1d](#openbl_1d)|[OpenBL.org](http://www.openbl.org/) last 24 hours IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|170 unique IPs|updated every 1 hour  from [this link](http://www.openbl.org/lists/base_1days.txt)
[openbl_30d](#openbl_30d)|[OpenBL.org](http://www.openbl.org/) last 30 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|2843 unique IPs|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_30days.txt)
openbl_360d|[OpenBL.org](http://www.openbl.org/) last 360 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|disabled|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_360days.txt)
[openbl_60d](#openbl_60d)|[OpenBL.org](http://www.openbl.org/) last 60 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|7022 unique IPs|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_60days.txt)
[openbl_7d](#openbl_7d)|[OpenBL.org](http://www.openbl.org/) last 7 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|695 unique IPs|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_7days.txt)
openbl_90d|[OpenBL.org](http://www.openbl.org/) last 90 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|disabled|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_90days.txt)
openbl_all|[OpenBL.org](http://www.openbl.org/) last all IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|disabled|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_all.txt)
[palevo](#palevo)|[Abuse.ch Palevo tracker](https://palevotracker.abuse.ch) worm includes IPs which are being used as botnet C&C for the Palevo crimeware - **excellent list**|ipv4 hash:ip|13 unique IPs|updated every 30 mins  from [this link](https://palevotracker.abuse.ch/blocklists.php?download=ipblocklist)
php_bad|[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) bad web hosts (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|disabled|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=b&rss=1)
[php_commenters](#php_commenters)|[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) comment spammers (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|403 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=c&rss=1)
[php_dictionary](#php_dictionary)|[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) directory attackers (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|702 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=d&rss=1)
[php_harvesters](#php_harvesters)|[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) harvesters (IPs that surf the internet looking for email addresses) (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|378 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=h&rss=1)
[php_spammers](#php_spammers)|[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) spam servers (IPs used by spammers to send messages) (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|700 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=s&rss=1)
[proxyrss](#proxyrss)|[proxyrss.com](http://www.proxyrss.com) open proxies syndicated from multiple sources.|ipv4 hash:ip|1299 unique IPs|updated every 4 hours  from [this link](http://www.proxyrss.com/proxylists/all.gz)
[proxz](#proxz)|[proxz.com](http://www.proxz.com) open proxies (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|1212 unique IPs|updated every 1 hour  from [this link](http://www.proxz.com/proxylists.xml)
[ri_connect_proxies](#ri_connect_proxies)|[rosinstrument.com](http://www.rosinstrument.com) open CONNECT proxies (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|2724 unique IPs|updated every 1 hour  from [this link](http://tools.rosinstrument.com/proxy/plab100.xml)
[ri_web_proxies](#ri_web_proxies)|[rosinstrument.com](http://www.rosinstrument.com) open HTTP proxies (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|7539 unique IPs|updated every 1 hour  from [this link](http://tools.rosinstrument.com/proxy/l100.xml)
[shunlist](#shunlist)|[AutoShun.org](http://autoshun.org/) IPs identified as hostile by correlating logs from distributed snort installations running the autoshun plugin|ipv4 hash:ip|1344 unique IPs|updated every 4 hours  from [this link](http://www.autoshun.org/files/shunlist.csv)
[snort_ipfilter](#snort_ipfilter)|[labs.snort.org](https://labs.snort.org/) supplied IP blacklist (this list seems to be updated frequently, but we found no information about it)|ipv4 hash:ip|10254 unique IPs|updated every 12 hours  from [this link](http://labs.snort.org/feeds/ip-filter.blf)
[spamhaus_drop](#spamhaus_drop)|[Spamhaus.org](http://www.spamhaus.org) DROP list (according to their site this list should be dropped at tier-1 ISPs globaly) - **excellent list**|ipv4 hash:net|653 subnets, 18340608 unique IPs|updated every 12 hours  from [this link](http://www.spamhaus.org/drop/drop.txt)
[spamhaus_edrop](#spamhaus_edrop)|[Spamhaus.org](http://www.spamhaus.org) EDROP (extended matches that should be used with DROP) - **excellent list**|ipv4 hash:net|56 subnets, 487424 unique IPs|updated every 12 hours  from [this link](http://www.spamhaus.org/drop/edrop.txt)
[sslbl](#sslbl)|[Abuse.ch SSL Blacklist](https://sslbl.abuse.ch/) bad SSL traffic related to malware or botnet activities - **excellent list**|ipv4 hash:ip|372 unique IPs|updated every 30 mins  from [this link](https://sslbl.abuse.ch/blacklist/sslipblacklist.csv)
stopforumspam_180d|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 180 days)|ipv4 hash:ip|disabled|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/listed_ip_180.zip)
[stopforumspam_1d](#stopforumspam_1d)|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers in the last 24 hours - **excellent list**|ipv4 hash:ip|6892 unique IPs|updated every 1 hour  from [this link](http://www.stopforumspam.com/downloads/listed_ip_1.zip)
[stopforumspam_30d](#stopforumspam_30d)|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 30 days)|ipv4 hash:ip|94424 unique IPs|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/listed_ip_30.zip)
stopforumspam_365d|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 365 days)|ipv4 hash:ip|disabled|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/listed_ip_365.zip)
[stopforumspam_7d](#stopforumspam_7d)|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 7 days)|ipv4 hash:ip|29338 unique IPs|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/listed_ip_7.zip)
stopforumspam_90d|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 90 days)|ipv4 hash:ip|disabled|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/listed_ip_90.zip)
stopforumspam_ever|[StopForumSpam.com](http://www.stopforumspam.com) all IPs used by forum spammers, **ever** (normally you don't want to use this ipset, use the hourly one which includes last 24 hours IPs or the 7 days one)|ipv4 hash:ip|disabled|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/bannedips.zip)
[virbl](#virbl)|[VirBL](http://virbl.bit.nl/) is a project of which the idea was born during the RIPE-48 meeting. The plan was to get reports of virusscanning mailservers, and put the IP-addresses that were reported to send viruses on a blacklist.|ipv4 hash:ip|20 unique IPs|updated every 1 hour  from [this link](http://virbl.bit.nl/download/virbl.dnsbl.bit.nl.txt)
[voipbl](#voipbl)|[VoIPBL.org](http://www.voipbl.org/) a distributed VoIP blacklist that is aimed to protects against VoIP Fraud and minimizing abuse for network that have publicly accessible PBX's. Several algorithms, external sources and manual confirmation are used before they categorize something as an attack and determine the threat level.|ipv4 hash:net|10533 subnets, 10945 unique IPs|updated every 4 hours  from [this link](http://www.voipbl.org/update/)
[xroxy](#xroxy)|[xroxy.com](http://www.xroxy.com) open proxies (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|2151 unique IPs|updated every 1 hour  from [this link](http://www.xroxy.com/proxyrss.xml)
[zeus](#zeus)|[Abuse.ch Zeus tracker](https://zeustracker.abuse.ch) standard, contains the same data as the ZeuS IP blocklist (zeus_badips) but with the slight difference that it doesn't exclude hijacked websites (level 2) and free web hosting providers (level 3). This means that this blocklist contains all IPv4 addresses associated with ZeuS C&Cs which are currently being tracked by ZeuS Tracker. Hence this blocklist will likely cause some false positives. - **excellent list**|ipv4 hash:ip|230 unique IPs|updated every 30 mins  from [this link](https://zeustracker.abuse.ch/blocklist.php?download=ipblocklist)
[zeus_badips](#zeus_badips)|[Abuse.ch Zeus tracker](https://zeustracker.abuse.ch) badips includes IPv4 addresses that are used by the ZeuS trojan. It is the recommened blocklist if you want to block only ZeuS IPs. It excludes IP addresses that ZeuS Tracker believes to be hijacked (level 2) or belong to a free web hosting provider (level 3). Hence the false postive rate should be much lower compared to the standard ZeuS IP blocklist. **excellent list**|ipv4 hash:ip|202 unique IPs|updated every 30 mins  from [this link](https://zeustracker.abuse.ch/blocklist.php?download=badips)

# Comparison of ipsets

Below we compare each ipset against all other.


## alienvault_reputation

[AlienVault.com](https://www.alienvault.com/) IP reputation database (this list seems to include port scanning hosts and to be updated regularly, but we found no information about its retention policy)

Source is downloaded from [this link](https://reputation.alienvault.com/reputation.generic).

The last time downloaded was found to be dated: Wed Jun 10 10:00:40 UTC 2015.

The ipset `alienvault_reputation` has **185045** entries, **185045** unique IPs.

The following table shows the overlaps of `alienvault_reputation` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `alienvault_reputation`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `alienvault_reputation`.
- ` this % ` is the percentage **of this ipset (`alienvault_reputation`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|13882|0.0%|7.5%|
[openbl_60d](#openbl_60d)|7022|7022|6998|99.6%|3.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|6261|0.0%|3.3%|
[et_block](#et_block)|999|18343755|6045|0.0%|3.2%|
[firehol_level3](#firehol_level3)|110340|9628074|5234|0.0%|2.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|4218|0.0%|2.2%|
[firehol_level1](#firehol_level1)|5135|688894845|4078|0.0%|2.2%|
[openbl_30d](#openbl_30d)|2843|2843|2825|99.3%|1.5%|
[dshield](#dshield)|20|5120|2564|50.0%|1.3%|
[firehol_level2](#firehol_level2)|23627|35252|1440|4.0%|0.7%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|1373|0.0%|0.7%|
[blocklist_de](#blocklist_de)|29712|29712|1368|4.6%|0.7%|
[shunlist](#shunlist)|1344|1344|1336|99.4%|0.7%|
[blocklist_de_ssh](#blocklist_de_ssh)|3507|3507|1150|32.7%|0.6%|
[et_compromised](#et_compromised)|1718|1718|1111|64.6%|0.6%|
[bruteforceblocker](#bruteforceblocker)|1712|1712|1098|64.1%|0.5%|
[openbl_7d](#openbl_7d)|695|695|689|99.1%|0.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|518|0.0%|0.2%|
[ciarmy](#ciarmy)|449|449|437|97.3%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|289|0.0%|0.1%|
[stopforumspam_30d](#stopforumspam_30d)|94424|94424|205|0.2%|0.1%|
[voipbl](#voipbl)|10533|10945|193|1.7%|0.1%|
[openbl_1d](#openbl_1d)|170|170|162|95.2%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14944|14944|125|0.8%|0.0%|
[snort_ipfilter](#snort_ipfilter)|10254|10254|116|1.1%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|103|0.3%|0.0%|
[sslbl](#sslbl)|372|372|66|17.7%|0.0%|
[zeus](#zeus)|230|230|61|26.5%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|18093|18093|59|0.3%|0.0%|
[firehol_anonymous](#firehol_anonymous)|18384|82411|56|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6892|6892|48|0.6%|0.0%|
[dm_tor](#dm_tor)|6507|6507|40|0.6%|0.0%|
[bm_tor](#bm_tor)|6512|6512|40|0.6%|0.0%|
[et_tor](#et_tor)|6340|6340|39|0.6%|0.0%|
[firehol_proxies](#firehol_proxies)|11989|12246|38|0.3%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2407|2407|38|1.5%|0.0%|
[zeus_badips](#zeus_badips)|202|202|37|18.3%|0.0%|
[nixspam](#nixspam)|39997|39997|35|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|182|182|35|19.2%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|30|5.7%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|82|82|19|23.1%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|3592|3592|19|0.5%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|2981|2981|19|0.6%|0.0%|
[php_commenters](#php_commenters)|403|403|18|4.4%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|15|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|14|0.0%|0.0%|
[php_harvesters](#php_harvesters)|378|378|12|3.1%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|1181|1181|11|0.9%|0.0%|
[malc0de](#malc0de)|313|313|10|3.1%|0.0%|
[php_dictionary](#php_dictionary)|702|702|9|1.2%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|8|0.6%|0.0%|
[php_spammers](#php_spammers)|700|700|6|0.8%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|6|0.4%|0.0%|
[xroxy](#xroxy)|2151|2151|5|0.2%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7539|7539|4|0.0%|0.0%|
[et_botcc](#et_botcc)|509|509|4|0.7%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2724|2724|3|0.1%|0.0%|
[proxz](#proxz)|1212|1212|3|0.2%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|123|123|3|2.4%|0.0%|
[proxyrss](#proxyrss)|1299|1299|2|0.1%|0.0%|
[feodo](#feodo)|105|105|2|1.9%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|1|0.1%|0.0%|

## blocklist_de

[Blocklist.de](https://www.blocklist.de/) IPs that have been detected by fail2ban in the last 48 hours - **excellent list**

Source is downloaded from [this link](http://lists.blocklist.de/lists/all.txt).

The last time downloaded was found to be dated: Wed Jun 10 14:30:08 UTC 2015.

The ipset `blocklist_de` has **29712** entries, **29712** unique IPs.

The following table shows the overlaps of `blocklist_de` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de`.
- ` this % ` is the percentage **of this ipset (`blocklist_de`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|23627|35252|29712|84.2%|100.0%|
[blocklist_de_mail](#blocklist_de_mail)|18093|18093|18051|99.7%|60.7%|
[blocklist_de_apache](#blocklist_de_apache)|14944|14944|14944|100.0%|50.2%|
[firehol_level3](#firehol_level3)|110340|9628074|4009|0.0%|13.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|3751|0.0%|12.6%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|3592|3592|3592|100.0%|12.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3507|3507|3503|99.8%|11.7%|
[blocklist_de_bots](#blocklist_de_bots)|2981|2981|2966|99.4%|9.9%|
[stopforumspam_30d](#stopforumspam_30d)|94424|94424|2739|2.9%|9.2%|
[blocklist_de_imap](#blocklist_de_imap)|2407|2407|2407|100.0%|8.1%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|2217|7.5%|7.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|1592|0.0%|5.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|1542|0.0%|5.1%|
[stopforumspam_1d](#stopforumspam_1d)|6892|6892|1392|20.1%|4.6%|
[alienvault_reputation](#alienvault_reputation)|185045|185045|1368|0.7%|4.6%|
[blocklist_de_ftp](#blocklist_de_ftp)|1181|1181|1181|100.0%|3.9%|
[openbl_60d](#openbl_60d)|7022|7022|986|14.0%|3.3%|
[nixspam](#nixspam)|39997|39997|983|2.4%|3.3%|
[openbl_30d](#openbl_30d)|2843|2843|785|27.6%|2.6%|
[bruteforceblocker](#bruteforceblocker)|1712|1712|661|38.6%|2.2%|
[et_compromised](#et_compromised)|1718|1718|635|36.9%|2.1%|
[firehol_anonymous](#firehol_anonymous)|18384|82411|617|0.7%|2.0%|
[firehol_proxies](#firehol_proxies)|11989|12246|603|4.9%|2.0%|
[shunlist](#shunlist)|1344|1344|452|33.6%|1.5%|
[ri_web_proxies](#ri_web_proxies)|7539|7539|426|5.6%|1.4%|
[openbl_7d](#openbl_7d)|695|695|386|55.5%|1.2%|
[firehol_level1](#firehol_level1)|5135|688894845|237|0.0%|0.7%|
[et_block](#et_block)|999|18343755|225|0.0%|0.7%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|215|0.0%|0.7%|
[proxyrss](#proxyrss)|1299|1299|215|16.5%|0.7%|
[snort_ipfilter](#snort_ipfilter)|10254|10254|213|2.0%|0.7%|
[xroxy](#xroxy)|2151|2151|196|9.1%|0.6%|
[blocklist_de_strongips](#blocklist_de_strongips)|182|182|182|100.0%|0.6%|
[proxz](#proxz)|1212|1212|175|14.4%|0.5%|
[openbl_1d](#openbl_1d)|170|170|130|76.4%|0.4%|
[php_dictionary](#php_dictionary)|702|702|107|15.2%|0.3%|
[php_spammers](#php_spammers)|700|700|101|14.4%|0.3%|
[php_commenters](#php_commenters)|403|403|99|24.5%|0.3%|
[ri_connect_proxies](#ri_connect_proxies)|2724|2724|78|2.8%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|64|0.0%|0.2%|
[blocklist_de_sip](#blocklist_de_sip)|82|82|62|75.6%|0.2%|
[ciarmy](#ciarmy)|449|449|42|9.3%|0.1%|
[php_harvesters](#php_harvesters)|378|378|36|9.5%|0.1%|
[voipbl](#voipbl)|10533|10945|31|0.2%|0.1%|
[dshield](#dshield)|20|5120|16|0.3%|0.0%|
[dm_tor](#dm_tor)|6507|6507|12|0.1%|0.0%|
[bm_tor](#bm_tor)|6512|6512|12|0.1%|0.0%|
[et_tor](#et_tor)|6340|6340|11|0.1%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|9|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|8|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|7|1.3%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|6|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|4|0.6%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|2|0.1%|0.0%|
[zeus_badips](#zeus_badips)|202|202|1|0.4%|0.0%|
[zeus](#zeus)|230|230|1|0.4%|0.0%|

## blocklist_de_apache

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service Apache, Apache-DDOS, RFI-Attacks.

Source is downloaded from [this link](http://lists.blocklist.de/lists/apache.txt).

The last time downloaded was found to be dated: Wed Jun 10 14:30:12 UTC 2015.

The ipset `blocklist_de_apache` has **14944** entries, **14944** unique IPs.

The following table shows the overlaps of `blocklist_de_apache` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_apache`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_apache`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_apache`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|23627|35252|14944|42.3%|100.0%|
[blocklist_de](#blocklist_de)|29712|29712|14944|50.2%|100.0%|
[blocklist_de_mail](#blocklist_de_mail)|18093|18093|11059|61.1%|74.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|3592|3592|3591|99.9%|24.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|2350|0.0%|15.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|1332|0.0%|8.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|1103|0.0%|7.3%|
[firehol_level3](#firehol_level3)|110340|9628074|313|0.0%|2.0%|
[stopforumspam_30d](#stopforumspam_30d)|94424|94424|229|0.2%|1.5%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|139|0.4%|0.9%|
[alienvault_reputation](#alienvault_reputation)|185045|185045|125|0.0%|0.8%|
[stopforumspam_1d](#stopforumspam_1d)|6892|6892|76|1.1%|0.5%|
[shunlist](#shunlist)|1344|1344|36|2.6%|0.2%|
[ciarmy](#ciarmy)|449|449|33|7.3%|0.2%|
[blocklist_de_strongips](#blocklist_de_strongips)|182|182|33|18.1%|0.2%|
[php_commenters](#php_commenters)|403|403|30|7.4%|0.2%|
[snort_ipfilter](#snort_ipfilter)|10254|10254|29|0.2%|0.1%|
[blocklist_de_bots](#blocklist_de_bots)|2981|2981|21|0.7%|0.1%|
[nixspam](#nixspam)|39997|39997|19|0.0%|0.1%|
[firehol_anonymous](#firehol_anonymous)|18384|82411|17|0.0%|0.1%|
[dm_tor](#dm_tor)|6507|6507|11|0.1%|0.0%|
[bm_tor](#bm_tor)|6512|6512|11|0.1%|0.0%|
[et_tor](#et_tor)|6340|6340|10|0.1%|0.0%|
[firehol_level1](#firehol_level1)|5135|688894845|8|0.0%|0.0%|
[et_block](#et_block)|999|18343755|8|0.0%|0.0%|
[php_spammers](#php_spammers)|700|700|7|1.0%|0.0%|
[firehol_proxies](#firehol_proxies)|11989|12246|7|0.0%|0.0%|
[openbl_60d](#openbl_60d)|7022|7022|6|0.0%|0.0%|
[openbl_30d](#openbl_30d)|2843|2843|6|0.2%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|5|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7539|7539|5|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|5|0.0%|0.0%|
[php_dictionary](#php_dictionary)|702|702|4|0.5%|0.0%|
[openbl_7d](#openbl_7d)|695|695|4|0.5%|0.0%|
[openbl_1d](#openbl_1d)|170|170|4|2.3%|0.0%|
[php_harvesters](#php_harvesters)|378|378|3|0.7%|0.0%|
[dshield](#dshield)|20|5120|3|0.0%|0.0%|
[voipbl](#voipbl)|10533|10945|2|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|2|0.3%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|1|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2407|2407|1|0.0%|0.0%|

## blocklist_de_bots

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the RFI-Attacks, REG-Bots, IRC-Bots or BadBots (BadBots = he has posted a Spam-Comment on a open Forum or Wiki).

Source is downloaded from [this link](http://lists.blocklist.de/lists/bots.txt).

The last time downloaded was found to be dated: Wed Jun 10 14:10:08 UTC 2015.

The ipset `blocklist_de_bots` has **2981** entries, **2981** unique IPs.

The following table shows the overlaps of `blocklist_de_bots` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_bots`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_bots`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_bots`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|23627|35252|2966|8.4%|99.4%|
[blocklist_de](#blocklist_de)|29712|29712|2966|9.9%|99.4%|
[firehol_level3](#firehol_level3)|110340|9628074|2397|0.0%|80.4%|
[stopforumspam_30d](#stopforumspam_30d)|94424|94424|2360|2.4%|79.1%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|2008|6.8%|67.3%|
[stopforumspam_1d](#stopforumspam_1d)|6892|6892|1316|19.0%|44.1%|
[firehol_anonymous](#firehol_anonymous)|18384|82411|491|0.5%|16.4%|
[firehol_proxies](#firehol_proxies)|11989|12246|490|4.0%|16.4%|
[ri_web_proxies](#ri_web_proxies)|7539|7539|349|4.6%|11.7%|
[proxyrss](#proxyrss)|1299|1299|211|16.2%|7.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|168|0.0%|5.6%|
[xroxy](#xroxy)|2151|2151|145|6.7%|4.8%|
[proxz](#proxz)|1212|1212|145|11.9%|4.8%|
[blocklist_de_strongips](#blocklist_de_strongips)|182|182|136|74.7%|4.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|89|0.0%|2.9%|
[php_commenters](#php_commenters)|403|403|80|19.8%|2.6%|
[ri_connect_proxies](#ri_connect_proxies)|2724|2724|74|2.7%|2.4%|
[firehol_level1](#firehol_level1)|5135|688894845|61|0.0%|2.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|57|0.0%|1.9%|
[et_block](#et_block)|999|18343755|57|0.0%|1.9%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|55|0.0%|1.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|30|0.0%|1.0%|
[php_harvesters](#php_harvesters)|378|378|26|6.8%|0.8%|
[snort_ipfilter](#snort_ipfilter)|10254|10254|24|0.2%|0.8%|
[php_spammers](#php_spammers)|700|700|24|3.4%|0.8%|
[nixspam](#nixspam)|39997|39997|21|0.0%|0.7%|
[blocklist_de_mail](#blocklist_de_mail)|18093|18093|21|0.1%|0.7%|
[blocklist_de_apache](#blocklist_de_apache)|14944|14944|21|0.1%|0.7%|
[php_dictionary](#php_dictionary)|702|702|20|2.8%|0.6%|
[alienvault_reputation](#alienvault_reputation)|185045|185045|19|0.0%|0.6%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|5|0.0%|0.1%|
[openbl_60d](#openbl_60d)|7022|7022|4|0.0%|0.1%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|4|0.7%|0.1%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|3|0.4%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|2|0.0%|0.0%|
[openbl_30d](#openbl_30d)|2843|2843|1|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|1|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|1|0.0%|0.0%|
[et_compromised](#et_compromised)|1718|1718|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1712|1712|1|0.0%|0.0%|

## blocklist_de_bruteforce

[Blocklist.de](https://www.blocklist.de/) All IPs which attacks Joomlas, Wordpress and other Web-Logins with Brute-Force Logins.

Source is downloaded from [this link](http://lists.blocklist.de/lists/bruteforcelogin.txt).

The last time downloaded was found to be dated: Wed Jun 10 14:14:13 UTC 2015.

The ipset `blocklist_de_bruteforce` has **3592** entries, **3592** unique IPs.

The following table shows the overlaps of `blocklist_de_bruteforce` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_bruteforce`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_bruteforce`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_bruteforce`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|23627|35252|3592|10.1%|100.0%|
[blocklist_de](#blocklist_de)|29712|29712|3592|12.0%|100.0%|
[blocklist_de_apache](#blocklist_de_apache)|14944|14944|3591|24.0%|99.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|263|0.0%|7.3%|
[firehol_level3](#firehol_level3)|110340|9628074|108|0.0%|3.0%|
[stopforumspam_30d](#stopforumspam_30d)|94424|94424|87|0.0%|2.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|71|0.0%|1.9%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|64|0.2%|1.7%|
[stopforumspam_1d](#stopforumspam_1d)|6892|6892|43|0.6%|1.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|42|0.0%|1.1%|
[snort_ipfilter](#snort_ipfilter)|10254|10254|25|0.2%|0.6%|
[nixspam](#nixspam)|39997|39997|19|0.0%|0.5%|
[alienvault_reputation](#alienvault_reputation)|185045|185045|19|0.0%|0.5%|
[firehol_anonymous](#firehol_anonymous)|18384|82411|15|0.0%|0.4%|
[php_commenters](#php_commenters)|403|403|10|2.4%|0.2%|
[et_tor](#et_tor)|6340|6340|9|0.1%|0.2%|
[dm_tor](#dm_tor)|6507|6507|9|0.1%|0.2%|
[bm_tor](#bm_tor)|6512|6512|9|0.1%|0.2%|
[blocklist_de_strongips](#blocklist_de_strongips)|182|182|9|4.9%|0.2%|
[php_spammers](#php_spammers)|700|700|7|1.0%|0.1%|
[firehol_proxies](#firehol_proxies)|11989|12246|6|0.0%|0.1%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|5|0.0%|0.1%|
[ri_web_proxies](#ri_web_proxies)|7539|7539|5|0.0%|0.1%|
[firehol_level1](#firehol_level1)|5135|688894845|5|0.0%|0.1%|
[et_block](#et_block)|999|18343755|5|0.0%|0.1%|
[php_dictionary](#php_dictionary)|702|702|4|0.5%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|4|0.0%|0.1%|
[php_harvesters](#php_harvesters)|378|378|2|0.5%|0.0%|
[voipbl](#voipbl)|10533|10945|1|0.0%|0.0%|
[shunlist](#shunlist)|1344|1344|1|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|1|0.1%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|1|0.0%|0.0%|

## blocklist_de_ftp

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours for attacks on the Service FTP.

Source is downloaded from [this link](http://lists.blocklist.de/lists/ftp.txt).

The last time downloaded was found to be dated: Wed Jun 10 14:30:13 UTC 2015.

The ipset `blocklist_de_ftp` has **1181** entries, **1181** unique IPs.

The following table shows the overlaps of `blocklist_de_ftp` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_ftp`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_ftp`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_ftp`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|23627|35252|1181|3.3%|100.0%|
[blocklist_de](#blocklist_de)|29712|29712|1181|3.9%|100.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|140|0.0%|11.8%|
[firehol_level3](#firehol_level3)|110340|9628074|25|0.0%|2.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|18|0.0%|1.5%|
[stopforumspam_30d](#stopforumspam_30d)|94424|94424|17|0.0%|1.4%|
[alienvault_reputation](#alienvault_reputation)|185045|185045|11|0.0%|0.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|10|0.0%|0.8%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|7|0.0%|0.5%|
[nixspam](#nixspam)|39997|39997|7|0.0%|0.5%|
[stopforumspam_1d](#stopforumspam_1d)|6892|6892|3|0.0%|0.2%|
[php_harvesters](#php_harvesters)|378|378|3|0.7%|0.2%|
[ciarmy](#ciarmy)|449|449|3|0.6%|0.2%|
[openbl_60d](#openbl_60d)|7022|7022|2|0.0%|0.1%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|2|0.0%|0.1%|
[firehol_anonymous](#firehol_anonymous)|18384|82411|2|0.0%|0.1%|
[blocklist_de_strongips](#blocklist_de_strongips)|182|182|2|1.0%|0.1%|
[openbl_7d](#openbl_7d)|695|695|1|0.1%|0.0%|
[openbl_30d](#openbl_30d)|2843|2843|1|0.0%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|18093|18093|1|0.0%|0.0%|

## blocklist_de_imap

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours for attacks on the Service imap, sasl, pop3, etc.

Source is downloaded from [this link](http://lists.blocklist.de/lists/imap.txt).

The last time downloaded was found to be dated: Wed Jun 10 14:30:13 UTC 2015.

The ipset `blocklist_de_imap` has **2407** entries, **2407** unique IPs.

The following table shows the overlaps of `blocklist_de_imap` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_imap`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_imap`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_imap`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|23627|35252|2407|6.8%|100.0%|
[blocklist_de](#blocklist_de)|29712|29712|2407|8.1%|100.0%|
[blocklist_de_mail](#blocklist_de_mail)|18093|18093|2389|13.2%|99.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|293|0.0%|12.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|53|0.0%|2.2%|
[firehol_level3](#firehol_level3)|110340|9628074|46|0.0%|1.9%|
[alienvault_reputation](#alienvault_reputation)|185045|185045|38|0.0%|1.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|29|0.0%|1.2%|
[openbl_60d](#openbl_60d)|7022|7022|26|0.3%|1.0%|
[openbl_30d](#openbl_30d)|2843|2843|21|0.7%|0.8%|
[nixspam](#nixspam)|39997|39997|14|0.0%|0.5%|
[stopforumspam_30d](#stopforumspam_30d)|94424|94424|12|0.0%|0.4%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|11|0.0%|0.4%|
[firehol_level1](#firehol_level1)|5135|688894845|11|0.0%|0.4%|
[et_block](#et_block)|999|18343755|11|0.0%|0.4%|
[snort_ipfilter](#snort_ipfilter)|10254|10254|7|0.0%|0.2%|
[openbl_7d](#openbl_7d)|695|695|7|1.0%|0.2%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|3|0.0%|0.1%|
[shunlist](#shunlist)|1344|1344|3|0.2%|0.1%|
[et_compromised](#et_compromised)|1718|1718|3|0.1%|0.1%|
[ciarmy](#ciarmy)|449|449|3|0.6%|0.1%|
[bruteforceblocker](#bruteforceblocker)|1712|1712|3|0.1%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2|0.0%|0.0%|
[xroxy](#xroxy)|2151|2151|1|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2724|2724|1|0.0%|0.0%|
[php_harvesters](#php_harvesters)|378|378|1|0.2%|0.0%|
[php_commenters](#php_commenters)|403|403|1|0.2%|0.0%|
[openbl_1d](#openbl_1d)|170|170|1|0.5%|0.0%|
[firehol_proxies](#firehol_proxies)|11989|12246|1|0.0%|0.0%|
[firehol_anonymous](#firehol_anonymous)|18384|82411|1|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14944|14944|1|0.0%|0.0%|

## blocklist_de_mail

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service Mail, Postfix.

Source is downloaded from [this link](http://lists.blocklist.de/lists/mail.txt).

The last time downloaded was found to be dated: Wed Jun 10 14:14:07 UTC 2015.

The ipset `blocklist_de_mail` has **18093** entries, **18093** unique IPs.

The following table shows the overlaps of `blocklist_de_mail` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_mail`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_mail`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_mail`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|23627|35252|18051|51.2%|99.7%|
[blocklist_de](#blocklist_de)|29712|29712|18051|60.7%|99.7%|
[blocklist_de_apache](#blocklist_de_apache)|14944|14944|11059|74.0%|61.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|2638|0.0%|14.5%|
[blocklist_de_imap](#blocklist_de_imap)|2407|2407|2389|99.2%|13.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|1389|0.0%|7.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|1263|0.0%|6.9%|
[nixspam](#nixspam)|39997|39997|919|2.2%|5.0%|
[firehol_level3](#firehol_level3)|110340|9628074|407|0.0%|2.2%|
[stopforumspam_30d](#stopforumspam_30d)|94424|94424|251|0.2%|1.3%|
[snort_ipfilter](#snort_ipfilter)|10254|10254|163|1.5%|0.9%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|139|0.4%|0.7%|
[firehol_anonymous](#firehol_anonymous)|18384|82411|104|0.1%|0.5%|
[firehol_proxies](#firehol_proxies)|11989|12246|103|0.8%|0.5%|
[php_dictionary](#php_dictionary)|702|702|83|11.8%|0.4%|
[php_spammers](#php_spammers)|700|700|69|9.8%|0.3%|
[ri_web_proxies](#ri_web_proxies)|7539|7539|68|0.9%|0.3%|
[alienvault_reputation](#alienvault_reputation)|185045|185045|59|0.0%|0.3%|
[xroxy](#xroxy)|2151|2151|51|2.3%|0.2%|
[stopforumspam_1d](#stopforumspam_1d)|6892|6892|39|0.5%|0.2%|
[openbl_60d](#openbl_60d)|7022|7022|34|0.4%|0.1%|
[proxz](#proxz)|1212|1212|27|2.2%|0.1%|
[openbl_30d](#openbl_30d)|2843|2843|27|0.9%|0.1%|
[php_commenters](#php_commenters)|403|403|26|6.4%|0.1%|
[blocklist_de_strongips](#blocklist_de_strongips)|182|182|21|11.5%|0.1%|
[blocklist_de_bots](#blocklist_de_bots)|2981|2981|21|0.7%|0.1%|
[firehol_level1](#firehol_level1)|5135|688894845|20|0.0%|0.1%|
[et_block](#et_block)|999|18343755|20|0.0%|0.1%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|19|0.0%|0.1%|
[openbl_7d](#openbl_7d)|695|695|7|1.0%|0.0%|
[php_harvesters](#php_harvesters)|378|378|5|1.3%|0.0%|
[et_compromised](#et_compromised)|1718|1718|4|0.2%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1712|1712|4|0.2%|0.0%|
[shunlist](#shunlist)|1344|1344|3|0.2%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2724|2724|3|0.1%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|3|0.0%|0.0%|
[ciarmy](#ciarmy)|449|449|3|0.6%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|2|0.3%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|2|0.0%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2|0.0%|0.0%|
[dm_tor](#dm_tor)|6507|6507|2|0.0%|0.0%|
[bm_tor](#bm_tor)|6512|6512|2|0.0%|0.0%|
[zeus_badips](#zeus_badips)|202|202|1|0.4%|0.0%|
[zeus](#zeus)|230|230|1|0.4%|0.0%|
[proxyrss](#proxyrss)|1299|1299|1|0.0%|0.0%|
[openbl_1d](#openbl_1d)|170|170|1|0.5%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|1|0.1%|0.0%|
[et_tor](#et_tor)|6340|6340|1|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|1181|1181|1|0.0%|0.0%|

## blocklist_de_sip

[Blocklist.de](https://www.blocklist.de/) All IP addresses that tried to login in a SIP, VOIP or Asterisk Server and are included in the IPs list from [infiltrated.net](www.infiltrated.net)

Source is downloaded from [this link](http://lists.blocklist.de/lists/sip.txt).

The last time downloaded was found to be dated: Wed Jun 10 14:10:07 UTC 2015.

The ipset `blocklist_de_sip` has **82** entries, **82** unique IPs.

The following table shows the overlaps of `blocklist_de_sip` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_sip`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_sip`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_sip`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|23627|35252|62|0.1%|75.6%|
[blocklist_de](#blocklist_de)|29712|29712|62|0.2%|75.6%|
[voipbl](#voipbl)|10533|10945|27|0.2%|32.9%|
[alienvault_reputation](#alienvault_reputation)|185045|185045|19|0.0%|23.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|12|0.0%|14.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|7|0.0%|8.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|6|0.0%|7.3%|
[firehol_level3](#firehol_level3)|110340|9628074|3|0.0%|3.6%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|2|0.0%|2.4%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|2|0.0%|2.4%|
[firehol_level1](#firehol_level1)|5135|688894845|2|0.0%|2.4%|
[et_block](#et_block)|999|18343755|2|0.0%|2.4%|
[shunlist](#shunlist)|1344|1344|1|0.0%|1.2%|
[et_botcc](#et_botcc)|509|509|1|0.1%|1.2%|

## blocklist_de_ssh

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service SSH.

Source is downloaded from [this link](http://lists.blocklist.de/lists/ssh.txt).

The last time downloaded was found to be dated: Wed Jun 10 14:14:05 UTC 2015.

The ipset `blocklist_de_ssh` has **3507** entries, **3507** unique IPs.

The following table shows the overlaps of `blocklist_de_ssh` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_ssh`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_ssh`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_ssh`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|23627|35252|3503|9.9%|99.8%|
[blocklist_de](#blocklist_de)|29712|29712|3503|11.7%|99.8%|
[alienvault_reputation](#alienvault_reputation)|185045|185045|1150|0.6%|32.7%|
[firehol_level3](#firehol_level3)|110340|9628074|1011|0.0%|28.8%|
[openbl_60d](#openbl_60d)|7022|7022|942|13.4%|26.8%|
[openbl_30d](#openbl_30d)|2843|2843|751|26.4%|21.4%|
[bruteforceblocker](#bruteforceblocker)|1712|1712|656|38.3%|18.7%|
[et_compromised](#et_compromised)|1718|1718|630|36.6%|17.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|520|0.0%|14.8%|
[shunlist](#shunlist)|1344|1344|413|30.7%|11.7%|
[openbl_7d](#openbl_7d)|695|695|374|53.8%|10.6%|
[firehol_level1](#firehol_level1)|5135|688894845|147|0.0%|4.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|143|0.0%|4.0%|
[et_block](#et_block)|999|18343755|138|0.0%|3.9%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|132|0.0%|3.7%|
[openbl_1d](#openbl_1d)|170|170|125|73.5%|3.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|56|0.0%|1.5%|
[blocklist_de_strongips](#blocklist_de_strongips)|182|182|30|16.4%|0.8%|
[stopforumspam_30d](#stopforumspam_30d)|94424|94424|23|0.0%|0.6%|
[dshield](#dshield)|20|5120|13|0.2%|0.3%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|6|0.0%|0.1%|
[nixspam](#nixspam)|39997|39997|6|0.0%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|6|0.0%|0.1%|
[ciarmy](#ciarmy)|449|449|3|0.6%|0.0%|
[voipbl](#voipbl)|10533|10945|2|0.0%|0.0%|
[sslbl](#sslbl)|372|372|1|0.2%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|1|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|10254|10254|1|0.0%|0.0%|
[php_spammers](#php_spammers)|700|700|1|0.1%|0.0%|
[php_commenters](#php_commenters)|403|403|1|0.2%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|1|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|1|0.0%|0.0%|
[firehol_anonymous](#firehol_anonymous)|18384|82411|1|0.0%|0.0%|
[et_tor](#et_tor)|6340|6340|1|0.0%|0.0%|
[dm_tor](#dm_tor)|6507|6507|1|0.0%|0.0%|
[bm_tor](#bm_tor)|6512|6512|1|0.0%|0.0%|

## blocklist_de_strongips

[Blocklist.de](https://www.blocklist.de/) All IPs which are older then 2 month and have more then 5.000 attacks.

Source is downloaded from [this link](http://lists.blocklist.de/lists/strongips.txt).

The last time downloaded was found to be dated: Wed Jun 10 14:10:09 UTC 2015.

The ipset `blocklist_de_strongips` has **182** entries, **182** unique IPs.

The following table shows the overlaps of `blocklist_de_strongips` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_strongips`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_strongips`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_strongips`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|23627|35252|182|0.5%|100.0%|
[blocklist_de](#blocklist_de)|29712|29712|182|0.6%|100.0%|
[firehol_level3](#firehol_level3)|110340|9628074|164|0.0%|90.1%|
[stopforumspam_30d](#stopforumspam_30d)|94424|94424|138|0.1%|75.8%|
[blocklist_de_bots](#blocklist_de_bots)|2981|2981|136|4.5%|74.7%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|120|0.4%|65.9%|
[stopforumspam_1d](#stopforumspam_1d)|6892|6892|113|1.6%|62.0%|
[php_commenters](#php_commenters)|403|403|45|11.1%|24.7%|
[alienvault_reputation](#alienvault_reputation)|185045|185045|35|0.0%|19.2%|
[blocklist_de_apache](#blocklist_de_apache)|14944|14944|33|0.2%|18.1%|
[blocklist_de_ssh](#blocklist_de_ssh)|3507|3507|30|0.8%|16.4%|
[openbl_60d](#openbl_60d)|7022|7022|25|0.3%|13.7%|
[openbl_7d](#openbl_7d)|695|695|24|3.4%|13.1%|
[openbl_30d](#openbl_30d)|2843|2843|24|0.8%|13.1%|
[blocklist_de_mail](#blocklist_de_mail)|18093|18093|21|0.1%|11.5%|
[openbl_1d](#openbl_1d)|170|170|20|11.7%|10.9%|
[shunlist](#shunlist)|1344|1344|19|1.4%|10.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|17|0.0%|9.3%|
[firehol_level1](#firehol_level1)|5135|688894845|12|0.0%|6.5%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|3592|3592|9|0.2%|4.9%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|8|0.0%|4.3%|
[php_spammers](#php_spammers)|700|700|8|1.1%|4.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|8|0.0%|4.3%|
[et_block](#et_block)|999|18343755|8|0.0%|4.3%|
[firehol_proxies](#firehol_proxies)|11989|12246|7|0.0%|3.8%|
[firehol_anonymous](#firehol_anonymous)|18384|82411|7|0.0%|3.8%|
[xroxy](#xroxy)|2151|2151|6|0.2%|3.2%|
[ri_web_proxies](#ri_web_proxies)|7539|7539|6|0.0%|3.2%|
[proxyrss](#proxyrss)|1299|1299|6|0.4%|3.2%|
[proxz](#proxz)|1212|1212|5|0.4%|2.7%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|4|0.0%|2.1%|
[php_dictionary](#php_dictionary)|702|702|3|0.4%|1.6%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|1.6%|
[snort_ipfilter](#snort_ipfilter)|10254|10254|2|0.0%|1.0%|
[php_harvesters](#php_harvesters)|378|378|2|0.5%|1.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|1181|1181|2|0.1%|1.0%|
[nixspam](#nixspam)|39997|39997|1|0.0%|0.5%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|1|0.0%|0.5%|
[dshield](#dshield)|20|5120|1|0.0%|0.5%|

## bm_tor

[torstatus.blutmagie.de](https://torstatus.blutmagie.de) list of all TOR network servers

Source is downloaded from [this link](https://torstatus.blutmagie.de/ip_list_all.php/Tor_ip_list_ALL.csv).

The last time downloaded was found to be dated: Wed Jun 10 14:09:02 UTC 2015.

The ipset `bm_tor` has **6512** entries, **6512** unique IPs.

The following table shows the overlaps of `bm_tor` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `bm_tor`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `bm_tor`.
- ` this % ` is the percentage **of this ipset (`bm_tor`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_anonymous](#firehol_anonymous)|18384|82411|6512|7.9%|100.0%|
[dm_tor](#dm_tor)|6507|6507|6507|100.0%|99.9%|
[et_tor](#et_tor)|6340|6340|5613|88.5%|86.1%|
[firehol_level3](#firehol_level3)|110340|9628074|1099|0.0%|16.8%|
[snort_ipfilter](#snort_ipfilter)|10254|10254|1059|10.3%|16.2%|
[stopforumspam_30d](#stopforumspam_30d)|94424|94424|649|0.6%|9.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|630|0.0%|9.6%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|529|1.8%|8.1%|
[firehol_level2](#firehol_level2)|23627|35252|376|1.0%|5.7%|
[stopforumspam_1d](#stopforumspam_1d)|6892|6892|370|5.3%|5.6%|
[firehol_proxies](#firehol_proxies)|11989|12246|236|1.9%|3.6%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|232|44.2%|3.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|180|0.0%|2.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|164|0.0%|2.5%|
[php_commenters](#php_commenters)|403|403|48|11.9%|0.7%|
[alienvault_reputation](#alienvault_reputation)|185045|185045|40|0.0%|0.6%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|22|0.0%|0.3%|
[openbl_60d](#openbl_60d)|7022|7022|20|0.2%|0.3%|
[blocklist_de](#blocklist_de)|29712|29712|12|0.0%|0.1%|
[blocklist_de_apache](#blocklist_de_apache)|14944|14944|11|0.0%|0.1%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|3592|3592|9|0.2%|0.1%|
[php_harvesters](#php_harvesters)|378|378|7|1.8%|0.1%|
[et_block](#et_block)|999|18343755|7|0.0%|0.1%|
[php_spammers](#php_spammers)|700|700|5|0.7%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7539|7539|4|0.0%|0.0%|
[php_dictionary](#php_dictionary)|702|702|4|0.5%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|4|0.0%|0.0%|
[voipbl](#voipbl)|10533|10945|3|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|3|0.0%|0.0%|
[firehol_level1](#firehol_level1)|5135|688894845|3|0.0%|0.0%|
[nixspam](#nixspam)|39997|39997|2|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|18093|18093|2|0.0%|0.0%|
[xroxy](#xroxy)|2151|2151|1|0.0%|0.0%|
[shunlist](#shunlist)|1344|1344|1|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3507|3507|1|0.0%|0.0%|

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
[firehol_level3](#firehol_level3)|110340|9628074|3|0.0%|0.0%|
[php_harvesters](#php_harvesters)|378|378|1|0.2%|0.0%|
[php_commenters](#php_commenters)|403|403|1|0.2%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.0%|
[ciarmy](#ciarmy)|449|449|1|0.2%|0.0%|

## bruteforceblocker

[danger.rulez.sk](http://danger.rulez.sk/) IPs detected by [bruteforceblocker](http://danger.rulez.sk/index.php/bruteforceblocker/) (fail2ban alternative for SSH on OpenBSD). This is an automatically generated list from users reporting failed authentication attempts. An IP seems to be included if 3 or more users report it. Its retention pocily seems 30 days.

Source is downloaded from [this link](http://danger.rulez.sk/projects/bruteforceblocker/blist.php).

The last time downloaded was found to be dated: Wed Jun 10 13:09:06 UTC 2015.

The ipset `bruteforceblocker` has **1712** entries, **1712** unique IPs.

The following table shows the overlaps of `bruteforceblocker` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `bruteforceblocker`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `bruteforceblocker`.
- ` this % ` is the percentage **of this ipset (`bruteforceblocker`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level3](#firehol_level3)|110340|9628074|1712|0.0%|100.0%|
[et_compromised](#et_compromised)|1718|1718|1638|95.3%|95.6%|
[alienvault_reputation](#alienvault_reputation)|185045|185045|1098|0.5%|64.1%|
[openbl_60d](#openbl_60d)|7022|7022|988|14.0%|57.7%|
[openbl_30d](#openbl_30d)|2843|2843|923|32.4%|53.9%|
[firehol_level2](#firehol_level2)|23627|35252|662|1.8%|38.6%|
[blocklist_de](#blocklist_de)|29712|29712|661|2.2%|38.6%|
[blocklist_de_ssh](#blocklist_de_ssh)|3507|3507|656|18.7%|38.3%|
[shunlist](#shunlist)|1344|1344|440|32.7%|25.7%|
[openbl_7d](#openbl_7d)|695|695|326|46.9%|19.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|154|0.0%|8.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|88|0.0%|5.1%|
[firehol_level1](#firehol_level1)|5135|688894845|87|0.0%|5.0%|
[et_block](#et_block)|999|18343755|84|0.0%|4.9%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|81|0.0%|4.7%|
[openbl_1d](#openbl_1d)|170|170|62|36.4%|3.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|53|0.0%|3.0%|
[stopforumspam_30d](#stopforumspam_30d)|94424|94424|11|0.0%|0.6%|
[dshield](#dshield)|20|5120|6|0.1%|0.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|5|0.0%|0.2%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|4|0.0%|0.2%|
[blocklist_de_mail](#blocklist_de_mail)|18093|18093|4|0.0%|0.2%|
[voipbl](#voipbl)|10533|10945|3|0.0%|0.1%|
[nixspam](#nixspam)|39997|39997|3|0.0%|0.1%|
[firehol_proxies](#firehol_proxies)|11989|12246|3|0.0%|0.1%|
[firehol_anonymous](#firehol_anonymous)|18384|82411|3|0.0%|0.1%|
[blocklist_de_imap](#blocklist_de_imap)|2407|2407|3|0.1%|0.1%|
[proxz](#proxz)|1212|1212|2|0.1%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|2|0.0%|0.1%|
[ciarmy](#ciarmy)|449|449|2|0.4%|0.1%|
[xroxy](#xroxy)|2151|2151|1|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6892|6892|1|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|10254|10254|1|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7539|7539|1|0.0%|0.0%|
[php_spammers](#php_spammers)|700|700|1|0.1%|0.0%|
[php_commenters](#php_commenters)|403|403|1|0.2%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|2981|2981|1|0.0%|0.0%|

## ciarmy

[CIArmy.com](http://ciarmy.com/) IPs with poor Rogue Packet score that have not yet been identified as malicious by the community

Source is downloaded from [this link](http://cinsscore.com/list/ci-badguys.txt).

The last time downloaded was found to be dated: Wed Jun 10 13:15:12 UTC 2015.

The ipset `ciarmy` has **449** entries, **449** unique IPs.

The following table shows the overlaps of `ciarmy` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ciarmy`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ciarmy`.
- ` this % ` is the percentage **of this ipset (`ciarmy`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level3](#firehol_level3)|110340|9628074|449|0.0%|100.0%|
[alienvault_reputation](#alienvault_reputation)|185045|185045|437|0.2%|97.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|99|0.0%|22.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|48|0.0%|10.6%|
[firehol_level2](#firehol_level2)|23627|35252|42|0.1%|9.3%|
[blocklist_de](#blocklist_de)|29712|29712|42|0.1%|9.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|36|0.0%|8.0%|
[blocklist_de_apache](#blocklist_de_apache)|14944|14944|33|0.2%|7.3%|
[shunlist](#shunlist)|1344|1344|30|2.2%|6.6%|
[firehol_level1](#firehol_level1)|5135|688894845|4|0.0%|0.8%|
[et_block](#et_block)|999|18343755|4|0.0%|0.8%|
[dshield](#dshield)|20|5120|3|0.0%|0.6%|
[blocklist_de_ssh](#blocklist_de_ssh)|3507|3507|3|0.0%|0.6%|
[blocklist_de_mail](#blocklist_de_mail)|18093|18093|3|0.0%|0.6%|
[blocklist_de_imap](#blocklist_de_imap)|2407|2407|3|0.1%|0.6%|
[blocklist_de_ftp](#blocklist_de_ftp)|1181|1181|3|0.2%|0.6%|
[stopforumspam_30d](#stopforumspam_30d)|94424|94424|2|0.0%|0.4%|
[openbl_7d](#openbl_7d)|695|695|2|0.2%|0.4%|
[openbl_60d](#openbl_60d)|7022|7022|2|0.0%|0.4%|
[openbl_30d](#openbl_30d)|2843|2843|2|0.0%|0.4%|
[bruteforceblocker](#bruteforceblocker)|1712|1712|2|0.1%|0.4%|
[voipbl](#voipbl)|10533|10945|1|0.0%|0.2%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|1|0.0%|0.2%|
[openbl_1d](#openbl_1d)|170|170|1|0.5%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.2%|
[fullbogons](#fullbogons)|3770|670213096|1|0.0%|0.2%|
[et_compromised](#et_compromised)|1718|1718|1|0.0%|0.2%|
[bogons](#bogons)|13|592708608|1|0.0%|0.2%|

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
[firehol_level3](#firehol_level3)|110340|9628074|123|0.0%|100.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|16|0.0%|13.0%|
[malc0de](#malc0de)|313|313|13|4.1%|10.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|3|0.0%|2.4%|
[alienvault_reputation](#alienvault_reputation)|185045|185045|3|0.0%|2.4%|
[snort_ipfilter](#snort_ipfilter)|10254|10254|2|0.0%|1.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|2|0.0%|1.6%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|1|0.0%|0.8%|

## dm_tor

[dan.me.uk](https://www.dan.me.uk) dynamic list of TOR exit points

Source is downloaded from [this link](https://www.dan.me.uk/torlist/).

The last time downloaded was found to be dated: Wed Jun 10 14:27:04 UTC 2015.

The ipset `dm_tor` has **6507** entries, **6507** unique IPs.

The following table shows the overlaps of `dm_tor` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `dm_tor`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `dm_tor`.
- ` this % ` is the percentage **of this ipset (`dm_tor`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_anonymous](#firehol_anonymous)|18384|82411|6507|7.8%|100.0%|
[bm_tor](#bm_tor)|6512|6512|6507|99.9%|100.0%|
[et_tor](#et_tor)|6340|6340|5610|88.4%|86.2%|
[firehol_level3](#firehol_level3)|110340|9628074|1098|0.0%|16.8%|
[snort_ipfilter](#snort_ipfilter)|10254|10254|1058|10.3%|16.2%|
[stopforumspam_30d](#stopforumspam_30d)|94424|94424|649|0.6%|9.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|630|0.0%|9.6%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|529|1.8%|8.1%|
[firehol_level2](#firehol_level2)|23627|35252|376|1.0%|5.7%|
[stopforumspam_1d](#stopforumspam_1d)|6892|6892|370|5.3%|5.6%|
[firehol_proxies](#firehol_proxies)|11989|12246|236|1.9%|3.6%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|232|44.2%|3.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|180|0.0%|2.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|164|0.0%|2.5%|
[php_commenters](#php_commenters)|403|403|48|11.9%|0.7%|
[alienvault_reputation](#alienvault_reputation)|185045|185045|40|0.0%|0.6%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|22|0.0%|0.3%|
[openbl_60d](#openbl_60d)|7022|7022|20|0.2%|0.3%|
[blocklist_de](#blocklist_de)|29712|29712|12|0.0%|0.1%|
[blocklist_de_apache](#blocklist_de_apache)|14944|14944|11|0.0%|0.1%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|3592|3592|9|0.2%|0.1%|
[php_harvesters](#php_harvesters)|378|378|7|1.8%|0.1%|
[et_block](#et_block)|999|18343755|7|0.0%|0.1%|
[php_spammers](#php_spammers)|700|700|5|0.7%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7539|7539|4|0.0%|0.0%|
[php_dictionary](#php_dictionary)|702|702|4|0.5%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|4|0.0%|0.0%|
[voipbl](#voipbl)|10533|10945|3|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|3|0.0%|0.0%|
[firehol_level1](#firehol_level1)|5135|688894845|3|0.0%|0.0%|
[nixspam](#nixspam)|39997|39997|2|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|18093|18093|2|0.0%|0.0%|
[xroxy](#xroxy)|2151|2151|1|0.0%|0.0%|
[shunlist](#shunlist)|1344|1344|1|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3507|3507|1|0.0%|0.0%|

## dshield

[DShield.org](https://dshield.org/) top 20 attacking class C (/24) subnets over the last three days - **excellent list**

Source is downloaded from [this link](http://feeds.dshield.org/block.txt).

The last time downloaded was found to be dated: Wed Jun 10 11:56:28 UTC 2015.

The ipset `dshield` has **20** entries, **5120** unique IPs.

The following table shows the overlaps of `dshield` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `dshield`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `dshield`.
- ` this % ` is the percentage **of this ipset (`dshield`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level1](#firehol_level1)|5135|688894845|5120|0.0%|100.0%|
[alienvault_reputation](#alienvault_reputation)|185045|185045|2564|1.3%|50.0%|
[et_block](#et_block)|999|18343755|1024|0.0%|20.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|512|0.0%|10.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|257|0.0%|5.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|256|0.0%|5.0%|
[openbl_60d](#openbl_60d)|7022|7022|59|0.8%|1.1%|
[firehol_level3](#firehol_level3)|110340|9628074|48|0.0%|0.9%|
[openbl_30d](#openbl_30d)|2843|2843|37|1.3%|0.7%|
[shunlist](#shunlist)|1344|1344|25|1.8%|0.4%|
[firehol_level2](#firehol_level2)|23627|35252|16|0.0%|0.3%|
[blocklist_de](#blocklist_de)|29712|29712|16|0.0%|0.3%|
[blocklist_de_ssh](#blocklist_de_ssh)|3507|3507|13|0.3%|0.2%|
[openbl_7d](#openbl_7d)|695|695|6|0.8%|0.1%|
[et_compromised](#et_compromised)|1718|1718|6|0.3%|0.1%|
[bruteforceblocker](#bruteforceblocker)|1712|1712|6|0.3%|0.1%|
[openbl_1d](#openbl_1d)|170|170|3|1.7%|0.0%|
[ciarmy](#ciarmy)|449|449|3|0.6%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14944|14944|3|0.0%|0.0%|
[malc0de](#malc0de)|313|313|1|0.3%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|182|182|1|0.5%|0.0%|

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
[firehol_level1](#firehol_level1)|5135|688894845|18339912|2.6%|99.9%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|18338560|99.9%|99.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|8532519|2.4%|46.5%|
[firehol_level3](#firehol_level3)|110340|9628074|6933348|72.0%|37.7%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|6932480|75.5%|37.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|2272798|0.2%|12.3%|
[fullbogons](#fullbogons)|3770|670213096|151552|0.0%|0.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|130922|0.0%|0.7%|
[alienvault_reputation](#alienvault_reputation)|185045|185045|6045|3.2%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1043|0.3%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|94424|94424|1027|1.0%|0.0%|
[dshield](#dshield)|20|5120|1024|20.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|517|0.1%|0.0%|
[snort_ipfilter](#snort_ipfilter)|10254|10254|299|2.9%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|297|1.0%|0.0%|
[firehol_level2](#firehol_level2)|23627|35252|292|0.8%|0.0%|
[openbl_60d](#openbl_60d)|7022|7022|247|3.5%|0.0%|
[zeus](#zeus)|230|230|228|99.1%|0.0%|
[blocklist_de](#blocklist_de)|29712|29712|225|0.7%|0.0%|
[zeus_badips](#zeus_badips)|202|202|202|100.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3507|3507|138|3.9%|0.0%|
[openbl_30d](#openbl_30d)|2843|2843|127|4.4%|0.0%|
[shunlist](#shunlist)|1344|1344|111|8.2%|0.0%|
[et_compromised](#et_compromised)|1718|1718|103|5.9%|0.0%|
[feodo](#feodo)|105|105|102|97.1%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1712|1712|84|4.9%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6892|6892|82|1.1%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|2981|2981|57|1.9%|0.0%|
[openbl_7d](#openbl_7d)|695|695|54|7.7%|0.0%|
[nixspam](#nixspam)|39997|39997|39|0.0%|0.0%|
[sslbl](#sslbl)|372|372|38|10.2%|0.0%|
[php_commenters](#php_commenters)|403|403|30|7.4%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|29|2.2%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|18093|18093|20|0.1%|0.0%|
[voipbl](#voipbl)|10533|10945|18|0.1%|0.0%|
[openbl_1d](#openbl_1d)|170|170|18|10.5%|0.0%|
[palevo](#palevo)|13|13|13|100.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|11|0.0%|0.0%|
[firehol_anonymous](#firehol_anonymous)|18384|82411|11|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2407|2407|11|0.4%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|8|0.5%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|182|182|8|4.3%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14944|14944|8|0.0%|0.0%|
[et_tor](#et_tor)|6340|6340|7|0.1%|0.0%|
[dm_tor](#dm_tor)|6507|6507|7|0.1%|0.0%|
[bm_tor](#bm_tor)|6512|6512|7|0.1%|0.0%|
[php_dictionary](#php_dictionary)|702|702|6|0.8%|0.0%|
[firehol_proxies](#firehol_proxies)|11989|12246|6|0.0%|0.0%|
[malc0de](#malc0de)|313|313|5|1.5%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|3592|3592|5|0.1%|0.0%|
[php_spammers](#php_spammers)|700|700|4|0.5%|0.0%|
[ciarmy](#ciarmy)|449|449|4|0.8%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|3|0.5%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|2|0.3%|0.0%|
[et_botcc](#et_botcc)|509|509|2|0.3%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|82|82|2|2.4%|0.0%|
[xroxy](#xroxy)|2151|2151|1|0.0%|0.0%|
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
[alienvault_reputation](#alienvault_reputation)|185045|185045|4|0.0%|0.7%|
[firehol_level3](#firehol_level3)|110340|9628074|3|0.0%|0.5%|
[et_block](#et_block)|999|18343755|2|0.0%|0.3%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|1|0.0%|0.1%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|1|0.0%|0.1%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|1|0.0%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.1%|
[firehol_level1](#firehol_level1)|5135|688894845|1|0.0%|0.1%|
[blocklist_de_sip](#blocklist_de_sip)|82|82|1|1.2%|0.1%|

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
[firehol_level3](#firehol_level3)|110340|9628074|1679|0.0%|97.7%|
[bruteforceblocker](#bruteforceblocker)|1712|1712|1638|95.6%|95.3%|
[alienvault_reputation](#alienvault_reputation)|185045|185045|1111|0.6%|64.6%|
[openbl_60d](#openbl_60d)|7022|7022|1003|14.2%|58.3%|
[openbl_30d](#openbl_30d)|2843|2843|930|32.7%|54.1%|
[firehol_level2](#firehol_level2)|23627|35252|636|1.8%|37.0%|
[blocklist_de](#blocklist_de)|29712|29712|635|2.1%|36.9%|
[blocklist_de_ssh](#blocklist_de_ssh)|3507|3507|630|17.9%|36.6%|
[shunlist](#shunlist)|1344|1344|451|33.5%|26.2%|
[openbl_7d](#openbl_7d)|695|695|315|45.3%|18.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|153|0.0%|8.9%|
[firehol_level1](#firehol_level1)|5135|688894845|107|0.0%|6.2%|
[et_block](#et_block)|999|18343755|103|0.0%|5.9%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|101|0.0%|5.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|89|0.0%|5.1%|
[openbl_1d](#openbl_1d)|170|170|55|32.3%|3.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|52|0.0%|3.0%|
[stopforumspam_30d](#stopforumspam_30d)|94424|94424|12|0.0%|0.6%|
[dshield](#dshield)|20|5120|6|0.1%|0.3%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|5|0.0%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|5|0.0%|0.2%|
[blocklist_de_mail](#blocklist_de_mail)|18093|18093|4|0.0%|0.2%|
[nixspam](#nixspam)|39997|39997|3|0.0%|0.1%|
[firehol_proxies](#firehol_proxies)|11989|12246|3|0.0%|0.1%|
[firehol_anonymous](#firehol_anonymous)|18384|82411|3|0.0%|0.1%|
[blocklist_de_imap](#blocklist_de_imap)|2407|2407|3|0.1%|0.1%|
[voipbl](#voipbl)|10533|10945|2|0.0%|0.1%|
[proxz](#proxz)|1212|1212|2|0.1%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|2|0.0%|0.1%|
[xroxy](#xroxy)|2151|2151|1|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6892|6892|1|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|10254|10254|1|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7539|7539|1|0.0%|0.0%|
[php_spammers](#php_spammers)|700|700|1|0.1%|0.0%|
[php_commenters](#php_commenters)|403|403|1|0.2%|0.0%|
[ciarmy](#ciarmy)|449|449|1|0.2%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|2981|2981|1|0.0%|0.0%|

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
[firehol_anonymous](#firehol_anonymous)|18384|82411|5618|6.8%|88.6%|
[bm_tor](#bm_tor)|6512|6512|5613|86.1%|88.5%|
[dm_tor](#dm_tor)|6507|6507|5610|86.2%|88.4%|
[firehol_level3](#firehol_level3)|110340|9628074|1105|0.0%|17.4%|
[snort_ipfilter](#snort_ipfilter)|10254|10254|1068|10.4%|16.8%|
[stopforumspam_30d](#stopforumspam_30d)|94424|94424|651|0.6%|10.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|614|0.0%|9.6%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|533|1.8%|8.4%|
[firehol_level2](#firehol_level2)|23627|35252|375|1.0%|5.9%|
[stopforumspam_1d](#stopforumspam_1d)|6892|6892|370|5.3%|5.8%|
[firehol_proxies](#firehol_proxies)|11989|12246|236|1.9%|3.7%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|233|44.4%|3.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|183|0.0%|2.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|163|0.0%|2.5%|
[php_commenters](#php_commenters)|403|403|48|11.9%|0.7%|
[alienvault_reputation](#alienvault_reputation)|185045|185045|39|0.0%|0.6%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|22|0.0%|0.3%|
[openbl_60d](#openbl_60d)|7022|7022|20|0.2%|0.3%|
[blocklist_de](#blocklist_de)|29712|29712|11|0.0%|0.1%|
[blocklist_de_apache](#blocklist_de_apache)|14944|14944|10|0.0%|0.1%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|3592|3592|9|0.2%|0.1%|
[php_harvesters](#php_harvesters)|378|378|7|1.8%|0.1%|
[et_block](#et_block)|999|18343755|7|0.0%|0.1%|
[php_spammers](#php_spammers)|700|700|5|0.7%|0.0%|
[php_dictionary](#php_dictionary)|702|702|4|0.5%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|4|0.0%|0.0%|
[voipbl](#voipbl)|10533|10945|3|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|3|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7539|7539|3|0.0%|0.0%|
[firehol_level1](#firehol_level1)|5135|688894845|3|0.0%|0.0%|
[xroxy](#xroxy)|2151|2151|1|0.0%|0.0%|
[shunlist](#shunlist)|1344|1344|1|0.0%|0.0%|
[nixspam](#nixspam)|39997|39997|1|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3507|3507|1|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|18093|18093|1|0.0%|0.0%|

## feodo

[Abuse.ch Feodo tracker](https://feodotracker.abuse.ch) trojan includes IPs which are being used by Feodo (also known as Cridex or Bugat) which commits ebanking fraud - **excellent list**

Source is downloaded from [this link](https://feodotracker.abuse.ch/blocklist/?download=ipblocklist).

The last time downloaded was found to be dated: Wed Jun 10 14:09:21 UTC 2015.

The ipset `feodo` has **105** entries, **105** unique IPs.

The following table shows the overlaps of `feodo` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `feodo`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `feodo`.
- ` this % ` is the percentage **of this ipset (`feodo`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level1](#firehol_level1)|5135|688894845|105|0.0%|100.0%|
[et_block](#et_block)|999|18343755|102|0.0%|97.1%|
[snort_ipfilter](#snort_ipfilter)|10254|10254|82|0.7%|78.0%|
[firehol_level3](#firehol_level3)|110340|9628074|82|0.0%|78.0%|
[sslbl](#sslbl)|372|372|38|10.2%|36.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|11|0.0%|10.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|3|0.0%|2.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|3|0.0%|2.8%|
[alienvault_reputation](#alienvault_reputation)|185045|185045|2|0.0%|1.9%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.9%|

## firehol_anonymous

**FireHOL Anonymous** - Known anonymizing IPs. (includes: firehol_proxies anonymous bm_tor dm_tor)

Source is downloaded from [this link]().

The last time downloaded was found to be dated: Sun Jun  7 22:20:34 UTC 2015.

The ipset `firehol_anonymous` has **18384** entries, **82411** unique IPs.

The following table shows the overlaps of `firehol_anonymous` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `firehol_anonymous`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `firehol_anonymous`.
- ` this % ` is the percentage **of this ipset (`firehol_anonymous`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_proxies](#firehol_proxies)|11989|12246|12246|100.0%|14.8%|
[ri_web_proxies](#ri_web_proxies)|7539|7539|7539|100.0%|9.1%|
[firehol_level3](#firehol_level3)|110340|9628074|6544|0.0%|7.9%|
[bm_tor](#bm_tor)|6512|6512|6512|100.0%|7.9%|
[dm_tor](#dm_tor)|6507|6507|6507|100.0%|7.8%|
[stopforumspam_30d](#stopforumspam_30d)|94424|94424|6031|6.3%|7.3%|
[et_tor](#et_tor)|6340|6340|5618|88.6%|6.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|3430|0.0%|4.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|2883|0.0%|3.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|2867|0.0%|3.4%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|2748|9.3%|3.3%|
[ri_connect_proxies](#ri_connect_proxies)|2724|2724|2724|100.0%|3.3%|
[xroxy](#xroxy)|2151|2151|2151|100.0%|2.6%|
[firehol_level2](#firehol_level2)|23627|35252|1351|3.8%|1.6%|
[proxyrss](#proxyrss)|1299|1299|1299|100.0%|1.5%|
[proxz](#proxz)|1212|1212|1212|100.0%|1.4%|
[snort_ipfilter](#snort_ipfilter)|10254|10254|1159|11.3%|1.4%|
[stopforumspam_1d](#stopforumspam_1d)|6892|6892|1017|14.7%|1.2%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|663|100.0%|0.8%|
[blocklist_de](#blocklist_de)|29712|29712|617|2.0%|0.7%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|524|100.0%|0.6%|
[blocklist_de_bots](#blocklist_de_bots)|2981|2981|491|16.4%|0.5%|
[nixspam](#nixspam)|39997|39997|106|0.2%|0.1%|
[blocklist_de_mail](#blocklist_de_mail)|18093|18093|104|0.5%|0.1%|
[php_dictionary](#php_dictionary)|702|702|94|13.3%|0.1%|
[php_spammers](#php_spammers)|700|700|80|11.4%|0.0%|
[voipbl](#voipbl)|10533|10945|79|0.7%|0.0%|
[php_commenters](#php_commenters)|403|403|76|18.8%|0.0%|
[alienvault_reputation](#alienvault_reputation)|185045|185045|56|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|28|0.0%|0.0%|
[openbl_60d](#openbl_60d)|7022|7022|23|0.3%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14944|14944|17|0.1%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|15|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|3592|3592|15|0.4%|0.0%|
[php_harvesters](#php_harvesters)|378|378|12|3.1%|0.0%|
[et_block](#et_block)|999|18343755|11|0.0%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|7|0.0%|0.0%|
[firehol_level1](#firehol_level1)|5135|688894845|7|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|182|182|7|3.8%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|6|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|3|0.2%|0.0%|
[et_compromised](#et_compromised)|1718|1718|3|0.1%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1712|1712|3|0.1%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|1181|1181|2|0.1%|0.0%|
[sslbl](#sslbl)|372|372|1|0.2%|0.0%|
[shunlist](#shunlist)|1344|1344|1|0.0%|0.0%|
[openbl_30d](#openbl_30d)|2843|2843|1|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3507|3507|1|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2407|2407|1|0.0%|0.0%|

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
[et_block](#et_block)|999|18343755|18339912|99.9%|2.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|8867972|2.5%|1.2%|
[firehol_level3](#firehol_level3)|110340|9628074|7500204|77.8%|1.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|7498240|81.6%|1.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|4637602|3.3%|0.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|2570531|0.3%|0.3%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|487424|100.0%|0.0%|
[dshield](#dshield)|20|5120|5120|100.0%|0.0%|
[alienvault_reputation](#alienvault_reputation)|185045|185045|4078|2.2%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1932|0.5%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|94424|94424|1099|1.1%|0.0%|
[sslbl](#sslbl)|372|372|372|100.0%|0.0%|
[voipbl](#voipbl)|10533|10945|333|3.0%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|302|1.0%|0.0%|
[firehol_level2](#firehol_level2)|23627|35252|302|0.8%|0.0%|
[snort_ipfilter](#snort_ipfilter)|10254|10254|300|2.9%|0.0%|
[openbl_60d](#openbl_60d)|7022|7022|297|4.2%|0.0%|
[blocklist_de](#blocklist_de)|29712|29712|237|0.7%|0.0%|
[zeus](#zeus)|230|230|230|100.0%|0.0%|
[zeus_badips](#zeus_badips)|202|202|202|100.0%|0.0%|
[shunlist](#shunlist)|1344|1344|187|13.9%|0.0%|
[openbl_30d](#openbl_30d)|2843|2843|158|5.5%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3507|3507|147|4.1%|0.0%|
[et_compromised](#et_compromised)|1718|1718|107|6.2%|0.0%|
[feodo](#feodo)|105|105|105|100.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1712|1712|87|5.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6892|6892|82|1.1%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|2981|2981|61|2.0%|0.0%|
[openbl_7d](#openbl_7d)|695|695|56|8.0%|0.0%|
[nixspam](#nixspam)|39997|39997|42|0.1%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|39|3.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|39|2.6%|0.0%|
[php_commenters](#php_commenters)|403|403|37|9.1%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|18093|18093|20|0.1%|0.0%|
[openbl_1d](#openbl_1d)|170|170|18|10.5%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|18|0.0%|0.0%|
[palevo](#palevo)|13|13|13|100.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|182|182|12|6.5%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2407|2407|11|0.4%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14944|14944|8|0.0%|0.0%|
[firehol_anonymous](#firehol_anonymous)|18384|82411|7|0.0%|0.0%|
[php_dictionary](#php_dictionary)|702|702|6|0.8%|0.0%|
[malc0de](#malc0de)|313|313|6|1.9%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|3592|3592|5|0.1%|0.0%|
[php_spammers](#php_spammers)|700|700|4|0.5%|0.0%|
[firehol_proxies](#firehol_proxies)|11989|12246|4|0.0%|0.0%|
[ciarmy](#ciarmy)|449|449|4|0.8%|0.0%|
[php_harvesters](#php_harvesters)|378|378|3|0.7%|0.0%|
[et_tor](#et_tor)|6340|6340|3|0.0%|0.0%|
[dm_tor](#dm_tor)|6507|6507|3|0.0%|0.0%|
[bm_tor](#bm_tor)|6512|6512|3|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|2|0.3%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|82|82|2|2.4%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7539|7539|1|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|1|0.1%|0.0%|
[et_botcc](#et_botcc)|509|509|1|0.1%|0.0%|

## firehol_level2

**FireHOL Level 2** - Maximum protection from attacks took place in the last 48 hours. (includes: openbl_1d blocklist_de stopforumspam_1d)

Source is downloaded from [this link]().

The last time downloaded was found to be dated: Sun Jun  7 22:20:34 UTC 2015.

The ipset `firehol_level2` has **23627** entries, **35252** unique IPs.

The following table shows the overlaps of `firehol_level2` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `firehol_level2`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `firehol_level2`.
- ` this % ` is the percentage **of this ipset (`firehol_level2`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|29712|29712|29712|100.0%|84.2%|
[blocklist_de_mail](#blocklist_de_mail)|18093|18093|18051|99.7%|51.2%|
[blocklist_de_apache](#blocklist_de_apache)|14944|14944|14944|100.0%|42.3%|
[firehol_level3](#firehol_level3)|110340|9628074|9345|0.0%|26.5%|
[stopforumspam_30d](#stopforumspam_30d)|94424|94424|8038|8.5%|22.8%|
[stopforumspam_1d](#stopforumspam_1d)|6892|6892|6892|100.0%|19.5%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|6015|20.5%|17.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|4155|0.0%|11.7%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|3592|3592|3592|100.0%|10.1%|
[blocklist_de_ssh](#blocklist_de_ssh)|3507|3507|3503|99.8%|9.9%|
[blocklist_de_bots](#blocklist_de_bots)|2981|2981|2966|99.4%|8.4%|
[blocklist_de_imap](#blocklist_de_imap)|2407|2407|2407|100.0%|6.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|1754|0.0%|4.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|1661|0.0%|4.7%|
[alienvault_reputation](#alienvault_reputation)|185045|185045|1440|0.7%|4.0%|
[firehol_anonymous](#firehol_anonymous)|18384|82411|1351|1.6%|3.8%|
[blocklist_de_ftp](#blocklist_de_ftp)|1181|1181|1181|100.0%|3.3%|
[firehol_proxies](#firehol_proxies)|11989|12246|1172|9.5%|3.3%|
[openbl_60d](#openbl_60d)|7022|7022|1041|14.8%|2.9%|
[nixspam](#nixspam)|39997|39997|990|2.4%|2.8%|
[openbl_30d](#openbl_30d)|2843|2843|820|28.8%|2.3%|
[bruteforceblocker](#bruteforceblocker)|1712|1712|662|38.6%|1.8%|
[ri_web_proxies](#ri_web_proxies)|7539|7539|657|8.7%|1.8%|
[et_compromised](#et_compromised)|1718|1718|636|37.0%|1.8%|
[snort_ipfilter](#snort_ipfilter)|10254|10254|591|5.7%|1.6%|
[shunlist](#shunlist)|1344|1344|455|33.8%|1.2%|
[openbl_7d](#openbl_7d)|695|695|421|60.5%|1.1%|
[proxyrss](#proxyrss)|1299|1299|407|31.3%|1.1%|
[dm_tor](#dm_tor)|6507|6507|376|5.7%|1.0%|
[bm_tor](#bm_tor)|6512|6512|376|5.7%|1.0%|
[et_tor](#et_tor)|6340|6340|375|5.9%|1.0%|
[xroxy](#xroxy)|2151|2151|325|15.1%|0.9%|
[firehol_level1](#firehol_level1)|5135|688894845|302|0.0%|0.8%|
[et_block](#et_block)|999|18343755|292|0.0%|0.8%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|278|0.0%|0.7%|
[proxz](#proxz)|1212|1212|261|21.5%|0.7%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|226|43.1%|0.6%|
[php_commenters](#php_commenters)|403|403|182|45.1%|0.5%|
[blocklist_de_strongips](#blocklist_de_strongips)|182|182|182|100.0%|0.5%|
[openbl_1d](#openbl_1d)|170|170|170|100.0%|0.4%|
[ri_connect_proxies](#ri_connect_proxies)|2724|2724|153|5.6%|0.4%|
[php_dictionary](#php_dictionary)|702|702|116|16.5%|0.3%|
[php_spammers](#php_spammers)|700|700|109|15.5%|0.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|89|0.0%|0.2%|
[blocklist_de_sip](#blocklist_de_sip)|82|82|62|75.6%|0.1%|
[php_harvesters](#php_harvesters)|378|378|56|14.8%|0.1%|
[ciarmy](#ciarmy)|449|449|42|9.3%|0.1%|
[voipbl](#voipbl)|10533|10945|34|0.3%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|20|0.0%|0.0%|
[dshield](#dshield)|20|5120|16|0.3%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|11|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|7|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|6|0.9%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|3|0.2%|0.0%|
[zeus_badips](#zeus_badips)|202|202|2|0.9%|0.0%|
[zeus](#zeus)|230|230|2|0.8%|0.0%|

## firehol_level3

**FireHOL Level 3** - All the bad IPs in last 30 days. (includes: openbl_30d stopforumspam_30d virbl malc0de shunlist malwaredomainlist bruteforceblocker ciarmy cleanmx_viruses snort_ipfilter ib_bluetack_spyware ib_bluetack_hijacked ib_bluetack_webexploit php_commenters php_dictionary php_harvesters php_spammers)

Source is downloaded from [this link]().

The last time downloaded was found to be dated: Sun Jun  7 22:20:34 UTC 2015.

The ipset `firehol_level3` has **110340** entries, **9628074** unique IPs.

The following table shows the overlaps of `firehol_level3` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `firehol_level3`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `firehol_level3`.
- ` this % ` is the percentage **of this ipset (`firehol_level3`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|9177856|100.0%|95.3%|
[firehol_level1](#firehol_level1)|5135|688894845|7500204|1.0%|77.8%|
[et_block](#et_block)|999|18343755|6933348|37.7%|72.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|6933037|37.8%|72.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|2537327|0.7%|26.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|919969|0.1%|9.5%|
[fullbogons](#fullbogons)|3770|670213096|566692|0.0%|5.8%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|339173|100.0%|3.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|161608|0.1%|1.6%|
[stopforumspam_30d](#stopforumspam_30d)|94424|94424|94424|100.0%|0.9%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|29338|100.0%|0.3%|
[snort_ipfilter](#snort_ipfilter)|10254|10254|10254|100.0%|0.1%|
[firehol_level2](#firehol_level2)|23627|35252|9345|26.5%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6892|6892|6668|96.7%|0.0%|
[firehol_anonymous](#firehol_anonymous)|18384|82411|6544|7.9%|0.0%|
[firehol_proxies](#firehol_proxies)|11989|12246|5504|44.9%|0.0%|
[alienvault_reputation](#alienvault_reputation)|185045|185045|5234|2.8%|0.0%|
[blocklist_de](#blocklist_de)|29712|29712|4009|13.4%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7539|7539|3637|48.2%|0.0%|
[openbl_60d](#openbl_60d)|7022|7022|2977|42.3%|0.0%|
[openbl_30d](#openbl_30d)|2843|2843|2843|100.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|2981|2981|2397|80.4%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1712|1712|1712|100.0%|0.0%|
[et_compromised](#et_compromised)|1718|1718|1679|97.7%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2724|2724|1540|56.5%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|1450|100.0%|0.0%|
[shunlist](#shunlist)|1344|1344|1344|100.0%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|1288|100.0%|0.0%|
[xroxy](#xroxy)|2151|2151|1287|59.8%|0.0%|
[et_tor](#et_tor)|6340|6340|1105|17.4%|0.0%|
[bm_tor](#bm_tor)|6512|6512|1099|16.8%|0.0%|
[dm_tor](#dm_tor)|6507|6507|1098|16.8%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3507|3507|1011|28.8%|0.0%|
[proxz](#proxz)|1212|1212|727|59.9%|0.0%|
[php_dictionary](#php_dictionary)|702|702|702|100.0%|0.0%|
[php_spammers](#php_spammers)|700|700|700|100.0%|0.0%|
[openbl_7d](#openbl_7d)|695|695|695|100.0%|0.0%|
[proxyrss](#proxyrss)|1299|1299|661|50.8%|0.0%|
[nixspam](#nixspam)|39997|39997|624|1.5%|0.0%|
[ciarmy](#ciarmy)|449|449|449|100.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|18093|18093|407|2.2%|0.0%|
[php_commenters](#php_commenters)|403|403|403|100.0%|0.0%|
[php_harvesters](#php_harvesters)|378|378|378|100.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|343|65.4%|0.0%|
[malc0de](#malc0de)|313|313|313|100.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14944|14944|313|2.0%|0.0%|
[zeus](#zeus)|230|230|203|88.2%|0.0%|
[zeus_badips](#zeus_badips)|202|202|180|89.1%|0.0%|
[openbl_1d](#openbl_1d)|170|170|164|96.4%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|182|182|164|90.1%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|123|123|123|100.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|3592|3592|108|3.0%|0.0%|
[sslbl](#sslbl)|372|372|96|25.8%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|88|0.0%|0.0%|
[feodo](#feodo)|105|105|82|78.0%|0.0%|
[voipbl](#voipbl)|10533|10945|59|0.5%|0.0%|
[dshield](#dshield)|20|5120|48|0.9%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2407|2407|46|1.9%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|1181|1181|25|2.1%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|24|3.6%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|24|0.0%|0.0%|
[virbl](#virbl)|20|20|20|100.0%|0.0%|
[palevo](#palevo)|13|13|11|84.6%|0.0%|
[et_botcc](#et_botcc)|509|509|3|0.5%|0.0%|
[bogons](#bogons)|13|592708608|3|0.0%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|82|82|3|3.6%|0.0%|

## firehol_proxies

**FireHOL Proxies** - Known open proxies in the last 30 days. (includes: ib_bluetack_proxies maxmind_proxy_fraud proxyrss proxz ri_connect_proxies ri_web_proxies xroxy)

Source is downloaded from [this link]().

The last time downloaded was found to be dated: Sun Jun  7 22:20:34 UTC 2015.

The ipset `firehol_proxies` has **11989** entries, **12246** unique IPs.

The following table shows the overlaps of `firehol_proxies` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `firehol_proxies`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `firehol_proxies`.
- ` this % ` is the percentage **of this ipset (`firehol_proxies`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_anonymous](#firehol_anonymous)|18384|82411|12246|14.8%|100.0%|
[ri_web_proxies](#ri_web_proxies)|7539|7539|7539|100.0%|61.5%|
[firehol_level3](#firehol_level3)|110340|9628074|5504|0.0%|44.9%|
[stopforumspam_30d](#stopforumspam_30d)|94424|94424|5442|5.7%|44.4%|
[ri_connect_proxies](#ri_connect_proxies)|2724|2724|2724|100.0%|22.2%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|2409|8.2%|19.6%|
[xroxy](#xroxy)|2151|2151|2151|100.0%|17.5%|
[proxyrss](#proxyrss)|1299|1299|1299|100.0%|10.6%|
[proxz](#proxz)|1212|1212|1212|100.0%|9.8%|
[firehol_level2](#firehol_level2)|23627|35252|1172|3.3%|9.5%|
[stopforumspam_1d](#stopforumspam_1d)|6892|6892|847|12.2%|6.9%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|663|100.0%|5.4%|
[blocklist_de](#blocklist_de)|29712|29712|603|2.0%|4.9%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|524|100.0%|4.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|521|0.0%|4.2%|
[blocklist_de_bots](#blocklist_de_bots)|2981|2981|490|16.4%|4.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|387|0.0%|3.1%|
[snort_ipfilter](#snort_ipfilter)|10254|10254|329|3.2%|2.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|285|0.0%|2.3%|
[et_tor](#et_tor)|6340|6340|236|3.7%|1.9%|
[dm_tor](#dm_tor)|6507|6507|236|3.6%|1.9%|
[bm_tor](#bm_tor)|6512|6512|236|3.6%|1.9%|
[nixspam](#nixspam)|39997|39997|104|0.2%|0.8%|
[blocklist_de_mail](#blocklist_de_mail)|18093|18093|103|0.5%|0.8%|
[php_dictionary](#php_dictionary)|702|702|93|13.2%|0.7%|
[php_spammers](#php_spammers)|700|700|78|11.1%|0.6%|
[php_commenters](#php_commenters)|403|403|74|18.3%|0.6%|
[alienvault_reputation](#alienvault_reputation)|185045|185045|38|0.0%|0.3%|
[openbl_60d](#openbl_60d)|7022|7022|20|0.2%|0.1%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|15|0.0%|0.1%|
[php_harvesters](#php_harvesters)|378|378|12|3.1%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|11|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|182|182|7|3.8%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14944|14944|7|0.0%|0.0%|
[et_block](#et_block)|999|18343755|6|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|3592|3592|6|0.1%|0.0%|
[firehol_level1](#firehol_level1)|5135|688894845|4|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|3|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|3|0.2%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|0.0%|
[et_compromised](#et_compromised)|1718|1718|3|0.1%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1712|1712|3|0.1%|0.0%|
[voipbl](#voipbl)|10533|10945|2|0.0%|0.0%|
[sslbl](#sslbl)|372|372|1|0.2%|0.0%|
[shunlist](#shunlist)|1344|1344|1|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2407|2407|1|0.0%|0.0%|

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
[firehol_level3](#firehol_level3)|110340|9628074|566692|5.8%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|565760|6.1%|0.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|264841|0.0%|0.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|252415|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|151552|0.8%|0.0%|
[et_block](#et_block)|999|18343755|151552|0.8%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|890|0.2%|0.0%|
[voipbl](#voipbl)|10533|10945|319|2.9%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|33|2.2%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|13|0.0%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|9|0.6%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|94424|94424|1|0.0%|0.0%|
[php_harvesters](#php_harvesters)|378|378|1|0.2%|0.0%|
[php_commenters](#php_commenters)|403|403|1|0.2%|0.0%|
[ciarmy](#ciarmy)|449|449|1|0.2%|0.0%|

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
[firehol_level3](#firehol_level3)|110340|9628074|24|0.0%|0.0%|
[firehol_level1](#firehol_level1)|5135|688894845|18|0.0%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|94424|94424|16|0.0%|0.0%|
[firehol_proxies](#firehol_proxies)|11989|12246|15|0.1%|0.0%|
[firehol_anonymous](#firehol_anonymous)|18384|82411|15|0.0%|0.0%|
[alienvault_reputation](#alienvault_reputation)|185045|185045|15|0.0%|0.0%|
[fullbogons](#fullbogons)|3770|670213096|13|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|11|1.6%|0.0%|
[firehol_level2](#firehol_level2)|23627|35252|11|0.0%|0.0%|
[et_block](#et_block)|999|18343755|11|0.0%|0.0%|
[blocklist_de](#blocklist_de)|29712|29712|8|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|5|0.0%|0.0%|
[nixspam](#nixspam)|39997|39997|5|0.0%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|4|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6892|6892|4|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7539|7539|4|0.0%|0.0%|
[xroxy](#xroxy)|2151|2151|3|0.1%|0.0%|
[php_dictionary](#php_dictionary)|702|702|3|0.4%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|3|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|18093|18093|3|0.0%|0.0%|
[voipbl](#voipbl)|10533|10945|2|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|10254|10254|2|0.0%|0.0%|
[php_harvesters](#php_harvesters)|378|378|2|0.5%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|1181|1181|2|0.1%|0.0%|
[proxz](#proxz)|1212|1212|1|0.0%|0.0%|
[php_spammers](#php_spammers)|700|700|1|0.1%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|1|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3507|3507|1|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|3592|3592|1|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|2981|2981|1|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14944|14944|1|0.0%|0.0%|

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
[firehol_level3](#firehol_level3)|110340|9628074|9177856|95.3%|100.0%|
[firehol_level1](#firehol_level1)|5135|688894845|7498240|1.0%|81.6%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|6932480|37.7%|75.5%|
[et_block](#et_block)|999|18343755|6932480|37.7%|75.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|2526625|0.7%|27.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|904796|0.1%|9.8%|
[fullbogons](#fullbogons)|3770|670213096|565760|0.0%|6.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|145472|0.1%|1.5%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1036|0.3%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|94424|94424|731|0.7%|0.0%|
[alienvault_reputation](#alienvault_reputation)|185045|185045|518|0.2%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|167|0.5%|0.0%|
[firehol_level2](#firehol_level2)|23627|35252|89|0.2%|0.0%|
[blocklist_de](#blocklist_de)|29712|29712|64|0.2%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|2981|2981|55|1.8%|0.0%|
[nixspam](#nixspam)|39997|39997|37|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6892|6892|30|0.4%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|27|2.0%|0.0%|
[openbl_60d](#openbl_60d)|7022|7022|16|0.2%|0.0%|
[openbl_30d](#openbl_30d)|2843|2843|12|0.4%|0.0%|
[snort_ipfilter](#snort_ipfilter)|10254|10254|11|0.1%|0.0%|
[zeus_badips](#zeus_badips)|202|202|10|4.9%|0.0%|
[zeus](#zeus)|230|230|10|4.3%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|7|0.4%|0.0%|
[firehol_anonymous](#firehol_anonymous)|18384|82411|7|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3507|3507|6|0.1%|0.0%|
[openbl_7d](#openbl_7d)|695|695|5|0.7%|0.0%|
[et_compromised](#et_compromised)|1718|1718|5|0.2%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1712|1712|5|0.2%|0.0%|
[php_dictionary](#php_dictionary)|702|702|4|0.5%|0.0%|
[et_tor](#et_tor)|6340|6340|4|0.0%|0.0%|
[dm_tor](#dm_tor)|6507|6507|4|0.0%|0.0%|
[bm_tor](#bm_tor)|6512|6512|4|0.0%|0.0%|
[shunlist](#shunlist)|1344|1344|3|0.2%|0.0%|
[php_spammers](#php_spammers)|700|700|3|0.4%|0.0%|
[firehol_proxies](#firehol_proxies)|11989|12246|3|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|182|182|3|1.6%|0.0%|
[openbl_1d](#openbl_1d)|170|170|2|1.1%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|2|0.3%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|18093|18093|2|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2407|2407|2|0.0%|0.0%|
[voipbl](#voipbl)|10533|10945|1|0.0%|0.0%|
[php_harvesters](#php_harvesters)|378|378|1|0.2%|0.0%|
[php_commenters](#php_commenters)|403|403|1|0.2%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|1|0.1%|0.0%|
[et_botcc](#et_botcc)|509|509|1|0.1%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|1181|1181|1|0.0%|0.0%|

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
[firehol_level1](#firehol_level1)|5135|688894845|2570531|0.3%|0.3%|
[et_block](#et_block)|999|18343755|2272798|12.3%|0.2%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|2272265|12.3%|0.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|1354507|0.9%|0.1%|
[firehol_level3](#firehol_level3)|110340|9628074|919969|9.5%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|904796|9.8%|0.1%|
[fullbogons](#fullbogons)|3770|670213096|264841|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|33155|6.8%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|13247|3.9%|0.0%|
[alienvault_reputation](#alienvault_reputation)|185045|185045|4218|2.2%|0.0%|
[firehol_anonymous](#firehol_anonymous)|18384|82411|3430|4.1%|0.0%|
[firehol_level2](#firehol_level2)|23627|35252|1661|4.7%|0.0%|
[blocklist_de](#blocklist_de)|29712|29712|1542|5.1%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|94424|94424|1516|1.6%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|18093|18093|1389|7.6%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14944|14944|1332|8.9%|0.0%|
[nixspam](#nixspam)|39997|39997|689|1.7%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|529|1.8%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|394|0.8%|0.0%|
[voipbl](#voipbl)|10533|10945|299|2.7%|0.0%|
[firehol_proxies](#firehol_proxies)|11989|12246|285|2.3%|0.0%|
[dshield](#dshield)|20|5120|257|5.0%|0.0%|
[dm_tor](#dm_tor)|6507|6507|164|2.5%|0.0%|
[bm_tor](#bm_tor)|6512|6512|164|2.5%|0.0%|
[openbl_60d](#openbl_60d)|7022|7022|163|2.3%|0.0%|
[et_tor](#et_tor)|6340|6340|163|2.5%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7539|7539|152|2.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6892|6892|132|1.9%|0.0%|
[snort_ipfilter](#snort_ipfilter)|10254|10254|118|1.1%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|97|6.6%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2724|2724|83|3.0%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|66|5.1%|0.0%|
[openbl_30d](#openbl_30d)|2843|2843|64|2.2%|0.0%|
[xroxy](#xroxy)|2151|2151|58|2.6%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|56|8.4%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3507|3507|56|1.5%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1712|1712|53|3.0%|0.0%|
[et_compromised](#et_compromised)|1718|1718|52|3.0%|0.0%|
[proxz](#proxz)|1212|1212|42|3.4%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|3592|3592|42|1.1%|0.0%|
[et_botcc](#et_botcc)|509|509|39|7.6%|0.0%|
[ciarmy](#ciarmy)|449|449|36|8.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|2981|2981|30|1.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2407|2407|29|1.2%|0.0%|
[shunlist](#shunlist)|1344|1344|27|2.0%|0.0%|
[proxyrss](#proxyrss)|1299|1299|25|1.9%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|21|4.0%|0.0%|
[openbl_7d](#openbl_7d)|695|695|14|2.0%|0.0%|
[php_dictionary](#php_dictionary)|702|702|12|1.7%|0.0%|
[php_harvesters](#php_harvesters)|378|378|11|2.9%|0.0%|
[malc0de](#malc0de)|313|313|11|3.5%|0.0%|
[php_spammers](#php_spammers)|700|700|10|1.4%|0.0%|
[php_commenters](#php_commenters)|403|403|10|2.4%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|1181|1181|10|0.8%|0.0%|
[zeus](#zeus)|230|230|7|3.0%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|82|82|6|7.3%|0.0%|
[bogons](#bogons)|13|592708608|5|0.0%|0.0%|
[zeus_badips](#zeus_badips)|202|202|4|1.9%|0.0%|
[sslbl](#sslbl)|372|372|3|0.8%|0.0%|
[openbl_1d](#openbl_1d)|170|170|3|1.7%|0.0%|
[feodo](#feodo)|105|105|3|2.8%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|123|123|3|2.4%|0.0%|
[virbl](#virbl)|20|20|2|10.0%|0.0%|

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
[firehol_level1](#firehol_level1)|5135|688894845|8867972|1.2%|2.5%|
[et_block](#et_block)|999|18343755|8532519|46.5%|2.4%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|8532506|46.5%|2.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|2830203|2.0%|0.8%|
[firehol_level3](#firehol_level3)|110340|9628074|2537327|26.3%|0.7%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2526625|27.5%|0.7%|
[fullbogons](#fullbogons)|3770|670213096|252415|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|98904|20.2%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|7728|2.2%|0.0%|
[alienvault_reputation](#alienvault_reputation)|185045|185045|6261|3.3%|0.0%|
[firehol_anonymous](#firehol_anonymous)|18384|82411|2883|3.4%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|94424|94424|2508|2.6%|0.0%|
[firehol_level2](#firehol_level2)|23627|35252|1754|4.9%|0.0%|
[blocklist_de](#blocklist_de)|29712|29712|1592|5.3%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|18093|18093|1263|6.9%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14944|14944|1103|7.3%|0.0%|
[nixspam](#nixspam)|39997|39997|1038|2.5%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|790|2.6%|0.0%|
[dshield](#dshield)|20|5120|512|10.0%|0.0%|
[voipbl](#voipbl)|10533|10945|434|3.9%|0.0%|
[firehol_proxies](#firehol_proxies)|11989|12246|387|3.1%|0.0%|
[openbl_60d](#openbl_60d)|7022|7022|320|4.5%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|226|0.4%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7539|7539|221|2.9%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6892|6892|205|2.9%|0.0%|
[et_tor](#et_tor)|6340|6340|183|2.8%|0.0%|
[dm_tor](#dm_tor)|6507|6507|180|2.7%|0.0%|
[bm_tor](#bm_tor)|6512|6512|180|2.7%|0.0%|
[snort_ipfilter](#snort_ipfilter)|10254|10254|164|1.5%|0.0%|
[openbl_30d](#openbl_30d)|2843|2843|147|5.1%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3507|3507|143|4.0%|0.0%|
[xroxy](#xroxy)|2151|2151|104|4.8%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2724|2724|104|3.8%|0.0%|
[et_compromised](#et_compromised)|1718|1718|89|5.1%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|2981|2981|89|2.9%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1712|1712|88|5.1%|0.0%|
[shunlist](#shunlist)|1344|1344|77|5.7%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|3592|3592|71|1.9%|0.0%|
[php_spammers](#php_spammers)|700|700|54|7.7%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2407|2407|53|2.2%|0.0%|
[proxyrss](#proxyrss)|1299|1299|52|4.0%|0.0%|
[proxz](#proxz)|1212|1212|50|4.1%|0.0%|
[ciarmy](#ciarmy)|449|449|48|10.6%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|45|3.1%|0.0%|
[openbl_7d](#openbl_7d)|695|695|40|5.7%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|29|5.5%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|26|2.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|26|3.9%|0.0%|
[php_dictionary](#php_dictionary)|702|702|23|3.2%|0.0%|
[et_botcc](#et_botcc)|509|509|21|4.1%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|1181|1181|18|1.5%|0.0%|
[php_commenters](#php_commenters)|403|403|16|3.9%|0.0%|
[malc0de](#malc0de)|313|313|16|5.1%|0.0%|
[zeus](#zeus)|230|230|9|3.9%|0.0%|
[php_harvesters](#php_harvesters)|378|378|9|2.3%|0.0%|
[zeus_badips](#zeus_badips)|202|202|8|3.9%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|182|182|8|4.3%|0.0%|
[openbl_1d](#openbl_1d)|170|170|7|4.1%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|82|82|7|8.5%|0.0%|
[sslbl](#sslbl)|372|372|6|1.6%|0.0%|
[feodo](#feodo)|105|105|3|2.8%|0.0%|
[virbl](#virbl)|20|20|2|10.0%|0.0%|
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
[firehol_level1](#firehol_level1)|5135|688894845|4637602|0.6%|3.3%|
[fullbogons](#fullbogons)|3770|670213096|4236143|0.6%|3.0%|
[bogons](#bogons)|13|592708608|4194304|0.7%|3.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|2830203|0.8%|2.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|1354507|0.1%|0.9%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|270785|55.5%|0.1%|
[firehol_level3](#firehol_level3)|110340|9628074|161608|1.6%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|145472|1.5%|0.1%|
[et_block](#et_block)|999|18343755|130922|0.7%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|130368|0.7%|0.0%|
[alienvault_reputation](#alienvault_reputation)|185045|185045|13882|7.5%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|9226|2.7%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|94424|94424|5840|6.1%|0.0%|
[firehol_level2](#firehol_level2)|23627|35252|4155|11.7%|0.0%|
[blocklist_de](#blocklist_de)|29712|29712|3751|12.6%|0.0%|
[firehol_anonymous](#firehol_anonymous)|18384|82411|2867|3.4%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|18093|18093|2638|14.5%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14944|14944|2350|15.7%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|1913|6.5%|0.0%|
[nixspam](#nixspam)|39997|39997|1700|4.2%|0.0%|
[voipbl](#voipbl)|10533|10945|1605|14.6%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|1172|2.4%|0.0%|
[openbl_60d](#openbl_60d)|7022|7022|746|10.6%|0.0%|
[dm_tor](#dm_tor)|6507|6507|630|9.6%|0.0%|
[bm_tor](#bm_tor)|6512|6512|630|9.6%|0.0%|
[et_tor](#et_tor)|6340|6340|614|9.6%|0.0%|
[firehol_proxies](#firehol_proxies)|11989|12246|521|4.2%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3507|3507|520|14.8%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6892|6892|467|6.7%|0.0%|
[openbl_30d](#openbl_30d)|2843|2843|296|10.4%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2407|2407|293|12.1%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|3592|3592|263|7.3%|0.0%|
[snort_ipfilter](#snort_ipfilter)|10254|10254|256|2.4%|0.0%|
[dshield](#dshield)|20|5120|256|5.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7539|7539|217|2.8%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|2981|2981|168|5.6%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1712|1712|154|8.9%|0.0%|
[et_compromised](#et_compromised)|1718|1718|153|8.9%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|150|28.6%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|147|11.4%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|1181|1181|140|11.8%|0.0%|
[shunlist](#shunlist)|1344|1344|121|9.0%|0.0%|
[xroxy](#xroxy)|2151|2151|108|5.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|108|7.4%|0.0%|
[proxz](#proxz)|1212|1212|101|8.3%|0.0%|
[ciarmy](#ciarmy)|449|449|99|22.0%|0.0%|
[openbl_7d](#openbl_7d)|695|695|79|11.3%|0.0%|
[et_botcc](#et_botcc)|509|509|77|15.1%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2724|2724|57|2.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|51|7.6%|0.0%|
[proxyrss](#proxyrss)|1299|1299|45|3.4%|0.0%|
[malc0de](#malc0de)|313|313|45|14.3%|0.0%|
[php_spammers](#php_spammers)|700|700|43|6.1%|0.0%|
[php_dictionary](#php_dictionary)|702|702|38|5.4%|0.0%|
[sslbl](#sslbl)|372|372|28|7.5%|0.0%|
[php_commenters](#php_commenters)|403|403|25|6.2%|0.0%|
[php_harvesters](#php_harvesters)|378|378|20|5.2%|0.0%|
[openbl_1d](#openbl_1d)|170|170|18|10.5%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|182|182|17|9.3%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|123|123|16|13.0%|0.0%|
[zeus](#zeus)|230|230|14|6.0%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|82|82|12|14.6%|0.0%|
[feodo](#feodo)|105|105|11|10.4%|0.0%|
[zeus_badips](#zeus_badips)|202|202|10|4.9%|0.0%|
[virbl](#virbl)|20|20|4|20.0%|0.0%|
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
[firehol_proxies](#firehol_proxies)|11989|12246|663|5.4%|100.0%|
[firehol_anonymous](#firehol_anonymous)|18384|82411|663|0.8%|100.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|56|0.0%|8.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|51|0.0%|7.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|26|0.0%|3.9%|
[firehol_level3](#firehol_level3)|110340|9628074|24|0.0%|3.6%|
[stopforumspam_30d](#stopforumspam_30d)|94424|94424|19|0.0%|2.8%|
[ri_web_proxies](#ri_web_proxies)|7539|7539|14|0.1%|2.1%|
[xroxy](#xroxy)|2151|2151|13|0.6%|1.9%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|11|0.0%|1.6%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|11|0.0%|1.6%|
[proxyrss](#proxyrss)|1299|1299|9|0.6%|1.3%|
[ri_connect_proxies](#ri_connect_proxies)|2724|2724|7|0.2%|1.0%|
[proxz](#proxz)|1212|1212|6|0.4%|0.9%|
[firehol_level2](#firehol_level2)|23627|35252|6|0.0%|0.9%|
[stopforumspam_1d](#stopforumspam_1d)|6892|6892|5|0.0%|0.7%|
[blocklist_de](#blocklist_de)|29712|29712|4|0.0%|0.6%|
[blocklist_de_bots](#blocklist_de_bots)|2981|2981|3|0.1%|0.4%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|2|0.0%|0.3%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|2|0.1%|0.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2|0.0%|0.3%|
[firehol_level1](#firehol_level1)|5135|688894845|2|0.0%|0.3%|
[et_block](#et_block)|999|18343755|2|0.0%|0.3%|
[snort_ipfilter](#snort_ipfilter)|10254|10254|1|0.0%|0.1%|
[php_dictionary](#php_dictionary)|702|702|1|0.1%|0.1%|
[nixspam](#nixspam)|39997|39997|1|0.0%|0.1%|
[blocklist_de_mail](#blocklist_de_mail)|18093|18093|1|0.0%|0.1%|
[alienvault_reputation](#alienvault_reputation)|185045|185045|1|0.0%|0.1%|

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
[firehol_level3](#firehol_level3)|110340|9628074|339173|3.5%|100.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|13247|0.0%|3.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|9226|0.0%|2.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|7728|0.0%|2.2%|
[firehol_level1](#firehol_level1)|5135|688894845|1932|0.0%|0.5%|
[et_block](#et_block)|999|18343755|1043|0.0%|0.3%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|1037|0.0%|0.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1036|0.0%|0.3%|
[fullbogons](#fullbogons)|3770|670213096|890|0.0%|0.2%|
[alienvault_reputation](#alienvault_reputation)|185045|185045|289|0.1%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|94424|94424|49|0.0%|0.0%|
[firehol_anonymous](#firehol_anonymous)|18384|82411|28|0.0%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|27|2.0%|0.0%|
[et_tor](#et_tor)|6340|6340|22|0.3%|0.0%|
[dm_tor](#dm_tor)|6507|6507|22|0.3%|0.0%|
[bm_tor](#bm_tor)|6512|6512|22|0.3%|0.0%|
[firehol_level2](#firehol_level2)|23627|35252|20|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|19|1.3%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|18|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|10254|10254|14|0.1%|0.0%|
[nixspam](#nixspam)|39997|39997|13|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6892|6892|11|0.1%|0.0%|
[firehol_proxies](#firehol_proxies)|11989|12246|11|0.0%|0.0%|
[blocklist_de](#blocklist_de)|29712|29712|9|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7539|7539|6|0.0%|0.0%|
[openbl_60d](#openbl_60d)|7022|7022|5|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|5|0.9%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14944|14944|5|0.0%|0.0%|
[voipbl](#voipbl)|10533|10945|4|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|3592|3592|4|0.1%|0.0%|
[openbl_30d](#openbl_30d)|2843|2843|3|0.1%|0.0%|
[malc0de](#malc0de)|313|313|3|0.9%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|3|0.0%|0.0%|
[et_compromised](#et_compromised)|1718|1718|2|0.1%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1712|1712|2|0.1%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|82|82|2|2.4%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|18093|18093|2|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|2981|2981|2|0.0%|0.0%|
[zeus_badips](#zeus_badips)|202|202|1|0.4%|0.0%|
[zeus](#zeus)|230|230|1|0.4%|0.0%|
[xroxy](#xroxy)|2151|2151|1|0.0%|0.0%|
[sslbl](#sslbl)|372|372|1|0.2%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|1|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2724|2724|1|0.0%|0.0%|
[proxz](#proxz)|1212|1212|1|0.0%|0.0%|
[proxyrss](#proxyrss)|1299|1299|1|0.0%|0.0%|
[php_harvesters](#php_harvesters)|378|378|1|0.2%|0.0%|
[php_dictionary](#php_dictionary)|702|702|1|0.1%|0.0%|
[php_commenters](#php_commenters)|403|403|1|0.2%|0.0%|
[palevo](#palevo)|13|13|1|7.6%|0.0%|
[feodo](#feodo)|105|105|1|0.9%|0.0%|
[dshield](#dshield)|20|5120|1|0.0%|0.0%|
[ciarmy](#ciarmy)|449|449|1|0.2%|0.0%|
[bogons](#bogons)|13|592708608|1|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3507|3507|1|0.0%|0.0%|

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
[firehol_level3](#firehol_level3)|110340|9628074|1450|0.0%|100.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|108|0.0%|7.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|97|0.0%|6.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|45|0.0%|3.1%|
[firehol_level1](#firehol_level1)|5135|688894845|39|0.0%|2.6%|
[fullbogons](#fullbogons)|3770|670213096|33|0.0%|2.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|19|0.0%|1.3%|
[et_block](#et_block)|999|18343755|8|0.0%|0.5%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|7|0.0%|0.4%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|6|0.0%|0.4%|
[alienvault_reputation](#alienvault_reputation)|185045|185045|6|0.0%|0.4%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|3|0.2%|0.2%|
[firehol_proxies](#firehol_proxies)|11989|12246|3|0.0%|0.2%|
[firehol_level2](#firehol_level2)|23627|35252|3|0.0%|0.2%|
[firehol_anonymous](#firehol_anonymous)|18384|82411|3|0.0%|0.2%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|2|0.0%|0.1%|
[stopforumspam_30d](#stopforumspam_30d)|94424|94424|2|0.0%|0.1%|
[stopforumspam_1d](#stopforumspam_1d)|6892|6892|2|0.0%|0.1%|
[openbl_60d](#openbl_60d)|7022|7022|2|0.0%|0.1%|
[openbl_30d](#openbl_30d)|2843|2843|2|0.0%|0.1%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|2|0.3%|0.1%|
[blocklist_de](#blocklist_de)|29712|29712|2|0.0%|0.1%|
[snort_ipfilter](#snort_ipfilter)|10254|10254|1|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7539|7539|1|0.0%|0.0%|
[openbl_7d](#openbl_7d)|695|695|1|0.1%|0.0%|
[nixspam](#nixspam)|39997|39997|1|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|1|0.0%|0.0%|
[et_botcc](#et_botcc)|509|509|1|0.1%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|182|182|1|0.5%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3507|3507|1|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|2981|2981|1|0.0%|0.0%|

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
[firehol_level3](#firehol_level3)|110340|9628074|313|0.0%|100.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|45|0.0%|14.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|16|0.0%|5.1%|
[cleanmx_viruses](#cleanmx_viruses)|123|123|13|10.5%|4.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|11|0.0%|3.5%|
[alienvault_reputation](#alienvault_reputation)|185045|185045|10|0.0%|3.1%|
[firehol_level1](#firehol_level1)|5135|688894845|6|0.0%|1.9%|
[et_block](#et_block)|999|18343755|5|0.0%|1.5%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|4|0.0%|1.2%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|4|0.3%|1.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|3|0.0%|0.9%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|1|0.0%|0.3%|
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
[firehol_level3](#firehol_level3)|110340|9628074|1288|0.0%|100.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|147|0.0%|11.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|66|0.0%|5.1%|
[firehol_level1](#firehol_level1)|5135|688894845|39|0.0%|3.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|29|0.0%|2.2%|
[et_block](#et_block)|999|18343755|29|0.0%|2.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|27|0.0%|2.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|27|0.0%|2.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|26|0.0%|2.0%|
[snort_ipfilter](#snort_ipfilter)|10254|10254|13|0.1%|1.0%|
[fullbogons](#fullbogons)|3770|670213096|9|0.0%|0.6%|
[alienvault_reputation](#alienvault_reputation)|185045|185045|8|0.0%|0.6%|
[stopforumspam_30d](#stopforumspam_30d)|94424|94424|4|0.0%|0.3%|
[malc0de](#malc0de)|313|313|4|1.2%|0.3%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|3|0.2%|0.2%|
[zeus](#zeus)|230|230|1|0.4%|0.0%|
[et_botcc](#et_botcc)|509|509|1|0.1%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|123|123|1|0.8%|0.0%|

## maxmind_proxy_fraud

[MaxMind.com](https://www.maxmind.com/en/anonymous-proxy-fraudulent-ip-address-list) list of anonymous proxy fraudelent IP addresses.

Source is downloaded from [this link](https://www.maxmind.com/en/anonymous-proxy-fraudulent-ip-address-list).

The last time downloaded was found to be dated: Wed Jun 10 14:27:07 UTC 2015.

The ipset `maxmind_proxy_fraud` has **524** entries, **524** unique IPs.

The following table shows the overlaps of `maxmind_proxy_fraud` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `maxmind_proxy_fraud`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `maxmind_proxy_fraud`.
- ` this % ` is the percentage **of this ipset (`maxmind_proxy_fraud`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_proxies](#firehol_proxies)|11989|12246|524|4.2%|100.0%|
[firehol_anonymous](#firehol_anonymous)|18384|82411|524|0.6%|100.0%|
[firehol_level3](#firehol_level3)|110340|9628074|343|0.0%|65.4%|
[stopforumspam_30d](#stopforumspam_30d)|94424|94424|342|0.3%|65.2%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|285|0.9%|54.3%|
[snort_ipfilter](#snort_ipfilter)|10254|10254|243|2.3%|46.3%|
[et_tor](#et_tor)|6340|6340|233|3.6%|44.4%|
[dm_tor](#dm_tor)|6507|6507|232|3.5%|44.2%|
[bm_tor](#bm_tor)|6512|6512|232|3.5%|44.2%|
[firehol_level2](#firehol_level2)|23627|35252|226|0.6%|43.1%|
[stopforumspam_1d](#stopforumspam_1d)|6892|6892|225|3.2%|42.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|150|0.0%|28.6%|
[php_commenters](#php_commenters)|403|403|49|12.1%|9.3%|
[alienvault_reputation](#alienvault_reputation)|185045|185045|30|0.0%|5.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|29|0.0%|5.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|21|0.0%|4.0%|
[openbl_60d](#openbl_60d)|7022|7022|20|0.2%|3.8%|
[ri_web_proxies](#ri_web_proxies)|7539|7539|10|0.1%|1.9%|
[php_harvesters](#php_harvesters)|378|378|7|1.8%|1.3%|
[blocklist_de](#blocklist_de)|29712|29712|7|0.0%|1.3%|
[php_spammers](#php_spammers)|700|700|6|0.8%|1.1%|
[php_dictionary](#php_dictionary)|702|702|5|0.7%|0.9%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|5|0.0%|0.9%|
[blocklist_de_bots](#blocklist_de_bots)|2981|2981|4|0.1%|0.7%|
[xroxy](#xroxy)|2151|2151|3|0.1%|0.5%|
[et_block](#et_block)|999|18343755|3|0.0%|0.5%|
[voipbl](#voipbl)|10533|10945|2|0.0%|0.3%|
[proxz](#proxz)|1212|1212|2|0.1%|0.3%|
[blocklist_de_mail](#blocklist_de_mail)|18093|18093|2|0.0%|0.3%|
[blocklist_de_apache](#blocklist_de_apache)|14944|14944|2|0.0%|0.3%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|1|0.0%|0.1%|
[shunlist](#shunlist)|1344|1344|1|0.0%|0.1%|
[ri_connect_proxies](#ri_connect_proxies)|2724|2724|1|0.0%|0.1%|
[proxyrss](#proxyrss)|1299|1299|1|0.0%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.1%|
[firehol_level1](#firehol_level1)|5135|688894845|1|0.0%|0.1%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|3592|3592|1|0.0%|0.1%|

## nixspam

[NiX Spam](http://www.heise.de/ix/NiX-Spam-DNSBL-and-blacklist-for-download-499637.html) IP addresses that sent spam in the last hour - automatically generated entries without distinguishing open proxies from relays, dialup gateways, and so on. All IPs are removed after 12 hours if there is no spam from there.

Source is downloaded from [this link](http://www.dnsbl.manitu.net/download/nixspam-ip.dump.gz).

The last time downloaded was found to be dated: Wed Jun 10 14:30:03 UTC 2015.

The ipset `nixspam` has **39997** entries, **39997** unique IPs.

The following table shows the overlaps of `nixspam` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `nixspam`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `nixspam`.
- ` this % ` is the percentage **of this ipset (`nixspam`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|1700|0.0%|4.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|1038|0.0%|2.5%|
[firehol_level2](#firehol_level2)|23627|35252|990|2.8%|2.4%|
[blocklist_de](#blocklist_de)|29712|29712|983|3.3%|2.4%|
[blocklist_de_mail](#blocklist_de_mail)|18093|18093|919|5.0%|2.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|689|0.0%|1.7%|
[firehol_level3](#firehol_level3)|110340|9628074|624|0.0%|1.5%|
[snort_ipfilter](#snort_ipfilter)|10254|10254|413|4.0%|1.0%|
[stopforumspam_30d](#stopforumspam_30d)|94424|94424|156|0.1%|0.3%|
[firehol_anonymous](#firehol_anonymous)|18384|82411|106|0.1%|0.2%|
[firehol_proxies](#firehol_proxies)|11989|12246|104|0.8%|0.2%|
[php_dictionary](#php_dictionary)|702|702|86|12.2%|0.2%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|80|0.2%|0.2%|
[ri_web_proxies](#ri_web_proxies)|7539|7539|71|0.9%|0.1%|
[php_spammers](#php_spammers)|700|700|70|10.0%|0.1%|
[xroxy](#xroxy)|2151|2151|42|1.9%|0.1%|
[firehol_level1](#firehol_level1)|5135|688894845|42|0.0%|0.1%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|39|0.0%|0.0%|
[et_block](#et_block)|999|18343755|39|0.0%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|37|0.0%|0.0%|
[alienvault_reputation](#alienvault_reputation)|185045|185045|35|0.0%|0.0%|
[proxz](#proxz)|1212|1212|24|1.9%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|2981|2981|21|0.7%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6892|6892|20|0.2%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|3592|3592|19|0.5%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14944|14944|19|0.1%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2407|2407|14|0.5%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|13|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|1181|1181|7|0.5%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2724|2724|6|0.2%|0.0%|
[proxyrss](#proxyrss)|1299|1299|6|0.4%|0.0%|
[php_commenters](#php_commenters)|403|403|6|1.4%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3507|3507|6|0.1%|0.0%|
[openbl_60d](#openbl_60d)|7022|7022|5|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|5|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|3|0.0%|0.0%|
[php_harvesters](#php_harvesters)|378|378|3|0.7%|0.0%|
[et_compromised](#et_compromised)|1718|1718|3|0.1%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1712|1712|3|0.1%|0.0%|
[voipbl](#voipbl)|10533|10945|2|0.0%|0.0%|
[shunlist](#shunlist)|1344|1344|2|0.1%|0.0%|
[dm_tor](#dm_tor)|6507|6507|2|0.0%|0.0%|
[bm_tor](#bm_tor)|6512|6512|2|0.0%|0.0%|
[openbl_7d](#openbl_7d)|695|695|1|0.1%|0.0%|
[openbl_30d](#openbl_30d)|2843|2843|1|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|1|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|1|0.1%|0.0%|
[et_tor](#et_tor)|6340|6340|1|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|182|182|1|0.5%|0.0%|

## openbl_1d

[OpenBL.org](http://www.openbl.org/) last 24 hours IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.

Source is downloaded from [this link](http://www.openbl.org/lists/base_1days.txt).

The last time downloaded was found to be dated: Wed Jun 10 14:32:00 UTC 2015.

The ipset `openbl_1d` has **170** entries, **170** unique IPs.

The following table shows the overlaps of `openbl_1d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl_1d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl_1d`.
- ` this % ` is the percentage **of this ipset (`openbl_1d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|23627|35252|170|0.4%|100.0%|
[openbl_60d](#openbl_60d)|7022|7022|165|2.3%|97.0%|
[firehol_level3](#firehol_level3)|110340|9628074|164|0.0%|96.4%|
[openbl_30d](#openbl_30d)|2843|2843|163|5.7%|95.8%|
[alienvault_reputation](#alienvault_reputation)|185045|185045|162|0.0%|95.2%|
[openbl_7d](#openbl_7d)|695|695|160|23.0%|94.1%|
[blocklist_de](#blocklist_de)|29712|29712|130|0.4%|76.4%|
[blocklist_de_ssh](#blocklist_de_ssh)|3507|3507|125|3.5%|73.5%|
[shunlist](#shunlist)|1344|1344|65|4.8%|38.2%|
[bruteforceblocker](#bruteforceblocker)|1712|1712|62|3.6%|36.4%|
[et_compromised](#et_compromised)|1718|1718|55|3.2%|32.3%|
[blocklist_de_strongips](#blocklist_de_strongips)|182|182|20|10.9%|11.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|18|0.0%|10.5%|
[firehol_level1](#firehol_level1)|5135|688894845|18|0.0%|10.5%|
[et_block](#et_block)|999|18343755|18|0.0%|10.5%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|14|0.0%|8.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|7|0.0%|4.1%|
[blocklist_de_apache](#blocklist_de_apache)|14944|14944|4|0.0%|2.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|3|0.0%|1.7%|
[dshield](#dshield)|20|5120|3|0.0%|1.7%|
[stopforumspam_30d](#stopforumspam_30d)|94424|94424|2|0.0%|1.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2|0.0%|1.1%|
[zeus_badips](#zeus_badips)|202|202|1|0.4%|0.5%|
[zeus](#zeus)|230|230|1|0.4%|0.5%|
[snort_ipfilter](#snort_ipfilter)|10254|10254|1|0.0%|0.5%|
[php_spammers](#php_spammers)|700|700|1|0.1%|0.5%|
[php_commenters](#php_commenters)|403|403|1|0.2%|0.5%|
[ciarmy](#ciarmy)|449|449|1|0.2%|0.5%|
[blocklist_de_mail](#blocklist_de_mail)|18093|18093|1|0.0%|0.5%|
[blocklist_de_imap](#blocklist_de_imap)|2407|2407|1|0.0%|0.5%|

## openbl_30d

[OpenBL.org](http://www.openbl.org/) last 30 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.

Source is downloaded from [this link](http://www.openbl.org/lists/base_30days.txt).

The last time downloaded was found to be dated: Wed Jun 10 12:07:00 UTC 2015.

The ipset `openbl_30d` has **2843** entries, **2843** unique IPs.

The following table shows the overlaps of `openbl_30d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl_30d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl_30d`.
- ` this % ` is the percentage **of this ipset (`openbl_30d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[openbl_60d](#openbl_60d)|7022|7022|2843|40.4%|100.0%|
[firehol_level3](#firehol_level3)|110340|9628074|2843|0.0%|100.0%|
[alienvault_reputation](#alienvault_reputation)|185045|185045|2825|1.5%|99.3%|
[et_compromised](#et_compromised)|1718|1718|930|54.1%|32.7%|
[bruteforceblocker](#bruteforceblocker)|1712|1712|923|53.9%|32.4%|
[firehol_level2](#firehol_level2)|23627|35252|820|2.3%|28.8%|
[blocklist_de](#blocklist_de)|29712|29712|785|2.6%|27.6%|
[blocklist_de_ssh](#blocklist_de_ssh)|3507|3507|751|21.4%|26.4%|
[openbl_7d](#openbl_7d)|695|695|695|100.0%|24.4%|
[shunlist](#shunlist)|1344|1344|547|40.6%|19.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|296|0.0%|10.4%|
[openbl_1d](#openbl_1d)|170|170|163|95.8%|5.7%|
[firehol_level1](#firehol_level1)|5135|688894845|158|0.0%|5.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|147|0.0%|5.1%|
[et_block](#et_block)|999|18343755|127|0.0%|4.4%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|119|0.0%|4.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|64|0.0%|2.2%|
[dshield](#dshield)|20|5120|37|0.7%|1.3%|
[blocklist_de_mail](#blocklist_de_mail)|18093|18093|27|0.1%|0.9%|
[blocklist_de_strongips](#blocklist_de_strongips)|182|182|24|13.1%|0.8%|
[blocklist_de_imap](#blocklist_de_imap)|2407|2407|21|0.8%|0.7%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|12|0.0%|0.4%|
[blocklist_de_apache](#blocklist_de_apache)|14944|14944|6|0.0%|0.2%|
[stopforumspam_30d](#stopforumspam_30d)|94424|94424|5|0.0%|0.1%|
[snort_ipfilter](#snort_ipfilter)|10254|10254|4|0.0%|0.1%|
[voipbl](#voipbl)|10533|10945|3|0.0%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|3|0.0%|0.1%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|2|0.1%|0.0%|
[ciarmy](#ciarmy)|449|449|2|0.4%|0.0%|
[zeus](#zeus)|230|230|1|0.4%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|1|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6892|6892|1|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|1|0.0%|0.0%|
[php_spammers](#php_spammers)|700|700|1|0.1%|0.0%|
[php_commenters](#php_commenters)|403|403|1|0.2%|0.0%|
[nixspam](#nixspam)|39997|39997|1|0.0%|0.0%|
[firehol_anonymous](#firehol_anonymous)|18384|82411|1|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|1181|1181|1|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|2981|2981|1|0.0%|0.0%|

## openbl_60d

[OpenBL.org](http://www.openbl.org/) last 60 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.

Source is downloaded from [this link](http://www.openbl.org/lists/base_60days.txt).

The last time downloaded was found to be dated: Wed Jun 10 12:07:00 UTC 2015.

The ipset `openbl_60d` has **7022** entries, **7022** unique IPs.

The following table shows the overlaps of `openbl_60d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl_60d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl_60d`.
- ` this % ` is the percentage **of this ipset (`openbl_60d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[alienvault_reputation](#alienvault_reputation)|185045|185045|6998|3.7%|99.6%|
[firehol_level3](#firehol_level3)|110340|9628074|2977|0.0%|42.3%|
[openbl_30d](#openbl_30d)|2843|2843|2843|100.0%|40.4%|
[firehol_level2](#firehol_level2)|23627|35252|1041|2.9%|14.8%|
[et_compromised](#et_compromised)|1718|1718|1003|58.3%|14.2%|
[bruteforceblocker](#bruteforceblocker)|1712|1712|988|57.7%|14.0%|
[blocklist_de](#blocklist_de)|29712|29712|986|3.3%|14.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3507|3507|942|26.8%|13.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|746|0.0%|10.6%|
[openbl_7d](#openbl_7d)|695|695|695|100.0%|9.8%|
[shunlist](#shunlist)|1344|1344|578|43.0%|8.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|320|0.0%|4.5%|
[firehol_level1](#firehol_level1)|5135|688894845|297|0.0%|4.2%|
[et_block](#et_block)|999|18343755|247|0.0%|3.5%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|235|0.0%|3.3%|
[openbl_1d](#openbl_1d)|170|170|165|97.0%|2.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|163|0.0%|2.3%|
[dshield](#dshield)|20|5120|59|1.1%|0.8%|
[stopforumspam_30d](#stopforumspam_30d)|94424|94424|48|0.0%|0.6%|
[blocklist_de_mail](#blocklist_de_mail)|18093|18093|34|0.1%|0.4%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|27|0.0%|0.3%|
[snort_ipfilter](#snort_ipfilter)|10254|10254|26|0.2%|0.3%|
[blocklist_de_imap](#blocklist_de_imap)|2407|2407|26|1.0%|0.3%|
[blocklist_de_strongips](#blocklist_de_strongips)|182|182|25|13.7%|0.3%|
[firehol_anonymous](#firehol_anonymous)|18384|82411|23|0.0%|0.3%|
[stopforumspam_1d](#stopforumspam_1d)|6892|6892|20|0.2%|0.2%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|20|3.8%|0.2%|
[firehol_proxies](#firehol_proxies)|11989|12246|20|0.1%|0.2%|
[et_tor](#et_tor)|6340|6340|20|0.3%|0.2%|
[dm_tor](#dm_tor)|6507|6507|20|0.3%|0.2%|
[bm_tor](#bm_tor)|6512|6512|20|0.3%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|16|0.0%|0.2%|
[php_commenters](#php_commenters)|403|403|11|2.7%|0.1%|
[voipbl](#voipbl)|10533|10945|8|0.0%|0.1%|
[blocklist_de_apache](#blocklist_de_apache)|14944|14944|6|0.0%|0.0%|
[nixspam](#nixspam)|39997|39997|5|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|5|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|2981|2981|4|0.1%|0.0%|
[zeus](#zeus)|230|230|2|0.8%|0.0%|
[php_harvesters](#php_harvesters)|378|378|2|0.5%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|2|0.1%|0.0%|
[ciarmy](#ciarmy)|449|449|2|0.4%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|1181|1181|2|0.1%|0.0%|
[zeus_badips](#zeus_badips)|202|202|1|0.4%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|1|0.0%|0.0%|
[php_spammers](#php_spammers)|700|700|1|0.1%|0.0%|

## openbl_7d

[OpenBL.org](http://www.openbl.org/) last 7 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.

Source is downloaded from [this link](http://www.openbl.org/lists/base_7days.txt).

The last time downloaded was found to be dated: Wed Jun 10 12:07:00 UTC 2015.

The ipset `openbl_7d` has **695** entries, **695** unique IPs.

The following table shows the overlaps of `openbl_7d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl_7d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl_7d`.
- ` this % ` is the percentage **of this ipset (`openbl_7d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[openbl_60d](#openbl_60d)|7022|7022|695|9.8%|100.0%|
[openbl_30d](#openbl_30d)|2843|2843|695|24.4%|100.0%|
[firehol_level3](#firehol_level3)|110340|9628074|695|0.0%|100.0%|
[alienvault_reputation](#alienvault_reputation)|185045|185045|689|0.3%|99.1%|
[firehol_level2](#firehol_level2)|23627|35252|421|1.1%|60.5%|
[blocklist_de](#blocklist_de)|29712|29712|386|1.2%|55.5%|
[blocklist_de_ssh](#blocklist_de_ssh)|3507|3507|374|10.6%|53.8%|
[bruteforceblocker](#bruteforceblocker)|1712|1712|326|19.0%|46.9%|
[et_compromised](#et_compromised)|1718|1718|315|18.3%|45.3%|
[shunlist](#shunlist)|1344|1344|227|16.8%|32.6%|
[openbl_1d](#openbl_1d)|170|170|160|94.1%|23.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|79|0.0%|11.3%|
[firehol_level1](#firehol_level1)|5135|688894845|56|0.0%|8.0%|
[et_block](#et_block)|999|18343755|54|0.0%|7.7%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|50|0.0%|7.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|40|0.0%|5.7%|
[blocklist_de_strongips](#blocklist_de_strongips)|182|182|24|13.1%|3.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|14|0.0%|2.0%|
[blocklist_de_mail](#blocklist_de_mail)|18093|18093|7|0.0%|1.0%|
[blocklist_de_imap](#blocklist_de_imap)|2407|2407|7|0.2%|1.0%|
[dshield](#dshield)|20|5120|6|0.1%|0.8%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|5|0.0%|0.7%|
[blocklist_de_apache](#blocklist_de_apache)|14944|14944|4|0.0%|0.5%|
[stopforumspam_30d](#stopforumspam_30d)|94424|94424|2|0.0%|0.2%|
[ciarmy](#ciarmy)|449|449|2|0.4%|0.2%|
[php_spammers](#php_spammers)|700|700|1|0.1%|0.1%|
[php_commenters](#php_commenters)|403|403|1|0.2%|0.1%|
[nixspam](#nixspam)|39997|39997|1|0.0%|0.1%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|1|0.0%|0.1%|
[blocklist_de_ftp](#blocklist_de_ftp)|1181|1181|1|0.0%|0.1%|

## palevo

[Abuse.ch Palevo tracker](https://palevotracker.abuse.ch) worm includes IPs which are being used as botnet C&C for the Palevo crimeware - **excellent list**

Source is downloaded from [this link](https://palevotracker.abuse.ch/blocklists.php?download=ipblocklist).

The last time downloaded was found to be dated: Wed Jun 10 14:09:17 UTC 2015.

The ipset `palevo` has **13** entries, **13** unique IPs.

The following table shows the overlaps of `palevo` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `palevo`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `palevo`.
- ` this % ` is the percentage **of this ipset (`palevo`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level1](#firehol_level1)|5135|688894845|13|0.0%|100.0%|
[et_block](#et_block)|999|18343755|13|0.0%|100.0%|
[snort_ipfilter](#snort_ipfilter)|10254|10254|11|0.1%|84.6%|
[firehol_level3](#firehol_level3)|110340|9628074|11|0.0%|84.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|2|0.0%|15.3%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|7.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|1|0.0%|7.6%|

## php_commenters

[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) comment spammers (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=c&rss=1).

The last time downloaded was found to be dated: Wed Jun 10 13:45:10 UTC 2015.

The ipset `php_commenters` has **403** entries, **403** unique IPs.

The following table shows the overlaps of `php_commenters` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `php_commenters`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `php_commenters`.
- ` this % ` is the percentage **of this ipset (`php_commenters`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level3](#firehol_level3)|110340|9628074|403|0.0%|100.0%|
[stopforumspam_30d](#stopforumspam_30d)|94424|94424|305|0.3%|75.6%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|225|0.7%|55.8%|
[firehol_level2](#firehol_level2)|23627|35252|182|0.5%|45.1%|
[stopforumspam_1d](#stopforumspam_1d)|6892|6892|158|2.2%|39.2%|
[blocklist_de](#blocklist_de)|29712|29712|99|0.3%|24.5%|
[blocklist_de_bots](#blocklist_de_bots)|2981|2981|80|2.6%|19.8%|
[firehol_anonymous](#firehol_anonymous)|18384|82411|76|0.0%|18.8%|
[firehol_proxies](#firehol_proxies)|11989|12246|74|0.6%|18.3%|
[snort_ipfilter](#snort_ipfilter)|10254|10254|58|0.5%|14.3%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|49|9.3%|12.1%|
[et_tor](#et_tor)|6340|6340|48|0.7%|11.9%|
[dm_tor](#dm_tor)|6507|6507|48|0.7%|11.9%|
[bm_tor](#bm_tor)|6512|6512|48|0.7%|11.9%|
[php_spammers](#php_spammers)|700|700|45|6.4%|11.1%|
[blocklist_de_strongips](#blocklist_de_strongips)|182|182|45|24.7%|11.1%|
[firehol_level1](#firehol_level1)|5135|688894845|37|0.0%|9.1%|
[et_block](#et_block)|999|18343755|30|0.0%|7.4%|
[blocklist_de_apache](#blocklist_de_apache)|14944|14944|30|0.2%|7.4%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|29|0.0%|7.1%|
[php_dictionary](#php_dictionary)|702|702|29|4.1%|7.1%|
[blocklist_de_mail](#blocklist_de_mail)|18093|18093|26|0.1%|6.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|25|0.0%|6.2%|
[ri_web_proxies](#ri_web_proxies)|7539|7539|23|0.3%|5.7%|
[alienvault_reputation](#alienvault_reputation)|185045|185045|18|0.0%|4.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|16|0.0%|3.9%|
[php_harvesters](#php_harvesters)|378|378|15|3.9%|3.7%|
[openbl_60d](#openbl_60d)|7022|7022|11|0.1%|2.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|10|0.0%|2.4%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|3592|3592|10|0.2%|2.4%|
[xroxy](#xroxy)|2151|2151|8|0.3%|1.9%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|7|0.0%|1.7%|
[proxz](#proxz)|1212|1212|7|0.5%|1.7%|
[nixspam](#nixspam)|39997|39997|6|0.0%|1.4%|
[ri_connect_proxies](#ri_connect_proxies)|2724|2724|5|0.1%|1.2%|
[proxyrss](#proxyrss)|1299|1299|4|0.3%|0.9%|
[zeus_badips](#zeus_badips)|202|202|1|0.4%|0.2%|
[zeus](#zeus)|230|230|1|0.4%|0.2%|
[openbl_7d](#openbl_7d)|695|695|1|0.1%|0.2%|
[openbl_30d](#openbl_30d)|2843|2843|1|0.0%|0.2%|
[openbl_1d](#openbl_1d)|170|170|1|0.5%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.2%|
[fullbogons](#fullbogons)|3770|670213096|1|0.0%|0.2%|
[et_compromised](#et_compromised)|1718|1718|1|0.0%|0.2%|
[bruteforceblocker](#bruteforceblocker)|1712|1712|1|0.0%|0.2%|
[bogons](#bogons)|13|592708608|1|0.0%|0.2%|
[blocklist_de_ssh](#blocklist_de_ssh)|3507|3507|1|0.0%|0.2%|
[blocklist_de_imap](#blocklist_de_imap)|2407|2407|1|0.0%|0.2%|

## php_dictionary

[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) directory attackers (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=d&rss=1).

The last time downloaded was found to be dated: Wed Jun 10 13:45:11 UTC 2015.

The ipset `php_dictionary` has **702** entries, **702** unique IPs.

The following table shows the overlaps of `php_dictionary` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `php_dictionary`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `php_dictionary`.
- ` this % ` is the percentage **of this ipset (`php_dictionary`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level3](#firehol_level3)|110340|9628074|702|0.0%|100.0%|
[php_spammers](#php_spammers)|700|700|296|42.2%|42.1%|
[stopforumspam_30d](#stopforumspam_30d)|94424|94424|133|0.1%|18.9%|
[firehol_level2](#firehol_level2)|23627|35252|116|0.3%|16.5%|
[blocklist_de](#blocklist_de)|29712|29712|107|0.3%|15.2%|
[firehol_anonymous](#firehol_anonymous)|18384|82411|94|0.1%|13.3%|
[firehol_proxies](#firehol_proxies)|11989|12246|93|0.7%|13.2%|
[snort_ipfilter](#snort_ipfilter)|10254|10254|91|0.8%|12.9%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|88|0.2%|12.5%|
[nixspam](#nixspam)|39997|39997|86|0.2%|12.2%|
[blocklist_de_mail](#blocklist_de_mail)|18093|18093|83|0.4%|11.8%|
[ri_web_proxies](#ri_web_proxies)|7539|7539|64|0.8%|9.1%|
[xroxy](#xroxy)|2151|2151|39|1.8%|5.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|38|0.0%|5.4%|
[php_commenters](#php_commenters)|403|403|29|7.1%|4.1%|
[stopforumspam_1d](#stopforumspam_1d)|6892|6892|26|0.3%|3.7%|
[proxz](#proxz)|1212|1212|23|1.8%|3.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|23|0.0%|3.2%|
[blocklist_de_bots](#blocklist_de_bots)|2981|2981|20|0.6%|2.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|12|0.0%|1.7%|
[alienvault_reputation](#alienvault_reputation)|185045|185045|9|0.0%|1.2%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|6|0.0%|0.8%|
[firehol_level1](#firehol_level1)|5135|688894845|6|0.0%|0.8%|
[et_block](#et_block)|999|18343755|6|0.0%|0.8%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|5|0.9%|0.7%|
[ri_connect_proxies](#ri_connect_proxies)|2724|2724|4|0.1%|0.5%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|4|0.0%|0.5%|
[et_tor](#et_tor)|6340|6340|4|0.0%|0.5%|
[dm_tor](#dm_tor)|6507|6507|4|0.0%|0.5%|
[bm_tor](#bm_tor)|6512|6512|4|0.0%|0.5%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|3592|3592|4|0.1%|0.5%|
[blocklist_de_apache](#blocklist_de_apache)|14944|14944|4|0.0%|0.5%|
[proxyrss](#proxyrss)|1299|1299|3|0.2%|0.4%|
[php_harvesters](#php_harvesters)|378|378|3|0.7%|0.4%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|3|0.0%|0.4%|
[blocklist_de_strongips](#blocklist_de_strongips)|182|182|3|1.6%|0.4%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.1%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|1|0.1%|0.1%|

## php_harvesters

[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) harvesters (IPs that surf the internet looking for email addresses) (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=h&rss=1).

The last time downloaded was found to be dated: Wed Jun 10 13:45:08 UTC 2015.

The ipset `php_harvesters` has **378** entries, **378** unique IPs.

The following table shows the overlaps of `php_harvesters` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `php_harvesters`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `php_harvesters`.
- ` this % ` is the percentage **of this ipset (`php_harvesters`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level3](#firehol_level3)|110340|9628074|378|0.0%|100.0%|
[stopforumspam_30d](#stopforumspam_30d)|94424|94424|83|0.0%|21.9%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|60|0.2%|15.8%|
[firehol_level2](#firehol_level2)|23627|35252|56|0.1%|14.8%|
[stopforumspam_1d](#stopforumspam_1d)|6892|6892|44|0.6%|11.6%|
[blocklist_de](#blocklist_de)|29712|29712|36|0.1%|9.5%|
[blocklist_de_bots](#blocklist_de_bots)|2981|2981|26|0.8%|6.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|20|0.0%|5.2%|
[php_commenters](#php_commenters)|403|403|15|3.7%|3.9%|
[firehol_proxies](#firehol_proxies)|11989|12246|12|0.0%|3.1%|
[firehol_anonymous](#firehol_anonymous)|18384|82411|12|0.0%|3.1%|
[alienvault_reputation](#alienvault_reputation)|185045|185045|12|0.0%|3.1%|
[snort_ipfilter](#snort_ipfilter)|10254|10254|11|0.1%|2.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|11|0.0%|2.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|9|0.0%|2.3%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|7|1.3%|1.8%|
[et_tor](#et_tor)|6340|6340|7|0.1%|1.8%|
[dm_tor](#dm_tor)|6507|6507|7|0.1%|1.8%|
[bm_tor](#bm_tor)|6512|6512|7|0.1%|1.8%|
[blocklist_de_mail](#blocklist_de_mail)|18093|18093|5|0.0%|1.3%|
[php_spammers](#php_spammers)|700|700|3|0.4%|0.7%|
[php_dictionary](#php_dictionary)|702|702|3|0.4%|0.7%|
[nixspam](#nixspam)|39997|39997|3|0.0%|0.7%|
[firehol_level1](#firehol_level1)|5135|688894845|3|0.0%|0.7%|
[blocklist_de_ftp](#blocklist_de_ftp)|1181|1181|3|0.2%|0.7%|
[blocklist_de_apache](#blocklist_de_apache)|14944|14944|3|0.0%|0.7%|
[xroxy](#xroxy)|2151|2151|2|0.0%|0.5%|
[ri_web_proxies](#ri_web_proxies)|7539|7539|2|0.0%|0.5%|
[proxyrss](#proxyrss)|1299|1299|2|0.1%|0.5%|
[openbl_60d](#openbl_60d)|7022|7022|2|0.0%|0.5%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|2|0.0%|0.5%|
[blocklist_de_strongips](#blocklist_de_strongips)|182|182|2|1.0%|0.5%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|3592|3592|2|0.0%|0.5%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|1|0.0%|0.2%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|1|0.0%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.2%|
[fullbogons](#fullbogons)|3770|670213096|1|0.0%|0.2%|
[et_block](#et_block)|999|18343755|1|0.0%|0.2%|
[bogons](#bogons)|13|592708608|1|0.0%|0.2%|
[blocklist_de_imap](#blocklist_de_imap)|2407|2407|1|0.0%|0.2%|

## php_spammers

[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) spam servers (IPs used by spammers to send messages) (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=s&rss=1).

The last time downloaded was found to be dated: Wed Jun 10 13:45:09 UTC 2015.

The ipset `php_spammers` has **700** entries, **700** unique IPs.

The following table shows the overlaps of `php_spammers` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `php_spammers`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `php_spammers`.
- ` this % ` is the percentage **of this ipset (`php_spammers`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level3](#firehol_level3)|110340|9628074|700|0.0%|100.0%|
[php_dictionary](#php_dictionary)|702|702|296|42.1%|42.2%|
[stopforumspam_30d](#stopforumspam_30d)|94424|94424|144|0.1%|20.5%|
[firehol_level2](#firehol_level2)|23627|35252|109|0.3%|15.5%|
[blocklist_de](#blocklist_de)|29712|29712|101|0.3%|14.4%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|87|0.2%|12.4%|
[snort_ipfilter](#snort_ipfilter)|10254|10254|85|0.8%|12.1%|
[firehol_anonymous](#firehol_anonymous)|18384|82411|80|0.0%|11.4%|
[firehol_proxies](#firehol_proxies)|11989|12246|78|0.6%|11.1%|
[nixspam](#nixspam)|39997|39997|70|0.1%|10.0%|
[blocklist_de_mail](#blocklist_de_mail)|18093|18093|69|0.3%|9.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|54|0.0%|7.7%|
[ri_web_proxies](#ri_web_proxies)|7539|7539|53|0.7%|7.5%|
[php_commenters](#php_commenters)|403|403|45|11.1%|6.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|43|0.0%|6.1%|
[xroxy](#xroxy)|2151|2151|32|1.4%|4.5%|
[stopforumspam_1d](#stopforumspam_1d)|6892|6892|32|0.4%|4.5%|
[blocklist_de_bots](#blocklist_de_bots)|2981|2981|24|0.8%|3.4%|
[proxz](#proxz)|1212|1212|21|1.7%|3.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|10|0.0%|1.4%|
[blocklist_de_strongips](#blocklist_de_strongips)|182|182|8|4.3%|1.1%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|3592|3592|7|0.1%|1.0%|
[blocklist_de_apache](#blocklist_de_apache)|14944|14944|7|0.0%|1.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|6|1.1%|0.8%|
[alienvault_reputation](#alienvault_reputation)|185045|185045|6|0.0%|0.8%|
[et_tor](#et_tor)|6340|6340|5|0.0%|0.7%|
[dm_tor](#dm_tor)|6507|6507|5|0.0%|0.7%|
[bm_tor](#bm_tor)|6512|6512|5|0.0%|0.7%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|4|0.0%|0.5%|
[proxyrss](#proxyrss)|1299|1299|4|0.3%|0.5%|
[firehol_level1](#firehol_level1)|5135|688894845|4|0.0%|0.5%|
[et_block](#et_block)|999|18343755|4|0.0%|0.5%|
[ri_connect_proxies](#ri_connect_proxies)|2724|2724|3|0.1%|0.4%|
[php_harvesters](#php_harvesters)|378|378|3|0.7%|0.4%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|0.4%|
[openbl_7d](#openbl_7d)|695|695|1|0.1%|0.1%|
[openbl_60d](#openbl_60d)|7022|7022|1|0.0%|0.1%|
[openbl_30d](#openbl_30d)|2843|2843|1|0.0%|0.1%|
[openbl_1d](#openbl_1d)|170|170|1|0.5%|0.1%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|1|0.0%|0.1%|
[et_compromised](#et_compromised)|1718|1718|1|0.0%|0.1%|
[bruteforceblocker](#bruteforceblocker)|1712|1712|1|0.0%|0.1%|
[blocklist_de_ssh](#blocklist_de_ssh)|3507|3507|1|0.0%|0.1%|

## proxyrss

[proxyrss.com](http://www.proxyrss.com) open proxies syndicated from multiple sources.

Source is downloaded from [this link](http://www.proxyrss.com/proxylists/all.gz).

The last time downloaded was found to be dated: Wed Jun 10 11:21:27 UTC 2015.

The ipset `proxyrss` has **1299** entries, **1299** unique IPs.

The following table shows the overlaps of `proxyrss` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `proxyrss`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `proxyrss`.
- ` this % ` is the percentage **of this ipset (`proxyrss`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_proxies](#firehol_proxies)|11989|12246|1299|10.6%|100.0%|
[firehol_anonymous](#firehol_anonymous)|18384|82411|1299|1.5%|100.0%|
[stopforumspam_30d](#stopforumspam_30d)|94424|94424|661|0.7%|50.8%|
[firehol_level3](#firehol_level3)|110340|9628074|661|0.0%|50.8%|
[ri_web_proxies](#ri_web_proxies)|7539|7539|588|7.7%|45.2%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|517|1.7%|39.7%|
[firehol_level2](#firehol_level2)|23627|35252|407|1.1%|31.3%|
[xroxy](#xroxy)|2151|2151|357|16.5%|27.4%|
[stopforumspam_1d](#stopforumspam_1d)|6892|6892|345|5.0%|26.5%|
[proxz](#proxz)|1212|1212|266|21.9%|20.4%|
[blocklist_de](#blocklist_de)|29712|29712|215|0.7%|16.5%|
[blocklist_de_bots](#blocklist_de_bots)|2981|2981|211|7.0%|16.2%|
[ri_connect_proxies](#ri_connect_proxies)|2724|2724|180|6.6%|13.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|52|0.0%|4.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|45|0.0%|3.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|25|0.0%|1.9%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|9|1.3%|0.6%|
[snort_ipfilter](#snort_ipfilter)|10254|10254|6|0.0%|0.4%|
[nixspam](#nixspam)|39997|39997|6|0.0%|0.4%|
[blocklist_de_strongips](#blocklist_de_strongips)|182|182|6|3.2%|0.4%|
[php_spammers](#php_spammers)|700|700|4|0.5%|0.3%|
[php_commenters](#php_commenters)|403|403|4|0.9%|0.3%|
[php_dictionary](#php_dictionary)|702|702|3|0.4%|0.2%|
[php_harvesters](#php_harvesters)|378|378|2|0.5%|0.1%|
[alienvault_reputation](#alienvault_reputation)|185045|185045|2|0.0%|0.1%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|1|0.1%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|18093|18093|1|0.0%|0.0%|

## proxz

[proxz.com](http://www.proxz.com) open proxies (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.proxz.com/proxylists.xml).

The last time downloaded was found to be dated: Wed Jun 10 13:31:29 UTC 2015.

The ipset `proxz` has **1212** entries, **1212** unique IPs.

The following table shows the overlaps of `proxz` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `proxz`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `proxz`.
- ` this % ` is the percentage **of this ipset (`proxz`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_proxies](#firehol_proxies)|11989|12246|1212|9.8%|100.0%|
[firehol_anonymous](#firehol_anonymous)|18384|82411|1212|1.4%|100.0%|
[firehol_level3](#firehol_level3)|110340|9628074|727|0.0%|59.9%|
[stopforumspam_30d](#stopforumspam_30d)|94424|94424|722|0.7%|59.5%|
[ri_web_proxies](#ri_web_proxies)|7539|7539|556|7.3%|45.8%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|488|1.6%|40.2%|
[xroxy](#xroxy)|2151|2151|435|20.2%|35.8%|
[proxyrss](#proxyrss)|1299|1299|266|20.4%|21.9%|
[firehol_level2](#firehol_level2)|23627|35252|261|0.7%|21.5%|
[ri_connect_proxies](#ri_connect_proxies)|2724|2724|208|7.6%|17.1%|
[stopforumspam_1d](#stopforumspam_1d)|6892|6892|180|2.6%|14.8%|
[blocklist_de](#blocklist_de)|29712|29712|175|0.5%|14.4%|
[blocklist_de_bots](#blocklist_de_bots)|2981|2981|145|4.8%|11.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|101|0.0%|8.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|50|0.0%|4.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|42|0.0%|3.4%|
[blocklist_de_mail](#blocklist_de_mail)|18093|18093|27|0.1%|2.2%|
[snort_ipfilter](#snort_ipfilter)|10254|10254|26|0.2%|2.1%|
[nixspam](#nixspam)|39997|39997|24|0.0%|1.9%|
[php_dictionary](#php_dictionary)|702|702|23|3.2%|1.8%|
[php_spammers](#php_spammers)|700|700|21|3.0%|1.7%|
[php_commenters](#php_commenters)|403|403|7|1.7%|0.5%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|6|0.9%|0.4%|
[blocklist_de_strongips](#blocklist_de_strongips)|182|182|5|2.7%|0.4%|
[alienvault_reputation](#alienvault_reputation)|185045|185045|3|0.0%|0.2%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|2|0.3%|0.1%|
[et_compromised](#et_compromised)|1718|1718|2|0.1%|0.1%|
[bruteforceblocker](#bruteforceblocker)|1712|1712|2|0.1%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|1|0.0%|0.0%|

## ri_connect_proxies

[rosinstrument.com](http://www.rosinstrument.com) open CONNECT proxies (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://tools.rosinstrument.com/proxy/plab100.xml).

The last time downloaded was found to be dated: Wed Jun 10 11:53:52 UTC 2015.

The ipset `ri_connect_proxies` has **2724** entries, **2724** unique IPs.

The following table shows the overlaps of `ri_connect_proxies` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ri_connect_proxies`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ri_connect_proxies`.
- ` this % ` is the percentage **of this ipset (`ri_connect_proxies`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_proxies](#firehol_proxies)|11989|12246|2724|22.2%|100.0%|
[firehol_anonymous](#firehol_anonymous)|18384|82411|2724|3.3%|100.0%|
[stopforumspam_30d](#stopforumspam_30d)|94424|94424|1540|1.6%|56.5%|
[firehol_level3](#firehol_level3)|110340|9628074|1540|0.0%|56.5%|
[ri_web_proxies](#ri_web_proxies)|7539|7539|1159|15.3%|42.5%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|586|1.9%|21.5%|
[xroxy](#xroxy)|2151|2151|390|18.1%|14.3%|
[proxz](#proxz)|1212|1212|208|17.1%|7.6%|
[proxyrss](#proxyrss)|1299|1299|180|13.8%|6.6%|
[firehol_level2](#firehol_level2)|23627|35252|153|0.4%|5.6%|
[stopforumspam_1d](#stopforumspam_1d)|6892|6892|105|1.5%|3.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|104|0.0%|3.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|83|0.0%|3.0%|
[blocklist_de](#blocklist_de)|29712|29712|78|0.2%|2.8%|
[blocklist_de_bots](#blocklist_de_bots)|2981|2981|74|2.4%|2.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|57|0.0%|2.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|7|1.0%|0.2%|
[nixspam](#nixspam)|39997|39997|6|0.0%|0.2%|
[snort_ipfilter](#snort_ipfilter)|10254|10254|5|0.0%|0.1%|
[php_commenters](#php_commenters)|403|403|5|1.2%|0.1%|
[php_dictionary](#php_dictionary)|702|702|4|0.5%|0.1%|
[php_spammers](#php_spammers)|700|700|3|0.4%|0.1%|
[blocklist_de_mail](#blocklist_de_mail)|18093|18093|3|0.0%|0.1%|
[alienvault_reputation](#alienvault_reputation)|185045|185045|3|0.0%|0.1%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|1|0.1%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2407|2407|1|0.0%|0.0%|

## ri_web_proxies

[rosinstrument.com](http://www.rosinstrument.com) open HTTP proxies (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://tools.rosinstrument.com/proxy/l100.xml).

The last time downloaded was found to be dated: Wed Jun 10 11:52:20 UTC 2015.

The ipset `ri_web_proxies` has **7539** entries, **7539** unique IPs.

The following table shows the overlaps of `ri_web_proxies` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ri_web_proxies`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ri_web_proxies`.
- ` this % ` is the percentage **of this ipset (`ri_web_proxies`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_proxies](#firehol_proxies)|11989|12246|7539|61.5%|100.0%|
[firehol_anonymous](#firehol_anonymous)|18384|82411|7539|9.1%|100.0%|
[firehol_level3](#firehol_level3)|110340|9628074|3637|0.0%|48.2%|
[stopforumspam_30d](#stopforumspam_30d)|94424|94424|3591|3.8%|47.6%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|1538|5.2%|20.4%|
[ri_connect_proxies](#ri_connect_proxies)|2724|2724|1159|42.5%|15.3%|
[xroxy](#xroxy)|2151|2151|946|43.9%|12.5%|
[firehol_level2](#firehol_level2)|23627|35252|657|1.8%|8.7%|
[proxyrss](#proxyrss)|1299|1299|588|45.2%|7.7%|
[proxz](#proxz)|1212|1212|556|45.8%|7.3%|
[stopforumspam_1d](#stopforumspam_1d)|6892|6892|447|6.4%|5.9%|
[blocklist_de](#blocklist_de)|29712|29712|426|1.4%|5.6%|
[blocklist_de_bots](#blocklist_de_bots)|2981|2981|349|11.7%|4.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|221|0.0%|2.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|217|0.0%|2.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|152|0.0%|2.0%|
[nixspam](#nixspam)|39997|39997|71|0.1%|0.9%|
[blocklist_de_mail](#blocklist_de_mail)|18093|18093|68|0.3%|0.9%|
[php_dictionary](#php_dictionary)|702|702|64|9.1%|0.8%|
[snort_ipfilter](#snort_ipfilter)|10254|10254|62|0.6%|0.8%|
[php_spammers](#php_spammers)|700|700|53|7.5%|0.7%|
[php_commenters](#php_commenters)|403|403|23|5.7%|0.3%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|14|2.1%|0.1%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|10|1.9%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|6|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|182|182|6|3.2%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|3592|3592|5|0.1%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14944|14944|5|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|4|0.0%|0.0%|
[dm_tor](#dm_tor)|6507|6507|4|0.0%|0.0%|
[bm_tor](#bm_tor)|6512|6512|4|0.0%|0.0%|
[alienvault_reputation](#alienvault_reputation)|185045|185045|4|0.0%|0.0%|
[et_tor](#et_tor)|6340|6340|3|0.0%|0.0%|
[php_harvesters](#php_harvesters)|378|378|2|0.5%|0.0%|
[sslbl](#sslbl)|372|372|1|0.2%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|1|0.0%|0.0%|
[firehol_level1](#firehol_level1)|5135|688894845|1|0.0%|0.0%|
[et_compromised](#et_compromised)|1718|1718|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1712|1712|1|0.0%|0.0%|

## shunlist

[AutoShun.org](http://autoshun.org/) IPs identified as hostile by correlating logs from distributed snort installations running the autoshun plugin

Source is downloaded from [this link](http://www.autoshun.org/files/shunlist.csv).

The last time downloaded was found to be dated: Wed Jun 10 11:30:06 UTC 2015.

The ipset `shunlist` has **1344** entries, **1344** unique IPs.

The following table shows the overlaps of `shunlist` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `shunlist`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `shunlist`.
- ` this % ` is the percentage **of this ipset (`shunlist`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level3](#firehol_level3)|110340|9628074|1344|0.0%|100.0%|
[alienvault_reputation](#alienvault_reputation)|185045|185045|1336|0.7%|99.4%|
[openbl_60d](#openbl_60d)|7022|7022|578|8.2%|43.0%|
[openbl_30d](#openbl_30d)|2843|2843|547|19.2%|40.6%|
[firehol_level2](#firehol_level2)|23627|35252|455|1.2%|33.8%|
[blocklist_de](#blocklist_de)|29712|29712|452|1.5%|33.6%|
[et_compromised](#et_compromised)|1718|1718|451|26.2%|33.5%|
[bruteforceblocker](#bruteforceblocker)|1712|1712|440|25.7%|32.7%|
[blocklist_de_ssh](#blocklist_de_ssh)|3507|3507|413|11.7%|30.7%|
[openbl_7d](#openbl_7d)|695|695|227|32.6%|16.8%|
[firehol_level1](#firehol_level1)|5135|688894845|187|0.0%|13.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|121|0.0%|9.0%|
[et_block](#et_block)|999|18343755|111|0.0%|8.2%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|98|0.0%|7.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|77|0.0%|5.7%|
[openbl_1d](#openbl_1d)|170|170|65|38.2%|4.8%|
[sslbl](#sslbl)|372|372|64|17.2%|4.7%|
[blocklist_de_apache](#blocklist_de_apache)|14944|14944|36|0.2%|2.6%|
[ciarmy](#ciarmy)|449|449|30|6.6%|2.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|27|0.0%|2.0%|
[dshield](#dshield)|20|5120|25|0.4%|1.8%|
[blocklist_de_strongips](#blocklist_de_strongips)|182|182|19|10.4%|1.4%|
[voipbl](#voipbl)|10533|10945|14|0.1%|1.0%|
[stopforumspam_30d](#stopforumspam_30d)|94424|94424|4|0.0%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|0.2%|
[blocklist_de_mail](#blocklist_de_mail)|18093|18093|3|0.0%|0.2%|
[blocklist_de_imap](#blocklist_de_imap)|2407|2407|3|0.1%|0.2%|
[snort_ipfilter](#snort_ipfilter)|10254|10254|2|0.0%|0.1%|
[nixspam](#nixspam)|39997|39997|2|0.0%|0.1%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|1|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6892|6892|1|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|1|0.1%|0.0%|
[firehol_proxies](#firehol_proxies)|11989|12246|1|0.0%|0.0%|
[firehol_anonymous](#firehol_anonymous)|18384|82411|1|0.0%|0.0%|
[et_tor](#et_tor)|6340|6340|1|0.0%|0.0%|
[dm_tor](#dm_tor)|6507|6507|1|0.0%|0.0%|
[bm_tor](#bm_tor)|6512|6512|1|0.0%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|82|82|1|1.2%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|3592|3592|1|0.0%|0.0%|

## snort_ipfilter

[labs.snort.org](https://labs.snort.org/) supplied IP blacklist (this list seems to be updated frequently, but we found no information about it)

Source is downloaded from [this link](http://labs.snort.org/feeds/ip-filter.blf).

The last time downloaded was found to be dated: Wed Jun 10 04:00:00 UTC 2015.

The ipset `snort_ipfilter` has **10254** entries, **10254** unique IPs.

The following table shows the overlaps of `snort_ipfilter` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `snort_ipfilter`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `snort_ipfilter`.
- ` this % ` is the percentage **of this ipset (`snort_ipfilter`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level3](#firehol_level3)|110340|9628074|10254|0.1%|100.0%|
[firehol_anonymous](#firehol_anonymous)|18384|82411|1159|1.4%|11.3%|
[et_tor](#et_tor)|6340|6340|1068|16.8%|10.4%|
[bm_tor](#bm_tor)|6512|6512|1059|16.2%|10.3%|
[dm_tor](#dm_tor)|6507|6507|1058|16.2%|10.3%|
[stopforumspam_30d](#stopforumspam_30d)|94424|94424|826|0.8%|8.0%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|669|2.2%|6.5%|
[firehol_level2](#firehol_level2)|23627|35252|591|1.6%|5.7%|
[nixspam](#nixspam)|39997|39997|413|1.0%|4.0%|
[stopforumspam_1d](#stopforumspam_1d)|6892|6892|411|5.9%|4.0%|
[firehol_proxies](#firehol_proxies)|11989|12246|329|2.6%|3.2%|
[firehol_level1](#firehol_level1)|5135|688894845|300|0.0%|2.9%|
[et_block](#et_block)|999|18343755|299|0.0%|2.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|256|0.0%|2.4%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|243|46.3%|2.3%|
[blocklist_de](#blocklist_de)|29712|29712|213|0.7%|2.0%|
[zeus](#zeus)|230|230|200|86.9%|1.9%|
[zeus_badips](#zeus_badips)|202|202|178|88.1%|1.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|164|0.0%|1.5%|
[blocklist_de_mail](#blocklist_de_mail)|18093|18093|163|0.9%|1.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|118|0.0%|1.1%|
[alienvault_reputation](#alienvault_reputation)|185045|185045|116|0.0%|1.1%|
[php_dictionary](#php_dictionary)|702|702|91|12.9%|0.8%|
[php_spammers](#php_spammers)|700|700|85|12.1%|0.8%|
[feodo](#feodo)|105|105|82|78.0%|0.7%|
[ri_web_proxies](#ri_web_proxies)|7539|7539|62|0.8%|0.6%|
[php_commenters](#php_commenters)|403|403|58|14.3%|0.5%|
[xroxy](#xroxy)|2151|2151|44|2.0%|0.4%|
[sslbl](#sslbl)|372|372|32|8.6%|0.3%|
[blocklist_de_apache](#blocklist_de_apache)|14944|14944|29|0.1%|0.2%|
[proxz](#proxz)|1212|1212|26|2.1%|0.2%|
[openbl_60d](#openbl_60d)|7022|7022|26|0.3%|0.2%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|3592|3592|25|0.6%|0.2%|
[blocklist_de_bots](#blocklist_de_bots)|2981|2981|24|0.8%|0.2%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|19|0.0%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|14|0.0%|0.1%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|13|1.0%|0.1%|
[php_harvesters](#php_harvesters)|378|378|11|2.9%|0.1%|
[palevo](#palevo)|13|13|11|84.6%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|11|0.0%|0.1%|
[blocklist_de_imap](#blocklist_de_imap)|2407|2407|7|0.2%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|6|0.0%|0.0%|
[proxyrss](#proxyrss)|1299|1299|6|0.4%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2724|2724|5|0.1%|0.0%|
[openbl_30d](#openbl_30d)|2843|2843|4|0.1%|0.0%|
[shunlist](#shunlist)|1344|1344|2|0.1%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|2|0.0%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|123|123|2|1.6%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|182|182|2|1.0%|0.0%|
[voipbl](#voipbl)|10533|10945|1|0.0%|0.0%|
[virbl](#virbl)|20|20|1|5.0%|0.0%|
[openbl_1d](#openbl_1d)|170|170|1|0.5%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|1|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|1|0.1%|0.0%|
[et_compromised](#et_compromised)|1718|1718|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1712|1712|1|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3507|3507|1|0.0%|0.0%|

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
[et_block](#et_block)|999|18343755|18338560|99.9%|99.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|8532506|2.4%|46.5%|
[firehol_level3](#firehol_level3)|110340|9628074|6933037|72.0%|37.8%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|6932480|75.5%|37.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|2272265|0.2%|12.3%|
[fullbogons](#fullbogons)|3770|670213096|151552|0.0%|0.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|130368|0.0%|0.7%|
[alienvault_reputation](#alienvault_reputation)|185045|185045|1373|0.7%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1037|0.3%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|94424|94424|1021|1.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|512|0.1%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|294|1.0%|0.0%|
[firehol_level2](#firehol_level2)|23627|35252|278|0.7%|0.0%|
[openbl_60d](#openbl_60d)|7022|7022|235|3.3%|0.0%|
[blocklist_de](#blocklist_de)|29712|29712|215|0.7%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3507|3507|132|3.7%|0.0%|
[openbl_30d](#openbl_30d)|2843|2843|119|4.1%|0.0%|
[et_compromised](#et_compromised)|1718|1718|101|5.8%|0.0%|
[shunlist](#shunlist)|1344|1344|98|7.2%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1712|1712|81|4.7%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6892|6892|80|1.1%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|2981|2981|57|1.9%|0.0%|
[openbl_7d](#openbl_7d)|695|695|50|7.1%|0.0%|
[nixspam](#nixspam)|39997|39997|39|0.0%|0.0%|
[php_commenters](#php_commenters)|403|403|29|7.1%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|29|2.2%|0.0%|
[snort_ipfilter](#snort_ipfilter)|10254|10254|19|0.1%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|18093|18093|19|0.1%|0.0%|
[zeus_badips](#zeus_badips)|202|202|15|7.4%|0.0%|
[zeus](#zeus)|230|230|15|6.5%|0.0%|
[voipbl](#voipbl)|10533|10945|14|0.1%|0.0%|
[openbl_1d](#openbl_1d)|170|170|14|8.2%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2407|2407|11|0.4%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|182|182|8|4.3%|0.0%|
[php_dictionary](#php_dictionary)|702|702|6|0.8%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|6|0.4%|0.0%|
[firehol_anonymous](#firehol_anonymous)|18384|82411|6|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|5|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|3592|3592|5|0.1%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14944|14944|5|0.0%|0.0%|
[php_spammers](#php_spammers)|700|700|4|0.5%|0.0%|
[malc0de](#malc0de)|313|313|4|1.2%|0.0%|
[firehol_proxies](#firehol_proxies)|11989|12246|3|0.0%|0.0%|
[et_tor](#et_tor)|6340|6340|3|0.0%|0.0%|
[dm_tor](#dm_tor)|6507|6507|3|0.0%|0.0%|
[bm_tor](#bm_tor)|6512|6512|3|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|2|0.3%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|82|82|2|2.4%|0.0%|
[sslbl](#sslbl)|372|372|1|0.2%|0.0%|
[php_harvesters](#php_harvesters)|378|378|1|0.2%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|1|0.1%|0.0%|
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
[firehol_level1](#firehol_level1)|5135|688894845|487424|0.0%|100.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|270785|0.1%|55.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|98904|0.0%|20.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|33155|0.0%|6.8%|
[et_block](#et_block)|999|18343755|517|0.0%|0.1%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|512|0.0%|0.1%|
[firehol_level3](#firehol_level3)|110340|9628074|88|0.0%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|94424|94424|78|0.0%|0.0%|
[alienvault_reputation](#alienvault_reputation)|185045|185045|14|0.0%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|9|0.0%|0.0%|
[php_commenters](#php_commenters)|403|403|7|1.7%|0.0%|
[firehol_level2](#firehol_level2)|23627|35252|7|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|10254|10254|6|0.0%|0.0%|
[blocklist_de](#blocklist_de)|29712|29712|6|0.0%|0.0%|
[zeus_badips](#zeus_badips)|202|202|5|2.4%|0.0%|
[zeus](#zeus)|230|230|5|2.1%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|2981|2981|5|0.1%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|182|182|4|2.1%|0.0%|
[nixspam](#nixspam)|39997|39997|3|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6892|6892|2|0.0%|0.0%|
[php_harvesters](#php_harvesters)|378|378|1|0.2%|0.0%|
[openbl_60d](#openbl_60d)|7022|7022|1|0.0%|0.0%|
[openbl_30d](#openbl_30d)|2843|2843|1|0.0%|0.0%|
[malc0de](#malc0de)|313|313|1|0.3%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3507|3507|1|0.0%|0.0%|

## sslbl

[Abuse.ch SSL Blacklist](https://sslbl.abuse.ch/) bad SSL traffic related to malware or botnet activities - **excellent list**

Source is downloaded from [this link](https://sslbl.abuse.ch/blacklist/sslipblacklist.csv).

The last time downloaded was found to be dated: Wed Jun 10 14:15:07 UTC 2015.

The ipset `sslbl` has **372** entries, **372** unique IPs.

The following table shows the overlaps of `sslbl` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `sslbl`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `sslbl`.
- ` this % ` is the percentage **of this ipset (`sslbl`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level1](#firehol_level1)|5135|688894845|372|0.0%|100.0%|
[firehol_level3](#firehol_level3)|110340|9628074|96|0.0%|25.8%|
[alienvault_reputation](#alienvault_reputation)|185045|185045|66|0.0%|17.7%|
[shunlist](#shunlist)|1344|1344|64|4.7%|17.2%|
[feodo](#feodo)|105|105|38|36.1%|10.2%|
[et_block](#et_block)|999|18343755|38|0.0%|10.2%|
[snort_ipfilter](#snort_ipfilter)|10254|10254|32|0.3%|8.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|28|0.0%|7.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|6|0.0%|1.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|3|0.0%|0.8%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|1|0.0%|0.2%|
[ri_web_proxies](#ri_web_proxies)|7539|7539|1|0.0%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.2%|
[firehol_proxies](#firehol_proxies)|11989|12246|1|0.0%|0.2%|
[firehol_anonymous](#firehol_anonymous)|18384|82411|1|0.0%|0.2%|
[blocklist_de_ssh](#blocklist_de_ssh)|3507|3507|1|0.0%|0.2%|

## stopforumspam_1d

[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers in the last 24 hours - **excellent list**

Source is downloaded from [this link](http://www.stopforumspam.com/downloads/listed_ip_1.zip).

The last time downloaded was found to be dated: Wed Jun 10 14:00:02 UTC 2015.

The ipset `stopforumspam_1d` has **6892** entries, **6892** unique IPs.

The following table shows the overlaps of `stopforumspam_1d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `stopforumspam_1d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `stopforumspam_1d`.
- ` this % ` is the percentage **of this ipset (`stopforumspam_1d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|23627|35252|6892|19.5%|100.0%|
[firehol_level3](#firehol_level3)|110340|9628074|6668|0.0%|96.7%|
[stopforumspam_30d](#stopforumspam_30d)|94424|94424|6666|7.0%|96.7%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|5010|17.0%|72.6%|
[blocklist_de](#blocklist_de)|29712|29712|1392|4.6%|20.1%|
[blocklist_de_bots](#blocklist_de_bots)|2981|2981|1316|44.1%|19.0%|
[firehol_anonymous](#firehol_anonymous)|18384|82411|1017|1.2%|14.7%|
[firehol_proxies](#firehol_proxies)|11989|12246|847|6.9%|12.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|467|0.0%|6.7%|
[ri_web_proxies](#ri_web_proxies)|7539|7539|447|5.9%|6.4%|
[snort_ipfilter](#snort_ipfilter)|10254|10254|411|4.0%|5.9%|
[et_tor](#et_tor)|6340|6340|370|5.8%|5.3%|
[dm_tor](#dm_tor)|6507|6507|370|5.6%|5.3%|
[bm_tor](#bm_tor)|6512|6512|370|5.6%|5.3%|
[proxyrss](#proxyrss)|1299|1299|345|26.5%|5.0%|
[xroxy](#xroxy)|2151|2151|229|10.6%|3.3%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|225|42.9%|3.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|205|0.0%|2.9%|
[proxz](#proxz)|1212|1212|180|14.8%|2.6%|
[php_commenters](#php_commenters)|403|403|158|39.2%|2.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|132|0.0%|1.9%|
[blocklist_de_strongips](#blocklist_de_strongips)|182|182|113|62.0%|1.6%|
[ri_connect_proxies](#ri_connect_proxies)|2724|2724|105|3.8%|1.5%|
[firehol_level1](#firehol_level1)|5135|688894845|82|0.0%|1.1%|
[et_block](#et_block)|999|18343755|82|0.0%|1.1%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|80|0.0%|1.1%|
[blocklist_de_apache](#blocklist_de_apache)|14944|14944|76|0.5%|1.1%|
[alienvault_reputation](#alienvault_reputation)|185045|185045|48|0.0%|0.6%|
[php_harvesters](#php_harvesters)|378|378|44|11.6%|0.6%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|3592|3592|43|1.1%|0.6%|
[blocklist_de_mail](#blocklist_de_mail)|18093|18093|39|0.2%|0.5%|
[php_spammers](#php_spammers)|700|700|32|4.5%|0.4%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|30|0.0%|0.4%|
[php_dictionary](#php_dictionary)|702|702|26|3.7%|0.3%|
[openbl_60d](#openbl_60d)|7022|7022|20|0.2%|0.2%|
[nixspam](#nixspam)|39997|39997|20|0.0%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|11|0.0%|0.1%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|5|0.7%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|4|0.0%|0.0%|
[voipbl](#voipbl)|10533|10945|3|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|1181|1181|3|0.2%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|2|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|2|0.1%|0.0%|
[shunlist](#shunlist)|1344|1344|1|0.0%|0.0%|
[openbl_30d](#openbl_30d)|2843|2843|1|0.0%|0.0%|
[et_compromised](#et_compromised)|1718|1718|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1712|1712|1|0.0%|0.0%|

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
[firehol_level3](#firehol_level3)|110340|9628074|94424|0.9%|100.0%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|29338|100.0%|31.0%|
[firehol_level2](#firehol_level2)|23627|35252|8038|22.8%|8.5%|
[stopforumspam_1d](#stopforumspam_1d)|6892|6892|6666|96.7%|7.0%|
[firehol_anonymous](#firehol_anonymous)|18384|82411|6031|7.3%|6.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|5840|0.0%|6.1%|
[firehol_proxies](#firehol_proxies)|11989|12246|5442|44.4%|5.7%|
[ri_web_proxies](#ri_web_proxies)|7539|7539|3591|47.6%|3.8%|
[blocklist_de](#blocklist_de)|29712|29712|2739|9.2%|2.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|2508|0.0%|2.6%|
[blocklist_de_bots](#blocklist_de_bots)|2981|2981|2360|79.1%|2.4%|
[ri_connect_proxies](#ri_connect_proxies)|2724|2724|1540|56.5%|1.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|1516|0.0%|1.6%|
[xroxy](#xroxy)|2151|2151|1272|59.1%|1.3%|
[firehol_level1](#firehol_level1)|5135|688894845|1099|0.0%|1.1%|
[et_block](#et_block)|999|18343755|1027|0.0%|1.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|1021|0.0%|1.0%|
[snort_ipfilter](#snort_ipfilter)|10254|10254|826|8.0%|0.8%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|731|0.0%|0.7%|
[proxz](#proxz)|1212|1212|722|59.5%|0.7%|
[proxyrss](#proxyrss)|1299|1299|661|50.8%|0.7%|
[et_tor](#et_tor)|6340|6340|651|10.2%|0.6%|
[dm_tor](#dm_tor)|6507|6507|649|9.9%|0.6%|
[bm_tor](#bm_tor)|6512|6512|649|9.9%|0.6%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|342|65.2%|0.3%|
[php_commenters](#php_commenters)|403|403|305|75.6%|0.3%|
[blocklist_de_mail](#blocklist_de_mail)|18093|18093|251|1.3%|0.2%|
[blocklist_de_apache](#blocklist_de_apache)|14944|14944|229|1.5%|0.2%|
[alienvault_reputation](#alienvault_reputation)|185045|185045|205|0.1%|0.2%|
[nixspam](#nixspam)|39997|39997|156|0.3%|0.1%|
[php_spammers](#php_spammers)|700|700|144|20.5%|0.1%|
[blocklist_de_strongips](#blocklist_de_strongips)|182|182|138|75.8%|0.1%|
[php_dictionary](#php_dictionary)|702|702|133|18.9%|0.1%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|3592|3592|87|2.4%|0.0%|
[php_harvesters](#php_harvesters)|378|378|83|21.9%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|78|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|49|0.0%|0.0%|
[openbl_60d](#openbl_60d)|7022|7022|48|0.6%|0.0%|
[voipbl](#voipbl)|10533|10945|35|0.3%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3507|3507|23|0.6%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|19|2.8%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|1181|1181|17|1.4%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|16|0.0%|0.0%|
[et_compromised](#et_compromised)|1718|1718|12|0.6%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2407|2407|12|0.4%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1712|1712|11|0.6%|0.0%|
[openbl_30d](#openbl_30d)|2843|2843|5|0.1%|0.0%|
[shunlist](#shunlist)|1344|1344|4|0.2%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|4|0.3%|0.0%|
[zeus_badips](#zeus_badips)|202|202|2|0.9%|0.0%|
[zeus](#zeus)|230|230|2|0.8%|0.0%|
[openbl_7d](#openbl_7d)|695|695|2|0.2%|0.0%|
[openbl_1d](#openbl_1d)|170|170|2|1.1%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|2|0.1%|0.0%|
[ciarmy](#ciarmy)|449|449|2|0.4%|0.0%|
[virbl](#virbl)|20|20|1|5.0%|0.0%|
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
[firehol_level3](#firehol_level3)|110340|9628074|29338|0.3%|100.0%|
[firehol_level2](#firehol_level2)|23627|35252|6015|17.0%|20.5%|
[stopforumspam_1d](#stopforumspam_1d)|6892|6892|5010|72.6%|17.0%|
[firehol_anonymous](#firehol_anonymous)|18384|82411|2748|3.3%|9.3%|
[firehol_proxies](#firehol_proxies)|11989|12246|2409|19.6%|8.2%|
[blocklist_de](#blocklist_de)|29712|29712|2217|7.4%|7.5%|
[blocklist_de_bots](#blocklist_de_bots)|2981|2981|2008|67.3%|6.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|1913|0.0%|6.5%|
[ri_web_proxies](#ri_web_proxies)|7539|7539|1538|20.4%|5.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|790|0.0%|2.6%|
[snort_ipfilter](#snort_ipfilter)|10254|10254|669|6.5%|2.2%|
[xroxy](#xroxy)|2151|2151|624|29.0%|2.1%|
[ri_connect_proxies](#ri_connect_proxies)|2724|2724|586|21.5%|1.9%|
[et_tor](#et_tor)|6340|6340|533|8.4%|1.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|529|0.0%|1.8%|
[dm_tor](#dm_tor)|6507|6507|529|8.1%|1.8%|
[bm_tor](#bm_tor)|6512|6512|529|8.1%|1.8%|
[proxyrss](#proxyrss)|1299|1299|517|39.7%|1.7%|
[proxz](#proxz)|1212|1212|488|40.2%|1.6%|
[firehol_level1](#firehol_level1)|5135|688894845|302|0.0%|1.0%|
[et_block](#et_block)|999|18343755|297|0.0%|1.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|294|0.0%|1.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|285|54.3%|0.9%|
[php_commenters](#php_commenters)|403|403|225|55.8%|0.7%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|167|0.0%|0.5%|
[blocklist_de_mail](#blocklist_de_mail)|18093|18093|139|0.7%|0.4%|
[blocklist_de_apache](#blocklist_de_apache)|14944|14944|139|0.9%|0.4%|
[blocklist_de_strongips](#blocklist_de_strongips)|182|182|120|65.9%|0.4%|
[alienvault_reputation](#alienvault_reputation)|185045|185045|103|0.0%|0.3%|
[php_dictionary](#php_dictionary)|702|702|88|12.5%|0.2%|
[php_spammers](#php_spammers)|700|700|87|12.4%|0.2%|
[nixspam](#nixspam)|39997|39997|80|0.2%|0.2%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|3592|3592|64|1.7%|0.2%|
[php_harvesters](#php_harvesters)|378|378|60|15.8%|0.2%|
[openbl_60d](#openbl_60d)|7022|7022|27|0.3%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|18|0.0%|0.0%|
[voipbl](#voipbl)|10533|10945|14|0.1%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|11|1.6%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|9|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|1181|1181|7|0.5%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3507|3507|6|0.1%|0.0%|
[et_compromised](#et_compromised)|1718|1718|5|0.2%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|4|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1712|1712|4|0.2%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2407|2407|3|0.1%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|2|0.1%|0.0%|
[zeus_badips](#zeus_badips)|202|202|1|0.4%|0.0%|
[zeus](#zeus)|230|230|1|0.4%|0.0%|
[shunlist](#shunlist)|1344|1344|1|0.0%|0.0%|
[openbl_30d](#openbl_30d)|2843|2843|1|0.0%|0.0%|
[ciarmy](#ciarmy)|449|449|1|0.2%|0.0%|

## virbl

[VirBL](http://virbl.bit.nl/) is a project of which the idea was born during the RIPE-48 meeting. The plan was to get reports of virusscanning mailservers, and put the IP-addresses that were reported to send viruses on a blacklist.

Source is downloaded from [this link](http://virbl.bit.nl/download/virbl.dnsbl.bit.nl.txt).

The last time downloaded was found to be dated: Wed Jun 10 13:42:03 UTC 2015.

The ipset `virbl` has **20** entries, **20** unique IPs.

The following table shows the overlaps of `virbl` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `virbl`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `virbl`.
- ` this % ` is the percentage **of this ipset (`virbl`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level3](#firehol_level3)|110340|9628074|20|0.0%|100.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|4|0.0%|20.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|2|0.0%|10.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|2|0.0%|10.0%|
[stopforumspam_30d](#stopforumspam_30d)|94424|94424|1|0.0%|5.0%|
[snort_ipfilter](#snort_ipfilter)|10254|10254|1|0.0%|5.0%|

## voipbl

[VoIPBL.org](http://www.voipbl.org/) a distributed VoIP blacklist that is aimed to protects against VoIP Fraud and minimizing abuse for network that have publicly accessible PBX's. Several algorithms, external sources and manual confirmation are used before they categorize something as an attack and determine the threat level.

Source is downloaded from [this link](http://www.voipbl.org/update/).

The last time downloaded was found to be dated: Wed Jun 10 14:36:26 UTC 2015.

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
[alienvault_reputation](#alienvault_reputation)|185045|185045|193|0.1%|1.7%|
[firehol_anonymous](#firehol_anonymous)|18384|82411|79|0.0%|0.7%|
[firehol_level3](#firehol_level3)|110340|9628074|59|0.0%|0.5%|
[stopforumspam_30d](#stopforumspam_30d)|94424|94424|35|0.0%|0.3%|
[firehol_level2](#firehol_level2)|23627|35252|34|0.0%|0.3%|
[blocklist_de](#blocklist_de)|29712|29712|31|0.1%|0.2%|
[blocklist_de_sip](#blocklist_de_sip)|82|82|27|32.9%|0.2%|
[et_block](#et_block)|999|18343755|18|0.0%|0.1%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|14|0.0%|0.1%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|14|0.0%|0.1%|
[shunlist](#shunlist)|1344|1344|14|1.0%|0.1%|
[openbl_60d](#openbl_60d)|7022|7022|8|0.1%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|4|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6892|6892|3|0.0%|0.0%|
[openbl_30d](#openbl_30d)|2843|2843|3|0.1%|0.0%|
[et_tor](#et_tor)|6340|6340|3|0.0%|0.0%|
[dm_tor](#dm_tor)|6507|6507|3|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1712|1712|3|0.1%|0.0%|
[bm_tor](#bm_tor)|6512|6512|3|0.0%|0.0%|
[nixspam](#nixspam)|39997|39997|2|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|2|0.3%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|2|0.0%|0.0%|
[firehol_proxies](#firehol_proxies)|11989|12246|2|0.0%|0.0%|
[et_compromised](#et_compromised)|1718|1718|2|0.1%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3507|3507|2|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14944|14944|2|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|10254|10254|1|0.0%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.0%|
[ciarmy](#ciarmy)|449|449|1|0.2%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|3592|3592|1|0.0%|0.0%|

## xroxy

[xroxy.com](http://www.xroxy.com) open proxies (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.xroxy.com/proxyrss.xml).

The last time downloaded was found to be dated: Wed Jun 10 14:33:02 UTC 2015.

The ipset `xroxy` has **2151** entries, **2151** unique IPs.

The following table shows the overlaps of `xroxy` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `xroxy`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `xroxy`.
- ` this % ` is the percentage **of this ipset (`xroxy`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_proxies](#firehol_proxies)|11989|12246|2151|17.5%|100.0%|
[firehol_anonymous](#firehol_anonymous)|18384|82411|2151|2.6%|100.0%|
[firehol_level3](#firehol_level3)|110340|9628074|1287|0.0%|59.8%|
[stopforumspam_30d](#stopforumspam_30d)|94424|94424|1272|1.3%|59.1%|
[ri_web_proxies](#ri_web_proxies)|7539|7539|946|12.5%|43.9%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|624|2.1%|29.0%|
[proxz](#proxz)|1212|1212|435|35.8%|20.2%|
[ri_connect_proxies](#ri_connect_proxies)|2724|2724|390|14.3%|18.1%|
[proxyrss](#proxyrss)|1299|1299|357|27.4%|16.5%|
[firehol_level2](#firehol_level2)|23627|35252|325|0.9%|15.1%|
[stopforumspam_1d](#stopforumspam_1d)|6892|6892|229|3.3%|10.6%|
[blocklist_de](#blocklist_de)|29712|29712|196|0.6%|9.1%|
[blocklist_de_bots](#blocklist_de_bots)|2981|2981|145|4.8%|6.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|108|0.0%|5.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|104|0.0%|4.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|58|0.0%|2.6%|
[blocklist_de_mail](#blocklist_de_mail)|18093|18093|51|0.2%|2.3%|
[snort_ipfilter](#snort_ipfilter)|10254|10254|44|0.4%|2.0%|
[nixspam](#nixspam)|39997|39997|42|0.1%|1.9%|
[php_dictionary](#php_dictionary)|702|702|39|5.5%|1.8%|
[php_spammers](#php_spammers)|700|700|32|4.5%|1.4%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|13|1.9%|0.6%|
[php_commenters](#php_commenters)|403|403|8|1.9%|0.3%|
[blocklist_de_strongips](#blocklist_de_strongips)|182|182|6|3.2%|0.2%|
[alienvault_reputation](#alienvault_reputation)|185045|185045|5|0.0%|0.2%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|524|524|3|0.5%|0.1%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|3|0.0%|0.1%|
[php_harvesters](#php_harvesters)|378|378|2|0.5%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.0%|
[et_tor](#et_tor)|6340|6340|1|0.0%|0.0%|
[et_compromised](#et_compromised)|1718|1718|1|0.0%|0.0%|
[et_block](#et_block)|999|18343755|1|0.0%|0.0%|
[dm_tor](#dm_tor)|6507|6507|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1712|1712|1|0.0%|0.0%|
[bm_tor](#bm_tor)|6512|6512|1|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2407|2407|1|0.0%|0.0%|

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
[et_block](#et_block)|999|18343755|228|0.0%|99.1%|
[firehol_level3](#firehol_level3)|110340|9628074|203|0.0%|88.2%|
[zeus_badips](#zeus_badips)|202|202|202|100.0%|87.8%|
[snort_ipfilter](#snort_ipfilter)|10254|10254|200|1.9%|86.9%|
[alienvault_reputation](#alienvault_reputation)|185045|185045|61|0.0%|26.5%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|15|0.0%|6.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|14|0.0%|6.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|10|0.0%|4.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|9|0.0%|3.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|7|0.0%|3.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|5|0.0%|2.1%|
[stopforumspam_30d](#stopforumspam_30d)|94424|94424|2|0.0%|0.8%|
[openbl_60d](#openbl_60d)|7022|7022|2|0.0%|0.8%|
[firehol_level2](#firehol_level2)|23627|35252|2|0.0%|0.8%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|1|0.0%|0.4%|
[php_commenters](#php_commenters)|403|403|1|0.2%|0.4%|
[openbl_30d](#openbl_30d)|2843|2843|1|0.0%|0.4%|
[openbl_1d](#openbl_1d)|170|170|1|0.5%|0.4%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|1|0.0%|0.4%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.4%|
[blocklist_de_mail](#blocklist_de_mail)|18093|18093|1|0.0%|0.4%|
[blocklist_de](#blocklist_de)|29712|29712|1|0.0%|0.4%|

## zeus_badips

[Abuse.ch Zeus tracker](https://zeustracker.abuse.ch) badips includes IPv4 addresses that are used by the ZeuS trojan. It is the recommened blocklist if you want to block only ZeuS IPs. It excludes IP addresses that ZeuS Tracker believes to be hijacked (level 2) or belong to a free web hosting provider (level 3). Hence the false postive rate should be much lower compared to the standard ZeuS IP blocklist. **excellent list**

Source is downloaded from [this link](https://zeustracker.abuse.ch/blocklist.php?download=badips).

The last time downloaded was found to be dated: Wed Jun 10 14:09:15 UTC 2015.

The ipset `zeus_badips` has **202** entries, **202** unique IPs.

The following table shows the overlaps of `zeus_badips` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `zeus_badips`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `zeus_badips`.
- ` this % ` is the percentage **of this ipset (`zeus_badips`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[zeus](#zeus)|230|230|202|87.8%|100.0%|
[firehol_level1](#firehol_level1)|5135|688894845|202|0.0%|100.0%|
[et_block](#et_block)|999|18343755|202|0.0%|100.0%|
[firehol_level3](#firehol_level3)|110340|9628074|180|0.0%|89.1%|
[snort_ipfilter](#snort_ipfilter)|10254|10254|178|1.7%|88.1%|
[alienvault_reputation](#alienvault_reputation)|185045|185045|37|0.0%|18.3%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|15|0.0%|7.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|10|0.0%|4.9%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|10|0.0%|4.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|8|0.0%|3.9%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|5|0.0%|2.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|4|0.0%|1.9%|
[stopforumspam_30d](#stopforumspam_30d)|94424|94424|2|0.0%|0.9%|
[firehol_level2](#firehol_level2)|23627|35252|2|0.0%|0.9%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|1|0.0%|0.4%|
[php_commenters](#php_commenters)|403|403|1|0.2%|0.4%|
[openbl_60d](#openbl_60d)|7022|7022|1|0.0%|0.4%|
[openbl_1d](#openbl_1d)|170|170|1|0.5%|0.4%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.4%|
[blocklist_de_mail](#blocklist_de_mail)|18093|18093|1|0.0%|0.4%|
[blocklist_de](#blocklist_de)|29712|29712|1|0.0%|0.4%|
