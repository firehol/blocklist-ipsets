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

The following list was automatically generated on Fri Jun  5 23:20:48 UTC 2015.

The update frequency is the maximum allowed by internal configuration. A list will never be downloaded sooner than the update frequency stated. A list may also not be downloaded, after this frequency expired, if it has not been modified on the server (as reported by HTTP `IF_MODIFIED_SINCE` method).

name|info|type|entries|update|
:--:|:--:|:--:|:-----:|:----:|
[alienvault_reputation](#alienvault_reputation)|[AlienVault.com](https://www.alienvault.com/) IP reputation database (this list seems to include port scanning hosts and to be updated regularly, but we found no information about its retention policy)|ipv4 hash:ip|176034 unique IPs|updated every 6 hours  from [this link](https://reputation.alienvault.com/reputation.generic)
[blocklist_de](#blocklist_de)|[Blocklist.de](https://www.blocklist.de/) IPs that have been detected by fail2ban in the last 48 hours - **excellent list**|ipv4 hash:ip|28768 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/all.txt)
[blocklist_de_apache](#blocklist_de_apache)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service Apache, Apache-DDOS, RFI-Attacks.|ipv4 hash:ip|15058 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/apache.txt)
[blocklist_de_bots](#blocklist_de_bots)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the RFI-Attacks, REG-Bots, IRC-Bots or BadBots (BadBots = he has posted a Spam-Comment on a open Forum or Wiki).|ipv4 hash:ip|3330 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/bots.txt)
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|[Blocklist.de](https://www.blocklist.de/) All IPs which attacks Joomlas, Wordpress and other Web-Logins with Brute-Force Logins.|ipv4 hash:ip|3708 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/bruteforcelogin.txt)
[blocklist_de_ftp](#blocklist_de_ftp)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours for attacks on the Service FTP.|ipv4 hash:ip|868 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/ftp.txt)
[blocklist_de_imap](#blocklist_de_imap)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours for attacks on the Service imap, sasl, pop3, etc.|ipv4 hash:ip|2050 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/imap.txt)
[blocklist_de_mail](#blocklist_de_mail)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service Mail, Postfix.|ipv4 hash:ip|16032 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/mail.txt)
[blocklist_de_sip](#blocklist_de_sip)|[Blocklist.de](https://www.blocklist.de/) All IP addresses that tried to login in a SIP, VOIP or Asterisk Server and are included in the IPs list from [infiltrated.net](www.infiltrated.net)|ipv4 hash:ip|92 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/sip.txt)
[blocklist_de_ssh](#blocklist_de_ssh)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service SSH.|ipv4 hash:ip|4496 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/ssh.txt)
[blocklist_de_strongips](#blocklist_de_strongips)|[Blocklist.de](https://www.blocklist.de/) All IPs which are older then 2 month and have more then 5.000 attacks.|ipv4 hash:ip|180 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/strongips.txt)
[bm_tor](#bm_tor)|[torstatus.blutmagie.de](https://torstatus.blutmagie.de) list of all TOR network servers|ipv4 hash:ip|6533 unique IPs|updated every 30 mins  from [this link](https://torstatus.blutmagie.de/ip_list_all.php/Tor_ip_list_ALL.csv)
[bogons](#bogons)|[Team-Cymru.org](http://www.team-cymru.org) private and reserved addresses defined by RFC 1918, RFC 5735, and RFC 6598 and netblocks that have not been allocated to a regional internet registry - **excellent list - use it only your internet interface**|ipv4 hash:net|13 subnets, 592708608 unique IPs|updated every 1 day  from [this link](http://www.team-cymru.org/Services/Bogons/bogon-bn-agg.txt)
[bruteforceblocker](#bruteforceblocker)|[danger.rulez.sk](http://danger.rulez.sk/) IPs detected by [bruteforceblocker](http://danger.rulez.sk/index.php/bruteforceblocker/) (fail2ban alternative for SSH on OpenBSD). This is an automatically generated list from users reporting failed authentication attempts. An IP seems to be included if 3 or more users report it. Its retention pocily seems 30 days.|ipv4 hash:ip|1977 unique IPs|updated every 3 hours  from [this link](http://danger.rulez.sk/projects/bruteforceblocker/blist.php)
[ciarmy](#ciarmy)|[CIArmy.com](http://ciarmy.com/) IPs with poor Rogue Packet score that have not yet been identified as malicious by the community|ipv4 hash:ip|421 unique IPs|updated every 3 hours  from [this link](http://cinsscore.com/list/ci-badguys.txt)
[cleanmx_viruses](#cleanmx_viruses)|[Clean-MX.de](http://support.clean-mx.de/clean-mx/viruses.php) IPs with viruses|ipv4 hash:ip|359 unique IPs|updated every 12 hours  from [this link](http://support.clean-mx.de/clean-mx/xmlviruses.php?sort=id%20desc&response=alive)
[dm_tor](#dm_tor)|[dan.me.uk](https://www.dan.me.uk) dynamic list of TOR exit points|ipv4 hash:ip|6483 unique IPs|updated every 30 mins  from [this link](https://www.dan.me.uk/torlist/)
[dshield](#dshield)|[DShield.org](https://dshield.org/) top 20 attacking class C (/24) subnets over the last three days - **excellent list**|ipv4 hash:net|20 subnets, 5120 unique IPs|updated every 4 hours  from [this link](http://feeds.dshield.org/block.txt)
[et_block](#et_block)|[EmergingThreats.net](http://www.emergingthreats.net/) default blacklist (at the time of writing includes spamhaus DROP, dshield and abuse.ch trackers, which are available separately too - prefer to use the direct ipsets instead of this, they seem to lag a bit in updates)|ipv4 hash:net|1016 subnets, 18338655 unique IPs|updated every 12 hours  from [this link](http://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt)
[et_botcc](#et_botcc)|[EmergingThreats.net Command and Control IPs](http://doc.emergingthreats.net/bin/view/Main/BotCC) These IPs are updates every 24 hours and should be considered VERY highly reliable indications that a host is communicating with a known and active Bot or Malware command and control server - (although they say this includes abuse.ch trackers, it does not - most probably it is the shadowserver.org C&C list)|ipv4 hash:ip|509 unique IPs|updated every 12 hours  from [this link](http://rules.emergingthreats.net/fwrules/emerging-PIX-CC.rules)
[et_compromised](#et_compromised)|[EmergingThreats.net compromised hosts](http://doc.emergingthreats.net/bin/view/Main/CompromisedHost) - (this seems to be based on bruteforceblocker)|ipv4 hash:ip|2086 unique IPs|updated every 12 hours  from [this link](http://rules.emergingthreats.net/blockrules/compromised-ips.txt)
et_dshield|[EmergingThreats.net](http://www.emergingthreats.net/) dshield blocklist|ipv4 hash:net|disabled|updated every 12 hours  from [this link](http://rules.emergingthreats.net/fwrules/emerging-PIX-DSHIELD.rules)
et_spamhaus|[EmergingThreats.net](http://www.emergingthreats.net/) spamhaus blocklist|ipv4 hash:net|disabled|updated every 12 hours  from [this link](http://rules.emergingthreats.net/fwrules/emerging-PIX-DROP.rules)
[et_tor](#et_tor)|[EmergingThreats.net](http://www.emergingthreats.net/) [list](http://doc.emergingthreats.net/bin/view/Main/TorRules) of TOR network IPs|ipv4 hash:ip|6610 unique IPs|updated every 12 hours  from [this link](http://rules.emergingthreats.net/blockrules/emerging-tor.rules)
[feodo](#feodo)|[Abuse.ch Feodo tracker](https://feodotracker.abuse.ch) trojan includes IPs which are being used by Feodo (also known as Cridex or Bugat) which commits ebanking fraud - **excellent list**|ipv4 hash:ip|96 unique IPs|updated every 30 mins  from [this link](https://feodotracker.abuse.ch/blocklist/?download=ipblocklist)
[fullbogons](#fullbogons)|[Team-Cymru.org](http://www.team-cymru.org) IP space that has been allocated to an RIR, but not assigned by that RIR to an actual ISP or other end-user - **excellent list - use it only your internet interface**|ipv4 hash:net|3715 subnets, 670310296 unique IPs|updated every 1 day  from [this link](http://www.team-cymru.org/Services/Bogons/fullbogons-ipv4.txt)
[geolite2_country](https://github.com/ktsaou/blocklist-ipsets/tree/master/geolite2_country)|[MaxMind GeoLite2](http://dev.maxmind.com/geoip/geoip2/geolite2/) databases are free IP geolocation databases comparable to, but less accurate than, MaxMind’s GeoIP2 databases. They include IPs per country, IPs per continent, IPs used by anonymous services (VPNs, Proxies, etc) and Satellite Providers.|ipv4 hash:net|All the world|updated every 7 days  from [this link](http://geolite.maxmind.com/download/geoip/database/GeoLite2-Country-CSV.zip)
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|[iBlocklist.com](https://www.iblocklist.com/) free version of [BlueTack.co.uk](http://www.bluetack.co.uk/) IPs that have been reported for bad deeds in p2p|ipv4 hash:ip|48134 unique IPs|updated every 12 hours  from [this link](http://list.iblocklist.com/?list=cwworuawihqvocglcoss&fileformat=p2p&archiveformat=gz)
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|[iBlocklist.com](https://www.iblocklist.com/) free version of [BlueTack.co.uk](http://www.bluetack.co.uk/) hijacked IP-Blocks Hijacked IP space are IP blocks that are being used without permission|ipv4 hash:net|535 subnets, 9177856 unique IPs|updated every 12 hours  from [this link](http://list.iblocklist.com/?list=usrcshglbiilevmyfhse&fileformat=p2p&archiveformat=gz)
[ib_bluetack_level1](#ib_bluetack_level1)|[iBlocklist.com](https://www.iblocklist.com/) free version of [BlueTack.co.uk](http://www.bluetack.co.uk/) Level 1 (for use in p2p): Companies or organizations who are clearly involved with trying to stop filesharing (e.g. Baytsp, MediaDefender, Mediasentry a.o.). Companies which anti-p2p activity has been seen from. Companies that produce or have a strong financial interest in copyrighted material (e.g. music, movie, software industries a.o.). Government ranges or companies that have a strong financial interest in doing work for governments. Legal industry ranges. IPs or ranges of ISPs from which anti-p2p activity has been observed. Basically this list will block all kinds of internet connections that most people would rather not have during their internet travels.|ipv4 hash:net|218309 subnets, 764987411 unique IPs|updated every 12 hours  from [this link](http://list.iblocklist.com/?list=ydxerpxkpcfqjaybcssw&fileformat=p2p&archiveformat=gz)
[ib_bluetack_level2](#ib_bluetack_level2)|[iBlocklist.com](https://www.iblocklist.com/) free version of BlueTack.co.uk Level 2 (for use in p2p). General corporate ranges. Ranges used by labs or researchers. Proxies.|ipv4 hash:net|72774 subnets, 348707599 unique IPs|updated every 12 hours  from [this link](http://list.iblocklist.com/?list=gyisgnzbhppbvsphucsw&fileformat=p2p&archiveformat=gz)
badips.com categories ipsets|[BadIPs.com](https://www.badips.com) community based IP blacklisting. They score IPs based on the reports they reports.|ipv4 hash:ip|disabled|disabled
[ib_bluetack_proxies](#ib_bluetack_proxies)|[iBlocklist.com](https://www.iblocklist.com/) free version of [BlueTack.co.uk](http://www.bluetack.co.uk/) Open Proxies IPs list (without TOR)|ipv4 hash:ip|673 unique IPs|updated every 12 hours  from [this link](http://list.iblocklist.com/?list=xoebmbyexwuiogmbyprb&fileformat=p2p&archiveformat=gz)
[ib_bluetack_spyware](#ib_bluetack_spyware)|[iBlocklist.com](https://www.iblocklist.com/) free version of [BlueTack.co.uk](http://www.bluetack.co.uk/) known malicious SPYWARE and ADWARE IP Address ranges|ipv4 hash:net|3274 subnets, 339192 unique IPs|updated every 12 hours  from [this link](http://list.iblocklist.com/?list=llvtlsjyoyiczbkjsxpf&fileformat=p2p&archiveformat=gz)
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|[iBlocklist.com](https://www.iblocklist.com/) free version of [BlueTack.co.uk](http://www.bluetack.co.uk/) web server hack and exploit attempts|ipv4 hash:ip|1460 unique IPs|updated every 12 hours  from [this link](http://list.iblocklist.com/?list=ghlzqtqxnzctvvajwwag&fileformat=p2p&archiveformat=gz)
infiltrated|[infiltrated.net](http://www.infiltrated.net) (this list seems to be updated frequently, but we found no information about it)|ipv4 hash:ip|disabled|updated every 12 hours  from [this link](http://www.infiltrated.net/blacklisted)
lashback_ubl|[The LashBack UBL](http://blacklist.lashback.com/) The Unsubscribe Blacklist (UBL) is a real-time blacklist of IP addresses which are sending email to names harvested from suppression files (this is a big list, more than 500.000 IPs)|ipv4 hash:ip|disabled|updated every 1 day  from [this link](http://www.unsubscore.com/blacklist.txt)
[malc0de](#malc0de)|[Malc0de.com](http://malc0de.com) malicious IPs of the last 30 days|ipv4 hash:ip|371 unique IPs|updated every 1 day  from [this link](http://malc0de.com/bl/IP_Blacklist.txt)
[malwaredomainlist](#malwaredomainlist)|[malwaredomainlist.com](http://www.malwaredomainlist.com) list of malware active ip addresses|ipv4 hash:ip|1288 unique IPs|updated every 12 hours  from [this link](http://www.malwaredomainlist.com/hostslist/ip.txt)
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|[MaxMind.com](https://www.maxmind.com/en/anonymous-proxy-fraudulent-ip-address-list) list of anonymous proxy fraudelent IP addresses.|ipv4 hash:ip|372 unique IPs|updated every 4 hours  from [this link](https://www.maxmind.com/en/anonymous-proxy-fraudulent-ip-address-list)
[nixspam](#nixspam)|[NiX Spam](http://www.heise.de/ix/NiX-Spam-DNSBL-and-blacklist-for-download-499637.html) IP addresses that sent spam in the last hour - automatically generated entries without distinguishing open proxies from relays, dialup gateways, and so on. All IPs are removed after 12 hours if there is no spam from there.|ipv4 hash:ip|20080 unique IPs|updated every 15 mins  from [this link](http://www.dnsbl.manitu.net/download/nixspam-ip.dump.gz)
openbl|[OpenBL.org](http://www.openbl.org/) default blacklist (currently it is the same with 90 days). OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications - **excellent list**|ipv4 hash:ip|disabled|updated every 4 hours  from [this link](http://www.openbl.org/lists/base.txt)
openbl_180d|[OpenBL.org](http://www.openbl.org/) last 180 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|disabled|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_180days.txt)
[openbl_1d](#openbl_1d)|[OpenBL.org](http://www.openbl.org/) last 24 hours IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|143 unique IPs|updated every 1 hour  from [this link](http://www.openbl.org/lists/base_1days.txt)
[openbl_30d](#openbl_30d)|[OpenBL.org](http://www.openbl.org/) last 30 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|3254 unique IPs|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_30days.txt)
openbl_360d|[OpenBL.org](http://www.openbl.org/) last 360 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|disabled|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_360days.txt)
[openbl_60d](#openbl_60d)|[OpenBL.org](http://www.openbl.org/) last 60 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|7667 unique IPs|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_60days.txt)
[openbl_7d](#openbl_7d)|[OpenBL.org](http://www.openbl.org/) last 7 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|893 unique IPs|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_7days.txt)
openbl_90d|[OpenBL.org](http://www.openbl.org/) last 90 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|disabled|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_90days.txt)
openbl_all|[OpenBL.org](http://www.openbl.org/) last all IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|disabled|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_all.txt)
[palevo](#palevo)|[Abuse.ch Palevo tracker](https://palevotracker.abuse.ch) worm includes IPs which are being used as botnet C&C for the Palevo crimeware - **excellent list**|ipv4 hash:ip|13 unique IPs|updated every 30 mins  from [this link](https://palevotracker.abuse.ch/blocklists.php?download=ipblocklist)
php_bad|[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) bad web hosts (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|disabled|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=b&rss=1)
[php_commenters](#php_commenters)|[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) comment spammers (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|326 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=c&rss=1)
[php_dictionary](#php_dictionary)|[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) directory attackers (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|508 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=d&rss=1)
[php_harvesters](#php_harvesters)|[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) harvesters (IPs that surf the internet looking for email addresses) (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|311 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=h&rss=1)
[php_spammers](#php_spammers)|[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) spam servers (IPs used by spammers to send messages) (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|495 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=s&rss=1)
[proxyrss](#proxyrss)|[proxyrss.com](http://www.proxyrss.com) open proxies syndicated from multiple sources.|ipv4 hash:ip|1768 unique IPs|updated every 4 hours  from [this link](http://www.proxyrss.com/proxylists/all.gz)
[proxz](#proxz)|[proxz.com](http://www.proxz.com) open proxies (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|824 unique IPs|updated every 1 hour  from [this link](http://www.proxz.com/proxylists.xml)
[ri_connect_proxies](#ri_connect_proxies)|[rosinstrument.com](http://www.rosinstrument.com) open CONNECT proxies (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|2421 unique IPs|updated every 1 hour  from [this link](http://tools.rosinstrument.com/proxy/plab100.xml)
[ri_web_proxies](#ri_web_proxies)|[rosinstrument.com](http://www.rosinstrument.com) open HTTP proxies (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|6466 unique IPs|updated every 1 hour  from [this link](http://tools.rosinstrument.com/proxy/l100.xml)
[shunlist](#shunlist)|[AutoShun.org](http://autoshun.org/) IPs identified as hostile by correlating logs from distributed snort installations running the autoshun plugin|ipv4 hash:ip|1229 unique IPs|updated every 4 hours  from [this link](http://www.autoshun.org/files/shunlist.csv)
[snort_ipfilter](#snort_ipfilter)|[labs.snort.org](https://labs.snort.org/) supplied IP blacklist (this list seems to be updated frequently, but we found no information about it)|ipv4 hash:ip|9994 unique IPs|updated every 12 hours  from [this link](http://labs.snort.org/feeds/ip-filter.blf)
[sorbs_dul](#sorbs_dul)|[Sorbs.net](https://www.sorbs.net/) DUL, Dynamic User IPs extracted from deltas.|ipv4 hash:net|8 subnets, 3584 unique IPs|updated every 1 min  from [this link]()
[sorbs_http](#sorbs_http)|[Sorbs.net](https://www.sorbs.net/) HTTP proxies, extracted from deltas.|ipv4 hash:net|19 subnets, 19 unique IPs|updated every 1 min  from [this link]()
[sorbs_misc](#sorbs_misc)|[Sorbs.net](https://www.sorbs.net/) MISC proxies, extracted from deltas.|ipv4 hash:net|19 subnets, 19 unique IPs|updated every 1 min  from [this link]()
[sorbs_new_spam](#sorbs_new_spam)|[Sorbs.net](https://www.sorbs.net/) NEW Spam senders, extracted from deltas.|ipv4 hash:net|27772 subnets, 28726 unique IPs|updated every 1 min  from [this link]()
[sorbs_recent_spam](#sorbs_recent_spam)|[Sorbs.net](https://www.sorbs.net/) RECENT Spam senders, extracted from deltas.|ipv4 hash:net|27772 subnets, 28726 unique IPs|updated every 1 min  from [this link]()
[sorbs_smtp](#sorbs_smtp)|[Sorbs.net](https://www.sorbs.net/) SMTP Open Relays, extracted from deltas.|ipv4 hash:net|13 subnets, 13 unique IPs|updated every 1 min  from [this link]()
[sorbs_socks](#sorbs_socks)|[Sorbs.net](https://www.sorbs.net/) SOCKS proxies, extracted from deltas.|ipv4 hash:net|19 subnets, 19 unique IPs|updated every 1 min  from [this link]()
[sorbs_spam](#sorbs_spam)|[Sorbs.net](https://www.sorbs.net/) Spam senders, extracted from deltas.|ipv4 hash:net|27772 subnets, 28726 unique IPs|updated every 1 min  from [this link]()
[sorbs_web](#sorbs_web)|[Sorbs.net](https://www.sorbs.net/) WEB exploits, extracted from deltas.|ipv4 hash:net|588 subnets, 589 unique IPs|updated every 1 min  from [this link]()
[spamhaus_drop](#spamhaus_drop)|[Spamhaus.org](http://www.spamhaus.org) DROP list (according to their site this list should be dropped at tier-1 ISPs globaly) - **excellent list**|ipv4 hash:net|653 subnets, 18404096 unique IPs|updated every 12 hours  from [this link](http://www.spamhaus.org/drop/drop.txt)
[spamhaus_edrop](#spamhaus_edrop)|[Spamhaus.org](http://www.spamhaus.org) EDROP (extended matches that should be used with DROP) - **excellent list**|ipv4 hash:net|55 subnets, 486400 unique IPs|updated every 12 hours  from [this link](http://www.spamhaus.org/drop/edrop.txt)
[sslbl](#sslbl)|[Abuse.ch SSL Blacklist](https://sslbl.abuse.ch/) bad SSL traffic related to malware or botnet activities - **excellent list**|ipv4 hash:ip|369 unique IPs|updated every 30 mins  from [this link](https://sslbl.abuse.ch/blacklist/sslipblacklist.csv)
stopforumspam_180d|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 180 days)|ipv4 hash:ip|disabled|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/listed_ip_180.zip)
[stopforumspam_1d](#stopforumspam_1d)|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers in the last 24 hours - **excellent list**|ipv4 hash:ip|7232 unique IPs|updated every 1 hour  from [this link](http://www.stopforumspam.com/downloads/listed_ip_1.zip)
[stopforumspam_30d](#stopforumspam_30d)|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 30 days)|ipv4 hash:ip|93498 unique IPs|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/listed_ip_30.zip)
stopforumspam_365d|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 365 days)|ipv4 hash:ip|disabled|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/listed_ip_365.zip)
[stopforumspam_7d](#stopforumspam_7d)|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 7 days)|ipv4 hash:ip|29882 unique IPs|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/listed_ip_7.zip)
stopforumspam_90d|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 90 days)|ipv4 hash:ip|disabled|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/listed_ip_90.zip)
stopforumspam_ever|[StopForumSpam.com](http://www.stopforumspam.com) all IPs used by forum spammers, **ever** (normally you don't want to use this ipset, use the hourly one which includes last 24 hours IPs or the 7 days one)|ipv4 hash:ip|disabled|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/bannedips.zip)
[virbl](#virbl)|[VirBL](http://virbl.bit.nl/) is a project of which the idea was born during the RIPE-48 meeting. The plan was to get reports of virusscanning mailservers, and put the IP-addresses that were reported to send viruses on a blacklist.|ipv4 hash:ip|12 unique IPs|updated every 1 hour  from [this link](http://virbl.bit.nl/download/virbl.dnsbl.bit.nl.txt)
[voipbl](#voipbl)|[VoIPBL.org](http://www.voipbl.org/) a distributed VoIP blacklist that is aimed to protects against VoIP Fraud and minimizing abuse for network that have publicly accessible PBX's. Several algorithms, external sources and manual confirmation are used before they categorize something as an attack and determine the threat level.|ipv4 hash:net|10452 subnets, 10864 unique IPs|updated every 4 hours  from [this link](http://www.voipbl.org/update/)
[xroxy](#xroxy)|[xroxy.com](http://www.xroxy.com) open proxies (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|2087 unique IPs|updated every 1 hour  from [this link](http://www.xroxy.com/proxyrss.xml)
[zeus](#zeus)|[Abuse.ch Zeus tracker](https://zeustracker.abuse.ch) standard, contains the same data as the ZeuS IP blocklist (zeus_badips) but with the slight difference that it doesn't exclude hijacked websites (level 2) and free web hosting providers (level 3). This means that this blocklist contains all IPv4 addresses associated with ZeuS C&Cs which are currently being tracked by ZeuS Tracker. Hence this blocklist will likely cause some false positives. - **excellent list**|ipv4 hash:ip|230 unique IPs|updated every 30 mins  from [this link](https://zeustracker.abuse.ch/blocklist.php?download=ipblocklist)
[zeus_badips](#zeus_badips)|[Abuse.ch Zeus tracker](https://zeustracker.abuse.ch) badips includes IPv4 addresses that are used by the ZeuS trojan. It is the recommened blocklist if you want to block only ZeuS IPs. It excludes IP addresses that ZeuS Tracker believes to be hijacked (level 2) or belong to a free web hosting provider (level 3). Hence the false postive rate should be much lower compared to the standard ZeuS IP blocklist. **excellent list**|ipv4 hash:ip|202 unique IPs|updated every 30 mins  from [this link](https://zeustracker.abuse.ch/blocklist.php?download=badips)

# Comparison of ipsets

Below we compare each ipset against all other.


## alienvault_reputation

[AlienVault.com](https://www.alienvault.com/) IP reputation database (this list seems to include port scanning hosts and to be updated regularly, but we found no information about its retention policy)

Source is downloaded from [this link](https://reputation.alienvault.com/reputation.generic).

The last time downloaded was found to be dated: Fri Jun  5 22:01:05 UTC 2015.

The ipset `alienvault_reputation` has **176034** entries, **176034** unique IPs.

The following table shows the overlaps of `alienvault_reputation` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `alienvault_reputation`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `alienvault_reputation`.
- ` this % ` is the percentage **of this ipset (`alienvault_reputation`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|13886|0.0%|7.8%|
[openbl_60d](#openbl_60d)|7667|7667|7647|99.7%|4.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|7286|0.0%|4.1%|
[et_block](#et_block)|1016|18338655|5535|0.0%|3.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|4727|0.0%|2.6%|
[dshield](#dshield)|20|5120|3338|65.1%|1.8%|
[openbl_30d](#openbl_30d)|3254|3254|3239|99.5%|1.8%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|1631|0.0%|0.9%|
[blocklist_de](#blocklist_de)|28768|28768|1498|5.2%|0.8%|
[et_compromised](#et_compromised)|2086|2086|1363|65.3%|0.7%|
[bruteforceblocker](#bruteforceblocker)|1977|1977|1277|64.5%|0.7%|
[blocklist_de_ssh](#blocklist_de_ssh)|4496|4496|1258|27.9%|0.7%|
[shunlist](#shunlist)|1229|1229|1216|98.9%|0.6%|
[openbl_7d](#openbl_7d)|893|893|888|99.4%|0.5%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|518|0.0%|0.2%|
[ciarmy](#ciarmy)|421|421|417|99.0%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|287|0.0%|0.1%|
[voipbl](#voipbl)|10452|10864|209|1.9%|0.1%|
[stopforumspam_30d](#stopforumspam_30d)|93498|93498|204|0.2%|0.1%|
[openbl_1d](#openbl_1d)|143|143|139|97.2%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|15058|15058|129|0.8%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9994|9994|121|1.2%|0.0%|
[sorbs_spam](#sorbs_spam)|27772|28726|103|0.3%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|27772|28726|103|0.3%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|27772|28726|103|0.3%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29882|29882|92|0.3%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|16032|16032|65|0.4%|0.0%|
[sslbl](#sslbl)|369|369|64|17.3%|0.0%|
[zeus](#zeus)|230|230|62|26.9%|0.0%|
[nixspam](#nixspam)|20080|20080|57|0.2%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7232|7232|55|0.7%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2050|2050|51|2.4%|0.0%|
[et_tor](#et_tor)|6610|6610|43|0.6%|0.0%|
[dm_tor](#dm_tor)|6483|6483|42|0.6%|0.0%|
[bm_tor](#bm_tor)|6533|6533|42|0.6%|0.0%|
[zeus_badips](#zeus_badips)|202|202|38|18.8%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|180|180|36|20.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3330|3330|31|0.9%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|26|6.9%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|3708|3708|21|0.5%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|92|92|18|19.5%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|486400|15|0.0%|0.0%|
[php_commenters](#php_commenters)|326|326|15|4.6%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|15|0.0%|0.0%|
[malc0de](#malc0de)|371|371|11|2.9%|0.0%|
[php_harvesters](#php_harvesters)|311|311|10|3.2%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|868|868|9|1.0%|0.0%|
[php_dictionary](#php_dictionary)|508|508|8|1.5%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|8|0.5%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|359|359|8|2.2%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|6|0.4%|0.0%|
[php_spammers](#php_spammers)|495|495|5|1.0%|0.0%|
[et_botcc](#et_botcc)|509|509|5|0.9%|0.0%|
[xroxy](#xroxy)|2087|2087|4|0.1%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2421|2421|3|0.1%|0.0%|
[proxz](#proxz)|824|824|3|0.3%|0.0%|
[proxyrss](#proxyrss)|1768|1768|3|0.1%|0.0%|
[ri_web_proxies](#ri_web_proxies)|6466|6466|2|0.0%|0.0%|
[feodo](#feodo)|96|96|2|2.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|1|0.1%|0.0%|

## blocklist_de

[Blocklist.de](https://www.blocklist.de/) IPs that have been detected by fail2ban in the last 48 hours - **excellent list**

Source is downloaded from [this link](http://lists.blocklist.de/lists/all.txt).

The last time downloaded was found to be dated: Fri Jun  5 23:10:03 UTC 2015.

The ipset `blocklist_de` has **28768** entries, **28768** unique IPs.

The following table shows the overlaps of `blocklist_de` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de`.
- ` this % ` is the percentage **of this ipset (`blocklist_de`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de_mail](#blocklist_de_mail)|16032|16032|16026|99.9%|55.7%|
[blocklist_de_apache](#blocklist_de_apache)|15058|15058|15056|99.9%|52.3%|
[blocklist_de_ssh](#blocklist_de_ssh)|4496|4496|4496|100.0%|15.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|3842|0.0%|13.3%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|3708|3708|3708|100.0%|12.8%|
[blocklist_de_bots](#blocklist_de_bots)|3330|3330|3321|99.7%|11.5%|
[stopforumspam_30d](#stopforumspam_30d)|93498|93498|2384|2.5%|8.2%|
[blocklist_de_imap](#blocklist_de_imap)|2050|2050|2045|99.7%|7.1%|
[stopforumspam_7d](#stopforumspam_7d)|29882|29882|2000|6.6%|6.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|1556|0.0%|5.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|1509|0.0%|5.2%|
[alienvault_reputation](#alienvault_reputation)|176034|176034|1498|0.8%|5.2%|
[stopforumspam_1d](#stopforumspam_1d)|7232|7232|1430|19.7%|4.9%|
[openbl_60d](#openbl_60d)|7667|7667|1208|15.7%|4.1%|
[sorbs_spam](#sorbs_spam)|27772|28726|1115|3.8%|3.8%|
[sorbs_recent_spam](#sorbs_recent_spam)|27772|28726|1115|3.8%|3.8%|
[sorbs_new_spam](#sorbs_new_spam)|27772|28726|1115|3.8%|3.8%|
[blocklist_de_ftp](#blocklist_de_ftp)|868|868|862|99.3%|2.9%|
[openbl_30d](#openbl_30d)|3254|3254|776|23.8%|2.6%|
[bruteforceblocker](#bruteforceblocker)|1977|1977|662|33.4%|2.3%|
[et_compromised](#et_compromised)|2086|2086|636|30.4%|2.2%|
[nixspam](#nixspam)|20080|20080|565|2.8%|1.9%|
[openbl_7d](#openbl_7d)|893|893|500|55.9%|1.7%|
[ri_web_proxies](#ri_web_proxies)|6466|6466|423|6.5%|1.4%|
[shunlist](#shunlist)|1229|1229|362|29.4%|1.2%|
[xroxy](#xroxy)|2087|2087|259|12.4%|0.9%|
[proxyrss](#proxyrss)|1768|1768|242|13.6%|0.8%|
[et_block](#et_block)|1016|18338655|186|0.0%|0.6%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|181|0.0%|0.6%|
[blocklist_de_strongips](#blocklist_de_strongips)|180|180|180|100.0%|0.6%|
[snort_ipfilter](#snort_ipfilter)|9994|9994|176|1.7%|0.6%|
[proxz](#proxz)|824|824|146|17.7%|0.5%|
[openbl_1d](#openbl_1d)|143|143|115|80.4%|0.3%|
[php_dictionary](#php_dictionary)|508|508|85|16.7%|0.2%|
[php_spammers](#php_spammers)|495|495|84|16.9%|0.2%|
[php_commenters](#php_commenters)|326|326|80|24.5%|0.2%|
[ri_connect_proxies](#ri_connect_proxies)|2421|2421|75|3.0%|0.2%|
[sorbs_web](#sorbs_web)|588|589|73|12.3%|0.2%|
[blocklist_de_sip](#blocklist_de_sip)|92|92|73|79.3%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|51|0.0%|0.1%|
[voipbl](#voipbl)|10452|10864|39|0.3%|0.1%|
[ciarmy](#ciarmy)|421|421|37|8.7%|0.1%|
[php_harvesters](#php_harvesters)|311|311|30|9.6%|0.1%|
[dshield](#dshield)|20|5120|13|0.2%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|12|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|11|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|486400|7|0.0%|0.0%|
[sorbs_socks](#sorbs_socks)|19|19|7|36.8%|0.0%|
[sorbs_misc](#sorbs_misc)|19|19|7|36.8%|0.0%|
[sorbs_http](#sorbs_http)|19|19|7|36.8%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|6|0.8%|0.0%|
[et_tor](#et_tor)|6610|6610|4|0.0%|0.0%|
[dm_tor](#dm_tor)|6483|6483|4|0.0%|0.0%|
[bm_tor](#bm_tor)|6533|6533|4|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|3|0.8%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|3|0.2%|0.0%|
[sslbl](#sslbl)|369|369|1|0.2%|0.0%|

## blocklist_de_apache

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service Apache, Apache-DDOS, RFI-Attacks.

Source is downloaded from [this link](http://lists.blocklist.de/lists/apache.txt).

The last time downloaded was found to be dated: Fri Jun  5 22:56:12 UTC 2015.

The ipset `blocklist_de_apache` has **15058** entries, **15058** unique IPs.

The following table shows the overlaps of `blocklist_de_apache` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_apache`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_apache`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_apache`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|28768|28768|15056|52.3%|99.9%|
[blocklist_de_mail](#blocklist_de_mail)|16032|16032|11059|68.9%|73.4%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|3708|3708|3708|100.0%|24.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|2372|0.0%|15.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|1328|0.0%|8.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|1088|0.0%|7.2%|
[stopforumspam_30d](#stopforumspam_30d)|93498|93498|221|0.2%|1.4%|
[stopforumspam_7d](#stopforumspam_7d)|29882|29882|137|0.4%|0.9%|
[alienvault_reputation](#alienvault_reputation)|176034|176034|129|0.0%|0.8%|
[sorbs_spam](#sorbs_spam)|27772|28726|104|0.3%|0.6%|
[sorbs_recent_spam](#sorbs_recent_spam)|27772|28726|104|0.3%|0.6%|
[sorbs_new_spam](#sorbs_new_spam)|27772|28726|104|0.3%|0.6%|
[stopforumspam_1d](#stopforumspam_1d)|7232|7232|66|0.9%|0.4%|
[nixspam](#nixspam)|20080|20080|55|0.2%|0.3%|
[blocklist_de_strongips](#blocklist_de_strongips)|180|180|35|19.4%|0.2%|
[ciarmy](#ciarmy)|421|421|31|7.3%|0.2%|
[shunlist](#shunlist)|1229|1229|28|2.2%|0.1%|
[php_commenters](#php_commenters)|326|326|26|7.9%|0.1%|
[blocklist_de_bots](#blocklist_de_bots)|3330|3330|24|0.7%|0.1%|
[snort_ipfilter](#snort_ipfilter)|9994|9994|9|0.0%|0.0%|
[openbl_60d](#openbl_60d)|7667|7667|8|0.1%|0.0%|
[et_block](#et_block)|1016|18338655|7|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|6|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|5|0.0%|0.0%|
[php_spammers](#php_spammers)|495|495|5|1.0%|0.0%|
[php_harvesters](#php_harvesters)|311|311|5|1.6%|0.0%|
[openbl_30d](#openbl_30d)|3254|3254|5|0.1%|0.0%|
[dshield](#dshield)|20|5120|5|0.0%|0.0%|
[php_dictionary](#php_dictionary)|508|508|4|0.7%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|4|0.0%|0.0%|
[et_tor](#et_tor)|6610|6610|4|0.0%|0.0%|
[dm_tor](#dm_tor)|6483|6483|4|0.0%|0.0%|
[bm_tor](#bm_tor)|6533|6533|4|0.0%|0.0%|
[voipbl](#voipbl)|10452|10864|3|0.0%|0.0%|
[openbl_7d](#openbl_7d)|893|893|3|0.3%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|3|0.0%|0.0%|
[sorbs_web](#sorbs_web)|588|589|2|0.3%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|2|0.5%|0.0%|
[et_compromised](#et_compromised)|2086|2086|2|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1977|1977|2|0.1%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|486400|1|0.0%|0.0%|

## blocklist_de_bots

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the RFI-Attacks, REG-Bots, IRC-Bots or BadBots (BadBots = he has posted a Spam-Comment on a open Forum or Wiki).

Source is downloaded from [this link](http://lists.blocklist.de/lists/bots.txt).

The last time downloaded was found to be dated: Fri Jun  5 22:56:14 UTC 2015.

The ipset `blocklist_de_bots` has **3330** entries, **3330** unique IPs.

The following table shows the overlaps of `blocklist_de_bots` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_bots`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_bots`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_bots`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|28768|28768|3321|11.5%|99.7%|
[stopforumspam_30d](#stopforumspam_30d)|93498|93498|2018|2.1%|60.6%|
[stopforumspam_7d](#stopforumspam_7d)|29882|29882|1802|6.0%|54.1%|
[stopforumspam_1d](#stopforumspam_1d)|7232|7232|1365|18.8%|40.9%|
[ri_web_proxies](#ri_web_proxies)|6466|6466|365|5.6%|10.9%|
[proxyrss](#proxyrss)|1768|1768|243|13.7%|7.2%|
[xroxy](#xroxy)|2087|2087|207|9.9%|6.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|196|0.0%|5.8%|
[blocklist_de_strongips](#blocklist_de_strongips)|180|180|132|73.3%|3.9%|
[proxz](#proxz)|824|824|123|14.9%|3.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|114|0.0%|3.4%|
[ri_connect_proxies](#ri_connect_proxies)|2421|2421|73|3.0%|2.1%|
[php_commenters](#php_commenters)|326|326|64|19.6%|1.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|44|0.0%|1.3%|
[et_block](#et_block)|1016|18338655|43|0.0%|1.2%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|42|0.0%|1.2%|
[sorbs_spam](#sorbs_spam)|27772|28726|35|0.1%|1.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|27772|28726|35|0.1%|1.0%|
[sorbs_new_spam](#sorbs_new_spam)|27772|28726|35|0.1%|1.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|35|0.0%|1.0%|
[nixspam](#nixspam)|20080|20080|32|0.1%|0.9%|
[alienvault_reputation](#alienvault_reputation)|176034|176034|31|0.0%|0.9%|
[blocklist_de_mail](#blocklist_de_mail)|16032|16032|24|0.1%|0.7%|
[blocklist_de_apache](#blocklist_de_apache)|15058|15058|24|0.1%|0.7%|
[php_harvesters](#php_harvesters)|311|311|22|7.0%|0.6%|
[snort_ipfilter](#snort_ipfilter)|9994|9994|13|0.1%|0.3%|
[php_spammers](#php_spammers)|495|495|13|2.6%|0.3%|
[php_dictionary](#php_dictionary)|508|508|11|2.1%|0.3%|
[openbl_60d](#openbl_60d)|7667|7667|10|0.1%|0.3%|
[sorbs_web](#sorbs_web)|588|589|7|1.1%|0.2%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|5|0.7%|0.1%|
[spamhaus_edrop](#spamhaus_edrop)|55|486400|4|0.0%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|4|0.0%|0.1%|
[voipbl](#voipbl)|10452|10864|3|0.0%|0.0%|
[openbl_30d](#openbl_30d)|3254|3254|2|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1977|1977|2|0.1%|0.0%|
[sorbs_socks](#sorbs_socks)|19|19|1|5.2%|0.0%|
[sorbs_misc](#sorbs_misc)|19|19|1|5.2%|0.0%|
[sorbs_http](#sorbs_http)|19|19|1|5.2%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1|0.0%|0.0%|
[et_compromised](#et_compromised)|2086|2086|1|0.0%|0.0%|

## blocklist_de_bruteforce

[Blocklist.de](https://www.blocklist.de/) All IPs which attacks Joomlas, Wordpress and other Web-Logins with Brute-Force Logins.

Source is downloaded from [this link](http://lists.blocklist.de/lists/bruteforcelogin.txt).

The last time downloaded was found to be dated: Fri Jun  5 22:56:16 UTC 2015.

The ipset `blocklist_de_bruteforce` has **3708** entries, **3708** unique IPs.

The following table shows the overlaps of `blocklist_de_bruteforce` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_bruteforce`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_bruteforce`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_bruteforce`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de_apache](#blocklist_de_apache)|15058|15058|3708|24.6%|100.0%|
[blocklist_de](#blocklist_de)|28768|28768|3708|12.8%|100.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|272|0.0%|7.3%|
[sorbs_spam](#sorbs_spam)|27772|28726|104|0.3%|2.8%|
[sorbs_recent_spam](#sorbs_recent_spam)|27772|28726|104|0.3%|2.8%|
[sorbs_new_spam](#sorbs_new_spam)|27772|28726|104|0.3%|2.8%|
[stopforumspam_30d](#stopforumspam_30d)|93498|93498|56|0.0%|1.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|55|0.0%|1.4%|
[nixspam](#nixspam)|20080|20080|52|0.2%|1.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|37|0.0%|0.9%|
[stopforumspam_7d](#stopforumspam_7d)|29882|29882|36|0.1%|0.9%|
[alienvault_reputation](#alienvault_reputation)|176034|176034|21|0.0%|0.5%|
[stopforumspam_1d](#stopforumspam_1d)|7232|7232|20|0.2%|0.5%|
[blocklist_de_strongips](#blocklist_de_strongips)|180|180|8|4.4%|0.2%|
[php_commenters](#php_commenters)|326|326|7|2.1%|0.1%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|6|0.0%|0.1%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|5|0.0%|0.1%|
[snort_ipfilter](#snort_ipfilter)|9994|9994|5|0.0%|0.1%|
[php_spammers](#php_spammers)|495|495|5|1.0%|0.1%|
[php_dictionary](#php_dictionary)|508|508|4|0.7%|0.1%|
[et_block](#et_block)|1016|18338655|4|0.0%|0.1%|
[shunlist](#shunlist)|1229|1229|3|0.2%|0.0%|
[php_harvesters](#php_harvesters)|311|311|3|0.9%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|0.0%|
[sorbs_web](#sorbs_web)|588|589|2|0.3%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|2|0.0%|0.0%|
[voipbl](#voipbl)|10452|10864|1|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[ciarmy](#ciarmy)|421|421|1|0.2%|0.0%|

## blocklist_de_ftp

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours for attacks on the Service FTP.

Source is downloaded from [this link](http://lists.blocklist.de/lists/ftp.txt).

The last time downloaded was found to be dated: Fri Jun  5 22:56:12 UTC 2015.

The ipset `blocklist_de_ftp` has **868** entries, **868** unique IPs.

The following table shows the overlaps of `blocklist_de_ftp` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_ftp`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_ftp`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_ftp`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|28768|28768|862|2.9%|99.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|75|0.0%|8.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|13|0.0%|1.4%|
[stopforumspam_30d](#stopforumspam_30d)|93498|93498|9|0.0%|1.0%|
[alienvault_reputation](#alienvault_reputation)|176034|176034|9|0.0%|1.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|7|0.0%|0.8%|
[nixspam](#nixspam)|20080|20080|6|0.0%|0.6%|
[sorbs_spam](#sorbs_spam)|27772|28726|3|0.0%|0.3%|
[sorbs_recent_spam](#sorbs_recent_spam)|27772|28726|3|0.0%|0.3%|
[sorbs_new_spam](#sorbs_new_spam)|27772|28726|3|0.0%|0.3%|
[php_harvesters](#php_harvesters)|311|311|3|0.9%|0.3%|
[openbl_60d](#openbl_60d)|7667|7667|3|0.0%|0.3%|
[stopforumspam_7d](#stopforumspam_7d)|29882|29882|2|0.0%|0.2%|
[blocklist_de_strongips](#blocklist_de_strongips)|180|180|2|1.1%|0.2%|
[php_spammers](#php_spammers)|495|495|1|0.2%|0.1%|
[openbl_30d](#openbl_30d)|3254|3254|1|0.0%|0.1%|
[ciarmy](#ciarmy)|421|421|1|0.2%|0.1%|

## blocklist_de_imap

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours for attacks on the Service imap, sasl, pop3, etc.

Source is downloaded from [this link](http://lists.blocklist.de/lists/imap.txt).

The last time downloaded was found to be dated: Fri Jun  5 23:14:15 UTC 2015.

The ipset `blocklist_de_imap` has **2050** entries, **2050** unique IPs.

The following table shows the overlaps of `blocklist_de_imap` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_imap`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_imap`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_imap`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de_mail](#blocklist_de_mail)|16032|16032|2050|12.7%|100.0%|
[blocklist_de](#blocklist_de)|28768|28768|2045|7.1%|99.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|232|0.0%|11.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|56|0.0%|2.7%|
[alienvault_reputation](#alienvault_reputation)|176034|176034|51|0.0%|2.4%|
[openbl_60d](#openbl_60d)|7667|7667|42|0.5%|2.0%|
[openbl_30d](#openbl_30d)|3254|3254|35|1.0%|1.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|35|0.0%|1.7%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|17|0.0%|0.8%|
[et_block](#et_block)|1016|18338655|17|0.0%|0.8%|
[sorbs_spam](#sorbs_spam)|27772|28726|16|0.0%|0.7%|
[sorbs_recent_spam](#sorbs_recent_spam)|27772|28726|16|0.0%|0.7%|
[sorbs_new_spam](#sorbs_new_spam)|27772|28726|16|0.0%|0.7%|
[openbl_7d](#openbl_7d)|893|893|15|1.6%|0.7%|
[nixspam](#nixspam)|20080|20080|11|0.0%|0.5%|
[stopforumspam_30d](#stopforumspam_30d)|93498|93498|9|0.0%|0.4%|
[et_compromised](#et_compromised)|2086|2086|8|0.3%|0.3%|
[bruteforceblocker](#bruteforceblocker)|1977|1977|7|0.3%|0.3%|
[snort_ipfilter](#snort_ipfilter)|9994|9994|3|0.0%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|0.1%|
[stopforumspam_7d](#stopforumspam_7d)|29882|29882|2|0.0%|0.0%|
[openbl_1d](#openbl_1d)|143|143|2|1.3%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|2|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|2|0.0%|0.0%|
[ciarmy](#ciarmy)|421|421|2|0.4%|0.0%|
[voipbl](#voipbl)|10452|10864|1|0.0%|0.0%|
[shunlist](#shunlist)|1229|1229|1|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2421|2421|1|0.0%|0.0%|
[php_spammers](#php_spammers)|495|495|1|0.2%|0.0%|
[php_dictionary](#php_dictionary)|508|508|1|0.1%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|180|180|1|0.5%|0.0%|

## blocklist_de_mail

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service Mail, Postfix.

Source is downloaded from [this link](http://lists.blocklist.de/lists/mail.txt).

The last time downloaded was found to be dated: Fri Jun  5 23:14:13 UTC 2015.

The ipset `blocklist_de_mail` has **16032** entries, **16032** unique IPs.

The following table shows the overlaps of `blocklist_de_mail` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_mail`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_mail`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_mail`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|28768|28768|16026|55.7%|99.9%|
[blocklist_de_apache](#blocklist_de_apache)|15058|15058|11059|73.4%|68.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|2502|0.0%|15.6%|
[blocklist_de_imap](#blocklist_de_imap)|2050|2050|2050|100.0%|12.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|1371|0.0%|8.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|1151|0.0%|7.1%|
[sorbs_spam](#sorbs_spam)|27772|28726|951|3.3%|5.9%|
[sorbs_recent_spam](#sorbs_recent_spam)|27772|28726|951|3.3%|5.9%|
[sorbs_new_spam](#sorbs_new_spam)|27772|28726|951|3.3%|5.9%|
[nixspam](#nixspam)|20080|20080|469|2.3%|2.9%|
[stopforumspam_30d](#stopforumspam_30d)|93498|93498|271|0.2%|1.6%|
[stopforumspam_7d](#stopforumspam_7d)|29882|29882|160|0.5%|0.9%|
[snort_ipfilter](#snort_ipfilter)|9994|9994|158|1.5%|0.9%|
[php_dictionary](#php_dictionary)|508|508|70|13.7%|0.4%|
[php_spammers](#php_spammers)|495|495|65|13.1%|0.4%|
[alienvault_reputation](#alienvault_reputation)|176034|176034|65|0.0%|0.4%|
[sorbs_web](#sorbs_web)|588|589|64|10.8%|0.3%|
[ri_web_proxies](#ri_web_proxies)|6466|6466|58|0.8%|0.3%|
[stopforumspam_1d](#stopforumspam_1d)|7232|7232|53|0.7%|0.3%|
[xroxy](#xroxy)|2087|2087|52|2.4%|0.3%|
[openbl_60d](#openbl_60d)|7667|7667|46|0.5%|0.2%|
[openbl_30d](#openbl_30d)|3254|3254|39|1.1%|0.2%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|25|0.0%|0.1%|
[et_block](#et_block)|1016|18338655|25|0.0%|0.1%|
[blocklist_de_bots](#blocklist_de_bots)|3330|3330|24|0.7%|0.1%|
[proxz](#proxz)|824|824|23|2.7%|0.1%|
[php_commenters](#php_commenters)|326|326|22|6.7%|0.1%|
[blocklist_de_strongips](#blocklist_de_strongips)|180|180|22|12.2%|0.1%|
[openbl_7d](#openbl_7d)|893|893|16|1.7%|0.0%|
[et_compromised](#et_compromised)|2086|2086|8|0.3%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1977|1977|7|0.3%|0.0%|
[sorbs_socks](#sorbs_socks)|19|19|6|31.5%|0.0%|
[sorbs_misc](#sorbs_misc)|19|19|6|31.5%|0.0%|
[sorbs_http](#sorbs_http)|19|19|6|31.5%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|4|0.0%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|4|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|4|0.0%|0.0%|
[et_tor](#et_tor)|6610|6610|4|0.0%|0.0%|
[dm_tor](#dm_tor)|6483|6483|4|0.0%|0.0%|
[bm_tor](#bm_tor)|6533|6533|4|0.0%|0.0%|
[voipbl](#voipbl)|10452|10864|2|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2421|2421|2|0.0%|0.0%|
[php_harvesters](#php_harvesters)|311|311|2|0.6%|0.0%|
[openbl_1d](#openbl_1d)|143|143|2|1.3%|0.0%|
[ciarmy](#ciarmy)|421|421|2|0.4%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|486400|1|0.0%|0.0%|
[shunlist](#shunlist)|1229|1229|1|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|1|0.1%|0.0%|
[dshield](#dshield)|20|5120|1|0.0%|0.0%|

## blocklist_de_sip

[Blocklist.de](https://www.blocklist.de/) All IP addresses that tried to login in a SIP, VOIP or Asterisk Server and are included in the IPs list from [infiltrated.net](www.infiltrated.net)

Source is downloaded from [this link](http://lists.blocklist.de/lists/sip.txt).

The last time downloaded was found to be dated: Fri Jun  5 23:14:15 UTC 2015.

The ipset `blocklist_de_sip` has **92** entries, **92** unique IPs.

The following table shows the overlaps of `blocklist_de_sip` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_sip`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_sip`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_sip`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|28768|28768|73|0.2%|79.3%|
[voipbl](#voipbl)|10452|10864|30|0.2%|32.6%|
[alienvault_reputation](#alienvault_reputation)|176034|176034|18|0.0%|19.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|13|0.0%|14.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|8|0.0%|8.6%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|2|0.0%|2.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|2|0.0%|2.1%|
[et_botcc](#et_botcc)|509|509|1|0.1%|1.0%|

## blocklist_de_ssh

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service SSH.

Source is downloaded from [this link](http://lists.blocklist.de/lists/ssh.txt).

The last time downloaded was found to be dated: Fri Jun  5 23:14:11 UTC 2015.

The ipset `blocklist_de_ssh` has **4496** entries, **4496** unique IPs.

The following table shows the overlaps of `blocklist_de_ssh` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_ssh`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_ssh`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_ssh`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|28768|28768|4496|15.6%|100.0%|
[alienvault_reputation](#alienvault_reputation)|176034|176034|1258|0.7%|27.9%|
[openbl_60d](#openbl_60d)|7667|7667|1140|14.8%|25.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|757|0.0%|16.8%|
[openbl_30d](#openbl_30d)|3254|3254|728|22.3%|16.1%|
[bruteforceblocker](#bruteforceblocker)|1977|1977|650|32.8%|14.4%|
[et_compromised](#et_compromised)|2086|2086|624|29.9%|13.8%|
[openbl_7d](#openbl_7d)|893|893|480|53.7%|10.6%|
[shunlist](#shunlist)|1229|1229|332|27.0%|7.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|161|0.0%|3.5%|
[openbl_1d](#openbl_1d)|143|143|113|79.0%|2.5%|
[et_block](#et_block)|1016|18338655|111|0.0%|2.4%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|109|0.0%|2.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|86|0.0%|1.9%|
[stopforumspam_30d](#stopforumspam_30d)|93498|93498|34|0.0%|0.7%|
[blocklist_de_strongips](#blocklist_de_strongips)|180|180|29|16.1%|0.6%|
[sorbs_spam](#sorbs_spam)|27772|28726|21|0.0%|0.4%|
[sorbs_recent_spam](#sorbs_recent_spam)|27772|28726|21|0.0%|0.4%|
[sorbs_new_spam](#sorbs_new_spam)|27772|28726|21|0.0%|0.4%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|8|0.0%|0.1%|
[stopforumspam_7d](#stopforumspam_7d)|29882|29882|7|0.0%|0.1%|
[dshield](#dshield)|20|5120|7|0.1%|0.1%|
[nixspam](#nixspam)|20080|20080|4|0.0%|0.0%|
[ciarmy](#ciarmy)|421|421|3|0.7%|0.0%|
[voipbl](#voipbl)|10452|10864|1|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7232|7232|1|0.0%|0.0%|
[sslbl](#sslbl)|369|369|1|0.2%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|486400|1|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1|0.0%|0.0%|

## blocklist_de_strongips

[Blocklist.de](https://www.blocklist.de/) All IPs which are older then 2 month and have more then 5.000 attacks.

Source is downloaded from [this link](http://lists.blocklist.de/lists/strongips.txt).

The last time downloaded was found to be dated: Fri Jun  5 22:56:15 UTC 2015.

The ipset `blocklist_de_strongips` has **180** entries, **180** unique IPs.

The following table shows the overlaps of `blocklist_de_strongips` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_strongips`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_strongips`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_strongips`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|28768|28768|180|0.6%|100.0%|
[blocklist_de_bots](#blocklist_de_bots)|3330|3330|132|3.9%|73.3%|
[stopforumspam_30d](#stopforumspam_30d)|93498|93498|128|0.1%|71.1%|
[stopforumspam_7d](#stopforumspam_7d)|29882|29882|117|0.3%|65.0%|
[stopforumspam_1d](#stopforumspam_1d)|7232|7232|108|1.4%|60.0%|
[php_commenters](#php_commenters)|326|326|36|11.0%|20.0%|
[alienvault_reputation](#alienvault_reputation)|176034|176034|36|0.0%|20.0%|
[blocklist_de_apache](#blocklist_de_apache)|15058|15058|35|0.2%|19.4%|
[blocklist_de_ssh](#blocklist_de_ssh)|4496|4496|29|0.6%|16.1%|
[openbl_60d](#openbl_60d)|7667|7667|27|0.3%|15.0%|
[openbl_30d](#openbl_30d)|3254|3254|25|0.7%|13.8%|
[openbl_7d](#openbl_7d)|893|893|24|2.6%|13.3%|
[blocklist_de_mail](#blocklist_de_mail)|16032|16032|22|0.1%|12.2%|
[shunlist](#shunlist)|1229|1229|20|1.6%|11.1%|
[openbl_1d](#openbl_1d)|143|143|19|13.2%|10.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|16|0.0%|8.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|8|0.0%|4.4%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|3708|3708|8|0.2%|4.4%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|7|0.0%|3.8%|
[et_block](#et_block)|1016|18338655|7|0.0%|3.8%|
[xroxy](#xroxy)|2087|2087|6|0.2%|3.3%|
[ri_web_proxies](#ri_web_proxies)|6466|6466|5|0.0%|2.7%|
[php_spammers](#php_spammers)|495|495|5|1.0%|2.7%|
[spamhaus_edrop](#spamhaus_edrop)|55|486400|4|0.0%|2.2%|
[proxyrss](#proxyrss)|1768|1768|4|0.2%|2.2%|
[proxz](#proxz)|824|824|3|0.3%|1.6%|
[php_dictionary](#php_dictionary)|508|508|3|0.5%|1.6%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|1.6%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|1.1%|
[blocklist_de_ftp](#blocklist_de_ftp)|868|868|2|0.2%|1.1%|
[sorbs_web](#sorbs_web)|588|589|1|0.1%|0.5%|
[sorbs_spam](#sorbs_spam)|27772|28726|1|0.0%|0.5%|
[sorbs_recent_spam](#sorbs_recent_spam)|27772|28726|1|0.0%|0.5%|
[sorbs_new_spam](#sorbs_new_spam)|27772|28726|1|0.0%|0.5%|
[snort_ipfilter](#snort_ipfilter)|9994|9994|1|0.0%|0.5%|
[php_harvesters](#php_harvesters)|311|311|1|0.3%|0.5%|
[nixspam](#nixspam)|20080|20080|1|0.0%|0.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|1|0.0%|0.5%|
[dshield](#dshield)|20|5120|1|0.0%|0.5%|
[bruteforceblocker](#bruteforceblocker)|1977|1977|1|0.0%|0.5%|
[blocklist_de_imap](#blocklist_de_imap)|2050|2050|1|0.0%|0.5%|

## bm_tor

[torstatus.blutmagie.de](https://torstatus.blutmagie.de) list of all TOR network servers

Source is downloaded from [this link](https://torstatus.blutmagie.de/ip_list_all.php/Tor_ip_list_ALL.csv).

The last time downloaded was found to be dated: Fri Jun  5 22:54:09 UTC 2015.

The ipset `bm_tor` has **6533** entries, **6533** unique IPs.

The following table shows the overlaps of `bm_tor` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `bm_tor`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `bm_tor`.
- ` this % ` is the percentage **of this ipset (`bm_tor`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[dm_tor](#dm_tor)|6483|6483|6425|99.1%|98.3%|
[et_tor](#et_tor)|6610|6610|5732|86.7%|87.7%|
[snort_ipfilter](#snort_ipfilter)|9994|9994|1071|10.7%|16.3%|
[stopforumspam_30d](#stopforumspam_30d)|93498|93498|627|0.6%|9.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|624|0.0%|9.5%|
[stopforumspam_7d](#stopforumspam_7d)|29882|29882|499|1.6%|7.6%|
[stopforumspam_1d](#stopforumspam_1d)|7232|7232|318|4.3%|4.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|188|0.0%|2.8%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|168|45.1%|2.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|165|0.0%|2.5%|
[alienvault_reputation](#alienvault_reputation)|176034|176034|42|0.0%|0.6%|
[php_commenters](#php_commenters)|326|326|34|10.4%|0.5%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|22|0.0%|0.3%|
[openbl_60d](#openbl_60d)|7667|7667|19|0.2%|0.2%|
[et_block](#et_block)|1016|18338655|9|0.0%|0.1%|
[php_harvesters](#php_harvesters)|311|311|7|2.2%|0.1%|
[ri_web_proxies](#ri_web_proxies)|6466|6466|5|0.0%|0.0%|
[php_spammers](#php_spammers)|495|495|5|1.0%|0.0%|
[php_dictionary](#php_dictionary)|508|508|4|0.7%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|4|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|16032|16032|4|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|15058|15058|4|0.0%|0.0%|
[blocklist_de](#blocklist_de)|28768|28768|4|0.0%|0.0%|
[voipbl](#voipbl)|10452|10864|3|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|3|0.0%|0.0%|
[xroxy](#xroxy)|2087|2087|2|0.0%|0.0%|
[sorbs_spam](#sorbs_spam)|27772|28726|2|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|27772|28726|2|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|27772|28726|2|0.0%|0.0%|
[shunlist](#shunlist)|1229|1229|1|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2421|2421|1|0.0%|0.0%|
[proxyrss](#proxyrss)|1768|1768|1|0.0%|0.0%|
[nixspam](#nixspam)|20080|20080|1|0.0%|0.0%|

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
[fullbogons](#fullbogons)|3715|670310296|592708608|88.4%|100.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|4194304|3.0%|0.7%|
[voipbl](#voipbl)|10452|10864|319|2.9%|0.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|5|0.0%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|93498|93498|1|0.0%|0.0%|
[php_harvesters](#php_harvesters)|311|311|1|0.3%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.0%|
[ciarmy](#ciarmy)|421|421|1|0.2%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1977|1977|1|0.0%|0.0%|

## bruteforceblocker

[danger.rulez.sk](http://danger.rulez.sk/) IPs detected by [bruteforceblocker](http://danger.rulez.sk/index.php/bruteforceblocker/) (fail2ban alternative for SSH on OpenBSD). This is an automatically generated list from users reporting failed authentication attempts. An IP seems to be included if 3 or more users report it. Its retention pocily seems 30 days.

Source is downloaded from [this link](http://danger.rulez.sk/projects/bruteforceblocker/blist.php).

The last time downloaded was found to be dated: Fri Jun  5 23:00:25 UTC 2015.

The ipset `bruteforceblocker` has **1977** entries, **1977** unique IPs.

The following table shows the overlaps of `bruteforceblocker` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `bruteforceblocker`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `bruteforceblocker`.
- ` this % ` is the percentage **of this ipset (`bruteforceblocker`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[et_compromised](#et_compromised)|2086|2086|1921|92.0%|97.1%|
[alienvault_reputation](#alienvault_reputation)|176034|176034|1277|0.7%|64.5%|
[openbl_60d](#openbl_60d)|7667|7667|1182|15.4%|59.7%|
[openbl_30d](#openbl_30d)|3254|3254|1128|34.6%|57.0%|
[blocklist_de](#blocklist_de)|28768|28768|662|2.3%|33.4%|
[blocklist_de_ssh](#blocklist_de_ssh)|4496|4496|650|14.4%|32.8%|
[shunlist](#shunlist)|1229|1229|450|36.6%|22.7%|
[openbl_7d](#openbl_7d)|893|893|394|44.1%|19.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|191|0.0%|9.6%|
[et_block](#et_block)|1016|18338655|102|0.0%|5.1%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|101|0.0%|5.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|98|0.0%|4.9%|
[openbl_1d](#openbl_1d)|143|143|81|56.6%|4.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|50|0.0%|2.5%|
[stopforumspam_30d](#stopforumspam_30d)|93498|93498|11|0.0%|0.5%|
[stopforumspam_7d](#stopforumspam_7d)|29882|29882|7|0.0%|0.3%|
[blocklist_de_mail](#blocklist_de_mail)|16032|16032|7|0.0%|0.3%|
[blocklist_de_imap](#blocklist_de_imap)|2050|2050|7|0.3%|0.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|5|0.0%|0.2%|
[voipbl](#voipbl)|10452|10864|2|0.0%|0.1%|
[proxz](#proxz)|824|824|2|0.2%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|2|0.0%|0.1%|
[blocklist_de_bots](#blocklist_de_bots)|3330|3330|2|0.0%|0.1%|
[blocklist_de_apache](#blocklist_de_apache)|15058|15058|2|0.0%|0.1%|
[xroxy](#xroxy)|2087|2087|1|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7232|7232|1|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|6466|6466|1|0.0%|0.0%|
[proxyrss](#proxyrss)|1768|1768|1|0.0%|0.0%|
[nixspam](#nixspam)|20080|20080|1|0.0%|0.0%|
[fullbogons](#fullbogons)|3715|670310296|1|0.0%|0.0%|
[dshield](#dshield)|20|5120|1|0.0%|0.0%|
[ciarmy](#ciarmy)|421|421|1|0.2%|0.0%|
[bogons](#bogons)|13|592708608|1|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|180|180|1|0.5%|0.0%|

## ciarmy

[CIArmy.com](http://ciarmy.com/) IPs with poor Rogue Packet score that have not yet been identified as malicious by the community

Source is downloaded from [this link](http://cinsscore.com/list/ci-badguys.txt).

The last time downloaded was found to be dated: Fri Jun  5 22:15:16 UTC 2015.

The ipset `ciarmy` has **421** entries, **421** unique IPs.

The following table shows the overlaps of `ciarmy` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ciarmy`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ciarmy`.
- ` this % ` is the percentage **of this ipset (`ciarmy`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[alienvault_reputation](#alienvault_reputation)|176034|176034|417|0.2%|99.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|86|0.0%|20.4%|
[blocklist_de](#blocklist_de)|28768|28768|37|0.1%|8.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|35|0.0%|8.3%|
[blocklist_de_apache](#blocklist_de_apache)|15058|15058|31|0.2%|7.3%|
[shunlist](#shunlist)|1229|1229|30|2.4%|7.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|23|0.0%|5.4%|
[voipbl](#voipbl)|10452|10864|6|0.0%|1.4%|
[dshield](#dshield)|20|5120|3|0.0%|0.7%|
[blocklist_de_ssh](#blocklist_de_ssh)|4496|4496|3|0.0%|0.7%|
[et_block](#et_block)|1016|18338655|2|0.0%|0.4%|
[blocklist_de_mail](#blocklist_de_mail)|16032|16032|2|0.0%|0.4%|
[blocklist_de_imap](#blocklist_de_imap)|2050|2050|2|0.0%|0.4%|
[stopforumspam_7d](#stopforumspam_7d)|29882|29882|1|0.0%|0.2%|
[stopforumspam_30d](#stopforumspam_30d)|93498|93498|1|0.0%|0.2%|
[stopforumspam_1d](#stopforumspam_1d)|7232|7232|1|0.0%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.2%|
[fullbogons](#fullbogons)|3715|670310296|1|0.0%|0.2%|
[et_compromised](#et_compromised)|2086|2086|1|0.0%|0.2%|
[bruteforceblocker](#bruteforceblocker)|1977|1977|1|0.0%|0.2%|
[bogons](#bogons)|13|592708608|1|0.0%|0.2%|
[blocklist_de_ftp](#blocklist_de_ftp)|868|868|1|0.1%|0.2%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|3708|3708|1|0.0%|0.2%|

## cleanmx_viruses

[Clean-MX.de](http://support.clean-mx.de/clean-mx/viruses.php) IPs with viruses

Source is downloaded from [this link](http://support.clean-mx.de/clean-mx/xmlviruses.php?sort=id%20desc&response=alive).

The last time downloaded was found to be dated: Fri Jun  5 19:36:57 UTC 2015.

The ipset `cleanmx_viruses` has **359** entries, **359** unique IPs.

The following table shows the overlaps of `cleanmx_viruses` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `cleanmx_viruses`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `cleanmx_viruses`.
- ` this % ` is the percentage **of this ipset (`cleanmx_viruses`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|48|0.0%|13.3%|
[malc0de](#malc0de)|371|371|28|7.5%|7.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|20|0.0%|5.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|10|0.0%|2.7%|
[alienvault_reputation](#alienvault_reputation)|176034|176034|8|0.0%|2.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|3|0.0%|0.8%|
[snort_ipfilter](#snort_ipfilter)|9994|9994|1|0.0%|0.2%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|1|0.0%|0.2%|

## dm_tor

[dan.me.uk](https://www.dan.me.uk) dynamic list of TOR exit points

Source is downloaded from [this link](https://www.dan.me.uk/torlist/).

The last time downloaded was found to be dated: Fri Jun  5 22:54:05 UTC 2015.

The ipset `dm_tor` has **6483** entries, **6483** unique IPs.

The following table shows the overlaps of `dm_tor` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `dm_tor`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `dm_tor`.
- ` this % ` is the percentage **of this ipset (`dm_tor`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[bm_tor](#bm_tor)|6533|6533|6425|98.3%|99.1%|
[et_tor](#et_tor)|6610|6610|5721|86.5%|88.2%|
[snort_ipfilter](#snort_ipfilter)|9994|9994|1057|10.5%|16.3%|
[stopforumspam_30d](#stopforumspam_30d)|93498|93498|626|0.6%|9.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|624|0.0%|9.6%|
[stopforumspam_7d](#stopforumspam_7d)|29882|29882|497|1.6%|7.6%|
[stopforumspam_1d](#stopforumspam_1d)|7232|7232|317|4.3%|4.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|188|0.0%|2.8%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|167|44.8%|2.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|164|0.0%|2.5%|
[alienvault_reputation](#alienvault_reputation)|176034|176034|42|0.0%|0.6%|
[php_commenters](#php_commenters)|326|326|33|10.1%|0.5%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|22|0.0%|0.3%|
[openbl_60d](#openbl_60d)|7667|7667|19|0.2%|0.2%|
[et_block](#et_block)|1016|18338655|9|0.0%|0.1%|
[php_harvesters](#php_harvesters)|311|311|7|2.2%|0.1%|
[ri_web_proxies](#ri_web_proxies)|6466|6466|5|0.0%|0.0%|
[php_spammers](#php_spammers)|495|495|5|1.0%|0.0%|
[php_dictionary](#php_dictionary)|508|508|4|0.7%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|4|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|16032|16032|4|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|15058|15058|4|0.0%|0.0%|
[blocklist_de](#blocklist_de)|28768|28768|4|0.0%|0.0%|
[voipbl](#voipbl)|10452|10864|3|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|3|0.0%|0.0%|
[xroxy](#xroxy)|2087|2087|2|0.0%|0.0%|
[sorbs_spam](#sorbs_spam)|27772|28726|2|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|27772|28726|2|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|27772|28726|2|0.0%|0.0%|
[shunlist](#shunlist)|1229|1229|1|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2421|2421|1|0.0%|0.0%|
[proxyrss](#proxyrss)|1768|1768|1|0.0%|0.0%|
[nixspam](#nixspam)|20080|20080|1|0.0%|0.0%|

## dshield

[DShield.org](https://dshield.org/) top 20 attacking class C (/24) subnets over the last three days - **excellent list**

Source is downloaded from [this link](http://feeds.dshield.org/block.txt).

The last time downloaded was found to be dated: Fri Jun  5 19:26:29 UTC 2015.

The ipset `dshield` has **20** entries, **5120** unique IPs.

The following table shows the overlaps of `dshield` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `dshield`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `dshield`.
- ` this % ` is the percentage **of this ipset (`dshield`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[alienvault_reputation](#alienvault_reputation)|176034|176034|3338|1.8%|65.1%|
[et_block](#et_block)|1016|18338655|1024|0.0%|20.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|268|0.0%|5.2%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|256|0.0%|5.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|256|0.0%|5.0%|
[openbl_60d](#openbl_60d)|7667|7667|20|0.2%|0.3%|
[blocklist_de](#blocklist_de)|28768|28768|13|0.0%|0.2%|
[voipbl](#voipbl)|10452|10864|10|0.0%|0.1%|
[openbl_30d](#openbl_30d)|3254|3254|8|0.2%|0.1%|
[blocklist_de_ssh](#blocklist_de_ssh)|4496|4496|7|0.1%|0.1%|
[blocklist_de_apache](#blocklist_de_apache)|15058|15058|5|0.0%|0.0%|
[shunlist](#shunlist)|1229|1229|4|0.3%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|4|0.0%|0.0%|
[zeus_badips](#zeus_badips)|202|202|3|1.4%|0.0%|
[zeus](#zeus)|230|230|3|1.3%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9994|9994|3|0.0%|0.0%|
[ciarmy](#ciarmy)|421|421|3|0.7%|0.0%|
[openbl_7d](#openbl_7d)|893|893|2|0.2%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29882|29882|1|0.0%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|93498|93498|1|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7232|7232|1|0.0%|0.0%|
[sorbs_spam](#sorbs_spam)|27772|28726|1|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|27772|28726|1|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|27772|28726|1|0.0%|0.0%|
[php_harvesters](#php_harvesters)|311|311|1|0.3%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|1|0.0%|0.0%|
[malc0de](#malc0de)|371|371|1|0.2%|0.0%|
[et_compromised](#et_compromised)|2086|2086|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1977|1977|1|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|180|180|1|0.5%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|16032|16032|1|0.0%|0.0%|

## et_block

[EmergingThreats.net](http://www.emergingthreats.net/) default blacklist (at the time of writing includes spamhaus DROP, dshield and abuse.ch trackers, which are available separately too - prefer to use the direct ipsets instead of this, they seem to lag a bit in updates)

Source is downloaded from [this link](http://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt).

The last time downloaded was found to be dated: Thu Jun  4 04:30:01 UTC 2015.

The ipset `et_block` has **1016** entries, **18338655** unique IPs.

The following table shows the overlaps of `et_block` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `et_block`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `et_block`.
- ` this % ` is the percentage **of this ipset (`et_block`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[spamhaus_drop](#spamhaus_drop)|653|18404096|18120448|98.4%|98.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|8598071|2.4%|46.8%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|7079936|77.1%|38.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|2272532|0.2%|12.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|196699|0.1%|1.0%|
[fullbogons](#fullbogons)|3715|670310296|20480|0.0%|0.1%|
[alienvault_reputation](#alienvault_reputation)|176034|176034|5535|3.1%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1043|0.3%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|93498|93498|1028|1.0%|0.0%|
[dshield](#dshield)|20|5120|1024|20.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|486400|517|0.1%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29882|29882|341|1.1%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9994|9994|313|3.1%|0.0%|
[openbl_60d](#openbl_60d)|7667|7667|246|3.2%|0.0%|
[zeus](#zeus)|230|230|223|96.9%|0.0%|
[zeus_badips](#zeus_badips)|202|202|200|99.0%|0.0%|
[blocklist_de](#blocklist_de)|28768|28768|186|0.6%|0.0%|
[openbl_30d](#openbl_30d)|3254|3254|166|5.1%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|4496|4496|111|2.4%|0.0%|
[shunlist](#shunlist)|1229|1229|107|8.7%|0.0%|
[et_compromised](#et_compromised)|2086|2086|102|4.8%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1977|1977|102|5.1%|0.0%|
[nixspam](#nixspam)|20080|20080|99|0.4%|0.0%|
[feodo](#feodo)|96|96|87|90.6%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7232|7232|80|1.1%|0.0%|
[openbl_7d](#openbl_7d)|893|893|49|5.4%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3330|3330|43|1.2%|0.0%|
[sslbl](#sslbl)|369|369|33|8.9%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|29|2.2%|0.0%|
[php_commenters](#php_commenters)|326|326|28|8.5%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|16032|16032|25|0.1%|0.0%|
[voipbl](#voipbl)|10452|10864|21|0.1%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2050|2050|17|0.8%|0.0%|
[palevo](#palevo)|13|13|13|100.0%|0.0%|
[dm_tor](#dm_tor)|6483|6483|9|0.1%|0.0%|
[bm_tor](#bm_tor)|6533|6533|9|0.1%|0.0%|
[sorbs_spam](#sorbs_spam)|27772|28726|8|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|27772|28726|8|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|27772|28726|8|0.0%|0.0%|
[openbl_1d](#openbl_1d)|143|143|8|5.5%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|8|0.0%|0.0%|
[et_tor](#et_tor)|6610|6610|8|0.1%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|7|0.4%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|180|180|7|3.8%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|15058|15058|7|0.0%|0.0%|
[php_dictionary](#php_dictionary)|508|508|4|0.7%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|4|1.0%|0.0%|
[malc0de](#malc0de)|371|371|4|1.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|3708|3708|4|0.1%|0.0%|
[php_spammers](#php_spammers)|495|495|2|0.4%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|2|0.2%|0.0%|
[et_botcc](#et_botcc)|509|509|2|0.3%|0.0%|
[ciarmy](#ciarmy)|421|421|2|0.4%|0.0%|
[xroxy](#xroxy)|2087|2087|1|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2421|2421|1|0.0%|0.0%|
[proxz](#proxz)|824|824|1|0.1%|0.0%|
[proxyrss](#proxyrss)|1768|1768|1|0.0%|0.0%|
[php_harvesters](#php_harvesters)|311|311|1|0.3%|0.0%|

## et_botcc

[EmergingThreats.net Command and Control IPs](http://doc.emergingthreats.net/bin/view/Main/BotCC) These IPs are updates every 24 hours and should be considered VERY highly reliable indications that a host is communicating with a known and active Bot or Malware command and control server - (although they say this includes abuse.ch trackers, it does not - most probably it is the shadowserver.org C&C list)

Source is downloaded from [this link](http://rules.emergingthreats.net/fwrules/emerging-PIX-CC.rules).

The last time downloaded was found to be dated: Thu Jun  4 04:30:01 UTC 2015.

The ipset `et_botcc` has **509** entries, **509** unique IPs.

The following table shows the overlaps of `et_botcc` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `et_botcc`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `et_botcc`.
- ` this % ` is the percentage **of this ipset (`et_botcc`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|78|0.0%|15.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|41|0.0%|8.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|22|0.0%|4.3%|
[alienvault_reputation](#alienvault_reputation)|176034|176034|5|0.0%|0.9%|
[et_block](#et_block)|1016|18338655|2|0.0%|0.3%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|1|0.0%|0.1%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|1|0.0%|0.1%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.1%|
[blocklist_de_sip](#blocklist_de_sip)|92|92|1|1.0%|0.1%|

## et_compromised

[EmergingThreats.net compromised hosts](http://doc.emergingthreats.net/bin/view/Main/CompromisedHost) - (this seems to be based on bruteforceblocker)

Source is downloaded from [this link](http://rules.emergingthreats.net/blockrules/compromised-ips.txt).

The last time downloaded was found to be dated: Thu Jun  4 04:30:08 UTC 2015.

The ipset `et_compromised` has **2086** entries, **2086** unique IPs.

The following table shows the overlaps of `et_compromised` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `et_compromised`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `et_compromised`.
- ` this % ` is the percentage **of this ipset (`et_compromised`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[bruteforceblocker](#bruteforceblocker)|1977|1977|1921|97.1%|92.0%|
[alienvault_reputation](#alienvault_reputation)|176034|176034|1363|0.7%|65.3%|
[openbl_60d](#openbl_60d)|7667|7667|1267|16.5%|60.7%|
[openbl_30d](#openbl_30d)|3254|3254|1189|36.5%|56.9%|
[blocklist_de](#blocklist_de)|28768|28768|636|2.2%|30.4%|
[blocklist_de_ssh](#blocklist_de_ssh)|4496|4496|624|13.8%|29.9%|
[shunlist](#shunlist)|1229|1229|462|37.5%|22.1%|
[openbl_7d](#openbl_7d)|893|893|387|43.3%|18.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|209|0.0%|10.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|105|0.0%|5.0%|
[et_block](#et_block)|1016|18338655|102|0.0%|4.8%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|100|0.0%|4.7%|
[openbl_1d](#openbl_1d)|143|143|77|53.8%|3.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|59|0.0%|2.8%|
[stopforumspam_30d](#stopforumspam_30d)|93498|93498|10|0.0%|0.4%|
[blocklist_de_mail](#blocklist_de_mail)|16032|16032|8|0.0%|0.3%|
[blocklist_de_imap](#blocklist_de_imap)|2050|2050|8|0.3%|0.3%|
[stopforumspam_7d](#stopforumspam_7d)|29882|29882|6|0.0%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|5|0.0%|0.2%|
[voipbl](#voipbl)|10452|10864|2|0.0%|0.0%|
[proxz](#proxz)|824|824|2|0.2%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|2|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|15058|15058|2|0.0%|0.0%|
[xroxy](#xroxy)|2087|2087|1|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7232|7232|1|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|6466|6466|1|0.0%|0.0%|
[proxyrss](#proxyrss)|1768|1768|1|0.0%|0.0%|
[nixspam](#nixspam)|20080|20080|1|0.0%|0.0%|
[dshield](#dshield)|20|5120|1|0.0%|0.0%|
[ciarmy](#ciarmy)|421|421|1|0.2%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3330|3330|1|0.0%|0.0%|

## et_tor

[EmergingThreats.net](http://www.emergingthreats.net/) [list](http://doc.emergingthreats.net/bin/view/Main/TorRules) of TOR network IPs

Source is downloaded from [this link](http://rules.emergingthreats.net/blockrules/emerging-tor.rules).

The last time downloaded was found to be dated: Thu Jun  4 04:30:08 UTC 2015.

The ipset `et_tor` has **6610** entries, **6610** unique IPs.

The following table shows the overlaps of `et_tor` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `et_tor`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `et_tor`.
- ` this % ` is the percentage **of this ipset (`et_tor`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[bm_tor](#bm_tor)|6533|6533|5732|87.7%|86.7%|
[dm_tor](#dm_tor)|6483|6483|5721|88.2%|86.5%|
[snort_ipfilter](#snort_ipfilter)|9994|9994|1111|11.1%|16.8%|
[stopforumspam_30d](#stopforumspam_30d)|93498|93498|644|0.6%|9.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|635|0.0%|9.6%|
[stopforumspam_7d](#stopforumspam_7d)|29882|29882|516|1.7%|7.8%|
[stopforumspam_1d](#stopforumspam_1d)|7232|7232|319|4.4%|4.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|187|0.0%|2.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|173|0.0%|2.6%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|172|46.2%|2.6%|
[alienvault_reputation](#alienvault_reputation)|176034|176034|43|0.0%|0.6%|
[php_commenters](#php_commenters)|326|326|35|10.7%|0.5%|
[openbl_60d](#openbl_60d)|7667|7667|21|0.2%|0.3%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|21|0.0%|0.3%|
[et_block](#et_block)|1016|18338655|8|0.0%|0.1%|
[php_harvesters](#php_harvesters)|311|311|7|2.2%|0.1%|
[php_spammers](#php_spammers)|495|495|6|1.2%|0.0%|
[ri_web_proxies](#ri_web_proxies)|6466|6466|5|0.0%|0.0%|
[php_dictionary](#php_dictionary)|508|508|5|0.9%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|16032|16032|4|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|15058|15058|4|0.0%|0.0%|
[blocklist_de](#blocklist_de)|28768|28768|4|0.0%|0.0%|
[voipbl](#voipbl)|10452|10864|3|0.0%|0.0%|
[sorbs_spam](#sorbs_spam)|27772|28726|3|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|27772|28726|3|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|27772|28726|3|0.0%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|0.0%|
[xroxy](#xroxy)|2087|2087|2|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|2|0.0%|0.0%|
[shunlist](#shunlist)|1229|1229|1|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2421|2421|1|0.0%|0.0%|
[proxyrss](#proxyrss)|1768|1768|1|0.0%|0.0%|
[nixspam](#nixspam)|20080|20080|1|0.0%|0.0%|

## feodo

[Abuse.ch Feodo tracker](https://feodotracker.abuse.ch) trojan includes IPs which are being used by Feodo (also known as Cridex or Bugat) which commits ebanking fraud - **excellent list**

Source is downloaded from [this link](https://feodotracker.abuse.ch/blocklist/?download=ipblocklist).

The last time downloaded was found to be dated: Fri Jun  5 22:54:18 UTC 2015.

The ipset `feodo` has **96** entries, **96** unique IPs.

The following table shows the overlaps of `feodo` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `feodo`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `feodo`.
- ` this % ` is the percentage **of this ipset (`feodo`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[et_block](#et_block)|1016|18338655|87|0.0%|90.6%|
[snort_ipfilter](#snort_ipfilter)|9994|9994|74|0.7%|77.0%|
[sslbl](#sslbl)|369|369|36|9.7%|37.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|10|0.0%|10.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|3|0.0%|3.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|3|0.0%|3.1%|
[alienvault_reputation](#alienvault_reputation)|176034|176034|2|0.0%|2.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|1.0%|

## fullbogons

[Team-Cymru.org](http://www.team-cymru.org) IP space that has been allocated to an RIR, but not assigned by that RIR to an actual ISP or other end-user - **excellent list - use it only your internet interface**

Source is downloaded from [this link](http://www.team-cymru.org/Services/Bogons/fullbogons-ipv4.txt).

The last time downloaded was found to be dated: Fri Jun  5 09:35:07 UTC 2015.

The ipset `fullbogons` has **3715** entries, **670310296** unique IPs.

The following table shows the overlaps of `fullbogons` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `fullbogons`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `fullbogons`.
- ` this % ` is the percentage **of this ipset (`fullbogons`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[bogons](#bogons)|13|592708608|592708608|100.0%|88.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|4236335|3.0%|0.6%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|565248|6.1%|0.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|249087|0.0%|0.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|239993|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|151552|0.8%|0.0%|
[et_block](#et_block)|1016|18338655|20480|0.1%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|890|0.2%|0.0%|
[voipbl](#voipbl)|10452|10864|319|2.9%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|33|2.2%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|15|0.0%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|9|0.6%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|93498|93498|2|0.0%|0.0%|
[php_harvesters](#php_harvesters)|311|311|1|0.3%|0.0%|
[ciarmy](#ciarmy)|421|421|1|0.2%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1977|1977|1|0.0%|0.0%|

## ib_bluetack_badpeers

[iBlocklist.com](https://www.iblocklist.com/) free version of [BlueTack.co.uk](http://www.bluetack.co.uk/) IPs that have been reported for bad deeds in p2p

Source is downloaded from [this link](http://list.iblocklist.com/?list=cwworuawihqvocglcoss&fileformat=p2p&archiveformat=gz).

The last time downloaded was found to be dated: Fri Jun  5 04:40:53 UTC 2015.

The ipset `ib_bluetack_badpeers` has **48134** entries, **48134** unique IPs.

The following table shows the overlaps of `ib_bluetack_badpeers` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ib_bluetack_badpeers`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ib_bluetack_badpeers`.
- ` this % ` is the percentage **of this ipset (`ib_bluetack_badpeers`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|1172|0.0%|2.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|406|0.0%|0.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|230|0.0%|0.4%|
[fullbogons](#fullbogons)|3715|670310296|15|0.0%|0.0%|
[alienvault_reputation](#alienvault_reputation)|176034|176034|15|0.0%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|93498|93498|14|0.0%|0.0%|
[sorbs_spam](#sorbs_spam)|27772|28726|13|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|27772|28726|13|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|27772|28726|13|0.0%|0.0%|
[blocklist_de](#blocklist_de)|28768|28768|12|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|11|1.6%|0.0%|
[nixspam](#nixspam)|20080|20080|10|0.0%|0.0%|
[et_block](#et_block)|1016|18338655|8|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|6|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|3708|3708|6|0.1%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|15058|15058|6|0.0%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29882|29882|5|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|4|0.0%|0.0%|
[dshield](#dshield)|20|5120|4|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|16032|16032|4|0.0%|0.0%|
[xroxy](#xroxy)|2087|2087|3|0.1%|0.0%|
[voipbl](#voipbl)|10452|10864|2|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7232|7232|2|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|6466|6466|2|0.0%|0.0%|
[php_harvesters](#php_harvesters)|311|311|2|0.6%|0.0%|
[php_dictionary](#php_dictionary)|508|508|2|0.3%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2050|2050|2|0.0%|0.0%|
[sorbs_web](#sorbs_web)|588|589|1|0.1%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9994|9994|1|0.0%|0.0%|
[proxz](#proxz)|824|824|1|0.1%|0.0%|
[php_spammers](#php_spammers)|495|495|1|0.2%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|4496|4496|1|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3330|3330|1|0.0%|0.0%|

## ib_bluetack_hijacked

[iBlocklist.com](https://www.iblocklist.com/) free version of [BlueTack.co.uk](http://www.bluetack.co.uk/) hijacked IP-Blocks Hijacked IP space are IP blocks that are being used without permission

Source is downloaded from [this link](http://list.iblocklist.com/?list=usrcshglbiilevmyfhse&fileformat=p2p&archiveformat=gz).

The last time downloaded was found to be dated: Fri Jun  5 05:10:45 UTC 2015.

The ipset `ib_bluetack_hijacked` has **535** entries, **9177856** unique IPs.

The following table shows the overlaps of `ib_bluetack_hijacked` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ib_bluetack_hijacked`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ib_bluetack_hijacked`.
- ` this % ` is the percentage **of this ipset (`ib_bluetack_hijacked`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[et_block](#et_block)|1016|18338655|7079936|38.6%|77.1%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|6998016|38.0%|76.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|2526625|0.7%|27.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|904796|0.1%|9.8%|
[fullbogons](#fullbogons)|3715|670310296|565248|0.0%|6.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|145472|0.1%|1.5%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1036|0.3%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|93498|93498|759|0.8%|0.0%|
[alienvault_reputation](#alienvault_reputation)|176034|176034|518|0.2%|0.0%|
[dshield](#dshield)|20|5120|256|5.0%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29882|29882|177|0.5%|0.0%|
[nixspam](#nixspam)|20080|20080|98|0.4%|0.0%|
[blocklist_de](#blocklist_de)|28768|28768|51|0.1%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3330|3330|35|1.0%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|27|2.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7232|7232|22|0.3%|0.0%|
[openbl_60d](#openbl_60d)|7667|7667|18|0.2%|0.0%|
[openbl_30d](#openbl_30d)|3254|3254|13|0.3%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9994|9994|11|0.1%|0.0%|
[zeus_badips](#zeus_badips)|202|202|10|4.9%|0.0%|
[zeus](#zeus)|230|230|10|4.3%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|4496|4496|8|0.1%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|7|0.4%|0.0%|
[openbl_7d](#openbl_7d)|893|893|5|0.5%|0.0%|
[et_compromised](#et_compromised)|2086|2086|5|0.2%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1977|1977|5|0.2%|0.0%|
[sorbs_spam](#sorbs_spam)|27772|28726|4|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|27772|28726|4|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|27772|28726|4|0.0%|0.0%|
[dm_tor](#dm_tor)|6483|6483|4|0.0%|0.0%|
[bm_tor](#bm_tor)|6533|6533|4|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|16032|16032|4|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|15058|15058|4|0.0%|0.0%|
[et_tor](#et_tor)|6610|6610|3|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|180|180|3|1.6%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2050|2050|3|0.1%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|3708|3708|3|0.0%|0.0%|
[shunlist](#shunlist)|1229|1229|2|0.1%|0.0%|
[php_spammers](#php_spammers)|495|495|2|0.4%|0.0%|
[php_dictionary](#php_dictionary)|508|508|2|0.3%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|2|0.2%|0.0%|
[voipbl](#voipbl)|10452|10864|1|0.0%|0.0%|
[php_harvesters](#php_harvesters)|311|311|1|0.3%|0.0%|
[php_commenters](#php_commenters)|326|326|1|0.3%|0.0%|
[et_botcc](#et_botcc)|509|509|1|0.1%|0.0%|

## ib_bluetack_level1

[iBlocklist.com](https://www.iblocklist.com/) free version of [BlueTack.co.uk](http://www.bluetack.co.uk/) Level 1 (for use in p2p): Companies or organizations who are clearly involved with trying to stop filesharing (e.g. Baytsp, MediaDefender, Mediasentry a.o.). Companies which anti-p2p activity has been seen from. Companies that produce or have a strong financial interest in copyrighted material (e.g. music, movie, software industries a.o.). Government ranges or companies that have a strong financial interest in doing work for governments. Legal industry ranges. IPs or ranges of ISPs from which anti-p2p activity has been observed. Basically this list will block all kinds of internet connections that most people would rather not have during their internet travels.

Source is downloaded from [this link](http://list.iblocklist.com/?list=ydxerpxkpcfqjaybcssw&fileformat=p2p&archiveformat=gz).

The last time downloaded was found to be dated: Fri Jun  5 09:14:41 UTC 2015.

The ipset `ib_bluetack_level1` has **218309** entries, **764987411** unique IPs.

The following table shows the overlaps of `ib_bluetack_level1` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ib_bluetack_level1`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ib_bluetack_level1`.
- ` this % ` is the percentage **of this ipset (`ib_bluetack_level1`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|16300309|4.6%|2.1%|
[et_block](#et_block)|1016|18338655|2272532|12.3%|0.2%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|2272265|12.3%|0.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|1354348|0.9%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|904796|9.8%|0.1%|
[fullbogons](#fullbogons)|3715|670310296|239993|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|486400|33155|6.8%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|13248|3.9%|0.0%|
[alienvault_reputation](#alienvault_reputation)|176034|176034|4727|2.6%|0.0%|
[blocklist_de](#blocklist_de)|28768|28768|1556|5.4%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|93498|93498|1554|1.6%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|16032|16032|1371|8.5%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|15058|15058|1328|8.8%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29882|29882|566|1.8%|0.0%|
[sorbs_spam](#sorbs_spam)|27772|28726|450|1.5%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|27772|28726|450|1.5%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|27772|28726|450|1.5%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|406|0.8%|0.0%|
[nixspam](#nixspam)|20080|20080|388|1.9%|0.0%|
[voipbl](#voipbl)|10452|10864|299|2.7%|0.0%|
[dshield](#dshield)|20|5120|268|5.2%|0.0%|
[et_tor](#et_tor)|6610|6610|173|2.6%|0.0%|
[openbl_60d](#openbl_60d)|7667|7667|172|2.2%|0.0%|
[bm_tor](#bm_tor)|6533|6533|165|2.5%|0.0%|
[dm_tor](#dm_tor)|6483|6483|164|2.5%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7232|7232|155|2.1%|0.0%|
[ri_web_proxies](#ri_web_proxies)|6466|6466|134|2.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|97|6.6%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9994|9994|92|0.9%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|4496|4496|86|1.9%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2421|2421|75|3.0%|0.0%|
[openbl_30d](#openbl_30d)|3254|3254|72|2.2%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|66|5.1%|0.0%|
[et_compromised](#et_compromised)|2086|2086|59|2.8%|0.0%|
[xroxy](#xroxy)|2087|2087|58|2.7%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|58|8.6%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1977|1977|50|2.5%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3330|3330|44|1.3%|0.0%|
[et_botcc](#et_botcc)|509|509|41|8.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|3708|3708|37|0.9%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2050|2050|35|1.7%|0.0%|
[proxyrss](#proxyrss)|1768|1768|34|1.9%|0.0%|
[proxz](#proxz)|824|824|29|3.5%|0.0%|
[shunlist](#shunlist)|1229|1229|27|2.1%|0.0%|
[ciarmy](#ciarmy)|421|421|23|5.4%|0.0%|
[sorbs_web](#sorbs_web)|588|589|21|3.5%|0.0%|
[openbl_7d](#openbl_7d)|893|893|19|2.1%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|17|4.5%|0.0%|
[php_dictionary](#php_dictionary)|508|508|11|2.1%|0.0%|
[malc0de](#malc0de)|371|371|11|2.9%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|359|359|10|2.7%|0.0%|
[php_harvesters](#php_harvesters)|311|311|9|2.8%|0.0%|
[php_spammers](#php_spammers)|495|495|7|1.4%|0.0%|
[php_commenters](#php_commenters)|326|326|7|2.1%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|868|868|7|0.8%|0.0%|
[zeus](#zeus)|230|230|6|2.6%|0.0%|
[bogons](#bogons)|13|592708608|5|0.0%|0.0%|
[zeus_badips](#zeus_badips)|202|202|4|1.9%|0.0%|
[sslbl](#sslbl)|369|369|3|0.8%|0.0%|
[feodo](#feodo)|96|96|3|3.1%|0.0%|
[openbl_1d](#openbl_1d)|143|143|2|1.3%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|92|92|2|2.1%|0.0%|
[virbl](#virbl)|12|12|1|8.3%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|180|180|1|0.5%|0.0%|

## ib_bluetack_level2

[iBlocklist.com](https://www.iblocklist.com/) free version of BlueTack.co.uk Level 2 (for use in p2p). General corporate ranges. Ranges used by labs or researchers. Proxies.

Source is downloaded from [this link](http://list.iblocklist.com/?list=gyisgnzbhppbvsphucsw&fileformat=p2p&archiveformat=gz).

The last time downloaded was found to be dated: Fri Jun  5 05:10:25 UTC 2015.

The ipset `ib_bluetack_level2` has **72774** entries, **348707599** unique IPs.

The following table shows the overlaps of `ib_bluetack_level2` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ib_bluetack_level2`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ib_bluetack_level2`.
- ` this % ` is the percentage **of this ipset (`ib_bluetack_level2`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|16300309|2.1%|4.6%|
[et_block](#et_block)|1016|18338655|8598071|46.8%|2.4%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|8598042|46.7%|2.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|2830140|2.0%|0.8%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2526625|27.5%|0.7%|
[fullbogons](#fullbogons)|3715|670310296|249087|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|486400|98904|20.3%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|7733|2.2%|0.0%|
[alienvault_reputation](#alienvault_reputation)|176034|176034|7286|4.1%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|93498|93498|2548|2.7%|0.0%|
[blocklist_de](#blocklist_de)|28768|28768|1509|5.2%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|16032|16032|1151|7.1%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|15058|15058|1088|7.2%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29882|29882|932|3.1%|0.0%|
[sorbs_spam](#sorbs_spam)|27772|28726|735|2.5%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|27772|28726|735|2.5%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|27772|28726|735|2.5%|0.0%|
[nixspam](#nixspam)|20080|20080|572|2.8%|0.0%|
[voipbl](#voipbl)|10452|10864|434|3.9%|0.0%|
[openbl_60d](#openbl_60d)|7667|7667|335|4.3%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|230|0.4%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7232|7232|218|3.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|6466|6466|189|2.9%|0.0%|
[dm_tor](#dm_tor)|6483|6483|188|2.8%|0.0%|
[bm_tor](#bm_tor)|6533|6533|188|2.8%|0.0%|
[et_tor](#et_tor)|6610|6610|187|2.8%|0.0%|
[openbl_30d](#openbl_30d)|3254|3254|168|5.1%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|4496|4496|161|3.5%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3330|3330|114|3.4%|0.0%|
[et_compromised](#et_compromised)|2086|2086|105|5.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9994|9994|103|1.0%|0.0%|
[xroxy](#xroxy)|2087|2087|100|4.7%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1977|1977|98|4.9%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2421|2421|95|3.9%|0.0%|
[shunlist](#shunlist)|1229|1229|72|5.8%|0.0%|
[proxyrss](#proxyrss)|1768|1768|66|3.7%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2050|2050|56|2.7%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|3708|3708|55|1.4%|0.0%|
[openbl_7d](#openbl_7d)|893|893|46|5.1%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|45|3.0%|0.0%|
[php_spammers](#php_spammers)|495|495|36|7.2%|0.0%|
[ciarmy](#ciarmy)|421|421|35|8.3%|0.0%|
[proxz](#proxz)|824|824|33|4.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|28|4.1%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|26|2.0%|0.0%|
[sorbs_web](#sorbs_web)|588|589|23|3.9%|0.0%|
[malc0de](#malc0de)|371|371|22|5.9%|0.0%|
[et_botcc](#et_botcc)|509|509|22|4.3%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|21|5.6%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|359|359|20|5.5%|0.0%|
[php_dictionary](#php_dictionary)|508|508|13|2.5%|0.0%|
[php_commenters](#php_commenters)|326|326|13|3.9%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|868|868|13|1.4%|0.0%|
[zeus](#zeus)|230|230|9|3.9%|0.0%|
[php_harvesters](#php_harvesters)|311|311|9|2.8%|0.0%|
[zeus_badips](#zeus_badips)|202|202|8|3.9%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|180|180|8|4.4%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|92|92|8|8.6%|0.0%|
[sslbl](#sslbl)|369|369|6|1.6%|0.0%|
[openbl_1d](#openbl_1d)|143|143|4|2.7%|0.0%|
[feodo](#feodo)|96|96|3|3.1%|0.0%|
[palevo](#palevo)|13|13|2|15.3%|0.0%|
[virbl](#virbl)|12|12|1|8.3%|0.0%|
[sorbs_socks](#sorbs_socks)|19|19|1|5.2%|0.0%|
[sorbs_smtp](#sorbs_smtp)|13|13|1|7.6%|0.0%|
[sorbs_misc](#sorbs_misc)|19|19|1|5.2%|0.0%|
[sorbs_http](#sorbs_http)|19|19|1|5.2%|0.0%|

## ib_bluetack_level3

[iBlocklist.com](https://www.iblocklist.com/) free version of BlueTack.co.uk Level 3 (for use in p2p). Many portal-type websites. ISP ranges that may be dodgy for some reason. Ranges that belong to an individual, but which have not been determined to be used by a particular company. Ranges for things that are unusual in some way. The L3 list is aka the paranoid list.

Source is downloaded from [this link](http://list.iblocklist.com/?list=uwnukjqktoggdknzrhgh&fileformat=p2p&archiveformat=gz).

The last time downloaded was found to be dated: Fri Jun  5 05:10:17 UTC 2015.

The ipset `ib_bluetack_level3` has **17802** entries, **139104824** unique IPs.

The following table shows the overlaps of `ib_bluetack_level3` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ib_bluetack_level3`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ib_bluetack_level3`.
- ` this % ` is the percentage **of this ipset (`ib_bluetack_level3`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[fullbogons](#fullbogons)|3715|670310296|4236335|0.6%|3.0%|
[bogons](#bogons)|13|592708608|4194304|0.7%|3.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|2830140|0.8%|2.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|1354348|0.1%|0.9%|
[spamhaus_edrop](#spamhaus_edrop)|55|486400|270785|55.6%|0.1%|
[et_block](#et_block)|1016|18338655|196699|1.0%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|145472|1.5%|0.1%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|130368|0.7%|0.0%|
[alienvault_reputation](#alienvault_reputation)|176034|176034|13886|7.8%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|9231|2.7%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|93498|93498|5886|6.2%|0.0%|
[blocklist_de](#blocklist_de)|28768|28768|3842|13.3%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|16032|16032|2502|15.6%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|15058|15058|2372|15.7%|0.0%|
[sorbs_spam](#sorbs_spam)|27772|28726|2047|7.1%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|27772|28726|2047|7.1%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|27772|28726|2047|7.1%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29882|29882|1876|6.2%|0.0%|
[voipbl](#voipbl)|10452|10864|1598|14.7%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1172|2.4%|0.0%|
[nixspam](#nixspam)|20080|20080|1165|5.8%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|4496|4496|757|16.8%|0.0%|
[openbl_60d](#openbl_60d)|7667|7667|745|9.7%|0.0%|
[et_tor](#et_tor)|6610|6610|635|9.6%|0.0%|
[dm_tor](#dm_tor)|6483|6483|624|9.6%|0.0%|
[bm_tor](#bm_tor)|6533|6533|624|9.5%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7232|7232|527|7.2%|0.0%|
[openbl_30d](#openbl_30d)|3254|3254|311|9.5%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|3708|3708|272|7.3%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2050|2050|232|11.3%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9994|9994|231|2.3%|0.0%|
[et_compromised](#et_compromised)|2086|2086|209|10.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3330|3330|196|5.8%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1977|1977|191|9.6%|0.0%|
[ri_web_proxies](#ri_web_proxies)|6466|6466|187|2.8%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|147|11.4%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|125|33.6%|0.0%|
[openbl_7d](#openbl_7d)|893|893|116|12.9%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|110|7.5%|0.0%|
[shunlist](#shunlist)|1229|1229|107|8.7%|0.0%|
[xroxy](#xroxy)|2087|2087|93|4.4%|0.0%|
[ciarmy](#ciarmy)|421|421|86|20.4%|0.0%|
[et_botcc](#et_botcc)|509|509|78|15.3%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|868|868|75|8.6%|0.0%|
[proxz](#proxz)|824|824|69|8.3%|0.0%|
[malc0de](#malc0de)|371|371|61|16.4%|0.0%|
[proxyrss](#proxyrss)|1768|1768|57|3.2%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2421|2421|53|2.1%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|51|7.5%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|359|359|48|13.3%|0.0%|
[sorbs_web](#sorbs_web)|588|589|38|6.4%|0.0%|
[php_dictionary](#php_dictionary)|508|508|29|5.7%|0.0%|
[php_spammers](#php_spammers)|495|495|28|5.6%|0.0%|
[sslbl](#sslbl)|369|369|24|6.5%|0.0%|
[php_commenters](#php_commenters)|326|326|18|5.5%|0.0%|
[php_harvesters](#php_harvesters)|311|311|17|5.4%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|180|180|16|8.8%|0.0%|
[openbl_1d](#openbl_1d)|143|143|15|10.4%|0.0%|
[zeus](#zeus)|230|230|14|6.0%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|92|92|13|14.1%|0.0%|
[zeus_badips](#zeus_badips)|202|202|10|4.9%|0.0%|
[feodo](#feodo)|96|96|10|10.4%|0.0%|
[virbl](#virbl)|12|12|1|8.3%|0.0%|
[palevo](#palevo)|13|13|1|7.6%|0.0%|

## ib_bluetack_proxies

[iBlocklist.com](https://www.iblocklist.com/) free version of [BlueTack.co.uk](http://www.bluetack.co.uk/) Open Proxies IPs list (without TOR)

Source is downloaded from [this link](http://list.iblocklist.com/?list=xoebmbyexwuiogmbyprb&fileformat=p2p&archiveformat=gz).

The last time downloaded was found to be dated: Fri Jun  5 05:10:10 UTC 2015.

The ipset `ib_bluetack_proxies` has **673** entries, **673** unique IPs.

The following table shows the overlaps of `ib_bluetack_proxies` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ib_bluetack_proxies`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ib_bluetack_proxies`.
- ` this % ` is the percentage **of this ipset (`ib_bluetack_proxies`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|58|0.0%|8.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|51|0.0%|7.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|28|0.0%|4.1%|
[stopforumspam_30d](#stopforumspam_30d)|93498|93498|22|0.0%|3.2%|
[xroxy](#xroxy)|2087|2087|13|0.6%|1.9%|
[stopforumspam_7d](#stopforumspam_7d)|29882|29882|12|0.0%|1.7%|
[ri_web_proxies](#ri_web_proxies)|6466|6466|12|0.1%|1.7%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|11|0.0%|1.6%|
[proxyrss](#proxyrss)|1768|1768|8|0.4%|1.1%|
[ri_connect_proxies](#ri_connect_proxies)|2421|2421|6|0.2%|0.8%|
[blocklist_de](#blocklist_de)|28768|28768|6|0.0%|0.8%|
[proxz](#proxz)|824|824|5|0.6%|0.7%|
[blocklist_de_bots](#blocklist_de_bots)|3330|3330|5|0.1%|0.7%|
[stopforumspam_1d](#stopforumspam_1d)|7232|7232|3|0.0%|0.4%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|2|0.0%|0.2%|
[sorbs_spam](#sorbs_spam)|27772|28726|2|0.0%|0.2%|
[sorbs_recent_spam](#sorbs_recent_spam)|27772|28726|2|0.0%|0.2%|
[sorbs_new_spam](#sorbs_new_spam)|27772|28726|2|0.0%|0.2%|
[nixspam](#nixspam)|20080|20080|2|0.0%|0.2%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2|0.0%|0.2%|
[et_block](#et_block)|1016|18338655|2|0.0%|0.2%|
[snort_ipfilter](#snort_ipfilter)|9994|9994|1|0.0%|0.1%|
[php_dictionary](#php_dictionary)|508|508|1|0.1%|0.1%|
[blocklist_de_mail](#blocklist_de_mail)|16032|16032|1|0.0%|0.1%|
[alienvault_reputation](#alienvault_reputation)|176034|176034|1|0.0%|0.1%|

## ib_bluetack_spyware

[iBlocklist.com](https://www.iblocklist.com/) free version of [BlueTack.co.uk](http://www.bluetack.co.uk/) known malicious SPYWARE and ADWARE IP Address ranges

Source is downloaded from [this link](http://list.iblocklist.com/?list=llvtlsjyoyiczbkjsxpf&fileformat=p2p&archiveformat=gz).

The last time downloaded was found to be dated: Fri Jun  5 04:40:02 UTC 2015.

The ipset `ib_bluetack_spyware` has **3274** entries, **339192** unique IPs.

The following table shows the overlaps of `ib_bluetack_spyware` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ib_bluetack_spyware`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ib_bluetack_spyware`.
- ` this % ` is the percentage **of this ipset (`ib_bluetack_spyware`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|13248|0.0%|3.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|9231|0.0%|2.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|7733|0.0%|2.2%|
[et_block](#et_block)|1016|18338655|1043|0.0%|0.3%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|1037|0.0%|0.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1036|0.0%|0.3%|
[fullbogons](#fullbogons)|3715|670310296|890|0.0%|0.2%|
[alienvault_reputation](#alienvault_reputation)|176034|176034|287|0.1%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|93498|93498|47|0.0%|0.0%|
[sorbs_spam](#sorbs_spam)|27772|28726|31|0.1%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|27772|28726|31|0.1%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|27772|28726|31|0.1%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|27|2.0%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29882|29882|24|0.0%|0.0%|
[dm_tor](#dm_tor)|6483|6483|22|0.3%|0.0%|
[bm_tor](#bm_tor)|6533|6533|22|0.3%|0.0%|
[et_tor](#et_tor)|6610|6610|21|0.3%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|19|1.3%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9994|9994|13|0.1%|0.0%|
[nixspam](#nixspam)|20080|20080|11|0.0%|0.0%|
[blocklist_de](#blocklist_de)|28768|28768|11|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7232|7232|8|0.1%|0.0%|
[ri_web_proxies](#ri_web_proxies)|6466|6466|5|0.0%|0.0%|
[openbl_60d](#openbl_60d)|7667|7667|5|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|5|1.3%|0.0%|
[voipbl](#voipbl)|10452|10864|4|0.0%|0.0%|
[openbl_30d](#openbl_30d)|3254|3254|4|0.1%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|4|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|16032|16032|4|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3330|3330|4|0.1%|0.0%|
[malc0de](#malc0de)|371|371|3|0.8%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|359|359|3|0.8%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|15058|15058|3|0.0%|0.0%|
[et_compromised](#et_compromised)|2086|2086|2|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1977|1977|2|0.1%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|92|92|2|2.1%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2050|2050|2|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|3708|3708|2|0.0%|0.0%|
[zeus_badips](#zeus_badips)|202|202|1|0.4%|0.0%|
[zeus](#zeus)|230|230|1|0.4%|0.0%|
[xroxy](#xroxy)|2087|2087|1|0.0%|0.0%|
[sslbl](#sslbl)|369|369|1|0.2%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|486400|1|0.0%|0.0%|
[shunlist](#shunlist)|1229|1229|1|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2421|2421|1|0.0%|0.0%|
[proxyrss](#proxyrss)|1768|1768|1|0.0%|0.0%|
[php_harvesters](#php_harvesters)|311|311|1|0.3%|0.0%|
[php_dictionary](#php_dictionary)|508|508|1|0.1%|0.0%|
[palevo](#palevo)|13|13|1|7.6%|0.0%|
[openbl_7d](#openbl_7d)|893|893|1|0.1%|0.0%|
[feodo](#feodo)|96|96|1|1.0%|0.0%|
[ciarmy](#ciarmy)|421|421|1|0.2%|0.0%|
[bogons](#bogons)|13|592708608|1|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|4496|4496|1|0.0%|0.0%|

## ib_bluetack_webexploit

[iBlocklist.com](https://www.iblocklist.com/) free version of [BlueTack.co.uk](http://www.bluetack.co.uk/) web server hack and exploit attempts

Source is downloaded from [this link](http://list.iblocklist.com/?list=ghlzqtqxnzctvvajwwag&fileformat=p2p&archiveformat=gz).

The last time downloaded was found to be dated: Fri Jun  5 04:40:03 UTC 2015.

The ipset `ib_bluetack_webexploit` has **1460** entries, **1460** unique IPs.

The following table shows the overlaps of `ib_bluetack_webexploit` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ib_bluetack_webexploit`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ib_bluetack_webexploit`.
- ` this % ` is the percentage **of this ipset (`ib_bluetack_webexploit`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|110|0.0%|7.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|97|0.0%|6.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|45|0.0%|3.0%|
[fullbogons](#fullbogons)|3715|670310296|33|0.0%|2.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|19|0.0%|1.3%|
[alienvault_reputation](#alienvault_reputation)|176034|176034|8|0.0%|0.5%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|7|0.0%|0.4%|
[et_block](#et_block)|1016|18338655|7|0.0%|0.4%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|6|0.0%|0.4%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|3|0.2%|0.2%|
[blocklist_de](#blocklist_de)|28768|28768|3|0.0%|0.2%|
[stopforumspam_30d](#stopforumspam_30d)|93498|93498|2|0.0%|0.1%|
[stopforumspam_1d](#stopforumspam_1d)|7232|7232|2|0.0%|0.1%|
[openbl_60d](#openbl_60d)|7667|7667|2|0.0%|0.1%|
[openbl_30d](#openbl_30d)|3254|3254|2|0.0%|0.1%|
[nixspam](#nixspam)|20080|20080|2|0.0%|0.1%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|2|0.2%|0.1%|
[blocklist_de_strongips](#blocklist_de_strongips)|180|180|2|1.1%|0.1%|
[blocklist_de_bots](#blocklist_de_bots)|3330|3330|2|0.0%|0.1%|
[stopforumspam_7d](#stopforumspam_7d)|29882|29882|1|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9994|9994|1|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|6466|6466|1|0.0%|0.0%|
[openbl_7d](#openbl_7d)|893|893|1|0.1%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1|0.0%|0.0%|
[et_botcc](#et_botcc)|509|509|1|0.1%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|4496|4496|1|0.0%|0.0%|

## malc0de

[Malc0de.com](http://malc0de.com) malicious IPs of the last 30 days

Source is downloaded from [this link](http://malc0de.com/bl/IP_Blacklist.txt).

The last time downloaded was found to be dated: Fri Jun  5 13:17:02 UTC 2015.

The ipset `malc0de` has **371** entries, **371** unique IPs.

The following table shows the overlaps of `malc0de` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `malc0de`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `malc0de`.
- ` this % ` is the percentage **of this ipset (`malc0de`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|61|0.0%|16.4%|
[cleanmx_viruses](#cleanmx_viruses)|359|359|28|7.7%|7.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|22|0.0%|5.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|11|0.0%|2.9%|
[alienvault_reputation](#alienvault_reputation)|176034|176034|11|0.0%|2.9%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|4|0.0%|1.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|4|0.3%|1.0%|
[et_block](#et_block)|1016|18338655|4|0.0%|1.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|3|0.0%|0.8%|
[spamhaus_edrop](#spamhaus_edrop)|55|486400|1|0.0%|0.2%|
[dshield](#dshield)|20|5120|1|0.0%|0.2%|

## malwaredomainlist

[malwaredomainlist.com](http://www.malwaredomainlist.com) list of malware active ip addresses

Source is downloaded from [this link](http://www.malwaredomainlist.com/hostslist/ip.txt).

The last time downloaded was found to be dated: Thu Jun  4 07:14:07 UTC 2015.

The ipset `malwaredomainlist` has **1288** entries, **1288** unique IPs.

The following table shows the overlaps of `malwaredomainlist` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `malwaredomainlist`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `malwaredomainlist`.
- ` this % ` is the percentage **of this ipset (`malwaredomainlist`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|147|0.0%|11.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|66|0.0%|5.1%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|29|0.0%|2.2%|
[et_block](#et_block)|1016|18338655|29|0.0%|2.2%|
[snort_ipfilter](#snort_ipfilter)|9994|9994|28|0.2%|2.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|27|0.0%|2.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|27|0.0%|2.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|26|0.0%|2.0%|
[fullbogons](#fullbogons)|3715|670310296|9|0.0%|0.6%|
[alienvault_reputation](#alienvault_reputation)|176034|176034|6|0.0%|0.4%|
[stopforumspam_30d](#stopforumspam_30d)|93498|93498|4|0.0%|0.3%|
[malc0de](#malc0de)|371|371|4|1.0%|0.3%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|3|0.2%|0.2%|
[stopforumspam_7d](#stopforumspam_7d)|29882|29882|2|0.0%|0.1%|
[sorbs_spam](#sorbs_spam)|27772|28726|1|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|27772|28726|1|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|27772|28726|1|0.0%|0.0%|
[nixspam](#nixspam)|20080|20080|1|0.0%|0.0%|
[et_botcc](#et_botcc)|509|509|1|0.1%|0.0%|
[dshield](#dshield)|20|5120|1|0.0%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|359|359|1|0.2%|0.0%|

## maxmind_proxy_fraud

[MaxMind.com](https://www.maxmind.com/en/anonymous-proxy-fraudulent-ip-address-list) list of anonymous proxy fraudelent IP addresses.

Source is downloaded from [this link](https://www.maxmind.com/en/anonymous-proxy-fraudulent-ip-address-list).

The last time downloaded was found to be dated: Fri Jun  5 22:18:59 UTC 2015.

The ipset `maxmind_proxy_fraud` has **372** entries, **372** unique IPs.

The following table shows the overlaps of `maxmind_proxy_fraud` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `maxmind_proxy_fraud`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `maxmind_proxy_fraud`.
- ` this % ` is the percentage **of this ipset (`maxmind_proxy_fraud`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_30d](#stopforumspam_30d)|93498|93498|233|0.2%|62.6%|
[stopforumspam_7d](#stopforumspam_7d)|29882|29882|190|0.6%|51.0%|
[snort_ipfilter](#snort_ipfilter)|9994|9994|178|1.7%|47.8%|
[et_tor](#et_tor)|6610|6610|172|2.6%|46.2%|
[bm_tor](#bm_tor)|6533|6533|168|2.5%|45.1%|
[dm_tor](#dm_tor)|6483|6483|167|2.5%|44.8%|
[stopforumspam_1d](#stopforumspam_1d)|7232|7232|155|2.1%|41.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|125|0.0%|33.6%|
[php_commenters](#php_commenters)|326|326|32|9.8%|8.6%|
[alienvault_reputation](#alienvault_reputation)|176034|176034|26|0.0%|6.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|21|0.0%|5.6%|
[openbl_60d](#openbl_60d)|7667|7667|18|0.2%|4.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|17|0.0%|4.5%|
[php_harvesters](#php_harvesters)|311|311|6|1.9%|1.6%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|5|0.0%|1.3%|
[ri_web_proxies](#ri_web_proxies)|6466|6466|4|0.0%|1.0%|
[php_spammers](#php_spammers)|495|495|4|0.8%|1.0%|
[php_dictionary](#php_dictionary)|508|508|4|0.7%|1.0%|
[et_block](#et_block)|1016|18338655|4|0.0%|1.0%|
[blocklist_de](#blocklist_de)|28768|28768|3|0.0%|0.8%|
[shunlist](#shunlist)|1229|1229|2|0.1%|0.5%|
[blocklist_de_apache](#blocklist_de_apache)|15058|15058|2|0.0%|0.5%|
[xroxy](#xroxy)|2087|2087|1|0.0%|0.2%|
[voipbl](#voipbl)|10452|10864|1|0.0%|0.2%|
[ri_connect_proxies](#ri_connect_proxies)|2421|2421|1|0.0%|0.2%|
[nixspam](#nixspam)|20080|20080|1|0.0%|0.2%|
[blocklist_de_ssh](#blocklist_de_ssh)|4496|4496|1|0.0%|0.2%|
[blocklist_de_mail](#blocklist_de_mail)|16032|16032|1|0.0%|0.2%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|3708|3708|1|0.0%|0.2%|

## nixspam

[NiX Spam](http://www.heise.de/ix/NiX-Spam-DNSBL-and-blacklist-for-download-499637.html) IP addresses that sent spam in the last hour - automatically generated entries without distinguishing open proxies from relays, dialup gateways, and so on. All IPs are removed after 12 hours if there is no spam from there.

Source is downloaded from [this link](http://www.dnsbl.manitu.net/download/nixspam-ip.dump.gz).

The last time downloaded was found to be dated: Fri Jun  5 23:15:02 UTC 2015.

The ipset `nixspam` has **20080** entries, **20080** unique IPs.

The following table shows the overlaps of `nixspam` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `nixspam`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `nixspam`.
- ` this % ` is the percentage **of this ipset (`nixspam`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[sorbs_spam](#sorbs_spam)|27772|28726|4216|14.6%|20.9%|
[sorbs_recent_spam](#sorbs_recent_spam)|27772|28726|4216|14.6%|20.9%|
[sorbs_new_spam](#sorbs_new_spam)|27772|28726|4216|14.6%|20.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|1165|0.0%|5.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|572|0.0%|2.8%|
[blocklist_de](#blocklist_de)|28768|28768|565|1.9%|2.8%|
[blocklist_de_mail](#blocklist_de_mail)|16032|16032|469|2.9%|2.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|388|0.0%|1.9%|
[stopforumspam_30d](#stopforumspam_30d)|93498|93498|188|0.2%|0.9%|
[sorbs_web](#sorbs_web)|588|589|150|25.4%|0.7%|
[snort_ipfilter](#snort_ipfilter)|9994|9994|131|1.3%|0.6%|
[stopforumspam_7d](#stopforumspam_7d)|29882|29882|99|0.3%|0.4%|
[et_block](#et_block)|1016|18338655|99|0.0%|0.4%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|98|0.0%|0.4%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|98|0.0%|0.4%|
[ri_web_proxies](#ri_web_proxies)|6466|6466|79|1.2%|0.3%|
[php_dictionary](#php_dictionary)|508|508|66|12.9%|0.3%|
[alienvault_reputation](#alienvault_reputation)|176034|176034|57|0.0%|0.2%|
[blocklist_de_apache](#blocklist_de_apache)|15058|15058|55|0.3%|0.2%|
[stopforumspam_1d](#stopforumspam_1d)|7232|7232|52|0.7%|0.2%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|3708|3708|52|1.4%|0.2%|
[php_spammers](#php_spammers)|495|495|51|10.3%|0.2%|
[xroxy](#xroxy)|2087|2087|50|2.3%|0.2%|
[blocklist_de_bots](#blocklist_de_bots)|3330|3330|32|0.9%|0.1%|
[proxz](#proxz)|824|824|22|2.6%|0.1%|
[ri_connect_proxies](#ri_connect_proxies)|2421|2421|16|0.6%|0.0%|
[proxyrss](#proxyrss)|1768|1768|13|0.7%|0.0%|
[php_commenters](#php_commenters)|326|326|13|3.9%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|11|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2050|2050|11|0.5%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|10|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|868|868|6|0.6%|0.0%|
[openbl_60d](#openbl_60d)|7667|7667|5|0.0%|0.0%|
[php_harvesters](#php_harvesters)|311|311|4|1.2%|0.0%|
[openbl_30d](#openbl_30d)|3254|3254|4|0.1%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|4496|4496|4|0.0%|0.0%|
[sorbs_socks](#sorbs_socks)|19|19|3|15.7%|0.0%|
[sorbs_misc](#sorbs_misc)|19|19|3|15.7%|0.0%|
[sorbs_http](#sorbs_http)|19|19|3|15.7%|0.0%|
[openbl_7d](#openbl_7d)|893|893|3|0.3%|0.0%|
[shunlist](#shunlist)|1229|1229|2|0.1%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|2|0.2%|0.0%|
[zeus_badips](#zeus_badips)|202|202|1|0.4%|0.0%|
[zeus](#zeus)|230|230|1|0.4%|0.0%|
[voipbl](#voipbl)|10452|10864|1|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|486400|1|0.0%|0.0%|
[openbl_1d](#openbl_1d)|143|143|1|0.6%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|1|0.0%|0.0%|
[et_tor](#et_tor)|6610|6610|1|0.0%|0.0%|
[et_compromised](#et_compromised)|2086|2086|1|0.0%|0.0%|
[dm_tor](#dm_tor)|6483|6483|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1977|1977|1|0.0%|0.0%|
[bm_tor](#bm_tor)|6533|6533|1|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|180|180|1|0.5%|0.0%|

## openbl_1d

[OpenBL.org](http://www.openbl.org/) last 24 hours IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.

Source is downloaded from [this link](http://www.openbl.org/lists/base_1days.txt).

The last time downloaded was found to be dated: Fri Jun  5 22:32:00 UTC 2015.

The ipset `openbl_1d` has **143** entries, **143** unique IPs.

The following table shows the overlaps of `openbl_1d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl_1d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl_1d`.
- ` this % ` is the percentage **of this ipset (`openbl_1d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[openbl_60d](#openbl_60d)|7667|7667|140|1.8%|97.9%|
[openbl_30d](#openbl_30d)|3254|3254|140|4.3%|97.9%|
[alienvault_reputation](#alienvault_reputation)|176034|176034|139|0.0%|97.2%|
[openbl_7d](#openbl_7d)|893|893|137|15.3%|95.8%|
[blocklist_de](#blocklist_de)|28768|28768|115|0.3%|80.4%|
[blocklist_de_ssh](#blocklist_de_ssh)|4496|4496|113|2.5%|79.0%|
[bruteforceblocker](#bruteforceblocker)|1977|1977|81|4.0%|56.6%|
[et_compromised](#et_compromised)|2086|2086|77|3.6%|53.8%|
[shunlist](#shunlist)|1229|1229|62|5.0%|43.3%|
[blocklist_de_strongips](#blocklist_de_strongips)|180|180|19|10.5%|13.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|15|0.0%|10.4%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|8|0.0%|5.5%|
[et_block](#et_block)|1016|18338655|8|0.0%|5.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|4|0.0%|2.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|2|0.0%|1.3%|
[blocklist_de_mail](#blocklist_de_mail)|16032|16032|2|0.0%|1.3%|
[blocklist_de_imap](#blocklist_de_imap)|2050|2050|2|0.0%|1.3%|
[nixspam](#nixspam)|20080|20080|1|0.0%|0.6%|

## openbl_30d

[OpenBL.org](http://www.openbl.org/) last 30 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.

Source is downloaded from [this link](http://www.openbl.org/lists/base_30days.txt).

The last time downloaded was found to be dated: Fri Jun  5 19:42:00 UTC 2015.

The ipset `openbl_30d` has **3254** entries, **3254** unique IPs.

The following table shows the overlaps of `openbl_30d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl_30d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl_30d`.
- ` this % ` is the percentage **of this ipset (`openbl_30d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[openbl_60d](#openbl_60d)|7667|7667|3254|42.4%|100.0%|
[alienvault_reputation](#alienvault_reputation)|176034|176034|3239|1.8%|99.5%|
[et_compromised](#et_compromised)|2086|2086|1189|56.9%|36.5%|
[bruteforceblocker](#bruteforceblocker)|1977|1977|1128|57.0%|34.6%|
[openbl_7d](#openbl_7d)|893|893|893|100.0%|27.4%|
[blocklist_de](#blocklist_de)|28768|28768|776|2.6%|23.8%|
[blocklist_de_ssh](#blocklist_de_ssh)|4496|4496|728|16.1%|22.3%|
[shunlist](#shunlist)|1229|1229|542|44.1%|16.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|311|0.0%|9.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|168|0.0%|5.1%|
[et_block](#et_block)|1016|18338655|166|0.0%|5.1%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|160|0.0%|4.9%|
[openbl_1d](#openbl_1d)|143|143|140|97.9%|4.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|72|0.0%|2.2%|
[blocklist_de_mail](#blocklist_de_mail)|16032|16032|39|0.2%|1.1%|
[blocklist_de_imap](#blocklist_de_imap)|2050|2050|35|1.7%|1.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|180|180|25|13.8%|0.7%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|13|0.0%|0.3%|
[dshield](#dshield)|20|5120|8|0.1%|0.2%|
[blocklist_de_apache](#blocklist_de_apache)|15058|15058|5|0.0%|0.1%|
[stopforumspam_30d](#stopforumspam_30d)|93498|93498|4|0.0%|0.1%|
[snort_ipfilter](#snort_ipfilter)|9994|9994|4|0.0%|0.1%|
[nixspam](#nixspam)|20080|20080|4|0.0%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|4|0.0%|0.1%|
[voipbl](#voipbl)|10452|10864|3|0.0%|0.0%|
[sorbs_spam](#sorbs_spam)|27772|28726|3|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|27772|28726|3|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|27772|28726|3|0.0%|0.0%|
[zeus](#zeus)|230|230|2|0.8%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7232|7232|2|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3330|3330|2|0.0%|0.0%|
[zeus_badips](#zeus_badips)|202|202|1|0.4%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29882|29882|1|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|486400|1|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|868|868|1|0.1%|0.0%|

## openbl_60d

[OpenBL.org](http://www.openbl.org/) last 60 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.

Source is downloaded from [this link](http://www.openbl.org/lists/base_60days.txt).

The last time downloaded was found to be dated: Fri Jun  5 19:42:00 UTC 2015.

The ipset `openbl_60d` has **7667** entries, **7667** unique IPs.

The following table shows the overlaps of `openbl_60d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl_60d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl_60d`.
- ` this % ` is the percentage **of this ipset (`openbl_60d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[alienvault_reputation](#alienvault_reputation)|176034|176034|7647|4.3%|99.7%|
[openbl_30d](#openbl_30d)|3254|3254|3254|100.0%|42.4%|
[et_compromised](#et_compromised)|2086|2086|1267|60.7%|16.5%|
[blocklist_de](#blocklist_de)|28768|28768|1208|4.1%|15.7%|
[bruteforceblocker](#bruteforceblocker)|1977|1977|1182|59.7%|15.4%|
[blocklist_de_ssh](#blocklist_de_ssh)|4496|4496|1140|25.3%|14.8%|
[openbl_7d](#openbl_7d)|893|893|893|100.0%|11.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|745|0.0%|9.7%|
[shunlist](#shunlist)|1229|1229|556|45.2%|7.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|335|0.0%|4.3%|
[et_block](#et_block)|1016|18338655|246|0.0%|3.2%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|240|0.0%|3.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|172|0.0%|2.2%|
[openbl_1d](#openbl_1d)|143|143|140|97.9%|1.8%|
[stopforumspam_30d](#stopforumspam_30d)|93498|93498|57|0.0%|0.7%|
[blocklist_de_mail](#blocklist_de_mail)|16032|16032|46|0.2%|0.5%|
[blocklist_de_imap](#blocklist_de_imap)|2050|2050|42|2.0%|0.5%|
[snort_ipfilter](#snort_ipfilter)|9994|9994|27|0.2%|0.3%|
[blocklist_de_strongips](#blocklist_de_strongips)|180|180|27|15.0%|0.3%|
[stopforumspam_7d](#stopforumspam_7d)|29882|29882|25|0.0%|0.3%|
[stopforumspam_1d](#stopforumspam_1d)|7232|7232|21|0.2%|0.2%|
[et_tor](#et_tor)|6610|6610|21|0.3%|0.2%|
[dshield](#dshield)|20|5120|20|0.3%|0.2%|
[dm_tor](#dm_tor)|6483|6483|19|0.2%|0.2%|
[bm_tor](#bm_tor)|6533|6533|19|0.2%|0.2%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|18|4.8%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|18|0.0%|0.2%|
[sorbs_spam](#sorbs_spam)|27772|28726|15|0.0%|0.1%|
[sorbs_recent_spam](#sorbs_recent_spam)|27772|28726|15|0.0%|0.1%|
[sorbs_new_spam](#sorbs_new_spam)|27772|28726|15|0.0%|0.1%|
[blocklist_de_bots](#blocklist_de_bots)|3330|3330|10|0.3%|0.1%|
[php_commenters](#php_commenters)|326|326|9|2.7%|0.1%|
[voipbl](#voipbl)|10452|10864|8|0.0%|0.1%|
[blocklist_de_apache](#blocklist_de_apache)|15058|15058|8|0.0%|0.1%|
[nixspam](#nixspam)|20080|20080|5|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|5|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|868|868|3|0.3%|0.0%|
[zeus](#zeus)|230|230|2|0.8%|0.0%|
[php_harvesters](#php_harvesters)|311|311|2|0.6%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.0%|
[zeus_badips](#zeus_badips)|202|202|1|0.4%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|486400|1|0.0%|0.0%|

## openbl_7d

[OpenBL.org](http://www.openbl.org/) last 7 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.

Source is downloaded from [this link](http://www.openbl.org/lists/base_7days.txt).

The last time downloaded was found to be dated: Fri Jun  5 19:42:00 UTC 2015.

The ipset `openbl_7d` has **893** entries, **893** unique IPs.

The following table shows the overlaps of `openbl_7d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl_7d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl_7d`.
- ` this % ` is the percentage **of this ipset (`openbl_7d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[openbl_60d](#openbl_60d)|7667|7667|893|11.6%|100.0%|
[openbl_30d](#openbl_30d)|3254|3254|893|27.4%|100.0%|
[alienvault_reputation](#alienvault_reputation)|176034|176034|888|0.5%|99.4%|
[blocklist_de](#blocklist_de)|28768|28768|500|1.7%|55.9%|
[blocklist_de_ssh](#blocklist_de_ssh)|4496|4496|480|10.6%|53.7%|
[bruteforceblocker](#bruteforceblocker)|1977|1977|394|19.9%|44.1%|
[et_compromised](#et_compromised)|2086|2086|387|18.5%|43.3%|
[shunlist](#shunlist)|1229|1229|273|22.2%|30.5%|
[openbl_1d](#openbl_1d)|143|143|137|95.8%|15.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|116|0.0%|12.9%|
[et_block](#et_block)|1016|18338655|49|0.0%|5.4%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|47|0.0%|5.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|46|0.0%|5.1%|
[blocklist_de_strongips](#blocklist_de_strongips)|180|180|24|13.3%|2.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|19|0.0%|2.1%|
[blocklist_de_mail](#blocklist_de_mail)|16032|16032|16|0.0%|1.7%|
[blocklist_de_imap](#blocklist_de_imap)|2050|2050|15|0.7%|1.6%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|5|0.0%|0.5%|
[stopforumspam_30d](#stopforumspam_30d)|93498|93498|3|0.0%|0.3%|
[nixspam](#nixspam)|20080|20080|3|0.0%|0.3%|
[blocklist_de_apache](#blocklist_de_apache)|15058|15058|3|0.0%|0.3%|
[snort_ipfilter](#snort_ipfilter)|9994|9994|2|0.0%|0.2%|
[dshield](#dshield)|20|5120|2|0.0%|0.2%|
[voipbl](#voipbl)|10452|10864|1|0.0%|0.1%|
[sorbs_spam](#sorbs_spam)|27772|28726|1|0.0%|0.1%|
[sorbs_recent_spam](#sorbs_recent_spam)|27772|28726|1|0.0%|0.1%|
[sorbs_new_spam](#sorbs_new_spam)|27772|28726|1|0.0%|0.1%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.1%|

## palevo

[Abuse.ch Palevo tracker](https://palevotracker.abuse.ch) worm includes IPs which are being used as botnet C&C for the Palevo crimeware - **excellent list**

Source is downloaded from [this link](https://palevotracker.abuse.ch/blocklists.php?download=ipblocklist).

The last time downloaded was found to be dated: Fri Jun  5 22:54:14 UTC 2015.

The ipset `palevo` has **13** entries, **13** unique IPs.

The following table shows the overlaps of `palevo` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `palevo`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `palevo`.
- ` this % ` is the percentage **of this ipset (`palevo`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[et_block](#et_block)|1016|18338655|13|0.0%|100.0%|
[snort_ipfilter](#snort_ipfilter)|9994|9994|11|0.1%|84.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|2|0.0%|15.3%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|7.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|1|0.0%|7.6%|

## php_commenters

[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) comment spammers (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=c&rss=1).

The last time downloaded was found to be dated: Fri Jun  5 22:45:11 UTC 2015.

The ipset `php_commenters` has **326** entries, **326** unique IPs.

The following table shows the overlaps of `php_commenters` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `php_commenters`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `php_commenters`.
- ` this % ` is the percentage **of this ipset (`php_commenters`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_30d](#stopforumspam_30d)|93498|93498|235|0.2%|72.0%|
[stopforumspam_7d](#stopforumspam_7d)|29882|29882|172|0.5%|52.7%|
[stopforumspam_1d](#stopforumspam_1d)|7232|7232|133|1.8%|40.7%|
[blocklist_de](#blocklist_de)|28768|28768|80|0.2%|24.5%|
[blocklist_de_bots](#blocklist_de_bots)|3330|3330|64|1.9%|19.6%|
[snort_ipfilter](#snort_ipfilter)|9994|9994|44|0.4%|13.4%|
[php_spammers](#php_spammers)|495|495|36|7.2%|11.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|180|180|36|20.0%|11.0%|
[et_tor](#et_tor)|6610|6610|35|0.5%|10.7%|
[bm_tor](#bm_tor)|6533|6533|34|0.5%|10.4%|
[dm_tor](#dm_tor)|6483|6483|33|0.5%|10.1%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|32|8.6%|9.8%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|28|0.0%|8.5%|
[et_block](#et_block)|1016|18338655|28|0.0%|8.5%|
[blocklist_de_apache](#blocklist_de_apache)|15058|15058|26|0.1%|7.9%|
[php_dictionary](#php_dictionary)|508|508|24|4.7%|7.3%|
[blocklist_de_mail](#blocklist_de_mail)|16032|16032|22|0.1%|6.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|18|0.0%|5.5%|
[ri_web_proxies](#ri_web_proxies)|6466|6466|17|0.2%|5.2%|
[sorbs_spam](#sorbs_spam)|27772|28726|15|0.0%|4.6%|
[sorbs_recent_spam](#sorbs_recent_spam)|27772|28726|15|0.0%|4.6%|
[sorbs_new_spam](#sorbs_new_spam)|27772|28726|15|0.0%|4.6%|
[alienvault_reputation](#alienvault_reputation)|176034|176034|15|0.0%|4.6%|
[nixspam](#nixspam)|20080|20080|13|0.0%|3.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|13|0.0%|3.9%|
[php_harvesters](#php_harvesters)|311|311|11|3.5%|3.3%|
[openbl_60d](#openbl_60d)|7667|7667|9|0.1%|2.7%|
[xroxy](#xroxy)|2087|2087|7|0.3%|2.1%|
[spamhaus_edrop](#spamhaus_edrop)|55|486400|7|0.0%|2.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|7|0.0%|2.1%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|3708|3708|7|0.1%|2.1%|
[ri_connect_proxies](#ri_connect_proxies)|2421|2421|4|0.1%|1.2%|
[proxz](#proxz)|824|824|4|0.4%|1.2%|
[sorbs_web](#sorbs_web)|588|589|2|0.3%|0.6%|
[proxyrss](#proxyrss)|1768|1768|2|0.1%|0.6%|
[zeus_badips](#zeus_badips)|202|202|1|0.4%|0.3%|
[zeus](#zeus)|230|230|1|0.4%|0.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.3%|

## php_dictionary

[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) directory attackers (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=d&rss=1).

The last time downloaded was found to be dated: Fri Jun  5 23:00:24 UTC 2015.

The ipset `php_dictionary` has **508** entries, **508** unique IPs.

The following table shows the overlaps of `php_dictionary` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `php_dictionary`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `php_dictionary`.
- ` this % ` is the percentage **of this ipset (`php_dictionary`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[php_spammers](#php_spammers)|495|495|150|30.3%|29.5%|
[sorbs_spam](#sorbs_spam)|27772|28726|134|0.4%|26.3%|
[sorbs_recent_spam](#sorbs_recent_spam)|27772|28726|134|0.4%|26.3%|
[sorbs_new_spam](#sorbs_new_spam)|27772|28726|134|0.4%|26.3%|
[stopforumspam_30d](#stopforumspam_30d)|93498|93498|98|0.1%|19.2%|
[blocklist_de](#blocklist_de)|28768|28768|85|0.2%|16.7%|
[snort_ipfilter](#snort_ipfilter)|9994|9994|78|0.7%|15.3%|
[blocklist_de_mail](#blocklist_de_mail)|16032|16032|70|0.4%|13.7%|
[stopforumspam_7d](#stopforumspam_7d)|29882|29882|66|0.2%|12.9%|
[nixspam](#nixspam)|20080|20080|66|0.3%|12.9%|
[ri_web_proxies](#ri_web_proxies)|6466|6466|40|0.6%|7.8%|
[xroxy](#xroxy)|2087|2087|31|1.4%|6.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|29|0.0%|5.7%|
[stopforumspam_1d](#stopforumspam_1d)|7232|7232|27|0.3%|5.3%|
[sorbs_web](#sorbs_web)|588|589|26|4.4%|5.1%|
[php_commenters](#php_commenters)|326|326|24|7.3%|4.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|13|0.0%|2.5%|
[proxz](#proxz)|824|824|12|1.4%|2.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|11|0.0%|2.1%|
[blocklist_de_bots](#blocklist_de_bots)|3330|3330|11|0.3%|2.1%|
[alienvault_reputation](#alienvault_reputation)|176034|176034|8|0.0%|1.5%|
[et_tor](#et_tor)|6610|6610|5|0.0%|0.9%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|4|0.0%|0.7%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|4|1.0%|0.7%|
[et_block](#et_block)|1016|18338655|4|0.0%|0.7%|
[dm_tor](#dm_tor)|6483|6483|4|0.0%|0.7%|
[bm_tor](#bm_tor)|6533|6533|4|0.0%|0.7%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|3708|3708|4|0.1%|0.7%|
[blocklist_de_apache](#blocklist_de_apache)|15058|15058|4|0.0%|0.7%|
[ri_connect_proxies](#ri_connect_proxies)|2421|2421|3|0.1%|0.5%|
[blocklist_de_strongips](#blocklist_de_strongips)|180|180|3|1.6%|0.5%|
[proxyrss](#proxyrss)|1768|1768|2|0.1%|0.3%|
[php_harvesters](#php_harvesters)|311|311|2|0.6%|0.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2|0.0%|0.3%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|2|0.0%|0.3%|
[sorbs_socks](#sorbs_socks)|19|19|1|5.2%|0.1%|
[sorbs_misc](#sorbs_misc)|19|19|1|5.2%|0.1%|
[sorbs_http](#sorbs_http)|19|19|1|5.2%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.1%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|1|0.1%|0.1%|
[blocklist_de_imap](#blocklist_de_imap)|2050|2050|1|0.0%|0.1%|

## php_harvesters

[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) harvesters (IPs that surf the internet looking for email addresses) (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=h&rss=1).

The last time downloaded was found to be dated: Fri Jun  5 22:45:10 UTC 2015.

The ipset `php_harvesters` has **311** entries, **311** unique IPs.

The following table shows the overlaps of `php_harvesters` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `php_harvesters`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `php_harvesters`.
- ` this % ` is the percentage **of this ipset (`php_harvesters`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_30d](#stopforumspam_30d)|93498|93498|68|0.0%|21.8%|
[stopforumspam_7d](#stopforumspam_7d)|29882|29882|52|0.1%|16.7%|
[stopforumspam_1d](#stopforumspam_1d)|7232|7232|40|0.5%|12.8%|
[blocklist_de](#blocklist_de)|28768|28768|30|0.1%|9.6%|
[blocklist_de_bots](#blocklist_de_bots)|3330|3330|22|0.6%|7.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|17|0.0%|5.4%|
[snort_ipfilter](#snort_ipfilter)|9994|9994|11|0.1%|3.5%|
[php_commenters](#php_commenters)|326|326|11|3.3%|3.5%|
[alienvault_reputation](#alienvault_reputation)|176034|176034|10|0.0%|3.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|9|0.0%|2.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|9|0.0%|2.8%|
[sorbs_spam](#sorbs_spam)|27772|28726|7|0.0%|2.2%|
[sorbs_recent_spam](#sorbs_recent_spam)|27772|28726|7|0.0%|2.2%|
[sorbs_new_spam](#sorbs_new_spam)|27772|28726|7|0.0%|2.2%|
[et_tor](#et_tor)|6610|6610|7|0.1%|2.2%|
[dm_tor](#dm_tor)|6483|6483|7|0.1%|2.2%|
[bm_tor](#bm_tor)|6533|6533|7|0.1%|2.2%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|6|1.6%|1.9%|
[blocklist_de_apache](#blocklist_de_apache)|15058|15058|5|0.0%|1.6%|
[nixspam](#nixspam)|20080|20080|4|0.0%|1.2%|
[proxyrss](#proxyrss)|1768|1768|3|0.1%|0.9%|
[blocklist_de_ftp](#blocklist_de_ftp)|868|868|3|0.3%|0.9%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|3708|3708|3|0.0%|0.9%|
[xroxy](#xroxy)|2087|2087|2|0.0%|0.6%|
[php_spammers](#php_spammers)|495|495|2|0.4%|0.6%|
[php_dictionary](#php_dictionary)|508|508|2|0.3%|0.6%|
[openbl_60d](#openbl_60d)|7667|7667|2|0.0%|0.6%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|2|0.0%|0.6%|
[blocklist_de_mail](#blocklist_de_mail)|16032|16032|2|0.0%|0.6%|
[spamhaus_edrop](#spamhaus_edrop)|55|486400|1|0.0%|0.3%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|1|0.0%|0.3%|
[ri_web_proxies](#ri_web_proxies)|6466|6466|1|0.0%|0.3%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.3%|
[fullbogons](#fullbogons)|3715|670310296|1|0.0%|0.3%|
[et_block](#et_block)|1016|18338655|1|0.0%|0.3%|
[dshield](#dshield)|20|5120|1|0.0%|0.3%|
[bogons](#bogons)|13|592708608|1|0.0%|0.3%|
[blocklist_de_strongips](#blocklist_de_strongips)|180|180|1|0.5%|0.3%|

## php_spammers

[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) spam servers (IPs used by spammers to send messages) (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=s&rss=1).

The last time downloaded was found to be dated: Fri Jun  5 22:45:11 UTC 2015.

The ipset `php_spammers` has **495** entries, **495** unique IPs.

The following table shows the overlaps of `php_spammers` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `php_spammers`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `php_spammers`.
- ` this % ` is the percentage **of this ipset (`php_spammers`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[php_dictionary](#php_dictionary)|508|508|150|29.5%|30.3%|
[sorbs_spam](#sorbs_spam)|27772|28726|116|0.4%|23.4%|
[sorbs_recent_spam](#sorbs_recent_spam)|27772|28726|116|0.4%|23.4%|
[sorbs_new_spam](#sorbs_new_spam)|27772|28726|116|0.4%|23.4%|
[stopforumspam_30d](#stopforumspam_30d)|93498|93498|112|0.1%|22.6%|
[blocklist_de](#blocklist_de)|28768|28768|84|0.2%|16.9%|
[snort_ipfilter](#snort_ipfilter)|9994|9994|73|0.7%|14.7%|
[stopforumspam_7d](#stopforumspam_7d)|29882|29882|66|0.2%|13.3%|
[blocklist_de_mail](#blocklist_de_mail)|16032|16032|65|0.4%|13.1%|
[nixspam](#nixspam)|20080|20080|51|0.2%|10.3%|
[php_commenters](#php_commenters)|326|326|36|11.0%|7.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|36|0.0%|7.2%|
[ri_web_proxies](#ri_web_proxies)|6466|6466|35|0.5%|7.0%|
[stopforumspam_1d](#stopforumspam_1d)|7232|7232|28|0.3%|5.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|28|0.0%|5.6%|
[xroxy](#xroxy)|2087|2087|25|1.1%|5.0%|
[sorbs_web](#sorbs_web)|588|589|25|4.2%|5.0%|
[proxz](#proxz)|824|824|14|1.6%|2.8%|
[blocklist_de_bots](#blocklist_de_bots)|3330|3330|13|0.3%|2.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|7|0.0%|1.4%|
[et_tor](#et_tor)|6610|6610|6|0.0%|1.2%|
[dm_tor](#dm_tor)|6483|6483|5|0.0%|1.0%|
[bm_tor](#bm_tor)|6533|6533|5|0.0%|1.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|180|180|5|2.7%|1.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|3708|3708|5|0.1%|1.0%|
[blocklist_de_apache](#blocklist_de_apache)|15058|15058|5|0.0%|1.0%|
[alienvault_reputation](#alienvault_reputation)|176034|176034|5|0.0%|1.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|4|1.0%|0.8%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|3|0.0%|0.6%|
[ri_connect_proxies](#ri_connect_proxies)|2421|2421|3|0.1%|0.6%|
[proxyrss](#proxyrss)|1768|1768|2|0.1%|0.4%|
[php_harvesters](#php_harvesters)|311|311|2|0.6%|0.4%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2|0.0%|0.4%|
[et_block](#et_block)|1016|18338655|2|0.0%|0.4%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1|0.0%|0.2%|
[blocklist_de_imap](#blocklist_de_imap)|2050|2050|1|0.0%|0.2%|
[blocklist_de_ftp](#blocklist_de_ftp)|868|868|1|0.1%|0.2%|

## proxyrss

[proxyrss.com](http://www.proxyrss.com) open proxies syndicated from multiple sources.

Source is downloaded from [this link](http://www.proxyrss.com/proxylists/all.gz).

The last time downloaded was found to be dated: Fri Jun  5 21:11:29 UTC 2015.

The ipset `proxyrss` has **1768** entries, **1768** unique IPs.

The following table shows the overlaps of `proxyrss` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `proxyrss`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `proxyrss`.
- ` this % ` is the percentage **of this ipset (`proxyrss`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_30d](#stopforumspam_30d)|93498|93498|778|0.8%|44.0%|
[ri_web_proxies](#ri_web_proxies)|6466|6466|666|10.3%|37.6%|
[stopforumspam_7d](#stopforumspam_7d)|29882|29882|610|2.0%|34.5%|
[xroxy](#xroxy)|2087|2087|424|20.3%|23.9%|
[stopforumspam_1d](#stopforumspam_1d)|7232|7232|380|5.2%|21.4%|
[ri_connect_proxies](#ri_connect_proxies)|2421|2421|266|10.9%|15.0%|
[blocklist_de_bots](#blocklist_de_bots)|3330|3330|243|7.2%|13.7%|
[blocklist_de](#blocklist_de)|28768|28768|242|0.8%|13.6%|
[proxz](#proxz)|824|824|220|26.6%|12.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|66|0.0%|3.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|57|0.0%|3.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|34|0.0%|1.9%|
[nixspam](#nixspam)|20080|20080|13|0.0%|0.7%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|8|1.1%|0.4%|
[sorbs_spam](#sorbs_spam)|27772|28726|6|0.0%|0.3%|
[sorbs_recent_spam](#sorbs_recent_spam)|27772|28726|6|0.0%|0.3%|
[sorbs_new_spam](#sorbs_new_spam)|27772|28726|6|0.0%|0.3%|
[blocklist_de_strongips](#blocklist_de_strongips)|180|180|4|2.2%|0.2%|
[snort_ipfilter](#snort_ipfilter)|9994|9994|3|0.0%|0.1%|
[php_harvesters](#php_harvesters)|311|311|3|0.9%|0.1%|
[alienvault_reputation](#alienvault_reputation)|176034|176034|3|0.0%|0.1%|
[sorbs_web](#sorbs_web)|588|589|2|0.3%|0.1%|
[php_spammers](#php_spammers)|495|495|2|0.4%|0.1%|
[php_dictionary](#php_dictionary)|508|508|2|0.3%|0.1%|
[php_commenters](#php_commenters)|326|326|2|0.6%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.0%|
[et_tor](#et_tor)|6610|6610|1|0.0%|0.0%|
[et_compromised](#et_compromised)|2086|2086|1|0.0%|0.0%|
[et_block](#et_block)|1016|18338655|1|0.0%|0.0%|
[dm_tor](#dm_tor)|6483|6483|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1977|1977|1|0.0%|0.0%|
[bm_tor](#bm_tor)|6533|6533|1|0.0%|0.0%|

## proxz

[proxz.com](http://www.proxz.com) open proxies (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.proxz.com/proxylists.xml).

The last time downloaded was found to be dated: Fri Jun  5 21:11:34 UTC 2015.

The ipset `proxz` has **824** entries, **824** unique IPs.

The following table shows the overlaps of `proxz` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `proxz`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `proxz`.
- ` this % ` is the percentage **of this ipset (`proxz`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_30d](#stopforumspam_30d)|93498|93498|493|0.5%|59.8%|
[stopforumspam_7d](#stopforumspam_7d)|29882|29882|400|1.3%|48.5%|
[ri_web_proxies](#ri_web_proxies)|6466|6466|370|5.7%|44.9%|
[xroxy](#xroxy)|2087|2087|328|15.7%|39.8%|
[proxyrss](#proxyrss)|1768|1768|220|12.4%|26.6%|
[stopforumspam_1d](#stopforumspam_1d)|7232|7232|148|2.0%|17.9%|
[blocklist_de](#blocklist_de)|28768|28768|146|0.5%|17.7%|
[ri_connect_proxies](#ri_connect_proxies)|2421|2421|139|5.7%|16.8%|
[blocklist_de_bots](#blocklist_de_bots)|3330|3330|123|3.6%|14.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|69|0.0%|8.3%|
[sorbs_spam](#sorbs_spam)|27772|28726|38|0.1%|4.6%|
[sorbs_recent_spam](#sorbs_recent_spam)|27772|28726|38|0.1%|4.6%|
[sorbs_new_spam](#sorbs_new_spam)|27772|28726|38|0.1%|4.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|33|0.0%|4.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|29|0.0%|3.5%|
[blocklist_de_mail](#blocklist_de_mail)|16032|16032|23|0.1%|2.7%|
[nixspam](#nixspam)|20080|20080|22|0.1%|2.6%|
[snort_ipfilter](#snort_ipfilter)|9994|9994|21|0.2%|2.5%|
[php_spammers](#php_spammers)|495|495|14|2.8%|1.6%|
[php_dictionary](#php_dictionary)|508|508|12|2.3%|1.4%|
[sorbs_web](#sorbs_web)|588|589|10|1.6%|1.2%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|5|0.7%|0.6%|
[php_commenters](#php_commenters)|326|326|4|1.2%|0.4%|
[blocklist_de_strongips](#blocklist_de_strongips)|180|180|3|1.6%|0.3%|
[alienvault_reputation](#alienvault_reputation)|176034|176034|3|0.0%|0.3%|
[et_compromised](#et_compromised)|2086|2086|2|0.0%|0.2%|
[bruteforceblocker](#bruteforceblocker)|1977|1977|2|0.1%|0.2%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1|0.0%|0.1%|
[et_block](#et_block)|1016|18338655|1|0.0%|0.1%|

## ri_connect_proxies

[rosinstrument.com](http://www.rosinstrument.com) open CONNECT proxies (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://tools.rosinstrument.com/proxy/plab100.xml).

The last time downloaded was found to be dated: Fri Jun  5 21:39:46 UTC 2015.

The ipset `ri_connect_proxies` has **2421** entries, **2421** unique IPs.

The following table shows the overlaps of `ri_connect_proxies` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ri_connect_proxies`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ri_connect_proxies`.
- ` this % ` is the percentage **of this ipset (`ri_connect_proxies`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_30d](#stopforumspam_30d)|93498|93498|1397|1.4%|57.7%|
[ri_web_proxies](#ri_web_proxies)|6466|6466|993|15.3%|41.0%|
[stopforumspam_7d](#stopforumspam_7d)|29882|29882|657|2.1%|27.1%|
[xroxy](#xroxy)|2087|2087|362|17.3%|14.9%|
[proxyrss](#proxyrss)|1768|1768|266|15.0%|10.9%|
[stopforumspam_1d](#stopforumspam_1d)|7232|7232|139|1.9%|5.7%|
[proxz](#proxz)|824|824|139|16.8%|5.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|95|0.0%|3.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|75|0.0%|3.0%|
[blocklist_de](#blocklist_de)|28768|28768|75|0.2%|3.0%|
[blocklist_de_bots](#blocklist_de_bots)|3330|3330|73|2.1%|3.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|53|0.0%|2.1%|
[nixspam](#nixspam)|20080|20080|16|0.0%|0.6%|
[sorbs_spam](#sorbs_spam)|27772|28726|10|0.0%|0.4%|
[sorbs_recent_spam](#sorbs_recent_spam)|27772|28726|10|0.0%|0.4%|
[sorbs_new_spam](#sorbs_new_spam)|27772|28726|10|0.0%|0.4%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|6|0.8%|0.2%|
[php_commenters](#php_commenters)|326|326|4|1.2%|0.1%|
[snort_ipfilter](#snort_ipfilter)|9994|9994|3|0.0%|0.1%|
[php_spammers](#php_spammers)|495|495|3|0.6%|0.1%|
[php_dictionary](#php_dictionary)|508|508|3|0.5%|0.1%|
[alienvault_reputation](#alienvault_reputation)|176034|176034|3|0.0%|0.1%|
[blocklist_de_mail](#blocklist_de_mail)|16032|16032|2|0.0%|0.0%|
[sorbs_web](#sorbs_web)|588|589|1|0.1%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.0%|
[et_tor](#et_tor)|6610|6610|1|0.0%|0.0%|
[et_block](#et_block)|1016|18338655|1|0.0%|0.0%|
[dm_tor](#dm_tor)|6483|6483|1|0.0%|0.0%|
[bm_tor](#bm_tor)|6533|6533|1|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2050|2050|1|0.0%|0.0%|

## ri_web_proxies

[rosinstrument.com](http://www.rosinstrument.com) open HTTP proxies (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://tools.rosinstrument.com/proxy/l100.xml).

The last time downloaded was found to be dated: Fri Jun  5 21:38:12 UTC 2015.

The ipset `ri_web_proxies` has **6466** entries, **6466** unique IPs.

The following table shows the overlaps of `ri_web_proxies` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ri_web_proxies`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ri_web_proxies`.
- ` this % ` is the percentage **of this ipset (`ri_web_proxies`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_30d](#stopforumspam_30d)|93498|93498|3117|3.3%|48.2%|
[stopforumspam_7d](#stopforumspam_7d)|29882|29882|1640|5.4%|25.3%|
[ri_connect_proxies](#ri_connect_proxies)|2421|2421|993|41.0%|15.3%|
[xroxy](#xroxy)|2087|2087|889|42.5%|13.7%|
[proxyrss](#proxyrss)|1768|1768|666|37.6%|10.3%|
[stopforumspam_1d](#stopforumspam_1d)|7232|7232|484|6.6%|7.4%|
[blocklist_de](#blocklist_de)|28768|28768|423|1.4%|6.5%|
[proxz](#proxz)|824|824|370|44.9%|5.7%|
[blocklist_de_bots](#blocklist_de_bots)|3330|3330|365|10.9%|5.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|189|0.0%|2.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|187|0.0%|2.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|134|0.0%|2.0%|
[sorbs_spam](#sorbs_spam)|27772|28726|130|0.4%|2.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|27772|28726|130|0.4%|2.0%|
[sorbs_new_spam](#sorbs_new_spam)|27772|28726|130|0.4%|2.0%|
[nixspam](#nixspam)|20080|20080|79|0.3%|1.2%|
[snort_ipfilter](#snort_ipfilter)|9994|9994|59|0.5%|0.9%|
[blocklist_de_mail](#blocklist_de_mail)|16032|16032|58|0.3%|0.8%|
[php_dictionary](#php_dictionary)|508|508|40|7.8%|0.6%|
[php_spammers](#php_spammers)|495|495|35|7.0%|0.5%|
[sorbs_web](#sorbs_web)|588|589|21|3.5%|0.3%|
[php_commenters](#php_commenters)|326|326|17|5.2%|0.2%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|12|1.7%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|5|0.0%|0.0%|
[et_tor](#et_tor)|6610|6610|5|0.0%|0.0%|
[dm_tor](#dm_tor)|6483|6483|5|0.0%|0.0%|
[bm_tor](#bm_tor)|6533|6533|5|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|180|180|5|2.7%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|4|1.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|2|0.0%|0.0%|
[alienvault_reputation](#alienvault_reputation)|176034|176034|2|0.0%|0.0%|
[php_harvesters](#php_harvesters)|311|311|1|0.3%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|
[et_compromised](#et_compromised)|2086|2086|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1977|1977|1|0.0%|0.0%|

## shunlist

[AutoShun.org](http://autoshun.org/) IPs identified as hostile by correlating logs from distributed snort installations running the autoshun plugin

Source is downloaded from [this link](http://www.autoshun.org/files/shunlist.csv).

The last time downloaded was found to be dated: Fri Jun  5 22:30:05 UTC 2015.

The ipset `shunlist` has **1229** entries, **1229** unique IPs.

The following table shows the overlaps of `shunlist` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `shunlist`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `shunlist`.
- ` this % ` is the percentage **of this ipset (`shunlist`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[alienvault_reputation](#alienvault_reputation)|176034|176034|1216|0.6%|98.9%|
[openbl_60d](#openbl_60d)|7667|7667|556|7.2%|45.2%|
[openbl_30d](#openbl_30d)|3254|3254|542|16.6%|44.1%|
[et_compromised](#et_compromised)|2086|2086|462|22.1%|37.5%|
[bruteforceblocker](#bruteforceblocker)|1977|1977|450|22.7%|36.6%|
[blocklist_de](#blocklist_de)|28768|28768|362|1.2%|29.4%|
[blocklist_de_ssh](#blocklist_de_ssh)|4496|4496|332|7.3%|27.0%|
[openbl_7d](#openbl_7d)|893|893|273|30.5%|22.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|107|0.0%|8.7%|
[et_block](#et_block)|1016|18338655|107|0.0%|8.7%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|97|0.0%|7.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|72|0.0%|5.8%|
[openbl_1d](#openbl_1d)|143|143|62|43.3%|5.0%|
[sslbl](#sslbl)|369|369|56|15.1%|4.5%|
[ciarmy](#ciarmy)|421|421|30|7.1%|2.4%|
[blocklist_de_apache](#blocklist_de_apache)|15058|15058|28|0.1%|2.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|27|0.0%|2.1%|
[blocklist_de_strongips](#blocklist_de_strongips)|180|180|20|11.1%|1.6%|
[voipbl](#voipbl)|10452|10864|12|0.1%|0.9%|
[stopforumspam_30d](#stopforumspam_30d)|93498|93498|4|0.0%|0.3%|
[dshield](#dshield)|20|5120|4|0.0%|0.3%|
[stopforumspam_7d](#stopforumspam_7d)|29882|29882|3|0.0%|0.2%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|3708|3708|3|0.0%|0.2%|
[snort_ipfilter](#snort_ipfilter)|9994|9994|2|0.0%|0.1%|
[nixspam](#nixspam)|20080|20080|2|0.0%|0.1%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|2|0.5%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2|0.0%|0.1%|
[stopforumspam_1d](#stopforumspam_1d)|7232|7232|1|0.0%|0.0%|
[sorbs_spam](#sorbs_spam)|27772|28726|1|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|27772|28726|1|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|27772|28726|1|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.0%|
[et_tor](#et_tor)|6610|6610|1|0.0%|0.0%|
[dm_tor](#dm_tor)|6483|6483|1|0.0%|0.0%|
[bm_tor](#bm_tor)|6533|6533|1|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|16032|16032|1|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2050|2050|1|0.0%|0.0%|

## snort_ipfilter

[labs.snort.org](https://labs.snort.org/) supplied IP blacklist (this list seems to be updated frequently, but we found no information about it)

Source is downloaded from [this link](http://labs.snort.org/feeds/ip-filter.blf).

The last time downloaded was found to be dated: Fri Jun  5 13:30:00 UTC 2015.

The ipset `snort_ipfilter` has **9994** entries, **9994** unique IPs.

The following table shows the overlaps of `snort_ipfilter` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `snort_ipfilter`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `snort_ipfilter`.
- ` this % ` is the percentage **of this ipset (`snort_ipfilter`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[et_tor](#et_tor)|6610|6610|1111|16.8%|11.1%|
[bm_tor](#bm_tor)|6533|6533|1071|16.3%|10.7%|
[dm_tor](#dm_tor)|6483|6483|1057|16.3%|10.5%|
[stopforumspam_30d](#stopforumspam_30d)|93498|93498|794|0.8%|7.9%|
[stopforumspam_7d](#stopforumspam_7d)|29882|29882|621|2.0%|6.2%|
[stopforumspam_1d](#stopforumspam_1d)|7232|7232|353|4.8%|3.5%|
[sorbs_spam](#sorbs_spam)|27772|28726|336|1.1%|3.3%|
[sorbs_recent_spam](#sorbs_recent_spam)|27772|28726|336|1.1%|3.3%|
[sorbs_new_spam](#sorbs_new_spam)|27772|28726|336|1.1%|3.3%|
[et_block](#et_block)|1016|18338655|313|0.0%|3.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|231|0.0%|2.3%|
[zeus](#zeus)|230|230|201|87.3%|2.0%|
[zeus_badips](#zeus_badips)|202|202|179|88.6%|1.7%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|178|47.8%|1.7%|
[blocklist_de](#blocklist_de)|28768|28768|176|0.6%|1.7%|
[blocklist_de_mail](#blocklist_de_mail)|16032|16032|158|0.9%|1.5%|
[nixspam](#nixspam)|20080|20080|131|0.6%|1.3%|
[alienvault_reputation](#alienvault_reputation)|176034|176034|121|0.0%|1.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|103|0.0%|1.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|92|0.0%|0.9%|
[php_dictionary](#php_dictionary)|508|508|78|15.3%|0.7%|
[feodo](#feodo)|96|96|74|77.0%|0.7%|
[php_spammers](#php_spammers)|495|495|73|14.7%|0.7%|
[ri_web_proxies](#ri_web_proxies)|6466|6466|59|0.9%|0.5%|
[sorbs_web](#sorbs_web)|588|589|53|8.9%|0.5%|
[xroxy](#xroxy)|2087|2087|48|2.2%|0.4%|
[php_commenters](#php_commenters)|326|326|44|13.4%|0.4%|
[sslbl](#sslbl)|369|369|29|7.8%|0.2%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|28|2.1%|0.2%|
[openbl_60d](#openbl_60d)|7667|7667|27|0.3%|0.2%|
[proxz](#proxz)|824|824|21|2.5%|0.2%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|20|0.0%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|13|0.0%|0.1%|
[blocklist_de_bots](#blocklist_de_bots)|3330|3330|13|0.3%|0.1%|
[php_harvesters](#php_harvesters)|311|311|11|3.5%|0.1%|
[palevo](#palevo)|13|13|11|84.6%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|11|0.0%|0.1%|
[blocklist_de_apache](#blocklist_de_apache)|15058|15058|9|0.0%|0.0%|
[sorbs_socks](#sorbs_socks)|19|19|7|36.8%|0.0%|
[sorbs_misc](#sorbs_misc)|19|19|7|36.8%|0.0%|
[sorbs_http](#sorbs_http)|19|19|7|36.8%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|486400|6|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|3708|3708|5|0.1%|0.0%|
[openbl_30d](#openbl_30d)|3254|3254|4|0.1%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2421|2421|3|0.1%|0.0%|
[proxyrss](#proxyrss)|1768|1768|3|0.1%|0.0%|
[dshield](#dshield)|20|5120|3|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2050|2050|3|0.1%|0.0%|
[shunlist](#shunlist)|1229|1229|2|0.1%|0.0%|
[openbl_7d](#openbl_7d)|893|893|2|0.2%|0.0%|
[voipbl](#voipbl)|10452|10864|1|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|1|0.1%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1|0.0%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|359|359|1|0.2%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|180|180|1|0.5%|0.0%|

## sorbs_dul

[Sorbs.net](https://www.sorbs.net/) DUL, Dynamic User IPs extracted from deltas.

Source is downloaded from [this link]().

The last time downloaded was found to be dated: Thu Jun  4 14:48:14 UTC 2015.

The ipset `sorbs_dul` has **8** entries, **3584** unique IPs.

The following table shows the overlaps of `sorbs_dul` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `sorbs_dul`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `sorbs_dul`.
- ` this % ` is the percentage **of this ipset (`sorbs_dul`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|

## sorbs_http

[Sorbs.net](https://www.sorbs.net/) HTTP proxies, extracted from deltas.

Source is downloaded from [this link]().

The last time downloaded was found to be dated: Fri Jun  5 17:04:14 UTC 2015.

The ipset `sorbs_http` has **19** entries, **19** unique IPs.

The following table shows the overlaps of `sorbs_http` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `sorbs_http`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `sorbs_http`.
- ` this % ` is the percentage **of this ipset (`sorbs_http`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[sorbs_spam](#sorbs_spam)|27772|28726|19|0.0%|100.0%|
[sorbs_socks](#sorbs_socks)|19|19|19|100.0%|100.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|27772|28726|19|0.0%|100.0%|
[sorbs_new_spam](#sorbs_new_spam)|27772|28726|19|0.0%|100.0%|
[sorbs_misc](#sorbs_misc)|19|19|19|100.0%|100.0%|
[snort_ipfilter](#snort_ipfilter)|9994|9994|7|0.0%|36.8%|
[blocklist_de](#blocklist_de)|28768|28768|7|0.0%|36.8%|
[blocklist_de_mail](#blocklist_de_mail)|16032|16032|6|0.0%|31.5%|
[sorbs_web](#sorbs_web)|588|589|3|0.5%|15.7%|
[nixspam](#nixspam)|20080|20080|3|0.0%|15.7%|
[stopforumspam_7d](#stopforumspam_7d)|29882|29882|2|0.0%|10.5%|
[stopforumspam_30d](#stopforumspam_30d)|93498|93498|2|0.0%|10.5%|
[xroxy](#xroxy)|2087|2087|1|0.0%|5.2%|
[stopforumspam_1d](#stopforumspam_1d)|7232|7232|1|0.0%|5.2%|
[php_dictionary](#php_dictionary)|508|508|1|0.1%|5.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|1|0.0%|5.2%|
[blocklist_de_bots](#blocklist_de_bots)|3330|3330|1|0.0%|5.2%|

## sorbs_misc

[Sorbs.net](https://www.sorbs.net/) MISC proxies, extracted from deltas.

Source is downloaded from [this link]().

The last time downloaded was found to be dated: Fri Jun  5 17:04:14 UTC 2015.

The ipset `sorbs_misc` has **19** entries, **19** unique IPs.

The following table shows the overlaps of `sorbs_misc` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `sorbs_misc`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `sorbs_misc`.
- ` this % ` is the percentage **of this ipset (`sorbs_misc`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[sorbs_spam](#sorbs_spam)|27772|28726|19|0.0%|100.0%|
[sorbs_socks](#sorbs_socks)|19|19|19|100.0%|100.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|27772|28726|19|0.0%|100.0%|
[sorbs_new_spam](#sorbs_new_spam)|27772|28726|19|0.0%|100.0%|
[sorbs_http](#sorbs_http)|19|19|19|100.0%|100.0%|
[snort_ipfilter](#snort_ipfilter)|9994|9994|7|0.0%|36.8%|
[blocklist_de](#blocklist_de)|28768|28768|7|0.0%|36.8%|
[blocklist_de_mail](#blocklist_de_mail)|16032|16032|6|0.0%|31.5%|
[sorbs_web](#sorbs_web)|588|589|3|0.5%|15.7%|
[nixspam](#nixspam)|20080|20080|3|0.0%|15.7%|
[stopforumspam_7d](#stopforumspam_7d)|29882|29882|2|0.0%|10.5%|
[stopforumspam_30d](#stopforumspam_30d)|93498|93498|2|0.0%|10.5%|
[xroxy](#xroxy)|2087|2087|1|0.0%|5.2%|
[stopforumspam_1d](#stopforumspam_1d)|7232|7232|1|0.0%|5.2%|
[php_dictionary](#php_dictionary)|508|508|1|0.1%|5.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|1|0.0%|5.2%|
[blocklist_de_bots](#blocklist_de_bots)|3330|3330|1|0.0%|5.2%|

## sorbs_new_spam

[Sorbs.net](https://www.sorbs.net/) NEW Spam senders, extracted from deltas.

Source is downloaded from [this link]().

The last time downloaded was found to be dated: Fri Jun  5 23:04:16 UTC 2015.

The ipset `sorbs_new_spam` has **27772** entries, **28726** unique IPs.

The following table shows the overlaps of `sorbs_new_spam` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `sorbs_new_spam`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `sorbs_new_spam`.
- ` this % ` is the percentage **of this ipset (`sorbs_new_spam`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[sorbs_spam](#sorbs_spam)|27772|28726|28726|100.0%|100.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|27772|28726|28726|100.0%|100.0%|
[nixspam](#nixspam)|20080|20080|4216|20.9%|14.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|2047|0.0%|7.1%|
[blocklist_de](#blocklist_de)|28768|28768|1115|3.8%|3.8%|
[blocklist_de_mail](#blocklist_de_mail)|16032|16032|951|5.9%|3.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|735|0.0%|2.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|450|0.0%|1.5%|
[snort_ipfilter](#snort_ipfilter)|9994|9994|336|3.3%|1.1%|
[stopforumspam_30d](#stopforumspam_30d)|93498|93498|322|0.3%|1.1%|
[sorbs_web](#sorbs_web)|588|589|284|48.2%|0.9%|
[stopforumspam_7d](#stopforumspam_7d)|29882|29882|178|0.5%|0.6%|
[php_dictionary](#php_dictionary)|508|508|134|26.3%|0.4%|
[ri_web_proxies](#ri_web_proxies)|6466|6466|130|2.0%|0.4%|
[php_spammers](#php_spammers)|495|495|116|23.4%|0.4%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|3708|3708|104|2.8%|0.3%|
[blocklist_de_apache](#blocklist_de_apache)|15058|15058|104|0.6%|0.3%|
[alienvault_reputation](#alienvault_reputation)|176034|176034|103|0.0%|0.3%|
[xroxy](#xroxy)|2087|2087|84|4.0%|0.2%|
[stopforumspam_1d](#stopforumspam_1d)|7232|7232|50|0.6%|0.1%|
[proxz](#proxz)|824|824|38|4.6%|0.1%|
[blocklist_de_bots](#blocklist_de_bots)|3330|3330|35|1.0%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|31|0.0%|0.1%|
[blocklist_de_ssh](#blocklist_de_ssh)|4496|4496|21|0.4%|0.0%|
[sorbs_socks](#sorbs_socks)|19|19|19|100.0%|0.0%|
[sorbs_misc](#sorbs_misc)|19|19|19|100.0%|0.0%|
[sorbs_http](#sorbs_http)|19|19|19|100.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2050|2050|16|0.7%|0.0%|
[php_commenters](#php_commenters)|326|326|15|4.6%|0.0%|
[openbl_60d](#openbl_60d)|7667|7667|15|0.1%|0.0%|
[sorbs_smtp](#sorbs_smtp)|13|13|13|100.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|13|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2421|2421|10|0.4%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|8|0.0%|0.0%|
[et_block](#et_block)|1016|18338655|8|0.0%|0.0%|
[php_harvesters](#php_harvesters)|311|311|7|2.2%|0.0%|
[proxyrss](#proxyrss)|1768|1768|6|0.3%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|4|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|486400|3|0.0%|0.0%|
[openbl_30d](#openbl_30d)|3254|3254|3|0.0%|0.0%|
[et_tor](#et_tor)|6610|6610|3|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|868|868|3|0.3%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|2|0.2%|0.0%|
[dm_tor](#dm_tor)|6483|6483|2|0.0%|0.0%|
[bm_tor](#bm_tor)|6533|6533|2|0.0%|0.0%|
[shunlist](#shunlist)|1229|1229|1|0.0%|0.0%|
[openbl_7d](#openbl_7d)|893|893|1|0.1%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|1|0.0%|0.0%|
[dshield](#dshield)|20|5120|1|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|180|180|1|0.5%|0.0%|

## sorbs_recent_spam

[Sorbs.net](https://www.sorbs.net/) RECENT Spam senders, extracted from deltas.

Source is downloaded from [this link]().

The last time downloaded was found to be dated: Fri Jun  5 23:04:15 UTC 2015.

The ipset `sorbs_recent_spam` has **27772** entries, **28726** unique IPs.

The following table shows the overlaps of `sorbs_recent_spam` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `sorbs_recent_spam`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `sorbs_recent_spam`.
- ` this % ` is the percentage **of this ipset (`sorbs_recent_spam`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[sorbs_spam](#sorbs_spam)|27772|28726|28726|100.0%|100.0%|
[sorbs_new_spam](#sorbs_new_spam)|27772|28726|28726|100.0%|100.0%|
[nixspam](#nixspam)|20080|20080|4216|20.9%|14.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|2047|0.0%|7.1%|
[blocklist_de](#blocklist_de)|28768|28768|1115|3.8%|3.8%|
[blocklist_de_mail](#blocklist_de_mail)|16032|16032|951|5.9%|3.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|735|0.0%|2.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|450|0.0%|1.5%|
[snort_ipfilter](#snort_ipfilter)|9994|9994|336|3.3%|1.1%|
[stopforumspam_30d](#stopforumspam_30d)|93498|93498|322|0.3%|1.1%|
[sorbs_web](#sorbs_web)|588|589|284|48.2%|0.9%|
[stopforumspam_7d](#stopforumspam_7d)|29882|29882|178|0.5%|0.6%|
[php_dictionary](#php_dictionary)|508|508|134|26.3%|0.4%|
[ri_web_proxies](#ri_web_proxies)|6466|6466|130|2.0%|0.4%|
[php_spammers](#php_spammers)|495|495|116|23.4%|0.4%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|3708|3708|104|2.8%|0.3%|
[blocklist_de_apache](#blocklist_de_apache)|15058|15058|104|0.6%|0.3%|
[alienvault_reputation](#alienvault_reputation)|176034|176034|103|0.0%|0.3%|
[xroxy](#xroxy)|2087|2087|84|4.0%|0.2%|
[stopforumspam_1d](#stopforumspam_1d)|7232|7232|50|0.6%|0.1%|
[proxz](#proxz)|824|824|38|4.6%|0.1%|
[blocklist_de_bots](#blocklist_de_bots)|3330|3330|35|1.0%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|31|0.0%|0.1%|
[blocklist_de_ssh](#blocklist_de_ssh)|4496|4496|21|0.4%|0.0%|
[sorbs_socks](#sorbs_socks)|19|19|19|100.0%|0.0%|
[sorbs_misc](#sorbs_misc)|19|19|19|100.0%|0.0%|
[sorbs_http](#sorbs_http)|19|19|19|100.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2050|2050|16|0.7%|0.0%|
[php_commenters](#php_commenters)|326|326|15|4.6%|0.0%|
[openbl_60d](#openbl_60d)|7667|7667|15|0.1%|0.0%|
[sorbs_smtp](#sorbs_smtp)|13|13|13|100.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|13|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2421|2421|10|0.4%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|8|0.0%|0.0%|
[et_block](#et_block)|1016|18338655|8|0.0%|0.0%|
[php_harvesters](#php_harvesters)|311|311|7|2.2%|0.0%|
[proxyrss](#proxyrss)|1768|1768|6|0.3%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|4|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|486400|3|0.0%|0.0%|
[openbl_30d](#openbl_30d)|3254|3254|3|0.0%|0.0%|
[et_tor](#et_tor)|6610|6610|3|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|868|868|3|0.3%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|2|0.2%|0.0%|
[dm_tor](#dm_tor)|6483|6483|2|0.0%|0.0%|
[bm_tor](#bm_tor)|6533|6533|2|0.0%|0.0%|
[shunlist](#shunlist)|1229|1229|1|0.0%|0.0%|
[openbl_7d](#openbl_7d)|893|893|1|0.1%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|1|0.0%|0.0%|
[dshield](#dshield)|20|5120|1|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|180|180|1|0.5%|0.0%|

## sorbs_smtp

[Sorbs.net](https://www.sorbs.net/) SMTP Open Relays, extracted from deltas.

Source is downloaded from [this link]().

The last time downloaded was found to be dated: Fri Jun  5 12:04:15 UTC 2015.

The ipset `sorbs_smtp` has **13** entries, **13** unique IPs.

The following table shows the overlaps of `sorbs_smtp` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `sorbs_smtp`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `sorbs_smtp`.
- ` this % ` is the percentage **of this ipset (`sorbs_smtp`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[sorbs_spam](#sorbs_spam)|27772|28726|13|0.0%|100.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|27772|28726|13|0.0%|100.0%|
[sorbs_new_spam](#sorbs_new_spam)|27772|28726|13|0.0%|100.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|1|0.0%|7.6%|

## sorbs_socks

[Sorbs.net](https://www.sorbs.net/) SOCKS proxies, extracted from deltas.

Source is downloaded from [this link]().

The last time downloaded was found to be dated: Fri Jun  5 17:04:14 UTC 2015.

The ipset `sorbs_socks` has **19** entries, **19** unique IPs.

The following table shows the overlaps of `sorbs_socks` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `sorbs_socks`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `sorbs_socks`.
- ` this % ` is the percentage **of this ipset (`sorbs_socks`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[sorbs_spam](#sorbs_spam)|27772|28726|19|0.0%|100.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|27772|28726|19|0.0%|100.0%|
[sorbs_new_spam](#sorbs_new_spam)|27772|28726|19|0.0%|100.0%|
[sorbs_misc](#sorbs_misc)|19|19|19|100.0%|100.0%|
[sorbs_http](#sorbs_http)|19|19|19|100.0%|100.0%|
[snort_ipfilter](#snort_ipfilter)|9994|9994|7|0.0%|36.8%|
[blocklist_de](#blocklist_de)|28768|28768|7|0.0%|36.8%|
[blocklist_de_mail](#blocklist_de_mail)|16032|16032|6|0.0%|31.5%|
[sorbs_web](#sorbs_web)|588|589|3|0.5%|15.7%|
[nixspam](#nixspam)|20080|20080|3|0.0%|15.7%|
[stopforumspam_7d](#stopforumspam_7d)|29882|29882|2|0.0%|10.5%|
[stopforumspam_30d](#stopforumspam_30d)|93498|93498|2|0.0%|10.5%|
[xroxy](#xroxy)|2087|2087|1|0.0%|5.2%|
[stopforumspam_1d](#stopforumspam_1d)|7232|7232|1|0.0%|5.2%|
[php_dictionary](#php_dictionary)|508|508|1|0.1%|5.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|1|0.0%|5.2%|
[blocklist_de_bots](#blocklist_de_bots)|3330|3330|1|0.0%|5.2%|

## sorbs_spam

[Sorbs.net](https://www.sorbs.net/) Spam senders, extracted from deltas.

Source is downloaded from [this link]().

The last time downloaded was found to be dated: Fri Jun  5 23:04:15 UTC 2015.

The ipset `sorbs_spam` has **27772** entries, **28726** unique IPs.

The following table shows the overlaps of `sorbs_spam` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `sorbs_spam`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `sorbs_spam`.
- ` this % ` is the percentage **of this ipset (`sorbs_spam`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[sorbs_recent_spam](#sorbs_recent_spam)|27772|28726|28726|100.0%|100.0%|
[sorbs_new_spam](#sorbs_new_spam)|27772|28726|28726|100.0%|100.0%|
[nixspam](#nixspam)|20080|20080|4216|20.9%|14.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|2047|0.0%|7.1%|
[blocklist_de](#blocklist_de)|28768|28768|1115|3.8%|3.8%|
[blocklist_de_mail](#blocklist_de_mail)|16032|16032|951|5.9%|3.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|735|0.0%|2.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|450|0.0%|1.5%|
[snort_ipfilter](#snort_ipfilter)|9994|9994|336|3.3%|1.1%|
[stopforumspam_30d](#stopforumspam_30d)|93498|93498|322|0.3%|1.1%|
[sorbs_web](#sorbs_web)|588|589|284|48.2%|0.9%|
[stopforumspam_7d](#stopforumspam_7d)|29882|29882|178|0.5%|0.6%|
[php_dictionary](#php_dictionary)|508|508|134|26.3%|0.4%|
[ri_web_proxies](#ri_web_proxies)|6466|6466|130|2.0%|0.4%|
[php_spammers](#php_spammers)|495|495|116|23.4%|0.4%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|3708|3708|104|2.8%|0.3%|
[blocklist_de_apache](#blocklist_de_apache)|15058|15058|104|0.6%|0.3%|
[alienvault_reputation](#alienvault_reputation)|176034|176034|103|0.0%|0.3%|
[xroxy](#xroxy)|2087|2087|84|4.0%|0.2%|
[stopforumspam_1d](#stopforumspam_1d)|7232|7232|50|0.6%|0.1%|
[proxz](#proxz)|824|824|38|4.6%|0.1%|
[blocklist_de_bots](#blocklist_de_bots)|3330|3330|35|1.0%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|31|0.0%|0.1%|
[blocklist_de_ssh](#blocklist_de_ssh)|4496|4496|21|0.4%|0.0%|
[sorbs_socks](#sorbs_socks)|19|19|19|100.0%|0.0%|
[sorbs_misc](#sorbs_misc)|19|19|19|100.0%|0.0%|
[sorbs_http](#sorbs_http)|19|19|19|100.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2050|2050|16|0.7%|0.0%|
[php_commenters](#php_commenters)|326|326|15|4.6%|0.0%|
[openbl_60d](#openbl_60d)|7667|7667|15|0.1%|0.0%|
[sorbs_smtp](#sorbs_smtp)|13|13|13|100.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|13|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2421|2421|10|0.4%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|8|0.0%|0.0%|
[et_block](#et_block)|1016|18338655|8|0.0%|0.0%|
[php_harvesters](#php_harvesters)|311|311|7|2.2%|0.0%|
[proxyrss](#proxyrss)|1768|1768|6|0.3%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|4|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|486400|3|0.0%|0.0%|
[openbl_30d](#openbl_30d)|3254|3254|3|0.0%|0.0%|
[et_tor](#et_tor)|6610|6610|3|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|868|868|3|0.3%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|2|0.2%|0.0%|
[dm_tor](#dm_tor)|6483|6483|2|0.0%|0.0%|
[bm_tor](#bm_tor)|6533|6533|2|0.0%|0.0%|
[shunlist](#shunlist)|1229|1229|1|0.0%|0.0%|
[openbl_7d](#openbl_7d)|893|893|1|0.1%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|1|0.0%|0.0%|
[dshield](#dshield)|20|5120|1|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|180|180|1|0.5%|0.0%|

## sorbs_web

[Sorbs.net](https://www.sorbs.net/) WEB exploits, extracted from deltas.

Source is downloaded from [this link]().

The last time downloaded was found to be dated: Fri Jun  5 23:04:16 UTC 2015.

The ipset `sorbs_web` has **588** entries, **589** unique IPs.

The following table shows the overlaps of `sorbs_web` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `sorbs_web`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `sorbs_web`.
- ` this % ` is the percentage **of this ipset (`sorbs_web`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[sorbs_spam](#sorbs_spam)|27772|28726|284|0.9%|48.2%|
[sorbs_recent_spam](#sorbs_recent_spam)|27772|28726|284|0.9%|48.2%|
[sorbs_new_spam](#sorbs_new_spam)|27772|28726|284|0.9%|48.2%|
[nixspam](#nixspam)|20080|20080|150|0.7%|25.4%|
[blocklist_de](#blocklist_de)|28768|28768|73|0.2%|12.3%|
[blocklist_de_mail](#blocklist_de_mail)|16032|16032|64|0.3%|10.8%|
[snort_ipfilter](#snort_ipfilter)|9994|9994|53|0.5%|8.9%|
[stopforumspam_30d](#stopforumspam_30d)|93498|93498|50|0.0%|8.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|38|0.0%|6.4%|
[stopforumspam_7d](#stopforumspam_7d)|29882|29882|37|0.1%|6.2%|
[php_dictionary](#php_dictionary)|508|508|26|5.1%|4.4%|
[php_spammers](#php_spammers)|495|495|25|5.0%|4.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|23|0.0%|3.9%|
[ri_web_proxies](#ri_web_proxies)|6466|6466|21|0.3%|3.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|21|0.0%|3.5%|
[xroxy](#xroxy)|2087|2087|16|0.7%|2.7%|
[stopforumspam_1d](#stopforumspam_1d)|7232|7232|13|0.1%|2.2%|
[proxz](#proxz)|824|824|10|1.2%|1.6%|
[blocklist_de_bots](#blocklist_de_bots)|3330|3330|7|0.2%|1.1%|
[sorbs_socks](#sorbs_socks)|19|19|3|15.7%|0.5%|
[sorbs_misc](#sorbs_misc)|19|19|3|15.7%|0.5%|
[sorbs_http](#sorbs_http)|19|19|3|15.7%|0.5%|
[proxyrss](#proxyrss)|1768|1768|2|0.1%|0.3%|
[php_commenters](#php_commenters)|326|326|2|0.6%|0.3%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|3708|3708|2|0.0%|0.3%|
[blocklist_de_apache](#blocklist_de_apache)|15058|15058|2|0.0%|0.3%|
[ri_connect_proxies](#ri_connect_proxies)|2421|2421|1|0.0%|0.1%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1|0.0%|0.1%|
[blocklist_de_strongips](#blocklist_de_strongips)|180|180|1|0.5%|0.1%|

## spamhaus_drop

[Spamhaus.org](http://www.spamhaus.org) DROP list (according to their site this list should be dropped at tier-1 ISPs globaly) - **excellent list**

Source is downloaded from [this link](http://www.spamhaus.org/drop/drop.txt).

The last time downloaded was found to be dated: Thu Jun  4 12:16:20 UTC 2015.

The ipset `spamhaus_drop` has **653** entries, **18404096** unique IPs.

The following table shows the overlaps of `spamhaus_drop` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `spamhaus_drop`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `spamhaus_drop`.
- ` this % ` is the percentage **of this ipset (`spamhaus_drop`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[et_block](#et_block)|1016|18338655|18120448|98.8%|98.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|8598042|2.4%|46.7%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|6998016|76.2%|38.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|2272265|0.2%|12.3%|
[fullbogons](#fullbogons)|3715|670310296|151552|0.0%|0.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|130368|0.0%|0.7%|
[alienvault_reputation](#alienvault_reputation)|176034|176034|1631|0.9%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1037|0.3%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|93498|93498|1023|1.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|486400|512|0.1%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29882|29882|336|1.1%|0.0%|
[dshield](#dshield)|20|5120|256|5.0%|0.0%|
[openbl_60d](#openbl_60d)|7667|7667|240|3.1%|0.0%|
[blocklist_de](#blocklist_de)|28768|28768|181|0.6%|0.0%|
[openbl_30d](#openbl_30d)|3254|3254|160|4.9%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|4496|4496|109|2.4%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1977|1977|101|5.1%|0.0%|
[et_compromised](#et_compromised)|2086|2086|100|4.7%|0.0%|
[nixspam](#nixspam)|20080|20080|98|0.4%|0.0%|
[shunlist](#shunlist)|1229|1229|97|7.8%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7232|7232|85|1.1%|0.0%|
[openbl_7d](#openbl_7d)|893|893|47|5.2%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3330|3330|42|1.2%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|29|2.2%|0.0%|
[php_commenters](#php_commenters)|326|326|28|8.5%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|16032|16032|25|0.1%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9994|9994|20|0.2%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2050|2050|17|0.8%|0.0%|
[zeus_badips](#zeus_badips)|202|202|16|7.9%|0.0%|
[zeus](#zeus)|230|230|16|6.9%|0.0%|
[voipbl](#voipbl)|10452|10864|14|0.1%|0.0%|
[sorbs_spam](#sorbs_spam)|27772|28726|8|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|27772|28726|8|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|27772|28726|8|0.0%|0.0%|
[openbl_1d](#openbl_1d)|143|143|8|5.5%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|180|180|7|3.8%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|6|0.4%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|6|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|3708|3708|5|0.1%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|15058|15058|5|0.0%|0.0%|
[php_dictionary](#php_dictionary)|508|508|4|0.7%|0.0%|
[malc0de](#malc0de)|371|371|4|1.0%|0.0%|
[php_spammers](#php_spammers)|495|495|3|0.6%|0.0%|
[dm_tor](#dm_tor)|6483|6483|3|0.0%|0.0%|
[bm_tor](#bm_tor)|6533|6533|3|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|2|0.2%|0.0%|
[et_tor](#et_tor)|6610|6610|2|0.0%|0.0%|
[sslbl](#sslbl)|369|369|1|0.2%|0.0%|
[php_harvesters](#php_harvesters)|311|311|1|0.3%|0.0%|
[et_botcc](#et_botcc)|509|509|1|0.1%|0.0%|

## spamhaus_edrop

[Spamhaus.org](http://www.spamhaus.org) EDROP (extended matches that should be used with DROP) - **excellent list**

Source is downloaded from [this link](http://www.spamhaus.org/drop/edrop.txt).

The last time downloaded was found to be dated: Wed Jun  3 21:37:19 UTC 2015.

The ipset `spamhaus_edrop` has **55** entries, **486400** unique IPs.

The following table shows the overlaps of `spamhaus_edrop` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `spamhaus_edrop`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `spamhaus_edrop`.
- ` this % ` is the percentage **of this ipset (`spamhaus_edrop`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|270785|0.1%|55.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|98904|0.0%|20.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|33155|0.0%|6.8%|
[et_block](#et_block)|1016|18338655|517|0.0%|0.1%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|512|0.0%|0.1%|
[stopforumspam_30d](#stopforumspam_30d)|93498|93498|92|0.0%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29882|29882|17|0.0%|0.0%|
[alienvault_reputation](#alienvault_reputation)|176034|176034|15|0.0%|0.0%|
[php_commenters](#php_commenters)|326|326|7|2.1%|0.0%|
[blocklist_de](#blocklist_de)|28768|28768|7|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9994|9994|6|0.0%|0.0%|
[zeus_badips](#zeus_badips)|202|202|5|2.4%|0.0%|
[zeus](#zeus)|230|230|5|2.1%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|180|180|4|2.2%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3330|3330|4|0.1%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7232|7232|3|0.0%|0.0%|
[sorbs_spam](#sorbs_spam)|27772|28726|3|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|27772|28726|3|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|27772|28726|3|0.0%|0.0%|
[php_harvesters](#php_harvesters)|311|311|1|0.3%|0.0%|
[openbl_60d](#openbl_60d)|7667|7667|1|0.0%|0.0%|
[openbl_30d](#openbl_30d)|3254|3254|1|0.0%|0.0%|
[nixspam](#nixspam)|20080|20080|1|0.0%|0.0%|
[malc0de](#malc0de)|371|371|1|0.2%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|4496|4496|1|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|16032|16032|1|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|15058|15058|1|0.0%|0.0%|

## sslbl

[Abuse.ch SSL Blacklist](https://sslbl.abuse.ch/) bad SSL traffic related to malware or botnet activities - **excellent list**

Source is downloaded from [this link](https://sslbl.abuse.ch/blacklist/sslipblacklist.csv).

The last time downloaded was found to be dated: Fri Jun  5 23:15:06 UTC 2015.

The ipset `sslbl` has **369** entries, **369** unique IPs.

The following table shows the overlaps of `sslbl` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `sslbl`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `sslbl`.
- ` this % ` is the percentage **of this ipset (`sslbl`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[alienvault_reputation](#alienvault_reputation)|176034|176034|64|0.0%|17.3%|
[shunlist](#shunlist)|1229|1229|56|4.5%|15.1%|
[feodo](#feodo)|96|96|36|37.5%|9.7%|
[et_block](#et_block)|1016|18338655|33|0.0%|8.9%|
[snort_ipfilter](#snort_ipfilter)|9994|9994|29|0.2%|7.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|24|0.0%|6.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|6|0.0%|1.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|3|0.0%|0.8%|
[stopforumspam_30d](#stopforumspam_30d)|93498|93498|1|0.0%|0.2%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|1|0.0%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.2%|
[blocklist_de_ssh](#blocklist_de_ssh)|4496|4496|1|0.0%|0.2%|
[blocklist_de](#blocklist_de)|28768|28768|1|0.0%|0.2%|

## stopforumspam_1d

[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers in the last 24 hours - **excellent list**

Source is downloaded from [this link](http://www.stopforumspam.com/downloads/listed_ip_1.zip).

The last time downloaded was found to be dated: Fri Jun  5 23:00:02 UTC 2015.

The ipset `stopforumspam_1d` has **7232** entries, **7232** unique IPs.

The following table shows the overlaps of `stopforumspam_1d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `stopforumspam_1d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `stopforumspam_1d`.
- ` this % ` is the percentage **of this ipset (`stopforumspam_1d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_30d](#stopforumspam_30d)|93498|93498|4608|4.9%|63.7%|
[stopforumspam_7d](#stopforumspam_7d)|29882|29882|4084|13.6%|56.4%|
[blocklist_de](#blocklist_de)|28768|28768|1430|4.9%|19.7%|
[blocklist_de_bots](#blocklist_de_bots)|3330|3330|1365|40.9%|18.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|527|0.0%|7.2%|
[ri_web_proxies](#ri_web_proxies)|6466|6466|484|7.4%|6.6%|
[proxyrss](#proxyrss)|1768|1768|380|21.4%|5.2%|
[snort_ipfilter](#snort_ipfilter)|9994|9994|353|3.5%|4.8%|
[et_tor](#et_tor)|6610|6610|319|4.8%|4.4%|
[bm_tor](#bm_tor)|6533|6533|318|4.8%|4.3%|
[dm_tor](#dm_tor)|6483|6483|317|4.8%|4.3%|
[xroxy](#xroxy)|2087|2087|276|13.2%|3.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|218|0.0%|3.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|155|41.6%|2.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|155|0.0%|2.1%|
[proxz](#proxz)|824|824|148|17.9%|2.0%|
[ri_connect_proxies](#ri_connect_proxies)|2421|2421|139|5.7%|1.9%|
[php_commenters](#php_commenters)|326|326|133|40.7%|1.8%|
[blocklist_de_strongips](#blocklist_de_strongips)|180|180|108|60.0%|1.4%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|85|0.0%|1.1%|
[et_block](#et_block)|1016|18338655|80|0.0%|1.1%|
[blocklist_de_apache](#blocklist_de_apache)|15058|15058|66|0.4%|0.9%|
[alienvault_reputation](#alienvault_reputation)|176034|176034|55|0.0%|0.7%|
[blocklist_de_mail](#blocklist_de_mail)|16032|16032|53|0.3%|0.7%|
[nixspam](#nixspam)|20080|20080|52|0.2%|0.7%|
[sorbs_spam](#sorbs_spam)|27772|28726|50|0.1%|0.6%|
[sorbs_recent_spam](#sorbs_recent_spam)|27772|28726|50|0.1%|0.6%|
[sorbs_new_spam](#sorbs_new_spam)|27772|28726|50|0.1%|0.6%|
[php_harvesters](#php_harvesters)|311|311|40|12.8%|0.5%|
[php_spammers](#php_spammers)|495|495|28|5.6%|0.3%|
[php_dictionary](#php_dictionary)|508|508|27|5.3%|0.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|22|0.0%|0.3%|
[openbl_60d](#openbl_60d)|7667|7667|21|0.2%|0.2%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|3708|3708|20|0.5%|0.2%|
[sorbs_web](#sorbs_web)|588|589|13|2.2%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|8|0.0%|0.1%|
[voipbl](#voipbl)|10452|10864|4|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|486400|3|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|3|0.4%|0.0%|
[openbl_30d](#openbl_30d)|3254|3254|2|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|2|0.0%|0.0%|
[zeus_badips](#zeus_badips)|202|202|1|0.4%|0.0%|
[zeus](#zeus)|230|230|1|0.4%|0.0%|
[sorbs_socks](#sorbs_socks)|19|19|1|5.2%|0.0%|
[sorbs_misc](#sorbs_misc)|19|19|1|5.2%|0.0%|
[sorbs_http](#sorbs_http)|19|19|1|5.2%|0.0%|
[shunlist](#shunlist)|1229|1229|1|0.0%|0.0%|
[et_compromised](#et_compromised)|2086|2086|1|0.0%|0.0%|
[dshield](#dshield)|20|5120|1|0.0%|0.0%|
[ciarmy](#ciarmy)|421|421|1|0.2%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1977|1977|1|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|4496|4496|1|0.0%|0.0%|

## stopforumspam_30d

[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 30 days)

Source is downloaded from [this link](http://www.stopforumspam.com/downloads/listed_ip_30.zip).

The last time downloaded was found to be dated: Fri Jun  5 00:01:20 UTC 2015.

The ipset `stopforumspam_30d` has **93498** entries, **93498** unique IPs.

The following table shows the overlaps of `stopforumspam_30d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `stopforumspam_30d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `stopforumspam_30d`.
- ` this % ` is the percentage **of this ipset (`stopforumspam_30d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_7d](#stopforumspam_7d)|29882|29882|29803|99.7%|31.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|5886|0.0%|6.2%|
[stopforumspam_1d](#stopforumspam_1d)|7232|7232|4608|63.7%|4.9%|
[ri_web_proxies](#ri_web_proxies)|6466|6466|3117|48.2%|3.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|2548|0.0%|2.7%|
[blocklist_de](#blocklist_de)|28768|28768|2384|8.2%|2.5%|
[blocklist_de_bots](#blocklist_de_bots)|3330|3330|2018|60.6%|2.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|1554|0.0%|1.6%|
[ri_connect_proxies](#ri_connect_proxies)|2421|2421|1397|57.7%|1.4%|
[xroxy](#xroxy)|2087|2087|1224|58.6%|1.3%|
[et_block](#et_block)|1016|18338655|1028|0.0%|1.0%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|1023|0.0%|1.0%|
[snort_ipfilter](#snort_ipfilter)|9994|9994|794|7.9%|0.8%|
[proxyrss](#proxyrss)|1768|1768|778|44.0%|0.8%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|759|0.0%|0.8%|
[et_tor](#et_tor)|6610|6610|644|9.7%|0.6%|
[bm_tor](#bm_tor)|6533|6533|627|9.5%|0.6%|
[dm_tor](#dm_tor)|6483|6483|626|9.6%|0.6%|
[proxz](#proxz)|824|824|493|59.8%|0.5%|
[sorbs_spam](#sorbs_spam)|27772|28726|322|1.1%|0.3%|
[sorbs_recent_spam](#sorbs_recent_spam)|27772|28726|322|1.1%|0.3%|
[sorbs_new_spam](#sorbs_new_spam)|27772|28726|322|1.1%|0.3%|
[blocklist_de_mail](#blocklist_de_mail)|16032|16032|271|1.6%|0.2%|
[php_commenters](#php_commenters)|326|326|235|72.0%|0.2%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|233|62.6%|0.2%|
[blocklist_de_apache](#blocklist_de_apache)|15058|15058|221|1.4%|0.2%|
[alienvault_reputation](#alienvault_reputation)|176034|176034|204|0.1%|0.2%|
[nixspam](#nixspam)|20080|20080|188|0.9%|0.2%|
[blocklist_de_strongips](#blocklist_de_strongips)|180|180|128|71.1%|0.1%|
[php_spammers](#php_spammers)|495|495|112|22.6%|0.1%|
[php_dictionary](#php_dictionary)|508|508|98|19.2%|0.1%|
[spamhaus_edrop](#spamhaus_edrop)|55|486400|92|0.0%|0.0%|
[php_harvesters](#php_harvesters)|311|311|68|21.8%|0.0%|
[openbl_60d](#openbl_60d)|7667|7667|57|0.7%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|3708|3708|56|1.5%|0.0%|
[sorbs_web](#sorbs_web)|588|589|50|8.4%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|47|0.0%|0.0%|
[voipbl](#voipbl)|10452|10864|37|0.3%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|4496|4496|34|0.7%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|22|3.2%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|14|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1977|1977|11|0.5%|0.0%|
[et_compromised](#et_compromised)|2086|2086|10|0.4%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2050|2050|9|0.4%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|868|868|9|1.0%|0.0%|
[shunlist](#shunlist)|1229|1229|4|0.3%|0.0%|
[openbl_30d](#openbl_30d)|3254|3254|4|0.1%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|4|0.3%|0.0%|
[openbl_7d](#openbl_7d)|893|893|3|0.3%|0.0%|
[zeus_badips](#zeus_badips)|202|202|2|0.9%|0.0%|
[zeus](#zeus)|230|230|2|0.8%|0.0%|
[sorbs_socks](#sorbs_socks)|19|19|2|10.5%|0.0%|
[sorbs_misc](#sorbs_misc)|19|19|2|10.5%|0.0%|
[sorbs_http](#sorbs_http)|19|19|2|10.5%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.0%|
[fullbogons](#fullbogons)|3715|670310296|2|0.0%|0.0%|
[sslbl](#sslbl)|369|369|1|0.2%|0.0%|
[dshield](#dshield)|20|5120|1|0.0%|0.0%|
[ciarmy](#ciarmy)|421|421|1|0.2%|0.0%|
[bogons](#bogons)|13|592708608|1|0.0%|0.0%|

## stopforumspam_7d

[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 7 days)

Source is downloaded from [this link](http://www.stopforumspam.com/downloads/listed_ip_7.zip).

The last time downloaded was found to be dated: Fri Jun  5 01:02:36 UTC 2015.

The ipset `stopforumspam_7d` has **29882** entries, **29882** unique IPs.

The following table shows the overlaps of `stopforumspam_7d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `stopforumspam_7d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `stopforumspam_7d`.
- ` this % ` is the percentage **of this ipset (`stopforumspam_7d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_30d](#stopforumspam_30d)|93498|93498|29803|31.8%|99.7%|
[stopforumspam_1d](#stopforumspam_1d)|7232|7232|4084|56.4%|13.6%|
[blocklist_de](#blocklist_de)|28768|28768|2000|6.9%|6.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|1876|0.0%|6.2%|
[blocklist_de_bots](#blocklist_de_bots)|3330|3330|1802|54.1%|6.0%|
[ri_web_proxies](#ri_web_proxies)|6466|6466|1640|25.3%|5.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|932|0.0%|3.1%|
[xroxy](#xroxy)|2087|2087|775|37.1%|2.5%|
[ri_connect_proxies](#ri_connect_proxies)|2421|2421|657|27.1%|2.1%|
[snort_ipfilter](#snort_ipfilter)|9994|9994|621|6.2%|2.0%|
[proxyrss](#proxyrss)|1768|1768|610|34.5%|2.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|566|0.0%|1.8%|
[et_tor](#et_tor)|6610|6610|516|7.8%|1.7%|
[bm_tor](#bm_tor)|6533|6533|499|7.6%|1.6%|
[dm_tor](#dm_tor)|6483|6483|497|7.6%|1.6%|
[proxz](#proxz)|824|824|400|48.5%|1.3%|
[et_block](#et_block)|1016|18338655|341|0.0%|1.1%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|336|0.0%|1.1%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|190|51.0%|0.6%|
[sorbs_spam](#sorbs_spam)|27772|28726|178|0.6%|0.5%|
[sorbs_recent_spam](#sorbs_recent_spam)|27772|28726|178|0.6%|0.5%|
[sorbs_new_spam](#sorbs_new_spam)|27772|28726|178|0.6%|0.5%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|177|0.0%|0.5%|
[php_commenters](#php_commenters)|326|326|172|52.7%|0.5%|
[blocklist_de_mail](#blocklist_de_mail)|16032|16032|160|0.9%|0.5%|
[blocklist_de_apache](#blocklist_de_apache)|15058|15058|137|0.9%|0.4%|
[blocklist_de_strongips](#blocklist_de_strongips)|180|180|117|65.0%|0.3%|
[nixspam](#nixspam)|20080|20080|99|0.4%|0.3%|
[alienvault_reputation](#alienvault_reputation)|176034|176034|92|0.0%|0.3%|
[php_spammers](#php_spammers)|495|495|66|13.3%|0.2%|
[php_dictionary](#php_dictionary)|508|508|66|12.9%|0.2%|
[php_harvesters](#php_harvesters)|311|311|52|16.7%|0.1%|
[sorbs_web](#sorbs_web)|588|589|37|6.2%|0.1%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|3708|3708|36|0.9%|0.1%|
[openbl_60d](#openbl_60d)|7667|7667|25|0.3%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|24|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|486400|17|0.0%|0.0%|
[voipbl](#voipbl)|10452|10864|13|0.1%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|12|1.7%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1977|1977|7|0.3%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|4496|4496|7|0.1%|0.0%|
[et_compromised](#et_compromised)|2086|2086|6|0.2%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|5|0.0%|0.0%|
[shunlist](#shunlist)|1229|1229|3|0.2%|0.0%|
[sorbs_socks](#sorbs_socks)|19|19|2|10.5%|0.0%|
[sorbs_misc](#sorbs_misc)|19|19|2|10.5%|0.0%|
[sorbs_http](#sorbs_http)|19|19|2|10.5%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|2|0.1%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2050|2050|2|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|868|868|2|0.2%|0.0%|
[zeus_badips](#zeus_badips)|202|202|1|0.4%|0.0%|
[zeus](#zeus)|230|230|1|0.4%|0.0%|
[openbl_30d](#openbl_30d)|3254|3254|1|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|
[dshield](#dshield)|20|5120|1|0.0%|0.0%|
[ciarmy](#ciarmy)|421|421|1|0.2%|0.0%|

## virbl

[VirBL](http://virbl.bit.nl/) is a project of which the idea was born during the RIPE-48 meeting. The plan was to get reports of virusscanning mailservers, and put the IP-addresses that were reported to send viruses on a blacklist.

Source is downloaded from [this link](http://virbl.bit.nl/download/virbl.dnsbl.bit.nl.txt).

The last time downloaded was found to be dated: Fri Jun  5 22:52:05 UTC 2015.

The ipset `virbl` has **12** entries, **12** unique IPs.

The following table shows the overlaps of `virbl` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `virbl`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `virbl`.
- ` this % ` is the percentage **of this ipset (`virbl`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|1|0.0%|8.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|1|0.0%|8.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|1|0.0%|8.3%|

## voipbl

[VoIPBL.org](http://www.voipbl.org/) a distributed VoIP blacklist that is aimed to protects against VoIP Fraud and minimizing abuse for network that have publicly accessible PBX's. Several algorithms, external sources and manual confirmation are used before they categorize something as an attack and determine the threat level.

Source is downloaded from [this link](http://www.voipbl.org/update/).

The last time downloaded was found to be dated: Fri Jun  5 20:36:37 UTC 2015.

The ipset `voipbl` has **10452** entries, **10864** unique IPs.

The following table shows the overlaps of `voipbl` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `voipbl`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `voipbl`.
- ` this % ` is the percentage **of this ipset (`voipbl`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|1598|0.0%|14.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|434|0.0%|3.9%|
[fullbogons](#fullbogons)|3715|670310296|319|0.0%|2.9%|
[bogons](#bogons)|13|592708608|319|0.0%|2.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|299|0.0%|2.7%|
[alienvault_reputation](#alienvault_reputation)|176034|176034|209|0.1%|1.9%|
[blocklist_de](#blocklist_de)|28768|28768|39|0.1%|0.3%|
[stopforumspam_30d](#stopforumspam_30d)|93498|93498|37|0.0%|0.3%|
[blocklist_de_sip](#blocklist_de_sip)|92|92|30|32.6%|0.2%|
[et_block](#et_block)|1016|18338655|21|0.0%|0.1%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|14|0.0%|0.1%|
[stopforumspam_7d](#stopforumspam_7d)|29882|29882|13|0.0%|0.1%|
[shunlist](#shunlist)|1229|1229|12|0.9%|0.1%|
[dshield](#dshield)|20|5120|10|0.1%|0.0%|
[openbl_60d](#openbl_60d)|7667|7667|8|0.1%|0.0%|
[ciarmy](#ciarmy)|421|421|6|1.4%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7232|7232|4|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|4|0.0%|0.0%|
[openbl_30d](#openbl_30d)|3254|3254|3|0.0%|0.0%|
[et_tor](#et_tor)|6610|6610|3|0.0%|0.0%|
[dm_tor](#dm_tor)|6483|6483|3|0.0%|0.0%|
[bm_tor](#bm_tor)|6533|6533|3|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3330|3330|3|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|15058|15058|3|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|2|0.0%|0.0%|
[et_compromised](#et_compromised)|2086|2086|2|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1977|1977|2|0.1%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|16032|16032|2|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9994|9994|1|0.0%|0.0%|
[openbl_7d](#openbl_7d)|893|893|1|0.1%|0.0%|
[nixspam](#nixspam)|20080|20080|1|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|4496|4496|1|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2050|2050|1|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|3708|3708|1|0.0%|0.0%|

## xroxy

[xroxy.com](http://www.xroxy.com) open proxies (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.xroxy.com/proxyrss.xml).

The last time downloaded was found to be dated: Fri Jun  5 22:33:01 UTC 2015.

The ipset `xroxy` has **2087** entries, **2087** unique IPs.

The following table shows the overlaps of `xroxy` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `xroxy`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `xroxy`.
- ` this % ` is the percentage **of this ipset (`xroxy`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_30d](#stopforumspam_30d)|93498|93498|1224|1.3%|58.6%|
[ri_web_proxies](#ri_web_proxies)|6466|6466|889|13.7%|42.5%|
[stopforumspam_7d](#stopforumspam_7d)|29882|29882|775|2.5%|37.1%|
[proxyrss](#proxyrss)|1768|1768|424|23.9%|20.3%|
[ri_connect_proxies](#ri_connect_proxies)|2421|2421|362|14.9%|17.3%|
[proxz](#proxz)|824|824|328|39.8%|15.7%|
[stopforumspam_1d](#stopforumspam_1d)|7232|7232|276|3.8%|13.2%|
[blocklist_de](#blocklist_de)|28768|28768|259|0.9%|12.4%|
[blocklist_de_bots](#blocklist_de_bots)|3330|3330|207|6.2%|9.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|100|0.0%|4.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|93|0.0%|4.4%|
[sorbs_spam](#sorbs_spam)|27772|28726|84|0.2%|4.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|27772|28726|84|0.2%|4.0%|
[sorbs_new_spam](#sorbs_new_spam)|27772|28726|84|0.2%|4.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|58|0.0%|2.7%|
[blocklist_de_mail](#blocklist_de_mail)|16032|16032|52|0.3%|2.4%|
[nixspam](#nixspam)|20080|20080|50|0.2%|2.3%|
[snort_ipfilter](#snort_ipfilter)|9994|9994|48|0.4%|2.2%|
[php_dictionary](#php_dictionary)|508|508|31|6.1%|1.4%|
[php_spammers](#php_spammers)|495|495|25|5.0%|1.1%|
[sorbs_web](#sorbs_web)|588|589|16|2.7%|0.7%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|13|1.9%|0.6%|
[php_commenters](#php_commenters)|326|326|7|2.1%|0.3%|
[blocklist_de_strongips](#blocklist_de_strongips)|180|180|6|3.3%|0.2%|
[alienvault_reputation](#alienvault_reputation)|176034|176034|4|0.0%|0.1%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|3|0.0%|0.1%|
[php_harvesters](#php_harvesters)|311|311|2|0.6%|0.0%|
[et_tor](#et_tor)|6610|6610|2|0.0%|0.0%|
[dm_tor](#dm_tor)|6483|6483|2|0.0%|0.0%|
[bm_tor](#bm_tor)|6533|6533|2|0.0%|0.0%|
[sorbs_socks](#sorbs_socks)|19|19|1|5.2%|0.0%|
[sorbs_misc](#sorbs_misc)|19|19|1|5.2%|0.0%|
[sorbs_http](#sorbs_http)|19|19|1|5.2%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.0%|
[et_compromised](#et_compromised)|2086|2086|1|0.0%|0.0%|
[et_block](#et_block)|1016|18338655|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1977|1977|1|0.0%|0.0%|

## zeus

[Abuse.ch Zeus tracker](https://zeustracker.abuse.ch) standard, contains the same data as the ZeuS IP blocklist (zeus_badips) but with the slight difference that it doesn't exclude hijacked websites (level 2) and free web hosting providers (level 3). This means that this blocklist contains all IPv4 addresses associated with ZeuS C&Cs which are currently being tracked by ZeuS Tracker. Hence this blocklist will likely cause some false positives. - **excellent list**

Source is downloaded from [this link](https://zeustracker.abuse.ch/blocklist.php?download=ipblocklist).

The last time downloaded was found to be dated: Fri Jun  5 21:11:52 UTC 2015.

The ipset `zeus` has **230** entries, **230** unique IPs.

The following table shows the overlaps of `zeus` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `zeus`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `zeus`.
- ` this % ` is the percentage **of this ipset (`zeus`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[et_block](#et_block)|1016|18338655|223|0.0%|96.9%|
[zeus_badips](#zeus_badips)|202|202|202|100.0%|87.8%|
[snort_ipfilter](#snort_ipfilter)|9994|9994|201|2.0%|87.3%|
[alienvault_reputation](#alienvault_reputation)|176034|176034|62|0.0%|26.9%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|16|0.0%|6.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|14|0.0%|6.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|10|0.0%|4.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|9|0.0%|3.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|6|0.0%|2.6%|
[spamhaus_edrop](#spamhaus_edrop)|55|486400|5|0.0%|2.1%|
[dshield](#dshield)|20|5120|3|0.0%|1.3%|
[stopforumspam_30d](#stopforumspam_30d)|93498|93498|2|0.0%|0.8%|
[openbl_60d](#openbl_60d)|7667|7667|2|0.0%|0.8%|
[openbl_30d](#openbl_30d)|3254|3254|2|0.0%|0.8%|
[stopforumspam_7d](#stopforumspam_7d)|29882|29882|1|0.0%|0.4%|
[stopforumspam_1d](#stopforumspam_1d)|7232|7232|1|0.0%|0.4%|
[php_commenters](#php_commenters)|326|326|1|0.3%|0.4%|
[nixspam](#nixspam)|20080|20080|1|0.0%|0.4%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.4%|

## zeus_badips

[Abuse.ch Zeus tracker](https://zeustracker.abuse.ch) badips includes IPv4 addresses that are used by the ZeuS trojan. It is the recommened blocklist if you want to block only ZeuS IPs. It excludes IP addresses that ZeuS Tracker believes to be hijacked (level 2) or belong to a free web hosting provider (level 3). Hence the false postive rate should be much lower compared to the standard ZeuS IP blocklist. **excellent list**

Source is downloaded from [this link](https://zeustracker.abuse.ch/blocklist.php?download=badips).

The last time downloaded was found to be dated: Fri Jun  5 22:54:13 UTC 2015.

The ipset `zeus_badips` has **202** entries, **202** unique IPs.

The following table shows the overlaps of `zeus_badips` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `zeus_badips`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `zeus_badips`.
- ` this % ` is the percentage **of this ipset (`zeus_badips`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[zeus](#zeus)|230|230|202|87.8%|100.0%|
[et_block](#et_block)|1016|18338655|200|0.0%|99.0%|
[snort_ipfilter](#snort_ipfilter)|9994|9994|179|1.7%|88.6%|
[alienvault_reputation](#alienvault_reputation)|176034|176034|38|0.0%|18.8%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|16|0.0%|7.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|10|0.0%|4.9%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|10|0.0%|4.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|8|0.0%|3.9%|
[spamhaus_edrop](#spamhaus_edrop)|55|486400|5|0.0%|2.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|4|0.0%|1.9%|
[dshield](#dshield)|20|5120|3|0.0%|1.4%|
[stopforumspam_30d](#stopforumspam_30d)|93498|93498|2|0.0%|0.9%|
[stopforumspam_7d](#stopforumspam_7d)|29882|29882|1|0.0%|0.4%|
[stopforumspam_1d](#stopforumspam_1d)|7232|7232|1|0.0%|0.4%|
[php_commenters](#php_commenters)|326|326|1|0.3%|0.4%|
[openbl_60d](#openbl_60d)|7667|7667|1|0.0%|0.4%|
[openbl_30d](#openbl_30d)|3254|3254|1|0.0%|0.4%|
[nixspam](#nixspam)|20080|20080|1|0.0%|0.4%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.4%|
