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

The following list was automatically generated on Sun Jun  7 12:42:39 UTC 2015.

The update frequency is the maximum allowed by internal configuration. A list will never be downloaded sooner than the update frequency stated. A list may also not be downloaded, after this frequency expired, if it has not been modified on the server (as reported by HTTP `IF_MODIFIED_SINCE` method).

name|info|type|entries|update|
:--:|:--:|:--:|:-----:|:----:|
[alienvault_reputation](#alienvault_reputation)|[AlienVault.com](https://www.alienvault.com/) IP reputation database (this list seems to include port scanning hosts and to be updated regularly, but we found no information about its retention policy)|ipv4 hash:ip|178903 unique IPs|updated every 6 hours  from [this link](https://reputation.alienvault.com/reputation.generic)
[blocklist_de](#blocklist_de)|[Blocklist.de](https://www.blocklist.de/) IPs that have been detected by fail2ban in the last 48 hours - **excellent list**|ipv4 hash:ip|27586 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/all.txt)
[blocklist_de_apache](#blocklist_de_apache)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service Apache, Apache-DDOS, RFI-Attacks.|ipv4 hash:ip|15388 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/apache.txt)
[blocklist_de_bots](#blocklist_de_bots)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the RFI-Attacks, REG-Bots, IRC-Bots or BadBots (BadBots = he has posted a Spam-Comment on a open Forum or Wiki).|ipv4 hash:ip|2976 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/bots.txt)
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|[Blocklist.de](https://www.blocklist.de/) All IPs which attacks Joomlas, Wordpress and other Web-Logins with Brute-Force Logins.|ipv4 hash:ip|4042 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/bruteforcelogin.txt)
[blocklist_de_ftp](#blocklist_de_ftp)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours for attacks on the Service FTP.|ipv4 hash:ip|635 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/ftp.txt)
[blocklist_de_imap](#blocklist_de_imap)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours for attacks on the Service imap, sasl, pop3, etc.|ipv4 hash:ip|2180 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/imap.txt)
[blocklist_de_mail](#blocklist_de_mail)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service Mail, Postfix.|ipv4 hash:ip|17025 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/mail.txt)
[blocklist_de_sip](#blocklist_de_sip)|[Blocklist.de](https://www.blocklist.de/) All IP addresses that tried to login in a SIP, VOIP or Asterisk Server and are included in the IPs list from [infiltrated.net](www.infiltrated.net)|ipv4 hash:ip|86 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/sip.txt)
[blocklist_de_ssh](#blocklist_de_ssh)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service SSH.|ipv4 hash:ip|2572 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/ssh.txt)
[blocklist_de_strongips](#blocklist_de_strongips)|[Blocklist.de](https://www.blocklist.de/) All IPs which are older then 2 month and have more then 5.000 attacks.|ipv4 hash:ip|165 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/strongips.txt)
[bm_tor](#bm_tor)|[torstatus.blutmagie.de](https://torstatus.blutmagie.de) list of all TOR network servers|ipv4 hash:ip|6522 unique IPs|updated every 30 mins  from [this link](https://torstatus.blutmagie.de/ip_list_all.php/Tor_ip_list_ALL.csv)
[bogons](#bogons)|[Team-Cymru.org](http://www.team-cymru.org) private and reserved addresses defined by RFC 1918, RFC 5735, and RFC 6598 and netblocks that have not been allocated to a regional internet registry - **excellent list - use it only your internet interface**|ipv4 hash:net|13 subnets, 592708608 unique IPs|updated every 1 day  from [this link](http://www.team-cymru.org/Services/Bogons/bogon-bn-agg.txt)
[bruteforceblocker](#bruteforceblocker)|[danger.rulez.sk](http://danger.rulez.sk/) IPs detected by [bruteforceblocker](http://danger.rulez.sk/index.php/bruteforceblocker/) (fail2ban alternative for SSH on OpenBSD). This is an automatically generated list from users reporting failed authentication attempts. An IP seems to be included if 3 or more users report it. Its retention pocily seems 30 days.|ipv4 hash:ip|1720 unique IPs|updated every 3 hours  from [this link](http://danger.rulez.sk/projects/bruteforceblocker/blist.php)
[ciarmy](#ciarmy)|[CIArmy.com](http://ciarmy.com/) IPs with poor Rogue Packet score that have not yet been identified as malicious by the community|ipv4 hash:ip|425 unique IPs|updated every 3 hours  from [this link](http://cinsscore.com/list/ci-badguys.txt)
[cleanmx_viruses](#cleanmx_viruses)|[Clean-MX.de](http://support.clean-mx.de/clean-mx/viruses.php) IPs with viruses|ipv4 hash:ip|310 unique IPs|updated every 12 hours  from [this link](http://support.clean-mx.de/clean-mx/xmlviruses.php?sort=id%20desc&response=alive)
[dm_tor](#dm_tor)|[dan.me.uk](https://www.dan.me.uk) dynamic list of TOR exit points|ipv4 hash:ip|6516 unique IPs|updated every 30 mins  from [this link](https://www.dan.me.uk/torlist/)
[dshield](#dshield)|[DShield.org](https://dshield.org/) top 20 attacking class C (/24) subnets over the last three days - **excellent list**|ipv4 hash:net|20 subnets, 5120 unique IPs|updated every 4 hours  from [this link](http://feeds.dshield.org/block.txt)
[et_block](#et_block)|[EmergingThreats.net](http://www.emergingthreats.net/) default blacklist (at the time of writing includes spamhaus DROP, dshield and abuse.ch trackers, which are available separately too - prefer to use the direct ipsets instead of this, they seem to lag a bit in updates)|ipv4 hash:net|1023 subnets, 18338662 unique IPs|updated every 12 hours  from [this link](http://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt)
[et_botcc](#et_botcc)|[EmergingThreats.net Command and Control IPs](http://doc.emergingthreats.net/bin/view/Main/BotCC) These IPs are updates every 24 hours and should be considered VERY highly reliable indications that a host is communicating with a known and active Bot or Malware command and control server - (although they say this includes abuse.ch trackers, it does not - most probably it is the shadowserver.org C&C list)|ipv4 hash:ip|509 unique IPs|updated every 12 hours  from [this link](http://rules.emergingthreats.net/fwrules/emerging-PIX-CC.rules)
[et_compromised](#et_compromised)|[EmergingThreats.net compromised hosts](http://doc.emergingthreats.net/bin/view/Main/CompromisedHost) - (this seems to be based on bruteforceblocker)|ipv4 hash:ip|2016 unique IPs|updated every 12 hours  from [this link](http://rules.emergingthreats.net/blockrules/compromised-ips.txt)
et_dshield|[EmergingThreats.net](http://www.emergingthreats.net/) dshield blocklist|ipv4 hash:net|disabled|updated every 12 hours  from [this link](http://rules.emergingthreats.net/fwrules/emerging-PIX-DSHIELD.rules)
et_spamhaus|[EmergingThreats.net](http://www.emergingthreats.net/) spamhaus blocklist|ipv4 hash:net|disabled|updated every 12 hours  from [this link](http://rules.emergingthreats.net/fwrules/emerging-PIX-DROP.rules)
[et_tor](#et_tor)|[EmergingThreats.net](http://www.emergingthreats.net/) [list](http://doc.emergingthreats.net/bin/view/Main/TorRules) of TOR network IPs|ipv4 hash:ip|6470 unique IPs|updated every 12 hours  from [this link](http://rules.emergingthreats.net/blockrules/emerging-tor.rules)
[feodo](#feodo)|[Abuse.ch Feodo tracker](https://feodotracker.abuse.ch) trojan includes IPs which are being used by Feodo (also known as Cridex or Bugat) which commits ebanking fraud - **excellent list**|ipv4 hash:ip|99 unique IPs|updated every 30 mins  from [this link](https://feodotracker.abuse.ch/blocklist/?download=ipblocklist)
[fullbogons](#fullbogons)|[Team-Cymru.org](http://www.team-cymru.org) IP space that has been allocated to an RIR, but not assigned by that RIR to an actual ISP or other end-user - **excellent list - use it only your internet interface**|ipv4 hash:net|3720 subnets, 670264216 unique IPs|updated every 1 day  from [this link](http://www.team-cymru.org/Services/Bogons/fullbogons-ipv4.txt)
[geolite2_country](https://github.com/ktsaou/blocklist-ipsets/tree/master/geolite2_country)|[MaxMind GeoLite2](http://dev.maxmind.com/geoip/geoip2/geolite2/) databases are free IP geolocation databases comparable to, but less accurate than, MaxMind’s GeoIP2 databases. They include IPs per country, IPs per continent, IPs used by anonymous services (VPNs, Proxies, etc) and Satellite Providers.|ipv4 hash:net|All the world|updated every 7 days  from [this link](http://geolite.maxmind.com/download/geoip/database/GeoLite2-Country-CSV.zip)
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|[iBlocklist.com](https://www.iblocklist.com/) free version of [BlueTack.co.uk](http://www.bluetack.co.uk/) IPs that have been reported for bad deeds in p2p|ipv4 hash:ip|47941 unique IPs|updated every 12 hours  from [this link](http://list.iblocklist.com/?list=cwworuawihqvocglcoss&fileformat=p2p&archiveformat=gz)
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|[iBlocklist.com](https://www.iblocklist.com/) free version of [BlueTack.co.uk](http://www.bluetack.co.uk/) hijacked IP-Blocks Hijacked IP space are IP blocks that are being used without permission|ipv4 hash:net|535 subnets, 9177856 unique IPs|updated every 12 hours  from [this link](http://list.iblocklist.com/?list=usrcshglbiilevmyfhse&fileformat=p2p&archiveformat=gz)
[ib_bluetack_level1](#ib_bluetack_level1)|[iBlocklist.com](https://www.iblocklist.com/) free version of [BlueTack.co.uk](http://www.bluetack.co.uk/) Level 1 (for use in p2p): Companies or organizations who are clearly involved with trying to stop filesharing (e.g. Baytsp, MediaDefender, Mediasentry a.o.). Companies which anti-p2p activity has been seen from. Companies that produce or have a strong financial interest in copyrighted material (e.g. music, movie, software industries a.o.). Government ranges or companies that have a strong financial interest in doing work for governments. Legal industry ranges. IPs or ranges of ISPs from which anti-p2p activity has been observed. Basically this list will block all kinds of internet connections that most people would rather not have during their internet travels.|ipv4 hash:net|218315 subnets, 764993617 unique IPs|updated every 12 hours  from [this link](http://list.iblocklist.com/?list=ydxerpxkpcfqjaybcssw&fileformat=p2p&archiveformat=gz)
[ib_bluetack_level2](#ib_bluetack_level2)|[iBlocklist.com](https://www.iblocklist.com/) free version of BlueTack.co.uk Level 2 (for use in p2p). General corporate ranges. Ranges used by labs or researchers. Proxies.|ipv4 hash:net|72952 subnets, 348710247 unique IPs|updated every 12 hours  from [this link](http://list.iblocklist.com/?list=gyisgnzbhppbvsphucsw&fileformat=p2p&archiveformat=gz)
badips.com categories ipsets|[BadIPs.com](https://www.badips.com) community based IP blacklisting. They score IPs based on the reports they reports.|ipv4 hash:ip|disabled|disabled
[ib_bluetack_proxies](#ib_bluetack_proxies)|[iBlocklist.com](https://www.iblocklist.com/) free version of [BlueTack.co.uk](http://www.bluetack.co.uk/) Open Proxies IPs list (without TOR)|ipv4 hash:ip|663 unique IPs|updated every 12 hours  from [this link](http://list.iblocklist.com/?list=xoebmbyexwuiogmbyprb&fileformat=p2p&archiveformat=gz)
[ib_bluetack_spyware](#ib_bluetack_spyware)|[iBlocklist.com](https://www.iblocklist.com/) free version of [BlueTack.co.uk](http://www.bluetack.co.uk/) known malicious SPYWARE and ADWARE IP Address ranges|ipv4 hash:net|3267 subnets, 339173 unique IPs|updated every 12 hours  from [this link](http://list.iblocklist.com/?list=llvtlsjyoyiczbkjsxpf&fileformat=p2p&archiveformat=gz)
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|[iBlocklist.com](https://www.iblocklist.com/) free version of [BlueTack.co.uk](http://www.bluetack.co.uk/) web server hack and exploit attempts|ipv4 hash:ip|1450 unique IPs|updated every 12 hours  from [this link](http://list.iblocklist.com/?list=ghlzqtqxnzctvvajwwag&fileformat=p2p&archiveformat=gz)
infiltrated|[infiltrated.net](http://www.infiltrated.net) (this list seems to be updated frequently, but we found no information about it)|ipv4 hash:ip|disabled|updated every 12 hours  from [this link](http://www.infiltrated.net/blacklisted)
lashback_ubl|[The LashBack UBL](http://blacklist.lashback.com/) The Unsubscribe Blacklist (UBL) is a real-time blacklist of IP addresses which are sending email to names harvested from suppression files (this is a big list, more than 500.000 IPs)|ipv4 hash:ip|disabled|updated every 1 day  from [this link](http://www.unsubscore.com/blacklist.txt)
[malc0de](#malc0de)|[Malc0de.com](http://malc0de.com) malicious IPs of the last 30 days|ipv4 hash:ip|361 unique IPs|updated every 1 day  from [this link](http://malc0de.com/bl/IP_Blacklist.txt)
[malwaredomainlist](#malwaredomainlist)|[malwaredomainlist.com](http://www.malwaredomainlist.com) list of malware active ip addresses|ipv4 hash:ip|1288 unique IPs|updated every 12 hours  from [this link](http://www.malwaredomainlist.com/hostslist/ip.txt)
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|[MaxMind.com](https://www.maxmind.com/en/anonymous-proxy-fraudulent-ip-address-list) list of anonymous proxy fraudelent IP addresses.|ipv4 hash:ip|372 unique IPs|updated every 4 hours  from [this link](https://www.maxmind.com/en/anonymous-proxy-fraudulent-ip-address-list)
[nixspam](#nixspam)|[NiX Spam](http://www.heise.de/ix/NiX-Spam-DNSBL-and-blacklist-for-download-499637.html) IP addresses that sent spam in the last hour - automatically generated entries without distinguishing open proxies from relays, dialup gateways, and so on. All IPs are removed after 12 hours if there is no spam from there.|ipv4 hash:ip|39997 unique IPs|updated every 15 mins  from [this link](http://www.dnsbl.manitu.net/download/nixspam-ip.dump.gz)
openbl|[OpenBL.org](http://www.openbl.org/) default blacklist (currently it is the same with 90 days). OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications - **excellent list**|ipv4 hash:ip|disabled|updated every 4 hours  from [this link](http://www.openbl.org/lists/base.txt)
openbl_180d|[OpenBL.org](http://www.openbl.org/) last 180 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|disabled|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_180days.txt)
[openbl_1d](#openbl_1d)|[OpenBL.org](http://www.openbl.org/) last 24 hours IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|116 unique IPs|updated every 1 hour  from [this link](http://www.openbl.org/lists/base_1days.txt)
[openbl_30d](#openbl_30d)|[OpenBL.org](http://www.openbl.org/) last 30 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|3245 unique IPs|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_30days.txt)
openbl_360d|[OpenBL.org](http://www.openbl.org/) last 360 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|disabled|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_360days.txt)
[openbl_60d](#openbl_60d)|[OpenBL.org](http://www.openbl.org/) last 60 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|7254 unique IPs|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_60days.txt)
[openbl_7d](#openbl_7d)|[OpenBL.org](http://www.openbl.org/) last 7 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|816 unique IPs|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_7days.txt)
openbl_90d|[OpenBL.org](http://www.openbl.org/) last 90 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|disabled|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_90days.txt)
openbl_all|[OpenBL.org](http://www.openbl.org/) last all IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|disabled|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_all.txt)
[palevo](#palevo)|[Abuse.ch Palevo tracker](https://palevotracker.abuse.ch) worm includes IPs which are being used as botnet C&C for the Palevo crimeware - **excellent list**|ipv4 hash:ip|13 unique IPs|updated every 30 mins  from [this link](https://palevotracker.abuse.ch/blocklists.php?download=ipblocklist)
php_bad|[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) bad web hosts (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|disabled|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=b&rss=1)
[php_commenters](#php_commenters)|[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) comment spammers (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|349 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=c&rss=1)
[php_dictionary](#php_dictionary)|[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) directory attackers (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|589 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=d&rss=1)
[php_harvesters](#php_harvesters)|[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) harvesters (IPs that surf the internet looking for email addresses) (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|324 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=h&rss=1)
[php_spammers](#php_spammers)|[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) spam servers (IPs used by spammers to send messages) (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|580 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=s&rss=1)
[proxyrss](#proxyrss)|[proxyrss.com](http://www.proxyrss.com) open proxies syndicated from multiple sources.|ipv4 hash:ip|1435 unique IPs|updated every 4 hours  from [this link](http://www.proxyrss.com/proxylists/all.gz)
[proxz](#proxz)|[proxz.com](http://www.proxz.com) open proxies (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|967 unique IPs|updated every 1 hour  from [this link](http://www.proxz.com/proxylists.xml)
[ri_connect_proxies](#ri_connect_proxies)|[rosinstrument.com](http://www.rosinstrument.com) open CONNECT proxies (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|2516 unique IPs|updated every 1 hour  from [this link](http://tools.rosinstrument.com/proxy/plab100.xml)
[ri_web_proxies](#ri_web_proxies)|[rosinstrument.com](http://www.rosinstrument.com) open HTTP proxies (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|6828 unique IPs|updated every 1 hour  from [this link](http://tools.rosinstrument.com/proxy/l100.xml)
[shunlist](#shunlist)|[AutoShun.org](http://autoshun.org/) IPs identified as hostile by correlating logs from distributed snort installations running the autoshun plugin|ipv4 hash:ip|1245 unique IPs|updated every 4 hours  from [this link](http://www.autoshun.org/files/shunlist.csv)
[snort_ipfilter](#snort_ipfilter)|[labs.snort.org](https://labs.snort.org/) supplied IP blacklist (this list seems to be updated frequently, but we found no information about it)|ipv4 hash:ip|9812 unique IPs|updated every 12 hours  from [this link](http://labs.snort.org/feeds/ip-filter.blf)
[sorbs_dul](#sorbs_dul)|[Sorbs.net](https://www.sorbs.net/) DUL, Dynamic User IPs extracted from deltas.|ipv4 hash:net|8 subnets, 3584 unique IPs|updated every 1 min  from [this link]()
[sorbs_http](#sorbs_http)|[Sorbs.net](https://www.sorbs.net/) HTTP proxies, extracted from deltas.|ipv4 hash:net|20 subnets, 20 unique IPs|updated every 1 min  from [this link]()
[sorbs_misc](#sorbs_misc)|[Sorbs.net](https://www.sorbs.net/) MISC proxies, extracted from deltas.|ipv4 hash:net|20 subnets, 20 unique IPs|updated every 1 min  from [this link]()
[sorbs_new_spam](#sorbs_new_spam)|[Sorbs.net](https://www.sorbs.net/) NEW Spam senders, extracted from deltas.|ipv4 hash:net|45326 subnets, 46326 unique IPs|updated every 1 min  from [this link]()
[sorbs_recent_spam](#sorbs_recent_spam)|[Sorbs.net](https://www.sorbs.net/) RECENT Spam senders, extracted from deltas.|ipv4 hash:net|45326 subnets, 46326 unique IPs|updated every 1 min  from [this link]()
[sorbs_smtp](#sorbs_smtp)|[Sorbs.net](https://www.sorbs.net/) SMTP Open Relays, extracted from deltas.|ipv4 hash:net|10 subnets, 10 unique IPs|updated every 1 min  from [this link]()
[sorbs_socks](#sorbs_socks)|[Sorbs.net](https://www.sorbs.net/) SOCKS proxies, extracted from deltas.|ipv4 hash:net|20 subnets, 20 unique IPs|updated every 1 min  from [this link]()
[sorbs_spam](#sorbs_spam)|[Sorbs.net](https://www.sorbs.net/) Spam senders, extracted from deltas.|ipv4 hash:net|45326 subnets, 46326 unique IPs|updated every 1 min  from [this link]()
[sorbs_web](#sorbs_web)|[Sorbs.net](https://www.sorbs.net/) WEB exploits, extracted from deltas.|ipv4 hash:net|619 subnets, 619 unique IPs|updated every 1 min  from [this link]()
[spamhaus_drop](#spamhaus_drop)|[Spamhaus.org](http://www.spamhaus.org) DROP list (according to their site this list should be dropped at tier-1 ISPs globaly) - **excellent list**|ipv4 hash:net|653 subnets, 18404096 unique IPs|updated every 12 hours  from [this link](http://www.spamhaus.org/drop/drop.txt)
[spamhaus_edrop](#spamhaus_edrop)|[Spamhaus.org](http://www.spamhaus.org) EDROP (extended matches that should be used with DROP) - **excellent list**|ipv4 hash:net|56 subnets, 487424 unique IPs|updated every 12 hours  from [this link](http://www.spamhaus.org/drop/edrop.txt)
[sslbl](#sslbl)|[Abuse.ch SSL Blacklist](https://sslbl.abuse.ch/) bad SSL traffic related to malware or botnet activities - **excellent list**|ipv4 hash:ip|372 unique IPs|updated every 30 mins  from [this link](https://sslbl.abuse.ch/blacklist/sslipblacklist.csv)
stopforumspam_180d|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 180 days)|ipv4 hash:ip|disabled|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/listed_ip_180.zip)
[stopforumspam_1d](#stopforumspam_1d)|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers in the last 24 hours - **excellent list**|ipv4 hash:ip|6093 unique IPs|updated every 1 hour  from [this link](http://www.stopforumspam.com/downloads/listed_ip_1.zip)
[stopforumspam_30d](#stopforumspam_30d)|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 30 days)|ipv4 hash:ip|93068 unique IPs|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/listed_ip_30.zip)
stopforumspam_365d|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 365 days)|ipv4 hash:ip|disabled|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/listed_ip_365.zip)
[stopforumspam_7d](#stopforumspam_7d)|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 7 days)|ipv4 hash:ip|29870 unique IPs|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/listed_ip_7.zip)
stopforumspam_90d|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 90 days)|ipv4 hash:ip|disabled|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/listed_ip_90.zip)
stopforumspam_ever|[StopForumSpam.com](http://www.stopforumspam.com) all IPs used by forum spammers, **ever** (normally you don't want to use this ipset, use the hourly one which includes last 24 hours IPs or the 7 days one)|ipv4 hash:ip|disabled|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/bannedips.zip)
[virbl](#virbl)|[VirBL](http://virbl.bit.nl/) is a project of which the idea was born during the RIPE-48 meeting. The plan was to get reports of virusscanning mailservers, and put the IP-addresses that were reported to send viruses on a blacklist.|ipv4 hash:ip|3 unique IPs|updated every 1 hour  from [this link](http://virbl.bit.nl/download/virbl.dnsbl.bit.nl.txt)
[voipbl](#voipbl)|[VoIPBL.org](http://www.voipbl.org/) a distributed VoIP blacklist that is aimed to protects against VoIP Fraud and minimizing abuse for network that have publicly accessible PBX's. Several algorithms, external sources and manual confirmation are used before they categorize something as an attack and determine the threat level.|ipv4 hash:net|10476 subnets, 10888 unique IPs|updated every 4 hours  from [this link](http://www.voipbl.org/update/)
[xroxy](#xroxy)|[xroxy.com](http://www.xroxy.com) open proxies (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|2115 unique IPs|updated every 1 hour  from [this link](http://www.xroxy.com/proxyrss.xml)
[zeus](#zeus)|[Abuse.ch Zeus tracker](https://zeustracker.abuse.ch) standard, contains the same data as the ZeuS IP blocklist (zeus_badips) but with the slight difference that it doesn't exclude hijacked websites (level 2) and free web hosting providers (level 3). This means that this blocklist contains all IPv4 addresses associated with ZeuS C&Cs which are currently being tracked by ZeuS Tracker. Hence this blocklist will likely cause some false positives. - **excellent list**|ipv4 hash:ip|232 unique IPs|updated every 30 mins  from [this link](https://zeustracker.abuse.ch/blocklist.php?download=ipblocklist)
[zeus_badips](#zeus_badips)|[Abuse.ch Zeus tracker](https://zeustracker.abuse.ch) badips includes IPv4 addresses that are used by the ZeuS trojan. It is the recommened blocklist if you want to block only ZeuS IPs. It excludes IP addresses that ZeuS Tracker believes to be hijacked (level 2) or belong to a free web hosting provider (level 3). Hence the false postive rate should be much lower compared to the standard ZeuS IP blocklist. **excellent list**|ipv4 hash:ip|203 unique IPs|updated every 30 mins  from [this link](https://zeustracker.abuse.ch/blocklist.php?download=badips)

# Comparison of ipsets

Below we compare each ipset against all other.


## alienvault_reputation

[AlienVault.com](https://www.alienvault.com/) IP reputation database (this list seems to include port scanning hosts and to be updated regularly, but we found no information about its retention policy)

Source is downloaded from [this link](https://reputation.alienvault.com/reputation.generic).

The last time downloaded was found to be dated: Sun Jun  7 10:00:32 UTC 2015.

The ipset `alienvault_reputation` has **178903** entries, **178903** unique IPs.

The following table shows the overlaps of `alienvault_reputation` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `alienvault_reputation`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `alienvault_reputation`.
- ` this % ` is the percentage **of this ipset (`alienvault_reputation`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|17813|139104928|13886|0.0%|7.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72952|348710247|7285|0.0%|4.0%|
[openbl_60d](#openbl_60d)|7254|7254|7231|99.6%|4.0%|
[et_block](#et_block)|1023|18338662|5280|0.0%|2.9%|
[dshield](#dshield)|20|5120|4608|90.0%|2.5%|
[openbl_30d](#openbl_30d)|3245|3245|3227|99.4%|1.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218315|764993617|3070|0.0%|1.7%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|1631|0.0%|0.9%|
[et_compromised](#et_compromised)|2016|2016|1315|65.2%|0.7%|
[shunlist](#shunlist)|1245|1245|1241|99.6%|0.6%|
[blocklist_de](#blocklist_de)|27586|27586|1167|4.2%|0.6%|
[bruteforceblocker](#bruteforceblocker)|1720|1720|1099|63.8%|0.6%|
[blocklist_de_ssh](#blocklist_de_ssh)|2572|2572|932|36.2%|0.5%|
[openbl_7d](#openbl_7d)|816|816|808|99.0%|0.4%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|518|0.0%|0.2%|
[ciarmy](#ciarmy)|425|425|421|99.0%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|287|0.0%|0.1%|
[voipbl](#voipbl)|10476|10888|206|1.8%|0.1%|
[stopforumspam_30d](#stopforumspam_30d)|93068|93068|205|0.2%|0.1%|
[blocklist_de_apache](#blocklist_de_apache)|15388|15388|131|0.8%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9812|9812|118|1.2%|0.0%|
[openbl_1d](#openbl_1d)|116|116|113|97.4%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29870|29870|95|0.3%|0.0%|
[sorbs_spam](#sorbs_spam)|45326|46326|92|0.1%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|45326|46326|92|0.1%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|45326|46326|92|0.1%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|17025|17025|68|0.3%|0.0%|
[sslbl](#sslbl)|372|372|64|17.2%|0.0%|
[zeus](#zeus)|232|232|61|26.2%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6093|6093|51|0.8%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2180|2180|50|2.2%|0.0%|
[et_tor](#et_tor)|6470|6470|40|0.6%|0.0%|
[dm_tor](#dm_tor)|6516|6516|40|0.6%|0.0%|
[bm_tor](#bm_tor)|6522|6522|40|0.6%|0.0%|
[zeus_badips](#zeus_badips)|203|203|38|18.7%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|165|165|36|21.8%|0.0%|
[nixspam](#nixspam)|39997|39997|30|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|2976|2976|27|0.9%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|26|6.9%|0.0%|
[php_commenters](#php_commenters)|349|349|18|5.1%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4042|4042|18|0.4%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|86|86|16|18.6%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|15|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47941|47941|15|0.0%|0.0%|
[malc0de](#malc0de)|361|361|11|3.0%|0.0%|
[php_harvesters](#php_harvesters)|324|324|10|3.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|9|0.6%|0.0%|
[php_dictionary](#php_dictionary)|589|589|8|1.3%|0.0%|
[php_spammers](#php_spammers)|580|580|6|1.0%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|6|0.4%|0.0%|
[xroxy](#xroxy)|2115|2115|4|0.1%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|310|310|4|1.2%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|635|635|4|0.6%|0.0%|
[ri_web_proxies](#ri_web_proxies)|6972|6828|3|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2665|2516|3|0.1%|0.0%|
[proxz](#proxz)|967|967|3|0.3%|0.0%|
[feodo](#feodo)|99|99|2|2.0%|0.0%|
[sorbs_web](#sorbs_web)|619|619|1|0.1%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|1|0.1%|0.0%|

## blocklist_de

[Blocklist.de](https://www.blocklist.de/) IPs that have been detected by fail2ban in the last 48 hours - **excellent list**

Source is downloaded from [this link](http://lists.blocklist.de/lists/all.txt).

The last time downloaded was found to be dated: Sun Jun  7 12:28:03 UTC 2015.

The ipset `blocklist_de` has **27586** entries, **27586** unique IPs.

The following table shows the overlaps of `blocklist_de` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de`.
- ` this % ` is the percentage **of this ipset (`blocklist_de`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de_mail](#blocklist_de_mail)|17025|17025|17025|100.0%|61.7%|
[blocklist_de_apache](#blocklist_de_apache)|15388|15388|15388|100.0%|55.7%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4042|4042|4042|100.0%|14.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|17813|139104928|3629|0.0%|13.1%|
[blocklist_de_bots](#blocklist_de_bots)|2976|2976|2976|100.0%|10.7%|
[blocklist_de_ssh](#blocklist_de_ssh)|2572|2572|2572|100.0%|9.3%|
[stopforumspam_30d](#stopforumspam_30d)|93068|93068|2283|2.4%|8.2%|
[blocklist_de_imap](#blocklist_de_imap)|2180|2180|2180|100.0%|7.9%|
[stopforumspam_7d](#stopforumspam_7d)|29870|29870|1959|6.5%|7.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|218315|764993617|1499|0.0%|5.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|72952|348710247|1430|0.0%|5.1%|
[stopforumspam_1d](#stopforumspam_1d)|6093|6093|1230|20.1%|4.4%|
[alienvault_reputation](#alienvault_reputation)|178903|178903|1167|0.6%|4.2%|
[sorbs_spam](#sorbs_spam)|45326|46326|1087|2.3%|3.9%|
[sorbs_recent_spam](#sorbs_recent_spam)|45326|46326|1087|2.3%|3.9%|
[sorbs_new_spam](#sorbs_new_spam)|45326|46326|1087|2.3%|3.9%|
[openbl_60d](#openbl_60d)|7254|7254|884|12.1%|3.2%|
[openbl_30d](#openbl_30d)|3245|3245|710|21.8%|2.5%|
[blocklist_de_ftp](#blocklist_de_ftp)|635|635|635|100.0%|2.3%|
[nixspam](#nixspam)|39997|39997|577|1.4%|2.0%|
[et_compromised](#et_compromised)|2016|2016|574|28.4%|2.0%|
[bruteforceblocker](#bruteforceblocker)|1720|1720|563|32.7%|2.0%|
[openbl_7d](#openbl_7d)|816|816|411|50.3%|1.4%|
[ri_web_proxies](#ri_web_proxies)|6972|6828|364|5.3%|1.3%|
[shunlist](#shunlist)|1245|1245|358|28.7%|1.2%|
[xroxy](#xroxy)|2115|2115|207|9.7%|0.7%|
[proxyrss](#proxyrss)|1435|1435|195|13.5%|0.7%|
[et_block](#et_block)|1023|18338662|180|0.0%|0.6%|
[blocklist_de_strongips](#blocklist_de_strongips)|165|165|165|100.0%|0.5%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|163|0.0%|0.5%|
[proxz](#proxz)|967|967|146|15.0%|0.5%|
[snort_ipfilter](#snort_ipfilter)|9812|9812|132|1.3%|0.4%|
[dshield](#dshield)|20|5120|108|2.1%|0.3%|
[php_spammers](#php_spammers)|580|580|86|14.8%|0.3%|
[openbl_1d](#openbl_1d)|116|116|86|74.1%|0.3%|
[php_dictionary](#php_dictionary)|589|589|85|14.4%|0.3%|
[php_commenters](#php_commenters)|349|349|84|24.0%|0.3%|
[sorbs_web](#sorbs_web)|619|619|68|10.9%|0.2%|
[blocklist_de_sip](#blocklist_de_sip)|86|86|67|77.9%|0.2%|
[ri_connect_proxies](#ri_connect_proxies)|2665|2516|64|2.5%|0.2%|
[ciarmy](#ciarmy)|425|425|38|8.9%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|34|0.0%|0.1%|
[voipbl](#voipbl)|10476|10888|30|0.2%|0.1%|
[php_harvesters](#php_harvesters)|324|324|29|8.9%|0.1%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47941|47941|12|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|8|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|4|0.0%|0.0%|
[sorbs_socks](#sorbs_socks)|20|20|4|20.0%|0.0%|
[sorbs_misc](#sorbs_misc)|20|20|4|20.0%|0.0%|
[sorbs_http](#sorbs_http)|20|20|4|20.0%|0.0%|
[et_tor](#et_tor)|6470|6470|4|0.0%|0.0%|
[dm_tor](#dm_tor)|6516|6516|3|0.0%|0.0%|
[bm_tor](#bm_tor)|6522|6522|3|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|2|0.1%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|2|0.3%|0.0%|
[zeus_badips](#zeus_badips)|203|203|1|0.4%|0.0%|
[zeus](#zeus)|232|232|1|0.4%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|

## blocklist_de_apache

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service Apache, Apache-DDOS, RFI-Attacks.

Source is downloaded from [this link](http://lists.blocklist.de/lists/apache.txt).

The last time downloaded was found to be dated: Sun Jun  7 12:28:06 UTC 2015.

The ipset `blocklist_de_apache` has **15388** entries, **15388** unique IPs.

The following table shows the overlaps of `blocklist_de_apache` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_apache`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_apache`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_apache`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|27586|27586|15388|55.7%|100.0%|
[blocklist_de_mail](#blocklist_de_mail)|17025|17025|11059|64.9%|71.8%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4042|4042|4042|100.0%|26.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|17813|139104928|2403|0.0%|15.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218315|764993617|1310|0.0%|8.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72952|348710247|1087|0.0%|7.0%|
[stopforumspam_30d](#stopforumspam_30d)|93068|93068|207|0.2%|1.3%|
[alienvault_reputation](#alienvault_reputation)|178903|178903|131|0.0%|0.8%|
[stopforumspam_7d](#stopforumspam_7d)|29870|29870|123|0.4%|0.7%|
[sorbs_spam](#sorbs_spam)|45326|46326|81|0.1%|0.5%|
[sorbs_recent_spam](#sorbs_recent_spam)|45326|46326|81|0.1%|0.5%|
[sorbs_new_spam](#sorbs_new_spam)|45326|46326|81|0.1%|0.5%|
[stopforumspam_1d](#stopforumspam_1d)|6093|6093|51|0.8%|0.3%|
[shunlist](#shunlist)|1245|1245|35|2.8%|0.2%|
[ciarmy](#ciarmy)|425|425|34|8.0%|0.2%|
[blocklist_de_strongips](#blocklist_de_strongips)|165|165|32|19.3%|0.2%|
[php_commenters](#php_commenters)|349|349|26|7.4%|0.1%|
[nixspam](#nixspam)|39997|39997|22|0.0%|0.1%|
[blocklist_de_bots](#blocklist_de_bots)|2976|2976|22|0.7%|0.1%|
[et_block](#et_block)|1023|18338662|13|0.0%|0.0%|
[openbl_60d](#openbl_60d)|7254|7254|8|0.1%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9812|9812|7|0.0%|0.0%|
[sorbs_web](#sorbs_web)|619|619|6|0.9%|0.0%|
[php_spammers](#php_spammers)|580|580|6|1.0%|0.0%|
[openbl_30d](#openbl_30d)|3245|3245|6|0.1%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47941|47941|6|0.0%|0.0%|
[dshield](#dshield)|20|5120|5|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|4|0.0%|0.0%|
[et_tor](#et_tor)|6470|6470|4|0.0%|0.0%|
[voipbl](#voipbl)|10476|10888|3|0.0%|0.0%|
[php_harvesters](#php_harvesters)|324|324|3|0.9%|0.0%|
[php_dictionary](#php_dictionary)|589|589|3|0.5%|0.0%|
[dm_tor](#dm_tor)|6516|6516|3|0.0%|0.0%|
[bm_tor](#bm_tor)|6522|6522|3|0.0%|0.0%|
[xroxy](#xroxy)|2115|2115|2|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|6972|6828|2|0.0%|0.0%|
[proxz](#proxz)|967|967|2|0.2%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|2|0.0%|0.0%|
[et_compromised](#et_compromised)|2016|2016|2|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1720|1720|2|0.1%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|1|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2665|2516|1|0.0%|0.0%|
[proxyrss](#proxyrss)|1435|1435|1|0.0%|0.0%|
[openbl_7d](#openbl_7d)|816|816|1|0.1%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|1|0.1%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.0%|

## blocklist_de_bots

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the RFI-Attacks, REG-Bots, IRC-Bots or BadBots (BadBots = he has posted a Spam-Comment on a open Forum or Wiki).

Source is downloaded from [this link](http://lists.blocklist.de/lists/bots.txt).

The last time downloaded was found to be dated: Sun Jun  7 12:28:09 UTC 2015.

The ipset `blocklist_de_bots` has **2976** entries, **2976** unique IPs.

The following table shows the overlaps of `blocklist_de_bots` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_bots`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_bots`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_bots`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|27586|27586|2976|10.7%|100.0%|
[stopforumspam_30d](#stopforumspam_30d)|93068|93068|1969|2.1%|66.1%|
[stopforumspam_7d](#stopforumspam_7d)|29870|29870|1792|5.9%|60.2%|
[stopforumspam_1d](#stopforumspam_1d)|6093|6093|1180|19.3%|39.6%|
[ri_web_proxies](#ri_web_proxies)|6972|6828|304|4.4%|10.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|17813|139104928|199|0.0%|6.6%|
[proxyrss](#proxyrss)|1435|1435|192|13.3%|6.4%|
[xroxy](#xroxy)|2115|2115|164|7.7%|5.5%|
[blocklist_de_strongips](#blocklist_de_strongips)|165|165|123|74.5%|4.1%|
[proxz](#proxz)|967|967|120|12.4%|4.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72952|348710247|109|0.0%|3.6%|
[php_commenters](#php_commenters)|349|349|66|18.9%|2.2%|
[ri_connect_proxies](#ri_connect_proxies)|2665|2516|61|2.4%|2.0%|
[sorbs_spam](#sorbs_spam)|45326|46326|50|0.1%|1.6%|
[sorbs_recent_spam](#sorbs_recent_spam)|45326|46326|50|0.1%|1.6%|
[sorbs_new_spam](#sorbs_new_spam)|45326|46326|50|0.1%|1.6%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|29|0.0%|0.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|218315|764993617|29|0.0%|0.9%|
[et_block](#et_block)|1023|18338662|29|0.0%|0.9%|
[alienvault_reputation](#alienvault_reputation)|178903|178903|27|0.0%|0.9%|
[nixspam](#nixspam)|39997|39997|26|0.0%|0.8%|
[php_dictionary](#php_dictionary)|589|589|24|4.0%|0.8%|
[snort_ipfilter](#snort_ipfilter)|9812|9812|23|0.2%|0.7%|
[php_spammers](#php_spammers)|580|580|23|3.9%|0.7%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|23|0.0%|0.7%|
[php_harvesters](#php_harvesters)|324|324|22|6.7%|0.7%|
[blocklist_de_mail](#blocklist_de_mail)|17025|17025|22|0.1%|0.7%|
[blocklist_de_apache](#blocklist_de_apache)|15388|15388|22|0.1%|0.7%|
[openbl_60d](#openbl_60d)|7254|7254|11|0.1%|0.3%|
[sorbs_web](#sorbs_web)|619|619|10|1.6%|0.3%|
[voipbl](#voipbl)|10476|10888|3|0.0%|0.1%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|2|0.0%|0.0%|
[openbl_30d](#openbl_30d)|3245|3245|2|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|2|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|1|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|1|0.1%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47941|47941|1|0.0%|0.0%|

## blocklist_de_bruteforce

[Blocklist.de](https://www.blocklist.de/) All IPs which attacks Joomlas, Wordpress and other Web-Logins with Brute-Force Logins.

Source is downloaded from [this link](http://lists.blocklist.de/lists/bruteforcelogin.txt).

The last time downloaded was found to be dated: Sun Jun  7 12:28:10 UTC 2015.

The ipset `blocklist_de_bruteforce` has **4042** entries, **4042** unique IPs.

The following table shows the overlaps of `blocklist_de_bruteforce` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_bruteforce`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_bruteforce`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_bruteforce`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de_apache](#blocklist_de_apache)|15388|15388|4042|26.2%|100.0%|
[blocklist_de](#blocklist_de)|27586|27586|4042|14.6%|100.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17813|139104928|303|0.0%|7.4%|
[sorbs_spam](#sorbs_spam)|45326|46326|81|0.1%|2.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|45326|46326|81|0.1%|2.0%|
[sorbs_new_spam](#sorbs_new_spam)|45326|46326|81|0.1%|2.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72952|348710247|54|0.0%|1.3%|
[stopforumspam_30d](#stopforumspam_30d)|93068|93068|53|0.0%|1.3%|
[stopforumspam_7d](#stopforumspam_7d)|29870|29870|33|0.1%|0.8%|
[nixspam](#nixspam)|39997|39997|22|0.0%|0.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218315|764993617|21|0.0%|0.5%|
[alienvault_reputation](#alienvault_reputation)|178903|178903|18|0.0%|0.4%|
[stopforumspam_1d](#stopforumspam_1d)|6093|6093|14|0.2%|0.3%|
[php_commenters](#php_commenters)|349|349|8|2.2%|0.1%|
[blocklist_de_strongips](#blocklist_de_strongips)|165|165|7|4.2%|0.1%|
[sorbs_web](#sorbs_web)|619|619|6|0.9%|0.1%|
[php_spammers](#php_spammers)|580|580|6|1.0%|0.1%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47941|47941|5|0.0%|0.1%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|4|0.0%|0.0%|
[et_block](#et_block)|1023|18338662|4|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9812|9812|3|0.0%|0.0%|
[php_dictionary](#php_dictionary)|589|589|3|0.5%|0.0%|
[php_harvesters](#php_harvesters)|324|324|2|0.6%|0.0%|
[xroxy](#xroxy)|2115|2115|1|0.0%|0.0%|
[voipbl](#voipbl)|10476|10888|1|0.0%|0.0%|
[shunlist](#shunlist)|1245|1245|1|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|6972|6828|1|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2665|2516|1|0.0%|0.0%|
[proxz](#proxz)|967|967|1|0.1%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.0%|
[ciarmy](#ciarmy)|425|425|1|0.2%|0.0%|

## blocklist_de_ftp

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours for attacks on the Service FTP.

Source is downloaded from [this link](http://lists.blocklist.de/lists/ftp.txt).

The last time downloaded was found to be dated: Sun Jun  7 12:28:07 UTC 2015.

The ipset `blocklist_de_ftp` has **635** entries, **635** unique IPs.

The following table shows the overlaps of `blocklist_de_ftp` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_ftp`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_ftp`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_ftp`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|27586|27586|635|2.3%|100.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17813|139104928|49|0.0%|7.7%|
[nixspam](#nixspam)|39997|39997|12|0.0%|1.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72952|348710247|12|0.0%|1.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218315|764993617|12|0.0%|1.8%|
[stopforumspam_30d](#stopforumspam_30d)|93068|93068|10|0.0%|1.5%|
[sorbs_spam](#sorbs_spam)|45326|46326|6|0.0%|0.9%|
[sorbs_recent_spam](#sorbs_recent_spam)|45326|46326|6|0.0%|0.9%|
[sorbs_new_spam](#sorbs_new_spam)|45326|46326|6|0.0%|0.9%|
[stopforumspam_7d](#stopforumspam_7d)|29870|29870|4|0.0%|0.6%|
[php_harvesters](#php_harvesters)|324|324|4|1.2%|0.6%|
[alienvault_reputation](#alienvault_reputation)|178903|178903|4|0.0%|0.6%|
[blocklist_de_strongips](#blocklist_de_strongips)|165|165|2|1.2%|0.3%|
[snort_ipfilter](#snort_ipfilter)|9812|9812|1|0.0%|0.1%|
[php_spammers](#php_spammers)|580|580|1|0.1%|0.1%|
[php_dictionary](#php_dictionary)|589|589|1|0.1%|0.1%|

## blocklist_de_imap

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours for attacks on the Service imap, sasl, pop3, etc.

Source is downloaded from [this link](http://lists.blocklist.de/lists/imap.txt).

The last time downloaded was found to be dated: Sun Jun  7 12:28:06 UTC 2015.

The ipset `blocklist_de_imap` has **2180** entries, **2180** unique IPs.

The following table shows the overlaps of `blocklist_de_imap` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_imap`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_imap`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_imap`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de_mail](#blocklist_de_mail)|17025|17025|2180|12.8%|100.0%|
[blocklist_de](#blocklist_de)|27586|27586|2180|7.9%|100.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17813|139104928|205|0.0%|9.4%|
[alienvault_reputation](#alienvault_reputation)|178903|178903|50|0.0%|2.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72952|348710247|48|0.0%|2.2%|
[openbl_60d](#openbl_60d)|7254|7254|41|0.5%|1.8%|
[sorbs_spam](#sorbs_spam)|45326|46326|36|0.0%|1.6%|
[sorbs_recent_spam](#sorbs_recent_spam)|45326|46326|36|0.0%|1.6%|
[sorbs_new_spam](#sorbs_new_spam)|45326|46326|36|0.0%|1.6%|
[openbl_30d](#openbl_30d)|3245|3245|36|1.1%|1.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218315|764993617|28|0.0%|1.2%|
[nixspam](#nixspam)|39997|39997|26|0.0%|1.1%|
[et_block](#et_block)|1023|18338662|15|0.0%|0.6%|
[stopforumspam_30d](#stopforumspam_30d)|93068|93068|14|0.0%|0.6%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|14|0.0%|0.6%|
[openbl_7d](#openbl_7d)|816|816|13|1.5%|0.5%|
[et_compromised](#et_compromised)|2016|2016|13|0.6%|0.5%|
[bruteforceblocker](#bruteforceblocker)|1720|1720|12|0.6%|0.5%|
[ri_web_proxies](#ri_web_proxies)|6972|6828|9|0.1%|0.4%|
[stopforumspam_7d](#stopforumspam_7d)|29870|29870|8|0.0%|0.3%|
[snort_ipfilter](#snort_ipfilter)|9812|9812|8|0.0%|0.3%|
[shunlist](#shunlist)|1245|1245|3|0.2%|0.1%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47941|47941|3|0.0%|0.1%|
[php_dictionary](#php_dictionary)|589|589|2|0.3%|0.0%|
[openbl_1d](#openbl_1d)|116|116|2|1.7%|0.0%|
[zeus_badips](#zeus_badips)|203|203|1|0.4%|0.0%|
[zeus](#zeus)|232|232|1|0.4%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6093|6093|1|0.0%|0.0%|
[php_spammers](#php_spammers)|580|580|1|0.1%|0.0%|
[php_commenters](#php_commenters)|349|349|1|0.2%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.0%|
[dshield](#dshield)|20|5120|1|0.0%|0.0%|
[ciarmy](#ciarmy)|425|425|1|0.2%|0.0%|

## blocklist_de_mail

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service Mail, Postfix.

Source is downloaded from [this link](http://lists.blocklist.de/lists/mail.txt).

The last time downloaded was found to be dated: Sun Jun  7 12:28:05 UTC 2015.

The ipset `blocklist_de_mail` has **17025** entries, **17025** unique IPs.

The following table shows the overlaps of `blocklist_de_mail` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_mail`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_mail`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_mail`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|27586|27586|17025|61.7%|100.0%|
[blocklist_de_apache](#blocklist_de_apache)|15388|15388|11059|71.8%|64.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17813|139104928|2620|0.0%|15.3%|
[blocklist_de_imap](#blocklist_de_imap)|2180|2180|2180|100.0%|12.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218315|764993617|1379|0.0%|8.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72952|348710247|1147|0.0%|6.7%|
[sorbs_spam](#sorbs_spam)|45326|46326|943|2.0%|5.5%|
[sorbs_recent_spam](#sorbs_recent_spam)|45326|46326|943|2.0%|5.5%|
[sorbs_new_spam](#sorbs_new_spam)|45326|46326|943|2.0%|5.5%|
[nixspam](#nixspam)|39997|39997|508|1.2%|2.9%|
[stopforumspam_30d](#stopforumspam_30d)|93068|93068|246|0.2%|1.4%|
[stopforumspam_7d](#stopforumspam_7d)|29870|29870|134|0.4%|0.7%|
[snort_ipfilter](#snort_ipfilter)|9812|9812|103|1.0%|0.6%|
[alienvault_reputation](#alienvault_reputation)|178903|178903|68|0.0%|0.3%|
[ri_web_proxies](#ri_web_proxies)|6972|6828|58|0.8%|0.3%|
[php_dictionary](#php_dictionary)|589|589|57|9.6%|0.3%|
[php_spammers](#php_spammers)|580|580|55|9.4%|0.3%|
[sorbs_web](#sorbs_web)|619|619|52|8.4%|0.3%|
[stopforumspam_1d](#stopforumspam_1d)|6093|6093|50|0.8%|0.2%|
[openbl_60d](#openbl_60d)|7254|7254|48|0.6%|0.2%|
[openbl_30d](#openbl_30d)|3245|3245|42|1.2%|0.2%|
[xroxy](#xroxy)|2115|2115|41|1.9%|0.2%|
[proxz](#proxz)|967|967|24|2.4%|0.1%|
[php_commenters](#php_commenters)|349|349|23|6.5%|0.1%|
[et_block](#et_block)|1023|18338662|23|0.0%|0.1%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|22|0.0%|0.1%|
[blocklist_de_strongips](#blocklist_de_strongips)|165|165|22|13.3%|0.1%|
[blocklist_de_bots](#blocklist_de_bots)|2976|2976|22|0.7%|0.1%|
[openbl_7d](#openbl_7d)|816|816|15|1.8%|0.0%|
[et_compromised](#et_compromised)|2016|2016|15|0.7%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1720|1720|14|0.8%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|5|0.0%|0.0%|
[sorbs_socks](#sorbs_socks)|20|20|4|20.0%|0.0%|
[sorbs_misc](#sorbs_misc)|20|20|4|20.0%|0.0%|
[sorbs_http](#sorbs_http)|20|20|4|20.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47941|47941|4|0.0%|0.0%|
[et_tor](#et_tor)|6470|6470|4|0.0%|0.0%|
[shunlist](#shunlist)|1245|1245|3|0.2%|0.0%|
[openbl_1d](#openbl_1d)|116|116|3|2.5%|0.0%|
[dm_tor](#dm_tor)|6516|6516|3|0.0%|0.0%|
[bm_tor](#bm_tor)|6522|6522|3|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2665|2516|2|0.0%|0.0%|
[proxyrss](#proxyrss)|1435|1435|2|0.1%|0.0%|
[php_harvesters](#php_harvesters)|324|324|2|0.6%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|2|0.0%|0.0%|
[zeus_badips](#zeus_badips)|203|203|1|0.4%|0.0%|
[zeus](#zeus)|232|232|1|0.4%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[dshield](#dshield)|20|5120|1|0.0%|0.0%|
[ciarmy](#ciarmy)|425|425|1|0.2%|0.0%|

## blocklist_de_sip

[Blocklist.de](https://www.blocklist.de/) All IP addresses that tried to login in a SIP, VOIP or Asterisk Server and are included in the IPs list from [infiltrated.net](www.infiltrated.net)

Source is downloaded from [this link](http://lists.blocklist.de/lists/sip.txt).

The last time downloaded was found to be dated: Sun Jun  7 12:28:07 UTC 2015.

The ipset `blocklist_de_sip` has **86** entries, **86** unique IPs.

The following table shows the overlaps of `blocklist_de_sip` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_sip`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_sip`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_sip`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|27586|27586|67|0.2%|77.9%|
[voipbl](#voipbl)|10476|10888|24|0.2%|27.9%|
[alienvault_reputation](#alienvault_reputation)|178903|178903|16|0.0%|18.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|17813|139104928|11|0.0%|12.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72952|348710247|5|0.0%|5.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218315|764993617|4|0.0%|4.6%|
[et_block](#et_block)|1023|18338662|3|0.0%|3.4%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|2|0.0%|2.3%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|1|0.0%|1.1%|

## blocklist_de_ssh

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service SSH.

Source is downloaded from [this link](http://lists.blocklist.de/lists/ssh.txt).

The last time downloaded was found to be dated: Sun Jun  7 12:28:03 UTC 2015.

The ipset `blocklist_de_ssh` has **2572** entries, **2572** unique IPs.

The following table shows the overlaps of `blocklist_de_ssh` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_ssh`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_ssh`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_ssh`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|27586|27586|2572|9.3%|100.0%|
[alienvault_reputation](#alienvault_reputation)|178903|178903|932|0.5%|36.2%|
[openbl_60d](#openbl_60d)|7254|7254|816|11.2%|31.7%|
[openbl_30d](#openbl_30d)|3245|3245|659|20.3%|25.6%|
[et_compromised](#et_compromised)|2016|2016|556|27.5%|21.6%|
[bruteforceblocker](#bruteforceblocker)|1720|1720|546|31.7%|21.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|17813|139104928|422|0.0%|16.4%|
[openbl_7d](#openbl_7d)|816|816|394|48.2%|15.3%|
[shunlist](#shunlist)|1245|1245|320|25.7%|12.4%|
[et_block](#et_block)|1023|18338662|112|0.0%|4.3%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|107|0.0%|4.1%|
[dshield](#dshield)|20|5120|102|1.9%|3.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72952|348710247|97|0.0%|3.7%|
[openbl_1d](#openbl_1d)|116|116|83|71.5%|3.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|218315|764993617|53|0.0%|2.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|165|165|28|16.9%|1.0%|
[stopforumspam_30d](#stopforumspam_30d)|93068|93068|8|0.0%|0.3%|
[sorbs_spam](#sorbs_spam)|45326|46326|6|0.0%|0.2%|
[sorbs_recent_spam](#sorbs_recent_spam)|45326|46326|6|0.0%|0.2%|
[sorbs_new_spam](#sorbs_new_spam)|45326|46326|6|0.0%|0.2%|
[nixspam](#nixspam)|39997|39997|6|0.0%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|5|0.0%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|3|0.0%|0.1%|
[ciarmy](#ciarmy)|425|425|3|0.7%|0.1%|
[stopforumspam_7d](#stopforumspam_7d)|29870|29870|2|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9812|9812|2|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|1|0.0%|0.0%|
[php_spammers](#php_spammers)|580|580|1|0.1%|0.0%|
[php_commenters](#php_commenters)|349|349|1|0.2%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|1|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47941|47941|1|0.0%|0.0%|

## blocklist_de_strongips

[Blocklist.de](https://www.blocklist.de/) All IPs which are older then 2 month and have more then 5.000 attacks.

Source is downloaded from [this link](http://lists.blocklist.de/lists/strongips.txt).

The last time downloaded was found to be dated: Sun Jun  7 12:28:10 UTC 2015.

The ipset `blocklist_de_strongips` has **165** entries, **165** unique IPs.

The following table shows the overlaps of `blocklist_de_strongips` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_strongips`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_strongips`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_strongips`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|27586|27586|165|0.5%|100.0%|
[stopforumspam_30d](#stopforumspam_30d)|93068|93068|125|0.1%|75.7%|
[blocklist_de_bots](#blocklist_de_bots)|2976|2976|123|4.1%|74.5%|
[stopforumspam_7d](#stopforumspam_7d)|29870|29870|114|0.3%|69.0%|
[stopforumspam_1d](#stopforumspam_1d)|6093|6093|89|1.4%|53.9%|
[alienvault_reputation](#alienvault_reputation)|178903|178903|36|0.0%|21.8%|
[php_commenters](#php_commenters)|349|349|35|10.0%|21.2%|
[blocklist_de_apache](#blocklist_de_apache)|15388|15388|32|0.2%|19.3%|
[blocklist_de_ssh](#blocklist_de_ssh)|2572|2572|28|1.0%|16.9%|
[openbl_60d](#openbl_60d)|7254|7254|26|0.3%|15.7%|
[openbl_7d](#openbl_7d)|816|816|24|2.9%|14.5%|
[openbl_30d](#openbl_30d)|3245|3245|24|0.7%|14.5%|
[blocklist_de_mail](#blocklist_de_mail)|17025|17025|22|0.1%|13.3%|
[shunlist](#shunlist)|1245|1245|20|1.6%|12.1%|
[openbl_1d](#openbl_1d)|116|116|19|16.3%|11.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17813|139104928|15|0.0%|9.0%|
[xroxy](#xroxy)|2115|2115|7|0.3%|4.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72952|348710247|7|0.0%|4.2%|
[et_block](#et_block)|1023|18338662|7|0.0%|4.2%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4042|4042|7|0.1%|4.2%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|6|0.0%|3.6%|
[ri_web_proxies](#ri_web_proxies)|6972|6828|5|0.0%|3.0%|
[php_spammers](#php_spammers)|580|580|5|0.8%|3.0%|
[proxz](#proxz)|967|967|4|0.4%|2.4%|
[proxyrss](#proxyrss)|1435|1435|3|0.2%|1.8%|
[php_harvesters](#php_harvesters)|324|324|3|0.9%|1.8%|
[php_dictionary](#php_dictionary)|589|589|3|0.5%|1.8%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|1.8%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|2|0.0%|1.2%|
[blocklist_de_ftp](#blocklist_de_ftp)|635|635|2|0.3%|1.2%|
[sorbs_web](#sorbs_web)|619|619|1|0.1%|0.6%|
[sorbs_spam](#sorbs_spam)|45326|46326|1|0.0%|0.6%|
[sorbs_recent_spam](#sorbs_recent_spam)|45326|46326|1|0.0%|0.6%|
[sorbs_new_spam](#sorbs_new_spam)|45326|46326|1|0.0%|0.6%|
[snort_ipfilter](#snort_ipfilter)|9812|9812|1|0.0%|0.6%|
[nixspam](#nixspam)|39997|39997|1|0.0%|0.6%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|1|0.0%|0.6%|
[bruteforceblocker](#bruteforceblocker)|1720|1720|1|0.0%|0.6%|

## bm_tor

[torstatus.blutmagie.de](https://torstatus.blutmagie.de) list of all TOR network servers

Source is downloaded from [this link](https://torstatus.blutmagie.de/ip_list_all.php/Tor_ip_list_ALL.csv).

The last time downloaded was found to be dated: Sun Jun  7 12:40:43 UTC 2015.

The ipset `bm_tor` has **6522** entries, **6522** unique IPs.

The following table shows the overlaps of `bm_tor` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `bm_tor`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `bm_tor`.
- ` this % ` is the percentage **of this ipset (`bm_tor`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[dm_tor](#dm_tor)|6516|6516|6430|98.6%|98.5%|
[et_tor](#et_tor)|6470|6470|5663|87.5%|86.8%|
[snort_ipfilter](#snort_ipfilter)|9812|9812|1055|10.7%|16.1%|
[stopforumspam_30d](#stopforumspam_30d)|93068|93068|635|0.6%|9.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|17813|139104928|625|0.0%|9.5%|
[stopforumspam_7d](#stopforumspam_7d)|29870|29870|498|1.6%|7.6%|
[stopforumspam_1d](#stopforumspam_1d)|6093|6093|311|5.1%|4.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72952|348710247|191|0.0%|2.9%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|167|44.8%|2.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218315|764993617|166|0.0%|2.5%|
[alienvault_reputation](#alienvault_reputation)|178903|178903|40|0.0%|0.6%|
[php_commenters](#php_commenters)|349|349|36|10.3%|0.5%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|22|0.0%|0.3%|
[openbl_60d](#openbl_60d)|7254|7254|20|0.2%|0.3%|
[php_harvesters](#php_harvesters)|324|324|7|2.1%|0.1%|
[ri_web_proxies](#ri_web_proxies)|6972|6828|5|0.0%|0.0%|
[et_block](#et_block)|1023|18338662|5|0.0%|0.0%|
[php_spammers](#php_spammers)|580|580|4|0.6%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|4|0.0%|0.0%|
[voipbl](#voipbl)|10476|10888|3|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|3|0.0%|0.0%|
[sorbs_spam](#sorbs_spam)|45326|46326|3|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|45326|46326|3|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|45326|46326|3|0.0%|0.0%|
[php_dictionary](#php_dictionary)|589|589|3|0.5%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|17025|17025|3|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|15388|15388|3|0.0%|0.0%|
[blocklist_de](#blocklist_de)|27586|27586|3|0.0%|0.0%|
[xroxy](#xroxy)|2115|2115|2|0.0%|0.0%|
[shunlist](#shunlist)|1245|1245|1|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2665|2516|1|0.0%|0.0%|
[dshield](#dshield)|20|5120|1|0.0%|0.0%|

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
[ib_bluetack_level3](#ib_bluetack_level3)|17813|139104928|4194304|3.0%|0.7%|
[voipbl](#voipbl)|10476|10888|319|2.9%|0.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218315|764993617|5|0.0%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|93068|93068|1|0.0%|0.0%|
[php_harvesters](#php_harvesters)|324|324|1|0.3%|0.0%|
[php_commenters](#php_commenters)|349|349|1|0.2%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.0%|
[ciarmy](#ciarmy)|425|425|1|0.2%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1720|1720|1|0.0%|0.0%|

## bruteforceblocker

[danger.rulez.sk](http://danger.rulez.sk/) IPs detected by [bruteforceblocker](http://danger.rulez.sk/index.php/bruteforceblocker/) (fail2ban alternative for SSH on OpenBSD). This is an automatically generated list from users reporting failed authentication attempts. An IP seems to be included if 3 or more users report it. Its retention pocily seems 30 days.

Source is downloaded from [this link](http://danger.rulez.sk/projects/bruteforceblocker/blist.php).

The last time downloaded was found to be dated: Sun Jun  7 12:41:19 UTC 2015.

The ipset `bruteforceblocker` has **1720** entries, **1720** unique IPs.

The following table shows the overlaps of `bruteforceblocker` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `bruteforceblocker`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `bruteforceblocker`.
- ` this % ` is the percentage **of this ipset (`bruteforceblocker`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[et_compromised](#et_compromised)|2016|2016|1652|81.9%|96.0%|
[alienvault_reputation](#alienvault_reputation)|178903|178903|1099|0.6%|63.8%|
[openbl_60d](#openbl_60d)|7254|7254|1005|13.8%|58.4%|
[openbl_30d](#openbl_30d)|3245|3245|973|29.9%|56.5%|
[blocklist_de](#blocklist_de)|27586|27586|563|2.0%|32.7%|
[blocklist_de_ssh](#blocklist_de_ssh)|2572|2572|546|21.2%|31.7%|
[shunlist](#shunlist)|1245|1245|422|33.8%|24.5%|
[openbl_7d](#openbl_7d)|816|816|326|39.9%|18.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17813|139104928|160|0.0%|9.3%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|101|0.0%|5.8%|
[et_block](#et_block)|1023|18338662|101|0.0%|5.8%|
[dshield](#dshield)|20|5120|95|1.8%|5.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72952|348710247|85|0.0%|4.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|218315|764993617|46|0.0%|2.6%|
[openbl_1d](#openbl_1d)|116|116|41|35.3%|2.3%|
[blocklist_de_mail](#blocklist_de_mail)|17025|17025|14|0.0%|0.8%|
[stopforumspam_30d](#stopforumspam_30d)|93068|93068|13|0.0%|0.7%|
[blocklist_de_imap](#blocklist_de_imap)|2180|2180|12|0.5%|0.6%|
[stopforumspam_7d](#stopforumspam_7d)|29870|29870|7|0.0%|0.4%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|5|0.0%|0.2%|
[stopforumspam_1d](#stopforumspam_1d)|6093|6093|3|0.0%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|3|0.0%|0.1%|
[voipbl](#voipbl)|10476|10888|2|0.0%|0.1%|
[proxz](#proxz)|967|967|2|0.2%|0.1%|
[blocklist_de_apache](#blocklist_de_apache)|15388|15388|2|0.0%|0.1%|
[xroxy](#xroxy)|2115|2115|1|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9812|9812|1|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|6972|6828|1|0.0%|0.0%|
[proxyrss](#proxyrss)|1435|1435|1|0.0%|0.0%|
[php_spammers](#php_spammers)|580|580|1|0.1%|0.0%|
[php_commenters](#php_commenters)|349|349|1|0.2%|0.0%|
[nixspam](#nixspam)|39997|39997|1|0.0%|0.0%|
[fullbogons](#fullbogons)|3720|670264216|1|0.0%|0.0%|
[ciarmy](#ciarmy)|425|425|1|0.2%|0.0%|
[bogons](#bogons)|13|592708608|1|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|165|165|1|0.6%|0.0%|

## ciarmy

[CIArmy.com](http://ciarmy.com/) IPs with poor Rogue Packet score that have not yet been identified as malicious by the community

Source is downloaded from [this link](http://cinsscore.com/list/ci-badguys.txt).

The last time downloaded was found to be dated: Sun Jun  7 10:15:16 UTC 2015.

The ipset `ciarmy` has **425** entries, **425** unique IPs.

The following table shows the overlaps of `ciarmy` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ciarmy`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ciarmy`.
- ` this % ` is the percentage **of this ipset (`ciarmy`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[alienvault_reputation](#alienvault_reputation)|178903|178903|421|0.2%|99.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17813|139104928|81|0.0%|19.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72952|348710247|44|0.0%|10.3%|
[blocklist_de](#blocklist_de)|27586|27586|38|0.1%|8.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|218315|764993617|35|0.0%|8.2%|
[blocklist_de_apache](#blocklist_de_apache)|15388|15388|34|0.2%|8.0%|
[shunlist](#shunlist)|1245|1245|33|2.6%|7.7%|
[et_block](#et_block)|1023|18338662|6|0.0%|1.4%|
[voipbl](#voipbl)|10476|10888|4|0.0%|0.9%|
[dshield](#dshield)|20|5120|3|0.0%|0.7%|
[blocklist_de_ssh](#blocklist_de_ssh)|2572|2572|3|0.1%|0.7%|
[stopforumspam_7d](#stopforumspam_7d)|29870|29870|1|0.0%|0.2%|
[stopforumspam_30d](#stopforumspam_30d)|93068|93068|1|0.0%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.2%|
[fullbogons](#fullbogons)|3720|670264216|1|0.0%|0.2%|
[et_compromised](#et_compromised)|2016|2016|1|0.0%|0.2%|
[bruteforceblocker](#bruteforceblocker)|1720|1720|1|0.0%|0.2%|
[bogons](#bogons)|13|592708608|1|0.0%|0.2%|
[blocklist_de_mail](#blocklist_de_mail)|17025|17025|1|0.0%|0.2%|
[blocklist_de_imap](#blocklist_de_imap)|2180|2180|1|0.0%|0.2%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4042|4042|1|0.0%|0.2%|

## cleanmx_viruses

[Clean-MX.de](http://support.clean-mx.de/clean-mx/viruses.php) IPs with viruses

Source is downloaded from [this link](http://support.clean-mx.de/clean-mx/xmlviruses.php?sort=id%20desc&response=alive).

The last time downloaded was found to be dated: Sun Jun  7 08:01:18 UTC 2015.

The ipset `cleanmx_viruses` has **310** entries, **310** unique IPs.

The following table shows the overlaps of `cleanmx_viruses` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `cleanmx_viruses`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `cleanmx_viruses`.
- ` this % ` is the percentage **of this ipset (`cleanmx_viruses`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|17813|139104928|44|0.0%|14.1%|
[malc0de](#malc0de)|361|361|14|3.8%|4.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72952|348710247|14|0.0%|4.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218315|764993617|9|0.0%|2.9%|
[alienvault_reputation](#alienvault_reputation)|178903|178903|4|0.0%|1.2%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|2|0.1%|0.6%|
[nixspam](#nixspam)|39997|39997|1|0.0%|0.3%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.3%|

## dm_tor

[dan.me.uk](https://www.dan.me.uk) dynamic list of TOR exit points

Source is downloaded from [this link](https://www.dan.me.uk/torlist/).

The last time downloaded was found to be dated: Sun Jun  7 12:40:40 UTC 2015.

The ipset `dm_tor` has **6516** entries, **6516** unique IPs.

The following table shows the overlaps of `dm_tor` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `dm_tor`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `dm_tor`.
- ` this % ` is the percentage **of this ipset (`dm_tor`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[bm_tor](#bm_tor)|6522|6522|6430|98.5%|98.6%|
[et_tor](#et_tor)|6470|6470|5647|87.2%|86.6%|
[snort_ipfilter](#snort_ipfilter)|9812|9812|1056|10.7%|16.2%|
[stopforumspam_30d](#stopforumspam_30d)|93068|93068|631|0.6%|9.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|17813|139104928|627|0.0%|9.6%|
[stopforumspam_7d](#stopforumspam_7d)|29870|29870|495|1.6%|7.5%|
[stopforumspam_1d](#stopforumspam_1d)|6093|6093|311|5.1%|4.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72952|348710247|191|0.0%|2.9%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|167|44.8%|2.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218315|764993617|166|0.0%|2.5%|
[alienvault_reputation](#alienvault_reputation)|178903|178903|40|0.0%|0.6%|
[php_commenters](#php_commenters)|349|349|36|10.3%|0.5%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|22|0.0%|0.3%|
[openbl_60d](#openbl_60d)|7254|7254|20|0.2%|0.3%|
[php_harvesters](#php_harvesters)|324|324|7|2.1%|0.1%|
[ri_web_proxies](#ri_web_proxies)|6972|6828|5|0.0%|0.0%|
[et_block](#et_block)|1023|18338662|5|0.0%|0.0%|
[php_spammers](#php_spammers)|580|580|4|0.6%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|4|0.0%|0.0%|
[voipbl](#voipbl)|10476|10888|3|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|3|0.0%|0.0%|
[sorbs_spam](#sorbs_spam)|45326|46326|3|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|45326|46326|3|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|45326|46326|3|0.0%|0.0%|
[php_dictionary](#php_dictionary)|589|589|3|0.5%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|17025|17025|3|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|15388|15388|3|0.0%|0.0%|
[blocklist_de](#blocklist_de)|27586|27586|3|0.0%|0.0%|
[xroxy](#xroxy)|2115|2115|2|0.0%|0.0%|
[shunlist](#shunlist)|1245|1245|1|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2665|2516|1|0.0%|0.0%|
[dshield](#dshield)|20|5120|1|0.0%|0.0%|

## dshield

[DShield.org](https://dshield.org/) top 20 attacking class C (/24) subnets over the last three days - **excellent list**

Source is downloaded from [this link](http://feeds.dshield.org/block.txt).

The last time downloaded was found to be dated: Sun Jun  7 11:26:28 UTC 2015.

The ipset `dshield` has **20** entries, **5120** unique IPs.

The following table shows the overlaps of `dshield` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `dshield`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `dshield`.
- ` this % ` is the percentage **of this ipset (`dshield`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[alienvault_reputation](#alienvault_reputation)|178903|178903|4608|2.5%|90.0%|
[et_block](#et_block)|1023|18338662|1792|0.0%|35.0%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|512|0.0%|10.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17813|139104928|256|0.0%|5.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72952|348710247|256|0.0%|5.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218315|764993617|256|0.0%|5.0%|
[openbl_60d](#openbl_60d)|7254|7254|141|1.9%|2.7%|
[openbl_30d](#openbl_30d)|3245|3245|128|3.9%|2.5%|
[blocklist_de](#blocklist_de)|27586|27586|108|0.3%|2.1%|
[blocklist_de_ssh](#blocklist_de_ssh)|2572|2572|102|3.9%|1.9%|
[shunlist](#shunlist)|1245|1245|101|8.1%|1.9%|
[et_compromised](#et_compromised)|2016|2016|95|4.7%|1.8%|
[bruteforceblocker](#bruteforceblocker)|1720|1720|95|5.5%|1.8%|
[openbl_7d](#openbl_7d)|816|816|42|5.1%|0.8%|
[openbl_1d](#openbl_1d)|116|116|12|10.3%|0.2%|
[voipbl](#voipbl)|10476|10888|5|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|15388|15388|5|0.0%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|93068|93068|3|0.0%|0.0%|
[ciarmy](#ciarmy)|425|425|3|0.7%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9812|9812|2|0.0%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29870|29870|1|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6093|6093|1|0.0%|0.0%|
[malc0de](#malc0de)|361|361|1|0.2%|0.0%|
[et_tor](#et_tor)|6470|6470|1|0.0%|0.0%|
[dm_tor](#dm_tor)|6516|6516|1|0.0%|0.0%|
[bm_tor](#bm_tor)|6522|6522|1|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|17025|17025|1|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2180|2180|1|0.0%|0.0%|

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
[spamhaus_drop](#spamhaus_drop)|653|18404096|18120448|98.4%|98.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72952|348710247|8500262|2.4%|46.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|7079936|77.1%|38.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218315|764993617|2272276|0.2%|12.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17813|139104928|195933|0.1%|1.0%|
[fullbogons](#fullbogons)|3720|670264216|20480|0.0%|0.1%|
[alienvault_reputation](#alienvault_reputation)|178903|178903|5280|2.9%|0.0%|
[dshield](#dshield)|20|5120|1792|35.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1040|0.3%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|93068|93068|1015|1.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|517|0.1%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9812|9812|315|3.2%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29870|29870|308|1.0%|0.0%|
[openbl_60d](#openbl_60d)|7254|7254|250|3.4%|0.0%|
[zeus](#zeus)|232|232|223|96.1%|0.0%|
[zeus_badips](#zeus_badips)|203|203|200|98.5%|0.0%|
[blocklist_de](#blocklist_de)|27586|27586|180|0.6%|0.0%|
[openbl_30d](#openbl_30d)|3245|3245|162|4.9%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2572|2572|112|4.3%|0.0%|
[shunlist](#shunlist)|1245|1245|110|8.8%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1720|1720|101|5.8%|0.0%|
[et_compromised](#et_compromised)|2016|2016|100|4.9%|0.0%|
[feodo](#feodo)|99|99|94|94.9%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6093|6093|71|1.1%|0.0%|
[openbl_7d](#openbl_7d)|816|816|49|6.0%|0.0%|
[nixspam](#nixspam)|39997|39997|49|0.1%|0.0%|
[sslbl](#sslbl)|372|372|35|9.4%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|29|2.2%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|2976|2976|29|0.9%|0.0%|
[php_commenters](#php_commenters)|349|349|28|8.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|17025|17025|23|0.1%|0.0%|
[voipbl](#voipbl)|10476|10888|17|0.1%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2180|2180|15|0.6%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|15388|15388|13|0.0%|0.0%|
[palevo](#palevo)|13|13|12|92.3%|0.0%|
[openbl_1d](#openbl_1d)|116|116|12|10.3%|0.0%|
[sorbs_spam](#sorbs_spam)|45326|46326|9|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|45326|46326|9|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|45326|46326|9|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|165|165|7|4.2%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|6|0.4%|0.0%|
[ciarmy](#ciarmy)|425|425|6|1.4%|0.0%|
[php_dictionary](#php_dictionary)|589|589|5|0.8%|0.0%|
[malc0de](#malc0de)|361|361|5|1.3%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47941|47941|5|0.0%|0.0%|
[dm_tor](#dm_tor)|6516|6516|5|0.0%|0.0%|
[bm_tor](#bm_tor)|6522|6522|5|0.0%|0.0%|
[et_tor](#et_tor)|6470|6470|4|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4042|4042|4|0.0%|0.0%|
[php_spammers](#php_spammers)|580|580|3|0.5%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|86|86|3|3.4%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|2|0.3%|0.0%|
[php_harvesters](#php_harvesters)|324|324|1|0.3%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|

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
[bruteforceblocker](#bruteforceblocker)|1720|1720|1652|96.0%|81.9%|
[alienvault_reputation](#alienvault_reputation)|178903|178903|1315|0.7%|65.2%|
[openbl_60d](#openbl_60d)|7254|7254|1216|16.7%|60.3%|
[openbl_30d](#openbl_30d)|3245|3245|1144|35.2%|56.7%|
[blocklist_de](#blocklist_de)|27586|27586|574|2.0%|28.4%|
[blocklist_de_ssh](#blocklist_de_ssh)|2572|2572|556|21.6%|27.5%|
[shunlist](#shunlist)|1245|1245|440|35.3%|21.8%|
[openbl_7d](#openbl_7d)|816|816|333|40.8%|16.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17813|139104928|199|0.0%|9.8%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|100|0.0%|4.9%|
[et_block](#et_block)|1023|18338662|100|0.0%|4.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72952|348710247|97|0.0%|4.8%|
[dshield](#dshield)|20|5120|95|1.8%|4.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|218315|764993617|52|0.0%|2.5%|
[openbl_1d](#openbl_1d)|116|116|44|37.9%|2.1%|
[blocklist_de_mail](#blocklist_de_mail)|17025|17025|15|0.0%|0.7%|
[blocklist_de_imap](#blocklist_de_imap)|2180|2180|13|0.5%|0.6%|
[stopforumspam_30d](#stopforumspam_30d)|93068|93068|11|0.0%|0.5%|
[stopforumspam_7d](#stopforumspam_7d)|29870|29870|7|0.0%|0.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|5|0.0%|0.2%|
[stopforumspam_1d](#stopforumspam_1d)|6093|6093|3|0.0%|0.1%|
[voipbl](#voipbl)|10476|10888|2|0.0%|0.0%|
[proxz](#proxz)|967|967|2|0.2%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|2|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|15388|15388|2|0.0%|0.0%|
[xroxy](#xroxy)|2115|2115|1|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9812|9812|1|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|6972|6828|1|0.0%|0.0%|
[proxyrss](#proxyrss)|1435|1435|1|0.0%|0.0%|
[nixspam](#nixspam)|39997|39997|1|0.0%|0.0%|
[ciarmy](#ciarmy)|425|425|1|0.2%|0.0%|

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
[bm_tor](#bm_tor)|6522|6522|5663|86.8%|87.5%|
[dm_tor](#dm_tor)|6516|6516|5647|86.6%|87.2%|
[snort_ipfilter](#snort_ipfilter)|9812|9812|1075|10.9%|16.6%|
[stopforumspam_30d](#stopforumspam_30d)|93068|93068|651|0.6%|10.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17813|139104928|633|0.0%|9.7%|
[stopforumspam_7d](#stopforumspam_7d)|29870|29870|516|1.7%|7.9%|
[stopforumspam_1d](#stopforumspam_1d)|6093|6093|314|5.1%|4.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72952|348710247|189|0.0%|2.9%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|168|45.1%|2.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218315|764993617|168|0.0%|2.5%|
[alienvault_reputation](#alienvault_reputation)|178903|178903|40|0.0%|0.6%|
[php_commenters](#php_commenters)|349|349|37|10.6%|0.5%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|22|0.0%|0.3%|
[openbl_60d](#openbl_60d)|7254|7254|20|0.2%|0.3%|
[php_harvesters](#php_harvesters)|324|324|7|2.1%|0.1%|
[php_spammers](#php_spammers)|580|580|6|1.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|6972|6828|5|0.0%|0.0%|
[php_dictionary](#php_dictionary)|589|589|5|0.8%|0.0%|
[et_block](#et_block)|1023|18338662|4|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|17025|17025|4|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|15388|15388|4|0.0%|0.0%|
[blocklist_de](#blocklist_de)|27586|27586|4|0.0%|0.0%|
[voipbl](#voipbl)|10476|10888|3|0.0%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|0.0%|
[xroxy](#xroxy)|2115|2115|2|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|2|0.0%|0.0%|
[sorbs_spam](#sorbs_spam)|45326|46326|2|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|45326|46326|2|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|45326|46326|2|0.0%|0.0%|
[shunlist](#shunlist)|1245|1245|1|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2665|2516|1|0.0%|0.0%|
[dshield](#dshield)|20|5120|1|0.0%|0.0%|

## feodo

[Abuse.ch Feodo tracker](https://feodotracker.abuse.ch) trojan includes IPs which are being used by Feodo (also known as Cridex or Bugat) which commits ebanking fraud - **excellent list**

Source is downloaded from [this link](https://feodotracker.abuse.ch/blocklist/?download=ipblocklist).

The last time downloaded was found to be dated: Sun Jun  7 12:41:11 UTC 2015.

The ipset `feodo` has **99** entries, **99** unique IPs.

The following table shows the overlaps of `feodo` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `feodo`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `feodo`.
- ` this % ` is the percentage **of this ipset (`feodo`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[et_block](#et_block)|1023|18338662|94|0.0%|94.9%|
[snort_ipfilter](#snort_ipfilter)|9812|9812|79|0.8%|79.7%|
[sslbl](#sslbl)|372|372|36|9.6%|36.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17813|139104928|11|0.0%|11.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72952|348710247|3|0.0%|3.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218315|764993617|3|0.0%|3.0%|
[alienvault_reputation](#alienvault_reputation)|178903|178903|2|0.0%|2.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|1.0%|

## fullbogons

[Team-Cymru.org](http://www.team-cymru.org) IP space that has been allocated to an RIR, but not assigned by that RIR to an actual ISP or other end-user - **excellent list - use it only your internet interface**

Source is downloaded from [this link](http://www.team-cymru.org/Services/Bogons/fullbogons-ipv4.txt).

The last time downloaded was found to be dated: Sun Jun  7 09:35:05 UTC 2015.

The ipset `fullbogons` has **3720** entries, **670264216** unique IPs.

The following table shows the overlaps of `fullbogons` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `fullbogons`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `fullbogons`.
- ` this % ` is the percentage **of this ipset (`fullbogons`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[bogons](#bogons)|13|592708608|592708608|100.0%|88.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17813|139104928|4235823|3.0%|0.6%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|565248|6.1%|0.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72952|348710247|247551|0.0%|0.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218315|764993617|233593|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|151552|0.8%|0.0%|
[et_block](#et_block)|1023|18338662|20480|0.1%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|890|0.2%|0.0%|
[voipbl](#voipbl)|10476|10888|319|2.9%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|33|2.2%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47941|47941|13|0.0%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|9|0.6%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|93068|93068|2|0.0%|0.0%|
[php_harvesters](#php_harvesters)|324|324|1|0.3%|0.0%|
[php_commenters](#php_commenters)|349|349|1|0.2%|0.0%|
[ciarmy](#ciarmy)|425|425|1|0.2%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1720|1720|1|0.0%|0.0%|

## ib_bluetack_badpeers

[iBlocklist.com](https://www.iblocklist.com/) free version of [BlueTack.co.uk](http://www.bluetack.co.uk/) IPs that have been reported for bad deeds in p2p

Source is downloaded from [this link](http://list.iblocklist.com/?list=cwworuawihqvocglcoss&fileformat=p2p&archiveformat=gz).

The last time downloaded was found to be dated: Sun Jun  7 05:00:59 UTC 2015.

The ipset `ib_bluetack_badpeers` has **47941** entries, **47941** unique IPs.

The following table shows the overlaps of `ib_bluetack_badpeers` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ib_bluetack_badpeers`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ib_bluetack_badpeers`.
- ` this % ` is the percentage **of this ipset (`ib_bluetack_badpeers`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|17813|139104928|1172|0.0%|2.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218315|764993617|394|0.0%|0.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72952|348710247|226|0.0%|0.4%|
[sorbs_spam](#sorbs_spam)|45326|46326|19|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|45326|46326|19|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|45326|46326|19|0.0%|0.0%|
[nixspam](#nixspam)|39997|39997|16|0.0%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|93068|93068|15|0.0%|0.0%|
[alienvault_reputation](#alienvault_reputation)|178903|178903|15|0.0%|0.0%|
[fullbogons](#fullbogons)|3720|670264216|13|0.0%|0.0%|
[blocklist_de](#blocklist_de)|27586|27586|12|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|11|1.6%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29870|29870|7|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|15388|15388|6|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|5|0.0%|0.0%|
[et_block](#et_block)|1023|18338662|5|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4042|4042|5|0.1%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|17025|17025|4|0.0%|0.0%|
[xroxy](#xroxy)|2115|2115|3|0.1%|0.0%|
[ri_web_proxies](#ri_web_proxies)|6972|6828|3|0.0%|0.0%|
[php_dictionary](#php_dictionary)|589|589|3|0.5%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|3|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2180|2180|3|0.1%|0.0%|
[voipbl](#voipbl)|10476|10888|2|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6093|6093|2|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9812|9812|2|0.0%|0.0%|
[php_harvesters](#php_harvesters)|324|324|2|0.6%|0.0%|
[proxz](#proxz)|967|967|1|0.1%|0.0%|
[php_spammers](#php_spammers)|580|580|1|0.1%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|1|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2572|2572|1|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|2976|2976|1|0.0%|0.0%|

## ib_bluetack_hijacked

[iBlocklist.com](https://www.iblocklist.com/) free version of [BlueTack.co.uk](http://www.bluetack.co.uk/) hijacked IP-Blocks Hijacked IP space are IP blocks that are being used without permission

Source is downloaded from [this link](http://list.iblocklist.com/?list=usrcshglbiilevmyfhse&fileformat=p2p&archiveformat=gz).

The last time downloaded was found to be dated: Sun Jun  7 05:30:02 UTC 2015.

The ipset `ib_bluetack_hijacked` has **535** entries, **9177856** unique IPs.

The following table shows the overlaps of `ib_bluetack_hijacked` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ib_bluetack_hijacked`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ib_bluetack_hijacked`.
- ` this % ` is the percentage **of this ipset (`ib_bluetack_hijacked`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[et_block](#et_block)|1023|18338662|7079936|38.6%|77.1%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|6998016|38.0%|76.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72952|348710247|2526625|0.7%|27.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218315|764993617|904796|0.1%|9.8%|
[fullbogons](#fullbogons)|3720|670264216|565248|0.0%|6.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17813|139104928|145472|0.1%|1.5%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1036|0.3%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|93068|93068|738|0.7%|0.0%|
[alienvault_reputation](#alienvault_reputation)|178903|178903|518|0.2%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29870|29870|150|0.5%|0.0%|
[nixspam](#nixspam)|39997|39997|48|0.1%|0.0%|
[blocklist_de](#blocklist_de)|27586|27586|34|0.1%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|27|2.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|2976|2976|23|0.7%|0.0%|
[openbl_60d](#openbl_60d)|7254|7254|17|0.2%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6093|6093|14|0.2%|0.0%|
[openbl_30d](#openbl_30d)|3245|3245|13|0.4%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9812|9812|12|0.1%|0.0%|
[zeus_badips](#zeus_badips)|203|203|10|4.9%|0.0%|
[zeus](#zeus)|232|232|10|4.3%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|7|0.4%|0.0%|
[sorbs_spam](#sorbs_spam)|45326|46326|5|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|45326|46326|5|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|45326|46326|5|0.0%|0.0%|
[openbl_7d](#openbl_7d)|816|816|5|0.6%|0.0%|
[et_compromised](#et_compromised)|2016|2016|5|0.2%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1720|1720|5|0.2%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2572|2572|5|0.1%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|17025|17025|5|0.0%|0.0%|
[dm_tor](#dm_tor)|6516|6516|4|0.0%|0.0%|
[bm_tor](#bm_tor)|6522|6522|4|0.0%|0.0%|
[php_spammers](#php_spammers)|580|580|3|0.5%|0.0%|
[php_dictionary](#php_dictionary)|589|589|3|0.5%|0.0%|
[et_tor](#et_tor)|6470|6470|3|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|165|165|3|1.8%|0.0%|
[shunlist](#shunlist)|1245|1245|2|0.1%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|2|0.3%|0.0%|
[voipbl](#voipbl)|10476|10888|1|0.0%|0.0%|
[php_harvesters](#php_harvesters)|324|324|1|0.3%|0.0%|
[php_commenters](#php_commenters)|349|349|1|0.2%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2180|2180|1|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4042|4042|1|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|15388|15388|1|0.0%|0.0%|

## ib_bluetack_level1

[iBlocklist.com](https://www.iblocklist.com/) free version of [BlueTack.co.uk](http://www.bluetack.co.uk/) Level 1 (for use in p2p): Companies or organizations who are clearly involved with trying to stop filesharing (e.g. Baytsp, MediaDefender, Mediasentry a.o.). Companies which anti-p2p activity has been seen from. Companies that produce or have a strong financial interest in copyrighted material (e.g. music, movie, software industries a.o.). Government ranges or companies that have a strong financial interest in doing work for governments. Legal industry ranges. IPs or ranges of ISPs from which anti-p2p activity has been observed. Basically this list will block all kinds of internet connections that most people would rather not have during their internet travels.

Source is downloaded from [this link](http://list.iblocklist.com/?list=ydxerpxkpcfqjaybcssw&fileformat=p2p&archiveformat=gz).

The last time downloaded was found to be dated: Sun Jun  7 09:27:01 UTC 2015.

The ipset `ib_bluetack_level1` has **218315** entries, **764993617** unique IPs.

The following table shows the overlaps of `ib_bluetack_level1` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ib_bluetack_level1`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ib_bluetack_level1`.
- ` this % ` is the percentage **of this ipset (`ib_bluetack_level1`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level2](#ib_bluetack_level2)|72952|348710247|16067826|4.6%|2.1%|
[et_block](#et_block)|1023|18338662|2272276|12.3%|0.2%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|2272265|12.3%|0.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|17813|139104928|1349274|0.9%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|904796|9.8%|0.1%|
[fullbogons](#fullbogons)|3720|670264216|233593|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|33155|6.8%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|13239|3.9%|0.0%|
[alienvault_reputation](#alienvault_reputation)|178903|178903|3070|1.7%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|93068|93068|1528|1.6%|0.0%|
[blocklist_de](#blocklist_de)|27586|27586|1499|5.4%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|17025|17025|1379|8.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|15388|15388|1310|8.5%|0.0%|
[sorbs_spam](#sorbs_spam)|45326|46326|667|1.4%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|45326|46326|667|1.4%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|45326|46326|667|1.4%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29870|29870|559|1.8%|0.0%|
[nixspam](#nixspam)|39997|39997|518|1.2%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47941|47941|394|0.8%|0.0%|
[voipbl](#voipbl)|10476|10888|296|2.7%|0.0%|
[dshield](#dshield)|20|5120|256|5.0%|0.0%|
[et_tor](#et_tor)|6470|6470|168|2.5%|0.0%|
[openbl_60d](#openbl_60d)|7254|7254|167|2.3%|0.0%|
[dm_tor](#dm_tor)|6516|6516|166|2.5%|0.0%|
[bm_tor](#bm_tor)|6522|6522|166|2.5%|0.0%|
[ri_web_proxies](#ri_web_proxies)|6972|6828|136|1.9%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6093|6093|130|2.1%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|97|6.6%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2665|2516|79|3.1%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9812|9812|74|0.7%|0.0%|
[openbl_30d](#openbl_30d)|3245|3245|69|2.1%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|66|5.1%|0.0%|
[xroxy](#xroxy)|2115|2115|58|2.7%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|56|8.4%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2572|2572|53|2.0%|0.0%|
[et_compromised](#et_compromised)|2016|2016|52|2.5%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1720|1720|46|2.6%|0.0%|
[proxyrss](#proxyrss)|1435|1435|45|3.1%|0.0%|
[ciarmy](#ciarmy)|425|425|35|8.2%|0.0%|
[proxz](#proxz)|967|967|34|3.5%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|2976|2976|29|0.9%|0.0%|
[shunlist](#shunlist)|1245|1245|28|2.2%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2180|2180|28|1.2%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4042|4042|21|0.5%|0.0%|
[sorbs_web](#sorbs_web)|619|619|18|2.9%|0.0%|
[openbl_7d](#openbl_7d)|816|816|18|2.2%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|17|4.5%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|635|635|12|1.8%|0.0%|
[php_harvesters](#php_harvesters)|324|324|11|3.3%|0.0%|
[php_dictionary](#php_dictionary)|589|589|11|1.8%|0.0%|
[malc0de](#malc0de)|361|361|11|3.0%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|310|310|9|2.9%|0.0%|
[php_spammers](#php_spammers)|580|580|8|1.3%|0.0%|
[php_commenters](#php_commenters)|349|349|8|2.2%|0.0%|
[zeus](#zeus)|232|232|6|2.5%|0.0%|
[bogons](#bogons)|13|592708608|5|0.0%|0.0%|
[zeus_badips](#zeus_badips)|203|203|4|1.9%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|86|86|4|4.6%|0.0%|
[sslbl](#sslbl)|372|372|3|0.8%|0.0%|
[feodo](#feodo)|99|99|3|3.0%|0.0%|
[sorbs_socks](#sorbs_socks)|20|20|1|5.0%|0.0%|
[sorbs_misc](#sorbs_misc)|20|20|1|5.0%|0.0%|
[sorbs_http](#sorbs_http)|20|20|1|5.0%|0.0%|
[openbl_1d](#openbl_1d)|116|116|1|0.8%|0.0%|

## ib_bluetack_level2

[iBlocklist.com](https://www.iblocklist.com/) free version of BlueTack.co.uk Level 2 (for use in p2p). General corporate ranges. Ranges used by labs or researchers. Proxies.

Source is downloaded from [this link](http://list.iblocklist.com/?list=gyisgnzbhppbvsphucsw&fileformat=p2p&archiveformat=gz).

The last time downloaded was found to be dated: Sun Jun  7 05:30:38 UTC 2015.

The ipset `ib_bluetack_level2` has **72952** entries, **348710247** unique IPs.

The following table shows the overlaps of `ib_bluetack_level2` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ib_bluetack_level2`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ib_bluetack_level2`.
- ` this % ` is the percentage **of this ipset (`ib_bluetack_level2`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level1](#ib_bluetack_level1)|218315|764993617|16067826|2.1%|4.6%|
[et_block](#et_block)|1023|18338662|8500262|46.3%|2.4%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|8499993|46.1%|2.4%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2526625|27.5%|0.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|17813|139104928|2338412|1.6%|0.6%|
[fullbogons](#fullbogons)|3720|670264216|247551|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|98904|20.2%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|7728|2.2%|0.0%|
[alienvault_reputation](#alienvault_reputation)|178903|178903|7285|4.0%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|93068|93068|2527|2.7%|0.0%|
[blocklist_de](#blocklist_de)|27586|27586|1430|5.1%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|17025|17025|1147|6.7%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|15388|15388|1087|7.0%|0.0%|
[sorbs_spam](#sorbs_spam)|45326|46326|1059|2.2%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|45326|46326|1059|2.2%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|45326|46326|1059|2.2%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29870|29870|882|2.9%|0.0%|
[nixspam](#nixspam)|39997|39997|807|2.0%|0.0%|
[voipbl](#voipbl)|10476|10888|434|3.9%|0.0%|
[openbl_60d](#openbl_60d)|7254|7254|327|4.5%|0.0%|
[dshield](#dshield)|20|5120|256|5.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47941|47941|226|0.4%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6093|6093|216|3.5%|0.0%|
[ri_web_proxies](#ri_web_proxies)|6972|6828|198|2.8%|0.0%|
[dm_tor](#dm_tor)|6516|6516|191|2.9%|0.0%|
[bm_tor](#bm_tor)|6522|6522|191|2.9%|0.0%|
[et_tor](#et_tor)|6470|6470|189|2.9%|0.0%|
[openbl_30d](#openbl_30d)|3245|3245|170|5.2%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|2976|2976|109|3.6%|0.0%|
[xroxy](#xroxy)|2115|2115|103|4.8%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9812|9812|102|1.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2665|2516|97|3.8%|0.0%|
[et_compromised](#et_compromised)|2016|2016|97|4.8%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2572|2572|97|3.7%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1720|1720|85|4.9%|0.0%|
[shunlist](#shunlist)|1245|1245|69|5.5%|0.0%|
[proxyrss](#proxyrss)|1435|1435|60|4.1%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4042|4042|54|1.3%|0.0%|
[php_spammers](#php_spammers)|580|580|49|8.4%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2180|2180|48|2.2%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|45|3.1%|0.0%|
[ciarmy](#ciarmy)|425|425|44|10.3%|0.0%|
[openbl_7d](#openbl_7d)|816|816|43|5.2%|0.0%|
[proxz](#proxz)|967|967|38|3.9%|0.0%|
[sorbs_web](#sorbs_web)|619|619|27|4.3%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|26|2.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|26|3.9%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|21|5.6%|0.0%|
[malc0de](#malc0de)|361|361|21|5.8%|0.0%|
[php_dictionary](#php_dictionary)|589|589|20|3.3%|0.0%|
[php_commenters](#php_commenters)|349|349|14|4.0%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|310|310|14|4.5%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|635|635|12|1.8%|0.0%|
[zeus](#zeus)|232|232|9|3.8%|0.0%|
[php_harvesters](#php_harvesters)|324|324|9|2.7%|0.0%|
[zeus_badips](#zeus_badips)|203|203|8|3.9%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|165|165|7|4.2%|0.0%|
[openbl_1d](#openbl_1d)|116|116|6|5.1%|0.0%|
[sslbl](#sslbl)|372|372|5|1.3%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|86|86|5|5.8%|0.0%|
[palevo](#palevo)|13|13|3|23.0%|0.0%|
[feodo](#feodo)|99|99|3|3.0%|0.0%|
[sorbs_socks](#sorbs_socks)|20|20|1|5.0%|0.0%|
[sorbs_smtp](#sorbs_smtp)|10|10|1|10.0%|0.0%|
[sorbs_misc](#sorbs_misc)|20|20|1|5.0%|0.0%|
[sorbs_http](#sorbs_http)|20|20|1|5.0%|0.0%|

## ib_bluetack_level3

[iBlocklist.com](https://www.iblocklist.com/) free version of BlueTack.co.uk Level 3 (for use in p2p). Many portal-type websites. ISP ranges that may be dodgy for some reason. Ranges that belong to an individual, but which have not been determined to be used by a particular company. Ranges for things that are unusual in some way. The L3 list is aka the paranoid list.

Source is downloaded from [this link](http://list.iblocklist.com/?list=uwnukjqktoggdknzrhgh&fileformat=p2p&archiveformat=gz).

The last time downloaded was found to be dated: Sun Jun  7 05:30:49 UTC 2015.

The ipset `ib_bluetack_level3` has **17813** entries, **139104928** unique IPs.

The following table shows the overlaps of `ib_bluetack_level3` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ib_bluetack_level3`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ib_bluetack_level3`.
- ` this % ` is the percentage **of this ipset (`ib_bluetack_level3`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[fullbogons](#fullbogons)|3720|670264216|4235823|0.6%|3.0%|
[bogons](#bogons)|13|592708608|4194304|0.7%|3.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72952|348710247|2338412|0.6%|1.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218315|764993617|1349274|0.1%|0.9%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|270785|55.5%|0.1%|
[et_block](#et_block)|1023|18338662|195933|1.0%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|145472|1.5%|0.1%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|130368|0.7%|0.0%|
[alienvault_reputation](#alienvault_reputation)|178903|178903|13886|7.7%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|9226|2.7%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|93068|93068|5853|6.2%|0.0%|
[blocklist_de](#blocklist_de)|27586|27586|3629|13.1%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|17025|17025|2620|15.3%|0.0%|
[sorbs_spam](#sorbs_spam)|45326|46326|2558|5.5%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|45326|46326|2558|5.5%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|45326|46326|2558|5.5%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|15388|15388|2403|15.6%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29870|29870|1948|6.5%|0.0%|
[nixspam](#nixspam)|39997|39997|1687|4.2%|0.0%|
[voipbl](#voipbl)|10476|10888|1599|14.6%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47941|47941|1172|2.4%|0.0%|
[openbl_60d](#openbl_60d)|7254|7254|743|10.2%|0.0%|
[et_tor](#et_tor)|6470|6470|633|9.7%|0.0%|
[dm_tor](#dm_tor)|6516|6516|627|9.6%|0.0%|
[bm_tor](#bm_tor)|6522|6522|625|9.5%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6093|6093|457|7.5%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2572|2572|422|16.4%|0.0%|
[openbl_30d](#openbl_30d)|3245|3245|314|9.6%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4042|4042|303|7.4%|0.0%|
[dshield](#dshield)|20|5120|256|5.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9812|9812|231|2.3%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2180|2180|205|9.4%|0.0%|
[et_compromised](#et_compromised)|2016|2016|199|9.8%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|2976|2976|199|6.6%|0.0%|
[ri_web_proxies](#ri_web_proxies)|6972|6828|195|2.8%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1720|1720|160|9.3%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|147|11.4%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|125|33.6%|0.0%|
[shunlist](#shunlist)|1245|1245|113|9.0%|0.0%|
[openbl_7d](#openbl_7d)|816|816|111|13.6%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|108|7.4%|0.0%|
[xroxy](#xroxy)|2115|2115|98|4.6%|0.0%|
[ciarmy](#ciarmy)|425|425|81|19.0%|0.0%|
[proxz](#proxz)|967|967|80|8.2%|0.0%|
[malc0de](#malc0de)|361|361|54|14.9%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2665|2516|53|2.1%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|51|7.6%|0.0%|
[proxyrss](#proxyrss)|1435|1435|50|3.4%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|635|635|49|7.7%|0.0%|
[sorbs_web](#sorbs_web)|619|619|44|7.1%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|310|310|44|14.1%|0.0%|
[php_spammers](#php_spammers)|580|580|32|5.5%|0.0%|
[php_dictionary](#php_dictionary)|589|589|31|5.2%|0.0%|
[sslbl](#sslbl)|372|372|26|6.9%|0.0%|
[php_commenters](#php_commenters)|349|349|22|6.3%|0.0%|
[php_harvesters](#php_harvesters)|324|324|17|5.2%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|165|165|15|9.0%|0.0%|
[zeus](#zeus)|232|232|13|5.6%|0.0%|
[feodo](#feodo)|99|99|11|11.1%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|86|86|11|12.7%|0.0%|
[zeus_badips](#zeus_badips)|203|203|10|4.9%|0.0%|
[openbl_1d](#openbl_1d)|116|116|10|8.6%|0.0%|
[palevo](#palevo)|13|13|1|7.6%|0.0%|

## ib_bluetack_proxies

[iBlocklist.com](https://www.iblocklist.com/) free version of [BlueTack.co.uk](http://www.bluetack.co.uk/) Open Proxies IPs list (without TOR)

Source is downloaded from [this link](http://list.iblocklist.com/?list=xoebmbyexwuiogmbyprb&fileformat=p2p&archiveformat=gz).

The last time downloaded was found to be dated: Sun Jun  7 05:30:04 UTC 2015.

The ipset `ib_bluetack_proxies` has **663** entries, **663** unique IPs.

The following table shows the overlaps of `ib_bluetack_proxies` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ib_bluetack_proxies`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ib_bluetack_proxies`.
- ` this % ` is the percentage **of this ipset (`ib_bluetack_proxies`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level1](#ib_bluetack_level1)|218315|764993617|56|0.0%|8.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17813|139104928|51|0.0%|7.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72952|348710247|26|0.0%|3.9%|
[stopforumspam_30d](#stopforumspam_30d)|93068|93068|22|0.0%|3.3%|
[xroxy](#xroxy)|2115|2115|13|0.6%|1.9%|
[ri_web_proxies](#ri_web_proxies)|6972|6828|13|0.1%|1.9%|
[stopforumspam_7d](#stopforumspam_7d)|29870|29870|12|0.0%|1.8%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47941|47941|11|0.0%|1.6%|
[proxyrss](#proxyrss)|1435|1435|8|0.5%|1.2%|
[ri_connect_proxies](#ri_connect_proxies)|2665|2516|7|0.2%|1.0%|
[stopforumspam_1d](#stopforumspam_1d)|6093|6093|6|0.0%|0.9%|
[proxz](#proxz)|967|967|6|0.6%|0.9%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|2|0.0%|0.3%|
[sorbs_spam](#sorbs_spam)|45326|46326|2|0.0%|0.3%|
[sorbs_recent_spam](#sorbs_recent_spam)|45326|46326|2|0.0%|0.3%|
[sorbs_new_spam](#sorbs_new_spam)|45326|46326|2|0.0%|0.3%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|2|0.1%|0.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2|0.0%|0.3%|
[et_block](#et_block)|1023|18338662|2|0.0%|0.3%|
[blocklist_de](#blocklist_de)|27586|27586|2|0.0%|0.3%|
[snort_ipfilter](#snort_ipfilter)|9812|9812|1|0.0%|0.1%|
[php_dictionary](#php_dictionary)|589|589|1|0.1%|0.1%|
[nixspam](#nixspam)|39997|39997|1|0.0%|0.1%|
[blocklist_de_bots](#blocklist_de_bots)|2976|2976|1|0.0%|0.1%|
[blocklist_de_apache](#blocklist_de_apache)|15388|15388|1|0.0%|0.1%|
[alienvault_reputation](#alienvault_reputation)|178903|178903|1|0.0%|0.1%|

## ib_bluetack_spyware

[iBlocklist.com](https://www.iblocklist.com/) free version of [BlueTack.co.uk](http://www.bluetack.co.uk/) known malicious SPYWARE and ADWARE IP Address ranges

Source is downloaded from [this link](http://list.iblocklist.com/?list=llvtlsjyoyiczbkjsxpf&fileformat=p2p&archiveformat=gz).

The last time downloaded was found to be dated: Sun Jun  7 05:00:08 UTC 2015.

The ipset `ib_bluetack_spyware` has **3267** entries, **339173** unique IPs.

The following table shows the overlaps of `ib_bluetack_spyware` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ib_bluetack_spyware`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ib_bluetack_spyware`.
- ` this % ` is the percentage **of this ipset (`ib_bluetack_spyware`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level1](#ib_bluetack_level1)|218315|764993617|13239|0.0%|3.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17813|139104928|9226|0.0%|2.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72952|348710247|7728|0.0%|2.2%|
[et_block](#et_block)|1023|18338662|1040|0.0%|0.3%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|1037|0.0%|0.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1036|0.0%|0.3%|
[fullbogons](#fullbogons)|3720|670264216|890|0.0%|0.2%|
[alienvault_reputation](#alienvault_reputation)|178903|178903|287|0.1%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|93068|93068|47|0.0%|0.0%|
[sorbs_spam](#sorbs_spam)|45326|46326|34|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|45326|46326|34|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|45326|46326|34|0.0%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|27|2.0%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29870|29870|25|0.0%|0.0%|
[et_tor](#et_tor)|6470|6470|22|0.3%|0.0%|
[dm_tor](#dm_tor)|6516|6516|22|0.3%|0.0%|
[bm_tor](#bm_tor)|6522|6522|22|0.3%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|19|1.3%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9812|9812|15|0.1%|0.0%|
[nixspam](#nixspam)|39997|39997|10|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6093|6093|9|0.1%|0.0%|
[blocklist_de](#blocklist_de)|27586|27586|8|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|6972|6828|5|0.0%|0.0%|
[openbl_60d](#openbl_60d)|7254|7254|5|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|5|1.3%|0.0%|
[voipbl](#voipbl)|10476|10888|4|0.0%|0.0%|
[openbl_30d](#openbl_30d)|3245|3245|4|0.1%|0.0%|
[malc0de](#malc0de)|361|361|3|0.8%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47941|47941|3|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1720|1720|3|0.1%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2572|2572|3|0.1%|0.0%|
[palevo](#palevo)|13|13|2|15.3%|0.0%|
[et_compromised](#et_compromised)|2016|2016|2|0.0%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|86|86|2|2.3%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|17025|17025|2|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|2976|2976|2|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|15388|15388|2|0.0%|0.0%|
[zeus_badips](#zeus_badips)|203|203|1|0.4%|0.0%|
[zeus](#zeus)|232|232|1|0.4%|0.0%|
[xroxy](#xroxy)|2115|2115|1|0.0%|0.0%|
[sslbl](#sslbl)|372|372|1|0.2%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|1|0.0%|0.0%|
[shunlist](#shunlist)|1245|1245|1|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2665|2516|1|0.0%|0.0%|
[proxyrss](#proxyrss)|1435|1435|1|0.0%|0.0%|
[php_harvesters](#php_harvesters)|324|324|1|0.3%|0.0%|
[php_dictionary](#php_dictionary)|589|589|1|0.1%|0.0%|
[openbl_7d](#openbl_7d)|816|816|1|0.1%|0.0%|
[feodo](#feodo)|99|99|1|1.0%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|310|310|1|0.3%|0.0%|
[ciarmy](#ciarmy)|425|425|1|0.2%|0.0%|
[bogons](#bogons)|13|592708608|1|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4042|4042|1|0.0%|0.0%|

## ib_bluetack_webexploit

[iBlocklist.com](https://www.iblocklist.com/) free version of [BlueTack.co.uk](http://www.bluetack.co.uk/) web server hack and exploit attempts

Source is downloaded from [this link](http://list.iblocklist.com/?list=ghlzqtqxnzctvvajwwag&fileformat=p2p&archiveformat=gz).

The last time downloaded was found to be dated: Sun Jun  7 05:00:08 UTC 2015.

The ipset `ib_bluetack_webexploit` has **1450** entries, **1450** unique IPs.

The following table shows the overlaps of `ib_bluetack_webexploit` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ib_bluetack_webexploit`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ib_bluetack_webexploit`.
- ` this % ` is the percentage **of this ipset (`ib_bluetack_webexploit`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|17813|139104928|108|0.0%|7.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218315|764993617|97|0.0%|6.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72952|348710247|45|0.0%|3.1%|
[fullbogons](#fullbogons)|3720|670264216|33|0.0%|2.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|19|0.0%|1.3%|
[alienvault_reputation](#alienvault_reputation)|178903|178903|9|0.0%|0.6%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|7|0.0%|0.4%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|6|0.0%|0.4%|
[et_block](#et_block)|1023|18338662|6|0.0%|0.4%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|3|0.2%|0.2%|
[stopforumspam_7d](#stopforumspam_7d)|29870|29870|2|0.0%|0.1%|
[stopforumspam_30d](#stopforumspam_30d)|93068|93068|2|0.0%|0.1%|
[stopforumspam_1d](#stopforumspam_1d)|6093|6093|2|0.0%|0.1%|
[openbl_60d](#openbl_60d)|7254|7254|2|0.0%|0.1%|
[openbl_30d](#openbl_30d)|3245|3245|2|0.0%|0.1%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|2|0.3%|0.1%|
[blocklist_de](#blocklist_de)|27586|27586|2|0.0%|0.1%|
[snort_ipfilter](#snort_ipfilter)|9812|9812|1|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|6972|6828|1|0.0%|0.0%|
[openbl_7d](#openbl_7d)|816|816|1|0.1%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47941|47941|1|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|165|165|1|0.6%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2572|2572|1|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|2976|2976|1|0.0%|0.0%|

## malc0de

[Malc0de.com](http://malc0de.com) malicious IPs of the last 30 days

Source is downloaded from [this link](http://malc0de.com/bl/IP_Blacklist.txt).

The last time downloaded was found to be dated: Sat Jun  6 13:17:03 UTC 2015.

The ipset `malc0de` has **361** entries, **361** unique IPs.

The following table shows the overlaps of `malc0de` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `malc0de`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `malc0de`.
- ` this % ` is the percentage **of this ipset (`malc0de`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|17813|139104928|54|0.0%|14.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72952|348710247|21|0.0%|5.8%|
[cleanmx_viruses](#cleanmx_viruses)|310|310|14|4.5%|3.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218315|764993617|11|0.0%|3.0%|
[alienvault_reputation](#alienvault_reputation)|178903|178903|11|0.0%|3.0%|
[et_block](#et_block)|1023|18338662|5|0.0%|1.3%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|4|0.0%|1.1%|
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
[ib_bluetack_level3](#ib_bluetack_level3)|17813|139104928|147|0.0%|11.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218315|764993617|66|0.0%|5.1%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|29|0.0%|2.2%|
[et_block](#et_block)|1023|18338662|29|0.0%|2.2%|
[snort_ipfilter](#snort_ipfilter)|9812|9812|27|0.2%|2.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|27|0.0%|2.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|27|0.0%|2.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72952|348710247|26|0.0%|2.0%|
[fullbogons](#fullbogons)|3720|670264216|9|0.0%|0.6%|
[alienvault_reputation](#alienvault_reputation)|178903|178903|6|0.0%|0.4%|
[stopforumspam_30d](#stopforumspam_30d)|93068|93068|4|0.0%|0.3%|
[malc0de](#malc0de)|361|361|4|1.1%|0.3%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|3|0.2%|0.2%|
[sorbs_spam](#sorbs_spam)|45326|46326|2|0.0%|0.1%|
[sorbs_recent_spam](#sorbs_recent_spam)|45326|46326|2|0.0%|0.1%|
[sorbs_new_spam](#sorbs_new_spam)|45326|46326|2|0.0%|0.1%|
[cleanmx_viruses](#cleanmx_viruses)|310|310|2|0.6%|0.1%|
[stopforumspam_7d](#stopforumspam_7d)|29870|29870|1|0.0%|0.0%|

## maxmind_proxy_fraud

[MaxMind.com](https://www.maxmind.com/en/anonymous-proxy-fraudulent-ip-address-list) list of anonymous proxy fraudelent IP addresses.

Source is downloaded from [this link](https://www.maxmind.com/en/anonymous-proxy-fraudulent-ip-address-list).

The last time downloaded was found to be dated: Sun Jun  7 11:42:59 UTC 2015.

The ipset `maxmind_proxy_fraud` has **372** entries, **372** unique IPs.

The following table shows the overlaps of `maxmind_proxy_fraud` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `maxmind_proxy_fraud`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `maxmind_proxy_fraud`.
- ` this % ` is the percentage **of this ipset (`maxmind_proxy_fraud`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_30d](#stopforumspam_30d)|93068|93068|231|0.2%|62.0%|
[stopforumspam_7d](#stopforumspam_7d)|29870|29870|189|0.6%|50.8%|
[snort_ipfilter](#snort_ipfilter)|9812|9812|175|1.7%|47.0%|
[et_tor](#et_tor)|6470|6470|168|2.5%|45.1%|
[dm_tor](#dm_tor)|6516|6516|167|2.5%|44.8%|
[bm_tor](#bm_tor)|6522|6522|167|2.5%|44.8%|
[stopforumspam_1d](#stopforumspam_1d)|6093|6093|146|2.3%|39.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|17813|139104928|125|0.0%|33.6%|
[php_commenters](#php_commenters)|349|349|34|9.7%|9.1%|
[alienvault_reputation](#alienvault_reputation)|178903|178903|26|0.0%|6.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72952|348710247|21|0.0%|5.6%|
[openbl_60d](#openbl_60d)|7254|7254|18|0.2%|4.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218315|764993617|17|0.0%|4.5%|
[php_harvesters](#php_harvesters)|324|324|6|1.8%|1.6%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|5|0.0%|1.3%|
[ri_web_proxies](#ri_web_proxies)|6972|6828|4|0.0%|1.0%|
[php_spammers](#php_spammers)|580|580|4|0.6%|1.0%|
[php_dictionary](#php_dictionary)|589|589|4|0.6%|1.0%|
[xroxy](#xroxy)|2115|2115|1|0.0%|0.2%|
[voipbl](#voipbl)|10476|10888|1|0.0%|0.2%|
[shunlist](#shunlist)|1245|1245|1|0.0%|0.2%|
[ri_connect_proxies](#ri_connect_proxies)|2665|2516|1|0.0%|0.2%|
[et_block](#et_block)|1023|18338662|1|0.0%|0.2%|
[blocklist_de_mail](#blocklist_de_mail)|17025|17025|1|0.0%|0.2%|
[blocklist_de_apache](#blocklist_de_apache)|15388|15388|1|0.0%|0.2%|
[blocklist_de](#blocklist_de)|27586|27586|1|0.0%|0.2%|

## nixspam

[NiX Spam](http://www.heise.de/ix/NiX-Spam-DNSBL-and-blacklist-for-download-499637.html) IP addresses that sent spam in the last hour - automatically generated entries without distinguishing open proxies from relays, dialup gateways, and so on. All IPs are removed after 12 hours if there is no spam from there.

Source is downloaded from [this link](http://www.dnsbl.manitu.net/download/nixspam-ip.dump.gz).

The last time downloaded was found to be dated: Sun Jun  7 12:30:03 UTC 2015.

The ipset `nixspam` has **39997** entries, **39997** unique IPs.

The following table shows the overlaps of `nixspam` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `nixspam`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `nixspam`.
- ` this % ` is the percentage **of this ipset (`nixspam`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[sorbs_spam](#sorbs_spam)|45326|46326|19395|41.8%|48.4%|
[sorbs_recent_spam](#sorbs_recent_spam)|45326|46326|19395|41.8%|48.4%|
[sorbs_new_spam](#sorbs_new_spam)|45326|46326|19395|41.8%|48.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17813|139104928|1687|0.0%|4.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72952|348710247|807|0.0%|2.0%|
[blocklist_de](#blocklist_de)|27586|27586|577|2.0%|1.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218315|764993617|518|0.0%|1.2%|
[blocklist_de_mail](#blocklist_de_mail)|17025|17025|508|2.9%|1.2%|
[stopforumspam_30d](#stopforumspam_30d)|93068|93068|149|0.1%|0.3%|
[sorbs_web](#sorbs_web)|619|619|92|14.8%|0.2%|
[php_dictionary](#php_dictionary)|589|589|90|15.2%|0.2%|
[snort_ipfilter](#snort_ipfilter)|9812|9812|83|0.8%|0.2%|
[php_spammers](#php_spammers)|580|580|75|12.9%|0.1%|
[stopforumspam_7d](#stopforumspam_7d)|29870|29870|69|0.2%|0.1%|
[ri_web_proxies](#ri_web_proxies)|6972|6828|53|0.7%|0.1%|
[et_block](#et_block)|1023|18338662|49|0.0%|0.1%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|48|0.0%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|48|0.0%|0.1%|
[stopforumspam_1d](#stopforumspam_1d)|6093|6093|32|0.5%|0.0%|
[alienvault_reputation](#alienvault_reputation)|178903|178903|30|0.0%|0.0%|
[xroxy](#xroxy)|2115|2115|28|1.3%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2180|2180|26|1.1%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|2976|2976|26|0.8%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4042|4042|22|0.5%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|15388|15388|22|0.1%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47941|47941|16|0.0%|0.0%|
[proxz](#proxz)|967|967|15|1.5%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|635|635|12|1.8%|0.0%|
[php_commenters](#php_commenters)|349|349|11|3.1%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|10|0.0%|0.0%|
[openbl_60d](#openbl_60d)|7254|7254|9|0.1%|0.0%|
[sorbs_socks](#sorbs_socks)|20|20|7|35.0%|0.0%|
[sorbs_misc](#sorbs_misc)|20|20|7|35.0%|0.0%|
[sorbs_http](#sorbs_http)|20|20|7|35.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2665|2516|7|0.2%|0.0%|
[proxyrss](#proxyrss)|1435|1435|6|0.4%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2572|2572|6|0.2%|0.0%|
[php_harvesters](#php_harvesters)|324|324|5|1.5%|0.0%|
[openbl_30d](#openbl_30d)|3245|3245|4|0.1%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|2|0.0%|0.0%|
[openbl_7d](#openbl_7d)|816|816|2|0.2%|0.0%|
[voipbl](#voipbl)|10476|10888|1|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|1|0.1%|0.0%|
[et_compromised](#et_compromised)|2016|2016|1|0.0%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|310|310|1|0.3%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1720|1720|1|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|165|165|1|0.6%|0.0%|

## openbl_1d

[OpenBL.org](http://www.openbl.org/) last 24 hours IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.

Source is downloaded from [this link](http://www.openbl.org/lists/base_1days.txt).

The last time downloaded was found to be dated: Sun Jun  7 11:57:00 UTC 2015.

The ipset `openbl_1d` has **116** entries, **116** unique IPs.

The following table shows the overlaps of `openbl_1d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl_1d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl_1d`.
- ` this % ` is the percentage **of this ipset (`openbl_1d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[openbl_7d](#openbl_7d)|816|816|116|14.2%|100.0%|
[openbl_60d](#openbl_60d)|7254|7254|116|1.5%|100.0%|
[openbl_30d](#openbl_30d)|3245|3245|116|3.5%|100.0%|
[alienvault_reputation](#alienvault_reputation)|178903|178903|113|0.0%|97.4%|
[blocklist_de](#blocklist_de)|27586|27586|86|0.3%|74.1%|
[blocklist_de_ssh](#blocklist_de_ssh)|2572|2572|83|3.2%|71.5%|
[shunlist](#shunlist)|1245|1245|54|4.3%|46.5%|
[et_compromised](#et_compromised)|2016|2016|44|2.1%|37.9%|
[bruteforceblocker](#bruteforceblocker)|1720|1720|41|2.3%|35.3%|
[blocklist_de_strongips](#blocklist_de_strongips)|165|165|19|11.5%|16.3%|
[et_block](#et_block)|1023|18338662|12|0.0%|10.3%|
[dshield](#dshield)|20|5120|12|0.2%|10.3%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|11|0.0%|9.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17813|139104928|10|0.0%|8.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72952|348710247|6|0.0%|5.1%|
[blocklist_de_mail](#blocklist_de_mail)|17025|17025|3|0.0%|2.5%|
[blocklist_de_imap](#blocklist_de_imap)|2180|2180|2|0.0%|1.7%|
[stopforumspam_30d](#stopforumspam_30d)|93068|93068|1|0.0%|0.8%|
[php_spammers](#php_spammers)|580|580|1|0.1%|0.8%|
[php_commenters](#php_commenters)|349|349|1|0.2%|0.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218315|764993617|1|0.0%|0.8%|

## openbl_30d

[OpenBL.org](http://www.openbl.org/) last 30 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.

Source is downloaded from [this link](http://www.openbl.org/lists/base_30days.txt).

The last time downloaded was found to be dated: Sun Jun  7 11:57:00 UTC 2015.

The ipset `openbl_30d` has **3245** entries, **3245** unique IPs.

The following table shows the overlaps of `openbl_30d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl_30d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl_30d`.
- ` this % ` is the percentage **of this ipset (`openbl_30d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[openbl_60d](#openbl_60d)|7254|7254|3245|44.7%|100.0%|
[alienvault_reputation](#alienvault_reputation)|178903|178903|3227|1.8%|99.4%|
[et_compromised](#et_compromised)|2016|2016|1144|56.7%|35.2%|
[bruteforceblocker](#bruteforceblocker)|1720|1720|973|56.5%|29.9%|
[openbl_7d](#openbl_7d)|816|816|816|100.0%|25.1%|
[blocklist_de](#blocklist_de)|27586|27586|710|2.5%|21.8%|
[blocklist_de_ssh](#blocklist_de_ssh)|2572|2572|659|25.6%|20.3%|
[shunlist](#shunlist)|1245|1245|532|42.7%|16.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17813|139104928|314|0.0%|9.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72952|348710247|170|0.0%|5.2%|
[et_block](#et_block)|1023|18338662|162|0.0%|4.9%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|156|0.0%|4.8%|
[dshield](#dshield)|20|5120|128|2.5%|3.9%|
[openbl_1d](#openbl_1d)|116|116|116|100.0%|3.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218315|764993617|69|0.0%|2.1%|
[blocklist_de_mail](#blocklist_de_mail)|17025|17025|42|0.2%|1.2%|
[blocklist_de_imap](#blocklist_de_imap)|2180|2180|36|1.6%|1.1%|
[blocklist_de_strongips](#blocklist_de_strongips)|165|165|24|14.5%|0.7%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|13|0.0%|0.4%|
[blocklist_de_apache](#blocklist_de_apache)|15388|15388|6|0.0%|0.1%|
[snort_ipfilter](#snort_ipfilter)|9812|9812|5|0.0%|0.1%|
[stopforumspam_30d](#stopforumspam_30d)|93068|93068|4|0.0%|0.1%|
[nixspam](#nixspam)|39997|39997|4|0.0%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|4|0.0%|0.1%|
[voipbl](#voipbl)|10476|10888|3|0.0%|0.0%|
[zeus](#zeus)|232|232|2|0.8%|0.0%|
[sorbs_spam](#sorbs_spam)|45326|46326|2|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|45326|46326|2|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|45326|46326|2|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|2|0.1%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|2976|2976|2|0.0%|0.0%|
[zeus_badips](#zeus_badips)|203|203|1|0.4%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29870|29870|1|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6093|6093|1|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|1|0.0%|0.0%|
[sorbs_web](#sorbs_web)|619|619|1|0.1%|0.0%|
[php_spammers](#php_spammers)|580|580|1|0.1%|0.0%|
[php_commenters](#php_commenters)|349|349|1|0.2%|0.0%|

## openbl_60d

[OpenBL.org](http://www.openbl.org/) last 60 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.

Source is downloaded from [this link](http://www.openbl.org/lists/base_60days.txt).

The last time downloaded was found to be dated: Sun Jun  7 11:57:00 UTC 2015.

The ipset `openbl_60d` has **7254** entries, **7254** unique IPs.

The following table shows the overlaps of `openbl_60d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl_60d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl_60d`.
- ` this % ` is the percentage **of this ipset (`openbl_60d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[alienvault_reputation](#alienvault_reputation)|178903|178903|7231|4.0%|99.6%|
[openbl_30d](#openbl_30d)|3245|3245|3245|100.0%|44.7%|
[et_compromised](#et_compromised)|2016|2016|1216|60.3%|16.7%|
[bruteforceblocker](#bruteforceblocker)|1720|1720|1005|58.4%|13.8%|
[blocklist_de](#blocklist_de)|27586|27586|884|3.2%|12.1%|
[openbl_7d](#openbl_7d)|816|816|816|100.0%|11.2%|
[blocklist_de_ssh](#blocklist_de_ssh)|2572|2572|816|31.7%|11.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|17813|139104928|743|0.0%|10.2%|
[shunlist](#shunlist)|1245|1245|548|44.0%|7.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72952|348710247|327|0.0%|4.5%|
[et_block](#et_block)|1023|18338662|250|0.0%|3.4%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|239|0.0%|3.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|218315|764993617|167|0.0%|2.3%|
[dshield](#dshield)|20|5120|141|2.7%|1.9%|
[openbl_1d](#openbl_1d)|116|116|116|100.0%|1.5%|
[stopforumspam_30d](#stopforumspam_30d)|93068|93068|53|0.0%|0.7%|
[blocklist_de_mail](#blocklist_de_mail)|17025|17025|48|0.2%|0.6%|
[blocklist_de_imap](#blocklist_de_imap)|2180|2180|41|1.8%|0.5%|
[snort_ipfilter](#snort_ipfilter)|9812|9812|28|0.2%|0.3%|
[blocklist_de_strongips](#blocklist_de_strongips)|165|165|26|15.7%|0.3%|
[stopforumspam_7d](#stopforumspam_7d)|29870|29870|24|0.0%|0.3%|
[stopforumspam_1d](#stopforumspam_1d)|6093|6093|21|0.3%|0.2%|
[et_tor](#et_tor)|6470|6470|20|0.3%|0.2%|
[dm_tor](#dm_tor)|6516|6516|20|0.3%|0.2%|
[bm_tor](#bm_tor)|6522|6522|20|0.3%|0.2%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|18|4.8%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|17|0.0%|0.2%|
[blocklist_de_bots](#blocklist_de_bots)|2976|2976|11|0.3%|0.1%|
[sorbs_spam](#sorbs_spam)|45326|46326|10|0.0%|0.1%|
[sorbs_recent_spam](#sorbs_recent_spam)|45326|46326|10|0.0%|0.1%|
[sorbs_new_spam](#sorbs_new_spam)|45326|46326|10|0.0%|0.1%|
[php_commenters](#php_commenters)|349|349|10|2.8%|0.1%|
[nixspam](#nixspam)|39997|39997|9|0.0%|0.1%|
[voipbl](#voipbl)|10476|10888|8|0.0%|0.1%|
[blocklist_de_apache](#blocklist_de_apache)|15388|15388|8|0.0%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|5|0.0%|0.0%|
[zeus](#zeus)|232|232|2|0.8%|0.0%|
[php_harvesters](#php_harvesters)|324|324|2|0.6%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|2|0.1%|0.0%|
[zeus_badips](#zeus_badips)|203|203|1|0.4%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|1|0.0%|0.0%|
[sorbs_web](#sorbs_web)|619|619|1|0.1%|0.0%|
[php_spammers](#php_spammers)|580|580|1|0.1%|0.0%|

## openbl_7d

[OpenBL.org](http://www.openbl.org/) last 7 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.

Source is downloaded from [this link](http://www.openbl.org/lists/base_7days.txt).

The last time downloaded was found to be dated: Sun Jun  7 11:57:00 UTC 2015.

The ipset `openbl_7d` has **816** entries, **816** unique IPs.

The following table shows the overlaps of `openbl_7d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl_7d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl_7d`.
- ` this % ` is the percentage **of this ipset (`openbl_7d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[openbl_60d](#openbl_60d)|7254|7254|816|11.2%|100.0%|
[openbl_30d](#openbl_30d)|3245|3245|816|25.1%|100.0%|
[alienvault_reputation](#alienvault_reputation)|178903|178903|808|0.4%|99.0%|
[blocklist_de](#blocklist_de)|27586|27586|411|1.4%|50.3%|
[blocklist_de_ssh](#blocklist_de_ssh)|2572|2572|394|15.3%|48.2%|
[et_compromised](#et_compromised)|2016|2016|333|16.5%|40.8%|
[bruteforceblocker](#bruteforceblocker)|1720|1720|326|18.9%|39.9%|
[shunlist](#shunlist)|1245|1245|220|17.6%|26.9%|
[openbl_1d](#openbl_1d)|116|116|116|100.0%|14.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|17813|139104928|111|0.0%|13.6%|
[et_block](#et_block)|1023|18338662|49|0.0%|6.0%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|46|0.0%|5.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72952|348710247|43|0.0%|5.2%|
[dshield](#dshield)|20|5120|42|0.8%|5.1%|
[blocklist_de_strongips](#blocklist_de_strongips)|165|165|24|14.5%|2.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|218315|764993617|18|0.0%|2.2%|
[blocklist_de_mail](#blocklist_de_mail)|17025|17025|15|0.0%|1.8%|
[blocklist_de_imap](#blocklist_de_imap)|2180|2180|13|0.5%|1.5%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|5|0.0%|0.6%|
[stopforumspam_30d](#stopforumspam_30d)|93068|93068|3|0.0%|0.3%|
[nixspam](#nixspam)|39997|39997|2|0.0%|0.2%|
[sorbs_spam](#sorbs_spam)|45326|46326|1|0.0%|0.1%|
[sorbs_recent_spam](#sorbs_recent_spam)|45326|46326|1|0.0%|0.1%|
[sorbs_new_spam](#sorbs_new_spam)|45326|46326|1|0.0%|0.1%|
[snort_ipfilter](#snort_ipfilter)|9812|9812|1|0.0%|0.1%|
[php_spammers](#php_spammers)|580|580|1|0.1%|0.1%|
[php_commenters](#php_commenters)|349|349|1|0.2%|0.1%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|1|0.0%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.1%|
[blocklist_de_apache](#blocklist_de_apache)|15388|15388|1|0.0%|0.1%|

## palevo

[Abuse.ch Palevo tracker](https://palevotracker.abuse.ch) worm includes IPs which are being used as botnet C&C for the Palevo crimeware - **excellent list**

Source is downloaded from [this link](https://palevotracker.abuse.ch/blocklists.php?download=ipblocklist).

The last time downloaded was found to be dated: Sun Jun  7 12:41:09 UTC 2015.

The ipset `palevo` has **13** entries, **13** unique IPs.

The following table shows the overlaps of `palevo` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `palevo`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `palevo`.
- ` this % ` is the percentage **of this ipset (`palevo`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[et_block](#et_block)|1023|18338662|12|0.0%|92.3%|
[snort_ipfilter](#snort_ipfilter)|9812|9812|11|0.1%|84.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72952|348710247|3|0.0%|23.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|2|0.0%|15.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17813|139104928|1|0.0%|7.6%|

## php_commenters

[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) comment spammers (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=c&rss=1).

The last time downloaded was found to be dated: Sun Jun  7 11:43:06 UTC 2015.

The ipset `php_commenters` has **349** entries, **349** unique IPs.

The following table shows the overlaps of `php_commenters` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `php_commenters`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `php_commenters`.
- ` this % ` is the percentage **of this ipset (`php_commenters`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_30d](#stopforumspam_30d)|93068|93068|255|0.2%|73.0%|
[stopforumspam_7d](#stopforumspam_7d)|29870|29870|186|0.6%|53.2%|
[stopforumspam_1d](#stopforumspam_1d)|6093|6093|126|2.0%|36.1%|
[blocklist_de](#blocklist_de)|27586|27586|84|0.3%|24.0%|
[blocklist_de_bots](#blocklist_de_bots)|2976|2976|66|2.2%|18.9%|
[snort_ipfilter](#snort_ipfilter)|9812|9812|45|0.4%|12.8%|
[php_spammers](#php_spammers)|580|580|39|6.7%|11.1%|
[et_tor](#et_tor)|6470|6470|37|0.5%|10.6%|
[dm_tor](#dm_tor)|6516|6516|36|0.5%|10.3%|
[bm_tor](#bm_tor)|6522|6522|36|0.5%|10.3%|
[blocklist_de_strongips](#blocklist_de_strongips)|165|165|35|21.2%|10.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|34|9.1%|9.7%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|28|0.0%|8.0%|
[et_block](#et_block)|1023|18338662|28|0.0%|8.0%|
[blocklist_de_apache](#blocklist_de_apache)|15388|15388|26|0.1%|7.4%|
[php_dictionary](#php_dictionary)|589|589|25|4.2%|7.1%|
[ri_web_proxies](#ri_web_proxies)|6972|6828|23|0.3%|6.5%|
[blocklist_de_mail](#blocklist_de_mail)|17025|17025|23|0.1%|6.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17813|139104928|22|0.0%|6.3%|
[alienvault_reputation](#alienvault_reputation)|178903|178903|18|0.0%|5.1%|
[sorbs_spam](#sorbs_spam)|45326|46326|16|0.0%|4.5%|
[sorbs_recent_spam](#sorbs_recent_spam)|45326|46326|16|0.0%|4.5%|
[sorbs_new_spam](#sorbs_new_spam)|45326|46326|16|0.0%|4.5%|
[php_harvesters](#php_harvesters)|324|324|14|4.3%|4.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72952|348710247|14|0.0%|4.0%|
[nixspam](#nixspam)|39997|39997|11|0.0%|3.1%|
[openbl_60d](#openbl_60d)|7254|7254|10|0.1%|2.8%|
[xroxy](#xroxy)|2115|2115|8|0.3%|2.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|218315|764993617|8|0.0%|2.2%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4042|4042|8|0.1%|2.2%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|7|0.0%|2.0%|
[proxz](#proxz)|967|967|7|0.7%|2.0%|
[proxyrss](#proxyrss)|1435|1435|6|0.4%|1.7%|
[ri_connect_proxies](#ri_connect_proxies)|2665|2516|5|0.1%|1.4%|
[sorbs_web](#sorbs_web)|619|619|2|0.3%|0.5%|
[zeus_badips](#zeus_badips)|203|203|1|0.4%|0.2%|
[zeus](#zeus)|232|232|1|0.4%|0.2%|
[openbl_7d](#openbl_7d)|816|816|1|0.1%|0.2%|
[openbl_30d](#openbl_30d)|3245|3245|1|0.0%|0.2%|
[openbl_1d](#openbl_1d)|116|116|1|0.8%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.2%|
[fullbogons](#fullbogons)|3720|670264216|1|0.0%|0.2%|
[bruteforceblocker](#bruteforceblocker)|1720|1720|1|0.0%|0.2%|
[bogons](#bogons)|13|592708608|1|0.0%|0.2%|
[blocklist_de_ssh](#blocklist_de_ssh)|2572|2572|1|0.0%|0.2%|
[blocklist_de_imap](#blocklist_de_imap)|2180|2180|1|0.0%|0.2%|

## php_dictionary

[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) directory attackers (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=d&rss=1).

The last time downloaded was found to be dated: Sun Jun  7 11:43:08 UTC 2015.

The ipset `php_dictionary` has **589** entries, **589** unique IPs.

The following table shows the overlaps of `php_dictionary` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `php_dictionary`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `php_dictionary`.
- ` this % ` is the percentage **of this ipset (`php_dictionary`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[php_spammers](#php_spammers)|580|580|210|36.2%|35.6%|
[sorbs_spam](#sorbs_spam)|45326|46326|181|0.3%|30.7%|
[sorbs_recent_spam](#sorbs_recent_spam)|45326|46326|181|0.3%|30.7%|
[sorbs_new_spam](#sorbs_new_spam)|45326|46326|181|0.3%|30.7%|
[stopforumspam_30d](#stopforumspam_30d)|93068|93068|110|0.1%|18.6%|
[nixspam](#nixspam)|39997|39997|90|0.2%|15.2%|
[blocklist_de](#blocklist_de)|27586|27586|85|0.3%|14.4%|
[stopforumspam_7d](#stopforumspam_7d)|29870|29870|71|0.2%|12.0%|
[snort_ipfilter](#snort_ipfilter)|9812|9812|68|0.6%|11.5%|
[blocklist_de_mail](#blocklist_de_mail)|17025|17025|57|0.3%|9.6%|
[ri_web_proxies](#ri_web_proxies)|6972|6828|46|0.6%|7.8%|
[xroxy](#xroxy)|2115|2115|35|1.6%|5.9%|
[stopforumspam_1d](#stopforumspam_1d)|6093|6093|32|0.5%|5.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17813|139104928|31|0.0%|5.2%|
[sorbs_web](#sorbs_web)|619|619|26|4.2%|4.4%|
[php_commenters](#php_commenters)|349|349|25|7.1%|4.2%|
[blocklist_de_bots](#blocklist_de_bots)|2976|2976|24|0.8%|4.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72952|348710247|20|0.0%|3.3%|
[proxz](#proxz)|967|967|17|1.7%|2.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218315|764993617|11|0.0%|1.8%|
[alienvault_reputation](#alienvault_reputation)|178903|178903|8|0.0%|1.3%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|5|0.0%|0.8%|
[et_tor](#et_tor)|6470|6470|5|0.0%|0.8%|
[et_block](#et_block)|1023|18338662|5|0.0%|0.8%|
[ri_connect_proxies](#ri_connect_proxies)|2665|2516|4|0.1%|0.6%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|4|1.0%|0.6%|
[proxyrss](#proxyrss)|1435|1435|3|0.2%|0.5%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|0.5%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47941|47941|3|0.0%|0.5%|
[dm_tor](#dm_tor)|6516|6516|3|0.0%|0.5%|
[bm_tor](#bm_tor)|6522|6522|3|0.0%|0.5%|
[blocklist_de_strongips](#blocklist_de_strongips)|165|165|3|1.8%|0.5%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4042|4042|3|0.0%|0.5%|
[blocklist_de_apache](#blocklist_de_apache)|15388|15388|3|0.0%|0.5%|
[sorbs_socks](#sorbs_socks)|20|20|2|10.0%|0.3%|
[sorbs_misc](#sorbs_misc)|20|20|2|10.0%|0.3%|
[sorbs_http](#sorbs_http)|20|20|2|10.0%|0.3%|
[php_harvesters](#php_harvesters)|324|324|2|0.6%|0.3%|
[blocklist_de_imap](#blocklist_de_imap)|2180|2180|2|0.0%|0.3%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.1%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|1|0.1%|0.1%|
[blocklist_de_ftp](#blocklist_de_ftp)|635|635|1|0.1%|0.1%|

## php_harvesters

[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) harvesters (IPs that surf the internet looking for email addresses) (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=h&rss=1).

The last time downloaded was found to be dated: Sun Jun  7 11:43:01 UTC 2015.

The ipset `php_harvesters` has **324** entries, **324** unique IPs.

The following table shows the overlaps of `php_harvesters` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `php_harvesters`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `php_harvesters`.
- ` this % ` is the percentage **of this ipset (`php_harvesters`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_30d](#stopforumspam_30d)|93068|93068|74|0.0%|22.8%|
[stopforumspam_7d](#stopforumspam_7d)|29870|29870|55|0.1%|16.9%|
[stopforumspam_1d](#stopforumspam_1d)|6093|6093|38|0.6%|11.7%|
[blocklist_de](#blocklist_de)|27586|27586|29|0.1%|8.9%|
[blocklist_de_bots](#blocklist_de_bots)|2976|2976|22|0.7%|6.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|17813|139104928|17|0.0%|5.2%|
[php_commenters](#php_commenters)|349|349|14|4.0%|4.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218315|764993617|11|0.0%|3.3%|
[snort_ipfilter](#snort_ipfilter)|9812|9812|10|0.1%|3.0%|
[alienvault_reputation](#alienvault_reputation)|178903|178903|10|0.0%|3.0%|
[sorbs_spam](#sorbs_spam)|45326|46326|9|0.0%|2.7%|
[sorbs_recent_spam](#sorbs_recent_spam)|45326|46326|9|0.0%|2.7%|
[sorbs_new_spam](#sorbs_new_spam)|45326|46326|9|0.0%|2.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72952|348710247|9|0.0%|2.7%|
[et_tor](#et_tor)|6470|6470|7|0.1%|2.1%|
[dm_tor](#dm_tor)|6516|6516|7|0.1%|2.1%|
[bm_tor](#bm_tor)|6522|6522|7|0.1%|2.1%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|6|1.6%|1.8%|
[nixspam](#nixspam)|39997|39997|5|0.0%|1.5%|
[blocklist_de_ftp](#blocklist_de_ftp)|635|635|4|0.6%|1.2%|
[blocklist_de_strongips](#blocklist_de_strongips)|165|165|3|1.8%|0.9%|
[blocklist_de_apache](#blocklist_de_apache)|15388|15388|3|0.0%|0.9%|
[xroxy](#xroxy)|2115|2115|2|0.0%|0.6%|
[ri_web_proxies](#ri_web_proxies)|6972|6828|2|0.0%|0.6%|
[php_spammers](#php_spammers)|580|580|2|0.3%|0.6%|
[php_dictionary](#php_dictionary)|589|589|2|0.3%|0.6%|
[openbl_60d](#openbl_60d)|7254|7254|2|0.0%|0.6%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47941|47941|2|0.0%|0.6%|
[blocklist_de_mail](#blocklist_de_mail)|17025|17025|2|0.0%|0.6%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4042|4042|2|0.0%|0.6%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|1|0.0%|0.3%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|1|0.0%|0.3%|
[proxyrss](#proxyrss)|1435|1435|1|0.0%|0.3%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.3%|
[fullbogons](#fullbogons)|3720|670264216|1|0.0%|0.3%|
[et_block](#et_block)|1023|18338662|1|0.0%|0.3%|
[bogons](#bogons)|13|592708608|1|0.0%|0.3%|

## php_spammers

[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) spam servers (IPs used by spammers to send messages) (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=s&rss=1).

The last time downloaded was found to be dated: Sun Jun  7 11:43:04 UTC 2015.

The ipset `php_spammers` has **580** entries, **580** unique IPs.

The following table shows the overlaps of `php_spammers` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `php_spammers`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `php_spammers`.
- ` this % ` is the percentage **of this ipset (`php_spammers`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[php_dictionary](#php_dictionary)|589|589|210|35.6%|36.2%|
[sorbs_spam](#sorbs_spam)|45326|46326|158|0.3%|27.2%|
[sorbs_recent_spam](#sorbs_recent_spam)|45326|46326|158|0.3%|27.2%|
[sorbs_new_spam](#sorbs_new_spam)|45326|46326|158|0.3%|27.2%|
[stopforumspam_30d](#stopforumspam_30d)|93068|93068|122|0.1%|21.0%|
[blocklist_de](#blocklist_de)|27586|27586|86|0.3%|14.8%|
[nixspam](#nixspam)|39997|39997|75|0.1%|12.9%|
[snort_ipfilter](#snort_ipfilter)|9812|9812|67|0.6%|11.5%|
[stopforumspam_7d](#stopforumspam_7d)|29870|29870|66|0.2%|11.3%|
[blocklist_de_mail](#blocklist_de_mail)|17025|17025|55|0.3%|9.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|72952|348710247|49|0.0%|8.4%|
[ri_web_proxies](#ri_web_proxies)|6972|6828|41|0.6%|7.0%|
[php_commenters](#php_commenters)|349|349|39|11.1%|6.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|17813|139104928|32|0.0%|5.5%|
[stopforumspam_1d](#stopforumspam_1d)|6093|6093|31|0.5%|5.3%|
[xroxy](#xroxy)|2115|2115|27|1.2%|4.6%|
[sorbs_web](#sorbs_web)|619|619|23|3.7%|3.9%|
[blocklist_de_bots](#blocklist_de_bots)|2976|2976|23|0.7%|3.9%|
[proxz](#proxz)|967|967|18|1.8%|3.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|218315|764993617|8|0.0%|1.3%|
[et_tor](#et_tor)|6470|6470|6|0.0%|1.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4042|4042|6|0.1%|1.0%|
[blocklist_de_apache](#blocklist_de_apache)|15388|15388|6|0.0%|1.0%|
[alienvault_reputation](#alienvault_reputation)|178903|178903|6|0.0%|1.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|165|165|5|3.0%|0.8%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|4|0.0%|0.6%|
[proxyrss](#proxyrss)|1435|1435|4|0.2%|0.6%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|4|1.0%|0.6%|
[dm_tor](#dm_tor)|6516|6516|4|0.0%|0.6%|
[bm_tor](#bm_tor)|6522|6522|4|0.0%|0.6%|
[ri_connect_proxies](#ri_connect_proxies)|2665|2516|3|0.1%|0.5%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|0.5%|
[et_block](#et_block)|1023|18338662|3|0.0%|0.5%|
[php_harvesters](#php_harvesters)|324|324|2|0.6%|0.3%|
[sorbs_socks](#sorbs_socks)|20|20|1|5.0%|0.1%|
[sorbs_misc](#sorbs_misc)|20|20|1|5.0%|0.1%|
[sorbs_http](#sorbs_http)|20|20|1|5.0%|0.1%|
[openbl_7d](#openbl_7d)|816|816|1|0.1%|0.1%|
[openbl_60d](#openbl_60d)|7254|7254|1|0.0%|0.1%|
[openbl_30d](#openbl_30d)|3245|3245|1|0.0%|0.1%|
[openbl_1d](#openbl_1d)|116|116|1|0.8%|0.1%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47941|47941|1|0.0%|0.1%|
[bruteforceblocker](#bruteforceblocker)|1720|1720|1|0.0%|0.1%|
[blocklist_de_ssh](#blocklist_de_ssh)|2572|2572|1|0.0%|0.1%|
[blocklist_de_imap](#blocklist_de_imap)|2180|2180|1|0.0%|0.1%|
[blocklist_de_ftp](#blocklist_de_ftp)|635|635|1|0.1%|0.1%|

## proxyrss

[proxyrss.com](http://www.proxyrss.com) open proxies syndicated from multiple sources.

Source is downloaded from [this link](http://www.proxyrss.com/proxylists/all.gz).

The last time downloaded was found to be dated: Sun Jun  7 10:01:32 UTC 2015.

The ipset `proxyrss` has **1435** entries, **1435** unique IPs.

The following table shows the overlaps of `proxyrss` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `proxyrss`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `proxyrss`.
- ` this % ` is the percentage **of this ipset (`proxyrss`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_30d](#stopforumspam_30d)|93068|93068|709|0.7%|49.4%|
[ri_web_proxies](#ri_web_proxies)|6972|6828|621|9.0%|43.2%|
[stopforumspam_7d](#stopforumspam_7d)|29870|29870|566|1.8%|39.4%|
[xroxy](#xroxy)|2115|2115|381|18.0%|26.5%|
[stopforumspam_1d](#stopforumspam_1d)|6093|6093|334|5.4%|23.2%|
[proxz](#proxz)|967|967|248|25.6%|17.2%|
[ri_connect_proxies](#ri_connect_proxies)|2665|2516|230|9.1%|16.0%|
[blocklist_de](#blocklist_de)|27586|27586|195|0.7%|13.5%|
[blocklist_de_bots](#blocklist_de_bots)|2976|2976|192|6.4%|13.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72952|348710247|60|0.0%|4.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17813|139104928|50|0.0%|3.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218315|764993617|45|0.0%|3.1%|
[sorbs_spam](#sorbs_spam)|45326|46326|11|0.0%|0.7%|
[sorbs_recent_spam](#sorbs_recent_spam)|45326|46326|11|0.0%|0.7%|
[sorbs_new_spam](#sorbs_new_spam)|45326|46326|11|0.0%|0.7%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|8|1.2%|0.5%|
[php_commenters](#php_commenters)|349|349|6|1.7%|0.4%|
[nixspam](#nixspam)|39997|39997|6|0.0%|0.4%|
[php_spammers](#php_spammers)|580|580|4|0.6%|0.2%|
[php_dictionary](#php_dictionary)|589|589|3|0.5%|0.2%|
[blocklist_de_strongips](#blocklist_de_strongips)|165|165|3|1.8%|0.2%|
[snort_ipfilter](#snort_ipfilter)|9812|9812|2|0.0%|0.1%|
[blocklist_de_mail](#blocklist_de_mail)|17025|17025|2|0.0%|0.1%|
[php_harvesters](#php_harvesters)|324|324|1|0.3%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.0%|
[et_compromised](#et_compromised)|2016|2016|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1720|1720|1|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|15388|15388|1|0.0%|0.0%|

## proxz

[proxz.com](http://www.proxz.com) open proxies (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.proxz.com/proxylists.xml).

The last time downloaded was found to be dated: Sun Jun  7 12:11:33 UTC 2015.

The ipset `proxz` has **967** entries, **967** unique IPs.

The following table shows the overlaps of `proxz` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `proxz`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `proxz`.
- ` this % ` is the percentage **of this ipset (`proxz`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_30d](#stopforumspam_30d)|93068|93068|590|0.6%|61.0%|
[stopforumspam_7d](#stopforumspam_7d)|29870|29870|440|1.4%|45.5%|
[ri_web_proxies](#ri_web_proxies)|6972|6828|439|6.4%|45.3%|
[xroxy](#xroxy)|2115|2115|363|17.1%|37.5%|
[proxyrss](#proxyrss)|1435|1435|248|17.2%|25.6%|
[ri_connect_proxies](#ri_connect_proxies)|2665|2516|157|6.2%|16.2%|
[stopforumspam_1d](#stopforumspam_1d)|6093|6093|151|2.4%|15.6%|
[blocklist_de](#blocklist_de)|27586|27586|146|0.5%|15.0%|
[blocklist_de_bots](#blocklist_de_bots)|2976|2976|120|4.0%|12.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17813|139104928|80|0.0%|8.2%|
[sorbs_spam](#sorbs_spam)|45326|46326|43|0.0%|4.4%|
[sorbs_recent_spam](#sorbs_recent_spam)|45326|46326|43|0.0%|4.4%|
[sorbs_new_spam](#sorbs_new_spam)|45326|46326|43|0.0%|4.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|72952|348710247|38|0.0%|3.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|218315|764993617|34|0.0%|3.5%|
[blocklist_de_mail](#blocklist_de_mail)|17025|17025|24|0.1%|2.4%|
[snort_ipfilter](#snort_ipfilter)|9812|9812|21|0.2%|2.1%|
[php_spammers](#php_spammers)|580|580|18|3.1%|1.8%|
[php_dictionary](#php_dictionary)|589|589|17|2.8%|1.7%|
[nixspam](#nixspam)|39997|39997|15|0.0%|1.5%|
[sorbs_web](#sorbs_web)|619|619|8|1.2%|0.8%|
[php_commenters](#php_commenters)|349|349|7|2.0%|0.7%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|6|0.9%|0.6%|
[blocklist_de_strongips](#blocklist_de_strongips)|165|165|4|2.4%|0.4%|
[alienvault_reputation](#alienvault_reputation)|178903|178903|3|0.0%|0.3%|
[et_compromised](#et_compromised)|2016|2016|2|0.0%|0.2%|
[bruteforceblocker](#bruteforceblocker)|1720|1720|2|0.1%|0.2%|
[blocklist_de_apache](#blocklist_de_apache)|15388|15388|2|0.0%|0.2%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47941|47941|1|0.0%|0.1%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4042|4042|1|0.0%|0.1%|

## ri_connect_proxies

[rosinstrument.com](http://www.rosinstrument.com) open CONNECT proxies (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://tools.rosinstrument.com/proxy/plab100.xml).

The last time downloaded was found to be dated: Sun Jun  7 05:34:43 UTC 2015.

The ipset `ri_connect_proxies` has **2665** entries, **2516** unique IPs.

The following table shows the overlaps of `ri_connect_proxies` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ri_connect_proxies`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ri_connect_proxies`.
- ` this % ` is the percentage **of this ipset (`ri_connect_proxies`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_30d](#stopforumspam_30d)|93068|93068|1440|1.5%|57.2%|
[ri_web_proxies](#ri_web_proxies)|6972|6828|1055|15.4%|41.9%|
[stopforumspam_7d](#stopforumspam_7d)|29870|29870|635|2.1%|25.2%|
[xroxy](#xroxy)|2115|2115|369|17.4%|14.6%|
[proxyrss](#proxyrss)|1435|1435|230|16.0%|9.1%|
[proxz](#proxz)|967|967|157|16.2%|6.2%|
[stopforumspam_1d](#stopforumspam_1d)|6093|6093|103|1.6%|4.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72952|348710247|97|0.0%|3.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218315|764993617|79|0.0%|3.1%|
[blocklist_de](#blocklist_de)|27586|27586|64|0.2%|2.5%|
[blocklist_de_bots](#blocklist_de_bots)|2976|2976|61|2.0%|2.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17813|139104928|53|0.0%|2.1%|
[sorbs_spam](#sorbs_spam)|45326|46326|10|0.0%|0.3%|
[sorbs_recent_spam](#sorbs_recent_spam)|45326|46326|10|0.0%|0.3%|
[sorbs_new_spam](#sorbs_new_spam)|45326|46326|10|0.0%|0.3%|
[nixspam](#nixspam)|39997|39997|7|0.0%|0.2%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|7|1.0%|0.2%|
[php_commenters](#php_commenters)|349|349|5|1.4%|0.1%|
[php_dictionary](#php_dictionary)|589|589|4|0.6%|0.1%|
[php_spammers](#php_spammers)|580|580|3|0.5%|0.1%|
[alienvault_reputation](#alienvault_reputation)|178903|178903|3|0.0%|0.1%|
[snort_ipfilter](#snort_ipfilter)|9812|9812|2|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|17025|17025|2|0.0%|0.0%|
[sorbs_web](#sorbs_web)|619|619|1|0.1%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.0%|
[et_tor](#et_tor)|6470|6470|1|0.0%|0.0%|
[dm_tor](#dm_tor)|6516|6516|1|0.0%|0.0%|
[bm_tor](#bm_tor)|6522|6522|1|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4042|4042|1|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|15388|15388|1|0.0%|0.0%|

## ri_web_proxies

[rosinstrument.com](http://www.rosinstrument.com) open HTTP proxies (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://tools.rosinstrument.com/proxy/l100.xml).

The last time downloaded was found to be dated: Sun Jun  7 06:29:38 UTC 2015.

The ipset `ri_web_proxies` has **6972** entries, **6828** unique IPs.

The following table shows the overlaps of `ri_web_proxies` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ri_web_proxies`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ri_web_proxies`.
- ` this % ` is the percentage **of this ipset (`ri_web_proxies`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_30d](#stopforumspam_30d)|93068|93068|3277|3.5%|47.9%|
[stopforumspam_7d](#stopforumspam_7d)|29870|29870|1624|5.4%|23.7%|
[ri_connect_proxies](#ri_connect_proxies)|2665|2516|1055|41.9%|15.4%|
[xroxy](#xroxy)|2115|2115|910|43.0%|13.3%|
[proxyrss](#proxyrss)|1435|1435|621|43.2%|9.0%|
[stopforumspam_1d](#stopforumspam_1d)|6093|6093|458|7.5%|6.7%|
[proxz](#proxz)|967|967|439|45.3%|6.4%|
[blocklist_de](#blocklist_de)|27586|27586|364|1.3%|5.3%|
[blocklist_de_bots](#blocklist_de_bots)|2976|2976|304|10.2%|4.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|72952|348710247|198|0.0%|2.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17813|139104928|195|0.0%|2.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218315|764993617|136|0.0%|1.9%|
[sorbs_spam](#sorbs_spam)|45326|46326|130|0.2%|1.9%|
[sorbs_recent_spam](#sorbs_recent_spam)|45326|46326|130|0.2%|1.9%|
[sorbs_new_spam](#sorbs_new_spam)|45326|46326|130|0.2%|1.9%|
[blocklist_de_mail](#blocklist_de_mail)|17025|17025|58|0.3%|0.8%|
[snort_ipfilter](#snort_ipfilter)|9812|9812|53|0.5%|0.7%|
[nixspam](#nixspam)|39997|39997|53|0.1%|0.7%|
[php_dictionary](#php_dictionary)|589|589|46|7.8%|0.6%|
[php_spammers](#php_spammers)|580|580|41|7.0%|0.6%|
[php_commenters](#php_commenters)|349|349|23|6.5%|0.3%|
[sorbs_web](#sorbs_web)|619|619|19|3.0%|0.2%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|13|1.9%|0.1%|
[blocklist_de_imap](#blocklist_de_imap)|2180|2180|9|0.4%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|5|0.0%|0.0%|
[et_tor](#et_tor)|6470|6470|5|0.0%|0.0%|
[dm_tor](#dm_tor)|6516|6516|5|0.0%|0.0%|
[bm_tor](#bm_tor)|6522|6522|5|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|165|165|5|3.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|4|1.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47941|47941|3|0.0%|0.0%|
[alienvault_reputation](#alienvault_reputation)|178903|178903|3|0.0%|0.0%|
[php_harvesters](#php_harvesters)|324|324|2|0.6%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|15388|15388|2|0.0%|0.0%|
[sslbl](#sslbl)|372|372|1|0.2%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|1|0.0%|0.0%|
[et_compromised](#et_compromised)|2016|2016|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1720|1720|1|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4042|4042|1|0.0%|0.0%|

## shunlist

[AutoShun.org](http://autoshun.org/) IPs identified as hostile by correlating logs from distributed snort installations running the autoshun plugin

Source is downloaded from [this link](http://www.autoshun.org/files/shunlist.csv).

The last time downloaded was found to be dated: Sun Jun  7 10:30:04 UTC 2015.

The ipset `shunlist` has **1245** entries, **1245** unique IPs.

The following table shows the overlaps of `shunlist` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `shunlist`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `shunlist`.
- ` this % ` is the percentage **of this ipset (`shunlist`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[alienvault_reputation](#alienvault_reputation)|178903|178903|1241|0.6%|99.6%|
[openbl_60d](#openbl_60d)|7254|7254|548|7.5%|44.0%|
[openbl_30d](#openbl_30d)|3245|3245|532|16.3%|42.7%|
[et_compromised](#et_compromised)|2016|2016|440|21.8%|35.3%|
[bruteforceblocker](#bruteforceblocker)|1720|1720|422|24.5%|33.8%|
[blocklist_de](#blocklist_de)|27586|27586|358|1.2%|28.7%|
[blocklist_de_ssh](#blocklist_de_ssh)|2572|2572|320|12.4%|25.7%|
[openbl_7d](#openbl_7d)|816|816|220|26.9%|17.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|17813|139104928|113|0.0%|9.0%|
[et_block](#et_block)|1023|18338662|110|0.0%|8.8%|
[dshield](#dshield)|20|5120|101|1.9%|8.1%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|96|0.0%|7.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72952|348710247|69|0.0%|5.5%|
[sslbl](#sslbl)|372|372|57|15.3%|4.5%|
[openbl_1d](#openbl_1d)|116|116|54|46.5%|4.3%|
[blocklist_de_apache](#blocklist_de_apache)|15388|15388|35|0.2%|2.8%|
[ciarmy](#ciarmy)|425|425|33|7.7%|2.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218315|764993617|28|0.0%|2.2%|
[blocklist_de_strongips](#blocklist_de_strongips)|165|165|20|12.1%|1.6%|
[voipbl](#voipbl)|10476|10888|13|0.1%|1.0%|
[stopforumspam_30d](#stopforumspam_30d)|93068|93068|5|0.0%|0.4%|
[blocklist_de_mail](#blocklist_de_mail)|17025|17025|3|0.0%|0.2%|
[blocklist_de_imap](#blocklist_de_imap)|2180|2180|3|0.1%|0.2%|
[stopforumspam_7d](#stopforumspam_7d)|29870|29870|2|0.0%|0.1%|
[snort_ipfilter](#snort_ipfilter)|9812|9812|2|0.0%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2|0.0%|0.1%|
[stopforumspam_1d](#stopforumspam_1d)|6093|6093|1|0.0%|0.0%|
[sorbs_spam](#sorbs_spam)|45326|46326|1|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|45326|46326|1|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|45326|46326|1|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.0%|
[et_tor](#et_tor)|6470|6470|1|0.0%|0.0%|
[dm_tor](#dm_tor)|6516|6516|1|0.0%|0.0%|
[bm_tor](#bm_tor)|6522|6522|1|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4042|4042|1|0.0%|0.0%|

## snort_ipfilter

[labs.snort.org](https://labs.snort.org/) supplied IP blacklist (this list seems to be updated frequently, but we found no information about it)

Source is downloaded from [this link](http://labs.snort.org/feeds/ip-filter.blf).

The last time downloaded was found to be dated: Sun Jun  7 01:30:00 UTC 2015.

The ipset `snort_ipfilter` has **9812** entries, **9812** unique IPs.

The following table shows the overlaps of `snort_ipfilter` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `snort_ipfilter`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `snort_ipfilter`.
- ` this % ` is the percentage **of this ipset (`snort_ipfilter`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[et_tor](#et_tor)|6470|6470|1075|16.6%|10.9%|
[dm_tor](#dm_tor)|6516|6516|1056|16.2%|10.7%|
[bm_tor](#bm_tor)|6522|6522|1055|16.1%|10.7%|
[stopforumspam_30d](#stopforumspam_30d)|93068|93068|779|0.8%|7.9%|
[stopforumspam_7d](#stopforumspam_7d)|29870|29870|606|2.0%|6.1%|
[stopforumspam_1d](#stopforumspam_1d)|6093|6093|347|5.6%|3.5%|
[et_block](#et_block)|1023|18338662|315|0.0%|3.2%|
[sorbs_spam](#sorbs_spam)|45326|46326|275|0.5%|2.8%|
[sorbs_recent_spam](#sorbs_recent_spam)|45326|46326|275|0.5%|2.8%|
[sorbs_new_spam](#sorbs_new_spam)|45326|46326|275|0.5%|2.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17813|139104928|231|0.0%|2.3%|
[zeus](#zeus)|232|232|200|86.2%|2.0%|
[zeus_badips](#zeus_badips)|203|203|179|88.1%|1.8%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|175|47.0%|1.7%|
[blocklist_de](#blocklist_de)|27586|27586|132|0.4%|1.3%|
[alienvault_reputation](#alienvault_reputation)|178903|178903|118|0.0%|1.2%|
[blocklist_de_mail](#blocklist_de_mail)|17025|17025|103|0.6%|1.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72952|348710247|102|0.0%|1.0%|
[nixspam](#nixspam)|39997|39997|83|0.2%|0.8%|
[feodo](#feodo)|99|99|79|79.7%|0.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218315|764993617|74|0.0%|0.7%|
[php_dictionary](#php_dictionary)|589|589|68|11.5%|0.6%|
[php_spammers](#php_spammers)|580|580|67|11.5%|0.6%|
[ri_web_proxies](#ri_web_proxies)|6972|6828|53|0.7%|0.5%|
[php_commenters](#php_commenters)|349|349|45|12.8%|0.4%|
[sorbs_web](#sorbs_web)|619|619|41|6.6%|0.4%|
[xroxy](#xroxy)|2115|2115|38|1.7%|0.3%|
[sslbl](#sslbl)|372|372|31|8.3%|0.3%|
[openbl_60d](#openbl_60d)|7254|7254|28|0.3%|0.2%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|27|2.0%|0.2%|
[blocklist_de_bots](#blocklist_de_bots)|2976|2976|23|0.7%|0.2%|
[proxz](#proxz)|967|967|21|2.1%|0.2%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|20|0.0%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|15|0.0%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|12|0.0%|0.1%|
[palevo](#palevo)|13|13|11|84.6%|0.1%|
[php_harvesters](#php_harvesters)|324|324|10|3.0%|0.1%|
[blocklist_de_imap](#blocklist_de_imap)|2180|2180|8|0.3%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|15388|15388|7|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|6|0.0%|0.0%|
[sorbs_socks](#sorbs_socks)|20|20|5|25.0%|0.0%|
[sorbs_misc](#sorbs_misc)|20|20|5|25.0%|0.0%|
[sorbs_http](#sorbs_http)|20|20|5|25.0%|0.0%|
[openbl_30d](#openbl_30d)|3245|3245|5|0.1%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4042|4042|3|0.0%|0.0%|
[shunlist](#shunlist)|1245|1245|2|0.1%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2665|2516|2|0.0%|0.0%|
[proxyrss](#proxyrss)|1435|1435|2|0.1%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47941|47941|2|0.0%|0.0%|
[dshield](#dshield)|20|5120|2|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2572|2572|2|0.0%|0.0%|
[openbl_7d](#openbl_7d)|816|816|1|0.1%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|1|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|1|0.1%|0.0%|
[et_compromised](#et_compromised)|2016|2016|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1720|1720|1|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|165|165|1|0.6%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|635|635|1|0.1%|0.0%|

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

The last time downloaded was found to be dated: Sun Jun  7 11:04:18 UTC 2015.

The ipset `sorbs_http` has **20** entries, **20** unique IPs.

The following table shows the overlaps of `sorbs_http` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `sorbs_http`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `sorbs_http`.
- ` this % ` is the percentage **of this ipset (`sorbs_http`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[sorbs_spam](#sorbs_spam)|45326|46326|20|0.0%|100.0%|
[sorbs_socks](#sorbs_socks)|20|20|20|100.0%|100.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|45326|46326|20|0.0%|100.0%|
[sorbs_new_spam](#sorbs_new_spam)|45326|46326|20|0.0%|100.0%|
[sorbs_misc](#sorbs_misc)|20|20|20|100.0%|100.0%|
[nixspam](#nixspam)|39997|39997|7|0.0%|35.0%|
[snort_ipfilter](#snort_ipfilter)|9812|9812|5|0.0%|25.0%|
[blocklist_de_mail](#blocklist_de_mail)|17025|17025|4|0.0%|20.0%|
[blocklist_de](#blocklist_de)|27586|27586|4|0.0%|20.0%|
[sorbs_web](#sorbs_web)|619|619|2|0.3%|10.0%|
[php_dictionary](#php_dictionary)|589|589|2|0.3%|10.0%|
[stopforumspam_7d](#stopforumspam_7d)|29870|29870|1|0.0%|5.0%|
[stopforumspam_30d](#stopforumspam_30d)|93068|93068|1|0.0%|5.0%|
[php_spammers](#php_spammers)|580|580|1|0.1%|5.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72952|348710247|1|0.0%|5.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218315|764993617|1|0.0%|5.0%|

## sorbs_misc

[Sorbs.net](https://www.sorbs.net/) MISC proxies, extracted from deltas.

Source is downloaded from [this link]().

The last time downloaded was found to be dated: Sun Jun  7 11:04:18 UTC 2015.

The ipset `sorbs_misc` has **20** entries, **20** unique IPs.

The following table shows the overlaps of `sorbs_misc` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `sorbs_misc`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `sorbs_misc`.
- ` this % ` is the percentage **of this ipset (`sorbs_misc`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[sorbs_spam](#sorbs_spam)|45326|46326|20|0.0%|100.0%|
[sorbs_socks](#sorbs_socks)|20|20|20|100.0%|100.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|45326|46326|20|0.0%|100.0%|
[sorbs_new_spam](#sorbs_new_spam)|45326|46326|20|0.0%|100.0%|
[sorbs_http](#sorbs_http)|20|20|20|100.0%|100.0%|
[nixspam](#nixspam)|39997|39997|7|0.0%|35.0%|
[snort_ipfilter](#snort_ipfilter)|9812|9812|5|0.0%|25.0%|
[blocklist_de_mail](#blocklist_de_mail)|17025|17025|4|0.0%|20.0%|
[blocklist_de](#blocklist_de)|27586|27586|4|0.0%|20.0%|
[sorbs_web](#sorbs_web)|619|619|2|0.3%|10.0%|
[php_dictionary](#php_dictionary)|589|589|2|0.3%|10.0%|
[stopforumspam_7d](#stopforumspam_7d)|29870|29870|1|0.0%|5.0%|
[stopforumspam_30d](#stopforumspam_30d)|93068|93068|1|0.0%|5.0%|
[php_spammers](#php_spammers)|580|580|1|0.1%|5.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72952|348710247|1|0.0%|5.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218315|764993617|1|0.0%|5.0%|

## sorbs_new_spam

[Sorbs.net](https://www.sorbs.net/) NEW Spam senders, extracted from deltas.

Source is downloaded from [this link]().

The last time downloaded was found to be dated: Sun Jun  7 12:04:19 UTC 2015.

The ipset `sorbs_new_spam` has **45326** entries, **46326** unique IPs.

The following table shows the overlaps of `sorbs_new_spam` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `sorbs_new_spam`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `sorbs_new_spam`.
- ` this % ` is the percentage **of this ipset (`sorbs_new_spam`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[sorbs_spam](#sorbs_spam)|45326|46326|46326|100.0%|100.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|45326|46326|46326|100.0%|100.0%|
[nixspam](#nixspam)|39997|39997|19395|48.4%|41.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17813|139104928|2558|0.0%|5.5%|
[blocklist_de](#blocklist_de)|27586|27586|1087|3.9%|2.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72952|348710247|1059|0.0%|2.2%|
[blocklist_de_mail](#blocklist_de_mail)|17025|17025|943|5.5%|2.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218315|764993617|667|0.0%|1.4%|
[stopforumspam_30d](#stopforumspam_30d)|93068|93068|320|0.3%|0.6%|
[sorbs_web](#sorbs_web)|619|619|320|51.6%|0.6%|
[snort_ipfilter](#snort_ipfilter)|9812|9812|275|2.8%|0.5%|
[php_dictionary](#php_dictionary)|589|589|181|30.7%|0.3%|
[stopforumspam_7d](#stopforumspam_7d)|29870|29870|167|0.5%|0.3%|
[php_spammers](#php_spammers)|580|580|158|27.2%|0.3%|
[ri_web_proxies](#ri_web_proxies)|6972|6828|130|1.9%|0.2%|
[alienvault_reputation](#alienvault_reputation)|178903|178903|92|0.0%|0.1%|
[xroxy](#xroxy)|2115|2115|82|3.8%|0.1%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4042|4042|81|2.0%|0.1%|
[blocklist_de_apache](#blocklist_de_apache)|15388|15388|81|0.5%|0.1%|
[stopforumspam_1d](#stopforumspam_1d)|6093|6093|57|0.9%|0.1%|
[blocklist_de_bots](#blocklist_de_bots)|2976|2976|50|1.6%|0.1%|
[proxz](#proxz)|967|967|43|4.4%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2180|2180|36|1.6%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|34|0.0%|0.0%|
[sorbs_socks](#sorbs_socks)|20|20|20|100.0%|0.0%|
[sorbs_misc](#sorbs_misc)|20|20|20|100.0%|0.0%|
[sorbs_http](#sorbs_http)|20|20|20|100.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47941|47941|19|0.0%|0.0%|
[php_commenters](#php_commenters)|349|349|16|4.5%|0.0%|
[proxyrss](#proxyrss)|1435|1435|11|0.7%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2665|2516|10|0.3%|0.0%|
[openbl_60d](#openbl_60d)|7254|7254|10|0.1%|0.0%|
[sorbs_smtp](#sorbs_smtp)|10|10|9|90.0%|0.0%|
[php_harvesters](#php_harvesters)|324|324|9|2.7%|0.0%|
[et_block](#et_block)|1023|18338662|9|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|7|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2572|2572|6|0.2%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|635|635|6|0.9%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|5|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|3|0.0%|0.0%|
[dm_tor](#dm_tor)|6516|6516|3|0.0%|0.0%|
[bm_tor](#bm_tor)|6522|6522|3|0.0%|0.0%|
[openbl_30d](#openbl_30d)|3245|3245|2|0.0%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|2|0.1%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|2|0.3%|0.0%|
[et_tor](#et_tor)|6470|6470|2|0.0%|0.0%|
[voipbl](#voipbl)|10476|10888|1|0.0%|0.0%|
[shunlist](#shunlist)|1245|1245|1|0.0%|0.0%|
[openbl_7d](#openbl_7d)|816|816|1|0.1%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|165|165|1|0.6%|0.0%|

## sorbs_recent_spam

[Sorbs.net](https://www.sorbs.net/) RECENT Spam senders, extracted from deltas.

Source is downloaded from [this link]().

The last time downloaded was found to be dated: Sun Jun  7 12:04:19 UTC 2015.

The ipset `sorbs_recent_spam` has **45326** entries, **46326** unique IPs.

The following table shows the overlaps of `sorbs_recent_spam` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `sorbs_recent_spam`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `sorbs_recent_spam`.
- ` this % ` is the percentage **of this ipset (`sorbs_recent_spam`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[sorbs_spam](#sorbs_spam)|45326|46326|46326|100.0%|100.0%|
[sorbs_new_spam](#sorbs_new_spam)|45326|46326|46326|100.0%|100.0%|
[nixspam](#nixspam)|39997|39997|19395|48.4%|41.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17813|139104928|2558|0.0%|5.5%|
[blocklist_de](#blocklist_de)|27586|27586|1087|3.9%|2.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72952|348710247|1059|0.0%|2.2%|
[blocklist_de_mail](#blocklist_de_mail)|17025|17025|943|5.5%|2.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218315|764993617|667|0.0%|1.4%|
[stopforumspam_30d](#stopforumspam_30d)|93068|93068|320|0.3%|0.6%|
[sorbs_web](#sorbs_web)|619|619|320|51.6%|0.6%|
[snort_ipfilter](#snort_ipfilter)|9812|9812|275|2.8%|0.5%|
[php_dictionary](#php_dictionary)|589|589|181|30.7%|0.3%|
[stopforumspam_7d](#stopforumspam_7d)|29870|29870|167|0.5%|0.3%|
[php_spammers](#php_spammers)|580|580|158|27.2%|0.3%|
[ri_web_proxies](#ri_web_proxies)|6972|6828|130|1.9%|0.2%|
[alienvault_reputation](#alienvault_reputation)|178903|178903|92|0.0%|0.1%|
[xroxy](#xroxy)|2115|2115|82|3.8%|0.1%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4042|4042|81|2.0%|0.1%|
[blocklist_de_apache](#blocklist_de_apache)|15388|15388|81|0.5%|0.1%|
[stopforumspam_1d](#stopforumspam_1d)|6093|6093|57|0.9%|0.1%|
[blocklist_de_bots](#blocklist_de_bots)|2976|2976|50|1.6%|0.1%|
[proxz](#proxz)|967|967|43|4.4%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2180|2180|36|1.6%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|34|0.0%|0.0%|
[sorbs_socks](#sorbs_socks)|20|20|20|100.0%|0.0%|
[sorbs_misc](#sorbs_misc)|20|20|20|100.0%|0.0%|
[sorbs_http](#sorbs_http)|20|20|20|100.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47941|47941|19|0.0%|0.0%|
[php_commenters](#php_commenters)|349|349|16|4.5%|0.0%|
[proxyrss](#proxyrss)|1435|1435|11|0.7%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2665|2516|10|0.3%|0.0%|
[openbl_60d](#openbl_60d)|7254|7254|10|0.1%|0.0%|
[sorbs_smtp](#sorbs_smtp)|10|10|9|90.0%|0.0%|
[php_harvesters](#php_harvesters)|324|324|9|2.7%|0.0%|
[et_block](#et_block)|1023|18338662|9|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|7|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2572|2572|6|0.2%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|635|635|6|0.9%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|5|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|3|0.0%|0.0%|
[dm_tor](#dm_tor)|6516|6516|3|0.0%|0.0%|
[bm_tor](#bm_tor)|6522|6522|3|0.0%|0.0%|
[openbl_30d](#openbl_30d)|3245|3245|2|0.0%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|2|0.1%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|2|0.3%|0.0%|
[et_tor](#et_tor)|6470|6470|2|0.0%|0.0%|
[voipbl](#voipbl)|10476|10888|1|0.0%|0.0%|
[shunlist](#shunlist)|1245|1245|1|0.0%|0.0%|
[openbl_7d](#openbl_7d)|816|816|1|0.1%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|165|165|1|0.6%|0.0%|

## sorbs_smtp

[Sorbs.net](https://www.sorbs.net/) SMTP Open Relays, extracted from deltas.

Source is downloaded from [this link]().

The last time downloaded was found to be dated: Sat Jun  6 23:04:13 UTC 2015.

The ipset `sorbs_smtp` has **10** entries, **10** unique IPs.

The following table shows the overlaps of `sorbs_smtp` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `sorbs_smtp`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `sorbs_smtp`.
- ` this % ` is the percentage **of this ipset (`sorbs_smtp`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[sorbs_spam](#sorbs_spam)|45326|46326|9|0.0%|90.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|45326|46326|9|0.0%|90.0%|
[sorbs_new_spam](#sorbs_new_spam)|45326|46326|9|0.0%|90.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72952|348710247|1|0.0%|10.0%|

## sorbs_socks

[Sorbs.net](https://www.sorbs.net/) SOCKS proxies, extracted from deltas.

Source is downloaded from [this link]().

The last time downloaded was found to be dated: Sun Jun  7 11:04:18 UTC 2015.

The ipset `sorbs_socks` has **20** entries, **20** unique IPs.

The following table shows the overlaps of `sorbs_socks` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `sorbs_socks`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `sorbs_socks`.
- ` this % ` is the percentage **of this ipset (`sorbs_socks`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[sorbs_spam](#sorbs_spam)|45326|46326|20|0.0%|100.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|45326|46326|20|0.0%|100.0%|
[sorbs_new_spam](#sorbs_new_spam)|45326|46326|20|0.0%|100.0%|
[sorbs_misc](#sorbs_misc)|20|20|20|100.0%|100.0%|
[sorbs_http](#sorbs_http)|20|20|20|100.0%|100.0%|
[nixspam](#nixspam)|39997|39997|7|0.0%|35.0%|
[snort_ipfilter](#snort_ipfilter)|9812|9812|5|0.0%|25.0%|
[blocklist_de_mail](#blocklist_de_mail)|17025|17025|4|0.0%|20.0%|
[blocklist_de](#blocklist_de)|27586|27586|4|0.0%|20.0%|
[sorbs_web](#sorbs_web)|619|619|2|0.3%|10.0%|
[php_dictionary](#php_dictionary)|589|589|2|0.3%|10.0%|
[stopforumspam_7d](#stopforumspam_7d)|29870|29870|1|0.0%|5.0%|
[stopforumspam_30d](#stopforumspam_30d)|93068|93068|1|0.0%|5.0%|
[php_spammers](#php_spammers)|580|580|1|0.1%|5.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72952|348710247|1|0.0%|5.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218315|764993617|1|0.0%|5.0%|

## sorbs_spam

[Sorbs.net](https://www.sorbs.net/) Spam senders, extracted from deltas.

Source is downloaded from [this link]().

The last time downloaded was found to be dated: Sun Jun  7 12:04:19 UTC 2015.

The ipset `sorbs_spam` has **45326** entries, **46326** unique IPs.

The following table shows the overlaps of `sorbs_spam` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `sorbs_spam`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `sorbs_spam`.
- ` this % ` is the percentage **of this ipset (`sorbs_spam`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[sorbs_recent_spam](#sorbs_recent_spam)|45326|46326|46326|100.0%|100.0%|
[sorbs_new_spam](#sorbs_new_spam)|45326|46326|46326|100.0%|100.0%|
[nixspam](#nixspam)|39997|39997|19395|48.4%|41.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17813|139104928|2558|0.0%|5.5%|
[blocklist_de](#blocklist_de)|27586|27586|1087|3.9%|2.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72952|348710247|1059|0.0%|2.2%|
[blocklist_de_mail](#blocklist_de_mail)|17025|17025|943|5.5%|2.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218315|764993617|667|0.0%|1.4%|
[stopforumspam_30d](#stopforumspam_30d)|93068|93068|320|0.3%|0.6%|
[sorbs_web](#sorbs_web)|619|619|320|51.6%|0.6%|
[snort_ipfilter](#snort_ipfilter)|9812|9812|275|2.8%|0.5%|
[php_dictionary](#php_dictionary)|589|589|181|30.7%|0.3%|
[stopforumspam_7d](#stopforumspam_7d)|29870|29870|167|0.5%|0.3%|
[php_spammers](#php_spammers)|580|580|158|27.2%|0.3%|
[ri_web_proxies](#ri_web_proxies)|6972|6828|130|1.9%|0.2%|
[alienvault_reputation](#alienvault_reputation)|178903|178903|92|0.0%|0.1%|
[xroxy](#xroxy)|2115|2115|82|3.8%|0.1%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4042|4042|81|2.0%|0.1%|
[blocklist_de_apache](#blocklist_de_apache)|15388|15388|81|0.5%|0.1%|
[stopforumspam_1d](#stopforumspam_1d)|6093|6093|57|0.9%|0.1%|
[blocklist_de_bots](#blocklist_de_bots)|2976|2976|50|1.6%|0.1%|
[proxz](#proxz)|967|967|43|4.4%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2180|2180|36|1.6%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|34|0.0%|0.0%|
[sorbs_socks](#sorbs_socks)|20|20|20|100.0%|0.0%|
[sorbs_misc](#sorbs_misc)|20|20|20|100.0%|0.0%|
[sorbs_http](#sorbs_http)|20|20|20|100.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47941|47941|19|0.0%|0.0%|
[php_commenters](#php_commenters)|349|349|16|4.5%|0.0%|
[proxyrss](#proxyrss)|1435|1435|11|0.7%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2665|2516|10|0.3%|0.0%|
[openbl_60d](#openbl_60d)|7254|7254|10|0.1%|0.0%|
[sorbs_smtp](#sorbs_smtp)|10|10|9|90.0%|0.0%|
[php_harvesters](#php_harvesters)|324|324|9|2.7%|0.0%|
[et_block](#et_block)|1023|18338662|9|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|7|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2572|2572|6|0.2%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|635|635|6|0.9%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|5|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|3|0.0%|0.0%|
[dm_tor](#dm_tor)|6516|6516|3|0.0%|0.0%|
[bm_tor](#bm_tor)|6522|6522|3|0.0%|0.0%|
[openbl_30d](#openbl_30d)|3245|3245|2|0.0%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|2|0.1%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|2|0.3%|0.0%|
[et_tor](#et_tor)|6470|6470|2|0.0%|0.0%|
[voipbl](#voipbl)|10476|10888|1|0.0%|0.0%|
[shunlist](#shunlist)|1245|1245|1|0.0%|0.0%|
[openbl_7d](#openbl_7d)|816|816|1|0.1%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|165|165|1|0.6%|0.0%|

## sorbs_web

[Sorbs.net](https://www.sorbs.net/) WEB exploits, extracted from deltas.

Source is downloaded from [this link]().

The last time downloaded was found to be dated: Sun Jun  7 12:04:19 UTC 2015.

The ipset `sorbs_web` has **619** entries, **619** unique IPs.

The following table shows the overlaps of `sorbs_web` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `sorbs_web`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `sorbs_web`.
- ` this % ` is the percentage **of this ipset (`sorbs_web`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[sorbs_spam](#sorbs_spam)|45326|46326|320|0.6%|51.6%|
[sorbs_recent_spam](#sorbs_recent_spam)|45326|46326|320|0.6%|51.6%|
[sorbs_new_spam](#sorbs_new_spam)|45326|46326|320|0.6%|51.6%|
[nixspam](#nixspam)|39997|39997|92|0.2%|14.8%|
[blocklist_de](#blocklist_de)|27586|27586|68|0.2%|10.9%|
[blocklist_de_mail](#blocklist_de_mail)|17025|17025|52|0.3%|8.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17813|139104928|44|0.0%|7.1%|
[stopforumspam_30d](#stopforumspam_30d)|93068|93068|42|0.0%|6.7%|
[snort_ipfilter](#snort_ipfilter)|9812|9812|41|0.4%|6.6%|
[stopforumspam_7d](#stopforumspam_7d)|29870|29870|28|0.0%|4.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72952|348710247|27|0.0%|4.3%|
[php_dictionary](#php_dictionary)|589|589|26|4.4%|4.2%|
[php_spammers](#php_spammers)|580|580|23|3.9%|3.7%|
[ri_web_proxies](#ri_web_proxies)|6972|6828|19|0.2%|3.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218315|764993617|18|0.0%|2.9%|
[xroxy](#xroxy)|2115|2115|11|0.5%|1.7%|
[stopforumspam_1d](#stopforumspam_1d)|6093|6093|10|0.1%|1.6%|
[blocklist_de_bots](#blocklist_de_bots)|2976|2976|10|0.3%|1.6%|
[proxz](#proxz)|967|967|8|0.8%|1.2%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4042|4042|6|0.1%|0.9%|
[blocklist_de_apache](#blocklist_de_apache)|15388|15388|6|0.0%|0.9%|
[sorbs_socks](#sorbs_socks)|20|20|2|10.0%|0.3%|
[sorbs_misc](#sorbs_misc)|20|20|2|10.0%|0.3%|
[sorbs_http](#sorbs_http)|20|20|2|10.0%|0.3%|
[php_commenters](#php_commenters)|349|349|2|0.5%|0.3%|
[ri_connect_proxies](#ri_connect_proxies)|2665|2516|1|0.0%|0.1%|
[openbl_60d](#openbl_60d)|7254|7254|1|0.0%|0.1%|
[openbl_30d](#openbl_30d)|3245|3245|1|0.0%|0.1%|
[blocklist_de_strongips](#blocklist_de_strongips)|165|165|1|0.6%|0.1%|
[alienvault_reputation](#alienvault_reputation)|178903|178903|1|0.0%|0.1%|

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
[et_block](#et_block)|1023|18338662|18120448|98.8%|98.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|72952|348710247|8499993|2.4%|46.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|6998016|76.2%|38.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218315|764993617|2272265|0.2%|12.3%|
[fullbogons](#fullbogons)|3720|670264216|151552|0.0%|0.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17813|139104928|130368|0.0%|0.7%|
[alienvault_reputation](#alienvault_reputation)|178903|178903|1631|0.9%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1037|0.3%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|93068|93068|1023|1.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|512|0.1%|0.0%|
[dshield](#dshield)|20|5120|512|10.0%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29870|29870|314|1.0%|0.0%|
[openbl_60d](#openbl_60d)|7254|7254|239|3.2%|0.0%|
[blocklist_de](#blocklist_de)|27586|27586|163|0.5%|0.0%|
[openbl_30d](#openbl_30d)|3245|3245|156|4.8%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2572|2572|107|4.1%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1720|1720|101|5.8%|0.0%|
[et_compromised](#et_compromised)|2016|2016|100|4.9%|0.0%|
[shunlist](#shunlist)|1245|1245|96|7.7%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6093|6093|74|1.2%|0.0%|
[nixspam](#nixspam)|39997|39997|48|0.1%|0.0%|
[openbl_7d](#openbl_7d)|816|816|46|5.6%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|29|2.2%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|2976|2976|29|0.9%|0.0%|
[php_commenters](#php_commenters)|349|349|28|8.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|17025|17025|22|0.1%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9812|9812|20|0.2%|0.0%|
[zeus_badips](#zeus_badips)|203|203|16|7.8%|0.0%|
[zeus](#zeus)|232|232|16|6.8%|0.0%|
[voipbl](#voipbl)|10476|10888|14|0.1%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2180|2180|14|0.6%|0.0%|
[openbl_1d](#openbl_1d)|116|116|11|9.4%|0.0%|
[sorbs_spam](#sorbs_spam)|45326|46326|7|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|45326|46326|7|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|45326|46326|7|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|6|0.4%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|165|165|6|3.6%|0.0%|
[php_dictionary](#php_dictionary)|589|589|5|0.8%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47941|47941|5|0.0%|0.0%|
[php_spammers](#php_spammers)|580|580|4|0.6%|0.0%|
[malc0de](#malc0de)|361|361|4|1.1%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4042|4042|4|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|15388|15388|4|0.0%|0.0%|
[dm_tor](#dm_tor)|6516|6516|3|0.0%|0.0%|
[bm_tor](#bm_tor)|6522|6522|3|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|2|0.3%|0.0%|
[et_tor](#et_tor)|6470|6470|2|0.0%|0.0%|
[sslbl](#sslbl)|372|372|1|0.2%|0.0%|
[php_harvesters](#php_harvesters)|324|324|1|0.3%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|86|86|1|1.1%|0.0%|

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
[ib_bluetack_level3](#ib_bluetack_level3)|17813|139104928|270785|0.1%|55.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72952|348710247|98904|0.0%|20.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|218315|764993617|33155|0.0%|6.8%|
[et_block](#et_block)|1023|18338662|517|0.0%|0.1%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|512|0.0%|0.1%|
[stopforumspam_30d](#stopforumspam_30d)|93068|93068|80|0.0%|0.0%|
[alienvault_reputation](#alienvault_reputation)|178903|178903|15|0.0%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29870|29870|10|0.0%|0.0%|
[php_commenters](#php_commenters)|349|349|7|2.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9812|9812|6|0.0%|0.0%|
[zeus_badips](#zeus_badips)|203|203|5|2.4%|0.0%|
[zeus](#zeus)|232|232|5|2.1%|0.0%|
[blocklist_de](#blocklist_de)|27586|27586|4|0.0%|0.0%|
[sorbs_spam](#sorbs_spam)|45326|46326|3|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|45326|46326|3|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|45326|46326|3|0.0%|0.0%|
[nixspam](#nixspam)|39997|39997|2|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|165|165|2|1.2%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|2976|2976|2|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6093|6093|1|0.0%|0.0%|
[php_harvesters](#php_harvesters)|324|324|1|0.3%|0.0%|
[openbl_60d](#openbl_60d)|7254|7254|1|0.0%|0.0%|
[openbl_30d](#openbl_30d)|3245|3245|1|0.0%|0.0%|
[malc0de](#malc0de)|361|361|1|0.2%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2572|2572|1|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|15388|15388|1|0.0%|0.0%|

## sslbl

[Abuse.ch SSL Blacklist](https://sslbl.abuse.ch/) bad SSL traffic related to malware or botnet activities - **excellent list**

Source is downloaded from [this link](https://sslbl.abuse.ch/blacklist/sslipblacklist.csv).

The last time downloaded was found to be dated: Sun Jun  7 12:30:06 UTC 2015.

The ipset `sslbl` has **372** entries, **372** unique IPs.

The following table shows the overlaps of `sslbl` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `sslbl`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `sslbl`.
- ` this % ` is the percentage **of this ipset (`sslbl`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[alienvault_reputation](#alienvault_reputation)|178903|178903|64|0.0%|17.2%|
[shunlist](#shunlist)|1245|1245|57|4.5%|15.3%|
[feodo](#feodo)|99|99|36|36.3%|9.6%|
[et_block](#et_block)|1023|18338662|35|0.0%|9.4%|
[snort_ipfilter](#snort_ipfilter)|9812|9812|31|0.3%|8.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17813|139104928|26|0.0%|6.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72952|348710247|5|0.0%|1.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218315|764993617|3|0.0%|0.8%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|1|0.0%|0.2%|
[ri_web_proxies](#ri_web_proxies)|6972|6828|1|0.0%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.2%|

## stopforumspam_1d

[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers in the last 24 hours - **excellent list**

Source is downloaded from [this link](http://www.stopforumspam.com/downloads/listed_ip_1.zip).

The last time downloaded was found to be dated: Sun Jun  7 12:00:01 UTC 2015.

The ipset `stopforumspam_1d` has **6093** entries, **6093** unique IPs.

The following table shows the overlaps of `stopforumspam_1d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `stopforumspam_1d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `stopforumspam_1d`.
- ` this % ` is the percentage **of this ipset (`stopforumspam_1d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_30d](#stopforumspam_30d)|93068|93068|5166|5.5%|84.7%|
[stopforumspam_7d](#stopforumspam_7d)|29870|29870|5004|16.7%|82.1%|
[blocklist_de](#blocklist_de)|27586|27586|1230|4.4%|20.1%|
[blocklist_de_bots](#blocklist_de_bots)|2976|2976|1180|39.6%|19.3%|
[ri_web_proxies](#ri_web_proxies)|6972|6828|458|6.7%|7.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17813|139104928|457|0.0%|7.5%|
[snort_ipfilter](#snort_ipfilter)|9812|9812|347|3.5%|5.6%|
[proxyrss](#proxyrss)|1435|1435|334|23.2%|5.4%|
[et_tor](#et_tor)|6470|6470|314|4.8%|5.1%|
[dm_tor](#dm_tor)|6516|6516|311|4.7%|5.1%|
[bm_tor](#bm_tor)|6522|6522|311|4.7%|5.1%|
[xroxy](#xroxy)|2115|2115|252|11.9%|4.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72952|348710247|216|0.0%|3.5%|
[proxz](#proxz)|967|967|151|15.6%|2.4%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|146|39.2%|2.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218315|764993617|130|0.0%|2.1%|
[php_commenters](#php_commenters)|349|349|126|36.1%|2.0%|
[ri_connect_proxies](#ri_connect_proxies)|2665|2516|103|4.0%|1.6%|
[blocklist_de_strongips](#blocklist_de_strongips)|165|165|89|53.9%|1.4%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|74|0.0%|1.2%|
[et_block](#et_block)|1023|18338662|71|0.0%|1.1%|
[sorbs_spam](#sorbs_spam)|45326|46326|57|0.1%|0.9%|
[sorbs_recent_spam](#sorbs_recent_spam)|45326|46326|57|0.1%|0.9%|
[sorbs_new_spam](#sorbs_new_spam)|45326|46326|57|0.1%|0.9%|
[blocklist_de_apache](#blocklist_de_apache)|15388|15388|51|0.3%|0.8%|
[alienvault_reputation](#alienvault_reputation)|178903|178903|51|0.0%|0.8%|
[blocklist_de_mail](#blocklist_de_mail)|17025|17025|50|0.2%|0.8%|
[php_harvesters](#php_harvesters)|324|324|38|11.7%|0.6%|
[php_dictionary](#php_dictionary)|589|589|32|5.4%|0.5%|
[nixspam](#nixspam)|39997|39997|32|0.0%|0.5%|
[php_spammers](#php_spammers)|580|580|31|5.3%|0.5%|
[openbl_60d](#openbl_60d)|7254|7254|21|0.2%|0.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|14|0.0%|0.2%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4042|4042|14|0.3%|0.2%|
[sorbs_web](#sorbs_web)|619|619|10|1.6%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|9|0.0%|0.1%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|6|0.9%|0.0%|
[voipbl](#voipbl)|10476|10888|4|0.0%|0.0%|
[et_compromised](#et_compromised)|2016|2016|3|0.1%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1720|1720|3|0.1%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|2|0.1%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47941|47941|2|0.0%|0.0%|
[zeus_badips](#zeus_badips)|203|203|1|0.4%|0.0%|
[zeus](#zeus)|232|232|1|0.4%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|1|0.0%|0.0%|
[shunlist](#shunlist)|1245|1245|1|0.0%|0.0%|
[openbl_30d](#openbl_30d)|3245|3245|1|0.0%|0.0%|
[dshield](#dshield)|20|5120|1|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2180|2180|1|0.0%|0.0%|

## stopforumspam_30d

[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 30 days)

Source is downloaded from [this link](http://www.stopforumspam.com/downloads/listed_ip_30.zip).

The last time downloaded was found to be dated: Sun Jun  7 00:00:41 UTC 2015.

The ipset `stopforumspam_30d` has **93068** entries, **93068** unique IPs.

The following table shows the overlaps of `stopforumspam_30d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `stopforumspam_30d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `stopforumspam_30d`.
- ` this % ` is the percentage **of this ipset (`stopforumspam_30d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_7d](#stopforumspam_7d)|29870|29870|29805|99.7%|32.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17813|139104928|5853|0.0%|6.2%|
[stopforumspam_1d](#stopforumspam_1d)|6093|6093|5166|84.7%|5.5%|
[ri_web_proxies](#ri_web_proxies)|6972|6828|3277|47.9%|3.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72952|348710247|2527|0.0%|2.7%|
[blocklist_de](#blocklist_de)|27586|27586|2283|8.2%|2.4%|
[blocklist_de_bots](#blocklist_de_bots)|2976|2976|1969|66.1%|2.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|218315|764993617|1528|0.0%|1.6%|
[ri_connect_proxies](#ri_connect_proxies)|2665|2516|1440|57.2%|1.5%|
[xroxy](#xroxy)|2115|2115|1251|59.1%|1.3%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|1023|0.0%|1.0%|
[et_block](#et_block)|1023|18338662|1015|0.0%|1.0%|
[snort_ipfilter](#snort_ipfilter)|9812|9812|779|7.9%|0.8%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|738|0.0%|0.7%|
[proxyrss](#proxyrss)|1435|1435|709|49.4%|0.7%|
[et_tor](#et_tor)|6470|6470|651|10.0%|0.6%|
[bm_tor](#bm_tor)|6522|6522|635|9.7%|0.6%|
[dm_tor](#dm_tor)|6516|6516|631|9.6%|0.6%|
[proxz](#proxz)|967|967|590|61.0%|0.6%|
[sorbs_spam](#sorbs_spam)|45326|46326|320|0.6%|0.3%|
[sorbs_recent_spam](#sorbs_recent_spam)|45326|46326|320|0.6%|0.3%|
[sorbs_new_spam](#sorbs_new_spam)|45326|46326|320|0.6%|0.3%|
[php_commenters](#php_commenters)|349|349|255|73.0%|0.2%|
[blocklist_de_mail](#blocklist_de_mail)|17025|17025|246|1.4%|0.2%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|231|62.0%|0.2%|
[blocklist_de_apache](#blocklist_de_apache)|15388|15388|207|1.3%|0.2%|
[alienvault_reputation](#alienvault_reputation)|178903|178903|205|0.1%|0.2%|
[nixspam](#nixspam)|39997|39997|149|0.3%|0.1%|
[blocklist_de_strongips](#blocklist_de_strongips)|165|165|125|75.7%|0.1%|
[php_spammers](#php_spammers)|580|580|122|21.0%|0.1%|
[php_dictionary](#php_dictionary)|589|589|110|18.6%|0.1%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|80|0.0%|0.0%|
[php_harvesters](#php_harvesters)|324|324|74|22.8%|0.0%|
[openbl_60d](#openbl_60d)|7254|7254|53|0.7%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4042|4042|53|1.3%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|47|0.0%|0.0%|
[sorbs_web](#sorbs_web)|619|619|42|6.7%|0.0%|
[voipbl](#voipbl)|10476|10888|36|0.3%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|22|3.3%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47941|47941|15|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2180|2180|14|0.6%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1720|1720|13|0.7%|0.0%|
[et_compromised](#et_compromised)|2016|2016|11|0.5%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|635|635|10|1.5%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2572|2572|8|0.3%|0.0%|
[shunlist](#shunlist)|1245|1245|5|0.4%|0.0%|
[openbl_30d](#openbl_30d)|3245|3245|4|0.1%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|4|0.3%|0.0%|
[openbl_7d](#openbl_7d)|816|816|3|0.3%|0.0%|
[dshield](#dshield)|20|5120|3|0.0%|0.0%|
[zeus_badips](#zeus_badips)|203|203|2|0.9%|0.0%|
[zeus](#zeus)|232|232|2|0.8%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|2|0.1%|0.0%|
[fullbogons](#fullbogons)|3720|670264216|2|0.0%|0.0%|
[sorbs_socks](#sorbs_socks)|20|20|1|5.0%|0.0%|
[sorbs_misc](#sorbs_misc)|20|20|1|5.0%|0.0%|
[sorbs_http](#sorbs_http)|20|20|1|5.0%|0.0%|
[openbl_1d](#openbl_1d)|116|116|1|0.8%|0.0%|
[ciarmy](#ciarmy)|425|425|1|0.2%|0.0%|
[bogons](#bogons)|13|592708608|1|0.0%|0.0%|

## stopforumspam_7d

[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 7 days)

Source is downloaded from [this link](http://www.stopforumspam.com/downloads/listed_ip_7.zip).

The last time downloaded was found to be dated: Sun Jun  7 01:00:09 UTC 2015.

The ipset `stopforumspam_7d` has **29870** entries, **29870** unique IPs.

The following table shows the overlaps of `stopforumspam_7d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `stopforumspam_7d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `stopforumspam_7d`.
- ` this % ` is the percentage **of this ipset (`stopforumspam_7d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_30d](#stopforumspam_30d)|93068|93068|29805|32.0%|99.7%|
[stopforumspam_1d](#stopforumspam_1d)|6093|6093|5004|82.1%|16.7%|
[blocklist_de](#blocklist_de)|27586|27586|1959|7.1%|6.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17813|139104928|1948|0.0%|6.5%|
[blocklist_de_bots](#blocklist_de_bots)|2976|2976|1792|60.2%|5.9%|
[ri_web_proxies](#ri_web_proxies)|6972|6828|1624|23.7%|5.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|72952|348710247|882|0.0%|2.9%|
[xroxy](#xroxy)|2115|2115|695|32.8%|2.3%|
[ri_connect_proxies](#ri_connect_proxies)|2665|2516|635|25.2%|2.1%|
[snort_ipfilter](#snort_ipfilter)|9812|9812|606|6.1%|2.0%|
[proxyrss](#proxyrss)|1435|1435|566|39.4%|1.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218315|764993617|559|0.0%|1.8%|
[et_tor](#et_tor)|6470|6470|516|7.9%|1.7%|
[bm_tor](#bm_tor)|6522|6522|498|7.6%|1.6%|
[dm_tor](#dm_tor)|6516|6516|495|7.5%|1.6%|
[proxz](#proxz)|967|967|440|45.5%|1.4%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|314|0.0%|1.0%|
[et_block](#et_block)|1023|18338662|308|0.0%|1.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|189|50.8%|0.6%|
[php_commenters](#php_commenters)|349|349|186|53.2%|0.6%|
[sorbs_spam](#sorbs_spam)|45326|46326|167|0.3%|0.5%|
[sorbs_recent_spam](#sorbs_recent_spam)|45326|46326|167|0.3%|0.5%|
[sorbs_new_spam](#sorbs_new_spam)|45326|46326|167|0.3%|0.5%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|150|0.0%|0.5%|
[blocklist_de_mail](#blocklist_de_mail)|17025|17025|134|0.7%|0.4%|
[blocklist_de_apache](#blocklist_de_apache)|15388|15388|123|0.7%|0.4%|
[blocklist_de_strongips](#blocklist_de_strongips)|165|165|114|69.0%|0.3%|
[alienvault_reputation](#alienvault_reputation)|178903|178903|95|0.0%|0.3%|
[php_dictionary](#php_dictionary)|589|589|71|12.0%|0.2%|
[nixspam](#nixspam)|39997|39997|69|0.1%|0.2%|
[php_spammers](#php_spammers)|580|580|66|11.3%|0.2%|
[php_harvesters](#php_harvesters)|324|324|55|16.9%|0.1%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4042|4042|33|0.8%|0.1%|
[sorbs_web](#sorbs_web)|619|619|28|4.5%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|25|0.0%|0.0%|
[openbl_60d](#openbl_60d)|7254|7254|24|0.3%|0.0%|
[voipbl](#voipbl)|10476|10888|14|0.1%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|12|1.8%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|10|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2180|2180|8|0.3%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47941|47941|7|0.0%|0.0%|
[et_compromised](#et_compromised)|2016|2016|7|0.3%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1720|1720|7|0.4%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|635|635|4|0.6%|0.0%|
[shunlist](#shunlist)|1245|1245|2|0.1%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|2|0.1%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2572|2572|2|0.0%|0.0%|
[zeus_badips](#zeus_badips)|203|203|1|0.4%|0.0%|
[zeus](#zeus)|232|232|1|0.4%|0.0%|
[sorbs_socks](#sorbs_socks)|20|20|1|5.0%|0.0%|
[sorbs_misc](#sorbs_misc)|20|20|1|5.0%|0.0%|
[sorbs_http](#sorbs_http)|20|20|1|5.0%|0.0%|
[openbl_30d](#openbl_30d)|3245|3245|1|0.0%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|1|0.0%|0.0%|
[dshield](#dshield)|20|5120|1|0.0%|0.0%|
[ciarmy](#ciarmy)|425|425|1|0.2%|0.0%|

## virbl

[VirBL](http://virbl.bit.nl/) is a project of which the idea was born during the RIPE-48 meeting. The plan was to get reports of virusscanning mailservers, and put the IP-addresses that were reported to send viruses on a blacklist.

Source is downloaded from [this link](http://virbl.bit.nl/download/virbl.dnsbl.bit.nl.txt).

The last time downloaded was found to be dated: Sun Jun  7 11:42:03 UTC 2015.

The ipset `virbl` has **3** entries, **3** unique IPs.

The following table shows the overlaps of `virbl` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `virbl`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `virbl`.
- ` this % ` is the percentage **of this ipset (`virbl`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|

## voipbl

[VoIPBL.org](http://www.voipbl.org/) a distributed VoIP blacklist that is aimed to protects against VoIP Fraud and minimizing abuse for network that have publicly accessible PBX's. Several algorithms, external sources and manual confirmation are used before they categorize something as an attack and determine the threat level.

Source is downloaded from [this link](http://www.voipbl.org/update/).

The last time downloaded was found to be dated: Sun Jun  7 09:53:01 UTC 2015.

The ipset `voipbl` has **10476** entries, **10888** unique IPs.

The following table shows the overlaps of `voipbl` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `voipbl`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `voipbl`.
- ` this % ` is the percentage **of this ipset (`voipbl`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|17813|139104928|1599|0.0%|14.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72952|348710247|434|0.0%|3.9%|
[fullbogons](#fullbogons)|3720|670264216|319|0.0%|2.9%|
[bogons](#bogons)|13|592708608|319|0.0%|2.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|218315|764993617|296|0.0%|2.7%|
[alienvault_reputation](#alienvault_reputation)|178903|178903|206|0.1%|1.8%|
[stopforumspam_30d](#stopforumspam_30d)|93068|93068|36|0.0%|0.3%|
[blocklist_de](#blocklist_de)|27586|27586|30|0.1%|0.2%|
[blocklist_de_sip](#blocklist_de_sip)|86|86|24|27.9%|0.2%|
[et_block](#et_block)|1023|18338662|17|0.0%|0.1%|
[stopforumspam_7d](#stopforumspam_7d)|29870|29870|14|0.0%|0.1%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|14|0.0%|0.1%|
[shunlist](#shunlist)|1245|1245|13|1.0%|0.1%|
[openbl_60d](#openbl_60d)|7254|7254|8|0.1%|0.0%|
[dshield](#dshield)|20|5120|5|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6093|6093|4|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|4|0.0%|0.0%|
[ciarmy](#ciarmy)|425|425|4|0.9%|0.0%|
[openbl_30d](#openbl_30d)|3245|3245|3|0.0%|0.0%|
[et_tor](#et_tor)|6470|6470|3|0.0%|0.0%|
[dm_tor](#dm_tor)|6516|6516|3|0.0%|0.0%|
[bm_tor](#bm_tor)|6522|6522|3|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|2976|2976|3|0.1%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|15388|15388|3|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47941|47941|2|0.0%|0.0%|
[et_compromised](#et_compromised)|2016|2016|2|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1720|1720|2|0.1%|0.0%|
[sorbs_spam](#sorbs_spam)|45326|46326|1|0.0%|0.0%|
[sorbs_recent_spam](#sorbs_recent_spam)|45326|46326|1|0.0%|0.0%|
[sorbs_new_spam](#sorbs_new_spam)|45326|46326|1|0.0%|0.0%|
[nixspam](#nixspam)|39997|39997|1|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4042|4042|1|0.0%|0.0%|

## xroxy

[xroxy.com](http://www.xroxy.com) open proxies (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.xroxy.com/proxyrss.xml).

The last time downloaded was found to be dated: Sun Jun  7 12:33:01 UTC 2015.

The ipset `xroxy` has **2115** entries, **2115** unique IPs.

The following table shows the overlaps of `xroxy` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `xroxy`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `xroxy`.
- ` this % ` is the percentage **of this ipset (`xroxy`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_30d](#stopforumspam_30d)|93068|93068|1251|1.3%|59.1%|
[ri_web_proxies](#ri_web_proxies)|6972|6828|910|13.3%|43.0%|
[stopforumspam_7d](#stopforumspam_7d)|29870|29870|695|2.3%|32.8%|
[proxyrss](#proxyrss)|1435|1435|381|26.5%|18.0%|
[ri_connect_proxies](#ri_connect_proxies)|2665|2516|369|14.6%|17.4%|
[proxz](#proxz)|967|967|363|37.5%|17.1%|
[stopforumspam_1d](#stopforumspam_1d)|6093|6093|252|4.1%|11.9%|
[blocklist_de](#blocklist_de)|27586|27586|207|0.7%|9.7%|
[blocklist_de_bots](#blocklist_de_bots)|2976|2976|164|5.5%|7.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72952|348710247|103|0.0%|4.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17813|139104928|98|0.0%|4.6%|
[sorbs_spam](#sorbs_spam)|45326|46326|82|0.1%|3.8%|
[sorbs_recent_spam](#sorbs_recent_spam)|45326|46326|82|0.1%|3.8%|
[sorbs_new_spam](#sorbs_new_spam)|45326|46326|82|0.1%|3.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218315|764993617|58|0.0%|2.7%|
[blocklist_de_mail](#blocklist_de_mail)|17025|17025|41|0.2%|1.9%|
[snort_ipfilter](#snort_ipfilter)|9812|9812|38|0.3%|1.7%|
[php_dictionary](#php_dictionary)|589|589|35|5.9%|1.6%|
[nixspam](#nixspam)|39997|39997|28|0.0%|1.3%|
[php_spammers](#php_spammers)|580|580|27|4.6%|1.2%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|13|1.9%|0.6%|
[sorbs_web](#sorbs_web)|619|619|11|1.7%|0.5%|
[php_commenters](#php_commenters)|349|349|8|2.2%|0.3%|
[blocklist_de_strongips](#blocklist_de_strongips)|165|165|7|4.2%|0.3%|
[alienvault_reputation](#alienvault_reputation)|178903|178903|4|0.0%|0.1%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47941|47941|3|0.0%|0.1%|
[php_harvesters](#php_harvesters)|324|324|2|0.6%|0.0%|
[et_tor](#et_tor)|6470|6470|2|0.0%|0.0%|
[dm_tor](#dm_tor)|6516|6516|2|0.0%|0.0%|
[bm_tor](#bm_tor)|6522|6522|2|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|15388|15388|2|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.0%|
[et_compromised](#et_compromised)|2016|2016|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1720|1720|1|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4042|4042|1|0.0%|0.0%|

## zeus

[Abuse.ch Zeus tracker](https://zeustracker.abuse.ch) standard, contains the same data as the ZeuS IP blocklist (zeus_badips) but with the slight difference that it doesn't exclude hijacked websites (level 2) and free web hosting providers (level 3). This means that this blocklist contains all IPv4 addresses associated with ZeuS C&Cs which are currently being tracked by ZeuS Tracker. Hence this blocklist will likely cause some false positives. - **excellent list**

Source is downloaded from [this link](https://zeustracker.abuse.ch/blocklist.php?download=ipblocklist).

The last time downloaded was found to be dated: Sun Jun  7 12:37:44 UTC 2015.

The ipset `zeus` has **232** entries, **232** unique IPs.

The following table shows the overlaps of `zeus` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `zeus`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `zeus`.
- ` this % ` is the percentage **of this ipset (`zeus`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[et_block](#et_block)|1023|18338662|223|0.0%|96.1%|
[zeus_badips](#zeus_badips)|203|203|203|100.0%|87.5%|
[snort_ipfilter](#snort_ipfilter)|9812|9812|200|2.0%|86.2%|
[alienvault_reputation](#alienvault_reputation)|178903|178903|61|0.0%|26.2%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|16|0.0%|6.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17813|139104928|13|0.0%|5.6%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|10|0.0%|4.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72952|348710247|9|0.0%|3.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218315|764993617|6|0.0%|2.5%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|5|0.0%|2.1%|
[stopforumspam_30d](#stopforumspam_30d)|93068|93068|2|0.0%|0.8%|
[openbl_60d](#openbl_60d)|7254|7254|2|0.0%|0.8%|
[openbl_30d](#openbl_30d)|3245|3245|2|0.0%|0.8%|
[stopforumspam_7d](#stopforumspam_7d)|29870|29870|1|0.0%|0.4%|
[stopforumspam_1d](#stopforumspam_1d)|6093|6093|1|0.0%|0.4%|
[php_commenters](#php_commenters)|349|349|1|0.2%|0.4%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.4%|
[blocklist_de_mail](#blocklist_de_mail)|17025|17025|1|0.0%|0.4%|
[blocklist_de_imap](#blocklist_de_imap)|2180|2180|1|0.0%|0.4%|
[blocklist_de](#blocklist_de)|27586|27586|1|0.0%|0.4%|

## zeus_badips

[Abuse.ch Zeus tracker](https://zeustracker.abuse.ch) badips includes IPv4 addresses that are used by the ZeuS trojan. It is the recommened blocklist if you want to block only ZeuS IPs. It excludes IP addresses that ZeuS Tracker believes to be hijacked (level 2) or belong to a free web hosting provider (level 3). Hence the false postive rate should be much lower compared to the standard ZeuS IP blocklist. **excellent list**

Source is downloaded from [this link](https://zeustracker.abuse.ch/blocklist.php?download=badips).

The last time downloaded was found to be dated: Sun Jun  7 12:41:05 UTC 2015.

The ipset `zeus_badips` has **203** entries, **203** unique IPs.

The following table shows the overlaps of `zeus_badips` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `zeus_badips`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `zeus_badips`.
- ` this % ` is the percentage **of this ipset (`zeus_badips`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[zeus](#zeus)|232|232|203|87.5%|100.0%|
[et_block](#et_block)|1023|18338662|200|0.0%|98.5%|
[snort_ipfilter](#snort_ipfilter)|9812|9812|179|1.8%|88.1%|
[alienvault_reputation](#alienvault_reputation)|178903|178903|38|0.0%|18.7%|
[spamhaus_drop](#spamhaus_drop)|653|18404096|16|0.0%|7.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17813|139104928|10|0.0%|4.9%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|10|0.0%|4.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72952|348710247|8|0.0%|3.9%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|5|0.0%|2.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218315|764993617|4|0.0%|1.9%|
[stopforumspam_30d](#stopforumspam_30d)|93068|93068|2|0.0%|0.9%|
[stopforumspam_7d](#stopforumspam_7d)|29870|29870|1|0.0%|0.4%|
[stopforumspam_1d](#stopforumspam_1d)|6093|6093|1|0.0%|0.4%|
[php_commenters](#php_commenters)|349|349|1|0.2%|0.4%|
[openbl_60d](#openbl_60d)|7254|7254|1|0.0%|0.4%|
[openbl_30d](#openbl_30d)|3245|3245|1|0.0%|0.4%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.4%|
[blocklist_de_mail](#blocklist_de_mail)|17025|17025|1|0.0%|0.4%|
[blocklist_de_imap](#blocklist_de_imap)|2180|2180|1|0.0%|0.4%|
[blocklist_de](#blocklist_de)|27586|27586|1|0.0%|0.4%|
