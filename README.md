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

The following list was automatically generated on Sun Jun  7 18:00:45 UTC 2015.

The update frequency is the maximum allowed by internal configuration. A list will never be downloaded sooner than the update frequency stated. A list may also not be downloaded, after this frequency expired, if it has not been modified on the server (as reported by HTTP `IF_MODIFIED_SINCE` method).

name|info|type|entries|update|
:--:|:--:|:--:|:-----:|:----:|
[alienvault_reputation](#alienvault_reputation)|[AlienVault.com](https://www.alienvault.com/) IP reputation database (this list seems to include port scanning hosts and to be updated regularly, but we found no information about its retention policy)|ipv4 hash:ip|180982 unique IPs|updated every 6 hours  from [this link](https://reputation.alienvault.com/reputation.generic)
[blocklist_de](#blocklist_de)|[Blocklist.de](https://www.blocklist.de/) IPs that have been detected by fail2ban in the last 48 hours - **excellent list**|ipv4 hash:ip|28720 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/all.txt)
[blocklist_de_apache](#blocklist_de_apache)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service Apache, Apache-DDOS, RFI-Attacks.|ipv4 hash:ip|16144 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/apache.txt)
[blocklist_de_bots](#blocklist_de_bots)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the RFI-Attacks, REG-Bots, IRC-Bots or BadBots (BadBots = he has posted a Spam-Comment on a open Forum or Wiki).|ipv4 hash:ip|3065 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/bots.txt)
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|[Blocklist.de](https://www.blocklist.de/) All IPs which attacks Joomlas, Wordpress and other Web-Logins with Brute-Force Logins.|ipv4 hash:ip|4804 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/bruteforcelogin.txt)
[blocklist_de_ftp](#blocklist_de_ftp)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours for attacks on the Service FTP.|ipv4 hash:ip|567 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/ftp.txt)
[blocklist_de_imap](#blocklist_de_imap)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours for attacks on the Service imap, sasl, pop3, etc.|ipv4 hash:ip|2450 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/imap.txt)
[blocklist_de_mail](#blocklist_de_mail)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service Mail, Postfix.|ipv4 hash:ip|17253 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/mail.txt)
[blocklist_de_sip](#blocklist_de_sip)|[Blocklist.de](https://www.blocklist.de/) All IP addresses that tried to login in a SIP, VOIP or Asterisk Server and are included in the IPs list from [infiltrated.net](www.infiltrated.net)|ipv4 hash:ip|86 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/sip.txt)
[blocklist_de_ssh](#blocklist_de_ssh)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service SSH.|ipv4 hash:ip|2701 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/ssh.txt)
[blocklist_de_strongips](#blocklist_de_strongips)|[Blocklist.de](https://www.blocklist.de/) All IPs which are older then 2 month and have more then 5.000 attacks.|ipv4 hash:ip|164 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/strongips.txt)
[bm_tor](#bm_tor)|[torstatus.blutmagie.de](https://torstatus.blutmagie.de) list of all TOR network servers|ipv4 hash:ip|6543 unique IPs|updated every 30 mins  from [this link](https://torstatus.blutmagie.de/ip_list_all.php/Tor_ip_list_ALL.csv)
[bogons](#bogons)|[Team-Cymru.org](http://www.team-cymru.org) private and reserved addresses defined by RFC 1918, RFC 5735, and RFC 6598 and netblocks that have not been allocated to a regional internet registry - **excellent list - use it only your internet interface**|ipv4 hash:net|13 subnets, 592708608 unique IPs|updated every 1 day  from [this link](http://www.team-cymru.org/Services/Bogons/bogon-bn-agg.txt)
[bruteforceblocker](#bruteforceblocker)|[danger.rulez.sk](http://danger.rulez.sk/) IPs detected by [bruteforceblocker](http://danger.rulez.sk/index.php/bruteforceblocker/) (fail2ban alternative for SSH on OpenBSD). This is an automatically generated list from users reporting failed authentication attempts. An IP seems to be included if 3 or more users report it. Its retention pocily seems 30 days.|ipv4 hash:ip|1706 unique IPs|updated every 3 hours  from [this link](http://danger.rulez.sk/projects/bruteforceblocker/blist.php)
[ciarmy](#ciarmy)|[CIArmy.com](http://ciarmy.com/) IPs with poor Rogue Packet score that have not yet been identified as malicious by the community|ipv4 hash:ip|433 unique IPs|updated every 3 hours  from [this link](http://cinsscore.com/list/ci-badguys.txt)
[cleanmx_viruses](#cleanmx_viruses)|[Clean-MX.de](http://support.clean-mx.de/clean-mx/viruses.php) IPs with viruses|ipv4 hash:ip|310 unique IPs|updated every 12 hours  from [this link](http://support.clean-mx.de/clean-mx/xmlviruses.php?sort=id%20desc&response=alive)
[dm_tor](#dm_tor)|[dan.me.uk](https://www.dan.me.uk) dynamic list of TOR exit points|ipv4 hash:ip|6564 unique IPs|updated every 30 mins  from [this link](https://www.dan.me.uk/torlist/)
[dshield](#dshield)|[DShield.org](https://dshield.org/) top 20 attacking class C (/24) subnets over the last three days - **excellent list**|ipv4 hash:net|20 subnets, 5120 unique IPs|updated every 4 hours  from [this link](http://feeds.dshield.org/block.txt)
[et_block](#et_block)|[EmergingThreats.net](http://www.emergingthreats.net/) default blacklist (at the time of writing includes spamhaus DROP, dshield and abuse.ch trackers, which are available separately too - prefer to use the direct ipsets instead of this, they seem to lag a bit in updates)|ipv4 hash:net|1023 subnets, 18338662 unique IPs|updated every 12 hours  from [this link](http://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt)
[et_botcc](#et_botcc)|[EmergingThreats.net Command and Control IPs](http://doc.emergingthreats.net/bin/view/Main/BotCC) These IPs are updates every 24 hours and should be considered VERY highly reliable indications that a host is communicating with a known and active Bot or Malware command and control server - (although they say this includes abuse.ch trackers, it does not - most probably it is the shadowserver.org C&C list)|ipv4 hash:ip|1 unique IPs|updated every 12 hours  from [this link](http://rules.emergingthreats.net/fwrules/emerging-PIX-CC.rules)
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
[malc0de](#malc0de)|[Malc0de.com](http://malc0de.com) malicious IPs of the last 30 days|ipv4 hash:ip|351 unique IPs|updated every 1 day  from [this link](http://malc0de.com/bl/IP_Blacklist.txt)
[malwaredomainlist](#malwaredomainlist)|[malwaredomainlist.com](http://www.malwaredomainlist.com) list of malware active ip addresses|ipv4 hash:ip|1288 unique IPs|updated every 12 hours  from [this link](http://www.malwaredomainlist.com/hostslist/ip.txt)
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|[MaxMind.com](https://www.maxmind.com/en/anonymous-proxy-fraudulent-ip-address-list) list of anonymous proxy fraudelent IP addresses.|ipv4 hash:ip|372 unique IPs|updated every 4 hours  from [this link](https://www.maxmind.com/en/anonymous-proxy-fraudulent-ip-address-list)
[nixspam](#nixspam)|[NiX Spam](http://www.heise.de/ix/NiX-Spam-DNSBL-and-blacklist-for-download-499637.html) IP addresses that sent spam in the last hour - automatically generated entries without distinguishing open proxies from relays, dialup gateways, and so on. All IPs are removed after 12 hours if there is no spam from there.|ipv4 hash:ip|39999 unique IPs|updated every 15 mins  from [this link](http://www.dnsbl.manitu.net/download/nixspam-ip.dump.gz)
openbl|[OpenBL.org](http://www.openbl.org/) default blacklist (currently it is the same with 90 days). OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications - **excellent list**|ipv4 hash:ip|disabled|updated every 4 hours  from [this link](http://www.openbl.org/lists/base.txt)
openbl_180d|[OpenBL.org](http://www.openbl.org/) last 180 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|disabled|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_180days.txt)
[openbl_1d](#openbl_1d)|[OpenBL.org](http://www.openbl.org/) last 24 hours IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|112 unique IPs|updated every 1 hour  from [this link](http://www.openbl.org/lists/base_1days.txt)
[openbl_30d](#openbl_30d)|[OpenBL.org](http://www.openbl.org/) last 30 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|3116 unique IPs|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_30days.txt)
openbl_360d|[OpenBL.org](http://www.openbl.org/) last 360 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|disabled|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_360days.txt)
[openbl_60d](#openbl_60d)|[OpenBL.org](http://www.openbl.org/) last 60 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|7251 unique IPs|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_60days.txt)
[openbl_7d](#openbl_7d)|[OpenBL.org](http://www.openbl.org/) last 7 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|812 unique IPs|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_7days.txt)
openbl_90d|[OpenBL.org](http://www.openbl.org/) last 90 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|disabled|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_90days.txt)
openbl_all|[OpenBL.org](http://www.openbl.org/) last all IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|disabled|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_all.txt)
[palevo](#palevo)|[Abuse.ch Palevo tracker](https://palevotracker.abuse.ch) worm includes IPs which are being used as botnet C&C for the Palevo crimeware - **excellent list**|ipv4 hash:ip|13 unique IPs|updated every 30 mins  from [this link](https://palevotracker.abuse.ch/blocklists.php?download=ipblocklist)
php_bad|[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) bad web hosts (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|disabled|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=b&rss=1)
[php_commenters](#php_commenters)|[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) comment spammers (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|373 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=c&rss=1)
[php_dictionary](#php_dictionary)|[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) directory attackers (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|589 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=d&rss=1)
[php_harvesters](#php_harvesters)|[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) harvesters (IPs that surf the internet looking for email addresses) (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|324 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=h&rss=1)
[php_spammers](#php_spammers)|[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) spam servers (IPs used by spammers to send messages) (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|580 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=s&rss=1)
[proxyrss](#proxyrss)|[proxyrss.com](http://www.proxyrss.com) open proxies syndicated from multiple sources.|ipv4 hash:ip|1454 unique IPs|updated every 4 hours  from [this link](http://www.proxyrss.com/proxylists/all.gz)
[proxz](#proxz)|[proxz.com](http://www.proxz.com) open proxies (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|985 unique IPs|updated every 1 hour  from [this link](http://www.proxz.com/proxylists.xml)
[ri_connect_proxies](#ri_connect_proxies)|[rosinstrument.com](http://www.rosinstrument.com) open CONNECT proxies (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|2533 unique IPs|updated every 1 hour  from [this link](http://tools.rosinstrument.com/proxy/plab100.xml)
[ri_web_proxies](#ri_web_proxies)|[rosinstrument.com](http://www.rosinstrument.com) open HTTP proxies (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|6930 unique IPs|updated every 1 hour  from [this link](http://tools.rosinstrument.com/proxy/l100.xml)
[shunlist](#shunlist)|[AutoShun.org](http://autoshun.org/) IPs identified as hostile by correlating logs from distributed snort installations running the autoshun plugin|ipv4 hash:ip|1188 unique IPs|updated every 4 hours  from [this link](http://www.autoshun.org/files/shunlist.csv)
[snort_ipfilter](#snort_ipfilter)|[labs.snort.org](https://labs.snort.org/) supplied IP blacklist (this list seems to be updated frequently, but we found no information about it)|ipv4 hash:ip|9408 unique IPs|updated every 12 hours  from [this link](http://labs.snort.org/feeds/ip-filter.blf)
[spamhaus_drop](#spamhaus_drop)|[Spamhaus.org](http://www.spamhaus.org) DROP list (according to their site this list should be dropped at tier-1 ISPs globaly) - **excellent list**|ipv4 hash:net|652 subnets, 18338560 unique IPs|updated every 12 hours  from [this link](http://www.spamhaus.org/drop/drop.txt)
[spamhaus_edrop](#spamhaus_edrop)|[Spamhaus.org](http://www.spamhaus.org) EDROP (extended matches that should be used with DROP) - **excellent list**|ipv4 hash:net|56 subnets, 487424 unique IPs|updated every 12 hours  from [this link](http://www.spamhaus.org/drop/edrop.txt)
[sslbl](#sslbl)|[Abuse.ch SSL Blacklist](https://sslbl.abuse.ch/) bad SSL traffic related to malware or botnet activities - **excellent list**|ipv4 hash:ip|375 unique IPs|updated every 30 mins  from [this link](https://sslbl.abuse.ch/blacklist/sslipblacklist.csv)
stopforumspam_180d|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 180 days)|ipv4 hash:ip|disabled|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/listed_ip_180.zip)
[stopforumspam_1d](#stopforumspam_1d)|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers in the last 24 hours - **excellent list**|ipv4 hash:ip|6071 unique IPs|updated every 1 hour  from [this link](http://www.stopforumspam.com/downloads/listed_ip_1.zip)
[stopforumspam_30d](#stopforumspam_30d)|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 30 days)|ipv4 hash:ip|93068 unique IPs|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/listed_ip_30.zip)
stopforumspam_365d|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 365 days)|ipv4 hash:ip|disabled|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/listed_ip_365.zip)
[stopforumspam_7d](#stopforumspam_7d)|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 7 days)|ipv4 hash:ip|29870 unique IPs|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/listed_ip_7.zip)
stopforumspam_90d|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 90 days)|ipv4 hash:ip|disabled|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/listed_ip_90.zip)
stopforumspam_ever|[StopForumSpam.com](http://www.stopforumspam.com) all IPs used by forum spammers, **ever** (normally you don't want to use this ipset, use the hourly one which includes last 24 hours IPs or the 7 days one)|ipv4 hash:ip|disabled|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/bannedips.zip)
[virbl](#virbl)|[VirBL](http://virbl.bit.nl/) is a project of which the idea was born during the RIPE-48 meeting. The plan was to get reports of virusscanning mailservers, and put the IP-addresses that were reported to send viruses on a blacklist.|ipv4 hash:ip|1 unique IPs|updated every 1 hour  from [this link](http://virbl.bit.nl/download/virbl.dnsbl.bit.nl.txt)
[voipbl](#voipbl)|[VoIPBL.org](http://www.voipbl.org/) a distributed VoIP blacklist that is aimed to protects against VoIP Fraud and minimizing abuse for network that have publicly accessible PBX's. Several algorithms, external sources and manual confirmation are used before they categorize something as an attack and determine the threat level.|ipv4 hash:net|10491 subnets, 10902 unique IPs|updated every 4 hours  from [this link](http://www.voipbl.org/update/)
[xroxy](#xroxy)|[xroxy.com](http://www.xroxy.com) open proxies (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|2119 unique IPs|updated every 1 hour  from [this link](http://www.xroxy.com/proxyrss.xml)
[zeus](#zeus)|[Abuse.ch Zeus tracker](https://zeustracker.abuse.ch) standard, contains the same data as the ZeuS IP blocklist (zeus_badips) but with the slight difference that it doesn't exclude hijacked websites (level 2) and free web hosting providers (level 3). This means that this blocklist contains all IPv4 addresses associated with ZeuS C&Cs which are currently being tracked by ZeuS Tracker. Hence this blocklist will likely cause some false positives. - **excellent list**|ipv4 hash:ip|232 unique IPs|updated every 30 mins  from [this link](https://zeustracker.abuse.ch/blocklist.php?download=ipblocklist)
[zeus_badips](#zeus_badips)|[Abuse.ch Zeus tracker](https://zeustracker.abuse.ch) badips includes IPv4 addresses that are used by the ZeuS trojan. It is the recommened blocklist if you want to block only ZeuS IPs. It excludes IP addresses that ZeuS Tracker believes to be hijacked (level 2) or belong to a free web hosting provider (level 3). Hence the false postive rate should be much lower compared to the standard ZeuS IP blocklist. **excellent list**|ipv4 hash:ip|203 unique IPs|updated every 30 mins  from [this link](https://zeustracker.abuse.ch/blocklist.php?download=badips)

# Comparison of ipsets

Below we compare each ipset against all other.


## alienvault_reputation

[AlienVault.com](https://www.alienvault.com/) IP reputation database (this list seems to include port scanning hosts and to be updated regularly, but we found no information about its retention policy)

Source is downloaded from [this link](https://reputation.alienvault.com/reputation.generic).

The last time downloaded was found to be dated: Sun Jun  7 16:00:25 UTC 2015.

The ipset `alienvault_reputation` has **180982** entries, **180982** unique IPs.

The following table shows the overlaps of `alienvault_reputation` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `alienvault_reputation`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `alienvault_reputation`.
- ` this % ` is the percentage **of this ipset (`alienvault_reputation`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|17813|139104928|14398|0.0%|7.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72952|348710247|7287|0.0%|4.0%|
[openbl_60d](#openbl_60d)|7251|7251|7230|99.7%|3.9%|
[et_block](#et_block)|1023|18338662|5281|0.0%|2.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|218315|764993617|3586|0.0%|1.9%|
[dshield](#dshield)|20|5120|3586|70.0%|1.9%|
[openbl_30d](#openbl_30d)|3116|3116|3101|99.5%|1.7%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|1632|0.0%|0.9%|
[et_compromised](#et_compromised)|2016|2016|1316|65.2%|0.7%|
[shunlist](#shunlist)|1188|1188|1182|99.4%|0.6%|
[blocklist_de](#blocklist_de)|28720|28720|1155|4.0%|0.6%|
[bruteforceblocker](#bruteforceblocker)|1706|1706|1089|63.8%|0.6%|
[blocklist_de_ssh](#blocklist_de_ssh)|2701|2701|920|34.0%|0.5%|
[openbl_7d](#openbl_7d)|812|812|806|99.2%|0.4%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|518|0.0%|0.2%|
[ciarmy](#ciarmy)|433|433|427|98.6%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|288|0.0%|0.1%|
[voipbl](#voipbl)|10491|10902|208|1.9%|0.1%|
[stopforumspam_30d](#stopforumspam_30d)|93068|93068|208|0.2%|0.1%|
[blocklist_de_apache](#blocklist_de_apache)|16144|16144|133|0.8%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9408|9408|119|1.2%|0.0%|
[openbl_1d](#openbl_1d)|112|112|110|98.2%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29870|29870|98|0.3%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|17253|17253|67|0.3%|0.0%|
[sslbl](#sslbl)|375|375|64|17.0%|0.0%|
[zeus](#zeus)|232|232|62|26.7%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6071|6071|52|0.8%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2450|2450|50|2.0%|0.0%|
[et_tor](#et_tor)|6470|6470|40|0.6%|0.0%|
[dm_tor](#dm_tor)|6564|6564|40|0.6%|0.0%|
[bm_tor](#bm_tor)|6543|6543|40|0.6%|0.0%|
[zeus_badips](#zeus_badips)|203|203|38|18.7%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|164|164|36|21.9%|0.0%|
[nixspam](#nixspam)|39999|39999|30|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|26|6.9%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3065|3065|26|0.8%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4804|4804|19|0.3%|0.0%|
[php_commenters](#php_commenters)|373|373|18|4.8%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|86|86|16|18.6%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|15|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47941|47941|15|0.0%|0.0%|
[malc0de](#malc0de)|351|351|11|3.1%|0.0%|
[php_harvesters](#php_harvesters)|324|324|10|3.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|10|0.6%|0.0%|
[php_dictionary](#php_dictionary)|589|589|8|1.3%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|7|0.5%|0.0%|
[php_spammers](#php_spammers)|580|580|6|1.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|567|567|5|0.8%|0.0%|
[xroxy](#xroxy)|2119|2119|4|0.1%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|310|310|4|1.2%|0.0%|
[ri_web_proxies](#ri_web_proxies)|6930|6930|3|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2533|2533|3|0.1%|0.0%|
[proxz](#proxz)|985|985|3|0.3%|0.0%|
[proxyrss](#proxyrss)|1454|1454|2|0.1%|0.0%|
[feodo](#feodo)|99|99|2|2.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|1|0.1%|0.0%|

## blocklist_de

[Blocklist.de](https://www.blocklist.de/) IPs that have been detected by fail2ban in the last 48 hours - **excellent list**

Source is downloaded from [this link](http://lists.blocklist.de/lists/all.txt).

The last time downloaded was found to be dated: Sun Jun  7 17:42:04 UTC 2015.

The ipset `blocklist_de` has **28720** entries, **28720** unique IPs.

The following table shows the overlaps of `blocklist_de` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de`.
- ` this % ` is the percentage **of this ipset (`blocklist_de`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de_mail](#blocklist_de_mail)|17253|17253|17228|99.8%|59.9%|
[blocklist_de_apache](#blocklist_de_apache)|16144|16144|16144|100.0%|56.2%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4804|4804|4804|100.0%|16.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|17813|139104928|3710|0.0%|12.9%|
[blocklist_de_bots](#blocklist_de_bots)|3065|3065|3049|99.4%|10.6%|
[blocklist_de_ssh](#blocklist_de_ssh)|2701|2701|2701|100.0%|9.4%|
[blocklist_de_imap](#blocklist_de_imap)|2450|2450|2446|99.8%|8.5%|
[stopforumspam_30d](#stopforumspam_30d)|93068|93068|2266|2.4%|7.8%|
[stopforumspam_7d](#stopforumspam_7d)|29870|29870|1931|6.4%|6.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|218315|764993617|1511|0.0%|5.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72952|348710247|1442|0.0%|5.0%|
[stopforumspam_1d](#stopforumspam_1d)|6071|6071|1280|21.0%|4.4%|
[alienvault_reputation](#alienvault_reputation)|180982|180982|1155|0.6%|4.0%|
[nixspam](#nixspam)|39999|39999|932|2.3%|3.2%|
[openbl_60d](#openbl_60d)|7251|7251|864|11.9%|3.0%|
[openbl_30d](#openbl_30d)|3116|3116|684|21.9%|2.3%|
[blocklist_de_ftp](#blocklist_de_ftp)|567|567|566|99.8%|1.9%|
[et_compromised](#et_compromised)|2016|2016|549|27.2%|1.9%|
[bruteforceblocker](#bruteforceblocker)|1706|1706|539|31.5%|1.8%|
[openbl_7d](#openbl_7d)|812|812|402|49.5%|1.3%|
[ri_web_proxies](#ri_web_proxies)|6930|6930|396|5.7%|1.3%|
[shunlist](#shunlist)|1188|1188|337|28.3%|1.1%|
[proxyrss](#proxyrss)|1454|1454|226|15.5%|0.7%|
[xroxy](#xroxy)|2119|2119|208|9.8%|0.7%|
[et_block](#et_block)|1023|18338662|179|0.0%|0.6%|
[blocklist_de_strongips](#blocklist_de_strongips)|164|164|164|100.0%|0.5%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|163|0.0%|0.5%|
[proxz](#proxz)|985|985|145|14.7%|0.5%|
[snort_ipfilter](#snort_ipfilter)|9408|9408|136|1.4%|0.4%|
[dshield](#dshield)|20|5120|117|2.2%|0.4%|
[php_commenters](#php_commenters)|373|373|91|24.3%|0.3%|
[openbl_1d](#openbl_1d)|112|112|83|74.1%|0.2%|
[php_spammers](#php_spammers)|580|580|81|13.9%|0.2%|
[php_dictionary](#php_dictionary)|589|589|80|13.5%|0.2%|
[ri_connect_proxies](#ri_connect_proxies)|2533|2533|67|2.6%|0.2%|
[blocklist_de_sip](#blocklist_de_sip)|86|86|67|77.9%|0.2%|
[ciarmy](#ciarmy)|433|433|36|8.3%|0.1%|
[voipbl](#voipbl)|10491|10902|34|0.3%|0.1%|
[php_harvesters](#php_harvesters)|324|324|33|10.1%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|33|0.0%|0.1%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47941|47941|15|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|9|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|4|0.0%|0.0%|
[et_tor](#et_tor)|6470|6470|4|0.0%|0.0%|
[dm_tor](#dm_tor)|6564|6564|4|0.0%|0.0%|
[bm_tor](#bm_tor)|6543|6543|3|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|2|0.1%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|2|0.3%|0.0%|
[zeus_badips](#zeus_badips)|203|203|1|0.4%|0.0%|
[zeus](#zeus)|232|232|1|0.4%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|

## blocklist_de_apache

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service Apache, Apache-DDOS, RFI-Attacks.

Source is downloaded from [this link](http://lists.blocklist.de/lists/apache.txt).

The last time downloaded was found to be dated: Sun Jun  7 17:56:04 UTC 2015.

The ipset `blocklist_de_apache` has **16144** entries, **16144** unique IPs.

The following table shows the overlaps of `blocklist_de_apache` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_apache`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_apache`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_apache`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|28720|28720|16144|56.2%|100.0%|
[blocklist_de_mail](#blocklist_de_mail)|17253|17253|11059|64.0%|68.5%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4804|4804|4804|100.0%|29.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|17813|139104928|2464|0.0%|15.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|218315|764993617|1316|0.0%|8.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72952|348710247|1090|0.0%|6.7%|
[stopforumspam_30d](#stopforumspam_30d)|93068|93068|207|0.2%|1.2%|
[alienvault_reputation](#alienvault_reputation)|180982|180982|133|0.0%|0.8%|
[stopforumspam_7d](#stopforumspam_7d)|29870|29870|120|0.4%|0.7%|
[stopforumspam_1d](#stopforumspam_1d)|6071|6071|45|0.7%|0.2%|
[shunlist](#shunlist)|1188|1188|36|3.0%|0.2%|
[ciarmy](#ciarmy)|433|433|33|7.6%|0.2%|
[nixspam](#nixspam)|39999|39999|31|0.0%|0.1%|
[blocklist_de_strongips](#blocklist_de_strongips)|164|164|31|18.9%|0.1%|
[php_commenters](#php_commenters)|373|373|26|6.9%|0.1%|
[blocklist_de_bots](#blocklist_de_bots)|3065|3065|22|0.7%|0.1%|
[et_block](#et_block)|1023|18338662|11|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9408|9408|9|0.0%|0.0%|
[openbl_60d](#openbl_60d)|7251|7251|8|0.1%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47941|47941|8|0.0%|0.0%|
[openbl_30d](#openbl_30d)|3116|3116|6|0.1%|0.0%|
[dshield](#dshield)|20|5120|6|0.1%|0.0%|
[php_spammers](#php_spammers)|580|580|5|0.8%|0.0%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|4|0.0%|0.0%|
[php_dictionary](#php_dictionary)|589|589|4|0.6%|0.0%|
[et_tor](#et_tor)|6470|6470|4|0.0%|0.0%|
[dm_tor](#dm_tor)|6564|6564|4|0.0%|0.0%|
[voipbl](#voipbl)|10491|10902|3|0.0%|0.0%|
[php_harvesters](#php_harvesters)|324|324|3|0.9%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|3|0.0%|0.0%|
[bm_tor](#bm_tor)|6543|6543|3|0.0%|0.0%|
[xroxy](#xroxy)|2119|2119|2|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|6930|6930|2|0.0%|0.0%|
[proxz](#proxz)|985|985|2|0.2%|0.0%|
[et_compromised](#et_compromised)|2016|2016|2|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1706|1706|2|0.1%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|1|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2533|2533|1|0.0%|0.0%|
[proxyrss](#proxyrss)|1454|1454|1|0.0%|0.0%|
[openbl_7d](#openbl_7d)|812|812|1|0.1%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|1|0.1%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.0%|

## blocklist_de_bots

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the RFI-Attacks, REG-Bots, IRC-Bots or BadBots (BadBots = he has posted a Spam-Comment on a open Forum or Wiki).

Source is downloaded from [this link](http://lists.blocklist.de/lists/bots.txt).

The last time downloaded was found to be dated: Sun Jun  7 17:56:13 UTC 2015.

The ipset `blocklist_de_bots` has **3065** entries, **3065** unique IPs.

The following table shows the overlaps of `blocklist_de_bots` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_bots`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_bots`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_bots`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|28720|28720|3049|10.6%|99.4%|
[stopforumspam_30d](#stopforumspam_30d)|93068|93068|1955|2.1%|63.7%|
[stopforumspam_7d](#stopforumspam_7d)|29870|29870|1768|5.9%|57.6%|
[stopforumspam_1d](#stopforumspam_1d)|6071|6071|1242|20.4%|40.5%|
[ri_web_proxies](#ri_web_proxies)|6930|6930|333|4.8%|10.8%|
[proxyrss](#proxyrss)|1454|1454|226|15.5%|7.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17813|139104928|200|0.0%|6.5%|
[xroxy](#xroxy)|2119|2119|167|7.8%|5.4%|
[blocklist_de_strongips](#blocklist_de_strongips)|164|164|123|75.0%|4.0%|
[proxz](#proxz)|985|985|119|12.0%|3.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72952|348710247|117|0.0%|3.8%|
[php_commenters](#php_commenters)|373|373|75|20.1%|2.4%|
[ri_connect_proxies](#ri_connect_proxies)|2533|2533|66|2.6%|2.1%|
[nixspam](#nixspam)|39999|39999|33|0.0%|1.0%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|29|0.0%|0.9%|
[et_block](#et_block)|1023|18338662|29|0.0%|0.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|218315|764993617|27|0.0%|0.8%|
[alienvault_reputation](#alienvault_reputation)|180982|180982|26|0.0%|0.8%|
[php_harvesters](#php_harvesters)|324|324|25|7.7%|0.8%|
[php_spammers](#php_spammers)|580|580|22|3.7%|0.7%|
[php_dictionary](#php_dictionary)|589|589|22|3.7%|0.7%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|22|0.0%|0.7%|
[blocklist_de_mail](#blocklist_de_mail)|17253|17253|22|0.1%|0.7%|
[blocklist_de_apache](#blocklist_de_apache)|16144|16144|22|0.1%|0.7%|
[snort_ipfilter](#snort_ipfilter)|9408|9408|20|0.2%|0.6%|
[openbl_60d](#openbl_60d)|7251|7251|10|0.1%|0.3%|
[voipbl](#voipbl)|10491|10902|3|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|2|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|2|0.0%|0.0%|
[openbl_30d](#openbl_30d)|3116|3116|1|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|1|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|1|0.1%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47941|47941|1|0.0%|0.0%|

## blocklist_de_bruteforce

[Blocklist.de](https://www.blocklist.de/) All IPs which attacks Joomlas, Wordpress and other Web-Logins with Brute-Force Logins.

Source is downloaded from [this link](http://lists.blocklist.de/lists/bruteforcelogin.txt).

The last time downloaded was found to be dated: Sun Jun  7 17:56:15 UTC 2015.

The ipset `blocklist_de_bruteforce` has **4804** entries, **4804** unique IPs.

The following table shows the overlaps of `blocklist_de_bruteforce` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_bruteforce`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_bruteforce`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_bruteforce`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de_apache](#blocklist_de_apache)|16144|16144|4804|29.7%|100.0%|
[blocklist_de](#blocklist_de)|28720|28720|4804|16.7%|100.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17813|139104928|367|0.0%|7.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72952|348710247|58|0.0%|1.2%|
[stopforumspam_30d](#stopforumspam_30d)|93068|93068|53|0.0%|1.1%|
[stopforumspam_7d](#stopforumspam_7d)|29870|29870|31|0.1%|0.6%|
[nixspam](#nixspam)|39999|39999|31|0.0%|0.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218315|764993617|26|0.0%|0.5%|
[alienvault_reputation](#alienvault_reputation)|180982|180982|19|0.0%|0.3%|
[stopforumspam_1d](#stopforumspam_1d)|6071|6071|10|0.1%|0.2%|
[php_commenters](#php_commenters)|373|373|8|2.1%|0.1%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47941|47941|7|0.0%|0.1%|
[blocklist_de_strongips](#blocklist_de_strongips)|164|164|6|3.6%|0.1%|
[snort_ipfilter](#snort_ipfilter)|9408|9408|5|0.0%|0.1%|
[php_spammers](#php_spammers)|580|580|5|0.8%|0.1%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|4|0.0%|0.0%|
[php_dictionary](#php_dictionary)|589|589|4|0.6%|0.0%|
[et_block](#et_block)|1023|18338662|4|0.0%|0.0%|
[php_harvesters](#php_harvesters)|324|324|2|0.6%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|2|0.0%|0.0%|
[xroxy](#xroxy)|2119|2119|1|0.0%|0.0%|
[voipbl](#voipbl)|10491|10902|1|0.0%|0.0%|
[shunlist](#shunlist)|1188|1188|1|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|6930|6930|1|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2533|2533|1|0.0%|0.0%|
[proxz](#proxz)|985|985|1|0.1%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.0%|
[ciarmy](#ciarmy)|433|433|1|0.2%|0.0%|

## blocklist_de_ftp

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours for attacks on the Service FTP.

Source is downloaded from [this link](http://lists.blocklist.de/lists/ftp.txt).

The last time downloaded was found to be dated: Sun Jun  7 17:56:11 UTC 2015.

The ipset `blocklist_de_ftp` has **567** entries, **567** unique IPs.

The following table shows the overlaps of `blocklist_de_ftp` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_ftp`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_ftp`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_ftp`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|28720|28720|566|1.9%|99.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17813|139104928|46|0.0%|8.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72952|348710247|12|0.0%|2.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|218315|764993617|12|0.0%|2.1%|
[stopforumspam_30d](#stopforumspam_30d)|93068|93068|10|0.0%|1.7%|
[php_harvesters](#php_harvesters)|324|324|5|1.5%|0.8%|
[nixspam](#nixspam)|39999|39999|5|0.0%|0.8%|
[alienvault_reputation](#alienvault_reputation)|180982|180982|5|0.0%|0.8%|
[stopforumspam_7d](#stopforumspam_7d)|29870|29870|4|0.0%|0.7%|
[blocklist_de_strongips](#blocklist_de_strongips)|164|164|2|1.2%|0.3%|
[snort_ipfilter](#snort_ipfilter)|9408|9408|1|0.0%|0.1%|
[php_spammers](#php_spammers)|580|580|1|0.1%|0.1%|
[php_dictionary](#php_dictionary)|589|589|1|0.1%|0.1%|

## blocklist_de_imap

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours for attacks on the Service imap, sasl, pop3, etc.

Source is downloaded from [this link](http://lists.blocklist.de/lists/imap.txt).

The last time downloaded was found to be dated: Sun Jun  7 17:56:11 UTC 2015.

The ipset `blocklist_de_imap` has **2450** entries, **2450** unique IPs.

The following table shows the overlaps of `blocklist_de_imap` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_imap`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_imap`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_imap`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de_mail](#blocklist_de_mail)|17253|17253|2450|14.2%|100.0%|
[blocklist_de](#blocklist_de)|28720|28720|2446|8.5%|99.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17813|139104928|224|0.0%|9.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72952|348710247|50|0.0%|2.0%|
[alienvault_reputation](#alienvault_reputation)|180982|180982|50|0.0%|2.0%|
[openbl_60d](#openbl_60d)|7251|7251|41|0.5%|1.6%|
[openbl_30d](#openbl_30d)|3116|3116|36|1.1%|1.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218315|764993617|31|0.0%|1.2%|
[nixspam](#nixspam)|39999|39999|21|0.0%|0.8%|
[et_block](#et_block)|1023|18338662|16|0.0%|0.6%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|15|0.0%|0.6%|
[et_compromised](#et_compromised)|2016|2016|15|0.7%|0.6%|
[stopforumspam_30d](#stopforumspam_30d)|93068|93068|14|0.0%|0.5%|
[bruteforceblocker](#bruteforceblocker)|1706|1706|14|0.8%|0.5%|
[openbl_7d](#openbl_7d)|812|812|12|1.4%|0.4%|
[ri_web_proxies](#ri_web_proxies)|6930|6930|9|0.1%|0.3%|
[stopforumspam_7d](#stopforumspam_7d)|29870|29870|8|0.0%|0.3%|
[snort_ipfilter](#snort_ipfilter)|9408|9408|8|0.0%|0.3%|
[shunlist](#shunlist)|1188|1188|4|0.3%|0.1%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47941|47941|4|0.0%|0.1%|
[php_dictionary](#php_dictionary)|589|589|2|0.3%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2|0.0%|0.0%|
[zeus_badips](#zeus_badips)|203|203|1|0.4%|0.0%|
[zeus](#zeus)|232|232|1|0.4%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6071|6071|1|0.0%|0.0%|
[php_spammers](#php_spammers)|580|580|1|0.1%|0.0%|
[php_commenters](#php_commenters)|373|373|1|0.2%|0.0%|
[ciarmy](#ciarmy)|433|433|1|0.2%|0.0%|

## blocklist_de_mail

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service Mail, Postfix.

Source is downloaded from [this link](http://lists.blocklist.de/lists/mail.txt).

The last time downloaded was found to be dated: Sun Jun  7 17:56:04 UTC 2015.

The ipset `blocklist_de_mail` has **17253** entries, **17253** unique IPs.

The following table shows the overlaps of `blocklist_de_mail` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_mail`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_mail`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_mail`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|28720|28720|17228|59.9%|99.8%|
[blocklist_de_apache](#blocklist_de_apache)|16144|16144|11059|68.5%|64.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17813|139104928|2617|0.0%|15.1%|
[blocklist_de_imap](#blocklist_de_imap)|2450|2450|2450|100.0%|14.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|218315|764993617|1384|0.0%|8.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72952|348710247|1149|0.0%|6.6%|
[nixspam](#nixspam)|39999|39999|862|2.1%|4.9%|
[stopforumspam_30d](#stopforumspam_30d)|93068|93068|242|0.2%|1.4%|
[stopforumspam_7d](#stopforumspam_7d)|29870|29870|133|0.4%|0.7%|
[snort_ipfilter](#snort_ipfilter)|9408|9408|109|1.1%|0.6%|
[alienvault_reputation](#alienvault_reputation)|180982|180982|67|0.0%|0.3%|
[ri_web_proxies](#ri_web_proxies)|6930|6930|61|0.8%|0.3%|
[php_dictionary](#php_dictionary)|589|589|53|8.9%|0.3%|
[php_spammers](#php_spammers)|580|580|52|8.9%|0.3%|
[stopforumspam_1d](#stopforumspam_1d)|6071|6071|48|0.7%|0.2%|
[openbl_60d](#openbl_60d)|7251|7251|48|0.6%|0.2%|
[openbl_30d](#openbl_30d)|3116|3116|42|1.3%|0.2%|
[xroxy](#xroxy)|2119|2119|39|1.8%|0.2%|
[proxz](#proxz)|985|985|24|2.4%|0.1%|
[et_block](#et_block)|1023|18338662|23|0.0%|0.1%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|22|0.0%|0.1%|
[php_commenters](#php_commenters)|373|373|22|5.8%|0.1%|
[blocklist_de_strongips](#blocklist_de_strongips)|164|164|22|13.4%|0.1%|
[blocklist_de_bots](#blocklist_de_bots)|3065|3065|22|0.7%|0.1%|
[et_compromised](#et_compromised)|2016|2016|16|0.7%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1706|1706|15|0.8%|0.0%|
[openbl_7d](#openbl_7d)|812|812|14|1.7%|0.0%|
[shunlist](#shunlist)|1188|1188|5|0.4%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|5|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47941|47941|5|0.0%|0.0%|
[et_tor](#et_tor)|6470|6470|4|0.0%|0.0%|
[dm_tor](#dm_tor)|6564|6564|4|0.0%|0.0%|
[bm_tor](#bm_tor)|6543|6543|3|0.0%|0.0%|
[php_harvesters](#php_harvesters)|324|324|2|0.6%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|2|0.0%|0.0%|
[zeus_badips](#zeus_badips)|203|203|1|0.4%|0.0%|
[zeus](#zeus)|232|232|1|0.4%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2533|2533|1|0.0%|0.0%|
[proxyrss](#proxyrss)|1454|1454|1|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[ciarmy](#ciarmy)|433|433|1|0.2%|0.0%|

## blocklist_de_sip

[Blocklist.de](https://www.blocklist.de/) All IP addresses that tried to login in a SIP, VOIP or Asterisk Server and are included in the IPs list from [infiltrated.net](www.infiltrated.net)

Source is downloaded from [this link](http://lists.blocklist.de/lists/sip.txt).

The last time downloaded was found to be dated: Sun Jun  7 17:42:06 UTC 2015.

The ipset `blocklist_de_sip` has **86** entries, **86** unique IPs.

The following table shows the overlaps of `blocklist_de_sip` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_sip`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_sip`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_sip`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|28720|28720|67|0.2%|77.9%|
[voipbl](#voipbl)|10491|10902|28|0.2%|32.5%|
[alienvault_reputation](#alienvault_reputation)|180982|180982|16|0.0%|18.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|17813|139104928|13|0.0%|15.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72952|348710247|6|0.0%|6.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|218315|764993617|4|0.0%|4.6%|
[et_block](#et_block)|1023|18338662|3|0.0%|3.4%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|2|0.0%|2.3%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|1|0.0%|1.1%|

## blocklist_de_ssh

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service SSH.

Source is downloaded from [this link](http://lists.blocklist.de/lists/ssh.txt).

The last time downloaded was found to be dated: Sun Jun  7 17:42:03 UTC 2015.

The ipset `blocklist_de_ssh` has **2701** entries, **2701** unique IPs.

The following table shows the overlaps of `blocklist_de_ssh` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_ssh`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_ssh`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_ssh`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|28720|28720|2701|9.4%|100.0%|
[alienvault_reputation](#alienvault_reputation)|180982|180982|920|0.5%|34.0%|
[openbl_60d](#openbl_60d)|7251|7251|798|11.0%|29.5%|
[openbl_30d](#openbl_30d)|3116|3116|635|20.3%|23.5%|
[et_compromised](#et_compromised)|2016|2016|531|26.3%|19.6%|
[bruteforceblocker](#bruteforceblocker)|1706|1706|522|30.5%|19.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17813|139104928|440|0.0%|16.2%|
[openbl_7d](#openbl_7d)|812|812|386|47.5%|14.2%|
[shunlist](#shunlist)|1188|1188|296|24.9%|10.9%|
[et_block](#et_block)|1023|18338662|113|0.0%|4.1%|
[dshield](#dshield)|20|5120|111|2.1%|4.1%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|107|0.0%|3.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72952|348710247|95|0.0%|3.5%|
[openbl_1d](#openbl_1d)|112|112|83|74.1%|3.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218315|764993617|55|0.0%|2.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|164|164|28|17.0%|1.0%|
[stopforumspam_30d](#stopforumspam_30d)|93068|93068|11|0.0%|0.4%|
[nixspam](#nixspam)|39999|39999|9|0.0%|0.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|5|0.0%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|3|0.0%|0.1%|
[stopforumspam_7d](#stopforumspam_7d)|29870|29870|2|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9408|9408|2|0.0%|0.0%|
[ciarmy](#ciarmy)|433|433|2|0.4%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|1|0.0%|0.0%|
[php_spammers](#php_spammers)|580|580|1|0.1%|0.0%|
[php_commenters](#php_commenters)|373|373|1|0.2%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|1|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47941|47941|1|0.0%|0.0%|

## blocklist_de_strongips

[Blocklist.de](https://www.blocklist.de/) All IPs which are older then 2 month and have more then 5.000 attacks.

Source is downloaded from [this link](http://lists.blocklist.de/lists/strongips.txt).

The last time downloaded was found to be dated: Sun Jun  7 17:42:10 UTC 2015.

The ipset `blocklist_de_strongips` has **164** entries, **164** unique IPs.

The following table shows the overlaps of `blocklist_de_strongips` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_strongips`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_strongips`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_strongips`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|28720|28720|164|0.5%|100.0%|
[stopforumspam_30d](#stopforumspam_30d)|93068|93068|124|0.1%|75.6%|
[blocklist_de_bots](#blocklist_de_bots)|3065|3065|123|4.0%|75.0%|
[stopforumspam_7d](#stopforumspam_7d)|29870|29870|113|0.3%|68.9%|
[stopforumspam_1d](#stopforumspam_1d)|6071|6071|89|1.4%|54.2%|
[php_commenters](#php_commenters)|373|373|37|9.9%|22.5%|
[alienvault_reputation](#alienvault_reputation)|180982|180982|36|0.0%|21.9%|
[blocklist_de_apache](#blocklist_de_apache)|16144|16144|31|0.1%|18.9%|
[blocklist_de_ssh](#blocklist_de_ssh)|2701|2701|28|1.0%|17.0%|
[openbl_60d](#openbl_60d)|7251|7251|26|0.3%|15.8%|
[openbl_7d](#openbl_7d)|812|812|24|2.9%|14.6%|
[openbl_30d](#openbl_30d)|3116|3116|24|0.7%|14.6%|
[blocklist_de_mail](#blocklist_de_mail)|17253|17253|22|0.1%|13.4%|
[shunlist](#shunlist)|1188|1188|20|1.6%|12.1%|
[openbl_1d](#openbl_1d)|112|112|19|16.9%|11.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17813|139104928|15|0.0%|9.1%|
[dshield](#dshield)|20|5120|8|0.1%|4.8%|
[xroxy](#xroxy)|2119|2119|7|0.3%|4.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72952|348710247|7|0.0%|4.2%|
[et_block](#et_block)|1023|18338662|7|0.0%|4.2%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|6|0.0%|3.6%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4804|4804|6|0.1%|3.6%|
[ri_web_proxies](#ri_web_proxies)|6930|6930|5|0.0%|3.0%|
[php_spammers](#php_spammers)|580|580|5|0.8%|3.0%|
[proxz](#proxz)|985|985|4|0.4%|2.4%|
[proxyrss](#proxyrss)|1454|1454|3|0.2%|1.8%|
[php_harvesters](#php_harvesters)|324|324|3|0.9%|1.8%|
[php_dictionary](#php_dictionary)|589|589|3|0.5%|1.8%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|1.8%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|2|0.0%|1.2%|
[nixspam](#nixspam)|39999|39999|2|0.0%|1.2%|
[blocklist_de_ftp](#blocklist_de_ftp)|567|567|2|0.3%|1.2%|
[snort_ipfilter](#snort_ipfilter)|9408|9408|1|0.0%|0.6%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|1|0.0%|0.6%|
[bruteforceblocker](#bruteforceblocker)|1706|1706|1|0.0%|0.6%|

## bm_tor

[torstatus.blutmagie.de](https://torstatus.blutmagie.de) list of all TOR network servers

Source is downloaded from [this link](https://torstatus.blutmagie.de/ip_list_all.php/Tor_ip_list_ALL.csv).

The last time downloaded was found to be dated: Sun Jun  7 17:54:07 UTC 2015.

The ipset `bm_tor` has **6543** entries, **6543** unique IPs.

The following table shows the overlaps of `bm_tor` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `bm_tor`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `bm_tor`.
- ` this % ` is the percentage **of this ipset (`bm_tor`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[dm_tor](#dm_tor)|6564|6564|6410|97.6%|97.9%|
[et_tor](#et_tor)|6470|6470|5633|87.0%|86.0%|
[snort_ipfilter](#snort_ipfilter)|9408|9408|1088|11.5%|16.6%|
[stopforumspam_30d](#stopforumspam_30d)|93068|93068|630|0.6%|9.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|17813|139104928|629|0.0%|9.6%|
[stopforumspam_7d](#stopforumspam_7d)|29870|29870|495|1.6%|7.5%|
[stopforumspam_1d](#stopforumspam_1d)|6071|6071|327|5.3%|4.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72952|348710247|188|0.0%|2.8%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|167|44.8%|2.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218315|764993617|166|0.0%|2.5%|
[php_commenters](#php_commenters)|373|373|42|11.2%|0.6%|
[alienvault_reputation](#alienvault_reputation)|180982|180982|40|0.0%|0.6%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|22|0.0%|0.3%|
[openbl_60d](#openbl_60d)|7251|7251|20|0.2%|0.3%|
[php_harvesters](#php_harvesters)|324|324|7|2.1%|0.1%|
[et_block](#et_block)|1023|18338662|5|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|6930|6930|4|0.0%|0.0%|
[php_spammers](#php_spammers)|580|580|4|0.6%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|4|0.0%|0.0%|
[voipbl](#voipbl)|10491|10902|3|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|3|0.0%|0.0%|
[php_dictionary](#php_dictionary)|589|589|3|0.5%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|17253|17253|3|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|16144|16144|3|0.0%|0.0%|
[blocklist_de](#blocklist_de)|28720|28720|3|0.0%|0.0%|
[xroxy](#xroxy)|2119|2119|2|0.0%|0.0%|
[nixspam](#nixspam)|39999|39999|2|0.0%|0.0%|
[shunlist](#shunlist)|1188|1188|1|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2533|2533|1|0.0%|0.0%|
[proxyrss](#proxyrss)|1454|1454|1|0.0%|0.0%|

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
[voipbl](#voipbl)|10491|10902|319|2.9%|0.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218315|764993617|5|0.0%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|93068|93068|1|0.0%|0.0%|
[php_harvesters](#php_harvesters)|324|324|1|0.3%|0.0%|
[php_commenters](#php_commenters)|373|373|1|0.2%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.0%|
[et_botcc](#et_botcc)|0|1|1|100.0%|0.0%|
[ciarmy](#ciarmy)|433|433|1|0.2%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1706|1706|1|0.0%|0.0%|

## bruteforceblocker

[danger.rulez.sk](http://danger.rulez.sk/) IPs detected by [bruteforceblocker](http://danger.rulez.sk/index.php/bruteforceblocker/) (fail2ban alternative for SSH on OpenBSD). This is an automatically generated list from users reporting failed authentication attempts. An IP seems to be included if 3 or more users report it. Its retention pocily seems 30 days.

Source is downloaded from [this link](http://danger.rulez.sk/projects/bruteforceblocker/blist.php).

The last time downloaded was found to be dated: Sun Jun  7 16:07:47 UTC 2015.

The ipset `bruteforceblocker` has **1706** entries, **1706** unique IPs.

The following table shows the overlaps of `bruteforceblocker` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `bruteforceblocker`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `bruteforceblocker`.
- ` this % ` is the percentage **of this ipset (`bruteforceblocker`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[et_compromised](#et_compromised)|2016|2016|1634|81.0%|95.7%|
[alienvault_reputation](#alienvault_reputation)|180982|180982|1089|0.6%|63.8%|
[openbl_60d](#openbl_60d)|7251|7251|996|13.7%|58.3%|
[openbl_30d](#openbl_30d)|3116|3116|961|30.8%|56.3%|
[blocklist_de](#blocklist_de)|28720|28720|539|1.8%|31.5%|
[blocklist_de_ssh](#blocklist_de_ssh)|2701|2701|522|19.3%|30.5%|
[shunlist](#shunlist)|1188|1188|395|33.2%|23.1%|
[openbl_7d](#openbl_7d)|812|812|320|39.4%|18.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|17813|139104928|155|0.0%|9.0%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|101|0.0%|5.9%|
[et_block](#et_block)|1023|18338662|101|0.0%|5.9%|
[dshield](#dshield)|20|5120|101|1.9%|5.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72952|348710247|86|0.0%|5.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218315|764993617|46|0.0%|2.6%|
[openbl_1d](#openbl_1d)|112|112|39|34.8%|2.2%|
[blocklist_de_mail](#blocklist_de_mail)|17253|17253|15|0.0%|0.8%|
[blocklist_de_imap](#blocklist_de_imap)|2450|2450|14|0.5%|0.8%|
[stopforumspam_30d](#stopforumspam_30d)|93068|93068|13|0.0%|0.7%|
[stopforumspam_7d](#stopforumspam_7d)|29870|29870|7|0.0%|0.4%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|5|0.0%|0.2%|
[stopforumspam_1d](#stopforumspam_1d)|6071|6071|3|0.0%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|3|0.0%|0.1%|
[voipbl](#voipbl)|10491|10902|2|0.0%|0.1%|
[proxz](#proxz)|985|985|2|0.2%|0.1%|
[nixspam](#nixspam)|39999|39999|2|0.0%|0.1%|
[blocklist_de_apache](#blocklist_de_apache)|16144|16144|2|0.0%|0.1%|
[xroxy](#xroxy)|2119|2119|1|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9408|9408|1|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|6930|6930|1|0.0%|0.0%|
[proxyrss](#proxyrss)|1454|1454|1|0.0%|0.0%|
[php_spammers](#php_spammers)|580|580|1|0.1%|0.0%|
[php_commenters](#php_commenters)|373|373|1|0.2%|0.0%|
[fullbogons](#fullbogons)|3720|670264216|1|0.0%|0.0%|
[ciarmy](#ciarmy)|433|433|1|0.2%|0.0%|
[bogons](#bogons)|13|592708608|1|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|164|164|1|0.6%|0.0%|

## ciarmy

[CIArmy.com](http://ciarmy.com/) IPs with poor Rogue Packet score that have not yet been identified as malicious by the community

Source is downloaded from [this link](http://cinsscore.com/list/ci-badguys.txt).

The last time downloaded was found to be dated: Sun Jun  7 16:15:16 UTC 2015.

The ipset `ciarmy` has **433** entries, **433** unique IPs.

The following table shows the overlaps of `ciarmy` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ciarmy`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ciarmy`.
- ` this % ` is the percentage **of this ipset (`ciarmy`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[alienvault_reputation](#alienvault_reputation)|180982|180982|427|0.2%|98.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|17813|139104928|82|0.0%|18.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72952|348710247|44|0.0%|10.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|218315|764993617|36|0.0%|8.3%|
[blocklist_de](#blocklist_de)|28720|28720|36|0.1%|8.3%|
[shunlist](#shunlist)|1188|1188|34|2.8%|7.8%|
[blocklist_de_apache](#blocklist_de_apache)|16144|16144|33|0.2%|7.6%|
[et_block](#et_block)|1023|18338662|6|0.0%|1.3%|
[voipbl](#voipbl)|10491|10902|4|0.0%|0.9%|
[dshield](#dshield)|20|5120|4|0.0%|0.9%|
[blocklist_de_ssh](#blocklist_de_ssh)|2701|2701|2|0.0%|0.4%|
[stopforumspam_7d](#stopforumspam_7d)|29870|29870|1|0.0%|0.2%|
[stopforumspam_30d](#stopforumspam_30d)|93068|93068|1|0.0%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.2%|
[fullbogons](#fullbogons)|3720|670264216|1|0.0%|0.2%|
[et_compromised](#et_compromised)|2016|2016|1|0.0%|0.2%|
[bruteforceblocker](#bruteforceblocker)|1706|1706|1|0.0%|0.2%|
[bogons](#bogons)|13|592708608|1|0.0%|0.2%|
[blocklist_de_mail](#blocklist_de_mail)|17253|17253|1|0.0%|0.2%|
[blocklist_de_imap](#blocklist_de_imap)|2450|2450|1|0.0%|0.2%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4804|4804|1|0.0%|0.2%|

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
[malc0de](#malc0de)|351|351|14|3.9%|4.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72952|348710247|14|0.0%|4.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218315|764993617|9|0.0%|2.9%|
[alienvault_reputation](#alienvault_reputation)|180982|180982|4|0.0%|1.2%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|2|0.1%|0.6%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.3%|

## dm_tor

[dan.me.uk](https://www.dan.me.uk) dynamic list of TOR exit points

Source is downloaded from [this link](https://www.dan.me.uk/torlist/).

The last time downloaded was found to be dated: Sun Jun  7 17:54:04 UTC 2015.

The ipset `dm_tor` has **6564** entries, **6564** unique IPs.

The following table shows the overlaps of `dm_tor` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `dm_tor`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `dm_tor`.
- ` this % ` is the percentage **of this ipset (`dm_tor`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[bm_tor](#bm_tor)|6543|6543|6410|97.9%|97.6%|
[et_tor](#et_tor)|6470|6470|5620|86.8%|85.6%|
[snort_ipfilter](#snort_ipfilter)|9408|9408|1085|11.5%|16.5%|
[stopforumspam_30d](#stopforumspam_30d)|93068|93068|630|0.6%|9.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17813|139104928|622|0.0%|9.4%|
[stopforumspam_7d](#stopforumspam_7d)|29870|29870|494|1.6%|7.5%|
[stopforumspam_1d](#stopforumspam_1d)|6071|6071|325|5.3%|4.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72952|348710247|188|0.0%|2.8%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|169|45.4%|2.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218315|764993617|164|0.0%|2.4%|
[php_commenters](#php_commenters)|373|373|42|11.2%|0.6%|
[alienvault_reputation](#alienvault_reputation)|180982|180982|40|0.0%|0.6%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|22|0.0%|0.3%|
[openbl_60d](#openbl_60d)|7251|7251|20|0.2%|0.3%|
[php_harvesters](#php_harvesters)|324|324|7|2.1%|0.1%|
[et_block](#et_block)|1023|18338662|5|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|6930|6930|4|0.0%|0.0%|
[php_spammers](#php_spammers)|580|580|4|0.6%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|4|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|17253|17253|4|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|16144|16144|4|0.0%|0.0%|
[blocklist_de](#blocklist_de)|28720|28720|4|0.0%|0.0%|
[voipbl](#voipbl)|10491|10902|3|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|3|0.0%|0.0%|
[php_dictionary](#php_dictionary)|589|589|3|0.5%|0.0%|
[xroxy](#xroxy)|2119|2119|2|0.0%|0.0%|
[nixspam](#nixspam)|39999|39999|2|0.0%|0.0%|
[shunlist](#shunlist)|1188|1188|1|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2533|2533|1|0.0%|0.0%|
[proxyrss](#proxyrss)|1454|1454|1|0.0%|0.0%|

## dshield

[DShield.org](https://dshield.org/) top 20 attacking class C (/24) subnets over the last three days - **excellent list**

Source is downloaded from [this link](http://feeds.dshield.org/block.txt).

The last time downloaded was found to be dated: Sun Jun  7 15:56:16 UTC 2015.

The ipset `dshield` has **20** entries, **5120** unique IPs.

The following table shows the overlaps of `dshield` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `dshield`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `dshield`.
- ` this % ` is the percentage **of this ipset (`dshield`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[alienvault_reputation](#alienvault_reputation)|180982|180982|3586|1.9%|70.0%|
[et_block](#et_block)|1023|18338662|1536|0.0%|30.0%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|512|0.0%|10.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218315|764993617|257|0.0%|5.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17813|139104928|256|0.0%|5.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72952|348710247|256|0.0%|5.0%|
[openbl_60d](#openbl_60d)|7251|7251|165|2.2%|3.2%|
[openbl_30d](#openbl_30d)|3116|3116|149|4.7%|2.9%|
[shunlist](#shunlist)|1188|1188|123|10.3%|2.4%|
[blocklist_de](#blocklist_de)|28720|28720|117|0.4%|2.2%|
[blocklist_de_ssh](#blocklist_de_ssh)|2701|2701|111|4.1%|2.1%|
[et_compromised](#et_compromised)|2016|2016|110|5.4%|2.1%|
[bruteforceblocker](#bruteforceblocker)|1706|1706|101|5.9%|1.9%|
[openbl_7d](#openbl_7d)|812|812|48|5.9%|0.9%|
[openbl_1d](#openbl_1d)|112|112|18|16.0%|0.3%|
[blocklist_de_strongips](#blocklist_de_strongips)|164|164|8|4.8%|0.1%|
[blocklist_de_apache](#blocklist_de_apache)|16144|16144|6|0.0%|0.1%|
[ciarmy](#ciarmy)|433|433|4|0.9%|0.0%|
[malc0de](#malc0de)|351|351|2|0.5%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|1|0.1%|0.0%|

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
[spamhaus_drop](#spamhaus_drop)|652|18338560|18054912|98.4%|98.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|72952|348710247|8500262|2.4%|46.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|7079936|77.1%|38.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218315|764993617|2272276|0.2%|12.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17813|139104928|195933|0.1%|1.0%|
[fullbogons](#fullbogons)|3720|670264216|20480|0.0%|0.1%|
[alienvault_reputation](#alienvault_reputation)|180982|180982|5281|2.9%|0.0%|
[dshield](#dshield)|20|5120|1536|30.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1040|0.3%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|93068|93068|1015|1.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|517|0.1%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9408|9408|315|3.3%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29870|29870|308|1.0%|0.0%|
[openbl_60d](#openbl_60d)|7251|7251|250|3.4%|0.0%|
[zeus](#zeus)|232|232|223|96.1%|0.0%|
[zeus_badips](#zeus_badips)|203|203|200|98.5%|0.0%|
[blocklist_de](#blocklist_de)|28720|28720|179|0.6%|0.0%|
[openbl_30d](#openbl_30d)|3116|3116|138|4.4%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2701|2701|113|4.1%|0.0%|
[shunlist](#shunlist)|1188|1188|105|8.8%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1706|1706|101|5.9%|0.0%|
[et_compromised](#et_compromised)|2016|2016|100|4.9%|0.0%|
[feodo](#feodo)|99|99|94|94.9%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6071|6071|67|1.1%|0.0%|
[openbl_7d](#openbl_7d)|812|812|47|5.7%|0.0%|
[nixspam](#nixspam)|39999|39999|44|0.1%|0.0%|
[sslbl](#sslbl)|375|375|35|9.3%|0.0%|
[php_commenters](#php_commenters)|373|373|29|7.7%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|29|2.2%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3065|3065|29|0.9%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|17253|17253|23|0.1%|0.0%|
[voipbl](#voipbl)|10491|10902|18|0.1%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2450|2450|16|0.6%|0.0%|
[palevo](#palevo)|13|13|13|100.0%|0.0%|
[openbl_1d](#openbl_1d)|112|112|13|11.6%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|16144|16144|11|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|164|164|7|4.2%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|6|0.4%|0.0%|
[ciarmy](#ciarmy)|433|433|6|1.3%|0.0%|
[php_dictionary](#php_dictionary)|589|589|5|0.8%|0.0%|
[malc0de](#malc0de)|351|351|5|1.4%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47941|47941|5|0.0%|0.0%|
[dm_tor](#dm_tor)|6564|6564|5|0.0%|0.0%|
[bm_tor](#bm_tor)|6543|6543|5|0.0%|0.0%|
[et_tor](#et_tor)|6470|6470|4|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4804|4804|4|0.0%|0.0%|
[php_spammers](#php_spammers)|580|580|3|0.5%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|86|86|3|3.4%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|2|0.3%|0.0%|
[php_harvesters](#php_harvesters)|324|324|1|0.3%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|

## et_botcc

[EmergingThreats.net Command and Control IPs](http://doc.emergingthreats.net/bin/view/Main/BotCC) These IPs are updates every 24 hours and should be considered VERY highly reliable indications that a host is communicating with a known and active Bot or Malware command and control server - (although they say this includes abuse.ch trackers, it does not - most probably it is the shadowserver.org C&C list)

Source is downloaded from [this link](http://rules.emergingthreats.net/fwrules/emerging-PIX-CC.rules).

The last time downloaded was found to be dated: Fri Jun  5 04:30:01 UTC 2015.

The ipset `et_botcc` has **0** entries, **1** unique IPs.

The following table shows the overlaps of `et_botcc` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `et_botcc`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `et_botcc`.
- ` this % ` is the percentage **of this ipset (`et_botcc`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[fullbogons](#fullbogons)|3720|670264216|1|0.0%|100.0%|
[bogons](#bogons)|13|592708608|1|0.0%|100.0%|

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
[bruteforceblocker](#bruteforceblocker)|1706|1706|1634|95.7%|81.0%|
[alienvault_reputation](#alienvault_reputation)|180982|180982|1316|0.7%|65.2%|
[openbl_60d](#openbl_60d)|7251|7251|1216|16.7%|60.3%|
[openbl_30d](#openbl_30d)|3116|3116|1139|36.5%|56.4%|
[blocklist_de](#blocklist_de)|28720|28720|549|1.9%|27.2%|
[blocklist_de_ssh](#blocklist_de_ssh)|2701|2701|531|19.6%|26.3%|
[shunlist](#shunlist)|1188|1188|414|34.8%|20.5%|
[openbl_7d](#openbl_7d)|812|812|332|40.8%|16.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17813|139104928|199|0.0%|9.8%|
[dshield](#dshield)|20|5120|110|2.1%|5.4%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|100|0.0%|4.9%|
[et_block](#et_block)|1023|18338662|100|0.0%|4.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72952|348710247|97|0.0%|4.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218315|764993617|52|0.0%|2.5%|
[openbl_1d](#openbl_1d)|112|112|42|37.5%|2.0%|
[blocklist_de_mail](#blocklist_de_mail)|17253|17253|16|0.0%|0.7%|
[blocklist_de_imap](#blocklist_de_imap)|2450|2450|15|0.6%|0.7%|
[stopforumspam_30d](#stopforumspam_30d)|93068|93068|11|0.0%|0.5%|
[stopforumspam_7d](#stopforumspam_7d)|29870|29870|7|0.0%|0.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|5|0.0%|0.2%|
[stopforumspam_1d](#stopforumspam_1d)|6071|6071|3|0.0%|0.1%|
[voipbl](#voipbl)|10491|10902|2|0.0%|0.0%|
[proxz](#proxz)|985|985|2|0.2%|0.0%|
[nixspam](#nixspam)|39999|39999|2|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|2|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|16144|16144|2|0.0%|0.0%|
[xroxy](#xroxy)|2119|2119|1|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9408|9408|1|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|6930|6930|1|0.0%|0.0%|
[proxyrss](#proxyrss)|1454|1454|1|0.0%|0.0%|
[ciarmy](#ciarmy)|433|433|1|0.2%|0.0%|

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
[bm_tor](#bm_tor)|6543|6543|5633|86.0%|87.0%|
[dm_tor](#dm_tor)|6564|6564|5620|85.6%|86.8%|
[snort_ipfilter](#snort_ipfilter)|9408|9408|1073|11.4%|16.5%|
[stopforumspam_30d](#stopforumspam_30d)|93068|93068|651|0.6%|10.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17813|139104928|633|0.0%|9.7%|
[stopforumspam_7d](#stopforumspam_7d)|29870|29870|516|1.7%|7.9%|
[stopforumspam_1d](#stopforumspam_1d)|6071|6071|326|5.3%|5.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72952|348710247|189|0.0%|2.9%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|168|45.1%|2.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218315|764993617|168|0.0%|2.5%|
[php_commenters](#php_commenters)|373|373|43|11.5%|0.6%|
[alienvault_reputation](#alienvault_reputation)|180982|180982|40|0.0%|0.6%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|22|0.0%|0.3%|
[openbl_60d](#openbl_60d)|7251|7251|20|0.2%|0.3%|
[php_harvesters](#php_harvesters)|324|324|7|2.1%|0.1%|
[php_spammers](#php_spammers)|580|580|6|1.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|6930|6930|5|0.0%|0.0%|
[php_dictionary](#php_dictionary)|589|589|5|0.8%|0.0%|
[et_block](#et_block)|1023|18338662|4|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|17253|17253|4|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|16144|16144|4|0.0%|0.0%|
[blocklist_de](#blocklist_de)|28720|28720|4|0.0%|0.0%|
[voipbl](#voipbl)|10491|10902|3|0.0%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|0.0%|
[xroxy](#xroxy)|2119|2119|2|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|2|0.0%|0.0%|
[nixspam](#nixspam)|39999|39999|2|0.0%|0.0%|
[shunlist](#shunlist)|1188|1188|1|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2533|2533|1|0.0%|0.0%|
[proxyrss](#proxyrss)|1454|1454|1|0.0%|0.0%|

## feodo

[Abuse.ch Feodo tracker](https://feodotracker.abuse.ch) trojan includes IPs which are being used by Feodo (also known as Cridex or Bugat) which commits ebanking fraud - **excellent list**

Source is downloaded from [this link](https://feodotracker.abuse.ch/blocklist/?download=ipblocklist).

The last time downloaded was found to be dated: Sun Jun  7 17:54:16 UTC 2015.

The ipset `feodo` has **99** entries, **99** unique IPs.

The following table shows the overlaps of `feodo` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `feodo`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `feodo`.
- ` this % ` is the percentage **of this ipset (`feodo`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[et_block](#et_block)|1023|18338662|94|0.0%|94.9%|
[snort_ipfilter](#snort_ipfilter)|9408|9408|79|0.8%|79.7%|
[sslbl](#sslbl)|375|375|36|9.6%|36.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17813|139104928|11|0.0%|11.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72952|348710247|3|0.0%|3.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218315|764993617|3|0.0%|3.0%|
[alienvault_reputation](#alienvault_reputation)|180982|180982|2|0.0%|2.0%|
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
[spamhaus_drop](#spamhaus_drop)|652|18338560|151552|0.8%|0.0%|
[et_block](#et_block)|1023|18338662|20480|0.1%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|890|0.2%|0.0%|
[voipbl](#voipbl)|10491|10902|319|2.9%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|33|2.2%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47941|47941|13|0.0%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|9|0.6%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|93068|93068|2|0.0%|0.0%|
[php_harvesters](#php_harvesters)|324|324|1|0.3%|0.0%|
[php_commenters](#php_commenters)|373|373|1|0.2%|0.0%|
[et_botcc](#et_botcc)|0|1|1|100.0%|0.0%|
[ciarmy](#ciarmy)|433|433|1|0.2%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1706|1706|1|0.0%|0.0%|

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
[nixspam](#nixspam)|39999|39999|16|0.0%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|93068|93068|15|0.0%|0.0%|
[blocklist_de](#blocklist_de)|28720|28720|15|0.0%|0.0%|
[alienvault_reputation](#alienvault_reputation)|180982|180982|15|0.0%|0.0%|
[fullbogons](#fullbogons)|3720|670264216|13|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|11|1.6%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|16144|16144|8|0.0%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29870|29870|7|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4804|4804|7|0.1%|0.0%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|5|0.0%|0.0%|
[et_block](#et_block)|1023|18338662|5|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|17253|17253|5|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2450|2450|4|0.1%|0.0%|
[xroxy](#xroxy)|2119|2119|3|0.1%|0.0%|
[ri_web_proxies](#ri_web_proxies)|6930|6930|3|0.0%|0.0%|
[php_dictionary](#php_dictionary)|589|589|3|0.5%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|3|0.0%|0.0%|
[voipbl](#voipbl)|10491|10902|2|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9408|9408|2|0.0%|0.0%|
[php_harvesters](#php_harvesters)|324|324|2|0.6%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6071|6071|1|0.0%|0.0%|
[proxz](#proxz)|985|985|1|0.1%|0.0%|
[php_spammers](#php_spammers)|580|580|1|0.1%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|1|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2701|2701|1|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3065|3065|1|0.0%|0.0%|

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
[spamhaus_drop](#spamhaus_drop)|652|18338560|6932480|37.8%|75.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72952|348710247|2526625|0.7%|27.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218315|764993617|904796|0.1%|9.8%|
[fullbogons](#fullbogons)|3720|670264216|565248|0.0%|6.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17813|139104928|145472|0.1%|1.5%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1036|0.3%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|93068|93068|738|0.7%|0.0%|
[alienvault_reputation](#alienvault_reputation)|180982|180982|518|0.2%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29870|29870|150|0.5%|0.0%|
[nixspam](#nixspam)|39999|39999|43|0.1%|0.0%|
[blocklist_de](#blocklist_de)|28720|28720|33|0.1%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|27|2.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3065|3065|22|0.7%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6071|6071|20|0.3%|0.0%|
[openbl_60d](#openbl_60d)|7251|7251|17|0.2%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9408|9408|12|0.1%|0.0%|
[openbl_30d](#openbl_30d)|3116|3116|12|0.3%|0.0%|
[zeus_badips](#zeus_badips)|203|203|10|4.9%|0.0%|
[zeus](#zeus)|232|232|10|4.3%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|7|0.4%|0.0%|
[openbl_7d](#openbl_7d)|812|812|5|0.6%|0.0%|
[et_compromised](#et_compromised)|2016|2016|5|0.2%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1706|1706|5|0.2%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2701|2701|5|0.1%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|17253|17253|5|0.0%|0.0%|
[dm_tor](#dm_tor)|6564|6564|4|0.0%|0.0%|
[bm_tor](#bm_tor)|6543|6543|4|0.0%|0.0%|
[php_spammers](#php_spammers)|580|580|3|0.5%|0.0%|
[php_dictionary](#php_dictionary)|589|589|3|0.5%|0.0%|
[et_tor](#et_tor)|6470|6470|3|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|164|164|3|1.8%|0.0%|
[shunlist](#shunlist)|1188|1188|2|0.1%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|2|0.3%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2450|2450|2|0.0%|0.0%|
[voipbl](#voipbl)|10491|10902|1|0.0%|0.0%|
[php_harvesters](#php_harvesters)|324|324|1|0.3%|0.0%|
[php_commenters](#php_commenters)|373|373|1|0.2%|0.0%|
[openbl_1d](#openbl_1d)|112|112|1|0.8%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4804|4804|1|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|16144|16144|1|0.0%|0.0%|

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
[spamhaus_drop](#spamhaus_drop)|652|18338560|2272265|12.3%|0.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|17813|139104928|1349274|0.9%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|904796|9.8%|0.1%|
[fullbogons](#fullbogons)|3720|670264216|233593|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|33155|6.8%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|13239|3.9%|0.0%|
[alienvault_reputation](#alienvault_reputation)|180982|180982|3586|1.9%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|93068|93068|1528|1.6%|0.0%|
[blocklist_de](#blocklist_de)|28720|28720|1511|5.2%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|17253|17253|1384|8.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|16144|16144|1316|8.1%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29870|29870|559|1.8%|0.0%|
[nixspam](#nixspam)|39999|39999|458|1.1%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47941|47941|394|0.8%|0.0%|
[voipbl](#voipbl)|10491|10902|296|2.7%|0.0%|
[dshield](#dshield)|20|5120|257|5.0%|0.0%|
[et_tor](#et_tor)|6470|6470|168|2.5%|0.0%|
[openbl_60d](#openbl_60d)|7251|7251|167|2.3%|0.0%|
[bm_tor](#bm_tor)|6543|6543|166|2.5%|0.0%|
[dm_tor](#dm_tor)|6564|6564|164|2.4%|0.0%|
[ri_web_proxies](#ri_web_proxies)|6930|6930|136|1.9%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6071|6071|133|2.1%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|97|6.6%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2533|2533|79|3.1%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9408|9408|76|0.8%|0.0%|
[openbl_30d](#openbl_30d)|3116|3116|68|2.1%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|66|5.1%|0.0%|
[xroxy](#xroxy)|2119|2119|58|2.7%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|56|8.4%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2701|2701|55|2.0%|0.0%|
[et_compromised](#et_compromised)|2016|2016|52|2.5%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1706|1706|46|2.6%|0.0%|
[proxyrss](#proxyrss)|1454|1454|41|2.8%|0.0%|
[ciarmy](#ciarmy)|433|433|36|8.3%|0.0%|
[proxz](#proxz)|985|985|34|3.4%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2450|2450|31|1.2%|0.0%|
[shunlist](#shunlist)|1188|1188|28|2.3%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3065|3065|27|0.8%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4804|4804|26|0.5%|0.0%|
[openbl_7d](#openbl_7d)|812|812|18|2.2%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|17|4.5%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|567|567|12|2.1%|0.0%|
[php_harvesters](#php_harvesters)|324|324|11|3.3%|0.0%|
[php_dictionary](#php_dictionary)|589|589|11|1.8%|0.0%|
[malc0de](#malc0de)|351|351|11|3.1%|0.0%|
[php_commenters](#php_commenters)|373|373|9|2.4%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|310|310|9|2.9%|0.0%|
[php_spammers](#php_spammers)|580|580|8|1.3%|0.0%|
[zeus](#zeus)|232|232|6|2.5%|0.0%|
[bogons](#bogons)|13|592708608|5|0.0%|0.0%|
[zeus_badips](#zeus_badips)|203|203|4|1.9%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|86|86|4|4.6%|0.0%|
[sslbl](#sslbl)|375|375|3|0.8%|0.0%|
[feodo](#feodo)|99|99|3|3.0%|0.0%|
[openbl_1d](#openbl_1d)|112|112|1|0.8%|0.0%|

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
[spamhaus_drop](#spamhaus_drop)|652|18338560|8434457|45.9%|2.4%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2526625|27.5%|0.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|17813|139104928|2338412|1.6%|0.6%|
[fullbogons](#fullbogons)|3720|670264216|247551|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|98904|20.2%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|7728|2.2%|0.0%|
[alienvault_reputation](#alienvault_reputation)|180982|180982|7287|4.0%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|93068|93068|2527|2.7%|0.0%|
[blocklist_de](#blocklist_de)|28720|28720|1442|5.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|17253|17253|1149|6.6%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|16144|16144|1090|6.7%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29870|29870|882|2.9%|0.0%|
[nixspam](#nixspam)|39999|39999|683|1.7%|0.0%|
[voipbl](#voipbl)|10491|10902|434|3.9%|0.0%|
[openbl_60d](#openbl_60d)|7251|7251|327|4.5%|0.0%|
[dshield](#dshield)|20|5120|256|5.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47941|47941|226|0.4%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6071|6071|204|3.3%|0.0%|
[ri_web_proxies](#ri_web_proxies)|6930|6930|200|2.8%|0.0%|
[et_tor](#et_tor)|6470|6470|189|2.9%|0.0%|
[dm_tor](#dm_tor)|6564|6564|188|2.8%|0.0%|
[bm_tor](#bm_tor)|6543|6543|188|2.8%|0.0%|
[openbl_30d](#openbl_30d)|3116|3116|167|5.3%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3065|3065|117|3.8%|0.0%|
[xroxy](#xroxy)|2119|2119|104|4.9%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9408|9408|103|1.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2533|2533|97|3.8%|0.0%|
[et_compromised](#et_compromised)|2016|2016|97|4.8%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2701|2701|95|3.5%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1706|1706|86|5.0%|0.0%|
[shunlist](#shunlist)|1188|1188|65|5.4%|0.0%|
[proxyrss](#proxyrss)|1454|1454|59|4.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4804|4804|58|1.2%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2450|2450|50|2.0%|0.0%|
[php_spammers](#php_spammers)|580|580|49|8.4%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|45|3.1%|0.0%|
[ciarmy](#ciarmy)|433|433|44|10.1%|0.0%|
[openbl_7d](#openbl_7d)|812|812|43|5.2%|0.0%|
[proxz](#proxz)|985|985|38|3.8%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|26|2.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|26|3.9%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|21|5.6%|0.0%|
[malc0de](#malc0de)|351|351|21|5.9%|0.0%|
[php_dictionary](#php_dictionary)|589|589|20|3.3%|0.0%|
[php_commenters](#php_commenters)|373|373|15|4.0%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|310|310|14|4.5%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|567|567|12|2.1%|0.0%|
[zeus](#zeus)|232|232|9|3.8%|0.0%|
[php_harvesters](#php_harvesters)|324|324|9|2.7%|0.0%|
[zeus_badips](#zeus_badips)|203|203|8|3.9%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|164|164|7|4.2%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|86|86|6|6.9%|0.0%|
[openbl_1d](#openbl_1d)|112|112|5|4.4%|0.0%|
[sslbl](#sslbl)|375|375|4|1.0%|0.0%|
[feodo](#feodo)|99|99|3|3.0%|0.0%|
[palevo](#palevo)|13|13|2|15.3%|0.0%|

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
[spamhaus_drop](#spamhaus_drop)|652|18338560|130368|0.7%|0.0%|
[alienvault_reputation](#alienvault_reputation)|180982|180982|14398|7.9%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|9226|2.7%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|93068|93068|5853|6.2%|0.0%|
[blocklist_de](#blocklist_de)|28720|28720|3710|12.9%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|17253|17253|2617|15.1%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|16144|16144|2464|15.2%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29870|29870|1948|6.5%|0.0%|
[voipbl](#voipbl)|10491|10902|1600|14.6%|0.0%|
[nixspam](#nixspam)|39999|39999|1356|3.3%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47941|47941|1172|2.4%|0.0%|
[openbl_60d](#openbl_60d)|7251|7251|741|10.2%|0.0%|
[et_tor](#et_tor)|6470|6470|633|9.7%|0.0%|
[bm_tor](#bm_tor)|6543|6543|629|9.6%|0.0%|
[dm_tor](#dm_tor)|6564|6564|622|9.4%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6071|6071|440|7.2%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2701|2701|440|16.2%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4804|4804|367|7.6%|0.0%|
[openbl_30d](#openbl_30d)|3116|3116|309|9.9%|0.0%|
[dshield](#dshield)|20|5120|256|5.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9408|9408|236|2.5%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2450|2450|224|9.1%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3065|3065|200|6.5%|0.0%|
[et_compromised](#et_compromised)|2016|2016|199|9.8%|0.0%|
[ri_web_proxies](#ri_web_proxies)|6930|6930|198|2.8%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1706|1706|155|9.0%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|147|11.4%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|125|33.6%|0.0%|
[openbl_7d](#openbl_7d)|812|812|109|13.4%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|108|7.4%|0.0%|
[shunlist](#shunlist)|1188|1188|106|8.9%|0.0%|
[xroxy](#xroxy)|2119|2119|99|4.6%|0.0%|
[proxz](#proxz)|985|985|82|8.3%|0.0%|
[ciarmy](#ciarmy)|433|433|82|18.9%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2533|2533|54|2.1%|0.0%|
[proxyrss](#proxyrss)|1454|1454|51|3.5%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|51|7.6%|0.0%|
[malc0de](#malc0de)|351|351|48|13.6%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|567|567|46|8.1%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|310|310|44|14.1%|0.0%|
[php_spammers](#php_spammers)|580|580|32|5.5%|0.0%|
[php_dictionary](#php_dictionary)|589|589|31|5.2%|0.0%|
[sslbl](#sslbl)|375|375|28|7.4%|0.0%|
[php_commenters](#php_commenters)|373|373|24|6.4%|0.0%|
[php_harvesters](#php_harvesters)|324|324|17|5.2%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|164|164|15|9.1%|0.0%|
[zeus](#zeus)|232|232|13|5.6%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|86|86|13|15.1%|0.0%|
[feodo](#feodo)|99|99|11|11.1%|0.0%|
[zeus_badips](#zeus_badips)|203|203|10|4.9%|0.0%|
[openbl_1d](#openbl_1d)|112|112|9|8.0%|0.0%|
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
[xroxy](#xroxy)|2119|2119|13|0.6%|1.9%|
[ri_web_proxies](#ri_web_proxies)|6930|6930|13|0.1%|1.9%|
[stopforumspam_7d](#stopforumspam_7d)|29870|29870|12|0.0%|1.8%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47941|47941|11|0.0%|1.6%|
[ri_connect_proxies](#ri_connect_proxies)|2533|2533|7|0.2%|1.0%|
[stopforumspam_1d](#stopforumspam_1d)|6071|6071|6|0.0%|0.9%|
[proxz](#proxz)|985|985|6|0.6%|0.9%|
[proxyrss](#proxyrss)|1454|1454|6|0.4%|0.9%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|2|0.0%|0.3%|
[nixspam](#nixspam)|39999|39999|2|0.0%|0.3%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|2|0.1%|0.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2|0.0%|0.3%|
[et_block](#et_block)|1023|18338662|2|0.0%|0.3%|
[blocklist_de](#blocklist_de)|28720|28720|2|0.0%|0.3%|
[snort_ipfilter](#snort_ipfilter)|9408|9408|1|0.0%|0.1%|
[php_dictionary](#php_dictionary)|589|589|1|0.1%|0.1%|
[dshield](#dshield)|20|5120|1|0.0%|0.1%|
[blocklist_de_bots](#blocklist_de_bots)|3065|3065|1|0.0%|0.1%|
[blocklist_de_apache](#blocklist_de_apache)|16144|16144|1|0.0%|0.1%|
[alienvault_reputation](#alienvault_reputation)|180982|180982|1|0.0%|0.1%|

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
[spamhaus_drop](#spamhaus_drop)|652|18338560|1037|0.0%|0.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1036|0.0%|0.3%|
[fullbogons](#fullbogons)|3720|670264216|890|0.0%|0.2%|
[alienvault_reputation](#alienvault_reputation)|180982|180982|288|0.1%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|93068|93068|47|0.0%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|27|2.0%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29870|29870|25|0.0%|0.0%|
[et_tor](#et_tor)|6470|6470|22|0.3%|0.0%|
[dm_tor](#dm_tor)|6564|6564|22|0.3%|0.0%|
[bm_tor](#bm_tor)|6543|6543|22|0.3%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|19|1.3%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9408|9408|15|0.1%|0.0%|
[nixspam](#nixspam)|39999|39999|12|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6071|6071|9|0.1%|0.0%|
[blocklist_de](#blocklist_de)|28720|28720|9|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|6930|6930|5|0.0%|0.0%|
[openbl_60d](#openbl_60d)|7251|7251|5|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|5|1.3%|0.0%|
[voipbl](#voipbl)|10491|10902|4|0.0%|0.0%|
[openbl_30d](#openbl_30d)|3116|3116|4|0.1%|0.0%|
[malc0de](#malc0de)|351|351|3|0.8%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47941|47941|3|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1706|1706|3|0.1%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2701|2701|3|0.1%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|16144|16144|3|0.0%|0.0%|
[et_compromised](#et_compromised)|2016|2016|2|0.0%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|86|86|2|2.3%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|17253|17253|2|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4804|4804|2|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3065|3065|2|0.0%|0.0%|
[zeus_badips](#zeus_badips)|203|203|1|0.4%|0.0%|
[zeus](#zeus)|232|232|1|0.4%|0.0%|
[xroxy](#xroxy)|2119|2119|1|0.0%|0.0%|
[sslbl](#sslbl)|375|375|1|0.2%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|1|0.0%|0.0%|
[shunlist](#shunlist)|1188|1188|1|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2533|2533|1|0.0%|0.0%|
[php_harvesters](#php_harvesters)|324|324|1|0.3%|0.0%|
[php_dictionary](#php_dictionary)|589|589|1|0.1%|0.0%|
[php_commenters](#php_commenters)|373|373|1|0.2%|0.0%|
[palevo](#palevo)|13|13|1|7.6%|0.0%|
[feodo](#feodo)|99|99|1|1.0%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|310|310|1|0.3%|0.0%|
[ciarmy](#ciarmy)|433|433|1|0.2%|0.0%|
[bogons](#bogons)|13|592708608|1|0.0%|0.0%|

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
[alienvault_reputation](#alienvault_reputation)|180982|180982|10|0.0%|0.6%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|7|0.0%|0.4%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|6|0.0%|0.4%|
[et_block](#et_block)|1023|18338662|6|0.0%|0.4%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|3|0.2%|0.2%|
[stopforumspam_7d](#stopforumspam_7d)|29870|29870|2|0.0%|0.1%|
[stopforumspam_30d](#stopforumspam_30d)|93068|93068|2|0.0%|0.1%|
[stopforumspam_1d](#stopforumspam_1d)|6071|6071|2|0.0%|0.1%|
[openbl_60d](#openbl_60d)|7251|7251|2|0.0%|0.1%|
[openbl_30d](#openbl_30d)|3116|3116|2|0.0%|0.1%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|2|0.3%|0.1%|
[blocklist_de](#blocklist_de)|28720|28720|2|0.0%|0.1%|
[snort_ipfilter](#snort_ipfilter)|9408|9408|1|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|6930|6930|1|0.0%|0.0%|
[openbl_7d](#openbl_7d)|812|812|1|0.1%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47941|47941|1|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|164|164|1|0.6%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2701|2701|1|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3065|3065|1|0.0%|0.0%|

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
[ib_bluetack_level3](#ib_bluetack_level3)|17813|139104928|48|0.0%|13.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72952|348710247|21|0.0%|5.9%|
[cleanmx_viruses](#cleanmx_viruses)|310|310|14|4.5%|3.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|218315|764993617|11|0.0%|3.1%|
[alienvault_reputation](#alienvault_reputation)|180982|180982|11|0.0%|3.1%|
[et_block](#et_block)|1023|18338662|5|0.0%|1.4%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|4|0.0%|1.1%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|4|0.3%|1.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|3|0.0%|0.8%|
[dshield](#dshield)|20|5120|2|0.0%|0.5%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|1|0.0%|0.2%|

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
[spamhaus_drop](#spamhaus_drop)|652|18338560|29|0.0%|2.2%|
[et_block](#et_block)|1023|18338662|29|0.0%|2.2%|
[snort_ipfilter](#snort_ipfilter)|9408|9408|28|0.2%|2.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|27|0.0%|2.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|27|0.0%|2.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72952|348710247|26|0.0%|2.0%|
[fullbogons](#fullbogons)|3720|670264216|9|0.0%|0.6%|
[alienvault_reputation](#alienvault_reputation)|180982|180982|7|0.0%|0.5%|
[stopforumspam_30d](#stopforumspam_30d)|93068|93068|4|0.0%|0.3%|
[malc0de](#malc0de)|351|351|4|1.1%|0.3%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|3|0.2%|0.2%|
[cleanmx_viruses](#cleanmx_viruses)|310|310|2|0.6%|0.1%|
[stopforumspam_7d](#stopforumspam_7d)|29870|29870|1|0.0%|0.0%|

## maxmind_proxy_fraud

[MaxMind.com](https://www.maxmind.com/en/anonymous-proxy-fraudulent-ip-address-list) list of anonymous proxy fraudelent IP addresses.

Source is downloaded from [this link](https://www.maxmind.com/en/anonymous-proxy-fraudulent-ip-address-list).

The last time downloaded was found to be dated: Sun Jun  7 16:07:09 UTC 2015.

The ipset `maxmind_proxy_fraud` has **372** entries, **372** unique IPs.

The following table shows the overlaps of `maxmind_proxy_fraud` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `maxmind_proxy_fraud`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `maxmind_proxy_fraud`.
- ` this % ` is the percentage **of this ipset (`maxmind_proxy_fraud`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_30d](#stopforumspam_30d)|93068|93068|231|0.2%|62.0%|
[stopforumspam_7d](#stopforumspam_7d)|29870|29870|189|0.6%|50.8%|
[snort_ipfilter](#snort_ipfilter)|9408|9408|174|1.8%|46.7%|
[dm_tor](#dm_tor)|6564|6564|169|2.5%|45.4%|
[et_tor](#et_tor)|6470|6470|168|2.5%|45.1%|
[bm_tor](#bm_tor)|6543|6543|167|2.5%|44.8%|
[stopforumspam_1d](#stopforumspam_1d)|6071|6071|148|2.4%|39.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|17813|139104928|125|0.0%|33.6%|
[php_commenters](#php_commenters)|373|373|39|10.4%|10.4%|
[alienvault_reputation](#alienvault_reputation)|180982|180982|26|0.0%|6.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72952|348710247|21|0.0%|5.6%|
[openbl_60d](#openbl_60d)|7251|7251|18|0.2%|4.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218315|764993617|17|0.0%|4.5%|
[php_harvesters](#php_harvesters)|324|324|6|1.8%|1.6%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|5|0.0%|1.3%|
[ri_web_proxies](#ri_web_proxies)|6930|6930|4|0.0%|1.0%|
[php_spammers](#php_spammers)|580|580|4|0.6%|1.0%|
[php_dictionary](#php_dictionary)|589|589|4|0.6%|1.0%|
[xroxy](#xroxy)|2119|2119|1|0.0%|0.2%|
[voipbl](#voipbl)|10491|10902|1|0.0%|0.2%|
[shunlist](#shunlist)|1188|1188|1|0.0%|0.2%|
[ri_connect_proxies](#ri_connect_proxies)|2533|2533|1|0.0%|0.2%|
[nixspam](#nixspam)|39999|39999|1|0.0%|0.2%|
[et_block](#et_block)|1023|18338662|1|0.0%|0.2%|
[blocklist_de_mail](#blocklist_de_mail)|17253|17253|1|0.0%|0.2%|
[blocklist_de_apache](#blocklist_de_apache)|16144|16144|1|0.0%|0.2%|
[blocklist_de](#blocklist_de)|28720|28720|1|0.0%|0.2%|

## nixspam

[NiX Spam](http://www.heise.de/ix/NiX-Spam-DNSBL-and-blacklist-for-download-499637.html) IP addresses that sent spam in the last hour - automatically generated entries without distinguishing open proxies from relays, dialup gateways, and so on. All IPs are removed after 12 hours if there is no spam from there.

Source is downloaded from [this link](http://www.dnsbl.manitu.net/download/nixspam-ip.dump.gz).

The last time downloaded was found to be dated: Sun Jun  7 17:45:03 UTC 2015.

The ipset `nixspam` has **39999** entries, **39999** unique IPs.

The following table shows the overlaps of `nixspam` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `nixspam`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `nixspam`.
- ` this % ` is the percentage **of this ipset (`nixspam`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|17813|139104928|1356|0.0%|3.3%|
[blocklist_de](#blocklist_de)|28720|28720|932|3.2%|2.3%|
[blocklist_de_mail](#blocklist_de_mail)|17253|17253|862|4.9%|2.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72952|348710247|683|0.0%|1.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|218315|764993617|458|0.0%|1.1%|
[snort_ipfilter](#snort_ipfilter)|9408|9408|360|3.8%|0.9%|
[stopforumspam_30d](#stopforumspam_30d)|93068|93068|159|0.1%|0.3%|
[php_dictionary](#php_dictionary)|589|589|84|14.2%|0.2%|
[stopforumspam_7d](#stopforumspam_7d)|29870|29870|82|0.2%|0.2%|
[php_spammers](#php_spammers)|580|580|66|11.3%|0.1%|
[ri_web_proxies](#ri_web_proxies)|6930|6930|56|0.8%|0.1%|
[et_block](#et_block)|1023|18338662|44|0.0%|0.1%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|43|0.0%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|43|0.0%|0.1%|
[stopforumspam_1d](#stopforumspam_1d)|6071|6071|35|0.5%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3065|3065|33|1.0%|0.0%|
[xroxy](#xroxy)|2119|2119|31|1.4%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4804|4804|31|0.6%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|16144|16144|31|0.1%|0.0%|
[alienvault_reputation](#alienvault_reputation)|180982|180982|30|0.0%|0.0%|
[proxz](#proxz)|985|985|26|2.6%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2450|2450|21|0.8%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47941|47941|16|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|12|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2701|2701|9|0.3%|0.0%|
[openbl_60d](#openbl_60d)|7251|7251|8|0.1%|0.0%|
[php_commenters](#php_commenters)|373|373|7|1.8%|0.0%|
[proxyrss](#proxyrss)|1454|1454|5|0.3%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|567|567|5|0.8%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2533|2533|4|0.1%|0.0%|
[openbl_7d](#openbl_7d)|812|812|3|0.3%|0.0%|
[openbl_30d](#openbl_30d)|3116|3116|3|0.0%|0.0%|
[voipbl](#voipbl)|10491|10902|2|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|2|0.0%|0.0%|
[php_harvesters](#php_harvesters)|324|324|2|0.6%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|2|0.3%|0.0%|
[et_tor](#et_tor)|6470|6470|2|0.0%|0.0%|
[et_compromised](#et_compromised)|2016|2016|2|0.0%|0.0%|
[dm_tor](#dm_tor)|6564|6564|2|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1706|1706|2|0.1%|0.0%|
[bm_tor](#bm_tor)|6543|6543|2|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|164|164|2|1.2%|0.0%|
[zeus_badips](#zeus_badips)|203|203|1|0.4%|0.0%|
[zeus](#zeus)|232|232|1|0.4%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|

## openbl_1d

[OpenBL.org](http://www.openbl.org/) last 24 hours IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.

Source is downloaded from [this link](http://www.openbl.org/lists/base_1days.txt).

The last time downloaded was found to be dated: Sun Jun  7 17:07:00 UTC 2015.

The ipset `openbl_1d` has **112** entries, **112** unique IPs.

The following table shows the overlaps of `openbl_1d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl_1d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl_1d`.
- ` this % ` is the percentage **of this ipset (`openbl_1d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[openbl_60d](#openbl_60d)|7251|7251|110|1.5%|98.2%|
[openbl_30d](#openbl_30d)|3116|3116|110|3.5%|98.2%|
[alienvault_reputation](#alienvault_reputation)|180982|180982|110|0.0%|98.2%|
[openbl_7d](#openbl_7d)|812|812|109|13.4%|97.3%|
[blocklist_de_ssh](#blocklist_de_ssh)|2701|2701|83|3.0%|74.1%|
[blocklist_de](#blocklist_de)|28720|28720|83|0.2%|74.1%|
[shunlist](#shunlist)|1188|1188|52|4.3%|46.4%|
[et_compromised](#et_compromised)|2016|2016|42|2.0%|37.5%|
[bruteforceblocker](#bruteforceblocker)|1706|1706|39|2.2%|34.8%|
[blocklist_de_strongips](#blocklist_de_strongips)|164|164|19|11.5%|16.9%|
[dshield](#dshield)|20|5120|18|0.3%|16.0%|
[et_block](#et_block)|1023|18338662|13|0.0%|11.6%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|12|0.0%|10.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|17813|139104928|9|0.0%|8.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72952|348710247|5|0.0%|4.4%|
[stopforumspam_30d](#stopforumspam_30d)|93068|93068|1|0.0%|0.8%|
[php_spammers](#php_spammers)|580|580|1|0.1%|0.8%|
[php_commenters](#php_commenters)|373|373|1|0.2%|0.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218315|764993617|1|0.0%|0.8%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.8%|

## openbl_30d

[OpenBL.org](http://www.openbl.org/) last 30 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.

Source is downloaded from [this link](http://www.openbl.org/lists/base_30days.txt).

The last time downloaded was found to be dated: Sun Jun  7 16:02:00 UTC 2015.

The ipset `openbl_30d` has **3116** entries, **3116** unique IPs.

The following table shows the overlaps of `openbl_30d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl_30d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl_30d`.
- ` this % ` is the percentage **of this ipset (`openbl_30d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[openbl_60d](#openbl_60d)|7251|7251|3116|42.9%|100.0%|
[alienvault_reputation](#alienvault_reputation)|180982|180982|3101|1.7%|99.5%|
[et_compromised](#et_compromised)|2016|2016|1139|56.4%|36.5%|
[bruteforceblocker](#bruteforceblocker)|1706|1706|961|56.3%|30.8%|
[openbl_7d](#openbl_7d)|812|812|812|100.0%|26.0%|
[blocklist_de](#blocklist_de)|28720|28720|684|2.3%|21.9%|
[blocklist_de_ssh](#blocklist_de_ssh)|2701|2701|635|23.5%|20.3%|
[shunlist](#shunlist)|1188|1188|503|42.3%|16.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17813|139104928|309|0.0%|9.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72952|348710247|167|0.0%|5.3%|
[dshield](#dshield)|20|5120|149|2.9%|4.7%|
[et_block](#et_block)|1023|18338662|138|0.0%|4.4%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|132|0.0%|4.2%|
[openbl_1d](#openbl_1d)|112|112|110|98.2%|3.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218315|764993617|68|0.0%|2.1%|
[blocklist_de_mail](#blocklist_de_mail)|17253|17253|42|0.2%|1.3%|
[blocklist_de_imap](#blocklist_de_imap)|2450|2450|36|1.4%|1.1%|
[blocklist_de_strongips](#blocklist_de_strongips)|164|164|24|14.6%|0.7%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|12|0.0%|0.3%|
[blocklist_de_apache](#blocklist_de_apache)|16144|16144|6|0.0%|0.1%|
[stopforumspam_30d](#stopforumspam_30d)|93068|93068|4|0.0%|0.1%|
[snort_ipfilter](#snort_ipfilter)|9408|9408|4|0.0%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|4|0.0%|0.1%|
[voipbl](#voipbl)|10491|10902|3|0.0%|0.0%|
[nixspam](#nixspam)|39999|39999|3|0.0%|0.0%|
[zeus](#zeus)|232|232|2|0.8%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|2|0.1%|0.0%|
[zeus_badips](#zeus_badips)|203|203|1|0.4%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29870|29870|1|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6071|6071|1|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|1|0.0%|0.0%|
[php_spammers](#php_spammers)|580|580|1|0.1%|0.0%|
[php_commenters](#php_commenters)|373|373|1|0.2%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3065|3065|1|0.0%|0.0%|

## openbl_60d

[OpenBL.org](http://www.openbl.org/) last 60 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.

Source is downloaded from [this link](http://www.openbl.org/lists/base_60days.txt).

The last time downloaded was found to be dated: Sun Jun  7 16:02:00 UTC 2015.

The ipset `openbl_60d` has **7251** entries, **7251** unique IPs.

The following table shows the overlaps of `openbl_60d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl_60d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl_60d`.
- ` this % ` is the percentage **of this ipset (`openbl_60d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[alienvault_reputation](#alienvault_reputation)|180982|180982|7230|3.9%|99.7%|
[openbl_30d](#openbl_30d)|3116|3116|3116|100.0%|42.9%|
[et_compromised](#et_compromised)|2016|2016|1216|60.3%|16.7%|
[bruteforceblocker](#bruteforceblocker)|1706|1706|996|58.3%|13.7%|
[blocklist_de](#blocklist_de)|28720|28720|864|3.0%|11.9%|
[openbl_7d](#openbl_7d)|812|812|812|100.0%|11.1%|
[blocklist_de_ssh](#blocklist_de_ssh)|2701|2701|798|29.5%|11.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17813|139104928|741|0.0%|10.2%|
[shunlist](#shunlist)|1188|1188|520|43.7%|7.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72952|348710247|327|0.0%|4.5%|
[et_block](#et_block)|1023|18338662|250|0.0%|3.4%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|239|0.0%|3.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|218315|764993617|167|0.0%|2.3%|
[dshield](#dshield)|20|5120|165|3.2%|2.2%|
[openbl_1d](#openbl_1d)|112|112|110|98.2%|1.5%|
[stopforumspam_30d](#stopforumspam_30d)|93068|93068|53|0.0%|0.7%|
[blocklist_de_mail](#blocklist_de_mail)|17253|17253|48|0.2%|0.6%|
[blocklist_de_imap](#blocklist_de_imap)|2450|2450|41|1.6%|0.5%|
[snort_ipfilter](#snort_ipfilter)|9408|9408|26|0.2%|0.3%|
[blocklist_de_strongips](#blocklist_de_strongips)|164|164|26|15.8%|0.3%|
[stopforumspam_7d](#stopforumspam_7d)|29870|29870|24|0.0%|0.3%|
[stopforumspam_1d](#stopforumspam_1d)|6071|6071|21|0.3%|0.2%|
[et_tor](#et_tor)|6470|6470|20|0.3%|0.2%|
[dm_tor](#dm_tor)|6564|6564|20|0.3%|0.2%|
[bm_tor](#bm_tor)|6543|6543|20|0.3%|0.2%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|18|4.8%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|17|0.0%|0.2%|
[php_commenters](#php_commenters)|373|373|10|2.6%|0.1%|
[blocklist_de_bots](#blocklist_de_bots)|3065|3065|10|0.3%|0.1%|
[voipbl](#voipbl)|10491|10902|8|0.0%|0.1%|
[nixspam](#nixspam)|39999|39999|8|0.0%|0.1%|
[blocklist_de_apache](#blocklist_de_apache)|16144|16144|8|0.0%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|5|0.0%|0.0%|
[zeus](#zeus)|232|232|2|0.8%|0.0%|
[php_harvesters](#php_harvesters)|324|324|2|0.6%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|2|0.1%|0.0%|
[zeus_badips](#zeus_badips)|203|203|1|0.4%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|1|0.0%|0.0%|
[php_spammers](#php_spammers)|580|580|1|0.1%|0.0%|

## openbl_7d

[OpenBL.org](http://www.openbl.org/) last 7 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.

Source is downloaded from [this link](http://www.openbl.org/lists/base_7days.txt).

The last time downloaded was found to be dated: Sun Jun  7 16:02:00 UTC 2015.

The ipset `openbl_7d` has **812** entries, **812** unique IPs.

The following table shows the overlaps of `openbl_7d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl_7d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl_7d`.
- ` this % ` is the percentage **of this ipset (`openbl_7d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[openbl_60d](#openbl_60d)|7251|7251|812|11.1%|100.0%|
[openbl_30d](#openbl_30d)|3116|3116|812|26.0%|100.0%|
[alienvault_reputation](#alienvault_reputation)|180982|180982|806|0.4%|99.2%|
[blocklist_de](#blocklist_de)|28720|28720|402|1.3%|49.5%|
[blocklist_de_ssh](#blocklist_de_ssh)|2701|2701|386|14.2%|47.5%|
[et_compromised](#et_compromised)|2016|2016|332|16.4%|40.8%|
[bruteforceblocker](#bruteforceblocker)|1706|1706|320|18.7%|39.4%|
[shunlist](#shunlist)|1188|1188|211|17.7%|25.9%|
[openbl_1d](#openbl_1d)|112|112|109|97.3%|13.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17813|139104928|109|0.0%|13.4%|
[dshield](#dshield)|20|5120|48|0.9%|5.9%|
[et_block](#et_block)|1023|18338662|47|0.0%|5.7%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|44|0.0%|5.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|72952|348710247|43|0.0%|5.2%|
[blocklist_de_strongips](#blocklist_de_strongips)|164|164|24|14.6%|2.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|218315|764993617|18|0.0%|2.2%|
[blocklist_de_mail](#blocklist_de_mail)|17253|17253|14|0.0%|1.7%|
[blocklist_de_imap](#blocklist_de_imap)|2450|2450|12|0.4%|1.4%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|5|0.0%|0.6%|
[stopforumspam_30d](#stopforumspam_30d)|93068|93068|3|0.0%|0.3%|
[nixspam](#nixspam)|39999|39999|3|0.0%|0.3%|
[snort_ipfilter](#snort_ipfilter)|9408|9408|1|0.0%|0.1%|
[php_spammers](#php_spammers)|580|580|1|0.1%|0.1%|
[php_commenters](#php_commenters)|373|373|1|0.2%|0.1%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|1|0.0%|0.1%|
[blocklist_de_apache](#blocklist_de_apache)|16144|16144|1|0.0%|0.1%|

## palevo

[Abuse.ch Palevo tracker](https://palevotracker.abuse.ch) worm includes IPs which are being used as botnet C&C for the Palevo crimeware - **excellent list**

Source is downloaded from [this link](https://palevotracker.abuse.ch/blocklists.php?download=ipblocklist).

The last time downloaded was found to be dated: Sun Jun  7 17:54:13 UTC 2015.

The ipset `palevo` has **13** entries, **13** unique IPs.

The following table shows the overlaps of `palevo` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `palevo`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `palevo`.
- ` this % ` is the percentage **of this ipset (`palevo`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[et_block](#et_block)|1023|18338662|13|0.0%|100.0%|
[snort_ipfilter](#snort_ipfilter)|9408|9408|11|0.1%|84.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72952|348710247|2|0.0%|15.3%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|7.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|17813|139104928|1|0.0%|7.6%|

## php_commenters

[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) comment spammers (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=c&rss=1).

The last time downloaded was found to be dated: Sun Jun  7 17:09:28 UTC 2015.

The ipset `php_commenters` has **373** entries, **373** unique IPs.

The following table shows the overlaps of `php_commenters` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `php_commenters`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `php_commenters`.
- ` this % ` is the percentage **of this ipset (`php_commenters`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_30d](#stopforumspam_30d)|93068|93068|272|0.2%|72.9%|
[stopforumspam_7d](#stopforumspam_7d)|29870|29870|202|0.6%|54.1%|
[stopforumspam_1d](#stopforumspam_1d)|6071|6071|147|2.4%|39.4%|
[blocklist_de](#blocklist_de)|28720|28720|91|0.3%|24.3%|
[blocklist_de_bots](#blocklist_de_bots)|3065|3065|75|2.4%|20.1%|
[snort_ipfilter](#snort_ipfilter)|9408|9408|51|0.5%|13.6%|
[et_tor](#et_tor)|6470|6470|43|0.6%|11.5%|
[dm_tor](#dm_tor)|6564|6564|42|0.6%|11.2%|
[bm_tor](#bm_tor)|6543|6543|42|0.6%|11.2%|
[php_spammers](#php_spammers)|580|580|40|6.8%|10.7%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|39|10.4%|10.4%|
[blocklist_de_strongips](#blocklist_de_strongips)|164|164|37|22.5%|9.9%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|29|0.0%|7.7%|
[et_block](#et_block)|1023|18338662|29|0.0%|7.7%|
[blocklist_de_apache](#blocklist_de_apache)|16144|16144|26|0.1%|6.9%|
[php_dictionary](#php_dictionary)|589|589|25|4.2%|6.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|17813|139104928|24|0.0%|6.4%|
[ri_web_proxies](#ri_web_proxies)|6930|6930|23|0.3%|6.1%|
[blocklist_de_mail](#blocklist_de_mail)|17253|17253|22|0.1%|5.8%|
[alienvault_reputation](#alienvault_reputation)|180982|180982|18|0.0%|4.8%|
[php_harvesters](#php_harvesters)|324|324|15|4.6%|4.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72952|348710247|15|0.0%|4.0%|
[openbl_60d](#openbl_60d)|7251|7251|10|0.1%|2.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218315|764993617|9|0.0%|2.4%|
[xroxy](#xroxy)|2119|2119|8|0.3%|2.1%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4804|4804|8|0.1%|2.1%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|7|0.0%|1.8%|
[proxz](#proxz)|985|985|7|0.7%|1.8%|
[nixspam](#nixspam)|39999|39999|7|0.0%|1.8%|
[ri_connect_proxies](#ri_connect_proxies)|2533|2533|5|0.1%|1.3%|
[proxyrss](#proxyrss)|1454|1454|5|0.3%|1.3%|
[zeus_badips](#zeus_badips)|203|203|1|0.4%|0.2%|
[zeus](#zeus)|232|232|1|0.4%|0.2%|
[openbl_7d](#openbl_7d)|812|812|1|0.1%|0.2%|
[openbl_30d](#openbl_30d)|3116|3116|1|0.0%|0.2%|
[openbl_1d](#openbl_1d)|112|112|1|0.8%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.2%|
[fullbogons](#fullbogons)|3720|670264216|1|0.0%|0.2%|
[bruteforceblocker](#bruteforceblocker)|1706|1706|1|0.0%|0.2%|
[bogons](#bogons)|13|592708608|1|0.0%|0.2%|
[blocklist_de_ssh](#blocklist_de_ssh)|2701|2701|1|0.0%|0.2%|
[blocklist_de_imap](#blocklist_de_imap)|2450|2450|1|0.0%|0.2%|

## php_dictionary

[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) directory attackers (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=d&rss=1).

The last time downloaded was found to be dated: Sun Jun  7 17:09:31 UTC 2015.

The ipset `php_dictionary` has **589** entries, **589** unique IPs.

The following table shows the overlaps of `php_dictionary` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `php_dictionary`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `php_dictionary`.
- ` this % ` is the percentage **of this ipset (`php_dictionary`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[php_spammers](#php_spammers)|580|580|210|36.2%|35.6%|
[stopforumspam_30d](#stopforumspam_30d)|93068|93068|110|0.1%|18.6%|
[nixspam](#nixspam)|39999|39999|84|0.2%|14.2%|
[blocklist_de](#blocklist_de)|28720|28720|80|0.2%|13.5%|
[stopforumspam_7d](#stopforumspam_7d)|29870|29870|71|0.2%|12.0%|
[snort_ipfilter](#snort_ipfilter)|9408|9408|66|0.7%|11.2%|
[blocklist_de_mail](#blocklist_de_mail)|17253|17253|53|0.3%|8.9%|
[ri_web_proxies](#ri_web_proxies)|6930|6930|47|0.6%|7.9%|
[xroxy](#xroxy)|2119|2119|35|1.6%|5.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17813|139104928|31|0.0%|5.2%|
[stopforumspam_1d](#stopforumspam_1d)|6071|6071|29|0.4%|4.9%|
[php_commenters](#php_commenters)|373|373|25|6.7%|4.2%|
[blocklist_de_bots](#blocklist_de_bots)|3065|3065|22|0.7%|3.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72952|348710247|20|0.0%|3.3%|
[proxz](#proxz)|985|985|17|1.7%|2.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218315|764993617|11|0.0%|1.8%|
[alienvault_reputation](#alienvault_reputation)|180982|180982|8|0.0%|1.3%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|5|0.0%|0.8%|
[et_tor](#et_tor)|6470|6470|5|0.0%|0.8%|
[et_block](#et_block)|1023|18338662|5|0.0%|0.8%|
[ri_connect_proxies](#ri_connect_proxies)|2533|2533|4|0.1%|0.6%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|4|1.0%|0.6%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4804|4804|4|0.0%|0.6%|
[blocklist_de_apache](#blocklist_de_apache)|16144|16144|4|0.0%|0.6%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|0.5%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47941|47941|3|0.0%|0.5%|
[dm_tor](#dm_tor)|6564|6564|3|0.0%|0.5%|
[bm_tor](#bm_tor)|6543|6543|3|0.0%|0.5%|
[blocklist_de_strongips](#blocklist_de_strongips)|164|164|3|1.8%|0.5%|
[proxyrss](#proxyrss)|1454|1454|2|0.1%|0.3%|
[php_harvesters](#php_harvesters)|324|324|2|0.6%|0.3%|
[blocklist_de_imap](#blocklist_de_imap)|2450|2450|2|0.0%|0.3%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.1%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|1|0.1%|0.1%|
[blocklist_de_ftp](#blocklist_de_ftp)|567|567|1|0.1%|0.1%|

## php_harvesters

[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) harvesters (IPs that surf the internet looking for email addresses) (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=h&rss=1).

The last time downloaded was found to be dated: Sun Jun  7 17:09:26 UTC 2015.

The ipset `php_harvesters` has **324** entries, **324** unique IPs.

The following table shows the overlaps of `php_harvesters` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `php_harvesters`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `php_harvesters`.
- ` this % ` is the percentage **of this ipset (`php_harvesters`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_30d](#stopforumspam_30d)|93068|93068|74|0.0%|22.8%|
[stopforumspam_7d](#stopforumspam_7d)|29870|29870|55|0.1%|16.9%|
[stopforumspam_1d](#stopforumspam_1d)|6071|6071|36|0.5%|11.1%|
[blocklist_de](#blocklist_de)|28720|28720|33|0.1%|10.1%|
[blocklist_de_bots](#blocklist_de_bots)|3065|3065|25|0.8%|7.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|17813|139104928|17|0.0%|5.2%|
[php_commenters](#php_commenters)|373|373|15|4.0%|4.6%|
[snort_ipfilter](#snort_ipfilter)|9408|9408|11|0.1%|3.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218315|764993617|11|0.0%|3.3%|
[alienvault_reputation](#alienvault_reputation)|180982|180982|10|0.0%|3.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72952|348710247|9|0.0%|2.7%|
[et_tor](#et_tor)|6470|6470|7|0.1%|2.1%|
[dm_tor](#dm_tor)|6564|6564|7|0.1%|2.1%|
[bm_tor](#bm_tor)|6543|6543|7|0.1%|2.1%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|6|1.6%|1.8%|
[blocklist_de_ftp](#blocklist_de_ftp)|567|567|5|0.8%|1.5%|
[blocklist_de_strongips](#blocklist_de_strongips)|164|164|3|1.8%|0.9%|
[blocklist_de_apache](#blocklist_de_apache)|16144|16144|3|0.0%|0.9%|
[xroxy](#xroxy)|2119|2119|2|0.0%|0.6%|
[ri_web_proxies](#ri_web_proxies)|6930|6930|2|0.0%|0.6%|
[php_spammers](#php_spammers)|580|580|2|0.3%|0.6%|
[php_dictionary](#php_dictionary)|589|589|2|0.3%|0.6%|
[openbl_60d](#openbl_60d)|7251|7251|2|0.0%|0.6%|
[nixspam](#nixspam)|39999|39999|2|0.0%|0.6%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47941|47941|2|0.0%|0.6%|
[blocklist_de_mail](#blocklist_de_mail)|17253|17253|2|0.0%|0.6%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4804|4804|2|0.0%|0.6%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|1|0.0%|0.3%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|1|0.0%|0.3%|
[proxyrss](#proxyrss)|1454|1454|1|0.0%|0.3%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.3%|
[fullbogons](#fullbogons)|3720|670264216|1|0.0%|0.3%|
[et_block](#et_block)|1023|18338662|1|0.0%|0.3%|
[bogons](#bogons)|13|592708608|1|0.0%|0.3%|

## php_spammers

[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) spam servers (IPs used by spammers to send messages) (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=s&rss=1).

The last time downloaded was found to be dated: Sun Jun  7 17:09:27 UTC 2015.

The ipset `php_spammers` has **580** entries, **580** unique IPs.

The following table shows the overlaps of `php_spammers` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `php_spammers`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `php_spammers`.
- ` this % ` is the percentage **of this ipset (`php_spammers`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[php_dictionary](#php_dictionary)|589|589|210|35.6%|36.2%|
[stopforumspam_30d](#stopforumspam_30d)|93068|93068|122|0.1%|21.0%|
[blocklist_de](#blocklist_de)|28720|28720|81|0.2%|13.9%|
[stopforumspam_7d](#stopforumspam_7d)|29870|29870|66|0.2%|11.3%|
[nixspam](#nixspam)|39999|39999|66|0.1%|11.3%|
[snort_ipfilter](#snort_ipfilter)|9408|9408|61|0.6%|10.5%|
[blocklist_de_mail](#blocklist_de_mail)|17253|17253|52|0.3%|8.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72952|348710247|49|0.0%|8.4%|
[ri_web_proxies](#ri_web_proxies)|6930|6930|42|0.6%|7.2%|
[php_commenters](#php_commenters)|373|373|40|10.7%|6.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17813|139104928|32|0.0%|5.5%|
[xroxy](#xroxy)|2119|2119|27|1.2%|4.6%|
[stopforumspam_1d](#stopforumspam_1d)|6071|6071|23|0.3%|3.9%|
[blocklist_de_bots](#blocklist_de_bots)|3065|3065|22|0.7%|3.7%|
[proxz](#proxz)|985|985|18|1.8%|3.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|218315|764993617|8|0.0%|1.3%|
[et_tor](#et_tor)|6470|6470|6|0.0%|1.0%|
[alienvault_reputation](#alienvault_reputation)|180982|180982|6|0.0%|1.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|164|164|5|3.0%|0.8%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4804|4804|5|0.1%|0.8%|
[blocklist_de_apache](#blocklist_de_apache)|16144|16144|5|0.0%|0.8%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|4|0.0%|0.6%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|4|1.0%|0.6%|
[dm_tor](#dm_tor)|6564|6564|4|0.0%|0.6%|
[bm_tor](#bm_tor)|6543|6543|4|0.0%|0.6%|
[ri_connect_proxies](#ri_connect_proxies)|2533|2533|3|0.1%|0.5%|
[proxyrss](#proxyrss)|1454|1454|3|0.2%|0.5%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|0.5%|
[et_block](#et_block)|1023|18338662|3|0.0%|0.5%|
[php_harvesters](#php_harvesters)|324|324|2|0.6%|0.3%|
[openbl_7d](#openbl_7d)|812|812|1|0.1%|0.1%|
[openbl_60d](#openbl_60d)|7251|7251|1|0.0%|0.1%|
[openbl_30d](#openbl_30d)|3116|3116|1|0.0%|0.1%|
[openbl_1d](#openbl_1d)|112|112|1|0.8%|0.1%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47941|47941|1|0.0%|0.1%|
[bruteforceblocker](#bruteforceblocker)|1706|1706|1|0.0%|0.1%|
[blocklist_de_ssh](#blocklist_de_ssh)|2701|2701|1|0.0%|0.1%|
[blocklist_de_imap](#blocklist_de_imap)|2450|2450|1|0.0%|0.1%|
[blocklist_de_ftp](#blocklist_de_ftp)|567|567|1|0.1%|0.1%|

## proxyrss

[proxyrss.com](http://www.proxyrss.com) open proxies syndicated from multiple sources.

Source is downloaded from [this link](http://www.proxyrss.com/proxylists/all.gz).

The last time downloaded was found to be dated: Sun Jun  7 14:11:23 UTC 2015.

The ipset `proxyrss` has **1454** entries, **1454** unique IPs.

The following table shows the overlaps of `proxyrss` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `proxyrss`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `proxyrss`.
- ` this % ` is the percentage **of this ipset (`proxyrss`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_30d](#stopforumspam_30d)|93068|93068|710|0.7%|48.8%|
[ri_web_proxies](#ri_web_proxies)|6930|6930|644|9.2%|44.2%|
[stopforumspam_7d](#stopforumspam_7d)|29870|29870|566|1.8%|38.9%|
[xroxy](#xroxy)|2119|2119|408|19.2%|28.0%|
[stopforumspam_1d](#stopforumspam_1d)|6071|6071|347|5.7%|23.8%|
[ri_connect_proxies](#ri_connect_proxies)|2533|2533|251|9.9%|17.2%|
[proxz](#proxz)|985|985|242|24.5%|16.6%|
[blocklist_de_bots](#blocklist_de_bots)|3065|3065|226|7.3%|15.5%|
[blocklist_de](#blocklist_de)|28720|28720|226|0.7%|15.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72952|348710247|59|0.0%|4.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17813|139104928|51|0.0%|3.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218315|764993617|41|0.0%|2.8%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|6|0.9%|0.4%|
[php_commenters](#php_commenters)|373|373|5|1.3%|0.3%|
[nixspam](#nixspam)|39999|39999|5|0.0%|0.3%|
[php_spammers](#php_spammers)|580|580|3|0.5%|0.2%|
[blocklist_de_strongips](#blocklist_de_strongips)|164|164|3|1.8%|0.2%|
[snort_ipfilter](#snort_ipfilter)|9408|9408|2|0.0%|0.1%|
[php_dictionary](#php_dictionary)|589|589|2|0.3%|0.1%|
[alienvault_reputation](#alienvault_reputation)|180982|180982|2|0.0%|0.1%|
[php_harvesters](#php_harvesters)|324|324|1|0.3%|0.0%|
[et_tor](#et_tor)|6470|6470|1|0.0%|0.0%|
[et_compromised](#et_compromised)|2016|2016|1|0.0%|0.0%|
[dm_tor](#dm_tor)|6564|6564|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1706|1706|1|0.0%|0.0%|
[bm_tor](#bm_tor)|6543|6543|1|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|17253|17253|1|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|16144|16144|1|0.0%|0.0%|

## proxz

[proxz.com](http://www.proxz.com) open proxies (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.proxz.com/proxylists.xml).

The last time downloaded was found to be dated: Sun Jun  7 16:42:09 UTC 2015.

The ipset `proxz` has **985** entries, **985** unique IPs.

The following table shows the overlaps of `proxz` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `proxz`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `proxz`.
- ` this % ` is the percentage **of this ipset (`proxz`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_30d](#stopforumspam_30d)|93068|93068|596|0.6%|60.5%|
[ri_web_proxies](#ri_web_proxies)|6930|6930|451|6.5%|45.7%|
[stopforumspam_7d](#stopforumspam_7d)|29870|29870|446|1.4%|45.2%|
[xroxy](#xroxy)|2119|2119|369|17.4%|37.4%|
[proxyrss](#proxyrss)|1454|1454|242|16.6%|24.5%|
[ri_connect_proxies](#ri_connect_proxies)|2533|2533|162|6.3%|16.4%|
[stopforumspam_1d](#stopforumspam_1d)|6071|6071|157|2.5%|15.9%|
[blocklist_de](#blocklist_de)|28720|28720|145|0.5%|14.7%|
[blocklist_de_bots](#blocklist_de_bots)|3065|3065|119|3.8%|12.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17813|139104928|82|0.0%|8.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72952|348710247|38|0.0%|3.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218315|764993617|34|0.0%|3.4%|
[nixspam](#nixspam)|39999|39999|26|0.0%|2.6%|
[blocklist_de_mail](#blocklist_de_mail)|17253|17253|24|0.1%|2.4%|
[snort_ipfilter](#snort_ipfilter)|9408|9408|20|0.2%|2.0%|
[php_spammers](#php_spammers)|580|580|18|3.1%|1.8%|
[php_dictionary](#php_dictionary)|589|589|17|2.8%|1.7%|
[php_commenters](#php_commenters)|373|373|7|1.8%|0.7%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|6|0.9%|0.6%|
[blocklist_de_strongips](#blocklist_de_strongips)|164|164|4|2.4%|0.4%|
[alienvault_reputation](#alienvault_reputation)|180982|180982|3|0.0%|0.3%|
[et_compromised](#et_compromised)|2016|2016|2|0.0%|0.2%|
[bruteforceblocker](#bruteforceblocker)|1706|1706|2|0.1%|0.2%|
[blocklist_de_apache](#blocklist_de_apache)|16144|16144|2|0.0%|0.2%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47941|47941|1|0.0%|0.1%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4804|4804|1|0.0%|0.1%|

## ri_connect_proxies

[rosinstrument.com](http://www.rosinstrument.com) open CONNECT proxies (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://tools.rosinstrument.com/proxy/plab100.xml).

The last time downloaded was found to be dated: Sun Jun  7 15:00:27 UTC 2015.

The ipset `ri_connect_proxies` has **2533** entries, **2533** unique IPs.

The following table shows the overlaps of `ri_connect_proxies` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ri_connect_proxies`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ri_connect_proxies`.
- ` this % ` is the percentage **of this ipset (`ri_connect_proxies`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_30d](#stopforumspam_30d)|93068|93068|1447|1.5%|57.1%|
[ri_web_proxies](#ri_web_proxies)|6930|6930|1064|15.3%|42.0%|
[stopforumspam_7d](#stopforumspam_7d)|29870|29870|637|2.1%|25.1%|
[xroxy](#xroxy)|2119|2119|371|17.5%|14.6%|
[proxyrss](#proxyrss)|1454|1454|251|17.2%|9.9%|
[proxz](#proxz)|985|985|162|16.4%|6.3%|
[stopforumspam_1d](#stopforumspam_1d)|6071|6071|124|2.0%|4.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72952|348710247|97|0.0%|3.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218315|764993617|79|0.0%|3.1%|
[blocklist_de](#blocklist_de)|28720|28720|67|0.2%|2.6%|
[blocklist_de_bots](#blocklist_de_bots)|3065|3065|66|2.1%|2.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|17813|139104928|54|0.0%|2.1%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|7|1.0%|0.2%|
[php_commenters](#php_commenters)|373|373|5|1.3%|0.1%|
[php_dictionary](#php_dictionary)|589|589|4|0.6%|0.1%|
[nixspam](#nixspam)|39999|39999|4|0.0%|0.1%|
[snort_ipfilter](#snort_ipfilter)|9408|9408|3|0.0%|0.1%|
[php_spammers](#php_spammers)|580|580|3|0.5%|0.1%|
[alienvault_reputation](#alienvault_reputation)|180982|180982|3|0.0%|0.1%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.0%|
[et_tor](#et_tor)|6470|6470|1|0.0%|0.0%|
[dm_tor](#dm_tor)|6564|6564|1|0.0%|0.0%|
[bm_tor](#bm_tor)|6543|6543|1|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|17253|17253|1|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4804|4804|1|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|16144|16144|1|0.0%|0.0%|

## ri_web_proxies

[rosinstrument.com](http://www.rosinstrument.com) open HTTP proxies (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://tools.rosinstrument.com/proxy/l100.xml).

The last time downloaded was found to be dated: Sun Jun  7 17:34:07 UTC 2015.

The ipset `ri_web_proxies` has **6930** entries, **6930** unique IPs.

The following table shows the overlaps of `ri_web_proxies` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ri_web_proxies`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ri_web_proxies`.
- ` this % ` is the percentage **of this ipset (`ri_web_proxies`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_30d](#stopforumspam_30d)|93068|93068|3305|3.5%|47.6%|
[stopforumspam_7d](#stopforumspam_7d)|29870|29870|1644|5.5%|23.7%|
[ri_connect_proxies](#ri_connect_proxies)|2533|2533|1064|42.0%|15.3%|
[xroxy](#xroxy)|2119|2119|915|43.1%|13.2%|
[proxyrss](#proxyrss)|1454|1454|644|44.2%|9.2%|
[stopforumspam_1d](#stopforumspam_1d)|6071|6071|495|8.1%|7.1%|
[proxz](#proxz)|985|985|451|45.7%|6.5%|
[blocklist_de](#blocklist_de)|28720|28720|396|1.3%|5.7%|
[blocklist_de_bots](#blocklist_de_bots)|3065|3065|333|10.8%|4.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72952|348710247|200|0.0%|2.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17813|139104928|198|0.0%|2.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218315|764993617|136|0.0%|1.9%|
[blocklist_de_mail](#blocklist_de_mail)|17253|17253|61|0.3%|0.8%|
[nixspam](#nixspam)|39999|39999|56|0.1%|0.8%|
[php_dictionary](#php_dictionary)|589|589|47|7.9%|0.6%|
[snort_ipfilter](#snort_ipfilter)|9408|9408|46|0.4%|0.6%|
[php_spammers](#php_spammers)|580|580|42|7.2%|0.6%|
[php_commenters](#php_commenters)|373|373|23|6.1%|0.3%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|13|1.9%|0.1%|
[blocklist_de_imap](#blocklist_de_imap)|2450|2450|9|0.3%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|5|0.0%|0.0%|
[et_tor](#et_tor)|6470|6470|5|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|164|164|5|3.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|4|1.0%|0.0%|
[dm_tor](#dm_tor)|6564|6564|4|0.0%|0.0%|
[bm_tor](#bm_tor)|6543|6543|4|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47941|47941|3|0.0%|0.0%|
[alienvault_reputation](#alienvault_reputation)|180982|180982|3|0.0%|0.0%|
[php_harvesters](#php_harvesters)|324|324|2|0.6%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|16144|16144|2|0.0%|0.0%|
[sslbl](#sslbl)|375|375|1|0.2%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|1|0.0%|0.0%|
[et_compromised](#et_compromised)|2016|2016|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1706|1706|1|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4804|4804|1|0.0%|0.0%|

## shunlist

[AutoShun.org](http://autoshun.org/) IPs identified as hostile by correlating logs from distributed snort installations running the autoshun plugin

Source is downloaded from [this link](http://www.autoshun.org/files/shunlist.csv).

The last time downloaded was found to be dated: Sun Jun  7 15:30:05 UTC 2015.

The ipset `shunlist` has **1188** entries, **1188** unique IPs.

The following table shows the overlaps of `shunlist` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `shunlist`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `shunlist`.
- ` this % ` is the percentage **of this ipset (`shunlist`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[alienvault_reputation](#alienvault_reputation)|180982|180982|1182|0.6%|99.4%|
[openbl_60d](#openbl_60d)|7251|7251|520|7.1%|43.7%|
[openbl_30d](#openbl_30d)|3116|3116|503|16.1%|42.3%|
[et_compromised](#et_compromised)|2016|2016|414|20.5%|34.8%|
[bruteforceblocker](#bruteforceblocker)|1706|1706|395|23.1%|33.2%|
[blocklist_de](#blocklist_de)|28720|28720|337|1.1%|28.3%|
[blocklist_de_ssh](#blocklist_de_ssh)|2701|2701|296|10.9%|24.9%|
[openbl_7d](#openbl_7d)|812|812|211|25.9%|17.7%|
[dshield](#dshield)|20|5120|123|2.4%|10.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17813|139104928|106|0.0%|8.9%|
[et_block](#et_block)|1023|18338662|105|0.0%|8.8%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|91|0.0%|7.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72952|348710247|65|0.0%|5.4%|
[sslbl](#sslbl)|375|375|57|15.2%|4.7%|
[openbl_1d](#openbl_1d)|112|112|52|46.4%|4.3%|
[blocklist_de_apache](#blocklist_de_apache)|16144|16144|36|0.2%|3.0%|
[ciarmy](#ciarmy)|433|433|34|7.8%|2.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218315|764993617|28|0.0%|2.3%|
[blocklist_de_strongips](#blocklist_de_strongips)|164|164|20|12.1%|1.6%|
[voipbl](#voipbl)|10491|10902|11|0.1%|0.9%|
[blocklist_de_mail](#blocklist_de_mail)|17253|17253|5|0.0%|0.4%|
[stopforumspam_30d](#stopforumspam_30d)|93068|93068|4|0.0%|0.3%|
[blocklist_de_imap](#blocklist_de_imap)|2450|2450|4|0.1%|0.3%|
[stopforumspam_7d](#stopforumspam_7d)|29870|29870|2|0.0%|0.1%|
[snort_ipfilter](#snort_ipfilter)|9408|9408|2|0.0%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2|0.0%|0.1%|
[stopforumspam_1d](#stopforumspam_1d)|6071|6071|1|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.0%|
[et_tor](#et_tor)|6470|6470|1|0.0%|0.0%|
[dm_tor](#dm_tor)|6564|6564|1|0.0%|0.0%|
[bm_tor](#bm_tor)|6543|6543|1|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4804|4804|1|0.0%|0.0%|

## snort_ipfilter

[labs.snort.org](https://labs.snort.org/) supplied IP blacklist (this list seems to be updated frequently, but we found no information about it)

Source is downloaded from [this link](http://labs.snort.org/feeds/ip-filter.blf).

The last time downloaded was found to be dated: Sun Jun  7 16:00:00 UTC 2015.

The ipset `snort_ipfilter` has **9408** entries, **9408** unique IPs.

The following table shows the overlaps of `snort_ipfilter` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `snort_ipfilter`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `snort_ipfilter`.
- ` this % ` is the percentage **of this ipset (`snort_ipfilter`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[bm_tor](#bm_tor)|6543|6543|1088|16.6%|11.5%|
[dm_tor](#dm_tor)|6564|6564|1085|16.5%|11.5%|
[et_tor](#et_tor)|6470|6470|1073|16.5%|11.4%|
[stopforumspam_30d](#stopforumspam_30d)|93068|93068|767|0.8%|8.1%|
[stopforumspam_7d](#stopforumspam_7d)|29870|29870|597|1.9%|6.3%|
[stopforumspam_1d](#stopforumspam_1d)|6071|6071|365|6.0%|3.8%|
[nixspam](#nixspam)|39999|39999|360|0.9%|3.8%|
[et_block](#et_block)|1023|18338662|315|0.0%|3.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17813|139104928|236|0.0%|2.5%|
[zeus](#zeus)|232|232|202|87.0%|2.1%|
[zeus_badips](#zeus_badips)|203|203|179|88.1%|1.9%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|174|46.7%|1.8%|
[blocklist_de](#blocklist_de)|28720|28720|136|0.4%|1.4%|
[alienvault_reputation](#alienvault_reputation)|180982|180982|119|0.0%|1.2%|
[blocklist_de_mail](#blocklist_de_mail)|17253|17253|109|0.6%|1.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72952|348710247|103|0.0%|1.0%|
[feodo](#feodo)|99|99|79|79.7%|0.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218315|764993617|76|0.0%|0.8%|
[php_dictionary](#php_dictionary)|589|589|66|11.2%|0.7%|
[php_spammers](#php_spammers)|580|580|61|10.5%|0.6%|
[php_commenters](#php_commenters)|373|373|51|13.6%|0.5%|
[ri_web_proxies](#ri_web_proxies)|6930|6930|46|0.6%|0.4%|
[xroxy](#xroxy)|2119|2119|32|1.5%|0.3%|
[sslbl](#sslbl)|375|375|31|8.2%|0.3%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|28|2.1%|0.2%|
[openbl_60d](#openbl_60d)|7251|7251|26|0.3%|0.2%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|20|0.0%|0.2%|
[proxz](#proxz)|985|985|20|2.0%|0.2%|
[blocklist_de_bots](#blocklist_de_bots)|3065|3065|20|0.6%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|15|0.0%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|12|0.0%|0.1%|
[php_harvesters](#php_harvesters)|324|324|11|3.3%|0.1%|
[palevo](#palevo)|13|13|11|84.6%|0.1%|
[blocklist_de_apache](#blocklist_de_apache)|16144|16144|9|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2450|2450|8|0.3%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|6|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4804|4804|5|0.1%|0.0%|
[openbl_30d](#openbl_30d)|3116|3116|4|0.1%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2533|2533|3|0.1%|0.0%|
[shunlist](#shunlist)|1188|1188|2|0.1%|0.0%|
[proxyrss](#proxyrss)|1454|1454|2|0.1%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47941|47941|2|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2701|2701|2|0.0%|0.0%|
[openbl_7d](#openbl_7d)|812|812|1|0.1%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|1|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|1|0.1%|0.0%|
[et_compromised](#et_compromised)|2016|2016|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1706|1706|1|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|164|164|1|0.6%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|567|567|1|0.1%|0.0%|

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
[et_block](#et_block)|1023|18338662|18054912|98.4%|98.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|72952|348710247|8434457|2.4%|45.9%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|6932480|75.5%|37.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218315|764993617|2272265|0.2%|12.3%|
[fullbogons](#fullbogons)|3720|670264216|151552|0.0%|0.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17813|139104928|130368|0.0%|0.7%|
[alienvault_reputation](#alienvault_reputation)|180982|180982|1632|0.9%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1037|0.3%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|93068|93068|1023|1.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|512|0.1%|0.0%|
[dshield](#dshield)|20|5120|512|10.0%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29870|29870|314|1.0%|0.0%|
[openbl_60d](#openbl_60d)|7251|7251|239|3.2%|0.0%|
[blocklist_de](#blocklist_de)|28720|28720|163|0.5%|0.0%|
[openbl_30d](#openbl_30d)|3116|3116|132|4.2%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2701|2701|107|3.9%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1706|1706|101|5.9%|0.0%|
[et_compromised](#et_compromised)|2016|2016|100|4.9%|0.0%|
[shunlist](#shunlist)|1188|1188|91|7.6%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6071|6071|72|1.1%|0.0%|
[openbl_7d](#openbl_7d)|812|812|44|5.4%|0.0%|
[nixspam](#nixspam)|39999|39999|43|0.1%|0.0%|
[php_commenters](#php_commenters)|373|373|29|7.7%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|29|2.2%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3065|3065|29|0.9%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|17253|17253|22|0.1%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9408|9408|20|0.2%|0.0%|
[zeus_badips](#zeus_badips)|203|203|16|7.8%|0.0%|
[zeus](#zeus)|232|232|16|6.8%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2450|2450|15|0.6%|0.0%|
[voipbl](#voipbl)|10491|10902|14|0.1%|0.0%|
[openbl_1d](#openbl_1d)|112|112|12|10.7%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|6|0.4%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|164|164|6|3.6%|0.0%|
[php_dictionary](#php_dictionary)|589|589|5|0.8%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47941|47941|5|0.0%|0.0%|
[php_spammers](#php_spammers)|580|580|4|0.6%|0.0%|
[malc0de](#malc0de)|351|351|4|1.1%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4804|4804|4|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|16144|16144|4|0.0%|0.0%|
[dm_tor](#dm_tor)|6564|6564|3|0.0%|0.0%|
[bm_tor](#bm_tor)|6543|6543|3|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|2|0.3%|0.0%|
[et_tor](#et_tor)|6470|6470|2|0.0%|0.0%|
[sslbl](#sslbl)|375|375|1|0.2%|0.0%|
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
[spamhaus_drop](#spamhaus_drop)|652|18338560|512|0.0%|0.1%|
[stopforumspam_30d](#stopforumspam_30d)|93068|93068|80|0.0%|0.0%|
[alienvault_reputation](#alienvault_reputation)|180982|180982|15|0.0%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29870|29870|10|0.0%|0.0%|
[php_commenters](#php_commenters)|373|373|7|1.8%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9408|9408|6|0.0%|0.0%|
[zeus_badips](#zeus_badips)|203|203|5|2.4%|0.0%|
[zeus](#zeus)|232|232|5|2.1%|0.0%|
[blocklist_de](#blocklist_de)|28720|28720|4|0.0%|0.0%|
[nixspam](#nixspam)|39999|39999|2|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|164|164|2|1.2%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3065|3065|2|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6071|6071|1|0.0%|0.0%|
[php_harvesters](#php_harvesters)|324|324|1|0.3%|0.0%|
[openbl_60d](#openbl_60d)|7251|7251|1|0.0%|0.0%|
[openbl_30d](#openbl_30d)|3116|3116|1|0.0%|0.0%|
[malc0de](#malc0de)|351|351|1|0.2%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2701|2701|1|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|16144|16144|1|0.0%|0.0%|

## sslbl

[Abuse.ch SSL Blacklist](https://sslbl.abuse.ch/) bad SSL traffic related to malware or botnet activities - **excellent list**

Source is downloaded from [this link](https://sslbl.abuse.ch/blacklist/sslipblacklist.csv).

The last time downloaded was found to be dated: Sun Jun  7 17:30:06 UTC 2015.

The ipset `sslbl` has **375** entries, **375** unique IPs.

The following table shows the overlaps of `sslbl` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `sslbl`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `sslbl`.
- ` this % ` is the percentage **of this ipset (`sslbl`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[alienvault_reputation](#alienvault_reputation)|180982|180982|64|0.0%|17.0%|
[shunlist](#shunlist)|1188|1188|57|4.7%|15.2%|
[feodo](#feodo)|99|99|36|36.3%|9.6%|
[et_block](#et_block)|1023|18338662|35|0.0%|9.3%|
[snort_ipfilter](#snort_ipfilter)|9408|9408|31|0.3%|8.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|17813|139104928|28|0.0%|7.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|72952|348710247|4|0.0%|1.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218315|764993617|3|0.0%|0.8%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|1|0.0%|0.2%|
[ri_web_proxies](#ri_web_proxies)|6930|6930|1|0.0%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.2%|

## stopforumspam_1d

[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers in the last 24 hours - **excellent list**

Source is downloaded from [this link](http://www.stopforumspam.com/downloads/listed_ip_1.zip).

The last time downloaded was found to be dated: Sun Jun  7 17:00:02 UTC 2015.

The ipset `stopforumspam_1d` has **6071** entries, **6071** unique IPs.

The following table shows the overlaps of `stopforumspam_1d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `stopforumspam_1d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `stopforumspam_1d`.
- ` this % ` is the percentage **of this ipset (`stopforumspam_1d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_30d](#stopforumspam_30d)|93068|93068|4630|4.9%|76.2%|
[stopforumspam_7d](#stopforumspam_7d)|29870|29870|4325|14.4%|71.2%|
[blocklist_de](#blocklist_de)|28720|28720|1280|4.4%|21.0%|
[blocklist_de_bots](#blocklist_de_bots)|3065|3065|1242|40.5%|20.4%|
[ri_web_proxies](#ri_web_proxies)|6930|6930|495|7.1%|8.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17813|139104928|440|0.0%|7.2%|
[snort_ipfilter](#snort_ipfilter)|9408|9408|365|3.8%|6.0%|
[proxyrss](#proxyrss)|1454|1454|347|23.8%|5.7%|
[bm_tor](#bm_tor)|6543|6543|327|4.9%|5.3%|
[et_tor](#et_tor)|6470|6470|326|5.0%|5.3%|
[dm_tor](#dm_tor)|6564|6564|325|4.9%|5.3%|
[xroxy](#xroxy)|2119|2119|260|12.2%|4.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72952|348710247|204|0.0%|3.3%|
[proxz](#proxz)|985|985|157|15.9%|2.5%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|148|39.7%|2.4%|
[php_commenters](#php_commenters)|373|373|147|39.4%|2.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218315|764993617|133|0.0%|2.1%|
[ri_connect_proxies](#ri_connect_proxies)|2533|2533|124|4.8%|2.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|164|164|89|54.2%|1.4%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|72|0.0%|1.1%|
[et_block](#et_block)|1023|18338662|67|0.0%|1.1%|
[alienvault_reputation](#alienvault_reputation)|180982|180982|52|0.0%|0.8%|
[blocklist_de_mail](#blocklist_de_mail)|17253|17253|48|0.2%|0.7%|
[blocklist_de_apache](#blocklist_de_apache)|16144|16144|45|0.2%|0.7%|
[php_harvesters](#php_harvesters)|324|324|36|11.1%|0.5%|
[nixspam](#nixspam)|39999|39999|35|0.0%|0.5%|
[php_dictionary](#php_dictionary)|589|589|29|4.9%|0.4%|
[php_spammers](#php_spammers)|580|580|23|3.9%|0.3%|
[openbl_60d](#openbl_60d)|7251|7251|21|0.2%|0.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|20|0.0%|0.3%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4804|4804|10|0.2%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|9|0.0%|0.1%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|6|0.9%|0.0%|
[voipbl](#voipbl)|10491|10902|3|0.0%|0.0%|
[et_compromised](#et_compromised)|2016|2016|3|0.1%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1706|1706|3|0.1%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|2|0.1%|0.0%|
[zeus_badips](#zeus_badips)|203|203|1|0.4%|0.0%|
[zeus](#zeus)|232|232|1|0.4%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|1|0.0%|0.0%|
[shunlist](#shunlist)|1188|1188|1|0.0%|0.0%|
[openbl_30d](#openbl_30d)|3116|3116|1|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47941|47941|1|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2450|2450|1|0.0%|0.0%|

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
[stopforumspam_1d](#stopforumspam_1d)|6071|6071|4630|76.2%|4.9%|
[ri_web_proxies](#ri_web_proxies)|6930|6930|3305|47.6%|3.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72952|348710247|2527|0.0%|2.7%|
[blocklist_de](#blocklist_de)|28720|28720|2266|7.8%|2.4%|
[blocklist_de_bots](#blocklist_de_bots)|3065|3065|1955|63.7%|2.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|218315|764993617|1528|0.0%|1.6%|
[ri_connect_proxies](#ri_connect_proxies)|2533|2533|1447|57.1%|1.5%|
[xroxy](#xroxy)|2119|2119|1252|59.0%|1.3%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|1023|0.0%|1.0%|
[et_block](#et_block)|1023|18338662|1015|0.0%|1.0%|
[snort_ipfilter](#snort_ipfilter)|9408|9408|767|8.1%|0.8%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|738|0.0%|0.7%|
[proxyrss](#proxyrss)|1454|1454|710|48.8%|0.7%|
[et_tor](#et_tor)|6470|6470|651|10.0%|0.6%|
[dm_tor](#dm_tor)|6564|6564|630|9.5%|0.6%|
[bm_tor](#bm_tor)|6543|6543|630|9.6%|0.6%|
[proxz](#proxz)|985|985|596|60.5%|0.6%|
[php_commenters](#php_commenters)|373|373|272|72.9%|0.2%|
[blocklist_de_mail](#blocklist_de_mail)|17253|17253|242|1.4%|0.2%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|231|62.0%|0.2%|
[alienvault_reputation](#alienvault_reputation)|180982|180982|208|0.1%|0.2%|
[blocklist_de_apache](#blocklist_de_apache)|16144|16144|207|1.2%|0.2%|
[nixspam](#nixspam)|39999|39999|159|0.3%|0.1%|
[blocklist_de_strongips](#blocklist_de_strongips)|164|164|124|75.6%|0.1%|
[php_spammers](#php_spammers)|580|580|122|21.0%|0.1%|
[php_dictionary](#php_dictionary)|589|589|110|18.6%|0.1%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|80|0.0%|0.0%|
[php_harvesters](#php_harvesters)|324|324|74|22.8%|0.0%|
[openbl_60d](#openbl_60d)|7251|7251|53|0.7%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4804|4804|53|1.1%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|47|0.0%|0.0%|
[voipbl](#voipbl)|10491|10902|36|0.3%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|22|3.3%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47941|47941|15|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2450|2450|14|0.5%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1706|1706|13|0.7%|0.0%|
[et_compromised](#et_compromised)|2016|2016|11|0.5%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2701|2701|11|0.4%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|567|567|10|1.7%|0.0%|
[shunlist](#shunlist)|1188|1188|4|0.3%|0.0%|
[openbl_30d](#openbl_30d)|3116|3116|4|0.1%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|4|0.3%|0.0%|
[openbl_7d](#openbl_7d)|812|812|3|0.3%|0.0%|
[zeus_badips](#zeus_badips)|203|203|2|0.9%|0.0%|
[zeus](#zeus)|232|232|2|0.8%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|2|0.1%|0.0%|
[fullbogons](#fullbogons)|3720|670264216|2|0.0%|0.0%|
[openbl_1d](#openbl_1d)|112|112|1|0.8%|0.0%|
[ciarmy](#ciarmy)|433|433|1|0.2%|0.0%|
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
[stopforumspam_1d](#stopforumspam_1d)|6071|6071|4325|71.2%|14.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17813|139104928|1948|0.0%|6.5%|
[blocklist_de](#blocklist_de)|28720|28720|1931|6.7%|6.4%|
[blocklist_de_bots](#blocklist_de_bots)|3065|3065|1768|57.6%|5.9%|
[ri_web_proxies](#ri_web_proxies)|6930|6930|1644|23.7%|5.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72952|348710247|882|0.0%|2.9%|
[xroxy](#xroxy)|2119|2119|695|32.7%|2.3%|
[ri_connect_proxies](#ri_connect_proxies)|2533|2533|637|25.1%|2.1%|
[snort_ipfilter](#snort_ipfilter)|9408|9408|597|6.3%|1.9%|
[proxyrss](#proxyrss)|1454|1454|566|38.9%|1.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218315|764993617|559|0.0%|1.8%|
[et_tor](#et_tor)|6470|6470|516|7.9%|1.7%|
[bm_tor](#bm_tor)|6543|6543|495|7.5%|1.6%|
[dm_tor](#dm_tor)|6564|6564|494|7.5%|1.6%|
[proxz](#proxz)|985|985|446|45.2%|1.4%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|314|0.0%|1.0%|
[et_block](#et_block)|1023|18338662|308|0.0%|1.0%|
[php_commenters](#php_commenters)|373|373|202|54.1%|0.6%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|189|50.8%|0.6%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|150|0.0%|0.5%|
[blocklist_de_mail](#blocklist_de_mail)|17253|17253|133|0.7%|0.4%|
[blocklist_de_apache](#blocklist_de_apache)|16144|16144|120|0.7%|0.4%|
[blocklist_de_strongips](#blocklist_de_strongips)|164|164|113|68.9%|0.3%|
[alienvault_reputation](#alienvault_reputation)|180982|180982|98|0.0%|0.3%|
[nixspam](#nixspam)|39999|39999|82|0.2%|0.2%|
[php_dictionary](#php_dictionary)|589|589|71|12.0%|0.2%|
[php_spammers](#php_spammers)|580|580|66|11.3%|0.2%|
[php_harvesters](#php_harvesters)|324|324|55|16.9%|0.1%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4804|4804|31|0.6%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|25|0.0%|0.0%|
[openbl_60d](#openbl_60d)|7251|7251|24|0.3%|0.0%|
[voipbl](#voipbl)|10491|10902|14|0.1%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|12|1.8%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|10|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2450|2450|8|0.3%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47941|47941|7|0.0%|0.0%|
[et_compromised](#et_compromised)|2016|2016|7|0.3%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1706|1706|7|0.4%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|567|567|4|0.7%|0.0%|
[shunlist](#shunlist)|1188|1188|2|0.1%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|2|0.1%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2701|2701|2|0.0%|0.0%|
[zeus_badips](#zeus_badips)|203|203|1|0.4%|0.0%|
[zeus](#zeus)|232|232|1|0.4%|0.0%|
[openbl_30d](#openbl_30d)|3116|3116|1|0.0%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|1|0.0%|0.0%|
[ciarmy](#ciarmy)|433|433|1|0.2%|0.0%|

## virbl

[VirBL](http://virbl.bit.nl/) is a project of which the idea was born during the RIPE-48 meeting. The plan was to get reports of virusscanning mailservers, and put the IP-addresses that were reported to send viruses on a blacklist.

Source is downloaded from [this link](http://virbl.bit.nl/download/virbl.dnsbl.bit.nl.txt).

The last time downloaded was found to be dated: Sun Jun  7 17:07:02 UTC 2015.

The ipset `virbl` has **1** entries, **1** unique IPs.

The following table shows the overlaps of `virbl` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `virbl`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `virbl`.
- ` this % ` is the percentage **of this ipset (`virbl`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|

## voipbl

[VoIPBL.org](http://www.voipbl.org/) a distributed VoIP blacklist that is aimed to protects against VoIP Fraud and minimizing abuse for network that have publicly accessible PBX's. Several algorithms, external sources and manual confirmation are used before they categorize something as an attack and determine the threat level.

Source is downloaded from [this link](http://www.voipbl.org/update/).

The last time downloaded was found to be dated: Sun Jun  7 16:08:05 UTC 2015.

The ipset `voipbl` has **10491** entries, **10902** unique IPs.

The following table shows the overlaps of `voipbl` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `voipbl`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `voipbl`.
- ` this % ` is the percentage **of this ipset (`voipbl`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|17813|139104928|1600|0.0%|14.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72952|348710247|434|0.0%|3.9%|
[fullbogons](#fullbogons)|3720|670264216|319|0.0%|2.9%|
[bogons](#bogons)|13|592708608|319|0.0%|2.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|218315|764993617|296|0.0%|2.7%|
[alienvault_reputation](#alienvault_reputation)|180982|180982|208|0.1%|1.9%|
[stopforumspam_30d](#stopforumspam_30d)|93068|93068|36|0.0%|0.3%|
[blocklist_de](#blocklist_de)|28720|28720|34|0.1%|0.3%|
[blocklist_de_sip](#blocklist_de_sip)|86|86|28|32.5%|0.2%|
[et_block](#et_block)|1023|18338662|18|0.0%|0.1%|
[stopforumspam_7d](#stopforumspam_7d)|29870|29870|14|0.0%|0.1%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|14|0.0%|0.1%|
[shunlist](#shunlist)|1188|1188|11|0.9%|0.1%|
[openbl_60d](#openbl_60d)|7251|7251|8|0.1%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|4|0.0%|0.0%|
[ciarmy](#ciarmy)|433|433|4|0.9%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6071|6071|3|0.0%|0.0%|
[openbl_30d](#openbl_30d)|3116|3116|3|0.0%|0.0%|
[et_tor](#et_tor)|6470|6470|3|0.0%|0.0%|
[dm_tor](#dm_tor)|6564|6564|3|0.0%|0.0%|
[bm_tor](#bm_tor)|6543|6543|3|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3065|3065|3|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|16144|16144|3|0.0%|0.0%|
[nixspam](#nixspam)|39999|39999|2|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47941|47941|2|0.0%|0.0%|
[et_compromised](#et_compromised)|2016|2016|2|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1706|1706|2|0.1%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4804|4804|1|0.0%|0.0%|

## xroxy

[xroxy.com](http://www.xroxy.com) open proxies (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.xroxy.com/proxyrss.xml).

The last time downloaded was found to be dated: Sun Jun  7 17:33:01 UTC 2015.

The ipset `xroxy` has **2119** entries, **2119** unique IPs.

The following table shows the overlaps of `xroxy` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `xroxy`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `xroxy`.
- ` this % ` is the percentage **of this ipset (`xroxy`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_30d](#stopforumspam_30d)|93068|93068|1252|1.3%|59.0%|
[ri_web_proxies](#ri_web_proxies)|6930|6930|915|13.2%|43.1%|
[stopforumspam_7d](#stopforumspam_7d)|29870|29870|695|2.3%|32.7%|
[proxyrss](#proxyrss)|1454|1454|408|28.0%|19.2%|
[ri_connect_proxies](#ri_connect_proxies)|2533|2533|371|14.6%|17.5%|
[proxz](#proxz)|985|985|369|37.4%|17.4%|
[stopforumspam_1d](#stopforumspam_1d)|6071|6071|260|4.2%|12.2%|
[blocklist_de](#blocklist_de)|28720|28720|208|0.7%|9.8%|
[blocklist_de_bots](#blocklist_de_bots)|3065|3065|167|5.4%|7.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72952|348710247|104|0.0%|4.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17813|139104928|99|0.0%|4.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218315|764993617|58|0.0%|2.7%|
[blocklist_de_mail](#blocklist_de_mail)|17253|17253|39|0.2%|1.8%|
[php_dictionary](#php_dictionary)|589|589|35|5.9%|1.6%|
[snort_ipfilter](#snort_ipfilter)|9408|9408|32|0.3%|1.5%|
[nixspam](#nixspam)|39999|39999|31|0.0%|1.4%|
[php_spammers](#php_spammers)|580|580|27|4.6%|1.2%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|13|1.9%|0.6%|
[php_commenters](#php_commenters)|373|373|8|2.1%|0.3%|
[blocklist_de_strongips](#blocklist_de_strongips)|164|164|7|4.2%|0.3%|
[alienvault_reputation](#alienvault_reputation)|180982|180982|4|0.0%|0.1%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47941|47941|3|0.0%|0.1%|
[php_harvesters](#php_harvesters)|324|324|2|0.6%|0.0%|
[et_tor](#et_tor)|6470|6470|2|0.0%|0.0%|
[dm_tor](#dm_tor)|6564|6564|2|0.0%|0.0%|
[bm_tor](#bm_tor)|6543|6543|2|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|16144|16144|2|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.0%|
[et_compromised](#et_compromised)|2016|2016|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1706|1706|1|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4804|4804|1|0.0%|0.0%|

## zeus

[Abuse.ch Zeus tracker](https://zeustracker.abuse.ch) standard, contains the same data as the ZeuS IP blocklist (zeus_badips) but with the slight difference that it doesn't exclude hijacked websites (level 2) and free web hosting providers (level 3). This means that this blocklist contains all IPv4 addresses associated with ZeuS C&Cs which are currently being tracked by ZeuS Tracker. Hence this blocklist will likely cause some false positives. - **excellent list**

Source is downloaded from [this link](https://zeustracker.abuse.ch/blocklist.php?download=ipblocklist).

The last time downloaded was found to be dated: Sun Jun  7 16:30:03 UTC 2015.

The ipset `zeus` has **232** entries, **232** unique IPs.

The following table shows the overlaps of `zeus` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `zeus`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `zeus`.
- ` this % ` is the percentage **of this ipset (`zeus`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[et_block](#et_block)|1023|18338662|223|0.0%|96.1%|
[zeus_badips](#zeus_badips)|203|203|203|100.0%|87.5%|
[snort_ipfilter](#snort_ipfilter)|9408|9408|202|2.1%|87.0%|
[alienvault_reputation](#alienvault_reputation)|180982|180982|62|0.0%|26.7%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|16|0.0%|6.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17813|139104928|13|0.0%|5.6%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|10|0.0%|4.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72952|348710247|9|0.0%|3.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218315|764993617|6|0.0%|2.5%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|5|0.0%|2.1%|
[stopforumspam_30d](#stopforumspam_30d)|93068|93068|2|0.0%|0.8%|
[openbl_60d](#openbl_60d)|7251|7251|2|0.0%|0.8%|
[openbl_30d](#openbl_30d)|3116|3116|2|0.0%|0.8%|
[stopforumspam_7d](#stopforumspam_7d)|29870|29870|1|0.0%|0.4%|
[stopforumspam_1d](#stopforumspam_1d)|6071|6071|1|0.0%|0.4%|
[php_commenters](#php_commenters)|373|373|1|0.2%|0.4%|
[nixspam](#nixspam)|39999|39999|1|0.0%|0.4%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.4%|
[blocklist_de_mail](#blocklist_de_mail)|17253|17253|1|0.0%|0.4%|
[blocklist_de_imap](#blocklist_de_imap)|2450|2450|1|0.0%|0.4%|
[blocklist_de](#blocklist_de)|28720|28720|1|0.0%|0.4%|

## zeus_badips

[Abuse.ch Zeus tracker](https://zeustracker.abuse.ch) badips includes IPv4 addresses that are used by the ZeuS trojan. It is the recommened blocklist if you want to block only ZeuS IPs. It excludes IP addresses that ZeuS Tracker believes to be hijacked (level 2) or belong to a free web hosting provider (level 3). Hence the false postive rate should be much lower compared to the standard ZeuS IP blocklist. **excellent list**

Source is downloaded from [this link](https://zeustracker.abuse.ch/blocklist.php?download=badips).

The last time downloaded was found to be dated: Sun Jun  7 17:54:11 UTC 2015.

The ipset `zeus_badips` has **203** entries, **203** unique IPs.

The following table shows the overlaps of `zeus_badips` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `zeus_badips`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `zeus_badips`.
- ` this % ` is the percentage **of this ipset (`zeus_badips`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[zeus](#zeus)|232|232|203|87.5%|100.0%|
[et_block](#et_block)|1023|18338662|200|0.0%|98.5%|
[snort_ipfilter](#snort_ipfilter)|9408|9408|179|1.9%|88.1%|
[alienvault_reputation](#alienvault_reputation)|180982|180982|38|0.0%|18.7%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|16|0.0%|7.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17813|139104928|10|0.0%|4.9%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|10|0.0%|4.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72952|348710247|8|0.0%|3.9%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|5|0.0%|2.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218315|764993617|4|0.0%|1.9%|
[stopforumspam_30d](#stopforumspam_30d)|93068|93068|2|0.0%|0.9%|
[stopforumspam_7d](#stopforumspam_7d)|29870|29870|1|0.0%|0.4%|
[stopforumspam_1d](#stopforumspam_1d)|6071|6071|1|0.0%|0.4%|
[php_commenters](#php_commenters)|373|373|1|0.2%|0.4%|
[openbl_60d](#openbl_60d)|7251|7251|1|0.0%|0.4%|
[openbl_30d](#openbl_30d)|3116|3116|1|0.0%|0.4%|
[nixspam](#nixspam)|39999|39999|1|0.0%|0.4%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.4%|
[blocklist_de_mail](#blocklist_de_mail)|17253|17253|1|0.0%|0.4%|
[blocklist_de_imap](#blocklist_de_imap)|2450|2450|1|0.0%|0.4%|
[blocklist_de](#blocklist_de)|28720|28720|1|0.0%|0.4%|
