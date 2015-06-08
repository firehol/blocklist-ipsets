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

The following list was automatically generated on Mon Jun  8 12:37:02 UTC 2015.

The update frequency is the maximum allowed by internal configuration. A list will never be downloaded sooner than the update frequency stated. A list may also not be downloaded, after this frequency expired, if it has not been modified on the server (as reported by HTTP `IF_MODIFIED_SINCE` method).

name|info|type|entries|update|
:--:|:--:|:--:|:-----:|:----:|
[alienvault_reputation](#alienvault_reputation)|[AlienVault.com](https://www.alienvault.com/) IP reputation database (this list seems to include port scanning hosts and to be updated regularly, but we found no information about its retention policy)|ipv4 hash:ip|181932 unique IPs|updated every 6 hours  from [this link](https://reputation.alienvault.com/reputation.generic)
[blocklist_de](#blocklist_de)|[Blocklist.de](https://www.blocklist.de/) IPs that have been detected by fail2ban in the last 48 hours - **excellent list**|ipv4 hash:ip|31859 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/all.txt)
[blocklist_de_apache](#blocklist_de_apache)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service Apache, Apache-DDOS, RFI-Attacks.|ipv4 hash:ip|16426 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/apache.txt)
[blocklist_de_bots](#blocklist_de_bots)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the RFI-Attacks, REG-Bots, IRC-Bots or BadBots (BadBots = he has posted a Spam-Comment on a open Forum or Wiki).|ipv4 hash:ip|3458 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/bots.txt)
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|[Blocklist.de](https://www.blocklist.de/) All IPs which attacks Joomlas, Wordpress and other Web-Logins with Brute-Force Logins.|ipv4 hash:ip|5111 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/bruteforcelogin.txt)
[blocklist_de_ftp](#blocklist_de_ftp)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours for attacks on the Service FTP.|ipv4 hash:ip|299 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/ftp.txt)
[blocklist_de_imap](#blocklist_de_imap)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours for attacks on the Service imap, sasl, pop3, etc.|ipv4 hash:ip|2731 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/imap.txt)
[blocklist_de_mail](#blocklist_de_mail)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service Mail, Postfix.|ipv4 hash:ip|19169 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/mail.txt)
[blocklist_de_sip](#blocklist_de_sip)|[Blocklist.de](https://www.blocklist.de/) All IP addresses that tried to login in a SIP, VOIP or Asterisk Server and are included in the IPs list from [infiltrated.net](www.infiltrated.net)|ipv4 hash:ip|86 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/sip.txt)
[blocklist_de_ssh](#blocklist_de_ssh)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service SSH.|ipv4 hash:ip|3512 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/ssh.txt)
[blocklist_de_strongips](#blocklist_de_strongips)|[Blocklist.de](https://www.blocklist.de/) All IPs which are older then 2 month and have more then 5.000 attacks.|ipv4 hash:ip|158 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/strongips.txt)
[bm_tor](#bm_tor)|[torstatus.blutmagie.de](https://torstatus.blutmagie.de) list of all TOR network servers|ipv4 hash:ip|6465 unique IPs|updated every 30 mins  from [this link](https://torstatus.blutmagie.de/ip_list_all.php/Tor_ip_list_ALL.csv)
[bogons](#bogons)|[Team-Cymru.org](http://www.team-cymru.org) private and reserved addresses defined by RFC 1918, RFC 5735, and RFC 6598 and netblocks that have not been allocated to a regional internet registry - **excellent list - use it only your internet interface**|ipv4 hash:net|13 subnets, 592708608 unique IPs|updated every 1 day  from [this link](http://www.team-cymru.org/Services/Bogons/bogon-bn-agg.txt)
[bruteforceblocker](#bruteforceblocker)|[danger.rulez.sk](http://danger.rulez.sk/) IPs detected by [bruteforceblocker](http://danger.rulez.sk/index.php/bruteforceblocker/) (fail2ban alternative for SSH on OpenBSD). This is an automatically generated list from users reporting failed authentication attempts. An IP seems to be included if 3 or more users report it. Its retention pocily seems 30 days.|ipv4 hash:ip|1703 unique IPs|updated every 3 hours  from [this link](http://danger.rulez.sk/projects/bruteforceblocker/blist.php)
[ciarmy](#ciarmy)|[CIArmy.com](http://ciarmy.com/) IPs with poor Rogue Packet score that have not yet been identified as malicious by the community|ipv4 hash:ip|422 unique IPs|updated every 3 hours  from [this link](http://cinsscore.com/list/ci-badguys.txt)
[cleanmx_viruses](#cleanmx_viruses)|[Clean-MX.de](http://support.clean-mx.de/clean-mx/viruses.php) IPs with viruses|ipv4 hash:ip|319 unique IPs|updated every 12 hours  from [this link](http://support.clean-mx.de/clean-mx/xmlviruses.php?sort=id%20desc&response=alive)
[dm_tor](#dm_tor)|[dan.me.uk](https://www.dan.me.uk) dynamic list of TOR exit points|ipv4 hash:ip|6482 unique IPs|updated every 30 mins  from [this link](https://www.dan.me.uk/torlist/)
[dshield](#dshield)|[DShield.org](https://dshield.org/) top 20 attacking class C (/24) subnets over the last three days - **excellent list**|ipv4 hash:net|20 subnets, 5120 unique IPs|updated every 4 hours  from [this link](http://feeds.dshield.org/block.txt)
[et_block](#et_block)|[EmergingThreats.net](http://www.emergingthreats.net/) default blacklist (at the time of writing includes spamhaus DROP, dshield and abuse.ch trackers, which are available separately too - prefer to use the direct ipsets instead of this, they seem to lag a bit in updates)|ipv4 hash:net|1023 subnets, 18338662 unique IPs|updated every 12 hours  from [this link](http://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt)
[et_botcc](#et_botcc)|[EmergingThreats.net Command and Control IPs](http://doc.emergingthreats.net/bin/view/Main/BotCC) These IPs are updates every 24 hours and should be considered VERY highly reliable indications that a host is communicating with a known and active Bot or Malware command and control server - (although they say this includes abuse.ch trackers, it does not - most probably it is the shadowserver.org C&C list)|ipv4 hash:ip|0 unique IPs|updated every 12 hours  from [this link](http://rules.emergingthreats.net/fwrules/emerging-PIX-CC.rules)
[et_compromised](#et_compromised)|[EmergingThreats.net compromised hosts](http://doc.emergingthreats.net/bin/view/Main/CompromisedHost) - (this seems to be based on bruteforceblocker)|ipv4 hash:ip|2016 unique IPs|updated every 12 hours  from [this link](http://rules.emergingthreats.net/blockrules/compromised-ips.txt)
et_dshield|[EmergingThreats.net](http://www.emergingthreats.net/) dshield blocklist|ipv4 hash:net|disabled|updated every 12 hours  from [this link](http://rules.emergingthreats.net/fwrules/emerging-PIX-DSHIELD.rules)
et_spamhaus|[EmergingThreats.net](http://www.emergingthreats.net/) spamhaus blocklist|ipv4 hash:net|disabled|updated every 12 hours  from [this link](http://rules.emergingthreats.net/fwrules/emerging-PIX-DROP.rules)
[et_tor](#et_tor)|[EmergingThreats.net](http://www.emergingthreats.net/) [list](http://doc.emergingthreats.net/bin/view/Main/TorRules) of TOR network IPs|ipv4 hash:ip|6470 unique IPs|updated every 12 hours  from [this link](http://rules.emergingthreats.net/blockrules/emerging-tor.rules)
[feodo](#feodo)|[Abuse.ch Feodo tracker](https://feodotracker.abuse.ch) trojan includes IPs which are being used by Feodo (also known as Cridex or Bugat) which commits ebanking fraud - **excellent list**|ipv4 hash:ip|100 unique IPs|updated every 30 mins  from [this link](https://feodotracker.abuse.ch/blocklist/?download=ipblocklist)
[firehol_anonymous](#firehol_anonymous)|**FireHOL Anonymous** - Known anonymizing IPs. (includes: firehol_proxies anonymous bm_tor dm_tor)|ipv4 hash:net|17882 subnets, 81890 unique IPs|updated every 1 min  from [this link]()
[firehol_level1](#firehol_level1)|**FireHOL Level 1** - Maximum protection without false positives. (includes: fullbogons dshield feodo palevo sslbl zeus spamhaus_drop spamhaus_edrop)|ipv4 hash:net|5088 subnets, 688943411 unique IPs|updated every 1 min  from [this link]()
[firehol_level2](#firehol_level2)|**FireHOL Level 2** - Maximum protection from attacks took place in the last 48 hours. (includes: openbl_1d blocklist_de stopforumspam_1d)|ipv4 hash:net|25736 subnets, 37353 unique IPs|updated every 1 min  from [this link]()
[firehol_level3](#firehol_level3)|**FireHOL Level 3** - All the bad IPs in last 30 days. (includes: openbl_30d stopforumspam_30d virbl malc0de shunlist malwaredomainlist bruteforceblocker ciarmy cleanmx_viruses snort_ipfilter ib_bluetack_spyware ib_bluetack_hijacked ib_bluetack_webexploit php_commenters php_dictionary php_harvesters php_spammers)|ipv4 hash:net|107735 subnets, 9625249 unique IPs|updated every 1 min  from [this link]()
[firehol_proxies](#firehol_proxies)|**FireHOL Proxies** - Known open proxies in the last 30 days. (includes: ib_bluetack_proxies maxmind_proxy_fraud proxyrss proxz ri_connect_proxies ri_web_proxies xroxy)|ipv4 hash:net|11383 subnets, 11607 unique IPs|updated every 1 min  from [this link]()
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
[nixspam](#nixspam)|[NiX Spam](http://www.heise.de/ix/NiX-Spam-DNSBL-and-blacklist-for-download-499637.html) IP addresses that sent spam in the last hour - automatically generated entries without distinguishing open proxies from relays, dialup gateways, and so on. All IPs are removed after 12 hours if there is no spam from there.|ipv4 hash:ip|28061 unique IPs|updated every 15 mins  from [this link](http://www.dnsbl.manitu.net/download/nixspam-ip.dump.gz)
openbl|[OpenBL.org](http://www.openbl.org/) default blacklist (currently it is the same with 90 days). OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications - **excellent list**|ipv4 hash:ip|disabled|updated every 4 hours  from [this link](http://www.openbl.org/lists/base.txt)
openbl_180d|[OpenBL.org](http://www.openbl.org/) last 180 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|disabled|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_180days.txt)
[openbl_1d](#openbl_1d)|[OpenBL.org](http://www.openbl.org/) last 24 hours IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|118 unique IPs|updated every 1 hour  from [this link](http://www.openbl.org/lists/base_1days.txt)
[openbl_30d](#openbl_30d)|[OpenBL.org](http://www.openbl.org/) last 30 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|2935 unique IPs|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_30days.txt)
openbl_360d|[OpenBL.org](http://www.openbl.org/) last 360 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|disabled|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_360days.txt)
[openbl_60d](#openbl_60d)|[OpenBL.org](http://www.openbl.org/) last 60 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|7239 unique IPs|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_60days.txt)
[openbl_7d](#openbl_7d)|[OpenBL.org](http://www.openbl.org/) last 7 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|820 unique IPs|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_7days.txt)
openbl_90d|[OpenBL.org](http://www.openbl.org/) last 90 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|disabled|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_90days.txt)
openbl_all|[OpenBL.org](http://www.openbl.org/) last all IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|disabled|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_all.txt)
[palevo](#palevo)|[Abuse.ch Palevo tracker](https://palevotracker.abuse.ch) worm includes IPs which are being used as botnet C&C for the Palevo crimeware - **excellent list**|ipv4 hash:ip|13 unique IPs|updated every 30 mins  from [this link](https://palevotracker.abuse.ch/blocklists.php?download=ipblocklist)
php_bad|[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) bad web hosts (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|disabled|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=b&rss=1)
[php_commenters](#php_commenters)|[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) comment spammers (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|373 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=c&rss=1)
[php_dictionary](#php_dictionary)|[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) directory attackers (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|630 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=d&rss=1)
[php_harvesters](#php_harvesters)|[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) harvesters (IPs that surf the internet looking for email addresses) (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|341 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=h&rss=1)
[php_spammers](#php_spammers)|[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) spam servers (IPs used by spammers to send messages) (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|622 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=s&rss=1)
[proxyrss](#proxyrss)|[proxyrss.com](http://www.proxyrss.com) open proxies syndicated from multiple sources.|ipv4 hash:ip|1481 unique IPs|updated every 4 hours  from [this link](http://www.proxyrss.com/proxylists/all.gz)
[proxz](#proxz)|[proxz.com](http://www.proxz.com) open proxies (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|1047 unique IPs|updated every 1 hour  from [this link](http://www.proxz.com/proxylists.xml)
[ri_connect_proxies](#ri_connect_proxies)|[rosinstrument.com](http://www.rosinstrument.com) open CONNECT proxies (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|2581 unique IPs|updated every 1 hour  from [this link](http://tools.rosinstrument.com/proxy/plab100.xml)
[ri_web_proxies](#ri_web_proxies)|[rosinstrument.com](http://www.rosinstrument.com) open HTTP proxies (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|7066 unique IPs|updated every 1 hour  from [this link](http://tools.rosinstrument.com/proxy/l100.xml)
[shunlist](#shunlist)|[AutoShun.org](http://autoshun.org/) IPs identified as hostile by correlating logs from distributed snort installations running the autoshun plugin|ipv4 hash:ip|1241 unique IPs|updated every 4 hours  from [this link](http://www.autoshun.org/files/shunlist.csv)
[snort_ipfilter](#snort_ipfilter)|[labs.snort.org](https://labs.snort.org/) supplied IP blacklist (this list seems to be updated frequently, but we found no information about it)|ipv4 hash:ip|9492 unique IPs|updated every 12 hours  from [this link](http://labs.snort.org/feeds/ip-filter.blf)
[spamhaus_drop](#spamhaus_drop)|[Spamhaus.org](http://www.spamhaus.org) DROP list (according to their site this list should be dropped at tier-1 ISPs globaly) - **excellent list**|ipv4 hash:net|652 subnets, 18338560 unique IPs|updated every 12 hours  from [this link](http://www.spamhaus.org/drop/drop.txt)
[spamhaus_edrop](#spamhaus_edrop)|[Spamhaus.org](http://www.spamhaus.org) EDROP (extended matches that should be used with DROP) - **excellent list**|ipv4 hash:net|56 subnets, 487424 unique IPs|updated every 12 hours  from [this link](http://www.spamhaus.org/drop/edrop.txt)
[sslbl](#sslbl)|[Abuse.ch SSL Blacklist](https://sslbl.abuse.ch/) bad SSL traffic related to malware or botnet activities - **excellent list**|ipv4 hash:ip|379 unique IPs|updated every 30 mins  from [this link](https://sslbl.abuse.ch/blacklist/sslipblacklist.csv)
stopforumspam_180d|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 180 days)|ipv4 hash:ip|disabled|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/listed_ip_180.zip)
[stopforumspam_1d](#stopforumspam_1d)|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers in the last 24 hours - **excellent list**|ipv4 hash:ip|6881 unique IPs|updated every 1 hour  from [this link](http://www.stopforumspam.com/downloads/listed_ip_1.zip)
[stopforumspam_30d](#stopforumspam_30d)|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 30 days)|ipv4 hash:ip|92247 unique IPs|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/listed_ip_30.zip)
stopforumspam_365d|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 365 days)|ipv4 hash:ip|disabled|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/listed_ip_365.zip)
[stopforumspam_7d](#stopforumspam_7d)|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 7 days)|ipv4 hash:ip|29278 unique IPs|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/listed_ip_7.zip)
stopforumspam_90d|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 90 days)|ipv4 hash:ip|disabled|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/listed_ip_90.zip)
stopforumspam_ever|[StopForumSpam.com](http://www.stopforumspam.com) all IPs used by forum spammers, **ever** (normally you don't want to use this ipset, use the hourly one which includes last 24 hours IPs or the 7 days one)|ipv4 hash:ip|disabled|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/bannedips.zip)
[virbl](#virbl)|[VirBL](http://virbl.bit.nl/) is a project of which the idea was born during the RIPE-48 meeting. The plan was to get reports of virusscanning mailservers, and put the IP-addresses that were reported to send viruses on a blacklist.|ipv4 hash:ip|8 unique IPs|updated every 1 hour  from [this link](http://virbl.bit.nl/download/virbl.dnsbl.bit.nl.txt)
[voipbl](#voipbl)|[VoIPBL.org](http://www.voipbl.org/) a distributed VoIP blacklist that is aimed to protects against VoIP Fraud and minimizing abuse for network that have publicly accessible PBX's. Several algorithms, external sources and manual confirmation are used before they categorize something as an attack and determine the threat level.|ipv4 hash:net|10491 subnets, 10902 unique IPs|updated every 4 hours  from [this link](http://www.voipbl.org/update/)
[xroxy](#xroxy)|[xroxy.com](http://www.xroxy.com) open proxies (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|2124 unique IPs|updated every 1 hour  from [this link](http://www.xroxy.com/proxyrss.xml)
[zeus](#zeus)|[Abuse.ch Zeus tracker](https://zeustracker.abuse.ch) standard, contains the same data as the ZeuS IP blocklist (zeus_badips) but with the slight difference that it doesn't exclude hijacked websites (level 2) and free web hosting providers (level 3). This means that this blocklist contains all IPv4 addresses associated with ZeuS C&Cs which are currently being tracked by ZeuS Tracker. Hence this blocklist will likely cause some false positives. - **excellent list**|ipv4 hash:ip|234 unique IPs|updated every 30 mins  from [this link](https://zeustracker.abuse.ch/blocklist.php?download=ipblocklist)
[zeus_badips](#zeus_badips)|[Abuse.ch Zeus tracker](https://zeustracker.abuse.ch) badips includes IPv4 addresses that are used by the ZeuS trojan. It is the recommened blocklist if you want to block only ZeuS IPs. It excludes IP addresses that ZeuS Tracker believes to be hijacked (level 2) or belong to a free web hosting provider (level 3). Hence the false postive rate should be much lower compared to the standard ZeuS IP blocklist. **excellent list**|ipv4 hash:ip|203 unique IPs|updated every 30 mins  from [this link](https://zeustracker.abuse.ch/blocklist.php?download=badips)

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
[openbl_60d](#openbl_60d)|7239|7239|7215|99.6%|3.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|6767|0.0%|3.7%|
[et_block](#et_block)|1023|18338662|5278|0.0%|2.9%|
[firehol_level3](#firehol_level3)|107735|9625249|5212|0.0%|2.8%|
[firehol_level1](#firehol_level1)|5088|688943411|4339|0.0%|2.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|4119|0.0%|2.2%|
[dshield](#dshield)|20|5120|3336|65.1%|1.8%|
[openbl_30d](#openbl_30d)|2935|2935|2917|99.3%|1.6%|
[firehol_level2](#firehol_level2)|25736|37353|1566|4.1%|0.8%|
[blocklist_de](#blocklist_de)|31859|31859|1496|4.6%|0.8%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|1374|0.0%|0.7%|
[et_compromised](#et_compromised)|2016|2016|1323|65.6%|0.7%|
[blocklist_de_ssh](#blocklist_de_ssh)|3512|3512|1272|36.2%|0.6%|
[shunlist](#shunlist)|1241|1241|1229|99.0%|0.6%|
[bruteforceblocker](#bruteforceblocker)|1703|1703|1081|63.4%|0.5%|
[openbl_7d](#openbl_7d)|820|820|811|98.9%|0.4%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|518|0.0%|0.2%|
[ciarmy](#ciarmy)|422|422|420|99.5%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|288|0.0%|0.1%|
[stopforumspam_30d](#stopforumspam_30d)|92247|92247|198|0.2%|0.1%|
[voipbl](#voipbl)|10491|10902|196|1.7%|0.1%|
[blocklist_de_apache](#blocklist_de_apache)|16426|16426|117|0.7%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9492|9492|116|1.2%|0.0%|
[openbl_1d](#openbl_1d)|118|118|114|96.6%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29278|29278|95|0.3%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|19169|19169|67|0.3%|0.0%|
[zeus](#zeus)|234|234|64|27.3%|0.0%|
[sslbl](#sslbl)|379|379|64|16.8%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6881|6881|53|0.7%|0.0%|
[firehol_anonymous](#firehol_anonymous)|17882|81890|51|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2731|2731|47|1.7%|0.0%|
[et_tor](#et_tor)|6470|6470|40|0.6%|0.0%|
[dm_tor](#dm_tor)|6482|6482|39|0.6%|0.0%|
[bm_tor](#bm_tor)|6465|6465|39|0.6%|0.0%|
[zeus_badips](#zeus_badips)|203|203|38|18.7%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|158|158|35|22.1%|0.0%|
[nixspam](#nixspam)|28061|28061|34|0.1%|0.0%|
[firehol_proxies](#firehol_proxies)|11383|11607|32|0.2%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3458|3458|27|0.7%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|26|6.9%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|5111|5111|18|0.3%|0.0%|
[php_commenters](#php_commenters)|373|373|17|4.5%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|15|0.0%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|86|86|15|17.4%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|14|0.0%|0.0%|
[php_harvesters](#php_harvesters)|341|341|10|2.9%|0.0%|
[malc0de](#malc0de)|351|351|10|2.8%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|10|0.6%|0.0%|
[php_dictionary](#php_dictionary)|630|630|8|1.2%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|299|299|8|2.6%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|7|0.5%|0.0%|
[php_spammers](#php_spammers)|622|622|5|0.8%|0.0%|
[xroxy](#xroxy)|2124|2124|4|0.1%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|319|319|4|1.2%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7066|7066|3|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2581|2581|3|0.1%|0.0%|
[proxz](#proxz)|1047|1047|3|0.2%|0.0%|
[feodo](#feodo)|100|100|2|2.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|1|0.1%|0.0%|

## blocklist_de

[Blocklist.de](https://www.blocklist.de/) IPs that have been detected by fail2ban in the last 48 hours - **excellent list**

Source is downloaded from [this link](http://lists.blocklist.de/lists/all.txt).

The last time downloaded was found to be dated: Mon Jun  8 12:14:04 UTC 2015.

The ipset `blocklist_de` has **31859** entries, **31859** unique IPs.

The following table shows the overlaps of `blocklist_de` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de`.
- ` this % ` is the percentage **of this ipset (`blocklist_de`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|25736|37353|31859|85.2%|100.0%|
[blocklist_de_mail](#blocklist_de_mail)|19169|19169|19169|100.0%|60.1%|
[blocklist_de_apache](#blocklist_de_apache)|16426|16426|16426|100.0%|51.5%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|5111|5111|5111|100.0%|16.0%|
[firehol_level3](#firehol_level3)|107735|9625249|3866|0.0%|12.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|3851|0.0%|12.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3512|3512|3512|100.0%|11.0%|
[blocklist_de_bots](#blocklist_de_bots)|3458|3458|3446|99.6%|10.8%|
[blocklist_de_imap](#blocklist_de_imap)|2731|2731|2716|99.4%|8.5%|
[stopforumspam_30d](#stopforumspam_30d)|92247|92247|2512|2.7%|7.8%|
[stopforumspam_7d](#stopforumspam_7d)|29278|29278|2125|7.2%|6.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|1573|0.0%|4.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|1568|0.0%|4.9%|
[alienvault_reputation](#alienvault_reputation)|181932|181932|1496|0.8%|4.6%|
[stopforumspam_1d](#stopforumspam_1d)|6881|6881|1418|20.6%|4.4%|
[nixspam](#nixspam)|28061|28061|1196|4.2%|3.7%|
[openbl_60d](#openbl_60d)|7239|7239|1165|16.0%|3.6%|
[openbl_30d](#openbl_30d)|2935|2935|887|30.2%|2.7%|
[et_compromised](#et_compromised)|2016|2016|757|37.5%|2.3%|
[bruteforceblocker](#bruteforceblocker)|1703|1703|731|42.9%|2.2%|
[firehol_anonymous](#firehol_anonymous)|17882|81890|603|0.7%|1.8%|
[firehol_proxies](#firehol_proxies)|11383|11607|598|5.1%|1.8%|
[shunlist](#shunlist)|1241|1241|425|34.2%|1.3%|
[openbl_7d](#openbl_7d)|820|820|416|50.7%|1.3%|
[ri_web_proxies](#ri_web_proxies)|7066|7066|402|5.6%|1.2%|
[blocklist_de_ftp](#blocklist_de_ftp)|299|299|299|100.0%|0.9%|
[proxyrss](#proxyrss)|1481|1481|218|14.7%|0.6%|
[snort_ipfilter](#snort_ipfilter)|9492|9492|210|2.2%|0.6%|
[firehol_level1](#firehol_level1)|5088|688943411|206|0.0%|0.6%|
[xroxy](#xroxy)|2124|2124|202|9.5%|0.6%|
[et_block](#et_block)|1023|18338662|185|0.0%|0.5%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|175|0.0%|0.5%|
[blocklist_de_strongips](#blocklist_de_strongips)|158|158|158|100.0%|0.4%|
[proxz](#proxz)|1047|1047|156|14.8%|0.4%|
[dshield](#dshield)|20|5120|122|2.3%|0.3%|
[php_dictionary](#php_dictionary)|630|630|90|14.2%|0.2%|
[php_commenters](#php_commenters)|373|373|89|23.8%|0.2%|
[openbl_1d](#openbl_1d)|118|118|87|73.7%|0.2%|
[php_spammers](#php_spammers)|622|622|83|13.3%|0.2%|
[ri_connect_proxies](#ri_connect_proxies)|2581|2581|71|2.7%|0.2%|
[blocklist_de_sip](#blocklist_de_sip)|86|86|67|77.9%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|45|0.0%|0.1%|
[php_harvesters](#php_harvesters)|341|341|41|12.0%|0.1%|
[ciarmy](#ciarmy)|422|422|34|8.0%|0.1%|
[voipbl](#voipbl)|10491|10902|32|0.2%|0.1%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|12|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|6|0.0%|0.0%|
[et_tor](#et_tor)|6470|6470|5|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|4|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|2|0.1%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|2|0.3%|0.0%|
[dm_tor](#dm_tor)|6482|6482|2|0.0%|0.0%|
[bm_tor](#bm_tor)|6465|6465|2|0.0%|0.0%|
[zeus_badips](#zeus_badips)|203|203|1|0.4%|0.0%|
[zeus](#zeus)|234|234|1|0.4%|0.0%|
[sslbl](#sslbl)|379|379|1|0.2%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|

## blocklist_de_apache

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service Apache, Apache-DDOS, RFI-Attacks.

Source is downloaded from [this link](http://lists.blocklist.de/lists/apache.txt).

The last time downloaded was found to be dated: Mon Jun  8 12:28:08 UTC 2015.

The ipset `blocklist_de_apache` has **16426** entries, **16426** unique IPs.

The following table shows the overlaps of `blocklist_de_apache` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_apache`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_apache`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_apache`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|25736|37353|16426|43.9%|100.0%|
[blocklist_de](#blocklist_de)|31859|31859|16426|51.5%|100.0%|
[blocklist_de_mail](#blocklist_de_mail)|19169|19169|11059|57.6%|67.3%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|5111|5111|5101|99.8%|31.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|2472|0.0%|15.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|1312|0.0%|7.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|1085|0.0%|6.6%|
[firehol_level3](#firehol_level3)|107735|9625249|260|0.0%|1.5%|
[stopforumspam_30d](#stopforumspam_30d)|92247|92247|198|0.2%|1.2%|
[alienvault_reputation](#alienvault_reputation)|181932|181932|117|0.0%|0.7%|
[stopforumspam_7d](#stopforumspam_7d)|29278|29278|115|0.3%|0.7%|
[stopforumspam_1d](#stopforumspam_1d)|6881|6881|49|0.7%|0.2%|
[ciarmy](#ciarmy)|422|422|31|7.3%|0.1%|
[blocklist_de_strongips](#blocklist_de_strongips)|158|158|30|18.9%|0.1%|
[nixspam](#nixspam)|28061|28061|28|0.0%|0.1%|
[shunlist](#shunlist)|1241|1241|26|2.0%|0.1%|
[php_commenters](#php_commenters)|373|373|24|6.4%|0.1%|
[blocklist_de_bots](#blocklist_de_bots)|3458|3458|21|0.6%|0.1%|
[firehol_level1](#firehol_level1)|5088|688943411|12|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9492|9492|9|0.0%|0.0%|
[dshield](#dshield)|20|5120|8|0.1%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|7|0.0%|0.0%|
[et_block](#et_block)|1023|18338662|7|0.0%|0.0%|
[voipbl](#voipbl)|10491|10902|4|0.0%|0.0%|
[php_spammers](#php_spammers)|622|622|4|0.6%|0.0%|
[php_dictionary](#php_dictionary)|630|630|4|0.6%|0.0%|
[et_tor](#et_tor)|6470|6470|4|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|3|0.0%|0.0%|
[openbl_60d](#openbl_60d)|7239|7239|3|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|3|0.0%|0.0%|
[openbl_30d](#openbl_30d)|2935|2935|2|0.0%|0.0%|
[firehol_proxies](#firehol_proxies)|11383|11607|2|0.0%|0.0%|
[firehol_anonymous](#firehol_anonymous)|17882|81890|2|0.0%|0.0%|
[xroxy](#xroxy)|2124|2124|1|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|1|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7066|7066|1|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2581|2581|1|0.0%|0.0%|
[proxz](#proxz)|1047|1047|1|0.0%|0.0%|
[php_harvesters](#php_harvesters)|341|341|1|0.2%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[dm_tor](#dm_tor)|6482|6482|1|0.0%|0.0%|
[bm_tor](#bm_tor)|6465|6465|1|0.0%|0.0%|

## blocklist_de_bots

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the RFI-Attacks, REG-Bots, IRC-Bots or BadBots (BadBots = he has posted a Spam-Comment on a open Forum or Wiki).

Source is downloaded from [this link](http://lists.blocklist.de/lists/bots.txt).

The last time downloaded was found to be dated: Mon Jun  8 12:28:10 UTC 2015.

The ipset `blocklist_de_bots` has **3458** entries, **3458** unique IPs.

The following table shows the overlaps of `blocklist_de_bots` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_bots`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_bots`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_bots`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|25736|37353|3447|9.2%|99.6%|
[blocklist_de](#blocklist_de)|31859|31859|3446|10.8%|99.6%|
[firehol_level3](#firehol_level3)|107735|9625249|2224|0.0%|64.3%|
[stopforumspam_30d](#stopforumspam_30d)|92247|92247|2202|2.3%|63.6%|
[stopforumspam_7d](#stopforumspam_7d)|29278|29278|1963|6.7%|56.7%|
[stopforumspam_1d](#stopforumspam_1d)|6881|6881|1369|19.8%|39.5%|
[firehol_anonymous](#firehol_anonymous)|17882|81890|514|0.6%|14.8%|
[firehol_proxies](#firehol_proxies)|11383|11607|509|4.3%|14.7%|
[ri_web_proxies](#ri_web_proxies)|7066|7066|341|4.8%|9.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|236|0.0%|6.8%|
[proxyrss](#proxyrss)|1481|1481|217|14.6%|6.2%|
[xroxy](#xroxy)|2124|2124|163|7.6%|4.7%|
[proxz](#proxz)|1047|1047|137|13.0%|3.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|133|0.0%|3.8%|
[blocklist_de_strongips](#blocklist_de_strongips)|158|158|121|76.5%|3.4%|
[php_commenters](#php_commenters)|373|373|74|19.8%|2.1%|
[ri_connect_proxies](#ri_connect_proxies)|2581|2581|67|2.5%|1.9%|
[firehol_level1](#firehol_level1)|5088|688943411|44|0.0%|1.2%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|43|0.0%|1.2%|
[et_block](#et_block)|1023|18338662|43|0.0%|1.2%|
[nixspam](#nixspam)|28061|28061|38|0.1%|1.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|34|0.0%|0.9%|
[php_harvesters](#php_harvesters)|341|341|30|8.7%|0.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|29|0.0%|0.8%|
[alienvault_reputation](#alienvault_reputation)|181932|181932|27|0.0%|0.7%|
[snort_ipfilter](#snort_ipfilter)|9492|9492|24|0.2%|0.6%|
[blocklist_de_mail](#blocklist_de_mail)|19169|19169|24|0.1%|0.6%|
[php_spammers](#php_spammers)|622|622|23|3.6%|0.6%|
[php_dictionary](#php_dictionary)|630|630|23|3.6%|0.6%|
[blocklist_de_apache](#blocklist_de_apache)|16426|16426|21|0.1%|0.6%|
[openbl_60d](#openbl_60d)|7239|7239|12|0.1%|0.3%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|2|0.3%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|1|0.0%|0.0%|
[openbl_30d](#openbl_30d)|2935|2935|1|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|1|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|1|0.0%|0.0%|
[et_tor](#et_tor)|6470|6470|1|0.0%|0.0%|
[dm_tor](#dm_tor)|6482|6482|1|0.0%|0.0%|
[bm_tor](#bm_tor)|6465|6465|1|0.0%|0.0%|

## blocklist_de_bruteforce

[Blocklist.de](https://www.blocklist.de/) All IPs which attacks Joomlas, Wordpress and other Web-Logins with Brute-Force Logins.

Source is downloaded from [this link](http://lists.blocklist.de/lists/bruteforcelogin.txt).

The last time downloaded was found to be dated: Mon Jun  8 12:10:13 UTC 2015.

The ipset `blocklist_de_bruteforce` has **5111** entries, **5111** unique IPs.

The following table shows the overlaps of `blocklist_de_bruteforce` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_bruteforce`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_bruteforce`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_bruteforce`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|25736|37353|5111|13.6%|100.0%|
[blocklist_de](#blocklist_de)|31859|31859|5111|16.0%|100.0%|
[blocklist_de_apache](#blocklist_de_apache)|16426|16426|5101|31.0%|99.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|376|0.0%|7.3%|
[firehol_level3](#firehol_level3)|107735|9625249|59|0.0%|1.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|53|0.0%|1.0%|
[stopforumspam_30d](#stopforumspam_30d)|92247|92247|49|0.0%|0.9%|
[stopforumspam_7d](#stopforumspam_7d)|29278|29278|31|0.1%|0.6%|
[nixspam](#nixspam)|28061|28061|28|0.0%|0.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|25|0.0%|0.4%|
[alienvault_reputation](#alienvault_reputation)|181932|181932|18|0.0%|0.3%|
[stopforumspam_1d](#stopforumspam_1d)|6881|6881|14|0.2%|0.2%|
[php_commenters](#php_commenters)|373|373|7|1.8%|0.1%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|6|0.0%|0.1%|
[blocklist_de_strongips](#blocklist_de_strongips)|158|158|6|3.7%|0.1%|
[snort_ipfilter](#snort_ipfilter)|9492|9492|5|0.0%|0.0%|
[php_spammers](#php_spammers)|622|622|4|0.6%|0.0%|
[php_dictionary](#php_dictionary)|630|630|4|0.6%|0.0%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|3|0.0%|0.0%|
[firehol_level1](#firehol_level1)|5088|688943411|3|0.0%|0.0%|
[et_block](#et_block)|1023|18338662|3|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|2|0.0%|0.0%|
[xroxy](#xroxy)|2124|2124|1|0.0%|0.0%|
[voipbl](#voipbl)|10491|10902|1|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7066|7066|1|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2581|2581|1|0.0%|0.0%|
[proxz](#proxz)|1047|1047|1|0.0%|0.0%|
[firehol_proxies](#firehol_proxies)|11383|11607|1|0.0%|0.0%|
[firehol_anonymous](#firehol_anonymous)|17882|81890|1|0.0%|0.0%|
[ciarmy](#ciarmy)|422|422|1|0.2%|0.0%|

## blocklist_de_ftp

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours for attacks on the Service FTP.

Source is downloaded from [this link](http://lists.blocklist.de/lists/ftp.txt).

The last time downloaded was found to be dated: Mon Jun  8 12:10:09 UTC 2015.

The ipset `blocklist_de_ftp` has **299** entries, **299** unique IPs.

The following table shows the overlaps of `blocklist_de_ftp` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_ftp`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_ftp`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_ftp`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|25736|37353|299|0.8%|100.0%|
[blocklist_de](#blocklist_de)|31859|31859|299|0.9%|100.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|26|0.0%|8.6%|
[firehol_level3](#firehol_level3)|107735|9625249|14|0.0%|4.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|9|0.0%|3.0%|
[alienvault_reputation](#alienvault_reputation)|181932|181932|8|0.0%|2.6%|
[stopforumspam_30d](#stopforumspam_30d)|92247|92247|6|0.0%|2.0%|
[php_harvesters](#php_harvesters)|341|341|6|1.7%|2.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|6|0.0%|2.0%|
[stopforumspam_7d](#stopforumspam_7d)|29278|29278|2|0.0%|0.6%|
[stopforumspam_1d](#stopforumspam_1d)|6881|6881|2|0.0%|0.6%|
[openbl_60d](#openbl_60d)|7239|7239|2|0.0%|0.6%|
[snort_ipfilter](#snort_ipfilter)|9492|9492|1|0.0%|0.3%|
[openbl_7d](#openbl_7d)|820|820|1|0.1%|0.3%|
[openbl_30d](#openbl_30d)|2935|2935|1|0.0%|0.3%|
[blocklist_de_strongips](#blocklist_de_strongips)|158|158|1|0.6%|0.3%|

## blocklist_de_imap

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours for attacks on the Service imap, sasl, pop3, etc.

Source is downloaded from [this link](http://lists.blocklist.de/lists/imap.txt).

The last time downloaded was found to be dated: Mon Jun  8 12:28:08 UTC 2015.

The ipset `blocklist_de_imap` has **2731** entries, **2731** unique IPs.

The following table shows the overlaps of `blocklist_de_imap` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_imap`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_imap`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_imap`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|25736|37353|2716|7.2%|99.4%|
[blocklist_de_mail](#blocklist_de_mail)|19169|19169|2716|14.1%|99.4%|
[blocklist_de](#blocklist_de)|31859|31859|2716|8.5%|99.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|223|0.0%|8.1%|
[firehol_level3](#firehol_level3)|107735|9625249|56|0.0%|2.0%|
[alienvault_reputation](#alienvault_reputation)|181932|181932|47|0.0%|1.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|43|0.0%|1.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|37|0.0%|1.3%|
[openbl_60d](#openbl_60d)|7239|7239|35|0.4%|1.2%|
[openbl_30d](#openbl_30d)|2935|2935|29|0.9%|1.0%|
[firehol_level1](#firehol_level1)|5088|688943411|16|0.0%|0.5%|
[et_block](#et_block)|1023|18338662|16|0.0%|0.5%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|15|0.0%|0.5%|
[stopforumspam_30d](#stopforumspam_30d)|92247|92247|13|0.0%|0.4%|
[nixspam](#nixspam)|28061|28061|13|0.0%|0.4%|
[openbl_7d](#openbl_7d)|820|820|10|1.2%|0.3%|
[ri_web_proxies](#ri_web_proxies)|7066|7066|9|0.1%|0.3%|
[firehol_proxies](#firehol_proxies)|11383|11607|9|0.0%|0.3%|
[firehol_anonymous](#firehol_anonymous)|17882|81890|9|0.0%|0.3%|
[et_compromised](#et_compromised)|2016|2016|8|0.3%|0.2%|
[bruteforceblocker](#bruteforceblocker)|1703|1703|7|0.4%|0.2%|
[stopforumspam_7d](#stopforumspam_7d)|29278|29278|6|0.0%|0.2%|
[snort_ipfilter](#snort_ipfilter)|9492|9492|6|0.0%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|0.1%|
[php_dictionary](#php_dictionary)|630|630|2|0.3%|0.0%|
[zeus_badips](#zeus_badips)|203|203|1|0.4%|0.0%|
[zeus](#zeus)|234|234|1|0.4%|0.0%|
[shunlist](#shunlist)|1241|1241|1|0.0%|0.0%|
[php_spammers](#php_spammers)|622|622|1|0.1%|0.0%|
[php_harvesters](#php_harvesters)|341|341|1|0.2%|0.0%|
[php_commenters](#php_commenters)|373|373|1|0.2%|0.0%|
[openbl_1d](#openbl_1d)|118|118|1|0.8%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|1|0.0%|0.0%|
[ciarmy](#ciarmy)|422|422|1|0.2%|0.0%|

## blocklist_de_mail

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service Mail, Postfix.

Source is downloaded from [this link](http://lists.blocklist.de/lists/mail.txt).

The last time downloaded was found to be dated: Mon Jun  8 12:14:08 UTC 2015.

The ipset `blocklist_de_mail` has **19169** entries, **19169** unique IPs.

The following table shows the overlaps of `blocklist_de_mail` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_mail`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_mail`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_mail`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|25736|37353|19169|51.3%|100.0%|
[blocklist_de](#blocklist_de)|31859|31859|19169|60.1%|100.0%|
[blocklist_de_apache](#blocklist_de_apache)|16426|16426|11059|67.3%|57.6%|
[blocklist_de_imap](#blocklist_de_imap)|2731|2731|2716|99.4%|14.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|2640|0.0%|13.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|1419|0.0%|7.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|1219|0.0%|6.3%|
[nixspam](#nixspam)|28061|28061|1130|4.0%|5.8%|
[firehol_level3](#firehol_level3)|107735|9625249|429|0.0%|2.2%|
[stopforumspam_30d](#stopforumspam_30d)|92247|92247|243|0.2%|1.2%|
[snort_ipfilter](#snort_ipfilter)|9492|9492|181|1.9%|0.9%|
[stopforumspam_7d](#stopforumspam_7d)|29278|29278|137|0.4%|0.7%|
[firehol_proxies](#firehol_proxies)|11383|11607|90|0.7%|0.4%|
[firehol_anonymous](#firehol_anonymous)|17882|81890|90|0.1%|0.4%|
[alienvault_reputation](#alienvault_reputation)|181932|181932|67|0.0%|0.3%|
[php_dictionary](#php_dictionary)|630|630|65|10.3%|0.3%|
[ri_web_proxies](#ri_web_proxies)|7066|7066|60|0.8%|0.3%|
[php_spammers](#php_spammers)|622|622|55|8.8%|0.2%|
[stopforumspam_1d](#stopforumspam_1d)|6881|6881|50|0.7%|0.2%|
[openbl_60d](#openbl_60d)|7239|7239|44|0.6%|0.2%|
[xroxy](#xroxy)|2124|2124|40|1.8%|0.2%|
[openbl_30d](#openbl_30d)|2935|2935|37|1.2%|0.1%|
[blocklist_de_bots](#blocklist_de_bots)|3458|3458|24|0.6%|0.1%|
[firehol_level1](#firehol_level1)|5088|688943411|23|0.0%|0.1%|
[php_commenters](#php_commenters)|373|373|22|5.8%|0.1%|
[et_block](#et_block)|1023|18338662|22|0.0%|0.1%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|21|0.0%|0.1%|
[blocklist_de_strongips](#blocklist_de_strongips)|158|158|21|13.2%|0.1%|
[proxz](#proxz)|1047|1047|19|1.8%|0.0%|
[et_compromised](#et_compromised)|2016|2016|13|0.6%|0.0%|
[openbl_7d](#openbl_7d)|820|820|12|1.4%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1703|1703|12|0.7%|0.0%|
[php_harvesters](#php_harvesters)|341|341|5|1.4%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|5|0.0%|0.0%|
[shunlist](#shunlist)|1241|1241|4|0.3%|0.0%|
[et_tor](#et_tor)|6470|6470|4|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2581|2581|3|0.1%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|3|0.0%|0.0%|
[zeus_badips](#zeus_badips)|203|203|1|0.4%|0.0%|
[zeus](#zeus)|234|234|1|0.4%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|1|0.0%|0.0%|
[proxyrss](#proxyrss)|1481|1481|1|0.0%|0.0%|
[openbl_1d](#openbl_1d)|118|118|1|0.8%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.0%|
[dm_tor](#dm_tor)|6482|6482|1|0.0%|0.0%|
[ciarmy](#ciarmy)|422|422|1|0.2%|0.0%|
[bm_tor](#bm_tor)|6465|6465|1|0.0%|0.0%|

## blocklist_de_sip

[Blocklist.de](https://www.blocklist.de/) All IP addresses that tried to login in a SIP, VOIP or Asterisk Server and are included in the IPs list from [infiltrated.net](www.infiltrated.net)

Source is downloaded from [this link](http://lists.blocklist.de/lists/sip.txt).

The last time downloaded was found to be dated: Mon Jun  8 12:10:09 UTC 2015.

The ipset `blocklist_de_sip` has **86** entries, **86** unique IPs.

The following table shows the overlaps of `blocklist_de_sip` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_sip`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_sip`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_sip`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|25736|37353|67|0.1%|77.9%|
[blocklist_de](#blocklist_de)|31859|31859|67|0.2%|77.9%|
[voipbl](#voipbl)|10491|10902|28|0.2%|32.5%|
[alienvault_reputation](#alienvault_reputation)|181932|181932|15|0.0%|17.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|12|0.0%|13.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|8|0.0%|9.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|6|0.0%|6.9%|
[firehol_level3](#firehol_level3)|107735|9625249|3|0.0%|3.4%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|2|0.0%|2.3%|
[et_block](#et_block)|1023|18338662|2|0.0%|2.3%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|1|0.0%|1.1%|
[shunlist](#shunlist)|1241|1241|1|0.0%|1.1%|
[firehol_level1](#firehol_level1)|5088|688943411|1|0.0%|1.1%|

## blocklist_de_ssh

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service SSH.

Source is downloaded from [this link](http://lists.blocklist.de/lists/ssh.txt).

The last time downloaded was found to be dated: Mon Jun  8 12:14:05 UTC 2015.

The ipset `blocklist_de_ssh` has **3512** entries, **3512** unique IPs.

The following table shows the overlaps of `blocklist_de_ssh` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_ssh`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_ssh`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_ssh`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|25736|37353|3512|9.4%|100.0%|
[blocklist_de](#blocklist_de)|31859|31859|3512|11.0%|100.0%|
[alienvault_reputation](#alienvault_reputation)|181932|181932|1272|0.6%|36.2%|
[openbl_60d](#openbl_60d)|7239|7239|1104|15.2%|31.4%|
[firehol_level3](#firehol_level3)|107735|9625249|1094|0.0%|31.1%|
[openbl_30d](#openbl_30d)|2935|2935|846|28.8%|24.0%|
[et_compromised](#et_compromised)|2016|2016|743|36.8%|21.1%|
[bruteforceblocker](#bruteforceblocker)|1703|1703|719|42.2%|20.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|539|0.0%|15.3%|
[openbl_7d](#openbl_7d)|820|820|403|49.1%|11.4%|
[shunlist](#shunlist)|1241|1241|392|31.5%|11.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|147|0.0%|4.1%|
[firehol_level1](#firehol_level1)|5088|688943411|126|0.0%|3.5%|
[dshield](#dshield)|20|5120|114|2.2%|3.2%|
[et_block](#et_block)|1023|18338662|111|0.0%|3.1%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|107|0.0%|3.0%|
[openbl_1d](#openbl_1d)|118|118|86|72.8%|2.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|78|0.0%|2.2%|
[blocklist_de_strongips](#blocklist_de_strongips)|158|158|27|17.0%|0.7%|
[stopforumspam_30d](#stopforumspam_30d)|92247|92247|19|0.0%|0.5%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|6|0.0%|0.1%|
[stopforumspam_7d](#stopforumspam_7d)|29278|29278|3|0.0%|0.0%|
[nixspam](#nixspam)|28061|28061|3|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|2|0.0%|0.0%|
[ciarmy](#ciarmy)|422|422|2|0.4%|0.0%|
[sslbl](#sslbl)|379|379|1|0.2%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|1|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9492|9492|1|0.0%|0.0%|
[php_spammers](#php_spammers)|622|622|1|0.1%|0.0%|
[php_commenters](#php_commenters)|373|373|1|0.2%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|1|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|1|0.0%|0.0%|

## blocklist_de_strongips

[Blocklist.de](https://www.blocklist.de/) All IPs which are older then 2 month and have more then 5.000 attacks.

Source is downloaded from [this link](http://lists.blocklist.de/lists/strongips.txt).

The last time downloaded was found to be dated: Mon Jun  8 12:28:11 UTC 2015.

The ipset `blocklist_de_strongips` has **158** entries, **158** unique IPs.

The following table shows the overlaps of `blocklist_de_strongips` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_strongips`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_strongips`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_strongips`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|25736|37353|158|0.4%|100.0%|
[blocklist_de](#blocklist_de)|31859|31859|158|0.4%|100.0%|
[firehol_level3](#firehol_level3)|107735|9625249|142|0.0%|89.8%|
[blocklist_de_bots](#blocklist_de_bots)|3458|3458|121|3.4%|76.5%|
[stopforumspam_30d](#stopforumspam_30d)|92247|92247|114|0.1%|72.1%|
[stopforumspam_7d](#stopforumspam_7d)|29278|29278|105|0.3%|66.4%|
[stopforumspam_1d](#stopforumspam_1d)|6881|6881|99|1.4%|62.6%|
[php_commenters](#php_commenters)|373|373|35|9.3%|22.1%|
[alienvault_reputation](#alienvault_reputation)|181932|181932|35|0.0%|22.1%|
[blocklist_de_apache](#blocklist_de_apache)|16426|16426|30|0.1%|18.9%|
[blocklist_de_ssh](#blocklist_de_ssh)|3512|3512|27|0.7%|17.0%|
[openbl_60d](#openbl_60d)|7239|7239|25|0.3%|15.8%|
[openbl_7d](#openbl_7d)|820|820|24|2.9%|15.1%|
[openbl_30d](#openbl_30d)|2935|2935|24|0.8%|15.1%|
[shunlist](#shunlist)|1241|1241|21|1.6%|13.2%|
[blocklist_de_mail](#blocklist_de_mail)|19169|19169|21|0.1%|13.2%|
[openbl_1d](#openbl_1d)|118|118|19|16.1%|12.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|16|0.0%|10.1%|
[firehol_level1](#firehol_level1)|5088|688943411|12|0.0%|7.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|6|0.0%|3.7%|
[et_block](#et_block)|1023|18338662|6|0.0%|3.7%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|5111|5111|6|0.1%|3.7%|
[xroxy](#xroxy)|2124|2124|5|0.2%|3.1%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|5|0.0%|3.1%|
[php_spammers](#php_spammers)|622|622|5|0.8%|3.1%|
[firehol_proxies](#firehol_proxies)|11383|11607|5|0.0%|3.1%|
[firehol_anonymous](#firehol_anonymous)|17882|81890|5|0.0%|3.1%|
[dshield](#dshield)|20|5120|5|0.0%|3.1%|
[proxyrss](#proxyrss)|1481|1481|4|0.2%|2.5%|
[ri_web_proxies](#ri_web_proxies)|7066|7066|3|0.0%|1.8%|
[proxz](#proxz)|1047|1047|3|0.2%|1.8%|
[php_dictionary](#php_dictionary)|630|630|3|0.4%|1.8%|
[nixspam](#nixspam)|28061|28061|3|0.0%|1.8%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|1.8%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|2|0.0%|1.2%|
[php_harvesters](#php_harvesters)|341|341|2|0.5%|1.2%|
[snort_ipfilter](#snort_ipfilter)|9492|9492|1|0.0%|0.6%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|1|0.0%|0.6%|
[bruteforceblocker](#bruteforceblocker)|1703|1703|1|0.0%|0.6%|
[blocklist_de_ftp](#blocklist_de_ftp)|299|299|1|0.3%|0.6%|

## bm_tor

[torstatus.blutmagie.de](https://torstatus.blutmagie.de) list of all TOR network servers

Source is downloaded from [this link](https://torstatus.blutmagie.de/ip_list_all.php/Tor_ip_list_ALL.csv).

The last time downloaded was found to be dated: Mon Jun  8 12:18:02 UTC 2015.

The ipset `bm_tor` has **6465** entries, **6465** unique IPs.

The following table shows the overlaps of `bm_tor` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `bm_tor`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `bm_tor`.
- ` this % ` is the percentage **of this ipset (`bm_tor`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_anonymous](#firehol_anonymous)|17882|81890|6465|7.8%|100.0%|
[dm_tor](#dm_tor)|6482|6482|6397|98.6%|98.9%|
[et_tor](#et_tor)|6470|6470|5558|85.9%|85.9%|
[firehol_level3](#firehol_level3)|107735|9625249|1088|0.0%|16.8%|
[snort_ipfilter](#snort_ipfilter)|9492|9492|1050|11.0%|16.2%|
[stopforumspam_30d](#stopforumspam_30d)|92247|92247|638|0.6%|9.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|623|0.0%|9.6%|
[stopforumspam_7d](#stopforumspam_7d)|29278|29278|511|1.7%|7.9%|
[firehol_level2](#firehol_level2)|25736|37353|355|0.9%|5.4%|
[stopforumspam_1d](#stopforumspam_1d)|6881|6881|354|5.1%|5.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|187|0.0%|2.8%|
[firehol_proxies](#firehol_proxies)|11383|11607|169|1.4%|2.6%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|166|44.6%|2.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|166|0.0%|2.5%|
[php_commenters](#php_commenters)|373|373|42|11.2%|0.6%|
[alienvault_reputation](#alienvault_reputation)|181932|181932|39|0.0%|0.6%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|22|0.0%|0.3%|
[openbl_60d](#openbl_60d)|7239|7239|20|0.2%|0.3%|
[php_harvesters](#php_harvesters)|341|341|7|2.0%|0.1%|
[et_block](#et_block)|1023|18338662|5|0.0%|0.0%|
[php_spammers](#php_spammers)|622|622|4|0.6%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|4|0.0%|0.0%|
[voipbl](#voipbl)|10491|10902|3|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|3|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7066|7066|3|0.0%|0.0%|
[php_dictionary](#php_dictionary)|630|630|3|0.4%|0.0%|
[firehol_level1](#firehol_level1)|5088|688943411|3|0.0%|0.0%|
[blocklist_de](#blocklist_de)|31859|31859|2|0.0%|0.0%|
[xroxy](#xroxy)|2124|2124|1|0.0%|0.0%|
[shunlist](#shunlist)|1241|1241|1|0.0%|0.0%|
[nixspam](#nixspam)|28061|28061|1|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|19169|19169|1|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3458|3458|1|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|16426|16426|1|0.0%|0.0%|

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
[firehol_level1](#firehol_level1)|5088|688943411|592708608|86.0%|100.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|4194304|3.0%|0.7%|
[voipbl](#voipbl)|10491|10902|319|2.9%|0.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|5|0.0%|0.0%|
[firehol_level3](#firehol_level3)|107735|9625249|5|0.0%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92247|92247|1|0.0%|0.0%|
[php_harvesters](#php_harvesters)|341|341|1|0.2%|0.0%|
[php_commenters](#php_commenters)|373|373|1|0.2%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.0%|
[ciarmy](#ciarmy)|422|422|1|0.2%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1703|1703|1|0.0%|0.0%|

## bruteforceblocker

[danger.rulez.sk](http://danger.rulez.sk/) IPs detected by [bruteforceblocker](http://danger.rulez.sk/index.php/bruteforceblocker/) (fail2ban alternative for SSH on OpenBSD). This is an automatically generated list from users reporting failed authentication attempts. An IP seems to be included if 3 or more users report it. Its retention pocily seems 30 days.

Source is downloaded from [this link](http://danger.rulez.sk/projects/bruteforceblocker/blist.php).

The last time downloaded was found to be dated: Mon Jun  8 10:54:20 UTC 2015.

The ipset `bruteforceblocker` has **1703** entries, **1703** unique IPs.

The following table shows the overlaps of `bruteforceblocker` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `bruteforceblocker`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `bruteforceblocker`.
- ` this % ` is the percentage **of this ipset (`bruteforceblocker`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level3](#firehol_level3)|107735|9625249|1703|0.0%|100.0%|
[et_compromised](#et_compromised)|2016|2016|1584|78.5%|93.0%|
[alienvault_reputation](#alienvault_reputation)|181932|181932|1081|0.5%|63.4%|
[openbl_60d](#openbl_60d)|7239|7239|985|13.6%|57.8%|
[openbl_30d](#openbl_30d)|2935|2935|934|31.8%|54.8%|
[firehol_level2](#firehol_level2)|25736|37353|735|1.9%|43.1%|
[blocklist_de](#blocklist_de)|31859|31859|731|2.2%|42.9%|
[blocklist_de_ssh](#blocklist_de_ssh)|3512|3512|719|20.4%|42.2%|
[shunlist](#shunlist)|1241|1241|415|33.4%|24.3%|
[openbl_7d](#openbl_7d)|820|820|317|38.6%|18.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|154|0.0%|9.0%|
[firehol_level1](#firehol_level1)|5088|688943411|108|0.0%|6.3%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|101|0.0%|5.9%|
[et_block](#et_block)|1023|18338662|101|0.0%|5.9%|
[dshield](#dshield)|20|5120|101|1.9%|5.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|88|0.0%|5.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|47|0.0%|2.7%|
[openbl_1d](#openbl_1d)|118|118|39|33.0%|2.2%|
[stopforumspam_30d](#stopforumspam_30d)|92247|92247|13|0.0%|0.7%|
[blocklist_de_mail](#blocklist_de_mail)|19169|19169|12|0.0%|0.7%|
[blocklist_de_imap](#blocklist_de_imap)|2731|2731|7|0.2%|0.4%|
[stopforumspam_7d](#stopforumspam_7d)|29278|29278|6|0.0%|0.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|5|0.0%|0.2%|
[firehol_proxies](#firehol_proxies)|11383|11607|3|0.0%|0.1%|
[firehol_anonymous](#firehol_anonymous)|17882|81890|3|0.0%|0.1%|
[voipbl](#voipbl)|10491|10902|2|0.0%|0.1%|
[proxz](#proxz)|1047|1047|2|0.1%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|2|0.0%|0.1%|
[xroxy](#xroxy)|2124|2124|1|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6881|6881|1|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7066|7066|1|0.0%|0.0%|
[php_spammers](#php_spammers)|622|622|1|0.1%|0.0%|
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
[firehol_level3](#firehol_level3)|107735|9625249|422|0.0%|100.0%|
[alienvault_reputation](#alienvault_reputation)|181932|181932|420|0.2%|99.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|82|0.0%|19.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|45|0.0%|10.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|35|0.0%|8.2%|
[firehol_level2](#firehol_level2)|25736|37353|34|0.0%|8.0%|
[blocklist_de](#blocklist_de)|31859|31859|34|0.1%|8.0%|
[shunlist](#shunlist)|1241|1241|33|2.6%|7.8%|
[blocklist_de_apache](#blocklist_de_apache)|16426|16426|31|0.1%|7.3%|
[et_block](#et_block)|1023|18338662|5|0.0%|1.1%|
[voipbl](#voipbl)|10491|10902|4|0.0%|0.9%|
[firehol_level1](#firehol_level1)|5088|688943411|3|0.0%|0.7%|
[dshield](#dshield)|20|5120|2|0.0%|0.4%|
[blocklist_de_ssh](#blocklist_de_ssh)|3512|3512|2|0.0%|0.4%|
[stopforumspam_7d](#stopforumspam_7d)|29278|29278|1|0.0%|0.2%|
[stopforumspam_30d](#stopforumspam_30d)|92247|92247|1|0.0%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.2%|
[fullbogons](#fullbogons)|3720|670264216|1|0.0%|0.2%|
[et_compromised](#et_compromised)|2016|2016|1|0.0%|0.2%|
[bruteforceblocker](#bruteforceblocker)|1703|1703|1|0.0%|0.2%|
[bogons](#bogons)|13|592708608|1|0.0%|0.2%|
[blocklist_de_mail](#blocklist_de_mail)|19169|19169|1|0.0%|0.2%|
[blocklist_de_imap](#blocklist_de_imap)|2731|2731|1|0.0%|0.2%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|5111|5111|1|0.0%|0.2%|

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
[firehol_level3](#firehol_level3)|107735|9625249|319|0.0%|100.0%|
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
[firehol_level1](#firehol_level1)|5088|688943411|1|0.0%|0.3%|
[firehol_anonymous](#firehol_anonymous)|17882|81890|1|0.0%|0.3%|

## dm_tor

[dan.me.uk](https://www.dan.me.uk) dynamic list of TOR exit points

Source is downloaded from [this link](https://www.dan.me.uk/torlist/).

The last time downloaded was found to be dated: Mon Jun  8 12:36:05 UTC 2015.

The ipset `dm_tor` has **6482** entries, **6482** unique IPs.

The following table shows the overlaps of `dm_tor` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `dm_tor`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `dm_tor`.
- ` this % ` is the percentage **of this ipset (`dm_tor`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_anonymous](#firehol_anonymous)|17882|81890|6482|7.9%|100.0%|
[bm_tor](#bm_tor)|6465|6465|6397|98.9%|98.6%|
[et_tor](#et_tor)|6470|6470|5549|85.7%|85.6%|
[firehol_level3](#firehol_level3)|107735|9625249|1083|0.0%|16.7%|
[snort_ipfilter](#snort_ipfilter)|9492|9492|1045|11.0%|16.1%|
[stopforumspam_30d](#stopforumspam_30d)|92247|92247|635|0.6%|9.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|622|0.0%|9.5%|
[stopforumspam_7d](#stopforumspam_7d)|29278|29278|510|1.7%|7.8%|
[firehol_level2](#firehol_level2)|25736|37353|353|0.9%|5.4%|
[stopforumspam_1d](#stopforumspam_1d)|6881|6881|352|5.1%|5.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|185|0.0%|2.8%|
[firehol_proxies](#firehol_proxies)|11383|11607|169|1.4%|2.6%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|166|44.6%|2.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|165|0.0%|2.5%|
[php_commenters](#php_commenters)|373|373|42|11.2%|0.6%|
[alienvault_reputation](#alienvault_reputation)|181932|181932|39|0.0%|0.6%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|22|0.0%|0.3%|
[openbl_60d](#openbl_60d)|7239|7239|20|0.2%|0.3%|
[php_harvesters](#php_harvesters)|341|341|7|2.0%|0.1%|
[et_block](#et_block)|1023|18338662|5|0.0%|0.0%|
[php_spammers](#php_spammers)|622|622|4|0.6%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|4|0.0%|0.0%|
[voipbl](#voipbl)|10491|10902|3|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|3|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7066|7066|3|0.0%|0.0%|
[php_dictionary](#php_dictionary)|630|630|3|0.4%|0.0%|
[firehol_level1](#firehol_level1)|5088|688943411|3|0.0%|0.0%|
[blocklist_de](#blocklist_de)|31859|31859|2|0.0%|0.0%|
[xroxy](#xroxy)|2124|2124|1|0.0%|0.0%|
[shunlist](#shunlist)|1241|1241|1|0.0%|0.0%|
[nixspam](#nixspam)|28061|28061|1|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|19169|19169|1|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3458|3458|1|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|16426|16426|1|0.0%|0.0%|

## dshield

[DShield.org](https://dshield.org/) top 20 attacking class C (/24) subnets over the last three days - **excellent list**

Source is downloaded from [this link](http://feeds.dshield.org/block.txt).

The last time downloaded was found to be dated: Mon Jun  8 11:55:55 UTC 2015.

The ipset `dshield` has **20** entries, **5120** unique IPs.

The following table shows the overlaps of `dshield` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `dshield`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `dshield`.
- ` this % ` is the percentage **of this ipset (`dshield`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level1](#firehol_level1)|5088|688943411|5120|0.0%|100.0%|
[alienvault_reputation](#alienvault_reputation)|181932|181932|3336|1.8%|65.1%|
[et_block](#et_block)|1023|18338662|1537|0.0%|30.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|768|0.0%|15.0%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|512|0.0%|10.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|512|0.0%|10.0%|
[openbl_60d](#openbl_60d)|7239|7239|182|2.5%|3.5%|
[firehol_level3](#firehol_level3)|107735|9625249|176|0.0%|3.4%|
[openbl_30d](#openbl_30d)|2935|2935|162|5.5%|3.1%|
[shunlist](#shunlist)|1241|1241|138|11.1%|2.6%|
[firehol_level2](#firehol_level2)|25736|37353|123|0.3%|2.4%|
[blocklist_de](#blocklist_de)|31859|31859|122|0.3%|2.3%|
[blocklist_de_ssh](#blocklist_de_ssh)|3512|3512|114|3.2%|2.2%|
[et_compromised](#et_compromised)|2016|2016|109|5.4%|2.1%|
[bruteforceblocker](#bruteforceblocker)|1703|1703|101|5.9%|1.9%|
[openbl_7d](#openbl_7d)|820|820|47|5.7%|0.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|17|0.0%|0.3%|
[openbl_1d](#openbl_1d)|118|118|13|11.0%|0.2%|
[blocklist_de_apache](#blocklist_de_apache)|16426|16426|8|0.0%|0.1%|
[blocklist_de_strongips](#blocklist_de_strongips)|158|158|5|3.1%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|4|0.0%|0.0%|
[malc0de](#malc0de)|351|351|2|0.5%|0.0%|
[ciarmy](#ciarmy)|422|422|2|0.4%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92247|92247|1|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9492|9492|1|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7066|7066|1|0.0%|0.0%|
[proxz](#proxz)|1047|1047|1|0.0%|0.0%|
[firehol_proxies](#firehol_proxies)|11383|11607|1|0.0%|0.0%|
[firehol_anonymous](#firehol_anonymous)|17882|81890|1|0.0%|0.0%|

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
[firehol_level1](#firehol_level1)|5088|688943411|18056249|2.6%|98.4%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|18054912|98.4%|98.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|8598311|2.4%|46.8%|
[firehol_level3](#firehol_level3)|107735|9625249|7080786|73.5%|38.6%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|7079936|77.1%|38.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|2272276|0.2%|12.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|195933|0.1%|1.0%|
[fullbogons](#fullbogons)|3720|670264216|20480|0.0%|0.1%|
[alienvault_reputation](#alienvault_reputation)|181932|181932|5278|2.9%|0.0%|
[dshield](#dshield)|20|5120|1537|30.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1040|0.3%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92247|92247|1008|1.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|517|0.1%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9492|9492|315|3.3%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29278|29278|304|1.0%|0.0%|
[openbl_60d](#openbl_60d)|7239|7239|250|3.4%|0.0%|
[firehol_level2](#firehol_level2)|25736|37353|246|0.6%|0.0%|
[zeus](#zeus)|234|234|222|94.8%|0.0%|
[zeus_badips](#zeus_badips)|203|203|199|98.0%|0.0%|
[blocklist_de](#blocklist_de)|31859|31859|185|0.5%|0.0%|
[openbl_30d](#openbl_30d)|2935|2935|127|4.3%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3512|3512|111|3.1%|0.0%|
[shunlist](#shunlist)|1241|1241|108|8.7%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1703|1703|101|5.9%|0.0%|
[et_compromised](#et_compromised)|2016|2016|100|4.9%|0.0%|
[feodo](#feodo)|100|100|94|94.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6881|6881|80|1.1%|0.0%|
[openbl_7d](#openbl_7d)|820|820|45|5.4%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3458|3458|43|1.2%|0.0%|
[sslbl](#sslbl)|379|379|35|9.2%|0.0%|
[php_commenters](#php_commenters)|373|373|29|7.7%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|29|2.2%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|19169|19169|22|0.1%|0.0%|
[voipbl](#voipbl)|10491|10902|18|0.1%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2731|2731|16|0.5%|0.0%|
[palevo](#palevo)|13|13|12|92.3%|0.0%|
[openbl_1d](#openbl_1d)|118|118|8|6.7%|0.0%|
[firehol_anonymous](#firehol_anonymous)|17882|81890|8|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|16426|16426|7|0.0%|0.0%|
[php_dictionary](#php_dictionary)|630|630|6|0.9%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|6|0.4%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|158|158|6|3.7%|0.0%|
[malc0de](#malc0de)|351|351|5|1.4%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|5|0.0%|0.0%|
[dm_tor](#dm_tor)|6482|6482|5|0.0%|0.0%|
[ciarmy](#ciarmy)|422|422|5|1.1%|0.0%|
[bm_tor](#bm_tor)|6465|6465|5|0.0%|0.0%|
[nixspam](#nixspam)|28061|28061|4|0.0%|0.0%|
[et_tor](#et_tor)|6470|6470|4|0.0%|0.0%|
[php_spammers](#php_spammers)|622|622|3|0.4%|0.0%|
[firehol_proxies](#firehol_proxies)|11383|11607|3|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|5111|5111|3|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|2|0.3%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|86|86|2|2.3%|0.0%|
[php_harvesters](#php_harvesters)|341|341|1|0.2%|0.0%|
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
[firehol_level3](#firehol_level3)|107735|9625249|1780|0.0%|88.2%|
[bruteforceblocker](#bruteforceblocker)|1703|1703|1584|93.0%|78.5%|
[alienvault_reputation](#alienvault_reputation)|181932|181932|1323|0.7%|65.6%|
[openbl_60d](#openbl_60d)|7239|7239|1222|16.8%|60.6%|
[openbl_30d](#openbl_30d)|2935|2935|1095|37.3%|54.3%|
[firehol_level2](#firehol_level2)|25736|37353|759|2.0%|37.6%|
[blocklist_de](#blocklist_de)|31859|31859|757|2.3%|37.5%|
[blocklist_de_ssh](#blocklist_de_ssh)|3512|3512|743|21.1%|36.8%|
[shunlist](#shunlist)|1241|1241|432|34.8%|21.4%|
[openbl_7d](#openbl_7d)|820|820|334|40.7%|16.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|199|0.0%|9.8%|
[firehol_level1](#firehol_level1)|5088|688943411|115|0.0%|5.7%|
[dshield](#dshield)|20|5120|109|2.1%|5.4%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|100|0.0%|4.9%|
[et_block](#et_block)|1023|18338662|100|0.0%|4.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|97|0.0%|4.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|52|0.0%|2.5%|
[openbl_1d](#openbl_1d)|118|118|36|30.5%|1.7%|
[blocklist_de_mail](#blocklist_de_mail)|19169|19169|13|0.0%|0.6%|
[stopforumspam_30d](#stopforumspam_30d)|92247|92247|11|0.0%|0.5%|
[blocklist_de_imap](#blocklist_de_imap)|2731|2731|8|0.2%|0.3%|
[stopforumspam_7d](#stopforumspam_7d)|29278|29278|6|0.0%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|5|0.0%|0.2%|
[firehol_proxies](#firehol_proxies)|11383|11607|3|0.0%|0.1%|
[firehol_anonymous](#firehol_anonymous)|17882|81890|3|0.0%|0.1%|
[voipbl](#voipbl)|10491|10902|2|0.0%|0.0%|
[proxz](#proxz)|1047|1047|2|0.1%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|2|0.0%|0.0%|
[xroxy](#xroxy)|2124|2124|1|0.0%|0.0%|
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
[firehol_anonymous](#firehol_anonymous)|17882|81890|5576|6.8%|86.1%|
[bm_tor](#bm_tor)|6465|6465|5558|85.9%|85.9%|
[dm_tor](#dm_tor)|6482|6482|5549|85.6%|85.7%|
[firehol_level3](#firehol_level3)|107735|9625249|1103|0.0%|17.0%|
[snort_ipfilter](#snort_ipfilter)|9492|9492|1059|11.1%|16.3%|
[stopforumspam_30d](#stopforumspam_30d)|92247|92247|660|0.7%|10.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|633|0.0%|9.7%|
[stopforumspam_7d](#stopforumspam_7d)|29278|29278|530|1.8%|8.1%|
[firehol_level2](#firehol_level2)|25736|37353|352|0.9%|5.4%|
[stopforumspam_1d](#stopforumspam_1d)|6881|6881|348|5.0%|5.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|189|0.0%|2.9%|
[firehol_proxies](#firehol_proxies)|11383|11607|173|1.4%|2.6%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|168|45.1%|2.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|168|0.0%|2.5%|
[php_commenters](#php_commenters)|373|373|43|11.5%|0.6%|
[alienvault_reputation](#alienvault_reputation)|181932|181932|40|0.0%|0.6%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|22|0.0%|0.3%|
[openbl_60d](#openbl_60d)|7239|7239|20|0.2%|0.3%|
[php_harvesters](#php_harvesters)|341|341|7|2.0%|0.1%|
[php_spammers](#php_spammers)|622|622|6|0.9%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7066|7066|5|0.0%|0.0%|
[php_dictionary](#php_dictionary)|630|630|5|0.7%|0.0%|
[blocklist_de](#blocklist_de)|31859|31859|5|0.0%|0.0%|
[et_block](#et_block)|1023|18338662|4|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|19169|19169|4|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|16426|16426|4|0.0%|0.0%|
[voipbl](#voipbl)|10491|10902|3|0.0%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|0.0%|
[xroxy](#xroxy)|2124|2124|2|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|2|0.0%|0.0%|
[firehol_level1](#firehol_level1)|5088|688943411|2|0.0%|0.0%|
[shunlist](#shunlist)|1241|1241|1|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2581|2581|1|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3458|3458|1|0.0%|0.0%|

## feodo

[Abuse.ch Feodo tracker](https://feodotracker.abuse.ch) trojan includes IPs which are being used by Feodo (also known as Cridex or Bugat) which commits ebanking fraud - **excellent list**

Source is downloaded from [this link](https://feodotracker.abuse.ch/blocklist/?download=ipblocklist).

The last time downloaded was found to be dated: Mon Jun  8 12:18:29 UTC 2015.

The ipset `feodo` has **100** entries, **100** unique IPs.

The following table shows the overlaps of `feodo` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `feodo`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `feodo`.
- ` this % ` is the percentage **of this ipset (`feodo`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level1](#firehol_level1)|5088|688943411|100|0.0%|100.0%|
[et_block](#et_block)|1023|18338662|94|0.0%|94.0%|
[snort_ipfilter](#snort_ipfilter)|9492|9492|79|0.8%|79.0%|
[firehol_level3](#firehol_level3)|107735|9625249|79|0.0%|79.0%|
[sslbl](#sslbl)|379|379|37|9.7%|37.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|11|0.0%|11.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|3|0.0%|3.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|3|0.0%|3.0%|
[alienvault_reputation](#alienvault_reputation)|181932|181932|2|0.0%|2.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|1.0%|

## firehol_anonymous

**FireHOL Anonymous** - Known anonymizing IPs. (includes: firehol_proxies anonymous bm_tor dm_tor)

Source is downloaded from [this link]().

The last time downloaded was found to be dated: Sun Jun  7 22:20:34 UTC 2015.

The ipset `firehol_anonymous` has **17882** entries, **81890** unique IPs.

The following table shows the overlaps of `firehol_anonymous` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `firehol_anonymous`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `firehol_anonymous`.
- ` this % ` is the percentage **of this ipset (`firehol_anonymous`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_proxies](#firehol_proxies)|11383|11607|11607|100.0%|14.1%|
[ri_web_proxies](#ri_web_proxies)|7066|7066|7066|100.0%|8.6%|
[dm_tor](#dm_tor)|6482|6482|6482|100.0%|7.9%|
[bm_tor](#bm_tor)|6465|6465|6465|100.0%|7.8%|
[firehol_level3](#firehol_level3)|107735|9625249|6257|0.0%|7.6%|
[stopforumspam_30d](#stopforumspam_30d)|92247|92247|5742|6.2%|7.0%|
[et_tor](#et_tor)|6470|6470|5576|86.1%|6.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|3419|0.0%|4.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|2868|0.0%|3.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|2831|0.0%|3.4%|
[stopforumspam_7d](#stopforumspam_7d)|29278|29278|2814|9.6%|3.4%|
[ri_connect_proxies](#ri_connect_proxies)|2581|2581|2581|100.0%|3.1%|
[xroxy](#xroxy)|2124|2124|2124|100.0%|2.5%|
[proxyrss](#proxyrss)|1481|1481|1481|100.0%|1.8%|
[firehol_level2](#firehol_level2)|25736|37353|1383|3.7%|1.6%|
[snort_ipfilter](#snort_ipfilter)|9492|9492|1141|12.0%|1.3%|
[stopforumspam_1d](#stopforumspam_1d)|6881|6881|1076|15.6%|1.3%|
[proxz](#proxz)|1047|1047|1047|100.0%|1.2%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|663|100.0%|0.8%|
[blocklist_de](#blocklist_de)|31859|31859|603|1.8%|0.7%|
[blocklist_de_bots](#blocklist_de_bots)|3458|3458|514|14.8%|0.6%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|372|100.0%|0.4%|
[nixspam](#nixspam)|28061|28061|97|0.3%|0.1%|
[blocklist_de_mail](#blocklist_de_mail)|19169|19169|90|0.4%|0.1%|
[php_dictionary](#php_dictionary)|630|630|81|12.8%|0.0%|
[voipbl](#voipbl)|10491|10902|78|0.7%|0.0%|
[php_commenters](#php_commenters)|373|373|70|18.7%|0.0%|
[php_spammers](#php_spammers)|622|622|69|11.0%|0.0%|
[alienvault_reputation](#alienvault_reputation)|181932|181932|51|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|27|0.0%|0.0%|
[openbl_60d](#openbl_60d)|7239|7239|23|0.3%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|15|0.0%|0.0%|
[php_harvesters](#php_harvesters)|341|341|13|3.8%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2731|2731|9|0.3%|0.0%|
[firehol_level1](#firehol_level1)|5088|688943411|8|0.0%|0.0%|
[et_block](#et_block)|1023|18338662|8|0.0%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|7|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|6|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|158|158|5|3.1%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|3|0.2%|0.0%|
[et_compromised](#et_compromised)|2016|2016|3|0.1%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1703|1703|3|0.1%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|16426|16426|2|0.0%|0.0%|
[sslbl](#sslbl)|379|379|1|0.2%|0.0%|
[shunlist](#shunlist)|1241|1241|1|0.0%|0.0%|
[openbl_30d](#openbl_30d)|2935|2935|1|0.0%|0.0%|
[dshield](#dshield)|20|5120|1|0.0%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|319|319|1|0.3%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|5111|5111|1|0.0%|0.0%|

## firehol_level1

**FireHOL Level 1** - Maximum protection without false positives. (includes: fullbogons dshield feodo palevo sslbl zeus spamhaus_drop spamhaus_edrop)

Source is downloaded from [this link]().

The last time downloaded was found to be dated: Sun Jun  7 22:15:43 UTC 2015.

The ipset `firehol_level1` has **5088** entries, **688943411** unique IPs.

The following table shows the overlaps of `firehol_level1` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `firehol_level1`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `firehol_level1`.
- ` this % ` is the percentage **of this ipset (`firehol_level1`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[fullbogons](#fullbogons)|3720|670264216|670264216|100.0%|97.2%|
[bogons](#bogons)|13|592708608|592708608|100.0%|86.0%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|18338560|100.0%|2.6%|
[et_block](#et_block)|1023|18338662|18056249|98.4%|2.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|8864643|2.5%|1.2%|
[firehol_level3](#firehol_level3)|107735|9625249|7499698|77.9%|1.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|7497728|81.6%|1.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|4637795|3.3%|0.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|2545443|0.3%|0.3%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|487424|100.0%|0.0%|
[dshield](#dshield)|20|5120|5120|100.0%|0.0%|
[alienvault_reputation](#alienvault_reputation)|181932|181932|4339|2.3%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1932|0.5%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92247|92247|1099|1.1%|0.0%|
[sslbl](#sslbl)|379|379|379|100.0%|0.0%|
[voipbl](#voipbl)|10491|10902|333|3.0%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29278|29278|321|1.0%|0.0%|
[openbl_60d](#openbl_60d)|7239|7239|320|4.4%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9492|9492|301|3.1%|0.0%|
[firehol_level2](#firehol_level2)|25736|37353|276|0.7%|0.0%|
[zeus](#zeus)|234|234|234|100.0%|0.0%|
[blocklist_de](#blocklist_de)|31859|31859|206|0.6%|0.0%|
[zeus_badips](#zeus_badips)|203|203|203|100.0%|0.0%|
[shunlist](#shunlist)|1241|1241|198|15.9%|0.0%|
[openbl_30d](#openbl_30d)|2935|2935|182|6.2%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3512|3512|126|3.5%|0.0%|
[et_compromised](#et_compromised)|2016|2016|115|5.7%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1703|1703|108|6.3%|0.0%|
[feodo](#feodo)|100|100|100|100.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6881|6881|89|1.2%|0.0%|
[openbl_7d](#openbl_7d)|820|820|54|6.5%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3458|3458|44|1.2%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|39|2.6%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|38|2.9%|0.0%|
[php_commenters](#php_commenters)|373|373|37|9.9%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|19169|19169|23|0.1%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|22|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2731|2731|16|0.5%|0.0%|
[openbl_1d](#openbl_1d)|118|118|14|11.8%|0.0%|
[palevo](#palevo)|13|13|13|100.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|158|158|12|7.5%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|16426|16426|12|0.0%|0.0%|
[firehol_anonymous](#firehol_anonymous)|17882|81890|8|0.0%|0.0%|
[malc0de](#malc0de)|351|351|7|1.9%|0.0%|
[php_dictionary](#php_dictionary)|630|630|6|0.9%|0.0%|
[nixspam](#nixspam)|28061|28061|5|0.0%|0.0%|
[php_spammers](#php_spammers)|622|622|4|0.6%|0.0%|
[firehol_proxies](#firehol_proxies)|11383|11607|4|0.0%|0.0%|
[php_harvesters](#php_harvesters)|341|341|3|0.8%|0.0%|
[dm_tor](#dm_tor)|6482|6482|3|0.0%|0.0%|
[ciarmy](#ciarmy)|422|422|3|0.7%|0.0%|
[bm_tor](#bm_tor)|6465|6465|3|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|5111|5111|3|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7066|7066|2|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|2|0.3%|0.0%|
[et_tor](#et_tor)|6470|6470|2|0.0%|0.0%|
[virbl](#virbl)|8|8|1|12.5%|0.0%|
[proxz](#proxz)|1047|1047|1|0.0%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|319|319|1|0.3%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|86|86|1|1.1%|0.0%|

## firehol_level2

**FireHOL Level 2** - Maximum protection from attacks took place in the last 48 hours. (includes: openbl_1d blocklist_de stopforumspam_1d)

Source is downloaded from [this link]().

The last time downloaded was found to be dated: Sun Jun  7 22:20:34 UTC 2015.

The ipset `firehol_level2` has **25736** entries, **37353** unique IPs.

The following table shows the overlaps of `firehol_level2` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `firehol_level2`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `firehol_level2`.
- ` this % ` is the percentage **of this ipset (`firehol_level2`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|31859|31859|31859|100.0%|85.2%|
[blocklist_de_mail](#blocklist_de_mail)|19169|19169|19169|100.0%|51.3%|
[blocklist_de_apache](#blocklist_de_apache)|16426|16426|16426|100.0%|43.9%|
[firehol_level3](#firehol_level3)|107735|9625249|8190|0.0%|21.9%|
[stopforumspam_1d](#stopforumspam_1d)|6881|6881|6881|100.0%|18.4%|
[stopforumspam_30d](#stopforumspam_30d)|92247|92247|6791|7.3%|18.1%|
[stopforumspam_7d](#stopforumspam_7d)|29278|29278|6186|21.1%|16.5%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|5111|5111|5111|100.0%|13.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|4297|0.0%|11.5%|
[blocklist_de_ssh](#blocklist_de_ssh)|3512|3512|3512|100.0%|9.4%|
[blocklist_de_bots](#blocklist_de_bots)|3458|3458|3447|99.6%|9.2%|
[blocklist_de_imap](#blocklist_de_imap)|2731|2731|2716|99.4%|7.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|1712|0.0%|4.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|1674|0.0%|4.4%|
[alienvault_reputation](#alienvault_reputation)|181932|181932|1566|0.8%|4.1%|
[firehol_anonymous](#firehol_anonymous)|17882|81890|1383|1.6%|3.7%|
[openbl_60d](#openbl_60d)|7239|7239|1215|16.7%|3.2%|
[nixspam](#nixspam)|28061|28061|1202|4.2%|3.2%|
[firehol_proxies](#firehol_proxies)|11383|11607|1175|10.1%|3.1%|
[openbl_30d](#openbl_30d)|2935|2935|918|31.2%|2.4%|
[et_compromised](#et_compromised)|2016|2016|759|37.6%|2.0%|
[bruteforceblocker](#bruteforceblocker)|1703|1703|735|43.1%|1.9%|
[ri_web_proxies](#ri_web_proxies)|7066|7066|716|10.1%|1.9%|
[snort_ipfilter](#snort_ipfilter)|9492|9492|576|6.0%|1.5%|
[openbl_7d](#openbl_7d)|820|820|447|54.5%|1.1%|
[shunlist](#shunlist)|1241|1241|429|34.5%|1.1%|
[proxyrss](#proxyrss)|1481|1481|414|27.9%|1.1%|
[xroxy](#xroxy)|2124|2124|370|17.4%|0.9%|
[bm_tor](#bm_tor)|6465|6465|355|5.4%|0.9%|
[dm_tor](#dm_tor)|6482|6482|353|5.4%|0.9%|
[et_tor](#et_tor)|6470|6470|352|5.4%|0.9%|
[blocklist_de_ftp](#blocklist_de_ftp)|299|299|299|100.0%|0.8%|
[firehol_level1](#firehol_level1)|5088|688943411|276|0.0%|0.7%|
[proxz](#proxz)|1047|1047|252|24.0%|0.6%|
[et_block](#et_block)|1023|18338662|246|0.0%|0.6%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|242|0.0%|0.6%|
[ri_connect_proxies](#ri_connect_proxies)|2581|2581|203|7.8%|0.5%|
[php_commenters](#php_commenters)|373|373|171|45.8%|0.4%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|160|43.0%|0.4%|
[blocklist_de_strongips](#blocklist_de_strongips)|158|158|158|100.0%|0.4%|
[dshield](#dshield)|20|5120|123|2.4%|0.3%|
[openbl_1d](#openbl_1d)|118|118|118|100.0%|0.3%|
[php_dictionary](#php_dictionary)|630|630|96|15.2%|0.2%|
[php_spammers](#php_spammers)|622|622|92|14.7%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|77|0.0%|0.2%|
[blocklist_de_sip](#blocklist_de_sip)|86|86|67|77.9%|0.1%|
[php_harvesters](#php_harvesters)|341|341|57|16.7%|0.1%|
[voipbl](#voipbl)|10491|10902|35|0.3%|0.0%|
[ciarmy](#ciarmy)|422|422|34|8.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|15|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|12|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|6|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|6|0.9%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|3|0.2%|0.0%|
[zeus_badips](#zeus_badips)|203|203|2|0.9%|0.0%|
[zeus](#zeus)|234|234|2|0.8%|0.0%|
[sslbl](#sslbl)|379|379|1|0.2%|0.0%|

## firehol_level3

**FireHOL Level 3** - All the bad IPs in last 30 days. (includes: openbl_30d stopforumspam_30d virbl malc0de shunlist malwaredomainlist bruteforceblocker ciarmy cleanmx_viruses snort_ipfilter ib_bluetack_spyware ib_bluetack_hijacked ib_bluetack_webexploit php_commenters php_dictionary php_harvesters php_spammers)

Source is downloaded from [this link]().

The last time downloaded was found to be dated: Sun Jun  7 22:20:34 UTC 2015.

The ipset `firehol_level3` has **107735** entries, **9625249** unique IPs.

The following table shows the overlaps of `firehol_level3` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `firehol_level3`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `firehol_level3`.
- ` this % ` is the percentage **of this ipset (`firehol_level3`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|9177856|100.0%|95.3%|
[firehol_level1](#firehol_level1)|5088|688943411|7499698|1.0%|77.9%|
[et_block](#et_block)|1023|18338662|7080786|38.6%|73.5%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|6933023|37.8%|72.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|2537274|0.7%|26.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|919945|0.1%|9.5%|
[fullbogons](#fullbogons)|3720|670264216|566182|0.0%|5.8%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|339173|100.0%|3.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|161474|0.1%|1.6%|
[stopforumspam_30d](#stopforumspam_30d)|92247|92247|92247|100.0%|0.9%|
[stopforumspam_7d](#stopforumspam_7d)|29278|29278|29205|99.7%|0.3%|
[snort_ipfilter](#snort_ipfilter)|9492|9492|9492|100.0%|0.0%|
[firehol_level2](#firehol_level2)|25736|37353|8190|21.9%|0.0%|
[firehol_anonymous](#firehol_anonymous)|17882|81890|6257|7.6%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6881|6881|5571|80.9%|0.0%|
[alienvault_reputation](#alienvault_reputation)|181932|181932|5212|2.8%|0.0%|
[firehol_proxies](#firehol_proxies)|11383|11607|5158|44.4%|0.0%|
[blocklist_de](#blocklist_de)|31859|31859|3866|12.1%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7066|7066|3412|48.2%|0.0%|
[openbl_60d](#openbl_60d)|7239|7239|3059|42.2%|0.0%|
[openbl_30d](#openbl_30d)|2935|2935|2935|100.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3458|3458|2224|64.3%|0.0%|
[et_compromised](#et_compromised)|2016|2016|1780|88.2%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1703|1703|1703|100.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2581|2581|1474|57.1%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|1450|100.0%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|1288|100.0%|0.0%|
[xroxy](#xroxy)|2124|2124|1270|59.7%|0.0%|
[shunlist](#shunlist)|1241|1241|1241|100.0%|0.0%|
[et_tor](#et_tor)|6470|6470|1103|17.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3512|3512|1094|31.1%|0.0%|
[bm_tor](#bm_tor)|6465|6465|1088|16.8%|0.0%|
[dm_tor](#dm_tor)|6482|6482|1083|16.7%|0.0%|
[openbl_7d](#openbl_7d)|820|820|820|100.0%|0.0%|
[proxyrss](#proxyrss)|1481|1481|724|48.8%|0.0%|
[proxz](#proxz)|1047|1047|637|60.8%|0.0%|
[php_dictionary](#php_dictionary)|630|630|630|100.0%|0.0%|
[php_spammers](#php_spammers)|622|622|622|100.0%|0.0%|
[nixspam](#nixspam)|28061|28061|608|2.1%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|19169|19169|429|2.2%|0.0%|
[ciarmy](#ciarmy)|422|422|422|100.0%|0.0%|
[php_commenters](#php_commenters)|373|373|373|100.0%|0.0%|
[malc0de](#malc0de)|351|351|351|100.0%|0.0%|
[php_harvesters](#php_harvesters)|341|341|341|100.0%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|319|319|319|100.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|16426|16426|260|1.5%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|233|62.6%|0.0%|
[zeus](#zeus)|234|234|205|87.6%|0.0%|
[zeus_badips](#zeus_badips)|203|203|181|89.1%|0.0%|
[dshield](#dshield)|20|5120|176|3.4%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|158|158|142|89.8%|0.0%|
[openbl_1d](#openbl_1d)|118|118|118|100.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|90|0.0%|0.0%|
[sslbl](#sslbl)|379|379|89|23.4%|0.0%|
[feodo](#feodo)|100|100|79|79.0%|0.0%|
[voipbl](#voipbl)|10491|10902|60|0.5%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|5111|5111|59|1.1%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2731|2731|56|2.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|25|3.7%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|25|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|299|299|14|4.6%|0.0%|
[palevo](#palevo)|13|13|11|84.6%|0.0%|
[virbl](#virbl)|8|8|8|100.0%|0.0%|
[bogons](#bogons)|13|592708608|5|0.0%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|86|86|3|3.4%|0.0%|

## firehol_proxies

**FireHOL Proxies** - Known open proxies in the last 30 days. (includes: ib_bluetack_proxies maxmind_proxy_fraud proxyrss proxz ri_connect_proxies ri_web_proxies xroxy)

Source is downloaded from [this link]().

The last time downloaded was found to be dated: Sun Jun  7 22:20:34 UTC 2015.

The ipset `firehol_proxies` has **11383** entries, **11607** unique IPs.

The following table shows the overlaps of `firehol_proxies` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `firehol_proxies`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `firehol_proxies`.
- ` this % ` is the percentage **of this ipset (`firehol_proxies`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_anonymous](#firehol_anonymous)|17882|81890|11607|14.1%|100.0%|
[ri_web_proxies](#ri_web_proxies)|7066|7066|7066|100.0%|60.8%|
[firehol_level3](#firehol_level3)|107735|9625249|5158|0.0%|44.4%|
[stopforumspam_30d](#stopforumspam_30d)|92247|92247|5100|5.5%|43.9%|
[ri_connect_proxies](#ri_connect_proxies)|2581|2581|2581|100.0%|22.2%|
[stopforumspam_7d](#stopforumspam_7d)|29278|29278|2419|8.2%|20.8%|
[xroxy](#xroxy)|2124|2124|2124|100.0%|18.2%|
[proxyrss](#proxyrss)|1481|1481|1481|100.0%|12.7%|
[firehol_level2](#firehol_level2)|25736|37353|1175|3.1%|10.1%|
[proxz](#proxz)|1047|1047|1047|100.0%|9.0%|
[stopforumspam_1d](#stopforumspam_1d)|6881|6881|872|12.6%|7.5%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|663|100.0%|5.7%|
[blocklist_de](#blocklist_de)|31859|31859|598|1.8%|5.1%|
[blocklist_de_bots](#blocklist_de_bots)|3458|3458|509|14.7%|4.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|481|0.0%|4.1%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|372|100.0%|3.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|360|0.0%|3.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|272|0.0%|2.3%|
[snort_ipfilter](#snort_ipfilter)|9492|9492|252|2.6%|2.1%|
[et_tor](#et_tor)|6470|6470|173|2.6%|1.4%|
[dm_tor](#dm_tor)|6482|6482|169|2.6%|1.4%|
[bm_tor](#bm_tor)|6465|6465|169|2.6%|1.4%|
[nixspam](#nixspam)|28061|28061|96|0.3%|0.8%|
[blocklist_de_mail](#blocklist_de_mail)|19169|19169|90|0.4%|0.7%|
[php_dictionary](#php_dictionary)|630|630|80|12.6%|0.6%|
[php_spammers](#php_spammers)|622|622|67|10.7%|0.5%|
[php_commenters](#php_commenters)|373|373|64|17.1%|0.5%|
[alienvault_reputation](#alienvault_reputation)|181932|181932|32|0.0%|0.2%|
[openbl_60d](#openbl_60d)|7239|7239|18|0.2%|0.1%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|15|0.0%|0.1%|
[php_harvesters](#php_harvesters)|341|341|12|3.5%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|10|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2731|2731|9|0.3%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|158|158|5|3.1%|0.0%|
[firehol_level1](#firehol_level1)|5088|688943411|4|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|3|0.2%|0.0%|
[et_compromised](#et_compromised)|2016|2016|3|0.1%|0.0%|
[et_block](#et_block)|1023|18338662|3|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1703|1703|3|0.1%|0.0%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|2|0.0%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|16426|16426|2|0.0%|0.0%|
[voipbl](#voipbl)|10491|10902|1|0.0%|0.0%|
[sslbl](#sslbl)|379|379|1|0.2%|0.0%|
[shunlist](#shunlist)|1241|1241|1|0.0%|0.0%|
[dshield](#dshield)|20|5120|1|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|5111|5111|1|0.0%|0.0%|

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
[firehol_level1](#firehol_level1)|5088|688943411|670264216|97.2%|100.0%|
[bogons](#bogons)|13|592708608|592708608|100.0%|88.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|4235823|3.0%|0.6%|
[firehol_level3](#firehol_level3)|107735|9625249|566182|5.8%|0.0%|
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
[bruteforceblocker](#bruteforceblocker)|1703|1703|1|0.0%|0.0%|

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
[firehol_level3](#firehol_level3)|107735|9625249|25|0.0%|0.0%|
[firehol_level1](#firehol_level1)|5088|688943411|22|0.0%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92247|92247|15|0.0%|0.0%|
[firehol_proxies](#firehol_proxies)|11383|11607|15|0.1%|0.0%|
[firehol_anonymous](#firehol_anonymous)|17882|81890|15|0.0%|0.0%|
[alienvault_reputation](#alienvault_reputation)|181932|181932|14|0.0%|0.0%|
[fullbogons](#fullbogons)|3720|670264216|13|0.0%|0.0%|
[firehol_level2](#firehol_level2)|25736|37353|12|0.0%|0.0%|
[blocklist_de](#blocklist_de)|31859|31859|12|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|11|1.6%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|16426|16426|7|0.0%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29278|29278|6|0.0%|0.0%|
[nixspam](#nixspam)|28061|28061|6|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|5111|5111|6|0.1%|0.0%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|5|0.0%|0.0%|
[et_block](#et_block)|1023|18338662|5|0.0%|0.0%|
[dshield](#dshield)|20|5120|4|0.0%|0.0%|
[xroxy](#xroxy)|2124|2124|3|0.1%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9492|9492|3|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7066|7066|3|0.0%|0.0%|
[php_dictionary](#php_dictionary)|630|630|3|0.4%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|3|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|19169|19169|3|0.0%|0.0%|
[voipbl](#voipbl)|10491|10902|2|0.0%|0.0%|
[php_harvesters](#php_harvesters)|341|341|2|0.5%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6881|6881|1|0.0%|0.0%|
[proxz](#proxz)|1047|1047|1|0.0%|0.0%|
[php_spammers](#php_spammers)|622|622|1|0.1%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|1|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3512|3512|1|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2731|2731|1|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3458|3458|1|0.0%|0.0%|

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
[firehol_level3](#firehol_level3)|107735|9625249|9177856|95.3%|100.0%|
[firehol_level1](#firehol_level1)|5088|688943411|7497728|1.0%|81.6%|
[et_block](#et_block)|1023|18338662|7079936|38.6%|77.1%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|6932480|37.8%|75.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|2526625|0.7%|27.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|904796|0.1%|9.8%|
[fullbogons](#fullbogons)|3720|670264216|565248|0.0%|6.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|145472|0.1%|1.5%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1036|0.3%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92247|92247|732|0.7%|0.0%|
[alienvault_reputation](#alienvault_reputation)|181932|181932|518|0.2%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29278|29278|158|0.5%|0.0%|
[firehol_level2](#firehol_level2)|25736|37353|77|0.2%|0.0%|
[blocklist_de](#blocklist_de)|31859|31859|45|0.1%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6881|6881|41|0.5%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3458|3458|34|0.9%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|27|2.0%|0.0%|
[openbl_60d](#openbl_60d)|7239|7239|17|0.2%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9492|9492|12|0.1%|0.0%|
[openbl_30d](#openbl_30d)|2935|2935|12|0.4%|0.0%|
[zeus_badips](#zeus_badips)|203|203|10|4.9%|0.0%|
[zeus](#zeus)|234|234|10|4.2%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|7|0.4%|0.0%|
[firehol_anonymous](#firehol_anonymous)|17882|81890|7|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3512|3512|6|0.1%|0.0%|
[openbl_7d](#openbl_7d)|820|820|5|0.6%|0.0%|
[et_compromised](#et_compromised)|2016|2016|5|0.2%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1703|1703|5|0.2%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|19169|19169|5|0.0%|0.0%|
[php_dictionary](#php_dictionary)|630|630|4|0.6%|0.0%|
[dm_tor](#dm_tor)|6482|6482|4|0.0%|0.0%|
[bm_tor](#bm_tor)|6465|6465|4|0.0%|0.0%|
[shunlist](#shunlist)|1241|1241|3|0.2%|0.0%|
[php_spammers](#php_spammers)|622|622|3|0.4%|0.0%|
[nixspam](#nixspam)|28061|28061|3|0.0%|0.0%|
[et_tor](#et_tor)|6470|6470|3|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|158|158|3|1.8%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2731|2731|3|0.1%|0.0%|
[openbl_1d](#openbl_1d)|118|118|2|1.6%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|2|0.3%|0.0%|
[firehol_proxies](#firehol_proxies)|11383|11607|2|0.0%|0.0%|
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
[firehol_level1](#firehol_level1)|5088|688943411|2545443|0.3%|0.3%|
[et_block](#et_block)|1023|18338662|2272276|12.3%|0.2%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|2272265|12.3%|0.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|1354507|0.9%|0.1%|
[firehol_level3](#firehol_level3)|107735|9625249|919945|9.5%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|904796|9.8%|0.1%|
[fullbogons](#fullbogons)|3720|670264216|239993|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|33155|6.8%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|13247|3.9%|0.0%|
[alienvault_reputation](#alienvault_reputation)|181932|181932|4119|2.2%|0.0%|
[firehol_anonymous](#firehol_anonymous)|17882|81890|3419|4.1%|0.0%|
[firehol_level2](#firehol_level2)|25736|37353|1674|4.4%|0.0%|
[blocklist_de](#blocklist_de)|31859|31859|1568|4.9%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92247|92247|1511|1.6%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|19169|19169|1419|7.4%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|16426|16426|1312|7.9%|0.0%|
[nixspam](#nixspam)|28061|28061|736|2.6%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29278|29278|558|1.9%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|394|0.8%|0.0%|
[voipbl](#voipbl)|10491|10902|299|2.7%|0.0%|
[firehol_proxies](#firehol_proxies)|11383|11607|272|2.3%|0.0%|
[et_tor](#et_tor)|6470|6470|168|2.5%|0.0%|
[openbl_60d](#openbl_60d)|7239|7239|166|2.2%|0.0%|
[bm_tor](#bm_tor)|6465|6465|166|2.5%|0.0%|
[dm_tor](#dm_tor)|6482|6482|165|2.5%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7066|7066|137|1.9%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6881|6881|121|1.7%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|97|6.6%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9492|9492|87|0.9%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2581|2581|79|3.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3512|3512|78|2.2%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|66|5.1%|0.0%|
[openbl_30d](#openbl_30d)|2935|2935|63|2.1%|0.0%|
[xroxy](#xroxy)|2124|2124|58|2.7%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|56|8.4%|0.0%|
[et_compromised](#et_compromised)|2016|2016|52|2.5%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1703|1703|47|2.7%|0.0%|
[proxz](#proxz)|1047|1047|37|3.5%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2731|2731|37|1.3%|0.0%|
[proxyrss](#proxyrss)|1481|1481|36|2.4%|0.0%|
[ciarmy](#ciarmy)|422|422|35|8.2%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3458|3458|29|0.8%|0.0%|
[shunlist](#shunlist)|1241|1241|28|2.2%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|319|319|25|7.8%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|5111|5111|25|0.4%|0.0%|
[openbl_7d](#openbl_7d)|820|820|18|2.1%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|17|4.5%|0.0%|
[dshield](#dshield)|20|5120|17|0.3%|0.0%|
[php_harvesters](#php_harvesters)|341|341|11|3.2%|0.0%|
[php_dictionary](#php_dictionary)|630|630|11|1.7%|0.0%|
[malc0de](#malc0de)|351|351|11|3.1%|0.0%|
[php_spammers](#php_spammers)|622|622|9|1.4%|0.0%|
[php_commenters](#php_commenters)|373|373|9|2.4%|0.0%|
[zeus](#zeus)|234|234|7|2.9%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|86|86|6|6.9%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|299|299|6|2.0%|0.0%|
[bogons](#bogons)|13|592708608|5|0.0%|0.0%|
[zeus_badips](#zeus_badips)|203|203|4|1.9%|0.0%|
[sslbl](#sslbl)|379|379|3|0.7%|0.0%|
[feodo](#feodo)|100|100|3|3.0%|0.0%|

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
[firehol_level1](#firehol_level1)|5088|688943411|8864643|1.2%|2.5%|
[et_block](#et_block)|1023|18338662|8598311|46.8%|2.4%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|8532506|46.5%|2.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|2830203|2.0%|0.8%|
[firehol_level3](#firehol_level3)|107735|9625249|2537274|26.3%|0.7%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2526625|27.5%|0.7%|
[fullbogons](#fullbogons)|3720|670264216|249087|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|98904|20.2%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|7728|2.2%|0.0%|
[alienvault_reputation](#alienvault_reputation)|181932|181932|6767|3.7%|0.0%|
[firehol_anonymous](#firehol_anonymous)|17882|81890|2868|3.5%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92247|92247|2489|2.6%|0.0%|
[firehol_level2](#firehol_level2)|25736|37353|1712|4.5%|0.0%|
[blocklist_de](#blocklist_de)|31859|31859|1573|4.9%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|19169|19169|1219|6.3%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|16426|16426|1085|6.6%|0.0%|
[nixspam](#nixspam)|28061|28061|929|3.3%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29278|29278|853|2.9%|0.0%|
[dshield](#dshield)|20|5120|512|10.0%|0.0%|
[voipbl](#voipbl)|10491|10902|434|3.9%|0.0%|
[firehol_proxies](#firehol_proxies)|11383|11607|360|3.1%|0.0%|
[openbl_60d](#openbl_60d)|7239|7239|329|4.5%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|226|0.4%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7066|7066|205|2.9%|0.0%|
[et_tor](#et_tor)|6470|6470|189|2.9%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6881|6881|187|2.7%|0.0%|
[bm_tor](#bm_tor)|6465|6465|187|2.8%|0.0%|
[dm_tor](#dm_tor)|6482|6482|185|2.8%|0.0%|
[openbl_30d](#openbl_30d)|2935|2935|152|5.1%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3512|3512|147|4.1%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3458|3458|133|3.8%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9492|9492|122|1.2%|0.0%|
[xroxy](#xroxy)|2124|2124|104|4.8%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2581|2581|99|3.8%|0.0%|
[et_compromised](#et_compromised)|2016|2016|97|4.8%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1703|1703|88|5.1%|0.0%|
[shunlist](#shunlist)|1241|1241|65|5.2%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|5111|5111|53|1.0%|0.0%|
[proxyrss](#proxyrss)|1481|1481|51|3.4%|0.0%|
[php_spammers](#php_spammers)|622|622|51|8.1%|0.0%|
[openbl_7d](#openbl_7d)|820|820|45|5.4%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|45|3.1%|0.0%|
[ciarmy](#ciarmy)|422|422|45|10.6%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2731|2731|43|1.5%|0.0%|
[proxz](#proxz)|1047|1047|42|4.0%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|26|2.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|26|3.9%|0.0%|
[php_dictionary](#php_dictionary)|630|630|22|3.4%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|21|5.6%|0.0%|
[malc0de](#malc0de)|351|351|21|5.9%|0.0%|
[php_commenters](#php_commenters)|373|373|15|4.0%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|319|319|10|3.1%|0.0%|
[zeus](#zeus)|234|234|9|3.8%|0.0%|
[php_harvesters](#php_harvesters)|341|341|9|2.6%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|299|299|9|3.0%|0.0%|
[zeus_badips](#zeus_badips)|203|203|8|3.9%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|86|86|8|9.3%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|158|158|6|3.7%|0.0%|
[openbl_1d](#openbl_1d)|118|118|5|4.2%|0.0%|
[sslbl](#sslbl)|379|379|4|1.0%|0.0%|
[palevo](#palevo)|13|13|3|23.0%|0.0%|
[feodo](#feodo)|100|100|3|3.0%|0.0%|

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
[firehol_level1](#firehol_level1)|5088|688943411|4637795|0.6%|3.3%|
[fullbogons](#fullbogons)|3720|670264216|4235823|0.6%|3.0%|
[bogons](#bogons)|13|592708608|4194304|0.7%|3.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|2830203|0.8%|2.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|1354507|0.1%|0.9%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|270785|55.5%|0.1%|
[et_block](#et_block)|1023|18338662|195933|1.0%|0.1%|
[firehol_level3](#firehol_level3)|107735|9625249|161474|1.6%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|145472|1.5%|0.1%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|130368|0.7%|0.0%|
[alienvault_reputation](#alienvault_reputation)|181932|181932|13876|7.6%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|9226|2.7%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92247|92247|5743|6.2%|0.0%|
[firehol_level2](#firehol_level2)|25736|37353|4297|11.5%|0.0%|
[blocklist_de](#blocklist_de)|31859|31859|3851|12.0%|0.0%|
[firehol_anonymous](#firehol_anonymous)|17882|81890|2831|3.4%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|19169|19169|2640|13.7%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|16426|16426|2472|15.0%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29278|29278|1899|6.4%|0.0%|
[voipbl](#voipbl)|10491|10902|1600|14.6%|0.0%|
[nixspam](#nixspam)|28061|28061|1227|4.3%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|1172|2.4%|0.0%|
[dshield](#dshield)|20|5120|768|15.0%|0.0%|
[openbl_60d](#openbl_60d)|7239|7239|741|10.2%|0.0%|
[et_tor](#et_tor)|6470|6470|633|9.7%|0.0%|
[bm_tor](#bm_tor)|6465|6465|623|9.6%|0.0%|
[dm_tor](#dm_tor)|6482|6482|622|9.5%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3512|3512|539|15.3%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6881|6881|510|7.4%|0.0%|
[firehol_proxies](#firehol_proxies)|11383|11607|481|4.1%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|5111|5111|376|7.3%|0.0%|
[openbl_30d](#openbl_30d)|2935|2935|295|10.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3458|3458|236|6.8%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9492|9492|230|2.4%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2731|2731|223|8.1%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7066|7066|199|2.8%|0.0%|
[et_compromised](#et_compromised)|2016|2016|199|9.8%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1703|1703|154|9.0%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|147|11.4%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|125|33.6%|0.0%|
[shunlist](#shunlist)|1241|1241|113|9.1%|0.0%|
[openbl_7d](#openbl_7d)|820|820|111|13.5%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|108|7.4%|0.0%|
[xroxy](#xroxy)|2124|2124|101|4.7%|0.0%|
[proxz](#proxz)|1047|1047|87|8.3%|0.0%|
[ciarmy](#ciarmy)|422|422|82|19.4%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2581|2581|54|2.0%|0.0%|
[proxyrss](#proxyrss)|1481|1481|54|3.6%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|51|7.6%|0.0%|
[malc0de](#malc0de)|351|351|48|13.6%|0.0%|
[php_spammers](#php_spammers)|622|622|37|5.9%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|319|319|36|11.2%|0.0%|
[php_dictionary](#php_dictionary)|630|630|33|5.2%|0.0%|
[sslbl](#sslbl)|379|379|29|7.6%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|299|299|26|8.6%|0.0%|
[php_commenters](#php_commenters)|373|373|24|6.4%|0.0%|
[php_harvesters](#php_harvesters)|341|341|18|5.2%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|158|158|16|10.1%|0.0%|
[zeus](#zeus)|234|234|14|5.9%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|86|86|12|13.9%|0.0%|
[feodo](#feodo)|100|100|11|11.0%|0.0%|
[zeus_badips](#zeus_badips)|203|203|10|4.9%|0.0%|
[openbl_1d](#openbl_1d)|118|118|8|6.7%|0.0%|
[virbl](#virbl)|8|8|1|12.5%|0.0%|
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
[firehol_proxies](#firehol_proxies)|11383|11607|663|5.7%|100.0%|
[firehol_anonymous](#firehol_anonymous)|17882|81890|663|0.8%|100.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|56|0.0%|8.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|51|0.0%|7.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|26|0.0%|3.9%|
[firehol_level3](#firehol_level3)|107735|9625249|25|0.0%|3.7%|
[stopforumspam_30d](#stopforumspam_30d)|92247|92247|20|0.0%|3.0%|
[xroxy](#xroxy)|2124|2124|13|0.6%|1.9%|
[stopforumspam_7d](#stopforumspam_7d)|29278|29278|13|0.0%|1.9%|
[ri_web_proxies](#ri_web_proxies)|7066|7066|13|0.1%|1.9%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|11|0.0%|1.6%|
[ri_connect_proxies](#ri_connect_proxies)|2581|2581|7|0.2%|1.0%|
[stopforumspam_1d](#stopforumspam_1d)|6881|6881|6|0.0%|0.9%|
[proxz](#proxz)|1047|1047|6|0.5%|0.9%|
[proxyrss](#proxyrss)|1481|1481|6|0.4%|0.9%|
[firehol_level2](#firehol_level2)|25736|37353|6|0.0%|0.9%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|2|0.0%|0.3%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|2|0.1%|0.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2|0.0%|0.3%|
[firehol_level1](#firehol_level1)|5088|688943411|2|0.0%|0.3%|
[et_block](#et_block)|1023|18338662|2|0.0%|0.3%|
[blocklist_de_bots](#blocklist_de_bots)|3458|3458|2|0.0%|0.3%|
[blocklist_de](#blocklist_de)|31859|31859|2|0.0%|0.3%|
[snort_ipfilter](#snort_ipfilter)|9492|9492|1|0.0%|0.1%|
[php_dictionary](#php_dictionary)|630|630|1|0.1%|0.1%|
[nixspam](#nixspam)|28061|28061|1|0.0%|0.1%|
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
[firehol_level3](#firehol_level3)|107735|9625249|339173|3.5%|100.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|13247|0.0%|3.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|9226|0.0%|2.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|7728|0.0%|2.2%|
[firehol_level1](#firehol_level1)|5088|688943411|1932|0.0%|0.5%|
[et_block](#et_block)|1023|18338662|1040|0.0%|0.3%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|1037|0.0%|0.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1036|0.0%|0.3%|
[fullbogons](#fullbogons)|3720|670264216|890|0.0%|0.2%|
[alienvault_reputation](#alienvault_reputation)|181932|181932|288|0.1%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92247|92247|46|0.0%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|27|2.0%|0.0%|
[firehol_anonymous](#firehol_anonymous)|17882|81890|27|0.0%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29278|29278|22|0.0%|0.0%|
[et_tor](#et_tor)|6470|6470|22|0.3%|0.0%|
[dm_tor](#dm_tor)|6482|6482|22|0.3%|0.0%|
[bm_tor](#bm_tor)|6465|6465|22|0.3%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|19|1.3%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9492|9492|15|0.1%|0.0%|
[firehol_level2](#firehol_level2)|25736|37353|15|0.0%|0.0%|
[firehol_proxies](#firehol_proxies)|11383|11607|10|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6881|6881|9|0.1%|0.0%|
[blocklist_de](#blocklist_de)|31859|31859|6|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7066|7066|5|0.0%|0.0%|
[openbl_60d](#openbl_60d)|7239|7239|5|0.0%|0.0%|
[nixspam](#nixspam)|28061|28061|5|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|5|1.3%|0.0%|
[voipbl](#voipbl)|10491|10902|4|0.0%|0.0%|
[openbl_30d](#openbl_30d)|2935|2935|4|0.1%|0.0%|
[malc0de](#malc0de)|351|351|3|0.8%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|3|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|16426|16426|3|0.0%|0.0%|
[palevo](#palevo)|13|13|2|15.3%|0.0%|
[et_compromised](#et_compromised)|2016|2016|2|0.0%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|319|319|2|0.6%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1703|1703|2|0.1%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3512|3512|2|0.0%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|86|86|2|2.3%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|5111|5111|2|0.0%|0.0%|
[zeus_badips](#zeus_badips)|203|203|1|0.4%|0.0%|
[zeus](#zeus)|234|234|1|0.4%|0.0%|
[xroxy](#xroxy)|2124|2124|1|0.0%|0.0%|
[sslbl](#sslbl)|379|379|1|0.2%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|1|0.0%|0.0%|
[shunlist](#shunlist)|1241|1241|1|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2581|2581|1|0.0%|0.0%|
[php_harvesters](#php_harvesters)|341|341|1|0.2%|0.0%|
[php_dictionary](#php_dictionary)|630|630|1|0.1%|0.0%|
[php_commenters](#php_commenters)|373|373|1|0.2%|0.0%|
[feodo](#feodo)|100|100|1|1.0%|0.0%|
[ciarmy](#ciarmy)|422|422|1|0.2%|0.0%|
[bogons](#bogons)|13|592708608|1|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|19169|19169|1|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3458|3458|1|0.0%|0.0%|

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
[firehol_level3](#firehol_level3)|107735|9625249|1450|0.0%|100.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|108|0.0%|7.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|97|0.0%|6.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|45|0.0%|3.1%|
[firehol_level1](#firehol_level1)|5088|688943411|39|0.0%|2.6%|
[fullbogons](#fullbogons)|3720|670264216|33|0.0%|2.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|19|0.0%|1.3%|
[alienvault_reputation](#alienvault_reputation)|181932|181932|10|0.0%|0.6%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|7|0.0%|0.4%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|6|0.0%|0.4%|
[et_block](#et_block)|1023|18338662|6|0.0%|0.4%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|3|0.2%|0.2%|
[firehol_proxies](#firehol_proxies)|11383|11607|3|0.0%|0.2%|
[firehol_level2](#firehol_level2)|25736|37353|3|0.0%|0.2%|
[firehol_anonymous](#firehol_anonymous)|17882|81890|3|0.0%|0.2%|
[stopforumspam_7d](#stopforumspam_7d)|29278|29278|2|0.0%|0.1%|
[stopforumspam_30d](#stopforumspam_30d)|92247|92247|2|0.0%|0.1%|
[openbl_60d](#openbl_60d)|7239|7239|2|0.0%|0.1%|
[openbl_30d](#openbl_30d)|2935|2935|2|0.0%|0.1%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|2|0.3%|0.1%|
[blocklist_de](#blocklist_de)|31859|31859|2|0.0%|0.1%|
[stopforumspam_1d](#stopforumspam_1d)|6881|6881|1|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9492|9492|1|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7066|7066|1|0.0%|0.0%|
[openbl_7d](#openbl_7d)|820|820|1|0.1%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|1|0.0%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|319|319|1|0.3%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|158|158|1|0.6%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3512|3512|1|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3458|3458|1|0.0%|0.0%|

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
[firehol_level3](#firehol_level3)|107735|9625249|351|0.0%|100.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|48|0.0%|13.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|21|0.0%|5.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|11|0.0%|3.1%|
[cleanmx_viruses](#cleanmx_viruses)|319|319|10|3.1%|2.8%|
[alienvault_reputation](#alienvault_reputation)|181932|181932|10|0.0%|2.8%|
[firehol_level1](#firehol_level1)|5088|688943411|7|0.0%|1.9%|
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
[firehol_level3](#firehol_level3)|107735|9625249|1288|0.0%|100.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|147|0.0%|11.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|66|0.0%|5.1%|
[firehol_level1](#firehol_level1)|5088|688943411|38|0.0%|2.9%|
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
[nixspam](#nixspam)|28061|28061|1|0.0%|0.0%|

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
[firehol_proxies](#firehol_proxies)|11383|11607|372|3.2%|100.0%|
[firehol_anonymous](#firehol_anonymous)|17882|81890|372|0.4%|100.0%|
[firehol_level3](#firehol_level3)|107735|9625249|233|0.0%|62.6%|
[stopforumspam_30d](#stopforumspam_30d)|92247|92247|232|0.2%|62.3%|
[stopforumspam_7d](#stopforumspam_7d)|29278|29278|190|0.6%|51.0%|
[snort_ipfilter](#snort_ipfilter)|9492|9492|174|1.8%|46.7%|
[et_tor](#et_tor)|6470|6470|168|2.5%|45.1%|
[dm_tor](#dm_tor)|6482|6482|166|2.5%|44.6%|
[bm_tor](#bm_tor)|6465|6465|166|2.5%|44.6%|
[stopforumspam_1d](#stopforumspam_1d)|6881|6881|160|2.3%|43.0%|
[firehol_level2](#firehol_level2)|25736|37353|160|0.4%|43.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|125|0.0%|33.6%|
[php_commenters](#php_commenters)|373|373|39|10.4%|10.4%|
[alienvault_reputation](#alienvault_reputation)|181932|181932|26|0.0%|6.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|21|0.0%|5.6%|
[openbl_60d](#openbl_60d)|7239|7239|18|0.2%|4.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|17|0.0%|4.5%|
[php_harvesters](#php_harvesters)|341|341|6|1.7%|1.6%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|5|0.0%|1.3%|
[ri_web_proxies](#ri_web_proxies)|7066|7066|4|0.0%|1.0%|
[php_spammers](#php_spammers)|622|622|4|0.6%|1.0%|
[php_dictionary](#php_dictionary)|630|630|4|0.6%|1.0%|
[xroxy](#xroxy)|2124|2124|1|0.0%|0.2%|
[voipbl](#voipbl)|10491|10902|1|0.0%|0.2%|
[shunlist](#shunlist)|1241|1241|1|0.0%|0.2%|
[ri_connect_proxies](#ri_connect_proxies)|2581|2581|1|0.0%|0.2%|
[et_block](#et_block)|1023|18338662|1|0.0%|0.2%|
[blocklist_de_mail](#blocklist_de_mail)|19169|19169|1|0.0%|0.2%|
[blocklist_de_apache](#blocklist_de_apache)|16426|16426|1|0.0%|0.2%|
[blocklist_de](#blocklist_de)|31859|31859|1|0.0%|0.2%|

## nixspam

[NiX Spam](http://www.heise.de/ix/NiX-Spam-DNSBL-and-blacklist-for-download-499637.html) IP addresses that sent spam in the last hour - automatically generated entries without distinguishing open proxies from relays, dialup gateways, and so on. All IPs are removed after 12 hours if there is no spam from there.

Source is downloaded from [this link](http://www.dnsbl.manitu.net/download/nixspam-ip.dump.gz).

The last time downloaded was found to be dated: Mon Jun  8 12:30:02 UTC 2015.

The ipset `nixspam` has **28061** entries, **28061** unique IPs.

The following table shows the overlaps of `nixspam` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `nixspam`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `nixspam`.
- ` this % ` is the percentage **of this ipset (`nixspam`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|1227|0.0%|4.3%|
[firehol_level2](#firehol_level2)|25736|37353|1202|3.2%|4.2%|
[blocklist_de](#blocklist_de)|31859|31859|1196|3.7%|4.2%|
[blocklist_de_mail](#blocklist_de_mail)|19169|19169|1130|5.8%|4.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|929|0.0%|3.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|736|0.0%|2.6%|
[firehol_level3](#firehol_level3)|107735|9625249|608|0.0%|2.1%|
[snort_ipfilter](#snort_ipfilter)|9492|9492|473|4.9%|1.6%|
[stopforumspam_30d](#stopforumspam_30d)|92247|92247|148|0.1%|0.5%|
[php_dictionary](#php_dictionary)|630|630|113|17.9%|0.4%|
[firehol_anonymous](#firehol_anonymous)|17882|81890|97|0.1%|0.3%|
[firehol_proxies](#firehol_proxies)|11383|11607|96|0.8%|0.3%|
[stopforumspam_7d](#stopforumspam_7d)|29278|29278|91|0.3%|0.3%|
[php_spammers](#php_spammers)|622|622|86|13.8%|0.3%|
[ri_web_proxies](#ri_web_proxies)|7066|7066|64|0.9%|0.2%|
[xroxy](#xroxy)|2124|2124|45|2.1%|0.1%|
[stopforumspam_1d](#stopforumspam_1d)|6881|6881|42|0.6%|0.1%|
[blocklist_de_bots](#blocklist_de_bots)|3458|3458|38|1.0%|0.1%|
[alienvault_reputation](#alienvault_reputation)|181932|181932|34|0.0%|0.1%|
[proxz](#proxz)|1047|1047|31|2.9%|0.1%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|5111|5111|28|0.5%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|16426|16426|28|0.1%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2731|2731|13|0.4%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2581|2581|8|0.3%|0.0%|
[openbl_60d](#openbl_60d)|7239|7239|8|0.1%|0.0%|
[php_commenters](#php_commenters)|373|373|7|1.8%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|6|0.0%|0.0%|
[proxyrss](#proxyrss)|1481|1481|5|0.3%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|5|0.0%|0.0%|
[firehol_level1](#firehol_level1)|5088|688943411|5|0.0%|0.0%|
[et_block](#et_block)|1023|18338662|4|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|3|0.0%|0.0%|
[php_harvesters](#php_harvesters)|341|341|3|0.8%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|158|158|3|1.8%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3512|3512|3|0.0%|0.0%|
[voipbl](#voipbl)|10491|10902|2|0.0%|0.0%|
[zeus_badips](#zeus_badips)|203|203|1|0.4%|0.0%|
[zeus](#zeus)|234|234|1|0.4%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|1|0.0%|0.0%|
[openbl_7d](#openbl_7d)|820|820|1|0.1%|0.0%|
[openbl_30d](#openbl_30d)|2935|2935|1|0.0%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|1|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|1|0.1%|0.0%|
[dm_tor](#dm_tor)|6482|6482|1|0.0%|0.0%|
[bm_tor](#bm_tor)|6465|6465|1|0.0%|0.0%|

## openbl_1d

[OpenBL.org](http://www.openbl.org/) last 24 hours IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.

Source is downloaded from [this link](http://www.openbl.org/lists/base_1days.txt).

The last time downloaded was found to be dated: Mon Jun  8 12:07:00 UTC 2015.

The ipset `openbl_1d` has **118** entries, **118** unique IPs.

The following table shows the overlaps of `openbl_1d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl_1d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl_1d`.
- ` this % ` is the percentage **of this ipset (`openbl_1d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[openbl_7d](#openbl_7d)|820|820|118|14.3%|100.0%|
[openbl_60d](#openbl_60d)|7239|7239|118|1.6%|100.0%|
[openbl_30d](#openbl_30d)|2935|2935|118|4.0%|100.0%|
[firehol_level3](#firehol_level3)|107735|9625249|118|0.0%|100.0%|
[firehol_level2](#firehol_level2)|25736|37353|118|0.3%|100.0%|
[alienvault_reputation](#alienvault_reputation)|181932|181932|114|0.0%|96.6%|
[blocklist_de](#blocklist_de)|31859|31859|87|0.2%|73.7%|
[blocklist_de_ssh](#blocklist_de_ssh)|3512|3512|86|2.4%|72.8%|
[shunlist](#shunlist)|1241|1241|50|4.0%|42.3%|
[bruteforceblocker](#bruteforceblocker)|1703|1703|39|2.2%|33.0%|
[et_compromised](#et_compromised)|2016|2016|36|1.7%|30.5%|
[blocklist_de_strongips](#blocklist_de_strongips)|158|158|19|12.0%|16.1%|
[firehol_level1](#firehol_level1)|5088|688943411|14|0.0%|11.8%|
[dshield](#dshield)|20|5120|13|0.2%|11.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|8|0.0%|6.7%|
[et_block](#et_block)|1023|18338662|8|0.0%|6.7%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|7|0.0%|5.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|5|0.0%|4.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2|0.0%|1.6%|
[stopforumspam_30d](#stopforumspam_30d)|92247|92247|1|0.0%|0.8%|
[php_spammers](#php_spammers)|622|622|1|0.1%|0.8%|
[php_commenters](#php_commenters)|373|373|1|0.2%|0.8%|
[blocklist_de_mail](#blocklist_de_mail)|19169|19169|1|0.0%|0.8%|
[blocklist_de_imap](#blocklist_de_imap)|2731|2731|1|0.0%|0.8%|

## openbl_30d

[OpenBL.org](http://www.openbl.org/) last 30 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.

Source is downloaded from [this link](http://www.openbl.org/lists/base_30days.txt).

The last time downloaded was found to be dated: Mon Jun  8 12:07:00 UTC 2015.

The ipset `openbl_30d` has **2935** entries, **2935** unique IPs.

The following table shows the overlaps of `openbl_30d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl_30d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl_30d`.
- ` this % ` is the percentage **of this ipset (`openbl_30d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[openbl_60d](#openbl_60d)|7239|7239|2935|40.5%|100.0%|
[firehol_level3](#firehol_level3)|107735|9625249|2935|0.0%|100.0%|
[alienvault_reputation](#alienvault_reputation)|181932|181932|2917|1.6%|99.3%|
[et_compromised](#et_compromised)|2016|2016|1095|54.3%|37.3%|
[bruteforceblocker](#bruteforceblocker)|1703|1703|934|54.8%|31.8%|
[firehol_level2](#firehol_level2)|25736|37353|918|2.4%|31.2%|
[blocklist_de](#blocklist_de)|31859|31859|887|2.7%|30.2%|
[blocklist_de_ssh](#blocklist_de_ssh)|3512|3512|846|24.0%|28.8%|
[openbl_7d](#openbl_7d)|820|820|820|100.0%|27.9%|
[shunlist](#shunlist)|1241|1241|520|41.9%|17.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|295|0.0%|10.0%|
[firehol_level1](#firehol_level1)|5088|688943411|182|0.0%|6.2%|
[dshield](#dshield)|20|5120|162|3.1%|5.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|152|0.0%|5.1%|
[et_block](#et_block)|1023|18338662|127|0.0%|4.3%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|121|0.0%|4.1%|
[openbl_1d](#openbl_1d)|118|118|118|100.0%|4.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|63|0.0%|2.1%|
[blocklist_de_mail](#blocklist_de_mail)|19169|19169|37|0.1%|1.2%|
[blocklist_de_imap](#blocklist_de_imap)|2731|2731|29|1.0%|0.9%|
[blocklist_de_strongips](#blocklist_de_strongips)|158|158|24|15.1%|0.8%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|12|0.0%|0.4%|
[stopforumspam_30d](#stopforumspam_30d)|92247|92247|4|0.0%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|4|0.0%|0.1%|
[voipbl](#voipbl)|10491|10902|3|0.0%|0.1%|
[snort_ipfilter](#snort_ipfilter)|9492|9492|3|0.0%|0.1%|
[zeus](#zeus)|234|234|2|0.8%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|2|0.1%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|16426|16426|2|0.0%|0.0%|
[zeus_badips](#zeus_badips)|203|203|1|0.4%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29278|29278|1|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6881|6881|1|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|1|0.0%|0.0%|
[php_spammers](#php_spammers)|622|622|1|0.1%|0.0%|
[php_commenters](#php_commenters)|373|373|1|0.2%|0.0%|
[nixspam](#nixspam)|28061|28061|1|0.0%|0.0%|
[firehol_anonymous](#firehol_anonymous)|17882|81890|1|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|299|299|1|0.3%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3458|3458|1|0.0%|0.0%|

## openbl_60d

[OpenBL.org](http://www.openbl.org/) last 60 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.

Source is downloaded from [this link](http://www.openbl.org/lists/base_60days.txt).

The last time downloaded was found to be dated: Mon Jun  8 12:07:00 UTC 2015.

The ipset `openbl_60d` has **7239** entries, **7239** unique IPs.

The following table shows the overlaps of `openbl_60d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl_60d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl_60d`.
- ` this % ` is the percentage **of this ipset (`openbl_60d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[alienvault_reputation](#alienvault_reputation)|181932|181932|7215|3.9%|99.6%|
[firehol_level3](#firehol_level3)|107735|9625249|3059|0.0%|42.2%|
[openbl_30d](#openbl_30d)|2935|2935|2935|100.0%|40.5%|
[et_compromised](#et_compromised)|2016|2016|1222|60.6%|16.8%|
[firehol_level2](#firehol_level2)|25736|37353|1215|3.2%|16.7%|
[blocklist_de](#blocklist_de)|31859|31859|1165|3.6%|16.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3512|3512|1104|31.4%|15.2%|
[bruteforceblocker](#bruteforceblocker)|1703|1703|985|57.8%|13.6%|
[openbl_7d](#openbl_7d)|820|820|820|100.0%|11.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|741|0.0%|10.2%|
[shunlist](#shunlist)|1241|1241|542|43.6%|7.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|329|0.0%|4.5%|
[firehol_level1](#firehol_level1)|5088|688943411|320|0.0%|4.4%|
[et_block](#et_block)|1023|18338662|250|0.0%|3.4%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|239|0.0%|3.3%|
[dshield](#dshield)|20|5120|182|3.5%|2.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|166|0.0%|2.2%|
[openbl_1d](#openbl_1d)|118|118|118|100.0%|1.6%|
[stopforumspam_30d](#stopforumspam_30d)|92247|92247|54|0.0%|0.7%|
[blocklist_de_mail](#blocklist_de_mail)|19169|19169|44|0.2%|0.6%|
[blocklist_de_imap](#blocklist_de_imap)|2731|2731|35|1.2%|0.4%|
[blocklist_de_strongips](#blocklist_de_strongips)|158|158|25|15.8%|0.3%|
[stopforumspam_7d](#stopforumspam_7d)|29278|29278|24|0.0%|0.3%|
[snort_ipfilter](#snort_ipfilter)|9492|9492|24|0.2%|0.3%|
[firehol_anonymous](#firehol_anonymous)|17882|81890|23|0.0%|0.3%|
[stopforumspam_1d](#stopforumspam_1d)|6881|6881|20|0.2%|0.2%|
[et_tor](#et_tor)|6470|6470|20|0.3%|0.2%|
[dm_tor](#dm_tor)|6482|6482|20|0.3%|0.2%|
[bm_tor](#bm_tor)|6465|6465|20|0.3%|0.2%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|18|4.8%|0.2%|
[firehol_proxies](#firehol_proxies)|11383|11607|18|0.1%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|17|0.0%|0.2%|
[blocklist_de_bots](#blocklist_de_bots)|3458|3458|12|0.3%|0.1%|
[php_commenters](#php_commenters)|373|373|10|2.6%|0.1%|
[voipbl](#voipbl)|10491|10902|8|0.0%|0.1%|
[nixspam](#nixspam)|28061|28061|8|0.0%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|5|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|16426|16426|3|0.0%|0.0%|
[zeus](#zeus)|234|234|2|0.8%|0.0%|
[php_harvesters](#php_harvesters)|341|341|2|0.5%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|2|0.1%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|299|299|2|0.6%|0.0%|
[zeus_badips](#zeus_badips)|203|203|1|0.4%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|1|0.0%|0.0%|
[php_spammers](#php_spammers)|622|622|1|0.1%|0.0%|

## openbl_7d

[OpenBL.org](http://www.openbl.org/) last 7 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.

Source is downloaded from [this link](http://www.openbl.org/lists/base_7days.txt).

The last time downloaded was found to be dated: Mon Jun  8 12:07:00 UTC 2015.

The ipset `openbl_7d` has **820** entries, **820** unique IPs.

The following table shows the overlaps of `openbl_7d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl_7d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl_7d`.
- ` this % ` is the percentage **of this ipset (`openbl_7d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[openbl_60d](#openbl_60d)|7239|7239|820|11.3%|100.0%|
[openbl_30d](#openbl_30d)|2935|2935|820|27.9%|100.0%|
[firehol_level3](#firehol_level3)|107735|9625249|820|0.0%|100.0%|
[alienvault_reputation](#alienvault_reputation)|181932|181932|811|0.4%|98.9%|
[firehol_level2](#firehol_level2)|25736|37353|447|1.1%|54.5%|
[blocklist_de](#blocklist_de)|31859|31859|416|1.3%|50.7%|
[blocklist_de_ssh](#blocklist_de_ssh)|3512|3512|403|11.4%|49.1%|
[et_compromised](#et_compromised)|2016|2016|334|16.5%|40.7%|
[bruteforceblocker](#bruteforceblocker)|1703|1703|317|18.6%|38.6%|
[shunlist](#shunlist)|1241|1241|216|17.4%|26.3%|
[openbl_1d](#openbl_1d)|118|118|118|100.0%|14.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|111|0.0%|13.5%|
[firehol_level1](#firehol_level1)|5088|688943411|54|0.0%|6.5%|
[dshield](#dshield)|20|5120|47|0.9%|5.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|45|0.0%|5.4%|
[et_block](#et_block)|1023|18338662|45|0.0%|5.4%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|42|0.0%|5.1%|
[blocklist_de_strongips](#blocklist_de_strongips)|158|158|24|15.1%|2.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|18|0.0%|2.1%|
[blocklist_de_mail](#blocklist_de_mail)|19169|19169|12|0.0%|1.4%|
[blocklist_de_imap](#blocklist_de_imap)|2731|2731|10|0.3%|1.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|5|0.0%|0.6%|
[stopforumspam_30d](#stopforumspam_30d)|92247|92247|3|0.0%|0.3%|
[php_spammers](#php_spammers)|622|622|1|0.1%|0.1%|
[php_commenters](#php_commenters)|373|373|1|0.2%|0.1%|
[nixspam](#nixspam)|28061|28061|1|0.0%|0.1%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|1|0.0%|0.1%|
[blocklist_de_ftp](#blocklist_de_ftp)|299|299|1|0.3%|0.1%|

## palevo

[Abuse.ch Palevo tracker](https://palevotracker.abuse.ch) worm includes IPs which are being used as botnet C&C for the Palevo crimeware - **excellent list**

Source is downloaded from [this link](https://palevotracker.abuse.ch/blocklists.php?download=ipblocklist).

The last time downloaded was found to be dated: Mon Jun  8 12:18:25 UTC 2015.

The ipset `palevo` has **13** entries, **13** unique IPs.

The following table shows the overlaps of `palevo` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `palevo`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `palevo`.
- ` this % ` is the percentage **of this ipset (`palevo`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level1](#firehol_level1)|5088|688943411|13|0.0%|100.0%|
[et_block](#et_block)|1023|18338662|12|0.0%|92.3%|
[snort_ipfilter](#snort_ipfilter)|9492|9492|11|0.1%|84.6%|
[firehol_level3](#firehol_level3)|107735|9625249|11|0.0%|84.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|3|0.0%|23.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|2|0.0%|15.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|1|0.0%|7.6%|

## php_commenters

[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) comment spammers (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=c&rss=1).

The last time downloaded was found to be dated: Mon Jun  8 12:36:20 UTC 2015.

The ipset `php_commenters` has **373** entries, **373** unique IPs.

The following table shows the overlaps of `php_commenters` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `php_commenters`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `php_commenters`.
- ` this % ` is the percentage **of this ipset (`php_commenters`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level3](#firehol_level3)|107735|9625249|373|0.0%|100.0%|
[stopforumspam_30d](#stopforumspam_30d)|92247|92247|277|0.3%|74.2%|
[stopforumspam_7d](#stopforumspam_7d)|29278|29278|206|0.7%|55.2%|
[firehol_level2](#firehol_level2)|25736|37353|171|0.4%|45.8%|
[stopforumspam_1d](#stopforumspam_1d)|6881|6881|150|2.1%|40.2%|
[blocklist_de](#blocklist_de)|31859|31859|89|0.2%|23.8%|
[blocklist_de_bots](#blocklist_de_bots)|3458|3458|74|2.1%|19.8%|
[firehol_anonymous](#firehol_anonymous)|17882|81890|70|0.0%|18.7%|
[firehol_proxies](#firehol_proxies)|11383|11607|64|0.5%|17.1%|
[snort_ipfilter](#snort_ipfilter)|9492|9492|50|0.5%|13.4%|
[et_tor](#et_tor)|6470|6470|43|0.6%|11.5%|
[php_spammers](#php_spammers)|622|622|42|6.7%|11.2%|
[dm_tor](#dm_tor)|6482|6482|42|0.6%|11.2%|
[bm_tor](#bm_tor)|6465|6465|42|0.6%|11.2%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|39|10.4%|10.4%|
[firehol_level1](#firehol_level1)|5088|688943411|37|0.0%|9.9%|
[blocklist_de_strongips](#blocklist_de_strongips)|158|158|35|22.1%|9.3%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|29|0.0%|7.7%|
[et_block](#et_block)|1023|18338662|29|0.0%|7.7%|
[php_dictionary](#php_dictionary)|630|630|26|4.1%|6.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|24|0.0%|6.4%|
[blocklist_de_apache](#blocklist_de_apache)|16426|16426|24|0.1%|6.4%|
[ri_web_proxies](#ri_web_proxies)|7066|7066|23|0.3%|6.1%|
[blocklist_de_mail](#blocklist_de_mail)|19169|19169|22|0.1%|5.8%|
[alienvault_reputation](#alienvault_reputation)|181932|181932|17|0.0%|4.5%|
[php_harvesters](#php_harvesters)|341|341|15|4.3%|4.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|15|0.0%|4.0%|
[openbl_60d](#openbl_60d)|7239|7239|10|0.1%|2.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|9|0.0%|2.4%|
[xroxy](#xroxy)|2124|2124|8|0.3%|2.1%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|7|0.0%|1.8%|
[proxz](#proxz)|1047|1047|7|0.6%|1.8%|
[nixspam](#nixspam)|28061|28061|7|0.0%|1.8%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|5111|5111|7|0.1%|1.8%|
[ri_connect_proxies](#ri_connect_proxies)|2581|2581|5|0.1%|1.3%|
[proxyrss](#proxyrss)|1481|1481|4|0.2%|1.0%|
[zeus_badips](#zeus_badips)|203|203|1|0.4%|0.2%|
[zeus](#zeus)|234|234|1|0.4%|0.2%|
[openbl_7d](#openbl_7d)|820|820|1|0.1%|0.2%|
[openbl_30d](#openbl_30d)|2935|2935|1|0.0%|0.2%|
[openbl_1d](#openbl_1d)|118|118|1|0.8%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.2%|
[fullbogons](#fullbogons)|3720|670264216|1|0.0%|0.2%|
[bruteforceblocker](#bruteforceblocker)|1703|1703|1|0.0%|0.2%|
[bogons](#bogons)|13|592708608|1|0.0%|0.2%|
[blocklist_de_ssh](#blocklist_de_ssh)|3512|3512|1|0.0%|0.2%|
[blocklist_de_imap](#blocklist_de_imap)|2731|2731|1|0.0%|0.2%|

## php_dictionary

[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) directory attackers (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=d&rss=1).

The last time downloaded was found to be dated: Mon Jun  8 12:36:21 UTC 2015.

The ipset `php_dictionary` has **630** entries, **630** unique IPs.

The following table shows the overlaps of `php_dictionary` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `php_dictionary`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `php_dictionary`.
- ` this % ` is the percentage **of this ipset (`php_dictionary`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level3](#firehol_level3)|107735|9625249|630|0.0%|100.0%|
[php_spammers](#php_spammers)|622|622|243|39.0%|38.5%|
[stopforumspam_30d](#stopforumspam_30d)|92247|92247|117|0.1%|18.5%|
[nixspam](#nixspam)|28061|28061|113|0.4%|17.9%|
[firehol_level2](#firehol_level2)|25736|37353|96|0.2%|15.2%|
[blocklist_de](#blocklist_de)|31859|31859|90|0.2%|14.2%|
[firehol_anonymous](#firehol_anonymous)|17882|81890|81|0.0%|12.8%|
[snort_ipfilter](#snort_ipfilter)|9492|9492|80|0.8%|12.6%|
[firehol_proxies](#firehol_proxies)|11383|11607|80|0.6%|12.6%|
[stopforumspam_7d](#stopforumspam_7d)|29278|29278|79|0.2%|12.5%|
[blocklist_de_mail](#blocklist_de_mail)|19169|19169|65|0.3%|10.3%|
[ri_web_proxies](#ri_web_proxies)|7066|7066|51|0.7%|8.0%|
[xroxy](#xroxy)|2124|2124|38|1.7%|6.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|33|0.0%|5.2%|
[stopforumspam_1d](#stopforumspam_1d)|6881|6881|29|0.4%|4.6%|
[php_commenters](#php_commenters)|373|373|26|6.9%|4.1%|
[blocklist_de_bots](#blocklist_de_bots)|3458|3458|23|0.6%|3.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|22|0.0%|3.4%|
[proxz](#proxz)|1047|1047|20|1.9%|3.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|11|0.0%|1.7%|
[alienvault_reputation](#alienvault_reputation)|181932|181932|8|0.0%|1.2%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|6|0.0%|0.9%|
[firehol_level1](#firehol_level1)|5088|688943411|6|0.0%|0.9%|
[et_block](#et_block)|1023|18338662|6|0.0%|0.9%|
[et_tor](#et_tor)|6470|6470|5|0.0%|0.7%|
[ri_connect_proxies](#ri_connect_proxies)|2581|2581|4|0.1%|0.6%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|4|1.0%|0.6%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|4|0.0%|0.6%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|5111|5111|4|0.0%|0.6%|
[blocklist_de_apache](#blocklist_de_apache)|16426|16426|4|0.0%|0.6%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|3|0.0%|0.4%|
[dm_tor](#dm_tor)|6482|6482|3|0.0%|0.4%|
[bm_tor](#bm_tor)|6465|6465|3|0.0%|0.4%|
[blocklist_de_strongips](#blocklist_de_strongips)|158|158|3|1.8%|0.4%|
[proxyrss](#proxyrss)|1481|1481|2|0.1%|0.3%|
[php_harvesters](#php_harvesters)|341|341|2|0.5%|0.3%|
[blocklist_de_imap](#blocklist_de_imap)|2731|2731|2|0.0%|0.3%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.1%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|1|0.1%|0.1%|

## php_harvesters

[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) harvesters (IPs that surf the internet looking for email addresses) (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=h&rss=1).

The last time downloaded was found to be dated: Mon Jun  8 12:36:19 UTC 2015.

The ipset `php_harvesters` has **341** entries, **341** unique IPs.

The following table shows the overlaps of `php_harvesters` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `php_harvesters`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `php_harvesters`.
- ` this % ` is the percentage **of this ipset (`php_harvesters`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level3](#firehol_level3)|107735|9625249|341|0.0%|100.0%|
[stopforumspam_30d](#stopforumspam_30d)|92247|92247|78|0.0%|22.8%|
[stopforumspam_7d](#stopforumspam_7d)|29278|29278|59|0.2%|17.3%|
[firehol_level2](#firehol_level2)|25736|37353|57|0.1%|16.7%|
[stopforumspam_1d](#stopforumspam_1d)|6881|6881|43|0.6%|12.6%|
[blocklist_de](#blocklist_de)|31859|31859|41|0.1%|12.0%|
[blocklist_de_bots](#blocklist_de_bots)|3458|3458|30|0.8%|8.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|18|0.0%|5.2%|
[php_commenters](#php_commenters)|373|373|15|4.0%|4.3%|
[firehol_anonymous](#firehol_anonymous)|17882|81890|13|0.0%|3.8%|
[snort_ipfilter](#snort_ipfilter)|9492|9492|12|0.1%|3.5%|
[firehol_proxies](#firehol_proxies)|11383|11607|12|0.1%|3.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|11|0.0%|3.2%|
[alienvault_reputation](#alienvault_reputation)|181932|181932|10|0.0%|2.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|9|0.0%|2.6%|
[et_tor](#et_tor)|6470|6470|7|0.1%|2.0%|
[dm_tor](#dm_tor)|6482|6482|7|0.1%|2.0%|
[bm_tor](#bm_tor)|6465|6465|7|0.1%|2.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|6|1.6%|1.7%|
[blocklist_de_ftp](#blocklist_de_ftp)|299|299|6|2.0%|1.7%|
[blocklist_de_mail](#blocklist_de_mail)|19169|19169|5|0.0%|1.4%|
[proxyrss](#proxyrss)|1481|1481|3|0.2%|0.8%|
[nixspam](#nixspam)|28061|28061|3|0.0%|0.8%|
[firehol_level1](#firehol_level1)|5088|688943411|3|0.0%|0.8%|
[xroxy](#xroxy)|2124|2124|2|0.0%|0.5%|
[ri_web_proxies](#ri_web_proxies)|7066|7066|2|0.0%|0.5%|
[php_spammers](#php_spammers)|622|622|2|0.3%|0.5%|
[php_dictionary](#php_dictionary)|630|630|2|0.3%|0.5%|
[openbl_60d](#openbl_60d)|7239|7239|2|0.0%|0.5%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|2|0.0%|0.5%|
[blocklist_de_strongips](#blocklist_de_strongips)|158|158|2|1.2%|0.5%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|1|0.0%|0.2%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|1|0.0%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.2%|
[fullbogons](#fullbogons)|3720|670264216|1|0.0%|0.2%|
[et_block](#et_block)|1023|18338662|1|0.0%|0.2%|
[bogons](#bogons)|13|592708608|1|0.0%|0.2%|
[blocklist_de_imap](#blocklist_de_imap)|2731|2731|1|0.0%|0.2%|
[blocklist_de_apache](#blocklist_de_apache)|16426|16426|1|0.0%|0.2%|

## php_spammers

[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) spam servers (IPs used by spammers to send messages) (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=s&rss=1).

The last time downloaded was found to be dated: Mon Jun  8 12:36:19 UTC 2015.

The ipset `php_spammers` has **622** entries, **622** unique IPs.

The following table shows the overlaps of `php_spammers` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `php_spammers`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `php_spammers`.
- ` this % ` is the percentage **of this ipset (`php_spammers`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level3](#firehol_level3)|107735|9625249|622|0.0%|100.0%|
[php_dictionary](#php_dictionary)|630|630|243|38.5%|39.0%|
[stopforumspam_30d](#stopforumspam_30d)|92247|92247|127|0.1%|20.4%|
[firehol_level2](#firehol_level2)|25736|37353|92|0.2%|14.7%|
[nixspam](#nixspam)|28061|28061|86|0.3%|13.8%|
[blocklist_de](#blocklist_de)|31859|31859|83|0.2%|13.3%|
[snort_ipfilter](#snort_ipfilter)|9492|9492|77|0.8%|12.3%|
[stopforumspam_7d](#stopforumspam_7d)|29278|29278|72|0.2%|11.5%|
[firehol_anonymous](#firehol_anonymous)|17882|81890|69|0.0%|11.0%|
[firehol_proxies](#firehol_proxies)|11383|11607|67|0.5%|10.7%|
[blocklist_de_mail](#blocklist_de_mail)|19169|19169|55|0.2%|8.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|51|0.0%|8.1%|
[ri_web_proxies](#ri_web_proxies)|7066|7066|45|0.6%|7.2%|
[php_commenters](#php_commenters)|373|373|42|11.2%|6.7%|
[stopforumspam_1d](#stopforumspam_1d)|6881|6881|38|0.5%|6.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|37|0.0%|5.9%|
[xroxy](#xroxy)|2124|2124|30|1.4%|4.8%|
[blocklist_de_bots](#blocklist_de_bots)|3458|3458|23|0.6%|3.6%|
[proxz](#proxz)|1047|1047|20|1.9%|3.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|9|0.0%|1.4%|
[et_tor](#et_tor)|6470|6470|6|0.0%|0.9%|
[blocklist_de_strongips](#blocklist_de_strongips)|158|158|5|3.1%|0.8%|
[alienvault_reputation](#alienvault_reputation)|181932|181932|5|0.0%|0.8%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|4|0.0%|0.6%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|4|1.0%|0.6%|
[firehol_level1](#firehol_level1)|5088|688943411|4|0.0%|0.6%|
[dm_tor](#dm_tor)|6482|6482|4|0.0%|0.6%|
[bm_tor](#bm_tor)|6465|6465|4|0.0%|0.6%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|5111|5111|4|0.0%|0.6%|
[blocklist_de_apache](#blocklist_de_apache)|16426|16426|4|0.0%|0.6%|
[ri_connect_proxies](#ri_connect_proxies)|2581|2581|3|0.1%|0.4%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|0.4%|
[et_block](#et_block)|1023|18338662|3|0.0%|0.4%|
[proxyrss](#proxyrss)|1481|1481|2|0.1%|0.3%|
[php_harvesters](#php_harvesters)|341|341|2|0.5%|0.3%|
[openbl_7d](#openbl_7d)|820|820|1|0.1%|0.1%|
[openbl_60d](#openbl_60d)|7239|7239|1|0.0%|0.1%|
[openbl_30d](#openbl_30d)|2935|2935|1|0.0%|0.1%|
[openbl_1d](#openbl_1d)|118|118|1|0.8%|0.1%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|1|0.0%|0.1%|
[bruteforceblocker](#bruteforceblocker)|1703|1703|1|0.0%|0.1%|
[blocklist_de_ssh](#blocklist_de_ssh)|3512|3512|1|0.0%|0.1%|
[blocklist_de_imap](#blocklist_de_imap)|2731|2731|1|0.0%|0.1%|

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
[firehol_proxies](#firehol_proxies)|11383|11607|1481|12.7%|100.0%|
[firehol_anonymous](#firehol_anonymous)|17882|81890|1481|1.8%|100.0%|
[firehol_level3](#firehol_level3)|107735|9625249|724|0.0%|48.8%|
[stopforumspam_30d](#stopforumspam_30d)|92247|92247|723|0.7%|48.8%|
[ri_web_proxies](#ri_web_proxies)|7066|7066|613|8.6%|41.3%|
[stopforumspam_7d](#stopforumspam_7d)|29278|29278|559|1.9%|37.7%|
[firehol_level2](#firehol_level2)|25736|37353|414|1.1%|27.9%|
[xroxy](#xroxy)|2124|2124|373|17.5%|25.1%|
[stopforumspam_1d](#stopforumspam_1d)|6881|6881|345|5.0%|23.2%|
[proxz](#proxz)|1047|1047|246|23.4%|16.6%|
[ri_connect_proxies](#ri_connect_proxies)|2581|2581|235|9.1%|15.8%|
[blocklist_de](#blocklist_de)|31859|31859|218|0.6%|14.7%|
[blocklist_de_bots](#blocklist_de_bots)|3458|3458|217|6.2%|14.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|54|0.0%|3.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|51|0.0%|3.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|36|0.0%|2.4%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|6|0.9%|0.4%|
[nixspam](#nixspam)|28061|28061|5|0.0%|0.3%|
[php_commenters](#php_commenters)|373|373|4|1.0%|0.2%|
[blocklist_de_strongips](#blocklist_de_strongips)|158|158|4|2.5%|0.2%|
[php_harvesters](#php_harvesters)|341|341|3|0.8%|0.2%|
[php_spammers](#php_spammers)|622|622|2|0.3%|0.1%|
[php_dictionary](#php_dictionary)|630|630|2|0.3%|0.1%|
[snort_ipfilter](#snort_ipfilter)|9492|9492|1|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|19169|19169|1|0.0%|0.0%|

## proxz

[proxz.com](http://www.proxz.com) open proxies (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.proxz.com/proxylists.xml).

The last time downloaded was found to be dated: Mon Jun  8 11:21:28 UTC 2015.

The ipset `proxz` has **1047** entries, **1047** unique IPs.

The following table shows the overlaps of `proxz` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `proxz`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `proxz`.
- ` this % ` is the percentage **of this ipset (`proxz`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_proxies](#firehol_proxies)|11383|11607|1047|9.0%|100.0%|
[firehol_anonymous](#firehol_anonymous)|17882|81890|1047|1.2%|100.0%|
[firehol_level3](#firehol_level3)|107735|9625249|637|0.0%|60.8%|
[stopforumspam_30d](#stopforumspam_30d)|92247|92247|631|0.6%|60.2%|
[ri_web_proxies](#ri_web_proxies)|7066|7066|479|6.7%|45.7%|
[stopforumspam_7d](#stopforumspam_7d)|29278|29278|456|1.5%|43.5%|
[xroxy](#xroxy)|2124|2124|384|18.0%|36.6%|
[firehol_level2](#firehol_level2)|25736|37353|252|0.6%|24.0%|
[proxyrss](#proxyrss)|1481|1481|246|16.6%|23.4%|
[stopforumspam_1d](#stopforumspam_1d)|6881|6881|188|2.7%|17.9%|
[ri_connect_proxies](#ri_connect_proxies)|2581|2581|178|6.8%|17.0%|
[blocklist_de](#blocklist_de)|31859|31859|156|0.4%|14.8%|
[blocklist_de_bots](#blocklist_de_bots)|3458|3458|137|3.9%|13.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|87|0.0%|8.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|42|0.0%|4.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|37|0.0%|3.5%|
[nixspam](#nixspam)|28061|28061|31|0.1%|2.9%|
[snort_ipfilter](#snort_ipfilter)|9492|9492|22|0.2%|2.1%|
[php_spammers](#php_spammers)|622|622|20|3.2%|1.9%|
[php_dictionary](#php_dictionary)|630|630|20|3.1%|1.9%|
[blocklist_de_mail](#blocklist_de_mail)|19169|19169|19|0.0%|1.8%|
[php_commenters](#php_commenters)|373|373|7|1.8%|0.6%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|6|0.9%|0.5%|
[blocklist_de_strongips](#blocklist_de_strongips)|158|158|3|1.8%|0.2%|
[alienvault_reputation](#alienvault_reputation)|181932|181932|3|0.0%|0.2%|
[et_compromised](#et_compromised)|2016|2016|2|0.0%|0.1%|
[bruteforceblocker](#bruteforceblocker)|1703|1703|2|0.1%|0.1%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|1|0.0%|0.0%|
[firehol_level1](#firehol_level1)|5088|688943411|1|0.0%|0.0%|
[dshield](#dshield)|20|5120|1|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|5111|5111|1|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|16426|16426|1|0.0%|0.0%|

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
[firehol_proxies](#firehol_proxies)|11383|11607|2581|22.2%|100.0%|
[firehol_anonymous](#firehol_anonymous)|17882|81890|2581|3.1%|100.0%|
[stopforumspam_30d](#stopforumspam_30d)|92247|92247|1474|1.5%|57.1%|
[firehol_level3](#firehol_level3)|107735|9625249|1474|0.0%|57.1%|
[ri_web_proxies](#ri_web_proxies)|7066|7066|1093|15.4%|42.3%|
[stopforumspam_7d](#stopforumspam_7d)|29278|29278|624|2.1%|24.1%|
[xroxy](#xroxy)|2124|2124|378|17.7%|14.6%|
[proxyrss](#proxyrss)|1481|1481|235|15.8%|9.1%|
[firehol_level2](#firehol_level2)|25736|37353|203|0.5%|7.8%|
[proxz](#proxz)|1047|1047|178|17.0%|6.8%|
[stopforumspam_1d](#stopforumspam_1d)|6881|6881|165|2.3%|6.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|99|0.0%|3.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|79|0.0%|3.0%|
[blocklist_de](#blocklist_de)|31859|31859|71|0.2%|2.7%|
[blocklist_de_bots](#blocklist_de_bots)|3458|3458|67|1.9%|2.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|54|0.0%|2.0%|
[nixspam](#nixspam)|28061|28061|8|0.0%|0.3%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|7|1.0%|0.2%|
[php_commenters](#php_commenters)|373|373|5|1.3%|0.1%|
[snort_ipfilter](#snort_ipfilter)|9492|9492|4|0.0%|0.1%|
[php_dictionary](#php_dictionary)|630|630|4|0.6%|0.1%|
[php_spammers](#php_spammers)|622|622|3|0.4%|0.1%|
[blocklist_de_mail](#blocklist_de_mail)|19169|19169|3|0.0%|0.1%|
[alienvault_reputation](#alienvault_reputation)|181932|181932|3|0.0%|0.1%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.0%|
[et_tor](#et_tor)|6470|6470|1|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|5111|5111|1|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|16426|16426|1|0.0%|0.0%|

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
[firehol_proxies](#firehol_proxies)|11383|11607|7066|60.8%|100.0%|
[firehol_anonymous](#firehol_anonymous)|17882|81890|7066|8.6%|100.0%|
[firehol_level3](#firehol_level3)|107735|9625249|3412|0.0%|48.2%|
[stopforumspam_30d](#stopforumspam_30d)|92247|92247|3371|3.6%|47.7%|
[stopforumspam_7d](#stopforumspam_7d)|29278|29278|1589|5.4%|22.4%|
[ri_connect_proxies](#ri_connect_proxies)|2581|2581|1093|42.3%|15.4%|
[xroxy](#xroxy)|2124|2124|921|43.3%|13.0%|
[firehol_level2](#firehol_level2)|25736|37353|716|1.9%|10.1%|
[proxyrss](#proxyrss)|1481|1481|613|41.3%|8.6%|
[stopforumspam_1d](#stopforumspam_1d)|6881|6881|526|7.6%|7.4%|
[proxz](#proxz)|1047|1047|479|45.7%|6.7%|
[blocklist_de](#blocklist_de)|31859|31859|402|1.2%|5.6%|
[blocklist_de_bots](#blocklist_de_bots)|3458|3458|341|9.8%|4.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|205|0.0%|2.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|199|0.0%|2.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|137|0.0%|1.9%|
[nixspam](#nixspam)|28061|28061|64|0.2%|0.9%|
[blocklist_de_mail](#blocklist_de_mail)|19169|19169|60|0.3%|0.8%|
[snort_ipfilter](#snort_ipfilter)|9492|9492|56|0.5%|0.7%|
[php_dictionary](#php_dictionary)|630|630|51|8.0%|0.7%|
[php_spammers](#php_spammers)|622|622|45|7.2%|0.6%|
[php_commenters](#php_commenters)|373|373|23|6.1%|0.3%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|13|1.9%|0.1%|
[blocklist_de_imap](#blocklist_de_imap)|2731|2731|9|0.3%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|5|0.0%|0.0%|
[et_tor](#et_tor)|6470|6470|5|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|4|1.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|3|0.0%|0.0%|
[dm_tor](#dm_tor)|6482|6482|3|0.0%|0.0%|
[bm_tor](#bm_tor)|6465|6465|3|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|158|158|3|1.8%|0.0%|
[alienvault_reputation](#alienvault_reputation)|181932|181932|3|0.0%|0.0%|
[php_harvesters](#php_harvesters)|341|341|2|0.5%|0.0%|
[firehol_level1](#firehol_level1)|5088|688943411|2|0.0%|0.0%|
[sslbl](#sslbl)|379|379|1|0.2%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|1|0.0%|0.0%|
[et_compromised](#et_compromised)|2016|2016|1|0.0%|0.0%|
[dshield](#dshield)|20|5120|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1703|1703|1|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|5111|5111|1|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|16426|16426|1|0.0%|0.0%|

## shunlist

[AutoShun.org](http://autoshun.org/) IPs identified as hostile by correlating logs from distributed snort installations running the autoshun plugin

Source is downloaded from [this link](http://www.autoshun.org/files/shunlist.csv).

The last time downloaded was found to be dated: Mon Jun  8 11:30:05 UTC 2015.

The ipset `shunlist` has **1241** entries, **1241** unique IPs.

The following table shows the overlaps of `shunlist` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `shunlist`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `shunlist`.
- ` this % ` is the percentage **of this ipset (`shunlist`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level3](#firehol_level3)|107735|9625249|1241|0.0%|100.0%|
[alienvault_reputation](#alienvault_reputation)|181932|181932|1229|0.6%|99.0%|
[openbl_60d](#openbl_60d)|7239|7239|542|7.4%|43.6%|
[openbl_30d](#openbl_30d)|2935|2935|520|17.7%|41.9%|
[et_compromised](#et_compromised)|2016|2016|432|21.4%|34.8%|
[firehol_level2](#firehol_level2)|25736|37353|429|1.1%|34.5%|
[blocklist_de](#blocklist_de)|31859|31859|425|1.3%|34.2%|
[bruteforceblocker](#bruteforceblocker)|1703|1703|415|24.3%|33.4%|
[blocklist_de_ssh](#blocklist_de_ssh)|3512|3512|392|11.1%|31.5%|
[openbl_7d](#openbl_7d)|820|820|216|26.3%|17.4%|
[firehol_level1](#firehol_level1)|5088|688943411|198|0.0%|15.9%|
[dshield](#dshield)|20|5120|138|2.6%|11.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|113|0.0%|9.1%|
[et_block](#et_block)|1023|18338662|108|0.0%|8.7%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|93|0.0%|7.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|65|0.0%|5.2%|
[sslbl](#sslbl)|379|379|58|15.3%|4.6%|
[openbl_1d](#openbl_1d)|118|118|50|42.3%|4.0%|
[ciarmy](#ciarmy)|422|422|33|7.8%|2.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|28|0.0%|2.2%|
[blocklist_de_apache](#blocklist_de_apache)|16426|16426|26|0.1%|2.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|158|158|21|13.2%|1.6%|
[voipbl](#voipbl)|10491|10902|12|0.1%|0.9%|
[stopforumspam_30d](#stopforumspam_30d)|92247|92247|4|0.0%|0.3%|
[blocklist_de_mail](#blocklist_de_mail)|19169|19169|4|0.0%|0.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|0.2%|
[snort_ipfilter](#snort_ipfilter)|9492|9492|2|0.0%|0.1%|
[stopforumspam_7d](#stopforumspam_7d)|29278|29278|1|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6881|6881|1|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.0%|
[firehol_proxies](#firehol_proxies)|11383|11607|1|0.0%|0.0%|
[firehol_anonymous](#firehol_anonymous)|17882|81890|1|0.0%|0.0%|
[et_tor](#et_tor)|6470|6470|1|0.0%|0.0%|
[dm_tor](#dm_tor)|6482|6482|1|0.0%|0.0%|
[bm_tor](#bm_tor)|6465|6465|1|0.0%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|86|86|1|1.1%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2731|2731|1|0.0%|0.0%|

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
[firehol_level3](#firehol_level3)|107735|9625249|9492|0.0%|100.0%|
[firehol_anonymous](#firehol_anonymous)|17882|81890|1141|1.3%|12.0%|
[et_tor](#et_tor)|6470|6470|1059|16.3%|11.1%|
[bm_tor](#bm_tor)|6465|6465|1050|16.2%|11.0%|
[dm_tor](#dm_tor)|6482|6482|1045|16.1%|11.0%|
[stopforumspam_30d](#stopforumspam_30d)|92247|92247|796|0.8%|8.3%|
[stopforumspam_7d](#stopforumspam_7d)|29278|29278|632|2.1%|6.6%|
[firehol_level2](#firehol_level2)|25736|37353|576|1.5%|6.0%|
[nixspam](#nixspam)|28061|28061|473|1.6%|4.9%|
[stopforumspam_1d](#stopforumspam_1d)|6881|6881|392|5.6%|4.1%|
[et_block](#et_block)|1023|18338662|315|0.0%|3.3%|
[firehol_level1](#firehol_level1)|5088|688943411|301|0.0%|3.1%|
[firehol_proxies](#firehol_proxies)|11383|11607|252|2.1%|2.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|230|0.0%|2.4%|
[blocklist_de](#blocklist_de)|31859|31859|210|0.6%|2.2%|
[zeus](#zeus)|234|234|203|86.7%|2.1%|
[blocklist_de_mail](#blocklist_de_mail)|19169|19169|181|0.9%|1.9%|
[zeus_badips](#zeus_badips)|203|203|179|88.1%|1.8%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|174|46.7%|1.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|122|0.0%|1.2%|
[alienvault_reputation](#alienvault_reputation)|181932|181932|116|0.0%|1.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|87|0.0%|0.9%|
[php_dictionary](#php_dictionary)|630|630|80|12.6%|0.8%|
[feodo](#feodo)|100|100|79|79.0%|0.8%|
[php_spammers](#php_spammers)|622|622|77|12.3%|0.8%|
[ri_web_proxies](#ri_web_proxies)|7066|7066|56|0.7%|0.5%|
[php_commenters](#php_commenters)|373|373|50|13.4%|0.5%|
[xroxy](#xroxy)|2124|2124|34|1.6%|0.3%|
[sslbl](#sslbl)|379|379|31|8.1%|0.3%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|28|2.1%|0.2%|
[openbl_60d](#openbl_60d)|7239|7239|24|0.3%|0.2%|
[blocklist_de_bots](#blocklist_de_bots)|3458|3458|24|0.6%|0.2%|
[proxz](#proxz)|1047|1047|22|2.1%|0.2%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|20|0.0%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|15|0.0%|0.1%|
[php_harvesters](#php_harvesters)|341|341|12|3.5%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|12|0.0%|0.1%|
[palevo](#palevo)|13|13|11|84.6%|0.1%|
[blocklist_de_apache](#blocklist_de_apache)|16426|16426|9|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|6|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2731|2731|6|0.2%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|5111|5111|5|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2581|2581|4|0.1%|0.0%|
[openbl_30d](#openbl_30d)|2935|2935|3|0.1%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|3|0.0%|0.0%|
[shunlist](#shunlist)|1241|1241|2|0.1%|0.0%|
[proxyrss](#proxyrss)|1481|1481|1|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|1|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|1|0.1%|0.0%|
[dshield](#dshield)|20|5120|1|0.0%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|319|319|1|0.3%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|158|158|1|0.6%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3512|3512|1|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|299|299|1|0.3%|0.0%|

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
[firehol_level1](#firehol_level1)|5088|688943411|18338560|2.6%|100.0%|
[et_block](#et_block)|1023|18338662|18054912|98.4%|98.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|8532506|2.4%|46.5%|
[firehol_level3](#firehol_level3)|107735|9625249|6933023|72.0%|37.8%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|6932480|75.5%|37.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|2272265|0.2%|12.3%|
[fullbogons](#fullbogons)|3720|670264216|151552|0.0%|0.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|130368|0.0%|0.7%|
[alienvault_reputation](#alienvault_reputation)|181932|181932|1374|0.7%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1037|0.3%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92247|92247|1017|1.1%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|512|0.1%|0.0%|
[dshield](#dshield)|20|5120|512|10.0%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29278|29278|311|1.0%|0.0%|
[firehol_level2](#firehol_level2)|25736|37353|242|0.6%|0.0%|
[openbl_60d](#openbl_60d)|7239|7239|239|3.3%|0.0%|
[blocklist_de](#blocklist_de)|31859|31859|175|0.5%|0.0%|
[openbl_30d](#openbl_30d)|2935|2935|121|4.1%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3512|3512|107|3.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1703|1703|101|5.9%|0.0%|
[et_compromised](#et_compromised)|2016|2016|100|4.9%|0.0%|
[shunlist](#shunlist)|1241|1241|93|7.4%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6881|6881|87|1.2%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3458|3458|43|1.2%|0.0%|
[openbl_7d](#openbl_7d)|820|820|42|5.1%|0.0%|
[php_commenters](#php_commenters)|373|373|29|7.7%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|29|2.2%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|19169|19169|21|0.1%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9492|9492|20|0.2%|0.0%|
[zeus_badips](#zeus_badips)|203|203|16|7.8%|0.0%|
[zeus](#zeus)|234|234|16|6.8%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2731|2731|15|0.5%|0.0%|
[voipbl](#voipbl)|10491|10902|14|0.1%|0.0%|
[openbl_1d](#openbl_1d)|118|118|7|5.9%|0.0%|
[php_dictionary](#php_dictionary)|630|630|6|0.9%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|6|0.4%|0.0%|
[firehol_anonymous](#firehol_anonymous)|17882|81890|6|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|5|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|158|158|5|3.1%|0.0%|
[php_spammers](#php_spammers)|622|622|4|0.6%|0.0%|
[malc0de](#malc0de)|351|351|4|1.1%|0.0%|
[nixspam](#nixspam)|28061|28061|3|0.0%|0.0%|
[dm_tor](#dm_tor)|6482|6482|3|0.0%|0.0%|
[bm_tor](#bm_tor)|6465|6465|3|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|5111|5111|3|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|16426|16426|3|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|2|0.3%|0.0%|
[firehol_proxies](#firehol_proxies)|11383|11607|2|0.0%|0.0%|
[et_tor](#et_tor)|6470|6470|2|0.0%|0.0%|
[sslbl](#sslbl)|379|379|1|0.2%|0.0%|
[php_harvesters](#php_harvesters)|341|341|1|0.2%|0.0%|
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
[firehol_level1](#firehol_level1)|5088|688943411|487424|0.0%|100.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|270785|0.1%|55.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|98904|0.0%|20.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|33155|0.0%|6.8%|
[et_block](#et_block)|1023|18338662|517|0.0%|0.1%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|512|0.0%|0.1%|
[firehol_level3](#firehol_level3)|107735|9625249|90|0.0%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92247|92247|79|0.0%|0.0%|
[alienvault_reputation](#alienvault_reputation)|181932|181932|15|0.0%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29278|29278|10|0.0%|0.0%|
[php_commenters](#php_commenters)|373|373|7|1.8%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9492|9492|6|0.0%|0.0%|
[firehol_level2](#firehol_level2)|25736|37353|6|0.0%|0.0%|
[zeus_badips](#zeus_badips)|203|203|5|2.4%|0.0%|
[zeus](#zeus)|234|234|5|2.1%|0.0%|
[blocklist_de](#blocklist_de)|31859|31859|4|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6881|6881|2|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|158|158|2|1.2%|0.0%|
[virbl](#virbl)|8|8|1|12.5%|0.0%|
[php_harvesters](#php_harvesters)|341|341|1|0.2%|0.0%|
[openbl_60d](#openbl_60d)|7239|7239|1|0.0%|0.0%|
[openbl_30d](#openbl_30d)|2935|2935|1|0.0%|0.0%|
[nixspam](#nixspam)|28061|28061|1|0.0%|0.0%|
[malc0de](#malc0de)|351|351|1|0.2%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|319|319|1|0.3%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3512|3512|1|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|19169|19169|1|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3458|3458|1|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|16426|16426|1|0.0%|0.0%|

## sslbl

[Abuse.ch SSL Blacklist](https://sslbl.abuse.ch/) bad SSL traffic related to malware or botnet activities - **excellent list**

Source is downloaded from [this link](https://sslbl.abuse.ch/blacklist/sslipblacklist.csv).

The last time downloaded was found to be dated: Mon Jun  8 12:30:06 UTC 2015.

The ipset `sslbl` has **379** entries, **379** unique IPs.

The following table shows the overlaps of `sslbl` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `sslbl`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `sslbl`.
- ` this % ` is the percentage **of this ipset (`sslbl`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level1](#firehol_level1)|5088|688943411|379|0.0%|100.0%|
[firehol_level3](#firehol_level3)|107735|9625249|89|0.0%|23.4%|
[alienvault_reputation](#alienvault_reputation)|181932|181932|64|0.0%|16.8%|
[shunlist](#shunlist)|1241|1241|58|4.6%|15.3%|
[feodo](#feodo)|100|100|37|37.0%|9.7%|
[et_block](#et_block)|1023|18338662|35|0.0%|9.2%|
[snort_ipfilter](#snort_ipfilter)|9492|9492|31|0.3%|8.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|29|0.0%|7.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|4|0.0%|1.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|3|0.0%|0.7%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|1|0.0%|0.2%|
[ri_web_proxies](#ri_web_proxies)|7066|7066|1|0.0%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.2%|
[firehol_proxies](#firehol_proxies)|11383|11607|1|0.0%|0.2%|
[firehol_level2](#firehol_level2)|25736|37353|1|0.0%|0.2%|
[firehol_anonymous](#firehol_anonymous)|17882|81890|1|0.0%|0.2%|
[blocklist_de_ssh](#blocklist_de_ssh)|3512|3512|1|0.0%|0.2%|
[blocklist_de](#blocklist_de)|31859|31859|1|0.0%|0.2%|

## stopforumspam_1d

[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers in the last 24 hours - **excellent list**

Source is downloaded from [this link](http://www.stopforumspam.com/downloads/listed_ip_1.zip).

The last time downloaded was found to be dated: Mon Jun  8 12:00:02 UTC 2015.

The ipset `stopforumspam_1d` has **6881** entries, **6881** unique IPs.

The following table shows the overlaps of `stopforumspam_1d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `stopforumspam_1d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `stopforumspam_1d`.
- ` this % ` is the percentage **of this ipset (`stopforumspam_1d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|25736|37353|6881|18.4%|100.0%|
[firehol_level3](#firehol_level3)|107735|9625249|5571|0.0%|80.9%|
[stopforumspam_30d](#stopforumspam_30d)|92247|92247|5554|6.0%|80.7%|
[stopforumspam_7d](#stopforumspam_7d)|29278|29278|5310|18.1%|77.1%|
[blocklist_de](#blocklist_de)|31859|31859|1418|4.4%|20.6%|
[blocklist_de_bots](#blocklist_de_bots)|3458|3458|1369|39.5%|19.8%|
[firehol_anonymous](#firehol_anonymous)|17882|81890|1076|1.3%|15.6%|
[firehol_proxies](#firehol_proxies)|11383|11607|872|7.5%|12.6%|
[ri_web_proxies](#ri_web_proxies)|7066|7066|526|7.4%|7.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|510|0.0%|7.4%|
[snort_ipfilter](#snort_ipfilter)|9492|9492|392|4.1%|5.6%|
[bm_tor](#bm_tor)|6465|6465|354|5.4%|5.1%|
[dm_tor](#dm_tor)|6482|6482|352|5.4%|5.1%|
[et_tor](#et_tor)|6470|6470|348|5.3%|5.0%|
[proxyrss](#proxyrss)|1481|1481|345|23.2%|5.0%|
[xroxy](#xroxy)|2124|2124|283|13.3%|4.1%|
[proxz](#proxz)|1047|1047|188|17.9%|2.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|187|0.0%|2.7%|
[ri_connect_proxies](#ri_connect_proxies)|2581|2581|165|6.3%|2.3%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|160|43.0%|2.3%|
[php_commenters](#php_commenters)|373|373|150|40.2%|2.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|121|0.0%|1.7%|
[blocklist_de_strongips](#blocklist_de_strongips)|158|158|99|62.6%|1.4%|
[firehol_level1](#firehol_level1)|5088|688943411|89|0.0%|1.2%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|87|0.0%|1.2%|
[et_block](#et_block)|1023|18338662|80|0.0%|1.1%|
[alienvault_reputation](#alienvault_reputation)|181932|181932|53|0.0%|0.7%|
[blocklist_de_mail](#blocklist_de_mail)|19169|19169|50|0.2%|0.7%|
[blocklist_de_apache](#blocklist_de_apache)|16426|16426|49|0.2%|0.7%|
[php_harvesters](#php_harvesters)|341|341|43|12.6%|0.6%|
[nixspam](#nixspam)|28061|28061|42|0.1%|0.6%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|41|0.0%|0.5%|
[php_spammers](#php_spammers)|622|622|38|6.1%|0.5%|
[php_dictionary](#php_dictionary)|630|630|29|4.6%|0.4%|
[openbl_60d](#openbl_60d)|7239|7239|20|0.2%|0.2%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|5111|5111|14|0.2%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|9|0.0%|0.1%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|6|0.9%|0.0%|
[voipbl](#voipbl)|10491|10902|3|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|2|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|299|299|2|0.6%|0.0%|
[zeus_badips](#zeus_badips)|203|203|1|0.4%|0.0%|
[zeus](#zeus)|234|234|1|0.4%|0.0%|
[shunlist](#shunlist)|1241|1241|1|0.0%|0.0%|
[openbl_30d](#openbl_30d)|2935|2935|1|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|1|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1703|1703|1|0.0%|0.0%|

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
[firehol_level3](#firehol_level3)|107735|9625249|92247|0.9%|100.0%|
[stopforumspam_7d](#stopforumspam_7d)|29278|29278|29202|99.7%|31.6%|
[firehol_level2](#firehol_level2)|25736|37353|6791|18.1%|7.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|5743|0.0%|6.2%|
[firehol_anonymous](#firehol_anonymous)|17882|81890|5742|7.0%|6.2%|
[stopforumspam_1d](#stopforumspam_1d)|6881|6881|5554|80.7%|6.0%|
[firehol_proxies](#firehol_proxies)|11383|11607|5100|43.9%|5.5%|
[ri_web_proxies](#ri_web_proxies)|7066|7066|3371|47.7%|3.6%|
[blocklist_de](#blocklist_de)|31859|31859|2512|7.8%|2.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|2489|0.0%|2.6%|
[blocklist_de_bots](#blocklist_de_bots)|3458|3458|2202|63.6%|2.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|1511|0.0%|1.6%|
[ri_connect_proxies](#ri_connect_proxies)|2581|2581|1474|57.1%|1.5%|
[xroxy](#xroxy)|2124|2124|1256|59.1%|1.3%|
[firehol_level1](#firehol_level1)|5088|688943411|1099|0.0%|1.1%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|1017|0.0%|1.1%|
[et_block](#et_block)|1023|18338662|1008|0.0%|1.0%|
[snort_ipfilter](#snort_ipfilter)|9492|9492|796|8.3%|0.8%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|732|0.0%|0.7%|
[proxyrss](#proxyrss)|1481|1481|723|48.8%|0.7%|
[et_tor](#et_tor)|6470|6470|660|10.2%|0.7%|
[bm_tor](#bm_tor)|6465|6465|638|9.8%|0.6%|
[dm_tor](#dm_tor)|6482|6482|635|9.7%|0.6%|
[proxz](#proxz)|1047|1047|631|60.2%|0.6%|
[php_commenters](#php_commenters)|373|373|277|74.2%|0.3%|
[blocklist_de_mail](#blocklist_de_mail)|19169|19169|243|1.2%|0.2%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|232|62.3%|0.2%|
[blocklist_de_apache](#blocklist_de_apache)|16426|16426|198|1.2%|0.2%|
[alienvault_reputation](#alienvault_reputation)|181932|181932|198|0.1%|0.2%|
[nixspam](#nixspam)|28061|28061|148|0.5%|0.1%|
[php_spammers](#php_spammers)|622|622|127|20.4%|0.1%|
[php_dictionary](#php_dictionary)|630|630|117|18.5%|0.1%|
[blocklist_de_strongips](#blocklist_de_strongips)|158|158|114|72.1%|0.1%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|79|0.0%|0.0%|
[php_harvesters](#php_harvesters)|341|341|78|22.8%|0.0%|
[openbl_60d](#openbl_60d)|7239|7239|54|0.7%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|5111|5111|49|0.9%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|46|0.0%|0.0%|
[voipbl](#voipbl)|10491|10902|37|0.3%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|20|3.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3512|3512|19|0.5%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|15|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1703|1703|13|0.7%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2731|2731|13|0.4%|0.0%|
[et_compromised](#et_compromised)|2016|2016|11|0.5%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|299|299|6|2.0%|0.0%|
[shunlist](#shunlist)|1241|1241|4|0.3%|0.0%|
[openbl_30d](#openbl_30d)|2935|2935|4|0.1%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|4|0.3%|0.0%|
[openbl_7d](#openbl_7d)|820|820|3|0.3%|0.0%|
[zeus_badips](#zeus_badips)|203|203|2|0.9%|0.0%|
[zeus](#zeus)|234|234|2|0.8%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|2|0.1%|0.0%|
[fullbogons](#fullbogons)|3720|670264216|2|0.0%|0.0%|
[openbl_1d](#openbl_1d)|118|118|1|0.8%|0.0%|
[dshield](#dshield)|20|5120|1|0.0%|0.0%|
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
[firehol_level3](#firehol_level3)|107735|9625249|29205|0.3%|99.7%|
[stopforumspam_30d](#stopforumspam_30d)|92247|92247|29202|31.6%|99.7%|
[firehol_level2](#firehol_level2)|25736|37353|6186|16.5%|21.1%|
[stopforumspam_1d](#stopforumspam_1d)|6881|6881|5310|77.1%|18.1%|
[firehol_anonymous](#firehol_anonymous)|17882|81890|2814|3.4%|9.6%|
[firehol_proxies](#firehol_proxies)|11383|11607|2419|20.8%|8.2%|
[blocklist_de](#blocklist_de)|31859|31859|2125|6.6%|7.2%|
[blocklist_de_bots](#blocklist_de_bots)|3458|3458|1963|56.7%|6.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|1899|0.0%|6.4%|
[ri_web_proxies](#ri_web_proxies)|7066|7066|1589|22.4%|5.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|853|0.0%|2.9%|
[xroxy](#xroxy)|2124|2124|667|31.4%|2.2%|
[snort_ipfilter](#snort_ipfilter)|9492|9492|632|6.6%|2.1%|
[ri_connect_proxies](#ri_connect_proxies)|2581|2581|624|24.1%|2.1%|
[proxyrss](#proxyrss)|1481|1481|559|37.7%|1.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|558|0.0%|1.9%|
[et_tor](#et_tor)|6470|6470|530|8.1%|1.8%|
[bm_tor](#bm_tor)|6465|6465|511|7.9%|1.7%|
[dm_tor](#dm_tor)|6482|6482|510|7.8%|1.7%|
[proxz](#proxz)|1047|1047|456|43.5%|1.5%|
[firehol_level1](#firehol_level1)|5088|688943411|321|0.0%|1.0%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|311|0.0%|1.0%|
[et_block](#et_block)|1023|18338662|304|0.0%|1.0%|
[php_commenters](#php_commenters)|373|373|206|55.2%|0.7%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|190|51.0%|0.6%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|158|0.0%|0.5%|
[blocklist_de_mail](#blocklist_de_mail)|19169|19169|137|0.7%|0.4%|
[blocklist_de_apache](#blocklist_de_apache)|16426|16426|115|0.7%|0.3%|
[blocklist_de_strongips](#blocklist_de_strongips)|158|158|105|66.4%|0.3%|
[alienvault_reputation](#alienvault_reputation)|181932|181932|95|0.0%|0.3%|
[nixspam](#nixspam)|28061|28061|91|0.3%|0.3%|
[php_dictionary](#php_dictionary)|630|630|79|12.5%|0.2%|
[php_spammers](#php_spammers)|622|622|72|11.5%|0.2%|
[php_harvesters](#php_harvesters)|341|341|59|17.3%|0.2%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|5111|5111|31|0.6%|0.1%|
[openbl_60d](#openbl_60d)|7239|7239|24|0.3%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|22|0.0%|0.0%|
[voipbl](#voipbl)|10491|10902|15|0.1%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|13|1.9%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|10|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|6|0.0%|0.0%|
[et_compromised](#et_compromised)|2016|2016|6|0.2%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1703|1703|6|0.3%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2731|2731|6|0.2%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3512|3512|3|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|2|0.1%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|299|299|2|0.6%|0.0%|
[zeus_badips](#zeus_badips)|203|203|1|0.4%|0.0%|
[zeus](#zeus)|234|234|1|0.4%|0.0%|
[shunlist](#shunlist)|1241|1241|1|0.0%|0.0%|
[openbl_30d](#openbl_30d)|2935|2935|1|0.0%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|1|0.0%|0.0%|
[ciarmy](#ciarmy)|422|422|1|0.2%|0.0%|

## virbl

[VirBL](http://virbl.bit.nl/) is a project of which the idea was born during the RIPE-48 meeting. The plan was to get reports of virusscanning mailservers, and put the IP-addresses that were reported to send viruses on a blacklist.

Source is downloaded from [this link](http://virbl.bit.nl/download/virbl.dnsbl.bit.nl.txt).

The last time downloaded was found to be dated: Mon Jun  8 12:07:02 UTC 2015.

The ipset `virbl` has **8** entries, **8** unique IPs.

The following table shows the overlaps of `virbl` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `virbl`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `virbl`.
- ` this % ` is the percentage **of this ipset (`virbl`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level3](#firehol_level3)|107735|9625249|8|0.0%|100.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|1|0.0%|12.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|1|0.0%|12.5%|
[firehol_level1](#firehol_level1)|5088|688943411|1|0.0%|12.5%|

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
[firehol_level1](#firehol_level1)|5088|688943411|333|0.0%|3.0%|
[fullbogons](#fullbogons)|3720|670264216|319|0.0%|2.9%|
[bogons](#bogons)|13|592708608|319|0.0%|2.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|299|0.0%|2.7%|
[alienvault_reputation](#alienvault_reputation)|181932|181932|196|0.1%|1.7%|
[firehol_anonymous](#firehol_anonymous)|17882|81890|78|0.0%|0.7%|
[firehol_level3](#firehol_level3)|107735|9625249|60|0.0%|0.5%|
[stopforumspam_30d](#stopforumspam_30d)|92247|92247|37|0.0%|0.3%|
[firehol_level2](#firehol_level2)|25736|37353|35|0.0%|0.3%|
[blocklist_de](#blocklist_de)|31859|31859|32|0.1%|0.2%|
[blocklist_de_sip](#blocklist_de_sip)|86|86|28|32.5%|0.2%|
[et_block](#et_block)|1023|18338662|18|0.0%|0.1%|
[stopforumspam_7d](#stopforumspam_7d)|29278|29278|15|0.0%|0.1%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|14|0.0%|0.1%|
[shunlist](#shunlist)|1241|1241|12|0.9%|0.1%|
[openbl_60d](#openbl_60d)|7239|7239|8|0.1%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|4|0.0%|0.0%|
[ciarmy](#ciarmy)|422|422|4|0.9%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|16426|16426|4|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6881|6881|3|0.0%|0.0%|
[openbl_30d](#openbl_30d)|2935|2935|3|0.1%|0.0%|
[et_tor](#et_tor)|6470|6470|3|0.0%|0.0%|
[dm_tor](#dm_tor)|6482|6482|3|0.0%|0.0%|
[bm_tor](#bm_tor)|6465|6465|3|0.0%|0.0%|
[nixspam](#nixspam)|28061|28061|2|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|2|0.0%|0.0%|
[et_compromised](#et_compromised)|2016|2016|2|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1703|1703|2|0.1%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.0%|
[firehol_proxies](#firehol_proxies)|11383|11607|1|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|5111|5111|1|0.0%|0.0%|

## xroxy

[xroxy.com](http://www.xroxy.com) open proxies (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.xroxy.com/proxyrss.xml).

The last time downloaded was found to be dated: Mon Jun  8 12:33:01 UTC 2015.

The ipset `xroxy` has **2124** entries, **2124** unique IPs.

The following table shows the overlaps of `xroxy` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `xroxy`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `xroxy`.
- ` this % ` is the percentage **of this ipset (`xroxy`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_proxies](#firehol_proxies)|11383|11607|2124|18.2%|100.0%|
[firehol_anonymous](#firehol_anonymous)|17882|81890|2124|2.5%|100.0%|
[firehol_level3](#firehol_level3)|107735|9625249|1270|0.0%|59.7%|
[stopforumspam_30d](#stopforumspam_30d)|92247|92247|1256|1.3%|59.1%|
[ri_web_proxies](#ri_web_proxies)|7066|7066|921|13.0%|43.3%|
[stopforumspam_7d](#stopforumspam_7d)|29278|29278|667|2.2%|31.4%|
[proxz](#proxz)|1047|1047|384|36.6%|18.0%|
[ri_connect_proxies](#ri_connect_proxies)|2581|2581|378|14.6%|17.7%|
[proxyrss](#proxyrss)|1481|1481|373|25.1%|17.5%|
[firehol_level2](#firehol_level2)|25736|37353|370|0.9%|17.4%|
[stopforumspam_1d](#stopforumspam_1d)|6881|6881|283|4.1%|13.3%|
[blocklist_de](#blocklist_de)|31859|31859|202|0.6%|9.5%|
[blocklist_de_bots](#blocklist_de_bots)|3458|3458|163|4.7%|7.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|104|0.0%|4.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|101|0.0%|4.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|58|0.0%|2.7%|
[nixspam](#nixspam)|28061|28061|45|0.1%|2.1%|
[blocklist_de_mail](#blocklist_de_mail)|19169|19169|40|0.2%|1.8%|
[php_dictionary](#php_dictionary)|630|630|38|6.0%|1.7%|
[snort_ipfilter](#snort_ipfilter)|9492|9492|34|0.3%|1.6%|
[php_spammers](#php_spammers)|622|622|30|4.8%|1.4%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|13|1.9%|0.6%|
[php_commenters](#php_commenters)|373|373|8|2.1%|0.3%|
[blocklist_de_strongips](#blocklist_de_strongips)|158|158|5|3.1%|0.2%|
[alienvault_reputation](#alienvault_reputation)|181932|181932|4|0.0%|0.1%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|3|0.0%|0.1%|
[php_harvesters](#php_harvesters)|341|341|2|0.5%|0.0%|
[et_tor](#et_tor)|6470|6470|2|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.0%|
[et_compromised](#et_compromised)|2016|2016|1|0.0%|0.0%|
[dm_tor](#dm_tor)|6482|6482|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1703|1703|1|0.0%|0.0%|
[bm_tor](#bm_tor)|6465|6465|1|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|5111|5111|1|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|16426|16426|1|0.0%|0.0%|

## zeus

[Abuse.ch Zeus tracker](https://zeustracker.abuse.ch) standard, contains the same data as the ZeuS IP blocklist (zeus_badips) but with the slight difference that it doesn't exclude hijacked websites (level 2) and free web hosting providers (level 3). This means that this blocklist contains all IPv4 addresses associated with ZeuS C&Cs which are currently being tracked by ZeuS Tracker. Hence this blocklist will likely cause some false positives. - **excellent list**

Source is downloaded from [this link](https://zeustracker.abuse.ch/blocklist.php?download=ipblocklist).

The last time downloaded was found to be dated: Mon Jun  8 11:01:58 UTC 2015.

The ipset `zeus` has **234** entries, **234** unique IPs.

The following table shows the overlaps of `zeus` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `zeus`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `zeus`.
- ` this % ` is the percentage **of this ipset (`zeus`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level1](#firehol_level1)|5088|688943411|234|0.0%|100.0%|
[et_block](#et_block)|1023|18338662|222|0.0%|94.8%|
[firehol_level3](#firehol_level3)|107735|9625249|205|0.0%|87.6%|
[zeus_badips](#zeus_badips)|203|203|203|100.0%|86.7%|
[snort_ipfilter](#snort_ipfilter)|9492|9492|203|2.1%|86.7%|
[alienvault_reputation](#alienvault_reputation)|181932|181932|64|0.0%|27.3%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|16|0.0%|6.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|14|0.0%|5.9%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|10|0.0%|4.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|9|0.0%|3.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|7|0.0%|2.9%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|5|0.0%|2.1%|
[stopforumspam_30d](#stopforumspam_30d)|92247|92247|2|0.0%|0.8%|
[openbl_60d](#openbl_60d)|7239|7239|2|0.0%|0.8%|
[openbl_30d](#openbl_30d)|2935|2935|2|0.0%|0.8%|
[firehol_level2](#firehol_level2)|25736|37353|2|0.0%|0.8%|
[stopforumspam_7d](#stopforumspam_7d)|29278|29278|1|0.0%|0.4%|
[stopforumspam_1d](#stopforumspam_1d)|6881|6881|1|0.0%|0.4%|
[php_commenters](#php_commenters)|373|373|1|0.2%|0.4%|
[nixspam](#nixspam)|28061|28061|1|0.0%|0.4%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.4%|
[blocklist_de_mail](#blocklist_de_mail)|19169|19169|1|0.0%|0.4%|
[blocklist_de_imap](#blocklist_de_imap)|2731|2731|1|0.0%|0.4%|
[blocklist_de](#blocklist_de)|31859|31859|1|0.0%|0.4%|

## zeus_badips

[Abuse.ch Zeus tracker](https://zeustracker.abuse.ch) badips includes IPv4 addresses that are used by the ZeuS trojan. It is the recommened blocklist if you want to block only ZeuS IPs. It excludes IP addresses that ZeuS Tracker believes to be hijacked (level 2) or belong to a free web hosting provider (level 3). Hence the false postive rate should be much lower compared to the standard ZeuS IP blocklist. **excellent list**

Source is downloaded from [this link](https://zeustracker.abuse.ch/blocklist.php?download=badips).

The last time downloaded was found to be dated: Mon Jun  8 12:18:22 UTC 2015.

The ipset `zeus_badips` has **203** entries, **203** unique IPs.

The following table shows the overlaps of `zeus_badips` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `zeus_badips`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `zeus_badips`.
- ` this % ` is the percentage **of this ipset (`zeus_badips`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[zeus](#zeus)|234|234|203|86.7%|100.0%|
[firehol_level1](#firehol_level1)|5088|688943411|203|0.0%|100.0%|
[et_block](#et_block)|1023|18338662|199|0.0%|98.0%|
[firehol_level3](#firehol_level3)|107735|9625249|181|0.0%|89.1%|
[snort_ipfilter](#snort_ipfilter)|9492|9492|179|1.8%|88.1%|
[alienvault_reputation](#alienvault_reputation)|181932|181932|38|0.0%|18.7%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|16|0.0%|7.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|10|0.0%|4.9%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|10|0.0%|4.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|8|0.0%|3.9%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|5|0.0%|2.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|4|0.0%|1.9%|
[stopforumspam_30d](#stopforumspam_30d)|92247|92247|2|0.0%|0.9%|
[firehol_level2](#firehol_level2)|25736|37353|2|0.0%|0.9%|
[stopforumspam_7d](#stopforumspam_7d)|29278|29278|1|0.0%|0.4%|
[stopforumspam_1d](#stopforumspam_1d)|6881|6881|1|0.0%|0.4%|
[php_commenters](#php_commenters)|373|373|1|0.2%|0.4%|
[openbl_60d](#openbl_60d)|7239|7239|1|0.0%|0.4%|
[openbl_30d](#openbl_30d)|2935|2935|1|0.0%|0.4%|
[nixspam](#nixspam)|28061|28061|1|0.0%|0.4%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.4%|
[blocklist_de_mail](#blocklist_de_mail)|19169|19169|1|0.0%|0.4%|
[blocklist_de_imap](#blocklist_de_imap)|2731|2731|1|0.0%|0.4%|
[blocklist_de](#blocklist_de)|31859|31859|1|0.0%|0.4%|
