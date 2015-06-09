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

The following list was automatically generated on Tue Jun  9 12:28:00 UTC 2015.

The update frequency is the maximum allowed by internal configuration. A list will never be downloaded sooner than the update frequency stated. A list may also not be downloaded, after this frequency expired, if it has not been modified on the server (as reported by HTTP `IF_MODIFIED_SINCE` method).

name|info|type|entries|update|
:--:|:--:|:--:|:-----:|:----:|
[alienvault_reputation](#alienvault_reputation)|[AlienVault.com](https://www.alienvault.com/) IP reputation database (this list seems to include port scanning hosts and to be updated regularly, but we found no information about its retention policy)|ipv4 hash:ip|182730 unique IPs|updated every 6 hours  from [this link](https://reputation.alienvault.com/reputation.generic)
[blocklist_de](#blocklist_de)|[Blocklist.de](https://www.blocklist.de/) IPs that have been detected by fail2ban in the last 48 hours - **excellent list**|ipv4 hash:ip|31902 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/all.txt)
[blocklist_de_apache](#blocklist_de_apache)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service Apache, Apache-DDOS, RFI-Attacks.|ipv4 hash:ip|16300 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/apache.txt)
[blocklist_de_bots](#blocklist_de_bots)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the RFI-Attacks, REG-Bots, IRC-Bots or BadBots (BadBots = he has posted a Spam-Comment on a open Forum or Wiki).|ipv4 hash:ip|3443 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/bots.txt)
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|[Blocklist.de](https://www.blocklist.de/) All IPs which attacks Joomlas, Wordpress and other Web-Logins with Brute-Force Logins.|ipv4 hash:ip|4930 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/bruteforcelogin.txt)
[blocklist_de_ftp](#blocklist_de_ftp)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours for attacks on the Service FTP.|ipv4 hash:ip|517 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/ftp.txt)
[blocklist_de_imap](#blocklist_de_imap)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours for attacks on the Service imap, sasl, pop3, etc.|ipv4 hash:ip|2743 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/imap.txt)
[blocklist_de_mail](#blocklist_de_mail)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service Mail, Postfix.|ipv4 hash:ip|20132 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/mail.txt)
[blocklist_de_sip](#blocklist_de_sip)|[Blocklist.de](https://www.blocklist.de/) All IP addresses that tried to login in a SIP, VOIP or Asterisk Server and are included in the IPs list from [infiltrated.net](www.infiltrated.net)|ipv4 hash:ip|86 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/sip.txt)
[blocklist_de_ssh](#blocklist_de_ssh)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service SSH.|ipv4 hash:ip|2511 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/ssh.txt)
[blocklist_de_strongips](#blocklist_de_strongips)|[Blocklist.de](https://www.blocklist.de/) All IPs which are older then 2 month and have more then 5.000 attacks.|ipv4 hash:ip|173 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/strongips.txt)
[bm_tor](#bm_tor)|[torstatus.blutmagie.de](https://torstatus.blutmagie.de) list of all TOR network servers|ipv4 hash:ip|6416 unique IPs|updated every 30 mins  from [this link](https://torstatus.blutmagie.de/ip_list_all.php/Tor_ip_list_ALL.csv)
[bogons](#bogons)|[Team-Cymru.org](http://www.team-cymru.org) private and reserved addresses defined by RFC 1918, RFC 5735, and RFC 6598 and netblocks that have not been allocated to a regional internet registry - **excellent list - use it only your internet interface**|ipv4 hash:net|13 subnets, 592708608 unique IPs|updated every 1 day  from [this link](http://www.team-cymru.org/Services/Bogons/bogon-bn-agg.txt)
[bruteforceblocker](#bruteforceblocker)|[danger.rulez.sk](http://danger.rulez.sk/) IPs detected by [bruteforceblocker](http://danger.rulez.sk/index.php/bruteforceblocker/) (fail2ban alternative for SSH on OpenBSD). This is an automatically generated list from users reporting failed authentication attempts. An IP seems to be included if 3 or more users report it. Its retention pocily seems 30 days.|ipv4 hash:ip|1718 unique IPs|updated every 3 hours  from [this link](http://danger.rulez.sk/projects/bruteforceblocker/blist.php)
[ciarmy](#ciarmy)|[CIArmy.com](http://ciarmy.com/) IPs with poor Rogue Packet score that have not yet been identified as malicious by the community|ipv4 hash:ip|447 unique IPs|updated every 3 hours  from [this link](http://cinsscore.com/list/ci-badguys.txt)
[cleanmx_viruses](#cleanmx_viruses)|[Clean-MX.de](http://support.clean-mx.de/clean-mx/viruses.php) IPs with viruses|ipv4 hash:ip|6 unique IPs|updated every 12 hours  from [this link](http://support.clean-mx.de/clean-mx/xmlviruses.php?sort=id%20desc&response=alive)
[dm_tor](#dm_tor)|[dan.me.uk](https://www.dan.me.uk) dynamic list of TOR exit points|ipv4 hash:ip|6417 unique IPs|updated every 30 mins  from [this link](https://www.dan.me.uk/torlist/)
[dshield](#dshield)|[DShield.org](https://dshield.org/) top 20 attacking class C (/24) subnets over the last three days - **excellent list**|ipv4 hash:net|20 subnets, 5120 unique IPs|updated every 4 hours  from [this link](http://feeds.dshield.org/block.txt)
[et_block](#et_block)|[EmergingThreats.net](http://www.emergingthreats.net/) default blacklist (at the time of writing includes spamhaus DROP, dshield and abuse.ch trackers, which are available separately too - prefer to use the direct ipsets instead of this, they seem to lag a bit in updates)|ipv4 hash:net|999 subnets, 18343755 unique IPs|updated every 12 hours  from [this link](http://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt)
[et_botcc](#et_botcc)|[EmergingThreats.net Command and Control IPs](http://doc.emergingthreats.net/bin/view/Main/BotCC) These IPs are updates every 24 hours and should be considered VERY highly reliable indications that a host is communicating with a known and active Bot or Malware command and control server - (although they say this includes abuse.ch trackers, it does not - most probably it is the shadowserver.org C&C list)|ipv4 hash:ip|509 unique IPs|updated every 12 hours  from [this link](http://rules.emergingthreats.net/fwrules/emerging-PIX-CC.rules)
[et_compromised](#et_compromised)|[EmergingThreats.net compromised hosts](http://doc.emergingthreats.net/bin/view/Main/CompromisedHost) - (this seems to be based on bruteforceblocker)|ipv4 hash:ip|1678 unique IPs|updated every 12 hours  from [this link](http://rules.emergingthreats.net/blockrules/compromised-ips.txt)
et_dshield|[EmergingThreats.net](http://www.emergingthreats.net/) dshield blocklist|ipv4 hash:net|disabled|updated every 12 hours  from [this link](http://rules.emergingthreats.net/fwrules/emerging-PIX-DSHIELD.rules)
et_spamhaus|[EmergingThreats.net](http://www.emergingthreats.net/) spamhaus blocklist|ipv4 hash:net|disabled|updated every 12 hours  from [this link](http://rules.emergingthreats.net/fwrules/emerging-PIX-DROP.rules)
[et_tor](#et_tor)|[EmergingThreats.net](http://www.emergingthreats.net/) [list](http://doc.emergingthreats.net/bin/view/Main/TorRules) of TOR network IPs|ipv4 hash:ip|6400 unique IPs|updated every 12 hours  from [this link](http://rules.emergingthreats.net/blockrules/emerging-tor.rules)
[feodo](#feodo)|[Abuse.ch Feodo tracker](https://feodotracker.abuse.ch) trojan includes IPs which are being used by Feodo (also known as Cridex or Bugat) which commits ebanking fraud - **excellent list**|ipv4 hash:ip|103 unique IPs|updated every 30 mins  from [this link](https://feodotracker.abuse.ch/blocklist/?download=ipblocklist)
[firehol_anonymous](#firehol_anonymous)|**FireHOL Anonymous** - Known anonymizing IPs. (includes: firehol_proxies anonymous bm_tor dm_tor)|ipv4 hash:net|17940 subnets, 81947 unique IPs|updated every 1 min  from [this link]()
[firehol_level1](#firehol_level1)|**FireHOL Level 1** - Maximum protection without false positives. (includes: fullbogons dshield feodo palevo sslbl zeus spamhaus_drop spamhaus_edrop)|ipv4 hash:net|5148 subnets, 688978821 unique IPs|updated every 1 min  from [this link]()
[firehol_level2](#firehol_level2)|**FireHOL Level 2** - Maximum protection from attacks took place in the last 48 hours. (includes: openbl_1d blocklist_de stopforumspam_1d)|ipv4 hash:net|26299 subnets, 37969 unique IPs|updated every 1 min  from [this link]()
[firehol_level3](#firehol_level3)|**FireHOL Level 3** - All the bad IPs in last 30 days. (includes: openbl_30d stopforumspam_30d virbl malc0de shunlist malwaredomainlist bruteforceblocker ciarmy cleanmx_viruses snort_ipfilter ib_bluetack_spyware ib_bluetack_hijacked ib_bluetack_webexploit php_commenters php_dictionary php_harvesters php_spammers)|ipv4 hash:net|108375 subnets, 9625859 unique IPs|updated every 1 min  from [this link]()
[firehol_proxies](#firehol_proxies)|**FireHOL Proxies** - Known open proxies in the last 30 days. (includes: ib_bluetack_proxies maxmind_proxy_fraud proxyrss proxz ri_connect_proxies ri_web_proxies xroxy)|ipv4 hash:net|11509 subnets, 11733 unique IPs|updated every 1 min  from [this link]()
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
[malc0de](#malc0de)|[Malc0de.com](http://malc0de.com) malicious IPs of the last 30 days|ipv4 hash:ip|342 unique IPs|updated every 1 day  from [this link](http://malc0de.com/bl/IP_Blacklist.txt)
[malwaredomainlist](#malwaredomainlist)|[malwaredomainlist.com](http://www.malwaredomainlist.com) list of malware active ip addresses|ipv4 hash:ip|1288 unique IPs|updated every 12 hours  from [this link](http://www.malwaredomainlist.com/hostslist/ip.txt)
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|[MaxMind.com](https://www.maxmind.com/en/anonymous-proxy-fraudulent-ip-address-list) list of anonymous proxy fraudelent IP addresses.|ipv4 hash:ip|372 unique IPs|updated every 4 hours  from [this link](https://www.maxmind.com/en/anonymous-proxy-fraudulent-ip-address-list)
[nixspam](#nixspam)|[NiX Spam](http://www.heise.de/ix/NiX-Spam-DNSBL-and-blacklist-for-download-499637.html) IP addresses that sent spam in the last hour - automatically generated entries without distinguishing open proxies from relays, dialup gateways, and so on. All IPs are removed after 12 hours if there is no spam from there.|ipv4 hash:ip|20501 unique IPs|updated every 15 mins  from [this link](http://www.dnsbl.manitu.net/download/nixspam-ip.dump.gz)
openbl|[OpenBL.org](http://www.openbl.org/) default blacklist (currently it is the same with 90 days). OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications - **excellent list**|ipv4 hash:ip|disabled|updated every 4 hours  from [this link](http://www.openbl.org/lists/base.txt)
openbl_180d|[OpenBL.org](http://www.openbl.org/) last 180 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|disabled|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_180days.txt)
[openbl_1d](#openbl_1d)|[OpenBL.org](http://www.openbl.org/) last 24 hours IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|141 unique IPs|updated every 1 hour  from [this link](http://www.openbl.org/lists/base_1days.txt)
[openbl_30d](#openbl_30d)|[OpenBL.org](http://www.openbl.org/) last 30 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|2857 unique IPs|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_30days.txt)
openbl_360d|[OpenBL.org](http://www.openbl.org/) last 360 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|disabled|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_360days.txt)
[openbl_60d](#openbl_60d)|[OpenBL.org](http://www.openbl.org/) last 60 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|7177 unique IPs|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_60days.txt)
[openbl_7d](#openbl_7d)|[OpenBL.org](http://www.openbl.org/) last 7 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|813 unique IPs|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_7days.txt)
openbl_90d|[OpenBL.org](http://www.openbl.org/) last 90 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|disabled|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_90days.txt)
openbl_all|[OpenBL.org](http://www.openbl.org/) last all IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|disabled|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_all.txt)
[palevo](#palevo)|[Abuse.ch Palevo tracker](https://palevotracker.abuse.ch) worm includes IPs which are being used as botnet C&C for the Palevo crimeware - **excellent list**|ipv4 hash:ip|13 unique IPs|updated every 30 mins  from [this link](https://palevotracker.abuse.ch/blocklists.php?download=ipblocklist)
php_bad|[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) bad web hosts (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|disabled|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=b&rss=1)
[php_commenters](#php_commenters)|[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) comment spammers (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|385 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=c&rss=1)
[php_dictionary](#php_dictionary)|[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) directory attackers (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|666 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=d&rss=1)
[php_harvesters](#php_harvesters)|[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) harvesters (IPs that surf the internet looking for email addresses) (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|366 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=h&rss=1)
[php_spammers](#php_spammers)|[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) spam servers (IPs used by spammers to send messages) (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|661 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=s&rss=1)
[proxyrss](#proxyrss)|[proxyrss.com](http://www.proxyrss.com) open proxies syndicated from multiple sources.|ipv4 hash:ip|1212 unique IPs|updated every 4 hours  from [this link](http://www.proxyrss.com/proxylists/all.gz)
[proxz](#proxz)|[proxz.com](http://www.proxz.com) open proxies (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|1122 unique IPs|updated every 1 hour  from [this link](http://www.proxz.com/proxylists.xml)
[ri_connect_proxies](#ri_connect_proxies)|[rosinstrument.com](http://www.rosinstrument.com) open CONNECT proxies (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|2644 unique IPs|updated every 1 hour  from [this link](http://tools.rosinstrument.com/proxy/plab100.xml)
[ri_web_proxies](#ri_web_proxies)|[rosinstrument.com](http://www.rosinstrument.com) open HTTP proxies (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|7263 unique IPs|updated every 1 hour  from [this link](http://tools.rosinstrument.com/proxy/l100.xml)
[shunlist](#shunlist)|[AutoShun.org](http://autoshun.org/) IPs identified as hostile by correlating logs from distributed snort installations running the autoshun plugin|ipv4 hash:ip|1279 unique IPs|updated every 4 hours  from [this link](http://www.autoshun.org/files/shunlist.csv)
[snort_ipfilter](#snort_ipfilter)|[labs.snort.org](https://labs.snort.org/) supplied IP blacklist (this list seems to be updated frequently, but we found no information about it)|ipv4 hash:ip|10116 unique IPs|updated every 12 hours  from [this link](http://labs.snort.org/feeds/ip-filter.blf)
[spamhaus_drop](#spamhaus_drop)|[Spamhaus.org](http://www.spamhaus.org) DROP list (according to their site this list should be dropped at tier-1 ISPs globaly) - **excellent list**|ipv4 hash:net|652 subnets, 18338560 unique IPs|updated every 12 hours  from [this link](http://www.spamhaus.org/drop/drop.txt)
[spamhaus_edrop](#spamhaus_edrop)|[Spamhaus.org](http://www.spamhaus.org) EDROP (extended matches that should be used with DROP) - **excellent list**|ipv4 hash:net|56 subnets, 487424 unique IPs|updated every 12 hours  from [this link](http://www.spamhaus.org/drop/edrop.txt)
[sslbl](#sslbl)|[Abuse.ch SSL Blacklist](https://sslbl.abuse.ch/) bad SSL traffic related to malware or botnet activities - **excellent list**|ipv4 hash:ip|379 unique IPs|updated every 30 mins  from [this link](https://sslbl.abuse.ch/blacklist/sslipblacklist.csv)
stopforumspam_180d|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 180 days)|ipv4 hash:ip|disabled|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/listed_ip_180.zip)
[stopforumspam_1d](#stopforumspam_1d)|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers in the last 24 hours - **excellent list**|ipv4 hash:ip|7429 unique IPs|updated every 1 hour  from [this link](http://www.stopforumspam.com/downloads/listed_ip_1.zip)
[stopforumspam_30d](#stopforumspam_30d)|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 30 days)|ipv4 hash:ip|92512 unique IPs|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/listed_ip_30.zip)
stopforumspam_365d|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 365 days)|ipv4 hash:ip|disabled|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/listed_ip_365.zip)
[stopforumspam_7d](#stopforumspam_7d)|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 7 days)|ipv4 hash:ip|29277 unique IPs|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/listed_ip_7.zip)
stopforumspam_90d|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 90 days)|ipv4 hash:ip|disabled|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/listed_ip_90.zip)
stopforumspam_ever|[StopForumSpam.com](http://www.stopforumspam.com) all IPs used by forum spammers, **ever** (normally you don't want to use this ipset, use the hourly one which includes last 24 hours IPs or the 7 days one)|ipv4 hash:ip|disabled|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/bannedips.zip)
[virbl](#virbl)|[VirBL](http://virbl.bit.nl/) is a project of which the idea was born during the RIPE-48 meeting. The plan was to get reports of virusscanning mailservers, and put the IP-addresses that were reported to send viruses on a blacklist.|ipv4 hash:ip|21 unique IPs|updated every 1 hour  from [this link](http://virbl.bit.nl/download/virbl.dnsbl.bit.nl.txt)
[voipbl](#voipbl)|[VoIPBL.org](http://www.voipbl.org/) a distributed VoIP blacklist that is aimed to protects against VoIP Fraud and minimizing abuse for network that have publicly accessible PBX's. Several algorithms, external sources and manual confirmation are used before they categorize something as an attack and determine the threat level.|ipv4 hash:net|10507 subnets, 10919 unique IPs|updated every 4 hours  from [this link](http://www.voipbl.org/update/)
[xroxy](#xroxy)|[xroxy.com](http://www.xroxy.com) open proxies (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|2139 unique IPs|updated every 1 hour  from [this link](http://www.xroxy.com/proxyrss.xml)
[zeus](#zeus)|[Abuse.ch Zeus tracker](https://zeustracker.abuse.ch) standard, contains the same data as the ZeuS IP blocklist (zeus_badips) but with the slight difference that it doesn't exclude hijacked websites (level 2) and free web hosting providers (level 3). This means that this blocklist contains all IPv4 addresses associated with ZeuS C&Cs which are currently being tracked by ZeuS Tracker. Hence this blocklist will likely cause some false positives. - **excellent list**|ipv4 hash:ip|233 unique IPs|updated every 30 mins  from [this link](https://zeustracker.abuse.ch/blocklist.php?download=ipblocklist)
[zeus_badips](#zeus_badips)|[Abuse.ch Zeus tracker](https://zeustracker.abuse.ch) badips includes IPv4 addresses that are used by the ZeuS trojan. It is the recommened blocklist if you want to block only ZeuS IPs. It excludes IP addresses that ZeuS Tracker believes to be hijacked (level 2) or belong to a free web hosting provider (level 3). Hence the false postive rate should be much lower compared to the standard ZeuS IP blocklist. **excellent list**|ipv4 hash:ip|202 unique IPs|updated every 30 mins  from [this link](https://zeustracker.abuse.ch/blocklist.php?download=badips)

# Comparison of ipsets

Below we compare each ipset against all other.


## alienvault_reputation

[AlienVault.com](https://www.alienvault.com/) IP reputation database (this list seems to include port scanning hosts and to be updated regularly, but we found no information about its retention policy)

Source is downloaded from [this link](https://reputation.alienvault.com/reputation.generic).

The last time downloaded was found to be dated: Tue Jun  9 10:00:42 UTC 2015.

The ipset `alienvault_reputation` has **182730** entries, **182730** unique IPs.

The following table shows the overlaps of `alienvault_reputation` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `alienvault_reputation`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `alienvault_reputation`.
- ` this % ` is the percentage **of this ipset (`alienvault_reputation`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|14118|0.0%|7.7%|
[openbl_60d](#openbl_60d)|7177|7177|7153|99.6%|3.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|6258|0.0%|3.4%|
[et_block](#et_block)|999|18343755|5280|0.0%|2.8%|
[firehol_level3](#firehol_level3)|108375|9625859|5176|0.0%|2.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|4217|0.0%|2.3%|
[firehol_level1](#firehol_level1)|5148|688978821|3823|0.0%|2.0%|
[openbl_30d](#openbl_30d)|2857|2857|2839|99.3%|1.5%|
[dshield](#dshield)|20|5120|2561|50.0%|1.4%|
[firehol_level2](#firehol_level2)|26299|37969|1401|3.6%|0.7%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|1374|0.0%|0.7%|
[blocklist_de](#blocklist_de)|31902|31902|1353|4.2%|0.7%|
[shunlist](#shunlist)|1279|1279|1263|98.7%|0.6%|
[blocklist_de_ssh](#blocklist_de_ssh)|2511|2511|1121|44.6%|0.6%|
[bruteforceblocker](#bruteforceblocker)|1718|1718|1103|64.2%|0.6%|
[et_compromised](#et_compromised)|1678|1678|1079|64.3%|0.5%|
[openbl_7d](#openbl_7d)|813|813|806|99.1%|0.4%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|518|0.0%|0.2%|
[ciarmy](#ciarmy)|447|447|434|97.0%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|288|0.0%|0.1%|
[stopforumspam_30d](#stopforumspam_30d)|92512|92512|199|0.2%|0.1%|
[voipbl](#voipbl)|10507|10919|190|1.7%|0.1%|
[openbl_1d](#openbl_1d)|141|141|137|97.1%|0.0%|
[snort_ipfilter](#snort_ipfilter)|10116|10116|124|1.2%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|16300|16300|120|0.7%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29277|29277|98|0.3%|0.0%|
[sslbl](#sslbl)|379|379|68|17.9%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|20132|20132|66|0.3%|0.0%|
[zeus](#zeus)|233|233|63|27.0%|0.0%|
[firehol_anonymous](#firehol_anonymous)|17940|81947|55|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7429|7429|47|0.6%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2743|2743|45|1.6%|0.0%|
[et_tor](#et_tor)|6400|6400|41|0.6%|0.0%|
[dm_tor](#dm_tor)|6417|6417|41|0.6%|0.0%|
[bm_tor](#bm_tor)|6416|6416|41|0.6%|0.0%|
[nixspam](#nixspam)|20501|20501|39|0.1%|0.0%|
[zeus_badips](#zeus_badips)|202|202|37|18.3%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|173|173|35|20.2%|0.0%|
[firehol_proxies](#firehol_proxies)|11509|11733|33|0.2%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3443|3443|29|0.8%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|26|6.9%|0.0%|
[php_commenters](#php_commenters)|385|385|17|4.4%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4930|4930|17|0.3%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|86|86|16|18.6%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|15|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|14|0.0%|0.0%|
[php_harvesters](#php_harvesters)|366|366|11|3.0%|0.0%|
[malc0de](#malc0de)|342|342|11|3.2%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|517|517|11|2.1%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|10|0.6%|0.0%|
[php_dictionary](#php_dictionary)|666|666|8|1.2%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|7|0.5%|0.0%|
[xroxy](#xroxy)|2139|2139|5|0.2%|0.0%|
[php_spammers](#php_spammers)|661|661|5|0.7%|0.0%|
[et_botcc](#et_botcc)|509|509|5|0.9%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7263|7263|3|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2644|2644|3|0.1%|0.0%|
[proxz](#proxz)|1122|1122|3|0.2%|0.0%|
[feodo](#feodo)|103|103|2|1.9%|0.0%|
[proxyrss](#proxyrss)|1212|1212|1|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|1|0.1%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|6|6|1|16.6%|0.0%|

## blocklist_de

[Blocklist.de](https://www.blocklist.de/) IPs that have been detected by fail2ban in the last 48 hours - **excellent list**

Source is downloaded from [this link](http://lists.blocklist.de/lists/all.txt).

The last time downloaded was found to be dated: Tue Jun  9 11:56:03 UTC 2015.

The ipset `blocklist_de` has **31902** entries, **31902** unique IPs.

The following table shows the overlaps of `blocklist_de` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de`.
- ` this % ` is the percentage **of this ipset (`blocklist_de`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|26299|37969|31902|84.0%|100.0%|
[blocklist_de_mail](#blocklist_de_mail)|20132|20132|20102|99.8%|63.0%|
[blocklist_de_apache](#blocklist_de_apache)|16300|16300|16300|100.0%|51.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4930|4930|4930|100.0%|15.4%|
[firehol_level3](#firehol_level3)|108375|9625859|4079|0.0%|12.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|3735|0.0%|11.7%|
[blocklist_de_bots](#blocklist_de_bots)|3443|3443|3443|100.0%|10.7%|
[blocklist_de_imap](#blocklist_de_imap)|2743|2743|2743|100.0%|8.5%|
[stopforumspam_30d](#stopforumspam_30d)|92512|92512|2663|2.8%|8.3%|
[blocklist_de_ssh](#blocklist_de_ssh)|2511|2511|2506|99.8%|7.8%|
[stopforumspam_7d](#stopforumspam_7d)|29277|29277|2271|7.7%|7.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|1606|0.0%|5.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|1554|0.0%|4.8%|
[stopforumspam_1d](#stopforumspam_1d)|7429|7429|1379|18.5%|4.3%|
[alienvault_reputation](#alienvault_reputation)|182730|182730|1353|0.7%|4.2%|
[openbl_60d](#openbl_60d)|7177|7177|1022|14.2%|3.2%|
[openbl_30d](#openbl_30d)|2857|2857|843|29.5%|2.6%|
[nixspam](#nixspam)|20501|20501|755|3.6%|2.3%|
[bruteforceblocker](#bruteforceblocker)|1718|1718|737|42.8%|2.3%|
[et_compromised](#et_compromised)|1678|1678|651|38.7%|2.0%|
[firehol_anonymous](#firehol_anonymous)|17940|81947|611|0.7%|1.9%|
[firehol_proxies](#firehol_proxies)|11509|11733|603|5.1%|1.8%|
[blocklist_de_ftp](#blocklist_de_ftp)|517|517|494|95.5%|1.5%|
[shunlist](#shunlist)|1279|1279|459|35.8%|1.4%|
[ri_web_proxies](#ri_web_proxies)|7263|7263|410|5.6%|1.2%|
[openbl_7d](#openbl_7d)|813|813|404|49.6%|1.2%|
[snort_ipfilter](#snort_ipfilter)|10116|10116|295|2.9%|0.9%|
[firehol_level1](#firehol_level1)|5148|688978821|224|0.0%|0.7%|
[et_block](#et_block)|999|18343755|216|0.0%|0.6%|
[xroxy](#xroxy)|2139|2139|203|9.4%|0.6%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|203|0.0%|0.6%|
[proxyrss](#proxyrss)|1212|1212|203|16.7%|0.6%|
[blocklist_de_strongips](#blocklist_de_strongips)|173|173|172|99.4%|0.5%|
[proxz](#proxz)|1122|1122|164|14.6%|0.5%|
[openbl_1d](#openbl_1d)|141|141|124|87.9%|0.3%|
[php_dictionary](#php_dictionary)|666|666|101|15.1%|0.3%|
[php_spammers](#php_spammers)|661|661|94|14.2%|0.2%|
[php_commenters](#php_commenters)|385|385|92|23.8%|0.2%|
[dshield](#dshield)|20|5120|85|1.6%|0.2%|
[ri_connect_proxies](#ri_connect_proxies)|2644|2644|77|2.9%|0.2%|
[blocklist_de_sip](#blocklist_de_sip)|86|86|67|77.9%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|58|0.0%|0.1%|
[php_harvesters](#php_harvesters)|366|366|40|10.9%|0.1%|
[ciarmy](#ciarmy)|447|447|33|7.3%|0.1%|
[voipbl](#voipbl)|10507|10919|32|0.2%|0.1%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|11|0.0%|0.0%|
[et_tor](#et_tor)|6400|6400|9|0.1%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|8|0.0%|0.0%|
[dm_tor](#dm_tor)|6417|6417|6|0.0%|0.0%|
[bm_tor](#bm_tor)|6416|6416|6|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|4|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|3|0.4%|0.0%|
[sslbl](#sslbl)|379|379|1|0.2%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|1|0.0%|0.0%|

## blocklist_de_apache

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service Apache, Apache-DDOS, RFI-Attacks.

Source is downloaded from [this link](http://lists.blocklist.de/lists/apache.txt).

The last time downloaded was found to be dated: Tue Jun  9 11:56:05 UTC 2015.

The ipset `blocklist_de_apache` has **16300** entries, **16300** unique IPs.

The following table shows the overlaps of `blocklist_de_apache` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_apache`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_apache`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_apache`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|26299|37969|16300|42.9%|100.0%|
[blocklist_de](#blocklist_de)|31902|31902|16300|51.0%|100.0%|
[blocklist_de_mail](#blocklist_de_mail)|20132|20132|11059|54.9%|67.8%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4930|4930|4930|100.0%|30.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|2444|0.0%|14.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|1332|0.0%|8.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|1100|0.0%|6.7%|
[firehol_level3](#firehol_level3)|108375|9625859|288|0.0%|1.7%|
[stopforumspam_30d](#stopforumspam_30d)|92512|92512|214|0.2%|1.3%|
[stopforumspam_7d](#stopforumspam_7d)|29277|29277|132|0.4%|0.8%|
[alienvault_reputation](#alienvault_reputation)|182730|182730|120|0.0%|0.7%|
[stopforumspam_1d](#stopforumspam_1d)|7429|7429|65|0.8%|0.3%|
[nixspam](#nixspam)|20501|20501|37|0.1%|0.2%|
[blocklist_de_strongips](#blocklist_de_strongips)|173|173|35|20.2%|0.2%|
[shunlist](#shunlist)|1279|1279|33|2.5%|0.2%|
[php_commenters](#php_commenters)|385|385|31|8.0%|0.1%|
[ciarmy](#ciarmy)|447|447|30|6.7%|0.1%|
[blocklist_de_bots](#blocklist_de_bots)|3443|3443|21|0.6%|0.1%|
[snort_ipfilter](#snort_ipfilter)|10116|10116|20|0.1%|0.1%|
[firehol_anonymous](#firehol_anonymous)|17940|81947|12|0.0%|0.0%|
[php_spammers](#php_spammers)|661|661|8|1.2%|0.0%|
[firehol_proxies](#firehol_proxies)|11509|11733|8|0.0%|0.0%|
[firehol_level1](#firehol_level1)|5148|688978821|8|0.0%|0.0%|
[et_tor](#et_tor)|6400|6400|8|0.1%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7263|7263|7|0.0%|0.0%|
[et_block](#et_block)|999|18343755|7|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|5|0.0%|0.0%|
[php_dictionary](#php_dictionary)|666|666|5|0.7%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|5|0.0%|0.0%|
[dm_tor](#dm_tor)|6417|6417|5|0.0%|0.0%|
[bm_tor](#bm_tor)|6416|6416|5|0.0%|0.0%|
[voipbl](#voipbl)|10507|10919|4|0.0%|0.0%|
[openbl_60d](#openbl_60d)|7177|7177|3|0.0%|0.0%|
[openbl_30d](#openbl_30d)|2857|2857|3|0.1%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|3|0.0%|0.0%|
[php_harvesters](#php_harvesters)|366|366|2|0.5%|0.0%|
[dshield](#dshield)|20|5120|2|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|1|0.0%|0.0%|
[openbl_7d](#openbl_7d)|813|813|1|0.1%|0.0%|
[openbl_1d](#openbl_1d)|141|141|1|0.7%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|

## blocklist_de_bots

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the RFI-Attacks, REG-Bots, IRC-Bots or BadBots (BadBots = he has posted a Spam-Comment on a open Forum or Wiki).

Source is downloaded from [this link](http://lists.blocklist.de/lists/bots.txt).

The last time downloaded was found to be dated: Tue Jun  9 11:56:09 UTC 2015.

The ipset `blocklist_de_bots` has **3443** entries, **3443** unique IPs.

The following table shows the overlaps of `blocklist_de_bots` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_bots`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_bots`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_bots`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|26299|37969|3443|9.0%|100.0%|
[blocklist_de](#blocklist_de)|31902|31902|3443|10.7%|100.0%|
[firehol_level3](#firehol_level3)|108375|9625859|2374|0.0%|68.9%|
[stopforumspam_30d](#stopforumspam_30d)|92512|92512|2342|2.5%|68.0%|
[stopforumspam_7d](#stopforumspam_7d)|29277|29277|2096|7.1%|60.8%|
[stopforumspam_1d](#stopforumspam_1d)|7429|7429|1310|17.6%|38.0%|
[firehol_anonymous](#firehol_anonymous)|17940|81947|523|0.6%|15.1%|
[firehol_proxies](#firehol_proxies)|11509|11733|520|4.4%|15.1%|
[ri_web_proxies](#ri_web_proxies)|7263|7263|357|4.9%|10.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|218|0.0%|6.3%|
[proxyrss](#proxyrss)|1212|1212|202|16.6%|5.8%|
[xroxy](#xroxy)|2139|2139|163|7.6%|4.7%|
[proxz](#proxz)|1122|1122|148|13.1%|4.2%|
[blocklist_de_strongips](#blocklist_de_strongips)|173|173|126|72.8%|3.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|122|0.0%|3.5%|
[ri_connect_proxies](#ri_connect_proxies)|2644|2644|74|2.7%|2.1%|
[php_commenters](#php_commenters)|385|385|74|19.2%|2.1%|
[firehol_level1](#firehol_level1)|5148|688978821|60|0.0%|1.7%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|57|0.0%|1.6%|
[et_block](#et_block)|999|18343755|57|0.0%|1.6%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|48|0.0%|1.3%|
[nixspam](#nixspam)|20501|20501|45|0.2%|1.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|31|0.0%|0.9%|
[php_harvesters](#php_harvesters)|366|366|29|7.9%|0.8%|
[alienvault_reputation](#alienvault_reputation)|182730|182730|29|0.0%|0.8%|
[snort_ipfilter](#snort_ipfilter)|10116|10116|28|0.2%|0.8%|
[php_dictionary](#php_dictionary)|666|666|24|3.6%|0.6%|
[blocklist_de_mail](#blocklist_de_mail)|20132|20132|24|0.1%|0.6%|
[php_spammers](#php_spammers)|661|661|21|3.1%|0.6%|
[blocklist_de_apache](#blocklist_de_apache)|16300|16300|21|0.1%|0.6%|
[openbl_60d](#openbl_60d)|7177|7177|13|0.1%|0.3%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|4|0.0%|0.1%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|3|0.4%|0.0%|
[openbl_30d](#openbl_30d)|2857|2857|1|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|1|0.0%|0.0%|
[et_tor](#et_tor)|6400|6400|1|0.0%|0.0%|
[dm_tor](#dm_tor)|6417|6417|1|0.0%|0.0%|
[bm_tor](#bm_tor)|6416|6416|1|0.0%|0.0%|

## blocklist_de_bruteforce

[Blocklist.de](https://www.blocklist.de/) All IPs which attacks Joomlas, Wordpress and other Web-Logins with Brute-Force Logins.

Source is downloaded from [this link](http://lists.blocklist.de/lists/bruteforcelogin.txt).

The last time downloaded was found to be dated: Tue Jun  9 12:09:24 UTC 2015.

The ipset `blocklist_de_bruteforce` has **4930** entries, **4930** unique IPs.

The following table shows the overlaps of `blocklist_de_bruteforce` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_bruteforce`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_bruteforce`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_bruteforce`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|26299|37969|4930|12.9%|100.0%|
[blocklist_de_apache](#blocklist_de_apache)|16300|16300|4930|30.2%|100.0%|
[blocklist_de](#blocklist_de)|31902|31902|4930|15.4%|100.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|349|0.0%|7.0%|
[firehol_level3](#firehol_level3)|108375|9625859|85|0.0%|1.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|67|0.0%|1.3%|
[stopforumspam_30d](#stopforumspam_30d)|92512|92512|66|0.0%|1.3%|
[stopforumspam_7d](#stopforumspam_7d)|29277|29277|47|0.1%|0.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|42|0.0%|0.8%|
[nixspam](#nixspam)|20501|20501|36|0.1%|0.7%|
[stopforumspam_1d](#stopforumspam_1d)|7429|7429|29|0.3%|0.5%|
[alienvault_reputation](#alienvault_reputation)|182730|182730|17|0.0%|0.3%|
[snort_ipfilter](#snort_ipfilter)|10116|10116|16|0.1%|0.3%|
[firehol_anonymous](#firehol_anonymous)|17940|81947|11|0.0%|0.2%|
[php_commenters](#php_commenters)|385|385|10|2.5%|0.2%|
[php_spammers](#php_spammers)|661|661|8|1.2%|0.1%|
[blocklist_de_strongips](#blocklist_de_strongips)|173|173|8|4.6%|0.1%|
[ri_web_proxies](#ri_web_proxies)|7263|7263|7|0.0%|0.1%|
[firehol_proxies](#firehol_proxies)|11509|11733|7|0.0%|0.1%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|5|0.0%|0.1%|
[php_dictionary](#php_dictionary)|666|666|5|0.7%|0.1%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|5|0.0%|0.1%|
[firehol_level1](#firehol_level1)|5148|688978821|5|0.0%|0.1%|
[et_block](#et_block)|999|18343755|5|0.0%|0.1%|
[et_tor](#et_tor)|6400|6400|4|0.0%|0.0%|
[dm_tor](#dm_tor)|6417|6417|4|0.0%|0.0%|
[bm_tor](#bm_tor)|6416|6416|4|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|2|0.0%|0.0%|
[voipbl](#voipbl)|10507|10919|1|0.0%|0.0%|
[shunlist](#shunlist)|1279|1279|1|0.0%|0.0%|
[php_harvesters](#php_harvesters)|366|366|1|0.2%|0.0%|

## blocklist_de_ftp

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours for attacks on the Service FTP.

Source is downloaded from [this link](http://lists.blocklist.de/lists/ftp.txt).

The last time downloaded was found to be dated: Tue Jun  9 12:14:06 UTC 2015.

The ipset `blocklist_de_ftp` has **517** entries, **517** unique IPs.

The following table shows the overlaps of `blocklist_de_ftp` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_ftp`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_ftp`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_ftp`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|26299|37969|494|1.3%|95.5%|
[blocklist_de](#blocklist_de)|31902|31902|494|1.5%|95.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|78|0.0%|15.0%|
[firehol_level3](#firehol_level3)|108375|9625859|18|0.0%|3.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|11|0.0%|2.1%|
[alienvault_reputation](#alienvault_reputation)|182730|182730|11|0.0%|2.1%|
[stopforumspam_30d](#stopforumspam_30d)|92512|92512|8|0.0%|1.5%|
[php_harvesters](#php_harvesters)|366|366|5|1.3%|0.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|5|0.0%|0.9%|
[openbl_60d](#openbl_60d)|7177|7177|3|0.0%|0.5%|
[openbl_30d](#openbl_30d)|2857|2857|3|0.1%|0.5%|
[nixspam](#nixspam)|20501|20501|3|0.0%|0.5%|
[stopforumspam_7d](#stopforumspam_7d)|29277|29277|2|0.0%|0.3%|
[shunlist](#shunlist)|1279|1279|2|0.1%|0.3%|
[et_compromised](#et_compromised)|1678|1678|2|0.1%|0.3%|
[bruteforceblocker](#bruteforceblocker)|1718|1718|2|0.1%|0.3%|
[blocklist_de_strongips](#blocklist_de_strongips)|173|173|2|1.1%|0.3%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|1|0.0%|0.1%|
[snort_ipfilter](#snort_ipfilter)|10116|10116|1|0.0%|0.1%|
[openbl_7d](#openbl_7d)|813|813|1|0.1%|0.1%|
[firehol_level1](#firehol_level1)|5148|688978821|1|0.0%|0.1%|
[firehol_anonymous](#firehol_anonymous)|17940|81947|1|0.0%|0.1%|
[et_block](#et_block)|999|18343755|1|0.0%|0.1%|
[ciarmy](#ciarmy)|447|447|1|0.2%|0.1%|
[blocklist_de_mail](#blocklist_de_mail)|20132|20132|1|0.0%|0.1%|
[blocklist_de_imap](#blocklist_de_imap)|2743|2743|1|0.0%|0.1%|

## blocklist_de_imap

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours for attacks on the Service imap, sasl, pop3, etc.

Source is downloaded from [this link](http://lists.blocklist.de/lists/imap.txt).

The last time downloaded was found to be dated: Tue Jun  9 11:56:06 UTC 2015.

The ipset `blocklist_de_imap` has **2743** entries, **2743** unique IPs.

The following table shows the overlaps of `blocklist_de_imap` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_imap`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_imap`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_imap`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|26299|37969|2743|7.2%|100.0%|
[blocklist_de](#blocklist_de)|31902|31902|2743|8.5%|100.0%|
[blocklist_de_mail](#blocklist_de_mail)|20132|20132|2740|13.6%|99.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|299|0.0%|10.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|55|0.0%|2.0%|
[firehol_level3](#firehol_level3)|108375|9625859|51|0.0%|1.8%|
[alienvault_reputation](#alienvault_reputation)|182730|182730|45|0.0%|1.6%|
[openbl_60d](#openbl_60d)|7177|7177|34|0.4%|1.2%|
[openbl_30d](#openbl_30d)|2857|2857|29|1.0%|1.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|26|0.0%|0.9%|
[nixspam](#nixspam)|20501|20501|22|0.1%|0.8%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|14|0.0%|0.5%|
[firehol_level1](#firehol_level1)|5148|688978821|14|0.0%|0.5%|
[et_block](#et_block)|999|18343755|14|0.0%|0.5%|
[snort_ipfilter](#snort_ipfilter)|10116|10116|11|0.1%|0.4%|
[stopforumspam_30d](#stopforumspam_30d)|92512|92512|8|0.0%|0.2%|
[openbl_7d](#openbl_7d)|813|813|7|0.8%|0.2%|
[et_compromised](#et_compromised)|1678|1678|7|0.4%|0.2%|
[bruteforceblocker](#bruteforceblocker)|1718|1718|7|0.4%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|0.1%|
[stopforumspam_7d](#stopforumspam_7d)|29277|29277|2|0.0%|0.0%|
[shunlist](#shunlist)|1279|1279|2|0.1%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2644|2644|2|0.0%|0.0%|
[firehol_proxies](#firehol_proxies)|11509|11733|2|0.0%|0.0%|
[firehol_anonymous](#firehol_anonymous)|17940|81947|2|0.0%|0.0%|
[xroxy](#xroxy)|2139|2139|1|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7429|7429|1|0.0%|0.0%|
[php_harvesters](#php_harvesters)|366|366|1|0.2%|0.0%|
[php_commenters](#php_commenters)|385|385|1|0.2%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|1|0.0%|0.0%|
[ciarmy](#ciarmy)|447|447|1|0.2%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|517|517|1|0.1%|0.0%|

## blocklist_de_mail

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service Mail, Postfix.

Source is downloaded from [this link](http://lists.blocklist.de/lists/mail.txt).

The last time downloaded was found to be dated: Tue Jun  9 12:09:20 UTC 2015.

The ipset `blocklist_de_mail` has **20132** entries, **20132** unique IPs.

The following table shows the overlaps of `blocklist_de_mail` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_mail`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_mail`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_mail`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|26299|37969|20102|52.9%|99.8%|
[blocklist_de](#blocklist_de)|31902|31902|20102|63.0%|99.8%|
[blocklist_de_apache](#blocklist_de_apache)|16300|16300|11059|67.8%|54.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|2808|0.0%|13.9%|
[blocklist_de_imap](#blocklist_de_imap)|2743|2743|2740|99.8%|13.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|1409|0.0%|6.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|1256|0.0%|6.2%|
[nixspam](#nixspam)|20501|20501|665|3.2%|3.3%|
[firehol_level3](#firehol_level3)|108375|9625859|489|0.0%|2.4%|
[snort_ipfilter](#snort_ipfilter)|10116|10116|247|2.4%|1.2%|
[stopforumspam_30d](#stopforumspam_30d)|92512|92512|239|0.2%|1.1%|
[stopforumspam_7d](#stopforumspam_7d)|29277|29277|130|0.4%|0.6%|
[firehol_proxies](#firehol_proxies)|11509|11733|79|0.6%|0.3%|
[firehol_anonymous](#firehol_anonymous)|17940|81947|79|0.0%|0.3%|
[php_dictionary](#php_dictionary)|666|666|73|10.9%|0.3%|
[alienvault_reputation](#alienvault_reputation)|182730|182730|66|0.0%|0.3%|
[php_spammers](#php_spammers)|661|661|64|9.6%|0.3%|
[stopforumspam_1d](#stopforumspam_1d)|7429|7429|53|0.7%|0.2%|
[ri_web_proxies](#ri_web_proxies)|7263|7263|46|0.6%|0.2%|
[xroxy](#xroxy)|2139|2139|43|2.0%|0.2%|
[openbl_60d](#openbl_60d)|7177|7177|43|0.5%|0.2%|
[openbl_30d](#openbl_30d)|2857|2857|36|1.2%|0.1%|
[php_commenters](#php_commenters)|385|385|24|6.2%|0.1%|
[blocklist_de_bots](#blocklist_de_bots)|3443|3443|24|0.6%|0.1%|
[blocklist_de_strongips](#blocklist_de_strongips)|173|173|23|13.2%|0.1%|
[firehol_level1](#firehol_level1)|5148|688978821|22|0.0%|0.1%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|21|0.0%|0.1%|
[et_block](#et_block)|999|18343755|21|0.0%|0.1%|
[proxz](#proxz)|1122|1122|18|1.6%|0.0%|
[et_compromised](#et_compromised)|1678|1678|10|0.5%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1718|1718|9|0.5%|0.0%|
[openbl_7d](#openbl_7d)|813|813|7|0.8%|0.0%|
[php_harvesters](#php_harvesters)|366|366|5|1.3%|0.0%|
[shunlist](#shunlist)|1279|1279|4|0.3%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|4|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|4|0.0%|0.0%|
[et_tor](#et_tor)|6400|6400|4|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2644|2644|3|0.1%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|2|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|1|0.0%|0.0%|
[proxyrss](#proxyrss)|1212|1212|1|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|1|0.1%|0.0%|
[dm_tor](#dm_tor)|6417|6417|1|0.0%|0.0%|
[ciarmy](#ciarmy)|447|447|1|0.2%|0.0%|
[bm_tor](#bm_tor)|6416|6416|1|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|517|517|1|0.1%|0.0%|

## blocklist_de_sip

[Blocklist.de](https://www.blocklist.de/) All IP addresses that tried to login in a SIP, VOIP or Asterisk Server and are included in the IPs list from [infiltrated.net](www.infiltrated.net)

Source is downloaded from [this link](http://lists.blocklist.de/lists/sip.txt).

The last time downloaded was found to be dated: Tue Jun  9 12:14:06 UTC 2015.

The ipset `blocklist_de_sip` has **86** entries, **86** unique IPs.

The following table shows the overlaps of `blocklist_de_sip` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_sip`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_sip`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_sip`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|26299|37969|67|0.1%|77.9%|
[blocklist_de](#blocklist_de)|31902|31902|67|0.2%|77.9%|
[voipbl](#voipbl)|10507|10919|26|0.2%|30.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|16|0.0%|18.6%|
[alienvault_reputation](#alienvault_reputation)|182730|182730|16|0.0%|18.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|6|0.0%|6.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|6|0.0%|6.9%|
[firehol_level3](#firehol_level3)|108375|9625859|3|0.0%|3.4%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|2|0.0%|2.3%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|2|0.0%|2.3%|
[firehol_level1](#firehol_level1)|5148|688978821|2|0.0%|2.3%|
[et_block](#et_block)|999|18343755|2|0.0%|2.3%|
[shunlist](#shunlist)|1279|1279|1|0.0%|1.1%|
[et_botcc](#et_botcc)|509|509|1|0.1%|1.1%|

## blocklist_de_ssh

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service SSH.

Source is downloaded from [this link](http://lists.blocklist.de/lists/ssh.txt).

The last time downloaded was found to be dated: Tue Jun  9 12:09:19 UTC 2015.

The ipset `blocklist_de_ssh` has **2511** entries, **2511** unique IPs.

The following table shows the overlaps of `blocklist_de_ssh` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_ssh`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_ssh`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_ssh`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|26299|37969|2506|6.6%|99.8%|
[blocklist_de](#blocklist_de)|31902|31902|2506|7.8%|99.8%|
[alienvault_reputation](#alienvault_reputation)|182730|182730|1121|0.6%|44.6%|
[firehol_level3](#firehol_level3)|108375|9625859|1059|0.0%|42.1%|
[openbl_60d](#openbl_60d)|7177|7177|959|13.3%|38.1%|
[openbl_30d](#openbl_30d)|2857|2857|799|27.9%|31.8%|
[bruteforceblocker](#bruteforceblocker)|1718|1718|726|42.2%|28.9%|
[et_compromised](#et_compromised)|1678|1678|639|38.0%|25.4%|
[shunlist](#shunlist)|1279|1279|418|32.6%|16.6%|
[openbl_7d](#openbl_7d)|813|813|394|48.4%|15.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|251|0.0%|9.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|136|0.0%|5.4%|
[firehol_level1](#firehol_level1)|5148|688978821|131|0.0%|5.2%|
[et_block](#et_block)|999|18343755|128|0.0%|5.0%|
[openbl_1d](#openbl_1d)|141|141|122|86.5%|4.8%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|117|0.0%|4.6%|
[dshield](#dshield)|20|5120|83|1.6%|3.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|54|0.0%|2.1%|
[blocklist_de_strongips](#blocklist_de_strongips)|173|173|27|15.6%|1.0%|
[stopforumspam_30d](#stopforumspam_30d)|92512|92512|13|0.0%|0.5%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|6|0.0%|0.2%|
[stopforumspam_7d](#stopforumspam_7d)|29277|29277|3|0.0%|0.1%|
[voipbl](#voipbl)|10507|10919|2|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|2|0.0%|0.0%|
[nixspam](#nixspam)|20501|20501|2|0.0%|0.0%|
[sslbl](#sslbl)|379|379|1|0.2%|0.0%|
[snort_ipfilter](#snort_ipfilter)|10116|10116|1|0.0%|0.0%|
[php_spammers](#php_spammers)|661|661|1|0.1%|0.0%|
[php_commenters](#php_commenters)|385|385|1|0.2%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|1|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|1|0.0%|0.0%|
[ciarmy](#ciarmy)|447|447|1|0.2%|0.0%|

## blocklist_de_strongips

[Blocklist.de](https://www.blocklist.de/) All IPs which are older then 2 month and have more then 5.000 attacks.

Source is downloaded from [this link](http://lists.blocklist.de/lists/strongips.txt).

The last time downloaded was found to be dated: Tue Jun  9 12:09:24 UTC 2015.

The ipset `blocklist_de_strongips` has **173** entries, **173** unique IPs.

The following table shows the overlaps of `blocklist_de_strongips` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_strongips`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_strongips`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_strongips`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|26299|37969|173|0.4%|100.0%|
[blocklist_de](#blocklist_de)|31902|31902|172|0.5%|99.4%|
[firehol_level3](#firehol_level3)|108375|9625859|154|0.0%|89.0%|
[stopforumspam_30d](#stopforumspam_30d)|92512|92512|126|0.1%|72.8%|
[blocklist_de_bots](#blocklist_de_bots)|3443|3443|126|3.6%|72.8%|
[stopforumspam_7d](#stopforumspam_7d)|29277|29277|113|0.3%|65.3%|
[stopforumspam_1d](#stopforumspam_1d)|7429|7429|107|1.4%|61.8%|
[php_commenters](#php_commenters)|385|385|41|10.6%|23.6%|
[blocklist_de_apache](#blocklist_de_apache)|16300|16300|35|0.2%|20.2%|
[alienvault_reputation](#alienvault_reputation)|182730|182730|35|0.0%|20.2%|
[blocklist_de_ssh](#blocklist_de_ssh)|2511|2511|27|1.0%|15.6%|
[openbl_60d](#openbl_60d)|7177|7177|25|0.3%|14.4%|
[openbl_30d](#openbl_30d)|2857|2857|25|0.8%|14.4%|
[openbl_7d](#openbl_7d)|813|813|24|2.9%|13.8%|
[blocklist_de_mail](#blocklist_de_mail)|20132|20132|23|0.1%|13.2%|
[shunlist](#shunlist)|1279|1279|22|1.7%|12.7%|
[openbl_1d](#openbl_1d)|141|141|17|12.0%|9.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|17|0.0%|9.8%|
[firehol_level1](#firehol_level1)|5148|688978821|10|0.0%|5.7%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4930|4930|8|0.1%|4.6%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|6|0.0%|3.4%|
[php_spammers](#php_spammers)|661|661|6|0.9%|3.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|6|0.0%|3.4%|
[et_block](#et_block)|999|18343755|6|0.0%|3.4%|
[xroxy](#xroxy)|2139|2139|5|0.2%|2.8%|
[firehol_proxies](#firehol_proxies)|11509|11733|5|0.0%|2.8%|
[firehol_anonymous](#firehol_anonymous)|17940|81947|5|0.0%|2.8%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|4|0.0%|2.3%|
[ri_web_proxies](#ri_web_proxies)|7263|7263|4|0.0%|2.3%|
[proxyrss](#proxyrss)|1212|1212|4|0.3%|2.3%|
[php_dictionary](#php_dictionary)|666|666|4|0.6%|2.3%|
[nixspam](#nixspam)|20501|20501|4|0.0%|2.3%|
[proxz](#proxz)|1122|1122|3|0.2%|1.7%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|1.7%|
[snort_ipfilter](#snort_ipfilter)|10116|10116|2|0.0%|1.1%|
[php_harvesters](#php_harvesters)|366|366|2|0.5%|1.1%|
[blocklist_de_ftp](#blocklist_de_ftp)|517|517|2|0.3%|1.1%|
[dshield](#dshield)|20|5120|1|0.0%|0.5%|

## bm_tor

[torstatus.blutmagie.de](https://torstatus.blutmagie.de) list of all TOR network servers

Source is downloaded from [this link](https://torstatus.blutmagie.de/ip_list_all.php/Tor_ip_list_ALL.csv).

The last time downloaded was found to be dated: Tue Jun  9 12:27:03 UTC 2015.

The ipset `bm_tor` has **6416** entries, **6416** unique IPs.

The following table shows the overlaps of `bm_tor` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `bm_tor`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `bm_tor`.
- ` this % ` is the percentage **of this ipset (`bm_tor`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_anonymous](#firehol_anonymous)|17940|81947|6416|7.8%|100.0%|
[dm_tor](#dm_tor)|6417|6417|6354|99.0%|99.0%|
[et_tor](#et_tor)|6400|6400|5693|88.9%|88.7%|
[firehol_level3](#firehol_level3)|108375|9625859|1076|0.0%|16.7%|
[snort_ipfilter](#snort_ipfilter)|10116|10116|1038|10.2%|16.1%|
[stopforumspam_30d](#stopforumspam_30d)|92512|92512|633|0.6%|9.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|614|0.0%|9.5%|
[stopforumspam_7d](#stopforumspam_7d)|29277|29277|520|1.7%|8.1%|
[stopforumspam_1d](#stopforumspam_1d)|7429|7429|351|4.7%|5.4%|
[firehol_level2](#firehol_level2)|26299|37969|351|0.9%|5.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|182|0.0%|2.8%|
[firehol_proxies](#firehol_proxies)|11509|11733|167|1.4%|2.6%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|164|44.0%|2.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|164|0.0%|2.5%|
[php_commenters](#php_commenters)|385|385|43|11.1%|0.6%|
[alienvault_reputation](#alienvault_reputation)|182730|182730|41|0.0%|0.6%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|22|0.0%|0.3%|
[openbl_60d](#openbl_60d)|7177|7177|20|0.2%|0.3%|
[php_harvesters](#php_harvesters)|366|366|7|1.9%|0.1%|
[blocklist_de](#blocklist_de)|31902|31902|6|0.0%|0.0%|
[et_block](#et_block)|999|18343755|5|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|16300|16300|5|0.0%|0.0%|
[php_spammers](#php_spammers)|661|661|4|0.6%|0.0%|
[nixspam](#nixspam)|20501|20501|4|0.0%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|4|0.0%|0.0%|
[firehol_level1](#firehol_level1)|5148|688978821|4|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4930|4930|4|0.0%|0.0%|
[voipbl](#voipbl)|10507|10919|3|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|3|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7263|7263|3|0.0%|0.0%|
[php_dictionary](#php_dictionary)|666|666|3|0.4%|0.0%|
[xroxy](#xroxy)|2139|2139|1|0.0%|0.0%|
[shunlist](#shunlist)|1279|1279|1|0.0%|0.0%|
[dshield](#dshield)|20|5120|1|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|20132|20132|1|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3443|3443|1|0.0%|0.0%|

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
[firehol_level1](#firehol_level1)|5148|688978821|592708608|86.0%|100.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|4194304|3.0%|0.7%|
[voipbl](#voipbl)|10507|10919|319|2.9%|0.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|5|0.0%|0.0%|
[firehol_level3](#firehol_level3)|108375|9625859|4|0.0%|0.0%|
[php_harvesters](#php_harvesters)|366|366|1|0.2%|0.0%|
[php_commenters](#php_commenters)|385|385|1|0.2%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.0%|
[ciarmy](#ciarmy)|447|447|1|0.2%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1718|1718|1|0.0%|0.0%|

## bruteforceblocker

[danger.rulez.sk](http://danger.rulez.sk/) IPs detected by [bruteforceblocker](http://danger.rulez.sk/index.php/bruteforceblocker/) (fail2ban alternative for SSH on OpenBSD). This is an automatically generated list from users reporting failed authentication attempts. An IP seems to be included if 3 or more users report it. Its retention pocily seems 30 days.

Source is downloaded from [this link](http://danger.rulez.sk/projects/bruteforceblocker/blist.php).

The last time downloaded was found to be dated: Tue Jun  9 12:00:23 UTC 2015.

The ipset `bruteforceblocker` has **1718** entries, **1718** unique IPs.

The following table shows the overlaps of `bruteforceblocker` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `bruteforceblocker`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `bruteforceblocker`.
- ` this % ` is the percentage **of this ipset (`bruteforceblocker`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level3](#firehol_level3)|108375|9625859|1718|0.0%|100.0%|
[et_compromised](#et_compromised)|1678|1678|1614|96.1%|93.9%|
[alienvault_reputation](#alienvault_reputation)|182730|182730|1103|0.6%|64.2%|
[openbl_60d](#openbl_60d)|7177|7177|1000|13.9%|58.2%|
[openbl_30d](#openbl_30d)|2857|2857|939|32.8%|54.6%|
[firehol_level2](#firehol_level2)|26299|37969|739|1.9%|43.0%|
[blocklist_de](#blocklist_de)|31902|31902|737|2.3%|42.8%|
[blocklist_de_ssh](#blocklist_de_ssh)|2511|2511|726|28.9%|42.2%|
[shunlist](#shunlist)|1279|1279|440|34.4%|25.6%|
[openbl_7d](#openbl_7d)|813|813|325|39.9%|18.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|152|0.0%|8.8%|
[firehol_level1](#firehol_level1)|5148|688978821|108|0.0%|6.2%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|101|0.0%|5.8%|
[et_block](#et_block)|999|18343755|101|0.0%|5.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|87|0.0%|5.0%|
[openbl_1d](#openbl_1d)|141|141|72|51.0%|4.1%|
[dshield](#dshield)|20|5120|65|1.2%|3.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|52|0.0%|3.0%|
[stopforumspam_30d](#stopforumspam_30d)|92512|92512|13|0.0%|0.7%|
[blocklist_de_mail](#blocklist_de_mail)|20132|20132|9|0.0%|0.5%|
[blocklist_de_imap](#blocklist_de_imap)|2743|2743|7|0.2%|0.4%|
[stopforumspam_7d](#stopforumspam_7d)|29277|29277|5|0.0%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|5|0.0%|0.2%|
[firehol_proxies](#firehol_proxies)|11509|11733|3|0.0%|0.1%|
[firehol_anonymous](#firehol_anonymous)|17940|81947|3|0.0%|0.1%|
[voipbl](#voipbl)|10507|10919|2|0.0%|0.1%|
[proxz](#proxz)|1122|1122|2|0.1%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|2|0.0%|0.1%|
[blocklist_de_ftp](#blocklist_de_ftp)|517|517|2|0.3%|0.1%|
[xroxy](#xroxy)|2139|2139|1|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7429|7429|1|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|10116|10116|1|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7263|7263|1|0.0%|0.0%|
[php_spammers](#php_spammers)|661|661|1|0.1%|0.0%|
[php_commenters](#php_commenters)|385|385|1|0.2%|0.0%|
[nixspam](#nixspam)|20501|20501|1|0.0%|0.0%|
[fullbogons](#fullbogons)|3778|670299624|1|0.0%|0.0%|
[ciarmy](#ciarmy)|447|447|1|0.2%|0.0%|
[bogons](#bogons)|13|592708608|1|0.0%|0.0%|

## ciarmy

[CIArmy.com](http://ciarmy.com/) IPs with poor Rogue Packet score that have not yet been identified as malicious by the community

Source is downloaded from [this link](http://cinsscore.com/list/ci-badguys.txt).

The last time downloaded was found to be dated: Tue Jun  9 10:15:17 UTC 2015.

The ipset `ciarmy` has **447** entries, **447** unique IPs.

The following table shows the overlaps of `ciarmy` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ciarmy`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ciarmy`.
- ` this % ` is the percentage **of this ipset (`ciarmy`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level3](#firehol_level3)|108375|9625859|447|0.0%|100.0%|
[alienvault_reputation](#alienvault_reputation)|182730|182730|434|0.2%|97.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|95|0.0%|21.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|46|0.0%|10.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|36|0.0%|8.0%|
[shunlist](#shunlist)|1279|1279|34|2.6%|7.6%|
[firehol_level2](#firehol_level2)|26299|37969|33|0.0%|7.3%|
[blocklist_de](#blocklist_de)|31902|31902|33|0.1%|7.3%|
[blocklist_de_apache](#blocklist_de_apache)|16300|16300|30|0.1%|6.7%|
[et_block](#et_block)|999|18343755|4|0.0%|0.8%|
[voipbl](#voipbl)|10507|10919|2|0.0%|0.4%|
[stopforumspam_30d](#stopforumspam_30d)|92512|92512|2|0.0%|0.4%|
[stopforumspam_7d](#stopforumspam_7d)|29277|29277|1|0.0%|0.2%|
[openbl_7d](#openbl_7d)|813|813|1|0.1%|0.2%|
[openbl_60d](#openbl_60d)|7177|7177|1|0.0%|0.2%|
[openbl_30d](#openbl_30d)|2857|2857|1|0.0%|0.2%|
[openbl_1d](#openbl_1d)|141|141|1|0.7%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.2%|
[fullbogons](#fullbogons)|3778|670299624|1|0.0%|0.2%|
[firehol_level1](#firehol_level1)|5148|688978821|1|0.0%|0.2%|
[et_compromised](#et_compromised)|1678|1678|1|0.0%|0.2%|
[bruteforceblocker](#bruteforceblocker)|1718|1718|1|0.0%|0.2%|
[bogons](#bogons)|13|592708608|1|0.0%|0.2%|
[blocklist_de_ssh](#blocklist_de_ssh)|2511|2511|1|0.0%|0.2%|
[blocklist_de_mail](#blocklist_de_mail)|20132|20132|1|0.0%|0.2%|
[blocklist_de_imap](#blocklist_de_imap)|2743|2743|1|0.0%|0.2%|
[blocklist_de_ftp](#blocklist_de_ftp)|517|517|1|0.1%|0.2%|

## cleanmx_viruses

[Clean-MX.de](http://support.clean-mx.de/clean-mx/viruses.php) IPs with viruses

Source is downloaded from [this link](http://support.clean-mx.de/clean-mx/xmlviruses.php?sort=id%20desc&response=alive).

The last time downloaded was found to be dated: Tue Jun  9 08:36:16 UTC 2015.

The ipset `cleanmx_viruses` has **6** entries, **6** unique IPs.

The following table shows the overlaps of `cleanmx_viruses` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `cleanmx_viruses`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `cleanmx_viruses`.
- ` this % ` is the percentage **of this ipset (`cleanmx_viruses`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level3](#firehol_level3)|108375|9625859|6|0.0%|100.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|1|0.0%|16.6%|
[malc0de](#malc0de)|342|342|1|0.2%|16.6%|
[alienvault_reputation](#alienvault_reputation)|182730|182730|1|0.0%|16.6%|

## dm_tor

[dan.me.uk](https://www.dan.me.uk) dynamic list of TOR exit points

Source is downloaded from [this link](https://www.dan.me.uk/torlist/).

The last time downloaded was found to be dated: Tue Jun  9 12:09:10 UTC 2015.

The ipset `dm_tor` has **6417** entries, **6417** unique IPs.

The following table shows the overlaps of `dm_tor` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `dm_tor`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `dm_tor`.
- ` this % ` is the percentage **of this ipset (`dm_tor`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_anonymous](#firehol_anonymous)|17940|81947|6417|7.8%|100.0%|
[bm_tor](#bm_tor)|6416|6416|6354|99.0%|99.0%|
[et_tor](#et_tor)|6400|6400|5686|88.8%|88.6%|
[firehol_level3](#firehol_level3)|108375|9625859|1075|0.0%|16.7%|
[snort_ipfilter](#snort_ipfilter)|10116|10116|1037|10.2%|16.1%|
[stopforumspam_30d](#stopforumspam_30d)|92512|92512|634|0.6%|9.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|614|0.0%|9.5%|
[stopforumspam_7d](#stopforumspam_7d)|29277|29277|522|1.7%|8.1%|
[stopforumspam_1d](#stopforumspam_1d)|7429|7429|351|4.7%|5.4%|
[firehol_level2](#firehol_level2)|26299|37969|351|0.9%|5.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|183|0.0%|2.8%|
[firehol_proxies](#firehol_proxies)|11509|11733|167|1.4%|2.6%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|164|44.0%|2.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|164|0.0%|2.5%|
[php_commenters](#php_commenters)|385|385|43|11.1%|0.6%|
[alienvault_reputation](#alienvault_reputation)|182730|182730|41|0.0%|0.6%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|22|0.0%|0.3%|
[openbl_60d](#openbl_60d)|7177|7177|20|0.2%|0.3%|
[php_harvesters](#php_harvesters)|366|366|7|1.9%|0.1%|
[blocklist_de](#blocklist_de)|31902|31902|6|0.0%|0.0%|
[nixspam](#nixspam)|20501|20501|5|0.0%|0.0%|
[et_block](#et_block)|999|18343755|5|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|16300|16300|5|0.0%|0.0%|
[php_spammers](#php_spammers)|661|661|4|0.6%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|4|0.0%|0.0%|
[firehol_level1](#firehol_level1)|5148|688978821|4|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4930|4930|4|0.0%|0.0%|
[voipbl](#voipbl)|10507|10919|3|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|3|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7263|7263|3|0.0%|0.0%|
[php_dictionary](#php_dictionary)|666|666|3|0.4%|0.0%|
[xroxy](#xroxy)|2139|2139|1|0.0%|0.0%|
[shunlist](#shunlist)|1279|1279|1|0.0%|0.0%|
[dshield](#dshield)|20|5120|1|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|20132|20132|1|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3443|3443|1|0.0%|0.0%|

## dshield

[DShield.org](https://dshield.org/) top 20 attacking class C (/24) subnets over the last three days - **excellent list**

Source is downloaded from [this link](http://feeds.dshield.org/block.txt).

The last time downloaded was found to be dated: Tue Jun  9 11:56:30 UTC 2015.

The ipset `dshield` has **20** entries, **5120** unique IPs.

The following table shows the overlaps of `dshield` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `dshield`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `dshield`.
- ` this % ` is the percentage **of this ipset (`dshield`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level1](#firehol_level1)|5148|688978821|5120|0.0%|100.0%|
[alienvault_reputation](#alienvault_reputation)|182730|182730|2561|1.4%|50.0%|
[et_block](#et_block)|999|18343755|1792|0.0%|35.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|1280|0.0%|25.0%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|512|0.0%|10.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|512|0.0%|10.0%|
[firehol_level3](#firehol_level3)|108375|9625859|115|0.0%|2.2%|
[openbl_60d](#openbl_60d)|7177|7177|113|1.5%|2.2%|
[openbl_30d](#openbl_30d)|2857|2857|101|3.5%|1.9%|
[shunlist](#shunlist)|1279|1279|97|7.5%|1.8%|
[firehol_level2](#firehol_level2)|26299|37969|85|0.2%|1.6%|
[blocklist_de](#blocklist_de)|31902|31902|85|0.2%|1.6%|
[blocklist_de_ssh](#blocklist_de_ssh)|2511|2511|83|3.3%|1.6%|
[et_compromised](#et_compromised)|1678|1678|65|3.8%|1.2%|
[bruteforceblocker](#bruteforceblocker)|1718|1718|65|3.7%|1.2%|
[openbl_7d](#openbl_7d)|813|813|17|2.0%|0.3%|
[openbl_1d](#openbl_1d)|141|141|11|7.8%|0.2%|
[malc0de](#malc0de)|342|342|2|0.5%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|16300|16300|2|0.0%|0.0%|
[voipbl](#voipbl)|10507|10919|1|0.0%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92512|92512|1|0.0%|0.0%|
[nixspam](#nixspam)|20501|20501|1|0.0%|0.0%|
[firehol_anonymous](#firehol_anonymous)|17940|81947|1|0.0%|0.0%|
[et_tor](#et_tor)|6400|6400|1|0.0%|0.0%|
[et_botcc](#et_botcc)|509|509|1|0.1%|0.0%|
[dm_tor](#dm_tor)|6417|6417|1|0.0%|0.0%|
[bm_tor](#bm_tor)|6416|6416|1|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|173|173|1|0.5%|0.0%|

## et_block

[EmergingThreats.net](http://www.emergingthreats.net/) default blacklist (at the time of writing includes spamhaus DROP, dshield and abuse.ch trackers, which are available separately too - prefer to use the direct ipsets instead of this, they seem to lag a bit in updates)

Source is downloaded from [this link](http://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt).

The last time downloaded was found to be dated: Mon Jun  8 04:30:01 UTC 2015.

The ipset `et_block` has **999** entries, **18343755** unique IPs.

The following table shows the overlaps of `et_block` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `et_block`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `et_block`.
- ` this % ` is the percentage **of this ipset (`et_block`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level1](#firehol_level1)|5148|688978821|18340165|2.6%|99.9%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|18338560|100.0%|99.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|8533288|2.4%|46.5%|
[firehol_level3](#firehol_level3)|108375|9625859|6933331|72.0%|37.7%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|6932480|75.5%|37.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|2272541|0.2%|12.3%|
[fullbogons](#fullbogons)|3778|670299624|151552|0.0%|0.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|130394|0.0%|0.7%|
[alienvault_reputation](#alienvault_reputation)|182730|182730|5280|2.8%|0.0%|
[dshield](#dshield)|20|5120|1792|35.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1041|0.3%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92512|92512|1011|1.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|517|0.1%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29277|29277|308|1.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|10116|10116|300|2.9%|0.0%|
[firehol_level2](#firehol_level2)|26299|37969|287|0.7%|0.0%|
[openbl_60d](#openbl_60d)|7177|7177|247|3.4%|0.0%|
[zeus](#zeus)|233|233|229|98.2%|0.0%|
[blocklist_de](#blocklist_de)|31902|31902|216|0.6%|0.0%|
[zeus_badips](#zeus_badips)|202|202|202|100.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2511|2511|128|5.0%|0.0%|
[openbl_30d](#openbl_30d)|2857|2857|127|4.4%|0.0%|
[nixspam](#nixspam)|20501|20501|114|0.5%|0.0%|
[shunlist](#shunlist)|1279|1279|104|8.1%|0.0%|
[et_compromised](#et_compromised)|1678|1678|101|6.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1718|1718|101|5.8%|0.0%|
[feodo](#feodo)|103|103|99|96.1%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7429|7429|89|1.1%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3443|3443|57|1.6%|0.0%|
[openbl_7d](#openbl_7d)|813|813|55|6.7%|0.0%|
[sslbl](#sslbl)|379|379|37|9.7%|0.0%|
[php_commenters](#php_commenters)|385|385|30|7.7%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|29|2.2%|0.0%|
[openbl_1d](#openbl_1d)|141|141|27|19.1%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|20132|20132|21|0.1%|0.0%|
[voipbl](#voipbl)|10507|10919|14|0.1%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2743|2743|14|0.5%|0.0%|
[palevo](#palevo)|13|13|13|100.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|9|0.0%|0.0%|
[firehol_anonymous](#firehol_anonymous)|17940|81947|8|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|16300|16300|7|0.0%|0.0%|
[php_dictionary](#php_dictionary)|666|666|6|0.9%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|6|0.4%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|173|173|6|3.4%|0.0%|
[malc0de](#malc0de)|342|342|5|1.4%|0.0%|
[et_tor](#et_tor)|6400|6400|5|0.0%|0.0%|
[dm_tor](#dm_tor)|6417|6417|5|0.0%|0.0%|
[bm_tor](#bm_tor)|6416|6416|5|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4930|4930|5|0.1%|0.0%|
[php_spammers](#php_spammers)|661|661|4|0.6%|0.0%|
[ciarmy](#ciarmy)|447|447|4|0.8%|0.0%|
[firehol_proxies](#firehol_proxies)|11509|11733|3|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|2|0.3%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|86|86|2|2.3%|0.0%|
[php_harvesters](#php_harvesters)|366|366|1|0.2%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[et_botcc](#et_botcc)|509|509|1|0.1%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|517|517|1|0.1%|0.0%|

## et_botcc

[EmergingThreats.net Command and Control IPs](http://doc.emergingthreats.net/bin/view/Main/BotCC) These IPs are updates every 24 hours and should be considered VERY highly reliable indications that a host is communicating with a known and active Bot or Malware command and control server - (although they say this includes abuse.ch trackers, it does not - most probably it is the shadowserver.org C&C list)

Source is downloaded from [this link](http://rules.emergingthreats.net/fwrules/emerging-PIX-CC.rules).

The last time downloaded was found to be dated: Mon Jun  8 04:30:01 UTC 2015.

The ipset `et_botcc` has **509** entries, **509** unique IPs.

The following table shows the overlaps of `et_botcc` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `et_botcc`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `et_botcc`.
- ` this % ` is the percentage **of this ipset (`et_botcc`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|80|0.0%|15.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|40|0.0%|7.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|22|0.0%|4.3%|
[alienvault_reputation](#alienvault_reputation)|182730|182730|5|0.0%|0.9%|
[firehol_level3](#firehol_level3)|108375|9625859|3|0.0%|0.5%|
[firehol_level1](#firehol_level1)|5148|688978821|2|0.0%|0.3%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|1|0.0%|0.1%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|1|0.0%|0.1%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|1|0.0%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.1%|
[et_block](#et_block)|999|18343755|1|0.0%|0.1%|
[dshield](#dshield)|20|5120|1|0.0%|0.1%|
[blocklist_de_sip](#blocklist_de_sip)|86|86|1|1.1%|0.1%|

## et_compromised

[EmergingThreats.net compromised hosts](http://doc.emergingthreats.net/bin/view/Main/CompromisedHost) - (this seems to be based on bruteforceblocker)

Source is downloaded from [this link](http://rules.emergingthreats.net/blockrules/compromised-ips.txt).

The last time downloaded was found to be dated: Mon Jun  8 04:30:07 UTC 2015.

The ipset `et_compromised` has **1678** entries, **1678** unique IPs.

The following table shows the overlaps of `et_compromised` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `et_compromised`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `et_compromised`.
- ` this % ` is the percentage **of this ipset (`et_compromised`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level3](#firehol_level3)|108375|9625859|1636|0.0%|97.4%|
[bruteforceblocker](#bruteforceblocker)|1718|1718|1614|93.9%|96.1%|
[alienvault_reputation](#alienvault_reputation)|182730|182730|1079|0.5%|64.3%|
[openbl_60d](#openbl_60d)|7177|7177|982|13.6%|58.5%|
[openbl_30d](#openbl_30d)|2857|2857|916|32.0%|54.5%|
[firehol_level2](#firehol_level2)|26299|37969|653|1.7%|38.9%|
[blocklist_de](#blocklist_de)|31902|31902|651|2.0%|38.7%|
[blocklist_de_ssh](#blocklist_de_ssh)|2511|2511|639|25.4%|38.0%|
[shunlist](#shunlist)|1279|1279|419|32.7%|24.9%|
[openbl_7d](#openbl_7d)|813|813|309|38.0%|18.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|151|0.0%|8.9%|
[firehol_level1](#firehol_level1)|5148|688978821|107|0.0%|6.3%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|101|0.0%|6.0%|
[et_block](#et_block)|999|18343755|101|0.0%|6.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|86|0.0%|5.1%|
[dshield](#dshield)|20|5120|65|1.2%|3.8%|
[openbl_1d](#openbl_1d)|141|141|60|42.5%|3.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|46|0.0%|2.7%|
[stopforumspam_30d](#stopforumspam_30d)|92512|92512|13|0.0%|0.7%|
[blocklist_de_mail](#blocklist_de_mail)|20132|20132|10|0.0%|0.5%|
[blocklist_de_imap](#blocklist_de_imap)|2743|2743|7|0.2%|0.4%|
[stopforumspam_7d](#stopforumspam_7d)|29277|29277|5|0.0%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|5|0.0%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|3|0.0%|0.1%|
[firehol_proxies](#firehol_proxies)|11509|11733|3|0.0%|0.1%|
[firehol_anonymous](#firehol_anonymous)|17940|81947|3|0.0%|0.1%|
[voipbl](#voipbl)|10507|10919|2|0.0%|0.1%|
[proxz](#proxz)|1122|1122|2|0.1%|0.1%|
[blocklist_de_ftp](#blocklist_de_ftp)|517|517|2|0.3%|0.1%|
[xroxy](#xroxy)|2139|2139|1|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7429|7429|1|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|10116|10116|1|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7263|7263|1|0.0%|0.0%|
[php_spammers](#php_spammers)|661|661|1|0.1%|0.0%|
[php_commenters](#php_commenters)|385|385|1|0.2%|0.0%|
[nixspam](#nixspam)|20501|20501|1|0.0%|0.0%|
[ciarmy](#ciarmy)|447|447|1|0.2%|0.0%|

## et_tor

[EmergingThreats.net](http://www.emergingthreats.net/) [list](http://doc.emergingthreats.net/bin/view/Main/TorRules) of TOR network IPs

Source is downloaded from [this link](http://rules.emergingthreats.net/blockrules/emerging-tor.rules).

The last time downloaded was found to be dated: Mon Jun  8 04:30:08 UTC 2015.

The ipset `et_tor` has **6400** entries, **6400** unique IPs.

The following table shows the overlaps of `et_tor` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `et_tor`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `et_tor`.
- ` this % ` is the percentage **of this ipset (`et_tor`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_anonymous](#firehol_anonymous)|17940|81947|5710|6.9%|89.2%|
[bm_tor](#bm_tor)|6416|6416|5693|88.7%|88.9%|
[dm_tor](#dm_tor)|6417|6417|5686|88.6%|88.8%|
[firehol_level3](#firehol_level3)|108375|9625859|1121|0.0%|17.5%|
[snort_ipfilter](#snort_ipfilter)|10116|10116|1082|10.6%|16.9%|
[stopforumspam_30d](#stopforumspam_30d)|92512|92512|659|0.7%|10.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|623|0.0%|9.7%|
[stopforumspam_7d](#stopforumspam_7d)|29277|29277|544|1.8%|8.5%|
[firehol_level2](#firehol_level2)|26299|37969|358|0.9%|5.5%|
[stopforumspam_1d](#stopforumspam_1d)|7429|7429|354|4.7%|5.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|186|0.0%|2.9%|
[firehol_proxies](#firehol_proxies)|11509|11733|168|1.4%|2.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|166|0.0%|2.5%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|165|44.3%|2.5%|
[php_commenters](#php_commenters)|385|385|43|11.1%|0.6%|
[alienvault_reputation](#alienvault_reputation)|182730|182730|41|0.0%|0.6%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|22|0.0%|0.3%|
[openbl_60d](#openbl_60d)|7177|7177|20|0.2%|0.3%|
[blocklist_de](#blocklist_de)|31902|31902|9|0.0%|0.1%|
[blocklist_de_apache](#blocklist_de_apache)|16300|16300|8|0.0%|0.1%|
[php_harvesters](#php_harvesters)|366|366|7|1.9%|0.1%|
[et_block](#et_block)|999|18343755|5|0.0%|0.0%|
[php_spammers](#php_spammers)|661|661|4|0.6%|0.0%|
[nixspam](#nixspam)|20501|20501|4|0.0%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|4|0.0%|0.0%|
[firehol_level1](#firehol_level1)|5148|688978821|4|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|20132|20132|4|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4930|4930|4|0.0%|0.0%|
[voipbl](#voipbl)|10507|10919|3|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|3|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7263|7263|3|0.0%|0.0%|
[php_dictionary](#php_dictionary)|666|666|3|0.4%|0.0%|
[xroxy](#xroxy)|2139|2139|1|0.0%|0.0%|
[shunlist](#shunlist)|1279|1279|1|0.0%|0.0%|
[dshield](#dshield)|20|5120|1|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3443|3443|1|0.0%|0.0%|

## feodo

[Abuse.ch Feodo tracker](https://feodotracker.abuse.ch) trojan includes IPs which are being used by Feodo (also known as Cridex or Bugat) which commits ebanking fraud - **excellent list**

Source is downloaded from [this link](https://feodotracker.abuse.ch/blocklist/?download=ipblocklist).

The last time downloaded was found to be dated: Tue Jun  9 12:27:10 UTC 2015.

The ipset `feodo` has **103** entries, **103** unique IPs.

The following table shows the overlaps of `feodo` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `feodo`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `feodo`.
- ` this % ` is the percentage **of this ipset (`feodo`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level1](#firehol_level1)|5148|688978821|103|0.0%|100.0%|
[et_block](#et_block)|999|18343755|99|0.0%|96.1%|
[snort_ipfilter](#snort_ipfilter)|10116|10116|81|0.8%|78.6%|
[firehol_level3](#firehol_level3)|108375|9625859|81|0.0%|78.6%|
[sslbl](#sslbl)|379|379|37|9.7%|35.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|11|0.0%|10.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|3|0.0%|2.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|3|0.0%|2.9%|
[alienvault_reputation](#alienvault_reputation)|182730|182730|2|0.0%|1.9%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.9%|

## firehol_anonymous

**FireHOL Anonymous** - Known anonymizing IPs. (includes: firehol_proxies anonymous bm_tor dm_tor)

Source is downloaded from [this link]().

The last time downloaded was found to be dated: Sun Jun  7 22:20:34 UTC 2015.

The ipset `firehol_anonymous` has **17940** entries, **81947** unique IPs.

The following table shows the overlaps of `firehol_anonymous` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `firehol_anonymous`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `firehol_anonymous`.
- ` this % ` is the percentage **of this ipset (`firehol_anonymous`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_proxies](#firehol_proxies)|11509|11733|11733|100.0%|14.3%|
[ri_web_proxies](#ri_web_proxies)|7263|7263|7263|100.0%|8.8%|
[dm_tor](#dm_tor)|6417|6417|6417|100.0%|7.8%|
[bm_tor](#bm_tor)|6416|6416|6416|100.0%|7.8%|
[firehol_level3](#firehol_level3)|108375|9625859|6355|0.0%|7.7%|
[stopforumspam_30d](#stopforumspam_30d)|92512|92512|5845|6.3%|7.1%|
[et_tor](#et_tor)|6400|6400|5710|89.2%|6.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|3417|0.0%|4.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|2877|0.0%|3.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|2832|0.0%|3.4%|
[stopforumspam_7d](#stopforumspam_7d)|29277|29277|2801|9.5%|3.4%|
[ri_connect_proxies](#ri_connect_proxies)|2644|2644|2644|100.0%|3.2%|
[xroxy](#xroxy)|2139|2139|2139|100.0%|2.6%|
[firehol_level2](#firehol_level2)|26299|37969|1324|3.4%|1.6%|
[proxyrss](#proxyrss)|1212|1212|1212|100.0%|1.4%|
[snort_ipfilter](#snort_ipfilter)|10116|10116|1135|11.2%|1.3%|
[proxz](#proxz)|1122|1122|1122|100.0%|1.3%|
[stopforumspam_1d](#stopforumspam_1d)|7429|7429|1010|13.5%|1.2%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|663|100.0%|0.8%|
[blocklist_de](#blocklist_de)|31902|31902|611|1.9%|0.7%|
[blocklist_de_bots](#blocklist_de_bots)|3443|3443|523|15.1%|0.6%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|372|100.0%|0.4%|
[nixspam](#nixspam)|20501|20501|114|0.5%|0.1%|
[php_dictionary](#php_dictionary)|666|666|86|12.9%|0.1%|
[blocklist_de_mail](#blocklist_de_mail)|20132|20132|79|0.3%|0.0%|
[voipbl](#voipbl)|10507|10919|78|0.7%|0.0%|
[php_spammers](#php_spammers)|661|661|73|11.0%|0.0%|
[php_commenters](#php_commenters)|385|385|71|18.4%|0.0%|
[alienvault_reputation](#alienvault_reputation)|182730|182730|55|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|28|0.0%|0.0%|
[openbl_60d](#openbl_60d)|7177|7177|23|0.3%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|15|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|16300|16300|12|0.0%|0.0%|
[php_harvesters](#php_harvesters)|366|366|11|3.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4930|4930|11|0.2%|0.0%|
[firehol_level1](#firehol_level1)|5148|688978821|8|0.0%|0.0%|
[et_block](#et_block)|999|18343755|8|0.0%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|7|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|6|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|173|173|5|2.8%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|3|0.2%|0.0%|
[et_compromised](#et_compromised)|1678|1678|3|0.1%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1718|1718|3|0.1%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2743|2743|2|0.0%|0.0%|
[sslbl](#sslbl)|379|379|1|0.2%|0.0%|
[shunlist](#shunlist)|1279|1279|1|0.0%|0.0%|
[openbl_30d](#openbl_30d)|2857|2857|1|0.0%|0.0%|
[dshield](#dshield)|20|5120|1|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|517|517|1|0.1%|0.0%|

## firehol_level1

**FireHOL Level 1** - Maximum protection without false positives. (includes: fullbogons dshield feodo palevo sslbl zeus spamhaus_drop spamhaus_edrop)

Source is downloaded from [this link]().

The last time downloaded was found to be dated: Sun Jun  7 22:15:43 UTC 2015.

The ipset `firehol_level1` has **5148** entries, **688978821** unique IPs.

The following table shows the overlaps of `firehol_level1` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `firehol_level1`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `firehol_level1`.
- ` this % ` is the percentage **of this ipset (`firehol_level1`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[fullbogons](#fullbogons)|3778|670299624|670299624|100.0%|97.2%|
[bogons](#bogons)|13|592708608|592708608|100.0%|86.0%|
[et_block](#et_block)|999|18343755|18340165|99.9%|2.6%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|18338560|100.0%|2.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|8867716|2.5%|1.2%|
[firehol_level3](#firehol_level3)|108375|9625859|7500191|77.9%|1.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|7498240|81.6%|1.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|4639652|3.3%|0.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|2569250|0.3%|0.3%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|487424|100.0%|0.0%|
[dshield](#dshield)|20|5120|5120|100.0%|0.0%|
[alienvault_reputation](#alienvault_reputation)|182730|182730|3823|2.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1932|0.5%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92512|92512|1088|1.1%|0.0%|
[sslbl](#sslbl)|379|379|379|100.0%|0.0%|
[voipbl](#voipbl)|10507|10919|334|3.0%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29277|29277|316|1.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|10116|10116|299|2.9%|0.0%|
[firehol_level2](#firehol_level2)|26299|37969|295|0.7%|0.0%|
[openbl_60d](#openbl_60d)|7177|7177|283|3.9%|0.0%|
[zeus](#zeus)|233|233|233|100.0%|0.0%|
[blocklist_de](#blocklist_de)|31902|31902|224|0.7%|0.0%|
[zeus_badips](#zeus_badips)|202|202|202|100.0%|0.0%|
[shunlist](#shunlist)|1279|1279|185|14.4%|0.0%|
[openbl_30d](#openbl_30d)|2857|2857|155|5.4%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2511|2511|131|5.2%|0.0%|
[nixspam](#nixspam)|20501|20501|115|0.5%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1718|1718|108|6.2%|0.0%|
[et_compromised](#et_compromised)|1678|1678|107|6.3%|0.0%|
[feodo](#feodo)|103|103|103|100.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7429|7429|90|1.2%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3443|3443|60|1.7%|0.0%|
[openbl_7d](#openbl_7d)|813|813|52|6.3%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|39|3.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|39|2.6%|0.0%|
[php_commenters](#php_commenters)|385|385|37|9.6%|0.0%|
[openbl_1d](#openbl_1d)|141|141|25|17.7%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|20132|20132|22|0.1%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|18|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2743|2743|14|0.5%|0.0%|
[palevo](#palevo)|13|13|13|100.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|173|173|10|5.7%|0.0%|
[firehol_anonymous](#firehol_anonymous)|17940|81947|8|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|16300|16300|8|0.0%|0.0%|
[malc0de](#malc0de)|342|342|7|2.0%|0.0%|
[php_dictionary](#php_dictionary)|666|666|6|0.9%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4930|4930|5|0.1%|0.0%|
[php_spammers](#php_spammers)|661|661|4|0.6%|0.0%|
[et_tor](#et_tor)|6400|6400|4|0.0%|0.0%|
[dm_tor](#dm_tor)|6417|6417|4|0.0%|0.0%|
[bm_tor](#bm_tor)|6416|6416|4|0.0%|0.0%|
[php_harvesters](#php_harvesters)|366|366|3|0.8%|0.0%|
[firehol_proxies](#firehol_proxies)|11509|11733|3|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|2|0.3%|0.0%|
[et_botcc](#et_botcc)|509|509|2|0.3%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|86|86|2|2.3%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7263|7263|1|0.0%|0.0%|
[ciarmy](#ciarmy)|447|447|1|0.2%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|517|517|1|0.1%|0.0%|

## firehol_level2

**FireHOL Level 2** - Maximum protection from attacks took place in the last 48 hours. (includes: openbl_1d blocklist_de stopforumspam_1d)

Source is downloaded from [this link]().

The last time downloaded was found to be dated: Sun Jun  7 22:20:34 UTC 2015.

The ipset `firehol_level2` has **26299** entries, **37969** unique IPs.

The following table shows the overlaps of `firehol_level2` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `firehol_level2`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `firehol_level2`.
- ` this % ` is the percentage **of this ipset (`firehol_level2`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|31902|31902|31902|100.0%|84.0%|
[blocklist_de_mail](#blocklist_de_mail)|20132|20132|20102|99.8%|52.9%|
[blocklist_de_apache](#blocklist_de_apache)|16300|16300|16300|100.0%|42.9%|
[firehol_level3](#firehol_level3)|108375|9625859|8871|0.0%|23.3%|
[stopforumspam_1d](#stopforumspam_1d)|7429|7429|7429|100.0%|19.5%|
[stopforumspam_30d](#stopforumspam_30d)|92512|92512|7417|8.0%|19.5%|
[stopforumspam_7d](#stopforumspam_7d)|29277|29277|6852|23.4%|18.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4930|4930|4930|100.0%|12.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|4195|0.0%|11.0%|
[blocklist_de_bots](#blocklist_de_bots)|3443|3443|3443|100.0%|9.0%|
[blocklist_de_imap](#blocklist_de_imap)|2743|2743|2743|100.0%|7.2%|
[blocklist_de_ssh](#blocklist_de_ssh)|2511|2511|2506|99.8%|6.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|1771|0.0%|4.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|1667|0.0%|4.3%|
[alienvault_reputation](#alienvault_reputation)|182730|182730|1401|0.7%|3.6%|
[firehol_anonymous](#firehol_anonymous)|17940|81947|1324|1.6%|3.4%|
[firehol_proxies](#firehol_proxies)|11509|11733|1111|9.4%|2.9%|
[openbl_60d](#openbl_60d)|7177|7177|1059|14.7%|2.7%|
[openbl_30d](#openbl_30d)|2857|2857|860|30.1%|2.2%|
[nixspam](#nixspam)|20501|20501|777|3.7%|2.0%|
[bruteforceblocker](#bruteforceblocker)|1718|1718|739|43.0%|1.9%|
[et_compromised](#et_compromised)|1678|1678|653|38.9%|1.7%|
[snort_ipfilter](#snort_ipfilter)|10116|10116|652|6.4%|1.7%|
[ri_web_proxies](#ri_web_proxies)|7263|7263|650|8.9%|1.7%|
[blocklist_de_ftp](#blocklist_de_ftp)|517|517|494|95.5%|1.3%|
[shunlist](#shunlist)|1279|1279|462|36.1%|1.2%|
[openbl_7d](#openbl_7d)|813|813|421|51.7%|1.1%|
[proxyrss](#proxyrss)|1212|1212|368|30.3%|0.9%|
[et_tor](#et_tor)|6400|6400|358|5.5%|0.9%|
[dm_tor](#dm_tor)|6417|6417|351|5.4%|0.9%|
[bm_tor](#bm_tor)|6416|6416|351|5.4%|0.9%|
[xroxy](#xroxy)|2139|2139|331|15.4%|0.8%|
[firehol_level1](#firehol_level1)|5148|688978821|295|0.0%|0.7%|
[et_block](#et_block)|999|18343755|287|0.0%|0.7%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|273|0.0%|0.7%|
[proxz](#proxz)|1122|1122|251|22.3%|0.6%|
[php_commenters](#php_commenters)|385|385|178|46.2%|0.4%|
[blocklist_de_strongips](#blocklist_de_strongips)|173|173|173|100.0%|0.4%|
[ri_connect_proxies](#ri_connect_proxies)|2644|2644|159|6.0%|0.4%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|156|41.9%|0.4%|
[openbl_1d](#openbl_1d)|141|141|141|100.0%|0.3%|
[php_dictionary](#php_dictionary)|666|666|107|16.0%|0.2%|
[php_spammers](#php_spammers)|661|661|105|15.8%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|89|0.0%|0.2%|
[dshield](#dshield)|20|5120|85|1.6%|0.2%|
[blocklist_de_sip](#blocklist_de_sip)|86|86|67|77.9%|0.1%|
[php_harvesters](#php_harvesters)|366|366|55|15.0%|0.1%|
[voipbl](#voipbl)|10507|10919|37|0.3%|0.0%|
[ciarmy](#ciarmy)|447|447|33|7.3%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|13|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|11|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|10|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|4|0.6%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|2|0.1%|0.0%|
[zeus_badips](#zeus_badips)|202|202|1|0.4%|0.0%|
[zeus](#zeus)|233|233|1|0.4%|0.0%|
[sslbl](#sslbl)|379|379|1|0.2%|0.0%|

## firehol_level3

**FireHOL Level 3** - All the bad IPs in last 30 days. (includes: openbl_30d stopforumspam_30d virbl malc0de shunlist malwaredomainlist bruteforceblocker ciarmy cleanmx_viruses snort_ipfilter ib_bluetack_spyware ib_bluetack_hijacked ib_bluetack_webexploit php_commenters php_dictionary php_harvesters php_spammers)

Source is downloaded from [this link]().

The last time downloaded was found to be dated: Sun Jun  7 22:20:34 UTC 2015.

The ipset `firehol_level3` has **108375** entries, **9625859** unique IPs.

The following table shows the overlaps of `firehol_level3` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `firehol_level3`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `firehol_level3`.
- ` this % ` is the percentage **of this ipset (`firehol_level3`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|9177856|100.0%|95.3%|
[firehol_level1](#firehol_level1)|5148|688978821|7500191|1.0%|77.9%|
[et_block](#et_block)|999|18343755|6933331|37.7%|72.0%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|6933031|37.8%|72.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|2537307|0.7%|26.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|919949|0.1%|9.5%|
[fullbogons](#fullbogons)|3778|670299624|566693|0.0%|5.8%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|339173|100.0%|3.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|161490|0.1%|1.6%|
[stopforumspam_30d](#stopforumspam_30d)|92512|92512|92512|100.0%|0.9%|
[stopforumspam_7d](#stopforumspam_7d)|29277|29277|29168|99.6%|0.3%|
[snort_ipfilter](#snort_ipfilter)|10116|10116|10116|100.0%|0.1%|
[firehol_level2](#firehol_level2)|26299|37969|8871|23.3%|0.0%|
[firehol_anonymous](#firehol_anonymous)|17940|81947|6355|7.7%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7429|7429|6026|81.1%|0.0%|
[firehol_proxies](#firehol_proxies)|11509|11733|5268|44.8%|0.0%|
[alienvault_reputation](#alienvault_reputation)|182730|182730|5176|2.8%|0.0%|
[blocklist_de](#blocklist_de)|31902|31902|4079|12.7%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7263|7263|3514|48.3%|0.0%|
[openbl_60d](#openbl_60d)|7177|7177|2990|41.6%|0.0%|
[openbl_30d](#openbl_30d)|2857|2857|2857|100.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3443|3443|2374|68.9%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1718|1718|1718|100.0%|0.0%|
[et_compromised](#et_compromised)|1678|1678|1636|97.4%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2644|2644|1502|56.8%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|1450|100.0%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|1288|100.0%|0.0%|
[xroxy](#xroxy)|2139|2139|1279|59.7%|0.0%|
[shunlist](#shunlist)|1279|1279|1279|100.0%|0.0%|
[et_tor](#et_tor)|6400|6400|1121|17.5%|0.0%|
[bm_tor](#bm_tor)|6416|6416|1076|16.7%|0.0%|
[dm_tor](#dm_tor)|6417|6417|1075|16.7%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2511|2511|1059|42.1%|0.0%|
[openbl_7d](#openbl_7d)|813|813|813|100.0%|0.0%|
[proxz](#proxz)|1122|1122|676|60.2%|0.0%|
[php_dictionary](#php_dictionary)|666|666|666|100.0%|0.0%|
[php_spammers](#php_spammers)|661|661|661|100.0%|0.0%|
[proxyrss](#proxyrss)|1212|1212|617|50.9%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|20132|20132|489|2.4%|0.0%|
[nixspam](#nixspam)|20501|20501|472|2.3%|0.0%|
[ciarmy](#ciarmy)|447|447|447|100.0%|0.0%|
[php_commenters](#php_commenters)|385|385|385|100.0%|0.0%|
[php_harvesters](#php_harvesters)|366|366|366|100.0%|0.0%|
[malc0de](#malc0de)|342|342|342|100.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|16300|16300|288|1.7%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|234|62.9%|0.0%|
[zeus](#zeus)|233|233|204|87.5%|0.0%|
[zeus_badips](#zeus_badips)|202|202|180|89.1%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|173|173|154|89.0%|0.0%|
[openbl_1d](#openbl_1d)|141|141|141|100.0%|0.0%|
[dshield](#dshield)|20|5120|115|2.2%|0.0%|
[sslbl](#sslbl)|379|379|96|25.3%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|88|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4930|4930|85|1.7%|0.0%|
[feodo](#feodo)|103|103|81|78.6%|0.0%|
[voipbl](#voipbl)|10507|10919|56|0.5%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2743|2743|51|1.8%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|23|3.4%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|23|0.0%|0.0%|
[virbl](#virbl)|21|21|21|100.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|517|517|18|3.4%|0.0%|
[palevo](#palevo)|13|13|11|84.6%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|6|6|6|100.0%|0.0%|
[bogons](#bogons)|13|592708608|4|0.0%|0.0%|
[et_botcc](#et_botcc)|509|509|3|0.5%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|86|86|3|3.4%|0.0%|

## firehol_proxies

**FireHOL Proxies** - Known open proxies in the last 30 days. (includes: ib_bluetack_proxies maxmind_proxy_fraud proxyrss proxz ri_connect_proxies ri_web_proxies xroxy)

Source is downloaded from [this link]().

The last time downloaded was found to be dated: Sun Jun  7 22:20:34 UTC 2015.

The ipset `firehol_proxies` has **11509** entries, **11733** unique IPs.

The following table shows the overlaps of `firehol_proxies` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `firehol_proxies`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `firehol_proxies`.
- ` this % ` is the percentage **of this ipset (`firehol_proxies`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_anonymous](#firehol_anonymous)|17940|81947|11733|14.3%|100.0%|
[ri_web_proxies](#ri_web_proxies)|7263|7263|7263|100.0%|61.9%|
[firehol_level3](#firehol_level3)|108375|9625859|5268|0.0%|44.8%|
[stopforumspam_30d](#stopforumspam_30d)|92512|92512|5205|5.6%|44.3%|
[ri_connect_proxies](#ri_connect_proxies)|2644|2644|2644|100.0%|22.5%|
[stopforumspam_7d](#stopforumspam_7d)|29277|29277|2397|8.1%|20.4%|
[xroxy](#xroxy)|2139|2139|2139|100.0%|18.2%|
[proxyrss](#proxyrss)|1212|1212|1212|100.0%|10.3%|
[proxz](#proxz)|1122|1122|1122|100.0%|9.5%|
[firehol_level2](#firehol_level2)|26299|37969|1111|2.9%|9.4%|
[stopforumspam_1d](#stopforumspam_1d)|7429|7429|799|10.7%|6.8%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|663|100.0%|5.6%|
[blocklist_de](#blocklist_de)|31902|31902|603|1.8%|5.1%|
[blocklist_de_bots](#blocklist_de_bots)|3443|3443|520|15.1%|4.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|487|0.0%|4.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|373|0.0%|3.1%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|372|100.0%|3.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|271|0.0%|2.3%|
[snort_ipfilter](#snort_ipfilter)|10116|10116|253|2.5%|2.1%|
[et_tor](#et_tor)|6400|6400|168|2.6%|1.4%|
[dm_tor](#dm_tor)|6417|6417|167|2.6%|1.4%|
[bm_tor](#bm_tor)|6416|6416|167|2.6%|1.4%|
[nixspam](#nixspam)|20501|20501|110|0.5%|0.9%|
[php_dictionary](#php_dictionary)|666|666|85|12.7%|0.7%|
[blocklist_de_mail](#blocklist_de_mail)|20132|20132|79|0.3%|0.6%|
[php_spammers](#php_spammers)|661|661|71|10.7%|0.6%|
[php_commenters](#php_commenters)|385|385|65|16.8%|0.5%|
[alienvault_reputation](#alienvault_reputation)|182730|182730|33|0.0%|0.2%|
[openbl_60d](#openbl_60d)|7177|7177|18|0.2%|0.1%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|15|0.0%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|11|0.0%|0.0%|
[php_harvesters](#php_harvesters)|366|366|10|2.7%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|16300|16300|8|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4930|4930|7|0.1%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|173|173|5|2.8%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|3|0.2%|0.0%|
[firehol_level1](#firehol_level1)|5148|688978821|3|0.0%|0.0%|
[et_compromised](#et_compromised)|1678|1678|3|0.1%|0.0%|
[et_block](#et_block)|999|18343755|3|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1718|1718|3|0.1%|0.0%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|2|0.0%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2743|2743|2|0.0%|0.0%|
[voipbl](#voipbl)|10507|10919|1|0.0%|0.0%|
[sslbl](#sslbl)|379|379|1|0.2%|0.0%|
[shunlist](#shunlist)|1279|1279|1|0.0%|0.0%|

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
[firehol_level1](#firehol_level1)|5148|688978821|670299624|97.2%|100.0%|
[bogons](#bogons)|13|592708608|592708608|100.0%|88.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|4237167|3.0%|0.6%|
[firehol_level3](#firehol_level3)|108375|9625859|566693|5.8%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|565760|6.1%|0.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|263817|0.0%|0.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|252159|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|151552|0.8%|0.0%|
[et_block](#et_block)|999|18343755|151552|0.8%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|890|0.2%|0.0%|
[voipbl](#voipbl)|10507|10919|319|2.9%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|33|2.2%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|13|0.0%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|9|0.6%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92512|92512|1|0.0%|0.0%|
[php_harvesters](#php_harvesters)|366|366|1|0.2%|0.0%|
[php_commenters](#php_commenters)|385|385|1|0.2%|0.0%|
[ciarmy](#ciarmy)|447|447|1|0.2%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1718|1718|1|0.0%|0.0%|

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
[firehol_level3](#firehol_level3)|108375|9625859|23|0.0%|0.0%|
[firehol_level1](#firehol_level1)|5148|688978821|18|0.0%|0.0%|
[firehol_proxies](#firehol_proxies)|11509|11733|15|0.1%|0.0%|
[firehol_anonymous](#firehol_anonymous)|17940|81947|15|0.0%|0.0%|
[alienvault_reputation](#alienvault_reputation)|182730|182730|14|0.0%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92512|92512|13|0.0%|0.0%|
[fullbogons](#fullbogons)|3778|670299624|13|0.0%|0.0%|
[nixspam](#nixspam)|20501|20501|11|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|11|1.6%|0.0%|
[firehol_level2](#firehol_level2)|26299|37969|11|0.0%|0.0%|
[blocklist_de](#blocklist_de)|31902|31902|11|0.0%|0.0%|
[et_block](#et_block)|999|18343755|9|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|5|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4930|4930|5|0.1%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|16300|16300|5|0.0%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29277|29277|4|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|10116|10116|4|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7263|7263|4|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|20132|20132|4|0.0%|0.0%|
[xroxy](#xroxy)|2139|2139|3|0.1%|0.0%|
[php_dictionary](#php_dictionary)|666|666|3|0.4%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|3|0.0%|0.0%|
[voipbl](#voipbl)|10507|10919|2|0.0%|0.0%|
[php_harvesters](#php_harvesters)|366|366|2|0.5%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7429|7429|1|0.0%|0.0%|
[proxz](#proxz)|1122|1122|1|0.0%|0.0%|
[php_spammers](#php_spammers)|661|661|1|0.1%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|1|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2511|2511|1|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2743|2743|1|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3443|3443|1|0.0%|0.0%|

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
[firehol_level3](#firehol_level3)|108375|9625859|9177856|95.3%|100.0%|
[firehol_level1](#firehol_level1)|5148|688978821|7498240|1.0%|81.6%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|6932480|37.8%|75.5%|
[et_block](#et_block)|999|18343755|6932480|37.7%|75.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|2526625|0.7%|27.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|904796|0.1%|9.8%|
[fullbogons](#fullbogons)|3778|670299624|565760|0.0%|6.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|145472|0.1%|1.5%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1036|0.3%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92512|92512|719|0.7%|0.0%|
[alienvault_reputation](#alienvault_reputation)|182730|182730|518|0.2%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29277|29277|157|0.5%|0.0%|
[nixspam](#nixspam)|20501|20501|112|0.5%|0.0%|
[firehol_level2](#firehol_level2)|26299|37969|89|0.2%|0.0%|
[blocklist_de](#blocklist_de)|31902|31902|58|0.1%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3443|3443|48|1.3%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7429|7429|37|0.4%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|27|2.0%|0.0%|
[openbl_60d](#openbl_60d)|7177|7177|17|0.2%|0.0%|
[openbl_30d](#openbl_30d)|2857|2857|12|0.4%|0.0%|
[snort_ipfilter](#snort_ipfilter)|10116|10116|11|0.1%|0.0%|
[zeus_badips](#zeus_badips)|202|202|10|4.9%|0.0%|
[zeus](#zeus)|233|233|10|4.2%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|7|0.4%|0.0%|
[firehol_anonymous](#firehol_anonymous)|17940|81947|7|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2511|2511|6|0.2%|0.0%|
[openbl_7d](#openbl_7d)|813|813|5|0.6%|0.0%|
[et_compromised](#et_compromised)|1678|1678|5|0.2%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1718|1718|5|0.2%|0.0%|
[php_dictionary](#php_dictionary)|666|666|4|0.6%|0.0%|
[et_tor](#et_tor)|6400|6400|4|0.0%|0.0%|
[dm_tor](#dm_tor)|6417|6417|4|0.0%|0.0%|
[bm_tor](#bm_tor)|6416|6416|4|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|20132|20132|4|0.0%|0.0%|
[shunlist](#shunlist)|1279|1279|3|0.2%|0.0%|
[php_spammers](#php_spammers)|661|661|3|0.4%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|173|173|3|1.7%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2743|2743|3|0.1%|0.0%|
[openbl_1d](#openbl_1d)|141|141|2|1.4%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|2|0.3%|0.0%|
[firehol_proxies](#firehol_proxies)|11509|11733|2|0.0%|0.0%|
[voipbl](#voipbl)|10507|10919|1|0.0%|0.0%|
[php_harvesters](#php_harvesters)|366|366|1|0.2%|0.0%|
[php_commenters](#php_commenters)|385|385|1|0.2%|0.0%|
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
[firehol_level1](#firehol_level1)|5148|688978821|2569250|0.3%|0.3%|
[et_block](#et_block)|999|18343755|2272541|12.3%|0.2%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|2272265|12.3%|0.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|1354507|0.9%|0.1%|
[firehol_level3](#firehol_level3)|108375|9625859|919949|9.5%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|904796|9.8%|0.1%|
[fullbogons](#fullbogons)|3778|670299624|263817|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|33155|6.8%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|13247|3.9%|0.0%|
[alienvault_reputation](#alienvault_reputation)|182730|182730|4217|2.3%|0.0%|
[firehol_anonymous](#firehol_anonymous)|17940|81947|3417|4.1%|0.0%|
[firehol_level2](#firehol_level2)|26299|37969|1667|4.3%|0.0%|
[blocklist_de](#blocklist_de)|31902|31902|1554|4.8%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92512|92512|1506|1.6%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|20132|20132|1409|6.9%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|16300|16300|1332|8.1%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29277|29277|549|1.8%|0.0%|
[nixspam](#nixspam)|20501|20501|395|1.9%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|394|0.8%|0.0%|
[voipbl](#voipbl)|10507|10919|299|2.7%|0.0%|
[firehol_proxies](#firehol_proxies)|11509|11733|271|2.3%|0.0%|
[openbl_60d](#openbl_60d)|7177|7177|167|2.3%|0.0%|
[et_tor](#et_tor)|6400|6400|166|2.5%|0.0%|
[dm_tor](#dm_tor)|6417|6417|164|2.5%|0.0%|
[bm_tor](#bm_tor)|6416|6416|164|2.5%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7263|7263|144|1.9%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7429|7429|124|1.6%|0.0%|
[snort_ipfilter](#snort_ipfilter)|10116|10116|117|1.1%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|97|6.6%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2644|2644|80|3.0%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|66|5.1%|0.0%|
[openbl_30d](#openbl_30d)|2857|2857|63|2.2%|0.0%|
[xroxy](#xroxy)|2139|2139|58|2.7%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|56|8.4%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2511|2511|54|2.1%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1718|1718|52|3.0%|0.0%|
[et_compromised](#et_compromised)|1678|1678|46|2.7%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4930|4930|42|0.8%|0.0%|
[et_botcc](#et_botcc)|509|509|40|7.8%|0.0%|
[proxz](#proxz)|1122|1122|39|3.4%|0.0%|
[ciarmy](#ciarmy)|447|447|36|8.0%|0.0%|
[proxyrss](#proxyrss)|1212|1212|31|2.5%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3443|3443|31|0.9%|0.0%|
[shunlist](#shunlist)|1279|1279|27|2.1%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2743|2743|26|0.9%|0.0%|
[openbl_7d](#openbl_7d)|813|813|18|2.2%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|17|4.5%|0.0%|
[php_dictionary](#php_dictionary)|666|666|12|1.8%|0.0%|
[php_harvesters](#php_harvesters)|366|366|11|3.0%|0.0%|
[malc0de](#malc0de)|342|342|11|3.2%|0.0%|
[php_spammers](#php_spammers)|661|661|10|1.5%|0.0%|
[php_commenters](#php_commenters)|385|385|10|2.5%|0.0%|
[zeus](#zeus)|233|233|7|3.0%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|86|86|6|6.9%|0.0%|
[bogons](#bogons)|13|592708608|5|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|517|517|5|0.9%|0.0%|
[zeus_badips](#zeus_badips)|202|202|4|1.9%|0.0%|
[openbl_1d](#openbl_1d)|141|141|4|2.8%|0.0%|
[sslbl](#sslbl)|379|379|3|0.7%|0.0%|
[feodo](#feodo)|103|103|3|2.9%|0.0%|
[virbl](#virbl)|21|21|1|4.7%|0.0%|

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
[firehol_level1](#firehol_level1)|5148|688978821|8867716|1.2%|2.5%|
[et_block](#et_block)|999|18343755|8533288|46.5%|2.4%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|8532506|46.5%|2.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|2830203|2.0%|0.8%|
[firehol_level3](#firehol_level3)|108375|9625859|2537307|26.3%|0.7%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2526625|27.5%|0.7%|
[fullbogons](#fullbogons)|3778|670299624|252159|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|98904|20.2%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|7728|2.2%|0.0%|
[alienvault_reputation](#alienvault_reputation)|182730|182730|6258|3.4%|0.0%|
[firehol_anonymous](#firehol_anonymous)|17940|81947|2877|3.5%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92512|92512|2475|2.6%|0.0%|
[firehol_level2](#firehol_level2)|26299|37969|1771|4.6%|0.0%|
[blocklist_de](#blocklist_de)|31902|31902|1606|5.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|20132|20132|1256|6.2%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|16300|16300|1100|6.7%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29277|29277|825|2.8%|0.0%|
[nixspam](#nixspam)|20501|20501|555|2.7%|0.0%|
[dshield](#dshield)|20|5120|512|10.0%|0.0%|
[voipbl](#voipbl)|10507|10919|434|3.9%|0.0%|
[firehol_proxies](#firehol_proxies)|11509|11733|373|3.1%|0.0%|
[openbl_60d](#openbl_60d)|7177|7177|327|4.5%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|226|0.4%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7429|7429|215|2.8%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7263|7263|211|2.9%|0.0%|
[et_tor](#et_tor)|6400|6400|186|2.9%|0.0%|
[dm_tor](#dm_tor)|6417|6417|183|2.8%|0.0%|
[bm_tor](#bm_tor)|6416|6416|182|2.8%|0.0%|
[snort_ipfilter](#snort_ipfilter)|10116|10116|175|1.7%|0.0%|
[openbl_30d](#openbl_30d)|2857|2857|149|5.2%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2511|2511|136|5.4%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3443|3443|122|3.5%|0.0%|
[xroxy](#xroxy)|2139|2139|104|4.8%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2644|2644|102|3.8%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1718|1718|87|5.0%|0.0%|
[et_compromised](#et_compromised)|1678|1678|86|5.1%|0.0%|
[shunlist](#shunlist)|1279|1279|73|5.7%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4930|4930|67|1.3%|0.0%|
[proxyrss](#proxyrss)|1212|1212|63|5.1%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2743|2743|55|2.0%|0.0%|
[php_spammers](#php_spammers)|661|661|52|7.8%|0.0%|
[ciarmy](#ciarmy)|447|447|46|10.2%|0.0%|
[openbl_7d](#openbl_7d)|813|813|45|5.5%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|45|3.1%|0.0%|
[proxz](#proxz)|1122|1122|43|3.8%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|26|2.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|26|3.9%|0.0%|
[php_dictionary](#php_dictionary)|666|666|22|3.3%|0.0%|
[et_botcc](#et_botcc)|509|509|22|4.3%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|21|5.6%|0.0%|
[malc0de](#malc0de)|342|342|20|5.8%|0.0%|
[php_commenters](#php_commenters)|385|385|15|3.8%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|517|517|11|2.1%|0.0%|
[openbl_1d](#openbl_1d)|141|141|10|7.0%|0.0%|
[zeus](#zeus)|233|233|9|3.8%|0.0%|
[php_harvesters](#php_harvesters)|366|366|9|2.4%|0.0%|
[zeus_badips](#zeus_badips)|202|202|8|3.9%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|173|173|6|3.4%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|86|86|6|6.9%|0.0%|
[sslbl](#sslbl)|379|379|5|1.3%|0.0%|
[palevo](#palevo)|13|13|3|23.0%|0.0%|
[feodo](#feodo)|103|103|3|2.9%|0.0%|
[virbl](#virbl)|21|21|2|9.5%|0.0%|

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
[firehol_level1](#firehol_level1)|5148|688978821|4639652|0.6%|3.3%|
[fullbogons](#fullbogons)|3778|670299624|4237167|0.6%|3.0%|
[bogons](#bogons)|13|592708608|4194304|0.7%|3.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|2830203|0.8%|2.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|1354507|0.1%|0.9%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|270785|55.5%|0.1%|
[firehol_level3](#firehol_level3)|108375|9625859|161490|1.6%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|145472|1.5%|0.1%|
[et_block](#et_block)|999|18343755|130394|0.7%|0.0%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|130368|0.7%|0.0%|
[alienvault_reputation](#alienvault_reputation)|182730|182730|14118|7.7%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|9226|2.7%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92512|92512|5744|6.2%|0.0%|
[firehol_level2](#firehol_level2)|26299|37969|4195|11.0%|0.0%|
[blocklist_de](#blocklist_de)|31902|31902|3735|11.7%|0.0%|
[firehol_anonymous](#firehol_anonymous)|17940|81947|2832|3.4%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|20132|20132|2808|13.9%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|16300|16300|2444|14.9%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29277|29277|1893|6.4%|0.0%|
[voipbl](#voipbl)|10507|10919|1600|14.6%|0.0%|
[nixspam](#nixspam)|20501|20501|1451|7.0%|0.0%|
[dshield](#dshield)|20|5120|1280|25.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|1172|2.4%|0.0%|
[openbl_60d](#openbl_60d)|7177|7177|740|10.3%|0.0%|
[et_tor](#et_tor)|6400|6400|623|9.7%|0.0%|
[dm_tor](#dm_tor)|6417|6417|614|9.5%|0.0%|
[bm_tor](#bm_tor)|6416|6416|614|9.5%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7429|7429|534|7.1%|0.0%|
[firehol_proxies](#firehol_proxies)|11509|11733|487|4.1%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4930|4930|349|7.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2743|2743|299|10.9%|0.0%|
[openbl_30d](#openbl_30d)|2857|2857|293|10.2%|0.0%|
[snort_ipfilter](#snort_ipfilter)|10116|10116|263|2.5%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2511|2511|251|9.9%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3443|3443|218|6.3%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7263|7263|204|2.8%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1718|1718|152|8.8%|0.0%|
[et_compromised](#et_compromised)|1678|1678|151|8.9%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|147|11.4%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|125|33.6%|0.0%|
[shunlist](#shunlist)|1279|1279|116|9.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|108|7.4%|0.0%|
[xroxy](#xroxy)|2139|2139|105|4.9%|0.0%|
[openbl_7d](#openbl_7d)|813|813|104|12.7%|0.0%|
[proxz](#proxz)|1122|1122|96|8.5%|0.0%|
[ciarmy](#ciarmy)|447|447|95|21.2%|0.0%|
[et_botcc](#et_botcc)|509|509|80|15.7%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|517|517|78|15.0%|0.0%|
[proxyrss](#proxyrss)|1212|1212|57|4.7%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2644|2644|55|2.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|51|7.6%|0.0%|
[malc0de](#malc0de)|342|342|48|14.0%|0.0%|
[php_spammers](#php_spammers)|661|661|41|6.2%|0.0%|
[php_dictionary](#php_dictionary)|666|666|35|5.2%|0.0%|
[sslbl](#sslbl)|379|379|30|7.9%|0.0%|
[php_commenters](#php_commenters)|385|385|24|6.2%|0.0%|
[php_harvesters](#php_harvesters)|366|366|19|5.1%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|173|173|17|9.8%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|86|86|16|18.6%|0.0%|
[zeus](#zeus)|233|233|14|6.0%|0.0%|
[feodo](#feodo)|103|103|11|10.6%|0.0%|
[zeus_badips](#zeus_badips)|202|202|10|4.9%|0.0%|
[openbl_1d](#openbl_1d)|141|141|10|7.0%|0.0%|
[virbl](#virbl)|21|21|1|4.7%|0.0%|
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
[firehol_proxies](#firehol_proxies)|11509|11733|663|5.6%|100.0%|
[firehol_anonymous](#firehol_anonymous)|17940|81947|663|0.8%|100.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|56|0.0%|8.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|51|0.0%|7.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|26|0.0%|3.9%|
[firehol_level3](#firehol_level3)|108375|9625859|23|0.0%|3.4%|
[stopforumspam_30d](#stopforumspam_30d)|92512|92512|18|0.0%|2.7%|
[ri_web_proxies](#ri_web_proxies)|7263|7263|14|0.1%|2.1%|
[xroxy](#xroxy)|2139|2139|13|0.6%|1.9%|
[stopforumspam_7d](#stopforumspam_7d)|29277|29277|13|0.0%|1.9%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|11|0.0%|1.6%|
[proxyrss](#proxyrss)|1212|1212|9|0.7%|1.3%|
[ri_connect_proxies](#ri_connect_proxies)|2644|2644|7|0.2%|1.0%|
[proxz](#proxz)|1122|1122|6|0.5%|0.9%|
[firehol_level2](#firehol_level2)|26299|37969|4|0.0%|0.6%|
[stopforumspam_1d](#stopforumspam_1d)|7429|7429|3|0.0%|0.4%|
[blocklist_de_bots](#blocklist_de_bots)|3443|3443|3|0.0%|0.4%|
[blocklist_de](#blocklist_de)|31902|31902|3|0.0%|0.4%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|2|0.0%|0.3%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|2|0.1%|0.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2|0.0%|0.3%|
[firehol_level1](#firehol_level1)|5148|688978821|2|0.0%|0.3%|
[et_block](#et_block)|999|18343755|2|0.0%|0.3%|
[snort_ipfilter](#snort_ipfilter)|10116|10116|1|0.0%|0.1%|
[php_dictionary](#php_dictionary)|666|666|1|0.1%|0.1%|
[nixspam](#nixspam)|20501|20501|1|0.0%|0.1%|
[blocklist_de_mail](#blocklist_de_mail)|20132|20132|1|0.0%|0.1%|
[alienvault_reputation](#alienvault_reputation)|182730|182730|1|0.0%|0.1%|

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
[firehol_level3](#firehol_level3)|108375|9625859|339173|3.5%|100.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|13247|0.0%|3.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|9226|0.0%|2.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|7728|0.0%|2.2%|
[firehol_level1](#firehol_level1)|5148|688978821|1932|0.0%|0.5%|
[et_block](#et_block)|999|18343755|1041|0.0%|0.3%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|1037|0.0%|0.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1036|0.0%|0.3%|
[fullbogons](#fullbogons)|3778|670299624|890|0.0%|0.2%|
[alienvault_reputation](#alienvault_reputation)|182730|182730|288|0.1%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92512|92512|48|0.0%|0.0%|
[firehol_anonymous](#firehol_anonymous)|17940|81947|28|0.0%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|27|2.0%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29277|29277|22|0.0%|0.0%|
[et_tor](#et_tor)|6400|6400|22|0.3%|0.0%|
[dm_tor](#dm_tor)|6417|6417|22|0.3%|0.0%|
[bm_tor](#bm_tor)|6416|6416|22|0.3%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|19|1.3%|0.0%|
[snort_ipfilter](#snort_ipfilter)|10116|10116|15|0.1%|0.0%|
[firehol_level2](#firehol_level2)|26299|37969|13|0.0%|0.0%|
[nixspam](#nixspam)|20501|20501|11|0.0%|0.0%|
[firehol_proxies](#firehol_proxies)|11509|11733|11|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7429|7429|9|0.1%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7263|7263|6|0.0%|0.0%|
[openbl_60d](#openbl_60d)|7177|7177|5|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|5|1.3%|0.0%|
[voipbl](#voipbl)|10507|10919|4|0.0%|0.0%|
[blocklist_de](#blocklist_de)|31902|31902|4|0.0%|0.0%|
[openbl_30d](#openbl_30d)|2857|2857|3|0.1%|0.0%|
[malc0de](#malc0de)|342|342|3|0.8%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|3|0.0%|0.0%|
[et_compromised](#et_compromised)|1678|1678|3|0.1%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|16300|16300|3|0.0%|0.0%|
[palevo](#palevo)|13|13|2|15.3%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1718|1718|2|0.1%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|86|86|2|2.3%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|20132|20132|2|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4930|4930|2|0.0%|0.0%|
[zeus_badips](#zeus_badips)|202|202|1|0.4%|0.0%|
[zeus](#zeus)|233|233|1|0.4%|0.0%|
[xroxy](#xroxy)|2139|2139|1|0.0%|0.0%|
[sslbl](#sslbl)|379|379|1|0.2%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|1|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2644|2644|1|0.0%|0.0%|
[proxz](#proxz)|1122|1122|1|0.0%|0.0%|
[proxyrss](#proxyrss)|1212|1212|1|0.0%|0.0%|
[php_harvesters](#php_harvesters)|366|366|1|0.2%|0.0%|
[php_dictionary](#php_dictionary)|666|666|1|0.1%|0.0%|
[php_commenters](#php_commenters)|385|385|1|0.2%|0.0%|
[feodo](#feodo)|103|103|1|0.9%|0.0%|
[ciarmy](#ciarmy)|447|447|1|0.2%|0.0%|
[bogons](#bogons)|13|592708608|1|0.0%|0.0%|

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
[firehol_level3](#firehol_level3)|108375|9625859|1450|0.0%|100.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|108|0.0%|7.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|97|0.0%|6.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|45|0.0%|3.1%|
[firehol_level1](#firehol_level1)|5148|688978821|39|0.0%|2.6%|
[fullbogons](#fullbogons)|3778|670299624|33|0.0%|2.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|19|0.0%|1.3%|
[alienvault_reputation](#alienvault_reputation)|182730|182730|10|0.0%|0.6%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|7|0.0%|0.4%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|6|0.0%|0.4%|
[et_block](#et_block)|999|18343755|6|0.0%|0.4%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|3|0.2%|0.2%|
[firehol_proxies](#firehol_proxies)|11509|11733|3|0.0%|0.2%|
[firehol_anonymous](#firehol_anonymous)|17940|81947|3|0.0%|0.2%|
[stopforumspam_7d](#stopforumspam_7d)|29277|29277|2|0.0%|0.1%|
[stopforumspam_30d](#stopforumspam_30d)|92512|92512|2|0.0%|0.1%|
[openbl_60d](#openbl_60d)|7177|7177|2|0.0%|0.1%|
[openbl_30d](#openbl_30d)|2857|2857|2|0.0%|0.1%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|2|0.3%|0.1%|
[firehol_level2](#firehol_level2)|26299|37969|2|0.0%|0.1%|
[stopforumspam_1d](#stopforumspam_1d)|7429|7429|1|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|10116|10116|1|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7263|7263|1|0.0%|0.0%|
[openbl_7d](#openbl_7d)|813|813|1|0.1%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|1|0.0%|0.0%|
[et_botcc](#et_botcc)|509|509|1|0.1%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2511|2511|1|0.0%|0.0%|
[blocklist_de](#blocklist_de)|31902|31902|1|0.0%|0.0%|

## malc0de

[Malc0de.com](http://malc0de.com) malicious IPs of the last 30 days

Source is downloaded from [this link](http://malc0de.com/bl/IP_Blacklist.txt).

The last time downloaded was found to be dated: Mon Jun  8 13:17:02 UTC 2015.

The ipset `malc0de` has **342** entries, **342** unique IPs.

The following table shows the overlaps of `malc0de` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `malc0de`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `malc0de`.
- ` this % ` is the percentage **of this ipset (`malc0de`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level3](#firehol_level3)|108375|9625859|342|0.0%|100.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|48|0.0%|14.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|20|0.0%|5.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|11|0.0%|3.2%|
[alienvault_reputation](#alienvault_reputation)|182730|182730|11|0.0%|3.2%|
[firehol_level1](#firehol_level1)|5148|688978821|7|0.0%|2.0%|
[et_block](#et_block)|999|18343755|5|0.0%|1.4%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|4|0.0%|1.1%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|4|0.3%|1.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|3|0.0%|0.8%|
[dshield](#dshield)|20|5120|2|0.0%|0.5%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|1|0.0%|0.2%|
[cleanmx_viruses](#cleanmx_viruses)|6|6|1|16.6%|0.2%|

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
[firehol_level3](#firehol_level3)|108375|9625859|1288|0.0%|100.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|147|0.0%|11.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|66|0.0%|5.1%|
[firehol_level1](#firehol_level1)|5148|688978821|39|0.0%|3.0%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|29|0.0%|2.2%|
[et_block](#et_block)|999|18343755|29|0.0%|2.2%|
[snort_ipfilter](#snort_ipfilter)|10116|10116|28|0.2%|2.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|27|0.0%|2.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|27|0.0%|2.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|26|0.0%|2.0%|
[fullbogons](#fullbogons)|3778|670299624|9|0.0%|0.6%|
[alienvault_reputation](#alienvault_reputation)|182730|182730|7|0.0%|0.5%|
[stopforumspam_30d](#stopforumspam_30d)|92512|92512|4|0.0%|0.3%|
[malc0de](#malc0de)|342|342|4|1.1%|0.3%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|3|0.2%|0.2%|
[zeus](#zeus)|233|233|1|0.4%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29277|29277|1|0.0%|0.0%|
[et_botcc](#et_botcc)|509|509|1|0.1%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|6|6|1|16.6%|0.0%|

## maxmind_proxy_fraud

[MaxMind.com](https://www.maxmind.com/en/anonymous-proxy-fraudulent-ip-address-list) list of anonymous proxy fraudelent IP addresses.

Source is downloaded from [this link](https://www.maxmind.com/en/anonymous-proxy-fraudulent-ip-address-list).

The last time downloaded was found to be dated: Tue Jun  9 09:27:05 UTC 2015.

The ipset `maxmind_proxy_fraud` has **372** entries, **372** unique IPs.

The following table shows the overlaps of `maxmind_proxy_fraud` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `maxmind_proxy_fraud`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `maxmind_proxy_fraud`.
- ` this % ` is the percentage **of this ipset (`maxmind_proxy_fraud`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_proxies](#firehol_proxies)|11509|11733|372|3.1%|100.0%|
[firehol_anonymous](#firehol_anonymous)|17940|81947|372|0.4%|100.0%|
[firehol_level3](#firehol_level3)|108375|9625859|234|0.0%|62.9%|
[stopforumspam_30d](#stopforumspam_30d)|92512|92512|233|0.2%|62.6%|
[stopforumspam_7d](#stopforumspam_7d)|29277|29277|192|0.6%|51.6%|
[snort_ipfilter](#snort_ipfilter)|10116|10116|172|1.7%|46.2%|
[et_tor](#et_tor)|6400|6400|165|2.5%|44.3%|
[dm_tor](#dm_tor)|6417|6417|164|2.5%|44.0%|
[bm_tor](#bm_tor)|6416|6416|164|2.5%|44.0%|
[stopforumspam_1d](#stopforumspam_1d)|7429|7429|156|2.0%|41.9%|
[firehol_level2](#firehol_level2)|26299|37969|156|0.4%|41.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|125|0.0%|33.6%|
[php_commenters](#php_commenters)|385|385|40|10.3%|10.7%|
[alienvault_reputation](#alienvault_reputation)|182730|182730|26|0.0%|6.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|21|0.0%|5.6%|
[openbl_60d](#openbl_60d)|7177|7177|18|0.2%|4.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|17|0.0%|4.5%|
[php_harvesters](#php_harvesters)|366|366|6|1.6%|1.6%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|5|0.0%|1.3%|
[ri_web_proxies](#ri_web_proxies)|7263|7263|4|0.0%|1.0%|
[php_spammers](#php_spammers)|661|661|4|0.6%|1.0%|
[php_dictionary](#php_dictionary)|666|666|4|0.6%|1.0%|
[xroxy](#xroxy)|2139|2139|1|0.0%|0.2%|
[voipbl](#voipbl)|10507|10919|1|0.0%|0.2%|
[shunlist](#shunlist)|1279|1279|1|0.0%|0.2%|
[ri_connect_proxies](#ri_connect_proxies)|2644|2644|1|0.0%|0.2%|
[nixspam](#nixspam)|20501|20501|1|0.0%|0.2%|
[et_block](#et_block)|999|18343755|1|0.0%|0.2%|
[blocklist_de_mail](#blocklist_de_mail)|20132|20132|1|0.0%|0.2%|
[blocklist_de_apache](#blocklist_de_apache)|16300|16300|1|0.0%|0.2%|
[blocklist_de](#blocklist_de)|31902|31902|1|0.0%|0.2%|

## nixspam

[NiX Spam](http://www.heise.de/ix/NiX-Spam-DNSBL-and-blacklist-for-download-499637.html) IP addresses that sent spam in the last hour - automatically generated entries without distinguishing open proxies from relays, dialup gateways, and so on. All IPs are removed after 12 hours if there is no spam from there.

Source is downloaded from [this link](http://www.dnsbl.manitu.net/download/nixspam-ip.dump.gz).

The last time downloaded was found to be dated: Tue Jun  9 12:15:02 UTC 2015.

The ipset `nixspam` has **20501** entries, **20501** unique IPs.

The following table shows the overlaps of `nixspam` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `nixspam`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `nixspam`.
- ` this % ` is the percentage **of this ipset (`nixspam`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|1451|0.0%|7.0%|
[firehol_level2](#firehol_level2)|26299|37969|777|2.0%|3.7%|
[blocklist_de](#blocklist_de)|31902|31902|755|2.3%|3.6%|
[blocklist_de_mail](#blocklist_de_mail)|20132|20132|665|3.3%|3.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|555|0.0%|2.7%|
[firehol_level3](#firehol_level3)|108375|9625859|472|0.0%|2.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|395|0.0%|1.9%|
[stopforumspam_30d](#stopforumspam_30d)|92512|92512|216|0.2%|1.0%|
[snort_ipfilter](#snort_ipfilter)|10116|10116|155|1.5%|0.7%|
[stopforumspam_7d](#stopforumspam_7d)|29277|29277|122|0.4%|0.5%|
[firehol_level1](#firehol_level1)|5148|688978821|115|0.0%|0.5%|
[firehol_anonymous](#firehol_anonymous)|17940|81947|114|0.1%|0.5%|
[et_block](#et_block)|999|18343755|114|0.0%|0.5%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|112|0.0%|0.5%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|112|0.0%|0.5%|
[firehol_proxies](#firehol_proxies)|11509|11733|110|0.9%|0.5%|
[php_dictionary](#php_dictionary)|666|666|105|15.7%|0.5%|
[php_spammers](#php_spammers)|661|661|95|14.3%|0.4%|
[stopforumspam_1d](#stopforumspam_1d)|7429|7429|77|1.0%|0.3%|
[ri_web_proxies](#ri_web_proxies)|7263|7263|73|1.0%|0.3%|
[xroxy](#xroxy)|2139|2139|51|2.3%|0.2%|
[blocklist_de_bots](#blocklist_de_bots)|3443|3443|45|1.3%|0.2%|
[alienvault_reputation](#alienvault_reputation)|182730|182730|39|0.0%|0.1%|
[blocklist_de_apache](#blocklist_de_apache)|16300|16300|37|0.2%|0.1%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4930|4930|36|0.7%|0.1%|
[proxz](#proxz)|1122|1122|33|2.9%|0.1%|
[blocklist_de_imap](#blocklist_de_imap)|2743|2743|22|0.8%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|11|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|11|0.0%|0.0%|
[php_harvesters](#php_harvesters)|366|366|10|2.7%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2644|2644|9|0.3%|0.0%|
[proxyrss](#proxyrss)|1212|1212|8|0.6%|0.0%|
[php_commenters](#php_commenters)|385|385|6|1.5%|0.0%|
[dm_tor](#dm_tor)|6417|6417|5|0.0%|0.0%|
[openbl_60d](#openbl_60d)|7177|7177|4|0.0%|0.0%|
[et_tor](#et_tor)|6400|6400|4|0.0%|0.0%|
[bm_tor](#bm_tor)|6416|6416|4|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|173|173|4|2.3%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|517|517|3|0.5%|0.0%|
[voipbl](#voipbl)|10507|10919|2|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|2|0.0%|0.0%|
[openbl_30d](#openbl_30d)|2857|2857|2|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2511|2511|2|0.0%|0.0%|
[openbl_7d](#openbl_7d)|813|813|1|0.1%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|1|0.1%|0.0%|
[et_compromised](#et_compromised)|1678|1678|1|0.0%|0.0%|
[dshield](#dshield)|20|5120|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1718|1718|1|0.0%|0.0%|

## openbl_1d

[OpenBL.org](http://www.openbl.org/) last 24 hours IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.

Source is downloaded from [this link](http://www.openbl.org/lists/base_1days.txt).

The last time downloaded was found to be dated: Tue Jun  9 11:32:00 UTC 2015.

The ipset `openbl_1d` has **141** entries, **141** unique IPs.

The following table shows the overlaps of `openbl_1d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl_1d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl_1d`.
- ` this % ` is the percentage **of this ipset (`openbl_1d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[openbl_7d](#openbl_7d)|813|813|141|17.3%|100.0%|
[openbl_60d](#openbl_60d)|7177|7177|141|1.9%|100.0%|
[openbl_30d](#openbl_30d)|2857|2857|141|4.9%|100.0%|
[firehol_level3](#firehol_level3)|108375|9625859|141|0.0%|100.0%|
[firehol_level2](#firehol_level2)|26299|37969|141|0.3%|100.0%|
[alienvault_reputation](#alienvault_reputation)|182730|182730|137|0.0%|97.1%|
[blocklist_de](#blocklist_de)|31902|31902|124|0.3%|87.9%|
[blocklist_de_ssh](#blocklist_de_ssh)|2511|2511|122|4.8%|86.5%|
[shunlist](#shunlist)|1279|1279|75|5.8%|53.1%|
[bruteforceblocker](#bruteforceblocker)|1718|1718|72|4.1%|51.0%|
[et_compromised](#et_compromised)|1678|1678|60|3.5%|42.5%|
[et_block](#et_block)|999|18343755|27|0.0%|19.1%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|25|0.0%|17.7%|
[firehol_level1](#firehol_level1)|5148|688978821|25|0.0%|17.7%|
[blocklist_de_strongips](#blocklist_de_strongips)|173|173|17|9.8%|12.0%|
[dshield](#dshield)|20|5120|11|0.2%|7.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|10|0.0%|7.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|10|0.0%|7.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|4|0.0%|2.8%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2|0.0%|1.4%|
[ciarmy](#ciarmy)|447|447|1|0.2%|0.7%|
[blocklist_de_apache](#blocklist_de_apache)|16300|16300|1|0.0%|0.7%|

## openbl_30d

[OpenBL.org](http://www.openbl.org/) last 30 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.

Source is downloaded from [this link](http://www.openbl.org/lists/base_30days.txt).

The last time downloaded was found to be dated: Tue Jun  9 12:07:00 UTC 2015.

The ipset `openbl_30d` has **2857** entries, **2857** unique IPs.

The following table shows the overlaps of `openbl_30d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl_30d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl_30d`.
- ` this % ` is the percentage **of this ipset (`openbl_30d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[openbl_60d](#openbl_60d)|7177|7177|2857|39.8%|100.0%|
[firehol_level3](#firehol_level3)|108375|9625859|2857|0.0%|100.0%|
[alienvault_reputation](#alienvault_reputation)|182730|182730|2839|1.5%|99.3%|
[bruteforceblocker](#bruteforceblocker)|1718|1718|939|54.6%|32.8%|
[et_compromised](#et_compromised)|1678|1678|916|54.5%|32.0%|
[firehol_level2](#firehol_level2)|26299|37969|860|2.2%|30.1%|
[blocklist_de](#blocklist_de)|31902|31902|843|2.6%|29.5%|
[openbl_7d](#openbl_7d)|813|813|813|100.0%|28.4%|
[blocklist_de_ssh](#blocklist_de_ssh)|2511|2511|799|31.8%|27.9%|
[shunlist](#shunlist)|1279|1279|537|41.9%|18.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|293|0.0%|10.2%|
[firehol_level1](#firehol_level1)|5148|688978821|155|0.0%|5.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|149|0.0%|5.2%|
[openbl_1d](#openbl_1d)|141|141|141|100.0%|4.9%|
[et_block](#et_block)|999|18343755|127|0.0%|4.4%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|121|0.0%|4.2%|
[dshield](#dshield)|20|5120|101|1.9%|3.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|63|0.0%|2.2%|
[blocklist_de_mail](#blocklist_de_mail)|20132|20132|36|0.1%|1.2%|
[blocklist_de_imap](#blocklist_de_imap)|2743|2743|29|1.0%|1.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|173|173|25|14.4%|0.8%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|12|0.0%|0.4%|
[snort_ipfilter](#snort_ipfilter)|10116|10116|6|0.0%|0.2%|
[stopforumspam_30d](#stopforumspam_30d)|92512|92512|4|0.0%|0.1%|
[voipbl](#voipbl)|10507|10919|3|0.0%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|3|0.0%|0.1%|
[blocklist_de_ftp](#blocklist_de_ftp)|517|517|3|0.5%|0.1%|
[blocklist_de_apache](#blocklist_de_apache)|16300|16300|3|0.0%|0.1%|
[nixspam](#nixspam)|20501|20501|2|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|2|0.1%|0.0%|
[zeus](#zeus)|233|233|1|0.4%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29277|29277|1|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7429|7429|1|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|1|0.0%|0.0%|
[php_spammers](#php_spammers)|661|661|1|0.1%|0.0%|
[php_commenters](#php_commenters)|385|385|1|0.2%|0.0%|
[firehol_anonymous](#firehol_anonymous)|17940|81947|1|0.0%|0.0%|
[ciarmy](#ciarmy)|447|447|1|0.2%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3443|3443|1|0.0%|0.0%|

## openbl_60d

[OpenBL.org](http://www.openbl.org/) last 60 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.

Source is downloaded from [this link](http://www.openbl.org/lists/base_60days.txt).

The last time downloaded was found to be dated: Tue Jun  9 12:07:00 UTC 2015.

The ipset `openbl_60d` has **7177** entries, **7177** unique IPs.

The following table shows the overlaps of `openbl_60d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl_60d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl_60d`.
- ` this % ` is the percentage **of this ipset (`openbl_60d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[alienvault_reputation](#alienvault_reputation)|182730|182730|7153|3.9%|99.6%|
[firehol_level3](#firehol_level3)|108375|9625859|2990|0.0%|41.6%|
[openbl_30d](#openbl_30d)|2857|2857|2857|100.0%|39.8%|
[firehol_level2](#firehol_level2)|26299|37969|1059|2.7%|14.7%|
[blocklist_de](#blocklist_de)|31902|31902|1022|3.2%|14.2%|
[bruteforceblocker](#bruteforceblocker)|1718|1718|1000|58.2%|13.9%|
[et_compromised](#et_compromised)|1678|1678|982|58.5%|13.6%|
[blocklist_de_ssh](#blocklist_de_ssh)|2511|2511|959|38.1%|13.3%|
[openbl_7d](#openbl_7d)|813|813|813|100.0%|11.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|740|0.0%|10.3%|
[shunlist](#shunlist)|1279|1279|565|44.1%|7.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|327|0.0%|4.5%|
[firehol_level1](#firehol_level1)|5148|688978821|283|0.0%|3.9%|
[et_block](#et_block)|999|18343755|247|0.0%|3.4%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|236|0.0%|3.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|167|0.0%|2.3%|
[openbl_1d](#openbl_1d)|141|141|141|100.0%|1.9%|
[dshield](#dshield)|20|5120|113|2.2%|1.5%|
[stopforumspam_30d](#stopforumspam_30d)|92512|92512|51|0.0%|0.7%|
[blocklist_de_mail](#blocklist_de_mail)|20132|20132|43|0.2%|0.5%|
[blocklist_de_imap](#blocklist_de_imap)|2743|2743|34|1.2%|0.4%|
[snort_ipfilter](#snort_ipfilter)|10116|10116|28|0.2%|0.3%|
[blocklist_de_strongips](#blocklist_de_strongips)|173|173|25|14.4%|0.3%|
[stopforumspam_7d](#stopforumspam_7d)|29277|29277|24|0.0%|0.3%|
[firehol_anonymous](#firehol_anonymous)|17940|81947|23|0.0%|0.3%|
[stopforumspam_1d](#stopforumspam_1d)|7429|7429|21|0.2%|0.2%|
[et_tor](#et_tor)|6400|6400|20|0.3%|0.2%|
[dm_tor](#dm_tor)|6417|6417|20|0.3%|0.2%|
[bm_tor](#bm_tor)|6416|6416|20|0.3%|0.2%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|18|4.8%|0.2%|
[firehol_proxies](#firehol_proxies)|11509|11733|18|0.1%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|17|0.0%|0.2%|
[blocklist_de_bots](#blocklist_de_bots)|3443|3443|13|0.3%|0.1%|
[php_commenters](#php_commenters)|385|385|10|2.5%|0.1%|
[voipbl](#voipbl)|10507|10919|8|0.0%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|5|0.0%|0.0%|
[nixspam](#nixspam)|20501|20501|4|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|517|517|3|0.5%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|16300|16300|3|0.0%|0.0%|
[zeus](#zeus)|233|233|2|0.8%|0.0%|
[php_harvesters](#php_harvesters)|366|366|2|0.5%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|2|0.1%|0.0%|
[zeus_badips](#zeus_badips)|202|202|1|0.4%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|1|0.0%|0.0%|
[php_spammers](#php_spammers)|661|661|1|0.1%|0.0%|
[ciarmy](#ciarmy)|447|447|1|0.2%|0.0%|

## openbl_7d

[OpenBL.org](http://www.openbl.org/) last 7 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.

Source is downloaded from [this link](http://www.openbl.org/lists/base_7days.txt).

The last time downloaded was found to be dated: Tue Jun  9 12:07:00 UTC 2015.

The ipset `openbl_7d` has **813** entries, **813** unique IPs.

The following table shows the overlaps of `openbl_7d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl_7d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl_7d`.
- ` this % ` is the percentage **of this ipset (`openbl_7d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[openbl_60d](#openbl_60d)|7177|7177|813|11.3%|100.0%|
[openbl_30d](#openbl_30d)|2857|2857|813|28.4%|100.0%|
[firehol_level3](#firehol_level3)|108375|9625859|813|0.0%|100.0%|
[alienvault_reputation](#alienvault_reputation)|182730|182730|806|0.4%|99.1%|
[firehol_level2](#firehol_level2)|26299|37969|421|1.1%|51.7%|
[blocklist_de](#blocklist_de)|31902|31902|404|1.2%|49.6%|
[blocklist_de_ssh](#blocklist_de_ssh)|2511|2511|394|15.6%|48.4%|
[bruteforceblocker](#bruteforceblocker)|1718|1718|325|18.9%|39.9%|
[et_compromised](#et_compromised)|1678|1678|309|18.4%|38.0%|
[shunlist](#shunlist)|1279|1279|230|17.9%|28.2%|
[openbl_1d](#openbl_1d)|141|141|141|100.0%|17.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|104|0.0%|12.7%|
[et_block](#et_block)|999|18343755|55|0.0%|6.7%|
[firehol_level1](#firehol_level1)|5148|688978821|52|0.0%|6.3%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|50|0.0%|6.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|45|0.0%|5.5%|
[blocklist_de_strongips](#blocklist_de_strongips)|173|173|24|13.8%|2.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|18|0.0%|2.2%|
[dshield](#dshield)|20|5120|17|0.3%|2.0%|
[blocklist_de_mail](#blocklist_de_mail)|20132|20132|7|0.0%|0.8%|
[blocklist_de_imap](#blocklist_de_imap)|2743|2743|7|0.2%|0.8%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|5|0.0%|0.6%|
[stopforumspam_30d](#stopforumspam_30d)|92512|92512|3|0.0%|0.3%|
[snort_ipfilter](#snort_ipfilter)|10116|10116|1|0.0%|0.1%|
[php_spammers](#php_spammers)|661|661|1|0.1%|0.1%|
[php_commenters](#php_commenters)|385|385|1|0.2%|0.1%|
[nixspam](#nixspam)|20501|20501|1|0.0%|0.1%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|1|0.0%|0.1%|
[ciarmy](#ciarmy)|447|447|1|0.2%|0.1%|
[blocklist_de_ftp](#blocklist_de_ftp)|517|517|1|0.1%|0.1%|
[blocklist_de_apache](#blocklist_de_apache)|16300|16300|1|0.0%|0.1%|

## palevo

[Abuse.ch Palevo tracker](https://palevotracker.abuse.ch) worm includes IPs which are being used as botnet C&C for the Palevo crimeware - **excellent list**

Source is downloaded from [this link](https://palevotracker.abuse.ch/blocklists.php?download=ipblocklist).

The last time downloaded was found to be dated: Tue Jun  9 12:27:06 UTC 2015.

The ipset `palevo` has **13** entries, **13** unique IPs.

The following table shows the overlaps of `palevo` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `palevo`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `palevo`.
- ` this % ` is the percentage **of this ipset (`palevo`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level1](#firehol_level1)|5148|688978821|13|0.0%|100.0%|
[et_block](#et_block)|999|18343755|13|0.0%|100.0%|
[snort_ipfilter](#snort_ipfilter)|10116|10116|11|0.1%|84.6%|
[firehol_level3](#firehol_level3)|108375|9625859|11|0.0%|84.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|3|0.0%|23.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|2|0.0%|15.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|1|0.0%|7.6%|

## php_commenters

[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) comment spammers (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=c&rss=1).

The last time downloaded was found to be dated: Tue Jun  9 11:27:12 UTC 2015.

The ipset `php_commenters` has **385** entries, **385** unique IPs.

The following table shows the overlaps of `php_commenters` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `php_commenters`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `php_commenters`.
- ` this % ` is the percentage **of this ipset (`php_commenters`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level3](#firehol_level3)|108375|9625859|385|0.0%|100.0%|
[stopforumspam_30d](#stopforumspam_30d)|92512|92512|289|0.3%|75.0%|
[stopforumspam_7d](#stopforumspam_7d)|29277|29277|215|0.7%|55.8%|
[firehol_level2](#firehol_level2)|26299|37969|178|0.4%|46.2%|
[stopforumspam_1d](#stopforumspam_1d)|7429|7429|153|2.0%|39.7%|
[blocklist_de](#blocklist_de)|31902|31902|92|0.2%|23.8%|
[blocklist_de_bots](#blocklist_de_bots)|3443|3443|74|2.1%|19.2%|
[firehol_anonymous](#firehol_anonymous)|17940|81947|71|0.0%|18.4%|
[firehol_proxies](#firehol_proxies)|11509|11733|65|0.5%|16.8%|
[snort_ipfilter](#snort_ipfilter)|10116|10116|54|0.5%|14.0%|
[et_tor](#et_tor)|6400|6400|43|0.6%|11.1%|
[dm_tor](#dm_tor)|6417|6417|43|0.6%|11.1%|
[bm_tor](#bm_tor)|6416|6416|43|0.6%|11.1%|
[php_spammers](#php_spammers)|661|661|42|6.3%|10.9%|
[blocklist_de_strongips](#blocklist_de_strongips)|173|173|41|23.6%|10.6%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|40|10.7%|10.3%|
[firehol_level1](#firehol_level1)|5148|688978821|37|0.0%|9.6%|
[blocklist_de_apache](#blocklist_de_apache)|16300|16300|31|0.1%|8.0%|
[et_block](#et_block)|999|18343755|30|0.0%|7.7%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|29|0.0%|7.5%|
[php_dictionary](#php_dictionary)|666|666|27|4.0%|7.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|24|0.0%|6.2%|
[blocklist_de_mail](#blocklist_de_mail)|20132|20132|24|0.1%|6.2%|
[ri_web_proxies](#ri_web_proxies)|7263|7263|23|0.3%|5.9%|
[alienvault_reputation](#alienvault_reputation)|182730|182730|17|0.0%|4.4%|
[php_harvesters](#php_harvesters)|366|366|15|4.0%|3.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|15|0.0%|3.8%|
[openbl_60d](#openbl_60d)|7177|7177|10|0.1%|2.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|10|0.0%|2.5%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4930|4930|10|0.2%|2.5%|
[xroxy](#xroxy)|2139|2139|8|0.3%|2.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|7|0.0%|1.8%|
[proxz](#proxz)|1122|1122|7|0.6%|1.8%|
[nixspam](#nixspam)|20501|20501|6|0.0%|1.5%|
[ri_connect_proxies](#ri_connect_proxies)|2644|2644|5|0.1%|1.2%|
[proxyrss](#proxyrss)|1212|1212|3|0.2%|0.7%|
[zeus_badips](#zeus_badips)|202|202|1|0.4%|0.2%|
[zeus](#zeus)|233|233|1|0.4%|0.2%|
[openbl_7d](#openbl_7d)|813|813|1|0.1%|0.2%|
[openbl_30d](#openbl_30d)|2857|2857|1|0.0%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.2%|
[fullbogons](#fullbogons)|3778|670299624|1|0.0%|0.2%|
[et_compromised](#et_compromised)|1678|1678|1|0.0%|0.2%|
[bruteforceblocker](#bruteforceblocker)|1718|1718|1|0.0%|0.2%|
[bogons](#bogons)|13|592708608|1|0.0%|0.2%|
[blocklist_de_ssh](#blocklist_de_ssh)|2511|2511|1|0.0%|0.2%|
[blocklist_de_imap](#blocklist_de_imap)|2743|2743|1|0.0%|0.2%|

## php_dictionary

[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) directory attackers (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=d&rss=1).

The last time downloaded was found to be dated: Tue Jun  9 11:27:13 UTC 2015.

The ipset `php_dictionary` has **666** entries, **666** unique IPs.

The following table shows the overlaps of `php_dictionary` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `php_dictionary`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `php_dictionary`.
- ` this % ` is the percentage **of this ipset (`php_dictionary`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level3](#firehol_level3)|108375|9625859|666|0.0%|100.0%|
[php_spammers](#php_spammers)|661|661|273|41.3%|40.9%|
[stopforumspam_30d](#stopforumspam_30d)|92512|92512|125|0.1%|18.7%|
[firehol_level2](#firehol_level2)|26299|37969|107|0.2%|16.0%|
[nixspam](#nixspam)|20501|20501|105|0.5%|15.7%|
[blocklist_de](#blocklist_de)|31902|31902|101|0.3%|15.1%|
[snort_ipfilter](#snort_ipfilter)|10116|10116|90|0.8%|13.5%|
[firehol_anonymous](#firehol_anonymous)|17940|81947|86|0.1%|12.9%|
[firehol_proxies](#firehol_proxies)|11509|11733|85|0.7%|12.7%|
[stopforumspam_7d](#stopforumspam_7d)|29277|29277|81|0.2%|12.1%|
[blocklist_de_mail](#blocklist_de_mail)|20132|20132|73|0.3%|10.9%|
[ri_web_proxies](#ri_web_proxies)|7263|7263|56|0.7%|8.4%|
[xroxy](#xroxy)|2139|2139|39|1.8%|5.8%|
[stopforumspam_1d](#stopforumspam_1d)|7429|7429|39|0.5%|5.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|35|0.0%|5.2%|
[php_commenters](#php_commenters)|385|385|27|7.0%|4.0%|
[blocklist_de_bots](#blocklist_de_bots)|3443|3443|24|0.6%|3.6%|
[proxz](#proxz)|1122|1122|23|2.0%|3.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|22|0.0%|3.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|12|0.0%|1.8%|
[alienvault_reputation](#alienvault_reputation)|182730|182730|8|0.0%|1.2%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|6|0.0%|0.9%|
[firehol_level1](#firehol_level1)|5148|688978821|6|0.0%|0.9%|
[et_block](#et_block)|999|18343755|6|0.0%|0.9%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4930|4930|5|0.1%|0.7%|
[blocklist_de_apache](#blocklist_de_apache)|16300|16300|5|0.0%|0.7%|
[ri_connect_proxies](#ri_connect_proxies)|2644|2644|4|0.1%|0.6%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|4|1.0%|0.6%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|4|0.0%|0.6%|
[blocklist_de_strongips](#blocklist_de_strongips)|173|173|4|2.3%|0.6%|
[proxyrss](#proxyrss)|1212|1212|3|0.2%|0.4%|
[php_harvesters](#php_harvesters)|366|366|3|0.8%|0.4%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|3|0.0%|0.4%|
[et_tor](#et_tor)|6400|6400|3|0.0%|0.4%|
[dm_tor](#dm_tor)|6417|6417|3|0.0%|0.4%|
[bm_tor](#bm_tor)|6416|6416|3|0.0%|0.4%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.1%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|1|0.1%|0.1%|

## php_harvesters

[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) harvesters (IPs that surf the internet looking for email addresses) (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=h&rss=1).

The last time downloaded was found to be dated: Tue Jun  9 11:27:07 UTC 2015.

The ipset `php_harvesters` has **366** entries, **366** unique IPs.

The following table shows the overlaps of `php_harvesters` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `php_harvesters`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `php_harvesters`.
- ` this % ` is the percentage **of this ipset (`php_harvesters`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level3](#firehol_level3)|108375|9625859|366|0.0%|100.0%|
[stopforumspam_30d](#stopforumspam_30d)|92512|92512|81|0.0%|22.1%|
[stopforumspam_7d](#stopforumspam_7d)|29277|29277|61|0.2%|16.6%|
[firehol_level2](#firehol_level2)|26299|37969|55|0.1%|15.0%|
[stopforumspam_1d](#stopforumspam_1d)|7429|7429|40|0.5%|10.9%|
[blocklist_de](#blocklist_de)|31902|31902|40|0.1%|10.9%|
[blocklist_de_bots](#blocklist_de_bots)|3443|3443|29|0.8%|7.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|19|0.0%|5.1%|
[php_commenters](#php_commenters)|385|385|15|3.8%|4.0%|
[snort_ipfilter](#snort_ipfilter)|10116|10116|14|0.1%|3.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|11|0.0%|3.0%|
[firehol_anonymous](#firehol_anonymous)|17940|81947|11|0.0%|3.0%|
[alienvault_reputation](#alienvault_reputation)|182730|182730|11|0.0%|3.0%|
[nixspam](#nixspam)|20501|20501|10|0.0%|2.7%|
[firehol_proxies](#firehol_proxies)|11509|11733|10|0.0%|2.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|9|0.0%|2.4%|
[et_tor](#et_tor)|6400|6400|7|0.1%|1.9%|
[dm_tor](#dm_tor)|6417|6417|7|0.1%|1.9%|
[bm_tor](#bm_tor)|6416|6416|7|0.1%|1.9%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|6|1.6%|1.6%|
[blocklist_de_mail](#blocklist_de_mail)|20132|20132|5|0.0%|1.3%|
[blocklist_de_ftp](#blocklist_de_ftp)|517|517|5|0.9%|1.3%|
[php_spammers](#php_spammers)|661|661|3|0.4%|0.8%|
[php_dictionary](#php_dictionary)|666|666|3|0.4%|0.8%|
[firehol_level1](#firehol_level1)|5148|688978821|3|0.0%|0.8%|
[xroxy](#xroxy)|2139|2139|2|0.0%|0.5%|
[ri_web_proxies](#ri_web_proxies)|7263|7263|2|0.0%|0.5%|
[openbl_60d](#openbl_60d)|7177|7177|2|0.0%|0.5%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|2|0.0%|0.5%|
[blocklist_de_strongips](#blocklist_de_strongips)|173|173|2|1.1%|0.5%|
[blocklist_de_apache](#blocklist_de_apache)|16300|16300|2|0.0%|0.5%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|1|0.0%|0.2%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|1|0.0%|0.2%|
[proxyrss](#proxyrss)|1212|1212|1|0.0%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.2%|
[fullbogons](#fullbogons)|3778|670299624|1|0.0%|0.2%|
[et_block](#et_block)|999|18343755|1|0.0%|0.2%|
[bogons](#bogons)|13|592708608|1|0.0%|0.2%|
[blocklist_de_imap](#blocklist_de_imap)|2743|2743|1|0.0%|0.2%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4930|4930|1|0.0%|0.2%|

## php_spammers

[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) spam servers (IPs used by spammers to send messages) (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=s&rss=1).

The last time downloaded was found to be dated: Tue Jun  9 11:27:08 UTC 2015.

The ipset `php_spammers` has **661** entries, **661** unique IPs.

The following table shows the overlaps of `php_spammers` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `php_spammers`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `php_spammers`.
- ` this % ` is the percentage **of this ipset (`php_spammers`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level3](#firehol_level3)|108375|9625859|661|0.0%|100.0%|
[php_dictionary](#php_dictionary)|666|666|273|40.9%|41.3%|
[stopforumspam_30d](#stopforumspam_30d)|92512|92512|136|0.1%|20.5%|
[firehol_level2](#firehol_level2)|26299|37969|105|0.2%|15.8%|
[nixspam](#nixspam)|20501|20501|95|0.4%|14.3%|
[blocklist_de](#blocklist_de)|31902|31902|94|0.2%|14.2%|
[snort_ipfilter](#snort_ipfilter)|10116|10116|85|0.8%|12.8%|
[stopforumspam_7d](#stopforumspam_7d)|29277|29277|80|0.2%|12.1%|
[firehol_anonymous](#firehol_anonymous)|17940|81947|73|0.0%|11.0%|
[firehol_proxies](#firehol_proxies)|11509|11733|71|0.6%|10.7%|
[blocklist_de_mail](#blocklist_de_mail)|20132|20132|64|0.3%|9.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|52|0.0%|7.8%|
[stopforumspam_1d](#stopforumspam_1d)|7429|7429|48|0.6%|7.2%|
[ri_web_proxies](#ri_web_proxies)|7263|7263|47|0.6%|7.1%|
[php_commenters](#php_commenters)|385|385|42|10.9%|6.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|41|0.0%|6.2%|
[xroxy](#xroxy)|2139|2139|32|1.4%|4.8%|
[proxz](#proxz)|1122|1122|21|1.8%|3.1%|
[blocklist_de_bots](#blocklist_de_bots)|3443|3443|21|0.6%|3.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|10|0.0%|1.5%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4930|4930|8|0.1%|1.2%|
[blocklist_de_apache](#blocklist_de_apache)|16300|16300|8|0.0%|1.2%|
[blocklist_de_strongips](#blocklist_de_strongips)|173|173|6|3.4%|0.9%|
[proxyrss](#proxyrss)|1212|1212|5|0.4%|0.7%|
[alienvault_reputation](#alienvault_reputation)|182730|182730|5|0.0%|0.7%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|4|0.0%|0.6%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|4|1.0%|0.6%|
[firehol_level1](#firehol_level1)|5148|688978821|4|0.0%|0.6%|
[et_tor](#et_tor)|6400|6400|4|0.0%|0.6%|
[et_block](#et_block)|999|18343755|4|0.0%|0.6%|
[dm_tor](#dm_tor)|6417|6417|4|0.0%|0.6%|
[bm_tor](#bm_tor)|6416|6416|4|0.0%|0.6%|
[ri_connect_proxies](#ri_connect_proxies)|2644|2644|3|0.1%|0.4%|
[php_harvesters](#php_harvesters)|366|366|3|0.8%|0.4%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|0.4%|
[openbl_7d](#openbl_7d)|813|813|1|0.1%|0.1%|
[openbl_60d](#openbl_60d)|7177|7177|1|0.0%|0.1%|
[openbl_30d](#openbl_30d)|2857|2857|1|0.0%|0.1%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|1|0.0%|0.1%|
[et_compromised](#et_compromised)|1678|1678|1|0.0%|0.1%|
[bruteforceblocker](#bruteforceblocker)|1718|1718|1|0.0%|0.1%|
[blocklist_de_ssh](#blocklist_de_ssh)|2511|2511|1|0.0%|0.1%|

## proxyrss

[proxyrss.com](http://www.proxyrss.com) open proxies syndicated from multiple sources.

Source is downloaded from [this link](http://www.proxyrss.com/proxylists/all.gz).

The last time downloaded was found to be dated: Tue Jun  9 10:01:24 UTC 2015.

The ipset `proxyrss` has **1212** entries, **1212** unique IPs.

The following table shows the overlaps of `proxyrss` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `proxyrss`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `proxyrss`.
- ` this % ` is the percentage **of this ipset (`proxyrss`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_proxies](#firehol_proxies)|11509|11733|1212|10.3%|100.0%|
[firehol_anonymous](#firehol_anonymous)|17940|81947|1212|1.4%|100.0%|
[firehol_level3](#firehol_level3)|108375|9625859|617|0.0%|50.9%|
[stopforumspam_30d](#stopforumspam_30d)|92512|92512|616|0.6%|50.8%|
[ri_web_proxies](#ri_web_proxies)|7263|7263|526|7.2%|43.3%|
[stopforumspam_7d](#stopforumspam_7d)|29277|29277|497|1.6%|41.0%|
[firehol_level2](#firehol_level2)|26299|37969|368|0.9%|30.3%|
[xroxy](#xroxy)|2139|2139|333|15.5%|27.4%|
[stopforumspam_1d](#stopforumspam_1d)|7429|7429|308|4.1%|25.4%|
[proxz](#proxz)|1122|1122|229|20.4%|18.8%|
[blocklist_de](#blocklist_de)|31902|31902|203|0.6%|16.7%|
[blocklist_de_bots](#blocklist_de_bots)|3443|3443|202|5.8%|16.6%|
[ri_connect_proxies](#ri_connect_proxies)|2644|2644|191|7.2%|15.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|63|0.0%|5.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|57|0.0%|4.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|31|0.0%|2.5%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|9|1.3%|0.7%|
[nixspam](#nixspam)|20501|20501|8|0.0%|0.6%|
[snort_ipfilter](#snort_ipfilter)|10116|10116|6|0.0%|0.4%|
[php_spammers](#php_spammers)|661|661|5|0.7%|0.4%|
[blocklist_de_strongips](#blocklist_de_strongips)|173|173|4|2.3%|0.3%|
[php_dictionary](#php_dictionary)|666|666|3|0.4%|0.2%|
[php_commenters](#php_commenters)|385|385|3|0.7%|0.2%|
[php_harvesters](#php_harvesters)|366|366|1|0.2%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|20132|20132|1|0.0%|0.0%|
[alienvault_reputation](#alienvault_reputation)|182730|182730|1|0.0%|0.0%|

## proxz

[proxz.com](http://www.proxz.com) open proxies (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.proxz.com/proxylists.xml).

The last time downloaded was found to be dated: Tue Jun  9 12:11:27 UTC 2015.

The ipset `proxz` has **1122** entries, **1122** unique IPs.

The following table shows the overlaps of `proxz` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `proxz`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `proxz`.
- ` this % ` is the percentage **of this ipset (`proxz`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_proxies](#firehol_proxies)|11509|11733|1122|9.5%|100.0%|
[firehol_anonymous](#firehol_anonymous)|17940|81947|1122|1.3%|100.0%|
[firehol_level3](#firehol_level3)|108375|9625859|676|0.0%|60.2%|
[stopforumspam_30d](#stopforumspam_30d)|92512|92512|670|0.7%|59.7%|
[ri_web_proxies](#ri_web_proxies)|7263|7263|508|6.9%|45.2%|
[stopforumspam_7d](#stopforumspam_7d)|29277|29277|482|1.6%|42.9%|
[xroxy](#xroxy)|2139|2139|405|18.9%|36.0%|
[firehol_level2](#firehol_level2)|26299|37969|251|0.6%|22.3%|
[proxyrss](#proxyrss)|1212|1212|229|18.8%|20.4%|
[ri_connect_proxies](#ri_connect_proxies)|2644|2644|188|7.1%|16.7%|
[stopforumspam_1d](#stopforumspam_1d)|7429|7429|184|2.4%|16.3%|
[blocklist_de](#blocklist_de)|31902|31902|164|0.5%|14.6%|
[blocklist_de_bots](#blocklist_de_bots)|3443|3443|148|4.2%|13.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|96|0.0%|8.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|43|0.0%|3.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|39|0.0%|3.4%|
[nixspam](#nixspam)|20501|20501|33|0.1%|2.9%|
[snort_ipfilter](#snort_ipfilter)|10116|10116|23|0.2%|2.0%|
[php_dictionary](#php_dictionary)|666|666|23|3.4%|2.0%|
[php_spammers](#php_spammers)|661|661|21|3.1%|1.8%|
[blocklist_de_mail](#blocklist_de_mail)|20132|20132|18|0.0%|1.6%|
[php_commenters](#php_commenters)|385|385|7|1.8%|0.6%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|6|0.9%|0.5%|
[blocklist_de_strongips](#blocklist_de_strongips)|173|173|3|1.7%|0.2%|
[alienvault_reputation](#alienvault_reputation)|182730|182730|3|0.0%|0.2%|
[et_compromised](#et_compromised)|1678|1678|2|0.1%|0.1%|
[bruteforceblocker](#bruteforceblocker)|1718|1718|2|0.1%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|1|0.0%|0.0%|

## ri_connect_proxies

[rosinstrument.com](http://www.rosinstrument.com) open CONNECT proxies (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://tools.rosinstrument.com/proxy/plab100.xml).

The last time downloaded was found to be dated: Tue Jun  9 06:02:23 UTC 2015.

The ipset `ri_connect_proxies` has **2644** entries, **2644** unique IPs.

The following table shows the overlaps of `ri_connect_proxies` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ri_connect_proxies`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ri_connect_proxies`.
- ` this % ` is the percentage **of this ipset (`ri_connect_proxies`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_proxies](#firehol_proxies)|11509|11733|2644|22.5%|100.0%|
[firehol_anonymous](#firehol_anonymous)|17940|81947|2644|3.2%|100.0%|
[stopforumspam_30d](#stopforumspam_30d)|92512|92512|1502|1.6%|56.8%|
[firehol_level3](#firehol_level3)|108375|9625859|1502|0.0%|56.8%|
[ri_web_proxies](#ri_web_proxies)|7263|7263|1116|15.3%|42.2%|
[stopforumspam_7d](#stopforumspam_7d)|29277|29277|617|2.1%|23.3%|
[xroxy](#xroxy)|2139|2139|382|17.8%|14.4%|
[proxyrss](#proxyrss)|1212|1212|191|15.7%|7.2%|
[proxz](#proxz)|1122|1122|188|16.7%|7.1%|
[firehol_level2](#firehol_level2)|26299|37969|159|0.4%|6.0%|
[stopforumspam_1d](#stopforumspam_1d)|7429|7429|112|1.5%|4.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|102|0.0%|3.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|80|0.0%|3.0%|
[blocklist_de](#blocklist_de)|31902|31902|77|0.2%|2.9%|
[blocklist_de_bots](#blocklist_de_bots)|3443|3443|74|2.1%|2.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|55|0.0%|2.0%|
[nixspam](#nixspam)|20501|20501|9|0.0%|0.3%|
[snort_ipfilter](#snort_ipfilter)|10116|10116|7|0.0%|0.2%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|7|1.0%|0.2%|
[php_commenters](#php_commenters)|385|385|5|1.2%|0.1%|
[php_dictionary](#php_dictionary)|666|666|4|0.6%|0.1%|
[php_spammers](#php_spammers)|661|661|3|0.4%|0.1%|
[blocklist_de_mail](#blocklist_de_mail)|20132|20132|3|0.0%|0.1%|
[alienvault_reputation](#alienvault_reputation)|182730|182730|3|0.0%|0.1%|
[blocklist_de_imap](#blocklist_de_imap)|2743|2743|2|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.0%|

## ri_web_proxies

[rosinstrument.com](http://www.rosinstrument.com) open HTTP proxies (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://tools.rosinstrument.com/proxy/l100.xml).

The last time downloaded was found to be dated: Tue Jun  9 06:18:23 UTC 2015.

The ipset `ri_web_proxies` has **7263** entries, **7263** unique IPs.

The following table shows the overlaps of `ri_web_proxies` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ri_web_proxies`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ri_web_proxies`.
- ` this % ` is the percentage **of this ipset (`ri_web_proxies`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_proxies](#firehol_proxies)|11509|11733|7263|61.9%|100.0%|
[firehol_anonymous](#firehol_anonymous)|17940|81947|7263|8.8%|100.0%|
[firehol_level3](#firehol_level3)|108375|9625859|3514|0.0%|48.3%|
[stopforumspam_30d](#stopforumspam_30d)|92512|92512|3466|3.7%|47.7%|
[stopforumspam_7d](#stopforumspam_7d)|29277|29277|1572|5.3%|21.6%|
[ri_connect_proxies](#ri_connect_proxies)|2644|2644|1116|42.2%|15.3%|
[xroxy](#xroxy)|2139|2139|935|43.7%|12.8%|
[firehol_level2](#firehol_level2)|26299|37969|650|1.7%|8.9%|
[proxyrss](#proxyrss)|1212|1212|526|43.3%|7.2%|
[proxz](#proxz)|1122|1122|508|45.2%|6.9%|
[stopforumspam_1d](#stopforumspam_1d)|7429|7429|450|6.0%|6.1%|
[blocklist_de](#blocklist_de)|31902|31902|410|1.2%|5.6%|
[blocklist_de_bots](#blocklist_de_bots)|3443|3443|357|10.3%|4.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|211|0.0%|2.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|204|0.0%|2.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|144|0.0%|1.9%|
[nixspam](#nixspam)|20501|20501|73|0.3%|1.0%|
[snort_ipfilter](#snort_ipfilter)|10116|10116|60|0.5%|0.8%|
[php_dictionary](#php_dictionary)|666|666|56|8.4%|0.7%|
[php_spammers](#php_spammers)|661|661|47|7.1%|0.6%|
[blocklist_de_mail](#blocklist_de_mail)|20132|20132|46|0.2%|0.6%|
[php_commenters](#php_commenters)|385|385|23|5.9%|0.3%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|14|2.1%|0.1%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4930|4930|7|0.1%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|16300|16300|7|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|6|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|4|1.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|4|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|173|173|4|2.3%|0.0%|
[et_tor](#et_tor)|6400|6400|3|0.0%|0.0%|
[dm_tor](#dm_tor)|6417|6417|3|0.0%|0.0%|
[bm_tor](#bm_tor)|6416|6416|3|0.0%|0.0%|
[alienvault_reputation](#alienvault_reputation)|182730|182730|3|0.0%|0.0%|
[php_harvesters](#php_harvesters)|366|366|2|0.5%|0.0%|
[sslbl](#sslbl)|379|379|1|0.2%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|1|0.0%|0.0%|
[firehol_level1](#firehol_level1)|5148|688978821|1|0.0%|0.0%|
[et_compromised](#et_compromised)|1678|1678|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1718|1718|1|0.0%|0.0%|

## shunlist

[AutoShun.org](http://autoshun.org/) IPs identified as hostile by correlating logs from distributed snort installations running the autoshun plugin

Source is downloaded from [this link](http://www.autoshun.org/files/shunlist.csv).

The last time downloaded was found to be dated: Tue Jun  9 11:30:06 UTC 2015.

The ipset `shunlist` has **1279** entries, **1279** unique IPs.

The following table shows the overlaps of `shunlist` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `shunlist`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `shunlist`.
- ` this % ` is the percentage **of this ipset (`shunlist`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level3](#firehol_level3)|108375|9625859|1279|0.0%|100.0%|
[alienvault_reputation](#alienvault_reputation)|182730|182730|1263|0.6%|98.7%|
[openbl_60d](#openbl_60d)|7177|7177|565|7.8%|44.1%|
[openbl_30d](#openbl_30d)|2857|2857|537|18.7%|41.9%|
[firehol_level2](#firehol_level2)|26299|37969|462|1.2%|36.1%|
[blocklist_de](#blocklist_de)|31902|31902|459|1.4%|35.8%|
[bruteforceblocker](#bruteforceblocker)|1718|1718|440|25.6%|34.4%|
[et_compromised](#et_compromised)|1678|1678|419|24.9%|32.7%|
[blocklist_de_ssh](#blocklist_de_ssh)|2511|2511|418|16.6%|32.6%|
[openbl_7d](#openbl_7d)|813|813|230|28.2%|17.9%|
[firehol_level1](#firehol_level1)|5148|688978821|185|0.0%|14.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|116|0.0%|9.0%|
[et_block](#et_block)|999|18343755|104|0.0%|8.1%|
[dshield](#dshield)|20|5120|97|1.8%|7.5%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|96|0.0%|7.5%|
[openbl_1d](#openbl_1d)|141|141|75|53.1%|5.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|73|0.0%|5.7%|
[sslbl](#sslbl)|379|379|64|16.8%|5.0%|
[ciarmy](#ciarmy)|447|447|34|7.6%|2.6%|
[blocklist_de_apache](#blocklist_de_apache)|16300|16300|33|0.2%|2.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|27|0.0%|2.1%|
[blocklist_de_strongips](#blocklist_de_strongips)|173|173|22|12.7%|1.7%|
[voipbl](#voipbl)|10507|10919|12|0.1%|0.9%|
[stopforumspam_30d](#stopforumspam_30d)|92512|92512|4|0.0%|0.3%|
[blocklist_de_mail](#blocklist_de_mail)|20132|20132|4|0.0%|0.3%|
[snort_ipfilter](#snort_ipfilter)|10116|10116|3|0.0%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|0.2%|
[blocklist_de_imap](#blocklist_de_imap)|2743|2743|2|0.0%|0.1%|
[blocklist_de_ftp](#blocklist_de_ftp)|517|517|2|0.3%|0.1%|
[stopforumspam_7d](#stopforumspam_7d)|29277|29277|1|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7429|7429|1|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[firehol_proxies](#firehol_proxies)|11509|11733|1|0.0%|0.0%|
[firehol_anonymous](#firehol_anonymous)|17940|81947|1|0.0%|0.0%|
[et_tor](#et_tor)|6400|6400|1|0.0%|0.0%|
[dm_tor](#dm_tor)|6417|6417|1|0.0%|0.0%|
[bm_tor](#bm_tor)|6416|6416|1|0.0%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|86|86|1|1.1%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4930|4930|1|0.0%|0.0%|

## snort_ipfilter

[labs.snort.org](https://labs.snort.org/) supplied IP blacklist (this list seems to be updated frequently, but we found no information about it)

Source is downloaded from [this link](http://labs.snort.org/feeds/ip-filter.blf).

The last time downloaded was found to be dated: Tue Jun  9 04:00:00 UTC 2015.

The ipset `snort_ipfilter` has **10116** entries, **10116** unique IPs.

The following table shows the overlaps of `snort_ipfilter` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `snort_ipfilter`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `snort_ipfilter`.
- ` this % ` is the percentage **of this ipset (`snort_ipfilter`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level3](#firehol_level3)|108375|9625859|10116|0.1%|100.0%|
[firehol_anonymous](#firehol_anonymous)|17940|81947|1135|1.3%|11.2%|
[et_tor](#et_tor)|6400|6400|1082|16.9%|10.6%|
[bm_tor](#bm_tor)|6416|6416|1038|16.1%|10.2%|
[dm_tor](#dm_tor)|6417|6417|1037|16.1%|10.2%|
[stopforumspam_30d](#stopforumspam_30d)|92512|92512|805|0.8%|7.9%|
[stopforumspam_7d](#stopforumspam_7d)|29277|29277|660|2.2%|6.5%|
[firehol_level2](#firehol_level2)|26299|37969|652|1.7%|6.4%|
[stopforumspam_1d](#stopforumspam_1d)|7429|7429|401|5.3%|3.9%|
[et_block](#et_block)|999|18343755|300|0.0%|2.9%|
[firehol_level1](#firehol_level1)|5148|688978821|299|0.0%|2.9%|
[blocklist_de](#blocklist_de)|31902|31902|295|0.9%|2.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|263|0.0%|2.5%|
[firehol_proxies](#firehol_proxies)|11509|11733|253|2.1%|2.5%|
[blocklist_de_mail](#blocklist_de_mail)|20132|20132|247|1.2%|2.4%|
[zeus](#zeus)|233|233|201|86.2%|1.9%|
[zeus_badips](#zeus_badips)|202|202|178|88.1%|1.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|175|0.0%|1.7%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|172|46.2%|1.7%|
[nixspam](#nixspam)|20501|20501|155|0.7%|1.5%|
[alienvault_reputation](#alienvault_reputation)|182730|182730|124|0.0%|1.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|117|0.0%|1.1%|
[php_dictionary](#php_dictionary)|666|666|90|13.5%|0.8%|
[php_spammers](#php_spammers)|661|661|85|12.8%|0.8%|
[feodo](#feodo)|103|103|81|78.6%|0.8%|
[ri_web_proxies](#ri_web_proxies)|7263|7263|60|0.8%|0.5%|
[php_commenters](#php_commenters)|385|385|54|14.0%|0.5%|
[xroxy](#xroxy)|2139|2139|36|1.6%|0.3%|
[sslbl](#sslbl)|379|379|32|8.4%|0.3%|
[openbl_60d](#openbl_60d)|7177|7177|28|0.3%|0.2%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|28|2.1%|0.2%|
[blocklist_de_bots](#blocklist_de_bots)|3443|3443|28|0.8%|0.2%|
[proxz](#proxz)|1122|1122|23|2.0%|0.2%|
[blocklist_de_apache](#blocklist_de_apache)|16300|16300|20|0.1%|0.1%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|19|0.0%|0.1%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4930|4930|16|0.3%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|15|0.0%|0.1%|
[php_harvesters](#php_harvesters)|366|366|14|3.8%|0.1%|
[palevo](#palevo)|13|13|11|84.6%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|11|0.0%|0.1%|
[blocklist_de_imap](#blocklist_de_imap)|2743|2743|11|0.4%|0.1%|
[ri_connect_proxies](#ri_connect_proxies)|2644|2644|7|0.2%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|6|0.0%|0.0%|
[proxyrss](#proxyrss)|1212|1212|6|0.4%|0.0%|
[openbl_30d](#openbl_30d)|2857|2857|6|0.2%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|4|0.0%|0.0%|
[shunlist](#shunlist)|1279|1279|3|0.2%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|173|173|2|1.1%|0.0%|
[openbl_7d](#openbl_7d)|813|813|1|0.1%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|1|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|1|0.1%|0.0%|
[et_compromised](#et_compromised)|1678|1678|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1718|1718|1|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2511|2511|1|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|517|517|1|0.1%|0.0%|

## spamhaus_drop

[Spamhaus.org](http://www.spamhaus.org) DROP list (according to their site this list should be dropped at tier-1 ISPs globaly) - **excellent list**

Source is downloaded from [this link](http://www.spamhaus.org/drop/drop.txt).

The last time downloaded was found to be dated: Tue Jun  9 01:09:50 UTC 2015.

The ipset `spamhaus_drop` has **652** entries, **18338560** unique IPs.

The following table shows the overlaps of `spamhaus_drop` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `spamhaus_drop`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `spamhaus_drop`.
- ` this % ` is the percentage **of this ipset (`spamhaus_drop`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level1](#firehol_level1)|5148|688978821|18338560|2.6%|100.0%|
[et_block](#et_block)|999|18343755|18338560|99.9%|100.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|8532506|2.4%|46.5%|
[firehol_level3](#firehol_level3)|108375|9625859|6933031|72.0%|37.8%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|6932480|75.5%|37.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|2272265|0.2%|12.3%|
[fullbogons](#fullbogons)|3778|670299624|151552|0.0%|0.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|130368|0.0%|0.7%|
[alienvault_reputation](#alienvault_reputation)|182730|182730|1374|0.7%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1037|0.3%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92512|92512|1008|1.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|512|0.1%|0.0%|
[dshield](#dshield)|20|5120|512|10.0%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29277|29277|307|1.0%|0.0%|
[firehol_level2](#firehol_level2)|26299|37969|273|0.7%|0.0%|
[openbl_60d](#openbl_60d)|7177|7177|236|3.2%|0.0%|
[blocklist_de](#blocklist_de)|31902|31902|203|0.6%|0.0%|
[openbl_30d](#openbl_30d)|2857|2857|121|4.2%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2511|2511|117|4.6%|0.0%|
[nixspam](#nixspam)|20501|20501|112|0.5%|0.0%|
[et_compromised](#et_compromised)|1678|1678|101|6.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1718|1718|101|5.8%|0.0%|
[shunlist](#shunlist)|1279|1279|96|7.5%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7429|7429|88|1.1%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3443|3443|57|1.6%|0.0%|
[openbl_7d](#openbl_7d)|813|813|50|6.1%|0.0%|
[php_commenters](#php_commenters)|385|385|29|7.5%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|29|2.2%|0.0%|
[openbl_1d](#openbl_1d)|141|141|25|17.7%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|20132|20132|21|0.1%|0.0%|
[snort_ipfilter](#snort_ipfilter)|10116|10116|19|0.1%|0.0%|
[zeus_badips](#zeus_badips)|202|202|16|7.9%|0.0%|
[zeus](#zeus)|233|233|16|6.8%|0.0%|
[voipbl](#voipbl)|10507|10919|14|0.1%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2743|2743|14|0.5%|0.0%|
[php_dictionary](#php_dictionary)|666|666|6|0.9%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|6|0.4%|0.0%|
[firehol_anonymous](#firehol_anonymous)|17940|81947|6|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|173|173|6|3.4%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|5|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4930|4930|5|0.1%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|16300|16300|5|0.0%|0.0%|
[php_spammers](#php_spammers)|661|661|4|0.6%|0.0%|
[malc0de](#malc0de)|342|342|4|1.1%|0.0%|
[et_tor](#et_tor)|6400|6400|3|0.0%|0.0%|
[dm_tor](#dm_tor)|6417|6417|3|0.0%|0.0%|
[bm_tor](#bm_tor)|6416|6416|3|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|2|0.3%|0.0%|
[firehol_proxies](#firehol_proxies)|11509|11733|2|0.0%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|86|86|2|2.3%|0.0%|
[sslbl](#sslbl)|379|379|1|0.2%|0.0%|
[php_harvesters](#php_harvesters)|366|366|1|0.2%|0.0%|
[et_botcc](#et_botcc)|509|509|1|0.1%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|517|517|1|0.1%|0.0%|

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
[firehol_level1](#firehol_level1)|5148|688978821|487424|0.0%|100.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|270785|0.1%|55.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|98904|0.0%|20.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|33155|0.0%|6.8%|
[et_block](#et_block)|999|18343755|517|0.0%|0.1%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|512|0.0%|0.1%|
[firehol_level3](#firehol_level3)|108375|9625859|88|0.0%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92512|92512|78|0.0%|0.0%|
[alienvault_reputation](#alienvault_reputation)|182730|182730|15|0.0%|0.0%|
[firehol_level2](#firehol_level2)|26299|37969|10|0.0%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29277|29277|9|0.0%|0.0%|
[blocklist_de](#blocklist_de)|31902|31902|8|0.0%|0.0%|
[php_commenters](#php_commenters)|385|385|7|1.8%|0.0%|
[snort_ipfilter](#snort_ipfilter)|10116|10116|6|0.0%|0.0%|
[zeus_badips](#zeus_badips)|202|202|5|2.4%|0.0%|
[zeus](#zeus)|233|233|5|2.1%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|173|173|4|2.3%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3443|3443|4|0.1%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7429|7429|3|0.0%|0.0%|
[nixspam](#nixspam)|20501|20501|2|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2511|2511|2|0.0%|0.0%|
[php_harvesters](#php_harvesters)|366|366|1|0.2%|0.0%|
[openbl_60d](#openbl_60d)|7177|7177|1|0.0%|0.0%|
[openbl_30d](#openbl_30d)|2857|2857|1|0.0%|0.0%|
[malc0de](#malc0de)|342|342|1|0.2%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|20132|20132|1|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|16300|16300|1|0.0%|0.0%|

## sslbl

[Abuse.ch SSL Blacklist](https://sslbl.abuse.ch/) bad SSL traffic related to malware or botnet activities - **excellent list**

Source is downloaded from [this link](https://sslbl.abuse.ch/blacklist/sslipblacklist.csv).

The last time downloaded was found to be dated: Tue Jun  9 12:15:07 UTC 2015.

The ipset `sslbl` has **379** entries, **379** unique IPs.

The following table shows the overlaps of `sslbl` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `sslbl`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `sslbl`.
- ` this % ` is the percentage **of this ipset (`sslbl`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level1](#firehol_level1)|5148|688978821|379|0.0%|100.0%|
[firehol_level3](#firehol_level3)|108375|9625859|96|0.0%|25.3%|
[alienvault_reputation](#alienvault_reputation)|182730|182730|68|0.0%|17.9%|
[shunlist](#shunlist)|1279|1279|64|5.0%|16.8%|
[feodo](#feodo)|103|103|37|35.9%|9.7%|
[et_block](#et_block)|999|18343755|37|0.0%|9.7%|
[snort_ipfilter](#snort_ipfilter)|10116|10116|32|0.3%|8.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|30|0.0%|7.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|5|0.0%|1.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|3|0.0%|0.7%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|1|0.0%|0.2%|
[ri_web_proxies](#ri_web_proxies)|7263|7263|1|0.0%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.2%|
[firehol_proxies](#firehol_proxies)|11509|11733|1|0.0%|0.2%|
[firehol_level2](#firehol_level2)|26299|37969|1|0.0%|0.2%|
[firehol_anonymous](#firehol_anonymous)|17940|81947|1|0.0%|0.2%|
[blocklist_de_ssh](#blocklist_de_ssh)|2511|2511|1|0.0%|0.2%|
[blocklist_de](#blocklist_de)|31902|31902|1|0.0%|0.2%|

## stopforumspam_1d

[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers in the last 24 hours - **excellent list**

Source is downloaded from [this link](http://www.stopforumspam.com/downloads/listed_ip_1.zip).

The last time downloaded was found to be dated: Tue Jun  9 12:00:01 UTC 2015.

The ipset `stopforumspam_1d` has **7429** entries, **7429** unique IPs.

The following table shows the overlaps of `stopforumspam_1d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `stopforumspam_1d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `stopforumspam_1d`.
- ` this % ` is the percentage **of this ipset (`stopforumspam_1d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|26299|37969|7429|19.5%|100.0%|
[firehol_level3](#firehol_level3)|108375|9625859|6026|0.0%|81.1%|
[stopforumspam_30d](#stopforumspam_30d)|92512|92512|6000|6.4%|80.7%|
[stopforumspam_7d](#stopforumspam_7d)|29277|29277|5804|19.8%|78.1%|
[blocklist_de](#blocklist_de)|31902|31902|1379|4.3%|18.5%|
[blocklist_de_bots](#blocklist_de_bots)|3443|3443|1310|38.0%|17.6%|
[firehol_anonymous](#firehol_anonymous)|17940|81947|1010|1.2%|13.5%|
[firehol_proxies](#firehol_proxies)|11509|11733|799|6.8%|10.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|534|0.0%|7.1%|
[ri_web_proxies](#ri_web_proxies)|7263|7263|450|6.1%|6.0%|
[snort_ipfilter](#snort_ipfilter)|10116|10116|401|3.9%|5.3%|
[et_tor](#et_tor)|6400|6400|354|5.5%|4.7%|
[dm_tor](#dm_tor)|6417|6417|351|5.4%|4.7%|
[bm_tor](#bm_tor)|6416|6416|351|5.4%|4.7%|
[proxyrss](#proxyrss)|1212|1212|308|25.4%|4.1%|
[xroxy](#xroxy)|2139|2139|245|11.4%|3.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|215|0.0%|2.8%|
[proxz](#proxz)|1122|1122|184|16.3%|2.4%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|156|41.9%|2.0%|
[php_commenters](#php_commenters)|385|385|153|39.7%|2.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|124|0.0%|1.6%|
[ri_connect_proxies](#ri_connect_proxies)|2644|2644|112|4.2%|1.5%|
[blocklist_de_strongips](#blocklist_de_strongips)|173|173|107|61.8%|1.4%|
[firehol_level1](#firehol_level1)|5148|688978821|90|0.0%|1.2%|
[et_block](#et_block)|999|18343755|89|0.0%|1.1%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|88|0.0%|1.1%|
[nixspam](#nixspam)|20501|20501|77|0.3%|1.0%|
[blocklist_de_apache](#blocklist_de_apache)|16300|16300|65|0.3%|0.8%|
[blocklist_de_mail](#blocklist_de_mail)|20132|20132|53|0.2%|0.7%|
[php_spammers](#php_spammers)|661|661|48|7.2%|0.6%|
[alienvault_reputation](#alienvault_reputation)|182730|182730|47|0.0%|0.6%|
[php_harvesters](#php_harvesters)|366|366|40|10.9%|0.5%|
[php_dictionary](#php_dictionary)|666|666|39|5.8%|0.5%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|37|0.0%|0.4%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4930|4930|29|0.5%|0.3%|
[openbl_60d](#openbl_60d)|7177|7177|21|0.2%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|9|0.0%|0.1%|
[voipbl](#voipbl)|10507|10919|5|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|3|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|3|0.4%|0.0%|
[zeus_badips](#zeus_badips)|202|202|1|0.4%|0.0%|
[zeus](#zeus)|233|233|1|0.4%|0.0%|
[shunlist](#shunlist)|1279|1279|1|0.0%|0.0%|
[openbl_30d](#openbl_30d)|2857|2857|1|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|1|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|1|0.0%|0.0%|
[et_compromised](#et_compromised)|1678|1678|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1718|1718|1|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2743|2743|1|0.0%|0.0%|

## stopforumspam_30d

[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 30 days)

Source is downloaded from [this link](http://www.stopforumspam.com/downloads/listed_ip_30.zip).

The last time downloaded was found to be dated: Tue Jun  9 00:00:34 UTC 2015.

The ipset `stopforumspam_30d` has **92512** entries, **92512** unique IPs.

The following table shows the overlaps of `stopforumspam_30d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `stopforumspam_30d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `stopforumspam_30d`.
- ` this % ` is the percentage **of this ipset (`stopforumspam_30d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level3](#firehol_level3)|108375|9625859|92512|0.9%|100.0%|
[stopforumspam_7d](#stopforumspam_7d)|29277|29277|29167|99.6%|31.5%|
[firehol_level2](#firehol_level2)|26299|37969|7417|19.5%|8.0%|
[stopforumspam_1d](#stopforumspam_1d)|7429|7429|6000|80.7%|6.4%|
[firehol_anonymous](#firehol_anonymous)|17940|81947|5845|7.1%|6.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|5744|0.0%|6.2%|
[firehol_proxies](#firehol_proxies)|11509|11733|5205|44.3%|5.6%|
[ri_web_proxies](#ri_web_proxies)|7263|7263|3466|47.7%|3.7%|
[blocklist_de](#blocklist_de)|31902|31902|2663|8.3%|2.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|2475|0.0%|2.6%|
[blocklist_de_bots](#blocklist_de_bots)|3443|3443|2342|68.0%|2.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|1506|0.0%|1.6%|
[ri_connect_proxies](#ri_connect_proxies)|2644|2644|1502|56.8%|1.6%|
[xroxy](#xroxy)|2139|2139|1265|59.1%|1.3%|
[firehol_level1](#firehol_level1)|5148|688978821|1088|0.0%|1.1%|
[et_block](#et_block)|999|18343755|1011|0.0%|1.0%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|1008|0.0%|1.0%|
[snort_ipfilter](#snort_ipfilter)|10116|10116|805|7.9%|0.8%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|719|0.0%|0.7%|
[proxz](#proxz)|1122|1122|670|59.7%|0.7%|
[et_tor](#et_tor)|6400|6400|659|10.2%|0.7%|
[dm_tor](#dm_tor)|6417|6417|634|9.8%|0.6%|
[bm_tor](#bm_tor)|6416|6416|633|9.8%|0.6%|
[proxyrss](#proxyrss)|1212|1212|616|50.8%|0.6%|
[php_commenters](#php_commenters)|385|385|289|75.0%|0.3%|
[blocklist_de_mail](#blocklist_de_mail)|20132|20132|239|1.1%|0.2%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|233|62.6%|0.2%|
[nixspam](#nixspam)|20501|20501|216|1.0%|0.2%|
[blocklist_de_apache](#blocklist_de_apache)|16300|16300|214|1.3%|0.2%|
[alienvault_reputation](#alienvault_reputation)|182730|182730|199|0.1%|0.2%|
[php_spammers](#php_spammers)|661|661|136|20.5%|0.1%|
[blocklist_de_strongips](#blocklist_de_strongips)|173|173|126|72.8%|0.1%|
[php_dictionary](#php_dictionary)|666|666|125|18.7%|0.1%|
[php_harvesters](#php_harvesters)|366|366|81|22.1%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|78|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4930|4930|66|1.3%|0.0%|
[openbl_60d](#openbl_60d)|7177|7177|51|0.7%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|48|0.0%|0.0%|
[voipbl](#voipbl)|10507|10919|35|0.3%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|18|2.7%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|13|0.0%|0.0%|
[et_compromised](#et_compromised)|1678|1678|13|0.7%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1718|1718|13|0.7%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2511|2511|13|0.5%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2743|2743|8|0.2%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|517|517|8|1.5%|0.0%|
[shunlist](#shunlist)|1279|1279|4|0.3%|0.0%|
[openbl_30d](#openbl_30d)|2857|2857|4|0.1%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|4|0.3%|0.0%|
[openbl_7d](#openbl_7d)|813|813|3|0.3%|0.0%|
[zeus_badips](#zeus_badips)|202|202|2|0.9%|0.0%|
[zeus](#zeus)|233|233|2|0.8%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|2|0.1%|0.0%|
[ciarmy](#ciarmy)|447|447|2|0.4%|0.0%|
[fullbogons](#fullbogons)|3778|670299624|1|0.0%|0.0%|
[dshield](#dshield)|20|5120|1|0.0%|0.0%|

## stopforumspam_7d

[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 7 days)

Source is downloaded from [this link](http://www.stopforumspam.com/downloads/listed_ip_7.zip).

The last time downloaded was found to be dated: Tue Jun  9 01:00:10 UTC 2015.

The ipset `stopforumspam_7d` has **29277** entries, **29277** unique IPs.

The following table shows the overlaps of `stopforumspam_7d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `stopforumspam_7d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `stopforumspam_7d`.
- ` this % ` is the percentage **of this ipset (`stopforumspam_7d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level3](#firehol_level3)|108375|9625859|29168|0.3%|99.6%|
[stopforumspam_30d](#stopforumspam_30d)|92512|92512|29167|31.5%|99.6%|
[firehol_level2](#firehol_level2)|26299|37969|6852|18.0%|23.4%|
[stopforumspam_1d](#stopforumspam_1d)|7429|7429|5804|78.1%|19.8%|
[firehol_anonymous](#firehol_anonymous)|17940|81947|2801|3.4%|9.5%|
[firehol_proxies](#firehol_proxies)|11509|11733|2397|20.4%|8.1%|
[blocklist_de](#blocklist_de)|31902|31902|2271|7.1%|7.7%|
[blocklist_de_bots](#blocklist_de_bots)|3443|3443|2096|60.8%|7.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|1893|0.0%|6.4%|
[ri_web_proxies](#ri_web_proxies)|7263|7263|1572|21.6%|5.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|825|0.0%|2.8%|
[snort_ipfilter](#snort_ipfilter)|10116|10116|660|6.5%|2.2%|
[xroxy](#xroxy)|2139|2139|648|30.2%|2.2%|
[ri_connect_proxies](#ri_connect_proxies)|2644|2644|617|23.3%|2.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|549|0.0%|1.8%|
[et_tor](#et_tor)|6400|6400|544|8.5%|1.8%|
[dm_tor](#dm_tor)|6417|6417|522|8.1%|1.7%|
[bm_tor](#bm_tor)|6416|6416|520|8.1%|1.7%|
[proxyrss](#proxyrss)|1212|1212|497|41.0%|1.6%|
[proxz](#proxz)|1122|1122|482|42.9%|1.6%|
[firehol_level1](#firehol_level1)|5148|688978821|316|0.0%|1.0%|
[et_block](#et_block)|999|18343755|308|0.0%|1.0%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|307|0.0%|1.0%|
[php_commenters](#php_commenters)|385|385|215|55.8%|0.7%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|192|51.6%|0.6%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|157|0.0%|0.5%|
[blocklist_de_apache](#blocklist_de_apache)|16300|16300|132|0.8%|0.4%|
[blocklist_de_mail](#blocklist_de_mail)|20132|20132|130|0.6%|0.4%|
[nixspam](#nixspam)|20501|20501|122|0.5%|0.4%|
[blocklist_de_strongips](#blocklist_de_strongips)|173|173|113|65.3%|0.3%|
[alienvault_reputation](#alienvault_reputation)|182730|182730|98|0.0%|0.3%|
[php_dictionary](#php_dictionary)|666|666|81|12.1%|0.2%|
[php_spammers](#php_spammers)|661|661|80|12.1%|0.2%|
[php_harvesters](#php_harvesters)|366|366|61|16.6%|0.2%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4930|4930|47|0.9%|0.1%|
[openbl_60d](#openbl_60d)|7177|7177|24|0.3%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|22|0.0%|0.0%|
[voipbl](#voipbl)|10507|10919|15|0.1%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|13|1.9%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|9|0.0%|0.0%|
[et_compromised](#et_compromised)|1678|1678|5|0.2%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1718|1718|5|0.2%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|4|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2511|2511|3|0.1%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|2|0.1%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2743|2743|2|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|517|517|2|0.3%|0.0%|
[zeus_badips](#zeus_badips)|202|202|1|0.4%|0.0%|
[zeus](#zeus)|233|233|1|0.4%|0.0%|
[shunlist](#shunlist)|1279|1279|1|0.0%|0.0%|
[openbl_30d](#openbl_30d)|2857|2857|1|0.0%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|1|0.0%|0.0%|
[ciarmy](#ciarmy)|447|447|1|0.2%|0.0%|

## virbl

[VirBL](http://virbl.bit.nl/) is a project of which the idea was born during the RIPE-48 meeting. The plan was to get reports of virusscanning mailservers, and put the IP-addresses that were reported to send viruses on a blacklist.

Source is downloaded from [this link](http://virbl.bit.nl/download/virbl.dnsbl.bit.nl.txt).

The last time downloaded was found to be dated: Tue Jun  9 11:32:04 UTC 2015.

The ipset `virbl` has **21** entries, **21** unique IPs.

The following table shows the overlaps of `virbl` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `virbl`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `virbl`.
- ` this % ` is the percentage **of this ipset (`virbl`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level3](#firehol_level3)|108375|9625859|21|0.0%|100.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|2|0.0%|9.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|1|0.0%|4.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|1|0.0%|4.7%|

## voipbl

[VoIPBL.org](http://www.voipbl.org/) a distributed VoIP blacklist that is aimed to protects against VoIP Fraud and minimizing abuse for network that have publicly accessible PBX's. Several algorithms, external sources and manual confirmation are used before they categorize something as an attack and determine the threat level.

Source is downloaded from [this link](http://www.voipbl.org/update/).

The last time downloaded was found to be dated: Tue Jun  9 09:36:37 UTC 2015.

The ipset `voipbl` has **10507** entries, **10919** unique IPs.

The following table shows the overlaps of `voipbl` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `voipbl`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `voipbl`.
- ` this % ` is the percentage **of this ipset (`voipbl`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|1600|0.0%|14.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|434|0.0%|3.9%|
[firehol_level1](#firehol_level1)|5148|688978821|334|0.0%|3.0%|
[fullbogons](#fullbogons)|3778|670299624|319|0.0%|2.9%|
[bogons](#bogons)|13|592708608|319|0.0%|2.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|299|0.0%|2.7%|
[alienvault_reputation](#alienvault_reputation)|182730|182730|190|0.1%|1.7%|
[firehol_anonymous](#firehol_anonymous)|17940|81947|78|0.0%|0.7%|
[firehol_level3](#firehol_level3)|108375|9625859|56|0.0%|0.5%|
[firehol_level2](#firehol_level2)|26299|37969|37|0.0%|0.3%|
[stopforumspam_30d](#stopforumspam_30d)|92512|92512|35|0.0%|0.3%|
[blocklist_de](#blocklist_de)|31902|31902|32|0.1%|0.2%|
[blocklist_de_sip](#blocklist_de_sip)|86|86|26|30.2%|0.2%|
[stopforumspam_7d](#stopforumspam_7d)|29277|29277|15|0.0%|0.1%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|14|0.0%|0.1%|
[et_block](#et_block)|999|18343755|14|0.0%|0.1%|
[shunlist](#shunlist)|1279|1279|12|0.9%|0.1%|
[openbl_60d](#openbl_60d)|7177|7177|8|0.1%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7429|7429|5|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|4|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|16300|16300|4|0.0%|0.0%|
[openbl_30d](#openbl_30d)|2857|2857|3|0.1%|0.0%|
[et_tor](#et_tor)|6400|6400|3|0.0%|0.0%|
[dm_tor](#dm_tor)|6417|6417|3|0.0%|0.0%|
[bm_tor](#bm_tor)|6416|6416|3|0.0%|0.0%|
[nixspam](#nixspam)|20501|20501|2|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|2|0.0%|0.0%|
[et_compromised](#et_compromised)|1678|1678|2|0.1%|0.0%|
[ciarmy](#ciarmy)|447|447|2|0.4%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1718|1718|2|0.1%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2511|2511|2|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.0%|
[firehol_proxies](#firehol_proxies)|11509|11733|1|0.0%|0.0%|
[dshield](#dshield)|20|5120|1|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4930|4930|1|0.0%|0.0%|

## xroxy

[xroxy.com](http://www.xroxy.com) open proxies (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.xroxy.com/proxyrss.xml).

The last time downloaded was found to be dated: Tue Jun  9 11:33:02 UTC 2015.

The ipset `xroxy` has **2139** entries, **2139** unique IPs.

The following table shows the overlaps of `xroxy` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `xroxy`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `xroxy`.
- ` this % ` is the percentage **of this ipset (`xroxy`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_proxies](#firehol_proxies)|11509|11733|2139|18.2%|100.0%|
[firehol_anonymous](#firehol_anonymous)|17940|81947|2139|2.6%|100.0%|
[firehol_level3](#firehol_level3)|108375|9625859|1279|0.0%|59.7%|
[stopforumspam_30d](#stopforumspam_30d)|92512|92512|1265|1.3%|59.1%|
[ri_web_proxies](#ri_web_proxies)|7263|7263|935|12.8%|43.7%|
[stopforumspam_7d](#stopforumspam_7d)|29277|29277|648|2.2%|30.2%|
[proxz](#proxz)|1122|1122|405|36.0%|18.9%|
[ri_connect_proxies](#ri_connect_proxies)|2644|2644|382|14.4%|17.8%|
[proxyrss](#proxyrss)|1212|1212|333|27.4%|15.5%|
[firehol_level2](#firehol_level2)|26299|37969|331|0.8%|15.4%|
[stopforumspam_1d](#stopforumspam_1d)|7429|7429|245|3.2%|11.4%|
[blocklist_de](#blocklist_de)|31902|31902|203|0.6%|9.4%|
[blocklist_de_bots](#blocklist_de_bots)|3443|3443|163|4.7%|7.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|105|0.0%|4.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|104|0.0%|4.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|58|0.0%|2.7%|
[nixspam](#nixspam)|20501|20501|51|0.2%|2.3%|
[blocklist_de_mail](#blocklist_de_mail)|20132|20132|43|0.2%|2.0%|
[php_dictionary](#php_dictionary)|666|666|39|5.8%|1.8%|
[snort_ipfilter](#snort_ipfilter)|10116|10116|36|0.3%|1.6%|
[php_spammers](#php_spammers)|661|661|32|4.8%|1.4%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|13|1.9%|0.6%|
[php_commenters](#php_commenters)|385|385|8|2.0%|0.3%|
[blocklist_de_strongips](#blocklist_de_strongips)|173|173|5|2.8%|0.2%|
[alienvault_reputation](#alienvault_reputation)|182730|182730|5|0.0%|0.2%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|3|0.0%|0.1%|
[php_harvesters](#php_harvesters)|366|366|2|0.5%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.0%|
[et_tor](#et_tor)|6400|6400|1|0.0%|0.0%|
[et_compromised](#et_compromised)|1678|1678|1|0.0%|0.0%|
[dm_tor](#dm_tor)|6417|6417|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1718|1718|1|0.0%|0.0%|
[bm_tor](#bm_tor)|6416|6416|1|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2743|2743|1|0.0%|0.0%|

## zeus

[Abuse.ch Zeus tracker](https://zeustracker.abuse.ch) standard, contains the same data as the ZeuS IP blocklist (zeus_badips) but with the slight difference that it doesn't exclude hijacked websites (level 2) and free web hosting providers (level 3). This means that this blocklist contains all IPv4 addresses associated with ZeuS C&Cs which are currently being tracked by ZeuS Tracker. Hence this blocklist will likely cause some false positives. - **excellent list**

Source is downloaded from [this link](https://zeustracker.abuse.ch/blocklist.php?download=ipblocklist).

The last time downloaded was found to be dated: Tue Jun  9 11:45:21 UTC 2015.

The ipset `zeus` has **233** entries, **233** unique IPs.

The following table shows the overlaps of `zeus` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `zeus`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `zeus`.
- ` this % ` is the percentage **of this ipset (`zeus`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level1](#firehol_level1)|5148|688978821|233|0.0%|100.0%|
[et_block](#et_block)|999|18343755|229|0.0%|98.2%|
[firehol_level3](#firehol_level3)|108375|9625859|204|0.0%|87.5%|
[zeus_badips](#zeus_badips)|202|202|202|100.0%|86.6%|
[snort_ipfilter](#snort_ipfilter)|10116|10116|201|1.9%|86.2%|
[alienvault_reputation](#alienvault_reputation)|182730|182730|63|0.0%|27.0%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|16|0.0%|6.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|14|0.0%|6.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|10|0.0%|4.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|9|0.0%|3.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|7|0.0%|3.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|5|0.0%|2.1%|
[stopforumspam_30d](#stopforumspam_30d)|92512|92512|2|0.0%|0.8%|
[openbl_60d](#openbl_60d)|7177|7177|2|0.0%|0.8%|
[stopforumspam_7d](#stopforumspam_7d)|29277|29277|1|0.0%|0.4%|
[stopforumspam_1d](#stopforumspam_1d)|7429|7429|1|0.0%|0.4%|
[php_commenters](#php_commenters)|385|385|1|0.2%|0.4%|
[openbl_30d](#openbl_30d)|2857|2857|1|0.0%|0.4%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|1|0.0%|0.4%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.4%|
[firehol_level2](#firehol_level2)|26299|37969|1|0.0%|0.4%|

## zeus_badips

[Abuse.ch Zeus tracker](https://zeustracker.abuse.ch) badips includes IPv4 addresses that are used by the ZeuS trojan. It is the recommened blocklist if you want to block only ZeuS IPs. It excludes IP addresses that ZeuS Tracker believes to be hijacked (level 2) or belong to a free web hosting provider (level 3). Hence the false postive rate should be much lower compared to the standard ZeuS IP blocklist. **excellent list**

Source is downloaded from [this link](https://zeustracker.abuse.ch/blocklist.php?download=badips).

The last time downloaded was found to be dated: Tue Jun  9 12:27:05 UTC 2015.

The ipset `zeus_badips` has **202** entries, **202** unique IPs.

The following table shows the overlaps of `zeus_badips` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `zeus_badips`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `zeus_badips`.
- ` this % ` is the percentage **of this ipset (`zeus_badips`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[zeus](#zeus)|233|233|202|86.6%|100.0%|
[firehol_level1](#firehol_level1)|5148|688978821|202|0.0%|100.0%|
[et_block](#et_block)|999|18343755|202|0.0%|100.0%|
[firehol_level3](#firehol_level3)|108375|9625859|180|0.0%|89.1%|
[snort_ipfilter](#snort_ipfilter)|10116|10116|178|1.7%|88.1%|
[alienvault_reputation](#alienvault_reputation)|182730|182730|37|0.0%|18.3%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|16|0.0%|7.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|10|0.0%|4.9%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|10|0.0%|4.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|8|0.0%|3.9%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|5|0.0%|2.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|4|0.0%|1.9%|
[stopforumspam_30d](#stopforumspam_30d)|92512|92512|2|0.0%|0.9%|
[stopforumspam_7d](#stopforumspam_7d)|29277|29277|1|0.0%|0.4%|
[stopforumspam_1d](#stopforumspam_1d)|7429|7429|1|0.0%|0.4%|
[php_commenters](#php_commenters)|385|385|1|0.2%|0.4%|
[openbl_60d](#openbl_60d)|7177|7177|1|0.0%|0.4%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.4%|
[firehol_level2](#firehol_level2)|26299|37969|1|0.0%|0.4%|
