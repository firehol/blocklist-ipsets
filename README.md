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

The following list was automatically generated on Tue Jun  9 08:37:31 UTC 2015.

The update frequency is the maximum allowed by internal configuration. A list will never be downloaded sooner than the update frequency stated. A list may also not be downloaded, after this frequency expired, if it has not been modified on the server (as reported by HTTP `IF_MODIFIED_SINCE` method).

name|info|type|entries|update|
:--:|:--:|:--:|:-----:|:----:|
[alienvault_reputation](#alienvault_reputation)|[AlienVault.com](https://www.alienvault.com/) IP reputation database (this list seems to include port scanning hosts and to be updated regularly, but we found no information about its retention policy)|ipv4 hash:ip|180914 unique IPs|updated every 6 hours  from [this link](https://reputation.alienvault.com/reputation.generic)
[blocklist_de](#blocklist_de)|[Blocklist.de](https://www.blocklist.de/) IPs that have been detected by fail2ban in the last 48 hours - **excellent list**|ipv4 hash:ip|31644 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/all.txt)
[blocklist_de_apache](#blocklist_de_apache)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service Apache, Apache-DDOS, RFI-Attacks.|ipv4 hash:ip|16180 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/apache.txt)
[blocklist_de_bots](#blocklist_de_bots)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the RFI-Attacks, REG-Bots, IRC-Bots or BadBots (BadBots = he has posted a Spam-Comment on a open Forum or Wiki).|ipv4 hash:ip|3492 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/bots.txt)
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|[Blocklist.de](https://www.blocklist.de/) All IPs which attacks Joomlas, Wordpress and other Web-Logins with Brute-Force Logins.|ipv4 hash:ip|4860 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/bruteforcelogin.txt)
[blocklist_de_ftp](#blocklist_de_ftp)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours for attacks on the Service FTP.|ipv4 hash:ip|360 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/ftp.txt)
[blocklist_de_imap](#blocklist_de_imap)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours for attacks on the Service imap, sasl, pop3, etc.|ipv4 hash:ip|2596 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/imap.txt)
[blocklist_de_mail](#blocklist_de_mail)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service Mail, Postfix.|ipv4 hash:ip|20039 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/mail.txt)
[blocklist_de_sip](#blocklist_de_sip)|[Blocklist.de](https://www.blocklist.de/) All IP addresses that tried to login in a SIP, VOIP or Asterisk Server and are included in the IPs list from [infiltrated.net](www.infiltrated.net)|ipv4 hash:ip|89 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/sip.txt)
[blocklist_de_ssh](#blocklist_de_ssh)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service SSH.|ipv4 hash:ip|2582 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/ssh.txt)
[blocklist_de_strongips](#blocklist_de_strongips)|[Blocklist.de](https://www.blocklist.de/) All IPs which are older then 2 month and have more then 5.000 attacks.|ipv4 hash:ip|166 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/strongips.txt)
[bm_tor](#bm_tor)|[torstatus.blutmagie.de](https://torstatus.blutmagie.de) list of all TOR network servers|ipv4 hash:ip|6355 unique IPs|updated every 30 mins  from [this link](https://torstatus.blutmagie.de/ip_list_all.php/Tor_ip_list_ALL.csv)
[bogons](#bogons)|[Team-Cymru.org](http://www.team-cymru.org) private and reserved addresses defined by RFC 1918, RFC 5735, and RFC 6598 and netblocks that have not been allocated to a regional internet registry - **excellent list - use it only your internet interface**|ipv4 hash:net|13 subnets, 592708608 unique IPs|updated every 1 day  from [this link](http://www.team-cymru.org/Services/Bogons/bogon-bn-agg.txt)
[bruteforceblocker](#bruteforceblocker)|[danger.rulez.sk](http://danger.rulez.sk/) IPs detected by [bruteforceblocker](http://danger.rulez.sk/index.php/bruteforceblocker/) (fail2ban alternative for SSH on OpenBSD). This is an automatically generated list from users reporting failed authentication attempts. An IP seems to be included if 3 or more users report it. Its retention pocily seems 30 days.|ipv4 hash:ip|1725 unique IPs|updated every 3 hours  from [this link](http://danger.rulez.sk/projects/bruteforceblocker/blist.php)
[ciarmy](#ciarmy)|[CIArmy.com](http://ciarmy.com/) IPs with poor Rogue Packet score that have not yet been identified as malicious by the community|ipv4 hash:ip|430 unique IPs|updated every 3 hours  from [this link](http://cinsscore.com/list/ci-badguys.txt)
[cleanmx_viruses](#cleanmx_viruses)|[Clean-MX.de](http://support.clean-mx.de/clean-mx/viruses.php) IPs with viruses|ipv4 hash:ip|6 unique IPs|updated every 12 hours  from [this link](http://support.clean-mx.de/clean-mx/xmlviruses.php?sort=id%20desc&response=alive)
[dm_tor](#dm_tor)|[dan.me.uk](https://www.dan.me.uk) dynamic list of TOR exit points|ipv4 hash:ip|6391 unique IPs|updated every 30 mins  from [this link](https://www.dan.me.uk/torlist/)
[dshield](#dshield)|[DShield.org](https://dshield.org/) top 20 attacking class C (/24) subnets over the last three days - **excellent list**|ipv4 hash:net|20 subnets, 5120 unique IPs|updated every 4 hours  from [this link](http://feeds.dshield.org/block.txt)
[et_block](#et_block)|[EmergingThreats.net](http://www.emergingthreats.net/) default blacklist (at the time of writing includes spamhaus DROP, dshield and abuse.ch trackers, which are available separately too - prefer to use the direct ipsets instead of this, they seem to lag a bit in updates)|ipv4 hash:net|999 subnets, 18343755 unique IPs|updated every 12 hours  from [this link](http://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt)
[et_botcc](#et_botcc)|[EmergingThreats.net Command and Control IPs](http://doc.emergingthreats.net/bin/view/Main/BotCC) These IPs are updates every 24 hours and should be considered VERY highly reliable indications that a host is communicating with a known and active Bot or Malware command and control server - (although they say this includes abuse.ch trackers, it does not - most probably it is the shadowserver.org C&C list)|ipv4 hash:ip|509 unique IPs|updated every 12 hours  from [this link](http://rules.emergingthreats.net/fwrules/emerging-PIX-CC.rules)
[et_compromised](#et_compromised)|[EmergingThreats.net compromised hosts](http://doc.emergingthreats.net/bin/view/Main/CompromisedHost) - (this seems to be based on bruteforceblocker)|ipv4 hash:ip|1678 unique IPs|updated every 12 hours  from [this link](http://rules.emergingthreats.net/blockrules/compromised-ips.txt)
et_dshield|[EmergingThreats.net](http://www.emergingthreats.net/) dshield blocklist|ipv4 hash:net|disabled|updated every 12 hours  from [this link](http://rules.emergingthreats.net/fwrules/emerging-PIX-DSHIELD.rules)
et_spamhaus|[EmergingThreats.net](http://www.emergingthreats.net/) spamhaus blocklist|ipv4 hash:net|disabled|updated every 12 hours  from [this link](http://rules.emergingthreats.net/fwrules/emerging-PIX-DROP.rules)
[et_tor](#et_tor)|[EmergingThreats.net](http://www.emergingthreats.net/) [list](http://doc.emergingthreats.net/bin/view/Main/TorRules) of TOR network IPs|ipv4 hash:ip|6400 unique IPs|updated every 12 hours  from [this link](http://rules.emergingthreats.net/blockrules/emerging-tor.rules)
[feodo](#feodo)|[Abuse.ch Feodo tracker](https://feodotracker.abuse.ch) trojan includes IPs which are being used by Feodo (also known as Cridex or Bugat) which commits ebanking fraud - **excellent list**|ipv4 hash:ip|103 unique IPs|updated every 30 mins  from [this link](https://feodotracker.abuse.ch/blocklist/?download=ipblocklist)
[firehol_anonymous](#firehol_anonymous)|**FireHOL Anonymous** - Known anonymizing IPs. (includes: firehol_proxies anonymous bm_tor dm_tor)|ipv4 hash:net|18076 subnets, 82086 unique IPs|updated every 1 min  from [this link]()
[firehol_level1](#firehol_level1)|**FireHOL Level 1** - Maximum protection without false positives. (includes: fullbogons dshield feodo palevo sslbl zeus spamhaus_drop spamhaus_edrop)|ipv4 hash:net|5092 subnets, 688943415 unique IPs|updated every 1 min  from [this link]()
[firehol_level2](#firehol_level2)|**FireHOL Level 2** - Maximum protection from attacks took place in the last 48 hours. (includes: openbl_1d blocklist_de stopforumspam_1d)|ipv4 hash:net|26088 subnets, 37744 unique IPs|updated every 1 min  from [this link]()
[firehol_level3](#firehol_level3)|**FireHOL Level 3** - All the bad IPs in last 30 days. (includes: openbl_30d stopforumspam_30d virbl malc0de shunlist malwaredomainlist bruteforceblocker ciarmy cleanmx_viruses snort_ipfilter ib_bluetack_spyware ib_bluetack_hijacked ib_bluetack_webexploit php_commenters php_dictionary php_harvesters php_spammers)|ipv4 hash:net|108319 subnets, 9625797 unique IPs|updated every 1 min  from [this link]()
[firehol_proxies](#firehol_proxies)|**FireHOL Proxies** - Known open proxies in the last 30 days. (includes: ib_bluetack_proxies maxmind_proxy_fraud proxyrss proxz ri_connect_proxies ri_web_proxies xroxy)|ipv4 hash:net|11673 subnets, 11900 unique IPs|updated every 1 min  from [this link]()
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
[ipdeny_country](https://github.com/ktsaou/blocklist-ipsets/tree/master/ipdeny_country)|[IPDeny.com](http://www.ipdeny.com/) geolocation database|ipv4 hash:net|All the world|updated every 1 day  from [this link](http://www.ipdeny.com/ipblocks/data/countries/all-zones.tar.gz)
lashback_ubl|[The LashBack UBL](http://blacklist.lashback.com/) The Unsubscribe Blacklist (UBL) is a real-time blacklist of IP addresses which are sending email to names harvested from suppression files (this is a big list, more than 500.000 IPs)|ipv4 hash:ip|disabled|updated every 1 day  from [this link](http://www.unsubscore.com/blacklist.txt)
[malc0de](#malc0de)|[Malc0de.com](http://malc0de.com) malicious IPs of the last 30 days|ipv4 hash:ip|342 unique IPs|updated every 1 day  from [this link](http://malc0de.com/bl/IP_Blacklist.txt)
[malwaredomainlist](#malwaredomainlist)|[malwaredomainlist.com](http://www.malwaredomainlist.com) list of malware active ip addresses|ipv4 hash:ip|1288 unique IPs|updated every 12 hours  from [this link](http://www.malwaredomainlist.com/hostslist/ip.txt)
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|[MaxMind.com](https://www.maxmind.com/en/anonymous-proxy-fraudulent-ip-address-list) list of anonymous proxy fraudelent IP addresses.|ipv4 hash:ip|372 unique IPs|updated every 4 hours  from [this link](https://www.maxmind.com/en/anonymous-proxy-fraudulent-ip-address-list)
[nixspam](#nixspam)|[NiX Spam](http://www.heise.de/ix/NiX-Spam-DNSBL-and-blacklist-for-download-499637.html) IP addresses that sent spam in the last hour - automatically generated entries without distinguishing open proxies from relays, dialup gateways, and so on. All IPs are removed after 12 hours if there is no spam from there.|ipv4 hash:ip|17190 unique IPs|updated every 15 mins  from [this link](http://www.dnsbl.manitu.net/download/nixspam-ip.dump.gz)
openbl|[OpenBL.org](http://www.openbl.org/) default blacklist (currently it is the same with 90 days). OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications - **excellent list**|ipv4 hash:ip|disabled|updated every 4 hours  from [this link](http://www.openbl.org/lists/base.txt)
openbl_180d|[OpenBL.org](http://www.openbl.org/) last 180 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|disabled|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_180days.txt)
[openbl_1d](#openbl_1d)|[OpenBL.org](http://www.openbl.org/) last 24 hours IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|137 unique IPs|updated every 1 hour  from [this link](http://www.openbl.org/lists/base_1days.txt)
[openbl_30d](#openbl_30d)|[OpenBL.org](http://www.openbl.org/) last 30 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|2861 unique IPs|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_30days.txt)
openbl_360d|[OpenBL.org](http://www.openbl.org/) last 360 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|disabled|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_360days.txt)
[openbl_60d](#openbl_60d)|[OpenBL.org](http://www.openbl.org/) last 60 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|7190 unique IPs|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_60days.txt)
[openbl_7d](#openbl_7d)|[OpenBL.org](http://www.openbl.org/) last 7 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|826 unique IPs|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_7days.txt)
openbl_90d|[OpenBL.org](http://www.openbl.org/) last 90 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|disabled|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_90days.txt)
openbl_all|[OpenBL.org](http://www.openbl.org/) last all IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|disabled|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_all.txt)
[palevo](#palevo)|[Abuse.ch Palevo tracker](https://palevotracker.abuse.ch) worm includes IPs which are being used as botnet C&C for the Palevo crimeware - **excellent list**|ipv4 hash:ip|13 unique IPs|updated every 30 mins  from [this link](https://palevotracker.abuse.ch/blocklists.php?download=ipblocklist)
php_bad|[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) bad web hosts (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|disabled|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=b&rss=1)
[php_commenters](#php_commenters)|[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) comment spammers (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|385 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=c&rss=1)
[php_dictionary](#php_dictionary)|[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) directory attackers (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|630 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=d&rss=1)
[php_harvesters](#php_harvesters)|[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) harvesters (IPs that surf the internet looking for email addresses) (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|366 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=h&rss=1)
[php_spammers](#php_spammers)|[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) spam servers (IPs used by spammers to send messages) (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|622 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=s&rss=1)
[proxyrss](#proxyrss)|[proxyrss.com](http://www.proxyrss.com) open proxies syndicated from multiple sources.|ipv4 hash:ip|1495 unique IPs|updated every 4 hours  from [this link](http://www.proxyrss.com/proxylists/all.gz)
[proxz](#proxz)|[proxz.com](http://www.proxz.com) open proxies (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|1108 unique IPs|updated every 1 hour  from [this link](http://www.proxz.com/proxylists.xml)
[ri_connect_proxies](#ri_connect_proxies)|[rosinstrument.com](http://www.rosinstrument.com) open CONNECT proxies (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|2644 unique IPs|updated every 1 hour  from [this link](http://tools.rosinstrument.com/proxy/plab100.xml)
[ri_web_proxies](#ri_web_proxies)|[rosinstrument.com](http://www.rosinstrument.com) open HTTP proxies (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|7263 unique IPs|updated every 1 hour  from [this link](http://tools.rosinstrument.com/proxy/l100.xml)
[shunlist](#shunlist)|[AutoShun.org](http://autoshun.org/) IPs identified as hostile by correlating logs from distributed snort installations running the autoshun plugin|ipv4 hash:ip|1264 unique IPs|updated every 4 hours  from [this link](http://www.autoshun.org/files/shunlist.csv)
[snort_ipfilter](#snort_ipfilter)|[labs.snort.org](https://labs.snort.org/) supplied IP blacklist (this list seems to be updated frequently, but we found no information about it)|ipv4 hash:ip|10116 unique IPs|updated every 12 hours  from [this link](http://labs.snort.org/feeds/ip-filter.blf)
[spamhaus_drop](#spamhaus_drop)|[Spamhaus.org](http://www.spamhaus.org) DROP list (according to their site this list should be dropped at tier-1 ISPs globaly) - **excellent list**|ipv4 hash:net|652 subnets, 18338560 unique IPs|updated every 12 hours  from [this link](http://www.spamhaus.org/drop/drop.txt)
[spamhaus_edrop](#spamhaus_edrop)|[Spamhaus.org](http://www.spamhaus.org) EDROP (extended matches that should be used with DROP) - **excellent list**|ipv4 hash:net|56 subnets, 487424 unique IPs|updated every 12 hours  from [this link](http://www.spamhaus.org/drop/edrop.txt)
[sslbl](#sslbl)|[Abuse.ch SSL Blacklist](https://sslbl.abuse.ch/) bad SSL traffic related to malware or botnet activities - **excellent list**|ipv4 hash:ip|382 unique IPs|updated every 30 mins  from [this link](https://sslbl.abuse.ch/blacklist/sslipblacklist.csv)
stopforumspam_180d|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 180 days)|ipv4 hash:ip|disabled|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/listed_ip_180.zip)
[stopforumspam_1d](#stopforumspam_1d)|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers in the last 24 hours - **excellent list**|ipv4 hash:ip|7467 unique IPs|updated every 1 hour  from [this link](http://www.stopforumspam.com/downloads/listed_ip_1.zip)
[stopforumspam_30d](#stopforumspam_30d)|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 30 days)|ipv4 hash:ip|92512 unique IPs|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/listed_ip_30.zip)
stopforumspam_365d|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 365 days)|ipv4 hash:ip|disabled|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/listed_ip_365.zip)
[stopforumspam_7d](#stopforumspam_7d)|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 7 days)|ipv4 hash:ip|29277 unique IPs|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/listed_ip_7.zip)
stopforumspam_90d|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 90 days)|ipv4 hash:ip|disabled|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/listed_ip_90.zip)
stopforumspam_ever|[StopForumSpam.com](http://www.stopforumspam.com) all IPs used by forum spammers, **ever** (normally you don't want to use this ipset, use the hourly one which includes last 24 hours IPs or the 7 days one)|ipv4 hash:ip|disabled|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/bannedips.zip)
[virbl](#virbl)|[VirBL](http://virbl.bit.nl/) is a project of which the idea was born during the RIPE-48 meeting. The plan was to get reports of virusscanning mailservers, and put the IP-addresses that were reported to send viruses on a blacklist.|ipv4 hash:ip|14 unique IPs|updated every 1 hour  from [this link](http://virbl.bit.nl/download/virbl.dnsbl.bit.nl.txt)
[voipbl](#voipbl)|[VoIPBL.org](http://www.voipbl.org/) a distributed VoIP blacklist that is aimed to protects against VoIP Fraud and minimizing abuse for network that have publicly accessible PBX's. Several algorithms, external sources and manual confirmation are used before they categorize something as an attack and determine the threat level.|ipv4 hash:net|10507 subnets, 10919 unique IPs|updated every 4 hours  from [this link](http://www.voipbl.org/update/)
[xroxy](#xroxy)|[xroxy.com](http://www.xroxy.com) open proxies (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|2138 unique IPs|updated every 1 hour  from [this link](http://www.xroxy.com/proxyrss.xml)
[zeus](#zeus)|[Abuse.ch Zeus tracker](https://zeustracker.abuse.ch) standard, contains the same data as the ZeuS IP blocklist (zeus_badips) but with the slight difference that it doesn't exclude hijacked websites (level 2) and free web hosting providers (level 3). This means that this blocklist contains all IPv4 addresses associated with ZeuS C&Cs which are currently being tracked by ZeuS Tracker. Hence this blocklist will likely cause some false positives. - **excellent list**|ipv4 hash:ip|232 unique IPs|updated every 30 mins  from [this link](https://zeustracker.abuse.ch/blocklist.php?download=ipblocklist)
[zeus_badips](#zeus_badips)|[Abuse.ch Zeus tracker](https://zeustracker.abuse.ch) badips includes IPv4 addresses that are used by the ZeuS trojan. It is the recommened blocklist if you want to block only ZeuS IPs. It excludes IP addresses that ZeuS Tracker believes to be hijacked (level 2) or belong to a free web hosting provider (level 3). Hence the false postive rate should be much lower compared to the standard ZeuS IP blocklist. **excellent list**|ipv4 hash:ip|203 unique IPs|updated every 30 mins  from [this link](https://zeustracker.abuse.ch/blocklist.php?download=badips)

# Comparison of ipsets

Below we compare each ipset against all other.


## alienvault_reputation

[AlienVault.com](https://www.alienvault.com/) IP reputation database (this list seems to include port scanning hosts and to be updated regularly, but we found no information about its retention policy)

Source is downloaded from [this link](https://reputation.alienvault.com/reputation.generic).

The last time downloaded was found to be dated: Tue Jun  9 04:00:22 UTC 2015.

The ipset `alienvault_reputation` has **180914** entries, **180914** unique IPs.

The following table shows the overlaps of `alienvault_reputation` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `alienvault_reputation`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `alienvault_reputation`.
- ` this % ` is the percentage **of this ipset (`alienvault_reputation`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|14114|0.0%|7.8%|
[openbl_60d](#openbl_60d)|7190|7190|7167|99.6%|3.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|6256|0.0%|3.4%|
[et_block](#et_block)|999|18343755|5280|0.0%|2.9%|
[firehol_level3](#firehol_level3)|108319|9625797|5146|0.0%|2.8%|
[firehol_level1](#firehol_level1)|5092|688943415|5105|0.0%|2.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|4214|0.0%|2.3%|
[dshield](#dshield)|20|5120|4099|80.0%|2.2%|
[openbl_30d](#openbl_30d)|2861|2861|2844|99.4%|1.5%|
[firehol_level2](#firehol_level2)|26088|37744|1422|3.7%|0.7%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|1374|0.0%|0.7%|
[blocklist_de](#blocklist_de)|31644|31644|1370|4.3%|0.7%|
[shunlist](#shunlist)|1264|1264|1252|99.0%|0.6%|
[blocklist_de_ssh](#blocklist_de_ssh)|2582|2582|1132|43.8%|0.6%|
[bruteforceblocker](#bruteforceblocker)|1725|1725|1101|63.8%|0.6%|
[et_compromised](#et_compromised)|1678|1678|1077|64.1%|0.5%|
[openbl_7d](#openbl_7d)|826|826|820|99.2%|0.4%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|518|0.0%|0.2%|
[ciarmy](#ciarmy)|430|430|405|94.1%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|288|0.0%|0.1%|
[stopforumspam_30d](#stopforumspam_30d)|92512|92512|198|0.2%|0.1%|
[voipbl](#voipbl)|10507|10919|189|1.7%|0.1%|
[openbl_1d](#openbl_1d)|137|137|133|97.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|10116|10116|124|1.2%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|16180|16180|117|0.7%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29277|29277|98|0.3%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|20039|20039|71|0.3%|0.0%|
[sslbl](#sslbl)|382|382|68|17.8%|0.0%|
[zeus](#zeus)|232|232|63|27.1%|0.0%|
[firehol_anonymous](#firehol_anonymous)|18076|82086|55|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2596|2596|49|1.8%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7467|7467|48|0.6%|0.0%|
[et_tor](#et_tor)|6400|6400|41|0.6%|0.0%|
[dm_tor](#dm_tor)|6391|6391|41|0.6%|0.0%|
[bm_tor](#bm_tor)|6355|6355|41|0.6%|0.0%|
[zeus_badips](#zeus_badips)|203|203|38|18.7%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|166|166|36|21.6%|0.0%|
[nixspam](#nixspam)|17190|17190|34|0.1%|0.0%|
[firehol_proxies](#firehol_proxies)|11673|11900|33|0.2%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3492|3492|32|0.9%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|26|6.9%|0.0%|
[php_commenters](#php_commenters)|385|385|17|4.4%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|89|89|16|17.9%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4860|4860|16|0.3%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|15|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|14|0.0%|0.0%|
[php_harvesters](#php_harvesters)|366|366|11|3.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|360|360|11|3.0%|0.0%|
[malc0de](#malc0de)|342|342|10|2.9%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|10|0.6%|0.0%|
[php_dictionary](#php_dictionary)|630|630|8|1.2%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|7|0.5%|0.0%|
[xroxy](#xroxy)|2138|2138|5|0.2%|0.0%|
[php_spammers](#php_spammers)|622|622|5|0.8%|0.0%|
[et_botcc](#et_botcc)|509|509|5|0.9%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7263|7263|3|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2644|2644|3|0.1%|0.0%|
[proxz](#proxz)|1108|1108|3|0.2%|0.0%|
[feodo](#feodo)|103|103|2|1.9%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|1|0.1%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|6|6|1|16.6%|0.0%|

## blocklist_de

[Blocklist.de](https://www.blocklist.de/) IPs that have been detected by fail2ban in the last 48 hours - **excellent list**

Source is downloaded from [this link](http://lists.blocklist.de/lists/all.txt).

The last time downloaded was found to be dated: Tue Jun  9 08:14:06 UTC 2015.

The ipset `blocklist_de` has **31644** entries, **31644** unique IPs.

The following table shows the overlaps of `blocklist_de` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de`.
- ` this % ` is the percentage **of this ipset (`blocklist_de`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|26088|37744|31644|83.8%|100.0%|
[blocklist_de_mail](#blocklist_de_mail)|20039|20039|20039|100.0%|63.3%|
[blocklist_de_apache](#blocklist_de_apache)|16180|16180|16180|100.0%|51.1%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4860|4860|4860|100.0%|15.3%|
[firehol_level3](#firehol_level3)|108319|9625797|4120|0.0%|13.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|3696|0.0%|11.6%|
[blocklist_de_bots](#blocklist_de_bots)|3492|3492|3492|100.0%|11.0%|
[stopforumspam_30d](#stopforumspam_30d)|92512|92512|2695|2.9%|8.5%|
[blocklist_de_imap](#blocklist_de_imap)|2596|2596|2584|99.5%|8.1%|
[blocklist_de_ssh](#blocklist_de_ssh)|2582|2582|2578|99.8%|8.1%|
[stopforumspam_7d](#stopforumspam_7d)|29277|29277|2315|7.9%|7.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|1602|0.0%|5.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|1565|0.0%|4.9%|
[stopforumspam_1d](#stopforumspam_1d)|7467|7467|1385|18.5%|4.3%|
[alienvault_reputation](#alienvault_reputation)|180914|180914|1370|0.7%|4.3%|
[openbl_60d](#openbl_60d)|7190|7190|1039|14.4%|3.2%|
[openbl_30d](#openbl_30d)|2861|2861|845|29.5%|2.6%|
[bruteforceblocker](#bruteforceblocker)|1725|1725|737|42.7%|2.3%|
[et_compromised](#et_compromised)|1678|1678|654|38.9%|2.0%|
[firehol_anonymous](#firehol_anonymous)|18076|82086|617|0.7%|1.9%|
[firehol_proxies](#firehol_proxies)|11673|11900|609|5.1%|1.9%|
[nixspam](#nixspam)|17190|17190|592|3.4%|1.8%|
[shunlist](#shunlist)|1264|1264|453|35.8%|1.4%|
[ri_web_proxies](#ri_web_proxies)|7263|7263|410|5.6%|1.2%|
[openbl_7d](#openbl_7d)|826|826|405|49.0%|1.2%|
[blocklist_de_ftp](#blocklist_de_ftp)|360|360|347|96.3%|1.0%|
[snort_ipfilter](#snort_ipfilter)|10116|10116|315|3.1%|0.9%|
[firehol_level1](#firehol_level1)|5092|688943415|228|0.0%|0.7%|
[proxyrss](#proxyrss)|1495|1495|212|14.1%|0.6%|
[et_block](#et_block)|999|18343755|210|0.0%|0.6%|
[xroxy](#xroxy)|2138|2138|201|9.4%|0.6%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|199|0.0%|0.6%|
[blocklist_de_strongips](#blocklist_de_strongips)|166|166|166|100.0%|0.5%|
[proxz](#proxz)|1108|1108|160|14.4%|0.5%|
[dshield](#dshield)|20|5120|129|2.5%|0.4%|
[openbl_1d](#openbl_1d)|137|137|119|86.8%|0.3%|
[php_dictionary](#php_dictionary)|630|630|91|14.4%|0.2%|
[php_commenters](#php_commenters)|385|385|91|23.6%|0.2%|
[php_spammers](#php_spammers)|622|622|82|13.1%|0.2%|
[ri_connect_proxies](#ri_connect_proxies)|2644|2644|76|2.8%|0.2%|
[blocklist_de_sip](#blocklist_de_sip)|89|89|70|78.6%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|55|0.0%|0.1%|
[php_harvesters](#php_harvesters)|366|366|39|10.6%|0.1%|
[voipbl](#voipbl)|10507|10919|33|0.3%|0.1%|
[ciarmy](#ciarmy)|430|430|33|7.6%|0.1%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|11|0.0%|0.0%|
[et_tor](#et_tor)|6400|6400|9|0.1%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|7|0.0%|0.0%|
[dm_tor](#dm_tor)|6391|6391|6|0.0%|0.0%|
[bm_tor](#bm_tor)|6355|6355|6|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|4|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|3|0.4%|0.0%|
[sslbl](#sslbl)|382|382|1|0.2%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|1|0.0%|0.0%|

## blocklist_de_apache

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service Apache, Apache-DDOS, RFI-Attacks.

Source is downloaded from [this link](http://lists.blocklist.de/lists/apache.txt).

The last time downloaded was found to be dated: Tue Jun  9 08:14:10 UTC 2015.

The ipset `blocklist_de_apache` has **16180** entries, **16180** unique IPs.

The following table shows the overlaps of `blocklist_de_apache` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_apache`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_apache`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_apache`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|26088|37744|16180|42.8%|100.0%|
[blocklist_de](#blocklist_de)|31644|31644|16180|51.1%|100.0%|
[blocklist_de_mail](#blocklist_de_mail)|20039|20039|11059|55.1%|68.3%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4860|4860|4860|100.0%|30.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|2434|0.0%|15.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|1333|0.0%|8.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|1099|0.0%|6.7%|
[firehol_level3](#firehol_level3)|108319|9625797|283|0.0%|1.7%|
[stopforumspam_30d](#stopforumspam_30d)|92512|92512|210|0.2%|1.2%|
[stopforumspam_7d](#stopforumspam_7d)|29277|29277|128|0.4%|0.7%|
[alienvault_reputation](#alienvault_reputation)|180914|180914|117|0.0%|0.7%|
[stopforumspam_1d](#stopforumspam_1d)|7467|7467|63|0.8%|0.3%|
[blocklist_de_strongips](#blocklist_de_strongips)|166|166|33|19.8%|0.2%|
[shunlist](#shunlist)|1264|1264|32|2.5%|0.1%|
[php_commenters](#php_commenters)|385|385|30|7.7%|0.1%|
[ciarmy](#ciarmy)|430|430|30|6.9%|0.1%|
[nixspam](#nixspam)|17190|17190|29|0.1%|0.1%|
[blocklist_de_bots](#blocklist_de_bots)|3492|3492|21|0.6%|0.1%|
[snort_ipfilter](#snort_ipfilter)|10116|10116|19|0.1%|0.1%|
[firehol_anonymous](#firehol_anonymous)|18076|82086|13|0.0%|0.0%|
[firehol_level1](#firehol_level1)|5092|688943415|11|0.0%|0.0%|
[firehol_proxies](#firehol_proxies)|11673|11900|9|0.0%|0.0%|
[et_tor](#et_tor)|6400|6400|8|0.1%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7263|7263|7|0.0%|0.0%|
[php_spammers](#php_spammers)|622|622|7|1.1%|0.0%|
[et_block](#et_block)|999|18343755|6|0.0%|0.0%|
[dshield](#dshield)|20|5120|6|0.1%|0.0%|
[php_dictionary](#php_dictionary)|630|630|5|0.7%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|5|0.0%|0.0%|
[dm_tor](#dm_tor)|6391|6391|5|0.0%|0.0%|
[bm_tor](#bm_tor)|6355|6355|5|0.0%|0.0%|
[voipbl](#voipbl)|10507|10919|4|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|4|0.0%|0.0%|
[openbl_60d](#openbl_60d)|7190|7190|3|0.0%|0.0%|
[openbl_30d](#openbl_30d)|2861|2861|3|0.1%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|3|0.0%|0.0%|
[php_harvesters](#php_harvesters)|366|366|2|0.5%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|1|0.0%|0.0%|
[proxyrss](#proxyrss)|1495|1495|1|0.0%|0.0%|
[openbl_7d](#openbl_7d)|826|826|1|0.1%|0.0%|
[openbl_1d](#openbl_1d)|137|137|1|0.7%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|

## blocklist_de_bots

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the RFI-Attacks, REG-Bots, IRC-Bots or BadBots (BadBots = he has posted a Spam-Comment on a open Forum or Wiki).

Source is downloaded from [this link](http://lists.blocklist.de/lists/bots.txt).

The last time downloaded was found to be dated: Tue Jun  9 08:10:10 UTC 2015.

The ipset `blocklist_de_bots` has **3492** entries, **3492** unique IPs.

The following table shows the overlaps of `blocklist_de_bots` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_bots`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_bots`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_bots`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|26088|37744|3492|9.2%|100.0%|
[blocklist_de](#blocklist_de)|31644|31644|3492|11.0%|100.0%|
[firehol_level3](#firehol_level3)|108319|9625797|2407|0.0%|68.9%|
[stopforumspam_30d](#stopforumspam_30d)|92512|92512|2380|2.5%|68.1%|
[stopforumspam_7d](#stopforumspam_7d)|29277|29277|2142|7.3%|61.3%|
[stopforumspam_1d](#stopforumspam_1d)|7467|7467|1318|17.6%|37.7%|
[firehol_anonymous](#firehol_anonymous)|18076|82086|531|0.6%|15.2%|
[firehol_proxies](#firehol_proxies)|11673|11900|528|4.4%|15.1%|
[ri_web_proxies](#ri_web_proxies)|7263|7263|358|4.9%|10.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|217|0.0%|6.2%|
[proxyrss](#proxyrss)|1495|1495|211|14.1%|6.0%|
[xroxy](#xroxy)|2138|2138|163|7.6%|4.6%|
[proxz](#proxz)|1108|1108|146|13.1%|4.1%|
[blocklist_de_strongips](#blocklist_de_strongips)|166|166|124|74.6%|3.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|117|0.0%|3.3%|
[php_commenters](#php_commenters)|385|385|74|19.2%|2.1%|
[ri_connect_proxies](#ri_connect_proxies)|2644|2644|72|2.7%|2.0%|
[firehol_level1](#firehol_level1)|5092|688943415|55|0.0%|1.5%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|52|0.0%|1.4%|
[et_block](#et_block)|999|18343755|52|0.0%|1.4%|
[nixspam](#nixspam)|17190|17190|49|0.2%|1.4%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|44|0.0%|1.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|33|0.0%|0.9%|
[alienvault_reputation](#alienvault_reputation)|180914|180914|32|0.0%|0.9%|
[php_harvesters](#php_harvesters)|366|366|29|7.9%|0.8%|
[snort_ipfilter](#snort_ipfilter)|10116|10116|28|0.2%|0.8%|
[php_dictionary](#php_dictionary)|630|630|24|3.8%|0.6%|
[blocklist_de_mail](#blocklist_de_mail)|20039|20039|21|0.1%|0.6%|
[blocklist_de_apache](#blocklist_de_apache)|16180|16180|21|0.1%|0.6%|
[php_spammers](#php_spammers)|622|622|20|3.2%|0.5%|
[openbl_60d](#openbl_60d)|7190|7190|17|0.2%|0.4%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|3|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|3|0.4%|0.0%|
[openbl_30d](#openbl_30d)|2861|2861|1|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|1|0.0%|0.0%|
[et_tor](#et_tor)|6400|6400|1|0.0%|0.0%|
[dm_tor](#dm_tor)|6391|6391|1|0.0%|0.0%|
[bm_tor](#bm_tor)|6355|6355|1|0.0%|0.0%|

## blocklist_de_bruteforce

[Blocklist.de](https://www.blocklist.de/) All IPs which attacks Joomlas, Wordpress and other Web-Logins with Brute-Force Logins.

Source is downloaded from [this link](http://lists.blocklist.de/lists/bruteforcelogin.txt).

The last time downloaded was found to be dated: Tue Jun  9 08:28:11 UTC 2015.

The ipset `blocklist_de_bruteforce` has **4860** entries, **4860** unique IPs.

The following table shows the overlaps of `blocklist_de_bruteforce` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_bruteforce`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_bruteforce`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_bruteforce`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|26088|37744|4860|12.8%|100.0%|
[blocklist_de_apache](#blocklist_de_apache)|16180|16180|4860|30.0%|100.0%|
[blocklist_de](#blocklist_de)|31644|31644|4860|15.3%|100.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|340|0.0%|6.9%|
[firehol_level3](#firehol_level3)|108319|9625797|79|0.0%|1.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|66|0.0%|1.3%|
[stopforumspam_30d](#stopforumspam_30d)|92512|92512|61|0.0%|1.2%|
[stopforumspam_7d](#stopforumspam_7d)|29277|29277|42|0.1%|0.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|42|0.0%|0.8%|
[nixspam](#nixspam)|17190|17190|29|0.1%|0.5%|
[stopforumspam_1d](#stopforumspam_1d)|7467|7467|27|0.3%|0.5%|
[alienvault_reputation](#alienvault_reputation)|180914|180914|16|0.0%|0.3%|
[snort_ipfilter](#snort_ipfilter)|10116|10116|15|0.1%|0.3%|
[firehol_anonymous](#firehol_anonymous)|18076|82086|11|0.0%|0.2%|
[php_commenters](#php_commenters)|385|385|9|2.3%|0.1%|
[ri_web_proxies](#ri_web_proxies)|7263|7263|7|0.0%|0.1%|
[php_spammers](#php_spammers)|622|622|7|1.1%|0.1%|
[firehol_proxies](#firehol_proxies)|11673|11900|7|0.0%|0.1%|
[blocklist_de_strongips](#blocklist_de_strongips)|166|166|7|4.2%|0.1%|
[php_dictionary](#php_dictionary)|630|630|5|0.7%|0.1%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|5|0.0%|0.1%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|4|0.0%|0.0%|
[firehol_level1](#firehol_level1)|5092|688943415|4|0.0%|0.0%|
[et_tor](#et_tor)|6400|6400|4|0.0%|0.0%|
[et_block](#et_block)|999|18343755|4|0.0%|0.0%|
[dm_tor](#dm_tor)|6391|6391|4|0.0%|0.0%|
[bm_tor](#bm_tor)|6355|6355|4|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|2|0.0%|0.0%|
[voipbl](#voipbl)|10507|10919|1|0.0%|0.0%|
[shunlist](#shunlist)|1264|1264|1|0.0%|0.0%|
[php_harvesters](#php_harvesters)|366|366|1|0.2%|0.0%|

## blocklist_de_ftp

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours for attacks on the Service FTP.

Source is downloaded from [this link](http://lists.blocklist.de/lists/ftp.txt).

The last time downloaded was found to be dated: Tue Jun  9 08:28:07 UTC 2015.

The ipset `blocklist_de_ftp` has **360** entries, **360** unique IPs.

The following table shows the overlaps of `blocklist_de_ftp` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_ftp`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_ftp`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_ftp`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|26088|37744|347|0.9%|96.3%|
[blocklist_de](#blocklist_de)|31644|31644|347|1.0%|96.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|50|0.0%|13.8%|
[firehol_level3](#firehol_level3)|108319|9625797|15|0.0%|4.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|11|0.0%|3.0%|
[alienvault_reputation](#alienvault_reputation)|180914|180914|11|0.0%|3.0%|
[stopforumspam_30d](#stopforumspam_30d)|92512|92512|5|0.0%|1.3%|
[php_harvesters](#php_harvesters)|366|366|5|1.3%|1.3%|
[openbl_60d](#openbl_60d)|7190|7190|3|0.0%|0.8%|
[openbl_30d](#openbl_30d)|2861|2861|3|0.1%|0.8%|
[nixspam](#nixspam)|17190|17190|3|0.0%|0.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|3|0.0%|0.8%|
[stopforumspam_7d](#stopforumspam_7d)|29277|29277|2|0.0%|0.5%|
[shunlist](#shunlist)|1264|1264|2|0.1%|0.5%|
[et_compromised](#et_compromised)|1678|1678|2|0.1%|0.5%|
[bruteforceblocker](#bruteforceblocker)|1725|1725|2|0.1%|0.5%|
[blocklist_de_strongips](#blocklist_de_strongips)|166|166|2|1.2%|0.5%|
[stopforumspam_1d](#stopforumspam_1d)|7467|7467|1|0.0%|0.2%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|1|0.0%|0.2%|
[snort_ipfilter](#snort_ipfilter)|10116|10116|1|0.0%|0.2%|
[openbl_7d](#openbl_7d)|826|826|1|0.1%|0.2%|
[firehol_level1](#firehol_level1)|5092|688943415|1|0.0%|0.2%|
[firehol_anonymous](#firehol_anonymous)|18076|82086|1|0.0%|0.2%|
[et_block](#et_block)|999|18343755|1|0.0%|0.2%|
[dshield](#dshield)|20|5120|1|0.0%|0.2%|
[ciarmy](#ciarmy)|430|430|1|0.2%|0.2%|

## blocklist_de_imap

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours for attacks on the Service imap, sasl, pop3, etc.

Source is downloaded from [this link](http://lists.blocklist.de/lists/imap.txt).

The last time downloaded was found to be dated: Tue Jun  9 08:28:06 UTC 2015.

The ipset `blocklist_de_imap` has **2596** entries, **2596** unique IPs.

The following table shows the overlaps of `blocklist_de_imap` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_imap`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_imap`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_imap`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|26088|37744|2584|6.8%|99.5%|
[blocklist_de_mail](#blocklist_de_mail)|20039|20039|2584|12.8%|99.5%|
[blocklist_de](#blocklist_de)|31644|31644|2584|8.1%|99.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|280|0.0%|10.7%|
[firehol_level3](#firehol_level3)|108319|9625797|54|0.0%|2.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|53|0.0%|2.0%|
[alienvault_reputation](#alienvault_reputation)|180914|180914|49|0.0%|1.8%|
[openbl_60d](#openbl_60d)|7190|7190|37|0.5%|1.4%|
[openbl_30d](#openbl_30d)|2861|2861|32|1.1%|1.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|25|0.0%|0.9%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|14|0.0%|0.5%|
[nixspam](#nixspam)|17190|17190|14|0.0%|0.5%|
[firehol_level1](#firehol_level1)|5092|688943415|14|0.0%|0.5%|
[et_block](#et_block)|999|18343755|14|0.0%|0.5%|
[snort_ipfilter](#snort_ipfilter)|10116|10116|12|0.1%|0.4%|
[openbl_7d](#openbl_7d)|826|826|9|1.0%|0.3%|
[stopforumspam_30d](#stopforumspam_30d)|92512|92512|7|0.0%|0.2%|
[et_compromised](#et_compromised)|1678|1678|7|0.4%|0.2%|
[bruteforceblocker](#bruteforceblocker)|1725|1725|7|0.4%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|0.1%|
[stopforumspam_7d](#stopforumspam_7d)|29277|29277|2|0.0%|0.0%|
[shunlist](#shunlist)|1264|1264|2|0.1%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2644|2644|2|0.0%|0.0%|
[firehol_proxies](#firehol_proxies)|11673|11900|2|0.0%|0.0%|
[firehol_anonymous](#firehol_anonymous)|18076|82086|2|0.0%|0.0%|
[xroxy](#xroxy)|2138|2138|1|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7467|7467|1|0.0%|0.0%|
[php_harvesters](#php_harvesters)|366|366|1|0.2%|0.0%|
[php_commenters](#php_commenters)|385|385|1|0.2%|0.0%|
[openbl_1d](#openbl_1d)|137|137|1|0.7%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|1|0.0%|0.0%|
[ciarmy](#ciarmy)|430|430|1|0.2%|0.0%|

## blocklist_de_mail

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service Mail, Postfix.

Source is downloaded from [this link](http://lists.blocklist.de/lists/mail.txt).

The last time downloaded was found to be dated: Tue Jun  9 08:14:09 UTC 2015.

The ipset `blocklist_de_mail` has **20039** entries, **20039** unique IPs.

The following table shows the overlaps of `blocklist_de_mail` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_mail`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_mail`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_mail`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|26088|37744|20039|53.0%|100.0%|
[blocklist_de](#blocklist_de)|31644|31644|20039|63.3%|100.0%|
[blocklist_de_apache](#blocklist_de_apache)|16180|16180|11059|68.3%|55.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|2781|0.0%|13.8%|
[blocklist_de_imap](#blocklist_de_imap)|2596|2596|2584|99.5%|12.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|1414|0.0%|7.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|1262|0.0%|6.2%|
[nixspam](#nixspam)|17190|17190|510|2.9%|2.5%|
[firehol_level3](#firehol_level3)|108319|9625797|506|0.0%|2.5%|
[snort_ipfilter](#snort_ipfilter)|10116|10116|270|2.6%|1.3%|
[stopforumspam_30d](#stopforumspam_30d)|92512|92512|234|0.2%|1.1%|
[stopforumspam_7d](#stopforumspam_7d)|29277|29277|129|0.4%|0.6%|
[firehol_proxies](#firehol_proxies)|11673|11900|74|0.6%|0.3%|
[firehol_anonymous](#firehol_anonymous)|18076|82086|74|0.0%|0.3%|
[alienvault_reputation](#alienvault_reputation)|180914|180914|71|0.0%|0.3%|
[php_dictionary](#php_dictionary)|630|630|62|9.8%|0.3%|
[php_spammers](#php_spammers)|622|622|54|8.6%|0.2%|
[stopforumspam_1d](#stopforumspam_1d)|7467|7467|49|0.6%|0.2%|
[openbl_60d](#openbl_60d)|7190|7190|47|0.6%|0.2%|
[ri_web_proxies](#ri_web_proxies)|7263|7263|45|0.6%|0.2%|
[openbl_30d](#openbl_30d)|2861|2861|39|1.3%|0.1%|
[xroxy](#xroxy)|2138|2138|38|1.7%|0.1%|
[php_commenters](#php_commenters)|385|385|24|6.2%|0.1%|
[firehol_level1](#firehol_level1)|5092|688943415|24|0.0%|0.1%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|22|0.0%|0.1%|
[et_block](#et_block)|999|18343755|22|0.0%|0.1%|
[blocklist_de_strongips](#blocklist_de_strongips)|166|166|21|12.6%|0.1%|
[blocklist_de_bots](#blocklist_de_bots)|3492|3492|21|0.6%|0.1%|
[proxz](#proxz)|1108|1108|14|1.2%|0.0%|
[et_compromised](#et_compromised)|1678|1678|11|0.6%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1725|1725|11|0.6%|0.0%|
[openbl_7d](#openbl_7d)|826|826|9|1.0%|0.0%|
[shunlist](#shunlist)|1264|1264|4|0.3%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2644|2644|4|0.1%|0.0%|
[php_harvesters](#php_harvesters)|366|366|4|1.0%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|4|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|4|0.0%|0.0%|
[et_tor](#et_tor)|6400|6400|4|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|2|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|1|0.0%|0.0%|
[proxyrss](#proxyrss)|1495|1495|1|0.0%|0.0%|
[openbl_1d](#openbl_1d)|137|137|1|0.7%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[dshield](#dshield)|20|5120|1|0.0%|0.0%|
[dm_tor](#dm_tor)|6391|6391|1|0.0%|0.0%|
[ciarmy](#ciarmy)|430|430|1|0.2%|0.0%|
[bm_tor](#bm_tor)|6355|6355|1|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2582|2582|1|0.0%|0.0%|

## blocklist_de_sip

[Blocklist.de](https://www.blocklist.de/) All IP addresses that tried to login in a SIP, VOIP or Asterisk Server and are included in the IPs list from [infiltrated.net](www.infiltrated.net)

Source is downloaded from [this link](http://lists.blocklist.de/lists/sip.txt).

The last time downloaded was found to be dated: Tue Jun  9 08:10:09 UTC 2015.

The ipset `blocklist_de_sip` has **89** entries, **89** unique IPs.

The following table shows the overlaps of `blocklist_de_sip` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_sip`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_sip`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_sip`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|26088|37744|70|0.1%|78.6%|
[blocklist_de](#blocklist_de)|31644|31644|70|0.2%|78.6%|
[voipbl](#voipbl)|10507|10919|27|0.2%|30.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|17|0.0%|19.1%|
[alienvault_reputation](#alienvault_reputation)|180914|180914|16|0.0%|17.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|7|0.0%|7.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|6|0.0%|6.7%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|2|0.0%|2.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|2|0.0%|2.2%|
[firehol_level3](#firehol_level3)|108319|9625797|2|0.0%|2.2%|
[firehol_level1](#firehol_level1)|5092|688943415|2|0.0%|2.2%|
[et_block](#et_block)|999|18343755|2|0.0%|2.2%|
[et_botcc](#et_botcc)|509|509|1|0.1%|1.1%|

## blocklist_de_ssh

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service SSH.

Source is downloaded from [this link](http://lists.blocklist.de/lists/ssh.txt).

The last time downloaded was found to be dated: Tue Jun  9 08:28:03 UTC 2015.

The ipset `blocklist_de_ssh` has **2582** entries, **2582** unique IPs.

The following table shows the overlaps of `blocklist_de_ssh` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_ssh`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_ssh`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_ssh`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|26088|37744|2578|6.8%|99.8%|
[blocklist_de](#blocklist_de)|31644|31644|2578|8.1%|99.8%|
[alienvault_reputation](#alienvault_reputation)|180914|180914|1132|0.6%|43.8%|
[firehol_level3](#firehol_level3)|108319|9625797|1060|0.0%|41.0%|
[openbl_60d](#openbl_60d)|7190|7190|967|13.4%|37.4%|
[openbl_30d](#openbl_30d)|2861|2861|800|27.9%|30.9%|
[bruteforceblocker](#bruteforceblocker)|1725|1725|725|42.0%|28.0%|
[et_compromised](#et_compromised)|1678|1678|642|38.2%|24.8%|
[shunlist](#shunlist)|1264|1264|415|32.8%|16.0%|
[openbl_7d](#openbl_7d)|826|826|394|47.6%|15.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|269|0.0%|10.4%|
[firehol_level1](#firehol_level1)|5092|688943415|134|0.0%|5.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|132|0.0%|5.1%|
[et_block](#et_block)|999|18343755|126|0.0%|4.8%|
[dshield](#dshield)|20|5120|121|2.3%|4.6%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|117|0.0%|4.5%|
[openbl_1d](#openbl_1d)|137|137|117|85.4%|4.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|58|0.0%|2.2%|
[blocklist_de_strongips](#blocklist_de_strongips)|166|166|28|16.8%|1.0%|
[stopforumspam_30d](#stopforumspam_30d)|92512|92512|15|0.0%|0.5%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|6|0.0%|0.2%|
[stopforumspam_7d](#stopforumspam_7d)|29277|29277|3|0.0%|0.1%|
[voipbl](#voipbl)|10507|10919|2|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|2|0.0%|0.0%|
[sslbl](#sslbl)|382|382|1|0.2%|0.0%|
[snort_ipfilter](#snort_ipfilter)|10116|10116|1|0.0%|0.0%|
[php_spammers](#php_spammers)|622|622|1|0.1%|0.0%|
[php_commenters](#php_commenters)|385|385|1|0.2%|0.0%|
[nixspam](#nixspam)|17190|17190|1|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|1|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|1|0.0%|0.0%|
[ciarmy](#ciarmy)|430|430|1|0.2%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|20039|20039|1|0.0%|0.0%|

## blocklist_de_strongips

[Blocklist.de](https://www.blocklist.de/) All IPs which are older then 2 month and have more then 5.000 attacks.

Source is downloaded from [this link](http://lists.blocklist.de/lists/strongips.txt).

The last time downloaded was found to be dated: Tue Jun  9 08:28:10 UTC 2015.

The ipset `blocklist_de_strongips` has **166** entries, **166** unique IPs.

The following table shows the overlaps of `blocklist_de_strongips` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_strongips`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_strongips`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_strongips`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|26088|37744|166|0.4%|100.0%|
[blocklist_de](#blocklist_de)|31644|31644|166|0.5%|100.0%|
[firehol_level3](#firehol_level3)|108319|9625797|152|0.0%|91.5%|
[stopforumspam_30d](#stopforumspam_30d)|92512|92512|124|0.1%|74.6%|
[blocklist_de_bots](#blocklist_de_bots)|3492|3492|124|3.5%|74.6%|
[stopforumspam_7d](#stopforumspam_7d)|29277|29277|113|0.3%|68.0%|
[stopforumspam_1d](#stopforumspam_1d)|7467|7467|103|1.3%|62.0%|
[php_commenters](#php_commenters)|385|385|41|10.6%|24.6%|
[alienvault_reputation](#alienvault_reputation)|180914|180914|36|0.0%|21.6%|
[blocklist_de_apache](#blocklist_de_apache)|16180|16180|33|0.2%|19.8%|
[blocklist_de_ssh](#blocklist_de_ssh)|2582|2582|28|1.0%|16.8%|
[openbl_60d](#openbl_60d)|7190|7190|26|0.3%|15.6%|
[openbl_30d](#openbl_30d)|2861|2861|25|0.8%|15.0%|
[openbl_7d](#openbl_7d)|826|826|24|2.9%|14.4%|
[shunlist](#shunlist)|1264|1264|22|1.7%|13.2%|
[blocklist_de_mail](#blocklist_de_mail)|20039|20039|21|0.1%|12.6%|
[openbl_1d](#openbl_1d)|137|137|16|11.6%|9.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|16|0.0%|9.6%|
[firehol_level1](#firehol_level1)|5092|688943415|9|0.0%|5.4%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4860|4860|7|0.1%|4.2%|
[php_spammers](#php_spammers)|622|622|6|0.9%|3.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|6|0.0%|3.6%|
[xroxy](#xroxy)|2138|2138|5|0.2%|3.0%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|5|0.0%|3.0%|
[firehol_proxies](#firehol_proxies)|11673|11900|5|0.0%|3.0%|
[firehol_anonymous](#firehol_anonymous)|18076|82086|5|0.0%|3.0%|
[et_block](#et_block)|999|18343755|5|0.0%|3.0%|
[ri_web_proxies](#ri_web_proxies)|7263|7263|4|0.0%|2.4%|
[proxyrss](#proxyrss)|1495|1495|4|0.2%|2.4%|
[php_dictionary](#php_dictionary)|630|630|4|0.6%|2.4%|
[nixspam](#nixspam)|17190|17190|4|0.0%|2.4%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|3|0.0%|1.8%|
[proxz](#proxz)|1108|1108|3|0.2%|1.8%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|1.8%|
[snort_ipfilter](#snort_ipfilter)|10116|10116|2|0.0%|1.2%|
[php_harvesters](#php_harvesters)|366|366|2|0.5%|1.2%|
[blocklist_de_ftp](#blocklist_de_ftp)|360|360|2|0.5%|1.2%|
[dshield](#dshield)|20|5120|1|0.0%|0.6%|

## bm_tor

[torstatus.blutmagie.de](https://torstatus.blutmagie.de) list of all TOR network servers

Source is downloaded from [this link](https://torstatus.blutmagie.de/ip_list_all.php/Tor_ip_list_ALL.csv).

The last time downloaded was found to be dated: Tue Jun  9 08:27:03 UTC 2015.

The ipset `bm_tor` has **6355** entries, **6355** unique IPs.

The following table shows the overlaps of `bm_tor` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `bm_tor`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `bm_tor`.
- ` this % ` is the percentage **of this ipset (`bm_tor`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_anonymous](#firehol_anonymous)|18076|82086|6355|7.7%|100.0%|
[dm_tor](#dm_tor)|6391|6391|6295|98.4%|99.0%|
[et_tor](#et_tor)|6400|6400|5719|89.3%|89.9%|
[firehol_level3](#firehol_level3)|108319|9625797|1067|0.0%|16.7%|
[snort_ipfilter](#snort_ipfilter)|10116|10116|1029|10.1%|16.1%|
[stopforumspam_30d](#stopforumspam_30d)|92512|92512|628|0.6%|9.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|612|0.0%|9.6%|
[stopforumspam_7d](#stopforumspam_7d)|29277|29277|515|1.7%|8.1%|
[firehol_level2](#firehol_level2)|26088|37744|353|0.9%|5.5%|
[stopforumspam_1d](#stopforumspam_1d)|7467|7467|351|4.7%|5.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|183|0.0%|2.8%|
[firehol_proxies](#firehol_proxies)|11673|11900|166|1.3%|2.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|165|0.0%|2.5%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|163|43.8%|2.5%|
[php_commenters](#php_commenters)|385|385|43|11.1%|0.6%|
[alienvault_reputation](#alienvault_reputation)|180914|180914|41|0.0%|0.6%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|22|0.0%|0.3%|
[openbl_60d](#openbl_60d)|7190|7190|20|0.2%|0.3%|
[php_harvesters](#php_harvesters)|366|366|7|1.9%|0.1%|
[blocklist_de](#blocklist_de)|31644|31644|6|0.0%|0.0%|
[et_block](#et_block)|999|18343755|5|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|16180|16180|5|0.0%|0.0%|
[php_spammers](#php_spammers)|622|622|4|0.6%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|4|0.0%|0.0%|
[firehol_level1](#firehol_level1)|5092|688943415|4|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4860|4860|4|0.0%|0.0%|
[voipbl](#voipbl)|10507|10919|3|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|3|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7263|7263|3|0.0%|0.0%|
[php_dictionary](#php_dictionary)|630|630|3|0.4%|0.0%|
[nixspam](#nixspam)|17190|17190|3|0.0%|0.0%|
[xroxy](#xroxy)|2138|2138|1|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|1|0.0%|0.0%|
[shunlist](#shunlist)|1264|1264|1|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|20039|20039|1|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3492|3492|1|0.0%|0.0%|

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
[firehol_level1](#firehol_level1)|5092|688943415|592708608|86.0%|100.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|4194304|3.0%|0.7%|
[voipbl](#voipbl)|10507|10919|319|2.9%|0.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|5|0.0%|0.0%|
[firehol_level3](#firehol_level3)|108319|9625797|4|0.0%|0.0%|
[php_harvesters](#php_harvesters)|366|366|1|0.2%|0.0%|
[php_commenters](#php_commenters)|385|385|1|0.2%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.0%|
[ciarmy](#ciarmy)|430|430|1|0.2%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1725|1725|1|0.0%|0.0%|

## bruteforceblocker

[danger.rulez.sk](http://danger.rulez.sk/) IPs detected by [bruteforceblocker](http://danger.rulez.sk/index.php/bruteforceblocker/) (fail2ban alternative for SSH on OpenBSD). This is an automatically generated list from users reporting failed authentication attempts. An IP seems to be included if 3 or more users report it. Its retention pocily seems 30 days.

Source is downloaded from [this link](http://danger.rulez.sk/projects/bruteforceblocker/blist.php).

The last time downloaded was found to be dated: Tue Jun  9 05:45:22 UTC 2015.

The ipset `bruteforceblocker` has **1725** entries, **1725** unique IPs.

The following table shows the overlaps of `bruteforceblocker` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `bruteforceblocker`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `bruteforceblocker`.
- ` this % ` is the percentage **of this ipset (`bruteforceblocker`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level3](#firehol_level3)|108319|9625797|1725|0.0%|100.0%|
[et_compromised](#et_compromised)|1678|1678|1628|97.0%|94.3%|
[alienvault_reputation](#alienvault_reputation)|180914|180914|1101|0.6%|63.8%|
[openbl_60d](#openbl_60d)|7190|7190|1000|13.9%|57.9%|
[openbl_30d](#openbl_30d)|2861|2861|936|32.7%|54.2%|
[firehol_level2](#firehol_level2)|26088|37744|741|1.9%|42.9%|
[blocklist_de](#blocklist_de)|31644|31644|737|2.3%|42.7%|
[blocklist_de_ssh](#blocklist_de_ssh)|2582|2582|725|28.0%|42.0%|
[shunlist](#shunlist)|1264|1264|439|34.7%|25.4%|
[openbl_7d](#openbl_7d)|826|826|324|39.2%|18.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|153|0.0%|8.8%|
[firehol_level1](#firehol_level1)|5092|688943415|108|0.0%|6.2%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|101|0.0%|5.8%|
[et_block](#et_block)|999|18343755|101|0.0%|5.8%|
[dshield](#dshield)|20|5120|101|1.9%|5.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|90|0.0%|5.2%|
[openbl_1d](#openbl_1d)|137|137|70|51.0%|4.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|52|0.0%|3.0%|
[stopforumspam_30d](#stopforumspam_30d)|92512|92512|13|0.0%|0.7%|
[blocklist_de_mail](#blocklist_de_mail)|20039|20039|11|0.0%|0.6%|
[blocklist_de_imap](#blocklist_de_imap)|2596|2596|7|0.2%|0.4%|
[stopforumspam_7d](#stopforumspam_7d)|29277|29277|5|0.0%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|5|0.0%|0.2%|
[firehol_proxies](#firehol_proxies)|11673|11900|3|0.0%|0.1%|
[firehol_anonymous](#firehol_anonymous)|18076|82086|3|0.0%|0.1%|
[voipbl](#voipbl)|10507|10919|2|0.0%|0.1%|
[stopforumspam_1d](#stopforumspam_1d)|7467|7467|2|0.0%|0.1%|
[proxz](#proxz)|1108|1108|2|0.1%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|2|0.0%|0.1%|
[blocklist_de_ftp](#blocklist_de_ftp)|360|360|2|0.5%|0.1%|
[xroxy](#xroxy)|2138|2138|1|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|10116|10116|1|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7263|7263|1|0.0%|0.0%|
[proxyrss](#proxyrss)|1495|1495|1|0.0%|0.0%|
[php_spammers](#php_spammers)|622|622|1|0.1%|0.0%|
[php_commenters](#php_commenters)|385|385|1|0.2%|0.0%|
[nixspam](#nixspam)|17190|17190|1|0.0%|0.0%|
[fullbogons](#fullbogons)|3720|670264216|1|0.0%|0.0%|
[ciarmy](#ciarmy)|430|430|1|0.2%|0.0%|
[bogons](#bogons)|13|592708608|1|0.0%|0.0%|

## ciarmy

[CIArmy.com](http://ciarmy.com/) IPs with poor Rogue Packet score that have not yet been identified as malicious by the community

Source is downloaded from [this link](http://cinsscore.com/list/ci-badguys.txt).

The last time downloaded was found to be dated: Tue Jun  9 07:15:16 UTC 2015.

The ipset `ciarmy` has **430** entries, **430** unique IPs.

The following table shows the overlaps of `ciarmy` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ciarmy`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ciarmy`.
- ` this % ` is the percentage **of this ipset (`ciarmy`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level3](#firehol_level3)|108319|9625797|430|0.0%|100.0%|
[alienvault_reputation](#alienvault_reputation)|180914|180914|405|0.2%|94.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|86|0.0%|20.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|46|0.0%|10.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|36|0.0%|8.3%|
[shunlist](#shunlist)|1264|1264|34|2.6%|7.9%|
[firehol_level2](#firehol_level2)|26088|37744|33|0.0%|7.6%|
[blocklist_de](#blocklist_de)|31644|31644|33|0.1%|7.6%|
[blocklist_de_apache](#blocklist_de_apache)|16180|16180|30|0.1%|6.9%|
[et_block](#et_block)|999|18343755|4|0.0%|0.9%|
[voipbl](#voipbl)|10507|10919|2|0.0%|0.4%|
[stopforumspam_30d](#stopforumspam_30d)|92512|92512|2|0.0%|0.4%|
[stopforumspam_7d](#stopforumspam_7d)|29277|29277|1|0.0%|0.2%|
[openbl_7d](#openbl_7d)|826|826|1|0.1%|0.2%|
[openbl_60d](#openbl_60d)|7190|7190|1|0.0%|0.2%|
[openbl_30d](#openbl_30d)|2861|2861|1|0.0%|0.2%|
[openbl_1d](#openbl_1d)|137|137|1|0.7%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.2%|
[fullbogons](#fullbogons)|3720|670264216|1|0.0%|0.2%|
[firehol_level1](#firehol_level1)|5092|688943415|1|0.0%|0.2%|
[et_compromised](#et_compromised)|1678|1678|1|0.0%|0.2%|
[bruteforceblocker](#bruteforceblocker)|1725|1725|1|0.0%|0.2%|
[bogons](#bogons)|13|592708608|1|0.0%|0.2%|
[blocklist_de_ssh](#blocklist_de_ssh)|2582|2582|1|0.0%|0.2%|
[blocklist_de_mail](#blocklist_de_mail)|20039|20039|1|0.0%|0.2%|
[blocklist_de_imap](#blocklist_de_imap)|2596|2596|1|0.0%|0.2%|
[blocklist_de_ftp](#blocklist_de_ftp)|360|360|1|0.2%|0.2%|

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
[firehol_level3](#firehol_level3)|108319|9625797|6|0.0%|100.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|1|0.0%|16.6%|
[malc0de](#malc0de)|342|342|1|0.2%|16.6%|
[alienvault_reputation](#alienvault_reputation)|180914|180914|1|0.0%|16.6%|

## dm_tor

[dan.me.uk](https://www.dan.me.uk) dynamic list of TOR exit points

Source is downloaded from [this link](https://www.dan.me.uk/torlist/).

The last time downloaded was found to be dated: Tue Jun  9 08:09:10 UTC 2015.

The ipset `dm_tor` has **6391** entries, **6391** unique IPs.

The following table shows the overlaps of `dm_tor` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `dm_tor`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `dm_tor`.
- ` this % ` is the percentage **of this ipset (`dm_tor`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_anonymous](#firehol_anonymous)|18076|82086|6391|7.7%|100.0%|
[bm_tor](#bm_tor)|6355|6355|6295|99.0%|98.4%|
[et_tor](#et_tor)|6400|6400|5729|89.5%|89.6%|
[firehol_level3](#firehol_level3)|108319|9625797|1079|0.0%|16.8%|
[snort_ipfilter](#snort_ipfilter)|10116|10116|1041|10.2%|16.2%|
[stopforumspam_30d](#stopforumspam_30d)|92512|92512|638|0.6%|9.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|614|0.0%|9.6%|
[stopforumspam_7d](#stopforumspam_7d)|29277|29277|523|1.7%|8.1%|
[firehol_level2](#firehol_level2)|26088|37744|357|0.9%|5.5%|
[stopforumspam_1d](#stopforumspam_1d)|7467|7467|355|4.7%|5.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|182|0.0%|2.8%|
[firehol_proxies](#firehol_proxies)|11673|11900|166|1.3%|2.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|165|0.0%|2.5%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|163|43.8%|2.5%|
[php_commenters](#php_commenters)|385|385|43|11.1%|0.6%|
[alienvault_reputation](#alienvault_reputation)|180914|180914|41|0.0%|0.6%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|22|0.0%|0.3%|
[openbl_60d](#openbl_60d)|7190|7190|20|0.2%|0.3%|
[php_harvesters](#php_harvesters)|366|366|7|1.9%|0.1%|
[blocklist_de](#blocklist_de)|31644|31644|6|0.0%|0.0%|
[et_block](#et_block)|999|18343755|5|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|16180|16180|5|0.0%|0.0%|
[php_spammers](#php_spammers)|622|622|4|0.6%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|4|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4860|4860|4|0.0%|0.0%|
[voipbl](#voipbl)|10507|10919|3|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|3|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7263|7263|3|0.0%|0.0%|
[php_dictionary](#php_dictionary)|630|630|3|0.4%|0.0%|
[nixspam](#nixspam)|17190|17190|3|0.0%|0.0%|
[firehol_level1](#firehol_level1)|5092|688943415|3|0.0%|0.0%|
[xroxy](#xroxy)|2138|2138|1|0.0%|0.0%|
[shunlist](#shunlist)|1264|1264|1|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|20039|20039|1|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3492|3492|1|0.0%|0.0%|

## dshield

[DShield.org](https://dshield.org/) top 20 attacking class C (/24) subnets over the last three days - **excellent list**

Source is downloaded from [this link](http://feeds.dshield.org/block.txt).

The last time downloaded was found to be dated: Tue Jun  9 07:53:45 UTC 2015.

The ipset `dshield` has **20** entries, **5120** unique IPs.

The following table shows the overlaps of `dshield` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `dshield`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `dshield`.
- ` this % ` is the percentage **of this ipset (`dshield`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level1](#firehol_level1)|5092|688943415|5120|0.0%|100.0%|
[alienvault_reputation](#alienvault_reputation)|180914|180914|4099|2.2%|80.0%|
[et_block](#et_block)|999|18343755|2048|0.0%|40.0%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|512|0.0%|10.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|512|0.0%|10.0%|
[openbl_60d](#openbl_60d)|7190|7190|168|2.3%|3.2%|
[firehol_level3](#firehol_level3)|108319|9625797|162|0.0%|3.1%|
[openbl_30d](#openbl_30d)|2861|2861|146|5.1%|2.8%|
[firehol_level2](#firehol_level2)|26088|37744|130|0.3%|2.5%|
[blocklist_de](#blocklist_de)|31644|31644|129|0.4%|2.5%|
[shunlist](#shunlist)|1264|1264|121|9.5%|2.3%|
[blocklist_de_ssh](#blocklist_de_ssh)|2582|2582|121|4.6%|2.3%|
[et_compromised](#et_compromised)|1678|1678|102|6.0%|1.9%|
[bruteforceblocker](#bruteforceblocker)|1725|1725|101|5.8%|1.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|92|0.0%|1.7%|
[openbl_7d](#openbl_7d)|826|826|49|5.9%|0.9%|
[openbl_1d](#openbl_1d)|137|137|25|18.2%|0.4%|
[blocklist_de_apache](#blocklist_de_apache)|16180|16180|6|0.0%|0.1%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|4|0.0%|0.0%|
[malc0de](#malc0de)|342|342|2|0.5%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29277|29277|1|0.0%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92512|92512|1|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|166|166|1|0.6%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|20039|20039|1|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|360|360|1|0.2%|0.0%|

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
[firehol_level1](#firehol_level1)|5092|688943415|18340420|2.6%|99.9%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|18338560|100.0%|99.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|8533288|2.4%|46.5%|
[firehol_level3](#firehol_level3)|108319|9625797|6933332|72.0%|37.7%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|6932480|75.5%|37.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|2272541|0.2%|12.3%|
[fullbogons](#fullbogons)|3720|670264216|151552|0.0%|0.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|130394|0.0%|0.7%|
[alienvault_reputation](#alienvault_reputation)|180914|180914|5280|2.9%|0.0%|
[dshield](#dshield)|20|5120|2048|40.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1041|0.3%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92512|92512|1011|1.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|517|0.1%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29277|29277|308|1.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|10116|10116|300|2.9%|0.0%|
[firehol_level2](#firehol_level2)|26088|37744|271|0.7%|0.0%|
[openbl_60d](#openbl_60d)|7190|7190|251|3.4%|0.0%|
[zeus](#zeus)|232|232|229|98.7%|0.0%|
[blocklist_de](#blocklist_de)|31644|31644|210|0.6%|0.0%|
[zeus_badips](#zeus_badips)|203|203|203|100.0%|0.0%|
[nixspam](#nixspam)|17190|17190|155|0.9%|0.0%|
[openbl_30d](#openbl_30d)|2861|2861|128|4.4%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2582|2582|126|4.8%|0.0%|
[shunlist](#shunlist)|1264|1264|104|8.2%|0.0%|
[et_compromised](#et_compromised)|1678|1678|101|6.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1725|1725|101|5.8%|0.0%|
[feodo](#feodo)|103|103|99|96.1%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7467|7467|78|1.0%|0.0%|
[openbl_7d](#openbl_7d)|826|826|53|6.4%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3492|3492|52|1.4%|0.0%|
[sslbl](#sslbl)|382|382|37|9.6%|0.0%|
[php_commenters](#php_commenters)|385|385|30|7.7%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|29|2.2%|0.0%|
[openbl_1d](#openbl_1d)|137|137|26|18.9%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|20039|20039|22|0.1%|0.0%|
[voipbl](#voipbl)|10507|10919|14|0.1%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2596|2596|14|0.5%|0.0%|
[palevo](#palevo)|13|13|12|92.3%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|9|0.0%|0.0%|
[firehol_anonymous](#firehol_anonymous)|18076|82086|8|0.0%|0.0%|
[php_dictionary](#php_dictionary)|630|630|6|0.9%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|6|0.4%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|16180|16180|6|0.0%|0.0%|
[malc0de](#malc0de)|342|342|5|1.4%|0.0%|
[et_tor](#et_tor)|6400|6400|5|0.0%|0.0%|
[dm_tor](#dm_tor)|6391|6391|5|0.0%|0.0%|
[bm_tor](#bm_tor)|6355|6355|5|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|166|166|5|3.0%|0.0%|
[php_spammers](#php_spammers)|622|622|4|0.6%|0.0%|
[ciarmy](#ciarmy)|430|430|4|0.9%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4860|4860|4|0.0%|0.0%|
[firehol_proxies](#firehol_proxies)|11673|11900|3|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|2|0.3%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|89|89|2|2.2%|0.0%|
[php_harvesters](#php_harvesters)|366|366|1|0.2%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[et_botcc](#et_botcc)|509|509|1|0.1%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|360|360|1|0.2%|0.0%|

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
[alienvault_reputation](#alienvault_reputation)|180914|180914|5|0.0%|0.9%|
[firehol_level3](#firehol_level3)|108319|9625797|3|0.0%|0.5%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|1|0.0%|0.1%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|1|0.0%|0.1%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|1|0.0%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.1%|
[firehol_level1](#firehol_level1)|5092|688943415|1|0.0%|0.1%|
[et_block](#et_block)|999|18343755|1|0.0%|0.1%|
[blocklist_de_sip](#blocklist_de_sip)|89|89|1|1.1%|0.1%|

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
[firehol_level3](#firehol_level3)|108319|9625797|1646|0.0%|98.0%|
[bruteforceblocker](#bruteforceblocker)|1725|1725|1628|94.3%|97.0%|
[alienvault_reputation](#alienvault_reputation)|180914|180914|1077|0.5%|64.1%|
[openbl_60d](#openbl_60d)|7190|7190|982|13.6%|58.5%|
[openbl_30d](#openbl_30d)|2861|2861|917|32.0%|54.6%|
[firehol_level2](#firehol_level2)|26088|37744|658|1.7%|39.2%|
[blocklist_de](#blocklist_de)|31644|31644|654|2.0%|38.9%|
[blocklist_de_ssh](#blocklist_de_ssh)|2582|2582|642|24.8%|38.2%|
[shunlist](#shunlist)|1264|1264|416|32.9%|24.7%|
[openbl_7d](#openbl_7d)|826|826|311|37.6%|18.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|151|0.0%|8.9%|
[firehol_level1](#firehol_level1)|5092|688943415|108|0.0%|6.4%|
[dshield](#dshield)|20|5120|102|1.9%|6.0%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|101|0.0%|6.0%|
[et_block](#et_block)|999|18343755|101|0.0%|6.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|86|0.0%|5.1%|
[openbl_1d](#openbl_1d)|137|137|58|42.3%|3.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|46|0.0%|2.7%|
[stopforumspam_30d](#stopforumspam_30d)|92512|92512|13|0.0%|0.7%|
[blocklist_de_mail](#blocklist_de_mail)|20039|20039|11|0.0%|0.6%|
[blocklist_de_imap](#blocklist_de_imap)|2596|2596|7|0.2%|0.4%|
[stopforumspam_7d](#stopforumspam_7d)|29277|29277|5|0.0%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|5|0.0%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|3|0.0%|0.1%|
[firehol_proxies](#firehol_proxies)|11673|11900|3|0.0%|0.1%|
[firehol_anonymous](#firehol_anonymous)|18076|82086|3|0.0%|0.1%|
[voipbl](#voipbl)|10507|10919|2|0.0%|0.1%|
[stopforumspam_1d](#stopforumspam_1d)|7467|7467|2|0.0%|0.1%|
[proxz](#proxz)|1108|1108|2|0.1%|0.1%|
[blocklist_de_ftp](#blocklist_de_ftp)|360|360|2|0.5%|0.1%|
[xroxy](#xroxy)|2138|2138|1|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|10116|10116|1|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7263|7263|1|0.0%|0.0%|
[proxyrss](#proxyrss)|1495|1495|1|0.0%|0.0%|
[php_spammers](#php_spammers)|622|622|1|0.1%|0.0%|
[php_commenters](#php_commenters)|385|385|1|0.2%|0.0%|
[nixspam](#nixspam)|17190|17190|1|0.0%|0.0%|
[ciarmy](#ciarmy)|430|430|1|0.2%|0.0%|

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
[firehol_anonymous](#firehol_anonymous)|18076|82086|5754|7.0%|89.9%|
[dm_tor](#dm_tor)|6391|6391|5729|89.6%|89.5%|
[bm_tor](#bm_tor)|6355|6355|5719|89.9%|89.3%|
[firehol_level3](#firehol_level3)|108319|9625797|1121|0.0%|17.5%|
[snort_ipfilter](#snort_ipfilter)|10116|10116|1082|10.6%|16.9%|
[stopforumspam_30d](#stopforumspam_30d)|92512|92512|659|0.7%|10.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|623|0.0%|9.7%|
[stopforumspam_7d](#stopforumspam_7d)|29277|29277|544|1.8%|8.5%|
[firehol_level2](#firehol_level2)|26088|37744|363|0.9%|5.6%|
[stopforumspam_1d](#stopforumspam_1d)|7467|7467|357|4.7%|5.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|186|0.0%|2.9%|
[firehol_proxies](#firehol_proxies)|11673|11900|168|1.4%|2.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|166|0.0%|2.5%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|165|44.3%|2.5%|
[php_commenters](#php_commenters)|385|385|43|11.1%|0.6%|
[alienvault_reputation](#alienvault_reputation)|180914|180914|41|0.0%|0.6%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|22|0.0%|0.3%|
[openbl_60d](#openbl_60d)|7190|7190|20|0.2%|0.3%|
[blocklist_de](#blocklist_de)|31644|31644|9|0.0%|0.1%|
[blocklist_de_apache](#blocklist_de_apache)|16180|16180|8|0.0%|0.1%|
[php_harvesters](#php_harvesters)|366|366|7|1.9%|0.1%|
[et_block](#et_block)|999|18343755|5|0.0%|0.0%|
[php_spammers](#php_spammers)|622|622|4|0.6%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|4|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|20039|20039|4|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4860|4860|4|0.0%|0.0%|
[voipbl](#voipbl)|10507|10919|3|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|3|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7263|7263|3|0.0%|0.0%|
[php_dictionary](#php_dictionary)|630|630|3|0.4%|0.0%|
[firehol_level1](#firehol_level1)|5092|688943415|3|0.0%|0.0%|
[nixspam](#nixspam)|17190|17190|2|0.0%|0.0%|
[xroxy](#xroxy)|2138|2138|1|0.0%|0.0%|
[shunlist](#shunlist)|1264|1264|1|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3492|3492|1|0.0%|0.0%|

## feodo

[Abuse.ch Feodo tracker](https://feodotracker.abuse.ch) trojan includes IPs which are being used by Feodo (also known as Cridex or Bugat) which commits ebanking fraud - **excellent list**

Source is downloaded from [this link](https://feodotracker.abuse.ch/blocklist/?download=ipblocklist).

The last time downloaded was found to be dated: Tue Jun  9 08:27:08 UTC 2015.

The ipset `feodo` has **103** entries, **103** unique IPs.

The following table shows the overlaps of `feodo` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `feodo`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `feodo`.
- ` this % ` is the percentage **of this ipset (`feodo`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level1](#firehol_level1)|5092|688943415|103|0.0%|100.0%|
[et_block](#et_block)|999|18343755|99|0.0%|96.1%|
[snort_ipfilter](#snort_ipfilter)|10116|10116|81|0.8%|78.6%|
[firehol_level3](#firehol_level3)|108319|9625797|81|0.0%|78.6%|
[sslbl](#sslbl)|382|382|37|9.6%|35.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|11|0.0%|10.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|3|0.0%|2.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|3|0.0%|2.9%|
[alienvault_reputation](#alienvault_reputation)|180914|180914|2|0.0%|1.9%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.9%|

## firehol_anonymous

**FireHOL Anonymous** - Known anonymizing IPs. (includes: firehol_proxies anonymous bm_tor dm_tor)

Source is downloaded from [this link]().

The last time downloaded was found to be dated: Sun Jun  7 22:20:34 UTC 2015.

The ipset `firehol_anonymous` has **18076** entries, **82086** unique IPs.

The following table shows the overlaps of `firehol_anonymous` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `firehol_anonymous`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `firehol_anonymous`.
- ` this % ` is the percentage **of this ipset (`firehol_anonymous`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_proxies](#firehol_proxies)|11673|11900|11900|100.0%|14.4%|
[ri_web_proxies](#ri_web_proxies)|7263|7263|7263|100.0%|8.8%|
[firehol_level3](#firehol_level3)|108319|9625797|6411|0.0%|7.8%|
[dm_tor](#dm_tor)|6391|6391|6391|100.0%|7.7%|
[bm_tor](#bm_tor)|6355|6355|6355|100.0%|7.7%|
[stopforumspam_30d](#stopforumspam_30d)|92512|92512|5901|6.3%|7.1%|
[et_tor](#et_tor)|6400|6400|5754|89.9%|7.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|3418|0.0%|4.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|2878|0.0%|3.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|2830|0.0%|3.4%|
[stopforumspam_7d](#stopforumspam_7d)|29277|29277|2826|9.6%|3.4%|
[ri_connect_proxies](#ri_connect_proxies)|2644|2644|2644|100.0%|3.2%|
[xroxy](#xroxy)|2138|2138|2138|100.0%|2.6%|
[proxyrss](#proxyrss)|1495|1495|1495|100.0%|1.8%|
[firehol_level2](#firehol_level2)|26088|37744|1372|3.6%|1.6%|
[snort_ipfilter](#snort_ipfilter)|10116|10116|1139|11.2%|1.3%|
[proxz](#proxz)|1108|1108|1108|100.0%|1.3%|
[stopforumspam_1d](#stopforumspam_1d)|7467|7467|1052|14.0%|1.2%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|663|100.0%|0.8%|
[blocklist_de](#blocklist_de)|31644|31644|617|1.9%|0.7%|
[blocklist_de_bots](#blocklist_de_bots)|3492|3492|531|15.2%|0.6%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|372|100.0%|0.4%|
[nixspam](#nixspam)|17190|17190|121|0.7%|0.1%|
[php_dictionary](#php_dictionary)|630|630|83|13.1%|0.1%|
[voipbl](#voipbl)|10507|10919|78|0.7%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|20039|20039|74|0.3%|0.0%|
[php_commenters](#php_commenters)|385|385|71|18.4%|0.0%|
[php_spammers](#php_spammers)|622|622|70|11.2%|0.0%|
[alienvault_reputation](#alienvault_reputation)|180914|180914|55|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|28|0.0%|0.0%|
[openbl_60d](#openbl_60d)|7190|7190|23|0.3%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|15|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|16180|16180|13|0.0%|0.0%|
[php_harvesters](#php_harvesters)|366|366|11|3.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4860|4860|11|0.2%|0.0%|
[firehol_level1](#firehol_level1)|5092|688943415|8|0.0%|0.0%|
[et_block](#et_block)|999|18343755|8|0.0%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|7|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|6|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|166|166|5|3.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|3|0.2%|0.0%|
[et_compromised](#et_compromised)|1678|1678|3|0.1%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1725|1725|3|0.1%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2596|2596|2|0.0%|0.0%|
[sslbl](#sslbl)|382|382|1|0.2%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|1|0.0%|0.0%|
[shunlist](#shunlist)|1264|1264|1|0.0%|0.0%|
[openbl_30d](#openbl_30d)|2861|2861|1|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|360|360|1|0.2%|0.0%|

## firehol_level1

**FireHOL Level 1** - Maximum protection without false positives. (includes: fullbogons dshield feodo palevo sslbl zeus spamhaus_drop spamhaus_edrop)

Source is downloaded from [this link]().

The last time downloaded was found to be dated: Sun Jun  7 22:15:43 UTC 2015.

The ipset `firehol_level1` has **5092** entries, **688943415** unique IPs.

The following table shows the overlaps of `firehol_level1` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `firehol_level1`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `firehol_level1`.
- ` this % ` is the percentage **of this ipset (`firehol_level1`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[fullbogons](#fullbogons)|3720|670264216|670264216|100.0%|97.2%|
[bogons](#bogons)|13|592708608|592708608|100.0%|86.0%|
[et_block](#et_block)|999|18343755|18340420|99.9%|2.6%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|18338560|100.0%|2.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|8864643|2.5%|1.2%|
[firehol_level3](#firehol_level3)|108319|9625797|7499690|77.9%|1.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|7497728|81.6%|1.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|4637028|3.3%|0.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|2545517|0.3%|0.3%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|487424|100.0%|0.0%|
[dshield](#dshield)|20|5120|5120|100.0%|0.0%|
[alienvault_reputation](#alienvault_reputation)|180914|180914|5105|2.8%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1932|0.5%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92512|92512|1088|1.1%|0.0%|
[sslbl](#sslbl)|382|382|382|100.0%|0.0%|
[voipbl](#voipbl)|10507|10919|333|3.0%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29277|29277|317|1.0%|0.0%|
[openbl_60d](#openbl_60d)|7190|7190|306|4.2%|0.0%|
[snort_ipfilter](#snort_ipfilter)|10116|10116|299|2.9%|0.0%|
[firehol_level2](#firehol_level2)|26088|37744|290|0.7%|0.0%|
[zeus](#zeus)|232|232|232|100.0%|0.0%|
[blocklist_de](#blocklist_de)|31644|31644|228|0.7%|0.0%|
[zeus_badips](#zeus_badips)|203|203|203|100.0%|0.0%|
[shunlist](#shunlist)|1264|1264|187|14.7%|0.0%|
[openbl_30d](#openbl_30d)|2861|2861|164|5.7%|0.0%|
[nixspam](#nixspam)|17190|17190|155|0.9%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2582|2582|134|5.1%|0.0%|
[et_compromised](#et_compromised)|1678|1678|108|6.4%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1725|1725|108|6.2%|0.0%|
[feodo](#feodo)|103|103|103|100.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7467|7467|79|1.0%|0.0%|
[openbl_7d](#openbl_7d)|826|826|55|6.6%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3492|3492|55|1.5%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|39|2.6%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|38|2.9%|0.0%|
[php_commenters](#php_commenters)|385|385|37|9.6%|0.0%|
[openbl_1d](#openbl_1d)|137|137|26|18.9%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|20039|20039|24|0.1%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|22|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2596|2596|14|0.5%|0.0%|
[palevo](#palevo)|13|13|13|100.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|16180|16180|11|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|166|166|9|5.4%|0.0%|
[firehol_anonymous](#firehol_anonymous)|18076|82086|8|0.0%|0.0%|
[malc0de](#malc0de)|342|342|7|2.0%|0.0%|
[php_dictionary](#php_dictionary)|630|630|6|0.9%|0.0%|
[php_spammers](#php_spammers)|622|622|4|0.6%|0.0%|
[bm_tor](#bm_tor)|6355|6355|4|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4860|4860|4|0.0%|0.0%|
[php_harvesters](#php_harvesters)|366|366|3|0.8%|0.0%|
[firehol_proxies](#firehol_proxies)|11673|11900|3|0.0%|0.0%|
[et_tor](#et_tor)|6400|6400|3|0.0%|0.0%|
[dm_tor](#dm_tor)|6391|6391|3|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|2|0.3%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|89|89|2|2.2%|0.0%|
[virbl](#virbl)|14|14|1|7.1%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7263|7263|1|0.0%|0.0%|
[et_botcc](#et_botcc)|509|509|1|0.1%|0.0%|
[ciarmy](#ciarmy)|430|430|1|0.2%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|360|360|1|0.2%|0.0%|

## firehol_level2

**FireHOL Level 2** - Maximum protection from attacks took place in the last 48 hours. (includes: openbl_1d blocklist_de stopforumspam_1d)

Source is downloaded from [this link]().

The last time downloaded was found to be dated: Sun Jun  7 22:20:34 UTC 2015.

The ipset `firehol_level2` has **26088** entries, **37744** unique IPs.

The following table shows the overlaps of `firehol_level2` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `firehol_level2`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `firehol_level2`.
- ` this % ` is the percentage **of this ipset (`firehol_level2`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|31644|31644|31644|100.0%|83.8%|
[blocklist_de_mail](#blocklist_de_mail)|20039|20039|20039|100.0%|53.0%|
[blocklist_de_apache](#blocklist_de_apache)|16180|16180|16180|100.0%|42.8%|
[firehol_level3](#firehol_level3)|108319|9625797|9394|0.0%|24.8%|
[stopforumspam_30d](#stopforumspam_30d)|92512|92512|7937|8.5%|21.0%|
[stopforumspam_7d](#stopforumspam_7d)|29277|29277|7483|25.5%|19.8%|
[stopforumspam_1d](#stopforumspam_1d)|7467|7467|7467|100.0%|19.7%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4860|4860|4860|100.0%|12.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|4166|0.0%|11.0%|
[blocklist_de_bots](#blocklist_de_bots)|3492|3492|3492|100.0%|9.2%|
[blocklist_de_imap](#blocklist_de_imap)|2596|2596|2584|99.5%|6.8%|
[blocklist_de_ssh](#blocklist_de_ssh)|2582|2582|2578|99.8%|6.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|1774|0.0%|4.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|1680|0.0%|4.4%|
[alienvault_reputation](#alienvault_reputation)|180914|180914|1422|0.7%|3.7%|
[firehol_anonymous](#firehol_anonymous)|18076|82086|1372|1.6%|3.6%|
[firehol_proxies](#firehol_proxies)|11673|11900|1152|9.6%|3.0%|
[openbl_60d](#openbl_60d)|7190|7190|1076|14.9%|2.8%|
[openbl_30d](#openbl_30d)|2861|2861|863|30.1%|2.2%|
[bruteforceblocker](#bruteforceblocker)|1725|1725|741|42.9%|1.9%|
[snort_ipfilter](#snort_ipfilter)|10116|10116|679|6.7%|1.7%|
[ri_web_proxies](#ri_web_proxies)|7263|7263|674|9.2%|1.7%|
[et_compromised](#et_compromised)|1678|1678|658|39.2%|1.7%|
[nixspam](#nixspam)|17190|17190|612|3.5%|1.6%|
[shunlist](#shunlist)|1264|1264|456|36.0%|1.2%|
[openbl_7d](#openbl_7d)|826|826|423|51.2%|1.1%|
[proxyrss](#proxyrss)|1495|1495|405|27.0%|1.0%|
[et_tor](#et_tor)|6400|6400|363|5.6%|0.9%|
[dm_tor](#dm_tor)|6391|6391|357|5.5%|0.9%|
[bm_tor](#bm_tor)|6355|6355|353|5.5%|0.9%|
[blocklist_de_ftp](#blocklist_de_ftp)|360|360|347|96.3%|0.9%|
[xroxy](#xroxy)|2138|2138|346|16.1%|0.9%|
[firehol_level1](#firehol_level1)|5092|688943415|290|0.0%|0.7%|
[et_block](#et_block)|999|18343755|271|0.0%|0.7%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|259|0.0%|0.6%|
[proxz](#proxz)|1108|1108|249|22.4%|0.6%|
[ri_connect_proxies](#ri_connect_proxies)|2644|2644|181|6.8%|0.4%|
[php_commenters](#php_commenters)|385|385|177|45.9%|0.4%|
[blocklist_de_strongips](#blocklist_de_strongips)|166|166|166|100.0%|0.4%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|156|41.9%|0.4%|
[openbl_1d](#openbl_1d)|137|137|137|100.0%|0.3%|
[dshield](#dshield)|20|5120|130|2.5%|0.3%|
[php_dictionary](#php_dictionary)|630|630|97|15.3%|0.2%|
[php_spammers](#php_spammers)|622|622|96|15.4%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|79|0.0%|0.2%|
[blocklist_de_sip](#blocklist_de_sip)|89|89|70|78.6%|0.1%|
[php_harvesters](#php_harvesters)|366|366|55|15.0%|0.1%|
[voipbl](#voipbl)|10507|10919|38|0.3%|0.1%|
[ciarmy](#ciarmy)|430|430|33|7.6%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|15|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|11|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|8|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|4|0.6%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|2|0.1%|0.0%|
[zeus_badips](#zeus_badips)|203|203|1|0.4%|0.0%|
[zeus](#zeus)|232|232|1|0.4%|0.0%|
[sslbl](#sslbl)|382|382|1|0.2%|0.0%|

## firehol_level3

**FireHOL Level 3** - All the bad IPs in last 30 days. (includes: openbl_30d stopforumspam_30d virbl malc0de shunlist malwaredomainlist bruteforceblocker ciarmy cleanmx_viruses snort_ipfilter ib_bluetack_spyware ib_bluetack_hijacked ib_bluetack_webexploit php_commenters php_dictionary php_harvesters php_spammers)

Source is downloaded from [this link]().

The last time downloaded was found to be dated: Sun Jun  7 22:20:34 UTC 2015.

The ipset `firehol_level3` has **108319** entries, **9625797** unique IPs.

The following table shows the overlaps of `firehol_level3` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `firehol_level3`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `firehol_level3`.
- ` this % ` is the percentage **of this ipset (`firehol_level3`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|9177856|100.0%|95.3%|
[firehol_level1](#firehol_level1)|5092|688943415|7499690|1.0%|77.9%|
[et_block](#et_block)|999|18343755|6933332|37.7%|72.0%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|6933031|37.8%|72.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|2537305|0.7%|26.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|919949|0.1%|9.5%|
[fullbogons](#fullbogons)|3720|670264216|566181|0.0%|5.8%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|339173|100.0%|3.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|161476|0.1%|1.6%|
[stopforumspam_30d](#stopforumspam_30d)|92512|92512|92512|100.0%|0.9%|
[stopforumspam_7d](#stopforumspam_7d)|29277|29277|29168|99.6%|0.3%|
[snort_ipfilter](#snort_ipfilter)|10116|10116|10116|100.0%|0.1%|
[firehol_level2](#firehol_level2)|26088|37744|9394|24.8%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7467|7467|6561|87.8%|0.0%|
[firehol_anonymous](#firehol_anonymous)|18076|82086|6411|7.8%|0.0%|
[firehol_proxies](#firehol_proxies)|11673|11900|5320|44.7%|0.0%|
[alienvault_reputation](#alienvault_reputation)|180914|180914|5146|2.8%|0.0%|
[blocklist_de](#blocklist_de)|31644|31644|4120|13.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7263|7263|3514|48.3%|0.0%|
[openbl_60d](#openbl_60d)|7190|7190|2997|41.6%|0.0%|
[openbl_30d](#openbl_30d)|2861|2861|2861|100.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3492|3492|2407|68.9%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1725|1725|1725|100.0%|0.0%|
[et_compromised](#et_compromised)|1678|1678|1646|98.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2644|2644|1502|56.8%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|1450|100.0%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|1288|100.0%|0.0%|
[xroxy](#xroxy)|2138|2138|1279|59.8%|0.0%|
[shunlist](#shunlist)|1264|1264|1264|100.0%|0.0%|
[et_tor](#et_tor)|6400|6400|1121|17.5%|0.0%|
[dm_tor](#dm_tor)|6391|6391|1079|16.8%|0.0%|
[bm_tor](#bm_tor)|6355|6355|1067|16.7%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2582|2582|1060|41.0%|0.0%|
[openbl_7d](#openbl_7d)|826|826|826|100.0%|0.0%|
[proxyrss](#proxyrss)|1495|1495|741|49.5%|0.0%|
[proxz](#proxz)|1108|1108|669|60.3%|0.0%|
[php_dictionary](#php_dictionary)|630|630|630|100.0%|0.0%|
[php_spammers](#php_spammers)|622|622|622|100.0%|0.0%|
[nixspam](#nixspam)|17190|17190|507|2.9%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|20039|20039|506|2.5%|0.0%|
[ciarmy](#ciarmy)|430|430|430|100.0%|0.0%|
[php_commenters](#php_commenters)|385|385|385|100.0%|0.0%|
[php_harvesters](#php_harvesters)|366|366|366|100.0%|0.0%|
[malc0de](#malc0de)|342|342|342|100.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|16180|16180|283|1.7%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|234|62.9%|0.0%|
[zeus](#zeus)|232|232|203|87.5%|0.0%|
[zeus_badips](#zeus_badips)|203|203|181|89.1%|0.0%|
[dshield](#dshield)|20|5120|162|3.1%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|166|166|152|91.5%|0.0%|
[openbl_1d](#openbl_1d)|137|137|137|100.0%|0.0%|
[sslbl](#sslbl)|382|382|96|25.1%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|89|0.0%|0.0%|
[feodo](#feodo)|103|103|81|78.6%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4860|4860|79|1.6%|0.0%|
[voipbl](#voipbl)|10507|10919|56|0.5%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2596|2596|54|2.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|23|3.4%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|23|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|360|360|15|4.1%|0.0%|
[virbl](#virbl)|14|14|14|100.0%|0.0%|
[palevo](#palevo)|13|13|11|84.6%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|6|6|6|100.0%|0.0%|
[bogons](#bogons)|13|592708608|4|0.0%|0.0%|
[et_botcc](#et_botcc)|509|509|3|0.5%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|89|89|2|2.2%|0.0%|

## firehol_proxies

**FireHOL Proxies** - Known open proxies in the last 30 days. (includes: ib_bluetack_proxies maxmind_proxy_fraud proxyrss proxz ri_connect_proxies ri_web_proxies xroxy)

Source is downloaded from [this link]().

The last time downloaded was found to be dated: Sun Jun  7 22:20:34 UTC 2015.

The ipset `firehol_proxies` has **11673** entries, **11900** unique IPs.

The following table shows the overlaps of `firehol_proxies` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `firehol_proxies`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `firehol_proxies`.
- ` this % ` is the percentage **of this ipset (`firehol_proxies`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_anonymous](#firehol_anonymous)|18076|82086|11900|14.4%|100.0%|
[ri_web_proxies](#ri_web_proxies)|7263|7263|7263|100.0%|61.0%|
[firehol_level3](#firehol_level3)|108319|9625797|5320|0.0%|44.7%|
[stopforumspam_30d](#stopforumspam_30d)|92512|92512|5257|5.6%|44.1%|
[ri_connect_proxies](#ri_connect_proxies)|2644|2644|2644|100.0%|22.2%|
[stopforumspam_7d](#stopforumspam_7d)|29277|29277|2420|8.2%|20.3%|
[xroxy](#xroxy)|2138|2138|2138|100.0%|17.9%|
[proxyrss](#proxyrss)|1495|1495|1495|100.0%|12.5%|
[firehol_level2](#firehol_level2)|26088|37744|1152|3.0%|9.6%|
[proxz](#proxz)|1108|1108|1108|100.0%|9.3%|
[stopforumspam_1d](#stopforumspam_1d)|7467|7467|836|11.1%|7.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|663|100.0%|5.5%|
[blocklist_de](#blocklist_de)|31644|31644|609|1.9%|5.1%|
[blocklist_de_bots](#blocklist_de_bots)|3492|3492|528|15.1%|4.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|490|0.0%|4.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|374|0.0%|3.1%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|372|100.0%|3.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|272|0.0%|2.2%|
[snort_ipfilter](#snort_ipfilter)|10116|10116|253|2.5%|2.1%|
[et_tor](#et_tor)|6400|6400|168|2.6%|1.4%|
[dm_tor](#dm_tor)|6391|6391|166|2.5%|1.3%|
[bm_tor](#bm_tor)|6355|6355|166|2.6%|1.3%|
[nixspam](#nixspam)|17190|17190|118|0.6%|0.9%|
[php_dictionary](#php_dictionary)|630|630|82|13.0%|0.6%|
[blocklist_de_mail](#blocklist_de_mail)|20039|20039|74|0.3%|0.6%|
[php_spammers](#php_spammers)|622|622|68|10.9%|0.5%|
[php_commenters](#php_commenters)|385|385|65|16.8%|0.5%|
[alienvault_reputation](#alienvault_reputation)|180914|180914|33|0.0%|0.2%|
[openbl_60d](#openbl_60d)|7190|7190|18|0.2%|0.1%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|15|0.0%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|11|0.0%|0.0%|
[php_harvesters](#php_harvesters)|366|366|10|2.7%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|16180|16180|9|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4860|4860|7|0.1%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|166|166|5|3.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|3|0.2%|0.0%|
[firehol_level1](#firehol_level1)|5092|688943415|3|0.0%|0.0%|
[et_compromised](#et_compromised)|1678|1678|3|0.1%|0.0%|
[et_block](#et_block)|999|18343755|3|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1725|1725|3|0.1%|0.0%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|2|0.0%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2596|2596|2|0.0%|0.0%|
[voipbl](#voipbl)|10507|10919|1|0.0%|0.0%|
[sslbl](#sslbl)|382|382|1|0.2%|0.0%|
[shunlist](#shunlist)|1264|1264|1|0.0%|0.0%|

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
[firehol_level1](#firehol_level1)|5092|688943415|670264216|97.2%|100.0%|
[bogons](#bogons)|13|592708608|592708608|100.0%|88.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|4235823|3.0%|0.6%|
[firehol_level3](#firehol_level3)|108319|9625797|566181|5.8%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|565248|6.1%|0.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|249087|0.0%|0.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|239993|0.0%|0.0%|
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
[ciarmy](#ciarmy)|430|430|1|0.2%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1725|1725|1|0.0%|0.0%|

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
[firehol_level3](#firehol_level3)|108319|9625797|23|0.0%|0.0%|
[firehol_level1](#firehol_level1)|5092|688943415|22|0.0%|0.0%|
[firehol_proxies](#firehol_proxies)|11673|11900|15|0.1%|0.0%|
[firehol_anonymous](#firehol_anonymous)|18076|82086|15|0.0%|0.0%|
[alienvault_reputation](#alienvault_reputation)|180914|180914|14|0.0%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92512|92512|13|0.0%|0.0%|
[fullbogons](#fullbogons)|3720|670264216|13|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|11|1.6%|0.0%|
[firehol_level2](#firehol_level2)|26088|37744|11|0.0%|0.0%|
[blocklist_de](#blocklist_de)|31644|31644|11|0.0%|0.0%|
[et_block](#et_block)|999|18343755|9|0.0%|0.0%|
[nixspam](#nixspam)|17190|17190|6|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|5|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4860|4860|5|0.1%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|16180|16180|5|0.0%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29277|29277|4|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|10116|10116|4|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7263|7263|4|0.0%|0.0%|
[dshield](#dshield)|20|5120|4|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|20039|20039|4|0.0%|0.0%|
[xroxy](#xroxy)|2138|2138|3|0.1%|0.0%|
[php_dictionary](#php_dictionary)|630|630|3|0.4%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|3|0.0%|0.0%|
[voipbl](#voipbl)|10507|10919|2|0.0%|0.0%|
[php_harvesters](#php_harvesters)|366|366|2|0.5%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7467|7467|1|0.0%|0.0%|
[proxz](#proxz)|1108|1108|1|0.0%|0.0%|
[php_spammers](#php_spammers)|622|622|1|0.1%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|1|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2582|2582|1|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2596|2596|1|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3492|3492|1|0.0%|0.0%|

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
[firehol_level3](#firehol_level3)|108319|9625797|9177856|95.3%|100.0%|
[firehol_level1](#firehol_level1)|5092|688943415|7497728|1.0%|81.6%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|6932480|37.8%|75.5%|
[et_block](#et_block)|999|18343755|6932480|37.7%|75.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|2526625|0.7%|27.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|904796|0.1%|9.8%|
[fullbogons](#fullbogons)|3720|670264216|565248|0.0%|6.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|145472|0.1%|1.5%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1036|0.3%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92512|92512|719|0.7%|0.0%|
[alienvault_reputation](#alienvault_reputation)|180914|180914|518|0.2%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29277|29277|157|0.5%|0.0%|
[nixspam](#nixspam)|17190|17190|152|0.8%|0.0%|
[firehol_level2](#firehol_level2)|26088|37744|79|0.2%|0.0%|
[blocklist_de](#blocklist_de)|31644|31644|55|0.1%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3492|3492|44|1.2%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7467|7467|30|0.4%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|27|2.0%|0.0%|
[openbl_60d](#openbl_60d)|7190|7190|17|0.2%|0.0%|
[openbl_30d](#openbl_30d)|2861|2861|12|0.4%|0.0%|
[snort_ipfilter](#snort_ipfilter)|10116|10116|11|0.1%|0.0%|
[zeus_badips](#zeus_badips)|203|203|10|4.9%|0.0%|
[zeus](#zeus)|232|232|10|4.3%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|7|0.4%|0.0%|
[firehol_anonymous](#firehol_anonymous)|18076|82086|7|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2582|2582|6|0.2%|0.0%|
[openbl_7d](#openbl_7d)|826|826|5|0.6%|0.0%|
[et_compromised](#et_compromised)|1678|1678|5|0.2%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1725|1725|5|0.2%|0.0%|
[php_dictionary](#php_dictionary)|630|630|4|0.6%|0.0%|
[et_tor](#et_tor)|6400|6400|4|0.0%|0.0%|
[dm_tor](#dm_tor)|6391|6391|4|0.0%|0.0%|
[bm_tor](#bm_tor)|6355|6355|4|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|20039|20039|4|0.0%|0.0%|
[shunlist](#shunlist)|1264|1264|3|0.2%|0.0%|
[php_spammers](#php_spammers)|622|622|3|0.4%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|166|166|3|1.8%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2596|2596|3|0.1%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|2|0.3%|0.0%|
[firehol_proxies](#firehol_proxies)|11673|11900|2|0.0%|0.0%|
[voipbl](#voipbl)|10507|10919|1|0.0%|0.0%|
[php_harvesters](#php_harvesters)|366|366|1|0.2%|0.0%|
[php_commenters](#php_commenters)|385|385|1|0.2%|0.0%|
[openbl_1d](#openbl_1d)|137|137|1|0.7%|0.0%|
[et_botcc](#et_botcc)|509|509|1|0.1%|0.0%|

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
[firehol_level1](#firehol_level1)|5092|688943415|2545517|0.3%|0.3%|
[et_block](#et_block)|999|18343755|2272541|12.3%|0.2%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|2272265|12.3%|0.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|1354507|0.9%|0.1%|
[firehol_level3](#firehol_level3)|108319|9625797|919949|9.5%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|904796|9.8%|0.1%|
[fullbogons](#fullbogons)|3720|670264216|239993|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|33155|6.8%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|13247|3.9%|0.0%|
[alienvault_reputation](#alienvault_reputation)|180914|180914|4214|2.3%|0.0%|
[firehol_anonymous](#firehol_anonymous)|18076|82086|3418|4.1%|0.0%|
[firehol_level2](#firehol_level2)|26088|37744|1680|4.4%|0.0%|
[blocklist_de](#blocklist_de)|31644|31644|1565|4.9%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92512|92512|1506|1.6%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|20039|20039|1414|7.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|16180|16180|1333|8.2%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29277|29277|549|1.8%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|394|0.8%|0.0%|
[nixspam](#nixspam)|17190|17190|350|2.0%|0.0%|
[voipbl](#voipbl)|10507|10919|299|2.7%|0.0%|
[firehol_proxies](#firehol_proxies)|11673|11900|272|2.2%|0.0%|
[openbl_60d](#openbl_60d)|7190|7190|167|2.3%|0.0%|
[et_tor](#et_tor)|6400|6400|166|2.5%|0.0%|
[dm_tor](#dm_tor)|6391|6391|165|2.5%|0.0%|
[bm_tor](#bm_tor)|6355|6355|165|2.5%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7263|7263|144|1.9%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7467|7467|127|1.7%|0.0%|
[snort_ipfilter](#snort_ipfilter)|10116|10116|117|1.1%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|97|6.6%|0.0%|
[dshield](#dshield)|20|5120|92|1.7%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2644|2644|80|3.0%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|66|5.1%|0.0%|
[openbl_30d](#openbl_30d)|2861|2861|64|2.2%|0.0%|
[xroxy](#xroxy)|2138|2138|58|2.7%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2582|2582|58|2.2%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|56|8.4%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1725|1725|52|3.0%|0.0%|
[et_compromised](#et_compromised)|1678|1678|46|2.7%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4860|4860|42|0.8%|0.0%|
[et_botcc](#et_botcc)|509|509|40|7.8%|0.0%|
[proxz](#proxz)|1108|1108|39|3.5%|0.0%|
[ciarmy](#ciarmy)|430|430|36|8.3%|0.0%|
[proxyrss](#proxyrss)|1495|1495|33|2.2%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3492|3492|33|0.9%|0.0%|
[shunlist](#shunlist)|1264|1264|26|2.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2596|2596|25|0.9%|0.0%|
[openbl_7d](#openbl_7d)|826|826|18|2.1%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|17|4.5%|0.0%|
[php_harvesters](#php_harvesters)|366|366|11|3.0%|0.0%|
[php_dictionary](#php_dictionary)|630|630|11|1.7%|0.0%|
[malc0de](#malc0de)|342|342|11|3.2%|0.0%|
[php_commenters](#php_commenters)|385|385|10|2.5%|0.0%|
[php_spammers](#php_spammers)|622|622|9|1.4%|0.0%|
[zeus](#zeus)|232|232|6|2.5%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|89|89|6|6.7%|0.0%|
[bogons](#bogons)|13|592708608|5|0.0%|0.0%|
[zeus_badips](#zeus_badips)|203|203|4|1.9%|0.0%|
[openbl_1d](#openbl_1d)|137|137|4|2.9%|0.0%|
[sslbl](#sslbl)|382|382|3|0.7%|0.0%|
[feodo](#feodo)|103|103|3|2.9%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|360|360|3|0.8%|0.0%|

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
[firehol_level1](#firehol_level1)|5092|688943415|8864643|1.2%|2.5%|
[et_block](#et_block)|999|18343755|8533288|46.5%|2.4%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|8532506|46.5%|2.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|2830203|2.0%|0.8%|
[firehol_level3](#firehol_level3)|108319|9625797|2537305|26.3%|0.7%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2526625|27.5%|0.7%|
[fullbogons](#fullbogons)|3720|670264216|249087|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|98904|20.2%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|7728|2.2%|0.0%|
[alienvault_reputation](#alienvault_reputation)|180914|180914|6256|3.4%|0.0%|
[firehol_anonymous](#firehol_anonymous)|18076|82086|2878|3.5%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92512|92512|2475|2.6%|0.0%|
[firehol_level2](#firehol_level2)|26088|37744|1774|4.7%|0.0%|
[blocklist_de](#blocklist_de)|31644|31644|1602|5.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|20039|20039|1262|6.2%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|16180|16180|1099|6.7%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29277|29277|825|2.8%|0.0%|
[dshield](#dshield)|20|5120|512|10.0%|0.0%|
[voipbl](#voipbl)|10507|10919|434|3.9%|0.0%|
[nixspam](#nixspam)|17190|17190|427|2.4%|0.0%|
[firehol_proxies](#firehol_proxies)|11673|11900|374|3.1%|0.0%|
[openbl_60d](#openbl_60d)|7190|7190|327|4.5%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|226|0.4%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7467|7467|217|2.9%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7263|7263|211|2.9%|0.0%|
[et_tor](#et_tor)|6400|6400|186|2.9%|0.0%|
[bm_tor](#bm_tor)|6355|6355|183|2.8%|0.0%|
[dm_tor](#dm_tor)|6391|6391|182|2.8%|0.0%|
[snort_ipfilter](#snort_ipfilter)|10116|10116|175|1.7%|0.0%|
[openbl_30d](#openbl_30d)|2861|2861|149|5.2%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2582|2582|132|5.1%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3492|3492|117|3.3%|0.0%|
[xroxy](#xroxy)|2138|2138|104|4.8%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2644|2644|102|3.8%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1725|1725|90|5.2%|0.0%|
[et_compromised](#et_compromised)|1678|1678|86|5.1%|0.0%|
[shunlist](#shunlist)|1264|1264|71|5.6%|0.0%|
[proxyrss](#proxyrss)|1495|1495|69|4.6%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4860|4860|66|1.3%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2596|2596|53|2.0%|0.0%|
[php_spammers](#php_spammers)|622|622|51|8.1%|0.0%|
[openbl_7d](#openbl_7d)|826|826|47|5.6%|0.0%|
[ciarmy](#ciarmy)|430|430|46|10.6%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|45|3.1%|0.0%|
[proxz](#proxz)|1108|1108|43|3.8%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|26|2.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|26|3.9%|0.0%|
[php_dictionary](#php_dictionary)|630|630|22|3.4%|0.0%|
[et_botcc](#et_botcc)|509|509|22|4.3%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|21|5.6%|0.0%|
[malc0de](#malc0de)|342|342|20|5.8%|0.0%|
[php_commenters](#php_commenters)|385|385|15|3.8%|0.0%|
[openbl_1d](#openbl_1d)|137|137|11|8.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|360|360|11|3.0%|0.0%|
[zeus](#zeus)|232|232|9|3.8%|0.0%|
[php_harvesters](#php_harvesters)|366|366|9|2.4%|0.0%|
[zeus_badips](#zeus_badips)|203|203|8|3.9%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|89|89|7|7.8%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|166|166|6|3.6%|0.0%|
[sslbl](#sslbl)|382|382|5|1.3%|0.0%|
[feodo](#feodo)|103|103|3|2.9%|0.0%|
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
[firehol_level1](#firehol_level1)|5092|688943415|4637028|0.6%|3.3%|
[fullbogons](#fullbogons)|3720|670264216|4235823|0.6%|3.0%|
[bogons](#bogons)|13|592708608|4194304|0.7%|3.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|2830203|0.8%|2.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|1354507|0.1%|0.9%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|270785|55.5%|0.1%|
[firehol_level3](#firehol_level3)|108319|9625797|161476|1.6%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|145472|1.5%|0.1%|
[et_block](#et_block)|999|18343755|130394|0.7%|0.0%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|130368|0.7%|0.0%|
[alienvault_reputation](#alienvault_reputation)|180914|180914|14114|7.8%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|9226|2.7%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92512|92512|5744|6.2%|0.0%|
[firehol_level2](#firehol_level2)|26088|37744|4166|11.0%|0.0%|
[blocklist_de](#blocklist_de)|31644|31644|3696|11.6%|0.0%|
[firehol_anonymous](#firehol_anonymous)|18076|82086|2830|3.4%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|20039|20039|2781|13.8%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|16180|16180|2434|15.0%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29277|29277|1893|6.4%|0.0%|
[voipbl](#voipbl)|10507|10919|1600|14.6%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|1172|2.4%|0.0%|
[nixspam](#nixspam)|17190|17190|1081|6.2%|0.0%|
[openbl_60d](#openbl_60d)|7190|7190|741|10.3%|0.0%|
[et_tor](#et_tor)|6400|6400|623|9.7%|0.0%|
[dm_tor](#dm_tor)|6391|6391|614|9.6%|0.0%|
[bm_tor](#bm_tor)|6355|6355|612|9.6%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7467|7467|539|7.2%|0.0%|
[firehol_proxies](#firehol_proxies)|11673|11900|490|4.1%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4860|4860|340|6.9%|0.0%|
[openbl_30d](#openbl_30d)|2861|2861|293|10.2%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2596|2596|280|10.7%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2582|2582|269|10.4%|0.0%|
[snort_ipfilter](#snort_ipfilter)|10116|10116|263|2.5%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3492|3492|217|6.2%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7263|7263|204|2.8%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1725|1725|153|8.8%|0.0%|
[et_compromised](#et_compromised)|1678|1678|151|8.9%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|147|11.4%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|125|33.6%|0.0%|
[shunlist](#shunlist)|1264|1264|114|9.0%|0.0%|
[openbl_7d](#openbl_7d)|826|826|110|13.3%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|108|7.4%|0.0%|
[xroxy](#xroxy)|2138|2138|105|4.9%|0.0%|
[proxz](#proxz)|1108|1108|96|8.6%|0.0%|
[ciarmy](#ciarmy)|430|430|86|20.0%|0.0%|
[et_botcc](#et_botcc)|509|509|80|15.7%|0.0%|
[proxyrss](#proxyrss)|1495|1495|61|4.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2644|2644|55|2.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|51|7.6%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|360|360|50|13.8%|0.0%|
[malc0de](#malc0de)|342|342|48|14.0%|0.0%|
[php_spammers](#php_spammers)|622|622|37|5.9%|0.0%|
[php_dictionary](#php_dictionary)|630|630|33|5.2%|0.0%|
[sslbl](#sslbl)|382|382|30|7.8%|0.0%|
[php_commenters](#php_commenters)|385|385|24|6.2%|0.0%|
[php_harvesters](#php_harvesters)|366|366|19|5.1%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|89|89|17|19.1%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|166|166|16|9.6%|0.0%|
[zeus](#zeus)|232|232|14|6.0%|0.0%|
[feodo](#feodo)|103|103|11|10.6%|0.0%|
[zeus_badips](#zeus_badips)|203|203|10|4.9%|0.0%|
[openbl_1d](#openbl_1d)|137|137|9|6.5%|0.0%|
[virbl](#virbl)|14|14|1|7.1%|0.0%|
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
[firehol_proxies](#firehol_proxies)|11673|11900|663|5.5%|100.0%|
[firehol_anonymous](#firehol_anonymous)|18076|82086|663|0.8%|100.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|56|0.0%|8.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|51|0.0%|7.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|26|0.0%|3.9%|
[firehol_level3](#firehol_level3)|108319|9625797|23|0.0%|3.4%|
[stopforumspam_30d](#stopforumspam_30d)|92512|92512|18|0.0%|2.7%|
[ri_web_proxies](#ri_web_proxies)|7263|7263|14|0.1%|2.1%|
[xroxy](#xroxy)|2138|2138|13|0.6%|1.9%|
[stopforumspam_7d](#stopforumspam_7d)|29277|29277|13|0.0%|1.9%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|11|0.0%|1.6%|
[proxyrss](#proxyrss)|1495|1495|8|0.5%|1.2%|
[ri_connect_proxies](#ri_connect_proxies)|2644|2644|7|0.2%|1.0%|
[proxz](#proxz)|1108|1108|6|0.5%|0.9%|
[firehol_level2](#firehol_level2)|26088|37744|4|0.0%|0.6%|
[stopforumspam_1d](#stopforumspam_1d)|7467|7467|3|0.0%|0.4%|
[blocklist_de_bots](#blocklist_de_bots)|3492|3492|3|0.0%|0.4%|
[blocklist_de](#blocklist_de)|31644|31644|3|0.0%|0.4%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|2|0.0%|0.3%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|2|0.1%|0.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2|0.0%|0.3%|
[firehol_level1](#firehol_level1)|5092|688943415|2|0.0%|0.3%|
[et_block](#et_block)|999|18343755|2|0.0%|0.3%|
[snort_ipfilter](#snort_ipfilter)|10116|10116|1|0.0%|0.1%|
[php_dictionary](#php_dictionary)|630|630|1|0.1%|0.1%|
[nixspam](#nixspam)|17190|17190|1|0.0%|0.1%|
[alienvault_reputation](#alienvault_reputation)|180914|180914|1|0.0%|0.1%|

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
[firehol_level3](#firehol_level3)|108319|9625797|339173|3.5%|100.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|13247|0.0%|3.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|9226|0.0%|2.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|7728|0.0%|2.2%|
[firehol_level1](#firehol_level1)|5092|688943415|1932|0.0%|0.5%|
[et_block](#et_block)|999|18343755|1041|0.0%|0.3%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|1037|0.0%|0.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1036|0.0%|0.3%|
[fullbogons](#fullbogons)|3720|670264216|890|0.0%|0.2%|
[alienvault_reputation](#alienvault_reputation)|180914|180914|288|0.1%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92512|92512|48|0.0%|0.0%|
[firehol_anonymous](#firehol_anonymous)|18076|82086|28|0.0%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|27|2.0%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29277|29277|22|0.0%|0.0%|
[et_tor](#et_tor)|6400|6400|22|0.3%|0.0%|
[dm_tor](#dm_tor)|6391|6391|22|0.3%|0.0%|
[bm_tor](#bm_tor)|6355|6355|22|0.3%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|19|1.3%|0.0%|
[snort_ipfilter](#snort_ipfilter)|10116|10116|15|0.1%|0.0%|
[firehol_level2](#firehol_level2)|26088|37744|15|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7467|7467|11|0.1%|0.0%|
[firehol_proxies](#firehol_proxies)|11673|11900|11|0.0%|0.0%|
[nixspam](#nixspam)|17190|17190|10|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7263|7263|6|0.0%|0.0%|
[openbl_60d](#openbl_60d)|7190|7190|5|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|5|1.3%|0.0%|
[voipbl](#voipbl)|10507|10919|4|0.0%|0.0%|
[blocklist_de](#blocklist_de)|31644|31644|4|0.0%|0.0%|
[openbl_30d](#openbl_30d)|2861|2861|3|0.1%|0.0%|
[malc0de](#malc0de)|342|342|3|0.8%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|3|0.0%|0.0%|
[et_compromised](#et_compromised)|1678|1678|3|0.1%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|16180|16180|3|0.0%|0.0%|
[proxyrss](#proxyrss)|1495|1495|2|0.1%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1725|1725|2|0.1%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|89|89|2|2.2%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|20039|20039|2|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4860|4860|2|0.0%|0.0%|
[zeus_badips](#zeus_badips)|203|203|1|0.4%|0.0%|
[zeus](#zeus)|232|232|1|0.4%|0.0%|
[xroxy](#xroxy)|2138|2138|1|0.0%|0.0%|
[sslbl](#sslbl)|382|382|1|0.2%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|1|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2644|2644|1|0.0%|0.0%|
[proxz](#proxz)|1108|1108|1|0.0%|0.0%|
[php_harvesters](#php_harvesters)|366|366|1|0.2%|0.0%|
[php_dictionary](#php_dictionary)|630|630|1|0.1%|0.0%|
[php_commenters](#php_commenters)|385|385|1|0.2%|0.0%|
[palevo](#palevo)|13|13|1|7.6%|0.0%|
[feodo](#feodo)|103|103|1|0.9%|0.0%|
[dshield](#dshield)|20|5120|1|0.0%|0.0%|
[ciarmy](#ciarmy)|430|430|1|0.2%|0.0%|
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
[firehol_level3](#firehol_level3)|108319|9625797|1450|0.0%|100.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|108|0.0%|7.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|97|0.0%|6.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|45|0.0%|3.1%|
[firehol_level1](#firehol_level1)|5092|688943415|39|0.0%|2.6%|
[fullbogons](#fullbogons)|3720|670264216|33|0.0%|2.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|19|0.0%|1.3%|
[alienvault_reputation](#alienvault_reputation)|180914|180914|10|0.0%|0.6%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|7|0.0%|0.4%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|6|0.0%|0.4%|
[et_block](#et_block)|999|18343755|6|0.0%|0.4%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|3|0.2%|0.2%|
[firehol_proxies](#firehol_proxies)|11673|11900|3|0.0%|0.2%|
[firehol_anonymous](#firehol_anonymous)|18076|82086|3|0.0%|0.2%|
[stopforumspam_7d](#stopforumspam_7d)|29277|29277|2|0.0%|0.1%|
[stopforumspam_30d](#stopforumspam_30d)|92512|92512|2|0.0%|0.1%|
[openbl_60d](#openbl_60d)|7190|7190|2|0.0%|0.1%|
[openbl_30d](#openbl_30d)|2861|2861|2|0.0%|0.1%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|2|0.3%|0.1%|
[firehol_level2](#firehol_level2)|26088|37744|2|0.0%|0.1%|
[stopforumspam_1d](#stopforumspam_1d)|7467|7467|1|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|10116|10116|1|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7263|7263|1|0.0%|0.0%|
[openbl_7d](#openbl_7d)|826|826|1|0.1%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|1|0.0%|0.0%|
[et_botcc](#et_botcc)|509|509|1|0.1%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2582|2582|1|0.0%|0.0%|
[blocklist_de](#blocklist_de)|31644|31644|1|0.0%|0.0%|

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
[firehol_level3](#firehol_level3)|108319|9625797|342|0.0%|100.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|48|0.0%|14.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|20|0.0%|5.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|11|0.0%|3.2%|
[alienvault_reputation](#alienvault_reputation)|180914|180914|10|0.0%|2.9%|
[firehol_level1](#firehol_level1)|5092|688943415|7|0.0%|2.0%|
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
[firehol_level3](#firehol_level3)|108319|9625797|1288|0.0%|100.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|147|0.0%|11.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|66|0.0%|5.1%|
[firehol_level1](#firehol_level1)|5092|688943415|38|0.0%|2.9%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|29|0.0%|2.2%|
[et_block](#et_block)|999|18343755|29|0.0%|2.2%|
[snort_ipfilter](#snort_ipfilter)|10116|10116|28|0.2%|2.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|27|0.0%|2.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|27|0.0%|2.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|26|0.0%|2.0%|
[fullbogons](#fullbogons)|3720|670264216|9|0.0%|0.6%|
[alienvault_reputation](#alienvault_reputation)|180914|180914|7|0.0%|0.5%|
[stopforumspam_30d](#stopforumspam_30d)|92512|92512|4|0.0%|0.3%|
[malc0de](#malc0de)|342|342|4|1.1%|0.3%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|3|0.2%|0.2%|
[stopforumspam_7d](#stopforumspam_7d)|29277|29277|1|0.0%|0.0%|
[nixspam](#nixspam)|17190|17190|1|0.0%|0.0%|
[et_botcc](#et_botcc)|509|509|1|0.1%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|6|6|1|16.6%|0.0%|

## maxmind_proxy_fraud

[MaxMind.com](https://www.maxmind.com/en/anonymous-proxy-fraudulent-ip-address-list) list of anonymous proxy fraudelent IP addresses.

Source is downloaded from [this link](https://www.maxmind.com/en/anonymous-proxy-fraudulent-ip-address-list).

The last time downloaded was found to be dated: Tue Jun  9 05:18:30 UTC 2015.

The ipset `maxmind_proxy_fraud` has **372** entries, **372** unique IPs.

The following table shows the overlaps of `maxmind_proxy_fraud` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `maxmind_proxy_fraud`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `maxmind_proxy_fraud`.
- ` this % ` is the percentage **of this ipset (`maxmind_proxy_fraud`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_proxies](#firehol_proxies)|11673|11900|372|3.1%|100.0%|
[firehol_anonymous](#firehol_anonymous)|18076|82086|372|0.4%|100.0%|
[firehol_level3](#firehol_level3)|108319|9625797|234|0.0%|62.9%|
[stopforumspam_30d](#stopforumspam_30d)|92512|92512|233|0.2%|62.6%|
[stopforumspam_7d](#stopforumspam_7d)|29277|29277|192|0.6%|51.6%|
[snort_ipfilter](#snort_ipfilter)|10116|10116|172|1.7%|46.2%|
[et_tor](#et_tor)|6400|6400|165|2.5%|44.3%|
[dm_tor](#dm_tor)|6391|6391|163|2.5%|43.8%|
[bm_tor](#bm_tor)|6355|6355|163|2.5%|43.8%|
[stopforumspam_1d](#stopforumspam_1d)|7467|7467|156|2.0%|41.9%|
[firehol_level2](#firehol_level2)|26088|37744|156|0.4%|41.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|125|0.0%|33.6%|
[php_commenters](#php_commenters)|385|385|40|10.3%|10.7%|
[alienvault_reputation](#alienvault_reputation)|180914|180914|26|0.0%|6.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|21|0.0%|5.6%|
[openbl_60d](#openbl_60d)|7190|7190|18|0.2%|4.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|17|0.0%|4.5%|
[php_harvesters](#php_harvesters)|366|366|6|1.6%|1.6%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|5|0.0%|1.3%|
[ri_web_proxies](#ri_web_proxies)|7263|7263|4|0.0%|1.0%|
[php_spammers](#php_spammers)|622|622|4|0.6%|1.0%|
[php_dictionary](#php_dictionary)|630|630|4|0.6%|1.0%|
[xroxy](#xroxy)|2138|2138|1|0.0%|0.2%|
[voipbl](#voipbl)|10507|10919|1|0.0%|0.2%|
[shunlist](#shunlist)|1264|1264|1|0.0%|0.2%|
[ri_connect_proxies](#ri_connect_proxies)|2644|2644|1|0.0%|0.2%|
[nixspam](#nixspam)|17190|17190|1|0.0%|0.2%|
[et_block](#et_block)|999|18343755|1|0.0%|0.2%|
[blocklist_de_mail](#blocklist_de_mail)|20039|20039|1|0.0%|0.2%|
[blocklist_de_apache](#blocklist_de_apache)|16180|16180|1|0.0%|0.2%|
[blocklist_de](#blocklist_de)|31644|31644|1|0.0%|0.2%|

## nixspam

[NiX Spam](http://www.heise.de/ix/NiX-Spam-DNSBL-and-blacklist-for-download-499637.html) IP addresses that sent spam in the last hour - automatically generated entries without distinguishing open proxies from relays, dialup gateways, and so on. All IPs are removed after 12 hours if there is no spam from there.

Source is downloaded from [this link](http://www.dnsbl.manitu.net/download/nixspam-ip.dump.gz).

The last time downloaded was found to be dated: Tue Jun  9 08:30:01 UTC 2015.

The ipset `nixspam` has **17190** entries, **17190** unique IPs.

The following table shows the overlaps of `nixspam` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `nixspam`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `nixspam`.
- ` this % ` is the percentage **of this ipset (`nixspam`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|1081|0.0%|6.2%|
[firehol_level2](#firehol_level2)|26088|37744|612|1.6%|3.5%|
[blocklist_de](#blocklist_de)|31644|31644|592|1.8%|3.4%|
[blocklist_de_mail](#blocklist_de_mail)|20039|20039|510|2.5%|2.9%|
[firehol_level3](#firehol_level3)|108319|9625797|507|0.0%|2.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|427|0.0%|2.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|350|0.0%|2.0%|
[stopforumspam_30d](#stopforumspam_30d)|92512|92512|216|0.2%|1.2%|
[snort_ipfilter](#snort_ipfilter)|10116|10116|181|1.7%|1.0%|
[firehol_level1](#firehol_level1)|5092|688943415|155|0.0%|0.9%|
[et_block](#et_block)|999|18343755|155|0.0%|0.9%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|152|0.0%|0.8%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|152|0.0%|0.8%|
[stopforumspam_7d](#stopforumspam_7d)|29277|29277|122|0.4%|0.7%|
[firehol_anonymous](#firehol_anonymous)|18076|82086|121|0.1%|0.7%|
[firehol_proxies](#firehol_proxies)|11673|11900|118|0.9%|0.6%|
[php_dictionary](#php_dictionary)|630|630|98|15.5%|0.5%|
[ri_web_proxies](#ri_web_proxies)|7263|7263|80|1.1%|0.4%|
[php_spammers](#php_spammers)|622|622|80|12.8%|0.4%|
[stopforumspam_1d](#stopforumspam_1d)|7467|7467|76|1.0%|0.4%|
[xroxy](#xroxy)|2138|2138|58|2.7%|0.3%|
[blocklist_de_bots](#blocklist_de_bots)|3492|3492|49|1.4%|0.2%|
[proxz](#proxz)|1108|1108|38|3.4%|0.2%|
[alienvault_reputation](#alienvault_reputation)|180914|180914|34|0.0%|0.1%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4860|4860|29|0.5%|0.1%|
[blocklist_de_apache](#blocklist_de_apache)|16180|16180|29|0.1%|0.1%|
[blocklist_de_imap](#blocklist_de_imap)|2596|2596|14|0.5%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|10|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2644|2644|9|0.3%|0.0%|
[php_harvesters](#php_harvesters)|366|366|8|2.1%|0.0%|
[php_commenters](#php_commenters)|385|385|7|1.8%|0.0%|
[proxyrss](#proxyrss)|1495|1495|6|0.4%|0.0%|
[openbl_60d](#openbl_60d)|7190|7190|6|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|6|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|166|166|4|2.4%|0.0%|
[openbl_30d](#openbl_30d)|2861|2861|3|0.1%|0.0%|
[dm_tor](#dm_tor)|6391|6391|3|0.0%|0.0%|
[bm_tor](#bm_tor)|6355|6355|3|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|360|360|3|0.8%|0.0%|
[voipbl](#voipbl)|10507|10919|2|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|2|0.0%|0.0%|
[openbl_7d](#openbl_7d)|826|826|2|0.2%|0.0%|
[et_tor](#et_tor)|6400|6400|2|0.0%|0.0%|
[zeus_badips](#zeus_badips)|203|203|1|0.4%|0.0%|
[zeus](#zeus)|232|232|1|0.4%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|1|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|1|0.1%|0.0%|
[et_compromised](#et_compromised)|1678|1678|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1725|1725|1|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2582|2582|1|0.0%|0.0%|

## openbl_1d

[OpenBL.org](http://www.openbl.org/) last 24 hours IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.

Source is downloaded from [this link](http://www.openbl.org/lists/base_1days.txt).

The last time downloaded was found to be dated: Tue Jun  9 08:32:00 UTC 2015.

The ipset `openbl_1d` has **137** entries, **137** unique IPs.

The following table shows the overlaps of `openbl_1d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl_1d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl_1d`.
- ` this % ` is the percentage **of this ipset (`openbl_1d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level3](#firehol_level3)|108319|9625797|137|0.0%|100.0%|
[firehol_level2](#firehol_level2)|26088|37744|137|0.3%|100.0%|
[openbl_60d](#openbl_60d)|7190|7190|136|1.8%|99.2%|
[openbl_30d](#openbl_30d)|2861|2861|136|4.7%|99.2%|
[openbl_7d](#openbl_7d)|826|826|135|16.3%|98.5%|
[alienvault_reputation](#alienvault_reputation)|180914|180914|133|0.0%|97.0%|
[blocklist_de](#blocklist_de)|31644|31644|119|0.3%|86.8%|
[blocklist_de_ssh](#blocklist_de_ssh)|2582|2582|117|4.5%|85.4%|
[shunlist](#shunlist)|1264|1264|72|5.6%|52.5%|
[bruteforceblocker](#bruteforceblocker)|1725|1725|70|4.0%|51.0%|
[et_compromised](#et_compromised)|1678|1678|58|3.4%|42.3%|
[firehol_level1](#firehol_level1)|5092|688943415|26|0.0%|18.9%|
[et_block](#et_block)|999|18343755|26|0.0%|18.9%|
[dshield](#dshield)|20|5120|25|0.4%|18.2%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|23|0.0%|16.7%|
[blocklist_de_strongips](#blocklist_de_strongips)|166|166|16|9.6%|11.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|11|0.0%|8.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|9|0.0%|6.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|4|0.0%|2.9%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.7%|
[ciarmy](#ciarmy)|430|430|1|0.2%|0.7%|
[blocklist_de_mail](#blocklist_de_mail)|20039|20039|1|0.0%|0.7%|
[blocklist_de_imap](#blocklist_de_imap)|2596|2596|1|0.0%|0.7%|
[blocklist_de_apache](#blocklist_de_apache)|16180|16180|1|0.0%|0.7%|

## openbl_30d

[OpenBL.org](http://www.openbl.org/) last 30 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.

Source is downloaded from [this link](http://www.openbl.org/lists/base_30days.txt).

The last time downloaded was found to be dated: Tue Jun  9 08:07:00 UTC 2015.

The ipset `openbl_30d` has **2861** entries, **2861** unique IPs.

The following table shows the overlaps of `openbl_30d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl_30d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl_30d`.
- ` this % ` is the percentage **of this ipset (`openbl_30d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[openbl_60d](#openbl_60d)|7190|7190|2861|39.7%|100.0%|
[firehol_level3](#firehol_level3)|108319|9625797|2861|0.0%|100.0%|
[alienvault_reputation](#alienvault_reputation)|180914|180914|2844|1.5%|99.4%|
[bruteforceblocker](#bruteforceblocker)|1725|1725|936|54.2%|32.7%|
[et_compromised](#et_compromised)|1678|1678|917|54.6%|32.0%|
[firehol_level2](#firehol_level2)|26088|37744|863|2.2%|30.1%|
[blocklist_de](#blocklist_de)|31644|31644|845|2.6%|29.5%|
[openbl_7d](#openbl_7d)|826|826|826|100.0%|28.8%|
[blocklist_de_ssh](#blocklist_de_ssh)|2582|2582|800|30.9%|27.9%|
[shunlist](#shunlist)|1264|1264|531|42.0%|18.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|293|0.0%|10.2%|
[firehol_level1](#firehol_level1)|5092|688943415|164|0.0%|5.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|149|0.0%|5.2%|
[dshield](#dshield)|20|5120|146|2.8%|5.1%|
[openbl_1d](#openbl_1d)|137|137|136|99.2%|4.7%|
[et_block](#et_block)|999|18343755|128|0.0%|4.4%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|121|0.0%|4.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|64|0.0%|2.2%|
[blocklist_de_mail](#blocklist_de_mail)|20039|20039|39|0.1%|1.3%|
[blocklist_de_imap](#blocklist_de_imap)|2596|2596|32|1.2%|1.1%|
[blocklist_de_strongips](#blocklist_de_strongips)|166|166|25|15.0%|0.8%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|12|0.0%|0.4%|
[snort_ipfilter](#snort_ipfilter)|10116|10116|6|0.0%|0.2%|
[stopforumspam_30d](#stopforumspam_30d)|92512|92512|4|0.0%|0.1%|
[voipbl](#voipbl)|10507|10919|3|0.0%|0.1%|
[nixspam](#nixspam)|17190|17190|3|0.0%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|3|0.0%|0.1%|
[blocklist_de_ftp](#blocklist_de_ftp)|360|360|3|0.8%|0.1%|
[blocklist_de_apache](#blocklist_de_apache)|16180|16180|3|0.0%|0.1%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|2|0.1%|0.0%|
[zeus](#zeus)|232|232|1|0.4%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29277|29277|1|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7467|7467|1|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|1|0.0%|0.0%|
[php_spammers](#php_spammers)|622|622|1|0.1%|0.0%|
[php_commenters](#php_commenters)|385|385|1|0.2%|0.0%|
[firehol_anonymous](#firehol_anonymous)|18076|82086|1|0.0%|0.0%|
[ciarmy](#ciarmy)|430|430|1|0.2%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3492|3492|1|0.0%|0.0%|

## openbl_60d

[OpenBL.org](http://www.openbl.org/) last 60 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.

Source is downloaded from [this link](http://www.openbl.org/lists/base_60days.txt).

The last time downloaded was found to be dated: Tue Jun  9 08:07:00 UTC 2015.

The ipset `openbl_60d` has **7190** entries, **7190** unique IPs.

The following table shows the overlaps of `openbl_60d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl_60d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl_60d`.
- ` this % ` is the percentage **of this ipset (`openbl_60d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[alienvault_reputation](#alienvault_reputation)|180914|180914|7167|3.9%|99.6%|
[firehol_level3](#firehol_level3)|108319|9625797|2997|0.0%|41.6%|
[openbl_30d](#openbl_30d)|2861|2861|2861|100.0%|39.7%|
[firehol_level2](#firehol_level2)|26088|37744|1076|2.8%|14.9%|
[blocklist_de](#blocklist_de)|31644|31644|1039|3.2%|14.4%|
[bruteforceblocker](#bruteforceblocker)|1725|1725|1000|57.9%|13.9%|
[et_compromised](#et_compromised)|1678|1678|982|58.5%|13.6%|
[blocklist_de_ssh](#blocklist_de_ssh)|2582|2582|967|37.4%|13.4%|
[openbl_7d](#openbl_7d)|826|826|826|100.0%|11.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|741|0.0%|10.3%|
[shunlist](#shunlist)|1264|1264|560|44.3%|7.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|327|0.0%|4.5%|
[firehol_level1](#firehol_level1)|5092|688943415|306|0.0%|4.2%|
[et_block](#et_block)|999|18343755|251|0.0%|3.4%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|240|0.0%|3.3%|
[dshield](#dshield)|20|5120|168|3.2%|2.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|167|0.0%|2.3%|
[openbl_1d](#openbl_1d)|137|137|136|99.2%|1.8%|
[stopforumspam_30d](#stopforumspam_30d)|92512|92512|52|0.0%|0.7%|
[blocklist_de_mail](#blocklist_de_mail)|20039|20039|47|0.2%|0.6%|
[blocklist_de_imap](#blocklist_de_imap)|2596|2596|37|1.4%|0.5%|
[snort_ipfilter](#snort_ipfilter)|10116|10116|28|0.2%|0.3%|
[blocklist_de_strongips](#blocklist_de_strongips)|166|166|26|15.6%|0.3%|
[stopforumspam_7d](#stopforumspam_7d)|29277|29277|25|0.0%|0.3%|
[firehol_anonymous](#firehol_anonymous)|18076|82086|23|0.0%|0.3%|
[stopforumspam_1d](#stopforumspam_1d)|7467|7467|20|0.2%|0.2%|
[et_tor](#et_tor)|6400|6400|20|0.3%|0.2%|
[dm_tor](#dm_tor)|6391|6391|20|0.3%|0.2%|
[bm_tor](#bm_tor)|6355|6355|20|0.3%|0.2%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|18|4.8%|0.2%|
[firehol_proxies](#firehol_proxies)|11673|11900|18|0.1%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|17|0.0%|0.2%|
[blocklist_de_bots](#blocklist_de_bots)|3492|3492|17|0.4%|0.2%|
[php_commenters](#php_commenters)|385|385|10|2.5%|0.1%|
[voipbl](#voipbl)|10507|10919|8|0.0%|0.1%|
[nixspam](#nixspam)|17190|17190|6|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|5|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|360|360|3|0.8%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|16180|16180|3|0.0%|0.0%|
[zeus](#zeus)|232|232|2|0.8%|0.0%|
[php_harvesters](#php_harvesters)|366|366|2|0.5%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|2|0.1%|0.0%|
[zeus_badips](#zeus_badips)|203|203|1|0.4%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|1|0.0%|0.0%|
[php_spammers](#php_spammers)|622|622|1|0.1%|0.0%|
[ciarmy](#ciarmy)|430|430|1|0.2%|0.0%|

## openbl_7d

[OpenBL.org](http://www.openbl.org/) last 7 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.

Source is downloaded from [this link](http://www.openbl.org/lists/base_7days.txt).

The last time downloaded was found to be dated: Tue Jun  9 08:07:00 UTC 2015.

The ipset `openbl_7d` has **826** entries, **826** unique IPs.

The following table shows the overlaps of `openbl_7d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl_7d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl_7d`.
- ` this % ` is the percentage **of this ipset (`openbl_7d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[openbl_60d](#openbl_60d)|7190|7190|826|11.4%|100.0%|
[openbl_30d](#openbl_30d)|2861|2861|826|28.8%|100.0%|
[firehol_level3](#firehol_level3)|108319|9625797|826|0.0%|100.0%|
[alienvault_reputation](#alienvault_reputation)|180914|180914|820|0.4%|99.2%|
[firehol_level2](#firehol_level2)|26088|37744|423|1.1%|51.2%|
[blocklist_de](#blocklist_de)|31644|31644|405|1.2%|49.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2582|2582|394|15.2%|47.6%|
[bruteforceblocker](#bruteforceblocker)|1725|1725|324|18.7%|39.2%|
[et_compromised](#et_compromised)|1678|1678|311|18.5%|37.6%|
[shunlist](#shunlist)|1264|1264|226|17.8%|27.3%|
[openbl_1d](#openbl_1d)|137|137|135|98.5%|16.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|110|0.0%|13.3%|
[firehol_level1](#firehol_level1)|5092|688943415|55|0.0%|6.6%|
[et_block](#et_block)|999|18343755|53|0.0%|6.4%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|49|0.0%|5.9%|
[dshield](#dshield)|20|5120|49|0.9%|5.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|47|0.0%|5.6%|
[blocklist_de_strongips](#blocklist_de_strongips)|166|166|24|14.4%|2.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|18|0.0%|2.1%|
[blocklist_de_mail](#blocklist_de_mail)|20039|20039|9|0.0%|1.0%|
[blocklist_de_imap](#blocklist_de_imap)|2596|2596|9|0.3%|1.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|5|0.0%|0.6%|
[stopforumspam_30d](#stopforumspam_30d)|92512|92512|3|0.0%|0.3%|
[nixspam](#nixspam)|17190|17190|2|0.0%|0.2%|
[snort_ipfilter](#snort_ipfilter)|10116|10116|1|0.0%|0.1%|
[php_spammers](#php_spammers)|622|622|1|0.1%|0.1%|
[php_commenters](#php_commenters)|385|385|1|0.2%|0.1%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|1|0.0%|0.1%|
[ciarmy](#ciarmy)|430|430|1|0.2%|0.1%|
[blocklist_de_ftp](#blocklist_de_ftp)|360|360|1|0.2%|0.1%|
[blocklist_de_apache](#blocklist_de_apache)|16180|16180|1|0.0%|0.1%|

## palevo

[Abuse.ch Palevo tracker](https://palevotracker.abuse.ch) worm includes IPs which are being used as botnet C&C for the Palevo crimeware - **excellent list**

Source is downloaded from [this link](https://palevotracker.abuse.ch/blocklists.php?download=ipblocklist).

The last time downloaded was found to be dated: Tue Jun  9 08:27:06 UTC 2015.

The ipset `palevo` has **13** entries, **13** unique IPs.

The following table shows the overlaps of `palevo` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `palevo`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `palevo`.
- ` this % ` is the percentage **of this ipset (`palevo`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level1](#firehol_level1)|5092|688943415|13|0.0%|100.0%|
[et_block](#et_block)|999|18343755|12|0.0%|92.3%|
[snort_ipfilter](#snort_ipfilter)|10116|10116|11|0.1%|84.6%|
[firehol_level3](#firehol_level3)|108319|9625797|11|0.0%|84.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|2|0.0%|15.3%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|7.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|1|0.0%|7.6%|

## php_commenters

[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) comment spammers (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=c&rss=1).

The last time downloaded was found to be dated: Tue Jun  9 08:00:09 UTC 2015.

The ipset `php_commenters` has **385** entries, **385** unique IPs.

The following table shows the overlaps of `php_commenters` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `php_commenters`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `php_commenters`.
- ` this % ` is the percentage **of this ipset (`php_commenters`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level3](#firehol_level3)|108319|9625797|385|0.0%|100.0%|
[stopforumspam_30d](#stopforumspam_30d)|92512|92512|289|0.3%|75.0%|
[stopforumspam_7d](#stopforumspam_7d)|29277|29277|215|0.7%|55.8%|
[firehol_level2](#firehol_level2)|26088|37744|177|0.4%|45.9%|
[stopforumspam_1d](#stopforumspam_1d)|7467|7467|153|2.0%|39.7%|
[blocklist_de](#blocklist_de)|31644|31644|91|0.2%|23.6%|
[blocklist_de_bots](#blocklist_de_bots)|3492|3492|74|2.1%|19.2%|
[firehol_anonymous](#firehol_anonymous)|18076|82086|71|0.0%|18.4%|
[firehol_proxies](#firehol_proxies)|11673|11900|65|0.5%|16.8%|
[snort_ipfilter](#snort_ipfilter)|10116|10116|54|0.5%|14.0%|
[et_tor](#et_tor)|6400|6400|43|0.6%|11.1%|
[dm_tor](#dm_tor)|6391|6391|43|0.6%|11.1%|
[bm_tor](#bm_tor)|6355|6355|43|0.6%|11.1%|
[php_spammers](#php_spammers)|622|622|42|6.7%|10.9%|
[blocklist_de_strongips](#blocklist_de_strongips)|166|166|41|24.6%|10.6%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|40|10.7%|10.3%|
[firehol_level1](#firehol_level1)|5092|688943415|37|0.0%|9.6%|
[et_block](#et_block)|999|18343755|30|0.0%|7.7%|
[blocklist_de_apache](#blocklist_de_apache)|16180|16180|30|0.1%|7.7%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|29|0.0%|7.5%|
[php_dictionary](#php_dictionary)|630|630|26|4.1%|6.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|24|0.0%|6.2%|
[blocklist_de_mail](#blocklist_de_mail)|20039|20039|24|0.1%|6.2%|
[ri_web_proxies](#ri_web_proxies)|7263|7263|23|0.3%|5.9%|
[alienvault_reputation](#alienvault_reputation)|180914|180914|17|0.0%|4.4%|
[php_harvesters](#php_harvesters)|366|366|15|4.0%|3.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|15|0.0%|3.8%|
[openbl_60d](#openbl_60d)|7190|7190|10|0.1%|2.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|10|0.0%|2.5%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4860|4860|9|0.1%|2.3%|
[xroxy](#xroxy)|2138|2138|8|0.3%|2.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|7|0.0%|1.8%|
[proxz](#proxz)|1108|1108|7|0.6%|1.8%|
[nixspam](#nixspam)|17190|17190|7|0.0%|1.8%|
[ri_connect_proxies](#ri_connect_proxies)|2644|2644|5|0.1%|1.2%|
[proxyrss](#proxyrss)|1495|1495|3|0.2%|0.7%|
[zeus_badips](#zeus_badips)|203|203|1|0.4%|0.2%|
[zeus](#zeus)|232|232|1|0.4%|0.2%|
[openbl_7d](#openbl_7d)|826|826|1|0.1%|0.2%|
[openbl_30d](#openbl_30d)|2861|2861|1|0.0%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.2%|
[fullbogons](#fullbogons)|3720|670264216|1|0.0%|0.2%|
[et_compromised](#et_compromised)|1678|1678|1|0.0%|0.2%|
[bruteforceblocker](#bruteforceblocker)|1725|1725|1|0.0%|0.2%|
[bogons](#bogons)|13|592708608|1|0.0%|0.2%|
[blocklist_de_ssh](#blocklist_de_ssh)|2582|2582|1|0.0%|0.2%|
[blocklist_de_imap](#blocklist_de_imap)|2596|2596|1|0.0%|0.2%|

## php_dictionary

[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) directory attackers (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=d&rss=1).

The last time downloaded was found to be dated: Tue Jun  9 08:00:10 UTC 2015.

The ipset `php_dictionary` has **630** entries, **630** unique IPs.

The following table shows the overlaps of `php_dictionary` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `php_dictionary`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `php_dictionary`.
- ` this % ` is the percentage **of this ipset (`php_dictionary`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level3](#firehol_level3)|108319|9625797|630|0.0%|100.0%|
[php_spammers](#php_spammers)|622|622|243|39.0%|38.5%|
[stopforumspam_30d](#stopforumspam_30d)|92512|92512|119|0.1%|18.8%|
[nixspam](#nixspam)|17190|17190|98|0.5%|15.5%|
[firehol_level2](#firehol_level2)|26088|37744|97|0.2%|15.3%|
[blocklist_de](#blocklist_de)|31644|31644|91|0.2%|14.4%|
[snort_ipfilter](#snort_ipfilter)|10116|10116|85|0.8%|13.4%|
[firehol_anonymous](#firehol_anonymous)|18076|82086|83|0.1%|13.1%|
[firehol_proxies](#firehol_proxies)|11673|11900|82|0.6%|13.0%|
[stopforumspam_7d](#stopforumspam_7d)|29277|29277|77|0.2%|12.2%|
[blocklist_de_mail](#blocklist_de_mail)|20039|20039|62|0.3%|9.8%|
[ri_web_proxies](#ri_web_proxies)|7263|7263|54|0.7%|8.5%|
[xroxy](#xroxy)|2138|2138|38|1.7%|6.0%|
[stopforumspam_1d](#stopforumspam_1d)|7467|7467|36|0.4%|5.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|33|0.0%|5.2%|
[php_commenters](#php_commenters)|385|385|26|6.7%|4.1%|
[blocklist_de_bots](#blocklist_de_bots)|3492|3492|24|0.6%|3.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|22|0.0%|3.4%|
[proxz](#proxz)|1108|1108|21|1.8%|3.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|11|0.0%|1.7%|
[alienvault_reputation](#alienvault_reputation)|180914|180914|8|0.0%|1.2%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|6|0.0%|0.9%|
[firehol_level1](#firehol_level1)|5092|688943415|6|0.0%|0.9%|
[et_block](#et_block)|999|18343755|6|0.0%|0.9%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4860|4860|5|0.1%|0.7%|
[blocklist_de_apache](#blocklist_de_apache)|16180|16180|5|0.0%|0.7%|
[ri_connect_proxies](#ri_connect_proxies)|2644|2644|4|0.1%|0.6%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|4|1.0%|0.6%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|4|0.0%|0.6%|
[blocklist_de_strongips](#blocklist_de_strongips)|166|166|4|2.4%|0.6%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|3|0.0%|0.4%|
[et_tor](#et_tor)|6400|6400|3|0.0%|0.4%|
[dm_tor](#dm_tor)|6391|6391|3|0.0%|0.4%|
[bm_tor](#bm_tor)|6355|6355|3|0.0%|0.4%|
[php_harvesters](#php_harvesters)|366|366|2|0.5%|0.3%|
[proxyrss](#proxyrss)|1495|1495|1|0.0%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.1%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|1|0.1%|0.1%|

## php_harvesters

[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) harvesters (IPs that surf the internet looking for email addresses) (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=h&rss=1).

The last time downloaded was found to be dated: Tue Jun  9 08:00:06 UTC 2015.

The ipset `php_harvesters` has **366** entries, **366** unique IPs.

The following table shows the overlaps of `php_harvesters` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `php_harvesters`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `php_harvesters`.
- ` this % ` is the percentage **of this ipset (`php_harvesters`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level3](#firehol_level3)|108319|9625797|366|0.0%|100.0%|
[stopforumspam_30d](#stopforumspam_30d)|92512|92512|81|0.0%|22.1%|
[stopforumspam_7d](#stopforumspam_7d)|29277|29277|61|0.2%|16.6%|
[firehol_level2](#firehol_level2)|26088|37744|55|0.1%|15.0%|
[stopforumspam_1d](#stopforumspam_1d)|7467|7467|42|0.5%|11.4%|
[blocklist_de](#blocklist_de)|31644|31644|39|0.1%|10.6%|
[blocklist_de_bots](#blocklist_de_bots)|3492|3492|29|0.8%|7.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|19|0.0%|5.1%|
[php_commenters](#php_commenters)|385|385|15|3.8%|4.0%|
[snort_ipfilter](#snort_ipfilter)|10116|10116|14|0.1%|3.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|11|0.0%|3.0%|
[firehol_anonymous](#firehol_anonymous)|18076|82086|11|0.0%|3.0%|
[alienvault_reputation](#alienvault_reputation)|180914|180914|11|0.0%|3.0%|
[firehol_proxies](#firehol_proxies)|11673|11900|10|0.0%|2.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|9|0.0%|2.4%|
[nixspam](#nixspam)|17190|17190|8|0.0%|2.1%|
[et_tor](#et_tor)|6400|6400|7|0.1%|1.9%|
[dm_tor](#dm_tor)|6391|6391|7|0.1%|1.9%|
[bm_tor](#bm_tor)|6355|6355|7|0.1%|1.9%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|6|1.6%|1.6%|
[blocklist_de_ftp](#blocklist_de_ftp)|360|360|5|1.3%|1.3%|
[blocklist_de_mail](#blocklist_de_mail)|20039|20039|4|0.0%|1.0%|
[firehol_level1](#firehol_level1)|5092|688943415|3|0.0%|0.8%|
[xroxy](#xroxy)|2138|2138|2|0.0%|0.5%|
[ri_web_proxies](#ri_web_proxies)|7263|7263|2|0.0%|0.5%|
[php_spammers](#php_spammers)|622|622|2|0.3%|0.5%|
[php_dictionary](#php_dictionary)|630|630|2|0.3%|0.5%|
[openbl_60d](#openbl_60d)|7190|7190|2|0.0%|0.5%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|2|0.0%|0.5%|
[blocklist_de_strongips](#blocklist_de_strongips)|166|166|2|1.2%|0.5%|
[blocklist_de_apache](#blocklist_de_apache)|16180|16180|2|0.0%|0.5%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|1|0.0%|0.2%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|1|0.0%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.2%|
[fullbogons](#fullbogons)|3720|670264216|1|0.0%|0.2%|
[et_block](#et_block)|999|18343755|1|0.0%|0.2%|
[bogons](#bogons)|13|592708608|1|0.0%|0.2%|
[blocklist_de_imap](#blocklist_de_imap)|2596|2596|1|0.0%|0.2%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4860|4860|1|0.0%|0.2%|

## php_spammers

[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) spam servers (IPs used by spammers to send messages) (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=s&rss=1).

The last time downloaded was found to be dated: Tue Jun  9 08:00:08 UTC 2015.

The ipset `php_spammers` has **622** entries, **622** unique IPs.

The following table shows the overlaps of `php_spammers` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `php_spammers`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `php_spammers`.
- ` this % ` is the percentage **of this ipset (`php_spammers`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level3](#firehol_level3)|108319|9625797|622|0.0%|100.0%|
[php_dictionary](#php_dictionary)|630|630|243|38.5%|39.0%|
[stopforumspam_30d](#stopforumspam_30d)|92512|92512|131|0.1%|21.0%|
[firehol_level2](#firehol_level2)|26088|37744|96|0.2%|15.4%|
[blocklist_de](#blocklist_de)|31644|31644|82|0.2%|13.1%|
[snort_ipfilter](#snort_ipfilter)|10116|10116|81|0.8%|13.0%|
[nixspam](#nixspam)|17190|17190|80|0.4%|12.8%|
[stopforumspam_7d](#stopforumspam_7d)|29277|29277|77|0.2%|12.3%|
[firehol_anonymous](#firehol_anonymous)|18076|82086|70|0.0%|11.2%|
[firehol_proxies](#firehol_proxies)|11673|11900|68|0.5%|10.9%|
[blocklist_de_mail](#blocklist_de_mail)|20039|20039|54|0.2%|8.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|51|0.0%|8.1%|
[stopforumspam_1d](#stopforumspam_1d)|7467|7467|46|0.6%|7.3%|
[ri_web_proxies](#ri_web_proxies)|7263|7263|45|0.6%|7.2%|
[php_commenters](#php_commenters)|385|385|42|10.9%|6.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|37|0.0%|5.9%|
[xroxy](#xroxy)|2138|2138|30|1.4%|4.8%|
[proxz](#proxz)|1108|1108|20|1.8%|3.2%|
[blocklist_de_bots](#blocklist_de_bots)|3492|3492|20|0.5%|3.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|9|0.0%|1.4%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4860|4860|7|0.1%|1.1%|
[blocklist_de_apache](#blocklist_de_apache)|16180|16180|7|0.0%|1.1%|
[blocklist_de_strongips](#blocklist_de_strongips)|166|166|6|3.6%|0.9%|
[alienvault_reputation](#alienvault_reputation)|180914|180914|5|0.0%|0.8%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|4|0.0%|0.6%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|4|1.0%|0.6%|
[firehol_level1](#firehol_level1)|5092|688943415|4|0.0%|0.6%|
[et_tor](#et_tor)|6400|6400|4|0.0%|0.6%|
[et_block](#et_block)|999|18343755|4|0.0%|0.6%|
[dm_tor](#dm_tor)|6391|6391|4|0.0%|0.6%|
[bm_tor](#bm_tor)|6355|6355|4|0.0%|0.6%|
[ri_connect_proxies](#ri_connect_proxies)|2644|2644|3|0.1%|0.4%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|0.4%|
[proxyrss](#proxyrss)|1495|1495|2|0.1%|0.3%|
[php_harvesters](#php_harvesters)|366|366|2|0.5%|0.3%|
[openbl_7d](#openbl_7d)|826|826|1|0.1%|0.1%|
[openbl_60d](#openbl_60d)|7190|7190|1|0.0%|0.1%|
[openbl_30d](#openbl_30d)|2861|2861|1|0.0%|0.1%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|1|0.0%|0.1%|
[et_compromised](#et_compromised)|1678|1678|1|0.0%|0.1%|
[bruteforceblocker](#bruteforceblocker)|1725|1725|1|0.0%|0.1%|
[blocklist_de_ssh](#blocklist_de_ssh)|2582|2582|1|0.0%|0.1%|

## proxyrss

[proxyrss.com](http://www.proxyrss.com) open proxies syndicated from multiple sources.

Source is downloaded from [this link](http://www.proxyrss.com/proxylists/all.gz).

The last time downloaded was found to be dated: Tue Jun  9 05:01:26 UTC 2015.

The ipset `proxyrss` has **1495** entries, **1495** unique IPs.

The following table shows the overlaps of `proxyrss` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `proxyrss`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `proxyrss`.
- ` this % ` is the percentage **of this ipset (`proxyrss`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_proxies](#firehol_proxies)|11673|11900|1495|12.5%|100.0%|
[firehol_anonymous](#firehol_anonymous)|18076|82086|1495|1.8%|100.0%|
[firehol_level3](#firehol_level3)|108319|9625797|741|0.0%|49.5%|
[stopforumspam_30d](#stopforumspam_30d)|92512|92512|740|0.7%|49.4%|
[ri_web_proxies](#ri_web_proxies)|7263|7263|609|8.3%|40.7%|
[stopforumspam_7d](#stopforumspam_7d)|29277|29277|573|1.9%|38.3%|
[firehol_level2](#firehol_level2)|26088|37744|405|1.0%|27.0%|
[xroxy](#xroxy)|2138|2138|354|16.5%|23.6%|
[stopforumspam_1d](#stopforumspam_1d)|7467|7467|336|4.4%|22.4%|
[ri_connect_proxies](#ri_connect_proxies)|2644|2644|243|9.1%|16.2%|
[proxz](#proxz)|1108|1108|238|21.4%|15.9%|
[blocklist_de](#blocklist_de)|31644|31644|212|0.6%|14.1%|
[blocklist_de_bots](#blocklist_de_bots)|3492|3492|211|6.0%|14.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|69|0.0%|4.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|61|0.0%|4.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|33|0.0%|2.2%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|8|1.2%|0.5%|
[nixspam](#nixspam)|17190|17190|6|0.0%|0.4%|
[snort_ipfilter](#snort_ipfilter)|10116|10116|4|0.0%|0.2%|
[blocklist_de_strongips](#blocklist_de_strongips)|166|166|4|2.4%|0.2%|
[php_commenters](#php_commenters)|385|385|3|0.7%|0.2%|
[php_spammers](#php_spammers)|622|622|2|0.3%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|2|0.0%|0.1%|
[php_dictionary](#php_dictionary)|630|630|1|0.1%|0.0%|
[et_compromised](#et_compromised)|1678|1678|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1725|1725|1|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|20039|20039|1|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|16180|16180|1|0.0%|0.0%|

## proxz

[proxz.com](http://www.proxz.com) open proxies (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.proxz.com/proxylists.xml).

The last time downloaded was found to be dated: Tue Jun  9 07:41:31 UTC 2015.

The ipset `proxz` has **1108** entries, **1108** unique IPs.

The following table shows the overlaps of `proxz` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `proxz`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `proxz`.
- ` this % ` is the percentage **of this ipset (`proxz`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_proxies](#firehol_proxies)|11673|11900|1108|9.3%|100.0%|
[firehol_anonymous](#firehol_anonymous)|18076|82086|1108|1.3%|100.0%|
[firehol_level3](#firehol_level3)|108319|9625797|669|0.0%|60.3%|
[stopforumspam_30d](#stopforumspam_30d)|92512|92512|663|0.7%|59.8%|
[ri_web_proxies](#ri_web_proxies)|7263|7263|503|6.9%|45.3%|
[stopforumspam_7d](#stopforumspam_7d)|29277|29277|476|1.6%|42.9%|
[xroxy](#xroxy)|2138|2138|403|18.8%|36.3%|
[firehol_level2](#firehol_level2)|26088|37744|249|0.6%|22.4%|
[proxyrss](#proxyrss)|1495|1495|238|15.9%|21.4%|
[ri_connect_proxies](#ri_connect_proxies)|2644|2644|188|7.1%|16.9%|
[stopforumspam_1d](#stopforumspam_1d)|7467|7467|179|2.3%|16.1%|
[blocklist_de](#blocklist_de)|31644|31644|160|0.5%|14.4%|
[blocklist_de_bots](#blocklist_de_bots)|3492|3492|146|4.1%|13.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|96|0.0%|8.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|43|0.0%|3.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|39|0.0%|3.5%|
[nixspam](#nixspam)|17190|17190|38|0.2%|3.4%|
[snort_ipfilter](#snort_ipfilter)|10116|10116|23|0.2%|2.0%|
[php_dictionary](#php_dictionary)|630|630|21|3.3%|1.8%|
[php_spammers](#php_spammers)|622|622|20|3.2%|1.8%|
[blocklist_de_mail](#blocklist_de_mail)|20039|20039|14|0.0%|1.2%|
[php_commenters](#php_commenters)|385|385|7|1.8%|0.6%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|6|0.9%|0.5%|
[blocklist_de_strongips](#blocklist_de_strongips)|166|166|3|1.8%|0.2%|
[alienvault_reputation](#alienvault_reputation)|180914|180914|3|0.0%|0.2%|
[et_compromised](#et_compromised)|1678|1678|2|0.1%|0.1%|
[bruteforceblocker](#bruteforceblocker)|1725|1725|2|0.1%|0.1%|
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
[firehol_proxies](#firehol_proxies)|11673|11900|2644|22.2%|100.0%|
[firehol_anonymous](#firehol_anonymous)|18076|82086|2644|3.2%|100.0%|
[stopforumspam_30d](#stopforumspam_30d)|92512|92512|1502|1.6%|56.8%|
[firehol_level3](#firehol_level3)|108319|9625797|1502|0.0%|56.8%|
[ri_web_proxies](#ri_web_proxies)|7263|7263|1116|15.3%|42.2%|
[stopforumspam_7d](#stopforumspam_7d)|29277|29277|617|2.1%|23.3%|
[xroxy](#xroxy)|2138|2138|382|17.8%|14.4%|
[proxyrss](#proxyrss)|1495|1495|243|16.2%|9.1%|
[proxz](#proxz)|1108|1108|188|16.9%|7.1%|
[firehol_level2](#firehol_level2)|26088|37744|181|0.4%|6.8%|
[stopforumspam_1d](#stopforumspam_1d)|7467|7467|133|1.7%|5.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|102|0.0%|3.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|80|0.0%|3.0%|
[blocklist_de](#blocklist_de)|31644|31644|76|0.2%|2.8%|
[blocklist_de_bots](#blocklist_de_bots)|3492|3492|72|2.0%|2.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|55|0.0%|2.0%|
[nixspam](#nixspam)|17190|17190|9|0.0%|0.3%|
[snort_ipfilter](#snort_ipfilter)|10116|10116|7|0.0%|0.2%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|7|1.0%|0.2%|
[php_commenters](#php_commenters)|385|385|5|1.2%|0.1%|
[php_dictionary](#php_dictionary)|630|630|4|0.6%|0.1%|
[blocklist_de_mail](#blocklist_de_mail)|20039|20039|4|0.0%|0.1%|
[php_spammers](#php_spammers)|622|622|3|0.4%|0.1%|
[alienvault_reputation](#alienvault_reputation)|180914|180914|3|0.0%|0.1%|
[blocklist_de_imap](#blocklist_de_imap)|2596|2596|2|0.0%|0.0%|
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
[firehol_proxies](#firehol_proxies)|11673|11900|7263|61.0%|100.0%|
[firehol_anonymous](#firehol_anonymous)|18076|82086|7263|8.8%|100.0%|
[firehol_level3](#firehol_level3)|108319|9625797|3514|0.0%|48.3%|
[stopforumspam_30d](#stopforumspam_30d)|92512|92512|3466|3.7%|47.7%|
[stopforumspam_7d](#stopforumspam_7d)|29277|29277|1572|5.3%|21.6%|
[ri_connect_proxies](#ri_connect_proxies)|2644|2644|1116|42.2%|15.3%|
[xroxy](#xroxy)|2138|2138|935|43.7%|12.8%|
[firehol_level2](#firehol_level2)|26088|37744|674|1.7%|9.2%|
[proxyrss](#proxyrss)|1495|1495|609|40.7%|8.3%|
[proxz](#proxz)|1108|1108|503|45.3%|6.9%|
[stopforumspam_1d](#stopforumspam_1d)|7467|7467|474|6.3%|6.5%|
[blocklist_de](#blocklist_de)|31644|31644|410|1.2%|5.6%|
[blocklist_de_bots](#blocklist_de_bots)|3492|3492|358|10.2%|4.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|211|0.0%|2.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|204|0.0%|2.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|144|0.0%|1.9%|
[nixspam](#nixspam)|17190|17190|80|0.4%|1.1%|
[snort_ipfilter](#snort_ipfilter)|10116|10116|60|0.5%|0.8%|
[php_dictionary](#php_dictionary)|630|630|54|8.5%|0.7%|
[php_spammers](#php_spammers)|622|622|45|7.2%|0.6%|
[blocklist_de_mail](#blocklist_de_mail)|20039|20039|45|0.2%|0.6%|
[php_commenters](#php_commenters)|385|385|23|5.9%|0.3%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|14|2.1%|0.1%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4860|4860|7|0.1%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|16180|16180|7|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|6|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|4|1.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|4|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|166|166|4|2.4%|0.0%|
[et_tor](#et_tor)|6400|6400|3|0.0%|0.0%|
[dm_tor](#dm_tor)|6391|6391|3|0.0%|0.0%|
[bm_tor](#bm_tor)|6355|6355|3|0.0%|0.0%|
[alienvault_reputation](#alienvault_reputation)|180914|180914|3|0.0%|0.0%|
[php_harvesters](#php_harvesters)|366|366|2|0.5%|0.0%|
[sslbl](#sslbl)|382|382|1|0.2%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|1|0.0%|0.0%|
[firehol_level1](#firehol_level1)|5092|688943415|1|0.0%|0.0%|
[et_compromised](#et_compromised)|1678|1678|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1725|1725|1|0.0%|0.0%|

## shunlist

[AutoShun.org](http://autoshun.org/) IPs identified as hostile by correlating logs from distributed snort installations running the autoshun plugin

Source is downloaded from [this link](http://www.autoshun.org/files/shunlist.csv).

The last time downloaded was found to be dated: Tue Jun  9 07:30:05 UTC 2015.

The ipset `shunlist` has **1264** entries, **1264** unique IPs.

The following table shows the overlaps of `shunlist` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `shunlist`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `shunlist`.
- ` this % ` is the percentage **of this ipset (`shunlist`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level3](#firehol_level3)|108319|9625797|1264|0.0%|100.0%|
[alienvault_reputation](#alienvault_reputation)|180914|180914|1252|0.6%|99.0%|
[openbl_60d](#openbl_60d)|7190|7190|560|7.7%|44.3%|
[openbl_30d](#openbl_30d)|2861|2861|531|18.5%|42.0%|
[firehol_level2](#firehol_level2)|26088|37744|456|1.2%|36.0%|
[blocklist_de](#blocklist_de)|31644|31644|453|1.4%|35.8%|
[bruteforceblocker](#bruteforceblocker)|1725|1725|439|25.4%|34.7%|
[et_compromised](#et_compromised)|1678|1678|416|24.7%|32.9%|
[blocklist_de_ssh](#blocklist_de_ssh)|2582|2582|415|16.0%|32.8%|
[openbl_7d](#openbl_7d)|826|826|226|27.3%|17.8%|
[firehol_level1](#firehol_level1)|5092|688943415|187|0.0%|14.7%|
[dshield](#dshield)|20|5120|121|2.3%|9.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|114|0.0%|9.0%|
[et_block](#et_block)|999|18343755|104|0.0%|8.2%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|96|0.0%|7.5%|
[openbl_1d](#openbl_1d)|137|137|72|52.5%|5.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|71|0.0%|5.6%|
[sslbl](#sslbl)|382|382|64|16.7%|5.0%|
[ciarmy](#ciarmy)|430|430|34|7.9%|2.6%|
[blocklist_de_apache](#blocklist_de_apache)|16180|16180|32|0.1%|2.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|26|0.0%|2.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|166|166|22|13.2%|1.7%|
[voipbl](#voipbl)|10507|10919|12|0.1%|0.9%|
[stopforumspam_30d](#stopforumspam_30d)|92512|92512|4|0.0%|0.3%|
[blocklist_de_mail](#blocklist_de_mail)|20039|20039|4|0.0%|0.3%|
[snort_ipfilter](#snort_ipfilter)|10116|10116|3|0.0%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|0.2%|
[blocklist_de_imap](#blocklist_de_imap)|2596|2596|2|0.0%|0.1%|
[blocklist_de_ftp](#blocklist_de_ftp)|360|360|2|0.5%|0.1%|
[stopforumspam_7d](#stopforumspam_7d)|29277|29277|1|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7467|7467|1|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[firehol_proxies](#firehol_proxies)|11673|11900|1|0.0%|0.0%|
[firehol_anonymous](#firehol_anonymous)|18076|82086|1|0.0%|0.0%|
[et_tor](#et_tor)|6400|6400|1|0.0%|0.0%|
[dm_tor](#dm_tor)|6391|6391|1|0.0%|0.0%|
[bm_tor](#bm_tor)|6355|6355|1|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4860|4860|1|0.0%|0.0%|

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
[firehol_level3](#firehol_level3)|108319|9625797|10116|0.1%|100.0%|
[firehol_anonymous](#firehol_anonymous)|18076|82086|1139|1.3%|11.2%|
[et_tor](#et_tor)|6400|6400|1082|16.9%|10.6%|
[dm_tor](#dm_tor)|6391|6391|1041|16.2%|10.2%|
[bm_tor](#bm_tor)|6355|6355|1029|16.1%|10.1%|
[stopforumspam_30d](#stopforumspam_30d)|92512|92512|805|0.8%|7.9%|
[firehol_level2](#firehol_level2)|26088|37744|679|1.7%|6.7%|
[stopforumspam_7d](#stopforumspam_7d)|29277|29277|660|2.2%|6.5%|
[stopforumspam_1d](#stopforumspam_1d)|7467|7467|404|5.4%|3.9%|
[blocklist_de](#blocklist_de)|31644|31644|315|0.9%|3.1%|
[et_block](#et_block)|999|18343755|300|0.0%|2.9%|
[firehol_level1](#firehol_level1)|5092|688943415|299|0.0%|2.9%|
[blocklist_de_mail](#blocklist_de_mail)|20039|20039|270|1.3%|2.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|263|0.0%|2.5%|
[firehol_proxies](#firehol_proxies)|11673|11900|253|2.1%|2.5%|
[zeus](#zeus)|232|232|201|86.6%|1.9%|
[nixspam](#nixspam)|17190|17190|181|1.0%|1.7%|
[zeus_badips](#zeus_badips)|203|203|179|88.1%|1.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|175|0.0%|1.7%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|172|46.2%|1.7%|
[alienvault_reputation](#alienvault_reputation)|180914|180914|124|0.0%|1.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|117|0.0%|1.1%|
[php_dictionary](#php_dictionary)|630|630|85|13.4%|0.8%|
[php_spammers](#php_spammers)|622|622|81|13.0%|0.8%|
[feodo](#feodo)|103|103|81|78.6%|0.8%|
[ri_web_proxies](#ri_web_proxies)|7263|7263|60|0.8%|0.5%|
[php_commenters](#php_commenters)|385|385|54|14.0%|0.5%|
[xroxy](#xroxy)|2138|2138|36|1.6%|0.3%|
[sslbl](#sslbl)|382|382|32|8.3%|0.3%|
[openbl_60d](#openbl_60d)|7190|7190|28|0.3%|0.2%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|28|2.1%|0.2%|
[blocklist_de_bots](#blocklist_de_bots)|3492|3492|28|0.8%|0.2%|
[proxz](#proxz)|1108|1108|23|2.0%|0.2%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|19|0.0%|0.1%|
[blocklist_de_apache](#blocklist_de_apache)|16180|16180|19|0.1%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|15|0.0%|0.1%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4860|4860|15|0.3%|0.1%|
[php_harvesters](#php_harvesters)|366|366|14|3.8%|0.1%|
[blocklist_de_imap](#blocklist_de_imap)|2596|2596|12|0.4%|0.1%|
[palevo](#palevo)|13|13|11|84.6%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|11|0.0%|0.1%|
[ri_connect_proxies](#ri_connect_proxies)|2644|2644|7|0.2%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|6|0.0%|0.0%|
[openbl_30d](#openbl_30d)|2861|2861|6|0.2%|0.0%|
[proxyrss](#proxyrss)|1495|1495|4|0.2%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|4|0.0%|0.0%|
[shunlist](#shunlist)|1264|1264|3|0.2%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|166|166|2|1.2%|0.0%|
[virbl](#virbl)|14|14|1|7.1%|0.0%|
[openbl_7d](#openbl_7d)|826|826|1|0.1%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|1|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|1|0.1%|0.0%|
[et_compromised](#et_compromised)|1678|1678|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1725|1725|1|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2582|2582|1|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|360|360|1|0.2%|0.0%|

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
[firehol_level1](#firehol_level1)|5092|688943415|18338560|2.6%|100.0%|
[et_block](#et_block)|999|18343755|18338560|99.9%|100.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|8532506|2.4%|46.5%|
[firehol_level3](#firehol_level3)|108319|9625797|6933031|72.0%|37.8%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|6932480|75.5%|37.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|2272265|0.2%|12.3%|
[fullbogons](#fullbogons)|3720|670264216|151552|0.0%|0.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|130368|0.0%|0.7%|
[alienvault_reputation](#alienvault_reputation)|180914|180914|1374|0.7%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1037|0.3%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92512|92512|1008|1.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|512|0.1%|0.0%|
[dshield](#dshield)|20|5120|512|10.0%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29277|29277|307|1.0%|0.0%|
[firehol_level2](#firehol_level2)|26088|37744|259|0.6%|0.0%|
[openbl_60d](#openbl_60d)|7190|7190|240|3.3%|0.0%|
[blocklist_de](#blocklist_de)|31644|31644|199|0.6%|0.0%|
[nixspam](#nixspam)|17190|17190|152|0.8%|0.0%|
[openbl_30d](#openbl_30d)|2861|2861|121|4.2%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2582|2582|117|4.5%|0.0%|
[et_compromised](#et_compromised)|1678|1678|101|6.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1725|1725|101|5.8%|0.0%|
[shunlist](#shunlist)|1264|1264|96|7.5%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7467|7467|77|1.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3492|3492|52|1.4%|0.0%|
[openbl_7d](#openbl_7d)|826|826|49|5.9%|0.0%|
[php_commenters](#php_commenters)|385|385|29|7.5%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|29|2.2%|0.0%|
[openbl_1d](#openbl_1d)|137|137|23|16.7%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|20039|20039|22|0.1%|0.0%|
[snort_ipfilter](#snort_ipfilter)|10116|10116|19|0.1%|0.0%|
[zeus_badips](#zeus_badips)|203|203|16|7.8%|0.0%|
[zeus](#zeus)|232|232|16|6.8%|0.0%|
[voipbl](#voipbl)|10507|10919|14|0.1%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2596|2596|14|0.5%|0.0%|
[php_dictionary](#php_dictionary)|630|630|6|0.9%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|6|0.4%|0.0%|
[firehol_anonymous](#firehol_anonymous)|18076|82086|6|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|5|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|166|166|5|3.0%|0.0%|
[php_spammers](#php_spammers)|622|622|4|0.6%|0.0%|
[malc0de](#malc0de)|342|342|4|1.1%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4860|4860|4|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|16180|16180|4|0.0%|0.0%|
[et_tor](#et_tor)|6400|6400|3|0.0%|0.0%|
[dm_tor](#dm_tor)|6391|6391|3|0.0%|0.0%|
[bm_tor](#bm_tor)|6355|6355|3|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|2|0.3%|0.0%|
[firehol_proxies](#firehol_proxies)|11673|11900|2|0.0%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|89|89|2|2.2%|0.0%|
[sslbl](#sslbl)|382|382|1|0.2%|0.0%|
[php_harvesters](#php_harvesters)|366|366|1|0.2%|0.0%|
[et_botcc](#et_botcc)|509|509|1|0.1%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|360|360|1|0.2%|0.0%|

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
[firehol_level1](#firehol_level1)|5092|688943415|487424|0.0%|100.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|270785|0.1%|55.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|98904|0.0%|20.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|33155|0.0%|6.8%|
[et_block](#et_block)|999|18343755|517|0.0%|0.1%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|512|0.0%|0.1%|
[firehol_level3](#firehol_level3)|108319|9625797|89|0.0%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92512|92512|78|0.0%|0.0%|
[alienvault_reputation](#alienvault_reputation)|180914|180914|15|0.0%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29277|29277|9|0.0%|0.0%|
[firehol_level2](#firehol_level2)|26088|37744|8|0.0%|0.0%|
[php_commenters](#php_commenters)|385|385|7|1.8%|0.0%|
[blocklist_de](#blocklist_de)|31644|31644|7|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|10116|10116|6|0.0%|0.0%|
[zeus_badips](#zeus_badips)|203|203|5|2.4%|0.0%|
[zeus](#zeus)|232|232|5|2.1%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|166|166|3|1.8%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3492|3492|3|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7467|7467|2|0.0%|0.0%|
[nixspam](#nixspam)|17190|17190|2|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2582|2582|2|0.0%|0.0%|
[virbl](#virbl)|14|14|1|7.1%|0.0%|
[php_harvesters](#php_harvesters)|366|366|1|0.2%|0.0%|
[openbl_60d](#openbl_60d)|7190|7190|1|0.0%|0.0%|
[openbl_30d](#openbl_30d)|2861|2861|1|0.0%|0.0%|
[malc0de](#malc0de)|342|342|1|0.2%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.0%|
[firehol_anonymous](#firehol_anonymous)|18076|82086|1|0.0%|0.0%|
[bm_tor](#bm_tor)|6355|6355|1|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|20039|20039|1|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|16180|16180|1|0.0%|0.0%|

## sslbl

[Abuse.ch SSL Blacklist](https://sslbl.abuse.ch/) bad SSL traffic related to malware or botnet activities - **excellent list**

Source is downloaded from [this link](https://sslbl.abuse.ch/blacklist/sslipblacklist.csv).

The last time downloaded was found to be dated: Tue Jun  9 08:15:05 UTC 2015.

The ipset `sslbl` has **382** entries, **382** unique IPs.

The following table shows the overlaps of `sslbl` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `sslbl`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `sslbl`.
- ` this % ` is the percentage **of this ipset (`sslbl`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level1](#firehol_level1)|5092|688943415|382|0.0%|100.0%|
[firehol_level3](#firehol_level3)|108319|9625797|96|0.0%|25.1%|
[alienvault_reputation](#alienvault_reputation)|180914|180914|68|0.0%|17.8%|
[shunlist](#shunlist)|1264|1264|64|5.0%|16.7%|
[feodo](#feodo)|103|103|37|35.9%|9.6%|
[et_block](#et_block)|999|18343755|37|0.0%|9.6%|
[snort_ipfilter](#snort_ipfilter)|10116|10116|32|0.3%|8.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|30|0.0%|7.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|5|0.0%|1.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|3|0.0%|0.7%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|1|0.0%|0.2%|
[ri_web_proxies](#ri_web_proxies)|7263|7263|1|0.0%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.2%|
[firehol_proxies](#firehol_proxies)|11673|11900|1|0.0%|0.2%|
[firehol_level2](#firehol_level2)|26088|37744|1|0.0%|0.2%|
[firehol_anonymous](#firehol_anonymous)|18076|82086|1|0.0%|0.2%|
[blocklist_de_ssh](#blocklist_de_ssh)|2582|2582|1|0.0%|0.2%|
[blocklist_de](#blocklist_de)|31644|31644|1|0.0%|0.2%|

## stopforumspam_1d

[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers in the last 24 hours - **excellent list**

Source is downloaded from [this link](http://www.stopforumspam.com/downloads/listed_ip_1.zip).

The last time downloaded was found to be dated: Tue Jun  9 08:00:01 UTC 2015.

The ipset `stopforumspam_1d` has **7467** entries, **7467** unique IPs.

The following table shows the overlaps of `stopforumspam_1d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `stopforumspam_1d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `stopforumspam_1d`.
- ` this % ` is the percentage **of this ipset (`stopforumspam_1d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|26088|37744|7467|19.7%|100.0%|
[firehol_level3](#firehol_level3)|108319|9625797|6561|0.0%|87.8%|
[stopforumspam_30d](#stopforumspam_30d)|92512|92512|6544|7.0%|87.6%|
[stopforumspam_7d](#stopforumspam_7d)|29277|29277|6464|22.0%|86.5%|
[blocklist_de](#blocklist_de)|31644|31644|1385|4.3%|18.5%|
[blocklist_de_bots](#blocklist_de_bots)|3492|3492|1318|37.7%|17.6%|
[firehol_anonymous](#firehol_anonymous)|18076|82086|1052|1.2%|14.0%|
[firehol_proxies](#firehol_proxies)|11673|11900|836|7.0%|11.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|539|0.0%|7.2%|
[ri_web_proxies](#ri_web_proxies)|7263|7263|474|6.5%|6.3%|
[snort_ipfilter](#snort_ipfilter)|10116|10116|404|3.9%|5.4%|
[et_tor](#et_tor)|6400|6400|357|5.5%|4.7%|
[dm_tor](#dm_tor)|6391|6391|355|5.5%|4.7%|
[bm_tor](#bm_tor)|6355|6355|351|5.5%|4.7%|
[proxyrss](#proxyrss)|1495|1495|336|22.4%|4.4%|
[xroxy](#xroxy)|2138|2138|263|12.3%|3.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|217|0.0%|2.9%|
[proxz](#proxz)|1108|1108|179|16.1%|2.3%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|156|41.9%|2.0%|
[php_commenters](#php_commenters)|385|385|153|39.7%|2.0%|
[ri_connect_proxies](#ri_connect_proxies)|2644|2644|133|5.0%|1.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|127|0.0%|1.7%|
[blocklist_de_strongips](#blocklist_de_strongips)|166|166|103|62.0%|1.3%|
[firehol_level1](#firehol_level1)|5092|688943415|79|0.0%|1.0%|
[et_block](#et_block)|999|18343755|78|0.0%|1.0%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|77|0.0%|1.0%|
[nixspam](#nixspam)|17190|17190|76|0.4%|1.0%|
[blocklist_de_apache](#blocklist_de_apache)|16180|16180|63|0.3%|0.8%|
[blocklist_de_mail](#blocklist_de_mail)|20039|20039|49|0.2%|0.6%|
[alienvault_reputation](#alienvault_reputation)|180914|180914|48|0.0%|0.6%|
[php_spammers](#php_spammers)|622|622|46|7.3%|0.6%|
[php_harvesters](#php_harvesters)|366|366|42|11.4%|0.5%|
[php_dictionary](#php_dictionary)|630|630|36|5.7%|0.4%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|30|0.0%|0.4%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4860|4860|27|0.5%|0.3%|
[openbl_60d](#openbl_60d)|7190|7190|20|0.2%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|11|0.0%|0.1%|
[voipbl](#voipbl)|10507|10919|5|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|3|0.4%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|2|0.0%|0.0%|
[et_compromised](#et_compromised)|1678|1678|2|0.1%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1725|1725|2|0.1%|0.0%|
[zeus_badips](#zeus_badips)|203|203|1|0.4%|0.0%|
[zeus](#zeus)|232|232|1|0.4%|0.0%|
[shunlist](#shunlist)|1264|1264|1|0.0%|0.0%|
[openbl_30d](#openbl_30d)|2861|2861|1|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|1|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|1|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2596|2596|1|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|360|360|1|0.2%|0.0%|

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
[firehol_level3](#firehol_level3)|108319|9625797|92512|0.9%|100.0%|
[stopforumspam_7d](#stopforumspam_7d)|29277|29277|29167|99.6%|31.5%|
[firehol_level2](#firehol_level2)|26088|37744|7937|21.0%|8.5%|
[stopforumspam_1d](#stopforumspam_1d)|7467|7467|6544|87.6%|7.0%|
[firehol_anonymous](#firehol_anonymous)|18076|82086|5901|7.1%|6.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|5744|0.0%|6.2%|
[firehol_proxies](#firehol_proxies)|11673|11900|5257|44.1%|5.6%|
[ri_web_proxies](#ri_web_proxies)|7263|7263|3466|47.7%|3.7%|
[blocklist_de](#blocklist_de)|31644|31644|2695|8.5%|2.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|2475|0.0%|2.6%|
[blocklist_de_bots](#blocklist_de_bots)|3492|3492|2380|68.1%|2.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|1506|0.0%|1.6%|
[ri_connect_proxies](#ri_connect_proxies)|2644|2644|1502|56.8%|1.6%|
[xroxy](#xroxy)|2138|2138|1265|59.1%|1.3%|
[firehol_level1](#firehol_level1)|5092|688943415|1088|0.0%|1.1%|
[et_block](#et_block)|999|18343755|1011|0.0%|1.0%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|1008|0.0%|1.0%|
[snort_ipfilter](#snort_ipfilter)|10116|10116|805|7.9%|0.8%|
[proxyrss](#proxyrss)|1495|1495|740|49.4%|0.7%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|719|0.0%|0.7%|
[proxz](#proxz)|1108|1108|663|59.8%|0.7%|
[et_tor](#et_tor)|6400|6400|659|10.2%|0.7%|
[dm_tor](#dm_tor)|6391|6391|638|9.9%|0.6%|
[bm_tor](#bm_tor)|6355|6355|628|9.8%|0.6%|
[php_commenters](#php_commenters)|385|385|289|75.0%|0.3%|
[blocklist_de_mail](#blocklist_de_mail)|20039|20039|234|1.1%|0.2%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|233|62.6%|0.2%|
[nixspam](#nixspam)|17190|17190|216|1.2%|0.2%|
[blocklist_de_apache](#blocklist_de_apache)|16180|16180|210|1.2%|0.2%|
[alienvault_reputation](#alienvault_reputation)|180914|180914|198|0.1%|0.2%|
[php_spammers](#php_spammers)|622|622|131|21.0%|0.1%|
[blocklist_de_strongips](#blocklist_de_strongips)|166|166|124|74.6%|0.1%|
[php_dictionary](#php_dictionary)|630|630|119|18.8%|0.1%|
[php_harvesters](#php_harvesters)|366|366|81|22.1%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|78|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4860|4860|61|1.2%|0.0%|
[openbl_60d](#openbl_60d)|7190|7190|52|0.7%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|48|0.0%|0.0%|
[voipbl](#voipbl)|10507|10919|35|0.3%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|18|2.7%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2582|2582|15|0.5%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|13|0.0%|0.0%|
[et_compromised](#et_compromised)|1678|1678|13|0.7%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1725|1725|13|0.7%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2596|2596|7|0.2%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|360|360|5|1.3%|0.0%|
[shunlist](#shunlist)|1264|1264|4|0.3%|0.0%|
[openbl_30d](#openbl_30d)|2861|2861|4|0.1%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|4|0.3%|0.0%|
[openbl_7d](#openbl_7d)|826|826|3|0.3%|0.0%|
[zeus_badips](#zeus_badips)|203|203|2|0.9%|0.0%|
[zeus](#zeus)|232|232|2|0.8%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|2|0.1%|0.0%|
[ciarmy](#ciarmy)|430|430|2|0.4%|0.0%|
[fullbogons](#fullbogons)|3720|670264216|1|0.0%|0.0%|
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
[firehol_level3](#firehol_level3)|108319|9625797|29168|0.3%|99.6%|
[stopforumspam_30d](#stopforumspam_30d)|92512|92512|29167|31.5%|99.6%|
[firehol_level2](#firehol_level2)|26088|37744|7483|19.8%|25.5%|
[stopforumspam_1d](#stopforumspam_1d)|7467|7467|6464|86.5%|22.0%|
[firehol_anonymous](#firehol_anonymous)|18076|82086|2826|3.4%|9.6%|
[firehol_proxies](#firehol_proxies)|11673|11900|2420|20.3%|8.2%|
[blocklist_de](#blocklist_de)|31644|31644|2315|7.3%|7.9%|
[blocklist_de_bots](#blocklist_de_bots)|3492|3492|2142|61.3%|7.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|1893|0.0%|6.4%|
[ri_web_proxies](#ri_web_proxies)|7263|7263|1572|21.6%|5.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|825|0.0%|2.8%|
[snort_ipfilter](#snort_ipfilter)|10116|10116|660|6.5%|2.2%|
[xroxy](#xroxy)|2138|2138|648|30.3%|2.2%|
[ri_connect_proxies](#ri_connect_proxies)|2644|2644|617|23.3%|2.1%|
[proxyrss](#proxyrss)|1495|1495|573|38.3%|1.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|549|0.0%|1.8%|
[et_tor](#et_tor)|6400|6400|544|8.5%|1.8%|
[dm_tor](#dm_tor)|6391|6391|523|8.1%|1.7%|
[bm_tor](#bm_tor)|6355|6355|515|8.1%|1.7%|
[proxz](#proxz)|1108|1108|476|42.9%|1.6%|
[firehol_level1](#firehol_level1)|5092|688943415|317|0.0%|1.0%|
[et_block](#et_block)|999|18343755|308|0.0%|1.0%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|307|0.0%|1.0%|
[php_commenters](#php_commenters)|385|385|215|55.8%|0.7%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|192|51.6%|0.6%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|157|0.0%|0.5%|
[blocklist_de_mail](#blocklist_de_mail)|20039|20039|129|0.6%|0.4%|
[blocklist_de_apache](#blocklist_de_apache)|16180|16180|128|0.7%|0.4%|
[nixspam](#nixspam)|17190|17190|122|0.7%|0.4%|
[blocklist_de_strongips](#blocklist_de_strongips)|166|166|113|68.0%|0.3%|
[alienvault_reputation](#alienvault_reputation)|180914|180914|98|0.0%|0.3%|
[php_spammers](#php_spammers)|622|622|77|12.3%|0.2%|
[php_dictionary](#php_dictionary)|630|630|77|12.2%|0.2%|
[php_harvesters](#php_harvesters)|366|366|61|16.6%|0.2%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4860|4860|42|0.8%|0.1%|
[openbl_60d](#openbl_60d)|7190|7190|25|0.3%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|22|0.0%|0.0%|
[voipbl](#voipbl)|10507|10919|15|0.1%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|13|1.9%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|9|0.0%|0.0%|
[et_compromised](#et_compromised)|1678|1678|5|0.2%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1725|1725|5|0.2%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|4|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2582|2582|3|0.1%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|2|0.1%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2596|2596|2|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|360|360|2|0.5%|0.0%|
[zeus_badips](#zeus_badips)|203|203|1|0.4%|0.0%|
[zeus](#zeus)|232|232|1|0.4%|0.0%|
[shunlist](#shunlist)|1264|1264|1|0.0%|0.0%|
[openbl_30d](#openbl_30d)|2861|2861|1|0.0%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|1|0.0%|0.0%|
[dshield](#dshield)|20|5120|1|0.0%|0.0%|
[ciarmy](#ciarmy)|430|430|1|0.2%|0.0%|

## virbl

[VirBL](http://virbl.bit.nl/) is a project of which the idea was born during the RIPE-48 meeting. The plan was to get reports of virusscanning mailservers, and put the IP-addresses that were reported to send viruses on a blacklist.

Source is downloaded from [this link](http://virbl.bit.nl/download/virbl.dnsbl.bit.nl.txt).

The last time downloaded was found to be dated: Tue Jun  9 08:32:04 UTC 2015.

The ipset `virbl` has **14** entries, **14** unique IPs.

The following table shows the overlaps of `virbl` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `virbl`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `virbl`.
- ` this % ` is the percentage **of this ipset (`virbl`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level3](#firehol_level3)|108319|9625797|14|0.0%|100.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|1|0.0%|7.1%|
[snort_ipfilter](#snort_ipfilter)|10116|10116|1|0.0%|7.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|1|0.0%|7.1%|
[firehol_level1](#firehol_level1)|5092|688943415|1|0.0%|7.1%|

## voipbl

[VoIPBL.org](http://www.voipbl.org/) a distributed VoIP blacklist that is aimed to protects against VoIP Fraud and minimizing abuse for network that have publicly accessible PBX's. Several algorithms, external sources and manual confirmation are used before they categorize something as an attack and determine the threat level.

Source is downloaded from [this link](http://www.voipbl.org/update/).

The last time downloaded was found to be dated: Tue Jun  9 05:27:05 UTC 2015.

The ipset `voipbl` has **10507** entries, **10919** unique IPs.

The following table shows the overlaps of `voipbl` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `voipbl`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `voipbl`.
- ` this % ` is the percentage **of this ipset (`voipbl`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|1600|0.0%|14.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|434|0.0%|3.9%|
[firehol_level1](#firehol_level1)|5092|688943415|333|0.0%|3.0%|
[fullbogons](#fullbogons)|3720|670264216|319|0.0%|2.9%|
[bogons](#bogons)|13|592708608|319|0.0%|2.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|299|0.0%|2.7%|
[alienvault_reputation](#alienvault_reputation)|180914|180914|189|0.1%|1.7%|
[firehol_anonymous](#firehol_anonymous)|18076|82086|78|0.0%|0.7%|
[firehol_level3](#firehol_level3)|108319|9625797|56|0.0%|0.5%|
[firehol_level2](#firehol_level2)|26088|37744|38|0.1%|0.3%|
[stopforumspam_30d](#stopforumspam_30d)|92512|92512|35|0.0%|0.3%|
[blocklist_de](#blocklist_de)|31644|31644|33|0.1%|0.3%|
[blocklist_de_sip](#blocklist_de_sip)|89|89|27|30.3%|0.2%|
[stopforumspam_7d](#stopforumspam_7d)|29277|29277|15|0.0%|0.1%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|14|0.0%|0.1%|
[et_block](#et_block)|999|18343755|14|0.0%|0.1%|
[shunlist](#shunlist)|1264|1264|12|0.9%|0.1%|
[openbl_60d](#openbl_60d)|7190|7190|8|0.1%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7467|7467|5|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|4|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|16180|16180|4|0.0%|0.0%|
[openbl_30d](#openbl_30d)|2861|2861|3|0.1%|0.0%|
[et_tor](#et_tor)|6400|6400|3|0.0%|0.0%|
[dm_tor](#dm_tor)|6391|6391|3|0.0%|0.0%|
[bm_tor](#bm_tor)|6355|6355|3|0.0%|0.0%|
[nixspam](#nixspam)|17190|17190|2|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|2|0.0%|0.0%|
[et_compromised](#et_compromised)|1678|1678|2|0.1%|0.0%|
[ciarmy](#ciarmy)|430|430|2|0.4%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1725|1725|2|0.1%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2582|2582|2|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.0%|
[firehol_proxies](#firehol_proxies)|11673|11900|1|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4860|4860|1|0.0%|0.0%|

## xroxy

[xroxy.com](http://www.xroxy.com) open proxies (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.xroxy.com/proxyrss.xml).

The last time downloaded was found to be dated: Tue Jun  9 08:33:01 UTC 2015.

The ipset `xroxy` has **2138** entries, **2138** unique IPs.

The following table shows the overlaps of `xroxy` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `xroxy`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `xroxy`.
- ` this % ` is the percentage **of this ipset (`xroxy`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_proxies](#firehol_proxies)|11673|11900|2138|17.9%|100.0%|
[firehol_anonymous](#firehol_anonymous)|18076|82086|2138|2.6%|100.0%|
[firehol_level3](#firehol_level3)|108319|9625797|1279|0.0%|59.8%|
[stopforumspam_30d](#stopforumspam_30d)|92512|92512|1265|1.3%|59.1%|
[ri_web_proxies](#ri_web_proxies)|7263|7263|935|12.8%|43.7%|
[stopforumspam_7d](#stopforumspam_7d)|29277|29277|648|2.2%|30.3%|
[proxz](#proxz)|1108|1108|403|36.3%|18.8%|
[ri_connect_proxies](#ri_connect_proxies)|2644|2644|382|14.4%|17.8%|
[proxyrss](#proxyrss)|1495|1495|354|23.6%|16.5%|
[firehol_level2](#firehol_level2)|26088|37744|346|0.9%|16.1%|
[stopforumspam_1d](#stopforumspam_1d)|7467|7467|263|3.5%|12.3%|
[blocklist_de](#blocklist_de)|31644|31644|201|0.6%|9.4%|
[blocklist_de_bots](#blocklist_de_bots)|3492|3492|163|4.6%|7.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|105|0.0%|4.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|104|0.0%|4.8%|
[nixspam](#nixspam)|17190|17190|58|0.3%|2.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|58|0.0%|2.7%|
[php_dictionary](#php_dictionary)|630|630|38|6.0%|1.7%|
[blocklist_de_mail](#blocklist_de_mail)|20039|20039|38|0.1%|1.7%|
[snort_ipfilter](#snort_ipfilter)|10116|10116|36|0.3%|1.6%|
[php_spammers](#php_spammers)|622|622|30|4.8%|1.4%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|13|1.9%|0.6%|
[php_commenters](#php_commenters)|385|385|8|2.0%|0.3%|
[blocklist_de_strongips](#blocklist_de_strongips)|166|166|5|3.0%|0.2%|
[alienvault_reputation](#alienvault_reputation)|180914|180914|5|0.0%|0.2%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|3|0.0%|0.1%|
[php_harvesters](#php_harvesters)|366|366|2|0.5%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.0%|
[et_tor](#et_tor)|6400|6400|1|0.0%|0.0%|
[et_compromised](#et_compromised)|1678|1678|1|0.0%|0.0%|
[dm_tor](#dm_tor)|6391|6391|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1725|1725|1|0.0%|0.0%|
[bm_tor](#bm_tor)|6355|6355|1|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2596|2596|1|0.0%|0.0%|

## zeus

[Abuse.ch Zeus tracker](https://zeustracker.abuse.ch) standard, contains the same data as the ZeuS IP blocklist (zeus_badips) but with the slight difference that it doesn't exclude hijacked websites (level 2) and free web hosting providers (level 3). This means that this blocklist contains all IPv4 addresses associated with ZeuS C&Cs which are currently being tracked by ZeuS Tracker. Hence this blocklist will likely cause some false positives. - **excellent list**

Source is downloaded from [this link](https://zeustracker.abuse.ch/blocklist.php?download=ipblocklist).

The last time downloaded was found to be dated: Tue Jun  9 04:31:29 UTC 2015.

The ipset `zeus` has **232** entries, **232** unique IPs.

The following table shows the overlaps of `zeus` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `zeus`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `zeus`.
- ` this % ` is the percentage **of this ipset (`zeus`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level1](#firehol_level1)|5092|688943415|232|0.0%|100.0%|
[et_block](#et_block)|999|18343755|229|0.0%|98.7%|
[zeus_badips](#zeus_badips)|203|203|203|100.0%|87.5%|
[firehol_level3](#firehol_level3)|108319|9625797|203|0.0%|87.5%|
[snort_ipfilter](#snort_ipfilter)|10116|10116|201|1.9%|86.6%|
[alienvault_reputation](#alienvault_reputation)|180914|180914|63|0.0%|27.1%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|16|0.0%|6.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|14|0.0%|6.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|10|0.0%|4.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|9|0.0%|3.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|6|0.0%|2.5%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|5|0.0%|2.1%|
[stopforumspam_30d](#stopforumspam_30d)|92512|92512|2|0.0%|0.8%|
[openbl_60d](#openbl_60d)|7190|7190|2|0.0%|0.8%|
[stopforumspam_7d](#stopforumspam_7d)|29277|29277|1|0.0%|0.4%|
[stopforumspam_1d](#stopforumspam_1d)|7467|7467|1|0.0%|0.4%|
[php_commenters](#php_commenters)|385|385|1|0.2%|0.4%|
[openbl_30d](#openbl_30d)|2861|2861|1|0.0%|0.4%|
[nixspam](#nixspam)|17190|17190|1|0.0%|0.4%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.4%|
[firehol_level2](#firehol_level2)|26088|37744|1|0.0%|0.4%|

## zeus_badips

[Abuse.ch Zeus tracker](https://zeustracker.abuse.ch) badips includes IPv4 addresses that are used by the ZeuS trojan. It is the recommened blocklist if you want to block only ZeuS IPs. It excludes IP addresses that ZeuS Tracker believes to be hijacked (level 2) or belong to a free web hosting provider (level 3). Hence the false postive rate should be much lower compared to the standard ZeuS IP blocklist. **excellent list**

Source is downloaded from [this link](https://zeustracker.abuse.ch/blocklist.php?download=badips).

The last time downloaded was found to be dated: Tue Jun  9 08:27:04 UTC 2015.

The ipset `zeus_badips` has **203** entries, **203** unique IPs.

The following table shows the overlaps of `zeus_badips` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `zeus_badips`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `zeus_badips`.
- ` this % ` is the percentage **of this ipset (`zeus_badips`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[zeus](#zeus)|232|232|203|87.5%|100.0%|
[firehol_level1](#firehol_level1)|5092|688943415|203|0.0%|100.0%|
[et_block](#et_block)|999|18343755|203|0.0%|100.0%|
[firehol_level3](#firehol_level3)|108319|9625797|181|0.0%|89.1%|
[snort_ipfilter](#snort_ipfilter)|10116|10116|179|1.7%|88.1%|
[alienvault_reputation](#alienvault_reputation)|180914|180914|38|0.0%|18.7%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|16|0.0%|7.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|10|0.0%|4.9%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|10|0.0%|4.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|8|0.0%|3.9%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|5|0.0%|2.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|4|0.0%|1.9%|
[stopforumspam_30d](#stopforumspam_30d)|92512|92512|2|0.0%|0.9%|
[stopforumspam_7d](#stopforumspam_7d)|29277|29277|1|0.0%|0.4%|
[stopforumspam_1d](#stopforumspam_1d)|7467|7467|1|0.0%|0.4%|
[php_commenters](#php_commenters)|385|385|1|0.2%|0.4%|
[openbl_60d](#openbl_60d)|7190|7190|1|0.0%|0.4%|
[nixspam](#nixspam)|17190|17190|1|0.0%|0.4%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.4%|
[firehol_level2](#firehol_level2)|26088|37744|1|0.0%|0.4%|
