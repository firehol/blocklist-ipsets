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

The following list was automatically generated on Wed Jun 10 07:01:05 UTC 2015.

The update frequency is the maximum allowed by internal configuration. A list will never be downloaded sooner than the update frequency stated. A list may also not be downloaded, after this frequency expired, if it has not been modified on the server (as reported by HTTP `IF_MODIFIED_SINCE` method).

name|info|type|entries|update|
:--:|:--:|:--:|:-----:|:----:|
[alienvault_reputation](#alienvault_reputation)|[AlienVault.com](https://www.alienvault.com/) IP reputation database (this list seems to include port scanning hosts and to be updated regularly, but we found no information about its retention policy)|ipv4 hash:ip|181943 unique IPs|updated every 6 hours  from [this link](https://reputation.alienvault.com/reputation.generic)
[blocklist_de](#blocklist_de)|[Blocklist.de](https://www.blocklist.de/) IPs that have been detected by fail2ban in the last 48 hours - **excellent list**|ipv4 hash:ip|29889 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/all.txt)
[blocklist_de_apache](#blocklist_de_apache)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service Apache, Apache-DDOS, RFI-Attacks.|ipv4 hash:ip|14825 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/apache.txt)
[blocklist_de_bots](#blocklist_de_bots)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the RFI-Attacks, REG-Bots, IRC-Bots or BadBots (BadBots = he has posted a Spam-Comment on a open Forum or Wiki).|ipv4 hash:ip|3015 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/bots.txt)
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|[Blocklist.de](https://www.blocklist.de/) All IPs which attacks Joomlas, Wordpress and other Web-Logins with Brute-Force Logins.|ipv4 hash:ip|3472 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/bruteforcelogin.txt)
[blocklist_de_ftp](#blocklist_de_ftp)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours for attacks on the Service FTP.|ipv4 hash:ip|864 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/ftp.txt)
[blocklist_de_imap](#blocklist_de_imap)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours for attacks on the Service imap, sasl, pop3, etc.|ipv4 hash:ip|2456 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/imap.txt)
[blocklist_de_mail](#blocklist_de_mail)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service Mail, Postfix.|ipv4 hash:ip|18940 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/mail.txt)
[blocklist_de_sip](#blocklist_de_sip)|[Blocklist.de](https://www.blocklist.de/) All IP addresses that tried to login in a SIP, VOIP or Asterisk Server and are included in the IPs list from [infiltrated.net](www.infiltrated.net)|ipv4 hash:ip|80 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/sip.txt)
[blocklist_de_ssh](#blocklist_de_ssh)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service SSH.|ipv4 hash:ip|3241 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/ssh.txt)
[blocklist_de_strongips](#blocklist_de_strongips)|[Blocklist.de](https://www.blocklist.de/) All IPs which are older then 2 month and have more then 5.000 attacks.|ipv4 hash:ip|174 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/strongips.txt)
[bm_tor](#bm_tor)|[torstatus.blutmagie.de](https://torstatus.blutmagie.de) list of all TOR network servers|ipv4 hash:ip|6410 unique IPs|updated every 30 mins  from [this link](https://torstatus.blutmagie.de/ip_list_all.php/Tor_ip_list_ALL.csv)
[bogons](#bogons)|[Team-Cymru.org](http://www.team-cymru.org) private and reserved addresses defined by RFC 1918, RFC 5735, and RFC 6598 and netblocks that have not been allocated to a regional internet registry - **excellent list - use it only your internet interface**|ipv4 hash:net|13 subnets, 592708608 unique IPs|updated every 1 day  from [this link](http://www.team-cymru.org/Services/Bogons/bogon-bn-agg.txt)
[bruteforceblocker](#bruteforceblocker)|[danger.rulez.sk](http://danger.rulez.sk/) IPs detected by [bruteforceblocker](http://danger.rulez.sk/index.php/bruteforceblocker/) (fail2ban alternative for SSH on OpenBSD). This is an automatically generated list from users reporting failed authentication attempts. An IP seems to be included if 3 or more users report it. Its retention pocily seems 30 days.|ipv4 hash:ip|1720 unique IPs|updated every 3 hours  from [this link](http://danger.rulez.sk/projects/bruteforceblocker/blist.php)
[ciarmy](#ciarmy)|[CIArmy.com](http://ciarmy.com/) IPs with poor Rogue Packet score that have not yet been identified as malicious by the community|ipv4 hash:ip|423 unique IPs|updated every 3 hours  from [this link](http://cinsscore.com/list/ci-badguys.txt)
[cleanmx_viruses](#cleanmx_viruses)|[Clean-MX.de](http://support.clean-mx.de/clean-mx/viruses.php) IPs with viruses|ipv4 hash:ip|172 unique IPs|updated every 12 hours  from [this link](http://support.clean-mx.de/clean-mx/xmlviruses.php?sort=id%20desc&response=alive)
[dm_tor](#dm_tor)|[dan.me.uk](https://www.dan.me.uk) dynamic list of TOR exit points|ipv4 hash:ip|6428 unique IPs|updated every 30 mins  from [this link](https://www.dan.me.uk/torlist/)
[dshield](#dshield)|[DShield.org](https://dshield.org/) top 20 attacking class C (/24) subnets over the last three days - **excellent list**|ipv4 hash:net|20 subnets, 5120 unique IPs|updated every 4 hours  from [this link](http://feeds.dshield.org/block.txt)
[et_block](#et_block)|[EmergingThreats.net](http://www.emergingthreats.net/) default blacklist (at the time of writing includes spamhaus DROP, dshield and abuse.ch trackers, which are available separately too - prefer to use the direct ipsets instead of this, they seem to lag a bit in updates)|ipv4 hash:net|999 subnets, 18343755 unique IPs|updated every 12 hours  from [this link](http://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt)
[et_botcc](#et_botcc)|[EmergingThreats.net Command and Control IPs](http://doc.emergingthreats.net/bin/view/Main/BotCC) These IPs are updates every 24 hours and should be considered VERY highly reliable indications that a host is communicating with a known and active Bot or Malware command and control server - (although they say this includes abuse.ch trackers, it does not - most probably it is the shadowserver.org C&C list)|ipv4 hash:ip|509 unique IPs|updated every 12 hours  from [this link](http://rules.emergingthreats.net/fwrules/emerging-PIX-CC.rules)
[et_compromised](#et_compromised)|[EmergingThreats.net compromised hosts](http://doc.emergingthreats.net/bin/view/Main/CompromisedHost) - (this seems to be based on bruteforceblocker)|ipv4 hash:ip|1718 unique IPs|updated every 12 hours  from [this link](http://rules.emergingthreats.net/blockrules/compromised-ips.txt)
et_dshield|[EmergingThreats.net](http://www.emergingthreats.net/) dshield blocklist|ipv4 hash:net|disabled|updated every 12 hours  from [this link](http://rules.emergingthreats.net/fwrules/emerging-PIX-DSHIELD.rules)
et_spamhaus|[EmergingThreats.net](http://www.emergingthreats.net/) spamhaus blocklist|ipv4 hash:net|disabled|updated every 12 hours  from [this link](http://rules.emergingthreats.net/fwrules/emerging-PIX-DROP.rules)
[et_tor](#et_tor)|[EmergingThreats.net](http://www.emergingthreats.net/) [list](http://doc.emergingthreats.net/bin/view/Main/TorRules) of TOR network IPs|ipv4 hash:ip|6340 unique IPs|updated every 12 hours  from [this link](http://rules.emergingthreats.net/blockrules/emerging-tor.rules)
[feodo](#feodo)|[Abuse.ch Feodo tracker](https://feodotracker.abuse.ch) trojan includes IPs which are being used by Feodo (also known as Cridex or Bugat) which commits ebanking fraud - **excellent list**|ipv4 hash:ip|104 unique IPs|updated every 30 mins  from [this link](https://feodotracker.abuse.ch/blocklist/?download=ipblocklist)
[firehol_anonymous](#firehol_anonymous)|**FireHOL Anonymous** - Known anonymizing IPs. (includes: firehol_proxies anonymous bm_tor dm_tor)|ipv4 hash:net|18443 subnets, 82465 unique IPs|updated every 1 min  from [this link]()
[firehol_level1](#firehol_level1)|**FireHOL Level 1** - Maximum protection without false positives. (includes: fullbogons dshield feodo palevo sslbl zeus spamhaus_drop spamhaus_edrop)|ipv4 hash:net|5146 subnets, 688981376 unique IPs|updated every 1 min  from [this link]()
[firehol_level2](#firehol_level2)|**FireHOL Level 2** - Maximum protection from attacks took place in the last 48 hours. (includes: openbl_1d blocklist_de stopforumspam_1d)|ipv4 hash:net|23830 subnets, 35462 unique IPs|updated every 1 min  from [this link]()
[firehol_level3](#firehol_level3)|**FireHOL Level 3** - All the bad IPs in last 30 days. (includes: openbl_30d stopforumspam_30d virbl malc0de shunlist malwaredomainlist bruteforceblocker ciarmy cleanmx_viruses snort_ipfilter ib_bluetack_spyware ib_bluetack_hijacked ib_bluetack_webexploit php_commenters php_dictionary php_harvesters php_spammers)|ipv4 hash:net|109927 subnets, 9627612 unique IPs|updated every 1 min  from [this link]()
[firehol_proxies](#firehol_proxies)|**FireHOL Proxies** - Known open proxies in the last 30 days. (includes: ib_bluetack_proxies maxmind_proxy_fraud proxyrss proxz ri_connect_proxies ri_web_proxies xroxy)|ipv4 hash:net|11996 subnets, 12233 unique IPs|updated every 1 min  from [this link]()
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
[nixspam](#nixspam)|[NiX Spam](http://www.heise.de/ix/NiX-Spam-DNSBL-and-blacklist-for-download-499637.html) IP addresses that sent spam in the last hour - automatically generated entries without distinguishing open proxies from relays, dialup gateways, and so on. All IPs are removed after 12 hours if there is no spam from there.|ipv4 hash:ip|18909 unique IPs|updated every 15 mins  from [this link](http://www.dnsbl.manitu.net/download/nixspam-ip.dump.gz)
openbl|[OpenBL.org](http://www.openbl.org/) default blacklist (currently it is the same with 90 days). OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications - **excellent list**|ipv4 hash:ip|disabled|updated every 4 hours  from [this link](http://www.openbl.org/lists/base.txt)
openbl_180d|[OpenBL.org](http://www.openbl.org/) last 180 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|disabled|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_180days.txt)
[openbl_1d](#openbl_1d)|[OpenBL.org](http://www.openbl.org/) last 24 hours IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|163 unique IPs|updated every 1 hour  from [this link](http://www.openbl.org/lists/base_1days.txt)
[openbl_30d](#openbl_30d)|[OpenBL.org](http://www.openbl.org/) last 30 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|2855 unique IPs|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_30days.txt)
openbl_360d|[OpenBL.org](http://www.openbl.org/) last 360 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|disabled|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_360days.txt)
[openbl_60d](#openbl_60d)|[OpenBL.org](http://www.openbl.org/) last 60 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|7022 unique IPs|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_60days.txt)
[openbl_7d](#openbl_7d)|[OpenBL.org](http://www.openbl.org/) last 7 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|692 unique IPs|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_7days.txt)
openbl_90d|[OpenBL.org](http://www.openbl.org/) last 90 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|disabled|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_90days.txt)
openbl_all|[OpenBL.org](http://www.openbl.org/) last all IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|disabled|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_all.txt)
[palevo](#palevo)|[Abuse.ch Palevo tracker](https://palevotracker.abuse.ch) worm includes IPs which are being used as botnet C&C for the Palevo crimeware - **excellent list**|ipv4 hash:ip|13 unique IPs|updated every 30 mins  from [this link](https://palevotracker.abuse.ch/blocklists.php?download=ipblocklist)
php_bad|[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) bad web hosts (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|disabled|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=b&rss=1)
[php_commenters](#php_commenters)|[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) comment spammers (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|403 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=c&rss=1)
[php_dictionary](#php_dictionary)|[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) directory attackers (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|666 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=d&rss=1)
[php_harvesters](#php_harvesters)|[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) harvesters (IPs that surf the internet looking for email addresses) (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|378 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=h&rss=1)
[php_spammers](#php_spammers)|[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) spam servers (IPs used by spammers to send messages) (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|661 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=s&rss=1)
[proxyrss](#proxyrss)|[proxyrss.com](http://www.proxyrss.com) open proxies syndicated from multiple sources.|ipv4 hash:ip|1536 unique IPs|updated every 4 hours  from [this link](http://www.proxyrss.com/proxylists/all.gz)
[proxz](#proxz)|[proxz.com](http://www.proxz.com) open proxies (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|1180 unique IPs|updated every 1 hour  from [this link](http://www.proxz.com/proxylists.xml)
[ri_connect_proxies](#ri_connect_proxies)|[rosinstrument.com](http://www.rosinstrument.com) open CONNECT proxies (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|2703 unique IPs|updated every 1 hour  from [this link](http://tools.rosinstrument.com/proxy/plab100.xml)
[ri_web_proxies](#ri_web_proxies)|[rosinstrument.com](http://www.rosinstrument.com) open HTTP proxies (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|7484 unique IPs|updated every 1 hour  from [this link](http://tools.rosinstrument.com/proxy/l100.xml)
[shunlist](#shunlist)|[AutoShun.org](http://autoshun.org/) IPs identified as hostile by correlating logs from distributed snort installations running the autoshun plugin|ipv4 hash:ip|1334 unique IPs|updated every 4 hours  from [this link](http://www.autoshun.org/files/shunlist.csv)
[snort_ipfilter](#snort_ipfilter)|[labs.snort.org](https://labs.snort.org/) supplied IP blacklist (this list seems to be updated frequently, but we found no information about it)|ipv4 hash:ip|10254 unique IPs|updated every 12 hours  from [this link](http://labs.snort.org/feeds/ip-filter.blf)
[spamhaus_drop](#spamhaus_drop)|[Spamhaus.org](http://www.spamhaus.org) DROP list (according to their site this list should be dropped at tier-1 ISPs globaly) - **excellent list**|ipv4 hash:net|653 subnets, 18340608 unique IPs|updated every 12 hours  from [this link](http://www.spamhaus.org/drop/drop.txt)
[spamhaus_edrop](#spamhaus_edrop)|[Spamhaus.org](http://www.spamhaus.org) EDROP (extended matches that should be used with DROP) - **excellent list**|ipv4 hash:net|56 subnets, 487424 unique IPs|updated every 12 hours  from [this link](http://www.spamhaus.org/drop/edrop.txt)
[sslbl](#sslbl)|[Abuse.ch SSL Blacklist](https://sslbl.abuse.ch/) bad SSL traffic related to malware or botnet activities - **excellent list**|ipv4 hash:ip|375 unique IPs|updated every 30 mins  from [this link](https://sslbl.abuse.ch/blacklist/sslipblacklist.csv)
stopforumspam_180d|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 180 days)|ipv4 hash:ip|disabled|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/listed_ip_180.zip)
[stopforumspam_1d](#stopforumspam_1d)|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers in the last 24 hours - **excellent list**|ipv4 hash:ip|6912 unique IPs|updated every 1 hour  from [this link](http://www.stopforumspam.com/downloads/listed_ip_1.zip)
[stopforumspam_30d](#stopforumspam_30d)|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 30 days)|ipv4 hash:ip|93938 unique IPs|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/listed_ip_30.zip)
stopforumspam_365d|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 365 days)|ipv4 hash:ip|disabled|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/listed_ip_365.zip)
[stopforumspam_7d](#stopforumspam_7d)|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 7 days)|ipv4 hash:ip|29338 unique IPs|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/listed_ip_7.zip)
stopforumspam_90d|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 90 days)|ipv4 hash:ip|disabled|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/listed_ip_90.zip)
stopforumspam_ever|[StopForumSpam.com](http://www.stopforumspam.com) all IPs used by forum spammers, **ever** (normally you don't want to use this ipset, use the hourly one which includes last 24 hours IPs or the 7 days one)|ipv4 hash:ip|disabled|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/bannedips.zip)
[virbl](#virbl)|[VirBL](http://virbl.bit.nl/) is a project of which the idea was born during the RIPE-48 meeting. The plan was to get reports of virusscanning mailservers, and put the IP-addresses that were reported to send viruses on a blacklist.|ipv4 hash:ip|26 unique IPs|updated every 1 hour  from [this link](http://virbl.bit.nl/download/virbl.dnsbl.bit.nl.txt)
[voipbl](#voipbl)|[VoIPBL.org](http://www.voipbl.org/) a distributed VoIP blacklist that is aimed to protects against VoIP Fraud and minimizing abuse for network that have publicly accessible PBX's. Several algorithms, external sources and manual confirmation are used before they categorize something as an attack and determine the threat level.|ipv4 hash:net|10522 subnets, 10934 unique IPs|updated every 4 hours  from [this link](http://www.voipbl.org/update/)
[xroxy](#xroxy)|[xroxy.com](http://www.xroxy.com) open proxies (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|2147 unique IPs|updated every 1 hour  from [this link](http://www.xroxy.com/proxyrss.xml)
[zeus](#zeus)|[Abuse.ch Zeus tracker](https://zeustracker.abuse.ch) standard, contains the same data as the ZeuS IP blocklist (zeus_badips) but with the slight difference that it doesn't exclude hijacked websites (level 2) and free web hosting providers (level 3). This means that this blocklist contains all IPv4 addresses associated with ZeuS C&Cs which are currently being tracked by ZeuS Tracker. Hence this blocklist will likely cause some false positives. - **excellent list**|ipv4 hash:ip|231 unique IPs|updated every 30 mins  from [this link](https://zeustracker.abuse.ch/blocklist.php?download=ipblocklist)
[zeus_badips](#zeus_badips)|[Abuse.ch Zeus tracker](https://zeustracker.abuse.ch) badips includes IPv4 addresses that are used by the ZeuS trojan. It is the recommened blocklist if you want to block only ZeuS IPs. It excludes IP addresses that ZeuS Tracker believes to be hijacked (level 2) or belong to a free web hosting provider (level 3). Hence the false postive rate should be much lower compared to the standard ZeuS IP blocklist. **excellent list**|ipv4 hash:ip|203 unique IPs|updated every 30 mins  from [this link](https://zeustracker.abuse.ch/blocklist.php?download=badips)

# Comparison of ipsets

Below we compare each ipset against all other.


## alienvault_reputation

[AlienVault.com](https://www.alienvault.com/) IP reputation database (this list seems to include port scanning hosts and to be updated regularly, but we found no information about its retention policy)

Source is downloaded from [this link](https://reputation.alienvault.com/reputation.generic).

The last time downloaded was found to be dated: Wed Jun 10 04:00:58 UTC 2015.

The ipset `alienvault_reputation` has **181943** entries, **181943** unique IPs.

The following table shows the overlaps of `alienvault_reputation` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `alienvault_reputation`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `alienvault_reputation`.
- ` this % ` is the percentage **of this ipset (`alienvault_reputation`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|13623|0.0%|7.4%|
[openbl_60d](#openbl_60d)|7022|7022|6999|99.6%|3.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|6261|0.0%|3.4%|
[et_block](#et_block)|999|18343755|6045|0.0%|3.3%|
[firehol_level3](#firehol_level3)|109927|9627612|5218|0.0%|2.8%|
[firehol_level1](#firehol_level1)|5146|688981376|4845|0.0%|2.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|4218|0.0%|2.3%|
[dshield](#dshield)|20|5120|3331|65.0%|1.8%|
[openbl_30d](#openbl_30d)|2855|2855|2838|99.4%|1.5%|
[firehol_level2](#firehol_level2)|23830|35462|1445|4.0%|0.7%|
[blocklist_de](#blocklist_de)|29889|29889|1379|4.6%|0.7%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|1373|0.0%|0.7%|
[shunlist](#shunlist)|1334|1334|1325|99.3%|0.7%|
[blocklist_de_ssh](#blocklist_de_ssh)|3241|3241|1145|35.3%|0.6%|
[bruteforceblocker](#bruteforceblocker)|1720|1720|1110|64.5%|0.6%|
[et_compromised](#et_compromised)|1718|1718|1109|64.5%|0.6%|
[openbl_7d](#openbl_7d)|692|692|687|99.2%|0.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|518|0.0%|0.2%|
[ciarmy](#ciarmy)|423|423|417|98.5%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|289|0.0%|0.1%|
[stopforumspam_30d](#stopforumspam_30d)|93938|93938|205|0.2%|0.1%|
[voipbl](#voipbl)|10522|10934|192|1.7%|0.1%|
[openbl_1d](#openbl_1d)|163|163|157|96.3%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14825|14825|132|0.8%|0.0%|
[snort_ipfilter](#snort_ipfilter)|10254|10254|116|1.1%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|103|0.3%|0.0%|
[sslbl](#sslbl)|375|375|66|17.6%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|18940|18940|63|0.3%|0.0%|
[zeus](#zeus)|231|231|62|26.8%|0.0%|
[firehol_anonymous](#firehol_anonymous)|18443|82465|56|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6912|6912|49|0.7%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2456|2456|41|1.6%|0.0%|
[dm_tor](#dm_tor)|6428|6428|40|0.6%|0.0%|
[bm_tor](#bm_tor)|6410|6410|40|0.6%|0.0%|
[et_tor](#et_tor)|6340|6340|39|0.6%|0.0%|
[zeus_badips](#zeus_badips)|203|203|38|18.7%|0.0%|
[nixspam](#nixspam)|18909|18909|35|0.1%|0.0%|
[firehol_proxies](#firehol_proxies)|11996|12233|35|0.2%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|174|174|35|20.1%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|26|6.9%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|80|80|21|26.2%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|3472|3472|20|0.5%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3015|3015|20|0.6%|0.0%|
[php_commenters](#php_commenters)|403|403|18|4.4%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|15|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|14|0.0%|0.0%|
[php_harvesters](#php_harvesters)|378|378|12|3.1%|0.0%|
[malc0de](#malc0de)|338|338|11|3.2%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|864|864|10|1.1%|0.0%|
[php_dictionary](#php_dictionary)|666|666|8|1.2%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|8|0.6%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|6|0.4%|0.0%|
[xroxy](#xroxy)|2147|2147|5|0.2%|0.0%|
[php_spammers](#php_spammers)|661|661|5|0.7%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7484|7484|4|0.0%|0.0%|
[et_botcc](#et_botcc)|509|509|4|0.7%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|172|172|4|2.3%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2703|2703|3|0.1%|0.0%|
[proxz](#proxz)|1180|1180|3|0.2%|0.0%|
[proxyrss](#proxyrss)|1536|1536|2|0.1%|0.0%|
[feodo](#feodo)|104|104|2|1.9%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|1|0.1%|0.0%|

## blocklist_de

[Blocklist.de](https://www.blocklist.de/) IPs that have been detected by fail2ban in the last 48 hours - **excellent list**

Source is downloaded from [this link](http://lists.blocklist.de/lists/all.txt).

The last time downloaded was found to be dated: Wed Jun 10 06:42:04 UTC 2015.

The ipset `blocklist_de` has **29889** entries, **29889** unique IPs.

The following table shows the overlaps of `blocklist_de` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de`.
- ` this % ` is the percentage **of this ipset (`blocklist_de`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|23830|35462|29889|84.2%|100.0%|
[blocklist_de_mail](#blocklist_de_mail)|18940|18940|18921|99.8%|63.3%|
[blocklist_de_apache](#blocklist_de_apache)|14825|14825|14825|100.0%|49.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|3872|0.0%|12.9%|
[firehol_level3](#firehol_level3)|109927|9627612|3855|0.0%|12.8%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|3472|3472|3472|100.0%|11.6%|
[blocklist_de_ssh](#blocklist_de_ssh)|3241|3241|3241|100.0%|10.8%|
[blocklist_de_bots](#blocklist_de_bots)|3015|3015|3015|100.0%|10.0%|
[stopforumspam_30d](#stopforumspam_30d)|93938|93938|2548|2.7%|8.5%|
[blocklist_de_imap](#blocklist_de_imap)|2456|2456|2446|99.5%|8.1%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|2279|7.7%|7.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|1593|0.0%|5.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|1535|0.0%|5.1%|
[alienvault_reputation](#alienvault_reputation)|181943|181943|1379|0.7%|4.6%|
[stopforumspam_1d](#stopforumspam_1d)|6912|6912|1375|19.8%|4.6%|
[openbl_60d](#openbl_60d)|7022|7022|1004|14.2%|3.3%|
[blocklist_de_ftp](#blocklist_de_ftp)|864|864|864|100.0%|2.8%|
[openbl_30d](#openbl_30d)|2855|2855|807|28.2%|2.6%|
[bruteforceblocker](#bruteforceblocker)|1720|1720|698|40.5%|2.3%|
[et_compromised](#et_compromised)|1718|1718|667|38.8%|2.2%|
[firehol_anonymous](#firehol_anonymous)|18443|82465|618|0.7%|2.0%|
[firehol_proxies](#firehol_proxies)|11996|12233|607|4.9%|2.0%|
[nixspam](#nixspam)|18909|18909|537|2.8%|1.7%|
[shunlist](#shunlist)|1334|1334|459|34.4%|1.5%|
[ri_web_proxies](#ri_web_proxies)|7484|7484|421|5.6%|1.4%|
[openbl_7d](#openbl_7d)|692|692|394|56.9%|1.3%|
[firehol_level1](#firehol_level1)|5146|688981376|234|0.0%|0.7%|
[proxyrss](#proxyrss)|1536|1536|218|14.1%|0.7%|
[snort_ipfilter](#snort_ipfilter)|10254|10254|215|2.0%|0.7%|
[et_block](#et_block)|999|18343755|211|0.0%|0.7%|
[xroxy](#xroxy)|2147|2147|202|9.4%|0.6%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|201|0.0%|0.6%|
[proxz](#proxz)|1180|1180|174|14.7%|0.5%|
[blocklist_de_strongips](#blocklist_de_strongips)|174|174|174|100.0%|0.5%|
[openbl_1d](#openbl_1d)|163|163|127|77.9%|0.4%|
[php_dictionary](#php_dictionary)|666|666|102|15.3%|0.3%|
[php_spammers](#php_spammers)|661|661|98|14.8%|0.3%|
[php_commenters](#php_commenters)|403|403|98|24.3%|0.3%|
[ri_connect_proxies](#ri_connect_proxies)|2703|2703|76|2.8%|0.2%|
[blocklist_de_sip](#blocklist_de_sip)|80|80|61|76.2%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|58|0.0%|0.1%|
[ciarmy](#ciarmy)|423|423|40|9.4%|0.1%|
[php_harvesters](#php_harvesters)|378|378|38|10.0%|0.1%|
[voipbl](#voipbl)|10522|10934|28|0.2%|0.0%|
[dshield](#dshield)|20|5120|25|0.4%|0.0%|
[et_tor](#et_tor)|6340|6340|10|0.1%|0.0%|
[dm_tor](#dm_tor)|6428|6428|10|0.1%|0.0%|
[bm_tor](#bm_tor)|6410|6410|10|0.1%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|8|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|7|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|6|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|4|0.6%|0.0%|
[zeus_badips](#zeus_badips)|203|203|1|0.4%|0.0%|
[zeus](#zeus)|231|231|1|0.4%|0.0%|
[sslbl](#sslbl)|375|375|1|0.2%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|1|0.0%|0.0%|

## blocklist_de_apache

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service Apache, Apache-DDOS, RFI-Attacks.

Source is downloaded from [this link](http://lists.blocklist.de/lists/apache.txt).

The last time downloaded was found to be dated: Wed Jun 10 06:42:07 UTC 2015.

The ipset `blocklist_de_apache` has **14825** entries, **14825** unique IPs.

The following table shows the overlaps of `blocklist_de_apache` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_apache`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_apache`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_apache`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|23830|35462|14825|41.8%|100.0%|
[blocklist_de](#blocklist_de)|29889|29889|14825|49.6%|100.0%|
[blocklist_de_mail](#blocklist_de_mail)|18940|18940|11059|58.3%|74.5%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|3472|3472|3472|100.0%|23.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|2343|0.0%|15.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|1333|0.0%|8.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|1105|0.0%|7.4%|
[firehol_level3](#firehol_level3)|109927|9627612|309|0.0%|2.0%|
[stopforumspam_30d](#stopforumspam_30d)|93938|93938|222|0.2%|1.4%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|137|0.4%|0.9%|
[alienvault_reputation](#alienvault_reputation)|181943|181943|132|0.0%|0.8%|
[stopforumspam_1d](#stopforumspam_1d)|6912|6912|75|1.0%|0.5%|
[shunlist](#shunlist)|1334|1334|35|2.6%|0.2%|
[ciarmy](#ciarmy)|423|423|35|8.2%|0.2%|
[blocklist_de_strongips](#blocklist_de_strongips)|174|174|32|18.3%|0.2%|
[php_commenters](#php_commenters)|403|403|31|7.6%|0.2%|
[snort_ipfilter](#snort_ipfilter)|10254|10254|28|0.2%|0.1%|
[blocklist_de_bots](#blocklist_de_bots)|3015|3015|22|0.7%|0.1%|
[nixspam](#nixspam)|18909|18909|17|0.0%|0.1%|
[firehol_anonymous](#firehol_anonymous)|18443|82465|15|0.0%|0.1%|
[firehol_level1](#firehol_level1)|5146|688981376|12|0.0%|0.0%|
[et_tor](#et_tor)|6340|6340|9|0.1%|0.0%|
[dm_tor](#dm_tor)|6428|6428|9|0.1%|0.0%|
[bm_tor](#bm_tor)|6410|6410|9|0.1%|0.0%|
[et_block](#et_block)|999|18343755|8|0.0%|0.0%|
[php_spammers](#php_spammers)|661|661|7|1.0%|0.0%|
[firehol_proxies](#firehol_proxies)|11996|12233|7|0.0%|0.0%|
[dshield](#dshield)|20|5120|7|0.1%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7484|7484|6|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|5|0.0%|0.0%|
[openbl_60d](#openbl_60d)|7022|7022|4|0.0%|0.0%|
[openbl_30d](#openbl_30d)|2855|2855|4|0.1%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|4|0.0%|0.0%|
[php_harvesters](#php_harvesters)|378|378|3|0.7%|0.0%|
[php_dictionary](#php_dictionary)|666|666|3|0.4%|0.0%|
[voipbl](#voipbl)|10522|10934|2|0.0%|0.0%|
[openbl_7d](#openbl_7d)|692|692|2|0.2%|0.0%|
[openbl_1d](#openbl_1d)|163|163|2|1.2%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|1|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2456|2456|1|0.0%|0.0%|

## blocklist_de_bots

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the RFI-Attacks, REG-Bots, IRC-Bots or BadBots (BadBots = he has posted a Spam-Comment on a open Forum or Wiki).

Source is downloaded from [this link](http://lists.blocklist.de/lists/bots.txt).

The last time downloaded was found to be dated: Wed Jun 10 06:42:11 UTC 2015.

The ipset `blocklist_de_bots` has **3015** entries, **3015** unique IPs.

The following table shows the overlaps of `blocklist_de_bots` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_bots`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_bots`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_bots`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|23830|35462|3015|8.5%|100.0%|
[blocklist_de](#blocklist_de)|29889|29889|3015|10.0%|100.0%|
[firehol_level3](#firehol_level3)|109927|9627612|2213|0.0%|73.3%|
[stopforumspam_30d](#stopforumspam_30d)|93938|93938|2176|2.3%|72.1%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|2066|7.0%|68.5%|
[stopforumspam_1d](#stopforumspam_1d)|6912|6912|1295|18.7%|42.9%|
[firehol_anonymous](#firehol_anonymous)|18443|82465|498|0.6%|16.5%|
[firehol_proxies](#firehol_proxies)|11996|12233|497|4.0%|16.4%|
[ri_web_proxies](#ri_web_proxies)|7484|7484|349|4.6%|11.5%|
[proxyrss](#proxyrss)|1536|1536|217|14.1%|7.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|182|0.0%|6.0%|
[xroxy](#xroxy)|2147|2147|147|6.8%|4.8%|
[proxz](#proxz)|1180|1180|144|12.2%|4.7%|
[blocklist_de_strongips](#blocklist_de_strongips)|174|174|129|74.1%|4.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|99|0.0%|3.2%|
[php_commenters](#php_commenters)|403|403|78|19.3%|2.5%|
[ri_connect_proxies](#ri_connect_proxies)|2703|2703|72|2.6%|2.3%|
[firehol_level1](#firehol_level1)|5146|688981376|60|0.0%|1.9%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|56|0.0%|1.8%|
[et_block](#et_block)|999|18343755|56|0.0%|1.8%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|51|0.0%|1.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|32|0.0%|1.0%|
[nixspam](#nixspam)|18909|18909|30|0.1%|0.9%|
[php_harvesters](#php_harvesters)|378|378|27|7.1%|0.8%|
[blocklist_de_mail](#blocklist_de_mail)|18940|18940|22|0.1%|0.7%|
[blocklist_de_apache](#blocklist_de_apache)|14825|14825|22|0.1%|0.7%|
[snort_ipfilter](#snort_ipfilter)|10254|10254|20|0.1%|0.6%|
[alienvault_reputation](#alienvault_reputation)|181943|181943|20|0.0%|0.6%|
[php_spammers](#php_spammers)|661|661|17|2.5%|0.5%|
[php_dictionary](#php_dictionary)|666|666|15|2.2%|0.4%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|5|0.0%|0.1%|
[openbl_60d](#openbl_60d)|7022|7022|5|0.0%|0.1%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|3|0.4%|0.0%|
[openbl_30d](#openbl_30d)|2855|2855|1|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|1|0.0%|0.0%|
[et_compromised](#et_compromised)|1718|1718|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1720|1720|1|0.0%|0.0%|

## blocklist_de_bruteforce

[Blocklist.de](https://www.blocklist.de/) All IPs which attacks Joomlas, Wordpress and other Web-Logins with Brute-Force Logins.

Source is downloaded from [this link](http://lists.blocklist.de/lists/bruteforcelogin.txt).

The last time downloaded was found to be dated: Wed Jun 10 06:42:12 UTC 2015.

The ipset `blocklist_de_bruteforce` has **3472** entries, **3472** unique IPs.

The following table shows the overlaps of `blocklist_de_bruteforce` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_bruteforce`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_bruteforce`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_bruteforce`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|23830|35462|3472|9.7%|100.0%|
[blocklist_de_apache](#blocklist_de_apache)|14825|14825|3472|23.4%|100.0%|
[blocklist_de](#blocklist_de)|29889|29889|3472|11.6%|100.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|252|0.0%|7.2%|
[firehol_level3](#firehol_level3)|109927|9627612|97|0.0%|2.7%|
[stopforumspam_30d](#stopforumspam_30d)|93938|93938|75|0.0%|2.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|69|0.0%|1.9%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|62|0.2%|1.7%|
[stopforumspam_1d](#stopforumspam_1d)|6912|6912|44|0.6%|1.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|42|0.0%|1.2%|
[snort_ipfilter](#snort_ipfilter)|10254|10254|24|0.2%|0.6%|
[alienvault_reputation](#alienvault_reputation)|181943|181943|20|0.0%|0.5%|
[nixspam](#nixspam)|18909|18909|16|0.0%|0.4%|
[firehol_anonymous](#firehol_anonymous)|18443|82465|13|0.0%|0.3%|
[php_commenters](#php_commenters)|403|403|10|2.4%|0.2%|
[et_tor](#et_tor)|6340|6340|8|0.1%|0.2%|
[php_spammers](#php_spammers)|661|661|7|1.0%|0.2%|
[dm_tor](#dm_tor)|6428|6428|7|0.1%|0.2%|
[bm_tor](#bm_tor)|6410|6410|7|0.1%|0.2%|
[blocklist_de_strongips](#blocklist_de_strongips)|174|174|7|4.0%|0.2%|
[ri_web_proxies](#ri_web_proxies)|7484|7484|6|0.0%|0.1%|
[firehol_proxies](#firehol_proxies)|11996|12233|6|0.0%|0.1%|
[firehol_level1](#firehol_level1)|5146|688981376|6|0.0%|0.1%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|5|0.0%|0.1%|
[et_block](#et_block)|999|18343755|5|0.0%|0.1%|
[php_dictionary](#php_dictionary)|666|666|3|0.4%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|3|0.0%|0.0%|
[php_harvesters](#php_harvesters)|378|378|2|0.5%|0.0%|
[voipbl](#voipbl)|10522|10934|1|0.0%|0.0%|
[shunlist](#shunlist)|1334|1334|1|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|1|0.0%|0.0%|
[dshield](#dshield)|20|5120|1|0.0%|0.0%|

## blocklist_de_ftp

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours for attacks on the Service FTP.

Source is downloaded from [this link](http://lists.blocklist.de/lists/ftp.txt).

The last time downloaded was found to be dated: Wed Jun 10 06:42:08 UTC 2015.

The ipset `blocklist_de_ftp` has **864** entries, **864** unique IPs.

The following table shows the overlaps of `blocklist_de_ftp` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_ftp`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_ftp`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_ftp`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|23830|35462|864|2.4%|100.0%|
[blocklist_de](#blocklist_de)|29889|29889|864|2.8%|100.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|115|0.0%|13.3%|
[firehol_level3](#firehol_level3)|109927|9627612|18|0.0%|2.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|15|0.0%|1.7%|
[stopforumspam_30d](#stopforumspam_30d)|93938|93938|12|0.0%|1.3%|
[alienvault_reputation](#alienvault_reputation)|181943|181943|10|0.0%|1.1%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|8|0.0%|0.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|7|0.0%|0.8%|
[stopforumspam_1d](#stopforumspam_1d)|6912|6912|4|0.0%|0.4%|
[nixspam](#nixspam)|18909|18909|4|0.0%|0.4%|
[php_harvesters](#php_harvesters)|378|378|3|0.7%|0.3%|
[ciarmy](#ciarmy)|423|423|2|0.4%|0.2%|
[blocklist_de_strongips](#blocklist_de_strongips)|174|174|2|1.1%|0.2%|
[openbl_7d](#openbl_7d)|692|692|1|0.1%|0.1%|
[openbl_60d](#openbl_60d)|7022|7022|1|0.0%|0.1%|
[openbl_30d](#openbl_30d)|2855|2855|1|0.0%|0.1%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|1|0.0%|0.1%|
[firehol_anonymous](#firehol_anonymous)|18443|82465|1|0.0%|0.1%|

## blocklist_de_imap

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours for attacks on the Service imap, sasl, pop3, etc.

Source is downloaded from [this link](http://lists.blocklist.de/lists/imap.txt).

The last time downloaded was found to be dated: Wed Jun 10 06:58:07 UTC 2015.

The ipset `blocklist_de_imap` has **2456** entries, **2456** unique IPs.

The following table shows the overlaps of `blocklist_de_imap` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_imap`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_imap`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_imap`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de_mail](#blocklist_de_mail)|18940|18940|2456|12.9%|100.0%|
[firehol_level2](#firehol_level2)|23830|35462|2446|6.8%|99.5%|
[blocklist_de](#blocklist_de)|29889|29889|2446|8.1%|99.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|310|0.0%|12.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|54|0.0%|2.1%|
[firehol_level3](#firehol_level3)|109927|9627612|45|0.0%|1.8%|
[alienvault_reputation](#alienvault_reputation)|181943|181943|41|0.0%|1.6%|
[openbl_60d](#openbl_60d)|7022|7022|29|0.4%|1.1%|
[openbl_30d](#openbl_30d)|2855|2855|24|0.8%|0.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|24|0.0%|0.9%|
[nixspam](#nixspam)|18909|18909|16|0.0%|0.6%|
[stopforumspam_30d](#stopforumspam_30d)|93938|93938|11|0.0%|0.4%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|11|0.0%|0.4%|
[firehol_level1](#firehol_level1)|5146|688981376|11|0.0%|0.4%|
[et_block](#et_block)|999|18343755|11|0.0%|0.4%|
[openbl_7d](#openbl_7d)|692|692|8|1.1%|0.3%|
[snort_ipfilter](#snort_ipfilter)|10254|10254|7|0.0%|0.2%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|3|0.0%|0.1%|
[et_compromised](#et_compromised)|1718|1718|3|0.1%|0.1%|
[bruteforceblocker](#bruteforceblocker)|1720|1720|3|0.1%|0.1%|
[shunlist](#shunlist)|1334|1334|2|0.1%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2703|2703|2|0.0%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2|0.0%|0.0%|
[firehol_proxies](#firehol_proxies)|11996|12233|2|0.0%|0.0%|
[firehol_anonymous](#firehol_anonymous)|18443|82465|2|0.0%|0.0%|
[xroxy](#xroxy)|2147|2147|1|0.0%|0.0%|
[php_harvesters](#php_harvesters)|378|378|1|0.2%|0.0%|
[php_commenters](#php_commenters)|403|403|1|0.2%|0.0%|
[openbl_1d](#openbl_1d)|163|163|1|0.6%|0.0%|
[ciarmy](#ciarmy)|423|423|1|0.2%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14825|14825|1|0.0%|0.0%|

## blocklist_de_mail

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service Mail, Postfix.

Source is downloaded from [this link](http://lists.blocklist.de/lists/mail.txt).

The last time downloaded was found to be dated: Wed Jun 10 06:58:05 UTC 2015.

The ipset `blocklist_de_mail` has **18940** entries, **18940** unique IPs.

The following table shows the overlaps of `blocklist_de_mail` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_mail`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_mail`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_mail`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|23830|35462|18921|53.3%|99.8%|
[blocklist_de](#blocklist_de)|29889|29889|18921|63.3%|99.8%|
[blocklist_de_apache](#blocklist_de_apache)|14825|14825|11059|74.5%|58.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|2817|0.0%|14.8%|
[blocklist_de_imap](#blocklist_de_imap)|2456|2456|2456|100.0%|12.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|1389|0.0%|7.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|1257|0.0%|6.6%|
[nixspam](#nixspam)|18909|18909|486|2.5%|2.5%|
[firehol_level3](#firehol_level3)|109927|9627612|425|0.0%|2.2%|
[stopforumspam_30d](#stopforumspam_30d)|93938|93938|267|0.2%|1.4%|
[snort_ipfilter](#snort_ipfilter)|10254|10254|167|1.6%|0.8%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|147|0.5%|0.7%|
[firehol_anonymous](#firehol_anonymous)|18443|82465|104|0.1%|0.5%|
[firehol_proxies](#firehol_proxies)|11996|12233|103|0.8%|0.5%|
[php_dictionary](#php_dictionary)|666|666|83|12.4%|0.4%|
[php_spammers](#php_spammers)|661|661|73|11.0%|0.3%|
[ri_web_proxies](#ri_web_proxies)|7484|7484|65|0.8%|0.3%|
[alienvault_reputation](#alienvault_reputation)|181943|181943|63|0.0%|0.3%|
[xroxy](#xroxy)|2147|2147|55|2.5%|0.2%|
[stopforumspam_1d](#stopforumspam_1d)|6912|6912|44|0.6%|0.2%|
[openbl_60d](#openbl_60d)|7022|7022|37|0.5%|0.1%|
[openbl_30d](#openbl_30d)|2855|2855|31|1.0%|0.1%|
[proxz](#proxz)|1180|1180|30|2.5%|0.1%|
[php_commenters](#php_commenters)|403|403|26|6.4%|0.1%|
[firehol_level1](#firehol_level1)|5146|688981376|23|0.0%|0.1%|
[blocklist_de_strongips](#blocklist_de_strongips)|174|174|23|13.2%|0.1%|
[et_block](#et_block)|999|18343755|22|0.0%|0.1%|
[blocklist_de_bots](#blocklist_de_bots)|3015|3015|22|0.7%|0.1%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|21|0.0%|0.1%|
[openbl_7d](#openbl_7d)|692|692|8|1.1%|0.0%|
[php_harvesters](#php_harvesters)|378|378|6|1.5%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2703|2703|4|0.1%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|4|0.0%|0.0%|
[shunlist](#shunlist)|1334|1334|3|0.2%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|0.0%|
[et_compromised](#et_compromised)|1718|1718|3|0.1%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1720|1720|3|0.1%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|2|0.0%|0.0%|
[dm_tor](#dm_tor)|6428|6428|2|0.0%|0.0%|
[bm_tor](#bm_tor)|6410|6410|2|0.0%|0.0%|
[zeus_badips](#zeus_badips)|203|203|1|0.4%|0.0%|
[zeus](#zeus)|231|231|1|0.4%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|1|0.0%|0.0%|
[proxyrss](#proxyrss)|1536|1536|1|0.0%|0.0%|
[openbl_1d](#openbl_1d)|163|163|1|0.6%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|1|0.1%|0.0%|
[et_tor](#et_tor)|6340|6340|1|0.0%|0.0%|
[ciarmy](#ciarmy)|423|423|1|0.2%|0.0%|

## blocklist_de_sip

[Blocklist.de](https://www.blocklist.de/) All IP addresses that tried to login in a SIP, VOIP or Asterisk Server and are included in the IPs list from [infiltrated.net](www.infiltrated.net)

Source is downloaded from [this link](http://lists.blocklist.de/lists/sip.txt).

The last time downloaded was found to be dated: Wed Jun 10 06:42:08 UTC 2015.

The ipset `blocklist_de_sip` has **80** entries, **80** unique IPs.

The following table shows the overlaps of `blocklist_de_sip` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_sip`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_sip`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_sip`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|23830|35462|61|0.1%|76.2%|
[blocklist_de](#blocklist_de)|29889|29889|61|0.2%|76.2%|
[voipbl](#voipbl)|10522|10934|24|0.2%|30.0%|
[alienvault_reputation](#alienvault_reputation)|181943|181943|21|0.0%|26.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|13|0.0%|16.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|6|0.0%|7.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|6|0.0%|7.5%|
[firehol_level3](#firehol_level3)|109927|9627612|4|0.0%|5.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|2|0.0%|2.5%|
[shunlist](#shunlist)|1334|1334|2|0.1%|2.5%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|2|0.0%|2.5%|
[firehol_level1](#firehol_level1)|5146|688981376|2|0.0%|2.5%|
[et_block](#et_block)|999|18343755|2|0.0%|2.5%|
[et_botcc](#et_botcc)|509|509|1|0.1%|1.2%|

## blocklist_de_ssh

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service SSH.

Source is downloaded from [this link](http://lists.blocklist.de/lists/ssh.txt).

The last time downloaded was found to be dated: Wed Jun 10 06:42:04 UTC 2015.

The ipset `blocklist_de_ssh` has **3241** entries, **3241** unique IPs.

The following table shows the overlaps of `blocklist_de_ssh` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_ssh`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_ssh`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_ssh`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|23830|35462|3241|9.1%|100.0%|
[blocklist_de](#blocklist_de)|29889|29889|3241|10.8%|100.0%|
[alienvault_reputation](#alienvault_reputation)|181943|181943|1145|0.6%|35.3%|
[firehol_level3](#firehol_level3)|109927|9627612|1039|0.0%|32.0%|
[openbl_60d](#openbl_60d)|7022|7022|957|13.6%|29.5%|
[openbl_30d](#openbl_30d)|2855|2855|770|26.9%|23.7%|
[bruteforceblocker](#bruteforceblocker)|1720|1720|694|40.3%|21.4%|
[et_compromised](#et_compromised)|1718|1718|663|38.5%|20.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|478|0.0%|14.7%|
[shunlist](#shunlist)|1334|1334|419|31.4%|12.9%|
[openbl_7d](#openbl_7d)|692|692|383|55.3%|11.8%|
[firehol_level1](#firehol_level1)|5146|688981376|137|0.0%|4.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|136|0.0%|4.1%|
[openbl_1d](#openbl_1d)|163|163|124|76.0%|3.8%|
[et_block](#et_block)|999|18343755|123|0.0%|3.7%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|117|0.0%|3.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|50|0.0%|1.5%|
[blocklist_de_strongips](#blocklist_de_strongips)|174|174|30|17.2%|0.9%|
[stopforumspam_30d](#stopforumspam_30d)|93938|93938|22|0.0%|0.6%|
[dshield](#dshield)|20|5120|18|0.3%|0.5%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|6|0.0%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|4|0.0%|0.1%|
[voipbl](#voipbl)|10522|10934|2|0.0%|0.0%|
[nixspam](#nixspam)|18909|18909|2|0.0%|0.0%|
[ciarmy](#ciarmy)|423|423|2|0.4%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6912|6912|1|0.0%|0.0%|
[sslbl](#sslbl)|375|375|1|0.2%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|1|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|10254|10254|1|0.0%|0.0%|
[php_spammers](#php_spammers)|661|661|1|0.1%|0.0%|
[php_commenters](#php_commenters)|403|403|1|0.2%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|1|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|1|0.0%|0.0%|
[firehol_anonymous](#firehol_anonymous)|18443|82465|1|0.0%|0.0%|
[et_tor](#et_tor)|6340|6340|1|0.0%|0.0%|
[dm_tor](#dm_tor)|6428|6428|1|0.0%|0.0%|
[bm_tor](#bm_tor)|6410|6410|1|0.0%|0.0%|

## blocklist_de_strongips

[Blocklist.de](https://www.blocklist.de/) All IPs which are older then 2 month and have more then 5.000 attacks.

Source is downloaded from [this link](http://lists.blocklist.de/lists/strongips.txt).

The last time downloaded was found to be dated: Wed Jun 10 06:42:11 UTC 2015.

The ipset `blocklist_de_strongips` has **174** entries, **174** unique IPs.

The following table shows the overlaps of `blocklist_de_strongips` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_strongips`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_strongips`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_strongips`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|23830|35462|174|0.4%|100.0%|
[blocklist_de](#blocklist_de)|29889|29889|174|0.5%|100.0%|
[firehol_level3](#firehol_level3)|109927|9627612|155|0.0%|89.0%|
[stopforumspam_30d](#stopforumspam_30d)|93938|93938|129|0.1%|74.1%|
[blocklist_de_bots](#blocklist_de_bots)|3015|3015|129|4.2%|74.1%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|116|0.3%|66.6%|
[stopforumspam_1d](#stopforumspam_1d)|6912|6912|108|1.5%|62.0%|
[php_commenters](#php_commenters)|403|403|45|11.1%|25.8%|
[alienvault_reputation](#alienvault_reputation)|181943|181943|35|0.0%|20.1%|
[blocklist_de_apache](#blocklist_de_apache)|14825|14825|32|0.2%|18.3%|
[blocklist_de_ssh](#blocklist_de_ssh)|3241|3241|30|0.9%|17.2%|
[openbl_60d](#openbl_60d)|7022|7022|25|0.3%|14.3%|
[openbl_7d](#openbl_7d)|692|692|24|3.4%|13.7%|
[openbl_30d](#openbl_30d)|2855|2855|24|0.8%|13.7%|
[blocklist_de_mail](#blocklist_de_mail)|18940|18940|23|0.1%|13.2%|
[openbl_1d](#openbl_1d)|163|163|21|12.8%|12.0%|
[shunlist](#shunlist)|1334|1334|20|1.4%|11.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|16|0.0%|9.1%|
[firehol_level1](#firehol_level1)|5146|688981376|12|0.0%|6.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|8|0.0%|4.5%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|7|0.0%|4.0%|
[php_spammers](#php_spammers)|661|661|7|1.0%|4.0%|
[firehol_proxies](#firehol_proxies)|11996|12233|7|0.0%|4.0%|
[firehol_anonymous](#firehol_anonymous)|18443|82465|7|0.0%|4.0%|
[et_block](#et_block)|999|18343755|7|0.0%|4.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|3472|3472|7|0.2%|4.0%|
[xroxy](#xroxy)|2147|2147|6|0.2%|3.4%|
[ri_web_proxies](#ri_web_proxies)|7484|7484|6|0.0%|3.4%|
[proxyrss](#proxyrss)|1536|1536|6|0.3%|3.4%|
[proxz](#proxz)|1180|1180|5|0.4%|2.8%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|4|0.0%|2.2%|
[php_dictionary](#php_dictionary)|666|666|4|0.6%|2.2%|
[nixspam](#nixspam)|18909|18909|3|0.0%|1.7%|
[snort_ipfilter](#snort_ipfilter)|10254|10254|2|0.0%|1.1%|
[php_harvesters](#php_harvesters)|378|378|2|0.5%|1.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2|0.0%|1.1%|
[dshield](#dshield)|20|5120|2|0.0%|1.1%|
[blocklist_de_ftp](#blocklist_de_ftp)|864|864|2|0.2%|1.1%|

## bm_tor

[torstatus.blutmagie.de](https://torstatus.blutmagie.de) list of all TOR network servers

Source is downloaded from [this link](https://torstatus.blutmagie.de/ip_list_all.php/Tor_ip_list_ALL.csv).

The last time downloaded was found to be dated: Wed Jun 10 06:45:03 UTC 2015.

The ipset `bm_tor` has **6410** entries, **6410** unique IPs.

The following table shows the overlaps of `bm_tor` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `bm_tor`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `bm_tor`.
- ` this % ` is the percentage **of this ipset (`bm_tor`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_anonymous](#firehol_anonymous)|18443|82465|6410|7.7%|100.0%|
[dm_tor](#dm_tor)|6428|6428|6341|98.6%|98.9%|
[et_tor](#et_tor)|6340|6340|5701|89.9%|88.9%|
[firehol_level3](#firehol_level3)|109927|9627612|1106|0.0%|17.2%|
[snort_ipfilter](#snort_ipfilter)|10254|10254|1068|10.4%|16.6%|
[stopforumspam_30d](#stopforumspam_30d)|93938|93938|637|0.6%|9.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|626|0.0%|9.7%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|528|1.7%|8.2%|
[firehol_level2](#firehol_level2)|23830|35462|353|0.9%|5.5%|
[stopforumspam_1d](#stopforumspam_1d)|6912|6912|349|5.0%|5.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|183|0.0%|2.8%|
[firehol_proxies](#firehol_proxies)|11996|12233|167|1.3%|2.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|164|0.0%|2.5%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|163|43.8%|2.5%|
[php_commenters](#php_commenters)|403|403|48|11.9%|0.7%|
[alienvault_reputation](#alienvault_reputation)|181943|181943|40|0.0%|0.6%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|22|0.0%|0.3%|
[openbl_60d](#openbl_60d)|7022|7022|20|0.2%|0.3%|
[blocklist_de](#blocklist_de)|29889|29889|10|0.0%|0.1%|
[blocklist_de_apache](#blocklist_de_apache)|14825|14825|9|0.0%|0.1%|
[php_harvesters](#php_harvesters)|378|378|7|1.8%|0.1%|
[et_block](#et_block)|999|18343755|7|0.0%|0.1%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|3472|3472|7|0.2%|0.1%|
[nixspam](#nixspam)|18909|18909|5|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7484|7484|4|0.0%|0.0%|
[php_spammers](#php_spammers)|661|661|4|0.6%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|4|0.0%|0.0%|
[voipbl](#voipbl)|10522|10934|3|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|3|0.0%|0.0%|
[php_dictionary](#php_dictionary)|666|666|3|0.4%|0.0%|
[firehol_level1](#firehol_level1)|5146|688981376|3|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|18940|18940|2|0.0%|0.0%|
[xroxy](#xroxy)|2147|2147|1|0.0%|0.0%|
[shunlist](#shunlist)|1334|1334|1|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3241|3241|1|0.0%|0.0%|

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
[firehol_level1](#firehol_level1)|5146|688981376|592708608|86.0%|100.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|4194304|3.0%|0.7%|
[voipbl](#voipbl)|10522|10934|319|2.9%|0.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|5|0.0%|0.0%|
[firehol_level3](#firehol_level3)|109927|9627612|5|0.0%|0.0%|
[php_harvesters](#php_harvesters)|378|378|1|0.2%|0.0%|
[php_commenters](#php_commenters)|403|403|1|0.2%|0.0%|
[nixspam](#nixspam)|18909|18909|1|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|172|172|1|0.5%|0.0%|
[ciarmy](#ciarmy)|423|423|1|0.2%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1720|1720|1|0.0%|0.0%|

## bruteforceblocker

[danger.rulez.sk](http://danger.rulez.sk/) IPs detected by [bruteforceblocker](http://danger.rulez.sk/index.php/bruteforceblocker/) (fail2ban alternative for SSH on OpenBSD). This is an automatically generated list from users reporting failed authentication attempts. An IP seems to be included if 3 or more users report it. Its retention pocily seems 30 days.

Source is downloaded from [this link](http://danger.rulez.sk/projects/bruteforceblocker/blist.php).

The last time downloaded was found to be dated: Wed Jun 10 06:54:23 UTC 2015.

The ipset `bruteforceblocker` has **1720** entries, **1720** unique IPs.

The following table shows the overlaps of `bruteforceblocker` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `bruteforceblocker`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `bruteforceblocker`.
- ` this % ` is the percentage **of this ipset (`bruteforceblocker`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level3](#firehol_level3)|109927|9627612|1720|0.0%|100.0%|
[et_compromised](#et_compromised)|1718|1718|1661|96.6%|96.5%|
[alienvault_reputation](#alienvault_reputation)|181943|181943|1110|0.6%|64.5%|
[openbl_60d](#openbl_60d)|7022|7022|1002|14.2%|58.2%|
[openbl_30d](#openbl_30d)|2855|2855|941|32.9%|54.7%|
[firehol_level2](#firehol_level2)|23830|35462|700|1.9%|40.6%|
[blocklist_de](#blocklist_de)|29889|29889|698|2.3%|40.5%|
[blocklist_de_ssh](#blocklist_de_ssh)|3241|3241|694|21.4%|40.3%|
[shunlist](#shunlist)|1334|1334|450|33.7%|26.1%|
[openbl_7d](#openbl_7d)|692|692|323|46.6%|18.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|152|0.0%|8.8%|
[firehol_level1](#firehol_level1)|5146|688981376|104|0.0%|6.0%|
[et_block](#et_block)|999|18343755|98|0.0%|5.6%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|95|0.0%|5.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|86|0.0%|5.0%|
[openbl_1d](#openbl_1d)|163|163|67|41.1%|3.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|52|0.0%|3.0%|
[stopforumspam_30d](#stopforumspam_30d)|93938|93938|13|0.0%|0.7%|
[dshield](#dshield)|20|5120|8|0.1%|0.4%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|5|0.0%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|5|0.0%|0.2%|
[voipbl](#voipbl)|10522|10934|3|0.0%|0.1%|
[firehol_proxies](#firehol_proxies)|11996|12233|3|0.0%|0.1%|
[firehol_anonymous](#firehol_anonymous)|18443|82465|3|0.0%|0.1%|
[blocklist_de_mail](#blocklist_de_mail)|18940|18940|3|0.0%|0.1%|
[blocklist_de_imap](#blocklist_de_imap)|2456|2456|3|0.1%|0.1%|
[proxz](#proxz)|1180|1180|2|0.1%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|2|0.0%|0.1%|
[ciarmy](#ciarmy)|423|423|2|0.4%|0.1%|
[xroxy](#xroxy)|2147|2147|1|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6912|6912|1|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|10254|10254|1|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7484|7484|1|0.0%|0.0%|
[proxyrss](#proxyrss)|1536|1536|1|0.0%|0.0%|
[php_spammers](#php_spammers)|661|661|1|0.1%|0.0%|
[php_commenters](#php_commenters)|403|403|1|0.2%|0.0%|
[fullbogons](#fullbogons)|3778|670299624|1|0.0%|0.0%|
[bogons](#bogons)|13|592708608|1|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3015|3015|1|0.0%|0.0%|

## ciarmy

[CIArmy.com](http://ciarmy.com/) IPs with poor Rogue Packet score that have not yet been identified as malicious by the community

Source is downloaded from [this link](http://cinsscore.com/list/ci-badguys.txt).

The last time downloaded was found to be dated: Wed Jun 10 04:15:14 UTC 2015.

The ipset `ciarmy` has **423** entries, **423** unique IPs.

The following table shows the overlaps of `ciarmy` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ciarmy`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ciarmy`.
- ` this % ` is the percentage **of this ipset (`ciarmy`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level3](#firehol_level3)|109927|9627612|423|0.0%|100.0%|
[alienvault_reputation](#alienvault_reputation)|181943|181943|417|0.2%|98.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|94|0.0%|22.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|47|0.0%|11.1%|
[firehol_level2](#firehol_level2)|23830|35462|41|0.1%|9.6%|
[blocklist_de](#blocklist_de)|29889|29889|40|0.1%|9.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|36|0.0%|8.5%|
[blocklist_de_apache](#blocklist_de_apache)|14825|14825|35|0.2%|8.2%|
[shunlist](#shunlist)|1334|1334|27|2.0%|6.3%|
[firehol_level1](#firehol_level1)|5146|688981376|6|0.0%|1.4%|
[dshield](#dshield)|20|5120|5|0.0%|1.1%|
[et_block](#et_block)|999|18343755|4|0.0%|0.9%|
[stopforumspam_30d](#stopforumspam_30d)|93938|93938|2|0.0%|0.4%|
[openbl_7d](#openbl_7d)|692|692|2|0.2%|0.4%|
[openbl_60d](#openbl_60d)|7022|7022|2|0.0%|0.4%|
[openbl_30d](#openbl_30d)|2855|2855|2|0.0%|0.4%|
[bruteforceblocker](#bruteforceblocker)|1720|1720|2|0.1%|0.4%|
[blocklist_de_ssh](#blocklist_de_ssh)|3241|3241|2|0.0%|0.4%|
[blocklist_de_ftp](#blocklist_de_ftp)|864|864|2|0.2%|0.4%|
[voipbl](#voipbl)|10522|10934|1|0.0%|0.2%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|1|0.0%|0.2%|
[openbl_1d](#openbl_1d)|163|163|1|0.6%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.2%|
[fullbogons](#fullbogons)|3778|670299624|1|0.0%|0.2%|
[et_compromised](#et_compromised)|1718|1718|1|0.0%|0.2%|
[bogons](#bogons)|13|592708608|1|0.0%|0.2%|
[blocklist_de_mail](#blocklist_de_mail)|18940|18940|1|0.0%|0.2%|
[blocklist_de_imap](#blocklist_de_imap)|2456|2456|1|0.0%|0.2%|

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
[firehol_level3](#firehol_level3)|109927|9627612|172|0.0%|100.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|22|0.0%|12.7%|
[malc0de](#malc0de)|338|338|20|5.9%|11.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|4|0.0%|2.3%|
[alienvault_reputation](#alienvault_reputation)|181943|181943|4|0.0%|2.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|3|0.0%|1.7%|
[firehol_level1](#firehol_level1)|5146|688981376|2|0.0%|1.1%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|1|0.0%|0.5%|
[snort_ipfilter](#snort_ipfilter)|10254|10254|1|0.0%|0.5%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|1|0.0%|0.5%|
[fullbogons](#fullbogons)|3778|670299624|1|0.0%|0.5%|
[bogons](#bogons)|13|592708608|1|0.0%|0.5%|

## dm_tor

[dan.me.uk](https://www.dan.me.uk) dynamic list of TOR exit points

Source is downloaded from [this link](https://www.dan.me.uk/torlist/).

The last time downloaded was found to be dated: Wed Jun 10 07:00:07 UTC 2015.

The ipset `dm_tor` has **6428** entries, **6428** unique IPs.

The following table shows the overlaps of `dm_tor` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `dm_tor`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `dm_tor`.
- ` this % ` is the percentage **of this ipset (`dm_tor`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_anonymous](#firehol_anonymous)|18443|82465|6428|7.7%|100.0%|
[bm_tor](#bm_tor)|6410|6410|6341|98.9%|98.6%|
[et_tor](#et_tor)|6340|6340|5686|89.6%|88.4%|
[firehol_level3](#firehol_level3)|109927|9627612|1099|0.0%|17.0%|
[snort_ipfilter](#snort_ipfilter)|10254|10254|1061|10.3%|16.5%|
[stopforumspam_30d](#stopforumspam_30d)|93938|93938|634|0.6%|9.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|622|0.0%|9.6%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|525|1.7%|8.1%|
[firehol_level2](#firehol_level2)|23830|35462|352|0.9%|5.4%|
[stopforumspam_1d](#stopforumspam_1d)|6912|6912|348|5.0%|5.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|183|0.0%|2.8%|
[firehol_proxies](#firehol_proxies)|11996|12233|166|1.3%|2.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|164|0.0%|2.5%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|162|43.5%|2.5%|
[php_commenters](#php_commenters)|403|403|48|11.9%|0.7%|
[alienvault_reputation](#alienvault_reputation)|181943|181943|40|0.0%|0.6%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|22|0.0%|0.3%|
[openbl_60d](#openbl_60d)|7022|7022|20|0.2%|0.3%|
[blocklist_de](#blocklist_de)|29889|29889|10|0.0%|0.1%|
[blocklist_de_apache](#blocklist_de_apache)|14825|14825|9|0.0%|0.1%|
[php_harvesters](#php_harvesters)|378|378|7|1.8%|0.1%|
[et_block](#et_block)|999|18343755|7|0.0%|0.1%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|3472|3472|7|0.2%|0.1%|
[nixspam](#nixspam)|18909|18909|6|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7484|7484|4|0.0%|0.0%|
[php_spammers](#php_spammers)|661|661|4|0.6%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|4|0.0%|0.0%|
[firehol_level1](#firehol_level1)|5146|688981376|4|0.0%|0.0%|
[voipbl](#voipbl)|10522|10934|3|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|3|0.0%|0.0%|
[php_dictionary](#php_dictionary)|666|666|3|0.4%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|18940|18940|2|0.0%|0.0%|
[xroxy](#xroxy)|2147|2147|1|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|1|0.0%|0.0%|
[shunlist](#shunlist)|1334|1334|1|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3241|3241|1|0.0%|0.0%|

## dshield

[DShield.org](https://dshield.org/) top 20 attacking class C (/24) subnets over the last three days - **excellent list**

Source is downloaded from [this link](http://feeds.dshield.org/block.txt).

The last time downloaded was found to be dated: Wed Jun 10 03:56:53 UTC 2015.

The ipset `dshield` has **20** entries, **5120** unique IPs.

The following table shows the overlaps of `dshield` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `dshield`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `dshield`.
- ` this % ` is the percentage **of this ipset (`dshield`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level1](#firehol_level1)|5146|688981376|5120|0.0%|100.0%|
[alienvault_reputation](#alienvault_reputation)|181943|181943|3331|1.8%|65.0%|
[et_block](#et_block)|999|18343755|1024|0.0%|20.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|273|0.0%|5.3%|
[openbl_60d](#openbl_60d)|7022|7022|65|0.9%|1.2%|
[firehol_level3](#firehol_level3)|109927|9627612|59|0.0%|1.1%|
[openbl_30d](#openbl_30d)|2855|2855|42|1.4%|0.8%|
[firehol_level2](#firehol_level2)|23830|35462|26|0.0%|0.5%|
[shunlist](#shunlist)|1334|1334|25|1.8%|0.4%|
[blocklist_de](#blocklist_de)|29889|29889|25|0.0%|0.4%|
[blocklist_de_ssh](#blocklist_de_ssh)|3241|3241|18|0.5%|0.3%|
[openbl_7d](#openbl_7d)|692|692|9|1.3%|0.1%|
[et_compromised](#et_compromised)|1718|1718|8|0.4%|0.1%|
[bruteforceblocker](#bruteforceblocker)|1720|1720|8|0.4%|0.1%|
[blocklist_de_apache](#blocklist_de_apache)|14825|14825|7|0.0%|0.1%|
[ciarmy](#ciarmy)|423|423|5|1.1%|0.0%|
[openbl_1d](#openbl_1d)|163|163|4|2.4%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|93938|93938|3|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|174|174|2|1.1%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|1|0.0%|0.0%|
[malc0de](#malc0de)|338|338|1|0.2%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|3472|3472|1|0.0%|0.0%|

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
[firehol_level1](#firehol_level1)|5146|688981376|18339910|2.6%|99.9%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|18338560|99.9%|99.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|8532519|2.4%|46.5%|
[firehol_level3](#firehol_level3)|109927|9627612|6933347|72.0%|37.7%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|6932480|75.5%|37.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|2272798|0.2%|12.3%|
[fullbogons](#fullbogons)|3778|670299624|151552|0.0%|0.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|130922|0.0%|0.7%|
[alienvault_reputation](#alienvault_reputation)|181943|181943|6045|3.3%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1043|0.3%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|93938|93938|1029|1.0%|0.0%|
[dshield](#dshield)|20|5120|1024|20.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|517|0.1%|0.0%|
[snort_ipfilter](#snort_ipfilter)|10254|10254|299|2.9%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|297|1.0%|0.0%|
[firehol_level2](#firehol_level2)|23830|35462|283|0.7%|0.0%|
[openbl_60d](#openbl_60d)|7022|7022|247|3.5%|0.0%|
[zeus](#zeus)|231|231|228|98.7%|0.0%|
[blocklist_de](#blocklist_de)|29889|29889|211|0.7%|0.0%|
[zeus_badips](#zeus_badips)|203|203|203|100.0%|0.0%|
[nixspam](#nixspam)|18909|18909|173|0.9%|0.0%|
[openbl_30d](#openbl_30d)|2855|2855|129|4.5%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3241|3241|123|3.7%|0.0%|
[shunlist](#shunlist)|1334|1334|111|8.3%|0.0%|
[et_compromised](#et_compromised)|1718|1718|103|5.9%|0.0%|
[feodo](#feodo)|104|104|102|98.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1720|1720|98|5.6%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6912|6912|87|1.2%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3015|3015|56|1.8%|0.0%|
[openbl_7d](#openbl_7d)|692|692|52|7.5%|0.0%|
[sslbl](#sslbl)|375|375|38|10.1%|0.0%|
[php_commenters](#php_commenters)|403|403|30|7.4%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|29|2.2%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|18940|18940|22|0.1%|0.0%|
[openbl_1d](#openbl_1d)|163|163|20|12.2%|0.0%|
[voipbl](#voipbl)|10522|10934|18|0.1%|0.0%|
[palevo](#palevo)|13|13|12|92.3%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|11|0.0%|0.0%|
[firehol_anonymous](#firehol_anonymous)|18443|82465|11|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2456|2456|11|0.4%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|8|0.5%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14825|14825|8|0.0%|0.0%|
[et_tor](#et_tor)|6340|6340|7|0.1%|0.0%|
[dm_tor](#dm_tor)|6428|6428|7|0.1%|0.0%|
[bm_tor](#bm_tor)|6410|6410|7|0.1%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|174|174|7|4.0%|0.0%|
[php_dictionary](#php_dictionary)|666|666|6|0.9%|0.0%|
[malc0de](#malc0de)|338|338|5|1.4%|0.0%|
[firehol_proxies](#firehol_proxies)|11996|12233|5|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|3472|3472|5|0.1%|0.0%|
[php_spammers](#php_spammers)|661|661|4|0.6%|0.0%|
[ciarmy](#ciarmy)|423|423|4|0.9%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|2|0.5%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|2|0.3%|0.0%|
[et_botcc](#et_botcc)|509|509|2|0.3%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|80|80|2|2.5%|0.0%|
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
[alienvault_reputation](#alienvault_reputation)|181943|181943|4|0.0%|0.7%|
[firehol_level3](#firehol_level3)|109927|9627612|3|0.0%|0.5%|
[et_block](#et_block)|999|18343755|2|0.0%|0.3%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|1|0.0%|0.1%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|1|0.0%|0.1%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|1|0.0%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.1%|
[firehol_level1](#firehol_level1)|5146|688981376|1|0.0%|0.1%|
[blocklist_de_sip](#blocklist_de_sip)|80|80|1|1.2%|0.1%|

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
[firehol_level3](#firehol_level3)|109927|9627612|1684|0.0%|98.0%|
[bruteforceblocker](#bruteforceblocker)|1720|1720|1661|96.5%|96.6%|
[alienvault_reputation](#alienvault_reputation)|181943|181943|1109|0.6%|64.5%|
[openbl_60d](#openbl_60d)|7022|7022|1003|14.2%|58.3%|
[openbl_30d](#openbl_30d)|2855|2855|937|32.8%|54.5%|
[firehol_level2](#firehol_level2)|23830|35462|669|1.8%|38.9%|
[blocklist_de](#blocklist_de)|29889|29889|667|2.2%|38.8%|
[blocklist_de_ssh](#blocklist_de_ssh)|3241|3241|663|20.4%|38.5%|
[shunlist](#shunlist)|1334|1334|450|33.7%|26.1%|
[openbl_7d](#openbl_7d)|692|692|316|45.6%|18.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|153|0.0%|8.9%|
[firehol_level1](#firehol_level1)|5146|688981376|109|0.0%|6.3%|
[et_block](#et_block)|999|18343755|103|0.0%|5.9%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|101|0.0%|5.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|89|0.0%|5.1%|
[openbl_1d](#openbl_1d)|163|163|61|37.4%|3.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|52|0.0%|3.0%|
[stopforumspam_30d](#stopforumspam_30d)|93938|93938|13|0.0%|0.7%|
[dshield](#dshield)|20|5120|8|0.1%|0.4%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|5|0.0%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|5|0.0%|0.2%|
[firehol_proxies](#firehol_proxies)|11996|12233|3|0.0%|0.1%|
[firehol_anonymous](#firehol_anonymous)|18443|82465|3|0.0%|0.1%|
[blocklist_de_mail](#blocklist_de_mail)|18940|18940|3|0.0%|0.1%|
[blocklist_de_imap](#blocklist_de_imap)|2456|2456|3|0.1%|0.1%|
[voipbl](#voipbl)|10522|10934|2|0.0%|0.1%|
[proxz](#proxz)|1180|1180|2|0.1%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|2|0.0%|0.1%|
[xroxy](#xroxy)|2147|2147|1|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6912|6912|1|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|10254|10254|1|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7484|7484|1|0.0%|0.0%|
[proxyrss](#proxyrss)|1536|1536|1|0.0%|0.0%|
[php_spammers](#php_spammers)|661|661|1|0.1%|0.0%|
[php_commenters](#php_commenters)|403|403|1|0.2%|0.0%|
[ciarmy](#ciarmy)|423|423|1|0.2%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3015|3015|1|0.0%|0.0%|

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
[firehol_anonymous](#firehol_anonymous)|18443|82465|5716|6.9%|90.1%|
[bm_tor](#bm_tor)|6410|6410|5701|88.9%|89.9%|
[dm_tor](#dm_tor)|6428|6428|5686|88.4%|89.6%|
[firehol_level3](#firehol_level3)|109927|9627612|1105|0.0%|17.4%|
[snort_ipfilter](#snort_ipfilter)|10254|10254|1068|10.4%|16.8%|
[stopforumspam_30d](#stopforumspam_30d)|93938|93938|642|0.6%|10.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|614|0.0%|9.6%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|533|1.8%|8.4%|
[firehol_level2](#firehol_level2)|23830|35462|356|1.0%|5.6%|
[stopforumspam_1d](#stopforumspam_1d)|6912|6912|353|5.1%|5.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|183|0.0%|2.8%|
[firehol_proxies](#firehol_proxies)|11996|12233|166|1.3%|2.6%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|163|43.8%|2.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|163|0.0%|2.5%|
[php_commenters](#php_commenters)|403|403|48|11.9%|0.7%|
[alienvault_reputation](#alienvault_reputation)|181943|181943|39|0.0%|0.6%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|22|0.0%|0.3%|
[openbl_60d](#openbl_60d)|7022|7022|20|0.2%|0.3%|
[blocklist_de](#blocklist_de)|29889|29889|10|0.0%|0.1%|
[blocklist_de_apache](#blocklist_de_apache)|14825|14825|9|0.0%|0.1%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|3472|3472|8|0.2%|0.1%|
[php_harvesters](#php_harvesters)|378|378|7|1.8%|0.1%|
[et_block](#et_block)|999|18343755|7|0.0%|0.1%|
[nixspam](#nixspam)|18909|18909|5|0.0%|0.0%|
[php_spammers](#php_spammers)|661|661|4|0.6%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|4|0.0%|0.0%|
[voipbl](#voipbl)|10522|10934|3|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|3|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7484|7484|3|0.0%|0.0%|
[php_dictionary](#php_dictionary)|666|666|3|0.4%|0.0%|
[firehol_level1](#firehol_level1)|5146|688981376|3|0.0%|0.0%|
[xroxy](#xroxy)|2147|2147|1|0.0%|0.0%|
[shunlist](#shunlist)|1334|1334|1|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3241|3241|1|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|18940|18940|1|0.0%|0.0%|

## feodo

[Abuse.ch Feodo tracker](https://feodotracker.abuse.ch) trojan includes IPs which are being used by Feodo (also known as Cridex or Bugat) which commits ebanking fraud - **excellent list**

Source is downloaded from [this link](https://feodotracker.abuse.ch/blocklist/?download=ipblocklist).

The last time downloaded was found to be dated: Wed Jun 10 06:45:12 UTC 2015.

The ipset `feodo` has **104** entries, **104** unique IPs.

The following table shows the overlaps of `feodo` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `feodo`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `feodo`.
- ` this % ` is the percentage **of this ipset (`feodo`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level1](#firehol_level1)|5146|688981376|104|0.0%|100.0%|
[et_block](#et_block)|999|18343755|102|0.0%|98.0%|
[snort_ipfilter](#snort_ipfilter)|10254|10254|82|0.7%|78.8%|
[firehol_level3](#firehol_level3)|109927|9627612|82|0.0%|78.8%|
[sslbl](#sslbl)|375|375|37|9.8%|35.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|11|0.0%|10.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|3|0.0%|2.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|3|0.0%|2.8%|
[alienvault_reputation](#alienvault_reputation)|181943|181943|2|0.0%|1.9%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.9%|

## firehol_anonymous

**FireHOL Anonymous** - Known anonymizing IPs. (includes: firehol_proxies anonymous bm_tor dm_tor)

Source is downloaded from [this link]().

The last time downloaded was found to be dated: Sun Jun  7 22:20:34 UTC 2015.

The ipset `firehol_anonymous` has **18443** entries, **82465** unique IPs.

The following table shows the overlaps of `firehol_anonymous` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `firehol_anonymous`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `firehol_anonymous`.
- ` this % ` is the percentage **of this ipset (`firehol_anonymous`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_proxies](#firehol_proxies)|11996|12233|12233|100.0%|14.8%|
[ri_web_proxies](#ri_web_proxies)|7484|7484|7484|100.0%|9.0%|
[firehol_level3](#firehol_level3)|109927|9627612|6496|0.0%|7.8%|
[dm_tor](#dm_tor)|6428|6428|6428|100.0%|7.7%|
[bm_tor](#bm_tor)|6410|6410|6410|100.0%|7.7%|
[stopforumspam_30d](#stopforumspam_30d)|93938|93938|5959|6.3%|7.2%|
[et_tor](#et_tor)|6340|6340|5716|90.1%|6.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|3424|0.0%|4.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|2883|0.0%|3.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|2852|0.0%|3.4%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|2762|9.4%|3.3%|
[ri_connect_proxies](#ri_connect_proxies)|2703|2703|2703|100.0%|3.2%|
[xroxy](#xroxy)|2147|2147|2147|100.0%|2.6%|
[proxyrss](#proxyrss)|1536|1536|1536|100.0%|1.8%|
[firehol_level2](#firehol_level2)|23830|35462|1334|3.7%|1.6%|
[proxz](#proxz)|1180|1180|1180|100.0%|1.4%|
[snort_ipfilter](#snort_ipfilter)|10254|10254|1168|11.3%|1.4%|
[stopforumspam_1d](#stopforumspam_1d)|6912|6912|998|14.4%|1.2%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|663|100.0%|0.8%|
[blocklist_de](#blocklist_de)|29889|29889|618|2.0%|0.7%|
[blocklist_de_bots](#blocklist_de_bots)|3015|3015|498|16.5%|0.6%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|372|100.0%|0.4%|
[nixspam](#nixspam)|18909|18909|147|0.7%|0.1%|
[blocklist_de_mail](#blocklist_de_mail)|18940|18940|104|0.5%|0.1%|
[php_dictionary](#php_dictionary)|666|666|89|13.3%|0.1%|
[voipbl](#voipbl)|10522|10934|78|0.7%|0.0%|
[php_commenters](#php_commenters)|403|403|76|18.8%|0.0%|
[php_spammers](#php_spammers)|661|661|75|11.3%|0.0%|
[alienvault_reputation](#alienvault_reputation)|181943|181943|56|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|28|0.0%|0.0%|
[openbl_60d](#openbl_60d)|7022|7022|23|0.3%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|15|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14825|14825|15|0.1%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|3472|3472|13|0.3%|0.0%|
[php_harvesters](#php_harvesters)|378|378|11|2.9%|0.0%|
[et_block](#et_block)|999|18343755|11|0.0%|0.0%|
[firehol_level1](#firehol_level1)|5146|688981376|8|0.0%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|7|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|174|174|7|4.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|6|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|3|0.2%|0.0%|
[et_compromised](#et_compromised)|1718|1718|3|0.1%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1720|1720|3|0.1%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2456|2456|2|0.0%|0.0%|
[sslbl](#sslbl)|375|375|1|0.2%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|1|0.0%|0.0%|
[shunlist](#shunlist)|1334|1334|1|0.0%|0.0%|
[openbl_30d](#openbl_30d)|2855|2855|1|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3241|3241|1|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|864|864|1|0.1%|0.0%|

## firehol_level1

**FireHOL Level 1** - Maximum protection without false positives. (includes: fullbogons dshield feodo palevo sslbl zeus spamhaus_drop spamhaus_edrop)

Source is downloaded from [this link]().

The last time downloaded was found to be dated: Sun Jun  7 22:15:43 UTC 2015.

The ipset `firehol_level1` has **5146** entries, **688981376** unique IPs.

The following table shows the overlaps of `firehol_level1` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `firehol_level1`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `firehol_level1`.
- ` this % ` is the percentage **of this ipset (`firehol_level1`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[fullbogons](#fullbogons)|3778|670299624|670299624|100.0%|97.2%|
[bogons](#bogons)|13|592708608|592708608|100.0%|86.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|18340608|100.0%|2.6%|
[et_block](#et_block)|999|18343755|18339910|99.9%|2.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|8867205|2.5%|1.2%|
[firehol_level3](#firehol_level3)|109927|9627612|7500217|77.9%|1.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|7498240|81.6%|1.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|4638370|3.3%|0.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|2569523|0.3%|0.3%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|487424|100.0%|0.0%|
[dshield](#dshield)|20|5120|5120|100.0%|0.0%|
[alienvault_reputation](#alienvault_reputation)|181943|181943|4845|2.6%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1933|0.5%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|93938|93938|1105|1.1%|0.0%|
[sslbl](#sslbl)|375|375|375|100.0%|0.0%|
[voipbl](#voipbl)|10522|10934|333|3.0%|0.0%|
[firehol_level2](#firehol_level2)|23830|35462|305|0.8%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|303|1.0%|0.0%|
[openbl_60d](#openbl_60d)|7022|7022|303|4.3%|0.0%|
[snort_ipfilter](#snort_ipfilter)|10254|10254|300|2.9%|0.0%|
[blocklist_de](#blocklist_de)|29889|29889|234|0.7%|0.0%|
[zeus](#zeus)|231|231|231|100.0%|0.0%|
[zeus_badips](#zeus_badips)|203|203|203|100.0%|0.0%|
[shunlist](#shunlist)|1334|1334|187|14.0%|0.0%|
[nixspam](#nixspam)|18909|18909|175|0.9%|0.0%|
[openbl_30d](#openbl_30d)|2855|2855|165|5.7%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3241|3241|137|4.2%|0.0%|
[et_compromised](#et_compromised)|1718|1718|109|6.3%|0.0%|
[feodo](#feodo)|104|104|104|100.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1720|1720|104|6.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6912|6912|87|1.2%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3015|3015|60|1.9%|0.0%|
[openbl_7d](#openbl_7d)|692|692|57|8.2%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|39|3.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|39|2.6%|0.0%|
[php_commenters](#php_commenters)|403|403|37|9.1%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|18940|18940|23|0.1%|0.0%|
[openbl_1d](#openbl_1d)|163|163|20|12.2%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|18|0.0%|0.0%|
[palevo](#palevo)|13|13|13|100.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|174|174|12|6.8%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14825|14825|12|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2456|2456|11|0.4%|0.0%|
[firehol_anonymous](#firehol_anonymous)|18443|82465|8|0.0%|0.0%|
[php_dictionary](#php_dictionary)|666|666|6|0.9%|0.0%|
[malc0de](#malc0de)|338|338|6|1.7%|0.0%|
[ciarmy](#ciarmy)|423|423|6|1.4%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|3472|3472|6|0.1%|0.0%|
[php_spammers](#php_spammers)|661|661|4|0.6%|0.0%|
[dm_tor](#dm_tor)|6428|6428|4|0.0%|0.0%|
[php_harvesters](#php_harvesters)|378|378|3|0.7%|0.0%|
[firehol_proxies](#firehol_proxies)|11996|12233|3|0.0%|0.0%|
[et_tor](#et_tor)|6340|6340|3|0.0%|0.0%|
[bm_tor](#bm_tor)|6410|6410|3|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|2|0.3%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|172|172|2|1.1%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|80|80|2|2.5%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7484|7484|1|0.0%|0.0%|
[et_botcc](#et_botcc)|509|509|1|0.1%|0.0%|

## firehol_level2

**FireHOL Level 2** - Maximum protection from attacks took place in the last 48 hours. (includes: openbl_1d blocklist_de stopforumspam_1d)

Source is downloaded from [this link]().

The last time downloaded was found to be dated: Sun Jun  7 22:20:34 UTC 2015.

The ipset `firehol_level2` has **23830** entries, **35462** unique IPs.

The following table shows the overlaps of `firehol_level2` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `firehol_level2`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `firehol_level2`.
- ` this % ` is the percentage **of this ipset (`firehol_level2`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|29889|29889|29889|100.0%|84.2%|
[blocklist_de_mail](#blocklist_de_mail)|18940|18940|18921|99.8%|53.3%|
[blocklist_de_apache](#blocklist_de_apache)|14825|14825|14825|100.0%|41.8%|
[firehol_level3](#firehol_level3)|109927|9627612|7759|0.0%|21.8%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|7234|24.6%|20.3%|
[stopforumspam_1d](#stopforumspam_1d)|6912|6912|6912|100.0%|19.4%|
[stopforumspam_30d](#stopforumspam_30d)|93938|93938|6395|6.8%|18.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|4281|0.0%|12.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|3472|3472|3472|100.0%|9.7%|
[blocklist_de_ssh](#blocklist_de_ssh)|3241|3241|3241|100.0%|9.1%|
[blocklist_de_bots](#blocklist_de_bots)|3015|3015|3015|100.0%|8.5%|
[blocklist_de_imap](#blocklist_de_imap)|2456|2456|2446|99.5%|6.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|1750|0.0%|4.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|1653|0.0%|4.6%|
[alienvault_reputation](#alienvault_reputation)|181943|181943|1445|0.7%|4.0%|
[firehol_anonymous](#firehol_anonymous)|18443|82465|1334|1.6%|3.7%|
[firehol_proxies](#firehol_proxies)|11996|12233|1120|9.1%|3.1%|
[openbl_60d](#openbl_60d)|7022|7022|1055|15.0%|2.9%|
[blocklist_de_ftp](#blocklist_de_ftp)|864|864|864|100.0%|2.4%|
[openbl_30d](#openbl_30d)|2855|2855|839|29.3%|2.3%|
[bruteforceblocker](#bruteforceblocker)|1720|1720|700|40.6%|1.9%|
[et_compromised](#et_compromised)|1718|1718|669|38.9%|1.8%|
[ri_web_proxies](#ri_web_proxies)|7484|7484|656|8.7%|1.8%|
[snort_ipfilter](#snort_ipfilter)|10254|10254|571|5.5%|1.6%|
[nixspam](#nixspam)|18909|18909|550|2.9%|1.5%|
[shunlist](#shunlist)|1334|1334|464|34.7%|1.3%|
[openbl_7d](#openbl_7d)|692|692|426|61.5%|1.2%|
[proxyrss](#proxyrss)|1536|1536|413|26.8%|1.1%|
[et_tor](#et_tor)|6340|6340|356|5.6%|1.0%|
[bm_tor](#bm_tor)|6410|6410|353|5.5%|0.9%|
[dm_tor](#dm_tor)|6428|6428|352|5.4%|0.9%|
[xroxy](#xroxy)|2147|2147|320|14.9%|0.9%|
[firehol_level1](#firehol_level1)|5146|688981376|305|0.0%|0.8%|
[et_block](#et_block)|999|18343755|283|0.0%|0.7%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|270|0.0%|0.7%|
[proxz](#proxz)|1180|1180|256|21.6%|0.7%|
[php_commenters](#php_commenters)|403|403|185|45.9%|0.5%|
[blocklist_de_strongips](#blocklist_de_strongips)|174|174|174|100.0%|0.4%|
[openbl_1d](#openbl_1d)|163|163|163|100.0%|0.4%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|156|41.9%|0.4%|
[ri_connect_proxies](#ri_connect_proxies)|2703|2703|144|5.3%|0.4%|
[php_dictionary](#php_dictionary)|666|666|109|16.3%|0.3%|
[php_spammers](#php_spammers)|661|661|105|15.8%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|89|0.0%|0.2%|
[blocklist_de_sip](#blocklist_de_sip)|80|80|61|76.2%|0.1%|
[php_harvesters](#php_harvesters)|378|378|57|15.0%|0.1%|
[ciarmy](#ciarmy)|423|423|41|9.6%|0.1%|
[voipbl](#voipbl)|10522|10934|30|0.2%|0.0%|
[dshield](#dshield)|20|5120|26|0.5%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|16|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|10|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|9|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|6|0.9%|0.0%|
[zeus_badips](#zeus_badips)|203|203|2|0.9%|0.0%|
[zeus](#zeus)|231|231|2|0.8%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|2|0.1%|0.0%|
[sslbl](#sslbl)|375|375|1|0.2%|0.0%|

## firehol_level3

**FireHOL Level 3** - All the bad IPs in last 30 days. (includes: openbl_30d stopforumspam_30d virbl malc0de shunlist malwaredomainlist bruteforceblocker ciarmy cleanmx_viruses snort_ipfilter ib_bluetack_spyware ib_bluetack_hijacked ib_bluetack_webexploit php_commenters php_dictionary php_harvesters php_spammers)

Source is downloaded from [this link]().

The last time downloaded was found to be dated: Sun Jun  7 22:20:34 UTC 2015.

The ipset `firehol_level3` has **109927** entries, **9627612** unique IPs.

The following table shows the overlaps of `firehol_level3` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `firehol_level3`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `firehol_level3`.
- ` this % ` is the percentage **of this ipset (`firehol_level3`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|9177856|100.0%|95.3%|
[firehol_level1](#firehol_level1)|5146|688981376|7500217|1.0%|77.9%|
[et_block](#et_block)|999|18343755|6933347|37.7%|72.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|6933036|37.8%|72.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|2537323|0.7%|26.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|919972|0.1%|9.5%|
[fullbogons](#fullbogons)|3778|670299624|566694|0.0%|5.8%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|339173|100.0%|3.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|161596|0.1%|1.6%|
[stopforumspam_30d](#stopforumspam_30d)|93938|93938|93938|100.0%|0.9%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|28011|95.4%|0.2%|
[snort_ipfilter](#snort_ipfilter)|10254|10254|10254|100.0%|0.1%|
[firehol_level2](#firehol_level2)|23830|35462|7759|21.8%|0.0%|
[firehol_anonymous](#firehol_anonymous)|18443|82465|6496|7.8%|0.0%|
[firehol_proxies](#firehol_proxies)|11996|12233|5376|43.9%|0.0%|
[alienvault_reputation](#alienvault_reputation)|181943|181943|5218|2.8%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6912|6912|5075|73.4%|0.0%|
[blocklist_de](#blocklist_de)|29889|29889|3855|12.8%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7484|7484|3593|48.0%|0.0%|
[openbl_60d](#openbl_60d)|7022|7022|2987|42.5%|0.0%|
[openbl_30d](#openbl_30d)|2855|2855|2855|100.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3015|3015|2213|73.3%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1720|1720|1720|100.0%|0.0%|
[et_compromised](#et_compromised)|1718|1718|1684|98.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2703|2703|1528|56.5%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|1450|100.0%|0.0%|
[shunlist](#shunlist)|1334|1334|1334|100.0%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|1288|100.0%|0.0%|
[xroxy](#xroxy)|2147|2147|1286|59.8%|0.0%|
[bm_tor](#bm_tor)|6410|6410|1106|17.2%|0.0%|
[et_tor](#et_tor)|6340|6340|1105|17.4%|0.0%|
[dm_tor](#dm_tor)|6428|6428|1099|17.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3241|3241|1039|32.0%|0.0%|
[proxz](#proxz)|1180|1180|707|59.9%|0.0%|
[proxyrss](#proxyrss)|1536|1536|699|45.5%|0.0%|
[openbl_7d](#openbl_7d)|692|692|692|100.0%|0.0%|
[php_dictionary](#php_dictionary)|666|666|666|100.0%|0.0%|
[php_spammers](#php_spammers)|661|661|661|100.0%|0.0%|
[nixspam](#nixspam)|18909|18909|550|2.9%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|18940|18940|425|2.2%|0.0%|
[ciarmy](#ciarmy)|423|423|423|100.0%|0.0%|
[php_commenters](#php_commenters)|403|403|403|100.0%|0.0%|
[php_harvesters](#php_harvesters)|378|378|378|100.0%|0.0%|
[malc0de](#malc0de)|338|338|338|100.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14825|14825|309|2.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|234|62.9%|0.0%|
[zeus](#zeus)|231|231|204|88.3%|0.0%|
[zeus_badips](#zeus_badips)|203|203|181|89.1%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|172|172|172|100.0%|0.0%|
[openbl_1d](#openbl_1d)|163|163|160|98.1%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|174|174|155|89.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|3472|3472|97|2.7%|0.0%|
[sslbl](#sslbl)|375|375|96|25.6%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|89|0.0%|0.0%|
[feodo](#feodo)|104|104|82|78.8%|0.0%|
[voipbl](#voipbl)|10522|10934|59|0.5%|0.0%|
[dshield](#dshield)|20|5120|59|1.1%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2456|2456|45|1.8%|0.0%|
[virbl](#virbl)|26|26|26|100.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|23|3.4%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|21|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|864|864|18|2.0%|0.0%|
[palevo](#palevo)|13|13|11|84.6%|0.0%|
[bogons](#bogons)|13|592708608|5|0.0%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|80|80|4|5.0%|0.0%|
[et_botcc](#et_botcc)|509|509|3|0.5%|0.0%|

## firehol_proxies

**FireHOL Proxies** - Known open proxies in the last 30 days. (includes: ib_bluetack_proxies maxmind_proxy_fraud proxyrss proxz ri_connect_proxies ri_web_proxies xroxy)

Source is downloaded from [this link]().

The last time downloaded was found to be dated: Sun Jun  7 22:20:34 UTC 2015.

The ipset `firehol_proxies` has **11996** entries, **12233** unique IPs.

The following table shows the overlaps of `firehol_proxies` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `firehol_proxies`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `firehol_proxies`.
- ` this % ` is the percentage **of this ipset (`firehol_proxies`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_anonymous](#firehol_anonymous)|18443|82465|12233|14.8%|100.0%|
[ri_web_proxies](#ri_web_proxies)|7484|7484|7484|100.0%|61.1%|
[firehol_level3](#firehol_level3)|109927|9627612|5376|0.0%|43.9%|
[stopforumspam_30d](#stopforumspam_30d)|93938|93938|5313|5.6%|43.4%|
[ri_connect_proxies](#ri_connect_proxies)|2703|2703|2703|100.0%|22.0%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|2353|8.0%|19.2%|
[xroxy](#xroxy)|2147|2147|2147|100.0%|17.5%|
[proxyrss](#proxyrss)|1536|1536|1536|100.0%|12.5%|
[proxz](#proxz)|1180|1180|1180|100.0%|9.6%|
[firehol_level2](#firehol_level2)|23830|35462|1120|3.1%|9.1%|
[stopforumspam_1d](#stopforumspam_1d)|6912|6912|790|11.4%|6.4%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|663|100.0%|5.4%|
[blocklist_de](#blocklist_de)|29889|29889|607|2.0%|4.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|501|0.0%|4.0%|
[blocklist_de_bots](#blocklist_de_bots)|3015|3015|497|16.4%|4.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|379|0.0%|3.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|372|100.0%|3.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|279|0.0%|2.2%|
[snort_ipfilter](#snort_ipfilter)|10254|10254|255|2.4%|2.0%|
[bm_tor](#bm_tor)|6410|6410|167|2.6%|1.3%|
[et_tor](#et_tor)|6340|6340|166|2.6%|1.3%|
[dm_tor](#dm_tor)|6428|6428|166|2.5%|1.3%|
[nixspam](#nixspam)|18909|18909|142|0.7%|1.1%|
[blocklist_de_mail](#blocklist_de_mail)|18940|18940|103|0.5%|0.8%|
[php_dictionary](#php_dictionary)|666|666|88|13.2%|0.7%|
[php_spammers](#php_spammers)|661|661|73|11.0%|0.5%|
[php_commenters](#php_commenters)|403|403|69|17.1%|0.5%|
[alienvault_reputation](#alienvault_reputation)|181943|181943|35|0.0%|0.2%|
[openbl_60d](#openbl_60d)|7022|7022|18|0.2%|0.1%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|15|0.0%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|11|0.0%|0.0%|
[php_harvesters](#php_harvesters)|378|378|10|2.6%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|174|174|7|4.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14825|14825|7|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|3472|3472|6|0.1%|0.0%|
[et_block](#et_block)|999|18343755|5|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|3|0.2%|0.0%|
[firehol_level1](#firehol_level1)|5146|688981376|3|0.0%|0.0%|
[et_compromised](#et_compromised)|1718|1718|3|0.1%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1720|1720|3|0.1%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|2|0.0%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2456|2456|2|0.0%|0.0%|
[voipbl](#voipbl)|10522|10934|1|0.0%|0.0%|
[sslbl](#sslbl)|375|375|1|0.2%|0.0%|
[shunlist](#shunlist)|1334|1334|1|0.0%|0.0%|

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
[firehol_level1](#firehol_level1)|5146|688981376|670299624|97.2%|100.0%|
[bogons](#bogons)|13|592708608|592708608|100.0%|88.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|4237167|3.0%|0.6%|
[firehol_level3](#firehol_level3)|109927|9627612|566694|5.8%|0.0%|
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
[nixspam](#nixspam)|18909|18909|1|0.0%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|172|172|1|0.5%|0.0%|
[ciarmy](#ciarmy)|423|423|1|0.2%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1720|1720|1|0.0%|0.0%|

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
[firehol_level3](#firehol_level3)|109927|9627612|21|0.0%|0.0%|
[firehol_level1](#firehol_level1)|5146|688981376|18|0.0%|0.0%|
[firehol_proxies](#firehol_proxies)|11996|12233|15|0.1%|0.0%|
[firehol_anonymous](#firehol_anonymous)|18443|82465|15|0.0%|0.0%|
[alienvault_reputation](#alienvault_reputation)|181943|181943|15|0.0%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|93938|93938|13|0.0%|0.0%|
[fullbogons](#fullbogons)|3778|670299624|13|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|11|1.6%|0.0%|
[et_block](#et_block)|999|18343755|11|0.0%|0.0%|
[firehol_level2](#firehol_level2)|23830|35462|10|0.0%|0.0%|
[blocklist_de](#blocklist_de)|29889|29889|8|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|5|0.0%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|4|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7484|7484|4|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|18940|18940|4|0.0%|0.0%|
[xroxy](#xroxy)|2147|2147|3|0.1%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6912|6912|3|0.0%|0.0%|
[php_dictionary](#php_dictionary)|666|666|3|0.4%|0.0%|
[nixspam](#nixspam)|18909|18909|3|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|3|0.0%|0.0%|
[voipbl](#voipbl)|10522|10934|2|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|10254|10254|2|0.0%|0.0%|
[php_harvesters](#php_harvesters)|378|378|2|0.5%|0.0%|
[proxz](#proxz)|1180|1180|1|0.0%|0.0%|
[php_spammers](#php_spammers)|661|661|1|0.1%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|1|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3241|3241|1|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|864|864|1|0.1%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|3472|3472|1|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3015|3015|1|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14825|14825|1|0.0%|0.0%|

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
[firehol_level3](#firehol_level3)|109927|9627612|9177856|95.3%|100.0%|
[firehol_level1](#firehol_level1)|5146|688981376|7498240|1.0%|81.6%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|6932480|37.7%|75.5%|
[et_block](#et_block)|999|18343755|6932480|37.7%|75.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|2526625|0.7%|27.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|904796|0.1%|9.8%|
[fullbogons](#fullbogons)|3778|670299624|565760|0.0%|6.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|145472|0.1%|1.5%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1036|0.3%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|93938|93938|735|0.7%|0.0%|
[alienvault_reputation](#alienvault_reputation)|181943|181943|518|0.2%|0.0%|
[nixspam](#nixspam)|18909|18909|172|0.9%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|167|0.5%|0.0%|
[firehol_level2](#firehol_level2)|23830|35462|89|0.2%|0.0%|
[blocklist_de](#blocklist_de)|29889|29889|58|0.1%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3015|3015|51|1.6%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6912|6912|35|0.5%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|27|2.0%|0.0%|
[openbl_60d](#openbl_60d)|7022|7022|16|0.2%|0.0%|
[openbl_30d](#openbl_30d)|2855|2855|12|0.4%|0.0%|
[snort_ipfilter](#snort_ipfilter)|10254|10254|11|0.1%|0.0%|
[zeus_badips](#zeus_badips)|203|203|10|4.9%|0.0%|
[zeus](#zeus)|231|231|10|4.3%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|7|0.4%|0.0%|
[firehol_anonymous](#firehol_anonymous)|18443|82465|7|0.0%|0.0%|
[openbl_7d](#openbl_7d)|692|692|5|0.7%|0.0%|
[et_compromised](#et_compromised)|1718|1718|5|0.2%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1720|1720|5|0.2%|0.0%|
[php_dictionary](#php_dictionary)|666|666|4|0.6%|0.0%|
[et_tor](#et_tor)|6340|6340|4|0.0%|0.0%|
[dm_tor](#dm_tor)|6428|6428|4|0.0%|0.0%|
[bm_tor](#bm_tor)|6410|6410|4|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3241|3241|4|0.1%|0.0%|
[shunlist](#shunlist)|1334|1334|3|0.2%|0.0%|
[php_spammers](#php_spammers)|661|661|3|0.4%|0.0%|
[openbl_1d](#openbl_1d)|163|163|3|1.8%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|18940|18940|3|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|2|0.3%|0.0%|
[firehol_proxies](#firehol_proxies)|11996|12233|2|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|174|174|2|1.1%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2456|2456|2|0.0%|0.0%|
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
[firehol_level1](#firehol_level1)|5146|688981376|2569523|0.3%|0.3%|
[et_block](#et_block)|999|18343755|2272798|12.3%|0.2%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|2272265|12.3%|0.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|1354507|0.9%|0.1%|
[firehol_level3](#firehol_level3)|109927|9627612|919972|9.5%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|904796|9.8%|0.1%|
[fullbogons](#fullbogons)|3778|670299624|263817|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|33155|6.8%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|13247|3.9%|0.0%|
[alienvault_reputation](#alienvault_reputation)|181943|181943|4218|2.3%|0.0%|
[firehol_anonymous](#firehol_anonymous)|18443|82465|3424|4.1%|0.0%|
[firehol_level2](#firehol_level2)|23830|35462|1653|4.6%|0.0%|
[blocklist_de](#blocklist_de)|29889|29889|1535|5.1%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|93938|93938|1519|1.6%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|18940|18940|1389|7.3%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14825|14825|1333|8.9%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|529|1.8%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|394|0.8%|0.0%|
[nixspam](#nixspam)|18909|18909|330|1.7%|0.0%|
[voipbl](#voipbl)|10522|10934|299|2.7%|0.0%|
[firehol_proxies](#firehol_proxies)|11996|12233|279|2.2%|0.0%|
[dshield](#dshield)|20|5120|273|5.3%|0.0%|
[dm_tor](#dm_tor)|6428|6428|164|2.5%|0.0%|
[bm_tor](#bm_tor)|6410|6410|164|2.5%|0.0%|
[openbl_60d](#openbl_60d)|7022|7022|163|2.3%|0.0%|
[et_tor](#et_tor)|6340|6340|163|2.5%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7484|7484|152|2.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6912|6912|133|1.9%|0.0%|
[snort_ipfilter](#snort_ipfilter)|10254|10254|118|1.1%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|97|6.6%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2703|2703|83|3.0%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|66|5.1%|0.0%|
[openbl_30d](#openbl_30d)|2855|2855|64|2.2%|0.0%|
[xroxy](#xroxy)|2147|2147|58|2.7%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|56|8.4%|0.0%|
[et_compromised](#et_compromised)|1718|1718|52|3.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1720|1720|52|3.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3241|3241|50|1.5%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|3472|3472|42|1.2%|0.0%|
[proxz](#proxz)|1180|1180|40|3.3%|0.0%|
[et_botcc](#et_botcc)|509|509|39|7.6%|0.0%|
[ciarmy](#ciarmy)|423|423|36|8.5%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3015|3015|32|1.0%|0.0%|
[shunlist](#shunlist)|1334|1334|27|2.0%|0.0%|
[proxyrss](#proxyrss)|1536|1536|27|1.7%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2456|2456|24|0.9%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|17|4.5%|0.0%|
[openbl_7d](#openbl_7d)|692|692|13|1.8%|0.0%|
[php_dictionary](#php_dictionary)|666|666|12|1.8%|0.0%|
[php_harvesters](#php_harvesters)|378|378|11|2.9%|0.0%|
[malc0de](#malc0de)|338|338|11|3.2%|0.0%|
[php_spammers](#php_spammers)|661|661|10|1.5%|0.0%|
[php_commenters](#php_commenters)|403|403|10|2.4%|0.0%|
[zeus](#zeus)|231|231|7|3.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|864|864|7|0.8%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|80|80|6|7.5%|0.0%|
[bogons](#bogons)|13|592708608|5|0.0%|0.0%|
[zeus_badips](#zeus_badips)|203|203|4|1.9%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|172|172|4|2.3%|0.0%|
[sslbl](#sslbl)|375|375|3|0.8%|0.0%|
[feodo](#feodo)|104|104|3|2.8%|0.0%|
[openbl_1d](#openbl_1d)|163|163|2|1.2%|0.0%|
[virbl](#virbl)|26|26|1|3.8%|0.0%|

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
[firehol_level1](#firehol_level1)|5146|688981376|8867205|1.2%|2.5%|
[et_block](#et_block)|999|18343755|8532519|46.5%|2.4%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|8532506|46.5%|2.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|2830203|2.0%|0.8%|
[firehol_level3](#firehol_level3)|109927|9627612|2537323|26.3%|0.7%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2526625|27.5%|0.7%|
[fullbogons](#fullbogons)|3778|670299624|252159|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|98904|20.2%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|7728|2.2%|0.0%|
[alienvault_reputation](#alienvault_reputation)|181943|181943|6261|3.4%|0.0%|
[firehol_anonymous](#firehol_anonymous)|18443|82465|2883|3.4%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|93938|93938|2502|2.6%|0.0%|
[firehol_level2](#firehol_level2)|23830|35462|1750|4.9%|0.0%|
[blocklist_de](#blocklist_de)|29889|29889|1593|5.3%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|18940|18940|1257|6.6%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14825|14825|1105|7.4%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|790|2.6%|0.0%|
[nixspam](#nixspam)|18909|18909|522|2.7%|0.0%|
[voipbl](#voipbl)|10522|10934|434|3.9%|0.0%|
[firehol_proxies](#firehol_proxies)|11996|12233|379|3.0%|0.0%|
[openbl_60d](#openbl_60d)|7022|7022|320|4.5%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|226|0.4%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7484|7484|219|2.9%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6912|6912|203|2.9%|0.0%|
[et_tor](#et_tor)|6340|6340|183|2.8%|0.0%|
[dm_tor](#dm_tor)|6428|6428|183|2.8%|0.0%|
[bm_tor](#bm_tor)|6410|6410|183|2.8%|0.0%|
[snort_ipfilter](#snort_ipfilter)|10254|10254|164|1.5%|0.0%|
[openbl_30d](#openbl_30d)|2855|2855|149|5.2%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3241|3241|136|4.1%|0.0%|
[xroxy](#xroxy)|2147|2147|104|4.8%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2703|2703|103|3.8%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3015|3015|99|3.2%|0.0%|
[et_compromised](#et_compromised)|1718|1718|89|5.1%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1720|1720|86|5.0%|0.0%|
[shunlist](#shunlist)|1334|1334|76|5.6%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|3472|3472|69|1.9%|0.0%|
[proxyrss](#proxyrss)|1536|1536|56|3.6%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2456|2456|54|2.1%|0.0%|
[php_spammers](#php_spammers)|661|661|52|7.8%|0.0%|
[proxz](#proxz)|1180|1180|48|4.0%|0.0%|
[ciarmy](#ciarmy)|423|423|47|11.1%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|45|3.1%|0.0%|
[openbl_7d](#openbl_7d)|692|692|42|6.0%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|26|2.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|26|3.9%|0.0%|
[php_dictionary](#php_dictionary)|666|666|22|3.3%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|21|5.6%|0.0%|
[et_botcc](#et_botcc)|509|509|21|4.1%|0.0%|
[malc0de](#malc0de)|338|338|19|5.6%|0.0%|
[php_commenters](#php_commenters)|403|403|16|3.9%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|864|864|15|1.7%|0.0%|
[zeus](#zeus)|231|231|9|3.8%|0.0%|
[php_harvesters](#php_harvesters)|378|378|9|2.3%|0.0%|
[zeus_badips](#zeus_badips)|203|203|8|3.9%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|174|174|8|4.5%|0.0%|
[openbl_1d](#openbl_1d)|163|163|7|4.2%|0.0%|
[sslbl](#sslbl)|375|375|6|1.6%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|80|80|6|7.5%|0.0%|
[palevo](#palevo)|13|13|3|23.0%|0.0%|
[feodo](#feodo)|104|104|3|2.8%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|172|172|3|1.7%|0.0%|
[virbl](#virbl)|26|26|2|7.6%|0.0%|

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
[firehol_level1](#firehol_level1)|5146|688981376|4638370|0.6%|3.3%|
[fullbogons](#fullbogons)|3778|670299624|4237167|0.6%|3.0%|
[bogons](#bogons)|13|592708608|4194304|0.7%|3.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|2830203|0.8%|2.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|1354507|0.1%|0.9%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|270785|55.5%|0.1%|
[firehol_level3](#firehol_level3)|109927|9627612|161596|1.6%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|145472|1.5%|0.1%|
[et_block](#et_block)|999|18343755|130922|0.7%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|130368|0.7%|0.0%|
[alienvault_reputation](#alienvault_reputation)|181943|181943|13623|7.4%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|9226|2.7%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|93938|93938|5824|6.1%|0.0%|
[firehol_level2](#firehol_level2)|23830|35462|4281|12.0%|0.0%|
[blocklist_de](#blocklist_de)|29889|29889|3872|12.9%|0.0%|
[firehol_anonymous](#firehol_anonymous)|18443|82465|2852|3.4%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|18940|18940|2817|14.8%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14825|14825|2343|15.8%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|1913|6.5%|0.0%|
[voipbl](#voipbl)|10522|10934|1602|14.6%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|1172|2.4%|0.0%|
[nixspam](#nixspam)|18909|18909|889|4.7%|0.0%|
[openbl_60d](#openbl_60d)|7022|7022|745|10.6%|0.0%|
[bm_tor](#bm_tor)|6410|6410|626|9.7%|0.0%|
[dm_tor](#dm_tor)|6428|6428|622|9.6%|0.0%|
[et_tor](#et_tor)|6340|6340|614|9.6%|0.0%|
[firehol_proxies](#firehol_proxies)|11996|12233|501|4.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6912|6912|483|6.9%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3241|3241|478|14.7%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2456|2456|310|12.6%|0.0%|
[openbl_30d](#openbl_30d)|2855|2855|297|10.4%|0.0%|
[snort_ipfilter](#snort_ipfilter)|10254|10254|256|2.4%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|3472|3472|252|7.2%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7484|7484|214|2.8%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3015|3015|182|6.0%|0.0%|
[et_compromised](#et_compromised)|1718|1718|153|8.9%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1720|1720|152|8.8%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|147|11.4%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|125|33.6%|0.0%|
[shunlist](#shunlist)|1334|1334|121|9.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|864|864|115|13.3%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|108|7.4%|0.0%|
[xroxy](#xroxy)|2147|2147|107|4.9%|0.0%|
[proxz](#proxz)|1180|1180|99|8.3%|0.0%|
[ciarmy](#ciarmy)|423|423|94|22.2%|0.0%|
[openbl_7d](#openbl_7d)|692|692|78|11.2%|0.0%|
[et_botcc](#et_botcc)|509|509|77|15.1%|0.0%|
[proxyrss](#proxyrss)|1536|1536|59|3.8%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2703|2703|57|2.1%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|51|7.6%|0.0%|
[malc0de](#malc0de)|338|338|46|13.6%|0.0%|
[php_spammers](#php_spammers)|661|661|41|6.2%|0.0%|
[php_dictionary](#php_dictionary)|666|666|35|5.2%|0.0%|
[sslbl](#sslbl)|375|375|28|7.4%|0.0%|
[php_commenters](#php_commenters)|403|403|25|6.2%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|172|172|22|12.7%|0.0%|
[php_harvesters](#php_harvesters)|378|378|20|5.2%|0.0%|
[openbl_1d](#openbl_1d)|163|163|18|11.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|174|174|16|9.1%|0.0%|
[zeus](#zeus)|231|231|14|6.0%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|80|80|13|16.2%|0.0%|
[feodo](#feodo)|104|104|11|10.5%|0.0%|
[zeus_badips](#zeus_badips)|203|203|10|4.9%|0.0%|
[virbl](#virbl)|26|26|4|15.3%|0.0%|
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
[firehol_proxies](#firehol_proxies)|11996|12233|663|5.4%|100.0%|
[firehol_anonymous](#firehol_anonymous)|18443|82465|663|0.8%|100.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|56|0.0%|8.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|51|0.0%|7.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|26|0.0%|3.9%|
[firehol_level3](#firehol_level3)|109927|9627612|23|0.0%|3.4%|
[stopforumspam_30d](#stopforumspam_30d)|93938|93938|18|0.0%|2.7%|
[ri_web_proxies](#ri_web_proxies)|7484|7484|14|0.1%|2.1%|
[xroxy](#xroxy)|2147|2147|13|0.6%|1.9%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|11|0.0%|1.6%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|11|0.0%|1.6%|
[proxyrss](#proxyrss)|1536|1536|10|0.6%|1.5%|
[ri_connect_proxies](#ri_connect_proxies)|2703|2703|7|0.2%|1.0%|
[proxz](#proxz)|1180|1180|6|0.5%|0.9%|
[firehol_level2](#firehol_level2)|23830|35462|6|0.0%|0.9%|
[stopforumspam_1d](#stopforumspam_1d)|6912|6912|5|0.0%|0.7%|
[blocklist_de](#blocklist_de)|29889|29889|4|0.0%|0.6%|
[blocklist_de_bots](#blocklist_de_bots)|3015|3015|3|0.0%|0.4%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|2|0.0%|0.3%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|2|0.1%|0.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2|0.0%|0.3%|
[firehol_level1](#firehol_level1)|5146|688981376|2|0.0%|0.3%|
[et_block](#et_block)|999|18343755|2|0.0%|0.3%|
[snort_ipfilter](#snort_ipfilter)|10254|10254|1|0.0%|0.1%|
[php_dictionary](#php_dictionary)|666|666|1|0.1%|0.1%|
[nixspam](#nixspam)|18909|18909|1|0.0%|0.1%|
[blocklist_de_mail](#blocklist_de_mail)|18940|18940|1|0.0%|0.1%|
[alienvault_reputation](#alienvault_reputation)|181943|181943|1|0.0%|0.1%|

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
[firehol_level3](#firehol_level3)|109927|9627612|339173|3.5%|100.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|13247|0.0%|3.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|9226|0.0%|2.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|7728|0.0%|2.2%|
[firehol_level1](#firehol_level1)|5146|688981376|1933|0.0%|0.5%|
[et_block](#et_block)|999|18343755|1043|0.0%|0.3%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|1037|0.0%|0.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1036|0.0%|0.3%|
[fullbogons](#fullbogons)|3778|670299624|890|0.0%|0.2%|
[alienvault_reputation](#alienvault_reputation)|181943|181943|289|0.1%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|93938|93938|48|0.0%|0.0%|
[firehol_anonymous](#firehol_anonymous)|18443|82465|28|0.0%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|27|2.0%|0.0%|
[et_tor](#et_tor)|6340|6340|22|0.3%|0.0%|
[dm_tor](#dm_tor)|6428|6428|22|0.3%|0.0%|
[bm_tor](#bm_tor)|6410|6410|22|0.3%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|19|1.3%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|18|0.0%|0.0%|
[firehol_level2](#firehol_level2)|23830|35462|16|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|10254|10254|14|0.1%|0.0%|
[nixspam](#nixspam)|18909|18909|13|0.0%|0.0%|
[firehol_proxies](#firehol_proxies)|11996|12233|11|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6912|6912|10|0.1%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7484|7484|6|0.0%|0.0%|
[blocklist_de](#blocklist_de)|29889|29889|6|0.0%|0.0%|
[openbl_60d](#openbl_60d)|7022|7022|5|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|5|1.3%|0.0%|
[voipbl](#voipbl)|10522|10934|4|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14825|14825|4|0.0%|0.0%|
[openbl_30d](#openbl_30d)|2855|2855|3|0.1%|0.0%|
[malc0de](#malc0de)|338|338|3|0.8%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|3|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|3472|3472|3|0.0%|0.0%|
[palevo](#palevo)|13|13|2|15.3%|0.0%|
[et_compromised](#et_compromised)|1718|1718|2|0.1%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1720|1720|2|0.1%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|80|80|2|2.5%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|18940|18940|2|0.0%|0.0%|
[zeus_badips](#zeus_badips)|203|203|1|0.4%|0.0%|
[zeus](#zeus)|231|231|1|0.4%|0.0%|
[xroxy](#xroxy)|2147|2147|1|0.0%|0.0%|
[sslbl](#sslbl)|375|375|1|0.2%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|1|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2703|2703|1|0.0%|0.0%|
[proxz](#proxz)|1180|1180|1|0.0%|0.0%|
[proxyrss](#proxyrss)|1536|1536|1|0.0%|0.0%|
[php_harvesters](#php_harvesters)|378|378|1|0.2%|0.0%|
[php_dictionary](#php_dictionary)|666|666|1|0.1%|0.0%|
[php_commenters](#php_commenters)|403|403|1|0.2%|0.0%|
[feodo](#feodo)|104|104|1|0.9%|0.0%|
[dshield](#dshield)|20|5120|1|0.0%|0.0%|
[ciarmy](#ciarmy)|423|423|1|0.2%|0.0%|
[bogons](#bogons)|13|592708608|1|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3015|3015|1|0.0%|0.0%|

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
[firehol_level3](#firehol_level3)|109927|9627612|1450|0.0%|100.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|108|0.0%|7.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|97|0.0%|6.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|45|0.0%|3.1%|
[firehol_level1](#firehol_level1)|5146|688981376|39|0.0%|2.6%|
[fullbogons](#fullbogons)|3778|670299624|33|0.0%|2.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|19|0.0%|1.3%|
[et_block](#et_block)|999|18343755|8|0.0%|0.5%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|7|0.0%|0.4%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|6|0.0%|0.4%|
[alienvault_reputation](#alienvault_reputation)|181943|181943|6|0.0%|0.4%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|3|0.2%|0.2%|
[firehol_proxies](#firehol_proxies)|11996|12233|3|0.0%|0.2%|
[firehol_anonymous](#firehol_anonymous)|18443|82465|3|0.0%|0.2%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|2|0.0%|0.1%|
[stopforumspam_30d](#stopforumspam_30d)|93938|93938|2|0.0%|0.1%|
[openbl_60d](#openbl_60d)|7022|7022|2|0.0%|0.1%|
[openbl_30d](#openbl_30d)|2855|2855|2|0.0%|0.1%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|2|0.3%|0.1%|
[firehol_level2](#firehol_level2)|23830|35462|2|0.0%|0.1%|
[stopforumspam_1d](#stopforumspam_1d)|6912|6912|1|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|10254|10254|1|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7484|7484|1|0.0%|0.0%|
[openbl_7d](#openbl_7d)|692|692|1|0.1%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|1|0.0%|0.0%|
[et_botcc](#et_botcc)|509|509|1|0.1%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3241|3241|1|0.0%|0.0%|
[blocklist_de](#blocklist_de)|29889|29889|1|0.0%|0.0%|

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
[firehol_level3](#firehol_level3)|109927|9627612|338|0.0%|100.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|46|0.0%|13.6%|
[cleanmx_viruses](#cleanmx_viruses)|172|172|20|11.6%|5.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|19|0.0%|5.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|11|0.0%|3.2%|
[alienvault_reputation](#alienvault_reputation)|181943|181943|11|0.0%|3.2%|
[firehol_level1](#firehol_level1)|5146|688981376|6|0.0%|1.7%|
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
[firehol_level3](#firehol_level3)|109927|9627612|1288|0.0%|100.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|147|0.0%|11.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|66|0.0%|5.1%|
[firehol_level1](#firehol_level1)|5146|688981376|39|0.0%|3.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|29|0.0%|2.2%|
[et_block](#et_block)|999|18343755|29|0.0%|2.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|27|0.0%|2.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|27|0.0%|2.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|26|0.0%|2.0%|
[snort_ipfilter](#snort_ipfilter)|10254|10254|13|0.1%|1.0%|
[fullbogons](#fullbogons)|3778|670299624|9|0.0%|0.6%|
[alienvault_reputation](#alienvault_reputation)|181943|181943|8|0.0%|0.6%|
[stopforumspam_30d](#stopforumspam_30d)|93938|93938|4|0.0%|0.3%|
[malc0de](#malc0de)|338|338|4|1.1%|0.3%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|3|0.2%|0.2%|
[zeus](#zeus)|231|231|1|0.4%|0.0%|
[et_botcc](#et_botcc)|509|509|1|0.1%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|172|172|1|0.5%|0.0%|

## maxmind_proxy_fraud

[MaxMind.com](https://www.maxmind.com/en/anonymous-proxy-fraudulent-ip-address-list) list of anonymous proxy fraudelent IP addresses.

Source is downloaded from [this link](https://www.maxmind.com/en/anonymous-proxy-fraudulent-ip-address-list).

The last time downloaded was found to be dated: Wed Jun 10 06:09:21 UTC 2015.

The ipset `maxmind_proxy_fraud` has **372** entries, **372** unique IPs.

The following table shows the overlaps of `maxmind_proxy_fraud` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `maxmind_proxy_fraud`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `maxmind_proxy_fraud`.
- ` this % ` is the percentage **of this ipset (`maxmind_proxy_fraud`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_proxies](#firehol_proxies)|11996|12233|372|3.0%|100.0%|
[firehol_anonymous](#firehol_anonymous)|18443|82465|372|0.4%|100.0%|
[firehol_level3](#firehol_level3)|109927|9627612|234|0.0%|62.9%|
[stopforumspam_30d](#stopforumspam_30d)|93938|93938|233|0.2%|62.6%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|192|0.6%|51.6%|
[snort_ipfilter](#snort_ipfilter)|10254|10254|170|1.6%|45.6%|
[et_tor](#et_tor)|6340|6340|163|2.5%|43.8%|
[bm_tor](#bm_tor)|6410|6410|163|2.5%|43.8%|
[dm_tor](#dm_tor)|6428|6428|162|2.5%|43.5%|
[stopforumspam_1d](#stopforumspam_1d)|6912|6912|156|2.2%|41.9%|
[firehol_level2](#firehol_level2)|23830|35462|156|0.4%|41.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|125|0.0%|33.6%|
[php_commenters](#php_commenters)|403|403|44|10.9%|11.8%|
[alienvault_reputation](#alienvault_reputation)|181943|181943|26|0.0%|6.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|21|0.0%|5.6%|
[openbl_60d](#openbl_60d)|7022|7022|18|0.2%|4.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|17|0.0%|4.5%|
[php_harvesters](#php_harvesters)|378|378|6|1.5%|1.6%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|5|0.0%|1.3%|
[ri_web_proxies](#ri_web_proxies)|7484|7484|4|0.0%|1.0%|
[php_spammers](#php_spammers)|661|661|4|0.6%|1.0%|
[php_dictionary](#php_dictionary)|666|666|4|0.6%|1.0%|
[et_block](#et_block)|999|18343755|2|0.0%|0.5%|
[xroxy](#xroxy)|2147|2147|1|0.0%|0.2%|
[voipbl](#voipbl)|10522|10934|1|0.0%|0.2%|
[shunlist](#shunlist)|1334|1334|1|0.0%|0.2%|
[ri_connect_proxies](#ri_connect_proxies)|2703|2703|1|0.0%|0.2%|
[nixspam](#nixspam)|18909|18909|1|0.0%|0.2%|
[blocklist_de_mail](#blocklist_de_mail)|18940|18940|1|0.0%|0.2%|
[blocklist_de_apache](#blocklist_de_apache)|14825|14825|1|0.0%|0.2%|
[blocklist_de](#blocklist_de)|29889|29889|1|0.0%|0.2%|

## nixspam

[NiX Spam](http://www.heise.de/ix/NiX-Spam-DNSBL-and-blacklist-for-download-499637.html) IP addresses that sent spam in the last hour - automatically generated entries without distinguishing open proxies from relays, dialup gateways, and so on. All IPs are removed after 12 hours if there is no spam from there.

Source is downloaded from [this link](http://www.dnsbl.manitu.net/download/nixspam-ip.dump.gz).

The last time downloaded was found to be dated: Wed Jun 10 06:45:02 UTC 2015.

The ipset `nixspam` has **18909** entries, **18909** unique IPs.

The following table shows the overlaps of `nixspam` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `nixspam`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `nixspam`.
- ` this % ` is the percentage **of this ipset (`nixspam`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|889|0.0%|4.7%|
[firehol_level3](#firehol_level3)|109927|9627612|550|0.0%|2.9%|
[firehol_level2](#firehol_level2)|23830|35462|550|1.5%|2.9%|
[blocklist_de](#blocklist_de)|29889|29889|537|1.7%|2.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|522|0.0%|2.7%|
[blocklist_de_mail](#blocklist_de_mail)|18940|18940|486|2.5%|2.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|330|0.0%|1.7%|
[stopforumspam_30d](#stopforumspam_30d)|93938|93938|204|0.2%|1.0%|
[snort_ipfilter](#snort_ipfilter)|10254|10254|195|1.9%|1.0%|
[firehol_level1](#firehol_level1)|5146|688981376|175|0.0%|0.9%|
[et_block](#et_block)|999|18343755|173|0.0%|0.9%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|172|0.0%|0.9%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|172|0.0%|0.9%|
[firehol_anonymous](#firehol_anonymous)|18443|82465|147|0.1%|0.7%|
[firehol_proxies](#firehol_proxies)|11996|12233|142|1.1%|0.7%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|127|0.4%|0.6%|
[php_dictionary](#php_dictionary)|666|666|104|15.6%|0.5%|
[ri_web_proxies](#ri_web_proxies)|7484|7484|98|1.3%|0.5%|
[php_spammers](#php_spammers)|661|661|88|13.3%|0.4%|
[xroxy](#xroxy)|2147|2147|63|2.9%|0.3%|
[stopforumspam_1d](#stopforumspam_1d)|6912|6912|49|0.7%|0.2%|
[proxz](#proxz)|1180|1180|39|3.3%|0.2%|
[alienvault_reputation](#alienvault_reputation)|181943|181943|35|0.0%|0.1%|
[blocklist_de_bots](#blocklist_de_bots)|3015|3015|30|0.9%|0.1%|
[blocklist_de_apache](#blocklist_de_apache)|14825|14825|17|0.1%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2456|2456|16|0.6%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|3472|3472|16|0.4%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|13|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2703|2703|9|0.3%|0.0%|
[php_commenters](#php_commenters)|403|403|9|2.2%|0.0%|
[php_harvesters](#php_harvesters)|378|378|8|2.1%|0.0%|
[proxyrss](#proxyrss)|1536|1536|7|0.4%|0.0%|
[dm_tor](#dm_tor)|6428|6428|6|0.0%|0.0%|
[openbl_60d](#openbl_60d)|7022|7022|5|0.0%|0.0%|
[et_tor](#et_tor)|6340|6340|5|0.0%|0.0%|
[bm_tor](#bm_tor)|6410|6410|5|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|864|864|4|0.4%|0.0%|
[openbl_30d](#openbl_30d)|2855|2855|3|0.1%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|3|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|174|174|3|1.7%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3241|3241|2|0.0%|0.0%|
[zeus_badips](#zeus_badips)|203|203|1|0.4%|0.0%|
[zeus](#zeus)|231|231|1|0.4%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|1|0.0%|0.0%|
[openbl_7d](#openbl_7d)|692|692|1|0.1%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|1|0.1%|0.0%|
[fullbogons](#fullbogons)|3778|670299624|1|0.0%|0.0%|
[bogons](#bogons)|13|592708608|1|0.0%|0.0%|

## openbl_1d

[OpenBL.org](http://www.openbl.org/) last 24 hours IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.

Source is downloaded from [this link](http://www.openbl.org/lists/base_1days.txt).

The last time downloaded was found to be dated: Wed Jun 10 06:32:00 UTC 2015.

The ipset `openbl_1d` has **163** entries, **163** unique IPs.

The following table shows the overlaps of `openbl_1d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl_1d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl_1d`.
- ` this % ` is the percentage **of this ipset (`openbl_1d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|23830|35462|163|0.4%|100.0%|
[firehol_level3](#firehol_level3)|109927|9627612|160|0.0%|98.1%|
[openbl_60d](#openbl_60d)|7022|7022|159|2.2%|97.5%|
[openbl_30d](#openbl_30d)|2855|2855|158|5.5%|96.9%|
[alienvault_reputation](#alienvault_reputation)|181943|181943|157|0.0%|96.3%|
[openbl_7d](#openbl_7d)|692|692|155|22.3%|95.0%|
[blocklist_de](#blocklist_de)|29889|29889|127|0.4%|77.9%|
[blocklist_de_ssh](#blocklist_de_ssh)|3241|3241|124|3.8%|76.0%|
[shunlist](#shunlist)|1334|1334|70|5.2%|42.9%|
[bruteforceblocker](#bruteforceblocker)|1720|1720|67|3.8%|41.1%|
[et_compromised](#et_compromised)|1718|1718|61|3.5%|37.4%|
[blocklist_de_strongips](#blocklist_de_strongips)|174|174|21|12.0%|12.8%|
[firehol_level1](#firehol_level1)|5146|688981376|20|0.0%|12.2%|
[et_block](#et_block)|999|18343755|20|0.0%|12.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|18|0.0%|11.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|16|0.0%|9.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|7|0.0%|4.2%|
[dshield](#dshield)|20|5120|4|0.0%|2.4%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|1.8%|
[stopforumspam_30d](#stopforumspam_30d)|93938|93938|2|0.0%|1.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|2|0.0%|1.2%|
[blocklist_de_apache](#blocklist_de_apache)|14825|14825|2|0.0%|1.2%|
[php_spammers](#php_spammers)|661|661|1|0.1%|0.6%|
[php_commenters](#php_commenters)|403|403|1|0.2%|0.6%|
[ciarmy](#ciarmy)|423|423|1|0.2%|0.6%|
[blocklist_de_mail](#blocklist_de_mail)|18940|18940|1|0.0%|0.6%|
[blocklist_de_imap](#blocklist_de_imap)|2456|2456|1|0.0%|0.6%|

## openbl_30d

[OpenBL.org](http://www.openbl.org/) last 30 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.

Source is downloaded from [this link](http://www.openbl.org/lists/base_30days.txt).

The last time downloaded was found to be dated: Wed Jun 10 04:07:00 UTC 2015.

The ipset `openbl_30d` has **2855** entries, **2855** unique IPs.

The following table shows the overlaps of `openbl_30d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl_30d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl_30d`.
- ` this % ` is the percentage **of this ipset (`openbl_30d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[openbl_60d](#openbl_60d)|7022|7022|2855|40.6%|100.0%|
[firehol_level3](#firehol_level3)|109927|9627612|2855|0.0%|100.0%|
[alienvault_reputation](#alienvault_reputation)|181943|181943|2838|1.5%|99.4%|
[bruteforceblocker](#bruteforceblocker)|1720|1720|941|54.7%|32.9%|
[et_compromised](#et_compromised)|1718|1718|937|54.5%|32.8%|
[firehol_level2](#firehol_level2)|23830|35462|839|2.3%|29.3%|
[blocklist_de](#blocklist_de)|29889|29889|807|2.6%|28.2%|
[blocklist_de_ssh](#blocklist_de_ssh)|3241|3241|770|23.7%|26.9%|
[openbl_7d](#openbl_7d)|692|692|692|100.0%|24.2%|
[shunlist](#shunlist)|1334|1334|546|40.9%|19.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|297|0.0%|10.4%|
[firehol_level1](#firehol_level1)|5146|688981376|165|0.0%|5.7%|
[openbl_1d](#openbl_1d)|163|163|158|96.9%|5.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|149|0.0%|5.2%|
[et_block](#et_block)|999|18343755|129|0.0%|4.5%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|121|0.0%|4.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|64|0.0%|2.2%|
[dshield](#dshield)|20|5120|42|0.8%|1.4%|
[blocklist_de_mail](#blocklist_de_mail)|18940|18940|31|0.1%|1.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|174|174|24|13.7%|0.8%|
[blocklist_de_imap](#blocklist_de_imap)|2456|2456|24|0.9%|0.8%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|12|0.0%|0.4%|
[stopforumspam_30d](#stopforumspam_30d)|93938|93938|4|0.0%|0.1%|
[snort_ipfilter](#snort_ipfilter)|10254|10254|4|0.0%|0.1%|
[blocklist_de_apache](#blocklist_de_apache)|14825|14825|4|0.0%|0.1%|
[voipbl](#voipbl)|10522|10934|3|0.0%|0.1%|
[nixspam](#nixspam)|18909|18909|3|0.0%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|3|0.0%|0.1%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|2|0.1%|0.0%|
[ciarmy](#ciarmy)|423|423|2|0.4%|0.0%|
[zeus](#zeus)|231|231|1|0.4%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|1|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6912|6912|1|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|1|0.0%|0.0%|
[php_spammers](#php_spammers)|661|661|1|0.1%|0.0%|
[php_commenters](#php_commenters)|403|403|1|0.2%|0.0%|
[firehol_anonymous](#firehol_anonymous)|18443|82465|1|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|864|864|1|0.1%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3015|3015|1|0.0%|0.0%|

## openbl_60d

[OpenBL.org](http://www.openbl.org/) last 60 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.

Source is downloaded from [this link](http://www.openbl.org/lists/base_60days.txt).

The last time downloaded was found to be dated: Wed Jun 10 04:07:00 UTC 2015.

The ipset `openbl_60d` has **7022** entries, **7022** unique IPs.

The following table shows the overlaps of `openbl_60d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl_60d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl_60d`.
- ` this % ` is the percentage **of this ipset (`openbl_60d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[alienvault_reputation](#alienvault_reputation)|181943|181943|6999|3.8%|99.6%|
[firehol_level3](#firehol_level3)|109927|9627612|2987|0.0%|42.5%|
[openbl_30d](#openbl_30d)|2855|2855|2855|100.0%|40.6%|
[firehol_level2](#firehol_level2)|23830|35462|1055|2.9%|15.0%|
[blocklist_de](#blocklist_de)|29889|29889|1004|3.3%|14.2%|
[et_compromised](#et_compromised)|1718|1718|1003|58.3%|14.2%|
[bruteforceblocker](#bruteforceblocker)|1720|1720|1002|58.2%|14.2%|
[blocklist_de_ssh](#blocklist_de_ssh)|3241|3241|957|29.5%|13.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|745|0.0%|10.6%|
[openbl_7d](#openbl_7d)|692|692|692|100.0%|9.8%|
[shunlist](#shunlist)|1334|1334|575|43.1%|8.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|320|0.0%|4.5%|
[firehol_level1](#firehol_level1)|5146|688981376|303|0.0%|4.3%|
[et_block](#et_block)|999|18343755|247|0.0%|3.5%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|235|0.0%|3.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|163|0.0%|2.3%|
[openbl_1d](#openbl_1d)|163|163|159|97.5%|2.2%|
[dshield](#dshield)|20|5120|65|1.2%|0.9%|
[stopforumspam_30d](#stopforumspam_30d)|93938|93938|50|0.0%|0.7%|
[blocklist_de_mail](#blocklist_de_mail)|18940|18940|37|0.1%|0.5%|
[blocklist_de_imap](#blocklist_de_imap)|2456|2456|29|1.1%|0.4%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|27|0.0%|0.3%|
[snort_ipfilter](#snort_ipfilter)|10254|10254|26|0.2%|0.3%|
[blocklist_de_strongips](#blocklist_de_strongips)|174|174|25|14.3%|0.3%|
[firehol_anonymous](#firehol_anonymous)|18443|82465|23|0.0%|0.3%|
[stopforumspam_1d](#stopforumspam_1d)|6912|6912|20|0.2%|0.2%|
[et_tor](#et_tor)|6340|6340|20|0.3%|0.2%|
[dm_tor](#dm_tor)|6428|6428|20|0.3%|0.2%|
[bm_tor](#bm_tor)|6410|6410|20|0.3%|0.2%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|18|4.8%|0.2%|
[firehol_proxies](#firehol_proxies)|11996|12233|18|0.1%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|16|0.0%|0.2%|
[php_commenters](#php_commenters)|403|403|11|2.7%|0.1%|
[voipbl](#voipbl)|10522|10934|8|0.0%|0.1%|
[nixspam](#nixspam)|18909|18909|5|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|5|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3015|3015|5|0.1%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14825|14825|4|0.0%|0.0%|
[zeus](#zeus)|231|231|2|0.8%|0.0%|
[php_harvesters](#php_harvesters)|378|378|2|0.5%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|2|0.1%|0.0%|
[ciarmy](#ciarmy)|423|423|2|0.4%|0.0%|
[zeus_badips](#zeus_badips)|203|203|1|0.4%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|1|0.0%|0.0%|
[php_spammers](#php_spammers)|661|661|1|0.1%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|864|864|1|0.1%|0.0%|

## openbl_7d

[OpenBL.org](http://www.openbl.org/) last 7 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.

Source is downloaded from [this link](http://www.openbl.org/lists/base_7days.txt).

The last time downloaded was found to be dated: Wed Jun 10 04:07:00 UTC 2015.

The ipset `openbl_7d` has **692** entries, **692** unique IPs.

The following table shows the overlaps of `openbl_7d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl_7d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl_7d`.
- ` this % ` is the percentage **of this ipset (`openbl_7d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[openbl_60d](#openbl_60d)|7022|7022|692|9.8%|100.0%|
[openbl_30d](#openbl_30d)|2855|2855|692|24.2%|100.0%|
[firehol_level3](#firehol_level3)|109927|9627612|692|0.0%|100.0%|
[alienvault_reputation](#alienvault_reputation)|181943|181943|687|0.3%|99.2%|
[firehol_level2](#firehol_level2)|23830|35462|426|1.2%|61.5%|
[blocklist_de](#blocklist_de)|29889|29889|394|1.3%|56.9%|
[blocklist_de_ssh](#blocklist_de_ssh)|3241|3241|383|11.8%|55.3%|
[bruteforceblocker](#bruteforceblocker)|1720|1720|323|18.7%|46.6%|
[et_compromised](#et_compromised)|1718|1718|316|18.3%|45.6%|
[shunlist](#shunlist)|1334|1334|226|16.9%|32.6%|
[openbl_1d](#openbl_1d)|163|163|155|95.0%|22.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|78|0.0%|11.2%|
[firehol_level1](#firehol_level1)|5146|688981376|57|0.0%|8.2%|
[et_block](#et_block)|999|18343755|52|0.0%|7.5%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|48|0.0%|6.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|42|0.0%|6.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|174|174|24|13.7%|3.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|13|0.0%|1.8%|
[dshield](#dshield)|20|5120|9|0.1%|1.3%|
[blocklist_de_mail](#blocklist_de_mail)|18940|18940|8|0.0%|1.1%|
[blocklist_de_imap](#blocklist_de_imap)|2456|2456|8|0.3%|1.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|5|0.0%|0.7%|
[ciarmy](#ciarmy)|423|423|2|0.4%|0.2%|
[blocklist_de_apache](#blocklist_de_apache)|14825|14825|2|0.0%|0.2%|
[stopforumspam_30d](#stopforumspam_30d)|93938|93938|1|0.0%|0.1%|
[snort_ipfilter](#snort_ipfilter)|10254|10254|1|0.0%|0.1%|
[php_spammers](#php_spammers)|661|661|1|0.1%|0.1%|
[php_commenters](#php_commenters)|403|403|1|0.2%|0.1%|
[nixspam](#nixspam)|18909|18909|1|0.0%|0.1%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|1|0.0%|0.1%|
[blocklist_de_ftp](#blocklist_de_ftp)|864|864|1|0.1%|0.1%|

## palevo

[Abuse.ch Palevo tracker](https://palevotracker.abuse.ch) worm includes IPs which are being used as botnet C&C for the Palevo crimeware - **excellent list**

Source is downloaded from [this link](https://palevotracker.abuse.ch/blocklists.php?download=ipblocklist).

The last time downloaded was found to be dated: Wed Jun 10 06:45:09 UTC 2015.

The ipset `palevo` has **13** entries, **13** unique IPs.

The following table shows the overlaps of `palevo` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `palevo`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `palevo`.
- ` this % ` is the percentage **of this ipset (`palevo`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level1](#firehol_level1)|5146|688981376|13|0.0%|100.0%|
[et_block](#et_block)|999|18343755|12|0.0%|92.3%|
[snort_ipfilter](#snort_ipfilter)|10254|10254|11|0.1%|84.6%|
[firehol_level3](#firehol_level3)|109927|9627612|11|0.0%|84.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|3|0.0%|23.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|2|0.0%|15.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|1|0.0%|7.6%|

## php_commenters

[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) comment spammers (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=c&rss=1).

The last time downloaded was found to be dated: Wed Jun 10 06:54:20 UTC 2015.

The ipset `php_commenters` has **403** entries, **403** unique IPs.

The following table shows the overlaps of `php_commenters` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `php_commenters`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `php_commenters`.
- ` this % ` is the percentage **of this ipset (`php_commenters`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level3](#firehol_level3)|109927|9627612|403|0.0%|100.0%|
[stopforumspam_30d](#stopforumspam_30d)|93938|93938|302|0.3%|74.9%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|225|0.7%|55.8%|
[firehol_level2](#firehol_level2)|23830|35462|185|0.5%|45.9%|
[stopforumspam_1d](#stopforumspam_1d)|6912|6912|161|2.3%|39.9%|
[blocklist_de](#blocklist_de)|29889|29889|98|0.3%|24.3%|
[blocklist_de_bots](#blocklist_de_bots)|3015|3015|78|2.5%|19.3%|
[firehol_anonymous](#firehol_anonymous)|18443|82465|76|0.0%|18.8%|
[firehol_proxies](#firehol_proxies)|11996|12233|69|0.5%|17.1%|
[snort_ipfilter](#snort_ipfilter)|10254|10254|58|0.5%|14.3%|
[et_tor](#et_tor)|6340|6340|48|0.7%|11.9%|
[dm_tor](#dm_tor)|6428|6428|48|0.7%|11.9%|
[bm_tor](#bm_tor)|6410|6410|48|0.7%|11.9%|
[blocklist_de_strongips](#blocklist_de_strongips)|174|174|45|25.8%|11.1%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|44|11.8%|10.9%|
[php_spammers](#php_spammers)|661|661|43|6.5%|10.6%|
[firehol_level1](#firehol_level1)|5146|688981376|37|0.0%|9.1%|
[blocklist_de_apache](#blocklist_de_apache)|14825|14825|31|0.2%|7.6%|
[et_block](#et_block)|999|18343755|30|0.0%|7.4%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|29|0.0%|7.1%|
[php_dictionary](#php_dictionary)|666|666|28|4.2%|6.9%|
[blocklist_de_mail](#blocklist_de_mail)|18940|18940|26|0.1%|6.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|25|0.0%|6.2%|
[ri_web_proxies](#ri_web_proxies)|7484|7484|23|0.3%|5.7%|
[alienvault_reputation](#alienvault_reputation)|181943|181943|18|0.0%|4.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|16|0.0%|3.9%|
[php_harvesters](#php_harvesters)|378|378|15|3.9%|3.7%|
[openbl_60d](#openbl_60d)|7022|7022|11|0.1%|2.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|10|0.0%|2.4%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|3472|3472|10|0.2%|2.4%|
[nixspam](#nixspam)|18909|18909|9|0.0%|2.2%|
[xroxy](#xroxy)|2147|2147|8|0.3%|1.9%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|7|0.0%|1.7%|
[proxz](#proxz)|1180|1180|7|0.5%|1.7%|
[ri_connect_proxies](#ri_connect_proxies)|2703|2703|5|0.1%|1.2%|
[proxyrss](#proxyrss)|1536|1536|3|0.1%|0.7%|
[zeus_badips](#zeus_badips)|203|203|1|0.4%|0.2%|
[zeus](#zeus)|231|231|1|0.4%|0.2%|
[openbl_7d](#openbl_7d)|692|692|1|0.1%|0.2%|
[openbl_30d](#openbl_30d)|2855|2855|1|0.0%|0.2%|
[openbl_1d](#openbl_1d)|163|163|1|0.6%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.2%|
[fullbogons](#fullbogons)|3778|670299624|1|0.0%|0.2%|
[et_compromised](#et_compromised)|1718|1718|1|0.0%|0.2%|
[bruteforceblocker](#bruteforceblocker)|1720|1720|1|0.0%|0.2%|
[bogons](#bogons)|13|592708608|1|0.0%|0.2%|
[blocklist_de_ssh](#blocklist_de_ssh)|3241|3241|1|0.0%|0.2%|
[blocklist_de_imap](#blocklist_de_imap)|2456|2456|1|0.0%|0.2%|

## php_dictionary

[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) directory attackers (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=d&rss=1).

The last time downloaded was found to be dated: Wed Jun 10 06:54:22 UTC 2015.

The ipset `php_dictionary` has **666** entries, **666** unique IPs.

The following table shows the overlaps of `php_dictionary` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `php_dictionary`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `php_dictionary`.
- ` this % ` is the percentage **of this ipset (`php_dictionary`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level3](#firehol_level3)|109927|9627612|666|0.0%|100.0%|
[php_spammers](#php_spammers)|661|661|273|41.3%|40.9%|
[stopforumspam_30d](#stopforumspam_30d)|93938|93938|126|0.1%|18.9%|
[firehol_level2](#firehol_level2)|23830|35462|109|0.3%|16.3%|
[nixspam](#nixspam)|18909|18909|104|0.5%|15.6%|
[blocklist_de](#blocklist_de)|29889|29889|102|0.3%|15.3%|
[firehol_anonymous](#firehol_anonymous)|18443|82465|89|0.1%|13.3%|
[snort_ipfilter](#snort_ipfilter)|10254|10254|88|0.8%|13.2%|
[firehol_proxies](#firehol_proxies)|11996|12233|88|0.7%|13.2%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|84|0.2%|12.6%|
[blocklist_de_mail](#blocklist_de_mail)|18940|18940|83|0.4%|12.4%|
[ri_web_proxies](#ri_web_proxies)|7484|7484|60|0.8%|9.0%|
[xroxy](#xroxy)|2147|2147|39|1.8%|5.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|35|0.0%|5.2%|
[php_commenters](#php_commenters)|403|403|28|6.9%|4.2%|
[stopforumspam_1d](#stopforumspam_1d)|6912|6912|27|0.3%|4.0%|
[proxz](#proxz)|1180|1180|23|1.9%|3.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|22|0.0%|3.3%|
[blocklist_de_bots](#blocklist_de_bots)|3015|3015|15|0.4%|2.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|12|0.0%|1.8%|
[alienvault_reputation](#alienvault_reputation)|181943|181943|8|0.0%|1.2%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|6|0.0%|0.9%|
[firehol_level1](#firehol_level1)|5146|688981376|6|0.0%|0.9%|
[et_block](#et_block)|999|18343755|6|0.0%|0.9%|
[ri_connect_proxies](#ri_connect_proxies)|2703|2703|4|0.1%|0.6%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|4|1.0%|0.6%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|4|0.0%|0.6%|
[blocklist_de_strongips](#blocklist_de_strongips)|174|174|4|2.2%|0.6%|
[php_harvesters](#php_harvesters)|378|378|3|0.7%|0.4%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|3|0.0%|0.4%|
[et_tor](#et_tor)|6340|6340|3|0.0%|0.4%|
[dm_tor](#dm_tor)|6428|6428|3|0.0%|0.4%|
[bm_tor](#bm_tor)|6410|6410|3|0.0%|0.4%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|3472|3472|3|0.0%|0.4%|
[blocklist_de_apache](#blocklist_de_apache)|14825|14825|3|0.0%|0.4%|
[proxyrss](#proxyrss)|1536|1536|2|0.1%|0.3%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.1%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|1|0.1%|0.1%|

## php_harvesters

[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) harvesters (IPs that surf the internet looking for email addresses) (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=h&rss=1).

The last time downloaded was found to be dated: Wed Jun 10 06:54:19 UTC 2015.

The ipset `php_harvesters` has **378** entries, **378** unique IPs.

The following table shows the overlaps of `php_harvesters` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `php_harvesters`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `php_harvesters`.
- ` this % ` is the percentage **of this ipset (`php_harvesters`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level3](#firehol_level3)|109927|9627612|378|0.0%|100.0%|
[stopforumspam_30d](#stopforumspam_30d)|93938|93938|81|0.0%|21.4%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|60|0.2%|15.8%|
[firehol_level2](#firehol_level2)|23830|35462|57|0.1%|15.0%|
[stopforumspam_1d](#stopforumspam_1d)|6912|6912|40|0.5%|10.5%|
[blocklist_de](#blocklist_de)|29889|29889|38|0.1%|10.0%|
[blocklist_de_bots](#blocklist_de_bots)|3015|3015|27|0.8%|7.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|20|0.0%|5.2%|
[php_commenters](#php_commenters)|403|403|15|3.7%|3.9%|
[alienvault_reputation](#alienvault_reputation)|181943|181943|12|0.0%|3.1%|
[snort_ipfilter](#snort_ipfilter)|10254|10254|11|0.1%|2.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|11|0.0%|2.9%|
[firehol_anonymous](#firehol_anonymous)|18443|82465|11|0.0%|2.9%|
[firehol_proxies](#firehol_proxies)|11996|12233|10|0.0%|2.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|9|0.0%|2.3%|
[nixspam](#nixspam)|18909|18909|8|0.0%|2.1%|
[et_tor](#et_tor)|6340|6340|7|0.1%|1.8%|
[dm_tor](#dm_tor)|6428|6428|7|0.1%|1.8%|
[bm_tor](#bm_tor)|6410|6410|7|0.1%|1.8%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|6|1.6%|1.5%|
[blocklist_de_mail](#blocklist_de_mail)|18940|18940|6|0.0%|1.5%|
[php_spammers](#php_spammers)|661|661|3|0.4%|0.7%|
[php_dictionary](#php_dictionary)|666|666|3|0.4%|0.7%|
[firehol_level1](#firehol_level1)|5146|688981376|3|0.0%|0.7%|
[blocklist_de_ftp](#blocklist_de_ftp)|864|864|3|0.3%|0.7%|
[blocklist_de_apache](#blocklist_de_apache)|14825|14825|3|0.0%|0.7%|
[xroxy](#xroxy)|2147|2147|2|0.0%|0.5%|
[ri_web_proxies](#ri_web_proxies)|7484|7484|2|0.0%|0.5%|
[openbl_60d](#openbl_60d)|7022|7022|2|0.0%|0.5%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|2|0.0%|0.5%|
[blocklist_de_strongips](#blocklist_de_strongips)|174|174|2|1.1%|0.5%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|3472|3472|2|0.0%|0.5%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|1|0.0%|0.2%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|1|0.0%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.2%|
[fullbogons](#fullbogons)|3778|670299624|1|0.0%|0.2%|
[et_block](#et_block)|999|18343755|1|0.0%|0.2%|
[bogons](#bogons)|13|592708608|1|0.0%|0.2%|
[blocklist_de_imap](#blocklist_de_imap)|2456|2456|1|0.0%|0.2%|

## php_spammers

[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) spam servers (IPs used by spammers to send messages) (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=s&rss=1).

The last time downloaded was found to be dated: Wed Jun 10 06:54:19 UTC 2015.

The ipset `php_spammers` has **661** entries, **661** unique IPs.

The following table shows the overlaps of `php_spammers` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `php_spammers`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `php_spammers`.
- ` this % ` is the percentage **of this ipset (`php_spammers`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level3](#firehol_level3)|109927|9627612|661|0.0%|100.0%|
[php_dictionary](#php_dictionary)|666|666|273|40.9%|41.3%|
[stopforumspam_30d](#stopforumspam_30d)|93938|93938|138|0.1%|20.8%|
[firehol_level2](#firehol_level2)|23830|35462|105|0.2%|15.8%|
[blocklist_de](#blocklist_de)|29889|29889|98|0.3%|14.8%|
[nixspam](#nixspam)|18909|18909|88|0.4%|13.3%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|83|0.2%|12.5%|
[snort_ipfilter](#snort_ipfilter)|10254|10254|82|0.7%|12.4%|
[firehol_anonymous](#firehol_anonymous)|18443|82465|75|0.0%|11.3%|
[firehol_proxies](#firehol_proxies)|11996|12233|73|0.5%|11.0%|
[blocklist_de_mail](#blocklist_de_mail)|18940|18940|73|0.3%|11.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|52|0.0%|7.8%|
[ri_web_proxies](#ri_web_proxies)|7484|7484|50|0.6%|7.5%|
[php_commenters](#php_commenters)|403|403|43|10.6%|6.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|41|0.0%|6.2%|
[xroxy](#xroxy)|2147|2147|32|1.4%|4.8%|
[stopforumspam_1d](#stopforumspam_1d)|6912|6912|32|0.4%|4.8%|
[proxz](#proxz)|1180|1180|21|1.7%|3.1%|
[blocklist_de_bots](#blocklist_de_bots)|3015|3015|17|0.5%|2.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|10|0.0%|1.5%|
[blocklist_de_strongips](#blocklist_de_strongips)|174|174|7|4.0%|1.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|3472|3472|7|0.2%|1.0%|
[blocklist_de_apache](#blocklist_de_apache)|14825|14825|7|0.0%|1.0%|
[alienvault_reputation](#alienvault_reputation)|181943|181943|5|0.0%|0.7%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|4|0.0%|0.6%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|4|1.0%|0.6%|
[firehol_level1](#firehol_level1)|5146|688981376|4|0.0%|0.6%|
[et_tor](#et_tor)|6340|6340|4|0.0%|0.6%|
[et_block](#et_block)|999|18343755|4|0.0%|0.6%|
[dm_tor](#dm_tor)|6428|6428|4|0.0%|0.6%|
[bm_tor](#bm_tor)|6410|6410|4|0.0%|0.6%|
[ri_connect_proxies](#ri_connect_proxies)|2703|2703|3|0.1%|0.4%|
[proxyrss](#proxyrss)|1536|1536|3|0.1%|0.4%|
[php_harvesters](#php_harvesters)|378|378|3|0.7%|0.4%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|0.4%|
[openbl_7d](#openbl_7d)|692|692|1|0.1%|0.1%|
[openbl_60d](#openbl_60d)|7022|7022|1|0.0%|0.1%|
[openbl_30d](#openbl_30d)|2855|2855|1|0.0%|0.1%|
[openbl_1d](#openbl_1d)|163|163|1|0.6%|0.1%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|1|0.0%|0.1%|
[et_compromised](#et_compromised)|1718|1718|1|0.0%|0.1%|
[bruteforceblocker](#bruteforceblocker)|1720|1720|1|0.0%|0.1%|
[blocklist_de_ssh](#blocklist_de_ssh)|3241|3241|1|0.0%|0.1%|

## proxyrss

[proxyrss.com](http://www.proxyrss.com) open proxies syndicated from multiple sources.

Source is downloaded from [this link](http://www.proxyrss.com/proxylists/all.gz).

The last time downloaded was found to be dated: Wed Jun 10 04:21:39 UTC 2015.

The ipset `proxyrss` has **1536** entries, **1536** unique IPs.

The following table shows the overlaps of `proxyrss` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `proxyrss`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `proxyrss`.
- ` this % ` is the percentage **of this ipset (`proxyrss`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_proxies](#firehol_proxies)|11996|12233|1536|12.5%|100.0%|
[firehol_anonymous](#firehol_anonymous)|18443|82465|1536|1.8%|100.0%|
[firehol_level3](#firehol_level3)|109927|9627612|699|0.0%|45.5%|
[stopforumspam_30d](#stopforumspam_30d)|93938|93938|697|0.7%|45.3%|
[ri_web_proxies](#ri_web_proxies)|7484|7484|606|8.0%|39.4%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|579|1.9%|37.6%|
[firehol_level2](#firehol_level2)|23830|35462|413|1.1%|26.8%|
[xroxy](#xroxy)|2147|2147|351|16.3%|22.8%|
[stopforumspam_1d](#stopforumspam_1d)|6912|6912|338|4.8%|22.0%|
[proxz](#proxz)|1180|1180|263|22.2%|17.1%|
[blocklist_de](#blocklist_de)|29889|29889|218|0.7%|14.1%|
[blocklist_de_bots](#blocklist_de_bots)|3015|3015|217|7.1%|14.1%|
[ri_connect_proxies](#ri_connect_proxies)|2703|2703|205|7.5%|13.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|59|0.0%|3.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|56|0.0%|3.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|27|0.0%|1.7%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|10|1.5%|0.6%|
[snort_ipfilter](#snort_ipfilter)|10254|10254|7|0.0%|0.4%|
[nixspam](#nixspam)|18909|18909|7|0.0%|0.4%|
[blocklist_de_strongips](#blocklist_de_strongips)|174|174|6|3.4%|0.3%|
[php_spammers](#php_spammers)|661|661|3|0.4%|0.1%|
[php_commenters](#php_commenters)|403|403|3|0.7%|0.1%|
[php_dictionary](#php_dictionary)|666|666|2|0.3%|0.1%|
[alienvault_reputation](#alienvault_reputation)|181943|181943|2|0.0%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.0%|
[et_compromised](#et_compromised)|1718|1718|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1720|1720|1|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|18940|18940|1|0.0%|0.0%|

## proxz

[proxz.com](http://www.proxz.com) open proxies (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.proxz.com/proxylists.xml).

The last time downloaded was found to be dated: Wed Jun 10 04:21:47 UTC 2015.

The ipset `proxz` has **1180** entries, **1180** unique IPs.

The following table shows the overlaps of `proxz` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `proxz`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `proxz`.
- ` this % ` is the percentage **of this ipset (`proxz`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_proxies](#firehol_proxies)|11996|12233|1180|9.6%|100.0%|
[firehol_anonymous](#firehol_anonymous)|18443|82465|1180|1.4%|100.0%|
[firehol_level3](#firehol_level3)|109927|9627612|707|0.0%|59.9%|
[stopforumspam_30d](#stopforumspam_30d)|93938|93938|700|0.7%|59.3%|
[ri_web_proxies](#ri_web_proxies)|7484|7484|540|7.2%|45.7%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|477|1.6%|40.4%|
[xroxy](#xroxy)|2147|2147|425|19.7%|36.0%|
[proxyrss](#proxyrss)|1536|1536|263|17.1%|22.2%|
[firehol_level2](#firehol_level2)|23830|35462|256|0.7%|21.6%|
[ri_connect_proxies](#ri_connect_proxies)|2703|2703|200|7.3%|16.9%|
[stopforumspam_1d](#stopforumspam_1d)|6912|6912|178|2.5%|15.0%|
[blocklist_de](#blocklist_de)|29889|29889|174|0.5%|14.7%|
[blocklist_de_bots](#blocklist_de_bots)|3015|3015|144|4.7%|12.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|99|0.0%|8.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|48|0.0%|4.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|40|0.0%|3.3%|
[nixspam](#nixspam)|18909|18909|39|0.2%|3.3%|
[blocklist_de_mail](#blocklist_de_mail)|18940|18940|30|0.1%|2.5%|
[snort_ipfilter](#snort_ipfilter)|10254|10254|26|0.2%|2.2%|
[php_dictionary](#php_dictionary)|666|666|23|3.4%|1.9%|
[php_spammers](#php_spammers)|661|661|21|3.1%|1.7%|
[php_commenters](#php_commenters)|403|403|7|1.7%|0.5%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|6|0.9%|0.5%|
[blocklist_de_strongips](#blocklist_de_strongips)|174|174|5|2.8%|0.4%|
[alienvault_reputation](#alienvault_reputation)|181943|181943|3|0.0%|0.2%|
[et_compromised](#et_compromised)|1718|1718|2|0.1%|0.1%|
[bruteforceblocker](#bruteforceblocker)|1720|1720|2|0.1%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|1|0.0%|0.0%|

## ri_connect_proxies

[rosinstrument.com](http://www.rosinstrument.com) open CONNECT proxies (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://tools.rosinstrument.com/proxy/plab100.xml).

The last time downloaded was found to be dated: Wed Jun 10 04:55:17 UTC 2015.

The ipset `ri_connect_proxies` has **2703** entries, **2703** unique IPs.

The following table shows the overlaps of `ri_connect_proxies` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ri_connect_proxies`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ri_connect_proxies`.
- ` this % ` is the percentage **of this ipset (`ri_connect_proxies`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_proxies](#firehol_proxies)|11996|12233|2703|22.0%|100.0%|
[firehol_anonymous](#firehol_anonymous)|18443|82465|2703|3.2%|100.0%|
[stopforumspam_30d](#stopforumspam_30d)|93938|93938|1528|1.6%|56.5%|
[firehol_level3](#firehol_level3)|109927|9627612|1528|0.0%|56.5%|
[ri_web_proxies](#ri_web_proxies)|7484|7484|1149|15.3%|42.5%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|582|1.9%|21.5%|
[xroxy](#xroxy)|2147|2147|389|18.1%|14.3%|
[proxyrss](#proxyrss)|1536|1536|205|13.3%|7.5%|
[proxz](#proxz)|1180|1180|200|16.9%|7.3%|
[firehol_level2](#firehol_level2)|23830|35462|144|0.4%|5.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|103|0.0%|3.8%|
[stopforumspam_1d](#stopforumspam_1d)|6912|6912|99|1.4%|3.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|83|0.0%|3.0%|
[blocklist_de](#blocklist_de)|29889|29889|76|0.2%|2.8%|
[blocklist_de_bots](#blocklist_de_bots)|3015|3015|72|2.3%|2.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|57|0.0%|2.1%|
[nixspam](#nixspam)|18909|18909|9|0.0%|0.3%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|7|1.0%|0.2%|
[snort_ipfilter](#snort_ipfilter)|10254|10254|5|0.0%|0.1%|
[php_commenters](#php_commenters)|403|403|5|1.2%|0.1%|
[php_dictionary](#php_dictionary)|666|666|4|0.6%|0.1%|
[blocklist_de_mail](#blocklist_de_mail)|18940|18940|4|0.0%|0.1%|
[php_spammers](#php_spammers)|661|661|3|0.4%|0.1%|
[alienvault_reputation](#alienvault_reputation)|181943|181943|3|0.0%|0.1%|
[blocklist_de_imap](#blocklist_de_imap)|2456|2456|2|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.0%|

## ri_web_proxies

[rosinstrument.com](http://www.rosinstrument.com) open HTTP proxies (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://tools.rosinstrument.com/proxy/l100.xml).

The last time downloaded was found to be dated: Wed Jun 10 06:28:46 UTC 2015.

The ipset `ri_web_proxies` has **7484** entries, **7484** unique IPs.

The following table shows the overlaps of `ri_web_proxies` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ri_web_proxies`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ri_web_proxies`.
- ` this % ` is the percentage **of this ipset (`ri_web_proxies`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_proxies](#firehol_proxies)|11996|12233|7484|61.1%|100.0%|
[firehol_anonymous](#firehol_anonymous)|18443|82465|7484|9.0%|100.0%|
[firehol_level3](#firehol_level3)|109927|9627612|3593|0.0%|48.0%|
[stopforumspam_30d](#stopforumspam_30d)|93938|93938|3547|3.7%|47.3%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|1527|5.2%|20.4%|
[ri_connect_proxies](#ri_connect_proxies)|2703|2703|1149|42.5%|15.3%|
[xroxy](#xroxy)|2147|2147|943|43.9%|12.6%|
[firehol_level2](#firehol_level2)|23830|35462|656|1.8%|8.7%|
[proxyrss](#proxyrss)|1536|1536|606|39.4%|8.0%|
[proxz](#proxz)|1180|1180|540|45.7%|7.2%|
[stopforumspam_1d](#stopforumspam_1d)|6912|6912|452|6.5%|6.0%|
[blocklist_de](#blocklist_de)|29889|29889|421|1.4%|5.6%|
[blocklist_de_bots](#blocklist_de_bots)|3015|3015|349|11.5%|4.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|219|0.0%|2.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|214|0.0%|2.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|152|0.0%|2.0%|
[nixspam](#nixspam)|18909|18909|98|0.5%|1.3%|
[blocklist_de_mail](#blocklist_de_mail)|18940|18940|65|0.3%|0.8%|
[php_dictionary](#php_dictionary)|666|666|60|9.0%|0.8%|
[snort_ipfilter](#snort_ipfilter)|10254|10254|59|0.5%|0.7%|
[php_spammers](#php_spammers)|661|661|50|7.5%|0.6%|
[php_commenters](#php_commenters)|403|403|23|5.7%|0.3%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|14|2.1%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|6|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|174|174|6|3.4%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|3472|3472|6|0.1%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14825|14825|6|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|4|1.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|4|0.0%|0.0%|
[dm_tor](#dm_tor)|6428|6428|4|0.0%|0.0%|
[bm_tor](#bm_tor)|6410|6410|4|0.0%|0.0%|
[alienvault_reputation](#alienvault_reputation)|181943|181943|4|0.0%|0.0%|
[et_tor](#et_tor)|6340|6340|3|0.0%|0.0%|
[php_harvesters](#php_harvesters)|378|378|2|0.5%|0.0%|
[sslbl](#sslbl)|375|375|1|0.2%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|1|0.0%|0.0%|
[firehol_level1](#firehol_level1)|5146|688981376|1|0.0%|0.0%|
[et_compromised](#et_compromised)|1718|1718|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1720|1720|1|0.0%|0.0%|

## shunlist

[AutoShun.org](http://autoshun.org/) IPs identified as hostile by correlating logs from distributed snort installations running the autoshun plugin

Source is downloaded from [this link](http://www.autoshun.org/files/shunlist.csv).

The last time downloaded was found to be dated: Wed Jun 10 03:30:04 UTC 2015.

The ipset `shunlist` has **1334** entries, **1334** unique IPs.

The following table shows the overlaps of `shunlist` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `shunlist`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `shunlist`.
- ` this % ` is the percentage **of this ipset (`shunlist`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level3](#firehol_level3)|109927|9627612|1334|0.0%|100.0%|
[alienvault_reputation](#alienvault_reputation)|181943|181943|1325|0.7%|99.3%|
[openbl_60d](#openbl_60d)|7022|7022|575|8.1%|43.1%|
[openbl_30d](#openbl_30d)|2855|2855|546|19.1%|40.9%|
[firehol_level2](#firehol_level2)|23830|35462|464|1.3%|34.7%|
[blocklist_de](#blocklist_de)|29889|29889|459|1.5%|34.4%|
[et_compromised](#et_compromised)|1718|1718|450|26.1%|33.7%|
[bruteforceblocker](#bruteforceblocker)|1720|1720|450|26.1%|33.7%|
[blocklist_de_ssh](#blocklist_de_ssh)|3241|3241|419|12.9%|31.4%|
[openbl_7d](#openbl_7d)|692|692|226|32.6%|16.9%|
[firehol_level1](#firehol_level1)|5146|688981376|187|0.0%|14.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|121|0.0%|9.0%|
[et_block](#et_block)|999|18343755|111|0.0%|8.3%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|98|0.0%|7.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|76|0.0%|5.6%|
[openbl_1d](#openbl_1d)|163|163|70|42.9%|5.2%|
[sslbl](#sslbl)|375|375|64|17.0%|4.7%|
[blocklist_de_apache](#blocklist_de_apache)|14825|14825|35|0.2%|2.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|27|0.0%|2.0%|
[ciarmy](#ciarmy)|423|423|27|6.3%|2.0%|
[dshield](#dshield)|20|5120|25|0.4%|1.8%|
[blocklist_de_strongips](#blocklist_de_strongips)|174|174|20|11.4%|1.4%|
[voipbl](#voipbl)|10522|10934|14|0.1%|1.0%|
[stopforumspam_30d](#stopforumspam_30d)|93938|93938|4|0.0%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|0.2%|
[blocklist_de_mail](#blocklist_de_mail)|18940|18940|3|0.0%|0.2%|
[snort_ipfilter](#snort_ipfilter)|10254|10254|2|0.0%|0.1%|
[blocklist_de_sip](#blocklist_de_sip)|80|80|2|2.5%|0.1%|
[blocklist_de_imap](#blocklist_de_imap)|2456|2456|2|0.0%|0.1%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|1|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6912|6912|1|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[firehol_proxies](#firehol_proxies)|11996|12233|1|0.0%|0.0%|
[firehol_anonymous](#firehol_anonymous)|18443|82465|1|0.0%|0.0%|
[et_tor](#et_tor)|6340|6340|1|0.0%|0.0%|
[dm_tor](#dm_tor)|6428|6428|1|0.0%|0.0%|
[bm_tor](#bm_tor)|6410|6410|1|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|3472|3472|1|0.0%|0.0%|

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
[firehol_level3](#firehol_level3)|109927|9627612|10254|0.1%|100.0%|
[firehol_anonymous](#firehol_anonymous)|18443|82465|1168|1.4%|11.3%|
[et_tor](#et_tor)|6340|6340|1068|16.8%|10.4%|
[bm_tor](#bm_tor)|6410|6410|1068|16.6%|10.4%|
[dm_tor](#dm_tor)|6428|6428|1061|16.5%|10.3%|
[stopforumspam_30d](#stopforumspam_30d)|93938|93938|808|0.8%|7.8%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|669|2.2%|6.5%|
[firehol_level2](#firehol_level2)|23830|35462|571|1.6%|5.5%|
[stopforumspam_1d](#stopforumspam_1d)|6912|6912|395|5.7%|3.8%|
[firehol_level1](#firehol_level1)|5146|688981376|300|0.0%|2.9%|
[et_block](#et_block)|999|18343755|299|0.0%|2.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|256|0.0%|2.4%|
[firehol_proxies](#firehol_proxies)|11996|12233|255|2.0%|2.4%|
[blocklist_de](#blocklist_de)|29889|29889|215|0.7%|2.0%|
[zeus](#zeus)|231|231|201|87.0%|1.9%|
[nixspam](#nixspam)|18909|18909|195|1.0%|1.9%|
[zeus_badips](#zeus_badips)|203|203|179|88.1%|1.7%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|170|45.6%|1.6%|
[blocklist_de_mail](#blocklist_de_mail)|18940|18940|167|0.8%|1.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|164|0.0%|1.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|118|0.0%|1.1%|
[alienvault_reputation](#alienvault_reputation)|181943|181943|116|0.0%|1.1%|
[php_dictionary](#php_dictionary)|666|666|88|13.2%|0.8%|
[php_spammers](#php_spammers)|661|661|82|12.4%|0.7%|
[feodo](#feodo)|104|104|82|78.8%|0.7%|
[ri_web_proxies](#ri_web_proxies)|7484|7484|59|0.7%|0.5%|
[php_commenters](#php_commenters)|403|403|58|14.3%|0.5%|
[xroxy](#xroxy)|2147|2147|44|2.0%|0.4%|
[sslbl](#sslbl)|375|375|32|8.5%|0.3%|
[blocklist_de_apache](#blocklist_de_apache)|14825|14825|28|0.1%|0.2%|
[proxz](#proxz)|1180|1180|26|2.2%|0.2%|
[openbl_60d](#openbl_60d)|7022|7022|26|0.3%|0.2%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|3472|3472|24|0.6%|0.2%|
[blocklist_de_bots](#blocklist_de_bots)|3015|3015|20|0.6%|0.1%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|19|0.0%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|14|0.0%|0.1%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|13|1.0%|0.1%|
[php_harvesters](#php_harvesters)|378|378|11|2.9%|0.1%|
[palevo](#palevo)|13|13|11|84.6%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|11|0.0%|0.1%|
[proxyrss](#proxyrss)|1536|1536|7|0.4%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2456|2456|7|0.2%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|6|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2703|2703|5|0.1%|0.0%|
[openbl_30d](#openbl_30d)|2855|2855|4|0.1%|0.0%|
[shunlist](#shunlist)|1334|1334|2|0.1%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|2|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|174|174|2|1.1%|0.0%|
[voipbl](#voipbl)|10522|10934|1|0.0%|0.0%|
[openbl_7d](#openbl_7d)|692|692|1|0.1%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|1|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|1|0.1%|0.0%|
[et_compromised](#et_compromised)|1718|1718|1|0.0%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|172|172|1|0.5%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1720|1720|1|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3241|3241|1|0.0%|0.0%|

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
[firehol_level1](#firehol_level1)|5146|688981376|18340608|2.6%|100.0%|
[et_block](#et_block)|999|18343755|18338560|99.9%|99.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|8532506|2.4%|46.5%|
[firehol_level3](#firehol_level3)|109927|9627612|6933036|72.0%|37.8%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|6932480|75.5%|37.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|2272265|0.2%|12.3%|
[fullbogons](#fullbogons)|3778|670299624|151552|0.0%|0.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|130368|0.0%|0.7%|
[alienvault_reputation](#alienvault_reputation)|181943|181943|1373|0.7%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1037|0.3%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|93938|93938|1023|1.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|512|0.1%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|294|1.0%|0.0%|
[firehol_level2](#firehol_level2)|23830|35462|270|0.7%|0.0%|
[openbl_60d](#openbl_60d)|7022|7022|235|3.3%|0.0%|
[blocklist_de](#blocklist_de)|29889|29889|201|0.6%|0.0%|
[nixspam](#nixspam)|18909|18909|172|0.9%|0.0%|
[openbl_30d](#openbl_30d)|2855|2855|121|4.2%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3241|3241|117|3.6%|0.0%|
[et_compromised](#et_compromised)|1718|1718|101|5.8%|0.0%|
[shunlist](#shunlist)|1334|1334|98|7.3%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1720|1720|95|5.5%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6912|6912|85|1.2%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3015|3015|56|1.8%|0.0%|
[openbl_7d](#openbl_7d)|692|692|48|6.9%|0.0%|
[php_commenters](#php_commenters)|403|403|29|7.1%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|29|2.2%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|18940|18940|21|0.1%|0.0%|
[snort_ipfilter](#snort_ipfilter)|10254|10254|19|0.1%|0.0%|
[zeus_badips](#zeus_badips)|203|203|16|7.8%|0.0%|
[zeus](#zeus)|231|231|16|6.9%|0.0%|
[openbl_1d](#openbl_1d)|163|163|16|9.8%|0.0%|
[voipbl](#voipbl)|10522|10934|14|0.1%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2456|2456|11|0.4%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|174|174|7|4.0%|0.0%|
[php_dictionary](#php_dictionary)|666|666|6|0.9%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|6|0.4%|0.0%|
[firehol_anonymous](#firehol_anonymous)|18443|82465|6|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|5|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|3472|3472|5|0.1%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14825|14825|5|0.0%|0.0%|
[php_spammers](#php_spammers)|661|661|4|0.6%|0.0%|
[malc0de](#malc0de)|338|338|4|1.1%|0.0%|
[et_tor](#et_tor)|6340|6340|3|0.0%|0.0%|
[dm_tor](#dm_tor)|6428|6428|3|0.0%|0.0%|
[bm_tor](#bm_tor)|6410|6410|3|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|2|0.3%|0.0%|
[firehol_proxies](#firehol_proxies)|11996|12233|2|0.0%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|80|80|2|2.5%|0.0%|
[sslbl](#sslbl)|375|375|1|0.2%|0.0%|
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
[firehol_level1](#firehol_level1)|5146|688981376|487424|0.0%|100.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|270785|0.1%|55.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|98904|0.0%|20.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|33155|0.0%|6.8%|
[et_block](#et_block)|999|18343755|517|0.0%|0.1%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|512|0.0%|0.1%|
[firehol_level3](#firehol_level3)|109927|9627612|89|0.0%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|93938|93938|79|0.0%|0.0%|
[alienvault_reputation](#alienvault_reputation)|181943|181943|14|0.0%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|9|0.0%|0.0%|
[firehol_level2](#firehol_level2)|23830|35462|9|0.0%|0.0%|
[php_commenters](#php_commenters)|403|403|7|1.7%|0.0%|
[blocklist_de](#blocklist_de)|29889|29889|7|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|10254|10254|6|0.0%|0.0%|
[zeus_badips](#zeus_badips)|203|203|5|2.4%|0.0%|
[zeus](#zeus)|231|231|5|2.1%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3015|3015|5|0.1%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|174|174|4|2.2%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6912|6912|3|0.0%|0.0%|
[php_harvesters](#php_harvesters)|378|378|1|0.2%|0.0%|
[openbl_60d](#openbl_60d)|7022|7022|1|0.0%|0.0%|
[openbl_30d](#openbl_30d)|2855|2855|1|0.0%|0.0%|
[nixspam](#nixspam)|18909|18909|1|0.0%|0.0%|
[malc0de](#malc0de)|338|338|1|0.2%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.0%|
[firehol_anonymous](#firehol_anonymous)|18443|82465|1|0.0%|0.0%|
[dm_tor](#dm_tor)|6428|6428|1|0.0%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|172|172|1|0.5%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3241|3241|1|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|18940|18940|1|0.0%|0.0%|

## sslbl

[Abuse.ch SSL Blacklist](https://sslbl.abuse.ch/) bad SSL traffic related to malware or botnet activities - **excellent list**

Source is downloaded from [this link](https://sslbl.abuse.ch/blacklist/sslipblacklist.csv).

The last time downloaded was found to be dated: Wed Jun 10 06:45:06 UTC 2015.

The ipset `sslbl` has **375** entries, **375** unique IPs.

The following table shows the overlaps of `sslbl` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `sslbl`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `sslbl`.
- ` this % ` is the percentage **of this ipset (`sslbl`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level1](#firehol_level1)|5146|688981376|375|0.0%|100.0%|
[firehol_level3](#firehol_level3)|109927|9627612|96|0.0%|25.6%|
[alienvault_reputation](#alienvault_reputation)|181943|181943|66|0.0%|17.6%|
[shunlist](#shunlist)|1334|1334|64|4.7%|17.0%|
[et_block](#et_block)|999|18343755|38|0.0%|10.1%|
[feodo](#feodo)|104|104|37|35.5%|9.8%|
[snort_ipfilter](#snort_ipfilter)|10254|10254|32|0.3%|8.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|28|0.0%|7.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|6|0.0%|1.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|3|0.0%|0.8%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|1|0.0%|0.2%|
[ri_web_proxies](#ri_web_proxies)|7484|7484|1|0.0%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.2%|
[firehol_proxies](#firehol_proxies)|11996|12233|1|0.0%|0.2%|
[firehol_level2](#firehol_level2)|23830|35462|1|0.0%|0.2%|
[firehol_anonymous](#firehol_anonymous)|18443|82465|1|0.0%|0.2%|
[blocklist_de_ssh](#blocklist_de_ssh)|3241|3241|1|0.0%|0.2%|
[blocklist_de](#blocklist_de)|29889|29889|1|0.0%|0.2%|

## stopforumspam_1d

[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers in the last 24 hours - **excellent list**

Source is downloaded from [this link](http://www.stopforumspam.com/downloads/listed_ip_1.zip).

The last time downloaded was found to be dated: Wed Jun 10 06:00:02 UTC 2015.

The ipset `stopforumspam_1d` has **6912** entries, **6912** unique IPs.

The following table shows the overlaps of `stopforumspam_1d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `stopforumspam_1d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `stopforumspam_1d`.
- ` this % ` is the percentage **of this ipset (`stopforumspam_1d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|23830|35462|6912|19.4%|100.0%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|6266|21.3%|90.6%|
[firehol_level3](#firehol_level3)|109927|9627612|5075|0.0%|73.4%|
[stopforumspam_30d](#stopforumspam_30d)|93938|93938|5042|5.3%|72.9%|
[blocklist_de](#blocklist_de)|29889|29889|1375|4.6%|19.8%|
[blocklist_de_bots](#blocklist_de_bots)|3015|3015|1295|42.9%|18.7%|
[firehol_anonymous](#firehol_anonymous)|18443|82465|998|1.2%|14.4%|
[firehol_proxies](#firehol_proxies)|11996|12233|790|6.4%|11.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|483|0.0%|6.9%|
[ri_web_proxies](#ri_web_proxies)|7484|7484|452|6.0%|6.5%|
[snort_ipfilter](#snort_ipfilter)|10254|10254|395|3.8%|5.7%|
[et_tor](#et_tor)|6340|6340|353|5.5%|5.1%|
[bm_tor](#bm_tor)|6410|6410|349|5.4%|5.0%|
[dm_tor](#dm_tor)|6428|6428|348|5.4%|5.0%|
[proxyrss](#proxyrss)|1536|1536|338|22.0%|4.8%|
[xroxy](#xroxy)|2147|2147|221|10.2%|3.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|203|0.0%|2.9%|
[proxz](#proxz)|1180|1180|178|15.0%|2.5%|
[php_commenters](#php_commenters)|403|403|161|39.9%|2.3%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|156|41.9%|2.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|133|0.0%|1.9%|
[blocklist_de_strongips](#blocklist_de_strongips)|174|174|108|62.0%|1.5%|
[ri_connect_proxies](#ri_connect_proxies)|2703|2703|99|3.6%|1.4%|
[firehol_level1](#firehol_level1)|5146|688981376|87|0.0%|1.2%|
[et_block](#et_block)|999|18343755|87|0.0%|1.2%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|85|0.0%|1.2%|
[blocklist_de_apache](#blocklist_de_apache)|14825|14825|75|0.5%|1.0%|
[nixspam](#nixspam)|18909|18909|49|0.2%|0.7%|
[alienvault_reputation](#alienvault_reputation)|181943|181943|49|0.0%|0.7%|
[blocklist_de_mail](#blocklist_de_mail)|18940|18940|44|0.2%|0.6%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|3472|3472|44|1.2%|0.6%|
[php_harvesters](#php_harvesters)|378|378|40|10.5%|0.5%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|35|0.0%|0.5%|
[php_spammers](#php_spammers)|661|661|32|4.8%|0.4%|
[php_dictionary](#php_dictionary)|666|666|27|4.0%|0.3%|
[openbl_60d](#openbl_60d)|7022|7022|20|0.2%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|10|0.0%|0.1%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|5|0.7%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|864|864|4|0.4%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|3|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|3|0.0%|0.0%|
[voipbl](#voipbl)|10522|10934|2|0.0%|0.0%|
[zeus_badips](#zeus_badips)|203|203|1|0.4%|0.0%|
[zeus](#zeus)|231|231|1|0.4%|0.0%|
[shunlist](#shunlist)|1334|1334|1|0.0%|0.0%|
[openbl_30d](#openbl_30d)|2855|2855|1|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|1|0.0%|0.0%|
[et_compromised](#et_compromised)|1718|1718|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1720|1720|1|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3241|3241|1|0.0%|0.0%|

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
[firehol_level3](#firehol_level3)|109927|9627612|93938|0.9%|100.0%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|27990|95.4%|29.7%|
[firehol_level2](#firehol_level2)|23830|35462|6395|18.0%|6.8%|
[firehol_anonymous](#firehol_anonymous)|18443|82465|5959|7.2%|6.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|5824|0.0%|6.1%|
[firehol_proxies](#firehol_proxies)|11996|12233|5313|43.4%|5.6%|
[stopforumspam_1d](#stopforumspam_1d)|6912|6912|5042|72.9%|5.3%|
[ri_web_proxies](#ri_web_proxies)|7484|7484|3547|47.3%|3.7%|
[blocklist_de](#blocklist_de)|29889|29889|2548|8.5%|2.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|2502|0.0%|2.6%|
[blocklist_de_bots](#blocklist_de_bots)|3015|3015|2176|72.1%|2.3%|
[ri_connect_proxies](#ri_connect_proxies)|2703|2703|1528|56.5%|1.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|1519|0.0%|1.6%|
[xroxy](#xroxy)|2147|2147|1269|59.1%|1.3%|
[firehol_level1](#firehol_level1)|5146|688981376|1105|0.0%|1.1%|
[et_block](#et_block)|999|18343755|1029|0.0%|1.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|1023|0.0%|1.0%|
[snort_ipfilter](#snort_ipfilter)|10254|10254|808|7.8%|0.8%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|735|0.0%|0.7%|
[proxz](#proxz)|1180|1180|700|59.3%|0.7%|
[proxyrss](#proxyrss)|1536|1536|697|45.3%|0.7%|
[et_tor](#et_tor)|6340|6340|642|10.1%|0.6%|
[bm_tor](#bm_tor)|6410|6410|637|9.9%|0.6%|
[dm_tor](#dm_tor)|6428|6428|634|9.8%|0.6%|
[php_commenters](#php_commenters)|403|403|302|74.9%|0.3%|
[blocklist_de_mail](#blocklist_de_mail)|18940|18940|267|1.4%|0.2%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|233|62.6%|0.2%|
[blocklist_de_apache](#blocklist_de_apache)|14825|14825|222|1.4%|0.2%|
[alienvault_reputation](#alienvault_reputation)|181943|181943|205|0.1%|0.2%|
[nixspam](#nixspam)|18909|18909|204|1.0%|0.2%|
[php_spammers](#php_spammers)|661|661|138|20.8%|0.1%|
[blocklist_de_strongips](#blocklist_de_strongips)|174|174|129|74.1%|0.1%|
[php_dictionary](#php_dictionary)|666|666|126|18.9%|0.1%|
[php_harvesters](#php_harvesters)|378|378|81|21.4%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|79|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|3472|3472|75|2.1%|0.0%|
[openbl_60d](#openbl_60d)|7022|7022|50|0.7%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|48|0.0%|0.0%|
[voipbl](#voipbl)|10522|10934|35|0.3%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3241|3241|22|0.6%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|18|2.7%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|13|0.0%|0.0%|
[et_compromised](#et_compromised)|1718|1718|13|0.7%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1720|1720|13|0.7%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|864|864|12|1.3%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2456|2456|11|0.4%|0.0%|
[shunlist](#shunlist)|1334|1334|4|0.2%|0.0%|
[openbl_30d](#openbl_30d)|2855|2855|4|0.1%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|4|0.3%|0.0%|
[dshield](#dshield)|20|5120|3|0.0%|0.0%|
[zeus_badips](#zeus_badips)|203|203|2|0.9%|0.0%|
[zeus](#zeus)|231|231|2|0.8%|0.0%|
[openbl_1d](#openbl_1d)|163|163|2|1.2%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|2|0.1%|0.0%|
[ciarmy](#ciarmy)|423|423|2|0.4%|0.0%|
[openbl_7d](#openbl_7d)|692|692|1|0.1%|0.0%|
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
[firehol_level3](#firehol_level3)|109927|9627612|28011|0.2%|95.4%|
[stopforumspam_30d](#stopforumspam_30d)|93938|93938|27990|29.7%|95.4%|
[firehol_level2](#firehol_level2)|23830|35462|7234|20.3%|24.6%|
[stopforumspam_1d](#stopforumspam_1d)|6912|6912|6266|90.6%|21.3%|
[firehol_anonymous](#firehol_anonymous)|18443|82465|2762|3.3%|9.4%|
[firehol_proxies](#firehol_proxies)|11996|12233|2353|19.2%|8.0%|
[blocklist_de](#blocklist_de)|29889|29889|2279|7.6%|7.7%|
[blocklist_de_bots](#blocklist_de_bots)|3015|3015|2066|68.5%|7.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|1913|0.0%|6.5%|
[ri_web_proxies](#ri_web_proxies)|7484|7484|1527|20.4%|5.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|790|0.0%|2.6%|
[snort_ipfilter](#snort_ipfilter)|10254|10254|669|6.5%|2.2%|
[xroxy](#xroxy)|2147|2147|623|29.0%|2.1%|
[ri_connect_proxies](#ri_connect_proxies)|2703|2703|582|21.5%|1.9%|
[proxyrss](#proxyrss)|1536|1536|579|37.6%|1.9%|
[et_tor](#et_tor)|6340|6340|533|8.4%|1.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|529|0.0%|1.8%|
[bm_tor](#bm_tor)|6410|6410|528|8.2%|1.7%|
[dm_tor](#dm_tor)|6428|6428|525|8.1%|1.7%|
[proxz](#proxz)|1180|1180|477|40.4%|1.6%|
[firehol_level1](#firehol_level1)|5146|688981376|303|0.0%|1.0%|
[et_block](#et_block)|999|18343755|297|0.0%|1.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|294|0.0%|1.0%|
[php_commenters](#php_commenters)|403|403|225|55.8%|0.7%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|192|51.6%|0.6%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|167|0.0%|0.5%|
[blocklist_de_mail](#blocklist_de_mail)|18940|18940|147|0.7%|0.5%|
[blocklist_de_apache](#blocklist_de_apache)|14825|14825|137|0.9%|0.4%|
[nixspam](#nixspam)|18909|18909|127|0.6%|0.4%|
[blocklist_de_strongips](#blocklist_de_strongips)|174|174|116|66.6%|0.3%|
[alienvault_reputation](#alienvault_reputation)|181943|181943|103|0.0%|0.3%|
[php_dictionary](#php_dictionary)|666|666|84|12.6%|0.2%|
[php_spammers](#php_spammers)|661|661|83|12.5%|0.2%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|3472|3472|62|1.7%|0.2%|
[php_harvesters](#php_harvesters)|378|378|60|15.8%|0.2%|
[openbl_60d](#openbl_60d)|7022|7022|27|0.3%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|18|0.0%|0.0%|
[voipbl](#voipbl)|10522|10934|14|0.1%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|11|1.6%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|9|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|864|864|8|0.9%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3241|3241|6|0.1%|0.0%|
[et_compromised](#et_compromised)|1718|1718|5|0.2%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1720|1720|5|0.2%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|4|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2456|2456|3|0.1%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|2|0.1%|0.0%|
[zeus_badips](#zeus_badips)|203|203|1|0.4%|0.0%|
[zeus](#zeus)|231|231|1|0.4%|0.0%|
[shunlist](#shunlist)|1334|1334|1|0.0%|0.0%|
[openbl_30d](#openbl_30d)|2855|2855|1|0.0%|0.0%|
[dshield](#dshield)|20|5120|1|0.0%|0.0%|
[ciarmy](#ciarmy)|423|423|1|0.2%|0.0%|

## virbl

[VirBL](http://virbl.bit.nl/) is a project of which the idea was born during the RIPE-48 meeting. The plan was to get reports of virusscanning mailservers, and put the IP-addresses that were reported to send viruses on a blacklist.

Source is downloaded from [this link](http://virbl.bit.nl/download/virbl.dnsbl.bit.nl.txt).

The last time downloaded was found to be dated: Wed Jun 10 06:42:03 UTC 2015.

The ipset `virbl` has **26** entries, **26** unique IPs.

The following table shows the overlaps of `virbl` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `virbl`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `virbl`.
- ` this % ` is the percentage **of this ipset (`virbl`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level3](#firehol_level3)|109927|9627612|26|0.0%|100.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|4|0.0%|15.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|2|0.0%|7.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|1|0.0%|3.8%|

## voipbl

[VoIPBL.org](http://www.voipbl.org/) a distributed VoIP blacklist that is aimed to protects against VoIP Fraud and minimizing abuse for network that have publicly accessible PBX's. Several algorithms, external sources and manual confirmation are used before they categorize something as an attack and determine the threat level.

Source is downloaded from [this link](http://www.voipbl.org/update/).

The last time downloaded was found to be dated: Wed Jun 10 06:18:24 UTC 2015.

The ipset `voipbl` has **10522** entries, **10934** unique IPs.

The following table shows the overlaps of `voipbl` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `voipbl`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `voipbl`.
- ` this % ` is the percentage **of this ipset (`voipbl`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|1602|0.0%|14.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|434|0.0%|3.9%|
[firehol_level1](#firehol_level1)|5146|688981376|333|0.0%|3.0%|
[fullbogons](#fullbogons)|3778|670299624|319|0.0%|2.9%|
[bogons](#bogons)|13|592708608|319|0.0%|2.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|299|0.0%|2.7%|
[alienvault_reputation](#alienvault_reputation)|181943|181943|192|0.1%|1.7%|
[firehol_anonymous](#firehol_anonymous)|18443|82465|78|0.0%|0.7%|
[firehol_level3](#firehol_level3)|109927|9627612|59|0.0%|0.5%|
[stopforumspam_30d](#stopforumspam_30d)|93938|93938|35|0.0%|0.3%|
[firehol_level2](#firehol_level2)|23830|35462|30|0.0%|0.2%|
[blocklist_de](#blocklist_de)|29889|29889|28|0.0%|0.2%|
[blocklist_de_sip](#blocklist_de_sip)|80|80|24|30.0%|0.2%|
[et_block](#et_block)|999|18343755|18|0.0%|0.1%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|14|0.0%|0.1%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|14|0.0%|0.1%|
[shunlist](#shunlist)|1334|1334|14|1.0%|0.1%|
[openbl_60d](#openbl_60d)|7022|7022|8|0.1%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|4|0.0%|0.0%|
[openbl_30d](#openbl_30d)|2855|2855|3|0.1%|0.0%|
[et_tor](#et_tor)|6340|6340|3|0.0%|0.0%|
[dm_tor](#dm_tor)|6428|6428|3|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1720|1720|3|0.1%|0.0%|
[bm_tor](#bm_tor)|6410|6410|3|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6912|6912|2|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|2|0.0%|0.0%|
[et_compromised](#et_compromised)|1718|1718|2|0.1%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3241|3241|2|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14825|14825|2|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|10254|10254|1|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.0%|
[firehol_proxies](#firehol_proxies)|11996|12233|1|0.0%|0.0%|
[ciarmy](#ciarmy)|423|423|1|0.2%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|3472|3472|1|0.0%|0.0%|

## xroxy

[xroxy.com](http://www.xroxy.com) open proxies (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.xroxy.com/proxyrss.xml).

The last time downloaded was found to be dated: Wed Jun 10 06:33:01 UTC 2015.

The ipset `xroxy` has **2147** entries, **2147** unique IPs.

The following table shows the overlaps of `xroxy` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `xroxy`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `xroxy`.
- ` this % ` is the percentage **of this ipset (`xroxy`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_proxies](#firehol_proxies)|11996|12233|2147|17.5%|100.0%|
[firehol_anonymous](#firehol_anonymous)|18443|82465|2147|2.6%|100.0%|
[firehol_level3](#firehol_level3)|109927|9627612|1286|0.0%|59.8%|
[stopforumspam_30d](#stopforumspam_30d)|93938|93938|1269|1.3%|59.1%|
[ri_web_proxies](#ri_web_proxies)|7484|7484|943|12.6%|43.9%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|623|2.1%|29.0%|
[proxz](#proxz)|1180|1180|425|36.0%|19.7%|
[ri_connect_proxies](#ri_connect_proxies)|2703|2703|389|14.3%|18.1%|
[proxyrss](#proxyrss)|1536|1536|351|22.8%|16.3%|
[firehol_level2](#firehol_level2)|23830|35462|320|0.9%|14.9%|
[stopforumspam_1d](#stopforumspam_1d)|6912|6912|221|3.1%|10.2%|
[blocklist_de](#blocklist_de)|29889|29889|202|0.6%|9.4%|
[blocklist_de_bots](#blocklist_de_bots)|3015|3015|147|4.8%|6.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|107|0.0%|4.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|104|0.0%|4.8%|
[nixspam](#nixspam)|18909|18909|63|0.3%|2.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|58|0.0%|2.7%|
[blocklist_de_mail](#blocklist_de_mail)|18940|18940|55|0.2%|2.5%|
[snort_ipfilter](#snort_ipfilter)|10254|10254|44|0.4%|2.0%|
[php_dictionary](#php_dictionary)|666|666|39|5.8%|1.8%|
[php_spammers](#php_spammers)|661|661|32|4.8%|1.4%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|13|1.9%|0.6%|
[php_commenters](#php_commenters)|403|403|8|1.9%|0.3%|
[blocklist_de_strongips](#blocklist_de_strongips)|174|174|6|3.4%|0.2%|
[alienvault_reputation](#alienvault_reputation)|181943|181943|5|0.0%|0.2%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|3|0.0%|0.1%|
[php_harvesters](#php_harvesters)|378|378|2|0.5%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.0%|
[et_tor](#et_tor)|6340|6340|1|0.0%|0.0%|
[et_compromised](#et_compromised)|1718|1718|1|0.0%|0.0%|
[et_block](#et_block)|999|18343755|1|0.0%|0.0%|
[dm_tor](#dm_tor)|6428|6428|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1720|1720|1|0.0%|0.0%|
[bm_tor](#bm_tor)|6410|6410|1|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2456|2456|1|0.0%|0.0%|

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
[firehol_level1](#firehol_level1)|5146|688981376|231|0.0%|100.0%|
[et_block](#et_block)|999|18343755|228|0.0%|98.7%|
[firehol_level3](#firehol_level3)|109927|9627612|204|0.0%|88.3%|
[zeus_badips](#zeus_badips)|203|203|203|100.0%|87.8%|
[snort_ipfilter](#snort_ipfilter)|10254|10254|201|1.9%|87.0%|
[alienvault_reputation](#alienvault_reputation)|181943|181943|62|0.0%|26.8%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|16|0.0%|6.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|14|0.0%|6.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|10|0.0%|4.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|9|0.0%|3.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|7|0.0%|3.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|5|0.0%|2.1%|
[stopforumspam_30d](#stopforumspam_30d)|93938|93938|2|0.0%|0.8%|
[openbl_60d](#openbl_60d)|7022|7022|2|0.0%|0.8%|
[firehol_level2](#firehol_level2)|23830|35462|2|0.0%|0.8%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|1|0.0%|0.4%|
[stopforumspam_1d](#stopforumspam_1d)|6912|6912|1|0.0%|0.4%|
[php_commenters](#php_commenters)|403|403|1|0.2%|0.4%|
[openbl_30d](#openbl_30d)|2855|2855|1|0.0%|0.4%|
[nixspam](#nixspam)|18909|18909|1|0.0%|0.4%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|1|0.0%|0.4%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.4%|
[blocklist_de_mail](#blocklist_de_mail)|18940|18940|1|0.0%|0.4%|
[blocklist_de](#blocklist_de)|29889|29889|1|0.0%|0.4%|

## zeus_badips

[Abuse.ch Zeus tracker](https://zeustracker.abuse.ch) badips includes IPv4 addresses that are used by the ZeuS trojan. It is the recommened blocklist if you want to block only ZeuS IPs. It excludes IP addresses that ZeuS Tracker believes to be hijacked (level 2) or belong to a free web hosting provider (level 3). Hence the false postive rate should be much lower compared to the standard ZeuS IP blocklist. **excellent list**

Source is downloaded from [this link](https://zeustracker.abuse.ch/blocklist.php?download=badips).

The last time downloaded was found to be dated: Wed Jun 10 06:45:07 UTC 2015.

The ipset `zeus_badips` has **203** entries, **203** unique IPs.

The following table shows the overlaps of `zeus_badips` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `zeus_badips`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `zeus_badips`.
- ` this % ` is the percentage **of this ipset (`zeus_badips`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[zeus](#zeus)|231|231|203|87.8%|100.0%|
[firehol_level1](#firehol_level1)|5146|688981376|203|0.0%|100.0%|
[et_block](#et_block)|999|18343755|203|0.0%|100.0%|
[firehol_level3](#firehol_level3)|109927|9627612|181|0.0%|89.1%|
[snort_ipfilter](#snort_ipfilter)|10254|10254|179|1.7%|88.1%|
[alienvault_reputation](#alienvault_reputation)|181943|181943|38|0.0%|18.7%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|16|0.0%|7.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|10|0.0%|4.9%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|10|0.0%|4.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|8|0.0%|3.9%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|5|0.0%|2.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|4|0.0%|1.9%|
[stopforumspam_30d](#stopforumspam_30d)|93938|93938|2|0.0%|0.9%|
[firehol_level2](#firehol_level2)|23830|35462|2|0.0%|0.9%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|1|0.0%|0.4%|
[stopforumspam_1d](#stopforumspam_1d)|6912|6912|1|0.0%|0.4%|
[php_commenters](#php_commenters)|403|403|1|0.2%|0.4%|
[openbl_60d](#openbl_60d)|7022|7022|1|0.0%|0.4%|
[nixspam](#nixspam)|18909|18909|1|0.0%|0.4%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.4%|
[blocklist_de_mail](#blocklist_de_mail)|18940|18940|1|0.0%|0.4%|
[blocklist_de](#blocklist_de)|29889|29889|1|0.0%|0.4%|
